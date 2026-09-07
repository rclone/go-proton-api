package proton_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rclone/go-proton-api"
	"github.com/rclone/go-proton-api/server"
	"github.com/stretchr/testify/require"
)

// credentialStore stands in for a config file shared between clients. Each
// client persists the tokens it receives, and each client's refresh hook reads
// whatever was most recently persisted.
type credentialStore struct {
	mu            sync.Mutex
	uid, acc, ref string
}

func (s *credentialStore) save(auth proton.Auth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uid, s.acc, s.ref = auth.UID, auth.AccessToken, auth.RefreshToken
}

func (s *credentialStore) load() (uid, acc, ref string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uid, s.acc, s.ref, s.ref != ""
}

// Two clients built from the same saved session hold the same single-use
// refresh token. When the first one refreshes, the server rotates the token
// and the second client's copy is spent. With a refresh hook the second client
// adopts the rotated credentials from the store instead of failing its own
// refresh and de-authing.
func TestAuth_RefreshHook_AdoptsRotatedCredentials(t *testing.T) {
	s := server.New()
	defer s.Close()

	_, _, err := s.CreateUser("user", []byte("pass"))
	require.NoError(t, err)

	s.SetAuthLife(time.Second)

	m := proton.New(
		proton.WithHostURL(s.GetHostURL()),
		proton.WithTransport(proton.InsecureTransport()),
	)
	defer m.Close()

	store := &credentialStore{}

	first, auth, err := m.NewClientWithLogin(context.Background(), "user", []byte("pass"))
	require.NoError(t, err)
	store.save(auth)
	first.AddAuthHandler(store.save)

	// The second client starts from the same saved session, as a second Fs in
	// the same process or a second process would.
	second := m.NewClient(auth.UID, auth.AccessToken, auth.RefreshToken)
	second.AddAuthHandler(store.save)
	second.AddAuthRefreshHook(store.load)

	deauthed := false
	second.AddDeauthHandler(func() { deauthed = true })

	// Let both access tokens expire.
	time.Sleep(2 * time.Second)

	// The first client refreshes and the server rotates the refresh token.
	_, err = first.GetUser(context.Background())
	require.NoError(t, err)
	_, _, rotated, _ := store.load()
	require.NotEqual(t, auth.RefreshToken, rotated, "server should have rotated the refresh token")

	// The second client's own refresh token is now spent. It must pick up the
	// rotated one from the store rather than fail.
	_, err = second.GetUser(context.Background())
	require.NoError(t, err)
	require.False(t, deauthed, "second client de-authed despite newer credentials being available")
}

// The hook is also consulted after a rejected refresh, so a client that read
// stale credentials just before another client rotated them still recovers.
func TestAuth_RefreshHook_RecoversAfterRejectedRefresh(t *testing.T) {
	s := server.New()
	defer s.Close()

	_, _, err := s.CreateUser("user", []byte("pass"))
	require.NoError(t, err)

	s.SetAuthLife(time.Second)

	m := proton.New(
		proton.WithHostURL(s.GetHostURL()),
		proton.WithTransport(proton.InsecureTransport()),
	)
	defer m.Close()

	store := &credentialStore{}

	first, auth, err := m.NewClientWithLogin(context.Background(), "user", []byte("pass"))
	require.NoError(t, err)
	store.save(auth)
	first.AddAuthHandler(store.save)

	second := m.NewClient(auth.UID, auth.AccessToken, auth.RefreshToken)
	second.AddAuthHandler(store.save)

	// The first call to the hook reports nothing newer, so the client goes
	// ahead with its own (doomed) refresh. Only the second call, made after
	// that refresh is rejected, sees the rotated credentials.
	calls := 0
	second.AddAuthRefreshHook(func() (string, string, string, bool) {
		calls++
		if calls == 1 {
			return "", "", "", false
		}
		return store.load()
	})

	deauthed := false
	second.AddDeauthHandler(func() { deauthed = true })

	time.Sleep(2 * time.Second)

	_, err = first.GetUser(context.Background())
	require.NoError(t, err)

	_, err = second.GetUser(context.Background())
	require.NoError(t, err)
	require.False(t, deauthed, "second client de-authed despite newer credentials being available")
	require.Equal(t, 2, calls, "hook should be consulted before the refresh and again after it was rejected")
}

// With nothing newer available a rejected refresh is a real revocation and the
// de-auth handlers must still fire.
func TestAuth_RefreshHook_StillDeauthsWhenNothingNewer(t *testing.T) {
	s := server.New()
	defer s.Close()

	userID, _, err := s.CreateUser("user", []byte("pass"))
	require.NoError(t, err)

	m := proton.New(
		proton.WithHostURL(s.GetHostURL()),
		proton.WithTransport(proton.InsecureTransport()),
	)
	defer m.Close()

	c, auth, err := m.NewClientWithLogin(context.Background(), "user", []byte("pass"))
	require.NoError(t, err)

	c.AddAuthRefreshHook(func() (string, string, string, bool) {
		return auth.UID, auth.AccessToken, auth.RefreshToken, true
	})

	deauthed := false
	c.AddDeauthHandler(func() { deauthed = true })

	require.NoError(t, s.RevokeUser(userID))

	_, err = c.GetUser(context.Background())
	require.Error(t, err)
	require.Eventually(t, func() bool { return deauthed }, time.Second, 50*time.Millisecond)
}

// Without a hook the second client has no way to learn about the rotation:
// its refresh is rejected and it de-auths. This is the failure the hook exists
// to prevent, kept here so the harness above is known to reproduce it.
func TestAuth_Refresh_SecondClientWithoutHookIsDeauthed(t *testing.T) {
	s := server.New()
	defer s.Close()

	_, _, err := s.CreateUser("user", []byte("pass"))
	require.NoError(t, err)

	s.SetAuthLife(time.Second)

	m := proton.New(
		proton.WithHostURL(s.GetHostURL()),
		proton.WithTransport(proton.InsecureTransport()),
	)
	defer m.Close()

	first, auth, err := m.NewClientWithLogin(context.Background(), "user", []byte("pass"))
	require.NoError(t, err)

	second := m.NewClient(auth.UID, auth.AccessToken, auth.RefreshToken)

	deauthed := false
	second.AddDeauthHandler(func() { deauthed = true })

	time.Sleep(2 * time.Second)

	_, err = first.GetUser(context.Background())
	require.NoError(t, err)

	_, err = second.GetUser(context.Background())
	require.Error(t, err)
	require.True(t, deauthed)
}
