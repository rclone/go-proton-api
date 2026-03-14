package proton_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rclone/go-proton-api"
	"github.com/stretchr/testify/require"
)

func TestMoveLinkByVolumeUsesV2Endpoint(t *testing.T) {
	var gotMethod string
	var gotPath string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Code":1000}`))
	}))
	defer ts.Close()

	m := proton.New(proton.WithHostURL(ts.URL))
	defer m.Close()

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.MoveLinkByVolume(context.Background(), "volume-id", "link-id", proton.MoveLinkReq{
		ParentLinkID: "parent-link-id",
		Name:         "encrypted-name",
		OriginalHash: "original-hash",
		Hash:         "new-hash",
	})
	require.NoError(t, err)
	require.Equal(t, http.MethodPut, gotMethod)
	require.Equal(t, "/drive/v2/volumes/volume-id/links/link-id/move", gotPath)
}

func TestGetRevisionVerificationUsesShareVerificationEndpoint(t *testing.T) {
	var gotMethod string
	var gotPath string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"VerificationCode":"abc","ContentKeyPacket":"def"}`))
	}))
	defer ts.Close()

	m := proton.New(proton.WithHostURL(ts.URL))
	defer m.Close()

	c := m.NewClient("", "", "")
	defer c.Close()

	res, err := c.GetRevisionVerification(context.Background(), "share-id", "link-id", "revision-id")
	require.NoError(t, err)
	require.Equal(t, http.MethodGet, gotMethod)
	require.Equal(t, "/drive/shares/share-id/links/link-id/revisions/revision-id/verification", gotPath)
	require.Equal(t, "abc", res.VerificationCode)
	require.Equal(t, "def", res.ContentKeyPacket)
}
