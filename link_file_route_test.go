package proton_test

import (
	"context"
	"errors"
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

func TestGetRevisionVerificationByVolumeUsesV2Endpoint(t *testing.T) {
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

	res, err := c.GetRevisionVerificationByVolume(context.Background(), "volume-id", "link-id", "revision-id")
	require.NoError(t, err)
	require.Equal(t, http.MethodGet, gotMethod)
	require.Equal(t, "/drive/v2/volumes/volume-id/links/link-id/revisions/revision-id/verification", gotPath)
	require.Equal(t, "abc", res.VerificationCode)
	require.Equal(t, "def", res.ContentKeyPacket)
}

func TestGetRevisionVerificationByVolumePropagatesAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"Code":9000,"Error":"boom"}`))
	}))
	defer ts.Close()

	m := proton.New(proton.WithHostURL(ts.URL))
	defer m.Close()

	c := m.NewClient("", "", "")
	defer c.Close()

	_, err := c.GetRevisionVerificationByVolume(context.Background(), "volume-id", "link-id", "revision-id")
	require.Error(t, err)

	var apiErr *proton.APIError
	require.True(t, errors.As(err, &apiErr))
	require.Equal(t, http.StatusInternalServerError, apiErr.Status)
	require.Equal(t, proton.Code(9000), apiErr.Code)
}

func TestMoveLinkByVolumePropagatesAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"Code":9001,"Error":"move failed"}`))
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
	require.Error(t, err)

	var apiErr *proton.APIError
	require.True(t, errors.As(err, &apiErr))
	require.Equal(t, http.StatusInternalServerError, apiErr.Status)
	require.Equal(t, proton.Code(9001), apiErr.Code)
}
