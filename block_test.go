package proton_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rclone/go-proton-api"
	"github.com/stretchr/testify/require"
)

func TestUploadBlockReplaysMultipartBodyAfterConnectionDrop(t *testing.T) {
	payload := []byte("encrypted Proton block payload")

	var (
		mu       sync.Mutex
		attempts [][]byte
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var received []byte
		file, _, err := r.FormFile("Block")
		if err == nil {
			received, err = io.ReadAll(file)
			require.NoError(t, err)
			require.NoError(t, file.Close())
		}

		mu.Lock()
		attempts = append(attempts, received)
		attempt := len(attempts)
		mu.Unlock()

		if attempt == 1 {
			hijacker, ok := w.(http.Hijacker)
			require.True(t, ok)
			conn, _, err := hijacker.Hijack()
			require.NoError(t, err)
			require.NoError(t, conn.Close())
			return
		}

		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/json")
		_, err = io.WriteString(w, `{"Code":1000}`)
		require.NoError(t, err)
	}))
	defer server.Close()

	manager := proton.New(
		proton.WithHostURL(server.URL),
		proton.WithRetryCount(1),
	)
	defer manager.Close()
	client := manager.NewClient("", "", "")
	defer client.Close()

	err := client.UploadBlock(
		context.Background(),
		server.URL+"/storage/blocks",
		"test-token",
		bytes.NewReader(payload),
	)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, attempts, 2)
	require.Equal(t, payload, attempts[0])
	require.Equal(t, payload, attempts[1])
}

func TestUploadBlockRetriesBadGatewayWithSameBody(t *testing.T) {
	payload := []byte("encrypted block survives 502 retry")

	var (
		mu       sync.Mutex
		attempts [][]byte
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, _, err := r.FormFile("Block")
		require.NoError(t, err)
		received, err := io.ReadAll(file)
		require.NoError(t, err)
		require.NoError(t, file.Close())

		mu.Lock()
		attempts = append(attempts, received)
		attempt := len(attempts)
		mu.Unlock()

		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/json")
		if attempt == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, err = io.WriteString(w, `{"Code":0,"Error":"simulated bad gateway"}`)
			require.NoError(t, err)
			return
		}
		_, err = io.WriteString(w, `{"Code":1000}`)
		require.NoError(t, err)
	}))
	defer server.Close()

	manager := proton.New(
		proton.WithHostURL(server.URL),
		proton.WithRetryCount(1),
	)
	defer manager.Close()
	client := manager.NewClient("", "", "")
	defer client.Close()

	err := client.UploadBlock(
		context.Background(),
		server.URL+"/storage/blocks",
		"test-token",
		bytes.NewReader(payload),
	)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, attempts, 2)
	require.Equal(t, payload, attempts[0])
	require.Equal(t, payload, attempts[1])
}
