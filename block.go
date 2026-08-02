package proton

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"

	"github.com/go-resty/resty/v2"
)

func (c *Client) GetBlock(ctx context.Context, bareURL, token string) (io.ReadCloser, error) {
	res, err := c.doRes(ctx, func(r *resty.Request) (*resty.Response, error) {
		return r.SetHeader("pm-storage-token", token).SetDoNotParseResponse(true).Get(bareURL)
	})
	if err != nil {
		return nil, err
	}

	return res.RawBody(), nil
}

func (c *Client) RequestBlockUpload(ctx context.Context, req BlockUploadReq) ([]BlockUploadLink, error) {
	var res struct {
		UploadLinks []BlockUploadLink
	}

	if err := c.do(ctx, func(r *resty.Request) (*resty.Response, error) {
		return r.SetResult(&res).SetBody(req).Post("/drive/blocks")
	}); err != nil {
		return nil, err
	}

	return res.UploadLinks, nil
}

// UploadBlock uploads an encrypted block to Proton storage.
// The block data is accepted as []byte so that resty can replay it on retry
// without exhausting an io.Reader. (resty rebuilds the request body on each
// retry attempt; if an io.Reader is used it is consumed on the first attempt
// and subsequent retries send an empty body, causing Code=2003 errors.)
func (c *Client) UploadBlock(ctx context.Context, bareURL, token string, block []byte) error {
	// Pre-build the multipart body into []byte. resty stores the raw []byte in
	// r.Body and reconstructs r.bodyBuf from it on every retry attempt, so the
	// storage server always receives the full block data.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	hdr := make(textproto.MIMEHeader)
	hdr.Set("Content-Disposition", `form-data; name="Block"; filename="blob"`)
	hdr.Set("Content-Type", "application/octet-stream")
	part, err := w.CreatePart(hdr)
	if err != nil {
		return fmt.Errorf("creating multipart field: %w", err)
	}
	if _, err := part.Write(block); err != nil {
		return fmt.Errorf("writing block data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("closing multipart writer: %w", err)
	}

	contentType := w.FormDataContentType()
	bodyBytes := buf.Bytes()

	return c.do(ctx, func(r *resty.Request) (*resty.Response, error) {
		return r.
			SetHeader("pm-storage-token", token).
			SetHeader("Content-Type", contentType).
			SetBody(bodyBytes).
			Post(bareURL)
	})
}
