package proton

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"

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

func (c *Client) UploadBlock(ctx context.Context, bareURL, token string, block io.Reader) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("Block", "blob")
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, block); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	contentType := writer.FormDataContentType()
	payload := body.Bytes()

	return c.do(ctx, func(r *resty.Request) (*resty.Response, error) {
		return r.
			SetHeader("pm-storage-token", token).
			SetHeader("Content-Type", contentType).
			SetBody(payload).
			AddRetryCondition(func(res *resty.Response, _ error) bool {
				if res == nil {
					return false
				}
				return res.StatusCode() >= http.StatusInternalServerError &&
					res.StatusCode() < 600
			}).
			Post(bareURL)
	})
}
