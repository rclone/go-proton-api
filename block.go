package proton

import (
	"context"
	"fmt"
	"io"
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
	// Storage servers require only pm-storage-token, not API auth headers.
	// Use a plain resty request instead of going through c.do() which adds
	// x-pm-uid and Authorization headers.
	req := resty.New().R().SetContext(ctx)
	req.SetHeader("pm-storage-token", token)
	req.SetMultipartField("Block", "blob", "application/octet-stream", block)

	resp, err := req.Post(bareURL)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("%v POST %s: %s", resp.StatusCode(), bareURL, resp.String())
	}

	return nil
}

func (c *Client) GetUploadVerification(ctx context.Context, volumeID, linkID, revisionID string) (UploadVerification, error) {
	var res struct {
		VerificationCode string
		ContentKeyPacket string
	}

	route := fmt.Sprintf("/drive/v2/volumes/%s/links/%s/revisions/%s/verification", volumeID, linkID, revisionID)
	if err := c.do(ctx, func(r *resty.Request) (*resty.Response, error) {
		return r.SetResult(&res).Get(route)
	}); err != nil {
		return UploadVerification{}, err
	}

	return UploadVerification{
		VerificationCode: res.VerificationCode,
		ContentKeyPacket: res.ContentKeyPacket,
	}, nil
}