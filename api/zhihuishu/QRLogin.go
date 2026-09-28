package zhihuishu

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	qrPassportBase = "https://passport.zhihuishu.com"
	qrLoginTimeout = 5 * time.Minute
)

// QRCode carries the image the user scans and the token used to poll for it.
type QRCode struct {
	ImagePNG []byte
	Token    string
}

// QRStatus mirrors the states the login page itself distinguishes.
type QRStatus struct {
	State        int
	Message      string
	OncePassword string
	UUID         string
}

const (
	QRWaiting   = -1
	QRScanned   = 0
	QRConfirmed = 1
	QRExpired   = 2
)

// qrServices each hold their own CAS session; the study flow needs all of them.
var qrServices = []string{
	"https://onlineservice-api.zhihuishu.com/",
	"https://kg-ai-run.zhihuishu.com/",
	"https://appcomm-user.zhihuishu.com/",
	"https://newbase.zhihuishu.com/",
}

// LoginQRCode runs the scan-to-login handshake and leaves the client signed in.
func (c *Client) LoginQRCode(ctx context.Context, onReady func(QRCode) error, interval time.Duration) (*User, error) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	var code QRCode
	if err := c.run(ctx, func(ctx context.Context) error {
		var err error
		code, err = c.requestQRCode(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	if onReady != nil {
		if err := onReady(code); err != nil {
			return nil, err
		}
	}
	deadline := time.Now().Add(qrLoginTimeout)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var status QRStatus
		if err := c.run(ctx, func(ctx context.Context) error {
			var err error
			status, err = c.pollQRCode(ctx, code.Token)
			return err
		}); err != nil {
			return nil, err
		}
		switch status.State {
		case QRConfirmed:
			if strings.TrimSpace(status.OncePassword) == "" || strings.TrimSpace(status.UUID) == "" {
				return nil, &RequestError{Operation: "qr login", Kind: ErrUnexpectedResponse}
			}
			if err := c.run(ctx, func(ctx context.Context) error { return c.completeQRLogin(ctx, status) }); err != nil {
				return nil, err
			}
			var user *User
			if err := c.run(ctx, func(ctx context.Context) error {
				if err := c.fetchSessionKeys(ctx); err != nil {
					return err
				}
				var err error
				user, err = c.currentUser(ctx)
				return err
			}); err != nil {
				return nil, err
			}
			return user, nil
		case QRExpired:
			return nil, &RequestError{Operation: "qr login", Kind: ErrNeedsUserAction}
		}
		if time.Now().After(deadline) {
			return nil, &RequestError{Operation: "qr login", Kind: ErrNeedsUserAction}
		}
		if err := waitForQR(ctx, interval); err != nil {
			return nil, err
		}
	}
}

func (c *Client) requestQRCode(ctx context.Context) (QRCode, error) {
	var response struct {
		Image string `json:"img"`
		Token string `json:"qrToken"`
	}
	if err := c.request(ctx, "qr request", http.MethodGet, qrPassportBase+"/qrCodeLogin/getLoginQrImg", nil, nil, &response); err != nil {
		return QRCode{}, err
	}
	image, err := base64.StdEncoding.DecodeString(strings.TrimSpace(response.Image))
	if err != nil || len(image) == 0 || strings.TrimSpace(response.Token) == "" {
		return QRCode{}, &RequestError{Operation: "qr request", Kind: ErrUnexpectedResponse}
	}
	return QRCode{ImagePNG: image, Token: response.Token}, nil
}

func (c *Client) pollQRCode(ctx context.Context, token string) (QRStatus, error) {
	var response struct {
		Status       *int   `json:"status"`
		Message      string `json:"msg"`
		OncePassword string `json:"oncePassword"`
		UUID         string `json:"uuid"`
	}
	target := qrPassportBase + "/qrCodeLogin/getLoginQrInfo?qrToken=" + url.QueryEscape(token)
	if err := c.request(ctx, "qr poll", http.MethodGet, target, nil, nil, &response); err != nil {
		return QRStatus{}, err
	}
	if response.Status == nil {
		return QRStatus{}, &RequestError{Operation: "qr poll", Kind: ErrUnexpectedResponse}
	}
	return QRStatus{State: *response.Status, Message: response.Message, OncePassword: response.OncePassword, UUID: response.UUID}, nil
}

// completeQRLogin exchanges the scan for a session and opens one per service.
func (c *Client) completeQRLogin(ctx context.Context, status QRStatus) error {
	form := url.Values{"uuid": {status.UUID}}.Encode()
	var abnormal struct {
		Status *int `json:"status"`
	}
	if err := c.sendForm(ctx, "qr abnormal login", "/user/abnormalLogin", form, &abnormal); err != nil {
		return err
	}
	if abnormal.Status == nil {
		return &RequestError{Operation: "qr abnormal login", Kind: ErrUnexpectedResponse}
	}
	if *abnormal.Status != 0 {
		return &RequestError{Operation: "qr abnormal login", Kind: ErrNeedsUserAction}
	}
	if err := c.followRedirects(ctx, "qr ticket", qrPassportBase+"/login?pwd="+url.QueryEscape(status.OncePassword)); err != nil {
		return err
	}
	for _, service := range qrServices {
		// A service may already accept the CAS cookie; only network failures are fatal.
		_ = c.followRedirects(ctx, "qr service", qrPassportBase+"/login?service="+url.QueryEscape(service))
	}
	return nil
}

func (c *Client) sendForm(ctx context.Context, operation, path, form string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, qrPassportBase+path, strings.NewReader(form))
	if err != nil {
		return &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", qrPassportBase+"/login")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &RequestError{Operation: operation, Kind: ErrRemoteRejected}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || json.Unmarshal(body, result) != nil {
		return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
	}
	return nil
}

// followRedirects walks the CAS handshake hop by hop so every cookie is kept.
func (c *Client) followRedirects(ctx context.Context, operation, target string) error {
	for hop := 0; hop < 12; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html,application/json,*/*")
		req.Header.Set("Referer", qrPassportBase+"/login")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
		}
		location := resp.Header.Get("Location")
		status := resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if status >= 300 && status < 400 && location != "" {
			next, err := resp.Request.URL.Parse(location)
			if err != nil {
				return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
			}
			if !strings.HasSuffix(strings.ToLower(next.Hostname()), "zhihuishu.com") && !strings.HasSuffix(strings.ToLower(next.Hostname()), "polymas.com") {
				return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
			}
			target = next.String()
			continue
		}
		if status < 200 || status >= 300 {
			return &RequestError{Operation: operation, Kind: ErrRemoteRejected}
		}
		return nil
	}
	return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
}

func waitForQR(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
