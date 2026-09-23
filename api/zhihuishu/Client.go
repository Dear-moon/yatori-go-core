package zhihuishu

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/net/publicsuffix"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	ErrAuthenticationFailed = errors.New("Zhihuishu authentication failed")
	ErrSessionExpired       = errors.New("Zhihuishu session expired")
	ErrNeedsUserAction      = errors.New("Zhihuishu requires user action")
	ErrUnexpectedResponse   = errors.New("Zhihuishu unexpected response")
	ErrRemoteRejected       = errors.New("Zhihuishu remote request rejected")
	ErrRequestFailed        = errors.New("Zhihuishu request failed")
	ErrUnsupportedResource  = errors.New("Zhihuishu resource is not supported")
	ErrStudyClosed          = errors.New("Zhihuishu course study is closed")
)

type RequestError struct {
	Operation string
	Kind      error
	cause     error
}

func (e *RequestError) Error() string        { return e.Operation + ": " + e.Kind.Error() }
func (e *RequestError) Is(target error) bool { return target == e.Kind }
func (e *RequestError) Unwrap() error        { return e.cause }

type ClientOptions struct {
	Timeout  time.Duration
	ProxyURL string
}

// BrowserSession contains ephemeral browser credentials and protocol parameters.
type BrowserSession struct {
	Cookies   []*http.Cookie `json:"-"`
	AIKey     []byte         `json:"-"`
	CourseKey []byte         `json:"-"`
	IV        []byte         `json:"-"`
	MapID     string         `json:"-"`
}

func (BrowserSession) String() string     { return "Zhihuishu browser session <redacted>" }
func (s BrowserSession) GoString() string { return s.String() }

type User struct{ ID string }
type Client struct {
	httpClient           *http.Client
	gate                 chan struct{}
	timeout              time.Duration
	aiKey, courseKey, iv []byte
	mapID                string
	verifiedOnce         bool
	user                 *User
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Timeout < 0 {
		return nil, errors.New("Zhihuishu timeout must be positive")
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 20, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	if options.ProxyURL != "" {
		proxy, err := url.Parse(options.ProxyURL)
		if err != nil || proxy.Hostname() == "" || (proxy.Scheme != "http" && proxy.Scheme != "https") || proxy.RawQuery != "" || proxy.Fragment != "" || (proxy.Path != "" && proxy.Path != "/") {
			return nil, errors.New("invalid Zhihuishu proxy configuration")
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	c := &Client{timeout: options.Timeout, gate: make(chan struct{}, 1), httpClient: &http.Client{Transport: transport, Jar: jar, Timeout: options.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	c.gate <- struct{}{}
	return c, nil
}
func (c *Client) Close() { c.httpClient.CloseIdleConnections() }
func (c *Client) run(ctx context.Context, f func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.gate:
	}
	defer func() { c.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return f(ctx)
}
func (c *Client) clearSession() {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	c.httpClient.Jar = jar
	c.aiKey, c.courseKey, c.iv = nil, nil, nil
	c.mapID = ""
	c.user = nil
	c.verifiedOnce = false
}
func validAESKey(k []byte) bool { return len(k) == 16 || len(k) == 24 || len(k) == 32 }

// LoginBrowserSession succeeds only after the server identifies the current user.
func (c *Client) LoginBrowserSession(ctx context.Context, session BrowserSession) (*User, error) {
	var user *User
	err := c.run(ctx, func(ctx context.Context) error {
		c.clearSession()
		verified := false
		defer func() {
			if !verified {
				c.clearSession()
			}
		}()
		invalid := &RequestError{Operation: "browser session", Kind: ErrAuthenticationFailed}
		if len(session.Cookies) == 0 || !validAESKey(session.AIKey) || !validAESKey(session.CourseKey) || len(session.IV) != aes.BlockSize {
			return invalid
		}
		for _, source := range session.Cookies {
			if source == nil {
				return invalid
			}
			cookie := *source
			domain := strings.ToLower(cookie.Domain)
			host := strings.TrimPrefix(domain, ".")
			if host != "zhihuishu.com" && !strings.HasSuffix(host, ".zhihuishu.com") {
				return invalid
			}
			if cookie.Path == "" || cookie.Path[0] != '/' {
				return invalid
			}
			if len(cookie.Value) >= 2 && cookie.Value[0] == '"' && cookie.Value[len(cookie.Value)-1] == '"' {
				cookie.Value = cookie.Value[1 : len(cookie.Value)-1]
				cookie.Quoted = true
			}
			cookie.Domain = domain
			if cookie.Valid() != nil {
				return invalid
			}
			if !strings.HasPrefix(domain, ".") {
				cookie.Domain = ""
			}
			c.httpClient.Jar.SetCookies(&url.URL{Scheme: "https", Host: host, Path: cookie.Path}, []*http.Cookie{&cookie})
		}
		c.aiKey = append([]byte(nil), session.AIKey...)
		c.courseKey = append([]byte(nil), session.CourseKey...)
		c.iv = append([]byte(nil), session.IV...)
		c.mapID = session.MapID
		var err error
		user, err = c.currentUser(ctx)
		verified = err == nil
		return err
	})
	return user, err
}
func (c *Client) authenticationError(operation string) error {
	c.user = nil
	kind := ErrAuthenticationFailed
	if c.verifiedOnce {
		kind = ErrSessionExpired
	}
	return &RequestError{Operation: operation, Kind: kind}
}

const onlineBase = "https://onlineservice-api.zhihuishu.com"
const aiBase = "https://kg-ai-run.zhihuishu.com/run/gateway/t"

func timeStamp() string { return strconv.FormatInt(time.Now().UnixMilli(), 10) }
func (c *Client) CurrentUser(ctx context.Context) (*User, error) {
	var user *User
	err := c.run(ctx, func(ctx context.Context) error { var err error; user, err = c.currentUser(ctx); return err })
	return user, err
}
func (c *Client) currentUser(ctx context.Context) (*User, error) {
	c.user = nil
	var response struct {
		Code   *int
		Result *struct {
			ID string `json:"uuid"`
		}
	}
	if err := c.request(ctx, "profile", http.MethodGet, onlineBase+"/gateway/f/v1/login/getLoginUserInfo?time="+timeStamp(), nil, nil, &response); err != nil {
		return nil, err
	}
	if response.Code == nil {
		return nil, &RequestError{Operation: "profile schema", Kind: ErrUnexpectedResponse}
	}
	if err := c.resultCode("profile", *response.Code); err != nil {
		return nil, err
	}
	if response.Result == nil || strings.TrimSpace(response.Result.ID) == "" {
		return nil, &RequestError{Operation: "profile identity", Kind: ErrUnexpectedResponse}
	}
	c.user = &User{ID: response.Result.ID}
	c.verifiedOnce = true
	return &User{ID: c.user.ID}, nil
}
func (c *Client) resultCode(operation string, code int) error {
	switch code {
	case 200:
		return nil
	case 401, 403:
		return c.authenticationError(operation)
	case 422:
		return &RequestError{Operation: operation, Kind: ErrNeedsUserAction}
	default:
		return &RequestError{Operation: operation, Kind: ErrRemoteRejected}
	}
}
func (c *Client) request(ctx context.Context, operation, method, target string, payload []byte, headers http.Header, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
	if err != nil {
		return &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return c.authenticationError(operation)
	}
	if resp.StatusCode == 422 {
		return &RequestError{Operation: operation, Kind: ErrNeedsUserAction}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &RequestError{Operation: operation, Kind: ErrRemoteRejected}
	}
	kind, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (kind != "application/json" && !strings.HasSuffix(kind, "+json")) {
		return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil {
		return &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	if len(body) > 4<<20 || json.Unmarshal(body, result) != nil {
		return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
	}
	return nil
}

// The normal AI course frontend uses AES-CBC with PKCS7 and an imported IV.
func encryptPayload(value any, key, iv []byte) (string, error) {
	if !validAESKey(key) || len(iv) != aes.BlockSize {
		return "", ErrAuthenticationFailed
	}
	var plain []byte
	var err error
	if s, ok := value.(string); ok {
		plain = []byte(s)
	} else {
		plain, err = json.Marshal(value)
	}
	if err != nil {
		return "", ErrUnexpectedResponse
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(padding)}, padding)...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", ErrAuthenticationFailed
	}
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}
func (c *Client) aiRequest(ctx context.Context, operation, path string, params any, result any) error {
	secret, err := encryptPayload(params, c.aiKey, c.iv)
	if err != nil {
		return &RequestError{Operation: operation, Kind: err}
	}
	header, err := encryptPayload(c.mapID, c.aiKey, c.iv)
	if err != nil {
		return &RequestError{Operation: operation, Kind: err}
	}
	body, _ := json.Marshal(struct {
		Secret string `json:"secretStr"`
		Date   int64  `json:"date"`
	}{secret, time.Now().UnixMilli()})
	var response struct {
		Code *int
		Data json.RawMessage
	}
	headers := http.Header{"Content-Type": {"application/json;charset=UTF-8"}, "XQJZXHIZ": {header}}
	if err := c.request(ctx, operation, http.MethodPost, aiBase+path, body, headers, &response); err != nil {
		return err
	}
	if response.Code == nil {
		return &RequestError{Operation: operation + " schema", Kind: ErrUnexpectedResponse}
	}
	if err := c.resultCode(operation, *response.Code); err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	if len(response.Data) == 0 || bytes.Equal(bytes.TrimSpace(response.Data), []byte("null")) || json.Unmarshal(response.Data, result) != nil {
		return &RequestError{Operation: operation + " data", Kind: ErrUnexpectedResponse}
	}
	return nil
}
