package mooc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

var (
	ErrAccountUnavailable       = errors.New("MOOC account unavailable")
	ErrAuthenticationFailed     = errors.New("MOOC authentication failed")
	ErrSessionExpired           = errors.New("MOOC session expired")
	ErrNeedsUserAction          = errors.New("MOOC requires user action")
	ErrRemoteRejected           = errors.New("MOOC remote request rejected")
	ErrUnexpectedResponse       = errors.New("MOOC unexpected response")
	ErrRequestFailed            = errors.New("MOOC request failed")
	ErrAuthenticationUnverified = errors.New("MOOC authentication identity has not been verified")
)

// RequestError omits remote bodies and URLs because they may contain authentication material.
type RequestError struct {
	Operation  string
	Kind       error
	StatusCode int
	cause      error
}

func (e *RequestError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("%s: %s (HTTP %d)", e.Operation, e.Kind, e.StatusCode)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Kind)
}

func (e *RequestError) Is(target error) bool { return target == e.Kind }
func (e *RequestError) Unwrap() error        { return e.cause }

type ClientOptions struct {
	Timeout   time.Duration
	IpProxySW bool
	ProxyIP   string
}

type MOOCClient struct {
	httpClient     *http.Client
	account        string
	options        ClientOptions
	gate           chan struct{}
	initialized    bool
	tk             string
	proof          proofParameters
	user           *MOOCUser
	verifiedOnce   bool
	lastVerifiedAt time.Time
	smsPending     bool
	nextSMSAt      time.Time
}

const (
	defaultTimeout   = 30 * time.Second
	maxResponseBytes = 1 << 20
	loginPageURL     = "https://www.icourse163.org/member/login.htm"
	proofTopURL      = "https://www.icourse163.org/member/login.htm?returnUrl=aHR0cHM6Ly93d3cuaWNvdXJzZTE2My5vcmcvaW5kZXguaHRt#/webLoginIndex"
	authBaseURL      = "https://reg.icourse163.org/dl/zj/yd/"
)

// NewMOOCClient creates an isolated cookie jar and a reusable transport for one account.
func NewMOOCClient(account string, options ClientOptions) (*MOOCClient, error) {
	if strings.TrimSpace(account) == "" {
		return nil, errors.New("MOOC account is required")
	}
	if options.Timeout < 0 {
		return nil, errors.New("MOOC timeout must be positive")
	}
	if options.Timeout == 0 {
		options.Timeout = defaultTimeout
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, &RequestError{Operation: "client", Kind: ErrRequestFailed, cause: err}
	}
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	// A session must not alternate between explicit and environment proxies.
	transport.Proxy = nil
	if options.IpProxySW {
		proxy, err := parseProxy(options.ProxyIP)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	c := &MOOCClient{
		account: account,
		options: options,
		gate:    make(chan struct{}, 1),
		httpClient: &http.Client{
			Transport: transport,
			Jar:       jar,
			Timeout:   options.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 || req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host {
					return &RequestError{Operation: "redirect", Kind: ErrUnexpectedResponse}
				}
				return nil
			},
		},
	}
	c.gate <- struct{}{}
	return c, nil
}

func parseProxy(value string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("MOOC proxy is required when enabled")
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	proxy, err := url.Parse(value)
	if err != nil || proxy.Hostname() == "" || (proxy.Scheme != "http" && proxy.Scheme != "https") ||
		(proxy.Path != "" && proxy.Path != "/") || proxy.RawQuery != "" || proxy.Fragment != "" {
		return nil, errors.New("invalid MOOC proxy configuration")
	}
	return proxy, nil
}

// Close releases idle connections; cancellation remains the caller's responsibility.
func (c *MOOCClient) Close() { c.httpClient.CloseIdleConnections() }

func (c *MOOCClient) run(ctx context.Context, operation func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, c.options.Timeout)
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
	return operation(ctx)
}

func (c *MOOCClient) request(ctx context.Context, operation, method, target string, payload []byte, expectJSON bool) ([]byte, error) {
	return c.requestWithHeaders(ctx, operation, method, target, payload, expectJSON, nil)
}

func (c *MOOCClient) requestWithHeaders(ctx context.Context, operation, method, target string, payload []byte, expectJSON bool, headers http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
	if err != nil {
		return nil, &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://www.icourse163.org")
		req.Header.Set("Referer", loginPageURL)
	}
	for key, values := range headers {
		req.Header[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUnauthorized && (operation == "profile" || operation == "courses" || operation == "chapters" || operation == "video progress") {
			return nil, c.unauthenticated(operation)
		}
		kind := ErrRemoteRejected
		if resp.StatusCode == http.StatusUnauthorized {
			kind = ErrSessionExpired
			if operation == "login" {
				kind = ErrAuthenticationFailed
			}
		}
		return nil, &RequestError{Operation: operation, Kind: kind, StatusCode: resp.StatusCode}
	}
	if operation == "profile" {
		contentType, _, parseErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if parseErr != nil || (contentType != "text/html" && contentType != "application/xhtml+xml") {
			return nil, &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
		}
	}
	if expectJSON {
		contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil || (contentType != "application/json" && !strings.HasSuffix(contentType, "+json")) {
			return nil, &RequestError{Operation: operation, Kind: ErrUnexpectedResponse, StatusCode: resp.StatusCode}
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	if len(body) > maxResponseBytes {
		return nil, &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
	}
	return body, nil
}
