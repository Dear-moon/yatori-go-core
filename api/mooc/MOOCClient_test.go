package mooc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tjfoc/gmsm/sm4"
)

func testClient(t *testing.T) *MOOCClient {
	t.Helper()
	c, err := NewMOOCClient("offline@example.invalid", ClientOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestClientIsolationAndProxy(t *testing.T) {
	a, b := testClient(t), testClient(t)
	u, _ := url.Parse(loginPageURL)
	a.httpClient.Jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "synthetic"}})
	if len(b.httpClient.Jar.Cookies(u)) != 0 {
		t.Fatal("cookie jars share state")
	}
	tr := a.httpClient.Transport.(*http.Transport)
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS verification disabled")
	}
	if tr.Proxy != nil {
		t.Fatal("disabled proxy uses environment")
	}
	p, err := NewMOOCClient("offline", ClientOptions{IpProxySW: true, ProxyIP: "127.0.0.1:8888"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	req, _ := http.NewRequest(http.MethodGet, loginPageURL, nil)
	proxy, err := p.httpClient.Transport.(*http.Transport).Proxy(req)
	if err != nil || proxy.String() != "http://127.0.0.1:8888" {
		t.Fatal("proxy not normalized")
	}
	for _, value := range []string{"", "socks5://localhost:8080", "http://localhost/path", "http://localhost?secret=redacted"} {
		if _, err := parseProxy(value); err == nil {
			t.Fatal("invalid proxy accepted")
		}
	}
}

func TestHTTPFailures(t *testing.T) {
	cases := []struct {
		name              string
		status            int
		contentType, body string
		kind              error
	}{
		{"unauthorized", 401, "application/json", "secret", ErrSessionExpired},
		{"rejected", 503, "application/json", "secret", ErrRemoteRejected},
		{"html", 200, "text/html", "secret", ErrUnexpectedResponse},
		{"oversized", 200, "application/json", strings.Repeat("x", maxResponseBytes+1), ErrUnexpectedResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			c := testClient(t)
			_, err := c.request(context.Background(), "gt", http.MethodGet, srv.URL, nil, true)
			if !errors.Is(err, tc.kind) {
				t.Fatalf("wrong error: %v", err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), srv.URL) {
				t.Fatal("error leaked response or URL")
			}
		})
	}
}

func TestTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "{}") }))
	defer srv.Close()
	c := testClient(t)
	if _, err := c.request(context.Background(), "tls", http.MethodGet, srv.URL, nil, false); !errors.Is(err, ErrRequestFailed) {
		t.Fatal("untrusted TLS certificate accepted")
	}
}

func TestRequestCancellationAndTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	c := testClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.request(ctx, "cancel", http.MethodGet, srv.URL, nil, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	c.httpClient.Timeout = 20 * time.Millisecond
	if _, err := c.request(context.Background(), "timeout", http.MethodGet, srv.URL, nil, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	<-c.gate
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.run(ctx, func(context.Context) error { t.Fatal("entered locked session"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	c.gate <- struct{}{}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOfflineLoginProtocol(t *testing.T) {
	c := testClient(t)
	calls := 0
	c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		body := "{}"
		if r.Method == http.MethodPost {
			var envelope struct{ EncParams string }
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Fatal(err)
			}
			cipher, err := hex.DecodeString(envelope.EncParams)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := hex.DecodeString(publicKey)
			plain, err := sm4.Sm4Ecb(key, cipher, false)
			if err != nil {
				t.Fatal(err)
			}
			var params map[string]any
			if err := json.Unmarshal(plain, &params); err != nil {
				t.Fatal(err)
			}
			switch r.URL.Path {
			case "/dl/zj/yd/gt":
				if params["un"] != c.account {
					t.Fatal("wrong account")
				}
				body = `{"ret":"201","tk":"synthetic-token"}`
			case "/dl/zj/yd/powGetP":
				if params["un"] != c.account || params["pvSid"] != "synthetic-session" || params["channel"] != "1" {
					t.Fatal("wrong proof request")
				}
				body = `{"ret":"201","pVInfo":{"maxTime":1000,"minTime":0,"sid":"synthetic-proof","args":{"puzzle":"synthetic","x":"2","t":3,"mod":"11"}}}`
			case "/dl/zj/yd/pwd/l":
				pv := params["pVParam"].(map[string]any)
				var args map[string]any
				if err := json.Unmarshal([]byte(pv["args"].(string)), &args); err != nil {
					t.Fatal(err)
				}
				if args["x"] != "1" || args["t"] != float64(3) {
					t.Fatal("proof changed")
				}
			}
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	if err := c.Login(context.Background(), "synthetic-password", ""); !errors.Is(err, ErrNeedsUserAction) || calls != 0 {
		t.Fatal("missing proof identifier performed network IO")
	}
	if err := c.Login(context.Background(), "synthetic-password", "synthetic-session"); !errors.Is(err, ErrAuthenticationUnverified) {
		t.Fatalf("false authentication result: %v", err)
	}
	if calls != 5 || c.proof.Sid != "" {
		t.Fatal("unexpected stages or reusable challenge")
	}
	if err := c.SubmitLogin(context.Background(), "synthetic-password"); !errors.Is(err, ErrSessionExpired) {
		t.Fatal(err)
	}
}

func TestMalformedResponses(t *testing.T) {
	for _, body := range []string{"", "null", "[]", "{", `{"ret":201}`} {
		var target struct{ Ret string }
		if err := decodeResponse("gt", []byte(body), &target); !errors.Is(err, ErrUnexpectedResponse) {
			t.Fatal("malformed response accepted")
		}
	}
	for _, body := range []string{`{}`, `{"ret":"201"}`, `{"ret":"400","tk":"secret"}`} {
		c := testClient(t)
		c.initialized = true
		c.tk = "old"
		c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})
		if err := c.Gt(context.Background()); err == nil || c.tk != "" {
			t.Fatal("failed stage retained token")
		}
	}
}

func TestParameterEscapingAndCrypto(t *testing.T) {
	value := "quote\"\\\n"
	for _, params := range []string{
		BuildPowGetPParams(value, value, value, value, 1, value, value),
		BuildDLInitParams(value, value, value, 1, value, value),
		BuildZCInitParams(value, value, value, 1, value, value),
		BuildGTParams(value, 1, value, value, value, value),
		BuildLParams(1, 10, value, value, value, value, value, value, value, 0, 1, value, value, 1, 1, 1, value, value),
	} {
		if !json.Valid([]byte(params)) {
			t.Fatal("invalid JSON escaping")
		}
	}
	id, err := BuildRtId()
	if err != nil || len(id) != 32 {
		t.Fatal("invalid request identifier")
	}
	encrypted, err := MOOCEncMS4(value)
	if err != nil || encrypted == "" {
		t.Fatal(err)
	}
	if _, err := MOOCRSA(strings.Repeat("x", 1000)); err == nil {
		t.Fatal("oversized RSA plaintext accepted")
	}
}

func TestProofCalculation(t *testing.T) {
	data := Data{Args: Args{X: "2", Mod: "11", T: 3}, MaxTime: 1000}
	count, elapsed, iterations, x, sign, err := VdfAsyncContext(context.Background(), data)
	if err != nil || count != 3 || iterations != 3 || x != "1" {
		t.Fatalf("wrong result: %d %d %s %v", count, iterations, x, err)
	}
	if elapsed == 0 && sign != PowSign("runTimes=3&spendTime=0&t=3&x=1", 3) {
		t.Fatal("signature changed")
	}
	if PowSign("hello", 0) != 613153351 {
		t.Fatal("MurmurHash3 vector changed")
	}
	for _, bad := range []Data{
		{Args: Args{X: "invalid", Mod: "11"}, MaxTime: 1},
		{Args: Args{X: "2", Mod: "0"}, MaxTime: 1},
		{Args: Args{X: "2", Mod: "11"}, MinTime: 2, MaxTime: 1},
		{Args: Args{X: "2", Mod: "11", T: -1}, MaxTime: 1},
		{Args: Args{X: strings.Repeat("f", 1025), Mod: "11"}, MaxTime: 1},
	} {
		if _, _, _, _, _, err := VdfAsync(bad); !errors.Is(err, ErrUnexpectedResponse) {
			t.Fatal("invalid proof accepted")
		}
	}
	data.MinTime = 1000
	data.MaxTime = 2000
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, _, _, _, _, err := VdfAsyncContext(ctx, data); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("proof did not cancel")
	}
}

func TestCookiesAndRedirects(t *testing.T) {
	c := testClient(t)
	received := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "synthetic", Path: "/"})
		}
		if r.URL.Path == "/check" {
			cookie, err := r.Cookie("session")
			received = err == nil && cookie.Value == "synthetic"
		}
		io.WriteString(w, "{}")
	}))
	defer srv.Close()
	for _, path := range []string{"/set", "/check"} {
		if _, err := c.request(context.Background(), "cookies", http.MethodGet, srv.URL+path, nil, false); err != nil {
			t.Fatal(err)
		}
	}
	if !received {
		t.Fatal("cookie not sent on next request")
	}
	origin, _ := http.NewRequest(http.MethodPost, loginPageURL, nil)
	for _, target := range []string{"http://www.icourse163.org/", "https://other.invalid/"} {
		redirect, _ := http.NewRequest(http.MethodGet, target, nil)
		if err := c.httpClient.CheckRedirect(redirect, []*http.Request{origin}); !errors.Is(err, ErrUnexpectedResponse) {
			t.Fatal("unsafe redirect accepted")
		}
	}
}

func TestMalformedProofAndLegacyErrors(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"ret":"201","pVInfo":null}`,
		`{"ret":"201","pVInfo":{"sid":"s","maxTime":1000,"args":{"puzzle":"p","x":"2","mod":"0","t":1}}}`,
		`{"ret":"201","pVInfo":{"sid":"s","maxTime":"wrong"}}`,
	} {
		c := testClient(t)
		c.initialized = true
		c.tk = "synthetic"
		c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})
		if err := c.PowGetP(context.Background(), "synthetic"); !errors.Is(err, ErrUnexpectedResponse) || c.proof.Sid != "" {
			t.Fatal("malformed proof accepted")
		}
	}
	cache := &MOOCUserCache{Account: "offline"}
	if err := cache.GtApi(); !errors.Is(err, ErrSessionExpired) {
		t.Fatal("legacy API discarded error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cache.InitCookiesApiContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("legacy API ignored context")
	}
	cache.Account = "changed"
	if err := cache.GtApi(); err == nil {
		t.Fatal("legacy session changed account")
	}
}
