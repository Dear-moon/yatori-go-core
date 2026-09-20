package mooc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// MOOCUserCache retains the experimental entry points; methods now return errors.
type MOOCUserCache struct {
	Account   string
	Password  string
	TK        string
	Sid       string
	X         string
	T         int
	Puzzle    string
	Mod       string
	MinTime   int64
	MaxTime   int64
	IpProxySW bool
	ProxyIP   string
	Timeout   time.Duration

	// ProofSessionID must come from the normal initialization flow, not a fixed sample.
	ProofSessionID string
	mu             sync.Mutex
	client         *MOOCClient
}

type proofParameters struct {
	MaxTime int64  `json:"maxTime"`
	MinTime int64  `json:"minTime"`
	Sid     string `json:"sid"`
	Args    struct {
		Puzzle string `json:"puzzle"`
		X      string `json:"x"`
		T      int    `json:"t"`
		Mod    string `json:"mod"`
	} `json:"args"`
}

func (p proofParameters) data() Data {
	return Data{NeedCheck: true, Sid: p.Sid, HashFunc: "VDF_FUNCTION",
		MaxTime: p.MaxTime, MinTime: p.MinTime,
		Args: Args{Puzzle: p.Args.Puzzle, X: p.Args.X, T: p.Args.T, Mod: p.Args.Mod}}
}

func (c *MOOCClient) post(ctx context.Context, operation, path, params string) ([]byte, error) {
	encrypted, err := MOOCEncMS4(params)
	if err != nil {
		return nil, &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	payload, err := json.Marshal(struct {
		EncParams string `json:"encParams"`
	}{encrypted})
	if err != nil {
		return nil, &RequestError{Operation: operation, Kind: ErrRequestFailed, cause: err}
	}
	return c.request(ctx, operation, http.MethodPost, authBaseURL+path, payload, true)
}

func decodeResponse(operation string, body []byte, target any) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
	}
	if err := json.Unmarshal(body, target); err != nil {
		return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
	}
	return nil
}

func (c *MOOCClient) initCookies(ctx context.Context) error {
	c.initialized = false
	c.tk = ""
	c.proof = proofParameters{}
	if err := c.resetCookies(); err != nil {
		return err
	}
	if _, err := c.request(ctx, "initialize", http.MethodGet, loginPageURL, nil, false); err != nil {
		return err
	}
	rtid, err := BuildRtId()
	if err != nil {
		return err
	}
	body, err := c.post(ctx, "initialize", "ini",
		BuildDLInitParams("imooc", "cjJVGQM", "www.icourse163.org", 1, loginPageURL, rtid))
	if err != nil {
		return err
	}
	var result map[string]json.RawMessage
	if err := decodeResponse("initialize", body, &result); err != nil {
		return err
	}
	c.initialized = true
	return nil
}

func (c *MOOCClient) gt(ctx context.Context) error {
	c.tk = ""
	c.proof = proofParameters{}
	if !c.initialized {
		return &RequestError{Operation: "gt", Kind: ErrSessionExpired}
	}
	rtid, err := BuildRtId()
	if err != nil {
		return err
	}
	body, err := c.post(ctx, "gt", "gt", BuildGTParams(c.account, 1, "imooc", "cjJVGQM", loginPageURL, rtid))
	if err != nil {
		return err
	}
	var result struct {
		Ret string `json:"ret"`
		TK  string `json:"tk"`
	}
	if err := decodeResponse("gt", body, &result); err != nil {
		return err
	}
	if result.Ret == "" {
		return &RequestError{Operation: "gt", Kind: ErrUnexpectedResponse}
	}
	if result.Ret != "201" {
		return &RequestError{Operation: "gt", Kind: ErrRemoteRejected}
	}
	if result.TK == "" {
		return &RequestError{Operation: "gt", Kind: ErrUnexpectedResponse}
	}
	c.tk = result.TK
	return nil
}

func (c *MOOCClient) powGetP(ctx context.Context, proofSessionID string) error {
	c.proof = proofParameters{}
	if !c.initialized || c.tk == "" {
		return &RequestError{Operation: "pow", Kind: ErrSessionExpired}
	}
	if strings.TrimSpace(proofSessionID) == "" {
		return &RequestError{Operation: "pow session identifier", Kind: ErrNeedsUserAction}
	}
	rtid, err := BuildRtId()
	if err != nil {
		return err
	}
	body, err := c.post(ctx, "pow", "powGetP",
		BuildPowGetPParams("imooc", "cjJVGQM", c.account, proofSessionID, 1, proofTopURL, rtid))
	if err != nil {
		return err
	}
	var result struct {
		Ret   string           `json:"ret"`
		Proof *proofParameters `json:"pVInfo"`
	}
	if err := decodeResponse("pow", body, &result); err != nil {
		return err
	}
	if result.Ret == "" {
		return &RequestError{Operation: "pow", Kind: ErrUnexpectedResponse}
	}
	if result.Ret != "201" {
		return &RequestError{Operation: "pow", Kind: ErrRemoteRejected}
	}
	if result.Proof == nil || result.Proof.Sid == "" || result.Proof.Args.Puzzle == "" {
		return &RequestError{Operation: "pow", Kind: ErrUnexpectedResponse}
	}
	if _, _, err := validateProof(result.Proof.data()); err != nil {
		return err
	}
	c.proof = *result.Proof
	return nil
}

func (c *MOOCClient) submitLogin(ctx context.Context, password string) error {
	if !c.initialized || c.tk == "" || c.proof.Sid == "" {
		return &RequestError{Operation: "login", Kind: ErrSessionExpired}
	}
	if password == "" {
		return &RequestError{Operation: "login", Kind: ErrAuthenticationFailed}
	}
	runTimes, spendTime, iterations, x, sign, err := VdfAsyncContext(ctx, c.proof.data())
	if err != nil {
		return err
	}
	encryptedPassword, err := MOOCRSA(password)
	if err != nil {
		return err
	}
	rtid, err := BuildRtId()
	if err != nil {
		return err
	}
	params := BuildLParams(1, 10, c.account, encryptedPassword, "imooc", "cjJVGQM", c.tk,
		"", c.proof.Args.Puzzle, int(spendTime), runTimes, c.proof.Sid, x, iterations, int(sign), 1, loginPageURL, rtid)
	// The challenge is single-use even when the request outcome is unknown.
	c.proof = proofParameters{}
	body, err := c.post(ctx, "login", "pwd/l", params)
	if err != nil {
		return err
	}
	var response map[string]json.RawMessage
	if err := decodeResponse("login", body, &response); err != nil {
		return err
	}
	// No verified final response schema or identity endpoint exists in the source evidence.
	return &RequestError{Operation: "login identity", Kind: ErrAuthenticationUnverified}
}

func (c *MOOCClient) InitCookies(ctx context.Context) error {
	return c.run(ctx, c.initCookies)
}

func (c *MOOCClient) Gt(ctx context.Context) error {
	return c.run(ctx, c.gt)
}

func (c *MOOCClient) PowGetP(ctx context.Context, proofSessionID string) error {
	return c.run(ctx, func(ctx context.Context) error { return c.powGetP(ctx, proofSessionID) })
}

func (c *MOOCClient) SubmitLogin(ctx context.Context, password string) error {
	return c.run(ctx, func(ctx context.Context) error { return c.submitLogin(ctx, password) })
}

// Login prepares the known protocol stages but cannot yet verify authenticated identity.
func (c *MOOCClient) Login(ctx context.Context, password, proofSessionID string) error {
	return c.run(ctx, func(ctx context.Context) error {
		if strings.TrimSpace(proofSessionID) == "" {
			return &RequestError{Operation: "pow session identifier", Kind: ErrNeedsUserAction}
		}
		if err := c.initCookies(ctx); err != nil {
			return err
		}
		if err := c.gt(ctx); err != nil {
			return err
		}
		if err := c.powGetP(ctx, proofSessionID); err != nil {
			return err
		}
		return c.submitLogin(ctx, password)
	})
}

func (cache *MOOCUserCache) clientForSession() (*MOOCClient, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.client != nil {
		if cache.client.account != cache.Account || cache.client.options.IpProxySW != cache.IpProxySW ||
			cache.client.options.ProxyIP != cache.ProxyIP {
			return nil, errors.New("create a new MOOCUserCache after changing account or proxy")
		}
		return cache.client, nil
	}
	client, err := NewMOOCClient(cache.Account, ClientOptions{Timeout: cache.Timeout, IpProxySW: cache.IpProxySW, ProxyIP: cache.ProxyIP})
	if err != nil {
		return nil, err
	}
	cache.client = client
	return client, nil
}

func (cache *MOOCUserCache) call(ctx context.Context, operation func(*MOOCClient, context.Context) error) error {
	c, err := cache.clientForSession()
	if err != nil {
		return err
	}
	return c.run(ctx, func(ctx context.Context) error {
		err := operation(c, ctx)
		cache.TK, cache.Sid = c.tk, c.proof.Sid
		cache.X, cache.T, cache.Puzzle, cache.Mod = c.proof.Args.X, c.proof.Args.T, c.proof.Args.Puzzle, c.proof.Args.Mod
		cache.MinTime, cache.MaxTime = c.proof.MinTime, c.proof.MaxTime
		return err
	})
}

func (cache *MOOCUserCache) InitCookiesApiContext(ctx context.Context) error {
	return cache.call(ctx, func(c *MOOCClient, ctx context.Context) error { return c.initCookies(ctx) })
}
func (cache *MOOCUserCache) GtApiContext(ctx context.Context) error {
	return cache.call(ctx, func(c *MOOCClient, ctx context.Context) error { return c.gt(ctx) })
}
func (cache *MOOCUserCache) PowGetPApiContext(ctx context.Context) error {
	return cache.call(ctx, func(c *MOOCClient, ctx context.Context) error { return c.powGetP(ctx, cache.ProofSessionID) })
}
func (cache *MOOCUserCache) LoginApiContext(ctx context.Context) error {
	return cache.call(ctx, func(c *MOOCClient, ctx context.Context) error { return c.submitLogin(ctx, cache.Password) })
}

// Deprecated: use InitCookiesApiContext to control cancellation.
func (cache *MOOCUserCache) InitCookiesApi() error {
	return cache.InitCookiesApiContext(context.Background())
}

// Deprecated: use GtApiContext to control cancellation.
func (cache *MOOCUserCache) GtApi() error { return cache.GtApiContext(context.Background()) }

// Deprecated: use PowGetPApiContext to control cancellation.
func (cache *MOOCUserCache) PowGetPApi() error { return cache.PowGetPApiContext(context.Background()) }

// Deprecated: use LoginApiContext to control cancellation.
func (cache *MOOCUserCache) LoginApi() error { return cache.LoginApiContext(context.Background()) }

func (c *MOOCClient) resetCookies() error {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return &RequestError{Operation: "initialize", Kind: ErrRequestFailed, cause: err}
	}
	c.httpClient.Jar = jar
	return nil
}
