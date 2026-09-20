package mooc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

const smsBaseURL = "https://reg.icourse163.org/dl/dlzc/yd/"

var mobilePattern = regexp.MustCompile(`^[0-9]{11}$`)
var smsCodePattern = regexp.MustCompile(`^[0-9]{4,8}$`)

type authResponse struct {
	Ret     string    `json:"ret"`
	DT      string    `json:"dt"`
	TK      string    `json:"tk"`
	PV      *bool     `json:"pv"`
	CapFlag *int      `json:"capFlag"`
	Proof   *smsProof `json:"pVInfo"`
}
type smsProof struct {
	proofParameters
	NeedCheck *bool  `json:"needCheck"`
	HashFunc  string `json:"hashFunc"`
}

func authResult(operation string, response authResponse) error {
	if response.Ret == "" {
		return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
	}
	if response.Ret == "201" {
		return nil
	}
	kind := ErrRemoteRejected
	switch response.Ret {
	case "441", "442", "444", "445", "447", "411", "635":
		kind = ErrNeedsUserAction
	case "420", "422", "602":
		kind = ErrAccountUnavailable
	case "401":
		kind = ErrAuthenticationFailed
	case "413", "415":
		if operation == "sms login" {
			kind = ErrAuthenticationFailed
		}
	}
	return &RequestError{Operation: operation, Kind: kind}
}

func (c *MOOCClient) smsRequest(ctx context.Context, operation, path string, params map[string]any) (*authResponse, error) {
	rtid, err := BuildRtId()
	if err != nil {
		return nil, err
	}
	params["pd"], params["pkid"], params["pkht"] = "imooc", "cjJVGQM", "www.icourse163.org"
	params["channel"], params["topURL"], params["rtid"] = 14, loginPageURL, rtid
	encrypted, err := MOOCEncMS4(marshalParams(params))
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(struct {
		EncParams string `json:"encParams"`
	}{encrypted})
	headers := http.Header{"Origin": []string{"https://reg.icourse163.org"}, "Referer": []string{"https://reg.icourse163.org/"}}
	body, err := c.requestWithHeaders(ctx, operation, http.MethodPost, smsBaseURL+path, payload, true, headers)
	if err != nil {
		return nil, err
	}
	var result authResponse
	if err := decodeResponse(operation, body, &result); err != nil {
		return nil, err
	}
	if err := authResult(operation, result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SendSMS starts a session and sends one code; interactive platform checks are not bypassed.
func (c *MOOCClient) SendSMS(ctx context.Context) error {
	return c.run(ctx, func(ctx context.Context) error {
		if !mobilePattern.MatchString(c.account) {
			return &RequestError{Operation: "mobile number", Kind: ErrAuthenticationFailed}
		}
		if time.Now().Before(c.nextSMSAt) {
			return &RequestError{Operation: "SMS cooldown", Kind: ErrRemoteRejected}
		}
		c.smsPending = false
		c.user = nil
		c.lastVerifiedAt = time.Time{}
		c.verifiedOnce = false
		c.tk = ""
		c.proof = proofParameters{}
		c.initialized = false
		if err := c.resetCookies(); err != nil {
			return err
		}
		if _, err := c.request(ctx, "sms initialize", http.MethodGet, loginPageURL, nil, false); err != nil {
			return err
		}
		init, err := c.smsRequest(ctx, "sms initialize", "ini", map[string]any{})
		if err != nil {
			return err
		}
		if init.CapFlag == nil || init.PV == nil {
			return &RequestError{Operation: "sms initialize", Kind: ErrUnexpectedResponse}
		}
		if *init.CapFlag != 0 {
			return &RequestError{Operation: "SMS verification", Kind: ErrNeedsUserAction}
		}
		params := map[string]any{"un": c.account}
		if *init.PV {
			challenge, err := c.smsRequest(ctx, "sms proof", "powGetP", map[string]any{"un": c.account})
			if err != nil {
				return err
			}
			if challenge.Proof == nil || challenge.Proof.NeedCheck == nil {
				return &RequestError{Operation: "sms proof", Kind: ErrUnexpectedResponse}
			}
			if *challenge.Proof.NeedCheck {
				p := challenge.Proof
				if p.HashFunc != "VDF_FUNCTION" || p.Sid == "" || p.Args.Puzzle == "" {
					return &RequestError{Operation: "sms proof", Kind: ErrUnexpectedResponse}
				}
				count, elapsed, iterations, x, sign, err := VdfAsyncContext(ctx, p.data())
				if err != nil {
					return err
				}
				params["pVParam"] = map[string]any{"puzzle": p.Args.Puzzle, "sid": p.Sid, "runTimes": count, "spendTime": elapsed,
					"args": marshalParams(map[string]any{"x": x, "t": iterations, "sign": sign})}
			}
		}
		// An uncertain delivery must not trigger an immediate duplicate SMS.
		c.nextSMSAt = time.Now().Add(time.Minute)
		if _, err := c.smsRequest(ctx, "send SMS", "sms/sm", params); err != nil {
			return err
		}
		c.smsPending = true
		return nil
	})
}

// LoginSMS reports success only after the site session yields a current identity.
func (c *MOOCClient) LoginSMS(ctx context.Context, code string) (*MOOCUser, error) {
	var user *MOOCUser
	err := c.run(ctx, func(ctx context.Context) error {
		if !c.smsPending || !smsCodePattern.MatchString(code) {
			return &RequestError{Operation: "sms login", Kind: ErrAuthenticationFailed}
		}
		ticket, err := c.smsRequest(ctx, "sms ticket", "gt", map[string]any{"un": c.account})
		if err != nil {
			return err
		}
		if ticket.TK == "" {
			return &RequestError{Operation: "sms ticket", Kind: ErrUnexpectedResponse}
		}
		if _, err := c.smsRequest(ctx, "sms login", "sms/vfsms", map[string]any{"un": c.account, "sms": code, "tk": ticket.TK, "domains": ""}); err != nil {
			return err
		}
		c.smsPending = false
		// The normal homepage redirect exchanges passport cookies for site cookies.
		if _, err := c.request(ctx, "session exchange", http.MethodGet, siteURL, nil, false); err != nil {
			return err
		}
		user, err = c.currentUser(ctx)
		return err
	})
	return user, err
}

func (c *MOOCClient) csrfCookie() string {
	u, _ := url.Parse(siteURL)
	for _, cookie := range c.httpClient.Jar.Cookies(u) {
		if cookie.Name == "NTESSTUDYSI" {
			return cookie.Value
		}
	}
	return ""
}
