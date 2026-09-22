package mooc

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// NewCookieClient creates an isolated client without requiring a phone number.
func NewCookieClient(options ClientOptions) (*MOOCClient, error) {
	return newMOOCClient("", options)
}

// LoginCookies imports browser cookies and succeeds only after verifying the current identity.
// Domain and Path must be supplied; a domain without a leading dot is treated as host-only.
func (c *MOOCClient) LoginCookies(ctx context.Context, cookies []*http.Cookie) (*MOOCUser, error) {
	var user *MOOCUser
	err := c.run(ctx, func(ctx context.Context) error {
		jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		if err != nil {
			return &RequestError{Operation: "cookie login", Kind: ErrRequestFailed, cause: err}
		}
		c.httpClient.Jar = jar
		c.user = nil
		c.lastVerifiedAt = time.Time{}
		c.verifiedOnce = false
		c.initialized = false
		c.tk = ""
		c.proof = proofParameters{}
		c.smsPending = false
		verified := false
		defer func() {
			if !verified {
				clean, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
				c.httpClient.Jar = clean
				c.user = nil
				c.lastVerifiedAt = time.Time{}
			}
		}()
		invalid := func() error { return &RequestError{Operation: "cookie login", Kind: ErrAuthenticationFailed} }
		if len(cookies) == 0 {
			return invalid()
		}
		for _, source := range cookies {
			if source == nil {
				return invalid()
			}
			cookie := *source
			domain := strings.ToLower(cookie.Domain)
			host := strings.TrimPrefix(domain, ".")
			if host != "icourse163.org" && !strings.HasSuffix(host, ".icourse163.org") {
				return invalid()
			}
			if cookie.Path == "" || cookie.Path[0] != '/' {
				return invalid()
			}
			// CDP may retain surrounding quotes that net/http represents separately.
			if strings.HasPrefix(cookie.Value, "\"") && strings.HasSuffix(cookie.Value, "\"") && len(cookie.Value) >= 2 {
				cookie.Value = cookie.Value[1 : len(cookie.Value)-1]
				cookie.Quoted = true
			}
			cookie.Domain = domain
			if cookie.Valid() != nil {
				return invalid()
			}
			if !strings.HasPrefix(domain, ".") {
				cookie.Domain = ""
			}
			jar.SetCookies(&url.URL{Scheme: "https", Host: host, Path: cookie.Path}, []*http.Cookie{&cookie})
		}
		user, err = c.currentUser(ctx)
		if err != nil {
			return err
		}
		verified = true
		return nil
	})
	return user, err
}
