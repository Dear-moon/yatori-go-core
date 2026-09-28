package mooc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCookieLogin(t *testing.T) {
	for _, mode := range []string{"success", "logged out", "HTML", "canceled", "timeout", "foreign domain", "invalid value", "empty", "expired"} {
		t.Run(mode, func(t *testing.T) {
			c, err := NewCookieClient(ClientOptions{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			cookie := &http.Cookie{Name: "fixture_session", Value: "\"fixture\"", Domain: ".icourse163.org", Path: "/", Secure: true, HttpOnly: true}
			cookies := []*http.Cookie{cookie}
			if mode == "foreign domain" {
				cookie.Domain = "icourse163.org.attacker.example"
			}
			if mode == "invalid value" {
				cookie.Value = "secret\nvalue"
			}
			if mode == "empty" {
				cookies = nil
			}
			if mode == "expired" {
				cookie.Expires = time.Now().Add(-time.Hour)
			}
			ctx := context.Background()
			if mode == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if mode == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Millisecond)
				defer cancel()
			}
			c.httpClient.Transport = profileTransport(func(r *http.Request) (*http.Response, error) {
				if mode == "timeout" {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				if mode == "success" {
					v, e := r.Cookie("fixture_session")
					if e != nil || v.Value != "fixture" {
						t.Fatal("session cookie not carried")
					}
				}
				body := `<script>window.webUser={id:"user-123",nickName:"Learner",loginId:"account-123"};</script>`
				if mode == "logged out" || mode == "expired" {
					body = `<script>window.urlPrefix={};</script><a href="/member/login.htm">Login</a>`
				}
				if mode == "HTML" {
					body = `<html>Unavailable</html>`
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			user, err := c.LoginCookies(ctx, cookies)
			if mode == "success" {
				if err != nil || user == nil || user.ID != "user-123" {
					t.Fatalf("identity verification failed: %v", err)
				}
				if cookie.Value != "\"fixture\"" {
					t.Fatal("caller cookie mutated")
				}
				other, e := NewCookieClient(ClientOptions{})
				if e != nil {
					t.Fatal(e)
				}
				defer other.Close()
				u, _ := url.Parse(siteURL)
				if len(other.httpClient.Jar.Cookies(u)) != 0 {
					t.Fatal("cookies leaked between instances")
				}
				return
			}
			if err == nil || user != nil {
				t.Fatal("unverified login succeeded")
			}
			if mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost")
			}
			if mode == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("timeout lost")
			}
			if mode == "HTML" && !errors.Is(err, ErrUnexpectedResponse) {
				t.Fatal("unexpected HTML misclassified")
			}
			u, _ := url.Parse(siteURL)
			if len(c.httpClient.Jar.Cookies(u)) != 0 || c.user != nil {
				t.Fatal("failed session retained")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("error contains cookie value")
			}
		})
	}
}
