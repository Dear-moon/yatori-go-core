package mooc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type profileTransport func(*http.Request) (*http.Response, error)

func (f profileTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIdentityPageSignals(t *testing.T) {
	for _, tt := range []struct {
		name, body     string
		found, invalid bool
	}{
		{"identity", `<script>window.webUser = {id:"user-123",nickName:"Learner",loginId:"account-123"};</script>`, true, false},
		{"logged out", `<script>window.urlPrefix = {};</script><a href="/member/login.htm">Login</a>`, false, false},
		{"generic HTML", `<html>Unavailable</html>`, false, true},
		{"missing identity", `<script>window.webUser = {nickName:"Learner",loginId:"account-123"};</script>`, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			user, found, err := parseIdentity([]byte(tt.body))
			if tt.invalid {
				if !errors.Is(err, ErrUnexpectedResponse) {
					t.Fatalf("expected schema error, got %v", err)
				}
				return
			}
			if err != nil || found != tt.found {
				t.Fatalf("found=%v error=%v", found, err)
			}
			if found && (user.ID != "user-123" || user.Nickname != "Learner") {
				t.Fatal("identity mismatch")
			}
		})
	}
}

func TestCurrentUserSessionExpiry(t *testing.T) {
	c, err := NewMOOCClient("test-account", ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	calls := 0
	c.httpClient.Transport = profileTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `<script>window.webUser = {id:"user-123",nickName:"Learner",loginId:"account-123"};</script>`
		if calls > 1 {
			body = `<script>window.urlPrefix = {};</script><a href="/member/login.htm">Login</a>`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	if _, err = c.CurrentUser(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.CurrentUser(context.Background()); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected expired session, got %v", err)
	}
	if c.user != nil {
		t.Fatal("expired identity remained cached")
	}
}

func TestVideoProgressReceipt(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		kind       error
	}{
		{"accepted", `{"code":0,"result":true}`, nil},
		{"rejected", `{"code":0,"result":false}`, ErrRemoteRejected},
		{"expired", `{"code":1,"result":null}`, ErrSessionExpired},
		{"missing receipt", `{"code":0}`, ErrUnexpectedResponse},
		{"malformed", `{"code":`, ErrUnexpectedResponse},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewMOOCClient("test-account", ClientOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			posted := false
			c.httpClient.Transport = profileTransport(func(r *http.Request) (*http.Response, error) {
				body := `<script>window.webUser = {id:"user-123",nickName:"Learner",loginId:"account-123"};</script>`
				headers := http.Header{"Content-Type": {"text/html"}, "Set-Cookie": {"NTESSTUDYSI=fixture; Path=/; Secure"}}
				if r.Method == http.MethodPost {
					posted = true
					if r.URL.Path != "/web/j/courseRpcBean.saveMocContentLearn.rpc" {
						t.Fatal("unexpected request path")
					}
					cookie, err := r.Cookie("NTESSTUDYSI")
					if err != nil || cookie.Value != "fixture" || r.Header.Get("edu-script-token") != "fixture" {
						t.Fatal("session cookie or CSRF missing")
					}
					raw, err := io.ReadAll(r.Body)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(string(raw), `"unitId":9007199254740993`) || !strings.Contains(string(raw), `"duration":60000`) || !strings.Contains(string(raw), `"learnedVideoTimeCount":30`) {
						t.Fatal("progress encoding mismatch")
					}
					headers = http.Header{"Content-Type": {"application/json"}}
					body = tt.body
				}
				return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			err = c.ReportVideoProgress(context.Background(), VideoProgress{CourseID: "1", TermID: "2", LessonID: "3", UnitID: "9007199254740993", ContentID: "4", Index: 2, IntervalSeconds: 60, PositionSeconds: 30, WatchedSeconds: 30})
			if !errors.Is(err, tt.kind) {
				t.Fatalf("got %v, expected %v", err, tt.kind)
			}
			if !posted {
				t.Fatal("no progress request")
			}
		})
	}
}
