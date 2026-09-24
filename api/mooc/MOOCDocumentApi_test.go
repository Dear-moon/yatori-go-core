package mooc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDocumentProgressReceipt(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		page       int
		kind       error
	}{
		{"middle page", `{"code":0,"result":true}`, 1, nil},
		{"last page", `{"code":0,"result":true}`, 2, nil},
		{"rejected", `{"code":0,"result":false}`, 1, ErrRemoteRejected},
		{"expired", `{"code":1,"result":null}`, 1, ErrSessionExpired},
		{"malformed", `{"code":`, 1, ErrUnexpectedResponse},
		{"missing receipt", `{"code":0}`, 1, ErrUnexpectedResponse},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewCookieClient(ClientOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			posted := false
			c.httpClient.Transport = profileTransport(func(r *http.Request) (*http.Response, error) {
				body := `<script>window.webUser={id:"user-123",nickName:"Learner",loginId:"account-123"};</script>`
				headers := http.Header{"Content-Type": {"text/html"}, "Set-Cookie": {"NTESSTUDYSI=fixture; Path=/; Secure"}}
				if r.Method == http.MethodPost {
					posted = true
					if r.URL.Path != "/web/j/courseRpcBean.saveMocContentLearn.rpc" || r.Header.Get("Auth-Signature") == "" {
						t.Error("incorrect signed endpoint")
					}
					var p struct {
						DTO struct {
							UnitID        json.Number `json:"unitId"`
							Page          int         `json:"pageNum"`
							Finished      bool        `json:"finished"`
							ContentType   int         `json:"contentType"`
							LastLearnTime int64       `json:"lastLearnTime"`
						}
					}
					if json.NewDecoder(r.Body).Decode(&p) != nil {
						t.Fatal("invalid payload")
					}
					if p.DTO.UnitID != "9007199254740993" || p.DTO.Page != tt.page || p.DTO.Finished != (tt.page == 2) || p.DTO.ContentType != 3 || p.DTO.LastLearnTime != 1700000000000 {
						t.Error("document semantics lost")
					}
					body = tt.body
					headers = http.Header{"Content-Type": {"application/json"}}
				}
				return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			err = c.ReportDocumentProgress(context.Background(), DocumentProgress{CourseID: "123", TermID: "456", LessonID: "789", UnitID: "9007199254740993", Index: 0, Page: tt.page, TotalPages: 2, ElapsedSeconds: 3, ObservedAt: time.UnixMilli(1700000000000)})
			if !errors.Is(err, tt.kind) || !posted {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestDocumentProgressInvalidInput(t *testing.T) {
	c, err := NewCookieClient(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.httpClient.Transport = profileTransport(func(*http.Request) (*http.Response, error) { t.Fatal("invalid input reached network"); return nil, nil })
	err = c.ReportDocumentProgress(context.Background(), DocumentProgress{})
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatal("invalid observation accepted")
	}
}

func TestDocumentCompletionRequiresReadback(t *testing.T) {
	for _, tt := range []struct {
		name                   string
		initial, after, writes int
		kind                   error
	}{
		{"verified", 0, 5, 1, nil},
		{"already learned", 5, 5, 0, nil},
		{"receipt without state change", 0, 0, 1, ErrRemoteRejected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewCookieClient(ClientOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			writes := 0
			c.httpClient.Transport = profileTransport(func(r *http.Request) (*http.Response, error) {
				body := `<script>window.webUser={id:"user-123",nickName:"Learner",loginId:"account-123"};</script>`
				headers := http.Header{"Content-Type": {"text/html"}, "Set-Cookie": {"NTESSTUDYSI=fixture; Path=/; Secure"}}
				if strings.Contains(r.URL.Path, "getLastLearnedMocTermDto") {
					status := tt.initial
					if writes > 0 {
						status = tt.after
					}
					body = fmt.Sprintf(`{"code":0,"result":{"mocTermDto":{"id":456,"chapters":[{"id":11,"name":"Chapter","lessons":[{"id":789,"name":"Lesson","units":[{"id":9007199254740993,"name":"Document","contentId":12,"contentType":3,"viewStatus":%d}]}]}]}}}`, status)
					headers = http.Header{"Content-Type": {"application/json"}}
				} else if strings.Contains(r.URL.Path, "saveMocContentLearn") {
					writes++
					var value struct {
						DTO struct {
							UnitID   json.Number `json:"unitId"`
							Finished bool        `json:"finished"`
							Page     int         `json:"pageNum"`
							Seconds  int         `json:"learnedVideoTimeCount"`
						} `json:"dto"`
					}
					if json.NewDecoder(r.Body).Decode(&value) != nil || value.DTO.UnitID != "9007199254740993" || !value.DTO.Finished || value.DTO.Page != 1 || value.DTO.Seconds != 0 {
						t.Fatal("invalid completion receipt")
					}
					body = `{"code":0,"result":true}`
					headers = http.Header{"Content-Type": {"application/json"}}
				} else if r.URL.Path != "/" {
					t.Fatal("unexpected endpoint")
				}
				return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			err = c.CompleteDocument(context.Background(), MOOCCourse{ID: "123", TermID: "456"}, MOOCLesson{ID: "789"}, MOOCUnit{ID: "9007199254740993", ContentID: "12", ContentType: 3})
			if !errors.Is(err, tt.kind) || writes != tt.writes {
				t.Fatalf("unexpected result: %v writes=%d", err, writes)
			}
		})
	}
}
