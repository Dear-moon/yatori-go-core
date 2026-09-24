package zhihuishu

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type offlineTransport func(*http.Request) (*http.Response, error)

func (f offlineTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testSession() BrowserSession {
	return BrowserSession{Cookies: []*http.Cookie{{Name: "fixture", Value: "synthetic-session", Domain: ".zhihuishu.com", Path: "/", Secure: true}}, AIKey: []byte("0123456789abcdef"), CourseKey: []byte("fedcba9876543210"), IV: []byte("0000000000000000")}
}
func jsonResponse(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

const profileFixture = `{"code":200,"result":{"uuid":"user-123","realName":"ignored"}}`

func TestBrowserSessionVerification(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		kind       error
	}{
		{"verified", profileFixture, nil},
		{"not logged in", `{"code":403,"result":null}`, ErrAuthenticationFailed},
		{"missing identity", `{"code":200,"result":{}}`, ErrUnexpectedResponse},
		{"missing code", `{"result":{"uuid":"user-123"}}`, ErrUnexpectedResponse},
		{"malformed", `{"code":`, ErrUnexpectedResponse},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(ClientOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) {
				if _, err := r.Cookie("fixture"); err != nil {
					t.Fatal("imported cookie missing")
				}
				return jsonResponse(r, tt.body), nil
			})
			input := testSession()
			user, err := c.LoginBrowserSession(context.Background(), input)
			if !errors.Is(err, tt.kind) {
				t.Fatalf("unexpected error %v", err)
			}
			if tt.kind == nil {
				if user == nil || user.ID != "user-123" {
					t.Fatal("identity mismatch")
				}
				input.AIKey[0] = 'x'
				if c.aiKey[0] == 'x' {
					t.Fatal("caller key aliases client")
				}
				other, _ := NewClient(ClientOptions{})
				defer other.Close()
				u, _ := url.Parse(onlineBase)
				if len(other.httpClient.Jar.Cookies(u)) != 0 {
					t.Fatal("global cookie state")
				}
			} else {
				u, _ := url.Parse(onlineBase)
				if user != nil || c.user != nil || len(c.httpClient.Jar.Cookies(u)) != 0 || len(c.aiKey) != 0 {
					t.Fatal("failed session retained")
				}
			}
		})
	}
}
func TestExpiredSessionAndCancellation(t *testing.T) {
	c, _ := NewClient(ClientOptions{})
	defer c.Close()
	calls := 0
	c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(r, profileFixture), nil
		}
		return jsonResponse(r, `{"code":403,"result":null}`), nil
	})
	if _, err := c.LoginBrowserSession(context.Background(), testSession()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CurrentUser(context.Background()); !errors.Is(err, ErrSessionExpired) {
		t.Fatal("session expiry not distinguished")
	}
	for _, timeout := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if timeout {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
		} else {
			cancel()
		}
		c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
		_, err := c.CurrentUser(ctx)
		cancel()
		expected := context.Canceled
		if timeout {
			expected = context.DeadlineExceeded
		}
		if !errors.Is(err, expected) {
			t.Fatalf("context semantics lost: %v", err)
		}
	}
}
func TestInvalidCookiesNeverReachNetwork(t *testing.T) {
	c, _ := NewClient(ClientOptions{})
	defer c.Close()
	c.httpClient.Transport = offlineTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid session reached network")
		return nil, nil
	})
	for _, domain := range []string{"evil.example", "zhihuishu.com.evil.example"} {
		s := testSession()
		s.Cookies[0].Domain = domain
		if _, err := c.LoginBrowserSession(context.Background(), s); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatal("unrelated cookie accepted")
		}
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", testSession(), testSession()), "synthetic-session") {
		t.Fatal("session formatting leaks credentials")
	}
}
func decryptFixture(t *testing.T, secret string, key, iv []byte) map[string]any {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(secret)
	if err != nil || len(data) == 0 || len(data)%16 != 0 {
		t.Fatal("invalid encrypted payload")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data, data)
	pad := int(data[len(data)-1])
	if pad < 1 || pad > 16 {
		t.Fatal("invalid padding")
	}
	var value map[string]any
	if json.Unmarshal(data[:len(data)-pad], &value) != nil {
		t.Fatal("invalid plaintext schema")
	}
	return value
}
func TestAICourseReadFlow(t *testing.T) {
	c, _ := NewClient(ClientOptions{})
	defer c.Close()
	session := testSession()
	c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "getLoginUserInfo") {
			return jsonResponse(r, profileFixture), nil
		}
		if strings.Contains(r.URL.Path, "queryStudentAICourseList") {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			decryptFixture(t, r.Form.Get("secretStr"), session.CourseKey, session.IV)
			return jsonResponse(r, `{"status":"200","rt":[{"courseId":"9007199254740993","classId":9007199254740995,"courseName":"Course"}]}`), nil
		}
		var encrypted struct {
			Secret string `json:"secretStr"`
		}
		if json.NewDecoder(r.Body).Decode(&encrypted) != nil {
			t.Fatal("invalid encrypted envelope")
		}
		params := decryptFixture(t, encrypted.Secret, session.AIKey, session.IV)
		if params["courseId"] != "9007199254740993" || params["classId"] != "9007199254740995" {
			t.Fatal("identifier lost")
		}
		if r.Header.Get("XQJZXHIZ") == "" {
			t.Fatal("map header missing")
		}
		switch {
		case strings.Contains(r.URL.Path, "list-knowledge-theme"):
			return jsonResponse(r, `{"code":200,"data":{"courseThemeList":[{"themeId":"module-1","themeName":"Module","subThemeList":[{"themeId":"unit-1","themeName":"Unit","knowledgeList":[{"knowledgeId":"point-1","knowledgeName":"Point"}]}]}]}}`), nil
		case strings.Contains(r.URL.Path, "list-knowledge-resource"):
			return jsonResponse(r, `{"code":200,"data":{"resourceList":[{"resourcesDetail":{"resourcesUid":"resource-1","resourcesName":"Book","resourcesFileId":"file-1","resourcesDataType":21,"resourcesTime":""},"resourcesBookDetail":{"mdContent":null,"pageList":[{}]},"studyStatus":0}]}}`), nil
		case strings.Contains(r.URL.Path, "is-end-study"):
			return jsonResponse(r, `{"code":200,"data":false}`), nil
		default:
			t.Fatal("unexpected endpoint")
			return nil, nil
		}
	})
	if _, err := c.LoginBrowserSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	courses, err := c.AICourses(context.Background())
	if err != nil || len(courses) != 1 {
		t.Fatalf("course read failed %v", err)
	}
	modules, err := c.Knowledge(context.Background(), courses[0])
	if err != nil || len(modules) != 1 {
		t.Fatalf("knowledge read failed %v", err)
	}
	resources, err := c.Resources(context.Background(), courses[0], "point-1")
	if err != nil || len(resources) != 1 || !resources[0].HasBookContent {
		t.Fatalf("resources read failed %v", err)
	}
	open, err := c.StudyOpen(context.Background(), courses[0])
	if err != nil || !open {
		t.Fatalf("availability failed %v", err)
	}
}

func TestProtocolID(t *testing.T) {
	for _, input := range []string{`"9007199254740995"`, `9007199254740995`} {
		var id protocolID
		if err := json.Unmarshal([]byte(input), &id); err != nil || string(id) != "9007199254740995" {
			t.Fatal("identifier precision lost")
		}
	}
	for _, input := range []string{`null`, `1.5`, `true`, `{}`, `-1`} {
		var id protocolID
		if json.Unmarshal([]byte(input), &id) == nil {
			t.Fatal("invalid identifier accepted")
		}
	}
}

func TestVideoTimingAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprint(canceled), func(t *testing.T) {
			c, _ := NewClient(ClientOptions{})
			defer c.Close()
			session := testSession()
			writes := 0
			started := time.Now()
			c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) {
				switch {
				case strings.Contains(r.URL.Path, "getLoginUserInfo"):
					return jsonResponse(r, profileFixture), nil
				case strings.Contains(r.URL.Path, "is-end-study"):
					return jsonResponse(r, `{"code":200,"data":false}`), nil
				case strings.Contains(r.URL.Path, "get-node-resources-detail"):
					return jsonResponse(r, `{"code":200,"data":{"resourcesQuoteDetail":{"videoStartTime":"17000","videoEndTime":"19000"}}}`), nil
				case strings.Contains(r.URL.Path, "get-video-time"):
					return jsonResponse(r, `{"code":200,"data":[{"videoId":123,"time":30}]}`), nil
				case strings.Contains(r.URL.Path, "get-knowledge-video-time"):
					return jsonResponse(r, `{"code":200,"data":{"resource":1}}`), nil
				case strings.Contains(r.URL.Path, "initVideoNew"):
					return jsonResponse(r, `{"successful":true,"result":{"lines":[{"lineUrl":"https://example.invalid/video"}]}}`), nil
				case strings.HasSuffix(r.URL.Path, "/study"), strings.HasSuffix(r.URL.Path, "/report"):
					if time.Since(started) < time.Second {
						t.Fatal("progress sent before elapsed interval")
					}
					var envelope struct {
						Secret string `json:"secretStr"`
					}
					if json.NewDecoder(r.Body).Decode(&envelope) != nil {
						t.Fatal("invalid request")
					}
					params := decryptFixture(t, envelope.Secret, session.AIKey, session.IV)
					if params["lastWatchTime"] != float64(19) {
						t.Fatal("clip position mismatch")
					}
					if params["studyTime"] != float64(1) && params["studyTotalTime"] != float64(1) {
						t.Fatal("elapsed time mismatch")
					}
					writes++
					return jsonResponse(r, `{"code":200,"data":null}`), nil
				default:
					t.Fatal("unexpected request")
					return nil, nil
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if _, err := c.LoginBrowserSession(ctx, session); err != nil {
				t.Fatal(err)
			}
			err := c.StudyVideo(ctx, AICourse{ID: "course", ClassID: "class"}, "point", Resource{ID: "resource", FileID: "123", DataType: 11, FileSuffix: "mp4"}, func(position, total int) {
				if position < 18 || total != 19 {
					t.Fatal("resource duration was not mapped to clip position")
				}
				if canceled {
					cancel()
				}
			})
			if canceled {
				if !errors.Is(err, context.Canceled) || writes != 0 {
					t.Fatal("cancellation wrote progress")
				}
			} else if err != nil || writes != 2 {
				t.Fatalf("report flow failed: %v, writes=%d", err, writes)
			}
		})
	}
}

func TestClosedCourseDoesNotWriteProgress(t *testing.T) {
	c, _ := NewClient(ClientOptions{})
	defer c.Close()
	c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "getLoginUserInfo") {
			return jsonResponse(r, profileFixture), nil
		}
		if strings.Contains(r.URL.Path, "is-end-study") {
			return jsonResponse(r, `{"code":200,"data":true}`), nil
		}
		t.Fatal("closed course reached a resource or progress endpoint")
		return nil, nil
	})
	ctx := context.Background()
	if _, err := c.LoginBrowserSession(ctx, testSession()); err != nil {
		t.Fatal(err)
	}
	course := AICourse{ID: "course", ClassID: "class"}
	if err := c.StudyVideo(ctx, course, "point", Resource{ID: "resource", FileID: "123", DataType: 11, FileSuffix: "mp4"}, nil); !errors.Is(err, ErrStudyClosed) {
		t.Fatalf("unexpected result: %v", err)
	}
	if err := c.CompleteBook(ctx, course, "point", Resource{ID: "book", DataType: 21}); !errors.Is(err, ErrStudyClosed) {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestBookRefetchesContentBeforeReceipt(t *testing.T) {
	c, _ := NewClient(ClientOptions{})
	defer c.Close()
	c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.Path, "getLoginUserInfo"):
			return jsonResponse(r, profileFixture), nil
		case strings.Contains(r.URL.Path, "is-end-study"):
			return jsonResponse(r, `{"code":200,"data":false}`), nil
		case strings.Contains(r.URL.Path, "list-knowledge-resource"):
			return jsonResponse(r, `{"code":200,"data":{"resourceList":[{"resourcesDetail":{"resourcesUid":"book","resourcesName":"Book","resourcesDataType":21},"resourcesBookDetail":{"mdContent":null,"pageList":[]},"studyStatus":0}]}}`), nil
		default:
			t.Fatal("missing book content produced a completion write")
			return nil, nil
		}
	})
	ctx := context.Background()
	if _, err := c.LoginBrowserSession(ctx, testSession()); err != nil {
		t.Fatal(err)
	}
	err := c.CompleteBook(ctx, AICourse{ID: "course", ClassID: "class"}, "point", Resource{ID: "book", DataType: 21, HasBookContent: true})
	if !errors.Is(err, ErrUnsupportedResource) {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestRejectedVideoReceiptStopsReporting(t *testing.T) {
	c, _ := NewClient(ClientOptions{})
	defer c.Close()
	writes := 0
	callbacks := 0
	c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.Path, "getLoginUserInfo"):
			return jsonResponse(r, profileFixture), nil
		case strings.Contains(r.URL.Path, "is-end-study"):
			return jsonResponse(r, `{"code":200,"data":false}`), nil
		case strings.Contains(r.URL.Path, "get-node-resources-detail"):
			return jsonResponse(r, `{"code":200,"data":{}}`), nil
		case strings.Contains(r.URL.Path, "get-video-time"):
			return jsonResponse(r, `{"code":200,"data":[{"videoId":123,"time":1}]}`), nil
		case strings.Contains(r.URL.Path, "get-knowledge-video-time"):
			return jsonResponse(r, `{"code":200,"data":{}}`), nil
		case strings.Contains(r.URL.Path, "initVideoNew"):
			return jsonResponse(r, `{"successful":true,"result":{"lines":[{"lineUrl":"https://example.invalid/video"}]}}`), nil
		case strings.HasSuffix(r.URL.Path, "/study"):
			writes++
			return jsonResponse(r, `{"code":500,"data":null}`), nil
		default:
			t.Fatal("rejected receipt was retried or followed by a report")
			return nil, nil
		}
	})
	ctx := context.Background()
	if _, err := c.LoginBrowserSession(ctx, testSession()); err != nil {
		t.Fatal(err)
	}
	err := c.StudyVideo(ctx, AICourse{ID: "course", ClassID: "class"}, "point", Resource{ID: "resource", FileID: "123", DataType: 11, FileSuffix: "mp4"}, func(int, int) { callbacks++ })
	if !errors.Is(err, ErrRemoteRejected) || writes != 1 || callbacks != 1 {
		t.Fatalf("unexpected result: %v writes=%d callbacks=%d", err, writes, callbacks)
	}
}

func TestUnavailableVideoDoesNotWriteProgress(t *testing.T) {
	c, _ := NewClient(ClientOptions{})
	defer c.Close()
	c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.Path, "getLoginUserInfo"):
			return jsonResponse(r, profileFixture), nil
		case strings.Contains(r.URL.Path, "is-end-study"):
			return jsonResponse(r, `{"code":200,"data":false}`), nil
		case strings.Contains(r.URL.Path, "get-node-resources-detail"):
			return jsonResponse(r, `{"code":200,"data":{"resourcesQuoteDetail":{"videoStartTime":"","videoEndTime":""}}}`), nil
		case strings.Contains(r.URL.Path, "get-video-time"):
			return jsonResponse(r, `{"code":200,"data":[{"videoId":123,"time":0}]}`), nil
		default:
			t.Fatal("unavailable video reached a playback or progress endpoint")
			return nil, nil
		}
	})
	ctx := context.Background()
	if _, err := c.LoginBrowserSession(ctx, testSession()); err != nil {
		t.Fatal(err)
	}
	err := c.StudyVideo(ctx, AICourse{ID: "course", ClassID: "class"}, "point", Resource{ID: "resource", FileID: "123", DataType: 11, FileSuffix: "mp4"}, nil)
	if !errors.Is(err, ErrUnsupportedResource) {
		t.Fatalf("unexpected result: %v", err)
	}
}
