package zhihuishu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestResourceKind(t *testing.T) {
	for _, tt := range []struct {
		name     string
		resource Resource
		want     ResourceKind
	}{
		{"book", Resource{DataType: 21}, ResourceBook},
		{"shared data type PPT", Resource{DataType: 11, FileSuffix: "pptx", QuoteFileType: 2}, ResourcePPT},
		{"normalized PPT", Resource{DataType: 11, FileSuffix: " .PPT "}, ResourcePPT},
		{"video", Resource{DataType: 11, FileSuffix: "mp4", QuoteFileType: 1}, ResourceVideo},
		{"quoted video without suffix", Resource{DataType: 11, QuoteFileType: 1}, ResourceVideo},
		{"unknown generic file", Resource{DataType: 11}, ResourceUnknown},
		{"PDF is not video", Resource{DataType: 11, FileSuffix: "pdf"}, ResourceUnknown},
		{"conflicting video quote", Resource{DataType: 11, FileSuffix: "mp4", QuoteFileType: 2}, ResourceUnknown},
		{"conflicting PPT quote", Resource{DataType: 11, FileSuffix: "pptx", QuoteFileType: 1}, ResourceUnknown},
		{"unhandled resource type", Resource{DataType: 12, FileSuffix: "pptx"}, ResourceUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.resource.Kind(); got != tt.want {
				t.Fatalf("kind=%s want=%s", got, tt.want)
			}
		})
	}
}

func TestPPTNeverEntersVideoFlow(t *testing.T) {
	c, _ := NewClient(ClientOptions{})
	defer c.Close()
	c.httpClient.Transport = offlineTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("PPT reached a video endpoint")
		return nil, nil
	})
	err := c.StudyVideo(context.Background(), AICourse{ID: "course", ClassID: "class"}, "point", Resource{ID: "resource", FileID: "file", DataType: 11, FileSuffix: "pptx", QuoteFileType: 2}, nil)
	if !errors.Is(err, ErrUnsupportedResource) {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestPPTPreviewReceipt(t *testing.T) {
	static := `{"pptCutType":0,"pptPageList":[{"pptPageSeq":2,"pptPageUrl":"https://example.invalid/2.jpg"},{"pptPageSeq":4,"pptPageUrl":"https://example.invalid/4.jpg"}]}`
	dynamic := `{"pptCutType":1,"pptDynamicStatus":1,"pptDynamicParam":"{\"pageCount\":62,\"format\":\"h5\",\"resultUrl\":\"https://example.invalid/slides/\"}"}`
	for _, tt := range []struct {
		name, preview string
		kind          error
		writes        int
	}{
		{"static", static, nil, 1},
		{"dynamic", dynamic, nil, 1},
		{"already complete", static, nil, 0},
		{"closed", static, ErrStudyClosed, 0},
		{"resource changed", static, ErrUnsupportedResource, 0},
		{"converting", `{"pptCutType":1,"pptDynamicStatus":0}`, ErrUnsupportedResource, 0},
		{"missing quoted page", `{"pptCutType":0,"pptPageList":[{"pptPageSeq":2,"pptPageUrl":"https://example.invalid/2.jpg"}]}`, ErrUnsupportedResource, 0},
		{"invalid page URL", `{"pptCutType":0,"pptPageList":[{"pptPageSeq":2,"pptPageUrl":"javascript:void(0)"}]}`, ErrUnsupportedResource, 0},
		{"missing schema", `{}`, ErrUnexpectedResponse, 0},
		{"invalid dynamic", `{"pptCutType":1,"pptDynamicStatus":1,"pptDynamicParam":"{}"}`, ErrUnexpectedResponse, 0},
		{"rejected", static, ErrRemoteRejected, 1},
		{"not confirmed", static, ErrRemoteRejected, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := NewClient(ClientOptions{})
			defer c.Close()
			session := testSession()
			writes, reads := 0, 0
			c.httpClient.Transport = offlineTransport(func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "getLoginUserInfo") {
					return jsonResponse(r, profileFixture), nil
				}
				var envelope struct {
					Secret string `json:"secretStr"`
				}
				if json.NewDecoder(r.Body).Decode(&envelope) != nil {
					t.Fatal("invalid request envelope")
				}
				params := decryptFixture(t, envelope.Secret, session.AIKey, session.IV)
				if params["courseId"] != "course" || params["classId"] != "class" {
					t.Fatal("course context lost")
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/is-end-study"):
					return jsonResponse(r, fmt.Sprintf(`{"code":200,"data":%t}`, tt.name == "closed")), nil
				case strings.HasSuffix(r.URL.Path, "/list-knowledge-resource"):
					reads++
					status, suffix := 0, "pptx"
					if tt.name == "already complete" || (writes == 1 && tt.name != "not confirmed") {
						status = 1
					}
					if tt.name == "resource changed" {
						suffix = "mp4"
					}
					return jsonResponse(r, fmt.Sprintf(`{"code":200,"data":{"resourceList":[{"resourcesDetail":{"resourcesUid":"resource","resourcesName":"Slides","resourcesFileId":"file","resourcesDataType":11,"resourcesLocalType":1,"resourcesSuffix":%q},"resourcesQuoteDetail":{"fileType":2,"pptPageSeqs":[2,4]},"studyStatus":%d}]}}`, suffix, status)), nil
				case strings.HasSuffix(r.URL.Path, "/get-ppt-detail-v2"):
					if tt.name == "already complete" || params["resourcesUid"] != "resource" || params["nodeUid"] != "point" {
						t.Fatal("unexpected preview request")
					}
					return jsonResponse(r, `{"code":200,"data":`+tt.preview+`}`), nil
				case strings.HasSuffix(r.URL.Path, "/completed"):
					writes++
					if writes > 1 || params["resourcesUid"] != "resource" || params["knowledgeId"] != "point" || params["watchUId"] != float64(1) {
						t.Fatal("invalid or repeated receipt")
					}
					if _, exists := params["nodeUid"]; exists {
						t.Fatal("preview-only field in receipt")
					}
					if tt.name == "rejected" {
						return jsonResponse(r, `{"code":500,"data":null}`), nil
					}
					return jsonResponse(r, `{"code":200,"data":null}`), nil
				default:
					t.Fatal("PPT reached an unrelated endpoint")
					return nil, nil
				}
			})
			ctx := context.Background()
			if _, err := c.LoginBrowserSession(ctx, session); err != nil {
				t.Fatal(err)
			}
			err := c.CompletePPT(ctx, AICourse{ID: "course", ClassID: "class"}, "point", Resource{ID: "resource", DataType: 11, FileSuffix: "pptx"})
			if !errors.Is(err, tt.kind) || writes != tt.writes {
				t.Fatalf("result=%v writes=%d want=%v/%d", err, writes, tt.kind, tt.writes)
			}
			if (tt.name == "static" || tt.name == "dynamic" || tt.name == "not confirmed") && reads != 2 {
				t.Fatal("receipt did not recheck server completion")
			}
		})
	}
}
