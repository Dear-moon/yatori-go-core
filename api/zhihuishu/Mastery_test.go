package zhihuishu

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type masteryTransport func(*http.Request) (*http.Response, error)

func (f masteryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func masteryTestClient(t *testing.T, handler func(*http.Request) string) *Client {
	t.Helper()
	c, err := NewClient(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.examKey = []byte("0123456789abcdef")
	c.iv = []byte("0123456789abcdef")
	c.httpClient.Transport = masteryTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(handler(r)))}, nil
	})
	return c
}

func TestMasteryExamResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       error
	}{
		{"accepted", `{"code":0,"data":true}`, nil},
		{"nonzero", `{"code":200,"data":true}`, ErrRemoteRejected},
		{"verification", `{"code":4003,"data":null}`, ErrNeedsUserAction},
		{"schema", `{"data":true}`, ErrUnexpectedResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := masteryTestClient(t, func(r *http.Request) string {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				expected, _ := encryptPayload(map[string]string{"answer": "12#@#34"}, cKey(), cKey())
				if r.Form.Get("secretStr") != expected {
					t.Fatal("answer payload was not encrypted as an exam request")
				}
				return tc.body
			})
			var accepted bool
			err := c.examRequest(context.Background(), "test", http.MethodPost, "/answer/saveAnswer", map[string]string{"answer": "12#@#34"}, &accepted)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v; want %v", err, tc.want)
			}
		})
	}
}
func cKey() []byte { return []byte("0123456789abcdef") }

func TestMasteryRejectsIncompletePaper(t *testing.T) {
	c := masteryTestClient(t, func(r *http.Request) string {
		if r.URL.Path != "/gateway/t/v1/exam/user/getExamSheetInfo" {
			t.Fatalf("unexpected mutation: %s", r.URL.Path)
		}
		return `{"code":0,"data":{"answerCount":1,"questionCount":2}}`
	})
	_, err := c.SubmitMasteryPaper(context.Background(), AICourse{ID: "1", ClassID: "2"}, MasteryPaper{ID: "3", ExamTestID: "4", KnowledgeID: "5", QuestionCount: 2})
	if !errors.Is(err, ErrRemoteRejected) {
		t.Fatalf("incomplete paper error = %v", err)
	}
}

func TestMasteryQuestionIDs(t *testing.T) {
	var q MasteryQuestion
	if err := json.Unmarshal([]byte(`{"id":42,"questionType":14,"optionVos":[{"id":"123","content":"对"}]}`), &q); err != nil {
		t.Fatal(err)
	}
	if string(q.ID) != "42" || string(q.Options[0].ID) != "123" {
		t.Fatal("numeric and string IDs were not preserved")
	}
}

func TestMasteryUsesActualQuestionSheet(t *testing.T) {
	c := masteryTestClient(t, func(r *http.Request) string {
		switch r.URL.Path {
		case "/gateway/t/v1/exam/user/getExamTestUserInfo":
			return `{"code":0,"data":{"examType":5,"examState":3}}`
		case "/gateway/t/v1/exam/user/getExamSheetInfo":
			return `{"code":0,"data":{"questionCount":1,"partSheetVos":[{"questionSheetVos":[{"questionId":21,"version":1}]}]}}`
		case "/gateway/t/v1/question/getExamQuestionInfo":
			return `{"code":0,"data":{"id":21,"questionType":1}}`
		default:
			t.Fatalf("unexpected request: %s", r.URL.Path)
			return ""
		}
	})
	questions, err := c.MasteryQuestions(context.Background(), AICourse{ID: "1", ClassID: "2"}, MasteryPaper{ID: "3", ExamTestID: "4", QuestionCount: 8})
	if err != nil || len(questions) != 1 {
		t.Fatalf("actual sheet = %d questions, %v", len(questions), err)
	}
}
