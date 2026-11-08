package zhihuishu

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const examBase = "https://studentexamtest.zhihuishu.com/gateway/t/v1"

type MasteryPoint struct {
	ID         string  `json:"knowledgeId"`
	Name       string  `json:"knowledgeName"`
	FreeExam   int     `json:"freeExam"`
	Percentage float64 `json:"masteryPercentage"`
}

type MasteryStatistics struct {
	Percentage float64 `json:"meanMasteryPercentage"`
	Themes     []struct {
		Points []MasteryPoint `json:"knowledgeList"`
	} `json:"themeList"`
}

type MasteryPaper struct {
	ID            string
	ExamTestID    string
	KnowledgeID   string
	QuestionCount int
}

type MasteryOption struct {
	ID      protocolID `json:"id"`
	Content string     `json:"content"`
	Sort    int        `json:"sort"`
}

type MasteryQuestion struct {
	ID       protocolID      `json:"id"`
	Content  string          `json:"content"`
	Type     int             `json:"questionType"`
	TypeName string          `json:"questionTypeName"`
	Options  []MasteryOption `json:"optionVos"`
}

type MasteryPaperStatus struct {
	State      int      `json:"examState"`
	Type       int      `json:"examType"`
	Score      *float64 `json:"score"`
	SubmitTime string   `json:"submitTime"`
}

type masterySheet struct {
	AnswerCount   int `json:"answerCount"`
	QuestionCount int `json:"questionCount"`
	Parts         []struct {
		Questions []struct {
			ID      protocolID `json:"questionId"`
			Version int        `json:"version"`
		} `json:"questionSheetVos"`
	} `json:"partSheetVos"`
}

func (c *Client) Mastery(ctx context.Context, course AICourse) (MasteryStatistics, error) {
	var result MasteryStatistics
	err := c.run(ctx, func(ctx context.Context) error {
		params, err := courseParams(course)
		if err != nil {
			return err
		}
		if _, err := c.currentUser(ctx); err != nil {
			return err
		}
		params["getListBool"] = true
		params["dateFormate"] = time.Now().UnixMilli()
		return c.aiRequest(ctx, "mastery statistics", "/stu/mastery-statistics/get-mastery-statistics", params, &result)
	})
	return result, err
}

func (c *Client) StartMasteryPaper(ctx context.Context, course AICourse, point MasteryPoint) (MasteryPaper, error) {
	paper := MasteryPaper{KnowledgeID: point.ID}
	open, err := c.StudyOpen(ctx, course)
	if err != nil {
		return paper, err
	}
	if !open {
		return paper, ErrStudyClosed
	}
	err = c.run(ctx, func(ctx context.Context) error {
		params, err := resourceParams(course, point.ID)
		if err != nil {
			return err
		}
		params["scMapId"] = course.ID
		params["dateFormate"] = time.Now().UnixMilli()
		var result struct {
			ID            protocolID `json:"paperId"`
			ExamTestID    protocolID `json:"examTestId"`
			QuestionCount int        `json:"questionNum"`
		}
		if err := c.aiRequest(ctx, "mastery create paper", "/stu/exam/questions-paper", params, &result); err != nil {
			return err
		}
		paper.ID, paper.ExamTestID, paper.QuestionCount = string(result.ID), string(result.ExamTestID), result.QuestionCount
		if paper.QuestionCount == 0 {
			return nil
		}
		if paper.ID == "" || paper.ExamTestID == "" {
			return ErrUnexpectedResponse
		}
		var opened bool
		if err := c.examRequest(ctx, "mastery open paper", http.MethodPost, "/exam/user/openExam", masteryPaperParams(course, paper), &opened); err != nil {
			return err
		}
		if !opened {
			return ErrRemoteRejected
		}
		return nil
	})
	return paper, err
}

func masteryPaperParams(course AICourse, paper MasteryPaper) map[string]any {
	return map[string]any{"courseId": course.ID, "examTestId": paper.ExamTestID, "examPaperId": paper.ID}
}

func (c *Client) MasteryQuestions(ctx context.Context, course AICourse, paper MasteryPaper) ([]MasteryQuestion, error) {
	var questions []MasteryQuestion
	err := c.run(ctx, func(ctx context.Context) error {
		params := masteryPaperParams(course, paper)
		var status MasteryPaperStatus
		if err := c.examRequest(ctx, "mastery paper status", http.MethodGet, "/exam/user/getExamTestUserInfo", params, &status); err != nil {
			return err
		}
		if status.Type != 5 || status.SubmitTime != "" {
			return ErrRemoteRejected
		}
		var sheet masterySheet
		if err := c.examRequest(ctx, "mastery question list", http.MethodGet, "/exam/user/getExamSheetInfo", params, &sheet); err != nil {
			return err
		}
		for _, part := range sheet.Parts {
			for _, item := range part.Questions {
				var question MasteryQuestion
				args := masteryPaperParams(course, paper)
				args["questionId"], args["version"] = item.ID, item.Version
				if err := c.examRequest(ctx, "mastery question detail", http.MethodGet, "/question/getExamQuestionInfo", args, &question); err != nil {
					return err
				}
				if question.ID != item.ID {
					return ErrUnexpectedResponse
				}
				questions = append(questions, question)
			}
		}
		if len(questions) != sheet.QuestionCount {
			return ErrUnexpectedResponse
		}
		return nil
	})
	return questions, err
}

func (c *Client) SaveMasteryAnswer(ctx context.Context, course AICourse, paper MasteryPaper, question MasteryQuestion, answer string) error {
	return c.run(ctx, func(ctx context.Context) error {
		params := masteryPaperParams(course, paper)
		params["recruitId"], params["questionId"], params["answer"], params["dataVos"] = course.ID, question.ID, answer, nil
		var accepted bool
		if err := c.examRequest(ctx, "mastery save answer", http.MethodPost, "/answer/saveAnswer", params, &accepted); err != nil {
			return err
		}
		if !accepted {
			return ErrRemoteRejected
		}
		return nil
	})
}

func (c *Client) SubmitMasteryPaper(ctx context.Context, course AICourse, paper MasteryPaper) (MasteryPaperStatus, error) {
	var status MasteryPaperStatus
	err := c.run(ctx, func(ctx context.Context) error {
		params := masteryPaperParams(course, paper)
		var sheet masterySheet
		if err := c.examRequest(ctx, "mastery verify saved answers", http.MethodGet, "/exam/user/getExamSheetInfo", params, &sheet); err != nil {
			return err
		}
		if sheet.AnswerCount != paper.QuestionCount || sheet.QuestionCount != paper.QuestionCount {
			return ErrRemoteRejected
		}
		params["courseType"], params["aiKnlowledgeId"] = 2, paper.KnowledgeID
		var result json.RawMessage
		if err := c.examRequest(ctx, "mastery submit", http.MethodPost, "/exam/user/submit", params, &result); err != nil {
			return err
		}
		if err := c.examRequest(ctx, "mastery submitted status", http.MethodGet, "/exam/user/getExamTestUserInfo", masteryPaperParams(course, paper), &status); err != nil {
			return err
		}
		if status.SubmitTime == "" {
			return ErrUnexpectedResponse
		}
		return nil
	})
	return status, err
}

func (c *Client) examRequest(ctx context.Context, operation, method, path string, params any, result any) error {
	if len(c.examKey) == 0 {
		pub, err := sessionPublicKey()
		if err != nil {
			return err
		}
		key, err := c.requestModuleKey(ctx, pub, 3)
		if err != nil {
			return err
		}
		c.examKey = key
	}
	secret, err := encryptPayload(params, c.examKey, c.iv)
	if err != nil {
		return err
	}
	form := url.Values{"secretStr": {secret}, "date": {strconv.FormatInt(time.Now().UnixMilli(), 10)}}
	target := examBase + path
	var body []byte
	if method == http.MethodGet {
		target += "?" + form.Encode()
	} else {
		body = []byte(form.Encode())
	}
	var response struct {
		Code *int            `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Referer": {"https://studentexamcomh5.zhihuishu.com/"}}
	if err := c.request(ctx, operation, method, target, body, headers, &response); err != nil {
		return err
	}
	if response.Code == nil {
		return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
	}
	if *response.Code != 0 {
		if *response.Code == 4003 {
			return &RequestError{Operation: operation, Kind: ErrNeedsUserAction}
		}
		if *response.Code == 401 || *response.Code == 403 {
			return c.authenticationError(operation)
		}
		return &RequestError{Operation: operation, Kind: ErrRemoteRejected}
	}
	if result != nil && json.Unmarshal(response.Data, result) != nil {
		return &RequestError{Operation: operation, Kind: ErrUnexpectedResponse}
	}
	return nil
}
