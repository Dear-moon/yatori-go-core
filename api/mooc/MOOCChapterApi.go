package mooc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type MOOCChapter struct {
	ID      string
	Name    string
	Lessons []MOOCLesson
}
type MOOCLesson struct {
	ID    string
	Name  string
	Units []MOOCUnit
}
type MOOCUnit struct {
	ID              string
	ContentID       string
	Name            string
	ContentType     int
	DurationSeconds *int
	ViewStatus      *int
}
type chapterDTO struct {
	ID      protocolID `json:"id"`
	Name    string     `json:"name"`
	Lessons []struct {
		ID    protocolID `json:"id"`
		Name  string     `json:"name"`
		Units []struct {
			ID          protocolID `json:"id"`
			ContentID   protocolID `json:"contentId"`
			Name        string     `json:"name"`
			ContentType *int       `json:"contentType"`
			Duration    *int       `json:"durationInSeconds"`
			ViewStatus  *int       `json:"viewStatus"`
		} `json:"units"`
	} `json:"lessons"`
}

// Chapters returns the server-visible curriculum for an enrolled term.
func (c *MOOCClient) Chapters(ctx context.Context, termID string) ([]MOOCChapter, error) {
	var chapters []MOOCChapter
	err := c.run(ctx, func(ctx context.Context) error {
		if termID == "" {
			return &RequestError{Operation: "chapters term", Kind: ErrUnexpectedResponse}
		}
		if _, err := c.currentUser(ctx); err != nil {
			return err
		}
		var result struct {
			Term *struct {
				ID       protocolID    `json:"id"`
				Chapters *[]chapterDTO `json:"chapters"`
			} `json:"mocTermDto"`
		}
		if err := c.formRPC(ctx, "chapters", "web/j/courseBean.getLastLearnedMocTermDto.rpc", url.Values{"termId": {termID}}, &result); err != nil {
			return err
		}
		invalid := &RequestError{Operation: "chapters schema", Kind: ErrUnexpectedResponse}
		if result.Term == nil || string(result.Term.ID) != termID || result.Term.Chapters == nil {
			return invalid
		}
		chapters = make([]MOOCChapter, 0, len(*result.Term.Chapters))
		seen := make(map[string]bool)
		for _, ch := range *result.Term.Chapters {
			if ch.ID == "" || ch.Name == "" {
				return invalid
			}
			chapter := MOOCChapter{ID: string(ch.ID), Name: ch.Name, Lessons: make([]MOOCLesson, 0, len(ch.Lessons))}
			for _, le := range ch.Lessons {
				if le.ID == "" || le.Name == "" {
					return invalid
				}
				lesson := MOOCLesson{ID: string(le.ID), Name: le.Name, Units: make([]MOOCUnit, 0, len(le.Units))}
				for _, un := range le.Units {
					if un.ID == "" || un.ContentID == "" || un.Name == "" || un.ContentType == nil || *un.ContentType <= 0 || (un.Duration != nil && *un.Duration < 0) || seen[string(un.ID)] {
						return invalid
					}
					seen[string(un.ID)] = true
					lesson.Units = append(lesson.Units, MOOCUnit{ID: string(un.ID), ContentID: string(un.ContentID), Name: un.Name, ContentType: *un.ContentType, DurationSeconds: un.Duration, ViewStatus: un.ViewStatus})
				}
				chapter.Lessons = append(chapter.Lessons, lesson)
			}
			chapters = append(chapters, chapter)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return chapters, nil
}

func (c *MOOCClient) formRPC(ctx context.Context, operation, path string, params url.Values, result any) error {
	token := c.csrfCookie()
	if token == "" {
		return &RequestError{Operation: operation + " CSRF", Kind: ErrUnexpectedResponse}
	}
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "edu-script-token": {token}, "Referer": {siteURL}}
	body, err := c.requestWithHeaders(ctx, operation, http.MethodPost, siteURL+path+"?"+url.Values{"csrfKey": {token}}.Encode(), []byte(params.Encode()), true, headers)
	if err != nil {
		return err
	}
	var envelope struct {
		Code   *int            `json:"code"`
		Result json.RawMessage `json:"result"`
	}
	if err := decodeResponse(operation, body, &envelope); err != nil {
		return err
	}
	if envelope.Code == nil {
		return &RequestError{Operation: operation + " schema", Kind: ErrUnexpectedResponse}
	}
	if *envelope.Code == 1 {
		return c.unauthenticated(operation)
	}
	if *envelope.Code != 0 {
		return &RequestError{Operation: operation, Kind: ErrRemoteRejected}
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return &RequestError{Operation: operation + " result", Kind: ErrUnexpectedResponse}
	}
	return decodeResponse(operation, envelope.Result, result)
}
