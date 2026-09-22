package mooc

import (
	"context"
	"encoding/json"
	"time"
)

// DocumentProgress records an observed page and its elapsed reading time.
type DocumentProgress struct {
	CourseID       string
	TermID         string
	LessonID       string
	UnitID         string
	Index          int
	Page           int
	TotalPages     int
	ElapsedSeconds int
	ObservedAt     time.Time
}

// ReportDocumentProgress requires a positive receipt; the last page determines completion.
func (c *MOOCClient) ReportDocumentProgress(ctx context.Context, progress DocumentProgress) error {
	return c.run(ctx, func(ctx context.Context) error {
		invalid := &RequestError{Operation: "document progress input", Kind: ErrUnexpectedResponse}
		for _, id := range []string{progress.CourseID, progress.TermID, progress.LessonID, progress.UnitID} {
			if !integerID.MatchString(id) || id[0] == '0' {
				return invalid
			}
		}
		if progress.Index < 0 || progress.Page < 1 || progress.TotalPages < progress.Page || progress.ElapsedSeconds < 0 || progress.ObservedAt.IsZero() || progress.ObservedAt.UnixMilli() <= 0 {
			return invalid
		}
		if _, err := c.currentUser(ctx); err != nil {
			return err
		}
		dto := struct {
			UnitID         json.Number `json:"unitId"`
			Finished       bool        `json:"finished"`
			ContentType    int         `json:"contentType"`
			Index          int         `json:"index"`
			Page           int         `json:"pageNum"`
			CourseID       json.Number `json:"courseId"`
			LessonID       json.Number `json:"lessonId"`
			TermID         json.Number `json:"termId"`
			LastLearnTime  int64       `json:"lastLearnTime"`
			LearnedSeconds int         `json:"learnedVideoTimeCount"`
		}{json.Number(progress.UnitID), progress.Page == progress.TotalPages, 3, progress.Index, progress.Page, json.Number(progress.CourseID), json.Number(progress.LessonID), json.Number(progress.TermID), progress.ObservedAt.UnixMilli(), progress.ElapsedSeconds}
		payload, err := json.Marshal(struct {
			DTO any `json:"dto"`
		}{dto})
		if err != nil {
			return invalid
		}
		return c.reportContentProgress(ctx, "document progress", payload)
	})
}
