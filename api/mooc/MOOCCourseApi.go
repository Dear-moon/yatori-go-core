package mooc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
)

const courseListPath = "web/j/learnerCourseRpcBean.getMyLearnedCoursePanelList.rpc"
const maxCoursePages = 1000

type MOOCCourse struct {
	ID     string
	TermID string
	Name   string
	School string
}
type protocolID string

var integerID = regexp.MustCompile(`^[0-9]+$`)

func (id *protocolID) UnmarshalJSON(raw []byte) error {
	var value string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
	} else {
		value = string(raw)
		if !integerID.MatchString(value) {
			return fmt.Errorf("invalid protocol ID")
		}
	}
	if value == "" {
		return fmt.Errorf("empty protocol ID")
	}
	*id = protocolID(value)
	return nil
}

type courseDTO struct {
	ID   protocolID `json:"id"`
	Name string     `json:"name"`
	Term *struct {
		ID protocolID `json:"id"`
	} `json:"termPanel"`
	School *struct {
		Name string `json:"name"`
	} `json:"schoolPanel"`
}
type coursePagination struct {
	Index *int `json:"pageIndex"`
	Pages *int `json:"totlePageCount"`
	Total *int `json:"totleCount"`
}
type coursePage struct {
	List       json.RawMessage   `json:"list"`
	Result     json.RawMessage   `json:"result"`
	Query      *coursePagination `json:"query"`
	Pagination *coursePagination `json:"pagination"`
}

// Courses returns the current learner's standard MOOC courses across all pages.
func (c *MOOCClient) Courses(ctx context.Context) ([]MOOCCourse, error) {
	courses := make([]MOOCCourse, 0)
	err := c.run(ctx, func(ctx context.Context) error {
		if _, err := c.currentUser(ctx); err != nil {
			return err
		}
		seen := map[string]bool{}
		previousPages := -1
		for page := 1; page <= maxCoursePages; page++ {
			params := url.Values{"type": {"30"}, "p": {fmt.Sprint(page)}, "psize": {"8"}, "courseType": {"1"}}
			token := c.csrfCookie()
			if token == "" {
				return &RequestError{Operation: "courses CSRF", Kind: ErrUnexpectedResponse}
			}
			target := siteURL + courseListPath + "?" + url.Values{"csrfKey": {token}}.Encode()
			headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "edu-script-token": {token}, "Referer": {siteURL + "home.htm"}}
			body, err := c.requestWithHeaders(ctx, "courses", http.MethodPost, target, []byte(params.Encode()), true, headers)
			if err != nil {
				return err
			}
			var envelope struct {
				Code   *int            `json:"code"`
				Result json.RawMessage `json:"result"`
				Data   json.RawMessage `json:"data"`
			}
			if err := decodeResponse("courses", body, &envelope); err != nil {
				return err
			}
			invalid := &RequestError{Operation: "courses schema", Kind: ErrUnexpectedResponse}
			if envelope.Code == nil {
				return invalid
			}
			if *envelope.Code == 1 {
				return c.unauthenticated("courses")
			}
			if *envelope.Code != 0 {
				return &RequestError{Operation: "courses", Kind: ErrRemoteRejected}
			}
			payload := envelope.Result
			if len(payload) == 0 {
				payload = envelope.Data
			}
			var data coursePage
			if err := decodeResponse("course page", payload, &data); err != nil {
				return err
			}
			list := data.List
			if len(list) == 0 {
				list = data.Result
			}
			paging := data.Query
			if paging == nil {
				paging = data.Pagination
			}
			if paging == nil || paging.Index == nil || paging.Pages == nil || paging.Total == nil {
				return invalid
			}
			if *paging.Index != page || *paging.Pages < 0 || *paging.Pages > maxCoursePages || *paging.Total < 0 {
				return invalid
			}
			if previousPages >= 0 && previousPages != *paging.Pages {
				return invalid
			}
			previousPages = *paging.Pages
			if len(list) == 0 || list[0] != '[' {
				return invalid
			}
			var rows []courseDTO
			if err := json.Unmarshal(list, &rows); err != nil {
				return invalid
			}
			if *paging.Pages == 0 && (len(rows) > 0 || *paging.Total != 0) {
				return invalid
			}
			if len(rows) == 0 && page < *paging.Pages {
				return invalid
			}
			for _, row := range rows {
				if row.ID == "" || row.Name == "" || row.Term == nil || row.Term.ID == "" {
					return invalid
				}
				key := string(row.ID) + "\x00" + string(row.Term.ID)
				if seen[key] {
					return invalid
				}
				seen[key] = true
				item := MOOCCourse{ID: string(row.ID), TermID: string(row.Term.ID), Name: row.Name}
				if row.School != nil {
					item.School = row.School.Name
				}
				courses = append(courses, item)
			}
			if page >= *paging.Pages {
				return nil
			}
		}
		return &RequestError{Operation: "courses pagination", Kind: ErrUnexpectedResponse}
	})
	if err != nil {
		return nil, err
	}
	return courses, nil
}
