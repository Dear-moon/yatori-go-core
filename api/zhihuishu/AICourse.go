package zhihuishu

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AICourse struct{ ID, ClassID, Name string }
type KnowledgeModule struct {
	ID, Name string
	Units    []KnowledgeUnit
}
type KnowledgeUnit struct {
	ID, Name string
	Points   []KnowledgePoint
}
type KnowledgePoint struct{ ID, Name string }
type Resource struct {
	ID, Name, FileID string
	DataType, Status int
	DurationSeconds  string
	BookPageCount    int
	HasBookContent   bool
}

// AICourses lists the AI course product observed in the authenticated student portal.
func (c *Client) AICourses(ctx context.Context) ([]AICourse, error) {
	var courses []AICourse
	err := c.run(ctx, func(ctx context.Context) error {
		if _, err := c.currentUser(ctx); err != nil {
			return err
		}
		secret, err := encryptPayload(map[string]any{}, c.courseKey, c.iv)
		if err != nil {
			return err
		}
		body := url.Values{"secretStr": {secret}, "dateFormate": {timeStamp()}}
		var response struct {
			Status  string `json:"status"`
			Courses *[]struct {
				ID      string     `json:"courseId"`
				ClassID protocolID `json:"classId"`
				Name    string     `json:"courseName"`
			} `json:"rt"`
		}
		if err := c.request(ctx, "AI courses", http.MethodPost, onlineBase+"/gateway/t/v1/student/queryStudentAICourseList", []byte(body.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, &response); err != nil {
			return err
		}
		switch response.Status {
		case "200":
		case "401", "403":
			return c.authenticationError("AI courses")
		default:
			return &RequestError{Operation: "AI courses status", Kind: ErrRemoteRejected}
		}
		if response.Courses == nil {
			return &RequestError{Operation: "AI courses schema", Kind: ErrUnexpectedResponse}
		}
		courses = make([]AICourse, 0, len(*response.Courses))
		seen := map[string]bool{}
		for _, dto := range *response.Courses {
			if dto.ID == "" || dto.ClassID == "" || dto.Name == "" || seen[dto.ID+"\x00"+string(dto.ClassID)] {
				return &RequestError{Operation: "AI courses schema", Kind: ErrUnexpectedResponse}
			}
			seen[dto.ID+"\x00"+string(dto.ClassID)] = true
			courses = append(courses, AICourse{ID: dto.ID, ClassID: string(dto.ClassID), Name: dto.Name})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return courses, nil
}
func courseParams(course AICourse) (map[string]any, error) {
	if strings.TrimSpace(course.ID) == "" || strings.TrimSpace(course.ClassID) == "" {
		return nil, &RequestError{Operation: "AI course input", Kind: ErrUnexpectedResponse}
	}
	return map[string]any{"courseId": course.ID, "classId": course.ClassID}, nil
}
func (c *Client) Knowledge(ctx context.Context, course AICourse) ([]KnowledgeModule, error) {
	var modules []KnowledgeModule
	err := c.run(ctx, func(ctx context.Context) error {
		params, err := courseParams(course)
		if err != nil {
			return err
		}
		if _, err := c.currentUser(ctx); err != nil {
			return err
		}
		var response struct {
			Modules *[]struct {
				ID    string `json:"themeId"`
				Name  string `json:"themeName"`
				Units []struct {
					ID     string `json:"themeId"`
					Name   string `json:"themeName"`
					Points []struct {
						ID   string `json:"knowledgeId"`
						Name string `json:"knowledgeName"`
					} `json:"knowledgeList"`
				} `json:"subThemeList"`
			} `json:"courseThemeList"`
		}
		if err := c.aiRequest(ctx, "knowledge", "/stu/knowledge-study/list-knowledge-theme", params, &response); err != nil {
			return err
		}
		if response.Modules == nil {
			return &RequestError{Operation: "knowledge schema", Kind: ErrUnexpectedResponse}
		}
		modules = make([]KnowledgeModule, 0, len(*response.Modules))
		for _, m := range *response.Modules {
			if m.ID == "" || m.Name == "" {
				return ErrUnexpectedResponse
			}
			module := KnowledgeModule{ID: m.ID, Name: m.Name}
			for _, u := range m.Units {
				if u.ID == "" || u.Name == "" {
					return ErrUnexpectedResponse
				}
				unit := KnowledgeUnit{ID: u.ID, Name: u.Name}
				for _, p := range u.Points {
					if p.ID == "" || p.Name == "" {
						return ErrUnexpectedResponse
					}
					unit.Points = append(unit.Points, KnowledgePoint{ID: p.ID, Name: p.Name})
				}
				module.Units = append(module.Units, unit)
			}
			modules = append(modules, module)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return modules, nil
}
func resourceParams(course AICourse, knowledgeID string) (map[string]any, error) {
	params, err := courseParams(course)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(knowledgeID) == "" {
		return nil, ErrUnexpectedResponse
	}
	params["knowledgeId"] = knowledgeID
	params["dateFormate"] = time.Now().UnixMilli()
	return params, nil
}
func (c *Client) Resources(ctx context.Context, course AICourse, knowledgeID string) ([]Resource, error) {
	var resources []Resource
	err := c.run(ctx, func(ctx context.Context) error {
		params, err := resourceParams(course, knowledgeID)
		if err != nil {
			return err
		}
		if _, err := c.currentUser(ctx); err != nil {
			return err
		}
		var response struct {
			Resources *[]struct {
				Detail *struct {
					ID       string `json:"resourcesUid"`
					Name     string `json:"resourcesName"`
					FileID   string `json:"resourcesFileId"`
					DataType *int   `json:"resourcesDataType"`
					Duration string `json:"resourcesTime"`
				} `json:"resourcesDetail"`
				Book *struct {
					Content *string           `json:"mdContent"`
					Pages   []json.RawMessage `json:"pageList"`
				} `json:"resourcesBookDetail"`
				Status *int `json:"studyStatus"`
			} `json:"resourceList"`
		}
		if err := c.aiRequest(ctx, "resources", "/stu/resources/list-knowledge-resource", params, &response); err != nil {
			return err
		}
		if response.Resources == nil {
			return ErrUnexpectedResponse
		}
		resources = make([]Resource, 0, len(*response.Resources))
		for _, r := range *response.Resources {
			if r.Detail == nil || r.Detail.ID == "" || r.Detail.DataType == nil || r.Status == nil {
				return ErrUnexpectedResponse
			}
			item := Resource{ID: r.Detail.ID, Name: r.Detail.Name, FileID: r.Detail.FileID, DataType: *r.Detail.DataType, Status: *r.Status, DurationSeconds: r.Detail.Duration}
			if r.Book != nil {
				item.BookPageCount = len(r.Book.Pages)
				item.HasBookContent = item.BookPageCount > 0 || (r.Book.Content != nil && strings.TrimSpace(*r.Book.Content) != "")
			}
			resources = append(resources, item)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resources, nil
}
func (c *Client) StudyOpen(ctx context.Context, course AICourse) (bool, error) {
	var closed bool
	err := c.run(ctx, func(ctx context.Context) error {
		params, err := courseParams(course)
		if err != nil {
			return err
		}
		if _, err := c.currentUser(ctx); err != nil {
			return err
		}
		params["dateFormate"] = time.Now().UnixMilli()
		return c.aiRequest(ctx, "study availability", "/stu/class/is-end-study", params, &closed)
	})
	return err == nil && !closed, err
}

type protocolID string

func (id *protocolID) UnmarshalJSON(data []byte) error {
	var value string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
	} else {
		value = string(data)
		if value == "" {
			return ErrUnexpectedResponse
		}
		for _, digit := range value {
			if digit < '0' || digit > '9' {
				return ErrUnexpectedResponse
			}
		}
	}
	*id = protocolID(value)
	return nil
}
