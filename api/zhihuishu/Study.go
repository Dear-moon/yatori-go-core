package zhihuishu

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// StudyVideo reports elapsed time in intervals matching the student player.
func (c *Client) StudyVideo(ctx context.Context, course AICourse, knowledgeID string, resource Resource, onProgress func(int, int)) error {
	if resource.Kind() != ResourceVideo || resource.ID == "" || resource.FileID == "" {
		return ErrUnsupportedResource
	}
	open, err := c.StudyOpen(ctx, course)
	if err != nil {
		return err
	}
	if !open {
		return ErrStudyClosed
	}
	var total, position int
	err = c.run(ctx, func(ctx context.Context) error {
		params, err := resourceParams(course, knowledgeID)
		if err != nil {
			return err
		}
		params["nodeUid"] = knowledgeID
		params["resourcesUid"] = resource.ID
		var detail struct {
			Quote *struct {
				FileType int    `json:"fileType"`
				Start    string `json:"videoStartTime"`
				End      string `json:"videoEndTime"`
			} `json:"resourcesQuoteDetail"`
			Video any `json:"resourcesVideoDetail"`
		}
		if err := c.aiRequest(ctx, "video detail", "/stu/resources/get-node-resources-detail", params, &detail); err != nil {
			return err
		}
		if detail.Video != nil || (detail.Quote != nil && detail.Quote.FileType != 0 && detail.Quote.FileType != 1) {
			return ErrUnsupportedResource
		}
		params, _ = courseParams(course)
		params["videoIdList"] = []string{resource.FileID}
		params["dateFormate"] = time.Now().UnixMilli()
		var durations []struct {
			ID   protocolID `json:"videoId"`
			Time int        `json:"time"`
		}
		if err := c.aiRequest(ctx, "video duration", "/stu/resources-lab/get-video-time", params, &durations); err != nil {
			return err
		}
		for _, duration := range durations {
			if string(duration.ID) == resource.FileID {
				total = duration.Time
			}
		}
		if total == 0 {
			return &RequestError{Operation: "video unavailable", Kind: ErrUnsupportedResource}
		}
		if total < 0 || total > 86400 {
			return ErrUnexpectedResponse
		}
		params, _ = resourceParams(course, knowledgeID)
		params["shareCourseId"] = ""
		var positions map[string]int
		if err := c.aiRequest(ctx, "video position", "/stu/studyRecord/get-knowledge-video-time", params, &positions); err != nil {
			return err
		}
		if positions[resource.ID] < 0 || positions[resource.ID] > total {
			return ErrUnexpectedResponse
		}
		clipStart := 0
		if detail.Quote != nil && detail.Quote.End != "" && detail.Quote.End != "0" {
			start, startErr := strconv.ParseInt(detail.Quote.Start, 10, 64)
			end, endErr := strconv.ParseInt(detail.Quote.End, 10, 64)
			if startErr != nil || endErr != nil || start < 0 || end <= start || end > int64(total)*1000 {
				return ErrUnexpectedResponse
			}
			clipStart = int(start / 1000)
			total = int((end + 999) / 1000)
		}
		// The endpoint stores accumulated seconds by resource, not playback position.
		position = clipStart + min(positions[resource.ID], total-clipStart)
		if position < 0 || position > total {
			return ErrUnexpectedResponse
		}
		var video struct {
			Successful bool `json:"successful"`
			Result     *struct {
				Lines []struct {
					URL string `json:"lineUrl"`
				} `json:"lines"`
			} `json:"result"`
		}
		if err := c.request(ctx, "video availability", http.MethodGet, "https://newbase.zhihuishu.com/video/initVideoNew?videoID="+url.QueryEscape(resource.FileID), nil, nil, &video); err != nil {
			return err
		}
		if !video.Successful || video.Result == nil || len(video.Result.Lines) == 0 {
			return ErrUnsupportedResource
		}
		return nil
	})
	if err != nil {
		return err
	}
	if onProgress != nil {
		onProgress(position, total)
	}
	for position < total {
		delta := min(10, total-position)
		timer := time.NewTimer(time.Duration(delta) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		next := position + delta
		err = c.run(ctx, func(ctx context.Context) error {
			params := map[string]any{"courseId": course.ID, "resourceId": resource.ID, "knowledgeId": knowledgeID, "source": 1, "studyFileType": 1, "fileId": resource.FileID, "studyTime": delta, "lastWatchTime": next, "dateFormate": time.Now().UnixMilli()}
			if err := c.aiRequest(ctx, "video study", "/stu/studyRecord/study", params, nil); err != nil {
				return err
			}
			params, _ = resourceParams(course, knowledgeID)
			params["fileId"] = resource.FileID
			params["studyTotalTime"] = delta
			params["lastWatchTime"] = next
			params["shareCourseId"] = ""
			params["nodeType"] = 1
			params["watchUId"] = 1
			return c.aiRequest(ctx, "video report", "/stu/studyRecord/report", params, nil)
		})
		if err != nil {
			return err
		}
		position = next
		if onProgress != nil {
			onProgress(position, total)
		}
	}
	return nil
}

// CompleteBook requires loaded content before sending the platform's preview receipt.
func (c *Client) CompleteBook(ctx context.Context, course AICourse, knowledgeID string, resource Resource) error {
	if resource.DataType != 21 || resource.ID == "" {
		return ErrUnsupportedResource
	}
	open, err := c.StudyOpen(ctx, course)
	if err != nil {
		return err
	}
	if !open {
		return ErrStudyClosed
	}
	resources, err := c.Resources(ctx, course, knowledgeID)
	if err != nil {
		return err
	}
	found := false
	for _, loaded := range resources {
		if loaded.ID == resource.ID && loaded.DataType == 21 && loaded.HasBookContent {
			found = true
			break
		}
	}
	if !found {
		return ErrUnsupportedResource
	}
	return c.run(ctx, func(ctx context.Context) error {
		params, err := resourceParams(course, knowledgeID)
		if err != nil {
			return err
		}
		params["resourcesUid"] = resource.ID
		params["watchUId"] = 1
		return c.aiRequest(ctx, "book preview", "/stu/studyRecord/completed", params, nil)
	})
}

// CompletePPT verifies the preview before sending the same receipt as the web reader.
func (c *Client) CompletePPT(ctx context.Context, course AICourse, knowledgeID string, resource Resource) error {
	if resource.Kind() != ResourcePPT || resource.ID == "" {
		return ErrUnsupportedResource
	}
	open, err := c.StudyOpen(ctx, course)
	if err != nil {
		return err
	}
	if !open {
		return ErrStudyClosed
	}
	resources, err := c.Resources(ctx, course, knowledgeID)
	if err != nil {
		return err
	}
	var loaded *Resource
	for i := range resources {
		if resources[i].ID == resource.ID && resources[i].Kind() == ResourcePPT {
			loaded = &resources[i]
			break
		}
	}
	if loaded == nil || loaded.LocalType != 1 || len(loaded.PPTPages) == 0 {
		return ErrUnsupportedResource
	}
	if loaded.Status == 1 {
		return nil
	}
	err = c.run(ctx, func(ctx context.Context) error {
		params, err := resourceParams(course, knowledgeID)
		if err != nil {
			return err
		}
		params["resourcesUid"] = loaded.ID
		params["nodeUid"] = knowledgeID
		var preview struct {
			CutType *int `json:"pptCutType"`
			Pages   []struct {
				Sequence int    `json:"pptPageSeq"`
				URL      string `json:"pptPageUrl"`
			} `json:"pptPageList"`
			DynamicStatus int    `json:"pptDynamicStatus"`
			DynamicParam  string `json:"pptDynamicParam"`
		}
		if err := c.aiRequest(ctx, "PPT preview", "/stu/resources-lab/get-ppt-detail-v2", params, &preview); err != nil {
			return err
		}
		if preview.CutType == nil {
			return ErrUnexpectedResponse
		}
		available := map[int]bool{}
		switch *preview.CutType {
		case 0:
			for _, page := range preview.Pages {
				if page.Sequence > 0 && validPreviewURL(page.URL) {
					available[page.Sequence] = true
				}
			}
		case 1:
			if preview.DynamicStatus != 1 {
				return ErrUnsupportedResource
			}
			var dynamic struct {
				PageCount int    `json:"pageCount"`
				Format    string `json:"format"`
				URL       string `json:"resultUrl"`
			}
			if json.Unmarshal([]byte(preview.DynamicParam), &dynamic) != nil || dynamic.PageCount <= 0 || dynamic.PageCount > 10000 || dynamic.Format == "" || !validPreviewURL(dynamic.URL) {
				return ErrUnexpectedResponse
			}
			for page := 1; page <= dynamic.PageCount; page++ {
				available[page] = true
			}
		default:
			return ErrUnsupportedResource
		}
		for _, page := range loaded.PPTPages {
			if !available[page] {
				return ErrUnsupportedResource
			}
		}
		delete(params, "nodeUid")
		params["watchUId"] = 1
		return c.aiRequest(ctx, "PPT preview receipt", "/stu/studyRecord/completed", params, nil)
	})
	if err != nil {
		return err
	}
	resources, err = c.Resources(ctx, course, knowledgeID)
	if err != nil {
		return err
	}
	for _, current := range resources {
		if current.ID == resource.ID && current.Kind() == ResourcePPT && current.Status == 1 {
			return nil
		}
	}
	return &RequestError{Operation: "PPT completion not confirmed", Kind: ErrRemoteRejected}
}

func validPreviewURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil
}
