package mooc

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// VideoProgress describes a playback observation, not a requested completion state.
type VideoProgress struct {
	CourseID        string
	TermID          string
	LessonID        string
	UnitID          string
	ContentID       string
	Index           int
	IntervalSeconds int
	PositionSeconds int
	WatchedSeconds  int
	Finished        bool
}

// ReportVideoProgress reports measured playback and requires a positive server receipt.
func (c *MOOCClient) ReportVideoProgress(ctx context.Context, progress VideoProgress) error {
	return c.run(ctx, func(ctx context.Context) error {
		invalid := &RequestError{Operation: "video progress input", Kind: ErrUnexpectedResponse}
		for _, id := range []string{progress.CourseID, progress.TermID, progress.LessonID, progress.UnitID, progress.ContentID} {
			if !integerID.MatchString(id) || id[0] == '0' {
				return invalid
			}
		}
		if progress.Index < 1 || progress.IntervalSeconds < 1 || progress.IntervalSeconds > math.MaxInt/1000 || progress.PositionSeconds < -1 || progress.WatchedSeconds < 0 || progress.WatchedSeconds > progress.IntervalSeconds {
			return invalid
		}
		if progress.PositionSeconds == -1 && (progress.WatchedSeconds != 0 || progress.Finished) {
			return invalid
		}
		user, err := c.currentUser(ctx)
		if err != nil {
			return err
		}
		dto := struct {
			UnitID         json.Number `json:"unitId"`
			Finished       bool        `json:"finished"`
			Index          int         `json:"index"`
			Duration       int         `json:"duration"`
			CourseID       json.Number `json:"courseId"`
			LessonID       json.Number `json:"lessonId"`
			VideoID        json.Number `json:"videoId"`
			TermID         json.Number `json:"termId"`
			UserID         string      `json:"userId"`
			ContentType    int         `json:"contentType"`
			Action         string      `json:"action"`
			VideoTime      int         `json:"videoTime"`
			LearnedSeconds int         `json:"learnedVideoTimeCount"`
		}{
			UnitID: json.Number(progress.UnitID), Finished: progress.Finished, Index: progress.Index,
			Duration: progress.IntervalSeconds * 1000, CourseID: json.Number(progress.CourseID),
			LessonID: json.Number(progress.LessonID), VideoID: json.Number(progress.ContentID),
			TermID: json.Number(progress.TermID), UserID: user.ID, ContentType: 1,
			Action: "LEARN_TIME_COUNT", VideoTime: progress.PositionSeconds, LearnedSeconds: progress.WatchedSeconds,
		}
		payload, err := json.Marshal(struct {
			DTO any `json:"dto"`
		}{dto})
		if err != nil {
			return invalid
		}
		token := c.csrfCookie()
		if token == "" {
			return &RequestError{Operation: "video progress CSRF", Kind: ErrUnexpectedResponse}
		}
		headers, err := rpcAuthHeaders(payload)
		if err != nil {
			return err
		}
		headers.Set("edu-script-token", token)
		headers.Set("Referer", siteURL)
		body, err := c.requestWithHeaders(ctx, "video progress", http.MethodPost, siteURL+"web/j/courseRpcBean.saveMocContentLearn.rpc?"+url.Values{"csrfKey": {token}}.Encode(), payload, true, headers)
		if err != nil {
			return err
		}
		var response struct {
			Code   *int  `json:"code"`
			Result *bool `json:"result"`
		}
		if err := decodeResponse("video progress", body, &response); err != nil {
			return err
		}
		if response.Code == nil {
			return &RequestError{Operation: "video progress schema", Kind: ErrUnexpectedResponse}
		}
		if *response.Code == 1 {
			return c.unauthenticated("video progress")
		}
		if *response.Code != 0 {
			return &RequestError{Operation: "video progress", Kind: ErrRemoteRejected}
		}
		if response.Result == nil {
			return &RequestError{Operation: "video progress receipt", Kind: ErrUnexpectedResponse}
		}
		if !*response.Result {
			return &RequestError{Operation: "video progress receipt", Kind: ErrRemoteRejected}
		}
		return nil
	})
}

func rpcAuthHeaders(payload []byte) (http.Header, error) {
	nonceValue, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		return nil, &RequestError{Operation: "request signature", Kind: ErrRequestFailed, cause: err}
	}
	nonce := strconv.FormatInt(nonceValue.Int64()+1000, 10)
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	// This public protocol salt is shipped by the site's geneAuthHeaders function.
	sum := md5.Sum(append(append([]byte(nil), payload...), []byte(nonce+timestamp+"fu2s2kxcswgn5hqanx7asmlogyr5wu29")...))
	return http.Header{
		"Content-Type":   {"application/json;charset=UTF-8"},
		"Timestamp":      {timestamp},
		"Nonce":          {nonce},
		"System":         {"v1"},
		"Auth-Signature": {strings.ToUpper(hex.EncodeToString(sum[:]))},
	}, nil
}
