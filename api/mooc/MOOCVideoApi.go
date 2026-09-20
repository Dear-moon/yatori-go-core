package mooc

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type MOOCVideo struct {
	ID                  string
	DurationSeconds     int
	LastPositionSeconds int
	Sources             []MOOCVideoSource
}
type MOOCVideoSource struct {
	Quality   int
	Format    string
	Encrypted bool
	URL       string `json:"-"`
}

// Signed playback addresses must not appear in ordinary diagnostic output.
func (s MOOCVideoSource) String() string {
	return fmt.Sprintf("quality=%d format=%s encrypted=%t", s.Quality, s.Format, s.Encrypted)
}

func videoResourceSign(unitID, userID, timestamp string) string {
	// The site's tokenEncrypt uses this MD5 input ordering for resource requests.
	sum := md5.Sum([]byte(unitID + "1" + timestamp + "881mooc" + userID))
	return hex.EncodeToString(sum[:])
}

// Video resolves the current authorized playback sources for a video unit.
func (c *MOOCClient) Video(ctx context.Context, unitID string) (*MOOCVideo, error) {
	var video *MOOCVideo
	err := c.run(ctx, func(ctx context.Context) error {
		if !integerID.MatchString(unitID) || unitID[0] == '0' {
			return &RequestError{Operation: "video unit", Kind: ErrUnexpectedResponse}
		}
		user, err := c.currentUser(ctx)
		if err != nil {
			return err
		}
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		var resource struct {
			LearnVideoTime *int       `json:"learnVideoTime"`
			UnitID         protocolID `json:"lessonUnitId"`
			ContentType    *int       `json:"contentType"`
			Video          *struct {
				ID        protocolID `json:"videoId"`
				Status    *int       `json:"status"`
				Signature string     `json:"signature"`
			} `json:"videoSignDto"`
		}
		params := url.Values{"bizId": {unitID}, "bizType": {"1"}, "contentType": {"1"}, "timestamp": {timestamp}, "sign": {videoResourceSign(unitID, user.ID, timestamp)}}
		if err := c.formRPC(ctx, "video resource", "web/j/resourceRpcBean.getResourceTokenV2.rpc", params, &resource); err != nil {
			return err
		}
		invalid := &RequestError{Operation: "video resource schema", Kind: ErrUnexpectedResponse}
		if string(resource.UnitID) != unitID || resource.ContentType == nil || *resource.ContentType != 1 || resource.Video == nil || resource.Video.Status == nil {
			return invalid
		}
		if *resource.Video.Status != 0 {
			return &RequestError{Operation: "video resource", Kind: ErrRemoteRejected}
		}
		if resource.Video.ID == "" || resource.Video.Signature == "" {
			return invalid
		}
		query := url.Values{"videoId": {string(resource.Video.ID)}, "signature": {resource.Video.Signature}, "clientType": {"1"}}
		headers := http.Header{"Origin": {"https://www.icourse163.org"}, "Referer": {siteURL}}
		body, err := c.requestWithHeaders(ctx, "video sources", http.MethodGet, "https://vod.study.163.com/eds/api/v1/vod/video?"+query.Encode(), nil, true, headers)
		if err != nil {
			return err
		}
		var response struct {
			Code   *int `json:"code"`
			Result *struct {
				ID       protocolID `json:"videoId"`
				Duration *int       `json:"duration"`
				Videos   []struct {
					Quality   *int   `json:"quality"`
					URL       string `json:"videoUrl"`
					Format    string `json:"format"`
					Secondary *bool  `json:"secondaryEncrypt"`
					Encrypted *bool  `json:"e"`
				} `json:"videos"`
			} `json:"result"`
		}
		if err := decodeResponse("video sources", body, &response); err != nil {
			return err
		}
		invalid = &RequestError{Operation: "video sources schema", Kind: ErrUnexpectedResponse}
		if response.Code == nil {
			return invalid
		}
		if *response.Code != 0 {
			return &RequestError{Operation: "video sources", Kind: ErrRemoteRejected}
		}
		result := response.Result
		if result == nil || result.ID != resource.Video.ID || result.Duration == nil || *result.Duration <= 0 || len(result.Videos) == 0 {
			return invalid
		}
		video = &MOOCVideo{ID: string(result.ID), DurationSeconds: *result.Duration, Sources: make([]MOOCVideoSource, 0, len(result.Videos))}
		if resource.LearnVideoTime != nil {
			if *resource.LearnVideoTime < 0 {
				return invalid
			}
			video.LastPositionSeconds = *resource.LearnVideoTime
		}
		for _, source := range result.Videos {
			target, err := url.Parse(source.URL)
			if err != nil || target.Host == "" || target.User != nil || (target.Scheme != "https" && target.Scheme != "http") || source.Quality == nil || source.Format == "" || source.Secondary == nil || source.Encrypted == nil {
				return invalid
			}
			video.Sources = append(video.Sources, MOOCVideoSource{Quality: *source.Quality, Format: source.Format, Encrypted: *source.Secondary || *source.Encrypted, URL: source.URL})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return video, nil
}
