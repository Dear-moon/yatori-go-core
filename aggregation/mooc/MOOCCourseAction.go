package mooc

import (
	"context"
	"errors"
	"time"

	api "github.com/yatori-dev/yatori-go-core/api/mooc"
)

type VideoClient interface {
	Video(context.Context, string) (*api.MOOCVideo, error)
	ReportVideoProgress(context.Context, api.VideoProgress) error
}
type StudyOptions struct {
	ReportInterval time.Duration
	OnProgress     func(positionSeconds, totalSeconds int)
}

// StudyVideo submits elapsed-time progress without rendering or decoding media.
func StudyVideo(ctx context.Context, client VideoClient, course api.MOOCCourse, lesson api.MOOCLesson, unit api.MOOCUnit, options StudyOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if unit.ContentType != 1 {
		return errors.New("MOOC study requires a video unit")
	}
	interval := options.ReportInterval
	if interval == 0 {
		interval = time.Minute
	}
	if interval < time.Second || interval%time.Second != 0 {
		return errors.New("MOOC report interval must be whole positive seconds")
	}
	video, err := client.Video(ctx, unit.ID)
	if err != nil {
		return err
	}
	if video == nil || video.DurationSeconds <= 0 || int64(video.DurationSeconds) > int64((1<<63-1)/time.Second) || video.LastPositionSeconds < 0 {
		return api.ErrUnexpectedResponse
	}
	position := video.LastPositionSeconds
	// A saved position alone does not prove that the completion receipt succeeded.
	if position >= video.DurationSeconds {
		position = video.DurationSeconds - 1
	}
	progress := api.VideoProgress{CourseID: course.ID, TermID: course.TermID, LessonID: lesson.ID, UnitID: unit.ID, ContentID: unit.ContentID, Index: 1, IntervalSeconds: int(interval / time.Second), PositionSeconds: -1}
	if err := client.ReportVideoProgress(ctx, progress); err != nil {
		return err
	}
	for position < video.DurationSeconds {
		step := progress.IntervalSeconds
		if remaining := video.DurationSeconds - position; step > remaining {
			step = remaining
		}
		timer := time.NewTimer(time.Duration(step) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		position += step
		progress.Index++
		progress.PositionSeconds = position
		progress.WatchedSeconds = step
		progress.Finished = position == video.DurationSeconds
		if err := client.ReportVideoProgress(ctx, progress); err != nil {
			return err
		}
		if options.OnProgress != nil {
			options.OnProgress(position, video.DurationSeconds)
		}
	}
	return nil
}
