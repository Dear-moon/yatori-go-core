package mooc

import (
	"context"
	"errors"
	"testing"
	"time"

	api "github.com/yatori-dev/yatori-go-core/api/mooc"
)

type studyClient struct {
	reports  []api.VideoProgress
	onReport func(api.VideoProgress) error
}

func (c *studyClient) Video(context.Context, string) (*api.MOOCVideo, error) {
	return &api.MOOCVideo{DurationSeconds: 2, LastPositionSeconds: 1}, nil
}
func (c *studyClient) ReportVideoProgress(_ context.Context, p api.VideoProgress) error {
	c.reports = append(c.reports, p)
	if c.onReport != nil {
		return c.onReport(p)
	}
	return nil
}
func runStudy(ctx context.Context, c *studyClient) error {
	return StudyVideo(ctx, c, api.MOOCCourse{ID: "1", TermID: "2"}, api.MOOCLesson{ID: "3"}, api.MOOCUnit{ID: "4", ContentID: "5", ContentType: 1}, StudyOptions{ReportInterval: time.Second})
}
func TestStudyWaitsBeforeCompletion(t *testing.T) {
	c := &studyClient{}
	start := time.Now()
	if err := runStudy(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < time.Second {
		t.Fatal("completion was submitted before elapsed study time")
	}
	if len(c.reports) != 2 {
		t.Fatalf("reports=%d", len(c.reports))
	}
	if c.reports[0].Finished || c.reports[0].PositionSeconds != -1 {
		t.Fatal("initial report marked completion")
	}
	last := c.reports[1]
	if !last.Finished || last.PositionSeconds != 2 || last.WatchedSeconds != 1 || last.Index != 2 {
		t.Fatal("resume or completion report mismatch")
	}
}
func TestStudyCancellationStopsReports(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &studyClient{onReport: func(api.VideoProgress) error { cancel(); return nil }}
	if err := runStudy(ctx, c); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if len(c.reports) != 1 || c.reports[0].Finished {
		t.Fatal("reported completion after cancellation")
	}
}
func TestStudyRejectionStops(t *testing.T) {
	c := &studyClient{onReport: func(api.VideoProgress) error { return api.ErrRemoteRejected }}
	if err := runStudy(context.Background(), c); !errors.Is(err, api.ErrRemoteRejected) {
		t.Fatalf("expected rejection, got %v", err)
	}
	if len(c.reports) != 1 {
		t.Fatal("retried a rejected write")
	}
}
