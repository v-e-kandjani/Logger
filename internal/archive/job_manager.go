package archive

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ExportJobStatus represents the lifecycle state of a custom export task
type ExportJobStatus string

const (
	JobStatusQueued    ExportJobStatus = "QUEUED"
	JobStatusRunning   ExportJobStatus = "RUNNING"
	JobStatusCompleted ExportJobStatus = "COMPLETED"
	JobStatusFailed    ExportJobStatus = "FAILED"
)

// ExportJob represents an asynchronous export and sealing background task
type ExportJob struct {
	ID          string               `json:"id"`
	Status      ExportJobStatus      `json:"status"`
	Stage       string               `json:"stage"` // INITIALIZING, QUERYING, EXTRACTING, STREAMING, HASHING, STAMPING, PACKAGING, REGISTERING, COMPLETED, FAILED
	StageText   string               `json:"stage_text"`
	Percent     int                  `json:"percent"`
	RecordCount int64                `json:"record_count"`
	TotalCount  int64                `json:"total_count"`
	Logs        []string             `json:"logs"`
	Options     CustomRangeOptions   `json:"options"`
	Result      *CustomArchiveResult `json:"result,omitempty"`
	DownloadURL string               `json:"download_url,omitempty"`
	Error       string               `json:"error,omitempty"`
	CreatedAt   time.Time            `json:"created_at"`
	CompletedAt *time.Time           `json:"completed_at,omitempty"`

	mu          sync.RWMutex
	subscribers map[chan *ExportJobSnapshot]struct{}
}

// ExportJobSnapshot provides a thread-safe snapshot of the export task state
type ExportJobSnapshot struct {
	ID          string               `json:"id"`
	Status      ExportJobStatus      `json:"status"`
	Stage       string               `json:"stage"`
	StageText   string               `json:"stage_text"`
	Percent     int                  `json:"percent"`
	RecordCount int64                `json:"record_count"`
	TotalCount  int64                `json:"total_count"`
	Logs        []string             `json:"logs"`
	LatestLog   string               `json:"latest_log,omitempty"`
	Result      *CustomArchiveResult `json:"result,omitempty"`
	DownloadURL string               `json:"download_url,omitempty"`
	Error       string               `json:"error,omitempty"`
	CreatedAt   time.Time            `json:"created_at"`
	CompletedAt *time.Time           `json:"completed_at,omitempty"`
}

// Snapshot returns a copy of current job state
func (j *ExportJob) Snapshot() *ExportJobSnapshot {
	j.mu.RLock()
	defer j.mu.RUnlock()

	logsCopy := make([]string, len(j.Logs))
	copy(logsCopy, j.Logs)

	latest := ""
	if len(j.Logs) > 0 {
		latest = j.Logs[len(j.Logs)-1]
	}

	return &ExportJobSnapshot{
		ID:          j.ID,
		Status:      j.Status,
		Stage:       j.Stage,
		StageText:   j.StageText,
		Percent:     j.Percent,
		RecordCount: j.RecordCount,
		TotalCount:  j.TotalCount,
		Logs:        logsCopy,
		LatestLog:   latest,
		Result:      j.Result,
		DownloadURL: j.DownloadURL,
		Error:       j.Error,
		CreatedAt:   j.CreatedAt,
		CompletedAt: j.CompletedAt,
	}
}

// AddLog appends a timestamped terminal output line
func (j *ExportJob) AddLog(msg string) {
	timestamp := time.Now().Format("15:04:05")
	formatted := fmt.Sprintf("[%s] %s", timestamp, msg)
	j.Logs = append(j.Logs, formatted)
}

// UpdateProgress updates stage, progress percent, counts and notifies subscribers
func (j *ExportJob) UpdateProgress(stage string, percent int, logMsg string, currentCount int64, totalCount int64) {
	j.mu.Lock()
	if stage != "" {
		j.Stage = stage
	}
	if percent >= 0 && percent <= 100 {
		j.Percent = percent
	}
	if currentCount > 0 {
		j.RecordCount = currentCount
	}
	if totalCount > 0 {
		j.TotalCount = totalCount
	}
	if logMsg != "" {
		j.StageText = logMsg
		j.AddLog(logMsg)
	}

	snap := &ExportJobSnapshot{
		ID:          j.ID,
		Status:      j.Status,
		Stage:       j.Stage,
		StageText:   j.StageText,
		Percent:     j.Percent,
		RecordCount: j.RecordCount,
		TotalCount:  j.TotalCount,
		Logs:        append([]string{}, j.Logs...),
		LatestLog:   logMsg,
		Result:      j.Result,
		DownloadURL: j.DownloadURL,
		Error:       j.Error,
		CreatedAt:   j.CreatedAt,
		CompletedAt: j.CompletedAt,
	}

	for ch := range j.subscribers {
		select {
		case ch <- snap:
		default:
		}
	}
	j.mu.Unlock()
}

// ExportJobManager coordinates asynchronous export operations and subscriber feeds
type ExportJobManager struct {
	mu     sync.RWMutex
	jobs   map[string]*ExportJob
	engine *Engine
}

// NewExportJobManager creates an in-memory job manager and starts its cleaner loop
func NewExportJobManager(engine *Engine) *ExportJobManager {
	mgr := &ExportJobManager{
		jobs:   make(map[string]*ExportJob),
		engine: engine,
	}
	go mgr.cleanupLoop()
	return mgr
}

// StartJob creates and launches an export task in a detached goroutine
func (m *ExportJobManager) StartJob(opts CustomRangeOptions) (*ExportJob, error) {
	if opts.End.Before(opts.Start) {
		return nil, fmt.Errorf("end time (%s) must be after start time (%s)", opts.End.Format(time.RFC3339), opts.Start.Format(time.RFC3339))
	}

	jobID := uuid.New().String()
	job := &ExportJob{
		ID:          jobID,
		Status:      JobStatusQueued,
		Stage:       "INITIALIZING",
		StageText:   "Dışa aktarma görevi sıraya alındı...",
		Percent:     2,
		Logs:        make([]string, 0),
		Options:     opts,
		CreatedAt:   time.Now(),
		subscribers: make(map[chan *ExportJobSnapshot]struct{}),
	}
	job.AddLog(fmt.Sprintf("Dışa aktarma görevi oluşturuldu (İş ID: %s)", jobID))
	job.AddLog(fmt.Sprintf("Aralık: %s -> %s (Zaman Referansı: %s, Format: %s)",
		opts.Start.Format("2006-01-02 15:04:05"),
		opts.End.Format("2006-01-02 15:04:05"),
		opts.TimeField,
		opts.Format,
	))

	m.mu.Lock()
	m.jobs[jobID] = job
	m.mu.Unlock()

	// Launch background task
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		job.mu.Lock()
		job.Status = JobStatusRunning
		job.mu.Unlock()

		job.UpdateProgress("INITIALIZING", 5, "Dışa aktarma ve mühürleme motoru hazırlandı.", 0, 0)

		res, err := m.engine.CreateCustomRangeArchiveWithProgress(ctx, opts, func(stage string, pct int, msg string, cur int64, tot int64) {
			job.UpdateProgress(stage, pct, msg, cur, tot)
		})

		job.mu.Lock()
		defer job.mu.Unlock()

		now := time.Now()
		job.CompletedAt = &now

		if err != nil {
			job.Status = JobStatusFailed
			job.Error = err.Error()
			job.Stage = "FAILED"
			job.StageText = "İşlem hatası: " + err.Error()
			job.AddLog("HATA: " + err.Error())
		} else {
			job.Status = JobStatusCompleted
			job.Result = res
			job.Percent = 100
			job.Stage = "COMPLETED"
			job.StageText = fmt.Sprintf("Tamamlandı: %d kayıt arşivlendi ve hazırlandı.", res.RecordCount)
			job.DownloadURL = fmt.Sprintf("/api/v1/archives/export-custom/download?job_id=%s", job.ID)
			job.AddLog(fmt.Sprintf("Dosya hazır: %s (%d bayt). İndirme başlatılabilir.", res.FilePath, res.ArchiveSize))
		}

		snap := &ExportJobSnapshot{
			ID:          job.ID,
			Status:      job.Status,
			Stage:       job.Stage,
			StageText:   job.StageText,
			Percent:     job.Percent,
			RecordCount: job.RecordCount,
			TotalCount:  job.TotalCount,
			Logs:        append([]string{}, job.Logs...),
			LatestLog:   job.StageText,
			Result:      job.Result,
			DownloadURL: job.DownloadURL,
			Error:       job.Error,
			CreatedAt:   job.CreatedAt,
			CompletedAt: job.CompletedAt,
		}

		for ch := range job.subscribers {
			select {
			case ch <- snap:
			default:
			}
		}
	}()

	return job, nil
}

// GetJob retrieves an existing job by ID
func (m *ExportJobManager) GetJob(id string) (*ExportJob, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	return j, ok
}

// Subscribe returns a channel that receives job snapshots whenever progress updates
func (m *ExportJobManager) Subscribe(id string) (<-chan *ExportJobSnapshot, func(), bool) {
	m.mu.RLock()
	job, ok := m.jobs[id]
	m.mu.RUnlock()

	if !ok {
		return nil, nil, false
	}

	job.mu.Lock()
	ch := make(chan *ExportJobSnapshot, 50)
	job.subscribers[ch] = struct{}{}

	// Send immediate initial snapshot
	initialSnap := &ExportJobSnapshot{
		ID:          job.ID,
		Status:      job.Status,
		Stage:       job.Stage,
		StageText:   job.StageText,
		Percent:     job.Percent,
		RecordCount: job.RecordCount,
		TotalCount:  job.TotalCount,
		Logs:        append([]string{}, job.Logs...),
		LatestLog:   job.StageText,
		Result:      job.Result,
		DownloadURL: job.DownloadURL,
		Error:       job.Error,
		CreatedAt:   job.CreatedAt,
		CompletedAt: job.CompletedAt,
	}
	ch <- initialSnap
	job.mu.Unlock()

	unsubscribe := func() {
		job.mu.Lock()
		delete(job.subscribers, ch)
		close(ch)
		job.mu.Unlock()
	}

	return ch, unsubscribe, true
}

// cleanupLoop periodically prunes completed or failed jobs older than 2 hours
func (m *ExportJobManager) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		cutoff := time.Now().Add(-2 * time.Hour)
		for id, j := range m.jobs {
			j.mu.RLock()
			completed := j.CompletedAt != nil && j.CompletedAt.Before(cutoff)
			j.mu.RUnlock()
			if completed {
				delete(m.jobs, id)
			}
		}
		m.mu.Unlock()
	}
}
