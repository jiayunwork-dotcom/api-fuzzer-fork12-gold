package progress

import (
	"fmt"
	"sync"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

type Estimator struct {
	mu sync.RWMutex

	startTime    time.Time
	totalTests   int
	completed    int
	testTimes    []time.Duration
	maxSamples   int
	currentQPS   float64
	baseQPS      float64
	timeout      time.Duration
}

func NewEstimator(totalTests int, baseQPS float64, timeout time.Duration) *Estimator {
	return &Estimator{
		startTime:  time.Now(),
		totalTests: totalTests,
		maxSamples: 100,
		baseQPS:    baseQPS,
		currentQPS: baseQPS,
		timeout:    timeout,
	}
}

func (e *Estimator) RecordTest(duration time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.completed++
	e.testTimes = append(e.testTimes, duration)
	if len(e.testTimes) > e.maxSamples {
		e.testTimes = e.testTimes[1:]
	}

	if len(e.testTimes) > 0 {
		total := time.Duration(0)
		for _, t := range e.testTimes {
			total += t
		}
		avg := total / time.Duration(len(e.testTimes))
		if avg > 0 {
			e.currentQPS = float64(time.Second) / float64(avg)
		}
	}
}

func (e *Estimator) SetQPS(qps float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.currentQPS = qps
}

func (e *Estimator) GetEstimate() *core.ProgressEstimate {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.totalTests == 0 {
		return &core.ProgressEstimate{
			Completed:       0,
			Total:           0,
			PercentComplete: 100,
		}
	}

	remaining := e.totalTests - e.completed
	percent := float64(e.completed) / float64(e.totalTests) * 100

	var avgTimePerTest time.Duration
	if e.completed > 0 {
		elapsed := time.Since(e.startTime)
		avgTimePerTest = elapsed / time.Duration(e.completed)
	}

	var estimatedTimeLeft time.Duration
	var eta time.Time

	if e.currentQPS > 0 {
		secondsLeft := float64(remaining) / e.currentQPS
		estimatedTimeLeft = time.Duration(secondsLeft * float64(time.Second))
		eta = time.Now().Add(estimatedTimeLeft)
	}

	willExceed := false
	if e.timeout > 0 && estimatedTimeLeft > e.timeout {
		willExceed = true
	}

	return &core.ProgressEstimate{
		Completed:        e.completed,
		Total:            e.totalTests,
		PercentComplete:  percent,
		AvgTimePerTest:   avgTimePerTest,
		RemainingTests:   remaining,
		EstimatedTimeLeft: estimatedTimeLeft,
		ETA:              eta,
		CurrentQPS:       e.currentQPS,
		WillExceedTimeout: willExceed,
	}
}

func (e *Estimator) UpdateTotal(total int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.totalTests = total
}

func (e *Estimator) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.startTime = time.Now()
	e.completed = 0
	e.testTimes = nil
	e.currentQPS = e.baseQPS
}

func FormatDuration(d time.Duration) string {
	if d < 0 {
		return "calculating..."
	}

	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func FormatETA(t time.Time) string {
	if t.IsZero() {
		return "calculating..."
	}
	return t.Format("15:04:05")
}
