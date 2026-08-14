package ratelimiter

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	mu sync.Mutex

	config        core.RateLimitConfig
	limiter       *rate.Limiter
	semaphore     chan struct{}
	lastRequest   time.Time
	currentQPS    int
	targetQPS     int
	consecutive429 int
	adaptive      bool
	progressive   bool
	requestCount  int
	startTime     time.Time
}

func NewRateLimiter(config core.RateLimitConfig) *RateLimiter {
	var limiter *rate.Limiter
	if config.QPS > 0 {
		limiter = rate.NewLimiter(rate.Limit(config.QPS), config.QPS)
	} else {
		limiter = rate.NewLimiter(rate.Inf, 0)
	}

	var semaphore chan struct{}
	if config.Concurrency > 0 {
		semaphore = make(chan struct{}, config.Concurrency)
	}

	return &RateLimiter{
		config:      config,
		limiter:     limiter,
		semaphore:   semaphore,
		targetQPS:   config.QPS,
		adaptive:    config.Adaptive,
		progressive: config.ProgressiveStress,
		startTime:   time.Now(),
	}
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	if rl.config.RequestInterval > 0 {
		rl.mu.Lock()
		elapsed := time.Since(rl.lastRequest)
		if elapsed < rl.config.RequestInterval {
			time.Sleep(rl.config.RequestInterval - elapsed)
		}
		rl.lastRequest = time.Now()
		rl.mu.Unlock()
	}

	if rl.progressive {
		rl.adjustProgressively()
	}

	if rl.semaphore != nil {
		rl.semaphore <- struct{}{}
	}

	return rl.limiter.Wait(ctx)
}

func (rl *RateLimiter) Release() {
	if rl.semaphore != nil {
		<-rl.semaphore
	}
}

func (rl *RateLimiter) HandleResponse(resp *core.HTTPResponse) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.requestCount++

	if resp.StatusCode == http.StatusTooManyRequests {
		rl.consecutive429++
		if rl.adaptive {
			rl.reduceRate()

			if retryAfter := resp.Headers["Retry-After"]; retryAfter != "" {
				if seconds, err := strconv.Atoi(retryAfter); err == nil {
					time.Sleep(time.Duration(seconds) * time.Second)
				}
			}
		}
	} else {
		rl.consecutive429 = 0
		if rl.adaptive && rl.currentQPS < rl.targetQPS && rl.consecutive429 == 0 {
			rl.increaseRate()
		}
	}
}

func (rl *RateLimiter) reduceRate() {
	if rl.currentQPS > 1 {
		rl.currentQPS = rl.currentQPS / 2
		if rl.currentQPS < 1 {
			rl.currentQPS = 1
		}
		rl.limiter.SetLimit(rate.Limit(rl.currentQPS))
		rl.limiter.SetBurst(rl.currentQPS)
	}
}

func (rl *RateLimiter) increaseRate() {
	if rl.currentQPS < rl.targetQPS {
		increase := rl.currentQPS / 4
		if increase < 1 {
			increase = 1
		}
		rl.currentQPS += increase
		if rl.currentQPS > rl.targetQPS {
			rl.currentQPS = rl.targetQPS
		}
		rl.limiter.SetLimit(rate.Limit(rl.currentQPS))
		rl.limiter.SetBurst(rl.currentQPS)
	}
}

func (rl *RateLimiter) adjustProgressively() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	elapsed := time.Since(rl.startTime)
	phase := int(elapsed.Minutes())

	progressiveQPS := (phase + 1) * 5
	if progressiveQPS > rl.targetQPS {
		progressiveQPS = rl.targetQPS
	}

	if progressiveQPS != rl.currentQPS {
		rl.currentQPS = progressiveQPS
		rl.limiter.SetLimit(rate.Limit(rl.currentQPS))
		rl.limiter.SetBurst(rl.currentQPS)
	}
}

func (rl *RateLimiter) GetCurrentQPS() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.currentQPS
}

func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	elapsed := time.Since(rl.startTime)
	actualQPS := 0.0
	if elapsed.Seconds() > 0 {
		actualQPS = float64(rl.requestCount) / elapsed.Seconds()
	}

	return map[string]interface{}{
		"target_qps":     rl.targetQPS,
		"current_qps":    rl.currentQPS,
		"actual_qps":     actualQPS,
		"concurrency":    rl.config.Concurrency,
		"request_count":  rl.requestCount,
		"consecutive_429": rl.consecutive429,
		"adaptive":       rl.adaptive,
		"progressive":    rl.progressive,
		"running_time":   elapsed.String(),
	}
}

type RequestExecutor struct {
	limiter      *RateLimiter
	httpClient   *core.HTTPClient
	maxBodySize  int64
}

func NewRequestExecutor(config core.RateLimitConfig, auth core.AuthConfig, maxBodySize int64) *RequestExecutor {
	return &RequestExecutor{
		limiter:     NewRateLimiter(config),
		httpClient:  core.NewHTTPClient(config.Timeout, auth),
		maxBodySize: maxBodySize,
	}
}

func (e *RequestExecutor) Execute(ctx context.Context, req *core.HTTPRequest) (*core.HTTPResponse, error) {
	if err := e.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	defer e.limiter.Release()

	resp, err := e.httpClient.Send(req, e.maxBodySize)
	if err == nil {
		e.limiter.HandleResponse(resp)

		if e.httpClient.RefreshTokenIfNeeded(resp) {
			resp, err = e.httpClient.Send(req, e.maxBodySize)
		}
	}

	return resp, err
}

func (e *RequestExecutor) GetLimiter() *RateLimiter {
	return e.limiter
}

func (e *RequestExecutor) GetHTTPClient() *core.HTTPClient {
	return e.httpClient
}
