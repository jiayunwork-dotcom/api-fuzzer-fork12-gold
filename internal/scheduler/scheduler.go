package scheduler

import (
	"sort"
	"strings"
	"sync"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

type Scheduler struct {
	mu sync.RWMutex

	api            *core.API
	state          *core.SchedulerState
	priorityQueue  []*core.ScheduledOperation
	completedOps   map[string]bool
	resourceTypes  map[string][]string
}

func NewScheduler(api *core.API, baseQPS int) *Scheduler {
	s := &Scheduler{
		api:          api,
		completedOps: make(map[string]bool),
		resourceTypes: make(map[string][]string),
		state: &core.SchedulerState{
			Queues:            make(map[string][]*core.ScheduledOperation),
			ConsecutiveIssues: make(map[string]int),
			ConsecutiveClean:  make(map[string]int),
			UsedStrategies:    make(map[string]map[core.FuzzStrategyType]bool),
			ResourceEndpoints: make(map[string][]string),
			BaseQPS:           baseQPS,
			CurrentQPS:        baseQPS,
		},
	}

	s.buildResourceMapping()
	s.buildPriorityQueue()

	return s
}

func (s *Scheduler) buildResourceMapping() {
	for path, methods := range s.api.Paths {
		resourceType := getResourceTypeFromPath(path)
		if resourceType == "" {
			continue
		}

		for method := range methods {
			endpointKey := method + " " + path
			s.resourceTypes[resourceType] = append(s.resourceTypes[resourceType], endpointKey)
			s.state.ResourceEndpoints[resourceType] = append(s.state.ResourceEndpoints[resourceType], endpointKey)
		}
	}
}

func (s *Scheduler) buildPriorityQueue() {
	var queue []*core.ScheduledOperation

	for path, methods := range s.api.Paths {
		for method, op := range methods {
			if op.Deprecated {
				continue
			}

			endpointKey := method + " " + path
			priority := s.calculateInitialPriority(op, path)

			scheduledOp := &core.ScheduledOperation{
				Operation:    op,
				Priority:     priority,
				ResourceType: getResourceTypeFromPath(path),
				Strategies:   s.getAvailableStrategies(endpointKey),
			}

			queue = append(queue, scheduledOp)
		}
	}

	sort.Slice(queue, func(i, j int) bool {
		return queue[i].Priority > queue[j].Priority
	})

	s.priorityQueue = queue
}

func (s *Scheduler) calculateInitialPriority(op *core.Operation, path string) int {
	priority := 50

	if len(op.Security) > 0 || len(s.api.Security) > 0 {
		priority += 20
	}

	if op.RequestBody != nil {
		for ct := range op.RequestBody.Content {
			if strings.Contains(ct, "multipart/form-data") || strings.Contains(ct, "application/x-www-form-urlencoded") {
				priority += 15
				break
			}
		}
	}

	if op.RequestBody != nil {
		for _, mediaType := range op.RequestBody.Content {
			if mediaType.Schema != nil && len(mediaType.Schema.Properties) > 5 {
				priority += 10
				break
			}
		}
	}

	for _, param := range op.Parameters {
		if param.Schema != nil && param.Schema.Type == "object" && len(param.Schema.Properties) > 3 {
			priority += 10
			break
		}
	}

	if strings.Contains(path, "{") && strings.Contains(path, "}") {
		priority += 5
	}

	if op.Method == "POST" || op.Method == "PUT" || op.Method == "PATCH" {
		priority += 5
	}

	if op.Method == "DELETE" {
		priority += 10
	}

	return priority
}

func (s *Scheduler) getAvailableStrategies(endpointKey string) []core.FuzzStrategyType {
	allStrategies := []core.FuzzStrategyType{
		core.FuzzStrategySQLi,
		core.FuzzStrategyXSS,
		core.FuzzStrategyPathTraversal,
		core.FuzzStrategyBoundary,
		core.FuzzStrategyTypeConfusion,
		core.FuzzStrategyFormatString,
		core.FuzzStrategyDeepNested,
		core.FuzzStrategyAuthBypass,
		core.FuzzStrategyIDOR,
		core.FuzzStrategyRateLimit,
	}

	if used, ok := s.state.UsedStrategies[endpointKey]; ok {
		var available []core.FuzzStrategyType
		for _, strat := range allStrategies {
			if !used[strat] {
				available = append(available, strat)
			}
		}
		return available
	}

	return allStrategies
}

func (s *Scheduler) GetNext() (*core.ScheduledOperation, core.FuzzStrategyType, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.priorityQueue) == 0 {
		return nil, "", false
	}

	op := s.priorityQueue[0]
	endpointKey := op.Operation.Method + " " + op.Operation.Path

	var strategy core.FuzzStrategyType
	if len(op.Strategies) > 0 {
		strategy = op.Strategies[0]
		op.Strategies = op.Strategies[1:]
	} else {
		s.priorityQueue = s.priorityQueue[1:]
		if len(s.priorityQueue) == 0 {
			return nil, "", false
		}
		op = s.priorityQueue[0]
		if len(op.Strategies) > 0 {
			strategy = op.Strategies[0]
			op.Strategies = op.Strategies[1:]
		} else {
			strategy = core.FuzzStrategyBoundary
		}
	}

	if s.state.UsedStrategies[endpointKey] == nil {
		s.state.UsedStrategies[endpointKey] = make(map[core.FuzzStrategyType]bool)
	}
	s.state.UsedStrategies[endpointKey][strategy] = true

	s.state.CurrentEndpoint = endpointKey
	s.state.CurrentStrategy = strategy

	if len(op.Strategies) == 0 {
		s.completedOps[endpointKey] = true
		s.priorityQueue = s.priorityQueue[1:]
	}

	return op, strategy, true
}

func (s *Scheduler) RecordIssue(endpointKey string, issue *core.Issue) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.ConsecutiveIssues[endpointKey]++
	s.state.ConsecutiveClean[endpointKey] = 0

	if s.state.ConsecutiveIssues[endpointKey] >= 3 {
		s.triggerDeepFuzz(endpointKey)
	}

	s.boostRelatedEndpoints(endpointKey)

	s.reprioritizeQueue()
}

func (s *Scheduler) RecordSuccess(endpointKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.ConsecutiveClean[endpointKey]++
	s.state.ConsecutiveIssues[endpointKey] = 0

	if s.state.ConsecutiveClean[endpointKey] >= 10 {
		s.applyCooling(endpointKey)
	}
}

func (s *Scheduler) triggerDeepFuzz(endpointKey string) {
	for i, op := range s.priorityQueue {
		opKey := op.Operation.Method + " " + op.Operation.Path
		if opKey == endpointKey {
			op.Priority += 50

			extraStrategies := []core.FuzzStrategyType{
				core.FuzzStrategySQLi,
				core.FuzzStrategyXSS,
				core.FuzzStrategyPathTraversal,
				core.FuzzStrategyDeepNested,
			}
			op.Strategies = append(op.Strategies, extraStrategies...)

			sort.Slice(s.priorityQueue, func(a, b int) bool {
				return s.priorityQueue[a].Priority > s.priorityQueue[b].Priority
			})
			break
		}
		_ = i
	}
}

func (s *Scheduler) boostRelatedEndpoints(endpointKey string) {
	resourceType := ""
	for rt, endpoints := range s.state.ResourceEndpoints {
		for _, ep := range endpoints {
			if ep == endpointKey {
				resourceType = rt
				break
			}
		}
		if resourceType != "" {
			break
		}
	}

	if resourceType == "" {
		return
	}

	for _, op := range s.priorityQueue {
		opKey := op.Operation.Method + " " + op.Operation.Path
		for _, ep := range s.state.ResourceEndpoints[resourceType] {
			if ep == opKey && ep != endpointKey {
				op.Priority += 30
				break
			}
		}
	}
}

func (s *Scheduler) applyCooling(endpointKey string) {
	for i, op := range s.priorityQueue {
		opKey := op.Operation.Method + " " + op.Operation.Path
		if opKey == endpointKey {
			op.Priority -= 20
			if op.Priority < 0 {
				op.Priority = 0
			}
			s.state.ConsecutiveClean[endpointKey] = 0
			break
		}
		_ = i
	}

	s.reprioritizeQueue()
}

func (s *Scheduler) reprioritizeQueue() {
	sort.Slice(s.priorityQueue, func(i, j int) bool {
		return s.priorityQueue[i].Priority > s.priorityQueue[j].Priority
	})
}

func (s *Scheduler) SetQPS(qps int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if qps < 1 {
		qps = 1
	}
	s.state.CurrentQPS = qps
}

func (s *Scheduler) GetQPS() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.CurrentQPS
}

func (s *Scheduler) Pause() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.IsPaused = true
}

func (s *Scheduler) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.IsPaused = false
}

func (s *Scheduler) IsPaused() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.IsPaused
}

func (s *Scheduler) GetState() *core.SchedulerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Scheduler) RestoreState(state *core.SchedulerState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

func (s *Scheduler) SkipCurrent() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.priorityQueue) > 0 {
		s.priorityQueue = s.priorityQueue[1:]
	}
}

func (s *Scheduler) RemainingCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, op := range s.priorityQueue {
		total += len(op.Strategies)
	}
	return total
}

func getResourceTypeFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if !strings.HasPrefix(part, "{") && !strings.HasSuffix(part, "}") {
			return part
		}
	}
	return ""
}
