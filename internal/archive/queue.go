package archive

import (
	"sync"
	"sync/atomic"
)

// queue is a FIFO bounded by bytes. Producers reserve first and then push;
// neither step waits on the writer or the disk. The writer releases an item's
// reservation once the item is written or dropped.
type queue struct {
	limit int64
	used  atomic.Int64

	mu     sync.Mutex
	items  []*queued
	closed bool
	notify chan struct{}
}

type queued struct {
	ev       *Event
	reserved int64
	// flushed, when set, is closed once the writer has handled every earlier item.
	flushed chan struct{}
}

func newQueue(limit int64) *queue {
	return &queue{limit: limit, notify: make(chan struct{}, 1)}
}

// reserve claims n bytes, failing instead of waiting when the queue is full.
func (q *queue) reserve(n int64) bool {
	if n < 0 {
		return false
	}
	for {
		cur := q.used.Load()
		if cur+n > q.limit {
			return false
		}
		if q.used.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

func (q *queue) release(n int64) {
	if n > 0 {
		q.used.Add(-n)
	}
}

// push appends an item whose bytes are already reserved. It fails after close.
func (q *queue) push(item *queued) bool {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return false
	}
	q.items = append(q.items, item)
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

// take removes and returns every queued item in order.
func (q *queue) take() []*queued {
	q.mu.Lock()
	items := q.items
	q.items = nil
	q.mu.Unlock()
	return items
}

// close refuses further pushes and returns what is still queued.
func (q *queue) close() []*queued {
	q.mu.Lock()
	q.closed = true
	items := q.items
	q.items = nil
	q.mu.Unlock()
	return items
}
