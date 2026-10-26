// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sync // import "go.opentelemetry.io/obi/pkg/internal/helpers/sync"

import (
	"context"
	"sync"
)

// Queue is a FIFO structure that allows asynchronously enqueuing messages and synchronously dequeuing them.
// The Dequeue operation is blocked until there is any content in the queue.
// You can see a Queue as a channel with infinite capacity where you can keep sending
// elements without getting blocked.
// TODO: can we replace this by channel-based msg.Queue?
type Queue[T any] struct {
	head   *node[T]
	tail   *node[T]
	limit  int
	length int
	mutex  sync.Mutex
	cond   *sync.Cond
}

type node[T any] struct {
	value T
	prev  *node[T]
}

func NewQueue[T any]() *Queue[T] {
	q := &Queue[T]{}
	q.cond = sync.NewCond(&q.mutex)
	return q
}

// NewBoundedQueue creates a FIFO queue that rejects new items when capacity is reached.
func NewBoundedQueue[T any](capacity int) *Queue[T] {
	if capacity <= 0 {
		panic("queue capacity must be positive")
	}
	q := &Queue[T]{limit: capacity}
	q.cond = sync.NewCond(&q.mutex)
	return q
}

// Enqueue adds an element unless a bounded queue has reached its capacity. This operation never blocks.
func (q *Queue[T]) Enqueue(item T) {
	q.TryEnqueue(item)
}

// TryEnqueue adds an element unless the queue has reached its configured capacity.
// It returns false when a bounded queue is full.
func (q *Queue[T]) TryEnqueue(item T) bool {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if q.limit > 0 && q.length >= q.limit {
		return false
	}
	q.append(item)
	q.cond.Signal() // Wake up one waiting goroutine
	return true
}

// Len returns the number of items currently queued.
func (q *Queue[T]) Len() int {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	return q.length
}

// Dequeue retrieves the firs element in the queue. If the queue is empty, Dequeue will
// block the current goroutine until there is any available element.
func (q *Queue[T]) Dequeue() T {
	q.mutex.Lock()
	for q.head == nil {
		q.cond.Wait()
	}
	item := q.remove()
	q.mutex.Unlock()
	return item
}

// TryDequeue retrieves the first element in the queue without blocking. The returned boolean
// is false if the queue is empty.
func (q *Queue[T]) TryDequeue() (T, bool) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if q.head == nil {
		var zero T
		return zero, false
	}
	return q.remove(), true
}

// DequeueContext retrieves the first element in the queue. If the queue is empty, DequeueContext
// blocks until an element is available or the context is canceled.
func (q *Queue[T]) DequeueContext(ctx context.Context) (T, error) {
	stop := context.AfterFunc(ctx, func() {
		q.mutex.Lock()
		q.cond.Broadcast()
		q.mutex.Unlock()
	})
	defer stop()

	q.mutex.Lock()
	defer q.mutex.Unlock()

	for {
		if err := ctx.Err(); err != nil {
			var zero T
			return zero, err
		}
		if q.head != nil {
			return q.remove(), nil
		}
		q.cond.Wait()
	}
}

func (q *Queue[T]) append(item T) {
	n := node[T]{value: item}
	if q.tail == nil {
		q.tail = &n
		q.head = &n
	} else {
		q.tail.prev = &n
		q.tail = &n
	}
	q.length++
}

func (q *Queue[T]) remove() T {
	v := q.head
	q.head = v.prev
	if q.head == nil {
		q.tail = nil
	}
	q.length--
	return v.value
}
