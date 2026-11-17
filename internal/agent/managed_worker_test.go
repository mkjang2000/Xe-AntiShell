package agent

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"xe-antishell/internal/storage"
)

// A fake acknowledged queue models the fixed64-record delivery transaction.
// Unacknowledged failures retain their head; successful sends advance in order.
type deliveryQueue struct {
	pending, acknowledged int
	attemptedHeads        []int
	failAttempts          map[int]error
	clock                 time.Time
	cost                  time.Duration
}

func (q *deliveryQueue) deliver(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	q.clock = q.clock.Add(q.cost)
	if q.pending == 0 {
		return true, nil
	}
	q.attemptedHeads = append(q.attemptedHeads, q.acknowledged+1)
	if err := q.failAttempts[len(q.attemptedHeads)]; err != nil {
		return false, err
	}
	size := 64
	if q.pending < size {
		size = q.pending
	}
	q.pending -= size
	q.acknowledged += size
	return false, nil
}

func TestManagedDeliveryDrainsHighVolumeInOrderWithoutIdlePerBatch(t *testing.T) {
	const records = 8192 + 17
	queue := deliveryQueue{pending: records, clock: time.Unix(1, 0), cost: 5 * time.Millisecond}
	started := queue.clock
	var waits []time.Duration
	var completed time.Duration
	runManagedDelivery(context.Background(), queue.deliver, func(_ context.Context, delay time.Duration) bool {
		waits = append(waits, delay)
		if queue.pending == 0 {
			completed = queue.clock.Sub(started)
			return false
		}
		queue.clock = queue.clock.Add(delay)
		return true
	}, func() time.Time { return queue.clock })
	if queue.pending != 0 || queue.acknowledged != records || len(queue.attemptedHeads) != 129 {
		t.Fatalf("high-volume queue did not drain: pending=%d acknowledged=%d calls=%d", queue.pending, queue.acknowledged, len(queue.attemptedHeads))
	}
	for i, head := range queue.attemptedHeads {
		if head != i*64+1 {
			t.Fatal("acknowledged delivery order changed")
		}
	}
	if completed >= 2*time.Second {
		t.Fatalf("idle interval still throttles nonempty batches: %s", completed)
	}
	for _, delay := range waits[:len(waits)-1] {
		if delay != managedDeliveryYield {
			t.Fatalf("backlog should yield briefly, got %s", delay)
		}
	}
	if waits[len(waits)-1] != managedDeliveryIdle {
		t.Fatal("drained queue did not return to idle polling")
	}
}

func TestManagedDeliveryBurstBoundsContinuousTraffic(t *testing.T) {
	for _, test := range []struct {
		name string
		cost time.Duration
		want int
	}{{"batch bound", 0, managedDeliveryBurstBatch}, {"time bound", 90 * time.Millisecond, 3}, {"slow single batch", time.Second, 1}} {
		t.Run(test.name, func(t *testing.T) {
			queue := deliveryQueue{pending: 1 << 20, clock: time.Unix(1, 0), cost: test.cost}
			waits := 0
			runManagedDelivery(context.Background(), queue.deliver, func(_ context.Context, delay time.Duration) bool {
				waits++
				if delay != managedDeliveryYield || len(queue.attemptedHeads) != test.want {
					t.Fatalf("unbounded burst: calls=%d delay=%s", len(queue.attemptedHeads), delay)
				}
				return waits < 1
			}, func() time.Time { return queue.clock })
			if waits != 1 {
				t.Fatal("continuous input never yielded")
			}
		})
	}
}

func TestManagedDeliveryKeepsUpWithTrafficAboveFormerSingleBatchRate(t *testing.T) {
	queue := deliveryQueue{pending: 1000, clock: time.Unix(1, 0), cost: 5 * time.Millisecond}
	started := queue.clock
	produced, total := 0, queue.pending
	deliver := func(ctx context.Context) (bool, error) {
		elapsed := queue.clock.Sub(started)
		if elapsed > 2*time.Second {
			elapsed = 2 * time.Second
		}
		// 200 arrivals/second exceeds the former64-record/second ceiling.
		arrivals := int(elapsed/(5*time.Millisecond)) - produced
		queue.pending += arrivals
		total += arrivals
		produced += arrivals
		return queue.deliver(ctx)
	}
	runManagedDelivery(context.Background(), deliver, func(_ context.Context, delay time.Duration) bool {
		if produced == 400 && queue.pending == 0 {
			return false
		}
		queue.clock = queue.clock.Add(delay)
		if queue.clock.Sub(started) > 3*time.Second {
			t.Fatal("ongoing traffic outran bounded delivery")
		}
		return true
	}, func() time.Time { return queue.clock })
	if queue.pending != 0 || queue.acknowledged != total || total != 1400 {
		t.Fatalf("continuous arrivals left backlog: pending=%d acknowledged=%d total=%d", queue.pending, queue.acknowledged, total)
	}
}

func TestManagedDeliveryPreservesHeadAndBackoffAcrossErrors(t *testing.T) {
	transient := errors.New("synthetic network failure")
	queue := deliveryQueue{pending: 129, clock: time.Unix(1, 0), failAttempts: map[int]error{1: transient, 2: transient, 3: transient, 5: transient}}
	var waits []time.Duration
	runManagedDelivery(context.Background(), queue.deliver, func(_ context.Context, delay time.Duration) bool {
		waits = append(waits, delay)
		queue.clock = queue.clock.Add(delay)
		return queue.pending != 0
	}, func() time.Time { return queue.clock })
	if !reflect.DeepEqual(queue.attemptedHeads, []int{1, 1, 1, 1, 65, 65, 129}) {
		t.Fatalf("retry skipped or reordered an unacknowledged head: %v", queue.attemptedHeads)
	}
	if !reflect.DeepEqual(waits, []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 2 * time.Second, time.Second}) {
		t.Fatalf("error backoff/recovery changed: %v", waits)
	}
}

func TestManagedDeliveryBackoffCapsAndMissingIdentityRemainsIdle(t *testing.T) {
	var waits []time.Duration
	attempts := 0
	runManagedDelivery(context.Background(), func(context.Context) (bool, error) {
		attempts++
		if attempts == 9 {
			return false, storage.ErrNotFound
		}
		return false, errors.New("synthetic offline central")
	}, func(_ context.Context, delay time.Duration) bool {
		waits = append(waits, delay)
		return len(waits) < 9
	}, time.Now)
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute, time.Minute, time.Second}
	if !reflect.DeepEqual(waits, want) {
		t.Fatalf("retry cap or missing enrollment behavior changed: %v", waits)
	}
}

func TestManagedDeliveryCancellationPreventsFurtherSends(t *testing.T) {
	t.Run("before initial send", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		runManagedDelivery(ctx, func(context.Context) (bool, error) { t.Fatal("sent after cancellation"); return false, nil }, func(context.Context, time.Duration) bool { t.Fatal("waited after cancellation"); return false }, time.Now)
	})
	t.Run("during send", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		runManagedDelivery(ctx, func(context.Context) (bool, error) { calls++; cancel(); return false, ctx.Err() }, func(context.Context, time.Duration) bool { t.Fatal("backed off after cancellation"); return false }, time.Now)
		if calls != 1 {
			t.Fatal("more than one request after cancellation")
		}
	})
	t.Run("during burst yield", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		runManagedDelivery(ctx, func(context.Context) (bool, error) { calls++; return false, nil }, func(waitCtx context.Context, delay time.Duration) bool {
			if delay != managedDeliveryYield {
				t.Fatal("missing cancellable burst yield")
			}
			cancel()
			return managedWait(waitCtx, delay)
		}, time.Now)
		if calls != managedDeliveryBurstBatch {
			t.Fatal("sent again after cancelled yield")
		}
	})
	for _, test := range []struct {
		name  string
		empty bool
		err   error
		delay time.Duration
	}{{"during empty idle", true, nil, time.Second}, {"during error backoff", false, errors.New("synthetic failure"), 2 * time.Second}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			calls := 0
			runManagedDelivery(ctx, func(context.Context) (bool, error) { calls++; return test.empty, test.err }, func(waitCtx context.Context, delay time.Duration) bool {
				if delay != test.delay {
					t.Fatalf("wrong wait before cancellation: %s", delay)
				}
				cancel()
				return managedWait(waitCtx, delay)
			}, time.Now)
			if calls != 1 {
				t.Fatal("sent after cancelled idle/backoff")
			}
		})
	}
}
