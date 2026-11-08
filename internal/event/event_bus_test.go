package event

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventBusIndependentDelivery(t *testing.T) {
	b := New(100)
	var storageCount, detectionCount, alertCount int64
	storageProc := func(e *Event) error { atomic.AddInt64(&storageCount, 1); return nil }
	detectionProc := func(e *Event) error { atomic.AddInt64(&detectionCount, 1); return nil }
	alertProc := func(e *Event) error { atomic.AddInt64(&alertCount, 1); return nil }
	b.SetProcessors(storageProc, detectionProc, alertProc)
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	const n = 50
	for i := 0; i < n; i++ {
		ev := NewEvent("sess", "127.0.0.1", "127.0.0.1", 1234, 22, "ssh", "ssh", EventTypeConnect, nil)
		if err := b.Publish(ev); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := atomic.LoadInt64(&storageCount); got != n {
		t.Errorf("storage processed %d, want %d", got, n)
	}
	if got := atomic.LoadInt64(&detectionCount); got != n {
		t.Errorf("detection processed %d, want %d", got, n)
	}
	if got := atomic.LoadInt64(&alertCount); got != n {
		t.Errorf("alert processed %d, want %d", got, n)
	}
	m := b.Metrics()
	if m.PublishedTotal != uint64(n) {
		t.Errorf("published %d, want %d", m.PublishedTotal, n)
	}
	if m.DroppedTotal != 0 {
		t.Errorf("dropped %d, want 0", m.DroppedTotal)
	}
}

func TestEventBusPublishAfterStopReturnsError(t *testing.T) {
	b := New(10)
	b.Start(context.Background())
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	ev := NewEvent("sess", "127.0.0.1", "127.0.0.1", 1234, 22, "ssh", "ssh", EventTypeConnect, nil)
	if err := b.Publish(ev); err != ErrBusStopped {
		t.Errorf("expected ErrBusStopped, got %v", err)
	}
}

func TestEventBusOverflowDoesNotBlock(t *testing.T) {
	b := New(2)
	storageCh := make(chan *Event, 1)
	detectionCh := make(chan *Event, 1)
	alertCh := make(chan *Event, 1)
	// Читаем из каналов в фоне, чтобы процессоры не блокировались на отправке.
	go func() {
		for range storageCh {
		}
	}()
	go func() {
		for range detectionCh {
		}
	}()
	go func() {
		for range alertCh {
		}
	}()
	b.SetProcessors(
		func(e *Event) error { storageCh <- e; return nil },
		func(e *Event) error { detectionCh <- e; return nil },
		func(e *Event) error { alertCh <- e; return nil },
	)
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	const n = 20
	var published, dropped int
	for i := 0; i < n; i++ {
		ev := NewEvent("sess", "127.0.0.1", "127.0.0.1", 1234, 22, "ssh", "ssh", EventTypeConnect, nil)
		if err := b.Publish(ev); err != nil {
			dropped++
		} else {
			published++
		}
	}
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	m := b.Metrics()
	if m.DroppedTotal == 0 {
		t.Error("expected some events to be dropped due to overflow, got 0")
	}
	if published+int(m.DroppedTotal) != n {
		t.Errorf("published %d + dropped %d != %d", published, m.DroppedTotal, n)
	}
	fmt.Printf("overflow test: published=%d dropped=%d metrics=%+v\n", published, m.DroppedTotal, m)
}

func TestEventBusConcurrentPublishAndStop(t *testing.T) {
	b := New(50)
	var processed int64
	var published int64
	b.SetProcessors(func(e *Event) error { atomic.AddInt64(&processed, 1); return nil }, nil, nil)
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	const n = 200
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			ev := NewEvent("sess", "127.0.0.1", "127.0.0.1", 1234, 22, "ssh", "ssh", EventTypeCommand, nil)
			if err := b.Publish(ev); err == nil {
				atomic.AddInt64(&published, 1)
			}
		}
	}()
	// Ждем, пока будет опубликовано хотя бы одно событие, перед остановкой.
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt64(&published) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no event was published before deadline")
		}
		time.Sleep(time.Millisecond)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	<-done
	if got, accepted, downstreamDropped := atomic.LoadInt64(&processed), atomic.LoadInt64(&published), b.Metrics().StorageDropped; uint64(got)+downstreamDropped != uint64(accepted) {
		t.Errorf("processed %d + explicitly dropped %d, want accepted publications %d", got, downstreamDropped, accepted)
	}
	if b.IsStopped() != true {
		t.Error("bus should be stopped")
	}
}

func TestEventBusGracefulShutdownCompletesWorkers(t *testing.T) {
	b := New(100)
	var wg sync.WaitGroup
	storageProc := func(e *Event) error {
		wg.Add(1)
		defer wg.Done()
		time.Sleep(time.Millisecond)
		return nil
	}
	b.SetProcessors(storageProc, nil, nil)
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	for i := 0; i < 10; i++ {
		ev := NewEvent("sess", "127.0.0.1", "127.0.0.1", 1234, 22, "ssh", "ssh", EventTypeConnect, nil)
		if err := b.Publish(ev); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := b.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not complete after shutdown")
	}
	m := b.Metrics()
	if m.StorageProcessed != 10 {
		t.Errorf("storage processed %d, want 10", m.StorageProcessed)
	}
}

func TestEventBusStartTwiceReturnsError(t *testing.T) {
	b := New(10)
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := b.Start(ctx); err != ErrAlreadyStarted {
		t.Errorf("expected ErrAlreadyStarted, got %v", err)
	}
	b.Stop(context.Background())
}
