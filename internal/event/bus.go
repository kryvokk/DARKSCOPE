package event

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// Ошибки шины события.
var (
	ErrBusStopped     = errors.New("event bus is stopped")
	ErrQueueFull      = errors.New("event queue is full")
	ErrAlreadyStarted = errors.New("event bus already started")
)

// Processor обрабатывает событие. nil означает "подсчитать как доставленное".
type Processor func(*Event) error

// Metrics содержит счетчики шины события.
type Metrics struct {
	PublishedTotal     uint64
	DroppedTotal       uint64
	StorageProcessed   uint64
	StorageDropped     uint64
	StorageErrors      uint64
	DetectionProcessed uint64
	DetectionDropped   uint64
	DetectionErrors    uint64
	AlertProcessed     uint64
	AlertDropped       uint64
	AlertErrors        uint64
	InputQueueLen      int
	StorageQueueLen    int
	DetectionQueueLen  int
	AlertQueueLen      int
}

// EventBus доставляет каждое событие независимо всем трём подписчикам
// (Storage, Detection, Alert) через отдельные буферизированные каналы.
// События не konkurрируют за одну общую очередь — у каждого подписчика своя.
type EventBus struct {
	publishMu sync.RWMutex // linearizes Publish against Stop
	in        chan *Event

	storageChan   chan *Event
	detectionChan chan *Event
	alertChan     chan *Event

	stopCh chan struct{}
	wg     sync.WaitGroup

	started atomic.Bool
	stopped atomic.Bool

	// Процессоры (могут быть nil — тогда событие только считается доставленным)
	storageProc   Processor
	detectionProc Processor
	alertProc     Processor

	// Метрики (atomic)
	publishedTotal     uint64
	droppedTotal       uint64
	storageProcessed   uint64
	storageDropped     uint64
	storageErrors      uint64
	detectionProcessed uint64
	detectionDropped   uint64
	detectionErrors    uint64
	alertProcessed     uint64
	alertDropped       uint64
	alertErrors        uint64
}

// New создает EventBus с заданными размерами буферов.
// bufferSize — размер основной входной очереди и каждой очереди подписчика.
func New(bufferSize int) *EventBus {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	return &EventBus{
		in:            make(chan *Event, bufferSize),
		storageChan:   make(chan *Event, bufferSize),
		detectionChan: make(chan *Event, bufferSize),
		alertChan:     make(chan *Event, bufferSize),
		stopCh:        make(chan struct{}),
	}
}

// SetProcessors назначает обработчики для подписчиков.
func (b *EventBus) SetProcessors(storage, detection, alert Processor) {
	b.storageProc = storage
	b.detectionProc = detection
	b.alertProc = alert
}

// Start запускает диспетчер и воркеры подписчиков.
func (b *EventBus) Start(ctx context.Context) error {
	if !b.started.CompareAndSwap(false, true) {
		return ErrAlreadyStarted
	}
	if b.stopped.Load() {
		return ErrBusStopped
	}

	b.wg.Add(1)
	go b.dispatch()

	// Один dedicated воркер на очередь подписчика. Это гарантирует
	// независимую доставку: каждый подписчик обрабатывает события своей
	// очередью и не konkurрирует с другими.
	b.wg.Add(1)
	go b.worker(b.storageChan, b.storageProc, &b.storageProcessed, &b.storageDropped, &b.storageErrors)
	b.wg.Add(1)
	go b.worker(b.detectionChan, b.detectionProc, &b.detectionProcessed, &b.detectionDropped, &b.detectionErrors)
	b.wg.Add(1)
	go b.worker(b.alertChan, b.alertProc, &b.alertProcessed, &b.alertDropped, &b.alertErrors)

	// Следим за отменой контекста для остановки.
	go func() {
		<-ctx.Done()
		_ = b.Stop(context.Background())
	}()

	return nil
}

// Publish публикует событие. Не блокирует вызывающего: при переполнении
// входной очереди событие отбрасывается и возвращается ErrQueueFull.
// После остановки шины возвращает ErrBusStopped.
func (b *EventBus) Publish(ev *Event) error {
	b.publishMu.RLock()
	defer b.publishMu.RUnlock()
	if b.stopped.Load() {
		return ErrBusStopped
	}
	select {
	case b.in <- ev:
		atomic.AddUint64(&b.publishedTotal, 1)
		return nil
	default:
		atomic.AddUint64(&b.droppedTotal, 1)
		return ErrQueueFull
	}
}

// dispatch читает события из основной очереди и независимо разносит их
// по очередям подписчиков (неблокирующе). Медленный подписчик не блокирует
// остальные. При остановке дочитывает все оставшиеся события из in
// неблокирующе (in не закрывается явно, чтобы избежать race с Publish).
func (b *EventBus) dispatch() {
	defer b.wg.Done()
	for {
		select {
		case <-b.stopCh:
			// Дреним все оставшиеся события из in неблокирующе.
			for {
				select {
				case ev, ok := <-b.in:
					if !ok {
						goto drainDone
					}
					b.fanOut(ev)
				default:
					goto drainDone // in пуст
				}
			}
		drainDone:
			close(b.storageChan)
			close(b.detectionChan)
			close(b.alertChan)
			return
		case ev, ok := <-b.in:
			if !ok {
				close(b.storageChan)
				close(b.detectionChan)
				close(b.alertChan)
				return
			}
			b.fanOut(ev)
		}
	}
}

// fanOut отправляет событие в каждую очередь подписчика неблокирующе.
// При переполнении очереди одного подписчика событие для него отбрасывается,
// остальные подписчики получают событие независимо.
func (b *EventBus) fanOut(ev *Event) {
	submit := func(ch chan<- *Event, dropped *uint64) bool {
		select {
		case ch <- ev:
			return true
		default:
			atomic.AddUint64(dropped, 1)
			return false
		}
	}
	submit(b.storageChan, &b.storageDropped)
	submit(b.detectionChan, &b.detectionDropped)
	submit(b.alertChan, &b.alertDropped)
}

// worker читает события из очереди подписчика и обрабатывает их.
// Завершается при закрытии канала.
func (b *EventBus) worker(ch <-chan *Event, proc Processor, processed, dropped, errors *uint64) {
	defer b.wg.Done()
	for ev := range ch {
		if proc != nil {
			if err := proc(ev); err != nil {
				atomic.AddUint64(errors, 1)
				continue
			}
		}
		atomic.AddUint64(processed, 1)
	}
}

// Stop инициирует graceful shutdown:
// 1. перестает принимать новые события (устанавливает stopped),
// 2. дренит очереди (дочитывает все события из in),
// 3. ждет завершения всех обработчиков с таймаутом.
func (b *EventBus) Stop(ctx context.Context) error {
	b.publishMu.Lock()
	if !b.stopped.CompareAndSwap(false, true) {
		b.publishMu.Unlock()
		return nil // уже остановлен
	}
	close(b.stopCh)
	b.publishMu.Unlock()
	// in не закрывается здесь — диспетчер дочитает его и сам завершится.

	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Metrics возвращает текущие счетчики и длины очередей (моментальный снимок).
func (b *EventBus) Metrics() Metrics {
	return Metrics{
		PublishedTotal:     atomic.LoadUint64(&b.publishedTotal),
		DroppedTotal:       atomic.LoadUint64(&b.droppedTotal),
		StorageProcessed:   atomic.LoadUint64(&b.storageProcessed),
		StorageDropped:     atomic.LoadUint64(&b.storageDropped),
		StorageErrors:      atomic.LoadUint64(&b.storageErrors),
		DetectionProcessed: atomic.LoadUint64(&b.detectionProcessed),
		DetectionDropped:   atomic.LoadUint64(&b.detectionDropped),
		DetectionErrors:    atomic.LoadUint64(&b.detectionErrors),
		AlertProcessed:     atomic.LoadUint64(&b.alertProcessed),
		AlertDropped:       atomic.LoadUint64(&b.alertDropped),
		AlertErrors:        atomic.LoadUint64(&b.alertErrors),
		InputQueueLen:      len(b.in),
		StorageQueueLen:    len(b.storageChan),
		DetectionQueueLen:  len(b.detectionChan),
		AlertQueueLen:      len(b.alertChan),
	}
}

// IsStopped возвращает true, если шина остановлена.
func (b *EventBus) IsStopped() bool {
	return b.stopped.Load()
}
