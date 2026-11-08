package protocols

import (
	"net"
	"sync"
)

// LimitedListener оборачивает net.Listener и ограничивает число
// одновременно «принятых» (не закрытых) соединений значением max.
// Сверх лимита соединение сразу закрывается; закрытие соединения
// освобождает слот. max <= 0 — без ограничения (passthrough).
type LimitedListener struct {
	net.Listener
	sem chan struct{}
}

// NewLimitedListener создаёт ограничивающий слушатель.
func NewLimitedListener(l net.Listener, max int) *LimitedListener {
	if max <= 0 {
		return &LimitedListener{Listener: l}
	}
	return &LimitedListener{
		Listener: l,
		sem:      make(chan struct{}, max),
	}
}

// Accept принимает соединение либо отклоняет его при исчерпании лимита.
func (l *LimitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitedConn{Conn: conn, sem: l.sem}, nil
		default:
			_ = conn.Close()
		}
	}
}

// limitedConn освобождает слот при закрытии; once защищает от
// двойного освобождения при повторном Close (безопасно для net/http).
type limitedConn struct {
	net.Conn
	sem  chan struct{}
	once sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		<-c.sem
	})
	return err
}
