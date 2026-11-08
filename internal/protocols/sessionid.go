package protocols

import (
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"
)

// sessionIDSeq — резерв для генерации ID, если crypto/rand недоступен.
var sessionIDSeq atomic.Uint64

// NewSessionID генерирует уникальный идентификатор сессии collector'а
// на основе crypto/rand (128 бит hex с префиксом протокола). При ошибке
// rand используется монотонный счётчик, чтобы ID остались уникальными.
func NewSessionID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		n := sessionIDSeq.Add(1)
		binary.BigEndian.PutUint64(b[8:], n)
	}
	return prefix + "-" + hexEncode(b)
}

func hexEncode(b [16]byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 32)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}
