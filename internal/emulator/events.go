package emulator

import (
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/protocols"
)

type BusPublisher struct {
	Bus                  protocols.Publisher
	SourceIP             string
	SourcePort, DestPort int
	Protocol             string
}

func (p BusPublisher) PublishCommand(sid, cmd, output, token string) {
	if p.Bus == nil {
		return
	}
	ev := event.NewEvent(sid, p.SourceIP, "127.0.0.1", p.SourcePort, p.DestPort, p.Protocol, p.Protocol, event.EventTypeCommand, map[string]interface{}{"command": cmd, "output": truncate(output)})
	ev.WithSeverity(event.SeverityLow)
	_ = p.Bus.Publish(ev)
	if token != "" {
		h := event.NewEvent(sid, p.SourceIP, "127.0.0.1", p.SourcePort, p.DestPort, p.Protocol, p.Protocol, event.EventTypeHoneytokenAccess, map[string]interface{}{"path": token, "command": cmd})
		h.WithSeverity(event.SeverityHigh)
		_ = p.Bus.Publish(h)
	}
}
func truncate(s string) string {
	if len(s) > MaxOutputBytes {
		return s[:MaxOutputBytes]
	}
	return s
}
