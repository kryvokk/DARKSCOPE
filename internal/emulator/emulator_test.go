package emulator

import (
	"strings"
	"sync"
	"testing"
)

type capture struct {
	mu       sync.Mutex
	commands int
	tokens   int
}

func (c *capture) PublishCommand(_, _, _, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commands++
	if token != "" {
		c.tokens++
	}
}
func TestParseQuotesEscapesAndRejectsShell(t *testing.T) {
	c, e := Parse(`echo "hello world" a\ b`)
	if e != nil || len(c) != 1 || len(c[0].Args) != 3 || c[0].Args[1] != "hello world" || c[0].Args[2] != "a b" {
		t.Fatalf("parse=%#v err=%v", c, e)
	}
	for _, s := range []string{"echo x;id", "echo $(id)", "cat x | sh", "echo 'unterminated"} {
		if _, e := Parse(s); e == nil {
			t.Fatalf("accepted unsafe input %q", s)
		}
	}
}
func TestVFSSafetyAndResourceBounds(t *testing.T) {
	f := NewFS()
	if e := f.WriteFile("../../../../host-file", "x", "/home/user"); e == nil {
		t.Fatal("path traversal accepted")
	}
	if e := f.WriteFile("/tmp/huge", strings.Repeat("x", MaxFileBytes+1), "/"); e == nil {
		t.Fatal("oversize accepted")
	}
	if e := f.WriteFile("/tmp/a", "ok", "/"); e != nil {
		t.Fatal(e)
	}
	if got, e := f.ReadFile("/tmp/a", "/"); e != nil || got != "ok" {
		t.Fatalf("read %q %v", got, e)
	}
}
func TestSessionIsolationCommandsAndHoneytoken(t *testing.T) {
	cap := &capture{}
	a := New("a", "ssh", cap)
	b := New("b", "telnet", cap)
	if r := a.Execute("touch isolated"); r.ExitCode != 0 {
		t.Fatal(r)
	}
	if _, e := b.FS.Stat("isolated", b.Cwd); e == nil {
		t.Fatal("session state leaked")
	}
	a.Execute("cat /etc/shadow")
	if cap.commands != 2 || cap.tokens != 1 {
		t.Fatalf("events command=%d honeytoken=%d", cap.commands, cap.tokens)
	}
}
func TestConcurrentVFS(t *testing.T) {
	f := NewFS()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := strings.Repeat("x", i+1)
			_ = f.WriteFile("/tmp/file"+p, p, "/")
			_, _ = f.List("/tmp", "/")
		}(i)
	}
	wg.Wait()
}
