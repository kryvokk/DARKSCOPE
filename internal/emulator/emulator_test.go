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

func TestEveryRegisteredCommandBehavior(t *testing.T) {
	// Every command is named explicitly here; failures include the command name.
	cases := map[string]string{"pwd": "/home/user", "cd /tmp": "", "ls /": "home", "tree /tmp": "/tmp", "cat /etc/passwd": "root:x", "head /etc/passwd": "root:x", "tail /etc/passwd": "user:x", "less /etc/passwd": "root:x", "more /etc/passwd": "root:x", "touch /tmp/t": "", "mkdir /tmp/d": "", "rm /tmp/t": "", "cp /etc/passwd /tmp/copy": "", "mv /tmp/copy /tmp/moved": "", "find /etc -name passwd": "/etc/passwd", "file /etc/passwd": "regular file", "stat /etc/passwd": "Size:", "whoami": "user", "id": "uid=1000", "hostname": "darkscope", "uname": "Linux darkscope", "uptime": "up 72h", "date": "2026", "env": "HOME=", "printenv USER": "user", "history": "pwd", "ps": "init", "top": "init", "df": "/dev/fake", "free": "2048000", "mount": "/proc", "ip": "eth0", "ifconfig": "eth0", "ping host": "simulated", "netstat": "LISTEN", "ss": "LISTEN", "curl http://x": "simulated", "wget http://x": "simulated", "ssh host": "simulated", "scp a b": "simulated", "help": "pwd", "man ls": "pwd", "echo hello": "hello", "printf hello": "hello", "grep root /etc/passwd": "root:x", "wc /etc/passwd": "2 2", "sort /etc/passwd": "root:x", "uniq /etc/passwd": "root:x", "which ls": "/usr/bin/ls"}
	if len(cases) != len(commandNames) {
		t.Fatalf("test map has %d commands; registry has %d", len(cases), len(commandNames))
	}
	for _, name := range commandNames {
		found := false
		for spec := range cases {
			if strings.Fields(spec)[0] == name {
				found = true
			}
		}
		if !found {
			t.Errorf("command %s has no behavioral test", name)
		}
	}
	for cmd, want := range cases {
		t.Run(strings.ReplaceAll(cmd, " ", "_"), func(t *testing.T) {
			e := New("test", "ssh", nil)
			if strings.HasPrefix(cmd, "rm ") {
				e.FS.WriteFile("/tmp/t", "x", "/")
			}
			if strings.HasPrefix(cmd, "mv ") {
				e.FS.WriteFile("/tmp/copy", "x", "/")
			}
			if cmd == "history" {
				e.Execute("pwd")
			}
			r := e.Execute(cmd)
			if r.ExitCode != 0 {
				t.Fatalf("%s exit %d: %s", cmd, r.ExitCode, r.Err)
			}
			if !strings.Contains(r.Out, want) {
				t.Fatalf("%s output %q lacks %q", cmd, r.Out, want)
			}
		})
	}
}

func TestFilesystemCommandWorkflow(t *testing.T) {
	e := New("workflow", "ssh", nil)
	if r := e.Execute("mkdir work"); r.ExitCode != 0 {
		t.Fatal(r)
	}
	e.Execute("cd work")
	e.FS.WriteFile("a", "alpha\nbeta\n", "/home/user/work")
	if got := e.Execute("cat a").Out; got != "alpha\nbeta\n" {
		t.Fatal(got)
	}
	if got := e.Execute("grep beta a").Out; got != "beta\n" {
		t.Fatal(got)
	}
	if !strings.HasPrefix(e.Execute("wc a").Out, "2 2 ") {
		t.Fatal("wc mismatch")
	}
	e.Execute("cp a b")
	e.Execute("mv b c")
	e.Execute("rm c")
	if _, err := e.FS.Stat("c", e.Cwd); err == nil {
		t.Fatal("rm left file")
	}
}

func TestRegistryMatchesSpecification(t *testing.T) {
	spec := strings.Fields("pwd cd ls tree cat head tail less more touch mkdir rm cp mv find file stat whoami id hostname uname uptime date env printenv history ps top df free mount ip ifconfig ping netstat ss curl wget ssh scp help man echo printf grep wc sort uniq which")
	got := map[string]bool{}
	for _, c := range commandNames {
		got[c] = true
	}
	for _, c := range spec {
		if !got[c] {
			t.Errorf("missing command %s", c)
		}
	}
	if len(got) != len(spec) {
		t.Fatalf("registry count %d differs from spec %d", len(got), len(spec))
	}
}
