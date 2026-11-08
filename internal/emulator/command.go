package emulator

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const MaxCommandBytes = 4096
const MaxOutputBytes = 65536

type Command struct{ Args []string }
type Result struct {
	Out, Err   string
	ExitCode   int
	Honeytoken string
}
type Publisher interface {
	PublishCommand(sessionID, command, output string, honeytoken string)
}
type Emulator struct {
	FS                                   *FS
	Cwd, User, Host, SessionID, Protocol string
	History                              []string
	publisher                            Publisher
}

func New(sessionID, protocol string, p Publisher) *Emulator {
	return &Emulator{FS: NewFS(), Cwd: "/home/user", User: "user", Host: "darkscope", SessionID: sessionID, Protocol: protocol, publisher: p}
}

// Parse implements a deliberately small shell-like lexer. Operators and command substitution are rejected.
func Parse(input string) ([]Command, error) {
	if len(input) > MaxCommandBytes {
		return nil, errors.New("command too long")
	}
	commands := []Command{}
	args := []string{}
	var b strings.Builder
	quote := rune(0)
	escape := false
	started := false
	flushArg := func() {
		if started {
			args = append(args, b.String())
			b.Reset()
			started = false
		}
	}
	flushCmd := func() {
		flushArg()
		if len(args) > 0 {
			commands = append(commands, Command{Args: args})
			args = nil
		}
	}
	for _, r := range input {
		if escape {
			b.WriteRune(r)
			started = true
			escape = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escape = true
			started = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			started = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			started = true
			continue
		}
		if r == '|' || r == '>' || r == '<' || r == '`' || r == '$' || r == ';' {
			return nil, fmt.Errorf("unsupported shell operator %q", r)
		}
		if r == ' ' || r == '\t' || r == '\n' {
			flushArg()
			continue
		}
		b.WriteRune(r)
		started = true
	}
	if escape || quote != 0 {
		return nil, errors.New("unterminated quote or escape")
	}
	flushCmd()
	return commands, nil
}

var commandNames = []string{"pwd", "cd", "ls", "tree", "cat", "head", "tail", "less", "more", "touch", "mkdir", "rm", "cp", "mv", "find", "file", "stat", "whoami", "id", "hostname", "uname", "uptime", "date", "env", "printenv", "history", "ps", "top", "df", "free", "mount", "ip", "ifconfig", "ping", "netstat", "ss", "curl", "wget", "ssh", "scp", "help", "man", "echo", "printf", "grep", "wc", "sort", "uniq", "which"}

func (e *Emulator) Execute(line string) Result {
	cmds, err := Parse(line)
	if err != nil {
		return Result{Err: err.Error(), ExitCode: 2}
	}
	var out strings.Builder
	result := Result{}
	for _, c := range cmds {
		if len(e.History) < 1000 {
			e.History = append(e.History, line)
		}
		r := e.execute(c.Args)
		out.WriteString(r.Out)
		if r.Err != "" {
			result.Err = r.Err
		}
		if r.ExitCode != 0 {
			result.ExitCode = r.ExitCode
		}
		if r.Honeytoken != "" {
			result.Honeytoken = r.Honeytoken
		}
	}
	result.Out = out.String()
	if len(result.Out) > MaxOutputBytes {
		result.Out = result.Out[:MaxOutputBytes]
	}
	if e.publisher != nil {
		e.publisher.PublishCommand(e.SessionID, line, result.Out, result.Honeytoken)
	}
	return result
}
func (e *Emulator) execute(a []string) Result {
	if len(a) == 0 {
		return Result{}
	}
	cmd := a[0]
	args := a[1:]
	fail := func(err error) Result { return Result{Err: cmd + ": " + err.Error() + "\n", ExitCode: 1} }
	switch cmd {
	case "pwd":
		return Result{Out: e.Cwd + "\n"}
	case "cd":
		p := "/home/user"
		if len(args) > 0 {
			p = args[0]
		}
		q, err := e.FS.Chdir(p, e.Cwd)
		if err != nil {
			return fail(err)
		}
		e.Cwd = q
		return Result{}
	case "whoami":
		return Result{Out: e.User + "\n"}
	case "hostname":
		return Result{Out: e.Host + "\n"}
	case "uname":
		return Result{Out: "Linux darkscope 6.1.0-fake x86_64 GNU/Linux\n"}
	case "id":
		return Result{Out: "uid=1000(user) gid=1000(user) groups=1000(user)\n"}
	case "date":
		return Result{Out: "Sun Nov  8 00:00:00 UTC 2026\n"}
	case "echo", "printf":
		return Result{Out: strings.Join(args, " ") + map[bool]string{true: "", false: "\n"}[cmd == "printf"]}
	case "help", "man":
		return Result{Out: strings.Join(commandNames, " ") + "\n"}
	case "history":
		var b strings.Builder
		for i, s := range e.History {
			fmt.Fprintf(&b, "%4d  %s\n", i+1, s)
		}
		return Result{Out: b.String()}
	case "ls", "tree":
		p := "."
		if len(args) > 0 {
			p = args[len(args)-1]
		}
		names, err := e.FS.List(p, e.Cwd)
		if err != nil {
			return fail(err)
		}
		return Result{Out: strings.Join(names, "  ") + "\n"}
	case "cat", "less", "more", "head", "tail":
		if len(args) == 0 {
			return fail(errors.New("missing file operand"))
		}
		data, err := e.FS.ReadFile(args[len(args)-1], e.Cwd)
		if err != nil {
			return fail(err)
		}
		q, _ := e.FS.Resolve(args[len(args)-1], e.Cwd)
		r := Result{Out: data}
		if cmd == "head" || cmd == "tail" {
			lines := strings.Split(data, "\n")
			if cmd == "head" && len(lines) > 10 {
				lines = lines[:10]
			}
			if cmd == "tail" && len(lines) > 10 {
				lines = lines[len(lines)-10:]
			}
			r.Out = strings.Join(lines, "\n")
		}
		if isHoneytoken(q) {
			r.Honeytoken = q
		}
		return r
	case "find":
		base := "."
		needle := ""
		for i, a := range args {
			if a == "-name" && i+1 < len(args) {
				needle = strings.Trim(args[i+1], "'\"")
			} else if !strings.HasPrefix(a, "-") {
				base = a
			}
		}
		root, err := e.FS.Resolve(base, e.Cwd)
		if err != nil {
			return fail(err)
		}
		var found []string
		for _, p := range e.FS.Paths() {
			if p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/") {
				if needle == "" || strings.Contains(p, needle) {
					found = append(found, p)
				}
			}
		}
		return Result{Out: strings.Join(found, "\n") + "\n"}
	case "stat", "file":
		if len(args) == 0 {
			return fail(errors.New("missing file operand"))
		}
		n, err := e.FS.Stat(args[0], e.Cwd)
		if err != nil {
			return fail(err)
		}
		typ := "regular file"
		if n.Dir {
			typ = "directory"
		}
		if cmd == "file" {
			return Result{Out: args[0] + ": " + typ + "\n"}
		}
		return Result{Out: fmt.Sprintf("File: %s\nSize: %d\nMode: %04o\nOwner: %s:%s\n", args[0], len(n.Data), n.Mode, n.Owner, n.Group)}
	case "grep":
		if len(args) < 2 {
			return fail(errors.New("usage: grep pattern file"))
		}
		d, err := e.FS.ReadFile(args[1], e.Cwd)
		if err != nil {
			return fail(err)
		}
		var lines []string
		for _, l := range strings.Split(d, "\n") {
			if strings.Contains(l, args[0]) {
				lines = append(lines, l)
			}
		}
		return Result{Out: strings.Join(lines, "\n") + "\n"}
	case "sort", "uniq":
		if len(args) == 0 {
			return fail(errors.New("missing file operand"))
		}
		d, err := e.FS.ReadFile(args[0], e.Cwd)
		if err != nil {
			return fail(err)
		}
		lines := strings.Split(strings.TrimSuffix(d, "\n"), "\n")
		if cmd == "sort" {
			sort.Strings(lines)
		} else {
			out := lines[:0]
			for _, l := range lines {
				if len(out) == 0 || out[len(out)-1] != l {
					out = append(out, l)
				}
			}
			lines = out
		}
		return Result{Out: strings.Join(lines, "\n") + "\n"}
	case "touch":
		for _, p := range args {
			if _, err := e.FS.Stat(p, e.Cwd); err != nil {
				if err = e.FS.WriteFile(p, "", e.Cwd); err != nil {
					return fail(err)
				}
			}
		}
		return Result{}
	case "mkdir":
		for _, p := range args {
			if err := e.FS.Mkdir(p, e.Cwd); err != nil {
				return fail(err)
			}
		}
		return Result{}
	case "rm":
		for _, p := range args {
			if err := e.FS.Remove(p, e.Cwd); err != nil {
				return fail(err)
			}
		}
		return Result{}
	case "cp", "mv":
		if len(args) != 2 {
			return fail(errors.New("requires source and destination"))
		}
		var err error
		if cmd == "cp" {
			err = e.FS.Copy(args[0], args[1], e.Cwd)
		} else {
			err = e.FS.Move(args[0], args[1], e.Cwd)
		}
		if err != nil {
			return fail(err)
		}
		return Result{}
	case "env", "printenv":
		return Result{Out: "HOME=/home/user\nUSER=user\nSHELL=/bin/bash\nPWD=" + e.Cwd + "\n"}
	case "ps", "top":
		return Result{Out: "PID TTY TIME CMD\n1 ? 00:00:01 init\n42 ? 00:00:00 sshd: user\n"}
	case "df":
		return Result{Out: "Filesystem Size Used Avail Use% Mounted on\n/dev/fake 20G 4G 16G 20% /\n"}
	case "free":
		return Result{Out: "              total        used        free\nMem:        2048000      512000     1536000\n"}
	case "ip", "ifconfig":
		return Result{Out: "lo: 127.0.0.1\neth0: 192.0.2.10/24\n"}
	case "ping", "curl", "wget", "ssh", "scp":
		return Result{Out: "network operation simulated; no connection made\n"}
	case "netstat", "ss", "mount":
		return Result{Out: "tcp LISTEN 0 128 0.0.0.0:2222\ntcp LISTEN 0 128 0.0.0.0:8080\ntcp LISTEN 0 128 0.0.0.0:2323\n"}
	case "which":
		if len(args) > 0 {
			for _, n := range commandNames {
				if n == args[0] {
					return Result{Out: "/usr/bin/" + n + "\n"}
				}
			}
			return Result{Err: args[0] + " not found\n", ExitCode: 1}
		}
	case "wc":
		if len(args) > 0 {
			d, err := e.FS.ReadFile(args[0], e.Cwd)
			if err != nil {
				return fail(err)
			}
			return Result{Out: fmt.Sprintf("%d %d %d\n", strings.Count(d, "\n"), len(strings.Fields(d)), len(d))}
		}
	}
	if !knownCommand(cmd) {
		return fail(errors.New("command not found"))
	}
	return Result{Out: ""}
}
func knownCommand(s string) bool {
	for _, n := range commandNames {
		if s == n {
			return true
		}
	}
	return false
}
func isHoneytoken(p string) bool {
	switch p {
	case "/root/.bash_history", "/home/user/.ssh/id_rsa", "/home/user/.aws/credentials", "/etc/passwd", "/etc/shadow", "/var/log/auth.log", "/var/www/html/config.php", "/opt/app/.env":
		return true
	}
	return false
}
