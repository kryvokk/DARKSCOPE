package emulator

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

const MaxFiles = 4096
const MaxFileBytes = 1 << 20

type Node struct {
	Name         string
	Dir          bool
	Data         string
	Mode         uint32
	Owner, Group string
	ModTime      time.Time
}
type FS struct {
	mu    sync.RWMutex
	nodes map[string]Node
	used  int
}

func NewFS() *FS {
	f := &FS{nodes: map[string]Node{}}
	now := time.Now().UTC()
	for _, p := range []string{"/", "/root", "/home", "/home/user", "/etc", "/var", "/var/log", "/tmp", "/usr", "/usr/bin", "/opt", "/proc", "/dev", "/home/user/.ssh", "/home/user/.aws", "/var/www", "/var/www/html", "/opt/app"} {
		f.nodes[p] = Node{Name: path.Base(p), Dir: true, Mode: 0755, Owner: "root", Group: "root", ModTime: now}
	}
	for p, s := range map[string]string{"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n", "/etc/shadow": "root:$6$FAKE$not-a-real-hash:19000:0:99999:7:::\n", "/root/.bash_history": "sudo -l\ncat /etc/shadow\n", "/home/user/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE-NOT-A-REAL-KEY\n-----END OPENSSH PRIVATE KEY-----\n", "/home/user/.aws/credentials": "[default]\naws_access_key_id = FAKEKEY000000000000\naws_secret_access_key = fake-not-valid\n", "/var/log/auth.log": "Nov 08 00:00:01 darkscope sshd[100]: Failed password for root\n", "/var/www/html/config.php": "<?php $db_password = 'fake-not-valid'; ?>\n", "/opt/app/.env": "DB_PASSWORD=fake-not-valid\n"} {
		_ = f.WriteFile(p, s, "user")
	}
	return f
}

func clean(p, cwd string) (string, error) {
	if p == "" {
		p = "."
	}
	if !strings.HasPrefix(p, "/") {
		p = strings.TrimSuffix(cwd, "/") + "/" + p
	}
	parts := strings.Split(p, "/")
	stack := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
		case "..":
			if len(stack) == 0 {
				return "", errors.New("path escapes virtual root")
			}
			stack = stack[:len(stack)-1]
		default:
			stack = append(stack, part)
		}
	}
	return "/" + strings.Join(stack, "/"), nil
}
func (f *FS) Resolve(p, cwd string) (string, error) { return clean(p, cwd) }
func (f *FS) Stat(p, cwd string) (Node, error) {
	q, e := clean(p, cwd)
	if e != nil {
		return Node{}, e
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, ok := f.nodes[q]
	if !ok {
		return Node{}, fmt.Errorf("%s: no such file or directory", p)
	}
	return n, nil
}
func (f *FS) ReadFile(p, cwd string) (string, error) {
	n, e := f.Stat(p, cwd)
	if e != nil {
		return "", e
	}
	if n.Dir {
		return "", fmt.Errorf("%s: is a directory", p)
	}
	return n.Data, nil
}
func (f *FS) WriteFile(p, data, cwd string) error {
	q, e := clean(p, cwd)
	if e != nil {
		return e
	}
	if len(data) > MaxFileBytes {
		return errors.New("file exceeds virtual size limit")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.nodes[q]; !ok && len(f.nodes) >= MaxFiles {
		return errors.New("virtual file limit reached")
	}
	par := path.Dir(q)
	if n, ok := f.nodes[par]; !ok || !n.Dir {
		return errors.New("parent directory does not exist")
	}
	n := f.nodes[q]
	if n.Dir {
		return errors.New("is a directory")
	}
	f.used += len(data) - len(n.Data)
	if f.used > 16*MaxFileBytes {
		f.used -= len(data) - len(n.Data)
		return errors.New("virtual filesystem storage limit reached")
	}
	if n.Mode == 0 {
		n = Node{Name: path.Base(q), Mode: 0644, Owner: "user", Group: "user"}
	}
	n.Data = data
	n.ModTime = time.Now().UTC()
	f.nodes[q] = n
	return nil
}

func (f *FS) Chdir(p, cwd string) (string, error) {
	q, e := clean(p, cwd)
	if e != nil {
		return "", e
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, ok := f.nodes[q]
	if !ok || !n.Dir {
		return "", fmt.Errorf("%s: not a directory", p)
	}
	return q, nil
}
func (f *FS) Mkdir(p, cwd string) error {
	q, e := clean(p, cwd)
	if e != nil {
		return e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.nodes[q]; ok {
		return errors.New("file exists")
	}
	if p := f.nodes[path.Dir(q)]; !p.Dir {
		return errors.New("parent directory does not exist")
	}
	if len(f.nodes) >= MaxFiles {
		return errors.New("virtual file limit reached")
	}
	f.nodes[q] = Node{Name: path.Base(q), Dir: true, Mode: 0755, Owner: "user", Group: "user", ModTime: time.Now().UTC()}
	return nil
}
func (f *FS) List(p, cwd string) ([]string, error) {
	q, e := clean(p, cwd)
	if e != nil {
		return nil, e
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, ok := f.nodes[q]
	if !ok {
		return nil, fmt.Errorf("%s: no such file or directory", p)
	}
	if !n.Dir {
		return []string{path.Base(q)}, nil
	}
	out := []string{}
	for k := range f.nodes {
		if k != q && path.Dir(k) == q {
			out = append(out, path.Base(k))
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *FS) Paths() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	r := make([]string, 0, len(f.nodes))
	for p := range f.nodes {
		r = append(r, p)
	}
	sort.Strings(r)
	return r
}
func (f *FS) Remove(p, cwd string) error {
	q, e := clean(p, cwd)
	if e != nil {
		return e
	}
	if q == "/" {
		return errors.New("cannot remove virtual root")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[q]
	if !ok {
		return errors.New("no such file or directory")
	}
	for k := range f.nodes {
		if strings.HasPrefix(k, q+"/") {
			return errors.New("directory not empty")
		}
	}
	delete(f.nodes, q)
	f.used -= len(n.Data)
	return nil
}
func (f *FS) Copy(src, dst, cwd string) error {
	d, e := clean(dst, cwd)
	if e != nil {
		return e
	}
	s, e := f.ReadFile(src, cwd)
	if e != nil {
		return e
	}
	return f.WriteFile(d, s, "/")
}
func (f *FS) Move(src, dst, cwd string) error {
	d, e := clean(dst, cwd)
	if e != nil {
		return e
	}
	s, e := clean(src, cwd)
	if e != nil {
		return e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[s]
	if !ok {
		return errors.New("no such file")
	}
	if _, ok = f.nodes[d]; ok {
		return errors.New("destination exists")
	}
	if _, ok = f.nodes[path.Dir(d)]; !ok {
		return errors.New("parent directory does not exist")
	}
	delete(f.nodes, s)
	n.Name = path.Base(d)
	f.nodes[d] = n
	return nil
}
