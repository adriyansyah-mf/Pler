package enricher

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcInfo holds the fields read from /proc/PID/ for a given process.
// All fields fall back to "unknown" / 0 if the process has already exited.
type ProcInfo struct {
	Cwd    string
	Cgroup string
	Netns  uint64
}

// Enricher reads process metadata from a procfs root.
// Use New("/proc") in production; pass a tempdir in tests.
type Enricher struct {
	procRoot string
}

func New(procRoot string) *Enricher {
	return &Enricher{procRoot: procRoot}
}

func (e *Enricher) Enrich(pid uint32) ProcInfo {
	return ProcInfo{
		Cwd:    e.cwd(pid),
		Cgroup: e.cgroup(pid),
		Netns:  e.netns(pid),
	}
}

func (e *Enricher) cwd(pid uint32) string {
	p := filepath.Join(e.procRoot, strconv.Itoa(int(pid)), "cwd")
	target, err := os.Readlink(p)
	if err != nil {
		return "unknown"
	}
	return target
}

func (e *Enricher) cgroup(pid uint32) string {
	p := filepath.Join(e.procRoot, strconv.Itoa(int(pid)), "cgroup")
	data, err := os.ReadFile(p)
	if err != nil {
		return "unknown"
	}
	// Each line: "hierarchy:controllers:path"
	// Return the last line whose path is not "/" (unified or last named cgroup).
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		parts := strings.SplitN(lines[i], ":", 3)
		if len(parts) == 3 && parts[2] != "/" && parts[2] != "" {
			return strings.TrimPrefix(parts[2], "/")
		}
	}
	return "unknown"
}

func (e *Enricher) netns(pid uint32) uint64 {
	p := filepath.Join(e.procRoot, strconv.Itoa(int(pid)), "ns", "net")
	target, err := os.Readlink(p)
	if err != nil {
		return 0
	}
	// Format: "net:[4026531992]"
	s := strings.TrimPrefix(target, "net:[")
	s = strings.TrimSuffix(s, "]")
	ns, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return ns
}
