package event

import "time"

// LogEntry is one line in /var/log/pler/execve.log.
type LogEntry struct {
	Timestamp     string `json:"timestamp"`
	Hostname      string `json:"hostname"`
	Program       string `json:"program"`
	EventType     string `json:"event_type"`
	Pid           uint32 `json:"pid"`
	Ppid          uint32 `json:"ppid"`
	Uid           uint32 `json:"uid"`
	Gid           uint32 `json:"gid"`
	Username      string `json:"username"`
	Group         string `json:"group"`
	Comm          string `json:"comm"`
	Filename      string `json:"filename"`
	Argv          string `json:"argv"`
	ArgvTruncated bool   `json:"argv_truncated"`
	Retval        int32  `json:"retval"`
	Success       bool   `json:"success"`
	Cwd           string `json:"cwd"`
	Cgroup        string `json:"cgroup"`
	Netns         uint64 `json:"netns"`
}

func (e *LogEntry) SetTimestamp(t time.Time) {
	e.Timestamp = t.UTC().Format(time.RFC3339Nano)
}
