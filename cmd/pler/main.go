package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"pler/internal/bpf"
	"pler/internal/config"
	"pler/internal/enricher"
	"pler/internal/event"
	"pler/internal/metrics"
	"pler/internal/writer"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/pler/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("config: %v", err)
	}

	hostname, _ := os.Hostname()

	if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0750); err != nil {
		log.Fatalf("mkdir log dir: %v", err)
	}

	f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		log.Fatalf("open log file: %v", err)
	}
	defer f.Close()

	// Set append-only flag so even root cannot truncate the log file.
	// Ignore error on filesystems that don't support it (tmpfs, overlay).
	if err := chAttrAppendOnly(cfg.LogFile); err != nil {
		log.Printf("chattr +a (non-fatal): %v", err)
	}

	w := writer.New(f, cfg.FlushInterval, cfg.FlushSize)
	defer w.Close()

	enr := enricher.New("/proc")

	pageCount := cfg.RingbufSize / os.Getpagesize()
	if pageCount < 1 {
		pageCount = 1
	}
	loader, err := bpf.NewLoader(pageCount)
	if err != nil {
		log.Fatalf("BPF: %v", err)
	}
	defer loader.Close()

	if err := os.MkdirAll("/run/pler", 0750); err == nil {
		m := metrics.New()
		if err := m.Serve("/run/pler/metrics.sock"); err != nil {
			log.Printf("metrics socket (non-fatal): %v", err)
		}
	}

	exclude := make(map[string]bool, len(cfg.ExcludeComms))
	for _, c := range cfg.ExcludeComms {
		exclude[c] = true
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	log.Printf("pler %s started — logging to %s", version, cfg.LogFile)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			result, err := loader.Read()
			if errors.Is(err, bpf.ErrClosed) {
				return
			}
			if err != nil {
				log.Printf("read: %v", err)
				continue
			}

			if result.LostSamples > 0 {
				entry := event.LogEntry{
					Hostname:  hostname,
					Program:   "pler",
					EventType: "monitor_drop",
					Argv:      fmt.Sprintf("lost %d samples", result.LostSamples),
				}
				entry.SetTimestamp(time.Now())
				w.Write(entry) //nolint:errcheck
				continue
			}

			if result.Event == nil {
				return
			}

			comm := nullStr(result.Event.Comm[:])
			if exclude[comm] {
				continue
			}

			info := enr.Enrich(result.Event.Pid)
			entry := buildEntry(result.Event, info, hostname)
			w.Write(entry) //nolint:errcheck
		}
	}()

	<-sig
	log.Println("shutting down")
	loader.Close()
	<-done
}

func buildEntry(ev *bpf.RawEvent, info enricher.ProcInfo, hostname string) event.LogEntry {
	entry := event.LogEntry{
		Hostname:      hostname,
		Program:       "pler",
		EventType:     "execve",
		Pid:           ev.Pid,
		Ppid:          ev.Ppid,
		Uid:           ev.Uid,
		Gid:           ev.Gid,
		Username:      uidName(ev.Uid),
		Group:         gidName(ev.Gid),
		Comm:          nullStr(ev.Comm[:]),
		Filename:      nullStr(ev.Filename[:]),
		Argv:          strings.TrimRight(nullStr(ev.Argv[:]), " "),
		ArgvTruncated: ev.ArgvTruncated != 0,
		Retval:        ev.Retval,
		Success:       ev.Retval == 0,
		Cwd:           info.Cwd,
		Cgroup:        info.Cgroup,
		Netns:         info.Netns,
	}
	entry.SetTimestamp(time.Now())
	return entry
}

func nullStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func uidName(uid uint32) string {
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return strconv.Itoa(int(uid))
	}
	return u.Username
}

func gidName(gid uint32) string {
	g, err := user.LookupGroupId(strconv.Itoa(int(gid)))
	if err != nil {
		return strconv.Itoa(int(gid))
	}
	return g.Name
}

// fsAppendFL is the Linux FS_APPEND_FL flag (linux/fs.h).
// It is not exported by golang.org/x/sys/unix so we define it here.
const fsAppendFL = 0x00000020

func chAttrAppendOnly(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	attr, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return fmt.Errorf("getflags: %w", err)
	}
	return unix.IoctlSetInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, attr|fsAppendFL)
}
