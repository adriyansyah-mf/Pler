package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// RawEvent mirrors struct event_t from execve.bpf.c.
// Field order and sizes must match exactly.
type RawEvent struct {
	TsNs          uint64
	Pid           uint32
	Ppid          uint32
	Uid           uint32
	Gid           uint32
	Retval        int32
	Comm          [16]byte
	Filename      [256]byte
	Argv          [2560]byte // ARGSIZE(128) * MAXARGS(20)
	ArgvTruncated uint8
	_             [3]byte // padding
}

// ReadResult is what Loader.Read returns per call.
type ReadResult struct {
	Event       *RawEvent
	LostSamples uint64
}

// ErrClosed is returned by Read after Close is called.
var ErrClosed = errors.New("loader closed")

// Loader owns the BPF objects, tracepoint links, and perf reader.
type Loader struct {
	objs   ExecveObjects
	links  []link.Link
	reader *perf.Reader
	once   sync.Once
}

// NewLoader loads the eBPF program, attaches both tracepoints, and
// opens the perf reader. pageCount is the number of 4KB pages per CPU
// for the perf ring buffer (e.g. 256 = 1 MB per CPU).
func NewLoader(pageCount int) (*Loader, error) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, fmt.Errorf(
			"BTF not available (/sys/kernel/btf/vmlinux missing).\n"+
				"On RHEL 8: ensure kernel >= 4.18.0-305 with CONFIG_DEBUG_INFO_BTF=y.\n"+
				"Error: %w", err)
	}

	l := &Loader{}
	if err := LoadExecveObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	enter, err := link.Tracepoint("syscalls", "sys_enter_execve", l.objs.HandleEnter, nil)
	if err != nil {
		l.objs.Close() //nolint:errcheck
		return nil, fmt.Errorf("attach sys_enter_execve: %w", err)
	}
	l.links = append(l.links, enter)

	exit, err := link.Tracepoint("syscalls", "sys_exit_execve", l.objs.HandleExit, nil)
	if err != nil {
		enter.Close()
		l.objs.Close() //nolint:errcheck
		return nil, fmt.Errorf("attach sys_exit_execve: %w", err)
	}
	l.links = append(l.links, exit)

	rd, err := perf.NewReader(l.objs.Events, os.Getpagesize()*pageCount)
	if err != nil {
		for _, lk := range l.links {
			lk.Close()
		}
		l.objs.Close() //nolint:errcheck
		return nil, fmt.Errorf("open perf reader: %w", err)
	}
	l.reader = rd

	return l, nil
}

// Read blocks until an event or lost-samples record is available.
// Returns ErrClosed when the loader has been closed.
func (l *Loader) Read() (ReadResult, error) {
	record, err := l.reader.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return ReadResult{}, ErrClosed
		}
		return ReadResult{}, err
	}

	if record.LostSamples > 0 {
		return ReadResult{LostSamples: record.LostSamples}, nil
	}

	var ev RawEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
		return ReadResult{}, fmt.Errorf("decode event: %w", err)
	}
	return ReadResult{Event: &ev}, nil
}

// Close detaches tracepoints and releases all BPF resources.
// After Close, Read returns ErrClosed. Safe to call more than once.
func (l *Loader) Close() {
	l.once.Do(func() {
		l.reader.Close() //nolint:errcheck
		for _, lk := range l.links {
			lk.Close()
		}
		l.objs.Close() //nolint:errcheck
	})
}
