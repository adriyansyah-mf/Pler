package metrics

import (
	"encoding/json"
	"net"
	"os"
	"sync/atomic"
)

// Metrics holds runtime counters for pler.
type Metrics struct {
	dropped atomic.Uint64
}

func New() *Metrics { return &Metrics{} }

// IncrDropped adds n to the lost-event counter.
func (m *Metrics) IncrDropped(n uint64) { m.dropped.Add(n) }

// Dropped returns the current lost-event count.
func (m *Metrics) Dropped() uint64 { return m.dropped.Load() }

// Serve starts a Unix socket listener at sockPath.
// Each connection receives one JSON line with current counters, then is closed.
func (m *Metrics) Serve(sockPath string) error {
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.respond(conn)
		}
	}()
	return nil
}

func (m *Metrics) respond(conn net.Conn) {
	defer conn.Close()
	data, _ := json.Marshal(map[string]any{
		"dropped_events": m.dropped.Load(),
	})
	conn.Write(append(data, '\n')) //nolint:errcheck
}
