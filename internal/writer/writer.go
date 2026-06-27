package writer

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Writer wraps an io.Writer with JSON encoding, buffering, and periodic flush.
type Writer struct {
	mu   sync.Mutex
	bw   *bufio.Writer
	done chan struct{}
}

// New creates a Writer that flushes every flushInterval or when the
// internal buffer reaches flushSize bytes, whichever comes first.
func New(w io.Writer, flushInterval time.Duration, flushSize int) *Writer {
	wrt := &Writer{
		bw:   bufio.NewWriterSize(w, flushSize),
		done: make(chan struct{}),
	}
	go wrt.periodicFlush(flushInterval)
	return wrt
}

// Write JSON-encodes entry and appends it as one line to the buffer.
func (w *Writer) Write(entry any) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.bw.Write(append(data, '\n'))
	return err
}

// Flush commits the buffer to the underlying writer.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bw.Flush()
}

// Close stops the periodic flush goroutine and flushes any remaining data.
func (w *Writer) Close() error {
	close(w.done)
	return w.Flush()
}

func (w *Writer) periodicFlush(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			w.Flush() //nolint:errcheck
		case <-w.done:
			return
		}
	}
}
