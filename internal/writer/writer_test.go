package writer_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pler/internal/writer"
)

func TestWrite_SingleEntry(t *testing.T) {
	var buf bytes.Buffer
	w := writer.New(&buf, 10*time.Second, 65536)
	defer w.Close()

	require.NoError(t, w.Write(map[string]any{"pid": 123, "filename": "/bin/bash"}))
	require.NoError(t, w.Flush())

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, float64(123), got["pid"])
	assert.Equal(t, "/bin/bash", got["filename"])
}

func TestWrite_MultipleEntries_OnePerLine(t *testing.T) {
	var buf bytes.Buffer
	w := writer.New(&buf, 10*time.Second, 65536)
	defer w.Close()

	for i := 0; i < 3; i++ {
		require.NoError(t, w.Write(map[string]any{"i": i}))
	}
	require.NoError(t, w.Flush())

	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	assert.Len(t, lines, 3)
	for idx, line := range lines {
		var entry map[string]any
		require.NoError(t, json.Unmarshal(line, &entry))
		assert.Equal(t, float64(idx), entry["i"])
	}
}

func TestWrite_PeriodicFlush(t *testing.T) {
	var buf bytes.Buffer
	w := writer.New(&buf, 50*time.Millisecond, 65536)
	defer w.Close()

	require.NoError(t, w.Write(map[string]any{"test": true}))
	time.Sleep(120 * time.Millisecond)

	assert.NotEmpty(t, buf.Bytes(), "periodic flush should have fired")
}

func TestClose_FlushesRemaining(t *testing.T) {
	var buf bytes.Buffer
	w := writer.New(&buf, 10*time.Second, 65536)

	require.NoError(t, w.Write(map[string]any{"x": 1}))
	require.NoError(t, w.Close())

	assert.NotEmpty(t, buf.Bytes())
}
