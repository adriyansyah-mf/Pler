package metrics_test

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pler/internal/metrics"
)

func TestIncrDropped_Accumulates(t *testing.T) {
	m := metrics.New()
	m.IncrDropped(5)
	m.IncrDropped(3)
	assert.Equal(t, uint64(8), m.Dropped())
}

func TestServe_ReturnsDropCount(t *testing.T) {
	m := metrics.New()
	m.IncrDropped(42)

	sockPath := filepath.Join(t.TempDir(), "metrics.sock")
	require.NoError(t, m.Serve(sockPath))

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	var result map[string]any
	require.NoError(t, json.NewDecoder(conn).Decode(&result))
	assert.Equal(t, float64(42), result["dropped_events"])
}

func TestServe_MultipleClients(t *testing.T) {
	m := metrics.New()
	m.IncrDropped(7)

	sockPath := filepath.Join(t.TempDir(), "m.sock")
	require.NoError(t, m.Serve(sockPath))

	for i := 0; i < 3; i++ {
		conn, err := net.Dial("unix", sockPath)
		require.NoError(t, err)
		var result map[string]any
		require.NoError(t, json.NewDecoder(conn).Decode(&result))
		conn.Close()
		assert.Equal(t, float64(7), result["dropped_events"])
	}
}
