package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pler/internal/config"
)

func TestDefault(t *testing.T) {
	cfg := config.Default()
	assert.Equal(t, "/var/log/pler/execve.log", cfg.LogFile)
	assert.Equal(t, 4*1024*1024, cfg.RingbufSize)
	assert.Equal(t, 100*time.Millisecond, cfg.FlushInterval)
	assert.Equal(t, 64*1024, cfg.FlushSize)
	assert.Equal(t, 20, cfg.MaxArgs)
	assert.Equal(t, 128, cfg.ArgSize)
	assert.Empty(t, cfg.ExcludeComms)
}

func TestLoad_OverridesDefaults(t *testing.T) {
	f := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(f, []byte(`log_file: /tmp/test.log
ringbuf_size: 1048576
flush_interval: 200ms
`), 0644)
	require.NoError(t, err)

	cfg, err := config.Load(f)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/test.log", cfg.LogFile)
	assert.Equal(t, 1048576, cfg.RingbufSize)
	assert.Equal(t, 200*time.Millisecond, cfg.FlushInterval)
	// unset fields keep defaults
	assert.Equal(t, 20, cfg.MaxArgs)
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/config.yaml")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestLoad_InvalidYAML(t *testing.T) {
	f := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(f, []byte(`log_file: [invalid`), 0644)
	_, err := config.Load(f)
	assert.Error(t, err)
}

func TestLoad_ExcludeComms(t *testing.T) {
	f := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(f, []byte("exclude_comms:\n  - wazuh-agent\n  - systemd\n"), 0644)
	cfg, err := config.Load(f)
	require.NoError(t, err)
	assert.Equal(t, []string{"wazuh-agent", "systemd"}, cfg.ExcludeComms)
}
