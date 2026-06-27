package enricher_test

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pler/internal/enricher"
)

func setupFakeProc(t *testing.T, pid uint32, cwd, cgroup, netns string) string {
	t.Helper()
	root := t.TempDir()
	pidDir := filepath.Join(root, strconv.Itoa(int(pid)))
	nsDir := filepath.Join(pidDir, "ns")
	require.NoError(t, os.MkdirAll(nsDir, 0755))
	require.NoError(t, os.Symlink(cwd, filepath.Join(pidDir, "cwd")))
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroup), 0644))
	require.NoError(t, os.Symlink(netns, filepath.Join(nsDir, "net")))
	return root
}

func TestEnrich_WebProcess(t *testing.T) {
	root := setupFakeProc(t, 1234,
		"/var/www/html",
		"0::/system.slice/php8.1-fpm.service\n",
		"net:[4026531992]",
	)
	e := enricher.New(root)
	info := e.Enrich(1234)

	assert.Equal(t, "/var/www/html", info.Cwd)
	assert.Equal(t, "system.slice/php8.1-fpm.service", info.Cgroup)
	assert.Equal(t, uint64(4026531992), info.Netns)
}

func TestEnrich_MissingPID(t *testing.T) {
	e := enricher.New(t.TempDir())
	info := e.Enrich(99999)

	assert.Equal(t, "unknown", info.Cwd)
	assert.Equal(t, "unknown", info.Cgroup)
	assert.Equal(t, uint64(0), info.Netns)
}

func TestEnrich_RootCgroup(t *testing.T) {
	root := setupFakeProc(t, 5678, "/", "0::/\n", "net:[4026531992]")
	e := enricher.New(root)
	info := e.Enrich(5678)

	// root cgroup "/" has no useful name — return "unknown"
	assert.Equal(t, "unknown", info.Cgroup)
}

func TestEnrich_MultipleCgroupLines(t *testing.T) {
	root := setupFakeProc(t, 9000, "/app",
		"12:devices:/docker/abc\n0::/system.slice/myapp.service\n",
		"net:[1234]",
	)
	e := enricher.New(root)
	info := e.Enrich(9000)

	// should return the last non-root cgroup (unified hierarchy)
	assert.Equal(t, "system.slice/myapp.service", info.Cgroup)
}
