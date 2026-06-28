//go:build integration

package integration_test

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pler/internal/bpf"
)

func TestExecveCapture_BinTrue(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("integration tests require root (or CAP_BPF + CAP_PERFMON)")
	}

	loader, err := bpf.NewLoader(64)
	require.NoError(t, err, "BPF loader failed — check BTF availability")
	defer loader.Close()

	found := make(chan *bpf.RawEvent, 1)
	go func() {
		for {
			result, err := loader.Read()
			if err != nil {
				return
			}
			if result.Event == nil {
				continue
			}
			if nullStr(result.Event.Filename[:]) == "/bin/true" {
				select {
				case found <- result.Event:
				default:
				}
				return
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	err = exec.Command("/bin/true").Run()
	require.NoError(t, err)

	select {
	case ev := <-found:
		assert.Equal(t, "/bin/true", nullStr(ev.Filename[:]))
		assert.Equal(t, int32(0), ev.Retval, "execve should succeed")
		assert.NotZero(t, ev.Pid)
		assert.NotZero(t, ev.Ppid)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: /bin/true execve event not captured within 3s")
	}
}

func TestExecveCapture_FailedExec(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("integration tests require root")
	}

	loader, err := bpf.NewLoader(64)
	require.NoError(t, err)
	defer loader.Close()

	found := make(chan *bpf.RawEvent, 1)
	go func() {
		for {
			result, err := loader.Read()
			if err != nil {
				return
			}
			if result.Event == nil {
				continue
			}
			if nullStr(result.Event.Filename[:]) == "/nonexistent-binary-pler-test" {
				select {
				case found <- result.Event:
				default:
				}
				return
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	exec.Command("/nonexistent-binary-pler-test").Run() //nolint:errcheck

	select {
	case ev := <-found:
		assert.NotEqual(t, int32(0), ev.Retval, "failed exec should have non-zero retval")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: failed execve event not captured")
	}
}

func nullStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
