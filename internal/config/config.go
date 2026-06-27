package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogFile       string        `yaml:"log_file"`
	RingbufSize   int           `yaml:"ringbuf_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	FlushSize     int           `yaml:"flush_size"`
	MaxArgs       int           `yaml:"max_args"`
	ArgSize       int           `yaml:"arg_size"`
	ExcludeComms  []string      `yaml:"exclude_comms"`
}

func Default() Config {
	return Config{
		LogFile:       "/var/log/pler/execve.log",
		RingbufSize:   4 * 1024 * 1024,
		FlushInterval: 100 * time.Millisecond,
		FlushSize:     64 * 1024,
		MaxArgs:       20,
		ArgSize:       128,
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	return cfg, yaml.Unmarshal(data, &cfg)
}
