// Package config provides runtime configuration and presets for netboy.
package config

import (
	"time"
)

// Default scanning parameters.
const (
	DefaultTimeout     = 800 * time.Millisecond
	DefaultConcurrency = 64
	DefaultFormat      = "text"
	DefaultPortPreset  = "top20"
)

// Options defines global CLI and scan options.
type Options struct {
	Timeout     time.Duration
	Concurrency int
	Format      string
	Verbose     bool
	OutputFile  string
}

// NewDefaultOptions returns sensible defaults for unprivileged network scanning.
func NewDefaultOptions() Options {
	return Options{
		Timeout:     DefaultTimeout,
		Concurrency: DefaultConcurrency,
		Format:      DefaultFormat,
		Verbose:     false,
	}
}
