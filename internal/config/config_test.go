package config

import (
	"testing"
	"time"
)

func TestNewDefaultOptions(t *testing.T) {
	opts := NewDefaultOptions()

	if opts.Timeout != 800*time.Millisecond {
		t.Errorf("expected 800ms timeout, got %v", opts.Timeout)
	}
	if opts.Concurrency != 64 {
		t.Errorf("expected concurrency 64, got %d", opts.Concurrency)
	}
	if opts.Format != "text" {
		t.Errorf("expected format 'text', got %s", opts.Format)
	}
	if opts.Verbose {
		t.Errorf("expected Verbose to be false by default")
	}
}
