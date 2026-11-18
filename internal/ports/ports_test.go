package ports

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"top20 preset", "top20", len(Top20Ports), false},
		{"top100 preset", "top100", len(Top100Ports), false},
		{"dev preset", "dev", len(DevPorts), false},
		{"comma list", "80,443,8080", 3, false},
		{"range", "3000-3004", 5, false},
		{"mixed comma and range", "80,3000-3002,443", 5, false},
		{"invalid port", "99999", 0, true},
		{"invalid range", "500-100", 0, true},
		{"empty", "", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ports, err := ParsePortSpec(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParsePortSpec(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && len(ports) != tc.wantLen {
				t.Errorf("ParsePortSpec(%q) len = %d, wantLen = %d", tc.input, len(ports), tc.wantLen)
			}
		})
	}
}

func TestLookupService(t *testing.T) {
	name, _ := LookupService(22)
	if name != "ssh" {
		t.Errorf("expected port 22 to be ssh, got %s", name)
	}

	nameUnknown, _ := LookupService(65432)
	if nameUnknown != "unknown" {
		t.Errorf("expected port 65432 to be unknown, got %s", nameUnknown)
	}
}

func TestScanHostLocal(t *testing.T) {
	// Spin up a dummy local TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on test port: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := ScanConfig{
		Target:      "127.0.0.1",
		Ports:       []int{port, port + 1}, // port is open, port+1 is closed
		Concurrency: 2,
		Timeout:     500 * time.Millisecond,
		GrabBanners: false,
	}

	results, err := ScanHost(ctx, cfg)
	if err != nil {
		t.Fatalf("ScanHost failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(results))
	}

	if results[0].Port != port {
		t.Errorf("expected open port %d, got %d", port, results[0].Port)
	}
	if results[0].State != "open" {
		t.Errorf("expected state 'open', got %s", results[0].State)
	}
}
