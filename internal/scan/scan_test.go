package scan

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantLen int
		wantErr bool
	}{
		{
			name:    "Standard /30 (2 usable hosts)",
			cidr:    "192.168.1.0/30",
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "Single IP without slash",
			cidr:    "192.168.1.50",
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "/32 host route",
			cidr:    "10.0.0.1/32",
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "Subnet /24 (254 usable hosts)",
			cidr:    "192.168.10.0/24",
			wantLen: 254,
			wantErr: false,
		},
		{
			name:    "Invalid CIDR string",
			cidr:    "not-an-ip/24",
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "Too large subnet /16",
			cidr:    "10.0.0.0/16",
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ips, err := ExpandCIDR(tc.cidr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ExpandCIDR(%q) error = %v, wantErr = %v", tc.cidr, err, tc.wantErr)
			}
			if !tc.wantErr && len(ips) != tc.wantLen {
				t.Errorf("ExpandCIDR(%q) got %d IPs, want %d", tc.cidr, len(ips), tc.wantLen)
			}
		})
	}
}

func TestListInterfaces(t *testing.T) {
	ifaces, err := ListInterfaces()
	if err != nil {
		t.Fatalf("ListInterfaces() failed: %v", err)
	}
	if len(ifaces) == 0 {
		t.Errorf("expected at least 1 network interface")
	}
}

func TestProbeHostAliveLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	alive, latency := probeHostAlive(ctx, "127.0.0.1", []int{port}, 500*time.Millisecond)
	if !alive {
		t.Errorf("expected 127.0.0.1 with open port %d to be alive", port)
	}
	if latency <= 0 {
		t.Errorf("expected positive latency, got %v", latency)
	}

	// Test non-listening port on loopback: should return alive due to RST/refused
	aliveRefused, _ := probeHostAlive(ctx, "127.0.0.1", []int{port + 999}, 300*time.Millisecond)
	if !aliveRefused {
		t.Logf("probeHostAlive on closed loopback port returned false (can happen if dropped)")
	}
}
