// Package scan provides network interface discovery and subnet host reconnaissance.
package scan

import (
	"time"

	"github.com/Emil-02/netboy/internal/ports"
)

// InterfaceInfo represents details of a local network interface.
type InterfaceInfo struct {
	Name       string   `json:"name"`
	IPs        []string `json:"ips"`
	Subnets    []string `json:"subnets"`
	MAC        string   `json:"mac"`
	IsUp       bool     `json:"is_up"`
	IsLoopback bool     `json:"is_loopback"`
}

// HostResult represents an active host discovered during scanning.
type HostResult struct {
	IP        string             `json:"ip"`
	Hostname  string             `json:"hostname,omitempty"`
	MAC       string             `json:"mac,omitempty"`
	Vendor    string             `json:"vendor,omitempty"`
	Latency   time.Duration      `json:"latency"`
	OpenPorts []ports.PortResult `json:"open_ports,omitempty"`
	IsGateway bool               `json:"is_gateway,omitempty"`
}

// SubnetScanConfig configures a subnet discovery job.
type SubnetScanConfig struct {
	CIDR        string
	ProbePorts  []int
	Concurrency int
	Timeout     time.Duration
	ResolveDNS  bool
	ScanPorts   bool
	PortPreset  string
}
