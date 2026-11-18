// Package report renders netboy scan and audit results in text, JSON, and markdown.
package report

import (
	"encoding/json"
	"io"

	"github.com/Emil-02/netboy/internal/audit"
	"github.com/Emil-02/netboy/internal/ports"
	"github.com/Emil-02/netboy/internal/scan"
)

// ScanPayload holds subnet scan data for reporting.
type ScanPayload struct {
	Subnet  string            `json:"subnet"`
	Hosts   []scan.HostResult `json:"hosts"`
	Elapsed string            `json:"elapsed"`
}

// PortsPayload holds single-host port scan data for reporting.
type PortsPayload struct {
	Host    string             `json:"host"`
	Ports   []ports.PortResult `json:"ports"`
	Elapsed string             `json:"elapsed"`
}

// AuditPayload holds audit analysis data for reporting.
type AuditPayload struct {
	Report  audit.AuditReport `json:"report"`
	Elapsed string            `json:"elapsed"`
}

// RenderJSON writes any payload as indented JSON.
func RenderJSON(w io.Writer, payload any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
