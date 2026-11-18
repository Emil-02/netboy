package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Emil-02/netboy/internal/audit"
	"github.com/Emil-02/netboy/internal/scan"
)

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	payload := ScanPayload{
		Subnet:  "192.168.1.0/24",
		Hosts:   []scan.HostResult{{IP: "192.168.1.1", Vendor: "MikroTik"}},
		Elapsed: "1.2s",
	}

	if err := RenderJSON(&buf, payload); err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	str := buf.String()
	if !strings.Contains(str, "192.168.1.1") || !strings.Contains(str, "MikroTik") {
		t.Errorf("expected JSON to contain host details, got: %s", str)
	}
}

func TestRenderScanText(t *testing.T) {
	var buf bytes.Buffer
	payload := ScanPayload{
		Subnet: "192.168.1.0/24",
		Hosts: []scan.HostResult{
			{IP: "192.168.1.1", Hostname: "router.lan", MAC: "00:0C:42:01:02:03", Vendor: "MikroTik"},
		},
		Elapsed: "800ms",
	}

	RenderScanText(&buf, payload)
	out := buf.String()
	if !strings.Contains(out, "192.168.1.1") || !strings.Contains(out, "MikroTik") {
		t.Errorf("RenderScanText output missing details: %s", out)
	}
}

func TestRenderAuditText(t *testing.T) {
	var buf bytes.Buffer
	findings := []audit.Finding{
		{
			ID:          "NET-SEC-002",
			Title:       "Unauthenticated Redis Store Exposed",
			Severity:    audit.SeverityCritical,
			Host:        "127.0.0.1",
			Port:        6379,
			Service:     "redis",
			Description: "Redis responded to PING",
			Remediation: "Set requirepass",
		},
	}
	score := audit.CalculateScore(findings)
	payload := AuditPayload{
		Report: audit.AuditReport{
			Target:   "127.0.0.1",
			Score:    score,
			Findings: findings,
		},
		Elapsed: "300ms",
	}

	RenderAuditText(&buf, payload)
	out := buf.String()
	if !strings.Contains(out, "CRITICAL") || !strings.Contains(out, "75/100") {
		t.Errorf("RenderAuditText output missing critical/score: %s", out)
	}
}

func TestRenderMarkdown(t *testing.T) {
	var buf bytes.Buffer
	payload := ScanPayload{
		Subnet:  "192.168.1.0/24",
		Hosts:   []scan.HostResult{{IP: "192.168.1.1", Vendor: "MikroTik"}},
		Elapsed: "1.2s",
	}

	RenderScanMarkdown(&buf, payload)
	out := buf.String()
	if !strings.Contains(out, "| `192.168.1.1` |") {
		t.Errorf("markdown missing table row: %s", out)
	}
}
