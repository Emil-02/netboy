package audit

import (
	"testing"

	"github.com/Emil-02/netboy/internal/ports"
)

func TestCalculateScore(t *testing.T) {
	// No findings -> 100 A
	scoreClean := CalculateScore(nil)
	if scoreClean.Value != 100 || scoreClean.Grade != "A" {
		t.Errorf("clean score want 100 A, got %d %s", scoreClean.Value, scoreClean.Grade)
	}

	// 1 Critical (-25) -> 75 B
	findingsCrit := []Finding{
		{ID: "NET-SEC-001", Severity: SeverityCritical},
	}
	scoreCrit := CalculateScore(findingsCrit)
	if scoreCrit.Value != 75 || scoreCrit.Grade != "B" {
		t.Errorf("critical score want 75 B, got %d %s", scoreCrit.Value, scoreCrit.Grade)
	}

	// 4 Critical (-100) -> 0 F
	findingsSevere := []Finding{
		{ID: "1", Severity: SeverityCritical},
		{ID: "2", Severity: SeverityCritical},
		{ID: "3", Severity: SeverityCritical},
		{ID: "4", Severity: SeverityCritical},
		{ID: "5", Severity: SeverityHigh},
	}
	scoreSevere := CalculateScore(findingsSevere)
	if scoreSevere.Value != 0 || scoreSevere.Grade != "F" {
		t.Errorf("severe score want 0 F, got %d %s", scoreSevere.Value, scoreSevere.Grade)
	}
}

func TestAuditPorts(t *testing.T) {
	mockPorts := []ports.PortResult{
		{
			Port:    6379,
			Service: "redis",
			Banner: ports.BannerDetails{
				RawBanner:   "+PONG",
				Unprotected: true,
			},
		},
		{
			Port:    2375,
			Service: "docker",
		},
		{
			Port:    23,
			Service: "telnet",
		},
		{
			Port:    5173,
			Service: "vite",
		},
	}

	report := AuditPorts("192.168.1.10", mockPorts)
	if len(report.Findings) != 4 {
		t.Errorf("expected 4 findings, got %d", len(report.Findings))
	}

	if report.Score.Counts[SeverityCritical] != 2 {
		t.Errorf("expected 2 critical findings (Redis, Docker), got %d", report.Score.Counts[SeverityCritical])
	}
	if report.Score.Counts[SeverityHigh] != 1 {
		t.Errorf("expected 1 high finding (Telnet), got %d", report.Score.Counts[SeverityHigh])
	}
	if report.Score.Counts[SeverityMedium] != 1 {
		t.Errorf("expected 1 medium finding (Dev server 5173), got %d", report.Score.Counts[SeverityMedium])
	}
}
