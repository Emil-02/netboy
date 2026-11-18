// Package audit provides security analysis and scoring for discovered network services.
package audit

// Severity levels matching security standards.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents an identified security risk, misconfiguration, or exposure.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Service     string   `json:"service"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
}

// Rule defines an audit evaluation rule against a discovered service.
type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	Check       func(host string, port int, service string, banner string, extra string, unprotected bool) *Finding
	Remediation string
}
