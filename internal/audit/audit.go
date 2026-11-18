package audit

import (
	"fmt"
	"strings"

	"github.com/Emil-02/netboy/internal/ports"
)

// AuditReport aggregates all findings and overall score.
type AuditReport struct {
	Target   string     `json:"target"`
	Score    AuditScore `json:"score"`
	Findings []Finding  `json:"findings"`
}

// BuiltinRules contains standard security evaluation rules for netboy.
var BuiltinRules = []Rule{
	{
		ID:       "NET-SEC-001",
		Title:    "Docker Remote API Exposed Unencrypted",
		Severity: SeverityCritical,
		Check: func(host string, port int, service string, banner string, extra string, unprotected bool) *Finding {
			if port == 2375 || unprotected && strings.Contains(strings.ToLower(extra), "docker") {
				return &Finding{
					ID:          "NET-SEC-001",
					Title:       "Docker Remote API Exposed Without TLS",
					Severity:    SeverityCritical,
					Host:        host,
					Port:        port,
					Service:     service,
					Description: "Port 2375 allows root-equivalent arbitrary container execution across network.",
					Remediation: "Bind Docker to unix:///var/run/docker.sock or enable TLS on port 2376.",
				}
			}
			return nil
		},
	},
	{
		ID:       "NET-SEC-002",
		Title:    "Unauthenticated Redis Store Exposed",
		Severity: SeverityCritical,
		Check: func(host string, port int, service string, banner string, extra string, unprotected bool) *Finding {
			if (port == 6379 && unprotected) || (port == 6379 && strings.Contains(banner, "+PONG")) {
				return &Finding{
					ID:          "NET-SEC-002",
					Title:       "Unauthenticated Redis Store Exposed",
					Severity:    SeverityCritical,
					Host:        host,
					Port:        port,
					Service:     service,
					Description: "Redis responded to PING without authentication. Any network user can read, flush, or execute commands.",
					Remediation: "Set `requirepass <password>` and `bind 127.0.0.1` in redis.conf.",
				}
			}
			return nil
		},
	},
	{
		ID:       "NET-SEC-003",
		Title:    "Database Exposed to Network",
		Severity: SeverityHigh,
		Check: func(host string, port int, service string, banner string, extra string, unprotected bool) *Finding {
			switch port {
			case 3306, 5432, 27017, 9200, 1433:
				dbName := service
				if dbName == "" {
					dbName = fmt.Sprintf("Database on port %d", port)
				}
				return &Finding{
					ID:          "NET-SEC-003",
					Title:       fmt.Sprintf("%s Exposed to Network", strings.ToUpper(dbName)),
					Severity:    SeverityHigh,
					Host:        host,
					Port:        port,
					Service:     service,
					Description: fmt.Sprintf("Direct access to %s is accessible over the network interface.", dbName),
					Remediation: "Bind database listeners to 127.0.0.1 or use SSH tunnels/VPN instead of direct network exposure.",
				}
			}
			return nil
		},
	},
	{
		ID:       "NET-SEC-004",
		Title:    "Cleartext Remote Management Protocol (Telnet/FTP/VNC)",
		Severity: SeverityHigh,
		Check: func(host string, port int, service string, banner string, extra string, unprotected bool) *Finding {
			if port == 23 || port == 21 || port == 5900 {
				proto := "Telnet"
				if port == 21 {
					proto = "FTP"
				} else if port == 5900 {
					proto = "VNC"
				}
				return &Finding{
					ID:          "NET-SEC-004",
					Title:       fmt.Sprintf("Insecure %s Protocol in Use", proto),
					Severity:    SeverityHigh,
					Host:        host,
					Port:        port,
					Service:     service,
					Description: fmt.Sprintf("%s transmits authentication credentials and commands in plain text across the wire.", proto),
					Remediation: fmt.Sprintf("Replace %s with SSH, SFTP, or an encrypted VPN tunnel.", proto),
				}
			}
			return nil
		},
	},
	{
		ID:       "NET-SEC-005",
		Title:    "Development Server Exposed on Network",
		Severity: SeverityMedium,
		Check: func(host string, port int, service string, banner string, extra string, unprotected bool) *Finding {
			switch port {
			case 3000, 4200, 5000, 5173, 8000, 8888:
				return &Finding{
					ID:          "NET-SEC-005",
					Title:       fmt.Sprintf("Dev Server Exposed on Port %d", port),
					Severity:    SeverityMedium,
					Host:        host,
					Port:        port,
					Service:     service,
					Description: "Development servers usually lack rate limiting, security headers, and authentication.",
					Remediation: "Bind development servers to localhost (`127.0.0.1`) instead of `0.0.0.0`.",
				}
			}
			return nil
		},
	},
	{
		ID:       "NET-SEC-006",
		Title:    "SMB / Windows File Sharing Exposed",
		Severity: SeverityMedium,
		Check: func(host string, port int, service string, banner string, extra string, unprotected bool) *Finding {
			if port == 445 || port == 139 {
				return &Finding{
					ID:          "NET-SEC-006",
					Title:       "SMB / File Sharing Exposed",
					Severity:    SeverityMedium,
					Host:        host,
					Port:        port,
					Service:     service,
					Description: "SMB protocol is a frequent target for lateral movement and credential relay attacks.",
					Remediation: "Block inbound port 445 on perimeter firewalls and disable SMBv1.",
				}
			}
			return nil
		},
	},
	{
		ID:       "NET-SEC-007",
		Title:    "Plain HTTP Without Transport Encryption",
		Severity: SeverityLow,
		Check: func(host string, port int, service string, banner string, extra string, unprotected bool) *Finding {
			if port == 80 || port == 8080 {
				return &Finding{
					ID:          "NET-SEC-007",
					Title:       "Plain HTTP Service (Unencrypted)",
					Severity:    SeverityLow,
					Host:        host,
					Port:        port,
					Service:     service,
					Description: "Web traffic on this port is unencrypted and subject to eavesdropping or session tampering.",
					Remediation: "Configure TLS / HTTPS with automatic HTTP to HTTPS redirection.",
				}
			}
			return nil
		},
	},
}

// AuditPorts analyzes open ports and returns security findings and a score.
func AuditPorts(target string, openPorts []ports.PortResult) AuditReport {
	var findings []Finding

	for _, p := range openPorts {
		for _, rule := range BuiltinRules {
			f := rule.Check(target, p.Port, p.Service, p.Banner.RawBanner, p.Banner.Extra, p.Banner.Unprotected)
			if f != nil {
				findings = append(findings, *f)
			}
		}
	}

	score := CalculateScore(findings)

	return AuditReport{
		Target:   target,
		Score:    score,
		Findings: findings,
	}
}
