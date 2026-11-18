package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Emil-02/netboy/internal/audit"
)

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
)

// RenderScanText prints human-readable subnet scan output.
func RenderScanText(w io.Writer, p ScanPayload) {
	fmt.Fprintf(w, "%s%snetboy scan%s — %s\n", colorBold, colorCyan, colorReset, p.Subnet)
	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)

	if len(p.Hosts) == 0 {
		fmt.Fprintf(w, "%s! Tidak ada host aktif yang merespons pada subnet ini.%s\n", colorYellow, colorReset)
		return
	}

	fmt.Fprintf(w, "%-16s %-20s %-18s %s\n", "IP ADDRESS", "HOSTNAME", "MAC ADDRESS", "VENDOR")
	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)

	for _, h := range p.Hosts {
		hostname := h.Hostname
		if hostname == "" {
			hostname = "-"
		}
		mac := h.MAC
		if mac == "" {
			mac = "-"
		}
		vendor := h.Vendor
		if vendor == "" {
			vendor = "-"
		}

		fmt.Fprintf(w, "%s%-16s%s %-20s %-18s %s\n",
			colorGreen, h.IP, colorReset,
			truncate(hostname, 19),
			mac,
			truncate(vendor, 24),
		)

		if len(h.OpenPorts) > 0 {
			var portStrs []string
			for _, op := range h.OpenPorts {
				portStrs = append(portStrs, fmt.Sprintf("%d/%s", op.Port, op.Service))
			}
			fmt.Fprintf(w, "  %s└─ open: %s%s\n", colorDim, strings.Join(portStrs, ", "), colorReset)
		}
	}

	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)
	fmt.Fprintf(w, "%s✓ Ditemukan %d host aktif%s (selesai dalam %s)\n",
		colorBold, len(p.Hosts), colorReset, p.Elapsed)
}

// RenderPortsText prints open ports and grabbed service banners.
func RenderPortsText(w io.Writer, p PortsPayload) {
	fmt.Fprintf(w, "%s%snetboy ports%s — %s\n", colorBold, colorCyan, colorReset, p.Host)
	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)

	if len(p.Ports) == 0 {
		fmt.Fprintf(w, "%s! Tidak ada port terbuka dari port yang dipindai.%s\n", colorYellow, colorReset)
		return
	}

	fmt.Fprintf(w, "%-8s %-12s %-10s %s\n", "PORT", "SERVICE", "LATENCY", "DETAILS / BANNER")
	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)

	for _, pt := range p.Ports {
		details := pt.Description
		if pt.Banner.RawBanner != "" {
			details = pt.Banner.RawBanner
		}
		if pt.Banner.Extra != "" {
			details += " (" + pt.Banner.Extra + ")"
		}

		portStr := fmt.Sprintf("%d/tcp", pt.Port)
		fmt.Fprintf(w, "%s%-8s%s %-12s %-10s %s\n",
			colorGreen, portStr, colorReset,
			pt.Service,
			fmt.Sprintf("%dms", pt.Latency.Milliseconds()),
			truncate(details, 35),
		)
	}

	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)
	fmt.Fprintf(w, "%s✓ %d port terbuka terdeteksi%s (selesai dalam %s)\n",
		colorBold, len(p.Ports), colorReset, p.Elapsed)
}

// RenderAuditText prints the audit score card and findings list.
func RenderAuditText(w io.Writer, p AuditPayload) {
	rep := p.Report
	fmt.Fprintf(w, "%s%snetboy audit%s — %s\n", colorBold, colorCyan, colorReset, rep.Target)
	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)

	// Score header
	scoreColor := colorGreen
	if rep.Score.Value < 75 {
		scoreColor = colorYellow
	}
	if rep.Score.Value < 50 {
		scoreColor = colorRed
	}

	fmt.Fprintf(w, "Network Security Score: %s%s%d/100 (Grade: %s)%s — %s\n",
		colorBold, scoreColor, rep.Score.Value, rep.Score.Grade, colorReset, rep.Score.Status)
	fmt.Fprintf(w, "Risiko: %d Critical, %d High, %d Medium, %d Low\n",
		rep.Score.Counts[audit.SeverityCritical],
		rep.Score.Counts[audit.SeverityHigh],
		rep.Score.Counts[audit.SeverityMedium],
		rep.Score.Counts[audit.SeverityLow],
	)
	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)

	if len(rep.Findings) == 0 {
		fmt.Fprintf(w, "%s✓ Tidak ditemukan risiko keamanan atau servis terekspos berbahaya!%s\n", colorGreen, colorReset)
		return
	}

	for _, f := range rep.Findings {
		var badge string
		switch f.Severity {
		case audit.SeverityCritical:
			badge = colorRed + "[CRITICAL]" + colorReset
		case audit.SeverityHigh:
			badge = colorYellow + "[HIGH]    " + colorReset
		case audit.SeverityMedium:
			badge = colorCyan + "[MEDIUM]  " + colorReset
		default:
			badge = colorDim + "[LOW]     " + colorReset
		}

		fmt.Fprintf(w, "%s %s%s%s (Port %d - %s)\n",
			badge, colorBold, f.Title, colorReset, f.Port, f.Service)
		fmt.Fprintf(w, "  %sMasalah:%s %s\n", colorDim, colorReset, f.Description)
		fmt.Fprintf(w, "  %sSolusi :%s %s%s%s\n\n", colorDim, colorReset, colorGreen, f.Remediation, colorReset)
	}

	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)
	fmt.Fprintf(w, "Pemeriksaan selesai dalam %s\n", p.Elapsed)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
