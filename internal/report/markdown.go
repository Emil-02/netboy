package report

import (
	"fmt"
	"io"

	"github.com/Emil-02/netboy/internal/audit"
)

// RenderScanMarkdown renders subnet scan results as markdown table.
func RenderScanMarkdown(w io.Writer, p ScanPayload) {
	fmt.Fprintf(w, "# netboy scan: `%s`\n\n", p.Subnet)
	fmt.Fprintf(w, "*Ditemukan %d host aktif (durasi: %s)*\n\n", len(p.Hosts), p.Elapsed)

	fmt.Fprintln(w, "| IP Address | Hostname | MAC Address | Vendor |")
	fmt.Fprintln(w, "|---|---|---|---|")
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
		fmt.Fprintf(w, "| `%s` | %s | `%s` | %s |\n", h.IP, hostname, mac, vendor)
	}
}

// RenderAuditMarkdown renders security audit report in markdown.
func RenderAuditMarkdown(w io.Writer, p AuditPayload) {
	rep := p.Report
	fmt.Fprintf(w, "# netboy audit: `%s`\n\n", rep.Target)
	fmt.Fprintf(w, "**Skor Keamanan:** %d/100 (Grade: **%s**) — *%s*\n\n",
		rep.Score.Value, rep.Score.Grade, rep.Score.Status)

	fmt.Fprintln(w, "### Ringkasan Temuan")
	fmt.Fprintf(w, "- 🔴 **Critical:** %d\n", rep.Score.Counts[audit.SeverityCritical])
	fmt.Fprintf(w, "- 🟠 **High:** %d\n", rep.Score.Counts[audit.SeverityHigh])
	fmt.Fprintf(w, "- 🟡 **Medium:** %d\n", rep.Score.Counts[audit.SeverityMedium])
	fmt.Fprintf(w, "- ⚪ **Low:** %d\n\n", rep.Score.Counts[audit.SeverityLow])

	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "✓ Tidak ada kerentanan atau service berbahaya terdeteksi.")
		return
	}

	fmt.Fprintln(w, "| Severity | Port | Judul | Solusi |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, f := range rep.Findings {
		fmt.Fprintf(w, "| **%s** | `%d` | %s | %s |\n", f.Severity, f.Port, f.Title, f.Remediation)
	}
}
