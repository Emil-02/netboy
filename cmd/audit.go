package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Emil-02/netboy/internal/audit"
	"github.com/Emil-02/netboy/internal/ports"
	"github.com/Emil-02/netboy/internal/report"
	"github.com/spf13/cobra"
)

var (
	optAuditPorts     string
	optAuditFailUnder int
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit <target>",
		Short: "Audit target for exposed dev services and security misconfigurations",
		Args:  cobra.ExactArgs(1),
		Example: `  netboy audit 127.0.0.1                  # audits local machine for exposed dev services
  netboy audit 192.168.1.1                # audits router / network gateway
  netboy audit 192.168.1.100 --fail-under 80 # fails in CI if security score < 80
  netboy audit 10.0.0.5 --format markdown > report.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			portList, err := ports.ParsePortSpec(optAuditPorts)
			if err != nil {
				return err
			}

			start := time.Now()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			scanCfg := ports.ScanConfig{
				Target:      target,
				Ports:       portList,
				Concurrency: optConcurrency,
				Timeout:     optTimeout,
				GrabBanners: true,
			}

			openPorts, err := ports.ScanHost(ctx, scanCfg)
			if err != nil {
				return err
			}

			auditRep := audit.AuditPorts(target, openPorts)
			elapsed := time.Since(start).Round(time.Millisecond).String()

			payload := report.AuditPayload{
				Report:  auditRep,
				Elapsed: elapsed,
			}

			w, cleanup, err := getOutputWriter(cmd)
			if err != nil {
				return err
			}
			defer cleanup()

			switch optFormat {
			case "json":
				if err := report.RenderJSON(w, payload); err != nil {
					return err
				}
			case "markdown", "md":
				report.RenderAuditMarkdown(w, payload)
			default:
				report.RenderAuditText(w, payload)
			}

			if optAuditFailUnder > 0 && auditRep.Score.Value < optAuditFailUnder {
				fmt.Fprintf(os.Stderr, "\n[FAIL] Skor keamanan %d di bawah ambang batas minimum (%d)\n",
					auditRep.Score.Value, optAuditFailUnder)
				os.Exit(1)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&optAuditPorts, "ports", "p", "dev", "Ports to audit: dev, top20, top100, or custom list")
	cmd.Flags().IntVar(&optAuditFailUnder, "fail-under", 0, "Exit with code 1 if security score is below this threshold (CI mode)")

	return cmd
}
