package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/Emil-02/netboy/internal/report"
	"github.com/Emil-02/netboy/internal/scan"
	"github.com/spf13/cobra"
)

var (
	optScanDeep       bool
	optScanDNS        bool
	optScanPortPreset string
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [CIDR / IP]",
		Short: "Discover active hosts on a subnet or local network",
		Example: `  netboy scan                        # auto-detects and scans active local subnet
  netboy scan 192.168.1.0/24         # scans specific CIDR
  netboy scan 192.168.1.0/24 --deep  # scans hosts and fingerprints open ports
  netboy scan --format json          # json output for scripting`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var targetSubnet string
			if len(args) > 0 {
				targetSubnet = args[0]
			} else {
				detected, err := scan.DetectDefaultSubnet()
				if err != nil {
					return fmt.Errorf("tidak dapat mendeteksi subnet lokal secara otomatis: %w", err)
				}
				targetSubnet = detected
			}

			start := time.Now()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cfg := scan.SubnetScanConfig{
				CIDR:        targetSubnet,
				Concurrency: optConcurrency,
				Timeout:     optTimeout,
				ResolveDNS:  optScanDNS,
				ScanPorts:   optScanDeep,
				PortPreset:  optScanPortPreset,
			}

			hosts, err := scan.ScanSubnet(ctx, cfg)
			if err != nil {
				return err
			}

			elapsed := time.Since(start).Round(time.Millisecond).String()
			payload := report.ScanPayload{
				Subnet:  targetSubnet,
				Hosts:   hosts,
				Elapsed: elapsed,
			}

			w, cleanup, err := getOutputWriter(cmd)
			if err != nil {
				return err
			}
			defer cleanup()

			switch optFormat {
			case "json":
				return report.RenderJSON(w, payload)
			case "markdown", "md":
				report.RenderScanMarkdown(w, payload)
				return nil
			default:
				report.RenderScanText(w, payload)
				return nil
			}
		},
	}

	cmd.Flags().BoolVar(&optScanDeep, "deep", false, "Perform deep port scan on all discovered hosts")
	cmd.Flags().BoolVar(&optScanDNS, "dns", true, "Resolve reverse DNS hostnames")
	cmd.Flags().StringVar(&optScanPortPreset, "preset", "top20", "Port preset when --deep is enabled (top20, dev, top100)")

	return cmd
}
