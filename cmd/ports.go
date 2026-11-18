package cmd

import (
	"context"
	"time"

	"github.com/Emil-02/netboy/internal/ports"
	"github.com/Emil-02/netboy/internal/report"
	"github.com/spf13/cobra"
)

var (
	optPortSpec string
	optNoBanner bool
)

func newPortsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ports <target>",
		Short: "Fast concurrent TCP port scan and service banner grabbing",
		Args:  cobra.ExactArgs(1),
		Example: `  netboy ports 192.168.1.1                # scans top 20 ports on router
  netboy ports 127.0.0.1 -p dev           # scans developer stack ports
  netboy ports localhost -p 3000,5432,6379 # scans specific ports
  netboy ports 192.168.1.50 -p 1-1000     # scans port range`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			portList, err := ports.ParsePortSpec(optPortSpec)
			if err != nil {
				return err
			}

			start := time.Now()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cfg := ports.ScanConfig{
				Target:      target,
				Ports:       portList,
				Concurrency: optConcurrency,
				Timeout:     optTimeout,
				GrabBanners: !optNoBanner,
			}

			results, err := ports.ScanHost(ctx, cfg)
			if err != nil {
				return err
			}

			elapsed := time.Since(start).Round(time.Millisecond).String()
			payload := report.PortsPayload{
				Host:    target,
				Ports:   results,
				Elapsed: elapsed,
			}

			w, cleanup, err := getOutputWriter(cmd)
			if err != nil {
				return err
			}
			defer cleanup()

			if optFormat == "json" {
				return report.RenderJSON(w, payload)
			}

			report.RenderPortsText(w, payload)
			return nil
		},
	}

	cmd.Flags().StringVarP(&optPortSpec, "ports", "p", "top20", "Port specification: top20, dev, top100, or custom (e.g. 80,443,3000-3005)")
	cmd.Flags().BoolVar(&optNoBanner, "no-banner", false, "Disable service banner grabbing")

	return cmd
}
