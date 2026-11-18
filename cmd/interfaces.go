package cmd

import (
	"fmt"
	"strings"

	"github.com/Emil-02/netboy/internal/report"
	"github.com/Emil-02/netboy/internal/scan"
	"github.com/spf13/cobra"
)

func newInterfacesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "interfaces",
		Short: "List local network interfaces and detected subnets",
		RunE: func(cmd *cobra.Command, args []string) error {
			ifaces, err := scan.ListInterfaces()
			if err != nil {
				return err
			}

			w, cleanup, err := getOutputWriter(cmd)
			if err != nil {
				return err
			}
			defer cleanup()

			if optFormat == "json" {
				return report.RenderJSON(w, ifaces)
			}

			fmt.Fprintf(w, "NETWORK INTERFACES & SUBNETS\n")
			fmt.Fprintf(w, "%s\n", strings.Repeat("─", 65))
			fmt.Fprintf(w, "%-12s %-18s %-16s %s\n", "NAME", "MAC ADDRESS", "STATUS", "IP / SUBNET")
			fmt.Fprintf(w, "%s\n", strings.Repeat("─", 65))

			for _, iface := range ifaces {
				status := "DOWN"
				if iface.IsUp {
					status = "UP"
				}
				if iface.IsLoopback {
					status += " (loopback)"
				}

				subnets := strings.Join(iface.Subnets, ", ")
				if subnets == "" {
					subnets = "-"
				}
				mac := iface.MAC
				if mac == "" {
					mac = "-"
				}

				fmt.Fprintf(w, "%-12s %-18s %-16s %s\n", iface.Name, mac, status, subnets)
			}
			fmt.Fprintf(w, "%s\n", strings.Repeat("─", 65))
			return nil
		},
	}
}
