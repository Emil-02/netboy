// Package cmd implements the netboy CLI commands.
package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// Version info set at build time or read from runtime/debug.
var Version = "dev"

var (
	optFormat      string
	optOutput      string
	optTimeout     time.Duration
	optConcurrency int
	optVerbose     bool
)

// NewRootCmd creates the base netboy command.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "netboy",
		Short: "Fast, zero-dependency network reconnaissance and security audit CLI",
		Long: `netboy 🤠 is a zero-dependency, developer-first network tool.
Scan local subnets, find exposed dev servers and databases, fingerprint open ports,
and audit your local network with a 0–100 security score. One Go binary, no libpcap needed.`,
		SilenceUsage: true,
	}

	rootCmd.PersistentFlags().StringVarP(&optFormat, "format", "f", "text", "Output format: text, json, markdown")
	rootCmd.PersistentFlags().StringVarP(&optOutput, "output", "o", "", "Write output to file")
	rootCmd.PersistentFlags().DurationVarP(&optTimeout, "timeout", "t", 800*time.Millisecond, "Per-host probe timeout")
	rootCmd.PersistentFlags().IntVarP(&optConcurrency, "concurrency", "c", 64, "Max concurrent worker routines")
	rootCmd.PersistentFlags().BoolVarP(&optVerbose, "verbose", "v", false, "Verbose output")

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newPortsCmd())
	rootCmd.AddCommand(newAuditCmd())
	rootCmd.AddCommand(newInterfacesCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

// Execute runs the netboy root command.
func Execute() int {
	rootCmd := NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		return 1
	}
	return 0
}

func getOutputWriter(cmd *cobra.Command) (io.Writer, func(), error) {
	if optOutput == "" {
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.Create(optOutput)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal membuat file output: %w", err)
	}
	cleanup := func() {
		_ = f.Close()
	}
	return f, cleanup, nil
}
