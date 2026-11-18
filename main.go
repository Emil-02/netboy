// Command netboy scans networks, discovers active hosts, fingerprints open ports, and audits service security.
package main

import (
	"os"
	"runtime/debug"

	"github.com/Emil-02/netboy/cmd"
)

var version = "0.1.0"

func main() {
	if version == "0.1.0" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}
	cmd.Version = version
	os.Exit(cmd.Execute())
}
