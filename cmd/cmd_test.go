package cmd

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "netboy") {
		t.Errorf("expected version output to contain 'netboy', got: %s", out)
	}
}

func TestInterfacesCommand(t *testing.T) {
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"interfaces", "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("interfaces command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "name") {
		t.Errorf("expected json output to contain 'name', got: %s", out)
	}
}

func TestPortsCommandLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"ports", "127.0.0.1",
		"-p", fmt.Sprintf("%d", port),
		"--format", "json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("ports command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, fmt.Sprintf("%d", port)) {
		t.Errorf("expected open port in output, got: %s", out)
	}
}

func TestAuditCommandLocal(t *testing.T) {
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"audit", "127.0.0.1",
		"-p", "65432",
		"--format", "json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("audit command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "score") {
		t.Errorf("expected score in audit output, got: %s", out)
	}
}
