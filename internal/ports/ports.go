package ports

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// PortResult represents the status and findings on a single port.
type PortResult struct {
	Port        int           `json:"port"`
	State       string        `json:"state"` // "open", "closed", "filtered"
	Service     string        `json:"service"`
	Description string        `json:"description"`
	Banner      BannerDetails `json:"banner,omitempty"`
	Latency     time.Duration `json:"latency,omitempty"`
}

// ScanConfig holds parameters for port scanning.
type ScanConfig struct {
	Target      string
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	GrabBanners bool
}

// ScanHost scans specified ports on target host using a controlled worker pool.
func ScanHost(ctx context.Context, cfg ScanConfig) ([]PortResult, error) {
	if len(cfg.Ports) == 0 {
		return nil, fmt.Errorf("no ports specified for scanning")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 32
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 800 * time.Millisecond
	}

	portsChan := make(chan int, len(cfg.Ports))
	resultsChan := make(chan PortResult, len(cfg.Ports))

	for _, p := range cfg.Ports {
		portsChan <- p
	}
	close(portsChan)

	var wg sync.WaitGroup
	workers := cfg.Concurrency
	if workers > len(cfg.Ports) {
		workers = len(cfg.Ports)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case port, ok := <-portsChan:
					if !ok {
						return
					}
					res := probePort(ctx, cfg.Target, port, cfg.Timeout, cfg.GrabBanners)
					if res.State == "open" {
						resultsChan <- res
					}
				}
			}
		}()
	}

	wg.Wait()
	close(resultsChan)

	var openPorts []PortResult
	for r := range resultsChan {
		openPorts = append(openPorts, r)
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	return openPorts, nil
}

func probePort(ctx context.Context, host string, port int, timeout time.Duration, grabBanner bool) PortResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	service, desc := LookupService(port)

	start := time.Now()
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	latency := time.Since(start)

	if err != nil {
		return PortResult{
			Port:        port,
			State:       "closed",
			Service:     service,
			Description: desc,
		}
	}
	_ = conn.Close()

	res := PortResult{
		Port:        port,
		State:       "open",
		Service:     service,
		Description: desc,
		Latency:     latency,
	}

	if grabBanner {
		res.Banner = GrabBanner(host, port, timeout)
	}

	return res
}
