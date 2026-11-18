package scan

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Emil-02/netboy/internal/oui"
	"github.com/Emil-02/netboy/internal/ports"
)

// DefaultProbePorts are ports checked to detect if a host is up without root.
var DefaultProbePorts = []int{80, 443, 22, 445, 53, 8080, 135, 3389, 21, 23, 8000}

// ListInterfaces returns all available network interfaces.
func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	var results []InterfaceInfo
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:       iface.Name,
			MAC:        iface.HardwareAddr.String(),
			IsUp:       (iface.Flags & net.FlagUp) != 0,
			IsLoopback: (iface.Flags & net.FlagLoopback) != 0,
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && ipNet.IP.To4() != nil {
					info.IPs = append(info.IPs, ipNet.IP.String())
					info.Subnets = append(info.Subnets, ipNet.String())
				}
			}
		}

		results = append(results, info)
	}

	return results, nil
}

// DetectDefaultSubnet discovers the primary IPv4 subnet of the active interface.
func DetectDefaultSubnet() (string, error) {
	// Attempt a connection to public DNS to find default outgoing route
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		localIP := localAddr.IP.To4()

		if localIP != nil {
			// Find which interface owns this IP
			ifaces, _ := ListInterfaces()
			for _, iface := range ifaces {
				for _, sub := range iface.Subnets {
					_, ipnet, err := net.ParseCIDR(sub)
					if err == nil && ipnet.Contains(localIP) {
						return sub, nil
					}
				}
			}
			// Fallback: assume /24
			return fmt.Sprintf("%d.%d.%d.0/24", localIP[0], localIP[1], localIP[2]), nil
		}
	}

	// Fallback to scanning interfaces directly
	ifaces, err := ListInterfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.IsUp && !iface.IsLoopback && len(iface.Subnets) > 0 {
			return iface.Subnets[0], nil
		}
	}

	return "", fmt.Errorf("could not automatically detect active subnet, please specify CIDR")
}

// ExpandCIDR expands a CIDR notation (e.g. 192.168.1.0/24) into a list of host IPs.
func ExpandCIDR(cidrStr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		// Maybe user supplied single IP
		singleIP := net.ParseIP(cidrStr)
		if singleIP != nil && singleIP.To4() != nil {
			return []string{singleIP.String()}, nil
		}
		return nil, fmt.Errorf("invalid CIDR or IP format: %q", cidrStr)
	}

	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv6 subnets are not currently supported for broad sweeps")
	}

	mask := ipnet.Mask
	ones, bits := mask.Size()
	hostBits := bits - ones
	if hostBits > 12 { // Limit sweep to /20 (4096 hosts) to avoid memory explosion
		return nil, fmt.Errorf("subnet too large (%d hosts), maximum allowed is /20", 1<<hostBits)
	}

	networkInt := binary.BigEndian.Uint32(ipnet.IP.To4())
	broadcastInt := networkInt | (^binary.BigEndian.Uint32(mask))

	var ips []string
	if hostBits <= 1 {
		// /31 or /32
		ips = append(ips, ip.String())
	} else {
		// Standard subnet: skip network (start+0) and broadcast (end)
		for current := networkInt + 1; current < broadcastInt; current++ {
			hostIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(hostIP, current)
			ips = append(ips, hostIP.String())
		}
	}

	return ips, nil
}

// ReadARPTable parses /proc/net/arp (on Linux) to map IP addresses to MAC addresses.
func ReadARPTable() map[string]string {
	arpMap := make(map[string]string)
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return arpMap
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Skip header line
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			ip := fields[0]
			flags := fields[2]
			mac := fields[3]
			// 0x0 flag means incomplete/unresolved, 0x2 is valid complete ARP
			if flags != "0x0" && mac != "00:00:00:00:00:00" {
				arpMap[ip] = mac
			}
		}
	}

	return arpMap
}

// ScanSubnet performs concurrent host discovery across the specified CIDR.
func ScanSubnet(ctx context.Context, cfg SubnetScanConfig) ([]HostResult, error) {
	ips, err := ExpandCIDR(cfg.CIDR)
	if err != nil {
		return nil, err
	}

	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 64
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 800 * time.Millisecond
	}
	if len(cfg.ProbePorts) == 0 {
		cfg.ProbePorts = DefaultProbePorts
	}

	type probeResult struct {
		ip      string
		alive   bool
		latency time.Duration
	}

	ipsChan := make(chan string, len(ips))
	for _, ip := range ips {
		ipsChan <- ip
	}
	close(ipsChan)

	resChan := make(chan probeResult, len(ips))
	var wg sync.WaitGroup

	workers := cfg.Concurrency
	if workers > len(ips) {
		workers = len(ips)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-ipsChan:
					if !ok {
						return
					}
					alive, latency := probeHostAlive(ctx, ip, cfg.ProbePorts, cfg.Timeout)
					if alive {
						resChan <- probeResult{ip: ip, alive: true, latency: latency}
					}
				}
			}
		}()
	}

	wg.Wait()
	close(resChan)

	// Fetch ARP table once after probing (probing triggers ARP resolutions in kernel)
	arpTable := ReadARPTable()

	var aliveHosts []HostResult
	for pr := range resChan {
		host := HostResult{
			IP:      pr.ip,
			Latency: pr.latency,
		}

		// Check MAC & Vendor from ARP table
		if mac, ok := arpTable[pr.ip]; ok {
			host.MAC = mac
			host.Vendor = oui.Lookup(mac)
		}

		// Reverse DNS lookup if enabled
		if cfg.ResolveDNS {
			names, err := net.LookupAddr(pr.ip)
			if err == nil && len(names) > 0 {
				host.Hostname = strings.TrimSuffix(names[0], ".")
			}
		}

		// Deep port scan on alive host if requested
		if cfg.ScanPorts {
			var portList []int
			switch cfg.PortPreset {
			case "dev":
				portList = ports.DevPorts
			case "top100":
				portList = ports.Top100Ports
			default:
				portList = ports.Top20Ports
			}
			openPorts, _ := ports.ScanHost(ctx, ports.ScanConfig{
				Target:      pr.ip,
				Ports:       portList,
				Concurrency: 16,
				Timeout:     cfg.Timeout,
				GrabBanners: true,
			})
			host.OpenPorts = openPorts
		}

		aliveHosts = append(aliveHosts, host)
	}

	sort.Slice(aliveHosts, func(i, j int) bool {
		return ipToUint32(aliveHosts[i].IP) < ipToUint32(aliveHosts[j].IP)
	})

	return aliveHosts, nil
}

// probeHostAlive checks if a host responds on any probe port or responds to quick SYN/Connect.
func probeHostAlive(ctx context.Context, ip string, probePorts []int, timeout time.Duration) (bool, time.Duration) {
	for _, port := range probePorts {
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		start := time.Now()
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return true, time.Since(start)
		}
		// In TCP, connection refused (RST) means the host IS alive and active!
		if err != nil && isConnectionRefused(err) {
			return true, time.Since(start)
		}
	}
	return false, 0
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "refused")
}

func ipToUint32(ipStr string) uint32 {
	parsed := net.ParseIP(ipStr).To4()
	if parsed == nil {
		return 0
	}
	return binary.BigEndian.Uint32(parsed)
}
