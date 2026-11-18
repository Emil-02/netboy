// Package ports provides fast TCP port scanning, presets, and service banner grabbing.
package ports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ServiceInfo holds port details.
type ServiceInfo struct {
	Port        int    `json:"port"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// WellKnownServices maps known port numbers to their default service metadata.
var WellKnownServices = map[int]ServiceInfo{
	21:    {21, "ftp", "File Transfer Protocol (insecure)"},
	22:    {22, "ssh", "Secure Shell"},
	23:    {23, "telnet", "Telnet (unencrypted plain text)"},
	25:    {25, "smtp", "Simple Mail Transfer"},
	53:    {53, "dns", "Domain Name System"},
	80:    {80, "http", "HyperText Transfer Protocol"},
	110:   {110, "pop3", "Post Office Protocol v3"},
	143:   {143, "imap", "Internet Message Access Protocol"},
	443:   {443, "https", "HTTP over TLS/SSL"},
	445:   {445, "smb", "Server Message Block"},
	993:   {993, "imaps", "IMAP over TLS"},
	995:   {995, "pop3s", "POP3 over TLS"},
	1433:  {1433, "mssql", "Microsoft SQL Server"},
	1521:  {1521, "oracle", "Oracle Database"},
	1883:  {1883, "mqtt", "MQTT IoT Message Broker"},
	2375:  {2375, "docker", "Docker Remote API (unencrypted!)"},
	2376:  {2376, "docker-tls", "Docker Remote API over TLS"},
	3000:  {3000, "dev-web", "React/Next.js/Node dev server"},
	3306:  {3306, "mysql", "MySQL / MariaDB database"},
	3389:  {3389, "rdp", "Remote Desktop Protocol"},
	4200:  {4200, "angular", "Angular dev server"},
	5000:  {5000, "flask", "Flask / ASP.NET dev server"},
	5173:  {5173, "vite", "Vite dev server"},
	5432:  {5432, "postgres", "PostgreSQL database"},
	5672:  {5672, "rabbitmq", "RabbitMQ messaging"},
	5900:  {5900, "vnc", "VNC Remote Desktop"},
	6379:  {6379, "redis", "Redis in-memory store"},
	8000:  {8000, "http-alt", "Common HTTP alternative (Django/FastAPI)"},
	8080:  {8080, "http-proxy", "Common HTTP alternative / Spring / Proxy"},
	8443:  {8443, "https-alt", "HTTPS alternative"},
	8888:  {8888, "jupyter", "Jupyter Notebook / Web alternative"},
	9000:  {9000, "minio", "MinIO S3 / PHP-FPM / Portainer"},
	9090:  {9090, "prometheus", "Prometheus monitoring"},
	9200:  {9200, "elasticsearch", "Elasticsearch REST API"},
	27017: {27017, "mongodb", "MongoDB database"},
}

// Top20Ports list.
var Top20Ports = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
	993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
}

// DevPorts list focusing on dev stacks & databases.
var DevPorts = []int{
	22, 80, 443, 1883, 2375, 3000, 3306, 4200, 5000, 5173,
	5432, 5672, 6379, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 27017,
}

// Top100Ports list.
var Top100Ports = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
	119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
	515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
	1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1883, 1900, 2000, 2001,
	2049, 2121, 2375, 2717, 3000, 3128, 3306, 3389, 3986, 4200, 4899, 5000,
	5009, 5051, 5060, 5101, 5173, 5190, 5357, 5432, 5631, 5666, 5672, 5800,
	5900, 6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
	8888, 9000, 9090, 9100, 9200, 9999, 27017,
}

// ParsePortSpec parses user input like "80,443,3000-3005" into a sorted deduplicated slice.
func ParsePortSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	switch strings.ToLower(spec) {
	case "top20", "top-20":
		return Top20Ports, nil
	case "top100", "top-100":
		return Top100Ports, nil
	case "dev":
		return DevPorts, nil
	}

	seen := make(map[int]bool)
	var ports []int

	parts := strings.Split(spec, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			rangeParts := strings.SplitN(p, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range %q", p)
			}
			for i := start; i <= end; i++ {
				if !seen[i] {
					seen[i] = true
					ports = append(ports, i)
				}
			}
		} else {
			port, err := strconv.Atoi(p)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port %q", p)
			}
			if !seen[port] {
				seen[port] = true
				ports = append(ports, port)
			}
		}
	}

	sort.Ints(ports)
	return ports, nil
}

// LookupService returns the service name and description for a port.
func LookupService(port int) (name string, desc string) {
	if info, ok := WellKnownServices[port]; ok {
		return info.Name, info.Description
	}
	return "unknown", "Unknown service"
}
