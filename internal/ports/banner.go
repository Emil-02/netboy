package ports

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// BannerDetails stores extracted service banner information.
type BannerDetails struct {
	RawBanner   string `json:"raw_banner,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	TLS         bool   `json:"tls,omitempty"`
	TLSSubject  string `json:"tls_subject,omitempty"`
	Extra       string `json:"extra,omitempty"`
	Unprotected bool   `json:"unprotected,omitempty"`
}

// GrabBanner probes an open port to fingerprint service details.
func GrabBanner(ip string, port int, timeout time.Duration) BannerDetails {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	details := BannerDetails{}

	// 1. Specific protocols based on port or heuristics
	switch port {
	case 22:
		return probeSSH(addr, timeout)
	case 6379:
		return probeRedis(addr, timeout)
	case 2375:
		return probeDocker(addr, timeout)
	case 443, 8443:
		return probeHTTPS(addr, ip, port, timeout)
	case 80, 8080, 3000, 5000, 5173, 8000, 8888, 9000, 9200:
		return probeHTTP(addr, timeout)
	default:
		// Generic banner grab (read first line if service announces itself)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return details
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))

		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err == nil && len(strings.TrimSpace(line)) > 0 {
			clean := strings.TrimSpace(line)
			details.RawBanner = clean
			if strings.HasPrefix(clean, "SSH-") {
				details.Product = "SSH"
				details.RawBanner = clean
			} else if strings.HasPrefix(clean, "220") {
				details.Product = "FTP/SMTP"
				details.RawBanner = clean
			}
			return details
		}

		// Try lightweight HTTP probe for unknown port
		return probeHTTP(addr, timeout)
	}
}

func probeSSH(addr string, timeout time.Duration) BannerDetails {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return BannerDetails{}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return BannerDetails{Product: "SSH"}
	}
	banner = strings.TrimSpace(banner)
	return BannerDetails{
		Product:   "SSH",
		RawBanner: banner,
	}
}

func probeRedis(addr string, timeout time.Duration) BannerDetails {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return BannerDetails{Product: "Redis"}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	_, _ = conn.Write([]byte("PING\r\n"))
	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err == nil {
		resp = strings.TrimSpace(resp)
		if strings.Contains(resp, "PONG") {
			return BannerDetails{
				Product:     "Redis",
				RawBanner:   "+PONG",
				Unprotected: true,
				Extra:       "CRITICAL: Unauthenticated Redis access! No password required.",
			}
		}
		if strings.Contains(resp, "NOAUTH") {
			return BannerDetails{
				Product:   "Redis",
				RawBanner: resp,
				Extra:     "Protected (Password required)",
			}
		}
	}
	return BannerDetails{Product: "Redis"}
}

func probeDocker(addr string, timeout time.Duration) BannerDetails {
	client := &http.Client{
		Timeout: timeout,
	}
	resp, err := client.Get(fmt.Sprintf("http://%s/version", addr))
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		return BannerDetails{
			Product:     "Docker Daemon",
			Unprotected: true,
			Extra:       "CRITICAL: Exposed unauthenticated Docker Remote API!",
		}
	}
	return BannerDetails{Product: "Docker API"}
}

func probeHTTP(addr string, timeout time.Duration) BannerDetails {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		return BannerDetails{}
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	title := extractHTMLTitle(resp.Body)

	var extra []string
	if title != "" {
		extra = append(extra, fmt.Sprintf("Title: %s", title))
	}
	if poweredBy != "" {
		extra = append(extra, fmt.Sprintf("X-Powered-By: %s", poweredBy))
	}

	return BannerDetails{
		Product:   "HTTP",
		RawBanner: server,
		Extra:     strings.Join(extra, ", "),
	}
}

func probeHTTPS(addr string, host string, port int, timeout time.Duration) BannerDetails {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		return BannerDetails{TLS: true}
	}
	defer conn.Close()

	details := BannerDetails{TLS: true}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		details.TLSSubject = cert.Subject.CommonName
		if len(cert.DNSNames) > 0 {
			details.Extra = fmt.Sprintf("SANs: %s", strings.Join(cert.DNSNames, ", "))
		}
	}

	// Also perform HTTPS request for Server header
	transport := &http.Transport{
		TLSClientConfig: conf,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	resp, err := client.Get(fmt.Sprintf("https://%s/", addr))
	if err == nil {
		defer resp.Body.Close()
		details.Product = "HTTPS"
		details.RawBanner = resp.Header.Get("Server")
		title := extractHTMLTitle(resp.Body)
		if title != "" {
			if details.Extra != "" {
				details.Extra += " | Title: " + title
			} else {
				details.Extra = "Title: " + title
			}
		}
	}

	return details
}

func extractHTMLTitle(body io.Reader) string {
	// Read up to 4KB to find <title>
	buf := make([]byte, 4096)
	n, err := body.Read(buf)
	if err != nil && err != io.EOF {
		return ""
	}
	content := string(buf[:n])
	lower := strings.ToLower(content)

	startIdx := strings.Index(lower, "<title>")
	if startIdx == -1 {
		return ""
	}
	startIdx += 7

	endIdx := strings.Index(lower[startIdx:], "</title>")
	if endIdx == -1 {
		return ""
	}

	title := strings.TrimSpace(content[startIdx : startIdx+endIdx])
	// Clean linebreaks
	title = strings.ReplaceAll(title, "\n", " ")
	title = strings.ReplaceAll(title, "\r", " ")
	return title
}
