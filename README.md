# netboy 🤠

**Fast, zero-dependency network reconnaissance and security audit CLI for developers & sysadmins.** One Go binary, no root required for basic scans, no external C libraries or libpcap needed.

[![CI](https://github.com/Emil-02/netboy/actions/workflows/ci.yml/badge.svg)](https://github.com/Emil-02/netboy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/Emil-02/netboy.svg)](https://pkg.go.dev/github.com/Emil-02/netboy)

🇮🇩 [Baca dalam Bahasa Indonesia](README.id.md)

> **Using an AI coding agent?** Install [`jaga-skill`](https://github.com/Emil-02/jaga/tree/main/skills/jaga-skill) with `npx jaga-skill init` — a gate that stops the agent before commit/deploy when secrets or personal data are detected.

```console
$ netboy scan
netboy scan — 192.168.1.0/24
────────────────────────────────────────────────────────────────────
IP ADDRESS       HOSTNAME             MAC ADDRESS        VENDOR
────────────────────────────────────────────────────────────────────
192.168.1.1      router.lan           28:6D:DA:41:C9:B0  MikroTik
192.168.1.14     printer-office       00:1E:C9:11:22:33  HP Inc.
192.168.1.18     sensor-iot.local     24:0A:C4:AA:BB:CC  Espressif Systems
192.168.1.21     dev-laptop           90:09:DF:89:D8:DA  Dell Inc.
────────────────────────────────────────────────────────────────────
✓ Ditemukan 4 host aktif (selesai dalam 520ms)
```

## Why netboy?

Heavy tools like `nmap` or `arp-scan` require root privileges, external C libraries (`libpcap`), or hundreds of complex flags. Meanwhile, developers routinely run Docker containers, databases, local API servers, and IoT devices that accidentally bind to `0.0.0.0` or stay unauthenticated.

`netboy` completes the developer security toolchain alongside [`envboy`](https://github.com/Emil-02/envboy), [`leakboy`](https://github.com/Emil-02/leakboy), and [`jaga`](https://github.com/Emil-02/jaga):

- **Zero dependencies & pure Go**: No libpcap, no CGO, no root permission needed for standard sweeps.
- **Fast concurrent scans**: Scans whole `/24` subnets in milliseconds using an intelligent worker pool.
- **Built-in OUI vendor database**: Identifies manufacturers (Apple, Raspberry Pi, Espressif, MikroTik, etc.) offline.
- **Service banner grabbing**: Fingerprints HTTP, SSH, Redis, Docker, databases, and SSL certificates.
- **Network Security Score (0–100)**: Instant rating and actionable recommendations for exposed dev services.
- **CI / Automation ready**: JSON, Markdown, and text output with `--fail-under` flag support.

## Commands

| Command | What it does |
|---|---|
| `netboy scan [CIDR]` | Discovers active hosts, hostnames, and MAC vendors on your local network or specified subnet |
| `netboy ports <target>` | Concurrently scans open ports and fingerprints service banners (`--ports dev,top20,top100`) |
| `netboy audit <target>` | Audits for exposed databases, dev servers, or unauthenticated services with a 0–100 score |
| `netboy interfaces` | Lists all active local network interfaces, IP addresses, and detected subnets |
| `netboy version` | Displays version and build info |

## Installation

### Via Go Install

```sh
go install github.com/Emil-02/netboy@latest
```

### From Source

```sh
git clone https://github.com/Emil-02/netboy.git
cd netboy
make test
make install
```

## Usage Examples

### 1. Subnet Discovery

```sh
# Auto-detects your active Wi-Fi / Ethernet subnet
netboy scan

# Scan a specific CIDR
netboy scan 192.168.1.0/24

# Deep scan (discovers hosts and fingerprints their open ports)
netboy scan 192.168.1.0/24 --deep

# JSON output for scripting or piping
netboy scan --format json
```

### 2. Fast Port Scanning

```sh
# Scan top 20 ports on router
netboy ports 192.168.1.1

# Scan common developer ports (3000, 5432, 6379, 8080, etc.)
netboy ports 127.0.0.1 -p dev

# Custom port list or range
netboy ports 192.168.1.50 -p 80,443,3000-3005
```

### 3. Security Audits & Scoring

```sh
$ netboy audit 127.0.0.1

netboy audit — 127.0.0.1
────────────────────────────────────────────────────────────────────
Network Security Score: 75/100 (Grade: B) — Good / Low Exposure
Risiko: 1 Critical, 0 High, 0 Medium, 0 Low
────────────────────────────────────────────────────────────────────
[CRITICAL] Unauthenticated Redis Store Exposed (Port 6379 - redis)
  Masalah: Redis responded to PING without authentication.
  Solusi : Set `requirepass <password>` and `bind 127.0.0.1` in redis.conf.
```

### 4. CI / Pipeline Integration

Fail your CI build if local services or test containers expose critical risks:

```sh
netboy audit 127.0.0.1 --fail-under 80
```

## Ecosystem

Part of the open source security toolkit by [@Emil-02](https://github.com/Emil-02):

- [jaga](https://github.com/Emil-02/jaga) — One gate to check secrets, PII, and repo hygiene before deploy.
- [envboy](https://github.com/Emil-02/envboy) — Back up, restore, check, and guard `.env` files across all repos.
- [leakboy](https://github.com/Emil-02/leakboy) — Find leaks in vibe-coded web apps before someone else does.
- [sensor](https://github.com/Emil-02/sensor) — Mask Indonesian PII (NIK, NPWP, phone, bank account) anywhere.
- [gh-spruce](https://github.com/Emil-02/gh-spruce) — Lighthouse for your GitHub profile and repositories.

## License

[MIT](LICENSE) © 2026 Emil-02
