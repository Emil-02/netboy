# netboy 🤠

**Alat audit keamanan dan pemindaian jaringan lokal yang cepat, tanpa dependensi eksternal, untuk developer dan sysadmin.** Satu binary Go, tanpa butuh root untuk pemindaian standar, tanpa library C / libpcap.

[![CI](https://github.com/Emil-02/netboy/actions/workflows/ci.yml/badge.svg)](https://github.com/Emil-02/netboy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🇬🇧 [Read in English](README.md)

> **Menggunakan AI coding agent?** Pasang [`jaga-skill`](https://github.com/Emil-02/jaga-skill) dengan `npx jaga-skill init` — gerbang pengaman yang menghentikan agen AI sebelum melakukan commit/deploy saat terdeteksi kredensial rahasia atau data pribadi.

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

## Kenapa netboy?

Scanner konvensional seperti `nmap` membutuhkan akses root, dependensi C (`libpcap`), atau puluhan parameter yang rumit. Di saat yang sama, developer sering kali menjalankan container Docker, database lokal, server pengembangan web, dan perangkat IoT yang tanpa sengaja ter-bind ke `0.0.0.0` atau tanpa proteksi sandi di jaringan lokal.

`netboy` melengkapi rangkaian perkakas keamanan pengembang bersama [`envboy`](https://github.com/Emil-02/envboy), [`leakboy`](https://github.com/Emil-02/leakboy), dan [`jaga`](https://github.com/Emil-02/jaga):

- **Tanpa dependensi luar (Pure Go)**: Tidak perlu libpcap, tanpa CGO, tidak wajib hak akses root untuk pemindaian jaringan biasa.
- **Cepat & konkuren**: Memindai seluruh subnet `/24` dalam hitungan ratusan milidetik dengan worker pool terkontrol.
- **Database Vendor OUI Offline**: Langsung mengenali pabrikan perangkat (Apple, Raspberry Pi, Espressif, MikroTik, HP, dll.).
- **Banner Grabbing Pintar**: Mendeteksi banner servis (HTTP, SSH, Redis, Docker API, database).
- **Skor Keamanan Jaringan (0–100)**: Penilaian instan dan panduan solusi konkrit untuk servis dev yang terekspos.
- **Siap untuk CI / Otomasi**: Format keluaran teks, JSON, dan Markdown dengan dukungan opsi `--fail-under`.

## Perintah Utama

| Perintah | Deskripsi |
|---|---|
| `netboy scan [CIDR]` | Menemukan perangkat aktif, nama host, dan vendor MAC pada jaringan lokal |
| `netboy ports <target>` | Memindai port terbuka dan membaca banner servis (`--ports dev,top20,top100`) |
| `netboy audit <target>` | Mengaudit database/servis yang terekspos dengan kalkulasi skor 0–100 |
| `netboy interfaces` | Menampilkan daftar interface jaringan, alamat IP, dan subnet aktif |
| `netboy version` | Menampilkan versi aplikasi |

## Instalasi

### Menggunakan Go Install

```sh
go install github.com/Emil-02/netboy@latest
```

### Kompilasi dari Source

```sh
git clone https://github.com/Emil-02/netboy.git
cd netboy
make test
make install
```

## Contoh Pemakaian

```sh
# Deteksi otomatis subnet Wi-Fi / LAN yang sedang aktif
netboy scan

# Pindai port stack developer (3000, 5432, 6379, 8080, dll.)
netboy ports 127.0.0.1 -p dev

# Audit keamanan servis lokal
netboy audit 127.0.0.1

# Jalankan dalam CI (gagal bila skor < 80)
netboy audit 127.0.0.1 --fail-under 80
```

## Lisensi

[MIT](LICENSE) © 2026 Emil-02
