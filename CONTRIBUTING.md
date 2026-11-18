# Berkontribusi ke netboy 🤠

Terima kasih sudah tertarik berkontribusi ke `netboy`. Sebelum mulai, silakan baca panduan singkat di bawah ini agar prosesnya rapi dan selaras.

## Aturan atribusi & kepemilikan

Repository ini dibuat dan dipelihara oleh akun GitHub [@Emil-02](https://github.com/Emil-02). Seluruh atribusi, kepemilikan, dan kredit penulisan di repository ini tercatat pada akun tersebut — **tidak ada pencantuman co-author, co-contributor, bot, atau akun lain dalam riwayat commit, metadata, maupun dokumentasi**. Lihat [`.github/CODEOWNERS`](.github/CODEOWNERS). Jika kamu ingin mengajukan perubahan, diskusikan terlebih dahulu melalui GitHub Issues atau Pull Request agar tata kelolanya tetap konsisten.

## Alur kerja

1. Buka issue terlebih dahulu untuk fitur besar, probe servis baru, atau perombakan skema output.
2. Buat branch baru dari `main` dengan format:
   - `feat/nama-fitur`
   - `fix/nama-perbaikan`
   - `docs/nama-dokumen`
3. Tulis unit test untuk setiap modul atau logika baru (`*_test.go`).
4. Jalankan pengujian lokal sebelum membuat PR:

```sh
go vet ./...
go test -race ./...
go build ./...
```

5. Buat Pull Request dengan penjelasan singkat: latar belakang, solusi teknis, dan verifikasi hasil pengujian.

## Struktur kode

* `cmd/`: Command line parser berbasis Cobra (`scan`, `ports`, `audit`, `interfaces`, `version`).
* `internal/scan/`: Engine penemuan host jaringan lokal, subnet CIDR expansion, dan ekstraksi info antarmuka.
* `internal/ports/`: Port scanner konkuren (worker pool), preset port, dan grabber banner servis.
* `internal/audit/`: Rule evaluasi celah keamanan servis lokal dan kalkulator skor 0–100.
* `internal/oui/`: Database dan pencarian vendor MAC tersemat tanpa ketergantungan eksternal.
* `internal/report/`: Formatter laporan terminal (ANSI), JSON, dan Markdown.
