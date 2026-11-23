# simpul-manifest

Satu sumber kebenaran untuk **versi terbaru** dan **status** (hijau / kuning / merah) setiap aplikasi Simpul Creative Apps.

Launcher dan setiap aplikasi (termasuk yang dipasang tanpa launcher) membaca file ini lewat modul [`simpul-guard`](https://github.com/simpulcreativeapps/simpul-guard), lalu **hanya mempercayainya kalau tanda tangannya sah**.

```
manifest.json        ← data: status & rilis terbaru tiap aplikasi
manifest.json.sig    ← tanda tangan Ed25519 atas manifest.json
public-keys/*.pub    ← kunci publik yang dipercaya (aman dipublikasikan)
tools/simpul-sign.mjs← alat buat kunci, validasi, tanda tangan, verifikasi
```

Alamat yang dibaca aplikasi:

1. Utama: `https://raw.githubusercontent.com/simpulcreativeapps/simpul-manifest/main/manifest.json`
2. Cadangan: salinan yang sama di situs Simpul Creative Apps (dipakai kalau GitHub tidak bisa dihubungi atau repo ini ditutup)

Butuh Node.js 18 atau lebih baru. Tidak ada dependensi lain.

---

## Status

| Status | Arti | Yang terjadi di komputer pengguna |
|---|---|---|
| `green` | Normal | Tidak ada pemberitahuan; update berjalan |
| `yellow` | Ada masalah, belum final | Banner pemberitahuan; aplikasi tetap bisa dipakai; update tetap berjalan |
| `red` | Dihentikan | Tidak ada update lagi; pemberitahuan + hitung mundur sampai `disable_at`; setelah itu aplikasi tidak bisa dibuka dan menawarkan uninstall |

Kalau manifest tidak bisa diambil atau tanda tangannya tidak sah, aplikasi **tetap berjalan seperti biasa** dengan status terakhir yang sah. Server mati tidak boleh mematikan aplikasi pengguna.

---

## Sekali saja: buat kunci

```bash
node tools/simpul-sign.mjs keygen
```

- Diminta passphrase (min. 12 karakter). Simpan di password manager.
- Kunci **privat** ditulis ke `~/.simpul-keys/` (di luar repo). Cadangkan ke dua tempat aman yang offline. **Jangan pernah di-commit atau diunggah.**
- Kunci **publik** ditulis ke `public-keys/<id>.pub`. File ini di-commit.
- Perintah ini juga mencetak satu baris untuk ditempel ke `simpul-guard/src/keys.rs`.

Buat **dua** kunci (utama dan cadangan) dan masukkan keduanya ke `simpul-guard`. Kalau kunci utama bocor, Anda tetap bisa menandatangani dengan kunci cadangan, lalu menarik kunci yang bocor di rilis berikutnya.

## Merilis versi baru

1. Unggah installer ke GitHub Releases repo aplikasinya.
2. Hitung sha256 installer:
   ```bash
   certutil -hashfile SimpulSync-Setup-0.2.0-x64.exe SHA256
   ```
3. Isi `release` aplikasi itu di `manifest.json`:
   ```json
   "release": {
     "version": "0.2.0",
     "url": "https://github.com/simpulcreativeapps/simpul-sync/releases/download/v0.2.0/SimpulSync-Setup-0.2.0-x64.exe",
     "sha256": "…64 karakter huruf kecil…",
     "notes_url": "https://github.com/simpulcreativeapps/simpul-sync/releases/tag/v0.2.0"
   }
   ```
4. Tanda tangani, cek, lalu push:
   ```bash
   node tools/simpul-sign.mjs sign --key ~/.simpul-keys/simpul-manifest-<id>.key
   node tools/simpul-sign.mjs verify
   git add manifest.json manifest.json.sig && git commit -m "Rilis Simpul Sync 0.2.0" && git push
   ```
5. Salin `manifest.json` dan `manifest.json.sig` yang sama ke situs (alamat cadangan).

## Kode kuning (peringatan)

```json
"sync": {
  "name": "Simpul Sync",
  "status": "yellow",
  "notice": {
    "title": "Pemberitahuan tentang Simpul Sync",
    "message": "Kami sedang meninjau sebuah keberatan terkait Simpul Sync. Aplikasi tetap bisa dipakai seperti biasa.",
    "source_url": "https://github.com/simpulcreativeapps/simpul-sync"
  },
  "release": { "…": "tetap boleh diisi" }
}
```

## Kode merah (penghentian)

```json
"sync": {
  "name": "Simpul Sync",
  "status": "red",
  "notice": {
    "title": "Simpul Sync dihentikan",
    "message": "Kami menerima permintaan penghentian dari pihak ketiga dan memilih menarik Simpul Sync. Aplikasi akan dinonaktifkan pada tanggal di bawah. Pekerjaan Anda tidak dihapus. Jika source code masih tersedia, Anda dapat membangunnya sendiri.",
    "disable_at": "2026-11-26T00:00:00Z",
    "source_url": "https://github.com/simpulcreativeapps/simpul-sync"
  },
  "release": null
}
```

Lalu tanda tangani, verifikasi, push, dan salin ke situs (sama seperti merilis versi baru).

- `release` wajib `null` saat merah: tidak ada lagi update.
- `disable_at` minimal beberapa hari ke depan, supaya pengguna sempat menyelesaikan dan mengekspor pekerjaan.
- **Membatalkan:** ubah kembali ke `green` (atau `yellow`) sebelum `disable_at`, tanda tangani, push.

## Pengaman yang dijalankan `simpul-guard`

- Tanda tangan Ed25519 wajib sah dan dari kunci yang tertanam di aplikasi.
- Manifest yang `issued_at`-nya lebih tua dari yang terakhir diterima ditolak (mencegah status lama diputar ulang).
- URL unduhan hanya boleh dari host yang diizinkan, dan installer dicek sha256-nya sebelum dijalankan.
- Manifest hanya berisi data; aplikasi tidak pernah menjalankan perintah dari manifest.
- Pengecekan tidak mengirim data pengguna apa pun.

Lihat [SECURITY.md](SECURITY.md) untuk melaporkan celah keamanan.
