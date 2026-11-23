# Kebijakan keamanan

## Melaporkan celah

Jangan laporkan celah keamanan lewat Issue publik. Kirim email ke **simpulcreative.apps@gmail.com** dengan subjek `[SECURITY]`, berisi:

- aplikasi dan versi yang terdampak,
- langkah untuk mereproduksi,
- dampak yang Anda perkirakan.

Kami akan membalas secepatnya dan memberi tahu kapan perbaikan dirilis. Mohon beri kami waktu memperbaiki sebelum mempublikasikan temuan.

## Yang termasuk lingkup

- Pemalsuan atau pemutaran ulang `manifest.json` yang diterima oleh aplikasi
- Unduhan update yang bisa dialihkan atau diganti tanpa terdeteksi
- Kebocoran data pengguna oleh launcher atau aplikasi
- Server MCP / CLI aplikasi Simpul yang bisa diakses dari luar komputer pengguna

## Rencana bila kunci tanda tangan bocor

1. Tanda tangani manifest baru dengan **kunci cadangan**.
2. Rilis versi aplikasi yang menghapus kunci yang bocor dari daftar kunci tepercaya.
3. Umumkan di repo ini dan di situs.
