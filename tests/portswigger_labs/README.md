# tests/portswigger_labs — template capture (SUDAH DISANITASI)

File di folder ini adalah capture mentah request HTTP dari lab
PortSwigger Web Security Academy, dipakai sebagai bahan uji parser ppmap.

## Aturan: JANGAN pernah commit nilai asli

Semua nilai sensitif WAJIB diganti placeholder sebelum commit:

| Bagian            | Placeholder                          |
|-------------------|--------------------------------------|
| Cookie sesi       | `Cookie: session=YOUR_SESSION_HERE`  |
| Host instance lab | `YOUR-LAB-ID.web-security-academy.net` |
| `sessionId` (JSON)| `"sessionId":"YOUR_LAB_SESSION_ID"`  |

Kenapa: cookie `session=` itu bearer credential untuk instance lab Anda
(repo ini PUBLIK), dan instance ID lab menunjukkan host target pengujian.

## Cara sanitasi otomatis

```bash
python tools/redact_lab_requests.py .        # jalankan dari root repo
python tools/redact_lab_requests.py . --verbose
```

Skrip bersifat idempotent (aman dijalankan berulang) dan hanya menyentuh
berkas `tests/portswigger_labs/*.txt`.

## Riwayat

2026-10-06: 6 capture + riwayat git (312 commit, 9 tag) ditulis ulang untuk
membuang 6 cookie sesi dan 5 host instance lab yang sebelumnya ikut ter-push.
