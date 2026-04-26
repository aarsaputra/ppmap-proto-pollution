# PPMAP 2026-2027 Strategic Roadmap (v4.5 - v5.0)

Berdasarkan analisis keamanan siber modern dan umpan balik strategis, berikut adalah peta jalan evolusi **PPMAP** untuk mempertahankan posisi sebagai alat pemindaian *Prototype Pollution* terdepan.

## 1. Peningkatan Deteksi Vektor Serangan Terbaru
- [ ] **Middle-Path WAF Bypass**: Injeksi payload pada segmen properti selain `root` (contoh: `a.__proto__.b`) untuk mem-bypass deteksi dangkal (Ref: CVE-2026-27837).
- [ ] **Non-Reflected Side-Channel Analysis**: Deteksi *blind server-side* melalui manipulasi struktur JSON (memicu *syntax error*) atau manipulasi `Content-Type`/`Charset` jika Interact.sh/OOB terblokir.
- [ ] **2026 Sink & Gadget Fingerprinting**: Pemindaian properti global mutakhir di *client* maupun *server-side*, termasuk `validateStatus` (Axios - CVE-2026-42041) dan bypass *merge* (seperti `defu` - CVE-2026-35209).
- [ ] **Serialization & Handler Pollution**: Deteksi polusi pada parser modern (YAML, CSV) dan pustaka sanitasi (e.g., `DOMPurify` - CVE-2026-41238, `devalue.parse` - CVE-2025-57820).

## 2. Optimalisasi Fitur Eksisting
- [ ] **Stabilisasi Async Engine**: Peningkatan penanganan kegagalan (*error handling*) dan laju kontrol (*rate-limiting*) pada mode `--async-scan`.
- [ ] **Layered Encoding WAF Evasion**: Peningkatan `Smart FP Engine` melalui modul fuzzing berbasis enkoding multi-lapis (misal: URL Encoding -> Decimal HTML -> Unicode) untuk menembus WAF.
- [ ] **Advanced Stealth Mode**: Penambahan *jitter*, pengacakan agen pengguna secara dinamis, jeda trafik berbasis manusia, dan pemblokiran modul recon yang terlalu agresif.

## 3. Peningkatan Dukungan DevEx & CI/CD
- [ ] **OpenAPI / Swagger Ingestion**: Pembuatan modul untuk parsing otomatis spesifikasi OpenAPI (JSON/YAML) guna menghasilkan rute injeksi secara akurat tanpa *crawling*.
- [ ] **Diff Scanning (Regression Targeting)**: Filter stateful yang hanya melakukan injeksi terhadap direktori atau parameter yang berubah berbasis hash target (`--save-baseline` / `--diff`).
- [ ] **CI/CD Native Logging**: Output CLI yang kompatibel dengan format agregasi (misal: JSON Lines) secara STDOUT untuk mempermudah perantaian dengan _pipeline tools_.
- [ ] **Refinement Docker Ekosistem**: _Multi-stage build_ yang super ringan dan _entrypoint_ stabil.

## 4. Inovasi Riset Jangka Panjang
- [ ] **AST (Abstract Syntax Tree) Integration**: Membedah JavaScript sisi klien menggunakan SAST hibrida (`node-source-parser`) secara mendalam sebelum eksekusi DOM.
- [ ] **LLM-Augmented Verification**: Mengirimkan hasil analisis AST ke *model* lokal (via *Ollama*) untuk penyaringan *false-positive* dan otomatisasi pembuatan *Proof of Concept*.
- [ ] **Native GraphQL Subscription**: Perluasan deteksi WebSocket menuju WebSocket-based GraphQL Subscriptions yang rentan polusi sesi.
