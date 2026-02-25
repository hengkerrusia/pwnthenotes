---
title: Command Substitution
description: Penjelasan mengenai terminologi Command Substitution
tags:
  - os
  - shell
  - concept
draft: false
---

## Deskripsi
**Command Substitution** (Substitusi Perintah) merupakan fungsionalitas di lingkup *shell* baris perintah (seperti *Bash*, *Zsh*) maupun beberapa iterasi bahasa pemrograman lama (Perl, Ruby, PHP) di mana _output_ dari sebuah perintah/sintaks komando yang dieksekusi akan ditangkap dan diumpankan sebagai argumen masukan untuk menggantikan lokasi panggilan (*placeholder*) deklarasi komando aslinya.

## Sintaks Asali
Subtstitusi perintah umumnya diformat menggunakan dua notasi populer:
1. **Backticks:** Sintaks tradisional menggunakan karakter kutip belakang (``` `perintah` ```). Masih sangat sering ditemui dan didukung oleh hampir semua jenis kompilator _shell POSIX_ standar.
2. **Simbol Dolar (`$`):** Sintaks *shell* modern lazim menggunakan tanda `$(perintah)` karena dinilai jauh lebih tangguh saat meretas deklarasi bertingkat (bersarang).

## Implikasi Keamanan Logis
Kegagalan menyanitasi untaian string luaran dari fitur ini melahirkan celah keamanan kritikal jika parameter itu dilempar ke fungsi eksekutor internal (seperti skenario *eval* ataupun utilitas pengurai berkas sistem). Inidividu lincah bisa merekayasa titik interupsi (*escape char*) sehingga sisipan perintah yang sengaja ditempatkan di dalam *backtick* langsung diotorisasi mentah secara siluman oleh *supervisor* proses pada *parent shell* peladen ([[remote-code-execution]]).
