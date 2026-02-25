---
title: Code Quality
description: Penjelasan mengenai terminologi Code Quality dalam pengembangan
tags:
  - software engineering
  - testing
draft: false
---

## Deskripsi
**Code Quality** (Kualitas Kode) adalah sebuah ukuran seberapa baik piranti lunak direkayasa dilihat dari berbagai metrik, utamanya seperti *Keterbacaan* (Readability), *Kestabilan*, *Skalabilitas*, dan utamanya **Keamanan** (Security). 

Dalam rekayasa sistem riil, kualitas basis kode yang buruk berbanding lurus dengan cacat arsitektur dan membengkaknya ruang kerentanan (*attack surface*) sebuah aplikasi (*Tech Debt*).

## Relevansi Keamanan (Security Quality)
Terdapat banyak anomali keamanan yang bersumber bukan karena desain aplikasinya rentan, namun murni disebabkan _developer_ abai dalam manajemen _Code Quality_, misal:
1. **Penggunaan API Berbahaya:** Menggunakan fungsionalitas pengujian/debug di ranah produksi (misalnya `assert()` atau `phpinfo()`). Pada PHP, fungsi utilitas _assert()_ diciptakan hanya sebagai perlengkapan _debugging_ dan tidak pantas dibiarkan tertinggal di level produksi.
2. **Hardcoded Secrets:** Membuang kredensial produksi pada struktur teks kode.
3. **Dead Code:** Fitur-fitur lama (seperti _API endpoint_ versi lawas) yang ditinggalkan (*orphaned*), namun masih dapat diakses publik hingga memunculkan jalan bagi parameter usang.

Pemeliharaan kualitas yang baik senantiasa menaati panduan keamanan (_Secure Coding Standard_) dan audit menggunakan alat deteksi kecacatan SAST (*Static Application Security Testing*).
