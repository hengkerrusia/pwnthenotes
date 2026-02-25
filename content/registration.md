---
title: Registration
description: Penjelasan mengenai fungsionalitas Registration
tags:
  - functionality
  - web
draft: false
---

## Deskripsi
Dalam konteks aplikasi web, **Registration** (Registrasi) adalah proses di mana pengguna baru membuat akun di dalam sistem. Proses ini biasanya melibatkan pengisian formulir dengan informasi dasar seperti username, email, dan password.

## Potensi Kerentanan
Fungsi registrasi sering kali menjadi sasaran empuk bagi penyerang. Beberapa kerentanan yang umum terjadi antara lain:
*   **Username Enumeration:** Sistem memberitahu apakah sebuah username sudah terdaftar atau belum, yang dapat digunakan untuk melakukan *brute force* username.
*   **Weak Password Policy:** Mengizinkan pengguna menggunakan password yang lemah.
*   **Case Sensitivity Issues:** Perbedaan penanganan huruf besar dan kecil antara backend (misalnya Node.js) dan database (misalnya MySQL/SQLite) saat mengecek *unique constraints*.
*   **Mass Assignment:** Parameter tambahan yang secara tidak sengaja dapat dimanipulasi saat registrasi (misalnya menambahkan `role=admin`).
