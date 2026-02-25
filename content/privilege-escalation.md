---
title: Privilege Escalation
description: Penjelasan mengenai terminologi Privilege Escalation
tags:
  - vulnerability
  - access control
draft: false
---

## Deskripsi
**Privilege Escalation** (Eskalasi Hak Akses) adalah jenis kerentanan *Broken Access Control* yang terjadi saat pengguna biasa sanggup mengeksploitasi cacat dalam otorisasi desain aplikasi, konfigurasi, atau sistem operasi untuk mendapatkan hak akses yang seharusnya tidak mereka miliki.

Ada dua ragam umum terkait ini:
1.  **Vertical Privilege Escalation:** Penyerang mendapatkan izin atau akses yang lebih tinggi/superior, misalnya mengubah peran diri dari *User* biasa menjadi *Admin* atau mendapatkan hak *root* atau spesifik *system account*.
2.  **Horizontal Privilege Escalation:** Penyerang dapat mengakses *resource* dengan level hak yang sepadan, namun berada dalam kapasitas akun orang lain (sering dibedah dalam kategori *Account Takeover* atau IDOR secara eksklusif).

Eskalasi wewenang vertikal sering ditemui akibat ceruk implementasi *[[mass-assignment]]* atau pembajakan sesi ID administrasi.
