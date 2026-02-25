---
title: Authorization
description: Penjelasan mengenai terminologi Authorization
tags:
  - security concept
  - access control
draft: false
---

## Deskripsi
**Authorization** (Otorisasi) adalah proses menetapkan hak akses atau hak istimewa setelah identitas pengguna berhasil diverifikasi (melalui [[login]]/autentikasi). Meskipun proses Autentikasi memastikan pengguna adalah "siapa yang dia klaim", proses Otorisasi menentukan "apa yang boleh dilakukan" oleh pengguna tersebut (misalnya, membaca file tertentu, memodifikasi data, atau mengakses halaman admin).

## Kerentanan Umum
Kerentanan pada fase otorisasi umumnya disebut **Broken Access Control**, contohnya:
*   **IDOR (Insecure Direct Object Reference):** Mengakses data milik pengguna lain hanya dengan mengubah ID pada parameter.
*   **Privilege Escalation:** Mendapatkan akses level yang lebih tinggi secara tidak sah (misalnya user biasa mengakses fungsi admin).
*   **Inconsistent Logic:** Seperti pada kasus perbedaan _collation_ database (*COLLATE NOCASE*) dan verifikasi level kode aplikasi.
