---
title: Login
description: Penjelasan mengenai fungsionalitas Login
tags:
  - functionality
  - web
  - authentication
draft: false
---

## Deskripsi
**Login** (Autentikasi) adalah proses atau fungsionalitas di mana sistem memverifikasi identitas pengguna, umumnya menggunakan kombinasi username dan password, atau metode lain seperti OTP, biometrik, atau OAuth.

## Potensi Kerentanan
*   **Credential Stuffing / Brute Force:** Mencoba ribuan kombinasi password jika tidak ada batasan percobaan (*rate limiting*).
*   **SQL Injection:** Terjadi saat input username/password dimasukkan langsung ke dalam query database tanpa sanitasi.
*   **Session Fixation:** Penyerang memberikan ID sesi miliknya kepada korban untuk digunakan saat login.
*   **Insecure Cookies:** Sistem menggunakan [[cookies]] yang tidak dikonfigurasi dengan aman (misalnya tanpa flag `HttpOnly` atau `Secure`).
