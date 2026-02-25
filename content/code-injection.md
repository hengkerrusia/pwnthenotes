---
title: Code Injection
description: Penjelasan mengenai kerentanan Code Injection
tags:
  - vulnerability
  - web
  - injection
draft: false
---

## Deskripsi
**Code Injection** adalah jenis kerentanan injeksi yang terjadi saat aplikasi web secara keliru mengeksekusi kode (*code statement*) yang sebagian isinya berasal dari input yang tidak divalidasi. Ini sangat berbeda dengan celah "Command Injection", yang merujuk pada eksekusi perintah sistem operasi pada _shell_ tingkat rendah.

Kerentanan ini biasanya dipicu oleh kurangnya pemilahan (*sanitization*) pada data eksternal yang kemudian diteruskan ke fungsi berbahaya seperti `eval()`, `assert()`, `setTimeout()`, atau `create_function()`.

## Dampak
Dampak paling nyata dari *Code Injection* adalah *Remote Code Execution* ([[remote-code-execution]]), di mana peretas menunggangi bahasa pemrosesan yang rentan (seumpama PHP, Node.js, atau Python) untuk memanipulasi _runtime environment_.

Penyerang dapat mencuri kredensial dalam memori, menghubungkan *reverse shell* ke peladen eksternal, dan mengompromi keseluruhan stabilitas sistem.

## Mitigasi
*   **Hindari fungsi berbahaya:** Jangan pernah menggunakan turunan fungsi tipe `eval()` dalam menerjemahkan logika, kalkulasi, atau data masuk. Fungsi ini acap diajarkan sebagai *anti-pattern* di lingkungan pengembangan yang tidak tepercaya.
*   Gunakan struktur strukturisasi data deklaratif yang ketat, misalnya format JSON untuk opsi parameter atau objek di sisi konfigurasi, alih-alih mencoba menerjemahkan untaian teks ke objek di tengah skrip berjalan.
