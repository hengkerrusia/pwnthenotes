---
title: Authentication
description: Penjelasan mengenai proses Authentication
tags:
  - security concept
  - identity
draft: false
---

## Deskripsi
**Authentication** (Autentikasi) adalah proses untuk memverifikasi entitas (seseorang atau perangkat) dan memastikan bahwa mereka adalah "orang yang mereka klaim". Dalam sistem komputasi, contoh paling nyata dari proses ini adalah saat memasukkan _username_ dan _password_ selama [[login]].

Autentikasi berbeda dengan [[authorization]] (Otorisasi). Autentikasi berfokus pada **"Siapa Anda?"**, sedangkan Otorisasi berfokus pada **"Apa yang boleh Anda lakukan?"**.

## Metode Umum
*   **Something you know:** Kata sandi (password), PIN.
*   **Something you have:** Smart card, token OTP, handphone.
*   **Something you are:** Sidik jari, pengenalan wajah (biometrik).

## Kerentanan Umum
Kegagalan dalam mengimplementasi autentikasi sering dilabeli dengan kategori *Broken Authentication*. Contoh masalah yang sering muncul:
* Validasi sesi (Session Management) yang buruk.
* Tidak adamya batasan pecobaan *login* (*Brute force*).
* Menyimpan *password* dalam wujud teks biasa (plaintext) di *database*.
