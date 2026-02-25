---
title: WAF Bypass
description: Penjelasan mengenai terminologi WAF Bypass
tags:
  - web
  - security concept
  - attack vector
draft: false
---

## Deskripsi
**WAF Bypass** (atau Penghindaran WAF) adalah kumpulan teknik dan metodologi yang dimanfaatkan oleh peretas (ataupun konsultan keamanan ketika menguji penetrasi) untuk menyelundupkan muatan peladen jahat (_Milicious Payload_) tanpa terdeteksi atau diblokir oleh alat pelindung _Web Application Firewall_ ([[web-application-firewall]]).

WAF secara umum sangat baik dalam mengenali pola _default_ eksploitasi statis yang terekam pada daftar mereka, namun tak jarang kebingungan saat berhadapan dengan modifikasi tata bahasa non-standar yang masih bersifat valid bagi prosesor aplikasi sasaran (_Server Evaluator_).

## Metode Penghindaran Umum
Penyerang tidak mencoba menyasar letak "cacat" atau mengeksploitasi cacat perisian bawaan _Firewall_ melainkan menggunakan taktik obfuskasi data:
1. **Encoding (Penyandian):** Jika _Firewall_ memblokir frasa `/etc/passwd` atau spasi (`%20`), peretas menyusupkan representasi nilainya melintasi bentuk skema Enkoding Unicode, HTML Enitity (`&#x2f;`), sampai padanan karakter URL Encode ganda (*Double URL Encoding*). Metode *Base64* lazim dimanfaatkan dalam sistem eksekusi sekunder.
2. **Karakter Wildcard / Globbing:** Menghindari sistem blokir nama utilitas linux dengan modifikasi `*` atau `?` (*contoh:* `/bin/c?t /e*c/pas*wd`).
3. **Pemisahan String (String Concatenation):** Karena WAF menyaring nilai mentah, nilai ini diubah format pemecah-susun menggunakan kutip pengantinya ke penggabungan (*contoh pada SQL*: `S`||`E`||`L`||`E`||`C`||`T` atau `'sys'.'tem'()` di dalam PHP).
