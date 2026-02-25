---
title: Regular Expression
description: Penjelasan mengenai terminologi Regular Expression
tags:
  - web
  - concept
draft: false
---

## Deskripsi
**Regular Expression** (disebut juga _Regex_ atau _Regexp_) adalah serangkaian karakter yang menetapkan pola atau kriteria pencarian (seperti menemukan dan mengganti atau _find and replace_ di *string* teks). Dalam komputasi modern, *regex* acap dimanfaatkan oleh bahasa pemrograman atau utilitas pemrosesan struktur teks untuk menemukan format sepadan dan validasi data masukan.

## Risiko Keamanan
Walaupun menjadi tulang punggung utilitas pembilasan input (*Sanitization*), kerentanan _Regex_ acap ditelusuri lewat dua pintu kelalaian implementasi:
1.  **Regular Expression Denial of Service (ReDoS):** Konstruksi pencarian reguler berulang (terutama menggunakan pemindah-*backtrack* _Wildcard_ serakah) dapat membutuhkan daya komputasi eksponensial dalam menyusun dan mencocokan rentetan string panjang (*Regex Catastrophic Backtracking*), menyebabkan server melambat tanpa henti.
2.  **Code Injection:** Beberapa bahasa (utamanya versi lampau sistem interpretasi PHP yang mendukung `preg_replace` dengan parameter _switch_ `/e`) memberikan _override feature_ langsung mengeksekusi parameter pengalihan _string_ yang masuk sebagai serangkai operasi pemrograman sah di mata server ([[remote-code-execution]]).
