---
title: Input Validation
description: Penjelasan mengenai proses validasi masukan
tags:
  - security concept
  - defense
draft: false
---

## Deskripsi
**Input Validation** (Validasi Masukan) merujuk pada skema standar perlindungan aplikasi web untuk mengevaluasi data masukan ke sistem perangkat lunak untuk memastikan bahwa isinya layak untuk diproses dari kacamata batasan fungsional logis, sintaksis yang benar, serta memenuhi kaidah model aplikasi itu sendiri.

Validasi pada level ini memastikan input berada di parameter panjang (*length*), rentang nilai (*range*), format yang aman (seperti *Regular Expression* pada *email*), dan set karakter yang ditentukan sebelumnya.

## Pendekatan
Validasi yang kuat sangat krusial dalam melawan berbagai ancaman yang berhubungan dengan kerentanan tipe *Injection* (misal SQLi, XSS, dan [[code-injection]]).

Terdapat dua pendekatan yang disarankan saat melakukan _input boundary design_:
1. **Allowlisting (Positive Validation):** Mengizinkan hanya set data dari pola terbatas yang telah ditunjuk dan dipastikan aman. Diunggulkan karena merupakan arsitektur pencegahan rekayasa mundur.
2. **Denylisting (Negative Validation):** Membuang atau mensanitasi karakter dan tipe yang dikategorikan *malicious* (buruk eksistensinya). Cenderung lemah karena penyerang umumnya merubah pendekatan *bypass* ke permutasi lain, yang melangkaui deteksi negatif sempit ini.
