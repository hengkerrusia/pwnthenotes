---
title: HTTP 302
description: Penjelasan mengenai HTTP Status Code 302 Found
tags:
  - web
  - protocol
draft: false
---

## Deskripsi
**HTTP 302** (Found / Moved Temporarily) adalah salah satu HTTP status code yang menunjukkan bahwa *resource* (halaman web atau data) yang diakses telah dipindahkan untuk sementara waktu ke URL lain. 

Ketika server web mengembalikan kode status 302, server juga akan menyertakan header `Location` yang berisi URL tujuan baru. Secara spesifikasi, ketika browser (*web client*) menerima pesan ini beserta header `Location`, browser akan secara otomatis melakukan _request_ baru (mengalihkan pengguna) ke URL tersebut.

## Relevansi dalam Keamanan
Pada aspek keamanan, terkadang penyerang dapat menahan atau mengabaikan *redirect* ini (menggunakan *proxy* seperti Burp Suite, curl, atau *script* *custom*) untuk:
* Mengeksploitasi kerentanan [[Execution After Redirect]].
* Mengecek respon server terkait *Open Redirect*.
