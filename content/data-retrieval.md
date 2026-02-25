---
title: Data Retrieval
description: Penjelasan mengenai proses pengambilan data
tags:
  - database
  - functionality
draft: false
---

## Deskripsi
**Data Retrieval** (Pengambilan Data) merujuk pada operasi dasar sebuah aplikasi yang digunakan untuk mengambil dan mempresentasikan informasi persisten dari sebuah wadah penyimpanan (umumnya *database*) untuk merespons permintaan klien.

Dalam arsitektur basis data relasional (RDBMS/SQL), operasi *data retrieval* ini diimplementasikan menggunakan perintah `SELECT`.

## Kerentanan Umum
Fungsionalitas atau alur pertukaran informasi pada fase pengambilan data seringkali terbuka untuk celah keamanan, termasuk namun tidak terbatas pada:
*   **SQL Injection:** Terjadi saat _query_ `SELECT` dimanipulasi melalui titik (*endpoint*) parameter dan langsung diinterpretasi oleh mesin *database* seolah itu adalah instruksi yang valid.
*   **IDOR / Broken Access Control:** Aplikasi mengembalikan data bukan berdasarkan ikatan kepemilikannya (tidak dipastikan ke database), namun murni mengandalkan asumsi parameter dari permintaan *client*.
