---
title: Execution After Redirect
description: Penjelasan tentang kerentanan Execution After Redirect (EAR)
tags:
  - vulnerability
  - web
  - PHP
draft: false
---

## Deskripsi
**Execution After Redirect (EAR)** adalah jenis kerentanan web di mana sebuah aplikasi gagal menghentikan eksekusi kode (sisa skrip) setelah menginstruksikan browser (pengguna) untuk melakukan pengalihan (redirect) ke halaman lain.

Hal ini sering terjadi pada bahasa pemrograman seperti PHP, di mana pemanggilan fungsi seperti `header("Location: ...")` hanya akan menyematkan header HTTP pada respons, namun tidak menghentikan jalannya eksekusi baris kode berikutnya.

## Dampak
Jika kode setelah perintah *header redirect* berisi proses pengambilan data rahasia atau modifikasi database, maka penyerang dapat:
1. Membaca informasi sensitif yang seharusnya tidak dapat diakses tanpa login.
2. Mengeksekusi fungsionalitas admin secara paksa hanya dengan mengabaikan perintah *redirect* dari sisi *client*.

## Mitigasi
Selalu gunakan fungsi untuk mengakhiri eksekusi dengan segera setelah memanggil perintah redirect. Di lingkungan PHP, gunakan `exit;` atau `die();`.

```php
// CONTOH RENTAN
if (!is_logged_in()) {
    header("Location: login.php");
}
show_secret_data();

// CONTOH AMAN
if (!is_logged_in()) {
    header("Location: login.php");
    exit(); // Skrip berhenti di sini
}
show_secret_data();
```
