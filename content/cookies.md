---
title: Cookies
description: Pengertian, fungsi, dan aspek keamanan HTTP Cookies dalam aplikasi web
tags:
  - cookies
  - session-management
  - web-security
  - http
---

# Cookies

**Cookies** adalah data berukuran kecil yang disimpan browser pengguna dan dikirim kembali ke server bersama setiap HTTP request. Cookies digunakan untuk menjaga state (keadaan) dalam komunikasi HTTP yang bersifat stateless.

## Fungsi Utama

| Fungsi | Deskripsi |
|--------|-----------|
| **Session Management** | Menyimpan status login pengguna (session ID) |
| **Personalization** | Menyimpan preferensi pengguna (bahasa, tema) |
| **Tracking** | Melacak perilaku pengguna untuk analitik atau iklan |

## Atribut Keamanan

```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
```

- **`HttpOnly`**: Mencegah akses cookie via JavaScript (mitigasi XSS)
- **`Secure`**: Cookie hanya dikirim melalui HTTPS
- **`SameSite`**: Mencegah pengiriman cookie dalam request cross-site (CSRF protection)
  - `Strict`: Paling ketat, tidak dikirim saat navigasi eksternal
  - `Lax`: Dikirim untuk GET request navigasi top-level
  - `None`: Tidak ada pembatasan (wajib pakai Secure)
- **`Path`**: Batasan scope cookie pada direktori tertentu
- **`Max-Age/Expires`**: Masa berlaku cookie

## Kerentanan Umum

- **Session Hijacking**: Pencurian session cookie via XSS atau sniffing
- **Session Fixation**: Memaksa pengguna menggunakan session ID yang diketahui penyerang
- **Cookie Tossing**: Overwriting cookie dengan atribut path yang lemah
- **Insecure Transmission**: Cookie dikirim tanpa enkripsi (tidak ada flag Secure)

## Best Practices

1. Selalu gunakan flag `HttpOnly` dan `Secure`
2. Implementasi `SameSite=Lax` atau `SameSite=Strict`
3. Gunakan prefix `__Host-` untuk cookie penting
4. Rotasi session ID setelah autentikasi berhasil
5. Implementasi expiry time yang sesuai
