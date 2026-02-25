---
title: IDOR
description: Penjelasan mengenai Insecure Direct Object Reference (IDOR)
tags:
  - vulnerability
  - web
  - access control
draft: false
---

## Deskripsi
**Insecure Direct Object Reference (IDOR)** adalah jenis kerentanan [*Broken Access Control*](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) yang terjadi ketika sebuah aplikasi mengekspos referensi langsung ke objek internal (berupa parameter ID pada URL, *hidden field* di dalam *form*, atau parameter JSON) tanpa disertai adanya kontrol akses atau validasi kepemilikan.

Sebagai contoh, pengguna dengan *user ID* `100` dapat mengubah parameter URL `/profile?user=100` menjadi `/profile?user=101` dan mendapatkan akses penuh ke profil pengguna bernomor urut `101` tersebut, meskipun bukan miliknya.

## Dampak
Dampak dari IDOR bisa dibilang sangat mematikan. Bergantung pada konteks fungsinya, penyerang bisa:
* **Information Disclosure:** Membaca data sensitif pengguna (seperti kartu kredit atau alamat tagihan).
* **Data Manipulation:** Memodifikasi detail pesanan, *password*, atau menghapus riwayat kesehatan.
* **Account Takeover:** Mengubah alamat *email* pada profil akun orang lain.

## Mitigasi
*   **Access Control Checks:** Berikan aturan [[authorization]] yang secara mutlak memverifikasi bahwa *user* peminta harus memiliki hak (berdasarkan ID Sesi terkait) sebelum memberikan objek.
*   **Indirect References:** Hindari pengiriman ID *database auto-increment*. Gunakan ID acak (*UUID* atau nilai kriptografis) yang tidak dapat diprediksi sebagai pengenal kepada klien.
