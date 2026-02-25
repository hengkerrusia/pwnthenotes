---
title: Data Modification
description: Penjelasan mengenai proses modifikasi data dan risikonya
tags:
  - database
  - functionality
draft: false
---

## Deskripsi
**Data Modification** (Modifikasi Data) merujuk pada proses menambah, mengubah, atau menghapus data yang tersimpan secara persisten dalam sebuah aplikasi.

Dalam konteks *database* SQL, aktivitas ini umumnya berkorespondensi dengan manipulasi instruksi `INSERT`, `UPDATE`, dan `DELETE`.

## Risiko Keamanan
Karena operasi ini melibatkan perubahan lanskap sistem informasi, kerentanan yang muncul bisa berdampak serius:
*   **Insecure Direct Object Reference (IDOR):** Memungkinkan pengguna mengubah baris spesifik di *database* yang bukan miliknya dengan memanipulasi *query parameter* (seperti `id=123`).
*   **SQL Injection:** Memungkinkan penyerang menghapus seluruh isi tabel atau mendapatkan data di luar parameter yang disetujui.
*   **Mass Assignment:** Menambahkan *field* pada permintaan yang seharusnya tidak boleh diubah, misalnya mengubah nilai `is_admin=true` pada proses [*update profile*](https://en.wikipedia.org/wiki/Mass_assignment_vulnerability).

## Mitigasi
*   Pastikan pengecekan otorisasi ([`authorization`](/authorization)) dilakukan **setiap saat** sebuah operasi `UPDATE` / `DELETE` diminta dari *client*.
*   Memonitor setiap perubahan (*audit trail*) dan menggunakan *parameterized queries* untuk mencegah eksekusi *database* secara *raw*.
