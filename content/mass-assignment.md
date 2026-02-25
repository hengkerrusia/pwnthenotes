---
title: Mass Assignment
description: Penjelasan tentang kerentanan Mass Assignment
tags:
  - vulnerability
  - web
draft: false
---

## Deskripsi
**Mass Assignment** (atau terkadang disebut *Auto-Binding* atau *Object Injection*) adalah sebuah kerentanan perancangan *software* di mana aplikasi bisnis (umumnya kerangka kerja berbasis MVC/ORM) menerima sekumpulan data input dari eksternal dan secara otomatis mengikatkan (*bind*) keseluruhan struktur data tersebut ke *model* internal atau objek *database*.

Kerentanan terjadi ketika *framework* menyimpan nilai atribut tambahan yang dikirimkan klien yang sebenarnya tidak diniatkan untuk diubah.

## Dampak
Jika skema objek yang direferensikan mengandung atribut-atribut bernilai sensitif—seperti status aktif, status pembayaran, atau level admin—penyerang bisa mengubahnya lewat permintaan (*request*) HTTP yang dimodifikasi. Kasus klasik eksploitasi fitur ini adalah melakukan *Privilege Escalation* (Peningkatan Hak Akses).

## Mitigasi
*   **Whitelisting Model:** Selalu definisikan daftar eksplisit berisi properti apa saja yang diizinkan untuk di-*bind* dari masukkan klien (contoh: di Rails gunakan `strong_parameters`, di Laravel gunakan `$fillable`).
*   **Data Transfer Object (DTO):** Gunakan objek perantara khusus untuk mengurai pesanan dari *client*, menyingkirkan atribut berbahaya, dan lalu meneruskan data spesifik baru ke entitas basis data.
