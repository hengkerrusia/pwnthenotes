---
title: Web Application Firewall (WAF)
description: Penjelasan mengenai Web Application Firewall (WAF)
tags:
  - web
  - security concept
  - defense
draft: false
---

## Deskripsi
**Web Application Firewall (WAF)** adalah garis pertahanan yang bertugas menyaring, memonitor, dan memblokir pergerakan lalu-lintas data web (_HTTP traffic_) dari dan ke sebuah layanan web. WAF secara tipikal digunakan untuk melindungi situs-situs krusial dari malapetaka pencurian data atau eksploitasi lapis aplikasi (OSI Layer 7).

## Mekanisme
1. **Signature-Based Validation:** WAF melacak pola perlintasan _bytes_ ke peladen dan mencocokkannya dengan templat identitas virus/eksploit (_signatures_) yang dikumpulkan sebelumnya (seumpama pola karakter `<script>alert(1)</script>` pada XSS). Kekurangannya mudah dikecoh jika pihak jahat dapat merangkai parameter sandi komputasional (contoh komando rahasia berbasis Enkoding Base64).
2. **Behavioral Analysis:** WAF mengevaluasi tingkah laku peretas dari kebiasaan pola normal, yang membuatnya piawai menangkal iterasi otomatis (seperti ancaman kerentanan *Brute Force* dan *DDoS L7*).

WAF sangat esensial sebagai benteng peretasan sementara selagi perancang aplikasi memperbaiki logika kode di basis peladen secara internal (misalnya menerapkan metode [[input-validation]]).
