---
title: Remote Code Execution (RCE)
description: Penjelasan mengenai Remote Code Execution (RCE)
tags:
  - vulnerability
  - critical
  - exploit
draft: false
---

## Deskripsi
**Remote Code Execution (RCE)** adalah level eksploitasi mutlak di mana agen ancaman (atau entitas penyerang) dapat menjalankan *code* sembarang atau perintah tingkat sistem pada peladen target dari jarak jauh, biasanya melalui _Internet_ atau koneksi lintas piranti dalam satu jaringan lokal.

RCE tidak merujuk pada spesifik satu buah kecacatan fungsi bawaan, melainkan suatu **simtom tingkat akhir** (*end-state impact*) dari bermacam-macam tipe masalah, seperti kelemahan [[code-injection]], _Command Injection_, celah _Memory Corruption_ (contohnya *Buffer Overflow* pada kernel Apache), atau deserialisasi objek tepercaya (*Insecure Deserialization*).

## Dampak
RCE adalah vonis hukuman cacat arsitektur keamanan dengan ganjaran skor CVSS dasar tertinggi (seputaran 9.8-10.0 tingkat "Kritis"). Implikasinya mencakup, tapi tak melulu meliputi:
* Menitikkan tatanan dominasi bot jaringan (*Ransomware/DDoS Botnet node*).
* Melakuan transisi ke eskalasi previlese lokal secara paksa ([[privilege-escalation]]).
* Kehilangan data pelanggan tak terkira jumlahnya (*Data breach* skala masif).

## Mitigasi
Karena sumber permasalahannya bukan satu-dimensi, upaya menanggulangi ancaman berakar di lapisan arsitektur dengan menggunakan prasyarat *Secure Coding Standards*, implementasi *Web Application Firewall* (WAF) sebagai lapis pertahanan semantik, memutakhirkan pembaruan perangkat lunak reguler, serta menggunakan *sandbox* isolatif atau Container (seperti Docker) sebagai jala pengaman.
