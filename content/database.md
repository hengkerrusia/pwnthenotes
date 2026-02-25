---
title: Database
description: Penjelasan mengenai sistem Basis Data
tags:
  - technology
  - concept
draft: false
---

## Deskripsi
**Database** (Basis Data) adalah koleksi sistematis dari data atau informasi yang terstruktur sehingga mudah untuk diakses, dikelola, dan diperbarui. *Database* modern sangat vital bagi fungsionalitas aplikasi dinamis karena menyediakan penampungan persisten.

Pendekatan populer adalah **Relational Database Management System (RDBMS)**, seperti MySQL, PostgreSQL, dan SQLite yang menuturkan perintah dengan bahasa SQL. Ada pula jenis NoSQL (seperti MongoDB atau Redis) yang menampung data tanpa skema terstruktur hierarkis.

## Risiko Keamanan
Database sering kali menjadi _"crown jewel"_ bagi seorang peretas. Jika tidak disusun dengan arsitektur aman (contohnya penerapan prinsip *Least Privilege*), maka *database* rentan terhadap *Data Breach*.

Serangan umum meliputi SQL Injection, pengambilan rujukan objek langsung (IDOR) yang ceroboh, dan [[mass-assignment]] di mana entitas luar memengaruhi integritas kolom secara acak.
