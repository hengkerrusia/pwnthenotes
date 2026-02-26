---
title: Pwn The Notes
description: Perpustakaan Pengetahuan Kerentanan Keamanan Web — Taksonomi Mutasi & Referensi Permukaan Serangan
---

## Apa neh?
**Pwn The Notes** adalah perpustakaan pengetahuan kerentanan keamanan web yang secara sistematis mengklasifikasikan lebih dari 100 kelas kerentanan web ke dalam 13 kategori. Berbeda dengan daftar cheat sheet konvensional atau daftar CVE, setiap topik disusun berdasarkan kriteria mutasi struktural — apa yang dimutasi, ketidaksesuaian apa yang dihasilkan, dan di mana hal tersebut dimanfaatkan sebagai serangan.

Setiap topik merupakan dokumen referensi yang terstruktur secara mendalam, mencakup seluruh permukaan serangan dari suatu kelas kerentanan melalui taksonomi tiga sumbu (Target Mutasi, Jenis Ketidaksesuaian/Bypass, Skenario Serangan).

## Topik

### Injection

| Kategori | Deskripsi |
| --- | --- |
| [SQL Injection](sql-injection.md) | Vektor mutasi injeksi SQL dan taksonomi bypass filter |
| [NoSQL Injection](nosql-injection.md) | injeksi NoSQL operator, variasi sintaksis, dan ekstraksi buta |
| [Command Injection](command-injection.md) | vektor mutasi injeksi command dan taksonomi bypass filter |
| [XSS](xss.md) | vektor mutasi injeksi XSS dan taksonomi bypass filter |
