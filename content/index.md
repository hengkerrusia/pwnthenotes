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
| [SQL Injection](injection/sql-injection.md) | Vektor mutasi SQL injection dan taksonomi bypass filter |
| [NoSQL Injection](injection/nosql-injection.md) | Operator NoSQL injection, variasi sintaks, dan blind extraction |
| [Command Injection](injection/command-injection.md) | Chaining OS command injection, penghindaran filter, dan mutasi spesifik shell |
| [XSS](injection/xss.md) | Payload Cross-Site Scripting yang bergantung pada konteks dan bypass filter |
| [SSTI](injection/SSTI.md) | Server-Side Template Injection di berbagai template engine |
| [EL Injection](injection/el-injection.md) | Expression Language injection dalam ekosistem Java EE / Spring |
| [XXE](injection/xxe.md) | XML External Entity injection, eksfiltrasi OOB, dan diferensial parser |
| [LDAP / XPath Injection](injection/ldap-xpath.md) | Taksonomi mutasi query injection pada LDAP dan XPath |
| [Prototype Pollution](injection/prototype-pollution.md) | Vektor JavaScript prototype chain pollution dan gadget chains |
| [GraphQL](injection/graphql.md) | Penyalahgunaan introspeksi GraphQL, batching attacks, dan vektor injeksi |
| [LaTeX Injection](injection/latex-injection.md) | Vektor mutasi LaTeX injection dan eksploitasi pemrosesan dokumen |
| [Protocol-Level Injection](injection/protocol-level-injection.md) | Injeksi tingkat protokol pada SMTP, LDAP, dan protokol wire lainnya |
| [SSI / ESI / XSLT Injection](injection/ssi-esi-xslt-injection.md) | Injeksi Server-Side Includes, Edge Side Includes, dan XSLT untuk RCE |
| [ORM Misuse → SQL Injection](injection/orm-misue-sql-injection.md) | Penyalahgunaan fungsi query ORM yang menyebabkan SQL injection |
| [CSV Formula Injection](injection/csv-formula-injection.md) | Injeksi formula spreadsheet melalui fungsionalitas ekspor CSV/Excel |
| [CSS Injection](injection/css-injection.md) | Eksfiltrasi data berbasis CSS dan serangan style injection |
