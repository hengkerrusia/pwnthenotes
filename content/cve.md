---
title: CVE
description: Common Vulnerabilities and Exposures - sistem standar untuk identifikasi kerentanan keamanan
tags:
  - cve
  - vulnerability
  - security-standards
---

# CVE (Common Vulnerabilities and Exposures)

**CVE** adalah sistem standar internasional untuk mengidentifikasi dan menamai kerentanan keamanan secara unik. Setiap kerentanan yang terdaftar mendapatkan ID CVE yang bersifat universal, memudahkan komunikasi dan pelacakan antar organisme keamanan.

## Format CVE ID

```
CVE-YYYY-NNNNN
```

- **CVE**: Prefix standar
- **YYYY**: Tahun publikasi/pendaftaran
- **NNNNN**: Nomor unik (4-5 digit, bisa lebih untuk tahun aktif)

Contoh: `CVE-2021-44228` (Log4Shell), `CVE-2017-0144` (EternalBlue)

## Proses Assignment

1. **Discovery**: Kerentanan ditemukan dan diverifikasi
2. **Request**: Vendor atau peneliti mengajukan ke CVE Numbering Authority (CNA)
3. **Assignment**: CNA memberikan ID CVE reserved
4. **Publication**: CVE dipublikasikan setelah patch tersedia atau sesuai timeline

## Tingkat Severity (CVSS)

| Skor | Severity | Deskripsi |
|------|----------|-----------|
| 0.0 | None | Tidak berdampak |
| 0.1 - 3.9 | Low | Dampak minimal |
| 4.0 - 6.9 | Medium | Dampak moderat |
| 7.0 - 8.9 | High | Dampak serius |
| 9.0 - 10.0 | Critical | Dampak sangat kritis |

## CVE vs Exploit

| Aspek | CVE | Exploit |
|-------|-----|---------|
| Definisi | Identifikasi kerentanan | Kode/teknik untuk memanfaatkan kerentanan |
| Tujuan | Dokumentasi & tracking | Eksploitasi aktif |
| Ketersediaan | Publik | Bisa private atau public |

## CVE Terkenal dalam Sejarah

- **CVE-2014-0160** (Heartbleed): OpenSSL memory leak, memengaruhi 17% server HTTPS
- **CVE-2017-0144** (EternalBlue): SMB vulnerability, digunakan WannaCry ransomware
- **CVE-2021-44228** (Log4Shell): RCE di Log4j, skala pengaruh massive
- **CVE-2023-38408** (OpenSSH): Terrapin attack pada enkripsi SSH

## Database CVE

- **NVD (National Vulnerability Database)**: Database CVE utama oleh NIST
- **MITRE CVE**: Sumber resmi CVE list
- **VulDB**: Database komersial dengan detail eksploitasi
