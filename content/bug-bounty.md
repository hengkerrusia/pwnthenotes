---
title: Bug Bounty
description: Program bug bounty, cara kerja, dan platform populer untuk peneliti keamanan
tags:
  - bug-bounty
  - security-research
  - vulnerability-disclosure
---

# Bug Bounty

**Bug Bounty** adalah program yang ditawarkan perusahaan atau organisasi kepada peneliti keamanan eksternal (hacker topi putih) untuk menemukan dan melaporkan kerentanan keamanan. Sebagai imbalannya, peneliti menerima hadiah berupa uang (bounty) berdasarkan tingkat keparahan bug.

## Cara Kerja

1. **Scope Definition**: Perusahaan menentukan target dan batasan (domain, aplikasi, fitur)
2. **Testing**: Peneliti mencari kerentanan sesuai aturan yang berlaku
3. **Report Submission**: Temuan dilaporkan melalui platform atau email resmi
4. **Validation**: Tim keamanan memvalidasi dan mereproduksi bug
5. **Fix & Payout**: Perusahaan memperbaiki bug dan membayar bounty

## Tingkat Severity & Reward

| Severity | Contoh Kerentanan | Range Bounty (USD) |
|----------|-------------------|-------------------|
| Critical | RCE, SQLi, ATO massal | $5,000 - $50,000+ |
| High | XSS stored, IDOR sensitif | $1,000 - $5,000 |
| Medium | XSS reflected, CSRF | $300 - $1,000 |
| Low | Information Disclosure | $100 - $500 |

## Platform Populer

- **HackerOne**: Platform bug bounty terbesar dengan klien enterprise
- **Bugcrowd**: Crowdsourced security testing dan bug bounty
- **Intigriti**: Platform Eropa dengan fokus pada GDPR compliance
- **YesWeHack**: Platform global dengan komunitas aktif di Asia

## Etika & Aturan

- **Do**: Patuhi scope program, laporkan secara pribadi, beri waktu patch
- **Don't**: Eksploitasi data pengguna, DoS attack, social engineering
- **Responsible Disclosure**: Jangan publikasikan sebelum fix tersedia

## Tips Sukses

- Pahami teknologi stack target dengan baik
- Automatisasi reconnaissance dan scanning
- Fokus pada fitur baru atau yang jarang diteliti
- Dokumentasi report yang jelas dengan POC

## Contoh Bug Bounty Terkenal

- **Google VRP**: $100,000+ untuk RCE di Pixel
- **Facebook**: $40,000 untuk Account Takeover
- **Apple**: $100,000+ untuk iCloud breach
