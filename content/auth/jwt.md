---
title: JWT
---

## Struktur Klasifikasi

Taksonomi ini mengorganisasi seluruh permukaan serangan JWT berdasarkan tiga sumbu ortogonal yang diturunkan dari analisis sistematis CVE, penelitian akademik, laporan bug bounty, dan tulisan praktisi hingga tahun 2025.

**Sumbu 1 — Target Mutasi (Utama):** Komponen struktural JWT yang dimanipulasi. JWT terdiri dari tiga segmen (Header, Payload, Signature) ditambah ekosistem manajemen kunci, transport, dan mekanisme lifecycle. Setiap kategori tingkat atas menargetkan komponen struktural yang berbeda — kolom algoritma, parameter header untuk resolusi kunci, tanda tangan kriptografis itu sendiri, claim payload, infrastruktur manajemen kunci, transport/penyimpanan token, atau lifecycle tingkat protokol.

**Sumbu 2 — Jenis Ketidaksesuaian (Lintas-Bidang):** Sifat pelanggaran keamanan yang diciptakan oleh setiap mutasi. Jenis ketidaksesuaian ini memotong semua kategori dan menjelaskan *mengapa* setiap mutasi berhasil:

| Jenis Ketidaksesuaian   | Deskripsi                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------------ |
| **Signature Bypass**    | Pemeriksaan integritas token sepenuhnya dihindari                                                |
| **Key Confusion**       | Verifier menggunakan kunci atau jenis kunci yang berbeda dari yang dimaksudkan                   |
| **Validation Gap**      | Pemeriksaan yang diperlukan (claim, parameter, batasan) tidak ada atau tidak lengkap             |
| **Injection**           | Data yang dikontrol penyerang mencapai interpreter yang tidak dimaksudkan (SQL, filesystem, URL) |
| **Cryptographic Flaw**  | Kelemahan matematis atau implementasi dalam algoritma penandatanganan/verifikasi                 |
| **Type Confusion**      | Verifier memproses token sebagai jenis yang berbeda (JWS vs. JWE) dari yang dimaksudkan          |
| **Resource Exhaustion** | Parameter yang dikontrol penyerang memaksa komputasi berlebihan sebelum autentikasi              |
| **Lifecycle Abuse**     | Mengeksploitasi sifat stateless JWT atau asumsi berbasis waktu                                   |

**Sumbu 3 — Skenario Serangan (Pemetaan):** Konteks dampak dunia nyata — bypass autentikasi, eskalasi hak istimewa, pengambilalihan akun, relay token lintas-layanan, SSRF, RCE, DoS, atau eksfiltrasi data. Ini dipetakan dalam bagian Pemetaan Skenario Serangan (§8).

### Mekanisme Fundamental

JWT adalah format token yang ringkas dan URL-safe yang didefinisikan dalam RFC 7519, terdiri dari tiga segmen yang di-encode Base64URL dan dipisahkan oleh titik: `Header.Payload.Signature`. Header menyatakan algoritma penandatanganan (`alg`) dan parameter opsional resolusi kunci (`kid`, `jku`, `jwk`, `x5u`, `x5c`). Payload berisi claim (issuer, subject, audience, expiration, data kustom). Signature dihitung atas `Base64URL(Header).Base64URL(Payload)` menggunakan algoritma dan kunci yang ditentukan. Verifikasi mengharuskan penerima untuk: (1) mengurai header, (2) me-resolve kunci yang benar, (3) memverifikasi signature, dan (4) memvalidasi claim. Setiap mutasi dalam taksonomi ini mengeksploitasi kegagalan pada satu atau lebih dari empat langkah ini.

---

## §1. Manipulasi Algoritma

Serangan yang memodifikasi atau mengeksploitasi kolom header `alg` untuk menumbangkan verifikasi signature. Ini adalah permukaan serangan JWT yang paling signifikan secara historis.

### §1-1. Bypass Algoritma None

Kolom `alg` diatur ke `"none"` (atau variasinya), yang menginstruksikan verifier untuk melewati pemeriksaan signature sepenuhnya.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **None kanonik** | Atur `alg` ke `"none"` dan hapus segmen signature | Server menerima algoritma yang tidak terdaftar/tidak dibatasi |
| **Variasi huruf besar/kecil** | Gunakan `"None"`, `"NONE"`, `"nOnE"` untuk melewati blocklist yang peka huruf | Pemeriksaan blocklist memeriksa `alg` secara peka huruf besar/kecil, tetapi parser menormalisasi |
| **Preservasi signature kosong** | Atur `alg` ke `"none"` tetapi pertahankan titik akhir (misalnya `header.payload.`) | Parser membutuhkan tiga segmen tetapi tidak menegakkan keberadaan signature |
| **Trik whitespace/encoding** | Sisipkan whitespace, null byte, atau padding Base64 alternatif di sekitar `"none"` | Parser menormalisasi sebelum perbandingan, tetapi blocklist memeriksa nilai mentah |
| **Bypass signature kosong algoritma tidak dikenal** | Atur `alg` ke nilai sembarang yang tidak didukung (misalnya `"zzz"`, `"foo"`). Fungsi komputasi signature library mengembalikan string kosong untuk algoritma yang tidak dikenal alih-alih memunculkan error. Penyerang menyediakan segmen signature kosong (titik akhir). Verifikasi membandingkan `"" == ""` dan lolos — jalur kode yang berbeda dari handler `none`, yang secara eksplisit melewati verifikasi (CVE-2026-23993) | Library mengembalikan nilai kosong/default dari komputasi signature untuk algoritma yang tidak dikenal; perbandingan signature tidak menolak nilai kosong |

**Contoh payload:**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.
```

### §1-2. Algorithm Confusion (Key Confusion)

Penyerang mengubah algoritma dari asimetris (RSA/ECDSA) ke simetris (HMAC), menyebabkan verifier memperlakukan kunci publik sebagai secret HMAC.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Kebingungan RS256→HS256** | Ubah `alg` dari `RS256` ke `HS256`; tandatangani dengan kunci publik [[RSA]] sebagai secret [[HMAC]] | Server memilih algoritma dari header token; kunci publik dapat diperoleh |
| **Kebingungan ES256→HS256** | Prinsip yang sama diterapkan pada downgrade ECDSA-ke-HMAC | Kunci publik terekspos melalui endpoint JWKS atau sertifikat |
| **Kebingungan PS256→HS256** | Downgrade RSA-PSS ke HMAC | Kondisi yang sama dengan varian RS256 |
| **Derivasi kunci publik** | Ketika kunci publik tidak langsung terekspos, turunkan dari dua token yang telah ditandatangani atau lebih menggunakan pemulihan matematis | Server telah menandatangani ≥2 token dengan kunci RSA yang sama; penyerang mendapatkan keduanya |

Serangan ini berhasil karena verifikasi HMAC menggunakan satu secret bersama, dan jika library menerima algoritma dari header token, ia akan menggunakan kunci publik RSA (nilai yang diketahui) sebagai secret HMAC — nilai yang juga diketahui penyerang.

### §1-3. Downgrade Algoritma

Memaksa penggunaan varian algoritma yang lebih lemah dalam keluarga algoritma yang sama.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Downgrade RS512→RS256** | Beralih ke varian RSA yang lebih lemah dengan persyaratan signature yang lebih pendek | Server mengizinkan fleksibilitas algoritma dalam keluarga RSA |
| **Downgrade ES512→ES256** | Beralih ke kurva ECDSA yang lebih lemah | Server tidak mem-pin kurva/ukuran kunci yang spesifik |
| **Kebingungan EdDSA→ECDSA** | Beralih antara algoritma kurva Edwards dan kurva Weierstrass | Library menangani beberapa keluarga algoritma EC |

---

## §2. Injeksi Parameter Header

Serangan yang mengeksploitasi parameter header JWT yang mengontrol resolusi kunci. Spesifikasi JWT mendefinisikan beberapa parameter header opsional (`kid`, `jku`, `jwk`, `x5u`, `x5c`, `cty`) yang, jika tidak divalidasi dengan benar, menjadi vektor injeksi.

### §2-1. Injeksi Key ID (`kid`)

Parameter `kid` mengidentifikasi kunci mana yang harus digunakan untuk verifikasi. Jika server menggunakan nilai ini dalam kueri database atau operasi filesystem tanpa sanitasi, ia menjadi vektor injeksi.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **SQL injection melalui `kid`** | Nilai `kid` berisi payload SQL (misalnya `' UNION SELECT 'known-secret' --`) yang mengembalikan kunci yang dikontrol penyerang dari database | Server menggunakan `kid` dalam kueri SQL mentah untuk mencari kunci penandatanganan |
| **Path traversal melalui `kid`** | `kid` mengarah ke file yang dapat diprediksi (misalnya `../../../dev/null` atau `../../../proc/self/environ`) | Server membaca materi kunci dari filesystem menggunakan `kid` sebagai path |
| **Kunci null melalui `/dev/null`** | Arahkan `kid` ke `/dev/null` (file kosong); tandatangani token dengan string kosong | Sistem Linux/Unix; server membaca path file dari `kid` |
| **Kunci file yang diketahui** | Arahkan `kid` ke file dengan konten yang diketahui (misalnya `../../../etc/hostname`, file CSS publik) dan gunakan konten tersebut sebagai kunci penandatanganan | File yang dapat diprediksi yang dapat diakses oleh proses server |
| **LDAP injection melalui `kid`** | Nilai `kid` berisi injeksi filter LDAP | Server me-resolve kunci dari direktori LDAP |
| **Command injection melalui `kid`** | Nilai `kid` memicu eksekusi perintah OS (misalnya melalui interpolasi backtick) | Server meneruskan `kid` ke perintah shell atau fungsi eval |

### §2-2. Injeksi JWK Set URL (`jku`)

Header `jku` menentukan URL dari mana server mengambil JSON Web Key Set untuk verifikasi.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **URL `jku` tanpa validasi** | Atur `jku` ke server yang dikontrol penyerang yang meng-hosting JWKS yang dibuat; tandatangani dengan kunci privat yang sesuai | Server mengambil JWKS dari URL apa pun yang ditentukan dalam header |
| **Bypass daftar izin URL** | Gunakan open redirect, DNS rebinding, atau diferensial parser URL untuk melewati daftar izin domain (misalnya `https://trusted.com@evil.com`, `https://trusted.com#@evil.com/jwks`) | Server memvalidasi domain `jku` tetapi rentan terhadap trik parsing URL |
| **Penyalahgunaan `jku` same-origin** | Simpan JWKS yang dibuat di path yang dapat dikontrol pengguna dalam domain tepercaya (misalnya upload file, halaman profil, endpoint API yang mencerminkan JSON) | Server membatasi `jku` ke same-origin tetapi konten pengguna dapat di-hosting pada domain yang sama |
| **SSRF melalui `jku`** | Arahkan `jku` ke layanan internal (`http://169.254.169.254/...`) untuk memicu permintaan sisi server | Server mengikuti `jku` tanpa membatasi ke host eksternal |

### §2-3. Injeksi JWK Tertanam (`jwk`)

Header `jwk` menyematkan kunci publik langsung di dalam token.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Token self-signed** | Hasilkan pasangan kunci RSA/EC milik penyerang; sematkan kunci publik di header `jwk`; tandatangani dengan kunci privat | Server menggunakan `jwk` tertanam untuk verifikasi tanpa memeriksa terhadap key store tepercaya |
| **Pencocokan Key ID** | Atur `kid` dalam `jwk` tertanam agar cocok dengan `kid` yang diketahui di key store tepercaya server, tetapi sediakan materi kunci yang berbeda | Server mencocokkan `kid` tetapi tidak memverifikasi apakah materi kunci cocok dengan kunci tepercaya (CVE-2025-24976) |

### §2-4. Injeksi Parameter Sertifikat X.509 (`x5u`, `x5c`)

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **URL `x5u` tanpa validasi** | Atur `x5u` ke URL yang dikontrol penyerang yang menyajikan sertifikat X.509 yang dibuat | Server mengambil sertifikat dari URL mana pun |
| **Rantai `x5c` self-signed** | Sematkan rantai sertifikat self-signed dalam header `x5c` | Server tidak memvalidasi rantai sertifikat terhadap CA tepercaya |
| **Kebingungan rantai sertifikat** | Berikan sertifikat leaf yang valid yang ditandatangani oleh root yang tidak tepercaya, berharap server hanya memvalidasi leaf | Logika validasi rantai yang tidak lengkap |

### §2-5. Manipulasi Content Type (`cty`)

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Kebingungan nested JWT** | Atur `cty` ke `"JWT"` untuk memicu pemrosesan token bersarang pada token yang tidak bersarang | Server mengikuti `cty` secara buta, memungkinkan double-decoding atau perubahan pemrosesan |
| **Deserialisasi melalui `cty`** | Atur `cty` ke `"application/x-java-serialized-object"` atau `"text/xml"` untuk memicu deserialisasi tidak aman atau pemrosesan XXE pada payload | Server menggunakan `cty` untuk menentukan strategi deserialisasi payload |

---

## §3. Kelemahan Implementasi Kriptografis

Serangan yang menargetkan kelemahan dalam algoritma kriptografis atau implementasinya, terlepas dari manipulasi header.

### §3-1. Eksploitasi Kunci Simetris Lemah

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Brute force berbasis kamus** | Gunakan hashcat (`-m 16500`) atau jwt_tool dengan wordlist yang diketahui (misalnya `jwt.secrets.list`) untuk memecahkan secret HMAC secara offline | Secret HMAC adalah string yang pendek, mudah ditebak, atau umum |
| **Secret default/hardcoded** | Gunakan secret default yang diketahui (`"secret"`, `"password"`, `"changeme"`, `"your-256-bit-secret"`) | Developer meninggalkan secret placeholder di produksi |
| **Cracking berbasis aturan** | Terapkan aturan hashcat (misalnya `best64.rule`) untuk memutasikan entri wordlist dan menemukan secret yang diturunkan dari kata sandi | Secret diturunkan dari kata sandi yang dipilih manusia |
| **Brute force (kunci pendek)** | Brute force karakter demi karakter untuk kunci yang lebih pendek dari 256 bit yang direkomendasikan | Panjang kunci jauh di bawah persyaratan MUST dari RFC 7518 |

Lebih dari 340 secret JWT lemah yang diketahui telah dikatalogkan. Serangan ini sepenuhnya offline — tidak diperlukan interaksi server setelah mendapatkan satu token yang valid.

### §3-2. Kelemahan Implementasi Elliptic Curve

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Psychic Signatures (nilai r,s nol)** | Kirimkan signature ECDSA di mana `r` dan `s` keduanya nol (atau nilai degenerat tertentu); persamaan verifikasi `0 = 0` menjadi trivially true | Java 15–18 dengan provider JCA bawaan (CVE-2022-21449) |
| **Penggunaan ulang nonce ECDSA** | Jika server menandatangani dua token berbeda dengan nonce ECDSA yang sama (`k`), kunci privat dapat dipulihkan secara matematis | Implementasi ECDSA sisi server dengan RNG yang rusak atau kegagalan nonce deterministik |
| **Serangan kurva tidak valid** | Sediakan titik kunci publik pada kurva yang berbeda (lebih lemah); server melakukan operasi pada kurva yang lemah, memungkinkan pemulihan kunci | Library tidak memvalidasi bahwa titik kunci publik berada pada kurva yang diharapkan |
| **Injeksi titik degenerat** | Gunakan titik kurva berorde kecil untuk membocorkan bit kunci privat melalui beberapa interaksi | Library tidak memeriksa orde titik |

### §3-3. Kelemahan Implementasi RSA

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Kunci RSA pendek** | Faktorkan modulus RSA ketika kunci yang lemah/pendek (< 2048 bit) digunakan | Server menggunakan kunci RSA berukuran kecil |
| **Bleichenbacher padding oracle** | Eksploitasi perbedaan validasi padding PKCS#1 v1.5 dalam dekripsi RSA (relevan untuk JWE) | Server menggunakan RSA dengan PKCS#1 v1.5 dan membocorkan validitas padding |
| **e=1 atau eksponen degenerat** | Gunakan kunci RSA dengan eksponen publik `e=1`, membuat pesan apa pun menjadi signature-nya sendiri | Library tidak memvalidasi parameter kunci RSA |

### §3-4. Penyalahgunaan Derivasi Kunci PBES2 (Serangan Billion Hashes)

JWE mendukung enkripsi berbasis kata sandi melalui PBES2 (RFC 7518 §4.8), di mana Content Encryption Key (CEK) diturunkan dari kata sandi menggunakan iterasi PBKDF2. Jumlah iterasi ditentukan dalam parameter header `p2c` (PBES2 Count) — yang dikontrol penyerang dan diproses *sebelum* pemeriksaan autentikasi atau validitas apa pun.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Jumlah iterasi berlebihan** | Atur `p2c` ke nilai integer 32-bit maksimum (2.147.483.647); server harus menyelesaikan semua iterasi PBKDF2 untuk menurunkan CEK sebelum dapat menentukan apakah token valid. Satu token berbahaya dapat menghabiskan waktu CPU selama menit hingga jam. Serangan ini sepenuhnya tanpa autentikasi — tidak diperlukan kredensial valid atau token sebelumnya. | Library mendukung algoritma enkripsi kunci PBES2 (`PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`) dan tidak menegakkan nilai `p2c` maksimum (CVE-2023-51775, CVE-2023-49290) |
| **DoS batch yang diperkuat** | Kirim beberapa token JWE dengan nilai `p2c` tinggi secara paralel, mengalikan kelelahan CPU di seluruh thread/proses worker | Server memproses token JWE dari sumber tanpa autentikasi; tidak ada pembatasan laju pada validasi token |

**Library yang terpengaruh dan perbaikannya:**
- **jose4j** (Java): rentan sebelum 0.9.4 (CVE-2023-51775)
- **go-jose** (Go): diperbaiki di v3.0.2 (CVE-2023-49290)
- **jose2go** (Go): diperbaiki di v1.6.0
- **josekit-rs** (Rust): diperbaiki di v0.8.5

---

## §4. Manipulasi Claim Payload

Serangan yang memodifikasi claim payload JWT untuk mengubah keputusan otorisasi, meningkatkan hak istimewa, atau melewati logika validasi. Ini memerlukan bypass signature (§1–§3) atau mengeksploitasi aplikasi yang memeriksa claim sebelum atau tanpa verifikasi signature penuh.

### §4-1. Manipulasi Identity Claim

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Penggantian `sub` (Subject)** | Ubah claim `sub` ke pengidentifikasi pengguna lain | Aplikasi menggunakan `sub` untuk otorisasi tanpa verifikasi tambahan |
| **Penggantian claim `email`** | Ubah claim `email` ke email pengguna yang ditarget | Aplikasi mempercayai claim email untuk pencarian identitas pengguna |
| **Substitusi ID numerik** | Ubah ID pengguna numerik dalam claim (misalnya `user_id`, `uid`) untuk menargetkan pengguna lain | BOLA/IDOR melalui claim JWT |
| **Kebingungan issuer (`iss`)** | Ubah `iss` ke issuer tepercaya berbeda yang juga diterima aplikasi | Lingkungan multi-IdP di mana issuer berbagi kunci penandatanganan atau validasi longgar |
| **Injeksi array dalam `iss`** | Berikan `iss` sebagai array yang berisi nilai legitimate dan berbahaya (CVE-2025-30144) | Library secara salah menerima array untuk claim bertipe string |

### §4-2. Manipulasi Authorization Claim

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Eskalasi role** | Ubah `role` dari `"user"` ke `"admin"` atau injeksikan `["admin", "user"]` | Aplikasi mengandalkan claim JWT untuk role-based access control |
| **Perluasan scope** | Tambahkan scope OAuth tambahan (misalnya `"read write admin"`) ke claim `scope` | API gateway mempercayai scope JWT tanpa merujuk silang ke server otorisasi |
| **Injeksi permission** | Tambahkan claim permission baru atau modifikasi flag boolean yang ada (misalnya `"is_admin": true`) | Aplikasi menggunakan claim JWT kustom untuk otorisasi yang lebih granular |
| **Manipulasi tenant ID** | Ubah `tenant_id` atau `org_id` untuk mengakses sumber daya tenant lain | Aplikasi multi-tenant dengan isolasi tenant berdasarkan claim JWT |

### §4-3. Manipulasi Temporal Claim

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Penghapusan expiration** | Hapus claim `exp` sepenuhnya, membuat token yang tidak pernah kedaluwarsa | Server tidak menegakkan keberadaan `exp` yang wajib |
| **Perpanjangan expiration** | Atur `exp` ke timestamp jauh di masa depan | Bypass signature tersedia; server mempercayai `exp` dalam token |
| **Bypass `nbf` (Not Before)** | Atur `nbf` ke waktu lampau atau manipulasi waktu sisi klien yang digunakan untuk pembuatan `nbf` | Aplikasi mengandalkan waktu yang disediakan klien untuk `nbf` |
| **Manipulasi `iat` (Issued At)** | Mundurkan atau majukan claim `iat` untuk mengelabui pemeriksaan berbasis usia | Server menggunakan `iat` untuk validasi kesegaran token |

### §4-4. Manipulasi Audience Claim

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Bypass audience (validasi hilang)** | Token tidak memiliki claim `aud` atau server tidak memvalidasinya, memungkinkan penggunaan token lintas-layanan | Validasi audience tidak diterapkan |
| **Kebingungan audience** | Gunakan token yang diterbitkan untuk Layanan A pada Layanan B ketika keduanya menerima issuer yang sama | Layanan berbagi kepercayaan tetapi tidak memvalidasi `aud` secara berbeda (CVE-2024-5798) |
| **Serangan ALBEAST** | Konfigurasikan token untuk tenant AWS milik penyerang sendiri dengan claim audience yang diterima oleh aplikasi korban | Lingkungan multi-tenant AWS tanpa validasi `aud`+penanda yang ketat |

---

## §5. Serangan Infrastruktur Manajemen Kunci

Serangan yang menargetkan infrastruktur yang menyimpan, mendistribusikan, dan merotasi kunci penandatanganan, bukan token itu sendiri.

### §5-1. Eksploitasi Endpoint JWKS

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Pengambilalihan endpoint JWKS** | Dapatkan kendali atas domain atau path yang meng-hosting endpoint JWKS (misalnya domain kedaluwarsa, DNS menggantung) | URL JWKS mengarah ke domain yang dapat didaftarkan atau dikendalikan penyerang |
| **Keracunan JWKS** | Suntikkan kunci publik penyerang ke endpoint JWKS melalui kerentanan aplikasi | Akses tulis ke endpoint JWKS atau backing store-nya |
| **Eksploitasi caching JWKS** | Eksploitasi jendela cache TTL — ganti kunci selama jendela saat server masih mempercayai kunci yang di-cache | Server meng-cache respons JWKS; penyerang dapat memodifikasi endpoint antara pembaruan cache |
| **Manipulasi OIDC discovery** | Modifikasi `.well-known/openid-configuration` untuk mengarah ke endpoint JWKS yang berbeda | Penyerang mengendalikan endpoint OIDC discovery atau dapat mencegat/memodifikasinya |

### §5-2. Kegagalan Rotasi Kunci

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Penerimaan kunci lama** | Eksploitasi server yang terus menerima token yang ditandatangani dengan kunci yang dicabut/dirotasi tanpa batas waktu | Tidak ada penegakan kedaluwarsa kunci |
| **Key rollback** | Tipu server agar kembali ke kunci yang lebih lama (berpotensi dikompromikan) | Pemilihan kunci berdasarkan `kid` tanpa memvalidasi kesegaran kunci |
| **Kebingungan kunci paralel** | Selama rotasi, eksploitasi jendela saat kunci lama dan baru sama-sama valid untuk melewati kontrol yang mengasumsikan operasi kunci tunggal | Logika aplikasi mengasumsikan satu kunci aktif |

### §5-3. Paparan Materi Kunci

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Kunci dalam source code** | Ekstrak secret HMAC dari repositori publik, image Docker, atau JavaScript sisi klien | Developer meng-commit secret ke version control |
| **Kunci dalam konfigurasi** | Ekstrak kunci dari cloud storage yang salah dikonfigurasi (S3 bucket), dump variabel lingkungan, atau pesan error | Praktik deployment yang tidak aman |
| **Kunci melalui side-channel** | Pulihkan materi kunci melalui timing attack pada perbandingan HMAC atau analisis daya pada perangkat tertanam | Fungsi perbandingan yang tidak dilindungi atau akses fisik |

---

## §6. Serangan Transport dan Penyimpanan Token

Serangan yang menargetkan cara JWT ditransmisikan, disimpan, dan dikelola dalam saluran komunikasi klien-server.

### §6-1. Vektor Kebocoran Token

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Kebocoran parameter URL** | JWT diteruskan sebagai parameter query URL, tercatat dalam log server, riwayat browser, dan header Referer | Aplikasi menggunakan JWT dalam URL daripada header Authorization |
| **Kebocoran header Referer** | Token dalam URL bocor ke domain pihak ketiga melalui header HTTP Referer | Sumber daya eksternal dimuat di halaman yang menerima token |
| **Paparan log server** | JWT dicatat dalam access log, error log, atau output debug dalam plaintext | Konfigurasi logging yang verbose |
| **Kebocoran lintas-origin** | Token dapat diakses oleh skrip pihak ketiga melalui DOM (localStorage/sessionStorage) | Kerentanan XSS + penyimpanan token sisi klien |
| **Pencatatan proxy/CDN** | Proxy atau CDN perantara mencatat header Authorization yang berisi JWT | Miskonfigurasi proxy/CDN |

### §6-2. Eksploitasi Penyimpanan Sisi Klien

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **XSS + pencurian localStorage** | Injeksi JavaScript membaca JWT dari `localStorage` atau `sessionStorage` | Token disimpan dalam penyimpanan browser; kerentanan XSS ada |
| **XSS + pencurian cookie** | Curi JWT dari cookie tanpa flag `HttpOnly` | Cookie tidak memiliki `HttpOnly`; kerentanan XSS ada |
| **CSRF dengan JWT berbasis cookie** | Jika JWT ada dalam cookie tanpa perlindungan CSRF, picu permintaan terautentikasi dari browser korban | JWT disimpan dalam cookie; tidak ada CSRF token; `SameSite` tidak diatur |

### §6-3. Token Replay

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Replay sederhana** | Cegat dan gunakan kembali JWT yang valid sebelum kedaluwarsa | Tidak ada perlindungan replay; token dicegat melalui MITM, log, atau kebocoran |
| **Replay lintas-konteks** | Gunakan token yang diperoleh dari satu konteks (misalnya email reset kata sandi) dalam konteks lain (misalnya autentikasi API) | Token tidak terikat ke tindakan atau konteks tertentu |
| **Penyalahgunaan token berumur panjang** | Eksploitasi token dengan kedaluwarsa yang sangat panjang (jam/hari) setelah pengguna telah logout | Tidak ada mekanisme pencabutan sisi server; jendela `exp` yang panjang |

---

## §7. Serangan Tingkat Protokol dan Struktural

Serangan yang mengeksploitasi properti fundamental dari spesifikasi JWT/JOSE atau interaksinya dengan protokol yang lebih luas.

### §7-1. Kebingungan JWS/JWE

JWS (ditandatangani) dan JWE (dienkripsi) berbagi format serialisasi kompak yang sama — segmen Base64URL yang dipisahkan titik — dan RFC 7519 secara eksplisit mengizinkan JWT untuk ditandatangani atau dienkripsi. Library yang menyediakan antarmuka `decode()` terpadu yang menangani kedua format tanpa menegakkan jenis mana yang diharapkan menciptakan permukaan serangan yang kaya di mana batas antara operasi penandatanganan dan enkripsi runtuh.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Kebingungan sign/encrypt (pemalsuan kunci publik)** | Penyerang memperoleh kunci publik RSA/EC (misalnya melalui OIDC `/.well-known/jwks.json`), lalu membuat token JWE yang dienkripsi dengan kunci publik tersebut. Ketika `decode()` terpadu server memproses JWE ini, ia mendekripsi menggunakan kunci privatnya dan menerima payload yang dikontrol penyerang sebagai JWT yang valid — penyerang menetapkan claim sembarang tanpa memerlukan kunci privat penandatanganan. Serangan ini secara fundamental menumbangkan model keamanan: verifikasi JWS membuktikan keaslian (hanya pemegang kunci privat yang dapat menandatangani), tetapi dekripsi JWE hanya membuktikan kerahasiaan (siapa pun dengan kunci publik dapat mengenkripsi). Dengan mengirimkan JWE di mana JWS diharapkan, penyerang mengubah pemeriksaan "bukti identitas" menjadi pemeriksaan "bisakah kamu membaca ini?" — yang bisa dilakukan siapa pun dengan kunci publik. | Library menerima JWS dan JWE melalui jalur decode tunggal; aplikasi menggunakan penandatanganan asimetris (RS*/PS*/ES*); penyerang dapat memperoleh kunci publik; tidak ada penegakan jenis token eksplisit (JWS vs. JWE) (CVE-2022-39174, CVE-2022-3102, CVE-2023-51774) |
| **Token polyglot** | Satu token dibuat agar valid di bawah beberapa interpretasi parsing di berbagai library JWT. Karena JWS (3 segmen yang dipisahkan titik) dan JWE (5 segmen yang dipisahkan titik) berbagi serialisasi kompak yang serupa, dan library berbeda dalam cara mereka mendeteksi dan merutekan jenis token, token yang dibuat dengan cermat dapat menyebabkan satu library memvalidasinya sebagai JWS yang sah sementara library lain memprosesnya sebagai JWE — memungkinkan pemalsuan token lengkap dalam arsitektur multi-library (misalnya gateway memvalidasi JWS, backend memproses JWE). Payload JWE, kunci terenkripsi, IV, dan kolom authentication tag dapat diatur ke urutan byte sembarang dengan panjang yang sesuai, memberikan penyerang kebebasan untuk membuat token yang ambigu tersebut. | Arsitektur multi-komponen yang menggunakan library JWT berbeda untuk validasi vs. konsumsi; library mendeteksi jenis token secara otomatis dari struktur daripada menegakkannya secara eksplisit |
| **Kebingungan jenis encrypted↔signed** | Kirimkan token JWS di mana server mengharapkan JWE, atau sebaliknya, mengeksploitasi jalur parsing dan logika validasi berbeda yang diterapkan pada setiap jenis | Server tidak menegakkan jenis token yang diharapkan melalui pemeriksaan jenis eksplisit atau validasi header `typ` |
| **Penyalahgunaan nested JWT** | Eksploitasi double-encoding atau double-processing ketika server menangani nested JWT (JWS di dalam JWE) | Server memproses token bersarang tanpa pemeriksaan kedalaman/jenis yang tepat |

### §7-2. Eksploitasi Encoding Base64

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Base64URL non-kanonik** | Gunakan representasi Base64 alternatif (padding berbeda, whitespace, jeda baris) yang mendekode ke nilai yang sama tetapi melewati pemeriksaan signature atau aturan WAF | Parser dan verifier menangani Base64 secara berbeda |
| **Injeksi Unicode/encoding** | Suntikkan karakter Unicode atau encoding alternatif dalam nilai claim yang dinormalisasi berbeda di seluruh komponen | Arsitektur multi-komponen dengan parser JSON/string yang berbeda |

### §7-3. Serangan Diferensial Parser

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Diferensial parser JSON** | Eksploitasi perbedaan antara parser JSON (kunci duplikat, koma akhir, komentar, presisi angka) di seluruh komponen yang memproses JWT yang sama | Library parsing JSON yang berbeda antara penerbit token, gateway, dan aplikasi |
| **Penanganan claim duplikat** | Sertakan claim yang sama dua kali dengan nilai berbeda; parser berbeda mengambil kemunculan pertama vs. terakhir | Ketidakkonsistenan parser antara lapisan validasi dan konsumsi |
| **Kelelahan memori melalui token yang cacat** | Kirim token dengan jumlah pemisah titik yang berlebihan, JSON yang sangat bersarang, atau segmen Base64 yang sangat panjang (CVE-2025-27144) | Library mengalokasikan memori sebanding dengan input tanpa pemeriksaan batas |

### §7-4. Eksploitasi Statelessness

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Token yang tidak dapat dicabut** | Eksploitasi ketidakmampuan fundamental untuk mencabut JWT stateless sebelum kedaluwarsa alaminya | Tidak ada daftar hitam token atau daftar pencabutan sisi server |
| **Session fixation melalui JWT** | Perbaiki sesi korban dengan menyuntikkan JWT yang diketahui, mempertahankan akses bahkan setelah tindakan korban | Aplikasi tidak mengikat JWT ke status sesi tambahan |
| **Ketiadaan keunikan `jti`** | Putar ulang token ketika claim `jti` (JWT ID) tidak ada atau server tidak melacak nilai `jti` yang telah digunakan | Tidak ada penegakan `jti`; tidak ada pelacakan sisi server |

---

## §8. Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur / Kondisi | Kategori Mutasi Utama |
|---|---|---|
| **Bypass Autentikasi** | Endpoint mana pun yang dilindungi JWT | §1 (manipulasi alg) + §2 (injeksi header) + §3 (kelemahan kripto) |
| **Eskalasi Hak Istimewa** | Role/izin disimpan dalam claim JWT | §4-2 (claim authz) + bypass signature apa pun (§1–§3) |
| **Pengambilalihan Akun** | Identitas diturunkan dari claim JWT | §4-1 (identity claim) + §6 (kebocoran/replay token) |
| **Relay Token Lintas-Layanan** | Microservices / arsitektur multi-API | §4-4 (bypass audience) + §5-1 (kebingungan JWKS) |
| **Akses Lintas-Tenant** | SaaS / platform cloud multi-tenant | §4-2 (manipulasi tenant ID) + §4-4 (ALBEAST) |
| **SSRF** | Server mengambil sumber daya jarak jauh dari header JWT | §2-2 (injeksi `jku`) + §2-4 (injeksi `x5u`) |
| **Remote Code Execution** | Deserialisasi tidak aman atau command injection | §2-1 (command injection `kid`) + §2-5 (deserialisasi `cty`) |
| **Denial of Service** | Server dengan sumber daya terbatas | §3-2 (kurva tidak valid) + §3-4 (billion hashes PBES2) + §7-3 (kelelahan memori) |
| **Pemalsuan Token melalui Type Confusion** | Penandatanganan asimetris dengan paparan kunci publik (OIDC) | §7-1 (kebingungan sign/encrypt, token polyglot) |
| **Bypass WAF/Gateway** | Appliance keamanan di depan aplikasi | §7-2 (trik encoding) + §1-1 (variasi huruf besar/kecil) |

---

## §9. Pemetaan CVE / Bounty (2022–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|---|---|---|
| §3-2 (Psychic Signatures) | CVE-2022-21449 (Java 15–18) | CVSS 7.5. Bypass signature ECDSA lengkap dengan nilai r,s nol. Mempengaruhi semua library JWT Java yang menggunakan JCA bawaan. |
| §1-1 (Algoritma None) | CVE-2024-48916 (Ceph RadosGW) | Bypass autentikasi. `alg=none` diterima, memungkinkan pemalsuan claim sembarang. |
| §4-4 (Bypass audience) | CVE-2024-5798 (HashiCorp Vault) | Bypass autentikasi. Claim audience JWT tidak divalidasi dengan benar; login tidak valid berhasil. |
| §1-2 (Algorithm confusion) | CVE-2024-54150 | Kebingungan RS256→HS256 yang memungkinkan pemalsuan token dengan kunci publik. |
| §4-1 (Injeksi array issuer) | CVE-2025-30144 (fast-jwt) | Bypass validasi issuer. Array diterima untuk claim `iss`, mencampurkan issuer yang sah dan berbahaya. |
| §7-3 (Kelelahan memori) | CVE-2025-27144 (Go JOSE) | DoS. JWT yang cacat dengan titik berlebihan menyebabkan konsumsi memori eksponensial. |
| §2-3 (Pencocokan Key ID) | CVE-2025-24976 (Distribution registry) | Injeksi kunci. `kid` dicocokkan tetapi materi kunci aktual tidak diverifikasi terhadap store tepercaya. |
| §7-1 (Kebingungan sign/encrypt) | CVE-2022-39174 (authlib/Python) | Bypass autentikasi. Kunci publik yang digunakan untuk verifikasi JWS dieksploitasi untuk memalsukan token JWE melalui antarmuka decode() terpadu. |
| §7-1 (Kebingungan sign/encrypt) | CVE-2022-3102 (jwcrypto/Python) | Bypass autentikasi. Vektor kebingungan sign/encrypt yang sama dengan CVE-2022-39174. |
| §7-1 (Kebingungan sign/encrypt) | CVE-2023-51774 (json-jwt/Ruby) | Bypass pemeriksaan identitas. Gem json-jwt Ruby (< 1.16.6, < 1.15.3.1) rentan terhadap kebingungan sign/encrypt yang memungkinkan pemalsuan claim sembarang. |
| §3-4 (Billion hashes PBES2) | CVE-2023-51775 (jose4j/Java) | DoS. Parameter `p2c` yang tidak dibatasi memungkinkan kelelahan CPU melalui 2^31 iterasi PBKDF2. Diperbaiki di jose4j 0.9.4. |
| §3-4 (Billion hashes PBES2) | CVE-2023-49290 (go-jose/Go) | DoS. Eksploitasi `p2c` PBES2 yang sama. Diperbaiki di go-jose v3.0.2. |
| §1-1 (Algoritma tidak dikenal, signature kosong) | CVE-2026-23993 (HarbourJwt) | Bypass autentikasi. `GetSignature()` mengembalikan string kosong untuk nilai `alg` yang tidak dikenal; perbandingan kosong-vs-kosong lolos verifikasi. |
| §5-1 / §6-3 (Kebocoran token) | Grafana Bug Bounty | Token JWT dalam parameter query bocor ke sumber data backend melalui permintaan yang di-proxy. |
| §6-3 (Replay / pencabutan) | HackerOne #3120790 (WakaTime) | Replay sesi. Token yang telah di-logout tetap valid, memungkinkan akses persisten. |

---

## §10. Alat Deteksi

### Alat Ofensif

| Alat | Cakupan Target | Teknik Utama |
|---|---|---|
| **jwt_tool** (Python) | Pengujian JWT yang komprehensif | 16+ modul serangan: none alg, algorithm confusion, injeksi `kid`, pengubahan claim, brute force, injeksi JWKS |
| **jwtXploiter** | Eksploitasi CVE yang diketahui | Menguji terhadap semua CVE JWT yang diketahui; mengeksploitasi claim header `kid`, `jku`, `x5u` |
| **JWT Security Analyzer** | Pembuatan payload untuk 20+ vektor serangan | Menghasilkan payload serangan untuk CVE-2024-54150, CVE-2025-30144, CVE-2025-4692, dan lainnya |
| **hashcat** (`-m 16500`) | Cracking secret HMAC | Serangan brute force / kamus / berbasis aturan secara offline terhadap secret HS256/HS384/HS512 |
| **jwtfuzz** (Rust) | Fuzzing dan malformasi | Menghasilkan token yang cacat: signature null, algoritma yang ditukar, psychic signatures, kasus tepi encoding |
| **JWTForge** | Pengujian OAuth2/OIDC | Layanan penjualan JWT yang menghasilkan token yang dapat dikustomisasi untuk fuzzing sistem autentikasi |

### Alat Defensif

| Alat | Cakupan Target | Teknik Utama |
|---|---|---|
| **Burp JWT Scanner** (Ekstensi) | Deteksi kerentanan otomatis | Memindai none algorithm, algorithm confusion, secret lemah, injeksi header dalam lalu lintas yang dicegat |
| **JWTLens** | Analisis dan visualisasi token | Mendekode, menganalisis, dan menyoroti masalah keamanan dalam struktur dan claim JWT |
| **OWASP WSTG JWT Tests** | Metodologi pengujian penetrasi | Daftar periksa terstruktur yang mencakup semua vektor serangan JWT untuk penilaian keamanan manual |

### Alat Penelitian

| Alat | Cakupan Target | Teknik Utama |
|---|---|---|
| **jwt.io** | Inspeksi token | Decoder/encoder online untuk analisis cepat struktur JWT |
| **PentesterLab JWT Exercises** | Pelatihan dan pengembangan keterampilan | Lab praktis untuk setiap kelas kerentanan JWT termasuk latihan khusus CVE |
| **hakaioffsec/jwt-vulnerabilities-lab** | Lingkungan praktik | Lab rentan berbasis Docker yang mengimplementasikan jenis kerentanan JWT utama |

---

## §10-1. Paparan JWT BaaS (Backend-as-a-Service)

Platform Backend-as-a-Service (Supabase, Firebase, Appwrite) mengekspos akses database melalui token JWT sisi klien. Tidak seperti arsitektur tradisional di mana kode sisi server menegakkan kontrol akses, platform BaaS menggeser batas keamanan ke kebijakan tingkat database — Row Level Security (RLS) di Supabase/PostgreSQL, Security Rules di Firebase. Ketika kebijakan ini salah dikonfigurasi atau tidak ada, JWT yang tertanam secara publik memberikan akses tanpa batas.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Row Level Security (RLS) yang hilang** | Platform BaaS menyematkan JWT "anon" dalam JavaScript sisi klien (sengaja publik). Keamanan sepenuhnya bergantung pada kebijakan RLS per-tabel. Ketika RLS tidak diaktifkan atau kebijakan tidak dikonfigurasi pada satu atau lebih tabel, JWT anon memberikan akses baca/tulis tanpa batas ke tabel-tabel tersebut — termasuk token autentikasi, token reset kata sandi, PII, dan kredensial | BaaS berbasis Supabase/PostgreSQL; satu atau lebih tabel tanpa `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` atau tanpa kebijakan yang didefinisikan |
| **Paparan Service Role Key** | JWT `service_role` (yang melewati semua RLS) yang bocor melalui kode sisi klien, file `.env` dalam repositori publik, pesan error, atau artefak build memberikan akses database admin penuh yang setara dengan akses superuser PostgreSQL langsung | Service role key dapat diakses penyerang; tidak ada batasan tingkat jaringan pada akses API Supabase langsung |
| **Miskonfigurasi Firebase Security Rules** | Firebase Realtime Database dan Firestore secara default menolak semua, tetapi developer biasanya menetapkan aturan yang terlalu permisif selama pengembangan (`".read": true, ".write": true`) dan gagal membatasinya sebelum produksi. Pengguna mana pun yang terautentikasi (atau anonim) dapat membaca/menulis seluruh database | Proyek Firebase dengan aturan keamanan yang permisif; autentikasi anonim diaktifkan |

---

## §11. Ringkasan: Prinsip-Prinsip Inti

**Properti fundamental yang membuat permukaan serangan JWT begitu luas adalah sifat ganda token sebagai pembawa data sekaligus rangkaian instruksi untuk verifikasinya sendiri.** Header JWT dikontrol penyerang namun mendikte keputusan keamanan yang kritis — algoritma mana yang digunakan, di mana menemukan kunci verifikasi, cara menginterpretasikan payload. Pembalikan kontrol ini (pesan yang menginstruksikan verifier cara memverifikasinya) adalah penyebab akar dari seluruh keluarga serangan §1 (manipulasi algoritma) dan §2 (injeksi parameter header). Tidak ada mekanisme autentikasi umum lain yang memberikan klien tingkat pengaruh ini atas proses verifikasi.

**Perbaikan inkremental gagal karena permukaan serangan bersifat kombinatorial.** Memperbaiki `alg: none` tidak mencegah algorithm confusion. Memperbaiki algorithm confusion tidak mencegah injeksi `kid`. Memperbaiki injeksi `kid` tidak mencegah SSRF `jku`. Setiap target mutasi (§1–§7) dapat dieksploitasi secara independen, dan kombinasi menciptakan rantai serangan baru (misalnya bypass `jku` + algorithm confusion + manipulasi claim). Library harus mengimplementasikan postur "tolak-secara-default" di seluruh *semua* parameter header secara bersamaan, yang banyak gagal dilakukan — terbukti dari CVE yang berulang di berbagai library dari tahun ke tahun (2015 hingga 2025).

**Solusi struktural memerlukan empat prinsip arsitektur:** (1) **Pinning algoritma sisi server** — jangan pernah membaca algoritma dari token; konfigurasikan di tingkat aplikasi. (2) **Resolusi kunci tertutup** — jangan pernah mengambil, menyematkan, atau me-resolve kunci secara dinamis dari header token; gunakan key store yang telah dikonfigurasi sebelumnya dan tidak dapat diubah. (3) **Penegakan jenis token eksplisit** — selalu terapkan apakah JWS atau JWE yang diharapkan; jangan pernah menggunakan antarmuka `decode()` terpadu yang mendeteksi jenis token secara otomatis. Serangan kebingungan sign/encrypt dan token polyglot (§7-1) menunjukkan bahwa menggabungkan penandatanganan dan enkripsi ke dalam satu jalur kode mengubah pemeriksaan bukti-keaslian menjadi pemeriksaan dekripsi semata, yang bisa dilewati siapa pun dengan kunci publik. (4) **Manajemen lifecycle stateful** — terima bahwa JWT yang sepenuhnya stateless tidak dapat mendukung pencabutan, pencegahan replay, atau pengikatan sesi; perkuat dengan status sisi server (daftar hitam token, rotasi refresh token, pelacakan `jti`) untuk kasus penggunaan mana pun yang memerlukan properti ini. DoS billion hashes PBES2 (§3-4) menegaskan bahwa bahkan spesifikasi RFC itu sendiri memiliki celah tingkat protokol — parameter komputasi yang tidak dibatasi — yang tidak dapat diperbaiki oleh library mana pun tanpa menyimpang dari standar.

---

*Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan.*

---

## Referensi

- RFC 7519: JSON Web Token (JWT) — https://datatracker.ietf.org/doc/html/rfc7519
- RFC 7518: JSON Web Algorithms (JWA) — https://datatracker.ietf.org/doc/html/rfc7518
- PortSwigger Web Security Academy: JWT Attacks — https://portswigger.net/web-security/jwt
- Auth0: Critical Vulnerabilities in JSON Web Token Libraries — https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- PentesterLab: The Ultimate Guide to JWT Vulnerabilities and Attacks — https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide
- HackTricks: JWT Vulnerabilities — https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens
- OWASP WSTG: Testing JSON Web Tokens — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
- Red Sentry: JWT Vulnerabilities List 2026 — https://redsentry.com/resources/blog/jwt-vulnerabilities-list-2026-security-risks-mitigation-guide
- TrustedSec: Keys to JWT Assessments — https://trustedsec.com/blog/keys-to-jwt-assessments-from-a-cheat-sheet-to-a-deep-dive
- Wallarm: 340 Weak JWT Secrets — https://lab.wallarm.com/340-weak-jwt-secrets-you-should-check-in-your-code/
- Intigriti: Exploiting JWT Vulnerabilities — https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-jwt-vulnerabilities
- Akamai: Analyzing Broken User Authentication Threats to JWT — https://www.akamai.com/blog/security-research/owasp-authentication-threats-for-json-web-token
- PentesterLab: CVE-2026-23993 HarbourJwt Unknown Algorithm JWT Bypass — https://pentesterlab.com/blog/cve-2026-23993-harbourjwt-unknown-alg-jwt-bypass
- JFrog: CVE-2022-21449 "Psychic Signatures" Analysis — https://jfrog.com/blog/cve-2022-21449-psychic-signatures-analyzing-the-new-java-crypto-vulnerability/
- Traceable AI: JWTs Under the Microscope — https://www.traceable.ai/blog-post/jwts-under-the-microscope-how-attackers-exploit-authentication-and-authorization-weaknesses
- Tom Tervoort (Secura): Three New Attacks Against JSON Web Tokens (BlackHat US 2023) — https://i.blackhat.com/BH-US-23/Presentations/US-23-Tervoort-Three-New-Attacks-Against-JSON-Web-Tokens.pdf
- Trail of Bits: Out of the kernel, into the tokens — https://blog.trailofbits.com/2024/03/08/out-of-the-kernel-into-the-tokens/