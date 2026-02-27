---
title: Kerentanan Implementasi Kriptografi (Konteks Web) — Taksonomi Mutasi/Variasi
---

## Ruang Lingkup & Batasan

Dokumen ini mencakup **kelemahan implementasi pada cryptographic primitive dan protokol** sebagaimana yang muncul dalam aplikasi web dan infrastruktur. Fokusnya adalah pada mekanisme kriptografi yang mendasar—cipher mode, operasi asimetris, hash function, RNG, siklus hidup key, parsing struktur data, dan kebocoran side-channel—bukan pada protokol tingkat tinggi yang menggunakannya.

**Tidak termasuk secara eksplisit** (dibahas dalam dokumen tersendiri):
- Serangan pada level protokol TLS/SSL (versi downgrade, negosiasi cipher, manajemen session, validasi sertifikat, HSTS) → `tls-security.md`
- Serangan khusus JWT (algorithm confusion, header injection, eksploitasi kid) → `jwt.md`
- SAML signature wrapping, kanonisasi, Golden/Silver SAML → `saml.md`
- Penanganan token OAuth, PKCE downgrade, autentikasi klien → `oauth.md`
- Pemalsuan enkripsi cookie (ECB/CBC tanpa MAC di level cookie) → `cookie.md`
- Kerberos, NTLM, RADIUS, FIDO2/WebAuthn/Passkey attacks → `authentication-bypass-and-sso.md`
- Bypass MFA, kelemahan token reset password → `account-takeover.md`
- Timing attack web (umum) → `web-timing-attack.md`

Ketika dokumen khusus protokol menyebutkan cryptographic primitive (misalnya, penggunaan ulang nonce ECDSA dalam konteks JWT), dokumen ini menyediakan **pembahasan umum** tentang mode kegagalan primitive tersebut di seluruh konteks web.

---

## Struktur Klasifikasi

Taksonomi ini disusun berdasarkan tiga sumbu:

### Sumbu 1 — Target Mutasi (Struktur Utama)

Komponen struktural dari sistem kriptografi yang diserang atau disalahgunakan. Sumbu ini mendefinisikan sembilan kategori utama (§1–§9).

### Sumbu 2 — Jenis Diskrepansi (Lintas Kategori)

Sifat jaminan kriptografi yang dilanggar:

| Jenis Diskrepansi | Deskripsi |
|---|---|
| **Integrity Bypass** | Ciphertext atau data yang ditandatangani dimanipulasi tanpa terdeteksi |
| **Key Recovery** | Material kunci rahasia atau private key diekstraksi |
| **Plaintext Recovery** | Data terenkripsi didekripsi tanpa memiliki kunci |
| **Authentication Bypass** | Signature atau MAC dipalsukan tanpa signing key |
| **Information Leakage** | Metadata, timing, atau informasi panjang mengungkap konten yang dilindungi |
| **Downgrade** | Algoritma/mode yang lebih kuat dipaksa beralih ke alternatif yang lebih lemah |
| **Denial of Service** | Operasi kriptografi dijadikan senjata untuk menghabiskan sumber daya |

### Sumbu 3 — Skenario Serangan (Pemetaan)

Konteks penerapan di mana celah tersebut dapat dieksploitasi:

| Skenario | Arsitektur |
|---|---|
| **MitM / Session Interception** | Penyerang yang berada di jaringan memodifikasi atau mengamati lalu lintas |
| **Token / Credential Forgery** | Penyerang menghasilkan material autentikasi yang valid |
| **Data Exfiltration** | Mengekstrak data yang dilindungi dari penyimpanan terenkripsi atau data dalam transit |
| **Retrospective Decryption** | Merekam lalu lintas sekarang untuk didekripsi di masa depan (HNDL) |
| **Supply Chain Compromise** | Menyerang library kriptografi atau distribusi kunci |
| **Infrastructure Compromise** | Mengeksploitasi pemrosesan kriptografi untuk RCE, DoS, atau pivoting |

---

## §1. Penyalahgunaan Cipher Mode & Parameter Simetris

Cipher simetris (AES, ChaCha20) adalah tulang punggung enkripsi web—data session, encrypted cookie, enkripsi field database, penyimpanan file. Keamanannya sepenuhnya bergantung pada pemilihan mode yang benar, penanganan parameter, dan proteksi integritas.

### §1-1. Eksploitasi CBC Mode Tanpa Autentikasi

AES-CBC memberikan kerahasiaan tetapi **tanpa integritas**. Tanpa MAC terpisah, ciphertext bersifat malleable.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **CBC Bit-Flipping** | Dalam dekripsi CBC, `plaintext[n] = DECRYPT(ciphertext[n]) XOR ciphertext[n-1]`. Memodifikasi byte `i` di blok `n-1` secara langsung meng-XOR perubahan yang sama ke plaintext blok `n`. Formula: `modified = original_byte XOR old_value XOR new_value`. | Penyerang dapat memotong dan memodifikasi ciphertext (cookie, parameter URL, field API). Tidak ada MAC/HMAC yang melindungi ciphertext. |
| **CBC Padding Oracle** | Ketika server mengungkapkan apakah padding PKCS#7 valid setelah dekripsi (melalui pesan error, timing, atau kode status HTTP), penyerang secara iteratif mendekripsi setiap byte dengan memanipulasi blok ciphertext sebelumnya dan mengamati respons oracle. Memerlukan sekitar 128 × block_size (dalam byte) kueri per blok (misalnya, ~2.048 untuk AES-128). | Server mengembalikan respons yang dapat dibedakan antara error padding vs. error aplikasi. Berlaku untuk sistem apa pun yang mendekripsi ciphertext CBC dari input yang tidak tepercaya. |
| **Manipulasi IV (Blok Pertama)** | IV berfungsi sebagai `ciphertext[0]` untuk blok pertama. Jika IV dikirimkan bersama ciphertext (umum pada cookie, parameter URL terenkripsi), penyerang mengendalikan XOR yang diterapkan ke plaintext blok pertama: `fake_iv = DECRYPT(block_1) XOR desired_plaintext`. | IV tidak dilindungi integritasnya atau dapat dikontrol pengguna. |
| **IV Reuse / IV yang Dapat Diprediksi** | Menggunakan kembali IV yang sama dengan kunci yang sama menghasilkan ciphertext identik untuk plaintext pertama yang identik, membocorkan kesamaan. IV yang dapat diprediksi memungkinkan serangan chosen-plaintext (pola serangan BEAST). Catatan: relasi `C1 XOR C2 = P1 XOR P2` berlaku untuk CTR/stream cipher, bukan CBC. | Pembuatan IV yang statis atau dapat diprediksi. Kunci yang sama digunakan di beberapa enkripsi. |

**Contoh — CBC Bit-Flipping pada Encrypted Cookie:**
```
Plaintext asli:  userid=12345&role=guest
Target plaintext: userid=12345&role=admin
Serangan: XOR byte pada posisi yang sesuai dengan "guest" di blok
          ciphertext sebelumnya dengan (ord('g')^ord('a')),
          (ord('u')^ord('d')), (ord('e')^ord('m')), (ord('s')^ord('i')),
          (ord('t')^ord('n')).
Efek samping: Blok yang dimodifikasi didekripsi menjadi sampah, tetapi
              blok target berisi "role=admin".
```

### §1-2. Kebocoran Pola ECB Mode

ECB mengenkripsi setiap blok secara independen dengan kunci yang sama, menghasilkan ciphertext identik untuk plaintext blok yang identik. Sifat deterministik ini membocorkan informasi struktural.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Block Boundary Alignment** | Penyerang mengontrol input yang berdekatan dengan nilai rahasia. Dengan memasukkan padding untuk menyelaraskan rahasia di batas blok dan mengamati blok ciphertext, byte-byte rahasia dipulihkan satu per satu (ECB byte-at-a-time / ECB oracle). | Aplikasi mengenkripsi input yang dikontrol penyerang yang digabungkan dengan data rahasia. ECB mode digunakan untuk enkripsi. |
| **Penyusunan Ulang Blok Ciphertext** | Karena setiap blok dienkripsi secara independen, blok dapat ditukar, diduplikasi, atau dihapus. Eskalasi peran dengan mengganti satu field terenkripsi dengan yang lain. | Data terstruktur (misalnya, `role=user`, `role=admin`) dienkripsi dalam ECB. Penyerang dapat mengumpulkan blok dari konteks yang berbeda. |
| **Pengenalan Pola** | Blok plaintext yang berulang menghasilkan blok ciphertext yang berulang, mengungkap struktur data, frekuensi pengulangan, dan batas field bahkan tanpa dekripsi. | Enkripsi ECB apa pun pada data terstruktur atau sebagian berulang. |

### §1-3. Penyalahgunaan Nonce CTR/GCM

Mode Counter (CTR) dan variannya yang terotentikasi, GCM, bergantung pada keunikan nonce. Penggunaan ulang nonce memiliki konsekuensi yang sangat fatal.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **CTR Nonce Reuse (Two-Time Pad)** | Menggunakan ulang nonce dengan kunci yang sama menghasilkan blok keystream yang identik. Meng-XOR dua ciphertext menghilangkan keystream: `C1 XOR C2 = P1 XOR P2`. Bagian plaintext yang diketahui atau dapat ditebak dari salah satu pesan memungkinkan pemulihan penuh pesan lainnya. | Pasangan (key, nonce) yang sama digunakan untuk dua enkripsi atau lebih. Umum terjadi pada server stateless atau sistem terdistribusi tanpa koordinasi nonce. |
| **GCM Nonce Reuse → Auth Key Recovery** | AES-GCM menggunakan polynomial MAC (GHASH) dengan kunci `H = AES_K(0^128)`. Dengan dua pesan yang dienkripsi menggunakan nonce yang sama, authentication key `H` dapat dipulihkan melalui polynomial GCD. Penyerang kemudian dapat memalsukan ciphertext yang terotentikasi. | Pasangan (key, nonce) yang sama digunakan untuk dua enkripsi GCM. Ini menghancurkan kerahasiaan DAN keaslian. |
| **Pemotongan GCM Tag yang Pendek** | GCM tag dapat dipotong untuk mengurangi overhead. Setiap bit yang dihapus menggandakan probabilitas pemalsuan. Tag 32-bit memungkinkan pemalsuan dengan probabilitas 2^-32 per percobaan—layak untuk serangan online dengan tingkat permintaan tinggi. | Aplikasi menggunakan GCM tag yang dipotong (< 96 bit). Volume permintaan tinggi tersedia. |

### §1-4. Penggunaan Ulang Keystream Stream Cipher

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Eksploitasi Bias RC4** | Byte output RC4 menunjukkan bias statistik. Byte output kedua memiliki probabilitas 2/256 untuk bernilai nol. Dengan ~2^30 enkripsi plaintext yang sama (misalnya, cookie yang dikirim dalam permintaan HTTPS berulang), bias memungkinkan pemulihan byte plaintext. | RC4 digunakan dalam TLS (sekarang sudah tidak direkomendasikan). Rahasia yang sama dienkripsi di banyak koneksi. |
| **ChaCha20 Nonce Reuse** | ChaCha20 (seperti CTR mode) menghasilkan keystream deterministik dari (key, nonce). Penggunaan ulang nonce menghasilkan two-time pad. Penggunaan ulang nonce ChaCha20-Poly1305 juga mengekspos Poly1305 one-time key (yang diturunkan dari blok 0 ChaCha20): mengautentikasi dua pesan dengan kunci yang sama memungkinkan pemulihan polynomial key, membahayakan kerahasiaan dan keaslian—analogis dengan penggunaan ulang nonce GCM yang mengekspos GHASH key. | Pasangan (key, nonce) yang sama digunakan ulang. Relevan dalam implementasi kustom yang melewati TLS. |

### §1-5. Pelanggaran Urutan Encrypt-then-MAC

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **MAC-then-Encrypt** | MAC dihitung atas plaintext, kemudian keduanya dienkripsi. Penerima harus mendekripsi sebelum memverifikasi integritas, menciptakan celah untuk padding oracle dan perbedaan waktu pemrosesan (Lucky13). TLS ≤1.2 dengan CBC suite menggunakan urutan ini. | CBC cipher suite dalam TLS 1.0/1.1/1.2. Protokol kustom apa pun yang menggunakan MAC-then-Encrypt. |
| **Encrypt-and-MAC** | MAC dihitung atas plaintext; enkripsi diterapkan hanya pada plaintext. MAC (atas plaintext) dikirim dalam bentuk jelas, membocorkan informasi tentang plaintext melalui MAC tag. Desain asli SSH menggunakan ini. | Protokol kustom yang menggunakan komposisi Encrypt-and-MAC. |
| **Tidak Ada MAC Sama Sekali** | Enkripsi diterapkan tanpa perlindungan integritas apa pun. Semua serangan manipulasi ciphertext (§1-1, §1-2, §1-3) menjadi dapat dieksploitasi dengan mudah. | Sangat umum dalam kode aplikasi web yang menggunakan AES mentah tanpa AEAD. |

---

## §2. Kelemahan Implementasi Kriptografi Asimetris

Kriptografi asimetris (RSA, ECDSA, Ed25519, ECDH) menopang tanda tangan digital, pertukaran kunci, dan autentikasi di seluruh web. Kesalahan implementasi dalam primitive ini merusak jaminan matematis yang mereka berikan.

### §2-1. Kerentanan Nonce ECDSA

Keamanan ECDSA sepenuhnya bergantung pada kerahasiaan dan keunikan nonce per-tanda tangan `k`. Kebocoran apa pun—bahkan beberapa bit—memungkinkan pemulihan private key melalui lattice reduction.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Nonce Reuse (Penggunaan Ulang Nilai k)** | Ketika `k` yang sama digunakan untuk dua tanda tangan pada pesan yang berbeda, kedua tanda tangan berbagi nilai `r` yang sama. Private key dapat dihitung langsung: `k = (hash(m1) - hash(m2)) / (s1 - s2) mod n`, kemudian `privateKey = (s1*k - hash(m1)) / r mod n`. | Kegagalan PRNG, seed statis, atau entropi yang tidak memadai saat penandatanganan. Dapat dideteksi dengan membandingkan nilai `r` di seluruh tanda tangan. |
| **Nonce Bias (Kebocoran Parsial)** | Jika nonce bias—misalnya, bit teratas selalu nol karena output hash lebih pendek dari orde kurva—serangan berbasis lattice (HNP/LLL) memulihkan private key dari beberapa tanda tangan. Implementasi P-521 PuTTY membocorkan 9 bit per nonce melalui pemotongan SHA-512 (CVE-2024-31497), memerlukan ~60 tanda tangan untuk pemulihan kunci penuh. | Ukuran output hash < orde kurva (P-521: 521 bit vs SHA-512: 512 bit). Bias sistematis apa pun dalam pembuatan nonce. |
| **Kebocoran Nonce Berbasis Timing** | Perkalian skalar yang tidak berjalan dalam waktu konstan saat penandatanganan membocorkan panjang bit nonce melalui waktu eksekusi. Kelas serangan Minerva mengeksploitasi perbedaan timing nanodetik untuk mengekstrak informasi nonce parsial, memungkinkan pemulihan kunci berbasis lattice. ECDSA OpenSSL memiliki sinyal timing ~300ns ketika word teratas dari nonce yang diinversi bernilai nol (CVE-2024-13176). | Operasi bignum yang tidak berjalan dalam waktu konstan pada jalur penandatanganan. Penyerang dapat mengukur waktu penandatanganan (proses lokal, VM co-located, atau network timing presisi tinggi). |
| **Invalid Curve Attack** | Jika implementasi ECDSA tidak memvalidasi bahwa public key pihak lawan terletak pada kurva yang diharapkan, penyerang mengirimkan titik pada kurva lemah dengan orde subgrup kecil. Shared secret atau tanda tangan yang dihasilkan membocorkan private key modulo orde subgrup. Chinese Remainder Theorem menggabungkan beberapa kebocoran untuk pemulihan penuh. | Validasi titik yang hilang dalam pertukaran kunci ECDH atau verifikasi ECDSA. Implementasi menerima koordinat (x, y) sembarang. |

**Contoh — Nonce Bias yang Mengarah ke Pemulihan Kunci (PuTTY CVE-2024-31497):**
```
Kurva: NIST P-521 (orde ≈ 2^521)
Hash: SHA-512 (output = 512 bit)
Bias: 9 bit teratas dari setiap nonce adalah nol
Tanda tangan yang dibutuhkan: ~60 (dari commit Git publik yang ditandatangani dengan SSH key)
Serangan: Bangun masalah lattice dari tuple (r, s, hash)
          Terapkan reduksi LLL/BKZ untuk memulihkan private key
Dampak: SSH private key dapat dipulihkan dari riwayat penandatanganan Git publik
```

### §2-2. Kerentanan Implementasi RSA

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **PKCS#1 v1.5 Padding Oracle (Bleichenbacher)** | RSA dengan padding PKCS#1 v1.5 rentan ketika server mengungkapkan validitas padding. Penyerang secara iteratif membuat ciphertext `c' = c * s^e mod n`, mengamati respons server, dan secara progresif mempersempit rentang plaintext. Biasanya memerlukan ~10.000–100.000 kueri oracle untuk kunci 2048-bit. | Server mengembalikan respons yang dapat dibedakan antara padding PKCS#1 v1.5 yang valid vs. tidak valid. Pertukaran kunci RSA (bukan penandatanganan RSA) dalam TLS. |
| **ROBOT (Return of Bleichenbacher's Oracle Threat)** | Varian modern yang menggunakan side-channel halus sebagai oracle: TCP reset vs. timeout, alert TLS duplikat, perbedaan kode status HTTP. Memengaruhi ~27% Alexa Top 100 pada 2017. Produk dari F5, Citrix, Palo Alto, IBM, dan Cisco rentan. | Pertukaran kunci RSA diaktifkan dalam TLS. Perbedaan perilaku yang dapat diamati pada kegagalan padding—bahkan di level TCP. |
| **Pembuatan Kunci RSA yang Lemah** | Kunci yang dihasilkan dengan entropi yang tidak cukup, faktor prima bersama di beberapa perangkat (umum dalam IoT/embedded), atau parameter yang terdegenerasi (misalnya, `e=1`). Factorable.net menemukan 0,2% TLS RSA public key berbagi faktor prima. | PRNG dengan entropi rendah saat pembuatan kunci. Perangkat produksi massal dengan firmware identik yang menghasilkan kunci saat pertama kali dinyalakan. |
| **Panjang Kunci RSA Pendek** | Kunci RSA di bawah 2048 bit dapat difaktorkan dengan sumber daya yang moderat. Kunci 1024-bit dapat dijangkau oleh penyerang dengan dana yang cukup. Kunci 512-bit (FREAK/kelas ekspor) dapat difaktorkan dengan mudah menggunakan perangkat keras konsumen. | Sistem warisan atau server yang salah konfigurasi yang menawarkan kunci RSA pendek. FREAK: memaksa RSA 512-bit kelas ekspor. |
| **Enkripsi Kunci Publik sebagai Autentikasi Token (Kerahasiaan ≠ Keaslian)** | Implementasi OIDC/OAuth yang mengenkripsi refresh token atau session token menggunakan RSA public key yang dapat diambil dari endpoint JWKS publik (`.well-known/jwks.json`). Karena public key tersedia untuk siapa saja, pihak mana pun dapat mengenkripsi payload token sembarang yang akan berhasil didekripsi dan diterima oleh server—server mengacaukan "saya dapat mendekripsi ini" dengan "ini asli." Penyerang mengekstrak RSA public key, membangun token dengan klaim yang dipalsukan (identitas pengguna, scope, kedaluwarsa), mengenkripsinya dengan public key, dan mengirimkannya ke token endpoint. Server mendekripsi dengan sukses, mempercayai klaim, dan menerbitkan access token yang valid untuk akun korban. | RSA public key yang digunakan untuk enkripsi token dapat diakses publik (endpoint JWKS). Integritas token hanya mengandalkan enkripsi (tidak ada tanda tangan atau MAC terpisah). Struktur/skema token dapat diprediksi atau terdokumentasi. (Lihat `oauth.md` untuk konteks khusus OAuth.) |

### §2-3. Kelemahan Implementasi Ed25519

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Validasi Parameter Public Key yang Hilang (Kerentanan Chalkias)** | Lebih dari 45 library Ed25519 mengekspos API penandatanganan yang menerima public key yang telah dihitung sebelumnya sebagai parameter optimasi. Jika library tidak memvalidasi bahwa public key sesuai dengan private key, penyerang dapat memanggil penandatanganan dengan public key yang dimanipulasi dan menggunakan kriptanalisis berbasis lattice pada tanda tangan yang dihasilkan untuk memulihkan private key. | Library mengekspos API `sign(message, privateKey, publicKey)`. Tidak ada validasi bahwa `publicKey = privateKey * G`. Penyerang dapat memanggil penandatanganan dengan nilai public key sembarang. |

### §2-4. Kelemahan Pertukaran Kunci Diffie-Hellman / ECDH

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Serangan Subgrup Kecil (DH)** | Penyerang mengirimkan nilai publik DH dari subgrup kecil dari grup multiplikasi. Shared secret terbatas pada sekumpulan nilai kecil yang dapat dipulihkan dengan brute force. | Parameter grup DH tidak memiliki validasi safe-prime. Server tidak memvalidasi bahwa nilai publik pihak lawan memiliki orde penuh. |
| **Logjam (DH Export Downgrade)** | Penyerang memaksa TLS handshake untuk menggunakan parameter DH "kelas ekspor" 512-bit, kemudian melakukan prekomputasi Number Field Sieve untuk memecahkan pertukaran kunci secara real time. Satu grup 512-bit digunakan ulang oleh ~8,4% domain HTTPS. | Server TLS mendukung cipher suite DHE_EXPORT. Klien tidak menolak parameter DH yang lemah. |
| **Penggunaan Ulang Kunci ECDH Lintas Protokol** | Ketika pasangan kunci ECDH yang sama digunakan untuk pertukaran kunci maupun penandatanganan (atau lintas protokol), penyerang dapat mengeksploitasi interaksi satu protokol untuk mengekstrak informasi yang dapat digunakan di protokol lain. | Pasangan kunci yang sama digunakan ulang di TLS, SSH, dan protokol lapisan aplikasi. |

---

## §3. Eksploitasi Hash Function & MAC

Hash function dan MAC memberikan integritas dan autentikasi. Penyalahgunaan atau eksploitasi sifat strukturalnya merusak jaminan tersebut.

### §3-1. Serangan Length Extension

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Merkle-Damgård Length Extension** | Hash function dengan konstruksi Merkle-Damgård (MD5, SHA-1, SHA-256) memungkinkan penyerang yang mengetahui `H(secret || message)` dan panjang `secret` untuk menghitung `H(secret || message || padding || attacker_suffix)` tanpa mengetahui `secret`. Ini merusak konstruksi MAC dalam bentuk `MAC = H(key || data)`. | Aplikasi menghitung `hash(secret + user_data)` sebagai pemeriksaan integritas. SHA-256 atau MD5 digunakan (bukan HMAC, bukan SHA-3, bukan SHA-512/256 yang dipotong). |
| **Pemalsuan Tanda Tangan API via Length Extension** | API web yang menggunakan `signature = SHA256(api_secret + request_params)` rentan. Penyerang menambahkan parameter tambahan (misalnya, `&admin=true`) dan menghitung hash yang diperluas yang valid. Server memvalidasi tanda tangan dan memproses parameter yang ditambahkan. | Umum dalam skema autentikasi API kustom yang menghindari HMAC. String kueri atau POST body digabungkan dengan secret sebelum di-hash. |

**Contoh — Ekstensi Tanda Tangan API:**
```
Asli:   GET /api?user=alice&sig=abc123
        Server menghitung: SHA256(secret + "user=alice") == abc123 ✓

Serangan: GET /api?user=alice[padding]&admin=true&sig=def456
          Penyerang menghitung: extend(abc123, len(secret), "&admin=true") → def456
          Server menghitung: SHA256(secret + "user=alice[padding]&admin=true") == def456 ✓
```

### §3-2. Eksploitasi Hash Collision dalam Konteks Web

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **MD5 Chosen-Prefix Collision** | Dua input berbeda yang berbagi awalan sembarang dapat dibuat menghasilkan hash MD5 yang sama dengan kompleksitas ~2^39 (praktis). Dieksploitasi dalam pemalsuan sertifikat X.509, pemalsuan respons RADIUS (BlastRADIUS, CVE-2024-3596), dan penandatanganan perangkat lunak. | Sistem apa pun yang menggunakan MD5 untuk integritas atau autentikasi. MD5 dalam RADIUS Response-Authenticator secara eksplisit dapat dieksploitasi. |
| **SHA-1 Identical-Prefix Collision** | Dua dokumen dengan awalan yang sama menghasilkan hash SHA-1 yang sama dengan biaya ~2^63 (SHAttered, 2017). Praktis untuk pemalsuan PDF, collision commit Git, dan penandatanganan sertifikat. | SHA-1 digunakan untuk tanda tangan digital, content addressing (Git), atau thumbprint sertifikat. |
| **Confusion Hash-sebagai-Deduplication** | Sistem content-addressable (CDN, cache, object store) yang menggunakan hash lemah untuk deduplication memungkinkan penyerang menggantikan konten dengan memberikan collision. Konten yang sah digantikan atau dicampur dengan konten berbahaya. | Deduplication yang dikunci dengan MD5 atau SHA-1. Penyerang dapat mengunggah konten ke sistem penyimpanan yang sama. |
| **Birthday Attack pada Output Hash Pendek** | Untuk output hash `n` bit, collision diharapkan setelah ~2^(n/2) percobaan. Hash yang dipotong (misalnya, pengenal 64-bit yang berasal dari SHA-256) rentan terhadap birthday attack dengan operasi ~2^32. | Output hash yang dipotong digunakan sebagai pengenal unik. Session token, CSRF token, atau cache key yang berasal dari hash yang dipotong. |

### §3-3. Penyalahgunaan HMAC dan MAC

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Timing Attack pada Perbandingan MAC** | Membandingkan MAC tag menggunakan perbandingan string standar (`==`) mengungkap byte yang berbeda pertama melalui perbedaan timing. Penyerang secara iteratif brute-force setiap byte dengan mengukur waktu perbandingan, mengurangi serangan dari 2^128 menjadi 128×256 = 32.768 percobaan untuk MAC 16-byte. | Fungsi perbandingan yang tidak berjalan dalam waktu konstan digunakan untuk verifikasi MAC. Perbedaan timing yang terukur (lokal atau berdekatan jaringan). |
| **Interaksi Panjang Kunci HMAC** | Kunci HMAC yang lebih panjang dari ukuran hash block pertama-tama di-hash, kemudian digunakan. Jika penyerang dapat memengaruhi pemilihan kunci dan hash yang dihasilkan lemah (collision), kunci yang berbeda menghasilkan output HMAC yang sama. Selain itu, kunci yang lebih pendek dari output hash memberikan keamanan yang lebih rendah dari yang diharapkan. | Aplikasi memungkinkan material kunci yang dipengaruhi pengguna untuk HMAC. Kunci yang sangat panjang dimasukkan tanpa kesadaran akan hashing internal. |
| **Penggunaan Ulang Kunci Poly1305** | Poly1305 (digunakan dalam ChaCha20-Poly1305) adalah MAC satu kali pakai. Menggunakan ulang kunci Poly1305 yang sama untuk dua pesan memungkinkan pemalsuan MAC untuk pesan sembarang. Dalam ChaCha20-Poly1305, penggunaan ulang nonce berarti penggunaan ulang kunci Poly1305. | Penggunaan ulang nonce dalam ChaCha20-Poly1305 (lihat §1-3). Protokol kustom yang menyalahgunakan Poly1305 sebagai MAC tujuan umum. |

### §3-4. Kerentanan Hashing Password

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Pemotongan bcrypt 72 Byte** | bcrypt secara diam-diam memotong password menjadi 72 byte. Password yang lebih panjang dari 72 byte yang berbagi 72 byte pertama yang sama menghasilkan hash yang identik. Dieksploitasi dalam insiden Okta Oktober 2024 di mana cache key berdasarkan hash bcrypt memungkinkan autentikasi dengan password apa pun yang berbagi 72 byte pertama. | Password atau input turunan yang melebihi 72 byte dimasukkan ke bcrypt. Cache key yang berasal dari hash bcrypt. |
| **Hash Tidak Disalted / Salt Global** | Tanpa salt per-pengguna, password yang identik menghasilkan hash yang identik, memungkinkan serangan rainbow table dan mengungkap penggunaan ulang password di antara pengguna. Salt global tunggal (dibagikan ke semua pengguna) memungkinkan prekomputasi setelah salt diketahui. | Sistem warisan yang menggunakan MD5/SHA-1/SHA-256 tanpa salt. Nilai salt global yang telah disusupi. |
| **Work Factor yang Tidak Mencukupi** | Fungsi hashing password (bcrypt, scrypt, Argon2) memerlukan parameter cost yang terkalibrasi. Cost factor yang terlalu rendah memungkinkan brute forcing berbasis GPU. bcrypt cost < 10, scrypt N < 2^14, atau memori Argon2 < 64MB umumnya dianggap tidak mencukupi untuk tahun 2025. | Parameter cost default atau lama. Tidak ada rekalibrasi berkala seiring perkembangan perangkat keras. |
| **Penyalahgunaan Iterasi PBKDF2 (Denial of Service)** | Ketika jumlah iterasi dapat dikontrol penyerang (misalnya, PBES2 dalam JWE/JWK), menetapkan nilai yang sangat tinggi memaksa server melakukan miliaran iterasi PBKDF2, menyebabkan kelelahan CPU. Satu permintaan dapat menghentikan server selama menit. | Jumlah iterasi diurai dari input yang tidak tepercaya (lihat jwt.md §5 untuk perlakuan khusus JWT). Key wrapping PBES2 dalam konteks non-JWT apa pun. |

---

## §4. Kegagalan Pembuatan Random Number & Nonce

Keamanan kriptografi secara mendasar bergantung pada kualitas pembuatan bilangan acak. Entropi yang tidak mencukupi atau generator yang dapat diprediksi merusak setiap operasi kriptografi yang dibangun di atasnya.

### §4-1. Entropi yang Tidak Mencukupi saat Pembuatan

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Boot-Time Entropy Starvation** | Sistem yang menghasilkan cryptographic key segera setelah boot (VM, container, perangkat IoT) mungkin memiliki entropi yang tidak mencukupi. `/dev/urandom` di Linux akan mengembalikan data bahkan dengan entropi rendah, berpotensi menghasilkan kunci yang dapat diprediksi. Factorable.net menemukan 5,57% host TLS dan 9,58% host SSH berbagi kunci akibat pembuatan kunci dengan entropi rendah. | Pembuatan kunci selama boot awal. VM yang dikloning dari satu snapshot (status PRNG awal yang identik). Perangkat embedded tanpa sumber entropi. |
| **VM Fork Entropy Duplication** | Ketika VM di-fork/klon, instance yang di-fork mewarisi status PRNG induk. Kedua VM menghasilkan nilai "acak" yang identik hingga entropi baru yang cukup dicampur. TLS session key, ECDSA nonce, dan CSRF token dapat bertabrakan. | Migrasi live VM atau kloning berbasis snapshot. Tidak ada reseed PRNG setelah fork. Auto-scaling cloud dari snapshot. |
| **Kegagalan Entropi Perangkat Embedded** | Perangkat yang tidak memiliki hardware RNG (tidak ada RDRAND, tidak ada TPM, tidak ada timer jitter) menghasilkan kunci dari sumber yang dapat diprediksi (uptime, PID, alamat MAC). Beberapa perangkat menghasilkan kunci yang identik. | Perangkat IoT, router, perangkat jaringan. Sistem headless tanpa entropi input pengguna. |

### §4-2. PRNG yang Dapat Diprediksi dalam Framework Web

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Math.random() untuk Token Keamanan** | `Math.random()` JavaScript menggunakan xorshift128+ (V8) atau PRNG non-kriptografis serupa. Status internal (128 bit di V8) dapat dipulihkan dari ~5 output berturut-turut, memungkinkan prediksi semua nilai masa depan dan masa lalu—termasuk session token, CSRF token, dan tautan reset password. | Aplikasi menggunakan `Math.random()` alih-alih `crypto.getRandomValues()` untuk nilai yang sensitif terhadap keamanan. |
| **Pemulihan Status Modul random Python** | Modul `random` Python menggunakan Mersenne Twister (MT19937). Status internal 624×32-bit dapat sepenuhnya dipulihkan dari 624 output 32-bit berturut-turut. Semua output berikutnya (token, nonce, kunci) dapat diprediksi. | Aplikasi menggunakan `random.random()` alih-alih modul `secrets` atau `os.urandom()` untuk token keamanan. |
| **Prediksi PHP mt_rand() / rand()** | `mt_rand()` PHP (Mersenne Twister) di-seed dengan nilai 32-bit saat pertama kali dipanggil. Seed dapat dipulihkan dari beberapa output, membuat semua nilai berikutnya dapat diprediksi. Sebelum PHP 7.1, `rand()` menggunakan LCG yang bahkan lebih lemah. | Aplikasi PHP yang menggunakan `mt_rand()` atau `rand()` untuk token, nilai CSRF, atau kode reset password. |
| **Kelemahan Ruby SecureRandom** | `SecureRandom` Ruby biasanya menggunakan `/dev/urandom`, tetapi fallback ke PRNG OpenSSL dapat memperkenalkan masalah dalam proses yang di-fork (sebelum Ruby 2.5 tidak melakukan reseed setelah fork). | Aplikasi Ruby yang menggunakan `SecureRandom` dalam proses worker yang di-fork (Unicorn, Puma prefork). |
| **Pemulihan Status java.util.Random Java** | `java.util.Random` Java menggunakan LCG 48-bit. Seed penuh dapat dipulihkan dari dua output berturut-turut. `ThreadLocalRandom` memiliki kelemahan yang sama. Hanya `java.security.SecureRandom` yang aman secara kriptografis. | Aplikasi Java yang menggunakan `Random` atau `ThreadLocalRandom` untuk nilai yang kritis terhadap keamanan. |

### §4-3. Kelemahan Pembuatan Nonce/IV

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Nonce Sekuensial dalam Sistem Terdistribusi** | Beberapa server yang menggunakan counter sekuensial untuk nonce (misalnya, `server_id || counter`) dapat bertubrukan jika ID server digunakan ulang, counter rollover, atau konfigurasi tidak konsisten. | Enkripsi terdistribusi tanpa koordinasi nonce terpusat. Rollover counter tidak ditangani. |
| **Nonce Berbasis Timestamp yang Bertabrakan** | Menggunakan timestamp sebagai nonce (misalnya, Unix epoch detik) menghasilkan collision ketika dua operasi terjadi dalam detik yang sama. Timestamp mikrodetik atau nanodetik mengurangi tetapi tidak menghilangkan risiko di bawah throughput tinggi. | Enkripsi throughput tinggi menggunakan nonce berbasis waktu. Masalah sinkronisasi clock dalam sistem terdistribusi. |
| **Nonce Deterministik dengan Input yang Dapat Diprediksi** | Nonce ECDSA deterministik RFC 6979 aman ketika diimplementasikan dengan benar, tetapi jika hash function atau private key disusupi, semua nonce menjadi dapat diprediksi. Skema nonce "deterministik" kustom yang menggunakan input lemah (misalnya, `HMAC(key, counter)` dengan kunci yang bocor) dapat langsung dieksploitasi. | Skema nonce deterministik kustom. Material kunci yang bocor dalam implementasi RFC 6979. |

---

## §5. Siklus Hidup & Manajemen Material Kunci

Paparan material kunci, dari pembuatan hingga penyimpanan, rotasi, dan penghancuran, mewakili jalur paling langsung menuju kompromi sistem kriptografi.

### §5-1. Paparan Material Kunci

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Kebocoran Repositori Source Code** | Private key, API secret, dan encryption key yang di-commit ke repositori Git (termasuk dalam riwayat commit bahkan setelah dihapus). Secret scanning GitHub mendeteksi >40 juta secret di repo publik pada tahun 2024. | File `.pem`, `.key`, `.pfx` dalam repositori. String kunci yang hardcoded dalam source code. File `.env` yang di-commit. |
| **Pengungkapan Kunci melalui Pesan Error** | Stack trace, halaman debug, dan pesan error yang verbose mengekspos material kunci, status PRNG, atau nilai kriptografi perantara. Halaman debug Django, `phpinfo()` PHP, dan stack trace Java semuanya pernah membocorkan secret. | Mode debug diaktifkan di produksi. Penanganan error yang verbose untuk operasi kriptografi. |
| **Pengungkapan Memori (Pola Heartbleed)** | Kerentanan buffer over-read dalam library TLS mengekspos memori server yang berisi private key, session key, dan kredensial pengguna. Heartbleed (CVE-2014-0160) membocorkan hingga 64KB per permintaan dari heap OpenSSL. Pola ini berulang dalam library TLS apa pun dengan bug manajemen buffer. (Lihat `tls-security.md` §7-2 dan `web-memory-disclosure.md` §1-1 untuk pembahasan terperinci.) | Library TLS dengan buffer over-read. Memori server berisi material kunci (umum karena proses yang berjalan lama). |
| **Paparan Backup dan Log** | Material kunci yang disertakan dalam backup database, log aplikasi, snapshot penyimpanan cloud, atau sistem monitoring. Backup database terenkripsi yang menyertakan encryption key dalam backup yang sama. | Logging body permintaan/respons yang berisi kunci. Sistem backup tanpa manajemen kunci terpisah. |

### §5-2. Kegagalan Rotasi dan Revokasi Kunci

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Tidak Ada Rotasi Kunci** | Cryptographic key yang digunakan tanpa batas. Kunci yang berumur panjang mengakumulasi risiko: lebih banyak data yang dienkripsi dengan kunci yang sama (meningkatkan paparan dari kompromi), lebih banyak waktu untuk kriptanalisis, dan lebih banyak kesempatan untuk eksfiltrasi. | Tidak ada kebijakan rotasi kunci. Kunci yang lebih tua dari siklus hidup organisasi. |
| **Rotasi Tanpa Re-Enkripsi** | Kunci dirotasi (kunci baru dibuat) tetapi data yang ada tetap dienkripsi dengan kunci lama, yang harus disimpan tanpa batas. Kunci yang "dirotasi" tidak memberikan forward security untuk data yang ada. | Kebijakan rotasi kunci tanpa strategi re-enkripsi data. Kunci lama disimpan bersama kunci baru dengan akses yang sama. |
| **Kegagalan Revokasi Sertifikat** | Sertifikat yang dicabut tetap dipercaya karena klien tidak memeriksa CRL/OCSP, responder OCSP tidak dapat dijangkau, atau OCSP soft-fail secara diam-diam menerima sertifikat. CRLite dan sertifikat berumur pendek adalah mitigasi yang sedang berkembang. (Lihat `tls-security.md` §4-3 untuk perlakuan revokasi khusus TLS.) | OCSP soft-fail (default di sebagian besar browser). Distribution point CRL tidak dapat dijangkau. Tidak ada OCSP Must-Staple. |
| **Confusion Key Endpoint JWKS** | Ketika endpoint JWKS melayani beberapa kunci dan `kid` (Key ID) tidak divalidasi dengan ketat, penyerang mungkin dapat mengeksploitasi jendela rollover kunci di mana kunci lama dan baru keduanya valid, atau menyuntikkan kunci tambahan jika endpoint JWKS dapat disusupi. | Endpoint JWKS melayani kunci tanpa binding `kid` yang ketat. Jendela rollover kunci dengan validasi yang permisif. (Lihat jwt.md untuk perlakuan khusus JWT.) |

### §5-3. Kelemahan Key Derivation Function (KDF)

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Penggunaan Langsung Password sebagai Kunci** | Menggunakan password pengguna langsung sebagai kunci AES (misalnya, padding dengan nol atau pemotongan) tanpa KDF. Password memiliki entropi jauh lebih sedikit daripada kunci, memungkinkan brute-force. | Pola `AES.new(password.encode().ljust(32, b'\0'))`. Tidak ada PBKDF2, scrypt, atau Argon2 yang diterapkan. |
| **KDF dengan Work Factor Rendah** | PBKDF2 dengan jumlah iterasi rendah (< 600.000 untuk SHA-256 per rekomendasi OWASP 2025). Setiap pengurangan setengah iterasi menggandakan kecepatan penyerang. Pemecahan PBKDF2-SHA256 yang dipercepat GPU pada 10.000 iterasi melebihi 1 juta tebakan/detik. | Parameter cost default atau lama. Tidak ada penyesuaian berkala seiring perkembangan perangkat keras. |
| **Penggunaan Ulang Salt dalam KDF** | Salt yang sama digunakan di beberapa pengguna atau derivasi. Memungkinkan serangan paralel: pecahkan satu password dan tabel yang telah dihitung sebelumnya berlaku untuk semua pengguna dengan salt tersebut. | Salt global atau tidak ada salt dalam KDF. Salt yang berasal dari nama pengguna (dapat diprediksi, entropi rendah). |
| **Confusion Jenis KDF** | Menggunakan hash function (SHA-256) alih-alih KDF yang tepat (PBKDF2, scrypt, Argon2) untuk derivasi password-ke-kunci. Hash yang cepat memungkinkan miliaran tebakan per detik di GPU. | `key = SHA256(password + salt)` tanpa iterasi. Mengacaukan hashing pesan dengan derivasi kunci. |

---

## §6. Kerentanan Parsing Struktur Data Kriptografi

Sistem kriptografi menggunakan struktur data yang kompleks (ASN.1/DER, sertifikat X.509, PKCS#7/CMS, encoding PEM). Kerentanan parser dalam struktur ini memungkinkan serangan pre-autentikasi.

### §6-1. Kelemahan Parsing ASN.1/DER

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Length Field Overflow** | Field panjang ASN.1 dapat menentukan panjang multi-byte. Parser yang mempercayai field panjang tanpa pemeriksaan batas dapat ditipu untuk mengalokasikan memori berlebihan atau membaca melampaui batas buffer. | Input ASN.1 yang tidak tepercaya (sertifikat, pesan CMS, file PKCS#12). Implementasi C/C++ tanpa pemeriksaan batas. |
| **Penyalahgunaan Indefinite Length Encoding** | BER (tetapi bukan DER) mengizinkan encoding panjang tidak terbatas. Parser yang menerima BER di mana DER diharapkan mungkin menangani struktur panjang tidak terbatas yang bersarang secara salah, menyebabkan stack overflow atau infinite loop. | Parser yang menerima input berencoding BER. Struktur yang sangat bersarang dengan panjang tidak terbatas. |
| **Type Confusion dalam ASN.1** | Tag ASN.1 mengidentifikasi jenis setiap elemen. Jika parser tidak memvalidasi tag yang diharapkan dengan ketat, penyerang dapat menggantikan satu jenis dengan jenis lain (misalnya, INTEGER di mana BIT STRING diharapkan), yang menyebabkan salah interpretasi parameter kriptografi. | Parsing ASN.1 yang longgar yang melewati validasi tag. Struktur sertifikat atau kunci dengan jenis yang diganti. |
| **Data Trailing / Encoding Non-Kanonik** | DER memerlukan encoding kanonik (panjang minimal, tidak ada data trailing). Parser yang menerima input non-kanonik atau mengabaikan byte trailing mungkin memproses data yang berbeda dari yang ditandatangani, memungkinkan bypass tanda tangan. | Validasi sertifikat menggunakan parser DER yang longgar. Data yang ditandatangani dengan konten yang tidak ditandatangani yang ditambahkan. |

### §6-2. Serangan Parsing Sertifikat X.509

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Null Byte dalam Common Name** | Sertifikat yang diterbitkan untuk `www.target.com\0.attacker.com` mungkin lulus validasi CA (yang melihat string penuh) sementara aplikasi memotong pada null byte dan cocok dengan `www.target.com`. | Penanganan string berbasis C dalam validasi sertifikat. CA yang menerbitkan sertifikat dengan null byte dalam nama (semakin jarang). |
| **Bypass Name Constraint** | Ekstensi Name Constraints X.509 membatasi domain mana yang dapat diterbitkan oleh CA bawahan. Parser yang mengabaikan atau tidak mengevaluasi name constraint dengan benar memungkinkan penerbitan sertifikat yang tidak sah. | Sertifikat CA perantara dengan name constraint. Klien yang tidak memberlakukan name constraint (banyak library TLS secara historis). |
| **Penanganan Critical Extension** | Ekstensi X.509 yang ditandai sebagai `critical` HARUS dipahami oleh klien; ekstensi kritis yang tidak dikenali HARUS menyebabkan penolakan. Library yang mengabaikan persyaratan ini menerima sertifikat dengan ekstensi yang relevan terhadap keamanan yang tidak mereka pahami. | Library TLS yang melewati ekstensi kritis yang tidak diketahui. Kode validasi sertifikat kustom. |
| **Confusion Kebijakan Sertifikat** | Sertifikat Extended Validation (EV), Organization Validation (OV), dan Domain Validation (DV) memiliki tingkat kepercayaan yang berbeda tetapi secara teknis setara dalam TLS. Aplikasi yang mengasumsikan jenis sertifikat menyiratkan tingkat keamanan dapat disesatkan. | Logika aplikasi yang bergantung pada level validasi sertifikat. Situs phishing dengan sertifikat DV. |

### §6-3. Parsing CMS/PKCS#7/S/MIME

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **CMS AuthEnvelopedData IV Overflow** | Saat mem-parsing struktur CMS menggunakan cipher AEAD (AES-GCM), IV dari parameter ASN.1 disalin ke buffer stack berukuran tetap tanpa validasi panjang. IV yang terlalu besar meluap buffer. Ini bersifat **pre-autentikasi** — tidak diperlukan material kunci yang valid. (CVE-2025-15467, OpenSSL 3.x) | Aplikasi memproses konten CMS/PKCS#7/S/MIME yang tidak tepercaya. OpenSSL 3.0–3.6 sebelum patch. |
| **Kerentanan Parsing PKCS#12** | File PKCS#12 (.pfx, .p12) berisi struktur terenkripsi yang bersarang. Bug parser dalam menangani PKCS#12 yang malformed memungkinkan heap overflow, NULL pointer dereference, dan infinite loop. Beberapa bug tersebut ditemukan dalam OpenSSL melalui fuzzing berbasis AI (2026). | Aplikasi mengimpor file PKCS#12 dari sumber yang tidak tepercaya. Alur kerja pendaftaran sertifikat atau impor kunci. |
| **Confusion Encoding PEM** | PEM adalah encoding base64 dari DER dengan baris header/footer. Beberapa objek PEM dalam satu file, header yang hilang, atau karakter non-base64 yang disematkan dapat menyebabkan ketidaksepakatan parser. Library yang berbeda mungkin mengekstrak sertifikat yang berbeda dari file PEM yang sama. | File PEM yang berisi beberapa sertifikat atau kunci. Parser yang berbeda dalam pipeline validasi sertifikat. |

---

## §7. Kebocoran Side-Channel dalam Konteks Web

Serangan side-channel mengeksploitasi informasi yang bocor melalui perilaku implementasi (timing, ukuran, daya, emanasi elektromagnetik) daripada kelemahan kriptografi. Dalam konteks web, side-channel yang dapat diamati jaringan adalah ancaman utama.

### §7-1. Timing Side-Channel

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Perbandingan Tidak dalam Waktu Konstan** | Perbandingan string MAC, token, atau password yang short-circuit pada ketidakcocokan pertama. Setiap posisi byte membocorkan informasi timing. Jitter jaringan memerlukan analisis statistik atas banyak permintaan, tetapi serangan presisi tinggi telah mendemonstrasikan pemulihan byte demi byte melalui internet. | Persamaan string standar (`==`, `strcmp`) untuk perbandingan MAC/token. Lihat §3-3 untuk perlakuan khusus HMAC. |
| **Timing Perkalian Skalar (ECDSA/ECDH)** | Perkalian titik dengan waktu yang bervariasi dalam operasi kurva eliptik membocorkan informasi tentang skalar (nonce atau private key) melalui waktu eksekusi. Bahkan perbedaan ~300ns dapat dieksploitasi dengan cukup banyak sampel. | Implementasi kurva eliptik yang tidak berjalan dalam waktu konstan. Lihat §2-1 untuk perlakuan khusus ECDSA. |
| **Timing Dekripsi RSA** | Operasi RSA private-key menggunakan Chinese Remainder Theorem (CRT) dengan modular exponentiation yang tidak berjalan dalam waktu konstan membocorkan informasi tentang faktor private key melalui timing. | Implementasi RSA tanpa blinding. Penyerang co-located atau network timing dengan analisis statistik. |
| **Timing Percabangan Bergantung Kunci** | Percabangan kondisional berdasarkan bit kunci (misalnya, square-and-multiply tanpa Montgomery ladder) membocorkan pola bit dari eksponen/skalar melalui waktu eksekusi. | Modular exponentiation yang tidak dilindungi. Operasi private key tanpa jaminan waktu konstan. |

### §7-2. Analisis Lalu Lintas Jaringan

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Klasifikasi Lalu Lintas Terenkripsi** | TLS mengenkripsi konten tetapi bukan metadata: ukuran paket, timing, arah, dan pola koneksi. Classifier machine learning mengidentifikasi halaman yang dikunjungi, endpoint API, dan tindakan pengguna dari pola lalu lintas terenkripsi dengan akurasi >90% dalam pengaturan yang terkontrol. | HTTPS tanpa padding lalu lintas. Ukuran halaman atau pola respons API yang khas. |
| **Compression Ratio Oracle (BREACH)** | Kompresi di level HTTP yang dikombinasikan dengan input yang dikontrol penyerang menciptakan length oracle: ketika tebakan cocok dengan konten yang ada, output yang dikompres lebih pendek, dan paket terenkripsi yang sesuai juga lebih kecil. Pemulihan byte demi byte secret dalam respons yang dikompres. | Kompresi HTTP diaktifkan. Input pengguna yang direfleksikan dalam respons yang berisi secret (CSRF token, API key). Lihat `tls-security.md` §3-3 untuk perlakuan di level TLS. |

---

## §8. Kerentanan Agility Kriptografi & Migrasi Algoritma

Transisi antar algoritma kriptografi—baik karena deprecation, standardisasi, atau ancaman kuantum—menciptakan kelas kerentanan yang berbeda.

### §8-1. Serangan Downgrade Algoritma

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Downgrade Cipher Suite / Algoritma** | Penyerang MitM memodifikasi negosiasi protokol untuk menghapus opsi yang kuat, memaksa pemilihan algoritma yang lemah. Berlaku untuk S/MIME, PGP, JOSE, dan protokol apa pun dengan negosiasi algoritma. Jika penerima tidak memberlakukan kekuatan algoritma minimum, penyerang berhasil. (Untuk downgrade cipher suite khusus TLS, lihat `tls-security.md` §1-2.) | Protokol mendukung beberapa opsi algoritma. Tidak ada kebijakan kekuatan algoritma minimum yang diberlakukan. |
| **Perilaku Fallback Library Kriptografi** | Library yang secara diam-diam fallback ke algoritma yang lebih lemah ketika algoritma yang diinginkan tidak tersedia (misalnya, fallback dari AES-256-GCM ke AES-128-CBC, atau dari ECDSA ke RSA) tanpa sepengetahuan aplikasi. | Library dengan perilaku fallback otomatis. Aplikasi tidak memverifikasi algoritma yang benar-benar digunakan. |

### §8-2. Ketidakfleksibelan Algoritma yang Hardcoded

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Embedding Algoritma Non-Agile** | Aplikasi yang meng-hardcode `RS256`, `AES-256-CBC`, atau cipher suite tertentu tidak dapat bermigrasi ke algoritma baru tanpa perubahan kode. Ketika algoritma yang di-hardcode sudah tidak direkomendasikan atau rusak, seluruh aplikasi memerlukan redeployment. | Algoritma yang ditentukan sebagai string literal dalam kode. Tidak ada pemilihan algoritma berbasis konfigurasi. |
| **Algoritma yang Terkunci Protokol** | Beberapa protokol menyematkan algoritma tertentu dalam spesifikasi mereka (misalnya, RADIUS menggunakan MD5 untuk Response-Authenticator). Peningkatan memerlukan perubahan versi protokol, yang memerlukan adopsi ekosistem yang luas. BlastRADIUS (CVE-2024-3596) mengeksploitasi ketergantungan MD5 RADIUS. | Standar protokol yang mewajibkan algoritma tertentu. Penerapan protokol lama. |
| **Pengikatan Algoritma Format Data** | Data terenkripsi yang disimpan dengan metadata algoritma (misalnya, header JWE, pengenal algoritma CMS). Ketika algoritma sudah tidak direkomendasikan, semua data yang disimpan harus di-enkripsi ulang—sebuah pekerjaan operasional yang sangat besar untuk database, backup, dan arsip. | Penyimpanan data terenkripsi berumur panjang. Tidak ada otomasi re-enkripsi. |

### §8-3. Risiko Migrasi Post-Quantum

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Harvest Now, Decrypt Later (HNDL)** | Musuh merekam lalu lintas terenkripsi saat ini untuk dekripsi di masa depan oleh komputer kuantum. Semua session yang menggunakan pertukaran kunci RSA atau ECDH rentan terhadap dekripsi retrospektif setelah komputer kuantum yang relevan secara kriptografis ada. (Lihat `tls-security.md` §10-1 untuk perlakuan HNDL khusus TLS.) | Data apa pun dengan persyaratan kerahasiaan jangka panjang yang dienkripsi dengan algoritma non-PQ. Musuh tingkat negara dengan kemampuan tangkapan lalu lintas skala besar. |
| **Kesalahan Implementasi Hybrid** | Menggabungkan algoritma klasik dan post-quantum (misalnya, X25519 + ML-KEM) menciptakan attack surface baru: penggabungan shared secret yang salah, validasi public key PQ yang hilang, atau fallback ke mode klasik-saja ketika negosiasi PQ gagal. | Implementasi pertukaran kunci hybrid. Adopsi PQ awal tanpa dukungan library yang matang. |
| **Dampak Ukuran Tanda Tangan PQ** | Tanda tangan ML-DSA (Dilithium) berukuran ~2,5KB (vs. ~256B untuk ECDSA). Dalam protokol seperti TLS, ini meningkatkan ukuran handshake, berpotensi menyebabkan fragmentasi dan ketidakcocokan middlebox. (Lihat `tls-security.md` §10-2 untuk perlakuan PQ khusus TLS.) | Tanda tangan PQ dalam protokol yang sensitif terhadap latensi. Jalur jaringan dengan MTU kecil atau middlebox yang tidak toleran. |
| **Kesenjangan Inventaris Kriptografi** | Organisasi tidak dapat bermigrasi apa yang tidak dapat mereka inventarisasi. Ketergantungan kriptografi yang tidak diketahui dalam library pihak ketiga, sistem embedded, dan aplikasi lama menciptakan blind spot. PCI DSS v4.0 mensyaratkan inventaris kriptografi yang terdokumentasi setelah Maret 2025. | Organisasi besar dengan tumpukan teknologi yang heterogen. Tidak ada alat crypto discovery otomatis yang diterapkan. |

---

## §9. Kelemahan Implementasi End-to-End Encryption (E2EE)

E2EE dalam aplikasi web (pesan, penyimpanan cloud, alat kolaborasi) memperkenalkan kriptografi sisi klien yang sangat sulit untuk diimplementasikan dengan benar.

### §9-1. Manajemen Kunci dalam E2EE

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Distribusi Kunci Tanpa Autentikasi** | Server mendistribusikan encryption key ke klien tanpa autentikasi kriptografi. Server yang berbahaya atau telah disusupi menggantikan kuncinya sendiri, mendapatkan akses ke semua konten terenkripsi di masa depan. Ditemukan dalam penyimpanan cloud E2EE Sync dan pCloud (ETH Zurich, 2024). | Distribusi kunci melalui API server tanpa verifikasi out-of-band. Tidak ada transparansi kunci atau perbandingan safety number. |
| **Bypass Upacara Verifikasi Kunci** | Sistem E2EE yang menawarkan tetapi tidak mewajibkan verifikasi kunci (perbandingan fingerprint, safety number) memungkinkan server secara diam-diam melakukan substitusi kunci untuk mayoritas pengguna yang tidak pernah memverifikasi. | Verifikasi kunci yang opsional. Tidak ada pengikatan kriptografi otomatis antara distribusi dan verifikasi kunci. |
| **Backdoor Key Escrow / Recovery** | Sistem E2EE dengan key recovery yang dimediasi server (misalnya, key recovery berbasis password) mengekspos encryption key ke server selama recovery, merusak jaminan E2EE. Server (atau penyerang yang menyusupi alur recovery) mendapatkan akses ke semua data terenkripsi. | Mekanisme key recovery yang melibatkan akses server ke material kunci plaintext. Recovery berbasis password tanpa key wrapping sisi klien. |

### §9-2. Implementasi Crypto Sisi Klien

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **IV / Nonce Tetap dalam Enkripsi File** | Seafile E2EE menggunakan initialization vector yang tetap untuk enkripsi AES semua chunk file. Dikombinasikan dengan mode CTR atau CBC, ini membocorkan informasi tentang konten file (lihat §1-3, §1-1). | IV/nonce statis yang di-hardcode atau berasal secara deterministik tanpa input khusus pesan. |
| **Integritas yang Hilang pada Chunk Terenkripsi** | Mengenkripsi chunk file tanpa autentikasi per-chunk memungkinkan server untuk menyusun ulang, menduplikasi, atau mengganti chunk. Klien mendekripsi sampah atau konten yang dipilih penyerang untuk chunk individual tanpa mendeteksi manipulasi. | Enkripsi di level chunk tanpa MAC di level chunk. Server dipercaya untuk pengurutan dan integritas chunk. |
| **Kebocoran Metadata** | E2EE melindungi konten file tetapi sering mengekspos: nama file, struktur direktori, ukuran file, timestamp modifikasi, hubungan berbagi, dan pola akses. Metadata ini dapat mengungkap informasi sensitif bahkan tanpa mendekripsi konten. | Desain E2EE yang mengenkripsi konten tetapi bukan metadata. Pengindeksan sisi server untuk pencarian atau deduplikasi. |
| **Penyalahgunaan WebCrypto API** | W3C WebCrypto API (`SubtleCrypto`) menyediakan cryptographic primitive tingkat rendah di browser. Desain API-nya mengharuskan developer membuat pilihan mode/parameter yang benar. Penyalahgunaan umum: menggunakan `AES-CBC` tanpa HMAC terpisah, `RSA-OAEP` dengan SHA-1 default, atau `ECDSA` dengan nonce `Math.random()` alih-alih RNG internal. | Implementasi E2EE berbasis browser. Developer yang tidak familiar dengan pemilihan cryptographic primitive. Tidak ada wrapper library crypto tingkat tinggi. |

### §9-3. Kelemahan E2EE di Level Protokol

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **File Injection / Tampering** | Layanan penyimpanan cloud E2EE yang tidak mengautentikasi metadata file memungkinkan server menyuntikkan file ke akun pengguna. File yang disuntikkan tampak sah terenkripsi bagi klien. Ditemukan di beberapa penyedia E2EE (Tresorit, Sync, pCloud, Seafile). | Metadata file (nama, jalur, info berbagi) tidak terikat secara kriptografis dengan encryption key. Server mengontrol daftar file. |
| **Downgrade ke Non-E2EE** | Aplikasi yang mendukung E2EE dan enkripsi sisi server mungkin secara diam-diam beralih ke mode non-E2EE tanpa sepengetahuan pengguna. Ini dapat terjadi selama error negosiasi protokol, skenario fallback, atau perubahan mode yang dimulai server. | Dukungan enkripsi dual-mode. Tidak ada penegakan mode E2EE-saja di sisi klien. |
| **Skalabilitas Manajemen Kunci Grup** | Pesan grup E2EE memerlukan enkripsi O(n) per pesan (fan-out sisi pengirim) atau shared group key dengan ratcheting yang kompleks. Pembaruan group key saat anggota dihapus sering diimplementasikan sebagai "buat kunci baru dan harap anggota lama tidak memiliki salinan yang ter-cache." | Grup besar dengan perubahan keanggotaan yang sering. Rotasi group key yang malas. |

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama |
|---|---|---|
| **MitM / Session Interception** | Penyerang yang berada di jaringan antara klien dan server | `tls-security.md` + §2-4 (DH/ECDH) + §1-1 (CBC) + §8-1 (downgrade) |
| **Token / Credential Forgery** | Penyerang menghasilkan material autentikasi yang valid | §2-1 (ECDSA) + §2-3 (Ed25519) + §3-1 (length extension) + §4 (PRNG) |
| **Data Exfiltration** | Mengekstrak data yang dilindungi dari penyimpanan terenkripsi atau transit | §1 (symmetric mode) + §7-2 (analisis lalu lintas) + §9 (kelemahan E2EE) |
| **Retrospective Decryption** | Lalu lintas yang direkam didekripsi kemudian (kuantum atau kompromi kunci) | §8-3 (PQC) + `tls-security.md` §1 (cipher lemah) + §5-1 (paparan kunci) |
| **Supply Chain Compromise** | Menyerang library crypto atau distribusi kunci | §6 (kerentanan parser) + §5-1 (kebocoran kunci) + §9-1 (distribusi kunci) |
| **Infrastructure Compromise** | Mengeksploitasi pemrosesan kriptografi untuk RCE, DoS, atau pivoting | §6-3 (parsing CMS) + §3-4 (PBKDF2 DoS) |

---

## Pemetaan CVE / Bounty (2024–2026)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|---|---|---|
| §2-1 (bias nonce ECDSA) | CVE-2024-31497 (PuTTY P-521) | Pemulihan SSH private key dari ~60 tanda tangan Git publik. Memengaruhi PuTTY, FileZilla, WinSCP, TortoiseGit. |
| §2-1 (timing ECDSA) | CVE-2024-13176 (OpenSSL) | Sinyal timing ~300ns pada inversi nonce ECDSA. Semua versi OpenSSL hingga 3.4. |
| §2-1 (timing ECDSA, Minerva) | CVE-2024-23342 (python-ecdsa) | Kebocoran panjang bit nonce melalui waktu penandatanganan. Private key dapat dipulihkan. |
| §2-1 (timing ECDSA, SM2) | CVE-2025-9231 (OpenSSL ARM64) | Variasi timing penandatanganan SM2. Semua OpenSSL < 3.6 pada ARM64. |
| §2-2 (RSA padding oracle) | ROBOT (2017, berkelanjutan) | ~27% Alexa Top 100 rentan. Produk F5, Citrix, Palo Alto, IBM, Cisco. (Lihat `tls-security.md` §2-1 untuk konteks TLS.) |
| §6-3 (CMS IV overflow) | CVE-2025-15467 (OpenSSL 3.x) | Stack buffer overflow pre-autentikasi dalam parsing CMS. RCE berhasil dicapai oleh JFrog. |
| §6-3 (beberapa kerentanan parser) | 12 CVE (OpenSSL, AISLE 2026) | 12 zero-day termasuk satu yang ada sejak 1998. Subsistem QUIC, PKCS#12, CMS, TLS 1.3, BIO. |
| §3-2 (collision MD5) | CVE-2024-3596 (BlastRADIUS) | Pemalsuan RADIUS Response-Authenticator melalui chosen-prefix collision MD5. |
| §3-4 (pemotongan bcrypt) | Insiden Okta (Okt 2024) | Collision cache key melalui pemotongan bcrypt 72 byte. Authentication bypass untuk password >72 byte. |
| §9-2 (implementasi E2EE) | ETH Zurich (2024) | Sync, pCloud, Icedrive, Seafile: kunci tanpa autentikasi, IV tetap, injeksi file. |
| §1-2 (CBC padding oracle) | CVE-2021-31196 (Microsoft Exchange) | ProxyOracle: CBC padding oracle AES pada cookie FBA Exchange. Dirantai dengan reflected XSS (CVE-2021-31195) untuk mencuri cookie HttpOnly melalui redirect SSRF, kemudian dekripsi offline memulihkan kredensial plaintext. 12 byte pertama dapat diprediksi (`Basic ` dalam UTF-16), menghilangkan kebutuhan pemulihan IV. |

---

## Alat Deteksi

### Alat Ofensif / Pengujian

| Alat | Cakupan Target | Teknik Inti |
|---|---|---|
| **PadBuster** | CBC padding oracle | Eksploitasi padding oracle otomatis untuk cookie/token terenkripsi CBC |
| **jwt_tool** | Implementasi JWT | Algorithm confusion, algoritma none, header injection, brute-force kunci |
| **hashcat / John the Ripper** | Pemecahan hash password | Brute-force dipercepat GPU untuk bcrypt, PBKDF2, scrypt, Argon2 |
| **nonce-disrespect** | GCM nonce reuse | Deteksi penggunaan ulang nonce GCM di seluruh koneksi |
| **ECDSA Nonce Analysis Scripts** | ECDSA nonce reuse/bias | Pemulihan kunci berbasis lattice dari nonce yang bias atau digunakan ulang |

*Untuk alat khusus TLS (testssl.sh, SSLyze, robot-detect, Raccoon Attack Tool), lihat bagian Alat Deteksi `tls-security.md`.*

### Alat Defensif / Analisis Statis

| Alat | Cakupan Target | Teknik Inti |
|---|---|---|
| **CryptoGuard** | Penyalahgunaan crypto API Java | Slicing program backward/forward yang peka konteks/field. 6 kategori CWE. |
| **CogniCrypt / CrySL** | Penyalahgunaan crypto Java/Android | Bahasa domain-spesifik CrySL yang mendefinisikan pola penggunaan crypto API yang benar. Plugin Eclipse. |
| **Semgrep (aturan crypto)** | Penyalahgunaan crypto multi-bahasa | Deteksi berbasis pola untuk pemanggilan fungsi crypto yang tidak aman (mode ECB, hash lemah, kunci hardcoded) |
| **CRYLOGGER** | Runtime Android/Java | Analisis dinamis: mencatat parameter crypto API selama eksekusi, memvalidasi secara offline |
| **Cryptosense Analyzer** | Inventaris crypto enterprise | Memetakan semua operasi kriptografi di seluruh portofolio aplikasi. Kepatuhan PCI DSS 4.0. |

---

## Ringkasan: Prinsip Inti

### Properti Fundamental

Kerentanan implementasi kriptografi web muncul dari **asimetri struktural**: algoritma kriptografi memberikan jaminan keamanan hanya dalam kondisi matematis yang tepat (nonce unik, operasi dalam waktu konstan, ciphertext yang terotentikasi, parameter yang divalidasi), tetapi ekosistem pengembangan web secara sistematis melanggar kondisi-kondisi ini. Kesenjangan antara "aman secara matematis" dan "diimplementasikan dengan aman" adalah di mana seluruh taksonomi ini berada.

### Mengapa Perbaikan Inkremental Gagal

Setiap kerentanan dalam taksonomi ini memiliki "perbaikan" yang mudah secara terpisah—gunakan AEAD alih-alih CBC, gunakan perbandingan waktu konstan, validasi sertifikat dengan benar. Namun kelas kerentanan ini tetap ada karena:

1. **Inversi abstraksi**: Framework web tingkat tinggi mengekspos cryptographic primitive tingkat rendah (AES-CBC, RSA-OAEP, nonce ECDSA) yang memerlukan pengetahuan spesialis untuk digunakan dengan benar. WebCrypto API adalah contoh kanonik dari desain yang tidak ramah developer.
2. **Default yang tidak aman**: Library dan API secara default menggunakan opsi yang tidak aman (tidak ada validasi sertifikat, algoritma lemah, operasi non-waktu-konstan) dan memerlukan opt-in eksplisit untuk keamanan.
3. **Kegagalan komposisi**: Komponen individu mungkin aman, tetapi komposisinya (MAC-then-Encrypt, enkripsi tanpa integritas, penggunaan ulang kunci lintas protokol) memperkenalkan kerentanan yang tidak dimiliki komponen mana pun secara terpisah.
4. **Hutang migrasi**: Cryptographic agility memerlukan infrastruktur yang tidak dimiliki sebagian besar aplikasi. Ketika algoritma sudah tidak direkomendasikan (MD5, SHA-1, RC4, 3DES), migrasinya lambat, tidak lengkap, dan menciptakan kerentanan transisi.

### Solusi Struktural

Satu-satunya pendekatan yang tahan lama adalah **menaikkan level abstraksi**: developer seharusnya berinteraksi dengan API berorientasi tujuan ("enkripsi pesan ini untuk penerima ini dengan integritas dan autentikasi") daripada API berorientasi primitive ("enkripsi dengan AES-256-GCM menggunakan kunci ini dan nonce ini"). Library seperti libsodium, Tink, dan age mencerminkan pendekatan ini. Dikombinasikan dengan inventaris kriptografi otomatis (§8-3), manajemen kunci berbasis hardware (§5), dan penegakan kekuatan algoritma minimum di level protokol (§8-1), attack surface dapat dikurangi—meskipun tidak pernah dihilangkan—secara struktural.

---

## Referensi

- Weiss, Y. dkk. "What Was Your Prompt? A Remote Keylogging Attack on AI Assistants." USENIX Security 2024.
- Heftrig, E. dkk. "KeyTrap: Denial-of-Service Attacks against DNSSEC." ACM CCS 2024. CVE-2023-50387.
- McDonald, G. dkk. "Whisper Leak: Side-Channel Attack on Remote Language Models." 2025.
- JFrog Security Research. "CVE-2025-15467: OpenSSL CMS AuthEnvelopedData Buffer Overflow." 2025.
- AISLE. "AI-Discovered 12 OpenSSL Zero-Days." Januari 2026.
- OpenSSL Security Advisory. CVE-2024-13176 (timing ECDSA), CVE-2025-9231 (timing SM2). (Untuk CVE OpenSSL khusus TLS, lihat `tls-security.md`.)
- PuTTY Advisory. CVE-2024-31497 (bias nonce P-521).
- python-ecdsa Advisory. CVE-2024-23342 (serangan timing Minerva).
- Böck, H. dkk. "Return Of Bleichenbacher's Oracle Threat (ROBOT)." USENIX Security 2018.
- Albrecht, M. & Heninger, N. "On Boundedly Generated Subgroups of Finite Groups." Crypto 2024.
- ETH Zurich. "End-to-End Encrypted Cloud Storage: Security Analysis." 2024.
- NIST CSWP 39. "Considerations for Achieving Crypto Agility." Desember 2025.
- NIST IR 8547. "Transition to Post-Quantum Cryptography Standards." 2024.
- Miles, N. dkk. "Methods and Benchmark for Detecting Cryptographic API Misuses in Python." IEEE TSE 2024.
- Cloudflare. "State of Post-Quantum Internet." 2025.
- PortSwigger Research. Top 10 Web Hacking Techniques, TLS Padding Oracle Prevalence, Ed25519 Library Analysis.
- HashiCorp Advisory. CVE-2024-5798 (Vault JWT audience bypass).
- cjwt Advisory. CVE-2024-54150 (Algorithm confusion).
- fast-jwt Advisory. CVE-2025-30144 (Issuer claim bypass).
- Proofpoint / IOActive. "Authentication Downgrade Attacks: MFA Bypass." 2025.
- MystenLabs. "ed25519-unsafe-libs: Vulnerable Ed25519 Implementations." GitHub.

---

*Dokumen ini dibuat untuk tujuan riset keamanan defensif dan pemahaman kerentanan.*
