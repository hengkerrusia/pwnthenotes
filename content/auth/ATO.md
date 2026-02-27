---
title: Account Takeover
---
# Taksonomi Mutasi/Variasi Registrasi & Account Takeover

---

## Struktur Klasifikasi

Registrasi & Account Takeover (Reg/ATO) adalah kelas kerentanan yang mencakup seluruh siklus hidup akun — mulai dari pembuatan akun, autentikasi, dan pemeliharaan sesi hingga pemulihan akun. Ini bukan satu kerentanan tunggal, melainkan attack surface yang kompleks yang muncul di berbagai titik transisi dari **authentication state machine**.

Taksonomi ini disusun berdasarkan tiga sumbu:

- **Sumbu 1 — Target Mutasi**: Komponen mana dari siklus hidup akun yang sedang dimanipulasi. Ini membentuk struktur utama dokumen.
- **Sumbu 2 — Jenis Perbedaan**: Jenis kegagalan verifikasi atau inkonsistensi state apa yang memungkinkan serangan. Ini adalah sumbu lintas-sektor yang berlaku di semua kategori.
- **Sumbu 3 — Skenario Serangan**: Bagaimana mutasi tersebut dimanfaatkan dalam eksploitasi di dunia nyata.

### Sumbu 2 — Jenis Perbedaan (Klasifikasi Lintas-Sektor)

| Kode | Jenis Perbedaan | Deskripsi |
|------|-----------------|-----------|
| **D1** | Identity Verification Gap | Ketiadaan atau bypass terhadap verifikasi kepemilikan email/nomor telepon |
| **D2** | State Management Flaw | Persistensi abnormal atau non-invalidasi sesi, token, atau transisi state |
| **D3** | Token/Secret Weakness | Prediktabilitas token, entropi rendah, atau adanya jalur kebocoran |
| **D4** | Logic Flow Bypass | Melewati langkah-langkah atau memanipulasi urutan alur autentikasi/verifikasi |
| **D5** | Race Condition / TOCTOU | Mengeksploitasi jeda waktu antara validasi dan penggunaan |
| **D6** | Trust Boundary Violation | Server mempercayai data dari client-side secara tanpa syarat |
| **D7** | Channel Compromise | Kompromi terhadap saluran autentikasi itu sendiri (SMS, email, deep link) |

---

## §1. Serangan Registrasi / Pembuatan Akun

Fase pembuatan akun adalah **medan pertempuran pra-autentikasi** dari ATO. Penyerang bisa saja membuat akun lebih dulu di layanan yang belum didaftarkan korban, atau mengeksploitasi kelemahan dalam proses registrasi itu sendiri.

### §1-1. Pre-Account Takeover

Kelas serangan di mana penyerang membuat akun **sebelum korban mendaftar**, mempertahankan akses ke akun tersebut ketika korban kemudian mendaftar. Lima varian telah diklasifikasikan secara sistematis oleh Microsoft Research pada tahun 2022.

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Classic-Federated Merge** | Penyerang membuat akun klasik (berbasis password) dengan email korban → korban mendaftar via OAuth/SSO dengan email yang sama → layanan secara otomatis menggabungkan kedua akun, memberikan akses kepada penyerang | Layanan secara otomatis menggabungkan akun klasik/federated berdasarkan email | D1, D4 |
| **Unexpired Session Identifier** | Penyerang membuat akun dengan email korban dan mempertahankan sesi login → korban memulihkan akun via password reset → sesi penyerang yang sudah ada tidak diinvalidasi | Password reset tidak menginvalidasi sesi yang sudah ada | D2 |
| **Trojan Identifier** | Penyerang membuat akun dengan email korban dan menambahkan faktor autentikasi sekunder (nomor telepon, email cadangan) → korban memulihkan akun tetapi faktor sekunder penyerang tetap ada | Pemulihan akun tidak menghapus metode autentikasi sekunder yang sudah ada sebelumnya | D2, D4 |
| **Unexpired Email Change** | Penyerang membuat akun dengan email korban → memulai permintaan perubahan email (tanpa menyelesaikan konfirmasi) → korban memulihkan akun → penyerang menyelesaikan link konfirmasi perubahan email yang masih tertunda untuk mengubah email ke miliknya | Password reset tidak menginvalidasi token perubahan email yang tertunda | D2, D3 |
| **Non-Verifying IdP** | Penyerang membuat akun melalui IdP yang tidak memverifikasi kepemilikan email → korban mendaftar via jalur klasik dengan email yang sama → layanan mempercayai email IdP sebagai terverifikasi dan menggabungkan akun | IdP tidak memverifikasi kepemilikan email dan layanan mempercayainya secara buta | D1, D6 |

### §1-2. Bypass Verifikasi Email

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Response Manipulation** | Memodifikasi status code respons server atau field JSON untuk mengaktifkan akun tanpa verifikasi email (misalnya `{"verified": false}` → `{"verified": true}`) | Server bergantung pada respons client untuk state verifikasi | D6 |
| **Forced Browsing** | Mengakses langsung halaman/API pasca-verifikasi tanpa menyelesaikan verifikasi email | Server tidak memeriksa state verifikasi pada setiap permintaan | D4 |
| **Activation Endpoint Direct Call** | Memanggil langsung endpoint API aktivasi tanpa token email untuk mengaktifkan akun | Verifikasi token tidak diimplementasikan pada endpoint aktivasi | D4 |
| **Email Normalization Differential** | Mengeksploitasi perbedaan normalisasi dalam alamat email — case sensitivity, titik (.), tag plus (+) — untuk melewati verifikasi (misalnya `victim@gmail.com` vs `Victim@Gmail.com`) | Logika normalisasi email yang tidak konsisten antara registrasi dan verifikasi | D1 |
| **Verification Link Reuse** | Menggunakan ulang link verifikasi yang sudah dipakai sebelumnya untuk perubahan email baru | Token verifikasi tidak terikat pada alamat email tertentu | D3 |
| **Auto-Login on Registration** | Auto-login saat registrasi selesai tanpa verifikasi email; penyerang mendaftar dengan email korban dan langsung mendapatkan sesi | Verifikasi email terpisah dari alur registrasi | D1, D4 |

### §1-3. Mass Assignment / Parameter Injection

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Role Escalation** | Menambahkan field hak akses seperti `role=admin` atau `isAdmin=true` ke dalam permintaan registrasi untuk membuat akun administrator | Server mengikat semua field request body ke objek | D6 |
| **Organization/Tenant Injection** | Memanipulasi parameter `org_id` atau `tenant_id` saat registrasi untuk bergabung ke organisasi lain sebagai admin | Isolasi tenant yang tidak memadai dalam arsitektur multi-tenant | D6 |
| **Account State Manipulation** | Menyuntikkan field state seperti `verified=true`, `active=true`, atau `email_confirmed=true` ke dalam permintaan registrasi | Field state akun tidak dilindungi oleh allowlist | D6, D4 |
| **Hidden Field Injection** | Menambahkan parameter API yang tidak terekspos di frontend (misalnya `credit_balance`, `subscription_tier`) ke dalam permintaan registrasi | Skema API menerima lebih banyak field daripada yang ditampilkan di form client | D6 |

### §1-4. Race Condition pada Registrasi

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Duplicate Account Creation** | Mengirimkan permintaan registrasi secara bersamaan dengan email/username yang sama untuk melewati constraint keunikan dan membuat akun duplikat | Pemeriksaan keunikan dilakukan di level aplikasi, bukan di level transaksi DB | D5 |
| **Invitation Code Reuse** | Mengirimkan beberapa permintaan registrasi secara bersamaan dengan satu kode undangan sekali-pakai untuk menggunakannya berulang kali | Konsumsi kode undangan bukan operasi atomik | D5 |
| **Promo/Coupon Double-Spend** | Menerapkan kode promo beberapa kali saat registrasi melalui race condition | Pemrosesan logika konsumsi kupon yang tidak atomik | D5 |
| **Registration Flooding** | Secara otomatis membuat akun palsu dalam jumlah besar untuk menguras sumber daya layanan atau melakukan enumerasi pengguna | Tidak ada rate limiting / CAPTCHA pada endpoint registrasi | D4 |

---

## §2. Serangan Password Reset / Pemulihan Akun

Password reset adalah **titik masuk paling sering** untuk ATO. Kerentanan muncul di setiap tahap alur reset — dari pembuatan token, pengiriman, validasi, hingga penerapannya.

### §2-1. Kelemahan Pembuatan Token

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Predictable Token (Timestamp-based)** | Token reset dibuat sebagai hash MD5/SHA1 dari timestamp, sehingga dapat diprediksi | Tidak menggunakan CSPRNG; token dibuat berdasarkan timestamp | D3 |
| **Sequential Token** | Token dibuat sebagai integer sekuensial atau mengikuti pola yang berurutan | Tidak ada keacakan dalam pembuatan token | D3 |
| **Short Token / Low Entropy** | Panjang token sangat pendek (misalnya angka 4-6 digit), sehingga brute-force menjadi layak | Entropi token yang tidak mencukupi + rate limiting yang tidak memadai | D3 |
| **Token Reuse Across Users** | Token reset yang dibuat dalam jendela waktu yang sama identik untuk pengguna yang berbeda | Tidak ada seed unik per pengguna dalam pembuatan token | D3 |
| **UUID v1 Token** | UUID v1 (berbasis timestamp + alamat MAC) digunakan sebagai token reset, sehingga dapat diprediksi | UUID v1 digunakan alih-alih UUID v4 berbasis CSPRNG | D3 |

### §2-2. Pengiriman Token / Kebocoran

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Host Header Poisoning** | Penyerang memodifikasi header `Host` dalam permintaan reset ke domain miliknya → server membuat link reset yang mengarah ke domain tersebut → korban mengklik dan token dikirimkan ke server penyerang | Server menggunakan header `Host` untuk membuat URL reset | D3, D6 |
| **Referer Header Leakage** | Token dalam URL bocor melalui header `Referer` ketika halaman reset memuat resource eksternal (gambar, skrip, tautan) | Token reset ada di parameter URL + pemuatan resource eksternal | D3 |
| **Response Body Exposure** | Token reset disertakan dalam body respons API, terekspos ke client | Token dikembalikan dalam respons HTTP, tidak hanya via email | D3 |
| **X-Forwarded-Host Poisoning** | Memanipulasi header proxy seperti `X-Forwarded-Host` atau `X-Original-URL` untuk mengubah host URL reset | Penentuan host di balik reverse proxy mempercayai header proxy | D3, D6 |
| **Password Reset via API Response** | Token reset atau password sementara langsung disertakan dalam respons API | Eksposur informasi debug untuk kemudahan pengembangan | D3 |

### §2-3. Bypass Validasi Token

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **User ID Manipulation** | Mengubah parameter `user_id` dalam URL reset ke ID pengguna lain untuk mereset passwordnya | Token tidak terikat pada pengguna tertentu | D4, D6 |
| **Token-User Decoupling** | Token reset dan identifier pengguna diteruskan sebagai parameter terpisah, memungkinkan kombinasi token milik sendiri yang valid + ID pengguna lain | Pengikatan pengguna tidak diverifikasi saat validasi token | D4 |
| **Empty/Null Token** | Meneruskan string kosong, `null`, atau `undefined` sebagai nilai token untuk melewati validasi | Penanganan exception yang tidak memadai untuk token kosong (misalnya `if (token == storedToken)` di mana storedToken bernilai null) | D4 |
| **Token Expiration Bypass** | Token yang sudah kedaluwarsa tetap diproses sebagai valid | Validasi kedaluwarsa token tidak diimplementasikan atau ketidakcocokan waktu server | D2, D3 |
| **Brute-Force Token** | Melakukan brute-force token pendek (4-6 digit) untuk menemukan token yang valid (kasus yang terdokumentasi berhasil dengan ~60.000 permintaan) | Tidak ada rate limiting pada endpoint validasi token | D3 |
| **Token Not Invalidated After Use** | Token reset yang sudah digunakan tidak diinvalidasi dan dapat digunakan kembali | Penghapusan/invalidasi token setelah digunakan tidak diimplementasikan | D2 |

### §2-4. Logic Flaw Alur Password Reset

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **MFA Step Skip** | Melewati langkah verifikasi MFA dalam alur reset dan langsung mengakses langkah perubahan password | Setiap langkah dalam alur reset tidak memverifikasi penyelesaian langkah sebelumnya | D4 |
| **Email Parameter Override** | Memodifikasi parameter `email` dalam permintaan reset ke email penyerang agar token reset dikirimkan ke kotak masuk penyerang | Server menggunakan parameter email dari permintaan alih-alih email yang terikat pada sesi/token | D6 |
| **Password Reset via OAuth Chain** | Mengeksploitasi secara silang alur OAuth "lupa password" dan alur reset standar untuk melewati autentikasi | Tidak ada isolasi state antara callback OAuth dan alur password reset | D4 |
| **Account Recovery Question Bypass** | Jawaban pertanyaan keamanan kosong, tidak case-sensitive, atau dapat ditebak dari informasi publik | Kelemahan inheren dari pemulihan akun berbasis pertanyaan keamanan | D1 |
| **Tokenless Direct Reset** | Endpoint password reset menerima email/username dan password baru secara langsung tanpa memerlukan token reset — penyerang mengirimkan identifier target untuk menetapkan password sembarang | Alur reset tidak memiliki langkah verifikasi token; endpoint perubahan password hanya mempercayai identifier yang disuplai pengguna | D4 |

---

## §3. Serangan Manajemen Sesi

Sesi adalah **representasi runtime** dari state autentikasi. ATO dapat terjadi di setiap tahap siklus hidup token sesi — pembuatan, pengiriman, pemeliharaan, dan invalidasi.

### §3-1. Session Fixation

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **URL-based Fixation** | Penyerang mengirimkan korban URL yang berisi session ID yang diketahuinya → korban login melalui URL tersebut → penyerang mengakses sesi terautentikasi menggunakan session ID yang sama | Session ID tidak di-regenerasi saat login | D2 |
| **Cookie-based Fixation** | Menetapkan cookie sesi yang diketahui penyerang di browser korban melalui XSS atau kerentanan pada domain terkait | XSS pada subdomain + session ID tidak di-regenerasi | D2 |
| **Cross-Subdomain Fixation** | Menetapkan cookie domain induk dari subdomain terkait untuk mem-fix sesi aplikasi target | Konfigurasi domain cookie wildcard | D2 |

### §3-2. Session Hijacking

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **XSS-based Token Theft** | Mengeksfiltrasi token sesi dari `document.cookie` atau `localStorage` melalui Stored/Reflected XSS | Kerentanan XSS + flag HttpOnly tidak disetel | D7 |
| **Cookie Theft via Malware** | Malware infostealer mengekstrak cookie sesi dari browser dan mengirimkannya ke penyerang | Keamanan endpoint yang tidak memadai | D7 |
| **Network-level Interception** | Menangkap token sesi melalui network sniffing pada komunikasi tidak terenkripsi (HTTP) | HTTPS tidak diterapkan atau flag Secure tidak disetel | D7 |
| **Token Replay / Pass-the-Cookie** | Menggunakan kembali token sesi yang dicuri di browser penyerang untuk melewati autentikasi (juga melewati MFA) — 147.000 serangan token replay terdeteksi oleh Microsoft pada tahun 2024 | Token sesi tidak terikat pada perangkat/IP | D2 |
| **Citrix-style Session Theft** | Langsung meng-query/mencuri cookie sesi pengguna lain melalui kerentanan sisi server (kasus pelanggaran MITRE 2024) | Kerentanan sisi server yang memungkinkan akses ke session store | D7 |

### §3-3. Eksploitasi State Sesi

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Session Non-Invalidation on Password Change** | Sesi yang ada tidak diinvalidasi setelah perubahan/reset password, memungkinkan penyerang mempertahankan akses | Invalidasi sesi penuh tidak diimplementasikan saat perubahan password | D2 |
| **Concurrent Session Abuse** | Tidak ada batas sesi bersamaan per akun, memungkinkan penyerang dan korban aktif secara simultan | Kontrol sesi bersamaan tidak diimplementasikan | D2 |
| **Session Persistence After Account Deactivation** | Sesi yang ada tetap valid bahkan setelah akun dinonaktifkan/dihapus | Invalidasi sesi tidak terhubung dengan perubahan state akun | D2 |
| **JWT None Algorithm** | Menyetel algoritma JWT ke `none` untuk membuat token valid tanpa tanda tangan | Library JWT mengizinkan algoritma `none` | D3, D4 |
| **JWT Key Confusion (RS256 → HS256)** | Menggunakan public key RS256 sebagai secret key HS256 untuk memalsukan token | Implementasi JWT mengizinkan algorithm confusion | D3 |

---

## §4. Bypass Multi-Factor Authentication

MFA adalah **pertahanan terakhir** terhadap ATO, namun kelemahan implementasi memungkinkan banyak cara bypass.

### §4-1. Bypass OTP/Kode

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **OTP Brute-Force** | Melakukan brute-force OTP 4-6 digit secara sistematis (hingga 999.999 percobaan) | Tidak ada rate limiting / account lockout pada endpoint verifikasi OTP | D3 |
| **Rate Limit Reset via Resend** | Meminta pengiriman ulang OTP mereset penghitung percobaan, memungkinkan brute-force tanpa batas | Resend OTP mereset hitungan percobaan OTP yang sudah ada | D4 |
| **OTP in Response Body** | OTP disertakan dalam body respons API, terlihat dalam traffic jaringan | OTP disertakan dalam respons untuk keperluan pengembangan/debug | D3 |
| **OTP Non-Expiration** | OTP tetap valid selamanya tanpa batas waktu, memungkinkan brute-force lambat | Waktu kedaluwarsa OTP tidak dikonfigurasi | D3 |
| **Universal/Default OTP** | Nilai tertentu (misalnya `000000`, `123456`) selalu valid sebagai OTP backdoor | OTP default untuk pengujian tetap ada di produksi | D3, D4 |
| **OTP Reuse** | OTP yang sudah digunakan tidak diinvalidasi dan dapat digunakan kembali | Invalidasi OTP setelah digunakan tidak diimplementasikan | D2 |

### §4-2. Bypass Logic Flow MFA

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Direct Dashboard Access** | Setelah autentikasi langkah 1 (password), langsung mengakses halaman pasca-autentikasi tanpa menyelesaikan langkah 2 (MFA) | Penyelesaian MFA tidak diverifikasi di sisi server pada setiap permintaan | D4 |
| **MFA Step Parameter Manipulation** | Memanipulasi parameter permintaan seperti `mfa_required=false` atau `step=3` untuk melewati langkah MFA | State MFA bergantung pada parameter client-side | D6 |
| **Response Manipulation** | Memodifikasi status code respons verifikasi MFA dari `403` → `200` | Kontrol alur berbasis kode respons di sisi client | D6 |
| **Backup Code Brute-Force** | Melakukan brute-force backup code MFA (biasanya alfanumerik 8 karakter) | Tidak ada rate limiting pada verifikasi backup code | D3 |
| **MFA Downgrade (2FA → No FA)** | Permintaan penonaktifan 2FA tidak memerlukan re-autentikasi, memungkinkan penyerang menghapus MFA setelah session hijack | Penonaktifan 2FA tidak memerlukan verifikasi kode 2FA saat ini | D4 |
| **MFA Setup Hijack** | TOTP seed terekspos dalam respons API saat setup 2FA, atau dapat diakses dari sesi lain sebelum setup selesai | Eksposur TOTP seed + isolasi sesi yang tidak memadai dalam alur setup | D3, D2 |

### §4-3. Channel Compromise MFA

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **SIM Swap** | Menipu operator untuk memindahkan nomor korban ke SIM penyerang → menerima SMS OTP — peningkatan 1.055% di Inggris pada tahun 2024 | MFA berbasis SMS + verifikasi identitas operator yang tidak memadai | D7 |
| **SS7 Interception** | Mengeksploitasi kerentanan protokol SS7 untuk mencegat SMS OTP di level jaringan | Kurangnya autentikasi/enkripsi pada SS7 (desain warisan) | D7 |
| **MFA Prompt Bombing / Fatigue** | Berulang kali mengirimkan notifikasi push persetujuan MFA kepada korban, mendorong persetujuan yang tidak disengaja atau karena kelelahan | MFA berbasis push + tidak ada batas rate notifikasi | D7 |
| **OAuth Device Code Phishing** | Menyalahgunakan alur OAuth 2.0 Device Authorization Grant untuk mengelabui korban memasukkan kode perangkat penyerang di halaman autentikasi Microsoft yang sah — digunakan secara aktif oleh aktor yang disponsori negara sejak Januari 2025 | OAuth Device Code Flow + rekayasa sosial | D7 |
| **AiTM (Adversary-in-the-Middle) Phishing** | Reverse proxy real-time (Evilginx, Modlishka, dll.) meneruskan ke situs asli sambil secara bersamaan menangkap token MFA dan cookie sesi | Proxy phishing real-time + token sesi tidak terikat pada perangkat | D7 |
| **DNS Cache Poisoning → Password Reset Interception (Kaminsky-Style)** | Meracuni MX record domain target atau DNS server mail untuk mengalihkan email password reset ke server mail yang dikontrol penyerang. Ketika korban meminta password reset, email yang berisi token reset dikirimkan ke penyerang, memungkinkan account takeover. Harus memicu permintaan reset dalam jendela TTL DNS, biasanya dikombinasikan dengan rekayasa sosial | DNS resolver rentan terhadap cache poisoning + respons DNS server mail target dapat di-spoof + alur password reset bergantung pada saluran email | D7 |

---

## §5. Serangan OAuth / SSO / Autentikasi Federasi

OAuth dan SSO membentuk **lapisan delegasi** autentikasi. Attack surface unik ada dalam manajemen state, pertukaran token, dan penautan akun selama proses delegasi.

### §5-1. Eksploitasi Alur OAuth

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **CSRF on OAuth Callback** | Parameter `state` OAuth tidak divalidasi → penyerang mengirimkan URL callback OAuth miliknya ke korban → akun korban ditautkan ke akun sosial penyerang | Parameter `state` tidak digunakan atau tidak divalidasi | D4, D6 |
| **Open Redirect in OAuth** | Validasi `redirect_uri` OAuth yang longgar membocorkan authorization code/token ke domain penyerang | Validasi redirect_uri hanya menggunakan wildcard atau sub-path | D3 |
| **Authorization Code Replay** | Authorization code yang sudah digunakan tidak diinvalidasi dan dapat digunakan kembali | Penggunaan sekali pakai authorization code tidak diterapkan | D2 |
| **Token Substitution** | Token OAuth yang diterbitkan untuk aplikasi lain digunakan untuk autentikasi di aplikasi target | Klaim `aud` (audience) token tidak divalidasi | D4 |
| **Implicit Flow Token Interception** | Access token dalam fragment (#) dari Implicit Grant bocor melalui open redirect | Penggunaan Implicit Flow + validasi redirect_uri yang tidak memadai | D3 |

### §5-2. Eksploitasi Account Linking

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Email-based Auto-Linking** | Selama login OAuth, email yang dikembalikan oleh IdP secara otomatis ditautkan ke akun yang sudah ada dengan email yang sama → penyerang menggunakan IdP yang mengembalikan email korban untuk mengakses akun yang sudah ada | Auto-linking akun berbasis email + verifikasi email IdP tidak diperiksa | D1, D6 |
| **IdP Email Unverified Trust** | Layanan mengabaikan `email_verified=false` yang dikembalikan oleh IdP dan tetap mempercayai email tersebut | Field `email_verified` dalam respons IdP tidak diperiksa | D1 |
| **Dangling OAuth Connection** | Koneksi OAuth dari akun sosial yang dihapus tetap ada di layanan; akun baru dengan social ID yang sama mengakses akun layanan yang sudah ada | Koneksi OAuth tidak di-refresh saat penghapusan/pembuatan ulang akun sosial | D2 |
| **Google Domain Ownership Change** | Ketika kepemilikan domain perusahaan berpindah, pemilik baru mengautentikasi via Google OAuth dengan email domain yang sama → mengakses akun SaaS mantan karyawan | Google OAuth mengizinkan autentikasi berbasis email domain + perubahan kepemilikan domain tidak tercermin | D1 |

---

## §6. Serangan Berbasis Kredensial

Serangan kredensial langsung merupakan **vektor ATO dengan volume tertinggi**. Pada tahun 2024, lebih dari 7 miliar kredensial beredar di dark web.

### §6-1. Credential Replay

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Credential Stuffing** | Secara otomatis mencoba kombinasi email/password yang bocor dalam skala besar terhadap layanan target — data Synthient 2025: 2 miliar email unik, 1,3 miliar password unik | Penggunaan ulang password + rate limiting yang tidak memadai | D3 |
| **Password Spraying** | Mencoba sekumpulan kecil password umum (`Password1!`, `Summer2025!`, dll.) terhadap banyak akun | Kebijakan account lockout gagal mendeteksi percobaan terdistribusi | D3 |
| **AI-Optimized Credential Selection** | Agen AI mengoptimalkan serangan dengan menganalisis pola keberhasilan sebelumnya, menargetkan domain bernilai tinggi, dan memprediksi probabilitas penggunaan ulang password | Serangan kredensial generasi berikutnya yang memanfaatkan model ML | D3 |
| **Stealer Log Exploitation** | Mengakses akun menggunakan cookie sesi + log kredensial yang dikumpulkan oleh malware infostealer | Infeksi endpoint + kredensial login yang tersimpan | D7 |

### §6-2. Varian Brute-Force

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Classic Brute-Force** | Mencoba semua kemungkinan kombinasi password terhadap satu akun | Tidak ada account lockout atau rate limiting | D3 |
| **Distributed Brute-Force** | Melakukan brute-force dari beberapa IP untuk melewati rate limiting | Hanya rate limiting berbasis IP yang diterapkan (tidak ada pembatasan berbasis akun) | D3 |
| **Username Enumeration → Targeted Attack** | Mengekstrak daftar username valid menggunakan respons diferensial dari alur registrasi/login/reset, lalu melancarkan serangan bertarget | Respons diferensial seperti "Pengguna tidak ada" vs. "Password salah" | D1 |

---

## §7. Rantai Kerentanan Client-Side

Bukan ATO secara mandiri, tetapi XSS dan CSRF berfungsi sebagai **komponen inti pembangun rantai ATO**.

### §7-1. Rantai XSS → ATO

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Stored XSS → Cookie Exfiltration** | Mengeksfiltrasi cookie sesi ke server eksternal melalui Stored XSS | XSS + flag HttpOnly tidak disetel | D7 |
| **Stored XSS → Email/Password Change** | Payload XSS memanggil API perubahan email atau password dalam konteks terautentikasi | XSS + re-autentikasi tidak diperlukan untuk operasi sensitif | D7, D4 |
| **Self-XSS + Login CSRF** | Login CSRF memaksa korban masuk ke akun penyerang, lalu Self-XSS di halaman pengaturan dieksekusi di browser korban → mencuri sesi/data korban yang sebenarnya | Self-XSS + tidak ada perlindungan CSRF pada endpoint login | D7 |
| **XSS → OAuth Token Theft** | Mencuri access token atau refresh token OAuth dari localStorage/sessionStorage melalui XSS | Token OAuth disimpan di penyimpanan yang dapat diakses JavaScript | D7 |
| **Zero-Click XSS ATO** | XSS dalam skrip eksternal atau komponen tertanam dieksekusi secara otomatis tanpa interaksi pengguna untuk mencapai ATO — dalam kasus Meta CAPI Gateway, dikombinasikan dengan whitelist CORS untuk memungkinkan Facebook ATO | XSS dalam skrip yang dimuat otomatis + misconfigurasi CORS | D7 |
| **XSS → Cross-Subdomain Cookie Bridge** | XSS pada subdomain mengeksfiltrasi cookie yang cakupannya ke domain induk (misalnya `.yelp.com`), memungkinkan session hijack pada aplikasi subdomain lain tempat cookie tersebut digunakan untuk autentikasi — menjembatani dampak XSS lintas batas subdomain | XSS pada subdomain mana pun + cookie sesi cakupannya ke domain induk (`Domain=.example.com`) | D7 |

### §7-2. Rantai CSRF → ATO

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **CSRF Email Change** | Ketika korban mengunjungi halaman penyerang, permintaan perubahan email dikirimkan secara otomatis, mengubah email akun ke email penyerang | Tidak ada CSRF token pada perubahan email + re-autentikasi tidak diperlukan | D4 |
| **CSRF Password Change** | Permintaan perubahan password tidak memiliki perlindungan CSRF dan tidak memerlukan password saat ini | Tidak diperlukan password saat ini + tidak ada CSRF token untuk perubahan password | D4 |
| **CORS Misconfiguration → Token Theft** | Kebijakan CORS yang terlalu permisif (server secara dinamis memantulkan header `Origin` di `Access-Control-Allow-Origin` dengan `Access-Control-Allow-Credentials: true`) memungkinkan panggilan API terautentikasi dan pencurian token dari situs penyerang — kasus Langflow CVE-2025-34291. Catatan: `ACAO: *` dengan kredensial diblokir oleh browser sesuai spesifikasi. | Misconfigurasi CORS + cookie `SameSite=None` | D4, D7 |

---

## §8. Serangan Kontrol Otorisasi & Parameter

Bahkan setelah autentikasi, kelemahan dalam **batasan otorisasi** memungkinkan akses ke akun lain.

### §8-1. IDOR-based ATO

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Profile IDOR** | Mengubah user ID dalam permintaan API untuk melihat profil pengguna lain (email, password hash, dll.) | Kontrol akses di level objek tidak diimplementasikan | D6 |
| **Password Change IDOR** | Mengubah user ID dalam API perubahan password untuk mereset password pengguna lain (kasus bounty $500) | Kecocokan antara pengguna sesi dan pengguna target tidak diverifikasi saat perubahan password | D6 |
| **API Key/Token IDOR** | Mengambil API key atau token autentikasi pengguna lain melalui IDOR untuk mengakses akun mereka | Kontrol akses yang tidak memadai pada endpoint manajemen API key | D6 |
| **Account Settings IDOR** | Memodifikasi pengaturan akun pengguna lain (email, MFA, akun sosial yang ditautkan, dll.) melalui IDOR | Tidak ada verifikasi otorisasi di level objek pada API perubahan pengaturan | D6 |

### §8-2. Privilege Escalation via Registration Context

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Invitation System Abuse** | Memodifikasi parameter role/permission dalam tautan undangan untuk mendaftar dengan hak yang lebih tinggi | Informasi role disertakan dalam token undangan tanpa penandatanganan | D6 |
| **Tenant Switching** | Memodifikasi identifier tenant saat registrasi/login untuk mengautentikasi sebagai pengguna organisasi lain | Isolasi multi-tenant yang tidak memadai | D6 |
| **Admin Registration Endpoint Exposure** | Endpoint registrasi khusus admin (`/admin/register`, `/api/admin/signup`) dapat diakses tanpa autentikasi — kasus bounty Shopify | Tidak ada kontrol akses yang diimplementasikan pada endpoint admin | D4 |
| **E-Commerce Checkout Session Hijack** | Endpoint modul pembayaran/checkout (misalnya `/checkout/express`, `/module/ps_checkout/ExpressCheckout`) membuat sesi terautentikasi berdasarkan email atau ID pesanan tanpa memverifikasi identitas pemohon. POST yang tidak terautentikasi dengan email korban menghasilkan sesi penuh untuk akun tersebut — alur checkout menjadi saluran autentikasi alternatif (CVE-2025-61922, CVSS 9.1) | Modul checkout membuat sesi tanpa verifikasi identitas; endpoint tidak terautentikasi | D1, D4 |

---

## §9. Serangan Passwordless / Magic Link

Autentikasi tanpa password menciptakan attack surface yang baru.

| Subtipe | Mekanisme | Kondisi Utama | Perbedaan |
|---------|-----------|---------------|-----------|
| **Magic Link Token Interception** | Mencegat token magic link dalam email melalui MITM, kompromi akun email, atau kebocoran Referer | Magic link menyertakan token dalam parameter URL + keamanan saluran email yang tidak memadai | D3, D7 |
| **Deep Link Hijacking (Mobile)** | Aplikasi berbahaya mencegat handler deep link aplikasi mobile untuk mencuri token magic link — kasus bounty $500 di Android | Verifikasi deep link yang tidak memadai + aplikasi berbahaya terpasang | D7 |
| **Magic Link URL Parameter Manipulation** | Memodifikasi parameter callback URL dalam magic link untuk mengarahkan ulang ke situs penyerang setelah autentikasi + kebocoran token | Tidak ada allowlist callback URL yang diterapkan | D3 |
| **Magic Link Non-Expiration** | Magic link tidak kedaluwarsa atau tetap valid untuk waktu yang lama (berhari-hari), memungkinkan penggunaan ulang dari arsip email | Kedaluwarsa token tidak disetel atau masa validitas yang terlalu panjang | D3 |
| **Passwordless → Password Recovery Paradox** | Mekanisme pemulihan akun dalam sistem passwordless rentan, menyebabkan ATO selama proses pemulihan | Alur pemulihan meniadakan manfaat keamanan dari passwordless | D4 |

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur / Kondisi | Kategori Mutasi Utama |
|----------|----------------------|----------------------|
| **Pre-Account Takeover** | Korban belum terdaftar di layanan + penyerang mengetahui email korban | §1-1, §5-2 |
| **Full Account Takeover** | Kontrol penuh atas akun diperoleh pasca-autentikasi | §2, §3-2, §4, §6, §7 |
| **Privilege Escalation** | Peningkatan dari pengguna biasa ke peran admin/hak tinggi | §1-3, §8-2 |
| **Credential Replay at Scale** | Serangan otomatis yang memanfaatkan data bocor dalam skala besar | §6-1, §6-2 |
| **MFA Bypass → ATO** | Akses akun setelah menghindari perlindungan MFA | §4-1, §4-2, §4-3 |
| **Session Persistence ATO** | Mempertahankan akses bahkan setelah pemilik sah mengubah password | §1-1 (Unexpired Session), §3-3 |
| **Chain Attack (Multi-Bug)** | Serangan komposit yang menggabungkan dua atau lebih kerentanan | §7-1, §7-2 + §2 atau §5 |
| **Supply Chain / Domain ATO** | Akses akun melalui perubahan kepemilikan domain atau akuisisi layanan | §5-2 (Domain Ownership Change) |

---

## Pemetaan CVE / Bounty (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|-----------------|------------|-----------------|
| §5-1 + §7-2 (CORS + CSRF + OAuth) | CVE-2025-34291 (Langflow) | Kritis — ATO + RCE. Permintaan lintas-origin memungkinkan token refresh |
| §7-1 (Zero-Click XSS → ATO) | Meta CAPI Gateway XSS (2026) | Full Facebook ATO. Rantai whitelist CORS + Stored XSS |
| §3-2 + §4-3 (Session Theft + MFA Bypass) | Pelanggaran MITRE Corporation (2024) | Kerentanan Citrix → pencurian cookie sesi → bypass MFA |
| §5-2 (Domain Ownership Change) | Google OAuth Domain Takeover | Mass SaaS ATO. Perubahan kepemilikan domain memungkinkan akses ke akun mantan karyawan |
| §4-3 (Device Code Phishing) | Kampanye UNK_SneakyStrike (2025-01) | 80.000+ akun ditargetkan, ~100 cloud tenant diserang |
| §6-1 (Credential Stuffing) | Pelanggaran Pelanggan Snowflake (2024) | Pelanggaran data masif. Kredensial bocor + MFA tidak diterapkan |
| §2-1 + §2-3 (Predictable Token + Brute-Force) | RubyGems Password Reset (2024) | ATO package manager dimungkinkan. Token berbasis MD5(timestamp) |
| §4-3 (SIM Swap) | Putusan Arbitrase T-Mobile (2024) | Ganti rugi $33 juta. Satu SIM swap yang mengakibatkan pencurian cryptocurrency |
| §8-1 (IDOR → Password Change) | Laporan Bounty HackerOne | $500. IDOR memungkinkan perubahan password untuk pengguna lain |
| §7-1 (Stored XSS + IDOR) | Label Studio GHSA-2mq9 | Full ATO. Rantai Stored XSS + IDOR melalui field custom_hotkeys |
| §1-3 (Mass Assignment) | Shopify Privilege Escalation | Pembuatan akun admin tanpa batas. Manipulasi parameter role saat registrasi |
| §1-2 (Invalid Email Registration) | HackerOne Signup Process | $3.750. Pembuatan akun dengan email tidak valid yang mengandung karakter khusus (%) |
| §6-1 (Missing Authentication) | CVE-2024-5910 (Palo Alto Expedition) | CVSS 9.3. Autentikasi hilang untuk fungsi kritis → admin ATO (ini adalah kerentanan missing-authentication, bukan Host Header Poisoning) |
| §8-2 (E-Commerce Checkout Session Hijack) | CVE-2025-61922 (PrestaShop Checkout < 5.0.5) | CVSS 9.1. Zero-click ATO melalui endpoint Express Checkout: POST yang tidak terautentikasi dengan email korban menghasilkan sesi terautentikasi |
| §3-3 (JWT None Algorithm) | CVE-2025-6023 (Grafana) | Tinggi. Perbaikan tidak lengkap → path traversal + open redirect → Full ATO |
| §3-3 + §4-2 (Session + MFA) | CVE-2025-1723 (ADSelfService Plus) | Session mismanagement memungkinkan akses tidak terotorisasi ke data enrollment pengguna saat MFA tidak diaktifkan |
| §7-1 (Self-XSS → ATO) | Facebook Self-XSS Payments | $62.500. Self-XSS dalam alur pembayaran yang dirangkai menjadi Full ATO |
| §7-1 (FXAuth Token Abuse) | Facebook Two-Click ATO | $30.000. Penyalahgunaan token FXAuth untuk two-click ATO |

---

## Tool Deteksi

### Tool Ofensif (Serangan / Pengujian)

| Tool | Cakupan Target | Teknik Inti |
|------|---------------|-------------|
| **Burp Suite** (Proxy) | Alur autentikasi penuh | Intersepsi permintaan, parameter tampering, pemindaian otomatis |
| **Evilginx** (Reverse Proxy) | Phishing AiTM | Reverse proxy penangkap token sesi/MFA secara real-time |
| **Modlishka** (Reverse Proxy) | Phishing AiTM | Pembuatan sertifikat otomatis + penangkapan sesi real-time |
| **SquarephishV2** (Phishing) | OAuth Device Code | Otomasi kampanye phishing Device Code |
| **Nuclei** (Scanner) | Pola ATO yang sudah diketahui | Pemindaian kerentanan berskala besar berbasis template |
| **ffuf / Turbo Intruder** (Fuzzer) | Rate Limiting / OTP | Pengujian brute-force berkecepatan tinggi dan race condition |
| **jwt_tool** (JWT) | Token JWT | Algoritma none, key confusion, claim tampering |
| **Autorize** (Ekstensi Burp) | IDOR / Access Control | Pengujian verifikasi otorisasi otomatis |
| **Hydra / Medusa** (Brute-Force) | Endpoint login | Brute-force password terdistribusi |

### Tool Defensif (Pertahanan / Deteksi)

| Tool | Cakupan Target | Teknik Inti |
|------|---------------|-------------|
| **Cloudflare Bot Management** | Credential Stuffing | Deteksi bot berbasis AI + analisis perilaku + threat intelligence |
| **Netacea** | Semua percobaan ATO | Mesin Intent Analytics — prediksi niat sesi |
| **Imperva ATO Protection** | Perlindungan login | Modul perlindungan login zero-latency |
| **Proofpoint ATO Protection** | Email + Akun | Threat intelligence + deteksi anomali berbasis ML |
| **Datadog ATO Protection** | Aplikasi penuh | Pemantauan perilaku runtime + pemblokiran otomatis |
| **Have I Been Pwned (HIBP)** | Kredensial yang bocor | Pencarian database email/password yang bocor |
| **Passkeys / FIDO2 WebAuthn** | Autentikasi penuh | Autentikasi berbasis hardware yang tahan phishing |

---

## Ringkasan: Prinsip Inti

### Akar Masalah: Ketidaklengkapan Authentication State Machine

Akar masalah dari kerentanan Registrasi & Account Takeover adalah bahwa **authentication state machine pada dasarnya tidak lengkap**. Akun dalam aplikasi web mengalami lusinan transisi state — pembuatan, verifikasi, autentikasi, pemeliharaan sesi, pemulihan, penautan, dan penonaktifan — dan di setiap titik transisi, invariant berikut harus terpenuhi: *"Apakah entitas yang melakukan tindakan ini adalah pemilik sah akun ini?"* Jika invariant ini terputus bahkan pada satu transisi saja, maka ATO terjadi.

### Mengapa Perbaikan Inkremental Gagal

Attack surface ATO bersifat **kombinatorial**. Fitur-fitur individual (registrasi, login, reset, OAuth, MFA) masing-masing mungkin diimplementasikan dengan benar, namun kerentanan baru muncul dari **interaksi** di antara mereka (Classic-Federated Merge, rantai OAuth + Reset, XSS + CSRF + Email Change). Selain itu, MFA — yang dianggap sebagai solusi mujarab — dapat dilewati melalui SIM Swap, proxy AiTM, brute-force OTP, dan Device Code phishing. Penyerang bisa memilih saluran yang paling lemah, sementara defender harus melindungi semua saluran.

### Solusi Struktural

Solusi struktural yang sesungguhnya berlandaskan tiga prinsip:

1. **Phishing-Resistant Authentication**: Passkeys/FIDO2 WebAuthn memastikan rahasia autentikasi tidak pernah meninggalkan perangkat dan terikat pada domain, secara struktural memblokir AiTM dan phishing.
2. **Session-Device Binding**: Mengikat token sesi secara kriptografis ke karakteristik hardware perangkat yang menerbitkannya, mencegah penggunaan ulang token setelah dicuri (Token Binding, DPoP).
3. **Atomic State Transition Verification**: Memverifikasi ulang konteks autentikasi pada setiap titik perubahan state (password reset, perubahan email, penautan OAuth, penonaktifan MFA), dan secara atomik menginvalidasi semua token/sesi terkait yang sebelumnya ada.

Hingga ketiga prinsip ini diterapkan sepenuhnya, Registrasi & Account Takeover akan terus menjadi kelas kerentanan yang paling sering terjadi dan paling berdampak.

---

## Referensi

- Microsoft Security Response Center, "Pre-hijacking Attacks on Web User Accounts" (2022)
- Sudhodanan & Paverd, "Pre-hijacked Accounts: An Empirical Study of Security Failures in User Account Creation on the Web" (USENIX Security 2022)
- PortSwigger Web Security Academy — Password Reset Poisoning, Race Conditions, OAuth
- OWASP Testing Guide — Authentication Testing, Session Management Testing
- OWASP Cheat Sheet Series — Forgot Password, Session Management, Credential Stuffing Prevention
- HackTricks — Reset/Forgotten Password Bypass, 2FA/MFA/OTP Bypass
- Proofpoint Threat Insight — "Access Granted: Phishing with Device Code Authorization" (2025)
- Positive Security — "Ransacking Your Password Reset Tokens"
- Sentry Security Blog — "Cracking Password Reset Mechanisms"
- Obsidian Security — CVE-2025-34291 Langflow Disclosure
- OPSWAT Unit 515 — Grafana CVE-2025-6023
- Microsoft MSRC — "Weaponizing Cross-Site Scripting" (2025)
- Youssef Sammouda — "Multiple XSS in Meta Conversion API Gateway" (2026)
- Bugcrowd — "Breaking the Chain: Exploiting OAuth and Forgot Password for Account Takeover"
- Keepnet Labs — "SIM Swap Fraud 2025: Stats, Legal Risks & 360° Defenses"
- Vectra AI — "The Hidden Risks of SMS-Based Multi-Factor Authentication"
- AppOmni — "How to Handle Increased Account Takeover Risks from Recent Credential Dumps" (2025)
- CVE-2025-61922: PrestaShop Checkout Express Checkout Account Takeover — https://dhakal-ananda.com.np/blogs/cve-2025-61922-analysis/
- HackerOne Reports — Berbagai pengungkapan bug bounty yang direferensikan dalam tabel CVE/Bounty

---

*Dokumen ini dibuat untuk keperluan riset keamanan defensif dan pemahaman kerentanan.*
