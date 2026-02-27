---
title: OAuth
---

## Struktur Klasifikasi

Taksonomi ini mengorganisasi seluruh permukaan serangan OAuth/OIDC berdasarkan tiga sumbu ortogonal yang diturunkan dari analisis sistematis CVE, penelitian akademik (USENIX, IEEE, BlackHat/DEF CON), tulisan praktisi, dan pengungkapan bug bounty hingga tahun 2025.

**Sumbu 1 — Target Mutasi (Utama):** Komponen struktural protokol OAuth yang dimutasi atau dieksploitasi. Sumbu ini membentuk bagian utama dokumen dalam 10 kategori tingkat atas yang mencakup alur redirect, kode otorisasi/token, identitas klien, identitas pengguna, consent/scope, sesi/state, siklus hidup token, pemilihan alur protokol, infrastruktur sisi server, serta arsitektur lintas-protokol/integrasi.

**Sumbu 2 — Jenis Ketidaksesuaian (Lintas-Bidang):** Sifat ketidakcocokan atau bypass yang diciptakan oleh setiap mutasi. Setiap teknik mengeksploitasi satu atau lebih jenis ketidaksesuaian berikut:

| Kode | Jenis Ketidaksesuaian | Deskripsi |
|------|-----------------------|-----------|
| **D1** | Bypass Validasi | Validasi `redirect_uri`, scope, atau klien tidak ada atau tidak memadai |
| **D2** | Kebingungan Identitas | Identitas pengguna, klien, atau IdP salah diatribusikan atau dipalsukan |
| **D3** | Kebocoran Token/Kode | Materi otorisasi lolos ke pihak yang tidak dimaksudkan |
| **D4** | Manipulasi State | Integritas sesi, state CSRF, atau nonce rusak |
| **D5** | Eskalasi Hak Istimewa | Izin yang diberikan melebihi yang telah diotorisasi |
| **D6** | Kebingungan Protokol | Downgrade alur, mix-up, atau ketidaksesuaian lintas-protokol |
| **D7** | Eksploitasi Temporal | Race condition, replay, atau penyalahgunaan masa hidup token |

**Sumbu 3 — Skenario Serangan (Pemetaan):** Hasil dunia nyata: pengambilalihan akun, pencurian token, akses persisten, SSRF, phishing, kompromi rantai pasok, atau pergerakan lateral. Dipetakan dalam §11.

---

## §1. Manipulasi Redirect URI

Parameter `redirect_uri` adalah target utama serangan OAuth karena mengontrol ke mana materi otorisasi (kode, token) dikirimkan. Kelemahan apa pun dalam validasi redirect URI menciptakan jalur langsung menuju pencurian kredensial.

### §1-1. Teknik Bypass Validasi

Server otorisasi harus memverifikasi bahwa `redirect_uri` dalam permintaan otorisasi sama persis dengan URI yang telah terdaftar sebelumnya. Kegagalan dalam validasi ini menciptakan kelas kerentanan OAuth yang paling luas.

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Tanpa validasi** | Server menerima nilai `redirect_uri` apa pun tanpa memeriksa URI yang terdaftar | AS tidak memiliki penegakan daftar izin | D1 |
| **Pencocokan domain saja** | Server hanya memvalidasi domain/origin, mengabaikan komponen path, query, dan fragment. Penyerang menggunakan `https://legitimate.com/attacker-controlled-path` | AS memeriksa origin tetapi bukan path lengkap | D1 |
| **Pencocokan subdomain** | Server memvalidasi `*.example.com`, memungkinkan `attacker.example.com` atau mengeksploitasi pengambilalihan subdomain | Validasi berbasis wildcard atau suffix | D1 |
| **Path traversal** | Penyerang menambahkan urutan `/../` atau `/..\` untuk keluar dari prefix path yang divalidasi, misalnya `https://client.com/callback/../attacker` | Server menormalisasi path setelah validasi | D1 |
| **Kebingungan path (diferensial parser)** | Server otorisasi dan browser tidak sepakat tentang komponen path dari redirect URI karena diferensial parser URL. AS memvalidasi path yang tampak aman, tetapi browser menginterpretasikan URI yang sama dengan path efektif yang berbeda karena perbedaan penanganan `;`, pembatas yang dikodekan, atau urutan normalisasi path — berbeda dari traversal `/../` sederhana, ini mengeksploitasi ketidaksepakatan struktural pada batas komponen path | Beberapa parser URL dalam rantai redirect dengan logika ekstraksi path yang berbeda; parser path AS ≠ parser path browser (ACM CCS, 2023) | D1, D6 |
| **Parameter pollution** | Menyuntikkan parameter `redirect_uri` duplikat; server menggunakan yang pertama untuk validasi tetapi yang terakhir untuk pengalihan (atau sebaliknya) | Penguraian parameter yang tidak konsisten | D1, D6 |
| **Bypass regex** | Mengeksploitasi pola regex yang cacat — jangkar yang hilang (`^`, `$`), titik yang tidak di-escape, atau quantifier yang tamak. Misalnya `redirect_uri=https://legitimateXcom.attacker.com` | Validasi regex kustom alih-alih pencocokan persis | D1 |
| **Manipulasi skema** | Mengubah `https://` menjadi `http://`, skema kustom (`myapp://`), atau URI `javascript:` | AS tidak menegakkan batasan skema | D1 |
| **Injeksi fragment** | Menambahkan `#fragment` ke redirect URI; beberapa server mengabaikan fragment selama validasi tetapi browser mempertahankannya selama redirect | Penanganan fragment yang tidak konsisten | D1, D3 |
| **Bypass Unicode/encoding** | Menggunakan karakter yang di-encode URL, double-encode, atau Unicode (misalnya `%2F` untuk `/`, karakter lebar penuh) untuk melewati perbandingan string | Validasi terjadi sebelum normalisasi URL | D1 |
| **Injeksi whitespace** | Menyisipkan karakter whitespace (spasi, tab, baris baru, atau whitespace Unicode) ke dalam `redirect_uri` untuk membingungkan validasi URL. Validator memperlakukan input sebagai aman atau menormalisasi whitespace berbeda dari browser/klien HTTP, menyebabkan redirect mengarah ke tujuan yang dikontrol penyerang dan membocorkan token OAuth — draw.io (2023) menunjukkan kebocoran token melalui redirect URI yang disuntikkan whitespace | Validasi URL tidak menolak atau menormalisasi whitespace tertanam; diferensial parser antara validator dan klien HTTP | D1, D3 |
| **Manipulasi port** | Menentukan port non-standar dalam `redirect_uri` ketika validasi mengabaikan nomor port, misalnya `https://legitimate.com:8443/callback` | Port tidak termasuk dalam validasi | D1 |
| **Bypass daftar izin alamat loopback** | Server otorisasi yang mengimplementasikan RFC 8252 (OAuth untuk Aplikasi Native) mengizinkan port apa pun pada alamat loopback (`127.0.0.1`, `[::1]`, `localhost`) sebagai redirect URI yang valid untuk klien native. Penyerang menjalankan server HTTP lokal pada port sembarang dan membuat `redirect_uri=http://127.0.0.1:{port}/callback`; AS menerimanya karena redirect loopback secara eksplisit diizinkan oleh spesifikasi. Dikombinasikan dengan ketidaksesuaian penguraian userinfo IPv6 (misalnya bentuk `http://[::1]`), pemeriksaan `127.0.0.1`-saja yang lebih ketat juga dapat dilewati | AS mengimplementasikan pengecualian loopback RFC 8252; korban memulai alur OAuth dengan redirect_uri penyerang yang mengarah ke localhost (penelitian OSEC "How We Broke Exchanges", 2025) | D1 |

### §1-2. Rantai Open Redirect

Ketika server otorisasi menegakkan pencocokan `redirect_uri` yang ketat tetapi aplikasi klien mengandung kerentanan open redirect, penyerang merantai keduanya untuk membocorkan materi otorisasi.

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Rantai open redirect klasik** | `redirect_uri=https://client.com/redirect?url=https://attacker.com` — kode/token mendarat di klien, lalu segera dialihkan ke penyerang | Klien memiliki endpoint open redirect di bawah domain yang terdaftar | D1, D3 |
| **Kebocoran berbasis Referer** | Setelah redirect ke klien, halaman klien memuat sumber daya eksternal; header `Referer` membocorkan kode otorisasi dari string query URL ke pihak ketiga | Halaman klien menyertakan gambar, skrip, atau piksel pelacakan eksternal | D3 |
| **Persistensi fragment dalam redirect** | Dalam implicit flow, access token ada di fragment URL (`#access_token=...`). Selama redirect sisi klien, fragment dipertahankan oleh browser dan dapat bocor ke tujuan yang dikontrol penyerang | Implicit flow + open redirect pada klien | D3 |
| **Kebocoran melalui halaman proxy** | Halaman klien dengan `postMessage` atau `window.name` yang dapat dibaca lintas-origin bertindak sebagai proxy untuk eksfiltrasi token | Klien menggunakan `postMessage` tanpa validasi origin | D3 |
| **Kebocoran melalui directory listing** | Redirect ke direktori pada klien yang menyajikan halaman indeks dengan tautan eksternal, membocorkan kode melalui Referer | Klien menyajikan konten yang dapat dikontrol pengguna di bawah path yang terdaftar | D3 |

### §1-3. Pembajakan Skema Redirect Mobile

Implementasi OAuth mobile menggunakan skema URI kustom (misalnya `myapp://callback`) yang tidak unik secara global, menciptakan peluang intersepsi.

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Tabrakan skema kustom** | Beberapa aplikasi mendaftarkan skema URI kustom yang sama; OS mengirimkan redirect ke aplikasi yang salah (berbahaya) | Android/iOS mengizinkan pendaftaran skema duplikat | D2, D3 |
| **Pembajakan Intent Filter (Android)** | Aplikasi berbahaya mendaftarkan Intent Filter yang lebih spesifik untuk URI callback OAuth, mendapatkan prioritas di atas aplikasi yang sah | Aplikasi penyerang cocok dengan URI dengan spesifisitas lebih tinggi | D3 |
| **Bypass Claimed URL** | Melewati verifikasi Android App Links atau iOS Universal Links untuk mencegat redirect berbasis HTTPS | `.well-known/assetlinks.json` atau `apple-app-site-association` yang tidak dikonfigurasi dengan benar | D3 |

---

## §2. Penanganan Authorization Code & Token

Authorization code adalah kredensial bearer yang dipertukarkan untuk token. Serangan dalam kategori ini menargetkan alur code grant, pertukaran token, dan mekanisme yang mengikat kode ke penerimanya yang dimaksudkan.

### §2-1. Intersepsi & Injeksi Authorization Code

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Intersepsi kode melalui redirect** | Penyerang mendapatkan authorization code melalui manipulasi redirect URI (§1) dan menukarkannya di token endpoint sebelum klien yang sah | Tidak ada PKCE; kode adalah kredensial bearer | D3 |
| **Injeksi kode (login CSRF)** | Penyerang memulai alur OAuth, mendapatkan kode yang terikat ke identitas mereka sendiri, lalu menyuntikkannya ke URL callback korban. Sesi korban kini terhubung ke akun penyerang | Validasi parameter `state` yang hilang atau lemah | D4 |
| **Replay kode** | Menggunakan ulang authorization code yang sebelumnya valid jika AS tidak membatalkannya setelah penggunaan pertama atau memiliki jendela waktu yang lebar | AS mengizinkan penggunaan ulang kode atau memiliki masa hidup kode yang panjang | D7 |
| **Downgrade PKCE** | Penyerang menghapus parameter `code_challenge` dari permintaan otorisasi atau memaksa fallback ke metode `plain`. Jika AS tidak mewajibkan PKCE, kode menjadi dapat disadap | AS tidak mewajibkan PKCE untuk semua klien | D6 |
| **Bypass PKCE melalui open redirect** | Bahkan dengan PKCE, jika kode bocor ke penyerang melalui open redirect pada domain klien (§1-2), penyerang dapat mencuri kode. Namun, mereka tetap memerlukan `code_verifier` — kecuali endpoint klien sendiri memproses kode secara otomatis | Klien secara otomatis menukar kode tanpa verifikasi PKCE | D1, D3 |
| **Injeksi authorization code melalui replay respons** | Penyerang menangkap respons otorisasi yang valid dari deviasi alur non-happy-path — misalnya AS mengembalikan kode valid pada jalur error, consent parsial, atau kasus tepi yang menyimpang dari RFC — dan memutar ulang seluruh URL callback terhadap sesi browser korban. Tidak seperti login CSRF (yang menggunakan kode penyerang sendiri) atau replay kode sederhana (yang menggunakan ulang kode di token endpoint), ini mengeksploitasi deviasi perilaku AS dari RFC yang membocorkan kode yang dapat digunakan melalui jalur respons tak terduga | AS mengembalikan kode valid pada jalur alur non-standar; kode tidak terikat ke sesi browser asal melalui PKCE | D3, D7 |

### §2-2. Vektor Kebocoran Token

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Paparan token implicit flow** | Access token yang dikirim dalam fragment URL dapat diakses oleh JavaScript di halaman, termasuk skrip yang disuntikkan (XSS) | Penggunaan implicit flow yang sudah usang | D3, D6 |
| **Token dalam riwayat browser** | Authorization code atau token muncul dalam URL, tersimpan dalam riwayat browser, log proxy, dan log akses server | Kode/token dikirim melalui parameter query | D3 |
| **Token melalui postMessage** | Halaman klien menggunakan `window.postMessage()` untuk berkomunikasi token lintas-origin tanpa pembatasan `targetOrigin` yang tepat | Validasi origin yang hilang dalam handler postMessage | D3 |
| **Token dalam respons error** | Server otorisasi atau klien menyertakan token/kode dalam parameter redirect error, mengeksposnya dalam log atau ke pihak ketiga | Penanganan error verbose yang mencerminkan parameter sensitif | D3 |
| **Token melalui WebSocket** | Klien mengirimkan token melalui WebSocket yang tidak terenkripsi atau ke endpoint WebSocket yang dapat diamati penyerang | Implementasi WebSocket tidak aman untuk transport token | D3 |
| **Kebocoran kode callback melalui pemblokiran navigasi** | Mekanisme pemblokiran navigasi browser (event handler `beforeunload`, `window.stop()`, iframe yang lambat dimuat) menunda atau mencegah redirect callback OAuth dari penyelesaian. Selama jeda navigasi, authorization code terlihat di URL yang tertunda, memungkinkan skrip yang dikontrol penyerang di halaman (melalui rantai open redirect atau XSS pada halaman di jalur redirect) untuk mengekstrak kode sebelum endpoint klien memprosesnya | Penyerang memiliki eksekusi skrip pada halaman dalam rantai redirect; browser mendukung intersepsi navigasi | D3 |
| **Penghentian redirect tingkat browser** | Batas sumber daya browser dan server menciptakan primitif pemblokiran redirect di luar intersepsi JavaScript: penolakan skema protokol (`about:`, URI `data:` → `about:blank#blocked`), perlindungan dangling markup (Chrome memblokir `<\t` dalam URL), overflow panjang URL (>2MB), cookie bombing (~400KB cookie yang dicakupkan ke path callback → HTTP 431), payload pemicu-WAF dalam parameter `state`, dan pembatasan laju navigasi (>200 navigasi/10 detik). URL redirect yang diblokir tetap ada dalam `navigation.entries()` Navigation API, dapat dibaca lintas-origin dari jendela opener | Penyerang dapat memicu redirect ke callback OAuth; browser menegakkan batas URL/navigasi; Navigation API tersedia (Chromium) | D3 |
| **Pemblokiran redirect berbasis sandbox** | Membuka callback OAuth di jendela yang dihasilkan dari iframe yang di-sandbox (`<iframe sandbox="allow-scripts allow-popups">`, tanpa `allow-forms` atau `allow-top-navigation`) memblokir redirect berbasis form dan navigasi sambil mempertahankan eksekusi skrip dan akses API same-origin. Authorization code tetap di URL yang tertunda, dapat diekstrak oleh skrip penyerang sebelum redirect selesai | Penyerang mengontrol iframe dengan atribut sandbox pada halaman dalam rantai redirect; sandbox mengizinkan skrip tetapi membatasi form/navigasi | D3 |

### §2-3. Serangan Token Exchange

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **CSRF token endpoint** | Penyerang mengirimkan permintaan token palsu dengan kode yang dicuri ke token endpoint server otorisasi | Token endpoint tidak memvalidasi client secret atau menggunakan klien publik | D4 |
| **Peningkatan scope saat token exchange** | Penyerang memodifikasi parameter `scope` dalam permintaan token untuk menyertakan hak istimewa yang lebih tinggi dari yang awalnya diotorisasi | AS menerima parameter scope di token endpoint tanpa membandingkan dengan otorisasi asal | D5 |
| **Brute-force client secret** | Menyerang token endpoint untuk menebak nilai client_secret untuk klien rahasia | Tidak ada pembatasan laju pada token endpoint; client secret yang lemah | D1 |

---

## §3. Identitas & Pendaftaran Klien

Identitas klien OAuth menentukan akses apa yang diterimanya. Serangan di sini menargetkan autentikasi klien, pendaftaran, dan peniruan.

### §3-1. Penyalahgunaan Dynamic Client Registration

Dynamic client registration OAuth/OIDC (RFC 7591) memungkinkan pembuatan klien secara terprogram, memperkenalkan permukaan serangan sisi server.

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **SSRF melalui `logo_uri`** | Mendaftarkan klien dengan `logo_uri` yang mengarah ke sumber daya internal; AS mengambil dan mengembalikan kontennya saat merender halaman consent | AS me-resolve `logo_uri` sisi server tanpa perlindungan SSRF | D1 |
| **SSRF melalui `jwks_uri`** | Menetapkan `jwks_uri` ke endpoint internal; AS mengambilnya saat memvalidasi assertion JWT klien | AS me-resolve `jwks_uri` tanpa batasan jaringan | D1 |
| **SSRF melalui `sector_identifier_uri`** | URL khusus OIDC ini mengarah ke array JSON dari redirect URI; AS mengambilnya selama validasi | AS me-resolve URI tanpa kontrol SSRF | D1 |
| **SSRF melalui `request_uris`** | Mendaftarkan `request_uris` yang mengarah ke sumber daya internal; AS mengambilnya saat memproses pushed authorization request | AS mendukung PAR dan me-resolve request URI | D1 |
| **XSS melalui `logo_uri` / `client_name`** | Menyuntikkan payload skrip ke dalam metadata klien yang dirender di layar consent | AS merender metadata klien tanpa sanitasi | D1 |
| **Pendaftaran redirect sembarang** | Mendaftarkan klien baru dengan redirect URI yang dikontrol penyerang, lalu menggunakan session poisoning (§6-2) untuk mengarahkan token ke klien baru | Endpoint pendaftaran terbuka tanpa persetujuan admin | D1, D4 |

### §3-2. Peniruan Klien

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Spoofing klien publik** | Karena klien publik (SPA, aplikasi mobile) tidak memiliki client_secret, pihak mana pun yang mengetahui `client_id` dapat meniru klien tersebut | Klien publik tanpa penegakan PKCE | D2 |
| **Kebocoran client secret** | Client secret yang terekspos dalam kode sisi klien, version control, atau pesan error, memungkinkan penyerang bertindak sebagai klien yang sah | Secret disimpan dalam artefak publik (bundle JS, APK mobile, repo Git) | D2, D3 |
| **Spoofing dokumen metadata client ID** | Dalam MCP dan spesifikasi terbaru yang menggunakan client ID berbasis URL, penyerang mengklaim URL metadata klien yang sah sebagai `client_id` mereka sendiri, mengikat ke redirect localhost | URL dokumen metadata digunakan sebagai client_id tanpa verifikasi kepemilikan | D2 |
| **Penyalahgunaan aplikasi first-party** | Mengeksploitasi aplikasi first-party yang telah di-pre-consent (misalnya Azure CLI, Azure PowerShell) yang memiliki izin hak istimewa tinggi di semua tenant enterprise | Aplikasi yang di-pre-consent dengan scope `Directory.ReadWrite.All` atau serupa | D2, D5 |

---

## §4. Identitas Pengguna & Claims

OAuth mendelegasikan autentikasi; OIDC memperluas dengan identity claim. Serangan di sini menargetkan cara identitas pengguna ditetapkan, diverifikasi, dan digunakan.

### §4-1. Serangan Identity Binding

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Kebingungan claim yang dapat diubah** | Aplikasi mengidentifikasi pengguna berdasarkan kolom yang dapat diubah (email, username) daripada claim `sub` yang tidak dapat diubah. Penyerang mengubah email mereka di IdP agar cocok dengan email korban di klien | Klien menggunakan `email` atau `preferred_username` sebagai pengidentifikasi utama | D2 |
| **Pengambilalihan akun sebelum pendaftaran** | Penyerang membuat akun di klien menggunakan email korban (tanpa verifikasi), lalu menunggu korban "Sign in with OAuth" — identitas OAuth bergabung dengan akun yang telah dibuat sebelumnya di bawah kendali penyerang | Klien mengizinkan pembuatan akun tanpa verifikasi email | D2 |
| **Pembajakan account linking** | Ketika klien mendukung beberapa provider OAuth, penyerang memaksa penghubungan akun IdP mereka ke akun korban yang sudah ada dengan memanipulasi alur penghubungan | Tidak ada perlindungan CSRF pada endpoint account linking | D2, D4 |
| **Bypass verifikasi email** | IdP menyediakan `email_verified: false` dalam ID token, tetapi klien mengabaikan tanda ini dan mempercayai email sebagai terverifikasi | Klien tidak memeriksa claim `email_verified` | D2 |
| **Tabrakan claim sub lintas-IdP** | IdP yang berbeda mungkin menggunakan nilai `sub` yang sama (misalnya ID numerik). Klien yang menggunakan `sub` tanpa menetapkan cakupan ke penerbit menciptakan tabrakan identitas lintas-IdP | Klien menyimpan `sub` tanpa pengikatan `iss` | D2 |
| **Over-provisioning aplikasi multi-tenant** | Aplikasi Azure AD yang terdaftar sebagai multi-tenant tanpa daftar izin tenant memungkinkan tenant Azure AD mana pun untuk mendapatkan access token yang valid untuk layanan internal. Penelitian "BingBang" Wiz (2023) menunjukkan akses tidak sah ke manipulasi hasil pencarian Bing.com dan data Office 365 melalui aplikasi Microsoft internal yang over-provisioned | Aplikasi Azure AD multi-tenant tanpa validasi tenant ID eksplisit; konfigurasi default menerima token dari semua tenant Azure | D1, D2 |

### §4-2. Injeksi Identitas

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Pemalsuan ID token** | Penyerang memalsukan ID token dengan claim sembarang jika klien tidak memvalidasi tanda tangan JWT, atau kunci penandatangan dikompromikan/lemah | Klien melewati verifikasi tanda tangan atau menggunakan `alg: none` | D2 |
| **Injeksi claim melalui userinfo** | Penyerang memodifikasi claim yang dikembalikan oleh endpoint userinfo jika klien mengambil data pengguna melalui saluran tidak aman atau tidak memvalidasinya terhadap claim ID token | Endpoint userinfo yang tidak dilindungi atau kurangnya validasi silang | D2 |
| **Audience injection** | Kelas serangan baru (2025) yang mengeksploitasi penanganan audience dalam autentikasi klien berbasis tanda tangan. AS penyerang mengklaim URI penerbit AS yang jujur sebagai token endpoint-nya; klien mengirimkan kredensial ke endpoint penyerang dengan keyakinan itu adalah AS yang jujur | Klien berinteraksi dengan beberapa instance AS dan tidak mengikat audience ke penerbit | D2, D6 |

---

## §5. Consent & Scope

Model otorisasi OAuth bergantung pada consent pengguna dan batas scope. Serangan di sini melewati consent atau meningkatkan izin yang diberikan.

### §5-1. Bypass Consent

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Consent phishing** | Penyerang membuat aplikasi OAuth yang tampak sah dengan nama yang menipu ("Security Compliance Tool", "Data Loader") dan meminta scope berbahaya melalui rekayasa sosial | Pengguna menyetujui scope yang luas tanpa memahami implikasinya | D5 |
| **Hidden consent grant** | Menggunakan izin yang didelegasikan `Directory.ReadWrite.All` untuk memanggil API `oauth2PermissionGrant`, secara terprogram memberikan izin yang didelegasikan tambahan (misalnya `RoleManagement.ReadWrite.Directory`) ke aplikasi berbahaya tanpa interaksi pengguna | Penyerang sudah memegang izin penulisan direktori | D5 |
| **Eksploitasi aplikasi yang di-pre-consent (AuthCodeFix/ConsentFix)** | Mengeksploitasi aplikasi first-party (Azure CLI, Azure PowerShell) dengan izin yang di-pre-consent secara luas di semua tenant enterprise. Penyerang mencuri kode autentikasi untuk aplikasi ini dan menukarkannya dengan token hak istimewa tinggi | Aplikasi yang di-pre-consent ada dengan scope yang terlalu luas | D5, D2 |
| **Akumulasi scope bertahap** | Meminta scope minimal pada awalnya, lalu secara bertahap meminta scope tambahan dalam alur otorisasi berikutnya. Pengguna terbiasa dan menyetujui izin yang semakin berbahaya | Aplikasi mendukung incremental consent | D5 |
| **Phishing admin consent** | Menargetkan administrator untuk memberikan `admin_consent` bagi suatu aplikasi, melewati consent per-pengguna dan memberikan akses seluruh organisasi | Organisasi target mengizinkan admin consent; admin direkayasa secara sosial | D5 |

### §5-2. Manipulasi Scope

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Injeksi parameter scope** | Memodifikasi parameter `scope` dalam permintaan otorisasi untuk menyertakan izin tambahan di luar yang biasanya diminta aplikasi | AS tidak membatasi scope yang dapat diminta per klien | D5 |
| **Peningkatan scope saat token exchange** | Menyertakan scope yang ditingkatkan dalam permintaan token yang tidak ada dalam permintaan otorisasi asal (lihat §2-3) | AS menerima dan menghormati parameter scope di token endpoint | D5 |
| **Persistensi offline access** | Menyertakan scope `offline_access` untuk mendapatkan refresh token yang memberikan akses jangka panjang di luar sesi pengguna | AS memberikan offline_access tanpa pemahaman eksplisit pengguna | D5, D7 |
| **Kombinasi scope berbahaya** | Scope yang secara individual tidak berbahaya yang menciptakan kemampuan berbahaya saat dikombinasikan (misalnya `Application.ReadWrite.All` + `AppRoleAssignment.ReadWrite.All` = eskalasi hak istimewa penuh) | Tidak ada mesin kebijakan yang mengevaluasi risiko scope yang digabungkan | D5 |

---

## §6. Manajemen Sesi & State

OAuth bergantung pada sesi browser, parameter state, dan nonce untuk menjaga integritas alur. Serangan di sini merusak pengikatan ini.

### §6-1. Serangan CSRF & State

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Parameter state yang hilang** | Tidak ada parameter `state` dalam permintaan otorisasi; penyerang memalsukan URL callback dengan authorization code mereka sendiri, menghubungkan sesi korban ke identitas penyerang | Klien menghilangkan `state` atau tidak memvalidasinya | D4 |
| **State yang dapat diprediksi** | Parameter state dapat ditebak (berurutan, berbasis timestamp, atau diturunkan dari nilai yang diketahui); penyerang menghitung nilai state yang valid sebelumnya | PRNG yang lemah atau pembuatan state yang deterministik | D4 |
| **State fixation** | Penyerang memulai alur OAuth, menangkap nilai `state`, lalu menipu korban untuk menyelesaikan alur dengan state penyerang, menyebabkan klien mengasosiasikan token yang dihasilkan dengan sesi penyerang | State tidak terikat secara kriptografis ke sesi pengguna | D4 |
| **Kebingungan state lintas-tab** | Pengguna memiliki beberapa tab terbuka; respons otorisasi dari satu alur dikonsumsi oleh sesi OAuth tab yang berbeda karena state cookie yang dibagikan | Klien menggunakan cookie (bukan penyimpanan per-tab) untuk pelacakan state | D4 |

### §6-2. Session Poisoning

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Penimpaan sesi otorisasi** | AS menyimpan parameter otorisasi (`client_id`, `redirect_uri`) dalam sesi sisi server. Permintaan bersamaan menimpa nilai yang tersimpan, menyebabkan respons dikirim ke redirect URI penyerang | AS menggunakan penyimpanan parameter berbasis sesi (bukan berbasis request-ID) | D4, D3 |
| **Mass assignment pada consent endpoint** | Mass assignment framework (misalnya Spring `@ModelAttribute`) memungkinkan penyerang untuk menyuntikkan parameter seperti `redirectUri` langsung ke permintaan konfirmasi consent, melewati validasi awal | Framework secara otomatis mengikat parameter permintaan ke objek sesi (CVE-2021-27582) | D4, D1 |
| **Cookie clobbering** | Penyerang menetapkan atau menimpa cookie dari domain terkait yang digunakan klien OAuth untuk pelacakan sesi, mengganggu validasi state | Cakupan cookie domain terkait atau kerentanan cookie tossing | D4 |

### §6-3. Nonce & Replay

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Validasi nonce yang hilang** | Klien tidak menyertakan atau memvalidasi `nonce` dalam ID token, memungkinkan replay ID token yang disadap dari sesi sebelumnya | Klien menghilangkan nonce atau melewati verifikasi | D7 |
| **Replay ID token** | Penyerang menangkap ID token yang valid (melalui intersepsi jaringan atau XSS) dan memutarnya ulang ke klien untuk mendirikan sesi terautentikasi | Tidak ada nonce; jendela `exp` yang panjang; klien tidak melacak penggunaan token | D7 |
| **Replay respons otorisasi** | Memutar ulang seluruh respons otorisasi (kode + state) jika kode belum dibatalkan dan state masih valid | AS tidak menegakkan kode satu kali pakai; klien tidak membuang state | D7 |

---

## §7. Siklus Hidup & Persistensi Token

Setelah token dikeluarkan, siklus hidupnya menciptakan permukaan serangan yang diperpanjang. Kategori ini mencakup penyalahgunaan token pasca-penerbitan.

### §7-1. Pencurian Token

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Ekstraksi token berbasis XSS** | Injeksi JavaScript mengekstrak access token dari localStorage, sessionStorage, atau variabel dalam memori | Token disimpan di lokasi yang dapat diakses browser; kerentanan XSS ada | D3 |
| **Token dari penyimpanan browser** | Access/refresh token yang disimpan dalam localStorage dapat diakses oleh skrip mana pun yang berjalan di origin yang sama, termasuk skrip pihak ketiga yang disuntikkan | Token disimpan dalam localStorage alih-alih cookie httpOnly | D3 |
| **Token dari credential store** | Mengekstrak token OAuth dari manajer kredensial OS, file konfigurasi, atau variabel lingkungan pada host yang dikompromikan | Token disimpan dalam plaintext di disk | D3 |
| **Token dari kebocoran repositori** | Token OAuth (terutama refresh token berumur panjang atau client secret) yang di-commit ke sistem version control | Secret dalam kode sumber atau file konfigurasi | D3 |
| **Token dari paparan proxy/log** | Token yang muncul dalam log server, log CDN, atau log proxy ketika dikirimkan sebagai parameter URL daripada header | Token dikirim sebagai parameter query alih-alih header Authorization | D3 |
| **Pass-the-Token** | Menggunakan access token OAuth yang dicuri secara langsung terhadap server sumber daya, melewati kebutuhan akan kredensial atau MFA | Token bearer diterima tanpa batasan pengirim | D3 |

### §7-2. Persistensi & Penyalahgunaan Token

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Persistensi refresh token** | Refresh token tetap valid selama 90+ hari. Penyerang dengan refresh token yang dicuri terus mencetak access token baru, mempertahankan akses tanpa batas | Tidak ada rotasi refresh token; masa hidup token yang panjang | D7 |
| **Persistensi device code** | Kode otorisasi perangkat mendapatkan refresh token yang bertahan di berbagai sesi; penyerang mempertahankan akses tanpa autentikasi ulang | Token device flow tidak dibatasi scope atau waktu | D7 |
| **Token tidak dicabut saat penggantian kata sandi** | Pengguna mengubah kata sandi tetapi token OAuth yang ada tetap valid, memungkinkan penyerang yang sebelumnya mencuri token untuk mempertahankan akses | AS tidak membatalkan token saat perubahan kredensial | D7 |
| **Zombie token dalam rantai pasok** | Token integrasi pihak ketiga (misalnya konektor Salesforce) tetap aktif lama setelah hubungan integrasi berakhir. Satu token integrasi yang dikompromikan memberikan akses ke ratusan lingkungan pelanggan (insiden UNC6395/Drift, 2025) | Tidak ada manajemen siklus hidup token integrasi | D7, D3 |
| **Pergerakan lateral melalui Graph API** | Menggunakan token OAuth yang dicuri untuk mengenumerasi tenant, pengguna, dan aplikasi terhubung melalui Microsoft Graph API, lalu melakukan pivot ke layanan tambahan | Token memiliki scope Graph API; lingkungan SaaS yang saling terhubung | D5, D7 |

---

## §8. Pemilihan & Kebingungan Alur Protokol

OAuth mendefinisikan beberapa jenis grant. Serangan di sini mengeksploitasi pemilihan, downgrade, atau kebingungan antara alur.

### §8-1. Eksploitasi Downgrade Alur & Deprecation

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Eksploitasi implicit flow** | Memaksa atau mengeksploitasi penggunaan implicit flow (yang sudah usang dalam OAuth 2.1) di mana token terekspos dalam fragment URL, dapat diakses oleh JavaScript dan bocor melalui Referer | Aplikasi masih mendukung implicit flow | D6, D3 |
| **Penyalahgunaan ROPC (Resource Owner Password Credentials)** | Mengeksploitasi aplikasi yang menerima username/password secara langsung, melewati UI autentikasi server otorisasi dan MFA apa pun | Aplikasi mendukung ROPC grant | D6 |
| **Downgrade PKCE** | Menghapus parameter PKCE dari permintaan otorisasi ketika AS tidak mewajibkan PKCE, kembali ke alur authorization code yang kurang aman | AS mendukung alur dengan dan tanpa PKCE | D6 |
| **Manipulasi response_type** | Mengubah `response_type` dari `code` ke `token` atau `id_token token` untuk memaksakan perilaku seperti implicit dan menerima token secara langsung | AS mendukung beberapa tipe respons untuk klien yang sama | D6, D3 |
| **OAuth Dirty Dancing** | Meminta nilai `response_type` yang tidak sepenuhnya didukung AS untuk klien tertentu (misalnya `code token`, `code id_token`). AS menolak kombinasi yang tidak didukung dan mengembalikan redirect error — tetapi respons error masih menyertakan authorization code atau token yang valid di URL redirect. Penyerang menangkap kredensial yang bocor dari redirect error melalui open redirect atau halaman yang dapat diamati penyerang dalam rantai redirect. Mengeksploitasi deviasi alur non-happy-path di mana implementasi AS mengantarkan materi otorisasi yang dapat digunakan bahkan ketika alur secara keseluruhan dianggap "gagal." PKCE tidak mencegah ini — penyerang menyiapkan `code_challenge` dalam tautan berbahaya | AS mengembalikan materi otorisasi parsial (kode atau token) dalam redirect error untuk kombinasi `response_type` yang tidak didukung; rantai redirect dapat diamati penyerang (Frans Rosén) | D6, D3 |

### §8-2. Serangan IdP Mix-Up

Ketika klien berinteraksi dengan beberapa server otorisasi, penyerang dapat membingungkan klien tentang AS mana yang mengeluarkan respons tertentu.

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Mix-up klasik** | Penyerang mengoperasikan AS berbahaya (AIdP). Klien memulai alur dengan AIdP, tetapi penyerang mengarahkan pengguna ke AS yang jujur (HIdP). Pengguna mengautentikasi di HIdP; klien mengirimkan kode yang dihasilkan ke token endpoint AIdP, memberikan penyerang kode korban | Klien berinteraksi dengan beberapa AS; tidak ada parameter `iss` dalam respons otorisasi | D6, D2 |
| **Mix-up token endpoint** | AS penyerang mendeklarasikan authorization endpoint AS yang jujur sebagai miliknya sendiri, tetapi menyediakan token endpoint-nya sendiri. Klien mengirimkan kredensial (kode + client_secret) ke token endpoint penyerang | Metadata AS tidak diverifikasi secara kriptografis | D6, D3 |
| **Kebingungan penerbit** | AS penyerang mengembalikan nilai `iss` AS yang jujur dalam metadatanya, menipu klien untuk memperlakukan token dari penerbit yang berbeda sebagai setara | Klien tidak memverifikasi `iss` terhadap AS yang awalnya dihubunginya | D6, D2 |

### §8-3. Serangan Device Authorization Grant

Alur device code (RFC 8628) telah muncul sebagai vektor serangan utama pada tahun 2024-2025, khususnya di lingkungan enterprise.

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Device code phishing** | Penyerang memulai alur otorisasi perangkat, mendapatkan kode pengguna, lalu merekayasa sosial korban (email, pesan Teams, kode QR) untuk memasukkan kode di URL otorisasi yang sah. Korban mengautentikasi dan memberikan akses ke sesi penyerang | Device flow diaktifkan; target rekayasa sosial yang rentan | D4 |
| **Bypass MFA melalui device flow** | Karena pengguna mengautentikasi langsung di halaman login AS (yang menangani MFA), perangkat penyerang menerima token dengan hak istimewa MFA-authenticated penuh tanpa pernah memiliki faktor kedua | Device flow secara desain memisahkan autentikasi dari perangkat yang meminta | D6 |
| **Kampanye device code otomatis** | Phishing otomatis berskala besar menggunakan alat seperti SquarePhish2 yang menghasilkan kode QR → redirect ke AS → email device code. Tingkat keberhasilan melebihi 50% dilaporkan dalam kampanye 2024-2025 | Infrastruktur phishing massal; target enterprise | D4 |
| **Aplikasi mimikri** | Penyerang mendaftarkan aplikasi OAuth dengan nama yang meniru alat yang sah ("Data Loader", "Security Compliance Tool", "My Ticket Portal") agar tampak dapat dipercaya dalam prompt consent | Pendaftaran aplikasi terbuka; tidak ada penegakan kebijakan penamaan | D2, D5 |

---

## §9. Endpoint & Infrastruktur Sisi Server

Server OAuth mengekspos beberapa endpoint (otorisasi, token, pendaftaran, discovery, userinfo, WebFinger) yang menghadirkan permukaan serangan tersendiri di luar alur protokol itu sendiri.

### §9-1. Serangan Discovery & Metadata

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Spoofing endpoint metadata** | Penyerang menyajikan respons `/.well-known/openid-configuration` palsu (melalui pembajakan DNS, MITM, atau poisoning cache), mengarahkan klien ke endpoint otorisasi/token berbahaya | Klien mengambil metadata melalui saluran tidak aman atau tidak melakukan pinning metadata | D2, D6 |
| **Manipulasi metadata** | Memodifikasi kolom tertentu dalam dokumen discovery (misalnya `token_endpoint`, `jwks_uri`) untuk mengarahkan alur kredensial ke infrastruktur penyerang | Endpoint metadata yang dikompromikan atau salah dikonfigurasi | D2 |

### §9-2. SSRF Endpoint Pendaftaran

(Lihat §3-1 untuk vektor SSRF dynamic client registration terperinci melalui `logo_uri`, `jwks_uri`, `sector_identifier_uri`, `request_uris`)

### §9-3. Injeksi WebFinger

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Enumerasi pengguna** | Endpoint `/.well-known/webfinger` mengembalikan HTTP 200 untuk pengguna yang ada dan 404 untuk yang tidak ada, memungkinkan enumerasi username | Endpoint WebFinger tanpa autentikasi dengan respons diferensial | D1 |
| **Injeksi LDAP melalui WebFinger** | Parameter `resource` dalam permintaan WebFinger disematkan tanpa escape ke dalam kueri LDAP. Penyerang menggunakan wildcard LDAP (`*`) dan injeksi filter untuk mengekstrak hash kata sandi karakter demi karakter | WebFinger yang didukung oleh direktori LDAP tanpa sanitasi input (CVE dalam ForgeRock OpenAM) | D1 |

### §9-4. Serangan Token Endpoint

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **SSRF token endpoint** | Jika AS me-resolve URL yang disediakan klien selama token exchange (misalnya mengambil JWKS untuk autentikasi klien), SSRF ke jaringan internal dimungkinkan | AS me-resolve URL dari assertion klien tanpa batasan jaringan | D1 |
| **Injeksi layar consent** | Menyuntikkan konten berbahaya (XSS) melalui kolom metadata klien (nama, logo, deskripsi) yang dirender di halaman consent AS | AS merender metadata klien tanpa sanitasi (CVE-2021-26715) | D1, D3 |

---

## §10. Arsitektur Lintas-Protokol & Integrasi

Penerapan OAuth modern melibatkan platform integrasi, rantai otorisasi multi-hop, dan penjembatan protokol yang memperkenalkan permukaan serangan arsitektur.

### §10-1. Serangan Platform Integrasi

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Cross-app OAuth Account Takeover (COAT)** | Dalam platform integrasi (Zapier, IFTTT, Microsoft Power Automate), aplikasi berbahaya penyerang mengeksploitasi arsitektur OAuth bersama platform untuk mencuri authorization code yang ditujukan untuk aplikasi lain. Satu klik pada tautan penyerang mengkompromikan layanan terhubung korban | Arsitektur OAuth platform tidak mengisolasi alur otorisasi per-aplikasi (CVE-2023-36019, CVSS 9.6) | D2, D3 |
| **Cross-app OAuth Request Forgery (CORF)** | Aplikasi penyerang di platform integrasi memulai tindakan tidak sah menggunakan token korban melalui penyimpanan token bersama platform | Platform tidak menegakkan isolasi token tingkat aplikasi | D4, D5 |
| **Kompromi token rantai pasok** | Integrasi SaaS pihak ketiga menyimpan token OAuth yang kemudian dikompromikan. Satu token memberikan akses ke ratusan lingkungan pelanggan (insiden UNC6395/Drift → Salesforce, 2025) | Penyimpanan token terpusat dalam middleware integrasi | D3, D7 |

### §10-2. Serangan Otorisasi MCP (Model Context Protocol)

Adopsi OAuth oleh protokol MCP (2025) memperkenalkan permukaan serangan baru dalam otorisasi agen AI.

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Injeksi authorization endpoint (CVE-2025-6514)** | Server MCP berbahaya mengembalikan `authorization_endpoint` yang dibuat dengan menyematkan perintah shell. Proxy MCP (`mcp-remote`) mengeksekusinya melalui shell sistem saat membuka browser untuk otorisasi | Proxy MCP tidak menyanitasi URL metadata OAuth yang disediakan server | D1, D6 |
| **Multi-hop confused deputy** | Dalam alur multi-hop MCP (pengguna → host AI → klien MCP → server MCP), konteks identitas dan izin hilang atau membingungkan di setiap batas, memungkinkan eskalasi hak istimewa | Rantai delegasi kompleks tanpa pengikatan otorisasi end-to-end | D5, D6 |
| **SSRF melalui Dokumen Metadata Client ID** | Server MCP mengambil metadata klien dari URL yang disediakan klien. Klien berbahaya menyediakan URL yang mengarah ke sumber daya internal | Server me-resolve URL client_id tanpa perlindungan SSRF | D1 |

### §10-3. Kebingungan Lintas-Protokol

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Kebingungan OAuth/SAML** | Sistem yang mendukung OAuth dan SAML untuk SSO mungkin memiliki pengikatan identitas yang tidak konsisten, memungkinkan penyerang untuk mengeksploitasi perbedaan dalam cara identitas ditetapkan | SSO dual-protokol dengan jalur resolusi identitas yang berbeda | D2, D6 |
| **Kebingungan jenis token** | Menggunakan access token di mana ID token diharapkan (atau sebaliknya), mengeksploitasi aplikasi yang tidak memvalidasi jenis token dan audience dengan benar | Aplikasi tidak memeriksa claim `typ` atau `aud` token | D2 |
| **Penyalahgunaan JWT bearer assertion** | Menggunakan token JWT yang sah dari satu konteks sebagai assertion klien di konteks lain, mengeksploitasi kunci penandatangan bersama atau validasi audience yang tidak memadai | Infrastruktur kunci bersama di seluruh layanan | D2, D6 |

### §10-4. SSO Gadget: Alur OAuth/OIDC sebagai Primitif Eskalasi Self-XSS

Alur otorisasi OAuth/OIDC menciptakan rantai navigasi lintas-origin (RP → IdP → RP) yang membawa status autentikasi melalui parameter URL. Ketika aplikasi memiliki kerentanan self-XSS (hanya dapat dieksploitasi dalam sesi penyerang sendiri), alur OAuth itu sendiri menjadi "gadget" yang menjembatani konteks terautentikasi penyerang ke browser korban — meningkatkan self-XSS berdampak rendah menjadi pengambilalihan akun penuh tanpa memerlukan login CSRF.

| Subtipe | Mekanisme | Kondisi Utama | Ketidaksesuaian |
|---------|-----------|---------------|-----------------|
| **Gadget redirect authorization endpoint** | Penyerang memulai permintaan otorisasi OAuth dengan `redirect_uri` yang dibuat yang mengarah ke halaman yang mengandung payload self-XSS. Ketika korban mengklik tautan penyerang, IdP mengautentikasi korban dan mengarahkan ke halaman RP tempat payload XSS tersimpan penyerang dieksekusi dalam sesi terautentikasi korban | Self-XSS pada RP; alur OAuth mempertahankan navigasi ke halaman yang rentan; tidak ada perlindungan CSRF tambahan pada endpoint callback | D3, D4 |
| **Halaman login IdP sebagai jembatan konteks** | Penyerang membuat URL otorisasi OAuth yang memaksa korban melalui alur login IdP. Setelah korban mengautentikasi di IdP, respons otorisasi mengarahkan ke endpoint callback RP. Jika halaman callback (atau halaman yang dapat dijangkau darinya) mengandung self-XSS yang dipicu oleh state yang dikontrol penyerang (misalnya data profil yang tersimpan, parameter query yang diteruskan melalui alur), XSS dieksekusi dalam konteks pasca-autentikasi korban | Self-XSS dapat dijangkau dari callback OAuth; IdP mengizinkan prompt=login atau sesi kedaluwarsa; data yang dikontrol penyerang bertahan di seluruh round-trip OAuth | D2, D4 |
| **Respons token endpoint sebagai pemicu XSS** | Dalam implicit atau hybrid flow, respons otorisasi (yang mengandung token atau kode dalam fragment/parameter URL) diproses oleh JavaScript sisi klien pada RP. Jika logika pemrosesan ini memiliki cacat injeksi, penyerang membuat URL respons otorisasi dengan nilai berbahaya dalam parameter state, code, atau error yang memicu XSS saat handler callback RP memprosesnya | Pemrosesan callback OAuth sisi klien dengan sanitasi yang tidak memadai dari parameter respons; implicit atau hybrid flow | D1, D3 |

Wawasan kuncinya adalah bahwa alur OAuth/OIDC secara inheren adalah **rantai navigasi lintas-origin yang membawa state yang dapat dipengaruhi penyerang** (melalui `state`, `redirect_uri`, `login_hint`, `prompt`, dan parameter lainnya). Tidak seperti login CSRF (§7-1 dalam `csrf.md`) yang memerlukan pemaksaan autentikasi sebagai penyerang, rantai SSO gadget mengeksploitasi autentikasi korban sendiri — penyerang hanya mengontrol jalur navigasi dan konteks tempat halaman pasca-autentikasi dirender.

---

## §11. Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama |
|----------|------------|-----------------------|
| **Pengambilalihan Akun** | Aplikasi mana pun yang dilindungi OAuth | §1 + §2-1 + §4-1 + §6-1 |
| **Pencurian Token / Pemanenan Kredensial** | Aplikasi dengan vektor kebocoran token | §1-2 + §2-2 + §7-1 + §8-3 |
| **Akses Tidak Sah yang Persisten** | Lingkungan cloud enterprise | §5-2 + §7-2 + §8-3 |
| **Eskalasi Hak Istimewa** | OAuth enterprise multi-scope (Azure AD, Google Workspace) | §2-3 + §5-1 + §5-2 |
| **SSRF / Eksploitasi Sisi Server** | Server OAuth dengan dynamic registration | §3-1 + §9-2 + §9-3 |
| **Phishing / Rekayasa Sosial** | OAuth enterprise, device flow | §5-1 + §8-3 |
| **Kompromi Rantai Pasok** | Platform integrasi, SaaS pihak ketiga | §7-2 + §10-1 |
| **Pergerakan Lateral (Cloud)** | Microsoft 365, Azure AD, Google Workspace | §7-2 + §10-1 + §10-2 |

---

## §12. Pemetaan CVE / Bounty (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|-----------------|-------------|-----------------|
| §3-1 (SSRF melalui `logo_uri`) + §9-4 | CVE-2021-26715 (MITREid Connect) | SSRF + XSS melalui endpoint pendaftaran klien. Server mengambil dan mengembalikan konten `logo_uri` tanpa validasi |
| §6-2 (Session poisoning mass assignment) | CVE-2021-27582 (MITREid Connect) | Mass assignment Spring `@ModelAttribute` memungkinkan penimpaan `redirectUri` di endpoint consent |
| §10-1 (Pengambilalihan lintas-aplikasi COAT) | CVE-2023-36019 (Microsoft) | CVSS 9.6. Satu klik mengkompromikan suite Microsoft 365 melalui platform integrasi |
| §3-2 (Penyalahgunaan aplikasi first-party) | ConsentFix/AuthCodeFix (2025) | Aplikasi Azure CLI dan Azure PowerShell yang di-pre-consent dapat dieksploitasi untuk eskalasi hak istimewa seluruh tenant |
| §4-1 (Kebingungan claim yang dapat diubah) | Google OAuth domain reuse (2024) | Domain startup yang gagal mengekspos jutaan akun. Bounty Google VRP $1.337 |
| §10-2 (Injeksi authorization endpoint MCP) | CVE-2025-6514 (mcp-remote) | RCE melalui server MCP berbahaya. 558.846 unduhan terpengaruh |
| §9-3 (Injeksi LDAP melalui WebFinger) | CVE dalam ForgeRock OpenAM | Ekstraksi hash kata sandi melalui injeksi wildcard LDAP karakter demi karakter |
| §8-3 (Device code phishing) | Kampanye Storm-2372 / ShinyHunters (2024-2025) | Kompromi enterprise Google, Qantas, dan lusinan organisasi besar. Bypass MFA |
| §7-2 (Kompromi token rantai pasok) | UNC6395/Drift-Salesforce (2025) | Satu token OAuth yang dicuri memberikan akses ke 700+ instance Salesforce pelanggan |
| §2-1 (Downgrade PKCE) | OAuth 2.1 / RFC 9700 (2025) | PKCE kini wajib untuk semua klien; alur non-PKCE secara resmi dihapus |
| §4-2 (Audience injection) | Diungkapkan ke IETF OAuth WG (Jan 2025) | Kelas serangan baru yang mempengaruhi OAuth 2.0, OIDC, FAPI, CIBA, dan beberapa ekstensi. Upaya perbaikan multi-standar yang terkoordinasi |
| §10-1 (Serangan lintas-aplikasi) | USENIX Security '25 | 11 dari 18 platform integrasi besar rentan terhadap COAT; 5 terhadap CORF. Microsoft, Google, Amazon terpengaruh |
| §1-1 (Bypass validasi redirect URI) | Beberapa laporan HackerOne | Berbagai bounty $X.XXX+ untuk bypass redirect_uri di platform besar |
| §9-1 (Bypass autentikasi proxy) | CVE-2025-54576 (OAuth2-Proxy) | Bypass autentikasi dalam OAuth2-Proxy; diperbaiki dalam v7.11.0 |
| §10-3 (Bypass SAML/OAuth) | CVE-2024-4985 (GitHub Enterprise Server) | Bypass autentikasi melalui SAML/OAuth di GitHub Enterprise Server |
| §4-1 (Over-provisioning aplikasi multi-tenant) | BingBang (Wiz Research, 2023) | Akses tidak sah ke aplikasi Microsoft internal termasuk manipulasi hasil pencarian Bing.com dan XSS Office 365 melalui aplikasi Azure AD multi-tenant yang over-provisioned |
| §1-1 (Injeksi whitespace) | Kebocoran Token OAuth draw.io (2023) | Kebocoran token OAuth melalui bypass whitespace dalam validasi redirect_uri |
| §1-1 (Kebingungan path) | ACM CCS "OAuth Path Confusion" (2023) | Bypass validasi redirect_uri melalui diferensial parser URL pada interpretasi komponen path |
| §2-2 (Kebocoran token melalui kunci publik) | Azure B2C Crypto Misuse (Praetorian, 2023) | Kunci publik RSA yang diekstrak dari endpoint JWKS digunakan untuk memalsukan refresh token terenkripsi → kompromi akun penuh pada tenant Azure AD B2C. Lihat `cryptographic-implementation-vulnerabilities.md` §2-2 |

---

## §13. Alat Deteksi

| Alat | Cakupan Target | Teknik Utama |
|------|----------------|--------------|
| **Burp Suite** (PortSwigger) | Pengujian alur OAuth/OIDC penuh | Proxy HTTP dengan aturan pemindaian khusus OAuth; manipulasi alur manual |
| **ActiveScan++** (Ekstensi Burp) | Discovery OpenID/OAuth | Mendeteksi `.well-known/openid-configuration` dan endpoint pendaftaran secara otomatis |
| **COVScan** (USENIX '25) | Kerentanan OAuth lintas-aplikasi dalam platform integrasi | Analisis lalu lintas jaringan semi-otomatis untuk deteksi COAT/CORF |
| **SquarePhish2** (Ofensif) | Simulasi phishing device code | Phishing alur device code otomatis dengan pembuatan kode QR |
| **OWASP ZAP** | Pengujian alur OAuth umum | Pemindaian aktif/pasif endpoint OAuth |
| **oauth-scanner** (GitHub) | Deteksi miskonfigurasi OAuth | Memeriksa bypass redirect_uri umum, state yang hilang, masalah scope |
| **Nuclei** (ProjectDiscovery) | Pemindaian berbasis template OAuth | Template komunitas untuk deteksi miskonfigurasi OAuth/OIDC |
| **Obsidian Security** (Komersial) | Pemantauan token OAuth SaaS | Mendeteksi pemberian OAuth yang mencurigakan, penyalahgunaan token, dan anomali scope di lingkungan cloud |
| **Push Security** (Komersial) | Analisis risiko scope OAuth | Mengidentifikasi integrasi OAuth pihak ketiga yang berbahaya dan kombinasi scope berisiko |
| **Microsoft Entra ID Protection** (Defensif) | Pemantauan OAuth Azure AD | Mendeteksi consent aplikasi OAuth yang anomali, masuk berisiko, dan pola phishing device code |

---

## §14. Ringkasan: Prinsip-Prinsip Inti

### Properti Fundamental

Seluruh ruang mutasi OAuth muncul dari satu realitas arsitektur: **OAuth adalah protokol delegasi yang memisahkan pihak yang mengautentikasi (pengguna) dari pihak yang mengonsumsi otorisasi (klien), dimediasi oleh kredensial bearer yang melintasi browser**. Arsitektur tiga pihak ini — dengan browser sebagai lapisan transport yang tidak tepercaya — menciptakan batas kepercayaan yang inheren yang dieksploitasi oleh setiap serangan dalam taksonomi ini dalam beberapa bentuk.

Authorization code, access token, dan refresh token semuanya adalah kredensial bearer: siapa pun yang memilikinya dapat menggunakannya. Tidak seperti kata sandi (yang membuktikan pengetahuan) atau sertifikat (yang membuktikan kepemilikan kunci privat), token OAuth tidak memiliki pengikatan intrinsik ke pemegang yang dimaksudkan. PKCE, DPoP, dan sender-constrained token adalah mitigasi untuk properti desain fundamental ini, bukan solusi untuk itu.

### Mengapa Perbaikan Inkremental Gagal

Setiap generasi peningkatan keamanan OAuth mengatasi vektor serangan tertentu sementara permukaan serangan mendasar bergeser. PKCE mencegah intersepsi kode tetapi tidak menghentikan injeksi kode melalui open redirect. Penghentian implicit flow mengatasi paparan token dalam fragment tetapi tidak menghilangkan kebocoran token melalui XSS atau postMessage. Validasi redirect URI yang ketat mencegah redirect sepele tetapi membuka pintu bagi serangan chaining yang semakin kreatif melalui open redirector, kebocoran Referer, dan halaman proxy.

Gelombang serangan device code phishing 2024-2025 mengilustrasikan ini dengan sempurna: serangan mengeksploitasi tidak ada kerentanan perangkat lunak — ia memanfaatkan perilaku yang dirancang protokol di mana autentikasi pengguna secara sengaja dipisahkan dari perangkat yang meminta. Demikian pula, serangan audience injection 2025 menunjukkan bahwa bahkan autentikasi klien berbasis tanda tangan (metode autentikasi klien terkuat) membawa ambiguitas fundamental ketika klien berinteraksi dengan beberapa server otorisasi.

### Solusi Struktural

Solusi yang benar-benar struktural akan memerlukan tiga properti yang sebagian besar kurang dimiliki penerapan OAuth saat ini: **(1) sender-constrained token** (DPoP, token terikat mTLS) yang secara kriptografis mengikat token ke pemegang yang dimaksudkan, **(2) PKCE universal + verifikasi penerbit** (kini diwajibkan dalam OAuth 2.1 / RFC 9700) yang mencegah intersepsi kode dan serangan mix-up, serta **(3) evaluasi otorisasi berkelanjutan** yang bergerak melampaui consent satu kali ke penegakan kebijakan real-time atas penggunaan token, konsumsi scope, dan anomali perilaku. Sampai ketiganya ada di mana-mana, taksonomi di atas akan terus tumbuh.

---

*Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan.*

---

## Referensi

- Doyensec, "Common OAuth Vulnerabilities," Januari 2025 — https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
- PortSwigger, "Hidden OAuth Attack Vectors" — https://portswigger.net/research/hidden-oauth-attack-vectors
- PortSwigger, "OAuth 2.0 Authentication Vulnerabilities" — https://portswigger.net/web-security/oauth
- Luo et al., "Universal Cross-app Attacks: Exploiting and Securing OAuth 2.0 in Integration Platforms," USENIX Security '25 — https://www.usenix.org/conference/usenixsecurity25/presentation/luo-kaixuan
- Küsters & Würtele, "Audience Injection Attacks: A New Class of Attacks on Web-Based Authorization and Authentication Standards," 2025 — https://eprint.iacr.org/2025/629
- IETF, "Updates to OAuth 2.0 Security Best Current Practice" — https://datatracker.ietf.org/doc/draft-wuertele-oauth-security-topics-update/
- IETF, "OAuth 2.0 Security Best Current Practice" — https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-22.html
- Obsidian Security, "The New Attack Surface: OAuth Token Abuse" — https://www.obsidiansecurity.com/blog/the-new-attack-surface-oauth-token-abuse
- Obsidian Security, "From Well-Known to Well-Pwned: Common Vulnerabilities in AI Agents" — https://www.obsidiansecurity.com/blog/from-well-known-to-well-pwned-common-vulnerabilities-in-ai-agents
- Semperis, "A New App Consent Attack: Hidden Consent Grant" — https://www.semperis.com/blog/app-consent-attack-hidden-consent-grant/
- Amla Labs, "When OAuth Becomes a Weapon: Lessons from CVE-2025-6514" — https://amlalabs.com/blog/oauth-cve-2025-6514/
- Proofpoint, "Access Granted: Phishing with Device Code Authorization" — https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover
- Unit42, "Trusted Connections, Hidden Risks: Token Management in the Third-Party Supply Chain" — https://unit42.paloaltonetworks.com/third-party-supply-chain-token-management/
- Push Security, "Dangerous OAuth Scopes in Third-Party Integrations" — https://pushsecurity.com/blog/the-risky-terrain-of-oauth-scopes-in-third-party
- Praetorian, "Attacking and Defending OAuth 2.0" — https://www.praetorian.com/blog/attacking-and-defending-oauth-2/
- WorkOS, "Defending OAuth: Common Attacks and How to Prevent Them" — https://workos.com/blog/oauth-common-attacks-and-how-to-prevent-them
- HackTricks, "OAuth to Account Takeover" — https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover
- OWASP, "OAuth 2.0 Protocol Cheatsheet" — https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html