---
title: Authentication & SSO Bypass
description: 
---

**Cakupan**: Kerentanan authentication bypass dan Single Sign-On (SSO)
**Pengecualian**: OAuth, JWT, SAML (dibahas dalam taksonomi terpisah)
**Lingkup**: Kerberos, LDAP, CAS, FIDO2/WebAuthn, MFA, manajemen sesi, auth middleware/framework, pemulihan kata sandi, akuisisi kredensial
**Periode**: Berfokus pada temuan 2024–2025, dengan teknik-teknik dasar yang disertakan

---

## Struktur Klasifikasi

Taksonomi ini mengorganisasi kerentanan authentication bypass dan SSO berdasarkan tiga sumbu ortogonal:

**Sumbu 1 — Lapisan Autentikasi yang Ditarget (Sumbu Utama):** Komponen struktural dari sistem autentikasi yang diserang. Sumbu ini membentuk bagian utama dokumen (§1–§9). Setiap kategori tingkat atas mewakili lapisan berbeda dari tumpukan autentikasi — mulai dari logika validasi kredensial tingkat rendah, mekanisme tingkat protokol, penegakan multi-faktor, siklus hidup sesi, arsitektur kepercayaan SSO, sistem tanpa kata sandi modern, middleware framework, alur pemulihan akun, hingga teknik akuisisi kredensial berskala besar.

**Sumbu 2 — Mekanisme Eksploitasi (Sumbu Lintas-Bidang):** Sifat cacat atau ketidaksesuaian yang memungkinkan bypass. Setiap teknik dalam §1–§9 mengeksploitasi satu atau lebih dari jenis mekanisme fundamental ini. Sumbu ini menjelaskan *mengapa* setiap mutasi berhasil, terlepas dari di mana ia terjadi.

**Sumbu 3 — Skenario Dampak (Sumbu Pemetaan):** Konteks penerapan dan hasil operasional ketika teknik tersebut dijadikan senjata. Sumbu ini menghubungkan teknik individu ke konsekuensi dunia nyata.

### Sumbu 2: Ringkasan Mekanisme Eksploitasi

| Mekanisme | Deskripsi |
|-----------|-----------|
| **Kelemahan Kriptografis** | Pemotongan hash, algoritma lemah (MD5, batas bcrypt), pembuatan token yang dapat diprediksi |
| **Cacat Logika / State Machine** | Langkah autentikasi yang dapat dilewati, diurutkan ulang, atau diterapkan ke sesi yang salah |
| **Pelanggaran Batas Input** | Input yang melebihi batas yang diharapkan menyebabkan pemotongan, overflow, atau bypass |
| **Cacat Desain Protokol** | Kelemahan bawaan dalam spesifikasi protokol autentikasi |
| **Race Condition / TOCTOU** | Mengeksploitasi celah waktu antara pemeriksaan autentikasi dan akses sumber daya |
| **Pelanggaran Batas Kepercayaan** | Menyalahgunakan hubungan kepercayaan antar sistem federasi atau komponen internal |
| **Relay / Reflection** | Meneruskan atau memantulkan materi autentikasi ke target yang tidak dimaksudkan |
| **Downgrade / Fallback** | Memaksa autentikasi ke metode yang lebih lemah yang dapat disadap |
| **Injection** | Menyisipkan data yang dikontrol penyerang ke dalam kueri atau pernyataan autentikasi |
| **Amplifikasi Social Engineering** | Menggabungkan eksploitasi teknis dengan manipulasi faktor manusia |

### Sumbu 3: Ringkasan Skenario Dampak

| Skenario | Arsitektur | Vektor Masuk Umum |
|----------|------------|-------------------|
| **Kompromi Domain Penuh** | Active Directory / domain Windows | §2 + §9 (pemalsuan tiket + akuisisi kredensial) |
| **Pengambilalihan Akun Cloud/SaaS** | Azure/Entra ID, Okta, Google Workspace | §3 + §4 (bypass MFA + pencurian sesi) |
| **Pengambilalihan Perangkat Jaringan** | Firewall, gateway VPN, antarmuka manajemen | §7 (bypass framework/middleware) |
| **Akses Aplikasi Web** | Aplikasi web kustom | §1 + §7 + §8 (cacat logika + middleware + pemulihan) |
| **Pergerakan Lateral** | Ekspansi pasca-kompromi awal | §2 + §5 (pemalsuan tiket + kepercayaan SSO) |
| **Backdoor Persisten** | Akses jangka panjang yang tidak terdeteksi | §2 + §5 (pemalsuan tiket + Golden dMSA) |

---

## §1. Cacat Logika Validasi Kredensial

Cacat dalam mekanisme fundamental yang membandingkan kredensial yang diberikan pengguna dengan referensi yang tersimpan. Kerentanan ini melewati autentikasi bukan dengan menyerang protokol atau sesi, tetapi dengan mengeksploitasi cacat implementasi dalam verifikasi kredensial itu sendiri.

### §1-1. Eksploitasi Batas Input

Ketika fungsi validasi kredensial memiliki batas input yang tidak terdokumentasi, input yang melebihi batas tersebut menghasilkan nilai perbandingan yang terpotong atau dapat diprediksi, sehingga memungkinkan bypass.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Pemotongan Hash Function** | Algoritma hashing dengan batas input tetap (misalnya batas 72 byte bcrypt) secara diam-diam memotong input berlebih, menyebabkan bagian kata sandi dikecualikan dari perbandingan saat dikombinasikan dengan nama pengguna atau ID pengguna yang panjang | Kunci cache terdiri dari userId + username + password yang melebihi batas input hash; cache digunakan sebagai fallback saat autentikasi utama tidak tersedia |
| **Tabrakan Kunci Cache** | Ketika hasil autentikasi di-cache dengan kunci yang terpotong, kredensial yang berbeda menghasilkan entri cache yang identik, memungkinkan autentikasi dengan kata sandi apa pun yang cocok dengan prefix yang terpotong | Cache autentikasi diaktifkan sebagai fallback ketersediaan tinggi; input hash dilampaui oleh kunci komposit |

Insiden bcrypt Okta (Oktober 2024) mengilustrasikan kategori ini: nama pengguna yang melebihi 52 karakter menyebabkan komponen kata sandi dari kunci cache yang di-hash dengan bcrypt terpotong sepenuhnya, memungkinkan autentikasi dengan hasil cache terlepas dari kata sandi aktual yang diberikan. Perbaikannya mengganti bcrypt dengan PBKDF2 untuk pembuatan kunci cache.

### §1-2. Bypass Autentikasi Berbasis Injection

Ketika kredensial yang diberikan pengguna dimasukkan ke dalam kueri backend tanpa sanitasi yang tepat, penyerang dapat memanipulasi logika kueri untuk mengembalikan hasil autentikasi yang valid untuk kredensial sembarang.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **LDAP Injection Auth Bypass** | Payload berbahaya yang disuntikkan ke kueri bind atau pencarian LDAP memodifikasi logika filter agar selalu bernilai benar (misalnya `(&(uid=*)(userPassword=*))`) | Aplikasi membangun kueri LDAP dari input pengguna yang tidak disanitasi; direktori LDAP digunakan untuk autentikasi |
| **SQL Injection Auth Bypass** | Injeksi gaya klasik `' OR '1'='1` dalam kueri login menyebabkan klausa WHERE mengembalikan rekaman pengguna yang valid terlepas dari kredensial | Pembuatan kueri SQL mentah tanpa parameterized query di endpoint autentikasi |
| **NoSQL Injection Auth Bypass** | Injeksi operator (misalnya `{"$gt": ""}`) dalam kueri autentikasi MongoDB/NoSQL melewati perbandingan kata sandi | API autentikasi berbasis JSON tanpa validasi tipe input |
| **LDAP Bind Confusion** | Mengeksploitasi server LDAP yang memperlakukan kata sandi kosong sebagai anonymous bind (autentikasi berhasil) ketika aplikasi tidak memvalidasi hasil bind dengan benar | Anonymous bind LDAP diaktifkan; aplikasi hanya memeriksa keberhasilan/kegagalan bind tanpa memverifikasi identitas |

Contoh dunia nyata terkini meliputi CVE-2024-37782 (Gladinet CentreStack) di mana injeksi LDAP melalui kolom nama pengguna memungkinkan akses tidak sah dan eksekusi perintah sembarang, serta CVE-2025-29810 (Windows Active Directory Domain Services) di mana manipulasi kueri LDAP memungkinkan eskalasi hak istimewa ke level SYSTEM (CVSS 7.5).

### §1-3. Eksploitasi Kredensial Default dan Hardcoded

Sistem autentikasi yang dikirim dengan kredensial yang diketahui atau algoritma pembuatan kredensial yang deterministik dan reversibel.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Kredensial Default Pabrik** | Pasangan username/password yang dikirim vendor identik di semua unit yang digunakan dan terdokumentasi dalam manual publik | Perangkat tidak dikonfigurasi ulang setelah penerapan; antarmuka manajemen terekspos |
| **Pembuatan Kredensial Deterministik** | Kredensial yang dihasilkan secara algoritmik dari pengidentifikasi perangkat (nomor seri, alamat MAC) menggunakan algoritma yang diketahui atau dapat dibalik | Algoritma di-reverse-engineer atau bocor; pengidentifikasi perangkat dapat diperoleh |
| **Service Account Hardcoded** | Aplikasi berisi kredensial tertanam untuk komunikasi layanan internal yang juga memberikan akses eksternal | Kredensial service account dalam kode sumber, firmware, atau file konfigurasi |
| **Kelemahan Shared Secret** | Shared secret (misalnya shared secret RADIUS) yang terlalu pendek, umum, atau digunakan kembali di berbagai lingkungan | Kemampuan intersepsi jalur jaringan; shared secret yang lemah |

### §1-4. Cacat Perbandingan Kriptografis

Cacat dalam cara nilai-nilai turunan kredensial dibandingkan, yang mengarah pada hasil autentikasi positif palsu.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Timing Side-Channel** | Perbandingan hash kata sandi atau token yang tidak membutuhkan waktu konstan membocorkan informasi tentang karakter yang benar melalui perbedaan waktu respons | Pengukuran waktu presisi tinggi dimungkinkan; perbandingan tidak menggunakan fungsi constant-time |
| **Type Juggling / Loose Comparison** | Bahasa dengan tipe lemah (PHP, JavaScript) mengevaluasi `"0" == 0 == false` sebagai sama. PHP juga memperlakukan `null == false` dan `null == 0` sebagai benar, tetapi JavaScript tidak (`null` hanya secara longgar sama dengan `undefined`). Dapat dieksploitasi untuk melewati pemeriksaan kata sandi ketika magic hash atau nilai yang type-confused diberikan | Persamaan longgar (`==`) alih-alih persamaan ketat (`===`) dalam perbandingan kredensial |
| **Ketidaksesuaian Normalisasi Encoding** | Bentuk normalisasi Unicode yang berbeda untuk string visual yang sama menghasilkan nilai hash yang berbeda, memungkinkan hash yang telah dihitung sebelumnya untuk cocok dengan input yang tidak terduga | Normalisasi Unicode tidak diterapkan secara konsisten antara pendaftaran dan autentikasi |

---

## §2. Serangan Autentikasi Tingkat Protokol

Serangan yang mengeksploitasi cacat desain atau implementasi dalam protokol autentikasi jaringan. Ini menargetkan mekanisme protokol itu sendiri daripada logika tingkat aplikasi.

### §2-1. Pemalsuan Tiket Kerberos

Membuat atau memanipulasi tiket Kerberos tanpa otoritas yang sah, memungkinkan autentikasi sebagai prinsipal sembarang.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Golden Ticket** | Memalsukan Ticket-Granting Tickets (TGT) menggunakan hash akun `krbtgt` yang telah dikompromi. Tiket palsu diterima tanpa syarat karena ditandatangani oleh kunci KDC sendiri, memberikan autentikasi sebagai pengguna mana pun termasuk Domain Admin | Penyerang telah memperoleh hash NTLM `krbtgt` (biasanya melalui kompromi domain controller) |
| **Silver Ticket** | Memalsukan tiket Ticket-Granting Service (TGS) menggunakan hash akun layanan yang telah dikompromi. Tidak seperti Golden Ticket, ini menargetkan layanan tertentu tetapi tidak memerlukan komunikasi dengan KDC, membuat deteksi jauh lebih sulit | Penyerang telah memperoleh hash NTLM akun layanan (melalui pencurian kredensial atau cara lain) |
| **Diamond Ticket** | Memodifikasi TGT yang sah yang diperoleh dari KDC daripada memalsukan dari awal, menyatu ke dalam siklus hidup tiket normal dan menghindari deteksi yang mencari tiket dengan metadata pembuatan yang anomali | Hash `krbtgt` telah dikompromi; penyerang ingin menghindari mekanisme deteksi Golden Ticket |
| **Golden dMSA** | Mengeksploitasi cacat desain dalam delegated Managed Service Accounts (dMSA) Windows Server 2025 di mana struktur `ManagedPasswordId` hanya berisi 1.024 kemungkinan kombinasi berbasis waktu, mengurangi derivasi kata sandi menjadi operasi brute-force sepele | Windows Server 2025 dengan dMSA yang diterapkan; penyerang memiliki kunci root KDS (akses Domain Admin, Enterprise Admin, atau SYSTEM) |

Kerentanan Golden dMSA, ditemukan pada Mei 2025, sangat penting karena menyerang fitur yang secara eksplisit dirancang untuk *meningkatkan* keamanan service account. Microsoft mengakui temuan tersebut tetapi mengkarakterisasinya sebagai perilaku by-design untuk skenario di mana rahasia domain controller sudah dikompromi.

### §2-2. Serangan Autentikasi LDAP

Menargetkan protokol LDAP sebagai backend autentikasi, di luar serangan injection yang dibahas dalam §1-2.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Eksploitasi Anonymous Bind** | Server LDAP yang dikonfigurasi untuk menerima anonymous bind (DN kosong + kata sandi kosong) sebagai autentikasi yang valid, di mana aplikasi menafsirkan bind yang berhasil sebagai terautentikasi | Anonymous bind LDAP diaktifkan; aplikasi tidak membedakan bind anonim dari bind terautentikasi |
| **Penyalahgunaan LDAP Referral** | Memanipulasi referral LDAP untuk mengarahkan ulang kueri autentikasi ke server LDAP yang dikontrol penyerang yang mengembalikan hasil positif palsu | Klien LDAP mengikuti referral; tidak ada validasi referral |
| **Pass-Back Attack** | Mengkonfigurasi ulang perangkat untuk mengarahkan autentikasi LDAP-nya ke server yang dikontrol penyerang, menangkap kredensial dalam cleartext saat pengguna mengautentikasi | Akses administratif ke konfigurasi LDAP perangkat; kredensial dikirim dalam cleartext |
| **Eksploitasi Hierarki ACL** | Memanfaatkan resolusi hierarki grup LDAP dan miskonfigurasi ACL untuk meningkatkan akses dari terbatas ke level SYSTEM | ACL Active Directory yang salah dikonfigurasi; akses kueri LDAP ke objek grup (CVE-2025-29810, CVSS 7.5) |

### §2-3. Bypass Autentikasi Mutual TLS (mTLS)

Mutual TLS memperluas TLS standar dengan mengharuskan klien untuk menyajikan sertifikat selama handshake. Cacat implementasi dalam validasi sertifikat, ekstraksi identitas, dan pemeriksaan pencabutan menciptakan vektor bypass autentikasi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Validasi Sertifikat Tanpa Pengikatan Identitas** | Aplikasi memvalidasi bahwa sertifikat klien ditandatangani oleh CA tepercaya tetapi tidak memverifikasi subject sertifikat, SAN, atau kolom identitas lainnya terhadap identitas pengguna yang diharapkan. Sertifikat apa pun dari CA yang sama mengautentikasi sebagai pengguna mana pun | mTLS diaktifkan; kepercayaan tingkat CA tanpa pengikatan identitas per-sertifikat |
| **Diferensial Ekstraksi Subject/SAN** | Komponen berbeda dalam rantai permintaan (load balancer, reverse proxy, aplikasi) mengekstrak identitas dari kolom sertifikat yang berbeda (CN, SAN, OU). Penyerang memperoleh sertifikat dengan SAN permisif atau CN yang tidak cocok yang melewati pemeriksaan satu komponen sambil diinterpretasikan berbeda oleh komponen lain | Terminasi mTLS multi-lapisan; logika ekstraksi identitas yang tidak konsisten di seluruh komponen |
| **Kepercayaan Header Proxy Tanpa Verifikasi Koneksi** | mTLS diterminasi di reverse proxy, yang meneruskan sertifikat klien atau subjeknya dalam header HTTP (misalnya `X-Client-Cert`, `X-SSL-Client-DN`). Aplikasi mempercayai header ini tanpa memverifikasi bahwa permintaan benar-benar melewati proxy — memungkinkan permintaan langsung dengan header yang disuntikkan untuk menyamar sebagai pemegang sertifikat mana pun | mTLS diterminasi di proxy; backend mempercayai header sertifikat tanpa verifikasi tingkat koneksi |
| **Bypass Pemeriksaan Pencabutan Sertifikat** | Aplikasi tidak memeriksa CRL atau OCSP untuk status pencabutan sertifikat, atau pemeriksaan gagal terbuka (memperlakukan timeout OCSP sebagai valid). Sertifikat yang dicabut terus mengautentikasi tanpa batas | Tidak ada pemeriksaan CRL/OCSP yang dikonfigurasi; atau kebijakan pencabutan fail-open |
| **Eskalasi Hak Istimewa melalui Injeksi Atribut Sertifikat** | CA atau otoritas pendaftaran mengizinkan atribut sertifikat (OU, peran, grup) untuk dipengaruhi oleh pemohon. Penyerang meminta sertifikat dengan atribut yang ditingkatkan yang digunakan aplikasi untuk keputusan otorisasi | Penerbitan sertifikat layanan mandiri atau dikontrol lemah; aplikasi menurunkan otorisasi dari atribut sertifikat (CVE-2025-9312) |

---

## §3. Bypass Multi-Factor Authentication

Teknik yang mengalahkan persyaratan autentikasi faktor kedua atau tambahan. Serangan ini mengakui bahwa faktor pertama (biasanya kata sandi) mungkin telah dikompromi dan menargetkan lapisan verifikasi tambahan.

### §3-1. Brute-Force TOTP / OTP

Menghabiskan ruang kode kata sandi satu kali berbasis waktu atau berbasis kejadian melalui enumerasi cepat.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Enumerasi Paralel Sesi (AuthQuake)** | Membuat sesi autentikasi baru dengan cepat dan mengenumerasi kode TOTP di semua sesi secara bersamaan. Kode TOTP 6 digit memiliki 1.000.000 nilai yang mungkin; tanpa pembatasan laju lintas-sesi, kelelahan membutuhkan sekitar 70 menit | Tidak ada pembatasan laju lintas sesi (hanya per sesi); tidak ada peringatan pada percobaan MFA yang gagal (Microsoft Azure MFA, ditambal Oktober 2024) |
| **Eksploitasi Jendela Waktu TOTP** | Mengeksploitasi jendela waktu yang terlalu murah hati di mana kode TOTP tetap valid untuk periode yang diperpanjang di luar jendela standar 30 detik | Server menerima kode dari beberapa langkah waktu (masa lalu dan masa depan); tidak ada penegakan satu kali pakai |
| **Keterpredikasian OTP** | Pembuatan OTP yang berurutan, berbasis waktu, atau tidak cukup acak memungkinkan prediksi kode masa depan | OTP diturunkan dari timestamp melalui algoritma lemah (misalnya MD5 dari epoch); tidak ada HMAC kriptografis |
| **Intersepsi OTP SMS** | Eksploitasi jaringan SS7, SIM swapping, atau intersepsi SMS berbasis malware untuk mendapatkan kode OTP dalam transit | SMS digunakan sebagai saluran pengiriman OTP; penyerang memiliki akses tingkat telco atau kemampuan rekayasa sosial |

### §3-2. MFA Fatigue dan Social Engineering

Mengeksploitasi elemen manusia dalam MFA dengan membanjiri pengguna dengan permintaan persetujuan atau memanipulasi mereka untuk mengotorisasi sesi penyerang.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Push Notification Bombing** | Berulang kali memicu notifikasi push MFA hingga pengguna menyetujui satu karena kelelahan, kebingungan, atau keinginan untuk menghentikan peringatan | MFA berbasis push tanpa pencocokan nomor; tidak ada pembatasan laju pada permintaan push |
| **Social Engineering Pencocokan Nomor** | Menghubungi korban dan meyakinkan mereka untuk memberikan nomor yang ditampilkan pada prompt MFA mereka, yang diduga untuk "verifikasi IT" | MFA pencocokan angka telah diterapkan; penyerang memiliki nomor telepon dan kredensial korban |
| **Pembajakan Pendaftaran MFA** | Mendaftarkan perangkat MFA yang dikontrol penyerang selama jendela pendaftaran awal sebelum pengguna yang sah menyelesaikan pengaturan | Tidak ada verifikasi pra-pendaftaran; tautan pendaftaran dikirim ke email yang dikompromi; jendela pendaftaran terbuka |

### §3-3. Serangan Downgrade Autentikasi

Memaksa sistem autentikasi untuk kembali dari metode tahan phishing (FIDO2/passkey) ke alternatif yang dapat disadap.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Downgrade Spoofing User-Agent** | Proxy AitM memalsukan user agent browser yang tidak kompatibel dengan FIDO2 (misalnya Safari di Windows), memicu kesalahan WebAuthn yang meminta pengguna untuk memilih alternatif yang lebih lemah (OTP, notifikasi push) | IdP menawarkan metode autentikasi fallback; proxy AitM dapat memodifikasi header User-Agent |
| **Penyembunyian Metode Melalui CSS Injection** | Menyuntikkan blok CSS `<style>` melalui proxy AitM atau XSS yang menyembunyikan opsi autentikasi FIDO2/kunci keamanan dari tampilan pengguna, hanya menyisakan metode yang dapat di-phish | Proxy AitM dapat menyuntikkan HTML/CSS; halaman autentikasi IdP merender pilihan metode di sisi klien |
| **Downgrade Versi Protokol** | Mengirimkan browser atau lingkungan palsu yang melaporkan tidak ada dukungan WebAuthn, memaksa fallback ke TOTP/SMS bahkan ketika pengguna telah mendaftarkan hardware key | IdP tidak menegakkan kebijakan FIDO2-only; degradasi yang baik ke metode yang lebih lemah diaktifkan |

Kategori serangan ini, pertama kali dipresentasikan secara resmi di OutOfTheBox 2025 di Bangkok, sangat mengkhawatirkan karena menargetkan metode autentikasi yang secara eksplisit dipasarkan sebagai "tahan phishing." Inti masalahnya adalah bahwa sebagian besar penerapan mempertahankan metode fallback yang dapat di-phish untuk kompatibilitas.

### §3-4. Intersepsi Sesi Adversary-in-the-Middle (AitM)

Menempatkan proxy real-time antara pengguna dan layanan yang sah untuk menangkap token sesi pasca-MFA, membuat semua faktor autentikasi tidak efektif.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Phishing Reverse Proxy (gaya Evilginx)** | Menerapkan situs phishing yang didukung oleh reverse proxy yang meneruskan semua lalu lintas ke layanan yang sah secara real-time, menangkap kredensial, respons MFA, dan cookie sesi yang dihasilkan secara bersamaan | Korban diarahkan ke domain phishing; tidak ada penegakan kredensial sesi terikat perangkat |
| **Kit Phishing-as-a-Service** | Platform AitM kelas komersial (Tycoon 2FA, Sneaky 2FA, NakedPages, EvilProxy, Saiga 2FA) yang menyediakan infrastruktur AitM turnkey dengan anti-deteksi, templating umpan, dan eksfiltrasi cookie | Langganan PhaaS; organisasi target menggunakan SSO cloud tanpa token terikat perangkat |
| **AitM Ekstensi Browser** | Ekstensi browser berbahaya yang mencegat alur autentikasi dan mengeksfiltrasi cookie sesi langsung dari penyimpanan cookie browser setelah autentikasi berhasil | Korban menginstal ekstensi berbahaya (misalnya teknik Cookie-Bite) |

Serangan AitM mengalami lonjakan 46% tahun ke tahun pada 2025. Evolusi terbaru melibatkan transisi pengiriman umpan dari kode QR ke lampiran HTML dan file SVG. Kesenjangan pertahanan fundamental adalah bahwa serangan ini mencuri artefak *pasca-autentikasi*, sehingga metode autentikasi yang lebih kuat saja tidak mencukupi.

### §3-5. Cacat Logika Implementasi MFA

Kesalahan arsitektur dalam cara MFA diintegrasikan ke dalam alur autentikasi, memungkinkan faktor kedua dilewati sepenuhnya.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Bypass Lewati-Langkah** | Langkah verifikasi MFA diimplementasikan sebagai halaman/endpoint terpisah. Setelah keberhasilan faktor pertama, langsung menavigasi ke URL pasca-MFA melewati pemeriksaan karena server tidak memverifikasi bahwa faktor kedua benar-benar diselesaikan | Status MFA sisi server tidak dilacak; URL untuk tujuan pasca-MFA dapat diprediksi |
| **Ketidaksesuaian Pengikatan Sesi** | Verifikasi MFA tidak terikat ke sesi yang sama dengan faktor pertama, memungkinkan penyerang untuk menyelesaikan autentikasi faktor pertama dalam satu sesi dan memenuhi MFA dalam sesi berbeda yang mereka kontrol | ID sesi tidak divalidasi di seluruh langkah autentikasi; kode MFA diterima untuk sesi yang menunggu mana pun |
| **Bypass Klasifikasi User Agent** | Kebijakan penegakan MFA mengecualikan user agent tertentu yang diklasifikasikan sebagai "tidak dikenal" (browser tidak umum, skrip Python, alat CLI) dari persyaratan MFA | Kebijakan SSO tidak menegakkan MFA untuk user agent yang tidak dikenal (kerentanan Okta, 2024) |
| **TOCTOU dalam Verifikasi MFA** | Race condition antara pemeriksaan MFA dan pemberian akses memungkinkan permintaan yang melewati selama jendela verifikasi | Pemeriksaan MFA dan otorisasi tidak bersifat atomik; pemrosesan permintaan bersamaan (CVE-2025-62004) |
| **Celah Penegakan MFA OpenID Connect** | RP (Relying Party) tidak memverifikasi apakah IdP benar-benar melakukan MFA selama alur autentikasi OIDC. RP mengabaikan klaim `acr` (Authentication Context Class Reference) atau `amr` (Authentication Methods References) IdP, atau IdP itu sendiri salah dikonfigurasi untuk mengeluarkan klaim tersebut tanpa memerlukan MFA — sepenuhnya melewati 2FA. Penyerang mendaftarkan IdP terpisah dengan MFA yang dinonaktifkan, atau secara selektif menargetkan alur IdP dengan kebijakan MFA yang longgar | RP tidak memvalidasi klaim `acr`/`amr` dalam token OIDC; atau IdP mengeluarkan klaim tingkat jaminan tinggi tanpa memerlukan MFA |
| **Rebinding TOTP Tanpa Autentikasi** | Endpoint penyiapan TOTP/MFA tidak memerlukan autentikasi ulang atau verifikasi MFA saat ini, memungkinkan penyerang dengan akses sesi untuk mengikat ulang rahasia TOTP korban ke autentikator yang dikontrol penyerang | Endpoint pendaftaran/pengaturan ulang TOTP dapat diakses tanpa autentikasi ulang; tidak ada verifikasi perangkat MFA yang ada |
| **Penegakan MFA Hanya Sisi Klien** | Tantangan MFA diimplementasikan sebagai modal atau overlay JavaScript sisi klien tanpa verifikasi sisi server yang sesuai — menonaktifkan JavaScript atau mencegat respons menghapus gerbang MFA sepenuhnya | Penegakan MFA hanya ada dalam kode frontend; backend memberikan akses penuh setelah autentikasi faktor pertama terlepas dari penyelesaian MFA |

---

## §4. Serangan Siklus Hidup Sesi & Token

Menargetkan status autentikasi *setelah* verifikasi kredensial berhasil. Serangan ini melewati kebutuhan untuk mengautentikasi sama sekali dengan mencuri, memanipulasi, atau memprediksi artefak yang mewakili sesi terautentikasi yang telah ditetapkan.

### §4-1. Session Fixation

Memaksa korban untuk menggunakan pengidentifikasi sesi yang telah ditentukan sebelumnya oleh penyerang, yang kemudian dapat digunakan penyerang untuk mengakses sesi setelah korban mengautentikasi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Fixation Berbasis URL** | ID sesi yang disematkan dalam parameter URL; penyerang mengirimkan URL yang berisi ID sesi yang telah ditetapkan sebelumnya kepada korban | Aplikasi menerima ID sesi dari parameter URL; sesi tidak diregenerasi saat login |
| **Fixation Berbasis Cookie** | Penyerang menetapkan cookie sesi di browser korban (melalui XSS, kontrol subdomain, atau injeksi header HTTP) sebelum autentikasi | Cookie dapat ditetapkan di seluruh subdomain; sesi tidak diregenerasi saat login |
| **Fixation Lintas-Subdomain** | Mengeksploitasi cakupan cookie untuk menetapkan cookie sesi dari subdomain yang dikontrol penyerang untuk autentikasi domain induk | Penyerang mengontrol subdomain mana pun; domain cookie ditetapkan terlalu luas |

### §4-2. Session Hijacking dan Pencurian Token

Menangkap atau mengekstrak token sesi yang valid dari pengguna yang terautentikasi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Ekstraksi Cookie Infostealer** | Keluarga malware (RedLine, Raccoon, Vidar, Lumma) mengekstrak cookie sesi, token autentikasi, dan kredensial browser dari mesin korban dalam skala industri — lebih dari 17 miliar cookie dicuri pada tahun 2024 saja | Mesin korban terinfeksi infostealer; log yang dicuri dijual di marketplace darknet |
| **Pencurian Sesi XSS** | Kerentanan cross-site scripting digunakan untuk mengeksfiltrasi cookie sesi melalui JavaScript | Kerentanan XSS dalam aplikasi terautentikasi; cookie tidak ditandai HttpOnly |
| **Sniffing Tingkat Jaringan** | Menangkap token sesi dari lalu lintas jaringan yang tidak terenkripsi atau titik inspeksi yang diterminasi TLS | HTTP tidak terenkripsi sedang digunakan; atau endpoint inspeksi TLS yang dikompromi |
| **Pencurian Cookie Ekstensi Browser** | Ekstensi browser yang berbahaya atau dikompromi dengan izin akses cookie mengeksfiltrasi token autentikasi | Ekstensi dengan izin `cookies` terpasang; ekstensi dapat membaca cookie situs mana pun |
| **Bypass App-Bound Encryption** | Infostealer yang melewati App-Bound Encryption Chrome (dirilis Juli 2024) dalam 45 hari penerapan, terus mengekstrak cookie meskipun ada perlindungan tingkat browser | App-Bound Encryption Chrome diterapkan; infostealer memiliki kemampuan bypass (diamati September 2024) |
| **Eksploitasi Cakupan Cookie Lintas-Subdomain** | Cookie sesi yang dicakupkan ke domain induk dapat diakses dari subdomain mana pun. XSS pada subdomain dengan kepercayaan lebih rendah membaca cookie autentikasi yang dibagikan melalui cakupan seluruh domain, memungkinkan pembajakan sesi pada subdomain dengan kepercayaan lebih tinggi | Atribut `Domain` cookie ditetapkan ke domain induk; XSS pada subdomain mana pun di bawah domain tersebut |
| **Kebocoran Login Nonce / Anti-CSRF Token** | Alur OAuth atau login mengeluarkan nonce satu kali (parameter state anti-CSRF atau token login) yang bocor lintas-origin — melalui header `Referer` ketika nonce disematkan dalam URL yang menavigasi ke sumber daya eksternal, melalui open redirect yang meneruskan URL yang membawa nonce ke domain yang dikontrol penyerang, atau melalui siaran `postMessage` status autentikasi selama urutan login. Penyerang memainkan ulang nonce yang bocor untuk menyelesaikan alur login korban dan mendapatkan sesi mereka | Nonce dikirimkan sebagai parameter kueri URL; halaman target memuat subresource lintas-origin (kebocoran Referer) atau berisi open redirect; nonce satu kali pakai tetapi tidak terikat ke origin |

Skala ekosistem infostealer sangat mengejutkan: 1,8 miliar kredensial dicuri di 5,8 juta perangkat pada tahun 2025, dengan lebih dari 54% korban ransomware memiliki kredensial domain yang muncul di marketplace infostealer *sebelum* serangan. Waktu rata-rata dari log yang dicuri hingga insiden ransomware kurang dari 48 jam.

### §4-3. Token Replay dan Persistensi Sesi

Menggunakan token autentikasi yang dicuri atau ditangkap untuk mendirikan akses tanpa mengautentikasi ulang.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Cookie Replay** | Mengimpor cookie sesi yang dicuri ke browser penyerang untuk mengambil alih sesi terautentikasi korban | Cookie sesi yang valid diperoleh (melalui metode §4-2); tidak ada pengikatan perangkat pada sesi |
| **Pass-the-Cookie** | Varian enterprise-spesifik dari cookie replay yang menargetkan sesi SSO cloud (Azure, Google Workspace, Okta) di mana satu cookie sesi memberikan akses ke beberapa aplikasi | Cookie sesi SSO dicuri; cookie tidak terikat ke perangkat/IP tertentu |
| **Eksploitasi Masa Hidup Token** | Menyalahgunakan masa hidup token yang terlalu panjang — sesi tetap valid selama berhari-hari atau berminggu-minggu tanpa persyaratan autentikasi ulang | Token sesi berumur panjang; tidak ada autentikasi berkelanjutan atau rotasi token |
| **Logout/Pencabutan yang Tidak Memadai** | Token sesi yang tetap valid setelah logout pengguna atau perubahan kata sandi karena server tidak benar-benar membatalkan status sesi sisi server | Token tanpa status tanpa daftar pencabutan sisi server; atau pemeriksaan pencabutan tidak diimplementasikan |

### §4-4. Manipulasi Respons SSO

Merusak respons autentikasi SSO di tingkat HTTP untuk mengubah penolakan menjadi persetujuan.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Pengubahan Kode Status** | Mencegat respons redirect HTTP 302-ke-SSO dan memodifikasinya menjadi 200 OK sambil menghapus header Location, melewati redirect SSO sepenuhnya dan mengakses isi respons internal | Aplikasi mengembalikan konten yang dilindungi bersama dengan redirect 302; intersepsi sisi klien dimungkinkan |
| **Injeksi Header SSO** | Menyuntikkan atau memodifikasi header terkait SSO (misalnya `X-Forwarded-User`, `Remote-User`) yang dipercaya aplikasi untuk identitas terautentikasi tanpa verifikasi independen | Aplikasi mempercayai header identitas yang ditetapkan proxy; penyerang dapat menyuntikkan header secara langsung |

---

## §5. Serangan Arsitektur Kepercayaan SSO

Mengeksploitasi hubungan kepercayaan dalam sistem autentikasi federasi. Serangan ini menargetkan *model kepercayaan* antara Identity Provider (IdP) dan Service Provider (SP), bukan implementasi protokol tertentu. (Serangan khusus SAML/OAuth dikecualikan per cakupan.)

### §5-1. Serangan Protokol CAS (Central Authentication Service)

Kerentanan dalam protokol SSO CAS dan implementasinya.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Bypass Validasi Tiket** | Mengeksploitasi cacat dalam cara tiket layanan CAS divalidasi, memungkinkan tiket palsu atau yang diputar ulang untuk diterima | Implementasi server CAS dengan validasi tiket tidak lengkap; struktur tiket layanan dapat diprediksi |
| **Manipulasi URL Layanan** | Memanipulasi parameter `service` dalam alur autentikasi CAS untuk mengarahkan ulang tiket terautentikasi ke layanan yang dikontrol penyerang | Server CAS tidak memvalidasi URL layanan terhadap daftar izin; open redirect dalam validasi layanan |
| **Penyalahgunaan CAS Proxy Ticket** | Mengeksploitasi autentikasi proxy CAS di mana layanan backend menggunakan proxy ticket untuk mengakses layanan lain atas nama pengguna, meningkatkan akses di luar cakupan yang dimaksudkan | Autentikasi proxy CAS diaktifkan; validasi proxy ticket tidak mencukupi |
| **Cacat Integrasi WebAuthn** | Kerentanan dalam cara CAS mengintegrasikan dengan WebAuthn/FIDO2, memungkinkan bypass autentikasi melalui manipulasi alur | Apereo CAS dengan WebAuthn diaktifkan (ditambal April 2025) |

### §5-2. Kompromi dan Peniruan IdP

Secara langsung mengkompromikan atau meniru Identity Provider untuk memalsukan pernyataan autentikasi sembarang.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Pencurian Kunci Penandatangan IdP** | Mencuri kunci privat yang digunakan IdP untuk menandatangani pernyataan autentikasi, memungkinkan pemalsuan token yang valid secara tidak terbatas untuk pengguna mana pun | Akses ke server IdP, sistem manajemen kunci, atau cadangan (serangan gaya SolarWinds/Nobelium) |
| **Eksploitasi Sinkronisasi AD** | Menargetkan organisasi yang menyinkronkan AD lokal dengan cloud IdP (Azure Entra ID), memanfaatkan kredensial sinkronisasi yang dikompromikan untuk mendapatkan akses tidak terbatas ke sistem identitas cloud | Azure AD Connect atau layanan sinkronisasi serupa diterapkan; kredensial layanan sinkronisasi dikompromikan (Black Hat 2025) |
| **Pendaftaran IdP Jahat** | Mendaftarkan IdP berbahaya dalam lingkungan multi-penyewa atau federasi yang mengeluarkan pernyataan autentikasi palsu yang diterima oleh SP | Kepercayaan federasi memungkinkan pendaftaran IdP dinamis; SP tidak memvalidasi identitas IdP secara ketat |

### §5-3. Eksploitasi Kepercayaan Lintas-Domain

Menyalahgunakan hubungan kepercayaan antara domain, forest, atau batas organisasi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Golden Ticket Lintas-Forest** | Menggunakan hash `krbtgt` yang dikompromikan dari satu forest untuk memalsukan tiket yang diterima di forest yang dipercaya, memanfaatkan hubungan kepercayaan antar-forest | Kepercayaan forest dikonfigurasi; hash `krbtgt` diperoleh dari satu forest; pemfilteran SID tidak diterapkan |
| **Pergerakan Lintas-Domain dMSA** | Serangan Golden dMSA (§2-1) yang memungkinkan pergerakan lateral lintas batas domain dengan membuat kata sandi untuk managed service account di domain yang dipercaya | Windows Server 2025 dMSA diterapkan di seluruh domain; kunci root KDS dikompromikan |
| **Eksploitasi Kata Sandi Akun Kepercayaan** | Mengekstrak atau melakukan brute-force kata sandi akun kepercayaan antar-domain untuk mendirikan autentikasi lintas-domain yang tidak sah | Kata sandi akun kepercayaan tidak dirotasi; dapat diakses melalui kueri LDAP atau ekstraksi database SAM |

### §5-4. Penyalahgunaan Sesi SSO dan Gaya FortiOS

Serangan yang menargetkan mekanisme SSO dalam perangkat jaringan dan perangkat keamanan.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Penyalahgunaan FortiOS SSO** | Memanfaatkan mekanisme kepercayaan SSO di FortiOS untuk melewati alur autentikasi normal, khususnya melalui agen RADIUS dan FSSO (Fortinet Single Sign-On) | FortiOS dengan FSSO dikonfigurasi; penyerang memahami protokol agen FSSO |
| **Bypass Pendaftaran Perangkat** | Melewati pemeriksaan kepatuhan perangkat dalam kebijakan akses bersyarat dengan memanipulasi klaim pendaftaran perangkat atau attestasi dalam alur SSO | Akses bersyarat berdasarkan klaim perangkat; klaim tidak terikat secara kriptografis |

### §5-5. Tabrakan Identitas Multi-Backend

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Tabrakan Pendaftaran LDAP-Database Lokal** | Aplikasi mendukung autentikasi LDAP dan database lokal. Penyerang mendaftarkan akun lokal dengan nama pengguna yang sama dengan pengguna LDAP yang ada — aplikasi menggabungkan kedua identitas, memberikan penyerang akses ke sumber daya pengguna LDAP melalui kredensial yang ditetapkan secara lokal | Backend autentikasi ganda (LDAP + DB lokal) tanpa deduplikasi identitas atau penegakan pengikatan backend |

---

## §6. Serangan Autentikasi Tanpa Kata Sandi & Modern

Menargetkan FIDO2, WebAuthn, passkey, dan mekanisme autentikasi pasca-kata sandi lainnya. Ini mewakili permukaan serangan yang paling baru dan paling sedikit dipelajari.

### §6-1. Manipulasi API WebAuthn

Mengeksploitasi API WebAuthn tingkat browser yang memediasi autentikasi passkey.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Pembajakan API melalui Ekstensi** | Ekstensi browser berbahaya atau JavaScript yang disuntikkan XSS mencegat panggilan `navigator.credentials.create()` dan `navigator.credentials.get()` WebAuthn, memalsukan alur pendaftaran dan login | Ekstensi berbahaya dengan izin yang cukup; atau kerentanan XSS di halaman autentikasi |
| **Kebingungan Discoverable vs. Non-Discoverable** | Server FIDO gagal membedakan antara kredensial discoverable (resident) dan non-discoverable, memungkinkan autentikasi dengan jenis kredensial yang salah dan berpotensi sebagai pengguna yang salah | Bug implementasi server FIDO; jenis kredensial tidak divalidasi selama assertion (CVE-2025-26788, StrongKey FIDO Server) |

### §6-2. Serangan Sinkronisasi Passkey

Menargetkan fabric sinkronisasi cloud yang memungkinkan portabilitas passkey di seluruh perangkat.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Kompromi Akun Penyedia Sinkronisasi** | Jika penyerang mendapatkan akses ke akun yang bertindak sebagai fabric sinkronisasi passkey (Google Password Manager, Apple iCloud Keychain, akun Microsoft), mereka dapat mereplikasi semua passkey yang disinkronkan ke perangkat mereka sendiri | Akun Google/Apple/Microsoft pengguna dikompromikan; passkey disinkronkan melalui penyedia tersebut |
| **Eksploitasi Sinkronisasi Lintas-Perangkat** | Mengeksploitasi protokol autentikasi lintas-perangkat berbasis BLE untuk mengautentikasi dari perangkat penyerang terdekat dengan memulai permintaan WebAuthn yang direspons oleh ponsel korban | Penyerang dalam jangkauan BLE; autentikasi lintas-perangkat diaktifkan; pengguna tidak memperhatikan prompt |

### §6-3. Serangan Hardware Token

Serangan fisik dan logis terhadap kunci keamanan hardware.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Pengisian Penyimpanan Kredensial** | Mengisi semua slot penyimpanan kredensial pada hardware token, mencegah pendaftaran kredensial baru dan memaksa fallback ke metode yang lebih lemah | Penyerang memiliki akses fisik atau tingkat protokol singkat ke token |
| **Lockout Paksa / Factory Reset** | Memicu mekanisme lockout atau factory reset pada hardware token, menghilangkan kredensial yang terdaftar dan memaksa alur pemulihan (yang mungkin lebih lemah) | Pengetahuan tentang ambang kelelahan PIN token; atau akses USB/NFC untuk memicu reset |
| **Pembajakan Kedekatan BLE** | Mengeksploitasi transport Bluetooth Low Energy untuk CTAP2 untuk mencegat atau memulai permintaan autentikasi dari hardware token terdekat | Penyerang dalam jangkauan BLE; kerentanan WebAuthn Chrome Android (CVE-2024-9956) |

### §6-4. Downgrade Metode Autentikasi

Memaksa fallback dari autentikasi tahan phishing ke yang dapat di-phish. (Mekanisme terperinci dalam §3-3; bagian ini mencakup implikasi arsitektur yang lebih luas.)

Ketegangan fundamental adalah bahwa autentikasi tahan phishing yang hampir universal memerlukan **semua** metode fallback untuk dihapus — tetapi organisasi mempertahankan alternatif yang lebih lemah untuk aksesibilitas, kompatibilitas, dan pemulihan bencana. Setiap metode fallback yang dipertahankan menjadi level keamanan *efektif*, terlepas dari seberapa kuat metode primernya.

---

## §7. Bypass Autentikasi Middleware & Framework

Kerentanan dalam cara framework aplikasi, reverse proxy, dan middleware menegakkan autentikasi. Ini melewati autentikasi bukan di tingkat kredensial tetapi di tingkat *arsitektur penegakan*.

### §7-1. Eksploitasi Header Internal / Routing

Menyalahgunakan header atau mekanisme routing yang digunakan framework secara internal untuk mengelola status autentikasi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Injeksi Header Subrequest Middleware** | Menetapkan header framework internal (misalnya Next.js `x-middleware-subrequest`) yang memberi sinyal kepada framework bahwa permintaan telah diautentikasi/diotorisasi oleh middleware, menyebabkan middleware sepenuhnya dilewati | Framework menggunakan header internal untuk kontrol alur middleware; permintaan eksternal tidak dihapus dari header ini (CVE-2025-29927, CVSS 9.1) |
| **Spoofing Header Proxy Tepercaya** | Menyuntikkan header seperti `X-Forwarded-For`, `X-Real-IP`, atau `X-Original-URL` yang digunakan aplikasi untuk menentukan identitas klien atau sumber daya yang diminta, melewati kontrol akses berbasis IP atau routing ke jalur autentikasi yang berbeda | Aplikasi mempercayai header proxy tanpa memverifikasi asal; tidak ada penghapusan header di ingress |
| **Simulasi IP Internal** | Memalsukan header IP sumber untuk tampak seperti lalu lintas internal/localhost, melewati autentikasi yang hanya diperlukan untuk permintaan eksternal | Autentikasi dikecualikan untuk IP internal; IP ditentukan dari header yang dapat dipalsukan |

CVE-2025-29927 Next.js adalah paradigmatik: nilai header tunggal (`x-middleware-subrequest: middleware`) menyebabkan *seluruh* middleware autentikasi dilewati. Kerentanan ini mempengaruhi salah satu framework web yang paling banyak digunakan dengan skor CVSS 9.1.

### §7-2. Bypass Jalur dan Saluran Alternatif

Mencapai fungsionalitas terautentikasi melalui titik masuk alternatif yang tidak memiliki penegakan autentikasi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Bypass Saluran WebSocket** | Mengakses fungsionalitas melalui endpoint WebSocket yang memiliki autentikasi berbeda (lebih lemah) dari endpoint HTTP yang sesuai. Autentikasi pada saluran WebSocket mungkin hanya memeriksa *keberadaan* token tanpa memvalidasi keasliannya | Endpoint WebSocket terekspos bersama HTTP; logika autentikasi tidak dibagikan (CVE-2024-55591, FortiOS, CVSS 9.8) |
| **Ketidaksesuaian Versi API** | Versi API lama yang masih dapat diakses yang memiliki autentikasi lebih lemah atau tidak ada, sementara versi yang lebih baru telah diperkeras | Versi API yang tidak digunakan lagi tidak dihentikan; autentikasi hanya ditambahkan ke versi baru |
| **Eksposur Antarmuka Debug / Manajemen** | Antarmuka administratif atau diagnostik yang dapat diakses tanpa autentikasi saat terekspos ke jaringan yang tidak dimaksudkan | Antarmuka manajemen terikat ke semua antarmuka alih-alih localhost; tidak ada autentikasi terpisah untuk manajemen (CVE-2024-0012, Palo Alto PAN-OS) |
| **Path Traversal ke Endpoint Tidak Terproteksi** | Menggunakan urutan directory traversal untuk menavigasi dari jalur terautentikasi ke yang tidak terautentikasi sambil mempertahankan penampilan akses yang diotorisasi | Inkonsistensi normalisasi jalur antara reverse proxy dan aplikasi; urutan traversal yang dikodekan tidak didekode secara seragam |

CVE-2024-55591 FortiOS (CVSS 9.8) mencontohkan bypass saluran WebSocket: modul WebSocket Node.js hanya memverifikasi *keberadaan* parameter `local_access_token` tanpa memvalidasi keaslian atau pengikatan sesinya, memungkinkan penyerang yang tidak terautentikasi untuk mendapatkan hak istimewa super-admin. Hampir 50.000 instance yang rentan terekspos di Internet.

### §7-3. Pengubahan HTTP Verb dan Metode

Mengeksploitasi penegakan autentikasi yang tidak konsisten di berbagai metode HTTP.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Bypass Method Override** | Menggunakan header override metode HTTP (`X-HTTP-Method-Override`, `X-Method-Override`) untuk mengonversi POST menjadi GET atau HEAD, di mana metode alternatif tidak tunduk pada pemeriksaan autentikasi yang sama | Framework mendukung header override metode; penegakan autentikasi spesifik metode |
| **Bypass Permintaan HEAD** | Mengirim permintaan HEAD ke endpoint yang hanya menegakkan autentikasi pada GET/POST, di mana respons HEAD mengungkapkan informasi atau memicu efek samping | Middleware autentikasi memeriksa jenis metode; HEAD tidak termasuk dalam penegakan |
| **Penyalahgunaan Metode CONNECT / TRACE** | Menggunakan metode HTTP yang tidak umum yang tidak dicakup oleh aturan middleware autentikasi, berpotensi mencapai fungsionalitas backend | Server web meneruskan metode yang tidak biasa ke aplikasi; ACL autentikasi tidak mencakup semua metode |

### §7-4. Diferensial Normalisasi Jalur

Mengeksploitasi perbedaan dalam cara proxy/WAF dan aplikasi menormalisasi jalur URL, memungkinkan permintaan mencapai endpoint terautentikasi sambil tampak mengakses yang tidak terautentikasi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Path Traversal yang Dikodekan** | Teknik double-encoding, encoding UTF-8, atau encoding lainnya yang dinormalisasi berbeda oleh WAF/proxy dibandingkan aplikasi, melewati aturan autentikasi berbasis jalur | WAF menormalisasi sekali; aplikasi menormalisasi dua kali (atau sebaliknya); urutan `/` atau `..` yang dikodekan diperlakukan berbeda |
| **Kebingungan Titik/Garis Miring Akhir** | Menambahkan titik akhir, garis miring, atau sufiks jalur lainnya yang diperlakukan proxy sebagai jalur berbeda (melewati aturan autentikasi) tetapi diperlakukan aplikasi sebagai setara | Pencocokan jalur proxy bersifat eksak; pencocokan jalur aplikasi bersifat fuzzy/dinormalisasi |
| **Injeksi Null Byte** | Menyisipkan null byte (`%00`) dalam jalur URL di mana proxy membaca jalur penuh tetapi aplikasi memotong di null byte, mencapai sumber daya terautentikasi melalui jalur yang tampak tidak terautentikasi | Bahasa/framework memperlakukan null byte sebagai terminator string; proxy/WAF tidak |

---

## §8. Pemulihan Kata Sandi & Pengambilalihan Akun

Mengeksploitasi mekanisme pemulihan akun, yang secara desain menyediakan jalur setara autentikasi yang melewati kredensial utama.

### §8-1. Serangan Token Reset Kata Sandi

Menargetkan alur reset kata sandi berbasis token.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Pembuatan Token yang Dapat Diprediksi** | Token reset yang diturunkan dari nilai yang dapat ditebak (timestamp, ID pengguna, penghitung berurutan) menggunakan algoritma lemah (MD5 dari epoch, Base64 dari email pengguna) | Algoritma pembuatan token kekurangan keacakan kriptografis; token dapat diturunkan dari nilai yang dapat diamati |
| **Penggunaan Ulang Token / Tidak Kedaluwarsa** | Token reset yang tetap valid setelah digunakan, memiliki jendela kedaluwarsa yang terlalu panjang, atau tidak pernah dibatalkan setelah reset berhasil | Tidak ada penegakan satu kali pakai; tidak ada kedaluwarsa; atau kedaluwarsa diukur dalam hari dan bukan menit |
| **Kebocoran Token melalui Referrer** | Token reset dalam parameter URL yang bocor ke situs pihak ketiga melalui header HTTP Referrer ketika halaman reset berisi sumber daya eksternal | Token dalam string kueri URL; halaman reset memuat JavaScript, CSS, atau gambar eksternal |
| **Keracunan Reset Kata Sandi** | Memanipulasi header `Host` dalam permintaan reset kata sandi untuk menyebabkan aplikasi membuat tautan reset yang mengarah ke domain yang dikontrol penyerang, mencuri token ketika korban mengklik | Aplikasi menggunakan header Host untuk membangun URL reset tanpa validasi; email dikirim ke pengguna yang sah dengan domain penyerang |

### §8-2. Bypass Alur Pemulihan Akun

Mengeksploitasi kelemahan dalam proses pemulihan akun secara keseluruhan di luar serangan token.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **IDOR di Endpoint Pemulihan** | Memanipulasi pengidentifikasi pengguna dalam panggilan API pemulihan untuk mereset kata sandi pengguna lain (misalnya mengubah `user_id=123` menjadi `user_id=456` dalam permintaan konfirmasi reset) | Pengidentifikasi pengguna dalam permintaan pemulihan tidak terikat ke sesi pemulihan yang terautentikasi |
| **Bypass Verifikasi Email/Telepon** | Melewati atau memanipulasi langkah verifikasi yang mengonfirmasi kepemilikan email atau nomor telepon pemulihan | Status verifikasi disimpan di sisi klien; atau endpoint verifikasi menerima kode apa pun; atau langkah verifikasi dapat dilewati dengan navigasi URL langsung |
| **Bypass State Machine Alur Pemulihan** | Menyelesaikan langkah pemulihan di luar urutan, atau memainkan ulang token keberhasilan langkah sebelumnya untuk melewati langkah verifikasi selanjutnya | Status alur pemulihan tidak dilacak di sisi server; transisi status tidak divalidasi |
| **Eksploitasi Pertanyaan Keamanan** | Menjawab pertanyaan keamanan menggunakan informasi yang tersedia secara publik (media sosial, pelanggaran data) atau mengeksploitasi pertanyaan dengan ruang jawaban terbatas | Pertanyaan keamanan yang lemah (misalnya "warna favorit"); jawaban tersedia melalui OSINT |
| **Reset MFA melalui Pemulihan** | Menggunakan alur pemulihan akun untuk menghapus atau mereset pendaftaran MFA, kemudian mengautentikasi hanya dengan faktor pertama | Alur pemulihan mengizinkan konfigurasi ulang MFA tanpa verifikasi MFA saat ini |

---

## §9. Akuisisi Kredensial Berskala Besar

Teknik sistematis untuk mendapatkan kredensial yang valid yang memungkinkan bypass autentikasi melalui login yang tampak sah. Ini bukan "bypass" dalam arti tradisional tetapi mewakili jalur utama yang memberi makan semua kategori serangan lainnya.

### §9-1. Password Spraying

Menguji sejumlah kecil kata sandi yang umum digunakan terhadap sejumlah besar akun secara bersamaan, tetap di bawah ambang lockout per akun.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Spray Klasik** | Mencoba kata sandi teratas (misalnya `Musim+Tahun`, `Perusahaan+123`) di semua akun yang dienumerasi dengan penundaan antara percobaan | Lockout akun berdasarkan jumlah percobaan per akun; tidak ada deteksi anomali global |
| **Spray Cerdas** | Menggunakan pola kata sandi yang diturunkan OSINT spesifik untuk organisasi target (tahun didirikan, lokasi kantor, tim olahraga) dikombinasikan dengan struktur kata sandi umum | Informasi organisasi yang tersedia secara publik; kebijakan kata sandi diketahui atau dapat ditebak |
| **Spray Lambat** | Mendistribusikan percobaan selama berhari-hari atau berminggu-minggu dengan interval yang diacak untuk menghindari deteksi berbasis waktu | Deteksi yang disetel untuk percobaan burst; tidak ada perbandingan baseline jangka panjang |

### §9-2. Credential Stuffing

Menguji pasangan kredensial (username + kata sandi) yang bocor dari pelanggaran terhadap layanan target, mengeksploitasi penggunaan ulang kata sandi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Stuffing Langsung** | Pengiriman otomatis pasangan kredensial yang bersumber dari pelanggaran ke endpoint login | Pengguna menggunakan kembali kata sandi di seluruh layanan; tidak ada pemeriksaan kredensial terhadap database pelanggaran |
| **Stuffing Varian** | Menerapkan aturan mutasi kata sandi umum (menambah angka, mengubah musim, menambahkan karakter khusus) ke kata sandi yang diketahui dari pelanggaran | Pengguna membuat modifikasi yang dapat diprediksi pada kata sandi yang dikompromikan |
| **Stuffing dengan Rotasi Proxy** | Mendistribusikan percobaan stuffing di seluruh jaringan proxy residensial untuk menghindari pembatasan laju berbasis IP | Pembatasan laju berdasarkan IP sumber; tidak ada deteksi perilaku/sidik jari |

Skala saat ini: sekitar 26 miliar percobaan stuffing per bulan (2024), dengan tingkat pertumbuhan 50% selama 18 bulan.

### §9-3. Ekosistem Infostealer

Pencurian kredensial skala industri melalui keluarga malware yang mengekstrak kredensial tersimpan, token sesi, dan materi autentikasi dari endpoint yang dikompromikan.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Ekstraksi Penyimpanan Kredensial Browser** | Mengekstrak nama pengguna dan kata sandi yang tersimpan dari penyimpanan kredensial browser (Chrome, Firefox, Edge) | Mesin korban terinfeksi; browser menyimpan kredensial; tidak ada enkripsi tambahan di luar tingkat OS |
| **Pemanenan Cookie Sesi** | Mengekstrak cookie sesi aktif dari penyimpanan browser, memungkinkan akses terautentikasi tanpa kredensial atau MFA (diperinci dalam §4-2) | Cookie browser tidak terikat ke perangkat; cookie dapat diakses oleh malware dengan hak istimewa tingkat pengguna |
| **Pencurian Sertifikat dan Kunci** | Mengekstrak sertifikat klien dan kunci privat dari penyimpanan kredensial sistem operasi | Penyimpanan sertifikat dapat diakses dengan hak istimewa tingkat pengguna; tidak ada perlindungan kunci terikat hardware |
| **Marketplace Log Kredensial** | Kredensial yang dicuri diagregasi dan dijual di marketplace darknet (Russian Market, Genesis) dengan pemfilteran berdasarkan domain, layanan, dan kesegaran | Infrastruktur marketplace kriminal yang matang; log dihargai $1–$50 per mesin |

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama | Rantai Umum |
|----------|------------|----------------------|-------------|
| **Kompromi Domain AD Penuh** | Active Directory lokal | §2 + §9 | Credential stuffing (§9-2) → Golden Ticket (§2-1) |
| **Pengambilalihan Akun Cloud/SaaS** | Azure/Entra, Okta, Google Workspace | §3 + §4 + §9 | Infostealer (§9-3) → Cookie replay (§4-3) → Akses lateral melalui SSO |
| **Pengambilalihan Perangkat Jaringan** | Firewall, VPN, antarmuka manajemen | §7 + §1 | Bypass WebSocket (§7-2) atau injeksi middleware (§7-1) → Akses admin |
| **Akses Aplikasi Web** | Aplikasi kustom | §1 + §7 + §8 | LDAP injection (§1-2) → Session fixation (§4-1) → Pengambilalihan akun |
| **Bypass Akun yang Dilindungi MFA** | Enterprise dengan MFA yang diterapkan | §3 + §6 | Serangan downgrade (§3-3) → Intersepsi AitM (§3-4) → Pencurian sesi (§4-2) |
| **Backdoor Domain Persisten** | Windows Server 2025 | §2-1 + §5-3 | Golden dMSA (§2-1) → Pergerakan lintas-domain (§5-3) → Akses tidak terbatas |
| **Pivot Sinkronisasi AD ke Cloud** | Hybrid lokal + cloud | §5-2 + §2 | Kompromi kredensial sinkronisasi AD (§5-2) → Kontrol cloud IdP → Seluruh tenant |
| **Eksploitasi Alur Pemulihan** | Aplikasi web mana pun | §8 + §4 | Keracunan reset (§8-1) → Reset kata sandi → Reset MFA (§8-2) → Akses penuh |

---

## Pemetaan CVE / Bounty (2024–2025)

| Kombinasi Mutasi | CVE / Kasus | Produk | Dampak / CVSS |
|-----------------|-------------|--------|---------------|
| §1-1 (Pemotongan Hash) | Okta Advisory (Okt 2024) | Okta AD/LDAP DelAuth | Bypass auth melalui pemotongan bcrypt 52-karakter; tidak ada CVE yang ditetapkan |
| §1-2 (LDAP Injection) | CVE-2024-37782 | Gladinet CentreStack v13.12 | Akses tidak sah + RCE melalui injeksi kolom username |
| §1-2 (Eksploitasi ACL LDAP) | CVE-2025-29810 | Windows AD Domain Services | Eskalasi hak istimewa ke SYSTEM; CVSS 7.5 |
| §2-1 (Golden dMSA) | Semperis Disclosure (Mei 2025) | Windows Server 2025 dMSA | Bypass auth untuk semua managed service account; Microsoft: "by design" |
| §3-1 (Brute Force TOTP) | Oasis Security (Des 2024) | Microsoft Azure MFA | AuthQuake: brute-force TOTP paralel sesi; tidak ada CVE yang ditetapkan |
| §3-5 (Bypass User Agent) | Okta Advisory (2024) | Okta SSO Policies | Bypass MFA melalui klasifikasi user agent yang tidak dikenal |
| §5-1 (CAS WebAuthn) | Apereo Advisory (Apr 2025) | Apereo CAS 7.x | Bypass autentikasi dalam integrasi WebAuthn; CVSS ~7.5 |
| §5-1 (CAS Flow Mgmt) | Apereo Advisory (Sep 2025) | Apereo CAS 7.x | Manipulasi alur OAuth/OIDC → bypass auth; CVSS ~7.5 |
| §6-1 (FIDO Credential Confusion) | CVE-2025-26788 | StrongKey FIDO Server 4.10–4.15 | Pengambilalihan akun melalui kebingungan kredensial discoverable/non-discoverable |
| §6-3 (Pembajakan Kedekatan BLE) | CVE-2024-9956 | Google Chrome Android | Serangan kedekatan BLE WebAuthn → penangkapan kredensial |
| §7-1 (Header Middleware) | CVE-2025-29927 | Next.js (semua versi) | Bypass middleware auth lengkap; CVSS 9.1 |
| §7-2 (Bypass WebSocket) | CVE-2024-55591 | FortiOS 7.0.x / FortiProxy | Super-admin melalui WebSocket; CVSS 9.8; zero-day yang dieksploitasi sejak Nov 2024 |
| §7-2 (Antarmuka Mgmt) | CVE-2024-0012 | Palo Alto PAN-OS | Akses admin tanpa autentikasi ke antarmuka web manajemen |
| §7-2 (Antarmuka Mgmt) | CVE-2025-0108 | Palo Alto PAN-OS | Bypass auth di antarmuka web manajemen |
| §2-1 (Autentikasi Sertifikat Kerberos) | CVE-2025-26647 | Windows Kerberos | Bypass auth berbasis sertifikat ketika penerbit cert tidak ada di NTAuth store |
| §2-1 (Penyimpanan Kerberos) | CVE-2025-29809 | Windows Kerberos | Bypass fitur keamanan melalui penyimpanan kunci Kerberos yang tidak aman; CVSS 7.1 |
| §6-1 (WSO2 mTLS) | CVE-2025-9312 | Produk WSO2 | Bypass auth mTLS → hak istimewa admin pada REST/SOAP API |
| §3-5 (TOCTOU MFA) | CVE-2025-62004 | BullWall Server | Race condition yang melewati MFA setelah autentikasi admin awal; CVSS 7.5 |
| §5-4 (NTLM Relay) | CVE-2021-33768, CVE-2022-21979 | Microsoft Exchange (ProxyRelay) | NTLM relay antar server Exchange melalui coercion PrinterBug. Akun mesin dalam grup Exchange Servers memiliki hak `ms-Exch-EPI-Token-Serialization` secara default, memungkinkan peniruan pengguna mana pun. Cacat desain arsitektur |
| §7-2 (Baca File Pre-auth) | CVE-2018-13379 | Fortinet FortiGate SSL VPN | Baca file sembarang pra-auth melalui buffer overflow `snprintf` yang menghapus sufiks `.json`; membocorkan file sesi yang berisi kredensial plaintext |
| §7-2 (Backdoor Hardcoded) | CVE-2018-13382 | Fortinet FortiGate SSL VPN | Parameter "magic" hardcoded di antarmuka login memungkinkan reset kata sandi untuk pengguna mana pun tanpa autentikasi |
| §7-2 (Baca File Pre-auth) | CVE-2019-11510 | Pulse Secure Connect | Baca file sembarang pra-auth melalui path traversal di fitur HTML5 Access; membocorkan token sesi plaintext dan kredensial yang di-cache |

---

## Alat Deteksi

### Alat Ofensif / Pengujian

| Alat | Cakupan Target | Teknik Utama |
|------|----------------|--------------|
| **Impacket** | Kerberos, LDAP, SMB | Library Python untuk interaksi protokol jaringan; termasuk GetTGT, GetST, secretsdump |
| **Rubeus** | Kerberos (Windows) | Toolkit penyalahgunaan Kerberos C#: pemalsuan tiket, overpass-the-hash, manipulasi tiket |
| **Evilginx** | Phishing AitM / bypass MFA | Framework phishing reverse proxy open-source untuk intersepsi cookie sesi real-time |
| **CrackMapExec / NetExec** | Rekognisi AD + pengujian kredensial | Credential spraying seluruh jaringan, operasi tiket Kerberos |
| **Hashcat / John the Ripper** | Cracking kredensial offline | Cracking hash yang dipercepat GPU untuk token autentikasi, seed TOTP |
| **Burp Suite** | Pengujian autentikasi web | Intersepsi HTTP, analisis alur autentikasi, pengujian manajemen sesi |
| **Nuclei** | Pemindaian CVE | Pemindai kerentanan berbasis template dengan template deteksi bypass auth |
| **NextSploit** | CVE-2025-29927 | Pemindai/exploiter khusus untuk bypass auth middleware Next.js |

### Alat Defensif / Deteksi

| Alat | Cakupan Target | Teknik Utama |
|------|----------------|--------------|
| **CrowdStrike Identity Protection** | Serangan autentikasi AD | Deteksi ancaman identitas real-time; pemantauan autentikasi anomali |
| **Microsoft Defender for Identity** | Serangan autentikasi AD | Deteksi Golden Ticket, pass-the-hash melalui sensor DC |
| **Semperis Directory Services Protector** | Serangan persistensi AD | Deteksi dan respons Golden Ticket, penyalahgunaan dMSA, DCSync |
| **OWASP ZAP** | Pengujian autentikasi web | DAST open-source dengan fuzzing alur autentikasi |
| **SSOScan** | Pengujian implementasi SSO | Deteksi kerentanan SSO otomatis (berfokus pada Facebook SSO) |
| **BloodHound / SharpHound** | Analisis jalur serangan AD | Analisis berbasis grafik atas hubungan kepercayaan AD, delegasi, dan jalur eskalasi |
| **PingCastle** | Penilaian keamanan AD | Penilaian kesehatan Active Directory dan analisis permukaan serangan |

---

## Ringkasan: Prinsip-Prinsip Inti

### Akar Masalah: Celah Materialisasi Kepercayaan

Seluruh permukaan serangan bypass autentikasi ada karena masalah arsitektur fundamental: **autentikasi adalah peristiwa satu titik waktu yang hasilnya harus dimaterialisasi menjadi artefak persisten dan dapat dipindahtangankan** (token sesi, tiket Kerberos, cookie, assertion) yang dipercaya oleh sistem berikutnya tanpa verifikasi ulang. Setiap teknik dalam taksonomi ini pada akhirnya mengeksploitasi celah antara *peristiwa* autentikasi dan *kepercayaan* yang berkelanjutan pada artefak yang dimaterialisasinya.

Tiket Kerberos dapat dipalsukan karena kepercayaan dimaterialisasi dalam struktur data yang ditandatangani, dan kunci penandatanganan adalah rahasia yang dapat dipulihkan. Cookie sesi dapat diputar ulang karena kepercayaan dimaterialisasi dalam artefak browser yang portabel. MFA dapat dilewati melalui AitM karena penyerang mencegat titik materialisasi. Alur pemulihan menciptakan jalur materialisasi alternatif dengan verifikasi yang lebih lemah. Bahkan serangan Golden dMSA mengeksploitasi cacat dalam cara *derivasi* kata sandi managed-service-account dimaterialisasi sebagai masalah brute-force 1.024 kemungkinan.

### Mengapa Patch Inkremental Gagal

1. **Lapisan pertahanan mendalam dapat diserang secara independen**: Setiap lapisan autentikasi (verifikasi kredensial, MFA, manajemen sesi, kepercayaan SSO) dapat dilewati secara independen. Memperkuat satu lapisan tidak melindungi terhadap bypass lapisan lainnya. Tren 2024–2025 berupa rantai AitM + infostealer menunjukkan bahwa bahkan MFA "tahan phishing" dilewati dengan menyerang lapisan sesi yang berada *di atasnya*.

2. **Ossifikasi protokol**: Protokol seperti Kerberos (dirancang sebelum model ancaman modern) dan mekanisme autentikasi warisan tidak dapat dirancang ulang secara fundamental tanpa merusak kompatibilitas dengan jutaan sistem yang sudah diterapkan.

3. **Masalah fallback**: Setiap sistem autentikasi mempertahankan alternatif yang lebih lemah untuk pemulihan bencana, aksesibilitas, atau kompatibilitas. Serangan downgrade autentikasi tahun 2025 membuktikan bahwa keamanan *efektif* dari sistem mana pun sama dengan metode fallback yang dipertahankan yang paling lemah.

4. **Proliferasi batas kepercayaan**: Ledakan SSO, federasi, sinkronisasi cloud, dan arsitektur hybrid berarti batas kepercayaan autentikasi berkembang biak lebih cepat dari yang dapat diamankan. Setiap hubungan kepercayaan (AD ↔ Azure, IdP ↔ SP, klien LDAP ↔ server) adalah permukaan serangan yang independen.

### Solusi Struktural

Satu-satunya mitigasi yang komprehensif adalah yang langsung mengatasi celah materialisasi kepercayaan:

- **Kredensial sesi terikat perangkat (DBSC)**: Pengikatan token sesi secara kriptografis ke perangkat tertentu mencegah replay bahkan jika cookie dicuri, sepenuhnya mengatasi §4.
- **Autentikasi berkelanjutan**: Memverifikasi ulang identitas sepanjang sesi daripada mempercayai peristiwa autentikasi satu titik waktu, mengatasi §4 dan mengurangi nilai bypass §3.
- **Kebijakan MFA tanpa fallback**: Menghilangkan semua metode fallback yang dapat di-phish, menerima trade-off kegunaan/aksesibilitas, yang merupakan satu-satunya pertahanan terhadap serangan downgrade §3-3.
- **Modernisasi protokol**: Menegakkan enkripsi AES untuk semua operasi Kerberos, mewajibkan protokol autentikasi modern di atas mekanisme warisan, dan memerlukan pengikatan saluran kriptografis.
- **Arsitektur tanpa kredensial**: Bergerak menuju sistem di mana tidak ada rahasia yang dapat diekstrak saat diam (passkey terikat hardware tanpa sinkronisasi, autentikasi berbasis sertifikat dengan kunci yang tidak dapat diekspor), yang secara struktural menghilangkan serangan akuisisi kredensial §9.

Lintasannya jelas: keamanan autentikasi harus berkembang dari "verifikasi sekali, percaya selamanya" menjadi "verifikasi terus-menerus, jangan percaya apa pun." Sampai transisi itu selesai, teknik-teknik yang didokumentasikan dalam taksonomi ini akan terus berkembang lebih cepat dari yang dapat ditahan oleh pertahanan titik.

---

## Referensi

- Semperis, "Golden dMSA: What Is dMSA Authentication Bypass?," Juli 2025
- Oasis Security, "Microsoft Azure MFA Bypass," Desember 2024
- IOActive, "Authentication Downgrade Attacks: Deep Dive into MFA Bypass," 2025
- Proofpoint, "Don't Phish-let Me Down: FIDO Authentication Downgrade," 2025
- JFrog, "CVE-2025-29927 - Authorization Bypass in Next.js," Maret 2025
- Watchtowr Labs, "FortiOS Authentication Bypass CVE-2024-55591," Januari 2025
- Sekoia, "Global Analysis of Adversary-in-the-Middle Phishing Threats," 2025
- Securing.pl, "CVE-2025-26788: Passkey Authentication Bypass in StrongKey FIDO Server," Februari 2025
- PortSwigger Research, "The Fragile Lock: Novel Bypasses for SAML Authentication," 2025
- Apereo Foundation, "CAS OAuth/OpenID Connect & WebAuthn Vulnerability Disclosure," April/September 2025
- Varonis, "Cookie-Bite: How Your Digital Crumbs Let Threat Actors Bypass MFA," 2025
- Microsoft Security Blog, "Defending Against Evolving Identity Attack Techniques," Mei 2025
- Okta Trust Center, "AD/LDAP Delegated Authentication Username Above 52 Characters Security Advisory," November 2024
- ZeroPath, "CVE-2025-9312: WSO2 mTLS Authentication Bypass," 2025
- DeepStrike, "Stealer Log Statistics 2025: Inside the Credential Theft Boom," 2025
- OWASP, "A07 Authentication Failures - OWASP Top 10:2025," 2025
- Hack The Box, "8 Powerful Kerberos Attacks," 2025
- PortSwigger Web Security Academy, "Authentication Vulnerabilities," 2025
- Datadog Security Labs, "Understanding CVE-2025-29927: The Next.js Middleware Authorization Bypass," 2025

---

*Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan.*