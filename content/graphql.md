---
title: "GraphQL"
description: ""
---

## Struktur Klasifikasi

Taksonomi ini mengorganisasi seluruh attack surface keamanan GraphQL di bawah tiga sumbu ortogonal yang berasal dari analisis sistematis CVE, laporan bug bounty, penelitian akademis, tulisan praktisi, dan offensive tooling.

**Sumbu 1 — Target Attack Surface (Sumbu Utama):** Komponen struktural dari ekosistem GraphQL yang menjadi target. Ini membentuk isi utama dokumen, mengorganisasi teknik berdasarkan *apa* yang diserang — mulai dari mekanisme schema discovery hingga protokol transport layer. Sepuluh kategori tingkat teratas mencakup seluruh ruang mutasi.

**Sumbu 2 — Mekanisme Eksploitasi (Sumbu Lintas):** Sifat dari teknik eksploitasi yang membuat setiap serangan berhasil. Satu target attack surface mungkin dapat dieksploitasi melalui beberapa mekanisme, dan satu mekanisme mungkin berlaku di berbagai target.

| Kode | Mekanisme | Deskripsi |
|------|-----------|-----------|
| **M1** | Information Disclosure | Membocorkan struktur internal, tipe, field, atau data debug |
| **M2** | Resource Exhaustion | Mengonsumsi sumber daya server secara tidak proporsional (CPU, memori, DB) |
| **M3** | Injection / Code Execution | Menyuntikkan payload berbahaya melalui input resolver |
| **M4** | Authorization Bypass | Mengakses data atau operasi tanpa izin yang tepat |
| **M5** | Input Validation Bypass | Menghindari filter, allowlist, atau logika sanitasi |
| **M6** | Protocol / Transport Abuse | Mengeksploitasi penanganan HTTP, WebSocket, atau content-type |
| **M7** | Cache Manipulation | Meracuni atau menyalahgunakan caching layer |

**Sumbu 3 — Impact Scenario (Sumbu Pemetaan):** Konsekuensi nyata ketika sebuah teknik berhasil dipersenjatai — reconnaissance, DoS, data exfiltration, privilege escalation, RCE, account takeover, atau SSRF. Dipetakan dalam §11.

### Konteks Fundamental: Mengapa GraphQL Menciptakan Attack Surface yang Unik

Filosofi desain inti GraphQL — satu endpoint, query yang dikendalikan klien, schema yang strongly-typed, dan introspection yang aktif secara default — secara fundamental mengubah model keamanan dibandingkan REST API. Dalam REST, attack surface terdistribusi di banyak endpoint dengan otorisasi yang spesifik per endpoint. Dalam GraphQL, satu endpoint `/graphql` menangani bentuk query yang tak terbatas, dan klien mendikte secara tepat field mana yang akan diambil, mutation mana yang akan dipanggil, dan seberapa dalam relasi yang akan ditelusuri. Kontrol sisi klien ini, dikombinasikan dengan sifat schema yang self-documenting, menciptakan attack surface yang terpusat dan unik untuk dieksploitasi.

---

## §1. Schema Discovery & Information Disclosure

Serangan schema discovery menarget sifat self-documenting GraphQL untuk merekonstruksi struktur internal API, mengungkap tipe, field, argumen, mutation, dan relasi yang menginformasikan eksploitasi selanjutnya.

### §1-1. Penyalahgunaan Introspection Query

Spesifikasi GraphQL menyertakan sistem introspection bawaan yang memungkinkan klien melakukan query pada schema untuk mendapatkan metadata lengkap tentang semua tipe, field, argumen, directive, dan relasi.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Full introspection dump** | Mengirim query `__schema` atau `__type` untuk mengambil definisi schema lengkap, termasuk semua query, mutation, subscription, input type, dan enum value | Introspection diaktifkan di produksi (default pada sebagian besar implementasi) |
| **Selective type probing** | Melakukan query `__type(name: "...")` untuk tipe tertentu (mis. `User`, `Admin`, `InternalConfig`) untuk menghindari deteksi oleh monitor yang memperhatikan full introspection | Introspection diaktifkan; tidak ada kontrol akses per tipe pada meta-field |
| **Introspection via parameter GET** | Mengodekan introspection query sebagai parameter query URL dalam request GET, melewati WAF atau middleware yang hanya memeriksa POST body | Server menerima query berbasis GET; WAF hanya memantau POST |
| **Introspection melalui content-type alternatif** | Mengirimkan introspection query dengan content-type `application/x-www-form-urlencoded` atau `multipart/form-data` alih-alih `application/json` | Server menerima berbagai content-type tanpa pembatasan |

### §1-2. Enumerasi Field Suggestion

Ketika introspection dinonaktifkan, server GraphQL seringkali masih mengekspos informasi schema melalui pesan error yang menyarankan nama field serupa ketika klien melakukan query pada field yang tidak ada.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Ekstraksi suggestion berbasis typo** | Melakukan query dengan nama field yang salah eja secara sengaja (mis. `usern` alih-alih `username`) untuk memicu respons "Did you mean...?" dari server, mengungkap nama field yang valid | Fitur field suggestion diaktifkan (default di Apollo, graphql-js, dan lainnya) |
| **Rekonstruksi schema berbasis dictionary** | Melakukan probing sistematis dengan dictionary nama field umum (mis. `password`, `token`, `secret`, `admin`, `internal`) dan menganalisis respons suggestion untuk merekonstruksi schema tanpa introspection | Field suggestion diaktifkan; tidak ada rate limiting pada query yang gagal |
| **Recursive suggestion chaining** | Menggunakan nama field yang ditemukan dari suggestion awal sebagai seed untuk probe selanjutnya, secara progresif mengungkap bagian schema yang lebih dalam | Schema besar dengan banyak tipe yang saling terhubung |

Alat seperti Clairvoyance mengotomatiskan proses ini dengan melakukan probing sistematis pada API dan merekonstruksi schema tersembunyi dari pesan error.

### §1-3. Kebocoran Informasi Berbasis Error

Respons error verbose dari server GraphQL dapat mengungkap detail implementasi internal, struktur database, path file, dan informasi technology stack.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Eksposur stack trace** | Mengirim query yang tidak valid atau memicu exception resolver untuk mendapatkan stack trace terperinci yang mengandung path file, versi library, dan nama fungsi internal | Mode debug diaktifkan di produksi; format error tidak difilter |
| **Propagasi error database** | Membuat input yang menyebabkan error database (mis. type mismatch, pelanggaran constraint) yang merambat melalui resolver ke dalam respons error GraphQL, mengungkap nama tabel, nama kolom, dan struktur query | Resolver meneruskan error database mentah ke error handler GraphQL |
| **Pengungkapan resolver path** | Memicu error dalam resolver bersarang untuk mengungkap jalur rantai resolver lengkap, mengekspos arsitektur layanan internal dan struktur relasi | Tidak ada middleware error masking; path error terperinci diaktifkan |
| **Type system error mining** | Mengirimkan query dengan tipe argumen yang salah untuk mengekstrak informasi tipe dari pesan error validasi (mis. "Expected type Int!, found String") | Validasi GraphQL default; tidak ada custom error formatter |

### §1-4. Fingerprinting Server Engine

Mengidentifikasi implementasi server GraphQL yang spesifik (Apollo, Hasura, graphql-java, Yoga, dll.) memungkinkan eksploitasi terarah dari CVE yang diketahui dan perilaku spesifik implementasi.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Behavioral fingerprinting** | Mengirimkan campuran query yang tidak berbahaya dan yang tidak valid, lalu menganalisis pola respons (format pesan error, status code, nilai header) yang berbeda antar implementasi | Endpoint GraphQL dapat diakses |
| **Diferensial format error** | Membandingkan struktur respons error (urutan field JSON, konvensi kode error, field extension) terhadap signature implementasi yang diketahui | Konfigurasi error handling default |
| **Deteksi protokol subscription** | Melakukan probing pada endpoint WebSocket untuk dukungan subscription dan menganalisis pola handshake untuk mengidentifikasi library transport yang mendasarinya | Endpoint WebSocket terekspos |

---

## §2. Eksploitasi Struktur Query (Denial of Service)

Bahasa query GraphQL yang fleksibel memungkinkan klien membangun query yang sangat kompleks. Tanpa kontrol sisi server, kemampuan ini menjadi vektor denial-of-service yang kuat.

### §2-1. Serangan Berbasis Depth

Schema GraphQL sering mengandung relasi sirkular (mis. `User → Posts → Author → Posts → Author...`), memungkinkan konstruksi query yang sangat bersarang yang secara eksponensial memperkuat panggilan database.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Eksploitasi relasi sirkular** | Membangun query yang melintasi relasi tipe sirkular hingga depth yang tak terbatas (mis. `{ user { posts { author { posts { author ... } } } } }`) | Referensi tipe sirkular dalam schema; tidak ada batas depth |
| **Deep nesting dengan list field** | Menyarangkan list-type field yang mengembalikan array, di mana setiap level mengalikan ukuran respons secara eksponensial (mis. 10 user × 10 post × 10 komentar = 1.000 objek pada depth 3) | List field dalam relasi sirkular; tidak ada complexity analysis |
| **Selective depth amplification** | Menarget cabang spesifik dari graph schema yang diketahui mahal secara komputasi (mis. field yang melibatkan JOIN, full-text search, atau panggilan API eksternal) pada depth maksimum | Resolver yang mahal tanpa batas biaya per resolver |

### §2-2. Serangan Berbasis Width (Alias Abuse)

Alias GraphQL memungkinkan field yang sama diminta berkali-kali dengan nama berbeda dalam satu query, memungkinkan amplifikasi horizontal.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Alias multiplication** | Meminta field yang mahal ratusan kali menggunakan alias (`a1: expensiveField, a2: expensiveField, ... a1000: expensiveField`) dalam satu query | Tidak ada batas jumlah alias; tidak ada query complexity analysis |
| **Brute force berbasis alias** | Menggunakan alias untuk mengeksekusi beberapa percobaan autentikasi (mis. mutation login) dalam satu HTTP request, melewati rate limit per request | Rate limiting diterapkan per HTTP request, bukan per operasi |
| **Amplifikasi alias lintas-field** | Menggabungkan alias di beberapa field yang mahal untuk memaksimalkan komputasi sisi server dalam satu query | Beberapa resolver mahal dapat diakses; tidak ada batas biaya agregat |

### §2-3. Serangan Berbasis Fragment

Fragment GraphQL memungkinkan reuse dan komposisi query tetapi dapat dipersenjatai untuk amplifikasi dan penghindaran.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Referensi fragment sirkular** | Membuat fragment yang secara rekursif mereferensikan satu sama lain (`fragment A on User { ...B }` / `fragment B on User { ...A }`), menyebabkan rekursi tak terbatas selama validasi atau eksekusi query | Server GraphQL tidak mendeteksi referensi fragment sirkular sebelum eksekusi |
| **Fragment spread amplification** | Menyebarkan fragment besar yang sama di banyak field atau alias untuk mengalikan ukuran query efektif setelah ekspansi fragment | Tidak ada complexity analysis pasca-ekspansi |
| **Type confusion inline fragment** | Menggunakan inline fragment pada tipe union/interface untuk meminta field dari beberapa tipe konkret, memperkuat jumlah field yang di-resolve melampaui apa yang tampak dalam teks query | Tipe union/interface dengan banyak tipe implementasi |

### §2-4. Directive Overloading

Directive memodifikasi perilaku query, dan ketika di-overload, dapat menguras sumber daya server atau melewati kontrol keamanan.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Penerapan directive berulang** | Menerapkan directive yang sama (mis. `@skip`, `@include`, atau custom directive) ratusan kali pada satu field, memaksa server mengevaluasi setiap pemanggilan directive | Tidak ada batas jumlah directive per field (CVE-2022-37734 di graphql-java) |
| **Injeksi directive yang tidak ada** | Menyertakan referensi ke directive yang tidak ada di server, memaksa layer validasi melakukan pencarian menyeluruh | Validasi memproses semua directive sebelum menolak yang tidak diketahui |
| **Resource exhaustion custom directive** | Menarget custom directive yang melakukan operasi mahal (pencarian database, panggilan API eksternal, operasi kriptografi) dengan menerapkannya di banyak field | Custom directive dengan efek samping; tidak ada penugasan biaya per directive |

### §2-5. Batch Query Amplification

Server GraphQL sering mendukung pemrosesan beberapa operasi dalam satu HTTP request, baik via array batching maupun query batching.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Array batch flooding** | Mengirimkan array berisi ratusan atau ribuan query dalam satu POST body (`[{query: "..."}, {query: "..."}, ...]`) untuk memperkuat beban kerja server | Array batching diaktifkan; tidak ada batas ukuran batch |
| **Batch + depth terkombinasi** | Melakukan batching beberapa query yang sangat bersarang secara bersamaan, menggabungkan amplifikasi horizontal dan vertikal | Batching dan query dalam maupun diizinkan tanpa batas agregat |
| **OTP exhaustion berbasis batch** | Mengirimkan semua nilai OTP yang mungkin (mis. 000000–999999) sebagai operasi individual dalam request yang di-batch untuk brute-force two-factor authentication | Batching diaktifkan untuk mutation autentikasi; rate limiting per request |

---

## §3. Injection Melalui Resolver

GraphQL sendiri adalah layer bahasa query — pengambilan data aktual terjadi di resolver. Ketika resolver membangun query backend menggunakan input klien yang tidak tersanitasi, kerentanan injection klasik muncul.

### §3-1. SQL Injection via Argumen GraphQL

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Injeksi argumen langsung** | Menyuntikkan payload SQL melalui argumen query/mutation (mis. `user(name: "' OR 1=1 --")`) yang langsung digabungkan ke dalam query SQL oleh resolver | Resolver menggunakan string concatenation untuk konstruksi SQL |
| **Injeksi parameter filter/sort** | Menyuntikkan SQL melalui parameter filter atau sorting dinamis (mis. `users(orderBy: "name; DROP TABLE users--")`) | Resolver filter/sort kustom tanpa parameterized query |
| **Injeksi input object bersarang** | Mengeksploitasi tipe input yang sangat bersarang di mana field bagian dalam cenderung tidak divalidasi (mis. `createUser(input: { address: { city: "'; DROP TABLE--" } })`) | Validasi input yang tidak konsisten di seluruh tipe input bersarang |

### §3-2. NoSQL Injection

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Injeksi operator MongoDB** | Menyuntikkan operator query MongoDB melalui argumen GraphQL (mis. `user(filter: { password: { $gt: "" } })`) untuk memanipulasi logika query | Resolver langsung meneruskan argumen ke query builder MongoDB |
| **Manipulasi query berbasis JSON** | Mengeksploitasi penanganan input JSON native GraphQL untuk menyuntikkan operator NoSQL yang tidak mungkin dilakukan dalam parameter REST berbasis URL | Tipe input GraphQL dipetakan langsung ke dokumen query NoSQL |

### §3-3. Server-Side Request Forgery (SSRF)

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **SSRF argumen URL** | Menyediakan URL yang dikendalikan penyerang dalam argumen mutation (mis. `importData(url: "http://169.254.169.254/latest/meta-data/")`) yang diambil oleh resolver sisi server | Resolver melakukan HTTP request berdasarkan URL yang disediakan pengguna |
| **SSRF mutation file upload** | Mengeksploitasi mutation file upload yang menerima URL alih-alih data file, menyebabkan server mengambil dari endpoint internal atau cloud metadata | Mutation upload menerima parameter URL untuk pengambilan file jarak jauh |
| **SSRF webhook/callback** | Menyuntikkan URL internal ke dalam mutation konfigurasi webhook atau notifikasi | Mutation mengizinkan pengaturan callback URL tanpa validasi domain |

### §3-4. OS Command Injection

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Shell execution resolver** | Menyuntikkan shell command melalui argumen yang diteruskan ke `exec()`, `system()`, atau fungsi serupa dalam resolver (mis. `convertFile(filename: "file.pdf; cat /etc/passwd")`) | Resolver menggunakan input pengguna dalam shell command |
| **Template injection melalui resolver** | Menyuntikkan sintaks template (mis. `{{7*7}}` untuk Jinja2) melalui argumen yang melewati server-side template engine | Output resolver melewati template engine tanpa sanitasi |

### §3-5. Cross-Site Scripting (XSS) via GraphQL

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Stored XSS via mutation** | Mengirimkan payload XSS melalui mutation (mis. `updateProfile(bio: "<script>...</script>")`) yang disimpan dan kemudian di-render di browser pengguna lain | Mutation menerima konten HTML/skrip; output tidak tersanitasi |
| **Reflected XSS melalui pesan error** | Menyuntikkan konten skrip yang tercermin dalam respons error GraphQL yang di-render dalam konteks browser (mis. antarmuka GraphiQL) | Pesan error di-render tanpa HTML encoding di UI klien |
| **XSS yang dikirim via subscription** | Mendorong payload XSS melalui channel subscription ke klien yang terhubung | Data subscription di-render dalam DOM tanpa sanitasi |

---

## §4. Serangan Autentikasi & Sesi

Arsitektur single-endpoint GraphQL memusatkan tantangan autentikasi. Tidak seperti REST di mana endpoint yang berbeda dapat memiliki persyaratan autentikasi yang berbeda, server GraphQL harus menangani autentikasi secara seragam di semua operasi.

### §4-1. Authentication Bypass

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Akses mutation tanpa autentikasi** | Mengakses mutation sensitif (mis. `resetPassword`, `changeEmail`, `createAdmin`) tanpa token autentikasi apa pun dengan langsung memanggil endpoint GraphQL | Middleware autentikasi tidak ada pada mutation tertentu |
| **Bypass tipe operasi alternatif** | Menggunakan query untuk melakukan tindakan yang hanya dilindungi ketika dipanggil sebagai mutation, atau mengakses endpoint subscription yang melewati pemeriksaan auth level query | Penegakan auth yang tidak konsisten di seluruh tipe operasi |
| **Pemetaan auth terpandu introspection** | Menggunakan schema introspection untuk menemukan semua mutation terkait autentikasi dan menguji setiap mutation secara sistematis untuk persyaratan auth yang hilang | Schema sepenuhnya terlihat; pemeriksaan auth tidak diterapkan secara seragam |

### §4-2. Cross-Site Request Forgery (CSRF)

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Downgrade content-type** | Mengubah Content-Type request dari `application/json` menjadi `application/x-www-form-urlencoded` atau `multipart/form-data`, yang dikirim browser sebagai request "simple" tanpa CORS preflight | Server menerima berbagai content-type; tidak ada validasi CSRF token |
| **Eksekusi mutation berbasis GET** | Mengeksekusi mutation via request GET dengan parameter query, melewati perlindungan CSRF yang hanya berlaku untuk request POST | Server menerima mutation via GET; tidak ada pembatasan method |
| **CSRF multipart upload** | Mengeksploitasi content-type `multipart/form-data` yang digunakan oleh mutation file upload, yang dikecualikan dari pemeriksaan CORS preflight | Mutation file upload diaktifkan; tidak ada perlindungan CSRF tambahan (CVE-2024-4994 di GitLab) |

### §4-3. Manipulasi Sesi & Token

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Token replay via batching** | Menggunakan kembali token yang sudah kedaluwarsa atau dicabut di seluruh request yang di-batch di mana validasi token hanya terjadi sekali untuk seluruh batch | Pemrosesan batch memvalidasi auth sekali di level batch |
| **Persistensi sesi subscription** | Mempertahankan koneksi WebSocket setelah token kedaluwarsa, terus menerima data real-time pada sesi yang sudah lama | Tidak ada re-autentikasi periodik pada koneksi WebSocket yang berumur panjang |
| **Manipulasi JWT claim** | Memodifikasi JWT claim (mis. role, permissions) dalam token yang digunakan untuk autentikasi GraphQL ketika verifikasi signature lemah atau tidak ada | Konfigurasi JWT yang lemah; algoritma `none` diterima |

---

## §5. Bypass Otorisasi & Kontrol Akses

Kegagalan otorisasi dalam GraphQL adalah salah satu kelas kerentanan yang paling sering dilaporkan dalam program bug bounty, karena model query fleksibel GraphQL memudahkan developer untuk melewatkan pemeriksaan kontrol akses pada field atau relasi individual.

### §5-1. Bypass Otorisasi Level Objek (IDOR)

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Enumerasi ID langsung** | Melakukan query objek menggunakan ID yang berurutan atau dapat diprediksi (mis. `user(id: 1)`, `user(id: 2)`, ...) tanpa verifikasi kepemilikan | Resolver tidak memverifikasi akses pengguna yang melakukan request ke objek tertentu |
| **Manipulasi Relay/Global ID** | Mendekode dan memodifikasi Relay global ID yang dikodekan Base64 (mis. `VXNlcjox` → `User:1` → modifikasi menjadi `User:2`) untuk mengakses objek yang tidak diizinkan | Relay-style ID tanpa otorisasi sisi server pada referensi yang didekode |
| **Relationship traversal** | Mengakses objek yang tidak diizinkan dengan melintasi relasi dari titik awal yang diizinkan (mis. `myPost { comments { author { privateEmail } } }`) | Otorisasi diterapkan pada root query tetapi tidak pada resolver bersarang |

### §5-2. Bypass Otorisasi Level Field

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Penambahan field sensitif** | Menambahkan field sensitif (mis. `passwordHash`, `ssn`, `internalNotes`) ke query yang diizinkan, mengeksploitasi kontrol akses per field yang hilang | Schema mengekspos field sensitif; otorisasi hanya di level query, bukan di level field |
| **Ekstraksi field berbasis fragment** | Menggunakan inline fragment pada tipe interface/union untuk mengakses field pada tipe konkret yang memiliki otorisasi lebih lemah daripada tipe abstrak | Otorisasi diterapkan pada interface tetapi tidak pada tipe implementasinya |
| **Duplikasi field berbasis alias** | Meminta field sensitif yang sama di bawah beberapa alias untuk menguji apakah otorisasi diterapkan secara konsisten atau hanya pada kemunculan pertama | Otorisasi yang tidak konsisten di seluruh referensi field yang di-alias |

### §5-3. Bypass Otorisasi Mutation

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Privilege escalation via mutation** | Memanggil mutation administratif (mis. `setUserRole(role: ADMIN)`) yang tidak memiliki role-based access control | Mutation terekspos dalam schema tanpa verifikasi role yang tepat (CVE-2025-14592 di GitLab) |
| **Mass assignment via input type** | Menyertakan field yang tidak diizinkan dalam objek input mutation (mis. menambahkan `isAdmin: true` ke mutation `updateProfile`) yang diterapkan resolver tanpa pemfilteran | Resolver memetakan semua input field secara otomatis ke kolom database tanpa allowlisting |
| **Horizontal privilege escalation** | Memodifikasi data pengguna lain melalui mutation yang menerima user ID tanpa memverifikasi hubungan pemanggil dengan pengguna tersebut | Mutation menerima target user ID tanpa validasi kepemilikan |

### §5-4. Bypass Otorisasi Subscription

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Subscription event tanpa otorisasi** | Subscribe ke event (mis. `newOrder`, `adminNotification`) tanpa pemeriksaan otorisasi yang tepat pada subscription resolver | Subscription resolver tidak memiliki middleware otorisasi |
| **Kebocoran data lintas-tenant** | Menerima subscription event dari tenant lain dalam arsitektur multi-tenant karena isolasi tenant yang hilang dalam filter subscription | Filter subscription tidak menyertakan konteks tenant |

---

## §6. Bypass Rate Limiting & Pencegahan Penyalahgunaan

Model single-endpoint GraphQL dan dukungan untuk batching/aliasing menciptakan tantangan fundamental bagi pendekatan rate limiting tradisional yang dirancang untuk REST API.

### §6-1. Bypass Berbasis Batching

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Array batch brute force** | Mengemas ratusan percobaan login/OTP/reset password ke dalam satu HTTP request yang di-batch, membuat semuanya tampak sebagai satu request bagi rate limiter level jaringan | Rate limiting di level jaringan/proxy (Nginx, CDN); batching diaktifkan |
| **Brute force berbasis alias** | Menggunakan alias untuk mengeksekusi beberapa query autentikasi dalam satu operasi GraphQL (mis. `a1: login(pass: "aaa"), a2: login(pass: "aab"), ...`) | Rate limiting per HTTP request; tidak ada penghitungan per operasi atau per alias |
| **Sequential batch chaining** | Mengirimkan request yang di-batch secara berturutan dengan cepat, masing-masing berisi jumlah operasi maksimum, untuk melipatgandakan throughput melampaui batas per request | Ukuran batch tidak terbatas atau sangat tinggi; tidak ada penghitungan operasi per detik |

### §6-2. Query Shape Evasion

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Obfuscation berbasis variabel** | Menggunakan variabel GraphQL untuk mengubah operasi efektif tanpa mengubah struktur query, menghindari aturan WAF yang mencocokkan teks query statis | Pencocokan pola WAF pada teks query mentah; variabel diproses secara terpisah |
| **Obfuscation struktural berbasis fragment** | Merestrukturisasi query menggunakan fragment dan fragment spread untuk mengubah representasi sintaksis sambil mempertahankan kesetaraan semantik | WAF atau middleware keamanan menggunakan pencocokan pola sintaksis |
| **Manipulasi hash persisted query** | Mencoba mendaftarkan query berbahaya sebagai persisted query (APQ) dengan mengeksploitasi hash collision atau race condition pendaftaran | APQ diaktifkan tanpa allowlisting; registrasi otomatis diizinkan |

---

## §7. Directive Abuse & Eksploitasi Custom Extension

Directive GraphQL (`@skip`, `@include`, dan custom directive) menyediakan kemampuan modifikasi query yang kuat yang dapat dipersenjatai untuk serangan DoS maupun logic bypass.

### §7-1. Penyalahgunaan Built-in Directive

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Manipulasi logika kondisional** | Menggunakan `@skip(if: ...)` dan `@include(if: ...)` dengan nilai variabel dinamis untuk menyelidiki field mana yang ada dan jalur otorisasi mana yang dievaluasi | Server mengevaluasi otorisasi sebelum pemfilteran directive |
| **Duplicate directive stacking** | Menerapkan built-in directive yang sama berkali-kali pada satu field untuk menguji anomali pemrosesan atau crash | Tidak ada deduplikasi directive dalam execution engine |

### §7-2. Eksploitasi Custom Directive

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Bypass auth directive via fragment** | Menghindari directive `@auth` atau `@hasRole` dengan mengakses field yang dilindungi melalui fragment yang sangat bersarang atau jalur relasi alternatif di mana directive tidak diwarisi | Directive otorisasi tidak dipropagasi ke semua jalur akses field |
| **Injeksi internal directive** | Memanggil internal-only directive (mis. `@internalDebug`, `@bypassCache`, `@trace`) dari query klien ketika server tidak membatasi penggunaan directive sisi klien | Directive internal tidak dibatasi untuk penggunaan sisi server |
| **Injeksi argumen directive** | Menyuntikkan nilai berbahaya ke dalam argumen directive (mis. `@cache(key: "../../admin")`) yang diproses tanpa sanitasi | Argumen custom directive tidak divalidasi |
| **Penghindaran directive berbasis fragment** | Mengakses field yang dilindungi oleh directive melalui inline fragment pada tipe berbeda dalam union/interface, di mana directive tidak diterapkan pada jalur alternatif | Directive diterapkan per field pada satu tipe tetapi tidak pada jalur interface alternatif |

---

## §8. Serangan Transport & Protocol Layer

GraphQL beroperasi melalui protokol HTTP dan WebSocket, dan kerentanan di transport layer dapat melemahkan kontrol keamanan level aplikasi.

### §8-1. Manipulasi HTTP Method & Content-Type

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **GET-based mutation smuggling** | Mengeksekusi mutation via HTTP GET request, melewati kontrol keamanan yang hanya berlaku untuk POST request | Server tidak membatasi mutation hanya untuk method POST |
| **Content-type confusion** | Mengirimkan query GraphQL dengan content-type yang tidak terduga (mis. `text/plain`, `application/x-www-form-urlencoded`) untuk melewati WAF atau pembatasan CORS | Server menerima query dalam content-type non-JSON |
| **Manipulasi multipart boundary** | Membuat request multipart dengan string boundary yang tidak biasa atau bagian bersarang untuk membingungkan middleware parsing sambil mengirimkan payload GraphQL yang valid | Server menggunakan lenient multipart parsing |

### §8-2. Serangan WebSocket / Subscription

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Cross-Site WebSocket Hijacking (CSWSH)** | Membuka koneksi WebSocket dari situs web berbahaya, memanfaatkan lampiran cookie otomatis browser untuk handshake WebSocket (tidak ada penegakan Same-Origin Policy) | Autentikasi berbasis cookie untuk WebSocket; tidak ada validasi header Origin |
| **Subscription flooding** | Membuka banyak subscription bersamaan ke event yang resource-intensive, menyebabkan server mempertahankan state berlebihan dan mendorong komputasi | Tidak ada batas subscription per klien; tidak ada cost analysis subscription |
| **WebSocket message injection** | Menyuntikkan operasi GraphQL berbahaya melalui protokol pesan WebSocket setelah koneksi terbentuk, melewati pemeriksaan auth awal | Autentikasi hanya pada inisialisasi koneksi; tidak ada validasi per pesan |
| **Persistensi koneksi setelah pencabutan auth** | Mempertahankan koneksi WebSocket setelah token kedaluwarsa atau sesi dicabut untuk terus menerima data subscription | Tidak ada re-autentikasi berbasis heartbeat pada koneksi berumur panjang |

### §8-3. Endpoint Discovery & Routing

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Brute force path umum** | Memindai path endpoint GraphQL yang umum (`/graphql`, `/gql`, `/api/graphql`, `/v1/graphql`, `/query`, `/graphiql`, `/playground`, `/altair`, `/explorer`) | Endpoint GraphQL di path yang dapat diprediksi tanpa autentikasi |
| **Enumerasi subdomain** | Menemukan GraphQL API pada subdomain (mis. `api.example.com`, `graph.example.com`, `internal-api.example.com`) | Endpoint GraphQL internal atau staging terekspos pada subdomain |
| **Eksposur IDE/playground** | Mengakses antarmuka IDE GraphQL (GraphiQL, Apollo Sandbox, Playground) yang dibiarkan aktif di produksi, menyediakan eksplorasi schema interaktif dan eksekusi query | Alat pengembangan tidak dinonaktifkan dalam deployment produksi |

---

## §9. Caching & Manipulasi Respons

Model query dinamis GraphQL menciptakan tantangan unik untuk caching, dan konfigurasi yang salah pada caching layer dapat dieksploitasi untuk kebocoran data atau poisoning.

### §9-1. Server-Side Cache Poisoning

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Manipulasi header batch response** | Dalam request yang di-batch, memanipulasi header cache-control melalui satu operasi untuk memengaruhi perilaku caching operasi lain dalam batch yang sama, menyebabkan respons sensitif di-cache secara publik | Pemrosesan batch menggabungkan response header di seluruh operasi (kerentanan cache poisoning Apollo Server) |
| **Cache poisoning persisted query** | Mendaftarkan query berbahaya di bawah hash yang bertabrakan atau menggantikan persisted query yang sah, menyebabkan klien selanjutnya yang meminta hash tersebut mengeksekusi query penyerang | APQ dengan registrasi terbuka; tidak ada verifikasi hash |
| **CDN cache key confusion** | Mengeksploitasi perbedaan antara cara CDN menghasilkan cache key dan cara server GraphQL menginterpretasi request, menyimpan respons satu pengguna untuk cache key pengguna lain | CDN caching diaktifkan untuk GraphQL; cache key tidak menyertakan konteks auth |

### §9-2. Client-Side Cache Manipulation

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Cache poisoning berbasis alias** | Menggunakan field `__typename` atau `id` yang di-alias untuk menyebabkan normalized cache Apollo Client menyimpan data yang dikendalikan penyerang di bawah cache key objek yang sah | Normalized cache Apollo Client; penyerang dapat mengeksekusi query dengan alias |
| **Cache pollution via type confusion** | Menyuntikkan objek dengan metadata tipe yang dimanipulasi ke dalam cache klien melalui query pada tipe union/interface, menyebabkan cache mengembalikan data yang salah untuk query selanjutnya | Normalized caching sisi klien dengan tipe polimorfis |

---

## §10. Serangan Spesifik Arsitektur & Federation

Federation dan pola gateway GraphQL memperkenalkan attack surface tambahan pada layer komposisi dan routing.

### §10-1. Eksploitasi Gateway / Router

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Akses langsung subgraph** | Melewati federation gateway dengan langsung melakukan query pada layanan subgraph individual yang mungkin memiliki autentikasi atau otorisasi lebih lemah daripada gateway | Layanan subgraph dapat diakses jaringan; tidak dibatasi hanya untuk traffic gateway |
| **Kesenjangan otorisasi lintas-subgraph** | Mengeksploitasi inkonsistensi otorisasi antar subgraph, di mana field dilindungi dalam satu subgraph tetapi data yang sama dapat diakses melalui relasi subgraph lain | Otorisasi diterapkan per subgraph, bukan di level federated schema |
| **Manipulasi komposisi schema** | Mengeksploitasi proses komposisi schema untuk menyuntikkan atau menimpa tipe dan field dari satu subgraph yang memengaruhi perilaku subgraph lain | Subgraph yang berbahaya atau terkompromikan dalam federation |

### §10-2. Kerentanan Schema Stitching

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Injeksi resolver yang di-stitch** | Menyuntikkan query berbahaya melalui schema yang di-stitch di mana output satu layanan digunakan sebagai input resolver layanan lain tanpa sanitasi yang tepat | Schema stitching tanpa validasi input antar layanan |
| **Eksploitasi type conflict** | Mengeksploitasi konflik penamaan antar schema yang di-stitch yang menyebabkan anomali penggabungan tipe, berpotensi mengekspos field dari layanan internal | Beberapa schema dengan nama tipe yang tumpang tindih tanpa resolusi konflik yang tepat |

### §10-3. Bypass Persisted Operations

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **APQ registration abuse** | Mendaftarkan query sembarang melalui mekanisme registrasi APQ, secara efektif melewati allowlist persisted query | APQ (Automatic Persisted Queries) digunakan alih-alih persisted operations yang ketat |
| **Eksploitasi hash collision** | Membuat query dengan hash SHA-256 yang bertabrakan dengan persisted query yang terdaftar (teoritis, kesulitan tinggi) | Sistem persisted query menggunakan hash yang pendek atau terpotong |
| **Fallback ke arbitrary query** | Mengeksploitasi mekanisme fallback di mana server menerima arbitrary query ketika hash persisted query tidak ditemukan, alih-alih menolak request | Perilaku fallback permisif; tidak ada mode penegakan yang ketat |

---

## §11. Pemetaan Attack Scenario (Sumbu 3)

| Skenario | Arsitektur / Kondisi | Kategori Mutasi Utama |
|----------|----------------------|----------------------|
| **Reconnaissance & Schema Discovery** | Endpoint GraphQL apa pun; konfigurasi default | §1-1, §1-2, §1-3, §1-4 |
| **Denial of Service** | Produksi traffic tinggi; relasi schema sirkular | §2-1, §2-2, §2-3, §2-4, §2-5, §8-2 |
| **Brute Force / Credential Stuffing** | Mutation auth terekspos; batching diaktifkan | §2-5, §6-1, §6-2 |
| **Data Exfiltration** | Field sensitif dalam schema; auth level field yang lemah | §5-1, §5-2, §5-4, §3-1, §3-2 |
| **Privilege Escalation** | Mutation admin dapat diakses; mass assignment memungkinkan | §5-3, §4-1, §5-1 |
| **Remote Code Execution** | Resolver tidak aman; command/template injection | §3-4, §3-1 |
| **Server-Side Request Forgery** | Input berbasis URL; mutation file upload | §3-3 |
| **Account Takeover** | Auth bypass + akses mutation | §4-1, §4-2, §5-3, §6-1 |
| **Cache Poisoning** | CDN/proxy caching; respons yang di-batch | §9-1, §9-2 |
| **Cross-Site Attacks** | Klien GraphQL berbasis browser; WebSocket subscription | §4-2, §8-2, §3-5 |
| **Supply Chain / Federation Compromise** | Arsitektur federated; schema stitching | §10-1, §10-2, §10-3 |

---

## §12. Pemetaan CVE / Bounty (2022–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|-----------------|------------|----------------|
| §2-4 (directive overloading) | CVE-2022-37734 (graphql-java) | DoS via pengulangan directive yang tidak dibatasi; menyebabkan konsumsi CPU berlebihan |
| §2-1 + §2-5 (depth + batching) | CVE-2024-40094 (graphql-java) | DoS via ExecutableNormalizedFields; introspection query menyebabkan resource exhaustion di IBM WebSphere Liberty dan Maximo |
| §1-1 (kontrol akses introspection) | CVE-2024-50312 (OpenShift) | Information disclosure; pengguna yang tidak berwenang mengambil daftar query/mutation lengkap |
| §2-2 (alias abuse) | CVE-2024-50311 (OpenShift) | DoS via alias batching di endpoint GraphQL |
| §4-2 (CSRF via multipart upload) | CVE-2024-4994 (GitLab) | CSRF tingkat keparahan tinggi yang memungkinkan eksekusi mutation GraphQL sembarang via multipart/form-data (dikecualikan dari CORS preflight) |
| §5-3 (bypass authz mutation) | CVE-2025-14592 (GitLab GLQL) | Eksekusi mutation tanpa otorisasi yang kritis di seluruh versi CE/EE |
| §8-2 (WebSocket MITM) | CVE-2024-54147 (Altair GraphQL Client) | Validasi sertifikat HTTPS yang hilang pada koneksi WebSocket; intersepsi MITM atas semua query |
| §3-3 (SSRF via upload) | GHSA-x27p-wfqw-hfcc (Craft CMS) | SSRF via mutation upload asset GraphQL; akses metadata cloud |
| §9-1 (batch cache poisoning) | SNYK-JS-APOLLOSERVERCORE-3098876 (Apollo Server) | Cache poisoning via penggabungan header POST request yang di-batch |
| §9-2 (client cache poisoning) | Apollo Client #10784 | Client-side cache poisoning via field `__typename` dan `id` yang di-alias |
| §5-2 + §1-1 (eksposur field) | Beberapa laporan HackerOne | Bounty $1.000–$10.000+ untuk ekstraksi field sensitif via query terpandu introspection |
| §6-1 (batch brute force) | Beberapa program bug bounty | Bypass 2FA/OTP via mutation autentikasi yang di-batch |

---

## §13. Alat Deteksi & Keamanan

| Alat | Cakupan Target | Teknik Inti |
|------|---------------|-------------|
| **InQL** (ekstensi Burp Suite) | Analisis schema, pemindaian kerentanan | Introspection query, rekonstruksi schema via pola Clairvoyance, pembuatan serangan point-and-click |
| **graphw00f** (fingerprinting) | Identifikasi server engine | Analisis diferensial behavioral di 30+ implementasi GraphQL |
| **Clairvoyance** (schema recovery) | Rekonstruksi schema tanpa introspection | Probing suggestion field berbasis dictionary; merekonstruksi tipe, field, dan argumen dari pesan error |
| **CrackQL** (brute force) | Pengujian autentikasi/rate limit | Otomasi serangan batching GraphQL-aware; brute forcing OTP dan password |
| **GraphQLer** (fuzzer) | Pengujian keamanan API komprehensif | Fuzzing API GraphQL context-aware dengan dependency resolution |
| **Goctopus** (discovery) | Endpoint discovery dan fingerprinting | Enumerasi subdomain, brute-force route, introspection, deteksi auth |
| **BatchQL** (pengujian DoS) | Penilaian kerentanan batch | Konstruksi batch query otomatis untuk pengujian rate limit dan DoS |
| **graphql-cop** (auditing) | Deteksi misconfiguration keamanan | Pemeriksaan otomatis untuk misconfiguration umum (introspection, batching, field suggestion) |
| **DVGA** (pelatihan) | Aplikasi GraphQL yang rentan | Aplikasi GraphQL yang sengaja rentan untuk berlatih teknik eksploitasi |
| **Escape.tech** (SaaS scanner) | Pemantauan keamanan API produksi | Pemindaian keamanan GraphQL berkelanjutan dengan deteksi kerentanan otomatis |
| **StackHawk** (DAST) | Dynamic application security testing | Pemindaian DAST GraphQL-aware termasuk deteksi field suggestion |

---

## §14. Ringkasan: Prinsip Inti

### Akar Penyebab: Client-Controlled Query Semantics

Properti fundamental yang memungkinkan seluruh attack surface GraphQL adalah **client-controlled query semantics atas schema yang self-documenting**. Tidak seperti REST, di mana server mendefinisikan bentuk respons yang tetap dan attack surface terdistribusi di seluruh endpoint, GraphQL memusatkan semua fungsionalitas di belakang satu endpoint dan memberikan klien kontrol luar biasa atas data apa yang diminta, seberapa dalam relasi ditelusuri, dan berapa banyak operasi yang dieksekusi per request. Schema, yang dapat di-query secara default, berfungsi sebagai blueprint serangan yang lengkap.

### Mengapa Perbaikan Inkremental Gagal

Setiap kelas kerentanan dalam taksonomi ini berasal dari aspek desain GraphQL yang berbeda, yang berarti memperbaiki satu kelas tidak menangani yang lain. Menonaktifkan introspection meninggalkan field suggestion tetap aktif (§1-2). Menambahkan batas depth tidak mencegah amplifikasi berbasis alias (§2-2). Rate limiting per HTTP request tidak berarti ketika batching mengalikan operasi (§6-1). Otorisasi di level query gagal ketika resolver bersarang tidak memiliki pemeriksaan sendiri (§5-1). Ortogonalitas vektor serangan ini berarti pertahanan komprehensif mengharuskan penanganan **setiap sumbu secara independen** — tidak ada satu konfigurasi toggle atau middleware tunggal yang mengamankan GraphQL API.

### Solusi Struktural

Pendekatan defense-in-depth harus melapisi beberapa kontrol:

1. **Schema minimization**: Ekspos hanya field, mutation, dan tipe yang benar-benar dibutuhkan klien. Hapus operasi internal, debug, dan administratif dari schema publik.
2. **Persisted operations (strict allowlist)**: Ganti arbitrary client query dengan hash operasi yang terdaftar di server, menghilangkan seluruh kelas serangan (§2, §6, §7) dengan menghapus kontrol klien atas struktur query.
3. **Per-resolver authorization**: Terapkan kontrol akses di setiap resolver, bukan hanya di titik masuk query, untuk mencegah relationship traversal dan bypass level field (§5).
4. **Query cost analysis**: Tetapkan biaya komputasi pada field dan tolak query yang melebihi threshold, menangani DoS berbasis depth, width, dan directive (§2, §7).
5. **Validasi input di resolver boundary**: Perlakukan setiap argumen GraphQL sebagai input pengguna yang tidak tepercaya dan terapkan parameterized query, URL allowlist, dan sanitasi input (§3).
6. **Transport hardening**: Batasi mutation hanya untuk POST, terapkan validasi content-type yang ketat, validasi header WebSocket Origin, dan implementasikan rate limiting per operasi (§4, §8).
7. **Keamanan federation-aware**: Terapkan autentikasi dan otorisasi di level gateway DAN level subgraph, membatasi akses langsung ke subgraph (§10).

---

## Referensi

- [GraphQL API Vulnerabilities — PortSwigger Web Security Academy](https://portswigger.net/web-security/graphql)
- [GraphQL Cheat Sheet — OWASP](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL Security — Dokumentasi Resmi GraphQL](https://graphql.org/learn/security/)
- [GraphQL Vulnerabilities and Common Attacks — Imperva](https://www.imperva.com/blog/graphql-vulnerabilities-common-attacks/)
- [GraphQL — HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)
- [PayloadsAllTheThings — GraphQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)
- [Awesome GraphQL Security — Escape Technologies](https://github.com/Escape-Technologies/awesome-graphql-security)
- [GraphQL Vulnerabilities — Application Security Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/web-application/graphql-vulnerabilities)
- [8 Common GraphQL Vulnerabilities — Escape.tech](https://escape.tech/blog/8-most-common-graphql-vulnerabilities/)
- [GraphQL Security — Tyk](https://tyk.io/blog/graphql-security-7-common-vulnerabilities-and-how-to-mitigate-the-risks/)
- [Directive Deception: Exploiting Custom GraphQL Directives — InstaTunnel](https://instatunnel.my/blog/directive-deception-exploiting-custom-graphql-directives-for-logic-bypass)
- [GraphQL Batching Attack — Wallarm](https://lab.wallarm.com/graphql-batching-attack/)
- [Securing Your GraphQL API from Malicious Queries — Apollo](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries)
- [Cross-Site Request Forgery Prevention — Apollo](https://www.apollographql.com/docs/graphos/routing/security/csrf)
- [That Single GraphQL Issue That You Keep Missing — Doyensec](https://blog.doyensec.com/2021/05/20/graphql-csrf.html)
- [GraphQL Error Handling: A Security POV — Escape.tech](https://escape.tech/blog/graphql-error-handling-a-security-pov/)
- [GraphQL Security from a Pentester's Perspective — AFINE](https://afine.com/graphql-security-from-a-pentesters-perspective/)
- [Enhancing GraphQL Security by Detecting Malicious Queries Using LLMs — arXiv](https://arxiv.org/html/2508.11711v2)
- [GraphQLer: Enhancing GraphQL Security with Context-Aware API Testing — arXiv](https://arxiv.org/html/2504.13358v1)
- [OWASP Web Security Testing Guide v4.2 — API Testing: GraphQL](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL)

---

*Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan.*