---
title: IDOR
---

## Struktur Klasifikasi

Taksonomi ini mengorganisir seluruh attack surface dari kerentanan IDOR/BOLA melalui tiga sumbu yang saling ortogonal. **Sumbu 1 (Target Mutasi Identifier)** adalah sumbu struktural utama — mengklasifikasikan teknik berdasarkan *komponen mana dari object reference atau alur otorisasi yang dimanipulasi*. **Sumbu 2 (Jenis Celah Otorisasi)** adalah sumbu lintas-sektor — menjelaskan *jenis kekurangan otorisasi apa* yang membuat setiap mutasi dapat dieksploitasi. **Sumbu 3 (Skenario Dampak)** memetakan teknik ke *hasil eksploitasi di dunia nyata*.

IDOR/BOLA pada dasarnya adalah **pemeriksaan otorisasi yang tidak ada atau cacat terhadap identifier objek yang disuplai pengguna**. Tidak seperti kerentanan injeksi atau parsing-differential, akar penyebabnya bukan cacat parsing teknis, melainkan sebuah *ketiadaan logis* — aplikasi mengautentikasi pengguna tetapi tidak pernah memverifikasi apakah identitas yang telah diautentikasi tersebut berwenang mengakses objek yang direferensikan. Hal ini membuat IDOR/BOLA sangat persisten: tidak dapat dieliminasi oleh satu library, fitur framework, atau perubahan protokol, melainkan membutuhkan penegakan otorisasi per-endpoint.

### Ringkasan Sumbu 2: Jenis Celah Otorisasi

| Jenis Celah | Deskripsi |
|-------------|-----------|
| **Absent Check** | Tidak ada logika otorisasi untuk endpoint tersebut; pengguna mana pun yang sudah (atau belum) terautentikasi dapat mengakses objek apa pun |
| **Inconsistent Check** | Otorisasi diterapkan pada beberapa endpoint/method tetapi tidak pada yang lain yang menyentuh resource yang sama |
| **Bypassable Check** | Logika otorisasi ada tetapi dapat dilewati melalui encoding, manipulasi format, atau trik parameter |
| **Logic Flaw** | Pemeriksaan otorisasi ada tetapi menggunakan validasi kepemilikan yang salah (misalnya, memeriksa org tetapi bukan user di dalam org) |
| **Temporal Gap** | Otorisasi lolos saat waktu pemeriksaan, tetapi state berubah sebelum waktu penggunaan (TOCTOU) |
| **Trust Boundary Violation** | Layanan internal atau komponen downstream melewati otorisasi, mempercayai upstream untuk telah melakukannya |

---

## §1. Tipe Identifier dan Prediktabilitas

Sifat identifier objek menentukan attack surface untuk enumerasi dan penebakan. Meskipun identifier yang tidak dapat diprediksi meningkatkan standar keamanan, hal tersebut tidak menggantikan pemeriksaan otorisasi — hanya menggeser serangan dari blind enumeration menjadi eksploitasi kebocoran identifier.

### §1-1. Identifier Numerik Sekuensial

Vektor IDOR paling klasik dan paling banyak dieksploitasi. Aplikasi yang menggunakan primary key database auto-increment sebagai identifier eksternal mengekspos seluruh ruang enumerasi ke aritmetika trivial.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Integer increment/decrement** | Mengubah `user_id=1001` menjadi `user_id=1002` untuk mengakses record yang berdekatan | PK auto-increment terekspos tanpa pemeriksaan otorisasi |
| **Range enumeration** | Iterasi melalui `id=1` hingga `id=N` untuk membuang semua record | Tidak ada rate limiting dikombinasikan dengan otorisasi yang tidak ada |
| **Negative / zero ID** | Memasukkan `id=0` atau `id=-1` untuk mengakses record default, admin, atau sentinel | Aplikasi menggunakan ID khusus untuk objek sistem tanpa membatasi akses |
| **Large integer overflow** | Memasukkan nilai yang melebihi rentang yang diharapkan (misalnya `id=999999999`) untuk memukul record edge-case | Perbedaan penanganan integer antara lapisan validasi dan lapisan database |
| **ID arithmetic pada composite key** | Memanipulasi satu komponen dari identifier komposit (misalnya `org_id=5&user_id=3` → `org_id=5&user_id=4`) | Pemeriksaan otorisasi hanya memeriksa satu komponen dari composite key |

### §1-2. Identifier UUID / GUID

UUID (v4) adalah nilai 128-bit dengan 122 bit keacakan (6 bit dicadangkan untuk versi/varian), menghasilkan ~2^122 kemungkinan nilai, sehingga blind enumeration tidak layak dilakukan. Namun, *persepsi* keamanan yang mereka berikan sering membuat developer melewati pemeriksaan otorisasi sepenuhnya, menciptakan rasa aman yang palsu yang runtuh ketika identifier bocor.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **UUID leakage via endpoint lain** | Memanen UUID dari listing pengguna, hasil pencarian, activity feed, atau shared link, lalu menggunakannya di endpoint yang tidak terlindungi | UUID diperlakukan sebagai rahasia, bukan identifier; tidak ada authz check di endpoint konsumer |
| **UUID leakage via pesan error** | Aplikasi mengembalikan UUID dalam respons error (misalnya "User `abc-def-123` not found") | Pesan error verbose mengekspos identifier internal |
| **UUID leakage via kode client-side** | Source JavaScript, komentar HTML, atau respons API menyematkan UUID objek pengguna lain | Frontend membocorkan identifier yang dipercaya backend sebagai "tidak dapat ditebak" |
| **Prediksi timestamp UUIDv1** | UUIDv1 mengenkode timestamp dan alamat MAC; jika waktu pembuatan diketahui, ruang UUID dapat dipersempit secara dramatis | Aplikasi menggunakan UUIDv1 bukan UUIDv4; penyerang mengetahui waktu pembuatan perkiraan |
| **Generasi UUID dengan PRNG lemah** | UUID yang dibuat dengan sumber acak lemah (misalnya `Math.random()` di JavaScript) dapat diprediksi | Generasi UUID kustom dengan entropi yang tidak memadai |
| **UUID format downgrade** | Menukar UUID dengan integer sederhana (misalnya `id=1` alih-alih `id=550e8400-...`) dan backend menerima kedua format | Backend ORM/DB menerima beberapa format ID tanpa membedakan |

### §1-3. Identifier Terenkode dan Ter-hash

Aplikasi terkadang mengenkode atau meng-hash identifier untuk menyamarkannya, memperlakukan ketidakjelasan sebagai mekanisme otorisasi. Ini adalah langkah-langkah security-through-obscurity yang runtuh di bawah analisis.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Decoding ID ter-Base64** | Mendekode `aWQ9MTIz` mengungkapkan `id=123`; penyerang mengenkode ID yang berbeda dan mengirimkannya | Base64 digunakan sebagai satu-satunya "perlindungan"; tidak ada otorisasi server-side |
| **Enkripsi reversibel** | Identifier dienkripsi dengan kunci statis atau bocor; penyerang mendekripsi, memodifikasi, dan mengenkripsi ulang | Enkripsi simetris dengan kunci terekspos di kode client-side atau kebocoran konfigurasi |
| **Hash collision / rainbow table** | Input pendek atau berentripi rendah di-hash (misalnya MD5 dari integer sekuensial); penyerang pra-komputasi tabel hash | Hash dari input yang dapat diprediksi (misalnya `MD5(user_id)`) tanpa salt atau secret key |
| **HMAC tanpa otorisasi** | Object reference dilindungi oleh HMAC tetapi aplikasi hanya memeriksa validitas HMAC, bukan kepemilikan | Token HMAC yang valid untuk objek X tidak menjamin bahwa pengguna A seharusnya mengakses objek X |
| **Object ID tertanam dalam JWT** | Identifier objek tertanam dalam klaim JWT; memodifikasi klaim (dengan algoritma lemah/none atau key confusion) mengubah objek yang direferensikan | Cacat validasi JWT dikombinasikan dengan object ID dalam payload (lihat §4-4) |

### §1-4. Identifier Berbasis String dan Semantik

Ketika identifier adalah string yang dapat dibaca manusia (username, alamat email, nama file, slug), attack surface beralih dari enumerasi ke social engineering dan pengumpulan informasi publik.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Substitusi username/email** | Mengganti `user=alice@corp.com` dengan `user=admin@corp.com` dalam permintaan API | Email/username digunakan sebagai kunci objek tanpa memverifikasi identitas pemanggil cocok |
| **Manipulasi filename** | Mengubah `file=report_alice.pdf` menjadi `file=report_bob.pdf` untuk mengakses dokumen pengguna lain | Filename sebagai referensi langsung ke file system atau objek penyimpanan |
| **Slug/path guessing** | Mengakses `/api/projects/secret-project-name` dengan menebak atau menemukan slug proyek | Slug digunakan sebagai kontrol akses tunggal; tidak ada verifikasi keanggotaan |
| **Wildcard dan glob injection** | Mengirimkan `id=*` atau `username=*` untuk memicu pattern matching yang mengembalikan semua record | Backend menginterpretasikan karakter wildcard di field identifier |

---

## §2. Lokasi Parameter dan Vektor Transport

Cacat otorisasi yang sama dapat bermanifestasi secara berbeda tergantung di mana identifier objek muncul dalam permintaan HTTP. Penyerang secara sistematis menguji semua lokasi parameter karena otorisasi mungkin diterapkan untuk satu vektor transport tetapi tidak yang lain.

### §2-1. Parameter Path URL

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Manipulasi segmen path REST** | Mengubah `/api/users/123/orders` menjadi `/api/users/456/orders` | Routing RESTful mengekstrak ID dari path; tidak ada authz di level middleware |
| **Nested resource traversal** | Mengakses `/api/orgs/1/users/2/documents/3` dengan mengganti segmen mana saja | Pemeriksaan otorisasi pada resource parent tetapi tidak pada child, atau sebaliknya |
| **Path version bypass** | Beralih dari `/api/v2/users/123` (terlindungi) ke `/api/v1/users/123` (tidak terlindungi — versi lama) | Versi API lama tidak memiliki otorisasi yang diterapkan pada versi yang lebih baru |

### §2-2. Parameter Query String

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Penukaran parameter query sederhana** | Mengubah `?account_id=100` menjadi `?account_id=101` | Vektor IDOR paling umum dan paling sederhana |
| **HTTP Parameter Pollution (HPP)** | Mengirimkan parameter duplikat: `?user_id=attacker&user_id=victim`; backend menggunakan nilai terakhir sementara otorisasi memeriksa yang pertama | Prioritas parsing parameter server-side berbeda dari middleware otorisasi |
| **Penambahan parameter** | Menambahkan parameter tak terduga seperti `&admin=true` atau `&user_id=victim` ke permintaan yang biasanya mengambil ID dari sesi | Aplikasi memprioritaskan parameter eksplisit atas nilai yang diambil dari sesi |

### §2-3. Request Body (JSON/XML/Form)

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Substitusi field body JSON** | Mengubah `{"user_id": 123}` menjadi `{"user_id": 456}` dalam body POST/PUT/PATCH | Parameter body digunakan untuk pencarian objek tanpa verifikasi kepemilikan |
| **Array wrapping** | Mengubah `{"id": 123}` menjadi `{"id": [123, 456]}` untuk mengakses beberapa objek atau melewati pemeriksaan otorisasi berbasis tipe | Backend menerima array di mana skalar diharapkan; iterasi tanpa authz per elemen |
| **Nested object injection** | Mengubah `{"id": 123}` menjadi `{"user": {"id": 456}}` untuk melewati pemeriksaan otorisasi flat-parameter | Logika otorisasi memeriksa `body.id` tetapi ORM mengikat dari `body.user.id` |
| **XML entity / attribute injection** | Dalam API berbasis XML, memodifikasi `<userId>123</userId>` atau menyuntikkan referensi entitas untuk mengubah nilai ID yang ter-resolve | API berbasis XML dengan entity expansion diaktifkan |
| **Mass assignment pada properti objek** | Mengirimkan field tambahan seperti `{"user_id": 456, "role": "admin"}` yang langsung diikat API ke data model | Framework API secara otomatis mengikat semua field input ke model (§5-2 BOPLA) |

### §2-4. HTTP Header dan Cookie

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Custom header injection** | Memodifikasi header `X-User-Id: 123` atau `X-Account-Id: 456` yang dipercaya layanan internal | Header diatur oleh reverse proxy atau API gateway; penyerang dapat menyuntikkan/menimpanya |
| **Manipulasi nilai cookie** | Mengubah cookie seperti `user_session=base64(user_id=123)` untuk mereferensikan pengguna yang berbeda | Object reference tertanam dalam nilai cookie alih-alih sesi server-side |
| **Akses berbasis Referer/Origin** | Aplikasi memberikan akses berdasarkan header `Referer` yang berisi URL objek yang "benar" | Referer digunakan sebagai sinyal otorisasi implisit |

### §2-5. WebSocket dan Saluran Real-Time

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **WebSocket message ID swap** | Setelah membuat koneksi WebSocket, mengirimkan pesan dengan channel/room ID pengguna lain | Otorisasi WebSocket hanya dilakukan saat waktu koneksi, bukan per pesan |
| **Subscription channel hijacking** | Berlangganan saluran real-time (misalnya `channel=user_456_notifications`) yang dimiliki pengguna lain | Nama saluran pub/sub dibuat dari identifier yang dapat diprediksi tanpa otorisasi langganan |

---

## §3. Teknik Bypass Logika Otorisasi

Ketika pemeriksaan otorisasi ada, penyerang menggunakan teknik manipulasi struktural untuk menghindarinya. Bypass ini menargetkan *implementasi* pemeriksaan, bukan *ketiadaan*-nya.

### §3-1. HTTP Method Tampering

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Method switching (GET ↔ POST)** | Otorisasi diterapkan pada `GET /api/users/123` tetapi tidak pada `POST /api/users/123` atau sebaliknya | Konfigurasi otorisasi per-method; beberapa method tidak terlindungi |
| **PUT/PATCH/DELETE bypass** | Operasi baca terlindungi tetapi operasi tulis/hapus pada resource yang sama tidak memiliki otorisasi | Developer mengamankan jalur baca tetapi mengabaikan jalur mutasi |
| **HEAD/OPTIONS information leak** | `HEAD /api/users/123` mengembalikan status code atau header yang mengungkapkan keberadaan objek tanpa memicu otorisasi | Handler method HEAD melewati middleware otorisasi |
| **Method override headers** | Menggunakan `X-HTTP-Method-Override: DELETE` dengan permintaan GET untuk melewati aturan otorisasi berbasis method | Framework mendukung method override; otorisasi diperiksa terhadap method asli |

### §3-2. Evasion Encoding dan Format

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **URL encoding** | Mengenkode identifier (`%31%32%33` untuk `123`) untuk melewati aturan otorisasi berbasis string-matching | Otorisasi melakukan perbandingan string tanpa URL-decoding |
| **Double encoding** | Double-encoding (`%2531%2532%2533`) melewati satu langkah decode di lapisan otorisasi | Otorisasi mendekode sekali; aplikasi mendekode lagi |
| **Unicode normalization** | Menggunakan varian Unicode dari digit atau karakter (misalnya fullwidth `１２３`) yang dinormalisasi ke nilai yang sama | Backend menormalisasi Unicode setelah pemeriksaan otorisasi |
| **Case manipulation** | Mengubah case dari identifier string (misalnya `UserName` vs `username`) ketika otorisasi case-sensitive tetapi lookup case-insensitive | Ketidaksesuaian case sensitivity antara otorisasi dan lapisan data |
| **JSON type juggling** | Mengirimkan `{"id": "123"}` (string) alih-alih `{"id": 123}` (integer) atau `{"id": 123.0}` (float) untuk melewati pemeriksaan tipe-ketat | Otorisasi melakukan perbandingan tipe ketat; backend melakukan type coercion |
| **Null byte injection** | Menambahkan `%00` ke identifier untuk memotongnya di satu lapisan sambil melewatinya di lapisan lain | Penanganan string berbasis C dalam otorisasi vs. penanganan length-aware di aplikasi |

### §3-3. Manipulasi Struktur Permintaan

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Content-Type switching** | Mengubah `Content-Type` dari `application/json` ke `application/x-www-form-urlencoded` atau `multipart/form-data` untuk melewati parsing body di middleware otorisasi | Middleware otorisasi hanya mem-parse satu content type |
| **Parameter migration** | Memindahkan identifier dari query string ke body atau sebaliknya untuk menghindari pemeriksaan spesifik-lokasi | Otorisasi memeriksa query param; aplikasi juga membaca body param |
| **Batch request injection** | Menyematkan object reference yang tidak diotorisasi di dalam panggilan API batch/bulk (misalnya `POST /api/batch` dengan operasi campuran authorized dan unauthorized) | Endpoint batch melakukan otorisasi pada batch secara keseluruhan, bukan per operasi |
| **GraphQL alias abuse** | Menggunakan alias GraphQL untuk meminta field yang sama dengan ID berbeda dalam satu query, melewati rate limiting atau otorisasi per-query | GraphQL resolver memeriksa otorisasi per query tetapi bukan per alias (§4-2) |

### §3-4. Bypass Resolusi Referensi Tidak Langsung

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Reference map prediction** | Ketika aplikasi menggunakan peta referensi tidak langsung (token acak yang dipetakan ke ID nyata), menebak atau brute-forcing token pemetaan | Peta referensi tidak langsung menggunakan entropi yang tidak mencukupi atau generasi yang dapat diprediksi |
| **Map pollution** | Menyuntikkan entri ke dalam peta referensi untuk membuat pemetaan dari token yang dikontrol penyerang ke ID objek korban | Peta referensi dapat ditulis oleh pengguna (misalnya disimpan dalam sesi client-side) |
| **Cache key manipulation** | Mengakses respons yang ter-cache untuk objek pengguna lain dengan memanipulasi cache key (misalnya menghapus header `Vary` atau parameter cache-buster) | Cache tidak menyertakan konteks otorisasi dalam cache key |

---

## §4. Vektor Spesifik Paradigma API

Arsitektur API dan bahasa kueri yang berbeda memperkenalkan attack surface khusus paradigma untuk IDOR/BOLA.

### §4-1. Vektor REST API

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Sub-resource traversal** | Mengakses `/users/{victim_id}/settings` ketika hanya diotorisasi untuk `/users/{attacker_id}/settings` | Otorisasi per-resource tidak diterapkan pada rute bersarang |
| **Collection endpoint data leak** | Mengakses endpoint listing `/api/users` atau `/api/orders` yang mengembalikan semua record tanpa memfilter berdasarkan kepemilikan | Endpoint koleksi tidak memiliki filtering per-objek |
| **HATEOAS link following** | Respons API menyertakan hypermedia link ke resource terkait; mengikuti link yang ditujukan untuk pengguna lain melewati kontrol akses berbasis navigasi | Otorisasi bergantung pada "pengguna hanya akan mengikuti link mereka sendiri" |
| **Bulk/batch endpoint abuse** | `POST /api/bulk` yang menerima array ID di mana otorisasi ID individual dilewati demi performa | Operasi batch mengoptimalkan otorisasi per-elemen |

### §4-2. Vektor GraphQL

Struktur query GraphQL yang fleksibel memperkenalkan attack surface IDOR unik yang tidak ada di REST API.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Node/Global ID query** | Melakukan query `node(id: "Base64EncodedGlobalId")` untuk mengakses objek apa pun dalam skema berdasarkan ID globalnya | Interface `node` bergaya Relay tidak memiliki otorisasi per-tipe |
| **Introspection-guided attack** | Menggunakan introspection untuk menemukan tipe objek, field, dan relasi, lalu membuat query untuk mengakses objek yang tidak diotorisasi | Introspection diaktifkan di produksi; mengungkapkan seluruh authorization surface |
| **Nested relationship traversal** | Melakukan query `user(id: attacker) { organization { users { privateData } } }` untuk melintasi relasi ke data pengguna lain | Otorisasi diperiksa pada field root tetapi tidak pada relasi yang ter-resolve |
| **Alias-based enumeration** | Menggunakan `a1: user(id: 1) { email } a2: user(id: 2) { email } ...` untuk menumerasi objek dalam satu permintaan, melewati rate limit | Rate limiting per-permintaan; tidak ada otorisasi per-field; alias melewati logika rate |
| **Mutation argument tampering** | Memodifikasi `mutation { updateUser(id: victim_id, input: {...}) }` untuk memperbarui record pengguna lain | Mutation resolver tidak memverifikasi kepemilikan objek target |
| **Fragment-based field extraction** | Menggunakan fragment untuk secara selektif meminta field sensitif yang mungkin memiliki tingkat otorisasi berbeda | Otorisasi di level field tidak konsisten di seluruh ekspansi fragment |

### §4-3. Vektor gRPC dan Protocol Buffer

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Manipulasi field number Protobuf** | Memodifikasi nomor field dalam pesan protobuf yang telah di-serialize untuk mereferensikan objek yang berbeda | Layanan gRPC mengekspos object ID dalam field protobuf tanpa otorisasi |
| **Akses service method** | Memanggil method internal layanan gRPC (misalnya `AdminService.GetUser`) yang tidak memiliki otorisasi karena dianggap "internal" | Service mesh mempercayai semua pemanggil internal; tidak ada otorisasi per-method |

### §4-4. Vektor Webhook dan Callback

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Webhook URL manipulation** | Mendaftarkan webhook untuk event pengguna lain dengan menentukan ID pengguna/resource mereka dalam langganan webhook | Pendaftaran webhook tidak memverifikasi kepemilikan resource yang dilanggan |
| **Callback parameter injection** | Callback OAuth/payment menyertakan object ID dalam return URL; memodifikasinya mengalihkan hasil callback ke objek penyerang | Handler callback mempercayai object ID dalam callback URL tanpa memverifikasi kepemilikan ulang |

---

## §5. Eksploitasi Scope Objek dan Relasi

IDOR/BOLA menjadi lebih rumit ketika menargetkan objek yang terhubung melalui hierarki relasional, batasan multi-tenant, atau aturan akses di level properti.

### §5-1. Akses Objek Horizontal vs. Vertikal

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Horizontal IDOR** | Mengakses resource pengguna lain pada tingkat hak yang sama (misalnya Pengguna A membaca pesanan Pengguna B) | Pola IDOR paling umum; tidak ada pemeriksaan kepemilikan |
| **Vertical IDOR (privilege escalation)** | Mengakses resource khusus admin dengan mereferensikan ID objek admin (misalnya mengakses `/admin/config/1` sebagai pengguna biasa) | Kontrol akses berbasis peran tidak diterapkan di level objek |
| **Cross-role function access (BFLA crossover)** | Pengguna dengan peran "viewer" mengakses endpoint yang ditujukan untuk peran "editor" dengan mereferensikan ID objek yang sama | Otorisasi di level fungsi dan objek tercampur; pemeriksaan peran hilang |

### §5-2. Manipulasi di Level Properti Objek (BOPLA)

BOPLA (Broken Object Property Level Authorization) adalah penyempurnaan dari BOLA di mana penyerang dapat mengakses atau memodifikasi *properti* tertentu dari objek yang mungkin mereka miliki akses parsial.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Sensitive field exposure** | API mengembalikan objek lengkap termasuk field yang seharusnya tidak dilihat pengguna (misalnya `password_hash`, `ssn`, `internal_notes`) | Tidak ada pemfilteran di level field berdasarkan peran/izin pemohon |
| **Mass assignment / property injection** | Mengirimkan `{"role": "admin"}` atau `{"balance": 99999}` bersama field yang sah dalam permintaan update | Framework secara otomatis mengikat request body ke model; tidak ada whitelist field yang dapat diperbarui |
| **Read-only field overwrite** | Memodifikasi field yang dimaksudkan tidak dapat diubah (misalnya `created_by`, `owner_id`, `plan_tier`) melalui permintaan API | API tidak menerapkan izin tulis di level field |
| **Partial update privilege bypass** | Endpoint PATCH memungkinkan pembaruan field apa pun dari objek yang dapat diakses pengguna secara parsial | Handler PATCH tidak membatasi field mana yang dapat dimodifikasi per peran |

### §5-3. Akses Multi-Tenant dan Cross-Organisasi

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Cross-tenant ID reference** | Pengguna di Tenant A mengakses resource milik Tenant B dengan menggunakan ID objek Tenant B | Isolasi tenant diterapkan di level aplikasi tetapi tidak di lapisan akses data |
| **Manipulasi tenant ID** | Memodifikasi `tenant_id`, `org_id`, atau `workspace_id` dalam parameter permintaan | Scoping tenant bergantung pada identifier tenant yang disuplai klien, bukan yang diambil dari sesi |
| **Shared resource tenant leak** | Mengakses resource shared/global yang secara tidak sengaja mengekspos data spesifik-tenant | Endpoint shared tidak memfilter hasil berdasarkan konteks tenant |
| **Sub-organization traversal** | Mengakses data organisasi saudara dalam struktur org hierarki dengan memodifikasi ID level-org | Otorisasi memeriksa keanggotaan org parent tetapi bukan sub-org spesifik |

### §5-4. Akses Objek Relasional dan Tidak Langsung

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Foreign key traversal** | Mengakses objek terkait melalui relasi foreign key (misalnya `order.customer_id` → akses record pelanggan) | Otorisasi pada objek primer tidak meluas ke objek terkait |
| **Inverse relationship exploitation** | Melakukan query dari "sisi lain" suatu relasi (misalnya alih-alih `user/123/orders`, query `order/456` secara langsung) | Otorisasi diterapkan pada satu arah traversal tetapi tidak pada arah sebaliknya |
| **Aggregation endpoint data leak** | Endpoint seperti `/api/stats?group_by=user_id` atau `/api/reports` mengagregasi data lintas pengguna tanpa filter kepemilikan | Query agregasi melewati row-level security |

---

## §6. Model Observasi: Blind IDOR dan Second-Order IDOR

Tidak semua eksploitasi IDOR menghasilkan hasil yang langsung terlihat. Memahami model feedback sangat penting untuk eksploitasi maupun deteksi.

### §6-1. Direct (Visible) IDOR

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Data dalam response body** | Data yang tidak diotorisasi dikembalikan langsung dalam respons HTTP | IDOR klasik; konfirmasi eksploitasi langsung |
| **Status code differential** | Kode status HTTP yang berbeda untuk objek yang ada vs. tidak ada mengungkapkan keberadaan objek | `200` untuk ID valid vs `404` untuk ID tidak valid; memungkinkan enumerasi bahkan tanpa eksposur data |
| **Response timing differential** | Waktu respons yang berbeda secara terukur untuk ID objek valid vs. tidak valid | Waktu pencarian database bervariasi; memungkinkan blind enumeration melalui timing side-channel |

### §6-2. Blind IDOR

Dalam blind IDOR, tindakan penyerang berhasil pada objek korban, tetapi penyerang tidak menerima konfirmasi langsung dalam respons.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Write-only blind IDOR** | Memodifikasi data pengguna lain (misalnya mengubah email mereka, menghapus item mereka) tanpa menerima data kembali | Endpoint tulis mengembalikan respons sukses generik; korban mengamati perubahan |
| **Side-effect blind IDOR** | Memicu tindakan atas nama pengguna lain (misalnya mengirim password reset, berhenti berlangganan dari layanan, memicu notifikasi) | Endpoint aksi tidak mengembalikan data pengguna target tetapi menjalankan efek samping |
| **Blind enumeration via error differential** | Pesan error berbeda secara subtle untuk objek yang diotorisasi-tapi-tidak-ada vs. yang tidak diotorisasi (misalnya "Not found" vs. "Forbidden") | Respons error membocorkan state otorisasi |

### §6-3. Second-Order IDOR

Efek eksploitasi bermanifestasi di *fungsionalitas yang berbeda* atau pada *waktu yang lebih lambat* dari injeksi awal. Pola umum meliputi object reference yang disuntikkan muncul di laporan/ekspor yang dihasilkan (di mana batch job memproses referensi tersimpan tanpa memeriksa ulang otorisasi) atau target notifikasi yang dimodifikasi (misalnya URL webhook) pada objek pengguna lain yang menyebabkan eksfiltrasi data melalui pipeline notifikasi.

---

## §7. Manipulasi Temporal dan Berbasis State

Keputusan otorisasi dapat dibatalkan oleh timing attack, transisi state, dan manipulasi alur kerja.

### §7-1. Race Condition / TOCTOU IDOR

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Concurrent request authorization bypass** | Mengirimkan permintaan simultan untuk mengubah kepemilikan objek dan mengakses objek; satu permintaan lolos pemeriksaan sebelum yang lain mengubah state | Pola check-then-act non-atomik dalam otorisasi |
| **Permission change race** | Mengakses resource dalam jendela antara pencabutan izin dan penegakannya | Propagasi izin asinkron; keputusan otorisasi yang di-cache |
| **Token refresh race** | Menggunakan sesi/token lama untuk mengakses objek selama jendela di mana token baru (dengan izin terbatas) sedang diterbitkan | Validasi token di-cache; revokasi tidak instan |

### §7-2. Penyalahgunaan Alur Kerja dan Transisi State

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Multi-step process ID swap** | Dalam alur kerja multi-langkah (misalnya buat → konfigurasi → kirim), menukar object ID antar langkah untuk melampirkan tindakan penyerang ke objek korban | Otorisasi diperiksa pada langkah 1 tetapi tidak diverifikasi ulang pada langkah berikutnya |
| **Draft/pending state access** | Mengakses objek dalam state pra-publikasi (misalnya draft post, pesanan yang tertunda) melalui referensi ID langsung | Visibilitas berbasis state tidak diterapkan di lapisan akses objek |

---

## §8. Eksploitasi Konteks Arsitektur dan Deployment

Arsitektur deployment aplikasi modern menciptakan celah otorisasi di batas-batas sistem yang mungkin tidak ditangani oleh layanan individual.

### §8-1. Pelanggaran Trust Boundary Microservice

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Inter-service trust assumption** | Layanan A mengautentikasi pengguna dan meneruskan konteks pengguna ke Layanan B; Layanan B mempercayai otorisasi Layanan A tanpa memeriksanya ulang | Pola "trusted caller" antar microservice; tidak ada otorisasi end-to-end |
| **API gateway bypass** | Mengakses langsung endpoint microservice backend yang melewati lapisan otorisasi API gateway | Layanan backend terekspos di jaringan internal tetapi dapat dijangkau via SSRF atau jaringan yang salah konfigurasi |
| **Service mesh token reuse** | Menggunakan token service-to-service yang diperoleh untuk satu tujuan untuk mengakses objek di layanan lain | Token layanan berbutir kasar tanpa scope di level objek |

### §8-2. Vektor Spesifik Mobile dan Client-Side

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Mobile API parameter exposure** | Aplikasi mobile mengirimkan object ID yang tersembunyi di UI tetapi terlihat dalam traffic yang diintersep (misalnya via Burp Suite/mitmproxy) | Backend mobile mempercayai pembatasan UI client-side sebagai kontrol akses |
| **Offline cache exploitation** | Aplikasi mobile menyimpan objek secara lokal dengan ID mereka; reverse-engineering cache mengungkapkan ID yang dapat digunakan terhadap API | Penyimpanan/cache lokal berisi ID untuk objek di luar scope otorisasi pengguna |
| **Deep link / URL scheme abuse** | Membuat deep link seperti `myapp://user/456/profile` untuk memicu aplikasi mengambil profil pengguna lain tanpa otorisasi | Handler deep link tidak memverifikasi otorisasi sebelum mengambil objek yang direferensikan |

### §8-3. Vektor Cloud dan Infrastruktur

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Cloud storage object ID guessing** | Mengakses `https://bucket.s3.amazonaws.com/user_456_document.pdf` dengan memodifikasi pola nama file | Objek cloud storage diberi nama dengan pola yang dapat diprediksi; tidak ada kebijakan IAM per-objek |
| **Shared database tanpa row-level security** | Beberapa microservice berbagi database; satu layanan melakukan query tanpa filter tenant/user yang diterapkan layanan lain | Datastore bersama; otorisasi diterapkan di lapisan aplikasi, bukan di lapisan database |

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama | Dampak Tipikal |
|----------|------------|----------------------|----------------|
| **Akses data horizontal** | Aplikasi web/API apa pun | §1 + §2 + §6-1 | Eksposur PII, pelanggaran privasi |
| **Vertical privilege escalation** | Sistem berbasis peran | §5-1 + §3-1 + §5-2 | Akses admin, kontrol konfigurasi |
| **Cross-tenant breach** | SaaS multi-tenant | §5-3 + §8-1 + §2-3 | Kompromi data tenant penuh |
| **Mass data exfiltration** | API dengan ID yang dapat dienumerasi | §1-1 + §6-1 + §4-1 | Pelanggaran data berskala besar |
| **Account takeover chain** | Aplikasi dengan API profil/pengaturan | §2-3 + §6-2 + §7-2 | Perubahan email/kata sandi → ATO penuh |
| **Financial manipulation** | Sistem pembayaran/penagihan | §5-2 + §7-1 + §3-3 | Manipulasi saldo, transaksi tidak diotorisasi |
| **Destructive blind IDOR** | API mana pun yang mendukung penulisan | §6-2 + §3-1 + §2-2 | Penghapusan data, gangguan layanan |
| **Supply chain compromise** | Sistem CI/CD dan artifact | §8-1 + §4-3 + §5-3 | Modifikasi build/deploy tidak diotorisasi |
| **IoT/device takeover** | Platform manajemen IoT | §8-2 + §1-1 + §5-3 | Kontrol perangkat, manipulasi firmware |

---

## Pemetaan CVE / Bug Bounty (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|-----------------|------------|-----------------|
| §1-1 + §4-1 (Sequential ID + REST sub-resource) | CVE-2024-1313 (Grafana) | Akses snapshot dashboard oleh pengguna yang tidak terautentikasi di Grafana (20 juta+ pengguna). Patch di v10.4.1 |
| §1-1 + §5-3 (Sequential ID + multi-tenant) | CVE-2024-46528 (KubeSphere v3.4.1/v4.1.1) | Pengguna berhak rendah mengakses resource cluster Kubernetes sensitif lintas tenant |
| §4-1 + §5-1 (REST endpoint + horizontal access) | CVE-2023-3285 hingga CVE-2023-3290 (Easy!Appointments) | 6 kerentanan BOLA dalam rentang CVE ini. Akses penuh ke data pasien/janji temu |
| §4-1 + §8-1 (REST + microservice trust) | CVE-2024-22278 (Harbor) | BOLA di container registry cloud-native; akses tidak diotorisasi ke container image dan repositori |
| §1-1 + §2-1 (Sequential ID + path param) | CVE-2024-56404 (One Identity Manager 9.x) | IDOR di sistem manajemen identitas; akses ke record identitas di seluruh perusahaan |
| §2-3 + §5-2 (Body param + mass assignment) | CVE-2024-1626 (Lunary AI) | IDOR di platform AI yang memungkinkan akses data tidak diotorisasi |
| §1-1 + §5-1 (Numeric ID + horizontal) | CVE-2024-55471 (Oqtane Framework) | IDOR yang memungkinkan akses data lintas pengguna dalam framework CMS .NET |
| §1-1 + §2-1 (Numeric param + path param) | CVE-2025-40658 (DM Corporative CMS < 2025.01) | CVSS 7.5. IDOR di panel admin melalui manipulasi parameter `option` di `/administer/selectionnode/framesSelection.asp`. |
| §1-1 + §6-1 (Enumerable ID + direct feedback) | HackerOne #PayPal | $10.500. IDOR untuk menambahkan pengguna sekunder dalam manajemen akun bisnis PayPal |
| §6-2 + §3-1 (Blind IDOR + method bypass) | HackerOne #various | $12.500. IDOR yang memungkinkan penghapusan lisensi/sertifikasi dari profil pengguna lain |
| §5-3 + §8-3 (Cross-tenant + cloud) | Growatt Solar IoT (2025) | BOLA dalam API inverter surya memungkinkan peretas mengambil kendali perangkat IoT lintas organisasi |

---

## Tool Deteksi

| Tool | Cakupan Target | Teknik Inti |
|------|---------------|-------------|
| **BOLABuster** (Palo Alto Unit 42) | REST API dengan spesifikasi OpenAPI | Analisis berbasis LLM dari spesifikasi API; menghasilkan test case BOLA secara otomatis; mengirim <1% permintaan dibanding fuzzer tradisional |
| **Autorize** (Ekstensi Burp) | Aplikasi web apa pun via proxy | Memutar ulang permintaan dengan sesi hak rendah; membandingkan respons untuk mendeteksi bypass otorisasi |
| **AuthMatrix** (Ekstensi Burp) | Aplikasi web dengan akses berbasis peran | Pengujian berbasis matriks dari pengguna × endpoint × method; menyoroti celah otorisasi secara visual |
| **APIsec Scanner** | REST dan GraphQL API | Deteksi BOLA otomatis dengan pemahaman logika bisnis; integrasi CI/CD |
| **Cloudflare API Shield** | API di belakang Cloudflare | Deteksi BOLA runtime via analisis pola traffic; memberi label endpoint dengan `cf-risk-bola-enumeration` dan `cf-risk-bola-pollution` |
| **Akto** | REST dan GraphQL API | Pengujian BOLA via parameter pollution; generasi test otomatis dari traffic API |
| **Cequence UAP** | Platform API enterprise | Penemuan API berbasis jaringan + analisis perilaku; mendeteksi pola enumerasi saat runtime |
| **InQL** (Ekstensi Burp) | GraphQL API | Analisis introspeksi GraphQL; mengidentifikasi tipe yang dapat di-query dan authorization test surface |
| **GraphQL Voyager** | GraphQL API | Visualisasi skema; memetakan relationship graph untuk mengidentifikasi traversal path kritis otorisasi |
| **Nuclei** (ProjectDiscovery) | Pemindaian kerentanan umum | Pemindaian berbasis template dengan template spesifik IDOR untuk pola umum |
| **OWASP ZAP Access Control Plugin** | Aplikasi web | Pengujian kontrol akses melalui perbandingan konteks pengguna |

---

## Ringkasan: Prinsip Inti

**Properti fundamental yang membuat IDOR/BOLA menjadi kelas kerentanan web paling persisten adalah pemisahan antara autentikasi dan otorisasi.** Framework web modern secara universal menyediakan middleware autentikasi (manajemen sesi, validasi JWT, alur OAuth) yang diadopsi developer secara default. Namun, tidak ada framework yang dapat secara otomatis menentukan *pengguna terautentikasi mana* yang seharusnya mengakses *objek spesifik mana* — ini pada dasarnya merupakan keputusan logika bisnis. Hasilnya adalah celah yang sistematis: developer dengan benar memverifikasi *siapa* pengguna tersebut, tetapi mengabaikan verifikasi *apa* yang seharusnya diakses pengguna tersebut. Setiap endpoint yang menerima identifier objek yang disuplai pengguna adalah potensi attack surface IDOR, dan dengan proliferasi RESTful API, GraphQL, dan microservice, jumlah endpoint tersebut per aplikasi telah tumbuh dari puluhan menjadi ribuan.

**Perbaikan inkremental gagal karena IDOR bukan satu bug melainkan kelalaian arsitekturil.** Menambal satu endpoint meninggalkan ratusan lainnya tanpa perlindungan. Mengganti ID sekuensial dengan UUID menggeser serangan dari enumerasi ke eksploitasi kebocoran tanpa mengatasi akar masalah. Menambahkan API gateway memindahkan masalah otorisasi, bukan menyelesaikannya. Bahkan tool pemindaian otomatis kesulitan karena BOLA adalah cacat *semantik* — menentukan apakah Pengguna A seharusnya mengakses Objek X memerlukan pemahaman aturan bisnis aplikasi, bukan hanya perilaku HTTP-nya. Inilah mengapa BOLA telah mempertahankan posisi #1 dalam OWASP API Security Top 10 sejak 2019.

**Solusi struktural membutuhkan arsitektur authorization-by-default:** setiap operasi akses data harus melewati lapisan otorisasi yang mengevaluasi kepemilikan/izin sebelum mengembalikan data. Ini dapat diimplementasikan sebagai kebijakan row-level security (RLS) di level database, query scoping di level ORM (misalnya selalu memfilter berdasarkan `tenant_id` dan `user_id`), atau policy engine di level middleware (misalnya OPA, Casbin, Cedar). Prinsip arsitektur utamanya adalah bahwa otorisasi harus bersifat **wajib dan tidak dapat dihindari** — tidak ada jalur kode yang harus dapat mengakses objek tanpa melewati gerbang otorisasi. Dikombinasikan dengan integration testing komprehensif yang memverifikasi bahwa akses lintas pengguna ditolak untuk setiap endpoint (menggunakan tool seperti Autorize atau BOLABuster), ini mengubah IDOR dari masalah penambalan endpoint-per-endpoint menjadi jaminan sistemik.

---

## Referensi

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP Insecure Direct Object Reference Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
- CWE-639: Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- Unit 42 — Harnessing LLMs for Automating BOLA Detection (BOLABuster): https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/
- Unit 42 — BOLA Vulnerabilities in Easy!Appointments: https://unit42.paloaltonetworks.com/bola-vulnerabilities-easyappointments/
- Unit 42 — BOLA Vulnerability in Harbor: https://unit42.paloaltonetworks.com/bola-vulnerability-impacts-container-registry-harbor/
- PortSwigger Web Security Academy — Insecure Direct Object References: https://portswigger.net/web-security/access-control/idor
- Cloudflare API Shield — BOLA Detection: https://developers.cloudflare.com/api-shield/security/bola-vulnerability-detection/
- HackerOne Top IDOR Reports: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPIDOR.md
- Intigriti — Complete Guide to Exploiting Advanced IDOR Vulnerabilities: https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities
- Fortbridge — IDOR Exploitation via HPP Case Study: https://fortbridge.co.uk/research/idor-exploitation-via-hpp-api-hacking-case-study/
- Escape.tech — IDOR in GraphQL: https://escape.tech/blog/idor-in-graphql/
- Intruder: "In GUID We Trust" (2022) — Analisis sistematis tentang prediktabilitas versi UUID; ekstraksi timestamp/MAC UUIDv1, metodologi cracking UUID

---

*Dokumen ini dibuat untuk keperluan riset keamanan defensif dan pemahaman kerentanan.*
