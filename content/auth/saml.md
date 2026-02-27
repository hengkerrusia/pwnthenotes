---
title: SAML
---
## Struktur Klasifikasi

Security Assertion Markup Language (SAML) adalah standar terbuka berbasis XML untuk pertukaran data autentikasi dan otorisasi antara identity provider (IdP) dan service provider (SP). Ketergantungannya pada XML sebagai format transport — dikombinasikan dengan model kepercayaan kompleks yang melibatkan tanda tangan kriptografis, penyampaian pesan multi-pihak, dan ekosistem library yang beragam — menciptakan permukaan mutasi yang sangat luas. Kerentanan dalam SAML tidak berasal dari satu celah tunggal, melainkan dari ketegangan fundamental antara fleksibilitas struktural XML dan jaminan ketat yang seharusnya diberikan oleh tanda tangan digital.

Taksonomi ini mengorganisasi seluruh permukaan serangan SAML berdasarkan tiga sumbu. **Sumbu 1 (Target Mutasi)** mendefinisikan _komponen struktural_ protokol SAML yang diserang — ini adalah sumbu organisasi utama. **Sumbu 2 (Jenis Ketidaksesuaian)** menggambarkan _jenis ketidakcocokan atau celah_ yang memungkinkan serangan — sumbu lintas-bidang ini menjelaskan mengapa setiap mutasi berhasil. **Sumbu 3 (Skenario Serangan)** memetakan _di mana dan bagaimana_ mutasi tersebut dijadikan senjata dalam penerapan dunia nyata.

### Sumbu 2: Jenis Ketidaksesuaian (Lintas-Bidang)

|Kode|Jenis Ketidaksesuaian|Deskripsi|
|---|---|---|
|**D1**|Celah Binding Signature-Konten|Bagian dokumen yang ditandatangani berbeda dari bagian yang diproses SP untuk logika bisnis|
|**D2**|Diferensial Parser|Dua parser XML (atau parser yang sama dalam mode berbeda) menghasilkan pohon dokumen yang berbeda dari input yang identik|
|**D3**|Divergensi Canonicalization|Transform C14N menghasilkan output yang tidak terduga (kosong, terpotong, atau berubah makna), merusak asumsi digest|
|**D4**|Kelalaian Validasi|Langkah verifikasi yang diperlukan (signature, recipient, timestamp, audience) sepenuhnya dilewati|
|**D5**|Kebingungan Batas Kepercayaan|Assertion yang valid untuk satu konteks kepercayaan diterima di konteks lain (lintas-SP, lintas-tenant, lintas-lingkungan)|
|**D6**|Kegagalan Validasi Temporal|Batasan berbasis waktu (NotBefore, NotOnOrAfter, jendela replay) tidak diterapkan atau diterapkan dengan toleransi yang berlebihan|
|**D7**|Kompromi Materi Kriptografis|Kunci penandatanganan atau sertifikat dicuri, dipalsukan, atau dapat dikontrol dari luar, memungkinkan pemalsuan assertion dari sumbernya|

### Akar Masalah Fundamental

Model keamanan SAML bergantung pada sebuah **rantai yang rapuh**: dokumen XML dibuat, di-canonicalize, di-digest, ditandatangani, dikirimkan, diterima, di-parse, diverifikasi signature-nya, dan kemudian _bagian yang berpotensi berbeda_ diekstrak untuk logika bisnis. Setiap tautan dalam rantai ini — pembuatan, canonicalization, parsing, verifikasi, ekstraksi — mungkin dilakukan oleh kode, library, atau konfigurasi yang berbeda. Ruang mutasi ada di setiap celah antara tahap pemrosesan ini.

---

## S1. XML Signature Wrapping (XSW)

XML Signature Wrapping mengeksploitasi pemisahan struktural antara referensi yang ditandatangani (diidentifikasi oleh URI) dan elemen yang benar-benar diproses SP untuk keputusan autentikasi. Dengan merelokasi, menduplikasi, atau menyarangkan elemen XML, penyerang dapat membuat signature terverifikasi terhadap elemen yang sah sementara SP memproses elemen yang dipalsukan.

### S1-1. Wrapping Tingkat Response

Penyerang menduplikasi atau merelokasi seluruh elemen `<samlp:Response>`, menempatkan salinan palsu di mana query XPath SP akan menemukannya terlebih dahulu.

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Post-Signature Clone (XSW1)**|`<Response>` unsigned yang di-clone disisipkan _setelah_ elemen `<Signature>` yang ada. SP memproses `<Response>` pertama yang ditemuinya (yang palsu) sementara verifikasi signature menarget yang asli melalui referensi URI.|SP menggunakan XPath non-spesifik (misalnya `//Response`) daripada pencarian berbasis URI|
|**Pre-Signature Clone (XSW2)**|`<Response>` unsigned yang di-clone disisipkan _sebelum_ elemen `<Signature>`. Urutan parser menentukan elemen mana yang dikonsumsi SP.|SP memilih elemen berdasarkan urutan dokumen daripada pencocokan atribut `ID`|
|**Envelope Inversion**|Response yang ditandatangani asli dibungkus di dalam Response palsu sebagai elemen anak (misalnya dalam `<samlp:Extensions>`). SP memproses Response terluar; verifikasi signature mengikuti URI ke dalam aslinya yang tersarang.|SP tidak menegakkan kedalaman dokumen maksimum atau skema struktural|

### S1-2. Wrapping Tingkat Assertion

Penyerang menargetkan elemen `<saml:Assertion>` secara khusus, menyuntikkan assertion palsu sambil mempertahankan assertion asli yang ditandatangani.

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Pre-Assertion Injection (XSW3)**|`<Assertion>` palsu yang unsigned ditempatkan sebelum Assertion yang ditandatangani secara sah dalam Response. SP mengekstrak Assertion pertama berdasarkan urutan dokumen.|SP tidak memverifikasi bahwa setiap Assertion memiliki signature yang valid|
|**Intra-Assertion Injection (XSW4)**|Assertion palsu yang unsigned disarangkan _di dalam_ Assertion yang ditandatangani sebagai elemen anak. Query XPath SP menelusuri ke dalam salinan palsu yang tersarang.|SP menggunakan XPath dengan sumbu turunan (`//Assertion`) yang mencocokkan elemen tersarang|
|**Assertion Swap (XSW5)**|Nilai dalam Assertion yang ditandatangani dimodifikasi (misalnya `NameID` diubah menjadi admin). Assertion asli yang tidak dimodifikasi ditambahkan ke dokumen dengan Signature-nya dihapus, berfungsi sebagai umpan.|Verifikasi signature memeriksa salinan yang dimodifikasi berdasarkan posisi daripada referensi `ID`|
|**Post-Signature Assertion (XSW6)**|Mirip dengan XSW5, tetapi salinan Assertion asli yang unsigned ditempatkan tepat setelah elemen `<Signature>` daripada di akhir dokumen.|Logika verifikasi signature yang bergantung pada posisi|

### S1-3. Penyematan Extension/Object Block

Titik ekstensi yang diizinkan skema dalam SAML menyediakan container tempat struktur yang ditandatangani secara lengkap dapat disembunyikan atau direlokasi.

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Extensions Block Embedding (XSW7)**|Assertion unsigned yang di-clone disematkan dalam elemen `<samlp:Extensions>` dari Response. SP memproses Assertion palsu ini sementara signature memvalidasi terhadap Assertion asli di posisi yang diharapkan.|SP tidak membatasi ekstraksi Assertion ke anak langsung Response|
|**Object Block Embedding (XSW8)**|Assertion yang ditandatangani asli direlokasi ke dalam elemen `<ds:Object>` di dalam blok `<ds:Signature>`. Assertion palsu menggantikannya di level teratas. Referensi URI signature masih dapat me-resolve ke aslinya di dalam `<ds:Object>`.|SP memproses assertion berdasarkan posisi; verifikasi signature mengikuti referensi URI ke dalam `<ds:Object>`|
|**Encrypted Assertion Wrapping**|Pada sistem yang mendukung assertion terenkripsi, Response yang ditandatangani dengan valid disematkan di dalam elemen `<ds:Object>`. Signature yang hanya ditemukan setelah dekripsi tidak divalidasi ulang, sehingga assertion palsu di luar dapat lolos. (CVE-2024-9487)|Assertion terenkripsi diaktifkan; ekstraksi signature pasca-dekripsi tidak divalidasi|

### S1-4. Wrapping Berbantuan Namespace

Manipulasi namespace memperkuat signature wrapping dengan membuat elemen tidak terlihat pada satu tahap pemrosesan sementara terlihat di tahap lainnya.

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Namespace Redeclaration Hiding**|Elemen `<Signature>` palsu ditempatkan di level Assertion dengan namespace yang dideklarasikan ulang (misalnya `xml:xmlns='http://www.w3.org/2000/09/xmldsig#'`). Satu parser memperlakukannya sebagai Signature yang valid; parser lain memperlakukannya sebagai elemen yang tidak dikenal dan melewatinya. Dikombinasikan dengan XSW untuk menempatkan signature yang sah di tempat lain.|Penanganan parser khusus untuk redeclaration namespace dengan prefiks `xml:`|
|**Namespace-Scoped Element Hiding**|Elemen ditempatkan dalam namespace yang dikenali modul verifikasi signature tetapi diabaikan logika bisnis SP (atau sebaliknya), sehingga secara efektif menciptakan container yang tidak terlihat.|Query XPath yang sadar-namespace vs. yang tidak sadar-namespace di berbagai tahap|

---

## S2. Serangan Diferensial Parser XML

Diferensial parser mengeksploitasi kenyataan bahwa implementasi SAML sering menggunakan beberapa parser XML — atau parser yang sama dalam konfigurasi berbeda — untuk verifikasi signature vs. ekstraksi logika bisnis. Ketika dua parser membuat pohon dokumen yang berbeda dari input yang sama, penyerang dapat membuat konten yang ditandatangani dan konten yang diproses menjadi berbeda.

### S2-1. Divergensi Dual-Parser

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Diferensial Nokogiri vs. REXML**|Ruby-SAML menggunakan Nokogiri (didukung libxml2) untuk verifikasi signature dan REXML (Ruby murni) untuk ekstraksi Assertion. Query XPath yang identik mengembalikan node yang berbeda karena divergensi struktural dalam pembuatan pohon. Penyerang membuat XML yang diterima oleh kedua parser tetapi diinterpretasikan secara berbeda. (CVE-2025-25291, CVE-2025-25292)|Ruby-SAML < 1.18.0 yang menggunakan arsitektur dual-parser|
|**libxml2 vs. Parser Kustom**|Implementasi SAML PHP yang menggunakan libxml2 untuk satu tahap dan parser kustom atau berbeda untuk tahap lain menunjukkan divergensi serupa dalam penanganan namespace, pengurutan atribut, dan pemrosesan DOCTYPE.|Implementasi mana pun yang menggunakan stack parser heterogen|
|**Divergensi DOM vs. SAX**|Parser DOM membangun pohon lengkap dalam memori sementara parser SAX memproses event secara berurutan. Inkonsistensi dalam resolusi entitas, pelingkupan namespace, dan penanganan error antara dua model tersebut menciptakan interpretasi yang berbeda.|Implementasi yang mencampur tahap pemrosesan DOM dan SAX|

### S2-2. Konflik Resolusi Atribut

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Duplicate Attribute Pollution**|Ketika sebuah elemen berisi `ID="1"` dan `samlp:ID="2"`, pencarian atribut yang tidak sadar-namespace (misalnya `node.attribute('ID')`) menghasilkan hasil yang tidak dapat diprediksi tergantung pada implementasi parser. Modul signature dan modul logika bisnis mungkin me-resolve nilai `ID` yang berbeda, merusak binding signature-ke-assertion.|Parser tidak menjamin urutan resolusi atribut untuk atribut dengan namespace yang bertabrakan|
|**Default Namespace Attribute Shadowing**|Atribut XML tidak mewarisi namespace default, tetapi beberapa parser secara salah menerapkan namespace default ke atribut. Ini menciptakan kualifikasi namespace phantom yang menyebabkan pencarian atribut gagal atau mengembalikan nilai yang salah di satu parser tetapi tidak di yang lain.|Penerapan namespace default yang berbeda ke atribut|

### S2-3. Diferensial Pemrosesan DOCTYPE dan DTD

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**DOCTYPE ATTLIST Injection**|Deklarasi `<!ATTLIST>` dalam DTD internal mendefinisikan nilai atribut default. REXML menerapkan default ini (misalnya menetapkan deklarasi namespace yang bertentangan), sementara Nokogiri/libxml2 mungkin mengabaikannya. Ini memungkinkan penyerang membuat REXML melihat struktur namespace yang sepenuhnya berbeda dari verifier signature. (CVE-2025-25291)|Pemrosesan REXML dengan DTD diaktifkan; Ruby < 3.4.2|
|**Diferensial Definisi Entitas**|Deklarasi entitas kustom dalam DTD internal diperluas oleh beberapa parser tetapi ditolak oleh yang lain. Penyerang mendefinisikan entitas yang, saat diperluas, mengubah konten semantik Assertion yang hanya terlihat oleh satu parser.|Kebijakan pemrosesan DTD yang berbeda di seluruh tahap parser|

### S2-4. Round-Trip Mutation

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Parse-Serialize-Reparse Mutation**|Ketika dokumen SAML di-parse, di-serialize, dan di-parse ulang (umum dalam rantai middleware), mutasi struktural dapat terjadi: urutan atribut berubah, deklarasi namespace berpindah, whitespace dinormalisasi secara berbeda. Signature yang diverifikasi pada parse pertama mungkin tidak cocok dengan struktur yang di-parse ulang.|Pipeline pemrosesan multi-tahap dengan serialisasi antar tahap|
|**Comment-Induced Round-Trip**|Komentar XML yang disisipkan di antara node teks (misalnya `admin<!---->@evil.com`) dihapus selama canonicalization tetapi dapat menyebabkan pemisahan node teks selama parsing. Setelah round-trip, node teks yang terpisah mungkin digabungkan kembali secara berbeda, mengubah nilai yang diekstrak.|Ekstraksi node teks menggunakan semantik first-child-only|

---

## S3. Eksploitasi Canonicalization

XML Canonicalization (C14N) adalah proses transformasi XML ke dalam bentuk byte-stream kanonik sebelum komputasi digest. Serangan pada canonicalization mengeksploitasi kasus tepi di mana output C14N berbeda dari apa yang diharapkan oleh penanda tangan atau verifier.

### S3-1. Void Canonicalization

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Kegagalan Canonicalization URI Relatif**|Memasukkan deklarasi namespace relatif (misalnya `xmlns:ns="1"`) menyebabkan algoritma C14N menemukan URI relatif yang tidak dapat di-resolve. Per spesifikasi, ini seharusnya menghasilkan error, tetapi banyak implementasi secara diam-diam mengembalikan string kosong. Digest dari string kosong (`SHA-256: 47DEQpj8...`) dapat diprediksi, memungkinkan penyerang memalsukan `<DigestValue>` yang cocok. (CVE-2025-66568, CVE-2025-66567)|Implementasi mengembalikan string kosong saat error C14N daripada gagal keras|
|**Namespace Error Swallowing**|Mirip dengan kegagalan URI relatif tetapi dipicu oleh URI namespace yang cacat, referensi namespace sirkular, atau deklarasi namespace yang melebihi batas implementasi. Output C14N terdegradasi menjadi kosong, memungkinkan pemalsuan digest yang dapat diprediksi.|Penanganan error yang permisif dalam implementasi C14N|
|**Forced Empty Canonicalization**|Penyerang membuat XML di mana elemen yang ditandatangani, setelah pemrosesan C14N, menghasilkan bentuk kanonik yang kosong atau hampir kosong (misalnya dengan hanya menggunakan node namespace yang dikecualikan oleh exclusive C14N). Penyerang kemudian menetapkan DigestValue ke hash dari output kosong yang diharapkan.|Exclusive C14N dengan pengecualian namespace yang dibuat dengan cermat|

### S3-2. Manipulasi Comment dan Whitespace

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Comment Injection Identity Spoofing**|Komentar XML dalam `<NameID>` (misalnya `admin@legit.com<!-->.evil.com`) dihapus selama C14N, sehingga signature terverifikasi terhadap `admin@legit.com.evil.com`. Namun, ekstraksi teks SP mungkin berhenti di batas komentar, mengekstrak hanya `admin@legit.com`. (CVE-2017-11427, CVE-2017-11428)|SP mengekstrak teks menggunakan node teks pertama daripada konten teks yang digabungkan sepenuhnya|
|**Diferensial CDATA Section**|Bagian CDATA (`<![CDATA[...]]>`) diselesaikan menjadi teks selama C14N tetapi mungkin dipertahankan atau dipecah oleh parser tertentu selama ekstraksi teks, mengubah nilai efektif yang diproses SP.|Penanganan CDATA spesifik-parser dalam ekstraksi teks|
|**Injeksi Whitespace Tidak Signifikan**|Whitespace antara elemen XML tidak signifikan per skema tetapi dapat dipertahankan secara berbeda oleh berbagai mode C14N (C14N 1.0 vs. C14N 1.1 vs. exclusive C14N). Ini dapat mengubah nilai digest atau menciptakan divergensi pemrosesan.|Versi algoritma C14N yang berbeda antara penanda tangan dan verifier|

### S3-3. Comment-Digest Divergence (SAMLStorm)

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**DigestValue Comment Injection**|Komentar XML yang berisi digest palsu disisipkan ke dalam elemen `<DigestValue>`: `<DigestValue><!--forged_digest-->legitimate_digest</DigestValue>`. Kode verifikasi digest membaca _node anak pertama_ (komentar yang berisi digest palsu) sementara C14N menghapus komentar, membuat verifikasi signature lolos terhadap digest yang sah. (CVE-2025-29775)|xml-crypto <= 6.0.0; ekstraksi digest menggunakan firstChild daripada textContent|
|**SignatureValue Comment Injection**|Teknik serupa diterapkan pada `<SignatureValue>`: menyuntikkan komentar untuk membuat kode verifikasi membaca nilai signature yang berbeda dari yang dihasilkan C14N, memungkinkan bypass signature bersamaan dengan manipulasi digest. (CVE-2025-29774)|Pola ekstraksi firstChild yang sama dalam pemrosesan SignatureValue|

---

## S4. Bypass Validasi Signature

Alih-alih memanipulasi struktur XML, serangan ini mengeksploitasi implementasi yang melakukan validasi signature yang tidak lengkap, salah, atau tidak ada.

### S4-1. Eksploitasi Ketiadaan Signature

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Signature Stripping**|Elemen `<ds:Signature>` sepenuhnya dihapus dari SAML Response. Implementasi yang memperlakukan signature yang hilang sebagai "tidak diperlukan" daripada "kegagalan validasi" menerima assertion unsigned sebagai valid.|SP dikonfigurasi dengan verifikasi signature opsional atau kebijakan terima-default|
|**Penghapusan Assertion Signature**|Dalam Response yang berisi signature tingkat-Response dan tingkat-Assertion, hanya signature tingkat-Response yang dihapus (atau sebaliknya). Implementasi memvalidasi signature yang tersisa tetapi memproses konten dari bagian yang unsigned.|SP memvalidasi hanya satu level signature tetapi memproses elemen dari keduanya|
|**Selective Signature Stripping**|Dalam response yang berisi beberapa Assertion, signature dihapus dari Assertion tertentu sementara yang lain tetap ditandatangani. SP memvalidasi satu Assertion yang ditandatangani dan kemudian memproses semua Assertion termasuk yang unsigned.|SP menerapkan validasi signature hanya pada Assertion pertama|

### S4-2. Manipulasi Sertifikat dan Kunci

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Substitusi Sertifikat Self-Signed**|Penyerang menghasilkan sertifikat self-signed, menandatangani SAML Response palsu dengan sertifikat tersebut, dan menyertakannya dalam elemen `<ds:KeyInfo>`. SP yang mengekstrak kunci verifikasi dari pesan itu sendiri (daripada trust store yang dikonfigurasi sebelumnya) akan memvalidasi signature palsu.|SP mempercayai sertifikat KeyInfo tertanam tanpa memeriksa terhadap trust store IdP|
|**Certificate Cloning**|Sertifikat IdP yang sah di-clone (subject, issuer, validitas disalin) dengan keypair baru. Validasi sertifikat SP memeriksa kolom metadata tetapi bukan fingerprint kunci publik yang sebenarnya.|Validasi sertifikat berdasarkan pencocokan DN/issuer daripada key pinning|
|**KeyInfo Injection**|Elemen `<ds:KeyInfo>` yang berisi kunci publik yang dikontrol penyerang disuntikkan ke dalam blok Signature. Implementasi yang memprioritaskan materi kunci tertanam daripada kunci IdP yang dikonfigurasi sebelumnya akan menggunakan kunci penyerang untuk verifikasi.|Preferensi implementasi untuk materi kunci inline daripada trust anchor yang dikonfigurasi|

### S4-3. Manipulasi Algoritma

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Downgrade Algoritma**|URI algoritma `<ds:SignatureMethod>` atau `<ds:DigestMethod>` diubah ke algoritma yang lebih lemah (misalnya SHA-1, MD5) atau algoritma non-standar yang ditangani implementasi secara tidak aman.|SP tidak menegakkan daftar izin algoritma|
|**Injeksi Algoritma "None"**|Identifier algoritma diatur ke nilai yang menunjukkan "none" atau dibiarkan kosong. Implementasi yang gagal memvalidasi algoritma mungkin melewati verifikasi sepenuhnya.|Tidak ada validasi algoritma sebelum eksekusi verifikasi|
|**HMAC Confusion**|Algoritma diubah dari algoritma asimetris (RSA-SHA256) ke algoritma HMAC. Jika implementasi menggunakan kunci publik IdP (atau sertifikat) sebagai secret HMAC, penyerang dapat menandatangani dengan materi kunci yang tersedia secara publik.|Implementasi tidak menegakkan konsistensi keluarga algoritma|

### S4-4. Manipulasi Reference dan Transform

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Empty Reference URI**|`<ds:Reference URI="">` menargetkan seluruh dokumen. Penyerang memodifikasi elemen di luar lingkup yang ditandatangani yang diharapkan sementara digest masih mencakup (atau tampaknya mencakup) root dokumen.|Definisi lingkup yang ambigu ketika URI kosong|
|**Reference URI Mismatch**|Reference URI diubah untuk mengarah ke elemen yang berbeda dari Assertion yang diproses SP. Signature terverifikasi terhadap elemen yang direferensikan; SP mengonsumsi elemen yang berbeda.|SP tidak memverifikasi bahwa Reference URI yang ditandatangani cocok dengan ID Assertion yang diproses|
|**Transform Chain Injection**|Elemen `<ds:Transform>` tambahan disuntikkan ke dalam rantai transform signature, mengubah data yang menjadi dasar komputasi digest (misalnya transform XPath yang mengecualikan elemen yang dimodifikasi penyerang).|SP tidak membatasi algoritma Transform yang diizinkan|
|**XSLT Transform Pre-Verification Execution (Java)**|API `javax.xml.crypto` Java memproses stylesheet XSLT dalam `<ds:Transform>` _sebelum_ menyelesaikan verifikasi signature. Penyerang menyematkan payload XSLT yang membaca file lokal melalui `unparsed-text()` atau memicu SSRF melalui `document()` selama pemanggilan `XMLSignature.validate()` — dampaknya terjadi terlepas dari apakah signature pada akhirnya valid.|API XML Signature JDK (`javax.xml.crypto.dsig`) dengan `TransformService` default; tidak ada daftar izin algoritma Transform (Google Project Zero, 2022)|
|**XPath Filter Injection dalam Reference**|Transform XPath Filter 2.0 pada `<ds:Reference>` mengevaluasi ekspresi yang dikontrol penyerang. Dengan menyuntikkan subexpression XPath ke dalam filter, penyerang mendefinisikan ulang node DOM mana yang dicakup digest — mengecualikan elemen yang dimodifikasi dari verifikasi sementara SP tetap memprosesnya untuk keputusan autentikasi.|Java atau .NET XML Signature dengan transform XPath Filter 2.0 diaktifkan; tidak ada validasi ekspresi atau pembatasan transform|

---

## S5. Serangan XML Injection dan Entitas

Fondasi XML SAML mewarisi seluruh spektrum kerentanan parsing XML. Serangan ini menargetkan lapisan XML daripada lapisan protokol SAML.

### S5-1. XML External Entity (XXE) Injection

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**XXE klasik melalui DOCTYPE**|Deklarasi `<!DOCTYPE>` dengan referensi entitas eksternal (misalnya `<!ENTITY xxe SYSTEM "file:///etc/passwd">`) disuntikkan ke dalam SAML Response. Ketika parser XML me-resolve entitas, ia membaca file lokal atau membuat permintaan HTTP keluar.|Parser XML mengaktifkan resolusi entitas eksternal (default di banyak parser)|
|**Out-of-Band XXE (OOB-XXE)**|Entitas eksternal memicu permintaan HTTP ke server yang dikontrol penyerang, mengeksfiltrasi konten file melalui parameter URL. Ini berhasil bahkan ketika nilai entitas tidak tercermin dalam output pemrosesan SAML.|Resolusi entitas eksternal + HTTP keluar diizinkan|
|**Parameter Entity XXE**|Entitas parameter (`%entity;`) dalam subset DTD digunakan alih-alih entitas umum, melewati filter yang memblokir sintaks `&entity;` dalam badan dokumen.|Parser memproses entitas parameter dalam subset DTD internal|
|**XXE melalui SAML Metadata**|Parser XML memproses dokumen metadata SAML (metadata IdP atau SP) yang berisi deklarasi entitas berbahaya. Metadata sering diambil secara otomatis dari URL yang dikonfigurasi.|Pembaruan metadata otomatis dengan parsing XML yang rentan|

### S5-2. XML Entity Expansion (DoS)

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Billion Laughs (Ekspansi Eksponensial)**|Definisi entitas bersarang menciptakan ekspansi eksponensial: setiap entitas mereferensikan entitas sebelumnya beberapa kali. Payload <1KB berkembang menjadi gigabyte dalam memori. `<!ENTITY lol9 "&lol8;&lol8;&lol8;...">`|Tidak ada batasan kedalaman atau ukuran ekspansi entitas|
|**Quadratic Blowup**|Satu entitas besar diulang berkali-kali dalam badan dokumen. Menghindari deteksi berbasis kedalaman tetapi masih menyebabkan konsumsi memori kuadratik.|Batasan ekspansi entitas berdasarkan kedalaman tetapi bukan ukuran total|
|**Recursive Entity Loop**|Referensi entitas sirkular (`<!ENTITY a "&b;"><!ENTITY b "&a;">`) menyebabkan loop pemrosesan tak terbatas, menguras CPU.|Tidak ada deteksi referensi sirkular dalam resolusi entitas|

### S5-3. XSLT Injection

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Eksekusi XSLT Berbasis Transform**|`<xsl:stylesheet>` berbahaya disematkan dalam elemen `<ds:Transform>` dalam blok Signature. Pemrosesan XSLT terjadi _sebelum_ verifikasi signature, sehingga signature bisa self-signed atau tidak valid. XSLT dapat membaca file lokal (`unparsed-text('/etc/passwd')`) dan mengeksfiltrasinya melalui HTTP.|Prosesor XML mendukung transform XSLT; tidak ada daftar izin algoritma Transform|
|**SSRF Berbasis XSLT**|Payload XSLT menggunakan fungsi `document()` atau `unparsed-text()` untuk membuat permintaan HTTP keluar ke layanan internal, memungkinkan SSRF dari endpoint pemrosesan SAML.|Prosesor XSLT mengizinkan fungsi akses jaringan|

### S5-4. SAML XML Injection (Sisi IdP)

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**InResponseTo Attribute Injection**|Request ID SAML (yang tercermin dalam atribut `InResponseTo` dari Response) dibuat untuk keluar dari konteks atribut XML dan menyuntikkan elemen atau atribut XML baru. Karena injeksi terjadi _sebelum_ IdP menandatangani response, konten palsu disertakan dalam signature yang valid.|IdP membangun XML melalui concatenation string tanpa encoding yang tepat|
|**User Attribute Injection**|Atribut yang dikontrol pengguna (nama, email, telepon) disertakan dalam SAML Assertion tanpa encoding XML. Penyerang menetapkan nama tampilan mereka ke nilai seperti `"/>admin<saml:Attribute Name="role"><saml:AttributeValue>admin`, menyuntikkan atribut tambahan atau penetapan role ke dalam Assertion yang ditandatangani.|IdP menggunakan pembuatan XML berbasis template tanpa escaping|
|**Issuer/Audience Injection**|EntityID SP atau nilai lain yang dikontrol SP yang tercermin dalam Assertion dibuat untuk menyuntikkan XML, mengubah batasan audience Assertion atau kondisi lainnya.|IdP mencerminkan nilai yang disediakan SP tanpa sanitasi|

---

## S6. Serangan Konten Assertion dan Tingkat Protokol

Serangan ini menargetkan konten semantik SAML Assertion dan alur protokol daripada lapisan XML atau signature.

### S6-1. Serangan Replay

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Simple Assertion Replay**|SAML Response yang valid ditangkap (melalui inspeksi browser, intersepsi proxy, atau XSS) dan disubmit ulang ke endpoint Assertion Consumer Service (ACS) SP.|SP tidak melacak ID Assertion yang telah dikonsumsi; tidak ada validasi `InResponseTo`|
|**Cross-Session Replay**|Assertion yang ditangkap diputar ulang dari browser, sesi, atau alamat IP yang berbeda. SP tidak mengikat Assertion ke konteks autentikasi asli.|Tidak ada session binding, validasi IP, atau channel binding pada konsumsi Assertion|
|**Window Extension Replay**|Assertion dengan jendela `NotOnOrAfter` yang murah hati (atau tanpa batasan waktu) tetap valid untuk periode yang diperpanjang, memberikan penyerang jendela replay yang besar.|SP menerima assertion dengan jendela validitas yang melebihi beberapa menit; tidak ada penegakan clock yang ketat|

### S6-2. Manipulasi Identitas

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**NameID Spoofing**|Dalam assertion yang unsigned atau diverifikasi lemah, nilai `<saml:NameID>` dimodifikasi langsung untuk menyamar sebagai pengguna target (misalnya mengubah `attacker@corp.com` menjadi `admin@corp.com`).|Bergantung pada bypass signature upstream (S1-S4) atau validasi signature yang hilang|
|**Attribute Value Manipulation**|Atribut role, keanggotaan grup, atau nilai entitlement dalam `<saml:AttributeStatement>` dimodifikasi untuk meningkatkan hak istimewa (misalnya mengubah `role=user` menjadi `role=admin`).|Dikombinasikan dengan bypass signature apa pun; SP mempercayai nilai atribut tanpa pemeriksaan otorisasi sekunder|
|**NameID Format Confusion**|Format NameID diubah (misalnya dari `emailAddress` ke `unspecified`), menyebabkan SP menginterpretasikan NameID secara berbeda atau mencocokkannya terhadap user store yang berbeda.|SP tidak menegakkan format NameID yang diharapkan|

### S6-3. Kegagalan Validasi Recipient dan Audience

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Token Recipient Confusion**|Assertion yang secara sah diterbitkan oleh IdP bersama untuk SP-A disubmit ke SP-B. Jika SP-B tidak memverifikasi bahwa atribut `Recipient` cocok dengan URL ACS-nya sendiri, ia menerima assertion dan mengautentikasi penyerang.|SP tidak memvalidasi `<SubjectConfirmationData Recipient="...">`|
|**Audience Restriction Bypass**|Elemen `<AudienceRestriction>` menentukan SP mana yang harus menerima Assertion. SP yang melewati pemeriksaan ini menerima assertion yang ditujukan untuk relying party lain.|SP tidak memvalidasi `<Audience>` terhadap EntityID-nya sendiri|
|**Destination Mismatch**|Atribut `Destination` pada `<samlp:Response>` harus cocok dengan URL ACS SP. Jika tidak diperiksa, assertion yang ditujukan untuk lingkungan staging dapat diputar ulang terhadap produksi.|SP tidak memvalidasi atribut `Destination`|
|**InResponseTo Bypass**|Atribut `InResponseTo` yang menghubungkan Response ke AuthnRequest asli tidak divalidasi. Ini memungkinkan serangan unsolicited Response di mana penyerang mengirimkan assertion palsu tanpa permintaan autentikasi yang sesuai.|SP menerima SSO yang dimulai dari IdP atau tidak mempertahankan cache request ID|

### S6-4. Eksploitasi RelayState

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Open Redirect melalui RelayState**|Parameter `RelayState` (digunakan untuk mengarahkan ulang pengguna setelah SSO) tidak divalidasi. Penyerang menetapkan RelayState ke URL berbahaya, dan SP mengarahkan pengguna yang terautentikasi ke situs yang dikontrol penyerang untuk phishing kredensial atau pencurian sesi.|SP tidak memiliki daftar izin target redirect RelayState|
|**RelayState Injection**|Nilai RelayState dicerminkan dalam respons SP tanpa sanitasi, memungkinkan XSS atau header injection.|RelayState dicerminkan dalam HTML atau header HTTP tanpa encoding|

### S6-5. Serangan Logout dan Sesi

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Logout Request Forgery**|`<samlp:LogoutRequest>` palsu dikirim ke SP, mengakhiri sesi pengguna lain. Jika signature LogoutRequest tidak diverifikasi, pengguna mana pun dapat me-logout pengguna lain.|Validasi signature LogoutRequest tidak diterapkan|
|**Session Fixation melalui SAML**|Penyerang memulai alur SAML, menangkap sesi pra-autentikasi, dan menipu korban untuk menyelesaikan autentikasi dalam sesi tersebut. Penyerang kemudian menggunakan sesi yang kini terautentikasi.|SP tidak meregenerasi ID sesi setelah konsumsi SAML Assertion|

---

## S7. Serangan Kriptografis dan Infrastruktur

Serangan ini menargetkan infrastruktur kepercayaan yang mendasari SAML daripada pesan individual.

### S7-1. Kompromi dan Pemalsuan Kunci

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Golden SAML**|Penyerang mengkompromikan kunci privat penandatanganan SAML IdP (misalnya dengan mengekstraknya dari server AD FS atau penyimpanan sertifikat token-signing). Dengan kunci privat, penyerang dapat memalsukan SAML assertion mana pun untuk pengguna mana pun ke SP mana pun, mencapai akses persisten yang tidak dapat terdeteksi. Terkait dengan serangan supply chain SolarWinds.|Kompromi kunci penandatanganan IdP (biasanya melalui master key AD FS DKM atau serupa)|
|**Silver SAML**|Alih-alih mengkompromikan kunci IdP, penyerang mendapatkan kunci privat dari sertifikat yang dihasilkan secara eksternal yang diimpor ke cloud IdP (misalnya Microsoft Entra ID). Karena cloud IdP mengizinkan impor sertifikat penandatanganan eksternal, kompromi kunci eksternal — yang mungkin disimpan dengan keamanan lebih rendah — memungkinkan kemampuan pemalsuan assertion yang sama.|Cloud IdP yang dikonfigurasi dengan sertifikat penandatanganan yang dihasilkan secara eksternal; kompromi kunci eksternal|
|**Metadata Key Injection**|Penyerang memodifikasi metadata yang dipublikasikan IdP untuk menyertakan sertifikat penandatanganan mereka sendiri. Jika SP secara otomatis menyegarkan metadata tanpa verifikasi integritas (misalnya tidak ada metadata yang ditandatangani, tidak ada sertifikat yang di-pin), assertion yang selanjutnya ditandatangani dengan kunci penyerang akan diterima.|Pembaruan metadata otomatis melalui saluran tidak aman atau tanpa validasi signature metadata|

### S7-2. Serangan Lifecycle Sertifikat

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Penerimaan Sertifikat Kedaluwarsa**|SP yang tidak menegakkan periode validitas sertifikat menerima assertion yang ditandatangani dengan sertifikat IdP yang kedaluwarsa. Penyerang yang mendapatkan kunci privat lama yang kedaluwarsa dapat memalsukan assertion.|SP tidak memeriksa NotBefore/NotAfter sertifikat|
|**Certificate Rollover Race**|Selama rotasi sertifikat IdP, ada jendela di mana sertifikat lama dan baru sama-sama valid. Jika kunci lama dikompromikan selama atau setelah rollover, SP mungkin masih menerimanya.|SP mempertahankan sertifikat lama dan baru tanpa segera mencabut yang lama|
|**CRL/OCSP Bypass**|SP tidak memeriksa Certificate Revocation List atau status OCSP, menerima assertion yang ditandatangani dengan sertifikat yang dicabut.|Tidak ada pemeriksaan pencabutan yang dikonfigurasi|

---

## S8. Kelemahan Parsing Spesifik Implementasi

Di luar diferensial parser, implementasi library individual mengandung bug parsing unik yang menciptakan kondisi yang dapat dieksploitasi.

### S8-1. Quirk libxml2

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Penyalahgunaan Internal Caching libxml2**|Internal node caching libxml2 dapat dimanipulasi untuk menyebabkan fungsi canonicalization memproses data node yang basi atau salah, menghasilkan nilai digest yang tidak terduga. Ini dieksploitasi untuk melewati autentikasi SAML di GitHub Enterprise. (CVE-2025-23369)|Pemrosesan XML yang didukung libxml2 dalam jalur verifikasi signature|
|**Pewarisan Namespace libxml2**|libxml2 menangani pewarisan namespace secara berbeda dalam kasus tepi tertentu (misalnya undeclaration namespace default `xmlns=""`), menghasilkan output canonicalization yang berbeda dari yang diharapkan oleh prosesor lain.|Pemrosesan libxml2 dan non-libxml2 yang dicampur dalam pipeline yang sama|

### S8-2. Kelemahan Library Spesifik Bahasa

|Subtipe|Mekanisme|Kondisi Utama|
|---|---|---|
|**Bug firstChild xml-crypto**|Library xml-crypto Node.js mengekstrak DigestValue dan SignatureValue menggunakan `firstChild` daripada `textContent`. Komentar XML adalah node anak, sehingga `<!--forged-->real` mengembalikan node komentar (nilai palsu) daripada teks yang digabungkan. (CVE-2025-29775, CVE-2025-29774 — SAMLStorm)|xml-crypto <= 6.0.0|
|**Kegagalan XPath Scope samlify**|Library samlify Node.js tidak memvalidasi dengan benar elemen mana yang dicakup oleh signature dalam verifikasi signature-nya. Penyerang dapat menyematkan signature yang valid (dari metadata atau respons error) dan menempatkan Assertion palsu di luar lingkup signature. (CVE-2025-47949)|samlify < 2.10.0|
|**Quirk REXML ruby-saml**|REXML memperlakukan prefiks `xml:` dan `xmlns` yang dicadangkan sebagai atribut biasa dan menerapkan default ATTLIST yang didefinisikan DOCTYPE, keduanya tidak dilakukan oleh libxml2/Nokogiri. Ini menciptakan pohon dokumen yang berbeda yang memungkinkan serangan namespace confusion dan attribute pollution. (CVE-2025-25291, CVE-2025-25292)|ruby-saml < 1.18.0 dengan REXML|
|**Kegagalan C14N xmlseclibs**|Implementasi canonicalization library PHP xmlseclibs secara diam-diam mengembalikan output kosong pada konstruksi namespace yang cacat tertentu, memungkinkan serangan void canonicalization. (Diperbaiki di 3.1.4)|xmlseclibs < 3.1.4|
|**Bypass Signature node-saml**|Library node-saml gagal memvalidasi dengan benar bahwa signature mencakup assertion spesifik yang sedang diproses, memungkinkan serangan wrapping di mana signature yang valid dari dokumen yang ditandatangani mana pun digunakan kembali. (CVE-2025-54369)|Versi node-saml tertentu dengan validasi referensi yang tidak lengkap|

---

## Pemetaan Skenario Serangan (Sumbu 3)

|Skenario|Arsitektur / Kondisi|Kategori Mutasi Utama|
|---|---|---|
|**Bypass Autentikasi / Peniruan Pengguna**|SP mana pun yang menerima SAML SSO|S1 + S2 + S3 + S4 (bypass signature apa pun dikombinasikan dengan manipulasi NameID)|
|**Eskalasi Hak Istimewa**|SP dengan akses berbasis role dari atribut SAML|S5-4 (injeksi atribut di IdP) atau S6-2 (manipulasi atribut dengan bypass signature)|
|**Pergerakan Lateral Lintas-SP**|Beberapa SP yang berbagi satu IdP|S6-3 (kebingungan recipient token) + S7-1 (Golden/Silver SAML)|
|**Akses Backdoor Persisten**|Lingkungan enterprise dengan AD FS / Entra ID|S7-1 (Golden SAML / Silver SAML — bertahan melewati reset kata sandi dan MFA)|
|**Eksfiltrasi Data melalui XML**|SP dengan parser XML yang rentan|S5-1 (XXE) + S5-3 (XSLT injection) — membaca file lokal dan mengeksfiltrasi melalui saluran OOB|
|**Denial of Service**|Endpoint SAML mana pun yang memproses XML|S5-2 (XML bomb / Billion Laughs) yang menargetkan endpoint ACS atau SLO|
|**Session Hijacking**|SP dengan manajemen sesi yang lemah|S6-1 (replay) + S6-5 (session fixation)|
|**Phishing / Pencurian Kredensial**|SP dengan RelayState yang tidak divalidasi|S6-4 (open redirect) — mengarahkan pengguna terautentikasi ke situs yang dikontrol penyerang|

---

## Pemetaan CVE / Bounty (2024-2025)

|Kombinasi Mutasi|CVE / Kasus|Dampak / Bounty|
|---|---|---|
|S3-1 + S1-4 (Void Canonicalization + Namespace-Assisted Wrapping)|CVE-2025-66568, CVE-2025-66567 (ruby-saml, php-saml, xmlseclibs)|Bypass autentikasi penuh di seluruh ekosistem Ruby/PHP SAML. Mempengaruhi semua ruby-saml < 1.18.0, xmlseclibs < 3.1.4|
|S2-1 + S2-3 (Diferensial Parser + DOCTYPE ATTLIST)|CVE-2025-25291, CVE-2025-25292 (ruby-saml)|CVSS 8.8. Pengambilalihan akun melalui divergensi Nokogiri/REXML. Diperbaiki di ruby-saml 1.12.4, 1.18.0. Berdampak pada GitLab (dipatch 17.9.2, 17.8.5, 17.7.7)|
|S3-3 (DigestValue/SignatureValue Comment Injection — SAMLStorm)|CVE-2025-29775, CVE-2025-29774 (xml-crypto)|Bypass autentikasi kritis dalam ekosistem SAML Node.js. xml-crypto <= 6.0.0, mempengaruhi 500k+ unduhan mingguan (node-saml, samlify, saml2-js)|
|S8-1 (Penyalahgunaan libxml2 Caching)|CVE-2025-23369 (GitHub Enterprise)|Bypass autentikasi SAML di GitHub Enterprise melalui quirk canonicalization libxml2|
|S1-3 (Encrypted Assertion Wrapping)|CVE-2024-9487, CVE-2024-4985 (GitHub Enterprise Server)|Akses administrator situs tanpa autentikasi. Hanya ketika assertion terenkripsi diaktifkan|
|S1-2 + S8-2 (Assertion Wrapping + Kegagalan XPath Scope)|CVE-2025-47949 (samlify)|Bypass autentikasi kritis + peniruan admin. samlify < 2.10.0|
|S4-1 + S6-2 (Signature Hilang + Manipulasi Identitas)|CVE-2024-45409 (ruby-saml / GitLab)|Bypass autentikasi melalui verifikasi signature SAML Response yang tidak tepat. Dieksploitasi di dunia nyata terhadap GitLab|
|S4-3 (Logika Validasi Signature)|CVE-2024-8698 (Keycloak)|Bypass verifikasi signature SAML yang memungkinkan bypass autentikasi dan eskalasi hak istimewa|
|S8-2 (Bypass Signature node-saml)|CVE-2025-54369 (node-saml)|Bypass autentikasi melalui kegagalan validasi lingkup signature|
|S7-1 (Golden SAML)|SolarWinds/SUNBURST (2020, relevansi berkelanjutan)|Akses persisten tingkat negara. Digunakan oleh UNC2452/Nobelium untuk pergerakan lateral di seluruh tenant Microsoft 365|
|S7-1 (Silver SAML)|Penelitian Semperis (2024)|Pemalsuan assertion Entra ID melalui kompromi sertifikat yang dihasilkan secara eksternal. Mengelabui mitigasi Golden SAML|
|S5-1 (XXE melalui SAML)|Oracle Commerce Cloud (2023)|SSRF melalui XXE dalam alur login SAML. Baca file dan akses layanan internal|
|S4-1 (Signature Stripping)|Rocket.Chat HackerOne Report #812064|Bypass autentikasi admin — respons SAML tidak diperiksa untuk keberadaan signature|
|S6-2 + S6-3 (Identitas + Kebingungan Recipient)|CVE-2020-2021 (PAN-OS)|CVSS 10.0. Bypass autentikasi SAML ketika SAML diaktifkan dan "Validate Identity Provider Certificate" dinonaktifkan|

---

## Alat Deteksi

|Alat|Cakupan Target|Teknik Utama|
|---|---|---|
|**SAML Raider** (Ekstensi Burp)|XSW1-8, kloning sertifikat, manipulasi signature|Pengeditan pesan SAML interaktif dengan pemalsuan signature, impor/ekspor sertifikat, pembuatan payload serangan XSW otomatis|
|**SAMLReQuest** (Ekstensi Burp)|Inspeksi pesan SAML|Dekoding otomatis pesan SAML yang terkompresi/terenkode dalam Proxy, Repeater, dan Intercept|
|**XSW Burp Extension** (d0ge/XSW)|Varian XML Signature Wrapping|Pembuatan payload serangan XSW otomatis untuk semua 8 varian klasik|
|**SAMLExtractor**|Penemuan endpoint SP|Mengekstrak URL consumer SAML dari aplikasi target untuk pengujian lebih lanjut|
|**samltool.io** (Online)|Debugging pesan SAML|Mendekode, memeriksa, dan memverifikasi assertion, signature, dan sertifikat SAML|
|**Invicti / Acunetix** (DAST)|XXE, validasi signature, XSW|Pemindaian keamanan SAML otomatis termasuk deteksi XXE dan bypass signature|
|**jwt_tool** (diadaptasi)|Inspeksi token SAML|Meskipun terutama untuk JWT, beberapa mode mendukung analisis assertion SAML|
|**ADFSDump / ADFSRelay**|Ekstraksi kunci Golden SAML|Mengekstrak sertifikat penandatanganan SAML dan kunci dari server AD FS untuk deteksi/pengujian Golden SAML|
|**AADInternals** (PowerShell)|SAML Entra ID/Azure AD|Mengekspor sertifikat penandatanganan SAML, menguji skenario Silver SAML, manipulasi konfigurasi federasi|
|**PayloadsAllTheThings** (Repositori)|Payload referensi|Payload injeksi SAML yang dikurasi: XSW1-8, XXE, XSLT, comment injection, template signature stripping|

---

## Ringkasan: Prinsip-Prinsip Inti

Permukaan mutasi SAML pada dasarnya merupakan konsekuensi dari penggunaan XML — format yang dirancang untuk fleksibilitas struktural maksimum — sebagai pembawa assertion autentikasi yang kritis terhadap keamanan. Seluruh model keamanan bergantung pada satu asumsi: bahwa elemen yang diverifikasi oleh tanda tangan digital adalah _persis_ elemen yang diproses SP untuk keputusan autentikasi. Setiap kategori dalam taksonomi ini mewakili cara berbeda untuk melanggar asumsi tersebut — dengan memindahkan elemen (S1), membuat parser tidak sepakat tentang struktur (S2), merusak canonicalization (S3), melewati langkah verifikasi (S4), menyerang lapisan XML itu sendiri (S5), mengeksploitasi celah tingkat protokol (S6), mengkompromikan infrastruktur kepercayaan (S7), atau mengeksploitasi bug spesifik library (S8).

Patch inkremental secara konsisten gagal menghilangkan ancaman SAML karena setiap library mengimplementasikan tumpukan parsing XML, canonicalization, evaluasi XPath, dan verifikasi signature-nya sendiri. Perbaikan di satu library (misalnya ruby-saml) tidak melindungi library lain (misalnya xml-crypto atau samlify), dan _kelas_ kerentanan yang sama (diferensial parser, void canonicalization, comment injection) muncul kembali secara independen di berbagai bahasa dan ekosistem. Gelombang penelitian 2025 — yang menunjukkan void canonicalization, SAMLStorm comment injection, dan serangan diferensial parser — mempengaruhi ekosistem Ruby, PHP, Node.js, dan Go secara bersamaan, meskipun telah ada penelitian selama beberapa dekade sebelumnya tentang XML signature wrapping pada SAML.

Solusi struktural akan memerlukan salah satu dari: (a) meninggalkan XML demi format token yang lebih sederhana dan tidak ambigu (seperti yang sebagian dicapai OIDC/JWT), (b) mewajibkan implementasi parser XML kanonik tunggal di semua tahap pemrosesan, atau (c) mendesain ulang binding signature-ke-konten agar tidak terpisahkan secara struktural daripada berbasis referensi. Sampai saat itu, SAML tetap menjadi protokol di mana setiap quirk parser XML, setiap pilihan implementasi library, dan setiap kasus tepi canonicalization adalah potensi bypass autentikasi.

---

## Referensi

- PortSwigger Research, "The Fragile Lock: Novel Bypasses For SAML Authentication" (2025) — https://portswigger.net/research/the-fragile-lock
- PortSwigger Research, "SAML Roulette: The Hacker Always Wins" (2025) — https://portswigger.net/research/saml-roulette-the-hacker-always-wins
- WorkOS, "SAMLStorm: Critical Authentication Bypass in xml-crypto and Node.js Libraries" (2025) — https://workos.com/blog/samlstorm
- GitHub Security Lab, "GHSL-2024-329/GHSL-2024-330: Authentication Bypasses in ruby-saml" — https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/
- ProjectDiscovery, "GitHub Enterprise SAML Authentication Bypass (CVE-2024-4985 / CVE-2024-9487)" — https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass
- Semperis, "Meet Silver SAML: Golden SAML in the Cloud" (2024) — https://www.semperis.com/blog/meet-silver-saml/
- NCC Group, "SAML XML Injection" — https://www.nccgroup.com/research-blog/saml-xml-injection/
- WorkOS, "Fun with SAML SSO Vulnerabilities and Footguns" — https://workos.com/blog/fun-with-saml-sso-vulnerabilities-and-footguns
- WorkOS, "Common SAML Security Vulnerabilities" — https://workos.com/guide/common-saml-security-vulnerabilities
- NetSPI, "Attacking SSO: Common SAML Vulnerabilities and Ways to Find Them" — https://www.netspi.com/blog/technical-blog/web-application-penetration-testing/attacking-sso-common-saml-vulnerabilities-ways-find/
- Endor Labs, "CVE-2025-47949: Samlify Signature Wrapping" — https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass
- Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012) — https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
- OWASP, "SAML Security Cheat Sheet" — https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- SwissKyRepo, "PayloadsAllTheThings — SAML Injection" — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SAML%20Injection
- CSO Online, "SAML Authentication Broken Almost Beyond Repair" (2025) — https://www.csoonline.com/article/4105030/saml-authentication-broken-almost-beyond-repair.html
- Google Project Zero: "Exploiting Java's XML Signature Verification" (2022) — Penyalahgunaan transform XSLT, injeksi XPath, dan bug spesifik implementasi dalam API `javax.xml.crypto` JDK: https://googleprojectzero.blogspot.com/2022/11/gregor-samsa-exploiting-java-xml.html
- "Hacking the Cloud with SAML" (2022) — Kerentanan autentikasi SAML dalam eksploitasi infrastruktur cloud

---

_Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan._