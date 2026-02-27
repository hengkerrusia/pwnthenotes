---
title: Expression Language Injection
description: 
---

## Struktur Klasifikasi

Expression Language (EL) Injection terjadi ketika data yang dikendalikan pengguna mengalir ke dalam interpreter ekspresi tanpa sanitasi yang memadai, memungkinkan penyerang memanipulasi alur eksekusi yang dimaksud. Taksonomi ini mengorganisir mutasi EL injection di tiga sumbu ortogonal:

**Sumbu 1: Injection Vector** — Komponen struktural atau fitur bahasa yang dieksploitasi (§1-§8)
**Sumbu 2: Bypass Mechanism** — Teknik penghindaran pertahanan yang digunakan
**Sumbu 3: Attack Impact** — Hasil eksploitasi dan konsekuensi keamanan

Taksonomi ini mencakup semua expression language utama yang digunakan dalam aplikasi enterprise: Spring Expression Language (SpEL), JSP Expression Language (EL/JSTL), Object-Graph Navigation Language (OGNL), MVFLEX Expression Language (MVEL), dan template engine (Thymeleaf, Freemarker, Velocity).

### Core Bypass Mechanism (Sumbu 2)

Serangan EL injection menggunakan enam mekanisme bypass fundamental yang melintasi semua injection vector:

| Tipe Bypass | Mekanisme | Penerapan |
|------------|-----------|---------------|
| **Sandbox Escape** | Menghindari security manager, akses metode terbatas, atau konteks evaluasi ekspresi | Semua bahasa dengan sandboxing |
| **Filter/WAF Bypass** | Menghindari deteksi berbasis pola melalui encoding, obfuscation, atau sintaks alternatif | Universal |
| **Context Escape** | Keluar dari scope ekspresi yang dimaksud ke konteks eksekusi yang lebih luas | Template engine, Spring tags |
| **Parser Differential** | Mengeksploitasi perbedaan antara validator dan interpreter | Sistem multi-komponen |
| **Double Evaluation** | Memicu beberapa pass resolusi ekspresi | Spring pre-3.0.6, OGNL |
| **Type Confusion** | Menyalahgunakan konversi tipe implisit atau mekanisme casting | Bahasa bertipe statis (Java) |

---

## §1. Manipulasi Sintaks Ekspresi

Mengeksploitasi variasi dalam interpretasi delimiter, nesting ekspresi, dan waktu evaluasi untuk menyuntikkan ekspresi berbahaya.

### §1-1. Variasi Delimiter

Expression language yang berbeda menggunakan delimiter yang berbeda, dan framework mungkin mendukung beberapa sintaks secara bersamaan.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Immediate Evaluation (`${}`)** | Sintaks immediate JSP/JSTL dievaluasi saat rendering halaman | Digunakan di JSP, Spring, JSTL |
| **Deferred Evaluation (`#{}`)** | Sintaks deferred JSF/Spring dievaluasi oleh lifecycle framework | Digunakan di JSF, Spring WebFlow |
| **Thymeleaf Inline (`[[...]]`)** | Text inlining Thymeleaf meng-escape HTML secara default tetapi mengevaluasi ekspresi | Thymeleaf 3.x+ |
| **Velocity Reference (`$var`)** | Variabel template Velocity tanpa method invocation | Template Velocity |
| **Freemarker Interpolation (`${...}`)** | Sintaks ekspresi Freemarker dengan built-in function | Template Freemarker |

**Contoh**: `${7*7}` vs `#{7*7}` — keduanya dievaluasi menjadi `49` tetapi dipicu pada fase lifecycle framework yang berbeda.

### §1-2. Nested Expression Injection

Menyuntikkan ekspresi dalam string yang mengalami beberapa pass resolusi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Double Resolution** | Ekspresi yang disematkan dalam string yang sendirinya dievaluasi sebagai ekspresi | Spring <3.0.6, konteks OGNL tertentu |
| **Template-in-Template** | Ekspresi yang disuntikkan ke variabel template yang nantinya dirender | Nested template rendering |
| **Constraint Violation Message** | Ekspresi yang disuntikkan ke template pesan error validasi | Spring Validation dengan input pengguna dalam pesan |

**Eksploitasi CVE-2022-22963**: Spring Cloud Function mengevaluasi header HTTP sebagai ekspresi SpEL. Payload: `T(java.lang.Runtime).getRuntime().exec("whoami")` disuntikkan via header `spring.cloud.function.routing-expression`.

### §1-3. Polyglot Injection

Payload tunggal yang valid di beberapa expression language untuk fingerprinting atau eksploitasi universal.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Mathematical Polyglot** | `{{7*7}}${7*7}<%= 7*7 %>#{7*7}` memicu respons berbeda per engine | Engine fingerprinting |
| **String Manipulation Polyglot** | `${'zkz'.toString().replace('k','x')}` bekerja di JSP EL, SpEL, OGNL | Deteksi RCE lintas bahasa |
| **Universal Detection Probe** | Payload yang diinterpretasikan oleh 40+ template engine (tabel Hackmanit) | Pemindaian kerentanan komprehensif |

---

## §2. Eksploitasi Fitur Bahasa

Memanfaatkan kapabilitas expression language bawaan seperti method invocation, akses properti, dan operator.

### §2-1. Method Invocation

Spesifikasi EL 2.2+ memungkinkan pemanggilan metode langsung pada objek, memungkinkan eksekusi kode arbitrer.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Direct Runtime Execution** | `T(java.lang.Runtime).getRuntime().exec('cmd')` (sintaks SpEL) | SpEL, akses metode penuh |
| **ProcessBuilder Invocation** | `new java.lang.ProcessBuilder(['cmd','/c','whoami']).start()` | EL berbasis Java dengan akses constructor |
| **ScriptEngineManager Execution** | `Class.forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval('...')` | JavaScript engine tersedia |
| **Static Method Access** | `T(java.lang.System).getProperty('user.dir')` | Operator T() SpEL untuk referensi class statis |

**Contoh**: JSP EL `${pageContext.request.getSession().setAttribute("admin",true)}` memanipulasi status session.

### §2-2. Property Access Chain

Menelusuri object graph untuk mencapai metode berbahaya atau data sensitif.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Implicit Object Access** | `${pageContext}`, `${applicationScope}`, `${sessionScope}` mengekspos state internal | JSP EL <2.2 |
| **Class Navigation** | `${''.getClass().forName('java.lang.Runtime')}` mengakses class arbitrer | Reflection tersedia |
| **Bean Traversal** | `@myBean.dangerousMethod()` mengakses Spring-managed bean | SpEL dengan akses bean |
| **Nested Property Chains** | `${user.account.permissions.admin}` — rantai panjang untuk mencapai properti terbatas | Model objek kompleks |

### §2-3. Penyalahgunaan Operator dan Built-in Function

Memanfaatkan operator dan fungsi khusus bahasa untuk information disclosure atau eksekusi.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Ternary Conditional Exploitation** | `${condition ? exec('cmd') : ''}` menyembunyikan eksekusi dalam kondisional | Operator kondisional didukung |
| **Elvis Operator Chaining** | `${var ?: exec('fallback')}` memicu eksekusi pada nilai null | Operator bergaya Groovy (SpEL) |
| **String Functions** | `concat()`, `substring()`, `replace()` untuk data exfiltration | Semua implementasi EL |
| **Collection Operators** | Operator projection/selection OGNL `collection.{? #this.condition}` | Khusus OGNL |

---

## §3. Type System Abuse (Reflection & Class Loading)

Mengeksploitasi reflection API Java dan dynamic class loading untuk mem-bypass pembatasan dan mencapai eksekusi.

### §3-1. Reflection-Based Execution

Menggunakan reflection untuk mengakses metode terbatas atau menghindari sandboxing.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **getClass() Chain** | `${''.getClass().forName('java.lang.Runtime').getMethods()[x]}` | Reflection tidak diblokir |
| **getDeclaredMethod Invocation** | `.getDeclaredMethod('getRuntime').invoke(null)` mem-bypass visibilitas | Akses metode private diperlukan |
| **Field Manipulation** | `.getDeclaredField('field').setAccessible(true).set()` memodifikasi field protected | Akses level field |
| **Constructor Access** | `.getDeclaredConstructor().newInstance()` menginstansiasi class arbitrer | Instansiasi tidak terbatas |

**Payload CVE-2024-51466**: Eksploitasi IBM Cognos via `${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('command')}`

### §3-2. ClassLoader Manipulation

Mem-bypass pembatasan OGNL 3.x+ yang memblokir `ClassLoader.loadClass()`.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Thread ClassLoader Access** | `Thread.currentThread().getContextClassLoader().loadClass()` | Referensi ClassLoader tidak langsung |
| **forName() Alternative** | `Class.forName('ClassName')` sebagai pengganti `ClassLoader.loadClass()` | Mem-bypass pembatasan OGNL (CVE-2023-22527) |
| **URLClassLoader Remote Loading** | Memuat class berbahaya dari URL yang dikontrol penyerang | Akses jaringan tersedia |

**Bypass Confluence CVE-2023-22527**: Menggunakan `Class.forName()` via Java reflection API alih-alih `ClassLoader.loadClass()` yang terbatas.

### §3-3. Type Conversion Exploitation

Menyalahgunakan mekanisme type casting dan konversi implisit.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **String-to-Class Coercion** | Framework secara otomatis mengkonversi string ke objek Class | Spring parameter binding |
| **Primitive Wrapper Confusion** | Perbedaan `Integer.TYPE` vs `Integer.class` | Edge case type system |
| **Array Type Casting** | Casting ke `Object[]` untuk mengakses array yang dilindungi | Bypass keamanan tipe |

---

## §4. Teknik Encoding & Obfuscation

Menghindari character filter, WAF, dan blacklist melalui representasi alternatif.

### §4-1. Character Construction

Membangun string tanpa literal quote dengan membentuk karakter secara terprogram.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **ASCII Code Point Conversion** | `true.toString().charAt(0).toChars(67)[0].toString()` menghasilkan `'C'` | Mem-bypass blacklist quote |
| **Concatenation Chains** | Metode `.concat()` untuk membangun string dari karakter individual | Filter quote aktif |
| **Boolean String Extraction** | `true.toString().charAt(0)` menghasilkan `'t'`, `false.toString()` menghasilkan `'f'` | Tidak ada string literal yang diizinkan |

**WAF Bypass Pulse Security**: Membangun `"java.lang.Runtime"` sebagai rantai 16 karakter via kode ASCII untuk mem-bypass filter quote dan mencapai RCE tanpa string.

### §4-2. Unicode dan Hex Encoding

Merepresentasikan karakter menggunakan escape sequence.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Hex Escapes** | `\x61` merepresentasikan `'a'` | Bahasa mendukung hex escape |
| **Unicode Escapes** | `\u003a` merepresentasikan `':'` | String literal Java |
| **Octal Escapes** | `\141` merepresentasikan `'a'` | Dukungan encoding legacy |
| **Mixed Encoding** | Menggabungkan URL, Unicode, hex untuk menghindari multi-format decoder | Mem-bypass WAF modern |

**Bypass Filter attr Thymeleaf**: Mengganti underscore dengan hex `\x5f` yang dirender sebagai `_` saat pemrosesan template.

### §4-3. Substitusi Karakter Khusus

Mengganti karakter yang difilter dengan padanan fungsional.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **$IFS untuk Spasi** | Internal field separator Bash menggantikan spasi dalam argumen perintah | Konteks eksekusi perintah Linux |
| **Bracket Notation** | `object['property']` sebagai pengganti `object.property` mem-bypass filter titik | Sintaks bergaya Jinja2, JavaScript |
| **Substitusi Filter attr** | `{{''|attr('__class__')}}` Jinja2 sebagai pengganti `{{''.__class__}}` | Karakter titik diblokir |
| **Format Function Injection** | `{{"%s"|format("value")}}` menggabungkan tanpa operator eksplisit | Penggabungan string diblokir |

---

## §5. Manipulasi Context Boundary

Keluar dari scope ekspresi yang dimaksud untuk menyuntikkan ke konteks eksekusi yang lebih luas.

### §5-1. Template Context Escape

Keluar dari konteks data ke konteks kode dalam template engine.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Spring Tag Double Resolution** | Spring <3.0.6 mengevaluasi JSP tag dua kali: `?msg=${param.test}&test=${payload}` | Versi Spring legacy |
| **Message Tag Injection** | `<spring:message code="${param.msg}"/>` mengevaluasi input pengguna | Spring message tag |
| **Eval Tag Direct Execution** | `<spring:eval expression="${param.vuln}"/>` secara eksplisit mengevaluasi ekspresi | Spring eval tag di JSP |

**Spring Double Resolution**: Menetapkan `springJspExpressionSupport=false` di web.xml menonaktifkan perilaku rentan.

### §5-2. Error Message Injection

Menyuntikkan ekspresi ke dalam konteks error handling dan logging.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Constraint Violation Template** | `context.buildConstraintViolationWithTemplate(userInput)` dalam Bean Validation | Spring Validation tanpa sanitasi |
| **Exception Message Interpolation** | Pesan error yang mengandung `${...}` dievaluasi | Logging framework dengan dukungan EL |
| **Struts Exception Handling** | Header Content-Type OGNL injection dipicu dalam error handler (CVE-2017-5638) | Error Jakarta Multipart parser |

**CVE-2017-5638 (Pelanggaran Data Equifax)**: Header Content-Type yang salah format `%{(#cmd='whoami')(...)}` dieksekusi saat pembangunan pesan exception.

### §5-3. HTTP Header dan Parameter Injection

Menyuntikkan ekspresi via metadata HTTP yang dievaluasi oleh framework.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Routing Expression Header** | `spring.cloud.function.routing-expression: T(Runtime).exec()` | Spring Cloud Function |
| **Content-Type OGNL** | OGNL berbahaya dalam header Content-Type saat multipart parsing | Versi Apache Struts yang rentan |
| **Accept-Language Exploitation** | Parameter pemilihan bahasa dievaluasi sebagai ekspresi | Framework i18n dengan EL |

**CVE-2022-22963**: Spring Cloud Function merutekan permintaan berdasarkan ekspresi SpEL dalam header HTTP, memungkinkan RCE.

---

## §6. Akses Implicit Object & Scope

Mengakses implicit object dan scope yang disediakan framework untuk mengungkap informasi atau mengeskalasi privilese.

### §6-1. Implicit Object JSP

Objek JSP standar yang terekspos ke ekspresi EL (pre-EL 2.2).

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **pageContext Exposure** | `${pageContext.request.getSession()}` mengakses session | Lingkungan JSP |
| **Session Scope Access** | `${sessionScope.user.password}` membaca atribut session | Data sensitif dalam session |
| **Application Scope Access** | `${applicationScope.config}` mengekspos konfigurasi seluruh aplikasi | Secret dalam application scope |
| **Request Parameter Injection** | `${param.admin}` membaca query parameter, `${paramValues}` untuk array | Parameter yang dikontrol pengguna |

**Information Disclosure**: Kebocoran informasi internal PayPal via traversal implicit object dalam konteks EL.

### §6-2. Scope Khusus Spring

Scope dan bean tambahan yang terekspos dalam Spring Framework.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Bean Access** | `@beanName` atau `@myService.method()` memanggil Spring bean | SpEL dengan bean resolution |
| **Environment Property Access** | `@environment.getProperty('secret.key')` membaca konfigurasi | Spring environment dapat diakses |
| **WebFlow Scope Pollution** | Mengakses flow dan conversation scope dalam Spring WebFlow | Scope khusus WebFlow |

**CVE-2025-41253**: Spring Cloud Gateway membocorkan variabel lingkungan via SpEL injection ketika actuator endpoint salah konfigurasi.

### §6-3. Variabel Context OGNL

Objek context khusus OGNL dan manipulasi value stack.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **`#_memberAccess Overwrite`** | Menimpa objek keamanan untuk mem-bypass sandbox (CVE-2020-17530) | OGNL tanpa sandboxing yang tepat |
| **Value Stack Access** | `#context['valueStack']` mengakses konteks action Struts | Framework Apache Struts |
| **OgnlContext Manipulation** | Manipulasi langsung konteks evaluasi OGNL | Integrasi OGNL mendalam |

---

## §7. Gadget Chain Construction

Merangkai beberapa teknik atau memanfaatkan metode "gadget" yang ada untuk mencapai eksploitasi kompleks.

### §7-1. Deserialization Gadget Chain

Menggunakan expression language untuk memicu gadget deserialisasi Java (kelas kerentanan crossover).

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Integrasi ysoserial** | Memanggil gadget deserialisasi via EL reflection | Commons Collections, Spring, dll. ada di classpath |
| **Remote Gadget Loading** | Memuat class gadget dari URL penyerang via URLClassLoader | Network egress diizinkan |

---

## §8. Mutasi Khusus Framework

Fitur dan kerentanan unik dalam implementasi expression language tertentu.

### §8-1. Kekhususan Spring SpEL

Fitur unik Spring Expression Language.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Operator T()** | `T(java.lang.System)` mereferensikan class statis | Sintaks khusus SpEL |
| **@Value Annotation Injection** | `@Value("${user.input}")` dievaluasi sebagai SpEL jika salah format | Spring configuration injection |
| **@Query SpEL Expressions** | Spring Data JPA `@Query` dengan SpEL `#{#entityName}` | Konstruksi query dinamis |
| **SimpleEvaluationContext Bypass** | Mengeksploitasi ReDoS bahkan dalam konteks terbatas | Keterbatasan sandbox SpEL |

### §8-2. Kekhususan OGNL (Struts/Confluence)

Projection, selection, dan double evaluation OGNL.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Projection Operator** | `collection.{property}` mengekstrak properti | Operasi koleksi OGNL |
| **Selection Operator** | `collection.{? #this.condition}` memfilter koleksi | Lambda expression OGNL |
| **Double OGNL Evaluation** | CVE-2020-17530 mengevaluasi ekspresi dua kali | Versi Struts yang rentan |
| **Namespace Redirect Injection** | Namespace `action:` dengan OGNL injection | Penanganan namespace Struts |

### §8-3. Kekhususan MVEL

Fitur MVFLEX Expression Language (Apache Unomi).

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Inline Collections** | Sintaks `['item1','item2']` untuk konstruksi list | Sintaks khusus MVEL |
| **Property Navigation** | Akses properti bersarang dengan navigasi null-safe otomatis | Fitur kenyamanan MVEL |
| **Script Import** | `import java.lang.Runtime; Runtime.exec()` | Mode evaluasi script MVEL |

**CVE-2020-13942**: Apache Unomi MVEL RCE via evaluasi ekspresi yang tidak disanitasi dalam kondisi profil.

### §8-4. Kekhususan Template Engine

Eksploitasi unik Freemarker, Velocity, Thymeleaf.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Freemarker Execute** | `<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("whoami")}` | Built-in Freemarker |
| **Velocity ClassTool** | `#set($class=$class.forName('Runtime'))` | Velocity dengan ClassTool aktif |
| **Thymeleaf Preprocessing** | `__${expression}__` diproses sebelum evaluasi utama | Preprocessing Thymeleaf 3.x |
| **Filter attr/format Jinja2** | `{{''|attr('__class__')}}` mem-bypass filter titik | Python Jinja2 (disertakan untuk perbandingan) |

---

## Pemetaan Attack Impact (Sumbu 3)

| Skenario Dampak | Mekanisme | Kategori Mutasi Utama |
|-----------------|-----------|---------------------------|
| **Information Disclosure** | Mengakses implicit object, variabel lingkungan, konfigurasi | §6 + §2-2 |
| **Remote Code Execution (RCE)** | Method invocation, reflection, ProcessBuilder | §2-1 + §3-1 + §5-3 |
| **Sandbox Escape** | Bypass berbasis reflection terhadap security manager dan konteks terbatas | §3-1 + §3-2 + §8-1 |
| **Authentication/Authorization Bypass** | Manipulasi session, modifikasi atribut role | §2-2 + §6-1 |
| **Configuration Manipulation** | Memodifikasi variabel application-scoped dan Spring bean | §6-2 + §2-2 |
| **Denial of Service (DoS)** | Penipisan resource via ReDoS atau infinite loop | §2-3 + §8-1 |
| **Data Exfiltration** | Mengekstrak data sensitif melalui pesan error atau kanal HTTP | §5-2 + §6 |

---

## Pemetaan CVE / Bounty (2016-2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|---------------------|-----------|----------------|
| §5-3 + §2-1 | CVE-2025-41253 (Spring Cloud Gateway) | HIGH. Ekspos variabel lingkungan via SpEL di route actuator |
| §5-2 + §3-1 | CVE-2024-51466 (IBM Cognos) | CRITICAL. RCE via EL injection berbasis reflection dalam pesan validasi |
| §3-2 + §8-2 | CVE-2023-22527 (Confluence) | CVSS 10.0 CRITICAL. RCE OGNL tanpa autentikasi via bypass Class.forName() |
| §5-3 + §2-1 | CVE-2022-22963 (Spring Cloud Function) | CRITICAL. RCE SpEL via header routing-expression, dieksploitasi di lapangan |
| §1-2 + §2-1 | CVE-2022-22980 (Spring Data MongoDB) | HIGH. SpEL injection dalam query derivation |
| §5-2 + §6-3 + §8-2 | CVE-2022-26134 (Confluence) | CRITICAL. OGNL injection dalam error handling |
| §5-2 + §6-3 | CVE-2021-26084 (Confluence) | CRITICAL. OGNL injection via WebWork |
| §8-2 | CVE-2020-17530 (Struts) | CRITICAL. Double OGNL evaluation via manipulasi #_memberAccess |
| §8-3 | CVE-2020-13942 (Apache Unomi) | CRITICAL. MVEL RCE dalam evaluasi kondisi profil |
| §5-3 + §8-2 | CVE-2017-5638 (Struts/Equifax) | CRITICAL. Pelanggaran data $50M+. OGNL injection via header Content-Type |
| §4-1 + WAF bypass | Studi Kasus Pulse Security | N/A. WAF bypass via konstruksi karakter ASCII mencapai RCE |
| §1-3 + §3-2 | Nuxeo/JBoss Seam (Amazon, 2018) | RCE tanpa autentikasi via bypass ACL path parameter titik koma → double EL evaluation `actionMethod` Seam → bypass blacklist menggunakan array notation (`""["class"]` alih-alih `.getClass()`) |
| §6-1 | PayPal Disclosure (tulisan Medium) | Bug bounty. Information disclosure internal via akses implicit object |

---

## Matriks Detection Tool

| Tool | Cakupan Target | Teknik Inti |
|------|-------------|---------------|
| **SSTImap** (Ofensif) | Deteksi & eksploitasi SSTI/EL komprehensif | Polyglot injection, pembuatan payload RCE otomatis |
| **Tplmap** (Ofensif) | Scanner SSTI legacy untuk beberapa template engine | Fingerprinting + pengujian akses file system |
| **BountyIt** (Ofensif) | Fuzzer multi-kerentanan (SSTI, XSS, LFI, RCE) | Deteksi delta content-length + verifikasi signature |
| **PayloadsAllTheThings** (Referensi) | Repositori payload komunitas | Koleksi payload yang dikurasi berdasarkan bahasa/framework |
| **Hackmanit Template Injection Table** (Referensi) | Tabel respons polyglot interaktif untuk 44 engine | Fingerprinting engine sistematis via polyglot |
| **Burp Extensions** (Ofensif) | Berbagai plugin deteksi SSTI | Pemindaian pasif & aktif dengan Collaborator |
| **Semgrep Rules** (Defensif) | Analisis statis untuk pola EL yang rentan | Deteksi tingkat kode pada evaluasi ekspresi yang tidak aman |
| **HTTP-Normalizer** (Defensif) | Parsing HTTP sesuai RFC untuk menghilangkan perbedaan | Pencegahan parser differential |
| **Spring Security Hardening** (Defensif) | Menonaktifkan double resolution, membatasi akses bean | Sandboxing tingkat framework |

---

## Ringkasan: Prinsip Inti

### Kerentanan Fundamental

Expression Language Injection ada karena adanya **ketegangan fundamental dalam desain EL**: bahasa-bahasa ini harus cukup kuat agar developer dapat mengakses state aplikasi dan memanggil metode, namun cukup aman untuk menangani input pengguna. Isu intinya adalah **pemisahan konteks kode dan data yang tidak memadai**. Ketika string yang dikendalikan pengguna mengalir ke interpreter ekspresi tanpa penegakan tipe yang ketat atau isolasi konteks, eksekusi kode arbitrer menjadi mungkin.

Kelas kerentanan ini bertahan selama beberapa dekade karena:

1. **Kepercayaan Implisit**: Framework secara implisit mempercayai input ekspresi, mengasumsikan developer tidak akan pernah meneruskan data pengguna langsung ke interpreter
2. **Kekayaan Fitur**: Method invocation EL 2.2+, reflection API, dan operator tipe memungkinkan komputasi Turing-complete
3. **Proliferasi Konteks**: Ekspresi muncul dalam berbagai konteks (template, anotasi, pesan validasi, header) membuat penyaringan komprehensif tidak praktis
4. **Evaluasi Berlapis**: Double resolution, preprocessing, dan evaluasi multi-tahap menciptakan blind spot bagi validator

### Mengapa Patch Inkremental Gagal

Blacklist dan character filter secara sistematis dikalahkan oleh:
- **Keragaman encoding**: Unicode, hex, oktal, konstruksi ASCII mem-bypass deteksi signature
- **Fleksibilitas sintaks**: Beberapa representasi ekuivalen (notasi bracket vs titik, T() vs Class.forName())
- **Ketersediaan gadget**: Reflection dan API ClassLoader menyediakan primitif RCE universal terlepas dari metode yang diblokir
- **Parser differential**: Validator dan interpreter mem-parse ekspresi secara berbeda, memungkinkan smuggling

CVE historis menunjukkan pola ini: CVE-2017-5638 (Struts) diikuti oleh CVE-2017-9791, CVE-2019-0230, CVE-2020-17530 — masing-masing mem-bypass mitigasi sebelumnya melalui konteks injeksi baru atau teknik encoding.

### Solusi Struktural

Satu-satunya pertahanan yang andal adalah **isolasi arsitektur**:

1. **Jangan pernah mengevaluasi input pengguna sebagai ekspresi**: Gunakan parameterized query, nilai yang di-allow-list, dan data binding bertipe-aman alih-alih evaluasi ekspresi berbasis string
2. **Output encoding yang context-aware**: Jika ekspresi tidak dapat dihindari, gunakan framework dengan konteks evaluasi yang aman (Spring's `SimpleEvaluationContext`) dan escape data pengguna dengan benar sebelum injeksi
3. **Prinsip least privilege**: Nonaktifkan reflection, class loading, dan akses metode statis dalam konteks ekspresi kecuali secara eksplisit diperlukan
4. **Validasi input di batas sistem**: Validasi tipe dan struktur data di titik masuk sistem sebelum mencapai layer ekspresi apapun
5. **Defense in depth**: Gabungkan sandboxing tingkat framework (double resolution dinonaktifkan, akses bean dibatasi) dengan proteksi runtime (security manager, kontrol network egress)

**Gold Standard**: Perpindahan Spring Framework dari `StandardEvaluationContext` yang permisif ke `SimpleEvaluationContext` yang restriktif, meskipun ini pun dapat di-bypass oleh ReDoS — menunjukkan bahwa keamanan sejati memerlukan eliminasi input pengguna dari evaluasi ekspresi sepenuhnya.

---

*Dokumen ini dibuat untuk keperluan riset keamanan defensif dan pemahaman kerentanan.*

---

## Referensi

### Advisori CVE
- [Spring Cloud Gateway CVE-2025-41253](https://securityonline.info/spring-patches-two-flaws-spel-injection-cve-2025-41253-leaks-secrets-stomp-csrf-bypasses-websocket-security/)
- [Confluence CVE-2023-22527 OGNL Injection](https://www.picussecurity.com/resource/blog/cve-2023-22527-another-ognl-injection-leads-to-rce-in-atlassian-confluence)
- [Spring Cloud Function CVE-2022-22963](https://www.akamai.com/blog/security/spring-cloud-function)
- [Apache Struts CVE-2017-5638 (Pelanggaran Data Equifax)](https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html)
- [Apache Struts CVE-2020-17530](https://blog.qualys.com/vulnerabilities-threat-research/2021/09/21/apache-struts-2-double-ognl-evaluation-vulnerability-cve-2020-17530)
- [Apache Unomi CVE-2020-13942 MVEL RCE](https://www.invicti.com/web-application-vulnerabilities/apache-unomi-mvel-rce-cve-2020-13942)

### Makalah Teknis dan Presentasi
- [Expression Language Injection - Minded Security (Stefano Di Paola)](https://mindedsecurity.com/wp-content/uploads/2020/10/ExpressionLanguageInjection.pdf)
- [Server-Side Template Injection: RCE for the Modern Web App - BlackHat 2015](https://blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [Remote Code Execution with EL Injection Vulnerabilities - Exploit-DB](https://www.exploit-db.com/docs/english/46303-remote-code-execution-with-el-injection-vulnerabilities.pdf)

### Sumber Daya Praktisi
- [OWASP Expression Language Injection](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
- [PortSwigger Expression Language Injection](https://portswigger.net/kb/issues/00100f20_expression-language-injection)
- [PayloadsAllTheThings - Server Side Template Injection (Java)](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/Java/)
- [EL Injection WAF Bypass - No Strings Attached - Pulse Security](https://pulsesecurity.co.nz/articles/EL-Injection-WAF-Bypass)
- [Leveraging SpEL Injection for RCE](https://xen0vas.github.io/Leveraging-the-SpEL-Injection-Vulnerability-to-get-RCE/)
- [Hackmanit Template Injection Vulnerabilities](https://hackmanit.de/en/blog-en/178-template-injection-vulnerabilities-understand-detect-identify/)

### Tools
- [SSTImap - Automatic SSTI Detection Tool](https://github.com/vladko312/SSTImap)
- [Tplmap - Server-Side Template Injection Detection and Exploitation](https://github.com/epinna/tplmap)
- [PayloadsAllTheThings GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)

### Riset Terbaru dan Posting Blog
- [Jinja2 Template Injection Filter Bypasses](https://0day.work/jinja2-template-injection-filter-bypasses/)
- [Obfuscating Attacks Using Encodings - PortSwigger](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)
- [Template Injection Workshop - GoSecure](https://gosecure.github.io/template-injection-workshop/)
- [InstaTunnel - Expression Language Injection: When ${} Leads to Remote](https://instatunnel.my/blog/expression-language-injection-when-becomes-your-worst-nightmare)