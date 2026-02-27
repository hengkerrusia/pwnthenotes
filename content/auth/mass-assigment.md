---
title: Mass Assigment
---
# Taksonomi Mutasi/Variasi Mass Assignment / Data Binding

---

## Struktur Klasifikasi

Mass assignment adalah kelas kerentanan yang muncul ketika sebuah aplikasi secara otomatis mengikat input yang dikontrol pengguna ke properti objek internal tanpa pembatasan yang memadai. Istilah ini berasal dari framework web yang memetakan parameter HTTP langsung ke atribut model — namun masalah mendasarnya jauh lebih umum dari itu. Di mana pun sebuah sistem menerima input terstruktur dan menggunakannya untuk mengisi object graph, risiko over-binding itu ada: penyerang menyuplai properti yang tidak pernah dimaksudkan developer untuk bisa diset dari luar.

Taksonomi ini mengorganisir seluruh ruang mutasi berdasarkan tiga sumbu. **Sumbu 1 (Binding Target)** mengklasifikasikan teknik berdasarkan *komponen struktural mana* dari object graph yang berhasil dijangkau penyerang. Ini adalah sumbu pengorganisasian utama. **Sumbu 2 (Mekanisme Bypass)** menjelaskan *bagaimana* penyerang menghindari perlindungan yang ada — celah pada denylist, misconfigurasi allowlist, traversal rantai properti, perbedaan format. **Sumbu 3 (Skenario Dampak)** memetakan teknik ke *konsekuensi* yang dicapai: privilege escalation, remote code execution, data tampering, atau authentication bypass.

Wawasan kritis yang menghubungkan mass assignment "klasik" (menimpa `isAdmin`) dengan hasil yang bersifat katastrofik seperti RCE adalah **nested property traversal**. Ketika mekanisme binding mengikuti object graph secara rekursif, parameter permintaan seperti `class.module.classLoader.resources.context.parent.pipeline.first.pattern` tidak sekadar menyetel field yang datar — melainkan menavigasi jauh ke dalam struktur objek internal runtime. Pemahaman ini, yang menjadi inti penelitian tentang ketidakamanan data binding pada framework seperti Spring, Grails, dan Struts, membingkai ulang mass assignment bukan sebagai bug validasi input sederhana, melainkan sebagai **primitif navigasi object graph** dengan spektrum keparahan mulai dari manipulasi atribut hingga kompromi sistem penuh.

### Ringkasan Sumbu 2: Jenis Mekanisme Bypass

| Tipe | Deskripsi |
|------|-----------|
| **Denylist Gap** | Perlindungan menyebutkan properti-properti yang diketahui berbahaya, tetapi melewatkan jalur baru (misalnya properti `module` di JDK9 yang melewati blokir `class.classLoader`) |
| **Allowlist Misconfiguration** | Allowlist ada tetapi terlalu permisif, tidak lengkap, atau defaultnya terbuka |
| **Property Chain Traversal** | Objek-objek perantara menciptakan jalur navigasi alternatif ke target yang diblokir |
| **Format/Encoding Differential** | Content type yang berbeda (JSON nesting, dot notation, bracket syntax) diparsing secara berbeda oleh logika binding |
| **Schema/Introspection Exposure** | Skema API atau introspection mengungkapkan nama field internal, memungkinkan over-binding yang tepat sasaran |
| **Language Metaclass Access** | Fitur metaprogramming di level bahasa (`__proto__`, `constructor`, `getClass()`) menyediakan titik masuk universal |

### Mekanisme Fundamental

Setiap implementasi data binding memiliki pola yang sama:

```
Parameter HTTP Request → Parser → Property Resolver → Object Graph Setter
```

Attack surface ada di setiap transisi: parser mungkin menginterpretasikan konstruksi spesifik-format (JSON nesting, ekspansi dot-notation); property resolver mungkin mengikuti referensi objek secara rekursif; dan setter mungkin tidak memvalidasi apakah properti target seharusnya bisa ditulis dari luar. Ketika framework mengutamakan kenyamanan developer daripada keamanan secara default — membuat semua properti dapat di-bind kecuali secara eksplisit dibatasi — seluruh object graph menjadi attack surface.

---

## §1. Direct Property Overwrite

Bentuk mass assignment paling sederhana dan paling umum: penyerang menyertakan parameter tambahan dalam sebuah permintaan yang langsung dipetakan ke atribut model yang tidak dimaksudkan untuk dimodifikasi dari luar. Tidak diperlukan traversal rantai properti — mekanisme binding menyetel field datar pada objek target.

### §1-1. Injeksi Field Role dan Privilege

Penyerang menambahkan parameter yang berkorespondensi dengan field terkait otorisasi yang tidak ditampilkan oleh form aplikasi, tetapi diterima oleh model.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Role field injection** | Menambahkan `role=admin` atau `is_admin=true` ke permintaan registrasi/update | Atribut model untuk role dapat di-bind; tidak ada allowlist yang membatasinya |
| **Permission flag override** | Menyetel flag boolean untuk permission (`can_delete=true`, `is_verified=true`) melalui parameter tambahan | Field flag ada pada model dan tidak dikecualikan dari binding |
| **Account status manipulation** | Memodifikasi `status=active`, `email_verified=true`, `banned=false` untuk melewati kontrol siklus hidup akun | Field status dapat ditulis melalui lapisan binding |
| **Tier/plan escalation** | Menyetel `subscription_tier=enterprise` atau `quota=unlimited` pada objek yang sensitif terhadap harga | Atribut komersial merupakan bagian dari model yang sama yang di-bind ke input pengguna |

Ini adalah skenario mass assignment "buku teks" dan tetap menjadi varian yang paling sering dilaporkan dalam program bug bounty. Insiden mass assignment GitHub (2012) — di mana seorang peneliti berhasil eskalasi privilege pada repositori GitHub mana pun dengan menyuntikkan parameter `public_key` — menunjukkan keparahannya di dunia nyata. OWASP API Security Top 10 (edisi 2023) menggabungkan kategori ini dengan Excessive Data Exposure di bawah **API3:2023 Broken Object Property Level Authorization (BOPLA)**, mengakui bahwa keduanya bersumber dari kontrol akses per-properti yang tidak memadai.

### §1-2. Tampering Field Keuangan dan Logika Bisnis

Di luar privilege escalation, direct property overwrite juga menargetkan field yang memiliki signifikansi moneter atau logika bisnis.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Price/amount override** | Menyetel `price=0`, `discount=100`, `total=0.01` pada objek order/transaksi | Field keuangan berada pada model yang sama dengan data keranjang belanja yang dapat diedit pengguna |
| **Quantity manipulation** | Memodifikasi field `quantity`, `limit`, atau `credits` melebihi batas yang diizinkan | Batasan numerik hanya diterapkan di lapisan UI |
| **Timestamp injection** | Menyetel `created_at`, `updated_at`, atau `expires_at` untuk memanipulasi pengurutan record atau memperpanjang masa berlaku | Field timestamp dibuat secara otomatis tetapi masih dapat di-bind |
| **Foreign key reassignment** | Mengubah `user_id`, `owner_id`, atau `organization_id` untuk mengasosiasikan objek dengan entitas yang berbeda | Kunci relasi merupakan bagian dari model yang di-bind dan tidak dibatasi |

Foreign key reassignment sangat berdampak karena dapat mengubah mass assignment menjadi IDOR — penyerang tidak hanya memodifikasi record miliknya sendiri, tetapi juga memindahkan kepemilikan atau akses ke objek yang dimiliki pengguna lain.

### §1-3. Injeksi Internal State dan Metadata

Menargetkan atribut yang mengontrol perilaku internal aplikasi, bukan fitur yang terlihat oleh pengguna.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Soft-delete flag reset** | Menyetel `deleted=false` atau `deleted_at=null` untuk "menghidupkan kembali" record yang sudah dihapus | Implementasi soft-delete menggunakan atribut model yang dapat di-bind |
| **Workflow state override** | Memaksakan `state=approved`, `review_status=completed` untuk melewati alur persetujuan | Transisi state machine tidak diterapkan secara independen dari model |
| **Feature flag injection** | Menyetel `beta_features=true`, `experimental=enabled` pada objek preferensi pengguna | Feature flag disimpan sebagai atribut di level pengguna dan dapat di-bind |
| **Audit field manipulation** | Menimpa `last_login`, `login_count`, `modified_by` untuk memalsukan jejak audit | Field audit diisi secara otomatis tetapi lapisan binding tidak mengecualikannya |

---

## §2. Nested Property Traversal

Di sinilah mass assignment melampaui sekadar penimpaan field sederhana dan menjadi **serangan navigasi object graph**. Ketika mekanisme data binding meresolusi jalur properti secara rekursif — menginterpretasikan `a.b.c` sebagai "ambil properti `b` dari objek `a`, lalu setel properti `c` di sana" — penyerang dapat melintasi sedalam apa pun ke dalam object graph runtime aplikasi.

Eskalasi keparahannya sangat dramatis. Direct property overwrite (§1) terbatas pada field di objek yang langsung di-bind. Nested property traversal menjangkau *objek mana pun yang bisa dicapai* dalam graph, termasuk internal framework, classloader, dan konfigurasi runtime. Penelitian tentang ketidakamanan data binding di berbagai framework web Java (Spring, Grails, Struts) menunjukkan bahwa mekanisme inilah yang menjadi akar struktural dari eskalasi binding-ke-RCE — jalur dari `user.name=Alice` ke `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{webshell}` adalah soal kedalaman, bukan jenis yang berbeda.

### §2-1. Navigasi Rantai Properti Java Bean

Model introspeksi Java mengekspos `getClass()` pada setiap objek melalui `java.lang.Object`. Dari `getClass()`, seluruh hierarki tipe dapat dinavigasi melalui property accessor. Implementasi data binding yang mengikuti rantai ini tanpa batasan mengekspos seluruh object graph runtime.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Direct classLoader access** | `class.classLoader.*` — menavigasi dari `getClass()` objek mana pun ke ClassLoader | Lingkungan pre-JDK9 tanpa denylist, atau denylist yang tidak lengkap |
| **Module-based classLoader bypass** | `class.module.classLoader.*` — menggunakan `java.lang.Module` di JDK9+ sebagai hop perantara untuk melewati denylist `class.classLoader` | Runtime JDK 9+; denylist memblokir `class.classLoader` tetapi tidak `class.module.classLoader` (CVE-2022-22965) |
| **ProtectionDomain traversal** | `class.protectionDomain.*` — mengakses kebijakan keamanan dan informasi code source | ProtectionDomain tidak disertakan dalam denylist binding |
| **Nested POJO graph navigation** | `address.city.region.country.*` — mengikuti relasi lintas objek domain yang saling terkait | Framework meresolusi jalur properti bersarang secara rekursif tanpa batas kedalaman |
| **Alternative path bypass of binding rules** | Properti sensitif yang sama dapat dicapai melalui beberapa jalur properti bersarang dalam object graph. Aturan keamanan binding (allowlist/denylist) diterapkan per jalur, bukan per properti tujuan. Jalur1 diblokir tetapi Jalur2 mencapai properti yang sama tanpa terblokir — CVE-2023-46131 (Grails DoS) menunjukkan hal ini di mana DIVER menemukan jalur alternatif yang tidak terblokir secara otomatis | Framework dengan beberapa jalur object graph ke properti runtime yang sama; aturan keamanan diterapkan pada jalur, bukan tujuan |

**Module-based classLoader bypass** adalah contoh kanonik mengapa pendekatan denylist gagal untuk nested property traversal. Spring Framework memblokir `class.classLoader` setelah CVE-2010-1622, tetapi ketika JDK 9 memperkenalkan `java.lang.Module` dengan metode `getClassLoader()`-nya sendiri, `class.module.classLoader` menyediakan jalur alternatif ke target yang sama. Denylist secara struktural tidak mampu mengantisipasi hal ini: ia memblokir jalur properti tertentu, bukan *kapabilitas* untuk mencapai ClassLoader. Perbaikan di Spring 5.3.18+ beralih ke pendekatan allowlist: deskriptor properti pada objek `Class` kini dibatasi hanya pada `name` dan `customBooleanEditor` saja, terlepas dari metode accessor yang sebenarnya tersedia.

### §2-2. Primitif Eksploitasi ClassLoader

Setelah penyerang berhasil mencapai ClassLoader melalui navigasi rantai properti, beberapa primitif eksploitasi tersedia tergantung pada server aplikasi dan konfigurasi runtime.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Tomcat AccessLogValve manipulation** | `classLoader.resources.context.parent.pipeline.first.*` — mengkonfigurasi ulang access log Tomcat untuk menulis JSP webshell: menyetel `pattern` ke kode shell, `suffix` ke `.jsp`, `directory` ke `webapps/ROOT` | Apache Tomcat; deployment WAR; webroot dapat ditulis |
| **URLClassLoader resource injection** | Memodifikasi entri classpath atau URL resource melalui properti ClassLoader untuk memuat kelas dari jarak jauh | ClassLoader mengekspos properti URL/path yang dapat dimutasi |
| **GroovyClassLoader code compilation** | Lingkungan Grails/Groovy mengekspos `GroovyClassLoader` yang dapat mengkompilasi dan mengeksekusi kode Groovy sembarang dari nilai properti | Framework berbasis Groovy; ClassLoader bertipe GroovyClassLoader (CVE-2022-35912) |
| **Thread context ClassLoader swap** | Mengganti context ClassLoader thread untuk mempengaruhi resolusi kelas pada operasi-operasi berikutnya | ClassLoader thread-local dapat disetel melalui rantai properti |
| **Tomcat appBase reconfiguration (file read)** | `class.parent.appBase=/` — memodifikasi properti `appBase` Host Tomcat ke root filesystem memungkinkan pembacaan file sembarang (misalnya `/etc/passwd`) melalui penyajian resource statis aplikasi web. Ini adalah primitif *baca* yang melengkapi primitif *tulis* AccessLogValve | Deployment Tomcat; properti `appBase` dapat dicapai melalui object graph data binding |
| **Web container configuration corruption (WSDoS)** | Memodifikasi properti runtime container — `defaultHostName`, `available` (disetel ke `false`), `contextPath`, `virtualHosts`, `acceptedReceiveBufferSize` — melalui data binding merusak konfigurasi container yang sedang berjalan, menyebabkan kegagalan layanan web segera. Tidak seperti primitif file-write, ini langsung merusak state yang berjalan tanpa membuat artefak di disk | Tomcat atau Jetty; properti konfigurasi container dapat dicapai melalui binding |
| **OS-level DoS via thread exhaustion (OSDoS)** | Memodifikasi properti `startStopThreads` Tomcat ke nilai ekstrem melalui data binding. Tomcat membuat thread yang melampaui batas proses OS (`ulimit -u`), menyebabkan kelelahan proses di level OS yang mempengaruhi semua proses di host — bukan hanya layanan web. Satu permintaan HTTP melewati batas JVM/OS untuk menolak layanan ke seluruh sistem operasi | Deployment Tomcat; `startStopThreads` dapat dicapai; tidak ada hardening batas resource di level OS |
| **JVM crash via reflection metadata corruption** | Grails mengekspos `cachedMethod` — sebuah instance `java.lang.reflect.Method` — melalui object graph data binding. Sub-properti `slot` adalah field internal JVM yang mengindeks metode dalam tabel metode kelas yang mendeklarasikannya. Memodifikasi `slot` ke nilai yang tidak valid menyebabkan JVM crash dengan segmentation fault saat metode tersebut kemudian dipanggil melalui refleksi. Mengakhiri seluruh proses JVM, bukan hanya layanan web | Framework Grails; `cachedMethod.slot` dapat dicapai; penggunaan refleksi Groovy memastikan metode yang rusak tersebut dipanggil |
| **Jetty container property manipulation** | Melalui data binding, properti container Jetty (`path`, `contextPath`, `executable`, ukuran buffer konektor, `minThreads`) dapat dicapai. Tidak seperti primitif RCE AccessLogValve Tomcat, eksploitasi Jetty menargetkan objek internal yang berbeda tetapi mencapai korupsi konfigurasi, DoS, atau akses file melalui mekanisme data binding yang sama | Jetty sebagai servlet container; data binding mencapai objek internal container |

Primitif Tomcat AccessLogValve bekerja melalui empat penugasan properti yang terkoordinasi:

```
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{shell_code}i
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell
```

Ini mengkonfigurasi ulang access logging Tomcat untuk menulis file JSP yang berisi konten yang dikontrol penyerang ke direktori root yang dapat diakses web. Penyerang kemudian meminta JSP yang dihasilkan untuk mengeksekusi perintah sembarang. Khususnya, varian Grails (CVE-2022-35912) berhasil mencapai ClassLoader bahkan di Java 8, berbeda dengan Spring4Shell. Ini membuktikan bahwa kelas kerentanan ini bersifat **structural terhadap framework**, tidak terikat pada versi runtime tertentu.

### §2-3. Rantai Expression Language dan Evaluasi

Beberapa framework mengikat parameter melalui expression language (OGNL, SpEL, MVEL) yang menyediakan navigasi object graph yang jauh lebih kaya daripada resolusi properti sederhana.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **OGNL static method access** | `ParametersInterceptor` Struts2 mengevaluasi `@java.lang.Runtime@getRuntime().exec(cmd)` melalui ekspresi parameter OGNL | Struts2 dengan sandbox OGNL yang tidak memadai; `allowStaticMethodAccess=true` |
| **OGNL classLoader navigation** | `class.classLoader` melalui resolusi properti OGNL dalam parameter binding Struts2 (S2-020, CVE-2014-0094) | Parameter `class` tidak dikecualikan dari `ParametersInterceptor` |
| **SpEL injection via binding** | Evaluasi Spring Expression Language dipicu selama data binding saat anotasi `@Value` atau sejenisnya memproses nilai yang di-bind | Nilai binding mengalir ke konteks evaluasi SpEL |
| **Double evaluation** | Nilai parameter diresolusi sekali oleh binder, lalu hasilnya dievaluasi kembali sebagai ekspresi (S2-061, CVE-2020-17530). Catatan: S2-045 (CVE-2017-5638) adalah kerentanan yang berbeda — injeksi OGNL melalui header Content-Type di parser Jakarta Multipart, bukan masalah double evaluation pada data binding. | Pesan error atau nilai intermediate yang mengandung input pengguna diparsing ulang |

Dalam Struts2, `ParametersInterceptor` adalah batas kritis antara parameter HTTP dan evaluasi OGNL. Kerentanan S2-003, S2-005, S2-009, S2-016, S2-020, dan S2-021 mewakili serangkaian bypass selama satu dekade terhadap berbagai pembatasan berturut-turut tentang nama dan nilai parameter apa yang boleh dievaluasi. S2-020 secara khusus menambahkan `^class\\..*` ke `excludeParams` — padanan Struts dari denylist Spring untuk `class.classLoader` — tetapi seperti pendekatan Spring, ini terbukti tidak cukup menghadapi navigasi rantai properti yang kreatif.

---

## §3. Eksploitasi Mekanisme Binding Spesifik-Framework

Setiap framework web mengimplementasikan data binding dengan mekanisme internal yang berbeda, menciptakan attack surface yang spesifik per framework. Bagian ini membahas bagaimana implementasi binding itu sendiri — bukan object graph yang dinavigasinya — memperkenalkan kerentanan.

### §3-1. Internals Binding Spring Framework

`DataBinder` dan `BeanWrapperImpl` Spring menggunakan introspeksi Java Bean (`java.beans.Introspector`) untuk menemukan properti yang dapat disetel. Kelas `CachedIntrospectionResults` menyimpan cache objek `PropertyDescriptor`, dan setiap properti dengan setter publik dapat di-bind kecuali secara eksplisit dikecualikan.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Implicit @ModelAttribute binding** | Parameter metode handler bertipe non-primitif tanpa anotasi eksplisit diresolusi sebagai `@ModelAttribute`, memicu full data binding | Controller Spring MVC dengan parameter POJO; developer tidak menyadari adanya implicit binding |
| **setDisallowedFields bypass** | `@InitBinder` dengan `setDisallowedFields("role")` memblokir kecocokan tepat tetapi tidak jalur bersarang seperti `role.name` atau varian yang terenkode | Denylist dikonfigurasi di level nama field, bukan level jalur properti |
| **WebDataBinder type coercion** | Sistem konversi tipe Spring (ConversionService) mengubah parameter string menjadi tipe kompleks, memperluas graph tipe yang dapat dicapai | Konverter kustom terdaftar; parameter enum/tipe memicu instansiasi objek |
| **Multipart binding expansion** | Parameter file upload (`MultipartFile`) di-bind bersama parameter biasa; field metadata (`originalFilename`, `contentType`) mungkin menimpa atribut model | Handler permintaan multipart mengikat semua parameter ke satu model |

Perbaikan Spring untuk CVE-2022-22965 secara fundamental mengubah `CachedIntrospectionResults` untuk menggunakan pendekatan allowlist: deskriptor properti pada objek `Class` kini dibatasi hanya pada `name` dan `customBooleanEditor`, terlepas dari metode accessor yang sebenarnya tersedia. Perubahan arsitektur ini dari "blokir yang diketahui buruk" ke "izinkan yang diketahui baik" merupakan pengakuan framework bahwa strategi denylist secara struktural tidak dapat dipertahankan. Namun, perbaikan ini bersifat **framework-level** — registrasi `PropertyEditor` kustom atau konfigurasi `ConversionService` yang membuat jalur properti baru tidak dicakup oleh perbaikan inti.

### §3-2. Data Binding Grails

Grails mengimplementasikan lapisan data binding-nya sendiri yang independen dari `BeanWrapperImpl` Spring, menggunakan kemampuan metaprogramming Groovy. Artinya, denylist Spring tidak melindungi aplikasi Grails.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **GroovyObject metaClass binding** | Objek Groovy mengekspos `metaClass` sebagai properti, menyediakan akses ke dispatch metode dan mutasi kelas | Data binding Grails tanpa pengecualian `metaClass` |
| **Command object auto-binding** | Command object Grails mengikat semua parameter permintaan secara default; constraint `bindable` bersifat opt-in | Developer menggunakan command object tanpa constraint binding eksplisit |
| **Domain class constructor binding** | `new DomainClass(params)` mengikat semua parameter ke instance domain | Binding berbasis constructor dalam controller Grails; tidak ada constraint `bindable` |
| **bindData selective bypass** | Allowlist `bindData(obj, params, [include: [...]])` dapat dikonfigurasi secara keliru atau dilewati melalui sintaks properti bersarang | Allowlist menyertakan properti induk tetapi penyerang menavigasinya |
| **Property alias bypass** | Introspeksi properti Groovy meresolusi beberapa nama ke properti yang mendasarinya yang sama (`classLoader` dan `classLoader0` adalah alias di Grails). Denylist yang memblokir `classLoader` dilewati menggunakan `classLoader0`, karena pemfilteran berbasis nama tidak meresolusi alias ke identitas properti kanonisnya | Framework Grails; denylist menggunakan pencocokan nama properti yang tepat |

CVE-2022-35912 mempengaruhi Grails versi 3.3.10 ke atas dan secara kritis tidak memerlukan JDK 9+ — berbeda dengan Spring4Shell. Ini membuktikan bahwa kelas kerentanan ini bersifat inheren terhadap *pola* data binding, bukan pada API JDK tertentu. Perbaikan membatasi akses properti terkait ClassLoader dalam kode binding Grails sendiri, tetapi arsitektur yang mendasarinya — di mana binding defaultnya terbuka — tetap ada.

### §3-3. Parameter Interception Struts2

Struts2 memproses parameter permintaan melalui tumpukan interceptor, dengan `ParametersInterceptor` mengubah parameter HTTP menjadi ekspresi OGNL yang dievaluasi terhadap value stack action.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **excludeParams regex bypass** | Regex `excludeParams` dalam `struts-default.xml` dapat dilewati melalui encoding Unicode, manipulasi nama parameter, atau edge case regex | Pola regex tidak mencakup semua varian encoding dari pola yang diblokir |
| **Prefixed parameter OGNL injection** | Parameter dengan awalan yang dikenali framework (`action:`, `redirect:`, `redirectAction:`) dievaluasi sebagai ekspresi OGNL | Struts2 < 2.3.15; pemrosesan parameter berawalan diaktifkan |
| **Value stack navigation** | OGNL dapat menavigasi seluruh value stack Struts2, mengakses bukan hanya action tetapi juga objek sesi, aplikasi, dan servlet context | Sandbox OGNL tidak memadai atau telah dilewati |
| **Sandbox escape via OgnlContext** | Memanipulasi `_memberAccess` atau `#context` untuk melemahkan pembatasan sandbox OGNL sebelum mengeksekusi metode berbahaya | Sandbox OGNL Struts2 aktif tetapi jalur escape masih ada |

Sejarah kerentanan parameter binding Struts2 (S2-001 hingga S2-066) pada dasarnya adalah kronik dari sandbox OGNL yang berulang kali dilewati. Setiap perbaikan membatasi jalur evaluasi tertentu, dan setiap kerentanan berikutnya menemukan jalur baru. Ini mencerminkan pola eskalasi denylist Spring/Grails, tetapi dalam Struts2 mekanisme binding-nya *pada dasarnya* adalah evaluator ekspresi, sehingga attack surface-nya secara fundamental lebih besar.

### §3-4. Strong Parameters Ruby on Rails

Rails memperkenalkan `strong_parameters` (Rails 4+) sebagai respons terhadap insiden mass assignment GitHub tahun 2012. Sebelumnya, deklarasi `attr_accessible` / `attr_protected` di level model adalah satu-satunya perlindungan, dan itu pun off secara default.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **permit! wildcard** | `params.permit!` mengizinkan semua parameter, sepenuhnya melewati strong parameters | Developer menggunakan `permit!` untuk kemudahan, seringkali di controller admin |
| **Nested attributes accept** | `accepts_nested_attributes_for` dikombinasikan dengan `permit` pada objek induk dapat mengekspos atribut model bersarang | Nested attributes dikonfigurasi; permit list menyertakan asosiasi tersebut |
| **Hash parameter injection** | Permit list menyertakan parameter hash (`permit(:settings)`) tanpa membatasi kuncinya, memungkinkan injeksi key-value sembarang | Atribut bertipe hash dengan permit yang tidak dibatasi |
| **Type coercion bypass** | Mengirimkan parameter sebagai tipe berbeda (array vs. string, hash vs. skalar) untuk melewati pemeriksaan permit yang spesifik-tipe | Pemeriksaan tipe dalam permit bersifat longgar atau tidak ada |

### §3-5. Binding Serializer Django dan DRF

`ModelForm` Django dan `ModelSerializer` Django REST Framework mengontrol eksposur field melalui deklarasi `fields` / `exclude`.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **fields = '__all__' exposure** | Menggunakan `fields = '__all__'` pada ModelForm atau ModelSerializer mengekspos setiap field model ke binding | Developer menggunakan shortcut `__all__`; model memiliki field sensitif |
| **Exclude list gap** | `exclude = ['password']` memblokir field tertentu tetapi setiap field model baru yang ditambahkan terekspos secara otomatis | Model berkembang dengan field sensitif baru; exclude list tidak diperbarui |
| **Serializer inheritance override** | Serializer anak mewarisi deklarasi field dari induk tetapi menambahkan atau menimpa field, tanpa sengaja mengekspos field terbatas milik induk | Hierarki warisan serializer yang kompleks |
| **Writable nested serializer** | `WritableNestedSerializer` dengan metode `create`/`update` yang memproses data bersarang tanpa memvalidasi field mana yang dapat ditulis | DRF nested serializer tanpa `read_only` eksplisit di level field |

### §3-6. Mass Assignment Eloquent Laravel

Laravel menggunakan properti model `$fillable` (allowlist) dan `$guarded` (denylist) untuk mengontrol mass assignment.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Empty $guarded array** | Menyetel `$guarded = []` menonaktifkan perlindungan mass assignment sepenuhnya | Developer secara eksplisit menghapus proteksi model |
| **JSON column nesting bypass** | Ekspresi kolom JSON (`settings->theme`) melewati pemeriksaan guarded pada versi Laravel tertentu | Laravel < 6.18.35 / 7.x < 7.24.0; JSON column nesting dalam permintaan |
| **forceFill / forceCreate abuse** | Metode yang secara eksplisit melewati pemeriksaan fillable/guarded digunakan dengan data yang dikontrol pengguna | Developer meneruskan `$request->all()` ke `forceFill()` |
| **$fillable over-inclusion** | Allowlist menyertakan field yang seharusnya tidak dapat ditulis pengguna (misalnya `user_id`, `role_type`) | Deklarasi `$fillable` manual menyertakan atribut sensitif |

---

## §4. Format dan Encoding Differential

Format pengiriman data binding — URL-encoded form data, JSON, XML, multipart — mempengaruhi cara mekanisme binding mengurai dan meresolusi jalur properti. Perbedaan antara format yang diharapkan dan format yang sebenarnya menciptakan peluang bypass.

### §4-1. Eksploitasi Struktur JSON

Dukungan JSON secara native untuk nesting, array, dan keragaman tipe (string, number, boolean, null, object, array) menciptakan perilaku binding yang berbeda dari parameter form yang datar.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Deep nesting for property traversal** | `{"class": {"module": {"classLoader": {...}}}}` — JSON nesting langsung dipetakan ke jalur properti bersarang tanpa perlu parsing dot-notation | Framework mengikat JSON body ke object graph; kunci bersarang menjadi rantai properti |
| **Type confusion via JSON types** | Mengirimkan `{"admin": true}` (boolean) vs `admin=true` (string) — JSON mempertahankan informasi tipe yang mungkin melewati validasi berbasis string | Lapisan binding menghormati tipe JSON; validasi hanya memeriksa nilai string |
| **Array index injection** | `{"users[0].role": "admin"}` — menyuntikkan akses properti berindeks untuk memodifikasi elemen koleksi | Framework mendukung notasi indeks array dalam binding JSON |
| **Null injection** | `{"field": null}` — menyetel field ke null untuk melewati validasi "tidak boleh kosong" sambil tetap memicu setter | Nilai null diproses oleh binder; validasi memeriksa kehadiran, bukan null |

### §4-2. Content-Type Switching

Mengirimkan data dengan `Content-Type` yang tidak terduga mungkin menyebabkan framework menggunakan parser yang berbeda, menghasilkan perilaku binding yang berbeda untuk parameter logis yang sama.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Form-to-JSON switch** | Mengirimkan `Content-Type: application/json` ke endpoint yang biasanya menerima form data; parser JSON mungkin meresolusi properti bersarang secara berbeda | Framework fallback ke atau memproses tambahan body JSON |
| **XML entity expansion** | Mengirimkan body XML dengan referensi entitas yang berkembang menjadi nama atau nilai properti yang tidak terlihat dalam inspeksi parameter mentah | Binding body XML diaktifkan; perluasan entitas tidak dinonaktifkan |
| **Multipart field injection** | Menambahkan field non-file ke permintaan multipart yang di-bind bersama metadata file upload | Binding multipart memproses semua bagian, tidak hanya bagian file |

### §4-3. Encoding Nama Parameter

Mengenkode nama properti menggunakan URL encoding, Unicode, atau sintaks spesifik-framework untuk melewati pembatasan berbasis pola.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **URL encoding of property separators** | `class%2Emodule%2EclassLoader` — URL-encoding separator titik untuk melewati pola denylist berbasis regex | Regex denylist mencocokkan titik literal tetapi framework mendekode sebelum resolusi |
| **Unicode normalization bypass** | Menggunakan padanan Unicode dari karakter ASCII dalam nama properti | Framework menormalisasi Unicode setelah pemeriksaan denylist tetapi sebelum resolusi properti |
| **Bracket notation substitution** | `class[module][classLoader]` — menggunakan sintaks kurung kotak sebagai pengganti dot notation | Framework mendukung kedua notasi tetapi denylist hanya mencakup salah satunya |

---

## §5. Eksposur Skema API dan Type System

Arsitektur API modern (GraphQL, OpenAPI/Swagger, gRPC) mengekspos informasi tipe yang memungkinkan serangan mass assignment yang tepat sasaran. Tidak seperti form web tradisional di mana penyerang harus menebak field tersembunyi, API yang mengekspos skema menyediakan peta lengkap dari object graph.

### §5-1. Mass Assignment Berbasis Introspection GraphQL

Sistem introspeksi GraphQL mengembalikan skema tipe yang lengkap, termasuk setiap field pada setiap tipe — baik yang dapat ditulis maupun tidak. Hal ini membuat penemuan mass assignment menjadi sangat mudah.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Mutation field injection** | Introspeksi mengungkapkan field pada tipe input mutation (misalnya `role`, `isAdmin`) yang tidak diekspos di UI aplikasi client | Introspeksi diaktifkan di produksi; tipe input mutation menyertakan field sensitif |
| **Schema-guided field enumeration** | Menggunakan query `__schema` untuk menemukan semua tipe dan field, lalu secara sistematis menguji setiap field yang dapat ditulis untuk over-binding | Introspeksi mengembalikan skema penuh tanpa kontrol akses |
| **Nested input type traversal** | Tipe input GraphQL dengan field objek bersarang memungkinkan penugasan properti mendalam dalam satu mutation | Definisi tipe input menyertakan objek bersarang dengan field sensitif |
| **Subscription-based field leak** | Berlangganan event yang mengembalikan tipe dengan lebih banyak field daripada query/mutation yang bersesuaian, mengungkapkan nama field yang dapat di-bind | Resolver subscription mengembalikan objek penuh tanpa pemfilteran di level field |

### §5-2. Eksposur Skema OpenAPI / Swagger

Spesifikasi OpenAPI secara eksplisit mendokumentasikan skema request body, termasuk properti, tipe, dan constraint.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Schema definition enumeration** | Membaca spesifikasi OpenAPI untuk menemukan semua properti yang dapat ditulis pada model permintaan, termasuk yang tidak digunakan oleh client resmi | Spesifikasi OpenAPI dapat diakses publik (misalnya `/swagger.json`) |
| **readOnly property binding** | Skema menandai properti sebagai `readOnly` (petunjuk informatif) tetapi binding sisi server tidak menerapkannya | `readOnly` dalam OpenAPI adalah constraint di level dokumentasi, tidak diterapkan di lapisan binding |
| **additionalProperties: true** | Skema mengizinkan properti tambahan sembarang, artinya binding server menerima pasangan key-value apa pun | Default `additionalProperties: true` di OpenAPI; tidak ada enforcement di sisi server |

### §5-3. Penemuan Field gRPC / Protocol Buffer

Definisi protocol buffer mengekspos nomor dan tipe field. Meskipun gRPC bersifat binary, refleksi skema atau kebocoran file `.proto` memungkinkan penemuan field.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Reflection-based field enumeration** | Server reflection gRPC diaktifkan; penyerang menumerasi semua field pesan termasuk yang internal | Refleksi server tidak dinonaktifkan di produksi |
| **Unknown field passthrough** | Penanganan Protobuf3 terhadap unknown field memungkinkan penyetelan properti pada versi pesan yang lebih baru yang diproses oleh lapisan binding server | Server memproses pesan proto3 dengan unknown field yang diteruskan ke layanan internal |

---

## §6. Eksploitasi Metaclass di Level Bahasa

Beberapa vektor mass assignment mengeksploitasi fitur metaprogramming di level bahasa daripada logika binding spesifik-framework. Ini mempengaruhi framework mana pun yang dibangun di atas bahasa tersebut, karena akses metaclass bersifat intrinsik terhadap model objek bahasa tersebut.

### §6-1. Prototype Pollution JavaScript

Warisan berbasis prototype JavaScript berarti setiap objek mendelegasikan ke rantai prototype. Properti yang disetel pada `Object.prototype` merambat ke *semua* objek dalam runtime. Ketika mekanisme binding memproses nama properti seperti `__proto__`, `constructor.prototype`, atau `constructor`, mereka dapat mencemari rantai prototype global.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **`__proto__` direct assignment** | `{"__proto__": {"isAdmin": true}}` — fungsi merge rekursif mengikuti `__proto__` sebagai kunci biasa, menyetel properti pada `Object.prototype` | Utilitas merge/assign tidak melewati kunci `__proto__`; misalnya `lodash.merge`, `hoek.merge` sebelum diperbaiki |
| **`constructor.prototype` traversal** | `{"constructor": {"prototype": {"isAdmin": true}}}` — menavigasi melalui `constructor` untuk mencapai prototype | `__proto__` diblokir tetapi `constructor.prototype` tidak |
| **Object.assign with tainted source** | `Object.assign(target, userInput)` di mana `userInput` mengandung `__proto__` — `Object.assign` native tidak menyalin `__proto__` tetapi implementasi kustom mungkin melakukannya | Fungsi merge/deep-copy kustom yang mengiterasi `Object.keys()` termasuk properti yang diwarisi |
| **ORM query operator injection** | `{"where": {"role": {"$ne": "admin"}}}` — ketika binding mengalir ke operator query NoSQL (Mongoose, Sequelize), prototype pollution dapat menyuntikkan logika query | Lapisan binding meneruskan objek pengguna langsung ke query builder ORM |

Prototype pollution adalah padanan struktural JavaScript dari traversal `class.classLoader` Java — keduanya mengeksploitasi akses metaclass di level bahasa untuk mencapai objek di luar scope binding yang dimaksud. Paralelnya tepat: `__proto__` menavigasi rantai prototype sama seperti `class.module.classLoader` menavigasi hierarki tipe Java.

### §6-2. Akses Atribut Python

`__class__`, `__dict__`, `__init__`, dan `__subclasses__()` Python menyediakan akses refleksi dan metaclass yang mirip dengan `getClass()` Java.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **`__class__` traversal** | `obj.__class__.__init__.__globals__` — menavigasi dari objek mana pun ke namespace global kelasnya | Template engine atau mekanisme binding mengevaluasi jalur atribut tanpa batasan |
| **`__dict__` direct manipulation** | Mengakses `__dict__` untuk membaca atau memodifikasi atribut instance termasuk yang "private" (name-mangled) | Framework mengekspos `__dict__` melalui resolusi properti |
| **MRO exploitation** | Menggunakan `__mro__` (Method Resolution Order) untuk menavigasi hierarki kelas dan menemukan kelas/metode yang berguna | Rantai SSTI Python yang melintasi `__mro__` untuk mencapai `os.system` atau `subprocess` |

### §6-3. Metaprogramming Ruby

Model open class Ruby dan delegasi `method_missing` menciptakan attack surface binding tambahan.

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **`send` method invocation** | Jika logika binding menggunakan `obj.send(param_name, param_value)`, metode sembarang dapat dipanggil | Implementasi binding kustom menggunakan `send` tanpa batasan |
| **`instance_variable_set` access** | Manipulasi variabel instance secara langsung yang melewati kontrol attribute accessor | Mekanisme binding atau kode developer menggunakan `instance_variable_set` dengan input pengguna |

---

## §7. Interaksi ORM dan Lapisan Persistensi

Mass assignment tidak selalu berhenti di objek aplikasi — ketika objek yang di-bind tersebut dipersistensi, lapisan ORM mungkin memproses properti tambahan yang mempengaruhi perilaku di level database.

### §7-1. Manipulasi Relasi dan Asosiasi

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Foreign key reassignment** | Mengikat `user_id` atau `account_id` yang berbeda untuk mengasosiasikan record dengan entitas lain | Field FK dapat di-bind; tidak ada validasi kepemilikan di lapisan persistensi |
| **Polymorphic type override** | Mengubah `type` pada polymorphic association (misalnya `commentable_type=Admin`) untuk berasosiasi dengan model yang berbeda | Field tipe STI atau polymorphic association dapat di-assign secara massal |
| **Nested association creation** | `user[posts_attributes][0][published]=true` — membuat atau memodifikasi record yang diasosiasikan melalui binding bersarang | `accepts_nested_attributes_for` (Rails) atau yang setara tanpa guard `reject_if` |
| **Join table injection** | Menambahkan entri ke join table many-to-many dengan mengikat ID asosiasi (`role_ids=[1,2,3]`) | Proxy asosiasi mengizinkan penugasan berbasis ID; tidak ada kontrol akses pada asosiasi |

### §7-2. Query dan Scope Injection

| Subtipe | Mekanisme | Kondisi Utama |
|---------|-----------|---------------|
| **Default scope override** | Mengikat parameter yang memodifikasi scope query atau pengurutan default, berpotensi mengungkapkan record tersembunyi | Parameter scope ORM dapat di-bind atau dikonfigurasi melalui input permintaan |
| **Soft-delete bypass** | Menyetel `deleted_at=null` untuk membuat record yang telah di-soft-delete muncul dalam query, atau sebaliknya | Field soft-delete dapat di-assign secara massal; default scope memfilter berdasarkan field ini |

---

## Pemetaan Skenario Serangan (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama |
|----------|------------|----------------------|
| **Privilege Escalation** | Aplikasi web mana pun dengan akses berbasis peran | §1-1 + §5-1 (penemuan field + injeksi role) |
| **Remote Code Execution** | Framework Java (Spring, Grails, Struts) dengan binding yang dapat mengakses ClassLoader | §2-1 + §2-2 + §2-3 (rantai properti → ClassLoader → primitif eksploitasi) |
| **Data Tampering** | E-commerce, SaaS, aplikasi keuangan | §1-2 + §7-1 (field keuangan + manipulasi relasi) |
| **Authentication Bypass** | API dengan eksposur skema | §1-3 + §5 (internal state + enumerasi berbasis skema) |
| **Prototype Pollution → XSS/RCE** | Aplikasi Node.js dengan binding berbasis merge | §6-1 (polusi rantai prototype → override template atau injeksi child_process) |
| **Arbitrary File Write** | Framework Java di atas Tomcat | §2-2 (manipulasi AccessLogValve untuk menulis webshell) |
| **Denial of Service** | Framework binding mana pun dengan deep nesting | §2-1 + §4-1 (resolusi properti rekursif dengan deep nesting menyebabkan stack overflow atau resource exhaustion) |
| **Audit Trail Falsification** | Aplikasi dengan metadata audit yang dapat di-bind | §1-3 (manipulasi field timestamp/author) |
| **Arbitrary File Read** | Framework Java di atas Tomcat | §2-2 (rekonfigurasi appBase untuk menyajikan root filesystem) |
| **OS-Level Denial of Service** | Framework Java di atas Tomcat | §2-2 (thread exhaustion startStopThreads yang melampaui batas JVM/OS) |
| **JVM Process Crash** | Grails di container mana pun | §2-2 (korupsi metadata refleksi cachedMethod.slot) |

---

## Pemetaan CVE / Bounty (2010–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak |
|-----------------|------------|--------|
| §2-1 (direct classLoader) | CVE-2010-1622 (Spring Framework) | RCE melalui traversal properti `class.classLoader`; demonstrasi pertama data binding → RCE |
| §3-3 (OGNL class access) + §2-3 | CVE-2014-0094 / S2-020 (Struts2) | Manipulasi ClassLoader melalui evaluasi OGNL `ParametersInterceptor` |
| §2-1 (module bypass) + §2-2 (AccessLogValve) | CVE-2022-22965 / Spring4Shell (Spring Framework) | RCE kritis; `class.module.classLoader` melewati denylist JDK9+; CVSS 9.8 |
| §3-2 (Grails binding) + §2-2 (classLoader) | CVE-2022-35912 (Grails Framework) | RCE kritis melalui data binding spesifik Grails; mempengaruhi Java 8+; CVSS 9.8 |
| §3-6 (JSON nesting bypass) | Laravel `$guarded` bypass (sebelum 6.18.35 / 7.x sebelum 7.24.0) | Mass assignment melalui ekspresi nesting kolom JSON yang melewati `$guarded` |
| §1-1 (role injection) | Insiden GitHub 2012 | Injeksi public key pada repo sembarang; menunjukkan keparahan mass assignment |
| §6-1 (`__proto__`) | CVE-2018-3721 (lodash) | Prototype pollution melalui `lodash.merge`; mempengaruhi semua aplikasi downstream |
| §6-1 (`__proto__`) | CVE-2019-10744 (lodash) | Prototype pollution dalam `lodash.defaultsDeep`; CVSS 9.1 |
| §6-1 (constructor.prototype) | CVE-2024-21529 (dset) | Prototype pollution melalui sanitasi yang tidak tepat dalam paket `dset` |
| §2-3 (OGNL double eval) | CVE-2020-17530 / S2-061 (Struts2) | Double OGNL evaluation yang mengarah ke RCE; bypass sandbox OGNL |
| §2-3 (OGNL injection) | CVE-2023-22527 (Confluence) | Injeksi OGNL dalam template injection Atlassian Confluence yang mengarah ke RCE |
| §2-1 (alternative path bypass) | CVE-2023-46131 (Grails Framework) | DoS melalui jalur properti alternatif ke properti yang diblokir; DIVER menemukan jalur yang tidak terblokir secara otomatis |
| §2-1 + §2-2 (temuan DIVER) | 81 kerentanan (Spring + Grails) | ISSTA 2024: penemuan otomatis 81 kerentanan data binding; 3 CVE baru ditetapkan |

---

## Tool Deteksi

| Tool | Cakupan Target | Teknik Inti |
|------|---------------|-------------|
| **DIVER** (Riset) | Data binding Spring, Grails | Ekstraksi Nested Property Graph + instrumentasi bind-site + fuzzing berbasis properti; menemukan 81 kerentanan |
| **Burp Suite Pro** (Komersial) | Aplikasi web umum | Ekstensi Param Miner untuk penemuan parameter tersembunyi; pemindaian aktif untuk mass assignment |
| **Arjun** (Open Source) | REST API | Brute-force parameter HTTP menggunakan wordlist besar untuk menemukan parameter yang dapat di-bind yang tersembunyi |
| **Param Miner** (Ekstensi Burp) | Aplikasi web | Penemuan parameter tersembunyi otomatis melalui analisis perbedaan respons |
| **InQL** (Ekstensi Burp) | GraphQL API | Otomasi query introspeksi; enumerasi field mutation; pengujian batch |
| **graphql-voyager** (Open Source) | GraphQL API | Eksplorasi skema visual untuk mengidentifikasi tipe input mutation dengan field sensitif |
| **Nuclei** (Open Source) | Multi-framework | Pemindaian berbasis template termasuk pengecekan Spring4Shell, OGNL Struts, dan mass assignment |
| **mass-assignment-check** (npm) | Node.js/Express | Analisis statis untuk mendeteksi object spread/assign yang tidak terlindungi dalam route handler |
| **Brakeman** (Open Source) | Ruby on Rails | Analisis statis yang mendeteksi `permit!`, strong parameters yang hilang, dan celah `attr_accessible` |
| **Semgrep** (Open Source) | Multi-bahasa | Analisis statis berbasis aturan dengan aturan komunitas untuk pola mass assignment di berbagai framework |

---

## Ringkasan: Prinsip Inti

Mass assignment bukan satu kerentanan — melainkan sebuah **konsekuensi struktural** dari automatic data binding, sebuah pola desain yang diadopsi oleh hampir semua framework web modern. Properti fundamental yang membuat seluruh ruang mutasi ini menjadi mungkin adalah **impedance mismatch antara kemudahan binding dan granularitas kontrol akses**: framework secara default mengikat semua properti demi produktivitas developer, sementara keamanan membutuhkan keputusan akses per-properti, per-konteks.

Eskalasi dari penimpaan field sederhana hingga remote code execution adalah soal kedalaman object graph. Penelitian di berbagai framework web Java (Spring, Grails, Struts) menunjukkan model ancaman yang terpadu: implementasi data binding *mana pun* yang meresolusi jalur properti bersarang tanpa batasan, dikombinasikan dengan runtime bahasa yang mengekspos informasi metaclass (`getClass()` Java, `__proto__` JavaScript, `__class__` Python), menciptakan jalur dari parameter HTTP yang dikontrol pengguna ke objek internal runtime. Sejarah CVE — dari CVE-2010-1622 hingga Spring4Shell (CVE-2022-22965) hingga CVE-2022-35912 — adalah studi kasus selama dua belas tahun tentang kegagalan penambalan denylist inkremental menghadapi attack surface yang secara struktural terbuka.

Perbaikan inkremental gagal karena attack surface didefinisikan oleh **object graph yang dapat dijangkau**, yang berkembang setiap kali runtime diperbarui (JDK 9 menghadirkan `Module`), setiap plugin framework baru, dan setiap perubahan model aplikasi. Denylist yang memblokir `class.classLoader` menjadi usang ketika `class.module.classLoader` muncul; regex yang memblokir `^class\\..*` menjadi usang ketika bracket notation atau URL encoding didukung. Solusi strukturalnya membutuhkan pembalikan default: binding harus bersifat **tertutup secara default** (allowlisting eksplisit untuk properti yang dapat di-bind per endpoint), dikombinasikan dengan resolusi properti **berkedalaman terbatas** yang mencegah traversal melampaui objek yang langsung di-bind. Framework yang telah mengadopsi pendekatan ini — strong parameters Rails, allowlist `CachedIntrospectionResults` Spring pasca-5.3.18, deklarasi `fields` eksplisit Django — mewakili arah arsitektur yang benar, namun warisan dari default "bind semuanya" berarti mass assignment akan tetap menjadi kelas kerentanan yang produktif untuk bertahun-tahun ke depan.

---

*Dokumen ini dibuat untuk keperluan riset keamanan defensif dan pemahaman kerentanan.*

## Referensi

- CVE-2022-22965 (Spring4Shell) — NVD, Spring Security Advisory
- CVE-2022-35912 (Grails RCE) — GitHub Security Advisory GHSA-6rh6-x8ww-9h97
- CVE-2010-1622 (Spring ClassLoader) — NVD
- CVE-2014-0094 / S2-020 (Struts2 ClassLoader) — Apache Struts Security Bulletins
- CVE-2020-17530 / S2-061 (Struts2 OGNL) — Apache Struts Security Bulletins
- OWASP API Security Top 10 2023 — API3:2023 Broken Object Property Level Authorization
- OWASP Mass Assignment Cheat Sheet
- ISSTA 2024: "Automated Data Binding Vulnerability Detection for Java Web Frameworks via Nested Property Graph" — Yan et al.
- BlackHat EU 2022: "DataBinding2Shell: Novel Pathways to RCE via Web Frameworks" — Haowen Mu, Biao He (Ant Security FG Lab)
