# macOS Apps - Inspecting、debugging、Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## 静的解析

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```
### Disarm (old jtool2)

[**こちらから disarm をダウンロードできます**](https://newosxbook.com/tools/disarm.html)。

> [!TIP]
> **`disarm`** は圧縮された IM4P ファイル（`kernelcache` など）にも対応しており、必要な部分だけを抽出したり、抽出せずに必要な部分を分析したりできます。
```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```
### Codesign / ldid

> [!TIP]
> **`Codesign`** は **macOS** にあり、**`ldid`** は **iOS** にあります。
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) は、**.pkg** ファイル（インストーラー）を検査し、インストールする前にその内容を確認するのに便利なツールです。\
これらのインストーラーには `preinstall` および `postinstall` bash スクリプトが含まれており、マルウェア作成者は通常、**マルウェア**を**永続化**するためにこれらを悪用します。

### hdiutil

このツールを使うと、Apple のディスクイメージ（**.dmg**）ファイルを**マウント**し、何かを実行する前に検査できます。
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
これは `/Volumes` にマウントされます

### Packed binaries

- 高いエントロピーを確認する
- 文字列を確認する（理解可能な文字列がほとんどない場合は、packed されている）
- MacOS 用の UPX packer は `__XHDR` というセクションを生成する

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> Objective-C で記述されたプログラムは、[Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) に **compiled** された **とき**、クラス宣言を**保持する**ことに注意する。このようなクラス宣言には、以下の名前と型が**含まれる**。

- 定義された interfaces
- interface methods
- interface instance variables
- 定義された protocols

binary の reversing をより困難にするため、これらの名前が obfuscated されている可能性があることに注意する。

### Function calling

objective-C を使用する binary で function が呼び出される場合、compiled code はその function を直接呼び出す代わりに **`objc_msgSend`** を呼び出す。これが最終的な function を呼び出す。

![Metadata - Function calling: objective-C を使用する binary で function が呼び出される場合、compiled code はその function を直接呼び出す代わりに objc msgSend を呼び出す。これが...](<../../../images/image (305).png>)

この function が想定する params は以下のとおり。

- 第 1 パラメータ（**self**）は「**message を受け取る class の instance を指す pointer**」。より簡単に言えば、method が invoke される対象の object。method が class method の場合、これは class object 全体の instance となる。一方、instance method の場合、self は class の instantiated instance を object として指す。
- 第 2 パラメータ（**op**）は「message を処理する method の selector」。より簡単に言えば、これは単に **method の名前**。
- 残りのパラメータは、method（op）が必要とする **values**。

**ARM64 で `lldb` を使用してこの情報を簡単に取得する方法**については、以下のページを参照。


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: method が invoke される対象の object** |
| **2nd argument**  | **rsi**                                                         | **op: method の名前**                             |
| **3rd argument**  | **rdx**                                                         | **method の第 1 引数**                         |
| **4th argument**  | **rcx**                                                         | **method の第 2 引数**                         |
| **5th argument**  | **r8**                                                          | **method の第 3 引数**                         |
| **6th argument**  | **r9**                                                          | **method の第 4 引数**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **method の第 5 引数以降**                        |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) は Objective-C binaries を class-dump する tool。github では dylibs が指定されているが、executables でも動作する。
```bash
./dynadump dump /path/to/bin
```
執筆時点では、**現在これが最もよく機能します**。

#### 通常のツール
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) は、Objective-C 形式のコード内にあるクラス、カテゴリ、プロトコルの宣言を生成する元祖ツールです。

古く、メンテナンスされていないため、正しく動作しない可能性があります。

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) は、最新のクロスプラットフォーム Objective-C class dump です。既存のツールと比較して、iCDump は Apple ecosystem から独立して実行でき、Python bindings を提供します。
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static Swift analysis

Swift バイナリでは Objective-C 互換性があるため、[class-dump](https://github.com/nygard/class-dump/) を使用して宣言を抽出できる場合がありますが、常に可能とは限りません。

**`jtool -l`** または **`otool -l`** のコマンドラインを使用すると、**`__swift5`** プレフィックスで始まる複数のセクションを見つけることができます：
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
これらのセクションに保存されている[**情報については、このブログ記事で詳しく確認できます**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)。

さらに、**Swift binaries には symbols が含まれている場合があります**（たとえば、libraries ではその functions を呼び出せるように symbols を保存する必要があります）。**symbols には通常、function name** や attributes に関する情報が読みにくい形式で含まれているため、非常に有用です。また、元の name を取得できる "**demanglers**" も存在します。
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dynamic Analysis

> [!WARNING]
> バイナリを debug するには、**SIP を無効化**（`csrutil disable` または `csrutil enable --without debug`）するか、バイナリを一時フォルダにコピーして `codesign --remove-signature <binary-path>` で**署名を削除**する必要があります。または、バイナリの debug を許可します（[この script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) を使用できます）。

> [!WARNING]
> macOS で `cloudconfigurationd` などの**システムバイナリを instrument**するには、**SIP を無効化する必要があります**（署名を削除するだけでは機能しません）。

### APIs

macOS には、process に関する情報を提供する興味深い APIs がいくつかあります。

- `proc_info`: 各 process に関する大量の情報を提供する主要なものです。他の process の情報を取得するには root である必要がありますが、特別な entitlements や mach ports は必要ありません。
- `libsysmon.dylib`: XPC で公開された functions を通じて process の情報を取得できます。ただし、`com.apple.sysmond.client` entitlement が必要です。

### Stackshot & microstackshots

**Stackshotting** は、実行中のすべての thread の call stack を含む、process の状態を取得するための technique です。これは、debug、performance analysis、および特定の時点における system の動作を理解する際に特に役立ちます。iOS と macOS では、**`sample`** や **`spindump`** などの tools や methods を使って stackshotting を実行できます。

### Sysdiagnose

この tool（`/usr/bini/ysdiagnose`）は、`ps` や `zprint` など、数十種類の異なる commands を実行してコンピューターから大量の情報を収集します。

これは **root** として実行する必要があり、daemon `/usr/libexec/sysdiagnosed` には `com.apple.system-task-ports` や `get-task-allow` などの非常に興味深い entitlements があります。

その plist は `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` にあり、3 つの MachServices を宣言しています。

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp 内の古い archive を削除します
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23（kernel）
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C class を介した user mode interface。dict には 3 つの arguments（`compress`、`display`、`run`）を渡せます

### Unified Logs

MacOS は大量の logs を生成します。これらは、application の実行時に**何をしているのか**を理解するうえで非常に役立ちます。

さらに、`<private>` tag を含む logs があり、一部の **user** または **computer** の**識別可能な**情報を**隠します**。ただし、**この情報を開示する certificate を install することが可能です**。[**こちら**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log) の説明に従ってください。

### Hopper

#### Left panel

Hopper の left panel では、binary の symbols（**Labels**）、procedures と functions の list（**Proc**）、および strings（**Str**）を確認できます。これらはすべての strings ではなく、Mach-O file の複数の部分（_cstring や `objc_methname` など）で定義されているものです。

#### Middle panel

middle panel では、**disassembled code** を確認できます。また、それぞれの icon をクリックすることで、**raw** disassemble、**graph**、**decompiled**、**binary** として表示できます。

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

code object を右クリックすると、その **object への参照および object からの参照**を確認したり、名前を変更したりできます（decompiled pseudocode では機能しません）。

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

さらに、**middle panel の下部では python commands を記述できます**。

#### Right panel

right panel では、**navigation history**（現在の状態にどのように到達したかを確認できます）、**call graph**（この function を **call するすべての functions** と、この function が **call するすべての functions** を確認できます）、および **local variables** の情報など、興味深い情報を確認できます。

### dtrace

application に極めて**低レベル**でアクセスでき、user が **programs を trace**したり、その execution flow を変更したりする手段を提供します。Dtrace は **probes** を使用します。これらは **kernel 全体に配置**され、system call の開始時や終了時などに存在します。

DTrace は `dtrace_probe_create` function を使用して、各 system call 用の probe を作成します。これらの probes は、各 system call の **entry point と exit point** で発火させることができます。DTrace との interaction は /dev/dtrace を通じて行われますが、これは root user のみ利用できます。

> [!TIP]
> SIP protection を完全に無効化せずに Dtrace を有効化するには、recovery mode で次を実行します: `csrutil enable --without dtrace`
>
> 自分で compile した **`dtrace`** や **`dtruss`** binaries も使用できます。

利用可能な dtrace probes は、次の command で取得できます。
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
probe nameは、provider、module、function、nameの4つの部分で構成されます（`fbt:mach_kernel:ptrace:entry`）。nameの一部を指定しなかった場合、Dtraceはその部分にワイルドカードを適用します。

DTraceでprobeを有効化し、probeが発火したときに実行するアクションを指定するには、D languageを使用する必要があります。

より詳しい説明と追加の例については、[https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)を参照してください。

#### 例

`man -k dtrace`を実行すると、**利用可能なDTrace scripts**が一覧表示されます。例: `sudo dtruss -n binary`

- 行内
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- script
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### kdebug

これは kernel tracing facility です。documented codes は **`/usr/share/misc/trace.codes`** にあります。

`latency`、`sc_usage`、`fs_usage`、`trace` などの tools は内部でこれを使用します。

`kdebug` と interface するには、`kern.kdebug` namespace 上で `sysctl` を使用します。使用する MIBs は `sys/sysctl.h` にあり、functions は `bsd/kern/kdebug.c` に実装されています。

custom client で kdebug とやり取りする手順は、通常以下のとおりです。

- KERN_KDSETREMOVE で既存の settings を削除する
- KERN_KDSETBUF と KERN_KDSETUP で trace を設定する
- KERN_KDGETBUF を使用して buffer entries の数を取得する
- KERN_KDPINDEX で自身の client を trace から除外する
- KERN_KDENABLE で tracing を有効化する
- KERN_KDREADTR を呼び出して buffer を読み取る
- 各 thread をその process と対応付けるには KERN_KDTHRMAP を呼び出す

この情報を取得するには、Apple tool の **`trace`** または custom tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** を使用できます。**

**Kdebug は一度に 1 customer のみ利用できます。** そのため、k-debug powered tool は同時に 1 つしか実行できません。

### ktrace

`ktrace_*` APIs は `libktrace.dylib` に由来し、`Kdebug` の APIs を wrap しています。そのため client は `ktrace_session_create` と `ktrace_events_[single/class]` を呼び出して特定の codes に対する callbacks を設定し、`ktrace_start` で tracing を開始できます。

**SIP を有効化した状態でも** これを使用できます。

client として utility の `ktrace` を使用できます。
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
または `tailspin`。

### kperf

これは kernel level profiling を実行するために使用され、`Kdebug` callout を使って構築されています。

基本的には、グローバル変数 `kernel_debug_active` がチェックされ、有効な場合は、呼び出し元の kernel frame の `Kdebug` code とアドレスとともに `kperf_kdebug_handler` が呼び出されます。`Kdebug` code が選択されたもののいずれかと一致すると、bitmap として設定された「actions」を取得します（オプションについては `osfmk/kperf/action.h` を確認してください）。

Kperf には sysctl MIB table もあります（root として実行）：`sysctl kperf`。これらの code は `osfmk/kperf/kperfbsd.c` にあります。

さらに、Kperf の機能の一部は `kpc` に含まれており、machine performance counters に関する情報を提供します。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) は、process が実行している process related actions を確認するための非常に便利な tool です（例えば、ある process が作成している new processes を監視できます）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) は、process 間の関係を表示する tool です。\
次のような command で Mac を監視する必要があります：**`sudo eslogger fork exec rename create > cap.json`**（これを起動する terminal には FDA が必要です）。その後、この tool に json を読み込ませると、すべての関係を表示できます：

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) は、file events（creation、modifications、deletions など）を監視し、それらの events に関する詳細な情報を提供します。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) は、Windows users が Microsoft Sysinternal の _Procmon_ から知っているかもしれない look and feel を備えた GUI tool です。この tool では、さまざまな event types の recording を開始および停止でき、file、process、network などの categories によってこれらの events を filtering でき、記録した events を json format で保存できます。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) は Xcode の Developer tools の一部であり、application performance の monitoring、memory leaks の identification、filesystem activity の tracking に使用されます。

![Crescendo - Apple Instruments: Apple Instruments は Xcode の Developer tools の一部であり、application performance の monitoring、memory leaks の identification、filesystem activity の tracking に使用されます](<../../../images/image (1138).png>)

### fs_usage

process によって実行された actions を追跡できます：
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) は、バイナリが使用する **libraries**、使用中の **files**、および **network** 接続を確認するのに役立ちます。\
また、バイナリのプロセスを **virustotal** と照合し、バイナリに関する情報を表示します。

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**this blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) では、SIP が無効になっている場合でもデバッグを防止する **`PT_DENY_ATTACH`** を使用する **running daemon** を **debug** する方法の例を確認できます。

### lldb

**lldb** は、macOS のバイナリ **debugging** におけるデファクト **tool** です。
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
ホームフォルダーに **`.lldbinit`** というファイルを作成し、次の行を記述することで、lldb使用時にintel flavourを設定できます。
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> lldb 内では、`process save-core` を使ってプロセスをダンプします

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>説明</strong></td></tr><tr><td><strong>run (r)</strong></td><td>実行を開始し、ブレークポイントに到達するかプロセスが終了するまで中断せずに続行します。</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>エントリポイントで停止して実行を開始します</td></tr><tr><td><strong>continue (c)</strong></td><td>デバッグ対象のプロセスの実行を続行します。</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>次の命令を実行します。このコマンドは関数呼び出しをスキップします。</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>次の命令を実行します。nexti コマンドとは異なり、このコマンドは関数呼び出しの中にステップインします。</td></tr><tr><td><strong>finish (f)</strong></td><td>現在の関数（「frame」）内の残りの命令を実行し、return して停止します。</td></tr><tr><td><strong>control + c</strong></td><td>実行を一時停止します。プロセスが run (r) または continue (c) されている場合、プロセスは現在実行中の場所で停止します。</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #main という名前のすべての関数</p><p><code>b <binname>`main</code> #バイナリの main 関数</p><p><code>b set -n main --shlib <lib_name></code> #指定したバイナリの main 関数</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #すべての NSFileManager メソッド</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> #そのライブラリのすべての関数で停止</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #ブレークポイントの一覧</p><p><code>br e/dis <num></code> #ブレークポイントを有効化/無効化</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #breakpoint コマンドのヘルプを取得</p><p>help memory write #メモリへの書き込み方法のヘルプを取得</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>メモリを null 終端文字列として表示します。</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>メモリをアセンブリ命令として表示します。</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>メモリをバイトとして表示します。</td></tr><tr><td><strong>print object (po)</strong></td><td><p>param が参照するオブジェクトを表示します</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Apple の Objective-C API またはメソッドのほとんどはオブジェクトを返すため、「print object」（po）コマンドで表示する必要があります。po で意味のある出力が得られない場合は <code>x/b</code> を使用します</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #そのアドレスに AAAA を書き込む<br>memory write -f s $rip+0x11f+7 "AAAA" #そのアドレスに AAAA を書き込む</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #現在の関数を逆アセンブル</p><p>dis -n <funcname> #関数を逆アセンブル</p><p>dis -n <funcname> -b <basename> #関数を逆アセンブル<br>dis -c 6 #6 行を逆アセンブル<br>dis -c 0x100003764 -e 0x100003768 #あるアドレスから別のアドレスまで<br>dis -p -c 4 #現在のアドレスから逆アセンブルを開始</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 #x1 レジスタ内の 3 コンポーネントの配列を確認</td></tr><tr><td><strong>image dump sections</strong></td><td>現在のプロセスのメモリマップを表示します</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #CoreNLP のすべてのシンボルのアドレスを取得</td></tr></tbody></table>

> [!TIP]
> **`objc_sendMsg`** 関数を呼び出す際、**rsi** レジスタには null 終端された（「C」）文字列として**メソッド名**が格納されます。lldb で名前を表示するには、次のようにします。
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- **`sysctl hw.model`** コマンドは、**host が MacOS** の場合は "Mac" を返しますが、VM の場合は異なる値を返します。
- **`hw.logicalcpu`** と **`hw.physicalcpu`** の値を操作して、一部の malware は VM かどうかを検出しようとします。
- 一部の malware は、MAC アドレス（00:50:56）に基づいて、マシンが **VMware** かどうかを検出することもできます。
- 次のような単純なコードを使用して、**プロセスがデバッグされているかどうか**を確認することもできます。
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- **`PT_DENY_ATTACH`** フラグを指定して **`ptrace`** system call を呼び出すこともできます。これにより、deb**u**gger が attach して tracing することを**防止**します。
- **`sysctl`** または **`ptrace`** 関数が **import** されているか確認できます（ただし、malware は動的に import する可能性があります）
- この writeup で説明されているとおり、「[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)」:\
「_Process # exited with **status = 45 (0x0000002d)** というメッセージは、通常、デバッグ対象が **`PT_DENY_ATTACH`** を使用していることを示す明確な兆候です_」

## Core Dumps

Core dumps は次の場合に作成されます。

- `kern.coredump` sysctl が 1 に設定されている場合（デフォルト）
- プロセスが suid/sgid ではない場合、または `kern.sugid_coredump` が 1 の場合（デフォルトは 0）
- `AS_CORE` limit が操作を許可している場合。`ulimit -c 0` を呼び出して code dumps の作成を抑制し、`ulimit -c unlimited` で再度有効にできます。

これらの場合、core dumps は `kern.corefile` sysctl に従って生成され、通常は `/cores/core/.%P` に保存されます。

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash は、**crash しているプロセスを分析し、crash report をディスクに保存します**。crash report には、**developer が crash の原因を診断するのに役立つ**情報が含まれています。\
**per-user launchd context で実行されている**アプリケーションやその他のプロセスの場合、ReportCrash は LaunchAgent として実行され、crash report をユーザーの `~/Library/Logs/DiagnosticReports/` に保存します。\
daemon、**system launchd context で実行されているその他のプロセス**、およびその他の privileged process の場合、ReportCrash は LaunchDaemon として実行され、crash report をシステムの `/Library/Logs/DiagnosticReports` に保存します。

crash report が **Apple に送信される**ことが心配な場合は、無効にできます。そうでなければ、crash report は **server がどのように crash したかを把握する**のに役立ちます。
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### スリープ

MacOSでfuzzingを行う際は、Macがスリープしないようにすることが重要です。

- systemsetup -setsleep Never
- pmset、システム設定
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 接続切断

SSH接続経由でfuzzingを行う場合、セッションが切断されないようにすることが重要です。そのため、以下の内容でsshd_configファイルを変更します。

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**以下のページを確認してください**。指定した **scheme または protocol を handling しているアプリ** を見つける方法を確認できます。


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

ネットワークデータを管理しているプロセスを見つけるのに役立ちます。
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
または `netstat` や `lsof` を使用します

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzer

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLIツールで動作します

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOSのGUIツールで**「そのまま動作します」**。一部のmacOSアプリには、一意なファイル名、正しい拡張子、sandboxからのファイル読み取り（`~/Library/Containers/com.apple.Safari/Data`）など、固有の要件がある点に注意してください。

いくつかの例:
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
### MacOS Fuzzing の詳細情報

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 参考資料

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
