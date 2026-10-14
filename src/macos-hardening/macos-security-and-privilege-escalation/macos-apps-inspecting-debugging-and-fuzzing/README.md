# macOSアプリ - 検査、デバッグ、ファジング

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

### Disarm（旧 jtool2）

[**disarmはこちらからダウンロードできます**](https://newosxbook.com/tools/disarm.html)。

> [!TIP]
> **`disarm`**は圧縮されたIM4Pファイル（`kernelcache`など）にも対応しており、必要な部分だけを抽出したり、抽出せずに必要な部分を解析したりできます。

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
> **`Codesign`** は **macOS** で使用でき、**`ldid`** は **iOS** で使用できます。

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) は、**.pkg** ファイル（インストーラー）を調査し、インストール前にその内容を確認するのに便利なツールです。\
これらのインストーラーには `preinstall` と `postinstall` の bash スクリプトが含まれており、マルウェア作者は通常、**マルウェアをpersist**させるためにこれらを悪用します。

### hdiutil

このツールは Apple のディスクイメージ（`.dmg`）ファイルを**マウント**し、何かを実行する前に内容を確認できるようにします。

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

`/Volumes` にマウントされます

### Packed binaries

- エントロピーが高いか確認する
- strings を確認する（理解できる文字列がほとんどない場合は、packed されている）
- macOS 用 UPX packer は `__XHDR` という section を生成する

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> Objective-C で書かれたプログラムは、[Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) に**コンパイル**されても、クラス宣言が**保持される**点に注意してください。こうしたクラス宣言には、以下の名前と型が**含まれます**。

- 定義されたインターフェース
- インターフェースのメソッド
- インターフェースのインスタンス変数
- 定義されたプロトコル

これらの名前は、バイナリのリバースを難しくするために難読化されている場合がある点に注意してください。

### Function calling

Objective-C を使用するバイナリで関数が呼び出される場合、コンパイルされたコードはその関数を直接呼び出すのではなく、**`objc_msgSend`** を呼び出します。これが最終的に関数を呼び出します。

![Metadata - Function calling: Objective-C を使用するバイナリで関数が呼び出される場合、コンパイルされたコードはその関数を直接呼び出すのではなく、objc msgSend を呼び出します。これが...](<../../../images/image (305).png>)

この関数が受け取るパラメーターは次のとおりです。

- 最初のパラメーター（**self**）は「メッセージを受け取る**クラスのインスタンスを指すポインター**」です。簡単に言えば、メソッドが呼び出される対象のオブジェクトです。クラスメソッドの場合、クラスオブジェクト全体のインスタンスを指します。一方、インスタンスメソッドの場合、インスタンス化されたクラスオブジェクトを指します。
- 2 番目のパラメーター（**op**）は「メッセージを処理するメソッドのセレクター」です。簡単に言えば、これは単に**メソッド名**です。
- 残りのパラメーターは、メソッド（op）で必要とされる**値**です。

このページでは、**ARM64 で `lldb` を使ってこの情報を簡単に取得する方法**を確認できます。


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: メソッドが呼び出される対象のオブジェクト** |
| **2nd argument**  | **rsi**                                                         | **op: メソッド名**                             |
| **3rd argument**  | **rdx**                                                         | **メソッドの第 1 引数**                         |
| **4th argument**  | **rcx**                                                         | **メソッドの第 2 引数**                         |
| **5th argument**  | **r8**                                                          | **メソッドの第 3 引数**                         |
| **6th argument**  | **r9**                                                          | **メソッドの第 4 引数**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **メソッドの第 5 引数以降**                        |

### ObjectiveC metadata のダンプ

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) は、Objective-C binaries を class-dump するツールです。GitHub では dylibs が対象とされていますが、実行ファイルでも動作します。

```bash
./dynadump dump /path/to/bin
```

執筆時点では、これが**現在最もよく機能するものです**。

#### 通常のツール

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) は、Objective-C形式のコードでクラス、カテゴリ、プロトコルの宣言を生成する元祖ツールです。

古く、メンテナンスされていないため、正しく動作しない可能性があります。

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) は、最新のクロスプラットフォーム対応Objective-C class dumpです。既存のツールと比べて、iCDumpはAppleエコシステムに依存せずに実行でき、Pythonバインディングも提供します。

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## 静的Swift解析

SwiftバイナリはObjective-Cとの互換性があるため、[class-dump](https://github.com/nygard/class-dump/)を使って宣言を抽出できる場合がありますが、常にできるとは限りません。

**`jtool -l`**または**`otool -l`**のコマンドラインを使うと、**`__swift5`**プレフィックスで始まる複数のセクションを見つけられます。

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

[**これらのセクションに保存されている情報については、このブログ記事**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)で詳しく確認できます。<sup>[[5]](#references)</sup>

さらに、**Swiftバイナリにはsymbolsが含まれている場合があります**（たとえば、ライブラリは関数を呼び出せるようにsymbolsを保存する必要があります）。**symbolsには通常、関数名や属性に関する情報が読みにくい形式で含まれている**ため、非常に役立ちます。また、元の名前を取得できる「**demanglers**」もあります。

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dynamic Analysis

> [!WARNING]
> **デバッグの既定手順として SIP を無効にしないでください。** `com.apple.security.get-task-allow` が設定された開発ビルドは、SIP を有効にしたままデバッグできます。LLDB を試す前に、`codesign -d --entitlements :- /path/to/binary` で対象を確認してください。デバッガの entitlement だけでは、SIP で保護された対象にアクセスできません。<sup>[[15]](#references)</sup>
>
> hardened runtime を使用する配布アプリでは通常 `get-task-allow` が省略され、アタッチがブロックされます。可能であれば開発者から提供された debug build を使用してください。使い捨てのコピーに再署名すると、テスト対象の動作が変わる可能性があります。保護された対象のために SIP を無効にする必要がある場合は、普段使用しているマシンではなく、専用のテストマシンまたは VM を使用してください。<sup>[[16]](#references)</sup>

> [!WARNING]
> macOS で `cloudconfigurationd` などの **system binaries に instrument を適用する**には、**SIP を無効にする必要があります**（署名を削除するだけでは機能しません）。

### APIs

macOS には、プロセスに関する情報を取得できる興味深い API がいくつかあります。

- `proc_info`: 各プロセスの多くの情報を取得できる主要な API です。他のプロセスの情報を取得するには root 権限が必要ですが、特別な entitlements や mach ports は必要ありません。
- `libsysmon.dylib`: XPC functions を通じてプロセス情報を公開しますが、呼び出し側には `com.apple.sysmond.client` entitlement が必要です。

### Stackshot & microstackshots

**Stackshotting** は、実行中のすべてのスレッドの call stacks を含む、プロセスの状態を取得する手法です。デバッグ、パフォーマンス分析、特定時点におけるシステムの動作の把握に特に役立ちます。iOS と macOS では、**`sample`** や **`spindump`** などのツールを使って、複数の方法で stackshotting を実行できます。

### Sysdiagnose

このツール（`/usr/bini/ysdiagnose`）は基本的に、`ps` や `zprint` など、さまざまなコマンドを多数実行して、コンピューターから多くの情報を収集します。

**root** として実行する必要があります。また、デーモン `/usr/libexec/sysdiagnosed` には、`com.apple.system-task-ports` や `get-task-allow` など、非常に興味深い entitlements があります。

その plist は `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` にあり、次の 3 つの MachServices が宣言されています。

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp 内の古いアーカイブを削除します
- `com.apple.sysdiagnose.kernel.ipc`: 特別な port 23（kernel）
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C class を介した user mode interface。dict 内で 3 つの引数（`compress`、`display`、`run`）を渡せます

### Unified Logs

macOS は、アプリケーションの動作を分析する際に役立つ詳細なログを生成します。

一部のログフィールドには `<private>` タグが含まれ、ユーザーやデバイスを特定できる情報が隠されています。古い手順では、これらのフィールドを表示するために証明書をインストールする方法が説明されていることがあります。現在のデバッグガイダンスでは、代わりに対象を明示した構成プロファイルの `Enable-Private-Data`、またはアプリケーションごとの `OSLogPreferences` を使用します。動作はサブシステムや macOS のリリースによって異なる場合があります。古い証明書／プロファイルに関する説明は references に残されています。<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### 左パネル

Hopper の左パネルでは、バイナリのシンボル（**Labels**）、プロシージャと関数の一覧（**Proc**）、文字列（**Str**）を確認できます。ここに表示されるのはすべての文字列ではなく、Mac-O ファイル内の複数の領域（`_cstring` や `objc_methname` など）で定義された文字列です。

#### 中央パネル

中央パネルでは、**逆アセンブルされたコード**を確認できます。また、該当するアイコンをクリックすると、**raw** な逆アセンブル、**graph**、**decompiled**、**binary** として表示できます。

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

コードオブジェクトを右クリックすると、そのオブジェクトへの参照や、そこからの参照を確認したり、名前を変更したりできます（decompiled pseudocode では機能しません）。

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

さらに、**中央下部では Python コマンドを記述できます**。

#### 右パネル

右パネルでは、現在の状態に至った経緯を確認できる **navigation history**、この関数を呼び出すすべての **functions** と、この関数が呼び出すすべての functions を確認できる **call graph**、および **local variables** の情報などを確認できます。

### dtrace

ユーザーがアプリケーションに**非常に低いレベル**でアクセスできるようにし、**プログラムを trace** したり、実行フローを変更したりする方法を提供します。Dtrace は **probes** を使用します。probes は **kernel 全体に配置**されており、system calls の開始地点や終了地点などにあります。

DTrace は **`dtrace_probe_create`** 関数を使用して、各 system call の probe を作成します。これらの probe は、各 system call の **entry point と exit point** で発火します。DTrace とのやり取りには `/dev/dtrace` を使用しますが、これは root user のみが利用できます。<sup>[[1]](#references)</sup>

> [!TIP]
> SIP 保護を完全に無効にせずに Dtrace を有効にするには、recovery mode で次を実行します: `csrutil enable --without dtrace`
>
> 自分でコンパイルしたバイナリに対して **`dtrace`** または **`dtruss`** を実行することもできます。

利用可能な dtrace probes は、次のコマンドで取得できます:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

プローブ名は provider、module、function、name の4つの部分で構成されます（`fbt:mach_kernel:ptrace:entry`）。名前の一部を指定しない場合、DTrace はその部分にワイルドカードを適用します。

DTrace がプローブを有効化し、プローブが発火したときに実行するアクションを指定するには、D 言語を使用します。

詳しい説明と追加の例は、[https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) にあります。

#### 例

`man -k dtrace` を実行すると、**利用可能な DTrace スクリプト**を一覧表示できます。例：`sudo dtruss -n binary`

- インライン

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

カーネルトレース機能です。文書化されたコードは **`/usr/share/misc/trace.codes`** にあります。

`latency`、`sc_usage`、`fs_usage`、`trace` などのツールは、内部でこれを使用します。

`kdebug` とやり取りするには、`kern.kdebug` 名前空間で `sysctl` を使用します。使用する MIB は `sys/sysctl.h` に記載されており、関数は `bsd/kern/kdebug.c` に実装されています。

カスタムクライアントで kdebug とやり取りする場合、通常は次の手順を実行します。

- KERN_KDSETREMOVE で既存の設定を削除する
- KERN_KDSETBUF と KERN_KDSETUP でトレースを設定する
- KERN_KDGETBUF でバッファエントリ数を取得する
- KERN_KDPINDEX でトレースから自身のクライアントを取得する
- KERN_KDENABLE でトレースを有効にする
- KERN_KDREADTR を呼び出してバッファを読み取る
- 各スレッドとそのプロセスを対応付けるには、KERN_KDTHRMAP を呼び出す

この情報を取得するには、Apple のツール **`trace`** またはカスタムツール [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** を使用できます。

**Kdebug は一度に 1 つのクライアントしか利用できない点に注意してください。** そのため、k-debug を使用するツールは同時に 1 つしか実行できません。

### ktrace

`ktrace_*` API は `libktrace.dylib` に由来し、Kdebug の API をラップしています。そのため、クライアントは `ktrace_session_create` と `ktrace_events_[single/class]` を呼び出して特定のコードにコールバックを設定し、`ktrace_start` で開始できます。

**SIP が有効な状態でも**使用できます。

クライアントとして `ktrace` ユーティリティを使用できます。

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

または `tailspin`。

### kperf

kernel level profiling に使用され、`Kdebug` callout を使って構築されています。

基本的に、グローバル変数 `kernel_debug_active` がチェックされ、有効な場合は、呼び出し元の kernel frame の `Kdebug` code とアドレスを指定して `kperf_kdebug_handler` が呼び出されます。`Kdebug` code が選択されたものと一致すると、bitmap として設定された「actions」が適用されます（オプションについては `osfmk/kperf/action.h` を確認してください）。

Kperf には sysctl MIB テーブルもあります（root として実行）：`sysctl kperf`。これらの code は `osfmk/kperf/kperfbsd.c` にあります。

さらに、Kperf の機能の一部は `kpc` にあり、マシンのパフォーマンスカウンターに関する情報を提供します。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) は、プロセスが実行しているプロセス関連のアクション（たとえば、プロセスが新たに作成しているプロセス）の確認に非常に便利なツールです。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) は、プロセス間の関係を表示するツールです。\
**`sudo eslogger fork exec rename create > cap.json`** のようなコマンドで Mac の監視を開始します（このコマンドを実行するターミナルには FDA が必要です）。その後、json をこのツールに読み込むと、すべての関係を表示できます：

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) は、ファイルの作成、変更、削除などのイベントを監視します。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) は、Windows ユーザーには Microsoft Sysinternal の _Procmon_ としておなじみの外観と操作感を備えた GUI ツールです。このツールでは、さまざまな種類のイベントの記録を開始・停止でき、ファイル、プロセス、ネットワークなどのカテゴリでイベントをフィルタリングできます。また、記録したイベントを json 形式で保存できます。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) は Xcode の Developer tools の一部で、アプリケーションのパフォーマンス監視、memory leak の特定、filesystem のアクティビティ追跡に使用されます。

![Crescendo - Apple Instruments: Apple Instruments は Xcode の Developer tools の一部で、アプリケーションのパフォーマンス監視、memory leak の特定、filesystem のアクティビティ追跡に使用されます](<../../../images/image (1138).png>)

### fs_usage

プロセスが実行するアクションを追跡できます：

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) は、バイナリが使用している **libraries**、使用中の **files**、および **network** 接続を確認するのに役立ちます。\
また、バイナリのプロセスを **virustotal** と照合し、バイナリに関する情報を表示します。

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**このブログ記事**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)では、SIP が無効になっていてもデバッグを阻止するために **`PT_DENY_ATTACH`** を使用している **実行中のデーモンをデバッグする**例を確認できます。<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` は、値 **31** (`0x1f`) の Darwin 固有の `ptrace(2)` リクエストです。他の引数は無視されます。プロセスは fork せずにこれを直接呼び出し、後続の親プロセスによるトレースを拒否できます。<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU の状態と呼び出し順序

結果は、どの `ptrace` request が最初に XNU に到達するかによって異なります:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB が先に attach する:** `debugserver` は `PT_ATTACHEXC` を使用します。XNU はこれを `PT_ATTACH` に変換し、`KAUTH_PROCESS_CANTRACE` による認可を実行して、対象プロセスに `P_LTRACED` を設定します。その後の `PT_DENY_ATTACH` はこのフラグを検知し、`W_EXITCODE(ENOTSUP, 0)` で対象プロセスを終了させます。通常、LLDB ではステータス **45** (`0x2d`) と表示されます。
- **対象プロセスが先に拒否する:** XNU は `P_LNOATTACH` を設定します。後続の attach はプロセストレース認可によって拒否されます。attach のエラーパスは `P_LNOATTACH` を検知し、attach を試みたプロセスに `SIGSEGV` を送信するため、LLDB では `debugserver` との接続が失われたように見える場合があります。

これらの経路を見分けるには、起動または attach の前に `debugserver` のログを有効にし、その `ptrace` request を確認します:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 の静的な識別とバイパス

難読化されていない ARM64 Mach-O では、インポートされた `_ptrace` のスタブを見つけ、呼び出し箇所を調べます。最初の整数引数は `w0` で渡されるため、この命令列からアンチデバッグ要求を直接確認できます。このインポートがないからといって、確実に使われていないとは限りません。コードが `ptrace` を動的に解決することもあるためです。インポートされた `_sysctl` もアンチデバッグチェックを示す場合がありますが、これも動的に解決される可能性があります。<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

実演したサンプルでは、即値を `0x1f` から `0x0` にパッチすると、要求が `PT_TRACE_ME` に変わり、プログラムは LLDB の下で続行できます。これは**サンプル固有のバイパス**であり、一般的な no-op ではありません。要求を変更するか、呼び出しをスキップするか、成功を返すよう強制するかを決める前に、呼び出し元の戻り値チェックと制御フローを確認してください。<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb**は、**macOS**バイナリの**デバッグ**における**事実上のツール**です。

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

ホームフォルダに次の行を記述した **`.lldbinit`** というファイルを作成すると、lldbの使用時にintel flavourを設定できます：

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> lldb 内で、`process save-core` を使ってプロセスをダンプします

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>説明</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>実行を開始します。ブレークポイントに到達するか、プロセスが終了するまで実行が続きます。</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>実行を開始し、エントリーポイントで停止します。</td></tr>
<tr><td><strong>continue (c)</strong></td><td>デバッグ中のプロセスの実行を再開します。</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>次の命令を実行します。このコマンドは関数呼び出しをスキップします。</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>次の命令を実行します。<code>nexti</code> コマンドとは異なり、関数呼び出しの中に進みます。</td></tr>
<tr><td><strong>finish (f)</strong></td><td>現在の関数（フレーム）の残りの命令を実行し、戻って停止します。</td></tr>
<tr><td><strong>control + c</strong></td><td>実行を一時停止します。プロセスの実行（<code>r</code>）または再開（<code>c</code>）後に入力すると、現在実行中の位置で停止します。</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # main という名前の関数</p>
<p><code>b &lt;binname&gt;`main</code> # バイナリの main 関数</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # 指定したバイナリの main 関数</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # 任意の NSFileManager メソッド</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # このライブラリのすべての関数で停止</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # ブレークポイント一覧</p>
<p><code>br e/dis &lt;num&gt;</code> # ブレークポイントを有効化／無効化</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # breakpoint コマンドのヘルプを表示</p>
<p><code>help memory write</code> # メモリへの書き込みに関するヘルプを表示</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>メモリをヌル終端文字列として表示します。</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>メモリをアセンブリ命令として表示します。</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>メモリをバイトとして表示します。</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>パラメーターが参照するオブジェクトを表示します。</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Apple の Objective-C API やメソッドの多くはオブジェクトを返すため、「print object」(<code>po</code>) コマンドで表示します。<code>po</code> で意味のある出力が得られない場合は、<code>x/b</code> を使用してください。</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # そのアドレスに AAAA を書き込む<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # そのアドレスに AAAA を書き込む
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # 現在の関数を逆アセンブル</p>
<p><code>dis -n &lt;funcname&gt;</code> # 関数を逆アセンブル</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # 関数を逆アセンブル<br>
<code>dis -c 6</code> # 6 行を逆アセンブル<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # 指定したアドレス間を逆アセンブル<br>
<code>dis -p -c 4</code> # 現在のアドレスから逆アセンブルを開始</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # <code>x1</code> レジスター内の 3 要素の配列を調べる</td></tr>
<tr><td><strong>image dump sections</strong></td><td>現在のプロセスメモリのマップを表示します。</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # CoreNLP のすべてのシンボルのアドレスを取得</td></tr>
</tbody>
</table>

> [!TIP]
> **`objc_sendMsg`** 関数の呼び出し時、**rsi** レジスターには、ヌル終端（「C」）文字列として**メソッド名**が格納されます。lldb で名前を表示するには、次のようにします。
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### 動的解析の回避

#### VM 検知

- **`sysctl hw.model`** コマンドは、通常、物理ハードウェアでは Mac のモデル識別子を返しますが、VM では異なる値を返す場合があります。<sup>[[3]](#references)</sup>
- マルウェアによっては、**`hw.logicalcpu`** と **`hw.physicalcpu`** の値を操作して、VM かどうかを検知しようとします。<sup>[[4]](#references)</sup>
- MAC アドレス（00:50:56）を基に、マシンが **VMware** 上で動作しているかを**検知**するマルウェアもあります。
- 次のような簡単なコードで、**プロセスがデバッグ中かどうか**を確認することもできます。
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- **`PT_DENY_ATTACH`** フラグを指定して **`ptrace`** システムコールを呼び出すこともできます。順序に依存する XNU の動作、`debugserver` のログ、ARM64 のパッチ適用手順については、[PT_DENY_ATTACH section](#page-title) を確認してください。<sup>[[7]](#references)[[12]](#references)</sup>

- **`PT_DENY_ATTACH`** フラグを指定して **`ptrace`** システムコールを呼び出すこともできます。これにより、デバ**ッ**ガーがアタッチしてトレースするのを**防止**します。
  - **`sysctl`** 関数または **`ptrace`** 関数が**インポート**されているかを確認できます（ただし、マルウェアが動的にインポートする可能性があります）。
  - 次の解説記事「[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)」にあるように：<sup>[[7]](#references)</sup>\
    「_Process # exited with **status = 45 (0x0000002d)** というメッセージは、デバッグ対象が **PT_DENY_ATTACH** を使用していることを示す典型的な兆候です_」
#### `fork()` によるプロセスの引き継ぎ

プロセスは、起動直後に `fork()` を呼び出して親プロセスを終了させ（`fork()` は正の子 PID を返す）、保護対象の処理を子プロセス内でのみ続行することで（`fork()` は `0` を返す）、元の PID にアタッチしたままのデバッガーを回避できます。`dlsym(RTLD_DEFAULT, "fork")` で `fork` を解決すると、直接の `_fork` 呼び出し箇所もなくなりますが、これは解析を妨げるだけです。シンボル名の文字列と動的解決のデータフローは、Mach-O バイナリ内に残ります。<sup>[[13]](#references)[[14]](#references)</sup>

arm64 では、固定アドレスではなくデータフローを追って、このパターンを検出します。`dlsym` の最初の 2 つの引数は `x0` と `x1` で渡され、`RTLD_DEFAULT` は `-2`（たとえば `movn x0, #1`）として現れることがあります。また、`adrp`/`add` の組み合わせで `"fork"` 文字列のアドレスを構築するのが一般的です。`dlsym` のスタブへの `bl` の後、返されたポインターを `x0` からヌルチェックと格納箇所を経由して、後続の間接 `blr` まで追跡します。次に、`w0` 内の `fork()` の結果を追います。0 なら子プロセスの処理に進み、正の値または `-1` なら親プロセス／エラー処理に進みます。<sup>[[13]](#references)[[14]](#references)</sup>

静的な回避方法としては、間接呼び出しを抑止し、既存の結果チェックが子プロセス側の処理に進むようにします。たとえば、コンパイラーが以下の命令列を生成している場合、`blr` と結果の格納を `nop` にパッチし、合成したゼロの結果を設定して、比較／分岐ロジックはそのまま残します。これにより、子プロセスを作成せずに、元の PID のままアプリケーションの実行が続きます。命令レジスターと分岐先は、解析対象のビルドに合わせて調整する必要があります。<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## コアダンプ

コアダンプは、次の場合に作成されます。

- `kern.coredump` sysctl が 1 に設定されている場合（デフォルト）
- プロセスが suid/sgid ではない場合、または `kern.sugid_coredump` が 1 の場合（デフォルトは 0）
- `AS_CORE` の上限で操作が許可されている場合。`ulimit -c 0` を呼び出してコアダンプの作成を抑制し、`ulimit -c unlimited` で再度有効にできます。

この場合、コアダンプは `kern.corefile` sysctl の設定に従って生成され、通常は `/cores/core/.%P` に保存されます。

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash は**クラッシュしたプロセスを解析し、クラッシュレポートをディスクに保存します**。クラッシュレポートには、開発者がクラッシュの原因を**診断するのに役立つ**情報が含まれています。\
**per-user の launchd コンテキストで実行されている**アプリケーションやその他のプロセスの場合、ReportCrash は LaunchAgent として実行され、ユーザーの `~/Library/Logs/DiagnosticReports/` にクラッシュレポートを保存します。\
デーモン、**system の launchd コンテキストで実行されている**その他のプロセス、およびその他の特権プロセスの場合、ReportCrash は LaunchDaemon として実行され、システムの `/Library/Logs/DiagnosticReports` にクラッシュレポートを保存します。

クラッシュレポートが**Apple に送信される**ことを懸念している場合は、無効にできます。そうでなければ、クラッシュレポートは**サーバーがクラッシュした原因を特定する**のに役立ちます。

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### スリープ

macOSでfuzzingを行う間、Macがスリープしないようにします。

- systemsetup -setsleep Never
- pmset、システム設定
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH接続の切断

SSH接続経由でfuzzingを行う場合、セッションが切断されないようにすることが重要です。そのため、次のようにsshd_configファイルを変更します。

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### 内部ハンドラー

**次のページを確認してください**。指定した scheme または protocol の**処理を担当するアプリ**を特定する方法がわかります。


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### ネットワークプロセスの列挙

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

### Stateful Mach IPC fuzzing

特権デーモンが公開する Mach サービスは、非特権クライアントまたは sandbox 内のクライアントが send right を取得できる場合、有用な fuzzing 対象になります。デーモンの `MachServices` launchd エントリを起点に、[MIG analysis workflow](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) を使って message ID と handler の対応を調べます。バイト列を変更する前に、通常のクライアントがサービスを利用している間に MIG server routine でブレークし、有効な request message を seed input として保存します。必要な header field、message size、descriptor layout を維持し、dispatch で即座に失敗せず handler に到達するように mutation します。<sup>[[17]](#references)</sup>

多くの handler は先行する呼び出しに依存します。harness でサービスの状態を初期化し、各 fuzz input を **operation と引数のシーケンス** として処理します。setup request（open や create など）を送信し、返された identifier を保持して、後続の request で使用します。こうすることで、coverage feedback によって未初期化オブジェクトのチェックに繰り返し引っかかるのではなく、状態遷移を探索できます。<sup>[[17]](#references)</sup>

closed-source の対象では、MIG dispatch routine を呼び出す in-process harness に Jackalope/TinyInst で instrument を適用できます。[CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) は具体的な実装例ですが、他のサービスにそのまま使える harness ではありません。<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**すべての crash を実際の IPC 経路で検証してください。** direct-dispatch harness は Mach message に対する kernel の検証を省略するため、特に無効な out-of-line (OOL) memory や port descriptor を渡した場合、誤検出を生じる可能性があります。harness 内で有効な OOL backing memory を割り当てたうえで、元のサービスアクセス権を持つクライアントから `mach_msg` 経由で縮小した testcase を再生し、デーモンが引き続き crash することを確認します。<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI ツールで動作します。

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

多くの macOS GUI ツールで「**そのまま動作**」します。アプリケーションによっては、一意のファイル名、特定の拡張子、または sandbox container (`~/Library/Containers/com.apple.Safari/Data`) からファイルを読み込むことなど、追加の要件があります。

例：

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

### macOS Fuzzingに関する追加情報

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)



## References

- [1] [OS X インシデント対応: スクリプティングと分析](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/)
- [4] [No Starch Press - The Art of Mac Malware: 悪意のあるソフトウェアを分析するためのガイド](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - このブログ記事のこれらのセクションに保存された情報](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attachを使用するAppleバイナリのデバッグ](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug Techniquesの回避: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcodeの構造化ログと`Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - macOS unified logでprivate dataを表示する](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h`のリクエスト定義](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU `mach_process.c`の`ptrace`実装](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - ptrace internals: デバッガのアタッチを防ぐ仕組み](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - forkの例](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - dlsymとforkを使用するAnti-debugging technique](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - デバッグツールのentitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - hardened third-party appのデバッグ](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Breaking the Sound Barrier Part I: Mach Messagesを使ったCoreAudioのFuzzing](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
{{#include ../../../banners/hacktricks-training.md}}
