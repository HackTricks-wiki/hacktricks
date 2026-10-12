# macOS Apps - 調査、デバッグ、Fuzzing

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

[**disarmはこちらからダウンロードできます**](https://newosxbook.com/tools/disarm.html)。

> [!TIP]
> **`disarm`**は、圧縮されたIM4Pファイル（`kernelcache`など）にも対応しており、必要な部分だけを抽出したり、抽出せずにその部分を解析したりできます。

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
> **`Codesign`** は **macOS** で、**`ldid`** は **iOS** で利用できます。

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) は、**.pkg** ファイル（インストーラー）を検査し、インストール前に中身を確認するのに便利なツールです。\
これらのインストーラーには `preinstall` と `postinstall` の bash スクリプトが含まれており、マルウェアの作成者は通常、これらを悪用してマルウェアを**persist**させます。

### hdiutil

このツールは Apple のディスクイメージ（`.dmg`）ファイルを**マウント**し、何かを実行する前に検査できるようにします。

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

`/Volumes` にマウントされます

### Packed binaries

- エントロピーが高いか確認する
- 文字列を確認する（理解できる文字列がほとんどない場合は、packedされている）
- macOS用のUPX packerは `__XHDR` というセクションを生成する

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> Objective-Cで書かれたプログラムは、[Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)に**コンパイル**された後も、クラス宣言を**保持**します。クラス宣言には、次の名前と型が**含まれます**。

- 定義されたインターフェース
- インターフェースのメソッド
- インターフェースのインスタンス変数
- 定義されたプロトコル

バイナリのリバースをより難しくするために、これらの名前が難読化されている場合があることに注意してください。

### Function calling

Objective-Cを使用するバイナリで関数が呼び出されると、コンパイル済みコードはその関数を直接呼び出す代わりに、**`objc_msgSend`**を呼び出します。これが最終的な関数を呼び出します。

![Metadata - Function calling: Objective-Cを使用するバイナリで関数が呼び出されると、コンパイル済みコードはその関数を直接呼び出す代わりに、objc msgSend を呼び出します。これが...](<../../../images/image (305).png>)

この関数が受け取るパラメーターは次のとおりです。

- 第1パラメーター（**self**）は「**メッセージを受け取るクラスのインスタンスを指すポインター**」です。簡単に言えば、メソッドが呼び出される対象のオブジェクトです。クラスメソッドの場合、これはクラスオブジェクト全体のインスタンスになります。一方、インスタンスメソッドの場合、selfはオブジェクトとしてインスタンス化されたクラスのインスタンスを指します。
- 第2パラメーター（**op**）は「メッセージを処理するメソッドのセレクター」です。簡単に言えば、これは単に**メソッド名**です。
- 残りのパラメーターは、メソッド（op）が必要とする**値**です。

**ARM64で`lldb`を使ってこの情報を簡単に取得する**方法については、こちらのページを参照してください。


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: メソッドが呼び出される対象のオブジェクト** |
| **2nd argument**  | **rsi**                                                         | **op: メソッド名**                             |
| **3rd argument**  | **rdx**                                                         | **メソッドの第1引数**                         |
| **4th argument**  | **rcx**                                                         | **メソッドの第2引数**                         |
| **5th argument**  | **r8**                                                          | **メソッドの第3引数**                         |
| **6th argument**  | **r9**                                                          | **メソッドの第4引数**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **メソッドの第5引数以降**                        |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump)は、Objective-Cバイナリをclass-dumpするツールです。GitHubの説明ではdylibが対象とされていますが、実行ファイルにも使用できます。

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

[**class-dump**](https://github.com/nygard/class-dump/) は、Objective-C形式のコード内にあるクラス、カテゴリ、プロトコルの宣言を生成する元祖のツールです。

古く、メンテナンスもされていないため、正常に動作しない可能性があります。

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) は、最新のクロスプラットフォーム対応Objective-C class dumpです。既存のツールと比べて、iCDumpはAppleエコシステムに依存せずに実行でき、Python bindingsを公開しています。

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Static Swift の分析

Swift バイナリでは、Objective-C との互換性があるため、[class-dump](https://github.com/nygard/class-dump/) を使って宣言を抽出できる場合がありますが、常にできるとは限りません。

**`jtool -l`** または **`otool -l`** のコマンドラインを使うと、**`__swift5`** というプレフィックスで始まる複数のセクションを見つけられます。

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

これらのセクションに保存されている[**情報については、このブログ記事**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)で詳しく説明されています。<sup>[[5]](#references)</sup>

さらに、**Swiftバイナリにはsymbolsが含まれている場合があります**（たとえば、ライブラリは関数を呼び出せるようにsymbolsを保存する必要があります）。**symbolsには通常、関数名や属性に関する情報が含まれていますが、表記が読みにくいため**、非常に役立ちます。また、元の名前を取得できる「**demanglers**」もあります。

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## 動的解析

> [!WARNING]
> バイナリをデバッグするには、**SIPを無効にする**（`csrutil disable` または `csrutil enable --without debug`）か、バイナリを一時フォルダにコピーして `codesign --remove-signature <binary-path>` で**署名を削除**するか、バイナリのデバッグを許可する必要があります（[このスクリプト](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)を使用できます）。

> [!WARNING]
> macOSで（`cloudconfigurationd` などの）**システムバイナリに計装を行う**には、**SIPを無効にする必要があります**（署名を削除するだけでは機能しません）。

### API

macOSには、プロセスに関する情報を取得できる便利なAPIがいくつかあります。

- `proc_info`: 各プロセスに関する多くの情報を提供する主要なAPIです。他のプロセスの情報を取得するにはroot権限が必要ですが、特別なentitlementやmach portは必要ありません。
- `libsysmon.dylib`: XPC関数を通じてプロセス情報を提供しますが、呼び出し側には `com.apple.sysmond.client` entitlementが必要です。

### Stackshot & microstackshots

**Stackshot**は、実行中のすべてのスレッドのコールスタックを含む、プロセスの状態を取得する手法です。特定の時点におけるデバッグ、パフォーマンス分析、システムの動作の理解に特に役立ちます。iOSとmacOSでは、**`sample`**や**`spindump`**などのツールや方法を使ってstackshotを取得できます。

### Sysdiagnose

このツール（`/usr/bini/ysdiagnose`）は基本的に、`ps`や`zprint`など、数十種類のコマンドを実行してコンピュータから大量の情報を収集します。

**root**として実行する必要があり、デーモン `/usr/libexec/sysdiagnosed` には `com.apple.system-task-ports` や `get-task-allow` など、非常に興味深いentitlementがあります。

plistは `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` にあり、3つのMachServicesが宣言されています。

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp 内の古いアーカイブを削除します
- `com.apple.sysdiagnose.kernel.ipc`: 特殊ポート23（kernel）
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-Cクラスを介したユーザーモードインターフェース。dict内の3つの引数（`compress`、`display`、`run`）を渡せます

### 統合ログ

macOSは、アプリケーションの動作を分析する際に役立つ詳細なログを生成します。

一部のログフィールドには、ユーザーやデバイスを特定できる情報を隠すために `<private>` というタグが含まれています。古い手順では、これらのフィールドを表示するために証明書をインストールする方法が説明されている場合があります。現在のデバッグ手順では、代わりに `Enable-Private-Data` を含む、明示的にスコープを限定した構成プロファイル、またはアプリケーション単位の `OSLogPreferences` を使用します。動作はサブシステムやmacOSのリリースによって異なる場合があります。古い証明書やプロファイルに関する説明は参考資料に残されています。 <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### 左パネル

Hopperの左パネルでは、バイナリのシンボル（**Labels**）、プロシージャと関数の一覧（**Proc**）、文字列（**Str**）を確認できます。ここに表示されるのはすべての文字列ではなく、Mac-Oファイルの複数の部分（_cstringや`objc_methname`など）で定義されたものです。

#### 中央パネル

中央パネルでは**逆アセンブルされたコード**を確認できます。それぞれのアイコンをクリックすると、**raw**形式、**graph**形式、**decompiled**形式、**binary**形式で逆アセンブル結果を表示できます。

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

コードオブジェクトを右クリックすると、そのオブジェクトへの参照やそのオブジェクトからの参照を確認したり、名前を変更したりできます（decompiled pseudocodeでは機能しません）。

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

また、**中央下部ではPythonコマンドを入力できます**。

#### 右パネル

右パネルでは、現在の状態に至った経緯を確認できる**ナビゲーション履歴**、この関数を呼び出すすべての**関数**と、この関数が呼び出すすべての関数を確認できる**コールグラフ**、**ローカル変数**の情報などを確認できます。

### dtrace

ユーザーがアプリケーションに**非常に低いレベル**でアクセスし、**プログラムをトレース**したり、実行フローを変更したりできるようにします。Dtraceは、**kernel内のさまざまな場所に配置されたprobe**を使用します。たとえば、システムコールの開始時や終了時などに配置されています。

DTraceは**`dtrace_probe_create`**関数を使って、各システムコールのprobeを作成します。これらのprobeは、**各システムコールのentry pointとexit point**で発火します。DTraceとのやり取りには `/dev/dtrace` を使用しますが、これはrootユーザーのみが利用できます。<sup>[[1]](#references)</sup>

> [!TIP]
> SIP保護を完全に無効にせずにDtraceを有効にするには、リカバリモードで次のコマンドを実行します: `csrutil enable --without dtrace`
>
> 自分で**コンパイルした**バイナリに対して、**`dtrace`**や**`dtruss`**を実行することもできます。

dtraceで利用可能なprobeは、次のコマンドで取得できます:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

プローブ名は4つの部分（provider、module、function、name）で構成されます（`fbt:mach_kernel:ptrace:entry`）。名前の一部を指定しない場合、Dtraceはその部分にワイルドカードを適用します。

DTraceでプローブを有効化し、プローブが発火したときに実行するアクションを指定するには、D languageを使用します。

詳しい説明とその他の例は、[https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)を参照してください。

#### 例

`man -k dtrace`を実行すると、**利用可能なDTraceスクリプト**の一覧が表示されます。例：`sudo dtruss -n binary`

- インライン

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- スクリプト

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

これはカーネルのトレース機能です。文書化されたコードは **`/usr/share/misc/trace.codes`** にあります。

`latency`、`sc_usage`、`fs_usage`、`trace` などのツールは、内部でこれを使用します。

`kdebug` とやり取りするには、`kern.kdebug` 名前空間の `sysctl` を使用します。使用する MIB は `sys/sysctl.h` にあり、関数は `bsd/kern/kdebug.c` に実装されています。

カスタムクライアントで kdebug とやり取りする場合、通常は次の手順を実行します。

- KERN_KDSETREMOVE で既存の設定を削除する
- KERN_KDSETBUF と KERN_KDSETUP でトレースを設定する
- KERN_KDGETBUF でバッファエントリ数を取得する
- KERN_KDPINDEX でトレースから自身のクライアントを取得する
- KERN_KDENABLE でトレースを有効にする
- KERN_KDREADTR を呼び出してバッファを読み取る
- 各スレッドをプロセスに対応付けるには、KERN_KDTHRMAP を呼び出す

この情報を取得するには、Apple のツール **`trace`** またはカスタムツール [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** を使用できます。

**Kdebug は一度に1つのクライアントのみ利用できます。** そのため、k-debug を利用するツールは同時に1つだけ実行できます。

### ktrace

`ktrace_*` API は `libktrace.dylib` にあり、Kdebug の API をラップしています。そのため、クライアントは `ktrace_session_create` と `ktrace_events_[single/class]` を呼び出して特定のコードにコールバックを設定し、その後 `ktrace_start` でトレースを開始できます。

**SIP が有効な状態でも**使用できます。

クライアントとして `ktrace` ユーティリティを使用できます。

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

または `tailspin`。

### kperf

これは kernel level profiling に使用され、`Kdebug` callouts を使って構築されています。

基本的には、グローバル変数 `kernel_debug_active` が確認され、有効な場合は、呼び出し元の kernel frame の `Kdebug` code と address を使って `kperf_kdebug_handler` が呼び出されます。`Kdebug` code が選択されたものと一致すると、bitmap として設定された「actions」が適用されます（選択肢は `osfmk/kperf/action.h` を確認してください）。

Kperf には sysctl MIB table もあります（root として実行）：`sysctl kperf`。これらの code は `osfmk/kperf/kperfbsd.c` にあります。

さらに、Kperf の機能の一部は、マシンの performance counters に関する情報を提供する `kpc` にあります。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) は、プロセスが実行しているプロセス関連のアクション（たとえば、プロセスが新たに作成しているプロセスの監視）を確認するのに非常に便利なツールです。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) は、プロセス間の関係を表示するツールです。\
**`sudo eslogger fork exec rename create > cap.json`** のようなコマンドで Mac を監視する必要があります（このコマンドを実行するターミナルには FDA が必要です）。その後、このツールで json を読み込み、すべての関係を表示できます。

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) は、作成、変更、削除などのファイルイベントを監視します。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) は、Windows ユーザーには Microsoft Sysinternal の _Procmon_ として知られているかもしれない、同様の外観と操作感を備えた GUI ツールです。このツールでは、さまざまな種類のイベントの記録を開始・停止できます。また、ファイル、プロセス、ネットワークなどのカテゴリでイベントをフィルタリングでき、記録したイベントを json 形式で保存する機能もあります。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) は Xcode の Developer tools の一部で、アプリケーションのパフォーマンス監視、メモリ leak の特定、ファイルシステムのアクティビティ追跡に使用されます。

![Crescendo - Apple Instruments: Apple Instruments は Xcode の Developer tools の一部で、アプリケーションのパフォーマンス監視、メモリ leak の特定、ファイルシステムのアクティビティ追跡に使用されます](<../../../images/image (1138).png>)

### fs_usage

プロセスが実行するアクションを追跡できます：

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) は、バイナリが使用している**ライブラリ**、使用中の**ファイル**、**ネットワーク**接続を確認するのに便利です。\
また、バイナリのプロセスを**virustotal**と照合し、バイナリに関する情報を表示します。

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**このブログ記事**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)では、SIPが無効でもデバッグを阻止するために**`PT_DENY_ATTACH`**を使用する**実行中のデーモンをデバッグする**方法の例を紹介しています。<sup>[[6]](#references)</sup>

### lldb

**lldb**は、**macOS**のバイナリ**デバッグ**における事実上の標準ツールです。

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

lldbでIntel形式を設定するには、ホームフォルダーに次の行を含む **`.lldbinit`** というファイルを作成します:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> lldb 内で、`process save-core` を使ってプロセスをダンプします

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) コマンド</strong></td><td><strong>説明</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>実行を開始します。ブレークポイントに到達するか、プロセスが終了するまで実行が続きます。</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>実行を開始し、エントリポイントで停止します。</td></tr>
<tr><td><strong>continue (c)</strong></td><td>デバッグ中のプロセスの実行を再開します。</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>次の命令を実行します。このコマンドは関数呼び出しをステップオーバーします。</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>次の命令を実行します。<code>nexti</code> コマンドとは異なり、このコマンドは関数呼び出しの中にステップインします。</td></tr>
<tr><td><strong>finish (f)</strong></td><td>現在の関数（フレーム）の残りの命令を実行し、戻り値を返して停止します。</td></tr>
<tr><td><strong>control + c</strong></td><td>実行を一時停止します。プロセスが実行（<code>r</code>）または再開（<code>c</code>）されている場合、その時点で実行中の場所で停止します。</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # main という名前の関数</p>
<p><code>b &lt;binname&gt;`main</code> # バイナリの main 関数</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # 指定したバイナリの main 関数</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # 任意の NSFileManager メソッド</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # そのライブラリのすべての関数でブレーク</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # ブレークポイント一覧</p>
<p><code>br e/dis &lt;num&gt;</code> # ブレークポイントの有効化／無効化</p>
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
<p>Apple の Objective-C API やメソッドの多くはオブジェクトを返すため、「print object」(<code>po</code>) コマンドで表示します。<code>po</code> で有用な出力が得られない場合は、<code>x/b</code> を使用してください。</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # そのアドレスに AAAA を書き込みます<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # そのアドレスに AAAA を書き込みます
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # 現在の関数を逆アセンブル</p>
<p><code>dis -n &lt;funcname&gt;</code> # 関数を逆アセンブル</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # 関数を逆アセンブル<br>
<code>dis -c 6</code> # 6 行を逆アセンブル<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # あるアドレスから別のアドレスまで逆アセンブル<br>
<code>dis -p -c 4</code> # 現在のアドレスから逆アセンブルを開始</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # <code>x1</code> レジスター内の 3 要素の配列を調べます</td></tr>
<tr><td><strong>image dump sections</strong></td><td>現在のプロセスメモリのマップを表示します。</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # CoreNLP のすべてのシンボルのアドレスを取得します</td></tr>
</tbody>
</table>

> [!TIP]
> **`objc_sendMsg`** 関数の呼び出し時、**rsi** レジスターには、ヌル終端の「C」文字列として**メソッド名**が格納されます。lldb で名前を表示するには、次のようにします。
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### 動的解析対策

#### VM 検出

- **`sysctl hw.model`** コマンドは通常、物理ハードウェアでは Mac のモデル識別子を返し、VM では異なる値を返すことがあります。<sup>[[3]](#references)</sup>
- 一部のマルウェアは、**`hw.logicalcpu`** と **`hw.physicalcpu`** の値を操作して、VM かどうかを検出しようとします。<sup>[[4]](#references)</sup>
- 一部のマルウェアは、MAC アドレス（00:50:56）を基に、そのマシンが **VMware** 上で動作しているかどうかも**検出**できます。
- 次のような簡単なコードで、**プロセスがデバッグされているかどうか**を確認することもできます。
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- **`PT_DENY_ATTACH`** フラグを指定して **`ptrace`** システムコールを呼び出すこともできます。これはデバッガーによるアタッチとトレースを**防ぎます**。
  - **`sysctl`** 関数または **`ptrace`** 関数が**インポート**されているか確認できます（ただし、マルウェアは動的にインポートする場合があります）
  - この writeup「[アンチデバッグ手法の回避：macOS ptrace の亜種](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)」で述べられているように、<sup>[[7]](#references)</sup>\
    「_Process # exited with **status = 45 (0x0000002d)** というメッセージは、デバッグ対象が **PT_DENY_ATTACH** を使用していることを示す典型的な兆候です_」

#### `fork()` によるプロセス引き継ぎ

プロセスは、起動直後に `fork()` を呼び出し、親プロセスを終了（`fork()` は正の子 PID を返します）させ、子プロセス内でのみ保護された処理を続行（`fork()` は `0` を返します）することで、元の PID にアタッチしたままのデバッガーを回避できます。`dlsym(RTLD_DEFAULT, "fork")` で `fork` を解決すると、直接の `_fork` 呼び出し箇所もなくなりますが、これは解析を困難にするだけです。シンボル名の文字列と動的解決のデータフローは、Mach-O バイナリ内に依然として見えています。<sup>[[10]](#references)[[11]](#references)</sup>

arm64 では、固定アドレスではなくデータフローを追跡してこのパターンを検出します。`dlsym` の最初の 2 つの引数は `x0` と `x1` で渡され、`RTLD_DEFAULT` は `-2`（たとえば `movn x0, #1`）として現れることがあります。また、`adrp`/`add` の組み合わせで `"fork"` 文字列のアドレスを構築するのが一般的です。`dlsym` スタブへの `bl` の後、返されたポインターを `x0` からヌルチェックと格納処理を経て、後続の間接 `blr` まで追跡します。続いて `fork()` の結果を `w0` で追います。値がゼロなら子プロセス側の処理へ進み、正の値と `-1` なら親プロセス／エラー側の処理へ進みます。<sup>[[10]](#references)[[11]](#references)</sup>

静的な回避方法は、間接呼び出しを抑止し、既存の結果チェックが子プロセス側へ進むようにすることです。たとえば、コンパイラーが以下に示す命令列を生成している場合、`blr` と結果の格納を `nop` にパッチし、合成したゼロの結果を設定して、比較／分岐ロジックはそのまま残します。これにより、子プロセスを作成せずに、元の PID のままアプリケーションが続行します。命令レジスターと分岐先は、解析対象のビルドに合わせて調整する必要があります。<sup>[[10]](#references)[[11]](#references)</sup>

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

コアダンプは次の場合に作成されます。

- `kern.coredump` sysctl が 1 に設定されている（デフォルト）
- プロセスが suid/sgid ではない、または `kern.sugid_coredump` が 1 に設定されている（デフォルトは 0）
- `AS_CORE` 制限が操作を許可している。`ulimit -c 0` を実行するとコアダンプの作成を抑止でき、`ulimit -c unlimited` で再び有効にできます。

このような場合、コアダンプは `kern.corefile` sysctl の設定に従って生成され、通常は `/cores/core/.%P` に保存されます。

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash は、**クラッシュしたプロセスを解析し、クラッシュレポートをディスクに保存**します。クラッシュレポートには、クラッシュの原因を**開発者が診断するのに役立つ**情報が含まれています。\
**ユーザーごとの launchd コンテキストで実行されている**アプリケーションやその他のプロセスの場合、ReportCrash は LaunchAgent として実行され、ユーザーの `~/Library/Logs/DiagnosticReports/` にクラッシュレポートを保存します。\
デーモン、**システムの launchd コンテキストで実行されている**その他のプロセス、およびその他の特権プロセスの場合、ReportCrash は LaunchDaemon として実行され、システムの `/Library/Logs/DiagnosticReports` にクラッシュレポートを保存します。

クラッシュレポートが**Apple に送信される**ことが心配な場合は、無効にできます。無効にしない場合、クラッシュレポートは**サーバーのクラッシュ原因を特定する**のに役立ちます。

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### スリープ

macOSでfuzzingを行う際は、Macがスリープしないようにします。

- systemsetup -setsleep Never
- pmset、システム設定
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSHの切断

SSH接続経由でfuzzingを行う場合は、セッションが切断されないようにすることが重要です。そのため、次のようにsshd_configファイルを変更します。

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### 内部ハンドラー

**次のページを確認して**、**指定した scheme または protocol の処理を担当するアプリ**を特定する方法を確認してください。


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

### ファザー

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI toolsで動作します

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

多くのmacOS GUI toolsで「**そのまま動作**」します。一部のアプリケーションには、固有のファイル名、特定の拡張子、またはSandbox container（`~/Library/Containers/com.apple.Safari/Data`）からファイルを読み込むなど、追加の要件があります。

例をいくつか紹介します。

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

### macOS Fuzzing に関するその他の情報

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [OS X インシデントレスポンス: スクリプティングと分析](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Fuzz の夏: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Mac Malware の技法、第I巻: 分析](https://taomm.org/)
- [4] [No Starch Press - Mac Malware の技法: 悪意のあるソフトウェアを分析するためのガイド](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - このブログ記事のセクションに保存された情報](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attach を使用する Apple バイナリのデバッグ](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug テクニックの回避: macOS ptrace のバリエーション](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode の構造化ログと `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - macOS unified log で private data を表示する](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - fork の例](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - dlsym と fork を使用する Anti-debugging テクニック](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
