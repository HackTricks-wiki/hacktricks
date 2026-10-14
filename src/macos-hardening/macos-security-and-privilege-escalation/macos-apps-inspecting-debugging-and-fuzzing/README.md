# macOS Apps - インスペクション、デバッグ、Fuzzing

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

### Disarm (旧 jtool2)

[**ここから disarm をダウンロードできます**](https://newosxbook.com/tools/disarm.html)。

> [!TIP]
> **`disarm`** は圧縮された IM4P ファイル（`kernelcache` など）にも対応しており、必要な部分だけを抽出したり、抽出せずに必要な部分を解析したりできます。

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
> **`Codesign`** は **macOS** で、**`ldid`** は **iOS** で見つけることができます。

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) は、**.pkg** ファイル（インストーラー）を調べ、インストール前に中身を確認するのに便利なツールです。\
これらのインストーラーには `preinstall` と `postinstall` の bash スクリプトが含まれており、マルウェア作者は通常、これらを悪用して**マルウェア**を**永続化**させます。

### hdiutil

このツールは Apple のディスクイメージ（`.dmg`）ファイルを**マウント**し、何かを実行する前に調査できるようにします:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

`/Volumes` にマウントされます

### Packed binaries

- エントロピーが高いか確認する
- strings を確認する（理解できる文字列がほとんどない場合は、packed されている）
- macOS 用の UPX packer は `__XHDR` というセクションを生成する

## Objective-C の静的解析

### メタデータ

> [!CAUTION]
> Objective-C で書かれたプログラムは、[Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) に **コンパイル** されても、クラス宣言を **保持** します。これらのクラス宣言には、以下の名前と型が **含まれます**。

- 定義されているインターフェース
- インターフェースのメソッド
- インターフェースのインスタンス変数
- 定義されているプロトコル

なお、binary のリバースを難しくするため、これらの名前は難読化されている場合があります。

### 関数呼び出し

Objective-C を使用する binary で関数が呼び出されると、コンパイルされたコードはその関数を直接呼び出すのではなく、**`objc_msgSend`** を呼び出します。これは最終的に関数を呼び出します。

![メタデータ - 関数呼び出し: Objective-C を使用する binary で関数が呼び出されると、コンパイルされたコードはその関数を直接呼び出すのではなく、objc_msgSend を呼び出します。これは最終的に...](<../../../images/image (305).png>)

この関数が受け取るパラメーターは次のとおりです。

- 第1パラメーター（**self**）は、「**メッセージを受け取るクラスのインスタンスを指すポインター**」です。より簡単に言うと、メソッドが呼び出される対象のオブジェクトです。メソッドがクラスメソッドの場合、これはクラスオブジェクト全体のインスタンスになります。一方、インスタンスメソッドの場合、self はオブジェクトとしてインスタンス化されたクラスのインスタンスを指します。
- 第2パラメーター（**op**）は、「メッセージを処理するメソッドのセレクター」です。より簡単に言うと、これは単に**メソッド名**です。
- 残りのパラメーターは、メソッド（op）が必要とする**値**です。

**ARM64 で `lldb` を使ってこの情報を簡単に取得する方法**はこちらを参照してください。

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **引数**        | **レジスター**                                                 | **（objc_msgSend の）**                          |
| --------------- | -------------------------------------------------------------- | ------------------------------------------------ |
| **第1引数**     | **rdi**                                                        | **self: メソッドが呼び出される対象のオブジェクト** |
| **第2引数**     | **rsi**                                                        | **op: メソッド名**                               |
| **第3引数**     | **rdx**                                                        | **メソッドの第1引数**                            |
| **第4引数**     | **rcx**                                                        | **メソッドの第2引数**                            |
| **第5引数**     | **r8**                                                         | **メソッドの第3引数**                            |
| **第6引数**     | **r9**                                                         | **メソッドの第4引数**                            |
| **第7引数以降** | <p><strong>rsp+</strong><br><strong>（スタック上）</strong></p> | **メソッドの第5引数以降**                       |

### ObjectiveC メタデータのダンプ

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) は Objective-C binaries の class-dump を行うツールです。GitHub の説明では dylibs が対象とされていますが、実行ファイルでも使用できます。

```bash
./dynadump dump /path/to/bin
```

執筆時点では、これが**現在最もよく機能するもの**です。

#### 通常のツール

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) は、Objective-C形式のコードに含まれるクラス、カテゴリ、プロトコルの宣言を生成する元祖ツールです。

古く、メンテナンスもされていないため、正常に動作しない可能性があります。

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) は、最新のクロスプラットフォーム対応Objective-C class dumpツールです。既存のツールと異なり、iCDumpはAppleエコシステムに依存せずに動作し、Pythonバインディングを提供します。

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Swiftの静的解析

Swiftバイナリでは、Objective-Cとの互換性により、[class-dump](https://github.com/nygard/class-dump/)を使って宣言を抽出できる場合がありますが、常にできるわけではありません。

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

これらのセクションに保存されている[**情報については、このブログ記事**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)で詳しく説明されています。<sup>[[5]](#references)</sup>

さらに、**Swiftバイナリにはsymbolsが含まれている場合があります**（たとえば、ライブラリは関数を呼び出せるようにsymbolsを保存する必要があります）。**symbolsには通常、関数名や属性に関する情報が含まれています**が、読みにくい形式になっています。そのため非常に役立ちます。また、元の名前を取得できる「**demangler**」もあります。

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## 動的解析

> [!WARNING]
> **デバッグの手順として、デフォルトでSIPを無効にしないでください。** `com.apple.security.get-task-allow` を持つ開発ビルドは、SIPを有効にしたままデバッグできます。LLDBを試す前に、`codesign -d --entitlements :- /path/to/binary` で対象を確認してください。デバッガのentitlementだけでは、SIPで保護された対象へのアクセスは許可されません。<sup>[[15]](#references)</sup>
>
> 配布アプリでは通常、hardened runtimeによって `get-task-allow` が省かれ、デバッガのアタッチがブロックされます。可能であれば開発者から提供されたデバッグビルドを使用してください。使い捨てコピーに再署名すると、検証対象の動作が変わる可能性があります。保護された対象のデバッグにSIPの無効化が必要な場合は、普段使用しているマシンではなく、専用のテストマシンまたはVMを使用してください。<sup>[[16]](#references)</sup>
>
> 以前、隔離されたテスト環境で保護された対象を扱うため、次の代替手段が案内されていました。
>
> バイナリをデバッグするには、SIPを無効にする（`csrutil disable` または `csrutil enable --without debug`）、バイナリを一時フォルダにコピーして `codesign --remove-signature <binary-path>` で署名を削除する、またはバイナリのデバッグを許可する必要がある点に注意してください（[このスクリプト](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)を使用できます）。
>
> これはSIPに関する一般的な要件ではありません。デバッグビルドを優先してください。また、コピーや署名の変更によって検証対象の動作が変わる可能性がある点にも注意してください。

> [!WARNING]
> macOSで `cloudconfigurationd` などの**システムバイナリに計装を施す**には、**SIPを無効にする必要があります**（署名を削除するだけでは不十分です）。

### API

macOSには、プロセスに関する情報を取得できる興味深いAPIがいくつかあります。

- `proc_info`: 各プロセスについて多くの情報を提供する主要なAPIです。他のプロセスの情報を取得するにはroot権限が必要ですが、特別なentitlementやMach portは必要ありません。
- `libsysmon.dylib`: XPC関数を通じてプロセス情報を提供しますが、呼び出し元には `com.apple.sysmond.client` entitlementが必要です。

### Stackshotとmicrostackshots

**Stackshot**は、実行中のすべてのスレッドのコールスタックを含む、プロセスの状態を取得する技術です。デバッグ、パフォーマンス分析、特定の時点におけるシステムの動作の把握に特に役立ちます。iOSおよびmacOSでは、**`sample`**や**`spindump`**などのツールを使ってStackshotを取得できます。

### Sysdiagnose

このツール（`/usr/bini/ysdiagnose`）は、`ps`や`zprint`など数十種類のコマンドを実行し、コンピュータから大量の情報を収集します。

**root**として実行する必要があります。また、デーモン `/usr/libexec/sysdiagnosed` は、`com.apple.system-task-ports`や`get-task-allow`など、非常に興味深いentitlementを持っています。

そのplistは `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` にあり、3つのMachServicesを宣言しています。

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp にある古いアーカイブを削除します
- `com.apple.sysdiagnose.kernel.ipc`: 特別なポート23（kernel）
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C classを通じたユーザーモードのインターフェイス。dictで3つの引数（`compress`、`display`、`run`）を渡せます

### Unified Logs

macOSは、アプリケーションの動作を分析する際に役立つ詳細なログを生成します。

一部のログフィールドには、ユーザーやデバイスを特定できる情報を隠すために `<private>` タグが含まれています。以前の手順では、これらのフィールドを表示するために証明書をインストールする方法が説明されていることがあります。現在のデバッグガイダンスでは、明示的にスコープを指定した `Enable-Private-Data` 構成プロファイル、またはアプリケーションごとの `OSLogPreferences` を使用します。挙動はサブシステムやmacOSのリリースによって異なる場合があります。以前の証明書／プロファイルに関する説明は参考文献に残されています。 <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### 左パネル

Hopperの左パネルでは、バイナリのシンボル（**Labels**）、プロシージャと関数の一覧（**Proc**）、文字列（**Str**）を確認できます。ここに表示されるのはすべての文字列ではなく、Mac-Oファイルの複数の領域（_cstringや`objc_methname`など）で定義された文字列です。

#### 中央パネル

中央パネルでは**逆アセンブルされたコード**を確認できます。該当するアイコンをクリックすると、**raw**な逆アセンブル、**graph**、**decompiled**、**binary**として表示できます。

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

コードオブジェクトを右クリックすると、そのオブジェクトへの／からの**参照**を確認したり、名前を変更したりできます（decompiled pseudocodeでは機能しません）。

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

さらに、**中央下部ではPythonコマンドを入力できます**。

#### 右パネル

右パネルでは、現在の状態に至った経緯を確認できる**ナビゲーション履歴**、この関数を**呼び出す関数**と、この関数が**呼び出す関数**をすべて確認できる**コールグラフ**、および**ローカル変数**の情報などを確認できます。

### dtrace

アプリケーションに対する**非常に低レベル**なアクセスを可能にし、**プログラムをトレース**したり、実行フローを変更したりできます。DTraceは、カーネル全体に配置された**probe**を使用します。probeはシステムコールの開始時や終了時などに設置されます。

DTraceは、各システムコールにprobeを作成するために**`dtrace_probe_create`**関数を使用します。これらのprobeは、**各システムコールの開始地点と終了地点**で発火します。DTraceとのやり取りには /dev/dtrace を使用しますが、これはrootユーザーのみ利用できます。<sup>[[1]](#references)</sup>

> [!TIP]
> SIPの保護を完全に無効にせずにDTraceを有効にするには、リカバリーモードで次を実行します: `csrutil enable --without dtrace`
>
> **自分でコンパイルした**バイナリに対して、**`dtrace`**や**`dtruss`**を使用することもできます。

利用可能なdtraceのprobeは、次のコマンドで確認できます。

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

プローブ名は、provider、module、function、name の4つの部分で構成されます（`fbt:mach_kernel:ptrace:entry`）。名前の一部を指定しない場合、DTrace はその部分にワイルドカードを適用します。

DTrace でプローブを有効化し、プローブが発火したときに実行するアクションを指定するには、D 言語を使用します。

詳しい説明とその他の例については、[https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) を参照してください。

#### 例

`man -k dtrace` を実行すると、**利用可能な DTrace スクリプト**を一覧表示できます。例：`sudo dtruss -n binary`

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

kernel tracing facilityです。documented codeは **`/usr/share/misc/trace.codes`** にあります。

`latency`、`sc_usage`、`fs_usage`、`trace` などのツールは、内部でこれを使用します。

`kdebug` とやり取りするには、`kern.kdebug` namespaceの `sysctl` を使用します。使用するMIBは `sys/sysctl.h` にあり、関数は `bsd/kern/kdebug.c` に実装されています。

カスタムclientでkdebugとやり取りする場合、通常は次の手順を実行します。

- KERN_KDSETREMOVEで既存の設定を削除する
- KERN_KDSETBUFとKERN_KDSETUPでtraceを設定する
- KERN_KDGETBUFでbuffer entryの数を取得する
- KERN_KDPINDEXでtraceから自分のclientを取得する
- KERN_KDENABLEでtracingを有効にする
- KERN_KDREADTRを呼び出してbufferを読み取る
- 各threadをそのprocessと対応づけるには、KERN_KDTHRMAPを呼び出す

この情報を取得するには、Appleのツール **`trace`** またはカスタムツール [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** を使用できます。

**Kdebugは一度に1つのclientしか利用できないことに注意してください。** そのため、k-debugを利用するツールは一度に1つしか実行できません。

### ktrace

`ktrace_*` APIは `libktrace.dylib` に由来し、KdebugのAPIをラップしています。そのため、clientは `ktrace_session_create` と `ktrace_events_[single/class]` を呼び出して特定のcodeにcallbackを設定し、その後 `ktrace_start` で開始できます。

**SIPが有効な状態でも**使用できます。

clientとして `ktrace` utilityを使用できます。

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

または `tailspin`。

### kperf

これは kernel level profiling に使用され、`Kdebug` callout を使って構築されています。

基本的には、グローバル変数 `kernel_debug_active` が確認され、有効な場合は、呼び出し元の kernel frame の `Kdebug` code とアドレスを指定して `kperf_kdebug_handler` が呼び出されます。`Kdebug` code が選択されたものと一致すると、bitmap として設定された「actions」が実行されます（選択肢については `osfmk/kperf/action.h` を確認してください）。

Kperf には sysctl MIB table もあります（root として実行）：`sysctl kperf`。これらの code は `osfmk/kperf/kperfbsd.c` にあります。

さらに、Kperf の機能の一部は `kpc` にあり、マシンの performance counter に関する情報を提供します。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) は、プロセスが実行しているプロセス関連のアクション（たとえば、プロセスが新たに作成するプロセスの監視）を確認するのに非常に便利なツールです。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) は、プロセス間の関係を表示するツールです。\
**`sudo eslogger fork exec rename create > cap.json`** のようなコマンドで Mac を監視する必要があります（このコマンドを実行するターミナルには FDA が必要です）。その後、このツールに json を読み込ませると、すべての関係を確認できます。

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) は、作成、変更、削除などのファイルイベントを監視します。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) は、Windows ユーザーには Microsoft Sysinternal の _Procmon_ と似た見た目や操作感でおなじみかもしれない GUI ツールです。このツールでは、さまざまな種類のイベントの記録を開始・停止したり、ファイル、プロセス、ネットワークなどのカテゴリでイベントをフィルタリングしたりできます。また、記録したイベントを json 形式で保存する機能もあります。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) は Xcode の Developer tools の一部で、アプリケーションのパフォーマンス監視、メモリリークの特定、filesystem のアクティビティの追跡に使用されます。

![Crescendo - Apple Instruments：Apple Instruments は Xcode の Developer tools の一部で、アプリケーションのパフォーマンス監視、メモリリークの特定、filesystem のアクティビティの追跡に使用されます](<../../../images/image (1138).png>)

### fs_usage

プロセスが実行するアクションを追跡できます：

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) は、バイナリが使用する **ライブラリ**、使用中の **ファイル**、および **ネットワーク**接続を確認するのに便利です。\
また、バイナリのプロセスを **virustotal** と照合し、そのバイナリに関する情報を表示します。

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**このブログ記事**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)では、SIPが無効になっていてもデバッグを防ぐために **`PT_DENY_ATTACH`** を使用する **実行中のデーモンをデバッグする**例を確認できます。<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` は値 **31**（`0x1f`）を持つ Darwin 固有の `ptrace(2)` リクエストです。その他の引数は無視されます。プロセスは fork せずにこれを直接呼び出し、以降の親プロセスによるトレースを拒否できます。<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU の状態と呼び出し順序

結果は、どの `ptrace` リクエストが最初に XNU に到達するかによって異なります:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB が先にアタッチする:** `debugserver` は `PT_ATTACHEXC` を使用します。XNU はこれを `PT_ATTACH` に変換し、`KAUTH_PROCESS_CANTRACE` の認可を実行して、対象プロセスに `P_LTRACED` を設定します。その後の `PT_DENY_ATTACH` はこのフラグを検知し、`W_EXITCODE(ENOTSUP, 0)` で対象プロセスを終了させます。通常、LLDB ではステータス **45** (`0x2d`) と表示されます。
- **対象プロセスが先に拒否する:** XNU は `P_LNOATTACH` を設定します。その後のアタッチはプロセス・トレーシング認可で拒否され、アタッチのエラー処理で `P_LNOATTACH` が検知されると、アタッチ元プロセスに `SIGSEGV` が送信されます。LLDB では `debugserver` との接続が失われたように見える場合があります。

この経路を判別するには、起動またはアタッチの前に `debugserver` のログを有効にし、その `ptrace` リクエストを調べてください:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 static identification and bypass

難読化されていない ARM64 Mach-O では、インポートされた `_ptrace` の stub を特定し、呼び出し箇所を調べます。最初の整数引数は `w0` に渡されるため、この命令列から anti-debug のリクエストを直接確認できます。インポートがないからといって、確実に使われていないとは限りません。コードが `ptrace` を動的に解決する場合があるためです。インポートされた `_sysctl` も anti-debug チェックを示す場合がありますが、こちらも動的に解決される可能性があります。<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

実例では、immediateを`0x1f`から`0x0`にパッチすると、リクエストが`PT_TRACE_ME`に変わり、プログラムがLLDBの下で続行できるようになります。これは**このサンプル固有のバイパス**であり、一般的なno-opではありません。リクエストを変更するか、呼び出しをスキップするか、成功を返すよう強制するかを決める前に、呼び出し元の戻り値チェックと制御フローを調べてください。<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb**は、**macOS**バイナリの**デバッグ**における事実上のツールです。

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

ホームフォルダに次の行を含む **`.lldbinit`** ファイルを作成すると、lldb の使用時に Intel flavor を設定できます。

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> lldb内で、`process save-core`を使ってプロセスをダンプします

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) コマンド</strong></td><td><strong>説明</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>実行を開始します。ブレークポイントに到達するか、プロセスが終了するまで実行が続きます。</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>実行を開始し、エントリーポイントで停止します。</td></tr>
<tr><td><strong>continue (c)</strong></td><td>デバッグ中のプロセスの実行を続けます。</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>次の命令を実行します。このコマンドは関数呼び出しをステップオーバーします。</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>次の命令を実行します。<code>nexti</code>コマンドとは異なり、このコマンドは関数呼び出しにステップインします。</td></tr>
<tr><td><strong>finish (f)</strong></td><td>現在の関数（フレーム）の残りの命令を実行し、戻って停止します。</td></tr>
<tr><td><strong>control + c</strong></td><td>実行を一時停止します。プロセスが実行（<code>r</code>）または再開（<code>c</code>）されている場合、現在実行中の場所で停止します。</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # mainという名前の関数すべて</p>
<p><code>b &lt;binname&gt;`main</code> # バイナリのmain関数</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # 指定したバイナリのmain関数</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # すべてのNSFileManagerメソッド</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # このライブラリのすべての関数にブレークポイントを設定</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # ブレークポイント一覧</p>
<p><code>br e/dis &lt;num&gt;</code> # ブレークポイントを有効化／無効化</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # breakpointコマンドのヘルプを表示</p>
<p><code>help memory write</code> # メモリへの書き込みに関するヘルプを表示</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>メモリをnull終端文字列として表示します。</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>メモリをアセンブリ命令として表示します。</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>メモリをバイトとして表示します。</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>パラメーターが参照するオブジェクトを出力します。</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>AppleのObjective-C APIやメソッドの多くはオブジェクトを返すため、「print object」(<code>po</code>)コマンドで表示します。<code>po</code>で意味のある出力が得られない場合は、<code>x/b</code>を使います。</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # そのアドレスにAAAAを書き込む<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # そのアドレスにAAAAを書き込む
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # 現在の関数を逆アセンブル</p>
<p><code>dis -n &lt;funcname&gt;</code> # 関数を逆アセンブル</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # 関数を逆アセンブル<br>
<code>dis -c 6</code> # 6行を逆アセンブル<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # 2つのアドレス間を逆アセンブル<br>
<code>dis -p -c 4</code> # 現在のアドレスから逆アセンブルを開始</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # <code>x1</code>レジスター内の3要素の配列を調べる</td></tr>
<tr><td><strong>image dump sections</strong></td><td>現在のプロセスメモリのマップを出力します。</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # CoreNLP内のすべてのシンボルのアドレスを取得</td></tr>
</tbody>
</table>

> [!TIP]
> **`objc_sendMsg`**関数を呼び出すと、**rsi**レジスターにはnull終端（「C」）文字列として**メソッド名**が格納されます。lldbで名前を出力するには、次のようにします。
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM検出

- **`sysctl hw.model`**コマンドは、物理ハードウェアでは通常Macのモデル識別子を返しますが、VMでは異なる値を返す場合があります。<sup>[[3]](#references)</sup>
- **`hw.logicalcpu`**と**`hw.physicalcpu`**の値を調べて、VMかどうかを検出しようとするmalwareもあります。<sup>[[4]](#references)</sup>
- ローダーは、次のstageをunpackする前にVMかどうかを調べるため、`sysctl`を通じて`kern.hv_vmm_present`や`machdep.cpu.brand_string`を照会する場合もあります。これらのチェックは、以下で説明するdebuggerのattach検出を補完するものであり、置き換えるものではありません。<sup>[[20]](#references)</sup>
- MAC address（00:50:56）を基に、マシンが**VMware**かどうかを**検出**するmalwareもあります。
- 次のような簡単なコードでも、**プロセスがdebugされているかどうか**を確認できます。
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- `PT_DENY_ATTACH` flagを指定して`ptrace` system callを呼び出す方法もあります。これにより、debuggerのattachとtraceを防止できます。順序に依存するXNUの挙動、`debugserver`のログ、ARM64のpatchingワークフローについては、[PT_DENY_ATTACH section](#page-title)を確認してください。<sup>[[7]](#references)[[12]](#references)</sup>
- **`PT_DENY_ATTACH`** flagを指定して**`ptrace`** system callを呼び出す方法もあります。順序に依存するXNUの挙動、`debugserver`のログ、ARM64のpatchingワークフローについては、[PT_DENY_ATTACH section](#page-title)を確認してください。<sup>[[7]](#references)[[12]](#references)</sup>
  - **`sysctl`**関数や**`ptrace`**関数が**import**されているか確認できます（ただし、malwareは動的にimportすることもあります）。
  - このwriteup「[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)」にあるように:<sup>[[7]](#references)</sup>\
    「_Process # exited with **status = 45 (0x0000002d)** というメッセージは、debug対象が**PT_DENY_ATTACH**を使っていることを示す典型的な兆候です_」

#### `fork()`によるプロセスの引き継ぎ

プロセスは、起動直後に`fork()`を呼び出し、親プロセスを終了させる（`fork()`は正の子PIDを返す）ことで、元のPIDにattachしたままのdebuggerを回避できます。保護されたロジックは子プロセス内でのみ続行されます（`fork()`は`0`を返します）。`dlsym(RTLD_DEFAULT, "fork")`で`fork`を解決すると、直接の`_fork`呼び出し箇所もなくなりますが、これはあくまでanalysisを妨げるだけです。シンボル名の文字列と動的解決のdata flowは、Mach-O binary内に残ります。<sup>[[13]](#references)[[14]](#references)</sup>

arm64では、固定アドレスではなくdata flowを追って、このパターンを検出します。`dlsym`の最初の2つの引数は`x0`と`x1`に渡され、`RTLD_DEFAULT`は`-2`（例: `movn x0, #1`）として現れる場合があります。また、`adrp`/`add`の組み合わせで`"fork"`文字列のアドレスを構築するのが一般的です。`dlsym`のstubへの`bl`の後、返されたpointerを`x0`からnullチェック、保存先、後続の間接`blr`まで追跡します。次に、`fork()`の戻り値を`w0`で追います。`0`なら子プロセスの処理へ進み、正の値と`-1`なら親プロセス／エラー処理へ進みます。<sup>[[13]](#references)[[14]](#references)</sup>

static bypassでは、間接呼び出しを抑止し、既存の結果チェックが子プロセス側の処理へ進むようにします。たとえば、コンパイラーが以下のシーケンスを生成した場合、`blr`と結果の保存処理を`nop`にpatchし、合成したゼロの結果を与えて、比較／分岐ロジックはそのまま残します。すると、子プロセスを作らずに元のPIDのままアプリケーションが続行されます。命令レジスターと分岐先は、解析したbuildに合わせて調整する必要があります。<sup>[[13]](#references)[[14]](#references)</sup>

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
- `AS_CORE` の上限が処理を許可している場合。`ulimit -c 0` を呼び出してコアダンプの作成を抑制し、`ulimit -c unlimited` で再び有効にできます。

これらの場合、コアダンプは `kern.corefile` sysctl の設定に従って生成され、通常は `/cores/core/.%P` に保存されます。

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash は**クラッシュしたプロセスを分析し、クラッシュレポートをディスクに保存します**。クラッシュレポートには、クラッシュの原因を**開発者が診断するのに役立つ**情報が含まれています。\
**per-user launchd コンテキストで実行されている**アプリケーションやその他のプロセスの場合、ReportCrash は LaunchAgent として実行され、ユーザーの `~/Library/Logs/DiagnosticReports/` にクラッシュレポートを保存します。\
デーモン、**system launchd コンテキストで実行されている**その他のプロセス、およびその他の特権プロセスの場合、ReportCrash は LaunchDaemon として実行され、システムの `/Library/Logs/DiagnosticReports` にクラッシュレポートを保存します。

クラッシュレポートが**Apple に送信される**のが心配な場合は、無効にできます。そうでなければ、クラッシュレポートはサーバーのクラッシュ原因を**特定する**のに役立ちます。

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

#### SSH Disconnect

SSH接続経由でfuzzingを行う場合は、セッションが切断されないようにすることが重要です。そのため、次のようにsshd_configファイルを変更します。

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### 内部ハンドラー

**次のページを確認して**、**指定したスキームまたはプロトコルを処理する**アプリを特定する方法を確認してください。


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### ネットワークプロセスの列挙

ネットワークデータを管理しているプロセスを特定するのに役立ちます。

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

特権デーモンが公開する Mach サービスは、権限のないクライアントや sandbox 内のクライアントが send right を取得できる場合、有用な fuzzing 対象になります。デーモンの launchd エントリにある `MachServices` を起点に、[MIG analysis workflow](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) を使ってメッセージ ID とハンドラーの対応を調べます。バイト列を変更する前に、通常のクライアントでサービスを利用しながら MIG server routine にブレークポイントを設定し、有効なリクエストメッセージを seed input として保存します。必須のヘッダーフィールド、メッセージサイズ、descriptor の配置を維持し、dispatch ですぐに失敗せず、ハンドラーまで変異が届くようにします。<sup>[[17]](#references)</sup>

多くのハンドラーは、それ以前の呼び出しに依存します。harness でサービスの状態を初期化し、各 fuzz input を**操作と引数**のシーケンスとして処理します。たとえば、open や create などのセットアップリクエストを送信し、返された識別子を保持して後続のリクエストで使用します。これにより、初期化されていないオブジェクトのチェックに繰り返し当たるのではなく、coverage feedback で状態遷移を探索できます。<sup>[[17]](#references)</sup>

closed-source の対象では、MIG dispatch routine を呼び出す in-process harness に Jackalope/TinyInst で instrumentation を施せます。[CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) は具体的な実装例ですが、他のサービスにそのまま使える harness ではありません。<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**クラッシュはすべて、実際の IPC 経路で検証してください。** direct-dispatch harness は Mach message に対するカーネルの検証を省略するため、特に無効な out-of-line (OOL) memory や port descriptor を渡した場合、誤検知を起こすことがあります。harness 内で有効な OOL backing memory を割り当てたうえで、元のサービスへのアクセス権を持つクライアントから `mach_msg` を使って縮小した testcase を再実行し、デーモンが依然としてクラッシュすることを確認します。<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI ツールで動作します

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

多くの macOS GUI ツールで「**そのまま動作**」します。アプリケーションによっては、一意のファイル名、特定の拡張子、sandbox container (`~/Library/Containers/com.apple.Safari/Data`) からのファイル読み込みなど、追加の要件があります。

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

### macOS Fuzzingに関する詳細情報

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [OS Xインシデントレスポンス: スクリプティングと分析](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Mac Malwareの技法、第I巻: 分析](https://taomm.org/)
- [4] [No Starch Press - Mac Malwareの技法: 悪意のあるソフトウェアを分析するためのガイド](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - このブログ記事のこれらのセクションに保存されている情報](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attachを使用するAppleバイナリのデバッグ](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug技法の回避: macOS ptraceの派生形](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcodeの構造化ログと`Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - macOS unified logでプライベートデータを表示する](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h`のリクエスト定義](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNUの`mach_process.c`における`ptrace`の実装](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - ptraceの内部: デバッガのアタッチを防ぐ仕組み](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - forkの例](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - dlsymとforkを使用したAnti-debugging技法](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - デバッグツールのエンタイトルメント](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - Hardenedされたサードパーティ製アプリのデバッグ](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - 音の壁を破る パートI: Machメッセージを使ったCoreAudioのFuzzing](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzzハーネス](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - 新バージョンのMacSync macOS情報窃取マルウェア、暗号資産愛好家と開発者を標的に](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
