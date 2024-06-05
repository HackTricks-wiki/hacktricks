# macOSアプリ - 検査、デバッグ、およびFuzzing

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**スティーラーマルウェア**によって**侵害**されていないかをチェックする**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

***

## 静的解析

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
{% endcode %}

### jtool2

このツールは、**codesign**、**otool**、**objdump** の**代替**として使用でき、いくつかの追加機能を提供します。[**こちらからダウンロード**](http://www.newosxbook.com/tools/jtool.html)するか、`brew` でインストールしてください。
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`** は **macOS** に、一方 **`ldid`** は **iOS** に見つけることができます
{% endhint %}
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html)は、**.pkg**ファイル（インストーラ）を検査し、インストールする前に中身を確認するのに役立つツールです。\
これらのインストーラには、通常、マルウェア作者が悪用する`preinstall`および`postinstall` bashスクリプトが含まれており、**マルウェアを** **持続化**するために悪用されます。

### hdiutil

このツールは、Appleディスクイメージ（**.dmg**）ファイルを**マウント**して、実行する前にそれらを検査することを可能にします：
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
### Objective-C

#### メタデータ

{% hint style="danger" %}
Objective-Cで書かれたプログラムは、[Mach-Oバイナリ](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)にコンパイルされる際に、クラス宣言を**保持**します。このようなクラス宣言には、以下の情報が含まれます：

* クラス
* クラスメソッド
* クラスのインスタンス変数
{% endhint %}

[class-dump](https://github.com/nygard/class-dump)を使用して、この情報を取得できます：
```bash
class-dump Kindle.app
```
#### 関数の呼び出し

Objective-Cを使用するバイナリで関数が呼び出されると、コンパイルされたコードはその関数を呼び出す代わりに **`objc_msgSend`** を呼び出します。これにより最終的な関数が呼び出されます:

![](<../../../.gitbook/assets/image (305).png>)

この関数が期待するパラメータは次のとおりです:

* 最初のパラメータ (**self**) は、「**メッセージを受け取るクラスのインスタンスを指すポインタ**」です。簡単に言うと、メソッドが呼び出されるオブジェクトです。メソッドがクラスメソッドの場合、これはクラスオブジェクトのインスタンス（全体として）になりますが、インスタンスメソッドの場合、selfはクラスのインスタンスとしてインスタンス化されたオブジェクトを指します。
* 2番目のパラメータ (**op**) は、「メッセージを処理するメソッドのセレクタ」です。単純に言うと、これは**メソッドの名前**です。
* 残りのパラメータは、メソッドで必要な**値**です（op）。

ARM64で **`lldb`** を使用してこの情報を簡単に取得する方法は、このページを参照してください:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **引数**         | **レジスタ**                                                   | **(for) objc\_msgSend**                                |
| ----------------- | -------------------------------------------------------------- | ------------------------------------------------------ |
| **1番目の引数**  | **rdi**                                                        | **self: メソッドが呼び出されるオブジェクト**         |
| **2番目の引数**  | **rsi**                                                        | **op: メソッドの名前**                                |
| **3番目の引数**  | **rdx**                                                        | **メソッドへの最初の引数**                            |
| **4番目の引数**  | **rcx**                                                        | **メソッドへの2番目の引数**                           |
| **5番目の引数**  | **r8**                                                         | **メソッドへの3番目の引数**                           |
| **6番目の引数**  | **r9**                                                         | **メソッドへの4番目の引数**                           |
| **7番目以降の引数** | <p><strong>rsp+</strong><br><strong>(スタック上)</strong></p> | **メソッドへの5番目以降の引数**                       |

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) は、dylibsからObjc-Classesを取得するツールです。

### Swift

Swiftバイナリでは、Objective-C互換性があるため、[class-dump](https://github.com/nygard/class-dump/)を使用して宣言を抽出することができますが、常にではありません。

**`jtool -l`** または **`otool -l`** コマンドラインを使用すると、**`__swift5`** 接頭辞で始まる複数のセクションを見つけることができます:
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
さらなる情報は、[**このブログ投稿**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)でこれらのセクションに保存されている情報について見つけることができます。

さらに、**Swift バイナリにはシンボルが含まれる可能性があります**（たとえば、ライブラリは関数を呼び出すためにシンボルを保存する必要があります）。**シンボルには通常、関数名や属性に関する情報が含まれており、見た目が醜いため、非常に役立ちます。**そして、**"デマングラー"**があり、元の名前を取得できます。
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### パッキングされたバイナリ

- 高いエントロピーをチェックする
- 文字列をチェックする（理解できる文字列がほとんどない場合、パッキングされている可能性がある）
- MacOS用のUPXパッカーは"\_\_XHDR"というセクションを生成する

## ダイナミック解析

{% hint style="warning" %}
バイナリをデバッグするには、**SIPを無効にする必要がある**（`csrutil disable`または`csrutil enable --without debug`）か、バイナリを一時フォルダにコピーして`codesign --remove-signature <binary-path>`で署名を削除するか、バイナリのデバッグを許可する（[このスクリプト](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)を使用できます）
{% endhint %}

{% hint style="warning" %}
macOS上で`cloudconfigurationd`などの**システムバイナリをインストルメント**するには、**SIPを無効にする必要がある**（単に署名を削除するだけでは機能しません）。
{% endhint %}

### APIs

macOSはいくつかの興味深いAPIを公開しており、プロセスに関する情報を提供しています：

- `proc_info`：これは各プロセスに関する多くの情報を提供する主要なAPIです。他のプロセスの情報を取得するにはrootである必要がありますが、特別な権限やmachポートは必要ありません。
- `libsysmon.dylib`：XPCで公開された関数を介してプロセスに関する情報を取得することができますが、`com.apple.sysmond.client`という権限が必要です。

### Stackshot & microstackshots

**Stackshotting**は、プロセスの状態をキャプチャするために使用される技術で、すべての実行中スレッドのコールスタックを含みます。これはデバッグ、パフォーマンス分析、特定の時点でのシステムの動作を理解するのに特に役立ちます。iOSとmacOSでは、**`sample`**や**`spindump`**などのツールや方法を使用して、stackshottingを実行できます。

### Sysdiagnose

このツール（`/usr/bini/ysdiagnose`）は、`ps`、`zprint`などのさまざまなコマンドを実行してコンピュータから多くの情報を収集します。

**root**として実行する必要があり、デーモン`/usr/libexec/sysdiagnosed`には`com.apple.system-task-ports`や`get-task-allow`など非常に興味深い権限があります。

そのplistは`/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`にあり、3つのMachServicesを宣言しています：

- `com.apple.sysdiagnose.CacheDelete`：/var/rmp内の古いアーカイブを削除します
- `com.apple.sysdiagnose.kernel.ipc`：特別ポート23（カーネル）
- `com.apple.sysdiagnose.service.xpc`：`Libsysdiagnose` Obj-Cクラスを介したユーザーモードインターフェース。辞書内で3つの引数を渡すことができます（`compress`、`display`、`run`）

### 統合ログ

MacOSはアプリケーションを実行する際に非常に役立つログを生成します。

さらに、一部のログにはユーザーまたはコンピュータの識別可能な情報を**非表示**にするための`<private>`タグが含まれています。ただし、この情報を開示するために**証明書をインストール**することが可能です。[**こちら**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)の説明に従ってください。

### Hopper

#### 左パネル

Hopperの左パネルでは、バイナリのシンボル（**ラベル**）、手順と関数のリスト（**Proc**）、および文字列（**Str**）を見ることができます。これらはMac-Oファイルのさまざまな部分で定義された文字列のすべてではありませんが、（例えば_cstringやobjc_methnameなど）。

#### 中央パネル

中央パネルでは、**逆アセンブルされたコード**を見ることができます。また、**生の**逆アセンブル、**グラフ**、**逆コンパイル**、**バイナリ**を見ることができます。それぞれのアイコンをクリックして切り替えることができます：

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

コードオブジェクトを右クリックすると、そのオブジェクトへの**参照/参照元**を見ることができます。また、その名前を変更することもできます（これは逆コンパイルされた擬似コードでは機能しません）：

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

さらに、**中央下部にPythonコマンドを記述**することができます。

#### 右パネル

右パネルでは、**ナビゲーション履歴**（現在の状況に到達するまでの経緯を把握するため）、**コールグラフ**（この関数を呼び出すすべての関数と、この関数が呼び出すすべての関数を表示できる）、**ローカル変数**情報など、興味深い情報を見ることができます。

### dtrace

Dtraceは、非常に**低レベル**でアプリケーションにアクセスできるようにし、ユーザーが**プログラムをトレース**したり、実行フローを変更したりする方法を提供します。Dtraceは、カーネル全体に配置される**プローブ**を使用します。これらのプローブは、システムコールの開始と終了などの場所に配置されます。

DTraceは、各システムコールの**エントリと終了点**でプローブを作成するために**`dtrace_probe_create`**関数を使用します。これらのプローブは、各システムコールの**エントリと終了点**で発火できます。DTraceとのやり取りは、ルートユーザー専用の/dev/dtraceを介して行われます。

{% hint style="success" %}
SIP保護を完全に無効にせずにDtraceを有効にするには、回復モードで次のコマンドを実行できます：`csrutil enable --without dtrace`

また、**コンパイルしたバイナリ**の**`dtrace`**または**`dtruss`**を実行できます。
{% endhint %}

dtraceの利用可能なプローブは、次のコマンドで取得できます：
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
プローブ名は、プロバイダー、モジュール、関数、名前（`fbt:mach_kernel:ptrace:entry`）の4つの部分で構成されています。名前の一部を指定しない場合、Dtraceはその部分をワイルドカードとして適用します。

プローブをアクティブ化し、それらが発生したときに実行するアクションを指定するには、D言語を使用する必要があります。

詳細な説明やさらなる例は、[https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) で見つけることができます。

#### 例

`man -k dtrace` を実行して、**利用可能なDTraceスクリプト**をリストアップします。例: `sudo dtruss -n binary`

* 1行で
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* スクリプト
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

これはカーネルトレース機能です。ドキュメント化されたコードは**`/usr/share/misc/trace.codes`**にあります。

`latency`、`sc_usage`、`fs_usage`、`trace`などのツールが内部で使用しています。

`kdebug`とやり取りするためには、`sysctl`を使用し、`kern.kdebug`名前空間を介して、使用するMIBは`sys/sysctl.h`にあり、関数は`bsd/kern/kdebug.c`に実装されています。

カスタムクライアントでkdebugとやり取りするためには、通常、次の手順を実行します:

* 既存の設定を削除するにはKERN\_KDSETREMOVEを使用します
* KERN\_KDSETBUFおよびKERN\_KDSETUPでトレースを設定します
* バッファエントリ数を取得するにはKERN\_KDGETBUFを使用します
* トレースから独自のクライアントを取得するにはKERN\_KDPINDEXを使用します
* KERN\_KDENABLEでトレースを有効にします
* KERN\_KDREADTRを呼び出してバッファを読み取ります
* 各スレッドをそれぞれのプロセスにマッチさせるにはKERN\_KDTHRMAPを呼び出します。

この情報を取得するためには、Appleのツール**`trace`**またはカスタムツール[kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**を使用できます。**

**Kdebugは1つの顧客にのみ利用可能**です。つまり、同時に1つのk-debug対応ツールしか実行できません。

### ktrace

`ktrace_*` APIは`libktrace.dylib`から来ており、`Kdebug`のものをラップしています。その後、クライアントは単に`ktrace_session_create`と`ktrace_events_[single/class]`を呼び出して特定のコードにコールバックを設定し、`ktrace_start`で開始できます。

**SIPが有効**な状態でもこれを使用できます。

クライアントとして、ユーティリティ`ktrace`を使用できます:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
または`tailspin`。

### kperf

これはカーネルレベルのプロファイリングに使用され、`Kdebug`コールアウトを使用して構築されています。

基本的に、グローバル変数`kernel_debug_active`がチェックされ、設定されると`Kdebug`コードと呼び出し元のカーネルフレームのアドレスを持つ`kperf_kdebug_handler`が呼び出されます。`Kdebug`コードが選択されたものと一致する場合、ビットマップとして構成された"アクション"が取得されます（オプションについては`osfmk/kperf/action.h`を参照）。

Kperfにはsysctl MIBテーブルもあります：（rootとして）`sysctl kperf`。これらのコードは`osfmk/kperf/kperfbsd.c`で見つけることができます。

さらに、Kperfsの機能のサブセットは`kpc`にあり、マシンパフォーマンスカウンタに関する情報を提供します。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor)は、プロセスが実行しているプロセス関連のアクションをチェックするための非常に便利なツールです（たとえば、プロセスが作成している新しいプロセスを監視します）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/)は、プロセス間の関係を表示するツールです。\
**`sudo eslogger fork exec rename create > cap.json`**のようなコマンドでMacを監視する必要があります（このコマンドを実行するためにはFDAが必要です）。その後、このツールでjsonをロードしてすべての関係を表示できます：

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor)は、ファイルイベント（作成、変更、削除など）を監視し、そのようなイベントに関する詳細情報を提供します。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo)は、Microsoft Sysinternalの_Procmon_からWindowsユーザーが知っている外観と感覚を持つGUIツールです。このツールを使用すると、さまざまなイベントタイプの記録を開始および停止でき、これらのイベントをファイル、プロセス、ネットワークなどのカテゴリでフィルタリングでき、記録されたイベントをjson形式で保存できます。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html)はXcodeの開発者ツールの一部で、アプリケーションのパフォーマンスを監視し、メモリリークを特定し、ファイルシステムのアクティビティを追跡するために使用されます。

![](<../../../.gitbook/assets/image (1138).png>)

### fs\_usage

プロセスによって実行されるアクションをフォローすることができます。
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html)は、バイナリが使用している**ライブラリ**、使用している**ファイル**、および**ネットワーク**接続を確認するのに役立ちます。\
また、バイナリプロセスを**virustotal**に対してチェックし、バイナリに関する情報を表示します。

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

[**このブログ投稿**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)では、**`PT_DENY_ATTACH`**を使用してデバッグを防止するデーモンをデバッグする方法の例が示されています。

### lldb

**lldb**は**macOS**バイナリの**デバッグ**における事実上のツールです。
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
LLDBを使用する際に`~/.lldbinit`というファイルを作成し、次の行を追加してintelフレーバーを設定できます：
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
lldb内で、`process save-core`を使用してプロセスをダンプします。
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) コマンド</strong></td><td><strong>説明</strong></td></tr><tr><td><strong>run (r)</strong></td><td>ブレークポイントがヒットするかプロセスが終了するまで続行される実行を開始します。</td></tr><tr><td><strong>continue (c)</strong></td><td>デバッグ対象プロセスの実行を継続します。</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>次の命令を実行します。このコマンドは関数呼び出しをスキップします。</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>次の命令を実行します。nextiコマンドとは異なり、このコマンドは関数呼び出しに入ります。</td></tr><tr><td><strong>finish (f)</strong></td><td>現在の関数（"frame"）内の残りの命令を実行して停止します。</td></tr><tr><td><strong>control + c</strong></td><td>実行を一時停止します。プロセスが実行されている場合、現在実行中の場所でプロセスを停止させます。</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main # main関数を呼び出す</p><p>b <binname>`main # バイナリのmain関数</p><p>b set -n main --shlib <lib_name> # 指定されたバイナリのmain関数</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l # ブレークポイントリスト</p><p>br e/dis <num> # ブレークポイントの有効化/無効化</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint # ブレークポイントコマンドのヘルプを取得</p><p>help memory write # メモリへの書き込みに関するヘルプを取得</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <a href="https://lldb.llvm.org/use/variable.html#type-format">format</a></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>メモリをヌル終端文字列として表示します。</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>メモリをアセンブリ命令として表示します。</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>メモリをバイトとして表示します。</td></tr><tr><td><strong>print object (po)</strong></td><td><p>これは、パラメータで参照されるオブジェクトを出力します</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>AppleのObjective-C APIやメソッドのほとんどはオブジェクトを返すため、「print object」（po）コマンドで表示する必要があります。意味のある出力が得られない場合は、<code>x/b</code>を使用します</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 # そのアドレスにAAAAを書き込む<br>memory write -f s $rip+0x11f+7 "AAAA" # アドレスにAAAAを書き込む</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis # 現在の関数を逆アセンブル</p><p>dis -n <funcname> # 関数を逆アセンブル</p><p>dis -n <funcname> -b <basename> # 関数を逆アセンブル</p><p>dis -c 6 # 6行を逆アセンブル</p><p>dis -c 0x100003764 -e 0x100003768 # 1つのアドレスからもう1つのアドレスまで</p><p>dis -p -c 4 # 現在のアドレスから逆アセンブルを開始</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1レジスタ内の3つのコンポーネントの配列をチェック</td></tr></tbody></table>

{% hint style="info" %}
**`objc_sendMsg`** 関数を呼び出す際、**rsi** レジスタにはメソッドの名前がヌル終端（"C"）文字列として保持されます。lldbを介して名前を印刷するには以下を実行します：

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### アンチダイナミック解析

#### VM 検出

* **`sysctl hw.model`** コマンドは、ホストがMacOSの場合に "Mac" を返しますが、VMの場合は異なる値を返します。
* 一部のマルウェアは、**`hw.logicalcpu`** と **`hw.physicalcpu`** の値を操作して、VMかどうかを検出しようとします。
* 一部のマルウェアは、MACアドレス（00:50:56）に基づいてマシンがVMwareであるかどうかを検出することもあります。
* プロセスがデバッグされているかどうかを簡単なコードで検出することも可能です：
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
* **`ptrace`** システムコールを **`PT_DENY_ATTACH`** フラグとともに呼び出すこともできます。これにより、デバッガがアタッチしてトレースするのを防ぎます。
* **`sysctl`** または **`ptrace`** 関数が **インポート** されているかどうかを確認できます（ただし、マルウェアは動的にインポートする可能性があります）
* この記事に記載されているように、"[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)"：\
"_メッセージ「Process # exited with **status = 45 (0x0000002d)**」は、通常、デバッグ対象が **PT\_DENY\_ATTACH** を使用していることを示す兆候です_"
## コアダンプ

コアダンプは次の場合に作成されます：

- `kern.coredump` sysctl が 1 に設定されている場合（デフォルト）
- プロセスが suid/sgid でないか、`kern.sugid_coredump` が 1 に設定されている場合（デフォルトは 0）
- `AS_CORE` 制限が操作を許可している場合。`ulimit -c 0` を呼び出してコアダンプの作成を抑制し、`ulimit -c unlimited` で再度有効にできます。

これらの場合、コアダンプは `kern.corefile` sysctl に従って生成され、通常は `/cores/core/.%P` に保存されます。

## ファジング

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash は**クラッシュしたプロセスを分析し、クラッシュレポートをディスクに保存**します。クラッシュレポートには、クラッシュの原因を**開発者が診断するのに役立つ情報**が含まれています。\
ユーザーごとの launchd コンテキストで実行されるアプリケーションや他のプロセスの場合、ReportCrash は LaunchAgent として実行され、クラッシュレポートはユーザーの `~/Library/Logs/DiagnosticReports/` に保存されます。\
デーモン、システム launchd コンテキストで実行される他のプロセスや他の特権プロセスの場合、ReportCrash は LaunchDaemon として実行され、クラッシュレポートはシステムの `/Library/Logs/DiagnosticReports` に保存されます。

クラッシュレポートが**Appleに送信されるのを心配**している場合は、それらを無効にすることができます。そうでない場合、クラッシュレポートは**サーバーがどのようにクラッシュしたかを特定するのに役立つ**ことがあります。
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sleep

MacOSでのFuzzing中は、Macがスリープモードに入らないようにすることが重要です：

* systemsetup -setsleep Never
* pmset、System Preferences
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Disconnect

SSH接続経由でFuzzingを行う場合は、セッションが切断されないようにすることが重要です。そのために、sshd\_configファイルを以下のように変更してください：

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### インターナルハンドラ

**次のページ**をチェックして、指定されたスキームやプロトコルを**処理するアプリケーション**を見つける方法を見つけてください：

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### ネットワークプロセスの列挙

ネットワークデータを管理しているプロセスを見つけるのは興味深いです：
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
または`netstat`または`lsof`を使用します

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### ファジャー

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI ツールに対応

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOS の GUI ツールで**"just works"**します。一部の macOS アプリには、ユニークなファイル名、適切な拡張子、サンドボックスからファイルを読み取る必要があるなど、特定の要件があります (`~/Library/Containers/com.apple.Safari/Data`)...

いくつかの例:

{% code overflow="wrap" %}
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
{% endcode %}

### もっとFuzzing MacOS情報

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 参考文献

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**スティーラーマルウェア**によって**侵害**されていないかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
