# macOSアプリ - 検査、デバッグ、およびFuzzing

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
- **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>

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

このツールは、**codesign**、**otool**、および**objdump**の**代替**として使用でき、いくつかの追加機能を提供します。[**こちらからダウンロード**](http://www.newosxbook.com/tools/jtool.html)するか、`brew`を使用してインストールしてください。
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
**`Codesign`** は **macOS** に、一方 **`ldid`** は **iOS** に見つかります
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html)は、**.pkg**ファイル（インストーラー）を検査し、インストールする前に中身を確認するのに役立つツールです。\
これらのインストーラーには、通常、マルウェアの作者が悪用する`preinstall`および`postinstall` bashスクリプトが含まれており、**マルウェアを** **持続化**するために使用されます。

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

[class-dump](https://github.com/nygard/class-dump)を使用して、この情報を取得できます。
```bash
class-dump Kindle.app
```
#### 関数の呼び出し

Objective-Cを使用するバイナリで関数が呼び出されると、コンパイルされたコードはその関数を呼び出す代わりに**`objc_msgSend`**を呼び出します。これにより最終的な関数が呼び出されます:

![](<../../../.gitbook/assets/image (560).png>)

この関数が期待するパラメータは次のとおりです:

- 最初のパラメータ (**self**) は、「**メッセージを受け取るクラスのインスタンスを指すポインタ**」です。簡単に言うと、メソッドが呼び出されるオブジェクトです。メソッドがクラスメソッドの場合、これはクラスオブジェクト全体のインスタンスになりますが、インスタンスメソッドの場合、selfはクラスのインスタンスとしてインスタンス化されたインスタンスを指します。
- 2番目のパラメータ (**op**) は、「メッセージを処理するメソッドのセレクタ」です。単純に言うと、これは**メソッドの名前**です。
- 残りのパラメータは、メソッドで必要な**値**です (op)。

| **引数**         | **レジスタ**                                                   | **(for) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1番目の引数**  | **rdi**                                                         | **self: メソッドが呼び出されるオブジェクト**         |
| **2番目の引数**  | **rsi**                                                         | **op: メソッドの名前**                                |
| **3番目の引数**  | **rdx**                                                         | **メソッドへの最初の引数**                            |
| **4番目の引数**  | **rcx**                                                         | **メソッドへの2番目の引数**                           |
| **5番目の引数**  | **r8**                                                          | **メソッドへの3番目の引数**                           |
| **6番目の引数**  | **r9**                                                          | **メソッドへの4番目の引数**                           |
| **7番目以降の引数** | <p><strong>rsp+</strong><br><strong>(スタック上)</strong></p> | **メソッドへの5番目以降の引数**                       |

### Swift

Swiftバイナリでは、Objective-C互換性があるため、[class-dump](https://github.com/nygard/class-dump/)を使用して宣言を抽出することができますが、常にではありません。

**`jtool -l`**または**`otool -l`**コマンドラインを使用すると、**`__swift5`**接頭辞で始まる複数のセクションを見つけることができます:
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
さらなる情報は、[**このブログポスト**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)でこのセクションに保存されている情報について見つけることができます。

さらに、**Swiftバイナリにはシンボルが含まれる可能性があります**（たとえば、ライブラリは関数を呼び出すためにシンボルを保存する必要があります）。**シンボルには通常、関数名と属性に関する情報が含まれており、見た目は醜い**ため、非常に役立ちます。そして、**"デマングラー"**があり、元の名前を取得できます。
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
バイナリをデバッグするには、**SIPを無効にする**必要があります（`csrutil disable`または`csrutil enable --without debug`）、またはバイナリを一時フォルダにコピーして`codesign --remove-signature <binary-path>`で署名を削除するか、バイナリのデバッグを許可する（[このスクリプト](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)を使用できます）
{% endhint %}

{% hint style="warning" %}
macOS上の`cloudconfigurationd`などの**システムバイナリ**を**インストール**するには、**SIPを無効**にする必要があります（署名を削除するだけでは機能しません）。
{% endhint %}

### 統合ログ

MacOSは多くのログを生成しますが、これらはアプリケーションを実行している際に非常に役立ち、**何をしているか**を理解しようとする際に非常に役立ちます。

さらに、一部のログには`<private>`というタグが含まれ、一部の**ユーザー**や**コンピューター**の**識別可能な**情報を**非表示**にするためのものです。ただし、**この情報を開示するための証明書をインストール**することが可能です。[**こちら**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)の説明に従ってください。

### Hopper

#### 左パネル

Hopperの左パネルでは、バイナリのシンボル（**ラベル**）、手続きと関数のリスト（**Proc**）、および文字列（**Str**）を見ることができます。これらはすべての文字列ではありませんが、Mac-Oファイルのさまざまな部分で定義されているものです（例：_cstringまたは`objc_methname`）。

#### 中央パネル

中央パネルでは、**逆アセンブルされたコード**を見ることができます。また、**生の**逆アセンブル、**グラフ**、**逆コンパイル**、**バイナリ**を見ることができます。それぞれのアイコンをクリックして切り替えることができます：

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

コードオブジェクトを右クリックすると、そのオブジェクトへの**参照/参照元**を見ることができます。また、名前を変更することもできます（逆コンパイルされた擬似コードでは機能しません）：

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

さらに、**中央下部にPythonコマンドを記述**することができます。

#### 右パネル

右パネルでは、**ナビゲーション履歴**（現在の状況に到達するまでの経緯を把握できる）、この関数を**呼び出すすべての関数**およびこの関数が**呼び出すすべての関数**を表示する**コールグラフ**、**ローカル変数**情報など、興味深い情報を見ることができます。

### dtrace

これにより、ユーザーは非常に**低レベル**でアプリケーションにアクセスでき、プログラムを**トレース**したり、実行フローを変更したりする方法を提供します。 Dtraceは、カーネル全体に配置される**プローブ**を使用し、システムコールの開始と終了などの場所に配置されます。

DTraceは、各システムコールの**入口と出口**でプローブを作成するために**`dtrace_probe_create`**関数を使用します。これらのプローブは、各システムコールの**入口と出口**で発火することができます。DTraceとのやり取りは、ルートユーザー専用の/dev/dtraceを介して行われます。

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
プローブ名は、プロバイダー、モジュール、関数、および名前（`fbt:mach_kernel:ptrace:entry`）の4つの部分で構成されています。名前の一部を指定しない場合、Dtraceはその部分をワイルドカードとして適用します。

プローブをアクティブにし、それらが発生したときに実行するアクションを指定するには、D言語を使用する必要があります。

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
### ktrace

これは**SIPが有効**の状態でも使用できます。
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor)は、プロセスが実行しているプロセス関連のアクションをチェックするための非常に便利なツールです（たとえば、プロセスが作成している新しいプロセスを監視します）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/)は、プロセス間の関係を表示するツールです。\
**`sudo eslogger fork exec rename create > cap.json`** のようなコマンドでMacを監視する必要があります（このコマンドを実行するためにはFDAが必要です）。その後、このツールでjsonをロードしてすべての関係を表示できます：

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor)は、ファイルイベント（作成、変更、削除など）を監視し、そのようなイベントに関する詳細情報を提供します。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo)は、Microsoft Sysinternalの _Procmon_ からWindowsユーザーが知っている外観と感覚を持つGUIツールです。このツールを使用すると、さまざまなイベントタイプの記録を開始および停止でき、これらのイベントをファイル、プロセス、ネットワークなどのカテゴリでフィルタリングでき、記録されたイベントをjson形式で保存する機能を提供します。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html)は、Xcodeの開発者ツールの一部であり、アプリケーションのパフォーマンスを監視し、メモリリークを特定し、ファイルシステムのアクティビティを追跡するために使用されます。

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

プロセスによって実行されるアクションを追跡することができます。
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html)は、バイナリが使用している**ライブラリ**、使用している**ファイル**、および**ネットワーク**接続を確認するのに役立ちます。\
また、バイナリプロセスを**virustotal**に対してチェックし、バイナリに関する情報を表示します。

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

[**このブログ投稿**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)では、**`PT_DENY_ATTACH`**を使用してデバッグを防止する実行中のデーモンをデバッグする方法の例が示されています。

### lldb

**lldb**は**macOS**バイナリのデバッグにおける事実上のツールです。
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
次の行を含むファイル**`.lldbinit`**をホームフォルダに作成することで、lldbを使用する際にintelフレーバーを設定できます：
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
lldb内で、`process save-core`を使用してプロセスをダンプします。
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) コマンド</strong></td><td><strong>説明</strong></td></tr><tr><td><strong>run (r)</strong></td><td>ブレークポイントがヒットするかプロセスが終了するまで続行される実行を開始します。</td></tr><tr><td><strong>continue (c)</strong></td><td>デバッグ対象プロセスの実行を継続します。</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>次の命令を実行します。このコマンドは関数呼び出しをスキップします。</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>次の命令を実行します。nextiコマンドとは異なり、このコマンドは関数呼び出しに入ります。</td></tr><tr><td><strong>finish (f)</strong></td><td>現在の関数（"frame"）内の残りの命令を実行して停止します。</td></tr><tr><td><strong>control + c</strong></td><td>実行を一時停止します。プロセスが実行されている場合、プロセスは現在実行中の場所で停止します。</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main # main関数を呼び出す</p><p>b <binname>`main # バイナリのmain関数</p><p>b set -n main --shlib <lib_name> # 指定されたバイナリのmain関数</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l # ブレークポイントリスト</p><p>br e/dis <num> # ブレークポイントを有効化/無効化</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint # ブレークポイントコマンドのヘルプを取得</p><p>help memory write # メモリへの書き込みに関するヘルプを取得</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <a href="https://lldb.llvm.org/use/variable.html#type-format">format</a></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>メモリをヌル終端文字列として表示します。</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>メモリをアセンブリ命令として表示します。</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>メモリをバイトとして表示します。</td></tr><tr><td><strong>print object (po)</strong></td><td><p>パラメータで参照されるオブジェクトを出力します</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>AppleのObjective-C APIやメソッドのほとんどはオブジェクトを返すため、「print object」（po）コマンドで表示する必要があります。意味のある出力が得られない場合は、<code>x/b</code>を使用してください</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 # そのアドレスにAAAAを書き込む<br>memory write -f s $rip+0x11f+7 "AAAA" # そのアドレスにAAAAを書き込む</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis # 現在の関数を逆アセンブル</p><p>dis -n <funcname> # 関数を逆アセンブル</p><p>dis -n <funcname> -b <basename> # 関数を逆アセンブル</p><p>dis -c 6 # 6行を逆アセンブル</p><p>dis -c 0x100003764 -e 0x100003768 # 1つのアドレスからもう1つのアドレスまで</p><p>dis -p -c 4 # 現在のアドレスから逆アセンブルを開始</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1レジスタ内の3つのコンポーネントの配列をチェック</td></tr></tbody></table>

{% hint style="info" %}
**`objc_sendMsg`** 関数を呼び出す際、**rsi** レジスタにはヌル終端（"C"）文字列としての**メソッド名**が格納されます。lldbを使用して名前を表示するには以下のようにします：

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### アンチダイナミック解析

#### VM検出

* **`sysctl hw.model`** コマンドは、**ホストがMacOS**の場合は "Mac" を返しますが、VMの場合は異なる値を返します。
* 一部のマルウェアは、**`hw.logicalcpu`** と **`hw.physicalcpu`** の値を操作して、VMであるかどうかを検出しようとします。
* 一部のマルウェアは、MACアドレス（00:50:56）に基づいてマシンがVMwareであるかどうかを検出することもできます。
* 単純なコードを使用して、プロセスがデバッグされているかどうかを検出することもできます：
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
* **`ptrace`** システムコールを **`PT_DENY_ATTACH`** フラグで呼び出すこともできます。これにより、デバッガがアタッチおよびトレースを防止します。
* **`sysctl`** または **`ptrace`** 関数が **インポート** されているかどうかを確認できます（ただし、マルウェアは動的にインポートする可能性があります）
* この記事に記載されているように、"[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)"：\
"_メッセージ「Process # exited with **status = 45 (0x0000002d)**」は、通常、デバッグ対象が **PT\_DENY\_ATTACH** を使用していることを示す兆候です_"

## ファジング

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrashは、**クラッシュしたプロセスを分析し、クラッシュレポートをディスクに保存**します。クラッシュレポートには、クラッシュの原因を診断するのに役立つ情報が含まれています。\
ユーザーごとのlaunchdコンテキストで実行されるアプリケーションや他のプロセスの場合、ReportCrashはLaunchAgentとして実行され、クラッシュレポートをユーザーの `~/Library/Logs/DiagnosticReports/` に保存します。\
デーモン、システムlaunchdコンテキストで実行される他のプロセスや他の特権を持つプロセスの場合、ReportCrashはLaunchDaemonとして実行され、クラッシュレポートをシステムの `/Library/Logs/DiagnosticReports` に保存します。

クラッシュレポートが**Appleに送信されるのを心配**している場合は、それらを無効にすることができます。そうでない場合、クラッシュレポートはサーバーがどのようにクラッシュしたかを把握するのに役立ちます。
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### スリープ

MacOSでのFuzzing中は、Macがスリープモードに入らないようにすることが重要です：

* systemsetup -setsleep Never
* pmset、システム環境設定
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSHの切断

SSH接続を介してFuzzingを行う場合は、セッションが切断されないようにすることが重要です。そのために、sshd_configファイルを以下のように変更します：

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### 内部ハンドラ

**以下のページ**をチェックして、指定されたスキームやプロトコルを処理するアプリを特定する方法を見つけてください：

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
または`netstat`または`lsof`を使用します。

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### ファジングツール

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLIツールに対応

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOSのGUIツールに**"just works"**します。一部のmacOSアプリはユニークなファイル名、適切な拡張子、サンドボックスからファイルを読み取る必要があるなど、特定の要件を満たす必要があります。

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

### 追加のFuzzing MacOS情報

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 参考文献

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**する。
* **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
