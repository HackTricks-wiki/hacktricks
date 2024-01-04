# macOSアプリ - 検査、デバッグ、ファジング

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを**共有する**

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
### jtool2

このツールは、**codesign**、**otool**、および **objdump** の**代替**として使用でき、いくつかの追加機能を提供します。[**こちらからダウンロードしてください**](http://www.newosxbook.com/tools/jtool.html)、または `brew` でインストールします。
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
**`Codesign`** は **macOS** で見つけることができ、**`ldid`** は **iOS** で見つけることができます
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) は、インストールする前に **.pkg** ファイル（インストーラー）の中身を調べるのに役立つツールです。\
これらのインストーラーには、マルウェアの作者が通常、**マルウェアを永続化するために悪用する** `preinstall` と `postinstall` のbashスクリプトが含まれています。

### hdiutil

このツールは、何かを実行する前に Apple のディスクイメージ（**.dmg**）ファイルを**マウント**して調べることができます：
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
`/Volumes`にマウントされます。

### Objective-C

#### メタデータ

{% hint style="danger" %}
Objective-Cで書かれたプログラムは、[Mach-Oバイナリ](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)に**コンパイルされた時に**、クラス宣言を**保持**することに注意してください。このクラス宣言には以下が**含まれます**：

* クラスの名前
* クラスメソッド
* クラスインスタンス変数

この情報は[**class-dump**](https://github.com/nygard/class-dump)を使用して取得できます：
```bash
class-dump Kindle.app
```
この名前は、バイナリのリバースエンジニアリングをより困難にするために難読化されている可能性があります。

#### 関数呼び出し

Objective-Cを使用するバイナリで関数が呼び出されると、コンパイルされたコードはその関数を直接呼び出すのではなく、**`objc_msgSend`** を呼び出します。これが最終的な関数を呼び出します：

![](<../../../.gitbook/assets/image (560).png>)

この関数が期待するパラメータは以下の通りです：

* 最初のパラメータ（**self**）は「**メッセージを受け取るクラスのインスタンスを指すポインタ**」です。もっと簡単に言うと、メソッドが呼び出されているオブジェクトです。メソッドがクラスメソッドの場合、これはクラスオブジェクト（全体）のインスタンスになりますが、インスタンスメソッドの場合、selfはクラスのインスタンス化されたインスタンスを指します。
* 2番目のパラメータ（**op**）は「メッセージを処理するメソッドのセレクタ」です。再び簡単に言うと、これは単に**メソッドの名前**です。
* 残りのパラメータは、メソッドによって**必要とされる値**です（op）。

| **引数**          | **レジスタ**                                                    | **(for) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1番目の引数**   | **rdi**                                                         | **self: メソッドが呼び出されているオブジェクト**       |
| **2番目の引数**   | **rsi**                                                         | **op: メソッドの名前**                                 |
| **3番目の引数**   | **rdx**                                                         | **メソッドへの1番目の引数**                            |
| **4番目の引数**   | **rcx**                                                         | **メソッドへの2番目の引数**                            |
| **5番目の引数**   | **r8**                                                          | **メソッドへの3番目の引数**                            |
| **6番目の引数**   | **r9**                                                          | **メソッドへの4番目の引数**                            |
| **7番目以降の引数** | <p><strong>rsp+</strong><br><strong>(スタック上)</strong></p>   | **メソッドへの5番目以降の引数**                        |

### Swift

Swiftバイナリでは、Objective-Cとの互換性があるため、時々[class-dump](https://github.com/nygard/class-dump/)を使用して宣言を抽出できますが、常に可能とは限りません。

**`jtool -l`** や **`otool -l`** コマンドラインを使用すると、**`__swift5`** プレフィックスで始まるいくつかのセクションを見つけることができます：
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
これらのセクションに保存されている情報についての詳細は、[**このブログ投稿**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)で見つけることができます。

さらに、**Swiftバイナリにはシンボルが含まれることがあります**（例えば、ライブラリは関数を呼び出すためにシンボルを保存する必要があります）。**シンボルには通常、関数名と属性に関する情報が不格好な方法で含まれています**ので、非常に有用であり、元の名前を取得できる"**デマングラー**"があります：
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### パックされたバイナリ

* 高エントロピーをチェックする
* 文字列をチェックする（ほとんど理解できる文字列がない場合、パックされている）
* MacOS用のUPXパッカーは、"\_\_XHDR"というセクションを生成します

## 動的分析

{% hint style="warning" %}
バイナリをデバッグするためには、**SIPを無効にする必要があります**（`csrutil disable`または`csrutil enable --without debug`を実行）またはバイナリを一時フォルダにコピーし、**署名を削除します** `codesign --remove-signature <binary-path>`を使用するか、バイナリのデバッグを許可します（[このスクリプト](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)を使用できます）
{% endhint %}

{% hint style="warning" %}
システムバイナリ（例えば`cloudconfigurationd`）を**インストルメントする**ためには、macOS上で**SIPを無効にする必要があります**（署名を削除するだけでは機能しません）。
{% endhint %}

### 統合ログ

MacOSは、アプリケーションが実行されている際に非常に役立つ多くのログを生成します。**何をしているのか**を理解しようとするときに特に有用です。

さらに、いくつかのログには`<private>`タグが含まれており、**ユーザー**や**コンピューター**の**識別可能な**情報を**隠します**。しかし、この情報を開示するための**証明書をインストールすることが可能です**。[**こちら**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)から説明に従ってください。

### Hopper

#### 左パネル

Hopperの左パネルでは、バイナリのシンボル（**ラベル**）、手続きと関数のリスト（**Proc**）、文字列（**Str**）を見ることができます。これらはMac-Oファイルのいくつかの部分（例えば_cstringや`objc_methname`）で定義されている文字列のすべてではありません。

#### 中央パネル

中央パネルでは、**逆アセンブルされたコード**を見ることができます。そして、それぞれのアイコンをクリックすることで、**生の**逆アセンブル、**グラフ**として、**デコンパイルされた**コード、**バイナリ**として見ることができます：

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

コードオブジェクトを右クリックすると、そのオブジェクトへ/からの**参照**を見ることができたり、その名前を変更することができます（デコンパイルされた擬似コードでは機能しません）：

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

さらに、**中央下部でPythonコマンドを書くことができます**。

#### 右パネル

右パネルでは、**ナビゲーション履歴**（現在の状況にどのように到達したかを知ることができます）、**コールグラフ**（この関数を呼び出すすべての関数と、この関数が呼び出すすべての関数を見ることができます）、**ローカル変数**の情報など、興味深い情報を見ることができます。

### dtrace

dtraceは、非常に**低レベル**でアプリケーションにアクセスすることをユーザーに許可し、プログラムを**トレース**したり、実行フローを変更することさえできます。dtraceは、システムコールの開始と終了などの場所にあるカーネル全体に**配置された** **プローブ**を使用します。

DTraceは、各システムコールに対してプローブを作成するために**`dtrace_probe_create`**関数を使用します。これらのプローブは、各システムコールの**入口と出口で発火**することができます。DTraceとのやり取りは/dev/dtraceを通じて行われ、これはrootユーザーのみが利用可能です。

{% hint style="success" %}
SIP保護を完全に無効にせずにDtraceを有効にするには、リカバリーモードで次のコマンドを実行します：`csrutil enable --without dtrace`

また、**`dtrace`**や**`dtruss`**を、**自分でコンパイルした**バイナリに対して使用することもできます。
{% endhint %}

dtraceの利用可能なプローブは、次の方法で取得できます：
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
プローブ名は4つの部分で構成されています: プロバイダー、モジュール、関数、名前 (`fbt:mach_kernel:ptrace:entry`)。名前の一部を指定しない場合、Dtraceはその部分をワイルドカードとして適用します。

DTraceを設定してプローブをアクティブにし、それらが発火したときに実行するアクションを指定するには、D言語を使用する必要があります。

より詳細な説明と例については、[https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)で見つけることができます。

#### 例

`man -k dtrace` を実行して、**利用可能なDTraceスクリプト**をリストします。例: `sudo dtruss -n binary`

* 行内
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

**SIPが有効になっていても**これを使用できます
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) は、プロセスが実行しているプロセス関連のアクションをチェックするのに非常に便利なツールです（例えば、プロセスが作成する新しいプロセスを監視します）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) は、プロセス間の関係を出力するツールです。\
**`sudo eslogger fork exec rename create > cap.json`** のようなコマンドでmacを監視する必要があります（このコマンドを起動するターミナルにはFDAが必要です）。その後、このツールでjsonを読み込むと、すべての関係を確認できます：

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) は、ファイルイベント（作成、変更、削除など）を監視し、そのようなイベントに関する詳細情報を提供することができます。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) は、Microsoft Sysinternalの _Procmon_ からおなじみの外観と操作感を持つGUIツールです。すべての種類のイベントの記録の開始と停止を行い、カテゴリー（ファイル、プロセス、ネットワークなど）によってフィルタリングし、記録されたイベントをjsonファイルとして保存できます。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) はXcodeの開発ツールの一部であり、アプリケーションのパフォーマンスを監視し、メモリリークを特定し、ファイルシステムのアクティビティを追跡するために使用されます。

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

プロセスによって実行されるアクションを追跡することができます：
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**TaskExplorer**](https://objective-see.com/products/taskexplorer.html)は、バイナリによって使用されている**ライブラリ**、使用中の**ファイル**、および**ネットワーク**接続を確認するのに便利です。\
また、バイナリプロセスを**virustotal**と照合し、バイナリに関する情報を表示します。

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

[**このブログ投稿**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)では、**`PT_DENY_ATTACH`** を使用してSIPが無効になっていてもデバッグを防止する**実行中のデーモン**を**デバッグ**する方法の例が紹介されています。

### lldb

**lldb**は**macOS**バイナリの**デバッグ**における事実上のツールです。
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
```
lldbを使用する際には、ホームフォルダに**`.lldbinit`**というファイルを作成し、以下の行を設定することでintelフレーバーを設定できます:
```
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
lldb内で、`process save-core`を使ってプロセスをダンプします。
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) コマンド</strong></td><td><strong>説明</strong></td></tr><tr><td><strong>run (r)</strong></td><td>実行を開始し、ブレークポイントに達するかプロセスが終了するまで続けます。</td></tr><tr><td><strong>continue (c)</strong></td><td>デバッグされているプロセスの実行を続けます。</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>次の命令を実行します。このコマンドは関数呼び出しをスキップします。</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>次の命令を実行します。nextiコマンドとは異なり、このコマンドは関数呼び出しにステップインします。</td></tr><tr><td><strong>finish (f)</strong></td><td>現在の関数（"フレーム"）内の残りの命令を実行し、停止します。</td></tr><tr><td><strong>control + c</strong></td><td>実行を一時停止します。プロセスがrun (r)またはcontinue (c)されている場合、現在実行中の場所でプロセスを停止させます。</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #mainと呼ばれる任意の関数</p><p>b &#x3C;binname>`main #バイナリのmain関数</p><p>b set -n main --shlib &#x3C;lib_name> #指定されたバイナリのmain関数</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #ブレークポイントリスト</p><p>br e/dis &#x3C;num> #ブレークポイントの有効/無効化</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #ブレークポイントコマンドのヘルプを表示</p><p>help memory write #メモリへの書き込み方法についてのヘルプを表示</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>メモリをヌル終端文字列として表示します。</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>メモリをアセンブリ命令として表示します。</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>メモリをバイトとして表示します。</td></tr><tr><td><strong>print object (po)</strong></td><td><p>パラメータによって参照されるオブジェクトを表示します。</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>AppleのObjective-C APIやメソッドのほとんどはオブジェクトを返すため、"print object" (po) コマンドで表示する必要があります。poが意味のある出力をしない場合は<code>x/b</code>を使用します。</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #そのアドレスにAAAAを書き込む<br>memory write -f s $rip+0x11f+7 "AAAA" #アドレスにAAAAを書き込む</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #現在の関数を逆アセンブル</p><p>dis -n &#x3C;funcname> #関数を逆アセンブル</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #関数を逆アセンブル<br>dis -c 6 #6行を逆アセンブル<br>dis -c 0x100003764 -e 0x100003768 # 一つのアドレスから別のアドレスまで<br>dis -p -c 4 #現在のアドレスから逆アセンブルを開始</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1レジスタの3コンポーネントの配列をチェック</td></tr></tbody></table>

{% hint style="info" %}
**`objc_sendMsg`** 関数を呼び出す際、**rsi** レジスタはメソッドの**名前**をヌル終端の("C")文字列として保持します。lldbで名前を表示するには：

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### アンチダイナミック解析

#### VM検出

* コマンド **`sysctl hw.model`** は、**ホストがMacOSの場合**は"Mac"を返し、VMの場合は異なる値を返します。
* **`hw.logicalcpu`** と **`hw.physicalcpu`** の値を操作することで、一部のマルウェアはVMであるかを検出しようとします。
* 一部のマルウェアは、MACアドレス（00:50:56）に基づいて、マシンが**VMware**であるかを**検出**することもできます。
* 以下のような単純なコードで、**プロセスがデバッグされているかどうか**を見つけることも可能です：
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //プロセスがデバッグされている }`
* **`ptrace`** システムコールを **`PT_DENY_ATTACH`** フラグと共に呼び出すこともできます。これにより、デバッガーがアタッチしてトレースするのを**防ぎます**。
* **`sysctl`** または **`ptrace`** 関数が**インポートされているか**を確認できます（ただし、マルウェアは動的にインポートすることもあります）
* この記事で指摘されているように、"[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_メッセージ Process # exited with **status = 45 (0x0000002d)** は通常、デバッグ対象が **PT\_DENY\_ATTACH** を使用していることを示す兆候です_”

## ファジング

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrashは**クラッシュしたプロセスを分析し、クラッシュレポートをディスクに保存**します。クラッシュレポートには、クラッシュの原因を**診断するのに役立つ情報**が含まれています。\
ユーザーごとのlaunchdコンテキストで**実行されているアプリケーションやその他のプロセス**の場合、ReportCrashはLaunchAgentとして実行され、クラッシュレポートをユーザーの`~/Library/Logs/DiagnosticReports/`に保存します。\
デーモンやシステムlaunchdコンテキストで**実行されているその他のプロセス**、その他の特権プロセスの場合、ReportCrashはLaunchDaemonとして実行され、クラッシュレポートをシステムの`/Library/Logs/DiagnosticReports`に保存します。

クラッシュレポートが**Appleに送信されること**を心配している場合は、それらを無効にすることができます。そうでなければ、クラッシュレポートは**サーバーがクラッシュした原因を解明する**のに役立つことがあります。
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### スリープ

MacOSでファジングを行う際には、Macがスリープ状態にならないようにすることが重要です：

* systemsetup -setsleep Never
* pmset、システム環境設定
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH切断

SSH接続を介してファジングを行う場合、セッションが切断されないようにすることが重要です。そのためにはsshd\_configファイルを変更します：

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### 内部ハンドラー

**以下のページをチェックして**、指定されたスキームまたはプロトコルを処理しているアプリがどれかを見つける方法を確認してください：

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### ネットワークプロセスの列挙

これは、ネットワークデータを管理しているプロセスを見つけるのに興味深いです：
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
または `netstat` や `lsof` を使用する

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### ファジャー

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLIツールに対応しています。

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOSのGUIツールで**「そのまま動作する」**ことが特徴です。ただし、一部のmacOSアプリにはユニークなファイル名が必要だったり、正しい拡張子が必要だったり、サンドボックスからファイルを読み込む必要がある（`~/Library/Containers/com.apple.Safari/Data`）など、特定の要件があることに注意してください。

いくつかの例：

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
```markdown
{% endcode %}

### MacOSに関するさらなるFuzzing情報

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 参考文献

* [**OS X インシデント対応：スクリプティングと分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
```
