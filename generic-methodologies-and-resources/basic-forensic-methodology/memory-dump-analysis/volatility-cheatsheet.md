# Volatility - チートシート

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

- **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live) をフォローする
- **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに **PRを提出**して、あなたのハッキングトリックを共有する

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) は **スペイン** で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ** でも最も重要なイベントの1つです。**技術的知識の促進を使命とする** この会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

**複数のVolatilityプラグインを並行して実行**する **高速でクレイジーな** ものをお探しの場合は、[https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility) を使用できます。
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## インストール

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Method1" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="メソッド2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatilityコマンド

[Volatilityコマンドリファレンス](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)で公式ドキュメントにアクセスします。

### "list"と"scan"プラグインに関する注意事項

Volatilityには、プラグインに対する2つの主要なアプローチがあり、その名前に反映されることがあります。"list"プラグインは、Windowsカーネル構造をナビゲートしてプロセス（メモリ内の`_EPROCESS`構造体のリンクリストを検索してウォークする）、OSハンドル（ハンドルテーブルを検索してリスト化するなど）などの情報を取得しようとします。これらは、たとえばプロセスをリストアップする場合にWindows APIが要求された場合とほぼ同じように振る舞います。

これにより、"list"プラグインは非常に高速ですが、マルウェアによる操作に対してWindows APIと同様に脆弱です。たとえば、マルウェアがDKOMを使用してプロセスを`_EPROCESS`リンクリストから切り離すと、そのプロセスはタスクマネージャに表示されず、pslistにも表示されません。

一方で、"scan"プラグインは、特定の構造体としてデリファレンスされたときに意味をなす可能性のあるものをメモリから彫り取るようなアプローチを取ります。たとえば、`psscan`はメモリを読み取り、それを`_EPROCESS`オブジェクトにしようとします（プールタグスキャンを使用しています。これは、興味のある構造体の存在を示す4バイトの文字列を検索する方法です）。利点は、終了したプロセスを発見できることであり、たとえマルウェアが`_EPROCESS`リンクリストを改ざんしても、プラグインはメモリ内にその構造が残っていることを見つけることができます（プロセスが実行されるためには、それがまだ存在する必要があるため）。欠点は、"scan"プラグインが"list"プラグインよりもやや遅く、時々誤検知を引き起こすことがあることです（過去に終了したプロセスであり、その構造の一部が他の操作によって上書きされた場合など）。

出典: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OSプロファイル

### Volatility3

Readmeに記載されているように、サポートする**OSのシンボルテーブル**を_volatility3/volatility/symbols_に配置する必要があります。\
さまざまなオペレーティングシステム用のシンボルテーブルパックは、以下から**ダウンロード**できます:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### 外部プロファイル

サポートされているプロファイルのリストを取得するには、次の操作を行います:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
もし**ダウンロードした新しいプロファイル**（たとえばLinux用）を使用したい場合は、次のフォルダ構造を作成する必要があります：_plugins/overlays/linux_ そしてこのフォルダにプロファイルを含むzipファイルを入れます。その後、次のコマンドを使用してプロファイルの数を取得します：
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
**LinuxとMacのプロファイル**は[https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)からダウンロードできます。

前のチャンクでプロファイルが`LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`と呼ばれていることがわかります。これを使用して次のような操作を実行できます：
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### プロファイルの発見
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo と kdbgscan の違い**

**imageinfo** が単にプロファイルの提案を行うのに対し、**kdbgscan** は正確なプロファイルと正確な KDBG アドレス（複数ある場合）を確実に特定するよう設計されています。このプラグインは、Volatility プロファイルにリンクされた KDBGHeader シグネチャをスキャンし、偽陽性を減らすための整合性チェックを適用します。出力の冗長性と実行できる整合性チェックの数は、Volatility が DTB を見つけることができるかどうかに依存します。したがって、正しいプロファイルをすでに知っている場合（または imageinfo からプロファイルの提案を受け取っている場合）、それを使用するようにしてください（[こちら](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)から）。

常に **kdbgscan が見つけたプロセスの数** を確認してください。時々、imageinfo と kdbgscan は **1つ以上の適切なプロファイル** を見つけることができますが、**有効なものはプロセスに関連するものだけ** です（これはプロセスを抽出するために正しい KDBG アドレスが必要だからです）。
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

**カーネルデバッガブロック**（\_KDDEBUGGER\_DATA64型のKdDebuggerDataBlockとしても知られる、または**KDBG**としてvolatilityによって呼ばれる）は、Volatilityやデバッガが行う多くの作業に重要です。たとえば、プロセスリストに必要なすべてのプロセスのリストヘッドであるPsActiveProcessHeadへの参照が含まれています。

## OS情報
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
プラグイン`banners.Banners`は、ダンプファイル内で**Linuxのバナーを見つける**ために**vol3**で使用できます。

## ハッシュ/パスワード

SAMハッシュ、[ドメインキャッシュされた資格情報](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials)、および[lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets)を抽出します。

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% タブ タイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## メモリーダンプ

プロセスのメモリーダンプは、プロセスの現在の状態のすべてを**抽出**します。**procdump**モジュールはコードのみを**抽出**します。
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの1つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての沸騰する出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## プロセス

### プロセスのリスト

**疑わしい**プロセス（名前で）や**予期しない**子プロセス（たとえば、iexplorer.exeの子としてcmd.exeなど）を見つけてみてください。\
pslistの結果とpsscanの結果を比較して、隠れたプロセスを特定することが興味深いかもしれません。
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示する

```bash
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

### プロファイルを指定してプラグインを実行する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 plugin_name
```

### プロセス一覧を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 pslist
```

### ネットワーク接続を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 connections
```

### ファイル一覧を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 filescan
```

### レジストリキーを取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
```

### コマンド履歴を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 cmdscan
```

### ユーザー情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

### プロセスのDLLリストを取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 dlllist -p <PID>
```

### メモリダンプからファイルを抽出する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpfiles -Q <physical_offset>
```

### メモリダンプからプロセスの実行可能ファイルを抽出する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 procdump -p <PID> -D <output_directory>
```

### メモリダンプからレジストリハイブを抽出する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 hivelist
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -o <offset>
```

### メモリダンプからハッシュを取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 hashdump
```

### メモリダンプからユーザーパスワードを取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 mimikatz
```

### メモリダンプからセキュリティトークンを取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 tokens
```

### メモリダンプからシステムサービスディスパッチテーブルを取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 svcscan
```

### メモリダンプからキャッシュされたログインパスワードを取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 cachedump
```

### メモリダンプからネットワーク情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 netscan
```

### メモリダンプからシステム情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 sysinfo
```

### メモリダンプからシステムファイルキャッシュを取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 shimcache
```

### メモリダンプからドライバモジュール情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 modules
```

### メモリダンプからシステムハンドル情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 handles
```

### メモリダンプからシステムオブジェクト情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 objects
```

### メモリダンプからセキュリティディスクリプタ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsd
```

### メモリダンプからイベントログ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 evtlogs
```

### メモリダンプからハードウェア情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 hivex
```

### メモリダンプからユーザープロファイル情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userassist
```

### メモリダンプからレジストリ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
```

### メモリダンプからユーザーロード情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userhandles
```

### メモリダンプからユーザーマップ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userassist
```

### メモリダンプからユーザーセキュリティ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userassist
```

### メモリダンプからユーザーセキュリティ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userassist
```

### メモリダンプからユーザーセキュリティ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userassist
```

### メモリダンプからユーザーセキュリティ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userassist
```

### メモリダンプからユーザーセキュリティ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userassist
```

### メモリダンプからユーザーセキュリティ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userassist
```

### メモリダンプからユーザーセキュリティ情報を取得する

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 userassist
```
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### ダンプ処理

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### コマンドライン

何か怪しいことが実行されましたか？
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示する

```bash
volatility --info | less
```

### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <image> imageinfo
```

### プロファイルを指定してプロセスリストを表示する

```bash
volatility -f <image> --profile=<profile> pslist
```

### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <image> --profile=<profile> hivelist
```

### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <image> --profile=<profile> connections
```

### プロファイルを指定してファイルを表示する

```bash
volatility -f <image> --profile=<profile> filescan
```

### プロファイルを指定してコンソール履歴を表示する

```bash
volatility -f <image> --profile=<profile> consoles
```

### プロファイルを指定してシャットダウン時間を表示する

```bash
volatility -f <image> --profile=<profile> timeliner
```

### プロファイルを指定して特定のプロセスのメモリダンプを取得する

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### プロファイルを指定して特定のファイルを抽出する

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>
```

これらのコマンドを使用して、Volatilityを効果的に活用し、メモリダンプ解析を行うことができます。{% endtab %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
Commands entered into cmd.exe are processed by **conhost.exe** (csrss.exe prior to Windows 7). So even if an attacker managed to **kill the cmd.exe** **prior** to us obtaining a memory **dump**, there is still a good chance of **recovering history** of the command line session from **conhost.exe’s memory**. If you find **something weird** (using the console's modules), try to **dump** the **memory** of the **conhost.exe associated** process and **search** for **strings** inside it to extract the command lines.

### Environment

Get the env variables of each running process. There could be some interesting values.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### トークン特権

予期しないサービスで特権トークンをチェックします。\
特権トークンを使用しているプロセスをリストアップすることが興味深いかもしれません。
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示する

```bash
volatility --info | less
```

### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <imagefile> imageinfo
```

### プロファイルを指定してプロセスリストを表示する

```bash
volatility -f <imagefile> --profile=<profile> pslist
```

### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <imagefile> --profile=<profile> hivelist
```

### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <imagefile> --profile=<profile> connections
```

### プロファイルを指定してファイルシステムを表示する

```bash
volatility -f <imagefile> --profile=<profile> filescan
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profile> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのモジュールを表示する

```bash
volatility -f <imagefile> --profile=<profile> modscan -p <pid>
```

### プロファイルを指定して特定のプロセスのスレッドを表示する

```bash
volatility -f <imagefile> --profile=<profile> threads -p <pid>
```

### プロファイルを指定して特定のプロセスのダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### プロファイルを指定して特定のファイルをダウンロードする

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>
```

### プロファイルを指定してレジストリキーのダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> printkey -o <offset>
```

これらのコマンドを使用して、Volatilityを活用し、メモリダンプから貴重な情報を取得できます。{% endtab %}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
### SIDs

プロセスが所有する各SSIDをチェックします。\
特権SIDを使用しているプロセス（および一部のサービスSIDを使用しているプロセス）をリストアップすることが興味深いかもしれません。
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示
```bash
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

### プロファイルの確認
```bash
volatility -f memory_dump.raw imageinfo
```

### プロセス一覧の取得
```bash
volatility -f memory_dump.raw --profile=ProfileName pslist
```

### ネットワーク接続の確認
```bash
volatility -f memory_dump.raw --profile=ProfileName connections
```

### ファイルシステムのリスト
```bash
volatility -f memory_dump.raw --profile=ProfileName filescan
```

### レジストリキーのリスト
```bash
volatility -f memory_dump.raw --profile=ProfileName printkey -K "KeyName"
```

### プロセスのマッピング情報
```bash
volatility -f memory_dump.raw --profile=ProfileName vadinfo -p ProcessID
```

### メモリダンプからファイルを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName dumpfiles -Q AddressRange -D output_directory/
```

### ユーザー情報の取得
```bash
volatility -f memory_dump.raw --profile=ProfileName hivelist
volatility -f memory_dump.raw --profile=ProfileName printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
```

### ログオンセッションの確認
```bash
volatility -f memory_dump.raw --profile=ProfileName sessions
```

### プロセスのコマンドライン引数
```bash
volatility -f memory_dump.raw --profile=ProfileName cmdline -p ProcessID
```

### メモリダンプから実行可能ファイルを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName malfind
```

### メモリダンプから DLL を抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName dlllist -p ProcessID
```

### メモリダンプからレジストリファイルを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName hivelist
volatility -f memory_dump.raw --profile=ProfileName printkey -o Offset
volatility -f memory_dump.raw --profile=ProfileName dumpregistry -o Offset -D output_directory/
```

### メモリダンプからネットワークトラフィックを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName netscan
```

### メモリダンプからプロセスのハンドルを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName handles -p ProcessID
```

### メモリダンプからセキュリティ属性を抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName getsids
```

### メモリダンプからセキュリティディスクリプタを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName getsd
```

### メモリダンプからセキュリティディスクリプタを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName getsd
```

### メモリダンプからセキュリティディスクリプタを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName getsd
```

### メモリダンプからセキュリティディスクリプタを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName getsd
```

### メモリダンプからセキュリティディスクリプタを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName getsd
```

### メモリダンプからセキュリティディスクリプタを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName getsd
```

### メモリダンプからセキュリティディスクリプタを抽出
```bash
volatility -f memory_dump.raw --profile=ProfileName getsd
```
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### ハンドル

プロセスがハンドルを持っている（開いている）他のファイル、キー、スレッド、プロセスを知るのに役立ちます。
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% タブ タイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### DLLs

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% タブ タイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### プロセスごとの文字列

Volatilityを使用すると、文字列がどのプロセスに属しているかを確認できます。
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示
```
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

### プロファイルを指定してイメージファイルの情報を表示
```
volatility -f memory_dump.raw imageinfo --profile=Win7SP1x64
```

### 特定のプロセスのネットワーク接続を表示
```
volatility -f memory_dump.raw --profile=Win7SP1x64 netscan -p PID
```

### レジストリキーの値を表示
```
volatility -f memory_dump.raw --profile=Win7SP1x64 printkey -o OFFSET -K "Software\Microsoft\Windows\CurrentVersion\Run"
```

### プロセスのハンドルを表示
```
volatility -f memory_dump.raw --profile=Win7SP1x64 handles -p PID
```

### ファイルキャッシュを表示
```
volatility -f memory_dump.raw --profile=Win7SP1x64 filescan | grep -i "file_name"
```

### プロセスのコマンドラインを表示
```
volatility -f memory_dump.raw --profile=Win7SP1x64 cmdline -p PID
```

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。{% endtab %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

プロセス内の文字列を検索するためにyarascanモジュールを使用することもできます。
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示する

```bash
volatility --info | less
```

### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <imagefile> imageinfo
```

### プロファイルを指定してプロセスリストを表示する

```bash
volatility -f <imagefile> --profile=<profile> pslist
```

### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <imagefile> --profile=<profile> hivelist
```

### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <imagefile> --profile=<profile> connections
```

### プロファイルを指定してファイルシステムを表示する

```bash
volatility -f <imagefile> --profile=<profile> filescan
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profile> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのモジュールを表示する

```bash
volatility -f <imagefile> --profile=<profile> modscan -p <pid>
```

### プロファイルを指定して特定のプロセスのスレッドを表示する

```bash
volatility -f <imagefile> --profile=<profile> threads -p <pid>
```

### プロファイルを指定して特定のプロセスのダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### プロファイルを指定してレジストリのダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> printkey -o <offset>
```

### プロファイルを指定して特定のファイルをダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -Q <file_path>
```

### プロファイルを指定して特定のファイルの内容をダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -r <file_path>
```

### プロファイルを指定してレジストリのハイブをダンプする

```bash
volatility -f <imagefile> --profile=<profile> hivedump -o <offset> -D <output_directory>
```

### プロファイルを指定してハッシュを取得する

```bash
volatility -f <imagefile> --profile=<profile> hashdump
```

### プロファイルを指定してユーザ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> userassist
```

### プロファイルを指定してコマンドヒストリを表示する

```bash
volatility -f <imagefile> --profile=<profile> cmdscan
```

### プロファイルを指定してレジストリのキーをダンプする

```bash
volatility -f <imagejson> --profile=<profile> printkey -o <offset>
```

### プロファイルを指定して特定のプロセスのダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### プロファイルを指定してレジストリのダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> printkey -o <offset>
```

### プロファイルを指定して特定のファイルをダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -Q <file_path>
```

### プロファイルを指定して特定のファイルの内容をダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -r <file_path>
```

### プロファイルを指定してレジストリのハイブをダンプする

```bash
volatility -f <imagefile> --profile=<profile> hivedump -o <offset> -D <output_directory>
```

### プロファイルを指定してハッシュを取得する

```bash
volatility -f <imagefile> --profile=<profile> hashdump
```

### プロファイルを指定してユーザ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> userassist
```

### プロファイルを指定してコマンドヒストリを表示する

```bash
volatility -f <imagefile> --profile=<profile> cmdscan
```
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows**システムは、実行されたプログラムを追跡するためにレジストリデータベース（**UserAssist keys**）に一連の**keys**を維持します。これらの**keys**には、実行回数や最終実行日時が利用可能です。
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示
```
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

### プロファイルの確認
```
volatility -f memory.raw imageinfo
```

### プロセス一覧の取得
```
volatility -f memory.raw --profile=ProfileName pslist
```

### 特定のプロセスの詳細情報を取得
```
volatility -f memory.raw --profile=ProfileName pstree -p ProcessID
```

### ネットワーク接続の確認
```
volatility -f memory.raw --profile=ProfileName connections
```

### ファイルシステムのリストを表示
```
volatility -f memory.raw --profile=ProfileName filescan
```

### レジストリキーのリストを表示
```
volatility -f memory.raw --profile=ProfileName printkey -o Offset
```

### コマンド履歴の取得
```
volatility -f memory.raw --profile=ProfileName cmdscan
```

### ユーザアカウントのリストを表示
```
volatility -f memory.raw --profile=ProfileName hivelist
volatility -f memory.raw --profile=ProfileName hivelist -o Offset
volatility -f memory.raw --profile=ProfileName hashdump -o Offset
```

### プロセスのメモリダンプ
```
volatility -f memory.raw --profile=ProfileName procdump -p ProcessID -D /dump/directory
```

### メモリダンプのファイルキャッシュを表示
```
volatility -f memory.raw --profile=ProfileName filecache
```

### メモリダンプからファイルを抽出
```
volatility -f memory.raw --profile=ProfileName dumpfiles -Q Offset --dump-dir /dump/directory
```

これらのコマンドを使用して、メモリダンプから貴重な情報を取得できます。{% endtab %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## サービス

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## ネットワーク

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
## レジストリハイブ

### 利用可能なハイブの表示

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
### 値を取得する

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
### ダンプ
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## ファイルシステム

### マウント

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関するVolatilityチートシートです。

### Volatilityチートシート

- **プラグインのリストを表示**: `volatility --info | less`
- **プロファイルのリストを表示**: `volatility --info | grep Profile`
- **プロファイルを指定して実行**: `volatility -f <ファイル名> --profile=<プロファイル名> <プラグイン名>`
- **プロセスリストを表示**: `volatility -f <ファイル名> --profile=<プロファイル名> pslist`
- **ネットワーク接続を表示**: `volatility -f <ファイル名> --profile=<プロファイル名> netscan`
- **レジストリキーを表示**: `volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <RegistryKey>`
- **ファイルを抽出**: `volatility -f <ファイル名> --profile=<プロファイル名> dump -D <出力ディレクトリ> --pid=<プロセスID> --name=<ファイル名>`
- **コマンドシェルを実行**: `volatility -f <ファイル名> --profile=<プロファイル名> cmdline -p <プロセスID>`
- **ダンプされたファイルをファイルシステムにマウント**: `volatility -f <ファイル名> --profile=<プロファイル名> mount -t <ファイルシステム> -o <オプション>`
- **プロセスのDLLリストを表示**: `volatility -f <ファイル名> --profile=<プロファイル名> dlllist -p <プロセスID>`

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。{% endtab %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
### スキャン/ダンプ

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関するVolatilityチートシートです。

### Volatilityチートシート

- **プラグインのリストを表示**: `volatility --info | less`
- **プロファイルのリストを表示**: `volatility --info | grep Profile`
- **プロファイルを指定して実行**: `volatility -f <ファイル名> --profile=<プロファイル名> <プラグイン名>`
- **プロセスリストを表示**: `volatility -f <ファイル名> --profile=<プロファイル名> pslist`
- **ネットワーク接続を表示**: `volatility -f <ファイル名> --profile=<プロファイル名> netscan`
- **レジストリキーを表示**: `volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <RegistryKey>`
- **ファイルをダンプ**: `volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <Offset>`
- **コマンド履歴を表示**: `volatility -f <ファイル名> --profile=<プロファイル名> cmdscan`

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### マスターファイルテーブル

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatilityチートシート

### プラグインのリストを表示する

```bash
volatility --info | less
```

### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <image> imageinfo
```

### プロファイルを指定してプロセス一覧を表示する

```bash
volatility -f <image> --profile=<profile> pslist
```

### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <image> --profile=<profile> hivelist
```

### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <image> --profile=<profile> connections
```

### プロファイルを指定してファイル一覧を表示する

```bash
volatility -f <image> --profile=<profile> filescan
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <image> --profile=<profile> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのDLLリストを表示する

```bash
volatility -f <image> --profile=<profile> dlllist -p <pid>
```

### プロファイルを指定して特定のプロセスのメモリダンプを取得する

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### プロファイルを指定して特定のファイルを抽出する

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>
```

これらのコマンドを使用して、Volatilityを活用し、メモリダンプ解析を行うことができます。{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

NTFSファイルシステムには、_マスターファイルテーブル_またはMFTと呼ばれるファイルが含まれています。NTFSファイルシステムボリューム上のすべてのファイルには、MFTに少なくとも1つのエントリがあります（MFT自体を含む）。**ファイルに関するすべての情報（サイズ、時刻と日付のスタンプ、権限、データ内容など）**は、MFTエントリまたはMFTエントリによって記述されるMFTの外側のスペースに格納されています。[こちら](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)から。
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## マルウェア

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}

### Yaraでスキャン

このスクリプトを使用して、githubからすべてのyaraマルウェアルールをダウンロードしてマージします: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ディレクトリを作成して、実行します。これにより、マルウェアのすべてのyaraルールが含まれる_**malware\_rules.yar**_というファイルが作成されます。
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## その他

### 外部プラグイン

外部プラグインを使用したい場合は、プラグインに関連するフォルダが最初に使用されるパラメータであることを確認してください。
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関するVolatilityチートシートです。

### Volatilityチートシート

- **プラグインのリストを表示**: `volatility --info | less`
- **プロファイルのリストを表示**: `volatility --info | grep Profile`
- **プロファイルを指定して実行**: `volatility -f <ファイル名> --profile=<プロファイル名> <プラグイン名>`
- **プロセスリストを表示**: `volatility -f <ファイル名> --profile=<プロファイル名> pslist`
- **ネットワーク接続を表示**: `volatility -f <ファイル名> --profile=<プロファイル名> netscan`
- **レジストリキーを表示**: `volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キー名>`
- **ファイルをダンプ**: `volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <プロセスID> -D <出力ディレクトリ>`
- **コマンド履歴を表示**: `volatility -f <ファイル名> --profile=<プロファイル名> cmdscan`

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。{% endtab %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
#### Autoruns

[https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% タブのタイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### シンボリックリンク

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatilityチートシート

### プラグインのリストを表示
```bash
volatility --info | grep -iE "rule|plugin"
```

### プロファイルのリストを表示
```bash
volatility --info | grep -i "profile"
```

### プロファイルを指定してプラグインを実行
```bash
volatility -f <memory_dump> --profile=<profile> <plugin_name>
```

### プロセス一覧を表示
```bash
volatility -f <memory_dump> --profile=<profile> pslist
```

### ネットワーク接続を表示
```bash
volatility -f <memory_dump> --profile=<profile> connections
```

### ファイル一覧を表示
```bash
volatility -f <memory_dump> --profile=<profile> filescan
```

### レジストリキーを表示
```bash
volatility -f <memory_dump> --profile=<profile> printkey -o <offset>
```

### レジストリ値を表示
```bash
volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key>
```

### プロセスのDLLリストを表示
```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>
```

### プロセスのハンドルを表示
```bash
volatility -f <memory_dump> --profile=<profile> handles -p <pid>
```

### キャッシュされたログイン情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> hashdump
```

### システムのサービス情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> svcscan
```

### システムのドライバ情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> driverscan
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> hivelist
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> userassist
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> shimcache
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> ldrmodules
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> malfind
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> apihooks
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> callbacks
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> idt
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> gdt
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> threads
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> mutantscan
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> getsids
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> modscan
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> psxview
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> vadinfo
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> vadtree
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> cmdline
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> consoles
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> envars
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> vadwalk
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> memmap
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> memstrings -s <string_length>
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> mftparser
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> shimcachemem
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> timeliner
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> truecryptmaster
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> truecryptpassphrase
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> truecryptsummary
```

### キャッシュされたユーザー情報を表示
```bash
volatility -f <memory_dump> --profile=<profile> windows
```
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

**メモリからbashの履歴を読むことが可能です。** _.bash\_history_ ファイルをダンプすることもできますが、無効になっている場合は、このVolatilityモジュールを使用できることに喜ぶでしょう。
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% タブ タイトル="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### タイムライン

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% タブのタイトル="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
### ドライバー

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する基本的な手法に関する情報です。

## Volatility チートシート

### プラグインのリストを表示
```bash
volatility --info | less
```

### プロファイルを指定してイメージファイルの情報を表示
```bash
volatility -f <image> imageinfo
```

### プロファイルを指定してプロセスリストを表示
```bash
volatility -f <image> --profile=<profile> pslist
```

### プロファイルを指定してネットワーク接続を表示
```bash
volatility -f <image> --profile=<profile> connections
```

### プロファイルを指定してレジストリキーを表示
```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

### プロファイルを指定してファイルをダンプ
```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address>
```

### プロファイルを指定して特定のプロセスのスタックを表示
```bash
volatility -f <image> --profile=<profile> stack -p <pid>
```

### プロファイルを指定して特定のプロセスのヒープを表示
```bash
volatility -f <image> --profile=<profile> memdump -p <pid> -D <output_directory>
```

これらのコマンドを使用して、メモリダンプ解析を効果的に行うことができます。{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
### クリップボードの取得
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IEの履歴を取得
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### メモ帳のテキストを取得
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### スクリーンショット
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### マスターブートレコード（MBR）
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
MBRは、そのメディア上に配置された[ファイルシステム](https://en.wikipedia.org/wiki/File_system)を含む論理パーティションがどのように構成されているかの情報を保持しています。MBRには、通常、インストールされたオペレーティングシステムに制御を渡すためのローダーとして機能する実行可能コードも含まれており、通常はローダーの[第二段階](https://en.wikipedia.org/wiki/Second-stage_boot_loader)に制御を渡すか、各パーティションの[ボリュームブートレコード](https://en.wikipedia.org/wiki/Volume_boot_record)（VBR）と連動して機能します。このMBRコードは通常、[ブートローダー](https://en.wikipedia.org/wiki/Boot_loader)と呼ばれています。[こちら](https://en.wikipedia.org/wiki/Master_boot_record)から。

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの一つです。**技術的知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**を使って、ゼロからヒーローまでAWSハッキングを学びましょう！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**する
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>
