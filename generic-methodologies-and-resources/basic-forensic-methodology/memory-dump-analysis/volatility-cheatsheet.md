# Volatility - チートシート

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

- **HackTricks で企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする
- **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください**

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの1つです。**技術的知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての沸騰する出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

**複数のVolatilityプラグインを並行して実行する**高速でクレイジーなものが必要な場合は、[https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)を使用できます。
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
#### volatility2

{% tabs %}
{% tab title="メソッド1" %}
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

Volatilityには、プラグインに対する2つの主要なアプローチがあり、その名前に反映されることがあります。"list"プラグインは、Windowsカーネル構造をナビゲートしてプロセス（メモリ内の`_EPROCESS`構造体のリンクリストを検索してウォークする）、OSハンドル（ハンドルテーブルを検出してリスト化するなど）などの情報を取得しようとします。これらは、たとえばプロセスをリストアップする場合にWindows APIが要求された場合とほぼ同じように振る舞います。

これにより、"list"プラグインは非常に高速ですが、Windows APIと同様にマルウェアによる操作の脆弱性があります。たとえば、マルウェアがDKOMを使用してプロセスを`_EPROCESS`リンクリストから切り離すと、そのプロセスはタスクマネージャに表示されず、pslistにも表示されません。

一方で、"scan"プラグインは、特定の構造体としてデリファレンスされたときに意味をなす可能性のあるものをメモリから彫り取るようなアプローチを取ります。たとえば、`psscan`はメモリを読み取り、それを`_EPROCESS`オブジェクトにしようとします（プールタグスキャンを使用しています。これは、興味のある構造体の存在を示す4バイトの文字列を検索する方法です）。利点は、終了したプロセスを発見できることであり、たとえマルウェアが`_EPROCESS`リンクリストを改ざんしても、プラグインはメモリ内にその構造が残っていることを見つけることができます（プロセスが実行されるためには、それがまだ存在する必要があるため）。欠点は、"scan"プラグインが"list"プラグインよりもやや遅く、時々誤検知を引き起こすことがあることです（過去に終了したプロセスであり、その構造の一部が他の操作によって上書きされた場合など）。

出典: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OSプロファイル

### Volatility3

Readmeに記載されているように、サポートしたい**OSのシンボルテーブル**を_volatility3/volatility/symbols_に配置する必要があります。\
さまざまなオペレーティングシステム用のシンボルテーブルパックは、以下から**ダウンロード**できます:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### 外部プロファイル

サポートされているプロファイルのリストを取得するには、以下を実行します:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
もし**ダウンロードした新しいプロファイル**（たとえばLinux用）を使用したい場合は、次のフォルダ構造を作成する必要があります：_plugins/overlays/linux_ そしてこのフォルダの中にプロファイルを含むzipファイルを入れます。その後、次のコマンドを使用してプロファイルの数を取得します：
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

前のチャンクでは、プロファイルが`LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`と呼ばれていることがわかります。これを使用して次のような操作を実行できます：
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### プロファイルの発見
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo と kdbgscan の違い**

[**こちらから**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): imageinfo が単にプロファイルの提案を行うのに対し、**kdbgscan** は正確なプロファイルと正確な KDBG アドレス（複数ある場合）を確実に特定するよう設計されています。このプラグインは、Volatility プロファイルにリンクされた KDBGHeader シグネチャをスキャンし、偽陽性を減らすための整合性チェックを適用します。出力の冗長性と実行できる整合性チェックの数は、Volatility が DTB を見つけることができるかどうかに依存します。したがって、正しいプロファイルをすでに知っている場合（または imageinfo からプロファイルの提案を受け取った場合）、それを使用することを確認してください。

常に **kdbgscan が見つけたプロセスの数**を確認してください。時々、imageinfo と kdbgscan は **1 つ以上の適切なプロファイル**を見つけることができますが、**有効なものはプロセスに関連するものだけ**です（これはプロセスを抽出するには正しい KDBG アドレスが必要だからです）。
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

**カーネルデバッガブロック**は、Volatilityによって**KDBG**として参照され、Volatilityやさまざまなデバッガによって実行されるフォレンジックタスクにとって重要です。 `_KDDEBUGGER_DATA64`タイプの`KdDebuggerDataBlock`として識別され、`PsActiveProcessHead`のような重要な参照情報を含んでいます。この特定の参照は、プロセスリストの先頭を指し示し、すべてのプロセスのリスト化を可能にします。これは徹底的なメモリ解析に不可欠です。

## OS情報
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
プラグイン`banners.Banners`は、ダンプファイル内で**Linuxのバナーを見つける**ために**vol3で使用**できます。

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

​​​[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの1つです。**技術的知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとって沸騰する出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## プロセス

### プロセスのリスト

**疑わしい**プロセス（名前で）や**予期しない**子プロセス（たとえば、iexplorer.exeの子としてcmd.exe）を見つけてみてください。\
pslistの結果とpsscanの結果を比較して、隠れたプロセスを特定することが興味深いかもしれません。
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する基本的な手法に関する情報です。

## Volatility チートシート

### プラグインのリストを表示
```
volatility --info
```

### プロファイルのリストを表示
```
volatility --info | grep Profile
```

### プロファイルを指定してプラグインを実行
```
volatility -f <dumpfile> --profile=<profile> <plugin>
```

### プロセスリストを表示
```
volatility -f <dumpfile> --profile=<profile> pslist
```

### ネットワーク接続を表示
```
volatility -f <dumpfile> --profile=<profile> connections
```

### ファイルシステムキャッシュを表示
```
volatility -f <dumpfile> --profile=<profile> cachedump
```

### レジストリキーを表示
```
volatility -f <dumpfile> --profile=<profile> printkey -o <offset>
```

### レジストリリストを表示
```
volatility -f <dumpfile> --profile=<profile> hivelist
```

### レジストリ値を表示
```
volatility -f <dumpfile> --profile=<profile> printkey -K <key>
```

### レジストリデータを表示
```
volatility -f <dumpfile> --profile=<profile> printkey -o <offset>
```

これらのコマンドを使用して、メモリダンプから有用な情報を取得し、フォレンジック調査をサポートします。{% endtab %}
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

{% タブ タイトル="vol2" %}
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
volatility -f <imagefile> imageinfo --profile=<profile>
```

### プロファイルを指定してプロセスリストを表示する

```bash
volatility -f <imagefile> --profile=<profile> pslist
```

### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <imagefile> --profile=<profile> printkey -K <key>
```

### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <imagefile> --profile=<profile> connections
```

### プロファイルを指定してファイルを表示する

```bash
volatility -f <imagefile> --profile=<profile> filescan
```

### プロファイルを指定してコマンドヒストリを表示する

```bash
volatility -f <imagefile> --profile=<profile> cmdscan
```

### プロファイルを指定してプロセスのハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profile> handles
```

### プロファイルを指定してレジストリのハッシュを表示する

```bash
volatility -f <imagefile> --profile=<profile> hivelist
```

### プロファイルを指定してファイルのハッシュを表示する

```bash
volatility -f <imagefile> --profile=<profile> filehash
```

### プロファイルを指定してマルウェアの検出を行う

```bash
volatility -f <imagefile> --profile=<profile> malfind
```

### プロファイルを指定してプロセスのダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### プロファイルを指定してサービスのリストを表示する

```bash
volatility -f <imagefile> --profile=<profile> svcscan
```

### プロファイルを指定してタイムラインを生成する

```bash
volatility -f <imagefile> --profile=<profile> timeliner
```

### プロファイルを指定してレジストリのデータをダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpregistry -D <output_directory>
```

### プロファイルを指定してファイルのダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>
```

### プロファイルを指定してユーザアカウント情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> hashdump
```

### プロファイルを指定してシステム情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> sysinfo
```

### プロファイルを指定してキャッシュ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> cachedump
```

### プロファイルを指定してシステムサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids
```

### プロファイルを指定してドライバモジュール情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> ldrmodules
```

### プロファイルを指定してユーザ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> userassist
```

### プロファイルを指定してシステムコール情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> syscall
```

### プロファイルを指定してセキュリティディスクリプタ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getsids
```

### プロファイルを指定してハッシュ値を計算する

```bash
volatility -f <imagefile> --profile=<profile> hashdump
```

### プロファイルを指定してユーザ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> userassist
```

### プロファイルを指定してシステムコール情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> syscall
```

### プロファイルを指定してセキュリティディスクリプタ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getsids
```

### プロファイルを指定してハッシュ値を計算する

```bash
volatility -f <imagefile> --profile=<profile> hashdump
```

### プロファイルを指定してユーザ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> userassist
```

### プロファイルを指定してシステムコール情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> syscall
```

### プロファイルを指定してセキュリティディスクリプタ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getsids
```

### プロファイルを指定してハッシュ値を計算する

```bash
volatility -f <imagefile> --profile=<profile> hashdump
```

### プロファイルを指定してユーザ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> userassist
```

### プロファイルを指定してシステムコール情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> syscall
```

### プロファイルを指定してセキュリティディスクリプタ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getsids
```

### プロファイルを指定してハッシュ値を計算する

```bash
volatility -f <imagefile> --profile=<profile> hashdump
```

### プロファイルを指定してユーザ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> userassist
```

### プロファイルを指定してシステムコール情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> syscall
```

### プロファイルを指定してセキュリティディスクリプタ情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getsids
```
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

`cmd.exe`で実行されたコマンドは**`conhost.exe`**によって管理されます（Windows 7より前のシステムでは`csrss.exe`）。これは、攻撃者によって**`cmd.exe`**が終了された場合でも、**`conhost.exe`**のメモリからセッションのコマンド履歴を回復することができる可能性があることを意味します。異常なアクティビティがコンソールのモジュールで検出された場合、関連する**`conhost.exe`**プロセスのメモリをダンプする必要があります。その後、このダンプ内で**strings**を検索することで、セッションで使用されたコマンドラインを抽出することができるかもしれません。

### 環境

実行中の各プロセスの環境変数を取得します。興味深い値があるかもしれません。
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
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

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <image> --profile=<profile> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのDLLを表示する

```bash
volatility -f <image> --profile=<profile> dlllist -p <pid>
```

### プロファイルを指定して特定のプロセスのスレッドを表示する

```bash
volatility -f <image> --profile=<profile> threads -p <pid>
```

### プロファイルを指定して特定のプロセスのメモリダンプを取得する

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### プロファイルを指定してレジストリの内容をダンプする

```bash
volatility -f <image> --profile=<profile> printkey -o <offset>
```

### プロファイルを指定して特定のファイルをダンプする

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address_range>
```

これらのコマンドを使用して、Volatilityを使用してメモリダンプを効果的に解析できます。

{% endtab %}
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
volatility --info | grep -iE "profile|plugin"
```

### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <image> imageinfo --profile=<profile>
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

### プロファイルを指定してファイルシステムを表示する

```bash
volatility -f <image> --profile=<profile> filescan
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <image> --profile=<profile> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのファイルディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> filescan | grep <pid>
```

### プロファイルを指定して特定のファイルをダンプする

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address>
```

### プロファイルを指定してレジストリキーの内容を表示する

```bash
volatility -f <image> --profile=<profile> printkey -o <offset>
```

### プロファイルを指定して特定のプロセスのスタックトレースを表示する

```bash
volatility -f <image> --profile=<profile> pstree -p <pid>
```

### プロファイルを指定して特定のプロセスのモジュールリストを表示する

```bash
volatility -f <image> --profile=<profile> dlllist -p <pid>
```

### プロファイルを指定して特定のプロセスのメモリマップを表示する

```bash
volatility -f <image> --profile=<profile> memmap -p <pid>
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する

```bash
volatility -f <image> --profile=<profile> screenshot -p <pid> --dump-dir=<output_directory>
```

### プロファイルを指定して特定のプロセスのスレッドリストを表示する

```bash
volatility -f <image> --profile=<profile> threads -p <pid>
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <image> --profile=<profile> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <image> --profile=<profile> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```

### プロファイルを指定して特定のプロセスのサービスディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsids -p <pid>
```

### プロファイルを指定して特定のプロセスのセキュリティディスクリプタを表示する

```bash
volatility -f <image> --profile=<profile> getsd -p <pid>
```
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

{% タブ タイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### ハンドル

プロセスがハンドルを持っている他のファイル、キー、スレッド、プロセスを知るために役立ちます。
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% タブのタイトル="vol2" %}
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

{% タブのタイトル="vol2" %}
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

### プロファイルを指定してファイルを表示する

```bash
volatility -f <imagefile> --profile=<profile> filescan
```

### プロファイルを指定してコマンド履歴を表示する

```bash
volatility -f <imagefile> --profile=<profile> cmdscan
```

### プロファイルを指定してレジストリをダンプする

```bash
volatility -f <imagefile> --profile=<profile> printkey -K <registrykey>
```

### プロファイルを指定してプロセスのダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> procdump -p <pid> -D <outputdirectory>
```

### プロファイルを指定して特定のプロセスのスタックトレースを表示する

```bash
volatility -f <imagefile> --profile=<profile> psscan
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profile> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのDLLリストを表示する

```bash
volatility -f <imagefile> --profile=<profile> dlllist -p <pid>
```

### プロファイルを指定して特定のプロセスのモジュール情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> modscan -p <pid>
```

### プロファイルを指定して特定のプロセスのネットワーク情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> connscan -p <pid>
```

### プロファイルを指定して特定のプロセスのファイルハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profile> filehandles -p <pid>
```

### プロファイルを指定して特定のプロセスのマルウェア解析を実行する

```bash
volatility -f <imagefile> --profile=<profile> malfind -p <pid>
```

### プロファイルを指定して特定のプロセスのレジストリキーを表示する

```bash
volatility -f <imagejson> --profile=<profile> printkey -K <registrykey>
```

### プロファイルを指定して特定のプロセスのレジストリ値を表示する

```bash
volatility -f <imagefile> --profile=<profile> printkey -K <registrykey> -V <registryvalue>
```

### プロファイルを指定して特定のプロセスのレジストリ値をダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpregistry -s <registrykey> -D <outputdirectory>
```

### プロファイルを指定して特定のプロセスのファイルをダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -Q <pid> -D <outputdirectory>
```

### プロファイルを指定して特定のプロセスのネットワーク情報をダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpnets -Q <pid> -D <outputdirectory>
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する

```bash
volatility -f <imagefile> --profile=<profile> screenshot -p <pid> -D <outputdirectory>
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory>
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format>
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality>
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution>
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示、プロセスツリー表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid --tree
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示、プロセスツリー表示、プロセスツリーID表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid --tree --treeid
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示、プロセスツリー表示、プロセスツリーID表示、プロセスツリー名表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid --tree --treeid --treename
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示、プロセスツリー表示、プロセスツリーID表示、プロセスツリー名表示、プロセスツリー親ID表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid --tree --treeid --treename --parent
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示、プロセスツリー表示、プロセスツリーID表示、プロセスツリー名表示、プロセスツリー親ID表示、プロセスツリー親名表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid --tree --treeid --treename --parent --parentname
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示、プロセスツリー表示、プロセスツリーID表示、プロセスツリー名表示、プロセスツリー親ID表示、プロセスツリー親名表示、プロセスツリー親親ID表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid --tree --treeid --treename --parent --parentname --grandparent
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示、プロセスツリー表示、プロセスツリーID表示、プロセスツリー名表示、プロセスツリー親ID表示、プロセスツリー親名表示、プロセスツリー親親ID表示、プロセスツリー親親名表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid --tree --treeid --treename --parent --parentname --grandparent --grandparentname
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示、プロセスツリー表示、プロセスツリーID表示、プロセスツリー名表示、プロセスツリー親ID表示、プロセスツリー親名表示、プロセスツリー親親ID表示、プロセスツリー親親名表示、プロセスツリー親親親ID表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid --tree --treeid --treename --parent --parentname --grandparent --grandparentname --greatgrandparent
```

### プロファイルを指定して特定のプロセスのスクリーンショットを取得する（全てのプロセス）（画像形式指定、圧縮、解像度指定、タイムスタンプ付与、プロセス名表示、プロセスID表示、プロセスツリー表示、プロセスツリーID表示、プロセスツリー名表示、プロセスツリー親ID表示、プロセスツリー親名表示、プロセスツリー親親ID表示、プロセスツリー親親名表示、プロセスツリー親親親ID表示、プロセスツリー親親親名表示）

```bash
volatility -f <imagefile> --profile=<profile> screenshot -D <outputdirectory> --format=<format> --quality=<quality> --resolution=<resolution> --timestamp --processtree --pid --tree --treeid --treename --parent --parentname --grandparent --grandparentname --greatgrandparent --greatgrandparentname
```
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

{% タブ タイトル="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows**は、**UserAssistキー**と呼ばれるレジストリ内の機能を使用して、実行したプログラムの履歴を追跡します。これらのキーは、各プログラムが実行された回数と最後に実行された日時を記録します。
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示
```bash
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

### プロファイルを指定してイメージファイルの情報を表示
```bash
volatility -f memory_dump.mem imageinfo --profile=Win7SP1x64
```

### 特定のプロセスのプロセスID（PID）を取得
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 pslist | grep process_name
```

### 特定のプロセスのメモリダンプを取得
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 memdump -p pid -D output_directory/
```

### レジストリキーの値を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -o offset
```

### ファイルを抽出
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpfiles -Q offset --dump-dir=output_directory/
```

### ネットワーク接続を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 connections
```

### ネットワークトラフィックを表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 tcpflow -p pid
```

### プロセスのDLLリストを表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 dlllist -p pid
```

### プロセスのハンドルを表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 handles -p pid
```

### キャッシュされたログイン資格情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 cachedump
```

### システムのサービス情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 svcscan
```

### システムのドライバモジュール情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 modules
```

### システムのタスクスケジュール情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

### システムのファイルキャッシュ情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 filescan
```

### システムのユーザ情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

### システムのユーザ情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

### システムのユーザ情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

### システムのユーザ情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

### システムのユーザ情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

### システムのユーザ情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

### システムのユーザ情報を表示
```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの1つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## サービス

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
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

### プロファイルを指定して特定のファイルを抽出する

```bash
volatility -f <imagefile> --profile=<profile> fileextract -f <file_path> -D <output_directory>
```

これらのコマンドを使用して、メモリダンプからさまざまな情報を取得できます。{% endtab %}
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

{% タブ タイトル="vol2" %}
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

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示する

```bash
volatility --info | grep -iE "profile" -A 5
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

### プロファイルを指定してファイルシステムを表示する

```bash
volatility -f <image> --profile=<profile> filescan
```

### プロファイルを指定してコマンドヒストリを表示する

```bash
volatility -f <image> --profile=<profile> cmdscan
```

### プロファイルを指定してレジストリをダンプする

```bash
volatility -f <image> --profile=<profile> printkey -K "KeyName"
```

### プロファイルを指定してプロセスのダンプを取得する

```bash
volatility -f <image> --profile=<profile> procdump -p <PID> -D <output_directory>
```

### プロファイルを指定して特定のプロセスのスタックトレースを表示する

```bash
volatility -f <image> --profile=<profile> psscan | grep <PID>
volatility -f <image> --profile=<profile> pstree -p | grep <PID>
volatility -f <image> --profile=<profile> threads | grep <PID>
volatility -f <image> --profile=<profile> stack -p <PID>
```

### プロファイルを指定して特定のファイルをダンプする

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address_range>
```

### プロファイルを指定して特定のファイルを抽出する

```bash
volatility -f <image> --profile=<profile> dumpfiles -r <output_directory> -Q <address_range>
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <image> --profile=<profile> handles -p <PID>
```

### プロファイルを指定して特定のプロセスの DLL リストを表示する

```bash
volatility -f <image> --profile=<profile> dlllist -p <PID>
```

### プロファイルを指定して特定のプロセスのモジュール情報を表示する

```bash
volatility -f <image> --profile=<profile> modscan -p <PID>
```

### プロファイルを指定して特定のプロセスのネットワーク情報を表示する

```bash
volatility -f <image> --profile=<profile> netscan -p <PID>
```

### プロファイルを指定して特定のプロセスのレジストリ情報を表示する

```bash
volatility -f <image> --profile=<profile> printkey -K "KeyName" -p <PID>
```

### プロファイルを指定して特定のプロセスのファイルハンドル情報を表示する

```bash
volatility -f <image> --profile=<profile> filehandles -p <PID>
```

### プロファイルを指定して特定のプロセスのマップされたファイル情報を表示する

```bash
volatility -f <image> --profile=<profile> malfind -p <PID>
```

### プロファイルを指定して特定のプロセスのレジストリヒストリ情報を表示する

```bash
volatility -f <image> --profile=<profile> hivelist -p <PID>
```

### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <image> --profile=<profile> getservicesids -p <PID>
```

### プロファイルを指定して特定のプロセスのサービスハンドル情報を表示する

```bash
volatility -f <image> --profile=<profile> svcscan -p <PID>
```

### プロファイルを指定して特定のプロセスのスケジュールされたタスク情報を表示する

```bash
volatility -f <image> --profile=<profile> malsysproc
```

### プロファイルを指定して特定のプロセスのスケジュールされたタスク情報を表示する

```bash
volatility -f <image> --profile=<profile> malsysproc
```

### プロファイルを指定して特定のプロセスのスケジュールされたタスク情報を表示する

```bash
volatility -f <image> --profile=<profile> malsysproc
```

### プロファイルを指定して特定のプロセスのスケジュールされたタスク情報を表示する

```bash
volatility -f <image> --profile=<profile> malsysproc
```

### プロファイルを指定して特定のプロセスのスケジュールされたタスク情報を表示する

```bash
volatility -f <image> --profile=<profile> malsysproc
```

### プロファイルを指定して特定のプロセスのスケジュールされたタスク情報を表示する

```bash
volatility -f <image> --profile=<profile> malsysproc
```

### プロファイルを指定して特定のプロセスのスケジュールされたタスク情報を表示する

```bash
volatility -f <image> --profile=<profile> malsysproc
```
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

{% タブ タイトル="vol2" %}
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

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示する

```bash
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

### プロファイルを指定してイメージ情報を表示する

```bash
volatility -f memory.raw imageinfo --profile=Win7SP1x64
```

### 特定のプロセスのプロセスID（PID）を取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 pslist | grep process_name
```

### 特定のプロセスのメモリダンプを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 memdump -p pid -D output_directory/
```

### ファイルをダウンロードする

```bash
volatility -f memory.raw --profile=Win7SP1x64 dumpfiles -Q address_range -D output_directory/
```

### レジストリキーを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key"
```

### ネットワーク接続を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 connections
```

### ネットワークトラフィックを表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 tcpstreams
```

### コマンド履歴を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 cmdscan
```

### ユーザー情報を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 getsids
```

### プロセスのDLLリストを表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 dlllist -p pid
```

### プロセスのハンドルを表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 handles -p pid
```

### サービス情報を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 svcscan
```

### キャッシュされたログイン情報を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 cachedump
```

### ファイルキャッシュを表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 filescan
```

### システム情報を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 sysinfo
```

### システムサービスディスパッチテーブル（SSDT）を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 ssdt
```

### ドライバモジュール情報を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 modules
```

### プロセスのネットワーク情報を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 netscan
```

### プロセスのセキュリティ情報を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 psxview
```

### レジストリ情報を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist
```

### レジストリ情報をダンプする

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivedump -o output_directory/ -s hive_offset
```

### レジストリキーの値を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key"
```

### レジストリ値を表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 printval -K "registry_key"
```

### レジストリツリーを表示する

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y
```

### レジストリツリーをダンプする

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -o output_directory/
```

### レジストリツリーを再帰的にダンプする

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む、全てのサブキーの値を含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -a -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む、全てのサブキーの値を含む、全てのサブキーの値のバイナリも含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -a -x -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む、全てのサブキーの値を含む、全てのサブキーの値のバイナリも含む、全てのサブキーの値のASCIIも含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -a -x -c -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む、全てのサブキーの値を含む、全てのサブキーの値のバイナリも含む、全てのサブキーの値のASCIIも含む、全てのサブキーの値のユニコードも含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -a -x -c -u -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む、全てのサブキーの値を含む、全てのサブキーの値のバイナリも含む、全てのサブキーの値のASCIIも含む、全てのサブキーの値のユニコードも含む、全てのサブキーの値のユニコードのバイナリも含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -a -x -c -u -w -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む、全てのサブキーの値を含む、全てのサブキーの値のバイナリも含む、全てのサブキーの値のASCIIも含む、全てのサブキーの値のユニコードも含む、全てのサブキーの値のユニコードのバイナリも含む、全てのサブキーの値のユニコードのASCIIも含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -a -x -c -u -w -z -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む、全てのサブキーの値を含む、全てのサブキーの値のバイナリも含む、全てのサブキーの値のASCIIも含む、全てのサブキーの値のユニコードも含む、全てのサブキーの値のユニコードのバイナリも含む、全てのサブキーの値のユニコードのASCIIも含む、全てのサブキーの値のユニコードのASCIIのバイナリも含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -a -x -c -u -w -z -q -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む、全てのサブキーの値を含む、全てのサブキーの値のバイナリも含む、全てのサブキーの値のASCIIも含む、全てのサブキーの値のユニコードも含む、全てのサブキーの値のユニコードのバイナリも含む、全てのサブキーの値のユニコードのASCIIも含む、全てのサブキーの値のユニコードのASCIIのバイナリも含む、全てのサブキーの値のユニコードのASCIIのユニコードも含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -a -x -c -u -w -z -q -t -o output_directory/
```

### レジストリツリーを再帰的にダンプする（値も含む、バイナリも含む、全てのサブキーを含む、全てのサブキーの値を含む、全てのサブキーの値のバイナリも含む、全てのサブキーの値のASCIIも含む、全てのサブキーの値のユニコードも含む、全てのサブキーの値のユニコードのバイナリも含む、全てのサブキーの値のユニコードのASCIIも含む、全てのサブキーの値のユニコードのASCIIのバイナリも含む、全てのサブキーの値のユニコードのASCIIのユニコードも含む、全てのサブキーの値のユニコードのASCIIのユニコードのバイナリも含む）

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -K "registry_key" -y -r -v -b -s -a -x -c -u -w -z -q -t -p -o output_directory/
```
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

{% タブ タイトル="vol2" %}
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

## Volatility チートシート

### プラグインのリストを表示する

```bash
volatility --info | grep -iE "rule|plugin"
```

### プロファイルを指定してプラグインを実行する

```bash
volatility -f memory.raw --profile=Win7SP1x64 <plugin_name>
```

### プロセスリストを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 pslist
```

### ネットワーク接続を取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 connections
```

### ファイルシステムキャッシュを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 cachedump
```

### レジストリキーを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -o <offset>
```

### プロセスのハンドルを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 handles -p <pid>
```

### ファイルをダンプする

```bash
volatility -f memory.raw --profile=Win7SP1x64 dumpfiles -Q <address_range>
```

### メモリマップを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 memmap
```

### カーネルモジュールを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 modscan
```

### システム情報を取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 sysinfo
```

### ユーザ情報を取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 getsids
```

### キャッシュされたログイン情報を取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hashdump
```

### プロセスのコマンドラインを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 cmdline -p <pid>
```

### レジストリのユーザリストを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist
```

### レジストリのユーザリストを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist
```

### レジストリのユーザリストを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist
```

### レジストリのユーザリストを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist
```

### レジストリのユーザリストを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist
```

### レジストリのユーザリストを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist
```

### レジストリのユーザリストを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist
```

### レジストリのユーザリストを取得する

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist
```
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

**NTFSファイルシステム**は、_マスターファイルテーブル_（MFT）として知られる重要なコンポーネントを使用します。このテーブルには、ボリューム上のすべてのファイルについて少なくとも1つのエントリが含まれており、MFT自体もカバーしています。各ファイルに関する重要な詳細（サイズ、タイムスタンプ、アクセス許可、実際のデータなど）は、MFTエントリ内にカプセル化されているか、MFT外部のエリアに存在し、これらのエントリによって参照されています。詳細については、[公式ドキュメント](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)を参照してください。

### SSLキー/証明書
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
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

### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <image> --profile=<profile> connections
```

### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

### プロファイルを指定してファイルをダンプする

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address range> -D <output directory>
```

### プロファイルを指定して特定のプロセスのスタックトレースを表示する

```bash
volatility -f <image> --profile=<profile> pstree -p <pid>
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <image> --profile=<profile> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのDLLリストを表示する

```bash
volatility -f <image> --profile=<profile> dlllist -p <pid>
```

### プロファイルを指定してレジストリのハッシュを表示する

```bash
volatility -f <image> --profile=<profile> hivelist
```

### プロファイルを指定してレジストリの内容を表示する

```bash
volatility -f <image> --profile=<profile> printkey -o <offset>
```

これらのコマンドを使用して、メモリダンプ解析を行う際に役立つ情報を取得できます。{% endtab %}
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
volatility -f <memory_dump> --profile=<profile_name> <plugin_name>
```

### プロセスリストを表示
```bash
volatility -f <memory_dump> --profile=<profile_name> pslist
```

### ネットワーク接続を表示
```bash
volatility -f <memory_dump> --profile=<profile_name> connections
```

### ファイルシステムキャッシュを表示
```bash
volatility -f <memory_dump> --profile=<profile_name> cache
```

### レジストリキーを表示
```bash
volatility -f <memory_dump> --profile=<profile_name> printkey -K <registry_key>
```

### レジストリリストを表示
```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
```

### レジストリ値を表示
```bash
volatility -f <memory_dump> --profile=<profile_name> printkey -K <registry_key> -V
```

### ファイルをダンプ
```bash
volatility -f <memory_dump> --profile=<profile_name> dump -D <output_directory> -i <file_offset>
```

### プロセスのダンプ
```bash
volatility -f <memory_dump> --profile=<profile_name> procdump -p <process_id> -D <output_directory>
```

### メモリマップを表示
```bash
volatility -f <memory_dump> --profile=<profile_name> memmap
```

### スクリーンショットを取得
```bash
volatility -f <memory_dump> --profile=<profile_name> screenshot -D <output_directory>
```

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。{% endtab %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## その他

### 外部プラグイン

外部プラグインを使用したい場合は、プラグインに関連するフォルダが最初のパラメータとして使用されていることを確認してください。
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
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

### プロファイルを指定してプロセス一覧を表示する

```bash
volatility -f <image> --profile=<profile> pslist
```

### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <image> --profile=<profile> connections
```

### プロファイルを指定してファイル一覧を表示する

```bash
volatility -f <image> --profile=<profile> filescan
```

### プロファイルを指定してコマンドヒストリを表示する

```bash
volatility -f <image> --profile=<profile> cmdscan
```

### プロファイルを指定してプロセスのハンドルを表示する

```bash
volatility -f <image> --profile=<profile> handles
```

### プロファイルを指定してレジストリのハッシュを表示する

```bash
volatility -f <image> --profile=<profile> hivelist
```

### プロファイルを指定してファイルのハッシュを表示する

```bash
volatility -f <image> --profile=<profile> filehash -H <file>
```

### プロファイルを指定して特定のプロセスのメモリダンプを取得する

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### プロファイルを指定して特定のファイルの内容を表示する

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>
```

これらのコマンドを使用して、メモリダンプ解析を効果的に行うことができます。{% endtab %}
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

### プロファイルを指定して特定のプロセスのメモリダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### プロファイルを指定して特定のファイルを抽出する

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>
```

これらのコマンドを使用して、Volatilityを効果的に活用し、メモリダンプ解析を行うことができます。{% endtab %}
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
volatility -f <dumpfile> --profile=<profile> <plugin_name>
```

### プロセスリストを表示
```bash
volatility -f <dumpfile> --profile=<profile> pslist
```

### ネットワーク接続を表示
```bash
volatility -f <dumpfile> --profile=<profile> connections
```

### ファイルシステムキャッシュを表示
```bash
volatility -f <dumpfile> --profile=<profile> filescan
```

### レジストリキーを表示
```bash
volatility -f <dumpfile> --profile=<profile> printkey -o <offset>
```

### レジストリリストを表示
```bash
volatility -f <dumpfile> --profile=<profile> hivelist
```

### レジストリ値を表示
```bash
volatility -f <dumpfile> --profile=<profile> print -s <registry_path>
```

### プロセスのDLLリストを表示
```bash
volatility -f <dumpfile> --profile=<profile> dlllist -p <pid>
```

### プロセスのハンドルリストを表示
```bash
volatility -f <dumpfile> --profile=<profile> handles -p <pid>
```

### キャッシュされたログイン情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> hashdump
```

### システムのサービス情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> svcscan
```

### システムのドライバ情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> driverscan
```

### システムのモジュール情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> modscan
```

### システムのタイムラインを表示
```bash
volatility -f <dumpfile> --profile=<profile> timeliner
```

### プロセスのコマンドラインを表示
```bash
volatility -f <dumpfile> --profile=<profile> cmdline -p <pid>
```

### プロセスのファイルディスクリプタを表示
```bash
volatility -f <dumpfile> --profile=<profile> filescan -p <pid>
```

### プロセスのマップされたファイルを表示
```bash
volatility -f <dumpfile> --profile=<profile> malfind -p <pid>
```

### プロセスのネットワーク情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> netscan -p <pid>
```

### プロセスのプロパティを表示
```bash
volatility -f <dumpfile> --profile=<profile> psscan -p <pid>
```

### プロセスのレジストリ情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> getsids -p <pid>
```

### プロセスのスレッド情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> threads -p <pid>
```

### プロセスのユーザ情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> getsids -p <pid>
```

### プロセスのヒープ情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> heap -p <pid>
```

### プロセスのハッシュ情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> hashdump -p <pid>
```

### プロセスのハンドル情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> handles -p <pid>
```

### プロセスのモジュール情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> moddump -p <pid>
```

### プロセスのストリーム情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> pstree -p <pid>
```

### プロセスのサービス情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> svcscan -p <pid>
```

### プロセスのタイムラインを表示
```bash
volatility -f <dumpfile> --profile=<profile> timeliner -p <pid>
```

### プロセスのハンドル情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> handles -p <pid>
```

### プロセスのモジュール情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> moddump -p <pid>
```

### プロセスのストリーム情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> pstree -p <pid>
```

### プロセスのサービス情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> svcscan -p <pid>
```

### プロセスのタイムラインを表示
```bash
volatility -f <dumpfile> --profile=<profile> timeliner -p <pid>
```

### プロセスのハンドル情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> handles -p <pid>
```

### プロセスのモジュール情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> moddump -p <pid>
```

### プロセスのストリーム情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> pstree -p <pid>
```

### プロセスのサービス情報を表示
```bash
volatility -f <dumpfile> --profile=<profile> svcscan -p <pid>
```

### プロセスのタイムラインを表示
```bash
volatility -f <dumpfile> --profile=<profile> timeliner -p <pid>
```
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

**メモリからbashの履歴を読むことが可能です。** _.bash\_history_ ファイルをダンプすることもできますが、無効になっている場合は、このVolatilityモジュールを使用できることに満足するでしょう。
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %}以下は、メモリダンプ解析に関する基本的な手法に関する情報です。

## Volatility チートシート

### プラグインのリストを表示する

```bash
volatility --info | less
```

### プロファイルを指定してイメージ情報を表示する

```bash
volatility -f <image> imageinfo
```

### プロファイルを指定してプロセスリストを表示する

```bash
volatility -f <image> --profile=<profile> pslist
```

### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <image> --profile=<profile> connections
```

### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <image> --profile=<profile> printkey -o <offset>
```

### プロファイルを指定してファイルをダンプする

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address range>
```

これらのコマンドを使用して、メモリダンプ解析を行う際に役立つ情報を取得できます。{% endtab %}
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

{% tab title="vol2" %}
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

{% tab title="vol2" %}以下は、メモリダンプ解析に関する情報です。

## Volatilityチートシート

### プラグインのリストを表示する

```bash
volatility --info | less
```

### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <imagefile> imageinfo --profile=<profilename>
```

### プロファイルを指定してプロセスリストを表示する

```bash
volatility -f <imagefile> --profile=<profilename> pslist
```

### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <imagefile> --profile=<profilename> hivelist
```

### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <imagefile> --profile=<profilename> connections
```

### プロファイルを指定してファイルシステムを表示する

```bash
volatility -f <imagefile> --profile=<profilename> filescan
```

### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profilename> handles -p <pid>
```

### プロファイルを指定して特定のプロセスのDLLリストを表示する

```bash
volatility -f <imagefile> --profile=<profilename> dlllist -p <pid>
```

### プロファイルを指定して特定のプロセスのメモリマップを表示する

```bash
volatility -f <imagefile> --profile=<profilename> memmap -p <pid>
```

### プロファイルを指定して特定のプロセスのスレッドを表示する

```bash
volatility -f <imagefile> --profile=<profilename> threads -p <pid>
```

### プロファイルを指定して特定のプロセスのモジュールを表示する

```bash
volatility -f <imagefile> --profile=<profilename> modlist -p <pid>
```

### プロファイルを指定してレジストリの内容をダンプする

```bash
volatility -f <imagefile> --profile=<profilename> printkey -o <offset>
```

### プロファイルを指定してファイルをダンプする

```bash
volatility -f <imagefile> --profile=<profilename> dumpfiles -Q <offset>
```

### プロファイルを指定してプロセスの実行可能なファイルをダンプする

```bash
volatility -f <imagefile> --profile=<profilename> procdump -p <pid> -D <outputdir>
```

### プロファイルを指定して特定のプロセスのレジストリハイブをダンプする

```bash
volatility -f <imagefile> --profile=<profilename> hivedump -o <offset> -D <outputdir>
```

これらのコマンドを使用して、Volatilityを使用してメモリダンプを効果的に解析できます。

{% endtab %}
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
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**マスターブートレコード（MBR）**は、ストレージメディアの論理パーティションを管理する上で重要な役割を果たします。これらのパーティションは異なる[ファイルシステム](https://en.wikipedia.org/wiki/File_system)で構成されています。MBRはパーティションレイアウト情報だけでなく、ブートローダーとして機能する実行可能コードも含んでいます。このブートローダーは、OSの第2段階の読み込みプロセスを直接開始するか（[第2段階ブートローダー](https://en.wikipedia.org/wiki/Second-stage_boot_loader)を参照）、または各パーティションの[ボリュームブートレコード](https://en.wikipedia.org/wiki/Volume_boot_record)（VBR）と協調して動作します。詳細な知識については、[MBR Wikipediaページ](https://en.wikipedia.org/wiki/Master_boot_record)を参照してください。

# 参考文献
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術的知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローしてください
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください

</details>
