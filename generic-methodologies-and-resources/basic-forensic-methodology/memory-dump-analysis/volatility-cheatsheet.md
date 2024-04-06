# Volatility - CheatSheet

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* \*\*💬 [Discordグループ](https://discord.gg/hRep4RUj7f)\*\*に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**する
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)**と**[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)**のGitHubリポジトリにPRを提出してください**

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの1つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家の熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

**複数のVolatilityプラグインを並行して実行する**高速でクレイジーなものをお探しの場合は、[https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)を使用できます。

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

#### メモリダンプ解析の基本的な手法

* プロファイルの選択
* プロセスリストの取得
* プロセスのマッピング情報の取得
* ネットワーク接続の確認
* ファイルハンドルの取得
* レジストリキーの取得
* サービスとドライバの取得
* キャッシュとレジストリの取得
* プロセスの実行可能ファイルの取得
* プロセスのモジュールの取得
* プロセスのスレッドの取得
* プロセスのハンドルの取得
* プロセスのオブジェクトの取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムラインの取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスのタイムライン情報の取得
* プロセスのネットワーク情報の取得
* プロセスのファイル情報の取得
* プロセスのレジストリ情報の取得
* プロセスのサービス情報の取得
* プロセスのドライバ情報の取得
* プロセスのデバイス情報の取得
* プロセスのイベント情報の取得
* プロセスのハンドル情報の取得
* プロセスのオブジェクト情報の取得
* プロセスのデバッグ情報の取得
* プロセスのセキュリティ情報の取得
* プロセスの

```
Download the executable from https://www.volatilityfoundation.org/26
```

```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```

## Volatilityコマンド

[Volatilityコマンドリファレンス](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)で公式ドキュメントにアクセスします。

### "list"と"scan"プラグインに関する注意事項

Volatilityには、プラグインに対する2つの主要なアプローチがあり、その名前に反映されることがあります。"list"プラグインは、Windowsカーネル構造をナビゲートしてプロセス（メモリ内の`_EPROCESS`構造体のリンクリストを検索してウォークする）、OSハンドル（ハンドルテーブルを検出してリスト化するなど）などの情報を取得しようとします。これらは、たとえばプロセスをリストアップする場合にWindows APIが要求された場合とほぼ同じように振る舞います。

これにより、「list」プラグインは非常に高速ですが、Windows APIと同様にマルウェアによる操作の脆弱性があります。たとえば、マルウェアがDKOMを使用してプロセスを`_EPROCESS`リンクリストから切り離すと、タスクマネージャに表示されず、pslistにも表示されません。

一方、「scan」プラグインは、特定の構造体としてデリファレンスされたときに意味をなす可能性のあるものをメモリから彫り取るようなアプローチを取ります。たとえば、`psscan`はメモリを読み取り、それを`_EPROCESS`オブジェクトにしようとします（構造体の存在を示す4バイトの文字列を検索するプールタグスキャンを使用します）。利点は、終了したプロセスを発見できることであり、たとえマルウェアが`_EPROCESS`リンクリストを改ざんしても、プラグインはメモリ内に残っている構造体を見つけることができます（プロセスが実行されるためにはまだ存在する必要があるため）。欠点は、「scan」プラグインが「list」プラグインよりもやや遅く、時々誤検知を引き起こすことがあることです（過去に終了したプロセスであり、その構造の一部が他の操作によって上書きされた場合）。

出典: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OSプロファイル

### Volatility3

Readmeに記載されているように、サポートしたい**OSのシンボルテーブル**を\_volatility3/volatility/symbols\_に配置する必要があります。\
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

[**こちらから**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): imageinfo が単にプロファイルの提案を行うのに対し、**kdbgscan** は正確なプロファイルと正確な KDBG アドレス（複数ある場合）を確実に特定するよう設計されています。このプラグインは、Volatility プロファイルにリンクされた KDBGHeader シグネチャをスキャンし、偽陽性を減らすための整合性チェックを適用します。出力の冗長性と実行できる整合性チェックの数は、Volatility が DTB を見つけることができるかどうかに依存します。したがって、正しいプロファイルをすでに知っている場合（または imageinfo からプロファイルの提案を受け取っている場合）、それを使用することを確認してください。

常に **kdbgscan が見つけたプロセスの数**を確認してください。時々、imageinfo と kdbgscan は **1 つ以上の適切なプロファイル**を見つけることができますが、**有効なものはプロセスに関連するものだけ**です（これはプロセスを抽出するために正しい KDBG アドレスが必要であるためです）。

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

**カーネルデバッガブロック**は、Volatilityによって**KDBG**として参照され、Volatilityやさまざまなデバッガによって実行されるフォレンジックタスクにとって重要です。`KdDebuggerDataBlock`として識別され、`_KDDEBUGGER_DATA64`型であり、`PsActiveProcessHead`のような重要な参照を含んでいます。この特定の参照はプロセスリストの先頭を指し示し、すべてのプロセスのリスト化を可能にし、徹底的なメモリ解析に不可欠です。

## OS情報

```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```

プラグイン`banners.Banners`は、ダンプファイルから**Linuxのバナー**を見つけるために**vol3で使用できます**。

## ハッシュ/パスワード

SAMハッシュ、[ドメインキャッシュされた資格情報](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials)、および[lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets)を抽出します。

```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```

以下は、メモリダンプ解析に関する情報です。

### Volatilityチートシート

#### プラグインのリストを表示する

```bash
volatility --info | less
```

#### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <imagefile> imageinfo --profile=<profilename>
```

#### プロファイルを指定してプロセス一覧を表示する

```bash
volatility -f <imagefile> --profile=<profilename> pslist
```

#### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <imagefile> --profile=<profilename> hivelist
```

#### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <imagefile> --profile=<profilename> connections
```

#### プロファイルを指定してファイル一覧を表示する

```bash
volatility -f <imagefile> --profile=<profilename> filescan
```

#### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profilename> handles -p <pid>
```

#### プロファイルを指定して特定のプロセスのDLLリストを表示する

```bash
volatility -f <imagefile> --profile=<profilename> dlllist -p <pid>
```

#### プロファイルを指定して特定のプロセスのメモリダンプを取得する

```bash
volatility -f <imagefile> --profile=<profilename> procdump -p <pid> -D <outputdirectory>
```

#### プロファイルを指定してレジストリの内容をダンプする

```bash
volatility -f <imagefile> --profile=<profilename> printkey -o <offset>
```

#### プロファイルを指定して特定のファイルを抽出する

```bash
volatility -f <imagefile> --profile=<profilename> dumpfiles -Q <addressrange> -D <outputdirectory>
```

これらのコマンドを使用して、Volatilityを効果的に活用しましょう。

```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```

## メモリーダンプ

プロセスのメモリーダンプは、プロセスの現在の状態のすべてを**抽出**します。**procdump**モジュールは**コード**のみを**抽出**します。

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

以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示する

```bash
volatility --info | grep -iE "rule|plugin"
```

#### プロファイルを確認する

```bash
volatility -f <dumpfile> imageinfo
```

#### プロセスのリストを表示する

```bash
volatility -f <dumpfile> --profile=<profile> pslist
```

#### ネットワーク接続を表示する

```bash
volatility -f <dumpfile> --profile=<profile> connections
```

#### ファイルシステムを調査する

```bash
volatility -f <dumpfile> --profile=<profile> filescan
```

#### レジストリキーを表示する

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key>
```

#### コマンド履歴を表示する

```bash
volatility -f <dumpfile> --profile=<profile> cmdscan
```

#### ユーザー情報を表示する

```bash
volatility -f <dumpfile> --profile=<profile> getsids
```

#### プロセスの実行コマンドを表示する

```bash
volatility -f <dumpfile> --profile=<profile> cmdline
```

#### メモリダンプからファイルを抽出する

```bash
volatility -f <dumpfile> --profile=<profile> dumpfiles -Q <address>
```

#### メモリダンプからプロセスを抽出する

```bash
volatility -f <dumpfile> --profile=<profile> procdump -p <pid> -D <output_directory>
```

#### メモリダンプからレジストリを抽出する

```bash
volatility -f <dumpfile> --profile=<profile> hivelist
volatility -f <dumpfile> --profile=<profile> printkey -o <offset>
```

これらのコマンドを使用して、メモリダンプから重要な情報を取得し、フォレンジック調査を行うことができます。

```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```

### ダンプ処理

```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```

\{% タブ タイトル="vol2" %\}

```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```

### コマンドライン

何か怪しいことが実行されましたか？

```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```

以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示

```
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

#### プロファイルの指定

```
volatility -f memory_dump.mem --profile=Win7SP1x64 plugin_name
```

#### プロセス一覧の取得

```
volatility -f memory_dump.mem --profile=Win7SP1x64 pslist
```

#### ネットワーク接続の確認

```
volatility -f memory_dump.mem --profile=Win7SP1x64 connections
```

#### ファイル一覧の取得

```
volatility -f memory_dump.mem --profile=Win7SP1x64 filescan
```

#### レジストリキーの列挙

```
volatility -f memory_dump.mem --profile=Win7SP1x64 hivelist
```

#### レジストリ内容の表示

```
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -o 0xfffff8a000002010
```

#### コマンド履歴の取得

```
volatility -f memory_dump.mem --profile=Win7SP1x64 cmdscan
```

#### ユーザリストの取得

```
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

#### プロセスの実行コマンドの取得

```
volatility -f memory_dump.mem --profile=Win7SP1x64 cmdline -p 1234
```

#### メモリダンプからファイルの抽出

```
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpfiles -Q 0x000000007efdd000 -D .
```

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。

```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```

`cmd.exe`で実行されたコマンドは\*\*`conhost.exe`**によって管理されます（Windows 7より前のシステムでは`csrss.exe`）。これは、攻撃者によって**`cmd.exe`**が終了された場合でも、**`conhost.exe`**のメモリからセッションのコマンド履歴を回復することができる可能性があることを意味します。異常なアクティビティがコンソールのモジュールで検出された場合、関連する**`conhost.exe`**プロセスのメモリをダンプする必要があります。その後、このダンプ内で**strings\*\*を検索することで、セッションで使用されたコマンドラインを抽出することができるかもしれません。

### 環境

実行中の各プロセスの環境変数を取得します。興味深い値があるかもしれません。

```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```

以下は、メモリダンプ解析に関する基本的な手法に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示する

```bash
volatility --info | grep -iE "profile" -A 20
```

#### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <imagefile> imageinfo --profile=<profile>
```

#### プロファイルを指定してプロセス一覧を表示する

```bash
volatility -f <imagefile> --profile=<profile> pslist
```

#### プロファイルを指定してレジストリキーをリストする

```bash
volatility -f <imagefile> --profile=<profile> hivelist
volatility -f <imagefile> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <imagefile> --profile=<profile> connections
```

#### プロファイルを指定してファイル一覧を表示する

```bash
volatility -f <imagefile> --profile=<profile> filescan
```

#### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profile> handles -p <pid>
```

#### プロファイルを指定して特定のプロセスのDLLリストを表示する

```bash
volatility -f <imagefile> --profile=<profile> dlllist -p <pid>
```

#### プロファイルを指定して特定のプロセスのメモリマップを表示する

```bash
volatility -f <imagefile> --profile=<profile> memmap -p <pid>
```

#### プロファイルを指定して特定のプロセスのスレッドを表示する

```bash
volatility -f <imagefile> --profile=<profile> threads -p <pid>
```

#### プロファイルを指定して特定のプロセスのモジュールを表示する

```bash
volatility -f <imagefile> --profile=<profile> modlist -p <pid>
```

#### プロファイルを指定して特定のプロセスのレジストリヒストリを表示する

```bash
volatility -f <imagefile> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定して特定のプロセスのスタックトレースを表示する

```bash
volatility -f <imagefile> --profile=<profile> stack -p <pid>
```

#### プロファイルを指定して特定のプロセスのヒープを表示する

```bash
volatility -f <imagefile> --profile=<profile> memdump -p <pid> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのスクリーンショットを取得する

```bash
volatility -f <imagefile> --profile=<profile> screenshot -p <pid> --dump-dir=<output_directory>
```

#### プロファイルを指定して特定のプロセスのファイルをダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -Q <pid> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのレジストリをダンプする

```bash
volatility -f <imagejson> --profile=<profile> dumpregistry -o <output_directory>
```

#### プロファイルを指定して特定のプロセスのイベントログをダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -S <service_name> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのイベントログをダンプする

```bash
volatility -f <imagefile> --profile=<profile> evtlogs -f <imagefile> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのレジストリヒストリをダンプする

```bash
volatility -f <imagefile> --profile=<profile> hivelist
volatility -f <imagefile> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のプロセスのレジストリをダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpregistry -o <output_directory>
```

#### プロファイルを指定して特定のプロセスのイベントログをダンプする

```bash
volatility -f <imagefile> --profile=<profile> evtlogs -f <imagefile> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのレジストリヒストリをダンプする

```bash
volatility -f <imagefile> --profile=<profile> hivelist
volatility -f <imagefile> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のプロセスのレジストリをダンプする

```bash
volatility -f <imagefile> --profile=<profile> dumpregistry -o <output_directory>
```

#### プロファイルを指定して特定のプロセスのイベントログをダンプする

```bash
volatility -f <imagefile> --profile=<profile> evtlogs -f <imagefile> -D <output_directory>
```

```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```

#### トークン特権

予期しないサービスで特権トークンをチェックします。\
特権トークンを使用しているプロセスをリストアップすることが興味深いかもしれません。

```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```

\{% タブのタイトル="vol2" %\}

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

以下は、メモリダンプ解析に関する情報です。

### Volatilityチートシート

#### プラグインのリストを表示

```bash
volatility --info | grep -iE "profile|linux"
```

#### プロファイルを指定してイメージファイルの情報を表示

```bash
volatility -f <image> imageinfo --profile=<profile>
```

#### プロファイルを指定してプロセス一覧を表示

```bash
volatility -f <image> --profile=<profile> pslist
```

#### プロファイルを指定してネットワーク接続を表示

```bash
volatility -f <image> --profile=<profile> connections
```

#### プロファイルを指定してレジストリキーを表示

```bash
volatility -f <image> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定してファイルをダンプ

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <PID> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのスタックトレースを表示

```bash
volatility -f <image> --profile=<profile> psscan | grep <process_name>
volatility -f <image> --profile=<profile> pstree -p <PID>
volatility -f <image> --profile=<profile> pstack <PID>
```

#### プロファイルを指定して特定のプロセスのハンドルを表示

```bash
volatility -f <image> --profile=<profile> handles -p <PID>
```

#### プロファイルを指定して特定のプロセスのDLLリストを表示

```bash
volatility -f <image> --profile=<profile> dlllist -p <PID>
```

#### プロファイルを指定して特定のプロセスのモジュール情報を表示

```bash
volatility -f <image> --profile=<profile> modscan | grep <process_name>
volatility -f <image> --profile=<profile> modules -p <PID>
```

#### プロファイルを指定して特定のプロセスのスクリーンショットを取得

```bash
volatility -f <image> --profile=<profile> screenshot -p <PID> --dump-dir=<output_directory>
```

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。

```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```

### ハンドル

プロセスがハンドルを持っている（開いている）他のファイル、キー、スレッド、プロセスを知るのに役立ちます。

```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```

以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示する

```bash
volatility --info | less
```

#### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <imagefile> imageinfo
```

#### プロファイルを指定してプロセスリストを表示する

```bash
volatility -f <imagefile> --profile=<profile> pslist
```

#### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <imagefile> --profile=<profile> hivelist
```

#### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <imagefile> --profile=<profile> connections
```

#### プロファイルを指定してファイルシステムを表示する

```bash
volatility -f <imagefile> --profile=<profile> filescan
```

#### プロファイルを指定して特定のプロセスのハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profile> handles -p <pid>
```

#### プロファイルを指定して特定のプロセスのファイルディスクリプタを表示する

```bash
volatility -f <imagefile> --profile=<profile> filescan -p <pid>
```

#### プロファイルを指定して特定のプロセスのモジュールを表示する

```bash
volatility -f <imagefile> --profile=<profile> modscan -p <pid>
```

#### プロファイルを指定して特定のプロセスのスタックトレースを表示する

```bash
volatility -f <imagefile> --profile=<profile> stack -p <pid>
```

#### プロファイルを指定して特定のプロセスのヒープを表示する

```bash
volatility -f <imagefile> --profile=<profile> memdump -p <pid> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのスクリーンショットを取得する

```bash
volatility -f <imagefile> --profile=<profile> screenshot -p <pid> --dump-dir=<output_directory>
```

これらのコマンドを使用して、Volatility を使用してメモリダンプを効果的に解析できます。

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

{% tab title="vol2" %}
以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示

```bash
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

#### プロファイルを指定してプラグインを実行

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 plugin_name
```

#### プロセス一覧を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 pslist
```

#### ネットワーク接続を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 connections
```

#### ファイル一覧を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 filescan
```

#### レジストリキーを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -K "KeyName"
```

#### コマンドヒストリを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 cmdscan
```

#### ユーザアカウントを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

#### プロセスのDLLリストを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 dlllist -p PID
```

#### メモリマップを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 memmap
```

#### キャッシュされたログイン情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 cachedump
```

#### システム情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 sysinfo
```

#### サービス一覧を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 svcscan
```

#### イベントログを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 evtlogs
```

#### プロセスのコマンドラインを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 cmdline -p PID
```

#### ファイルのダンプを作成

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpfiles -Q AddressRange -D output_directory/
```

#### レジストリのダンプを作成

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 hivelist
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -o Offset
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpregistry -o Offset -D output_directory/
```

#### プロセスのスクリーンショットを取得

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 screenshot -p PID -D output_directory/
```

#### プロセスのファイルディスクリプタを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 handles -p PID
```

#### プロセスのネットワーク情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 netscan -p PID
```

#### プロセスのレジストリハンドルを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 handles -p PID
```

#### プロセスのセキュリティディスクリプタを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsd -p PID
```

#### プロセスのサービスディスクリプタを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsd -p PID
```

#### プロセスのモジュール情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 modscan -p PID
```

#### プロセスのモジュール情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 moddump -p PID -D output_directory/
```

#### プロセスのハンドル情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 handles -p PID
```

#### プロセスのファイルオブジェクト情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 filescan -p PID
```

#### プロセスのファイルオブジェクト情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpfiles -p PID -D output_directory/
```

#### プロセスのネットワーク情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 netscan -p PID
```

#### プロセスのネットワーク情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 connscan -p PID -D output_directory/
```

#### プロセスのレジストリ情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -p PID
```

#### プロセスのレジストリ情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 hivelist
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -o Offset
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpregistry -o Offset -D output_directory/
```

#### プロセスのスレッド情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 threads -p PID
```

#### プロセスのスレッド情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 threads -p PID -D output_directory/
```

#### プロセスのハンドル情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 handles -p PID
```

#### プロセスのハンドル情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 handles -p PID -D output_directory/
```

#### プロセスのセキュリティディスクリプタを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsd -p PID
```

#### プロセスのサービスディスクリプタを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsd -p PID
```

#### プロセスのモジュール情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 modscan -p PID
```

#### プロセスのモジュール情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 moddump -p PID -D output_directory/
```

#### プロセスのファイルオブジェクト情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 filescan -p PID
```

#### プロセスのファイルオブジェクト情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpfiles -p PID -D output_directory/
```

#### プロセスのネットワーク情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 netscan -p PID
```

#### プロセスのネットワーク情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 connscan -p PID -D output_directory/
```

#### プロセスのレジストリ情報を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -p PID
```

#### プロセスのレジストリ情報をダンプ

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 hivelist
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -o Offset
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpregistry -o Offset -D output_directory/
```

```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```

#### プロセスごとの文字列

Volatilityを使用すると、文字列がどのプロセスに属しているかを確認できます。

```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}
以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示する

```bash
volatility --info | less
```

#### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <imagefile> imageinfo --profile=<profile>
```

#### プロファイルを指定してプロセス一覧を表示する

```bash
volatility -f <imagefile> --profile=<profile> pslist
```

#### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <imagefile> --profile=<profile> hivelist
```

#### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <imagefile> --profile=<profile> connections
```

#### プロファイルを指定してファイル一覧を表示する

```bash
volatility -f <imagefile> --profile=<profile> filescan
```

#### プロファイルを指定してコマンド履歴を表示する

```bash
volatility -f <imagefile> --profile=<profile> cmdscan
```

#### プロファイルを指定してプロセスのハンドルを表示する

```bash
volatility -f <imagefile> --profile=<profile> handles
```

#### プロファイルを指定してレジストリキーの値を表示する

```bash
volatility -f <imagefile> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のプロセスのスタックトレースを表示する

```bash
volatility -f <imagefile> --profile=<profile> pstree -p <pid>
```

#### プロファイルを指定して特定のプロセスのモジュール情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> dlllist -p <pid>
```

#### プロファイルを指定して特定のプロセスのネットワーク情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> connscan -p <pid>
```

#### プロファイルを指定して特定のプロセスのファイルハンドル情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> filehandles -p <pid>
```

#### プロファイルを指定して特定のプロセスのレジストリ情報を表示する

```bash
volatility -f <imagejson> --profile=<profile> handles -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

#### プロファイルを指定して特定のプロセスのサービス情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> getservicesids -p <pid>
```

```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

プロセス内の文字列を検索するためにyarascanモジュールを使用することもできます：

```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```

以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示

```
volatility --info | grep -iE "name|file"
```

#### プロファイルのリストを表示

```
volatility --info | grep -i "profile"
```

#### プロファイルを指定してプラグインを実行

```
volatility -f <dumpfile> --profile=<profile> <plugin>
```

#### プロセス一覧を表示

```
volatility -f <dumpfile> --profile=<profile> pslist
```

#### ネットワーク接続を表示

```
volatility -f <dumpfile> --profile=<profile> connections
```

#### ファイル一覧を表示

```
volatility -f <dumpfile> --profile=<profile> filescan
```

#### レジストリキーを表示

```
volatility -f <dumpfile> --profile=<profile> printkey -o <offset>
```

#### レジストリ値を表示

```
volatility -f <dumpfile> --profile=<profile> printkey -o <offset> -K <key>
```

#### レジストリ全体を表示

```
volatility -f <dumpfile> --profile=<profile> hivelist
```

#### レジストリダンプを表示

```
volatility -f <dumpfile> --profile=<profile> dumpregistry -o <offset> -s <size> -f <outputfile>
```

#### プロセスのメモリダンプを取得

```
volatility -f <dumpfile> --profile=<profile> procdump -p <pid> -D <outputdir>
```

#### ファイルのダウンロード

```
volatility -f <dumpfile> --profile=<profile> dumpfiles -Q <offset> -D <outputdir>
```

#### メモリダンプのプラグインを実行

```
volatility -f <dumpfile> --profile=<profile> <plugin>
```

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。

```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```

### UserAssist

**Windows**は、**UserAssistキー**と呼ばれるレジストリ内の機能を使用して、実行したプログラムの履歴を追跡します。これらのキーは、各プログラムが実行された回数と最後に実行された日時を記録します。

```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```

\{% タブのタイトル="vol2" %\}

```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## サービス

```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```

以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示する

```bash
volatility --info | less
```

#### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <imagefile> imageinfo
```

#### プロファイルを指定してプロセスリストを表示する

```bash
volatility -f <imagefile> --profile=<profile> pslist
```

#### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <imagefile> --profile=<profile> hivelist
```

#### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <imagefile> --profile=<profile> connections
```

#### プロファイルを指定してファイルシステムを表示する

```bash
volatility -f <imagefile> --profile=<profile> filescan
```

#### プロファイルを指定してコンソール履歴を表示する

```bash
volatility -f <imagefile> --profile=<profile> consoles
```

#### プロファイルを指定してシステム情報を表示する

```bash
volatility -f <imagefile> --profile=<profile> sysinfo
```

#### プロファイルを指定して特定のプロセスのメモリダンプを取得する

```bash
volatility -f <imagefile> --profile=<profile> memdump -p <pid> -D <output_directory>
```

#### プロファイルを指定して特定のファイルの内容を表示する

```bash
volatility -f <imagefile> --profile=<profile> dumpfiles -Q <address_range>
```

これらのコマンドを使用して、Volatilityを効果的に活用し、メモリダンプ解析を行うことができます。

```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```

## メモリーダンプ解析の基本的な手法

### Volatility チートシート

* **プラグインのリストを表示する**: `volatility --info | less`
* **プロファイルのリストを表示する**: `volatility --info | grep Profile`
* **プロセスのリストを表示する**: `volatility -f <dump> --profile=<profile> pslist`
* **レジストリのキーをリストする**: `volatility -f <dump> --profile=<profile> hivelist`
* **レジストリの内容を表示する**: `volatility -f <dump> --profile=<profile> printkey -o <offset>`
* **ネットワーク接続を表示する**: `volatility -f <dump> --profile=<profile> connections`
* **ソケットを表示する**: `volatility -f <dump> --profile=<profile> sockets`
* **ネットワークインターフェースを表示する**: `volatility -f <dump> --profile=<profile> ifconfig`
* **ルーティングテーブルを表示する**: `volatility -f <dump> --profile=<profile> route`
* **ファイアウォールルールを表示する**: `volatility -f <dump> --profile=<profile> netscan`
* **ネットワークキャッシュを表示する**: `volatility -f <dump> --profile=<profile> netscan`
* **ARP キャッシュを表示する**: `volatility -f <dump> --profile=<profile> arp`
* **DNS キャッシュを表示する**: `volatility -f <dump> --profile=<profile> dnscache`

```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```

以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示

```
volatility --info | less
```

#### プロファイルを指定してイメージファイルの情報を表示

```
volatility -f <image> imageinfo
```

#### プロファイルを指定してプロセスリストを表示

```
volatility -f <image> --profile=<profile> pslist
```

#### プロファイルを指定してレジストリキーを表示

```
volatility -f <image> --profile=<profile> hivelist
```

#### プロファイルを指定してネットワーク接続を表示

```
volatility -f <image> --profile=<profile> connections
```

#### プロファイルを指定してファイルツリーを表示

```
volatility -f <image> --profile=<profile> filescan
```

#### プロファイルを指定して特定のプロセスのハンドルを表示

```
volatility -f <image> --profile=<profile> handles -p <pid>
```

#### プロファイルを指定して特定のプロセスのファイルディスクリプタを表示

```
volatility -f <image> --profile=<profile> filescan -p <pid>
```

#### プロファイルを指定して特定のプロセスの DLL リストを表示

```
volatility -f <image> --profile=<profile> dlllist -p <pid>
```

#### プロファイルを指定して特定のプロセスのモジュール情報を表示

```
volatility -f <image> --profile=<profile> modscan -p <pid>
```

#### プロファイルを指定して特定のプロセスのスレッド情報を表示

```
volatility -f <image> --profile=<profile> threads -p <pid>
```

#### プロファイルを指定して特定のプロセスのメモリマップを表示

```
volatility -f <image> --profile=<profile> memmap -p <pid>
```

#### プロファイルを指定して特定のプロセスのメモリダンプを取得

```
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

#### プロファイルを指定してレジストリのダンプを取得

```
volatility -f <image> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のファイルのダンプを取得

```
volatility -f <image> --profile=<profile> dumpfiles -Q <file_path> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのスタックトレースを表示

```
volatility -f <image> --profile=<profile> stack -p <pid>
```

#### プロファイルを指定して特定のプロセスのヒープ情報を表示

```
volatility -f <image> --profile=<profile> heap -p <pid>
```

#### プロファイルを指定して特定のプロセスのヒープダンプを取得

```
volatility -f <image> --profile=<profile> memdump -p <pid> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのスクリーンショットを取得

```
volatility -f <image> --profile=<profile> screenshot -p <pid> -D <output_directory>
```

#### プロファイルを指定して特定のプロセスのレジスタ情報を表示

```
volatility -f <image> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のプロセスのレジスタ情報を表示

```
volatility -f <image> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のプロセスのレジスタ情報を表示

```
volatility -f <image> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のプロセスのレジスタ情報を表示

```
volatility -f <image> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のプロセスのレジスタ情報を表示

```
volatility -f <image> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のプロセスのレジスタ情報を表示

```
volatility -f <image> --profile=<profile> printkey -o <offset>
```

#### プロファイルを指定して特定のプロセスのレジスタ情報を表示

```
volatility -f <image> --profile=<profile> printkey -o <offset>
```

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

### レジストリハイブ

#### 利用可能なハイブの表示

```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```

\{% タブ タイトル="vol2" %\}

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```

#### 値を取得する

```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```

\{% タブ タイトル="vol2" %\}

```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```

#### ダンプ

```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```

### ファイルシステム

#### マウント

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}
以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示

```bash
volatility --info | less
```

#### プロファイルを指定してイメージファイルの情報を表示

```bash
volatility -f <image> imageinfo
```

#### プロファイルを指定してプロセス一覧を表示

```bash
volatility -f <image> --profile=<profile> pslist
```

#### プロファイルを指定してネットワーク接続を表示

```bash
volatility -f <image> --profile=<profile> connections
```

#### プロファイルを指定してレジストリキーを表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してファイルをダンプ

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address range>
```

#### プロファイルを指定して特定のプロセスのスタックトレースを表示

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output directory>
```

#### プロファイルを指定して特定のプロセスのハンドルを表示

```bash
volatility -f <image> --profile=<profile> handles -p <pid>
```

#### プロファイルを指定して特定のプロセスのDLLリストを表示

```bash
volatility -f <image> --profile=<profile> dlllist -p <pid>
```

#### プロファイルを指定してレジストリのハッシュを表示

```bash
volatility -f <image> --profile=<profile> hivelist
```

#### プロファイルを指定してレジストリの内容を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してファイルの内容を表示

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address range>
```

#### プロファイルを指定してイベントログを表示

```bash
volatility -f <image> --profile=<profile> evtlogs
```

#### プロファイルを指定してシステム情報を表示

```bash
volatility -f <image> --profile=<profile> sysinfo
```

#### プロファイルを指定してキャッシュ情報を表示

```bash
volatility -f <image> --profile=<profile> caches
```

#### プロファイルを指定してサービス情報を表示

```bash
volatility -f <image> --profile=<profile> svcscan
```

#### プロファイルを指定してファイルキャッシュ情報を表示

```bash
volatility -f <image> --profile=<profile> filescan
```

#### プロファイルを指定してレジストリキーのハッシュを表示

```bash
volatility -f <image> --profile=<profile> hivelist
```

#### プロファイルを指定してユーザ情報を表示

```bash
volatility -f <image> --profile=<profile> userassist
```

#### プロファイルを指定してコマンドヒストリを表示

```bash
volatility -f <image> --profile=<profile> cmdscan
```

#### プロファイルを指定してシェルコマンドヒストリを表示

```bash
volatility -f <image> --profile=<profile> consoles
```

#### プロファイルを指定してファイル情報を表示

```bash
volatility -f <image> --profile=<profile> filescan
```

#### プロファイルを指定してネットワーク情報を表示

```bash
volatility -f <image> --profile=<profile> netscan
```

#### プロファイルを指定してプロセスのコマンドラインを表示

```bash
volatility -f <image> --profile=<profile> cmdline
```

#### プロファイルを指定してレジストリの最終書き込み時間を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリの最終アクセス時間を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリの最終変更時間を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのオーナー情報を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのセキュリティ情報を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのサブキーを表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリの値を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのバリューを表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのサブキーを再帰的に表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリの値を再帰的に表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのバリューを再帰的に表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのハッシュを表示

```bash
volatility -f <image> --profile=<profile> hivelist
```

#### プロファイルを指定してレジストリの内容を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してファイルの内容を表示

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address range>
```

#### プロファイルを指定してイベントログを表示

```bash
volatility -f <image> --profile=<profile> evtlogs
```

#### プロファイルを指定してシステム情報を表示

```bash
volatility -f <image> --profile=<profile> sysinfo
```

#### プロファイルを指定してキャッシュ情報を表示

```bash
volatility -f <image> --profile=<profile> caches
```

#### プロファイルを指定してサービス情報を表示

```bash
volatility -f <image> --profile=<profile> svcscan
```

#### プロファイルを指定してファイルキャッシュ情報を表示

```bash
volatility -f <image> --profile=<profile> filescan
```

#### プロファイルを指定してレジストリキーのハッシュを表示

```bash
volatility -f <image> --profile=<profile> hivelist
```

#### プロファイルを指定してユーザ情報を表示

```bash
volatility -f <image> --profile=<profile> userassist
```

#### プロファイルを指定してコマンドヒストリを表示

```bash
volatility -f <image> --profile=<profile> cmdscan
```

#### プロファイルを指定してシェルコマンドヒストリを表示

```bash
volatility -f <image> --profile=<profile> consoles
```

#### プロファイルを指定してファイル情報を表示

```bash
volatility -f <image> --profile=<profile> filescan
```

#### プロファイルを指定してネットワーク情報を表示

```bash
volatility -f <image> --profile=<profile> netscan
```

#### プロファイルを指定してプロセスのコマンドラインを表示

```bash
volatility -f <image> --profile=<profile> cmdline
```

#### プロファイルを指定してレジストリの最終書き込み時間を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリの最終アクセス時間を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリの最終変更時間を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのオーナー情報を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのセキュリティ情報を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのサブキーを表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリの値を表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのバリューを表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのサブキーを再帰的に表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリの値を再帰的に表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してレジストリのバリューを再帰的に表示

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```

#### スキャン/ダンプ

```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```

\{% タブのタイトル="vol2" %\}

```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```

#### マスターファイルテーブル

```bash
# I couldn't find any plugin to extract this information in volatility3
```

以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示

```
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

#### プロファイルの確認

```
volatility -f memory.raw imageinfo
```

#### プロセス一覧の取得

```
volatility -f memory.raw --profile=ProfileName pslist
```

#### ネットワーク接続の確認

```
volatility -f memory.raw --profile=ProfileName connections
```

#### ファイル一覧の取得

```
volatility -f memory.raw --profile=ProfileName filescan
```

#### レジストリキーの一覧を取得

```
volatility -f memory.raw --profile=ProfileName hivelist
```

#### レジストリのダンプ

```
volatility -f memory.raw --profile=ProfileName printkey -o hive_offset
```

#### プロセスのダンプ

```
volatility -f memory.raw --profile=ProfileName procdump -p PID -D /path/to/dump/
```

#### ファイルのダンプ

```
volatility -f memory.raw --profile=ProfileName dumpfiles -Q address_range -D /path/to/dump/
```

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。

```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

**NTFSファイルシステム**は、_マスターファイルテーブル_（MFT）として知られる重要なコンポーネントを使用します。このテーブルには、ボリューム上のすべてのファイルについて少なくとも1つのエントリが含まれており、MFT自体もカバーされています。各ファイルに関する重要な詳細（サイズ、タイムスタンプ、アクセス許可、実際のデータなど）は、MFTエントリ内またはこれらのエントリによって参照されるMFT外の領域にカプセル化されています。詳細については、[公式ドキュメント](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)を参照してください。

#### SSLキー/証明書

```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```

\{% タブ タイトル="vol2" %\}

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

{% tab title="vol2" %}
以下は、メモリダンプ解析に関する情報です。

### Volatilityチートシート

#### プラグインのリストを表示する

```bash
volatility --info | less
```

#### プロファイルを指定してVolatilityを実行する

```bash
volatility -f <memory_dump> --profile=<profile_name> <plugin_name>
```

#### プロセスリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> pslist
```

#### ネットワーク接続を取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> connections
```

#### ファイルシステムキャッシュを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> cachedump
```

#### レジストリキーを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### プロセスのハンドルを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> handles -p <pid>
```

#### ファイルをダウンロードする

```bash
volatility -f <memory_dump> --profile=<profile_name> dumpfiles -Q <file_path> -D <output_directory>
```

#### コマンド履歴を取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> cmdscan
```

#### ユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### プロセスのDLLリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> dlllist -p <pid>
```

#### サービスリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> svcscan
```

#### ネットワークトラフィックを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> tcpconn
```

#### ログオンイベントを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> logonlist
```

#### システム情報を取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> sysinfo
```

#### プロセスのコマンドラインを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> cmdline -p <pid>
```

#### レジストリのユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### レジストリのユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### レジストリのユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### レジストリのユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### レジストリのユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### レジストリのユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### レジストリのユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### レジストリのユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

#### レジストリのユーザリストを取得する

```bash
volatility -f <memory_dump> --profile=<profile_name> hivelist
volatility -f <memory_dump> --profile=<profile_name> printkey -o <offset>
```

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
_**rules**_ ディレクトリを作成して実行します。これにより、マルウェアのすべてのyaraルールが含まれる _**malware\_rules.yar**_ というファイルが作成されます。

```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```

### Volatility Cheatsheet

#### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
* **Dumping a DLL**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Listing Sockets**
  * `voljson -f <memory_dump> --profile=<profile> sockets`
* **Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Registry Analysis**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Getting Registry Hive**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping Registry Hive** json
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <registry_key>`
* **File Analysis**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Dumping a File**
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`
* **Yara Scanning**
  * `volatility -f <memory_dump> --profile=<profile> yarascan --yara-file=<rules_file>`
* **Process Tree**
  * `volatility -f <memory_dump> --profile=<profile> pstree`
* **Command Line History**
  * `volatility -f <memory_dump> --profile=<profile> cmdline`
* **User Accounts**
  * `volatility -f <memory_dump> --profile=<profile> useraccounts`
* **Screenshots**
  * `volatility -f <memory_dump> --profile=<profile> screenshot -D <output_directory>`
* **Kernel Drivers**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Driver Module**
  * `volatility -f <memory_dump> --profile=<profile> moddump -b <base_address> -D <output_directory>`
* **API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Hidden Objects**
  * `volatility -f <memory_dump> --profile=<profile> hiddenevents`
* **Detecting Rootkits**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Injections**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting API-Hooking**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Driver Signature Bypass**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Herpaderping**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Ghostwriting**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Hollowing**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Process Process Doppelgänging**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* \*\*Detecting Process Process

```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```

### その他

#### 外部プラグイン

外部プラグインを使用したい場合は、プラグインに関連するフォルダが最初に使用されるパラメータであることを確認してください。

```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```

以下は、メモリダンプ解析に関する情報です。

### Volatilityチートシート

#### プラグインのリストを表示

```bash
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

#### プロファイルを指定してVolatilityを実行

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 plugin_name
```

#### プロセス一覧を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 pslist
```

#### ネットワーク接続を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 connections
```

#### ファイル一覧を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 filescan
```

#### レジストリキーを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 printkey -K "KeyName"
```

#### コマンド履歴を表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 cmdscan
```

#### ユーザリストを表示

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 getsids
```

これらのコマンドを使用して、メモリダンプから有用な情報を取得できます。

```bash
volatilitye --plugins="/tmp/plugins/" [...]
```

#### Autoruns

[https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)

```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```

### Mutexes

```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```

以下は、メモリダンプ解析に関する情報です。

### Volatility チートシート

#### プラグインのリストを表示

```bash
volatility --info | less
```

#### プロファイルのリストを表示

```bash
volatility --info | grep Profile
```

#### プロファイルを指定してイメージファイルの情報を表示

```bash
volatility -f <image> imageinfo --profile=<profile>
```

#### プロセスのリストを表示

```bash
volatility -f <image> --profile=<profile> pslist
```

#### 特定のプロセスの詳細を表示

```bash
volatility -f <image> --profile=<profile> pstree -p <pid>
```

#### ネットワーク接続のリストを表示

```bash
volatility -f <image> --profile=<profile> connections
```

#### ファイルハンドルのリストを表示

```bash
volatility -f <image> --profile=<profile> filescan
```

#### レジストリキーのリストを表示

```bash
volatility -f <image> --profile=<profile> hivelist
```

#### レジストリの内容を表示

```bash
volatility -f <image> --profile=<profile> printkey -o <offset>
```

#### コマンド履歴を表示

```bash
volatility -f <image> --profile=<profile> cmdscan
```

#### ユーザアカウントのリストを表示

```bash
volatility -f <image> --profile=<profile> useraccounts
```

#### ユーザアカウントのパスワードハッシュを表示

```bash
volatility -f <image> --profile=<profile> hashdump
```

#### プロセスの実行コマンドを表示

```bash
volatility -f <image> --profile=<profile> cmdline -p <pid>
```

#### メモリダンプからファイルを抽出

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <offset>
```

#### メモリダンプからプロセスを抽出

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

これらのコマンドを使用して、メモリダンプ解析を行うことができます。

```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```

### シンボリックリンク

```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```

\{% タブのタイトル="vol2" %\}

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```

### Bash

**メモリからbashの履歴を読むことが可能です。** _.bash\_history_ ファイルをダンプすることもできますが、無効になっている場合は、このVolatilityモジュールを使用できることに喜ぶでしょう。

```
./vol.py -f file.dmp linux.bash.Bash
```

以下は、メモリダンプ解析に関する情報です。

### Volatilityチートシート

#### プラグインのリストを表示する

```bash
volatility --info | less
```

#### プロファイルを指定してイメージファイルの情報を表示する

```bash
volatility -f <image> imageinfo
```

#### プロファイルを指定してプロセス一覧を表示する

```bash
volatility -f <image> --profile=<profile> pslist
```

#### プロファイルを指定してネットワーク接続を表示する

```bash
volatility -f <image> --profile=<profile> connections
```

#### プロファイルを指定してレジストリキーを表示する

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

#### プロファイルを指定してファイルをダンプする

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address range>
```

これらのコマンドを使用して、Volatilityを効果的に活用しましょう。

```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```

### タイムライン

```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```

以下は、メモリダンプ解析に関する基本的な手法に関する情報です。

## Volatility チートシート

### プラグインのリストを表示

```bash
volatility --info | less
```

### プロファイルのリストを表示

```bash
volatility -f <dump> imageinfo
```

### プロセスのリストを表示

```bash
volatility -f <dump> pslist
```

### ネットワーク接続のリストを表示

```bash
volatility -f <dump> connections
```

### ファイルシステムのリストを表示

```bash
volatility -f <dump> filescan
```

### レジストリのリストを表示

```bash
volatility -f <dump> hivelist
```

### レジストリキーのリストを表示

```bash
volatility -f <dump> printkey -K "ControlSet001\services"
```

### レジストリ値のリストを表示

```bash
volatility -f <dump> printkey -K "ControlSet001\services" -V
```

### レジストリ値のデータを表示

```bash
volatility -f <dump> printkey -K "ControlSet001\services" -V -v
```

### レジストリ値のデータを16進数で表示

```bash
volatility -f <dump> printkey -K "ControlSet001\services" -V -v --output=hex
```

### プロセスのDLLリストを表示

```bash
volatility -f <dump> dlllist -p <pid>
```

### プロセスのハンドルリストを表示

```bash
volatility -f <dump> handles -p <pid>
```

### プロセスのファイルディスクリプタを表示

```bash
volatility -f <dump> filescan -p <pid>
```

### プロセスのネットワーク接続を表示

```bash
volatility -f <dump> connscan -p <pid>
```

### プロセスのレジストリキーを表示

```bash
volatility -f <dump> printkey -K "Software\Microsoft\Windows\CurrentVersion\Run" -p <pid>
```

### プロセスのレジストリ値を表示

```bash
volatility -f <dump> printkey -K "Software\Microsoft\Windows\CurrentVersion\Run" -p <pid> -V
```

### プロセスのレジストリ値のデータを表示

```bash
volatility -f <dump> printkey -K "Software\Microsoft\Windows\CurrentVersion\Run" -p <pid> -V -v
```

### プロセスのレジストリ値のデータを16進数で表示

```bash
volatility -f <dump> printkey -K "Software\Microsoft\Windows\CurrentVersion\Run" -p <pid> -V -v --output=hex
```

### プロセスのモジュールリストを表示

```bash
volatility -f <dump> modlist -p <pid>
```

### プロセスのモジュール情報を表示

```bash
volatility -f <dump> moddump -p <pid> -D <output_directory>
```

### スクリーンショットを取得

```bash
volatility -f <dump> screenshot --dump-dir=<output_directory>
```

### プロセスのスクリーンショットを取得

```bash
volatility -f <dump> screenshot -p <pid> --dump-dir=<output_directory>
```

### ファイルのダウンロード

```bash
volatility -f <dump> dumpfiles -Q <address_range> -D <output_directory>
```

### ファイルのダウンロード（ファイル名指定）

```bash
volatility -f <dump> dumpfiles -Q <address_range> -D <output_directory> --name
```

### ファイルのダウンロード（ファイル名指定＆自動解凍）

```bash
volatility -f <dump> dumpfiles -Q <address_range> -D <output_directory> --name --unzip
```

### レジストリハイブのダウンロード

```bash
volatility -f <dump> hivelist --output-file=<output_file>
```

### レジストリハイブのダウンロード（指定したハイブ）

```bash
volatility -f <dump> printkey -o <offset> --output-file=<output_file>
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数）

```bash
volatility -f <dump> printkey -o <offset> --output-file=<output_file> --output=hex
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍）

```bash
volatility -f <dump> printkey -o <offset> --output-file=<output_file> --output=hex --unzip
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍＆ファイル名指定）

```bash
volatility -f <dump> printkey -o <offset> --output-file=<output_file> --output=hex --unzip --name
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍＆ファイル名指定＆フォーマット指定）

```bash
volatility -f <dump> printkey -o <offset> --output-file=<output_file> --output=hex --unzip --name --format=reg
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍＆ファイル名指定＆フォーマット指定＆レジストリキー指定）

```bash
volatility -f <dump> printkey -o <offset> -K "ControlSet001\services" --output-file=<output_file> --output=hex --unzip --name --format=reg
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍＆ファイル名指定＆フォーマット指定＆レジストリキー指定＆レジストリ値指定）

```bash
volatility -f <dump> printkey -o <offset> -K "ControlSet001\services" -V --output-file=<output_file> --output=hex --unzip --name --format=reg
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍＆ファイル名指定＆フォーマット指定＆レジストリキー指定＆レジストリ値指定＆データ表示）

```bash
volatility -f <dump> printkey -o <offset> -K "ControlSet001\services" -V -v --output-file=<output_file> --output=hex --unzip --name --format=reg
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍＆ファイル名指定＆フォーマット指定＆レジストリキー指定＆レジストリ値指定＆データ表示＆データ16進数表示）

```bash
volatility -f <dump> printkey -o <offset> -K "ControlSet001\services" -V -v --output-file=<output_file> --output=hex --unzip --name --format=reg
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍＆ファイル名指定＆フォーマット指定＆レジストリキー指定＆レジストリ値指定＆データ表示＆データ16進数表示＆データ自動解凍）

```bash
volatility -f <dump> printkey -o <offset> -K "ControlSet001\services" -V -v --output-file=<output_file> --output=hex --unzip --name --format=reg
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍＆ファイル名指定＆フォーマット指定＆レジストリキー指定＆レジストリ値指定＆データ表示＆データ16進数表示＆データ自動解凍＆データ自動解凍）

```bash
volatility -f <dump> printkey -o <offset> -K "ControlSet001\services" -V -v --output-file=<output_file> --output=hex --unzip --name --format=reg
```

### レジストリハイブのダウンロード（指定したハイブ＆16進数＆自動解凍＆ファイル名指定＆フォーマット指定＆レジストリキー指定＆レジストリ値指定＆データ表示＆データ16進数表示＆データ自動解凍＆データ自動解凍＆データ自動解凍）

```bash
volatility -f <dump> printkey -o <offset> -K "ControlSet001\services" -V -v --output-file=<output_file> --output=hex --unzip --name --format=reg
```

```
volatility --profile=Win7SP1x86_23418 -f timeliner
```

### ドライバー

```
./vol.py -f file.dmp windows.driverscan.DriverScan
```

以下は、メモリダンプ解析に関する情報です。

## Volatility チートシート

### プラグインのリストを表示

```bash
volatility --info | grep -iE "plugin_name1|plugin_name2"
```

### プロファイルを指定してイメージファイルの情報を表示

```bash
volatility -f memory.raw imageinfo --profile=Win7SP1x64
```

### 特定のプロセスのネットワーク接続を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 netscan -p PID
```

### 特定のプロセスのファイルハンドルを表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 filescan -p PID
```

### レジストリキーの値を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 printkey -o OFFSET
```

### プロセスのコマンドライン引数を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 cmdline -p PID
```

### プロセスの DLL リストを表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 dlllist -p PID
```

### プロセスのモジュール情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 modscan -p PID
```

### プロセスのヒープ情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 heaps -p PID
```

### プロセスのスレッド情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 threads -p PID
```

### プロセスのハンドル情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 handles -p PID
```

### プロセスのマップされたファイルを表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 malfind -p PID
```

### プロセスのネットワーク情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 connscan -p PID
```

### プロセスのレジストリハンドルを表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 hivelist -p PID
```

### プロセスのセキュリティ属性を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getsids -p PID
```

### プロセスのサービス情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getservicesids -p PID
```

### プロセスのサービス情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getservicesids -p PID
```

### プロセスのサービス情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getservicesids -p PID
```

### プロセスのサービス情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getservicesids -p PID
```

### プロセスのサービス情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getservicesids -p PID
```

### プロセスのサービス情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getservicesids -p PID
```

### プロセスのサービス情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getservicesids -p PID
```

### プロセスのサービス情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getservicesids -p PID
```

### プロセスのサービス情報を表示

```bash
volatility -f memory.raw --profile=Win7SP1x64 getservicesids -p PID
```

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

\*\*マスターブートレコード（MBR）\*\*は、ストレージメディアの論理パーティションを管理する際に重要な役割を果たします。これらのパーティションは異なる[ファイルシステム](https://en.wikipedia.org/wiki/File\_system)で構成されています。MBRはパーティションレイアウト情報だけでなく、ブートローダーとして機能する実行可能コードも含んでいます。このブートローダーは、OSの第2段階の読み込みプロセスを直接開始するか、各パーティションの[ボリュームブートレコード](https://en.wikipedia.org/wiki/Volume\_boot\_record)（VBR）と協調して動作します。詳細な知識については、[MBR Wikipediaページ](https://en.wikipedia.org/wiki/Master\_boot\_record)を参照してください。

## 参考文献

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術的知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての活発な交流の場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

**HackTricksをサポートする他の方法：HackTricksで企業を宣伝したい場合やHackTricksをPDFでダウンロードしたい場合は、**[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)**をチェックしてください！**[**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)**を入手してください**[**The PEASS Family**](https://opensea.io/collection/the-peass-family)**を発見し、独占的な**[**NFTs**](https://opensea.io/collection/the-peass-family)**コレクションをご覧ください💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f)**や**[**telegramグループ**](https://t.me/peass)**に参加するか、Twitter 🐦** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてくださいハッキングトリックを共有するために、**[**HackTricks**](https://github.com/carlospolop/hacktricks)**と**[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)**のGitHubリポジトリにPRを提出してください**

</details>
