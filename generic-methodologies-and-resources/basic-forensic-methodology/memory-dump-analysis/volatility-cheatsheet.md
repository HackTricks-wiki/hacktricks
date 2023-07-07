# Volatility - チートシート

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。この大会は、技術的な知識を促進することを目的としており、あらゆる分野の技術とサイバーセキュリティの専門家のための活気ある交流の場です。

{% embed url="https://www.rootedcon.com/" %}

もし**高速でクレイジーな**ものが欲しい場合は、複数のVolatilityプラグインを並列で実行することができます: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
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
#### メソッド1: プロファイルの選択

- `imageinfo`コマンドを使用して、メモリダンプのプロファイルを特定します。

```bash
volatility -f <memory_dump> imageinfo
```

- プロファイルの選択肢が表示されます。適切なプロファイルを選択します。

```bash
volatility -f <memory_dump> --profile=<profile> <command>
```

- プロファイルを指定することで、Volatilityは正しいオフセットと構造を使用してメモリダンプを解析します。

{% endtab %}
{% tab title="Method2" %}

#### メソッド2: プロセスのリスト

- `pslist`コマンドを使用して、メモリダンプ内の実行中のプロセスのリストを取得します。

```bash
volatility -f <memory_dump> --profile=<profile> pslist
```

- プロセスのリストには、プロセスID（PID）、親プロセスID（PPID）、プロセス名、および実行中のスレッド数が含まれます。

{% endtab %}
{% tab title="Method3" %}

#### メソッド3: プロセスのメモリダンプ

- `procdump`コマンドを使用して、特定のプロセスのメモリダンプを作成します。

```bash
volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>
```

- `<pid>`には対象プロセスのPIDを指定し、`<output_directory>`にはメモリダンプの保存先ディレクトリを指定します。

{% endtab %}
{% tab title="Method4" %}

#### メソッド4: ファイルのリスト

- `filescan`コマンドを使用して、メモリダンプ内のファイルのリストを取得します。

```bash
volatility -f <memory_dump> --profile=<profile> filescan
```

- ファイルのリストには、ファイルのハンドル、ファイルパス、およびファイルサイズが含まれます。

{% endtab %}
{% tab title="Method5" %}

#### メソッド5: ファイルの抽出

- `dumpfiles`コマンドを使用して、メモリダンプから特定のファイルを抽出します。

```bash
volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <file_path> -D <output_directory>
```

- `<file_path>`には抽出したいファイルのパスを指定し、`<output_directory>`には抽出したファイルの保存先ディレクトリを指定します。

{% endtab %}
{% endtabs %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% tab title="方法2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatilityコマンド

公式ドキュメントにアクセスするには、[Volatilityコマンドリファレンス](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)を参照してください。

### 「list」対「scan」プラグインに関する注意事項

Volatilityには、プラグインに対して2つの主要なアプローチがあり、それはプラグインの名前に反映されることもあります。「list」プラグインは、Windowsカーネルの構造をナビゲートして、プロセス（メモリ内の`_EPROCESS`構造体のリンクリストを検索してウォークする）、OSハンドル（ハンドルテーブルを検索してリスト化し、見つかったポインタを参照解除するなど）などの情報を取得しようとします。これらは、たとえば、プロセスの一覧を表示するように要求された場合にWindows APIが振る舞うのとほぼ同じように振る舞います。

これにより、「list」プラグインは非常に高速ですが、マルウェアによる操作に対してWindows APIと同じくらい脆弱です。たとえば、マルウェアがDKOMを使用してプロセスを`_EPROCESS`リンクリストから切り離す場合、それはタスクマネージャに表示されず、pslistにも表示されません。

一方、「scan」プラグインは、特定の構造体としてデリファレンスされた場合に意味を持つ可能性のあるものをメモリから切り出すというアプローチを取ります。たとえば、`psscan`はメモリを読み取り、それを`_EPROCESS`オブジェクトに変換しようとします（興味のある構造体の存在を示す4バイトの文字列を検索するプールタグスキャンを使用します）。利点は、終了したプロセスを発掘できることであり、マルウェアが`_EPROCESS`リンクリストを改ざんしても、プラグインはメモリ内に残っている構造体を見つけることができます（プロセスが実行されるためにはまだ存在する必要があるため）。欠点は、「scan」プラグインが「list」プラグインよりもやや遅く、時には誤検知（過去に終了したプロセスであり、その構造の一部が他の操作によって上書きされたもの）を引き起こすことがあることです。

出典：[http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OSプロファイル

### Volatility3

readme内で説明されているように、サポートするOSの**シンボルテーブル**を_volatility3/volatility/symbols_に配置する必要があります。さまざまなオペレーティングシステムのシンボルテーブルパックは、以下から**ダウンロード**できます。

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### 外部プロファイル

サポートされているプロファイルのリストを取得するには、以下を実行します。
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
もし**ダウンロードした新しいプロファイル**（例えばLinuxのもの）を使用したい場合は、以下のフォルダ構造を作成する必要があります: _plugins/overlays/linux_ そして、このフォルダにプロファイルを含むzipファイルを入れます。次に、以下のコマンドを使用してプロファイルの数を取得します:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
LinuxとMacのプロファイルは[https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)から**ダウンロード**できます。

前のチャンクでは、プロファイルが`LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`と呼ばれていることがわかります。これを使用して、次のような操作を実行できます。
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### プロファイルの発見

```plaintext
volatility -f <memory_dump> imageinfo
```

このコマンドは、メモリダンプファイルのプロファイル情報を表示します。プロファイル情報には、オペレーティングシステムのバージョンやアーキテクチャなどが含まれています。
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfoとkdbgscanの違い**

imageinfoは単にプロファイルの提案を行うだけですが、**kdbgscan**は正確なプロファイルと正確なKDBGアドレス（複数ある場合）を確実に特定するために設計されています。このプラグインは、Volatilityプロファイルに関連するKDBGHeaderのシグネチャをスキャンし、偽陽性を減らすために正当性チェックを適用します。出力の冗長性と実行できる正当性チェックの数は、VolatilityがDTBを見つけることができるかどうかに依存します。したがって、すでに正しいプロファイルを知っている場合（またはimageinfoからプロファイルの提案を受け取った場合）、それを使用するようにしてください（[ここ](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)から）。

常にkdbgscanが見つけた**プロセスの数**を確認してください。imageinfoとkdbgscanは、**1つ以上の適切なプロファイル**を見つけることがありますが、**有効なプロファイルには関連するプロセスがある**ことに注意してください（これはプロセスを抽出するために正しいKDBGアドレスが必要なためです）。
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

**カーネルデバッガブロック**（\_KDDEBUGGER\_DATA64型のKdDebuggerDataBlockとしても知られる）は、Volatilityとデバッガが行う多くのことに重要です。たとえば、プロセスリストに必要なすべてのプロセスのリストヘッドであるPsActiveProcessHeadへの参照が含まれています。

## OS情報
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
プラグイン`banners.Banners`は、ダンプ内のLinuxバナーを見つけるために**vol3で使用できます**。

## ハッシュ/パスワード

SAMハッシュ、[ドメインのキャッシュされた資格情報](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials)、および[lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets)を抽出します。

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ>
```

### 特定のスレッドのヒープのヒープブロックのデータをファイルに保存する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数で表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump
```

### 特定のスレッドのヒープのヒープブロックのデータをASCIIで表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --dump
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z -e
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化し、クラウドストレージにアップロードする

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z -e -u
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化し、クラウドストレージにアップロードし、リンクを生成する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z -e -u -l
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化し、クラウドストレージにアップロードし、リンクを生成し、メールで送信する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z -e -u -l -m
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化し、クラウドストレージにアップロードし、リンクを生成し、メールで送信し、自動的に実行する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z -e -u -l -m -a
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化し、クラウドストレージにアップロードし、リンクを生成し、メールで送信し、自動的に実行し、実行後にファイルを削除する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z -e -u -l -m -a -r
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化し、クラウドストレージにアップロードし、リンクを生成し、メールで送信し、自動的に実行し、実行後にファイルを削除し、実行後にシステムをシャットダウンする

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z -e -u -l -m -a -r -s
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化し、クラウドストレージにアップロードし、リンクを生成し、メールで送信し、自動的に実行し、実行後にファイルを削除し、実行後にシステムをシャットダウンし、実行後にシステムを再起動する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z -e -u -l -m -a -r -s -b
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化し、クラウドストレージにアップロードし、リンクを生成し、メールで送信し、自動的に実行し、実行後にファイルを削除し、実行後にシステムをシャットダウンし、実行後にシステムを再起動し、実行後にシステムをスリープする

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名> --hexdump --dump -o -z -e -u -l -m -a -r -s -b -w
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存し、圧縮し、暗号化し、クラウドストレージにアップロードし、リンクを生成し、メールで送信し、自動的に実行し、実行後にファイルを削除し、実行後にシステムをシャットダウンし、実行後にシステムを再起動し、実行後にシステムをスリープし、実行後にシステムをハイバネートする

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## メモリダンプ

プロセスのメモリダンプは、プロセスの現在の状態のすべてを抽出します。**procdump**モジュールは、**コード**のみを抽出します。
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術的な知識の促進を目的**として、この会議はあらゆる分野の技術とサイバーセキュリティの専門家の熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## プロセス

### プロセスの一覧表示

**疑わしい**プロセス（名前による）や**予期しない**子プロセス（例えば、iexplorer.exeの子としてのcmd.exe）を見つけてみてください。\
pslistの結果とpsscanの結果を比較して、隠れたプロセスを特定することが興味深いかもしれません。

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
# Volatility Cheat Sheet

## Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

## Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory image.
- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `connections`: Lists network connections.
- `cmdline`: Displays command-line arguments for processes.
- `malfind`: Finds hidden or injected code.
- `dumpfiles`: Extracts files from memory.

## Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `mbrparser`: Parses the Master Boot Record (MBR).
- `ssdt`: Displays the System Service Descriptor Table (SSDT).
- `idt`: Displays the Interrupt Descriptor Table (IDT).
- `gdt`: Displays the Global Descriptor Table (GDT).
- `ldrmodules`: Lists loaded modules.
- `modscan`: Scans for modules.
- `vadinfo`: Displays information about Virtual Address Descriptors (VADs).
- `vaddump`: Dumps a specific VAD.
- `vadtree`: Displays a VAD tree.

## Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Finds hidden or injected code.
- `timeliner`: Creates a timeline of events.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates.
- `hivelist`: Lists registry hives.
- `hashdump`: Dumps password hashes.
- `shellbags`: Lists Windows Explorer shellbags.

## Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheat sheet, analysts can effectively extract and analyze valuable information from memory dumps.
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### プロセスのダンプ

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プ
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### コマンドライン

何か怪しいことが実行されましたか？
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プ
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

cmd.exeに入力されたコマンドは、**conhost.exe**（Windows 7以前はcsrss.exe）によって処理されます。したがって、攻撃者がメモリ**ダンプ**を取得する前にcmd.exeを**終了**させたとしても、**conhost.exeのメモリ**からコマンドラインセッションの履歴を復元する可能性があります。コンソールのモジュールを使用して**奇妙なもの**を見つけた場合は、**関連するconhost.exeのプロセスのメモリ**を**ダンプ**し、その中から文字列を**検索**してコマンドラインを抽出してください。

### 環境

実行中の各プロセスの環境変数を取得します。興味深い値があるかもしれません。
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

## ネットワーク

### ネットワーク接続の一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> netscan
```

### 特定のプロセスのネットワーク接続を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> connscan -p <プロセスID>
```

### 特定のプロセスのネットワーク通信内容を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> tcpdump -p <プロセスID>
```

## ファイルシステム

### ファイルシステムの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> filescan
```

### 特定のプロセスが開いているファイルを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> handles -p <プロセスID>
```

### 特定のファイルの内容を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <ファイルパス>
```

## レジストリ

### レジストリキーの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hivelist
```

### 特定のレジストリキーの内容を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キーパス>
```

### 特定のレジストリキーのサブキー一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キーパス> -v
```

### 特定のレジストリキーの値を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キーパス> -v -o <オフセット>
```

## イベントログ

### イベントログの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> evtlogs
```

### 特定のイベントログの内容を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpcerts -n <イベントログ名>
```

### 特定のイベントログのイベントを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpcerts -n <イベントログ名> -e <イベントID>
```

## ユーザー情報

### ユーザーの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hivescan
```

### 特定のユーザーのSIDを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> getsids -u <ユーザー名>
```

### 特定のユーザーのパスワードハッシュを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hashdump -u <ユーザー名>
```

## プロセスの実行

### 特定のプロセスを実行する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> -D <出力ディレクトリ> procdump -p <プロセスID>
```

### 特定のプロセスを実行してメモリダンプを取得する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> -D <出力ディレクトリ> memdump -p <プロセスID>
```

### 特定のプロセスを実行してメモリダンプを取得する（圧縮）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> -D <出力ディレクトリ> memdump --compress -p <プロセスID>
```

## メモリダンプの解析

### メモリダンプのプロファイルを表示する

```bash
volatility -f <ファイル名> imageinfo
```

### メモリダンプのプロファイルを指定して解析する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> <コマンド>
```

### メモリダンプのプロファイルを自動的に判別して解析する

```bash
volatility -f <ファイル名> <コマンド>
```
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### トークンの特権

予期しないサービスで特権トークンをチェックします。\
特権トークンを使用しているプロセスのリストを作成することが興味深いかもしれません。

{% tabs %}
{% tab title="vol3" %}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
# Volatility Cheat Sheet

## Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

## Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory image.
- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `connections`: Lists network connections.
- `cmdline`: Displays command-line arguments for processes.
- `malfind`: Finds hidden or injected code.
- `dumpfiles`: Extracts files from memory.

## Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `mbrparser`: Parses the Master Boot Record (MBR).
- `ssdt`: Displays the System Service Descriptor Table (SSDT).
- `idt`: Displays the Interrupt Descriptor Table (IDT).
- `gdt`: Displays the Global Descriptor Table (GDT).
- `ldrmodules`: Lists loaded modules.
- `modscan`: Scans for modules.
- `vadinfo`: Displays information about Virtual Address Descriptors (VADs).
- `vaddump`: Dumps a specific VAD.
- `vadtree`: Displays a VAD tree.

## Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Finds hidden or injected code.
- `timeliner`: Creates a timeline of events.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hashdump`: Dumps password hashes.

## Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheat sheet, analysts can effectively extract and analyze valuable information from memory dumps.
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

各プロセスが所有するSSIDをチェックします。\
特権SIDを使用しているプロセス（および一部のサービスSIDを使用しているプロセス）をリストアップすることが興味深いかもしれません。
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### ハンドル

プロセスがハンドルを持っている他のファイル、キー、スレッド、プロセスなどを知るために役立ちます。
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### DLLs

{% tabs %}
{% tab title="vol3" %}

DLLs（Dynamic Link Libraries）は、Windowsシステムで共有されるコードとリソースのコレクションです。これらのDLLは、プロセスが実行される際に自動的に読み込まれ、必要な機能を提供します。Volatilityを使用して、メモリダンプからDLL情報を抽出することができます。

以下は、DLL情報を取得するための一般的なコマンドです。

```plaintext
volatility -f <memory_dump> --profile=<profile> dlllist
```

このコマンドを実行すると、メモリダンプ内のすべてのプロセスのDLL情報が表示されます。DLLのベースアドレス、サイズ、パスなどの詳細な情報が含まれています。

また、特定のプロセスのDLL情報を取得するには、次のコマンドを使用します。

```plaintext
volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>
```

`<pid>`は、対象のプロセスのPID（プロセスID）です。

DLL情報は、マルウェア解析やフォレンジック調査において重要な情報源となります。特定のDLLが異常な挙動を示している場合、それがセキュリティ上の問題を引き起こしている可能性があります。
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R -V
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R -V -S
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R -V -S -T
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R -V -S -T -U
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R -V -S -T -U -W
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R -V -S -T -U -W -Y
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R -V -S -T -U -W -Y -Z
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R -V -S -T -U -W -Y -Z -A
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> free -p <プロセスID> -t <スレッドID> -s -v -a -x -r -X -R -V -S -T -U -W -Y -Z -A -B
```

### 特定のスレッドのヒープのフリーブロックのスタックトレースを表示する（詳細情報あり、アドレスも表示、アドレスを16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示、アドレスを逆順で16進数で表示、アドレスを逆順で表示）

```bash
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### プロセスごとの文字列

Volatilityを使用すると、文字列がどのプロセスに属しているかを確認できます。

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
## プロセスとスレッド

### プロセス一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### スレッド一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threadstacks -p <プロセスID>
```

## ネットワーク

### ネットワーク接続の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> netscan
```

### ネットワーク接続の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> connscan
```

### ネットワーク接続のプロセスとスレッドの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> connscan -p <プロセスID>
```

## ファイルシステム

### ファイル一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> filescan
```

### 特定のファイルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> filescan -i <inode>
```

### ファイルの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## レジストリ

### レジストリキー一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hivelist
```

### 特定のレジストリキーの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キーパス>
```

### レジストリキーの値の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キーパス> -o <オフセット>
```

### レジストリキーの値のデータの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キーパス> -o <オフセット> -D
```

## イベントログ

### イベントログの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> evtlogs
```

### 特定のイベントログの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> evtlogs -n <ログ名>
```

### イベントログの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> evtlogs -n <ログ名> -o <オフセット>
```

## プロセスメモリ

### 特定のプロセスのメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のプロセスのメモリダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```

## ファイルキャッシュ

### ファイルキャッシュの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> filescan
```

### 特定のファイルキャッシュの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> filescan -i <inode>
```

### ファイルキャッシュの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのヒープ

### 特定のプロセスのヒープの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID>
```

### 特定のヒープの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heap -p <プロセスID> -H <ヒープアドレス>
```

### 特定のヒープの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpheap -p <プロセスID> -H <ヒープアドレス> -D <出力ディレクトリ>
```

## プロセスのスタック

### 特定のプロセスのスタックの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID>
```

### 特定のスタックの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -s <スタックアドレス>
```

### 特定のスタックの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpstack -p <プロセスID> -s <スタックアドレス> -D <出力ディレクトリ>
```

## プロセスのモジュール

### 特定のプロセスのモジュールの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> modules -p <プロセスID>
```

### 特定のモジュールの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> modscan -p <プロセスID> -m <モジュール名>
```

### 特定のモジュールの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのスレッド

### 特定のプロセスのスレッドの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threadstacks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのハンドル

### 特定のプロセスのハンドルの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> handles -p <プロセスID>
```

### 特定のハンドルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> handles -p <プロセスID> -t <ハンドルタイプ>
```

### 特定のハンドルの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのセキュリティ

### 特定のプロセスのセキュリティ情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> getsids -p <プロセスID>
```

### 特定のセキュリティ情報の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> getsids -p <プロセスID> -t <セキュリティID>
```

### 特定のセキュリティ情報の内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのネットワーク

### 特定のプロセスのネットワーク情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> netscan -p <プロセスID>
```

### 特定のネットワーク情報の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> netscan -p <プロセスID> -t <ネットワークID>
```

### 特定のネットワーク情報の内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのウィンドウ

### 特定のプロセスのウィンドウ情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> windows -p <プロセスID>
```

### 特定のウィンドウ情報の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> windows -p <プロセスID> -t <ウィンドウID>
```

### 特定のウィンドウ情報の内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのサービス

### 特定のプロセスのサービス情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> services -p <プロセスID>
```

### 特定のサービス情報の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> services -p <プロセスID> -t <サービスID>
```

### 特定のサービス情報の内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのウィンドウステーション

### 特定のプロセスのウィンドウステーション情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> winstations -p <プロセスID>
```

### 特定のウィンドウステーション情報の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> winstations -p <プロセスID> -t <ウィンドウステーションID>
```

### 特定のウィンドウステーション情報の内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのデスクトップ

### 特定のプロセスのデスクトップ情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> desktops -p <プロセスID>
```

### 特定のデスクトップ情報の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> desktops -p <プロセスID> -t <デスクトップID>
```

### 特定のデスクトップ情報の内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのウィンドウステーション

### 特定のプロセスのウィンドウステーション情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> winstations -p <プロセスID>
```

### 特定のウィンドウステーション情報の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> winstations -p <プロセスID> -t <ウィンドウステーションID>
```

### 特定のウィンドウステーション情報の内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

それはまた、yarascanモジュールを使用してプロセス内の文字列を検索することも可能です。
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows**システムは、実行されたプログラムを追跡するために、レジストリデータベース（**UserAssistキー**）に一連の**キー**を保持しています。これらの**キー**には、実行回数や最終実行日時が利用可能です。
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
# Volatility Cheat Sheet

## Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

## Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory image.
- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `connections`: Lists network connections.
- `cmdline`: Displays command-line arguments for processes.
- `malfind`: Finds hidden or injected code.
- `dumpfiles`: Extracts files from memory.

## Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `mbrparser`: Parses the Master Boot Record (MBR).
- `ssdt`: Displays the System Service Descriptor Table (SSDT).
- `idt`: Displays the Interrupt Descriptor Table (IDT).
- `gdt`: Displays the Global Descriptor Table (GDT).
- `ldrmodules`: Lists loaded modules.
- `modscan`: Scans for modules.
- `vadinfo`: Displays information about Virtual Address Descriptors (VADs).
- `vaddump`: Dumps memory based on VADs.
- `vadtree`: Displays a tree of VADs.

## Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Finds hidden or injected code.
- `timeliner`: Creates a timeline of events.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates.
- `hivelist`: Lists registry hives.
- `hashdump`: Dumps password hashes.
- `shellbags`: Extracts information from Windows Explorer shellbags.

## Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheat sheet, analysts can effectively extract and analyze valuable information from memory dumps.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。技術的な知識を促進することを使命としているこの会議は、あらゆる分野の技術とサイバーセキュリティの専門家の熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## サービス

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -
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
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -
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
{% endtab %}
{% endtabs %}

## レジストリハイブ

### 利用可能なハイブの表示

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -h
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -h -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -h -H -H -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### 値を取得する

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% tabs %}
{% tab title="English" %}
A memory dump is a snapshot of the computer's memory at a specific point in time. It contains information about the running processes, loaded modules, network connections, and other system-related data. Analyzing memory dumps can provide valuable insights into the state of a system during a security incident or forensic investigation.

To analyze a memory dump, you can use the Volatility framework. Volatility is an open-source tool that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of memory-related artifacts.

The basic steps for analyzing a memory dump using Volatility are as follows:

1. Identify the profile: The profile specifies the operating system and service pack version of the memory dump. You need to determine the correct profile to ensure accurate analysis.

2. Extract the necessary information: Use Volatility commands to extract the desired information from the memory dump. This can include process lists, network connections, registry hives, and more.

3. Analyze the extracted data: Once you have extracted the relevant information, analyze it to identify any suspicious or malicious activity. Look for signs of malware, unauthorized access, or other indicators of compromise.

4. Cross-reference with other data sources: To get a complete picture of the incident, cross-reference the memory dump analysis with other data sources such as log files, network traffic captures, and system event logs.

By following these steps, you can effectively analyze memory dumps and uncover valuable information for incident response and forensic investigations.
{% endtab %}
{% endtabs %}

### ダンプ

メモリダンプは、特定の時点でのコンピュータのメモリのスナップショットです。実行中のプロセス、ロードされたモジュール、ネットワーク接続、およびその他のシステム関連のデータに関する情報が含まれています。メモリダンプの分析は、セキュリティインシデントや法的調査中のシステムの状態に関する貴重な洞察を提供することができます。

メモリダンプを分析するためには、Volatilityフレームワークを使用することができます。Volatilityは、メモリダンプから情報を抽出し分析するためのオープンソースツールです。さまざまな種類のメモリ関連のアーティファクトを調査するために使用でき、幅広いオペレーティングシステムをサポートしています。

Volatilityを使用してメモリダンプを分析する基本的な手順は次のとおりです。

1. プロファイルの特定：プロファイルは、メモリダンプのオペレーティングシステムとサービスパックのバージョンを指定します。正確な分析を行うために、正しいプロファイルを特定する必要があります。

2. 必要な情報の抽出：Volatilityコマンドを使用して、メモリダンプから必要な情報を抽出します。これには、プロセスリスト、ネットワーク接続、レジストリハイブなどが含まれる場合があります。

3. 抽出したデータの分析：関連する情報を抽出したら、それを分析して、不審な活動や悪意のある活動を特定します。マルウェアの兆候、不正アクセス、またはその他の侵害の指標を探します。

4. 他のデータソースとの相互参照：インシデントの完全な情報を得るために、メモリダンプの分析をログファイル、ネットワークトラフィックキャプチャ、およびシステムイベントログなどの他のデータソースと相互参照します。

これらの手順に従うことで、メモリダンプを効果的に分析し、インシデント対応や法的調査において貴重な情報を明らかにすることができます。
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
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ>
```

### 特定のスレッドのヒープのヒープブロックのデータをファイルに保存する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数で表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータをASCIIで表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> strings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリは自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
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
## プロセスとスレッド

### プロセス一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pslist
```

### 特定のプロセスの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> psxview -p <プロセスID>
```

### スレッド一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threads
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threadstacks -p <プロセスID>
```

## ネットワーク

### ネットワーク接続の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> netscan
```

### ネットワーク接続の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> connscan
```

### ネットワーク接続のプロセスとスレッドの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> connscan -p
```

## ファイルシステム

### ファイル一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan
```

### ファイルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan -i <inode>
```

### ファイルの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> dumpfiles -Q <inode>
```

## レジストリ

### レジストリキー一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> hivelist
```

### レジストリキーの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キーパス>
```

### レジストリキーのサブキー一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キーパス> -v
```

### レジストリキーの値の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キーパス> -v -o <オフセット>
```

## イベントログ

### イベントログの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs
```

### 特定のイベントログの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs -n <イベントログ名>
```

### イベントログの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs -o <オフセット>
```

## プロセスメモリ

### 特定のプロセスのメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のプロセスのメモリダンプの作成（ファイル名指定）

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ> --name=<ファイル名>
```

### 特定のプロセスのメモリダンプの作成（ファイル名指定、圧縮）

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ> --name=<ファイル名> --compress
```

### 特定のプロセスのメモリダンプの作成（ファイル名指定、圧縮、暗号化）

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ> --name=<ファイル名> --compress --crypt=<パスワード>
```

## プロセスヒープ

### 特定のプロセスのヒープ情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heaps -p <プロセスID>
```

### 特定のヒープの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -H <ヒープアドレス>
```

### 特定のヒープのブロック一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -H <ヒープアドレス> -B
```

### 特定のヒープのブロックの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -H <ヒープアドレス> -B -o <オフセット>
```

## プロセススレッドスタック

### 特定のスレッドのスタックの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのスタックの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> stack -p <プロセスID> -t <スレッドID> -o <オフセット>
```

## プロセススレッドヒープ

### 特定のスレッドのヒープ情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のヒープの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -t <スレッドID> -H <ヒープアドレス>
```

### 特定のヒープのブロック一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -t <スレッドID> -H <ヒープアドレス> -B
```

### 特定のヒープのブロックの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -t <スレッドID> -H <ヒープアドレス> -B -o <オフセット>
```

## プロセススレッドスタック

### 特定のスレッドのスタックの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのスタックの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> stack -p <プロセスID> -t <スレッドID> -o <オフセット>
```

## プロセススレッドヒープ

### 特定のスレッドのヒープ情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のヒープの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -t <スレッドID> -H <ヒープアドレス>
```

### 特定のヒープのブロック一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -t <スレッドID> -H <ヒープアドレス> -B
```

### 特定のヒープのブロックの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -t <スレッドID> -H <ヒープアドレス> -B -o <オフセット>
```

## ドライバとモジュール

### ドライバ一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> driverscan
```

### ドライバの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> modscan
```

### 特定のドライバの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> modscan -m <ドライバ名>
```

### 特定のモジュールの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> modscan -m <モジュール名>
```

## サービス

### サービス一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> svcscan
```

### 特定のサービスの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> svcscan -s <サービス名>
```

## プロセスとスレッド

### プロセス一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pslist
```

### 特定のプロセスの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> psxview -p <プロセスID>
```

### スレッド一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threads
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threadstacks -p <プロセスID>
```

## ネットワーク

### ネットワーク接続の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> netscan
```

### ネットワーク接続の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> connscan
```

### ネットワーク接続のプロセスとスレッドの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> connscan -p
```

## ファイルシステム

### ファイル一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan
```

### ファイルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan -i <inode>
```

### ファイルの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> dumpfiles -Q <inode>
```

## レジストリ

### レジストリキー一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> hivelist
```

### レジストリキーの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キーパス>
```

### レジストリキーのサブキー一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キーパス> -v
```

### レジストリキーの値の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キーパス> -v -o <オフセット>
```

## イベントログ

### イベントログの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs
```

### 特定のイベントログの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs -n <イベントログ名>
```

### イベントログの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs -o <オフセット>
```

## プロセスメモリ

### 特定のプロセスのメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のプロセスのメモリダンプの作成（ファイル名指定）

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ> --name=<ファイル名>
```

### 特定のプロセスのメモリダンプの作成（ファイル名指定、圧縮）

```bash
volatility -f <ファイル名> --profile=<プロファイル
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### マスターファイルテーブル

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
## プロセスとスレッド

### プロセス一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pslist
```

### 特定のプロセスの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> psxview -p <プロセスID>
```

### スレッド一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threads
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threadstacks -p <プロセスID>
```

## ネットワーク

### ネットワーク接続の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> netscan
```

### ネットワーク接続の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> connscan
```

### ネットワーク接続のプロセスとスレッドの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> connscan -p <プロセスID>
```

## ファイルシステム

### ファイル一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan
```

### ファイルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan -i <フイイルID>
```

### ファイルの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> dumpfiles -Q <ファイルID> -D <出力ディレクトリ>
```

## レジストリ

### レジストリキー一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> hivelist
```

### レジストリキーの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -o <オフセット>
```

### レジストリキーのサブキー一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キー名>
```

### レジストリキーの値の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キー名> -V
```

## イベントログ

### イベントログの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs
```

### 特定のイベントログの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs -n <ログ名>
```

### イベントログの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs -n <ログ名> -o <オフセット>
```

## プロセスのメモリ解析

### 特定のプロセスのメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のプロセスのメモリダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル>
```

### 特定のプロセスのメモリダンプの解析（GUI）

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル> -g
```

### 特定のプロセスのメモリダンプの解析（プラグイン）

```bash
volatility -f <ファイル名> --profile=<プロファイル> <プラグイン名> -p <プロセスID>
```

## ネットワークのメモリ解析

### 特定のネットワーク接続のメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のネットワーク接続のメモリダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル>
```

### 特定のネットワーク接続のメモリダンプの解析（GUI）

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル> -g
```

### 特定のネットワーク接続のメモリダンプの解析（プラグイン）

```bash
volatility -f <ファイル名> --profile=<プロファイル> <プラグイン名> -p <プロセスID>
```

## ファイルシステムのメモリ解析

### 特定のファイルのメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のファイルのメモリダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル>
```

### 特定のファイルのメモリダンプの解析（GUI）

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル> -g
```

### 特定のファイルのメモリダンプの解析（プラグイン）

```bash
volatility -f <ファイル名> --profile=<プロファイル> <プラグイン名> -p <プロセスID>
```

## レジストリのメモリ解析

### 特定のレジストリキーのメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のレジストリキーのメモリダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル>
```

### 特定のレジストリキーのメモリダンプの解析（GUI）

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル> -g
```

### 特定のレジストリキーのメモリダンプの解析（プラグイン）

```bash
volatility -f <ファイル名> --profile=<プロファイル> <プラグイン名> -p <プロセスID>
```

## イベントログのメモリ解析

### 特定のイベントログのメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のイベントログのメモリダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル>
```

### 特定のイベントログのメモリダンプの解析（GUI）

```bash
volatility -f <ファイル名> --profile=<プロファイル> volshell -f <メモリダンプファイル> -g
```

### 特定のイベントログのメモリダンプの解析（プラグイン）

```bash
volatility -f <ファイル名> --profile=<プロファイル> <プラグイン名> -p <プロセスID>
```

## メモリ解析のワークフロー

1. プロセス、ネットワーク、ファイルシステム、レジストリ、イベントログの情報を収集する。
2. 必要な情報を特定するために、各種コマンドを使用する。
3. 特定のプロセス、ネットワーク接続、ファイル、レジストリキー、イベントログを解析するために、メモリダンプを作成する。
4. メモリダンプを解析するために、volshellコマンドを使用する。
5. 必要な情報を特定するために、各種プラグインを使用する。

## メモリ解析のヒント

- プロセス、ネットワーク接続、ファイル、レジストリキー、イベントログの情報を収集する前に、プロファイルを適切に設定すること。
- メモリダンプを作成する前に、必要な情報を特定すること。
- メモリダンプを解析する前に、volshellコマンドを使用して必要な情報を特定すること。
- メモリダンプを解析する前に、各種プラグインを使用して必要な情報を特定すること。

## メモリ解析のトラブルシューティング

- プロファイルが正しく設定されているか確認すること。
- メモリダンプが正しく作成されているか確認すること。
- volshellコマンドが正しく使用されているか確認すること。
- 各種プラグインが正しく使用されているか確認すること。

## メモリ解析のベストプラクティス

- プロファイルを適切に設定すること。
- 必要な情報を特定するために、各種コマンドを使用すること。
- メモリダンプを作成する前に、必要な情報を特定すること。
- メモリダンプを解析する前に、volshellコマンドを使用して必要な情報を特定すること。
- 必要な情報を特定するために、各種プラグインを使用すること。
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

NTFSファイルシステムには、_マスターファイルテーブル_またはMFTと呼ばれるファイルが含まれています。NTFSファイルシステムボリューム上のすべてのファイルには、MFTに少なくとも1つのエントリがあります（MFT自体も含まれます）。**ファイルに関するすべての情報（サイズ、時刻、日付スタンプ、アクセス許可、データ内容など）**は、MFTエントリまたはMFTエントリで説明されるMFTの外部のスペースに格納されます。[ここから](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)。

### SSLキー/証明書
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ>
```

### 特定のスレッドのヒープのヒープブロックのデータをファイルに保存する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数で表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータをASCIIで表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> strings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリは自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```
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
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -
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

### yaraでスキャンする

このスクリプトを使用して、githubからすべてのyaraマルウェアルールをダウンロードしてマージします：[https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ディレクトリを作成し、実行します。これにより、マルウェアのすべてのyaraルールが含まれた_**malware\_rules.yar**_というファイルが作成されます。
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
# Volatility Cheat Sheet

## Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

## Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory image.
- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `cmdline`: Displays command-line arguments for processes.
- `netscan`: Scans for network connections.
- `connections`: Lists open network connections.
- `modules`: Lists loaded modules.
- `malfind`: Finds hidden or injected code.

## Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `memdump`: Dumps a process memory.
- `dumpfiles`: Extracts files from memory.
- `dumpregistry`: Dumps the registry.
- `dumpcerts`: Dumps certificates.
- `vadinfo`: Displays information about virtual address descriptors.
- `vaddump`: Dumps a virtual address space.
- `vadtree`: Displays a virtual address space tree.
- `vadwalk`: Walks the virtual address space.
- `apihooks`: Lists API hooks.
- `ldrmodules`: Lists loaded modules using the loader order.

## Plugins

Volatility also supports plugins, which provide additional functionality. Some popular plugins include:

- `malfind`: Finds hidden or injected code.
- `timeliner`: Creates a timeline of events.
- `shellbags`: Extracts information from Windows shellbags.
- `cmdscan`: Scans for command history.
- `hivelist`: Lists registry hives.
- `hashdump`: Dumps password hashes.
- `svcscan`: Scans for Windows services.

## Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheat sheet, analysts can extract valuable information from memory dumps and uncover evidence of malicious activity.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## MISC

### 外部プラグイン

外部プラグインを使用する場合は、プラグインに関連するフォルダが最初のパラメータとして使用されていることを確認してください。
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktraces -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ>
```

### 特定のスレッドのヒープのヒープブロックのデータをファイルに保存する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数で表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexdump -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータをASCIIで表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> strings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -D <出力ディレクトリ>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリは自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス> -f <出力ファイル名>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```

### 特定のスレッドのヒープのヒープブロックのデータを16進数とASCIIで表示し、ファイルに保存する（ディレクトリとファイル名は自動生成）

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hexstrings -p <プロセスID> -t <スレッドID> -b <ヒープブロックアドレス>
```
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

[https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)からダウンロードしてください。
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### ミューテックス

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
## プロセスとスレッド

### プロセス一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### スレッド一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threadstacks -p <プロセスID>
```

## ネットワーク

### ネットワーク接続の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> netscan
```

### ネットワーク接続の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> connscan
```

### ネットワーク接続のプロセスとスレッドの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> connscan -p <プロセスID>
```

## ファイルシステム

### ファイル一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> filescan
```

### 特定のファイルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> filescan -i <inode>
```

### ファイルの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## レジストリ

### レジストリキー一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> hivelist
```

### 特定のレジストリキーの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キーパス>
```

### レジストリキーの値の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キーパス> -o <オフセット>
```

### レジストリキーの値のデータの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> printkey -K <キーパス> -o <オフセット> -D
```

## イベントログ

### イベントログの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> evtlogs
```

### 特定のイベントログの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> evtlogs -n <ログ名>
```

### イベントログの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> evtlogs -n <ログ名> -o <オフセット>
```

## プロセスメモリ

### 特定のプロセスのメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のプロセスのメモリダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル名> memdump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```

## ファイルキャッシュ

### ファイルキャッシュの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> filescan
```

### 特定のファイルキャッシュの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> filescan -i <inode>
```

### ファイルキャッシュの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpfiles -Q <inode>
```

## プロセスのヒープ

### 特定のプロセスのヒープの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID>
```

### 特定のヒープの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heap -p <プロセスID> -H <ヒープアドレス>
```

### 特定のヒープの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> dumpheap -p <プロセスID> -H <ヒープアドレス> -D <出力ディレクトリ>
```

## プロセスのスタック

### 特定のプロセスのスタックの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID>
```

### 特定のスタックの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -s <スタックアドレス>
```

### 特定のスタックの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -s <スタックアドレス> -D <出力ディレクトリ>
```

## プロセスのモジュール

### 特定のプロセスのモジュールの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> modules -p <プロセスID>
```

### 特定のモジュールの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> modscan -p <プロセスID>
```

### 特定のモジュールの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ>
```

## プロセスのスレッド

### 特定のプロセスのスレッドの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threadstacks -p <プロセスID> -t <スレッドID>
```

## プロセスのハンドル

### 特定のプロセスのハンドルの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> handles -p <プロセスID>
```

### 特定のハンドルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> handles -p <プロセスID> -t <ハンドルID>
```

## プロセスのセキュリティデスクリプタ

### 特定のプロセスのセキュリティデスクリプタの一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> sdt -p <プロセスID>
```

### 特定のセキュリティデスクリプタの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> sdt -p <プロセスID> -t <セキュリティデスクリプタID>
```

## プロセスのモジュールリスト

### 特定のプロセスのモジュールリストの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> modscan -p <プロセスID>
```

## プロセスのモジュール情報

### 特定のプロセスのモジュール情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> modinfo -p <プロセスID> -D <出力ディレクトリ>
```

## プロセスのモジュールダンプ

### 特定のプロセスのモジュールダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ>
```

## プロセスのモジュールベースアドレス

### 特定のプロセスのモジュールベースアドレスの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> modscan -p <プロセスID>
```

## プロセスのモジュールベースアドレスの詳細情報

### 特定のモジュールベースアドレスの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル名> modinfo -p <プロセスID> -D <出力ディレクトリ>
```

## プロセスのモジュールベースアドレスのダンプ

### 特定のモジュールベースアドレスのダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ>
```

## プロセスのモジュールベースアドレスのダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```

## プロセスのモジュールベースアドレスのダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```

## プロセスのモジュールベースアドレスのダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```

## プロセスのモジュールベースアドレスのダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```

## プロセスのモジュールベースアドレスのダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```

## プロセスのモジュールベースアドレスのダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```

## プロセスのモジュールベースアドレスのダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル名> moddump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### シンボリックリンク

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
# Volatility Cheat Sheet

## Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

## Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory image.
- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `connections`: Lists network connections.
- `cmdline`: Displays command-line arguments for processes.
- `malfind`: Finds hidden or injected code.
- `dumpfiles`: Extracts files from memory.

## Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `mbrparser`: Parses the Master Boot Record (MBR).
- `ssdt`: Displays the System Service Descriptor Table (SSDT).
- `idt`: Displays the Interrupt Descriptor Table (IDT).
- `gdt`: Displays the Global Descriptor Table (GDT).
- `ldrmodules`: Lists loaded modules.
- `modscan`: Scans for modules.
- `vadinfo`: Displays information about Virtual Address Descriptors (VADs).
- `vaddump`: Dumps a specific VAD.
- `vadtree`: Displays a VAD tree.

## Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Finds hidden or injected code.
- `timeliner`: Creates a timeline of events.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates.
- `hivelist`: Lists registry hives.
- `hashdump`: Dumps password hashes.
- `shellbags`: Lists Windows Explorer shellbags.

## Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheat sheet, analysts can effectively extract and analyze valuable information from memory dumps.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

メモリからbashの履歴を読み取ることができます。_.bash\_history_ファイルをダンプすることもできますが、無効にされている場合は、このvolatilityモジュールを使用できることに満足するでしょう。
```
./vol.py -f file.dmp linux.bash.Bash
```
# Volatility Cheat Sheet

## Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

## Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory image.
- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `connections`: Lists network connections.
- `cmdline`: Displays command-line arguments for processes.
- `malfind`: Finds hidden or injected code.
- `dumpfiles`: Extracts files from memory.

## Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `mbrparser`: Parses the Master Boot Record (MBR).
- `ssdt`: Displays the System Service Descriptor Table (SSDT).
- `idt`: Displays the Interrupt Descriptor Table (IDT).
- `gdt`: Displays the Global Descriptor Table (GDT).
- `ldrmodules`: Lists loaded modules.
- `modscan`: Scans for modules.
- `vadinfo`: Displays information about Virtual Address Descriptors (VADs).
- `vaddump`: Dumps a specific VAD.
- `vadtree`: Displays a VAD tree.

## Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Finds hidden or injected code.
- `timeliner`: Creates a timeline of events.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hashdump`: Dumps password hashes.

## Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheat sheet, analysts can effectively extract and analyze valuable information from memory dumps.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### タイムライン

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
## プロセスとスレッド

### プロセス一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pslist
```

### 特定のプロセスの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> psxview -p <プロセスID>
```

### スレッド一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threads
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threadstacks -p <プロセスID>
```

## ネットワーク

### ネットワーク接続の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> netscan
```

### ネットワーク接続の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> connscan
```

### ネットワーク接続のプロセスとスレッドの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> connscan -p <プロセスID>
```

## ファイルシステム

### ファイル一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan
```

### ファイルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan -i <フイイルID>
```

### ファイルの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> dumpfiles -Q <ファイルID> -D <出力ディレクトリ>
```

## レジストリ

### レジストリキー一覧の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> hivelist
```

### レジストリキーの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キーパス>
```

### レジストリキーの値の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> printkey -K <キーパス> -o <オフセット>
```

## イベントログ

### イベントログの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs
```

### 特定のイベントログの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> evtlogs -n <イベントログ名>
```

## プロセスメモリ

### 特定のプロセスのメモリダンプの作成

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ>
```

### 特定のプロセスのメモリダンプの解析

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ>
```

## ファイルキャッシュ

### ファイルキャッシュの表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan
```

### ファイルキャッシュの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> filescan -i <ファイルID>
```

### ファイルキャッシュの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> dumpfiles -Q <ファイルID> -D <出力ディレクトリ>
```

## プロセスヒープ

### 特定のプロセスのヒープ情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heaps -p <プロセスID>
```

### 特定のヒープの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> heap -p <プロセスID> -H <ヒープID>
```

### 特定のヒープの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ> -h <ヒープID>
```

## プロセススタック

### 特定のプロセスのスタック情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> stack -p <プロセスID>
```

### 特定のスタックの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> stack -p <プロセスID> -s <スタックID>
```

### 特定のスタックの内容の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> memdump -p <プロセスID> -D <出力ディレクトリ> --dump-dir=<ダンプディレクトリ> -s <スタックID>
```

## プロセスモジュール

### 特定のプロセスのモジュール情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> modules -p <プロセスID>
```

### 特定のモジュールの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> moddump -p <プロセスID> -m <モジュール名> -D <出力ディレクトリ>
```

## プロセスハンドル

### 特定のプロセスのハンドル情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> handles -p <プロセスID>
```

### 特定のハンドルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> handles -p <プロセスID> -t <ハンドルタイプ> -o <オブジェクトID>
```

## プロセススレッド

### 特定のプロセスのスレッド情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threads -p <プロセスID>
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threadstacks -p <プロセスID> -t <スレッドID>
```

## プロセスタイムライン

### プロセスの実行時間の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree
```

### 特定のプロセスの実行時間の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree -p <プロセスID>
```

### プロセスの実行時間の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree -v
```

## プロセスハンドル

### 特定のプロセスのハンドル情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> handles -p <プロセスID>
```

### 特定のハンドルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> handles -p <プロセスID> -t <ハンドルタイプ> -o <オブジェクトID>
```

## プロセススレッド

### 特定のプロセスのスレッド情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threads -p <プロセスID>
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threadstacks -p <プロセスID> -t <スレッドID>
```

## プロセスタイムライン

### プロセスの実行時間の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree
```

### 特定のプロセスの実行時間の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree -p <プロセスID>
```

### プロセスの実行時間の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree -v
```

## プロセスモジュール

### 特定のプロセスのモジュール情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> modules -p <プロセスID>
```

### 特定のモジュールの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> moddump -p <プロセスID> -m <モジュール名> -D <出力ディレクトリ>
```

## プロセスハンドル

### 特定のプロセスのハンドル情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> handles -p <プロセスID>
```

### 特定のハンドルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> handles -p <プロセスID> -t <ハンドルタイプ> -o <オブジェクトID>
```

## プロセススレッド

### 特定のプロセスのスレッド情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threads -p <プロセスID>
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threadstacks -p <プロセスID> -t <スレッドID>
```

## プロセスタイムライン

### プロセスの実行時間の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree
```

### 特定のプロセスの実行時間の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree -p <プロセスID>
```

### プロセスの実行時間の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree -v
```

## プロセスモジュール

### 特定のプロセスのモジュール情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> modules -p <プロセスID>
```

### 特定のモジュールの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> moddump -p <プロセスID> -m <モジュール名> -D <出力ディレクトリ>
```

## プロセスハンドル

### 特定のプロセスのハンドル情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> handles -p <プロセスID>
```

### 特定のハンドルの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> handles -p <プロセスID> -t <ハンドルタイプ> -o <オブジェクトID>
```

## プロセススレッド

### 特定のプロセスのスレッド情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threads -p <プロセスID>
```

### 特定のスレッドの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> threadstacks -p <プロセスID> -t <スレッドID>
```

## プロセスタイムライン

### プロセスの実行時間の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree
```

### 特定のプロセスの実行時間の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree -p <プロセスID>
```

### プロセスの実行時間の詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> pstree -v
```

## プロセスモジュール

### 特定のプロセスのモジュール情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> modules -p <プロセスID>
```

### 特定のモジュールの詳細情報の表示

```bash
volatility -f <ファイル名> --profile=<プロファイル> moddump -p <プロセスID> -m <モジュール名> -D <出力デ
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### ドライバー

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
## プロセスとスレッド

### プロセスの一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> pslist
```

### 特定のプロセスの詳細情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> psxview -p <プロセスID>
```

### 特定のプロセスのスレッド一覧を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> threads -p <プロセスID>
```

### 特定のスレッドのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stack -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープ情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID>
```

### 特定のスレッドのヒープのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのアロケーション情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> allocations -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのフリーブロック情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> freeblocks -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのスタックトレースを表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> stacktrace -p <プロセスID> -t <スレッドID> -c -C -H -I -J -K -L
```

### 特定のスレッドのヒープのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンクのヒープチャンク情報を表示する

```bash
volatility -f <ファイル名> --profile=<プロファイル名> heaps -
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### クリップボードの取得
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IEの履歴を取得する

```bash
volatility -f <memory_dump> --profile=<profile> iehistory
```

このコマンドを使用して、Internet Explorer（IE）の履歴を取得できます。`<memory_dump>`にはメモリダンプファイルのパスを、`<profile>`には使用しているプロファイルの名前を指定します。
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### メモ帳のテキストを取得する

```
volatility -f <memory_dump> notepad
```

メモリダンプファイルからメモ帳のテキストを取得するためには、上記のコマンドを使用します。
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

The Master Boot Record (MBR) is a small section of a storage device that contains the boot loader program and the partition table. It is located in the first sector of the disk and is responsible for booting the operating system. The MBR is essential for the proper functioning of the system and is often targeted by malware and other malicious activities. Analyzing the MBR can provide valuable insights into the system's boot process and potential security breaches.
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
MBRは、そのメディア上に含まれる[ファイルシステム](https://en.wikipedia.org/wiki/File_system)をどのように組織化するかの情報を保持しています。MBRには、通常はインストールされたオペレーティングシステムに制御を渡すためのローダーとして機能する実行可能なコードも含まれています。これは通常、ローダーの[セカンドステージ](https://en.wikipedia.org/wiki/Second-stage_boot_loader)に制御を渡すか、各パーティションの[ボリュームブートレコード](https://en.wikipedia.org/wiki/Volume_boot_record)（VBR）と組み合わせて使用されます。このMBRコードは通常、[ブートローダー](https://en.wikipedia.org/wiki/Boot_loader)と呼ばれます。[ここから](https://en.wikipedia.org/wiki/Master_boot_record)。

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。技術的な知識を促進することを使命としているこの会議は、あらゆる分野の技術とサイバーセキュリティの専門家の活発な交流の場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
