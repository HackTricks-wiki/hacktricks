# macOSの起動/環境制約

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**
*
* .

</details>

## 基本情報

macOSの起動制約は、**プロセスの開始方法、実行者、および場所を制御**することでセキュリティを強化するために導入されました。macOS Venturaで導入され、システムバイナリを異なる制約カテゴリに分類する**信頼キャッシュ**内で定義される制約フレームワークを提供します。これらの制約はシステム内のすべての実行可能バイナリに適用され、特定のバイナリを起動するための要件を規定する**ルール**のセットを含みます。これらのルールには、バイナリが満たす必要がある自己制約、親プロセスが満たす必要がある親制約、および他の関連エンティティが守る必要がある責任制約が含まれます。

このメカニズムは、macOS Sonomaからはサードパーティのアプリにも**環境制約**を適用することができます。これにより、開発者はアプリを保護するために**環境制約のキーと値のセット**を指定することができます。

起動環境とライブラリの制約は、**`launchd`プロパティリストファイル**に保存するか、**コードサイニングで使用する別のプロパティリスト**ファイルに保存します。

制約には4つのタイプがあります：

* **自己制約**：**実行中の**バイナリに適用される制約。
* **親プロセス制約**：**プロセスの親**に適用される制約（たとえば、**`launchd`**がXPサービスを実行している場合）。
* **責任制約**：XPC通信でサービスを呼び出す**プロセスに適用**される制約。
* **ライブラリロード制約**：ロードできるコードを選択的に記述するためにライブラリロード制約を使用します。

したがって、プロセスが別のプロセスを起動しようとする場合（`execve(_:_:_:)`または`posix_spawn(_:_:_:_:_:_:)`を呼び出すことによって）、オペレーティングシステムは**実行可能ファイルが自己制約を満たしているかどうか**をチェックします。また、**親プロセスの実行可能ファイルが実行可能ファイルの親制約を満たしているか**、および**責任プロセスの実行可能ファイルが実行可能ファイルの責任制約を満たしているか**をチェックします。これらの起動制約のいずれかが満たされていない場合、オペレーティングシステムはプログラムを実行しません。

ライブラリをロードする際に、ライブラリ制約の**いずれかの部分が真ではない**場合、プロセスはライブラリを**ロードしません**。

## LCカテゴリ

LCは、**事実**と**論理演算**（and、orなど）から構成されるもので、事実を組み合わせます。

[**LCが使用できる事実は文書化されています**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints)。例えば：

* is-init-proc：実行可能ファイルがオペレーティングシステムの初期化プロセス（`launchd`）であるかどうかを示すブール値。
* is-sip-protected：実行可能ファイルがSystem Integrity Protection（SIP）によって保護されたファイルであるかどうかを示すブール値。
* `on-authorized-authapfs-volume:`：オペレーティングシステムが認可された、認証済みのAPFSボリュームから実行可能ファイルをロードしたかどうかを示すブール値。
* `on-authorized-authapfs-volume`：オペレーティングシステムが認可された、認証済みのAPFSボリュームから実行可能ファイルをロードしたかどうかを示すブール値。
* Cryptexesボリューム
* `on-system-volume:`：オペレーティングシステムが現在起動しているシステムボリュームから実行可能ファイルをロードしたかどうかを示すブール値。
* /System内部...
* ...

Appleのバイナリが署名されると、それは**信頼キャッシュ**内の**LCカテゴリ**に割り当てられます。

* **iOS 16のLCカテゴリ**は[**ここで逆向きにドキュメント化されています**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。
* 現在の**LCカテゴリ（macOS 14** - Somona）は逆向きになっており、[**ここで説明が見つかります**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。

たとえば、カテゴリ1は：
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: システムまたはCryptexesボリュームにある必要があります。
* `launch-type == 1`: システムサービスである必要があります（LaunchDaemons内のplist）。
* `validation-category == 1`: オペレーティングシステムの実行可能ファイルです。
* `is-init-proc`: Launchd

### LCカテゴリの逆向き解析

詳細については[こちら](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints)を参照してくださいが、基本的にはこれらは**AMFI（AppleMobileFileIntegrity）**で定義されているため、**KEXT**を取得するためにカーネル開発キットをダウンロードする必要があります。**`kConstraintCategory`**で始まるシンボルが興味深いものです。これらを抽出すると、デコードする必要があるDER（ASN.1）エンコードされたストリームが得られます。[ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php)またはpython-asn1ライブラリとその`dump.py`スクリプト、[andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master)を使用して、より理解しやすい文字列を取得できます。

## 環境制約

これらは**サードパーティのアプリケーション**で設定された起動制約です。開発者は、アプリケーションへのアクセスを制限するために、自身のアプリケーションで使用する**事実**と**論理演算子**を選択できます。

アプリケーションの環境制約を列挙することが可能です。
```bash
codesign -d -vvvv app.app
```
## 信頼キャッシュ

**macOS**にはいくつかの信頼キャッシュがあります：

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

そして、iOSでは**`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**にあるようです。

### 信頼キャッシュの列挙

前述の信頼キャッシュファイルは、**IMG4**および**IM4P**形式です。IM4PはIMG4形式のペイロードセクションです。

[**pyimg4**](https://github.com/m1stadev/PyIMG4)を使用してデータベースのペイロードを抽出できます：

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

（別のオプションとして、[**img4tool**](https://github.com/tihmstar/img4tool)というツールを使用することもできます。このツールは、リリースが古く、x86\_64向けのものであっても、M1でも実行されます。ただし、適切な場所にインストールする必要があります）。

これで、ツール[**trustcache**](https://github.com/CRKatri/trustcache)を使用して、情報を読みやすい形式で取得できます：
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
信頼キャッシュは以下の構造に従います。したがって、**LCカテゴリは4番目の列です**。
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
次に、[**このスクリプト**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)のようなものを使用してデータを抽出することができます。

そのデータから、**`0`の起動制約値を持つアプリ**をチェックできます。これは制約されていないアプリです（各値の詳細については[**こちら**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)を参照）。

## 攻撃の緩和策

起動制約は、古い攻撃を緩和するためにいくつかの攻撃を防ぎます。例えば、予期しない場所からの実行や予期しない親プロセスによる呼び出し（launchdだけが起動するはずの場合）を防ぎます。

さらに、起動制約はダウングレード攻撃も緩和します。

ただし、一般的なXPCの乱用、Electronのコードインジェクション、ライブラリの検証が行われていないdylibインジェクション（ライブラリをロードできるチームIDが既知の場合を除く）は緩和されません。

### XPCデーモンの保護

この執筆時点（Sonomaリリース）では、デーモンXPCサービスの**責任あるプロセスはXPCサービス自体**であり、接続するクライアントではありません（FB: FB13206884を提出）。一瞬バグだと仮定しても、私たちは**攻撃者のコードでXPCサービスを起動することはできません**が、それが**既にアクティブ**である場合（元のアプリによって呼び出された可能性があるため）、接続することを防ぐものは何もありません。したがって、制約を設定することは良い考えかもしれませんし、攻撃の時間枠を制限することもできますが、それは主要な問題を解決するものではなく、私たちのXPCサービスは依然として接続するクライアントを適切に検証する必要があります。それが唯一のセキュリティ確保方法です。また、最初に述べたように、現在はこの方法では機能しません。

### Electronの保護

アプリケーションが**LaunchServiceによって開かれる必要がある**（親の制約で）。これは**`open`**を使用することで実現できます（環境変数を設定できます）または**Launch Services API**を使用することで実現できます（環境変数を指定できます）。

## 参考文献

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**
*
* .

</details>
