# macOS Launch/Environment Constraints & Trust Cache

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>から<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong>！</summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* **💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングトリックを共有するには、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください**
*
* .

</details>

## 基本情報

macOSの起動制約は、**プロセスの開始方法、誰が、どこからプロセスを開始できるか**を規制することでセキュリティを強化するために導入されました。macOS Venturaで開始され、**各システムバイナリを異なる制約カテゴリに分類**するフレームワークを提供し、それらは**信頼キャッシュ**内に定義されたシステムバイナリとそれらのハッシュを含むリストを含みます。これらの制約は、システム内のすべての実行可能なバイナリに適用され、特定のバイナリを起動するための**要件を明確にする**一連の**ルール**を含みます。これらのルールには、バイナリが満たす必要がある自己制約、親プロセスが満たす必要がある親制約、および他の関連エンティティが守る必要がある責任制約が含まれます。

このメカニズムは、macOS Sonomaから始まる**環境制約**を通じてサードパーティのアプリケーションにも拡張され、開発者が**環境制約のためのキーと値のセット**を指定することでアプリを保護できるようになりました。

**起動環境とライブラリ制約**を定義するには、**`launchd`プロパティリストファイル**に保存するか、**コードサイニングで使用する別個のプロパティリスト**ファイルに保存します。

制約には4種類あります：

* **自己制約**：**実行中の**バイナリに適用される制約。
* **親プロセス**：プロセスの**親に適用される**制約（たとえば**`launchd`**がXPサービスを実行している場合）。
* **責任制約**：XPC通信でサービスを呼び出すプロセスに適用される制約。
* **ライブラリロード制約**：ロードできるコードを選択的に記述するためにライブラリロード制約を使用します。

したがって、プロセスが別のプロセスを起動しようとする場合（`execve(_:_:_:)`または`posix_spawn(_:_:_:_:_:_:)`を呼び出すことにより）、オペレーティングシステムは**実行可能ファイルが自己制約を満たしているかどうか**をチェックします。また、**親プロセスの実行可能ファイルが実行可能ファイルの親制約を満たしているか**、および**責任プロセスの実行可能ファイルが実行可能ファイルの責任プロセス制約を満たしているか**をチェックします。これらの起動制約のいずれかが満たされていない場合、オペレーティングシステムはプログラムを実行しません。

ライブラリをロードする際に**ライブラリ制約の一部が真でない**場合、プロセスは**ライブラリをロードしません**。

## LCカテゴリ

LCは**事実**と**論理演算**（and、orなど）で構成され、事実を組み合わせます。

[**LCが使用できる事実は文書化されています**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints)。例：

* is-init-proc：実行可能ファイルがオペレーティングシステムの初期化プロセス（`launchd`）である必要があるかどうかを示すブール値。
* is-sip-protected：System Integrity Protection（SIP）によって保護されたファイルである必要があるかどうかを示すブール値。
* `on-authorized-authapfs-volume:`：オペレーティングシステムが認証されたAPFSボリュームから実行可能ファイルを読み込んだかどうかを示すブール値。
* `on-authorized-authapfs-volume`：オペレーティングシステムが認証されたAPFSボリュームから実行可能ファイルを読み込んだかどうかを示すブール値。
* Cryptexesボリューム
* `on-system-volume:`：オペレーティングシステムが現在起動しているシステムボリュームから実行可能ファイルを読み込んだかどうかを示すブール値。
* /System内部...
* ...

Appleバイナリが署名されると、**信頼キャッシュ**内の**LCカテゴリ**に割り当てられます。

* **iOS 16 LCカテゴリ**は[**こちらで逆アセンブルされ文書化されています**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。
* 現在の**LCカテゴリ（macOS 14** - Somona）は逆アセンブルされ、[**こちらで説明が見つかります**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。

たとえば、カテゴリ1は：
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: システムまたはCryptexesボリューム内にある必要があります。
* `launch-type == 1`: システムサービスである必要があります（LaunchDaemons内のplist）。
* `validation-category == 1`: オペレーティングシステムの実行可能ファイルです。
* `is-init-proc`: Launchd

### LCカテゴリの逆変換

詳細は[**こちら**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints)にありますが、基本的に、これらは**AMFI（AppleMobileFileIntegrity）**で定義されているため、**KEXT**を取得するためにKernel Development Kitをダウンロードする必要があります。 **`kConstraintCategory`**で始まるシンボルが**興味深い**ものです。 これらを抽出すると、ASN.1でエンコードされたストリームが得られます。これを[ASN.1デコーダ](https://holtstrom.com/michael/tools/asn1decoder.php)またはpython-asn1ライブラリとその`dump.py`スクリプト、[andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master)を使用してデコードする必要があります。これにより、より理解しやすい文字列が得られます。

## 環境制約

これらは**サードパーティアプリケーション**で構成されたLaunch Constraintsです。 開発者は、自分のアプリケーションへのアクセスを制限するために使用する**事実**と**論理演算子**を選択できます。

アプリケーションの環境制約を列挙することが可能です。
```bash
codesign -d -vvvv app.app
```
## 信頼キャッシュ

**macOS** にはいくつかの信頼キャッシュがあります:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

iOSでは、**`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** にあるようです。

{% hint style="warning" %}
Apple Silicon デバイスで実行されている macOS では、Apple が署名したバイナリが信頼キャッシュに含まれていない場合、AMFI はそのバイナリの読み込みを拒否します。
{% endhint %}

### 信頼キャッシュの列挙

前述の信頼キャッシュファイルは **IMG4** および **IM4P** 形式であり、IM4P は IMG4 形式のペイロードセクションです。

[**pyimg4**](https://github.com/m1stadev/PyIMG4) を使用してデータベースのペイロードを抽出できます:

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

（別のオプションとして、[**img4tool**](https://github.com/tihmstar/img4tool) ツールを使用することもできます。このツールは、リリースが古く、x86\_64 用に適切な場所にインストールされていれば、M1 でも実行されます）。

今、[**trustcache**](https://github.com/CRKatri/trustcache) ツールを使用して、情報を読みやすい形式で取得できます：
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
信頼キャッシュは以下の構造に従いますので、**LCカテゴリは4番目の列です**。
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
次に、[**このスクリプト**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)などを使用してデータを抽出できます。

そのデータから、**`0`の起動制約値を持つアプリ**をチェックできます。これは制約されていないものです（各値については[**こちら**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)を参照）。

## 攻撃緩和

起動制約は、**プロセスが予期しない状況で実行されないようにすることで**、いくつかの古い攻撃を緩和していました。たとえば、予期しない場所からの起動や予期しない親プロセスによる起動（launchdだけが起動すべき場合）などです。

さらに、起動制約は**ダウングレード攻撃を緩和**します。

ただし、これらは**一般的なXPC**の悪用、**Electron**コードの挿入、ライブラリの検証なしでの**dylibの挿入**（ライブラリを読み込むことができるチームIDがわかっている場合を除く）を緩和しません。

### XPCデーモン保護

Sonomaリリースでは、デーモンXPCサービスの**責任構成**が注目されます。XPCサービスは、接続するクライアントが責任を負うのではなく、自己責任を負います。これはフィードバックレポートFB13206884に記載されています。この設定は欠陥のように見えるかもしれませんが、次のようなXPCサービスとの相互作用を許可します：

- **XPCサービスの起動**：バグと仮定される場合、この設定では攻撃者コードを介してXPCサービスを起動することは許可されません。
- **アクティブサービスへの接続**：XPCサービスが既に実行中の場合（おそらく元のアプリケーションによってアクティブ化された場合）、接続に障壁はありません。

XPCサービスに制約を実装することで、**潜在的な攻撃の余地を狭める**ことができますが、主要な懸念には対処できません。XPCサービスのセキュリティを確保するには、接続するクライアントを効果的に**検証する**ことが不可欠です。これがサービスのセキュリティを強化する唯一の方法です。また、言及された責任構成が現在稼働していることに留意する価値がありますが、これは意図された設計と一致しない可能性があります。


### Electron保護

アプリケーションが**親の制約でLaunchServiceによって開かれる必要がある**場合でも、これは**`open`**（環境変数を設定できる）を使用するか、**Launch Services API**（環境変数を指定できる）を使用して達成できます。

## 参考文献

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>こちら</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを発見
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れる
* **💬**[**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングトリックを共有するには、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **および**[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください**
*
* .

</details>
