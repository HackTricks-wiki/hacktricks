# macOS MDM

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>で学ぶ！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェック！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**でフォローする 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

**macOS MDMについて学ぶ:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基本

### **MDM（モバイルデバイス管理）概要**

[モバイルデバイス管理](https://en.wikipedia.org/wiki/Mobile\_device\_management)（MDM）は、スマートフォン、ノートパソコン、タブレットなどのさまざまなエンドユーザーデバイスを管理するために使用されます。特にAppleのプラットフォーム（iOS、macOS、tvOS）では、専門機能、API、およびプラクティスが関与します。MDMの操作は、商用またはオープンソースの互換性のあるMDMサーバーに依存し、[MDMプロトコル](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)をサポートする必要があります。主なポイントは次のとおりです：

- デバイスに対する集中制御
- MDMプロトコルに準拠するMDMサーバーへの依存
- MDMサーバーが、リモートデータ消去や構成のインストールなど、さまざまなコマンドをデバイスに送信できる能力

### **DEP（デバイス登録プログラム）の基本**

Appleが提供する[デバイス登録プログラム](https://www.apple.com/business/site/docs/DEP\_Guide.pdf)（DEP）は、iOS、macOS、tvOSデバイスのゼロタッチ構成を容易にすることで、モバイルデバイス管理（MDM）の統合を効率化します。DEPは登録プロセスを自動化し、デバイスを箱から出してすぐに使用できるようにし、ユーザーまたは管理者の介入を最小限に抑えます。主な側面は次のとおりです：

- デバイスが初めてアクティブ化されるときに事前定義されたMDMサーバーに自動的に登録できるようにする
- 新しいデバイスに特に有益ですが、再構成中のデバイスにも適用できます
- 簡単なセットアップを容易にし、デバイスを組織での使用にすばやく準備させます

### **セキュリティに関する考慮事項**

DEPによる簡単な登録は有益ですが、適切な保護措置がMDM登録に適切に施されていない場合、攻撃者はこの簡略化されたプロセスを利用して、企業のMDMサーバーに自分のデバイスを登録し、法人デバイスとして偽装する可能性があります。

{% hint style="danger" %}
**セキュリティアラート**: 簡略化されたDEP登録は、適切な保護措置が施されていない場合、組織のMDMサーバーに認可されていないデバイスの登録を許可する可能性があります。
{% endhint %}

### **SCEP（Simple Certificate Enrolment Protocol）とは**

- TLSやHTTPSが普及する前に作成された比較的古いプロトコル
- クライアントに証明書署名リクエスト（CSR）を送信し、証明書を取得するための標準化された方法を提供
- クライアントはサーバーに署名された証明書を要求します

### **構成プロファイルとは（モバイル構成ファイルとも呼ばれる）**

- Appleの公式方法で**システム構成を設定/強制**する
- 複数のペイロードを含むファイル形式
- プロパティリスト（XMLタイプ）に基づく
- 「起源を検証し、整合性を確保し、内容を保護するために署名と暗号化できます。」Basics — Page 70, iOS Security Guide, January 2018.

## プロトコル

### MDM

- APNs（**Appleサーバー**）+ RESTful API（**MDMベンダーサーバー**）の組み合わせ
- **デバイス**と**デバイス管理製品**に関連するサーバー間で**通信**が行われる
- MDMからデバイスへの**コマンド**は**plistエンコードされた辞書**で配信される
- すべて**HTTPS**経由。MDMサーバーは（通常）ピン留めされています。
- AppleはMDMベンダーに**APNs証明書**を認証するために提供します

### DEP

- **3つのAPI**：販売業者用1つ、MDMベンダー用1つ、デバイス識別用1つ（未公開）：
- いわゆる[DEP「クラウドサービス」API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。これは、MDMサーバーがDEPプロファイルを特定のデバイスに関連付けるために使用されます。
- [Apple認定販売業者が使用するDEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)は、デバイスの登録、登録状況の確認、トランザクション状況の確認に使用されます。
- 未公開のプライベートDEP API。これはAppleデバイスがDEPプロファイルをリクエストするために使用されます。macOSでは、`cloudconfigurationd`バイナリがこのAPIを介して通信を行います。
- より現代的で**JSON**ベース（plistとは異なる）
- AppleはMDMベンダーに**OAuthトークン**を提供します

**DEP「クラウドサービス」API**

- RESTful
- AppleからMDMサーバーにデバイスレコードを同期
- MDMサーバーからAppleに「DEPプロファイル」を同期（後でデバイスに提供されます）
- DEP「プロファイル」には次が含まれます：
- MDMベンダーサーバーのURL
- サーバーURLの追加信頼された証明書（オプションのピン留め）
- その他の設定（例：Setup Assistantでスキップする画面）

## シリアル番号

2010年以降に製造されたAppleデバイスは、一般的に**12文字の英数字**のシリアル番号を持ち、**最初の3桁は製造場所**を表し、次の**2桁は製造年**と**週**を示し、次の**3桁は一意の識別子**を提供し、**最後の4桁はモデル番号**を表します。

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 登録および管理手順

1. デバイスレコードの作成（販売業者、Apple）：新しいデバイスのレコードが作成されます
2. デバイスレコードの割り当て（顧客）：デバイスがMDMサーバーに割り当てられます
3. デバイスレコードの同期（MDMベンダー）：MDMはデバイスレコードを同期し、DEPプロファイルをAppleにプッシュします
4. DEPチェックイン（デバイス）：デバイスがDEPプロファイルを取得します
5. プロファイルの取得（デバイス）
6. プロファイルのインストール（デバイス） a. MDM、SCEP、およびルートCAペイロードを含む
7. MDMコマンドの発行（デバイス）

![](<../../../.gitbook/assets/image (694).png>)

ファイル`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`は、登録プロセスの**高レベルな「ステップ」**と見なすことができる関数をエクスポートします。
### ステップ4: DEPチェックイン - アクティベーションレコードの取得

このプロセスのこの部分は、**ユーザーがMacを初めて起動**したとき（または完全に消去した後）

![](<../../../.gitbook/assets/image (1044).png>)

または`sudo profiles show -type enrollment`を実行したときに発生します

* **デバイスがDEP対応かどうか**を判断する
* アクティベーションレコードはDEPの「プロファイル」の内部名です
* デバイスがインターネットに接続されるとすぐに開始されます
* **`CPFetchActivationRecord`**によって駆動されます
* **`cloudconfigurationd`**によって実装され、XPCを介して行われます。デバイスが最初に起動されるときの**「セットアップアシスタント」**または**`profiles`**コマンドは、このデーモンにアクティベーションレコードを取得するように連絡します。
* LaunchDaemon（常にrootとして実行）

**`MCTeslaConfigurationFetcher`**によって実行されるアクティベーションレコードの取得には、**Absinthe**と呼ばれる暗号化が使用されます

1. **証明書を取得**
1. [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)を取得
2. 証明書から状態を**初期化**（**`NACInit`**）
1. **`IOKit`**を介したデバイス固有のデータを使用します（たとえば、**シリアル番号**）
3. **セッションキーを取得**
1. [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)にPOST
4. セッションを確立（**`NACKeyEstablishment`**）
5. リクエストを作成
1. `{ "action": "RequestProfileConfiguration", "sn": "" }`というデータを送信して[https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)にPOST
2. JSONペイロードはAbsintheを使用して暗号化されます（**`NACSign`**）
3. すべてのリクエストはHTTPs経由で行われ、組み込みのルート証明書が使用されます

![](<../../../.gitbook/assets/image (566) (1).png>)

応答は、次のような重要なデータを含むJSON辞書です：

* **url**：アクティベーションプロファイルのMDMベンダーホストのURL
* **anchor-certs**：信頼されるアンカーとして使用されるDER証明書の配列

### **ステップ5: プロファイルの取得**

![](<../../../.gitbook/assets/image (444).png>)

* DEPプロファイルで提供された**URL**にリクエストを送信します。
* **アンカー証明書**が提供された場合、**信頼性を評価**するために使用されます。
* リマインダー：DEPプロファイルの**anchor\_certs**プロパティ
* デバイス識別情報を含む、単純な.plist形式のリクエスト
* 例：**UDID、OSバージョン**。
* CMSで署名され、DERでエンコードされています
* **デバイス識別証明書（APNSから）**を使用して署名されています
* **証明書チェーン**には期限切れの**Apple iPhone Device CA**が含まれています

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### ステップ6: プロファイルのインストール

* 取得した後、**プロファイルはシステムに保存**されます
* このステップは自動的に開始されます（**セットアップアシスタント**にある場合）
* **`CPInstallActivationProfile`**によって駆動されます
* mdmclientによってXPCを介して実装されます
* LaunchDaemon（rootとして）またはLaunchAgent（ユーザーとして）、コンテキストに応じて異なります
* 構成プロファイルには複数のペイロードが含まれています
* フレームワークには、プロファイルをインストールするためのプラグインベースのアーキテクチャがあります
* 各ペイロードタイプはプラグインに関連付けられています
* XPC（フレームワーク内）またはクラシックなCocoa（ManagedClient.app内）になります
* 例：
* 証明書ペイロードはCertificateService.xpcを使用します

通常、MDMベンダーによって提供される**アクティベーションプロファイル**には、次のペイロードが含まれます：

* `com.apple.mdm`：デバイスをMDMに**登録**するため
* `com.apple.security.scep`：デバイスに**クライアント証明書**を安全に提供するため
* `com.apple.security.pem`：デバイスのシステムキーチェーンに**信頼されるCA証明書**を**インストール**するため
* MDMペイロードをインストールすることは、ドキュメントのMDMチェックインに相当します
* ペイロードには次の**主要なプロパティ**が含まれます：
*
* MDMチェックインURL（**`CheckInURL`**）
* MDMコマンドポーリングURL（**`ServerURL`**）+ トリガーするAPNsトピック
* MDMペイロードをインストールするには、**`CheckInURL`**にリクエストを送信します
* **`mdmclient`**で実装されています
* MDMペイロードは他のペイロードに依存する場合があります
* **リクエストを特定の証明書にピン留めする**ことができます：
* プロパティ：**`CheckInURLPinningCertificateUUIDs`**
* プロパティ：**`ServerURLPinningCertificateUUIDs`**
* PEMペイロードを介して配信されます
* デバイスに識別証明書を付与することができます：
* プロパティ：IdentityCertificateUUID
* SCEPペイロードを介して配信されます

### **ステップ7: MDMコマンドの受信**

MDMチェックインが完了すると、ベンダーはAPNsを使用して**プッシュ通知を発行**できます
受信後、**`mdmclient`**によって処理されます
MDMコマンドをポーリングするために、リクエストが**ServerURL**に送信されます
以前にインストールされたMDMペイロードを使用します：
リクエストをピン留めするための**`ServerURLPinningCertificateUUIDs`**、TLSクライアント証明書には**`IdentityCertificateUUID`**を使用します

## 攻撃

### 他の組織へのデバイス登録

以前にコメントしたように、組織にデバイスを登録しようとするためには、その組織に属する**シリアル番号**だけが必要です。デバイスが登録されると、複数の組織が新しいデバイスに機密データをインストールします：証明書、アプリケーション、WiFiパスワード、VPN構成など。\
したがって、登録プロセスが適切に保護されていない場合、これは攻撃者にとって危険なエントリーポイントとなり得ます:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**する。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
