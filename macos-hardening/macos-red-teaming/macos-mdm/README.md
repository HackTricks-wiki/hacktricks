# macOS MDM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有する**ために、[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## 基本

### MDM（モバイルデバイス管理）とは何ですか？

[モバイルデバイス管理](https://en.wikipedia.org/wiki/Mobile\_device\_management)（MDM）は、モバイル電話、ノートパソコン、デスクトップ、タブレットなどの**エンドユーザーコンピューティングデバイス**を管理するために一般的に使用される技術です。AppleのiOS、macOS、tvOSなどのプラットフォームの場合、特定の機能、API、および技術を指し、管理者がこれらのデバイスを管理するために使用します。MDMを介したデバイスの管理には、商用またはオープンソースの互換性のあるMDMサーバーが必要で、[MDMプロトコル](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)のサポートを実装しています。

* **集中的なデバイス管理**を実現する方法
* MDMプロトコルのサポートを実装した**MDMサーバー**が必要
* MDMサーバーは、リモートワイプや「この設定をインストールする」といったMDMコマンドを**デバイスに送信**できる

### 基本 DEP（デバイス登録プログラム）とは何ですか？

[デバイス登録プログラム](https://www.apple.com/business/site/docs/DEP\_Guide.pdf)（DEP）は、Appleが提供するサービスで、iOS、macOS、tvOSデバイスの**モバイルデバイス管理（MDM）登録**を**ゼロタッチ構成**で簡素化します。デバイスを構成するためにエンドユーザーまたは管理者がアクションを起こす必要がある従来の展開方法とは異なり、またはMDMサーバーに手動で登録する必要がある場合とは異なり、DEPはこのプロセスをブートストラップし、新しいAppleデバイスを開封してすぐに組織で使用できるようにします。

管理者はDEPを活用して、デバイスを組織のMDMサーバーに自動的に登録できます。デバイスが登録されると、多くの場合、組織が所有する「信頼された」デバイスとして扱われ、証明書、アプリケーション、WiFiパスワード、VPN設定などのいずれかの数を受け取ることができます。

* デバイスが**初めて電源を入れた**ときに自動的に事前に設定されたMDMサーバーに登録することができる
* デバイスが**新品**の場合に最も有用
* OSの新規インストールで**消去**された場合にも有用

{% hint style="danger" %}
残念ながら、組織がMDM登録を**保護するための追加の手順を踏んでいない**場合、DEPを介した簡素化されたエンドユーザーの登録プロセスは、攻撃者が組織のMDMサーバーに選択したデバイスを登録するための簡素化されたプロセスを意味することができます。
{% endhint %}

### 基本 SCEP（シンプル証明書登録プロトコル）とは何ですか？

* TLSとHTTPSが普及する前に作成された比較的古いプロトコル
* クライアントが証明書を取得するための**証明書署名リクエスト**（CSR）を送信するための標準化された方法を提供します。クライアントは、サーバーに署名された証明書を与えるように依頼します。

### 設定プロファイル（mobileconfigs）とは何ですか？

* Appleの公式な方法で、**システムの設定/強制**を行う方法です。
* 複数のペイロードを含むファイル形式です。
* プロパティリスト（XML形式）に基づいています。
* 「その起源を検証し、整合性を確保し、内容を保護するために署名と暗号化することができます。」Basics — Page 70, iOS Security Guide, January 2018.

## プロトコル

### MDM

* APNs（**Appleサーバー**）+ RESTful API（**MDMベンダーサーバー**）の組み合わせ
* **デバイス**と**デバイス管理**製品に関連するサーバー間の**通信**
* MDMからデバイスに**plistエンコードされた辞書**形式のコマンドを送信
* すべて**HTTPS**で行われます。MDMサーバーは（通常）ピン留めされています。
* AppleはMDMベンダーにAPNs証明書を発行します（認証に使用）

### DEP

* **3つのAPI**：リセラー用、MDMベンダー用、デバイスID用（非公開）：
* いわゆる[DEP「クラウドサービス」API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。これは、MDMサーバーがDEPプロファイルを特定のデバイスに関連付けるために使用されます。
* [Apple認定リセラーが使用するDEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)。デバイスの登録、登録状況の確認、トランザクション状況の確認に使用されます。
* 非公開のプライベートDEP API。これは、Appleデバイ
## シリアル番号

2010年以降に製造されたAppleデバイスは、一般的には**12文字の英数字のシリアル番号**を持ちます。最初の3桁は製造場所を表し、続く2桁は製造年と週を示し、次の3桁は一意の識別子を提供し、最後の4桁はモデル番号を表します。

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 登録と管理の手順

1. デバイスレコードの作成（販売業者、Apple）：新しいデバイスのレコードが作成されます。
2. デバイスレコードの割り当て（顧客）：デバイスがMDMサーバーに割り当てられます。
3. デバイスレコードの同期（MDMベンダー）：MDMはデバイスレコードを同期し、DEPプロファイルをAppleにプッシュします。
4. DEPチェックイン（デバイス）：デバイスがDEPプロファイルを取得します。
5. プロファイルの取得（デバイス）
6. プロファイルのインストール（デバイス）a. MDM、SCEP、およびルートCAのペイロードを含む
7. MDMコマンドの発行（デバイス）

![](<../../../.gitbook/assets/image (564).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`ファイルは、登録プロセスの**高レベルな「ステップ」**と見なすことができる関数をエクスポートしています。

### ステップ4：DEPチェックイン - アクティベーションレコードの取得

このプロセスのこの部分は、**ユーザーがMacを初めて起動**したとき（または完全なワイプ後）に発生します。

![](<../../../.gitbook/assets/image (568).png>)

または、`sudo profiles show -type enrollment`を実行したとき

* デバイスがDEP対応かどうかを判断する
* アクティベーションレコードは、DEPの「プロファイル」の内部名です。
* デバイスがインターネットに接続されるとすぐに開始されます。
* **`CPFetchActivationRecord`**によって駆動されます。
* **`cloudconfigurationd`**によって実装されます。デバイスが初めて起動されるときの**「セットアップアシスタント」**または**`profiles`**コマンドは、このデーモンに接触してアクティベーションレコードを取得します。
* LaunchDaemon（常にrootとして実行）

**`MCTeslaConfigurationFetcher`**によって実行されるアクティベーションレコードの取得には、**Absinthe**と呼ばれる暗号化が使用されます。

1. **証明書**の取得
1. [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)にGETリクエストを送信
2. 証明書から状態を**初期化**（**`NACInit`**）
1. **IOKit**を介したデバイス固有のデータ（例：**シリアル番号**）を使用
3. **セッションキー**の取得
1. [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)にPOSTリクエストを送信
4. セッションの確立（**`NACKeyEstablishment`**）
5. リクエストの作成
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)にデータ`{ "action": "RequestProfileConfiguration", "sn": "" }`を送信するPOSTリクエスト
2. JSONペイロードはAbsintheを使用して暗号化されます（**`NACSign`**）
3. すべてのリクエストはHTTPs経由で行われ、組み込みのルート証明書が使用されます

![](<../../../.gitbook/assets/image (566).png>)

応答は、以下のような重要なデータを含むJSON辞書です。

* **url**：アクティベーションプロファイルのMDMベンダーホストのURL
* **anchor-certs**：信頼されたアンカーとして使用されるDER証明書の配列

### **ステップ5：プロファイルの取得**

![](<../../../.gitbook/assets/image (567).png>)

* DEPプロファイルで提供された**URL**にリクエストが送信されます。
* **アンカー証明書**が提供された場合、信頼性を評価するために使用されます。
* リマインダー：DEPプロファイルの**anchor\_certs**プロパティ
* リクエストは、デバイスの識別情報（例：**UDID、OSバージョン**）を含む単純な.plistです。
* CMSで署名され、DERでエンコードされています。
* デバイスのアイデンティティ証明書（APNSから）を使用して署名されています。
* 証明書チェーンには、期限切れの**Apple iPhone Device CA**が含まれています。

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (7).png>)

### ステップ6：プロファイルのインストール

* 取得したプロファイルは、システムに保存されます。
* このステップは自動的に開始されます（**セットアップアシスタント**の場合）。
* **`CPInstallActivationProfile`**によって駆動されます。
* mdmclientを介して実装されます（XPCを使用）。
* LaunchDaemon（rootとして実行）またはLaunchAgent（ユーザーとして実行）によって実行される場合があります。
* 構成プロファイルには、複数のペイロードをインストールするためのプラグインベースのアーキテクチャがあります。
* 各ペイロードタイプはプラグインに関連付けられています。
* XPC（フレームワーク内）またはクラシックなCocoa（ManagedClient.app内）である場合があります。
* 例：
* 証明書ペイロードはCertificateService.xpcを使用します。

通常、MDMベンダーによって提供される**アクティベーションプロファイル**には、次のペイロードが含まれています。

* `com.apple.mdm`：デバイスをMDMに**登録**するためのもの
* `com.apple.security.scep`：デバイスに**クライアント証明書**を安全に提供するためのもの。
* `com.apple.security.pem`：デバイスのシステムキーチェーンに**信頼されたCA証明書**を**インストール**するためのもの。
* ドキュメントのMDMチェックインに相当するMDMペイロードのインストール
* ペイロードには以下のキーのプロパティが含まれます：
*
* MDMチェックインURL（**`CheckInURL`**）
* MDMコマンドポーリングURL（**`ServerURL`**）+ トリガーするためのAPNsトピック
* MDMペイロードをインストールするために、リクエストは**`CheckInURL`**に送信されます。
* **`mdmclient`**で実装されています。
* MDMペイロードは他のペイロードに依存することができます。
* 特定の証明書にリクエストを固定することができます：
* プロパティ：**`CheckInURLPinningCertificateUUIDs`**
* プロパティ：**`ServerURLPinningCertificateUUIDs`**
* PEMペイロードを介して配信されます
* デバイスにアイデンティテ
### **ステップ7: MDMコマンドの受信**

* MDMのチェックインが完了した後、ベンダーは**APNsを使用してプッシュ通知を発行**できる
* 受信後、**`mdmclient`**が処理する
* MDMコマンドをポーリングするために、ServerURLにリクエストが送信される
* 以前にインストールされたMDMペイロードを使用する:
* リクエストのピン留めには**`ServerURLPinningCertificateUUIDs`**を使用
* TLSクライアント証明書には**`IdentityCertificateUUID`**を使用

## 攻撃

### 他の組織にデバイスを登録する

以前にコメントしたように、デバイスを組織に登録するためには、その組織に所属する**シリアル番号のみが必要**です。デバイスが登録されると、複数の組織が新しいデバイスに機密データをインストールします: 証明書、アプリケーション、WiFiパスワード、VPNの設定など。\
したがって、登録プロセスが正しく保護されていない場合、これは攻撃者にとって危険なエントリーポイントとなり得ます。

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

## **参考文献**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**企業を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
