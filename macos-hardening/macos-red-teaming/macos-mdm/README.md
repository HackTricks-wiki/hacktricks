# macOS MDM

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>で学ぶ！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私をフォローする [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

**macOS MDMについて学ぶ:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基本

### **MDM（モバイルデバイス管理）概要**
[モバイルデバイス管理](https://en.wikipedia.org/wiki/Mobile_device_management)（MDM）は、スマートフォン、ノートパソコン、タブレットなどのさまざまなエンドユーザーデバイスを管理するために使用されます。特にAppleのプラットフォーム（iOS、macOS、tvOS）では、専門機能、API、およびプラクティスが関与します。MDMの操作は、商用またはオープンソースの互換性のあるMDMサーバーに依存し、[MDMプロトコル](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)をサポートする必要があります。主なポイントは次のとおりです：

- デバイスに対する集中制御。
- MDMプロトコルに準拠するMDMサーバーへの依存。
- MDMサーバーが、リモートデータ消去や構成のインストールなど、さまざまなコマンドをデバイスに送信できる能力。

### **DEP（デバイス登録プログラム）の基本**
Appleが提供する[デバイス登録プログラム](https://www.apple.com/business/site/docs/DEP_Guide.pdf)（DEP）は、iOS、macOS、tvOSデバイスのゼロタッチ構成を容易にすることで、モバイルデバイス管理（MDM）の統合を効率化します。DEPは登録プロセスを自動化し、デバイスを最初に起動するとすぐに、ユーザーまたは管理者の介入を最小限に抑えてデバイスを運用可能にします。主な側面は次のとおりです：

- デバイスが初めて起動されると、事前定義されたMDMサーバーに自動的に登録される。
- 新しいデバイスに最適であるが、再構成中のデバイスにも適用可能。
- 組織での使用にすばやく準備されるように、簡単なセットアップを容易にします。

### **セキュリティに関する考慮事項**
DEPによって提供される簡単な登録の利便性は、有益である一方、セキュリティリスクをもたらす可能性があります。MDM登録に適切な保護措置が施されていない場合、攻撃者はこの簡略化されたプロセスを悪用して、企業デバイスを装ったまま組織のMDMサーバーに自分のデバイスを登録する可能性があります。

{% hint style="danger" %}
**セキュリティアラート**: 簡略化されたDEP登録は、適切な保護措置が施されていない場合、組織のMDMサーバーに認可されていないデバイスを登録する可能性があります。
{% endhint %}

### **SCEP（Simple Certificate Enrolment Protocol）とは？**

- **TLSやHTTPS**が普及する前に作成された比較的古いプロトコル。
- クライアントに**証明書署名リクエスト（CSR）**を送信し、証明書を取得するための標準化された方法を提供します。クライアントは、サーバーに署名された証明書を提供するよう要求します。

### **構成プロファイル（別名mobileconfigs）とは？**

- Appleの公式方法で**システム構成を設定/強制する**。
- 複数のペイロードを含むファイル形式。
- プロパティリスト（XMLタイプ）に基づいています。
- 「起源を検証し、整合性を確保し、内容を保護するために署名および暗号化できます。」Basics — Page 70, iOS Security Guide, January 2018.

## プロトコル

### MDM

- APNs（**Appleサーバー**）+ RESTful API（**MDMベンダーサーバー**）の組み合わせ
- **デバイス**と**デバイス管理製品**に関連するサーバー間で**通信**が行われます
- MDMからデバイスに**plistエンコードされた辞書**でコマンドが送信されます
- すべてが**HTTPS**経由。MDMサーバーは（通常）ピン留めされます。
- AppleはMDMベンダーに**APNs証明書**を認証するための証明書を付与します

### DEP

- **3つのAPI**：販売代理店用1つ、MDMベンダー用1つ、デバイス識別用1つ（未公開）：
- いわゆる[DEP "クラウドサービス"API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。これは、MDMサーバーがDEPプロファイルを特定のデバイスに関連付けるために使用されます。
- [Apple認定リセラーが使用するDEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)は、デバイスの登録、登録ステータスの確認、トランザクションステータスの確認に使用されます。
- 未公開のプライベートDEP API。これは、AppleデバイスがDEPプロファイルをリクエストするために使用されます。macOSでは、`cloudconfigurationd`バイナリがこのAPIを介して通信を行います。
- より現代的で**JSON**ベース（vs. plist）
- AppleはMDMベンダーに**OAuthトークン**を付与します

**DEP "クラウドサービス"API**

- RESTful
- AppleからMDMサーバーにデバイスレコードを同期
- MDMサーバーからAppleに「DEPプロファイル」を同期（後でデバイスに配信されます）
- DEP「プロファイル」には次のものが含まれます：
- MDMベンダーサーバーのURL
- サーバーURLの追加信頼できる証明書（オプションのピン留め）
- その他の設定（例：セットアップアシスタントでスキップする画面など）

## シリアル番号

2010年以降に製造されたAppleデバイスは、一般的に**12文字の英数字**のシリアル番号を持ち、**最初の3桁は製造場所**を表し、次の**2桁は製造年**と**週**を示し、次の**3桁は一意の識別子**を提供し、最後の**4桁はモデル番号**を表します。

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 登録および管理手順

1. デバイスレコードの作成（リセラー、Apple）：新しいデバイスのレコードが作成されます
2. デバイスレコードの割り当て（顧客）：デバイスがMDMサーバーに割り当てられます
3. デバイスレコードの同期（MDMベンダー）：MDMはデバイスレコードを同期し、DEPプロファイルをAppleにプッシュします
4. DEPチェックイン（デバイス）：デバイスがDEPプロファイルを取得します
5. プロファイルの取得（デバイス）
6. プロファイルのインストール（デバイス） a. MDM、SCEP、ルートCAペイロードを含む
7. MDMコマンドの発行（デバイス）

![](<../../../.gitbook/assets/image (564).png>)

ファイル`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`は、登録プロセスの**高レベルな「ステップ」**と見なすことができる関数をエクスポートします。

### ステップ4: DEPチェックイン - アクティベーションレコードの取得

このプロセスのこの部分は、**ユーザーがMacを初めて起動**したとき（または完全なワイプ後）

![](<../../../.gitbook/assets/image (568).png>)

または`sudo profiles show -type enrollment`を実行したとき

- **デバイスがDEP対応かどうかを判断**
- アクティベーションレコードはDEP「プロファイル」の内部名です
- デバイスがインターネットに接続されるとすぐに開始
- **`CPFetchActivationRecord`**によって駆動
- **`cloudconfigurationd`**によってXPC経由で実装されます。デバイスが最初に起動されたときの**「セットアップアシスタント」**または**`profiles`**コマンドは、アクティベーションレコードを取得するためにこのデーモンに連絡します。
- LaunchDaemon（常にrootとして実行）

**`MCTeslaConfigurationFetcher`**によって実行されるアクティベーションレコードの取得には、**Absinthe**と呼ばれる暗号化が使用されます。

1. **証明書を取得**
   - [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)にGETリクエスト
2. 証明書から状態を**初期化**（**`NACInit`**）
   - 端末固有のデータを使用（`IOKit`経由のシリアル番号など）
3. **セッションキーを取得**
   - [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)にPOSTリクエスト
4. セッションを確立（**`NACKeyEstablishment`**）
5. リクエストを作成
   - `{ "action": "RequestProfileConfiguration", "sn": "" }`のデータを送信して[https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)にPOSTリクエスト
   - JSONペイロードはAbsintheを使用して暗号化されます（**`NACSign`**）
   - すべてのリクエストはHTTPS経由で行われ、組み込みのルート証明書が使用されます

![](<../../../.gitbook/assets/image (566).png>)

応答は、次のような重要なデータを含むJSON辞書です：

- **url**：アクティベーションプロファイルのMDMベンダーホストのURL
- **anchor-certs**：信頼されるアンカーとして使用されるDER証明書の配列

### **ステップ5: プロファイルの取得**

![](<../../../.gitbook/assets/image (567).png>)

- DEPプロファイルで提供された**URL**にリクエストを送信します。
- **アンカー証明書**が提供された場合、**信頼を評価**するために使用されます。
- 注意：DEPプロファイルの**anchor\_certs**プロパティ
- リクエストは、デバイス識別情報などの**UDID、OSバージョン**を含む**単純な.plist**です。
- CMSで署名され、DERでエンコードされます
- **デバイス識別証明書（APNSから）**を使用して署名されます
- **証明書チェーン**には期限切れの**Apple iPhone Device CA**が含まれます

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1)
