# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDMについて学ぶには、次を確認してください:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基本

### **MDM (モバイルデバイス管理) 概要**

[モバイルデバイス管理](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) は、スマートフォン、ラップトップ、タブレットなどのさまざまなエンドユーザーデバイスを監視するために利用されます。特にAppleのプラットフォーム（iOS、macOS、tvOS）においては、一連の専門的な機能、API、および実践が含まれます。MDMの運用は、商業的に入手可能またはオープンソースの互換性のあるMDMサーバーに依存し、[MDMプロトコル](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)をサポートする必要があります。主なポイントは以下の通りです：

- デバイスの集中管理。
- MDMプロトコルに準拠したMDMサーバーへの依存。
- MDMサーバーがデバイスにさまざまなコマンドを送信できる能力、例えば、リモートデータ消去や設定インストールなど。

### **DEP (デバイス登録プログラム) の基本**

Appleが提供する[デバイス登録プログラム](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) は、iOS、macOS、tvOSデバイスのモバイルデバイス管理（MDM）を簡素化し、ゼロタッチ構成を可能にします。DEPは登録プロセスを自動化し、デバイスが箱から出してすぐに動作可能になり、最小限のユーザーまたは管理者の介入で済むようにします。重要な側面は以下の通りです：

- デバイスが初回起動時に事前定義されたMDMサーバーに自動的に登録されることを可能にします。
- 主に新しいデバイスに有益ですが、再構成中のデバイスにも適用可能です。
- 簡単なセットアップを促進し、デバイスを迅速に組織で使用できるようにします。

### **セキュリティの考慮事項**

DEPによって提供される登録の容易さは有益ですが、セキュリティリスクをもたらす可能性があることに注意が必要です。MDM登録に対する保護措置が適切に施されていない場合、攻撃者はこの簡素化されたプロセスを利用して、自分のデバイスを組織のMDMサーバーに登録し、企業デバイスを装う可能性があります。

> [!CAUTION]
> **セキュリティ警告**: 簡素化されたDEP登録は、適切な保護策が講じられていない場合、組織のMDMサーバーに対する不正なデバイス登録を許可する可能性があります。

### SCEP (シンプル証明書登録プロトコル) とは？

- TLSやHTTPSが広まる前に作成された比較的古いプロトコルです。
- クライアントが証明書を取得するために**証明書署名要求**（CSR）を送信する標準化された方法を提供します。クライアントはサーバーに署名された証明書を要求します。

### 構成プロファイル（別名mobileconfigs）とは？

- Appleの公式な**システム構成の設定/強制方法**です。
- 複数のペイロードを含むことができるファイル形式です。
- プロパティリスト（XML形式）に基づいています。
- 「その起源を検証し、整合性を確保し、内容を保護するために署名および暗号化できます。」 基本 — ページ70, iOSセキュリティガイド, 2018年1月。

## プロトコル

### MDM

- APNs（**Appleサーバー**） + RESTful API（**MDM** **ベンダー**サーバー）の組み合わせ
- **通信**は**デバイス**と**デバイス管理製品**に関連するサーバーの間で行われます
- **コマンド**はMDMからデバイスに**plistエンコードされた辞書**で送信されます
- すべて**HTTPS**経由です。MDMサーバーは（通常）ピン留めされます。
- AppleはMDMベンダーに**APNs証明書**を認証用に付与します

### DEP

- **3つのAPI**: 1つはリセラー用、1つはMDMベンダー用、1つはデバイスID用（未文書）：
- いわゆる[DEP "クラウドサービス" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。これはMDMサーバーが特定のデバイスにDEPプロファイルを関連付けるために使用されます。
- [Apple認定リセラーが使用するDEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)は、デバイスを登録し、登録状況を確認し、取引状況を確認します。
- 未文書のプライベートDEP API。これはAppleデバイスが自分のDEPプロファイルを要求するために使用されます。macOSでは、`cloudconfigurationd`バイナリがこのAPIを介して通信する責任があります。
- より現代的で**JSON**ベース（vs. plist）
- AppleはMDMベンダーに**OAuthトークン**を付与します

**DEP "クラウドサービス" API**

- RESTful
- AppleからMDMサーバーへのデバイスレコードの同期
- MDMサーバーからAppleへの「DEPプロファイル」の同期（後でデバイスに配信される）
- DEP「プロファイル」には以下が含まれます：
- MDMベンダーサーバーのURL
- サーバーURL用の追加の信頼された証明書（オプションのピン留め）
- 追加の設定（例：セットアップアシスタントでスキップする画面）

## シリアル番号

2010年以降に製造されたAppleデバイスは一般的に**12文字の英数字**のシリアル番号を持ち、**最初の3桁は製造場所**を表し、次の**2桁**は**製造年**と**週**を示し、次の**3桁**は**ユニークな識別子**を提供し、**最後の4桁**は**モデル番号**を表します。

{{#ref}}
macos-serial-number.md
{{#endref}}

## 登録と管理の手順

1. デバイスレコードの作成（リセラー、Apple）：新しいデバイスのレコードが作成されます
2. デバイスレコードの割り当て（顧客）：デバイスがMDMサーバーに割り当てられます
3. デバイスレコードの同期（MDMベンダー）：MDMがデバイスレコードを同期し、DEPプロファイルをAppleにプッシュします
4. DEPチェックイン（デバイス）：デバイスがDEPプロファイルを取得します
5. プロファイルの取得（デバイス）
6. プロファイルのインストール（デバイス） a. MDM、SCEP、およびルートCAペイロードを含む
7. MDMコマンドの発行（デバイス）

![](<../../../images/image (694).png>)

ファイル`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`は、登録プロセスの**高レベルの「ステップ」**と見なされる関数をエクスポートします。

### ステップ4: DEPチェックイン - アクティベーションレコードの取得

このプロセスの一部は、**ユーザーが初めてMacを起動したとき**（または完全にワイプした後）に発生します。

![](<../../../images/image (1044).png>)

または`sudo profiles show -type enrollment`を実行したとき。

- **デバイスがDEP対応かどうかを判断**
- アクティベーションレコードは**DEP「プロファイル」**の内部名です
- デバイスがインターネットに接続されるとすぐに始まります
- **`CPFetchActivationRecord`**によって駆動されます
- **`cloudconfigurationd`**によってXPCを介して実装されます。デバイスが初めて起動されたときの**「セットアップアシスタント」**または**`profiles`**コマンドがこのデーモンに連絡してアクティベーションレコードを取得します。
- LaunchDaemon（常にrootとして実行）

アクティベーションレコードを取得するために**`MCTeslaConfigurationFetcher`**によって実行されるいくつかのステップに従います。このプロセスは**Absinthe**という暗号化を使用します。

1. **証明書を取得**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **証明書から状態を初期化**（**`NACInit`**）
1. 様々なデバイス固有のデータを使用します（例：**シリアル番号を`IOKit`経由で**）
3. **セッションキーを取得**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. セッションを確立（**`NACKeyEstablishment`**）
5. リクエストを行う
1. POST [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)にデータ`{ "action": "RequestProfileConfiguration", "sn": "" }`を送信
2. JSONペイロードはAbsintheを使用して暗号化されます（**`NACSign`**）
3. すべてのリクエストはHTTPs経由で行われ、組み込みのルート証明書が使用されます

![](<../../../images/image (566) (1).png>)

レスポンスは、以下のような重要なデータを含むJSON辞書です：

- **url**: アクティベーションプロファイルのためのMDMベンダーホストのURL
- **anchor-certs**: 信頼されたアンカーとして使用されるDER証明書の配列

### **ステップ5: プロファイルの取得**

![](<../../../images/image (444).png>)

- **DEPプロファイルで提供されたurl**にリクエストが送信されます。
- 提供された場合、**アンカー証明書**が**信頼性を評価**するために使用されます。
- リマインダー: **DEPプロファイルのanchor_certsプロパティ**
- **リクエストはデバイス識別を含むシンプルな.plist**です
- 例: **UDID、OSバージョン**。
- CMS署名、DERエンコード
- **デバイスID証明書（APNSからの）**を使用して署名されます。
- **証明書チェーン**には期限切れの**Apple iPhone Device CA**が含まれます。

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### ステップ6: プロファイルのインストール

- 取得後、**プロファイルはシステムに保存されます**
- このステップは自動的に開始されます（**セットアップアシスタント**にいる場合）
- **`CPInstallActivationProfile`**によって駆動されます
- XPCを介してmdmclientによって実装されます
- LaunchDaemon（rootとして）またはLaunchAgent（ユーザーとして）、コンテキストに応じて
- 構成プロファイルにはインストールする複数のペイロードがあります
- フレームワークはプロファイルをインストールするためのプラグインベースのアーキテクチャを持っています
- 各ペイロードタイプはプラグインに関連付けられています
- XPC（フレームワーク内）または従来のCocoa（ManagedClient.app内）である可能性があります
- 例：
- 証明書ペイロードはCertificateService.xpcを使用します

通常、MDMベンダーが提供する**アクティベーションプロファイル**には**以下のペイロード**が含まれます：

- `com.apple.mdm`: デバイスをMDMに**登録**するため
- `com.apple.security.scep`: デバイスに**クライアント証明書**を安全に提供するため。
- `com.apple.security.pem`: デバイスのシステムキーチェーンに**信頼されたCA証明書**をインストールするため。
- MDMペイロードのインストールは、文書内の**MDMチェックイン**に相当します。
- ペイロードには**主要なプロパティ**が含まれます：
- - MDMチェックインURL（**`CheckInURL`**）
- MDMコマンドポーリングURL（**`ServerURL`**） + それをトリガーするAPNsトピック
- MDMペイロードをインストールするために、リクエストが**`CheckInURL`**に送信されます
- **`mdmclient`**で実装されています
- MDMペイロードは他のペイロードに依存することがあります
- 特定の証明書にリクエストをピン留めすることを許可します：
- プロパティ：**`CheckInURLPinningCertificateUUIDs`**
- プロパティ：**`ServerURLPinningCertificateUUIDs`**
- PEMペイロードを介して配信されます
- デバイスにアイデンティティ証明書を付与することを許可します：
- プロパティ：IdentityCertificateUUID
- SCEPペイロードを介して配信されます

### **ステップ7: MDMコマンドのリスニング**

- MDMチェックインが完了した後、ベンダーは**APNsを使用してプッシュ通知を発行**できます
- 受信時、**`mdmclient`**によって処理されます
- MDMコマンドをポーリングするために、リクエストがServerURLに送信されます
- 以前にインストールされたMDMペイロードを利用します：
- **`ServerURLPinningCertificateUUIDs`**によるリクエストのピン留め
- **`IdentityCertificateUUID`**によるTLSクライアント証明書

## 攻撃

### 他の組織へのデバイスの登録

前述のように、デバイスを組織に登録しようとするには、**その組織に属するシリアル番号のみが必要**です。デバイスが登録されると、いくつかの組織は新しいデバイスに機密データをインストールします：証明書、アプリケーション、WiFiパスワード、VPN設定など[こちら](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)を参照してください。\
したがって、登録プロセスが適切に保護されていない場合、これは攻撃者にとって危険な入り口となる可能性があります：

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
