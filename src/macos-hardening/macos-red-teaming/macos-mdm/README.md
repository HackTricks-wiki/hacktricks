# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDMについて学ぶには、以下を参照してください:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## 基本

### **MDM (Mobile Device Management) の概要**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) は、スマートフォン、ノートPC、タブレットなど、さまざまなエンドユーザーデバイスの管理に利用されます。特にAppleのプラットフォーム (iOS、macOS、tvOS) では、専用の機能、API、プラクティスが含まれます。MDMの運用には、商用またはオープンソースで提供され、[MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) に準拠したMDMサーバーが必要です。主なポイントは次のとおりです。

- デバイスを一元管理できる。
- MDMプロトコルに準拠したMDMサーバーが必要。
- MDMサーバーからデバイスに、リモートデータ消去や構成のインストールなど、さまざまなコマンドを送信できる。

### **DEP (Device Enrollment Program) の基本**

Appleが提供する [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) は、iOS、macOS、tvOSデバイスのゼロタッチ構成を可能にし、Mobile Device Management (MDM) への統合を簡素化します。DEPは登録プロセスを自動化するため、ユーザーや管理者の介入を最小限に抑え、デバイスを箱から出してすぐに使える状態にできます。主なポイントは次のとおりです。

- 初回アクティベーション時に、デバイスが事前に指定されたMDMサーバーへ自動登録できる。
- 主に新品のデバイスに有効だが、再構成中のデバイスにも適用できる。
- 簡単なセットアップで、デバイスを迅速に組織で使える状態にできる。

### **セキュリティ上の考慮事項**

DEPが提供する登録の容易さは便利である一方、セキュリティリスクにもなり得る点に注意が必要です。MDM登録に対する保護策が適切に実施されていない場合、攻撃者はこの簡素化されたプロセスを悪用し、会社所有のデバイスを装って組織のMDMサーバーに自分のデバイスを登録できる可能性があります。<sup>[[2]](#references)</sup>

> [!CAUTION]
> **セキュリティ警告**: 適切な保護策が講じられていない場合、DEP登録の簡素化により、組織のMDMサーバーに不正なデバイスが登録される可能性があります。

### SCEP (Simple Certificate Enrolment Protocol) とは？

- TLSやHTTPSが広く普及する前に作られた、比較的古いプロトコル。
- クライアントが証明書を取得するために **Certificate Signing Request** (CSR) を送信する標準的な方法を提供する。クライアントはサーバーに署名済み証明書の発行を要求する。

### Configuration Profiles (別名 mobileconfigs) とは？

- **システム構成の設定・適用**に使われるAppleの公式な方法。
- 複数のペイロードを含められるファイル形式。
- property list (XML形式) に基づく。
- 「その出所を検証し、完全性を確保し、内容を保護するために、署名および暗号化できる。」『iOS Security Guide』2018年1月版、基本事項 — 70ページ。

## プロトコル

### MDM

- APNs (**Appleサーバー**) と RESTful API (**MDMベンダー**のサーバー) の組み合わせ
- **デバイス**と、**デバイス** **管理** **製品**に関連付けられたサーバー間で**通信**が行われる
- MDMからデバイスへ、**plist形式でエンコードされた辞書**で**コマンド**が配信される
- すべて **HTTPS** 経由。MDMサーバーではピンニングが可能で、通常は実施されている。
- Appleは認証用の **APNs証明書**をMDMベンダーに発行する

### DEP

- **3つのAPI**: リセラー用、MDMベンダー用、デバイス識別用 (非公開) がそれぞれ1つ:
  - いわゆる [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。MDMサーバーがDEPプロファイルを特定のデバイスに関連付けるために使用する。
  - [Apple Authorized Resellersが使用するDEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)。デバイスの登録、登録状況の確認、トランザクション状況の確認に使用する。
  - 非公開のDEP API。AppleデバイスがDEPプロファイルを要求するために使用する。macOSでは、`cloudconfigurationd` バイナリがこのAPIを介した通信を担当する。
- より新しく、**JSON** ベース (plistとは異なる)
- AppleはMDMベンダーに **OAuth token** を発行する

**DEP "cloud service" API**

- RESTful
- デバイスレコードをAppleからMDMサーバーへ同期する
- 「DEPプロファイル」をMDMサーバーからAppleへ同期する (後にAppleからデバイスへ配信される)
- DEP「プロファイル」には以下が含まれる:
  - MDMベンダーサーバーのURL
  - サーバーURL用の追加の信頼済み証明書 (任意のピンニング)
  - 追加設定 (例: Setup Assistantでスキップする画面)

## シリアル番号

2010年以降に製造されたAppleデバイスのシリアル番号は、一般に **12文字の英数字**で構成されます。**先頭3桁は製造場所**、続く **2桁は製造年と週**、その次の **3桁は一意の識別子**、**末尾4桁はモデル番号**を表します。


{{#ref}}
macos-serial-number.md
{{#endref}}

## 登録と管理の手順

1. デバイスレコードの作成 (リセラー、Apple): 新しいデバイスのレコードが作成される
2. デバイスレコードの割り当て (顧客): デバイスがMDMサーバーに割り当てられる
3. デバイスレコードの同期 (MDMベンダー): MDMがデバイスレコードを同期し、DEPプロファイルをAppleにプッシュする
4. DEP check-in (デバイス): デバイスがDEPプロファイルを取得する
5. プロファイルの取得 (デバイス)
6. プロファイルのインストール (デバイス) a. MDM、SCEP、root CAペイロードを含む
7. MDMコマンドの発行 (デバイス)

![シリアル番号 - 登録と管理の手順: 7. MDMコマンドの発行 (デバイス)](<../../../images/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` ファイルは、登録プロセスの**高レベルな「手順」**とみなせる関数をエクスポートします。

### ステップ4: DEP check-in - Activation Recordの取得

このプロセスは、**ユーザーがMacを初めて起動したとき** (または完全に消去した後) に発生します。

![登録と管理の手順 - ステップ4: DEP check-in - Activation Recordの取得: このプロセスは、ユーザーがMacを初めて起動したとき (または完全に消去した後) に発生します](<../../../images/image (1044).png>)

または `sudo profiles show -type enrollment` を実行したときに発生します。

- **デバイスがDEPに対応しているか**を判定する
- Activation Recordは、DEP「プロファイル」の内部名称
- デバイスがインターネットに接続されるとすぐに開始する
- **`CPFetchActivationRecord`** によって実行される
- XPC経由で **`cloudconfigurationd`** が実装する。**Setup Assistant** (デバイスの初回起動時) または **`profiles`** コマンドが、このデーモンに**接続して**Activation Recordを取得する。
  - LaunchDaemon (常にrootとして実行)

Activation Recordの取得は、**`MCTeslaConfigurationFetcher`** によっていくつかの手順で行われます。このプロセスでは **Absinthe** という暗号化方式が使われます。<sup>[[1]](#references)</sup>

1. **証明書**を取得する
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 証明書から状態を**初期化**する (**`NACInit`**)
   1. デバイス固有のさまざまなデータを使用する (例: **`IOKit` 経由のシリアル番号**)
3. **セッションキー**を取得する
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. セッションを確立する (**`NACKeyEstablishment`**)
5. リクエストを行う
   1. POSTを [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) に送信し、データ `{ "action": "RequestProfileConfiguration", "sn": "" }` を渡す
   2. JSONペイロードはAbsintheを使って暗号化される (**`NACSign`**)
   3. すべてのリクエストはHTTPS経由で行われ、組み込みのroot証明書が使用される

![登録と管理の手順 - ステップ4: DEP check-in - Activation Recordの取得: 3. すべてのリクエストはHTTPS経由で行われ、組み込みのroot証明書が使用される](<../../../images/image (566) (1).png>)

レスポンスはJSON辞書で、以下のような重要なデータが含まれます。

- **url**: Activation Profile用のMDMベンダーホストのURL
- **anchor-certs**: 信頼アンカーとして使用されるDER証明書の配列

### **ステップ5: プロファイルの取得**

![ステップ4: DEP check-in - Activation Recordの取得 - ステップ5: プロファイルの取得: ステップ5: プロファイルの取得](<../../../images/image (444).png>)

- **DEPプロファイルで指定されたURL**にリクエストを送信する。
- 提供されている場合は、**Anchor certificates** を使って**信頼性を評価**する。
  - DEPプロファイルの **anchor_certs** プロパティに注意
- **リクエストはデバイス識別情報を含む単純な .plist**
  - 例: **UDID、OSバージョン**。
- CMS署名付き、DERエンコード
- **デバイスID証明書 (APNSから取得)** を使って署名される
- **証明書チェーン**には有効期限切れの **Apple iPhone Device CA** が含まれる

![ステップ4: DEP check-in - Activation Recordの取得 - ステップ5: プロファイルの取得: デバイスID証明書 (APNSから取得) を使って署名される](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### ステップ6: プロファイルのインストール

- 取得したプロファイルは**システムに保存される**
- この手順は (setup assistant内では) 自動的に開始する
- **`CPInstallActivationProfile`** によって実行される
- XPC経由でmdmclientが実装する
  - コンテキストに応じてLaunchDaemon (rootとして実行) またはLaunchAgent (ユーザーとして実行)
- Configuration profilesには、インストールする複数のペイロードが含まれる
- プロファイルのインストールには、フレームワークのプラグインベースのアーキテクチャを使用する
- 各ペイロードタイプはプラグインに関連付けられる
  - XPC (フレームワーク内) または従来のCocoa (ManagedClient.app) を使用できる
- 例:
  - Certificate PayloadsにはCertificateService.xpcを使用する

通常、MDMベンダーが提供する **activation profile** には、以下のペイロードが含まれます。

- `com.apple.mdm`: デバイスをMDMに**登録**する
- `com.apple.security.scep`: デバイスに**クライアント証明書**を安全に提供する。
- `com.apple.security.pem`: 信頼済みCA証明書をデバイスのSystem Keychainに**インストール**する。
- MDMペイロードのインストールは、ドキュメントに記載された**MDM check-in**に相当する
- ペイロードには**重要なプロパティ**が含まれる:
- - MDM Check-In URL (**`CheckInURL`**)
  - MDM Command Polling URL (**`ServerURL`**) と、それをトリガーするAPNs topic
- MDMペイロードをインストールするため、リクエストは **`CheckInURL`** に送信される
- **`mdmclient`** で実装される
- MDMペイロードは他のペイロードに依存できる
- **リクエストを特定の証明書にピン留め**できる:
  - プロパティ: **`CheckInURLPinningCertificateUUIDs`**
  - プロパティ: **`ServerURLPinningCertificateUUIDs`**
  - PEMペイロード経由で配信される
- デバイスにID証明書を割り当てられる:
  - プロパティ: IdentityCertificateUUID
  - SCEPペイロード経由で配信される

### **ステップ7: MDMコマンドを待ち受ける**

- MDM check-inが完了すると、ベンダーはAPNsを使って**プッシュ通知を発行できる**
- 通知を受信すると、**`mdmclient`** が処理する
- MDMコマンドをポーリングするため、リクエストをServerURLに送信する
- 事前にインストールされたMDMペイロードを利用する:
  - リクエストのピンニングには **`ServerURLPinningCertificateUUIDs`** を使用
  - TLSクライアント証明書には **`IdentityCertificateUUID`** を使用

## 攻撃

### 他の組織へのデバイス登録

割り当てられたシリアル番号から組織の登録経路を特定できますが、MDM登録が保証されるわけではありません。登録プロファイルを返す前に、サーバーが `configuration_web_url` を通じてユーザー認証を要求する場合があります。割り当て済みのシリアル番号ならすべてデバイス群に登録できると考えず、別の登録経路でこのチェックが省略されていないかを確認してください。<sup>[[3]](#references)</sup>

不正な登録を行う手順については、以下のリンク先を参照してください。侵害後のMDM制御とパッケージ配信については、[macOS Red Teaming](../) を参照してください。


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [macOS MDMの詳細解説 (およびその侵害方法)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — 「MDM Me Maybe?」 (DEP/MDM登録のセキュリティ調査)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Webビューによる認証](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
