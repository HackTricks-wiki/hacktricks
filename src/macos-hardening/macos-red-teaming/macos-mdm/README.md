# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDMについては、以下を参照してください:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基礎

### **MDM（Mobile Device Management）の概要**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management)（MDM）は、スマートフォン、ノートパソコン、タブレットなど、さまざまなエンドユーザーデバイスを管理するために使用されます。特にAppleのプラットフォーム（iOS、macOS、tvOS）では、専用の機能、API、プラクティスの集合を指します。MDMの運用には、商用またはopen-sourceで提供され、[MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)をサポートする互換性のあるMDMサーバーが必要です。主なポイントは以下のとおりです。

- デバイスを集中管理できる。
- MDM protocolに準拠したMDMサーバーに依存する。
- MDMサーバーからデバイスへ、リモートデータ消去や設定のインストールなど、さまざまなコマンドを送信できる。

### **DEP（Device Enrollment Program）の基礎**

Appleが提供する[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf)（DEP）は、iOS、macOS、tvOSデバイスのzero-touch設定を可能にすることで、Mobile Device Management（MDM）の導入を効率化します。DEPはenrollmentプロセスを自動化し、ユーザーや管理者の介入を最小限に抑えながら、デバイスを箱から出してすぐに使用できる状態にします。主なポイントは以下のとおりです。

- 初回アクティベーション時に、デバイスが事前定義されたMDMサーバーへ自動的に登録できる。
- 主に新品のデバイスに有効だが、再設定中のデバイスにも適用できる。
- 簡単なセットアップを可能にし、デバイスを組織で迅速に使用できる状態にする。

### **セキュリティ上の考慮事項**

DEPによってenrollmentが容易になることは有益ですが、同時にセキュリティリスクを生じさせる可能性がある点に注意が必要です。MDM enrollmentに対する保護策が適切に適用されていない場合、攻撃者はこの簡略化されたプロセスを悪用し、企業デバイスを装って自身のデバイスを組織のMDMサーバーに登録できる可能性があります。<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Security Alert**: 適切な保護策がない場合、簡略化されたDEP enrollmentによって、権限のないデバイスが組織のMDMサーバーに登録される可能性があります。

### SCEP（Simple Certificate Enrolment Protocol）とは？

- TLSやHTTPSが広く普及する前に作成された、比較的古いprotocol。
- クライアントが証明書の発行を目的として、標準化された方法で**Certificate Signing Request**（CSR）を送信できる。クライアントはサーバーに署名済み証明書の発行を要求する。

### Configuration Profiles（別名mobileconfigs）とは？

- **システム設定を指定・強制する**Apple公式の方法。
- 複数のpayloadを含められるファイル形式。
- property list（XML形式）を基盤としている。
- 「出所を検証し、完全性を保証し、内容を保護するために、署名および暗号化できる。」Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- APNs（**Apple server**）とRESTful API（**MDM** **vendor** server）の組み合わせ
- **通信**は、**device** **management** **product**に関連付けられた**device**とサーバーの間で行われる
- **Commands**はMDMからデバイスへ、**plist-encoded dictionaries**として配信される
- すべて**HTTPS**経由。MDMサーバーではpinningを使用でき（通常は使用されている）。
- Appleは認証用にMDM vendorへ**APNs certificate**を付与する

### DEP

- **3つのAPI**: reseller用、MDM vendor用、device identity用（undocumented）の各1つ:
- いわゆる[DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。MDMサーバーがDEP profileを特定のデバイスに関連付けるために使用される。
- [Apple Authorized Resellerが使用するDEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)。デバイスのenroll、enrollment statusの確認、transaction statusの確認に使用される。
- undocumented private DEP API。Apple Devicesが自身のDEP profileを要求するために使用される。macOSでは、`cloudconfigurationd` binaryがこのAPI経由の通信を担当する。
- より新しく、**JSON**ベース（plistではない）
- AppleはMDM vendorへ**OAuth token**を付与する

**DEP "cloud service" API**

- RESTful
- AppleからMDM serverへdevice recordsをsyncする
- MDM serverからAppleへ「DEP profiles」をsyncする（後でAppleからdeviceへ配信される）
- DEP「profile」には以下が含まれる:
- MDM vendor server URL
- server URL用の追加のtrusted certificates（optional pinning）
- 追加設定（例: Setup Assistantでスキップする画面）

## Serial Number

2010年以降に製造されたApple devicesには、一般に**12文字の英数字**のserial numbersが付けられています。**最初の3桁は製造場所**、続く**2桁は製造年**と**製造週**、次の**3桁は一意の** **identifier**、最後の**4桁はmodel number**を表します。


{{#ref}}
macos-serial-number.md
{{#endref}}

## Enrolmentとmanagementの手順

1. Device record creation（Reseller、Apple）: 新しいdeviceのrecordが作成される
2. Device record assignment（Customer）: deviceがMDM serverに割り当てられる
3. Device record sync（MDM vendor）: MDMがdevice recordsをsyncし、DEP profilesをAppleへpushする
4. DEP check-in（Device）: deviceが自身のDEP profileを取得する
5. Profile retrieval（Device）
6. Profile installation（Device） a. MDM、SCEP、root CA payloadsを含む
7. MDM command issuance（Device）

![Serial Number - Enrolmentとmanagementの手順: 7. MDM command issuance（Device）](<../../../images/image (694).png>)

ファイル`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`は、enrolment processの**high-levelな「steps」**とみなせるfunctionsをexportします。

### Step 4: DEP check-in - Activation Recordの取得

このプロセスは、**userが初めてMacをbootしたとき**（または完全なwipe後）に実行されます。

![Enrolmentとmanagementの手順 - Step 4: DEP check-in - Activation Recordの取得: このプロセスは、userが初めてMacをbootしたとき（または完全な...](<../../../images/image (1044).png>)

または`sudo profiles show -type enrollment`を実行したときに実行されます。

- **deviceがDEP enabledかどうか**を判定する
- Activation RecordはDEP「profile」の内部名
- deviceがInternetに接続されるとすぐに開始される
- **`CPFetchActivationRecord`**によって駆動される
- XPC経由で**`cloudconfigurationd`**により実装される。deviceを初めてbootしたときの**"Setup Assistant**"または**`profiles`** commandが、このdaemonへ接続してactivation recordを取得する。
- LaunchDaemon（常にrootとして実行）

Activation Recordの取得には、**`MCTeslaConfigurationFetcher`**によって実行されるいくつかのstepsがあります。このプロセスでは**Absinthe**という暗号化が使用されます。<sup>[[1]](#references)</sup>

1. **certificate**を取得
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. certificateからstateを**initialize**（**`NACInit`**）
1. device固有のさまざまなdata（例: **`IOKit`**経由の**Serial Number**）を使用
3. **session key**を取得
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. sessionを確立（**`NACKeyEstablishment`**）
5. requestを実行
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)へPOSTし、`{ "action": "RequestProfileConfiguration", "sn": "" }`のdataを送信
2. JSON payloadはAbsinthe（**`NACSign`**）を使用して暗号化される
3. すべてのrequestはHTTPs経由で、built-in root certificatesが使用される

![Enrolmentとmanagementの手順 - Step 4: DEP check-in - Activation Recordの取得: 3. すべてのrequestはHTTPs経由で、built-in root certificatesが使用される](<../../../images/image (566) (1).png>)

responseは、以下のような重要なdataを含むJSON dictionaryです。

- **url**: activation profile用のMDM vendor hostのURL
- **anchor-certs**: trusted anchorsとして使用されるDER certificatesの配列

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Activation Recordの取得 - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- **DEP profileで提供されたurl**へrequestが送信される。
- 提供されている場合、**anchor certificates**が**trustを評価**するために使用される。
- 注意: DEP profileの**anchor_certs** property
- **requestはdevice identificationを含む単純な.plist**
- 例: **UDID、OS version**。
- CMS-signed、DER-encoded
- **device identity certificate（APNS由来）**を使用して署名される
- **certificate chain**には期限切れの**Apple iPhone Device CA**が含まれる

![Step 4: DEP check-in - Activation Recordの取得 - Step 5: Profile Retrieval: device identity certificate（APNS由来）を使用して署名される](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- 取得後、**profileはsystem上に保存される**
- このstepは（**setup assistant**内の場合）自動的に開始される
- **`CPInstallActivationProfile`**によって駆動される
- XPC経由でmdmclientにより実装される
- contextに応じて、LaunchDaemon（rootとして）またはLaunchAgent（userとして）になる
- Configuration profilesにはinstall対象の複数のpayloadsが含まれる
- Frameworkはprofile installのためのplugin-based architectureを持つ
- 各payload typeはpluginに関連付けられる
- XPC（framework内）またはclassic Cocoa（ManagedClient.app）として実装できる
- 例:
- Certificate PayloadsはCertificateService.xpcを使用する

通常、MDM vendorが提供する**activation profile**には以下のpayloadsが含まれます。

- `com.apple.mdm`: deviceをMDMに**enroll**する
- `com.apple.security.scep`: deviceへ**client certificate**をsecureに提供する
- `com.apple.security.pem`: deviceのSystem Keychainへtrusted CA certificatesを**install**する
- MDM payloadのinstallは、documentationにおける**MDM check-inと同等**
- Payloadには**key properties**が含まれる:
- - MDM Check-In URL（**`CheckInURL`**）
- MDM Command Polling URL（**`ServerURL`**）と、それをtriggerするAPNs topic
- MDM payloadをinstallするため、requestが**`CheckInURL`**へ送信される
- **`mdmclient`**により実装される
- MDM payloadは他のpayloadsに依存できる
- **specific certificatesへのrequest pinning**を可能にする:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- PEM payload経由で配信される
- deviceにidentity certificateを関連付けられる:
- Property: IdentityCertificateUUID
- SCEP payload経由で配信される

### **Step 7: MDM commandsのlisten**

- MDM check-inが完了すると、vendorは**APNsを使用してpush notificationsを発行**できる
- 受信後、**`mdmclient`**が処理する
- MDM commandsをpollするため、requestがServerURLへ送信される
- 以前installされたMDM payloadを使用する:
- **`ServerURLPinningCertificateUUIDs`**でrequestをpinningする
- **`IdentityCertificateUUID`**でTLS client certificateを使用する

## Attacks

### 他のOrganizationsへのDevicesのEnrolling

前述のとおり、deviceをorganizationへenrollするために必要なのは、**そのOrganizationに属するSerial Numberだけ**です。deviceがenrollされると、多くのorganizationsは新しいdeviceへ、certificates、applications、WiFi passwords、VPN configurations [and so on](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)などのsensitive dataをinstallします。\
したがって、enrolment processが適切に保護されていない場合、これはattackersにとって危険なentrypointになる可能性があります。<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [macOS MDMの詳細分析（およびCompromiseされる可能性）](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — 「MDM Me Maybe?」（DEP/MDM enrollment security research）](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
