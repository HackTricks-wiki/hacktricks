# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDMについて学ぶには、以下を参照してください:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基礎

### **MDM (Mobile Device Management) の概要**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) は、スマートフォン、ノートパソコン、タブレットなど、さまざまなエンドユーザーデバイスを管理するために利用されます。特にAppleのプラットフォーム (iOS、macOS、tvOS) では、専用の機能、API、プラクティスの集合を扱います。MDMの運用には、商用またはオープンソースで提供され、[MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) をサポートする互換性のあるMDM serverが必要です。主なポイントは以下のとおりです。

- デバイスを集中管理できる。
- MDM protocolに準拠したMDM serverに依存する。
- MDM serverからデバイスへ、リモートでのデータ消去や設定のインストールなど、さまざまなコマンドを送信できる。

### **DEP (Device Enrollment Program) の基礎**

Appleが提供する [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) は、iOS、macOS、tvOSデバイスのゼロタッチ設定を可能にすることで、Mobile Device Management (MDM) の導入を効率化します。DEPはenrollmentプロセスを自動化し、ユーザーや管理者による介入を最小限に抑えながら、デバイスを箱から出してすぐに運用できるようにします。主な特徴は以下のとおりです。

- 初回activation時に、デバイスが事前定義されたMDM serverへ自律的に登録できる。
- 主に新品のデバイスに有用だが、再設定中のデバイスにも適用できる。
- 簡単なセットアップを実現し、デバイスを組織で迅速に利用可能にする。

### **セキュリティ上の考慮事項**

DEPによる容易なenrollmentは便利である一方、セキュリティリスクにもなり得る点に注意が必要です。MDM enrollmentに対する保護対策が適切に強制されていない場合、攻撃者はこの簡略化されたプロセスを悪用し、企業デバイスを装って自身のデバイスを組織のMDM serverに登録する可能性があります。<sup>[2]</sup>

> [!CAUTION]
> **セキュリティ警告**: 適切な保護対策が存在しない場合、簡略化されたDEP enrollmentによって、権限のないデバイスが組織のMDM serverに登録される可能性があります。

### SCEP (Simple Certificate Enrolment Protocol) とは？

- TLSとHTTPSが広く普及する前に作られた、比較的古いprotocol。
- クライアントが証明書の発行を受けるために **Certificate Signing Request** (CSR) を送信する標準化された方法を提供する。クライアントはserverに署名済み証明書の発行を要求する。

### Configuration Profiles (mobileconfigsとも呼ばれる) とは？

- **システム設定を指定・強制するためのApple公式の方法。**
- 複数のpayloadを含めることができるファイル形式。
- property list (XML形式) に基づく。
- 「出所を検証し、完全性を確保し、内容を保護するために、署名および暗号化できる。」Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers) の組み合わせ
- **Communication** は **device** と、**device** **management** **product** に関連付けられたserverの間で行われる
- **Commands** はMDMからデバイスへ **plist-encoded dictionaries** として配信される
- すべて **HTTPS** 経由。MDM serversではpinningが (通常) 行われる。
- Appleは認証用にMDM vendorへ **APNs certificate** を付与する

### DEP

- **3 APIs**: reseller用、MDM vendor用、device identity用 (未公開) が1つずつ存在する:
- いわゆる [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。MDM serversがDEP profilesを特定のデバイスに関連付けるために使用される。
- [Apple Authorized Resellersが使用するDEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)。デバイスのenroll、enrollment statusの確認、transaction statusの確認に使用される。
- 未公開のprivate DEP API。Apple DevicesがDEP profileを要求するために使用される。macOSでは、`cloudconfigurationd` binaryがこのAPI経由の通信を担当する。
- より現代的で **JSON** ベース (plistではなく)
- AppleはMDM vendorへ **OAuth token** を付与する

**DEP "cloud service" API**

- RESTful
- AppleからMDM serverへdevice recordsをsyncする
- MDM serverからAppleへ「DEP profiles」をsyncする (後でAppleからデバイスへ配信される)
- DEPの「profile」には以下が含まれる:
- MDM vendor server URL
- server URL用の追加のtrusted certificates (任意のpinning)
- 追加設定 (Setup Assistantでスキップする画面など)

## Serial Number

2010年以降に製造されたApple devicesには、通常 **12文字の英数字** のserial numbersが付与されます。最初の3桁は製造場所を表し、続く **2桁** は製造年と製造週を示します。次の **3桁** は **unique** な **identifier** を提供し、最後の **4桁** は **model number** を表します。


{{#ref}}
macos-serial-number.md
{{#endref}}

## enrollmentおよびmanagementの手順

1. Device record creation (Reseller, Apple): 新しいdeviceのrecordが作成される
2. Device record assignment (Customer): deviceがMDM serverに割り当てられる
3. Device record sync (MDM vendor): MDMがdevice recordsをsyncし、DEP profilesをAppleへpushする
4. DEP check-in (Device): deviceがDEP profileを取得する
5. Profile retrieval (Device)
6. Profile installation (Device) a. MDM、SCEP、root CA payloadsを含む
7. MDM command issuance (Device)

![Serial Number - enrollmentおよびmanagementの手順: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` ファイルは、enrollment processの **high-level "steps"** とみなせるfunctionsをexportしています。

### Step 4: DEP check-in - Activation Recordの取得

このプロセスは、**userが初めてMacをbootしたとき** (または完全なwipe後) に発生します。

![enrollmentおよびmanagementの手順 - Step 4: DEP check-in - Activation Recordの取得: このプロセスは、userが初めてMacをbootしたとき、または完全な...](<../../../images/image (1044).png>)

または `sudo profiles show -type enrollment` を実行したときに発生します。

- **deviceがDEP enabledかどうか** を判断する
- Activation RecordはDEP「profile」の内部名称
- deviceがInternetに接続されるとすぐに開始される
- **`CPFetchActivationRecord`** によって駆動される
- XPC経由で **`cloudconfigurationd`** によって実装される。**"Setup Assistant**" (deviceの初回boot時) または **`profiles`** commandが、このdaemonに **contactして** activation recordを取得する。
- LaunchDaemon (常にrootとして実行)

Activation Recordの取得は **`MCTeslaConfigurationFetcher`** によっていくつかの手順で実行されます。このプロセスでは **Absinthe** というencryptionが使用されます。<sup>[1]</sup>

1. **certificate** を取得
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. certificateからstateを **Initialize** (**`NACInit`**)
1. さまざまなdevice固有データを使用 (例: **`IOKit`** 経由の **Serial Number**)
3. **session key** を取得
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. sessionを確立 (**`NACKeyEstablishment`**)
5. requestを実行
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) にPOSTし、データ `{ "action": "RequestProfileConfiguration", "sn": "" }` を送信
2. JSON payloadはAbsintheを使用してencryptedされる (**`NACSign`**)
3. すべてのrequestsはHTTPs経由で、built-in root certificatesが使用される

![enrollmentおよびmanagementの手順 - Step 4: DEP check-in - Activation Recordの取得: 3. すべてのrequestsはHTTPs経由で、built-in root certificatesが使用される](<../../../images/image (566) (1).png>)

responseは、以下のような重要なdataを含むJSON dictionaryです。

- **url**: activation profile用のMDM vendor hostのURL
- **anchor-certs**: trusted anchorsとして使用されるDER certificatesのarray

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Activation Recordの取得 - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- **DEP profileで提供されたurl** にrequestが送信される。
- 提供されている場合、**Anchor certificates** が **trustを評価** するために使用される。
- 注意: DEP profileの **anchor_certs** property
- **Requestはdevice identificationを含む単純な.plist**
- 例: **UDID、OS version**。
- CMS-signed、DER-encoded
- **device identity certificate (APNS由来)** を使用して署名される
- **Certificate chain** には期限切れの **Apple iPhone Device CA** が含まれる

![Step 4: DEP check-in - Activation Recordの取得 - Step 5: Profile Retrieval: Signed using the device identity certificate (from APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- 取得後、**profileはsystem上に保存される**
- このstepは ( **setup assistant** 内にある場合) 自動的に開始される
- **`CPInstallActivationProfile`** によって駆動される
- XPC経由でmdmclientにより実装される
- Contextに応じてLaunchDaemon (rootとして) またはLaunchAgent (userとして)
- Configuration profilesには、インストールする複数のpayloadsが存在する
- Frameworkはprofilesをインストールするためのplugin-based architectureを持つ
- 各payload typeはpluginに関連付けられている
- XPC (framework内) またはclassic Cocoa (ManagedClient.app) として実装可能
- 例:
- Certificate PayloadsはCertificateService.xpcを使用する

通常、MDM vendorが提供する **activation profile** には、以下のpayloadsが含まれます。

- `com.apple.mdm`: deviceをMDMに **enroll** する
- `com.apple.security.scep`: deviceへ **client certificate** を安全に提供する。
- `com.apple.security.pem`: deviceのSystem Keychainへtrusted CA certificatesを **install** する。
- MDM payloadのinstallは、documentationにおける **MDM check-in** に相当する
- Payloadには **key properties** が含まれる:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + trigger用のAPNs topic
- MDM payloadをinstallするため、requestが **`CheckInURL`** に送信される
- **`mdmclient`** によって実装される
- MDM payloadは他のpayloadsに依存できる
- **specific certificatesへのrequestsのpinning** が可能:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- PEM payload経由で配信される
- deviceにidentity certificateを付与できる:
- Property: IdentityCertificateUUID
- SCEP payload経由で配信される

### **Step 7: MDM commandsのlisten**

- MDM check-inの完了後、vendorは **APNsを使用してpush notificationsを発行** できる
- 受信時には **`mdmclient`** によって処理される
- MDM commandsをpollするため、requestがServerURLに送信される
- 以前にinstallされたMDM payloadを使用:
- **`ServerURLPinningCertificateUUIDs`** によるrequestのpinning
- TLS client certificate用の **`IdentityCertificateUUID`**

## Attacks

### 他の組織へのDevicesのenroll

前述のとおり、deviceを組織にenrollしようとするには、**その組織に属するSerial Numberだけが必要です**。deviceがenrollされると、多くの組織では新しいdeviceにsensitive dataをinstallします。これにはcertificates、applications、WiFi passwords、VPN configurations [など](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf) が含まれます。\
したがって、enrollment processが正しく保護されていない場合、これは攻撃者にとって危険なentrypointになる可能性があります:<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
