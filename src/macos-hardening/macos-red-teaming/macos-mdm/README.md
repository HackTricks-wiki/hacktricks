# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM について学ぶには、以下を参照してください:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## 基礎

### **MDM (Mobile Device Management) の概要**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) は、スマートフォン、ラップトップ、タブレットなど、さまざまなエンドユーザーデバイスを管理するために利用されます。特に Apple のプラットフォーム (iOS、macOS、tvOS) では、専門的な機能、API、プラクティスの集合として実装されています。MDM の運用には、商用またはオープンソースで提供され、[MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) をサポートする互換性のある MDM サーバーが必要です。主なポイントは以下のとおりです。

- デバイスを一元管理できる。
- MDM protocol に準拠した MDM サーバーに依存する。
- MDM サーバーからデバイスに、リモートデータ消去や設定のインストールなど、さまざまなコマンドを送信できる。

### **DEP (Device Enrollment Program) の基礎**

Apple が提供する [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) は、iOS、macOS、tvOS デバイスの zero-touch configuration を可能にすることで、Mobile Device Management (MDM) の導入を効率化します。DEP は enrollment process を自動化し、ユーザーや管理者による介入を最小限に抑えながら、デバイスを箱から出してすぐに利用できる状態にします。主な要素は以下のとおりです。

- 初回アクティベーション時に、デバイスが事前定義された MDM サーバーへ自動的に登録できる。
- 主に新品のデバイスに有用だが、再構成中のデバイスにも適用できる。
- 簡単なセットアップを実現し、デバイスを組織で迅速に利用できる状態にする。

### **セキュリティ上の考慮事項**

DEP による enrollment の容易さは有益である一方、セキュリティリスクにもなり得る点に注意が必要です。MDM enrollment に対する保護対策が適切に強制されていない場合、攻撃者はこの簡略化されたプロセスを悪用して、自身のデバイスを組織の MDM サーバーに登録し、企業デバイスになりすます可能性があります。<sup>[[2]](#references)</sup>

> [!CAUTION]
> **セキュリティ警告**: 適切な保護対策が存在しない場合、簡略化された DEP enrollment によって、未承認のデバイスが組織の MDM サーバーに登録される可能性があります。

### SCEP (Simple Certificate Enrolment Protocol) とは？

- TLS や HTTPS が普及する前に作成された、比較的古い protocol。
- クライアントに証明書を付与する目的で、**Certificate Signing Request** (CSR) を送信する標準化された方法を提供する。クライアントはサーバーに署名済み証明書の発行を要求する。

### Configuration Profiles (別名 mobileconfigs) とは？

- **システム設定を指定・強制する** Apple 公式の方法。
- 複数の payloads を含められるファイル形式。
- property lists (XML 形式) に基づく。
- 「origin を検証し、integrity を確保し、contents を保護するために、署名および暗号化できる。」Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers) の組み合わせ
- **Communication** は **device** と、**device** **management** **product** に関連付けられたサーバーの間で行われる
- **Commands** は **plist-encoded dictionaries** として MDM からデバイスへ配信される
- すべて **HTTPS** 経由。MDM サーバーは pinning される場合があり、通常は pinning されている。
- Apple は認証用に MDM vendor へ **APNs certificate** を付与する

### DEP

- **3 APIs**: reseller 用 1 つ、MDM vendor 用 1 つ、device identity 用 1 つ (undocumented):
- いわゆる [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。これは MDM サーバーが DEP profiles を特定のデバイスに関連付けるために使用される。
- [Apple Authorized Resellers が使用する DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)。デバイスの enrollment、enrollment status の確認、transaction status の確認に使用される。
- undocumented private DEP API。Apple Devices が DEP profile を要求するために使用される。macOS では、`cloudconfigurationd` binary がこの API 経由の通信を担当する。
- より modern で **JSON** ベース (plist と比較して)
- Apple は MDM vendor に **OAuth token** を付与する

**DEP "cloud service" API**

- RESTful
- Apple から MDM サーバーへ device records を sync する
- MDM サーバーから Apple へ “DEP profiles” を sync する (後で Apple によりデバイスへ配信される)
- DEP “profile” には以下が含まれる:
- MDM vendor server URL
- server URL 用の Additional trusted certificates (optional pinning)
- Extra settings (例: Setup Assistant でスキップする screens)

## Serial Number

2010 年以降に製造された Apple デバイスには、一般的に **12-character alphanumeric** の serial numbers が付与されます。**最初の 3 桁は製造場所**を表し、続く **2 桁は製造年**と**製造週**を示し、次の **3 桁は固有の** **identifier** を提供し、**最後の 4 桁は model number** を表します。


{{#ref}}
macos-serial-number.md
{{#endref}}

## Enrolment と management の手順

1. Device record creation (Reseller, Apple): 新しいデバイスの record が作成される
2. Device record assignment (Customer): デバイスが MDM サーバーに割り当てられる
3. Device record sync (MDM vendor): MDM が device records を sync し、DEP profiles を Apple へ push する
4. DEP check-in (Device): デバイスが DEP profile を取得する
5. Profile retrieval (Device)
6. Profile installation (Device) a. MDM、SCEP、root CA payloads を含む
7. MDM command issuance (Device)

![Serial Number - Enrolment と management の手順: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

ファイル `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` は、enrolment process の **high-level "steps"** とみなせる functions を export しています。

### Step 4: DEP check-in - Activation Record の取得

この process は、**user が Mac を初めて boot したとき** (または完全に wipe した後) に発生します。

![Enrolment と management の手順 - Step 4: DEP check-in - Activation Record の取得: この process は user が Mac を初めて boot したとき、または完全に...](<../../../images/image (1044).png>)

または `sudo profiles show -type enrollment` を実行したときに発生します。

- **device が DEP enabled かどうか**を判定する
- Activation Record は DEP “profile” の内部名称
- device が Internet に接続されるとすぐに開始される
- **`CPFetchActivationRecord`** により駆動される
- XPC 経由で **`cloudconfigurationd`** により実装される。**"Setup Assistant**" (device が最初に boot されたとき) または **`profiles`** command が、この daemon に **contact して** activation record を取得する。
- LaunchDaemon (常に root として実行)

Activation Record の取得には、**`MCTeslaConfigurationFetcher`** によって実行されるいくつかの steps が存在します。この process では **Absinthe** という encryption が使用されます。<sup>[[1]](#references)</sup>

1. **certificate** を retrieve
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. certificate から state を **initialize** (**`NACInit`**)
1. さまざまな device-specific data を使用する (例: **`IOKit`** 経由の **Serial Number**)
3. **session key** を retrieve
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. session を establish (**`NACKeyEstablishment`**)
5. request を実行
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) へ POST し、`{ "action": "RequestProfileConfiguration", "sn": "" }` の data を送信する
2. JSON payload は Absinthe (**`NACSign`**) を使用して encrypted される
3. すべての requests は HTTPs 経由で実行され、built-in root certificates が使用される

![Enrolment と management の手順 - Step 4: DEP check-in - Activation Record の取得: 3. すべての requests は HTTPs 経由で実行され、built-in root certificates が使用される](<../../../images/image (566) (1).png>)

response は、以下のような重要な data を含む JSON dictionary です。

- **url**: activation profile 用の MDM vendor host の URL
- **anchor-certs**: trusted anchors として使用される DER certificates の Array

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Activation Record の取得 - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- **DEP profile で提供された url** に request が送信される。
- 提供されている場合、**Anchor certificates** が **trust を evaluate** するために使用される。
- Reminder: DEP profile の **anchor_certs** property
- **Request は device identification を含む単純な .plist**
- 例: **UDID、OS version**。
- CMS-signed、DER-encoded
- **device identity certificate (from APNS)** を使用して signed される
- **Certificate chain** には期限切れの **Apple iPhone Device CA** が含まれる

![Step 4: DEP check-in - Activation Record の取得 - Step 5: Profile Retrieval: device identity certificate (from APNS) を使用して Signed される](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- 取得されると、**profile は system に stored される**
- この step は ( **setup assistant** 内の場合) 自動的に開始される
- **`CPInstallActivationProfile`** により駆動される
- XPC 経由で mdmclient により実装される
- context に応じて LaunchDaemon (root として) または LaunchAgent (user として)
- Configuration profiles には install する複数の payloads がある
- Framework は profiles を install するための plugin-based architecture を持つ
- 各 payload type は plugin に関連付けられる
- XPC (framework 内) または classic Cocoa (ManagedClient.app) にできる
- 例:
- Certificate Payloads は CertificateService.xpc を使用する

通常、MDM vendor が提供する **activation profile** には以下の payloads が含まれます。

- `com.apple.mdm`: device を MDM に **enroll** する
- `com.apple.security.scep`: **client certificate** を device に secure に提供する。
- `com.apple.security.pem`: trusted CA certificates を device の System Keychain に **install** する。
- MDM payload の install は **documentation における MDM check-in と同等**
- Payload には **key properties** が含まれる:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + それを trigger する APNs topic
- MDM payload を install するため、request は **`CheckInURL`** に送信される
- **`mdmclient`** により実装される
- MDM payload は他の payloads に依存できる
- **specific certificates に requests を pin** できる:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- PEM payload 経由で配信される
- device に identity certificate を付与できる:
- Property: IdentityCertificateUUID
- SCEP payload 経由で配信される

### **Step 7: MDM commands の listen**

- MDM check-in が完了すると、vendor は **APNs を使用して push notifications を issue** できる
- 受信時は **`mdmclient`** が handle する
- MDM commands を poll するため、request は ServerURL に送信される
- 以前 install された MDM payload を使用する:
- **`ServerURLPinningCertificateUUIDs`** で request を pinning する
- **`IdentityCertificateUUID`** で TLS client certificate を使用する

## Attacks

### 他の組織への Devices の Enrolling

前述のとおり、device を組織に **enroll** しようとするには、その組織に属する **Serial Number だけが必要**です。device が enroll されると、多くの組織は新しい device に sensitive data を install します。これには certificates、applications、WiFi passwords、VPN configurations [など](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf) が含まれます。\
したがって、enrollment process が適切に保護されていない場合、これは攻撃者にとって危険な entrypoint となる可能性があります。<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
