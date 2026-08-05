# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM에 대해 알아보려면 다음을 확인하세요:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 기본 사항

### **MDM (Mobile Device Management) 개요**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management)(MDM)은 스마트폰, 노트북, 태블릿과 같은 다양한 최종 사용자 기기를 관리하는 데 사용됩니다. 특히 Apple 플랫폼(iOS, macOS, tvOS)에서는 일련의 특수 기능, API 및 관행을 포함합니다. MDM의 동작은 호환 가능한 MDM 서버에 의존하며, 이 서버는 상용 또는 open-source 형태로 제공되고 [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)을 지원해야 합니다. 주요 사항은 다음과 같습니다.

- 기기에 대한 중앙 집중식 제어.
- MDM protocol을 준수하는 MDM 서버에 대한 의존성.
- MDM 서버가 원격 데이터 삭제 또는 configuration 설치와 같은 다양한 명령을 기기로 전송할 수 있는 기능.

### **DEP (Device Enrollment Program) 기본 사항**

Apple이 제공하는 [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf)(DEP)은 iOS, macOS 및 tvOS 기기의 zero-touch configuration을 지원하여 Mobile Device Management(MDM) 통합을 간소화합니다. DEP는 enrollment 프로세스를 자동화하여 사용자의 개입이나 관리자의 개입을 최소화하고 기기를 개봉 직후 사용할 수 있도록 합니다. 주요 사항은 다음과 같습니다.

- 최초 활성화 시 기기가 사전 정의된 MDM 서버에 자동으로 등록되도록 지원.
- 주로 새 기기에 유용하지만, 재구성 중인 기기에도 적용 가능.
- 간단한 setup을 지원하여 기기를 조직에서 신속하게 사용할 수 있도록 함.

### **보안 고려 사항**

DEP가 제공하는 간편한 enrollment는 유용하지만 보안 위험을 초래할 수도 있습니다. MDM enrollment에 대한 보호 조치가 충분히 적용되지 않으면 공격자가 이 간소화된 프로세스를 악용하여 조직의 MDM 서버에 자신의 기기를 등록하고 corporate device로 가장할 수 있습니다.<sup>[2]</sup>

> [!CAUTION]
> **보안 경고**: 적절한 보호 조치가 없으면 간소화된 DEP enrollment를 통해 승인되지 않은 기기가 조직의 MDM 서버에 등록될 수 있습니다.

### SCEP (Simple Certificate Enrolment Protocol)란 무엇인가?

- TLS와 HTTPS가 널리 사용되기 전에 만들어진 비교적 오래된 protocol.
- 클라이언트가 certificate를 발급받기 위한 **Certificate Signing Request**(CSR)를 표준화된 방식으로 전송할 수 있도록 함. 클라이언트는 서버에 서명된 certificate를 요청함.

### Configuration Profiles(일명 mobileconfigs)란 무엇인가?

- **system configuration을 설정하고 강제하는** Apple의 공식 방식.
- 여러 payload를 포함할 수 있는 file format.
- property lists(XML 형식)를 기반으로 함.
- “origin을 검증하고, integrity를 보장하며, contents를 보호하기 위해 서명 및 암호화할 수 있음.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- APNs(**Apple server**) + RESTful API(**MDM** **vendor** servers)의 조합
- **Communication**은 **device**와 **device** **management** **product**에 연결된 서버 사이에서 이루어짐
- MDM에서 기기로 전달되는 **Commands**는 **plist-encoded dictionaries** 형식임
- 모두 **HTTPS**를 사용함. MDM servers는 pinning될 수 있으며, 일반적으로 pinning됨.
- Apple은 authentication을 위해 MDM vendor에 **APNs certificate**를 발급함

### DEP

- **3개의 API**: reseller용 1개, MDM vendor용 1개, device identity용 1개(undocumented):
- 이른바 [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM servers가 DEP profiles를 특정 devices와 연결하는 데 사용됨.
- [Apple Authorized Resellers가 사용하는 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html). devices를 enroll하고, enrollment status를 확인하며, transaction status를 확인하는 데 사용됨.
- undocumented private DEP API. Apple Devices가 자신의 DEP profile을 요청하는 데 사용됨. macOS에서는 `cloudconfigurationd` binary가 이 API를 통한 communication을 담당함.
- 더 modern하고 **JSON** 기반임(plist와 비교)
- Apple은 MDM vendor에 **OAuth token**을 발급함

**DEP "cloud service" API**

- RESTful
- Apple에서 MDM server로 device records를 sync
- MDM server에서 Apple로 “DEP profiles”를 sync(이후 Apple이 device에 전달)
- DEP “profile”에는 다음이 포함됨:
- MDM vendor server URL
- server URL에 대한 추가 trusted certificates(선택적 pinning)
- 추가 settings(예: Setup Assistant에서 건너뛸 screens)

## Serial Number

2010년 이후 제조된 Apple devices는 일반적으로 **12-character alphanumeric** serial numbers를 사용합니다. **처음 세 자리 숫자는 제조 위치**, 그 다음 **두 자리는 제조 연도**와 **주차**, 다음 **세 자리 숫자는 고유한** **identifier**, **마지막 네 자리 숫자는 model number**를 나타냅니다.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Enrolment 및 management 단계

1. Device record creation (Reseller, Apple): 새 device의 record가 생성됨
2. Device record assignment (Customer): device가 MDM server에 할당됨
3. Device record sync (MDM vendor): MDM이 device records를 sync하고 DEP profiles를 Apple로 push함
4. DEP check-in (Device): device가 자신의 DEP profile을 가져옴
5. Profile retrieval (Device)
6. Profile installation (Device) a. MDM, SCEP 및 root CA payloads 포함
7. MDM command issuance (Device)

![Serial Number - Enrolment 및 management 단계: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` 파일은 enrollment process의 **high-level "steps"**로 간주할 수 있는 functions를 export합니다.

### Step 4: DEP check-in - Activation Record 가져오기

이 process는 **user가 Mac을 처음 boot할 때**(또는 complete wipe 이후) 발생합니다.

![Enrolment 및 management 단계 - Step 4: DEP check-in - Activation Record 가져오기: 이 process는 user가 Mac을 처음 boot할 때(또는 complete...](<../../../images/image (1044).png>)

또는 `sudo profiles show -type enrollment`을 실행할 때 발생합니다.

- **device가 DEP enabled인지** 확인
- Activation Record는 **DEP “profile”**의 internal name임
- device가 Internet에 연결되는 즉시 시작됨
- **`CPFetchActivationRecord`**에 의해 구동됨
- XPC를 통해 **`cloudconfigurationd`**가 구현함. device가 처음 boot될 때 실행되는 **"Setup Assistant**" 또는 **`profiles`** command가 이 daemon에 **contact하여** activation record를 가져옴.
- LaunchDaemon(root로 항상 실행)

Activation Record를 가져오기 위해 **`MCTeslaConfigurationFetcher`**가 수행하는 몇 가지 단계를 따릅니다. 이 process는 **Absinthe**라는 encryption을 사용합니다.<sup>[1]</sup>

1. **certificate** 가져오기
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. certificate에서 state **initialize**(**`NACInit`**)
1. 다양한 device-specific data 사용(예: **`IOKit`**을 통한 **Serial Number**)
3. **session key** 가져오기
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. session 수립(**`NACKeyEstablishment`**)
5. request 수행
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)에 POST하고 `{ "action": "RequestProfileConfiguration", "sn": "" }` data 전송
2. JSON payload는 Absinthe를 사용해 encryption됨(**`NACSign`**)
3. 모든 requests는 HTTPs를 사용하며, built-in root certificates가 사용됨

![Enrolment 및 management 단계 - Step 4: DEP check-in - Activation Record 가져오기: 3. 모든 requests는 HTTPs를 사용하며, built-in root certificates가 사용됨](<../../../images/image (566) (1).png>)

response는 다음과 같은 중요한 data를 포함하는 JSON dictionary입니다.

- **url**: activation profile을 제공하는 MDM vendor host의 URL
- **anchor-certs**: trusted anchors로 사용되는 DER certificates의 Array

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Activation Record 가져오기 - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- **DEP profile에 제공된 url**로 request 전송.
- 제공된 경우 **anchor certificates**를 사용하여 **trust 평가**.
- 참고: DEP profile의 **anchor_certs** property
- **Request는 device identification이 포함된 단순한 .plist**
- 예: **UDID, OS version**.
- CMS-signed, DER-encoded
- **device identity certificate(APNS에서 가져옴)**를 사용하여 서명됨
- **Certificate chain**에는 만료된 **Apple iPhone Device CA**가 포함됨

![Step 4: DEP check-in - Activation Record 가져오기 - Step 5: Profile Retrieval: device identity certificate(APNS에서 가져옴)를 사용하여 서명됨](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- 가져온 후 **profile은 system에 저장됨**
- 이 단계는(**setup assistant**에 있는 경우) 자동으로 시작됨
- **`CPInstallActivationProfile`**에 의해 구동됨
- XPC를 통해 mdmclient가 구현함
- context에 따라 LaunchDaemon(root 권한) 또는 LaunchAgent(user 권한)
- Configuration profiles에는 설치할 여러 payloads가 있음
- Framework는 profiles 설치를 위한 plugin-based architecture를 사용함
- 각 payload type은 plugin과 연결됨
- XPC(framework 내) 또는 classic Cocoa(ManagedClient.app)일 수 있음
- 예:
- Certificate Payloads는 CertificateService.xpc를 사용함

일반적으로 MDM vendor가 제공하는 **activation profile**에는 다음 payloads가 포함됩니다.

- `com.apple.mdm`: device를 MDM에 **enroll**하기 위한 payload
- `com.apple.security.scep`: **client certificate**를 device에 안전하게 제공하기 위한 payload
- `com.apple.security.pem`: trusted CA certificates를 device의 System Keychain에 **install**하기 위한 payload
- MDM payload 설치는 documentation에서 설명하는 **MDM check-in**에 해당함
- Payload에는 **key properties**가 포함됨:
- - MDM Check-In URL(**`CheckInURL`**)
- MDM Command Polling URL(**`ServerURL`**) + 이를 trigger하기 위한 APNs topic
- MDM payload를 설치하기 위해 **`CheckInURL`**로 request 전송
- **`mdmclient`**에 의해 구현됨
- MDM payload는 다른 payloads에 의존할 수 있음
- 특정 certificates에 request를 pinning할 수 있음:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- PEM payload를 통해 전달됨
- device에 identity certificate를 부여할 수 있음:
- Property: IdentityCertificateUUID
- SCEP payload를 통해 전달됨

### **Step 7: MDM commands 수신 대기**

- MDM check-in이 완료되면 vendor는 **APNs를 사용하여 push notifications를 발행**할 수 있음
- 수신 시 **`mdmclient`**가 처리함
- MDM commands를 poll하기 위해 ServerURL로 request 전송
- 이전에 설치된 MDM payload를 사용함:
- **`ServerURLPinningCertificateUUIDs`**: request pinning용
- **`IdentityCertificateUUID`**: TLS client certificate용

## Attacks

### 다른 조직에 Devices Enrolling

앞서 설명했듯이, device를 조직에 enroll하기 위해서는 **해당 Organization에 속한 Serial Number만 필요합니다**. device가 enroll되면 여러 organizations가 certificates, applications, WiFi passwords, VPN configurations [and so on](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)과 같은 민감한 data를 새 device에 설치합니다.\
따라서 enrollment process가 올바르게 보호되지 않으면 attackers에게 위험한 entrypoint가 될 수 있습니다.<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
