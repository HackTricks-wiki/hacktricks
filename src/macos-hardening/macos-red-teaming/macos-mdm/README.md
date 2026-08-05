# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM에 대해 알아보려면 다음을 확인하세요:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 기본 사항

### **MDM (Mobile Device Management) 개요**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM)은 스마트폰, 노트북, 태블릿과 같은 다양한 최종 사용자 디바이스를 관리하는 데 사용됩니다. 특히 Apple 플랫폼(iOS, macOS, tvOS)에서는 특수 기능, API 및 운영 방식의 집합을 의미합니다. MDM은 호환 가능한 MDM 서버를 기반으로 동작하며, 해당 서버는 상용 또는 오픈소스일 수 있고 [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)을 지원해야 합니다. 주요 사항은 다음과 같습니다.

- 디바이스에 대한 중앙 집중식 제어
- MDM protocol을 준수하는 MDM 서버에 대한 의존성
- MDM 서버가 원격 데이터 삭제 또는 구성 설치와 같은 다양한 명령을 디바이스로 전달할 수 있음

### **DEP (Device Enrollment Program) 기본 사항**

Apple이 제공하는 [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP)은 iOS, macOS 및 tvOS 디바이스에 zero-touch 구성을 제공하여 Mobile Device Management (MDM) 통합을 간소화합니다. DEP는 enrollment 프로세스를 자동화하여 사용자의 개입이나 관리자의 조치를 최소화하면서 디바이스를 개봉 직후부터 사용할 수 있도록 합니다. 주요 사항은 다음과 같습니다.

- 최초 활성화 시 디바이스가 사전 정의된 MDM 서버에 자동으로 등록되도록 함
- 주로 새 디바이스에 유용하지만, 재구성 중인 디바이스에도 적용 가능
- 간단한 설정을 지원하여 디바이스를 조직에서 신속하게 사용할 수 있도록 함

### **보안 고려 사항**

DEP가 제공하는 간편한 enrollment는 유용하지만 보안 위험을 초래할 수도 있다는 점에 유의해야 합니다. MDM enrollment에 대한 보호 조치가 적절하게 적용되지 않으면 공격자가 이 간소화된 프로세스를 악용하여 조직의 MDM 서버에 자신의 디바이스를 등록하고 기업 디바이스로 위장할 수 있습니다.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **보안 경고**: 적절한 보호 조치가 없으면 간소화된 DEP enrollment를 통해 권한이 없는 디바이스가 조직의 MDM 서버에 등록될 수 있습니다.

### SCEP (Simple Certificate Enrolment Protocol)란 무엇인가?

- TLS와 HTTPS가 널리 사용되기 전에 만들어진 비교적 오래된 protocol
- 클라이언트가 인증서를 발급받기 위한 **Certificate Signing Request** (CSR)를 표준화된 방식으로 전송할 수 있도록 함. 클라이언트는 서버에 서명된 인증서를 요청함

### Configuration Profiles (mobileconfigs라고도 함)란 무엇인가?

- **시스템 구성을 설정/강제 적용하기 위한 Apple의 공식 방식**
- 여러 payload를 포함할 수 있는 파일 형식
- property lists(XML 형식)를 기반으로 함
- “origin을 검증하고, 무결성을 보장하며, contents를 보호하기 위해 서명 및 암호화할 수 있음.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- APNs(**Apple server**s) + RESTful API(**MDM** **vendor** 서버)의 조합
- **통신**은 **device**와 **device** **management** **product**에 연결된 서버 간에 이루어짐
- **명령**은 **MDM**에서 **device**로 **plist-encoded dictionaries** 형태로 전달됨
- 모두 **HTTPS**를 사용함. MDM 서버는 pinning될 수 있으며, 일반적으로 pinning됨
- Apple은 인증을 위해 MDM vendor에 **APNs certificate**를 발급함

### DEP

- **3개의 API**: reseller용 1개, MDM vendor용 1개, device identity용 1개(문서화되지 않음):
- 소위 [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM 서버가 DEP profile을 특정 디바이스와 연결하는 데 사용됨
- 디바이스를 enrollment하고, enrollment 상태를 확인하며, transaction 상태를 확인하기 위해 Apple Authorized Reseller가 사용하는 [DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)
- 문서화되지 않은 private DEP API. Apple Devices가 DEP profile을 요청하는 데 사용됨. macOS에서는 `cloudconfigurationd` binary가 이 API를 통한 통신을 담당함
- 더 현대적이며 **JSON** 기반(plist와 비교)
- Apple은 MDM vendor에 **OAuth token**을 발급함

**DEP "cloud service" API**

- RESTful
- Apple에서 MDM 서버로 device records를 sync
- MDM 서버에서 Apple로 “DEP profiles”를 sync (이후 Apple이 디바이스로 전달)
- DEP “profile”에는 다음이 포함됨:
- MDM vendor server URL
- server URL을 위한 추가 trusted certificates (선택적 pinning)
- 추가 설정(예: Setup Assistant에서 건너뛸 화면)

## Serial Number

2010년 이후 제조된 Apple 디바이스는 일반적으로 **12자리 영숫자** serial number를 사용합니다. 처음 세 자리는 **제조 위치**, 다음 두 자리는 제조 **연도**와 **주차**, 그다음 세 자리는 **고유** **identifier**, 마지막 **네 자리**는 **model number**를 나타냅니다.


{{#ref}}
macos-serial-number.md
{{#endref}}

## enrollment 및 management 단계

1. Device record creation (Reseller, Apple): 새 디바이스의 record가 생성됨
2. Device record assignment (Customer): 디바이스가 MDM 서버에 할당됨
3. Device record sync (MDM vendor): MDM이 device records를 sync하고 DEP profiles를 Apple로 push함
4. DEP check-in (Device): 디바이스가 DEP profile을 가져옴
5. Profile retrieval (Device)
6. Profile installation (Device) a. MDM, SCEP 및 root CA payloads 포함
7. MDM command issuance (Device)

![Serial Number - enrollment 및 management 단계: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` 파일은 enrollment 프로세스의 **high-level "steps"**로 간주할 수 있는 functions를 export합니다.

### Step 4: DEP check-in - Activation Record 가져오기

이 프로세스는 **사용자가 Mac을 처음 부팅할 때**(또는 완전히 wipe한 후) 발생합니다.

![enrollment 및 management 단계 - Step 4: DEP check-in - Activation Record 가져오기: 이 프로세스는 사용자가 Mac을 처음 부팅할 때 또는 완전히...](<../../../images/image (1044).png>)

또는 `sudo profiles show -type enrollment`을 실행할 때 발생합니다.

- **device가 DEP enabled인지** 확인
- Activation Record는 **DEP “profile”**의 내부 명칭
- device가 Internet에 연결되는 즉시 시작됨
- **`CPFetchActivationRecord`**에 의해 구동됨
- XPC를 통해 **`cloudconfigurationd`**가 구현함. **"Setup Assistant**"(device를 처음 boot할 때) 또는 **`profiles`** command가 이 daemon에 **contact하여** activation record를 가져옴
- LaunchDaemon (항상 root로 실행)

Activation Record를 가져오기 위해 **`MCTeslaConfigurationFetcher`**가 몇 가지 단계를 수행합니다. 이 프로세스는 **Absinthe**라는 encryption을 사용합니다.<sup>[[1]](#references)</sup>

1. **certificate** 가져오기
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. certificate에서 state **initialize** (**`NACInit`**)
1. 다양한 device-specific data 사용(예: **`IOKit`**을 통한 **Serial Number**)
3. **session key** 가져오기
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. session 수립 (**`NACKeyEstablishment`**)
5. request 수행
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)에 POST하며 `{ "action": "RequestProfileConfiguration", "sn": "" }` data 전송
2. JSON payload는 Absinthe를 사용하여 encryption됨(**`NACSign`**)
3. 모든 request는 HTTPs를 사용하며, built-in root certificates가 사용됨

![enrollment 및 management 단계 - Step 4: DEP check-in - Activation Record 가져오기: 3. 모든 request는 HTTPs를 사용하며, built-in root certificates가 사용됨](<../../../images/image (566) (1).png>)

응답은 다음과 같은 중요한 data를 포함하는 JSON dictionary입니다.

- **url**: activation profile을 위한 MDM vendor host의 URL
- **anchor-certs**: trusted anchors로 사용되는 DER certificates의 Array

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Activation Record 가져오기 - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- **DEP profile에 제공된 url**로 request 전송
- 제공된 경우 **Anchor certificates**를 사용하여 **trust 평가**
- 참고: DEP profile의 **anchor_certs** property
- **Request는 device identification을 포함하는 단순한 .plist**
- 예시: **UDID, OS version**
- CMS-signed, DER-encoded
- **APNS의 device identity certificate**를 사용하여 서명됨
- **Certificate chain**에 만료된 **Apple iPhone Device CA**가 포함됨

![Step 4: DEP check-in - Activation Record 가져오기 - Step 5: Profile Retrieval: APNS의 device identity certificate를 사용하여 서명됨](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- 가져온 후 **profile은 시스템에 저장됨**
- 이 단계는 **setup assistant**에서 자동으로 시작됨
- **`CPInstallActivationProfile`**에 의해 구동됨
- XPC를 통해 mdmclient가 구현함
- context에 따라 LaunchDaemon(root로 실행) 또는 LaunchAgent(user로 실행)
- Configuration profiles에는 설치할 여러 payload가 있음
- Framework는 profiles 설치를 위해 plugin-based architecture를 사용함
- 각 payload type은 plugin과 연결됨
- XPC(framework 내) 또는 classic Cocoa(ManagedClient.app 내)일 수 있음
- 예시:
- Certificate Payloads는 CertificateService.xpc를 사용함

일반적으로 MDM vendor가 제공하는 **activation profile**에는 다음 payload가 포함됩니다.

- `com.apple.mdm`: device를 MDM에 **enroll**하기 위한 payload
- `com.apple.security.scep`: device에 **client certificate**를 안전하게 제공하기 위한 payload
- `com.apple.security.pem`: device의 System Keychain에 trusted CA certificates를 **install**하기 위한 payload
- MDM payload 설치는 문서에서 설명하는 **MDM check-in**에 해당함
- Payload에는 **key properties**가 포함됨:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + 이를 trigger하기 위한 APNs topic
- MDM payload를 install하기 위해 request가 **`CheckInURL`**로 전송됨
- **`mdmclient`**가 구현함
- MDM payload는 다른 payload에 의존할 수 있음
- request를 특정 certificates에 pinning할 수 있음:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- PEM payload를 통해 전달됨
- device에 identity certificate를 할당할 수 있음:
- Property: IdentityCertificateUUID
- SCEP payload를 통해 전달됨

### **Step 7: MDM commands 수신 대기**

- MDM check-in이 완료되면 vendor는 **APNs를 사용하여 push notifications를 발행**할 수 있음
- 수신 시 **`mdmclient`**가 처리함
- MDM commands를 poll하기 위해 request가 ServerURL로 전송됨
- 이전에 설치된 MDM payload를 사용함:
- **`ServerURLPinningCertificateUUIDs`**는 request pinning에 사용됨
- **`IdentityCertificateUUID`**는 TLS client certificate에 사용됨

## Attacks

### 다른 조직에 Devices Enrolling

앞서 설명했듯이, device를 조직에 enroll하려면 **해당 조직에 속한 Serial Number 하나만 필요합니다**. device가 enroll되면 여러 조직이 새 device에 certificates, applications, WiFi passwords, VPN configurations [and so on](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)과 같은 민감한 data를 install합니다.\
따라서 enrollment process가 적절하게 보호되지 않는 경우 공격자에게 위험한 entrypoint가 될 수 있습니다.<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
