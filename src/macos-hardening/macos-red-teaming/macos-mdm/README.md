# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM에 대해 알아보려면 확인:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 기본

### **MDM (Mobile Device Management) 개요**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM)은 스마트폰, 노트북, 태블릿 등 다양한 엔드유저 디바이스를 관리하기 위해 사용됩니다. 특히 Apple 플랫폼(iOS, macOS, tvOS)에 대해 특화된 기능, API 및 관행을 포함합니다. MDM의 운영은 상용 또는 오픈소스의 호환되는 MDM 서버에 의존하며, 해당 서버는 [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)을 지원해야 합니다. 주요 내용은 다음과 같습니다:

- 디바이스에 대한 중앙 집중식 제어.
- MDM 프로토콜을 준수하는 MDM 서버에 의존.
- MDM 서버는 원격 데이터 삭제나 구성 설치와 같은 다양한 명령을 디바이스로 전송할 수 있음.

### **DEP (Device Enrollment Program) 기초**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP)은 Apple이 제공하는 것으로, iOS, macOS, tvOS 디바이스의 MDM 통합을 자동화하여 제로 터치 설정을 가능하게 합니다. DEP는 등록 프로세스를 자동화하여 디바이스가 박스에서 꺼내자마자 최소한의 사용자/관리자 개입으로 운영될 수 있게 합니다. 핵심 사항은 다음과 같습니다:

- 디바이스가 초기 활성화 시 미리 정의된 MDM 서버에 자동으로 등록되도록 허용.
- 주로 새 디바이스에 유용하지만 재구성되는 디바이스에도 적용 가능.
- 간단한 설정으로 조직에서 빠르게 사용 준비를 할 수 있게 함.

### **보안 고려사항**

DEP가 제공하는 간편한 등록은 유용하지만 보안 리스크를 동반할 수 있다는 점에 유의해야 합니다. MDM 등록에 대한 적절한 보호조치가 없다면 공격자가 이 간소화된 절차를 악용하여 조직의 MDM 서버에 자신의 디바이스를 기업 디바이스로 가장하여 등록할 수 있습니다.

> [!CAUTION]
> **보안 경고**: DEP의 간편한 등록 절차는 적절한 보호 장치가 없을 경우, 승인되지 않은 디바이스가 조직의 MDM 서버에 등록될 수 있게 할 수 있습니다.

### SCEP (Simple Certificate Enrolment Protocol)란?

- TLS와 HTTPS가 널리 보급되기 전 만들어진 비교적 오래된 프로토콜.
- 클라이언트가 인증서를 발급받기 위해 **Certificate Signing Request**(CSR)를 표준화된 방식으로 서버에 전송할 수 있게 함. 클라이언트는 서버에 서명된 인증서를 요청함.

### Configuration Profiles (aka mobileconfigs)란?

- Apple이 시스템 구성을 설정/강제하기 위해 제공하는 공식 방식.
- 여러 페이로드를 포함할 수 있는 파일 포맷.
- property lists(XML 형식)를 기반으로 함.
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” — Basics — Page 70, iOS Security Guide, January 2018.

## 프로토콜

### MDM

- APNs(**Apple server**s) + RESTful API(**MDM** **vendor** servers)의 결합
- **device**와 해당 **device management product**에 연동된 서버 간의 **통신**
- **Commands**는 **plist-encoded dictionaries** 형태로 MDM에서 디바이스로 전달됨
- 모두 **HTTPS**로 통신. MDM 서버는 (일반적으로) pinning 되어 있을 수 있음.
- Apple은 인증을 위해 MDM 벤더에 **APNs certificate**를 발급함

### DEP

- **3개의 API**: 리셀러용 1개, MDM 벤더용 1개, 디바이스 신원용(비공개) 1개
- 소위 말하는 [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM 서버가 DEP 프로파일을 특정 디바이스와 연동하기 위해 사용됨.
- [Apple Authorized Resellers가 사용하는 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)로 디바이스 등록, 등록 상태 확인, 트랜잭션 상태 확인 등에 사용됨.
- 비공개의 undocumented DEP API. Apple 디바이스가 자신의 DEP 프로파일을 요청하는 데 사용됨. macOS에서는 `cloudconfigurationd` 바이너리가 이 API와 통신을 담당.
- plist 대비 보다 현대적이고 **JSON** 기반
- Apple은 MDM 벤더에 **OAuth token**을 발급함

**DEP "cloud service" API**

- RESTful
- Apple에서 MDM 서버로 디바이스 레코드를 동기화
- MDM 서버에서 Apple로 “DEP profiles”을 동기화(나중에 Apple이 디바이스에 전달)
- DEP “profile”에는 다음이 포함됨:
  - MDM vendor 서버 URL
  - 서버 URL에 대한 추가 신뢰 인증서(선택적 pinning)
  - 추가 설정(예: Setup Assistant에서 건너뛸 화면들)

## 시리얼 번호

2010년 이후 제조된 Apple 디바이스는 일반적으로 **12글자의 영숫자** 시리얼 번호를 가지며, 처음 **3자리**는 제조 위치, 다음 **2자리**는 제조 연도 및 주, 다음 **3자리**는 고유 식별자, 마지막 **4자리**는 모델 번호를 나타냅니다.

{{#ref}}
macos-serial-number.md
{{#endref}}

## 등록 및 관리 절차

1. Device record 생성(Reseller, Apple): 새 디바이스의 레코드가 생성됨
2. Device record 할당(Customer): 디바이스가 MDM 서버에 할당됨
3. Device record 동기화(MDM vendor): MDM은 디바이스 레코드를 동기화하고 DEP 프로파일을 Apple에 푸시함
4. DEP 체크인(Device): 디바이스가 자신의 DEP 프로파일을 가져옴
5. Profile retrieval(Device)
6. Profile 설치(Device) — 예: MDM, SCEP 및 root CA 페이로드 포함
7. MDM 명령 발행(Device)

![](<../../../images/image (694).png>)

파일 `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`는 등록 프로세스의 고수준 "단계"로 간주될 수 있는 함수들을 export합니다.

### Step 4: DEP 체크인 - Activation Record 얻기

이 단계는 사용자가 Mac을 처음 부팅할 때(또는 완전 초기화 후) 발생합니다.

![](<../../../images/image (1044).png>)

또는 `sudo profiles show -type enrollment` 실행 시에도 발생

- **디바이스가 DEP 활성화인지 여부 판단**
- Activation Record는 내부적으로 **DEP “profile”**의 명칭임
- 디바이스가 인터넷에 연결되는 즉시 시작됨
- **`CPFetchActivationRecord`**에 의해 구동
- **`cloudconfigurationd`**가 XPC를 통해 구현. **Setup Assistant**(디바이스가 처음 부팅될 때)나 `profiles` 명령이 이 데몬에 연락해 activation record를 가져옴.
- LaunchDaemon(항상 root로 실행)

Activation Record를 얻기 위해 **`MCTeslaConfigurationFetcher`**가 수행하는 몇 단계가 있으며, 이 과정은 **Absinthe**라는 암호화를 사용합니다.

1. **certificate** 가져오기
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 인증서로부터 상태 초기화(**`NACInit`**)
   1. 다양한 디바이스 특정 데이터를 사용(예: **Serial Number via `IOKit`**)
3. **session key** 가져오기
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 세션 수립(**`NACKeyEstablishment`**)
5. 요청 수행
   1. POST to [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) 에 데이터 `{ "action": "RequestProfileConfiguration", "sn": "" }` 전송
   2. JSON 페이로드는 Absinthe(**`NACSign`**)로 암호화됨
   3. 모든 요청은 HTTPS, 내장된 루트 인증서를 사용

![](<../../../images/image (566) (1).png>)

응답은 다음과 같은 중요한 데이터를 포함하는 JSON 딕셔너리입니다:

- **url**: activation profile을 제공하는 MDM vendor 호스트의 URL
- **anchor-certs**: 신뢰 앵커로 사용되는 DER 인증서 배열

### **Step 5: Profile Retrieval**

![](<../../../images/image (444).png>)

- 요청은 **DEP 프로파일에 제공된 url**로 전송됨.
- **Anchor certificates**가 제공되면 신뢰 평가에 사용됨.
- 참고: DEP 프로파일의 **anchor_certs** 속성
- **요청은 간단한 .plist**로 디바이스 식별 정보를 담음
- 예: **UDID, OS version**
- CMS-signed, DER-encoded
- APNS의 **device identity certificate**로 서명됨
- **Certificate chain**에는 만료된 **Apple iPhone Device CA**가 포함될 수 있음

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- 일단 받아오면 **프로파일은 시스템에 저장됨**
- 이 단계는 (Setup Assistant인 경우) 자동으로 시작됨
- **`CPInstallActivationProfile`**에 의해 구동
- mdmclient가 XPC를 통해 구현
- 컨텍스트에 따라 LaunchDaemon(root) 또는 LaunchAgent(사용자)로 실행
- Configuration profiles은 설치할 여러 페이로드를 가짐
- 프레임워크는 플러그인 기반 아키텍처로 페이로드를 설치
- 각 페이로드 타입은 플러그인과 연동
- 프레임워크 내부의 XPC이거나 전통적 Cocoa(ManagedClient.app)일 수 있음
- 예시:
  - Certificate Payloads는 CertificateService.xpc 사용

일반적으로 MDM 벤더가 제공하는 **activation profile**에는 다음과 같은 페이로드가 포함됩니다:

- `com.apple.mdm`: 디바이스를 MDM에 **enroll**하기 위한 페이로드
- `com.apple.security.scep`: 디바이스에 **client certificate**를 안전하게 제공하기 위한 SCEP 페이로드
- `com.apple.security.pem`: 시스템 키체인에 **trusted CA 인증서**를 설치하기 위한 PEM 페이로드
- MDM 페이로드 설치는 문서상의 **MDM check-in**에 해당
- 페이로드는 다음과 같은 주요 속성을 포함:
  - MDM Check-In URL(**`CheckInURL`**)
  - MDM Command Polling URL(**`ServerURL`**) + 이를 트리거하는 APNs topic
- MDM 페이로드를 설치하려면 요청이 **`CheckInURL`**로 전송됨
- **`mdmclient`**에서 구현
- MDM 페이로드는 다른 페이로드에 의존할 수 있음
- 특정 인증서에 요청을 pinning하도록 허용:
  - 속성: **`CheckInURLPinningCertificateUUIDs`**
  - 속성: **`ServerURLPinningCertificateUUIDs`**
  - PEM 페이로드를 통해 전달됨
- 디바이스에 identity certificate를 부여할 수 있음:
  - 속성: IdentityCertificateUUID
  - SCEP 페이로드를 통해 전달됨

### Step 7: Listening for MDM commands

- MDM 체크인이 완료되면, 벤더는 **APNs를 사용해 푸시 알림을 발행**할 수 있음
- 수신 시 **`mdmclient`**가 처리
- MDM 명령을 폴링하려면 요청이 ServerURL로 전송됨
- 이전에 설치된 MDM 페이로드를 사용:
  - **`ServerURLPinningCertificateUUIDs`**로 요청 pinning
  - **`IdentityCertificateUUID`**로 TLS 클라이언트 인증서 사용

## 공격

### 다른 조직에 디바이스 등록

앞서 언급한 바와 같이, 디바이스를 어떤 조직에 등록하려고 시도할 때에는 **그 조직에 속한 Serial Number만 있으면** 됩니다. 일단 디바이스가 등록되면 여러 조직은 새 디바이스에 민감한 데이터를 설치할 수 있습니다: 인증서, 애플리케이션, WiFi 비밀번호, VPN 구성 등([and so on](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)).\
따라서 등록 프로세스가 적절히 보호되지 않으면 이는 공격자에게 위험한 진입점이 될 수 있습니다.

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
