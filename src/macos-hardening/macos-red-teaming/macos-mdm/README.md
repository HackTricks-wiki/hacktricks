# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM에 대해 알아보려면 다음을 확인하세요:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 기본 사항

### **MDM (모바일 장치 관리) 개요**

[모바일 장치 관리](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM)은 스마트폰, 노트북 및 태블릿과 같은 다양한 최종 사용자 장치를 관리하는 데 사용됩니다. 특히 Apple의 플랫폼(iOS, macOS, tvOS)에서는 특수 기능, API 및 관행의 집합이 포함됩니다. MDM의 작동은 상용 또는 오픈 소스인 호환 MDM 서버에 의존하며, [MDM 프로토콜](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)을 지원해야 합니다. 주요 사항은 다음과 같습니다:

- 장치에 대한 중앙 집중식 제어.
- MDM 프로토콜을 준수하는 MDM 서버에 의존.
- MDM 서버가 원격 데이터 삭제 또는 구성 설치와 같은 다양한 명령을 장치에 전송할 수 있는 기능.

### **DEP (장치 등록 프로그램) 기본 사항**

Apple에서 제공하는 [장치 등록 프로그램](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP)은 iOS, macOS 및 tvOS 장치에 대한 제로 터치 구성을 용이하게 하여 모바일 장치 관리(MDM)의 통합을 간소화합니다. DEP는 등록 프로세스를 자동화하여 장치가 최소한의 사용자 또는 관리 개입으로 즉시 작동할 수 있도록 합니다. 필수 사항은 다음과 같습니다:

- 장치가 초기 활성화 시 미리 정의된 MDM 서버에 자율적으로 등록할 수 있도록 합니다.
- 주로 새 장치에 유용하지만 재구성 중인 장치에도 적용 가능합니다.
- 간단한 설정을 통해 장치를 신속하게 조직에서 사용할 수 있도록 합니다.

### **보안 고려 사항**

DEP가 제공하는 등록의 용이성은 유익하지만 보안 위험을 초래할 수 있습니다. MDM 등록에 대한 보호 조치가 적절하게 시행되지 않으면 공격자가 이 간소화된 프로세스를 악용하여 자신의 장치를 조직의 MDM 서버에 등록하고 기업 장치로 가장할 수 있습니다.

> [!CAUTION]
> **보안 경고**: 간소화된 DEP 등록은 적절한 보호 장치가 마련되지 않은 경우 조직의 MDM 서버에 무단 장치 등록을 허용할 수 있습니다.

### SCEP (간단한 인증서 등록 프로토콜)란 무엇인가요?

- TLS 및 HTTPS가 널리 퍼지기 전에 만들어진 비교적 오래된 프로토콜입니다.
- 클라이언트가 인증서를 부여받기 위해 **인증서 서명 요청** (CSR)을 보내는 표준화된 방법을 제공합니다. 클라이언트는 서버에 서명된 인증서를 요청합니다.

### 구성 프로파일(모바일 구성 파일)이란 무엇인가요?

- Apple의 공식적인 **시스템 구성 설정/강제 적용 방법**입니다.
- 여러 페이로드를 포함할 수 있는 파일 형식입니다.
- 속성 목록(XML 형식)을 기반으로 합니다.
- “출처를 검증하고 무결성을 보장하며 내용을 보호하기 위해 서명 및 암호화될 수 있습니다.” 기본 사항 — 페이지 70, iOS 보안 가이드, 2018년 1월.

## 프로토콜

### MDM

- APNs (**Apple 서버**) + RESTful API (**MDM** **공급업체** 서버)의 조합
- **통신**은 **장치**와 **장치 관리** **제품**과 관련된 서버 간에 발생합니다.
- **명령**은 MDM에서 장치로 **plist 인코딩된 사전**으로 전달됩니다.
- 모두 **HTTPS**를 통해 이루어집니다. MDM 서버는 (대개) 핀 고정됩니다.
- Apple은 인증을 위해 MDM 공급업체에 **APNs 인증서**를 부여합니다.

### DEP

- **3개의 API**: 1개는 리셀러용, 1개는 MDM 공급업체용, 1개는 장치 ID용(문서화되지 않음):
- 소위 [DEP "클라우드 서비스" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM 서버가 DEP 프로파일을 특정 장치와 연결하는 데 사용됩니다.
- [Apple 공인 리셀러가 사용하는 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)로 장치를 등록하고, 등록 상태를 확인하며, 거래 상태를 확인합니다.
- 문서화되지 않은 개인 DEP API. Apple 장치가 자신의 DEP 프로파일을 요청하는 데 사용됩니다. macOS에서는 `cloudconfigurationd` 바이너리가 이 API를 통해 통신하는 역할을 합니다.
- 더 현대적이고 **JSON** 기반입니다(대비 plist).
- Apple은 MDM 공급업체에 **OAuth 토큰**을 부여합니다.

**DEP "클라우드 서비스" API**

- RESTful
- Apple에서 MDM 서버로 장치 기록 동기화
- MDM 서버에서 Apple로 “DEP 프로파일” 동기화(나중에 장치에 전달됨)
- DEP “프로파일”에는 다음이 포함됩니다:
- MDM 공급업체 서버 URL
- 서버 URL에 대한 추가 신뢰할 수 있는 인증서(선택적 핀 고정)
- 추가 설정(예: 설정 도우미에서 건너뛸 화면)

## 일련 번호

2010년 이후 제조된 Apple 장치는 일반적으로 **12자리 알phanumeric** 일련 번호를 가지며, **첫 세 자리는 제조 위치**를 나타내고, 다음 **두 자리는** 제조 **연도**와 **주**를 나타내며, 다음 **세 자리는** **고유 식별자**를 제공하고, **마지막 네 자리는** **모델 번호**를 나타냅니다.

{{#ref}}
macos-serial-number.md
{{#endref}}

## 등록 및 관리 단계

1. 장치 기록 생성 (리셀러, Apple): 새 장치에 대한 기록이 생성됩니다.
2. 장치 기록 할당 (고객): 장치가 MDM 서버에 할당됩니다.
3. 장치 기록 동기화 (MDM 공급업체): MDM이 장치 기록을 동기화하고 DEP 프로파일을 Apple에 푸시합니다.
4. DEP 체크인 (장치): 장치가 자신의 DEP 프로파일을 받습니다.
5. 프로파일 검색 (장치)
6. 프로파일 설치 (장치) a. MDM, SCEP 및 루트 CA 페이로드 포함
7. MDM 명령 발행 (장치)

![](<../../../images/image (694).png>)

파일 `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`는 등록 프로세스의 **고급 "단계"**로 간주될 수 있는 기능을 내보냅니다.

### 단계 4: DEP 체크인 - 활성화 기록 가져오기

이 프로세스의 일부는 **사용자가 Mac을 처음 부팅할 때** (또는 완전 초기화 후) 발생합니다.

![](<../../../images/image (1044).png>)

또는 `sudo profiles show -type enrollment`을 실행할 때

- **장치가 DEP 활성화되었는지 여부를 확인합니다.**
- 활성화 기록은 **DEP “프로파일”**의 내부 이름입니다.
- 장치가 인터넷에 연결되면 시작됩니다.
- **`CPFetchActivationRecord`**에 의해 구동됩니다.
- **`cloudconfigurationd`**에 의해 XPC를 통해 구현됩니다. **"설정 도우미"** (장치가 처음 부팅될 때) 또는 **`profiles`** 명령이 이 데몬에 연락하여 활성화 기록을 검색합니다.
- LaunchDaemon (항상 root로 실행됨)

활성화 기록을 가져오는 과정은 **`MCTeslaConfigurationFetcher`**에 의해 수행됩니다. 이 과정은 **Absinthe**라는 암호화를 사용합니다.

1. **인증서 검색**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 인증서에서 상태 **초기화** (**`NACInit`**)
1. 다양한 장치 특정 데이터 사용 (즉, **`IOKit`를 통한 일련 번호**)
3. **세션 키 검색**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 세션 설정 (**`NACKeyEstablishment`**)
5. 요청하기
1. POST [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)로 데이터 `{ "action": "RequestProfileConfiguration", "sn": "" }` 전송
2. JSON 페이로드는 Absinthe로 암호화됩니다 (**`NACSign`**)
3. 모든 요청은 HTTPs를 통해 이루어지며, 내장 루트 인증서가 사용됩니다.

![](<../../../images/image (566) (1).png>)

응답은 다음과 같은 중요한 데이터가 포함된 JSON 사전입니다:

- **url**: 활성화 프로파일을 위한 MDM 공급업체 호스트의 URL
- **anchor-certs**: 신뢰할 수 있는 앵커로 사용되는 DER 인증서 배열

### **단계 5: 프로파일 검색**

![](<../../../images/image (444).png>)

- **DEP 프로파일**에 제공된 **url**로 요청이 전송됩니다.
- 제공된 경우 **앵커 인증서**가 **신뢰성 평가**에 사용됩니다.
- 알림: **DEP 프로파일의 anchor_certs** 속성
- **요청은 장치 식별이 포함된 간단한 .plist**입니다.
- 예: **UDID, OS 버전**.
- CMS 서명, DER 인코딩
- **장치 ID 인증서(APNS에서)**를 사용하여 서명됩니다.
- **인증서 체인**에는 만료된 **Apple iPhone Device CA**가 포함됩니다.

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### 단계 6: 프로파일 설치

- 검색된 후, **프로파일은 시스템에 저장됩니다.**
- 이 단계는 자동으로 시작됩니다( **설정 도우미**에 있는 경우).
- **`CPInstallActivationProfile`**에 의해 구동됩니다.
- XPC를 통해 mdmclient에 의해 구현됩니다.
- LaunchDaemon (root로 실행) 또는 LaunchAgent (사용자로 실행), 상황에 따라 다름.
- 구성 프로파일은 설치할 여러 페이로드를 가집니다.
- 프레임워크는 프로파일 설치를 위한 플러그인 기반 아키텍처를 가지고 있습니다.
- 각 페이로드 유형은 플러그인과 연결되어 있습니다.
- XPC(프레임워크 내) 또는 클래식 Cocoa(ManagedClient.app)일 수 있습니다.
- 예:
- 인증서 페이로드는 CertificateService.xpc를 사용합니다.

일반적으로 MDM 공급업체가 제공하는 **활성화 프로파일**은 **다음 페이로드를 포함합니다**:

- `com.apple.mdm`: 장치를 MDM에 **등록**하기 위해
- `com.apple.security.scep`: 장치에 **클라이언트 인증서**를 안전하게 제공하기 위해.
- `com.apple.security.pem`: 장치의 시스템 키체인에 **신뢰할 수 있는 CA 인증서**를 설치하기 위해.
- MDM 페이로드 설치는 문서에서 **MDM 체크인**에 해당합니다.
- 페이로드는 **주요 속성**을 포함합니다:
- - MDM 체크인 URL (**`CheckInURL`**)
- MDM 명령 폴링 URL (**`ServerURL`**) + 이를 트리거하기 위한 APNs 주제
- MDM 페이로드를 설치하기 위해 요청이 **`CheckInURL`**로 전송됩니다.
- **`mdmclient`**에서 구현됩니다.
- MDM 페이로드는 다른 페이로드에 의존할 수 있습니다.
- 특정 인증서에 요청을 핀 고정할 수 있습니다:
- 속성: **`CheckInURLPinningCertificateUUIDs`**
- 속성: **`ServerURLPinningCertificateUUIDs`**
- PEM 페이로드를 통해 전달됩니다.
- 장치에 신원 인증서를 부여할 수 있습니다:
- 속성: IdentityCertificateUUID
- SCEP 페이로드를 통해 전달됩니다.

### **단계 7: MDM 명령 수신 대기**

- MDM 체크인이 완료된 후, 공급업체는 **APNs를 사용하여 푸시 알림을 발행할 수 있습니다.**
- 수신 시, **`mdmclient`**에 의해 처리됩니다.
- MDM 명령을 폴링하기 위해 요청이 ServerURL로 전송됩니다.
- 이전에 설치된 MDM 페이로드를 사용합니다:
- **`ServerURLPinningCertificateUUIDs`** 요청 핀 고정용
- **`IdentityCertificateUUID`** TLS 클라이언트 인증서용

## 공격

### 다른 조직에 장치 등록하기

앞서 언급했듯이, 장치를 조직에 등록하려면 **해당 조직에 속한 일련 번호만 필요합니다**. 장치가 등록되면 여러 조직이 새 장치에 민감한 데이터를 설치합니다: 인증서, 애플리케이션, WiFi 비밀번호, VPN 구성 [등등](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
따라서 등록 프로세스가 올바르게 보호되지 않으면 공격자에게 위험한 진입점이 될 수 있습니다:

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
