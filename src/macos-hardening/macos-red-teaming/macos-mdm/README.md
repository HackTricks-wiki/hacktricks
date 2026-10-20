# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM에 대한 내용은 다음을 확인하세요:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## 기본 사항

### **MDM (Mobile Device Management) 개요**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM)은 스마트폰, 노트북, 태블릿과 같은 다양한 최종 사용자 장치를 관리하는 데 사용됩니다. 특히 Apple 플랫폼(iOS, macOS, tvOS)의 경우, MDM은 전문화된 기능, API, 관행의 집합으로 구성됩니다. MDM을 운영하려면 상용 또는 오픈소스 MDM 서버가 필요하며, 해당 서버는 [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)을 지원해야 합니다. 주요 사항은 다음과 같습니다.

- 장치를 중앙에서 제어합니다.
- MDM 프로토콜을 준수하는 MDM 서버가 필요합니다.
- MDM 서버가 장치에 다양한 명령을 전송할 수 있습니다. 예를 들어 원격 데이터 삭제 또는 구성 설치가 가능합니다.

### **DEP (Device Enrollment Program) 기본 사항**

Apple이 제공하는 [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP)은 iOS, macOS, tvOS 장치의 제로 터치 구성을 지원해 Mobile Device Management (MDM) 통합을 간소화합니다. DEP는 등록 프로세스를 자동화하여 사용자의 장치가 최소한의 사용자 또는 관리자 개입만으로 개봉 직후부터 작동할 수 있게 합니다. 주요 사항은 다음과 같습니다.

- 장치가 처음 활성화될 때 사전 지정된 MDM 서버에 자동으로 등록되도록 합니다.
- 주로 신품 장치에 유용하지만, 재구성 중인 장치에도 적용할 수 있습니다.
- 간편한 설정을 지원하여 장치를 조직에서 빠르게 사용할 수 있도록 합니다.

### **보안 고려 사항**

DEP가 제공하는 간편한 등록은 유용하지만, 보안 위험을 초래할 수도 있습니다. MDM 등록에 보호 조치가 제대로 적용되지 않으면 공격자가 이 간소화된 절차를 악용해 기업 장치인 것처럼 위장하여 조직의 MDM 서버에 자신의 장치를 등록할 수 있습니다.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **보안 경고**: 적절한 보호 조치가 없으면 간소화된 DEP 등록을 통해 승인되지 않은 장치가 조직의 MDM 서버에 등록될 수 있습니다.

### SCEP (Simple Certificate Enrolment Protocol)란?

- TLS와 HTTPS가 널리 보급되기 전에 만들어진 비교적 오래된 프로토콜입니다.
- 클라이언트가 인증서를 발급받기 위해 **Certificate Signing Request** (CSR)를 전송하는 표준 방식을 제공합니다. 클라이언트는 서버에 서명된 인증서를 요청합니다.

### Configuration Profiles (일명 mobileconfigs)란?

- 시스템 구성을 **설정/강제 적용**하는 Apple의 공식 방식입니다.
- 여러 페이로드를 포함할 수 있는 파일 형식입니다.
- property list (XML 종류)를 기반으로 합니다.
- “출처를 검증하고, 무결성을 보장하며, 내용을 보호하기 위해 서명 및 암호화할 수 있습니다.” *Basics — Page 70, iOS Security Guide, January 2018.*

## 프로토콜

### MDM

- APNs (**Apple 서버**) + RESTful API (**MDM** **벤더** 서버)의 조합입니다.
- **장치**와 **장치** **관리** **제품**에 연결된 서버 간에 **통신**이 이루어집니다.
- MDM에서 장치로 전달되는 **명령**은 **plist로 인코딩된 딕셔너리** 형식입니다.
- 모든 통신은 **HTTPS**로 이루어집니다. MDM 서버는 인증서 고정(pinning)을 적용할 수 있으며, 일반적으로 적용합니다.
- Apple은 인증을 위해 MDM 벤더에 **APNs 인증서**를 발급합니다.

### DEP

- **API 3개**: 리셀러용 1개, MDM 벤더용 1개, 장치 식별용 1개(문서화되지 않음):
  - 이른바 [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)입니다. MDM 서버가 DEP 프로파일을 특정 장치와 연결하는 데 사용합니다.
  - [Apple 공인 리셀러가 사용하는 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)입니다. 장치를 등록하고 등록 상태 및 트랜잭션 상태를 확인하는 데 사용합니다.
  - 문서화되지 않은 비공개 DEP API입니다. Apple 장치가 DEP 프로파일을 요청하는 데 사용합니다. macOS에서는 `cloudconfigurationd` 바이너리가 이 API를 통한 통신을 담당합니다.
- 더 현대적이고 **JSON** 기반입니다(plist와 달리).
- Apple은 MDM 벤더에 **OAuth 토큰**을 발급합니다.

**DEP "cloud service" API**

- RESTful입니다.
- Apple에서 MDM 서버로 장치 레코드를 동기화합니다.
- MDM 서버에서 Apple로 “DEP 프로파일”을 동기화합니다(Apple이 나중에 장치로 전달).
- DEP “프로파일”에는 다음이 포함됩니다.
  - MDM 벤더 서버 URL
  - 서버 URL에 사용할 추가 신뢰 인증서(선택적 pinning)
  - 추가 설정(예: Setup Assistant에서 건너뛸 화면)

## 일련번호

2010년 이후에 제조된 Apple 장치는 일반적으로 **12자리 영숫자** 일련번호를 사용합니다. **처음 세 자리**는 제조 장소를, 그다음 **두 자리**는 제조 **연도**와 **주차**를, 다음 **세 자리**는 **고유한** **식별자**를 나타내며, **마지막** **네 자리**는 **모델 번호**를 나타냅니다.


{{#ref}}
macos-serial-number.md
{{#endref}}

## 등록 및 관리 단계

1. 장치 레코드 생성(리셀러, Apple): 새 장치의 레코드가 생성됩니다.
2. 장치 레코드 할당(고객): 장치가 MDM 서버에 할당됩니다.
3. 장치 레코드 동기화(MDM 벤더): MDM이 장치 레코드를 동기화하고 DEP 프로파일을 Apple에 푸시합니다.
4. DEP 체크인(장치): 장치가 DEP 프로파일을 가져옵니다.
5. 프로파일 검색(장치)
6. 프로파일 설치(장치) a. MDM, SCEP 및 루트 CA 페이로드 포함
7. MDM 명령 발행(장치)

![일련번호 - 등록 및 관리 단계: 7. MDM 명령 발행(장치)](<../../../images/image (694).png>)

파일 `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`는 등록 프로세스의 상위 수준 "단계"로 볼 수 있는 함수를 내보냅니다.

### 4단계: DEP 체크인 - Activation Record 가져오기

이 프로세스는 **사용자가 처음으로 Mac을 부팅할 때**(또는 완전히 지운 후) 진행됩니다.

![등록 및 관리 단계 - 4단계: DEP 체크인 - Activation Record 가져오기: 이 프로세스는 사용자가 처음으로 Mac을 부팅할 때(또는 완전히 지운 후) 진행됩니다.](<../../../images/image (1044).png>)

또는 `sudo profiles show -type enrollment`을 실행할 때 진행됩니다.

- **장치에서 DEP가 활성화되어 있는지** 확인합니다.
- Activation Record는 내부적으로 DEP “프로파일”을 가리키는 이름입니다.
- 장치가 인터넷에 연결되는 즉시 시작됩니다.
- **`CPFetchActivationRecord`**가 실행을 주도합니다.
- XPC를 통해 **`cloudconfigurationd`**가 구현합니다. 장치를 처음 부팅할 때의 **"Setup Assistant**" 또는 **`profiles`** 명령이 Activation Record를 가져오기 위해 **이 데몬에 연결합니다**.
  - LaunchDaemon (항상 root로 실행)

**`MCTeslaConfigurationFetcher`**가 Activation Record를 가져오기 위한 몇 가지 단계를 수행합니다. 이 프로세스는 **Absinthe**라는 암호화를 사용합니다.<sup>[[1]](#references)</sup>

1. **인증서** 가져오기
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 인증서에서 상태 **초기화** (**`NACInit`**)
   1. 장치별 데이터를 다양하게 사용합니다(예: **`IOKit`을 통한 일련번호**).
3. **세션 키** 가져오기
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 세션 설정 (**`NACKeyEstablishment`**)
5. 요청 전송
   1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)에 POST 요청을 보내며 데이터는 `{ "action": "RequestProfileConfiguration", "sn": "" }`입니다.
   2. JSON 페이로드는 Absinthe를 사용해 암호화됩니다 (**`NACSign`**).
   3. 모든 요청은 HTTPS를 통해 이루어지며, 내장된 루트 인증서를 사용합니다.

![등록 및 관리 단계 - 4단계: DEP 체크인 - Activation Record 가져오기: 3. 모든 요청은 HTTPS를 통해 이루어지며, 내장된 루트 인증서를 사용합니다.](<../../../images/image (566) (1).png>)

응답은 다음과 같은 중요한 데이터가 포함된 JSON 딕셔너리입니다.

- **url**: Activation Profile을 제공하는 MDM 벤더 호스트의 URL
- **anchor-certs**: 신뢰 앵커로 사용되는 DER 인증서 배열

### **5단계: 프로파일 검색**

![4단계: DEP 체크인 - Activation Record 가져오기 - 5단계: 프로파일 검색: 5단계: 프로파일 검색](<../../../images/image (444).png>)

- DEP 프로파일에 제공된 **url**로 요청을 전송합니다.
- 제공된 경우 **앵커 인증서**를 사용해 **신뢰를 평가**합니다.
  - 참고: DEP 프로파일의 **anchor_certs** 속성입니다.
- **요청은 장치 식별 정보가 포함된 간단한 .plist**입니다.
  - 예: **UDID, OS 버전**.
- CMS 서명 및 DER 인코딩 형식입니다.
- **장치 ID 인증서(APNS에서 제공)**를 사용해 서명됩니다.
- **인증서 체인**에는 만료된 **Apple iPhone Device CA**가 포함됩니다.

![4단계: DEP 체크인 - Activation Record 가져오기 - 5단계: 프로파일 검색: 장치 ID 인증서(APNS에서 제공)를 사용해 서명됨](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### 6단계: 프로파일 설치

- 가져온 프로파일은 **시스템에 저장됩니다**.
- 이 단계는 (**Setup Assistant**에서) 자동으로 시작됩니다.
- **`CPInstallActivationProfile`**이 실행을 주도합니다.
- XPC를 통해 mdmclient가 구현합니다.
  - LaunchDaemon (root로 실행) 또는 LaunchAgent (사용자로 실행), 상황에 따라 다릅니다.
- Configuration Profile에는 설치할 페이로드가 여러 개 있습니다.
- 프레임워크는 프로파일 설치를 위한 플러그인 기반 아키텍처를 사용합니다.
- 각 페이로드 유형은 플러그인과 연결됩니다.
  - XPC(프레임워크 내) 또는 기존 Cocoa(ManagedClient.app)일 수 있습니다.
- 예:
  - Certificate Payload는 CertificateService.xpc를 사용합니다.

일반적으로 MDM 벤더가 제공하는 **Activation Profile에는 다음 페이로드가 포함됩니다**.

- `com.apple.mdm`: 장치를 MDM에 **등록**합니다.
- `com.apple.security.scep`: 장치에 **클라이언트 인증서**를 안전하게 제공합니다.
- `com.apple.security.pem`: 장치의 System Keychain에 **신뢰 CA 인증서를 설치**합니다.
- MDM 페이로드를 설치하는 것은 문서에서 말하는 **MDM 체크인**에 해당합니다.
- 페이로드에는 **주요 속성**이 포함됩니다.
- - MDM Check-In URL (**`CheckInURL`**)
  - MDM 명령 폴링 URL (**`ServerURL`**) + 이를 트리거하는 APNs topic
- MDM 페이로드를 설치하려면 **`CheckInURL`**로 요청을 보냅니다.
- **`mdmclient`**에서 구현됩니다.
- MDM 페이로드는 다른 페이로드에 의존할 수 있습니다.
- 특정 인증서에 요청을 고정할 수 있습니다.
  - 속성: **`CheckInURLPinningCertificateUUIDs`**
  - 속성: **`ServerURLPinningCertificateUUIDs`**
  - PEM 페이로드를 통해 전달됩니다.
- 장치에 ID 인증서를 연결할 수 있습니다.
  - 속성: IdentityCertificateUUID
  - SCEP 페이로드를 통해 전달됩니다.

### **7단계: MDM 명령 대기**

- MDM 체크인이 완료되면 벤더가 **APNs를 사용해 푸시 알림을 전송**할 수 있습니다.
- 알림을 받으면 **`mdmclient`**가 처리합니다.
- MDM 명령을 폴링하기 위해 ServerURL로 요청을 보냅니다.
- 이전에 설치된 MDM 페이로드를 사용합니다.
  - 요청 고정에 **`ServerURLPinningCertificateUUIDs`** 사용
  - TLS 클라이언트 인증서에 **`IdentityCertificateUUID`** 사용

## 공격

### 다른 조직에 장치 등록하기

할당된 일련번호로 조직의 등록 경로를 확인할 수 있지만, MDM 등록이 보장되는 것은 **아닙니다**. 서버는 등록 프로파일을 반환하기 전에 `configuration_web_url`을 통해 사용자 인증을 요구할 수 있습니다. 할당된 일련번호만으로 모든 장치가 조직의 장치 관리 범위에 등록될 수 있다고 가정하지 말고, 대체 등록 경로에서 해당 확인 절차가 생략되는지 평가하세요.<sup>[[3]](#references)</sup>

악성 등록 절차는 아래에 링크된 페이지를 참조하세요. 침해 이후 MDM 제어 및 패키지 전달에 대해서는 [macOS Red Teaming](../)을 참조하세요.


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [macOS MDM 심층 분석 (및 침해 방법)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM 등록 보안 연구)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — 웹 뷰를 통한 인증](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
