# 다른 조직에 장치 등록하기

{{#include ../../../banners/hacktricks-training.md}}

## 소개

[**이전에 언급된 바와 같이**](#what-is-mdm-mobile-device-management)**,** 장치를 조직에 등록하기 위해서는 **해당 조직에 속하는 일련 번호만 필요합니다**. 장치가 등록되면 여러 조직이 새로운 장치에 민감한 데이터를 설치합니다: 인증서, 애플리케이션, WiFi 비밀번호, VPN 구성 [등등](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
따라서 등록 프로세스가 제대로 보호되지 않으면 공격자에게 위험한 진입점이 될 수 있습니다.

**다음은 연구의 요약입니다 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). 추가 기술 세부정보를 확인하세요!**

## DEP 및 MDM 이진 분석 개요

이 연구는 macOS의 장치 등록 프로그램(DEP) 및 모바일 장치 관리(MDM)와 관련된 이진 파일을 다룹니다. 주요 구성 요소는 다음과 같습니다:

- **`mdmclient`**: MDM 서버와 통신하고 macOS 10.13.4 이전 버전에서 DEP 체크인을 트리거합니다.
- **`profiles`**: 구성 프로필을 관리하고 macOS 10.13.4 이후 버전에서 DEP 체크인을 트리거합니다.
- **`cloudconfigurationd`**: DEP API 통신을 관리하고 장치 등록 프로필을 검색합니다.

DEP 체크인은 개인 구성 프로필 프레임워크의 `CPFetchActivationRecord` 및 `CPGetActivationRecord` 함수를 사용하여 활성화 레코드를 가져오며, `CPFetchActivationRecord`는 XPC를 통해 `cloudconfigurationd`와 조정됩니다.

## 테슬라 프로토콜 및 앱신트 스킴 리버스 엔지니어링

DEP 체크인은 `cloudconfigurationd`가 _iprofiles.apple.com/macProfile_에 암호화되고 서명된 JSON 페이로드를 전송하는 것을 포함합니다. 페이로드에는 장치의 일련 번호와 "RequestProfileConfiguration" 작업이 포함됩니다. 사용된 암호화 스킴은 내부적으로 "Absinthe"라고 불립니다. 이 스킴을 풀어내는 것은 복잡하며 여러 단계를 포함하여 활성화 레코드 요청에 임의의 일련 번호를 삽입하는 대체 방법을 탐색하게 되었습니다.

## DEP 요청 프록시

Charles Proxy와 같은 도구를 사용하여 _iprofiles.apple.com_에 대한 DEP 요청을 가로채고 수정하려는 시도는 페이로드 암호화 및 SSL/TLS 보안 조치로 인해 방해받았습니다. 그러나 `MCCloudConfigAcceptAnyHTTPSCertificate` 구성을 활성화하면 서버 인증서 검증을 우회할 수 있지만, 페이로드의 암호화된 특성은 여전히 복호화 키 없이 일련 번호 수정을 방지합니다.

## DEP와 상호작용하는 시스템 이진 파일 계측

`cloudconfigurationd`와 같은 시스템 이진 파일을 계측하려면 macOS에서 시스템 무결성 보호(SIP)를 비활성화해야 합니다. SIP가 비활성화되면 LLDB와 같은 도구를 사용하여 시스템 프로세스에 연결하고 DEP API 상호작용에 사용되는 일련 번호를 수정할 수 있습니다. 이 방법은 권한 및 코드 서명의 복잡성을 피할 수 있어 선호됩니다.

**이진 계측 활용:**
`cloudconfigurationd`에서 JSON 직렬화 전에 DEP 요청 페이로드를 수정하는 것이 효과적임을 입증했습니다. 이 과정은 다음을 포함했습니다:

1. `cloudconfigurationd`에 LLDB 연결.
2. 시스템 일련 번호가 검색되는 지점 찾기.
3. 페이로드가 암호화되고 전송되기 전에 메모리에 임의의 일련 번호 주입.

이 방법은 임의의 일련 번호에 대한 전체 DEP 프로필을 검색할 수 있게 하여 잠재적인 취약점을 보여주었습니다.

### Python을 사용한 계측 자동화

이용 과정은 LLDB API와 함께 Python을 사용하여 자동화되어 임의의 일련 번호를 프로그래밍 방식으로 주입하고 해당 DEP 프로필을 검색할 수 있게 되었습니다.

### DEP 및 MDM 취약점의 잠재적 영향

연구는 중요한 보안 문제를 강조했습니다:

1. **정보 유출**: DEP에 등록된 일련 번호를 제공함으로써 DEP 프로필에 포함된 민감한 조직 정보를 검색할 수 있습니다.

{{#include ../../../banners/hacktricks-training.md}}
