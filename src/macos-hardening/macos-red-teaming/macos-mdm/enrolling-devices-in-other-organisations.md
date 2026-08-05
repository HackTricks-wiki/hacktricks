# 다른 조직에 기기 등록하기

{{#include ../../../banners/hacktricks-training.md}}

## Intro

[**앞서 설명한 것처럼**](#what-is-mdm-mobile-device-management)**,** 기기를 조직에 등록하려면 **해당 조직에 속한 Serial Number 하나만 있으면 됩니다**. 기기가 등록되면 여러 조직에서 새 기기에 민감한 데이터를 설치합니다. 여기에는 인증서, 애플리케이션, WiFi 비밀번호, VPN 구성 [등](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)이 포함됩니다.\
따라서 등록 프로세스가 적절히 보호되지 않는다면 공격자에게 위험한 진입점이 될 수 있습니다.

**다음은 연구 자료 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)의 요약입니다. 자세한 기술 정보는 해당 자료를 확인하세요!**<sup>[1]</sup>

## DEP 및 MDM Binary Analysis 개요

이 연구는 macOS의 Device Enrollment Program (DEP) 및 Mobile Device Management (MDM)과 관련된 바이너리를 분석합니다. 주요 구성 요소는 다음과 같습니다.

- **`mdmclient`**: MDM 서버와 통신하며 10.13.4 이전 macOS 버전에서 DEP check-in을 트리거합니다.
- **`profiles`**: Configuration Profiles를 관리하며 macOS 버전 10.13.4 이상에서 DEP check-in을 트리거합니다.
- **`cloudconfigurationd`**: DEP API 통신을 관리하고 Device Enrollment profiles를 가져옵니다.

DEP check-in은 private Configuration Profiles framework의 `CPFetchActivationRecord` 및 `CPGetActivationRecord` 함수를 사용해 Activation Record를 가져오며, `CPFetchActivationRecord`는 XPC를 통해 `cloudconfigurationd`와 통신합니다.<sup>[1]</sup>

## Tesla Protocol 및 Absinthe Scheme Reverse Engineering

DEP check-in 과정에서 `cloudconfigurationd`는 암호화되고 서명된 JSON payload를 _iprofiles.apple.com/macProfile_로 전송합니다. payload에는 기기의 serial number와 "RequestProfileConfiguration" action이 포함됩니다. 사용되는 encryption scheme은 내부적으로 "Absinthe"라고 불립니다. 이 scheme을 해독하는 과정은 복잡하고 여러 단계가 필요하므로, Activation Record request에 임의의 serial number를 삽입하는 대체 방법을 탐색하게 되었습니다.<sup>[1]</sup>

## DEP Requests Proxying

Charles Proxy와 같은 도구를 사용해 _iprofiles.apple.com_에 대한 DEP requests를 가로채고 수정하려는 시도는 payload encryption 및 SSL/TLS security measures로 인해 제한되었습니다. 그러나 `MCCloudConfigAcceptAnyHTTPSCertificate` configuration을 활성화하면 server certificate validation을 우회할 수 있습니다. 다만 payload가 암호화되어 있으므로 decryption key 없이는 serial number를 수정할 수 없습니다.<sup>[1]</sup>

## DEP와 상호작용하는 System Binaries Instrumenting

`cloudconfigurationd`와 같은 system binaries를 instrumenting하려면 macOS에서 System Integrity Protection (SIP)을 비활성화해야 합니다. SIP가 비활성화되면 LLDB와 같은 도구를 사용해 system processes에 attach하고 DEP API interactions에서 사용되는 serial number를 수정할 수 있습니다. 이 방법은 entitlements 및 code signing의 복잡성을 피할 수 있어 선호됩니다.

**Binary Instrumentation Exploiting:**
`cloudconfigurationd`에서 JSON serialization 전에 DEP request payload를 수정하는 방법이 효과적인 것으로 확인되었습니다. 과정은 다음과 같습니다.

1. `cloudconfigurationd`에 LLDB를 attach합니다.
2. system serial number가 가져와지는 지점을 찾습니다.
3. payload가 암호화되어 전송되기 전에 memory에 임의의 serial number를 주입합니다.

이 방법을 사용하면 임의의 serial numbers에 대한 complete DEP profiles를 가져올 수 있어 잠재적인 vulnerability가 존재함을 입증할 수 있습니다.<sup>[1]</sup>

### Python으로 Instrumentation 자동화

LLDB API를 사용하는 Python으로 exploitation process를 자동화하여 임의의 serial numbers를 programmatically 주입하고 해당 DEP profiles를 가져올 수 있었습니다.<sup>[1]</sup>

### DEP 및 MDM Vulnerabilities의 잠재적 영향

이 연구는 다음과 같은 중대한 security concerns를 강조했습니다.

1. **Information Disclosure**: DEP-registered serial number를 제공하면 DEP profile에 포함된 민감한 조직 정보를 가져올 수 있습니다.<sup>[1]</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
