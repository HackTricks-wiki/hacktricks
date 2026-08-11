# 다른 조직에 기기 등록하기

{{#include ../../../banners/hacktricks-training.md}}

## 소개

Apple Automated Device Enrollment(이전 명칭 DEP)은 조직에 할당된 기기를 식별하는 것부터 시작합니다. 여기에서 요약한 2018년 연구에 따르면, 할당된 serial number를 알고 있는 것만으로도 일부 조직의 enrollment profile을 가져올 수 있었습니다. 해당 조직들이 충분한 추가 인증을 요구하지 않았기 때문입니다. 이는 역사적 발견이며, 현재 모든 MDM이 serial number만으로 join될 수 있다는 주장이 아닙니다. Profile에는 certificate, application, Wi-Fi secret, VPN setting 및 기타 민감한 configuration이 포함될 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

**다음은 research [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)의 요약입니다. 자세한 technical detail은 해당 문서를 확인하세요!**<sup>[[1]](#references)</sup>

## DEP 및 MDM Binary Analysis 개요

이 research에서는 당시 최신 macOS version의 DEP 및 MDM과 관련된 binary를 분석했습니다. Component 이름과 responsibility는 release에 따라 변경될 수 있습니다.

- **`mdmclient`**: MDM server와 통신하며 10.13.4 이전 macOS version에서 DEP check-in을 trigger합니다.
- **`profiles`**: Configuration Profile을 관리하며 macOS version 10.13.4 이상에서 DEP check-in을 trigger합니다.
- **`cloudconfigurationd`**: DEP API communication을 관리하고 Device Enrollment profile을 가져옵니다.

DEP check-in은 private Configuration Profiles framework의 `CPFetchActivationRecord` 및 `CPGetActivationRecord` function을 사용하여 Activation Record를 가져오며, `CPFetchActivationRecord`는 XPC를 통해 `cloudconfigurationd`와 조정합니다.<sup>[[1]](#references)</sup>

## Tesla Protocol 및 Absinthe Scheme Reverse Engineering

DEP check-in에서는 `cloudconfigurationd`가 암호화되고 서명된 JSON payload를 _iprofiles.apple.com/macProfile_로 전송합니다. Payload에는 기기의 serial number와 `"RequestProfileConfiguration"` action이 포함됩니다. 사용된 encryption scheme은 내부적으로 "Absinthe"라고 불립니다. 이 scheme을 분석하는 과정은 복잡하고 수많은 단계가 필요했으며, 그 결과 Activation Record request에 임의의 serial number를 삽입하는 alternative method를 탐색하게 되었습니다.<sup>[[1]](#references)</sup>

## DEP Request Proxying

Charles Proxy와 같은 tool을 사용하여 _iprofiles.apple.com_에 대한 DEP request를 intercept하고 수정하려는 시도는 payload encryption 및 SSL/TLS security measure로 인해 제한되었습니다. 그러나 `MCCloudConfigAcceptAnyHTTPSCertificate` configuration을 활성화하면 server certificate validation을 우회할 수 있습니다. 다만 payload가 암호화되어 있으므로 decryption key 없이는 여전히 serial number를 수정할 수 없습니다.<sup>[[1]](#references)</sup>

## DEP와 상호작용하는 System Binary Instrumentation

`cloudconfigurationd`와 같은 system binary를 instrument하려면 macOS에서 System Integrity Protection(SIP)을 비활성화해야 합니다. SIP를 비활성화하면 LLDB와 같은 tool을 사용하여 system process에 attach하고 DEP API interaction에 사용되는 serial number를 수정할 수 있습니다. 이 method는 entitlements 및 code signing의 복잡성을 피할 수 있으므로 선호됩니다.<sup>[[1]](#references)</sup>

**Binary Instrumentation Exploiting:**
`cloudconfigurationd`에서 JSON serialization 전에 DEP request payload를 수정하는 방법이 효과적인 것으로 확인되었습니다. 과정은 다음과 같습니다.

1. LLDB를 `cloudconfigurationd`에 attach합니다.
2. system serial number가 fetch되는 지점을 찾습니다.
3. payload가 암호화되어 전송되기 전에 memory에 임의의 serial number를 inject합니다.

이 method를 사용하면 researchers가 제공된 할당 serial number에 대한 DEP profile을 가져올 수 있었습니다. 할당되지 않은 임의의 serial number를 유효하게 만든 것은 아닙니다.<sup>[[1]](#references)</sup>

### Python으로 Instrumentation 자동화

Exploitation process는 LLDB API를 사용하는 Python으로 자동화되었으며, 이를 통해 임의의 serial number를 programmatically inject하고 해당 DEP profile을 가져올 수 있었습니다.<sup>[[1]](#references)</sup>

### DEP 및 MDM Vulnerability의 잠재적 영향

이 research에서는 다음과 같은 중대한 security concern을 강조했습니다.

1. **Information Disclosure**: DEP에 등록된 serial number를 제공하면 DEP profile에 포함된 민감한 조직 정보를 가져올 수 있습니다.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
