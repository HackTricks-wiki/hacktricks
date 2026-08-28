# 다른 조직에 장치 등록하기

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Apple Automated Device Enrollment(이전 명칭 DEP)은 먼저 조직에 할당된 장치를 식별하는 것부터 시작합니다. 여기서 요약한 2018년 연구에서는 할당된 serial number를 알고 있는 것만으로도 일부 조직의 enrollment profile을 가져올 수 있었습니다. 해당 조직들이 충분한 추가 인증을 요구하지 않았기 때문입니다. 이는 역사적 발견이며, 현재 모든 MDM이 serial number만으로 가입될 수 있다는 주장이 아닙니다. Profile에는 certificate, application, Wi-Fi secret, VPN 설정 및 기타 민감한 구성이 포함될 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

**다음은 연구 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)의 요약입니다. 추가 기술 세부 사항은 원문을 확인하세요!**<sup>[[1]](#references)</sup>

## DEP 및 MDM Binary Analysis 개요

이 연구에서는 당시 최신 macOS 버전에서 DEP 및 MDM과 관련된 binary를 분석했습니다. Component 이름과 역할은 release에 따라 변경될 수 있습니다:

- **`mdmclient`**: MDM server와 통신하고 10.13.4 이전 macOS 버전에서 DEP check-in을 trigger합니다.
- **`profiles`**: Configuration Profile을 관리하고 macOS 버전 10.13.4 이상에서 DEP check-in을 trigger합니다.
- **`cloudconfigurationd`**: DEP API 통신을 관리하고 Device Enrollment profile을 가져옵니다.

DEP check-in은 private Configuration Profiles framework의 `CPFetchActivationRecord` 및 `CPGetActivationRecord` function을 사용해 Activation Record를 가져오며, `CPFetchActivationRecord`는 XPC를 통해 `cloudconfigurationd`와 조정합니다.<sup>[[1]](#references)</sup>

## Tesla Protocol 및 Absinthe Scheme Reverse Engineering

DEP check-in 과정에서 `cloudconfigurationd`는 암호화되고 서명된 JSON payload를 _iprofiles.apple.com/macProfile_로 전송합니다. Payload에는 장치의 serial number와 "RequestProfileConfiguration" action이 포함됩니다. 사용된 encryption scheme은 내부적으로 "Absinthe"라고 합니다. 이 scheme을 해제하는 과정은 복잡하고 많은 단계를 필요로 하며, 그 결과 Activation Record request에 arbitrary serial number를 삽입하는 alternative method를 모색하게 되었습니다.<sup>[[1]](#references)</sup>

## DEP Request Proxying

Charles Proxy와 같은 tool을 사용해 _iprofiles.apple.com_으로 전송되는 DEP request를 intercept하고 수정하려는 시도는 payload encryption 및 SSL/TLS security measure로 인해 제한되었습니다. 그러나 `MCCloudConfigAcceptAnyHTTPSCertificate` configuration을 활성화하면 server certificate validation을 우회할 수 있습니다. 다만 payload가 암호화되어 있으므로 decryption key 없이는 serial number를 수정할 수 없습니다.<sup>[[1]](#references)</sup>

## DEP와 상호 작용하는 System Binary Instrumentation

`cloudconfigurationd`와 같은 system binary를 instrument하려면 macOS에서 System Integrity Protection(SIP)을 비활성화해야 합니다. SIP가 비활성화되면 LLDB와 같은 tool을 사용해 system process에 attach하고 DEP API interaction에서 사용되는 serial number를 잠재적으로 수정할 수 있습니다. 이 방법은 entitlement 및 code signing의 복잡성을 피할 수 있어 선호됩니다.<sup>[[1]](#references)</sup>

**Binary Instrumentation 악용:**
`cloudconfigurationd`에서 JSON serialization 전에 DEP request payload를 수정하는 방식이 효과적인 것으로 확인되었습니다. 과정은 다음과 같습니다:

1. LLDB를 `cloudconfigurationd`에 attach합니다.
2. system serial number가 가져와지는 지점을 찾습니다.
3. payload가 암호화되어 전송되기 전에 memory에 arbitrary serial number를 inject합니다.

이 방법을 통해 연구자들은 입력한 할당된 serial number에 대한 DEP profile을 가져올 수 있었습니다. 할당되지 않은 arbitrary serial number를 유효하게 만들지는 못했습니다.<sup>[[1]](#references)</sup>

### Python으로 Instrumentation 자동화

LLDB API를 사용하는 Python으로 exploitation process를 자동화하여 arbitrary serial number를 programmatically inject하고 이에 대응하는 DEP profile을 가져올 수 있었습니다.<sup>[[1]](#references)</sup>

## 2025년 재검토: VM에서의 Rogue Enrollment

Black Hat Asia 2025 research에서는 원래의 trust-boundary 문제가 여전히 **MDM layer**에서 중요할 수 있음을 보여주었습니다. `cloudconfigurationd`를 LLDB로 patch하는 대신, 연구자들은 OpenCore를 사용해 QEMU/KVM에서 macOS를 실행하고 VM의 SMBIOS를 통해 candidate identity를 제공했습니다. 수정되지 않은 macOS enrollment stack은 이후 암호화된 Apple exchange를 수행했습니다. 따라서 publicly leaked serial과 유효해 보이는 candidate는 해당 physical Mac을 보유하지 않고도 테스트할 수 있습니다. 다만 성공하려면 해당 serial이 조직에 할당되어 있어야 하며 조직의 enrollment path에 authentication이 충분하지 않아야 합니다.<sup>[[3]](#references)</sup>

Authorized lab device의 경우 관련 OpenCore `PlatformInfo` 값에는 product model과 serial이 포함됩니다. 실제 deployment에서는 ROM과 UUID도 내부적으로 일관되게 유지해야 합니다:<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
동일한 연구에서는 private file `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`에서 `CheckProfilesFetchRateLimit` 상태도 확인했습니다. 이 검사가 client 측에서 유지되었기 때문에 저장된 시간 값을 수정하면 이를 무력화할 수 있었습니다. 이러한 경로는 문서화되지 않았고 버전에 따라 달라지지만, 현재 macOS 빌드를 평가할 때 유용한 reversing pivot으로 사용할 수 있습니다:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
두 번째 artifact는 cached activation record를 노출할 수 있으며, 해당 flow가 direct `ConfigurationURL`을 사용하는지 또는 authenticated `ConfigurationWebURL`을 사용하는지 확인할 수 있습니다. Advertised flow와 MDM-specific legacy enrollment endpoint를 모두 테스트해야 합니다. Main web flow에서만 SSO를 활성화해도 parallel direct endpoint는 보호되지 않습니다. 전체 protocol sequence는 [macOS MDM overview](README.md)를 참조하십시오.<sup>[[3]](#references)</sup>

### Enrollment 이후 Secret Hunting

Rogue enrollment는 entry point일 뿐입니다. Enrollment 이후에는 전달된 모든 profile, bootstrap policy, package-repository configuration, agent installation script 및 self-service item을 검사하십시오. 2025년 연구에서는 Wi-Fi credentials, shared local-administrator passwords, signed cloud-storage URLs, webhook URLs, security-agent activation data 및 MDM/API credentials의 사례가 확인되었습니다. 전달된 script에 포함된 tenant API credential은 하나의 rogue endpoint를 다른 managed device에 대한 제어권으로 확장할 수 있으므로, live filesystem과 다운로드되거나 cached된 policy content를 모두 검색해야 합니다.<sup>[[3]](#references)</sup>

유용한 검토 대상은 다음과 같습니다:<sup>[[3]](#references)</sup>

- 설치된 `.mobileconfig` payload와 Configuration Profiles database
- 계정을 생성하거나 EDR/VPN agent를 설치하는 PreStage/bootstrap script 및 package
- Munki 또는 기타 package repository URL, 특히 bearer/SAS-style signature가 포함된 query string
- Self-service catalog와 이를 뒷받침하는 policy API. 여기에는 enrollment SSO policy를 적용하지 않을 수 있는 legacy route도 포함됩니다.
- `password`, `token`, `secret`, `Authorization`, webhook hostname 및 vendor API endpoint를 대상으로 하는 shell history와 cached policy output

### Trust Boundary 강화

Serial number를 possession의 증명이 **아닌**, inventory/routing attribute로 취급하십시오. Enrollment와 self service에 user authentication을 요구하고, device별로 고유한 local administrator password를 생성하며, tenant API credential 또는 재사용 가능한 infrastructure secret을 profile이나 script에 절대 포함하지 마십시오. 불가피한 bootstrap token은 수명을 짧게 유지하고 provisioning 중인 단일 action과 device로 제한하십시오.<sup>[[3]](#references)</sup>

macOS 14 이상을 실행하는 Apple-silicon Mac에서는 Managed Device Attestation이 identity를 Secure Enclave에 cryptographically bind할 수 있습니다. Apple-rooted attestation에는 fresh nonce와 함께 serial number, UDID, OS version, SIP state 및 secure-boot state가 포함될 수 있으며, ACME는 이를 통해 hardware-bound client identity를 발급할 수 있습니다. 해당 identity를 사용하여 MDM channel을 보호하고 high-value certificate, VPN access 및 기타 resource에 대한 접근을 제어하되, device attestation은 operator가 아닌 device를 증명하므로 별도의 user authentication을 유지하십시오.<sup>[[4]](#references)</sup>

## DEP 및 MDM Vulnerability의 잠재적 영향

연구에서는 다음과 같은 중대한 security concern이 강조되었습니다.

1. **Information Disclosure**: DEP-registered serial number를 제공하면 DEP profile에 포함된 민감한 조직 정보를 retrieved할 수 있습니다.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM일 수도 있고 아닐 수도: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Rogue Device Enrolment를 사용한 Apple MDM Hacking](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
