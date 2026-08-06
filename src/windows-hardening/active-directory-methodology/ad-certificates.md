# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **Subject**는 인증서의 소유자를 나타냅니다.
- **Public Key**는 개인이 보유한 키와 쌍을 이루어 인증서를 정당한 소유자와 연결합니다.
- **Validity Period**는 **NotBefore** 및 **NotAfter** 날짜로 정의되며, 인증서의 유효 기간을 나타냅니다.
- Certificate Authority (CA)가 제공하는 고유한 **Serial Number**는 각 인증서를 식별합니다.
- **Issuer**는 인증서를 발급한 CA를 의미합니다.
- **SubjectAlternativeName**을 사용하면 subject에 추가 이름을 지정할 수 있어 식별의 유연성이 향상됩니다.
- **Basic Constraints**는 인증서가 CA용인지 최종 entity용인지 식별하고 사용 제한을 정의합니다.
- **Extended Key Usages (EKUs)**는 Object Identifiers (OIDs)를 통해 code signing 또는 email encryption과 같은 인증서의 구체적인 용도를 지정합니다.
- **Signature Algorithm**은 인증서에 서명하는 방법을 지정합니다.
- 발급자의 개인 키로 생성되는 **Signature**는 인증서의 신뢰성을 보장합니다.<sup>[[4]](#references)</sup>

### Special Considerations

- **Subject Alternative Names (SANs)**는 인증서를 여러 identity에 적용할 수 있도록 확장하며, 여러 domain을 사용하는 서버에 필수적입니다. 공격자가 SAN specification을 조작하여 impersonation하는 위험을 방지하려면 안전한 발급 프로세스가 중요합니다.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS는 AD forest 내 CA certificates를 지정된 container를 통해 인식하며, 각 container는 고유한 역할을 수행합니다:<sup>[[4]](#references)</sup>

- **Certification Authorities** container에는 신뢰할 수 있는 root CA certificates가 저장됩니다.
- **Enrolment Services** container에는 Enterprise CAs와 해당 certificate templates에 대한 세부 정보가 포함됩니다.
- **NTAuthCertificates** object에는 AD authentication에 권한이 부여된 CA certificates가 포함됩니다.
- **AIA (Authority Information Access)** container는 intermediate 및 cross CA certificates를 사용하여 certificate chain validation을 지원합니다.

### Certificate Acquisition: Client Certificate Request Flow

1. request process는 client가 Enterprise CA를 찾는 것에서 시작됩니다.
2. public-private key pair를 생성한 후 public key와 기타 세부 정보가 포함된 CSR이 생성됩니다.
3. CA는 사용 가능한 certificate templates를 기준으로 CSR을 평가하고, template의 permissions에 따라 certificate를 발급합니다.
4. 승인되면 CA는 자신의 private key로 certificate에 서명한 후 client에게 반환합니다.<sup>[[4]](#references)</sup>

### Certificate Templates

AD 내에 정의되는 이러한 templates는 허용되는 EKUs와 enrollment 또는 modification rights를 포함하여 certificates 발급을 위한 설정 및 permissions을 지정하며, certificate services에 대한 access를 관리하는 데 중요합니다.<sup>[[4]](#references)</sup>

**Template schema version이 중요합니다.** Legacy **v1** templates(예: 기본 제공되는 **WebServer** template)에는 여러 최신 enforcement 설정이 없습니다. **ESC15/EKUwu** research에서 확인된 바에 따르면, **v1 templates**에서는 requester가 CSR에 **Application Policies/EKUs**를 삽입할 수 있으며, 이는 template에 설정된 EKUs보다 **우선적으로 적용**됩니다. 따라서 enrollment rights만으로 client-auth, enrollment agent 또는 code-signing certificates를 생성할 수 있습니다. **v2/v3 templates**를 우선 사용하고, v1 defaults를 제거하거나 supersede하며, EKUs를 의도한 용도로 엄격하게 제한해야 합니다.<sup>[[1]](#references)</sup>

## Certificate Enrollment

certificates의 enrollment process는 administrator가 **certificate template을 생성**하는 것으로 시작하며, 이후 Enterprise Certificate Authority (CA)가 이를 **publish**합니다. 이를 통해 template을 client enrollment에 사용할 수 있으며, 이는 Active Directory object의 `certificatetemplates` field에 template의 name을 추가하여 수행됩니다.<sup>[[4]](#references)</sup>

client가 certificate를 request하려면 **enrollment rights**가 부여되어야 합니다. 이러한 rights는 certificate template 및 Enterprise CA 자체의 security descriptors에 정의됩니다. request가 성공하려면 두 위치 모두에서 permissions가 부여되어야 합니다.

### Template Enrollment Rights

이러한 rights는 Access Control Entries (ACEs)를 통해 지정되며, 다음과 같은 permissions을 정의합니다:

- **Certificate-Enrollment** 및 **Certificate-AutoEnrollment** rights. 각각 특정 GUID와 연결됩니다.
- **ExtendedRights**는 모든 extended permissions을 허용합니다.
- **FullControl/GenericAll**은 template에 대한 완전한 control을 제공합니다.

### Enterprise CA Enrollment Rights

CA의 rights는 Certificate Authority management console을 통해 확인할 수 있는 security descriptor에 정의됩니다. 일부 settings는 low-privileged users에게 remote access까지 허용할 수 있어 security concern이 될 수 있습니다.

### Additional Issuance Controls

다음과 같은 특정 controls가 적용될 수 있습니다:

- **Manager Approval**: certificate manager가 승인할 때까지 requests를 pending state로 설정합니다.
- **Enrolment Agents and Authorized Signatures**: CSR에 필요한 signatures 수와 필요한 Application Policy OIDs를 지정합니다.

### Methods to Request Certificates

certificates는 다음 방법으로 request할 수 있습니다:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)을 사용하며, DCOM interfaces를 이용합니다.
2. **ICertPassage Remote Protocol** (MS-ICPR)을 사용하며, named pipes 또는 TCP/IP를 통해 수행합니다.
3. Certificate Authority Web Enrollment role이 설치된 **certificate enrollment web interface**를 사용합니다.
4. **Certificate Enrollment Service** (CES)를 **Certificate Enrollment Policy** (CEP) service와 함께 사용합니다.
5. Simple Certificate Enrollment Protocol (SCEP)을 사용하는 network devices용 **Network Device Enrollment Service** (NDES)를 사용합니다.

Windows users는 GUI(`certmgr.msc` 또는 `certlm.msc`)나 command-line tools(`certreq.exe` 또는 PowerShell의 `Get-Certificate` command)를 통해서도 certificates를 request할 수 있습니다.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate 인증

Active Directory (AD)는 주로 **Kerberos** 및 **Secure Channel (Schannel)** 프로토콜을 사용하여 certificate 인증을 지원합니다.

### Kerberos 인증 프로세스

Kerberos 인증 프로세스에서 사용자가 Ticket Granting Ticket (TGT)을 요청할 때, 사용자의 certificate **private key**로 요청에 서명합니다. 이 요청은 domain controller에서 certificate의 **유효성**, **경로**, **revocation 상태**를 포함한 여러 검증을 거칩니다. 또한 certificate가 신뢰할 수 있는 source에서 발급되었는지 확인하고, 발급자가 **NTAUTH certificate store**에 존재하는지 검증합니다. 검증이 성공하면 TGT가 발급됩니다. AD의 **`NTAuthCertificates`** object는 다음 위치에 있습니다:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
는 certificate authentication에 대한 신뢰를 설정하는 데 핵심적입니다.<sup>[[4]](#references)</sup>

**KB5014754** rollout 이후 modern Kerberos certificate auth는 단순히 EKU만이 아니라 대부분 **mapping strength**와 관련됩니다.<sup>[[2]](#references)</sup> Hardened forest에서는:

- **UPN/DNS SAN**만 포함하는 certificate로는 더 이상 logon에 충분하지 않을 수 있습니다.
- KDC는 일반적으로 **SID security extension** (`1.3.6.1.4.1.311.25.2`) 또는 `altSecurityIdentities`의 강력한 명시적 mapping인 **strong binding**을 우선합니다.
- cert에 strong mapping이 없으면 DC는 compatibility mode에서 **Kdcsvc Event ID 39/41**을 log하고, enforcement mode에서는 auth를 거부합니다.
- 혼합 attack path에서는 **ESC9/ESC16**이 중요한데, 발급된 cert에서 SID extension을 제거하기 때문입니다. 이후 operators는 attack path가 지원하는 경우 explicit mapping 또는 SAN URL SID format에 의존합니다.

### Secure Channel (Schannel) Authentication

Schannel은 보안 TLS/SSL 연결을 지원합니다. handshake 중 client가 certificate를 제시하며, 해당 certificate가 성공적으로 검증되면 access가 승인됩니다. Certificate를 AD account에 mapping하는 과정에는 Kerberos의 **S4U2Self** function이나 certificate의 **Subject Alternative Name (SAN)** 등이 사용될 수 있습니다.<sup>[[4]](#references)</sup>

**PKINIT**를 사용할 수 없는 경우 Schannel은 실질적인 fallback이기도 합니다. 예를 들어 domain controller에 적합한 **Smart Card Logon** certificate가 없으면 `certipy auth`/PKINIT tooling이 TGT를 가져오는 데 실패할 수 있지만, 동일한 certificate를 **LDAPS** 또는 **LDAP StartTLS**에 사용하여 authentication 및 LDAP operations를 수행할 수 있습니다.

### AD Certificate Services Enumeration

AD의 certificate services는 LDAP queries를 통해 enumerate할 수 있으며, **Enterprise Certificate Authorities (CAs)** 및 해당 configurations에 관한 정보를 확인할 수 있습니다. 이는 special privileges 없이 domain-authenticated user라면 누구나 사용할 수 있습니다. **[Certify](https://github.com/GhostPack/Certify)** 및 **[Certipy](https://github.com/ly4k/Certipy)**와 같은 tools는 AD CS environments에서 enumeration 및 vulnerability assessment에 사용됩니다.

이러한 tools를 사용하기 위한 commands는 다음과 같습니다:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## 최신 취약점 및 보안 업데이트 (2022-2025)

| 연도 | ID / 이름 | 영향 | 주요 요점 |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT 중 machine account 인증서를 spoofing하여 발생하는 *권한 상승*. | **2022년 5월 10일** 보안 업데이트에 patch가 포함되었습니다. **KB5014754**를 통해 auditing 및 strong-mapping 제어 기능이 도입되었으며, 환경은 이제 *Full Enforcement* 모드로 전환되어야 합니다.  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) 및 CES roles의 *원격 코드 실행*. | 공개 PoC는 제한적이지만 취약한 IIS components가 내부에 노출된 경우가 많습니다. **2023년 7월** Patch Tuesday 기준으로 patch되었습니다.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates**에서 enrollment rights가 있는 requester는 CSR에 **Application Policies/EKUs**를 삽입할 수 있으며, 이는 template EKUs보다 우선되어 client-auth, enrollment agent 또는 code-signing certificates를 생성합니다. | **2024년 11월 12일** 기준으로 patch되었습니다. v1 templates(예: 기본 WebServer)를 교체하거나 supersede하고, EKUs를 용도에 맞게 제한하며, enrollment rights를 최소화해야 합니다. |

### Microsoft hardening timeline (KB5014754)

Microsoft는 Kerberos certificate authentication을 weak implicit mappings에서 벗어나게 하기 위해 세 단계의 rollout(Compatibility → Audit → Enforcement)을 도입했습니다. **2025년 2월 11일** 기준으로 `StrongCertificateBindingEnforcement` registry value가 설정되지 않은 경우 domain controllers는 자동으로 **Full Enforcement**로 전환됩니다. 이후 Microsoft는 timeline을 업데이트하여 **2025년 9월 9일** 보안 업데이트까지 compatibility mode로 fallback할 수 있도록 했습니다.<sup>[[2]](#references)</sup> Administrators는 다음을 수행해야 합니다.

1. 모든 DC와 AD CS servers에 patch를 적용합니다(2022년 5월 또는 이후).
2. *Audit* phase 동안 weak mappings에 대한 Event ID 39/41을 monitor합니다.
3. enforcement가 weak mappings를 차단하기 전에 새로운 **SID extension**을 사용하여 client-auth certificates를 재발급하거나 strong manual mappings를 구성합니다.

### Hardened forests를 위한 operator notes

- **ESC1/ESC6만으로는 2025년 이후 환경에서 더 이상 전체 상황을 설명할 수 없습니다**. 다른 principal에 대한 cert를 request하는 경우 일반적으로 SID extension 또는 explicit mapping과 같은 strong mapping artifact도 필요합니다.
- **ESC15 (EKUwu)**는 주로 patch되지 않은 환경에서 유용합니다. **Application Policies**를 삽입하여 **WebServer**와 같은 무해한 **v1** templates를 authentication 또는 enrollment-agent 기능을 가진 certs로 변환하기 때문입니다. Kerberos PKINIT은 여전히 EKUs를 평가하지만 **LDAP Schannel**도 Application Policies를 적용하므로 LDAP 기반 abuse가 여전히 유효합니다.<sup>[[1]](#references)</sup>
- **ESC16**은 CA 전체에 적용되는 설정입니다. CA가 SID security extension을 전역적으로 비활성화하면 attack chain이 다른 지원 형식으로 SID를 삽입하지 않는 한, 발급되는 모든 certificate는 더 약한 mapping 동작으로 fallback합니다.

---

## Detection 및 Hardening 개선 사항

* **Defender for Identity AD CS sensor (2023-2024)**는 이제 ESC1-ESC8/ESC11에 대한 posture assessments를 표시하고, *“비-DC에 대한 domain-controller certificate issuance”* (ESC8) 및 *“임의의 Application Policies를 사용한 Certificate Enrollment 방지”* (ESC15)와 같은 real-time alerts를 생성합니다. 이러한 detections를 활용하려면 모든 AD CS servers에 sensors가 배포되어 있는지 확인합니다.<sup>[[3]](#references)</sup>
* 모든 templates에서 **“Supply in the request”** option을 비활성화하거나 범위를 엄격히 제한합니다. 명시적으로 정의된 SAN/EKU values를 우선 사용합니다.
* 반드시 필요한 경우가 아니라면 templates에서 **Any Purpose** 또는 **No EKU**를 제거합니다(ESC2 scenarios 해결).
* 민감한 templates(예: WebServer / CodeSigning)에 대해 **manager approval** 또는 전용 Enrollment Agent workflows를 요구합니다.
* web enrollment (`certsrv`) 및 CES/NDES endpoints를 trusted networks로 제한하거나 client-certificate authentication 뒤에 배치합니다.
* RPC enrollment encryption을 적용합니다(`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`). 이를 통해 ESC11(RPC relay)을 완화할 수 있습니다. 이 flag는 **기본적으로 활성화**되어 있지만 legacy clients를 위해 비활성화되는 경우가 많아 relay risk가 다시 발생합니다.
* **IIS 기반 enrollment endpoints**(CES/Certsrv)를 보호합니다. 가능한 경우 NTLM을 비활성화하거나 HTTPS + Extended Protection을 요구하여 ESC8 relays를 차단합니다.

---

## References

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
