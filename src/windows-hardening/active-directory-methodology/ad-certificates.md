# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Certificate의 Components

- certificate의 **Subject**는 소유자를 나타냅니다.
- **Public Key**는 비공개로 보관된 key와 짝을 이루어 certificate를 정당한 소유자와 연결합니다.
- **Validity Period**는 **NotBefore**와 **NotAfter** 날짜로 정의되며, certificate의 유효 기간을 표시합니다.
- Certificate Authority (CA)가 제공하는 고유한 **Serial Number**는 각 certificate를 식별합니다.
- **Issuer**는 certificate를 발급한 CA를 의미합니다.
- **SubjectAlternativeName**은 subject에 대한 추가 이름을 허용하여 식별 유연성을 높입니다.
- **Basic Constraints**는 certificate가 CA용인지 end entity용인지 식별하고 사용 제한을 정의합니다.
- **Extended Key Usages (EKUs)**는 Object Identifiers (OIDs)를 통해 code signing이나 email encryption 같은 certificate의 특정 용도를 구분합니다.
- **Signature Algorithm**은 certificate에 서명하는 방법을 지정합니다.
- 발급자의 private key로 생성된 **Signature**는 certificate의 진위를 보장합니다.

### Special Considerations

- **Subject Alternative Names (SANs)**는 certificate의 적용 범위를 여러 identity로 확장하며, 여러 domain을 가진 server에 매우 중요합니다. 안전한 발급 절차는 공격자가 SAN specification을 조작해 impersonation risk를 일으키는 것을 막기 위해 필수적입니다.

### Active Directory (AD)의 Certificate Authorities (CAs)

AD CS는 AD forest 내에서 지정된 container를 통해 CA certificate를 인식하며, 각 container는 고유한 역할을 수행합니다:

- **Certification Authorities** container는 신뢰되는 root CA certificate를 보관합니다.
- **Enrolment Services** container는 Enterprise CAs와 그 certificate template의 세부 정보를 담고 있습니다.
- **NTAuthCertificates** object는 AD authentication이 허가된 CA certificate를 포함합니다.
- **AIA (Authority Information Access)** container는 intermediate 및 cross CA certificate를 사용한 certificate chain validation을 지원합니다.

### Certificate Acquisition: Client Certificate Request Flow

1. 요청 과정은 client가 Enterprise CA를 찾는 것에서 시작됩니다.
2. public-private key pair를 생성한 뒤, public key와 기타 세부 정보를 포함한 CSR이 만들어집니다.
3. CA는 CSR을 사용 가능한 certificate template과 대조해 평가하고, template의 permissions에 따라 certificate를 발급합니다.
4. 승인이 완료되면, CA는 자신의 private key로 certificate에 서명한 뒤 client에게 반환합니다.

### Certificate Templates

AD 내에서 정의되는 이 template들은 허용된 EKUs와 enrollment 또는 modification rights를 포함하여 certificate 발급을 위한 설정과 permissions를 정리하며, certificate service 접근 관리에 매우 중요합니다.

**Template schema version matters.** legacy **v1** template(예: 기본 제공 **WebServer** template)은 여러 modern enforcement knob가 부족합니다. **ESC15/EKUwu** research에 따르면 **v1 template**에서는 requester가 CSR에 **Application Policies/EKUs**를 넣을 수 있고, 이는 template에 설정된 EKUs보다 **우선**하므로, enrollment rights만으로 client-auth, enrollment agent, 또는 code-signing certificate를 사용할 수 있게 됩니다. **v2/v3 template**를 우선 사용하고, v1 기본값은 제거하거나 대체하며, EKUs는 의도한 용도에 맞게 엄격하게 제한하세요.

## Certificate Enrollment

certificate enrollment process는 administrator가 **certificate template를 생성**한 뒤 Enterprise Certificate Authority (CA)가 이를 **publish**하면서 시작됩니다. 이렇게 하면 template가 client enrollment에 사용 가능해지며, 이는 Active Directory object의 `certificatetemplates` field에 template 이름을 추가함으로써 이루어집니다.

client가 certificate를 요청하려면 **enrollment rights**가 부여되어야 합니다. 이 권한은 certificate template와 Enterprise CA 자체의 security descriptor에 의해 정의됩니다. request가 성공하려면 두 위치 모두에서 permission이 부여되어야 합니다.

### Template Enrollment Rights

이 rights는 Access Control Entries (ACEs)를 통해 지정되며, 다음과 같은 permissions를 상세히 정의합니다:

- 특정 GUID와 연결된 **Certificate-Enrollment** 및 **Certificate-AutoEnrollment** rights.
- 모든 extended permission을 허용하는 **ExtendedRights**.
- template에 대한 완전한 제어를 제공하는 **FullControl/GenericAll**.

### Enterprise CA Enrollment Rights

CA의 rights는 Certificate Authority management console에서 접근 가능한 security descriptor에 정의됩니다. 일부 설정은 low-privileged user에게 remote access까지 허용하며, 이는 security concern이 될 수 있습니다.

### Additional Issuance Controls

다음과 같은 특정 control이 적용될 수 있습니다:

- **Manager Approval**: certificate manager가 승인할 때까지 request를 pending state로 둡니다.
- **Enrolment Agents and Authorized Signatures**: CSR에 필요한 signature 수와 필요한 Application Policy OID를 지정합니다.

### Methods to Request Certificates

certificate는 다음 방법으로 요청할 수 있습니다:

1. DCOM interface를 사용하는 **Windows Client Certificate Enrollment Protocol** (MS-WCCE).
2. named pipe 또는 TCP/IP를 통한 **ICertPassage Remote Protocol** (MS-ICPR).
3. Certificate Authority Web Enrollment role이 설치된 **certificate enrollment web interface**.
4. **Certificate Enrollment Service** (CES)와 **Certificate Enrollment Policy** (CEP) service의 조합.
5. network device를 위한 **Network Device Enrollment Service** (NDES)로, Simple Certificate Enrollment Protocol (SCEP)을 사용합니다.

Windows user는 GUI(`certmgr.msc` 또는 `certlm.msc`)나 command-line tool(`certreq.exe` 또는 PowerShell의 `Get-Certificate` command)로도 certificate를 요청할 수 있습니다.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD)는 certificate authentication을 지원하며, 주로 **Kerberos**와 **Secure Channel (Schannel)** 프로토콜을 활용합니다.

### Kerberos Authentication Process

Kerberos authentication process에서 사용자의 Ticket Granting Ticket (TGT) 요청은 사용자의 certificate의 **private key**를 사용해 서명됩니다. 이 요청은 domain controller에 의해 여러 검증을 거치는데, 여기에는 certificate의 **validity**, **path**, 그리고 **revocation status**가 포함됩니다. 검증에는 또한 certificate가 trusted source에서 왔는지 확인하고, issuer가 **NTAUTH certificate store**에 존재하는지 확인하는 과정도 포함됩니다. 이러한 검증이 성공하면 TGT가 발급됩니다. AD의 **`NTAuthCertificates`** object는 다음 위치에 있습니다:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is certificate authentication의 신뢰를 구축하는 데 핵심적입니다.

**KB5014754** 롤아웃 이후, 현대 Kerberos certificate auth는 주로 **mapping strength**에 관한 것이지, EKU만의 문제가 아닙니다. 강화된 forests에서는:

- **UPN/DNS SAN**만 포함된 certificate는 더 이상 logon에 충분하지 않을 수 있습니다.
- KDC는 일반적으로 **SID security extension** (`1.3.6.1.4.1.311.25.2`) 또는 `altSecurityIdentities`의 강한 explicit mapping과 같은 **strong binding**을 선호합니다.
- cert에 strong mapping이 없으면, DC는 compatibility mode에서 **Kdcsvc Event ID 39/41**을 기록하고 enforcement mode에서는 auth를 거부합니다.
- mixed attack paths에서는 **ESC9/ESC16**가 중요합니다. 이들은 발급된 cert에서 SID extension을 제거하기 때문입니다. 이후 운영자는 attack path가 지원하는 경우 explicit mappings 또는 SAN URL SID formats에 의존합니다.

### Secure Channel (Schannel) Authentication

Schannel은 secure TLS/SSL connections를 지원하며, handshake 동안 client가 certificate를 제시하고, 그것이 성공적으로 validated되면 access가 authorized됩니다. certificate를 AD account에 mapping하는 작업에는 Kerberos의 **S4U2Self** 기능 또는 certificate의 **Subject Alternative Name (SAN)** 등이 포함될 수 있습니다.

Schannel은 **PKINIT**를 사용할 수 없을 때의 실질적인 fallback이기도 합니다. 예를 들어, domain controller에 적절한 **Smart Card Logon** certificate가 없으면 `certipy auth`/PKINIT tooling이 TGT를 얻지 못할 수 있지만, 같은 certificate는 **LDAPS** 또는 **LDAP StartTLS**에 대해 authentication 및 LDAP operations에 여전히 사용할 수 있습니다.

### AD Certificate Services Enumeration

AD의 certificate services는 LDAP queries를 통해 enumerated될 수 있으며, 이를 통해 **Enterprise Certificate Authorities (CAs)** 및 그 configurations에 대한 정보를 확인할 수 있습니다. 이는 특별한 privileges 없이 domain-authenticated user라면 누구나 접근할 수 있습니다. **[Certify](https://github.com/GhostPack/Certify)**와 **[Certipy](https://github.com/ly4k/Certipy)** 같은 tools는 AD CS environments에서 enumeration 및 vulnerability assessment에 사용됩니다.

이러한 tools를 사용하는 commands는 다음과 같습니다:
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

## Recent Vulnerabilities & Security Updates (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT 중 machine account certificates를 spoofing하여 *Privilege escalation*. | Patch는 **2022년 5월 10일** security updates에 포함되어 있습니다. Auditing 및 strong-mapping controls는 **KB5014754**를 통해 도입되었습니다. 환경은 이제 *Full Enforcement* mode여야 합니다.  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) 및 CES roles에서 *Remote code-execution*. | Public PoC는 제한적이지만, 취약한 IIS components는 종종 내부적으로 노출됩니다. **2023년 7월** Patch Tuesday 기준으로 patch되었습니다.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates**에서 enrollment rights를 가진 requester는 CSR에 **Application Policies/EKUs**를 삽입할 수 있으며, 이는 template EKUs보다 우선 적용되어 client-auth, enrollment agent, 또는 code-signing certificates를 생성합니다. | **2024년 11월 12일** 기준으로 patched. v1 templates(예: default WebServer)을 교체하거나 상위 대체하고, EKUs를 의도에 맞게 제한하며, enrollment rights를 제한하세요. |

### Microsoft hardening timeline (KB5014754)

Microsoft는 Kerberos certificate authentication을 약한 implicit mappings에서 분리하기 위해 3단계 rollout (Compatibility → Audit → Enforcement)을 도입했습니다. **2025년 2월 11일** 기준으로, `StrongCertificateBindingEnforcement` registry value가 설정되어 있지 않으면 domain controllers는 자동으로 **Full Enforcement**로 전환됩니다. 이후 Microsoft는 timeline을 업데이트하여, **2025년 9월 9일** security update까지는 compatibility mode로의 fallback이 계속 가능하도록 했습니다. Administrators는 다음을 수행해야 합니다:

1. 모든 DCs 및 AD CS servers를 patch하세요 (2022년 5월 또는 이후).
2. *Audit* phase 동안 weak mappings에 대한 Event ID 39/41을 모니터링하세요.
3. enforcement가 weak mappings를 차단하기 전에 client-auth certificates를 새 **SID extension**으로 re-issue하거나, 강한 manual mappings를 구성하세요.

### Operator notes for hardened forests

- **ESC1/ESC6 alone is no longer the whole story** in 2025+ environments. 다른 principal에 대해 cert를 요청하는 경우, 일반적으로 SID extension이나 explicit mapping 같은 strong mapping artifact도 필요합니다.
- **ESC15 (EKUwu)**는 주로 unpatched environments에서 유용합니다. **WebServer** 같은 harmless **v1** templates를 **Application Policies**를 주입하여 authentication- 또는 enrollment-agent-capable certs로 바꾸기 때문입니다. Kerberos PKINIT는 여전히 EKUs를 평가하지만, **LDAP Schannel**도 Application Policies를 허용하므로 LDAP-based abuse가 여전히 유효합니다.
- **ESC16**은 CA-wide knob입니다: CA가 SID security extension을 전역적으로 비활성화하면, attack chain이 다른 지원되는 format으로 SID를 주입하지 않는 한 발급되는 모든 certificate는 더 약한 mapping behavior로 되돌아갑니다.

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** now surfaces posture assessments for ESC1-ESC8/ESC11 and generates real-time alerts such as *“Domain-controller certificate issuance for a non-DC”* (ESC8) and *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). 이러한 detections를 활용하려면 모든 AD CS servers에 sensor가 배포되어 있는지 확인하세요.
* 모든 templates에서 **“Supply in the request”** 옵션을 비활성화하거나 엄격히 범위를 제한하세요. 명시적으로 정의된 SAN/EKU values를 우선하세요.
* 꼭 필요한 경우가 아니면 templates에서 **Any Purpose** 또는 **No EKU**를 제거하세요 (ESC2 scenarios 대응).
* 민감한 templates(예: WebServer / CodeSigning)에 대해서는 **manager approval** 또는 전용 Enrollment Agent workflows를 요구하세요.
* web enrollment (`certsrv`) 및 CES/NDES endpoints를 신뢰할 수 있는 networks 또는 client-certificate authentication 뒤로 제한하세요.
* RPC enrollment encryption(`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`)을 강제하여 ESC11 (RPC relay)을 완화하세요. 이 flag는 **기본적으로 on**이지만, legacy clients 때문에 자주 비활성화되며, 그러면 relay risk가 다시 열립니다.
* **IIS-based enrollment endpoints** (CES/Certsrv)를 보호하세요: 가능한 경우 NTLM을 비활성화하거나 HTTPS + Extended Protection을 요구하여 ESC8 relays를 차단하세요.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
