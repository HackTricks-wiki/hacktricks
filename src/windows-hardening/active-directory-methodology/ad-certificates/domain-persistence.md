# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**이것은 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)에서 공유된 도메인 지속성 기술의 요약입니다**. 추가 세부정보는 해당 링크를 확인하세요.

## 도난당한 CA 인증서로 인증서 위조하기 - DPERSIST1

인증서가 CA 인증서인지 어떻게 알 수 있나요?

여러 조건이 충족되면 인증서가 CA 인증서임을 확인할 수 있습니다:

- 인증서는 CA 서버에 저장되며, 개인 키는 머신의 DPAPI 또는 운영 체제가 지원하는 경우 TPM/HSM과 같은 하드웨어로 보호됩니다.
- 인증서의 발급자(Issuer) 및 주체(Subject) 필드가 CA의 고유 이름과 일치합니다.
- "CA Version" 확장자가 CA 인증서에만 존재합니다.
- 인증서에는 확장 키 사용(EKU) 필드가 없습니다.

이 인증서의 개인 키를 추출하기 위해 CA 서버의 `certsrv.msc` 도구가 내장 GUI를 통해 지원되는 방법입니다. 그럼에도 불구하고 이 인증서는 시스템 내의 다른 인증서와 다르지 않으므로, [THEFT2 기술](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)과 같은 방법을 사용하여 추출할 수 있습니다.

인증서와 개인 키는 다음 명령어를 사용하여 Certipy로도 얻을 수 있습니다:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA 인증서와 그 개인 키를 `.pfx` 형식으로 획득한 후, [ForgeCert](https://github.com/GhostPack/ForgeCert)와 같은 도구를 사용하여 유효한 인증서를 생성할 수 있습니다:
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
> 인증서 위조의 대상이 되는 사용자는 활성 상태여야 하며 Active Directory에서 인증할 수 있어야 프로세스가 성공합니다. krbtgt와 같은 특수 계정에 대한 인증서를 위조하는 것은 효과적이지 않습니다.

이 위조된 인증서는 **유효** 기간이 지정된 종료일까지 **루트 CA 인증서가 유효한 한** (보통 5년에서 **10년 이상**) 유효합니다. 또한 **기계**에 대해서도 유효하므로 **S4U2Self**와 결합하면 공격자는 **CA 인증서가 유효한 한** 어떤 도메인 기계에서든 **지속성을 유지할 수 있습니다**.\
게다가, 이 방법으로 **생성된 인증서**는 CA가 이를 인식하지 못하므로 **취소할 수 없습니다**.

## 악성 CA 인증서 신뢰 - DPERSIST2

`NTAuthCertificates` 객체는 Active Directory (AD)가 사용하는 `cacertificate` 속성 내에 하나 이상의 **CA 인증서**를 포함하도록 정의됩니다. **도메인 컨트롤러**의 검증 프로세스는 인증하는 **인증서**의 발급자 필드에 지정된 **CA**와 일치하는 항목을 `NTAuthCertificates` 객체에서 확인하는 것을 포함합니다. 일치하는 항목이 발견되면 인증이 진행됩니다.

공격자는 이 AD 객체에 대한 제어 권한이 있는 경우 `NTAuthCertificates` 객체에 자체 서명된 CA 인증서를 추가할 수 있습니다. 일반적으로 **Enterprise Admin** 그룹의 구성원과 **도메인 관리자** 또는 **포리스트 루트 도메인**의 **관리자**만 이 객체를 수정할 수 있는 권한이 부여됩니다. 그들은 `certutil.exe`를 사용하여 `NTAuthCertificates` 객체를 편집할 수 있으며, 명령어는 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`입니다. 또는 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)을 사용할 수 있습니다.

이 기능은 ForgeCert를 사용하여 동적으로 인증서를 생성하는 이전에 설명된 방법과 함께 사용할 때 특히 관련이 있습니다.

## 악의적인 잘못된 구성 - DPERSIST3

AD CS 구성 요소의 **보안 설명자 수정**을 통한 **지속성** 기회는 풍부합니다. "[Domain Escalation](domain-escalation.md)" 섹션에 설명된 수정 사항은 권한이 상승된 공격자에 의해 악의적으로 구현될 수 있습니다. 여기에는 다음과 같은 민감한 구성 요소에 "제어 권한" (예: WriteOwner/WriteDACL 등)을 추가하는 것이 포함됩니다:

- **CA 서버의 AD 컴퓨터** 객체
- **CA 서버의 RPC/DCOM 서버**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 내의 모든 **하위 AD 객체 또는 컨테이너** (예: 인증서 템플릿 컨테이너, 인증 기관 컨테이너, NTAuthCertificates 객체 등)
- 기본적으로 또는 조직에 의해 AD CS를 제어할 권한이 위임된 **AD 그룹** (예: 내장된 Cert Publishers 그룹 및 그 구성원)

악의적인 구현의 예는 도메인에서 **상승된 권한**을 가진 공격자가 기본 **`User`** 인증서 템플릿에 **`WriteOwner`** 권한을 추가하는 것입니다. 공격자는 먼저 **`User`** 템플릿의 소유권을 자신으로 변경합니다. 그 후, **`mspki-certificate-name-flag`**를 **1**로 설정하여 **`ENROLLEE_SUPPLIES_SUBJECT`**를 활성화하여 사용자가 요청에 주체 대체 이름을 제공할 수 있도록 합니다. 이후 공격자는 **템플릿**을 사용하여 **도메인 관리자** 이름을 대체 이름으로 선택하고, 획득한 인증서를 DA로서 인증에 사용할 수 있습니다.

{{#include ../../../banners/hacktricks-training.md}}
