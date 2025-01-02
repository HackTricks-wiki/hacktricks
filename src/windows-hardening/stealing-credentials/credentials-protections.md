# Windows Credentials Protections

## Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) 프로토콜은 Windows XP와 함께 도입되었으며, HTTP 프로토콜을 통한 인증을 위해 설계되었으며 **Windows XP에서 Windows 8.0 및 Windows Server 2003에서 Windows Server 2012까지 기본적으로 활성화되어 있습니다**. 이 기본 설정은 **LSASS(로컬 보안 권한 하위 시스템 서비스)에서 평문 비밀번호 저장**을 초래합니다. 공격자는 Mimikatz를 사용하여 **이 자격 증명을 추출**할 수 있습니다:
```bash
sekurlsa::wdigest
```
이 기능을 **켜거나 끄려면**, _**UseLogonCredential**_ 및 _**Negotiate**_ 레지스트리 키가 _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 내에서 "1"로 설정되어야 합니다. 이러한 키가 **없거나 "0"으로 설정되어 있으면**, WDigest는 **비활성화**됩니다:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA 보호

**Windows 8.1**부터 Microsoft는 LSA의 보안을 강화하여 **신뢰할 수 없는 프로세스에 의한 무단 메모리 읽기 또는 코드 주입을 차단**합니다. 이 강화는 `mimikatz.exe sekurlsa:logonpasswords`와 같은 명령의 일반적인 기능을 방해합니다. 이 _**강화된 보호**_를 **활성화**하려면, _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_의 _**RunAsPPL**_ 값을 1로 조정해야 합니다:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

이 보호를 우회하는 것은 Mimikatz 드라이버 mimidrv.sys를 사용하여 가능합니다:

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**는 **Windows 10 (Enterprise 및 Education 에디션)** 전용 기능으로, **Virtual Secure Mode (VSM)** 및 **Virtualization Based Security (VBS)**를 사용하여 머신 자격 증명의 보안을 강화합니다. 이는 CPU 가상화 확장을 활용하여 주요 프로세스를 보호된 메모리 공간 내에서 격리시켜, 주요 운영 체제의 접근을 차단합니다. 이 격리는 커널조차도 VSM의 메모리에 접근할 수 없도록 하여, **pass-the-hash**와 같은 공격으로부터 자격 증명을 효과적으로 보호합니다. **Local Security Authority (LSA)**는 이 안전한 환경 내에서 신뢰할 수 있는 요소로 작동하며, 주요 OS의 **LSASS** 프로세스는 VSM의 LSA와 단순히 통신하는 역할만 합니다.

기본적으로 **Credential Guard**는 활성화되어 있지 않으며, 조직 내에서 수동으로 활성화해야 합니다. 이는 **Mimikatz**와 같은 도구에 대한 보안을 강화하는 데 중요하며, 이러한 도구는 자격 증명을 추출하는 능력이 제한됩니다. 그러나 로그인 시도 중에 자격 증명을 평문으로 캡처하기 위해 사용자 정의 **Security Support Providers (SSP)**를 추가함으로써 여전히 취약점을 악용할 수 있습니다.

**Credential Guard**의 활성화 상태를 확인하려면, _**HKLM\System\CurrentControlSet\Control\LSA**_ 아래의 레지스트리 키 _**LsaCfgFlags**_를 검사할 수 있습니다. "**1**" 값은 **UEFI 잠금**이 있는 활성화를 나타내고, "**2**"는 잠금 없이, "**0**"은 활성화되지 않음을 나타냅니다. 이 레지스트리 확인은 강력한 지표이지만, Credential Guard를 활성화하기 위한 유일한 단계는 아닙니다. 이 기능을 활성화하기 위한 자세한 안내와 PowerShell 스크립트는 온라인에서 확인할 수 있습니다.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
포괄적인 이해와 **Credential Guard**를 Windows 10에서 활성화하는 방법 및 **Windows 11 Enterprise 및 Education (버전 22H2)**의 호환 시스템에서 자동으로 활성화하는 방법에 대한 지침은 [Microsoft의 문서](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)를 방문하세요.

자격 증명 캡처를 위한 사용자 지정 SSP 구현에 대한 추가 세부정보는 [이 가이드](../active-directory-methodology/custom-ssp.md)에 제공됩니다.

## RDP RestrictedAdmin 모드

**Windows 8.1 및 Windows Server 2012 R2**는 _**RDP를 위한 Restricted Admin 모드**_를 포함하여 여러 새로운 보안 기능을 도입했습니다. 이 모드는 [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) 공격과 관련된 위험을 완화하여 보안을 강화하도록 설계되었습니다.

전통적으로 RDP를 통해 원격 컴퓨터에 연결할 때, 자격 증명은 대상 컴퓨터에 저장됩니다. 이는 특히 권한이 상승된 계정을 사용할 때 상당한 보안 위험을 초래합니다. 그러나 _**Restricted Admin 모드**_의 도입으로 이 위험이 크게 줄어듭니다.

**mstsc.exe /RestrictedAdmin** 명령을 사용하여 RDP 연결을 시작할 때, 원격 컴퓨터에 대한 인증은 자격 증명을 저장하지 않고 수행됩니다. 이 접근 방식은 악성 소프트웨어 감염이 발생하거나 악의적인 사용자가 원격 서버에 접근할 경우, 자격 증명이 서버에 저장되지 않기 때문에 손상되지 않도록 보장합니다.

**Restricted Admin 모드**에서는 RDP 세션에서 네트워크 리소스에 접근하려는 시도가 개인 자격 증명을 사용하지 않으며, 대신 **기계의 ID**가 사용된다는 점에 유의해야 합니다.

이 기능은 원격 데스크톱 연결을 보호하고 보안 위반 시 민감한 정보가 노출되는 것을 방지하는 데 중요한 진전을 나타냅니다.

![](../../images/RAM.png)

자세한 정보는 [이 리소스](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)를 방문하세요.

## 캐시된 자격 증명

Windows는 **Local Security Authority (LSA)**를 통해 **도메인 자격 증명**을 보호하며, **Kerberos** 및 **NTLM**과 같은 보안 프로토콜로 로그온 프로세스를 지원합니다. Windows의 주요 기능 중 하나는 **마지막 10개의 도메인 로그인**을 캐시하여 **도메인 컨트롤러가 오프라인일 때도 사용자가 컴퓨터에 접근할 수 있도록** 하는 것입니다. 이는 회사 네트워크에서 자주 떨어져 있는 노트북 사용자에게 유용합니다.

캐시된 로그인 수는 특정 **레지스트리 키 또는 그룹 정책**을 통해 조정할 수 있습니다. 이 설정을 보거나 변경하려면 다음 명령을 사용합니다:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
이 캐시된 자격 증명에 대한 접근은 엄격하게 제어되며, **SYSTEM** 계정만이 이를 볼 수 있는 필요한 권한을 가지고 있습니다. 이 정보를 액세스해야 하는 관리자는 SYSTEM 사용자 권한으로 수행해야 합니다. 자격 증명은 다음에 저장됩니다: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**는 `lsadump::cache` 명령을 사용하여 이러한 캐시된 자격 증명을 추출하는 데 사용될 수 있습니다.

자세한 내용은 원본 [source](http://juggernaut.wikidot.com/cached-credentials)에서 포괄적인 정보를 제공합니다.

## 보호된 사용자

**Protected Users group**의 구성원 자격은 사용자에게 여러 보안 향상을 도입하여 자격 증명 도용 및 남용에 대한 더 높은 수준의 보호를 보장합니다:

- **Credential Delegation (CredSSP)**: **Allow delegating default credentials**에 대한 그룹 정책 설정이 활성화되어 있더라도, 보호된 사용자의 평문 자격 증명은 캐시되지 않습니다.
- **Windows Digest**: **Windows 8.1 및 Windows Server 2012 R2**부터 시스템은 보호된 사용자의 평문 자격 증명을 캐시하지 않으며, Windows Digest 상태와 관계없이 적용됩니다.
- **NTLM**: 시스템은 보호된 사용자의 평문 자격 증명이나 NT 일방향 함수(NTOWF)를 캐시하지 않습니다.
- **Kerberos**: 보호된 사용자의 경우, Kerberos 인증은 **DES** 또는 **RC4 키**를 생성하지 않으며, 초기 티켓 부여 티켓(TGT) 획득을 초과하여 평문 자격 증명이나 장기 키를 캐시하지 않습니다.
- **오프라인 로그인**: 보호된 사용자는 로그인 또는 잠금 해제 시 캐시된 검증자가 생성되지 않으므로 이러한 계정에 대한 오프라인 로그인이 지원되지 않습니다.

이러한 보호는 **Protected Users group**의 구성원이 장치에 로그인하는 순간 활성화됩니다. 이는 다양한 자격 증명 손상 방법으로부터 보호하기 위한 중요한 보안 조치가 마련되어 있음을 보장합니다.

자세한 정보는 공식 [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)을 참조하십시오.

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

{{#include ../../banners/hacktricks-training.md}}
