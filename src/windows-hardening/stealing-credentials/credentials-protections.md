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
## LSA Protection (PP & PPL 보호 프로세스)

**Protected Process (PP)** 및 **Protected Process Light (PPL)**는 **Windows 커널 수준 보호**로, **LSASS**와 같은 민감한 프로세스에 대한 무단 접근을 방지하기 위해 설계되었습니다. **Windows Vista**에서 도입된 **PP 모델**은 원래 **DRM** 집행을 위해 만들어졌으며, **특별 미디어 인증서**로 서명된 바이너리만 보호할 수 있었습니다. **PP**로 표시된 프로세스는 **동일하거나 더 높은 보호 수준**을 가진 다른 **PP 프로세스**만 접근할 수 있으며, 그 경우에도 **특별히 허용되지 않는 한 제한된 접근 권한**만 가집니다.

**PPL**은 **Windows 8.1**에서 도입된 PP의 더 유연한 버전입니다. **디지털 서명의 EKU (Enhanced Key Usage)** 필드를 기반으로 한 **"보호 수준"**을 도입하여 **더 넓은 사용 사례**(예: LSASS, Defender)를 허용합니다. 보호 수준은 `EPROCESS.Protection` 필드에 저장되며, 이는 다음을 포함하는 `PS_PROTECTION` 구조체입니다:
- **Type** (`Protected` 또는 `ProtectedLight`)
- **Signer** (예: `WinTcb`, `Lsa`, `Antimalware` 등)

이 구조체는 단일 바이트로 패킹되어 **누가 누구에게 접근할 수 있는지**를 결정합니다:
- **더 높은 서명자 값은 더 낮은 값을 접근할 수 있습니다**
- **PPL은 PP에 접근할 수 없습니다**
- **보호되지 않은 프로세스는 어떤 PPL/PP에도 접근할 수 없습니다**

### 공격적 관점에서 알아야 할 사항

- **LSASS가 PPL로 실행될 때**, 일반 관리자 컨텍스트에서 `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)`를 사용하여 열려고 시도하면 **`0x5 (Access Denied)`**로 실패합니다. `SeDebugPrivilege`가 활성화되어 있어도 마찬가지입니다.
- **Process Hacker**와 같은 도구를 사용하거나 `EPROCESS.Protection` 값을 읽어 프로그래밍적으로 **LSASS 보호 수준을 확인할 수 있습니다**.
- LSASS는 일반적으로 `PsProtectedSignerLsa-Light` (`0x41`)를 가지며, **더 높은 수준의 서명자로 서명된 프로세스**만 접근할 수 있습니다. 예를 들어 `WinTcb` (`0x61` 또는 `0x62`)입니다.
- PPL은 **사용자 공간 전용 제한**입니다; **커널 수준 코드는 이를 완전히 우회할 수 있습니다**.
- LSASS가 PPL이라고 해서 **커널 쉘코드를 실행하거나 적절한 접근 권한을 가진 고급 프로세스를 활용할 수 있다면 자격 증명 덤프를 방지하지는 않습니다**.
- **PPL 설정 또는 제거**는 재부팅 또는 **Secure Boot/UEFI 설정**이 필요하며, 이는 레지스트리 변경이 되돌려진 후에도 PPL 설정을 지속시킬 수 있습니다.

**PPL 보호 우회 옵션:**

PPL에도 불구하고 LSASS를 덤프하려면 3가지 주요 옵션이 있습니다:
1. **서명된 커널 드라이버 (예: Mimikatz + mimidrv.sys)**를 사용하여 **LSASS의 보호 플래그를 제거합니다**:

![](../../images/mimidrv.png)

2. **자신의 취약한 드라이버(BYOVD)**를 가져와 커널 코드를 실행하고 보호를 비활성화합니다. **PPLKiller**, **gdrv-loader**, 또는 **kdmapper**와 같은 도구를 사용하면 가능합니다.
3. **다른 프로세스에서 열린 LSASS 핸들을 훔친 다음** 이를 자신의 프로세스로 **복제합니다**. 이는 `pypykatz live lsa --method handledup` 기술의 기초입니다.
4. **임의의 코드를 해당 주소 공간에 로드할 수 있는 특권 프로세스를 악용하거나 다른 특권 프로세스 내부에 로드하여 PPL 제한을 효과적으로 우회합니다**. [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) 또는 [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump)에서 이 예제를 확인할 수 있습니다.

**LSASS에 대한 LSA 보호(PPL/PP)의 현재 상태 확인**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- For more information about this check [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**는 **Windows 10 (Enterprise 및 Education editions)** 전용 기능으로, **Virtual Secure Mode (VSM)** 및 **Virtualization Based Security (VBS)**를 사용하여 머신 자격 증명의 보안을 강화합니다. 이 기능은 CPU 가상화 확장을 활용하여 주요 프로세스를 보호된 메모리 공간 내에서 격리시켜, 주요 운영 체제의 접근을 차단합니다. 이 격리는 커널조차 VSM의 메모리에 접근할 수 없도록 하여, **pass-the-hash**와 같은 공격으로부터 자격 증명을 효과적으로 보호합니다. **Local Security Authority (LSA)**는 이 안전한 환경 내에서 신뢰할 수 있는 요소로 작동하며, 주요 OS의 **LSASS** 프로세스는 VSM의 LSA와 단순히 통신하는 역할만 합니다.

기본적으로 **Credential Guard**는 활성화되어 있지 않으며, 조직 내에서 수동으로 활성화해야 합니다. 이는 **Mimikatz**와 같은 도구에 대한 보안을 강화하는 데 중요하며, 이러한 도구는 자격 증명을 추출하는 능력이 제한됩니다. 그러나 로그인 시도 중에 자격 증명을 평문으로 캡처하기 위해 사용자 정의 **Security Support Providers (SSP)**를 추가함으로써 여전히 취약점을 악용할 수 있습니다.

**Credential Guard**의 활성화 상태를 확인하려면, _**HKLM\System\CurrentControlSet\Control\LSA**_ 아래의 레지스트리 키 _**LsaCfgFlags**_를 검사할 수 있습니다. 값이 "**1**"이면 **UEFI lock**이 활성화된 상태, "**2**"는 잠금 없이, "**0**"은 비활성화된 상태를 나타냅니다. 이 레지스트리 확인은 강력한 지표이지만, Credential Guard를 활성화하기 위한 유일한 단계는 아닙니다. 이 기능을 활성화하기 위한 자세한 안내와 PowerShell 스크립트는 온라인에서 확인할 수 있습니다.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
포괄적인 이해와 **Credential Guard**를 Windows 10에서 활성화하는 방법 및 **Windows 11 Enterprise 및 Education (버전 22H2)**의 호환 시스템에서 자동으로 활성화하는 방법에 대한 지침은 [Microsoft의 문서](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)를 방문하세요.

자격 증명 캡처를 위한 사용자 지정 SSP 구현에 대한 추가 세부정보는 [이 가이드](../active-directory-methodology/custom-ssp.md)에서 제공됩니다.

## RDP RestrictedAdmin 모드

**Windows 8.1 및 Windows Server 2012 R2**는 _**RDP를 위한 Restricted Admin 모드**_를 포함하여 여러 가지 새로운 보안 기능을 도입했습니다. 이 모드는 [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) 공격과 관련된 위험을 완화하여 보안을 강화하기 위해 설계되었습니다.

전통적으로 RDP를 통해 원격 컴퓨터에 연결할 때, 자격 증명은 대상 컴퓨터에 저장됩니다. 이는 특히 권한이 상승된 계정을 사용할 때 상당한 보안 위험을 초래합니다. 그러나 _**Restricted Admin 모드**_의 도입으로 이 위험이 크게 줄어듭니다.

**mstsc.exe /RestrictedAdmin** 명령을 사용하여 RDP 연결을 시작할 때, 원격 컴퓨터에 자격 증명을 저장하지 않고 인증이 수행됩니다. 이 접근 방식은 악성 소프트웨어 감염이 발생하거나 악의적인 사용자가 원격 서버에 접근할 경우, 자격 증명이 서버에 저장되지 않기 때문에 손상되지 않도록 보장합니다.

**Restricted Admin 모드**에서는 RDP 세션에서 네트워크 리소스에 접근하려는 시도가 개인 자격 증명을 사용하지 않으며, 대신 **기계의 ID**가 사용된다는 점에 유의해야 합니다.

이 기능은 원격 데스크톱 연결을 보호하고 보안 위반 시 민감한 정보가 노출되는 것을 방지하는 데 있어 중요한 진전을 나타냅니다.

![](../../images/RAM.png)

자세한 정보는 [이 리소스](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)를 방문하세요.

## 캐시된 자격 증명

Windows는 **Local Security Authority (LSA)**를 통해 **도메인 자격 증명**을 보호하며, **Kerberos** 및 **NTLM**과 같은 보안 프로토콜로 로그온 프로세스를 지원합니다. Windows의 주요 기능 중 하나는 **마지막 10개의 도메인 로그인**을 캐시하여 **도메인 컨트롤러가 오프라인일 때도 사용자가 컴퓨터에 접근할 수 있도록** 하는 것입니다. 이는 회사 네트워크에서 자주 떨어져 있는 노트북 사용자에게 유용합니다.

캐시된 로그인 수는 특정 **레지스트리 키 또는 그룹 정책**을 통해 조정할 수 있습니다. 이 설정을 보거나 변경하려면 다음 명령을 사용합니다:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
이 캐시된 자격 증명에 대한 접근은 엄격하게 제어되며, **SYSTEM** 계정만이 이를 볼 수 있는 필요한 권한을 가지고 있습니다. 이 정보를 접근해야 하는 관리자는 SYSTEM 사용자 권한으로 접근해야 합니다. 자격 증명은 다음에 저장됩니다: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**는 `lsadump::cache` 명령어를 사용하여 이 캐시된 자격 증명을 추출하는 데 사용될 수 있습니다.

자세한 내용은 원본 [source](http://juggernaut.wikidot.com/cached-credentials)에서 포괄적인 정보를 제공합니다.

## 보호된 사용자

**Protected Users group**의 구성원은 자격 증명 도용 및 남용에 대한 더 높은 수준의 보호를 보장하는 여러 보안 향상을 도입합니다:

- **Credential Delegation (CredSSP)**: **Allow delegating default credentials**에 대한 그룹 정책 설정이 활성화되어 있더라도, 보호된 사용자의 평문 자격 증명은 캐시되지 않습니다.
- **Windows Digest**: **Windows 8.1 및 Windows Server 2012 R2**부터, 시스템은 보호된 사용자의 평문 자격 증명을 캐시하지 않습니다. Windows Digest 상태와 관계없이 적용됩니다.
- **NTLM**: 시스템은 보호된 사용자의 평문 자격 증명이나 NT 일방향 함수(NTOWF)를 캐시하지 않습니다.
- **Kerberos**: 보호된 사용자의 경우, Kerberos 인증은 **DES** 또는 **RC4 키**를 생성하지 않으며, 평문 자격 증명이나 초기 Ticket-Granting Ticket (TGT) 획득을 초과하는 장기 키를 캐시하지 않습니다.
- **오프라인 로그인**: 보호된 사용자는 로그인 또는 잠금 해제 시 캐시된 검증자가 생성되지 않으므로, 이러한 계정에 대한 오프라인 로그인이 지원되지 않습니다.

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
