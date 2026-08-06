# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack**은 각 domain controller의 LSASS process에 **master password**를 **inject**하여 **Active Directory authentication을 우회**할 수 있게 하는 technique입니다. Injection 후에는 사용자의 실제 password가 계속 작동하는 동시에, master password (기본값 **`mimikatz`**)를 사용하여 **모든 domain user**로 authentication할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

주요 사항:

- 모든 DC에서 **Domain Admin/SYSTEM + SeDebugPrivilege**가 필요하며, **각 reboot 후 다시 적용해야** 합니다.<sup>[[2]](#references)</sup>
- **NTLM** 및 **Kerberos RC4 (etype 0x17)** validation path를 patch합니다. AES-only realm 또는 AES를 강제하는 account는 **skeleton key를 허용하지 않습니다**.<sup>[[2]](#references)</sup>
- third-party LSA authentication package 또는 추가 smart-card / MFA provider와 충돌할 수 있습니다.<sup>[[2]](#references)</sup>
- Mimikatz module은 호환성 문제 발생 시 Kerberos/AES hook을 건드리지 않도록 선택적 switch `/letaes`를 지원합니다.<sup>[[3]](#references)</sup>

### Execution

일반적인, PPL로 보호되지 않는 LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
**LSASS가 PPL로 실행 중인 경우** LSASS를 patching하기 전에 protection을 제거하려면 kernel driver가 필요합니다:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Injection 이후, 모든 domain account로 인증하되 password는 `mimikatz`(또는 operator가 설정한 값)를 사용합니다. 다중 DC 환경에서는 **모든 DC**에서 반복해야 합니다.

## 완화책

- **로그 모니터링**
- unsigned driver인 `mimidrv.sys`와 같은 driver 설치에 대한 System **Event ID 7045**(service/driver install)를 모니터링합니다.
- **Sysmon**: `mimidrv.sys`에 대한 Event ID 7(driver load), system이 아닌 process에서 `lsass.exe`에 접근하는 의심스러운 동작에 대한 Event ID 10을 모니터링합니다.
- 민감한 privilege 사용 또는 LSA authentication package registration 이상에 대한 Security **Event ID 4673/4611**을 확인하고, DC에서 RC4(etype 0x17)를 사용하는 예상치 못한 4624 logon과 상관 분석합니다.
- **LSASS 강화**
- DC에서 **RunAsPPL/Credential Guard/Secure LSASS**를 활성화된 상태로 유지하여 attacker가 kernel-mode driver deployment를 수행하도록 강제합니다(더 많은 telemetry와 더 어려운 exploitation).
- 가능한 경우 legacy **RC4**를 비활성화합니다. Kerberos ticket을 AES로 제한하면 skeleton key가 사용하는 RC4 hook path를 차단할 수 있습니다.<sup>[[2]](#references)</sup>
- 빠른 PowerShell hunts:
- unsigned kernel driver 설치 탐지: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz driver 탐색: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- reboot 후 PPL 적용 여부 검증: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

추가적인 credential-hardening 지침은 [Windows credential protection](../stealing-credentials/credentials-protections.md)을 확인하세요.

## References

- [1] [Netwrix – Active Directory의 Skeleton Key attack (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
