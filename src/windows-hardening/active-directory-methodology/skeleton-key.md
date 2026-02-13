# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** is a technique that allows attackers to **bypass Active Directory authentication** by **injecting a master password** into the LSASS process of each domain controller. After injection, the master password (default **`mimikatz`**) can be used to authenticate as **any domain user** while their real passwords still work.

Key facts:

- Requires **Domain Admin/SYSTEM + SeDebugPrivilege** on every DC and must be **reapplied after each reboot**.
- Patches **NTLM** and **Kerberos RC4 (etype 0x17)** validation paths; AES-only realms or accounts enforcing AES will **not accept the skeleton key**.
- Can conflict with third‑party LSA authentication packages or additional smart‑card / MFA providers.
- The Mimikatz module accepts the optional switch `/letaes` to avoid touching Kerberos/AES hooks in case of compatibility issues.

### Execution

클래식(non‑PPL으로 보호되지 않은) LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
만약 **LSASS가 PPL로 실행 중인 경우** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), LSASS를 패치하기 전에 보호를 제거하려면 커널 드라이버가 필요합니다:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
인젝션 후, 아무 도메인 계정으로 인증하되 비밀번호로 `mimikatz`(또는 운영자가 설정한 값)를 사용하세요. 다중‑DC 환경에서는 **모든 DC**에 대해 반복 수행해야 합니다.

## 완화

- **로그 모니터링**
- System **Event ID 7045** (service/driver install) — 서명되지 않은 드라이버(예: `mimidrv.sys`)에 대한 주의.
- **Sysmon**: Event ID 7 (driver load) — `mimidrv.sys` 관련; Event ID 10 — 비시스템 프로세스에서 `lsass.exe`에 대한 의심스러운 접근.
- Security **Event ID 4673/4611** — 민감 권한 사용 또는 LSA 인증 패키지 등록 이상; DCs에서 RC4 (etype 0x17)를 사용하는 예기치 않은 4624 로그인과 상관관계 분석.
- **LSASS 강화**
- DCs에서 **RunAsPPL/Credential Guard/Secure LSASS** 를 활성화하여 공격자를 커널 모드 드라이버 배포로 유도(텔레메트리 증가, 악용 난이도 상승).
- 가능한 경우 레거시 **RC4**를 비활성화하세요; Kerberos 티켓을 AES로 제한하면 skeleton key가 사용하는 RC4 훅 경로를 차단할 수 있습니다.
- 빠른 PowerShell 헌팅:
- 서명되지 않은 커널 드라이버 설치 탐지: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz 드라이버 탐지: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- 재부팅 후 PPL 적용 확인: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

추가적인 자격 증명 강화 지침은 [Windows credentials protections](../stealing-credentials/credentials-protections.md)을 확인하세요.

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
