# 스켈레톤 키

{{#include ../../banners/hacktricks-training.md}}

## 스켈레톤 키 공격

**스켈레톤 키 공격**은 공격자가 **마스터 비밀번호**를 도메인 컨트롤러에 **주입하여 Active Directory 인증을 우회**할 수 있게 해주는 정교한 기술입니다. 이를 통해 공격자는 **비밀번호 없이도 모든 사용자로 인증**할 수 있으며, 사실상 **도메인에 대한 무제한 접근 권한을 부여**받습니다.

이 공격은 [Mimikatz](https://github.com/gentilkiwi/mimikatz)를 사용하여 수행할 수 있습니다. 이 공격을 수행하기 위해서는 **도메인 관리자 권한이 필요**하며, 공격자는 포괄적인 침해를 보장하기 위해 각 도메인 컨트롤러를 목표로 삼아야 합니다. 그러나 공격의 효과는 일시적이며, **도메인 컨트롤러를 재시작하면 악성 코드가 제거**되므로 지속적인 접근을 위해서는 재구현이 필요합니다.

**공격 실행**에는 단일 명령어가 필요합니다: `misc::skeleton`.

## 완화 조치

이러한 공격에 대한 완화 전략에는 서비스 설치 또는 민감한 권한 사용을 나타내는 특정 이벤트 ID를 모니터링하는 것이 포함됩니다. 특히, 시스템 이벤트 ID 7045 또는 보안 이벤트 ID 4673을 찾으면 의심스러운 활동을 드러낼 수 있습니다. 또한, `lsass.exe`를 보호된 프로세스로 실행하면 공격자의 노력을 상당히 저해할 수 있으며, 이는 그들이 커널 모드 드라이버를 사용해야 하므로 공격의 복잡성이 증가합니다.

보안 조치를 강화하기 위한 PowerShell 명령어는 다음과 같습니다:

- 의심스러운 서비스 설치를 감지하려면 다음을 사용하세요: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- 특히 Mimikatz의 드라이버를 감지하기 위해 다음 명령어를 사용할 수 있습니다: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- `lsass.exe`를 강화하기 위해 보호된 프로세스로 활성화하는 것이 권장됩니다: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

시스템 재부팅 후 검증은 보호 조치가 성공적으로 적용되었는지 확인하는 데 중요합니다. 이는 다음을 통해 수행할 수 있습니다: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## 참고 문헌

- [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{{#include ../../banners/hacktricks-training.md}}
