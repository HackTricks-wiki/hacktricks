# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

As jy gevind het dat jy in 'n System Path-lêergids kan **skryf** (let daarop dat dit nie sal werk as jy in 'n User Path-lêergids kan skryf nie), is dit moontlik dat jy **privileges in die system kan verhoog**.

Om dit te doen, kan jy 'n **Dll Hijacking** misbruik waar jy 'n **library gaan hijack** wat gelaai word deur 'n service of process met **meer privileges** as jy, en omdat daardie service 'n Dll laai wat waarskynlik selfs in die hele system nie bestaan nie, gaan dit probeer om dit vanaf die System Path te laai waar jy kan skryf.

Vir meer info oor **wat Dll Hijackig is** kyk:


{{#ref}}
./
{{#endref}}

## Privesc met Dll Hijacking

### Vind 'n ontbrekende Dll

Die eerste ding wat jy nodig het, is om 'n **process** te identifiseer wat met **meer privileges** as jy loop en probeer om 'n Dll vanaf die System Path te **laai** waar jy kan skryf.

Onthou dat hierdie tegniek afhang van 'n **Machine/System PATH**-inskrywing, nie net van jou **User PATH** nie. Daarom, voordat jy tyd op Procmon bestee, is dit die moeite werd om die **Machine PATH**-inskrywings te enumereer en te kyk watter een skryfbaar is:
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
Die probleem in hierdie gevalle is dat daardie prosesse waarskynlik reeds loop. Om te vind watter Dlls die services kort, moet jy procmon so gou as moontlik laat begin (voordat prosesse gelaai word). So, om ontbrekende .dlls te vind, doen:

- **Skep** die gids `C:\privesc_hijacking` en voeg die pad `C:\privesc_hijacking` by die **System Path env variable**. Jy kan dit **handmatig** doen of met **PS**:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Begin **`procmon`** en gaan na **`Options`** --> **`Enable boot logging`** en druk **`OK`** in die prompt.
- Herbegin dan. Sodra die rekenaar herbegin is, sal **`procmon`** begin om gebeurtenisse so gou as moontlik **op te neem**.
- Sodra **Windows** begin het, **voer `procmon` weer uit**, dit sal vir jou sê dat dit reeds loop en sal **jou vra of jy die gebeurtenisse in 'n lêer wil stoor**. Sê **yes** en **stoor die gebeurtenisse in 'n lêer**.
- **Nadat** die **lêer** **gegenereer** is, **sluit** die oopgemaakte **`procmon`**-venster en **open die gebeurtenislêer**.
- Voeg hierdie **filters** by en jy sal al die Dlls vind wat sommige **proccess probeer laai het** vanaf die writable System Path-lêergids:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging is only required for services that start too early** to observe otherwise. If you can **trigger the target service/program on demand** (for example, by interacting with its COM interface, restarting the service, or relaunching a scheduled task), it is usually faster to keep a normal Procmon capture with filters such as **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, and **`Path begins with <writable_machine_path>`**.

### Missed Dlls

Running this in a free **virtual (vmware) Windows 11 machine** I got these results:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In this case the .exe are useless so ignore them, the missed DLLs where from:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

After finding this, I found this interesting blog post that also explains how to [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Which is what we **are going to do now**.

### Other candidates worth triaging

`WptsExtensions.dll` is a good example, but it is not the only recurring **phantom DLL** that shows up in privileged services. Modern hunting rules and public hijack catalogs still track names such as:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Classic **SYSTEM** candidate on client systems. Good when the writable directory is in the **Machine PATH** and the service probes the DLL during startup. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesting on **server editions** because the service runs as **SYSTEM** and can be **triggered on demand by a normal user** in some builds, making it better than reboot-only cases. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Usually yields **`NT AUTHORITY\LOCAL SERVICE`** first. That is often still enough because the token has **`SeImpersonatePrivilege`**, so you can chain it with [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Treat these names as **triage hints**, not guaranteed wins: they are **SKU/build dependent**, and Microsoft may change the behavior between releases. The important takeaway is to look for **missing DLLs in privileged services that traverse the Machine PATH**, especially if the service can be **re-triggered without rebooting**.

### Exploitation

So, to **escalate privileges** we are going to hijack the library **WptsExtensions.dll**. Having the **path** and the **name** we just need to **generate the malicious dll**.

You can [**try to use any of these examples**](#creating-and-compiling-dlls). You could run payloads such as: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Note that **not all the service are run** with **`NT AUTHORITY\SYSTEM`** some are also run with **`NT AUTHORITY\LOCAL SERVICE`** which has **less privileges** and you **won't be able to create a new user** abuse its permissions.\
> However, that user has the **`seImpersonate`** privilege, so you can use the[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). So, in this case a rev shell is a better option that trying to create a user.

At the moment of writing the **Task Scheduler** service is run with **Nt AUTHORITY\SYSTEM**.

Having **generated the malicious Dll** (_in my case I used x64 rev shell and I got a shell back but defender killed it because it was from msfvenom_), save it in the writable System Path with the name **WptsExtensions.dll** and **restart** the computer (or restart the service or do whatever it takes to rerun the affected service/program).

When the service is re-started, the **dll should be loaded and executed** (you can **reuse** the **procmon** trick to check if the **library was loaded as expected**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
