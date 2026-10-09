# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

If you can **write to a directory in the system-wide `PATH`** (not merely your user `PATH`), you may be able to **escalate privileges** on the system.

This can be abused through **DLL hijacking** when a more-privileged service or process tries to load a DLL that does not exist in its earlier search locations and eventually searches the writable system `PATH` directory.

A writable Machine `PATH` entry is only a **primitive**, not proof of code execution. For an unpackaged application using the standard search order, `PATH` is reached after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory. A full path or `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` policy may exclude `PATH` completely.<sup>[[4]](#references)</sup>

For more information about **DLL hijacking**, see:

{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

First, **identify a process** running with **more privileges** that tries to **load a DLL from a writable system `PATH` directory**.

Remember that this technique depends on a **Machine/System PATH** entry, not only on your **User PATH**. Therefore, before spending time on Procmon, it's worth enumerating the **Machine PATH** entries and checking which ones are writable:<sup>[[1]](#references)</sup>

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

ACL text can be misleading because group membership, deny ACEs, and inherited permissions affect the result. In an authorized test, a create/delete probe checks the **effective access of the current token** (it is intrusive and may generate alerts):<sup>[[1]](#references)</sup>

```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
    ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
    Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
    $probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
    catch { }
}
```

### Confirm the target's effective `PATH`

The Machine `PATH` read from the registry is configuration data; the loader uses the environment block of the **target process**. Every process owns an environment block, and a child normally inherits a copy of its parent's environment. Consequently, a long-running service can retain an older value, and a service launched with a custom environment can differ from the value seen in your shell. Treat an observed Procmon probe of the exact directory by the target PID as ground truth; after changing `PATH` in a lab, restart the relevant process tree or reboot before concluding that the lookup does not occur.<sup>[[5]](#references)</sup>

The problem in these cases is that those processes are probably already running. To identify DLLs that services try and fail to load, launch Procmon as early as possible (before the processes start), then:

> [!WARNING]
> Adding a user-writable directory to the Machine `PATH` **creates the vulnerable condition**. Do this only in an isolated research VM to reveal which privileged processes reach the `PATH`; on an assessed host, monitor the existing writable entry without changing system configuration.<sup>[[1]](#references)</sup>

- **Create** the folder `C:\privesc_hijacking` and add the path `C:\privesc_hijacking` to **System Path env variable**. You can do this **manually** or with **PS**:

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

- Launch **`procmon`** and go to **`Options`** --> **`Enable boot logging`** and press **`OK`** in the prompt.
- Then, **reboot**. When the computer is restarted **`procmon`** will start **recording** events asap.
- Once **Windows** is **started execute `procmon`** again, it'll tell you that it has been running and will **ask you if you want to store** the events in a file. Say **yes** and **store the events in a file**.
- **After** the **file** is **generated**, **close** the opened **`procmon`** window and **open the events file**.
- Add these **filters** to find all DLLs that a **process tried to load** from the writable System Path folder:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging is only required for services that start too early** to observe otherwise. If you can **trigger the target service/program on demand** (for example, by interacting with its COM interface, restarting the service, or relaunching a scheduled task), it is usually faster to keep a normal Procmon capture with filters such as **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, and **`Path begins with <writable_machine_path>`**.

### Missed DLLs

Running this in a free **virtual (vmware) Windows 11 machine** I got these results:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In this case, ignore the `.exe` results. The missing-DLL probes came from:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

The following example uses the technique described in this article about [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Other candidates worth triaging

`WptsExtensions.dll` is a good example, but it is not the only recurring **phantom DLL** that shows up in privileged services. Modern hunting rules and public hijack catalogs still track names such as:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Classic **SYSTEM** candidate on client systems. Good when the writable directory is in the **Machine PATH** and the service probes the DLL during startup. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesting on **server editions** because the service runs as **SYSTEM** and can be **triggered on demand by a normal user** in some builds, making it better than reboot-only cases. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Usually yields **`NT AUTHORITY\LOCAL SERVICE`** first. That is often still enough because the token has **`SeImpersonatePrivilege`**, so you can chain it with [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Treat these names as **triage hints**, not guaranteed wins: they are **SKU/build dependent**, and Microsoft may change the behavior between releases. The important takeaway is to look for **missing DLLs in privileged services that traverse the Machine PATH**, especially if the service can be **re-triggered without rebooting**.

### Validate a candidate before weaponizing it

A `NAME NOT FOUND` event by itself is not enough. Before placing a payload, verify the complete chain:<sup>[[1]](#references)[[4]](#references)</sup>

1. The event belongs to the expected **PID, command line, service account, and integrity level**, and the missing path is the exact writable Machine `PATH` directory.
2. For the same DLL basename, no earlier directory returns `SUCCESS`, and the module is not satisfied by the loaded-module list, KnownDLLs, redirection, or an SxS manifest.
3. The probe repeats when a low-privileged user invokes the intended trigger. A boot-only lookup is usable but operationally much worse than an on-demand one.
4. The payload architecture matches the process. If the application later resolves exports, proxy the legitimate DLL or export the expected symbols; see [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. First use a harmless canary DLL that records the PID, identity, and timestamp. In Procmon, require a successful **`Load Image`** from the planted path rather than assuming that a preceding file probe caused execution.

### Exploitation

To **escalate privileges**, hijack **`WptsExtensions.dll`**. Once the **path** and **name** are known, generate the malicious DLL.

You can [**try to use any of these examples**](README.md#creating-and-compiling-dlls). You could run payloads such as: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Note that **not all services run** as **`NT AUTHORITY\SYSTEM`**. Some run as **`NT AUTHORITY\LOCAL SERVICE`**, which has **fewer privileges**, so abusing one of these services may not let you create a new user.\
> However, that account has the **`SeImpersonatePrivilege`** user right, so you can use the [**Potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). In this case, a reverse shell is a better option than trying to create a user.

The **Task Scheduler** service normally runs as **`NT AUTHORITY\SYSTEM`**, but verify the actual deployment and do not infer the execution identity only from the service name:<sup>[[3]](#references)</sup>

```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```

Having **generated the malicious Dll** (_in my case I used x64 rev shell and I got a shell back but defender killed it because it was from msfvenom_), save it in the writable System Path with the name **WptsExtensions.dll** and **restart** the computer (or restart the service or do whatever it takes to rerun the affected service/program).

When the service is re-started, the **DLL should be loaded and executed** (you can **reuse** the **Procmon** trick to check if the **library was loaded as expected**).

> [!NOTE]
> Plan cleanup before triggering. A service may keep the DLL mapped and lock the file until it stops; for `WptsExtensions.dll`, stopping Task Scheduler requires elevated rights. After obtaining the intended context, stop the target safely, remove the payload, and restore any lab-only `PATH` change.<sup>[[1]](#references)</sup>

### Remediation / detection

Remove weak write grants from every Machine `PATH` directory and remove stale entries. Developers should load trusted libraries by full path or constrain resolution with `SetDefaultDllDirectories` / `LoadLibraryEx` search flags. Defenders can correlate changes to the Machine `PATH` with privileged processes loading DLLs from non-system, user-writable directories.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
