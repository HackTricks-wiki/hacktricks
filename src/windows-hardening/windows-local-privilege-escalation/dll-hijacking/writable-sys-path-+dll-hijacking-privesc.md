# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

If you found that you can **write in a System Path folder** (note that this won't work if you can write in a User Path folder) it's possible that you could **escalate privileges** in the system.

In order to do that you can abuse a **Dll Hijacking** where you are going to **hijack a library being loaded** by a service or process with **more privileges** than yours, and because that service is loading a Dll that probably doesn't even exist in the entire system, it's going to try to load it from the System Path where you can write.

For more info about **what is Dll Hijackig** check:



{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

The first thing you need is to **identify a process** running with **more privileges** than you that is trying to **load a Dll from the System Path** you can write in.

The problem in this cases is that probably thoses processes are already running. To find which Dlls are lacking the services you need to launch procmon as soon as possible (before processes are loaded). So, to find lacking .dlls do:

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
- Add these **filters** and you will find all the Dlls that some **proccess tried to load** from the writable System Path folder:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

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

### Exploitation

So, to **escalate privileges** we are going to hijack the library **WptsExtensions.dll**. Having the **path** and the **name** we just need to **generate the malicious dll**.

You can [**try to use any of these examples**](#creating-and-compiling-dlls). You could run payloads such as: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Note that **not all the service are run** with **`NT AUTHORITY\SYSTEM`** some are also run with **`NT AUTHORITY\LOCAL SERVICE`** which has **less privileges** and you **won't be able to create a new user** abuse its permissions.\
> However, that user has the **`seImpersonate`** privilege, so you can use the[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). So, in this case a rev shell is a better option that trying to create a user.

At the moment of writing the **Task Scheduler** service is run with **Nt AUTHORITY\SYSTEM**.

Having **generated the malicious Dll** (_in my case I used x64 rev shell and I got a shell back but defender killed it because it was from msfvenom_), save it in the writable System Path with the name **WptsExtensions.dll** and **restart** the computer (or restart the service or do whatever it takes to rerun the affected service/program).

When the service is re-started, the **dll should be loaded and executed** (you can **reuse** the **procmon** trick to check if the **library was loaded as expected**).

{{#include ../../../banners/hacktricks-training.md}}

