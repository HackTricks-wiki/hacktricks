# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Якщо ви виявили, що можете **писати в папку System Path** (зверніть увагу, що це не спрацює, якщо ви можете писати в папку User Path), можливо, ви зможете **підвищити привілеї** в системі.

Щоб це зробити, ви можете зловживати **Dll Hijacking**, де ви будете **перехоплювати бібліотеку, що завантажується** службою або процесом з **вищими привілеями**, ніж у вас, і оскільки ця служба завантажує Dll, якої, ймовірно, навіть не існує в усій системі, вона спробує завантажити її з System Path, куди ви можете писати.

Для отримання додаткової інформації про **що таке Dll Hijackig** дивіться:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

Перше, що вам потрібно, це **ідентифікувати процес**, який працює з **вищими привілеями**, ніж у вас, і намагається **завантажити Dll з System Path**, куди ви можете писати.

Пам'ятайте, що ця техніка залежить від запису **Machine/System PATH**, а не лише від вашого **User PATH**. Тому, перш ніж витрачати час на Procmon, варто перелічити записи **Machine PATH** і перевірити, які з них доступні для запису:
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
Проблема в цих випадках у тому, що, ймовірно, ці процеси вже запущені. Щоб знайти, яких Dlls не вистачає службам, тобі потрібно запустити procmon якомога швидше (до завантаження процесів). Отже, щоб знайти відсутні .dlls, зроби так:

- **Create** папку `C:\privesc_hijacking` і додай шлях `C:\privesc_hijacking` до **System Path env variable**. Це можна зробити **manually** або за допомогою **PS**:
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
- Запустіть **`procmon`** і перейдіть до **`Options`** --> **`Enable boot logging`** та натисніть **`OK`** у prompt.
- Потім **перезавантажтеся**. Коли computer буде restarted, **`procmon`** почне **recording** events asap.
- Після того як **Windows** **started execute `procmon`** знову, він повідомить, що вже працював, і **спитає, чи хочете ви store** events у файл. Скажіть **yes** і **store the events in a file**.
- **Після** того як **file** буде **generated**, **close** відкрите вікно **`procmon`** і **open the events file**.
- Додайте ці **filters**, і ви знайдете всі Dlls, які some **proccess tried to load** з writable System Path folder:

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
