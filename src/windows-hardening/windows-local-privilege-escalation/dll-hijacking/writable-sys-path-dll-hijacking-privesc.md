# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

**System Path 폴더에 write할 수 있다면** (User Path 폴더에 write할 수 있는 경우에는 작동하지 않는다는 점에 유의) 시스템에서 **privileges를 escalate**할 수 있습니다.

이를 위해 **Dll Hijacking**을 악용할 수 있습니다. 자신보다 **더 많은 privileges**를 가진 service 또는 process가 **load하는 library를 hijack**하는 방식입니다. 또한 해당 service가 시스템 전체에 존재하지 않을 가능성이 높은 Dll을 load하려고 하기 때문에, write할 수 있는 System Path에서 해당 Dll을 load하려고 시도하게 됩니다.

**Dll Hijack이 무엇인지**에 대한 자세한 정보는 다음을 확인하세요:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

먼저 자신보다 **더 많은 privileges**로 실행 중이며, 자신이 write할 수 있는 **System Path에서 Dll을 load하려고 시도하는 process**를 **식별**해야 합니다.

이 technique은 **User PATH**만이 아니라 **Machine/System PATH** entry에 의존한다는 점을 기억하세요. 따라서 Procmon에 시간을 들이기 전에 **Machine PATH** entry를 열거하고, 그중 write 가능한 항목을 확인하는 것이 좋습니다:<sup>[[1]](#references)</sup>
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
이 경우의 문제는 해당 프로세스가 이미 실행 중일 가능성이 높다는 것입니다. 어떤 DLL이 누락되었는지 확인하려면 프로세스가 로드되기 전에 최대한 빨리 procmon을 실행해야 합니다. 따라서 누락된 .dll을 확인하려면 다음을 수행합니다:

- **Create** 폴더 `C:\privesc_hijacking`를 만들고 경로 `C:\privesc_hijacking`를 **System Path env variable**에 추가합니다. 이 작업은 **manually** 수행하거나 **PS**를 사용하여 수행할 수 있습니다:
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
- **`procmon`**을 실행하고 **`Options`** --> **`Enable boot logging`**으로 이동한 다음, 프롬프트에서 **`OK`**를 누릅니다.
- 그런 다음 **재부팅**합니다. 컴퓨터가 다시 시작되면 **`procmon`**이 가능한 한 빨리 이벤트 **recording**을 시작합니다.
- **Windows**가 **시작되면 `procmon`을 다시 실행**합니다. 그러면 실행 중이었다는 메시지가 표시되고 이벤트를 파일에 **저장할지 묻습니다**. **yes**를 선택하고 **이벤트를 파일에 저장**합니다.
- **파일**이 **생성된 후**, 열려 있는 **`procmon`** 창을 닫고 **이벤트 파일을 엽니다**.
- 다음 **filters**를 추가하면 일부 **proccess가 writable System Path 폴더에서 load하려고 시도한** 모든 Dll을 찾을 수 있습니다:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging은 너무 일찍 시작되는 서비스**를 다른 방법으로 관찰할 수 없을 때만 필요합니다. **대상 service/program을 필요할 때 trigger할 수 있다면** (예: COM interface와 상호작용하거나, service를 restart하거나, scheduled task를 relaunch하는 경우), 일반적으로 **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, **`Path begins with <writable_machine_path>`**와 같은 filters를 사용해 일반적인 Procmon capture를 유지하는 것이 더 빠릅니다.

### 누락된 Dll

무료 **virtual (vmware) Windows 11 machine**에서 이를 실행했을 때 다음 결과를 얻었습니다:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

이 경우 .exe는 쓸모가 없으므로 무시합니다. 누락된 DLL은 다음에서 발생했습니다:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

이를 확인한 후, [**privesc를 위해 WptsExtensions.dll을 abuse하는 방법**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)을 설명하는 흥미로운 blog post를 발견했습니다. 이제 이것을 **수행할 것입니다**.<sup>[[3]](#references)</sup>

### 추가로 triage할 가치가 있는 후보

`WptsExtensions.dll`은 좋은 예시이지만, privileged services에서 나타나는 유일한 반복적인 **phantom DLL**은 아닙니다. 최신 hunting rules와 public hijack catalogs에서는 다음과 같은 이름도 추적합니다:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client systems에서 사용되는 전형적인 **SYSTEM** 후보입니다. writable directory가 **Machine PATH**에 있고 service가 startup 중 DLL을 probe할 때 유용합니다. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | 일부 build에서는 service가 **SYSTEM**으로 실행되고 일반 user가 **on demand로 trigger할 수 있기** 때문에 **server editions**에서 흥미롭습니다. 따라서 reboot-only case보다 유리합니다. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 일반적으로 먼저 **`NT AUTHORITY\LOCAL SERVICE`**를 얻습니다. 이 token에는 **`SeImpersonatePrivilege`**가 있으므로, [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md)와 chain할 수 있어 여전히 충분한 경우가 많습니다. |

이러한 이름은 **triage hints**로 취급해야 하며, 성공을 보장하지는 않습니다. **SKU/build에 따라 달라지고**, Microsoft가 release마다 동작을 변경할 수 있습니다. 중요한 점은 **Machine PATH를 순회하는 privileged services에서 missing DLL을 찾는 것**이며, 특히 해당 service를 **reboot 없이 다시 trigger할 수 있는 경우**가 중요합니다.

### Exploitation

따라서 **privileges를 escalate하기** 위해 library **WptsExtensions.dll**을 hijack할 것입니다. **path**와 **name**을 알고 있으므로 이제 **malicious dll을 generate**하기만 하면 됩니다.

[**다음 예시 중 하나를 사용해 볼 수 있습니다**](#creating-and-compiling-dlls). 다음과 같은 payload를 실행할 수 있습니다: rev shell 획득, user 추가, beacon 실행 등.

> [!WARNING]
> **모든 service가 `NT AUTHORITY\SYSTEM`으로 실행되는 것은 아닙니다.** 일부는 **`NT AUTHORITY\LOCAL SERVICE`**로 실행되며, 이 계정은 **privileges가 더 적기** 때문에 해당 permissions를 abuse하여 **새 user를 생성할 수 없습니다**.\
> 하지만 이 user에게는 **`seImpersonate`** privilege가 있으므로 [ **potato suite를 사용해 privileges를 escalate할 수 있습니다**](../roguepotato-and-printspoofer.md). 따라서 이 경우에는 user를 생성하려고 시도하는 것보다 rev shell이 더 나은 선택입니다.

현재 작성 시점에는 **Task Scheduler** service가 **Nt AUTHORITY\SYSTEM**으로 실행됩니다.

**malicious Dll을 생성한 후** (_제 경우에는 x64 rev shell을 사용해 shell을 얻었지만, msfvenom에서 생성된 것이었기 때문에 defender가 이를 종료했습니다_), 이를 writable System Path에 **WptsExtensions.dll**이라는 이름으로 저장하고 컴퓨터를 **restart**합니다 (또는 service를 restart하거나 영향을 받은 service/program을 다시 실행하는 데 필요한 작업을 수행합니다).

Service가 다시 시작되면 **dll이 load되고 executed되어야 합니다** (**library가 예상대로 load되었는지 확인하기 위해** **procmon** 기법을 **재사용할 수 있습니다**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
