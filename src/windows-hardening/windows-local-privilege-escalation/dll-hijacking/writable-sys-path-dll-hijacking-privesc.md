# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## 소개

만약 **System Path 폴더에 write할 수 있다면**(주의: **User Path 폴더에 write할 수 있는 것만으로는 동작하지 않음**) 시스템에서 **privileges를 escalate**할 수 있을 가능성이 있습니다.

이를 위해, 서비스나 프로세스가 자신보다 **더 높은 privileges**로 **loading 중인 Dll을 hijack**하는 **Dll Hijacking**을 악용할 수 있습니다. 이 서비스는 아마 시스템 전체에 존재하지도 않는 Dll을 loading하려고 하므로, write 가능한 System Path에서 그것을 load하려고 시도하게 됩니다.

**Dll Hijackig가 무엇인지**에 대한 자세한 정보는 다음을 확인하세요:


{{#ref}}
./
{{#endref}}

## Dll Hijacking으로 Privesc하기

### 누락된 Dll 찾기

가장 먼저 필요한 것은, 당신보다 **더 높은 privileges**로 실행 중이며, 당신이 write할 수 있는 **System Path에서 Dll을 load하려는 process**를 **식별**하는 것입니다.

이 technique는 **User PATH**가 아니라 **Machine/System PATH** entry에 의존한다는 점을 기억하세요. 따라서 Procmon에 시간을 쓰기 전에, **Machine PATH** entry들을 열거하고 어떤 것들이 writable인지 확인하는 것이 좋습니다:
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
이 경우의 문제는 아마 해당 프로세스들이 이미 실행 중이라는 점이다. 어떤 Dlls이 부족한지 찾으려면 프로세스가 로드되기 전에 최대한 빨리 procmon을 실행해야 한다. 따라서 누락된 .dlls를 찾으려면 다음을 수행하라:

- **Create** 폴더 `C:\privesc_hijacking`를 만들고 `C:\privesc_hijacking` 경로를 **System Path env variable**에 추가한다. 이 작업은 **수동**으로 하거나 **PS**로 할 수 있다:
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
- **`procmon`**을 실행하고 **`Options`** --> **`Enable boot logging`**으로 이동한 다음 프롬프트에서 **`OK`**를 누르세요.
- 그런 다음 **reboot**하세요. 컴퓨터가 재시작되면 **`procmon`**이 가능한 한 빨리 이벤트를 **recording**하기 시작합니다.
- **Windows**가 시작된 뒤 **`procmon`**을 다시 실행하면, 이미 실행 중이었다는 메시지가 뜨고 이벤트를 파일에 **store**할지 묻습니다. **yes**를 선택하고 이벤트를 파일에 **store**하세요.
- **파일**이 생성된 **후**, 열린 **`procmon`** 창을 **close**하고 이벤트 파일을 **open**하세요.
- 아래 **filters**를 추가하면 writable System Path 폴더에서 어떤 **proccess**가 로드하려 했던 모든 Dlls를 찾을 수 있습니다:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging**은 그렇지 않으면 관찰하기에 너무 일찍 시작되는 서비스에만 필요합니다. 대상 서비스/program을 **on demand**로 **trigger**할 수 있다면(예: COM interface와 상호작용하거나, 서비스를 재시작하거나, scheduled task를 다시 실행하는 방식), 보통은 **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, 그리고 **`Path begins with <writable_machine_path>`** 같은 filters를 사용한 일반 Procmon capture를 유지하는 것이 더 빠릅니다.

### Missed Dlls

무료 **virtual (vmware) Windows 11 machine**에서 이를 실행해 보니 다음 결과가 나왔습니다:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

이 경우 .exe는 쓸모가 없으므로 무시해도 되고, 놓친 DLL들은 다음에서 나온 것입니다:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

이를 찾은 뒤, **WptsExtensions.dll for privesc**를 악용하는 방법도 설명하는 흥미로운 블로그 글을 발견했습니다: [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). 이제 우리가 **바로 그 작업을 하게 될** 것입니다.

### Other candidates worth triaging

`WptsExtensions.dll`은 좋은 예시이지만, privileged services에서 반복적으로 나타나는 유일한 **phantom DLL**은 아닙니다. 최신 hunting rules와 public hijack catalogs는 다음과 같은 이름들도 계속 추적합니다:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | 클라이언트 시스템에서 흔한 **SYSTEM** 후보입니다. writable directory가 **Machine PATH** 안에 있고 서비스가 시작 시 DLL을 검사할 때 유용합니다. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | 서비스가 **SYSTEM**으로 실행되며 일부 빌드에서는 일반 사용자가 **on demand**로 **trigger**할 수 있어, reboot-only 사례보다 더 유용합니다. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 보통 먼저 **`NT AUTHORITY\LOCAL SERVICE`**를 얻습니다. 이 토큰에는 종종 **`SeImpersonatePrivilege`**가 있으므로, [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md)와 연결할 수 있습니다. |

이 이름들을 **보장된 성공**이 아니라 **triage 힌트**로 보세요: 이는 **SKU/build dependent**이며, Microsoft는 릴리스 간 동작을 바꿀 수 있습니다. 중요한 점은 **Machine PATH**를 탐색하는 privileged services에서 **missing DLLs**를 찾는 것이고, 특히 서비스가 **reboot 없이 다시 trigger**될 수 있다면 더욱 중요합니다.

### Exploitation

따라서 **권한 상승**을 위해 library **WptsExtensions.dll**을 hijack할 것입니다. **path**와 **name**을 이미 알았으므로, 이제 **malicious dll**을 만들기만 하면 됩니다.

[**이 예시들 중 아무거나 사용해 보세요**](#creating-and-compiling-dlls). 예를 들어 rev shell을 실행하거나, 사용자를 추가하거나, beacon을 실행할 수 있습니다...

> [!WARNING]
> **모든 service가** **`NT AUTHORITY\SYSTEM`**으로 실행되는 것은 아닙니다. 일부는 **`NT AUTHORITY\LOCAL SERVICE`**로도 실행되며, 이 계정은 **권한이 더 낮아** 새 사용자를 만들 수 없습니다. 따라서 그 권한을 악용할 수 없습니다.\
> 하지만 그 사용자는 **`seImpersonate`** privilege를 가지고 있으므로, [**potato suite**](../roguepotato-and-printspoofer.md)를 사용해 권한을 상승시킬 수 있습니다. 따라서 이 경우에는 사용자를 만들려 하기보다 rev shell이 더 나은 옵션입니다.

작성 시점에는 **Task Scheduler** 서비스가 **Nt AUTHORITY\SYSTEM**으로 실행됩니다.

**malicious Dll**을 생성한 뒤(_제 경우 x64 rev shell을 사용했고 shell을 얻었지만 msfvenom에서 왔기 때문에 defender가 종료했습니다_), writable System Path에 **WptsExtensions.dll** 이름으로 저장하고 컴퓨터를 **restart**하세요(또는 서비스를 재시작하거나, 영향을 받는 service/program을 다시 실행하는 데 필요한 작업을 수행하세요).

서비스가 다시 시작되면 **dll이 로드되고 실행**되어야 합니다(**procmon** 트릭을 다시 사용해 **library가 예상대로 로드되었는지** 확인할 수 있습니다).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
