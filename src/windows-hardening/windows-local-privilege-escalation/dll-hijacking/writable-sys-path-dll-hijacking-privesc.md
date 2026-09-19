# Writable Sys Path +DLL Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

**system-wide `PATH`**(단순히 사용자 `PATH`가 아님)의 디렉터리에 **write**할 수 있다면 시스템에서 **privilege escalation**을 수행할 수 있습니다.

더 높은 권한의 service 또는 process가 이전 검색 위치에 존재하지 않는 DLL을 load하려고 시도한 후, 결국 write 가능한 system `PATH` 디렉터리를 검색할 때 **DLL hijacking**을 통해 이를 악용할 수 있습니다.

**DLL hijacking**에 대한 자세한 내용은 다음을 참조하세요:


{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

먼저 **더 높은 권한**으로 실행 중이며 **write 가능한 system `PATH` 디렉터리에서 DLL을 load**하려고 시도하는 **process**를 식별합니다.

이 technique은 **User PATH**만이 아니라 **Machine/System PATH** 항목에 의존한다는 점을 기억하세요. 따라서 Procmon에 시간을 할애하기 전에 **Machine PATH** 항목을 열거하고 어떤 항목에 write할 수 있는지 확인하는 것이 좋습니다:<sup>[[1]](#references)</sup>
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
이러한 경우의 문제는 해당 프로세스가 이미 실행 중일 가능성이 높다는 것입니다. 서비스가 로드하려고 시도했지만 실패한 DLL을 식별하려면 Procmon을 가능한 한 일찍(프로세스가 시작되기 전에) 실행한 다음:

- **Create** 폴더 `C:\privesc_hijacking`를 생성하고 경로 `C:\privesc_hijacking`를 **System Path env variable**에 추가합니다. 이 작업은 **manually** 수행하거나 **PS**를 사용하여 수행할 수 있습니다:
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
- **`procmon`**을 실행하고 **`Options`** --> **`Enable boot logging`**으로 이동한 다음 프롬프트에서 **`OK`**를 누릅니다.
- 그런 다음 **재부팅**합니다. 컴퓨터가 다시 시작되면 **`procmon`**이 가능한 한 빨리 이벤트 **기록을 시작**합니다.
- **Windows**가 **시작되면 `procmon`을 다시 실행**합니다. 그러면 이미 실행 중이었다는 메시지가 표시되고 이벤트를 파일에 **저장할지 묻습니다**. **예**를 선택하고 **이벤트를 파일에 저장**합니다.
- **파일**이 **생성되면**, 열려 있는 **`procmon`** 창을 닫고 **이벤트 파일을 엽니다**.
- **writable System Path 폴더에서 process가 로드하려고 한** 모든 DLL을 찾으려면 다음 **filters**를 추가합니다:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging은** 그렇지 않으면 관찰하기 **너무 일찍 시작되는 services**에만 필요합니다. **대상 service/program을 필요할 때 trigger할 수 있다면**(예: COM interface와 상호작용하거나, service를 재시작하거나, scheduled task를 다시 실행하는 경우), 일반적으로 **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, **`Path begins with <writable_machine_path>`**와 같은 filters를 사용해 일반 Procmon capture를 유지하는 편이 더 빠릅니다.

### 누락된 DLL

**virtual (vmware) Windows 11 machine**에서 무료로 실행했을 때 다음 결과를 얻었습니다:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

이 경우 `.exe` 결과는 무시합니다. 누락된 DLL probe는 다음에서 발생했습니다:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

다음 예제에서는 이 문서에서 설명한 [**privilege escalation을 위해 `WptsExtensions.dll`을 abuse하는 방법**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)을 사용합니다.<sup>[[3]](#references)</sup>

### 추가로 triage할 가치가 있는 candidates

`WptsExtensions.dll`은 좋은 예시지만, privileged services에 나타나는 유일한 반복적인 **phantom DLL**은 아닙니다. 최신 hunting rules와 public hijack catalogs에서는 여전히 다음과 같은 이름을 추적합니다:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client systems에서 사용하는 전형적인 **SYSTEM** candidate입니다. writable directory가 **Machine PATH**에 있고 service가 startup 중 DLL을 probe할 때 유용합니다. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | 일부 builds에서는 service가 **SYSTEM**으로 실행되고 **일반 user가 필요할 때 trigger할 수 있기** 때문에 **server editions**에서 흥미로운 candidate입니다. 따라서 reboot-only cases보다 유리합니다. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 일반적으로 먼저 **`NT AUTHORITY\LOCAL SERVICE`**를 반환합니다. 이 token에는 **`SeImpersonatePrivilege`**가 있으므로, [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md)와 chain으로 연결할 수 있어 충분한 경우가 많습니다. |

이러한 이름은 **triage 힌트**로만 취급해야 하며, 성공이 보장되는 것은 아닙니다. 이들은 **SKU/build에 따라 달라지며**, Microsoft가 release 간 동작을 변경할 수 있습니다. 중요한 점은 **Machine PATH를 순회하는 privileged services에서 누락된 DLL**을 찾는 것이며, 특히 service를 **reboot 없이 다시 trigger할 수 있는 경우**를 확인해야 합니다.

### Exploitation

**privilege를 escalate**하려면 **`WptsExtensions.dll`을 hijack**합니다. **path**와 **name**을 알고 있다면 malicious DLL을 생성합니다.

[**다음 예제 중 하나를 사용해 볼 수 있습니다**](#creating-and-compiling-dlls). 다음과 같은 payload를 실행할 수 있습니다: rev shell 획득, user 추가, beacon 실행 등.

> [!WARNING]
> **모든 services가** **`NT AUTHORITY\SYSTEM`**으로 실행되는 것은 아닙니다. 일부는 **`NT AUTHORITY\LOCAL SERVICE`**로 실행되며, 이 계정은 **privilege가 더 적기** 때문에 이러한 service 중 하나를 abuse해도 새 user를 생성하지 못할 수 있습니다.\
> 하지만 이 account에는 **`SeImpersonatePrivilege`** user right가 있으므로, [**Potato suite를 사용해 privilege를 escalate할 수 있습니다**](../roguepotato-and-printspoofer.md). 이 경우 user를 생성하려는 것보다 reverse shell이 더 나은 선택입니다.

이 문서를 작성하는 시점에 **Task Scheduler** service는 **Nt AUTHORITY\SYSTEM**으로 실행됩니다.

**malicious Dll을 생성한 후** (_제 경우에는 x64 rev shell을 사용했고 shell을 돌려받았지만, msfvenom에서 생성한 것이어서 defender가 종료했습니다_), writable System Path에 **WptsExtensions.dll**이라는 이름으로 저장하고 컴퓨터를 **재시작**합니다(또는 service를 재시작하거나 영향을 받은 service/program을 다시 실행하는 데 필요한 작업을 수행합니다).

Service가 다시 시작되면 **dll이 로드되고 실행되어야 합니다**(**library가 예상대로 로드되었는지** 확인하려면 **procmon** 기법을 다시 사용할 수 있습니다).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
