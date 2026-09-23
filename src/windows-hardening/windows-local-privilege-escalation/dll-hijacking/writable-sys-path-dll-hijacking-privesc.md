# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

시스템 전체의 `PATH`(단순히 사용자 `PATH`가 아님)에 있는 디렉터리에 **쓰기 권한**이 있다면, 시스템에서 **권한을 상승**시킬 수 있습니다.

더 높은 권한으로 실행되는 service 또는 process가 이전 검색 위치에 존재하지 않는 DLL을 load하려고 시도한 후, 결국 쓰기 가능한 시스템 `PATH` 디렉터리를 검색할 때 **DLL hijacking**을 통해 이를 악용할 수 있습니다.

쓰기 가능한 Machine `PATH` 항목은 **primitive**일 뿐이며, code execution의 증거는 아닙니다. 표준 검색 순서를 사용하는 unpackaged application의 경우 `PATH`에 도달하기 전에 redirection, API sets, SxS, loaded-module list, KnownDLLs, application 및 Windows 디렉터리, current directory가 먼저 검색됩니다. Full path 또는 `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` policy를 사용하면 `PATH`가 완전히 제외될 수 있습니다.<sup>[[4]](#references)</sup>

**DLL hijacking**에 대한 자세한 내용은 다음을 참조하세요.

{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

먼저 **더 높은 권한으로 실행 중이며**, **쓰기 가능한 시스템 `PATH` 디렉터리에서 DLL을 load하려고 시도하는 process**를 식별합니다.

이 technique은 **User PATH**만이 아니라 **Machine/System PATH** 항목에 의존한다는 점을 기억하세요. 따라서 Procmon에 시간을 들이기 전에 **Machine PATH** 항목을 열거하고, 어떤 항목에 쓰기 권한이 있는지 확인하는 것이 좋습니다:<sup>[[1]](#references)</sup>
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
ACL 텍스트는 group membership, deny ACEs 및 inherited permissions가 결과에 영향을 미치므로 오해를 불러일으킬 수 있습니다. 권한이 부여된 테스트에서는 create/delete probe를 통해 **현재 token의 effective access**를 확인합니다(이는 intrusive하며 alerts를 생성할 수 있습니다):<sup>[[1]](#references)</sup>
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
### 대상의 유효한 `PATH` 확인

레지스트리에서 읽은 Machine `PATH`는 구성 데이터이며, loader는 **대상 프로세스**의 environment block을 사용합니다. 모든 프로세스는 environment block을 소유하며, 자식 프로세스는 일반적으로 부모 프로세스의 environment를 복사해 상속합니다. 따라서 장시간 실행되는 service는 이전 값을 유지할 수 있고, 사용자 지정 environment로 실행된 service는 shell에서 확인되는 값과 다를 수 있습니다. 대상 PID가 해당 디렉터리를 정확히 probe한 Procmon 결과를 실제 기준으로 취급하세요. 실험 환경에서 `PATH`를 변경한 후 lookup이 발생하지 않는다고 결론 내리기 전에 관련 process tree를 restart하거나 reboot해야 합니다.<sup>[[5]](#references)</sup>

이러한 경우의 문제는 해당 process들이 이미 실행 중일 가능성이 높다는 것입니다. service가 load하려다 실패하는 DLL을 식별하려면 Procmon을 가능한 한 일찍(프로세스가 시작되기 전에) 실행한 다음:

> [!WARNING]
> user-writable 디렉터리를 Machine `PATH`에 추가하면 **취약한 조건이 생성됩니다**. 이는 격리된 research VM에서만 수행하여 어떤 privileged process가 `PATH`에 접근하는지 확인하세요. 평가 대상 host에서는 system configuration을 변경하지 말고 기존 writable entry를 모니터링하세요.<sup>[[1]](#references)</sup>

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
- **`procmon`**을 실행하고 **`Options`** --> **`Enable boot logging`**으로 이동한 다음, 프롬프트에서 **`OK`**를 누릅니다.
- 그런 다음 **재부팅**합니다. 컴퓨터가 다시 시작되면 **`procmon`**이 최대한 빠르게 이벤트 **기록**을 시작합니다.
- **Windows**가 **시작되면 `procmon`을 다시 실행**합니다. 그러면 해당 프로그램이 실행 중이었다고 알리고 이벤트를 파일에 **저장할지 묻습니다**. **예**를 선택하고 **이벤트를 파일에 저장**합니다.
- **파일**이 **생성되면**, 열려 있는 **`procmon`** 창을 닫고 **이벤트 파일을 엽니다**.
- writable System Path 폴더에서 **프로세스가 로드하려고 시도한** 모든 DLL을 찾기 위해 다음 **필터**를 추가합니다:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging은 너무 일찍 시작되어** 다른 방식으로는 관찰할 수 없는 서비스에만 필요합니다. **대상 service/program을 필요할 때 트리거할 수 있다면**(예: COM interface와 상호 작용하거나, service를 재시작하거나, scheduled task를 다시 실행하는 경우), 일반적인 Procmon 캡처를 유지하면서 **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, **`Path begins with <writable_machine_path>`**와 같은 필터를 사용하는 편이 일반적으로 더 빠릅니다.

### 누락된 DLL

**가상 (vmware) Windows 11 free machine**에서 이를 실행했을 때 다음 결과를 얻었습니다:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

이 경우 `.exe` 결과는 무시합니다. 누락된 DLL probe는 다음에서 발생했습니다:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

다음 예제에서는 이 문서의 [**권한 상승을 위해 `WptsExtensions.dll`을 악용하는**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) technique을 사용합니다.<sup>[[3]](#references)</sup>

### 추가로 triage할 가치가 있는 후보

`WptsExtensions.dll`은 좋은 예시지만, 권한이 높은 service에 반복적으로 나타나는 **phantom DLL**은 이것만이 아닙니다. 최신 hunting rule과 공개 hijack catalog에서는 다음과 같은 이름도 추적합니다:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client system에서 사용 가능한 전형적인 **SYSTEM** 후보입니다. writable directory가 **Machine PATH**에 있고 service가 startup 중 DLL을 probe할 때 유용합니다. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | 일부 build에서는 service가 **SYSTEM**으로 실행되고 **일반 사용자가 필요할 때 트리거할 수 있기** 때문에 **server edition**에서 흥미로운 후보입니다. 따라서 reboot만 필요한 경우보다 유리합니다. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 일반적으로 먼저 **`NT AUTHORITY\LOCAL SERVICE`**를 얻습니다. 해당 token에는 **`SeImpersonatePrivilege`**가 있으므로, 이를 [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md)와 chain할 수 있어 충분한 경우가 많습니다. |

이러한 이름은 **triage 힌트**일 뿐, 성공을 보장하지는 않습니다. **SKU/build에 따라 달라지며**, Microsoft가 release 간 동작을 변경할 수 있습니다. 중요한 점은 **Machine PATH를 순회하는 권한 높은 service에서 누락된 DLL**을 찾는 것입니다. 특히 service를 **reboot 없이 다시 트리거할 수 있는 경우**가 중요합니다.

### weaponize하기 전에 후보 검증

`NAME NOT FOUND` event만으로는 충분하지 않습니다. payload를 배치하기 전에 전체 chain을 검증합니다:<sup>[[1]](#references)[[4]](#references)</sup>

1. event가 예상한 **PID, command line, service account, integrity level**에 해당하고, 누락된 path가 정확히 writable Machine `PATH` directory인지 확인합니다.
2. 동일한 DLL basename에 대해 더 앞선 directory가 `SUCCESS`를 반환하지 않는지, 그리고 module이 loaded-module list, KnownDLLs, redirection 또는 SxS manifest로 충족되지 않는지 확인합니다.
3. 낮은 권한의 사용자가 의도한 trigger를 호출할 때 probe가 반복되는지 확인합니다. boot-only lookup도 사용할 수 있지만, on-demand 방식보다 운용 측면에서 훨씬 좋지 않습니다.
4. payload architecture가 process와 일치하는지 확인합니다. application이 나중에 export를 resolve한다면 legitimate DLL을 proxy하거나 예상되는 symbol을 export합니다. [Creating and compiling DLLs](README.md#creating-and-compiling-dlls)를 참고하세요.
5. 먼저 PID, identity 및 timestamp를 기록하는 무해한 canary DLL을 사용합니다. Procmon에서는 이전의 file probe가 execution을 유발했다고 가정하지 말고, planted path에서 성공한 **`Load Image`**를 요구해야 합니다.

### Exploitation

**권한을 상승**하려면 **`WptsExtensions.dll`**을 hijack합니다. **path**와 **name**을 알고 있다면 malicious DLL을 생성합니다.

[**다음 예제 중 하나를 사용해 볼 수 있습니다**](README.md#creating-and-compiling-dlls). 다음과 같은 payload를 실행할 수 있습니다: rev shell 획득, user 추가, beacon 실행 등...

> [!WARNING]
> **모든 service가** **`NT AUTHORITY\SYSTEM`**으로 실행되는 것은 아닙니다. 일부는 **권한이 더 적은** **`NT AUTHORITY\LOCAL SERVICE`**로 실행되므로, 이러한 service 중 하나를 악용해도 새 user를 생성하지 못할 수 있습니다.\
> 하지만 해당 account에는 **`SeImpersonatePrivilege`** user right가 있으므로 [**Potato suite를 사용해 권한을 상승**](../roguepotato-and-printspoofer.md)할 수 있습니다. 이 경우 user를 생성하려고 시도하는 것보다 reverse shell이 더 나은 선택입니다.

**Task Scheduler** service는 일반적으로 **`NT AUTHORITY\SYSTEM`**으로 실행되지만, 실제 deployment를 확인해야 하며 service name만으로 execution identity를 추론해서는 안 됩니다:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
**malicious Dll을 생성한 후** (_이 경우 x64 rev shell을 사용했고 shell을 얻었지만, msfvenom에서 생성된 것이었기 때문에 defender가 종료했습니다_), 해당 파일을 writable System Path에 **WptsExtensions.dll**이라는 이름으로 저장하고 컴퓨터를 **restart**합니다(또는 서비스를 restart하거나 영향을 받는 서비스/프로그램을 다시 실행하는 데 필요한 작업을 수행합니다).

서비스가 다시 시작되면 **DLL이 로드되고 실행되어야 합니다**(**Procmon** 트릭을 재사용하여 **라이브러리가 예상대로 로드되었는지** 확인할 수 있습니다).

> [!NOTE]
> 트리거하기 전에 cleanup을 계획하세요. 서비스가 DLL을 계속 매핑한 상태로 유지하여 서비스가 중지될 때까지 파일을 잠글 수 있습니다. `WptsExtensions.dll`의 경우 Task Scheduler를 중지하려면 elevated rights가 필요합니다. 의도한 context를 확보한 후 target을 안전하게 중지하고 payload를 제거한 다음, lab 전용 `PATH` 변경 사항을 복원하세요.<sup>[[1]](#references)</sup>

### 완화 / 탐지

모든 Machine `PATH` 디렉터리에서 취약한 write 권한을 제거하고 오래된 항목을 제거하세요. 개발자는 full path를 사용하여 trusted library를 로드하거나 `SetDefaultDllDirectories` / `LoadLibraryEx` search flag를 사용해 resolution을 제한해야 합니다. Defenders는 Machine `PATH` 변경 사항과 privileged process가 system 디렉터리가 아니며 user-writable한 디렉터리에서 DLL을 로드하는 행위를 연관 지어 분석할 수 있습니다.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Persistence 또는 Privilege Escalation을 위해 로드된 의심스러운 DLL](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
