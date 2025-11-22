# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## 소개

만약 당신이 **write in a System Path folder**에 쓸 수 있다는 것을 발견했다면(참고: 이것은 User Path folder에 쓸 수 있는 경우에는 작동하지 않습니다), 시스템에서 **escalate privileges**할 가능성이 있습니다.

이를 위해 당신은 **Dll Hijacking**을 악용할 수 있습니다. 이는 당신보다 **more privileges**를 가진 서비스나 프로세스가 로드하는 라이브러리를 **hijack a library being loaded**하는 방법입니다. 그리고 그 서비스가 시스템 전체에 존재하지 않을 가능성이 큰 Dll을 로드하려 하기 때문에, 당신이 쓸 수 있는 System Path에서 그것을 로드하려 시도할 것입니다.

자세한 내용은 **what is Dll Hijackig**을(를) 확인하세요:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### 누락된 Dll 찾기

먼저 필요한 것은 당신보다 **more privileges**로 실행되며 당신이 쓸 수 있는 **load a Dll from the System Path**을 시도하는 프로세스를 **identify a process**하는 것입니다.

문제는 이러한 경우 해당 프로세스들이 이미 실행 중일 가능성이 크다는 점입니다. 어떤 Dll들이 누락되었는지 찾으려면 프로세스들이 로드되기 전에 가능한 빨리 procmon을 실행해야 합니다. 따라서 누락된 .dll을 찾으려면 다음을 수행하세요:

- `C:\privesc_hijacking` 폴더를 생성하고 해당 경로 `C:\privesc_hijacking`를 **System Path env variable**에 추가하세요. 이 작업은 수동(**manually**)으로 하거나 **PS**로 수행할 수 있습니다:
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
- **`procmon`** 를 실행하고 **`Options`** --> **`Enable boot logging`** 로 이동한 다음 프롬프트에서 **`OK`** 를 누릅니다.
- 그다음 **재부팅(reboot)** 합니다. 컴퓨터가 재시작되면 **`procmon`** 이 가능한 한 빨리 이벤트 기록을 시작합니다.
- Windows가 시작된 후 **`procmon`** 을 다시 실행하면 이미 실행 중이었다고 알리고 이벤트를 파일에 저장할지 물어봅니다. **yes** 라고 답하고 **이벤트를 파일에 저장** 합니다.
- **파일이 생성된 후**, 열려 있는 **`procmon`** 창을 닫고 **이벤트 파일을 엽니다**.
- 다음 **필터**들을 추가하면 writable System Path 폴더에서 어떤 프로세스가 로드하려고 했는지 모든 Dll을 찾을 수 있습니다:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### 누락된 Dlls

무료 가상(vmware) Windows 11 머신에서 이 방법을 실행했을 때 다음과 같은 결과를 얻었습니다:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

이 경우 .exe 파일들은 쓸모없으니 무시하고, 누락된 DLL들은 다음에서 로드되었습니다:

| 서비스                          | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

이걸 찾은 뒤, 다음 흥미로운 블로그 포스트도 발견했는데 [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) 에서도 이를 설명합니다. 이것이 **지금 우리가 하려는 작업**입니다.

### Exploitation

권한을 상승시키기 위해 WptsExtensions.dll 라이브러리를 하이재킹할 것입니다. 경로와 이름을 알았으니 악성 dll을 생성하면 됩니다.

[**try to use any of these examples**](#creating-and-compiling-dlls) 를 시도해볼 수 있습니다. 실행할 수 있는 페이로드 예: rev shell 획득, 사용자 추가, beacon 실행 등...

> [!WARNING]
> 모든 서비스가 **`NT AUTHORITY\SYSTEM`** 으로 실행되는 것은 아닙니다. 일부는 **`NT AUTHORITY\LOCAL SERVICE`** 로 실행되며 권한이 더 적기 때문에 새 사용자를 생성할 수 없을 수 있습니다.\
> 하지만 해당 계정은 **`seImpersonate`** 권한을 가지고 있으므로 [ **potato suite to escalate privileges** ](../roguepotato-and-printspoofer.md) 를 사용해 권한을 상승시킬 수 있습니다. 따라서 이 경우 새 사용자 만들기를 시도하는 것보다 rev shell이 더 나은 선택입니다.

작성 시점에서는 Task Scheduler 서비스가 **Nt AUTHORITY\SYSTEM** 으로 실행되고 있었습니다.

악성 Dll을 생성한 후(제 경우 x64 rev shell을 사용했고 셸을 얻었지만 msfvenom에서 생성되어 defender가 차단했습니다), 이를 writable System Path에 이름을 **WptsExtensions.dll** 로 저장하고 컴퓨터를 재시작하거나(또는 해당 서비스/프로그램을 재시작하여 다시 실행되게 합니다).

서비스가 재시작되면 해당 dll이 로드되어 실행되어야 합니다(라이브러리가 예상대로 로드되었는지 확인하려면 **procmon** 트릭을 재사용할 수 있습니다).

{{#include ../../../banners/hacktricks-training.md}}
