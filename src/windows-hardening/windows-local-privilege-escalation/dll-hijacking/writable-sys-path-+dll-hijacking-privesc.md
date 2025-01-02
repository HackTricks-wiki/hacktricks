# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

시스템 경로 폴더에 **쓰기**가 가능하다는 것을 발견했다면(사용자 경로 폴더에 쓸 수 있는 경우에는 작동하지 않음), 시스템에서 **권한 상승**을 할 수 있을 가능성이 있습니다.

이를 위해 **Dll Hijacking**을 악용할 수 있으며, 이는 **당신보다 더 높은 권한**을 가진 서비스나 프로세스에 의해 **로드되는 라이브러리**를 **탈취**하는 것입니다. 그리고 그 서비스가 아마도 시스템 전체에 존재하지 않는 Dll을 로드하려고 시도하기 때문에, 당신이 쓸 수 있는 시스템 경로에서 로드하려고 할 것입니다.

**Dll Hijacking이 무엇인지**에 대한 더 많은 정보는 다음을 확인하세요:

{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

가장 먼저 필요한 것은 **당신보다 더 높은 권한**으로 실행 중인 **프로세스**를 **식별**하는 것입니다. 이 프로세스는 당신이 쓸 수 있는 시스템 경로에서 **Dll을 로드하려고** 하고 있습니다.

이 경우의 문제는 아마도 그 프로세스들이 이미 실행 중이라는 것입니다. 필요한 서비스의 부족한 Dll을 찾기 위해서는 프로세스가 로드되기 전에 가능한 한 빨리 procmon을 실행해야 합니다. 따라서 부족한 .dll을 찾기 위해 다음을 수행하세요:

- **폴더** `C:\privesc_hijacking`를 **생성**하고 `C:\privesc_hijacking` 경로를 **시스템 경로 환경 변수**에 추가하세요. 이는 **수동으로** 또는 **PS**를 사용하여 할 수 있습니다:
```powershell
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
- **`procmon`**을 실행하고 **`Options`** --> **`Enable boot logging`**으로 이동한 후 프롬프트에서 **`OK`**를 누릅니다.
- 그런 다음 **재부팅**합니다. 컴퓨터가 재시작되면 **`procmon`**이 가능한 한 빨리 **이벤트를 기록**하기 시작합니다.
- **Windows**가 **시작된 후 `procmon`을 다시 실행**하면 실행 중임을 알려주고 **이벤트를 파일에 저장할 것인지 묻습니다**. **예**라고 말하고 **이벤트를 파일에 저장**합니다.
- **파일이 생성된 후**, 열린 **`procmon`** 창을 **닫고 이벤트 파일을 엽니다**.
- 이러한 **필터**를 추가하면 어떤 **프로세스가 쓰기 가능한 시스템 경로 폴더에서 Dll을 로드하려고 했는지** 알 수 있습니다:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### 놓친 Dlls

무료 **가상 (vmware) Windows 11 머신**에서 이 작업을 실행했을 때 다음과 같은 결과를 얻었습니다:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

이 경우 .exe는 쓸모가 없으므로 무시하고, 놓친 DLL은 다음과 같습니다:

| 서비스                           | Dll                | CMD 라인                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| 작업 스케줄러 (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 진단 정책 서비스 (DPS)         | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

이것을 찾은 후, [**WptsExtensions.dll을 악용하는 방법**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)에 대해서도 설명하는 흥미로운 블로그 게시물을 발견했습니다. 이것이 우리가 **지금 하려는 일**입니다.

### 악용

따라서 **권한을 상승시키기 위해** 라이브러리 **WptsExtensions.dll**을 하이재킹할 것입니다. **경로**와 **이름**을 알았으니 이제 **악성 dll을 생성**하기만 하면 됩니다.

[**이 예제 중 하나를 사용해 볼 수 있습니다**](./#creating-and-compiling-dlls). 리버스 쉘을 얻거나, 사용자를 추가하거나, 비콘을 실행하는 등의 페이로드를 실행할 수 있습니다...

> [!WARNING]
> 모든 서비스가 **`NT AUTHORITY\SYSTEM`**으로 실행되는 것은 아닙니다. 일부는 **`NT AUTHORITY\LOCAL SERVICE`**로 실행되며, 이는 **권한이 적습니다**. 따라서 **새 사용자를 생성할 수 없습니다**.\
> 그러나 해당 사용자는 **`seImpersonate`** 권한을 가지고 있으므로 [**potato suite를 사용하여 권한을 상승시킬 수 있습니다**](../roguepotato-and-printspoofer.md). 따라서 이 경우 리버스 쉘이 사용자를 생성하려고 시도하는 것보다 더 나은 옵션입니다.

이 글을 작성할 당시 **작업 스케줄러** 서비스는 **Nt AUTHORITY\SYSTEM**으로 실행되고 있습니다.

**악성 Dll을 생성한 후** (_제 경우 x64 리버스 쉘을 사용했으며 쉘을 받았지만 defender가 msfvenom에서 온 것이기 때문에 이를 차단했습니다_), 쓰기 가능한 시스템 경로에 **WptsExtensions.dll**이라는 이름으로 저장하고 **컴퓨터를 재시작**합니다 (또는 서비스를 재시작하거나 영향을 받는 서비스/프로그램을 다시 실행하기 위해 필요한 모든 작업을 수행합니다).

서비스가 재시작되면 **dll이 로드되고 실행되어야 합니다** (이때 **procmon** 트릭을 재사용하여 **라이브러리가 예상대로 로드되었는지 확인할 수 있습니다**).

{{#include ../../../banners/hacktricks-training.md}}
