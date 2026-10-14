# Obejścia kontroli dostępu do plików w trybie jądra

{{#include ../../banners/hacktricks-training.md}}

## Podatny schemat sterownika

Sterownik nie zachowuje granicy bezpieczeństwa wywołującego tylko dlatego, że działa w jego kontekście. Otwarcia obiektów w trybie jądra zwykle omijają kontrole dostępu. `OBJ_KERNEL_HANDLE` sprawia jedynie, że wynikowy uchwyt jest dostępny z trybu jądra. Gdy sterownik otwiera obiekt lub manipuluje nim w imieniu trybu użytkownika, musi również użyć `OBJ_FORCE_ACCESS_CHECK`, aby Object Manager sprawdził żądane uprawnienia względem efektywnego tokenu.<sup>[[3]](#references)[[4]](#references)</sup>

Przeprowadź audyt IOCTL-i obsługujących pliki i funkcji zwrotnych tworzenia pod kątem następującej sekwencji:<sup>[[3]](#references)[[4]](#references)</sup>

1. Tryb użytkownika przekazuje ścieżkę, uchwyt źródłowy, żądane uprawnienia lub typ operacji.
2. Sterownik działa w kontekście wywołującego, ale wywołuje `IoCreateFileEx`, `ZwCreateFile` lub podobną funkcję bez `OBJ_FORCE_ACCESS_CHECK`.
3. Uchwyt pliku lub katalogu dostępnego tylko z jądra zostaje zapisany w stanie przypisanym do uchwytu.
4. Późniejsza operacja decyduje, czy działać w kontekście wywołującego, na podstawie stanu kontrolowanego przez atakującego, takiego jak maska dostępu żądana podczas pierwszego otwarcia.
5. Uprzywilejowana ścieżka wykonuje zmianę nazwy lub tworzy łącze przy użyciu klasy informacji `BypassAccessCheck`.

To **prymityw plikowy confused deputy**, niekoniecznie uszkodzenie pamięci. Szczególnie niebezpieczne odwrócenie logiki stanu to: „zażądano zapisu — działaj w kontekście wywołującego; nie zażądano zapisu — pozostań uprzywilejowanym”. W takiej konstrukcji celowe zażądanie wyłącznie dostępu do odczytu może odblokować potężniejszą ścieżkę.<sup>[[3]](#references)</sup>

## Przykład vSMB: uprzywilejowany dostęp do katalogu głównego i uprzywilejowana zmiana nazwy

`storvsp.sys` implementuje Virtual Server Message Block (vSMB). Gdy funkcja **Virtual Machine Platform** jest włączona, tryb użytkownika może uzyskać dostęp do `\Device\STORVSP` przez `\\.\STORVSP`. Ścieżka systemu plików vSMB ma postać `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 i CVE-2025-64673 pokazały, jak dwie niespójne decyzje dotyczące kontroli dostępu mogły zmienić ten interfejs w lokalną eskalację uprawnień.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Powiązanie funkcji ze zgłoszeniami CVE w źródle opiera się na inżynierii wstecznej poprawionej wersji pliku binarnego, a nie na kodzie źródłowym Microsoftu. Badacze ostrzegają, że identyfikatory mogą być przypisane do przeciwnych funkcji.<sup>[[3]](#references)</sup>

### 1. Utwórz udział tylko do odczytu, którego katalogiem głównym jest chroniony katalog

Podatna ścieżka tworzenia zapisywała żądane uprawnienia w trwałych flagach, takich jak `HasReadAccess`, `HasWriteAccess` i `HasAppendAccess`. Następnie otwierała ścieżkę zaplecza z `OBJ_KERNEL_HANDLE`, ale bez `OBJ_FORCE_ACCESS_CHECK`. Próba działania w kontekście wywołującego nie sprawiała więc, że otwarcie pliku respektowało jego uprawnienia NTFS.<sup>[[3]](#references)[[4]](#references)</sup>

Zażądaj wyłącznie `FILE_READ_DATA`. Spowoduje to, że `HasWriteAccess` pozostanie wyczyszczona, a jednocześnie uzyskasz udział, którego wewnętrzny katalog główny wskazuje na chroniony katalog:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

Najważniejszym artefaktem nie jest uchwyt katalogu System32 w trybie użytkownika. Jest nim uchwyt urządzenia vSMB powiązany ze stanem sterownika, który zawiera uprzywilejowany uchwyt główny jądra.<sup>[[3]](#references)</sup>

### 2. Wykorzystanie niezgodności stanu do podmiany chronionego pliku

IOCTL `0x240330` przyjmował uchwyt pliku źródłowego, klasę informacji i bufor informacji o zmiennej długości:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Podatny handler akceptował `FileRenameInformation`, `FileLinkInformation` i `FileRenameInformationEx`. W przypadku zwykłej ścieżki zmiany nazwy dzielił ścieżkę nadrzędną od ostatniego składnika, a następnie otwierał katalog nadrzędny względem zapisanego uchwytu root. To otwarcie ponownie używało `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` bez `OBJ_FORCE_ACCESS_CHECK`. Odrzucano niezerową wartość `RootDirectory` podaną przez atakującego w strukturze zmiany nazwy, więc sterownik dostarczał własny, uprzywilejowany uchwyt katalogu.<sup>[[3]](#references)</sup>

Wykorzystywana gałąź była wybierana przez **nieżądanie dostępu do zapisu na etapie 1**:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: podszyj się pod zapamiętany kontekst zabezpieczeń root.
- `HasWriteAccess == 0`: pomiń podszywanie się i zamień `FileRenameInformation` lub `FileRenameInformationEx` na wariant `BypassAccessCheck`.

Handler duplikował podany przez atakującego uchwyt źródłowy w `PsInitialSystemProcess`, uzyskiwał do niego referencję jako do obiektu pliku, umieszczał uprzywilejowany uchwyt katalogu docelowego w strukturze zmiany nazwy i wywoływał `ZwSetInformationFile`. Przy `ReplaceIfExists = TRUE` plik kontrolowany przez wywołującego mógł więc zastąpić istniejący plik poniżej chronionego root.<sup>[[3]](#references)</sup>

Podczas analizy podobnego handlera śledź **zarówno pochodzenie uchwytów, jak i kontekst zabezpieczeń** we wszystkich gałęziach. Walidacja danych wejściowych, kontrole przepełnienia liczb całkowitych, `IO_STOP_ON_SYMLINK` oraz ograniczenie akceptowanych klas informacji nie kompensują połączenia uprzywilejowanego uchwytu root z operacją omijającą kontrolę dostępu.<sup>[[3]](#references)</sup>

## Od zapisu do chronionego pliku do wykonania jako SYSTEM

Mechanizm podmiany chronionego pliku prowadzi do wykonania kodu, gdy uprzywilejowany proces później załaduje podmieniony moduł. W przedstawionym łańcuchu plikiem docelowym był `C:\Windows\System32\wuapi.dll`. Aktywowanie klasy COM local-server `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` dla interfejsu `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` i wywołanie `IWaaSRemediation::LaunchDetectionOnly()` powodowało załadowanie tej biblioteki DLL przez proces SYSTEM.<sup>[[3]](#references)</sup>

To wywołanie COM jest **wyzwalaczem aktywacji**, a nie [przejęciem rejestru COM](com-hijacking.md). Mechanizm podmiany pliku dostarcza umieszczony tam moduł, a uprzywilejowany loader zapewnia jego wykonanie. W przypadku innych łańcuchów wykorzystujących zapis do chronionych plików ustal dokładny obraz, ścieżkę DLL, politykę podpisów, bitowość, eksportowane funkcje i niezawodny wyzwalacz, zanim wybierzesz cel. Ogólny proces analizy loadera opisano w sekcji [łączenie dowolnego zapisu do pliku z DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[3]](#references)</sup>

### Przenoszenie tokena Session 0 na interaktywny pulpit

Ładunek załadowany przez usługę jest zwykle wykonywany w Session 0. Aby utworzyć proces interaktywny, może pobrać aktywną sesję konsoli za pomocą `WTSGetActiveConsoleSessionId`, włączyć wymagane uprawnienia tokena, zduplikować bieżący token SYSTEM jako token podstawowy i ustawić jego `TokenSessionId` na aktywną sesję. Następnie `CreateProcessAsUserW` używa tego tokena z `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` jest wymagane do ustawienia identyfikatora sesji tokenu w tym scenariuszu. Interaktywna stacja okien i pulpit również muszą przyznawać tokenowi dostęp. Zobacz [duplikowanie tokenu z Session 0](sedebug-+-seimpersonate-copy-token.md), aby poznać pełny przebieg kopiowania tokenu.<sup>[[3]](#references)[[5]](#references)</sup>

## Wskazówki dotyczące poprawek i przeglądu

Aktualizacje Microsoftu z grudnia 2025 r. naprawiły przedstawiony łańcuch. Inżynieria wsteczna wykazała, że poprawiona ścieżka tworzenia vSMB odrzuca niezaufanych wywołujących, którzy żądają katalogu głównego udziału bez `FILE_WRITE_DATA`. Wymuszono również kontrolę dostępu dla odpowiednich operacji. Zapobiega to odwróceniu stanu, zanim nieuprzywilejowany wywołujący uzyska dostęp do uprzywilejowanego katalogu głównego.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

W kodzie sterownika stosuj następujące zasady:<sup>[[3]](#references)[[4]](#references)</sup>

- Dodawaj `OBJ_FORCE_ACCESS_CHECK` zawsze, gdy obiekt jest otwierany na żądanie z trybu użytkownika. Nie traktuj `OBJ_KERNEL_HANDLE` jako mechanizmu kontroli autoryzacji.<sup>[[4]](#references)</sup>
- Przechwytuj i weryfikuj tryb wywołującego oraz efektywny kontekst podmiotu. Nie pozwalaj, aby żądane uprawnienia wybierały bardziej uprzywilejowaną ścieżkę wykonania.
- Weryfikuj uchwyty użytkownika, używając prawidłowego typu obiektu, maski dostępu i `UserMode`. Zduplikowanie uchwytu do procesu systemowego nie weryfikuje uprawnień do żądanej operacji.
- Rozwiązuj ścieżki docelowe względem zaufanego uchwytu, ale upewnij się, że sam zaufany uchwyt został otwarty z wymuszoną kontrolą dostępu wywołującego.
- Unikaj klas `File*BypassAccessCheck` w operacjach inicjowanych przez użytkownika. Jeśli kod wewnętrzny rzeczywiście ich potrzebuje, zabezpiecz tę ścieżkę decyzją autoryzacyjną niezależną od flag dostępu kontrolowanych przez użytkownika.
- Instaluj poprawki w podatnych systemach. Podatna powierzchnia ma znaczenie, gdy Virtual Machine Platform ładuje `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Od wirtualnego udziału do fizycznego powłoki: wykorzystanie niespójnej kontroli dostępu w Windows do LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Uchwyty obiektów](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Funkcja CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
