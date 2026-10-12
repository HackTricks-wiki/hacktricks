# Windows: Double-Fetch w buforze użytkownika mapowanym przez MDL

{{#include ../../banners/hacktricks-training.md}}

Sterownik jądra Windows powoduje double-fetch, gdy sprawdza dane w stronach należących do wywołującego, a następnie przekazuje wskaźnik do tych samych stron do interfejsu API wrażliwego z punktu widzenia bezpieczeństwa. Zablokowanie i zmapowanie stron nie sprawia, że ich zawartość staje się niezmienna. CVE-2025-55680 w `cldflt.sys` ilustruje ten wzorzec: sterownik sprawdził nazwę względną placeholdera Cloud Files, a następnie utworzył obiekt, wciąż korzystając ze zmiennego bufora wywołującego.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` tworzy pliki lub katalogi w zarejestrowanym katalogu głównym synchronizacji Cloud Files. W podatnej ścieżce zmiana nazwy po jej sprawdzeniu mogła przekierować uprzywilejowane tworzenie obiektu poza ten katalog główny.<sup>[[1]](#references)[[2]](#references)</sup>

## Dlaczego zablokowanie stron nie zablokowało danych

Podatna ścieżka `HsmpOpCreatePlaceholders()` alokowała MDL dla danych wywołującego, wywoływała `ProbeForRead()` i `MmProbeAndLockPages()`, a następnie mapowała te strony do wirtualnej przestrzeni adresowej jądra. MDL opisuje i blokuje strony fizyczne, dzięki czemu pozostają one w pamięci. **Nie** tworzy migawki ich bajtów. Proces działający w trybie użytkownika może więc modyfikować tę samą pamięć fizyczną, podczas gdy sterownik odczytuje ją przez mapowanie systemowe.<sup>[[1]](#references)[[3]](#references)</sup>

Istotna ścieżka żądania i użycia wyglądała następująco:<sup>[[1]](#references)</sup>

1. `cldapi.dll` wysyłał kod sterujący Cloud Files `0x903BC` z tagiem `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) i operacją tworzenia placeholdera `0xC0000001`.
2. Każdy rekord danych zawierał pary 16-bitowych wartości offsetu/długości dla nazwy względnej i identyfikatora pliku. Większość stałych pól kopiowano do rekordu na stosie, ale nazwa o zmiennej długości pozostawała w zmapowanych stronach użytkownika.
3. Sterownik przeszukiwał nazwę UTF-16 i odrzucał ukośnik odwrotny lub dwukropek.
4. Następnie tworzył `UNICODE_STRING`, którego `Buffer` nadal wskazywał na dane zmapowanego bufora, i przypisywał go do `OBJECT_ATTRIBUTES.ObjectName`.
5. `FltCreateFileEx2()` ponownie odczytywał ten wskaźnik. Równoległy zapis mógł więc sprawić, że walidacja zobaczyła jeden ciąg znaków, a tworzenie pliku — inny.

To **double-fetch**, mimo że oba odczyty korzystają z wirtualnego adresu jądra: granica bezpieczeństwa zależy od magazynu bazowego, a nie od tego, które mapowanie wirtualne dereferencjonuje sterownik.<sup>[[1]](#references)</sup>

## Układ wyścigu w Cloud Files

Opisana strategia exploita wykorzystywała wielokrotnie wysyłane żądania, wątki modyfikujące dane i junction, aby przekształcić double-fetch w przekierowanie ścieżki:<sup>[[1]](#references)</sup>

1. Zarejestrować kontrolowany przez atakującego katalog za pomocą `CfRegisterSyncRoot()` i utworzyć w nim `JUSTASTRING` jako junction do chronionego miejsca docelowego.
2. Przygotować współdzielony rekord placeholdera z prawidłową nazwą jednoskładnikową `JUSTASTRINGDnewfile.dll`.
3. Uruchomić wątki modyfikujące, które przełączają 16-bitowy znak UTF-16 `D` między `D` a `\`. Drugi wariant to `JUSTASTRING\newfile.dll`.
4. Równolegle uruchomić wątki robocze, które wielokrotnie wysyłają żądania tworzenia placeholdera odwołujące się do tych samych danych, a wątek monitorujący sprawdza chronione miejsce docelowe.
5. Udana iteracja sprawdza wariant bez separatora, a następnie podąża za junction, gdy późniejsza operacja tworzenia odczytuje wariant zawierający `\`.

Ten prymityw umożliwia jedynie tworzenie chronionych plików lub katalogów. Wykonanie kodu wymaga dodatkowo kontroli nad zawartością utworzonego pliku oraz uprzywilejowanego programu, który go wykorzysta, na przykład odpowiedniego celu do DLL side-loading. Oryginalna analiza wykorzystywała taki końcowy etap łańcucha, ale nie opublikowała loadera, payloadu ani kompletnego, samodzielnego exploita.<sup>[[1]](#references)</sup>

Informacje o uzupełniających technikach celowo poszerzających wyścigi podczas wyszukiwania ścieżek w Windows znajdziesz w artykule [Kernel Race Condition Exploitation via Object Manager Slow Paths](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Eskalacja uprawnień przez TOCTOU w minifiltrze Cloud Files systemu Microsoft Windows](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - Funkcja CfCreatePlaceholders](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - Funkcja MmProbeAndLockPages](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
