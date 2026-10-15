# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## Zakres

Implant po uzyskaniu dostępu może załadować podpisany sterownik jądra jako usługę i udostępnić płaszczyznę sterowania w trybie użytkownika za pośrednictwem `IRP_MJ_DEVICE_CONTROL`. Podpis sterownika potwierdza jedynie, że Windows akceptuje obraz — nie oznacza to, że autoryzacja IOCTL, operacje na pamięci, wywołania zwrotne czy hooki są bezpieczne. Jeden analizowany rootkit używał trzech handlerów podczas normalnego działania, ale udostępniał dziesiątki dodatkowych prymitywów post-exploitation, dlatego reverse engineering musi obejmować cały dispatcher, a nie tylko żądania zaobserwowane w śladzie działania malware.<sup>[[1]](#references)</sup>

## Analiza podpisanego sterownika i IOCTL

Zacznij od `DriverEntry`, zanotuj obiekty urządzeń i dowiązania symboliczne DOS, znajdź procedurę `MajorFunction[IRP_MJ_DEVICE_CONTROL]` i zmapuj wszystkie porównania oraz wpisy w tabelach prowadzące do handlera. Porównaj nazwy otwierane przez kod w trybie użytkownika z nazwami faktycznie utworzonymi przez sterownik: w jednym zaobserwowanym łańcuchu otwierano `\\.\msagent`, podczas gdy sterownik tworzył `\Device\ToolTool` i `\DosDevices\ToolTool`. Ta rozbieżność może wskazywać na inną próbkę lub konfigurację, brakującą logikę konfiguracji albo niespójność analizy.<sup>[[1]](#references)</sup>

Zdekoduj każdy kod sterujący przed odtworzeniem struktury wejściowej.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

Te trzy kody dekodują się jako `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` i `METHOD_BUFFERED`. **Nie** dowodzi to, że nieuprzywilejowany wywołujący może z nich skorzystać: sprawdź również DACL urządzenia, obsługę tworzenia/otwierania, kontrole wywołującego dla każdego żądania, oczekiwane długości buforów, osadzone wskaźniki, obsługę cyklu życia PID oraz to, czy handler ufa PID lub fladze podanej przez wywołującego.<sup>[[1]](#references)</sup>

Gdy implant używa tylko podzbioru poleceń, pogrupuj pozostałe handlery według prymitywu, zamiast uznawać je za martwy kod. Jeden wielofunkcyjny driver udostępniał wszystkie poniższe klasy:<sup>[[1]](#references)</sup>

- **Sterowanie/konfiguracja:** przełączanie stanu rootkita; dodawanie, usuwanie, wyszukiwanie lub czyszczenie chronionych ścieżek, procesów i adresów C2.
- **Manipulowanie procesami:** kończenie procesu o danym PID, odmapowywanie jego obrazu, wstrzykiwanie za pomocą `NtCreateThreadEx`, ukrywanie/przywracanie procesów lub modułów użytkownika oraz usuwanie ochrony PPL.
- **Manipulowanie jądrem:** odłączanie załadowanego drivera od listy, wyliczanie/wyłączanie/przywracanie callbacków powiadomień, ręczne mapowanie innego drivera i zapis pod dowolny adres jądra.
- **Manipulowanie obiektami:** usuwanie/odszyfrowywanie plików oraz tworzenie lub modyfikowanie wartości rejestru.

## Ręczne mapowanie jądra za pomocą podatnego, podpisanego drivera

Podpisany driver z operacjami odczytu/zapisu pamięci jądra może posłużyć jako loader niepodpisanego obrazu drivera, bez proszenia Windows o załadowanie go jako zwykłego drivera.<sup>[[2]](#references)[[7]](#references)</sup> Przykład LocalStranger otwiera istniejące urządzenie `\\.\WinNotify`; kod źródłowy nie pokazuje, że nieuprzywilejowany użytkownik może zainstalować, uruchomić lub otworzyć ten driver na dowolnym hoście.<sup>[[2]](#references)[[3]](#references)</sup> Mapper przyjmuje ścieżkę do obrazu, pobiera adres bazowy załadowanego jądra i używa IOCTL-i urządzenia do odczytu/zapisu pamięci wirtualnej.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Aby przekształcić dostęp do odczytu/zapisu w wywołanie jądra, mapper odczytuje wartość immediate zawierającą bazę PTE z `MmGetVirtualForPhysical` i przechodzi po wpisach tablic stron obejmujących `NtAddAtom`.<sup>[[5]](#references)[[7]](#references)</sup> Obliczenie PTE to `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`; kod sprawdza również, czy PDE wskazuje na dużą stronę.<sup>[[5]](#references)[[7]](#references)</sup> Tymczasowo ustawia wpis obejmujący adres jako zapisywalny, zastępuje wpis syscalla skokiem do żądanej funkcji jądra, wywołuje stub `NtAddAtom` z trybu użytkownika, a następnie przywraca oryginalne bajty i wpis strony.<sup>[[6]](#references)</sup>

Mapper wykorzystuje tę ścieżkę wywołania do `ExAllocatePool`, mapuje sekcje PE, importy i relokacje do obrazu, zapisuje go do zaalokowanej pamięci i wywołuje jego punkt wejścia.<sup>[[7]](#references)[[8]](#references)</sup> Ta implementacja obsługuje wyłącznie relokowalne obrazy PE x64; odczyt bazy PTE zakłada również stały układ `MmGetVirtualForPhysical + 34`.<sup>[[5]](#references)[[8]](#references)</sup> Traktuj ją jako zależną od kompilacji, a nie jako niezależne obejście KASLR ani dowód, że HVCI lub PatchGuard pozwala na mapowanie.<sup>[[5]](#references)[[8]](#references)</sup> Przykład użycia odczytu/zapisu jądra wyłącznie do operacji na danych znajdziesz w [kradzieży tokena SYSTEM](arbitrary-kernel-rw-token-theft.md).

## Wyjątki dla zaufanych procesów

Przydatnym wzorcem projektowym jest IOCTL rejestrujący PID wraz z flagą **trusted**. Ta sama weryfikacja zaufania jest następnie używana przez filtry plików, rejestru, procesów i wątków: niezaufane narzędzia otrzymują przefiltrowane wyniki wyliczania, ograniczone prawa do uchwytów albo `STATUS_ACCESS_DENIED`, podczas gdy implant nadal może aktualizować własne ukryte obiekty. Traktuj to jako granicę autoryzacji i sprawdź, jak wpisy są uwierzytelniane, synchronizowane i usuwane po zakończeniu procesu lub ponownym użyciu PID.<sup>[[1]](#references)</sup>

Rootkity mogą przechowywać zasady w wartościach `REG_MULTI_SZ` i kompilować listy plików, katalogów, kluczy rejestru, wartości rejestru, ignorowanych obrazów, chronionych obrazów i ukrytych obrazów do drzew AVL. Podczas analizy prześledź wszystkie miejsca odczytu i zapisu tych współdzielonych drzew; łączą one konfigurację rejestru, IOCTL-e, callbacki i logikę filtrowania, nawet jeśli nazwy funkcji zostały usunięte.<sup>[[1]](#references)</sup>

## Ukrywanie procesów i modułów za pomocą DKOM

### `EPROCESS.ActiveProcessLinks`

Przesunięcia `ActiveProcessLinks` różnią się w zależności od kompilacji Windows. Odporny na różnice wersji rootkit może sprawdzić znane kandydaty, a następnie przeszukać `EPROCESS` w poszukiwaniu spójnego `LIST_ENTRY`, którego sąsiedzi wskazują z powrotem na kandydata. Zachowuje wykryte przesunięcie, ukrywa proces, ponownie łącząc wskaźniki `Flink`/`Blink` sąsiadów, i zapisuje stan, aby później ponownie wstawić wpis na listę. Proces nadal działa, ale znika z wyników enumeratorów przechodzących po liście aktywnych procesów.<sup>[[1]](#references)</sup>

To **DKOM**, a nie zakończenie procesu. Wykrywanie powinno porównywać wyniki oparte na listach z niezależnymi dowodami, takimi jak skanowanie puli/obiektów, własność wątków, tablice uchwytów, artefakty planisty i inspekcja pamięci jądra. Proces znaleziony podczas skanowania, ale nieobecny na kanonicznej liście, ma większe znaczenie niż którykolwiek z tych widoków rozpatrywany osobno.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Analogiczny prymityw do ukrywania modułów wyszukuje docelowy wpis w `PsLoadedModuleList` i modyfikuje sąsiednie wskaźniki `Flink`/`Blink`. Driver pozostaje zmapowany i wykonywalny, ale zapytania o moduły oparte na liście go pomijają. Porównuj listę loadera z wykonywalnymi mapowaniami jądra, tagami puli, obiektami urządzeń/driverów, kluczami usług, adresami callbacków i wskaźnikami dispatch wskazującymi obszary spoza wymienionych obrazów.<sup>[[1]](#references)</sup>

## Ochrona i ukrywanie za pomocą callbacków

Rootkit może łączyć udokumentowane frameworki callbacków z DKOM i hookami:<sup>[[1]](#references)</sup>

- Handlery pre-operation `ObRegisterCallbacks` dla `PsProcessType` i `PsThreadType` usuwają prawa używane do kończenia procesu, dostępu do pamięci wirtualnej, duplikowania uchwytów lub manipulowania wątkami, gdy niezaufany wywołujący otwiera chroniony obiekt. Zapisz altitude callbacka i ustal, do którego modułu należy każdy adres callbacka.
- `PsSetCreateProcessNotifyRoutineEx` i `PsSetLoadImageNotifyRoutine` aktualizują stan chronionych/ignorowanych/ukrytych procesów w miarę pojawiania się procesów i obrazów; jednorazowe przejście po procesach może uzupełnić stan o obiekty istniejące przed rejestracją.
- Minifiltr systemu plików odmawia dostępu do skonfigurowanych ścieżek. Nietypowa implementacja może utworzyć klucz `Instances`, dynamicznie wybrać altitude i zwiększać ją oraz ponawiać próbę, gdy `FltRegisterFilter` zgłosi konflikt.
- Procedura `CmRegisterCallbackEx` może ukrywać chronione nazwy podczas wyliczania i blokować bezpośrednie otwieranie, zmianę nazwy, ustawianie lub usuwanie, jednocześnie dopuszczając zarejestrowane zaufane procesy.

Skoreluj rejestracje `ObRegisterCallbacks`, wartości altitude callbacków rejestru, wyniki `fltmc filters`, klucze usług `Instances` i adresy callbacków. Jeśli zwykłe narzędzia są filtrowane, sprawdź te struktury w obrazie pamięci pozyskanym offline lub za pomocą innej zaufanej warstwy pozyskiwania danych.<sup>[[1]](#references)</sup>

## Filtrowanie wyników Nsiproxy

Ukrywanie informacji o sieci może obejmować `\Driver\Nsiproxy`: pobranie obiektu drivera za pomocą `ObReferenceObjectByName`, zapisanie wskaźnika handlera, zastąpienie go wrapperem i usunięcie zwróconych rekordów IPv4 pasujących do listy C2 zarządzanej przez IOCTL, zanim dane trafią do trybu użytkownika. Aplikacje korzystające z filtrowanych danych NSI mogą przestać wyświetlać połączenie, mimo że ruch nadal istnieje.<sup>[[1]](#references)</sup>

Porównuj widoki połączeń hosta z przechwytywaniem pakietów, telemetrią WFP/ETW i obiektami sieciowymi w pamięci jądra. Sprawdź również wskaźniki dispatch/handlera `Nsiproxy` i upewnij się, że każdy z nich wskazuje adres w oczekiwanym podpisanym module; wskaźnik do niezarejestrowanego mapowania może połączyć filtrowanie sieci z DKOM `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Lista kontrolna dochodzenia

Najsilniejszym sygnałem jest rozbieżność między warstwami, a nie pojedyncza nazwa pliku lub hash. Skoreluj:<sup>[[1]](#references)</sup>

1. Utworzenie usługi jądra i podpisany driver, którego wiek certyfikatu, wydawca lub ścieżka nie pasują do zainstalowanego produktu.
2. Utworzenie urządzenia, łącza DOS i ruch IOCTL, w tym rozbieżności między nazwami urządzenia w trybie użytkownika i w jądrze.
3. Żądanie rejestracji PID, po którym inne procesy nie mogą otwierać, wyliczać, modyfikować ani usuwać tych samych obiektów.
4. Callbacki obiektów/rejestru/procesów/obrazów, instancje minifiltrów i hooki, których adresy nie należą do zwykle wyliczanego drivera.
5. Różnice między inwentaryzacjami procesów, modułów, callbacków i sieci opartymi na listach oraz na skanowaniu.

## References

- [1] [Kaspersky Securelist - HoneyMyte udoskonala CoolClient za pomocą podpisanego rootkita jądra Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [Plik README LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [Inicjalizacja drivera LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [Wiersz poleceń mappera LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Rozwiązywanie eksportu jądra i bazy PTE w LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Trampolina wywołania jądra LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [Alokacja i wywołanie punktu wejścia przez mapper LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [Mapowanie PE w LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Kontekst jądra i syscalli w LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Wrappery IOCTL pamięci wirtualnej LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
