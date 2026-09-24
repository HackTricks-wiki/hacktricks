# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## Zakres

Implant po uzyskaniu kompromitacji może załadować podpisany sterownik jądra jako usługę i udostępnić user-mode control plane za pośrednictwem `IRP_MJ_DEVICE_CONTROL`. Podpisywanie sterownika jedynie potwierdza, że Windows akceptuje obraz; nie sprawia, że autoryzacja IOCTL, operacje pamięci, callbacki ani hooki są bezpieczne. Jeden z przeanalizowanych rootkitów używał trzech handlerów podczas normalnego działania, ale udostępniał dziesiątki dodatkowych post-exploitation primitives, dlatego reverse engineering musi obejmować cały dispatcher, a nie tylko żądania zaobserwowane w śladzie malware.<sup>[[1]](#references)</sup>

## Triage podpisanego sterownika i IOCTL

Rozpocznij od `DriverEntry`, zapisz obiekty urządzeń i dowiązania symboliczne DOS, znajdź procedurę `MajorFunction[IRP_MJ_DEVICE_CONTROL]` i zmapuj każde porównanie/wpis tabeli prowadzący do handlera. Porównaj nazwy otwierane przez user mode z nazwami faktycznie tworzonymi przez sterownik: w jednym zaobserwowanym łańcuchu otwierano `\\.\msagent`, podczas gdy sterownik tworzył `\Device\ToolTool` i `\DosDevices\ToolTool`. Ta rozbieżność może wskazywać na inną próbkę/konfigurację, brakującą logikę konfiguracji albo niespójność analizy.<sup>[[1]](#references)</sup>

Przed odtworzeniem struktury wejściowej zdekoduj każdy control code.<sup>[[1]](#references)</sup>
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
Te trzy kody dekodują się jako `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` oraz `METHOD_BUFFERED`. To **nie** dowodzi, że nieuprzywilejowany caller może do nich dotrzeć: należy również sprawdzić DACL urządzenia, obsługę create/open, kontrole callera dla poszczególnych żądań, oczekiwane długości buforów, osadzone wskaźniki, obsługę czasu życia PID oraz to, czy handler ufa PID-owi lub fladze dostarczonym przez callera.<sup>[[1]](#references)</sup>

Gdy implant używa tylko podzbioru poleceń, pogrupuj pozostałe handlery według prymitywu, zamiast odrzucać je jako martwy kod. Pojedynczy wielofunkcyjny sterownik ujawnił wszystkie poniższe klasy:<sup>[[1]](#references)</sup>

- **Sterowanie/konfiguracja:** przełączanie stanu rootkita; dodawanie, usuwanie, odpytywanie lub czyszczenie chronionych ścieżek, procesów i adresów C2.
- **Manipulowanie procesami:** kończenie PID, usuwanie mapowania jego obrazu, wstrzykiwanie za pomocą `NtCreateThreadEx`, ukrywanie/przywracanie procesów lub modułów użytkownika oraz usuwanie ochrony PPL.
- **Manipulowanie jądrem:** odłączanie załadowanego sterownika, wyliczanie/wyłączanie/przywracanie callbacków powiadomień, ręczne mapowanie innego sterownika oraz zapis pod dowolny adres jądra.
- **Manipulowanie obiektami:** usuwanie/deszyfrowanie plików oraz tworzenie lub modyfikowanie wartości rejestru.

## Wyjątki dla zaufanych procesów

Przydatnym wzorcem projektowym jest IOCTL, który rejestruje PID wraz z flagą **zaufany**. To samo sprawdzenie zaufania jest następnie stosowane przez filtry plików, rejestru, procesów i wątków: niezaufane narzędzia otrzymują przefiltrowane wyniki wyliczania, ograniczone prawa do uchwytów lub `STATUS_ACCESS_DENIED`, podczas gdy implant nadal może aktualizować własne ukryte obiekty. Traktuj to jako granicę autoryzacji i sprawdź, jak wpisy są uwierzytelniane, synchronizowane i usuwane po zakończeniu procesu lub ponownym użyciu PID.<sup>[[1]](#references)</sup>

Rootkity mogą przechowywać politykę w wartościach `REG_MULTI_SZ` oraz kompilować listy plików, katalogów, kluczy rejestru, wartości rejestru, ignorowanych obrazów, chronionych obrazów i ukrytych obrazów w drzewach AVL. Podczas analizy śledź każdego czytelnika i zapisującego do tych współdzielonych drzew; łączy to konfigurację rejestru, IOCTL-e, callbacki i logikę filtrowania, nawet gdy nazwy funkcji zostały usunięte.<sup>[[1]](#references)</sup>

## Ukrywanie procesów i modułów za pomocą DKOM

### `EPROCESS.ActiveProcessLinks`

Offsety `ActiveProcessLinks` różnią się w zależności od builda Windows. Tolerancyjny względem wersji rootkit może testować znane kandydatury, a następnie skanować `EPROCESS` w poszukiwaniu spójnego `LIST_ENTRY`, którego sąsiednie elementy wskazują z powrotem na kandydata. Zachowuje wykryty offset, ukrywa proces, ponownie łącząc `Flink`/`Blink` jego sąsiadów, oraz zachowuje stan, aby później ponownie dołączyć wpis. Proces nadal działa, ale znika z enumeratorów przechodzących po aktywnej liście procesów.<sup>[[1]](#references)</sup>

To jest **DKOM**, a nie zakończenie procesu. Wykrywanie powinno porównywać wyniki oparte na listach z niezależnymi dowodami, takimi jak skanowanie puli/obiektów, własność wątków, tablice uchwytów, artefakty planisty oraz inspekcja pamięci jądra. Proces widoczny podczas skanowania, lecz nieobecny na kanonicznej liście, jest bardziej znaczący niż którykolwiek z tych widoków rozpatrywany osobno.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Równoważny prymityw ukrywania modułów wyszukuje docelowy wpis w `PsLoadedModuleList` i modyfikuje sąsiednie wskaźniki `Flink`/`Blink`. Sterownik pozostaje zmapowany i wykonywalny, ale zapytania o moduły oparte na liście go pomijają. Porównaj listę loadera z wykonywalnymi mapowaniami jądra, tagami puli, obiektami urządzeń/sterowników, kluczami usług, adresami callbacków oraz wskaźnikami dispatch wskazującymi poza obraz znajdujący się na liście.<sup>[[1]](#references)</sup>

## Ochrona i ukrywanie za pomocą callbacków

Rootkit może łączyć udokumentowane frameworki callbacków z DKOM i hookami:<sup>[[1]](#references)</sup>

- Handlery pre-operation `ObRegisterCallbacks` dla `PsProcessType` i `PsThreadType` usuwają prawa używane do kończenia procesu, dostępu do pamięci wirtualnej, duplikowania lub manipulowania wątkiem, gdy niezaufany caller otwiera chroniony obiekt docelowy. Zapisz altitude callbacku i określ moduł będący właścicielem każdego adresu callbacku.
- `PsSetCreateProcessNotifyRoutineEx` oraz `PsSetLoadImageNotifyRoutine` utrzymują stan chronionych/ignorowanych/ukrytych procesów, gdy pojawiają się procesy i obrazy; jednorazowe przejście po procesach może uzupełnić obiekty istniejące przed rejestracją.
- Minifiltr systemu plików odmawia dostępu do skonfigurowanych ścieżek. Nietypowa implementacja może utworzyć klucz `Instances`, dynamicznie wybrać altitude oraz zwiększać ją i ponawiać próbę, gdy `FltRegisterFilter` zgłosi kolizję.
- Procedura `CmRegisterCallbackEx` może ukrywać chronione nazwy przed wyliczaniem oraz odmawiać bezpośredniego otwierania, zmiany nazwy, ustawiania lub usuwania operacji, jednocześnie wyłączając z tego zarejestrowane zaufane procesy.

Skoreluj rejestracje `ObRegisterCallbacks`, altitude callbacków rejestru, dane wyjściowe `fltmc filters`, klucze usług `Instances` oraz adresy callbacków. Jeśli zwykłe narzędzia są filtrowane, sprawdź te struktury z obrazu pamięci offline lub z użyciem innej zaufanej warstwy pozyskiwania danych.<sup>[[1]](#references)</sup>

## Filtrowanie wyników Nsiproxy

Ukrywanie sieci może być wymierzone w `\Driver\Nsiproxy`: uzyskaj obiekt sterownika za pomocą `ObReferenceObjectByName`, zapisz wskaźnik handlera, zastąp go wrapperem i usuń zwrócone rekordy IPv4 pasujące do zarządzanej przez IOCTL listy C2, zanim otrzyma je tryb użytkownika. Aplikacje korzystające z przefiltrowanych danych NSI mogą przestać wyświetlać połączenie, mimo że ruch nadal istnieje.<sup>[[1]](#references)</sup>

Porównaj widoki połączeń hosta z przechwytywaniem pakietów, telemetrią WFP/ETW oraz obiektami sieciowymi pamięci jądra. Sprawdź również wskaźniki dispatch/handler `Nsiproxy` i potwierdź, że każdy z nich rozwiązuje się wewnątrz oczekiwanego podpisanego modułu; wskaźnik do niezlistowanego mapowania może połączyć filtrowanie sieciowe z DKOM `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Lista kontrolna dochodzenia

Najsilniejszym sygnałem jest niezgodność między warstwami, a nie pojedyncza nazwa pliku lub hash. Skoreluj:<sup>[[1]](#references)</sup>

1. Utworzenie usługi jądra oraz podpisany sterownik, którego wiek certyfikatu, wydawca lub ścieżka są niespójne z zainstalowanym produktem.
2. Utworzenie urządzenia, linki DOS i ruch IOCTL, w tym niezgodne nazwy urządzeń w trybie użytkownika i w jądrze.
3. Żądanie rejestracji PID, po którym inne procesy nie mogą otwierać, wyliczać, modyfikować lub usuwać tych samych obiektów.
4. Callbacki obiektów/rejestru/procesów/obrazów, instancje minifiltrów oraz hooki, których adresy nie należą do normalnie wyliczanego sterownika.
5. Różnice między inwentarzami procesów, modułów, callbacków i sieci opartymi na listach a inwentarzami opartymi na skanowaniu.

## References

- [1] [Kaspersky Securelist - HoneyMyte wzbogaca CoolClient o podpisany rootkit jądra Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
