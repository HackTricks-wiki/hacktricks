# Artefakty Windows

{{#include ../../../banners/hacktricks-training.md}}

## Ogólne artefakty Windows

### Powiadomienia Windows 10

Baza danych powiadomień użytkownika znajduje się w `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (na przykład `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). We wczesnych wydaniach Windows 10 używano pliku `appdb.dat`; w aktualizacji Anniversary Update (1607) wprowadzono `wpndatabase.db`. Baza SQLite zawiera tabelę `Notification` z ładunkami powiadomień i polami czasu, choć okres przechowywania i dostępne dane różnią się w zależności od wydania i zasad czyszczenia.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline to funkcja historii aktywności, która może zawierać rekordy dotyczące obsługiwanych aplikacji, dokumentów i innych działań użytkownika; zakres danych zależy od aplikacji i wersji Windows.<sup>[[4]](#references)</sup>

Baza danych znajduje się w `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Można ją otworzyć za pomocą SQLite lub przeanalizować przy użyciu [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), a wyniki przeglądać w [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### Migawki Windows Recall (komputery Copilot+)

Recall jest dostępny opcjonalnie na obsługiwanych komputerach Copilot+ z Windows 11. Obecne kompilacje szyfrują migawki i ich indeks za pomocą kluczy powiązanych z Windows Hello i enklawą VBS. Nie należy traktować kopii magazynu wykonanej w trybie offline jak bazy SQLite w postaci jawnej; wersja zapoznawcza z 2024 r. i wydana wersja mają różne właściwości dostępu.<sup>[[77]](#references)</sup>

W przypadku **aktywnej, włączonej sesji Recall** proces renderowania `AIXHost.exe` działający w kontekście tego samego użytkownika stanowi odrębną powierzchnię dostępu. Proof of concept TotalRecall Reloaded wstrzykuje bibliotekę DLL do tego procesu i wywołuje interfejsy COM Recall. Wyodrębnienie pełnej historii nadal wymaga uwierzytelnienia użytkownika za pomocą Windows Hello; nie jest to odszyfrowywanie danych w trybie offline ani obejście Hello. Badacz udokumentował działanie narzędzia w Windows 11 ARM64, dlatego przed użyciem należy sprawdzić jego zgodność z docelową kompilacją.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` używa `GetRecentCaptureThumbnail`, aby zażądać dużej wersji najnowszego zrzutu bez Hello. Po autoryzacji `--wait` może wyodrębnić zrzuty ekranu, tekst OCR i metadane poszczególnych zrzutów, w tym kontekst aplikacji i okna. Dane wyjściowe są zapisywane w katalogu `extraction_*` oznaczonym datą i godziną. Są to ustalenia zależne od kompilacji, uzyskane na podstawie proof of concept, a nie gwarancja, że Recall jest włączony lub że zarejestrowano każdy ekran.<sup>[[78]](#references)</sup>

### ADS (Alternatywne strumienie danych)

Pliki pobrane spoza lokalnej granicy zaufania mogą zawierać **alternatywny strumień danych `Zone.Identifier`**, który przechowuje informacje o strefie i może zawierać metadane źródła, takie jak URL. Jego obecność i pola zależą od programu, który go utworzył, oraz zasad systemowych.<sup>[[6]](#references)</sup>

## **Kopie zapasowe plików**

### Kosz

W systemie Vista i nowszych wersjach **Kosz** znajduje się w folderze **`$Recycle.bin`** w katalogu głównym dysku (na przykład `C:\$Recycle.bin`).\
Po usunięciu pliku w tym folderze tworzone są 2 konkretne pliki:

- `$I{id}`: Informacje o pliku, w tym czas usunięcia i pierwotna ścieżka
- `$R{id}`: Zawartość pliku

![Kopie zapasowe plików - Kosz: $R{id}: Zawartość pliku](<../../../images/image (1029).png>)

Mając te pliki, możesz użyć [**Rifiuti2**](https://github.com/abelcheung/rifiuti2), aby wyodrębnić pierwotną ścieżkę i czas usunięcia (użyj wersji odpowiedniej dla docelowego wydania systemu Windows).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Kopie zapasowe plików - Kosz: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Kopie woluminów w tle

Usługa Volume Shadow Copy (VSS) może tworzyć kopie woluminów z określonego punktu w czasie, gdy pliki są używane; kopia w tle nie zastępuje obrazu forensic.<sup>[[8]](#references)</sup>

Metadane kopii są zwykle powiązane z katalogiem `\System Volume Information` w katalogu głównym woluminu, a identyfikatory różnią się w zależności od systemu:

![Kosz - Kopie woluminów w tle: Te kopie zapasowe są zwykle przechowywane w katalogu System Volume Information w katalogu głównym systemu plików, a ich nazwy składają się z identyfikatorów UID widocznych na...](<../../../images/image (94).png>)

Po zamontowaniu obrazu za pomocą odpowiedniego narzędzia forensic [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) może wyświetlić dostępne migawki VSS oraz umożliwić przeglądanie lub kopiowanie z nich plików.<sup>[[9]](#references)</sup>

![Kosz - Kopie woluminów w tle: Po zamontowaniu obrazu forensic za pomocą ArsenalImageMounter można użyć narzędzia ShadowCopyView do sprawdzenia kopii w tle, a nawet wyodrębnienia plików...](<../../../images/image (576).png>)

Konfiguracja modułu zapisującego rejestru VSS obejmuje `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, gdzie można określić pliki i klucze wykluczone z kopii zapasowej:<sup>[[10]](#references)[[11]](#references)</sup>

![Kosz - Kopie woluminów w tle: Wpis rejestru HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore zawiera pliki i klucze, których nie należy uwzględniać w kopii zapasowej](<../../../images/image (254).png>)

Klucz `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` zawiera również konfigurację usługi VSS.<sup>[[8]](#references)</sup>

### Pliki automatycznie zapisane przez Office

Lokalizacje AutoRecover różnią się w zależności od aplikacji Office, wersji i konfiguracji. W przypadku Word Microsoft podaje `%APPDATA%\Microsoft\Word` jako domyślną lokalizację; sprawdź ustawienia aplikacji, aby ustalić aktywną ścieżkę.<sup>[[12]](#references)</sup>

## Elementy powłoki

Element powłoki zawiera informacje o tym, jak uzyskać dostęp do innego pliku.

### Ostatnio używane dokumenty (LNK)

System Windows często tworzy skróty do ostatnio używanych elementów, gdy użytkownik otwiera element lub uzyskuje do niego dostęp w inny sposób:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Dostęp do folderu może również powodować utworzenie skrótów do tego folderu i powiązanych folderów nadrzędnych.

Pliki skrótów mogą zawierać typ elementu docelowego, jego czasy MAC, informacje o woluminie i ścieżkę docelową. Te metadane mogą pomóc zidentyfikować usunięty element docelowy, ale sam artefakt nie dowodzi, że konkretny użytkownik otworzył ten element.<sup>[[13]](#references)[[14]](#references)</sup>

Znaczniki czasu samego pliku LNK w systemie plików różnią się od osadzonych w nim znaczników czasu elementu docelowego. Nie należy uznawać utworzenia skrótu za pierwsze użycie ani jego modyfikacji za ostatnie użycie bez potwierdzenia w innych artefaktach; format przechowuje znaczniki czasu elementu docelowego oddzielnie od znaczników czasu pliku skrótu.<sup>[[13]](#references)[[14]](#references)</sup>

Link do [**LinkParser**](http://4discovery.com/our-tools/) pozostawiono jako opcję historyczną, ale podczas weryfikacji dokumentacja była niedostępna. Udokumentowany parser wiersza poleceń to [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Te narzędzia zwykle udostępniają dwa zestawy znaczników czasu:

- **Znaczniki czasu elementu docelowego:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Znaczniki czasu pliku skrótu:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Pierwszy zestaw dotyczy elementu docelowego, a drugi samego pliku LNK. Interpretuj oba zestawy z uwzględnieniem dokumentacji parsera i kontekstu systemu plików.<sup>[[14]](#references)[[15]](#references)</sup>

Te same informacje można uzyskać, uruchamiając narzędzie wiersza poleceń systemu Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

W tym przypadku informacje zostaną zapisane w pliku CSV.

### Jumplists

Jump Lists to listy ostatnich lub związanych z zadaniami elementów dla poszczególnych aplikacji; mogą być tworzone automatycznie lub niestandardowo.<sup>[[13]](#references)</sup>

Automatyczne Jump Lists są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` i używają nazw takich jak `{id}.automaticDestinations-ms`, gdzie identyfikator wskazuje aplikację.

Niestandardowe Jump Lists są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; aplikacja określa, które wpisy zadań lub elementów tworzy.

Czasy utworzenia i modyfikacji systemu plików dotyczą pliku Jump List, a nie automatycznie pierwszego i ostatniego dostępu do każdego z wymienionych w nim elementów docelowych. Zestawiaj sparsowane wpisy ze znacznikami czasu pliku i innymi artefaktami.<sup>[[13]](#references)</sup>

Możesz przejrzeć Jump Lists za pomocą [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Ostatnie dokumenty (LNK) - Jumplists: Możesz przejrzeć jumplists za pomocą JumplistExplorer](<../../../images/image (168).png>)

(_Zwróć uwagę, że znaczniki czasu podane przez JumplistExplorer dotyczą samego pliku jumplist_)

### Shellbags

[**Kliknij ten link, aby dowiedzieć się, czym są shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Użycie urządzeń USB w systemie Windows

Użycie USB można czasem potwierdzić za pomocą artefaktów tworzonych podczas uzyskiwania dostępu do plików na nośnikach wymiennych, w tym:

- Folder Windows Recent
- Folder Microsoft Office Recent
- Jumplists

Narzędzia takie jak [**USBDetective**](https://usbdetective.com) korelują te artefakty z zapisami urządzeń USB, ale dostępność artefaktów zależy od wersji Windows i aplikacji.<sup>[[18]](#references)</sup>

W testach opisanych dla przepływów MTP w Windows XP i Windows 7 niektóre pliki LNK wskazywały na folder `WPDNSE` zamiast na oryginalną ścieżkę.<sup>[[16]](#references)</sup>

![Shellbags - Użycie urządzeń USB w systemie Windows: Zwróć uwagę, że niektóre pliki LNK zamiast wskazywać oryginalną ścieżkę, wskazują folder WPDNSE](<../../../images/image (218).png>)

W badaniu zaobserwowano kopie w `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; w testach tymczasowa zawartość nie przetrwała ponownego uruchomienia, a identyfikator GUID można było skorelować z danymi shellbag. Traktuj to jako zachowanie zależne od systemu operacyjnego, urządzenia i aplikacji, a nie jako regułę uniwersalną.<sup>[[16]](#references)</sup>

### Informacje z rejestru

[Sprawdź tę stronę, aby dowiedzieć się](interesting-windows-registry-keys.md#usb-information), które klucze rejestru zawierają interesujące informacje o podłączonych urządzeniach USB.

### setupapi

W systemie Vista i nowszych sprawdź `C:\Windows\inf\setupapi.dev.log` pod kątem aktywności związanej z instalacją urządzeń. Nagłówki sekcji zawierają znaczniki czasu `Section start`; dokumentują one przetwarzanie konfiguracji i należy je korelować z innymi dowodami połączenia, zamiast traktować jako dokładny czas fizycznego podłączenia urządzenia.<sup>[[17]](#references)</sup>

![Informacje z rejestru - setupapi: Sprawdź plik C: Windows inf setupapi.dev.log, aby uzyskać znaczniki czasu połączenia USB (wyszukaj Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) można użyć do uzyskania informacji o urządzeniach USB, które były podłączone do obrazu.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective można użyć do uzyskania informacji o urządzeniach USB, które były podłączone do obrazu](<../../../images/image (452).png>)

### Czyszczenie Plug and Play

Zaplanowane zadanie o nazwie `Plug and Play Cleanup` usuwa nieaktualne wersje sterowników. Opisana przez Adama Harrisona definicja zadania w Windows 10 obejmuje również sterowniki nieaktywne przez 30 dni, więc ślady sterowników urządzeń wymiennych mogą zostać usunięte; przed uogólnieniem tego zachowania sprawdź lokalną definicję zadania i kompilację Windows.<sup>[[1]](#references)</sup>

Zadanie znajduje się w następującej ścieżce: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Definicja XML zaplanowanego zadania Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Kluczowe składniki i ustawienia zadania:**

- **pnpclean.dll**: Ta biblioteka DLL odpowiada za właściwy proces czyszczenia.
- **UseUnifiedSchedulingEngine**: Ustawiono na `TRUE`, co oznacza użycie ogólnego aparatu planowania zadań.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Nakazuje Harmonogramowi zadań uruchamiać zadanie czyszczenia co miesiąc podczas regularnej konserwacji automatycznej.
  - **Deadline ('P2M')**: Nakazuje Harmonogramowi zadań uruchomić zadanie podczas awaryjnej konserwacji automatycznej, jeśli zadanie nie powiedzie się przez dwa kolejne miesiące.

Ta konfiguracja planuje regularną konserwację i ponowne próby po kolejnych niepowodzeniach; dokładny plik XML i działanie zależą od wersji systemu.<sup>[[1]](#references)</sup>

**Więcej informacji:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-maile

E-maile zawierają **2 interesujące części: nagłówki i treść** wiadomości. W **nagłówkach** można znaleźć takie informacje jak:

- **Kto** wysłał e-maile (adres e-mail, IP, serwery pocztowe, przez które przekazano wiadomość)
- **Kiedy** wysłano e-mail

Nagłówki `References` i `In-Reply-To` mogą również zawierać identyfikatory wiadomości używane do powiązania odpowiedzi z konwersacją.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - E-maile: Kiedy wysłano e-mail](<../../../images/image (593).png>)

### Aplikacja Poczta systemu Windows

Ta aplikacja zapisuje treść e-maili w pomocniczych plikach tekstowych lub HTML w ścieżkach takich jak `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; dokładny układ ponumerowanych folderów i plików może się różnić w zależności od artefaktu.<sup>[[75]](#references)</sup>

**Metadane** e-maili i **kontakty** można znaleźć w **bazie danych ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` używa formatu Extensible Storage Engine (ESE). Pracuj na kopii i użyj parsera ESE, takiego jak [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); jeśli narzędzie wymaga rozszerzenia `.edb`, zmień nazwę wyłącznie kopii i sprawdź schemat tabel przed poleganiem na tabeli `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Podczas sprawdzania właściwości MAPI programu Outlook istotne właściwości kanoniczne obejmują:

- `PidTagClientSubmitTime`: czas UTC, w którym klient wysłał wiadomość.
- `PidTagConversationIndex`: względne położenie wiadomości w wątku konwersacji.
- `PidTagEntryId`: identyfikator obiektu wiadomości.
- `PidTagMessageFlags`: flagi stanu, takie jak wysłana, przeczytana, nieprzeczytana lub zawierająca załączniki.
- `PidTagLastVerbExecuted`: ostatnia zarejestrowana operacja dotycząca wiadomości, taka jak otwarcie, odpowiedź lub przekazanie dalej.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Lokalizacje plików danych programu Outlook różnią się w zależności od wersji i typu konta. Microsoft podaje następujące typowe lokalizacje plików PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Ścieżka rejestru `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` może wskazywać profil Outlooka i powiązaną konfigurację plików danych.

Pliki PST mogą zawierać wiadomości, kontakty, dane kalendarza i inne elementy Outlooka. Możesz przejrzeć kopię za pomocą [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Aplikacja Poczta systemu Windows - Microsoft Outlook: Możesz otworzyć plik PST za pomocą narzędzia Kernel PST Viewer](<../../../images/image (498).png>)

### Pliki OST programu Microsoft Outlook

**Plik OST** to lokalna pamięć podręczna dla kont Exchange lub Microsoft 365; tryb buforowanej wymiany nie dotyczy kont POP ani IMAP. Okres przechowywania danych offline można skonfigurować; często domyślnie wynosi 12 miesięcy, natomiast limity rozmiaru PST/OST są odrębnymi, konfigurowalnymi ustawieniami. Do wyświetlenia pliku OST można użyć [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Odzyskiwanie załączników

Utracone załączniki można czasem odzyskać z następujących lokalizacji:

- W starszych konfiguracjach Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- W nowszych konfiguracjach Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Pliki MBOX Thunderbird

**Thunderbird** przechowuje dane profilu w `%APPDATA%\Thunderbird\Profiles`; foldery poczty często używają plików mbox bez rozszerzenia w katalogach `Mail` lub `ImapMail` powiązanych z kontem.<sup>[[29]](#references)[[30]](#references)</sup>

### Miniatury obrazów

- **Windows XP**: Podglądy miniatur były zwykle przechowywane w plikach `thumbs.db` w poszczególnych folderach.
- **Foldery sieciowe**: Plik `thumbs.db` może być nadal tworzony dla folderu UNC, gdy włączone jest odpowiednie działanie miniatur; nie zakładaj, że tworzy go każda wersja lub konfiguracja zasad systemu Windows.
- **Windows Vista i nowsze**: Systemowa pamięć podręczna miniatur znajduje się w `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` i zawiera pliki takie jak **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) może analizować starsze pliki `Thumbs.db`, a [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) może analizować nowoczesne bazy danych pamięci podręcznej miniatur.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Informacje z rejestru systemu Windows

Rejestr systemu Windows, w którym przechowywane są dane konfiguracji systemu i użytkowników, znajduje się w plikach hive w następujących lokalizacjach:

- `%WINDIR%\System32\Config` — pliki hive komputera będące podstawą różnych podkluczy `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` — plik hive `HKEY_CURRENT_USER` użytkownika.
- Niektóre starsze instalacje Windows zawierają kopie w `%WINDIR%\System32\Config\RegBack\`; system Windows 10 w wersji 1803 i nowszych nie zapełnia tego katalogu automatycznie, chyba że włączono okresowe tworzenie kopii zapasowych.<sup>[[34]](#references)[[35]](#references)</sup>
- Dane powłoki i rejestracji klas dla poszczególnych użytkowników są również zwykle przechowywane w `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` we współczesnym systemie Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Narzędzia

Niektóre narzędzia przydają się do analizy plików hive rejestru; przed poleganiem na wynikach sprawdź, jakie formaty plików hive i wersje obsługuje dane narzędzie:

- **Edytor rejestru**: Jest zainstalowany w systemie Windows. To graficzny interfejs do przeglądania rejestru Windows bieżącej sesji.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Umożliwia wczytanie pliku rejestru i przeglądanie go za pomocą interfejsu graficznego. Zawiera również zakładki wyróżniające klucze z interesującymi informacjami.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Również oferuje graficzny interfejs do przeglądania wczytanego rejestru oraz wtyczki wyróżniające interesujące informacje.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Kolejna aplikacja z interfejsem graficznym, która potrafi wyodrębniać informacje z wczytanego pliku hive rejestru.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Odzyskiwanie usuniętych elementów

Usunięte komórki hive mogą pozostać w pliku do czasu ponownego wykorzystania zajmowanego przez nie miejsca, ale odzyskiwanie zależy od stanu pliku hive i parsera; odzyskane usunięte klucze traktuj jako dowody wymagające weryfikacji, a nie jako gwarantowane zapisy.

### Czas ostatniego zapisu

Klucze rejestru zawierają znacznik czasu ostatniego zapisu; system Windows udostępnia go dla klucza lub dowolnego jego wpisu wartości, więc wartość nie musi mieć własnego, niezależnego znacznika czasu modyfikacji.<sup>[[69]](#references)</sup>

### SAM

Plik hive **SAM** zawiera dane lokalnych kont użytkowników i grup, w tym skróty haseł chronione za pomocą materiału boot-key systemu.<sup>[[38]](#references)[[39]](#references)</sup>

W `SAM\Domains\Account\Users` można uzyskać identyfikatory kont oraz niektóre pola dotyczące logowania i zasad. Do wyodrębnienia skrótów offline potrzebny jest również plik hive `SYSTEM`, aby odzyskać odpowiedni materiał boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

### Interesujące wpisy w rejestrze systemu Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Uruchamiane programy

### Podstawowe procesy systemu Windows

Istniejący [wpis o typowych procesach Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) pozostaje dodatkowym materiałem do lektury; twierdzenia dotyczące zachowania procesów weryfikuj na podstawie aktualnej dokumentacji Windows i lokalnych dowodów.<sup>[[2]](#references)</sup>

### Ostatnie aplikacje Windows

W wersjach Windows 10, które udostępniają ten artefakt, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` zawiera podklucze dla poszczególnych aplikacji z polami takimi jak czas ostatniego użycia i liczba uruchomień; artefakt usunięto w późniejszych wydaniach, dlatego sprawdź kompilację systemu docelowego.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

W systemach udostępniających Background Activity Moderator sprawdź ścieżkę `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` lub nowszą `...\bam\State\UserSettings\{SID}`. Wartości są przypisane do SID użytkownika i mogą zawierać śledzone ścieżki plików wykonywalnych oraz dane czasu wykonania w formacie zbliżonym do FILETIME; artefakt zależy od wersji i należy go potwierdzać innymi dowodami.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch buforuje zasoby i metadane uruchamiania, aby programy mogły startować szybciej.

Pliki Prefetch są przechowywane jako pliki `.pf` w `C:\Windows\Prefetch`; format, czas przechowywania i limity liczby plików zależą od wersji Windows. Microsoft dokumentuje przechowywanie ośmiu ostatnich czasów uruchomienia i maksymalnie 1024 plików w systemie Windows 8 i nowszych, dlatego nie należy uogólniać starszych opisów stałych limitów.<sup>[[13]](#references)</sup>

Nazwa pliku ma zwykle postać `{program_name}-{hash}.pf`, gdzie skrót jest wyliczany na podstawie kontekstu uruchomienia, takiego jak ścieżka i argumenty; system Windows 10 i nowsze mogą kompresować plik. Obecność pliku jest przydatnym dowodem uruchomienia, ale sama w sobie nie dowodzi, że program uruchomił użytkownik, dlatego należy ją korelować z innymi artefaktami.<sup>[[13]](#references)</sup>

Do analizy tych plików można użyć [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), które obsługuje analizę katalogów, eksport do CSV/HTML oraz dekompresję obsługiwanych plików Prefetch z Windows 10.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** uzupełnia Prefetch, wykorzystując historyczne wzorce użycia w celu usprawnienia ładowania. W systemach, które je tworzą, pliki baz danych są zwykle przechowywane w lokalizacji `C:\Windows\Prefetch\Ag*.db`; ich format i występowanie zależą od wersji systemu.<sup>[[41]](#references)</sup>

Te bazy danych mogą zawierać nazwy aplikacji, liczbę użyć, dostępne pliki lub woluminy, ścieżki i zakresy czasu, ale nie należy traktować ich jako dokładnego dziennika wykonania.<sup>[[41]](#references)</sup>

Istniejący link do [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) pozostaje potencjalnym parserem; przed użyciem sprawdź jego aktualną dostępność i obsługiwane formaty wyjściowe w dokumentacji narzędzia.

### SRUM

**System Resource Usage Monitor** (SRUM) rejestruje wykorzystanie zasobów przez aplikacje i użytkowników. Został wprowadzony w Windows 8 i przechowuje dane w bazie ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Dostarcza następujących informacji:

- AppID i Path
- Użytkownik/SID powiązany z rekordem
- Wysłane bajty
- Odebrane bajty
- Interfejs sieciowy
- Czas trwania połączenia
- Czas działania procesu

Częstotliwość zbierania danych i okres ich przechowywania zależą od implementacji; nie należy zakładać, że każdy rekord odpowiada dokładnemu 60-minutowemu przedziałowi działania.<sup>[[13]](#references)</sup>

Dane można wyodrębnić i przejrzeć za pomocą [**srum_dump**](https://github.com/MarkBaggett/srum-dump), korzystając z opcji opisanych w dokumentacji aktualnej wersji narzędzia.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**, znany również jako **ShimCache**, jest częścią infrastruktury zgodności aplikacji systemu Windows i zapisuje metadane plików na potrzeby podejmowania decyzji dotyczących zgodności. Ścieżka do gałęzi rejestru, format rekordów, zachowywana pojemność i pola różnią się w zależności od wersji systemu Windows; w nowoczesnych wersjach sam ShimCache nie może dowieść, że użytkownik uruchomił plik. Przeanalizuj odpowiednią gałąź rejestru `SYSTEM` za pomocą narzędzia [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) i potwierdź jego wyniki za pomocą artefaktów wykonania.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Do analizy zapisanych informacji zaleca się użycie narzędzia AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Plik **Amcache.hve** to gałąź rejestru zawierająca spis aplikacji i plików zaobserwowanych przez system Windows. Zazwyczaj znajduje się w lokalizacji `C:\Windows\AppCompat\Programs\Amcache.hve`.

Może zawierać powiązane i niepowiązane wpisy plików, ścieżki oraz wartości SHA1, ale jego obecność jest dowodem inwentaryzacyjnym i sama w sobie nie dowodzi, że proces został uruchomiony.<sup>[[13]](#references)[[44]](#references)</sup>

Do wyodrębnienia i analizy pliku **Amcache.hve** użyj narzędzia [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). To polecenie analizuje gałąź rejestru i zapisuje dane wyjściowe w formacie CSV.<sup>[[44]](#references)</sup>

Na przykład:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Spośród wygenerowanych plików CSV `Amcache_Unassociated file entries` może być przydatny podczas badania plików niepowiązanych z rozpoznanym programem.<sup>[[44]](#references)</sup>

### RecentFileCache

W systemach Windows 7 plik `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` może zawierać informacje o niedawno zaobserwowanych plikach binarnych; dostępność i znaczenie tych danych zależą od wersji.

Do analizy pliku można użyć [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser).<sup>[[45]](#references)</sup>

### Zaplanowane zadania

Ślady zaplanowanych zadań mogą znajdować się w `C:\Windows\System32\Tasks` w przypadku współczesnych zadań oraz w `C:\Windows\Tasks` w postaci plików `.job` w przypadku starszych zadań; sprawdź format definicji zadań odpowiedni dla danego systemu operacyjnego.<sup>[[73]](#references)[[74]](#references)</sup>

### Usługi

Baza danych Service Control Manager znajduje się w `SYSTEM\CurrentControlSet\Services` (w przypadku offline'owego ula SYSTEM sprawdź odpowiadający mu klucz control-set); zawiera konfigurację usług i sterowników, np. ścieżki plików wykonywalnych i typy uruchamiania.<sup>[[72]](#references)</sup>

### **Windows Store**

Zainstalowane aplikacje Windows Store mogą być reprezentowane w `\ProgramData\Microsoft\Windows\AppRepository\`, w tym w bazie danych **`StateRepository-Machine.srd`**. Schemat i ścieżki różnią się w zależności od wydania Windows.<sup>[[71]](#references)</sup>

Baza danych może zawierać identyfikatory aplikacji, numery pakietów i wyświetlane nazwy. Luki w identyfikatorach same w sobie nie dowodzą, że aplikacja została odinstalowana; zweryfikuj to na podstawie stanu pakietów i rejestru.

Rejestracje pakietów mogą również występować w `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft dokumentuje zależny od wersji podklucz `Deprovisioned` dla usuniętych aplikacji aprowizowanych; nie zakładaj, że podklucz `Deleted` istnieje w każdej kompilacji.<sup>[[70]](#references)</sup>

## Zdarzenia Windows

W zależności od dostawcy zdarzenia Windows mogą zawierać:

- Informacje o tym, co się wydarzyło
- Sygnaturę czasową `TimeCreated`, którą należy interpretować z uwzględnieniem schematu zdarzenia i kontekstu czasu na hoście
- Użytkowników, których dotyczy zdarzenie
- Hosty, których dotyczy zdarzenie (nazwę hosta, adres IP)
- Dostępne zasoby (pliki, foldery, drukarki lub usługi).<sup>[[49]](#references)</sup>

Przed Windows Vista dzienniki zdarzeń na ogół używały starszego formatu binarnego i znajdowały się w `C:\Windows\System32\config`; w systemach Vista i nowszych używany jest format Windows Event Log, zwykle w `C:\Windows\System32\winevt\Logs`, a pliki `.evtx` zawierają dane zdarzeń renderowane jako XML.<sup>[[46]](#references)[[47]](#references)</sup>

Rejestr SYSTEM przechowuje konfigurację kanałów w **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, w tym skonfigurowaną ścieżkę pliku i ustawienia przechowywania.<sup>[[47]](#references)</sup>

Można je przeglądać za pomocą Windows Event Viewer (**`eventvwr.msc`**) lub narzędzi takich jak [**Event Log Explorer**](https://eventlogxp.com) i [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Interpretacja rejestrowania zdarzeń zabezpieczeń Windows

W systemie Vista i nowszych kanał Security jest zwykle przechowywany w `C:\Windows\System32\winevt\Logs\Security.evtx`. Maksymalny rozmiar i zasady przechowywania można konfigurować; przy logowaniu cyklicznym starsze rekordy mogą zostać nadpisane po osiągnięciu limitu pliku. Kanał może rejestrować zdarzenia uwierzytelniania, wylogowania, uprawnień, zasad inspekcji i dostępu do obiektów, jeśli włączono odpowiednie inspekcje.<sup>[[46]](#references)[[47]](#references)</sup>

### Kluczowe identyfikatory zdarzeń dotyczące uwierzytelniania użytkowników:

- **Event ID 4624**: Pomyślne logowanie do konta.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Nieudane logowanie do konta.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Sesja logowania została zakończona.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Użytkownik zainicjował wylogowanie.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Do nowego logowania przypisano specjalne uprawnienia; jest to częste w przypadku kont systemowych i administratorów, więc samo w sobie nie dowodzi złośliwej aktywności.<sup>[[54]](#references)</sup>

#### Typy logowania często rejestrowane w zdarzeniach 4624, 4625, 4634 i 4647:

- **Interactive (2)**: Interaktywne logowanie lokalne.
- **Network (3)**: Dostęp do udostępnionego zasobu.
- **Batch (4)**: Logowanie procesu wsadowego.
- **Service (5)**: Logowanie usługi.
- **Unlock (7)**: Odblokowanie stacji roboczej.
- **NetworkCleartext (8)**: Logowanie sieciowe, podczas którego poświadczenia są przekazywane w postaci jawnego tekstu do pakietu uwierzytelniania.
- **NewCredentials (9)**: Logowanie z użyciem podanych alternatywnych poświadczeń dla połączeń wychodzących.
- **RemoteInteractive (10)**: Logowanie przez Remote Desktop lub Terminal Services.
- **CachedInteractive (11)**: Logowanie interaktywne z użyciem buforowanych poświadczeń domenowych.
- **CachedRemoteInteractive (12)**: Logowanie zdalne interaktywne z użyciem buforowanych poświadczeń.
- **CachedUnlock (13)**: Odblokowanie z użyciem buforowanych poświadczeń.<sup>[[50]](#references)[[51]](#references)</sup>

#### Kody Status i Sub Status dla EventID 4625:

- **0xC0000064**: Taki użytkownik nie istnieje.
- **0xC000006A**: Prawidłowa nazwa użytkownika, ale nieprawidłowe hasło.
- **0xC0000234**: Konto zablokowane.
- **0xC0000072**: Konto wyłączone.
- **0xC000006F**: Logowanie poza dozwolonymi godzinami.
- **0xC0000070**: Naruszenie ograniczeń stacji roboczej.
- **0xC0000193**: Konto wygasło.
- **0xC0000071**: Hasło wygasło.
- **0xC0000133**: Różnica czasu między klientem a serwerem jest zbyt duża.
- **0xC0000224**: Konto musi zmienić hasło.
- **0xC0000225**: `STATUS_NOT_FOUND`; sam kod nie wskazuje na błąd systemu ani atak.
- **0xC000015B**: Żądany typ logowania nie został przyznany temu kontu.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Zmiana czasu**: Zmieniono czas systemowy. Wiele zdarzeń odzwierciedla rutynową korektę czasu przez usługę czasu, dlatego przed uznaniem tego za manipulację sprawdź, kto ją wykonał i jakie było źródło czasu.<sup>[[56]](#references)</sup>

#### Identyfikatory zdarzeń 12, 13, 1074, 6005, 6006, 6008 i 6009:

- **Kontekst zasilania i usług**: Zdarzenie 12 rejestruje uruchomienie systemu operacyjnego, 13 — jego zamknięcie, 1074 — zaplanowane zamknięcie lub ponowne uruchomienie, 6008 wskazuje nieoczekiwane zamknięcie, a 6009 rejestruje wersję Windows podczas uruchamiania. Zdarzenia 6005 i 6006 wskazują odpowiednio uruchomienie i zatrzymanie usługi Event Log; same w sobie nie dowodzą uruchomienia ani zamknięcia systemu operacyjnego.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Usunięcie dziennika**: Zdarzenie 1102 rejestruje wyczyszczenie dziennika inspekcji Security; zbadaj, kto wykonał tę czynność i jakie zdarzenia jej towarzyszyły, zamiast zakładać intencje wyłącznie na podstawie tego zdarzenia.<sup>[[62]](#references)</sup>

#### Identyfikatory zdarzeń dotyczących śledzenia urządzeń USB:

- **20001 / 20003**: Zdarzenia instalacji urządzeń `UserPnp`, które mogą pomóc ustalić pierwsze użycie lub aktywność instalacyjną.
- **10000 / 10100**: Zdarzenia `DriverFrameworks-UserMode`, które mogą towarzyszyć aktywności urządzenia.
- **Event ID 112**: Aktywność `DeviceSetupManager/Admin`, która może dostarczyć znaczników czasu związanych z podłączeniem urządzenia.
- Dostawca, kanał i znaczenie zdarzeń różnią się w zależności od wersji Windows; przed przypisaniem im znaczenia sprawdź nazwę dostawcy i zawartość zdarzenia.<sup>[[59]](#references)</sup>

Praktyczne przykłady typów logowania i powiązanych z nimi materiałów uwierzytelniających znajdziesz w [szczegółowym poradniku Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Szczegóły zdarzenia, w tym typ logowania, status, podstatus, adres źródłowy i pola procesu, dostarczają kontekstu dla Event ID 4625; kod statusu ani powtarzający się wzorzec niepowodzeń nie są rozstrzygającym dowodem, lecz wskazówką do dalszego badania.<sup>[[51]](#references)[[55]](#references)</sup>

### Odzyskiwanie zdarzeń Windows

Ponieważ dzienniki zdarzeń są często zapisywane cyklicznie, rekordów nadpisanych przez rejestrator może nie dać się odzyskać. Przed interakcją z działającym systemem zachowaj obraz kryminalistyczny lub kopię roboczą; używaj zweryfikowanego parsera lub narzędzia do odzyskiwania, takiego jak **Bulk_extractor**, dopiero po upewnieniu się, że dana wersja narzędzia obsługuje docelowe dane `.evtx`; nie odłączaj działającego systemu wyłącznie po to, by spróbować odzyskać zdarzenia.<sup>[[46]](#references)</sup>

### Identyfikowanie typowych ataków na podstawie zdarzeń Windows

Praktyczne zestawienie identyfikatorów zdarzeń znajdziesz w istniejącym odnośniku [Red Team Recipe](https://redteamrecipe.com/event-codes/); zweryfikuj przykłady na podstawie powyższej dokumentacji dostawcy.

#### Ataki Brute Force

Powiąż powtarzające się niepowodzenia Event ID 4625 z późniejszym sukcesem 4624, typem logowania, statusem, źródłem i kontekstem konta; taka sekwencja jest wskazówką do zbadania, a nie dowodem ataku.<sup>[[50]](#references)[[51]](#references)</sup>

#### Zmiana czasu

Event ID 4616 rejestruje zmiany czasu systemowego, które mogą utrudnić analizę osi czasu; porównaj te dane z informacjami o usłudze czasu i dowodami z hosta.<sup>[[56]](#references)</sup>

#### Śledzenie urządzeń USB

Identyfikatory zdarzeń USB zależą od dostawcy; skoreluj zdarzenia `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 i `DeviceSetupManager/Admin` 112 z artefaktami SetupAPI i rejestru.<sup>[[17]](#references)[[59]](#references)</sup>

#### Zdarzenia zasilania systemu

Użyj zdarzeń 12/13/1074/6008/6009, aby ustalić kontekst uruchomienia systemu operacyjnego, zamknięcia, ponownego uruchomienia i nieoczekiwanej utraty zasilania; zdarzenia 6005/6006 oznaczają uruchomienie/zatrzymanie usługi Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Usunięcie dziennika

Security Event ID 1102 rejestruje wyczyszczenie dziennika inspekcji Security i należy je skorelować z kontem oraz procesem odpowiedzialnym za tę czynność.<sup>[[62]](#references)</sup>



## References

- [1] [Czyszczenie funkcji Plug and Play w Windows](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Badanie typowych procesów Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Cyfrowa analiza kryminalistyczna powiadomień Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Narzędzia kryminalistyczne Erica Zimmermana](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier i alternatywne strumienie danych](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Usługa Volume Shadow Copy](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operacje tworzenia i przywracania kopii zapasowej rejestru w ramach VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Klucze rejestru używane do tworzenia i przywracania kopii zapasowej](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problem z wydajnością Word w lokalizacji AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Podręcznik reagowania na incydenty](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: binarny format pliku Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Analiza kryminalistyczna USB MTP: identyfikowanie śladów eksfiltracji danych](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Wpisy dziennika instalacji urządzeń SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID i typy pokrewne](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Znajdowanie i przenoszenie plików danych Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Włączanie trybu Cached Exchange](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Synchronizowany jest tylko podzbiór elementów](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Konfigurowanie limitów rozmiaru plików danych Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profile — gdzie Thunderbird przechowuje dane użytkownika](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Ustawienia kont Thunderbird i katalogi mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Interfejs IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Ule rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Rejestr systemowy nie jest kopiowany do RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Odzyskiwanie rejestru Windows](https://www.mitec.cz/wrr.html)
- [38] [Zdalna edycja rejestru](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Przegląd techniczny haseł](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Ślady Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Format pliku dziennika zdarzeń](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Klucz rejestru Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Właściwość zdarzenia TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Zdarzenie 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Zdarzenie 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Zdarzenie 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Zdarzenie 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Zdarzenie 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: wartości NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Zdarzenie 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Rozwiązywanie problemów z nieoczekiwanymi ponownymi uruchomieniami za pomocą dzienników zdarzeń systemowych](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Rozwiązywanie problemów z trwającym zamykaniem](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Analiza kryminalistyczna urządzeń pamięci masowej USB w Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Typy logowania w Windows](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Zdarzenie 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Modulator aktywności w tle](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Rejestr — RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Szybkie drukowanie przestaje drukować załączniki PDF w Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Pliki rejestru Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Zapobieganie ponownemu pojawianiu się usuniętych aplikacji podczas aktualizacji](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: wyniki testów FTK i Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Baza danych zainstalowanych usług](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Zaplanowane zadania kończą się błędem „Usługa Harmonogram zadań jest niedostępna”](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Poruszanie się po bazie danych Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: format wiadomości internetowych](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Zarządzanie Recall na urządzeniach klienckich Windows](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
