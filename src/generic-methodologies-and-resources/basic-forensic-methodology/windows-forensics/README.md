# Artefakty Windows

{{#include ../../../banners/hacktricks-training.md}}

## Ogólne artefakty Windows

### Powiadomienia Windows 10

W ścieżce `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` można znaleźć bazę danych `appdb.dat` (przed Windows anniversary) lub `wpndatabase.db` (po Windows Anniversary).

W tej bazie SQLite można znaleźć tabelę `Notification` zawierającą wszystkie powiadomienia (w formacie XML), które mogą zawierać interesujące dane.

### Oś czasu

Timeline to funkcja Windows, która zapewnia **chronologiczną historię** odwiedzonych stron internetowych, edytowanych dokumentów i uruchamianych aplikacji.

Baza danych znajduje się w ścieżce `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Można ją otworzyć za pomocą narzędzia SQLite lub narzędzia [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), **które generuje 2 pliki, które można otworzyć za pomocą narzędzia** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Pobrane pliki mogą zawierać **ADS Zone.Identifier**, wskazujący **w jaki sposób** zostały **pobrane** z intranetu, internetu itd. Niektóre programy (np. przeglądarki) zwykle umieszczają tam **jeszcze więcej** **informacji**, takich jak **URL**, z którego pobrano plik.

## **Kopie zapasowe plików**

### Kosz

W Vista/Win7/Win8/Win10 **Kosz** można znaleźć w folderze **`$Recycle.bin`** w katalogu głównym dysku (`C:\$Recycle.bin`).\
Po usunięciu pliku w tym folderze tworzone są 2 określone pliki:

- `$I{id}`: Informacje o pliku (data jego usunięcia}
- `$R{id}`: Zawartość pliku

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

Mając te pliki, można użyć narzędzia [**Rifiuti**](https://github.com/abelcheung/rifiuti2), aby uzyskać pierwotną lokalizację usuniętych plików oraz datę ich usunięcia (użyj `rifiuti-vista.exe` dla Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Kopie zapasowe plików - Kosz: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Kopie migawkowe woluminów

Shadow Copy to technologia zawarta w Microsoft Windows, która może tworzyć **kopie zapasowe** lub migawki plików albo woluminów komputera, nawet gdy są one używane.

Kopie te zwykle znajdują się w `\System Volume Information` w katalogu głównym systemu plików, a ich nazwa składa się z **UID-ów**, jak pokazano na poniższym obrazie:

![Kosz - Kopie migawkowe woluminów: Kopie te zwykle znajdują się w System Volume Information w katalogu głównym systemu plików, a ich nazwa składa się z UID-ów, jak pokazano na...](<../../../images/image (94).png>)

Po zamontowaniu obrazu forensics za pomocą **ArsenalImageMounter** można użyć narzędzia [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) do zbadania kopii migawkowej, a nawet **wyodrębnienia plików** z kopii zapasowych kopii migawkowej.

![Kosz - Kopie migawkowe woluminów: Po zamontowaniu obrazu forensics za pomocą ArsenalImageMounter narzędzie ShadowCopyView może zostać użyte do zbadania kopii migawkowej, a nawet wyodrębnienia plików...](<../../../images/image (576).png>)

Wpis rejestru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` zawiera pliki i klucze, których **nie należy uwzględniać w kopii zapasowej**:

![Kosz - Kopie migawkowe woluminów: Wpis rejestru HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore zawiera pliki i klucze, których nie należy uwzględniać w kopii zapasowej](<../../../images/image (254).png>)

Rejestr `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` również zawiera informacje konfiguracyjne dotyczące `Volume Shadow Copies`.

### Automatycznie zapisane pliki Office

Automatycznie zapisane pliki Office można znaleźć w: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementy powłoki

Element powłoki to element zawierający informacje o sposobie uzyskania dostępu do innego pliku.

### Ostatnie dokumenty (LNK)

Windows **automatycznie** **tworzy** te **skróty**, gdy użytkownik **otwiera, używa lub tworzy plik** w:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Gdy tworzony jest folder, tworzony jest również link do tego folderu, folderu nadrzędnego oraz folderu nadrzędnego drugiego poziomu.

Te automatycznie utworzone pliki linków **zawierają informacje o źródle**, takie jak informacja, czy jest to **plik**, **czy folder**, czasy **MAC** tego pliku, **informacje o woluminie**, na którym przechowywany jest plik, oraz **folder docelowego pliku**. Informacje te mogą być przydatne do odzyskania tych plików w przypadku ich usunięcia.

Ponadto **data utworzenia pliku linku** to pierwszy **moment**, w którym oryginalny plik został **po raz pierwszy** **użyty**, a **data** **modyfikacji** pliku linku to ostatni **moment**, w którym użyto pliku źródłowego.

Do zbadania tych plików można użyć narzędzia [**LinkParser**](http://4discovery.com/our-tools/).

W tym narzędziu znajdziesz **2 zestawy** znaczników czasu:

- **Pierwszy zestaw:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Drugi zestaw:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Pierwszy zestaw znaczników czasu odnosi się do **znaczników czasu samego pliku**. Drugi zestaw odnosi się do **znaczników czasu połączonego pliku**.

Te same informacje można uzyskać, uruchamiając narzędzie Windows CLI: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
W tym przypadku informacje zostaną zapisane w pliku CSV.

### Jumplists

Są to ostatnio używane pliki wskazane dla poszczególnych aplikacji. Jest to lista **ostatnich plików używanych przez aplikację**, do której można uzyskać dostęp w każdej aplikacji. Mogą być tworzone **automatycznie lub niestandardowo**.

**Jumplists** utworzone automatycznie są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Nazwy jumplists mają format `{id}.autmaticDestinations-ms`, gdzie początkowe ID jest identyfikatorem aplikacji.

Niestandardowe jumplists są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` i są zwykle tworzone przez aplikację, ponieważ wydarzyło się coś **ważnego** z plikiem (na przykład został oznaczony jako ulubiony).

Czas **utworzenia** dowolnego jumplista wskazuje **pierwszy moment uzyskania dostępu do pliku**, a czas modyfikacji — **ostatni taki moment**.

Możesz sprawdzać jumplists za pomocą narzędzia [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Recent Documents (LNK) - Jumplists: Jumplists można sprawdzać za pomocą JumplistExplorer](<../../../images/image (168).png>)

(_Zwróć uwagę, że znaczniki czasu wyświetlane przez JumplistExplorer odnoszą się do samego pliku jumplist_)

### Shellbags

[**Kliknij ten link, aby dowiedzieć się, czym są shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Użycie Windows USBs

Możliwe jest ustalenie, że użyto urządzenia USB, dzięki utworzeniu:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Zauważ, że niektóre pliki LNK zamiast wskazywać oryginalną ścieżkę, wskazują folder WPDNSE:

![Shellbags - Użycie Windows USBs: Zauważ, że niektóre pliki LNK zamiast wskazywać oryginalną ścieżkę, wskazują folder WPDNSE](<../../../images/image (218).png>)

Pliki w folderze WPDNSE są kopiami oryginalnych plików, dlatego nie przetrwają ponownego uruchomienia komputera, a identyfikator GUID jest pobierany z shellbaga.

### Informacje z rejestru

[Sprawdź tę stronę, aby dowiedzieć się,](interesting-windows-registry-keys.md#usb-information) które klucze rejestru zawierają interesujące informacje o podłączonych urządzeniach USB.

### setupapi

Sprawdź plik `C:\Windows\inf\setupapi.dev.log`, aby uzyskać znaczniki czasu dotyczące momentu nawiązania połączenia USB (wyszukaj `Section start`).

![Informacje z rejestru - setupapi: Sprawdź plik C: Windows inf setupapi.dev.log, aby uzyskać znaczniki czasu dotyczące momentu nawiązania połączenia USB (wyszukaj Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

Narzędzie [**USBDetective**](https://usbdetective.com) może służyć do uzyskiwania informacji o urządzeniach USB, które zostały podłączone do obrazu.

![setupapi - USB Detective: USBDetective może służyć do uzyskiwania informacji o urządzeniach USB, które zostały podłączone do obrazu](<../../../images/image (452).png>)

### Plug and Play Cleanup

Zaplanowane zadanie o nazwie „Plug and Play Cleanup” służy przede wszystkim do usuwania nieaktualnych wersji sterowników. Wbrew określonemu celowi, jakim jest zachowanie najnowszej wersji pakietu sterownika, źródła internetowe sugerują, że zadanie obejmuje również sterowniki, które były nieaktywne przez 30 dni. W rezultacie sterowniki urządzeń wymiennych, które nie były podłączone w ciągu ostatnich 30 dni, mogą zostać usunięte.<sup>[[1]](#references)</sup>

Zadanie znajduje się w następującej ścieżce: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Poniżej przedstawiono zrzut ekranu zawartości zadania: ![USB Detective - Plug and Play Cleanup: Zadanie znajduje się w następującej ścieżce: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Główne elementy i ustawienia zadania:**

- **pnpclean.dll**: Ta biblioteka DLL odpowiada za właściwy proces czyszczenia.
- **UseUnifiedSchedulingEngine**: Ustawione na `TRUE`, co wskazuje na użycie ogólnego silnika planowania zadań.
- **MaintenanceSettings**:
- **Period ('P1M')**: Nakazuje Task Scheduler uruchamiać zadanie czyszczenia co miesiąc podczas standardowej konserwacji automatycznej.
- **Deadline ('P2M')**: Nakazuje Task Scheduler, jeśli zadanie nie powiedzie się przez dwa kolejne miesiące, uruchomić je podczas awaryjnej konserwacji automatycznej.

Taka konfiguracja zapewnia regularną konserwację i czyszczenie sterowników, a także umożliwia ponowienie zadania w przypadku kolejnych niepowodzeń.

**Więcej informacji znajdziesz tutaj:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-maile

E-maile zawierają **2 interesujące elementy: nagłówki i treść** wiadomości. W **nagłówkach** można znaleźć informacje takie jak:

- **Kto** wysłał e-maile (adres e-mail, adres IP, serwery pocztowe, które przekierowały wiadomość)
- **Kiedy** e-mail został wysłany

Ponadto w nagłówkach `References` i `In-Reply-To` można znaleźć identyfikator wiadomości:

![Plug and Play Cleanup - E-maile: Kiedy e-mail został wysłany](<../../../images/image (593).png>)

### Windows Mail App

Ta aplikacja zapisuje e-maile w formacie HTML lub tekstowym. E-maile można znaleźć w podfolderach znajdujących się w `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. E-maile są zapisywane z rozszerzeniem `.dat`.

**Metadane** e-maili i **kontakty** można znaleźć w **bazie danych EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Zmień rozszerzenie** pliku z `.vol` na `.edb`, a następnie użyj narzędzia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), aby go otworzyć. W tabeli `Message` można wyświetlić e-maile.

### Microsoft Outlook

Gdy używane są serwery Exchange lub klienci Outlook, dostępne będą nagłówki MAPI:

- `Mapi-Client-Submit-Time`: czas systemowy wysłania e-maila
- `Mapi-Conversation-Index`: liczba wiadomości potomnych w wątku oraz znacznik czasu każdej wiadomości w wątku
- `Mapi-Entry-ID`: identyfikator wiadomości.
- `Mappi-Message-Flags` i `Pr_last_Verb-Executed`: informacje o kliencie MAPI (wiadomość odczytana? nieodczytana? odpowiedziano na nią? przekierowano ją? wiadomość poza biurem?)

W kliencie Microsoft Outlook wszystkie wysłane i odebrane wiadomości, dane kontaktów oraz dane kalendarza są przechowywane w pliku PST w:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Ścieżka rejestru `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` wskazuje używany plik.

Plik PST można otworzyć za pomocą narzędzia [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: Plik PST można otworzyć za pomocą narzędzia Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Plik **OST** jest generowany przez Microsoft Outlook, gdy jest skonfigurowany z serwerem **IMAP** lub **Exchange**, i przechowuje informacje podobne do pliku PST. Plik ten jest synchronizowany z serwerem, zachowując dane z **ostatnich 12 miesięcy** do **maksymalnego rozmiaru 50 GB**, i znajduje się w tym samym katalogu co plik PST. Do wyświetlenia pliku OST można użyć narzędzia [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Odzyskiwanie załączników

Utracone załączniki można czasami odzyskać z:

- Dla **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Dla **IE11 i nowszych**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** wykorzystuje **pliki MBOX** do przechowywania danych, które znajdują się w `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniatury obrazów

- **Windows XP i 8-8.1**: Uzyskanie dostępu do folderu zawierającego miniatury generuje plik `thumbs.db` przechowujący podglądy obrazów, nawet po ich usunięciu.
- **Windows 7/10**: Plik `thumbs.db` jest tworzony, gdy folder jest otwierany przez sieć za pośrednictwem ścieżki UNC.
- **Windows Vista i nowsze**: Podglądy miniatur są centralizowane w `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, w plikach o nazwach **thumbcache_xxx.db**. Narzędzia [**Thumbsviewer**](https://thumbsviewer.github.io) i [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) służą do wyświetlania tych plików.

### Informacje z Windows Registry

Windows Registry, przechowujący obszerne dane dotyczące aktywności systemu i użytkowników, znajduje się w plikach:

- `%windir%\System32\Config` dla różnych podkluczy `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` dla `HKEY_CURRENT_USER`.
- Windows Vista i nowsze wersje tworzą kopie zapasowe plików rejestru `HKEY_LOCAL_MACHINE` w `%Windir%\System32\Config\RegBack\`.
- Ponadto informacje o wykonywaniu programów są przechowywane w `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` od Windows Vista i Windows 2008 Server.

### Narzędzia

Niektóre narzędzia są przydatne do analizy plików rejestru:

- **Registry Editor**: Jest zainstalowany w Windows. To narzędzie GUI umożliwiające poruszanie się po rejestrze Windows bieżącej sesji.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Umożliwia załadowanie pliku rejestru i poruszanie się po nim za pomocą GUI. Zawiera również zakładki wyróżniające klucze z interesującymi informacjami.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Ponownie, jest to narzędzie GUI umożliwiające poruszanie się po załadowanym rejestrze. Zawiera również plugins wyróżniające interesujące informacje w załadowanym rejestrze.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Kolejna aplikacja GUI zdolna do wyodrębniania ważnych informacji z załadowanego rejestru.

### Odzyskiwanie usuniętego elementu

Po usunięciu klucza zostaje on oznaczony jako usunięty, ale dopóki zajmowane przez niego miejsce nie będzie potrzebne, nie zostanie usunięty fizycznie. Dlatego za pomocą narzędzi takich jak **Registry Explorer** można odzyskać te usunięte klucze.

### Last Write Time

Każda para klucz-wartość zawiera **znacznik czasu** wskazujący moment jej ostatniej modyfikacji.

### SAM

Plik/ul **SAM** zawiera hashe **użytkowników, grup i haseł użytkowników** systemu.

W `SAM\Domains\Account\Users` można uzyskać nazwę użytkownika, RID, ostatnie logowanie, ostatnią nieudaną próbę logowania, licznik logowań, zasady haseł oraz czas utworzenia konta. Aby uzyskać **hashe**, potrzebny jest również plik/ul **SYSTEM**.

### Interesujące wpisy w Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Wykonywane programy

### Podstawowe procesy Windows

W [tym artykule](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) możesz dowiedzieć się więcej o typowych procesach Windows, aby wykrywać podejrzane zachowania.

### Ostatnie aplikacje Windows

W rejestrze `NTUSER.DAT`, w ścieżce `Software\Microsoft\Current Version\Search\RecentApps`, można znaleźć podklucze zawierające informacje o **wykonanej aplikacji**, **ostatnim czasie** jej wykonania oraz **liczbie uruchomień**.

### BAM (Background Activity Moderator)

Możesz otworzyć plik `SYSTEM` za pomocą edytora rejestru. W ścieżce `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` znajdziesz informacje o **aplikacjach wykonywanych przez każdego użytkownika** (zwróć uwagę na `{SID}` w ścieżce) oraz o tym, **kiedy** zostały wykonane (czas znajduje się w wartości Data rejestru).

### Windows Prefetch

Prefetching to technika umożliwiająca komputerowi ciche **pobieranie zasobów niezbędnych do wyświetlenia treści**, do których użytkownik **może uzyskać dostęp w niedalekiej przyszłości**, dzięki czemu zasoby mogą być dostępne szybciej.

Windows prefetch polega na tworzeniu **pamięci podręcznych wykonanych programów**, aby można było je szybciej ładować. Pamięci podręczne są tworzone jako pliki `.pf` w ścieżce `C:\Windows\Prefetch`. W systemach XP/VISTA/WIN7 limit wynosi 128 plików, a w Win8/Win10 — 1024 pliki.

Nazwa pliku jest tworzona jako `{program_name}-{hash}.pf` (hash jest oparty na ścieżce i argumentach pliku wykonywalnego). W W10 pliki te są skompresowane. Należy pamiętać, że sama obecność pliku wskazuje, iż **program został w pewnym momencie wykonany**.

Plik `C:\Windows\Prefetch\Layout.ini` zawiera **nazwy folderów plików, które są objęte prefetchingiem**. Plik ten zawiera **informacje o liczbie wykonań**, **datach** wykonania oraz **plikach** **otwieranych** przez program.

Do sprawdzania tych plików można użyć narzędzia [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** ma ten sam cel co prefetch — **szybsze ładowanie programów** poprzez przewidywanie, co zostanie załadowane jako następne. Nie zastępuje jednak usługi prefetch.\
Ta usługa generuje pliki baz danych w `C:\Windows\Prefetch\Ag*.db`.

W tych bazach danych można znaleźć **nazwę** **programu**, **liczbę** **uruchomień**, **otwarte** **pliki**, **uzyskany dostęp** do **woluminu**, **pełną** **ścieżkę**, **przedziały czasowe** oraz **znaczniki czasu**.

Dostęp do tych informacji można uzyskać za pomocą narzędzia [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitoruje** **zasoby** **wykorzystywane** **przez proces**. Pojawił się w W8 i przechowuje dane w bazie danych ESE znajdującej się w `C:\Windows\System32\sru\SRUDB.dat`.

Udostępnia następujące informacje:

- AppID i ścieżka
- Użytkownik, który uruchomił proces
- Wysłane bajty
- Odebrane bajty
- Interfejs sieciowy
- Czas trwania połączenia
- Czas trwania procesu

Te informacje są aktualizowane co 60 minut.

Dane z tego pliku można uzyskać za pomocą narzędzia [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, znany również jako **ShimCache**, stanowi część **Application Compatibility Database** opracowanej przez **Microsoft** w celu rozwiązywania problemów ze zgodnością aplikacji. Ten komponent systemu rejestruje różne informacje o metadanych pliku, w tym:

- Pełna ścieżka pliku
- Rozmiar pliku
- Czas ostatniej modyfikacji w ramach **$Standard_Information** (SI)
- Czas ostatniej aktualizacji ShimCache
- Flaga wykonania procesu

Dane te są przechowywane w rejestrze w określonych lokalizacjach, zależnie od wersji systemu operacyjnego:

- W systemie XP dane są przechowywane w `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, z pojemnością 96 wpisów.
- W systemach Server 2003 oraz Windows 2008, 2012, 2016, 7, 8 i 10 ścieżka przechowywania to `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, z pojemnością odpowiednio 512 i 1024 wpisów.

Do analizy przechowywanych informacji zaleca się użycie narzędzia [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Do analizy przechowywanych informacji zaleca się użycie narzędzia AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Plik **Amcache.hve** jest zasadniczo gałęzią rejestru, która rejestruje informacje o aplikacjach uruchomionych w systemie. Zwykle znajduje się w `C:\Windows\AppCompat\Programas\Amcache.hve`.

Plik ten wyróżnia się przechowywaniem rekordów ostatnio uruchamianych procesów, w tym ścieżek do plików wykonywalnych i ich hashy SHA1. Informacje te są niezwykle cenne podczas śledzenia aktywności aplikacji w systemie.

Do wyodrębnienia i analizy danych z **Amcache.hve** można użyć narzędzia [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Poniższe polecenie przedstawia przykład użycia AmcacheParser do przeanalizowania zawartości pliku **Amcache.hve** i zapisania wyników w formacie CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Wśród wygenerowanych plików CSV szczególnie wyróżnia się `Amcache_Unassociated file entries` ze względu na bogate informacje, które dostarcza na temat niepowiązanych wpisów plików.

Najciekawszym wygenerowanym plikiem CVS jest `Amcache_Unassociated file entries`.

### RecentFileCache

Ten artefakt można znaleźć wyłącznie w W7, w lokalizacji `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, i zawiera on informacje o ostatnim uruchomieniu niektórych plików binarnych.

Do przeanalizowania pliku można użyć narzędzia [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser).

### Zaplanowane zadania

Można je wyodrębnić z `C:\Windows\Tasks` lub `C:\Windows\System32\Tasks` i odczytać jako XML.

### Usługi

Można je znaleźć w rejestrze w lokalizacji `SYSTEM\ControlSet001\Services`. Można sprawdzić, co zostanie wykonane i kiedy.

### **Windows Store**

Zainstalowane aplikacje można znaleźć w `\ProgramData\Microsoft\Windows\AppRepository\`\
To repozytorium zawiera **log** z informacjami o **każdej aplikacji zainstalowanej** w systemie, znajdującymi się w bazie danych **`StateRepository-Machine.srd`**.

W tabeli Application tej bazy danych można znaleźć kolumny: "Application ID", "PackageNumber" oraz "Display Name". Kolumny te zawierają informacje o aplikacjach preinstalowanych i zainstalowanych. Można również ustalić, czy niektóre aplikacje zostały odinstalowane, ponieważ identyfikatory zainstalowanych aplikacji powinny być sekwencyjne.

**Zainstalowane aplikacje** można również znaleźć w ścieżce rejestru: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
**Odinstalowane** **aplikacje** znajdują się w: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Zdarzenia Windows

Informacje pojawiające się w zdarzeniach Windows obejmują:

- Co się wydarzyło
- Znacznik czasu (UTC + 0)
- Zaangażowani użytkownicy
- Zaangażowane hosty (nazwa hosta, adres IP)
- Uzyskane zasoby (pliki, foldery, drukarki, usługi)

Przed Windows Vista logi znajdowały się w `C:\Windows\System32\config`, a po Windows Vista w `C:\Windows\System32\winevt\Logs`. Przed Windows Vista logi zdarzeń były w formacie binarnym, a później są w **formacie XML** i używają rozszerzenia **.evtx**.

Lokalizację plików zdarzeń można znaleźć w rejestrze SYSTEM, w **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Można je przeglądać za pomocą Podglądu zdarzeń Windows (**`eventvwr.msc`**) lub innych narzędzi, takich jak [**Event Log Explorer**](https://eventlogxp.com) **lub** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Zrozumienie rejestrowania zdarzeń bezpieczeństwa Windows

Zdarzenia dostępu są zapisywane w pliku konfiguracji zabezpieczeń znajdującym się w `C:\Windows\System32\winevt\Security.evtx`. Rozmiar tego pliku można dostosować, a po osiągnięciu jego pojemności starsze zdarzenia są nadpisywane. Rejestrowane zdarzenia obejmują logowania i wylogowania użytkowników, działania użytkowników oraz zmiany ustawień zabezpieczeń, a także dostęp do plików, folderów i współdzielonych zasobów.

### Kluczowe identyfikatory zdarzeń dotyczące uwierzytelniania użytkowników:

- **EventID 4624**: Oznacza pomyślne uwierzytelnienie użytkownika.
- **EventID 4625**: Sygnalizuje niepowodzenie uwierzytelniania.
- **EventIDs 4634/4647**: Oznaczają zdarzenia wylogowania użytkownika.
- **EventID 4672**: Oznacza logowanie z uprawnieniami administracyjnymi.

#### Podtypy w ramach EventID 4634/4647:

- **Interactive (2)**: Bezpośrednie logowanie użytkownika.
- **Network (3)**: Dostęp do współdzielonych folderów.
- **Batch (4)**: Wykonanie procesów wsadowych.
- **Service (5)**: Uruchomienie usługi.
- **Proxy (6)**: Uwierzytelnianie proxy.
- **Unlock (7)**: Odblokowanie ekranu za pomocą hasła.
- **Network Cleartext (8)**: Przesyłanie hasła jawnym tekstem, często z IIS.
- **New Credentials (9)**: Użycie innych danych uwierzytelniających w celu uzyskania dostępu.
- **Remote Interactive (10)**: Logowanie przez zdalny pulpit lub usługi terminalowe.
- **Cache Interactive (11)**: Logowanie przy użyciu danych uwierzytelniających zapisanych w pamięci podręcznej, bez kontaktu z kontrolerem domeny.
- **Cache Remote Interactive (12)**: Zdalne logowanie przy użyciu danych uwierzytelniających zapisanych w pamięci podręcznej.
- **Cached Unlock (13)**: Odblokowanie przy użyciu danych uwierzytelniających zapisanych w pamięci podręcznej.

#### Kody Status i Sub Status dla EventID 4625:

- **0xC0000064**: Nazwa użytkownika nie istnieje — może wskazywać na atak polegający na enumeracji nazw użytkowników.
- **0xC000006A**: Prawidłowa nazwa użytkownika, ale nieprawidłowe hasło — możliwe zgadywanie hasła lub próba brute-force.
- **0xC0000234**: Konto użytkownika zostało zablokowane — może być następstwem ataku brute-force powodującego wiele nieudanych logowań.
- **0xC0000072**: Konto wyłączone — nieautoryzowane próby uzyskania dostępu do wyłączonych kont.
- **0xC000006F**: Logowanie poza dozwolonym czasem — wskazuje na próby uzyskania dostępu poza ustalonymi godzinami logowania i może świadczyć o nieautoryzowanym dostępie.
- **0xC0000070**: Naruszenie ograniczeń stacji roboczej — może oznaczać próbę logowania z nieautoryzowanej lokalizacji.
- **0xC0000193**: Wygaśnięcie konta — próby uzyskania dostępu przy użyciu wygasłych kont użytkowników.
- **0xC0000071**: Wygasłe hasło — próby logowania przy użyciu nieaktualnych haseł.
- **0xC0000133**: Problemy z synchronizacją czasu — duże rozbieżności czasu między klientem i serwerem mogą wskazywać na bardziej zaawansowane ataki, takie jak pass-the-ticket.
- **0xC0000224**: Wymagana obowiązkowa zmiana hasła — częste obowiązkowe zmiany mogą sugerować próbę destabilizacji bezpieczeństwa konta.
- **0xC0000225**: Wskazuje na błąd systemu, a nie problem z bezpieczeństwem.
- **0xC000015b**: Odrzucony typ logowania — próba uzyskania dostępu przy użyciu nieautoryzowanego typu logowania, na przykład próba uruchomienia usługi przez użytkownika.

#### EventID 4616:

- **Zmiana czasu**: Modyfikacja czasu systemowego może zacierać chronologię zdarzeń.

#### EventID 6005 i 6006:

- **Uruchomienie i zamknięcie systemu**: EventID 6005 wskazuje uruchomienie systemu, a EventID 6006 jego zamknięcie.

#### EventID 1102:

- **Usunięcie logów**: Wyczyszczenie logów bezpieczeństwa, które często jest sygnałem ostrzegawczym wskazującym na próbę ukrycia nielegalnych działań.

#### EventIDs dotyczące śledzenia urządzeń USB:

- **20001 / 20003 / 10000**: Pierwsze podłączenie urządzenia USB.
- **10100**: Aktualizacja sterownika USB.
- **EventID 112**: Czas podłączenia urządzenia USB.

Praktyczne przykłady symulowania tych typów logowania i możliwości pozyskiwania danych uwierzytelniających można znaleźć w [szczegółowym przewodniku Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Szczegóły zdarzeń, w tym kody statusu i podstatusu, dostarczają dodatkowych informacji o przyczynach zdarzeń, co jest szczególnie istotne w przypadku Event ID 4625.

### Odzyskiwanie zdarzeń Windows

Aby zwiększyć szanse na odzyskanie usuniętych zdarzeń Windows, zaleca się wyłączenie podejrzanego komputera poprzez bezpośrednie odłączenie go od zasilania. Do próby odzyskania takich zdarzeń zaleca się użycie narzędzia **Bulk_extractor**, z określeniem rozszerzenia `.evtx`.

### Identyfikowanie typowych ataków za pomocą zdarzeń Windows

Kompleksowy przewodnik dotyczący używania identyfikatorów zdarzeń Windows do identyfikowania typowych cyberataków można znaleźć na stronie [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Ataki brute force

Można je rozpoznać po wielu rekordach EventID 4625, po których następuje EventID 4624, jeśli atak zakończył się powodzeniem.

#### Zmiana czasu

Rejestrowana przez EventID 4616; zmiany czasu systemowego mogą utrudniać analizę śledczą.

#### Śledzenie urządzeń USB

Przydatne System EventIDs do śledzenia urządzeń USB obejmują 20001/20003/10000 dla pierwszego użycia, 10100 dla aktualizacji sterownika oraz EventID 112 z DeviceSetupManager, zawierający znaczniki czasu podłączenia.

#### Zdarzenia zasilania systemu

EventID 6005 wskazuje uruchomienie systemu, a EventID 6006 oznacza jego zamknięcie.

#### Usunięcie logów

Security EventID 1102 sygnalizuje usunięcie logów i jest kluczowym zdarzeniem w analizie śledczej.

## Odnośniki

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
