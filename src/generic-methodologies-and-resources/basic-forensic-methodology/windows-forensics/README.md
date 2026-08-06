# Artefakty Windows

{{#include ../../../banners/hacktricks-training.md}}

## Ogólne artefakty Windows

### Powiadomienia Windows 10

W ścieżce `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` można znaleźć bazę danych `appdb.dat` (przed Windows Anniversary) lub `wpndatabase.db` (po Windows Anniversary).

Wewnątrz tej bazy SQLite znajduje się tabela `Notification` zawierająca wszystkie powiadomienia (w formacie XML), które mogą zawierać interesujące dane.

### Oś czasu

Oś czasu to funkcja Windows, która zapewnia **chronologiczną historię** odwiedzanych stron internetowych, edytowanych dokumentów i uruchamianych aplikacji.

Baza danych znajduje się w ścieżce `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Bazę tę można otworzyć za pomocą narzędzia SQLite lub narzędzia [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), **które generuje 2 pliki, które można otworzyć za pomocą narzędzia** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Pobrane pliki mogą zawierać **ADS Zone.Identifier**, wskazujący **w jaki sposób** zostały **pobrane** z intranetu, internetu itd. Niektóre programy (takie jak przeglądarki) zwykle umieszczają tam jeszcze **więcej** **informacji**, takich jak **URL**, z którego pobrano plik.

## **Kopie zapasowe plików**

### Kosz

W systemach Vista/Win7/Win8/Win10 **Kosz** można znaleźć w folderze **`$Recycle.bin`** w katalogu głównym dysku (`C:\$Recycle.bin`).\
Po usunięciu pliku w tym folderze tworzone są 2 określone pliki:

- `$I{id}`: Informacje o pliku (data jego usunięcia}
- `$R{id}`: Zawartość pliku

![Kopie zapasowe plików - Kosz: $R{id}: Zawartość pliku](<../../../images/image (1029).png>)

Mając te pliki, można użyć narzędzia [**Rifiuti**](https://github.com/abelcheung/rifiuti2), aby uzyskać pierwotną ścieżkę usuniętych plików oraz datę ich usunięcia (w przypadku Vista – Win10 użyj `rifiuti-vista.exe`).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Kopie zapasowe plików - Kosz: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Kopie woluminów w tle

Shadow Copy to technologia dostępna w systemie Microsoft Windows, która może tworzyć **kopie zapasowe** lub migawki plików albo woluminów komputera, nawet gdy są one używane.

Te kopie zapasowe zwykle znajdują się w `\System Volume Information` w katalogu głównym systemu plików, a ich nazwy składają się z **UID-ów**, jak pokazano na poniższym obrazie:

![Kosz - Kopie woluminów w tle: Te kopie zapasowe zwykle znajdują się w System Volume Information w katalogu głównym systemu plików, a ich nazwy składają się z UID-ów, jak pokazano na...](<../../../images/image (94).png>)

Po zamontowaniu obrazu forensics za pomocą **ArsenalImageMounter** narzędzie [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) może zostać użyte do sprawdzenia kopii w tle, a nawet do **wyodrębnienia plików** z kopii zapasowych kopii w tle.

![Kosz - Kopie woluminów w tle: Po zamontowaniu obrazu forensics za pomocą ArsenalImageMounter narzędzie ShadowCopyView może zostać użyte do sprawdzenia kopii w tle, a nawet do wyodrębnienia plików...](<../../../images/image (576).png>)

Wpis rejestru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` zawiera pliki i klucze, których **nie należy uwzględniać w kopii zapasowej**:

![Kosz - Kopie woluminów w tle: Wpis rejestru HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore zawiera pliki i klucze, których nie należy uwzględniać w kopii zapasowej](<../../../images/image (254).png>)

Rejestr `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` zawiera również informacje konfiguracyjne dotyczące `Volume Shadow Copies`.

### Pliki automatycznie zapisywane przez Office

Automatycznie zapisywane pliki Office można znaleźć w: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementy powłoki

Element powłoki to element zawierający informacje o sposobie uzyskania dostępu do innego pliku.

### Ostatnio używane dokumenty (LNK)

System Windows **automatycznie** **tworzy** te **skróty**, gdy użytkownik **otwiera, używa lub tworzy plik** w:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Po utworzeniu folderu tworzony jest również link do folderu, folderu nadrzędnego oraz folderu nadrzędnego wyższego poziomu.

Te automatycznie tworzone pliki linków **zawierają informacje o pochodzeniu**, takie jak informacja, czy jest to **plik**, **czy folder**, czasy **MAC** tego pliku, **informacje o woluminie**, na którym przechowywany jest plik, oraz **folder docelowego pliku**. Informacje te mogą być przydatne do odzyskania tych plików, jeśli zostały usunięte.

Ponadto **data utworzenia linku** jest pierwszym **momentem**, w którym oryginalny plik został po raz pierwszy **użyty**, a **data** **modyfikacji** linku jest ostatnim **momentem**, w którym użyto pliku źródłowego.

Do sprawdzania tych plików można użyć narzędzia [**LinkParser**](http://4discovery.com/our-tools/).

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

Są to ostatnio używane pliki wskazane dla poszczególnych aplikacji. Jest to lista **ostatnio używanych przez aplikację plików**, do której można uzyskać dostęp z poziomu każdej aplikacji. Mogą być tworzone **automatycznie lub niestandardowo**.

Automatycznie tworzone **jumplists** są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Nazwy jumplists mają format `{id}.autmaticDestinations-ms`, gdzie początkowe ID jest identyfikatorem aplikacji.

Niestandardowe jumplists są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` i są zwykle tworzone przez aplikację, ponieważ wydarzyło się coś **ważnego** z plikiem (być może został oznaczony jako ulubiony).

Czas **utworzenia** dowolnego jumplista wskazuje **pierwszy moment uzyskania dostępu do pliku**, a czas modyfikacji — **ostatni taki moment**.

Możesz przeanalizować jumplists za pomocą [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Ostatnie dokumenty (LNK) - Jumplists: Jumplists można analizować za pomocą JumplistExplorer](<../../../images/image (168).png>)

(_Pamiętaj, że znaczniki czasu podawane przez JumplistExplorer odnoszą się do samego pliku jumplista_)

### Shellbags

[**Kliknij ten link, aby dowiedzieć się, czym są shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Użycie urządzeń USB w Windows

Możliwe jest ustalenie, czy urządzenie USB było używane, dzięki utworzeniu:

- Folderu Windows Recent
- Folderu Microsoft Office Recent
- Jumplists

Należy zauważyć, że niektóre pliki LNK zamiast wskazywać oryginalną ścieżkę, wskazują folder WPDNSE:

![Shellbags - Użycie urządzeń USB w Windows: Należy zauważyć, że niektóre pliki LNK zamiast wskazywać oryginalną ścieżkę, wskazują folder WPDNSE](<../../../images/image (218).png>)

Pliki w folderze WPDNSE są kopiami oryginalnych plików, dlatego nie przetrwają ponownego uruchomienia komputera, a GUID jest pobierany z shellbaga.

### Informacje z rejestru

[Sprawdź tę stronę, aby dowiedzieć się](interesting-windows-registry-keys.md#usb-information), które klucze rejestru zawierają interesujące informacje o podłączonych urządzeniach USB.

### setupapi

Sprawdź plik `C:\Windows\inf\setupapi.dev.log`, aby uzyskać znaczniki czasu wskazujące, kiedy nastąpiło połączenie USB (wyszukaj `Section start`).

![Informacje z rejestru - setupapi: Sprawdź plik C: Windows inf setupapi.dev.log, aby uzyskać znaczniki czasu wskazujące, kiedy nastąpiło połączenie USB (wyszukaj Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) można użyć do uzyskania informacji o urządzeniach USB, które zostały podłączone do obrazu.

![setupapi - USB Detective: USBDetective można użyć do uzyskania informacji o urządzeniach USB, które zostały podłączone do obrazu](<../../../images/image (452).png>)

### Plug and Play Cleanup

Zaplanowane zadanie znane jako „Plug and Play Cleanup” służy głównie do usuwania nieaktualnych wersji sterowników. Wbrew określonemu celowi, jakim jest zachowanie najnowszej wersji pakietu sterownika, źródła internetowe sugerują, że zadanie obejmuje również sterowniki, które były nieaktywne przez 30 dni. W związku z tym sterowniki urządzeń wymiennych, które nie były podłączane w ciągu ostatnich 30 dni, mogą zostać usunięte.<sup>[[1]](#references)</sup>

Zadanie znajduje się pod następującą ścieżką: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Poniżej przedstawiono zrzut ekranu zawartości zadania: ![USB Detective - Plug and Play Cleanup: Zadanie znajduje się pod następującą ścieżką: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Główne komponenty i ustawienia zadania:**

- **pnpclean.dll**: Ta biblioteka DLL odpowiada za właściwy proces czyszczenia.
- **UseUnifiedSchedulingEngine**: Ustawione na `TRUE`, co oznacza użycie ogólnego mechanizmu planowania zadań.
- **MaintenanceSettings**:
- **Period ('P1M')**: Nakazuje Task Scheduler uruchamiać zadanie czyszczenia co miesiąc podczas standardowej konserwacji automatycznej.
- **Deadline ('P2M')**: Nakazuje Task Scheduler, jeśli zadanie nie powiedzie się przez dwa kolejne miesiące, uruchomić je podczas awaryjnej konserwacji automatycznej.

Taka konfiguracja zapewnia regularną konserwację i czyszczenie sterowników, a także umożliwia ponowienie zadania w przypadku kolejnych niepowodzeń.

**Więcej informacji:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## E-maile

E-maile zawierają **2 interesujące części: nagłówki i treść** wiadomości. W **nagłówkach** można znaleźć informacje takie jak:

- **Kto** wysłał e-maile (adres e-mail, adres IP, serwery pocztowe, które przekierowały wiadomość)
- **Kiedy** e-mail został wysłany

Ponadto w nagłówkach `References` i `In-Reply-To` można znaleźć ID wiadomości:

![Plug and Play Cleanup - E-maile: Kiedy e-mail został wysłany](<../../../images/image (593).png>)

### Aplikacja Windows Mail

Ta aplikacja zapisuje e-maile w formacie HTML lub tekstowym. E-maile można znaleźć w podfolderach w `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. E-maile są zapisywane z rozszerzeniem `.dat`.

**Metadane** e-maili i **kontakty** można znaleźć w **bazie danych EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Zmień rozszerzenie** pliku z `.vol` na `.edb`, a następnie użyj narzędzia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), aby go otworzyć. W tabeli `Message` można zobaczyć e-maile.

### Microsoft Outlook

Gdy używane są serwery Exchange lub klienci Outlook, dostępne będą nagłówki MAPI:

- `Mapi-Client-Submit-Time`: czas systemowy wysłania e-maila
- `Mapi-Conversation-Index`: liczba wiadomości potomnych w wątku oraz znacznik czasu każdej wiadomości wątku
- `Mapi-Entry-ID`: identyfikator wiadomości.
- `Mappi-Message-Flags` i `Pr_last_Verb-Executed`: informacje o kliencie MAPI (wiadomość przeczytana? nieprzeczytana? odpowiedziano na nią? przekierowano ją? wiadomość poza biurem?)

W kliencie Microsoft Outlook wszystkie wysłane i odebrane wiadomości, dane kontaktów oraz dane kalendarza są przechowywane w pliku PST w:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Ścieżka rejestru `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` wskazuje używany plik.

Plik PST można otworzyć za pomocą narzędzia [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Aplikacja Windows Mail - Microsoft Outlook: Plik PST można otworzyć za pomocą narzędzia Kernel PST Viewer](<../../../images/image (498).png>)

### Pliki OST Microsoft Outlook

**Plik OST** jest generowany przez Microsoft Outlook po skonfigurowaniu go z serwerem **IMAP** lub **Exchange** i przechowuje informacje podobne do pliku PST. Plik ten jest synchronizowany z serwerem i zachowuje dane z **ostatnich 12 miesięcy**, do **maksymalnego rozmiaru 50 GB**. Znajduje się w tym samym katalogu co plik PST. Do wyświetlenia pliku OST można użyć narzędzia [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Odzyskiwanie załączników

Utracone załączniki można czasami odzyskać z:

- Dla **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Dla **IE11 i nowszych**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Pliki Thunderbird MBOX

**Thunderbird** używa **plików MBOX** do przechowywania danych. Znajdują się one w `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniatury obrazów

- **Windows XP i 8-8.1**: Uzyskanie dostępu do folderu zawierającego miniatury powoduje utworzenie pliku `thumbs.db` przechowującego podglądy obrazów, nawet po ich usunięciu.
- **Windows 7/10**: Plik `thumbs.db` jest tworzony, gdy folder jest otwierany przez sieć za pośrednictwem ścieżki UNC.
- **Windows Vista i nowsze**: Podglądy miniatur są przechowywane centralnie w `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, w plikach o nazwach **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) i [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) to narzędzia do wyświetlania tych plików.

### Informacje z rejestru Windows

Rejestr Windows, przechowujący obszerne dane dotyczące systemu i aktywności użytkownika, znajduje się w plikach w:

- `%windir%\System32\Config` dla różnych podkluczy `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` dla `HKEY_CURRENT_USER`.
- Windows Vista i nowsze wersje tworzą kopie zapasowe plików rejestru `HKEY_LOCAL_MACHINE` w `%Windir%\System32\Config\RegBack\`.
- Ponadto informacje o wykonywaniu programów są przechowywane w `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` od Windows Vista i Windows 2008 Server.

### Narzędzia

Niektóre narzędzia są przydatne do analizy plików rejestru:

- **Registry Editor**: Jest zainstalowany w Windows. To GUI umożliwiające nawigowanie po rejestrze Windows bieżącej sesji.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Umożliwia załadowanie pliku rejestru i nawigowanie po nim za pomocą GUI. Zawiera również Bookmarks wyróżniające klucze z interesującymi informacjami.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Ponownie, narzędzie udostępnia GUI umożliwiające nawigowanie po załadowanym rejestrze, a także zawiera plugins wyróżniające interesujące informacje w załadowanym rejestrze.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Kolejna aplikacja GUI umożliwiająca wyodrębnianie ważnych informacji z załadowanego rejestru.

### Odzyskiwanie usuniętego elementu

Po usunięciu klucza jest on oznaczany jako usunięty, ale dopóki zajmowane przez niego miejsce nie będzie potrzebne, nie zostanie usunięty. Dlatego za pomocą narzędzi takich jak **Registry Explorer** można odzyskać te usunięte klucze.

### Last Write Time

Każda para klucz-wartość zawiera **znacznik czasu** wskazujący ostatni moment jej modyfikacji.

### SAM

Plik/ul **SAM** zawiera hashe **użytkowników, grup i haseł użytkowników** systemu.

W `SAM\Domains\Account\Users` można uzyskać nazwę użytkownika, RID, ostatnie logowanie, ostatnie nieudane logowanie, licznik logowań, zasady haseł oraz czas utworzenia konta. Aby uzyskać **hashe**, potrzebny jest również plik/ul **SYSTEM**.

### Interesujące wpisy w rejestrze Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Wykonywane programy

### Podstawowe procesy Windows

W [tym artykule](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) możesz dowiedzieć się o typowych procesach Windows, aby wykrywać podejrzane zachowania.<sup>[[2]](#references)</sup>

### Ostatnie aplikacje Windows

W rejestrze `NTUSER.DAT`, w ścieżce `Software\Microsoft\Current Version\Search\RecentApps`, znajdują się podklucze z informacjami o **wykonanej aplikacji**, **ostatnim czasie** jej wykonania oraz **liczbie uruchomień**.

### BAM (Background Activity Moderator)

Możesz otworzyć plik `SYSTEM` za pomocą edytora rejestru. W ścieżce `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` znajdziesz informacje o **aplikacjach uruchamianych przez każdego użytkownika** (zwróć uwagę na `{SID}` w ścieżce) oraz o tym, **kiedy** zostały uruchomione (czas znajduje się w wartości Data rejestru).

### Windows Prefetch

Prefetching to technika, która pozwala komputerowi w tle **pobrać zasoby niezbędne do wyświetlenia treści**, do których użytkownik **może uzyskać dostęp w najbliższej przyszłości**, dzięki czemu zasoby mogą być używane szybciej.

Windows prefetch polega na tworzeniu **pamięci podręcznych wykonanych programów**, aby można je było szybciej załadować. Pamięci podręczne są tworzone jako pliki `.pf` w ścieżce `C:\Windows\Prefetch`. Limit wynosi 128 plików w XP/VISTA/WIN7 oraz 1024 pliki w Win8/Win10.

Nazwa pliku jest tworzona w formacie `{program_name}-{hash}.pf` (hash jest oparty na ścieżce i argumentach pliku wykonywalnego). W W10 pliki te są skompresowane. Należy pamiętać, że sama obecność pliku wskazuje, iż **program został w pewnym momencie uruchomiony**.

Plik `C:\Windows\Prefetch\Layout.ini` zawiera **nazwy folderów zawierających pliki objęte prefetchingiem**. Zawiera on **informacje o liczbie uruchomień**, **datach** uruchomień oraz **plikach** **otwieranych** przez program.

Do analizy tych plików można użyć narzędzia [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** ma ten sam cel co prefetch — **szybsze ładowanie programów** poprzez przewidywanie, co zostanie załadowane jako następne. Nie zastępuje jednak usługi prefetch.\
Usługa ta generuje pliki baz danych w `C:\Windows\Prefetch\Ag*.db`.

W tych bazach danych można znaleźć **nazwę** **programu**, **liczbę** jego **uruchomień**, **otwarte** **pliki**, **uzyskany dostęp** do **woluminu**, **pełną** **ścieżkę**, **przedziały czasowe** oraz **znaczniki czasu**.

Dostęp do tych informacji można uzyskać za pomocą narzędzia [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitoruje** **zasoby** **zużywane** **przez proces**. Pojawił się w systemie W8 i przechowuje dane w bazie ESE znajdującej się w `C:\Windows\System32\sru\SRUDB.dat`.

Udostępnia następujące informacje:

- AppID i ścieżka
- Użytkownik, który uruchomił proces
- Wysłane bajty
- Odebrane bajty
- Interfejs sieciowy
- Czas trwania połączenia
- Czas trwania procesu

Informacje te są aktualizowane co 60 minut.

Datę z tego pliku można uzyskać za pomocą narzędzia [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, znany również jako **ShimCache**, stanowi część **Application Compatibility Database** opracowanej przez **Microsoft** w celu rozwiązywania problemów ze zgodnością aplikacji. Ten komponent systemu rejestruje różne elementy metadanych plików, w tym:

- Pełną ścieżkę pliku
- Rozmiar pliku
- Czas ostatniej modyfikacji w ramach **$Standard_Information** (SI)
- Czas ostatniej aktualizacji ShimCache
- Flagę wykonania procesu

Dane te są przechowywane w rejestrze w określonych lokalizacjach, zależnie od wersji systemu operacyjnego:

- W XP dane są przechowywane w `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, z pojemnością 96 wpisów.
- W Server 2003 oraz w wersjach Windows 2008, 2012, 2016, 7, 8 i 10 ścieżka przechowywania to `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, z możliwością przechowywania odpowiednio 512 i 1024 wpisów.

Do parsowania przechowywanych informacji zaleca się użycie narzędzia [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Do parsowania przechowywanych informacji zaleca się użycie narzędzia AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Plik **Amcache.hve** jest zasadniczo ulem rejestru, który rejestruje szczegóły dotyczące aplikacji uruchamianych w systemie. Zwykle znajduje się w `C:\Windows\AppCompat\Programas\Amcache.hve`.

Plik ten wyróżnia się przechowywaniem informacji o niedawno uruchamianych procesach, w tym ścieżek do plików wykonywalnych i ich hashy SHA1. Informacje te są niezwykle przydatne do śledzenia aktywności aplikacji w systemie.

Do wyodrębniania i analizowania danych z **Amcache.hve** można użyć narzędzia [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Poniższe polecenie przedstawia przykład użycia AmcacheParser do sparsowania zawartości pliku **Amcache.hve** i zapisania wyników w formacie CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Wśród wygenerowanych plików CSV szczególnie wyróżnia się `Amcache_Unassociated file entries` ze względu na bogate informacje, które dostarcza na temat niepowiązanych wpisów plików.

Najciekawszym wygenerowanym plikiem CVS jest `Amcache_Unassociated file entries`.

### RecentFileCache

Ten artefakt można znaleźć wyłącznie w W7, w lokalizacji `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, i zawiera on informacje o niedawnym wykonywaniu niektórych plików binarnych.

Do parsowania pliku można użyć narzędzia [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser).

### Scheduled tasks

Można je wyodrębnić z `C:\Windows\Tasks` lub `C:\Windows\System32\Tasks` i odczytać jako XML.

### Services

Można je znaleźć w rejestrze w lokalizacji `SYSTEM\ControlSet001\Services`. Można sprawdzić, co zostanie wykonane i kiedy.

### **Windows Store**

Zainstalowane aplikacje można znaleźć w `\ProgramData\Microsoft\Windows\AppRepository\`\
To repozytorium zawiera **dziennik** z informacjami o **każdej aplikacji zainstalowanej** w systemie, znajdującymi się w bazie danych **`StateRepository-Machine.srd`**.

W tabeli Application tej bazy danych można znaleźć kolumny: "Application ID", "PackageNumber" oraz "Display Name". Kolumny te zawierają informacje o preinstalowanych i zainstalowanych aplikacjach. Można również sprawdzić, czy niektóre aplikacje zostały odinstalowane, ponieważ identyfikatory zainstalowanych aplikacji powinny być sekwencyjne.

**Zainstalowane aplikacje** można również znaleźć w ścieżce rejestru: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
**Odinstalowane** **aplikacje** znajdują się w: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Informacje pojawiające się w Windows events obejmują:

- Co się wydarzyło
- Znacznik czasu (UTC + 0)
- Użytkowników, których dotyczy zdarzenie
- Hosty, których dotyczy zdarzenie (hostname, IP)
- Uzyskane zasoby (pliki, foldery, drukarki, usługi)

Przed Windows Vista dzienniki znajdują się w `C:\Windows\System32\config`, a po Windows Vista w `C:\Windows\System32\winevt\Logs`. Przed Windows Vista dzienniki zdarzeń były w formacie binarnym, a po tej wersji systemu są w **formacie XML** i używają rozszerzenia **.evtx**.

Lokalizację plików zdarzeń można znaleźć w rejestrze SYSTEM pod adresem **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Można je wyświetlać za pomocą Windows Event Viewer (**`eventvwr.msc`**) lub innych narzędzi, takich jak [**Event Log Explorer**](https://eventlogxp.com) **lub** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Understanding Windows Security Event Logging

Zdarzenia dostępu są rejestrowane w pliku konfiguracji zabezpieczeń znajdującym się w `C:\Windows\System32\winevt\Security.evtx`. Rozmiar tego pliku można dostosować, a po osiągnięciu jego pojemności starsze zdarzenia są nadpisywane. Rejestrowane zdarzenia obejmują logowania i wylogowania użytkowników, działania użytkowników oraz zmiany ustawień zabezpieczeń, a także dostęp do plików, folderów i współdzielonych zasobów.

### Key Event IDs for User Authentication:

- **EventID 4624**: Wskazuje, że użytkownik pomyślnie przeszedł uwierzytelnianie.
- **EventID 4625**: Sygnalizuje niepowodzenie uwierzytelniania.
- **EventIDs 4634/4647**: Reprezentują zdarzenia wylogowania użytkownika.
- **EventID 4672**: Oznacza logowanie z uprawnieniami administracyjnymi.

#### Sub-types within EventID 4634/4647:

- **Interactive (2)**: Bezpośrednie logowanie użytkownika.
- **Network (3)**: Dostęp do współdzielonych folderów.
- **Batch (4)**: Wykonywanie procesów wsadowych.
- **Service (5)**: Uruchamianie usług.
- **Proxy (6)**: Uwierzytelnianie proxy.
- **Unlock (7)**: Odblokowanie ekranu za pomocą hasła.
- **Network Cleartext (8)**: Transmisja hasła w postaci jawnego tekstu, często z IIS.
- **New Credentials (9)**: Użycie innych poświadczeń w celu uzyskania dostępu.
- **Remote Interactive (10)**: Logowanie przez Remote Desktop lub terminal services.
- **Cache Interactive (11)**: Logowanie przy użyciu zapisanych w cache poświadczeń bez kontaktu z domain controller.
- **Cache Remote Interactive (12)**: Zdalne logowanie przy użyciu zapisanych w cache poświadczeń.
- **Cached Unlock (13)**: Odblokowanie przy użyciu zapisanych w cache poświadczeń.

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: Nazwa użytkownika nie istnieje - Może wskazywać na username enumeration attack.
- **0xC000006A**: Prawidłowa nazwa użytkownika, ale nieprawidłowe hasło - Możliwe password guessing lub brute-force attempt.
- **0xC0000234**: Konto użytkownika zostało zablokowane - Może nastąpić po brute-force attack skutkującym wieloma nieudanymi logowaniami.
- **0xC0000072**: Konto jest wyłączone - Nieautoryzowane próby uzyskania dostępu do wyłączonych kont.
- **0xC000006F**: Logowanie poza dozwolonym czasem - Wskazuje na próby uzyskania dostępu poza ustalonymi godzinami logowania, co może oznaczać nieautoryzowany dostęp.
- **0xC0000070**: Naruszenie ograniczeń stacji roboczej - Może oznaczać próbę logowania z nieautoryzowanej lokalizacji.
- **0xC0000193**: Wygaśnięcie konta - Próby uzyskania dostępu przy użyciu wygasłych kont użytkowników.
- **0xC0000071**: Wygasłe hasło - Próby logowania przy użyciu nieaktualnych haseł.
- **0xC0000133**: Problemy z synchronizacją czasu - Duże różnice czasu między klientem a serwerem mogą wskazywać na bardziej zaawansowane ataki, takie jak pass-the-ticket.
- **0xC0000224**: Wymagana jest obowiązkowa zmiana hasła - Częste obowiązkowe zmiany mogą sugerować próbę destabilizacji bezpieczeństwa konta.
- **0xC0000225**: Wskazuje raczej na błąd systemu niż problem z bezpieczeństwem.
- **0xC000015b**: Odmowa typu logowania - Próba uzyskania dostępu przy użyciu nieautoryzowanego typu logowania, np. gdy użytkownik próbuje wykonać logowanie usługi.

#### EventID 4616:

- **Time Change**: Modyfikacja czasu systemowego, która może zacierać chronologię zdarzeń.

#### EventID 6005 and 6006:

- **System Startup and Shutdown**: EventID 6005 wskazuje uruchomienie systemu, natomiast EventID 6006 oznacza jego zamknięcie.

#### EventID 1102:

- **Log Deletion**: Wyczyszczenie dzienników zabezpieczeń, co często jest sygnałem ostrzegawczym wskazującym na próbę ukrycia nielegalnych działań.

#### EventIDs for USB Device Tracking:

- **20001 / 20003 / 10000**: Pierwsze podłączenie urządzenia USB.
- **10100**: Aktualizacja sterownika USB.
- **EventID 112**: Czas podłączenia urządzenia USB.

Praktyczne przykłady symulowania tych typów logowania i możliwości credential dumping można znaleźć w [szczegółowym przewodniku Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Szczegóły zdarzeń, w tym kody statusu i podstatusu, dostarczają dodatkowych informacji o przyczynach zdarzeń, co jest szczególnie istotne w przypadku Event ID 4625.

### Recovering Windows Events

Aby zwiększyć szanse na odzyskanie usuniętych Windows Events, zaleca się wyłączenie podejrzanego komputera przez bezpośrednie odłączenie go od zasilania. Do prób odzyskania takich zdarzeń zalecane jest narzędzie **Bulk_extractor**, z określonym rozszerzeniem `.evtx`.

### Identifying Common Attacks via Windows Events

Kompleksowy przewodnik dotyczący wykorzystania Windows Event IDs do identyfikowania typowych cyberataków znajduje się na stronie [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Można je rozpoznać po wielu rekordach EventID 4625, po których następuje EventID 4624, jeśli atak zakończy się powodzeniem.

#### Time Change

Rejestrowane przez EventID 4616 zmiany czasu systemowego mogą utrudniać analizę śledczą.

#### USB Device Tracking

Przydatne System EventIDs do śledzenia urządzeń USB obejmują 20001/20003/10000 dla pierwszego użycia, 10100 dla aktualizacji sterownika oraz EventID 112 z DeviceSetupManager dla znaczników czasu podłączenia.

#### System Power Events

EventID 6005 wskazuje uruchomienie systemu, natomiast EventID 6006 oznacza jego zamknięcie.

#### Log Deletion

Security EventID 1102 sygnalizuje usunięcie dzienników, co jest kluczowym zdarzeniem w analizie śledczej.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
