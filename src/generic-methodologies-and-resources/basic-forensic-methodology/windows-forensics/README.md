# Artefakty Windows

{{#include ../../../banners/hacktricks-training.md}}

## Ogólne artefakty Windows

### Powiadomienia Windows 10

Baza danych powiadomień dla poszczególnych użytkowników znajduje się w `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (na przykład `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Wczesne wydania Windows 10 używały pliku `appdb.dat`; w aktualizacji Anniversary Update (1607) wprowadzono plik `wpndatabase.db`. Baza SQLite zawiera tabelę `Notification` z treściami powiadomień i polami dotyczącymi czasu, jednak zakres przechowywanych oraz dostępnych danych zależy od wydania systemu i zasad czyszczenia.<sup>[[3]](#references)</sup>

### Oś czasu

Windows Timeline to funkcja historii aktywności, która może zawierać rekordy dotyczące obsługiwanych aplikacji, dokumentów i innych aktywności użytkownika; jej zakres zależy od aplikacji i wersji Windows.<sup>[[4]](#references)</sup>

Baza danych znajduje się w `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Można ją otworzyć za pomocą SQLite lub przeanalizować przy użyciu [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), a następnie przejrzeć dane wyjściowe za pomocą [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Pliki pobrane spoza lokalnej granicy zaufania mogą zawierać **alternatywny strumień danych `Zone.Identifier`**, który zapisuje informacje o strefie i może zawierać metadane pochodzenia, takie jak URL. Jego obecność i pola zależą od źródła oraz zasad systemowych.<sup>[[6]](#references)</sup>

## **Kopie zapasowe plików**

### Kosz

W systemie Vista i nowszych **Kosz** znajduje się w folderze **`$Recycle.bin`** w katalogu głównym dysku (na przykład `C:\$Recycle.bin`).\
Po usunięciu pliku w tym folderze tworzone są 2 określone pliki:

- `$I{id}`: Informacje o pliku, w tym czas usunięcia i pierwotna ścieżka
- `$R{id}`: Zawartość pliku

![Kopie zapasowe plików - Kosz: $R{id}: Zawartość pliku](<../../../images/image (1029).png>)

Mając te pliki, można użyć narzędzia [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) do wyodrębnienia pierwotnej ścieżki i czasu usunięcia (należy użyć wersji odpowiedniej dla docelowego wydania Windows).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Kopie plików - Kosz: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Kopie woluminów w tle

Volume Shadow Copy Service (VSS) może tworzyć kopie woluminów w określonym momencie, gdy pliki są używane; kopia w tle nie zastępuje obrazu kryminalistycznego.<sup>[[8]](#references)</sup>

Metadane kopii są zwykle powiązane z `\System Volume Information` w katalogu głównym woluminu, a identyfikatory różnią się w zależności od systemu:

![Kosz - Kopie woluminów w tle: Te kopie zapasowe zwykle znajdują się w System Volume Information w katalogu głównym systemu plików, a ich nazwa składa się z identyfikatorów UID pokazanych na...](<../../../images/image (94).png>)

Po zamontowaniu obrazu za pomocą odpowiedniego narzędzia do montowania obrazów kryminalistycznych [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) może wyliczyć dostępne migawki VSS oraz przeglądać lub kopiować z nich pliki.<sup>[[9]](#references)</sup>

![Kosz - Kopie woluminów w tle: Po zamontowaniu obrazu kryminalistycznego za pomocą ArsenalImageMounter narzędzie ShadowCopyView może zostać użyte do zbadania kopii w tle, a nawet wyodrębnienia plików...](<../../../images/image (576).png>)

Konfiguracja rejestracyjnego składnika VSS zapisującego dane obejmuje `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, gdzie można określić pliki i klucze wykluczone z kopii zapasowej:<sup>[[10]](#references)[[11]](#references)</sup>

![Kosz - Kopie woluminów w tle: Wpis rejestru HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore zawiera pliki i klucze, których nie należy uwzględniać w kopii zapasowej](<../../../images/image (254).png>)

Klucz `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` również zawiera konfigurację usługi VSS.<sup>[[8]](#references)</sup>

### Automatycznie zapisane pliki Office

Lokalizacje funkcji AutoRecover różnią się w zależności od aplikacji Office, wersji i konfiguracji. W przypadku Word firma Microsoft wskazuje `%APPDATA%\Microsoft\Word` jako lokalizację domyślną; aktywną ścieżkę należy sprawdzić w ustawieniach aplikacji.<sup>[[12]](#references)</sup>

## Elementy powłoki

Element powłoki to element zawierający informacje o sposobie dostępu do innego pliku.

### Ostatnio używane dokumenty (LNK)

Windows często tworzy skróty do ostatnio używanych elementów, gdy użytkownik otwiera element lub uzyskuje do niego dostęp w inny sposób:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Dostęp do folderu może również powodować tworzenie łączy dla tego folderu i powiązanych folderów nadrzędnych.

Te pliki łączy mogą zawierać typ elementu docelowego, czasy MAC elementu docelowego, informacje o woluminie oraz ścieżkę elementu docelowego. Te metadane mogą pomóc w identyfikacji usuniętego elementu docelowego, ale sam artefakt nie stanowi dowodu, że element docelowy został otwarty przez konkretnego użytkownika.<sup>[[13]](#references)[[14]](#references)</sup>

Znaczniki czasu systemu plików samego pliku LNK i osadzone w nim znaczniki czasu elementu docelowego są odrębne. Nie należy interpretować utworzenia łącza jako pierwszego użycia ani modyfikacji łącza jako ostatniego użycia bez potwierdzających artefaktów; format przechowuje znaczniki czasu elementu docelowego oddzielnie od znaczników czasu pliku łącza.<sup>[[13]](#references)[[14]](#references)</sup>

Istniejący link do [**LinkParser**](http://4discovery.com/our-tools/) pozostawiono jako opcję historyczną, ale podczas przeglądu dokumentacja nie była dostępna. W przypadku udokumentowanego parsera działającego w wierszu poleceń użyj [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Te narzędzia zwykle udostępniają dwa zestawy znaczników czasu:

- **Znaczniki czasu elementu docelowego:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Znaczniki czasu pliku łącza:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Pierwszy zestaw odnosi się do elementu docelowego, a drugi do samego pliku LNK. Oba zestawy należy interpretować zgodnie z dokumentacją parsera i kontekstem systemu plików.<sup>[[14]](#references)[[15]](#references)</sup>

Te same informacje można uzyskać, uruchamiając narzędzie Windows CLI: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
W tym przypadku informacje zostaną zapisane w pliku CSV.

### Jumplists

Jump Lists to listy elementów ostatnio używanych lub związanych z określonymi zadaniami, przypisane do poszczególnych aplikacji; mogą być automatyczne lub niestandardowe.<sup>[[13]](#references)</sup>

Automatyczne Jump Lists są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` i używają nazw takich jak `{id}.automaticDestinations-ms`, gdzie ID identyfikuje aplikację.

Niestandardowe Jump Lists są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; aplikacja kontroluje, które wpisy zadań lub elementów tworzy.

Czasy utworzenia i modyfikacji systemu plików opisują plik Jump List, a nie automatycznie pierwszy i ostatni dostęp do każdego wymienionego celu. Skoreluj przeanalizowane wpisy ze znacznikami czasu pliku oraz innymi artefaktami.<sup>[[13]](#references)</sup>

Jump Lists można sprawdzać za pomocą [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Ostatnie dokumenty (LNK) - Jumplists: Jump Lists można sprawdzać za pomocą JumplistExplorer](<../../../images/image (168).png>)

(_Należy pamiętać, że znaczniki czasu podawane przez JumplistExplorer dotyczą samego pliku jumplist_)

### Shellbags

[**Kliknij ten link, aby dowiedzieć się, czym są shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Użycie urządzeń USB w Windows

Użycie USB można czasami potwierdzić za pomocą artefaktów tworzonych podczas uzyskiwania dostępu do plików z nośników wymiennych, w tym:

- Folder Windows Recent
- Folder Microsoft Office Recent
- Jumplists

Narzędzia takie jak [**USBDetective**](https://usbdetective.com) korelują te artefakty z rekordami urządzeń USB, ale dostępność artefaktów zależy od wersji Windows i aplikacji.<sup>[[18]](#references)</sup>

W testach udokumentowanych dla przepływów pracy MTP w Windows XP i Windows 7 niektóre pliki LNK wskazywały na folder `WPDNSE` zamiast na oryginalną ścieżkę.<sup>[[16]](#references)</sup>

![Shellbags - Użycie urządzeń USB w Windows: Należy zauważyć, że niektóre pliki LNK zamiast wskazywać na oryginalną ścieżkę wskazują na folder WPDNSE](<../../../images/image (218).png>)

W tym badaniu zaobserwowano kopie w lokalizacji `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; w przeprowadzonych testach zawartość tymczasowa nie przetrwała ponownego uruchomienia, a GUID można było skorelować z danymi shellbag. Należy traktować to jako zachowanie zależne od systemu operacyjnego, urządzenia i aplikacji, a nie jako uniwersalną regułę.<sup>[[16]](#references)</sup>

### Informacje z rejestru

[Sprawdź tę stronę, aby dowiedzieć się](interesting-windows-registry-keys.md#usb-information), które klucze rejestru zawierają interesujące informacje o podłączonych urządzeniach USB.

### setupapi

W systemach Vista i nowszych sprawdź `C:\Windows\inf\setupapi.dev.log` pod kątem aktywności związanej z instalacją urządzeń. Nagłówki sekcji zawierają znaczniki czasu `Section start`; dokumentują one przetwarzanie instalacji i powinny być korelowane z innymi dowodami połączenia, a nie traktowane jako dokładny czas fizycznego podłączenia urządzenia.<sup>[[17]](#references)</sup>

![Informacje z rejestru - setupapi: Sprawdź plik C: Windows inf setupapi.dev.log, aby uzyskać znaczniki czasu informujące, kiedy zostało utworzone połączenie USB (wyszukaj Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) może służyć do uzyskiwania informacji o urządzeniach USB, które zostały podłączone do obrazu.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective może służyć do uzyskiwania informacji o urządzeniach USB, które zostały podłączone do obrazu](<../../../images/image (452).png>)

### Plug and Play Cleanup

Zaplanowane zadanie znane jako `Plug and Play Cleanup` usuwa nieaktualne wersje sterowników. Udokumentowana przez Adama Harrisona definicja zadania w Windows 10 obejmuje również sterowniki nieaktywne przez 30 dni, dlatego dowody dotyczące sterowników urządzeń wymiennych mogą zostać usunięte; przed uogólnieniem tego zachowania należy potwierdzić lokalną definicję zadania i kompilację Windows.<sup>[[1]](#references)</sup>

Zadanie znajduje się pod następującą ścieżką: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Definicja XML zaplanowanego zadania Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Kluczowe komponenty i ustawienia zadania:**

- **pnpclean.dll**: Ta biblioteka DLL odpowiada za właściwy proces czyszczenia.
- **UseUnifiedSchedulingEngine**: Ustawione na `TRUE`, co wskazuje na użycie ogólnego silnika planowania zadań.
- **MaintenanceSettings**:
- **Period ('P1M')**: Nakazuje Task Scheduler uruchamiać zadanie czyszczenia co miesiąc podczas standardowej Automatic maintenance.
- **Deadline ('P2M')**: Nakazuje Task Scheduler, jeśli zadanie nie powiedzie się przez dwa kolejne miesiące, uruchomić je podczas awaryjnej Automatic maintenance.

Ta konfiguracja planuje regularną konserwację i ponawia próbę po kolejnych niepowodzeniach; dokładny kod XML i zachowanie zależą od wersji.<sup>[[1]](#references)</sup>

**Więcej informacji znajdziesz tutaj:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Wiadomości e-mail

Wiadomości e-mail zawierają **2 interesujące części: nagłówki i treść** wiadomości. W **nagłówkach** można znaleźć informacje takie jak:

- **Kto** wysłał wiadomości e-mail (adres e-mail, adres IP, serwery pocztowe, które przekierowały wiadomość)
- **Kiedy** wiadomość e-mail została wysłana

Ponadto nagłówki `References` i `In-Reply-To` mogą zawierać identyfikatory wiadomości używane do powiązania odpowiedzi z rozmową.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Wiadomości e-mail: Kiedy wiadomość e-mail została wysłana](<../../../images/image (593).png>)

### Windows Mail App

Ta aplikacja zapisuje treść wiadomości e-mail w pomocniczych plikach tekstowych lub HTML w ścieżkach takich jak `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; dokładny układ numerowanych folderów i plików może różnić się w zależności od artefaktu.<sup>[[75]](#references)</sup>

**Metadane** wiadomości e-mail oraz **kontakty** można znaleźć w **bazie ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` używa formatu Extensible Storage Engine (ESE). Pracuj na kopii i użyj parsera ESE, takiego jak [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); jeśli narzędzie wymaga sufiksu `.edb`, zmień nazwę wyłącznie kopii i zweryfikuj schemat tabeli przed poleganiem na tabeli `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Podczas sprawdzania właściwości MAPI programu Outlook do właściwości kanonicznych należą:

- `PidTagClientSubmitTime`: czas UTC, w którym klient przesłał wiadomość.
- `PidTagConversationIndex`: względna pozycja wiadomości w wątku rozmowy.
- `PidTagEntryId`: identyfikator obiektu wiadomości.
- `PidTagMessageFlags`: flagi statusu, takie jak wysłana, przeczytana, nieprzeczytana lub zawierająca załączniki.
- `PidTagLastVerbExecuted`: ostatnia operacja zarejestrowana dla wiadomości, taka jak otwarcie, odpowiedź lub przekazanie dalej.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Lokalizacje plików danych programu Outlook różnią się w zależności od wersji i typu konta. Microsoft dokumentuje następujące typowe lokalizacje plików PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Ścieżka rejestru `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` może identyfikować profil Outlook oraz powiązaną konfigurację plików danych.

Pliki PST mogą zawierać wiadomości, kontakty, dane kalendarza oraz inne elementy Outlook. Kopię można sprawdzić za pomocą [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Plik PST można otworzyć za pomocą narzędzia Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**Plik OST** to lokalna pamięć podręczna dla kont Exchange lub Microsoft 365; Cached Exchange Mode nie dotyczy kont POP ani IMAP. Okres przechowywania danych offline można konfigurować i często domyślnie wynosi on 12 miesięcy, natomiast limity rozmiaru PST/OST są niezależnymi ustawieniami konfigurowalnymi. Do wyświetlenia pliku OST można użyć [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Odzyskiwanie załączników

Utracone załączniki mogą być możliwe do odzyskania z:

- W przypadku starszych konfiguracji Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- W przypadku nowszych konfiguracji Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Pliki Thunderbird MBOX

**Thunderbird** przechowuje dane profilu w `%APPDATA%\Thunderbird\Profiles`; foldery pocztowe zwykle używają plików mbox bez rozszerzenia, znajdujących się w katalogach `Mail` lub `ImapMail` właściwych dla danego konta.<sup>[[29]](#references)[[30]](#references)</sup>

### Miniatury obrazów

- **Windows XP**: Podglądy miniatur były zwykle przechowywane w plikach `thumbs.db` dla poszczególnych folderów.
- **Foldery sieciowe**: Plik `thumbs.db` może nadal być tworzony dla folderu UNC, gdy włączone jest odpowiednie zachowanie dotyczące miniatur; nie należy zakładać, że każda wersja Windows lub każda zasada tworzy taki plik.
- **Windows Vista i nowsze**: Systemowa pamięć podręczna miniatur jest scentralizowana w `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, w plikach takich jak **thumbcache_xxx.db**. Narzędzie [**Thumbsviewer**](https://thumbsviewer.github.io) może analizować starsze pliki `Thumbs.db`, a [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) może analizować nowoczesne bazy danych pamięci podręcznej miniatur.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Informacje z rejestru Windows

Rejestr Windows, przechowujący dane konfiguracji systemu i użytkowników, znajduje się w plikach hive w:

- `%WINDIR%\System32\Config` dla hive komputera obsługujących różne podklucze `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` dla hive użytkownika `HKEY_CURRENT_USER`.
- Niektóre starsze instalacje Windows zawierają kopie w `%WINDIR%\System32\Config\RegBack\`; Windows 10 w wersji 1803 i nowszych nie wypełnia automatycznie tego katalogu, chyba że włączono okresowe tworzenie kopii zapasowych.<sup>[[34]](#references)[[35]](#references)</sup>
- Dane shell i rejestracji klas dla poszczególnych użytkowników są również zwykle przechowywane w `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` we współczesnych systemach Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Narzędzia

Niektóre narzędzia są przydatne do analizowania hive rejestru; przed poleganiem na wynikach należy potwierdzić obsługiwane przez każde narzędzie formaty hive i wersję:

- **Registry Editor**: Jest zainstalowany w Windows. To GUI umożliwiający nawigowanie po rejestrze Windows bieżącej sesji.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Umożliwia załadowanie pliku rejestru i nawigowanie po nim za pomocą GUI. Zawiera również zakładki wyróżniające klucze z interesującymi informacjami.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Ponownie, zawiera GUI umożliwiające nawigowanie po załadowanym rejestrze, a także pluginy wyróżniające interesujące informacje w załadowanym rejestrze.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Kolejna aplikacja GUI umożliwiająca wyodrębnianie informacji z załadowanego hive rejestru.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Odzyskiwanie usuniętego elementu

Usunięte komórki hive mogą pozostać do czasu ponownego wykorzystania zajmowanego przez nie miejsca, ale odzyskiwanie zależy od stanu hive i parsera; odzyskane usunięte klucze należy traktować jako dowody wymagające weryfikacji, a nie jako gwarantowane rekordy.

### Czas ostatniego zapisu

Klucze rejestru zawierają znacznik czasu ostatniego zapisu; Windows udostępnia go dla klucza lub dowolnego z jego wpisów wartości, dlatego wartość nie musi mieć własnego, niezależnego znacznika czasu modyfikacji.<sup>[[69]](#references)</sup>

### SAM

Hive **SAM** zawiera dane lokalnych kont użytkowników i grup, w tym hashe haseł chronione za pomocą materiału systemowego boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

W `SAM\Domains\Account\Users` można uzyskać identyfikatory kont oraz niektóre pola logowania i zasad. Offline extraction hashy wymaga również hive `SYSTEM` w celu odzyskania odpowiedniego materiału boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

### Interesujące wpisy w rejestrze Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Wykonywane programy

### Podstawowe procesy Windows

Istniejący [post dotyczący typowych procesów Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) pozostaje dodatkowym materiałem do lektury; twierdzenia dotyczące zachowania procesów należy potwierdzać w aktualnej dokumentacji Windows oraz za pomocą lokalnych dowodów.<sup>[[2]](#references)</sup>

### Windows Recent APPs

W wersjach Windows 10, które udostępniają ten artefakt, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` zawiera podklucze dla poszczególnych aplikacji z polami takimi jak czas ostatniego użycia i liczba uruchomień; artefakt usunięto z późniejszych wydań, dlatego należy zweryfikować docelową kompilację.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

W systemach udostępniających Background Activity Moderator sprawdź ścieżkę `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` lub nowszą `...\bam\State\UserSettings\{SID}`. Wartości są indeksowane według SID użytkownika i mogą zawierać ścieżki śledzonych plików wykonywalnych oraz dane wykonania podobne do FILETIME; artefakt zależy od wersji i powinien być potwierdzany innymi dowodami.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch buforuje zasoby i metadane uruchamiania, aby programy mogły uruchamiać się szybciej.

Pliki Prefetch są przechowywane jako pliki `.pf` w `C:\Windows\Prefetch`; format, przechowywanie oraz limity liczby plików różnią się w zależności od wersji Windows. Microsoft dokumentuje przechowywanie ośmiu ostatnich czasów wykonania oraz maksymalnie 1024 plików w Windows 8 i nowszych, dlatego starszych podsumowań dotyczących stałych limitów nie należy uogólniać.<sup>[[13]](#references)</sup>

Nazwa pliku zwykle ma postać `{program_name}-{hash}.pf`, gdzie hash jest wyprowadzany z kontekstu wykonania, takiego jak ścieżka i argumenty; Windows 10 i nowsze mogą kompresować ten plik. Obecność pliku jest użytecznym dowodem wykonania, ale sama w sobie nie potwierdza, że program uruchomił użytkownik, dlatego należy ją korelować z innymi artefaktami.<sup>[[13]](#references)</sup>

Do sprawdzania tych plików można użyć [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), który dokumentuje analizowanie katalogów, dane wyjściowe CSV/HTML oraz obsługę dekompresji odpowiednich plików Prefetch w Windows 10.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** uzupełnia Prefetch, wykorzystując historyczne wzorce użycia w celu usprawnienia ładowania. W systemach, które je generują, jego pliki baz danych zwykle znajdują się w `C:\Windows\Prefetch\Ag*.db`; format i obecność tych plików zależą od wersji systemu.<sup>[[41]](#references)</sup>

Te bazy danych mogą zawierać nazwy aplikacji, liczbę użyć, uzyskiwane pliki lub woluminy, ścieżki oraz zakresy czasowe, ale nie należy traktować ich jako dokładnego dziennika uruchomień.<sup>[[41]](#references)</sup>

Istniejący link do [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) pozostaje możliwym parserem; przed użyciem należy sprawdzić jego aktualną dostępność oraz obsługiwany format danych wyjściowych w dokumentacji narzędzia.

### SRUM

**System Resource Usage Monitor** (SRUM) rejestruje wykorzystanie zasobów przez aplikacje i użytkowników. Został wprowadzony w Windows 8 i przechowuje dane w bazie ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Dostarcza następujących informacji:

- AppID i ścieżka
- Użytkownik/SID powiązany z rekordem
- Wysłane bajty
- Odebrane bajty
- Interfejs sieciowy
- Czas trwania połączenia
- Czas trwania procesu

Częstotliwość gromadzenia danych i ich retencja zależą od implementacji; nie należy zakładać, że każdy rekord reprezentuje dokładny 60-minutowy przedział wykonywania.<sup>[[13]](#references)</sup>

Dane można wyodrębniać i analizować za pomocą [**srum_dump**](https://github.com/MarkBaggett/srum-dump), korzystając z opcji udokumentowanych dla bieżącej wersji narzędzia.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, znany również jako **ShimCache**, jest częścią infrastruktury zgodności aplikacji systemu Windows i rejestruje metadane plików na potrzeby decyzji dotyczących zgodności. Ścieżka ula, format rekordów, zachowywana pojemność i pola różnią się w zależności od wersji systemu Windows; we współczesnym systemie Windows sam ShimCache nie może potwierdzić, że użytkownik wykonał plik. Przeanalizuj odpowiedni ul `SYSTEM` za pomocą narzędzia [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) i potwierdź jego dane za pomocą artefaktów wykonania.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Do przeanalizowania zapisanych informacji zaleca się użycie narzędzia AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Plik **Amcache.hve** jest ulem rejestru, który tworzy spis aplikacji i plików zaobserwowanych przez system Windows. Zwykle znajduje się w lokalizacji `C:\Windows\AppCompat\Programs\Amcache.hve`.

Może zawierać powiązane i niepowiązane wpisy plików, ścieżki oraz wartości SHA1, ale jego obecność jest dowodem inwentaryzacyjnym i sama w sobie nie potwierdza, że proces został wykonany.<sup>[[13]](#references)[[44]](#references)</sup>

Do wyodrębniania i analizowania pliku **Amcache.hve** użyj narzędzia [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). To polecenie analizuje ul i zapisuje dane wyjściowe w formacie CSV.<sup>[[44]](#references)</sup>

Na przykład:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Wśród wygenerowanych plików CSV `Amcache_Unassociated file entries` może być przydatny podczas badania plików, które nie są powiązane z rozpoznanym programem.<sup>[[44]](#references)</sup>

### RecentFileCache

W systemach Windows 7 plik `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` może zawierać informacje o ostatnio zaobserwowanych plikach binarnych; jego dostępność i znaczenie zależą od wersji systemu.

Do parsowania pliku można użyć narzędzia [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser).<sup>[[45]](#references)</sup>

### Zaplanowane zadania

Ślady zaplanowanych zadań mogą znajdować się w `C:\Windows\System32\Tasks` w przypadku nowoczesnych zadań oraz w `C:\Windows\Tasks` w postaci plików `.job` w przypadku zadań starszego typu; należy sprawdzić format definicji zadań właściwy dla danego systemu operacyjnego.<sup>[[73]](#references)[[74]](#references)</sup>

### Usługi

Baza danych Service Control Manager znajduje się w `SYSTEM\CurrentControlSet\Services` (w przypadku offline'owego ula SYSTEM należy sprawdzić odpowiadający mu klucz control-set); zawiera konfigurację usług i sterowników, taką jak ścieżki plików wykonywalnych i typy uruchamiania.<sup>[[72]](#references)</sup>

### **Windows Store**

Zainstalowane aplikacje Windows Store mogą być reprezentowane w `\ProgramData\Microsoft\Windows\AppRepository\`, w tym w bazie danych **`StateRepository-Machine.srd`**. Schemat i ścieżki różnią się w zależności od wydania Windows.<sup>[[71]](#references)</sup>

Baza danych może zawierać identyfikatory aplikacji, numery pakietów i nazwy wyświetlane. Luki w identyfikatorach nie są same w sobie dowodem odinstalowania aplikacji; należy je potwierdzić za pomocą stanu pakietów i rejestru.

Rejestracje pakietów mogą również pojawiać się w `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft opisuje zależny od wersji podklucz `Deprovisioned` dla usuniętych aplikacji provisioned; nie należy zakładać, że podklucz `Deleted` istnieje w każdej kompilacji.<sup>[[70]](#references)</sup>

## Windows Events

W zależności od providera zdarzenia Windows mogą zawierać:

- Co się wydarzyło
- Sygnaturę czasową `TimeCreated`, którą należy interpretować na podstawie schematu zdarzenia i kontekstu czasu systemowego hosta
- Zaangażowanych użytkowników
- Zaangażowane hosty (hostname, IP)
- Uzyskane zasoby (pliki, foldery, drukarki lub usługi).<sup>[[49]](#references)</sup>

Przed Windows Vista dzienniki zdarzeń zazwyczaj używały starszego formatu binarnego w `C:\Windows\System32\config`; Windows Vista i nowsze wersje używają formatu Windows Event Log, zwykle w `C:\Windows\System32\winevt\Logs`, gdzie pliki `.evtx` zawierają dane zdarzeń renderowane jako XML.<sup>[[46]](#references)[[47]](#references)</sup>

Rejestr SYSTEM przechowuje konfigurację kanałów w **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, w tym skonfigurowaną ścieżkę pliku i ustawienia przechowywania.<sup>[[47]](#references)</sup>

Można je przeglądać za pomocą Windows Event Viewer (**`eventvwr.msc`**) lub narzędzi takich jak [**Event Log Explorer**](https://eventlogxp.com) i [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

W systemach Vista i nowszych kanał Security jest zwykle przechowywany w `C:\Windows\System32\winevt\Logs\Security.evtx`. Jego maksymalny rozmiar i zasady przechowywania można konfigurować; przy logowaniu cyklicznym starsze rekordy mogą zostać nadpisane po osiągnięciu przez plik limitu. Kanał może rejestrować zdarzenia uwierzytelniania, wylogowania, uprawnień, zasad audytu i dostępu do obiektów, jeśli włączono odpowiedni auditing.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: Pomyślne logowanie do konta.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Nieudane logowanie do konta.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Sesja logowania została zakończona.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Użytkownik zainicjował wylogowanie.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Do nowego logowania przypisano specjalne uprawnienia; jest to częste w przypadku kont systemowych i administratorów, więc samo w sobie nie stanowi dowodu złośliwej aktywności.<sup>[[54]](#references)</sup>

#### Typy logowania często rejestrowane w 4624, 4625, 4634 i 4647:

- **Interactive (2)**: Interaktywne logowanie lokalne.
- **Network (3)**: Dostęp do współdzielonego zasobu.
- **Batch (4)**: Logowanie procesu wsadowego.
- **Service (5)**: Logowanie usługi.
- **Unlock (7)**: Odblokowanie stacji roboczej.
- **NetworkCleartext (8)**: Logowanie sieciowe, podczas którego dane uwierzytelniające są przekazywane do pakietu uwierzytelniającego w postaci jawnego tekstu.
- **NewCredentials (9)**: Logowanie z użyciem podanych alternatywnych danych uwierzytelniających dla połączeń wychodzących.
- **RemoteInteractive (10)**: Logowanie przez Remote Desktop lub Terminal Services.
- **CachedInteractive (11)**: Interaktywne logowanie z użyciem buforowanych danych uwierzytelniających domeny.
- **CachedRemoteInteractive (12)**: Buforowane logowanie zdalnie interaktywne.
- **CachedUnlock (13)**: Odblokowanie z użyciem buforowanych danych uwierzytelniających.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: Nie ma takiego użytkownika.
- **0xC000006A**: Prawidłowa nazwa użytkownika, ale nieprawidłowe hasło.
- **0xC0000234**: Konto zostało zablokowane.
- **0xC0000072**: Konto jest wyłączone.
- **0xC000006F**: Logowanie poza dozwolonymi godzinami.
- **0xC0000070**: Naruszenie ograniczenia stacji roboczej.
- **0xC0000193**: Konto wygasło.
- **0xC0000071**: Hasło wygasło.
- **0xC0000133**: Różnica czasu między klientem a serwerem jest zbyt duża.
- **0xC0000224**: Konto musi zmienić hasło.
- **0xC0000225**: `STATUS_NOT_FOUND`; sam kod nie wskazuje na błąd systemu ani atak.
- **0xC000015B**: Żądany typ logowania nie został przyznany kontu.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Zmieniono czas systemowy. Wiele zdarzeń odzwierciedla rutynową korektę usługi czasu, dlatego przed uznaniem tego za manipulację należy skorelować sprawcę i źródło czasu.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 i 6009:

- **Power and service context**: Zdarzenie 12 rejestruje uruchomienie systemu operacyjnego, 13 jego zamknięcie, 1074 planowane zamknięcie lub ponowne uruchomienie, 6008 nieoczekiwane zamknięcie, a 6009 rejestruje wersję Windows podczas uruchamiania. Zdarzenia 6005 i 6006 wskazują odpowiednio na uruchomienie i zatrzymanie usługi Event Log; same w sobie nie są dowodem uruchomienia ani zamknięcia systemu operacyjnego.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Zdarzenie 1102 rejestruje wyczyszczenie dziennika audytu Security; należy zbadać sprawcę i sąsiednie zdarzenia, zamiast wyciągać wnioski o zamiarze wyłącznie na podstawie tego zdarzenia.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: Zdarzenia instalacji urządzeń `UserPnp`, które mogą pomóc ustalić pierwsze użycie lub aktywność instalacyjną.
- **10000 / 10100**: Zdarzenia `DriverFrameworks-UserMode`, które mogą towarzyszyć aktywności urządzenia.
- **Event ID 112**: Aktywność `DeviceSetupManager/Admin`, która może dostarczyć sygnatur czasowych związanych z podłączeniem.
- Provider, kanał i znaczenie zdarzeń różnią się w zależności od wersji Windows; przed przypisaniem znaczenia należy sprawdzić nazwę providera i dane zdarzenia.<sup>[[59]](#references)</sup>

Praktyczne przykłady typów logowania i powiązanych z nimi danych uwierzytelniających można znaleźć w [szczegółowym przewodniku Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Szczegóły zdarzenia, w tym typ logowania, status, podstatus, adres źródłowy i pola procesu, dostarczają kontekstu dla Event ID 4625; kod statusu lub powtarzający się wzorzec niepowodzeń jest wskazówką do dalszego badania, a nie wnioskiem.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Ponieważ dzienniki zdarzeń często działają cyklicznie, rekordy nadpisane przez logger mogą być niemożliwe do odzyskania. Przed interakcją z działającym systemem należy zabezpieczyć obraz forensic lub kopię roboczą; zwalidowanego parsera lub carvera, takiego jak **Bulk_extractor**, należy używać dopiero po potwierdzeniu, że wersja narzędzia obsługuje docelowe dane `.evtx`; nie należy odłączać działającego systemu wyłącznie w celu próby odzyskania zdarzeń.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Praktyczne zestawienie identyfikatorów zdarzeń można znaleźć w istniejącym odnośniku [Red Team Recipe](https://redteamrecipe.com/event-codes/); jego przykłady należy zweryfikować w dokumentacji providerów powyżej.

#### Brute Force Attacks

Należy skorelować powtarzające się nieudane próby Event ID 4625 z późniejszym pomyślnym zdarzeniem 4624, typem logowania, statusem, źródłem i kontekstem konta; sekwencja ta jest wskaźnikiem wymagającym zbadania, a nie dowodem ataku.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 rejestruje zmiany czasu systemowego, które mogą komplikować analizę osi czasu; należy porównać je z informacjami o usłudze czasu i danymi hosta.<sup>[[56]](#references)</sup>

#### USB Device Tracking

Identyfikatory zdarzeń USB zależą od providera; należy skorelować `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 i `DeviceSetupManager/Admin` 112 ze śladami SetupAPI i rejestru.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Należy użyć 12/13/1074/6008/6009 w celu ustalenia kontekstu uruchomienia, zamknięcia, ponownego uruchomienia systemu operacyjnego i nieoczekiwanej utraty zasilania; 6005/6006 oznaczają uruchomienie/zatrzymanie usługi Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 rejestruje wyczyszczenie dziennika audytu Security i powinien zostać skorelowany z odpowiedzialnym kontem oraz procesem.<sup>[[62]](#references)</sup>

## References

- [1] [Czyszczenie Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Badanie typowych procesów Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Cyfrowe forensic spojrzenie na powiadomienia Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Narzędzia forensic Erica Zimmermana](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier i Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Usługa Volume Shadow Copy](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operacje tworzenia i przywracania kopii zapasowej rejestru za pomocą VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Klucze rejestru do tworzenia i przywracania kopii zapasowych](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problem z wydajnością Worda dotyczący lokalizacji AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Podręcznik Incident Response](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Binarny format pliku Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Identyfikowanie śladów eksfiltracji danych](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Wpisy dziennika instalacji urządzeń SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID i typy powiązane](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Znajdowanie i przenoszenie plików danych Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Włączanie Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Synchronizowany jest tylko podzbiór elementów](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Konfigurowanie limitów rozmiaru plików danych Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profile - gdzie Thunderbird przechowuje dane użytkownika](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Ustawienia kont Thunderbird i katalogi mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Interfejs IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Ule rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Rejestr systemowy nie jest tworzony w kopii RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Zdalna edycja rejestru](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Przegląd techniczny haseł](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Ślady Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Format pliku Event Log](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Klucz rejestru Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Właściwość zdarzenia TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: Wartości NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Rozwiązywanie problemów z nieoczekiwanymi restartami za pomocą dzienników zdarzeń systemowych](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Rozwiązywanie problemów z zamykaniem systemu w toku](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forensics urządzeń pamięci USB w Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Typy logowania Windows](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderator aktywności w tle](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print przestaje drukować załączniki PDF w Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Pliki rejestru Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Zapobieganie powrotowi usuniętych aplikacji podczas aktualizacji](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Wyniki testów FTK i Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Baza danych zainstalowanych usług](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks kończą się błędem „Task Scheduler Service Is Not Available”](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Poruszanie się po bazie danych Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Format wiadomości internetowych](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
