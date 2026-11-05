# Windows artefakti

{{#include ../../../banners/hacktricks-training.md}}

## Generički Windows artefakti

### Windows 10 obaveštenja

Baza podataka obaveštenja po korisniku nalazi se u `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (na primer, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Ranija izdanja Windows 10 koristila su `appdb.dat`; Anniversary Update (1607) uveo je `wpndatabase.db`. SQLite baza podataka sadrži tabelu `Notification` sa sadržajima obaveštenja i poljima za vremenske oznake, ali zadržani i dostupni podaci zavise od izdanja i pravila čišćenja.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline je funkcija za istoriju aktivnosti koja može da sadrži zapise o podržanim aplikacijama, dokumentima i drugim aktivnostima korisnika; obuhvat zavisi od aplikacije i verzije Windowsa.<sup>[[4]](#references)</sup>

Baza podataka se nalazi na putanji `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Može se otvoriti pomoću SQLite-a ili analizirati alatom [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), čiji se izlaz može pregledati pomoću alata [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### Windows Recall snimci (Copilot+ računari)

Recall je opcionalan na podržanim Windows 11 Copilot+ računarima. Trenutne verzije šifruju snimke i njihov indeks pomoću ključeva povezanih sa Windows Hello i VBS enklavom. Nemojte tretirati kopiju skladišta van mreže kao SQLite bazu podataka u otvorenom tekstu; preview verzija iz 2024. i objavljena verzija imaju različita svojstva pristupa.<sup>[[77]](#references)</sup>

U **aktivnoj Recall sesiji** u kojoj je funkcija omogućena, proces za renderovanje `AIXHost.exe` istog korisnika predstavlja zasebnu površinu za pristup. Dokaz koncepta TotalRecall Reloaded ubacuje DLL u taj proces i poziva njegove Recall COM interfejse. Za izdvajanje celokupne istorije korisnik i dalje mora da se autentifikuje pomoću Windows Hello; ovo nije dešifrovanje van mreže niti zaobilaženje Hello autentifikacije. Istraživač je dokumentovao alat na Windows 11 ARM64 sistemu, zato proverite kompatibilnost sa ciljnom verzijom pre nego što se oslonite na njega.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` koristi `GetRecentCaptureThumbnail` da zatraži veliku verziju najnovijeg snimka bez Hello. Nakon autorizacije, `--wait` može da izdvoji snimke ekrana, OCR tekst i metapodatke za svaki snimak, uključujući informacije o aplikaciji i prozoru. Izlaz se upisuje u direktorijum `extraction_*` sa vremenskom oznakom. Ovo su nalazi zavisni od verzije međuverzije, do kojih se došlo pomoću proof of concept-a; oni ne garantuju da je Recall omogućen niti da je zabeležen svaki ekran.<sup>[[78]](#references)</sup>

### ADS (Alternate Data Streams)

Datoteke preuzete izvan lokalne granice poverenja mogu da sadrže **`Zone.Identifier` alternativni tok podataka**, koji beleži informacije o zoni i može da sadrži metapodatke o poreklu, kao što je URL. Njegovo prisustvo i polja zavise od programa koji ga kreira i sistemske politike.<sup>[[6]](#references)</sup>

## **Rezervne kopije datoteka**

### Kanta za otpatke

U sistemima Vista i novijim, **Kanta za otpatke** nalazi se u fascikli **`$Recycle.bin`** u korenu diska (na primer, `C:\$Recycle.bin`).\
Kada se datoteka izbriše u ovoj fascikli, kreiraju se 2 posebne datoteke:

- `$I{id}`: Informacije o datoteci, uključujući vreme brisanja i originalnu putanju
- `$R{id}`: Sadržaj datoteke

![Rezervne kopije datoteka - Kanta za otpatke: $R{id}: Sadržaj datoteke](<../../../images/image (1029).png>)

Pomoću ovih datoteka možete koristiti [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) da izdvojite originalnu putanju i vreme brisanja (koristite verziju odgovarajuću za ciljnu verziju Windows-a).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Rezervne kopije datoteka - korpa za otpatke: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Senčene kopije volumena

Volume Shadow Copy Service (VSS) može da kreira senčene kopije volumena u određenom trenutku dok su datoteke u upotrebi; senčena kopija nije zamena za forenzičku sliku.<sup>[[8]](#references)</sup>

Metapodaci kopije obično su povezani sa `\System Volume Information` u korenu volumena, uz identifikatore koji se razlikuju od sistema do sistema:

![Korpa za otpatke - senčene kopije volumena: Ove rezervne kopije se obično nalaze u fascikli System Volume Information u korenu sistema datoteka, a naziv je sastavljen od UID-ova prikazanih na...](<../../../images/image (94).png>)

Nakon montiranja slike pomoću odgovarajućeg forenzičkog alata za montiranje, alat [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) može da prikaže dostupne VSS snimke i omogući pregledanje ili kopiranje datoteka iz njih.<sup>[[9]](#references)</sup>

![Korpa za otpatke - senčene kopije volumena: Nakon montiranja forenzičke slike pomoću ArsenalImageMounter-a, alat ShadowCopyView može da se koristi za pregled senčene kopije, pa čak i za izdvajanje datoteka...](<../../../images/image (576).png>)

Konfiguracija VSS registry writer-a obuhvata `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, gde mogu da budu navedene datoteke i ključevi izuzeti iz rezervne kopije:<sup>[[10]](#references)[[11]](#references)</sup>

![Korpa za otpatke - senčene kopije volumena: stavka registra HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore sadrži datoteke i ključeve koje ne treba uključiti u rezervnu kopiju](<../../../images/image (254).png>)

Ključ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` takođe sadrži konfiguraciju VSS usluge.<sup>[[8]](#references)</sup>

### Automatski sačuvane Office datoteke

Lokacije AutoRecover-a se razlikuju u zavisnosti od Office aplikacije, verzije i konfiguracije. Za Word, Microsoft navodi `%APPDATA%\Microsoft\Word` kao podrazumevanu lokaciju; proverite podešavanja aplikacije da biste utvrdili aktivnu putanju.<sup>[[12]](#references)</sup>

## Shell stavke

Shell stavka sadrži informacije o tome kako pristupiti drugoj datoteci.

### Nedavni dokumenti (LNK)

Windows obično kreira prečice ka nedavno korišćenim stavkama kada korisnik otvori stavku ili joj na drugi način pristupi:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Pristup fascikli može da kreira i prečice ka toj fascikli i povezanim nadređenim fasciklama.

Ove datoteke prečica mogu da sadrže tip cilja, MAC vremena cilja, informacije o volumenu i putanju cilja. Ti metapodaci mogu da pomognu u identifikovanju uklonjenog cilja, ali sam artefakt nije dokaz da je određeni korisnik otvorio cilj.<sup>[[13]](#references)[[14]](#references)</sup>

Vremenske oznake datoteke LNK u sistemu datoteka razlikuju se od vremenskih oznaka ugrađenih za cilj. Nemojte tumačiti kreiranje prečice kao prvo korišćenje, niti njenu izmenu kao poslednje korišćenje, bez potkrepljujućih artefakata; format čuva vremenske oznake cilja odvojeno od vremenskih oznaka same datoteke prečice.<sup>[[13]](#references)[[14]](#references)</sup>

Postojeća veza ka alatu [**LinkParser**](http://4discovery.com/our-tools/) zadržana je kao istorijska opcija, ali njegova dokumentacija nije bila dostupna tokom pregleda. Za dokumentovan parser komandne linije koristite [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Ovi alati obično prikazuju dva skupa vremenskih oznaka:

- **Vremenske oznake cilja:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Vremenske oznake datoteke prečice:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Prvi skup odnosi se na cilj; drugi skup odnosi se na samu datoteku LNK. Tumačite oba skupa u skladu sa dokumentacijom parsera i kontekstom sistema datoteka.<sup>[[14]](#references)[[15]](#references)</sup>

Iste informacije možete da dobijete pokretanjem Windows CLI alata: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

У овом случају, информације ће бити сачуване у CSV датотеци.

### Jumplists

Jump Lists су листе ставки које су недавно коришћене или су специфичне за одређени задатак, за сваку апликацију; могу бити аутоматске или прилагођене.<sup>[[13]](#references)</sup>

Аутоматске Jump Lists се чувају у `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` и користе називе попут `{id}.automaticDestinations-ms`, где ID идентификује апликацију.

Прилагођене Jump Lists се чувају у `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; апликација контролише које ставке задатака или елемената креира.

Времена креирања и измене у систему датотека описују саму датотеку Jump List-а, а не аутоматски први и последњи приступ свакој наведеној одредишној ставци. Упоредите парсиране ставке са временским ознакама датотеке и другим артефактима.<sup>[[13]](#references)</sup>

Jump Lists можете прегледати помоћу алатке [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Недавни документи (LNK) - Jumplists: Jump Lists можете прегледати помоћу алатке JumplistExplorer](<../../../images/image (168).png>)

(_Имајте на уму да се временске ознаке које приказује JumplistExplorer односе на саму датотеку Jump List-а_)

### Shellbags

[**Пратите ову везу да бисте сазнали шта су shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Употреба USB уређаја у Windows-у

Употреба USB уређаја понекад се може потврдити артефактима насталим приликом приступа датотекама са преносивих медија, укључујући:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Алатке као што је [**USBDetective**](https://usbdetective.com) упоређују ове артефакте са записима о USB уређајима, али доступност артефаката зависи од верзије Windows-а и апликације.<sup>[[18]](#references)</sup>

У тестовима документованим за MTP радне токове у Windows XP-у и Windows 7-у, неки LNK-ови су упућивали на фасциклу `WPDNSE` уместо на првобитну путању.<sup>[[16]](#references)</sup>

![Shellbags - Употреба USB уређаја у Windows-у: Имајте на уму да неке LNK датотеке, уместо на првобитну путању, упућују на фасциклу WPDNSE](<../../../images/image (218).png>)

У тој студији су уочене копије у фасцикли `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; привремени садржај није преживео поновно покретање у тестовима, а GUID се могао упоредити са shellbag подацима. Ово посматрајте као понашање које зависи од оперативног система, уређаја и апликације, а не као универзално правило.<sup>[[16]](#references)</sup>

### Информације из Registry-ја

[Проверите ову страницу да бисте сазнали](interesting-windows-registry-keys.md#usb-information) који registry кључеви садрже занимљиве информације о повезаним USB уређајима.

### setupapi

У Vista-и и новијим верзијама, проверите `C:\Windows\inf\setupapi.dev.log` да бисте пронашли активности инсталације уређаја. Заглавља одељака садрже временске ознаке `Section start`; она бележе обраду инсталације и треба их упоредити са другим доказима о повезивању, а не третирати као тачно време физичког прикључивања уређаја.<sup>[[17]](#references)</sup>

![Информације из Registry-ја - setupapi: Проверите датотеку C: Windows inf setupapi.dev.log да бисте добили временске ознаке када је дошло до USB повезивања (потражите Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) се може користити за добијање информација о USB уређајима који су били повезани са форензичком сликом.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective се може користити за добијање информација о USB уређајима који су били повезани са форензичком сликом](<../../../images/image (452).png>)

### Чишћење Plug and Play-а

Заказани задатак познат као `Plug and Play Cleanup` уклања застареле верзије драјвера. Дефиниција задатка за Windows 10 коју је документовао Adam Harrison такође обухвата драјвере који нису били активни 30 дана, па се докази о драјверима преносивих уређаја могу уклонити; проверите локалну дефиницију задатка и верзију Windows-а пре него што ово понашање уопштите.<sup>[[1]](#references)</sup>

Задатак се налази на следећој путањи: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![XML дефиниција заказаног задатка Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Кључне компоненте и подешавања задатка:**

- **pnpclean.dll**: Ова DLL датотека је задужена за само чишћење.
- **UseUnifiedSchedulingEngine**: Подешено на `TRUE`, што означава употребу генеричког механизма за заказивање задатака.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Налаже Task Scheduler-у да покреће задатак чишћења месечно, током редовног аутоматског одржавања.
  - **Deadline ('P2M')**: Налаже Task Scheduler-у да, ако задатак не успе два месеца узастопно, покрене задатак током ванредног аутоматског одржавања.

Ова конфигурација заказује редовно одржавање и поновне покушаје након узастопних неуспеха; тачан XML и понашање зависе од верзије.<sup>[[1]](#references)</sup>

**За више информација погледајте:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Имејлови

Имејлови садрже **2 занимљива дела: заглавља и садржај** имејла. У **заглављима** можете пронаћи информације као што су:

- **Ко** је послао имејлове (имејл адреса, IP адреса, mail сервери који су проследили имејл)
- **Када** је имејл послат

Заглавља `References` и `In-Reply-To` такође могу садржати ID-ове порука који се користе за повезивање одговора са разговором.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Имејлови: Када је имејл послат](<../../../images/image (593).png>)

### Windows Mail App

Ова апликација чува садржај имејлова у помоћним текстуалним или HTML датотекама на путањама попут `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; нумерисана фасцикла и распоред датотека могу се разликовати у зависности од артефакта.<sup>[[75]](#references)</sup>

**Метаподаци** имејлова и **контакти** могу се пронаћи у **ESE бази података** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` користи формат Extensible Storage Engine (ESE). Радите са копијом и користите ESE парсер, као што је [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); ако алатка захтева наставак `.edb`, промените назив само копији и проверите шему табеле пре него што се ослоните на табелу `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Приликом провере Outlook MAPI својстава, канонска својства обухватају:

- `PidTagClientSubmitTime`: UTC време када је клијент послао поруку.
- `PidTagConversationIndex`: релативни положај поруке у низу порука разговора.
- `PidTagEntryId`: идентификатор објекта поруке.
- `PidTagMessageFlags`: статусне заставице, попут послате, прочитане, непрочитане или са прилозима.
- `PidTagLastVerbExecuted`: последња забележена радња за поруку, попут отварања, одговарања или прослеђивања.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Локације Outlook датотека са подацима разликују се у зависности од верзије и типа налога. Microsoft наводи следеће уобичајене локације PST/OST датотека:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry путања `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` може указивати на Outlook профил и повезану конфигурацију датотека са подацима.

PST датотеке могу садржати поруке, контакте, календарске податке и друге Outlook ставке. Копију можете прегледати помоћу алатке [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: PST датотеку можете отворити помоћу алатке Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST датотеке

**OST датотека** је локални кеш за Exchange или Microsoft 365 налоге; Cached Exchange Mode се не примењује на POP или IMAP налоге. Период за чување ван мреже може се конфигурисати и често је подразумевано 12 месеци, док су ограничења величине PST/OST датотека засебна подешавања која се могу конфигурисати. За преглед OST датотеке можете користити [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Преузимање прилога

Изгубљени прилози се можда могу опоравити са следећих локација:

- За застареле Outlook/IE конфигурације: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- За новије Outlook/IE11 конфигурације: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX датотеке

**Thunderbird** чува податке профила у `%APPDATA%\Thunderbird\Profiles`; поштанске фасцикле обично користе mbox датотеке без наставка у фасциклама `Mail` или `ImapMail` специфичним за налог.<sup>[[29]](#references)[[30]](#references)</sup>

### Сличице слика

- **Windows XP**: Прегледи сличица су се обично чували у датотекама `thumbs.db` у појединачним фасциклама.
- **Мрежне фасцикле**: Датотека `thumbs.db` и даље може бити креирана за UNC фасциклу ако је омогућено одговарајуће понашање сличица; немојте претпостављати да је креира свака верзија или смерница Windows-а.
- **Windows Vista и новије верзије**: Системски кеш сличица је централизован у `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, у датотекама као што је **thumbcache_xxx.db**. Алатка [**Thumbsviewer**](https://thumbsviewer.github.io) може да парсира застареле датотеке `Thumbs.db`, док [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) може да парсира модерне базе података кеша сличица.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Информације из Windows Registry-ја

Windows Registry, који чува конфигурационе податке система и корисника, налази се у hive датотекама на следећим локацијама:

- `%WINDIR%\System32\Config` за системске hive-ове на којима се заснивају различити поткључеви `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` за корисников `HKEY_CURRENT_USER` hive.
- Неке старије инсталације Windows-а садрже копије у `%WINDIR%\System32\Config\RegBack\`; Windows 10 верзије 1803 и новије не попуњавају аутоматски овај директоријум осим ако није омогућено периодично прављење резервних копија.<sup>[[34]](#references)[[35]](#references)</sup>
- Подаци о љуску и регистрацији класа за појединачне кориснике често се чувају и у `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` у модерним верзијама Windows-а.<sup>[[34]](#references)[[66]](#references)</sup>

### Алатке

Неке алатке су корисне за анализу registry hive-ова; проверите формате hive-ова и верзије које подржава свака алатка пре него што се ослоните на њен излаз:

- **Registry Editor**: Инсталиран је у Windows-у. Ово је GUI за навигацију кроз Windows registry тренутне сесије.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Омогућава учитавање registry датотеке и навигацију кроз њу помоћу GUI-ја. Садржи и обележиваче који истичу кључеве са занимљивим информацијама.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): И ова алатка има GUI који омогућава навигацију кроз учитани registry, а садржи и додатке који истичу занимљиве информације у њему.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Још једна GUI апликација која може да издвоји информације из учитаног registry hive-а.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Опоравак обрисаних елемената

Обрисане ћелије hive-а могу остати сачуване све док се њихов простор поново не искористи, али опоравак зависи од стања hive-а и парсера; опорављене обрисане кључеве третирајте као доказе које треба проверити, а не као гарантоване записе.

### Време последњег уписа

Registry кључеви садрже временску ознаку последњег уписа; Windows је излаже за кључ или било који од његових уноса вредности, па вредност не мора нужно имати сопствену, независну временску ознаку измене.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive садржи податке о локалним корисничким и групним налозима, укључујући хешеве лозинки заштићене материјалом boot key-а система.<sup>[[38]](#references)[[39]](#references)</sup>

У `SAM\Domains\Account\Users` можете пронаћи идентификаторе налога и нека поља за пријављивање и смернице. За издвајање хешева ван мреже потребан је и `SYSTEM` hive да би се повратио одговарајући материјал boot key-а.<sup>[[38]](#references)[[39]](#references)</sup>

### Занимљиви уноси у Windows Registry-ју


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Покренути програми

### Основни Windows процеси

Постојећи [пост о уобичајеним Windows процесима](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) наведен је као додатна литература; тврдње о понашању процеса проверите у актуелној Windows документацији и локалним доказима.<sup>[[2]](#references)</sup>

### Недавне Windows апликације

У верзијама Windows 10 које то подржавају, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` садржи поткључеве за појединачне апликације, са пољима као што су време последње употребе и број покретања; овај артефакт је уклоњен у каснијим издањима, па проверите циљну верзију система.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

На системима који подржавају Background Activity Moderator, проверите путању `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` или новију путању `...\bam\State\UserSettings\{SID}`. Вредности су организоване по корисничком SID-у и могу садржати праћене путање до извршних датотека и податке о извршавању налик FILETIME формату; овај артефакт зависи од верзије и треба га потврдити другим доказима.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch кешира ресурсе и метаподатке о покретању како би се програми брже покретали.

Prefetch датотеке се чувају као `.pf` датотеке у `C:\Windows\Prefetch`; формат, период чувања и ограничења броја датотека разликују се у зависности од верзије Windows-а. Microsoft наводи да се у Windows 8 и новијим верзијама чува последњих осам времена покретања и до 1024 датотеке, па не треба уопштавати старије прегледе са фиксним ограничењима.<sup>[[13]](#references)</sup>

Назив датотеке обично је у формату `{program_name}-{hash}.pf`, где hash потиче из контекста извршавања, попут путање и аргумената; Windows 10 и новије верзије могу компресовати датотеку. Присуство датотеке је користан доказ извршавања, али само по себи не доказује да ју је покренуо корисник и треба га упоредити са другим артефактима.<sup>[[13]](#references)</sup>

За преглед ових датотека можете користити [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), који документује парсирање директоријума, излаз у CSV/HTML формату и подршку за декомпресију одговарајућих Windows 10 Prefetch датотека.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** dopunjuje Prefetch korišćenjem istorijskih obrazaca upotrebe radi bržeg učitavanja. Na sistemima koji ih generišu, njegove datoteke baze podataka obično se nalaze u `C:\Windows\Prefetch\Ag*.db`; format i prisustvo zavise od verzije.<sup>[[41]](#references)</sup>

Ove baze podataka mogu da sadrže nazive aplikacija, broj korišćenja, pristupljene datoteke ili volumene, putanje i vremenske raspone, ali ih ne treba smatrati preciznim evidencijama izvršavanja.<sup>[[41]](#references)</sup>

Postojeća veza ka [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) zadržana je kao mogući parser; pre upotrebe proverite njegovu trenutnu dostupnost i podržani izlaz u dokumentaciji alata.

### SRUM

**System Resource Usage Monitor** (SRUM) beleži korišćenje resursa aplikacija i korisnika. Uveden je u Windows 8 i skladišti podatke u ESE bazi podataka `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Pruža sledeće informacije:

- AppID and Path
- User/SID associated with the record
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

Učestalost prikupljanja podataka i njihovo zadržavanje zavise od implementacije; nemojte pretpostaviti da svaki zapis predstavlja tačan interval izvršavanja od 60 minuta.<sup>[[13]](#references)</sup>

Podatke možete izdvojiti i pregledati pomoću alata [**srum_dump**](https://github.com/MarkBaggett/srum-dump), koristeći opcije navedene u dokumentaciji trenutne verzije alata.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**, poznat i kao **ShimCache**, deo je Windows infrastrukture za kompatibilnost aplikacija i beleži metapodatke o datotekama radi donošenja odluka o kompatibilnosti. Putanja do hive-a, format zapisa, kapacitet zadržanih podataka i polja razlikuju se u zavisnosti od izdanja Windows-a; na modernim verzijama Windows-a, ShimCache sam po sebi ne može da dokaže da je korisnik pokrenuo datoteku. Parsirajte relevantni hive `SYSTEM` pomoću alata [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) i potkrepite njegov izlaz drugim artefaktima izvršavanja.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Za parsiranje sačuvanih informacija preporučuje se korišćenje alata AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Datoteka **Amcache.hve** je registry hive koji popisuje aplikacije i datoteke koje je Windows zabeležio. Obično se nalazi na putanji `C:\Windows\AppCompat\Programs\Amcache.hve`.

Može da sadrži povezane i nepovezane unose datoteka, putanje i SHA1 vrednosti, ali njeno prisustvo predstavlja dokaz o popisu i samo po sebi ne dokazuje da je neki proces izvršen.<sup>[[13]](#references)[[44]](#references)</sup>

Za izdvajanje i analizu datoteke **Amcache.hve** koristite alat [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Ova komanda parsira hive i zapisuje CSV izlaz.<sup>[[44]](#references)</sup>

Na primer:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Među generisanim CSV datotekama, `Amcache_Unassociated file entries` može biti koristan pri istraživanju datoteka koje nisu povezane ni sa jednim prepoznatim programom.<sup>[[44]](#references)</sup>

### RecentFileCache

Na sistemima Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` može sadržati informacije o nedavno uočenim binarnim datotekama; dostupnost i značenje zavise od verzije.

Za parsiranje datoteke možete koristiti [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser).<sup>[[45]](#references)</sup>

### Planirani zadaci

Podaci o planiranim zadacima mogu se naći u `C:\Windows\System32\Tasks` za savremene zadatke, a u `C:\Windows\Tasks` u obliku `.job` datoteka za zastarele zadatke; pregledajte format definicije zadatka koji odgovara datom OS-u.<sup>[[73]](#references)[[74]](#references)</sup>

### Usluge

Baza podataka Service Control Manager-a nalazi se u `SYSTEM\CurrentControlSet\Services` (za vanmrežni SYSTEM hive pregledajte odgovarajući control-set ključ); sadrži konfiguraciju usluga i drajvera, kao što su putanje do izvršnih datoteka i tipovi pokretanja.<sup>[[72]](#references)</sup>

### **Windows Store**

Instalirane Windows Store aplikacije mogu biti predstavljene u `\ProgramData\Microsoft\Windows\AppRepository\`, uključujući bazu podataka **`StateRepository-Machine.srd`**. Šema i putanje razlikuju se u zavisnosti od izdanja Windows-a.<sup>[[71]](#references)</sup>

Baza podataka može sadržati identifikatore aplikacija, brojeve paketa i prikazna imena. Praznine u identifikatorima same po sebi ne dokazuju da je neka aplikacija deinstalirana; potvrdite to proverom stanja paketa i registra.

Registracije paketa mogu se pojaviti i u `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft dokumentuje podključ `Deprovisioned`, specifičan za pojedine verzije, za uklonjene prethodno instalirane aplikacije; nemojte pretpostavljati da podključ `Deleted` postoji u svakoj verziji.<sup>[[70]](#references)</sup>

## Windows događaji

U zavisnosti od provider-a, Windows događaji mogu sadržati:

- Šta se dogodilo
- Vremensku oznaku `TimeCreated`, koju treba tumačiti u kontekstu šeme događaja i vremena na hostu
- Uključene korisnike
- Uključene hostove (ime hosta, IP adresa)
- Pristupljene resurse (datoteke, fascikle, štampače ili usluge).<sup>[[49]](#references)</sup>

Pre Windows Vista, evidencije događaja uglavnom su koristile zastareli binarni format u `C:\Windows\System32\config`; Vista i novije verzije koriste Windows Event Log format, koji se obično nalazi u `C:\Windows\System32\winevt\Logs`, a `.evtx` datoteke sadrže podatke o događajima prikazane u XML-u.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registar čuva konfiguraciju kanala u **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, uključujući konfigurisanu putanju do datoteke i podešavanja zadržavanja.<sup>[[47]](#references)</sup>

Mogu se pregledati pomoću Windows Event Viewer-a (**`eventvwr.msc`**) ili alatki kao što su [**Event Log Explorer**](https://eventlogxp.com) i [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Razumevanje Windows Security Event Logging-a

U sistemima Vista i novijim, kanal Security obično se čuva u `C:\Windows\System32\winevt\Logs\Security.evtx`. Njegova maksimalna veličina i smernice zadržavanja mogu se konfigurisati; kod kružnog zapisivanja stariji zapisi mogu biti prepisani kada datoteka dostigne ograničenje. Kanal može beležiti događaje autentifikacije, odjave, privilegija, smernica nadzora i pristupa objektima kada je omogućeno odgovarajuće nadgledanje.<sup>[[46]](#references)[[47]](#references)</sup>

### Ključni ID-jevi događaja za autentifikaciju korisnika:

- **Event ID 4624**: Uspešna prijava na nalog.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Neuspešna prijava na nalog.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Sesija prijave je prekinuta.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Korisnik je pokrenuo odjavu.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Novoj prijavi dodeljene su posebne privilegije; ovo je uobičajeno za sistemske i administratorske naloge, pa samo po sebi ne dokazuje zlonamernu aktivnost.<sup>[[54]](#references)</sup>

#### Tipovi prijave koji se često beleže u događajima 4624, 4625, 4634 i 4647:

- **Interactive (2)**: Interaktivna lokalna prijava.
- **Network (3)**: Pristup deljenom resursu.
- **Batch (4)**: Prijava batch procesa.
- **Service (5)**: Prijava usluge.
- **Unlock (7)**: Otključavanje radne stanice.
- **NetworkCleartext (8)**: Mrežna prijava pri kojoj se akreditivi prosleđuju authentication paketu u čistom tekstu.
- **NewCredentials (9)**: Prijava uz korišćenje prosleđenih alternativnih akreditiva za odlazne veze.
- **RemoteInteractive (10)**: Prijava putem Remote Desktop-a ili Terminal Services-a.
- **CachedInteractive (11)**: Interaktivna prijava uz korišćenje keširanih akreditiva domena.
- **CachedRemoteInteractive (12)**: Keširana udaljena interaktivna prijava.
- **CachedUnlock (13)**: Otključavanje uz korišćenje keširanih akreditiva.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status i Sub Status kodovi za EventID 4625:

- **0xC0000064**: Takav korisnik ne postoji.
- **0xC000006A**: Tačno korisničko ime, ali pogrešna lozinka.
- **0xC0000234**: Nalog je zaključan.
- **0xC0000072**: Nalog je onemogućen.
- **0xC000006F**: Prijava van dozvoljenog vremena.
- **0xC0000070**: Kršenje ograničenja radne stanice.
- **0xC0000193**: Nalog je istekao.
- **0xC0000071**: Lozinka je istekla.
- **0xC0000133**: Vremenska razlika između klijenta i servera je prevelika.
- **0xC0000224**: Nalog mora da promeni lozinku.
- **0xC0000225**: `STATUS_NOT_FOUND`; sam kod ne ukazuje na grešku sistema ili napad.
- **0xC000015B**: Nalog nema odobrenje za traženi tip prijave.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Promena vremena**: Vreme sistema je promenjeno. Mnogi događaji odražavaju uobičajenu korekciju vremena koju vrši servis za sinhronizaciju, zato proverite aktera i izvor vremena pre nego što događaj smatrate neovlašćenom izmenom.<sup>[[56]](#references)</sup>

#### ID-jevi događaja 12, 13, 1074, 6005, 6006, 6008 i 6009:

- **Kontekst napajanja i usluga**: Događaj 12 beleži pokretanje OS-a, 13 beleži gašenje OS-a, 1074 beleži planirano gašenje ili ponovno pokretanje, 6008 ukazuje na neočekivano gašenje, a 6009 beleži verziju Windows-a pri pokretanju. Događaji 6005 i 6006 označavaju pokretanje i zaustavljanje Event Log servisa; oni sami po sebi ne dokazuju pokretanje i gašenje OS-a.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Brisanje evidencije**: Događaj 1102 beleži da je Security audit log obrisan; istražite aktera i okolne događaje, umesto da samo na osnovu ovog događaja pretpostavite nameru.<sup>[[62]](#references)</sup>

#### ID-jevi događaja za praćenje USB uređaja:

- **20001 / 20003**: `UserPnp` događaji instaliranja uređaja koji mogu pomoći u utvrđivanju prve upotrebe ili aktivnosti instaliranja.
- **10000 / 10100**: `DriverFrameworks-UserMode` događaji koji mogu pratiti aktivnost uređaja.
- **Event ID 112**: Aktivnost `DeviceSetupManager/Admin` koja može pružiti vremenske oznake povezane sa priključivanjem uređaja.
- Provider, kanal i značenje događaja razlikuju se u zavisnosti od verzije Windows-a; proverite ime provider-a i sadržaj događaja pre nego što mu pripišete značenje.<sup>[[59]](#references)</sup>

Praktične primere tipova prijava i povezanih akreditiva potražite u [detaljnom vodiču Altered Security-ja](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Detalji događaja, uključujući tip prijave, status, podstatus, izvornu adresu i polja procesa, pružaju kontekst za Event ID 4625; statusni kod ili ponavljani obrazac neuspešnih pokušaja predstavljaju trag za istragu, a ne zaključak.<sup>[[51]](#references)[[55]](#references)</sup>

### Oporavak Windows događaja

Pošto se evidencije događaja često zapisuju kružno, zapisi koje je zapisivač prepisao možda se ne mogu oporaviti. Napravite forenzičku sliku ili radnu kopiju pre interakcije sa aktivnim sistemom; koristite proveren parser ili alatku za izdvajanje podataka, kao što je **Bulk_extractor**, tek nakon što potvrdite da verzija alatke podržava ciljane `.evtx` podatke, i nemojte isključivati sistem koji radi samo da biste pokušali da oporavite događaje.<sup>[[46]](#references)</sup>

### Prepoznavanje uobičajenih napada pomoću Windows događaja

Praktičnu referencu za ID-jeve događaja potražite na postojećem linku [Red Team Recipe](https://redteamrecipe.com/event-codes/) i proverite njihove primere u dokumentaciji provider-a navedenoj iznad.

#### Brute Force napadi

Povežite ponovljene neuspešne pokušaje prijave Event ID 4625 sa kasnijom uspešnom prijavom 4624, tipom prijave, statusom, izvorom i kontekstom naloga; ovaj niz je indikator za istragu, a ne dokaz napada.<sup>[[50]](#references)[[51]](#references)</sup>

#### Promena vremena

Event ID 4616 beleži promene sistemskog vremena, što može otežati analizu vremenske linije; uporedite ga sa podacima servisa za sinhronizaciju vremena i hosta.<sup>[[56]](#references)</sup>

#### Praćenje USB uređaja

USB ID-jevi događaja zavise od provider-a; uporedite događaje `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 i `DeviceSetupManager/Admin` 112 sa artefaktima SetupAPI-ja i registra.<sup>[[17]](#references)[[59]](#references)</sup>

#### Događaji napajanja sistema

Za kontekst pokretanja, gašenja i ponovnog pokretanja OS-a, kao i neočekivanog gubitka napajanja, koristite 12/13/1074/6008/6009; 6005/6006 označavaju pokretanje/zaustavljanje Event Log servisa.<sup>[[57]](#references)[[58]](#references)</sup>

#### Brisanje evidencije

Security Event ID 1102 beleži da je Security audit log obrisan; povežite ga sa odgovornim nalogom i procesom.<sup>[[62]](#references)</sup>



## References

- [1] [Čišćenje Windows Plug and Play-a](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Istraživanje uobičajenih Windows procesa](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Digitalno-forenzički pogled na Windows 10 obaveštenja](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Forenzičke alatke Erica Zimmermana](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier i alternativni tokovi podataka](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Usluga Volume Shadow Copy](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operacije pravljenja rezervnih kopija i vraćanja registra u okviru VSS-a](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Ključevi registra za pravljenje rezervnih kopija i vraćanje](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problem sa performansama Word-a na lokaciji AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Priručnik za odgovor na incidente](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Binarni format Shell Link-a](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP forenzika: Prepoznavanje artefakata eksfiltracije podataka](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Unosi u evidenciji SetupAPI-ja za instaliranje uređaja](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID i povezani tipovi](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Pronalaženje i prenos Outlook datoteka sa podacima](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Uključivanje Cached Exchange Mode-a](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Sinhronizuje se samo podskup stavki](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Konfigurisanje ograničenja veličine za Outlook datoteke sa podacima](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profili - Gde Thunderbird čuva korisničke podatke](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Podešavanja Thunderbird naloga i mbox direktorijumi](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Interfejs IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Registar sistema nije sačuvan u RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Oporavak Windows registra](https://www.mitec.cz/wrr.html)
- [38] [Udaljeno uređivanje registra](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Tehnički pregled lozinki](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch podaci](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Format datoteke Event Log-a](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Ključ registra Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Svojstvo događaja TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS vrednosti](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Rešavanje problema sa neočekivanim ponovnim pokretanjem pomoću evidencija sistemskih događaja](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Rešavanje problema sa gašenjem u toku](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forenzika USB uređaja za skladištenje podataka u Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Sjajni Windows tipovi prijave](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderator pozadinske aktivnosti](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registar - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print prestaje da štampa PDF priloge u Outlook Desktop-u](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Datoteke Windows registra](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Sprečavanje ponovnog pojavljivanja uklonjenih aplikacija tokom ažuriranja](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Rezultati testiranja FTK-a i Registry Viewer-a](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Baza podataka instaliranih usluga](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Zadaci](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Planirani zadaci ne uspevaju uz grešku da usluga Task Scheduler nije dostupna](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Kretanje kroz bazu podataka Windows Mail-a](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Format internet poruka](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Upravljanje Recall-om za Windows klijente](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
