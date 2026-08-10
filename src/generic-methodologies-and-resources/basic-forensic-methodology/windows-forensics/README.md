# Windows artefakti

## Generički Windows artefakti

### Windows 10 obaveštenja

Baza podataka obaveštenja po korisniku nalazi se u `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (na primer, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Rana izdanja Windows 10 koristila su `appdb.dat`; Anniversary Update (1607) uveo je `wpndatabase.db`. SQLite baza podataka uključuje tabelu `Notification` sa sadržajima obaveštenja i poljima za vremenske oznake, iako se period čuvanja i dostupni podaci razlikuju u zavisnosti od izdanja i politike čišćenja.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline je funkcija istorije aktivnosti koja može sadržati zapise za podržane aplikacije, dokumente i druge aktivnosti korisnika; obuhvat zavisi od aplikacije i verzije Windows-a.<sup>[[4]](#references)</sup>

Baza podataka nalazi se na adresi `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Može se otvoriti pomoću SQLite-a ili parsirati pomoću [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), čiji se izlaz može pregledati pomoću [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Datoteke preuzete izvan lokalne granice poverenja mogu sadržati **`Zone.Identifier` alternate data stream**, koji beleži informacije o zoni i može uključivati metapodatke o poreklu, kao što je URL. Njegovo prisustvo i polja zavise od izvora i sistemske politike.<sup>[[6]](#references)</sup>

## **Rezervne kopije datoteka**

### Recycle Bin

Na sistemima Vista i novijim, **Recycle Bin** se može pronaći u fascikli **`$Recycle.bin`** u korenu diska (na primer, `C:\$Recycle.bin`).\
Kada se datoteka obriše iz ove fascikle, kreiraju se 2 određene datoteke:

- `$I{id}`: Informacije o datoteci, uključujući vreme brisanja i originalnu putanju
- `$R{id}`: Sadržaj datoteke

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

Ako imate ove datoteke, možete koristiti [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) za izdvajanje originalne putanje i vremena brisanja (koristite verziju odgovarajuću ciljnom izdanju Windows-a).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) može da kreira shadow copies volumena u određenom trenutku dok su datoteke u upotrebi; shadow copy nije zamena za forenzičku sliku.<sup>[[8]](#references)</sup>

Metapodaci kopije se obično povezuju sa direktorijumom `\System Volume Information` u korenu volumena, sa identifikatorima koji se razlikuju u zavisnosti od sistema:

![Recycle Bin - Volume Shadow Copies: Ove rezervne kopije se obično nalaze u direktorijumu System Volume Information u korenu sistema datoteka, a naziv se sastoji od UID-ova prikazanih u...](<../../../images/image (94).png>)

Nakon montiranja slike pomoću odgovarajućeg forenzičkog mounter-a, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) može da nabroji dostupne VSS snapshots i da pregleda ili kopira datoteke iz njih.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Nakon montiranja forenzičke slike pomoću ArsenalImageMounter-a, alat ShadowCopyView može da se koristi za pregled shadow copy-ja, pa čak i za ekstrakciju datoteka...](<../../../images/image (576).png>)

Konfiguracija VSS registry writer-a uključuje `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, gde se mogu navesti datoteke i ključevi izuzeti iz backup-a:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Registry unos HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore sadrži datoteke i ključeve koje ne treba uključiti u backup](<../../../images/image (254).png>)

Ključ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` takođe sadrži konfiguraciju VSS service-a.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

Lokacije AutoRecover-a se razlikuju u zavisnosti od Office aplikacije, verzije i konfiguracije. Za Word, Microsoft navodi `%APPDATA%\Microsoft\Word` kao podrazumevanu lokaciju; proverite podešavanja aplikacije da biste utvrdili aktivnu putanju.<sup>[[12]](#references)</sup>

## Shell Items

Shell item je stavka koja sadrži informacije o načinu pristupa drugoj datoteci.

### Recent Documents (LNK)

Windows obično kreira prečice do nedavno korišćenih stavki kada korisnik otvori stavku ili joj na drugi način pristupi:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Pristup folderu takođe može da kreira linkove za taj folder i povezane nadređene foldere.

Ove link datoteke mogu da sadrže tip cilja, MAC vremena cilja, informacije o volumenu i putanju cilja. Ti metapodaci mogu pomoći pri identifikaciji uklonjenog cilja, ali sam artifact nije dokaz da je određeni korisnik otvorio cilj.<sup>[[13]](#references)[[14]](#references)</sup>

Vremenske oznake LNK datoteke u njenom filesystem-u i ugrađene vremenske oznake cilja međusobno su različite. Nemojte tumačiti kreiranje linka kao prvo korišćenje ili izmenu linka kao poslednje korišćenje bez potvrde iz drugih artifact-a; format čuva vremenske oznake cilja odvojeno od vremenskih oznaka link datoteke.<sup>[[13]](#references)[[14]](#references)</sup>

Postojeći link ka alatu [**LinkParser**](http://4discovery.com/our-tools/) zadržan je kao istorijska opcija, ali njegova dokumentacija nije bila dostupna tokom provere. Za dokumentovani command-line parser koristite [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Ovi alati obično prikazuju dva skupa vremenskih oznaka:

- **Vremenske oznake cilja:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Vremenske oznake link datoteke:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Prvi skup odnosi se na cilj; drugi skup odnosi se na samu LNK datoteku. Oba skupa tumačite uz pomoć dokumentacije parser-a i u kontekstu filesystem-a.<sup>[[14]](#references)[[15]](#references)</sup>

Iste informacije možete dobiti pokretanjem Windows CLI alata: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
U ovom slučaju, informacije će biti sačuvane u CSV datoteci.

### Jumplists

Jump Lists su liste nedavnih stavki ili stavki specifičnih za zadatak, organizovane po aplikaciji, i mogu biti automatske ili prilagođene.<sup>[[13]](#references)</sup>

Automatske Jump Lists čuvaju se u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` i koriste nazive kao što je `{id}.automaticDestinations-ms`, gde ID identifikuje aplikaciju.

Prilagođene Jump Lists čuvaju se u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; aplikacija kontroliše koje unose zadataka ili stavki kreira.

Vremena kreiranja i izmene koja beleži filesystem opisuju Jump List datoteku, a ne automatski prvi i poslednji pristup svakom navedenom cilju. Povežite analizirane unose sa vremenskim oznakama datoteke i drugim artefaktima.<sup>[[13]](#references)</sup>

Jump Lists možete pregledati pomoću alata [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Nedavni dokumenti (LNK) - Jumplists: Jumplists možete pregledati pomoću alata JumplistExplorer](<../../../images/image (168).png>)

(_Imajte na umu da se vremenske oznake koje prikazuje JumplistExplorer odnose na samu jumplist datoteku_)

### Shellbags

[**Pratite ovaj link da biste saznali šta su shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Korišćenje Windows USB uređaja

Korišćenje USB uređaja ponekad se može potvrditi artefaktima kreiranim prilikom pristupa datotekama sa prenosivih medija, uključujući:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Alati kao što je [**USBDetective**](https://usbdetective.com) povezuju ove artefakte sa zapisima o USB uređajima, ali dostupnost artefakata zavisi od verzije Windowsa i aplikacije.<sup>[[18]](#references)</sup>

U testiranjima Windows XP i Windows 7 MTP workflow-a, dokumentovano je da su neki LNK-ovi pokazivali na `WPDNSE` folder umesto na originalnu putanju.<sup>[[16]](#references)</sup>

![Shellbags - Korišćenje Windows USB uređaja: Imajte na umu da neke LNK datoteke, umesto da pokazuju na originalnu putanju, pokazuju na WPDNSE folder](<../../../images/image (218).png>)

Ta studija je zabeležila kopije u `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; privremeni sadržaj nije preživeo restart u njihovim testovima, a GUID se mogao povezati sa shellbag podacima. Ovo treba posmatrati kao ponašanje zavisno od OS-a, uređaja i aplikacije, a ne kao univerzalno pravilo.<sup>[[16]](#references)</sup>

### Informacije iz Registry-ja

[Proverite ovu stranicu da biste saznali](interesting-windows-registry-keys.md#usb-information) koji registry ključevi sadrže zanimljive informacije o povezanim USB uređajima.

### setupapi

Na Visti i novijim verzijama, pregledajte `C:\Windows\inf\setupapi.dev.log` radi aktivnosti instaliranja uređaja. Zaglavlja odeljaka uključuju vremenske oznake `Section start`; ona dokumentuju obradu podešavanja i treba ih povezati sa drugim dokazima o povezivanju, a ne tretirati kao tačno vreme fizičkog priključivanja.<sup>[[17]](#references)</sup>

![Informacije iz Registry-ja - setupapi: Proverite datoteku C: Windows inf setupapi.dev.log da biste dobili vremenske oznake kada je USB veza uspostavljena (pretražite Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) može se koristiti za dobijanje informacija o USB uređajima koji su bili povezani sa image-om.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective može da se koristi za dobijanje informacija o USB uređajima koji su bili povezani sa image-om](<../../../images/image (452).png>)

### Plug and Play Cleanup

Scheduled task poznat kao `Plug and Play Cleanup` uklanja zastarele verzije drivera. Definicija Windows 10 task-a koju je dokumentovao Adam Harrison takođe cilja drivere koji nisu aktivni 30 dana, pa dokazi o driverima prenosivih uređaja mogu biti obrisani; pre uopštavanja ovog ponašanja proverite lokalnu definiciju task-a i Windows build.<sup>[[1]](#references)</sup>

Task se nalazi na sledećoj putanji: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Ključne komponente i podešavanja task-a:**

- **pnpclean.dll**: Ovaj DLL je odgovoran za stvarni proces čišćenja.
- **UseUnifiedSchedulingEngine**: Postavljen je na `TRUE`, što ukazuje na korišćenje generičkog task scheduling engine-a.
- **MaintenanceSettings**:
- **Period ('P1M')**: Usmerava Task Scheduler da pokrene task čišćenja jednom mesečno tokom redovnog Automatic maintenance-a.
- **Deadline ('P2M')**: Nalaže Task Scheduler-u da, ako task ne uspe dva uzastopna meseca, izvrši task tokom emergency Automatic maintenance-a.

Ova konfiguracija zakazuje redovno održavanje i ponovna pokretanja nakon uzastopnih neuspeha; tačan XML i ponašanje zavise od verzije.<sup>[[1]](#references)</sup>

**Za više informacija pogledajte:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Emailovi

Emailovi sadrže **2 zanimljiva dela: zaglavlja i sadržaj** emaila. U **zaglavljima** možete pronaći informacije kao što su:

- **Ko** je poslao emailove (email adresa, IP, mail serveri koji su preusmerili email)
- **Kada** je email poslat

Takođe, zaglavlja `References` i `In-Reply-To` mogu sadržati message ID-jeve koji se koriste za povezivanje odgovora sa konverzacijom.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emailovi: Kada je email poslat](<../../../images/image (593).png>)

### Windows Mail App

Ova aplikacija čuva sadržaj emaila u pomoćnim tekstualnim ili HTML datotekama na putanjama kao što je `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; tačna struktura numerisanih foldera i datoteka može se razlikovati u zavisnosti od artefakta.<sup>[[75]](#references)</sup>

**Metadata** emailova i **kontakti** mogu se pronaći u **ESE bazi podataka** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` koristi Extensible Storage Engine (ESE) format. Radite na kopiji i koristite ESE parser kao što je [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); ako alat zahteva `.edb` sufiks, preimenujte samo kopiju i proverite šemu tabela pre oslanjanja na tabelu `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Prilikom pregleda Outlook MAPI svojstava, kanonska svojstva uključuju:

- `PidTagClientSubmitTime`: UTC vreme kada je klijent poslao poruku.
- `PidTagConversationIndex`: relativna pozicija poruke u niti konverzacije.
- `PidTagEntryId`: identifikator objekta poruke.
- `PidTagMessageFlags`: statusne zastavice kao što su poslato, pročitano, nepročitano ili sa prilozima.
- `PidTagLastVerbExecuted`: poslednja operacija zabeležena za poruku, kao što su otvaranje, odgovaranje ili prosleđivanje.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Lokacije Outlook data-file-ova razlikuju se u zavisnosti od verzije i tipa naloga. Microsoft dokumentuje sledeće uobičajene lokacije za PST/OST datoteke:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry putanja `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` može identifikovati Outlook profil i povezanu konfiguraciju data-file-ova.

PST datoteke mogu sadržati poruke, kontakte, podatke kalendara i druge Outlook stavke. Kopiju možete pregledati pomoću alata [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: PST datoteku možete otvoriti pomoću alata Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST datoteka** je lokalni cache za Exchange ili Microsoft 365 naloge; Cached Exchange Mode se ne primenjuje na POP ili IMAP naloge. Period rada offline može da se konfiguriše i često je podrazumevano 12 meseci, dok su ograničenja veličine PST/OST datoteka zasebna podesiva svojstva. Za pregled OST datoteke može se koristiti [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Preuzimanje priloga

Izgubljeni prilozi mogu se oporaviti iz:

- Za legacy Outlook/IE konfiguracije: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Za novije Outlook/IE11 konfiguracije: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** čuva podatke profila u `%APPDATA%\Thunderbird\Profiles`; mail folderi obično koriste mbox datoteke bez ekstenzije unutar `Mail` ili `ImapMail` direktorijuma specifičnih za nalog.<sup>[[29]](#references)[[30]](#references)</sup>

### Sličice slika

- **Windows XP**: Pregledi sličica obično su čuvani u `thumbs.db` datotekama unutar svakog foldera.
- **Mrežni folderi**: `thumbs.db` datoteka se i dalje može kreirati za UNC folder kada je relevantno ponašanje sličica omogućeno; ne treba pretpostaviti da je svaka verzija Windowsa ili svaka policy konfiguracija kreira.
- **Windows Vista i noviji**: Sistemski cache sličica centralizovan je u `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, sa datotekama kao što je **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) može parsirati legacy `Thumbs.db`, dok [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) može parsirati moderne baze podataka cache-a sličica.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Informacije iz Windows Registry-ja

Windows Registry, koji čuva konfiguracione podatke sistema i korisnika, nalazi se u hive datotekama u:

- `%WINDIR%\System32\Config` za machine hive-ove koji podržavaju različite `HKEY_LOCAL_MACHINE` podključeve.
- `%USERPROFILE%\NTUSER.DAT` za korisnikov `HKEY_CURRENT_USER` hive.
- Neke starije Windows instalacije sadrže kopije u `%WINDIR%\System32\Config\RegBack\`; Windows 10 version 1803 i novije verzije ne popunjavaju automatski ovaj direktorijum osim ako periodični backup nije omogućen.<sup>[[34]](#references)[[35]](#references)</sup>
- Podaci o shell-u i class-registration podaci po korisniku takođe se obično čuvaju u `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` na modernim verzijama Windowsa.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Neki alati su korisni za analizu registry hive-ova; pre oslanjanja na rezultat proverite podržane hive formate i verziju svakog alata:

- **Registry Editor**: Instaliran je u Windowsu. To je GUI za navigaciju kroz Windows Registry trenutne sesije.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Omogućava učitavanje registry datoteke i navigaciju kroz nju pomoću GUI-ja. Takođe sadrži Bookmarks koji ističu ključeve sa zanimljivim informacijama.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Takođe ima GUI koji omogućava navigaciju kroz učitani registry i sadrži plugins koji ističu zanimljive informacije unutar učitanog registry-ja.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Još jedna GUI aplikacija sposobna za izvlačenje informacija iz učitanog registry hive-a.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Oporavak obrisanog elementa

Obrisane hive ćelije mogu ostati dok se njihov prostor ne iskoristi ponovo, ali oporavak zavisi od stanja hive-a i parsera; oporavljene obrisane ključeve treba tretirati kao dokaze koji zahtevaju validaciju, a ne kao garantovane zapise.

### Vreme poslednjeg upisivanja

Registry ključevi sadrže vremensku oznaku poslednjeg upisivanja; Windows je izlaže za ključ ili bilo koji od njegovih value unosa, pa vrednost ne mora imati sopstvenu nezavisnu vremensku oznaku izmene.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive sadrži podatke o lokalnim korisničkim i grupnim nalozima, uključujući password hash-eve zaštićene system boot-key materijalom.<sup>[[38]](#references)[[39]](#references)</sup>

U `SAM\Domains\Account\Users` možete dobiti identifikatore naloga i neka polja za logon i policy. Offline izvlačenje hash-eva takođe zahteva `SYSTEM` hive radi oporavka relevantnog boot-key materijala.<sup>[[38]](#references)[[39]](#references)</sup>

### Zanimljivi unosi u Windows Registry-ju


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Izvršeni programi

### Osnovni Windows procesi

[Post o uobičajenim Windows procesima](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) zadržan je kao dodatna literatura; tvrdnje o ponašanju procesa potvrdite aktuelnom Windows dokumentacijom i lokalnim dokazima.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Na verzijama Windows 10 koje to izlažu, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` sadrži podključeve po aplikaciji sa poljima kao što su vreme poslednjeg korišćenja i broj pokretanja; artefakt je uklonjen iz novijih izdanja, pa proverite ciljni build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Na sistemima koji izlažu Background Activity Moderator, pregledajte putanju `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` ili noviju putanju `...\bam\State\UserSettings\{SID}`. Vrednosti su organizovane prema korisničkom SID-u i mogu sadržati praćene putanje izvršnih datoteka i execution podatke nalik FILETIME-u; artefakt zavisi od verzije i treba ga potvrditi drugim dokazima.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch kešira resurse i metadata o pokretanju kako bi programi mogli brže da se pokrenu.

Prefetch datoteke čuvaju se kao `.pf` datoteke u `C:\Windows\Prefetch`; format, zadržavanje i ograničenja broja datoteka razlikuju se u zavisnosti od verzije Windowsa. Microsoft dokumentuje zadržavanje poslednjih osam vremena izvršavanja i do 1024 datoteke na Windowsu 8 i novijim verzijama, pa starije sažetke sa fiksnim ograničenjima ne treba uopštavati.<sup>[[13]](#references)</sup>

Naziv datoteke obično koristi format `{program_name}-{hash}.pf`, pri čemu se hash izvodi iz konteksta izvršavanja, kao što su putanja i argumenti; Windows 10 i novije verzije mogu kompresovati datoteku. Prisustvo datoteke predstavlja koristan dokaz izvršavanja, ali samo po sebi nije dokaz da ju je izvršio korisnik i treba ga povezati sa drugim artefaktima.<sup>[[13]](#references)</sup>

Za pregled ovih datoteka možete koristiti [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), koji dokumentuje parsiranje direktorijuma, CSV/HTML output i podršku za dekompresiju primenljivih Windows 10 Prefetch datoteka.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** dopunjuje Prefetch korišćenjem istorijskih obrazaca upotrebe radi poboljšanja učitavanja. Na sistemima koji ih generišu, njegove datoteke baze podataka obično se nalaze na lokaciji `C:\Windows\Prefetch\Ag*.db`; format i prisustvo zavise od verzije.<sup>[[41]](#references)</sup>

Ove baze podataka mogu sadržati nazive aplikacija, broj korišćenja, pristupljene datoteke ili volumene, putanje i vremenske opsege, ali ih ne treba tretirati kao tačan dnevnik izvršavanja.<sup>[[41]](#references)</sup>

Postojeći link ka alatu [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) zadržan je kao mogući parser; pre upotrebe proverite njegovu trenutnu dostupnost i podržani izlaz u dokumentaciji alata.

### SRUM

**System Resource Usage Monitor** (SRUM) beleži korišćenje resursa od strane aplikacija i korisnika. Uveden je u Windows 8 i čuva podatke u ESE bazi podataka `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Pruža sledeće informacije:

- AppID i putanja
- Korisnik/SID povezan sa zapisom
- Poslate bajtove
- Primljene bajtove
- Mrežni interfejs
- Trajanje veze
- Trajanje procesa

Učestalost prikupljanja i zadržavanje podataka zavise od implementacije; ne pretpostavljajte da svaki zapis predstavlja tačan interval izvršavanja od 60 minuta.<sup>[[13]](#references)</sup>

Podatke možete izdvojiti i pregledati pomoću alata [**srum_dump**](https://github.com/MarkBaggett/srum-dump), koristeći opcije dokumentovane za trenutnu verziju alata.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, poznat i kao **ShimCache**, deo je Windows infrastrukture za kompatibilnost aplikacija i beleži metapodatke o fajlovima radi donošenja odluka o kompatibilnosti. Putanja do hive-a, format zapisa, zadržani kapacitet i polja razlikuju se u zavisnosti od izdanja Windows-a; na modernom Windows-u, sam ShimCache ne može da dokaže da je korisnik izvršio fajl. Parsirajte relevantni `SYSTEM` hive pomoću alata [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) i potvrdite njegov izlaz drugim execution artifacts.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Za parsiranje sačuvanih informacija preporučuje se korišćenje alata AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Fajl **Amcache.hve** je registry hive koji sadrži inventar aplikacija i fajlova koje je Windows uočio. Obično se nalazi na lokaciji `C:\Windows\AppCompat\Programs\Amcache.hve`.

Može sadržati povezane i nepovezane unose fajlova, putanje i SHA1 vrednosti, ali njegovo prisustvo predstavlja dokaz o inventaru i samo po sebi ne dokazuje da je neki proces izvršen.<sup>[[13]](#references)[[44]](#references)</sup>

Za izdvajanje i analizu fajla **Amcache.hve** koristite alat [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Ova komanda parsira hive i upisuje CSV izlaz.<sup>[[44]](#references)</sup>

Na primer:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Među generisanim CSV datotekama, `Amcache_Unassociated file entries` može biti koristan pri istrazi datoteka koje nisu povezane sa prepoznatim programom.<sup>[[44]](#references)</sup>

### RecentFileCache

Na Windows 7 sistemima, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` može sadržati informacije o nedavno uočenim binarnim datotekama; dostupnost i značenje podataka zavise od verzije.

Možete koristiti [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) za parsiranje datoteke.<sup>[[45]](#references)</sup>

### Zakazani zadaci

Dokazi o zakazanim zadacima mogu se nalaziti u `C:\Windows\System32\Tasks` za moderne zadatke i u `C:\Windows\Tasks`, sa `.job` datotekama, za legacy zadatke; analizirajte format definicije zadatka koji odgovara operativnom sistemu.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Baza podataka Service Control Manager-a nalazi se pod `SYSTEM\CurrentControlSet\Services` (kod offline SYSTEM hive-a analizirajte odgovarajući control-set ključ); sadrži konfiguraciju servisa i drivera, kao što su putanje do izvršnih datoteka i tipovi pokretanja.<sup>[[72]](#references)</sup>

### **Windows Store**

Instalirane Windows Store aplikacije mogu biti predstavljene pod `\ProgramData\Microsoft\Windows\AppRepository\`, uključujući bazu podataka **`StateRepository-Machine.srd`**. Schema i putanje razlikuju se u zavisnosti od izdanja Windows-a.<sup>[[71]](#references)</sup>

Baza podataka može sadržati identifikatore aplikacija, brojeve paketa i prikazna imena. Praznine u identifikatorima same po sebi nisu dokaz da je aplikacija deinstalirana; potvrdite nalaze stanjem paketa i registry-ja.

Registracije paketa mogu se pojaviti i pod `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft dokumentuje podključ specifičan za verziju, `Deprovisioned`, za uklonjene provisioned aplikacije; nemojte pretpostavljati da podključ `Deleted` postoji u svakoj build verziji.<sup>[[70]](#references)</sup>

## Windows događaji

U zavisnosti od provider-a, Windows događaji mogu sadržati:

- Šta se dogodilo
- Vremensku oznaku `TimeCreated`, koja se mora tumačiti u skladu sa schemom događaja i vremenskim kontekstom hosta
- Uključene korisnike
- Uključene hostove (hostname, IP)
- Pristupljene resurse (datoteke, fascikle, štampače ili servise).<sup>[[49]](#references)</sup>

Pre Windows Vista, event log-ovi su uglavnom koristili legacy binarni format u `C:\Windows\System32\config`; Vista i novije verzije koriste Windows Event Log format, obično u `C:\Windows\System32\winevt\Logs`, pri čemu `.evtx` datoteke sadrže XML-renderovane podatke o događajima.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry čuva konfiguraciju channel-a pod **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, uključujući konfigurisanu putanju datoteke i podešavanja zadržavanja.<sup>[[47]](#references)</sup>

Mogu se pregledati pomoću Windows Event Viewer-a (**`eventvwr.msc`**) ili alata kao što su [**Event Log Explorer**](https://eventlogxp.com) i [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Razumevanje Windows Security event logging-a

Na Vista i novijim verzijama, Security channel se obično čuva u `C:\Windows\System32\winevt\Logs\Security.evtx`. Njegova maksimalna veličina i politika zadržavanja mogu se konfigurisati; kod circular logging-a, stariji zapisi mogu biti prepisani kada datoteka dostigne ograničenje. Channel može beležiti authentication, logoff, privilege, audit-policy i object-access događaje kada je odgovarajući auditing omogućen.<sup>[[46]](#references)[[47]](#references)</sup>

### Ključni Event ID-jevi za korisničku authentication:

- **Event ID 4624**: Uspešan logon naloga.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Neuspešan logon naloga.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Logon sesija je prekinuta.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Korisnik je pokrenuo logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Posebne privilegije dodeljene su novom logon-u; ovo je uobičajeno za system i administrator naloge, pa samo po sebi nije dokaz zlonamerne aktivnosti.<sup>[[54]](#references)</sup>

#### Tipovi logon-a koji se često beleže u 4624, 4625, 4634 i 4647:

- **Interactive (2)**: Interaktivni lokalni logon.
- **Network (3)**: Pristup deljenom resursu.
- **Batch (4)**: Logon batch procesa.
- **Service (5)**: Logon servisa.
- **Unlock (7)**: Otključavanje radne stanice.
- **NetworkCleartext (8)**: Network logon koji authentication package-u prosleđuje credentials u cleartext obliku.
- **NewCredentials (9)**: Logon koji koristi prosleđene alternativne credentials za outbound connections.
- **RemoteInteractive (10)**: Remote Desktop ili Terminal Services logon.
- **CachedInteractive (11)**: Interaktivni logon koji koristi cached domain credentials.
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon.
- **CachedUnlock (13)**: Otključavanje pomoću cached credentials.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status i Sub Status kodovi za EventID 4625:

- **0xC0000064**: Takav korisnik ne postoji.
- **0xC000006A**: Ispravno korisničko ime, ali pogrešna lozinka.
- **0xC0000234**: Nalog je zaključan.
- **0xC0000072**: Nalog je onemogućen.
- **0xC000006F**: Logon van dozvoljenog vremena.
- **0xC0000070**: Kršenje ograničenja radne stanice.
- **0xC0000193**: Nalog je istekao.
- **0xC0000071**: Lozinka je istekla.
- **0xC0000133**: Vremenska razlika između client-a i servera je prevelika.
- **0xC0000224**: Nalog mora promeniti lozinku.
- **0xC0000225**: `STATUS_NOT_FOUND`; sam kod ne identifikuje sistemski bug ili napad.
- **0xC000015B**: Zahtevani tip logon-a nije odobren nalogu.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Sistemsko vreme je promenjeno. Mnogi događaji odražavaju uobičajenu korekciju time-service-a, zato pre nego što promenu označite kao tampering, povežite actor-a i izvor vremena.<sup>[[56]](#references)</sup>

#### Event ID-jevi 12, 13, 1074, 6005, 6006, 6008 i 6009:

- **Power and service context**: Event 12 beleži pokretanje OS-a, 13 beleži gašenje OS-a, 1074 beleži planirano gašenje ili restart, 6008 ukazuje na neočekivano gašenje, a 6009 beleži Windows verziju pri boot-u. Events 6005 i 6006 ukazuju na pokretanje i zaustavljanje Event Log servisa; sami po sebi nisu dokaz pokretanja i gašenja OS-a.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 beleži da je Security audit log obrisan; istražite actor-a i okolne događaje umesto da nameru pretpostavite samo na osnovu ovog događaja.<sup>[[62]](#references)</sup>

#### EventID-jevi za praćenje USB uređaja:

- **20001 / 20003**: `UserPnp` događaji instalacije uređaja koji mogu pomoći pri utvrđivanju prve upotrebe ili aktivnosti instalacije.
- **10000 / 10100**: `DriverFrameworks-UserMode` događaji koji mogu pratiti aktivnost uređaja.
- **Event ID 112**: `DeviceSetupManager/Admin` aktivnost koja može pružiti vremenske oznake povezane sa priključivanjem uređaja.
- Provider, channel i značenje događaja razlikuju se u zavisnosti od verzije Windows-a; proverite naziv provider-a i payload događaja pre nego što mu dodelite značenje.<sup>[[59]](#references)</sup>

Za praktične primere tipova logon-a i sa njima povezanog credential materijala pogledajte [detaljni vodič kompanije Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Detalji događaja, uključujući tip logon-a, status, substatus, izvornu adresu i process polja, pružaju kontekst za Event ID 4625; statusni kod ili obrazac ponovljenih neuspeha predstavljaju istražni trag, a ne zaključak.<sup>[[51]](#references)[[55]](#references)</sup>

### Oporavak Windows događaja

Pošto su event log-ovi obično circular, zapisi koje je logger prepisao možda se ne mogu oporaviti. Sačuvajte forensic image ili radnu kopiju pre interakcije sa live sistemom; koristite validirani parser ili carver, kao što je **Bulk_extractor**, tek nakon potvrde da verzija alata podržava ciljne `.evtx` podatke i nemojte isključivati sistem koji radi samo da biste pokušali da oporavite događaje.<sup>[[46]](#references)</sup>

### Identifikovanje uobičajenih napada pomoću Windows događaja

Za praktičan pregled event ID-jeva pogledajte postojeći link [Red Team Recipe](https://redteamrecipe.com/event-codes/) i proverite njegove primere u odnosu na prethodno navedenu dokumentaciju provider-a.

#### Brute Force napadi

Povežite ponovljene neuspehe Event ID 4625 sa kasnijim uspehom 4624, tipom logon-a, statusom, izvorom i kontekstom naloga; sekvenca je indikator za istragu, a ne dokaz napada.<sup>[[50]](#references)[[51]](#references)</sup>

#### Promena vremena

Event ID 4616 beleži promene sistemskog vremena, što može otežati analizu timeline-a; uporedite ga sa time-service i host dokazima.<sup>[[56]](#references)</sup>

#### Praćenje USB uređaja

USB event ID-jevi zavise od provider-a; povežite `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 i `DeviceSetupManager/Admin` 112 sa SetupAPI i registry artefaktima.<sup>[[17]](#references)[[59]](#references)</sup>

#### Sistemski power događaji

Koristite 12/13/1074/6008/6009 za kontekst pokretanja OS-a, gašenja, restarta i neočekivanog gubitka napajanja; 6005/6006 označavaju pokretanje/zaustavljanje Event Log servisa.<sup>[[57]](#references)[[58]](#references)</sup>

#### Brisanje log-a

Security Event ID 1102 beleži da je Security audit log obrisan i treba ga povezati sa odgovornim nalogom i procesom.<sup>[[62]](#references)</sup>

## References

- [1] [Čišćenje Windows Plug and Play-a](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Istraživanje uobičajenih Windows procesa](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Digitalno-forenzički prikaz Windows 10 obaveštenja](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic alati](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier i Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operacije backup-a i restore-a registry-ja pod VSS-om](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry ključevi za backup i restore](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problem sa performansama Word-a na AutoRecover lokaciji](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Vodič za Incident Response](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Binarni format Shell Link datoteke](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP forenzika: Identifikovanje artefakata eksfiltracije podataka](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Zapisi SetupAPI log-a o instalaciji uređaja](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID i povezani tipovi](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Pronalaženje i prenos Outlook data datoteka](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Uključivanje Cached Exchange Mode-a](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Sinhronizuje se samo podskup stavki](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Konfigurisanje ograničenja veličine za Outlook data datoteke](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profili - Gde Thunderbird čuva korisničke podatke](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird podešavanja naloga i mbox direktorijumi](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interfejs](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry se ne backup-uje u RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Daljinsko uređivanje registry-ja](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Tehnički pregled lozinki](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch dokazi](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Format Event Log datoteke](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry ključ](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated svojstvo događaja](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS vrednosti](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Otklanjanje neočekivanih reboot-a pomoću system event log-ova](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Otklanjanje problema sa gašenjem u toku](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forenzika USB Storage uređaja za Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderator aktivnosti u pozadini](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print prestaje da štampa PDF priloge u Outlook Desktop-u](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry datoteke](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Sprečavanje vraćanja uklonjenih aplikacija tokom update-a](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Rezultati testiranja FTK i Registry Viewer-a](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Baza podataka instaliranih servisa](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks ne uspevaju uz grešku Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigacija kroz Windows Mail bazu podataka](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
