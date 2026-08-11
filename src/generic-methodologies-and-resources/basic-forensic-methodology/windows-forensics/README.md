# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

Baza podataka obaveštenja po korisniku nalazi se u `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (na primer, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Rana izdanja Windows 10 koristila su `appdb.dat`; Anniversary Update (1607) uveo je `wpndatabase.db`. SQLite baza podataka sadrži tabelu `Notification` sa sadržajem obaveštenja i poljima vremenskih oznaka, iako se period zadržavanja i dostupni podaci razlikuju u zavisnosti od izdanja i politike čišćenja.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline je funkcija istorije aktivnosti koja može sadržati zapise za podržane aplikacije, dokumente i druge aktivnosti korisnika; obuhvat zavisi od aplikacije i verzije Windows-a.<sup>[[4]](#references)</sup>

Baza podataka se nalazi na lokaciji `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Može se otvoriti pomoću SQLite-a ili analizirati pomoću alata [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), čiji se izlaz može pregledati pomoću alata [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Datoteke preuzete izvan lokalne granice poverenja mogu sadržati **alternativni tok podataka `Zone.Identifier`**, koji beleži informacije o zoni i može sadržati metapodatke o poreklu, kao što je URL. Njegovo prisustvo i polja zavise od izvora i sistemske politike.<sup>[[6]](#references)</sup>

## **Rezervne kopije datoteka**

### Recycle Bin

Na sistemima Vista i novijim, **Recycle Bin** se može pronaći u fascikli **`$Recycle.bin`** u korenu diska (na primer, `C:\$Recycle.bin`).\
Kada se datoteka obriše u ovoj fascikli, kreiraju se 2 određene datoteke:

- `$I{id}`: Informacije o datoteci, uključujući vreme brisanja i originalnu putanju
- `$R{id}`: Sadržaj datoteke

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

Ako imate ove datoteke, možete koristiti alat [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) za izdvajanje originalne putanje i vremena brisanja (koristite verziju koja odgovara ciljnom izdanju Windows-a).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Rezervne kopije datoteka - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) može da kreira shadow copies volumena u određenom trenutku dok su datoteke u upotrebi; shadow copy nije zamena za forenzičku sliku.<sup>[[8]](#references)</sup>

Metapodaci kopije se obično povezuju sa direktorijumom `\System Volume Information` u korenu volumena, uz identifikatore koji se razlikuju u zavisnosti od sistema:

![Recycle Bin - Volume Shadow Copies: Ove rezervne kopije se obično nalaze u System Volume Information u korenu sistema datoteka, a naziv se sastoji od UID-ova prikazanih na...](<../../../images/image (94).png>)

Nakon montiranja image-a pomoću odgovarajućeg forenzičkog mounter-a, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) može da izlista dostupne VSS snapshot-e i da pregleda ili kopira datoteke iz njih.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Nakon montiranja forenzičkog image-a pomoću ArsenalImageMounter-a, alat ShadowCopyView može da se koristi za pregled shadow copy-ja, pa čak i za ekstrakciju datoteka...](<../../../images/image (576).png>)

Konfiguracija registry writer-a za VSS uključuje `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, gde mogu biti navedene datoteke i ključevi izuzeti iz backup-a:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Registry unos HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore sadrži datoteke i ključeve koji se ne bekapuju](<../../../images/image (254).png>)

Ključ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` takođe sadrži konfiguraciju VSS service-a.<sup>[[8]](#references)</sup>

### Automatski sačuvane Office datoteke

Lokacije AutoRecover-a se razlikuju u zavisnosti od Office aplikacije, verzije i konfiguracije. Za Word, Microsoft navodi `%APPDATA%\Microsoft\Word` kao podrazumevanu lokaciju; proverite podešavanja aplikacije da biste utvrdili aktivnu putanju.<sup>[[12]](#references)</sup>

## Shell Items

Shell item je stavka koja sadrži informacije o načinu pristupa drugoj datoteci.

### Nedavno korišćeni dokumenti (LNK)

Windows obično kreira prečice za nedavno korišćene stavke kada korisnik otvori stavku ili joj na drugi način pristupi:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Pristup folderu takođe može da kreira linkove za taj folder i povezane nadređene foldere.

Ove link datoteke mogu da sadrže tip odredišta, MAC vremena odredišta, informacije o volumenu i putanju odredišta. Ti metapodaci mogu pomoći u identifikovanju uklonjenog odredišta, ali sam artifact nije dokaz da je određeni korisnik otvorio odredište.<sup>[[13]](#references)[[14]](#references)</sup>

Vremenske oznake LNK datoteke u sopstvenom filesystem-u i ugrađene vremenske oznake odredišta međusobno se razlikuju. Nemojte tumačiti kreiranje linka kao prvo korišćenje ili izmenu linka kao poslednje korišćenje bez potvrde iz drugih artifact-a; format čuva vremenske oznake odredišta odvojeno od vremenskih oznaka link datoteke.<sup>[[13]](#references)[[14]](#references)</sup>

Postojeći [**LinkParser**](http://4discovery.com/our-tools/) link zadržan je kao istorijska opcija, ali njegova dokumentacija nije bila dostupna tokom pregleda. Za dokumentovani parser komandne linije koristite [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Ovi alati obično prikazuju dva skupa vremenskih oznaka:

- **Vremenske oznake odredišta:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Vremenske oznake link datoteke:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Prvi skup odnosi se na odredište; drugi skup odnosi se na samu LNK datoteku. Oba skupa tumačite u skladu sa dokumentacijom parser-a i kontekstom filesystem-a.<sup>[[14]](#references)[[15]](#references)</sup>

Iste informacije možete dobiti pokretanjem Windows CLI alata: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
U ovom slučaju, informacije će biti sačuvane unutar CSV datoteke.

### Jumplists

Jump Lists su liste nedavnih stavki ili stavki specifičnih za zadatke po aplikaciji i mogu biti automatske ili prilagođene.<sup>[[13]](#references)</sup>

Automatic Jump Lists se čuvaju u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` i koriste nazive kao što je `{id}.automaticDestinations-ms`, pri čemu ID identifikuje aplikaciju.

Custom Jump Lists se čuvaju u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; aplikacija kontroliše koje unose zadataka ili stavki kreira.

Vremena kreiranja i izmene koja beleži filesystem opisuju Jump List datoteku, a ne automatski prvi i poslednji pristup svakoj navedenoj ciljnoj stavci. Uparite parsirane unose sa vremenskim oznakama datoteke i drugim artefaktima.<sup>[[13]](#references)</sup>

Jump Lists možete pregledati pomoću alata [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Jump Lists možete pregledati pomoću alata JumplistExplorer](<../../../images/image (168).png>)

(_Imajte na umu da su vremenske oznake koje prikazuje JumplistExplorer povezane sa samom jumplist datotekom_)

### Shellbags

[**Pratite ovaj link da biste saznali šta su shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Korišćenje Windows USB uređaja

Korišćenje USB uređaja ponekad se može potvrditi artefaktima kreiranim prilikom pristupa datotekama sa prenosivih medija, uključujući:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Alati kao što je [**USBDetective**](https://usbdetective.com) povezuju ove artefakte sa zapisima o USB uređajima, ali dostupnost artefakata zavisi od verzije Windows-a i aplikacije.<sup>[[18]](#references)</sup>

U testiranju MTP radnih tokova dokumentovanih za Windows XP i Windows 7, neki LNK-ovi su upućivali na `WPDNSE` folder umesto na originalnu putanju.<sup>[[16]](#references)</sup>

![Shellbags - Use of Windows USBs: Imajte na umu da neke LNK datoteke, umesto da upućuju na originalnu putanju, upućuju na WPDNSE folder](<../../../images/image (218).png>)

Ta studija je uočila kopije u `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; privremeni sadržaj nije preživeo restart u njenim testovima, a GUID se mogao povezati sa shellbag podacima. Ovo treba posmatrati kao ponašanje zavisno od OS-a, uređaja i aplikacije, a ne kao univerzalno pravilo.<sup>[[16]](#references)</sup>

### Registry Information

[Proverite ovu stranicu da biste saznali](interesting-windows-registry-keys.md#usb-information) koji registry ključevi sadrže zanimljive informacije o povezanim USB uređajima.

### setupapi

Na sistemima Vista i novijim, pregledajte `C:\Windows\inf\setupapi.dev.log` u potrazi za aktivnostima instalacije uređaja. Zaglavlja odeljaka uključuju vremenske oznake `Section start`; ona dokumentuju obradu podešavanja i treba ih povezati sa drugim dokazima o povezivanju, a ne tretirati kao tačno vreme fizičkog priključivanja uređaja.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Proverite datoteku C: Windows inf setupapi.dev.log da biste dobili vremenske oznake o tome kada je USB veza uspostavljena (pretražite Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) se može koristiti za prikupljanje informacija o USB uređajima koji su bili povezani sa image-om.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective se može koristiti za prikupljanje informacija o USB uređajima koji su bili povezani sa image-om](<../../../images/image (452).png>)

### Plug and Play Cleanup

Zakazani task pod nazivom `Plug and Play Cleanup` uklanja zastarele verzije drajvera. Definicija Windows 10 taska koju je dokumentovao Adam Harrison takođe cilja drajvere koji su neaktivni 30 dana, pa dokazi o drajverima prenosivih uređaja mogu biti očišćeni; pre generalizovanja ovog ponašanja potvrdite lokalnu definiciju taska i build Windows-a.<sup>[[1]](#references)</sup>

Task se nalazi na sledećoj putanji: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Ključne komponente i podešavanja taska:**

- **pnpclean.dll**: Ovaj DLL je odgovoran za stvarni proces čišćenja.
- **UseUnifiedSchedulingEngine**: Podešeno na `TRUE`, što označava korišćenje generičkog engine-a za zakazivanje taskova.
- **MaintenanceSettings**:
- **Period ('P1M')**: Usmerava Task Scheduler da pokrene task čišćenja jednom mesečno tokom redovnog Automatic održavanja.
- **Deadline ('P2M')**: Nalaže Task Scheduler-u da, ako task ne uspe dva uzastopna meseca, izvrši task tokom hitnog Automatic održavanja.

Ova konfiguracija zakazuje redovno održavanje i ponovne pokušaje nakon uzastopnih neuspeha; tačan XML i ponašanje zavise od verzije.<sup>[[1]](#references)</sup>

**Za više informacija pogledajte:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Emails

Emails sadrže **2 zanimljiva dela: zaglavlja i sadržaj** email-a. U **zagavljima** možete pronaći informacije kao što su:

- **Ko** je poslao emails (email adresa, IP, mail serveri koji su preusmerili email)
- **Kada** je email poslat

Takođe, zaglavlja `References` i `In-Reply-To` mogu sadržati ID-ove poruka koji se koriste za povezivanje odgovora sa konverzacijom.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: Kada je email poslat](<../../../images/image (593).png>)

### Windows Mail App

Ova aplikacija čuva sadržaj email-a u pomoćnim tekstualnim ili HTML datotekama na putanjama kao što je `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; tačan raspored numerisanih foldera i datoteka može se razlikovati u zavisnosti od artefakta.<sup>[[75]](#references)</sup>

**Metadata** email-ova i **kontakti** mogu se pronaći unutar **ESE baze** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` koristi Extensible Storage Engine (ESE) format. Radite na kopiji i koristite ESE parser kao što je [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); ako alat zahteva sufiks `.edb`, preimenujte samo kopiju i proverite šemu tabela pre oslanjanja na tabelu `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Prilikom pregledanja Outlook MAPI svojstava, kanonska svojstva uključuju:

- `PidTagClientSubmitTime`: UTC vreme kada je klijent poslao poruku.
- `PidTagConversationIndex`: relativna pozicija poruke u niti konverzacije.
- `PidTagEntryId`: identifikator objekta poruke.
- `PidTagMessageFlags`: statusne zastavice kao što su poslato, pročitano, nepročitano ili sa prilozima.
- `PidTagLastVerbExecuted`: poslednja operacija zabeležena za poruku, kao što su otvaranje, odgovaranje ili prosleđivanje.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Lokacije Outlook data-file datoteka razlikuju se u zavisnosti od verzije i tipa naloga. Microsoft dokumentuje sledeće uobičajene lokacije za PST/OST datoteke:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry putanja `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` može identifikovati Outlook profil i povezanu konfiguraciju data-file datoteka.

PST datoteke mogu sadržati poruke, kontakte, podatke kalendara i druge Outlook stavke. Kopiju možete pregledati pomoću alata [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: PST datoteku možete otvoriti pomoću alata Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST datoteka** je lokalni cache za Exchange ili Microsoft 365 naloge; Cached Exchange Mode se ne primenjuje na POP ili IMAP naloge. Period rada van mreže može da se konfiguriše i često je podrazumevano podešen na 12 meseci, dok su ograničenja veličine PST/OST datoteka zasebna podesiva podešavanja. Za pregled OST datoteke može se koristiti [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Retrieving Attachments

Izgubljeni prilozi mogu se povratiti iz:

- Za legacy Outlook/IE konfiguracije: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Za novije Outlook/IE11 konfiguracije: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** čuva podatke profila u `%APPDATA%\Thunderbird\Profiles`; mail folderi obično koriste mbox datoteke bez ekstenzije u folderima `Mail` ili `ImapMail` specifičnim za nalog.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Pregledi sličica obično su čuvani u `thumbs.db` datotekama po folderu.
- **Network folders**: `thumbs.db` datoteka i dalje može biti kreirana za UNC folder kada je relevantno ponašanje sličica omogućeno; nemojte pretpostaviti da je svaka verzija Windows-a ili policy kreira.
- **Windows Vista i noviji**: System thumbnail cache je centralizovan u `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, sa datotekama kao što je **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) može parsirati legacy `Thumbs.db`, dok [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) može parsirati moderne baze podataka keša sličica.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

Windows Registry, koji čuva konfiguracione podatke sistema i korisnika, sadržan je u hive datotekama na sledećim lokacijama:

- `%WINDIR%\System32\Config` za machine hive-ove koji podržavaju različite `HKEY_LOCAL_MACHINE` podključeve.
- `%USERPROFILE%\NTUSER.DAT` za `HKEY_CURRENT_USER` hive korisnika.
- Neke starije Windows instalacije sadrže kopije u `%WINDIR%\System32\Config\RegBack\`; Windows 10 version 1803 i novije verzije ne popunjavaju automatski ovaj direktorijum osim ako nije omogućeno periodično backup-ovanje.<sup>[[34]](#references)[[35]](#references)</sup>
- Podaci shell-a i class-registration podaci po korisniku takođe se obično čuvaju u `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` na modernim Windows sistemima.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Neki alati su korisni za analizu registry hive-ova; pre oslanjanja na rezultat proverite podržane formate hive-ova i verziju svakog alata:

- **Registry Editor**: Instaliran je u Windows-u. To je GUI za navigaciju kroz Windows registry trenutne sesije.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Omogućava učitavanje registry datoteke i navigaciju kroz nju pomoću GUI-ja. Takođe sadrži Bookmarks koji ističu ključeve sa zanimljivim informacijama.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Takođe ima GUI koji omogućava navigaciju kroz učitani registry, a sadrži i plugins koji ističu zanimljive informacije unutar učitanog registry-ja.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Još jedna GUI aplikacija koja može da izvuče informacije iz učitanog registry hive-a.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recovering Deleted Element

Obrisane ćelije hive-a mogu ostati dok se njihov prostor ne iskoristi ponovo, ali oporavak zavisi od stanja hive-a i parsera; oporavljene obrisane ključeve tretirajte kao dokaze koji zahtevaju validaciju, a ne kao garantovane zapise.

### Last Write Time

Registry ključevi sadrže vremensku oznaku poslednjeg upisa; Windows je izlaže za ključ ili bilo koji njegov value entry, tako da value ne mora imati sopstvenu nezavisnu vremensku oznaku izmene.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive sadrži podatke o lokalnim korisničkim i grupnim nalozima, uključujući hash-eve lozinki zaštićene materijalom system boot-key-a.<sup>[[38]](#references)[[39]](#references)</sup>

U `SAM\Domains\Account\Users` možete dobiti identifikatore naloga i neka polja za prijavljivanje i policy. Offline izvlačenje hash-eva takođe zahteva `SYSTEM` hive radi oporavka relevantnog materijala boot-key-a.<sup>[[38]](#references)[[39]](#references)</sup>

### Zanimljivi unosi u Windows Registry-ju


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

Postojeći [post o uobičajenim Windows procesima](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) zadržan je kao dodatna literatura; tvrdnje o ponašanju procesa potvrdite aktuelnom Windows dokumentacijom i lokalnim dokazima.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Na Windows 10 verzijama koje ga izlažu, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` sadrži podključeve po aplikaciji sa poljima kao što su vreme poslednje upotrebe i broj pokretanja; artefakt je uklonjen iz novijih izdanja, pa proverite ciljni build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Na sistemima koji izlažu Background Activity Moderator, pregledajte putanju `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` ili noviju putanju `...\bam\State\UserSettings\{SID}`. Vrednosti su indeksirane SID-om korisnika i mogu sadržati praćene putanje izvršnih datoteka i podatke o izvršavanju nalik FILETIME-u; artefakt zavisi od verzije i treba ga potvrditi drugim dokazima.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch kešira resurse i metadata pokretanja kako bi programi mogli brže da se pokrenu.

Prefetch datoteke se čuvaju kao `.pf` datoteke u `C:\Windows\Prefetch`; format, zadržavanje i ograničenja broja datoteka razlikuju se u zavisnosti od verzije Windows-a. Microsoft dokumentuje zadržavanje poslednjih osam vremena izvršavanja i do 1024 datoteke na Windows 8 i novijim verzijama, pa se stariji sažeci sa fiksnim ograničenjima ne mogu generalizovati.<sup>[[13]](#references)</sup>

Naziv datoteke obično koristi format `{program_name}-{hash}.pf`, pri čemu se hash izvodi iz konteksta izvršavanja, kao što su putanja i argumenti; Windows 10 i noviji mogu kompresovati datoteku. Prisustvo predstavlja koristan dokaz izvršavanja, ali samo po sebi nije dokaz da je izvršavanje pokrenuo korisnik i treba ga povezati sa drugim artefaktima.<sup>[[13]](#references)</sup>

Za pregled ovih datoteka možete koristiti [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), koji dokumentuje parsiranje direktorijuma, CSV/HTML output i podršku za dekompresiju primenljivih Windows 10 Prefetch datoteka.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Moderator aktivnosti u pozadini) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** dopunjuje Prefetch korišćenjem istorijskih obrazaca upotrebe radi poboljšanja učitavanja. Na sistemima koji ih generišu, njegove datoteke baze podataka obično se nalaze na lokaciji `C:\Windows\Prefetch\Ag*.db`; format i prisustvo zavise od verzije sistema.<sup>[[41]](#references)</sup>

Ove baze podataka mogu sadržati nazive aplikacija, broj korišćenja, pristupane datoteke ili volumene, putanje i vremenske opsege, ali ih ne treba posmatrati kao precizan dnevnik izvršavanja.<sup>[[41]](#references)</sup>

Postojeća veza ka alatu [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) zadržana je kao mogući parser; pre upotrebe proverite njegovu trenutnu dostupnost i podržani izlaz u dokumentaciji alata.

### SRUM

**System Resource Usage Monitor** (SRUM) beleži korišćenje resursa od strane aplikacija i korisnika. Uveden je u Windows 8 i čuva podatke u ESE bazi podataka `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Pruža sledeće informacije:

- AppID i putanja
- Korisnik/SID povezan sa zapisom
- Poslati bajtovi
- Primljeni bajtovi
- Mrežni interfejs
- Trajanje veze
- Trajanje procesa

Učestalost prikupljanja i period zadržavanja zavise od implementacije; nemojte pretpostaviti da svaki zapis predstavlja tačan interval izvršavanja od 60 minuta.<sup>[[13]](#references)</sup>

Podatke možete izdvojiti i pregledati pomoću alata [**srum_dump**](https://github.com/MarkBaggett/srum-dump), koristeći opcije dokumentovane za trenutnu verziju alata.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, takođe poznat kao **ShimCache**, deo je Windows infrastrukture za kompatibilnost aplikacija i beleži metapodatke o datotekama radi donošenja odluka o kompatibilnosti. Putanja hive-a, format zapisa, zadržani kapacitet i polja razlikuju se u zavisnosti od izdanja Windows-a; na modernim sistemima, sam ShimCache ne može da dokaže da je korisnik izvršio datoteku. Parsirajte relevantni `SYSTEM` hive pomoću alata [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) i potvrdite njegov izlaz drugim artefaktima izvršavanja.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Za parsiranje sačuvanih informacija preporučuje se upotreba alata AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Datoteka **Amcache.hve** je registry hive koji sadrži inventar aplikacija i datoteka koje je Windows uočio. Obično se nalazi na lokaciji `C:\Windows\AppCompat\Programs\Amcache.hve`.

Može sadržati povezane i nepovezane unose datoteka, putanje i SHA1 vrednosti, ali njeno prisustvo predstavlja dokaz o inventaru i samo po sebi ne dokazuje da je proces izvršen.<sup>[[13]](#references)[[44]](#references)</sup>

Za izdvajanje i analizu datoteke **Amcache.hve** koristite alat [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Ova komanda parsira hive i upisuje CSV izlaz.<sup>[[44]](#references)</sup>

Na primer:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Među generisanim CSV datotekama, `Amcache_Unassociated file entries` može biti koristan pri istraživanju datoteka koje nisu povezane sa prepoznatim programom.<sup>[[44]](#references)</sup>

### RecentFileCache

Na Windows 7 sistemima, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` može sadržati informacije o nedavno uočenim binarnim datotekama; dostupnost i semantika zavise od verzije.

Možete koristiti [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) za parsiranje datoteke.<sup>[[45]](#references)</sup>

### Scheduled tasks

Dokazi o scheduled tasks mogu se pronaći u `C:\Windows\System32\Tasks` za moderne tasks i u `C:\Windows\Tasks` sa `.job` datotekama za legacy tasks; proverite format definicije taska koji odgovara operativnom sistemu.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Baza podataka Service Control Manager-a nalazi se pod `SYSTEM\CurrentControlSet\Services` (za offline SYSTEM hive proverite odgovarajući control-set ključ); sadrži konfiguraciju services i driver-a, kao što su putanje izvršnih datoteka i tipovi pokretanja.<sup>[[72]](#references)</sup>

### **Windows Store**

Instalirane Windows Store aplikacije mogu biti predstavljene pod `\ProgramData\Microsoft\Windows\AppRepository\`, uključujući bazu podataka **`StateRepository-Machine.srd`**. Schema i putanje se razlikuju u zavisnosti od izdanja Windows-a.<sup>[[71]](#references)</sup>

Baza podataka može sadržati identifikatore aplikacija, brojeve paketa i prikazna imena. Praznine u identifikatorima same po sebi nisu dokaz da je aplikacija deinstalirana; potvrdite nalaze pomoću stanja paketa i registry-ja.

Registracije paketa mogu se pojaviti i pod `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft dokumentuje `Deprovisioned` podključ specifičan za verziju, za uklonjene provisioned aplikacije; nemojte pretpostaviti da `Deleted` podključ postoji u svakoj build verziji.<sup>[[70]](#references)</sup>

## Windows Events

U zavisnosti od provider-a, Windows events mogu sadržati:

- Šta se dogodilo
- Vremensku oznaku `TimeCreated`, koja se mora tumačiti u skladu sa event schemom i vremenskim kontekstom hosta
- Uključene korisnike
- Uključene hostove (hostname, IP)
- Pristupljene asset-e (datoteke, fascikle, štampače ili services).<sup>[[49]](#references)</sup>

Pre Windows Vista, event logs su uglavnom koristili legacy binarni format u okviru `C:\Windows\System32\config`; Vista i novije verzije koriste Windows Event Log format, obično u okviru `C:\Windows\System32\winevt\Logs`, pri čemu `.evtx` datoteke sadrže XML-renderovane podatke o eventima.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry čuva konfiguraciju channel-a pod **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, uključujući konfigurisanu putanju datoteke i postavke zadržavanja.<sup>[[47]](#references)</sup>

Mogu se pregledati pomoću Windows Event Viewer-a (**`eventvwr.msc`**) ili tools kao što su [**Event Log Explorer**](https://eventlogxp.com) i [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Na Vista i novijim verzijama, Security channel se obično čuva na `C:\Windows\System32\winevt\Logs\Security.evtx`. Njegova maksimalna veličina i retention policy mogu se konfigurisati; kod circular logging-a, stariji zapisi mogu biti prepisani kada datoteka dostigne ograničenje. Channel može beležiti authentication, logoff, privilege, audit-policy i object-access events kada je odgovarajuće auditing podešavanje omogućeno.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: Uspešan logon naloga.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Neuspešan logon naloga.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Logon session je prekinuta.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Korisnik je pokrenuo logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Posebne privilegije su dodeljene novom logon-u; ovo je uobičajeno za system i administrator accounts, pa samo po sebi nije dokaz malicious activity-ja.<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: Interaktivni lokalni logon.
- **Network (3)**: Pristup shared resource-u.
- **Batch (4)**: Logon batch-process-a.
- **Service (5)**: Logon service-a.
- **Unlock (7)**: Otključavanje workstation-a.
- **NetworkCleartext (8)**: Network logon koji authentication package-u prosleđuje credentials u cleartext-u.
- **NewCredentials (9)**: Logon koji koristi prosleđene alternate credentials za outbound connections.
- **RemoteInteractive (10)**: Remote Desktop ili Terminal Services logon.
- **CachedInteractive (11)**: Interaktivni logon koji koristi cached domain credentials.
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon.
- **CachedUnlock (13)**: Otključavanje pomoću cached credentials.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: Takav korisnik ne postoji.
- **0xC000006A**: Ispravno korisničko ime, ali pogrešna lozinka.
- **0xC0000234**: Nalog je zaključan.
- **0xC0000072**: Nalog je onemogućen.
- **0xC000006F**: Logon van dozvoljenog vremena.
- **0xC0000070**: Kršenje ograničenja workstation-a.
- **0xC0000193**: Nalog je istekao.
- **0xC0000071**: Lozinka je istekla.
- **0xC0000133**: Vremenska razlika između client-a i server-a je prevelika.
- **0xC0000224**: Nalog mora promeniti lozinku.
- **0xC0000225**: `STATUS_NOT_FOUND`; sam kod ne identifikuje system bug ili attack.
- **0xC000015B**: Zahtevani logon type nije odobren za nalog.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Vreme sistema je promenjeno. Mnogi events odražavaju rutinsku korekciju time-service-a, zato pre nego što ovo smatrate tampering-om povežite actor-a i source vremena.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: Event 12 beleži pokretanje OS-a, 13 beleži gašenje OS-a, 1074 beleži planirano gašenje ili restart, 6008 ukazuje na neočekivano gašenje, a 6009 beleži Windows verziju pri boot-u. Events 6005 i 6006 ukazuju na to da je Event Log service pokrenut, odnosno zaustavljen; sami po sebi nisu dokaz pokretanja i gašenja OS-a.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 beleži da je Security audit log obrisan; istražite actor-a i okolne events umesto da nameru pretpostavite samo na osnovu ovog event-a.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: `UserPnp` device-installation events koji mogu pomoći u utvrđivanju prve upotrebe ili aktivnosti instalacije.
- **10000 / 10100**: `DriverFrameworks-UserMode` events koji mogu pratiti aktivnosti uređaja.
- **Event ID 112**: `DeviceSetupManager/Admin` activity koja može pružiti timestamps povezane sa priključivanjem.
- Provider, channel i semantika event-a razlikuju se u zavisnosti od verzije Windows-a; proverite ime provider-a i payload event-a pre nego što mu dodelite značenje.<sup>[[59]](#references)</sup>

Za praktične primere logon types i sa njima povezanog credential material-a pogledajte [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Detalji event-a, uključujući logon type, status, substatus, source address i process fields, pružaju kontekst za Event ID 4625; status code ili ponavljani pattern neuspeha predstavljaju istražni trag, a ne zaključak.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Pošto su event logs obično circular, zapisi koje je logger prepisao možda se ne mogu oporaviti. Sačuvajte forensic image ili working copy pre interakcije sa live system-om; koristite validated parser ili carver, kao što je **Bulk_extractor**, tek nakon potvrde da verzija tool-a podržava ciljne `.evtx` podatke i nemojte isključivati system koji radi samo da biste pokušali da oporavite events.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Za praktičnu referencu Event ID-jeva pogledajte postojeći link [Red Team Recipe](https://redteamrecipe.com/event-codes/) i proverite njegove primere u odnosu na prethodnu dokumentaciju provider-a.

#### Brute Force Attacks

Povežite ponovljene neuspehe Event ID 4625 sa kasnijim uspehom 4624, logon type-om, statusom, source-om i kontekstom naloga; sekvenca je indikator za istragu, a ne dokaz attack-a.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 beleži promene system time-a, što može otežati timeline analysis; uporedite ga sa dokazima time-service-a i host-a.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB Event IDs su specifični za provider; povežite `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 i `DeviceSetupManager/Admin` 112 sa SetupAPI i registry artifacts.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Koristite 12/13/1074/6008/6009 za kontekst pokretanja, gašenja i restartovanja OS-a, kao i neočekivanog gubitka napajanja; 6005/6006 označavaju pokretanje/zaustavljanje Event Log service-a.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 beleži da je Security audit log obrisan i treba ga povezati sa odgovornim nalogom i process-om.<sup>[[62]](#references)</sup>

## References

- [1] [Čišćenje Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Istraživanje uobičajenih Windows procesa](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Digitalno-forenzički prikaz Windows 10 notifications](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier i Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operacije backup-a i restore-a registry-ja pod VSS-om](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry ključevi za backup i restore](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problem sa performansama Word-a na AutoRecover lokaciji](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Vodič za Incident Response](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Identifikovanje artifacts eksfiltracije podataka](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Unosi u SetupAPI log za instalaciju uređaja](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID i povezani types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Pronalaženje i prenos Outlook data files](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Uključivanje Cached Exchange Mode-a](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Sinhronizuje se samo podskup stavki](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Konfigurisanje ograničenja veličine za Outlook data files](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Gde Thunderbird čuva user data](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings i mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry nije backup-ovan u RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Daljinsko uređivanje registry-ja](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Tehnički pregled lozinki](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Format Event Log datoteke](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry ključ](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Rešavanje problema sa neočekivanim reboot-ovima pomoću system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Rešavanje problema sa gašenjem u toku procesa](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forensics USB Storage Device-a za Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderator aktivnosti u pozadini](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print prestaje da štampa PDF attachments u Outlook Desktop-u](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry datoteke](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Sprečavanje vraćanja uklonjenih aplikacija tokom update-a](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Rezultati testiranja FTK i Registry Viewer-a](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Baza podataka instaliranih services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks ne uspevaju uz grešku Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigacija kroz Windows Mail bazu podataka](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
