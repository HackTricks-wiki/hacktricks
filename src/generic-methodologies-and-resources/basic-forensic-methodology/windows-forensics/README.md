# Windows Artefakti

{{#include ../../../banners/hacktricks-training.md}}

## Generički Windows artefakti

### Windows 10 obaveštenja

Na putanji `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` možete pronaći bazu podataka `appdb.dat` (pre Windows anniversary) ili `wpndatabase.db` (nakon Windows Anniversary).

Unutar ove SQLite baze podataka možete pronaći tabelu `Notification` sa svim obaveštenjima (u XML formatu) koja mogu sadržati zanimljive podatke.

### Vremenska linija

Timeline je Windows karakteristika koja pruža **hronološku istoriju posećenih veb-stranica, izmenjenih dokumenata i izvršenih aplikacija**.

Baza podataka se nalazi na putanji `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Ova baza podataka može se otvoriti pomoću SQLite alata ili alata [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), **koji generiše 2 datoteke koje se mogu otvoriti pomoću alata** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Preuzete datoteke mogu sadržati **ADS Zone.Identifier**, koji ukazuje na to **kako** su **preuzete** sa intraneta, interneta itd. Neki softver (kao što su browseri) obično dodaje čak i **više** **informacija**, kao što je **URL** sa kojeg je datoteka preuzeta.

## **Rezervne kopije datoteka**

### Korpa za otpatke

U sistemima Vista/Win7/Win8/Win10 **Korpa za otpatke** može se pronaći u fascikli **`$Recycle.bin`** u korenu diska (`C:\$Recycle.bin`).\
Kada se datoteka obriše u ovoj fascikli, kreiraju se 2 specifične datoteke:

- `$I{id}`: Informacije o datoteci (datum njenog brisanja}
- `$R{id}`: Sadržaj datoteke

![Rezervne kopije datoteka - Korpa za otpatke: $R{id}: Sadržaj datoteke](<../../../images/image (1029).png>)

Pomoću ovih datoteka možete koristiti alat [**Rifiuti**](https://github.com/abelcheung/rifiuti2) da dobijete originalnu lokaciju obrisanih datoteka i datum njihovog brisanja (koristite `rifiuti-vista.exe` za Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Datoteke rezervnih kopija - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy je tehnologija uključena u Microsoft Windows koja može da kreira **rezervne kopije** ili snimke računarskih datoteka ili volumena, čak i kada se oni koriste.

Ove rezervne kopije se obično nalaze u `\System Volume Information` u korenu sistema datoteka, a naziv se sastoji od **UID-ova**, kao što je prikazano na sledećoj slici:

![Recycle Bin - Volume Shadow Copies: Ove rezervne kopije se obično nalaze u System Volume Information u korenu sistema datoteka, a naziv se sastoji od UID-ova, kao što je prikazano na...](<../../../images/image (94).png>)

Montiranjem forenzičke slike pomoću alata **ArsenalImageMounter**, alat [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) može da se koristi za pregled shadow copy-ja, pa čak i za **izdvajanje datoteka** iz shadow copy rezervnih kopija.

![Recycle Bin - Volume Shadow Copies: Montiranjem forenzičke slike pomoću alata ArsenalImageMounter, alat ShadowCopyView može da se koristi za pregled shadow copy-ja, pa čak i za izdvajanje datoteka...](<../../../images/image (576).png>)

Registarski unos `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` sadrži datoteke i ključeve koje **ne treba uključiti u rezervne kopije**:

![Recycle Bin - Volume Shadow Copies: Registarski unos HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore sadrži datoteke i ključeve koje ne treba uključiti u rezervne kopije](<../../../images/image (254).png>)

Registar `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` takođe sadrži konfiguracione informacije o funkciji `Volume Shadow Copies`.

### Automatski sačuvane Office datoteke

Office automatski sačuvane datoteke možete pronaći na lokaciji: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Shell item je stavka koja sadrži informacije o tome kako pristupiti drugoj datoteci.

### Nedavni dokumenti (LNK)

Windows **automatski** **kreira** ove **prečice** kada korisnik **otvori, koristi ili kreira datoteku** u:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Kada se kreira fascikla, kreiraju se i linkovi ka toj fascikli, nadređenoj fascikli i fascikli na još višem nivou.

Ove automatski kreirane datoteke linkova **sadrže informacije o poreklu**, na primer da li je u pitanju **datoteka** **ili** **fascikla**, **MAC** **vremena** te datoteke, **informacije o volumenu** na kojem je datoteka sačuvana i **fascikla ciljne datoteke**. Ove informacije mogu biti korisne za oporavak tih datoteka u slučaju da su obrisane.

Takođe, **datum kreiranja linka** je prvo **vreme** kada je originalna datoteka **prvi put** **korišćena**, a **datum izmene** linka je poslednje **vreme** kada je datoteka porekla korišćena.

Za pregled ovih datoteka možete koristiti [**LinkParser**](http://4discovery.com/our-tools/).

U ovom alatu pronaći ćete **2 skupa** vremenskih oznaka:

- **Prvi skup:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Drugi skup:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Prvi skup vremenskih oznaka odnosi se na **vremenske oznake same datoteke**. Drugi skup odnosi se na **vremenske oznake linkovane datoteke**.

Iste informacije možete dobiti pokretanjem Windows CLI alata: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
U ovom slučaju, informacije će biti sačuvane unutar CSV datoteke.

### Jumplists

Ovo su nedavne datoteke navedene po aplikaciji. To je lista **nedavnih datoteka koje je aplikacija koristila**, kojoj možete pristupiti u svakoj aplikaciji. Mogu biti kreirane **automatski ili prilagođeno**.

Automatski kreirani **jumplists** čuvaju se u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplists se imenuju prema formatu `{id}.autmaticDestinations-ms`, gde je početni ID ID aplikacije.

Prilagođeni jumplists čuvaju se u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` i aplikacija ih obično kreira zato što se sa datotekom dogodilo nešto **važno** (možda je označena kao omiljena)

**Vreme kreiranja** bilo kog jumplista označava **prvi put kada je datoteci pristupljeno**, a **vreme izmene poslednji put**.

Jumplists možete pregledati pomoću alata [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Nedavni dokumenti (LNK) - Jumplists: Jumplists možete pregledati pomoću alata JumplistExplorer](<../../../images/image (168).png>)

(_Imajte na umu da se vremenske oznake koje pruža JumplistExplorer odnose na samu datoteku jumplista_)

### Shellbags

[**Pratite ovaj link da biste saznali šta su shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Korišćenje Windows USB uređaja

Moguće je utvrditi da je USB uređaj korišćen zahvaljujući kreiranju:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Imajte na umu da neke LNK datoteke, umesto da upućuju na originalnu putanju, upućuju na fasciklu WPDNSE:

![Shellbags - Korišćenje Windows USB uređaja: Imajte na umu da neke LNK datoteke, umesto da upućuju na originalnu putanju, upućuju na fasciklu WPDNSE](<../../../images/image (218).png>)

Datoteke u fascikli WPDNSE predstavljaju kopije originalnih datoteka, pa neće preživeti ponovno pokretanje računara, a GUID se preuzima iz shellbag-a.

### Informacije iz Registry-ja

[Proverite ovu stranicu da biste saznali](interesting-windows-registry-keys.md#usb-information) koji registry ključevi sadrže zanimljive informacije o povezanim USB uređajima.

### setupapi

Proverite datoteku `C:\Windows\inf\setupapi.dev.log` da biste dobili vremenske oznake o tome kada je USB veza uspostavljena (pretražite `Section start`).

![Informacije iz Registry-ja - setupapi: Proverite datoteku C: Windows inf setupapi.dev.log da biste dobili vremenske oznake o tome kada je USB veza uspostavljena (pretražite Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) može se koristiti za dobijanje informacija o USB uređajima koji su bili povezani sa image-om.

![setupapi - USB Detective: USBDetective može da se koristi za dobijanje informacija o USB uređajima koji su bili povezani sa image-om](<../../../images/image (452).png>)

### Plug and Play Cleanup

Zakazani zadatak poznat kao 'Plug and Play Cleanup' prvenstveno je namenjen uklanjanju zastarelih verzija driver-a. Suprotno njegovoj navedenoj svrsi zadržavanja najnovije verzije driver paketa, online izvori ukazuju na to da takođe cilja driver-e koji nisu bili aktivni 30 dana. Zbog toga driver-i za prenosive uređaje koji nisu bili povezani u prethodnih 30 dana mogu biti obrisani.<sup>[[1]](#references)</sup>

Zadatak se nalazi na sledećoj putanji: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Prikazan je screenshot sadržaja zadatka: ![USB Detective - Plug and Play Cleanup: Zadatak se nalazi na sledećoj putanji: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Ključne komponente i podešavanja zadatka:**

- **pnpclean.dll**: Ovaj DLL je odgovoran za stvarni proces čišćenja.
- **UseUnifiedSchedulingEngine**: Postavljeno na `TRUE`, što označava korišćenje generičkog engine-a za zakazivanje zadataka.
- **MaintenanceSettings**:
- **Period ('P1M')**: Upućuje Task Scheduler da pokrene zadatak čišćenja jednom mesečno tokom redovnog Automatic održavanja.
- **Deadline ('P2M')**: Nalaže Task Scheduler-u da, ako zadatak ne uspe dva uzastopna meseca, izvrši zadatak tokom hitnog Automatic održavanja.

Ova konfiguracija obezbeđuje redovno održavanje i čišćenje driver-a, uz mogućnost ponovnog pokušaja izvršavanja zadatka u slučaju uzastopnih neuspeha.

**Za više informacija pogledajte:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Email poruke

Email poruke sadrže **2 zanimljiva dela: zaglavlja i sadržaj** email poruke. U **zaglavljima** možete pronaći informacije kao što su:

- **Ko** je poslao email poruke (email adresa, IP, mail serveri koji su preusmerili email)
- **Kada** je email poslat

Takođe, u zaglavljima `References` i `In-Reply-To` možete pronaći ID poruka:

![Plug and Play Cleanup - Email poruke: Kada je email poslat](<../../../images/image (593).png>)

### Windows Mail App

Ova aplikacija čuva email poruke u HTML ili tekstualnom formatu. Email poruke možete pronaći unutar podfascikli u `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Email poruke se čuvaju sa ekstenzijom `.dat`.

**Metadata** email poruka i **kontakti** mogu se pronaći unutar **EDB baze podataka**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Promenite ekstenziju** datoteke iz `.vol` u `.edb` i možete koristiti alat [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) da je otvorite. Unutar tabele `Message` možete videti email poruke.

### Microsoft Outlook

Kada se koriste Exchange serveri ili Outlook klijenti, postoje MAPI zaglavlja:

- `Mapi-Client-Submit-Time`: Vreme na sistemu kada je email poslat
- `Mapi-Conversation-Index`: Broj podređenih poruka u thread-u i vremenska oznaka svake poruke u thread-u
- `Mapi-Entry-ID`: Identifikator poruke.
- `Mappi-Message-Flags` i `Pr_last_Verb-Executed`: Informacije o MAPI klijentu (poruka pročitana? nije pročitana? odgovoreno? preusmereno? out of the office?)

U Microsoft Outlook klijentu, sve poslate/primljene poruke, podaci o kontaktima i podaci kalendara čuvaju se u PST datoteci na lokacijama:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry putanja `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` označava datoteku koja se koristi.

PST datoteku možete otvoriti pomoću alata [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: PST datoteku možete otvoriti pomoću alata Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST datoteka** se generiše u Microsoft Outlook-u kada je konfigurisan sa **IMAP** ili **Exchange** serverom i čuva informacije slične onima u PST datoteci. Ova datoteka se sinhronizuje sa serverom, zadržavajući podatke za **poslednjih 12 meseci** do **maksimalne veličine od 50GB**, i nalazi se u istom direktorijumu kao PST datoteka. Za pregled OST datoteke može se koristiti [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Preuzimanje priloga

Izgubljeni prilozi se možda mogu povratiti iz:

- Za **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Za **IE11 i novije**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** koristi **MBOX datoteke** za čuvanje podataka, koje se nalaze u `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Sličice slika

- **Windows XP i 8-8.1**: Pristupanje fascikli sa sličicama generiše datoteku `thumbs.db` koja čuva preglede slika, čak i nakon brisanja.
- **Windows 7/10**: `thumbs.db` se kreira kada se fascikli pristupi preko mreže putem UNC putanje.
- **Windows Vista i noviji**: Pregledi sličica centralizovani su u `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, sa datotekama čiji su nazivi **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) i [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) su alati za pregled ovih datoteka.

### Informacije iz Windows Registry-ja

Windows Registry, koji čuva obimne podatke o aktivnostima sistema i korisnika, nalazi se u datotekama na sledećim lokacijama:

- `%windir%\System32\Config` za različite `HKEY_LOCAL_MACHINE` podključeve.
- `%UserProfile%{User}\NTUSER.DAT` za `HKEY_CURRENT_USER`.
- Windows Vista i novije verzije prave rezervne kopije `HKEY_LOCAL_MACHINE` registry datoteka u `%Windir%\System32\Config\RegBack\`.
- Pored toga, informacije o izvršavanju programa čuvaju se u `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` počev od Windows Vista i Windows 2008 Server verzija.

### Tools

Neki alati su korisni za analizu registry datoteka:

- **Registry Editor**: Instaliran je u Windows-u. To je GUI za navigaciju kroz Windows registry trenutne sesije.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Omogućava učitavanje registry datoteke i navigaciju kroz nju pomoću GUI-ja. Takođe sadrži Bookmarks koji ističu ključeve sa zanimljivim informacijama.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Takođe ima GUI koji omogućava navigaciju kroz učitani registry, a sadrži i plugins koji ističu zanimljive informacije unutar učitanog registry-ja.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Još jedna GUI aplikacija sposobna za izdvajanje važnih informacija iz učitanog registry-ja.

### Povrat obrisanog elementa

Kada se ključ obriše, označava se kao takav, ali se neće ukloniti sve dok prostor koji zauzima ne bude potreban. Zbog toga je pomoću alata kao što je **Registry Explorer** moguće povratiti ove obrisane ključeve.

### Vreme poslednjeg upisa

Svaki Key-Value sadrži **vremensku oznaku** koja označava poslednji trenutak kada je izmenjen.

### SAM

Datoteka/hive **SAM** sadrži hash-eve **korisnika, grupa i lozinki korisnika** sistema.

U `SAM\Domains\Account\Users` možete dobiti korisničko ime, RID, poslednju prijavu, poslednji neuspešni pokušaj prijave, brojač prijava, politiku lozinke i vreme kreiranja naloga. Da biste dobili **hash-eve**, takođe vam je potrebna datoteka/hive **SYSTEM**.

### Zanimljivi unosi u Windows Registry-ju


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Izvršeni programi

### Osnovni Windows procesi

U [ovoj objavi](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) možete saznati više o uobičajenim Windows procesima za otkrivanje sumnjivog ponašanja.<sup>[[2]](#references)</sup>

### Nedavne Windows APPs

Unutar registry-ja `NTUSER.DAT`, na putanji `Software\Microsoft\Current Version\Search\RecentApps`, možete pronaći podključeve sa informacijama o **izvršenoj aplikaciji**, **poslednjem vremenu** njenog izvršavanja i **broju puta** koliko je pokrenuta.

### BAM (Background Activity Moderator)

Datoteku `SYSTEM` možete otvoriti pomoću registry editora, a unutar putanje `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` možete pronaći informacije o **aplikacijama koje je izvršio svaki korisnik** (obratite pažnju na `{SID}` u putanji) i **vremenu** kada su izvršene (vreme se nalazi unutar Data vrednosti registry-ja).

### Windows Prefetch

Prefetching je tehnika koja omogućava računaru da neprimetno **preuzme neophodne resurse potrebne za prikaz sadržaja** kojem korisnik **možda želi da pristupi u bliskoj budućnosti**, kako bi resursi mogli brže da se pristupe.

Windows prefetch podrazumeva kreiranje **cache-ova izvršenih programa** kako bi mogli brže da se učitaju. Ovi cache-ovi se kreiraju kao `.pf` datoteke unutar putanje: `C:\Windows\Prefetch`. Ograničenje je 128 datoteka u XP/VISTA/WIN7 i 1024 datoteke u Win8/Win10.

Naziv datoteke kreira se kao `{program_name}-{hash}.pf` (hash se zasniva na putanji i argumentima executable-a). U W10 ove datoteke su kompresovane. Imajte na umu da samo prisustvo datoteke ukazuje na to da je **program u nekom trenutku izvršen**.

Datoteka `C:\Windows\Prefetch\Layout.ini` sadrži **nazive fascikli datoteka koje se prefetch-uju**. Ova datoteka sadrži **informacije o broju izvršavanja**, **datumima** izvršavanja i **datotekama** koje je program **otvorio**.

Za pregled ovih datoteka možete koristiti alat [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** ima isti cilj kao i prefetch, **brže učitavanje programa** predviđanjem onoga što će sledeće biti učitano. Međutim, ne zamenjuje prefetch servis.\
Ovaj servis generiše datoteke baza podataka u `C:\Windows\Prefetch\Ag*.db`.

U ovim bazama podataka možete pronaći **naziv** **programa**, **broj** **izvršavanja**, **otvorene** **datoteke**, **količinu** **pristupa**, **potpunu** **putanju**, **vremenske okvire** i **vremenske oznake**.

Ovim informacijama možete pristupiti pomoću alata [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **nadzire** **resurse** koje **troši** **proces**. Pojavio se u sistemu W8 i čuva podatke u ESE bazi podataka koja se nalazi na lokaciji `C:\Windows\System32\sru\SRUDB.dat`.

Pruža sledeće informacije:

- AppID i putanja
- Korisnik koji je izvršio proces
- Poslati bajtovi
- Primljeni bajtovi
- Mrežni interfejs
- Trajanje veze
- Trajanje procesa

Ove informacije se ažuriraju svakih 60 minuta.

Podatke iz ove datoteke možete dobiti pomoću alata [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, poznat i kao **ShimCache**, deo je **Application Compatibility Database** sistema koji je razvio **Microsoft** radi rešavanja problema sa kompatibilnošću aplikacija. Ova komponenta sistema beleži različite delove metapodataka o fajlovima, uključujući:

- Punu putanju do fajla
- Veličinu fajla
- Vreme poslednje izmene pod **$Standard_Information** (SI)
- Vreme poslednjeg ažuriranja ShimCache-a
- Process Execution Flag

Ovi podaci se čuvaju u registru na određenim lokacijama, u zavisnosti od verzije operativnog sistema:

- Za XP, podaci se čuvaju u `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, sa kapacitetom od 96 unosa.
- Za Server 2003, kao i za Windows verzije 2008, 2012, 2016, 7, 8 i 10, putanja za čuvanje je `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, sa kapacitetom od 512, odnosno 1024 unosa.

Za parsiranje sačuvanih informacija preporučuje se korišćenje alata [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Za parsiranje sačuvanih informacija preporučuje se korišćenje alata AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Fajl **Amcache.hve** je u suštini registry hive koji beleži detalje o aplikacijama koje su izvršavane na sistemu. Obično se nalazi na lokaciji `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ovaj fajl je značajan jer čuva zapise o nedavno izvršavanim procesima, uključujući putanje do izvršnih fajlova i njihove SHA1 hash vrednosti. Ove informacije su veoma korisne za praćenje aktivnosti aplikacija na sistemu.

Za izdvajanje i analizu podataka iz fajla **Amcache.hve** može se koristiti alat [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Sledeća komanda je primer korišćenja alata AmcacheParser za parsiranje sadržaja fajla **Amcache.hve** i prikaz rezultata u CSV formatu:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Među generisanim CSV datotekama, `Amcache_Unassociated file entries` je posebno značajna zbog obilja informacija koje pruža o nepovezanim unosima datoteka.

Najzanimljivija generisana CSV datoteka je `Amcache_Unassociated file entries`.

### RecentFileCache

Ovaj artifact se može pronaći samo u W7, na lokaciji `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, i sadrži informacije o nedavnom izvršavanju određenih binarnih datoteka.

Možete koristiti alat [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) za parsiranje datoteke.

### Scheduled tasks

Možete ih ekstraktovati iz `C:\Windows\Tasks` ili `C:\Windows\System32\Tasks` i pročitati kao XML.

### Services

Možete ih pronaći u registru, u okviru `SYSTEM\ControlSet001\Services`. Možete videti šta će biti izvršeno i kada.

### **Windows Store**

Instalirane aplikacije mogu se pronaći na lokaciji `\ProgramData\Microsoft\Windows\AppRepository\`\
Ovo spremište sadrži **log** sa **svakom aplikacijom instaliranom** na sistemu, u bazi podataka **`StateRepository-Machine.srd`**.

U tabeli Application ove baze podataka moguće je pronaći kolone: "Application ID", "PackageNumber" i "Display Name". Ove kolone sadrže informacije o unapred instaliranim i instaliranim aplikacijama, a može se utvrditi da li su neke aplikacije deinstalirane, jer bi ID-jevi instaliranih aplikacija trebalo da budu sekvencijalni.

Takođe je moguće **pronaći instalirane aplikacije** u putanji registra: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
A **deinstalirane** **aplikacije** na lokaciji: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Informacije koje se pojavljuju u Windows events su:

- Šta se dogodilo
- Vremenska oznaka (UTC + 0)
- Uključeni korisnici
- Uključeni hostovi (hostname, IP)
- Pristupljena sredstva (datoteke, fascikle, štampači, services)

Logovi se nalaze u `C:\Windows\System32\config` pre Windows Vista, a nakon Windows Vista u `C:\Windows\System32\winevt\Logs`. Pre Windows Vista, event logovi su bili u binarnom formatu, a nakon toga su u **XML formatu** i koriste ekstenziju **.evtx**.

Lokacija event datoteka može se pronaći u SYSTEM registru, na lokaciji **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Mogu se prikazati pomoću Windows Event Viewer-a (**`eventvwr.msc`**) ili drugim alatima, kao što su [**Event Log Explorer**](https://eventlogxp.com) **ili** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Razumevanje Windows Security Event Logging

Access events se beleže u security konfiguracionoj datoteci koja se nalazi na lokaciji `C:\Windows\System32\winevt\Security.evtx`. Veličina ove datoteke može se podešavati, a kada se dostigne njen kapacitet, stariji events se prepisuju. Zabeleženi events obuhvataju prijavljivanja i odjavljivanja korisnika, radnje korisnika i promene security podešavanja, kao i pristup datotekama, fasciklama i deljenim sredstvima.

### Ključni Event IDs za User Authentication:

- **EventID 4624**: Označava da je korisnik uspešno autentifikovan.
- **EventID 4625**: Ukazuje na neuspešnu autentifikaciju.
- **EventIDs 4634/4647**: Predstavljaju events odjavljivanja korisnika.
- **EventID 4672**: Označava prijavljivanje sa administratorskim privilegijama.

#### Podtipovi unutar EventID 4634/4647:

- **Interactive (2)**: Direktno prijavljivanje korisnika.
- **Network (3)**: Pristup deljenim fasciklama.
- **Batch (4)**: Izvršavanje batch procesa.
- **Service (5)**: Pokretanje service-a.
- **Proxy (6)**: Proxy autentifikacija.
- **Unlock (7)**: Otključavanje ekrana lozinkom.
- **Network Cleartext (8)**: Prenos lozinke u čistom tekstu, često iz IIS-a.
- **New Credentials (9)**: Korišćenje drugih kredencijala za pristup.
- **Remote Interactive (10)**: Prijavljivanje putem remote desktop-a ili terminal services-a.
- **Cache Interactive (11)**: Prijavljivanje keširanim kredencijalima bez kontakta sa domain controller-om.
- **Cache Remote Interactive (12)**: Remote prijavljivanje keširanim kredencijalima.
- **Cached Unlock (13)**: Otključavanje pomoću keširanih kredencijala.

#### Status i Sub Status kodovi za EventID 4625:

- **0xC0000064**: Korisničko ime ne postoji - Može ukazivati na username enumeration attack.
- **0xC000006A**: Ispravno korisničko ime, ali pogrešna lozinka - Mogući pokušaj pogađanja lozinke ili brute-force napad.
- **0xC0000234**: Korisnički nalog je zaključan - Može uslediti nakon brute-force napada koji je doveo do više neuspešnih prijavljivanja.
- **0xC0000072**: Nalog je onemogućen - Neovlašćeni pokušaji pristupa onemogućenim nalozima.
- **0xC000006F**: Prijavljivanje van dozvoljenog vremena - Ukazuje na pokušaje pristupa van podešenih sati za prijavljivanje, što može biti znak neovlašćenog pristupa.
- **0xC0000070**: Kršenje ograničenja radne stanice - Može predstavljati pokušaj prijavljivanja sa neovlašćene lokacije.
- **0xC0000193**: Istek naloga - Pokušaji pristupa pomoću isteklih korisničkih naloga.
- **0xC0000071**: Istekla lozinka - Pokušaji prijavljivanja sa zastarelim lozinkama.
- **0xC0000133**: Problemi sa sinhronizacijom vremena - Velike razlike u vremenu između client-a i servera mogu ukazivati na sofisticiranije napade, kao što je pass-the-ticket.
- **0xC0000224**: Zahteva se obavezna promena lozinke - Česte obavezne promene mogu ukazivati na pokušaj destabilizacije security-ja naloga.
- **0xC0000225**: Ukazuje na system bug, a ne na security problem.
- **0xC000015b**: Odbijen tip prijavljivanja - Pokušaj pristupa sa neovlašćenim tipom prijavljivanja, kao kada korisnik pokušava da izvrši service logon.

#### EventID 4616:

- **Time Change**: Izmena sistemskog vremena, što može prikriti vremensku liniju events.

#### EventID 6005 i 6006:

- **System Startup and Shutdown**: EventID 6005 označava pokretanje sistema, dok EventID 6006 označava njegovo gašenje.

#### EventID 1102:

- **Log Deletion**: Brisanje security logova, što je često znak prikrivanja nezakonitih aktivnosti.

#### EventIDs za USB Device Tracking:

- **20001 / 20003 / 10000**: Prvo povezivanje USB uređaja.
- **10100**: Ažuriranje USB driver-a.
- **EventID 112**: Vreme priključivanja USB uređaja.

Za praktične primere simuliranja ovih tipova prijavljivanja i mogućnosti credential dumping-a pogledajte [detaljan vodič Altered Security-ja](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Detalji events, uključujući status i sub-status kodove, pružaju dodatni uvid u uzroke events, što je naročito značajno kod Event ID 4625.

### Recovering Windows Events

Da biste povećali šanse za oporavak obrisanih Windows Events, preporučuje se da računar osumnjičenog isključite direktnim izvlačenjem napajanja. **Bulk_extractor**, recovery alat kome se navodi ekstenzija `.evtx`, preporučuje se za pokušaj oporavka takvih events.

### Identifikovanje uobičajenih napada pomoću Windows Events

Za sveobuhvatan vodič o korišćenju Windows Event IDs za identifikovanje uobičajenih cyber napada posetite [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Prepoznaju se po više zapisa EventID 4625, nakon kojih sledi EventID 4624 ako napad uspe.

#### Time Change

Beleži se pomoću EventID 4616; promene sistemskog vremena mogu otežati forensic analizu.

#### USB Device Tracking

Korisni System EventIDs za USB device tracking obuhvataju 20001/20003/10000 za početnu upotrebu, 10100 za ažuriranja driver-a i EventID 112 iz DeviceSetupManager-a za vremenske oznake priključivanja.

#### System Power Events

EventID 6005 označava pokretanje sistema, dok EventID 6006 označava gašenje.

#### Log Deletion

Security EventID 1102 signalizira brisanje logova, što je kritičan event za forensic analizu.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
