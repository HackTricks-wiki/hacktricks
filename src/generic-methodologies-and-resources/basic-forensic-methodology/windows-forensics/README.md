# Windows artefakti

{{#include ../../../banners/hacktricks-training.md}}

## Generički Windows artefakti

### Windows 10 obaveštenja

Na putanji `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` možete pronaći bazu podataka `appdb.dat` (pre Windows Anniversary) ili `wpndatabase.db` (nakon Windows Anniversary).

Unutar ove SQLite baze podataka možete pronaći tabelu `Notification` sa svim obaveštenjima (u XML formatu), koja mogu sadržati zanimljive podatke.

### Timeline

Timeline je Windows funkcija koja pruža **hronološku istoriju posećenih veb-stranica, izmenjenih dokumenata i izvršenih aplikacija**.

Baza podataka se nalazi na putanji `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Ova baza podataka može se otvoriti pomoću SQLite alata ili alata [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), **koji generiše 2 datoteke koje se mogu otvoriti pomoću alata** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Preuzete datoteke mogu sadržati **ADS Zone.Identifier**, koji ukazuje na to **kako** su **preuzete** sa intraneta, interneta itd. Neki softver (kao što su browseri) obično dodaje i **više** **informacija**, kao što je **URL** sa kojeg je datoteka preuzeta.

## **Rezervne kopije datoteka**

### Korpa za otpatke

U sistemima Vista/Win7/Win8/Win10 **Korpa za otpatke** može se pronaći u folderu **`$Recycle.bin`** u korenu diska (`C:\$Recycle.bin`).\
Kada se datoteka obriše u ovom folderu, kreiraju se 2 specifične datoteke:

- `$I{id}`: Informacije o datoteci (datum kada je obrisana}
- `$R{id}`: Sadržaj datoteke

![Rezervne kopije datoteka - Korpa za otpatke: $R{id}: Sadržaj datoteke](<../../../images/image (1029).png>)

Pomoću ovih datoteka možete koristiti alat [**Rifiuti**](https://github.com/abelcheung/rifiuti2) da dobijete originalnu lokaciju obrisanih datoteka i datum kada su obrisane (koristite `rifiuti-vista.exe` za Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy je tehnologija uključena u Microsoft Windows koja može da kreira **rezervne kopije** ili snimke računarskih datoteka ili volumena, čak i kada su u upotrebi.

Ove rezervne kopije se obično nalaze u direktorijumu `\System Volume Information` u korenu sistema datoteka, a naziv se sastoji od **UID-ova**, kao što je prikazano na sledećoj slici:

![Recycle Bin - Volume Shadow Copies: Ove rezervne kopije se obično nalaze u direktorijumu System Volume Information u korenu sistema datoteka, a naziv se sastoji od UID-ova prikazanih na...](<../../../images/image (94).png>)

Montiranjem forenzičke slike pomoću alata **ArsenalImageMounter**, alat [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) može da se koristi za pregled shadow copy-ja, pa čak i za **ekstrakciju datoteka** iz shadow copy rezervnih kopija.

![Recycle Bin - Volume Shadow Copies: Montiranjem forenzičke slike pomoću alata ArsenalImageMounter, alat ShadowCopyView može da se koristi za pregled shadow copy-ja, pa čak i za ekstrakciju datoteka...](<../../../images/image (576).png>)

Stavka registra `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` sadrži datoteke i ključeve koje **ne treba uključiti u rezervnu kopiju**:

![Recycle Bin - Volume Shadow Copies: Stavka registra HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore sadrži datoteke i ključeve koje ne treba uključiti u rezervnu kopiju](<../../../images/image (254).png>)

Registar `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` takođe sadrži informacije o konfiguraciji za `Volume Shadow Copies`.

### Automatski sačuvane Office datoteke

Office automatski sačuvane datoteke možete pronaći na lokaciji: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Shell item je stavka koja sadrži informacije o načinu pristupa drugoj datoteci.

### Nedavni dokumenti (LNK)

Windows **automatski** **kreira** ove **prečice** kada korisnik **otvori, koristi ili kreira datoteku** u:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Kada se kreira direktorijum, kreiraju se i linkovi ka tom direktorijumu, nadređenom direktorijumu i direktorijumu iznad njega.

Ove automatski kreirane datoteke sa linkovima **sadrže informacije o izvornom objektu**, kao što su podaci da li je u pitanju **datoteka** **ili** **direktorijum**, **MAC** **vremena** te datoteke, **informacije o volumenu** na kojem je datoteka sačuvana i **direktorijum ciljne datoteke**. Ove informacije mogu biti korisne za oporavak tih datoteka u slučaju da su uklonjene.

Takođe, **datum kreiranja linka** je prvo **vreme** kada je originalna datoteka **prvi put** **korišćena**, a **datum** **izmene** linka je poslednje **vreme** kada je izvorna datoteka korišćena.

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

Prvi skup vremenskih oznaka odnosi se na **vremenske oznake same datoteke**. Drugi skup odnosi se na **vremenske oznake povezane datoteke**.

Iste informacije možete dobiti pokretanjem Windows CLI alata: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
U ovom slučaju, informacije će biti sačuvane unutar CSV datoteke.

### Jumplists

Ovo su nedavne datoteke navedene po aplikaciji. To je lista **nedavno korišćenih datoteka u aplikaciji** kojoj možete pristupiti u svakoj aplikaciji. Mogu biti kreirane **automatski ili prilagođene**.

**Jumplists** kreirani automatski čuvaju se u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplists prate format `{id}.autmaticDestinations-ms`, gde je početni ID ID aplikacije.

Prilagođeni jumplists čuvaju se u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` i obično ih kreira aplikacija zato što se sa datotekom dogodilo nešto **važno** (možda je označena kao omiljena).

**Vreme kreiranja** bilo kog jumplista označava **prvi put kada je datoteci pristupljeno**, a **vreme izmene poslednji put**.

Jumplists možete pregledati pomoću alata [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Nedavni dokumenti (LNK) - Jumplists: Jumplists možete pregledati pomoću alata JumplistExplorer](<../../../images/image (168).png>)

(_Imajte na umu da su vremenske oznake koje prikazuje JumplistExplorer povezane sa samom jumplist datotekom_)

### Shellbags

[**Pratite ovaj link da biste saznali šta su shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Korišćenje Windows USB uređaja

Moguće je utvrditi da je USB uređaj korišćen zahvaljujući kreiranju sledećih elemenata:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Imajte na umu da neke LNK datoteke, umesto da upućuju na originalnu putanju, upućuju na WPDNSE folder:

![Shellbags - Korišćenje Windows USB uređaja: Imajte na umu da neke LNK datoteke, umesto da upućuju na originalnu putanju, upućuju na WPDNSE folder](<../../../images/image (218).png>)

Datoteke u folderu WPDNSE predstavljaju kopije originalnih datoteka, pa neće preživeti ponovno pokretanje računara, a GUID je preuzet iz shellbaga.

### Informacije iz Registry-ja

[Na ovoj stranici saznajte](interesting-windows-registry-keys.md#usb-information) koji registry ključevi sadrže zanimljive informacije o povezanim USB uređajima.

### setupapi

Proverite datoteku `C:\Windows\inf\setupapi.dev.log` da biste dobili vremenske oznake o tome kada je USB veza uspostavljena (pretražite `Section start`).

![Informacije iz Registry-ja - setupapi: Proverite datoteku C: Windows inf setupapi.dev.log da biste dobili vremenske oznake o tome kada je USB veza uspostavljena (pretražite Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) može se koristiti za dobijanje informacija o USB uređajima koji su bili povezani sa image-om.

![setupapi - USB Detective: USBDetective može da se koristi za dobijanje informacija o USB uređajima koji su bili povezani sa image-om](<../../../images/image (452).png>)

### Plug and Play Cleanup

Zakazani task poznat kao 'Plug and Play Cleanup' prvenstveno je namenjen uklanjanju zastarelih verzija drivera. Suprotno njegovoj navedenoj svrsi zadržavanja najnovije verzije driver paketa, online izvori navode da takođe cilja drivere koji nisu bili aktivni 30 dana. Zbog toga driveri prenosivih uređaja koji nisu bili povezani tokom prethodnih 30 dana mogu biti obrisani.<sup>[[1]](#references)</sup>

Task se nalazi na sledećoj putanji: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Snimak ekrana koji prikazuje sadržaj taska: ![USB Detective - Plug and Play Cleanup: Task se nalazi na sledećoj putanji: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Ključne komponente i podešavanja taska:**

- **pnpclean.dll**: Ovaj DLL je odgovoran za stvarni proces čišćenja.
- **UseUnifiedSchedulingEngine**: Postavljeno na `TRUE`, što ukazuje na korišćenje generičkog engine-a za zakazivanje taskova.
- **MaintenanceSettings**:
- **Period ('P1M')**: Nalaže Task Scheduler-u da pokrene task čišćenja jednom mesečno tokom redovnog Automatic održavanja.
- **Deadline ('P2M')**: Nalaže Task Scheduler-u da, ako task ne uspe tokom dva uzastopna meseca, izvrši task tokom hitnog Automatic održavanja.

Ova konfiguracija obezbeđuje redovno održavanje i čišćenje drivera, uz mogućnost ponovnog pokušaja izvršavanja taska u slučaju uzastopnih neuspeha.

**Za više informacija pogledajte:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emailovi

Emailovi sadrže **2 zanimljiva dela: headere i sadržaj** emaila. U **headerima** možete pronaći informacije kao što su:

- **Ko** je poslao emailove (email adresa, IP adresa, mail serveri koji su preusmerili email)
- **Kada** je email poslat

Takođe, u headerima `References` i `In-Reply-To` možete pronaći ID poruka:

![Plug and Play Cleanup - Emailovi: Kada je email poslat](<../../../images/image (593).png>)

### Windows Mail App

Ova aplikacija čuva emailove u HTML ili tekstualnom formatu. Emailove možete pronaći u podfolderima unutar `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Emailovi se čuvaju sa ekstenzijom `.dat`.

**Metapodaci** emailova i **kontakti** mogu se pronaći unutar **EDB baze podataka**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Promenite ekstenziju** datoteke iz `.vol` u `.edb`, a zatim možete koristiti alat [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) da je otvorite. Unutar tabele `Message` možete videti emailove.

### Microsoft Outlook

Kada se koriste Exchange serveri ili Outlook klijenti, postoje MAPI headeri:

- `Mapi-Client-Submit-Time`: Vreme na sistemu kada je email poslat
- `Mapi-Conversation-Index`: Broj podređenih poruka u thread-u i vremenska oznaka svake poruke u thread-u
- `Mapi-Entry-ID`: Identifikator poruke.
- `Mappi-Message-Flags` i `Pr_last_Verb-Executed`: Informacije o MAPI klijentu (poruka pročitana? nije pročitana? na nju je odgovoreno? preusmerena? van kancelarije?)

U Microsoft Outlook klijentu, sve poslate/primljene poruke, podaci o kontaktima i podaci kalendara čuvaju se u PST datoteci na sledećim lokacijama:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry putanja `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` ukazuje na datoteku koja se koristi.

PST datoteku možete otvoriti pomoću alata [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: PST datoteku možete otvoriti pomoću alata Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST datoteku** generiše Microsoft Outlook kada je konfigurisan sa **IMAP** ili **Exchange** serverom i ona čuva informacije slične onima u PST datoteci. Ova datoteka se sinhronizuje sa serverom, zadržavajući podatke za **poslednjih 12 meseci** do **maksimalne veličine od 50 GB**, i nalazi se u istom direktorijumu kao PST datoteka. Za pregled OST datoteke može se koristiti [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Preuzimanje priloga

Izgubljeni prilozi možda se mogu oporaviti sa sledećih lokacija:

- Za **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Za **IE11 i novije verzije**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** koristi **MBOX datoteke** za čuvanje podataka, koje se nalaze na lokaciji `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Sličice slika

- **Windows XP i 8-8.1**: Pristup folderu sa sličicama generiše datoteku `thumbs.db` koja čuva preglede slika, čak i nakon brisanja.
- **Windows 7/10**: `thumbs.db` se kreira kada se folderu pristupi preko mreže putem UNC putanje.
- **Windows Vista i novije verzije**: Pregledi sličica centralizovani su u `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, u datotekama čiji je naziv oblika **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) i [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) su alati za pregled ovih datoteka.

### Informacije iz Windows Registry-ja

Windows Registry, koji čuva obimne podatke o sistemskim aktivnostima i aktivnostima korisnika, nalazi se u datotekama na sledećim lokacijama:

- `%windir%\System32\Config` za različite `HKEY_LOCAL_MACHINE` podključeve.
- `%UserProfile%{User}\NTUSER.DAT` za `HKEY_CURRENT_USER`.
- Windows Vista i novije verzije prave rezervne kopije registry datoteka `HKEY_LOCAL_MACHINE` u `%Windir%\System32\Config\RegBack\`.
- Pored toga, informacije o izvršavanju programa čuvaju se u `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` počevši od Windows Vista i Windows 2008 Server verzija.

### Alati

Neki alati su korisni za analizu registry datoteka:

- **Registry Editor**: Instaliran je u Windows-u. To je GUI za kretanje kroz Windows Registry trenutne sesije.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Omogućava učitavanje registry datoteke i kretanje kroz nju pomoću GUI-ja. Takođe sadrži Bookmarks koji ističu ključeve sa zanimljivim informacijama.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Takođe poseduje GUI koji omogućava kretanje kroz učitani Registry, kao i plugins koji ističu zanimljive informacije unutar učitanog Registry-ja.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Još jedna GUI aplikacija sposobna za izdvajanje važnih informacija iz učitanog Registry-ja.

### Oporavak obrisanog elementa

Kada se ključ obriše, označava se kao obrisan, ali se neće ukloniti sve dok prostor koji zauzima ne bude potreban. Zbog toga je pomoću alata kao što je **Registry Explorer** moguće oporaviti obrisane ključeve.

### Vreme poslednjeg upisivanja

Svaki Key-Value sadrži **vremensku oznaku** koja označava vreme poslednje izmene.

### SAM

Datoteka/hive **SAM** sadrži hash vrednosti **korisnika, grupa i lozinki korisnika** sistema.

U `SAM\Domains\Account\Users` možete dobiti korisničko ime, RID, poslednju prijavu, poslednji neuspešni pokušaj prijave, brojač prijava, password policy i vreme kreiranja naloga. Da biste dobili **hash vrednosti**, takođe vam je potrebna datoteka/hive **SYSTEM**.

### Zanimljivi unosi u Windows Registry-ju


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Izvršeni programi

### Osnovni Windows procesi

U [ovoj objavi](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) možete saznati više o uobičajenim Windows procesima radi otkrivanja sumnjivog ponašanja.

### Nedavne Windows APPs

Unutar registry datoteke `NTUSER.DAT`, na putanji `Software\Microsoft\Current Version\Search\RecentApps`, možete pronaći podključeve sa informacijama o **izvršenoj aplikaciji**, **vremenu** njenog poslednjeg izvršavanja i **broju pokretanja**.

### BAM (Background Activity Moderator)

Datoteku `SYSTEM` možete otvoriti pomoću registry editora, a unutar putanje `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` možete pronaći informacije o **aplikacijama koje je izvršio svaki korisnik** (obratite pažnju na `{SID}` u putanji), kao i **vreme** njihovog izvršavanja (vreme se nalazi unutar Data vrednosti Registry-ja).

### Windows Prefetch

Prefetching je tehnika koja omogućava računaru da neprimetno **preuzme neophodne resurse potrebne za prikazivanje sadržaja** kojem korisnik **možda želi da pristupi u bliskoj budućnosti**, kako bi se resursima moglo brže pristupiti.

Windows prefetch podrazumeva kreiranje **keš memorija izvršenih programa** kako bi mogli brže da se učitaju. Ove keš memorije kreiraju se kao `.pf` datoteke unutar putanje: `C:\Windows\Prefetch`. Ograničenje je 128 datoteka u XP/VISTA/WIN7 i 1024 datoteke u Win8/Win10.

Naziv datoteke kreira se u formatu `{program_name}-{hash}.pf` (hash se zasniva na putanji i argumentima izvršne datoteke). U W10 su ove datoteke kompresovane. Imajte na umu da samo prisustvo datoteke ukazuje na to da je **program u nekom trenutku bio izvršen**.

Datoteka `C:\Windows\Prefetch\Layout.ini` sadrži **nazive foldera datoteka koje se prefetch-uju**. Ova datoteka sadrži **informacije o broju izvršavanja**, **datumima** izvršavanja i **datotekama** koje je program **otvorio**.

Za pregled ovih datoteka možete koristiti alat [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** ima isti cilj kao i prefetch, **brže učitavanje programa** predviđanjem šta će sledeće biti učitano. Međutim, ne zamenjuje prefetch servis.\
Ovaj servis generiše datoteke baze podataka u `C:\Windows\Prefetch\Ag*.db`.

U ovim bazama podataka možete pronaći **ime** **programa**, **broj** **izvršavanja**, **otvorene** **datoteke**, **korišćeni** **volumen**, **potpunu** **putanju**, **vremenske periode** i **vremenske oznake**.

Ovim informacijama možete pristupiti pomoću alata [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **nadgleda** **resurse** koje **troši** **proces**. Pojavio se u W8 i čuva podatke u ESE bazi podataka koja se nalazi na lokaciji `C:\Windows\System32\sru\SRUDB.dat`.

Pruža sledeće informacije:

- AppID i putanja
- Korisnik koji je izvršio proces
- Poslati bajtovi
- Primljeni bajtovi
- Mrežni interfejs
- Trajanje veze
- Trajanje procesa

Ove informacije se ažuriraju svakih 60 minuta.

Datum iz ove datoteke možete dobiti pomoću alata [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, takođe poznat kao **ShimCache**, predstavlja deo **Application Compatibility Database** sistema koji je razvio **Microsoft** radi rešavanja problema kompatibilnosti aplikacija. Ova komponenta sistema beleži različite delove metapodataka o datoteci, koji uključuju:

- Punu putanju do datoteke
- Veličinu datoteke
- Vreme poslednje izmene pod **$Standard_Information** (SI)
- Vreme poslednjeg ažuriranja ShimCache-a
- Oznaku izvršavanja procesa

Ovi podaci se čuvaju u registru na određenim lokacijama, u zavisnosti od verzije operativnog sistema:

- Za XP, podaci se čuvaju u `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, sa kapacitetom od 96 unosa.
- Za Server 2003, kao i za Windows verzije 2008, 2012, 2016, 7, 8 i 10, putanja za čuvanje je `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`, sa kapacitetom od 512, odnosno 1024 unosa.

Za parsiranje sačuvanih informacija preporučuje se upotreba alata [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Za parsiranje sačuvanih informacija preporučuje se upotreba alata AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Datoteka **Amcache.hve** je u suštini registry hive koji beleži detalje o aplikacijama koje su izvršene na sistemu. Obično se nalazi na lokaciji `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ova datoteka je značajna jer čuva zapise o nedavno izvršenim procesima, uključujući putanje do izvršnih datoteka i njihove SHA1 hash vrednosti. Ove informacije su od velike vrednosti za praćenje aktivnosti aplikacija na sistemu.

Za izdvajanje i analizu podataka iz datoteke **Amcache.hve** može se koristiti alat [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Sledeća komanda je primer upotrebe alata AmcacheParser za parsiranje sadržaja datoteke **Amcache.hve** i prikaz rezultata u CSV formatu:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Među generisanim CSV datotekama, `Amcache_Unassociated file entries` je posebno značajna zbog bogatih informacija koje pruža o nepovezanim unosima datoteka.

Najzanimljivija generisana CSV datoteka je `Amcache_Unassociated file entries`.

### RecentFileCache

Ovaj artifact može da se pronađe samo u W7, na lokaciji `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, i sadrži informacije o nedavnom izvršavanju nekih binarnih datoteka.

Za parsiranje datoteke možete koristiti alat [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser).

### Zakazani zadaci

Možete ih izdvojiti iz `C:\Windows\Tasks` ili `C:\Windows\System32\Tasks` i pročitati kao XML.

### Usluge

Možete ih pronaći u registry-ju, pod `SYSTEM\ControlSet001\Services`. Možete videti šta će biti izvršeno i kada.

### **Windows Store**

Instalirane aplikacije mogu se pronaći u `\ProgramData\Microsoft\Windows\AppRepository`\
Ovaj repository sadrži **log** sa **svakom aplikacijom instaliranom** na sistemu, unutar baze podataka **`StateRepository-Machine.srd`**.

Unutar tabele Application ove baze podataka moguće je pronaći kolone: "Application ID", "PackageNumber" i "Display Name". Ove kolone sadrže informacije o unapred instaliranim i instaliranim aplikacijama, a moguće je utvrditi da li su neke aplikacije deinstalirane, jer bi ID-jevi instaliranih aplikacija trebalo da budu sekvencijalni.

Takođe je moguće **pronaći instalirane aplikacije** unutar registry putanje: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`\
A **deinstalirane** **aplikacije** nalaze se u: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows događaji

Informacije koje se pojavljuju u Windows događajima su:

- Šta se dogodilo
- Vremenska oznaka (UTC + 0)
- Uključeni korisnici
- Uključeni hostovi (hostname, IP)
- Pristupljena sredstva (datoteke, folderi, štampači, services)

Logovi se nalaze u `C:\Windows\System32\config` pre Windows Vista, a nakon Windows Vista u `C:\Windows\System32\winevt\Logs`. Pre Windows Vista, event logovi su bili u binarnom formatu, a nakon njega su u **XML formatu** i koriste ekstenziju **.evtx**.

Lokacija event datoteka može se pronaći u SYSTEM registry-ju, na lokaciji **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Mogu se prikazati pomoću Windows Event Viewer-a (**`eventvwr.msc`**) ili drugim alatima, kao što su [**Event Log Explorer**](https://eventlogxp.com) **ili** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Razumevanje Windows Security Event Logging-a

Access događaji se beleže u security konfiguracionoj datoteci koja se nalazi na `C:\Windows\System32\winevt\Security.evtx`. Veličina ove datoteke može da se podešava, a kada se dostigne njen kapacitet, stariji događaji se prepisuju. Zabeleženi događaji obuhvataju prijavljivanja i odjavljivanja korisnika, radnje korisnika i promene security podešavanja, kao i pristup datotekama, folderima i deljenim sredstvima.

### Ključni Event ID-jevi za autentikaciju korisnika:

- **EventID 4624**: Označava da je korisnik uspešno autentifikovan.
- **EventID 4625**: Ukazuje na neuspešnu autentikaciju.
- **EventIDs 4634/4647**: Predstavljaju događaje odjavljivanja korisnika.
- **EventID 4672**: Označava prijavljivanje sa administrativnim privilegijama.

#### Podtipovi unutar EventID 4634/4647:

- **Interactive (2)**: Direktno prijavljivanje korisnika.
- **Network (3)**: Pristup deljenim folderima.
- **Batch (4)**: Izvršavanje batch procesa.
- **Service (5)**: Pokretanje service-a.
- **Proxy (6)**: Proxy autentikacija.
- **Unlock (7)**: Otključavanje ekrana lozinkom.
- **Network Cleartext (8)**: Prenos lozinke u čistom tekstu, često iz IIS-a.
- **New Credentials (9)**: Korišćenje drugih credential-a za pristup.
- **Remote Interactive (10)**: Prijavljivanje putem remote desktop-a ili terminal services-a.
- **Cache Interactive (11)**: Prijavljivanje pomoću keširanih credential-a bez kontakta sa domain controller-om.
- **Cache Remote Interactive (12)**: Remote prijavljivanje pomoću keširanih credential-a.
- **Cached Unlock (13)**: Otključavanje pomoću keširanih credential-a.

#### Status i Sub Status kodovi za EventID 4625:

- **0xC0000064**: Korisničko ime ne postoji - Može ukazivati na username enumeration attack.
- **0xC000006A**: Ispravno korisničko ime, ali pogrešna lozinka - Mogući password guessing ili brute-force pokušaj.
- **0xC0000234**: Korisnički nalog je zaključan - Može uslediti nakon brute-force napada koji je izazvao više neuspešnih prijavljivanja.
- **0xC0000072**: Nalog je onemogućen - Neovlašćeni pokušaji pristupa onemogućenim nalozima.
- **0xC000006F**: Prijavljivanje van dozvoljenog vremena - Ukazuje na pokušaje pristupa van podešenih sati za prijavljivanje, što može biti znak neovlašćenog pristupa.
- **0xC0000070**: Kršenje ograničenja radne stanice - Može predstavljati pokušaj prijavljivanja sa neovlašćene lokacije.
- **0xC0000193**: Istek naloga - Pokušaji pristupa pomoću korisničkih naloga kojima je istekao rok.
- **0xC0000071**: Lozinka je istekla - Pokušaji prijavljivanja sa zastarelim lozinkama.
- **0xC0000133**: Problemi sa sinhronizacijom vremena - Velike razlike u vremenu između klijenta i servera mogu ukazivati na sofisticiranije napade kao što je pass-the-ticket.
- **0xC0000224**: Zahteva se obavezna promena lozinke - Česte obavezne promene mogu ukazivati na pokušaj destabilizacije security-ja naloga.
- **0xC0000225**: Ukazuje na sistemski bug, a ne na security problem.
- **0xC000015b**: Tip prijavljivanja je odbijen - Pokušaj pristupa sa neovlašćenim tipom prijavljivanja, kao što je pokušaj korisnika da izvrši service logon.

#### EventID 4616:

- **Time Change**: Izmena sistemskog vremena, što može prikriti vremensku liniju događaja.

#### EventID 6005 i 6006:

- **System Startup and Shutdown**: EventID 6005 označava pokretanje sistema, dok EventID 6006 označava njegovo gašenje.

#### EventID 1102:

- **Log Deletion**: Brisanje security logova, što je često znak prikrivanja nedozvoljenih aktivnosti.

#### EventID-jevi za praćenje USB uređaja:

- **20001 / 20003 / 10000**: Prvo povezivanje USB uređaja.
- **10100**: Ažuriranje USB driver-a.
- **EventID 112**: Vreme priključivanja USB uređaja.

Za praktične primere simulacije ovih tipova prijavljivanja i mogućnosti credential dumping-a pogledajte [detaljan vodič kompanije Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Detalji događaja, uključujući status i sub-status kodove, pružaju dodatne uvide u uzroke događaja, što je naročito značajno kod Event ID 4625.

### Oporavak Windows događaja

Da bi se povećale šanse za oporavak obrisanih Windows događaja, preporučuje se isključivanje sumnjivog računara direktnim izvlačenjem utikača iz struje. **Bulk_extractor**, recovery alat za koji se navodi ekstenzija `.evtx`, preporučuje se za pokušaj oporavka takvih događaja.

### Identifikovanje uobičajenih napada pomoću Windows događaja

Za sveobuhvatan vodič o korišćenju Windows Event ID-jeva za identifikovanje uobičajenih cyber napada posetite [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force napadi

Prepoznaju se po višestrukim zapisima EventID 4625, nakon kojih sledi EventID 4624 ako napad uspe.

#### Promena vremena

Beleži se pomoću EventID 4616; promene sistemskog vremena mogu otežati forensic analizu.

#### Praćenje USB uređaja

Korisni System EventID-jevi za praćenje USB uređaja obuhvataju 20001/20003/10000 za početnu upotrebu, 10100 za ažuriranja driver-a i EventID 112 iz DeviceSetupManager-a za vremenske oznake priključivanja.

#### Događaji napajanja sistema

EventID 6005 označava pokretanje sistema, dok EventID 6006 označava njegovo gašenje.

#### Brisanje logova

Security EventID 1102 signalizira brisanje logova, što je kritičan događaj za forensic analizu.

## Reference

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
