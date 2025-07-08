# Windows artefakti

{{#include ../../../banners/hacktricks-training.md}}

## Generički Windows artefakti

### Windows 10 obaveštenja

U putanji `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` možete pronaći bazu podataka `appdb.dat` (pre Windows godišnjice) ili `wpndatabase.db` (posle Windows godišnjice).

Unutar ove SQLite baze podataka, možete pronaći tabelu `Notification` sa svim obaveštenjima (u XML formatu) koja mogu sadržati zanimljive podatke.

### Hronološka linija

Hronološka linija je karakteristika Windows-a koja pruža **hronološku istoriju** web stranica koje su posećene, uređivanih dokumenata i izvršenih aplikacija.

Baza podataka se nalazi u putanji `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Ova baza podataka može se otvoriti sa SQLite alatom ili sa alatom [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **koji generiše 2 datoteke koje se mogu otvoriti sa alatom** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternativni podaci)

Preuzete datoteke mogu sadržati **ADS Zone.Identifier** koji označava **kako** je **preuzeta** sa intraneta, interneta itd. Neki softver (kao što su pregledači) obično dodaju čak i **više** **informacija** kao što je **URL** sa kojeg je datoteka preuzeta.

## **Backup datoteka**

### Korpa za otpatke

U Vista/Win7/Win8/Win10 **Korpa za otpatke** može se pronaći u folderu **`$Recycle.bin`** u korenu diska (`C:\$Recycle.bin`).\
Kada se datoteka obriše u ovom folderu, kreiraju se 2 specifične datoteke:

- `$I{id}`: Informacije o datoteci (datum kada je obrisana)
- `$R{id}`: Sadržaj datoteke

![](<../../../images/image (1029).png>)

Imajući ove datoteke, možete koristiti alat [**Rifiuti**](https://github.com/abelcheung/rifiuti2) da dobijete originalnu adresu obrisanih datoteka i datum kada je obrisana (koristite `rifiuti-vista.exe` za Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy je tehnologija uključena u Microsoft Windows koja može da kreira **rezervne kopije** ili snimke računarskih datoteka ili volumena, čak i kada su u upotrebi.

Ove rezervne kopije se obično nalaze u `\System Volume Information` iz korena datotečnog sistema, a naziv se sastoji od **UID-ova** prikazanih na sledećoj slici:

![](<../../../images/image (94).png>)

Montiranjem forenzičke slike sa **ArsenalImageMounter**, alat [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) može se koristiti za inspekciju shadow copy-a i čak **izvlačenje datoteka** iz rezervnih kopija shadow copy-a.

![](<../../../images/image (576).png>)

Registri unos `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` sadrži datoteke i ključeve **koje ne treba praviti rezervne kopije**:

![](<../../../images/image (254).png>)

Registri `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` takođe sadrži informacije o konfiguraciji `Volume Shadow Copies`.

### Office AutoSaved Files

Možete pronaći automatski sačuvane datoteke u: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Shell item je stavka koja sadrži informacije o tome kako pristupiti drugoj datoteci.

### Recent Documents (LNK)

Windows **automatski** **kreira** ove **prečice** kada korisnik **otvori, koristi ili kreira datoteku** u:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Kada se kreira folder, takođe se kreira veza do foldera, do roditeljskog foldera i do foldera bake.

Ove automatski kreirane datoteke sa linkovima **sadrže informacije o poreklu** kao što su da li je to **datoteka** **ili** **folder**, **MAC** **vremena** te datoteke, **informacije o volumenu** gde je datoteka smeštena i **folder ciljne datoteke**. Ove informacije mogu biti korisne za oporavak tih datoteka u slučaju da su uklonjene.

Takođe, **datum kreiranja link** datoteke je prvi **put** kada je originalna datoteka **prvi** **put** **korisćena**, a **datum** **modifikacije** link datoteke je **poslednji** **put** kada je izvorna datoteka korišćena.

Da biste inspekciju ovih datoteka, možete koristiti [**LinkParser**](http://4discovery.com/our-tools/).

U ovom alatu ćete pronaći **2 skupa** vremenskih oznaka:

- **Prvi skup:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Drugi skup:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Prvi skup vremenskih oznaka se odnosi na **vremenske oznake same datoteke**. Drugi skup se odnosi na **vremenske oznake povezane datoteke**.

Možete dobiti iste informacije pokretanjem Windows CLI alata: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
U ovom slučaju, informacije će biti sačuvane unutar CSV datoteke.

### Jumplists

Ovo su nedavne datoteke koje su označene po aplikaciji. To je lista **nedavnih datoteka korišćenih od strane aplikacije** kojoj možete pristupiti u svakoj aplikaciji. Mogu biti kreirane **automatski ili po meri**.

**Jumplists** kreirane automatski se čuvaju u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplists su imenovane prema formatu `{id}.autmaticDestinations-ms` gde je početni ID ID aplikacije.

Prilagođene jumplists se čuvaju u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` i obično ih kreira aplikacija jer se nešto **važnog** dogodilo sa datotekom (možda označeno kao omiljeno).

**Vreme kreiranja** bilo koje jumplist ukazuje na **prvi put kada je datoteka pristupljena** i **vreme modifikacije poslednji put**.

Možete pregledati jumplists koristeći [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../images/image (168).png>)

(_Napomena da su vremenski oznake koje pruža JumplistExplorer povezane sa samom jumplist datotekom_)

### Shellbags

[**Pratite ovaj link da saznate šta su shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Korišćenje Windows USB-a

Moguće je identifikovati da je USB uređaj korišćen zahvaljujući kreiranju:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Napomena da neka LNK datoteka umesto da pokazuje na originalni put, pokazuje na WPDNSE folder:

![](<../../../images/image (218).png>)

Datoteke u folderu WPDNSE su kopije originalnih, stoga neće preživeti restart PC-a i GUID se uzima iz shellbaga.

### Registry Information

[Proverite ovu stranicu da saznate](interesting-windows-registry-keys.md#usb-information) koji registry ključevi sadrže zanimljive informacije o USB povezanim uređajima.

### setupapi

Proverite datoteku `C:\Windows\inf\setupapi.dev.log` da dobijete vremenske oznake o tome kada je USB konekcija uspostavljena (potražite `Section start`).

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) može se koristiti za dobijanje informacija o USB uređajima koji su bili povezani na sliku.

![](<../../../images/image (452).png>)

### Plug and Play Cleanup

Zakazana aktivnost poznata kao 'Plug and Play Cleanup' prvenstveno je dizajnirana za uklanjanje zastarelih verzija drajvera. Suprotno njenoj specificiranoj svrsi zadržavanja najnovije verzije paketa drajvera, online izvori sugerišu da takođe cilja drajvere koji su bili neaktivni 30 dana. Kao rezultat, drajveri za uklonjive uređaje koji nisu povezani u poslednjih 30 dana mogu biti podložni brisanju.

Zadatak se nalazi na sledećem putu: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Prikazana je slika koja prikazuje sadržaj zadatka: ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Ključne komponente i podešavanja zadatka:**

- **pnpclean.dll**: Ova DLL je odgovorna za stvarni proces čišćenja.
- **UseUnifiedSchedulingEngine**: Podešeno na `TRUE`, što ukazuje na korišćenje generičkog mehanizma za zakazivanje zadataka.
- **MaintenanceSettings**:
- **Period ('P1M')**: Usmerava Task Scheduler da pokrene zadatak čišćenja mesečno tokom redovnog automatskog održavanja.
- **Deadline ('P2M')**: Upravlja Task Scheduler-om, ako zadatak ne uspe dva uzastopna meseca, da izvrši zadatak tokom hitnog automatskog održavanja.

Ova konfiguracija osigurava redovno održavanje i čišćenje drajvera, sa odredbama za ponovni pokušaj zadatka u slučaju uzastopnih neuspeha.

**Za više informacija proverite:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Emailovi sadrže **2 zanimljiva dela: zaglavlja i sadržaj** emaila. U **zaglavljima** možete pronaći informacije kao što su:

- **Ko** je poslao emailove (email adresa, IP, mail serveri koji su preusmerili email)
- **Kada** je email poslat

Takođe, unutar zaglavlja `References` i `In-Reply-To` možete pronaći ID poruka:

![](<../../../images/image (593).png>)

### Windows Mail App

Ova aplikacija čuva emailove u HTML-u ili tekstu. Možete pronaći emailove unutar podfoldera unutar `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Emailovi se čuvaju sa ekstenzijom `.dat`.

**Metapodaci** emailova i **kontakti** mogu se naći unutar **EDB baze podataka**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Promenite ekstenziju** datoteke sa `.vol` na `.edb` i možete koristiti alat [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) da je otvorite. Unutar tabele `Message` možete videti emailove.

### Microsoft Outlook

Kada se koriste Exchange serveri ili Outlook klijenti, biće prisutni neki MAPI zaglavlja:

- `Mapi-Client-Submit-Time`: Vreme sistema kada je email poslat
- `Mapi-Conversation-Index`: Broj poruka dece u niti i vremenska oznaka svake poruke u niti
- `Mapi-Entry-ID`: Identifikator poruke.
- `Mappi-Message-Flags` i `Pr_last_Verb-Executed`: Informacije o MAPI klijentu (poruka pročitana? nije pročitana? odgovoreno? preusmereno? van kancelarije?)

U Microsoft Outlook klijentu, sve poslata/primljene poruke, podaci o kontaktima i podaci o kalendaru se čuvaju u PST datoteci u:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Putanja u registru `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` ukazuje na datoteku koja se koristi.

Možete otvoriti PST datoteku koristeći alat [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST datoteka** se generiše od strane Microsoft Outlook-a kada je konfigurisan sa **IMAP** ili **Exchange** serverom, čuvajući slične informacije kao PST datoteka. Ova datoteka se sinhronizuje sa serverom, zadržavajući podatke za **poslednjih 12 meseci** do **maksimalne veličine od 50GB**, i nalazi se u istom direktorijumu kao PST datoteka. Da biste pregledali OST datoteku, može se koristiti [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Retrieving Attachments

Izgubljeni dodaci mogu biti dostupni iz:

- Za **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Za **IE11 i više**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** koristi **MBOX datoteke** za čuvanje podataka, smeštene u `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Image Thumbnails

- **Windows XP i 8-8.1**: Pristup folderu sa sličicama generiše `thumbs.db` datoteku koja čuva preglede slika, čak i nakon brisanja.
- **Windows 7/10**: `thumbs.db` se kreira kada se pristupa preko mreže putem UNC puta.
- **Windows Vista i novije**: Pregledi sličica su centralizovani u `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` sa datotekama nazvanim **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) i [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) su alati za pregled ovih datoteka.

### Windows Registry Information

Windows Registry, koji čuva opsežne podatke o sistemu i korisničkim aktivnostima, sadrži se unutar datoteka u:

- `%windir%\System32\Config` za razne `HKEY_LOCAL_MACHINE` podključeve.
- `%UserProfile%{User}\NTUSER.DAT` za `HKEY_CURRENT_USER`.
- Windows Vista i novije verzije prave rezervne kopije `HKEY_LOCAL_MACHINE` registracionih datoteka u `%Windir%\System32\Config\RegBack\`.
- Pored toga, informacije o izvršenju programa se čuvaju u `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` od Windows Vista i Windows 2008 Server nadalje.

### Tools

Neki alati su korisni za analizu registracionih datoteka:

- **Registry Editor**: Instaliran je u Windows-u. To je GUI za navigaciju kroz Windows registry trenutne sesije.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Omogućava vam da učitate registracionu datoteku i navigirate kroz njih sa GUI-jem. Takođe sadrži oznake koje ističu ključeve sa zanimljivim informacijama.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Takođe ima GUI koji omogućava navigaciju kroz učitanu registraciju i sadrži dodatke koji ističu zanimljive informacije unutar učitane registracije.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Još jedna GUI aplikacija sposobna da izvuče važne informacije iz učitane registracije.

### Recovering Deleted Element

Kada se ključ obriše, označen je kao takav, ali dok se prostor koji zauzima ne zatreba, neće biti uklonjen. Stoga, korišćenjem alata kao što je **Registry Explorer**, moguće je povratiti ove obrisane ključeve.

### Last Write Time

Svaki Key-Value sadrži **vremensku oznaku** koja ukazuje na poslednji put kada je modifikovan.

### SAM

Datoteka/hive **SAM** sadrži **korisnike, grupe i heširane lozinke korisnika** sistema.

U `SAM\Domains\Account\Users` možete dobiti korisničko ime, RID, poslednju prijavu, poslednji neuspešni prijavljivanje, brojač prijava, politiku lozinki i kada je nalog kreiran. Da biste dobili **hešove**, takođe **trebate** datoteku/hive **SYSTEM**.

### Interesting entries in the Windows Registry

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

U [ovom postu](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) možete saznati o uobičajenim Windows procesima za otkrivanje sumnjivih ponašanja.

### Windows Recent APPs

Unutar registra `NTUSER.DAT` na putu `Software\Microsoft\Current Version\Search\RecentApps` možete pronaći podključeve sa informacijama o **izvršenoj aplikaciji**, **poslednjem putu** kada je izvršena, i **broju puta** kada je pokrenuta.

### BAM (Background Activity Moderator)

Možete otvoriti datoteku `SYSTEM` sa editorom registra i unutar puta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` možete pronaći informacije o **aplikacijama koje je izvršio svaki korisnik** (napomena na `{SID}` u putu) i **u koje vreme** su izvršene (vreme je unutar Data vrednosti registra).

### Windows Prefetch

Prefetching je tehnika koja omogućava računaru da tiho **preuzme potrebne resurse potrebne za prikazivanje sadržaja** koji korisnik **može pristupiti u bliskoj budućnosti** kako bi se resursi mogli brže pristupiti.

Windows prefetch se sastoji od kreiranja **kešova izvršenih programa** kako bi ih mogli brže učitati. Ovi keševi se kreiraju kao `.pf` datoteke unutar puta: `C:\Windows\Prefetch`. Postoji limit od 128 datoteka u XP/VISTA/WIN7 i 1024 datoteka u Win8/Win10.

Ime datoteke se kreira kao `{program_name}-{hash}.pf` (heš se zasniva na putu i argumentima izvršnog programa). U W10 ove datoteke su kompresovane. Imajte na umu da sama prisutnost datoteke ukazuje da je **program izvršen** u nekom trenutku.

Datoteka `C:\Windows\Prefetch\Layout.ini` sadrži **imena foldera datoteka koje su preuzete**. Ova datoteka sadrži **informacije o broju izvršenja**, **datumima** izvršenja i **datotekama** **otvorenim** od strane programa.

Da biste pregledali ove datoteke, možete koristiti alat [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** ima isti cilj kao prefetch, **brže učitavanje programa** predviđanjem šta će biti učitano sledeće. Međutim, ne zamenjuje prefetch servis.\
Ova usluga će generisati datoteke baze podataka u `C:\Windows\Prefetch\Ag*.db`.

U ovim bazama podataka možete pronaći **ime** **programa**, **broj** **izvršavanja**, **otvorene** **datoteke**, **pristup** **volumenu**, **potpunu** **putanju**, **vremenske okvire** i **vremenske oznake**.

Možete pristupiti ovim informacijama koristeći alat [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**Monitor korišćenja sistemskih resursa** (SRUM) **prati** **resurse** **koje koristi** **proces**. Pojavio se u W8 i čuva podatke u ESE bazi podataka smeštenoj u `C:\Windows\System32\sru\SRUDB.dat`.

Daje sledeće informacije:

- AppID i Putanja
- Korisnik koji je izvršio proces
- Poslati bajtovi
- Primljeni bajtovi
- Mrežni interfejs
- Trajanje veze
- Trajanje procesa

Ove informacije se ažuriraju svake 60 minuta.

Možete dobiti datum iz ove datoteke koristeći alat [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, poznat i kao **ShimCache**, deo je **Baze podataka o kompatibilnosti aplikacija** koju je razvila **Microsoft** kako bi se rešili problemi sa kompatibilnošću aplikacija. Ova sistemska komponenta beleži razne delove metapodataka o datotekama, koji uključuju:

- Puni put do datoteke
- Veličinu datoteke
- Vreme poslednje izmene pod **$Standard_Information** (SI)
- Vreme poslednje ažuriranja ShimCache-a
- Zastavicu izvršenja procesa

Ovi podaci se čuvaju u registru na specifičnim lokacijama u zavisnosti od verzije operativnog sistema:

- Za XP, podaci se čuvaju pod `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` sa kapacitetom za 96 unosa.
- Za Server 2003, kao i za Windows verzije 2008, 2012, 2016, 7, 8 i 10, putanja za skladištenje je `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, sa kapacitetom od 512 i 1024 unosa, respektivno.

Za analizu sačuvanih informacija, preporučuje se korišćenje alata [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../images/image (75).png>)

### Amcache

Datoteka **Amcache.hve** je u suštini registri hives koji beleži detalje o aplikacijama koje su izvršene na sistemu. Obično se nalazi na `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ova datoteka je značajna jer čuva zapise o nedavno izvršenim procesima, uključujući puteve do izvršnih datoteka i njihove SHA1 heš vrednosti. Ove informacije su neprocenjive za praćenje aktivnosti aplikacija na sistemu.

Za ekstrakciju i analizu podataka iz **Amcache.hve**, može se koristiti alat [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Sledeća komanda je primer kako koristiti AmcacheParser za analizu sadržaja datoteke **Amcache.hve** i izlaz rezultata u CSV formatu:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Među generisanim CSV datotekama, `Amcache_Unassociated file entries` je posebno značajan zbog bogatih informacija koje pruža o neudruženim unosima datoteka.

Najzanimljivija CVS datoteka koja je generisana je `Amcache_Unassociated file entries`.

### RecentFileCache

Ovaj artefakt se može naći samo u W7 u `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` i sadrži informacije o nedavnoj izvršavanju nekih binarnih datoteka.

Možete koristiti alat [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) za analizu datoteke.

### Zakazane radnje

Možete ih izvući iz `C:\Windows\Tasks` ili `C:\Windows\System32\Tasks` i pročitati ih kao XML.

### Servisi

Možete ih pronaći u registru pod `SYSTEM\ControlSet001\Services`. Možete videti šta će biti izvršeno i kada.

### **Windows Store**

Instalirane aplikacije se mogu naći u `\ProgramData\Microsoft\Windows\AppRepository\`\
Ova biblioteka ima **log** sa **svakom instaliranom** aplikacijom u sistemu unutar baze podataka **`StateRepository-Machine.srd`**.

Unutar tabele aplikacija ove baze podataka, moguće je pronaći kolone: "Application ID", "PackageNumber" i "Display Name". Ove kolone sadrže informacije o unapred instaliranim i instaliranim aplikacijama i može se utvrditi da li su neke aplikacije deinstalirane jer bi ID-ovi instaliranih aplikacija trebali biti sekvencijalni.

Takođe je moguće **pronaći instaliranu aplikaciju** unutar registra na putu: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
I **deinstalirane** **aplikacije** u: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows događaji

Informacije koje se pojavljuju unutar Windows događaja su:

- Šta se desilo
- Vreme (UTC + 0)
- Uključeni korisnici
- Uključeni hostovi (hostname, IP)
- Pristupeni resursi (datoteke, folderi, štampači, servisi)

Logovi se nalaze u `C:\Windows\System32\config` pre Windows Vista i u `C:\Windows\System32\winevt\Logs` posle Windows Vista. Pre Windows Vista, logovi događaja su bili u binarnom formatu, a posle toga su u **XML formatu** i koriste **.evtx** ekstenziju.

Lokacija datoteka događaja može se pronaći u SYSTEM registru u **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Mogu se vizualizovati iz Windows Event Viewer-a (**`eventvwr.msc`**) ili sa drugim alatima kao što su [**Event Log Explorer**](https://eventlogxp.com) **ili** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Razumevanje Windows sigurnosnog logovanja događaja

Događaji pristupa se beleže u datoteci sigurnosne konfiguracije koja se nalazi na `C:\Windows\System32\winevt\Security.evtx`. Veličina ove datoteke je prilagodljiva, a kada se dostigne njen kapacitet, stariji događaji se prepisuju. Beleženi događaji uključuju prijave i odjave korisnika, korisničke akcije i promene sigurnosnih postavki, kao i pristup datotekama, folderima i deljenim resursima.

### Ključni ID-evi događaja za autentifikaciju korisnika:

- **EventID 4624**: Ukazuje na uspešnu autentifikaciju korisnika.
- **EventID 4625**: Signalizira neuspeh autentifikacije.
- **EventIDs 4634/4647**: Predstavljaju događaje odjave korisnika.
- **EventID 4672**: Označava prijavu sa administratorskim privilegijama.

#### Podtipovi unutar EventID 4634/4647:

- **Interaktivno (2)**: Direktna prijava korisnika.
- **Mrežno (3)**: Pristup deljenim folderima.
- **Serijski (4)**: Izvršavanje serijskih procesa.
- **Servis (5)**: Pokretanje servisa.
- **Proxy (6)**: Proxy autentifikacija.
- **Otključavanje (7)**: Ekran otključan lozinkom.
- **Mrežni čisti tekst (8)**: Prenos lozinke u čistom tekstu, često iz IIS-a.
- **Nove kredencijale (9)**: Korišćenje različitih kredencijala za pristup.
- **Daljinsko interaktivno (10)**: Prijava putem daljinske radne površine ili terminalskih usluga.
- **Keširano interaktivno (11)**: Prijava sa keširanim kredencijalima bez kontakta sa kontrolerom domena.
- **Keširano daljinsko interaktivno (12)**: Daljinska prijava sa keširanim kredencijalima.
- **Keširano otključavanje (13)**: Otključavanje sa keširanim kredencijalima.

#### Status i podstatus kodovi za EventID 4625:

- **0xC0000064**: Korisničko ime ne postoji - Može ukazivati na napad na enumeraciju korisničkog imena.
- **0xC000006A**: Tačno korisničko ime, ali pogrešna lozinka - Mogući pokušaj pogađanja lozinke ili brute-force napad.
- **0xC0000234**: Korisnički nalog je zaključan - Može uslediti nakon brute-force napada koji rezultira višestrukim neuspelim prijavama.
- **0xC0000072**: Nalog je onemogućen - Neovlašćeni pokušaji pristupa onemogućenim nalozima.
- **0xC000006F**: Prijava van dozvoljenog vremena - Ukazuje na pokušaje pristupa van postavljenih sati prijave, mogući znak neovlašćenog pristupa.
- **0xC0000070**: Kršenje ograničenja radne stanice - Može biti pokušaj prijave sa neovlašćenog mesta.
- **0xC0000193**: Istek naloga - Pokušaji pristupa sa isteklim korisničkim nalozima.
- **0xC0000071**: Istekla lozinka - Pokušaji prijave sa zastarelim lozinkama.
- **0xC0000133**: Problemi sa sinhronizacijom vremena - Velike vremenske razlike između klijenta i servera mogu ukazivati na sofisticiranije napade poput pass-the-ticket.
- **0xC0000224**: Obavezna promena lozinke potrebna - Česte obavezne promene mogu sugerisati pokušaj destabilizacije sigurnosti naloga.
- **0xC0000225**: Ukazuje na grešku u sistemu, a ne na sigurnosni problem.
- **0xC000015b**: Odbijeni tip prijave - Pokušaj pristupa sa neovlašćenim tipom prijave, kao što je korisnik koji pokušava da izvrši prijavu servisa.

#### EventID 4616:

- **Promena vremena**: Izmena sistemskog vremena, može zamagliti vremensku liniju događaja.

#### EventID 6005 i 6006:

- **Pokretanje i gašenje sistema**: EventID 6005 označava pokretanje sistema, dok EventID 6006 označava gašenje.

#### EventID 1102:

- **Brisanje logova**: Brisanje sigurnosnih logova, što je često crvena zastava za prikrivanje nelegalnih aktivnosti.

#### EventIDs za praćenje USB uređaja:

- **20001 / 20003 / 10000**: Prva konekcija USB uređaja.
- **10100**: Ažuriranje USB drajvera.
- **EventID 112**: Vreme umetanja USB uređaja.

Za praktične primere simulacije ovih tipova prijava i mogućnosti iskopavanja kredencijala, pogledajte [detaljni vodič Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Detalji događaja, uključujući status i podstatus kodove, pružaju dodatne uvide u uzroke događaja, posebno u Event ID 4625.

### Oporavak Windows događaja

Da biste povećali šanse za oporavak obrisanih Windows događaja, preporučuje se da isključite sumnjivi računar direktnim isključivanjem. **Bulk_extractor**, alat za oporavak koji specificira ekstenziju `.evtx`, se preporučuje za pokušaj oporavka takvih događaja.

### Identifikacija uobičajenih napada putem Windows događaja

Za sveobuhvatan vodič o korišćenju Windows Event ID-ova u identifikaciji uobičajenih sajber napada, posetite [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force napadi

Identifikovani višestrukim zapisima EventID 4625, praćenim EventID 4624 ako napad uspe.

#### Promena vremena

Zabeležena EventID 4616, promene sistemskog vremena mogu otežati forenzičku analizu.

#### Praćenje USB uređaja

Korisni sistemski EventID-ovi za praćenje USB uređaja uključuju 20001/20003/10000 za početnu upotrebu, 10100 za ažuriranja drajvera, i EventID 112 iz DeviceSetupManager-a za vremenske oznake umetanja.

#### Događaji napajanja sistema

EventID 6005 označava pokretanje sistema, dok EventID 6006 označava gašenje.

#### Brisanje logova

Sigurnosni EventID 1102 signalizira brisanje logova, kritičan događaj za forenzičku analizu.

{{#include ../../../banners/hacktricks-training.md}}
