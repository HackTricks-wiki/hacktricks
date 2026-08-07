# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Basiese Inligting**

**System Integrity Protection (SIP)** in macOS is 'n meganisme wat ontwerp is om te voorkom dat selfs die mees bevoorregte gebruikers ongemagtigde veranderinge aan belangrike stelselvouers maak. Hierdie funksie speel 'n belangrike rol in die handhawing van die integriteit van die stelsel deur handelinge soos die byvoeging, wysiging of verwydering van lêers in beskermde areas te beperk. Die primêre vouers wat deur SIP beskerm word, sluit die volgende in:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Die reëls wat SIP se gedrag beheer, word gedefinieer in die konfigurasielêer by **`/System/Library/Sandbox/rootless.conf`**. Binne hierdie lêer word paaie met 'n asterisk (\*) voorafgegaan, aangedui as uitsonderings op die andersins streng SIP-beperkings.

Beskou die voorbeeld hieronder:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Hierdie brokkie impliseer dat SIP gewoonlik die **`/usr`**-gids beveilig, maar dat wysigings in spesifieke subgidse (`/usr/libexec/cups`, `/usr/local` en `/usr/share/man`) toegelaat word, soos aangedui deur die asterisk (\*) voor hul paaie.

Om te verifieer of ’n gids of lêer deur SIP beskerm word, kan jy die **`ls -lOd`**-opdrag gebruik om te kyk of die **`restricted`**- of **`sunlnk`**-vlag teenwoordig is. Byvoorbeeld:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In hierdie geval dui die **`sunlnk`**-flag aan dat die `/usr/libexec/cups`-directory self **nie deleted kan word nie**, hoewel files daarin geskep, modified of deleted kan word.

Aan die ander kant:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hier dui die **`restricted`**-flag aan dat die `/usr/libexec`-gids deur SIP beskerm word. In ’n SIP-beskermde gids kan lêers nie geskep, gewysig of uitgevee word nie.

Daarbenewens, as ’n lêer die **`com.apple.rootless`** extended **attribute** bevat, sal daardie lêer ook **deur SIP beskerm** word.

> [!TIP]
> Let daarop dat die **Sandbox**-hook **`hook_vnode_check_setextattr`** enige poging om die extended attribute **`com.apple.rootless`** te wysig, voorkom.

**SIP beperk ook ander root-aksies**, soos:

- Die laai van onbetroubare kernel extensions
- Die verkryging van task-ports vir Apple-signed prosesse
- Die wysiging van NVRAM-veranderlikes
- Die toelating van kernel debugging

Opsies word in ’n nvram-veranderlike as ’n bitflag gestoor (`csr-active-config` op Intel, en `lp-sip0` word vanaf die gebootte Device Tree vir ARM gelees). Jy kan die flags in die XNU-bronkode in `csr.sh` vind:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP-status

Jy kan met die volgende command kontroleer of SIP op jou stelsel geaktiveer is:
```bash
csrutil status
```
As jy SIP moet deaktiveer, moet jy jou rekenaar in recovery mode herbegin (deur Command+R tydens opstart te druk) en dan die volgende command uitvoer:
```bash
csrutil disable
```
As jy SIP geaktiveer wil hou maar debugging-beskerming wil verwyder, kan jy dit doen met:
```bash
csrutil enable --without debug
```
### Ander beperkings

- **Verhoed die laai van ongetekende kernel extensions** (kexts), wat verseker dat slegs geverifieerde extensions met die stelselkernel interaksie het.
- **Verhoed die debugging** van macOS-stelselprosesse, wat kernstelselkomponente teen ongemagtigde toegang en wysiging beskerm.
- **Verhoed tools** soos dtrace om stelselprosesse te inspekteer, wat die integriteit van die stelsel se werking verder beskerm.

[**Leer meer oor SIP-inligting in hierdie praatjie**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **SIP-verwante Entitlements**

- `com.apple.rootless.xpc.bootstrap`: Beheer launchd
- `com.apple.rootless.install[.heritable]`: Toegang tot lêerstelsel
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Bestuur UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: XPC-opstellingsvermoëns
- `com.apple.rootless.xpc.effective-root`: Root via launchd XPC
- `com.apple.rootless.restricted-block-devices`: Toegang tot rou block devices
- `com.apple.rootless.internal.installer-equivalent`: Onbeperkte lêerstelseltoegang
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Volle toegang tot NVRAM
- `com.apple.rootless.storage.label`: Wysig lêers wat deur com.apple.rootless xattr met die ooreenstemmende label beperk word
- `com.apple.rootless.volume.VM.label`: Onderhou VM swap op volume

## SIP-bypasses

Deur SIP te omseil, kan 'n aanvaller:

- **Toegang tot gebruikersdata**: Lees sensitiewe gebruikersdata soos e-pos, boodskappe en Safari-geskiedenis van alle gebruikersrekeninge.
- **TCC Bypass**: Manipuleer die TCC-databasis (Transparency, Consent, and Control) direk om ongemagtigde toegang tot die webcam, mikrofoon en ander hulpbronne toe te staan.
- **Vestig persistence**: Plaas malware in SIP-beskermde liggings, wat dit bestand teen verwydering maak, selfs met root privileges. Dit sluit ook die moontlikheid in om met die Malware Removal Tool (MRT) te peuter.
- **Laai Kernel Extensions**: Alhoewel daar addisionele beveiligingsmaatreëls is, vereenvoudig die omseiling van SIP die proses om ongetekende kernel extensions te laai.

### Installer Packages

**Installer packages wat met Apple's certificate onderteken is** kan die beskermings daarvan omseil. Dit beteken dat selfs packages wat deur standard developers onderteken is, geblokkeer sal word as hulle probeer om SIP-beskermde directories te wysig.

### Nie-bestaande SIP-lêer

Een moontlike skuiwergat is dat, indien 'n lêer in **`rootless.conf` gespesifiseer is maar tans nie bestaan nie**, dit geskep kan word. Malware kan dit uitbuit om **persistence** op die stelsel te **vestig**. 'n Kwaadwillige program kan byvoorbeeld 'n .plist-lêer in `/System/Library/LaunchDaemons` skep as dit in `rootless.conf` gelys is maar nie teenwoordig is nie.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Die entitlement **`com.apple.rootless.install.heritable`** laat toe dat SIP omseil word

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Daar is ontdek dat dit moontlik was om die installer package te **vervang nadat die stelsel sy code**-signature geverifieer het, waarna die stelsel die kwaadwillige package in plaas van die oorspronklike sou installeer. Omdat hierdie aksies deur **`system_installd`** uitgevoer is, sou dit SIP kon omseil.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Indien 'n package vanaf 'n gemounte image of eksterne drive geïnstalleer is, sou die **installer** die binary vanaf **daardie lêerstelsel** **uitvoer** (eerder as vanaf 'n SIP-beskermde ligging), wat **`system_installd`** 'n arbitrêre binary sou laat uitvoer.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Navorsers van hierdie blogplasing**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) het 'n kwesbaarheid in macOS se System Integrity Protection (SIP)-meganisme ontdek, wat die 'Shrootless'-kwesbaarheid genoem is. Hierdie kwesbaarheid sentreer rondom die **`system_installd`**-daemon, wat 'n entitlement, **`com.apple.rootless.install.heritable`**, het wat enige van sy child processes toelaat om SIP se lêerstelselbeperkings te omseil.<sup>[[4]](#references)</sup>

Die **`system_installd`**-daemon sal packages installeer wat deur **Apple** onderteken is.

Navorsers het gevind dat **`system_installd`** tydens die installering van 'n Apple-ondertekende package (.pkg-lêer) enige **post-install**-scripts uitvoer wat in die package ingesluit is. Hierdie scripts word deur die verstek-shell, **`zsh`**, uitgevoer, wat outomaties commands uit die **`/etc/zshenv`**-lêer **uitvoer** indien dit bestaan, selfs in nie-interaktiewe mode. Hierdie gedrag kon deur aanvallers uitgebuit word: deur 'n kwaadwillige `/etc/zshenv`-lêer te skep en te wag dat **`system_installd` `zsh` aanroep**, kon hulle arbitrêre operasies op die device uitvoer.<sup>[[4]](#references)</sup>

Daarbenewens is ontdek dat **`/etc/zshenv` as 'n algemene aanvalstegniek gebruik kon word**, nie net vir 'n SIP-bypass nie. Elke gebruikersprofiel het 'n `~/.zshenv`-lêer, wat op dieselfde manier as `/etc/zshenv` werk, maar nie root permissions vereis nie. Hierdie lêer kon as 'n persistence-meganisme gebruik word, wat elke keer geaktiveer word wanneer `zsh` begin, of as 'n privilege elevation-meganisme. Indien 'n admin-gebruiker met `sudo -s` of `sudo <command>` na root elevate, sou die `~/.zshenv`-lêer geaktiveer word, wat effektief na root elevate.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) is ontdek dat dieselfde **`system_installd`**-proses steeds misbruik kon word, omdat dit die **post-install script binne 'n ewekansig benoemde folder wat deur SIP beskerm word, binne `/tmp` geplaas het**. Die probleem is dat **`/tmp` self nie deur SIP beskerm word nie**, en dit dus moontlik was om 'n **virtual image daarop te mount**, waarna die **installer** die **post-install script** daarin sou plaas, die virtual image sou **unmount**, al die **folders** sou **herskep** en die **post-install** script met die **payload** om uit te voer sou **byvoeg**.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

'n Kwesbaarheid is geïdentifiseer waar **`fsck_cs`** mislei is om 'n kritieke lêer te korrupteer, weens sy vermoë om **symbolic links** te volg. Aanvallers het spesifiek 'n link vanaf _`/dev/diskX`_ na die lêer `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` geskep. Deur **`fsck_cs`** op _`/dev/diskX`_ uit te voer, is `Info.plist` gekorrupteer. Die integriteit van hierdie lêer is noodsaaklik vir die bedryfstelsel se SIP (System Integrity Protection), wat die laai van kernel extensions beheer. Sodra dit gekorrupteer is, word SIP se vermoë om kernel exclusions te bestuur, benadeel.<sup>[[6]](#references)</sup>

Die commands om hierdie kwesbaarheid uit te buit is:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Die uitbuiting van hierdie kwesbaarheid het ernstige implikasies. Die `Info.plist`-lêer, wat normaalweg verantwoordelik is vir die bestuur van toestemmings vir kernel extensions, word oneffektief. Dit sluit die onvermoë in om sekere extensions, soos `AppleHWAccess.kext`, te blacklist. Gevolglik, met SIP se beheermeganisme buite werking, kan hierdie extension gelaai word, wat ongemagtigde lees- en skryftoegang tot die stelsel se RAM verleen.<sup>[[6]](#references)</sup>

#### [Mount oor SIP-beskermde vouers](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Dit was moontlik om ’n nuwe file system oor **SIP-beskermde vouers te mount om die beskerming te omseil**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Die stelsel is ingestel om vanaf ’n ingebedde installeringskyfbeeld binne die `Install macOS Sierra.app` te begin om die bedryfstelsel op te gradeer, met gebruik van die `bless`-hulpmiddel. Die gebruikte opdrag is soos volg:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Die sekuriteit van hierdie proses kan gekompromitteer word indien 'n aanvaller die upgrade image (`InstallESD.dmg`) wysig voordat dit geboot word. Die strategie behels die vervanging van 'n dynamic loader (dyld) met 'n kwaadwillige weergawe (`libBaseIA.dylib`). Hierdie vervanging lei daartoe dat die aanvaller se code uitgevoer word wanneer die installer geïnisieer word.<sup>[[7]](#references)</sup>

Die aanvaller se code verkry beheer tydens die upgrade-proses en buit die stelsel se vertroue in die installer uit. Die aanval word uitgevoer deur die `InstallESD.dmg`-image via method swizzling te wysig, met spesifieke fokus op die `extractBootBits`-method. Dit maak die inspuiting van kwaadwillige code moontlik voordat die disk image gebruik word.<sup>[[7]](#references)</sup>

Daarbenewens is daar binne die `InstallESD.dmg` 'n `BaseSystem.dmg`, wat as die root file system van die upgrade code dien. Deur 'n dynamic library hierin in te spuit, kan die kwaadwillige code binne 'n proses werk wat OS-level-lêers kan wysig, wat die potensiaal vir stelselkompromittering aansienlik verhoog.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In hierdie praatjie van [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) word getoon hoe **`systemmigrationd`** (wat SIP kan omseil) 'n **bash**- en 'n **perl**-script uitvoer, wat deur middel van die env variables **`BASH_ENV`** en **`PERL5OPT`** misbruik kan word.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Soos [**in hierdie blogplasing uiteengesit**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), het 'n `postinstall`-script van `InstallAssistant.pkg`-packages toegelaat dat die volgende uitgevoer word:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
en dit was moontlik om ’n symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` te skep wat ’n gebruiker sou toelaat om **enige lêer te unrestrict en SIP-beskerming te omseil**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Die entitlement **`com.apple.rootless.install`** laat toe dat SIP omseil word

Dit is bekend dat die entitlement `com.apple.rootless.install` System Integrity Protection (SIP) op macOS omseil. Dit is spesifiek genoem in verband met [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[[10]](#references)</sup>

In hierdie spesifieke geval beskik die stelsel se XPC-diens by `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` oor hierdie entitlement. Dit laat die verwante proses toe om SIP-beperkings te omseil. Verder bied hierdie diens merkwaardig genoeg ’n metode wat die verskuiwing van lêers toelaat sonder om enige sekuriteitsmaatreëls af te dwing.<sup>[[10]](#references)</sup>

## Sealed System Snapshots

Sealed System Snapshots is ’n funksie wat Apple in **macOS Big Sur (macOS 11)** bekendgestel het as deel van sy **System Integrity Protection (SIP)**-meganisme, om ’n bykomende laag sekuriteit en stelselstabiliteit te bied. Dit is in wese leesalleen-weergawes van die stelselvolume.

Hier is ’n meer gedetailleerde oorsig:

1. **Onveranderlike stelsel**: Sealed System Snapshots maak die macOS-stelselvolume "onveranderlik", wat beteken dat dit nie gewysig kan word nie. Dit voorkom ongemagtigde of toevallige veranderinge aan die stelsel wat sekuriteit of stelselstabiliteit kan benadeel.
2. **Stelselsagteware-opdaterings**: Wanneer jy macOS-opdaterings of -opgraderings installeer, skep macOS ’n nuwe stelselsnapshot. Die macOS-opstartvolume gebruik dan **APFS (Apple File System)** om na hierdie nuwe snapshot oor te skakel. Die hele proses om opdaterings toe te pas, word veiliger en meer betroubaar, aangesien die stelsel altyd na die vorige snapshot kan terugkeer indien iets tydens die opdatering verkeerd loop.
3. **Dataskeiding**: In samewerking met die konsep van Data- en Stelselvolumeskeiding wat in macOS Catalina bekendgestel is, verseker die Sealed System Snapshot-funksie dat al jou data en instellings op ’n aparte "**Data**"-volume gestoor word. Hierdie skeiding maak jou data onafhanklik van die stelsel, wat die proses van stelselopdaterings vereenvoudig en stelselsekuriteit verbeter.

Onthou dat hierdie snapshots outomaties deur macOS bestuur word en nie bykomende spasie op jou skyf gebruik nie, danksy die spasiedelingsvermoëns van APFS. Dit is ook belangrik om daarop te let dat hierdie snapshots van **Time Machine snapshots** verskil, wat gebruikerstoeganklike rugsteunkopieë van die hele stelsel is.

### Check Snapshots

Die opdrag **`diskutil apfs list`** lys die **besonderhede van die APFS-volumes** en hul uitleg:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

In die vorige uitvoer is dit moontlik om te sien dat **gebruikerstoeganklike liggings** onder `/System/Volumes/Data` gemonteer word.

Verder word die **macOS-stelselvolumesnapshot** in `/` gemonteer en dit is **sealed** (kriptografies deur die OS onderteken). Dus, indien SIP omseil en dit gewysig word, **sal die OS nie meer selflaai nie**.

Dit is ook moontlik om **te verifieer dat seal geaktiveer is** deur die volgende uit te voer:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Boonop word die snapshot-skyf ook as **slegs-lees** gemonteer:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Verwysings

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sink die S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft vind nuwe macOS-kwesbaarheid, Shrootless, wat System Integrity Protection kan omseil](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple se vrugtelose rootless-sekuriteit gebreek deur kode wat in 'n tweet pas - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Om Apple se System Integrity Protection te omseil - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple versag kwesbaarhede in Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: The POC for SIP-Bypass Is Even Tweetable](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
