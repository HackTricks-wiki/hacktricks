# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Maelezo ya Msingi**

**System Integrity Protection (SIP)** katika macOS ni utaratibu ulioundwa kuzuia hata users wenye privileges za juu zaidi kufanya mabadiliko yasiyoidhinishwa kwenye system folders muhimu. Kipengele hiki kina jukumu muhimu katika kudumisha integrity ya system kwa kuzuia vitendo kama kuongeza, kurekebisha au kufuta files katika maeneo yaliyolindwa. Folders kuu zinazolindwa na SIP ni pamoja na:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Rules zinazoongoza tabia ya SIP zimefafanuliwa katika configuration file iliyoko kwenye **`/System/Library/Sandbox/rootless.conf`**. Ndani ya file hii, paths zilizo na asterisk (\*) mwanzoni huwakilisha exceptions kwa restrictions kali za SIP.

Fikiria mfano ulio hapa chini:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Kipande hiki kinaonyesha kuwa ingawa SIP kwa ujumla hulinda directory ya **`/usr`**, kuna subdirectories maalum (`/usr/libexec/cups`, `/usr/local`, na `/usr/share/man`) ambazo marekebisho yanaruhusiwa, kama inavyoonyeshwa na asterisk (\*) iliyo kabla ya paths hizo.

Ili kuthibitisha kama directory au file inalindwa na SIP, unaweza kutumia command ya **`ls -lOd`** kuangalia uwepo wa flag ya **`restricted`** au **`sunlnk`**. Kwa mfano:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Katika hali hii, flag ya **`sunlnk`** inaashiria kuwa directory ya `/usr/libexec/cups` yenyewe **haiwezi kufutwa**, ingawa faili zilizomo ndani yake zinaweza kuundwa, kurekebishwa au kufutwa.

Kwa upande mwingine:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hapa, flag ya **`restricted`** inaonyesha kuwa directory ya `/usr/libexec` inalindwa na SIP. Katika directory inayolindwa na SIP, mafaili hayawezi kuundwa, kurekebishwa, au kufutwa.

Zaidi ya hayo, ikiwa faili ina **attribute** iliyopanuliwa ya **`com.apple.rootless`**, faili hiyo pia **inalindwa na SIP**.

> [!TIP]
> Kumbuka kuwa **Sandbox** hook **`hook_vnode_check_setextattr`** huzuia jaribio lolote la kurekebisha attribute iliyopanuliwa ya **`com.apple.rootless`.**

**SIP pia huweka mipaka kwa vitendo vingine vya root** kama vile:

- Kupakia kernel extensions zisizoaminika
- Kupata task-ports za michakato iliyosainiwa na Apple
- Kurekebisha variables za NVRAM
- Kuruhusu kernel debugging

Options hudumishwa katika nvram variable kama bitflag (`csr-active-config` kwenye Intel, na `lp-sip0` husomwa kutoka kwenye Device Tree iliyo-bootiwa kwa ARM). Unaweza kupata flags katika source code ya XNU kwenye `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Hali ya SIP

Unaweza kuangalia ikiwa SIP imewezeshwa kwenye mfumo wako kwa kutumia command ifuatayo:
```bash
csrutil status
```
Ikiwa unahitaji kulemaza SIP, lazima uwashe upya kompyuta yako katika recovery mode (kwa kubonyeza Command+R wakati wa kuwasha), kisha utekeleze amri ifuatayo:
```bash
csrutil disable
```
Ukitaka kuweka SIP ikiwa imewashwa lakini uondoe ulinzi wa debugging, unaweza kufanya hivyo kwa:
```bash
csrutil enable --without debug
```
### Vizuizi Vingine

- **Huzuia kupakia unsigned kernel extensions** (kexts), na kuhakikisha kuwa extensions zilizothibitishwa pekee ndizo zinazoingiliana na system kernel.
- **Huzuia debugging** ya macOS system processes, na kulinda core system components dhidi ya access na modification zisizoidhinishwa.
- **Huzuia tools** kama dtrace kuchunguza system processes, na hivyo kulinda zaidi integrity ya uendeshaji wa system.

[**Jifunze zaidi kuhusu SIP info katika mazungumzo haya**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **SIP related Entitlements**

- `com.apple.rootless.xpc.bootstrap`: Dhibiti launchd
- `com.apple.rootless.install[.heritable]`: Fikia file system
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Dhibiti UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Uwezo wa XPC setup
- `com.apple.rootless.xpc.effective-root`: Root kupitia launchd XPC
- `com.apple.rootless.restricted-block-devices`: Access ya raw block devices
- `com.apple.rootless.internal.installer-equivalent`: Unfettered filesystem access
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Full access kwa NVRAM
- `com.apple.rootless.storage.label`: Modify files zilizozuiwa na com.apple.rootless xattr zenye label inayolingana
- `com.apple.rootless.volume.VM.label`: Dumisha VM swap kwenye volume

## SIP Bypasses

Kubypass SIP humwezesha attacker:

- **Kufikia User Data**: Kusoma user data nyeti kama barua pepe, messages, na Safari history kutoka user accounts zote.
- **TCC Bypass**: Kudhibiti moja kwa moja TCC (Transparency, Consent, and Control) database ili kutoa access isiyoidhinishwa kwa webcam, microphone, na resources nyingine.
- **Kuanzisha Persistence**: Kuweka malware katika maeneo yaliyolindwa na SIP, na kuifanya iwe sugu dhidi ya kuondolewa, hata kwa root privileges. Hii pia inajumuisha uwezekano wa kuchezea Malware Removal Tool (MRT).
- **Kupakia Kernel Extensions**: Ingawa kuna safeguards za ziada, kubypass SIP hurahisisha mchakato wa kupakia unsigned kernel extensions.

### Installer Packages

**Installer packages zilizosainiwa kwa certificate ya Apple** zinaweza kubypass protections zake. Hii inamaanisha kwamba hata packages zilizosainiwa na standard developers zitazuiwa ikiwa zitajaribu kubadilisha directories zilizolindwa na SIP.

### Inexistent SIP file

Loophole moja inayowezekana ni kwamba ikiwa file imeainishwa katika **`rootless.conf` lakini haipo kwa sasa**, inaweza kuundwa. Malware inaweza kutumia hili **kuanzisha persistence** kwenye system. Kwa mfano, program hasidi inaweza kuunda file ya .plist katika `/System/Library/LaunchDaemons` ikiwa imeorodheshwa katika `rootless.conf` lakini haipo.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** inaruhusu kubypass SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Iligunduliwa kwamba iliwezekana **kubadilisha installer package baada ya system kuthibitisha** signature ya code yake, na kisha system inge-install package hasidi badala ya ya awali. Kwa kuwa actions hizi zilifanywa na **`system_installd`**, ingewezesha kubypass SIP.<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Ikiwa package ili-install kutoka kwenye mounted image au external drive, **installer** inge-**execute** binary kutoka kwenye **file system hiyo** (badala ya location iliyolindwa na SIP), na hivyo kufanya **`system_installd`** i-execute arbitrary binary.<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**Researchers kutoka kwenye blog post hii**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) waligundua vulnerability katika macOS System Integrity Protection (SIP) mechanism, iliyopewa jina la 'Shrootless' vulnerability. Vulnerability hii inalenga **`system_installd`** daemon, ambayo ina entitlement, **`com.apple.rootless.install.heritable`**, inayoruhusu child processes zake zote kubypass file system restrictions za SIP.<sup>[4]</sup>

**`system_installd`** daemon ita-install packages zilizosainiwa na **Apple**.

Researchers waligundua kwamba wakati wa installation ya Apple-signed package (.pkg file), **`system_installd`** **hu-run** scripts zozote za **post-install** zilizojumuishwa kwenye package. Scripts hizi hu-execute na default shell, **`zsh`**, ambayo hu-run kiotomatiki commands kutoka kwenye file la **`/etc/zshenv`**, ikiwa lipo, hata katika non-interactive mode. Tabia hii inaweza kutumiwa na attackers: kwa kuunda file hasidi la `/etc/zshenv` na kusubiri **`system_installd` i-invoke `zsh`**, wangeweza kufanya arbitrary operations kwenye device.<sup>[4]</sup>

Zaidi ya hayo, iligunduliwa kwamba **`/etc/zshenv` inaweza kutumiwa kama general attack technique**, si kwa SIP bypass pekee. Kila user profile ina file la `~/.zshenv`, ambalo hufanya kazi kwa njia sawa na `/etc/zshenv` lakini halihitaji root permissions. File hili linaweza kutumika kama persistence mechanism, na ku-trigger kila `zsh` inapoanza, au kama privilege elevation mechanism. Ikiwa admin user ana-elevate kuwa root kwa kutumia `sudo -s` au `sudo <command>`, file la `~/.zshenv` linge-trigger, na hivyo kwa ufanisi ku-elevate kuwa root.<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Katika [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) iligunduliwa kwamba process ileile ya **`system_installd`** bado ingeweza kutumiwa vibaya kwa sababu ilikuwa ikiweka **post-install script ndani ya folder yenye jina random iliyolindwa na SIP ndani ya `/tmp`**. Jambo muhimu ni kwamba **`/tmp` yenyewe haijalindwa na SIP**, kwa hiyo iliwezekana **kui-mount** **virtual image juu yake**, kisha **installer** ingeweka humo **post-install script**, **ku-unmount** virtual image, **kuunda upya** **folders** zote na **kuongeza** **post installation** script yenye **payload** ya ku-execute.<sup>[5]</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Vulnerability ilitambuliwa ambapo **`fsck_cs`** ilipotoshwa na kusababisha corruption ya file muhimu, kutokana na uwezo wake wa kufuata **symbolic links**. Specifically, attackers walitengeneza link kutoka _`/dev/diskX`_ kwenda kwenye file `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Ku-execute **`fsck_cs`** kwenye _`/dev/diskX`_ kulisababisha corruption ya `Info.plist`. Integrity ya file hili ni muhimu kwa SIP (System Integrity Protection) ya operating system, ambayo hudhibiti loading ya kernel extensions. Baada ya ku-corruptiwa, uwezo wa SIP wa kusimamia kernel exclusions huathirika.<sup>[6]</sup>

Commands za ku-exploit vulnerability hii ni:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Unyonyaji wa udhaifu huu una madhara makubwa. Faili ya `Info.plist`, ambayo kwa kawaida huwa na jukumu la kudhibiti ruhusa za kernel extensions, huwa haifanyi kazi. Hii inajumuisha kutoweza kuzuia extensions fulani, kama vile `AppleHWAccess.kext`. Kwa hivyo, kwa kuwa utaratibu wa udhibiti wa SIP haukufanya kazi, extension hii inaweza kupakiwa na kutoa read na write access isiyoidhinishwa kwenye RAM ya mfumo.<sup>[6]</sup>

#### [Mount over SIP protected folders](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Iliwezekana kuweka file system mpya juu ya **SIP protected folders ili kupita ulinzi huo**.<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Mfumo umewekwa kuwasha kutoka kwenye disk image ya installer iliyopachikwa ndani ya `Install macOS Sierra.app` ili ku-upgrade OS, kwa kutumia utility ya `bless`. Command iliyotumika ni kama ifuatavyo:<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Usalama wa mchakato huu unaweza kuathiriwa ikiwa mshambuliaji atabadilisha image ya upgrade (`InstallESD.dmg`) kabla ya ku-boot. Mkakati huu unahusisha kubadilisha dynamic loader (dyld) kwa toleo hasidi (`libBaseIA.dylib`). Ubadilishaji huu husababisha code ya mshambuliaji kutekelezwa installer inapoanzishwa.<sup>[7]</sup>

Code ya mshambuliaji hupata udhibiti wakati wa mchakato wa upgrade, ikitumia trust ya mfumo kwa installer. Shambulio hili huendelea kwa kubadilisha image ya `InstallESD.dmg` kupitia method swizzling, hasa ikilenga method ya `extractBootBits`. Hii huwezesha kuingizwa kwa code hasidi kabla ya disk image kutumiwa.<sup>[7]</sup>

Zaidi ya hayo, ndani ya `InstallESD.dmg` kuna `BaseSystem.dmg`, ambayo hutumika kama root file system ya code ya upgrade. Kuingiza dynamic library ndani yake huwezesha code hasidi kufanya kazi ndani ya process inayoweza kubadilisha files za kiwango cha OS, hivyo kuongeza kwa kiasi kikubwa uwezekano wa system compromise.<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Katika mazungumzo haya kutoka [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), inaonyeshwa jinsi **`systemmigrationd`** (ambayo inaweza kubypass SIP) hutekeleza script ya **bash** na script ya **perl**, ambazo zinaweza kutumiwa vibaya kupitia env variables **`BASH_ENV`** na **`PERL5OPT`**.<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Kama [**ilivyoelezwa kwa undani katika blog post hii**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), script ya `postinstall` kutoka kwenye packages za `InstallAssistant.pkg` ilikuwa ikitekelezwa:<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
na iliwezekana kuunda symlink katika `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` ambayo ingemruhusu mtumiaji **kuondoa restriction kwenye faili yoyote, akipita ulinzi wa SIP**.<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** inaruhusu kupita SIP

Entitlement `com.apple.rootless.install` inajulikana kwa kupita System Integrity Protection (SIP) kwenye macOS. Hili lilitajwa hasa kuhusiana na [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[10]</sup>

Katika hali hii mahususi, system XPC service iliyoko `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` ina entitlement hii. Hii inaruhusu process inayohusiana nayo kupita vikwazo vya SIP. Zaidi ya hayo, service hii ina method inayoruhusu kuhamisha mafaili bila kutekeleza hatua zozote za usalama.<sup>[10]</sup>

## Sealed System Snapshots

Sealed System Snapshots ni feature iliyoletwa na Apple katika **macOS Big Sur (macOS 11)** kama sehemu ya utaratibu wake wa **System Integrity Protection (SIP)** ili kutoa safu ya ziada ya usalama na uthabiti wa mfumo. Kimsingi ni matoleo ya system volume yanayoweza kusomwa pekee.

Hapa kuna maelezo zaidi:

1. **Mfumo Usiozoweza Kubadilishwa**: Sealed System Snapshots hufanya macOS system volume kuwa "immutable", ikimaanisha haiwezi kurekebishwa. Hii huzuia mabadiliko yasiyoruhusiwa au ya kimakosa kwenye mfumo ambayo yanaweza kuhatarisha usalama au uthabiti wa mfumo.
2. **System Software Updates**: Unaposakinisha macOS updates au upgrades, macOS huunda system snapshot mpya. macOS startup volume hutumia **APFS (Apple File System)** kubadilisha kwenda kwenye snapshot hii mpya. Mchakato mzima wa kutumia updates huwa salama na wa kuaminika zaidi kwa kuwa mfumo unaweza kurudi kwenye snapshot iliyotangulia ikiwa hitilafu itatokea wakati wa update.
3. **Kutenganisha Data**: Pamoja na dhana ya kutenganisha Data na System volume iliyoletwa katika macOS Catalina, feature ya Sealed System Snapshot huhakikisha kwamba data na settings zako zote zinahifadhiwa kwenye "**Data**" volume tofauti. Utenganishaji huu hufanya data yako iwe huru kutoka kwa mfumo, jambo linalorahisisha mchakato wa system updates na kuimarisha usalama wa mfumo.

Kumbuka kwamba snapshots hizi zinasimamiwa kiotomatiki na macOS na hazitumii nafasi ya ziada kwenye disk yako, kutokana na uwezo wa APFS wa kushirikisha nafasi. Pia ni muhimu kutambua kwamba snapshots hizi ni tofauti na **Time Machine snapshots**, ambazo ni backups za mfumo mzima zinazoweza kufikiwa na mtumiaji.

### Check Snapshots

Command **`diskutil apfs list`** huorodhesha **maelezo ya APFS volumes** na mpangilio wake:

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

Katika output iliyotangulia inawezekana kuona kwamba **maeneo yanayoweza kufikiwa na mtumiaji** yamewekwa chini ya `/System/Volumes/Data`.

Zaidi ya hayo, **macOS System volume snapshot** imewekwa kwenye `/` na **imefungwa kwa seal** (imesainiwa cryptographically na OS). Kwa hiyo, SIP ikipitwa na snapshot hiyo kurekebishwa, **OS haitawaka tena**.

Pia inawezekana **kuthibitisha kwamba seal imewezeshwa** kwa kuendesha:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Zaidi ya hayo, diski ya snapshot pia imewekwa katika hali ya **kusoma pekee**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Marejeleo

- [1] [SyScan360 - Stefan Esser - OS X El Capitan ikizamisha S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Blogu ya Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Blogu ya Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft imegundua vulnerability mpya ya macOS, Shrootless, inayoweza kupita System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple's fruitless rootless security imevunjwa na code inayotoshea kwenye tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Kupita System Integrity Protection ya Apple - Blogu ya Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple inarekebisha vulnerabilities katika Installer Scripts - Blogu ya Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: POC ya SIP-Bypass Inaweza Hata Kutoshea Kwenye Tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
