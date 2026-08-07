# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Maelezo ya Msingi**

**System Integrity Protection (SIP)** katika macOS ni utaratibu ulioundwa kuzuia hata watumiaji wenye mamlaka ya juu zaidi kufanya mabadiliko yasiyoidhinishwa kwenye folda muhimu za mfumo. Kipengele hiki kina jukumu muhimu katika kudumisha uadilifu wa mfumo kwa kuzuia vitendo kama vile kuongeza, kurekebisha au kufuta faili katika maeneo yaliyolindwa. Folda kuu zinazolindwa na SIP ni pamoja na:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Sheria zinazoongoza tabia ya SIP zimefafanuliwa katika faili ya usanidi iliyoko kwenye **`/System/Library/Sandbox/rootless.conf`**. Ndani ya faili hii, paths zilizo na kiambishi cha nyota (\*) hutambuliwa kama exceptions kwa vizuizi vingine vikali vya SIP.

Fikiria mfano ulio hapa chini:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Kipande hiki kinaonyesha kwamba ingawa SIP kwa ujumla hulinda directory ya **`/usr`**, kuna subdirectories maalum (`/usr/libexec/cups`, `/usr/local`, na `/usr/share/man`) ambako marekebisho yanaruhusiwa, kama inavyoonyeshwa na asterisk (\*) iliyo kabla ya paths zao.

Ili kuthibitisha kama directory au file inalindwa na SIP, unaweza kutumia command ya **`ls -lOd`** kuangalia uwepo wa flag ya **`restricted`** au **`sunlnk`**. Kwa mfano:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Katika hali hii, flag ya **`sunlnk`** inaashiria kwamba directory ya `/usr/libexec/cups` yenyewe **haiwezi kufutwa**, ingawa faili zilizo ndani yake zinaweza kuundwa, kurekebishwa au kufutwa.

Kwa upande mwingine:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hapa, flag ya **`restricted`** inaonyesha kwamba directory ya `/usr/libexec` inalindwa na SIP. Katika directory inayolindwa na SIP, faili haziwezi kuundwa, kurekebishwa, au kufutwa.

Zaidi ya hayo, ikiwa faili ina **attribute** ya extended **attribute** **`com.apple.rootless`**, faili hiyo pia **italindwa na SIP**.

> [!TIP]
> Kumbuka kwamba **Sandbox** hook **`hook_vnode_check_setextattr`** huzuia jaribio lolote la kurekebisha extended attribute **`com.apple.rootless`.**

**SIP pia hupunguza actions nyingine za root** kama vile:

- Kupakia kernel extensions zisizoaminika
- Kupata task-ports za processes zilizosainiwa na Apple
- Kurekebisha variables za NVRAM
- Kuruhusu kernel debugging

Options huhifadhiwa katika nvram variable kama bitflag (`csr-active-config` kwenye Intel na `lp-sip0` husomwa kutoka kwenye Device Tree iliyo-bootiwa kwa ARM). Unaweza kupata flags katika XNU source code kwenye `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Hali ya SIP

Unaweza kuangalia ikiwa SIP imewezeshwa kwenye mfumo wako kwa command ifuatayo:
```bash
csrutil status
```
Ikiwa unahitaji kuzima SIP, lazima uwashe upya kompyuta yako katika recovery mode (kwa kubonyeza Command+R wakati wa kuwasha), kisha utekeleze amri ifuatayo:
```bash
csrutil disable
```
Ikiwa ungependa kuweka SIP ikiwa imewezeshwa lakini uondoe ulinzi wa debugging, unaweza kufanya hivyo kwa:
```bash
csrutil enable --without debug
```
### Other Restrictions

- **Huzuia upakiaji wa kernel extensions (kexts) ambazo hazijasainiwa**, na kuhakikisha kuwa extensions zilizothibitishwa pekee ndizo zinazoingiliana na system kernel.
- **Huzuia debugging** ya macOS system processes, na kulinda core system components dhidi ya access na modification zisizoidhinishwa.
- **Huzuia tools** kama dtrace kukagua system processes, na hivyo kulinda zaidi integrity ya utendaji wa system.

[**Jifunze zaidi kuhusu SIP info katika mazungumzo haya**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **SIP related Entitlements**

- `com.apple.rootless.xpc.bootstrap`: Control launchd
- `com.apple.rootless.install[.heritable]`: Access file system
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Manage UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: XPC setup capabilities
- `com.apple.rootless.xpc.effective-root`: Root via launchd XPC
- `com.apple.rootless.restricted-block-devices`: Access to raw block devices
- `com.apple.rootless.internal.installer-equivalent`: Unfettered filesystem access
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Full access to NVRAM
- `com.apple.rootless.storage.label`: Modify files restricted by com.apple.rootless xattr with the corresponding label
- `com.apple.rootless.volume.VM.label`: Maintain VM swap on volume

## SIP Bypasses

Kukwepa SIP humwezesha attacker:

- **Kufikia User Data**: Kusoma user data nyeti kama mail, messages, na Safari history kutoka user accounts zote.
- **TCC Bypass**: Kudhibiti moja kwa moja TCC (Transparency, Consent, and Control) database ili kutoa access isiyoidhinishwa kwa webcam, microphone, na resources nyingine.
- **Kuanzisha Persistence**: Kuweka malware katika SIP-protected locations, na kuifanya iwe sugu dhidi ya kuondolewa, hata kwa root privileges. Hii pia inajumuisha uwezekano wa kuharibu Malware Removal Tool (MRT).
- **Kupakia Kernel Extensions**: Ingawa kuna safeguards za ziada, kukwepa SIP hurahisisha mchakato wa kupakia unsigned kernel extensions.

### Installer Packages

**Installer packages zilizosainiwa kwa certificate ya Apple** zinaweza kukwepa protections zake. Hii inamaanisha kuwa hata packages zilizosainiwa na standard developers zitazuiwa ikiwa zitajaribu kurekebisha SIP-protected directories.

### Inexistent SIP file

Loophole moja inayowezekana ni kwamba ikiwa file limeainishwa katika **`rootless.conf` lakini halipo kwa sasa**, linaweza kuundwa. Malware inaweza kutumia hili **kuanzisha persistence** kwenye system. Kwa mfano, malicious program inaweza kuunda .plist file katika `/System/Library/LaunchDaemons` ikiwa limeorodheshwa katika `rootless.conf` lakini halipo.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** inaruhusu kukwepa SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Iligunduliwa kwamba iliwezekana **kubadilisha installer package baada ya system kuthibitisha** code yake **signature**, kisha system inge-install malicious package badala ya original. Kwa kuwa vitendo hivi vilitekelezwa na **`system_installd`**, vingeruhusu kukwepa SIP.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Ikiwa package ili-installiwa kutoka mounted image au external drive, **installer** inge-**execute** binary kutoka **hiyo file system** (badala ya SIP protected location), na hivyo kufanya **`system_installd`** i-execute arbitrary binary.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Researchers kutoka blog post hii**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) waligundua vulnerability katika macOS System Integrity Protection (SIP) mechanism, iliyopewa jina la 'Shrootless' vulnerability. Vulnerability hii inahusu **`system_installd`** daemon, ambayo ina entitlement, **`com.apple.rootless.install.heritable`**, inayoruhusu child processes zake zote kukwepa SIP's file system restrictions.<sup>[[4]](#references)</sup>

**`system_installd`** daemon ita-install packages zilizosainiwa na **Apple**.

Researchers waligundua kwamba wakati wa ku-install Apple-signed package (.pkg file), **`system_installd`** **hu-run** scripts zozote za **post-install** zilizojumuishwa kwenye package. Scripts hizi hu-execute na default shell, **`zsh`**, ambayo hu-**run** automatically commands kutoka kwenye **`/etc/zshenv`** file, ikiwa lipo, hata katika non-interactive mode. Tabia hii inaweza kutumiwa na attackers: kwa kuunda malicious `/etc/zshenv` file na kusubiri **`system_installd` i-invoke `zsh`**, wangeweza kufanya arbitrary operations kwenye device.<sup>[[4]](#references)</sup>

Zaidi ya hayo, iligunduliwa kwamba **`/etc/zshenv` inaweza kutumiwa kama general attack technique**, si kwa SIP bypass pekee. Kila user profile ina `~/.zshenv` file, ambalo hufanya kazi kwa njia sawa na `/etc/zshenv` lakini halihitaji root permissions. File hili linaweza kutumiwa kama persistence mechanism, liki-trigger kila `zsh` inapoanza, au kama privilege elevation mechanism. Ikiwa admin user anaelevate hadi root kwa kutumia `sudo -s` au `sudo <command>`, `~/.zshenv` file lita-trigger, na hivyo ku-elevate hadi root.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Katika [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) iligunduliwa kwamba mchakato huo huo wa **`system_installd`** bado ungeweza kutumiwa vibaya kwa sababu ulikuwa ukiweka **post-install script ndani ya random named folder iliyolindwa na SIP ndani ya `/tmp`**. Jambo ni kwamba **`/tmp` yenyewe hailindwi na SIP**, kwa hiyo iliwezekana **ku-mount** **virtual image juu yake**, kisha **installer** ingeweka humo **post-install script**, **ku-unmount** virtual image, **kuunda upya** **folders** zote na **kuongeza** **post installation** script yenye **payload** ya ku-execute.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Vulnerability ilitambuliwa ambapo **`fsck_cs`** ilidanganywa na kusababisha corruption ya file muhimu, kutokana na uwezo wake wa kufuata **symbolic links**. Specifically, attackers walitengeneza link kutoka _`/dev/diskX`_ kwenda kwenye file `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Ku-execute **`fsck_cs`** kwenye _`/dev/diskX`_ kulisababisha corruption ya `Info.plist`. Integrity ya file hili ni muhimu kwa SIP (System Integrity Protection) ya operating system, ambayo inadhibiti upakiaji wa kernel extensions. Baada ya ku-corruptiwa, uwezo wa SIP wa kudhibiti kernel exclusions huathirika.<sup>[[6]](#references)</sup>

Commands za kutumia vulnerability hii ni:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Kutumia udhaifu huu kuna madhara makubwa. Faili ya `Info.plist`, ambayo kwa kawaida husimamia ruhusa za kernel extensions, huwa haina ufanisi. Hii inajumuisha kutoweza kuweka baadhi ya extensions kwenye blacklist, kama vile `AppleHWAccess.kext`. Kwa hivyo, kwa kuwa mfumo wa udhibiti wa SIP hauko katika hali ya kufanya kazi, extension hii inaweza kupakiwa na kutoa read na write access isiyoidhinishwa kwa RAM ya mfumo.<sup>[[6]](#references)</sup>

#### [Mount juu ya folda zinazolindwa na SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Iliwezekana ku-mount file system mpya juu ya **folda zinazolindwa na SIP ili kukwepa ulinzi**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Mfumo umewekwa kuwasha kutoka kwenye disk image ya installer iliyopachikwa ndani ya `Install macOS Sierra.app` ili kuboresha OS, kwa kutumia utility ya `bless`. Command iliyotumika ni kama ifuatavyo:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Usalama wa mchakato huu unaweza kuathiriwa ikiwa mshambulizi atabadilisha upgrade image (`InstallESD.dmg`) kabla ya ku-boot. Mkakati huu unahusisha kubadilisha dynamic loader (dyld) na toleo hasidi (`libBaseIA.dylib`). Ubadilishaji huu husababisha code ya mshambulizi kutekelezwa installer inapoanzishwa.<sup>[[7]](#references)</sup>

Code ya mshambulizi hupata udhibiti wakati wa mchakato wa upgrade, ikitumia imani ya mfumo kwa installer. Shambulio hilo huendelea kwa kubadilisha image ya `InstallESD.dmg` kupitia method swizzling, hasa ikilenga method ya `extractBootBits`. Hii huruhusu kuingizwa kwa code hasidi kabla disk image haijatumiwa.<sup>[[7]](#references)</sup>

Zaidi ya hayo, ndani ya `InstallESD.dmg` kuna `BaseSystem.dmg`, ambayo hutumika kama root file system ya code ya upgrade. Kuingiza dynamic library ndani yake huruhusu code hasidi kufanya kazi ndani ya process yenye uwezo wa kubadilisha files za kiwango cha OS, jambo linaloongeza kwa kiasi kikubwa uwezekano wa mfumo kuathiriwa.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Katika mazungumzo haya kutoka [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), inaonyeshwa jinsi **`systemmigrationd`** (ambayo inaweza bypass SIP) hutekeleza script ya **bash** na ya **perl**, ambazo zinaweza kutumiwa vibaya kupitia env variables **`BASH_ENV`** na **`PERL5OPT`**.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Kama [**ilivyoelezwa kwa kina katika chapisho hili la blogu**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), script ya `postinstall` kutoka kwenye packages za `InstallAssistant.pkg` iliruhusiwa kutekeleza:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
na iliwezekana kuunda symlink katika `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` ambayo ingemruhusu mtumiaji **kuondoa restriction kwenye faili yoyote, akipita ulinzi wa SIP**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** inaruhusu kupita SIP

Entitlement `com.apple.rootless.install` inajulikana kwa kupita System Integrity Protection (SIP) kwenye macOS. Hili lilitajwa hasa kuhusiana na [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[[10]](#references)</sup>

Katika hali hii maalum, system XPC service iliyo kwenye `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` ina entitlement hii. Hii inaruhusu process inayohusiana nayo kupita vikwazo vya SIP. Zaidi ya hayo, service hii ina method inayoruhusu kuhamisha faili bila kutekeleza hatua zozote za usalama.<sup>[[10]](#references)</sup>

## Sealed System Snapshots

Sealed System Snapshots ni feature iliyoletwa na Apple katika **macOS Big Sur (macOS 11)** kama sehemu ya utaratibu wake wa **System Integrity Protection (SIP)**, ili kutoa safu ya ziada ya usalama na uthabiti wa mfumo. Kimsingi, ni matoleo ya system volume yanayoweza kusomwa tu.

Hapa kuna maelezo zaidi:

1. **Immutable System**: Sealed System Snapshots hufanya macOS system volume kuwa "immutable", kumaanisha kwamba haiwezi kurekebishwa. Hii huzuia mabadiliko yasiyoidhinishwa au ya kimakosa kwenye system ambayo yanaweza kuhatarisha usalama au uthabiti wa mfumo.
2. **System Software Updates**: Unaposakinisha macOS updates au upgrades, macOS huunda system snapshot mpya. Kisha macOS startup volume hutumia **APFS (Apple File System)** kubadilisha kwenda kwenye snapshot hii mpya. Mchakato mzima wa kutumia updates huwa salama na wa kuaminika zaidi kwa sababu system inaweza kurejea kwenye snapshot ya awali ikiwa kuna tatizo lolote wakati wa update.
3. **Data Separation**: Pamoja na dhana ya kutenganisha Data na System volume iliyoletwa katika macOS Catalina, feature ya Sealed System Snapshot huhakikisha kwamba data na settings zako zote zimehifadhiwa kwenye "**Data**" volume tofauti. Utenganishaji huu hufanya data yako ijitegemee kutoka kwa system, jambo linalorahisisha mchakato wa system updates na kuimarisha usalama wa system.

Kumbuka kwamba snapshots hizi zinasimamiwa kiotomatiki na macOS na hazitumii nafasi ya ziada kwenye disk yako, kutokana na uwezo wa APFS wa kushiriki nafasi. Ni muhimu pia kutambua kwamba snapshots hizi ni tofauti na **Time Machine snapshots**, ambazo ni backups za system nzima zinazoweza kufikiwa na mtumiaji.

### Kagua Snapshots

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
|   Encrypted:                 No
</code></pre>

Katika output ya awali, inawezekana kuona kwamba **locations zinazoweza kufikiwa na mtumiaji** zime-mount chini ya `/System/Volumes/Data`.

Zaidi ya hayo, **macOS System volume snapshot** ime-mount katika `/` na ni **sealed** (imesainiwa cryptographically na OS). Kwa hiyo, ikiwa SIP itapitiwa na snapshot hiyo kurekebishwa, **OS haitawaka tena**.

Pia inawezekana **kuthibitisha kwamba seal imewashwa** kwa kuendesha:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Zaidi ya hayo, snapshot disk pia imewekwa kama **read-only**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Marejeleo

- [1] [SyScan360 - Stefan Esser - OS X El Capitan inazamisha S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Blogu ya Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" bugs za mantiki (tatu) ftw! - Blogu ya Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft inagundua vulnerability mpya ya macOS, Shrootless, inayoweza kufanya bypass ya System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Uchambuzi wa Kiufundi: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Usalama wa rootless wa Apple usio na matunda wavunjwa na code inayotoshea kwenye tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Kufanya bypass ya Apple's System Integrity Protection - Blogu ya Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Kupata Migraine - Unique SIP Bypass kwenye MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple inapunguza vulnerabilities katika Installer Scripts - Blogu ya Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: POC ya SIP-Bypass inaweza hata kutweetiwa](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
