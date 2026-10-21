# Faili, Folda, Binaries na Memory za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Mpangilio wa mfumo wa faili

Apple inaeleza mfumo wa faili wa macOS kama mpangilio wa mfumo, wa ndani, wa mtandao na wa watumiaji. Yaliyomo hasa hutofautiana kulingana na toleo la OS, na maeneo ya mfumo yanazidi kulindwa au kuundwa kwa namna ya kuonekana tu. <sup>[[1]](#references)</sup>

- **/Applications**: Programu zilizosakinishwa zinapaswa kuwa hapa. Watumiaji wote wataweza kuzifikia.
- **/bin**: Binaries za command line
- **/cores**: Ikiwa ipo, hutumika kuhifadhi core dumps
- **/dev**: Kila kitu huchukuliwa kama faili, kwa hivyo unaweza kuona vifaa vya hardware vikiwa vimehifadhiwa hapa.
- **/etc**: Faili za usanidi
- **/Library**: Saraka ndogo na faili nyingi zinazohusiana na mapendeleo, akiba na logi zinaweza kupatikana hapa. Folda ya Library ipo kwenye root na kwenye saraka ya kila mtumiaji.
- **/private**: Haijaandikwa kwenye nyaraka, lakini folda nyingi zilizotajwa ni symbolic links zinazoelekeza kwenye saraka ya private.
- **/sbin**: Binaries muhimu za mfumo (zinazohusiana na usimamizi)
- **/System**: Faili zinazohitajika na macOS; mti huu huwa na vipengele vilivyotolewa na Apple.
- **/tmp**: Faili za muda (symbolic link inayoelekeza `/private/tmp`). Usakinishaji wa zamani mara nyingi ulisafisha faili za muda zilizopitwa na wakati kwa ratiba ya mara kwa mara, wakati mwingine ikielezwa kuwa ni kila baada ya siku tatu, lakini muda wa sasa wa usafishaji hutegemea mfumo na sera; usitegemee data kubaki hapo.
- **/Users**: Saraka za nyumbani za watumiaji.
- **/usr**: Faili za usanidi na binaries za mfumo
- **/var**: Faili za logi
- **/Volumes**: Volumes zilizowekwa huonekana hapa.
- **/.vol**: Ukiendesha `stat a.txt`, utapata kitu kama `16777223 7545753 -rw-r--r-- 1 username wheel ...` ambapo nambari ya kwanza ni kitambulisho cha volume ambako faili ipo, na ya pili ni nambari ya inode. Unaweza kufikia maudhui ya faili hii kupitia /.vol/ kwa kutumia taarifa hizo, kwa kuendesha `cat /.vol/16777223/7545753`

### Folda za Programu

- Programu za **mfumo** ziko chini ya `/System/Applications`
- Programu **zilizosakinishwa** kwa kawaida husakinishwa kwenye `/Applications` au `~/Applications`
- **Data ya programu** inaweza kupatikana kwenye `/Library/Application Support` kwa programu zinazoendeshwa kama root na `~/Library/Application Support` kwa programu zinazoendeshwa kama mtumiaji.
- **Daemons** za programu za wahusika wengine **zinazohitaji kuendeshwa kama root** kwa kawaida ziko kwenye `/Library/PrivilegedHelperTools/`.
- Programu za **Sandboxed** huunganishwa kwenye folda ya `~/Library/Containers`. Kila programu ina folda iliyopewa jina kulingana na bundle ID ya programu (`com.apple.Safari`).
- **Kernel** iko kwenye `/System/Library/Kernels/kernel`
- **Kernel extensions** za Apple ziko kwenye `/System/Library/Extensions`
- **Kernel extensions** za wahusika wengine huhifadhiwa kwenye `/Library/Extensions`

### Faili Zenye Taarifa Nyeti

macOS huhifadhi taarifa nyeti, ikiwemo credentials, katika maeneo kadhaa:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Visakinishaji vya pkg vilivyo hatarini


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Kwa tofauti kati ya volume ya Data inayoweza kuandikwa na volume ya System iliyofungwa, zinazoonekana kwenye mpangilio huu, angalia [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Viendelezi Mahususi vya OS X

- **`.dmg`**: Faili za Apple Disk Image hutumika sana kwa visakinishaji.
- **`.kext`**: Lazima ifuate muundo maalum na ni toleo la OS X la driver. (ni bundle)
- **`.plist`**: Property list huhifadhi taarifa zilizopangwa katika umbizo la XML au binary.
  - Inaweza kuwa XML au binary. Faili za binary zinaweza kusomwa kwa kutumia:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Application bundle inayofuata muundo sanifu wa saraka za macOS.
- **`.dylib`**: Dynamic libraries (kama faili za Windows DLL)
- **`.pkg`**: Vifurushi vya kisasa vya flat installer ni archive za XAR, lakini `.pkg` ni umbizo la installer, si jina jingine la XAR. Vifurushi vya zamani vya installer vya mtindo wa bundle ni saraka. Angalia [visakinishaji vya macOS](macos-installers-abuse.md) kwa muundo wa kifurushi na ukaguzi wake. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Faili hii ipo kwenye kila saraka; huhifadhi sifa na mipangilio maalum ya saraka.
- **`.Spotlight-V100`**: Folda hii huonekana kwenye saraka ya root ya kila volume kwenye mfumo.
- **`.metadata_never_index`**: Ikiwa faili hii iko kwenye root ya volume, Spotlight haitaorodhesha volume hiyo.
- **`.noindex`**: Faili na folda zenye kiendelezi hiki hazitaorodheshwa na Spotlight.
- **`.sdef`**: Faili ya ufafanuzi wa scripting inayoeleza jinsi AppleScript inavyoweza kuingiliana na programu.

### Bundles za macOS

Bundle ni saraka yenye mpangilio sanifu ambao Finder inaweza kuonyesha kama kitu kimoja; application bundles hutumia kiendelezi cha `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Kwenye macOS na iOS, system libraries na frameworks zinazotumiwa mara nyingi huunganishwa mapema kwenye **dyld shared cache**, jambo linaloboresha kasi ya kuanzisha programu. Ingawa hushughulikiwa kama cache moja ya kimantiki, matoleo ya sasa yanaweza kuihifadhi kama cache kuu pamoja na faili ndogo kadhaa za subcache badala ya kuwa faili moja halisi. Umbizo na mahali ilipo ni maelezo ya utekelezaji yanayobadilika kulingana na matoleo ya OS. <sup>[[3]](#references)</sup>

Hii hupatikana kwenye macOS katika `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, na katika matoleo ya zamani unaweza kupata **shared cache** kwenye **`/System/Library/dyld/`**.\
Kwenye iOS unaweza kuzipata katika **`/System/Library/Caches/com.apple.dyld/`**.

Sawa na dyld shared cache, kernel na kernel extensions pia hujumuishwa kwenye kernel cache, ambayo hupakiwa wakati wa kuwasha mfumo.

Matoleo ya zamani yangeweza kutolewa kwa kutumia [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Huenda build hiyo isiunge mkono umbizo la sasa la cache; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) ni chaguo jingine:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Kumbuka kwamba hata kama zana ya `dyld_shared_cache_util` haifanyi kazi, unaweza kupitisha **shared dyld binary kwa Hopper** na Hopper itaweza kutambua maktaba zote na kukuruhusu **uchague unayotaka kuchunguza**:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Baadhi ya extractors hazitafanya kazi kwa sababu dylibs zimeunganishwa mapema zikiwa na anwani zilizowekwa moja kwa moja, kwa hiyo huenda zikaruka hadi kwenye anwani zisizojulikana.

> [!TIP]
> Pia inawezekana kupakua Shared Library Cache ya vifaa vingine vya \*OS kwenye macOS kwa kutumia emulator katika Xcode. Zitapakuliwa ndani ya: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, kama:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** hutumia syscall **`shared_region_check_np`** kujua kama SLC imepangwa kwenye kumbukumbu (ambayo hurejesha anwani) na **`shared_region_map_and_slide_np`** kupanga SLC kwenye kumbukumbu.

Kumbuka kwamba hata kama SLC inasogezwa (slid) inapotumiwa mara ya kwanza, **processes** zote hutumia **nakala ileile**, jambo ambalo **liliondoa** ulinzi wa ASLR ikiwa mshambulizi angeweza kuendesha processes kwenye mfumo. Hili lilitumiwa vibaya hapo awali na kurekebishwa kwa shared region pager.

Branch pools ni dylibs ndogo za Mach-O zinazounda nafasi ndogo kati ya image mappings, na hivyo kufanya isiwezekane kuingilia kati utendaji.

### Vikwazo vya mazingira vya shared cache

`DYLD_SHARED_CACHE_DIR` hutaja saraka ya cache, ilhali `DYLD_SHARED_REGION` huchagua hali ya shared-region. Tahajia ya awali ya `DYLD_DHARED_REGION` haikuwa sahihi, na `avoid` si thamani halali ya `DYLD_SHARED_CACHE_DIR`. Dyld ya sasa huruhusu hali ya `private` tu iwapo AMFI imetoa ruhusa ya kutumia custom shared caches, kwa hiyo kuweka environment variables pekee hakuthibitishi kwamba process inaweza kupakia cache mbadala. <sup>[[10]](#references)</sup>

## Ruhusa Maalum za Faili

### Ruhusa za folda

Kwa saraka, **read** huruhusu kuorodhesha vitu vilivyomo, **write** huruhusu kuunda au kuondoa vitu vilivyomo, na **execute** huruhusu kupitia saraka hiyo. Kwa hiyo, mtumiaji anayeweza kusoma faili lakini hawezi kupitia saraka mama hawezi kufikia faili hiyo kwa kutumia path. <sup>[[4]](#references)</sup>

### Virekebishaji vya flag

Faili zinaweza kuwa na flags zinazobadilisha jinsi zinavyofanya kazi. Kagua flags katika saraka kwa kutumia `ls -lO /path/directory`.

- **`uchg`**: Inajulikana kama flag ya **uchange**, huzuia **kitendo chochote** cha kubadilisha au kufuta **faili**. Ili kuiweka, tumia: `chflags uchg file.txt`
  - Mmiliki wa faili au root anaweza kuondoa flag hii ya **mtumiaji** kwa kutumia `chflags nouchg file.txt`; si kinga dhidi yao. Flag tofauti ya **mfumo** ya immutable (`schg`) imezuiwa kwa root. <sup>[[11]](#references)</sup>
- **`restricted`**: Flag hii hufanya faili **ilindwe na SIP** (huwezi kuongeza flag hii kwenye faili).
- **`Sticky bit`**: Katika saraka yenye sticky bit, ni mmiliki wa faili, mmiliki wa saraka, au root pekee anayeweza kubadilisha jina au kufuta kitu kilichomo. Kwa kawaida huwashwa kwenye `/tmp` ili kuzuia watumiaji kufuta au kuhamisha faili za watumiaji wengine.

Flags zote ziko kwenye faili `sys/stat.h` (ipate kwa kutumia `mdfind stat.h | grep stat.h`) na ni:

- `UF_SETTABLE` 0x0000ffff: Kinyago cha flags zinazoweza kubadilishwa na mmiliki.
- `UF_NODUMP` 0x00000001: Usidump faili.
- `UF_IMMUTABLE` 0x00000002: Faili haiwezi kubadilishwa.
- `UF_APPEND` 0x00000004: Maandishi yanaweza kuongezwa tu kwenye faili.
- `UF_OPAQUE` 0x00000008: Saraka haionyeshi yaliyomo kwenye union.
- `UF_COMPRESSED` 0x00000020: Faili imebanwa (kwenye baadhi ya file-systems).
- `UF_TRACKED` 0x00000040: Hakuna arifa za ufutaji au ubadilishaji wa majina kwa faili zilizo na flag hii.
- `UF_DATAVAULT` 0x00000080: Entitlement inahitajika ili kusoma na kuandika.
- `UF_HIDDEN` 0x00008000: Dokezo kwamba kipengee hiki hakipaswi kuonyeshwa kwenye GUI.
- `SF_SUPPORTED` 0x009f0000: Kinyago cha flags zinazoungwa mkono na superuser.
- `SF_SETTABLE` 0x3fff0000: Kinyago cha flags zinazoweza kubadilishwa na superuser.
- `SF_SYNTHETIC` 0xc0000000: Kinyago cha flags synthetic za mfumo za kusoma pekee.
- `SF_ARCHIVED` 0x00010000: Faili imehifadhiwa kwenye archive.
- `SF_IMMUTABLE` 0x00020000: Faili haiwezi kubadilishwa.
- `SF_APPEND` 0x00040000: Maandishi yanaweza kuongezwa tu kwenye faili.
- `SF_RESTRICTED` 0x00080000: Entitlement inahitajika ili kuandika.
- `SF_NOUNLINK` 0x00100000: Kipengee hakiwezi kuondolewa, kupewa jina jipya, au kuwekwa mount.
- `SF_FIRMLINK` 0x00800000: Faili ni firmlink.
- `SF_DATALESS` 0x40000000: Faili ni object isiyo na data.

### **File ACLs**

File **ACLs** huwa na **ACE** (Access Control Entries) ambapo **ruhusa za kina zaidi** zinaweza kupewa watumiaji tofauti.

Inawezekana kuipa **saraka** ruhusa hizi: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Kwa **faili**: `read`, `write`, `append`, na `execute`.

Faili ikiwa na ACLs, utaona **alama ya "+" unapo orodhesha ruhusa kama ilivyo hapa**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

Unaweza **kusoma ACLs** za faili kwa kutumia:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

Unaweza kupata **faili zote zenye ACL** kwa kutumia amri ifuatayo (hii ni polepole sana):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Sifa Zilizopanuliwa

Sifa zilizopanuliwa ni thamani za metadata zenye majina, zilizohifadhiwa kando na sifa za kawaida za faili. Ziorodheshe kwa `ls -l@` na uzikague au uzirekebishe kwa `xattr`. <sup>[[5]](#references)</sup> Baadhi ya sifa zilizopanuliwa za kawaida ni:

- `com.apple.resourceFork`: Utangamano wa resource fork. Pia huonekana kama `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadata ya macOS Gatekeeper quarantine
- `metadata:*`: Metadata ya macOS, kama vile `_backup_excludeItem` au `kMD*`
- `com.apple.lastuseddate` (#PS): Tarehe ya mwisho faili ilipotumiwa
- `com.apple.FinderInfo`: Taarifa za macOS Finder, kama vile lebo za rangi
- `com.apple.TextEncoding`: Hubainisha usimbaji wa maandishi wa faili za maandishi za ASCII
- `com.apple.logd.metadata`: Hutumiwa na logd kwenye faili zilizo katika `/var/db/diagnostics`
- `com.apple.genstore.*`: Hifadhi ya vizazi (`/.DocumentRevisions-V100` katika mzizi wa mfumo wa faili)
- `com.apple.rootless`: Metadata ya macOS inayohusishwa na System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Alama za logd za vipindi vya kuwasha mfumo zenye UUID ya kipekee
- `com.apple.decmpfs`: Metadata ya macOS ya mbano wa faili usioonekana
- `com.apple.cprotect`: \*OS: Data ya usimbaji fiche kwa kila faili (III/11)
- `com.apple.installd.*`: \*OS: Metadata inayotumiwa na installd, k.m., `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks hutoa mkondo mbadala wa data kwenye macOS. Maudhui yanaweza kuhifadhiwa katika sifa iliyopanuliwa ya `com.apple.ResourceFork` na kufikiwa kupitia `file/..namedfork/rsrc`.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

Unaweza **kupata faili zote zilizo na sifa hii iliyopanuliwa** kwa kutumia:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

Sifa iliyopanuliwa `com.apple.decmpfs` huhifadhi metadata ya compression ya uwazi; haionyeshi usimbaji fiche. Kulingana na umbizo la compression, data iliyobanwa inaweza kuhifadhiwa kwenye sifa au kwenye resource fork, na hufunguliwa kiotomatiki inaposomwa.

Bendera `UF_COMPRESSED` huonekana kama `compressed` katika `ls -lO`. Usiiondoe mwenyewe: kufanya hivyo kunaweza kusababisha mfumo kutafsiri vibaya muundo wa data iliyobanwa.

Amri ya kuondoa bendera imeonyeshwa hapa kwa sababu ni muhimu wakati wa ukaguzi wa forensics, lakini kuiendesha dhidi ya faili iliyobanwa kunaweza kuifanya faili hiyo ionekane tupu au isiweze kufikiwa hadi metadata yake itengenezwe:

```bash
chflags nocompressed /path/to/file
```

Huduma iliyojengewa ndani ya `/usr/bin/afscexpand` inaweza kulazimisha upanuzi wa faili zilizobanwa bila kuonekana. Huduma tofauti ya wahusika wengine, `afsctool`, inaweza pia kukagua au kufungua faili zilizobanwa kwa mfumo wa faili wa Apple, lakini haipaswi kuchanganywa na amri iliyojengewa ndani. <sup>[[8]](#references)</sup>


### Maeneo ya kuvutia ya usanidi (macOS)

| Njia / Eneo | Kusudi / Inachosanidi | Usalama / Uwezekano wa Mashambulizi |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Huhifadhi faili za plist za feature-flag za Apple zinazodhibiti tabia za hiari au za majaribio katika system daemons / frameworks | Ikiwa mshambuliaji anaweza kukwepa SIP au kupata privileges, kuzichezea kunaweza kuwezesha njia za msimbo zilizofichwa au kuzima safeguards |
| `/System/Library/CoreServices/systemVersion.plist` | Huhifadhi metadata ya toleo la macOS (ProductVersion, BuildVersion) inayotumiwa na apps / installers kuamua tabia | Kuibadilisha kunaweza kuzihadaa apps au installers kukubali matoleo ya OS yasiyoungwa mkono au kufungua vipengele |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferences za app / mfumo mzima | Ikiwa zinaweza kuandikwa, washambuliaji wanaweza kuingiza mipangilio ya kuelekeza tabia ya app, kuzima protections, au kusababisha usanidi usio sahihi |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Ufafanuzi wa plist wa daemons na agents za mandharinyuma | Kuingiza au kuchezea plist (ikiwa ruhusa zinaruhusu) huwezesha persistence au privilege escalations |
| `/etc/hosts` | Mipangilio ya hostname ↔ IP inayotumiwa na system DNS resolver | Kuelekeza upya majina ya domain, kunasa trafiki, au kuiga huduma zilizo chini ya udhibiti wa ndani |
| `/etc/sudoers` | Hufafanua ni nani anayeweza kutekeleza amri kwa `sudo` na kwa masharti gani | Faili ya sudoers iliyoharibika inaweza kumpa root au privileges zisizofaa mshambuliaji |
| `/private/var/db/dslocal/nodes/Default/users/` | Faili za plist zinazofafanua akaunti za watumiaji wa ndani | Kuzichezea huruhusu kuunda au kurekebisha akaunti za watumiaji, password hashes, au metadata ya watumiaji |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Kusakinisha au kurekebisha kexts kunaweza kusababisha udhibiti wa kiwango cha kernel; SIP / signature policies huzilinda sana |
| `/private/var/db/SystemPolicyConfiguration/` | Huhifadhi usanidi wa utekelezaji wa system policy (kwa mfano, Gatekeeper, notarization) | Kuzichezea kunaweza kuruhusu kukwepa ukaguzi wa policy au sheria za uaminifu |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binaries saidizi za SSH na faili za usanidi | Usanidi usio sahihi husababisha usalama dhaifu wa SSH, ufikiaji usioidhinishwa, au algorithms zisizo salama |
| `/System/Library/Sandbox/Profiles` | System sandbox profiles (SBPL) zinazotumiwa kuzuia vitendo vya process | Kubadilisha au kurekebisha profiles kunaweza kufungua njia za kutoroka sandbox au kudhoofisha udhibiti |

> **Kumbuka**: Nyingi ya njia hizi ziko ndani ya saraka zinazolindwa na SIP (kwa mfano, `/System`) na zimezuiwa kuandikwa isipokuwa SIP izimwe au ikwepwe.  


## Universal Binaries na Muundo wa Mach-O

Mach-O ndiyo muundo asilia wa executable kwenye macOS. Universal binary, au fat binary, hufunga slices nyingi za Mach-O za usanifu tofauti ndani ya faili moja; ukurasa maalum unaeleza miundo yote miwili:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Hatari ya Faili na Metadata ya Handler

LaunchServices, file quarantine, na Gatekeeper kwa pamoja huathiri jinsi macOS inavyoshughulikia faili zilizopakuliwa na kuchagua apps kwa extensions na URL schemes. Databases na faili zao za ndani za rasilimali hubadilika kati ya matoleo; tumia kurasa maalum badala ya kuichukulia njia ya faragha ya CoreTypes kama kiolesura thabiti cha policy:

Katika matoleo yanayoonyesha metadata ya hatari ya CoreTypes ya zamani chini ya `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, kategoria zinazopatikana mara nyingi ni:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: Maudhui yanayochukuliwa kuwa salama vya kutosha kufunguliwa kiotomatiki chini ya policy ya app husika.
- **`LSRiskCategoryNeutral`**: Maudhui ambayo kwa kawaida hayasababishi onyo na hayafunguliwi kiotomatiki.
- **`LSRiskCategoryUnsafeExecutable`**: Maudhui ya executable ambayo mtumiaji anapaswa kuonywa kuhusu app.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Vifurushi kama archives vinavyoweza kuwa na maudhui ya executable na vinavyohitaji ukaguzi zaidi.

Haya ni maelezo ya utekelezaji, si API thabiti ya public policy; thibitisha metadata halisi na tabia ya Safari/Gatekeeper kwenye toleo la macOS linalojaribiwa.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Faili za log

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Ina taarifa kuhusu faili zilizopakuliwa, kama URL ya mahali zilipopakuliwa.
- **Unified log**: Katika matoleo ya sasa ya macOS, ulizia matukio ya mfumo na app kwa `log show` na `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** na **`/private/var/log/asl/*.asl`**: Mabaki ya mfumo wa zamani wa logging ambayo huenda bado yana umuhimu kwenye mifumo ya zamani. Katika matoleo hayo, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` husanidi `syslogd`; `launchctl list | grep com.apple.syslogd` inaweza kusaidia kubaini kama huduma imepakiwa.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Huhifadhi faili na apps zilizofikiwa hivi karibuni kupitia "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Njia ya zamani ya preferences inayohusishwa na login items; matoleo ya kisasa ya macOS hutumia mifumo mingine pia.
- **`$HOME/Library/Logs/DiskUtility.log`**: Log ya zamani ya Disk Utility ambayo inaweza kuwa na taarifa kuhusu drives, ikiwemo vifaa vya USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data kuhusu wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Data ya zamani ya launchd overrides.



## References

- [1] [Apple - Mwongozo wa Kuprogramu Mfumo wa Faili](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Mwongozo wa Kuprogramu Bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - Muhtasari wa dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Mwongozo wa Kuprogramu Mfumo wa Faili: Usalama wa Mfumo wa Faili wa macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - Ukurasa wa mwongozo wa macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - Ukurasa wa mwongozo wa macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - Ukurasa wa mwongozo wa macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums - Kufungua Apple Archives](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Usalama wa Shell Script: flags maalum za ruhusa za faili](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Kazi za Code Signing: vifurushi vya installer](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
