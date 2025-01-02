# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper** ni kipengele cha usalama kilichotengenezwa kwa mifumo ya uendeshaji ya Mac, kilichoundwa kuhakikisha kwamba watumiaji **wanatumia tu programu zinazotegemewa** kwenye mifumo yao. Inafanya kazi kwa **kuhakiki programu** ambayo mtumiaji anapakua na kujaribu kufungua kutoka **vyanzo vya nje ya App Store**, kama vile programu, plug-in, au kifurushi cha installer.

Mekaniki kuu ya Gatekeeper inategemea **mchakato wa uthibitisho**. Inakagua ikiwa programu iliyopakuliwa **imewekwa saini na mendelezi anayejulikana**, kuhakikisha uhalali wa programu hiyo. Zaidi ya hayo, inathibitisha ikiwa programu hiyo **imeandikishwa na Apple**, ikithibitisha kwamba haina maudhui mabaya yanayojulikana na haijabadilishwa baada ya kuandikishwa.

Zaidi, Gatekeeper inaimarisha udhibiti wa mtumiaji na usalama kwa **kuwataka watumiaji kuidhinisha ufunguzi** wa programu iliyopakuliwa kwa mara ya kwanza. Ulinzi huu husaidia kuzuia watumiaji kuendesha kwa bahati mbaya msimbo wa utendaji ambao unaweza kuwa na madhara ambao wanaweza kuwa wamechukulia kuwa faili ya data isiyo na madhara.

### Application Signatures

Saini za programu, pia zinajulikana kama saini za msimbo, ni sehemu muhimu ya miundombinu ya usalama ya Apple. Zinatumika **kuhakiki utambulisho wa mwandishi wa programu** (mendelezi) na kuhakikisha kwamba msimbo haujabadilishwa tangu iliposainiwa mwisho.

Hivi ndivyo inavyofanya kazi:

1. **Kusaini Programu:** Wakati mendelezi yuko tayari kusambaza programu yao, wanapiga **saini ya programu kwa kutumia funguo ya faragha**. Funguo hii ya faragha inahusishwa na **cheti ambacho Apple inatoa kwa mendelezi** wanapojiandikisha katika Programu ya Mendelezi ya Apple. Mchakato wa kusaini unajumuisha kuunda hash ya kijiografia ya sehemu zote za programu na kuificha hash hii kwa funguo ya faragha ya mendelezi.
2. **Kusambaza Programu:** Programu iliyosainiwa kisha inasambazwa kwa watumiaji pamoja na cheti cha mendelezi, ambacho kinafunguo ya umma inayohusiana.
3. **Kuhakiki Programu:** Wakati mtumiaji anapakua na kujaribu kuendesha programu, mfumo wa uendeshaji wa Mac unatumia funguo ya umma kutoka kwa cheti cha mendelezi kufichua hash. Kisha inarejesha hash kulingana na hali ya sasa ya programu na kulinganisha hii na hash iliyofichuliwa. Ikiwa zinakubaliana, inamaanisha **programu hiyo haijabadilishwa** tangu mendelezi aliposaini, na mfumo unaruhusu programu hiyo kuendesha.

Saini za programu ni sehemu muhimu ya teknolojia ya Gatekeeper ya Apple. Wakati mtumiaji anajaribu **kufungua programu iliyopakuliwa kutoka mtandao**, Gatekeeper inathibitisha saini ya programu. Ikiwa imesainiwa kwa cheti kilichotolewa na Apple kwa mendelezi anayejulikana na msimbo haujabadilishwa, Gatekeeper inaruhusu programu hiyo kuendesha. Vinginevyo, inazuia programu hiyo na kumjulisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper pia inakagua ikiwa programu hiyo imeandikishwa** na Apple, ikiongeza safu ya ziada ya usalama. Mchakato wa kuandikishwa unakagua programu hiyo kwa masuala ya usalama yanayojulikana na msimbo mbaya, na ikiwa ukaguzi huu unakubalika, Apple inaongeza tiketi kwa programu ambayo Gatekeeper inaweza kuithibitisha.

#### Check Signatures

Wakati wa kuangalia **kielelezo cha malware** unapaswa kila wakati **kuangalia saini** ya binary kwani **mendelezi** aliyesaini inaweza kuwa tayari **ina uhusiano** na **malware.**
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarization

Mchakato wa notarization wa Apple unatumika kama kinga ya ziada kulinda watumiaji kutokana na programu zinazoweza kuwa na madhara. Unahusisha **mwandishi kuwasilisha programu yao kwa ajili ya uchunguzi** na **Huduma ya Notary ya Apple**, ambayo haipaswi kuchanganywa na Mapitio ya Programu. Huduma hii ni **mfumo wa kiotomatiki** unaochunguza programu iliyowasilishwa kwa uwepo wa **maudhui mabaya** na masuala yoyote yanayoweza kutokea na saini ya msimbo.

Ikiwa programu hiyo **inasimama** ukaguzi huu bila kuibua wasiwasi wowote, Huduma ya Notary inaunda tiketi ya notarization. Mwandishi anahitajika **kuunganisha tiketi hii na programu yao**, mchakato unaojulikana kama 'stapling.' Zaidi ya hayo, tiketi ya notarization pia inachapishwa mtandaoni ambapo Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuipata.

Wakati wa usakinishaji au utekelezaji wa kwanza wa programu na mtumiaji, uwepo wa tiketi ya notarization - iwe imeunganishwa na executable au kupatikana mtandaoni - **inaarifu Gatekeeper kwamba programu hiyo imetolewa na Apple**. Kama matokeo, Gatekeeper inaonyesha ujumbe wa maelezo katika kidirisha cha uzinduzi wa awali, ikionyesha kwamba programu hiyo imefanyiwa ukaguzi wa maudhui mabaya na Apple. Mchakato huu hivyo huongeza ujasiri wa mtumiaji katika usalama wa programu wanazosakinisha au kuendesha kwenye mifumo yao.

### spctl & syspolicyd

> [!CAUTION]
> Kumbuka kwamba kuanzia toleo la Sequoia, **`spctl`** haiwaruhusu kubadilisha usanidi wa Gatekeeper tena.

**`spctl`** ni zana ya CLI ya kuorodhesha na kuingiliana na Gatekeeper (pamoja na daemon ya `syspolicyd` kupitia ujumbe wa XPC). Kwa mfano, inawezekana kuona **hali** ya GateKeeper kwa:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Kumbuka kwamba ukaguzi wa saini wa GateKeeper unafanywa tu kwa **faili zenye sifa ya Quarantine**, si kwa kila faili.

GateKeeper itakagua ikiwa kulingana na **mapendeleo & saini** binary inaweza kutekelezwa:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ndicho daemon kuu kinachohusika na kutekeleza Gatekeeper. Inashikilia hifadhidata iliyoko katika `/var/db/SystemPolicy` na inawezekana kupata msimbo wa kusaidia [hifadhidata hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) na [templat ya SQL hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Kumbuka kwamba hifadhidata haijakabiliwa na SIP na inaweza kuandikwa na root na hifadhidata `/var/db/.SystemPolicy-default` inatumika kama nakala ya awali endapo nyingine itaharibika.

Zaidi ya hayo, vifurushi **`/var/db/gke.bundle`** na **`/var/db/gkopaque.bundle`** vina faili zenye sheria ambazo zinaingizwa katika hifadhidata. Unaweza kuangalia hifadhidata hii kama root kwa:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** pia inatoa seva ya XPC yenye operesheni tofauti kama `assess`, `update`, `record` na `cancel` ambazo pia zinaweza kufikiwa kwa kutumia **`Security.framework`'s `SecAssessment*`** APIs na **`xpctl`** kwa kweli inazungumza na **`syspolicyd`** kupitia XPC.

Tazama jinsi sheria ya kwanza ilivyomalizika kwa "**App Store**" na ya pili kwa "**Developer ID**" na kwamba katika picha iliyopita ilikuwa **imewezeshwa kutekeleza programu kutoka kwa App Store na waendelezaji waliotambulika**.\
Ikiwa **utabadilisha** mipangilio hiyo kuwa App Store, sheria za "**Notarized Developer ID" zitaondoka**.

Pia kuna maelfu ya sheria za **aina GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Hizi ni hash ambazo zinatoka:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Au unaweza kuorodhesha taarifa za awali kwa:
```bash
sudo spctl --list
```
Chaguzi **`--master-disable`** na **`--global-disable`** za **`spctl`** zita **ondoa** kabisa ukaguzi huu wa saini:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wakati umewezeshwa kabisa, chaguo jipya litajitokeza:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Inawezekana **kuangalia kama App itaruhusiwa na GateKeeper** kwa:
```bash
spctl --assess -v /Applications/App.app
```
Inawezekana kuongeza sheria mpya katika GateKeeper kuruhusu utekelezaji wa programu fulani kwa:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
Kuhusu **kernel extensions**, folda `/var/db/SystemPolicyConfiguration` ina faili zenye orodha ya kexts zinazoruhusiwa kupakiwa. Aidha, `spctl` ina haki `com.apple.private.iokit.nvram-csr` kwa sababu ina uwezo wa kuongeza kernel extensions mpya zilizothibitishwa ambazo zinahitaji kuhifadhiwa pia katika NVRAM katika ufunguo `kext-allowed-teams`.

### Faili za Kuzuia

Pale **kupakua** programu au faili, programu maalum za macOS kama vile vivinjari vya wavuti au wateja wa barua pepe **huongeza sifa ya faili iliyopanuliwa**, inayojulikana kwa jina la "**quarantine flag**," kwa faili iliyopakuliwa. Sifa hii inafanya kazi kama kipimo cha usalama ili **kuashiria faili** kama inatoka kwenye chanzo kisichotegemewa (mtandao), na huenda ikabeba hatari. Hata hivyo, si programu zote huongeza sifa hii, kwa mfano, programu za kawaida za mteja wa BitTorrent mara nyingi hupita mchakato huu.

**Kuwepo kwa quarantine flag kunaashiria kipengele cha usalama cha Gatekeeper cha macOS wakati mtumiaji anajaribu kutekeleza faili hiyo**.

Katika hali ambapo **quarantine flag haipo** (kama ilivyo kwa faili zilizopakuliwa kupitia baadhi ya wateja wa BitTorrent), **ukaguzi wa Gatekeeper huenda usifanyike**. Hivyo, watumiaji wanapaswa kuwa waangalifu wanapofungua faili zilizopakuliwa kutoka vyanzo visivyo salama au visivyojulikana.

> [!NOTE] > **Kuangalia** **halali** ya saini za msimbo ni mchakato **unaohitaji rasilimali nyingi** ambao unajumuisha kuunda **hashes** za kificho za msimbo na rasilimali zake zote zilizofungwa. Aidha, kuangalia halali ya cheti kunahusisha kufanya **ukaguzi mtandaoni** kwa seva za Apple ili kuona kama kimeondolewa baada ya kutolewa. Kwa sababu hizi, ukaguzi kamili wa saini ya msimbo na notarization ni **mgumu kufanywa kila wakati programu inapoanzishwa**.
>
> Kwa hivyo, ukaguzi huu **ufanywa tu wakati wa kutekeleza programu zenye sifa ya kuzuia.**

> [!WARNING]
> Sifa hii lazima iwe **imewekwa na programu inayounda/kupakua** faili.
>
> Hata hivyo, faili ambazo zimewekwa kwenye sandbox zitakuwa na sifa hii imewekwa kwa kila faili wanayounda. Na programu zisizo na sandbox zinaweza kuziweka zenyewe, au kuashiria ufunguo [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) katika **Info.plist** ambayo itafanya mfumo kuweka sifa ya `com.apple.quarantine` kwenye faili zilizoundwa,

Aidha, faili zote zinazoundwa na mchakato unaoitwa **`qtn_proc_apply_to_self`** zimewekwa kwenye kuzuia. Au API **`qtn_file_apply_to_path`** inaongeza sifa ya kuzuia kwenye njia maalum ya faili.

Inawezekana **kuangalia hali yake na kuwezesha/kuzima** (inahitaji root) kwa:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Unaweza pia **kupata kama faili ina sifa ya kuzuia ya muda mrefu** kwa kutumia:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Angalia **thamani** ya **sifa** za **kupanuliwa** na upate programu ambayo iliandika sifa ya karantini na:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Kwa kweli mchakato "unaweza kuweka bendera za karantini kwa faili zinazoundwa" (nimejaribu tayari kutumia bendera ya USER_APPROVED katika faili iliyoundwa lakini haitatumika):

<details>

<summary>Kanuni ya Chanzo inatumia bendera za karantini</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

Na **ondoa** sifa hiyo kwa:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Na pata faili zote zilizowekwa karantini kwa:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Taarifa za karantini pia zinahifadhiwa katika hifadhidata kuu inayosimamiwa na LaunchServices katika **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** ambayo inaruhusu GUI kupata data kuhusu asili za faili. Zaidi ya hayo, hii inaweza kubadilishwa na programu ambazo zinaweza kuwa na nia ya kuficha asili zake. Aidha, hii inaweza kufanywa kutoka kwa LaunchServices APIS.

#### **libquarantine.dylb**

Maktaba hii inatoa kazi kadhaa ambazo zinaruhusu kubadilisha maeneo ya sifa za ziada.

APIs za `qtn_file_*` zinahusiana na sera za karantini za faili, APIs za `qtn_proc_*` zinatumika kwa michakato (faili zilizoundwa na mchakato). Kazi zisizotolewa za `__qtn_syscall_quarantine*` ndizo zinazotumia sera ambazo zinaita `mac_syscall` na "Quarantine" kama hoja ya kwanza ambayo inatuma maombi kwa `Quarantine.kext`.

#### **Quarantine.kext**

Kipanuzi cha kernel kinapatikana tu kupitia **cache ya kernel kwenye mfumo**; hata hivyo, unaweza kupakua **Kernel Debug Kit kutoka** [**https://developer.apple.com/**](https://developer.apple.com/), ambayo itakuwa na toleo lililosimbwa la kipanuzi.

Kext hii itashughulikia kupitia MACF simu kadhaa ili kukamata matukio yote ya mzunguko wa maisha ya faili: Uundaji, ufunguzi, upatanishi, kuunganisha... hata `setxattr` ili kuzuia kuweka sifa ya ziada ya `com.apple.quarantine`.

Pia inatumia MIB kadhaa:

- `security.mac.qtn.sandbox_enforce`: Lazimisha karantini pamoja na Sandbox
- `security.mac.qtn.user_approved_exec`: Michakato ya karantini inaweza tu kutekeleza faili zilizothibitishwa

### XProtect

XProtect ni kipengele cha ndani cha **anti-malware** katika macOS. XProtect **inaangalia programu yoyote inapozinduliwa au kubadilishwa kwa mara ya kwanza dhidi ya hifadhidata yake** ya malware inayojulikana na aina za faili zisizo salama. Unapopakua faili kupitia programu fulani, kama Safari, Mail, au Messages, XProtect kwa otomatiki inachunguza faili hiyo. Ikiwa inalingana na malware yoyote inayojulikana katika hifadhidata yake, XProtect itazuia **faili hiyo isifanye kazi** na kukujulisha kuhusu tishio hilo.

Hifadhidata ya XProtect **inasasishwa mara kwa mara** na Apple kwa maelezo mapya ya malware, na sasisho haya hupakuliwa na kufungwa kiotomatiki kwenye Mac yako. Hii inahakikisha kwamba XProtect iko daima na habari za hivi punde kuhusu vitisho vinavyojulikana.

Hata hivyo, inafaa kutambua kwamba **XProtect si suluhisho kamili la antivirus**. Inaangalia tu orodha maalum ya vitisho vinavyojulikana na haisahihishi skanning ya upatikanaji kama programu nyingi za antivirus.

Unaweza kupata taarifa kuhusu sasisho la hivi punde la XProtect ukikimbia:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect iko kwenye eneo lililolindwa na SIP katika **/Library/Apple/System/Library/CoreServices/XProtect.bundle** na ndani ya bundle unaweza kupata taarifa ambazo XProtect inatumia:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Inaruhusu msimbo wenye cdhashes hizo kutumia haki za zamani.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodha ya plugins na nyongeza ambazo haziruhusiwi kupakia kupitia BundleID na TeamID au kuashiria toleo la chini.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Sheria za Yara kugundua malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Hifadhidata ya SQLite3 yenye hashes za programu zilizozuiwa na TeamIDs.

Kumbuka kwamba kuna App nyingine katika **`/Library/Apple/System/Library/CoreServices/XProtect.app`** inayohusiana na XProtect ambayo haijahusishwa na mchakato wa Gatekeeper.

### Si Gatekeeper

> [!CAUTION]
> Kumbuka kwamba Gatekeeper **haiendeshwi kila wakati** unapotekeleza programu, ni _**AppleMobileFileIntegrity**_ (AMFI) tu itakay **thibitisha saini za msimbo wa kutekeleza** unapotekeleza app ambayo tayari imeendeshwa na kuthibitishwa na Gatekeeper.

Kwa hivyo, hapo awali ilikuwa inawezekana kutekeleza app ili kuikatia cache na Gatekeeper, kisha **kubadilisha faili zisizotekelezwa za programu** (kama Electron asar au faili za NIB) na ikiwa hakuna kinga nyingine zilizopo, programu hiyo ilitekelezwa na **nyongeza mbaya**.

Hata hivyo, sasa hii haiwezekani kwa sababu macOS **inazuia kubadilisha faili** ndani ya bundles za programu. Hivyo, ukijaribu shambulio la [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), utaona kwamba si tena inawezekana kulitumia kwa sababu baada ya kutekeleza app ili kuikatia cache na Gatekeeper, huwezi kubadilisha bundle. Na ikiwa badala yake unabadilisha jina la saraka ya Contents kuwa NotCon (kama ilivyoonyeshwa katika exploit), kisha kutekeleza binary kuu ya app ili kuikatia cache na Gatekeeper, itasababisha kosa na haitatekelezwa.

## Mipango ya Kuepuka Gatekeeper

Njia yoyote ya kuepuka Gatekeeper (kufanikiwa kumfanya mtumiaji apakue kitu na kukitekeleza wakati Gatekeeper inapaswa kukataa) inachukuliwa kuwa udhaifu katika macOS. Hizi ni baadhi ya CVEs zilizotolewa kwa mbinu ambazo ziliruhusu kuepuka Gatekeeper katika siku za nyuma:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilionekana kwamba ikiwa **Archive Utility** inatumika kwa uchimbaji, faili zenye **njia zinazozidi herufi 886** hazipati sifa ya ziada ya com.apple.quarantine. Hali hii bila kukusudia inaruhusu faili hizo **kuepuka ukaguzi wa usalama wa Gatekeeper**.

Angalia [**ripoti ya asili**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa maelezo zaidi.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wakati programu inaundwa kwa **Automator**, taarifa kuhusu kile inachohitaji kutekeleza iko ndani ya `application.app/Contents/document.wflow` si katika executable. Executable ni binary ya jumla ya Automator inayoitwa **Automator Application Stub**.

Kwa hivyo, unaweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **kuashiria kwa kiungo cha alama kwa Automator Application Stub nyingine ndani ya mfumo** na itatekeleza kilichomo ndani ya `document.wflow` (script yako) **bila kuamsha Gatekeeper** kwa sababu executable halisi haina xattr ya karantini.

Mfano wa eneo linalotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Angalia [**ripoti ya asili**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa maelezo zaidi.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika kuepuka hii, faili ya zip iliundwa na programu ikianza kubana kutoka `application.app/Contents` badala ya `application.app`. Kwa hivyo, **sifa ya karantini** ilitumika kwa **faili zote kutoka `application.app/Contents`** lakini **siyo kwa `application.app`**, ambayo ilikuwa inakaguliwa na Gatekeeper, hivyo Gatekeeper iliepukwa kwa sababu wakati `application.app` iliposhughulikiwa **haikuwa na sifa ya karantini.**
```bash
zip -r test.app/Contents test.zip
```
Angalia [**ripoti asilia**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa maelezo zaidi.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama vipengele ni tofauti, matumizi ya udhaifu huu ni sawa sana na ule wa awali. Katika kesi hii, tutaunda Archive ya Apple kutoka **`application.app/Contents`** hivyo **`application.app` haitapata sifa ya karantini** wakati inakandamizwa na **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Angalia [**ripoti asilia**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kwa maelezo zaidi.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** inaweza kutumika kuzuia mtu yeyote kuandika sifa katika faili:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Zaidi ya hayo, muundo wa faili wa **AppleDouble** unakopi faili ikiwa ni pamoja na ACE zake.

Katika [**kanuni ya chanzo**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba uwakilishi wa maandiko wa ACL ulihifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL katika faili lililoshinikizwa. Hivyo, ikiwa umeweka programu katika faili la zip kwa muundo wa faili wa **AppleDouble** ukiwa na ACL inayozuia xattrs nyingine kuandikwa ndani yake... xattr ya karantini haikuwekwa katika programu:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Angalia [**ripoti asilia**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.

Kumbuka kwamba hii inaweza pia kutumika kwa AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Iligundulika kwamba **Google Chrome haikuwa ikipanga sifa ya karantini** kwa faili zilizopakuliwa kwa sababu ya matatizo fulani ya ndani ya macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Mifumo ya faili ya AppleDouble huhifadhi sifa za faili katika faili tofauti inayaanza na `._`, hii husaidia kunakili sifa za faili **katika mashine za macOS**. Hata hivyo, ilionekana kwamba baada ya kufungua faili ya AppleDouble, faili inayaanza na `._` **haikupatiwa sifa ya karantini**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Kuweza kuunda faili ambayo haitakuwa na sifa ya karantini, ilikuwa **inawezekana kupita Gatekeeper.** Njia ilikuwa **kuunda faili ya DMG programu** kwa kutumia kanuni ya jina la AppleDouble (anza nayo `._`) na kuunda **faili inayoonekana kama kiungo cha sym kwa faili hii iliyofichwa** bila sifa ya karantini.\
Wakati **faili ya dmg inatekelezwa**, kwa kuwa haina sifa ya karantini itapita **Gatekeeper.**
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### uchg (kutoka katika [mazungumzo](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Unda directory yenye programu.
- Ongeza uchg kwenye programu.
- Fanya programu kuwa faili ya tar.gz.
- Tuma faili ya tar.gz kwa mwathirika.
- Mwathirika anafungua faili ya tar.gz na kuendesha programu.
- Gatekeeper haitakagua programu.

### Zuia Quarantine xattr

Katika kifurushi cha ".app" ikiwa xattr ya quarantine haijongezwa, wakati wa kuendesha **Gatekeeper haitasababisha**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
