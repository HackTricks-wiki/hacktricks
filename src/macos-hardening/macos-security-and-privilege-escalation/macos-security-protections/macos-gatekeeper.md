# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ni kipengele cha usalama kilichotengenezwa kwa ajili ya mifumo ya uendeshaji ya Mac, kilichoundwa kuhakikisha kuwa watumiaji **wanaendesha software inayoaminika pekee** kwenye mifumo yao. Hufanya kazi kwa **kuthibitisha software** ambayo mtumiaji anapakua na kujaribu kuifungua kutoka **vyanzo vilivyo nje ya App Store**, kama vile app, plug-in au kifurushi cha installer.

Utaratibu mkuu wa Gatekeeper unategemea mchakato wake wa **uthibitishaji**. Hukagua ikiwa software iliyopakuliwa **imesainiwa na developer anayetambuliwa**, kuhakikisha uhalali wa software hiyo. Zaidi ya hayo, huthibitisha ikiwa software hiyo **imefanyiwa notarisation na Apple**, ikithibitisha kuwa haina maudhui hasidi yanayojulikana na haijabadilishwa baada ya notarisation.

Zaidi ya hayo, Gatekeeper huimarisha udhibiti na usalama wa mtumiaji kwa **kuwauliza watumiaji waidhinishe ufunguaji** wa software iliyopakuliwa kwa mara ya kwanza. Ulinzi huu husaidia kuzuia watumiaji kuendesha bila kukusudia code ya executable inayoweza kuwa hatari, ambayo huenda waliidhani kimakosa kuwa ni data file isiyo na madhara.

### Saini za Application

Saini za application, pia zinazojulikana kama code signatures, ni sehemu muhimu ya miundombinu ya usalama ya Apple. Hutumika **kuthibitisha utambulisho wa mwandishi wa software** (developer) na kuhakikisha kuwa code haijabadilishwa tangu iliposainiwa mara ya mwisho.

Hivi ndivyo inavyofanya kazi:

1. **Kusaini Application:** Developer anapokuwa tayari kusambaza application yake, **husaini application kwa kutumia private key**. Private key hii inahusishwa na **certificate ambayo Apple humpatia developer** anapojiandikisha katika Apple Developer Program. Mchakato wa kusaini unahusisha kuunda cryptographic hash ya sehemu zote za app na kusimba hash hiyo kwa kutumia private key ya developer.
2. **Kusambaza Application:** Application iliyosainiwa husambazwa kwa watumiaji pamoja na certificate ya developer, ambayo ina public key inayolingana.
3. **Kuthibitisha Application:** Mtumiaji anapopakua na kujaribu kuendesha application, mfumo wa uendeshaji wa Mac hutumia public key iliyo kwenye certificate ya developer kusimbua hash hiyo. Kisha huhesabu upya hash kulingana na hali ya sasa ya application na kuilinganisha na hash iliyosimbuliwa. Zikilingana, inamaanisha **application haijabadilishwa** tangu developer alipoisaini, na mfumo huruhusu application kuendeshwa.

Saini za application ni sehemu muhimu ya teknolojia ya Apple ya Gatekeeper. Mtumiaji anapojaribu **kufungua application iliyopakuliwa kutoka kwenye internet**, Gatekeeper huthibitisha saini ya application. Ikiwa imesainiwa kwa certificate iliyotolewa na Apple kwa developer anayejulikana na code haijabadilishwa, Gatekeeper huruhusu application kuendeshwa. Vinginevyo, huzuia application na kumjulisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper pia hukagua ikiwa application imefanyiwa notarisation** na Apple, na kuongeza safu ya ziada ya usalama. Mchakato wa notarisation hukagua application ili kubaini matatizo ya usalama yanayojulikana na code hasidi; ikiwa ukaguzi huu utafaulu, Apple huongeza ticket kwenye application ambayo Gatekeeper inaweza kuithibitisha.

#### Check Signatures

Unapokagua **malware sample**, unapaswa kila mara **kuangalia saini** ya binary kwa sababu **developer** aliyeisaini huenda tayari **anahusishwa** na **malware.**
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

Mchakato wa notarization wa Apple hutumika kama ulinzi wa ziada wa kuwalinda watumiaji dhidi ya software inayoweza kuwa hatari. Unahusisha **developer kuwasilisha application yao kwa uchunguzi** na **Apple's Notary Service**, ambayo haipaswi kuchanganywa na App Review. Huduma hii ni **mfumo wa kiotomatiki** unaochunguza software iliyowasilishwa ili kubaini uwepo wa **maudhui hasidi** na matatizo yoyote yanayoweza kuhusiana na code-signing.

Ikiwa software **itafaulu** ukaguzi huu bila kuibua wasiwasi wowote, Notary Service hutengeneza notarization ticket. Kisha developer anatakiwa **kuambatisha ticket hii kwenye software yao**, mchakato unaojulikana kama 'stapling.' Zaidi ya hayo, notarization ticket pia huchapishwa online, ambako Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuifikia.

Mtumiaji anaposakinisha au kutekeleza software hiyo kwa mara ya kwanza, kuwepo kwa notarization ticket - iwe imebandikwa kwenye executable au imepatikana online - **huijulisha Gatekeeper kwamba software imefanyiwa notarization na Apple**. Kwa hiyo, Gatekeeper huonyesha ujumbe unaoeleza katika dialog ya kwanza ya uzinduzi, ukionyesha kwamba software imekaguliwa na Apple ili kubaini maudhui hasidi. Mchakato huu huongeza imani ya mtumiaji katika usalama wa software anayoweka au kuendesha kwenye mifumo yake.

### spctl & syspolicyd

> [!CAUTION]
> Kumbuka kwamba kuanzia toleo la Sequoia, **`spctl`** hairuhusu tena kurekebisha usanidi wa Gatekeeper.

**`spctl`** ni zana ya CLI ya kuorodhesha na kuingiliana na Gatekeeper (kupitia daemon ya `syspolicyd` kwa kutumia ujumbe wa XPC). Kwa mfano, inawezekana kuona **hali** ya GateKeeper kwa:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Kumbuka kwamba ukaguzi wa saini wa GateKeeper hufanywa tu kwa **files zilizo na Quarantine attribute**, si kwa kila file.

GateKeeper itaangalia ikiwa, kulingana na **preferences na signature**, binary inaweza kutekelezwa:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ndiyo daemon kuu inayohusika na kutekeleza Gatekeeper. Inatunza database iliyo katika `/var/db/SystemPolicy`, na inawezekana kupata code ya kusaidia [database hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) na [SQL template hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Kumbuka kwamba database haizuiliwi na SIP na inaweza kuandikwa na root, na database `/var/db/.SystemPolicy-default` hutumika kama backup ya awali ikiwa nyingine itaharibika.

Zaidi ya hayo, bundles **`/var/db/gke.bundle`** na **`/var/db/gkopaque.bundle`** zina files zilizo na rules zinazoingizwa kwenye database. Unaweza kuangalia database hii ukiwa root kwa kutumia:
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
**`syspolicyd`** pia hufichua XPC server yenye operations tofauti kama `assess`, `update`, `record` na `cancel`, ambazo pia zinaweza kufikiwa kwa kutumia APIs za **`Security.framework`'s `SecAssessment*`**, na **`spctl`** kwa hakika huwasiliana na **`syspolicyd`** kupitia XPC.

Kumbuka jinsi rule ya kwanza ilivyomalizika kwa "**App Store**" na ya pili kwa "**Developer ID**", na kwamba katika image iliyotangulia ilikuwa **imewezeshwa kutekeleza apps kutoka App Store na developers waliotambuliwa**.\
Ukibadilisha setting hiyo kuwa App Store, rules za "**Notarized Developer ID" zitatoweka**.

Pia kuna maelfu ya rules za **type GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Hizi ni hashes kutoka:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Au unaweza kuorodhesha taarifa za awali kwa:
```bash
sudo spctl --list
```
Chaguo **`--master-disable`** na **`--global-disable`** za **`spctl`** zita **lemaza kabisa** ukaguzi huu wa signatures:
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
Inawezekana kuongeza sheria mpya katika GateKeeper ili kuruhusu utekelezaji wa apps fulani kwa kutumia:
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
Kuhusu **kernel extensions**, folda `/var/db/SystemPolicyConfiguration` ina faili zenye orodha za kexts zinazoruhusiwa kupakiwa. Isitoshe, `spctl` ina entitlement `com.apple.private.iokit.nvram-csr` kwa sababu inaweza kuongeza kernel extensions mpya zilizoidhinishwa awali, ambazo pia zinahitaji kuhifadhiwa kwenye NVRAM katika key ya `kext-allowed-teams`.

#### Kusimamia Gatekeeper kwenye macOS 15 (Sequoia) na matoleo ya baadaye

- Bypass ya muda mrefu ya Finder **Ctrl+Open / Right-click → Open** imeondolewa; users lazima waruhusu app iliyozuiwa waziwazi kupitia **System Settings → Privacy & Security → Open Anyway** baada ya dialog ya kwanza ya kuzuia.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` hazikubaliwi tena; `spctl` sasa kimsingi ni ya kusoma tu kwa assessment na usimamizi wa labels, huku utekelezaji wa policy ukisanidiwa kupitia UI au MDM.

Kuanzia macOS 15 Sequoia, end users hawawezi tena kubadilisha policy ya Gatekeeper kutoka `spctl`. Usimamizi hufanywa kupitia System Settings au kwa ku-deploy MDM configuration profile yenye payload ya `com.apple.systempolicy.control`. Mfano wa sehemu ya profile ya kuruhusu App Store na developers waliotambuliwa (lakini si "Anywhere"):

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

Baada ya **kupakua** application au faili, **applications** maalum za macOS kama vile web browsers au email clients **huambatisha extended file attribute**, inayojulikana kwa kawaida kama "**quarantine flag**," kwenye faili lililopakuliwa. Attribute hii hutumika kama hatua ya usalama ya **kuweka alama kwenye faili** kwamba limetoka kwenye chanzo kisichoaminika (internet), na huenda likawa na hatari. Hata hivyo, si applications zote huambatisha attribute hii; kwa mfano, software maarufu za BitTorrent client kwa kawaida hupita mchakato huu.

**Uwepo wa quarantine flag huashiria macOS's Gatekeeper security feature wakati mtumiaji anapojaribu kutekeleza faili**.

Iwapo **quarantine flag haipo** (kama ilivyo kwa mafaili yaliyopakuliwa kupitia baadhi ya BitTorrent clients), **checks za Gatekeeper huenda zisifanywe**. Kwa hiyo, watumiaji wanapaswa kuwa waangalifu wanapofungua mafaili yaliyopakuliwa kutoka kwenye vyanzo visivyo salama au visivyojulikana.

> [!NOTE] > **Kukagua** **uhalali** wa code signatures ni mchakato unaotumia **rasilimali nyingi**, unaojumuisha kutengeneza cryptographic **hashes** za code na resources zake zote zilizobundled. Zaidi ya hayo, kukagua uhalali wa certificate kunahusisha kufanya **online check** kwenye servers za Apple ili kuona ikiwa ime-revoked baada ya kutolewa. Kwa sababu hizi, full code signature na notarization check **si jambo la kiutendaji kufanywa kila mara app inapozinduliwa**.
>
> Kwa hiyo, checks hizi **hufanywa tu wakati wa kutekeleza apps zilizo na quarantined attribute.**

> [!WARNING]
> Attribute hii lazima **iwekwe na application inayounda/inayopakua** faili.
>
> Hata hivyo, mafaili yaliyo sandboxed yatakuwa na attribute hii ikiwa imewekwa kwenye kila faili linaloundwa nayo. Na apps zisizo sandboxed zinaweza kujiwekea yenyewe, au kubainisha key ya [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) kwenye **Info.plist**, jambo litakalofanya mfumo uweke extended attribute ya `com.apple.quarantine` kwenye mafaili yaliyoundwa,

Zaidi ya hayo, mafaili yote yaliyoundwa na process inayokiita **`qtn_proc_apply_to_self`** yanawekwa quarantine. Au API **`qtn_file_apply_to_path`** huongeza quarantine attribute kwenye file path iliyobainishwa.

Inawezekana **kukagua status yake na kuiwezesha/kui-disable** (root inahitajika) kwa kutumia:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Unaweza pia **kubaini ikiwa faili ina quarantine extended attribute** kwa:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Kagua **thamani** ya **extended** **attributes** na utambue app iliyoandika quarantine attr kwa:
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
Kwa kweli, process inaweza "kuweka quarantine flags kwenye files inazounda" (tayari nilijaribu kutumia flag ya USER_APPROVED kwenye file iliyoundwa, lakini haikutumika):

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

Na **ondoa** sifa hiyo kwa kutumia:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Na pata faili zote zilizowekwa karantini kwa kutumia:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Maelezo ya Quarantine pia huhifadhiwa katika database kuu inayosimamiwa na LaunchServices katika **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, ambayo huruhusu GUI kupata data kuhusu asili ya faili. Zaidi ya hayo, hii inaweza kuandikwa upya na applications ambazo zinaweza kuwa na nia ya kuficha asili yake. Pia, hili linaweza kufanywa kupitia LaunchServices APIs.

#### **libquarantine.dylib**

Library hii hu-export functions kadhaa zinazoruhusu kudhibiti fields za extended attributes.

`qtn_file_*` APIs hushughulikia sera za file quarantine, huku `qtn_proc_*` APIs zikitumika kwa processes (files zilizoundwa na process). Functions ambazo hazija-exportiwa za `__qtn_syscall_quarantine*` ndizo zinazotumia sera hizo; huita `mac_syscall` ikiwa na "Quarantine" kama argument ya kwanza, ambayo hutuma requests kwa `Quarantine.kext`.

#### **Quarantine.kext**

Kernel extension hii inapatikana tu kupitia **kernel cache kwenye mfumo**; hata hivyo, _unaweza kupakua **Kernel Debug Kit kutoka** [**https://developer.apple.com/**](https://developer.apple.com/), ambayo itakuwa na toleo la extension lenye symbols._

Kext hii hutumia MACF ku-hook calls kadhaa ili kunasa matukio yote ya mzunguko wa maisha wa faili: kuundwa, kufunguliwa, kubadilishwa jina, kuundwa kwa hard link... hata `setxattr`, ili kuizuia kuweka extended attribute ya `com.apple.quarantine`.

Pia hutumia MIBs kadhaa:

- `security.mac.qtn.sandbox_enforce`: L enforce quarantine pamoja na Sandbox
- `security.mac.qtn.user_approved_exec`: Procs zilizo Querantined zinaweza kutekeleza files zilizoidhinishwa pekee

#### Provenance xattr (Ventura na baadaye)

macOS 13 Ventura ilianzisha utaratibu tofauti wa provenance ambao hujazwa mara ya kwanza app iliyo quarantined inaporuhusiwa kuendeshwa.<sup>[[2]](#references)</sup> Artefacts mbili huundwa:

- `com.apple.provenance` xattr kwenye directory ya `.app` bundle (binary value yenye ukubwa usiobadilika inayojumuisha primary key na flags).
- Row katika table ya `provenance_tracking` ndani ya ExecPolicy database iliyoko `/var/db/SystemPolicyConfiguration/ExecPolicy/`, inayohifadhi cdhash ya app pamoja na metadata.

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

XProtect ni kipengele cha **anti-malware** kilichojengwa ndani ya macOS. XProtect **hukagua kila application inapozinduliwa kwa mara ya kwanza au kurekebishwa dhidi ya database yake** ya malware inayojulikana na aina za mafaili yasiyo salama. Unapopakua faili kupitia baadhi ya apps, kama vile Safari, Mail, au Messages, XProtect hukagua faili hiyo kiotomatiki. Ikiwa inalingana na malware yoyote inayojulikana kwenye database yake, XProtect **itazuia faili hiyo kuendeshwa** na kukuarifu kuhusu tishio hilo.

Database ya XProtect **husasishwa mara kwa mara** na Apple kwa kutumia ufafanuzi mpya wa malware, na masasisho haya hupakuliwa na kusakinishwa kiotomatiki kwenye Mac yako. Hii huhakikisha kwamba XProtect huwa imesasishwa kila wakati kulingana na matishio ya hivi karibuni yanayojulikana.

Hata hivyo, ni muhimu kutambua kwamba **XProtect si suluhisho kamili la antivirus**. Hukagua tu orodha mahususi ya matishio yanayojulikana na haifanyi scanning ya on-access kama software nyingi za antivirus.

Unaweza kupata taarifa kuhusu update ya hivi karibuni ya XProtect kwa kuendesha:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect iko katika eneo linalolindwa na SIP kwenye **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, na ndani ya bundle hiyo unaweza kupata taarifa zinazotumiwa na XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Huruhusu code yenye cdhash hizo kutumia legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodha ya plugins na extensions ambazo haziruhusiwi kupakiwa kupitia BundleID na TeamID, au zinazoonyesha minimum version.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules za kugundua malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 database yenye hashes za applications zilizozuiwa na TeamIDs.

Kumbuka kwamba kuna App nyingine kwenye **`/Library/Apple/System/Library/CoreServices/XProtect.app`** inayohusiana na XProtect, lakini haihusiki na mchakato wa Gatekeeper.

> XProtect Remediator: Kwenye macOS za kisasa, Apple husafirisha on-demand scanners (XProtect Remediator) ambazo huendeshwa mara kwa mara kupitia launchd ili kugundua na kurekebisha familia za malware. Unaweza kuona scans hizi kwenye unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Sio Gatekeeper

> [!CAUTION]
> Kumbuka kwamba Gatekeeper **haiendeshwi kila wakati** unapotekeleza application; ni _**AppleMobileFileIntegrity**_ pekee ambayo **itathibitisha signatures za executable code** unapotekeleza app ambayo tayari imetekelezwa na kuthibitishwa na Gatekeeper.

Kwa hiyo, awali ilikuwa inawezekana kutekeleza app ili kui-cache na Gatekeeper, kisha **kubadilisha files ambazo si executables za application** (kama Electron asar au NIB files), na ikiwa hakukuwa na protections nyingine zilizowekwa, application **ilitekelezwa** pamoja na nyongeza **hasidi**.

Hata hivyo, sasa hili haliwezekani kwa sababu macOS **inazuia kubadilishwa kwa files** zilizo ndani ya application bundles. Kwa hiyo, ukijaribu [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack, utaona kwamba haiwezekani tena kuitumia vibaya kwa sababu baada ya kutekeleza app ili kui-cache na Gatekeeper, hutaweza kubadilisha bundle. Na ukibadilisha, kwa mfano, jina la directory ya Contents kuwa NotCon (kama ilivyoonyeshwa kwenye exploit), kisha ukatekeleza binary kuu ya app ili kui-cache na Gatekeeper, itasababisha error na haitatekelezwa.

## Gatekeeper Bypasses

Njia yoyote ya kubypass Gatekeeper (kufanikiwa kumfanya user adownload kitu na kukitekeleza wakati Gatekeeper inapaswa kukizuia) inachukuliwa kuwa vulnerability katika macOS. Hizi ni baadhi ya CVEs zilizotolewa kwa techniques zilizoruhusu kubypass Gatekeeper hapo awali:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilibainika kwamba ikiwa **Archive Utility** itatumika kwa extraction, files zenye **paths zinazozidi characters 886** hazipewi extended attribute ya com.apple.quarantine. Hali hii huruhusu files hizo **kukwepa** ukaguzi wa usalama wa Gatekeeper.<sup>[[5]](#references)</sup>

Angalia [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa maelezo zaidi.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Application inapoundwa kwa kutumia **Automator**, taarifa kuhusu inachohitaji kutekeleza huwa ndani ya `application.app/Contents/document.wflow`, si ndani ya executable. Executable hiyo ni generic Automator binary inayoitwa **Automator Application Stub**.

Kwa hiyo, ungeweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **ielekeze kwa symbolic link kwenda kwenye Automator Application Stub nyingine iliyo ndani ya system**, na ingetekeleza kilicho ndani ya `document.wflow` (script yako) **bila ku-trigger Gatekeeper**, kwa sababu executable halisi haina quarantine xattr.<sup>[[6]](#references)</sup>

Mfano wa location inayotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Angalia [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa maelezo zaidi.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika bypass hii, zip file iliundwa ikiwa na application iliyoanza ku-compress kutoka `application.app/Contents` badala ya `application.app`. Kwa hiyo, **quarantine attr** iliwekwa kwenye **files zote kutoka `application.app/Contents`**, lakini **si kwenye `application.app`**, ambayo ndiyo Gatekeeper ilikuwa ikikagua. Hivyo Gatekeeper ilibypassiwa kwa sababu `application.app` ilipo-triggeriwa **haikuwa na quarantine attribute.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Angalia [**ripoti asili**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa maelezo zaidi.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama components ni tofauti, exploitation ya vulnerability hii inafanana sana na ile ya awali. Katika hali hii tutazalisha Apple Archive kutoka **`application.app/Contents`**, hivyo **`application.app` haitapokea quarantine attr** itakapodecompressed na **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Angalia [**ripoti ya awali**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kwa maelezo zaidi.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** inaweza kutumika kuzuia mtu yeyote kuandika attribute katika faili:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Zaidi ya hayo, **AppleDouble** file format hunakili faili pamoja na ACE zake.<sup>[[9]](#references)</sup>

Katika [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba ACL text representation iliyohifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** itawekwa kama ACL kwenye faili iliyofunguliwa. Kwa hiyo, ikiwa unge-compress programu kwenye zip file kwa kutumia **AppleDouble** file format yenye ACL inayozuia xattrs nyingine kuandikwa humo... quarantine xattr haikuwekwa kwenye programu:
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

Iligunduliwa kuwa **Google Chrome haikuwa ikiweka quarantine attribute** kwenye files zilizopakuliwa kwa sababu ya matatizo fulani ya ndani ya macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble huhifadhi attributes za file katika file tofauti ambalo jina lake huanza na `._`; hii husaidia kunakili attributes za file **kati ya mashine za macOS**. Hata hivyo, baada ya ku-decompress file ya AppleDouble, file lililoanza na `._` **halikupewa quarantine attribute**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Kwa kuwa iliwezekana kuunda faili ambayo haitawekewa attribute ya quarantine, **iliwezekana kupita Gatekeeper.** Mbinu ilikuwa **kuunda application ya faili ya DMG** kwa kutumia kanuni ya majina ya AppleDouble (kuanza kwa `._`) na kuunda **faili inayoonekana kama sym link ya** faili hii iliyofichwa bila attribute ya quarantine.\
**Faili ya dmg inapotekelezwa**, kwa kuwa haina attribute ya quarantine, **itapita Gatekeeper**.
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

Gatekeeper bypass iliyorekebishwa katika macOS Sonoma 14.0 iliruhusu apps zilizoundwa mahsusi kuendeshwa bila kuomba ruhusa. Maelezo yalifichuliwa hadharani baada ya patching, na tatizo hilo lilikuwa likitumiwa kikamilifu in the wild kabla ya kurekebishwa. Hakikisha Sonoma 14.0 au toleo la baadaye limesakinishwa.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Gatekeeper bypass katika macOS 14.4 (iliyotolewa Machi 2024), iliyotokana na jinsi `libarchive` ilivyoshughulikia ZIPs hasidi, iliruhusu apps kukwepa assessment. Fanya update hadi 14.4 au toleo la baadaye, ambapo Apple ilirekebisha tatizo hilo.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** iliyopachikwa katika app iliyopakuliwa ingeweza kuanzishwa bila Gatekeeper assessment, kwa sababu workflows zilichukuliwa kama data na kuendeshwa na Automator helper nje ya njia ya kawaida ya notarization prompt. Kwa hiyo, `.app` iliyoundwa mahsusi na kubeba Quick Action inayoendesha shell script (kwa mfano, ndani ya `Contents/PlugIns/*.workflow/Contents/document.wflow`) ingeweza kutekelezwa mara moja wakati wa launch. Apple iliongeza dialogu ya ziada ya consent na kurekebisha njia ya assessment katika Ventura **13.7**, Sonoma **14.7**, na Sequoia **15**.<sup>[[3]](#references)</sup>

### Third‑party unarchivers zinazosambaza quarantine vibaya (2023–2024)

Vulnerabilities kadhaa katika extraction tools maarufu (kwa mfano, The Unarchiver) zilisababisha files zilizotolewa kutoka kwenye archives kukosa xattr ya `com.apple.quarantine`, na hivyo kuwezesha fursa za Gatekeeper bypass. Tegemea kila mara macOS Archive Utility au tools zilizopigwa patch wakati wa testing, na thibitisha xattrs baada ya extraction.

### uchg (kutoka kwenye [talk hii](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Unda directory iliyo na app.
- Ongeza uchg kwenye app.
- Compress app iwe faili ya tar.gz.
- Tuma faili ya tar.gz kwa victim.
- Victim anafungua faili ya tar.gz na kuendesha app.
- Gatekeeper hai-check app.<sup>[[12]](#references)</sup>

### Zuia Quarantine xattr

Katika bundle ya ".app", ikiwa quarantine xattr haijaongezwa, wakati wa kuitekeleza **Gatekeeper haitaanzishwa**.

## References

- [1] [Apple Platform Security: Kuhusu maudhui ya usalama ya macOS Sonoma 14.4 (inajumuisha CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Jinsi macOS sasa inavyofuatilia chanzo cha apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia inaondoa Gatekeeper bypass ya Control‑click “Open”](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: Ugunduzi wa CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Kukwepa macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs yatambua vulnerability ya Safari inayowezesha Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs yatambua vulnerability ya macOS Archive Utility inayowezesha Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Achilles heel ya Gatekeeper: Kugundua vulnerability ya macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ugunduzi wa Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Kupata na kuripoti Gatekeeper bypass exploit kwa msaada wa Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Kukwepa Security na Privacy Mechanisms za macOS — Kuanzia Gatekeeper hadi System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
{{#include ../../../banners/hacktricks-training.md}}
