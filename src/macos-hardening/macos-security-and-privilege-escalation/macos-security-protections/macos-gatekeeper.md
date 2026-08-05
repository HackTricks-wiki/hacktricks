# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ni security feature iliyoundwa kwa ajili ya operating systems za Mac, yenye lengo la kuhakikisha kuwa watumiaji **wanaendesha software zinazoaminika pekee** kwenye systems zao. Hufanya kazi kwa **kuthibitisha software** ambayo mtumiaji amedownload na kujaribu kuifungua kutoka **sources zilizo nje ya App Store**, kama vile app, plug-in, au installer package.

Mbinu kuu ya Gatekeeper inategemea mchakato wake wa **verification**. Hukagua ikiwa software iliyodownload **imesainiwa na developer anayetambuliwa**, hivyo kuthibitisha uhalisi wa software hiyo. Zaidi ya hayo, huhakikisha kuwa software hiyo **ime-notarise-d na Apple**, jambo linalothibitisha kuwa haina malicious content inayojulikana na haijabadilishwa baada ya notarisation.

Pia, Gatekeeper huimarisha udhibiti na usalama wa mtumiaji kwa **kuwauliza watumiaji waidhinishe ufunguaji** wa software iliyodownload mara ya kwanza. Ulinzi huu husaidia kuzuia watumiaji kuendesha bila kukusudia executable code inayoweza kuwa hatari, ambayo huenda waliidhani kuwa ni data file isiyo na madhara.

### Application Signatures

Application signatures, zinazojulikana pia kama code signatures, ni sehemu muhimu ya security infrastructure ya Apple. Hutumika **kuthibitisha utambulisho wa mwandishi wa software** (developer) na kuhakikisha kuwa code haijabadilishwa tangu isainiwe mara ya mwisho.

Hivi ndivyo inavyofanya kazi:

1. **Signing the Application:** Developer anapokuwa tayari kusambaza application yake, **huisaini application kwa kutumia private key**. Private key hii inahusishwa na **certificate ambayo Apple humtolea developer** anapojiandikisha kwenye Apple Developer Program. Mchakato wa kusaini unahusisha kutengeneza cryptographic hash ya sehemu zote za app na ku-encrypt hash hiyo kwa kutumia private key ya developer.
2. **Distributing the Application:** Application iliyosainiwa husambazwa kwa watumiaji pamoja na certificate ya developer, ambayo ina public key inayolingana.
3. **Verifying the Application:** Mtumiaji anapodownload na kujaribu kuendesha application, operating system ya Mac hutumia public key kutoka kwenye certificate ya developer ku-decrypt hash. Kisha hukokotoa upya hash kulingana na hali ya sasa ya application na kuilinganisha na hash iliyodecryptiwa. Ikiwa zinalingana, inamaanisha kuwa **application haijabadilishwa** tangu developer alipoisaini, na system huruhusu application kuendeshwa.

Application signatures ni sehemu muhimu ya teknolojia ya Apple ya Gatekeeper. Mtumiaji anapojaribu **kufungua application iliyodownload kutoka internet**, Gatekeeper huthibitisha application signature. Ikiwa imesainiwa kwa certificate iliyotolewa na Apple kwa developer anayejulikana na code haijabadilishwa, Gatekeeper huruhusu application kuendeshwa. Vinginevyo, huzuia application na kumjulisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper pia hukagua ikiwa application ime-notarise-d** na Apple, na kuongeza security layer nyingine. Mchakato wa notarisation hukagua application kutafuta security issues zinazojulikana na malicious code, na ikiwa ukaguzi huu utafaulu, Apple huongeza ticket kwenye application ambayo Gatekeeper inaweza kuithibitisha.

#### Check Signatures

Unapokagua **malware sample**, unapaswa kila mara **kuangalia signature** ya binary, kwa sababu **developer** aliyeisaini huenda tayari **anahusishwa** na **malware.**
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

Mchakato wa notarization wa Apple hutumika kama ulinzi wa ziada wa kuwalinda watumiaji dhidi ya software inayoweza kuwa na madhara. Unahusisha **developer kuwasilisha application yao ili ichunguzwe** na **Apple's Notary Service**, ambayo haipaswi kuchanganywa na App Review. Service hii ni **mfumo wa kiotomatiki** unaochunguza software iliyowasilishwa ili kubaini uwepo wa **maudhui hasidi** na matatizo yoyote yanayoweza kuhusiana na code-signing.

Ikiwa software **itafaulu** ukaguzi huu bila kuibua wasiwasi wowote, Notary Service hutengeneza notarization ticket. Kisha developer anatakiwa **kuambatisha ticket hii kwenye software yao**, mchakato unaojulikana kama 'stapling.' Zaidi ya hayo, notarization ticket huchapishwa pia mtandaoni, ambapo Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuipata.

Mtumiaji anaposakinisha au kuendesha software hiyo kwa mara ya kwanza, kuwepo kwa notarization ticket - iwe imebandikwa kwenye executable au imepatikana mtandaoni - **huijulisha Gatekeeper kwamba software hiyo imefanyiwa notarization na Apple**. Kwa sababu hiyo, Gatekeeper huonyesha ujumbe wa maelezo katika dialog ya kwanza ya launch, ukionyesha kwamba software imefanyiwa ukaguzi na Apple ili kubaini maudhui hasidi. Mchakato huu huongeza imani ya mtumiaji katika usalama wa software anayosakinisha au kuendesha kwenye mifumo yake.

### spctl & syspolicyd

> [!CAUTION]
> Kumbuka kwamba kuanzia toleo la Sequoia, **`spctl`** hairuhusu tena kurekebisha usanidi wa Gatekeeper.

**`spctl`** ni CLI tool ya kuorodhesha na kuingiliana na Gatekeeper (kupitia daemon ya `syspolicyd` kwa kutumia ujumbe wa XPC). Kwa mfano, inawezekana kuona **status** ya GateKeeper kwa:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Kumbuka kwamba ukaguzi wa signatures wa GateKeeper hufanywa tu kwa **files zenye Quarantine attribute**, si kwa kila file.

GateKeeper itaangalia ikiwa, kulingana na **preferences & signature**, binary inaweza ku-execute:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ni daemon kuu inayohusika na ku-enforce Gatekeeper. Inatunza database iliyo katika `/var/db/SystemPolicy`, na inawezekana kupata code inayosaidia [database hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) na [SQL template hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Kumbuka kwamba database haizuiliwi na SIP na inaweza kuandikwa na root, na database `/var/db/.SystemPolicy-default` hutumika kama backup ya awali endapo nyingine itaharibika.

Zaidi ya hayo, bundles **`/var/db/gke.bundle`** na **`/var/db/gkopaque.bundle`** zina files zenye rules zinazoingizwa kwenye database. Unaweza kuangalia database hii kama root kwa:
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
**`syspolicyd`** pia hutoa XPC server yenye operations tofauti kama `assess`, `update`, `record` na `cancel`, ambazo pia zinaweza kufikiwa kwa kutumia APIs za **`Security.framework`'s `SecAssessment*`**, na **`spctl`** kwa hakika huwasiliana na **`syspolicyd`** kupitia XPC.

Zingatia jinsi rule ya kwanza ilivyoishia kwenye "**App Store**" na ya pili kwenye "**Developer ID**", na kwamba kwenye image iliyotangulia ilikuwa **imewezeshwa kuendesha apps kutoka App Store na developers waliotambuliwa**.\
Ukifanya **modify** setting hiyo iwe App Store, rules za "**Notarized Developer ID" zitatoweka**.

Pia kuna maelfu ya rules za **type GKE**:
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

Au unaweza kuorodhesha maelezo ya awali kwa kutumia:
```bash
sudo spctl --list
```
Chaguo **`--master-disable`** na **`--global-disable`** za **`spctl`** zitazima kabisa **ukaguzi huu wa signature**:
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
Inawezekana kuongeza sheria mpya katika GateKeeper ili kuruhusu utekelezaji wa programu fulani kwa kutumia:
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
Kuhusu **kernel extensions**, folda `/var/db/SystemPolicyConfiguration` ina faili zenye orodha za kexts zinazoruhusiwa kupakiwa. Zaidi ya hayo, `spctl` ina entitlement `com.apple.private.iokit.nvram-csr` kwa sababu inaweza kuongeza kernel extensions mpya zilizoidhinishwa awali, ambazo pia zinahitaji kuhifadhiwa kwenye NVRAM katika key ya `kext-allowed-teams`.

#### Kusimamia Gatekeeper kwenye macOS 15 (Sequoia) na matoleo ya baadaye

- Bypass ya muda mrefu ya Finder **Ctrl+Open / Right-click → Open** imeondolewa; users lazima waruhusu waziwazi app iliyozuiwa kupitia **System Settings → Privacy & Security → Open Anyway** baada ya dialog ya kwanza ya kuzuia.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` hazikubaliki tena; `spctl` sasa kimsingi ni ya kusoma tu kwa assessment na usimamizi wa labels, huku utekelezaji wa policy ukisanidiwa kupitia UI au MDM.

Kuanzia macOS 15 Sequoia, end users hawawezi tena kubadilisha Gatekeeper policy kupitia `spctl`. Usimamizi hufanywa kupitia System Settings au kwa kusambaza MDM configuration profile yenye payload ya `com.apple.systempolicy.control`. Mfano wa profile snippet ya kuruhusu App Store na identified developers (lakini si "Anywhere"):

<details>
<summary>MDM profile ya kuruhusu App Store na identified developers</summary>
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

Baada ya **kupakua** application au faili, baadhi ya **applications** maalum za macOS kama vile web browsers au email clients **huambatanisha file attribute ya ziada**, inayojulikana kwa kawaida kama "**quarantine flag**," kwenye faili lililopakuliwa. Attribute hii hutumika kama hatua ya usalama ya **kuweka alama kwenye faili** kuonyesha kuwa limetoka kwenye chanzo kisichoaminika (internet), na huenda likawa na hatari. Hata hivyo, si applications zote huambatanisha attribute hii; kwa mfano, software za kawaida za BitTorrent client kwa kawaida hupita mchakato huu.

**Uwepo wa quarantine flag huashiria kipengele cha usalama cha macOS cha Gatekeeper mtumiaji anapojaribu kuendesha faili**.

Iwapo **quarantine flag haipo** (kama ilivyo kwa mafaili yaliyopakuliwa kupitia baadhi ya BitTorrent clients), **checks za Gatekeeper huenda zisifanywe**. Kwa hivyo, watumiaji wanapaswa kuwa waangalifu wanapofungua mafaili yaliyopakuliwa kutoka kwenye vyanzo visivyo salama au visivyojulikana.

> [!NOTE] > **Kukagua** **uhalali** wa code signatures ni mchakato unaotumia **rasilimali nyingi**, unaojumuisha kutengeneza **hashes** za cryptographic za code na resources zake zote zilizobundled. Zaidi ya hayo, kukagua uhalali wa certificate kunahusisha kufanya **online check** kwenye servers za Apple ili kuona kama ime-revoked baada ya kutolewa. Kwa sababu hizi, full code signature na notarization check **si practical kuendeshwa kila app inapozinduliwa**.
>
> Kwa hiyo, checks hizi **huendeshwa tu wakati wa kutekeleza apps zenye quarantined attribute.**

> [!WARNING]
> Attribute hii lazima **iwekwe na application inayounda/kupakua** faili.
>
> Hata hivyo, mafaili yaliyo sandboxed yatakuwa na attribute hii ikiwekwa kwenye kila faili yanayounda. Na apps ambazo si sandboxed zinaweza kuiweka zenyewe, au kubainisha key ya [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) kwenye **Info.plist**, jambo litakalofanya mfumo uweke extended attribute ya `com.apple.quarantine` kwenye mafaili yaliyoundwa,

Zaidi ya hayo, mafaili yote yaliyoundwa na process inayotumia **`qtn_proc_apply_to_self`** huwa quarantined. Au API **`qtn_file_apply_to_path`** huongeza quarantine attribute kwenye file path iliyobainishwa.

Inawezekana **kukagua status yake na kuiwezesha/kui-disable** (root required) kwa:
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
Kagua **thamani** ya **sifa** **zilizopanuliwa** na utambue app iliyoandika quarantine attr kwa:
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
Kwa kweli, mchakato "ungeweza kuweka quarantine flags kwenye mafaili unayounda" (tayari nilijaribu kuweka flag ya USER_APPROVED kwenye faili iliyoundwa, lakini haikukubali):

<details>

<summary>Source Code ya kutumia quarantine flags</summary>
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

Na **ondoa** attribute hiyo kwa:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Na upate faili zote zilizowekwa kwenye quarantine kwa kutumia:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Taarifa za Quarantine pia huhifadhiwa katika database kuu inayodhibitiwa na LaunchServices kwenye **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, ambayo huwezesha GUI kupata data kuhusu asili ya faili. Aidha, hii inaweza kuandikwa upya na applications ambazo zinaweza kuwa na nia ya kuficha asili yake. Pia, hili linaweza kufanywa kupitia LaunchServices APIS.

#### **libquarantine.dylib**

Library hii hu-export functions kadhaa zinazoruhusu kudhibiti fields za extended attributes.

`qtn_file_*` APIs hushughulikia sera za file quarantine, huku `qtn_proc_*` APIs zikitumika kwa processes (files zilizoundwa na process). Functions ambazo hazija-exportiwa za `__qtn_syscall_quarantine*` ndizo zinazotumia sera hizo; huita `mac_syscall` ikiwa na `"Quarantine"` kama argument ya kwanza, ambayo hutuma requests kwa `Quarantine.kext`.

#### **Quarantine.kext**

Kernel extension hii inapatikana tu kupitia **kernel cache kwenye system**; hata hivyo, _unaweza kupakua_ **Kernel Debug Kit kutoka** [**https://developer.apple.com/**](https://developer.apple.com/), ambayo itakuwa na toleo la extension lenye symbols.

Kext hii itatumia hooks kupitia MACF kwenye calls kadhaa ili kunasa matukio yote ya lifecycle ya file: Creation, opening, renaming, hard-linkning... hata `setxattr`, ili kuizuia isiweke extended attribute ya `com.apple.quarantine`.

Pia hutumia MIBs kadhaa:

- `security.mac.qtn.sandbox_enforce`: Inalazimisha quarantine pamoja na Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs zinaweza kutekeleza files zilizoidhinishwa pekee

#### Provenance xattr (Ventura na matoleo ya baadaye)

macOS 13 Ventura ilianzisha mechanism tofauti ya provenance, ambayo hujazwa mara ya kwanza app iliyo kwenye quarantine inaporuhusiwa ku-run.<sup>[[2]](#references)</sup> Artefacts mbili huundwa:

- `com.apple.provenance` xattr kwenye directory ya `.app` bundle (binary value yenye size isiyobadilika, iliyo na primary key na flags).
- Row katika table ya `provenance_tracking` iliyo ndani ya ExecPolicy database kwenye `/var/db/SystemPolicyConfiguration/ExecPolicy/`, inayohifadhi cdhash na metadata ya app.

Matumizi ya kivitendo:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect ni kipengele cha **anti-malware** kilichojengwa ndani ya macOS. XProtect **hukagua kila application inapozinduliwa au kurekebishwa kwa mara ya kwanza dhidi ya database yake** yenye malware inayojulikana na aina za faili zisizo salama. Unapopakua faili kupitia application fulani, kama vile Safari, Mail, au Messages, XProtect hukagua faili hiyo kiotomatiki. Ikiwa inalingana na malware yoyote inayojulikana katika database yake, XProtect **huzuia faili hiyo kuendeshwa** na kukuarifu kuhusu tishio hilo.

Database ya XProtect **husasishwa mara kwa mara** na Apple kwa ufafanuzi mpya wa malware, na masasisho hayo hupakuliwa na kusakinishwa kiotomatiki kwenye Mac yako. Hii huhakikisha kuwa XProtect huwa imesasishwa kila wakati kulingana na vitisho vipya vinavyojulikana.

Hata hivyo, ni muhimu kutambua kuwa **XProtect si antivirus yenye vipengele kamili**. Hukagua tu orodha maalum ya vitisho vinavyojulikana na haifanyi on-access scanning kama software nyingi za antivirus.

Unaweza kupata maelezo kuhusu update ya hivi karibuni ya XProtect kwa kuendesha:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect iko katika eneo lililolindwa na SIP kwenye **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, na ndani ya bundle hiyo unaweza kupata taarifa zinazotumiwa na XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Huruhusu code yenye cdhashes hizo kutumia legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodha ya plugins na extensions ambazo haziruhusiwi kupakiwa kupitia BundleID na TeamID, au zinazoonyesha minimum version.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules za kutambua malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 database yenye hashes za applications zilizozuiwa na TeamIDs.

Kumbuka kuwa kuna App nyingine kwenye **`/Library/Apple/System/Library/CoreServices/XProtect.app`** inayohusiana na XProtect, lakini haihusiki na mchakato wa Gatekeeper.

> XProtect Remediator: Kwenye macOS za kisasa, Apple husambaza on-demand scanners (XProtect Remediator) ambazo huendeshwa mara kwa mara kupitia launchd ili kutambua na kurekebisha families za malware. Unaweza kuona scans hizi kwenye unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Sio Gatekeeper

> [!CAUTION]
> Kumbuka kuwa Gatekeeper **haiendeshwi kila mara** unapotekeleza application; ni _**AppleMobileFileIntegrity**_ pekee ambayo **itathibitisha executable code signatures** unapotekeleza app ambayo tayari imetekelezwa na kuthibitishwa na Gatekeeper.

Kwa hiyo, hapo awali ilikuwa inawezekana kutekeleza app ili kui-cache na Gatekeeper, kisha **kubadilisha files zisizo executables za application** (kama Electron asar au NIB files), na ikiwa hakukuwa na protections nyingine, application **ilitekelezwa** ikiwa na additions **za malicious**.

Hata hivyo, sasa hili haliwezekani kwa sababu macOS **inazuia kubadilisha files** zilizo ndani ya applications bundles. Kwa hiyo, ukijaribu [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack, utaona kuwa haiwezekani tena kuitumia vibaya kwa sababu baada ya kutekeleza app ili kui-cache na Gatekeeper, hutaweza kubadilisha bundle. Na ukibadilisha, kwa mfano, jina la directory ya Contents kuwa NotCon (kama ilivyoonyeshwa kwenye exploit), kisha ukatekeleza main binary ya app ili kui-cache na Gatekeeper, itasababisha error na haitatekelezwa.

## Gatekeeper Bypasses

Njia yoyote ya kubypass Gatekeeper (kufanikiwa kumfanya user adownload kitu na kukitekeleza wakati Gatekeeper inapaswa kukizuia) inachukuliwa kuwa vulnerability kwenye macOS. Hizi ni baadhi ya CVEs zilizopewa techniques zilizowezesha kubypass Gatekeeper hapo awali:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilibainika kuwa ikiwa **Archive Utility** inatumika kufanya extraction, files zenye **paths zinazozidi characters 886** hazipokei extended attribute ya com.apple.quarantine. Hali hii bila kukusudia huruhusu files hizo **kukwepa** security checks za Gatekeeper.<sup>[[5]](#references)</sup>

Angalia [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa maelezo zaidi.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Application inapoundwa kwa kutumia **Automator**, taarifa kuhusu inachohitaji kutekeleza huwa ndani ya `application.app/Contents/document.wflow`, si kwenye executable. Executable yenyewe ni generic Automator binary inayoitwa **Automator Application Stub**.

Kwa hiyo, ungeweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **ielekeze kwa symbolic link kwenda kwenye Automator Application Stub nyingine iliyo ndani ya system**, na ingetekeleza kilicho ndani ya `document.wflow` (script yako) **bila ku-trigger Gatekeeper**, kwa sababu executable halisi haina quarantine xattr.<sup>[[6]](#references)</sup>

Mfano wa location inayotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Angalia [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa maelezo zaidi.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika bypass hii, zip file iliundwa ikiwa na application iliyoanza ku-compress kutoka `application.app/Contents` badala ya `application.app`. Kwa hiyo, **quarantine attr** iliwekwa kwenye **files zote kutoka `application.app/Contents`**, lakini **haikuwekwa kwenye `application.app`**, ambayo ndiyo Gatekeeper ilikuwa inakagua. Kwa hiyo Gatekeeper ilibypassiwa kwa sababu `application.app` ilipo-triggeriwa **haikuwa na quarantine attribute.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Angalia [**ripoti ya awali**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa maelezo zaidi.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama components ni tofauti, exploitation ya vulnerability hii inafanana sana na ile ya awali. Katika hali hii, tutatengeneza Apple Archive kutoka **`application.app/Contents`**, hivyo **`application.app` haitapata quarantine attr** itakapodecompressed na **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Angalia [**ripoti ya awali**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kwa maelezo zaidi.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** inaweza kutumika kumzuia mtu yeyote kuandika attribute kwenye faili:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Zaidi ya hayo, **AppleDouble** file format hunakili file pamoja na ACEs zake.<sup>[[9]](#references)</sup>

Katika [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba ACL text representation iliyohifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** itawekwa kama ACL kwenye file iliyodecompressed. Kwa hivyo, ikiwa ungecompress application kuwa zip file yenye **AppleDouble** file format pamoja na ACL inayozuia xattrs nyingine kuandikwa ndani yake... quarantine xattr haikuwekwa kwenye application:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Angalia [**ripoti ya awali**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.

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

AppleDouble file formats huhifadhi attributes za file kwenye file tofauti linaloanza kwa `._`, jambo hili husaidia kunakili attributes za file **kati ya mashine za macOS**. Hata hivyo, iligunduliwa kuwa baada ya kufungua compressed AppleDouble file, file linaloanza kwa `._` **halikupewa quarantine attribute**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Kuweza kuunda faili ambalo halitawekewa quarantine attribute, **iliwezekana kubypass Gatekeeper.** Mbinu hiyo ilikuwa **kuunda application ya DMG file** kwa kutumia AppleDouble name convention (kuanza kwa `._`) na kuunda **visible file kama sym link inayoelekeza kwenye** faili hili lililofichwa bila quarantine attribute.\
**dmg file inapotekelezwa**, kwa kuwa haina quarantine attribute, **itabwepass Gatekeeper**.
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

Gatekeeper bypass iliyorekebishwa katika macOS Sonoma 14.0 iliruhusu apps zilizoundwa mahsusi kuendeshwa bila kuonyesha ombi la ruhusa. Maelezo yalifichuliwa hadharani baada ya patching, na tatizo hilo lilikuwa likitumiwa kikamilifu kwenye mazingira halisi kabla ya kurekebishwa. Hakikisha Sonoma 14.0 au toleo la baadaye limesakinishwa.

### [CVE-2024-27853]

Gatekeeper bypass katika macOS 14.4 (iliyotolewa Machi 2024), iliyotokana na jinsi `libarchive` ilivyoshughulikia ZIPs hasidi, iliruhusu apps kukwepa assessment. Update hadi 14.4 au toleo la baadaye, ambapo Apple ilirekebisha tatizo hilo.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** iliyopachikwa ndani ya app iliyopakuliwa ingeweza kuanzishwa bila Gatekeeper kufanya assessment, kwa sababu workflows zilichukuliwa kama data na kutekelezwa na Automator helper nje ya njia ya kawaida ya notarization prompt. Kwa hiyo, `.app` iliyoundwa mahsusi na kubeba Quick Action inayoendesha shell script (kwa mfano, ndani ya `Contents/PlugIns/*.workflow/Contents/document.wflow`) ingeweza kutekelezwa mara moja wakati wa launch. Apple iliongeza dialog ya ziada ya consent na kurekebisha njia ya assessment katika Ventura **13.7**, Sonoma **14.7**, na Sequoia **15**.<sup>[[3]](#references)</sup>

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Vulnerabilities kadhaa katika extraction tools maarufu (kwa mfano, The Unarchiver) zilisababisha files zilizotolewa kutoka kwenye archives kukosa `com.apple.quarantine` xattr, na hivyo kuwezesha fursa za Gatekeeper bypass. Daima tumia macOS Archive Utility au tools zilizopigwa patch wakati wa testing, na validate xattrs baada ya extraction.

### uchg (kutoka kwenye [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Create directory iliyo na app.
- Add uchg kwenye app.
- Compress app iwe tar.gz file.
- Send tar.gz file kwa victim.
- Victim anafungua tar.gz file na ku-run app.
- Gatekeeper haikagui app.<sup>[[12]](#references)</sup>

### Zuia Quarantine xattr

Katika ".app" bundle, ikiwa quarantine xattr haijaongezwa kwake, wakati wa kui-execute **Gatekeeper haitatrigger**.


## References

- [1] [Apple Platform Security: Kuhusu maudhui ya usalama ya macOS Sonoma 14.4 (inajumuisha CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Jinsi macOS sasa inavyofuatilia provenance ya apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia inaondoa Gatekeeper bypass ya Control‑click “Open”](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: Ugunduzi wa CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Kukwepa macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs inatambua Safari vulnerability inayowezesha Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs inatambua macOS Archive Utility vulnerability inayowezesha Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Achilles heel ya Gatekeeper: Kufichua macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ugunduzi wa Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Kupata na kuripoti Gatekeeper bypass exploit kwa msaada wa Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Kukwepa macOS Security and Privacy Mechanisms — Kutoka Gatekeeper hadi System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
