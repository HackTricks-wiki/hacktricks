# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ni kipengele cha usalama kilichotengenezwa kwa ajili ya mifumo ya uendeshaji ya Mac, kinacholenga kuhakikisha kuwa watumiaji **wanaendesha software inayoaminika pekee** kwenye mifumo yao. Hufanya kazi kwa **kuthibitisha software** ambayo mtumiaji ameipakua na kujaribu kuifungua kutoka kwenye **sources zilizo nje ya App Store**, kama vile app, plug-in, au installer package.

Utaratibu mkuu wa Gatekeeper unategemea mchakato wake wa **verification**. Hukagua ikiwa software iliyopakuliwa **imesainiwa na developer anayetambuliwa**, na hivyo kuhakikisha uhalali wa software hiyo. Pia, huthibitisha ikiwa software hiyo **imefanyiwa notarisation na Apple**, jambo linalothibitisha kuwa haina maudhui hasidi yanayojulikana na haijabadilishwa baada ya notarisation.

Zaidi ya hayo, Gatekeeper huimarisha udhibiti na usalama wa mtumiaji kwa **kuwaomba watumiaji waidhinishe kufunguliwa** kwa software iliyopakuliwa mara ya kwanza. Ulinzi huu husaidia kuwazuia watumiaji kuendesha bila kukusudia code inayoweza kuwa hatari, ambayo huenda waliidhani kimakosa kuwa ni data file isiyo na madhara.

### Application Signatures

Application signatures, pia hujulikana kama code signatures, ni sehemu muhimu ya miundombinu ya usalama ya Apple. Hutumika **kuthibitisha utambulisho wa mwandishi wa software** (developer) na kuhakikisha kuwa code haijabadilishwa tangu iliposainiwa mara ya mwisho.

Hivi ndivyo inavyofanya kazi:

1. **Signing the Application:** Developer anapokuwa tayari kusambaza application yake, **huisaini application kwa kutumia private key**. Private key hii inahusishwa na **certificate ambayo Apple humpatia developer** anapojiandikisha katika Apple Developer Program. Mchakato wa signing unahusisha kuunda cryptographic hash ya sehemu zote za app na ku-encrypt hash hiyo kwa kutumia private key ya developer.
2. **Distributing the Application:** Application iliyosainiwa husambazwa kwa watumiaji pamoja na certificate ya developer, ambayo ina public key inayolingana.
3. **Verifying the Application:** Mtumiaji anapopakua na kujaribu kuendesha application, mfumo wa uendeshaji wa Mac hutumia public key kutoka kwenye certificate ya developer ku-decrypt hash hiyo. Kisha huhesabu upya hash kulingana na hali ya sasa ya application na kuilinganisha na hash iliyodecryptiwa. Ikiwa zinalingana, hii inamaanisha kuwa **application haijabadilishwa** tangu developer alipoisaini, na mfumo huruhusu application kuendeshwa.

Application signatures ni sehemu muhimu ya teknolojia ya Apple ya Gatekeeper. Mtumiaji anapojaribu **kufungua application iliyopakuliwa kutoka kwenye internet**, Gatekeeper huthibitisha application signature. Ikiwa imesainiwa kwa certificate iliyotolewa na Apple kwa developer anayejulikana na code haijabadilishwa, Gatekeeper huruhusu application kuendeshwa. Vinginevyo, huzuia application na kumtahadharisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper pia hukagua ikiwa application imefanyiwa notarization** na Apple, na hivyo kuongeza tabaka la ziada la usalama. Mchakato wa notarization hukagua application dhidi ya masuala ya usalama yanayojulikana na code hasidi, na ikiwa ukaguzi huo utafaulu, Apple huongeza ticket kwenye application ambayo Gatekeeper inaweza kuithibitisha.

#### Check Signatures

Unapokagua **malware sample**, unapaswa kila mara **kuangalia signature** ya binary kwa sababu **developer** aliyeisaini huenda tayari **anahusishwa** na **malware.**
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

Mchakato wa notarization wa Apple hutumika kama ulinzi wa ziada wa kuwalinda watumiaji dhidi ya software inayoweza kuwa na madhara. Unahusisha **developer kuwasilisha application yao kwa ajili ya kuchunguzwa** na **Apple's Notary Service**, ambayo haipaswi kuchanganywa na App Review. Service hii ni **mfumo wa kiotomatiki** unaochunguza software iliyowasilishwa ili kubaini uwepo wa **maudhui hasidi** na matatizo yoyote yanayoweza kuhusiana na code-signing.

Ikiwa software **itafaulu** ukaguzi huu bila kuibua wasiwasi wowote, Notary Service hutengeneza ticket ya notarization. Kisha developer anatakiwa **kuambatisha ticket hii kwenye software yao**, mchakato unaojulikana kama 'stapling.' Zaidi ya hayo, ticket ya notarization pia huchapishwa mtandaoni, ambapo Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuipata.

Mtumiaji anapoweka au kuendesha software hiyo kwa mara ya kwanza, kuwepo kwa ticket ya notarization - iwe ime-staple kwenye executable au imepatikana mtandaoni - **huifahamisha Gatekeeper kwamba software hiyo imefanyiwa notarization na Apple**. Kwa sababu hiyo, Gatekeeper huonyesha ujumbe unaoeleza katika dialog ya kwanza ya uzinduzi, ukionyesha kwamba software hiyo imekaguliwa na Apple kwa ajili ya maudhui hasidi. Mchakato huu huongeza imani ya mtumiaji katika usalama wa software anayoweka au kuendesha kwenye mifumo yake.

### spctl & syspolicyd

> [!CAUTION]
> Kumbuka kwamba kuanzia toleo la Sequoia, **`spctl`** hairuhusu tena kubadilisha usanidi wa Gatekeeper.

**`spctl`** ni zana ya CLI ya kuorodhesha na kuwasiliana na Gatekeeper (kupitia daemon ya `syspolicyd` kwa kutumia ujumbe wa XPC). Kwa mfano, inawezekana kuona **hali** ya GateKeeper kwa:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Kumbuka kwamba ukaguzi wa GateKeeper wa signature hufanywa tu kwa **files zenye Quarantine attribute**, si kwa kila file.

GateKeeper itaangalia ikiwa, kulingana na **preferences na signature**, binary inaweza kutekelezwa:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ndiye daemon mkuu anayehusika na kutekeleza Gatekeeper. Anadumisha database iliyo katika `/var/db/SystemPolicy`, na inawezekana kupata code ya kusaidia [database hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) na [SQL template hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Kumbuka kwamba database hailazimishwi na SIP na inaweza kuandikwa na root, huku database `/var/db/.SystemPolicy-default` ikitumika kama backup ya awali endapo nyingine itaharibika.

Zaidi ya hayo, bundles **`/var/db/gke.bundle`** na **`/var/db/gkopaque.bundle`** zina files zilizo na rules zinazoingizwa kwenye database. Unaweza kuangalia database hii kama root kwa:
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
**`syspolicyd`** pia hufichua seva ya XPC yenye operesheni tofauti kama `assess`, `update`, `record` na `cancel`, ambazo pia zinaweza kufikiwa kwa kutumia API za **`Security.framework`'s `SecAssessment*`**, na **`spctl`** kwa hakika huwasiliana na **`syspolicyd`** kupitia XPC.

Zingatia kwamba sheria ya kwanza iliishia kwa "**App Store**" na ya pili kwa "**Developer ID**", na kwamba katika picha iliyotangulia ilikuwa **imewezeshwa kutekeleza programu kutoka App Store na watengenezaji waliotambuliwa**.\
Ukibadilisha mpangilio huo kuwa App Store, sheria za "**Notarized Developer ID" zitatoweka**.

Pia kuna maelfu ya sheria za **type GKE** :
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

Au unaweza kuorodhesha maelezo ya awali kwa:
```bash
sudo spctl --list
```
Chaguo **`--master-disable`** na **`--global-disable`** za **`spctl`** zita **zima kabisa** ukaguzi huu wa signatures:
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

Inawezekana **kuangalia ikiwa App itaruhusiwa na GateKeeper** kwa kutumia:
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
Kuhusu **kernel extensions**, folda `/var/db/SystemPolicyConfiguration` ina mafaili yenye orodha za kexts zinazoruhusiwa kupakiwa. Zaidi ya hayo, `spctl` ina entitlement `com.apple.private.iokit.nvram-csr` kwa sababu ina uwezo wa kuongeza kernel extensions mpya zilizoidhinishwa awali, ambazo pia zinahitaji kuhifadhiwa katika NVRAM kwenye key ya `kext-allowed-teams`.

#### Kusimamia Gatekeeper kwenye macOS 15 (Sequoia) na matoleo ya baadaye

- Bypass ya muda mrefu ya Finder **Ctrl+Open / Right-click → Open** imeondolewa; users lazima waruhusu waziwazi app iliyozuiwa kutoka **System Settings → Privacy & Security → Open Anyway** baada ya dialog ya kwanza ya kuzuia.<sup>[4]</sup>
- `spctl --master-disable/--global-disable` hazikubaliki tena; `spctl` sasa kimsingi ni read-only kwa assessment na label management, huku policy enforcement ikisanidiwa kupitia UI au MDM.

Kuanzia macOS 15 Sequoia, end users hawawezi tena kubadilisha Gatekeeper policy kutoka `spctl`. Usimamizi hufanywa kupitia System Settings au kwa ku-deploy MDM configuration profile yenye payload ya `com.apple.systempolicy.control`. Mfano wa profile snippet ya kuruhusu App Store na identified developers (lakini si "Anywhere"):

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

Wakati wa **kupakua** application au faili, **applications** maalum za macOS kama vile browsers za wavuti au email clients **huambatisha extended file attribute**, inayojulikana kwa kawaida kama "**quarantine flag**," kwenye faili lililopakuliwa. Attribute hii hufanya kazi kama hatua ya usalama ya **kuweka alama kwenye faili** kuonyesha kuwa limetoka kwenye chanzo kisichoaminika (intaneti), na huenda likawa na hatari. Hata hivyo, si applications zote huambatisha attribute hii; kwa mfano, software ya kawaida ya BitTorrent client kwa kawaida hupita mchakato huu.

**Uwepo wa quarantine flag huashiria kipengele cha usalama cha macOS cha Gatekeeper mtumiaji anapojaribu kutekeleza faili hilo**.

Iwapo **quarantine flag haipo** (kama ilivyo kwa faili yaliyopakuliwa kupitia baadhi ya BitTorrent clients), **ukaguzi wa Gatekeeper huenda usifanywe**. Kwa hivyo, watumiaji wanapaswa kuwa waangalifu wanapofungua faili yaliyopakuliwa kutoka kwenye vyanzo visivyo salama au visivyojulikana.

> [!NOTE] > **Kukagua** **uhalali** wa code signatures ni mchakato unaotumia **rasilimali nyingi**, unaojumuisha kutengeneza **hashes za cryptographic** za code na rasilimali zake zote zilizo bundled. Zaidi ya hayo, kukagua uhalali wa certificate kunahusisha kufanya **ukaguzi wa mtandaoni** kwenye servers za Apple ili kubaini ikiwa imebatilishwa baada ya kutolewa. Kwa sababu hizi, kufanya ukaguzi kamili wa code signature na notarization **kila app inapozinduliwa si jambo linalofaa**.
>
> Kwa hivyo, ukaguzi huu **hufanywa tu wakati wa kutekeleza apps zenye quarantined attribute.**

> [!WARNING]
> Attribute hii lazima **iwe imewekwa na application inayounda/kupakua** faili.
>
> Hata hivyo, faili zilizowekwa kwenye sandbox zitakuwa na attribute hii kwenye kila faili wanayounda. Na apps zisizo kwenye sandbox zinaweza kuiweka zenyewe, au kubainisha key ya [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) kwenye **Info.plist**, jambo ambalo litaifanya system iweke extended attribute ya `com.apple.quarantine` kwenye faili zinazoundwa,

Zaidi ya hayo, faili zote zinazoundwa na process inayowaita **`qtn_proc_apply_to_self`** huwekwa kwenye quarantine. Au API **`qtn_file_apply_to_path`** huongeza quarantine attribute kwenye path maalum ya faili.

Inawezekana **kuangalia status yake na kuiwezesha/kui-disable** (root inahitajika) kwa kutumia:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Unaweza pia **kuangalia ikiwa faili lina extended attribute ya quarantine** kwa:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Kagua **value** ya **extended** **attributes** na ubaini app iliyoandika quarantine attr kwa:
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
Kwa kweli, process "inaweza kuweka quarantine flags kwenye files inazounda" (tayari nilijaribu kutumia USER_APPROVED flag kwenye file iliyoundwa, lakini haikukubali):

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

Na **ondoa** attribute hiyo kwa kutumia:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Na pata faili zote zilizowekwa karantini kwa kutumia:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Taarifa za quarantine pia huhifadhiwa katika database kuu inayosimamiwa na LaunchServices kwenye **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, ambayo huwezesha GUI kupata data kuhusu asili ya file. Zaidi ya hayo, data hii inaweza kuandikwa upya na applications ambazo zinaweza kuwa na nia ya kuficha asili yake. Pia, hili linaweza kufanywa kupitia LaunchServices APIS.

#### **libquarantine.dylib**

Library hii inatoa functions kadhaa zinazoruhusu kubadilisha fields za extended attributes.

APIs za `qtn_file_*` hushughulikia quarantine policies za files, huku APIs za `qtn_proc_*` zikitumika kwa processes (files zilizoundwa na process). Functions zisizo-exportiwa za `__qtn_syscall_quarantine*` ndizo zinazotumia policies; functions hizo huiita `mac_syscall` kwa "Quarantine" kama argument ya kwanza, ambayo hutuma requests kwa `Quarantine.kext`.

#### **Quarantine.kext**

Kernel extension hii inapatikana tu kupitia **kernel cache kwenye mfumo**; hata hivyo, _unaweza kupakua **Kernel Debug Kit kutoka** [**https://developer.apple.com/**](https://developer.apple.com/), ambayo itakuwa na toleo la extension lenye symbols._

Kext hii itatumia MACF ku-hook calls kadhaa ili kunasa matukio yote ya file lifecycle: Creation, opening, renaming, hard-linkning... hata `setxattr`, ili kuizuia kuweka extended attribute ya `com.apple.quarantine`.

Pia hutumia MIBs kadhaa:

- `security.mac.qtn.sandbox_enforce`: Enforce quarantine pamoja na Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs zinaweza ku-execute files zilizoidhinishwa pekee

#### Provenance xattr (Ventura and later)

macOS 13 Ventura ilianzisha provenance mechanism tofauti ambayo hujazwa mara ya kwanza app iliyo kwenye quarantine inaporuhusiwa ku-run.<sup>[2]</sup> Artefacts mbili huundwa:

- `com.apple.provenance` xattr kwenye directory ya `.app` bundle (binary value yenye ukubwa usiobadilika iliyo na primary key na flags).
- Row katika table ya `provenance_tracking` ndani ya ExecPolicy database kwenye `/var/db/SystemPolicyConfiguration/ExecPolicy/`, inayohifadhi cdhash na metadata ya app.

Matumizi ya kiutendaji:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect ni kipengele cha **anti-malware** kilichojengwa ndani ya macOS. XProtect **hukagua kila application inapozinduliwa kwa mara ya kwanza au kurekebishwa, na kuilinganisha na database yake** ya malware inayojulikana na aina za faili zisizo salama. Unapopakua faili kupitia apps fulani, kama vile Safari, Mail, au Messages, XProtect hukagua faili hiyo kiotomatiki. Ikiendana na malware yoyote inayojulikana kwenye database yake, XProtect **huzuia faili hiyo kuendeshwa** na kukuarifu kuhusu tishio hilo.

Database ya XProtect **husasishwa mara kwa mara** na Apple kwa kuweka definitions mpya za malware, na masasisho haya hupakuliwa na kusakinishwa kiotomatiki kwenye Mac yako. Hii huhakikisha kuwa XProtect daima ina taarifa za sasa kuhusu vitisho vinavyojulikana hivi karibuni.

Hata hivyo, ni muhimu kutambua kwamba **XProtect si antivirus yenye vipengele kamili**. Hukagua tu orodha maalum ya vitisho vinavyojulikana na haifanyi ukaguzi wa on-access kama software nyingi za antivirus.

Unaweza kupata taarifa kuhusu update ya hivi karibuni ya XProtect kwa kuendesha:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect iko katika eneo lililolindwa na SIP kwenye **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, na ndani ya bundle unaweza kupata taarifa zinazotumiwa na XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Huruhusu code yenye cdhashes hizo kutumia legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodha ya plugins na extensions ambazo haziruhusiwi kupakiwa kupitia BundleID na TeamID, au zinazoonyesha minimum version.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules za kutambua malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 database yenye hashes za applications zilizozuiwa na TeamIDs.

Kumbuka kwamba kuna App nyingine kwenye **`/Library/Apple/System/Library/CoreServices/XProtect.app`** inayohusiana na XProtect, lakini haihusiki na mchakato wa Gatekeeper.

> XProtect Remediator: Kwenye macOS za kisasa, Apple husambaza on-demand scanners (XProtect Remediator) zinazotumia launchd mara kwa mara kutambua na kurekebisha familia za malware. Unaweza kuona scans hizi kwenye unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Sio Gatekeeper

> [!CAUTION]
> Kumbuka kwamba Gatekeeper **haitekelezwi kila mara** unapotekeleza application; ni _**AppleMobileFileIntegrity**_ pekee inayothibitisha **executable code signatures** unapotekeleza app ambayo tayari ilikuwa imetekelezwa na kuthibitishwa na Gatekeeper.

Kwa hiyo, hapo awali iliwezekana kutekeleza app ili kui-cache na Gatekeeper, kisha **kubadilisha files ambazo si executables za application** (kama Electron asar au NIB files), na ikiwa hakukuwa na protections nyingine, application **ilitekelezwa** ikiwa na additions **zenye malicious**.

Hata hivyo, sasa hili haliwezekani kwa sababu macOS **inazuia kubadilishwa kwa files** zilizo ndani ya applications bundles. Kwa hiyo, ukijaribu [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack, utagundua kwamba haiwezekani tena kuitumia vibaya, kwa sababu baada ya kutekeleza app ili kui-cache na Gatekeeper, hutaweza kubadilisha bundle. Na ukibadilisha, kwa mfano, jina la directory ya Contents kuwa NotCon (kama ilivyoonyeshwa kwenye exploit), kisha ukatekeleza main binary ya app ili kui-cache na Gatekeeper, itasababisha error na haitatekelezwa.

## Gatekeeper Bypasses

Njia yoyote ya kubypass Gatekeeper (kufanikiwa kumfanya user adownload kitu na kukitekeleza wakati Gatekeeper inapaswa kukizuia) inachukuliwa kuwa vulnerability kwenye macOS. Hizi ni baadhi ya CVEs zilizotolewa kwa techniques zilizowezesha kubypass Gatekeeper hapo awali:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilibainika kwamba ikiwa **Archive Utility** inatumika kwa extraction, files zenye **paths zinazozidi characters 886** hazipewi extended attribute ya com.apple.quarantine. Hali hii inaruhusu files hizo bila kukusudiwa **kukwepa** security checks za Gatekeeper.<sup>[5]</sup>

Angalia [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa maelezo zaidi.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wakati application inaundwa kwa kutumia **Automator**, taarifa kuhusu inachohitaji kutekeleza huwa ndani ya `application.app/Contents/document.wflow`, si kwenye executable. Executable ni generic Automator binary tu inayoitwa **Automator Application Stub**.

Kwa hiyo, ungeweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **ielekeze kwa symbolic link kwenye Automator Application Stub nyingine iliyo ndani ya system**, na itatekeleza kilicho ndani ya `document.wflow` (script yako) **bila ku-trigger Gatekeeper**, kwa sababu executable halisi haina quarantine xattr.<sup>[6]</sup>

Mfano wa location inayotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Angalia [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa maelezo zaidi.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika bypass hii, zip file iliundwa ikiwa na application iliyoanza ku-compress kutoka `application.app/Contents` badala ya `application.app`. Kwa hiyo, **quarantine attr** ilitumika kwa **files zote kutoka `application.app/Contents`** lakini **si kwa `application.app`**, ambayo ndiyo Gatekeeper ilikuwa iki-check; hivyo Gatekeeper ilibypassiwa kwa sababu `application.app` ilipo-triggeriwa **haikuwa na quarantine attribute.**<sup>[7]</sup>
```bash
zip -r test.app/Contents test.zip
```
Angalia [**ripoti ya awali**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa maelezo zaidi.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama components ni tofauti, exploitation ya vulnerability hii inafanana sana na ile ya awali. Katika hali hii, tutatengeneza Apple Archive kutoka **`application.app/Contents`**, hivyo **`application.app` haitapata quarantine attr** itakapodecompressed na **Archive Utility**.<sup>[8]</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Angalia [**ripoti ya awali**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kwa maelezo zaidi.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** inaweza kutumiwa kumzuia mtu yeyote kuandika attribute katika faili:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Zaidi ya hayo, umbizo la faili la **AppleDouble** linakili faili pamoja na ACEs zake.<sup>[9]</sup>

Katika [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba uwakilishi wa maandishi wa ACL uliohifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL katika faili iliyofunguliwa kutoka kwenye archive. Kwa hiyo, ikiwa ungecompress application kuwa faili la zip kwa kutumia umbizo la faili la **AppleDouble**, lenye ACL inayozuia xattrs nyingine kuandikwa humo... quarantine xattr haikuwekwa kwenye application:
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

Ilibainika kuwa **Google Chrome haikuwa ikiweka quarantine attribute** kwenye mafaili yaliyopakuliwa kwa sababu ya matatizo fulani ya ndani ya macOS.<sup>[10]</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Miundo ya mafaili ya AppleDouble huhifadhi attributes za faili kwenye faili tofauti inayoanza na `._`; hii husaidia kunakili attributes za faili **kati ya mashine za macOS**. Hata hivyo, ilibainika kuwa baada ya kufungua faili ya AppleDouble, faili inayoanza na `._` **haikupewa quarantine attribute**.<sup>[11]</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Kuweza kuunda faili ambalo halitakuwa na sifa ya quarantine, **iliwezekana kubypass Gatekeeper.** Mbinu ilikuwa **kuunda application ya faili ya DMG** kwa kutumia kanuni ya majina ya AppleDouble (kuanza na `._`) na kuunda **faili inayoonekana kama sym link ya** faili hii iliyofichwa bila sifa ya quarantine.\
**Faili ya dmg inapotekelezwa**, kwa kuwa haina sifa ya quarantine, **itapita Gatekeeper.**
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

Gatekeeper bypass iliyorekebishwa katika macOS Sonoma 14.0 iliruhusu apps zilizoundwa mahsusi kuendeshwa bila kuomba ruhusa. Maelezo yalifichuliwa hadharani baada ya patching, na tatizo hilo lilikuwa likitumiwa kikamilifu porini kabla ya kurekebishwa. Hakikisha Sonoma 14.0 au toleo la baadaye limesakinishwa.

### [CVE-2024-27853]

Gatekeeper bypass katika macOS 14.4 (iliyotolewa Machi 2024), iliyotokana na jinsi `libarchive` ilivyoshughulikia ZIPs hasidi, iliruhusu apps kukwepa assessment. Update hadi 14.4 au toleo la baadaye, ambapo Apple ilishughulikia tatizo hilo.<sup>[1]</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** iliyowekwa ndani ya app iliyopakuliwa ingeweza kuanzishwa bila Gatekeeper assessment, kwa sababu workflows zilichukuliwa kama data na kutekelezwa na Automator helper nje ya njia ya kawaida ya notarization prompt. Kwa hivyo, `.app` iliyoundwa mahsusi na inayobeba Quick Action inayoendesha shell script (kwa mfano, ndani ya `Contents/PlugIns/*.workflow/Contents/document.wflow`) ingeweza kutekelezwa mara moja wakati wa launch. Apple iliongeza dialog ya ziada ya consent na kurekebisha assessment path katika Ventura **13.7**, Sonoma **14.7**, na Sequoia **15**.<sup>[3]</sup>

### Third‑party unarchivers kusambaza vibaya quarantine (2023–2024)

Vulnerabilities kadhaa katika extraction tools maarufu (kwa mfano, The Unarchiver) zilisababisha files zilizotolewa kutoka kwenye archives kukosa `com.apple.quarantine` xattr, hivyo kuwezesha fursa za Gatekeeper bypass. Tegemea kila mara macOS Archive Utility au tools zilizopigwa patch wakati wa testing, na uhakikishe xattrs baada ya extraction.

### uchg (kutoka [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf) hii)

- Create directory yenye app.
- Add uchg kwenye app.
- Compress app kuwa faili ya tar.gz.
- Tuma faili ya tar.gz kwa victim.
- Victim anafungua faili ya tar.gz na anaendesha app.
- Gatekeeper hai-check app.<sup>[12]</sup>

### Zuia Quarantine xattr

Katika bundle ya ".app", ikiwa quarantine xattr haijaongezwa ndani yake, wakati wa kui-execute **Gatekeeper haitatriggeriwa**.


## Marejeo

- [1] [Apple Platform Security: Kuhusu maudhui ya usalama ya macOS Sonoma 14.4 (inajumuisha CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Jinsi macOS sasa inavyofuatilia provenance ya apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia inaondoa Control‑click “Open” Gatekeeper bypass](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: Ugunduzi wa CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Kukwepa macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs imetambua Safari vulnerability inayoruhusu Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs imetambua macOS Archive Utility vulnerability inayoruhusu Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Achilles heel ya Gatekeeper: Kugundua macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ugunduzi wa Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Kupata na kuripoti Gatekeeper bypass exploit kwa msaada wa Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Kukwepa macOS Security and Privacy Mechanisms — Kutoka Gatekeeper hadi System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
