# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ni kipengele cha usalama kilichotengenezwa kwa mifumo ya uendeshaji ya Mac, kilichoundwa kuhakikisha kuwa watumiaji **wanaendesha programu zinazoaminika pekee** kwenye mifumo yao. Hufanya kazi kwa **kuthibitisha programu** ambazo mtumiaji anapakua na kujaribu kufungua kutoka **vyanzo vilivyo nje ya App Store**, kama vile app, plug-in au kifurushi cha kisakinishi.

Utaratibu mkuu wa Gatekeeper ni mchakato wake wa **uthibitishaji**. Hukagua kama programu iliyopakuliwa **imesainiwa na msanidi anayetambulika**, ili kuhakikisha uhalisi wa programu. Pia huthibitisha kama programu **imeidhinishwa na Apple (notarised)**, ikihakikisha kuwa haina maudhui hasidi yanayojulikana na haijabadilishwa baada ya kuidhinishwa.

Zaidi ya hayo, Gatekeeper huimarisha udhibiti wa mtumiaji na usalama kwa **kuwaomba watumiaji waidhinishe kufunguliwa** kwa programu iliyopakuliwa mara ya kwanza. Kinga hii husaidia kuzuia watumiaji kuendesha bila kukusudia code inayoweza kudhuru, ambayo huenda waliidhani kimakosa kuwa faili ya data isiyo na madhara.

### Application Signatures

Saini za programu, zinazojulikana pia kama saini za code, ni sehemu muhimu ya miundombinu ya usalama ya Apple. Hutumika **kuthibitisha utambulisho wa mwandishi wa programu** (msanidi) na kuhakikisha kuwa code haijabadilishwa tangu iliposainiwa mara ya mwisho.

Hivi ndivyo inavyofanya kazi:

1. **Kusaini Application:** Msanidi anapokuwa tayari kusambaza application yake, **husaini application kwa kutumia ufunguo binafsi**. Ufunguo huu binafsi unahusishwa na **cheti ambacho Apple humpa msanidi** anapojiandikisha kwenye Apple Developer Program. Mchakato wa kusaini huhusisha kuunda hash ya kriptografia ya sehemu zote za app na kusimba hash hiyo kwa ufunguo binafsi wa msanidi.
2. **Kusambaza Application:** Kisha application iliyosainiwa husambazwa kwa watumiaji pamoja na cheti cha msanidi, ambacho kina ufunguo wa umma unaolingana.
3. **Kuthibitisha Application:** Mtumiaji anapopakua na kujaribu kuendesha application, mfumo wa uendeshaji wa Mac hutumia ufunguo wa umma kutoka kwenye cheti cha msanidi kusimbua hash. Kisha hukokotoa upya hash kulingana na hali ya sasa ya application na kuilinganisha na hash iliyosimbuliwa. Zikilingana, inamaanisha **application haijabadilishwa** tangu msanidi aliposisaini, na mfumo huruhusu application kuendeshwa.

Saini za application ni sehemu muhimu ya teknolojia ya Gatekeeper ya Apple. Mtumiaji anapojaribu **kufungua application iliyopakuliwa kutoka kwenye intaneti**, Gatekeeper huthibitisha saini ya application. Ikiwa imesainiwa kwa cheti kilichotolewa na Apple kwa msanidi anayejulikana, na code haijabadilishwa, Gatekeeper huruhusu application kuendeshwa. Vinginevyo, huzuia application na kumtahadharisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper hukagua pia kama application imeidhinishwa na Apple**, na kuongeza safu nyingine ya usalama. Mchakato wa kuidhinisha hukagua application ili kubaini matatizo ya usalama yanayojulikana na code hasidi. Ukaguzi huu ukifaulu, Apple huongeza tiketi kwenye application ambayo Gatekeeper inaweza kuthibitisha.

#### Check Signatures

Unapokagua **sampuli ya malware**, unapaswa **kukagua saini** ya binary kila mara, kwa kuwa **msanidi** aliyeisaini anaweza kuwa tayari **anahusishwa** na **malware**.

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

### Uthibitishaji wa Apple

Mchakato wa Apple wa notarization ni kinga ya ziada inayolinda watumiaji dhidi ya programu zinazoweza kuwa hatari. Unahusisha **msanidi kuwasilisha programu yake ichunguzwe** na **Apple's Notary Service**, ambayo haipaswi kuchanganywa na App Review. Huduma hii ni **mfumo wa kiotomatiki** unaokagua programu iliyowasilishwa ili kubaini kama ina **maudhui hasidi** au matatizo yoyote yanayoweza kuhusiana na kusaini msimbo.

Programu **ikifaulu** ukaguzi huu bila kubainika kuwa na tatizo lolote, Notary Service hutengeneza tiketi ya notarization. Kisha msanidi anatakiwa **kuambatisha tiketi hii kwenye programu yake**; mchakato huu huitwa 'stapling.' Zaidi ya hayo, tiketi ya notarization huchapishwa pia mtandaoni, ambako Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuipata.

Mtumiaji anaposakinisha au kutekeleza programu kwa mara ya kwanza, kuwepo kwa tiketi ya notarization — iwe imeambatishwa kwenye faili inayotekelezeka au imepatikana mtandaoni — **huifahamisha Gatekeeper kwamba Apple imefanya notarization ya programu hiyo**. Kwa hiyo, Gatekeeper huonyesha ujumbe wa maelezo katika kisanduku cha mazungumzo cha uzinduzi wa kwanza, unaoonyesha kwamba Apple imekagua programu hiyo ili kubaini maudhui hasidi. Mchakato huu huongeza imani ya watumiaji kuhusu usalama wa programu wanazosakinisha au kuendesha kwenye mifumo yao.

### spctl & syspolicyd

> [!CAUTION]
> Kumbuka kwamba kuanzia toleo la Sequoia, **`spctl`** hairuhusu tena kurekebisha usanidi wa Gatekeeper.

**`spctl`** ni zana ya CLI ya kuorodhesha na kuingiliana na Gatekeeper (kupitia daemon ya `syspolicyd` kwa kutumia ujumbe wa XPC). Kwa mfano, inawezekana kuona **hali** ya GateKeeper kwa kutumia:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Kumbuka kuwa ukaguzi wa sahihi wa GateKeeper hufanywa tu kwa **faili zenye sifa ya Quarantine**, si kwa kila faili.

GateKeeper itaangalia ikiwa binary inaweza kutekelezwa kulingana na **mapendeleo na sahihi**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ndiyo daemon kuu inayohusika na kutekeleza Gatekeeper. Hudumisha database iliyo katika `/var/db/SystemPolicy`, na inawezekana kupata code inayotumika kusaidia [database hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) na [kiolezo cha SQL hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Kumbuka kuwa database hii haizuiliwi na SIP na inaweza kuandikwa na root, na database `/var/db/.SystemPolicy-default` hutumika kama nakala rudufu ya awali endapo nyingine itaharibika.

Zaidi ya hayo, bundle **`/var/db/gke.bundle`** na **`/var/db/gkopaque.bundle`** zina faili zenye sheria zinazoingizwa kwenye database. Unaweza kuangalia database hii kama root kwa kutumia:

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

**`syspolicyd`** pia hutoa seva ya XPC yenye shughuli mbalimbali kama `assess`, `update`, `record` na `cancel`, ambazo pia zinaweza kufikiwa kwa kutumia API za **`Security.framework`'s `SecAssessment*`**; na **`spctl`** kwa hakika huwasiliana na **`syspolicyd`** kupitia XPC.

Kumbuka kwamba sheria ya kwanza iliishia kwa "**App Store**" na ya pili kwa "**Developer ID**", na kwamba katika picha iliyotangulia ilikuwa **imewezeshwa kutekeleza programu kutoka App Store na za wasanidi waliotambuliwa**.\
Uk**ibadilisha** mpangilio huo kuwa App Store, sheria za "**Notarized Developer ID" zitatoweka**.

Pia kuna maelfu ya sheria za **aina ya GKE** :

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Hizi ni hashes zinazotoka kwenye:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Au unaweza kuorodhesha maelezo yaliyotangulia kwa kutumia:

```bash
sudo spctl --list
```

Chaguo **`--master-disable`** na **`--global-disable`** za **`spctl`** **huzima** kabisa ukaguzi huu wa sahihi:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Ikiwashwa kikamilifu, chaguo jipya litaonekana:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Inawezekana **kuangalia ikiwa App itaruhusiwa na GateKeeper** kwa kutumia:

```bash
spctl --assess -v /Applications/App.app
```

Kwenye macOS 14 na matoleo ya baadaye, **`syspolicy_check`** ni ukaguzi muhimu wa kiwango cha juu kabla ya kusambaza bundle ya programu. Hutoa uchunguzi wa trusted-execution unaoweza kuchukuliwa hatua kwa urahisi zaidi kuliko matokeo ya kawaida ya `spctl`, ingawa Apple bado inapendekeza kujaribu mchakato halisi wa kupakua/kutoa faili/kuanzisha kwa mara ya kwanza, kwa sababu hilo pia hujaribu usambazaji wa quarantine.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
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

Kuhusu **kernel extensions**, folda `/var/db/SystemPolicyConfiguration` ina faili zenye orodha za kext zinazoruhusiwa kupakiwa. Zaidi ya hayo, `spctl` ina entitlement `com.apple.private.iokit.nvram-csr` kwa sababu inaweza kuongeza kernel extensions mpya zilizoidhinishwa awali, ambazo pia zinahitaji kuhifadhiwa kwenye NVRAM katika key ya `kext-allowed-teams`.

#### Kusimamia Gatekeeper kwenye macOS 15 (Sequoia) na matoleo ya baadaye

- Njia ya muda mrefu ya kukwepa kizuizi kwa kutumia Finder **Ctrl+Open / Right-click → Open** imeondolewa; watumiaji lazima waruhusu waziwazi app iliyozuiwa kupitia **System Settings → Privacy & Security → Open Anyway** baada ya kidirisha cha kwanza cha kuzuia kuonekana.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` hazikubaliwi tena kama mabadiliko ya sera yasiyohitaji usimamizi. Vitendo vinavyorekebisha hifadhidata ya sheria au hali ya jumla ya ukaguzi vimepitwa na wakati, kwa hiyo tumia `spctl` kwa ukaguzi na usanidi utekelezaji kupitia UI au MDM.

Kuanzia macOS 15 Sequoia, watumiaji wa mwisho hawawezi tena kubadilisha sera ya Gatekeeper kupitia `spctl`. Usimamizi hufanywa kupitia System Settings au kwa kusambaza wasifu wa usanidi wa MDM wenye payload ya `com.apple.systempolicy.control`. Mfano wa sehemu ya wasifu inayoruhusu App Store na watengenezaji waliotambuliwa (lakini si "Anywhere"):

<details>
<summary>Wasifu wa MDM wa kuruhusu App Store na watengenezaji waliotambuliwa</summary>

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

Wakati wa **kupakua** programu au faili, **programu** fulani za macOS kama vile vivinjari vya wavuti au programu za barua pepe **huongeza sifa iliyopanuliwa ya faili**, inayojulikana kwa kawaida kama "**alama ya quarantine**," kwenye faili iliyopakuliwa. Sifa hii hutumika kama hatua ya usalama ya **kuashiria faili** kuwa imetoka kwenye chanzo kisichoaminika (intaneti), na huenda ikawa na hatari. Hata hivyo, si programu zote huongeza sifa hii; kwa mfano, programu za kawaida za mteja wa BitTorrent kwa kawaida huruka hatua hii.

**Kuwepo kwa alama ya quarantine hujulisha kipengele cha usalama cha macOS, Gatekeeper, mtumiaji anapojaribu kutekeleza faili**.

Ikiwa **alama ya quarantine haipo** (kama ilivyo kwa faili zilizopakuliwa kupitia baadhi ya programu za mteja wa BitTorrent), **ukaguzi wa** Gatekeeper huenda **usifanyike**. Kwa hivyo, watumiaji wanapaswa kuwa waangalifu wanapofungua faili zilizopakuliwa kutoka kwenye vyanzo visivyo salama au visivyojulikana.

> [!NOTE] > **Kukagua** **uhalali** wa sahihi za msimbo ni mchakato unaotumia **rasilimali nyingi**, unaojumuisha kutengeneza **hashes** za kriptografia za msimbo na rasilimali zote zilizounganishwa nao. Zaidi ya hayo, kukagua uhalali wa cheti kunahusisha kufanya **ukaguzi mtandaoni** kwenye seva za Apple ili kuona kama cheti kimebatilishwa baada ya kutolewa. Kwa sababu hizi, kufanya ukaguzi kamili wa sahihi ya msimbo na notarization **kila mara programu inapozinduliwa si jambo linalowezekana**.
>
> Kwa hivyo, ukaguzi huu **hufanywa tu wakati wa kutekeleza programu zilizo na sifa ya quarantine.**

> [!WARNING]
> Sifa hii lazima **iwekezwe na programu inayounda/kupakua** faili.
>
> Hata hivyo, faili zitakazoundwa na programu zilizo kwenye sandbox zitakuwa na sifa hii. Programu ambazo haziko kwenye sandbox zinaweza kuiongeza zenyewe, au kubainisha kitufe cha [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) katika **Info.plist**, jambo litakalofanya mfumo uweke sifa iliyopanuliwa ya `com.apple.quarantine` kwenye faili zilizoundwa,

Zaidi ya hayo, faili zote zinazoundwa na mchakato unaoitisha **`qtn_proc_apply_to_self`** huwekwa kwenye quarantine. Au API **`qtn_file_apply_to_path`** huongeza sifa ya quarantine kwenye njia maalum ya faili.

Inawezekana **kuangalia hali yake na kuiwasha/kuzima** (ruhusa za root zinahitajika) kwa kutumia:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Unaweza pia **kubaini kama faili lina sifa iliyopanuliwa ya quarantine** kwa kutumia:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Angalia **thamani** ya **sifa** **zilizopanuliwa** na utambue programu iliyoandika sifa ya quarantine kwa kutumia:

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

Kwa kweli, mchakato “unaweza kuweka quarantine flags kwenye faili unazounda” (tayari nilijaribu kuweka flag ya USER_APPROVED kwenye faili lililoundwa, lakini haikuwezekana):

<details>

<summary>Msimbo wa Chanzo: weka quarantine flags</summary>

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

Na upate faili zote zilizowekwa karantini kwa kutumia:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Taarifa za Quarantine pia huhifadhiwa katika hifadhidata kuu inayosimamiwa na LaunchServices kwenye **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, ambayo huruhusu GUI kupata data kuhusu asili ya faili. Zaidi ya hayo, programu zinazoweza kutaka kuficha asili yake zinaweza kuibadilisha. Pia, hili linaweza kufanywa kupitia LaunchServices APIs.

#### **libquarantine.dylib**

Maktaba hii husafirisha functions kadhaa zinazoruhusu kudhibiti sehemu za extended attribute.

APIs za `qtn_file_*` hushughulikia sera za file quarantine, huku APIs za `qtn_proc_*` zikitumika kwa processes (faili zilizoundwa na process). Functions zisizosafirishwa za `__qtn_syscall_quarantine*` ndizo zinazotekeleza sera hizo kwa kuita `mac_syscall` na kutumia "Quarantine" kama argument ya kwanza, jambo linalotuma maombi kwa `Quarantine.kext`.

#### **Quarantine.kext**

Kernel extension hii inapatikana tu kupitia **kernel cache kwenye mfumo**; hata hivyo, _unaweza_ kupakua **Kernel Debug Kit kutoka** [**https://developer.apple.com/**](https://developer.apple.com/), ambayo itakuwa na toleo la extension lenye alama za symbols.

Kext hii hutumia MACF ku-hook calls kadhaa ili kunasa matukio yote ya mzunguko wa maisha wa faili: kuunda, kufungua, kubadilisha jina, kuunda hard link... hata `setxattr`, ili kuizuia kuweka extended attribute ya `com.apple.quarantine`.

Pia hutumia MIB kadhaa:

- `security.mac.qtn.sandbox_enforce`: Tekeleza quarantine pamoja na Sandbox
- `security.mac.qtn.user_approved_exec`: Procs zilizo kwenye quarantine zinaweza kuendesha faili zilizoidhinishwa pekee

#### Provenance xattr (Ventura na matoleo ya baadaye)

macOS 13 Ventura ilianzisha utaratibu tofauti wa provenance ambao hujazwa mara ya kwanza app iliyo kwenye quarantine inaporuhusiwa kuendeshwa.<sup>[[2]](#references)</sup> Vipengee viwili huundwa:

- xattr ya `com.apple.provenance` kwenye saraka ya `.app` bundle (thamani ya binary yenye ukubwa usiobadilika, iliyo na primary key na flags).
- Safu katika jedwali la `provenance_tracking` ndani ya hifadhidata ya ExecPolicy kwenye `/var/db/SystemPolicyConfiguration/ExecPolicy/`, inayohifadhi cdhash na metadata za app.

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

XProtect ni kipengele cha **anti-malware** kilichojengewa ndani ya macOS. XProtect **hukagua kila programu inapozinduliwa au kurekebishwa kwa mara ya kwanza, kwa kuilinganisha na hifadhidata yake** ya malware inayojulikana na aina za faili zisizo salama. Unapopakua faili kupitia baadhi ya programu, kama Safari, Mail, au Messages, XProtect huchanganua faili hiyo kiotomatiki. Ikiwa inalingana na malware yoyote inayojulikana katika hifadhidata yake, XProtect **huzuia faili hiyo kufanya kazi** na kukuarifu kuhusu tishio hilo.

Apple **husasisha hifadhidata ya XProtect mara kwa mara** kwa ufafanuzi mpya wa malware, na masasisho haya hupakuliwa na kusakinishwa kiotomatiki kwenye Mac yako. Hii huhakikisha kuwa XProtect inakuwa na taarifa za hivi karibuni kuhusu vitisho vinavyojulikana.

Hata hivyo, ni muhimu kutambua kuwa **XProtect si suluhisho kamili la antivirus**. Hukagua tu orodha maalum ya vitisho vinavyojulikana na haichanganui faili zinapofikiwa kama programu nyingi za antivirus.

Unaweza kupata taarifa kuhusu sasisho la hivi karibuni la XProtect kwa kuendesha:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect iko katika eneo linalolindwa na SIP kwenye **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, na ndani ya bundle unaweza kupata taarifa zinazotumiwa na XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Huruhusu code yenye cdhash hizo kutumia legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodha ya plugins na extensions ambazo haziruhusiwi kupakiwa kupitia BundleID na TeamID au zinazoonyesha toleo la chini kabisa linalohitajika.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Kanuni za Yara za kugundua malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Hifadhidata ya SQLite3 yenye hashes za programu zilizozuiwa na TeamIDs.

Kumbuka kuwa kuna App nyingine kwenye **`/Library/Apple/System/Library/CoreServices/XProtect.app`** inayohusiana na XProtect, lakini haihusiki na mchakato wa Gatekeeper.

> XProtect Remediator: Kwenye macOS za kisasa, Apple husambaza vichanganuzi vinavyoendeshwa unapovitaka (XProtect Remediator), ambavyo huendeshwa mara kwa mara kupitia launchd ili kugundua na kurekebisha familia za malware. Unaweza kuona uchanganuzi huu kwenye unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Sio Gatekeeper

> [!CAUTION]
> Kumbuka kwamba Gatekeeper **haiendeshwi kila unapotekeleza** programu. _**AppleMobileFileIntegrity**_ (AMFI) **huthibitisha tu sahihi za msimbo unaotekelezeka** unapotekeleza programu ambayo tayari ilitekelezwa na kuthibitishwa na Gatekeeper.

Kwa hiyo, hapo awali iliwezekana kutekeleza programu ili ihifadhiwe kwenye cache ya Gatekeeper, kisha **kurekebisha faili zisizotekelezeka za programu** (kama vile Electron asar au faili za NIB). Ikiwa hakukuwa na ulinzi mwingine, programu **ingetekelezwa** ikiwa na nyongeza **hasidi**.

Hata hivyo, hili haliwezekani tena kwa sababu macOS **huzuia kurekebishwa kwa faili** zilizo ndani ya app bundles. Kwa hiyo, ukijaribu shambulio la [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), utagundua kwamba haliwezekani tena kulitumia vibaya. Baada ya kutekeleza programu ili ihifadhiwe kwenye cache ya Gatekeeper, hutaweza kurekebisha bundle. Na ukibadilisha, kwa mfano, jina la directory ya Contents kuwa NotCon (kama ilivyoelekezwa kwenye exploit), kisha utekeleze binary kuu ya programu ili ihifadhiwe kwenye cache ya Gatekeeper, kosa litatokea na programu haitatekelezwa.

## Gatekeeper Bypasses

Njia yoyote ya kukwepa Gatekeeper (kufanikiwa kumfanya mtumiaji apakue kitu na kukitekeleza wakati Gatekeeper inapaswa kukizuia) huchukuliwa kuwa udhaifu katika macOS. Hizi ni baadhi ya CVE zilizotolewa kwa mbinu zilizowezesha kukwepa Gatekeeper hapo awali:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilibainika kwamba **Archive Utility** inapotumika kutoa faili kwenye archive, faili zenye **path zinazozidi herufi 886** hazipewi extended attribute ya com.apple.quarantine. Hali hii husababisha faili hizo **kukwepa** ukaguzi wa usalama wa Gatekeeper bila kukusudia.<sup>[[5]](#references)</sup>

Angalia [**ripoti ya awali**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa maelezo zaidi.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Programu inapoundwa kwa **Automator**, maelezo kuhusu inachohitaji kutekeleza huwa ndani ya `application.app/Contents/document.wflow`, si kwenye executable. Executable ni binary ya kawaida tu ya Automator inayoitwa **Automator Application Stub**.

Kwa hiyo, ungeweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **ielekeze kwa symbolic link kwenda kwa Automator Application Stub nyingine iliyo ndani ya mfumo**, na itatekeleza kilicho ndani ya `document.wflow` (script yako) **bila kuanzisha Gatekeeper**, kwa sababu executable halisi haina quarantine xattr.<sup>[[6]](#references)</sup>

Mfano wa eneo linalotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Angalia [**ripoti ya awali**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa maelezo zaidi.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika bypass hii, faili ya zip iliundwa kwa kuanza kubana programu kutoka `application.app/Contents` badala ya `application.app`. Kwa hiyo, **quarantine attr** ilitumika kwa **faili zote zilizo ndani ya `application.app/Contents`**, lakini **haikutumika kwa `application.app`**, ambayo ndiyo ilikuwa ikikaguliwa na Gatekeeper. Hivyo, Gatekeeper ilikwepwa kwa sababu `application.app` ilipoanzishwa **haikuwa na quarantine attribute.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Angalia [**ripoti asili**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa maelezo zaidi.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama vipengele ni tofauti, exploitation ya vulnerability hii inafanana sana na ile iliyotangulia. Katika hali hii, tutaunda Apple Archive kutoka **`application.app/Contents`** ili **`application.app` isipate quarantine attr** inapofunguliwa kwa kubanuliwa na **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Angalia [**ripoti ya asili**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kwa maelezo zaidi.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** inaweza kutumiwa kuzuia mtu yeyote kuandika attribute kwenye faili:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Kwa utaratibu wa `com.apple.acl.text`/AppleDouble na uzalishaji kamili wa sidecar, angalia [uzalishaji upya wa bypass ya quarantine ya AppleDouble ACL](macos-fs-tricks/macos-appledouble-acl-quarantine-bypass.md). Tofauti ya ZIP ya programu ya Gatekeeper hutumia mfuatano ufuatao:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Angalia [**ripoti ya awali**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.<sup>[[9]](#references)</sup>

Kumbuka kuwa hili linaweza pia kutumiwa kupitia AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Iligunduliwa kuwa **Google Chrome haikuwa ikiweka sifa ya quarantine** kwenye faili zilizopakuliwa kutokana na matatizo fulani ya ndani ya macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble huhifadhi sifa za faili kwenye faili tofauti ambayo jina lake huanza na `._`; hii husaidia kunakili sifa za faili **kati ya mashine za macOS**. Hata hivyo, baada ya kufungua faili ya AppleDouble iliyobanwa, faili inayoanza na `._` **haikuwekewa sifa ya quarantine**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Kwa kuwa iliwezekana kuunda faili ambayo haitakuwa na sifa ya quarantine, **iliwezekana kukwepa Gatekeeper.** Mbinu hiyo ilikuwa **kuunda faili ya application ya DMG** kwa kutumia kanuni ya majina ya AppleDouble (kuanza na `._`) na kuunda **faili inayoonekana kama symlink ya faili hii iliyofichwa** isiyo na sifa ya quarantine.\
**Faili ya DMG inapotekelezwa**, kwa kuwa haina sifa ya quarantine, **itakwepa Gatekeeper**.

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

Apple ilirekebisha hitilafu ya mantiki ya LaunchServices katika macOS Sonoma 14.0 kwa kuboresha ukaguzi. Ushauri wa umma unasema tu kwamba app ingeweza kukwepa Gatekeeper, kwa hivyo usikisie fomati mahususi ya carrier au mnyororo wa unyonyaji kutokana na ingizo la CVE pekee.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Udhaifu wa kukwepa Gatekeeper katika macOS 14.4 (iliyotolewa Machi 2024), uliotokana na jinsi `libarchive` ilivyoshughulikia ZIP hasidi, uliwezesha apps kukwepa tathmini. Sasisha hadi 14.4 au toleo la baadaye ambako Apple ilishughulikia tatizo hilo.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** iliyopachikwa ndani ya app iliyopakuliwa ingeweza kuanzishwa bila tathmini ya Gatekeeper, kwa sababu workflows zilichukuliwa kama data na kutekelezwa na Automator helper nje ya mchakato wa kawaida wa kuonyesha kidokezo cha notarization. Kwa hiyo, `.app` iliyoundwa mahsusi na kuwekewa Quick Action inayoendesha shell script (kwa mfano, ndani ya `Contents/PlugIns/*.workflow/Contents/document.wflow`) ingeweza kutekelezwa mara moja wakati wa kuzinduliwa. Apple iliongeza kisanduku cha ziada cha idhini na kurekebisha mchakato wa tathmini katika Ventura **13.7**, Sonoma **14.7**, na Sequoia **15**.<sup>[[3]](#references)</sup>

### Hitilafu za uenezaji wa quarantine wakati wa uchimbaji na kunakili

Utafiti wa 2024 uligundua mapengo ya uenezaji katika matoleo yaliyojaribiwa ya iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z), na 7z Utility (DMG/ZIP/7Z); pia ulibaini kuwa sifa hiyo ilipotea wakati wa kunakili kutoka host kwenda guest kwa kutumia VMware Tools. Wauzaji kadhaa walitangaza marekebisho baadaye, kwa hiyo chukulia majina haya kama vidokezo vya **kujaribu tena matoleo mahususi**, si kama orodha ya kudumu ya software zilizo hatarini. Tatizo hilo hilo la mpaka wa uaminifu linahusu pia workflows asilia za Unix: `curl`/`scp` haziongezi quarantine, na `tar`/`unzip` za command line hazirithi quarantine kiotomatiki kutoka kwenye archive ya carrier.<sup>[[15]](#references)</sup>

Kwa majaribio ya kiusalama, linganisha carrier na app ya mwisho baada ya **kila** hatua ya mpito kupitia browser, mail client, archive, disk image, cloud-sync, shared folder, na kunakili VM. Kukataliwa waziwazi na `spctl` hakurekebishi xattr iliyokosekana: bila quarantine, huenda mchakato wa kawaida wa Gatekeeper wakati wa kufungua kwa mara ya kwanza usiombe tathmini hiyo kamwe.<sup>[[15]](#references)</sup>

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

### uchg (kutoka kwenye [mazungumzo haya](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Unda directory iliyo na app.
- Ongeza uchg kwenye app.
- Finya app iwe faili la tar.gz.
- Tuma faili la tar.gz kwa mwathiriwa.
- Mwathiriwa afungue faili la tar.gz na aendeshe app.
- Gatekeeper haiikaguzi app.<sup>[[12]](#references)</sup>

### Kuzuia Quarantine xattr

Katika kifurushi cha ".app", ikiwa quarantine xattr haijaongezwa kwake, **Gatekeeper haitawashwa** wakati wa kuiendesha.

Tazama [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) kwa mbinu za filesystem, flag, ACL na AppleDouble zinazoweza kuzuia au kuondoa extended attributes.





## References

- [1] [Usalama wa Apple Platform: Kuhusu maudhui ya usalama ya macOS Sonoma 14.4 (inajumuisha CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Jinsi macOS sasa inavyofuatilia asili ya apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia yaondoa njia ya kukwepa Gatekeeper ya kubofya “Open” kwa Control](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Ugunduzi wa CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Kukwepa macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs yatambua udhaifu wa Safari unaoruhusu kukwepa Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs yatambua udhaifu wa macOS Archive Utility unaoruhusu kukwepa Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Achilles heel ya Gatekeeper: Kugundua udhaifu wa macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ugunduzi wa njia ya kukwepa Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Kupata na kuripoti exploit ya kukwepa Gatekeeper kwa msaada wa Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Kukwepa mifumo ya usalama na faragha ya macOS — Kutoka Gatekeeper hadi System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Kujaribu bidhaa iliyothibitishwa kwa notarization](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Kukwepa Gatekeeper — Kufichua udhaifu katika mfumo wa usalama wa macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
