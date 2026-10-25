# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ni kipengele cha usalama kilichotengenezwa kwa ajili ya mifumo ya uendeshaji ya Mac, kinachohakikisha kuwa watumiaji **wanaendesha programu zinazoaminika pekee** kwenye mifumo yao. Hufanya hivi kwa **kuthibitisha programu** ambazo mtumiaji anapakua na kujaribu kufungua kutoka **vyanzo vilivyo nje ya App Store**, kama vile app, plug-in au kifurushi cha kisakinishi.

Utaratibu mkuu wa Gatekeeper ni mchakato wake wa **uthibitishaji**. Hukagua ikiwa programu iliyopakuliwa **imesainiwa na developer anayetambulika**, ili kuhakikisha uhalisi wa programu hiyo. Pia huthibitisha ikiwa programu **imeidhinishwa na Apple kupitia notarization**, na kuthibitisha kuwa haina maudhui hasidi yanayojulikana na haijabadilishwa baada ya notarization.

Aidha, Gatekeeper huimarisha udhibiti na usalama wa mtumiaji kwa **kuwaomba watumiaji waidhinishe kufungua** programu iliyopakuliwa mara ya kwanza. Hatua hii ya ulinzi husaidia kuzuia watumiaji kuendesha kimakosa msimbo unaoweza kuwa hatari, ambao wanaweza kuwa wamekosea kuuchukulia kama faili ya data isiyo na madhara.

### Saini za Programu

Saini za programu, zinazojulikana pia kama saini za msimbo, ni sehemu muhimu ya miundombinu ya usalama ya Apple. Hutumiwa **kuthibitisha utambulisho wa mwandishi wa programu** (developer) na kuhakikisha kuwa msimbo haujabadilishwa tangu uliposainiwa mara ya mwisho.

Hivi ndivyo inavyofanya kazi:

1. **Kusaini Programu:** Developer anapokuwa tayari kusambaza programu yake, **huisaini programu hiyo kwa kutumia ufunguo wa faragha**. Ufunguo huu wa faragha unahusishwa na **cheti ambacho Apple humpa developer** anapojiandikisha katika Apple Developer Program. Mchakato wa kusaini huhusisha kutengeneza hash ya kriptografia ya sehemu zote za app na kusimba hash hiyo kwa kutumia ufunguo wa faragha wa developer.
2. **Kusambaza Programu:** Kisha programu iliyosainiwa husambazwa kwa watumiaji pamoja na cheti cha developer, ambacho kina ufunguo wa umma unaolingana.
3. **Kuthibitisha Programu:** Mtumiaji anapopakua programu na kujaribu kuiendesha, mfumo wa uendeshaji wa Mac hutumia ufunguo wa umma kutoka kwenye cheti cha developer kusimbua hash hiyo. Kisha huhesabu upya hash kulingana na hali ya sasa ya programu na kuilinganisha na hash iliyosimbuliwa. Zikilingana, inamaanisha kuwa **programu haijabadilishwa** tangu developer alipoisaini, na mfumo huruhusu programu hiyo kuendeshwa.

Saini za programu ni sehemu muhimu ya teknolojia ya Gatekeeper ya Apple. Mtumiaji anapojaribu **kufungua programu iliyopakuliwa kutoka kwenye intaneti**, Gatekeeper huthibitisha saini ya programu hiyo. Ikiwa imesainiwa kwa cheti kilichotolewa na Apple kwa developer anayejulikana na msimbo haujabadilishwa, Gatekeeper huruhusu programu kuendeshwa. Vinginevyo, huizuia programu na kumtahadharisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper hukagua pia ikiwa programu imeidhinishwa kupitia notarization** na Apple, na kuongeza safu nyingine ya usalama. Mchakato wa notarization hukagua programu ili kubaini matatizo ya usalama yanayojulikana na msimbo hasidi; ukaguzi huu ukifaulu, Apple huongeza tiketi kwenye programu ambayo Gatekeeper inaweza kuthibitisha.

#### Kukagua Saini

Unapokagua **sampuli ya malware**, unapaswa **kukagua saini** ya binary kila wakati, kwa kuwa **developer** aliyeisaini huenda tayari **anahusishwa** na **malware**.

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

Mchakato wa Apple wa notarization hutumika kama kinga ya ziada ya kuwalinda watumiaji dhidi ya programu zinazoweza kuwa hatari. Unahusisha **msanidi kuwasilisha programu yake ichunguzwe** na **Apple's Notary Service**, ambayo haipaswi kuchanganywa na App Review. Huduma hii ni **mfumo wa kiotomatiki** unaokagua programu iliyowasilishwa ili kubaini uwepo wa **maudhui hasidi** na matatizo yoyote yanayoweza kuhusiana na utiaji saini wa msimbo.

Programu **ikifaulu** ukaguzi huu bila kuibua wasiwasi wowote, Notary Service hutengeneza tiketi ya notarization. Kisha msanidi anatakiwa **kuambatisha tiketi hii kwenye programu yake**, mchakato unaojulikana kama 'stapling.' Zaidi ya hayo, tiketi ya notarization pia huchapishwa mtandaoni, ambako Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuifikia.

Mtumiaji anaposakinisha au kuendesha programu kwa mara ya kwanza, kuwepo kwa tiketi ya notarization—iwe imeambatishwa kwenye faili inayotekelezeka au imepatikana mtandaoni—**huarifu Gatekeeper kwamba programu hiyo imefanyiwa notarization na Apple**. Kwa hivyo, Gatekeeper huonyesha ujumbe wenye maelezo katika kisanduku cha mazungumzo cha uzinduzi wa kwanza, unaoonyesha kwamba Apple imekagua programu hiyo ili kubaini maudhui hasidi. Hivyo, mchakato huu huongeza imani ya mtumiaji kuhusu usalama wa programu anazosakinisha au kuendesha kwenye mifumo yao.

### spctl & syspolicyd

> [!CAUTION]
> Kumbuka kuwa kuanzia toleo la Sequoia, **`spctl`** hairuhusu tena kubadilisha usanidi wa Gatekeeper.

**`spctl`** ni zana ya CLI ya kuorodhesha na kuwasiliana na Gatekeeper (kupitia daemon ya `syspolicyd` kwa kutumia ujumbe wa XPC). Kwa mfano, inawezekana kuona **hali** ya GateKeeper kwa kutumia:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Kumbuka kwamba ukaguzi wa sahihi wa GateKeeper hufanywa tu kwa **faili zilizo na sifa ya Quarantine**, si kwa kila faili.

GateKeeper itaangalia kama binary inaweza kutekelezwa kulingana na **mapendeleo na sahihi**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ndiyo daemon kuu inayohusika na kutekeleza Gatekeeper. Hudumisha database iliyo katika `/var/db/SystemPolicy`, na inawezekana kupata msimbo unaosaidia [database hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) na [kiolezo cha SQL hapa](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Kumbuka kwamba SIP haiwekei vikwazo database hii, na root anaweza kuiandika. Database ya `/var/db/.SystemPolicy-default` hutumika kama nakala asili ya akiba endapo nyingine itaharibika.

Aidha, bundles **`/var/db/gke.bundle`** na **`/var/db/gkopaque.bundle`** zina faili zenye sheria zinazoingizwa kwenye database. Unaweza kuangalia database hii kama root kwa kutumia:

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

**`syspolicyd`** pia hufichua seva ya XPC yenye operesheni mbalimbali kama `assess`, `update`, `record` na `cancel`. Operesheni hizi pia zinaweza kufikiwa kwa kutumia API za **`Security.framework` za `SecAssessment*`**, na **`spctl`** huwasiliana na **`syspolicyd`** kupitia XPC.

Kumbuka kwamba kanuni ya kwanza iliishia kwa "**App Store**" na ya pili kwa "**Developer ID**", na kwamba kwenye picha ya awali, mipangilio ilikuwa **imewezesha kuendesha programu kutoka App Store na kutoka kwa wasanidi waliotambuliwa**.\
Uk **rekebisha** mpangilio huo uwe App Store, **kanuni za "Notarized Developer ID" zitatoweka**.

Pia kuna maelfu ya kanuni za **aina ya GKE** :

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

Chaguo **`--master-disable`** na **`--global-disable`** za **`spctl`** zitazima kabisa ukaguzi huu wa sahihi:

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

Inawezekana **kuangalia kama App itaruhusiwa na GateKeeper** kwa kutumia:

```bash
spctl --assess -v /Applications/App.app
```

Kwenye macOS 14 na matoleo ya baadaye, **`syspolicy_check`** ni ukaguzi muhimu wa kiwango cha juu kabla ya kusambaza kifurushi cha programu. Hutoa uchunguzi unaoweza kuchukuliwa hatua kuhusu trusted execution kuliko matokeo ya kawaida ya `spctl`, ingawa Apple bado inapendekeza kujaribu mchakato halisi wa kupakua/kutoa faili/kuanzisha programu kwa mara ya kwanza kwa sababu pia hujaribu uenezaji wa quarantine.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

Inawezekana kuongeza sheria mpya katika GateKeeper ili kuruhusu programu fulani kutekelezwa kwa kutumia:

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

Kuhusu **kernel extensions**, folda `/var/db/SystemPolicyConfiguration` ina faili zenye orodha za kext zinazoruhusiwa kupakiwa. Zaidi ya hayo, `spctl` ina entitlement `com.apple.private.iokit.nvram-csr` kwa sababu inaweza kuongeza kernel extensions mpya zilizoidhinishwa mapema, ambazo pia zinahitaji kuhifadhiwa kwenye NVRAM katika key ya `kext-allowed-teams`.

#### Kusimamia Gatekeeper kwenye macOS 15 (Sequoia) na matoleo ya baadaye

- Njia ya zamani ya kupita kizuizi kupitia Finder **Ctrl+Open / Right-click → Open** imeondolewa; watumiaji lazima waruhusu waziwazi app iliyozuiwa kupitia **System Settings → Privacy & Security → Open Anyway** baada ya ujumbe wa kwanza wa kuzuia.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` hazikubaliwi tena kama mabadiliko ya sera yanayofanywa bila uangalizi. Operesheni zinazobadilisha hifadhidata ya sheria au hali ya jumla ya ukaguzi zimeacha kutumika; kwa hiyo, tumia `spctl` kufanya ukaguzi na usanidi utekelezaji kupitia UI au MDM.

Kuanzia macOS 15 Sequoia, watumiaji wa mwisho hawawezi tena kubadilisha sera ya Gatekeeper kupitia `spctl`. Usimamizi hufanywa kupitia System Settings au kwa kusambaza wasifu wa usanidi wa MDM wenye payload ya `com.apple.systempolicy.control`. Mfano wa sehemu ya wasifu inayoruhusu App Store na wasanidi waliotambuliwa (lakini si “Anywhere”):

<details>
<summary>Wasifu wa MDM wa kuruhusu App Store na wasanidi waliotambuliwa</summary>

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

Wakati wa **kupakua** programu au faili, **programu** fulani za macOS, kama vile vivinjari vya wavuti au wateja wa barua pepe, **huambatisha sifa ya faili iliyopanuliwa**, inayojulikana kwa kawaida kama "**alama ya quarantine**," kwenye faili iliyopakuliwa. Sifa hii ni hatua ya usalama ya **kuashiria faili** kuwa imetoka kwenye chanzo kisichoaminika (intaneti), na huenda ikawa na hatari. Hata hivyo, si programu zote zinazoweka sifa hii; kwa mfano, programu za kawaida za mteja wa BitTorrent kwa kawaida huruka hatua hii.

**Kuwepo kwa alama ya quarantine huitaarifu macOS kuhusu kipengele cha usalama cha Gatekeeper mtumiaji anapojaribu kutekeleza faili**.

Iwapo **alama ya quarantine haipo** (kama ilivyo kwa faili zilizopakuliwa kupitia baadhi ya wateja wa BitTorrent), huenda **ukaguzi** wa Gatekeeper **usifanyike**. Kwa hivyo, watumiaji wanapaswa kuwa waangalifu wanapofungua faili zilizopakuliwa kutoka kwenye vyanzo visivyo salama au visivyojulikana.

> [!NOTE] > **Kukagua** **uhalali** wa saini za msimbo ni **mchakato unaotumia rasilimali nyingi** unaojumuisha kutengeneza **hashi** za kriptografia za msimbo na rasilimali zake zote zilizojumuishwa. Zaidi ya hayo, kukagua uhalali wa cheti kunahusisha kufanya **ukaguzi wa mtandaoni** kwenye seva za Apple ili kuona ikiwa cheti kilibatilishwa baada ya kutolewa. Kwa sababu hizi, ukaguzi kamili wa saini ya msimbo na notarization **hauwezi kutekelezwa kila wakati programu inapozinduliwa**.
>
> Kwa hivyo, ukaguzi huu **hufanywa tu wakati wa kutekeleza programu zilizo na sifa ya quarantine.**

> [!WARNING]
> Sifa hii lazima **iwekwe na programu inayounda/kupakua** faili.
>
> Hata hivyo, faili zinazowekwa kwenye sandbox zitakuwa na sifa hii kwenye kila faili wanayounda. Na programu zisizowekwa kwenye sandbox zinaweza kujiwekea sifa hiyo zenyewe, au kubainisha kitufe cha [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) kwenye **Info.plist**, kitakachofanya mfumo uweke sifa iliyopanuliwa `com.apple.quarantine` kwenye faili zilizoundwa,

Zaidi ya hayo, faili zote zinazoundwa na mchakato unaoita **`qtn_proc_apply_to_self`** huwekwa kwenye quarantine. Au API **`qtn_file_apply_to_path`** huongeza sifa ya quarantine kwenye njia maalum ya faili.

Inawezekana **kuangalia hali yake na kuiwasha/kuzima** (unahitaji root) kwa kutumia:

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

Kagua **thamani** ya **sifa** **zilizopanuliwa** na ujue programu iliyoandika sifa ya quarantine kwa kutumia:

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

Kwa kweli, mchakato “unaweza kuweka flags za quarantine kwenye faili unazounda” (tayari nilijaribu kuweka flag ya USER_APPROVED kwenye faili iliyoundwa, lakini haikubali kuwekwa):

<details>

<summary>Msimbo Chanzo wa kuweka flags za quarantine</summary>

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

Na utafute faili zote zilizowekwa karantini kwa kutumia:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Taarifa za quarantine pia huhifadhiwa katika hifadhidata kuu inayodhibitiwa na LaunchServices kwenye **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, ambayo huruhusu GUI kupata data kuhusu chanzo cha faili. Zaidi ya hayo, programu zinazoweza kutaka kuficha chanzo chake zinaweza kubadilisha taarifa hizi. Hili linaweza pia kufanywa kupitia LaunchServices APIs.

#### **libquarantine.dylib**

Maktaba hii husafirisha functions kadhaa zinazowezesha kudhibiti sehemu za extended attribute.

APIs za `qtn_file_*` hushughulikia sera za quarantine za faili, huku APIs za `qtn_proc_*` zikitumika kwa processes (faili zilizoundwa na process). Functions zisizosafirishwa za `__qtn_syscall_quarantine*` ndizo zinazotumia sera hizi; huita `mac_syscall` kwa "Quarantine" kama hoja ya kwanza, na hivyo kutuma maombi kwa `Quarantine.kext`.

#### **Quarantine.kext**

Kernel extension hii inapatikana tu kupitia **kernel cache kwenye mfumo**; hata hivyo, _unaweza_ kupakua **Kernel Debug Kit kutoka** [**https://developer.apple.com/**](https://developer.apple.com/), ambayo ina toleo la extension lenye alama za symbols.

Kext hii hutumia MACF ku-hook calls kadhaa ili kunasa matukio yote ya mzunguko wa maisha wa faili: kuunda, kufungua, kubadilisha jina, kuunda hard link... hata `setxattr`, ili kuzuia kuweka extended attribute ya `com.apple.quarantine`.

Pia hutumia MIB kadhaa:

- `security.mac.qtn.sandbox_enforce`: Tekeleza quarantine pamoja na Sandbox
- `security.mac.qtn.user_approved_exec`: Processes zilizo na quarantine zinaweza kutekeleza faili zilizoidhinishwa pekee

#### Provenance xattr (Ventura na matoleo ya baadaye)

macOS 13 Ventura ilianzisha utaratibu tofauti wa provenance, ambao hujazwa mara ya kwanza programu iliyo na quarantine inaporuhusiwa kuendeshwa.<sup>[[2]](#references)</sup> Vipengee viwili huundwa:

- xattr ya `com.apple.provenance` kwenye saraka ya `.app` bundle (thamani ya binary ya ukubwa usiobadilika iliyo na primary key na flags).
- Safu katika jedwali la `provenance_tracking` ndani ya hifadhidata ya ExecPolicy kwenye `/var/db/SystemPolicyConfiguration/ExecPolicy/`, inayohifadhi cdhash na metadata ya programu.

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

XProtect ni kipengele **cha kupambana na programu hasidi** kilichojengewa ndani ya macOS. XProtect **hukagua kila programu inapozinduliwa au kurekebishwa kwa mara ya kwanza, kwa kuilinganisha na hifadhidata yake** ya programu hasidi zinazojulikana na aina za faili zisizo salama. Unapopakua faili kupitia baadhi ya programu, kama Safari, Mail au Messages, XProtect huchanganua faili hiyo kiotomatiki. Ikiwa inalingana na programu hasidi yoyote inayojulikana kwenye hifadhidata yake, XProtect **huzuia faili hiyo kufanya kazi** na kukuonya kuhusu tishio hilo.

Apple **husasisha mara kwa mara** hifadhidata ya XProtect kwa ufafanuzi mpya wa programu hasidi, na masasisho haya hupakuliwa na kusakinishwa kiotomatiki kwenye Mac yako. Hii huhakikisha kuwa XProtect inasasishwa kila wakati ili kukabiliana na vitisho vya hivi karibuni vinavyojulikana.

Hata hivyo, inafaa kutambua kuwa **XProtect si suluhisho kamili la antivirus**. Hukagua tu orodha maalum ya vitisho vinavyojulikana na haifanyi uchanganuzi wa wakati wa ufikiaji kama programu nyingi za antivirus.

Unaweza kupata taarifa kuhusu sasisho la hivi karibuni la XProtect kwa kutumia amri hii:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect iko katika eneo linalolindwa na SIP kwenye **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, na ndani ya bundle hiyo unaweza kupata maelezo yanayotumiwa na XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Huruhusu code yenye cdhash hizo kutumia legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodha ya plugins na extensions ambazo haziruhusiwi kupakiwa, kulingana na BundleID na TeamID, au zinazoonyesha toleo la chini kabisa linalohitajika.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Sheria za Yara za kutambua malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Database ya SQLite3 yenye hashes za applications zilizozuiwa na TeamIDs.

Kumbuka kwamba kuna App nyingine inayohusiana na XProtect kwenye **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, lakini haihusiki na mchakato wa Gatekeeper.

> XProtect Remediator: Kwenye matoleo ya kisasa ya macOS, Apple hujumuisha skana za on-demand (XProtect Remediator) ambazo huendeshwa mara kwa mara kupitia launchd ili kugundua na kurekebisha familia za malware. Unaweza kuona skana hizi kwenye unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Sio Gatekeeper

> [!CAUTION]
> Kumbuka kwamba Gatekeeper **haiendeshwi kila unapotekeleza** programu; _**AppleMobileFileIntegrity**_ (AMFI) **huthibitisha saini za msimbo unaotekelezeka pekee** unapotekeleza programu ambayo tayari imetekelezwa na kuthibitishwa na Gatekeeper.

Kwa hiyo, hapo awali ilikuwa inawezekana kutekeleza programu ili Gatekeeper ihifadhi taarifa zake kwenye cache, kisha **kurekebisha faili zisizotekelezeka za programu** (kama faili za Electron asar au NIB). Ikiwa hakukuwa na kinga nyingine, programu **ilitekelezwa** ikiwa na nyongeza **hasidi**.

Hata hivyo, sasa hili haliwezekani kwa sababu macOS **huzuia kurekebishwa kwa faili** zilizo ndani ya vifurushi vya programu. Kwa hiyo, ukijaribu shambulio la [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), utaona kwamba haliwezekani tena kulitumia vibaya, kwa sababu baada ya kutekeleza programu ili Gatekeeper ihifadhi taarifa zake kwenye cache, hutaweza kurekebisha kifurushi. Na ukibadilisha, kwa mfano, jina la saraka ya Contents kuwa NotCon (kama ilivyoelekezwa kwenye exploit), kisha utekeleze binary kuu ya programu ili Gatekeeper ihifadhi taarifa zake kwenye cache, kosa litatokea na programu haitatekelezwa.

## Gatekeeper Bypasses

Njia yoyote ya kukwepa Gatekeeper (kufanikiwa kumfanya mtumiaji apakue kitu na kukitekeleza wakati Gatekeeper inapaswa kukizuia) huchukuliwa kuwa udhaifu katika macOS. Hizi ni baadhi ya CVE zilizotolewa kwa mbinu zilizowezesha kukwepa Gatekeeper hapo awali:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilibainika kuwa **Archive Utility** ikitumika kutoa faili, faili zenye **njia zinazozidi herufi 886** hazipati sifa iliyopanuliwa ya com.apple.quarantine. Hali hii huruhusu faili hizo **kukwepa** ukaguzi wa usalama wa Gatekeeper bila kukusudia.<sup>[[5]](#references)</sup>

Angalia [**ripoti ya awali**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa maelezo zaidi.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Programu ikiundwa kwa kutumia **Automator**, taarifa kuhusu kile inachohitaji kutekeleza huwa ndani ya `application.app/Contents/document.wflow`, si kwenye executable. Executable ni binary ya jumla tu ya Automator inayoitwa **Automator Application Stub**.

Kwa hiyo, unaweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **ielekeze kwa kutumia symbolic link kwenye Automator Application Stub nyingine iliyo ndani ya mfumo**, kisha itatekeleza kilicho ndani ya `document.wflow` (script yako) **bila kuanzisha Gatekeeper**, kwa sababu executable halisi haina xattr ya quarantine.<sup>[[6]](#references)</sup>

Mfano wa eneo linalotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Angalia [**ripoti ya awali**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa maelezo zaidi.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika mbinu hii ya kukwepa, faili ya zip iliundwa kwa kuanza kubana programu kutoka `application.app/Contents` badala ya `application.app`. Kwa hiyo, **sifa ya quarantine** ilitumika kwa **faili zote zilizo ndani ya `application.app/Contents`**, lakini **haikutumika kwa `application.app`**, ambayo ndiyo iliyokuwa ikikaguliwa na Gatekeeper. Hivyo, Gatekeeper ilikwepwa kwa sababu wakati `application.app` ilipoanzishwa **haikuwa na sifa ya quarantine.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Angalia [**ripoti ya awali**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa maelezo zaidi.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama vipengele ni tofauti, exploitation ya vulnerability hii inafanana sana na ile iliyotangulia. Katika hali hii tutazalisha Apple Archive kutoka **`application.app/Contents`**, ili **`application.app` isipate sifa ya quarantine** inapofinyuliwa na **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Angalia [**ripoti ya awali**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kwa maelezo zaidi.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** inaweza kutumiwa kuzuia mtu yeyote kuandika attribute kwenye faili:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Zaidi ya hayo, umbizo la faili la **AppleDouble** linakili faili pamoja na ACE zake.<sup>[[9]](#references)</sup>

Katika [**msimbo chanzo**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba uwakilishi wa maandishi wa ACL uliohifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL kwenye faili iliyofunguliwa kutoka kwenye kumbukumbu iliyobanwa. Kwa hivyo, ukibanisha programu kwenye faili ya zip kwa kutumia umbizo la faili la **AppleDouble** na ACL inayozuia xattr nyingine kuandikwa humo... xattr ya quarantine haikuwekwa kwenye programu:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Angalia [**ripoti asili**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.<sup>[[9]](#references)</sup> Tazama [uzalishaji upya wa AppleDouble/ACL](macos-fs-tricks/macos-xattr-acls-extra-stuff.md) kwa hatua za kuunda na kuthibitisha sidecar.

Kumbuka kuwa hili pia linaweza kutumiwa vibaya kupitia AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Iligunduliwa kuwa **Google Chrome haikuwa ikiweka sifa ya quarantine** kwa faili zilizopakuliwa kutokana na matatizo fulani ya ndani ya macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble huhifadhi sifa za faili katika faili tofauti ambayo jina lake huanza na `._`; hii husaidia kunakili sifa za faili **kati ya mashine za macOS**. Hata hivyo, baada ya kufungua faili ya AppleDouble iliyobanwa, faili inayoanza na `._` **haikupewa sifa ya quarantine**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Kwa kuweza kuunda faili ambayo haitakuwa na sifa ya quarantine, **iliwezekana kukwepa Gatekeeper.** Ujanja ulikuwa **kuunda programu ya faili ya DMG** kwa kutumia kanuni ya majina ya AppleDouble (kuanza na `._`) na kuunda **faili inayoonekana kama symlink ya faili hii iliyofichwa** bila sifa ya quarantine.\
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

Apple ilirekebisha hitilafu ya mantiki ya LaunchServices katika macOS Sonoma 14.0 kwa kuboresha ukaguzi. Ushauri wa umma unasema tu kwamba programu inaweza kukwepa Gatekeeper, kwa hivyo usihitimishe muundo mahususi wa kifurushi au mnyororo wa exploitation kutokana na ingizo la CVE pekee.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Bypass ya Gatekeeper katika macOS 14.4 (iliyotolewa Machi 2024), iliyotokana na jinsi `libarchive` ilivyoshughulikia ZIP hasidi, iliruhusu programu kukwepa ukaguzi. Sasisha hadi 14.4 au toleo la baadaye, ambako Apple ilirekebisha tatizo hilo.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Workflow ya Automator Quick Action** iliyopachikwa katika programu iliyopakuliwa inaweza kuanzishwa bila ukaguzi wa Gatekeeper, kwa sababu workflow zilichukuliwa kama data na kutekelezwa na helper ya Automator nje ya utaratibu wa kawaida wa kidokezo cha notarization. Kwa hiyo, `.app` iliyotengenezwa kwa makusudi na inayojumuisha Quick Action inayoendesha shell script (kwa mfano, ndani ya `Contents/PlugIns/*.workflow/Contents/document.wflow`) inaweza kutekelezwa mara moja inapozinduliwa. Apple iliongeza kisanduku cha ziada cha ridhaa na kurekebisha utaratibu wa ukaguzi katika Ventura **13.7**, Sonoma **14.7**, na Sequoia **15**.<sup>[[3]](#references)</sup>

### Hitilafu za uenezaji wa quarantine kwenye mipaka ya uchimbuaji na kunakili

Utafiti wa 2024 uligundua mapengo ya uenezaji katika matoleo yaliyokaguliwa ya iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z), na 7z Utility (DMG/ZIP/7Z); pia ulibaini sifa hiyo ikipotea wakati wa kunakili kutoka kwa host kwenda kwa guest kupitia VMware Tools. Wachuuzi kadhaa walitangaza marekebisho baadaye, kwa hiyo chukulia majina haya kama vidokezo vya **kupima upya matoleo mahususi**, si kama orodha ya kudumu ya programu zilizo hatarini. Tatizo hilohilo la mpaka wa uaminifu linahusu pia workflows asilia za Unix: `curl`/`scp` haziongezi quarantine, na `tar`/`unzip` za mstari wa amri hazirithi quarantine kiotomatiki kutoka kwenye archive ya kifurushi.<sup>[[15]](#references)</sup>

Kwa majaribio ya offensive, linganisha kifurushi na programu ya mwisho baada ya **kila** mabadiliko kupitia kivinjari, mteja wa barua pepe, archive, picha ya diski, usawazishaji wa cloud, folda iliyoshirikiwa, na kunakili kwa VM. Kukataliwa waziwazi na `spctl` hakurekebishi xattr inayokosekana: bila quarantine, utaratibu wa kawaida wa Gatekeeper wakati wa kufungua kwa mara ya kwanza huenda usiombe kamwe ukaguzi huo.<sup>[[15]](#references)</sup>

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

### uchg (kutoka kwenye [hotuba hii](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Unda saraka iliyo na app.
- Ongeza uchg kwenye app.
- Bana app iwe faili la tar.gz.
- Tuma faili la tar.gz kwa mwathiriwa.
- Mwathiriwa afungue faili la tar.gz na aendeshe app.
- Gatekeeper haikague app.<sup>[[12]](#references)</sup>

### Zuia Quarantine xattr

Ikiwa xattr ya quarantine haijaongezwa kwenye kifurushi cha ".app", **Gatekeeper haitawashwa** wakati wa kukitekeleza.

Tazama [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) kwa mbinu za msingi za filesystem, flag, ACL na AppleDouble zinazoweza kuzuia au kuondoa attributes zilizopanuliwa.





## References

- [1] [Usalama wa Apple Platform: Kuhusu maudhui ya usalama ya macOS Sonoma 14.4 (inajumuisha CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Jinsi macOS inavyofuatilia sasa asili ya apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia yaondoa njia ya kukwepa Gatekeeper ya Control-click “Open”](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Ugunduzi wa CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Kukwepa macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs yatambua udhaifu wa Safari unaoruhusu kukwepa Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs yatambua udhaifu wa macOS Archive Utility unaoruhusu kukwepa Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Achilles heel ya Gatekeeper: Kufichua udhaifu wa macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ugunduzi wa njia ya kukwepa Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Kupata na kuripoti exploit ya kukwepa Gatekeeper kwa msaada wa Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Kukwepa mifumo ya usalama na faragha ya macOS — kutoka Gatekeeper hadi System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Kuhusu maudhui ya usalama ya macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Kujaribu bidhaa iliyothibitishwa kwa notarization](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Kukwepa Gatekeeper — Kufichua udhaifu katika mfumo wa usalama wa macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
