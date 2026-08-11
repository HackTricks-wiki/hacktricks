# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** Mac operating systems के लिए विकसित एक security feature है, जिसे यह सुनिश्चित करने के लिए बनाया गया है कि users अपने systems पर **केवल trusted software चलाएँ**। यह उस software को **validate** करके काम करता है जिसे user **App Store के बाहर के sources** से download करके खोलने का प्रयास करता है, जैसे कोई app, plug-in या installer package।

Gatekeeper का मुख्य mechanism इसकी **verification** process में निहित है। यह जाँचता है कि downloaded software **किसी recognized developer द्वारा signed है या नहीं**, जिससे software की authenticity सुनिश्चित होती है। इसके अलावा, यह पता लगाता है कि software **Apple द्वारा notarised है या नहीं**, जिससे यह पुष्टि होती है कि उसमें कोई ज्ञात malicious content नहीं है और notarisation के बाद उसके साथ छेड़छाड़ नहीं की गई है।

इसके अतिरिक्त, Gatekeeper downloaded software को पहली बार खोलने की **users से approval माँगकर** user control और security को मजबूत करता है। यह safeguard users को अनजाने में ऐसे potentially harmful executable code को चलाने से रोकने में मदद करता है, जिसे वे गलती से harmless data file समझ सकते हैं।

### Application Signatures

Application signatures, जिन्हें code signatures भी कहा जाता है, Apple के security infrastructure का एक महत्वपूर्ण component हैं। इनका उपयोग **software author** (developer) की **identity verify करने** और यह सुनिश्चित करने के लिए किया जाता है कि code पर आखिरी बार sign किए जाने के बाद से उसके साथ छेड़छाड़ नहीं की गई है।

यह इस तरह काम करता है:

1. **Signing the Application:** जब कोई developer अपनी application distribute करने के लिए तैयार होता है, तो वह **private key का उपयोग करके application को sign करता है**। यह private key उस **certificate से जुड़ी होती है जिसे Apple developer को Apple Developer Program में enrol करने पर issue करता है**। Signing process में app के सभी parts का cryptographic hash बनाना और इस hash को developer की private key से encrypt करना शामिल होता है।
2. **Distributing the Application:** इसके बाद signed application को developer के certificate के साथ users को distribute किया जाता है, जिसमें corresponding public key होती है।
3. **Verifying the Application:** जब कोई user application download करके उसे run करने का प्रयास करता है, तो उसका Mac operating system hash को decrypt करने के लिए developer के certificate से public key का उपयोग करता है। इसके बाद यह application की current state के आधार पर hash को फिर से calculate करता है और इसकी तुलना decrypted hash से करता है। यदि दोनों match करते हैं, तो इसका अर्थ है कि **developer द्वारा sign किए जाने के बाद application को modify नहीं किया गया है**, और system application को run करने की अनुमति देता है।

Application signatures Apple की Gatekeeper technology का एक आवश्यक हिस्सा हैं। जब कोई user **internet से downloaded application को open करने का प्रयास करता है**, तो Gatekeeper application signature को verify करता है। यदि वह Apple द्वारा किसी known developer को issue किए गए certificate से signed है और code के साथ छेड़छाड़ नहीं की गई है, तो Gatekeeper application को run करने की अनुमति देता है। अन्यथा, यह application को block करके user को alert करता है।

macOS Catalina से शुरू होकर, **Gatekeeper यह भी जाँचता है कि application Apple द्वारा notarized है या नहीं**, जिससे security की एक अतिरिक्त layer जुड़ती है। Notarization process application को known security issues और malicious code के लिए जाँचती है, और यदि ये checks सफल होते हैं, तो Apple application में एक ticket जोड़ता है जिसे Gatekeeper verify कर सकता है।

#### Check Signatures

किसी **malware sample** की जाँच करते समय आपको हमेशा binary का **signature check करना चाहिए**, क्योंकि उसे sign करने वाला **developer** पहले से **malware से related** हो सकता है।
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

Apple की notarization प्रक्रिया उपयोगकर्ताओं को संभावित रूप से हानिकारक software से बचाने के लिए एक अतिरिक्त सुरक्षा उपाय के रूप में काम करती है। इसमें **developer द्वारा अपने application को जांच के लिए submit करना** शामिल है, जिसे **Apple's Notary Service** द्वारा किया जाता है और इसे App Review से भ्रमित नहीं किया जाना चाहिए। यह service एक **automated system** है, जो submit किए गए software में **malicious content** और code-signing से जुड़ी संभावित समस्याओं की जांच करती है।

यदि software बिना किसी चिंता के इस जांच को **पास** कर लेता है, तो Notary Service एक notarization ticket तैयार करती है। इसके बाद developer को यह ticket अपने software के साथ **attach करना** आवश्यक होता है, इस प्रक्रिया को 'stapling' कहा जाता है। इसके अलावा, notarization ticket online भी प्रकाशित किया जाता है, जहां Gatekeeper, Apple की security technology, इसे access कर सकता है।

Software की पहली installation या execution के दौरान, notarization ticket का मौजूद होना - चाहे वह executable के साथ stapled हो या online मिला हो - **Gatekeeper को सूचित करता है कि software को Apple द्वारा notarize किया गया है**। परिणामस्वरूप, Gatekeeper initial launch dialog में एक descriptive message दिखाता है, जिसमें बताया जाता है कि Apple ने software में malicious content की जांच की है। इस प्रक्रिया से users का अपने systems पर install या run किए जाने वाले software की security में confidence बढ़ता है।

### spctl & syspolicyd

> [!CAUTION]
> ध्यान दें कि Sequoia version से, **`spctl`** अब Gatekeeper configuration को modify करने की अनुमति नहीं देता।

**`spctl`** Gatekeeper को enumerate करने और उसके साथ interact करने का CLI tool है (XPC messages के माध्यम से `syspolicyd` daemon के साथ)। उदाहरण के लिए, निम्नलिखित command से **GateKeeper** का **status** देखना संभव है:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> ध्यान दें कि GateKeeper signature checks केवल **Quarantine attribute वाली files** पर किए जाते हैं, हर file पर नहीं।

GateKeeper यह जाँचता है कि **preferences और signature** के अनुसार किसी binary को execute किया जा सकता है या नहीं:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** Gatekeeper को enforce करने के लिए ज़िम्मेदार मुख्य daemon है। यह `/var/db/SystemPolicy` में स्थित एक database को maintain करता है और [database को support करने वाला code यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) तथा [SQL template यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) मिल सकता है। ध्यान दें कि यह database SIP द्वारा restricted नहीं है और root द्वारा writable है। Database `/var/db/.SystemPolicy-default` का उपयोग तब original backup के रूप में किया जाता है, जब दूसरा database corrupt हो जाए।

इसके अलावा, **`/var/db/gke.bundle`** और **`/var/db/gkopaque.bundle`** bundles में वे files होती हैं जिनमें database में insert किए जाने वाले rules होते हैं। आप root के रूप में इस database को यहाँ दिए गए command से check कर सकते हैं:
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
**`syspolicyd`** अलग-अलग operations जैसे `assess`, `update`, `record` और `cancel` वाला एक XPC server भी expose करता है, जिन्हें **`Security.framework` के `SecAssessment*`** APIs का उपयोग करके भी access किया जा सकता है और **`spctl`** वास्तव में XPC के माध्यम से **`syspolicyd`** से communicate करता है।

ध्यान दें कि पहला rule "**App Store**" पर और दूसरा "**Developer ID**" पर समाप्त हुआ था और पिछली image में यह **App Store और identified developers से apps execute करने के लिए enabled था**।\
यदि आप उस setting को App Store में **modify** करते हैं, तो "**Notarized Developer ID" rules गायब हो जाएंगे**।

**type GKE** के भी हजारों rules हैं:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
ये hashes निम्नलिखित से हैं:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

या आप पिछली जानकारी को इस कमांड से सूचीबद्ध कर सकते हैं:
```bash
sudo spctl --list
```
**`spctl`** के विकल्प **`--master-disable`** और **`--global-disable`** इन signature checks को पूरी तरह **disable** कर देंगे:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
पूरी तरह enabled होने पर, एक नया option दिखाई देगा:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

इससे **जाँचना संभव है कि किसी App को GateKeeper द्वारा अनुमति दी जाएगी या नहीं**:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper में कुछ apps के execution की अनुमति देने के लिए नए rules जोड़ना संभव है:
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
**kernel extensions** के संबंध में, फ़ोल्डर `/var/db/SystemPolicyConfiguration` में उन kexts की सूचियों वाली फ़ाइलें होती हैं जिन्हें लोड करने की अनुमति है। इसके अलावा, `spctl` के पास `com.apple.private.iokit.nvram-csr` entitlement है, क्योंकि यह पहले से स्वीकृत नए kernel extensions जोड़ने में सक्षम है, जिन्हें `kext-allowed-teams` key में NVRAM में भी सहेजना आवश्यक होता है।

#### macOS 15 (Sequoia) और उसके बाद Gatekeeper को manage करना

- लंबे समय से उपलब्ध Finder **Ctrl+Open / Right-click → Open** bypass हटा दिया गया है; पहले block dialog के बाद users को **System Settings → Privacy & Security → Open Anyway** से blocked app को explicitly allow करना होगा।<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` अब accepted नहीं हैं; `spctl` assessment और label management के लिए प्रभावी रूप से read-only है, जबकि policy enforcement को UI या MDM के माध्यम से configure किया जाता है।

macOS 15 Sequoia से end users अब `spctl` से Gatekeeper policy toggle नहीं कर सकते। Management System Settings के माध्यम से या `com.apple.systempolicy.control` payload वाली MDM configuration profile deploy करके किया जाता है। App Store और identified developers को allow करने (लेकिन "Anywhere" को नहीं) के लिए example profile snippet:

<details>
<summary>App Store और identified developers को allow करने वाली MDM profile</summary>
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

### Quarantine Files

किसी application या file को **downloading** करने पर, कुछ macOS **applications**, जैसे web browsers या email clients, downloaded file में एक **extended file attribute** जोड़ते हैं, जिसे आमतौर पर "**quarantine flag**" कहा जाता है। यह attribute एक security measure के रूप में काम करता है और **file को mark** करता है कि वह किसी untrusted source (internet) से आई है और उसमें संभावित risks हो सकते हैं। हालांकि, सभी applications यह attribute नहीं जोड़ते; उदाहरण के लिए, सामान्य BitTorrent client software आमतौर पर इस process को bypass करता है।

**quarantine flag की मौजूदगी macOS के Gatekeeper security feature को signal करती है, जब user file को execute करने का प्रयास करता है**।

यदि **quarantine flag मौजूद नहीं है** (जैसा कि कुछ BitTorrent clients के माध्यम से downloaded files के साथ होता है), तो Gatekeeper के **checks शायद perform न किए जाएं**। इसलिए, users को कम secure या unknown sources से downloaded files खोलते समय सावधानी बरतनी चाहिए।

> [!NOTE] > **code signatures की validity की checking** एक **resource-intensive** process है, जिसमें code और उसके सभी bundled resources के cryptographic **hashes** generate करना शामिल है। इसके अलावा, certificate validity की checking में Apple के servers पर **online check** करना शामिल है, ताकि यह पता लगाया जा सके कि issue होने के बाद उसे revoke किया गया है या नहीं। इन कारणों से, हर बार app launch होने पर full code signature और notarization check चलाना **impractical** है।
>
> इसलिए, ये checks **केवल quarantined attribute वाली apps को execute करते समय चलाए जाते हैं।**

> [!WARNING]
> यह attribute उस **application द्वारा set किया जाना चाहिए जो file create/download कर रही है**।
>
> हालांकि, sandboxed files द्वारा create की जाने वाली प्रत्येक file में यह attribute set होगा। और non sandboxed apps इसे स्वयं set कर सकते हैं, या [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key को **Info.plist** में specify कर सकते हैं, जिससे system create की गई files पर `com.apple.quarantine` extended attribute set कर देगा,

इसके अलावा, **`qtn_proc_apply_to_self`** को call करने वाली process द्वारा create की गई सभी files quarantined होती हैं। या **`qtn_file_apply_to_path`** API किसी specified file path में quarantine attribute जोड़ती है।

इसे **check करने और enable/disable करने** (root required) के लिए यह संभव है:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
आप यह भी **पता लगा सकते हैं कि किसी फ़ाइल में quarantine extended attribute है या नहीं**:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** के **value** की जाँच करें और पता लगाएँ कि quarantine attr किस app ने लिखा था:
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
वास्तव में कोई process "अपने द्वारा बनाई गई files पर quarantine flags सेट कर सकता है" (मैंने बनाई गई file में USER_APPROVED flag लागू करने की कोशिश की थी, लेकिन यह लागू नहीं हुआ):

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
**और** उस attribute को इससे हटाएँ:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
और quarantine की गई सभी फ़ाइलें इससे खोजें:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine जानकारी LaunchServices द्वारा प्रबंधित एक central database में भी stored होती है, जो **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** पर स्थित है और GUI को file origins के बारे में data प्राप्त करने की अनुमति देती है। इसके अलावा, इसे उन applications द्वारा overwrite किया जा सकता है जो इसके origins को छिपाने में interested हो सकती हैं। यह LaunchServices APIs के माध्यम से भी किया जा सकता है।

#### **libquarantine.dylib**

यह library कई functions export करती है, जो extended attribute fields को manipulate करने की अनुमति देते हैं।

`qtn_file_*` APIs file quarantine policies से deal करती हैं, जबकि `qtn_proc_*` APIs processes पर लागू होती हैं (process द्वारा बनाई गई files)। Unexported `__qtn_syscall_quarantine*` functions वे functions हैं जो इन policies को लागू करती हैं और `mac_syscall` को पहले argument के रूप में "Quarantine" के साथ call करती हैं, जो requests को `Quarantine.kext` पर भेजता है।

#### **Quarantine.kext**

यह kernel extension केवल **system के kernel cache** के माध्यम से उपलब्ध है; हालांकि, आप [**https://developer.apple.com/**](https://developer.apple.com/) से **Kernel Debug Kit download** कर सकते हैं, जिसमें extension का symbolicated version होगा।

यह Kext MACF के माध्यम से कई calls को hook करेगा ताकि सभी file lifecycle events को trap किया जा सके: Creation, opening, renaming, hard-linkning... यहां तक कि `setxattr` को भी, ताकि उसे `com.apple.quarantine` extended attribute set करने से रोका जा सके।

यह कुछ MIBs का भी उपयोग करता है:

- `security.mac.qtn.sandbox_enforce`: Sandbox के साथ quarantine enforce करता है
- `security.mac.qtn.user_approved_exec`: Querantined procs केवल approved files को execute कर सकते हैं

#### Provenance xattr (Ventura and later)

macOS 13 Ventura ने एक separate provenance mechanism introduce किया, जो पहली बार किसी quarantined app को run करने की अनुमति मिलने पर populated होता है।<sup>[[2]](#references)</sup> दो artefacts create किए जाते हैं:

- `.app` bundle directory पर `com.apple.provenance` xattr (एक fixed-size binary value जिसमें primary key और flags होते हैं)।
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` पर स्थित ExecPolicy database के अंदर `provenance_tracking` table में एक row, जिसमें app का cdhash और metadata stored होता है।

Practical usage:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect macOS में एक built-in **anti-malware** feature है। XProtect **किसी भी application को पहली बार launch या modify किए जाने पर, उसे ज्ञात malware और unsafe file types के अपने database से check करता है**। जब आप Safari, Mail या Messages जैसे कुछ apps के माध्यम से कोई file download करते हैं, तो XProtect उस file को automatically scan करता है। यदि वह इसके database में मौजूद किसी ज्ञात malware से match होती है, तो XProtect **file को run होने से रोक देगा** और आपको threat के बारे में alert करेगा।

XProtect database को Apple द्वारा नए malware definitions के साथ **नियमित रूप से update किया जाता है**, और ये updates आपके Mac पर automatically download और install हो जाते हैं। इससे यह सुनिश्चित होता है कि XProtect नवीनतम ज्ञात threats के साथ हमेशा up-to-date रहे।

हालांकि, यह ध्यान रखना आवश्यक है कि **XProtect एक full-featured antivirus solution नहीं है**। यह केवल ज्ञात threats की एक specific list को check करता है और अधिकांश antivirus software की तरह on-access scanning नहीं करता।

आप नवीनतम XProtect update के बारे में जानकारी प्राप्त करने के लिए यह चलाएँ:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect, **/Library/Apple/System/Library/CoreServices/XProtect.bundle** में स्थित SIP protected location है और bundle के अंदर आपको XProtect द्वारा उपयोग की जाने वाली जानकारी मिल सकती है:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: उन cdhashes वाले code को legacy entitlements उपयोग करने की अनुमति देता है।
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: उन plugins और extensions की सूची जिन्हें BundleID और TeamID के आधार पर load करने की अनुमति नहीं है, या जो minimum version दर्शाते हैं।
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware detect करने के लिए Yara rules।
- **`XProtect.bundle/Contents/Resources/gk.db`**: blocked applications और TeamIDs के hashes वाला SQLite3 database।

ध्यान दें कि **`/Library/Apple/System/Library/CoreServices/XProtect.app`** में एक अन्य App भी है जो XProtect से संबंधित है, लेकिन Gatekeeper process में शामिल नहीं है।

> XProtect Remediator: आधुनिक macOS पर, Apple on-demand scanners (XProtect Remediator) उपलब्ध कराता है, जो malware families को detect और remediate करने के लिए launchd के माध्यम से समय-समय पर run होते हैं। आप इन scans को unified logs में देख सकते हैं:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper नहीं

> [!CAUTION]
> ध्यान दें कि Gatekeeper **हर बार application execute करने पर run नहीं होता**; केवल _**AppleMobileFileIntegrity**_ उस समय **executable code signatures को verify** करेगा, जब आप ऐसा app execute करते हैं जिसे Gatekeeper द्वारा पहले ही execute और verify किया जा चुका है।

इसलिए, पहले किसी app को Gatekeeper के साथ cache करने के लिए execute करना, फिर application की **non-executable files को modify करना** (जैसे Electron asar या NIB files) संभव था और यदि कोई अन्य protections मौजूद न हों, तो application को **malicious** additions के साथ **execute** किया जा सकता था।

हालांकि, अब यह संभव नहीं है क्योंकि macOS **application bundles के अंदर files को modify करने से रोकता है**। इसलिए, यदि आप [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack आजमाते हैं, तो आप पाएंगे कि अब इसका abuse करना संभव नहीं है, क्योंकि app को Gatekeeper के साथ cache करने के लिए execute करने के बाद आप bundle को modify नहीं कर पाएंगे। और यदि आप, उदाहरण के लिए, Contents directory का नाम बदलकर NotCon कर देते हैं (जैसा कि exploit में बताया गया है), और फिर app के main binary को Gatekeeper के साथ cache करने के लिए execute करते हैं, तो यह एक error trigger करेगा और execute नहीं होगा।

## Gatekeeper Bypasses

Gatekeeper को bypass करने का कोई भी तरीका (user से कुछ download करवाकर उसे तब execute करवाना जब Gatekeeper को उसे disallow करना चाहिए) macOS में vulnerability माना जाता है। अतीत में Gatekeeper bypass करने वाली techniques के लिए assign किए गए कुछ CVEs ये हैं:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

यह देखा गया कि यदि extraction के लिए **Archive Utility** का उपयोग किया जाता है, तो **886 characters से अधिक लंबे paths** वाली files को com.apple.quarantine extended attribute नहीं मिलता। यह स्थिति अनजाने में उन files को Gatekeeper की security checks को **circumvent करने** की अनुमति देती है।<sup>[[5]](#references)</sup>

अधिक जानकारी के लिए [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) देखें।<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

जब कोई application **Automator** के साथ बनाई जाती है, तो उसे execute करने के लिए आवश्यक information executable में नहीं, बल्कि `application.app/Contents/document.wflow` के अंदर होती है। Executable केवल **Automator Application Stub** नामक एक generic Automator binary होती है।

इसलिए, आप `application.app/Contents/MacOS/Automator\ Application\ Stub` को **system के अंदर मौजूद किसी अन्य Automator Application Stub की ओर symbolic link point** करवा सकते हैं और यह `document.wflow` (आपकी script) के अंदर मौजूद content को **Gatekeeper trigger किए बिना execute** कर देगा, क्योंकि actual executable में quarantine xattr नहीं होता।<sup>[[6]](#references)</sup>

उदाहरण के लिए expected location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

अधिक जानकारी के लिए [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) देखें।<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

इस bypass में एक zip file बनाई गई थी, जिसमें compression `application.app` से शुरू करने के बजाय `application.app/Contents` से शुरू किया गया था। इसलिए **quarantine attr** `application.app/Contents` की सभी **files पर apply** हुआ, लेकिन **`application.app` पर नहीं**। Gatekeeper इसी `application.app` को check कर रहा था, इसलिए Gatekeeper bypass हो गया, क्योंकि जब `application.app` trigger किया गया, तो **उसमें quarantine attribute नहीं था।**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) देखें।<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

भले ही components अलग हों, इस vulnerability का exploitation पिछली vulnerability के समान ही है। इस मामले में हम **`application.app/Contents`** से एक Apple Archive बनाएंगे, इसलिए **`application.app`** को **Archive Utility** द्वारा decompress किए जाने पर quarantine attr नहीं मिलेगा।<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) देखें।<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** का उपयोग किसी को भी फ़ाइल में attribute लिखने से रोकने के लिए किया जा सकता है:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
इसके अलावा, **AppleDouble** file format किसी file को उसके ACEs समेत copy करता है।<sup>[[9]](#references)</sup>

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में यह देखना संभव है कि **`com.apple.acl.text`** नामक xattr के अंदर stored ACL text representation को decompressed file में ACL के रूप में set किया जाएगा। इसलिए, यदि आपने किसी application को **AppleDouble** file format के साथ ऐसी ACL वाले zip file में compress किया, जो अन्य xattrs को उसमें लिखे जाने से रोकती है... तो application में quarantine xattr set नहीं हुआ:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) देखें।<sup>[[9]](#references)</sup>

ध्यान दें कि इसका AppleArchives के साथ भी exploit किया जा सकता है:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

यह पता चला कि **Google Chrome डाउनलोड की गई files पर quarantine attribute सेट नहीं कर रहा था**, जिसका कारण macOS की कुछ internal समस्याएँ थीं।<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble किसी file के attributes को एक अलग file में store करता है, जिसका नाम `._` से शुरू होता है; इससे file attributes को **macOS machines के बीच copy करने** में मदद मिलती है। हालाँकि, AppleDouble file को decompress करने के बाद, `._` से शुरू होने वाली file को **quarantine attribute नहीं दिया गया**।<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
ऐसी फ़ाइल बनाने में सक्षम होने पर, जिसमें quarantine attribute सेट नहीं होगा, **Gatekeeper को bypass करना संभव था।** तरीका यह था कि AppleDouble naming convention का उपयोग करके एक **DMG file application** बनाई जाए (इसे `._` से शुरू किया जाए) और इस hidden फ़ाइल के लिए quarantine attribute के बिना एक **visible file को sym link** के रूप में बनाया जाए।\
जब **dmg file को execute किया जाता है**, तो उसमें quarantine attribute न होने के कारण यह **Gatekeeper को bypass कर देगी।**
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

macOS Sonoma 14.0 में fixed किया गया एक Gatekeeper bypass crafted apps को बिना prompt दिखाए run होने देता था। Patching के बाद details publicly disclose की गईं और fix से पहले यह issue wild में actively exploited था। सुनिश्चित करें कि Sonoma 14.0 या बाद का version installed हो।<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4 (March 2024 में released) में एक Gatekeeper bypass, malicious ZIPs की `libarchive` handling से उत्पन्न हुआ, जिससे apps assessment से बच सकती थीं। 14.4 या बाद के version पर update करें, जहां Apple ने इस issue को address किया।<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

एक downloaded app में embedded **Automator Quick Action workflow**, Gatekeeper assessment के बिना trigger हो सकता था, क्योंकि workflows को data की तरह treat किया जाता था और सामान्य notarization prompt path के बाहर Automator helper द्वारा execute किया जाता था। इसलिए, shell script run करने वाले Quick Action को bundle करने वाला crafted `.app` (जैसे `Contents/PlugIns/*.workflow/Contents/document.wflow` के अंदर) launch होते ही execute हो सकता था। Apple ने Ventura **13.7**, Sonoma **14.7**, और Sequoia **15** में एक extra consent dialog जोड़ा और assessment path को fix किया।<sup>[[3]](#references)</sup>

### Third‑party unarchivers द्वारा quarantine का गलत propagation (2023–2024)

लोकप्रिय extraction tools (जैसे The Unarchiver) में कई vulnerabilities के कारण archives से extracted files में `com.apple.quarantine` xattr नहीं जुड़ता था, जिससे Gatekeeper bypass के अवसर मिलते थे। Testing करते समय हमेशा macOS Archive Utility या patched tools पर निर्भर रहें और extraction के बाद xattrs को validate करें।

### uchg (इस [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf) से)

- एक ऐसा directory बनाएं जिसमें एक app हो।
- app में uchg जोड़ें।
- app को tar.gz file में compress करें।
- tar.gz file victim को भेजें।
- victim tar.gz file खोलता है और app run करता है।
- Gatekeeper app को check नहीं करता।<sup>[[12]](#references)</sup>

### Quarantine xattr को रोकना

यदि किसी ".app" bundle में quarantine xattr add नहीं किया गया है, तो उसे execute करने पर **Gatekeeper trigger नहीं होगा**।

## References

- [1] [Apple Platform Security: macOS Sonoma 14.4 के security content के बारे में (इसमें CVE-2024-27853 शामिल है)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS अब apps की provenance को कैसे track करता है](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7 के security content के बारे में (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia ने Control‑click “Open” Gatekeeper bypass को हटा दिया](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: CVE-2021-1810 की discovery](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper को bypass करना](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs ने Gatekeeper bypass की अनुमति देने वाली Safari vulnerability की पहचान की](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs ने Gatekeeper bypass की अनुमति देने वाली macOS Archive Utility vulnerability की पहचान की (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper की Achilles heel: एक macOS vulnerability की खोज](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: एक Gatekeeper Bypass की discovery (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor की सहायता से Gatekeeper bypass exploit को खोजना और report करना](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS Security और Privacy Mechanisms को bypass करना — Gatekeeper से System Integrity Protection तक (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14 के security content के बारे में (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
{{#include ../../../banners/hacktricks-training.md}}
