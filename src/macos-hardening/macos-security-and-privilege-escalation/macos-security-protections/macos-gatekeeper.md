# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** Mac operating systems के लिए विकसित एक security feature है, जिसे यह सुनिश्चित करने के लिए बनाया गया है कि users अपने systems पर **केवल trusted software चलाएं**। यह उस software को **validate** करके काम करता है जिसे user डाउनलोड करता है और **App Store के बाहर के sources** से खोलने का प्रयास करता है, जैसे कोई app, plug-in या installer package।

Gatekeeper का मुख्य mechanism इसकी **verification** process में है। यह जांचता है कि डाउनलोड किया गया software **किसी recognized developer द्वारा signed है या नहीं**, जिससे software की authenticity सुनिश्चित होती है। इसके अलावा, यह पता लगाता है कि software **Apple द्वारा notarised है या नहीं**, जिससे यह पुष्टि होती है कि उसमें कोई ज्ञात malicious content नहीं है और notarisation के बाद उसके साथ छेड़छाड़ नहीं की गई है।

इसके अतिरिक्त, Gatekeeper पहली बार डाउनलोड किए गए software को खोलने के लिए **users से approval लेने** के माध्यम से user control और security को मजबूत करता है। यह safeguard users को अनजाने में संभावित रूप से हानिकारक executable code चलाने से रोकने में मदद करता है, जिसे उन्होंने गलती से harmless data file समझ लिया हो।

### Application Signatures

Application signatures, जिन्हें code signatures भी कहा जाता है, Apple के security infrastructure का एक महत्वपूर्ण component हैं। इनका उपयोग **software author (developer) की identity verify करने** और यह सुनिश्चित करने के लिए किया जाता है कि code पर उसके last signed होने के बाद से कोई छेड़छाड़ नहीं की गई है।

यह इस प्रकार काम करता है:

1. **Signing the Application:** जब कोई developer अपना application distribute करने के लिए तैयार होता है, तो वह **private key का उपयोग करके application को sign करता है**। यह private key उस **certificate से जुड़ी होती है जो Apple developer को Apple Developer Program में enrol करने पर जारी करता है**। Signing process में app के सभी parts का cryptographic hash बनाना और इस hash को developer की private key से encrypt करना शामिल होता है।
2. **Distributing the Application:** इसके बाद signed application को developer के certificate के साथ users तक distribute किया जाता है, जिसमें संबंधित public key होती है।
3. **Verifying the Application:** जब कोई user application डाउनलोड करके उसे चलाने का प्रयास करता है, तो उसका Mac operating system developer के certificate से public key का उपयोग करके hash को decrypt करता है। इसके बाद वह application की current state के आधार पर hash को फिर से calculate करता है और इसकी तुलना decrypted hash से करता है। यदि दोनों match करते हैं, तो इसका अर्थ है कि **developer द्वारा sign किए जाने के बाद application में कोई modification नहीं किया गया है**, और system application को चलने की अनुमति देता है।

Application signatures Apple की Gatekeeper technology का एक आवश्यक हिस्सा हैं। जब कोई user **internet से डाउनलोड किए गए application को खोलने** का प्रयास करता है, तो Gatekeeper application signature verify करता है। यदि इसे Apple द्वारा किसी known developer को जारी किए गए certificate से sign किया गया है और code के साथ छेड़छाड़ नहीं की गई है, तो Gatekeeper application को चलने की अनुमति देता है। अन्यथा, यह application को block करके user को alert करता है।

macOS Catalina से शुरू होकर, **Gatekeeper यह भी जांचता है कि application Apple द्वारा notarized है या नहीं**, जिससे security की एक अतिरिक्त layer जुड़ती है। Notarization process application में ज्ञात security issues और malicious code की जांच करती है, और यदि ये checks pass हो जाएं, तो Apple application में एक ticket जोड़ता है जिसे Gatekeeper verify कर सकता है।

#### Check Signatures

किसी **malware sample** की जांच करते समय आपको हमेशा binary का **signature check करना चाहिए**, क्योंकि इसे sign करने वाला **developer** पहले से **malware से related** हो सकता है।
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

Apple की notarization प्रक्रिया उपयोगकर्ताओं को संभावित रूप से हानिकारक software से बचाने के लिए एक अतिरिक्त सुरक्षा उपाय के रूप में कार्य करती है। इसमें **developer द्वारा अपनी application को जांच के लिए submit करना** शामिल है, जिसकी जांच **Apple's Notary Service** करता है। इसे App Review के साथ भ्रमित नहीं करना चाहिए। यह service एक **automated system** है, जो submitted software में **malicious content** और code-signing से जुड़ी संभावित समस्याओं की जांच करता है।

यदि software बिना किसी चिंता के इस जांच में **pass** हो जाता है, तो Notary Service एक notarization ticket तैयार करता है। इसके बाद developer को यह ticket अपने **software से attach करना** होता है; इस प्रक्रिया को 'stapling' कहा जाता है। इसके अतिरिक्त, notarization ticket को online भी प्रकाशित किया जाता है, जहां Gatekeeper, Apple की security technology, इसे access कर सकता है।

जब user पहली बार software को install या execute करता है, तो notarization ticket की मौजूदगी - चाहे वह executable के साथ stapled हो या online मिली हो - **Gatekeeper को बताती है कि software को Apple द्वारा notarize किया गया है**। परिणामस्वरूप, Gatekeeper initial launch dialog में एक descriptive message दिखाता है, जिसमें बताया जाता है कि Apple ने software में malicious content की जांच की है। इस प्रकार यह प्रक्रिया users द्वारा अपने systems पर install या run किए जाने वाले software की security में उनका confidence बढ़ाती है।

### spctl & syspolicyd

> [!CAUTION]
> ध्यान दें कि Sequoia version से **`spctl`** अब Gatekeeper configuration को modify करने की अनुमति नहीं देता।

**`spctl`** Gatekeeper को enumerate करने और उसके साथ interact करने का CLI tool है (XPC messages के माध्यम से `syspolicyd` daemon के साथ)। उदाहरण के लिए, निम्न command से **GateKeeper** का **status** देखा जा सकता है:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> ध्यान दें कि GateKeeper signature checks केवल **Quarantine attribute वाली files** पर किए जाते हैं, हर file पर नहीं।

GateKeeper यह जाँच करेगा कि **preferences और signature** के अनुसार किसी binary को execute किया जा सकता है या नहीं:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** Gatekeeper को लागू करने के लिए जिम्मेदार मुख्य daemon है। यह `/var/db/SystemPolicy` में स्थित database को maintain करता है और [database को support करने वाला code यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) तथा [SQL template यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) मिल सकता है। ध्यान दें कि database SIP द्वारा unrestricted है और root द्वारा writable है। Database `/var/db/.SystemPolicy-default` का उपयोग original backup के रूप में किया जाता है, यदि दूसरा database corrupt हो जाए।

इसके अलावा, bundles **`/var/db/gke.bundle`** और **`/var/db/gkopaque.bundle`** में ऐसी files होती हैं जिनमें database में insert किए जाने वाले rules होते हैं। आप root के रूप में इस database को निम्न command से check कर सकते हैं:
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
**`syspolicyd`** अलग-अलग operations जैसे `assess`, `update`, `record` और `cancel` वाला एक XPC server भी expose करता है, जिन्हें **`Security.framework`'s `SecAssessment*`** APIs का उपयोग करके भी access किया जा सकता है और **`spctl`** वास्तव में XPC के माध्यम से **`syspolicyd`** से communicate करता है।

ध्यान दें कि पहली rule "**App Store**" पर और दूसरी "**Developer ID**" पर समाप्त हुई थी और पिछले image में यह **App Store और identified developers से apps execute करने के लिए enabled** थी।\
यदि आप उस setting को App Store में **modify** करते हैं, तो "**Notarized Developer ID" rules गायब हो जाएंगी**।

**type GKE** की हजारों rules भी हैं:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
ये hashes इनसे हैं:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

या आप पिछली जानकारी को इस तरह सूचीबद्ध कर सकते हैं:
```bash
sudo spctl --list
```
**`spctl`** के **`--master-disable`** और **`--global-disable`** options इन signature checks को पूरी तरह **disable** कर देंगे:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
पूरी तरह सक्षम होने पर, एक नया विकल्प दिखाई देगा:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

इससे **जाँचना संभव है कि किसी App को GateKeeper द्वारा अनुमति दी जाएगी या नहीं**:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper में नए rules जोड़कर कुछ apps के execution की अनुमति देना संभव है:
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
Regarding **kernel extensions**, folder `/var/db/SystemPolicyConfiguration` में लोड किए जाने की अनुमति वाले kexts की सूचियों वाली files होती हैं। इसके अलावा, `spctl` के पास `com.apple.private.iokit.nvram-csr` entitlement है, क्योंकि यह नए pre-approved kernel extensions जोड़ सकता है, जिन्हें NVRAM में `kext-allowed-teams` key के अंतर्गत भी save करना आवश्यक होता है।

#### macOS 15 (Sequoia) और बाद के versions में Gatekeeper को manage करना

- लंबे समय से मौजूद Finder **Ctrl+Open / Right-click → Open** bypass को हटा दिया गया है; पहले block dialog के बाद users को **System Settings → Privacy & Security → Open Anyway** से blocked app को explicitly allow करना होगा।<sup>[4]</sup>
- `spctl --master-disable/--global-disable` अब स्वीकार नहीं किए जाते; assessment और label management के लिए `spctl` प्रभावी रूप से read-only है, जबकि policy enforcement को UI या MDM के माध्यम से configure किया जाता है।

macOS 15 Sequoia से शुरू होकर, end users अब `spctl` से Gatekeeper policy को toggle नहीं कर सकते। Management **System Settings** के माध्यम से या `com.apple.systempolicy.control` payload वाले MDM configuration profile को deploy करके किया जाता है। App Store और identified developers को allow करने के लिए (लेकिन "Anywhere" को नहीं) profile snippet का उदाहरण:

<details>
<summary>App Store और identified developers को allow करने वाला MDM profile</summary>
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

किसी application या file को **downloading** करने पर, कुछ macOS **applications**, जैसे web browsers या email clients, downloaded file में एक **extended file attribute** जोड़ते हैं, जिसे आमतौर पर "**quarantine flag**" कहा जाता है। यह attribute एक security measure के रूप में कार्य करता है और **file को mark** करता है कि वह किसी untrusted source (internet) से आई है और उसमें संभावित risks हो सकते हैं। हालांकि, सभी applications यह attribute नहीं जोड़ते; उदाहरण के लिए, सामान्य BitTorrent client software आमतौर पर इस process को bypass करता है।

**quarantine flag की मौजूदगी macOS के Gatekeeper security feature को signal करती है, जब user file को execute करने का प्रयास करता है**।

जब **quarantine flag मौजूद नहीं होता** (जैसे कुछ BitTorrent clients के माध्यम से downloaded files में), तो Gatekeeper के **checks शायद perform न किए जाएं**। इसलिए, users को कम secure या unknown sources से downloaded files खोलते समय सावधानी बरतनी चाहिए।

> [!NOTE] > **code signatures की validity को check करना** एक **resource-intensive** process है, जिसमें code और उसके सभी bundled resources के cryptographic **hashes generate** करना शामिल है। इसके अलावा, certificate validity check करने के लिए Apple के servers पर **online check** करना पड़ता है, ताकि यह पता लगाया जा सके कि जारी होने के बाद certificate revoke तो नहीं किया गया है। इन कारणों से, हर बार app launch होने पर full code signature और notarization check चलाना **impractical है**।
>
> इसलिए, ये checks **केवल quarantined attribute वाली apps को execute करते समय चलाए जाते हैं।**

> [!WARNING]
> यह attribute उस **application द्वारा set किया जाना चाहिए जो file create/download कर रही है**।
>
> हालांकि, sandboxed files बनाने वाली files में यह attribute set होगा। और non sandboxed apps इसे स्वयं set कर सकती हैं, या [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key को **Info.plist** में specify कर सकती हैं, जिससे system बनाई गई files पर `com.apple.quarantine` extended attribute set कर देगा,

इसके अलावा, **`qtn_proc_apply_to_self`** call करने वाली process द्वारा बनाई गई सभी files quarantined होती हैं। या **`qtn_file_apply_to_path`** API किसी specified file path में quarantine attribute जोड़ती है।

इसे **check करने और enable/disable करने** (root required) का तरीका है:
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
**extended** **attributes** का **value** जांचें और पता लगाएं कि quarantine attr किस app ने लिखा है:
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
वास्तव में, कोई process "अपने द्वारा बनाई गई files पर quarantine flags सेट कर सकता है" (मैंने पहले ही बनाई गई file में USER_APPROVED flag लागू करने का प्रयास किया था, लेकिन यह लागू नहीं हुआ):

<details>

<summary>Source Code से quarantine flags लागू करना</summary>
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

और **remove** उस attribute को:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
और सभी quarantined फ़ाइलें इससे खोजें:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information को LaunchServices द्वारा managed central database में भी store किया जाता है, जो **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** पर स्थित है और GUI को file origins के बारे में data प्राप्त करने की अनुमति देता है। इसके अलावा, इसे उन applications द्वारा overwrite किया जा सकता है जो इसके origins को छिपाने में interested हो सकती हैं। यह LaunchServices APIS के माध्यम से भी किया जा सकता है।

#### **libquarantine.dylib**

यह library कई functions export करती है, जो extended attribute fields को manipulate करने की अनुमति देते हैं।

`qtn_file_*` APIs file quarantine policies से deal करती हैं, जबकि `qtn_proc_*` APIs processes पर लागू होती हैं (process द्वारा बनाई गई files)। Unexported `__qtn_syscall_quarantine*` functions वे functions हैं जो policies को apply करती हैं और `mac_syscall` को पहले argument के रूप में "Quarantine" के साथ call करती हैं, जो requests को `Quarantine.kext` तक भेजता है।

#### **Quarantine.kext**

यह kernel extension केवल **system के kernel cache** के माध्यम से उपलब्ध है; हालांकि, आप [**https://developer.apple.com/**](https://developer.apple.com/) से **Kernel Debug Kit download** कर सकते हैं, जिसमें extension का symbolicated version होगा।

यह Kext MACF के माध्यम से कई calls को hook करेगा ताकि सभी file lifecycle events को trap किया जा सके: Creation, opening, renaming, hard-linkning... यहां तक कि `setxattr` को भी, ताकि उसे `com.apple.quarantine` extended attribute set करने से रोका जा सके।

यह कुछ MIBs का भी उपयोग करता है:

- `security.mac.qtn.sandbox_enforce`: Sandbox के साथ quarantine enforce करता है
- `security.mac.qtn.user_approved_exec`: Querantined procs केवल approved files को execute कर सकते हैं

#### Provenance xattr (Ventura और बाद के versions)

macOS 13 Ventura ने एक अलग provenance mechanism introduce किया, जो पहली बार किसी quarantined app को run करने की अनुमति मिलने पर populate होता है।<sup>[2]</sup> दो artefacts create किए जाते हैं:

- `.app` bundle directory पर `com.apple.provenance` xattr (primary key और flags वाला fixed-size binary value)।
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` पर ExecPolicy database के अंदर `provenance_tracking` table में एक row, जिसमें app का cdhash और metadata store होता है।

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

XProtect macOS में अंतर्निहित **anti-malware** feature है। XProtect **हर application को पहली बार launch या modify किए जाने पर उसके database में मौजूद** ज्ञात malware और असुरक्षित file types के विरुद्ध **जाँचता है**। जब आप Safari, Mail या Messages जैसे कुछ apps के माध्यम से कोई file download करते हैं, तो XProtect उस file को automatically scan करता है। यदि वह इसके database में मौजूद किसी ज्ञात malware से match करती है, तो XProtect **उस file को run होने से रोक देगा** और आपको threat के बारे में alert करेगा।

XProtect database को Apple द्वारा नए malware definitions के साथ **नियमित रूप से update** किया जाता है, और ये updates आपके Mac पर automatically download और install हो जाते हैं। इससे यह सुनिश्चित होता है कि XProtect नवीनतम ज्ञात threats के साथ हमेशा up-to-date रहे।

हालाँकि, यह ध्यान रखना महत्वपूर्ण है कि **XProtect एक full-featured antivirus solution नहीं है**। यह केवल ज्ञात threats की एक specific list की जाँच करता है और अधिकांश antivirus software की तरह on-access scanning नहीं करता।

आप निम्न command चलाकर नवीनतम XProtect update की जानकारी प्राप्त कर सकते हैं:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect **/Library/Apple/System/Library/CoreServices/XProtect.bundle** में स्थित SIP protected location है और bundle के अंदर आपको XProtect द्वारा उपयोग की जाने वाली जानकारी मिल सकती है:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: इन cdhashes वाले code को legacy entitlements उपयोग करने की अनुमति देता है।
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: उन plugins और extensions की सूची जिन्हें BundleID और TeamID के आधार पर load होने से रोका जाता है या जो minimum version दर्शाते हैं।
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware detect करने के लिए Yara rules।
- **`XProtect.bundle/Contents/Resources/gk.db`**: blocked applications और TeamIDs के hashes वाला SQLite3 database।

ध्यान दें कि **`/Library/Apple/System/Library/CoreServices/XProtect.app`** में एक अन्य App भी है जो XProtect से संबंधित है, लेकिन Gatekeeper process में शामिल नहीं है।

> XProtect Remediator: आधुनिक macOS पर Apple on-demand scanners (XProtect Remediator) उपलब्ध कराता है, जो malware families को detect और remediate करने के लिए launchd के माध्यम से समय-समय पर run होते हैं। आप इन scans को unified logs में देख सकते हैं:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper नहीं

> [!CAUTION]
> ध्यान दें कि Gatekeeper **हर बार** application execute करने पर **execute नहीं होता**। इसके बजाय, _**AppleMobileFileIntegrity**_ केवल **executable code signatures को verify** करेगा, जब आप ऐसा app execute करते हैं जिसे Gatekeeper द्वारा पहले ही execute और verify किया जा चुका है।

इसलिए, पहले किसी app को Gatekeeper के साथ cache करने के लिए execute करना, फिर application की **non-executable files को modify करना** (जैसे Electron asar या NIB files) संभव था और यदि कोई अन्य protections लागू नहीं होतीं, तो application को **malicious** additions के साथ **execute** किया जा सकता था।

हालांकि, अब यह संभव नहीं है क्योंकि macOS **application bundles के अंदर files को modify करने से रोकता है**। इसलिए, यदि आप [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack आजमाते हैं, तो पाएंगे कि अब इसका abuse करना संभव नहीं है, क्योंकि app को Gatekeeper के साथ cache करने के लिए execute करने के बाद आप bundle को modify नहीं कर पाएंगे। और यदि आप, उदाहरण के लिए, Contents directory का नाम बदलकर NotCon कर देते हैं (जैसा कि exploit में बताया गया है), और फिर app के main binary को Gatekeeper के साथ cache करने के लिए execute करते हैं, तो यह एक error trigger करेगा और execute नहीं होगा।

## Gatekeeper Bypasses

Gatekeeper को bypass करने का कोई भी तरीका (user से कुछ download करवाकर उसे execute करवाना, जबकि Gatekeeper को उसे disallow करना चाहिए) macOS में vulnerability माना जाता है। ये कुछ CVEs हैं, जो उन techniques को assign किए गए थे जिनसे अतीत में Gatekeeper को bypass किया जा सकता था:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

यह देखा गया कि यदि extraction के लिए **Archive Utility** का उपयोग किया जाता है, तो **886 characters से अधिक लंबे paths** वाली files को com.apple.quarantine extended attribute नहीं मिलता। यह स्थिति अनजाने में उन files को Gatekeeper के security checks को **circumvent करने** की अनुमति देती है।<sup>[5]</sup>

अधिक जानकारी के लिए [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) देखें।

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

जब कोई application **Automator** के साथ बनाई जाती है, तो उसे execute करने के लिए आवश्यक जानकारी executable में नहीं, बल्कि `application.app/Contents/document.wflow` के अंदर होती है। Executable केवल एक generic Automator binary होती है, जिसे **Automator Application Stub** कहा जाता है।

इसलिए, आप `application.app/Contents/MacOS/Automator\ Application\ Stub` को **system के अंदर मौजूद किसी अन्य Automator Application Stub से symbolic link के माध्यम से point** करा सकते हैं और यह `document.wflow` (आपकी script) के अंदर मौजूद चीज़ों को **Gatekeeper trigger किए बिना execute** करेगा, क्योंकि actual executable में quarantine xattr नहीं होता।<sup>[6]</sup>

उदाहरण के लिए अपेक्षित location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

अधिक जानकारी के लिए [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) देखें।

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

इस bypass में एक zip file बनाई गई थी, जिसमें compression `application.app` के बजाय `application.app/Contents` से शुरू किया गया था। इसलिए **quarantine attr** `application.app/Contents` की **सभी files** पर apply हुआ, लेकिन `application.app` पर नहीं। Gatekeeper इसी `application.app` को check कर रहा था, इसलिए Gatekeeper bypass हो गया, क्योंकि जब `application.app` को trigger किया गया, तो **उसमें quarantine attribute नहीं था।**<sup>[7]</sup>
```bash
zip -r test.app/Contents test.zip
```
अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) देखें।

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

भले ही components अलग हों, इस vulnerability का exploitation पिछली vulnerability के समान ही है। इस मामले में हम **`application.app/Contents`** से एक Apple Archive generate करेंगे, इसलिए **`application.app`** को **Archive Utility** द्वारा decompress किए जाने पर quarantine attr नहीं मिलेगा।<sup>[8]</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) देखें।

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** का उपयोग किसी को भी फ़ाइल में कोई attribute लिखने से रोकने के लिए किया जा सकता है:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
इसके अलावा, **AppleDouble** file format किसी file को उसके ACEs सहित copy करता है।<sup>[9]</sup>

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में देखा जा सकता है कि **`com.apple.acl.text`** नामक xattr में संग्रहीत ACL text representation को decompressed file में ACL के रूप में set किया जाता है। इसलिए, यदि आपने **AppleDouble** file format का उपयोग करके किसी application को ऐसी ACL के साथ zip file में compress किया है, जो उसमें अन्य xattrs को लिखे जाने से रोकती है... तो quarantine xattr application में set नहीं हुआ:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) देखें।

ध्यान दें कि इसका exploitation AppleArchives के साथ भी किया जा सकता है:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

यह पता चला कि **Google Chrome downloaded files पर quarantine attribute सेट नहीं कर रहा था**, क्योंकि macOS की कुछ internal समस्याएँ थीं।<sup>[10]</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble file formats किसी file के attributes को `._` से शुरू होने वाली एक अलग file में store करते हैं, जिससे **macOS machines के बीच file attributes** copy करने में मदद मिलती है। हालांकि, यह देखा गया कि AppleDouble file को decompress करने के बाद, `._` से शुरू होने वाली file को **quarantine attribute नहीं दिया गया**।<sup>[11]</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
ऐसी फ़ाइल बनाने में सक्षम होना, जिसमें quarantine attribute सेट न हो, **Gatekeeper को bypass करना संभव बनाता था।** तरीका यह था कि AppleDouble name convention (इसे `._` से शुरू करके) का उपयोग करके एक **DMG file application** बनाई जाए और इस hidden फ़ाइल के लिए एक **visible file को sym link** के रूप में बनाया जाए, जिसमें quarantine attribute न हो।\
जब **dmg file execute की जाती है**, तो उसमें quarantine attribute न होने के कारण यह **Gatekeeper को bypass कर देती है।**
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

macOS Sonoma 14.0 में ठीक किया गया एक Gatekeeper bypass crafted apps को prompt दिखाए बिना चलने देता था। Patching के बाद इसके details सार्वजनिक किए गए और fix से पहले यह issue wild में actively exploited था। सुनिश्चित करें कि Sonoma 14.0 या बाद का version installed हो।

### [CVE-2024-27853]

macOS 14.4 (March 2024 में released) में मौजूद एक Gatekeeper bypass, malicious ZIPs को `libarchive` द्वारा handle किए जाने से उत्पन्न हुआ था और apps को assessment से बच निकलने देता था। 14.4 या बाद के version पर update करें, जिसमें Apple ने इस issue को address किया है।<sup>[1]</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

किसी downloaded app में embedded **Automator Quick Action workflow**, Gatekeeper assessment के बिना trigger हो सकता था, क्योंकि workflows को data के रूप में treat किया जाता था और normal notarization prompt path के बाहर Automator helper द्वारा execute किया जाता था। इसलिए, shell script चलाने वाले Quick Action को bundle करने वाला crafted `.app` (जैसे `Contents/PlugIns/*.workflow/Contents/document.wflow` के अंदर) launch होते ही execute हो सकता था। Apple ने अतिरिक्त consent dialog जोड़ा और Ventura **13.7**, Sonoma **14.7**, तथा Sequoia **15** में assessment path को ठीक किया।<sup>[3]</sup>

### Third‑party unarchivers द्वारा quarantine का गलत propagation (2023–2024)

लोकप्रिय extraction tools (जैसे The Unarchiver) में मौजूद कई vulnerabilities के कारण archives से extracted files में `com.apple.quarantine` xattr नहीं जुड़ता था, जिससे Gatekeeper bypass के अवसर मिलते थे। Testing करते समय हमेशा macOS Archive Utility या patched tools पर निर्भर रहें और extraction के बाद xattrs को validate करें।

### uchg (इस [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf) से)

- एक ऐसा directory बनाएँ जिसमें कोई app हो।
- app में uchg जोड़ें।
- app को tar.gz file में compress करें।
- tar.gz file victim को भेजें।
- victim tar.gz file खोलकर app चलाता है।
- Gatekeeper app को check नहीं करता।<sup>[12]</sup>

### Quarantine xattr को रोकना

यदि किसी ".app" bundle में quarantine xattr add नहीं किया गया है, तो उसे execute करने पर **Gatekeeper trigger नहीं होगा**।


## References

- [1] [Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: How macOS now tracks the provenance of apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: The Discovery of CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypassing The macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifies Safari vulnerability allowing for Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifies macOS Archive Utility vulnerability allowing for Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper's Achilles heel: Unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Discovery of a Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Finding and reporting a Gatekeeper bypass exploit with help from Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypassing macOS Security and Privacy Mechanisms — From Gatekeeper to System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
