# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## मुख्य Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), जिसका उपयोग **user-specific credentials** जैसे application passwords, internet passwords, user-generated certificates, network passwords और user-generated public/private keys को स्टोर करने के लिए किया जाता है।
- **System Keychain** (`/Library/Keychains/System.keychain`), जो **system-wide credentials** जैसे WiFi passwords, system root certificates, system private keys और system application passwords स्टोर करता है।<sup>[[1]](#references)</sup>
  - `/System/Library/Keychains/*` में certificates जैसे अन्य components भी मिल सकते हैं।
- प्रति-user **data protection keychain**, Keychain Access में **Local Items** या **iCloud** के रूप में दिखाई देता है। यह `login.keychain-db` से अलग होता है और इसमें केवल local तथा synchronizable, दोनों तरह के items शामिल होते हैं; `security` मुख्य रूप से file-based-keychain टूल है, इसलिए `dump-keychain` का छोटा-सा परिणाम यह साबित नहीं करता कि यहाँ credentials मौजूद नहीं हैं।<sup>[[5]](#references)</sup>
- **iOS** में `/private/var/Keychains/` में केवल एक **Keychain** होता है। इस folder में `TrustStore`, certificates authorities (`caissuercache`) और OSCP entries (`ocspache`) के databases भी होते हैं।
  - Apps को application identifier के आधार पर keychain में केवल अपने private area तक सीमित रखा जाता है।

### Password Keychain Access

कॉपी किया हुआ **file-based** keychain plaintext नहीं होता। इसके protected items को offline decrypt करने के लिए keychain password या उसके बराबर key material की ज़रूरत होती है; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) इस format को target करता है।<sup>[[1]](#references)</sup> यह unlocked user session में live read से अलग है, जहाँ item access controls पढ़ने की अनुमति दे सकते हैं या login password दोबारा माँगे बिना prompt दिखा सकते हैं। data protection keychain में protection और access-group का अलग model होता है।<sup>[[5]](#references)</sup>

## Keychain Entries की Protections

### File-based keychain ACLs

नीचे दिए गए `SecAccess` ACL और partition-list rules **file-based** keychains के लिए हैं। इसके बजाय, data protection keychain items code-signing access groups और वैकल्पिक `SecAccessControl` conditions का उपयोग करते हैं; file-based ACL dump से उनकी accessibility का अनुमान न लगाएँ।<sup>[[5]](#references)</sup>

File-based keychain में हर entry **Access Control Lists (ACLs)** द्वारा नियंत्रित होती है, जो तय करती हैं कि keychain entry पर कौन-से actions कौन कर सकता है, जिनमें ये शामिल हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Holder को secret का clear text प्राप्त करने देता है।
- **`kSecACLAuthorizationExportWrapped`**: Holder को clear text, दिए गए दूसरे password से encrypted रूप में प्राप्त करने देता है।
- **`kSecACLAuthorizationAny`**: Holder को कोई भी action करने देता है।

ACLs के साथ **trusted applications की list** भी होती है, जो बिना prompt के ये actions कर सकती हैं। यह इनमें से कोई हो सकती है:<sup>[[1]](#references)</sup>

- **N`il`** (किसी authorization की ज़रूरत नहीं, **हर कोई trusted है**)
- **खाली** list (**कोई भी trusted नहीं है**)
- विशिष्ट **applications** की **list**।

Entry में **`kSecACLAuthorizationPartitionID`** key भी हो सकती है, जिसका उपयोग **teamid, apple,** और **cdhash** की पहचान के लिए किया जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

- यदि **teamid** निर्दिष्ट है, तो entry की value को **बिना** **prompt** के **access** करने के लिए application का **teamid समान** होना चाहिए।
- यदि **apple** निर्दिष्ट है, तो app को **Apple** द्वारा **signed** होना चाहिए।
- यदि **cdhash** दिया गया है, तो **app** का **cdhash** वही विशिष्ट cdhash होना चाहिए।

### File-based keychain entry बनाना

**`Keychain Access.app`** का उपयोग करके कोई **नई** **entry** बनाई जाती है, तो ये rules लागू होते हैं:<sup>[[1]](#references)</sup>

- सभी apps encrypt कर सकते हैं।
- कोई भी app (user से prompt किए बिना) export/decrypt नहीं कर सकता।
- सभी apps integrity check देख सकते हैं।
- कोई भी app ACLs नहीं बदल सकता।
- **partitionID** को **`apple`** पर सेट किया जाता है।

जब कोई **application keychain में entry बनाती है**, तो rules थोड़े अलग होते हैं:<sup>[[1]](#references)</sup>

- सभी apps encrypt कर सकते हैं।
- केवल **entry बनाने वाला application** (या स्पष्ट रूप से जोड़े गए अन्य apps) (user से prompt किए बिना) export/decrypt कर सकते हैं।
- सभी apps integrity check देख सकते हैं।
- कोई भी app ACLs नहीं बदल सकता।
- **partitionID** को **`teamid:[teamID here]`** पर सेट किया जाता है।

## Keychain को Access करना

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` आइटम की partition list सेट करता है, जबकि `-k` वह मौजूदा Keychain password देता है जो यह बदलाव करने के लिए ज़रूरी है; password लेने वाला flag deprecated है।<sup>[[4]](#references)</sup> सफल update से यह साबित नहीं होता कि बाद में read करने पर कोई prompt नहीं आएगा: एक देखे गए, disabled prototype ने `Security.framework` के ज़रिए आइटम query करने पर भी confirmation prompt दिखाया। Matching partition ID, ऊपर बताए गए ACL और trusted-application checks का केवल एक हिस्सा है, इसलिए वास्तविक read path की पुष्टि करें।<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> secrets की **keychain enumeration और dumping**, जिससे **prompt नहीं आएगा**, [**LockSmith**](https://github.com/its-a-feature/LockSmith) tool से की जा सकती है।
>
> अन्य API endpoints, [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code में मिल सकते हैं।

**Security Framework** का उपयोग करके हर keychain entry की **info** list करें और प्राप्त करें, या Apple के open source cli tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** को भी देख सकते हैं। API के कुछ उदाहरण:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** हर entry की info देता है और इसका उपयोग करते समय कुछ attributes सेट किए जा सकते हैं:
  - **`kSecReturnData`**: यदि true हो, तो यह data को decrypt करने की कोशिश करेगा (संभावित pop-ups से बचने के लिए इसे false सेट करें)
  - **`kSecReturnRef`**: किसी key, certificate या identity के लिए object reference प्राप्त करें; password items का यह object representation नहीं होता। बाद में targeted query के लिए password की पहचान हेतु `kSecReturnPersistentRef` का उपयोग करें।<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: entries का metadata प्राप्त करें
  - **`kSecMatchLimit`**: लौटाए जाने वाले results की संख्या
  - **`kSecClass`**: keychain entry का प्रकार

हर entry के **ACLs** प्राप्त करें:<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`** से **keychain item का ACL** प्राप्त किया जा सकता है। यह ACLs की एक list लौटाता है (जैसे `kSecACLAuthorizationExportClear` और पहले बताए गए अन्य ACLs), जिसमें हर entry में ये होते हैं:<sup>[[1]](#references)[[2]](#references)</sup>
  - Description
  - **Trusted Application List**। इसमें ये हो सकते हैं:
    - कोई app: /Applications/Slack.app
    - कोई binary: /usr/libexec/airportd
    - कोई group: group://AirPort

Data export करें:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** plaintext प्राप्त करता है
- API **`SecItemExport`** keys और certificates export करता है, लेकिन content को encrypted रूप में export करने के लिए password सेट करने पड़ सकते हैं

और ये वे **requirements** हैं जिनके ज़रिए **बिना prompt के secret export** किया जा सकता है:<sup>[[1]](#references)</sup>

- यदि **1+ trusted** apps सूचीबद्ध हैं:
  - उचित **authorizations** चाहिए (**`Nil`**, या secret info तक access के authorization में अनुमत apps की list का **हिस्सा** होना)
  - Code signature का **PartitionID** से match होना ज़रूरी है
  - Code signature का किसी एक **trusted app** से match होना ज़रूरी है (या सही KeychainAccessGroup का member होना)
- यदि **all applications trusted** हैं:
  - उचित **authorizations** चाहिए
  - Code signature का **PartitionID** से match होना ज़रूरी है
    - यदि **PartitionID नहीं है**, तो इसकी ज़रूरत नहीं है

> [!CAUTION]
> इसलिए, यदि **1 application सूचीबद्ध है**, तो आपको उस **application में code inject करना होगा**।
>
> यदि **partitionID** में **apple** दिया गया है, तो आप इसे **`osascript`** से access कर सकते हैं—यानी partitionID में apple वाले सभी applications को trust करने वाली किसी भी चीज़ से। इसके लिए **`Python`** का भी उपयोग किया जा सकता है।

### दो अतिरिक्त attributes

- **Invisible**: यह एक boolean flag है जो entry को Keychain app के **UI** से **छिपाता** है<sup>[[1]](#references)</sup>
- **General**: इसका उपयोग **metadata** store करने के लिए होता है (इसलिए यह ENCRYPTED नहीं होता)<sup>[[1]](#references)</sup>
  - Microsoft sensitive endpoint तक access के लिए सभी refresh tokens को plaintext में store कर रहा था।<sup>[[1]](#references)</sup>

### Data protection keychain: पहले enumerate करें, फिर एक item query करें

`kSecUseDataProtectionKeychain: true` के साथ target user के login context में किसी **signed app** से `SecItemCopyMatching` चलाएँ; यह न मानें कि `security dump-keychain` या default SecItem query ने इस store को search किया है। Caller को केवल अपने authorized access groups दिखाई देते हैं।<sup>[[5]](#references)</sup>

यदि testing code किसी अन्य process के अंदर चलता है, तो उसका data protection keychain access उस host executable के entitlements के अनुसार होता है। `codesign -d --entitlements - /path/to/Target.app` से वास्तविक signed entitlements जाँचें और संबंधित checks के लिए [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) देखें।<sup>[[7]](#references)</sup>

पहले किसी एक item class के लिए केवल **attributes** माँगें। `kSecAttrSynchronizableAny` में local और iCloud-synchronizable, दोनों तरह के matches शामिल होते हैं; इसे छोड़ने पर synchronizable items शामिल नहीं होते।<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` व्यापक enumeration के दौरान authentication UI को रोकता है, लेकिन इसके बदले protected matches छोड़ देता है।<sup>[[9]](#references)</sup> ज़रूरत पड़ने पर `kSecClassInternetPassword` के साथ दोहराएँ।

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

अनुमत secret read के लिए, चुने गए item (उदाहरण के लिए, class, service और account) के लिए एक **नई**, सीमित query बनाएँ, `kSecReturnData: true` और `kSecMatchLimit: kSecMatchLimitOne` सेट करें, और item-विशिष्ट authentication या error की अपेक्षा रखें। Password items के लिए `kSecReturnData` को `kSecMatchLimitAll` के साथ **नहीं** जोड़ें।<sup>[[10]](#references)</sup> `errSecItemNotFound` परिणाम का अर्थ यह भी हो सकता है कि store गलत है, sync filter मेल नहीं खाता, या access-group entitlement मौजूद नहीं है—यह ज़रूरी नहीं कि credential अनुपस्थित ही हो।<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: "macOS Keychain का Lock Picking" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - MacSync macOS stealer का नया संस्करण crypto enthusiasts और developers को निशाना बनाता है](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) man page का mirror](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Mac keychain APIs और implementations के बारे में](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: मूल बातें](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: आम गलतियाँ और सर्वोत्तम तरीके](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Face ID या Touch ID से Keychain Items को access करना](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
