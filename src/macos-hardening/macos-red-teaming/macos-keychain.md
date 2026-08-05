# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), जिसका उपयोग **user-specific credentials** जैसे application passwords, internet passwords, user-generated certificates, network passwords और user-generated public/private keys को store करने के लिए किया जाता है।
- **System Keychain** (`/Library/Keychains/System.keychain`), जिसमें **system-wide credentials** जैसे WiFi passwords, system root certificates, system private keys और system application passwords store होते हैं।<sup>[[1]](#references)</sup>
- `/System/Library/Keychains/*` में certificates जैसे अन्य components भी मिल सकते हैं।
- **iOS** में केवल एक **Keychain** होता है, जो `/private/var/Keychains/` में स्थित होता है। इस folder में `TrustStore`, certificate authorities (`caissuercache`) और OSCP entries (`ocspache`) के databases भी होते हैं।
- Apps को उनके application identifier के आधार पर Keychain में केवल उनके private area तक restricted किया जाता है।

### Password Keychain Access

इन files में inherent protection नहीं होती और इन्हें **downloaded** किया जा सकता है, लेकिन ये encrypted होती हैं और इन्हें decrypt करने के लिए **user's plaintext password** आवश्यक होता है। [**Chainbreaker**](https://github.com/n0fate/chainbreaker) जैसे tool का उपयोग decryption के लिए किया जा सकता है।<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain की प्रत्येक entry **Access Control Lists (ACLs)** द्वारा नियंत्रित होती है, जो यह निर्धारित करती हैं कि कौन Keychain entry पर विभिन्न actions perform कर सकता है, जिनमें शामिल हैं:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: holder को secret का clear text प्राप्त करने की अनुमति देता है।
- **ACLAuhtorizationExportWrapped**: holder को किसी अन्य provided password से encrypted clear text प्राप्त करने की अनुमति देता है।
- **ACLAuhtorizationAny**: holder को कोई भी action perform करने की अनुमति देता है।

ACLs के साथ **trusted applications की list** भी होती है, जो बिना prompting के ये actions perform कर सकती हैं। यह हो सकता है:<sup>[[1]](#references)</sup>

- **N`il`** (किसी authorization की आवश्यकता नहीं, **everyone is trusted**)
- एक **empty** list (**nobody** is trusted)
- Specific **applications** की **list**।

Entry में **`ACLAuthorizationPartitionID`,** key भी हो सकती है, जिसका उपयोग **teamid, apple,** और **cdhash** की पहचान करने के लिए किया जाता है।<sup>[[1]](#references)</sup>

- यदि **teamid** specified है, तो **prompt** के बिना **entry** value **access** करने के लिए used application का **same teamid** होना आवश्यक है।
- यदि **apple** specified है, तो app को **Apple** द्वारा **signed** होना आवश्यक है।
- यदि **cdhash** indicated है, तो **app** में specific **cdhash** होना आवश्यक है।

### Creating a Keychain Entry

जब **`Keychain Access.app`** का उपयोग करके **new** **entry** बनाई जाती है, तो निम्न rules लागू होते हैं:<sup>[[1]](#references)</sup>

- सभी apps encrypt कर सकती हैं।
- **No apps** export/decrypt कर सकती हैं (user को prompt किए बिना)।
- सभी apps integrity check देख सकती हैं।
- कोई भी app ACLs को change नहीं कर सकती।
- **partitionID** को **`apple`** पर set किया जाता है।

जब कोई **application** Keychain में entry create करती है, तो rules थोड़े अलग होते हैं:<sup>[[1]](#references)</sup>

- सभी apps encrypt कर सकती हैं।
- केवल **creating application** (या explicitly added अन्य apps) export/decrypt कर सकती हैं (user को prompt किए बिना)।
- सभी apps integrity check देख सकती हैं।
- कोई भी app ACLs को change नहीं कर सकती।
- **partitionID** को **`teamid:[teamID here]`** पर set किया जाता है।

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> ऐसे secrets की **keychain enumeration and dumping**, जो **prompt generate नहीं करेंगे**, tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) से की जा सकती है।
>
> अन्य API endpoints [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code में मिल सकते हैं।

**Security Framework** का उपयोग करके प्रत्येक keychain entry के बारे में **info** की सूची बनाएं और प्राप्त करें। आप Apple के open source cli tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** को भी देख सकते हैं। कुछ API examples:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** प्रत्येक entry की info देता है और इसका उपयोग करते समय कुछ attributes सेट किए जा सकते हैं:
- **`kSecReturnData`**: यदि true है, तो यह data को decrypt करने का प्रयास करेगा (संभावित pop-ups से बचने के लिए false सेट करें)
- **`kSecReturnRef`**: keychain item का reference भी प्राप्त करें (यदि बाद में पता चले कि pop-up के बिना decrypt किया जा सकता है, तो इसे true सेट करें)
- **`kSecReturnAttributes`**: entries के बारे में metadata प्राप्त करें
- **`kSecMatchLimit`**: कितने results लौटाने हैं
- **`kSecClass`**: keychain entry किस प्रकार की है

प्रत्येक entry की **ACLs** प्राप्त करें:<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`** से आप **keychain item के ACL** प्राप्त कर सकते हैं। यह ACLs की एक सूची लौटाएगा (जैसे `ACLAuhtorizationExportClear` और पहले बताए गए अन्य ACLs), जिसमें प्रत्येक list में शामिल होते हैं:
- Description
- **Trusted Application List**। इसमें शामिल हो सकता है:
- एक app: /Applications/Slack.app
- एक binary: /usr/libexec/airportd
- एक group: group://AirPort

Data export करें:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** plaintext प्राप्त करता है
- API **`SecItemExport`** keys और certificates export करता है, लेकिन content को encrypted रूप में export करने के लिए passwords सेट करने पड़ सकते हैं

और ये वे **requirements** हैं जिनसे **बिना prompt के secret export** किया जा सकता है:<sup>[[1]](#references)</sup>

- यदि **1+ trusted** apps सूचीबद्ध हैं:
- उपयुक्त **authorizations** आवश्यक हैं (**`Nil`**, या secret info access करने के authorization में allowed apps की list का **part** होना)
- code signature का **PartitionID** से match करना आवश्यक है
- code signature का किसी एक **trusted app** से match करना आवश्यक है (या सही KeychainAccessGroup का member होना आवश्यक है)
- यदि **all applications trusted** हैं:
- उपयुक्त **authorizations** आवश्यक हैं
- code signature का **PartitionID** से match करना आवश्यक है
- यदि **no PartitionID** है, तो इसकी आवश्यकता नहीं है

> [!CAUTION]
> इसलिए, यदि **1 application listed** है, तो आपको उस application में **code inject** करना होगा।
>
> यदि **partitionID** में **apple** indicate किया गया है, तो आप इसे **`osascript`** से access कर सकते हैं। यानी वे सभी applications जो partitionID में apple के साथ trusting कर रही हैं। इसके लिए **`Python`** का भी उपयोग किया जा सकता है।

### दो अतिरिक्त attributes

- **Invisible**: यह एक boolean flag है, जो entry को **UI** Keychain app से **hide** करता है<sup>[[1]](#references)</sup>
- **General**: इसका उपयोग **metadata** store करने के लिए होता है (इसलिए यह **ENCRYPTED नहीं है**)<sup>[[1]](#references)</sup>
- Microsoft सभी refresh tokens को plaintext में store कर रहा था, ताकि sensitive endpoint access किए जा सकें।<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
