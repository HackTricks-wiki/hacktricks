# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## मुख्य Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), जिसका उपयोग **user-specific credentials** जैसे application passwords, internet passwords, user-generated certificates, network passwords और user-generated public/private keys को store करने के लिए किया जाता है।
- **System Keychain** (`/Library/Keychains/System.keychain`), जो **system-wide credentials** जैसे WiFi passwords, system root certificates, system private keys और system application passwords को store करता है।<sup>[[1]](#references)</sup>
- `/System/Library/Keychains/*` में certificates जैसे अन्य components को भी find करना संभव है।
- **iOS** में केवल एक **Keychain** होता है, जो `/private/var/Keychains/` में स्थित होता है। इस folder में `TrustStore`, certificate authorities (`caissuercache`) और OSCP entries (`ocspache`) के databases भी होते हैं।
- Apps को उनके application identifier के आधार पर keychain में केवल उनके private area तक restricted किया जाएगा।

### Password Keychain Access

इन files में inherent protection नहीं होती और इन्हें **downloaded** किया जा सकता है, लेकिन ये encrypted होती हैं और **user's plaintext password** की आवश्यकता होती है ताकि इन्हें **decrypted** किया जा सके। [**Chainbreaker**](https://github.com/n0fate/chainbreaker) जैसे tool का उपयोग decryption के लिए किया जा सकता है।<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain में प्रत्येक entry **Access Control Lists (ACLs)** द्वारा governed होती है, जो यह निर्धारित करती हैं कि keychain entry पर कौन विभिन्न actions perform कर सकता है, जिनमें शामिल हैं:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Holder को secret का clear text प्राप्त करने की अनुमति देता है।
- **ACLAuthorizationExportWrapped**: Holder को किसी अन्य provided password से encrypted clear text प्राप्त करने की अनुमति देता है।
- **ACLAuthorizationAny**: Holder को कोई भी action perform करने की अनुमति देता है।

ACLs के साथ trusted applications की एक **list** भी होती है, जो बिना prompting के ये actions perform कर सकती हैं। यह हो सकती है:<sup>[[1]](#references)</sup>

- **N`il`** (किसी authorization की आवश्यकता नहीं, **everyone is trusted**)
- एक **empty** list (**nobody** is trusted)
- Specific **applications** की **List**।

Entry में **`ACLAuthorizationPartitionID`,** key भी हो सकती है, जिसका उपयोग **teamid, apple,** और **cdhash** की पहचान करने के लिए किया जाता है।<sup>[[1]](#references)</sup>

- यदि **teamid** specified है, तो **entry** value को **prompt** के बिना **access** करने के लिए application का **same teamid** होना आवश्यक है।
- यदि **apple** specified है, तो app का **signed** by **Apple** होना आवश्यक है।
- यदि **cdhash** indicated है, तो **app** में specific **cdhash** होना आवश्यक है।

### Creating a Keychain Entry

जब **`Keychain Access.app`** का उपयोग करके एक **new** **entry** create की जाती है, तो निम्नलिखित rules लागू होते हैं:<sup>[[1]](#references)</sup>

- सभी apps encrypt कर सकते हैं।
- **No apps** export/decrypt नहीं कर सकते (user को prompt किए बिना)।
- सभी apps integrity check देख सकते हैं।
- कोई भी app ACLs change नहीं कर सकता।
- **partitionID** को **`apple`** पर set किया जाता है।

जब कोई **application keychain में entry create करती है**, तो rules थोड़े अलग होते हैं:<sup>[[1]](#references)</sup>

- सभी apps encrypt कर सकते हैं।
- केवल **creating application** (या कोई अन्य explicitly added apps) ही export/decrypt कर सकती हैं (user को prompt किए बिना)।
- सभी apps integrity check देख सकती हैं।
- कोई भी app ACLs change नहीं कर सकती।
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **prompt उत्पन्न न करने वाले** secrets की **keychain enumeration और dumping** tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) से की जा सकती है।
>
> अन्य API endpoints [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code में मिल सकते हैं।

**Security Framework** का उपयोग करके प्रत्येक keychain entry को list करें और उसके बारे में **info** प्राप्त करें। आप Apple के open source cli tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html) को भी देख सकते हैं। कुछ API examples:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** प्रत्येक entry की info देती है और इसका उपयोग करते समय कुछ attributes set किए जा सकते हैं:
- **`kSecReturnData`**: यदि true है, तो यह data को decrypt करने का प्रयास करेगा (संभावित pop-ups से बचने के लिए false set करें)
- **`kSecReturnRef`**: keychain item का reference भी प्राप्त करें (यदि बाद में पता चले कि pop-up के बिना decrypt कर सकते हैं, तो इसे true set करें)
- **`kSecReturnAttributes`**: entries के बारे में metadata प्राप्त करें
- **`kSecMatchLimit`**: कितने results return करने हैं
- **`kSecClass`**: keychain entry किस प्रकार की है

प्रत्येक entry के **ACLs** प्राप्त करें:<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`** से आप **keychain item का ACL** प्राप्त कर सकते हैं। यह ACLs की एक list return करती है (जैसे `ACLAuthorizationExportClear` और पहले बताए गए अन्य ACLs), जिसमें प्रत्येक entry के पास होता है:
- Description
- **Trusted Application List**। यह हो सकता है:
- एक app: /Applications/Slack.app
- एक binary: /usr/libexec/airportd
- एक group: group://AirPort

Data export करें:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** plaintext प्राप्त करती है
- API **`SecItemExport`** keys और certificates को export करती है, लेकिन content को encrypted रूप में export करने के लिए passwords set करने पड़ सकते हैं

और ये **बिना prompt के secret export करने में सक्षम होने** की **requirements** हैं:<sup>[[1]](#references)</sup>

- यदि **1+ trusted** apps listed हैं:
- उपयुक्त **authorizations** चाहिए (**`Nil`**, या secret info तक access की authorization में allowed apps की list का **part** होना चाहिए)
- code signature का **PartitionID** से match करना आवश्यक है
- code signature का किसी एक **trusted app** से match करना आवश्यक है (या सही KeychainAccessGroup का member होना चाहिए)
- यदि **all applications trusted** हैं:
- उपयुक्त **authorizations** चाहिए
- code signature का **PartitionID** से match करना आवश्यक है
- यदि **no PartitionID** है, तो इसकी आवश्यकता नहीं है

> [!CAUTION]
> इसलिए, यदि **1 application listed** है, तो आपको उस application में **code inject करना होगा**।
>
> यदि **partitionID** में **apple** indicated है, तो आप **`osascript`** से इसे access कर सकते हैं। इसलिए वे सभी applications को trust करने वाली चीजें जिनके partitionID में apple है, access की जा सकती हैं। इसके लिए **`Python`** का भी उपयोग किया जा सकता है।

### Two additional attributes

- **Invisible**: यह एक boolean flag है जो entry को **UI** Keychain app से **hide** करता है<sup>[[1]](#references)</sup>
- **General**: इसका उपयोग **metadata** store करने के लिए होता है (इसलिए यह **ENCRYPTED नहीं है**)<sup>[[1]](#references)</sup>
- Microsoft sensitive endpoint तक access करने के लिए सभी refresh tokens को plain text में store कर रहा था।<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
