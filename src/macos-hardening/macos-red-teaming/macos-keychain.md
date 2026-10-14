# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## मुख्य Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), जिसका उपयोग **user-specific credentials** जैसे application passwords, internet passwords, user-generated certificates, network passwords और user-generated public/private keys को स्टोर करने के लिए किया जाता है।
- **System Keychain** (`/Library/Keychains/System.keychain`), जिसमें **system-wide credentials** जैसे WiFi passwords, system root certificates, system private keys और system application passwords स्टोर होते हैं।<sup>[[1]](#references)</sup>
  - `/System/Library/Keychains/*` में certificates जैसे अन्य components भी मिल सकते हैं।
- **iOS** में `/private/var/Keychains/` में स्थित केवल एक **Keychain** होता है। इस folder में `TrustStore`, certificate authorities (`caissuercache`) और OSCP entries (`ocspache`) के databases भी होते हैं।
  - Apps को keychain में केवल उनके application identifier के आधार पर उनके private area तक सीमित रखा जाता है।

### Password Keychain तक पहुंच

इन files में अपने-आप कोई protection नहीं होती और इन्हें **download** किया जा सकता है, लेकिन ये encrypted होती हैं और इन्हें decrypt करने के लिए **user का plaintext password** चाहिए। Decryption के लिए [**Chainbreaker**](https://github.com/n0fate/chainbreaker) जैसे tool का उपयोग किया जा सकता है।<sup>[[1]](#references)</sup>

## Keychain Entries की सुरक्षा

### ACLs

Keychain में प्रत्येक entry को **Access Control Lists (ACLs)** नियंत्रित करती हैं। ये तय करती हैं कि कौन keychain entry पर कौन-सी actions कर सकता है, जिनमें शामिल हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Holder को secret का clear text प्राप्त करने की अनुमति देता है।
- **`kSecACLAuthorizationExportWrapped`**: Holder को secret का clear text, दिए गए किसी अन्य password से encrypted करके प्राप्त करने की अनुमति देता है।
- **`kSecACLAuthorizationAny`**: Holder को कोई भी action करने की अनुमति देता है।

ACLs के साथ **trusted applications की list** भी होती है, जो बिना prompt दिए ये actions कर सकती हैं। यह list हो सकती है:<sup>[[1]](#references)</sup>

- **N`il`** (किसी authorization की आवश्यकता नहीं, **हर कोई trusted है**)
- एक **खाली** list (**कोई भी** trusted नहीं है)
- विशिष्ट **applications** की **list**।

Entry में **`kSecACLAuthorizationPartitionID`** key भी हो सकती है, जिसका उपयोग **teamid, apple** और **cdhash** की पहचान के लिए किया जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

- यदि **teamid** निर्दिष्ट है, तो **entry** value को **बिना** **prompt** के **access** करने के लिए application का **teamid समान** होना चाहिए।
- यदि **apple** निर्दिष्ट है, तो app को **Apple द्वारा signed** होना चाहिए।
- यदि **cdhash** दिया गया है, तो **app** में वही विशिष्ट **cdhash** होना चाहिए।

### Keychain Entry बनाना

**`Keychain Access.app`** का उपयोग करके **नई** **entry** बनाए जाने पर, ये नियम लागू होते हैं:<sup>[[1]](#references)</sup>

- सभी apps encrypt कर सकते हैं।
- **कोई भी app** (user को prompt दिए बिना) export/decrypt नहीं कर सकता।
- सभी apps integrity check देख सकते हैं।
- कोई भी app ACLs नहीं बदल सकता।
- **partitionID** को **`apple`** पर सेट किया जाता है।

जब कोई **application keychain में entry बनाती है**, तो नियम थोड़े अलग होते हैं:<sup>[[1]](#references)</sup>

- सभी apps encrypt कर सकते हैं।
- केवल **entry बनाने वाला application** (या स्पष्ट रूप से जोड़े गए अन्य apps) (user को prompt दिए बिना) export/decrypt कर सकते हैं।
- सभी apps integrity check देख सकते हैं।
- कोई भी app ACLs नहीं बदल सकता।
- **partitionID** को **`teamid:[teamID here]`** पर सेट किया जाता है।

## Keychain तक पहुंच

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

`-S` आइटम की partition list सेट करता है, जबकि `-k` यह बदलाव करने के लिए ज़रूरी मौजूदा Keychain password देता है; password लेने वाला flag deprecated है।<sup>[[4]](#references)</sup> सफल update से यह साबित नहीं होता कि बाद में read करते समय कोई prompt नहीं आएगा: एक देखे गए, disabled prototype ने `Security.framework` के ज़रिए आइटम query करने पर भी confirmation prompt दिखाया। मेल खाता partition ID, ऊपर बताए गए ACL और trusted-application checks का सिर्फ़ एक हिस्सा है, इसलिए वास्तविक read path की पुष्टि करें।<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> secrets की **keychain enumeration और dumping**, जिससे **prompt नहीं आएगा**, टूल [**LockSmith**](https://github.com/its-a-feature/LockSmith) से की जा सकती है।
>
> अन्य API endpoints, [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code में मिल सकते हैं।

हर keychain entry की **info** सूचीबद्ध करने और पाने के लिए **Security Framework** का उपयोग करें; या Apple के open source cli tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** को भी देख सकते हैं। API के कुछ उदाहरण:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** हर entry की info देता है और इसका उपयोग करते समय आप कुछ attributes सेट कर सकते हैं:
  - **`kSecReturnData`**: यदि true हो, तो यह data decrypt करने की कोशिश करेगा (संभावित pop-ups से बचने के लिए इसे false सेट करें)
  - **`kSecReturnRef`**: keychain item का reference भी पाएँ (यदि बाद में पता चले कि pop-up के बिना decrypt किया जा सकता है, तो इसे true सेट करें)
  - **`kSecReturnAttributes`**: entries का metadata पाएँ
  - **`kSecMatchLimit`**: लौटाए जाने वाले results की संख्या
  - **`kSecClass`**: keychain entry का प्रकार

हर entry के **ACLs** पाएँ:<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`** से आप **keychain item का ACL** पा सकते हैं। यह ACLs की एक सूची लौटाता है (जैसे `kSecACLAuthorizationExportClear` और पहले बताए गए अन्य ACLs), जिसमें हर entry में शामिल हैं:<sup>[[1]](#references)[[2]](#references)</sup>
  - Description
  - **Trusted Application List**। इसमें ये शामिल हो सकते हैं:
    - कोई app: /Applications/Slack.app
    - कोई binary: /usr/libexec/airportd
    - कोई group: group://AirPort

Data export करें:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** plaintext प्राप्त करता है
- API **`SecItemExport`** keys और certificates export करता है, लेकिन content को encrypted रूप में export करने के लिए password सेट करना पड़ सकता है

और ये वे **requirements** हैं जिनसे **prompt के बिना secret export** किया जा सकता है:<sup>[[1]](#references)</sup>

- यदि **1+ trusted** apps सूचीबद्ध हों:
  - उपयुक्त **authorizations** चाहिए (**`Nil`**, या secret info तक पहुँचने की authorization में allowed apps की सूची का **हिस्सा** होना)
  - code signature का **PartitionID** से मेल खाना चाहिए
  - code signature का किसी **trusted app** से मेल खाना चाहिए (या सही KeychainAccessGroup का सदस्य होना चाहिए)
- यदि **सभी applications trusted** हों:
  - उपयुक्त **authorizations** चाहिए
  - code signature का **PartitionID** से मेल खाना चाहिए
    - यदि **PartitionID नहीं है**, तो इसकी ज़रूरत नहीं

> [!CAUTION]
> इसलिए, यदि **1 application सूचीबद्ध है**, तो आपको **उस application में code inject करना होगा**।
>
> यदि **partitionID** में **apple** दर्शाया गया है, तो आप इसे **`osascript`** से access कर सकते हैं; यानी वे सभी applications जो partitionID में apple होने पर भरोसा करती हैं। इसके लिए **`Python`** का भी उपयोग किया जा सकता है।

### दो अतिरिक्त attributes

- **Invisible**: यह entry को **UI** Keychain app से **छिपाने** के लिए boolean flag है<sup>[[1]](#references)</sup>
- **General**: इसका उपयोग **metadata** स्टोर करने के लिए होता है (इसलिए यह ENCRYPTED नहीं है)<sup>[[1]](#references)</sup>
  - Microsoft संवेदनशील endpoint तक पहुँचने के लिए सभी refresh tokens को plaintext में स्टोर कर रहा था।<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: "macOS Keychain को Lock Picking करना" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - MacSync macOS stealer का नया संस्करण crypto enthusiasts और developers को निशाना बनाता है](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) man page mirror](https://keith.github.io/xcode-man-pages/security.1.html)
