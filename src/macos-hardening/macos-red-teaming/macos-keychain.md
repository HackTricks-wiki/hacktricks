# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychain Kuu

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), ambayo hutumika kuhifadhi **credentials maalum za mtumiaji** kama vile application passwords, internet passwords, vyeti vilivyoundwa na mtumiaji, network passwords, na funguo za umma/za faragha zilizoundwa na mtumiaji.
- **System Keychain** (`/Library/Keychains/System.keychain`), ambayo huhifadhi **credentials za mfumo mzima** kama vile WiFi passwords, system root certificates, system private keys, na system application passwords.<sup>[[1]](#references)</sup>
- Inawezekana kupata components nyingine kama certificates katika `/System/Library/Keychains/*`
- Katika **iOS** kuna **Keychain** moja tu iliyoko `/private/var/Keychains/`. Folder hii pia ina databases za `TrustStore`, certificate authorities (`caissuercache`) na OSCP entries (`ocspache`).
- Apps zitawekewa mipaka katika keychain kwenye eneo lao la faragha pekee kulingana na application identifier.

### Password Keychain Access

Files hizi, ingawa hazina protection ya asili na zinaweza **kupakuliwa**, zimesimbwa kwa encryption na zinahitaji **password ya mtumiaji ikiwa plaintext ili zifunguliwe**. Tool kama [**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kwa decryption.<sup>[[1]](#references)</sup>

## Protections za Keychain Entries

### ACLs

Kila entry katika keychain inadhibitiwa na **Access Control Lists (ACLs)** ambazo huamua ni nani anayeweza kutekeleza actions mbalimbali kwenye keychain entry, zikiwemo:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Humruhusu mwenye access kupata secret katika clear text.
- **ACLAuthorizationExportWrapped**: Humruhusu mwenye access kupata clear text iliyosimbwa kwa encryption kwa kutumia password nyingine iliyotolewa.
- **ACLAuthorizationAny**: Humruhusu mwenye access kutekeleza action yoyote.

ACLs pia huambatana na **list ya trusted applications** zinazoweza kutekeleza actions hizi bila kuonyesha prompt. Hii inaweza kuwa:<sup>[[1]](#references)</sup>

- **N`il`** (hakuna authorization inayohitajika, **kila mtu anaaminika**)
- **List** tupu (**hakuna mtu anayeaminika**)
- **List** ya **applications** maalum.

Pia entry inaweza kuwa na key **`ACLAuthorizationPartitionID`,** ambayo hutumika kutambua **teamid, apple,** na **cdhash.**<sup>[[1]](#references)</sup>

- Ikiwa **teamid** imeainishwa, application lazima iwe na **teamid ileile** ili **ipate access ya** value ya **entry** bila **prompt**.
- Ikiwa **apple** imeainishwa, app inahitaji kuwa **signed** na **Apple**.
- Ikiwa **cdhash** imeonyeshwa, basi **app** lazima iwe na **cdhash** maalum.

### Kuunda Keychain Entry

Wakati **entry** **mpya** inapoundwa kwa kutumia **`Keychain Access.app`**, rules zifuatazo hutumika:<sup>[[1]](#references)</sup>

- Apps zote zinaweza kufanya encryption.
- **Hakuna apps** zinazoweza kufanya export/decrypt (bila kuonyesha prompt kwa mtumiaji).
- Apps zote zinaweza kuona integrity check.
- Hakuna apps zinazoweza kubadilisha ACLs.
- **partitionID** huwekwa kuwa **`apple`**.

Wakati **application inaunda entry katika keychain**, rules huwa tofauti kidogo:<sup>[[1]](#references)</sup>

- Apps zote zinaweza kufanya encryption.
- Ni **application iliyounda entry** pekee (au apps nyingine zilizoongezwa waziwazi) inayoweza kufanya export/decrypt (bila kuonyesha prompt kwa mtumiaji).
- Apps zote zinaweza kuona integrity check.
- Hakuna apps zinazoweza kubadilisha ACLs.
- **partitionID** huwekwa kuwa **`teamid:[teamID here]`**.

## Kufikia Keychain

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
> **keychain enumeration and dumping** ya secrets ambazo **hazitazalisha prompt** inaweza kufanywa kwa kutumia tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> API endpoints nyingine zinaweza kupatikana kwenye source code ya [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Orodhesha na upate **info** kuhusu kila keychain entry ukitumia **Security Framework**, au unaweza pia kuangalia cli tool ya Apple yenye open source, [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Baadhi ya mifano ya API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** hutoa info kuhusu kila entry, na kuna attributes kadhaa unazoweza kuweka unapoitumia:
- **`kSecReturnData`**: Ikiwa ni true, itajaribu ku-decrypt data (weka false ili kuepuka pop-ups zinazoweza kutokea)
- **`kSecReturnRef`**: Pata pia reference ya keychain item (weka true endapo baadaye utaona kuwa unaweza ku-decrypt bila pop-up)
- **`kSecReturnAttributes`**: Pata metadata kuhusu entries
- **`kSecMatchLimit`**: Idadi ya results za kurudisha
- **`kSecClass`**: Aina ya keychain entry

Pata **ACLs** za kila entry:<sup>[[1]](#references)</sup>

- Kwa API **`SecAccessCopyACLList`** unaweza kupata **ACL ya keychain item**. Inarudisha list ya ACLs (kama vile `ACLAuthorizationExportClear` na nyingine zilizotajwa awali), ambapo kila entry ina:
- Maelezo
- **Trusted Application List**. Hii inaweza kuwa:
- App: /Applications/Slack.app
- Binary: /usr/libexec/airportd
- Group: group://AirPort

Export data:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** hupata plaintext
- API **`SecItemExport`** hu-export keys na certificates, lakini huenda ukahitaji kuweka passwords ili ku-export content ikiwa encrypted

Na haya ndiyo **mahitaji** ya kuweza **ku-export secret bila prompt**:<sup>[[1]](#references)</sup>

- Ikiwa kuna apps **1+ trusted** zilizoorodheshwa:
- Unahitaji **authorizations** zinazofaa (**`Nil`**, au kuwa **sehemu** ya list ya apps zinazoruhusiwa katika authorization ya kufikia secret info)
- Code signature lazima ilingane na **PartitionID**
- Code signature lazima ilingane na ya **trusted app** moja (au uwe member wa KeychainAccessGroup inayofaa)
- Ikiwa **all applications trusted**:
- Unahitaji **authorizations** zinazofaa
- Code signature lazima ilingane na **PartitionID**
- Ikiwa hakuna **PartitionID**, basi hili halihitajiki

> [!CAUTION]
> Kwa hiyo, ikiwa kuna **application 1 iliyoorodheshwa**, unahitaji **ku-inject code kwenye application hiyo**.
>
> Ikiwa **apple** imeonyeshwa kwenye **partitionID**, unaweza kuifikia kwa kutumia **`osascript`**, kwa hiyo chochote kinacho-trust applications zote huku apple ikiwa kwenye partitionID. **`Python`** pia inaweza kutumika kwa hili.

### Attributes mbili za ziada

- **Invisible**: Ni boolean flag ya **kuficha** entry kutoka kwenye **UI** ya Keychain app<sup>[[1]](#references)</sup>
- **General**: Hutumika kuhifadhi **metadata** (kwa hiyo HAIJA-ENCRYPTIWA)<sup>[[1]](#references)</sup>
- Microsoft ilikuwa ikihifadhi refresh tokens zote kwenye plain text ili kufikia endpoint nyeti.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Kuchagua Lock ya macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
