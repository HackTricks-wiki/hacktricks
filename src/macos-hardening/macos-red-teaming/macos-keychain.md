# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychain Kuu

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), hutumika kuhifadhi **credentials maalum za mtumiaji** kama vile password za application, password za internet, certificates zilizotengenezwa na mtumiaji, password za network, pamoja na public/private keys zilizotengenezwa na mtumiaji.
- **System Keychain** (`/Library/Keychains/System.keychain`), huhifadhi **credentials za mfumo mzima** kama vile password za WiFi, certificates za system root, system private keys, na password za system application.<sup>[[1]](#references)</sup>
- Inawezekana kupata components nyingine kama certificates katika `/System/Library/Keychains/*`
- Katika **iOS** kuna **Keychain** moja tu iliyoko `/private/var/Keychains/`. Folder hii pia ina databases za `TrustStore`, certificate authorities (`caissuercache`) na OSCP entries (`ocspache`).
- Apps zitazuiwa katika keychain na kufikia eneo lao binafsi pekee, kulingana na application identifier yao.

### Password Keychain Access

Files hizi, ingawa hazina protection ya asili na zinaweza **kupakuliwa**, zime-encryptiwa na zinahitaji **plaintext password ya mtumiaji ili zidecryptiwe**. Tool kama [**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kwa decryption.<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Kila entry katika keychain inadhibitiwa na **Access Control Lists (ACLs)** ambazo huamua nani anaweza kutekeleza actions mbalimbali kwenye keychain entry, ikiwa ni pamoja na:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Humruhusu mwenye access kupata secret katika clear text.
- **ACLAuhtorizationExportWrapped**: Humruhusu mwenye access kupata clear text ikiwa ime-encryptiwa kwa password nyingine iliyotolewa.
- **ACLAuhtorizationAny**: Humruhusu mwenye access kutekeleza action yoyote.

ACLs pia huambatana na **list ya trusted applications** zinazoweza kutekeleza actions hizi bila kuonyesha prompt. Hii inaweza kuwa:<sup>[[1]](#references)</sup>

- **N`il`** (hakuna authorization inayohitajika, **kila mtu anaaminika**)
- List **tupu** (**hakuna mtu anayeaminika**)
- **List** ya **applications** maalum.

Pia entry inaweza kuwa na key **`ACLAuthorizationPartitionID`,** inayotumika kutambua **teamid, apple,** na **cdhash.**<sup>[[1]](#references)</sup>

- Ikiwa **teamid** imeainishwa, ili **kufikia value ya entry** **bila** **prompt**, application iliyotumika lazima iwe na **teamid** ileile.
- Ikiwa **apple** imeainishwa, app lazima iwe **signed** na **Apple**.
- Ikiwa **cdhash** imeonyeshwa, **app** lazima iwe na **cdhash** maalum.

### Creating a Keychain Entry

Wakati **entry** **mpya** inaundwa kwa kutumia **`Keychain Access.app`**, rules zifuatazo hutumika:<sup>[[1]](#references)</sup>

- Apps zote zinaweza ku-encrypt.
- **Hakuna apps** zinazoweza ku-export/decrypt (bila kumuuliza mtumiaji).
- Apps zote zinaweza kuona integrity check.
- Hakuna apps zinazoweza kubadilisha ACLs.
- **partitionID** huwekwa kuwa **`apple`**.

Wakati **application inaunda entry katika keychain**, rules huwa tofauti kidogo:<sup>[[1]](#references)</sup>

- Apps zote zinaweza ku-encrypt.
- Ni **application iliyounda entry** pekee (au apps nyingine zilizoongezwa waziwazi) inayoweza ku-export/decrypt (bila kumuuliza mtumiaji).
- Apps zote zinaweza kuona integrity check.
- Hakuna apps zinazoweza kubadilisha ACLs.
- **partitionID** huwekwa kuwa **`teamid:[teamID here]`**.

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
> **Uorodheshaji na dumping wa keychain** wa secrets ambao **hautazalisha prompt** unaweza kufanywa kwa kutumia tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> API endpoints nyingine zinaweza kupatikana katika source code ya [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Orodhesha na upate **taarifa** kuhusu kila keychain entry kwa kutumia **Security Framework**, au unaweza pia kuangalia cli tool ya Apple yenye open source inayoitwa [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Baadhi ya mifano ya API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** hutoa taarifa kuhusu kila entry, na kuna attributes unazoweza kuweka unapoitumia:
- **`kSecReturnData`**: Ikiwa ni true, itajaribu decrypt data (weka false ili kuepuka pop-ups zinazoweza kutokea)
- **`kSecReturnRef`**: Pata pia reference ya keychain item (weka true iwapo baadaye utaona kuwa unaweza ku-decrypt bila pop-up)
- **`kSecReturnAttributes`**: Pata metadata kuhusu entries
- **`kSecMatchLimit`**: Idadi ya results za kurejesha
- **`kSecClass`**: Aina ya keychain entry

Pata **ACLs** za kila entry:<sup>[[1]](#references)</sup>

- Kwa API **`SecAccessCopyACLList`** unaweza kupata **ACL ya keychain item**, na itarejesha orodha ya ACLs (kama `ACLAuhtorizationExportClear` na nyingine zilizotajwa awali), ambapo kila orodha ina:
- Description
- **Trusted Application List**. Hii inaweza kuwa:
- App: /Applications/Slack.app
- Binary: /usr/libexec/airportd
- Group: group://AirPort

Export data:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** hupata plaintext
- API **`SecItemExport`** hu-export keys na certificates, lakini huenda ukahitaji kuweka passwords ili ku-export content ikiwa ime-encryptiwa

Na hizi ndizo **requirements** za kuweza **ku-export secret bila prompt**:<sup>[[1]](#references)</sup>

- Ikiwa kuna **trusted** apps **1+** zilizoorodheshwa:
- Unahitaji **authorizations** zinazofaa (**`Nil`**, au uwe **sehemu** ya orodha ya apps zinazoruhusiwa katika authorization ya kufikia secret info)
- Code signature lazima ilingane na **PartitionID**
- Code signature lazima ilingane na ya **trusted app** moja (au uwe member wa KeychainAccessGroup inayofaa)
- Ikiwa **applications zote ni trusted**:
- Unahitaji **authorizations** zinazofaa
- Code signature lazima ilingane na **PartitionID**
- Ikiwa hakuna **PartitionID**, basi hii haihitajiki

> [!CAUTION]
> Kwa hiyo, ikiwa kuna **application 1 iliyoorodheshwa**, unahitaji **ku-inject code katika application hiyo**.
>
> Ikiwa **apple** imeonyeshwa katika **partitionID**, unaweza kuifikia kwa kutumia **`osascript`**, kwa hiyo chochote kinacho-trust applications zote huku kikiwa na apple katika partitionID. **`Python`** pia inaweza kutumika kwa hili.

### Attributes mbili za ziada

- **Invisible**: Ni boolean flag ya **kuficha** entry kutoka kwenye **UI** ya Keychain app<sup>[[1]](#references)</sup>
- **General**: Hutumika kuhifadhi **metadata** (kwa hiyo HAIJA-ENCRYPTIWA)<sup>[[1]](#references)</sup>
- Microsoft ilikuwa ikihifadhi refresh tokens zote kwa plain text ili kufikia sensitive endpoint.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
