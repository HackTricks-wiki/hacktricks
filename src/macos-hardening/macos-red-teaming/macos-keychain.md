# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychain Kuu

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), ambayo hutumika kuhifadhi **credentials za mtumiaji** kama vile passwords za application, passwords za internet, certificates zilizoundwa na mtumiaji, passwords za network, na public/private keys zilizoundwa na mtumiaji.
- **System Keychain** (`/Library/Keychains/System.keychain`), ambayo huhifadhi **credentials za mfumo mzima** kama vile passwords za WiFi, system root certificates, system private keys, na system application passwords.<sup>[[1]](#references)</sup>
- Inawezekana kupata components nyingine kama certificates katika `/System/Library/Keychains/*`
- Katika **iOS** kuna **Keychain** moja tu inayopatikana katika `/private/var/Keychains/`. Folder hii pia ina databases za `TrustStore`, certificate authorities (`caissuercache`) na OSCP entries (`ocspache`).
- Apps zitaruhusiwa katika keychain kufikia eneo lao binafsi pekee, kulingana na application identifier yao.

### Ufikiaji wa Password Keychain

Files hizi, ingawa hazina protection ya asili na zinaweza **downloadiwa**, zimesimbwa kwa encryption na zinahitaji **password ya mtumiaji katika plaintext ili zidecryptiwe**. Tool kama [**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kwa decryption.<sup>[[1]](#references)</sup>

## Protections za Keychain Entries

### ACLs

Kila entry katika keychain inadhibitiwa na **Access Control Lists (ACLs)** ambazo huamua ni nani anayeweza kutekeleza actions mbalimbali kwenye keychain entry, zikiwemo:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Humruhusu mwenye haki kupata maandishi wazi ya secret.
- **ACLAuhtorizationExportWrapped**: Humruhusu mwenye haki kupata maandishi wazi yaliyosimbwa kwa encryption kwa kutumia password nyingine iliyotolewa.
- **ACLAuhtorizationAny**: Humruhusu mwenye haki kutekeleza action yoyote.

ACLs pia huambatana na **list ya trusted applications** zinazoweza kutekeleza actions hizi bila kuonyesha prompt. Hii inaweza kuwa:<sup>[[1]](#references)</sup>

- **N`il`** (hakuna authorization inayohitajika, **kila mtu anaaminika**)
- **List tupu** (**hakuna mtu** anayeaminika)
- **List** ya **applications** maalum.

Pia entry inaweza kuwa na key **`ACLAuthorizationPartitionID`,** ambayo hutumika kutambua **teamid, apple,** na **cdhash.**<sup>[[1]](#references)</sup>

- Ikiwa **teamid** imeainishwa, ili **kufikia** value ya **entry** **bila** **prompt**, application iliyotumika lazima iwe na **teamid** hiyo hiyo.
- Ikiwa **apple** imeainishwa, app lazima iwe **signed** na **Apple**.
- Ikiwa **cdhash** imeonyeshwa, **app** lazima iwe na **cdhash** hiyo maalum.

### Kuunda Keychain Entry

Wakati **entry** **mpya** inaundwa kwa kutumia **`Keychain Access.app`**, rules zifuatazo hutumika:<sup>[[1]](#references)</sup>

- Apps zote zinaweza kufanya encryption.
- **Hakuna apps** zinazoweza kufanya export/decrypt (bila kumuonyesha mtumiaji prompt).
- Apps zote zinaweza kuona integrity check.
- Hakuna apps zinazoweza kubadilisha ACLs.
- **partitionID** huwekwa kuwa **`apple`**.

Wakati **application inaunda entry katika keychain**, rules huwa tofauti kidogo:<sup>[[1]](#references)</sup>

- Apps zote zinaweza kufanya encryption.
- Ni **application iliyounda entry** pekee (au apps nyingine zilizoongezwa waziwazi) inayoweza kufanya export/decrypt (bila kumuonyesha mtumiaji prompt).
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

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **Enumeration na dumping ya secrets za keychain** ambazo **hazitazalisha prompt** zinaweza kufanywa kwa kutumia tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> API endpoints nyingine zinaweza kupatikana katika source code ya [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) ya Apple yenye open source.

Orodhesha na upate **info** kuhusu kila keychain entry ukitumia **Security Framework**, au unaweza pia kuangalia cli tool ya Apple yenye open source, [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Baadhi ya API examples:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** hutoa info kuhusu kila entry, na kuna attributes ambazo unaweza kuweka unapoitumia:
- **`kSecReturnData`**: Ikiwa ni true, itajaribu ku-decrypt data (weka false ili kuepuka pop-ups zinazoweza kutokea)
- **`kSecReturnRef`**: Pata pia reference ya keychain item (weka true endapo baadaye utaona unaweza ku-decrypt bila pop-up)
- **`kSecReturnAttributes`**: Pata metadata kuhusu entries
- **`kSecMatchLimit`**: Idadi ya results zitakazorudishwa
- **`kSecClass`**: Aina ya keychain entry

Pata **ACLs** za kila entry:<sup>[[1]](#references)</sup>

- Kwa API **`SecAccessCopyACLList`** unaweza kupata **ACL ya keychain item**, na itarudisha list ya ACLs (kama `ACLAuhtorizationExportClear` na nyingine zilizotajwa awali), ambapo kila list ina:
- Description
- **Trusted Application List**. Hii inaweza kuwa:
- App: /Applications/Slack.app
- Binary: /usr/libexec/airportd
- Group: group://AirPort

Export data:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** hupata plaintext
- API **`SecItemExport`** hu-export keys na certificates, lakini huenda ukahitaji kuweka passwords ili ku-export content ikiwa encrypted

Na hizi ndizo **requirements** za kuweza **ku-export secret bila prompt**:<sup>[[1]](#references)</sup>

- Ikiwa kuna apps **1+ trusted** zilizoorodheshwa:
- Inahitajika kuwa na **authorizations** zinazofaa (**`Nil`**, au kuwa **sehemu** ya allowed list ya apps katika authorization ya kufikia secret info)
- Code signature inapaswa kufanana na **PartitionID**
- Code signature inapaswa kufanana na ya **trusted app** mmoja (au uwe member wa KeychainAccessGroup sahihi)
- Ikiwa **all applications trusted**:
- Inahitajika kuwa na **authorizations** zinazofaa
- Code signature inapaswa kufanana na **PartitionID**
- Ikiwa hakuna **PartitionID**, basi hii haihitajiki

> [!CAUTION]
> Kwa hiyo, ikiwa kuna **application 1 iliyoorodheshwa**, unahitaji **ku-inject code katika application hiyo**.
>
> Ikiwa **apple** imeonyeshwa katika **partitionID**, unaweza kuifikia kwa **`osascript`**, hivyo chochote kinacho-trust all applications zenye apple katika partitionID. **`Python`** pia inaweza kutumika kwa hili.

### Two additional attributes

- **Invisible**: Ni boolean flag ya **kuficha** entry kutoka kwenye **UI** Keychain app<sup>[[1]](#references)</sup>
- **General**: Hutumika kuhifadhi **metadata** (kwa hiyo HAIJAENCRYPTIWA)<sup>[[1]](#references)</sup>
- Microsoft ilikuwa ikihifadhi refresh tokens zote kwa plain text ili kufikia sensitive endpoint.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
