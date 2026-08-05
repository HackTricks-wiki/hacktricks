# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), ambayo hutumika kuhifadhi **credentials maalum za mtumiaji** kama vile application passwords, internet passwords, user-generated certificates, network passwords, pamoja na user-generated public/private keys.
- **System Keychain** (`/Library/Keychains/System.keychain`), ambayo huhifadhi **credentials za mfumo mzima** kama vile WiFi passwords, system root certificates, system private keys, na system application passwords.<sup>[1]</sup>
- Inawezekana kupata components nyingine kama certificates katika `/System/Library/Keychains/*`
- Katika **iOS** kuna **Keychain** moja tu, iliyoko `/private/var/Keychains/`. Folda hii pia ina databases za `TrustStore`, certificate authorities (`caissuercache`) na OSCP entries (`ocspache`).
- Apps zitawekewa vikwazo katika keychain na zitaruhusiwa tu kufikia eneo lake binafsi kulingana na application identifier.

### Password Keychain Access

Faili hizi, ingawa hazina ulinzi wa asili na zinaweza **downloaded**, zimesimbwa kwa encryption na zinahitaji **user's plaintext password ili decrypt**. Tool kama [**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kwa decryption.<sup>[1]</sup>

## Keychain Entries Protections

### ACLs

Kila entry katika keychain inadhibitiwa na **Access Control Lists (ACLs)**, ambazo huamua nani anaweza kutekeleza vitendo mbalimbali kwenye keychain entry, ikiwa ni pamoja na:<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: Humruhusu mwenye ruhusa kupata secret katika clear text.
- **ACLAuhtorizationExportWrapped**: Humruhusu mwenye ruhusa kupata clear text iliyosimbwa kwa encryption kwa kutumia password nyingine iliyotolewa.
- **ACLAuhtorizationAny**: Humruhusu mwenye ruhusa kutekeleza kitendo chochote.

ACLs pia huambatana na **list ya trusted applications** zinazoweza kutekeleza vitendo hivi bila kuonyesha prompt. Hii inaweza kuwa:<sup>[1]</sup>

- **N`il`** (hakuna authorization inayohitajika, **kila mtu anaaminiwa**)
- List **tupu** (**hakuna mtu anayeaminiwa**)
- **List** ya **applications** maalum.

Pia entry inaweza kuwa na key **`ACLAuthorizationPartitionID`,** ambayo hutumika kutambua **teamid, apple,** na **cdhash.**<sup>[1]</sup>

- Ikiwa **teamid** imeainishwa, ili **kufikia** value ya **entry** **bila** **prompt**, application iliyotumika lazima iwe na **teamid** ileile.
- Ikiwa **apple** imeainishwa, app lazima iwe **signed** na **Apple**.
- Ikiwa **cdhash** imeonyeshwa, **app** lazima iwe na **cdhash** maalum.

### Creating a Keychain Entry

Wakati **entry** **mpya** inaundwa kwa kutumia **`Keychain Access.app`**, rules zifuatazo hutumika:<sup>[1]</sup>

- Apps zote zinaweza kufanya encryption.
- **Hakuna apps** zinazoweza kufanya export/decrypt (bila kumwonyesha mtumiaji prompt).
- Apps zote zinaweza kuona integrity check.
- Hakuna apps zinazoweza kubadilisha ACLs.
- **partitionID** imewekwa kuwa **`apple`**.

Wakati **application inaunda entry katika keychain**, rules hutofautiana kidogo:<sup>[1]</sup>

- Apps zote zinaweza kufanya encryption.
- Ni **application iliyounda entry** pekee (au apps nyingine zilizoongezwa waziwazi) inayoweza kufanya export/decrypt (bila kumwonyesha mtumiaji prompt).
- Apps zote zinaweza kuona integrity check.
- Hakuna apps zinazoweza kubadilisha ACLs.
- **partitionID** imewekwa kuwa **`teamid:[teamID here]`**.

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
> **keychain enumeration and dumping** ya secrets ambazo **hazitatengeneza prompt** inaweza kufanywa kwa kutumia tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> API endpoints nyingine zinaweza kupatikana katika source code ya [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Orodhesha na upate **info** kuhusu kila keychain entry kwa kutumia **Security Framework**, au unaweza pia kuangalia cli tool ya Apple yenye source code wazi, [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Baadhi ya mifano ya API:<sup>[1]</sup>

- API **`SecItemCopyMatching`** hutoa info kuhusu kila entry na kuna baadhi ya attributes unazoweza kuweka unapoitumia:
- **`kSecReturnData`**: Ikiwa ni true, itajaribu ku-decrypt data (weka false ili kuepuka pop-ups zinazoweza kutokea)
- **`kSecReturnRef`**: Pia pata reference ya keychain item (weka true ikiwa baadaye utaona kuwa unaweza ku-decrypt bila pop-up)
- **`kSecReturnAttributes`**: Pata metadata kuhusu entries
- **`kSecMatchLimit`**: Idadi ya results za kurudisha
- **`kSecClass`**: Aina ya keychain entry

Pata **ACLs** za kila entry:<sup>[1]</sup>

- Kwa API **`SecAccessCopyACLList`** unaweza kupata **ACL ya keychain item**, na itarudisha list ya ACLs (kama `ACLAuhtorizationExportClear` na nyingine zilizotajwa awali), ambapo kila list ina:
- Description
- **Trusted Application List**. Hii inaweza kuwa:
- App: /Applications/Slack.app
- Binary: /usr/libexec/airportd
- Group: group://AirPort

Export data:<sup>[1]</sup>

- API **`SecKeychainItemCopyContent`** hupata plaintext
- API **`SecItemExport`** hu-export keys na certificates, lakini huenda ukahitaji kuweka passwords ili ku-export content ikiwa encrypted

Na hizi ndizo **requirements** za kuweza **ku-export secret bila prompt**:<sup>[1]</sup>

- Ikiwa kuna trusted apps **1+** zilizoorodheshwa:
- Inahitajika **authorizations** zinazofaa (**`Nil`**, au uwe **sehemu** ya list ya apps zinazoruhusiwa katika authorization ya kufikia secret info)
- Code signature inahitajika ku-match **PartitionID**
- Code signature inahitajika ku-match ya **trusted app** moja (au uwe member wa KeychainAccessGroup inayofaa)
- Ikiwa **applications zote ni trusted**:
- Inahitajika **authorizations** zinazofaa
- Code signature inahitajika ku-match **PartitionID**
- Ikiwa hakuna **PartitionID**, basi hili halihitajiki

> [!CAUTION]
> Kwa hiyo, ikiwa kuna **application 1 iliyoorodheshwa**, unahitaji **ku-inject code kwenye application hiyo**.
>
> Ikiwa **apple** imeonyeshwa katika **partitionID**, unaweza kuifikia kwa kutumia **`osascript`**, kwa hiyo chochote kinacho-trust applications zote huku kikiwa na apple katika partitionID. **`Python`** pia inaweza kutumika kwa hili.

### Sifa mbili za ziada

- **Invisible**: Ni boolean flag ya **kuficha** entry kutoka kwenye **UI** ya Keychain app<sup>[1]</sup>
- **General**: Hutumika kuhifadhi **metadata** (kwa hiyo HAIJAENCRYPTIWA)<sup>[1]</sup>
- Microsoft ilikuwa inahifadhi refresh tokens zote kwa plain text ili kufikia sensitive endpoint.<sup>[1]</sup>

## Marejeleo

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
