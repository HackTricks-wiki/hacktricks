# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), ambayo inatumika kuhifadhi **akidi za mtumiaji** kama nywila za programu, nywila za mtandao, vyeti vilivyoundwa na mtumiaji, nywila za mtandao, na funguo za umma/za kibinafsi zilizoundwa na mtumiaji.
- **System Keychain** (`/Library/Keychains/System.keychain`), ambayo inahifadhi **akidi za mfumo mzima** kama nywila za WiFi, vyeti vya mfumo, funguo za kibinafsi za mfumo, na nywila za programu za mfumo.
- Inawezekana kupata vipengele vingine kama vyeti katika `/System/Library/Keychains/*`
- Katika **iOS** kuna **Keychain** moja iliyoko katika `/private/var/Keychains/`. Folda hii pia ina hifadhidata za `TrustStore`, mamlaka za vyeti (`caissuercache`) na entries za OSCP (`ocspache`).
- Programu zitakuwa na vizuizi katika keychain tu katika eneo lao la kibinafsi kulingana na kitambulisho chao cha programu.

### Password Keychain Access

Faili hizi, ingawa hazina ulinzi wa ndani na zinaweza **kupakuliwa**, zimefungwa na zinahitaji **nywila ya mtumiaji ya maandiko ili kufunguliwa**. Chombo kama [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kinaweza kutumika kwa ajili ya kufungua.

## Keychain Entries Protections

### ACLs

Kila kipengele katika keychain kinatawaliwa na **Access Control Lists (ACLs)** ambazo zinaelekeza nani anaweza kufanya vitendo mbalimbali kwenye kipengele cha keychain, ikiwa ni pamoja na:

- **ACLAuhtorizationExportClear**: Inaruhusu mwenyewe kupata maandiko ya siri.
- **ACLAuhtorizationExportWrapped**: Inaruhusu mwenyewe kupata maandiko ya siri yaliyofichwa kwa nywila nyingine iliyotolewa.
- **ACLAuhtorizationAny**: Inaruhusu mwenyewe kufanya kitendo chochote.

ACLs zinakuja na **orodha ya programu zinazotegemewa** ambazo zinaweza kufanya vitendo hivi bila kuombwa. Hii inaweza kuwa:

- **N`il`** (hakuna idhini inayohitajika, **kila mtu anategemewa**)
- Orodha **bila** (hakuna mtu anategemewa)
- **Orodha** ya **programu** maalum.

Pia kipengele kinaweza kuwa na funguo **`ACLAuthorizationPartitionID`,** ambayo inatumika kutambua **teamid, apple,** na **cdhash.**

- Ikiwa **teamid** imeainishwa, basi ili **kufikia thamani ya kipengele** **bila** **kuombwa** programu iliyotumika lazima iwe na **teamid sawa**.
- Ikiwa **apple** imeainishwa, basi programu inahitaji kuwa **imeandikwa** na **Apple**.
- Ikiwa **cdhash** imeonyeshwa, basi **programu** lazima iwe na **cdhash** maalum.

### Creating a Keychain Entry

Wakati **kipengele kipya** kinaundwa kwa kutumia **`Keychain Access.app`**, sheria zifuatazo zinatumika:

- Programu zote zinaweza kuficha.
- **Hakuna programu** zinaweza kusafirisha/kufungua (bila kuombwa mtumiaji).
- Programu zote zinaweza kuona ukaguzi wa uaminifu.
- Hakuna programu zinaweza kubadilisha ACLs.
- **partitionID** imewekwa kuwa **`apple`**.

Wakati **programu inaunda kipengele katika keychain**, sheria ni tofauti kidogo:

- Programu zote zinaweza kuficha.
- Ni **programu inayounda** tu (au programu nyingine yoyote iliyoongezwa wazi) zinaweza kusafirisha/kufungua (bila kuombwa mtumiaji).
- Programu zote zinaweza kuona ukaguzi wa uaminifu.
- Hakuna programu zinaweza kubadilisha ACLs.
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
> **Uhesabuji wa keychain na kutolewa** kwa siri ambazo **hazitazalisha kiashiria** zinaweza kufanywa kwa kutumia chombo [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Nyingine API endpoints zinaweza kupatikana katika [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) msimbo wa chanzo.

Orodhesha na pata **info** kuhusu kila kiingilio cha keychain kwa kutumia **Security Framework** au unaweza pia kuangalia chombo cha cli cha chanzo wazi cha Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Baadhi ya mifano ya API:

- API **`SecItemCopyMatching`** inatoa info kuhusu kila kiingilio na kuna baadhi ya sifa unaweza kuweka unapoitumia:
- **`kSecReturnData`**: Ikiwa ni kweli, itajaribu kufungua data (weka kuwa uongo ili kuepuka pop-ups zinazoweza kutokea)
- **`kSecReturnRef`**: Pata pia rejea kwa kipengee cha keychain (weka kuwa kweli ikiwa baadaye utaona unaweza kufungua bila pop-up)
- **`kSecReturnAttributes`**: Pata metadata kuhusu viingilio
- **`kSecMatchLimit`**: Ni matokeo mangapi ya kurudisha
- **`kSecClass`**: Ni aina gani ya kiingilio cha keychain

Pata **ACLs** za kila kiingilio:

- Kwa API **`SecAccessCopyACLList`** unaweza kupata **ACL kwa kipengee cha keychain**, na itarudisha orodha ya ACLs (kama `ACLAuhtorizationExportClear` na zingine zilizotajwa hapo awali) ambapo kila orodha ina:
- Maelezo
- **Orodha ya Maombi ya Kuaminika**. Hii inaweza kuwa:
- Programu: /Applications/Slack.app
- Binary: /usr/libexec/airportd
- Kundi: group://AirPort

Export data:

- API **`SecKeychainItemCopyContent`** inapata maandiko
- API **`SecItemExport`** inasafirisha funguo na vyeti lakini inaweza kuhitaji kuweka nywila ili kusafirisha yaliyomo kwa usimbaji

Na hizi ndizo **mahitaji** ya kuwa na uwezo wa **kusafirisha siri bila kiashiria**:

- Ikiwa **1+ maombi ya kuaminika** yameorodheshwa:
- Inahitaji **idhini** sahihi (**`Nil`**, au kuwa **sehemu** ya orodha inayoruhusiwa ya maombi katika idhini ya kufikia info ya siri)
- Inahitaji saini ya msimbo kuendana na **PartitionID**
- Inahitaji saini ya msimbo kuendana na ile ya **programu moja ya kuaminika** (au kuwa mwanachama wa kundi sahihi la KeychainAccessGroup)
- Ikiwa **maombi yote ni ya kuaminika**:
- Inahitaji **idhini** sahihi
- Inahitaji saini ya msimbo kuendana na **PartitionID**
- Ikiwa **hakuna PartitionID**, basi hii haitahitajika

> [!CAUTION]
> Hivyo, ikiwa kuna **1 programu iliyoorodheshwa**, unahitaji **kuingiza msimbo katika programu hiyo**.
>
> Ikiwa **apple** inaonyeshwa katika **partitionID**, unaweza kuipata kwa kutumia **`osascript`** hivyo chochote kinachounga mkono maombi yote na apple katika partitionID. **`Python`** inaweza pia kutumika kwa hili.

### Sifa mbili za ziada

- **Invisible**: Ni bendera ya boolean ili **kuficha** kiingilio kutoka kwa programu ya **UI** Keychain
- **General**: Ni kuhifadhi **metadata** (hivyo SI IMESIMBWA)
- Microsoft ilikuwa ikihifadhi katika maandiko yote ya wazi tokens za refresher kufikia kiwambo nyeti.

## References

- [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
