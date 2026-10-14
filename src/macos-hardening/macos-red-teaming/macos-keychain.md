# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychain Kuu

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), ambayo hutumika kuhifadhi **sifa za mtumiaji** kama vile nywila za programu, nywila za intaneti, vyeti vilivyoundwa na mtumiaji, nywila za mtandao, na funguo za umma/faragha zilizoundwa na mtumiaji.
- **System Keychain** (`/Library/Keychains/System.keychain`), ambayo huhifadhi **sifa za mfumo mzima** kama vile nywila za WiFi, vyeti vya mizizi ya mfumo, funguo za faragha za mfumo, na nywila za programu za mfumo.<sup>[[1]](#references)</sup>
  - Inawezekana kupata vipengele vingine kama vile vyeti katika `/System/Library/Keychains/*`
- Katika **iOS** kuna **Keychain** moja tu, iliyoko `/private/var/Keychains/`. Folda hii pia ina hifadhidata za `TrustStore`, mamlaka za vyeti (`caissuercache`) na maingizo ya OSCP (`ocspache`).
  - Programu zitazuiwa kwenye Keychain na kuruhusiwa tu kufikia eneo lao la faragha kulingana na kitambulisho cha programu.

### Ufikiaji wa Keychain kwa Nenosiri

Faili hizi hazina ulinzi wa ndani na zinaweza **kupakuliwa**, lakini zimesimbwa kwa njia fiche na zinahitaji **nenosiri lisilosimbwa la mtumiaji ili kufunguliwa**. Zana kama [**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kuzifungua.<sup>[[1]](#references)</sup>

## Ulinzi wa Maingizo ya Keychain

### ACLs

Kila ingizo katika Keychain hudhibitiwa na **Orodha za Udhibiti wa Ufikiaji (ACLs)** zinazoamua nani anaweza kufanya vitendo mbalimbali kwenye ingizo la Keychain, vikiwemo:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Humruhusu mwenye ruhusa kupata maandishi wazi ya siri.
- **`kSecACLAuthorizationExportWrapped`**: Humruhusu mwenye ruhusa kupata maandishi wazi yaliyosimbwa kwa njia fiche kwa kutumia nenosiri jingine lililotolewa.
- **`kSecACLAuthorizationAny`**: Humruhusu mwenye ruhusa kufanya kitendo chochote.

ACLs huambatana pia na **orodha ya programu zinazoaminika** zinazoweza kufanya vitendo hivi bila kuuliza. Orodha hii inaweza kuwa:<sup>[[1]](#references)</sup>

- **N`il`** (hakuna idhini inayohitajika, **kila mtu anaaminika**)
- Orodha **tupu** (**hakuna mtu** anayeaminika)
- **Orodha** ya **programu** mahususi.

Pia, ingizo linaweza kuwa na ufunguo **`kSecACLAuthorizationPartitionID`,** unaotumika kutambua **teamid, apple,** na **cdhash.**<sup>[[1]](#references)[[2]](#references)</sup>

- Ikiwa **teamid** imebainishwa, programu lazima iwe na **teamid ileile** ili **kufikia** thamani ya **ingizo** bila **kuulizwa**.
- Ikiwa **apple** imebainishwa, programu inahitaji kuwa **imesainiwa** na **Apple**.
- Ikiwa **cdhash** imebainishwa, **programu** lazima iwe na **cdhash** husika.

### Kuunda Ingizo la Keychain

Wakati **ingizo jipya** linapoundwa kwa kutumia **`Keychain Access.app`**, sheria zifuatazo hutumika:<sup>[[1]](#references)</sup>

- Programu zote zinaweza kusimba kwa njia fiche.
- **Hakuna programu** inayoweza kuhamisha/kufungua kwa usimbuaji (bila kumuuliza mtumiaji).
- Programu zote zinaweza kuona ukaguzi wa uadilifu.
- Hakuna programu inayoweza kubadilisha ACLs.
- **partitionID** huwekwa kuwa **`apple`**.

Wakati **programu inaunda ingizo kwenye Keychain**, sheria hutofautiana kidogo:<sup>[[1]](#references)</sup>

- Programu zote zinaweza kusimba kwa njia fiche.
- Ni **programu iliyoliumba** pekee (au programu nyingine zozote zilizoongezwa waziwazi) inayoweza kuhamisha/kufungua kwa usimbuaji (bila kumuuliza mtumiaji).
- Programu zote zinaweza kuona ukaguzi wa uadilifu.
- Hakuna programu inayoweza kubadilisha ACLs.
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
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` huweka partition list ya kipengee, huku `-k` ikitoa nenosiri la sasa la Keychain linalohitajika kufanya mabadiliko hayo; flag inayopokea nenosiri imepitwa na wakati.<sup>[[4]](#references)</sup> Sasisho likifanikiwa haithibitishi kuwa usomaji wa baadaye hautatoa prompt: prototype moja iliyozimwa lakini iliyoonekana bado ilisababisha prompt ya uthibitisho ilipoulizia kipengee kupitia `Security.framework`. Partition ID inayolingana ni sehemu moja tu ya ukaguzi wa ACL na trusted-application ulioelezwa hapo juu, kwa hiyo hakikisha njia halisi ya usomaji.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> **Kuhesabu na kutoa** siri za **keychain bila kutoa prompt** kunaweza kufanywa kwa kutumia tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> API endpoints nyingine zinaweza kupatikana kwenye source code ya [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Orodhesha na upate **maelezo** kuhusu kila ingizo la keychain kwa kutumia **Security Framework**, au unaweza pia kuangalia tool ya cli ya open source ya Apple, [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Baadhi ya mifano ya API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** hutoa maelezo kuhusu kila ingizo, na kuna attributes unazoweza kuweka unapoitumia:
  - **`kSecReturnData`**: Ikiwa ni true, itajaribu kufungua data iliyosimbwa (iweke false ili kuepuka pop-ups zinazoweza kutokea)
  - **`kSecReturnRef`**: Pia pata reference ya kipengee cha keychain (iweke true ikiwa baadaye utaona kuwa unaweza kufungua bila pop-up)
  - **`kSecReturnAttributes`**: Pata metadata kuhusu maingizo
  - **`kSecMatchLimit`**: Idadi ya matokeo ya kurejesha
  - **`kSecClass`**: Aina ya ingizo la keychain

Pata **ACLs** za kila ingizo:<sup>[[1]](#references)</sup>

- Kwa API **`SecAccessCopyACLList`** unaweza kupata **ACL ya kipengee cha keychain**. Hurejesha orodha ya ACLs (kama vile `kSecACLAuthorizationExportClear` na nyingine zilizotajwa awali), ambapo kila ingizo lina:<sup>[[1]](#references)[[2]](#references)</sup>
  - Maelezo
  - **Orodha ya Trusted Application**. Hii inaweza kuwa:
    - App: /Applications/Slack.app
    - Binary: /usr/libexec/airportd
    - Group: group://AirPort

Hamisha data:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** hupata maandishi yasiyosimbwa
- API **`SecItemExport`** huhamisha keys na certificates, lakini huenda ukahitaji kuweka nywila ili kuhamisha maudhui yakiwa yamesimbwa

Na haya ndiyo **masharti** ya kuweza **kuhamisha siri bila prompt**:<sup>[[1]](#references)</sup>

- Ikiwa kuna app **1 au zaidi zinazoaminika** zilizoorodheshwa:
  - Unahitaji **authorizations** zinazofaa (**`Nil`**, au uwe **sehemu** ya orodha ya apps zinazoruhusiwa kwenye authorization ya kufikia maelezo ya siri)
  - Code signature lazima ilingane na **PartitionID**
  - Code signature lazima ilingane na ya app **moja inayoaminika** (au uwe mwanachama wa KeychainAccessGroup inayofaa)
- Ikiwa **apps zote zinaaminika**:
  - Unahitaji **authorizations** zinazofaa
  - Code signature lazima ilingane na **PartitionID**
    - Ikiwa **hakuna PartitionID**, basi hili halihitajiki

> [!CAUTION]
> Kwa hiyo, ikiwa **app moja imeorodheshwa**, unahitaji **kuingiza code kwenye app hiyo**.
>
> Ikiwa **apple** imeonyeshwa kwenye **partitionID**, unaweza kuifikia kwa kutumia **`osascript`**. Hivyo, chochote kinachoamini apps zote huku apple ikiwa kwenye partitionID kinaweza kufikiwa. **`Python`** pia inaweza kutumika.

### Attributes mbili za ziada

- **Invisible**: Hii ni boolean flag ya **kuficha** ingizo kwenye app ya Keychain ya **UI**<sup>[[1]](#references)</sup>
- **General**: Hutumika kuhifadhi **metadata** (kwa hiyo HAIJASIMBWA)<sup>[[1]](#references)</sup>
  - Microsoft ilikuwa ikihifadhi refresh tokens zote kama maandishi yasiyosimbwa ili kufikia endpoint nyeti.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: "Kuvunja kufuli la macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Toleo jipya la mwizi wa macOS wa MacSync linalenga wapenda crypto na developers](https://securelist.com/macsync-new-version/121383/)
- [4] [Nakala ya ukurasa wa mwongozo wa Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
