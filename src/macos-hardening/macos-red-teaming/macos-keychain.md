# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychain Kuu

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), inayotumika kuhifadhi **credentials mahususi za mtumiaji** kama vile nywila za programu, nywila za intaneti, certificates zilizoundwa na mtumiaji, nywila za mtandao na public/private keys zilizoundwa na mtumiaji.
- **System Keychain** (`/Library/Keychains/System.keychain`), inayohifadhi **credentials za mfumo mzima** kama vile nywila za WiFi, root certificates za mfumo, private keys za mfumo na nywila za programu za mfumo.<sup>[[1]](#references)</sup>
  - Inawezekana kupata vipengele vingine kama certificates katika `/System/Library/Keychains/*`
- **data protection keychain** ya kila mtumiaji huonekana kama **Local Items** au **iCloud** katika Keychain Access. Ni tofauti na `login.keychain-db` na ina vipengee vya ndani pekee na vinavyoweza kusawazishwa; `security` ni zana inayohusu zaidi file-based-keychain, kwa hivyo matokeo mafupi ya `dump-keychain` hayathibitishi kwamba hakuna credentials hapa.<sup>[[5]](#references)</sup>
- Katika **iOS** kuna **Keychain** moja tu, iliyoko `/private/var/Keychains/`. Folda hii pia ina databases za `TrustStore`, mamlaka za certificates (`caissuercache`) na entries za OSCP (`ocspache`).
  - Programu zitazuiwa kutumia Keychain zaidi ya eneo lao la faragha, kulingana na application identifier.

### Ufikiaji wa Keychain ya Nywila

Keychain ya **file-based** iliyonakiliwa si plaintext. Ili kusimbua offline vipengee vyake vilivyolindwa, unahitaji nywila ya keychain au key material inayolingana; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) inalenga format hii.<sup>[[1]](#references)</sup> Hii ni tofauti na kusoma moja kwa moja katika session ya mtumiaji iliyo unlocked, ambapo access controls za kipengee zinaweza kuruhusu usomaji au kuonyesha prompt bila kuhitaji tena nywila ya kuingia. data protection keychain ina modeli tofauti ya ulinzi na access-group.<sup>[[5]](#references)</sup>

## Ulinzi wa Entries za Keychain

### ACL za file-based keychain

Sheria za `SecAccess` ACL na partition-list zilizo hapa chini zinahusu **file-based** keychains. Vipengee vya data protection keychain badala yake hutumia access groups za code-signing na masharti ya hiari ya `SecAccessControl`; usihitimishe ufikivu wake kutokana na dump ya file-based ACL.<sup>[[5]](#references)</sup>

Kila entry katika file-based keychain inadhibitiwa na **Access Control Lists (ACLs)** zinazoamua nani anaweza kutekeleza vitendo mbalimbali kwenye entry ya keychain, ikiwemo:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Humruhusu mwenye ruhusa kupata secret katika hali ya clear text.
- **`kSecACLAuthorizationExportWrapped`**: Humruhusu mwenye ruhusa kupata clear text ikiwa imesimbwa kwa nywila nyingine iliyotolewa.
- **`kSecACLAuthorizationAny`**: Humruhusu mwenye ruhusa kutekeleza kitendo chochote.

ACL huambatana pia na **orodha ya programu zinazoaminika** zinazoweza kutekeleza vitendo hivi bila kuonyesha prompt. Orodha hiyo inaweza kuwa:<sup>[[1]](#references)</sup>

- **N`il`** (hakuna idhini inayohitajika, **kila mtu anaaminika**)
- Orodha **tupu** (**hakuna mtu** anayeaminika)
- **Orodha** ya **programu** mahususi.

Pia entry inaweza kuwa na key **`kSecACLAuthorizationPartitionID`,** inayotumika kutambua **teamid, apple,** na **cdhash.**<sup>[[1]](#references)[[2]](#references)</sup>

- Ikiwa **teamid** imebainishwa, programu lazima iwe na **teamid ileile** ili **ifikie** thamani ya **entry** bila **prompt**.
- Ikiwa **apple** imebainishwa, programu inahitaji kuwa **imesainiwa** na **Apple**.
- Ikiwa **cdhash** imebainishwa, **programu** lazima iwe na **cdhash** mahususi.

### Kuunda entry ya file-based keychain

**Entry** **mpya** inapoundwa kwa kutumia **`Keychain Access.app`**, sheria zifuatazo hutumika:<sup>[[1]](#references)</sup>

- Programu zote zinaweza kusimba.
- **Hakuna programu** inayoweza ku-export/decrypt (bila kuonyesha prompt kwa mtumiaji).
- Programu zote zinaweza kuona ukaguzi wa integrity.
- Hakuna programu inayoweza kubadilisha ACLs.
- **partitionID** huwekwa kuwa **`apple`**.

**Programu inapounda entry katika keychain**, sheria huwa tofauti kidogo:<sup>[[1]](#references)</sup>

- Programu zote zinaweza kusimba.
- Ni **programu iliyounda entry** pekee (au programu nyingine yoyote iliyoongezwa waziwazi) inayoweza ku-export/decrypt (bila kuonyesha prompt kwa mtumiaji).
- Programu zote zinaweza kuona ukaguzi wa integrity.
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

`-S` huweka partition list ya kipengee, ilhali `-k` hutoa password ya sasa ya Keychain inayohitajika kufanya mabadiliko hayo; flag inayopokea password imepitwa na wakati.<sup>[[4]](#references)</sup> Kusasisha kwa mafanikio hakuthibitishi kwamba usomaji wa baadaye hautatoa prompt: prototype moja iliyozimwa na kujaribiwa bado ilitoa prompt ya uthibitisho ilipojaribu kupata kipengee kupitia `Security.framework`. Partition ID inayolingana ni sehemu moja tu ya ukaguzi wa ACL na trusted-application ulioelezwa hapo juu, kwa hivyo hakikisha njia halisi ya kusoma.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> **Kuhesabu keychain na kutoa siri** bila **kusababisha prompt** kunawezekana kwa kutumia zana [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> API endpoints nyingine zinaweza kupatikana kwenye source code ya [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Orodhesha na upate **maelezo** kuhusu kila ingizo la keychain kwa kutumia **Security Framework**, au unaweza pia kuangalia zana ya CLI ya Apple iliyo open source, [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Baadhi ya mifano ya API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** hutoa maelezo kuhusu kila ingizo, na kuna baadhi ya attributes unazoweza kuweka unapoitumia:
  - **`kSecReturnData`**: Ikiwa ni true, itajaribu kufungua data (iweke kuwa false ili kuepuka pop-up zinazoweza kutokea)
  - **`kSecReturnRef`**: Pata object reference ya key, certificate, au identity; password items hazina uwakilishi huu wa object. Tumia `kSecReturnPersistentRef` kutambua password kwa query maalum ya baadaye.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Pata metadata kuhusu entries
  - **`kSecMatchLimit`**: Idadi ya matokeo ya kurudisha
  - **`kSecClass`**: Aina ya ingizo la keychain

Pata **ACLs** za kila ingizo:<sup>[[1]](#references)</sup>

- Kwa API **`SecAccessCopyACLList`** unaweza kupata **ACL ya kipengee cha keychain**. Hurejesha orodha ya ACLs (kama vile `kSecACLAuthorizationExportClear` na nyingine zilizotajwa hapo awali), ambapo kila ingizo lina:<sup>[[1]](#references)[[2]](#references)</sup>
  - Maelezo
  - **Orodha ya Trusted Application**. Hii inaweza kuwa:
    - App: /Applications/Slack.app
    - Binary: /usr/libexec/airportd
    - Group: group://AirPort

Hamisha data:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** hupata plaintext
- API **`SecItemExport`** huhamisha keys na certificates, lakini huenda ukahitaji kuweka passwords ili kuhamisha maudhui yakiwa yamesimbwa kwa njia fiche

Na hizi ndizo **masharti** ya kuweza **kuhamisha siri bila prompt**:<sup>[[1]](#references)</sup>

- Ikiwa kuna app **1 au zaidi zinazoaminika** zilizoorodheshwa:
  - Unahitaji **authorizations** zinazofaa (**`Nil`**, au uwe **sehemu** ya orodha ya apps zinazoruhusiwa kwenye authorization ya kufikia maelezo ya siri)
  - Code signature inahitaji kulingana na **PartitionID**
  - Code signature inahitaji kulingana na ya **app moja inayoaminika** (au uwe mwanachama wa KeychainAccessGroup inayofaa)
- Ikiwa **apps zote zinaaminika**:
  - Unahitaji **authorizations** zinazofaa
  - Code signature inahitaji kulingana na **PartitionID**
    - Ikiwa hakuna **PartitionID**, basi hili halihitajiki

> [!CAUTION]
> Kwa hiyo, ikiwa kuna **app 1 iliyoorodheshwa**, unahitaji **kuingiza code kwenye app hiyo**.
>
> Ikiwa **apple** imeonyeshwa kwenye **partitionID**, unaweza kuifikia kwa kutumia **`osascript`**; hivyo, kitu chochote kinachoamini apps zote huku kikiwa na apple kwenye partitionID kinaweza kufikiwa. **`Python`** pia inaweza kutumika kwa hili.

### Attributes mbili za ziada

- **Invisible**: Hii ni boolean flag ya **kuficha** ingizo kwenye app ya Keychain ya **UI**<sup>[[1]](#references)</sup>
- **General**: Hutumika kuhifadhi **metadata** (kwa hiyo HAIJASIMBWA KWA NJIA FICHE)<sup>[[1]](#references)</sup>
  - Microsoft ilikuwa ikihifadhi refresh tokens zote kama plain text ili kufikia endpoint nyeti.<sup>[[1]](#references)</sup>

### Data protection keychain: orodhesha, kisha ulizie kipengee kimoja

Endesha `SecItemCopyMatching` kutoka kwa **app iliyosainiwa katika muktadha wa kuingia wa mtumiaji lengwa** ikiwa na `kSecUseDataProtectionKeychain: true`; usidhani kwamba `security dump-keychain` au SecItem query ya kawaida ilitafuta kwenye hifadhi hii. Caller huona tu access groups ambazo imeidhinishwa kutumia.<sup>[[5]](#references)</sup>

Ikiwa code ya majaribio inaendeshwa ndani ya process nyingine, ufikiaji wake wa data protection keychain hufuata entitlements za executable hiyo mwenyeji. Kagua entitlements halisi zilizosainiwa kwa kutumia `codesign -d --entitlements - /path/to/Target.app` na uone [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) kwa ukaguzi unaohusiana.<sup>[[7]](#references)</sup>

Kwanza omba **attributes pekee** za class moja ya vipengee. `kSecAttrSynchronizableAny` hujumuisha vinavyolingana vilivyo local na vinavyosawazishwa kupitia iCloud; ukiiacha, vipengee vinavyosawazishwa havitajumuishwa.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` huzuia UI ya uthibitishaji wakati wa kuorodhesha kwa upana, lakini kwa gharama ya kuruka vinavyolingana vilivyolindwa.<sup>[[9]](#references)</sup> Rudia kwa kutumia `kSecClassInternetPassword` ikihitajika.

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

Kwa usomaji unaoruhusiwa wa siri, tengeneza query **mpya** na finyu kwa kipengee kilichochaguliwa (kwa mfano, class, service na account), weka `kSecReturnData: true` na `kSecMatchLimit: kSecMatchLimitOne`, na tarajia uthibitishaji mahususi kwa kipengee hicho au hitilafu. **Usiunganishe** `kSecReturnData` na `kSecMatchLimitAll` kwa vipengee vya password.<sup>[[10]](#references)</sup> Matokeo ya `errSecItemNotFound` yanaweza pia kuashiria matumizi ya store isiyo sahihi, kichujio cha sync, au kukosekana kwa ruhusa ya access-group badala ya kukosekana kwa credential.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: "Kuchokonoa macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Toleo jipya la mwizi wa macOS MacSync linalenga wapenda crypto na wasanidi programu](https://securelist.com/macsync-new-version/121383/)
- [4] [Nakala ya kioo ya ukurasa wa mwongozo wa Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Kuhusu API na utekelezaji wa keychain kwenye Mac](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Misingi](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Mitego na mbinu bora](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Kufikia vipengee vya Keychain kwa kutumia Face ID au Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
