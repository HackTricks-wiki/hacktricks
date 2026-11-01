# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Belangrikste Keychains

- Die **User Keychain** (`~/Library/Keychains/login.keychain-db`), wat gebruik word om **gebruikerspesifieke aanmeldbewyse** soos toepassingswagwoorde, internetwagwoorde, gebruiker-gegenereerde sertifikate, netwerkwagwoorde en gebruiker-gegenereerde publieke/private sleutels te stoor.
- Die **System Keychain** (`/Library/Keychains/System.keychain`), wat **stelselwye aanmeldbewyse** soos WiFi-wagwoorde, stelselwortelsertifikate, stelselprivate sleutels en stelseltoepassingswagwoorde stoor.<sup>[[1]](#references)</sup>
  - Ander komponente, soos sertifikate, kan gevind word in `/System/Library/Keychains/*`
- Die per-gebruiker **data protection keychain** verskyn as **Local Items** of **iCloud** in Keychain Access. Dit is apart van `login.keychain-db` en bevat items wat net plaaslik is sowel as items wat gesinkroniseer kan word; `security` is hoofsaaklik 'n lêergebaseerde-keychain-instrument, dus beteken 'n kort `dump-keychain`-resultaat nie dat daar geen aanmeldbewyse hier is nie.<sup>[[5]](#references)</sup>
- In **iOS** is daar net een **Keychain**, geleë in `/private/var/Keychains/`. Hierdie vouer bevat ook databasisse vir die `TrustStore`, sertifikaatowerhede (`caissuercache`) en OSCP-inskrywings (`ocspache`).
  - Toepassings word in die keychain beperk tot slegs hul private area, gebaseer op hul toepassing-identifiseerder.

### Toegang tot Keychain met 'n wagwoord

'n Gekopieerde **lêergebaseerde** keychain is nie gewone teks nie. Vanlyn dekripsie van die beskermde items vereis die keychain-wagwoord of ekwivalente sleutelmateriaal; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) is ontwerp vir hierdie formaat.<sup>[[1]](#references)</sup> Dit verskil van 'n regstreekse lees in 'n ontsluite gebruikersessie, waar itemtoegangsbeheer die lees kan toelaat of 'n versoek kan aktiveer sonder dat die aanmeldwagwoord weer vereis word. Die data protection keychain het 'n ander beskermings- en toegangs-groepmodel.<sup>[[5]](#references)</sup>

## Keychain-inskrywings se beskerming

### Lêergebaseerde keychain-ACL's

Die `SecAccess` ACL- en partisie-lysreëls hieronder beskryf **lêergebaseerde** keychains. Data protection keychain-items gebruik eerder kodeondertekening-toegangsgroepe en opsionele `SecAccessControl`-voorwaardes; moenie hul toeganklikheid aflei uit 'n lêergebaseerde ACL-dump nie.<sup>[[5]](#references)</sup>

Elke inskrywing in 'n lêergebaseerde keychain word beheer deur **Access Control Lists (ACLs)** wat bepaal wie verskeie handelinge op die keychain-inskrywing mag uitvoer, insluitend:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Laat die houer toe om die geheim in gewone teks te kry.
- **`kSecACLAuthorizationExportWrapped`**: Laat die houer toe om die gewone teks te kry wat met 'n ander verskafde wagwoord geënkripteer is.
- **`kSecACLAuthorizationAny`**: Laat die houer toe om enige handeling uit te voer.

Die ACL's word verder vergesel van 'n **lys vertroude toepassings** wat hierdie handelinge sonder 'n versoek kan uitvoer. Dit kan wees:<sup>[[1]](#references)</sup>

- **N`il`** (geen magtiging nodig nie, **almal word vertrou**)
- 'n **leë** lys (**niemand** word vertrou nie)
- 'n **lys** van spesifieke **toepassings**.

Die inskrywing kan ook die sleutel **`kSecACLAuthorizationPartitionID`** bevat, wat gebruik word om die **teamid, apple** en **cdhash** te identifiseer.<sup>[[1]](#references)[[2]](#references)</sup>

- As die **teamid** gespesifiseer is, moet die toepassing dieselfde **teamid** hê om toegang tot die **inskrywing se waarde** te verkry **sonder** 'n **versoek**.
- As **apple** gespesifiseer is, moet die toepassing deur **Apple** **onderteken** wees.
- As die **cdhash** aangedui word, moet die **toepassing** die spesifieke **cdhash** hê.

### Skep 'n lêergebaseerde keychain-inskrywing

Wanneer 'n **nuwe** **inskrywing** met **`Keychain Access.app`** geskep word, geld die volgende reëls:<sup>[[1]](#references)</sup>

- Alle toepassings kan enkripteer.
- **Geen toepassings** kan uitvoer/dekripteer nie (sonder om die gebruiker te vra).
- Alle toepassings kan die integriteitskontrole sien.
- Geen toepassings kan ACL's verander nie.
- Die **partitionID** is ingestel op **`apple`**.

Wanneer 'n **toepassing 'n inskrywing in die keychain skep**, is die reëls effens anders:<sup>[[1]](#references)</sup>

- Alle toepassings kan enkripteer.
- Slegs die **toepassing wat dit geskep het** (of enige ander toepassings wat uitdruklik bygevoeg is) kan uitvoer/dekripteer (sonder om die gebruiker te vra).
- Alle toepassings kan die integriteitskontrole sien.
- Geen toepassings kan die ACL's verander nie.
- Die **partitionID** is ingestel op **`teamid:[teamID here]`**.

## Toegang tot die Keychain

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

`-S` stel die item se partition list in, terwyl `-k` die huidige Keychain-wagwoord verskaf wat nodig is om daardie verandering aan te bring; die vlag wat ’n wagwoord vereis, is verouderd.<sup>[[4]](#references)</sup> ’n Suksesvolle opdatering bewys nie dat ’n latere leesaksie stil sal verloop nie: een waargenome, gedeaktiveerde prototipe het steeds ’n bevestigingsvenster geaktiveer toe dit die item via `Security.framework` navraag gedoen het. ’n Ooreenstemmende partition ID is net een deel van die ACL- en vertroude-toepassing-kontroles wat hierbo beskryf word, so verifieer die werklike leespad.<sup>[[3]](#references)</sup>

### API's

> [!TIP]
> Die **opsomming en dumping van geheime uit die Keychain** wat **nie ’n prompt sal genereer nie**, kan met die nutsding [**LockSmith**](https://github.com/its-a-feature/LockSmith) gedoen word.
>
> Ander API-eindpunte kan in die bronkode van [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) gevind word.

Lys en kry **inligting** oor elke Keychain-inskrywing met die **Security Framework**, of kyk ook na Apple se oopbron-opdragreëlnutsding [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Enkele API-voorbeelde:<sup>[[1]](#references)</sup>

- Die API **`SecItemCopyMatching`** gee inligting oor elke inskrywing, en daar is verskeie attribute wat jy kan instel wanneer jy dit gebruik:
  - **`kSecReturnData`**: As dit true is, sal dit probeer om die data te dekripteer (stel dit op false om moontlike opspringvensters te vermy)
  - **`kSecReturnRef`**: Kry ’n objekverwysing vir ’n sleutel, sertifikaat of identiteit; wagwoorditems het nie hierdie objekvoorstelling nie. Gebruik `kSecReturnPersistentRef` om ’n wagwoord vir ’n latere, geteikende navraag te identifiseer.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Kry metadata oor inskrywings
  - **`kSecMatchLimit`**: Hoeveel resultate om terug te gee
  - **`kSecClass`**: Watter soort Keychain-inskrywing

Kry die **ACL's** van elke inskrywing:<sup>[[1]](#references)</sup>

- Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die Keychain-item** kry. Dit gee ’n lys ACL's terug (soos `kSecACLAuthorizationExportClear` en die ander wat voorheen genoem is), waar elke inskrywing die volgende bevat:<sup>[[1]](#references)[[2]](#references)</sup>
  - Beskrywing
  - **Lys van vertroude toepassings**. Dit kan die volgende wees:
    - ’n Toepassing: /Applications/Slack.app
    - ’n Binêre lêer: /usr/libexec/airportd
    - ’n Groep: group://AirPort

Voer die data uit:<sup>[[1]](#references)</sup>

- Die API **`SecKeychainItemCopyContent`** kry die plaintext
- Die API **`SecItemExport`** voer die sleutels en sertifikate uit, maar jy sal moontlik wagwoorde moet instel om die inhoud geïnkripteer uit te voer

En dit is die **vereistes** om ’n **geheim sonder ’n prompt te kan uitvoer**:<sup>[[1]](#references)</sup>

- As **1 of meer vertroude toepassings** gelys is:
  - Die toepaslike **magtigings** is nodig (**`Nil`**, of wees **deel** van die lys toepassings wat in die magtiging toegelaat word om toegang tot die geheime inligting te kry)
  - Die kodesignatuur moet met die **PartitionID** ooreenstem
  - Die kodesignatuur moet met dié van een **vertroude toepassing** ooreenstem (of jy moet lid wees van die regte KeychainAccessGroup)
- As **alle toepassings vertrou word**:
  - Die toepaslike **magtigings** is nodig
  - Die kodesignatuur moet met die **PartitionID** ooreenstem
    - As daar **geen PartitionID** is nie, is dit nie nodig nie

> [!CAUTION]
> As daar dus **1 toepassing gelys is**, moet jy **kode in daardie toepassing inspuit**.
>
> As **apple** in die **partitionID** aangedui word, kan jy toegang daartoe kry met **`osascript`**; dit geld dus vir enigiets wat alle toepassings vertrou met apple in die partitionID. **`Python`** kan ook hiervoor gebruik word.

### Twee bykomende attribute

- **Invisible**: Dit is ’n boolean-vlag om die inskrywing in die Keychain-toepassing se **UI** te **versteek**<sup>[[1]](#references)</sup>
- **General**: Dit stoor **metadata** (dus is dit NIE GEKRIPTEER NIE)<sup>[[1]](#references)</sup>
  - Microsoft het al die refresh tokens vir toegang tot sensitiewe eindpunte in gewone teks gestoor.<sup>[[1]](#references)</sup>

### Data protection Keychain: lys items en doen dan navraag oor een item

Voer `SecItemCopyMatching` uit vanaf ’n **getekende toepassing in die teiken gebruiker se aanmeldingskonteks** met `kSecUseDataProtectionKeychain: true`; moenie aanvaar dat `security dump-keychain` of ’n verstek-SecItem-navraag hierdie stoorplek deursoek het nie. Die aanroeper sien net die toegangsgroepe waarvoor dit gemagtig is.<sup>[[5]](#references)</sup>

As toetskode binne ’n ander proses loop, volg sy toegang tot die data protection Keychain die gasheertoepassing se entitlements. Inspekteer die werklike getekende entitlements met `codesign -d --entitlements - /path/to/Target.app` en sien [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) vir verwante kontroles.<sup>[[7]](#references)</sup>

Versoek eers **slegs attributes** vir een itemklas. `kSecAttrSynchronizableAny` sluit beide plaaslike en iCloud-sinchroniseerbare resultate in; as jy dit weglaat, word sinchroniseerbare items uitgesluit.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` vermy die verifikasie-UI tydens breë opsomming, maar slaan beskermde resultate oor.<sup>[[9]](#references)</sup> Herhaal indien nodig met `kSecClassInternetPassword`.

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

Vir ’n toegelate geheimeis, bou ’n **nuwe**, beperkte navraag vir die geselekteerde item (byvoorbeeld klas, diens en rekening), stel `kSecReturnData: true` en `kSecMatchLimit: kSecMatchLimitOne` in, en verwag itemspesifieke verifikasie of ’n fout. Moenie `kSecReturnData` met `kSecMatchLimitAll` vir wagwoorditems kombineer nie.<sup>[[10]](#references)</sup> ’n `errSecItemNotFound`-resultaat kan ook op die verkeerde store, sinkronisasiefilter of ontbrekende access-group-regte dui, eerder as dat ’n geloofsbrief ontbreek.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: "Slotpluk van die macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - ’n Nuwe weergawe van die MacSync macOS-steeler teiken kripto-entoesiaste en ontwikkelaars](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1)-manbladsy-spieël](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Oor Mac-keychain-API’s en implementasies](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Grondbeginsels](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Slaggate en beste praktyke](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Toegang tot Keychain-items met Face ID of Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
