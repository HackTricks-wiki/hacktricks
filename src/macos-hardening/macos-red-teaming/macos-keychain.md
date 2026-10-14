# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Hoof-Keychains

- Die **User Keychain** (`~/Library/Keychains/login.keychain-db`), wat gebruik word om **gebruikerspesifieke geloofsbriewe** soos toepassingwagwoorde, internetwagwoorde, gebruikergegenereerde sertifikate, netwerkwagwoorde en gebruikergegenereerde publieke/private sleutels te stoor.
- Die **System Keychain** (`/Library/Keychains/System.keychain`), wat **stelselwye geloofsbriewe** soos WiFi-wagwoorde, stelselwortelsertifikate, stelselprivate sleutels en stelseltoepassingwagwoorde stoor.<sup>[[1]](#references)</sup>
  - Dit is moontlik om ander komponente, soos sertifikate, in `/System/Library/Keychains/*` te vind.
- In **iOS** is daar net een **Keychain**, geleë in `/private/var/Keychains/`. Hierdie vouer bevat ook databasisse vir die `TrustStore`, sertifikaatowerhede (`caissuercache`) en OSCP-inskrywings (`ocspache`).
  - Toepassings word in die keychain beperk tot slegs hul private area, gebaseer op hul toepassing-identifiseerder.

### Wagwoordtoegang tot Keychain

Hierdie lêers het geen ingeboude beskerming nie en kan **afgelaai word**, maar hulle is geënkripteer en vereis die **gebruiker se wagwoord in gewone teks om gedekripteer te word**. ’n Hulpmiddel soos [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan vir dekripsie gebruik word.<sup>[[1]](#references)</sup>

## Beskerming van Keychain-inskrywings

### ACLs

Elke inskrywing in die keychain word deur **Access Control Lists (ACLs)** beheer, wat bepaal wie verskeie handelinge op die keychain-inskrywing kan uitvoer, insluitend:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Laat die houer toe om die geheim in gewone teks te verkry.
- **`kSecACLAuthorizationExportWrapped`**: Laat die houer toe om die geheim in gewone teks te verkry, geënkripteer met ’n ander verskafde wagwoord.
- **`kSecACLAuthorizationAny`**: Laat die houer toe om enige handeling uit te voer.

Die ACLs word verder vergesel van ’n **lys vertroude toepassings** wat hierdie handelinge sonder ’n versoek kan uitvoer. Dit kan wees:<sup>[[1]](#references)</sup>

- **N`il`** (geen magtiging nodig nie, **almal word vertrou**)
- ’n **Leë** lys (**niemand** word vertrou nie)
- ’n **Lys** van spesifieke **toepassings**.

Die inskrywing kan ook die sleutel **`kSecACLAuthorizationPartitionID`** bevat, wat gebruik word om die **teamid, apple** en **cdhash** te identifiseer.<sup>[[1]](#references)[[2]](#references)</sup>

- As die **teamid** gespesifiseer word, moet die toepassing dieselfde **teamid** hê om toegang tot die inskrywingswaarde **sonder** ’n **versoek** te kry.
- As **apple** gespesifiseer word, moet die toepassing deur **Apple** **onderteken** wees.
- As die **cdhash** aangedui word, moet die **toepassing** die spesifieke **cdhash** hê.

### Skep van ’n Keychain-inskrywing

Wanneer ’n **nuwe** **inskrywing** met **`Keychain Access.app`** geskep word, geld die volgende reëls:<sup>[[1]](#references)</sup>

- Alle toepassings kan enkripteer.
- **Geen toepassings** kan uitvoer/dekripteer nie (sonder om die gebruiker te vra).
- Alle toepassings kan die integriteitskontrole sien.
- Geen toepassings kan ACLs verander nie.
- Die **partitionID** word op **`apple`** gestel.

Wanneer ’n **toepassing ’n inskrywing in die keychain skep**, is die reëls effens anders:<sup>[[1]](#references)</sup>

- Alle toepassings kan enkripteer.
- Slegs die **toepassing wat die inskrywing geskep het** (of enige ander toepassings wat uitdruklik bygevoeg is) kan uitvoer/dekripteer (sonder om die gebruiker te vra).
- Alle toepassings kan die integriteitskontrole sien.
- Geen toepassings kan die ACLs verander nie.
- Die **partitionID** word op **`teamid:[teamID here]`** gestel.

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

`-S` stel die item se partition list in, terwyl `-k` die huidige Keychain-wagwoord verskaf wat nodig is om daardie verandering aan te bring; die vlag wat ’n wagwoord vereis, is afgekeur.<sup>[[4]](#references)</sup> ’n Suksesvolle opdatering bewys nie dat ’n latere leesaksie stil sal verloop nie: een waargenome, gedeaktiveerde prototipe het steeds ’n bevestigingsversoek geaktiveer toe dit die item deur `Security.framework` navraag gedoen het. ’n Ooreenstemmende partition ID is slegs een deel van die ACL- en vertroude-toepassing-kontroles wat hierbo beskryf word, so verifieer die werklike leespad.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> Die **enumerasie en dump van keychain**-geheime wat **nie ’n versoek sal genereer nie**, kan met die instrument [**LockSmith**](https://github.com/its-a-feature/LockSmith) gedoen word
>
> Ander API-eindpunte kan in die bronkode [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) gevind word.

Lys en kry **inligting** oor elke keychain-inskrywing met die **Security Framework**, of jy kan ook Apple se oopbron CLI-instrument [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** nagaan. Enkele API-voorbeelde:<sup>[[1]](#references)</sup>

- Die API **`SecItemCopyMatching`** gee inligting oor elke inskrywing, en daar is ’n paar attribute wat jy kan stel wanneer jy dit gebruik:
  - **`kSecReturnData`**: Indien waar, sal dit probeer om die data te dekripteer (stel dit op false om moontlike opspringvensters te vermy)
  - **`kSecReturnRef`**: Kry ook ’n verwysing na die keychain-item (stel dit op true indien jy later sien dat jy sonder ’n opspringvenster kan dekripteer)
  - **`kSecReturnAttributes`**: Kry metadata oor inskrywings
  - **`kSecMatchLimit`**: Hoeveel resultate om terug te gee
  - **`kSecClass`**: Watter soort keychain-inskrywing

Kry die **ACLs** van elke inskrywing:<sup>[[1]](#references)</sup>

- Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die keychain-item** kry. Dit gee ’n lys ACLs terug (soos `kSecACLAuthorizationExportClear` en die ander wat vroeër genoem is), waar elke inskrywing die volgende bevat:<sup>[[1]](#references)[[2]](#references)</sup>
  - Beskrywing
  - **Lys van vertroude toepassings**. Dit kan wees:
    - ’n Toepassing: /Applications/Slack.app
    - ’n Binêre lêer: /usr/libexec/airportd
    - ’n Groep: group://AirPort

Voer die data uit:<sup>[[1]](#references)</sup>

- Die API **`SecKeychainItemCopyContent`** kry die plaintext
- Die API **`SecItemExport`** voer die sleutels en sertifikate uit, maar jy sal moontlik wagwoorde moet stel om die inhoud geënkripteer uit te voer

En dit is die **vereistes** om ’n geheim **sonder ’n versoek uit te voer**:<sup>[[1]](#references)</sup>

- Indien **1+ vertroude** toepassings gelys is:
  - Benodig die toepaslike **magtigings** (**`Nil`**, of wees **deel** van die toegelate lys toepassings in die magtiging om toegang tot die geheime inligting te kry)
  - Die kodesignatuur moet met **PartitionID** ooreenstem
  - Die kodesignatuur moet met dié van een **vertroude toepassing** ooreenstem (of jy moet lid wees van die korrekte KeychainAccessGroup)
- Indien **alle toepassings vertrou word**:
  - Benodig die toepaslike **magtigings**
  - Die kodesignatuur moet met **PartitionID** ooreenstem
    - Indien daar **geen PartitionID** is nie, is dit nie nodig nie

> [!CAUTION]
> Daarom moet jy **kode in daardie toepassing inspuit** indien **1 toepassing gelys** is.
>
> Indien **apple** in die **partitionID** aangedui word, kan jy toegang daartoe kry met **`osascript`** vir enigiets wat alle toepassings vertrou met apple in die partitionID. **`Python`** kan ook hiervoor gebruik word.

### Twee bykomende attributes

- **Invisible**: Dit is ’n Booleaanse vlag om die inskrywing in die Keychain-toepassing se **UI** te **versteek**<sup>[[1]](#references)</sup>
- **General**: Dit is vir die stoor van **metadata** (dus is dit NIE GEKRIPTEER NIE)<sup>[[1]](#references)</sup>
  - Microsoft het al die refresh tokens om toegang tot sensitiewe eindpunte te kry, in gewone teks gestoor.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - A new version of the MacSync macOS stealer targets crypto enthusiasts and developers](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) man page mirror](https://keith.github.io/xcode-man-pages/security.1.html)
