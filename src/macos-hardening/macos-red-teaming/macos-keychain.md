# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Belangrikste Keychains

- Die **User Keychain** (`~/Library/Keychains/login.keychain-db`), wat gebruik word om **gebruiker-spesifieke credentials** soos application passwords, internet passwords, user-generated certificates, network passwords en user-generated public/private keys te stoor.
- Die **System Keychain** (`/Library/Keychains/System.keychain`), wat **stelselwye credentials** soos WiFi passwords, system root certificates, system private keys en system application passwords stoor.<sup>[[1]](#references)</sup>
- Dit is moontlik om ander komponente, soos certificates, in `/System/Library/Keychains/*` te vind.
- In **iOS** is daar slegs een **Keychain**, geleë in `/private/var/Keychains/`. Hierdie vouer bevat ook databases vir die `TrustStore`, certificate authorities (`caissuercache`) en OSCP entries (`ocspache`).
- Apps sal in die keychain beperk word tot slegs hul private area, gebaseer op hul application identifier.

### Password Keychain Access

Hierdie files het geen inherente protection nie en kan dus **download** word, maar hulle is encrypted en vereis die **user's plaintext password om decrypted te word**. 'n Tool soos [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan vir decryption gebruik word.<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Elke entry in die keychain word deur **Access Control Lists (ACLs)** beheer, wat bepaal wie verskeie actions op die keychain entry kan uitvoer, insluitend:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Laat die holder toe om die clear text van die secret te verkry.
- **ACLAuthorizationExportWrapped**: Laat die holder toe om die clear text encrypted met 'n ander verskafde password te verkry.
- **ACLAuthorizationAny**: Laat die holder toe om enige action uit te voer.

Die ACLs word verder vergesel van 'n **list of trusted applications** wat hierdie actions sonder prompting kan uitvoer. Dit kan wees:<sup>[[1]](#references)</sup>

- **N`il`** (geen authorization required nie, **everyone is trusted**)
- 'n **empty** list (**nobody** is trusted)
- 'n **List** van spesifieke **applications**.

Die entry kan ook die key **`ACLAuthorizationPartitionID`,** bevat, wat gebruik word om die **teamid, apple,** en **cdhash** te identifiseer.<sup>[[1]](#references)</sup>

- Indien die **teamid** gespesifiseer is, moet die application dieselfde **teamid** hê om toegang tot die **entry** value te verkry **sonder** 'n **prompt**.
- Indien die **apple** gespesifiseer is, moet die app deur **Apple** **signed** wees.
- Indien die **cdhash** aangedui word, moet die **app** die spesifieke **cdhash** hê.

### Creating a Keychain Entry

Wanneer 'n **new** **entry** met **`Keychain Access.app`** geskep word, geld die volgende rules:<sup>[[1]](#references)</sup>

- Alle apps kan encrypt.
- **Geen apps** kan export/decrypt nie (sonder om die user te prompt).
- Alle apps kan die integrity check sien.
- Geen apps kan ACLs verander nie.
- Die **partitionID** word op **`apple`** gestel.

Wanneer 'n **application 'n entry in die keychain skep**, verskil die rules effens:<sup>[[1]](#references)</sup>

- Alle apps kan encrypt.
- Slegs die **creating application** (of enige ander apps wat eksplisiet bygevoeg is) kan export/decrypt (sonder om die user te prompt).
- Alle apps kan die integrity check sien.
- Geen apps kan die ACLs verander nie.
- Die **partitionID** word op **`teamid:[teamID here]`** gestel.

## Accessing the Keychain

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
> Die **keychain enumeration and dumping** van geheime wat **nie 'n prompt genereer nie**, kan met die tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) gedoen word.
>
> Ander API-endpoints kan in die bronkode van [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) gevind word.

Lys en kry **inligting** oor elke keychain-inskrywing met die **Security Framework**, of jy kan ook Apple se open source CLI-tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html) nagaan. Enkele API-voorbeelde:<sup>[[1]](#references)</sup>

- Die API **`SecItemCopyMatching`** gee inligting oor elke inskrywing, en daar is sommige attribute wat jy kan stel wanneer jy dit gebruik:
- **`kSecReturnData`**: As dit waar is, sal dit probeer om die data te dekripteer (stel dit op vals om potensiële opspringvensters te vermy)
- **`kSecReturnRef`**: Kry ook 'n verwysing na die keychain-item (stel dit op waar indien jy later sien dat jy dit sonder 'n opspringvenster kan dekripteer)
- **`kSecReturnAttributes`**: Kry metadata oor inskrywings
- **`kSecMatchLimit`**: Hoeveel resultate om terug te stuur
- **`kSecClass`**: Watter soort keychain-inskrywing

Kry **ACLs** van elke inskrywing:<sup>[[1]](#references)</sup>

- Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die keychain-item** kry. Dit gee 'n lys van ACLs terug (soos `ACLAuthorizationExportClear` en die ander wat voorheen genoem is), waar elke inskrywing het:
- Beskrywing
- **Trusted Application List**. Dit kan wees:
- 'n App: /Applications/Slack.app
- 'n Binary: /usr/libexec/airportd
- 'n Groep: group://AirPort

Export die data:<sup>[[1]](#references)</sup>

- Die API **`SecKeychainItemCopyContent`** kry die plaintext
- Die API **`SecItemExport`** export die sleutels en sertifikate, maar jy sal moontlik wagwoorde moet stel om die inhoud geënkripteer te export

En dit is die **vereistes** om 'n **geheim sonder 'n prompt te kan export**:<sup>[[1]](#references)</sup>

- Indien **1+ trusted** apps gelys is:
- Benodig die toepaslike **authorizations** (**`Nil`**, of wees **deel** van die toegelate lys van apps in die authorization om toegang tot die geheiminligting te kry)
- Benodig 'n code signature wat met **PartitionID** ooreenstem
- Benodig 'n code signature wat met dié van een **trusted app** ooreenstem (of wees 'n lid van die korrekte KeychainAccessGroup)
- Indien **alle toepassings trusted** is:
- Benodig die toepaslike **authorizations**
- Benodig 'n code signature wat met **PartitionID** ooreenstem
- Indien **geen PartitionID** is nie, is dit nie nodig nie

> [!CAUTION]
> Daarom, indien daar **1 toepassing gelys** is, moet jy **code in daardie toepassing inject**.
>
> Indien **apple** in die **partitionID** aangedui word, kan jy toegang daartoe kry met **`osascript`**; dus enigiets wat alle toepassings vertrou met apple in die partitionID. **`Python`** kan ook hiervoor gebruik word.

### Twee addisionele attributes

- **Invisible**: Dit is 'n boolean-vlag om die inskrywing vir die **UI** Keychain-app te **versteek**<sup>[[1]](#references)</sup>
- **General**: Dit word gebruik om **metadata** te stoor (dit is dus NIE GEËNKRIPTEER nie)<sup>[[1]](#references)</sup>
- Microsoft het al die refresh tokens om toegang tot sensitiewe endpoint te kry, in gewone teks gestoor.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking van die macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
