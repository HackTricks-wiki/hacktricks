# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Hoof-Keychains

- Die **User Keychain** (`~/Library/Keychains/login.keychain-db`), wat gebruik word om **gebruiker-spesifieke credentials** soos application passwords, internet passwords, user-generated certificates, network passwords en user-generated public/private keys te stoor.
- Die **System Keychain** (`/Library/Keychains/System.keychain`), wat **stelselwye credentials** soos WiFi passwords, system root certificates, system private keys en system application passwords stoor.<sup>[[1]](#references)</sup>
- Dit is moontlik om ander komponente, soos certificates, in `/System/Library/Keychains/*` te vind.
- In **iOS** is daar slegs een **Keychain**, geleë in `/private/var/Keychains/`. Hierdie vouer bevat ook databases vir die `TrustStore`, certificate authorities (`caissuercache`) en OSCP entries (`ocspache`).
- Apps sal in die keychain slegs tot hul private area beperk word, gebaseer op hul application identifier.

### Password Keychain Access

Hierdie lêers het geen ingeboude beskerming nie en kan **afgelaai** word, maar hulle is encrypted en vereis die **user se plaintext password om decrypted te word**. ’n Tool soos [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan vir decryption gebruik word.<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Elke entry in die keychain word deur **Access Control Lists (ACLs)** beheer, wat bepaal wie verskeie actions op die keychain entry kan uitvoer, insluitend:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Laat die holder toe om die clear text van die secret te kry.
- **ACLAuhtorizationExportWrapped**: Laat die holder toe om die clear text encrypted met ’n ander verskafde password te kry.
- **ACLAuhtorizationAny**: Laat die holder toe om enige action uit te voer.

Die ACLs word verder vergesel deur ’n **lys van trusted applications** wat hierdie actions sonder prompting kan uitvoer. Dit kan wees:<sup>[[1]](#references)</sup>

- **N`il`** (geen authorization word vereis nie, **almal word vertrou**)
- ’n **leë** lys (**niemand** word vertrou nie)
- **Lys** van spesifieke **applications**.

Die entry kan ook die key **`ACLAuthorizationPartitionID`,** bevat, wat gebruik word om die **teamid, apple,** en **cdhash** te identifiseer.<sup>[[1]](#references)</sup>

- Indien die **teamid** gespesifiseer word, moet die application wat gebruik word dieselfde teamid hê om die entry se waarde **sonder** ’n **prompt** te **access**.
- Indien die **apple** gespesifiseer word, moet die app deur **Apple** **signed** wees.
- Indien die **cdhash** aangedui word, moet die **app** die spesifieke **cdhash** hê.

### Creating a Keychain Entry

Wanneer ’n **nuwe** **entry** met **`Keychain Access.app`** geskep word, is die volgende reëls van toepassing:<sup>[[1]](#references)</sup>

- Alle apps kan encrypt.
- **Geen apps** kan export/decrypt nie (sonder om die gebruiker te prompt).
- Alle apps kan die integrity check sien.
- Geen apps kan ACLs verander nie.
- Die **partitionID** word op **`apple`** gestel.

Wanneer ’n **application ’n entry in die keychain skep**, verskil die reëls effens:<sup>[[1]](#references)</sup>

- Alle apps kan encrypt.
- Slegs die **creating application** (of enige ander apps wat eksplisiet bygevoeg is) kan export/decrypt (sonder om die gebruiker te prompt).
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

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> Die **keychain enumeration and dumping** van secrets wat **won't generate a prompt** kan met die tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) gedoen word.
>
> Ander API endpoints kan in die Apple se open source cli tool [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html)-broncode gevind word.

Lys en kry **info** oor elke keychain-entry met die **Security Framework**, of jy kan ook Apple se open source cli tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html) nagaan. Sommige API-voorbeelde:<sup>[[1]](#references)</sup>

- Die API **`SecItemCopyMatching`** gee info oor elke entry, en daar is sommige attributes wat jy kan stel wanneer jy dit gebruik:
- **`kSecReturnData`**: Indien true, sal dit probeer om die data te decrypt (stel dit op false om moontlike pop-ups te vermy)
- **`kSecReturnRef`**: Kry ook ’n reference na die keychain-item (stel dit op true indien jy later sien dat jy sonder ’n pop-up kan decrypt)
- **`kSecReturnAttributes`**: Kry metadata oor entries
- **`kSecMatchLimit`**: Hoeveel resultate om terug te gee
- **`kSecClass`**: Watter soort keychain-entry

Kry **ACLs** van elke entry:<sup>[[1]](#references)</sup>

- Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die keychain-item** kry, en dit sal ’n lys ACLs teruggee (soos `ACLAuhtorizationExportClear` en die ander wat vroeër genoem is), waar elke lys die volgende bevat:
- Beskrywing
- **Trusted Application List**. Dit kan wees:
- ’n App: /Applications/Slack.app
- ’n Binary: /usr/libexec/airportd
- ’n Groep: group://AirPort

Export die data:<sup>[[1]](#references)</sup>

- Die API **`SecKeychainItemCopyContent`** kry die plaintext
- Die API **`SecItemExport`** export die keys en certificates, maar jy sal moontlik passwords moet stel om die content encrypted te export

En dit is die **vereistes** om ’n secret **sonder ’n prompt te kan export**:<sup>[[1]](#references)</sup>

- Indien **1+ trusted** apps gelys is:
- Benodig die toepaslike **authorizations** (**`Nil`**, of wees **deel** van die toegelate lys apps in die authorization om toegang tot die secret info te verkry)
- Die code signature moet met **PartitionID** ooreenstem
- Die code signature moet ooreenstem met dié van een **trusted app** (of wees ’n lid van die korrekte KeychainAccessGroup)
- Indien **alle applications trusted** is:
- Benodig die toepaslike **authorizations**
- Die code signature moet met **PartitionID** ooreenstem
- Indien **geen PartitionID** bestaan nie, is dit nie nodig nie

> [!CAUTION]
> Daarom, indien daar **1 application gelys** is, moet jy **code in daardie application inject**.
>
> Indien **apple** in die **partitionID** aangedui word, kan jy toegang daartoe kry met **`osascript`**, dus enigiets wat alle applications met apple in die partitionID trust. **`Python`** kan ook hiervoor gebruik word.

### Twee addisionele attributes

- **Invisible**: Dit is ’n boolean flag om die entry van die **UI** Keychain-app te **hide**<sup>[[1]](#references)</sup>
- **General**: Dit word gebruik om **metadata** te stoor (dit is dus NIE ENCRYPTED nie)<sup>[[1]](#references)</sup>
- Microsoft het al die refresh tokens om toegang tot sensitiewe endpoint te verkry in plaintext gestoor.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
