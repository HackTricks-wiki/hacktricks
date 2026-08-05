# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Hoof-Keychains

- Die **Gebruiker-Keychain** (`~/Library/Keychains/login.keychain-db`), wat gebruik word om **gebruikerspesifieke geloofsbriewe** soos toepassingswagwoorde, internetwagwoorde, gebruiker-gegenereerde sertifikate, netwerkpl             wagwoorde en gebruiker-gegenereerde publieke/private sleutels te stoor.
- Die **Stelsel-Keychain** (`/Library/Keychains/System.keychain`), wat **stelselwye geloofsbriewe** soos WiFi-wagwoorde, stelselwortelsertifikate, private stelselsleutels en stelseltoepassingswagwoorde stoor.<sup>[1]</sup>
- Dit is moontlik om ander komponente, soos sertifikate, in `/System/Library/Keychains/*` te vind.
- In **iOS** is daar slegs een **Keychain**, geleë in `/private/var/Keychains/`. Hierdie vouer bevat ook databasisse vir die `TrustStore`, sertifikaatowerhede (`caissuercache`) en OSCP-inskrywings (`ocspache`).
- Toepassings sal in die keychain beperk word tot slegs hul private area, gebaseer op hul toepassingsidentifiseerder.

### Wagwoord-Keychain-toegang

Hierdie lêers het weliswaar geen ingeboude beskerming nie en kan **afgelaai** word, maar hulle is geënkripteer en vereis die **gebruiker se gewone-teks-wagwoord om gedekripteer te word**. ’n Tool soos [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan vir dekripsie gebruik word.<sup>[1]</sup>

## Beskerming van Keychain-inskrywings

### ACLs

Elke inskrywing in die keychain word deur **Access Control Lists (ACLs)** beheer, wat bepaal wie verskeie aksies op die keychain-inskrywing kan uitvoer, insluitend:<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: Laat die houer toe om die gewone teks van die geheim te verkry.
- **ACLAuhtorizationExportWrapped**: Laat die houer toe om die gewone teks te verkry, geënkripteer met ’n ander verskafde wagwoord.
- **ACLAuhtorizationAny**: Laat die houer toe om enige aksie uit te voer.

Die ACLs word verder vergesel deur ’n **lys van vertroude toepassings** wat hierdie aksies kan uitvoer sonder om ’n prompt te wys. Dit kan wees:<sup>[1]</sup>

- **N`il`** (geen magtiging benodig nie, **almal word vertrou**)
- ’n **Leë** lys (**niemand** word vertrou nie)
- ’n **Lys** van spesifieke **toepassings**.

Die inskrywing kan ook die sleutel **`ACLAuthorizationPartitionID`,** bevat, wat gebruik word om die **teamid, apple,** en **cdhash** te identifiseer.<sup>[1]</sup>

- As die **teamid** gespesifiseer word, moet die gebruikte toepassing dieselfde teamid hê om toegang tot die **inskrywing** se waarde **sonder** ’n **prompt** te verkry.
- As die **apple** gespesifiseer word, moet die toepassing deur **Apple** **onderteken** wees.
- As die **cdhash** aangedui word, moet die **toepassing** die spesifieke **cdhash** hê.

### Skep van ’n Keychain-inskrywing

Wanneer ’n **nuwe** **inskrywing** met **`Keychain Access.app`** geskep word, geld die volgende reëls:<sup>[1]</sup>

- Alle toepassings kan enkripteer.
- **Geen toepassings** kan uitvoer/dekripteer nie (sonder om die gebruiker te vra).
- Alle toepassings kan die integriteitskontrole sien.
- Geen toepassings kan ACLs verander nie.
- Die **partitionID** word op **`apple`** gestel.

Wanneer ’n **toepassing ’n inskrywing in die keychain skep**, verskil die reëls effens:<sup>[1]</sup>

- Alle toepassings kan enkripteer.
- Slegs die **skeppende toepassing** (of enige ander toepassings wat uitdruklik bygevoeg is) kan uitvoer/dekripteer (sonder om die gebruiker te vra).
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

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> Die **keychain enumeration and dumping** van secrets wat **won't generate a prompt** kan met die tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) gedoen word
>
> Ander API endpoints kan in die [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html)-source code gevind word.

Lys en kry **info** oor elke keychain-entry deur die **Security Framework** te gebruik, of jy kan ook Apple se open source cli tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** nagaan. Sommige API-voorbeelde:<sup>[1]</sup>

- Die API **`SecItemCopyMatching`** gee info oor elke entry en daar is sommige attributes wat jy kan stel wanneer jy dit gebruik:
- **`kSecReturnData`**: As dit true is, sal dit probeer om die data te decrypt (stel dit op false om potensiële pop-ups te vermy)
- **`kSecReturnRef`**: Kry ook ’n reference na die keychain-item (stel dit op true indien jy later sien dat jy sonder ’n pop-up kan decrypt)
- **`kSecReturnAttributes`**: Kry metadata oor entries
- **`kSecMatchLimit`**: Hoeveel resultate om terug te gee
- **`kSecClass`**: Watter soort keychain-entry

Kry **ACLs** van elke entry:<sup>[1]</sup>

- Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die keychain-item** kry, en dit sal ’n lys ACLs teruggee (soos `ACLAuhtorizationExportClear` en die ander wat voorheen genoem is), waar elke lys het:
- Beskrywing
- **Trusted Application List**. Dit kan wees:
- ’n App: /Applications/Slack.app
- ’n Binary: /usr/libexec/airportd
- ’n Groep: group://AirPort

Export the data:<sup>[1]</sup>

- Die API **`SecKeychainItemCopyContent`** kry die plaintext
- Die API **`SecItemExport`** export die keys en certificates, maar jy moet dalk passwords stel om die content encrypted te export

En dit is die **requirements** om ’n secret **without a prompt te kan export**:<sup>[1]</sup>

- Indien **1+ trusted** apps gelys is:
- Benodig die toepaslike **authorizations** (**`Nil`**, of wees **part** van die toegelate lys apps in die authorization om toegang tot die secret info te kry)
- Benodig code signature om met **PartitionID** ooreen te stem
- Benodig code signature om met dié van een **trusted app** ooreen te stem (of wees ’n lid van die korrekte KeychainAccessGroup)
- Indien **all applications trusted** is:
- Benodig die toepaslike **authorizations**
- Benodig code signature om met **PartitionID** ooreen te stem
- Indien **no PartitionID**, dan is dit nie nodig nie

> [!CAUTION]
> Daarom, indien daar **1 application listed** is, moet jy **code in daardie application inject**.
>
> Indien **apple** in die **partitionID** aangedui word, kan jy dit met **`osascript`** access, dus enigiets wat all applications trust met apple in die partitionID. **`Python`** kan ook hiervoor gebruik word.

### Twee additional attributes

- **Invisible**: Dit is ’n boolean flag om die entry van die **UI** Keychain-app te **hide**<sup>[1]</sup>
- **General**: Dit is om **metadata** te stoor (dus is dit **NOT ENCRYPTED**)<sup>[1]</sup>
- Microsoft het al die refresh tokens om toegang tot sensitiewe endpoint te kry in plain text gestoor.<sup>[1]</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
