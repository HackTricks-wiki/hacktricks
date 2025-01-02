# macOS Sleutelkettie

{{#include ../../banners/hacktricks-training.md}}

## Hoof Sleutelketties

- Die **Gebruiker Sleutelkettie** (`~/Library/Keychains/login.keychain-db`), wat gebruik word om **gebruiker-spesifieke akrediteerings** soos toepassingswagwoorde, internetwagwoorde, gebruiker-gegenereerde sertifikate, netwerkwagwoorde, en gebruiker-gegenereerde publieke/privaat sleutels te stoor.
- Die **Stelsel Sleutelkettie** (`/Library/Keychains/System.keychain`), wat **stelsel-wye akrediteerings** soos WiFi wagwoorde, stelsel wortelsertifikate, stelsel privaat sleutels, en stelsel toepassingswagwoorde stoor.
- Dit is moontlik om ander komponente soos sertifikate in `/System/Library/Keychains/*` te vind.
- In **iOS** is daar slegs een **Sleutelkettie** geleë in `/private/var/Keychains/`. Hierdie gids bevat ook databasisse vir die `TrustStore`, sertifikaatowerhede (`caissuercache`) en OSCP inskrywings (`ocspache`).
- Toepassings sal in die sleutelkettie beperk wees tot hul private area gebaseer op hul toepassingsidentifiseerder.

### Wagwoord Sleutelkettie Toegang

Hierdie lêers, terwyl hulle nie inherente beskerming het nie en **afgelaai** kan word, is versleuteld en vereis die **gebruikers se platte wagwoord om ontcijfer** te word. 'n Gereedskap soos [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word vir ontcijfering.

## Sleutelkettie Inskrywings Beskerming

### ACLs

Elke inskrywing in die sleutelkettie word gereguleer deur **Toegang Beheer Lyste (ACLs)** wat bepaal wie verskillende aksies op die sleutelkettie inskrywing kan uitvoer, insluitend:

- **ACLAuhtorizationExportClear**: Laat die houer toe om die duidelike teks van die geheim te verkry.
- **ACLAuhtorizationExportWrapped**: Laat die houer toe om die duidelike teks wat met 'n ander verskafde wagwoord versleuteld is, te verkry.
- **ACLAuhtorizationAny**: Laat die houer toe om enige aksie uit te voer.

Die ACLs word verder vergesel deur 'n **lys van vertroude toepassings** wat hierdie aksies kan uitvoer sonder om te vra. Dit kan wees:

- **N`il`** (geen toestemming vereis, **elkeen is vertrou**)
- 'n **leë** lys (**niemand** is vertrou)
- **Lys** van spesifieke **toepassings**.

Ook kan die inskrywing die sleutel **`ACLAuthorizationPartitionID`** bevat, wat gebruik word om die **teamid, apple,** en **cdhash** te identifiseer.

- As die **teamid** gespesifiseer is, dan om die **inskrywing** waarde **sonder** 'n **prompt** te **verkry**, moet die gebruikte toepassing die **selfde teamid** hê.
- As die **apple** gespesifiseer is, dan moet die toepassing **onderteken** wees deur **Apple**.
- As die **cdhash** aangedui is, dan moet die **app** die spesifieke **cdhash** hê.

### Skep van 'n Sleutelkettie Inskrywing

Wanneer 'n **nuwe** **inskrywing** geskep word met **`Keychain Access.app`**, geld die volgende reëls:

- Alle toepassings kan versleutel.
- **Geen toepassings** kan uitvoer/ontcijfer (sonder om die gebruiker te vra).
- Alle toepassings kan die integriteitskontrole sien.
- Geen toepassings kan ACLs verander nie.
- Die **partitionID** is gestel op **`apple`**.

Wanneer 'n **toepassing 'n inskrywing in die sleutelkettie skep**, is die reëls effens anders:

- Alle toepassings kan versleutel.
- Slegs die **skepende toepassing** (of enige ander toepassings wat eksplisiet bygevoeg is) kan uitvoer/ontcijfer (sonder om die gebruiker te vra).
- Alle toepassings kan die integriteitskontrole sien.
- Geen toepassings kan die ACLs verander nie.
- Die **partitionID** is gestel op **`teamid:[teamID here]`**.

## Toegang tot die Sleutelkettie

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
> Die **keychain enumerasie en dumping** van geheime wat **nie 'n prompt sal genereer nie** kan gedoen word met die hulpmiddel [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Ander API eindpunte kan gevind word in [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) bronkode.

Lys en kry **inligting** oor elke keychain inskrywing met die **Security Framework** of jy kan ook die Apple se oopbron cli hulpmiddel [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Sommige API voorbeelde:

- Die API **`SecItemCopyMatching`** gee inligting oor elke inskrywing en daar is 'n paar eienskappe wat jy kan stel wanneer jy dit gebruik:
- **`kSecReturnData`**: As waar, sal dit probeer om die data te ontsleutel (stel op vals om potensiële pop-ups te vermy)
- **`kSecReturnRef`**: Kry ook verwysing na keychain item (stel op waar in geval jy later sien jy kan ontsleutel sonder pop-up)
- **`kSecReturnAttributes`**: Kry metadata oor inskrywings
- **`kSecMatchLimit`**: Hoeveel resultate om terug te gee
- **`kSecClass`**: Watter soort keychain inskrywing

Kry **ACLs** van elke inskrywing:

- Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die keychain item** kry, en dit sal 'n lys van ACLs teruggee (soos `ACLAuhtorizationExportClear` en die ander voorheen genoem) waar elke lys het:
- Beskrywing
- **Vertroude Toepassing Lys**. Dit kan wees:
- 'n app: /Applications/Slack.app
- 'n binêre: /usr/libexec/airportd
- 'n groep: group://AirPort

Eksporteer die data:

- Die API **`SecKeychainItemCopyContent`** kry die platte teks
- Die API **`SecItemExport`** eksporteer die sleutels en sertifikate maar jy mag dalk moet wagwoord stel om die inhoud versleuteld te eksporteer

En dit is die **vereistes** om 'n **geheim sonder 'n prompt** te kan **eksporteer**:

- As **1+ vertroude** apps gelys:
- Nodig die toepaslike **autorisaties** (**`Nil`**, of wees **deel** van die toegelate lys van apps in die autorisasie om toegang tot die geheime inligting te verkry)
- Nodig kodehandtekening om te pas by **PartitionID**
- Nodig kodehandtekening om te pas by een **vertroude app** (of wees 'n lid van die regte KeychainAccessGroup)
- As **alle toepassings vertrou**:
- Nodig die toepaslike **autorisaties**
- Nodig kodehandtekening om te pas by **PartitionID**
- As **geen PartitionID**, dan is dit nie nodig nie

> [!CAUTION]
> Daarom, as daar **1 toepassing gelys** is, moet jy **kode in daardie toepassing inspuit**.
>
> As **apple** aangedui word in die **partitionID**, kan jy dit toegang met **`osascript`** so enigiets wat al die toepassings met apple in die partitionID vertrou. **`Python`** kan ook hiervoor gebruik word.

### Twee addisionele eienskappe

- **Onsigbaar**: Dit is 'n booleaanse vlag om die inskrywing van die **UI** Keychain app te **versteek**
- **Algemeen**: Dit is om **metadata** te stoor (so dit is NIE VERSPREID nie)
- Microsoft het al die verfrissingstokens in platte teks gestoor om toegang tot sensitiewe eindpunte te verkry.

## References

- [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
