# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Glavni Keychain-ovi

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), koji se koristi za čuvanje **korisničkih kredencijala** kao što su lozinke za aplikacije, lozinke za internet, sertifikati koje je korisnik generisao, lozinke za mrežu i javni/privatni ključevi koje je korisnik generisao.
- **System Keychain** (`/Library/Keychains/System.keychain`), koji čuva **sistemske kredencijale** kao što su WiFi lozinke, sistemski root sertifikati, sistemski privatni ključevi i lozinke za sistemske aplikacije.
- Moguće je pronaći druge komponente kao što su sertifikati u `/System/Library/Keychains/*`
- U **iOS** postoji samo jedan **Keychain** smešten u `/private/var/Keychains/`. Ova fascikla takođe sadrži baze podataka za `TrustStore`, sertifikacione autoritete (`caissuercache`) i OSCP unose (`ocspache`).
- Aplikacije će biti ograničene u keychain-u samo na njihovu privatnu oblast na osnovu njihovog identifikatora aplikacije.

### Pristup lozinkama Keychain-a

Ove datoteke, iako nemaju inherentnu zaštitu i mogu se **preuzeti**, su enkriptovane i zahtevaju **korisničku lozinku u čistom tekstu za dekripciju**. Alat kao što je [**Chainbreaker**](https://github.com/n0fate/chainbreaker) može se koristiti za dekripciju.

## Zaštita unosa u Keychain-u

### ACLs

Svaki unos u keychain-u je regulisan **Access Control Lists (ACLs)** koje određuju ko može da izvrši različite radnje na unosu u keychain-u, uključujući:

- **ACLAuhtorizationExportClear**: Omogućava nosiocu da dobije čist tekst tajne.
- **ACLAuhtorizationExportWrapped**: Omogućava nosiocu da dobije čist tekst enkriptovan drugom datom lozinkom.
- **ACLAuhtorizationAny**: Omogućava nosiocu da izvrši bilo koju radnju.

ACLs su dodatno praćene **listom pouzdanih aplikacija** koje mogu izvršiti ove radnje bez traženja dozvole. Ovo može biti:

- **N`il`** (nije potrebna autorizacija, **svi su pouzdani**)
- **prazna** lista (**niko** nije pouzdan)
- **Lista** specifičnih **aplikacija**.

Takođe, unos može sadržati ključ **`ACLAuthorizationPartitionID`,** koji se koristi za identifikaciju **teamid, apple,** i **cdhash.**

- Ako je **teamid** specificiran, tada da bi se **pristupilo** vrednosti unosa **bez** **upita** aplikacija koja se koristi mora imati **isti teamid**.
- Ako je **apple** specificiran, tada aplikacija mora biti **potpisana** od strane **Apple**.
- Ako je **cdhash** naznačen, tada **aplikacija** mora imati specifični **cdhash**.

### Kreiranje unosa u Keychain-u

Kada se **novi** **unos** kreira koristeći **`Keychain Access.app`**, sledeća pravila se primenjuju:

- Sve aplikacije mogu enkriptovati.
- **Nijedna aplikacija** ne može izvesti/dekripovati (bez traženja dozvole korisnika).
- Sve aplikacije mogu videti proveru integriteta.
- Nijedna aplikacija ne može menjati ACLs.
- **partitionID** je postavljen na **`apple`**.

Kada **aplikacija kreira unos u keychain-u**, pravila su malo drugačija:

- Sve aplikacije mogu enkriptovati.
- Samo **aplikacija koja kreira** (ili bilo koje druge aplikacije koje su eksplicitno dodate) mogu izvesti/dekripovati (bez traženja dozvole korisnika).
- Sve aplikacije mogu videti proveru integriteta.
- Nijedna aplikacija ne može menjati ACLs.
- **partitionID** je postavljen na **`teamid:[teamID here]`**.

## Pristupanje Keychain-u

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
> **Enumeracija i dumpovanje** tajni koje **neće generisati prompt** može se uraditi pomoću alata [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Ostali API krajnji tačke mogu se naći u [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) izvorni kod.

Lista i dobijanje **informacija** o svakom unosu u keychain koristeći **Security Framework** ili možete proveriti Apple-ov open source cli alat [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Neki primeri API-ja:

- API **`SecItemCopyMatching`** daje informacije o svakom unosu i postoje neki atributi koje možete postaviti prilikom korišćenja:
- **`kSecReturnData`**: Ako je tačno, pokušaće da dekriptuje podatke (postavite na netačno da biste izbegli potencijalne iskačuće prozore)
- **`kSecReturnRef`**: Takođe dobijate referencu na stavku keychain-a (postavite na tačno u slučaju da kasnije vidite da možete dekriptovati bez iskačućeg prozora)
- **`kSecReturnAttributes`**: Dobijate metapodatke o unosima
- **`kSecMatchLimit`**: Koliko rezultata da se vrati
- **`kSecClass`**: Koja vrsta unosa u keychain

Dobijte **ACLs** svakog unosa:

- Sa API-jem **`SecAccessCopyACLList`** možete dobiti **ACL za stavku keychain-a**, i vratiće listu ACL-ova (kao što su `ACLAuhtorizationExportClear` i ostali prethodno pomenuti) gde svaka lista ima:
- Opis
- **Lista pouzdanih aplikacija**. Ovo može biti:
- Aplikacija: /Applications/Slack.app
- Binarni: /usr/libexec/airportd
- Grupa: group://AirPort

Izvezite podatke:

- API **`SecKeychainItemCopyContent`** dobija plaintext
- API **`SecItemExport`** izvozi ključeve i sertifikate, ali možda će biti potrebno postaviti lozinke za izvoz sadržaja šifrovanog

I ovo su **zahtevi** da biste mogli da **izvezete tajnu bez prompta**:

- Ako je **1+ pouzdana** aplikacija navedena:
- Potrebne su odgovarajuće **autorizacije** (**`Nil`**, ili biti **deo** dozvoljene liste aplikacija u autorizaciji za pristup tajnim informacijama)
- Potrebna je potpisna šifra koja se poklapa sa **PartitionID**
- Potrebna je potpisna šifra koja se poklapa sa jednom **pouzdanom aplikacijom** (ili biti član pravog KeychainAccessGroup)
- Ako su **sve aplikacije pouzdane**:
- Potrebne su odgovarajuće **autorizacije**
- Potrebna je potpisna šifra koja se poklapa sa **PartitionID**
- Ako **nema PartitionID**, onda ovo nije potrebno

> [!CAUTION]
> Stoga, ako postoji **1 aplikacija navedena**, potrebno je **ubaciti kod u tu aplikaciju**.
>
> Ako je **apple** naznačen u **partitionID**, možete mu pristupiti pomoću **`osascript`** tako da bilo šta što veruje svim aplikacijama sa apple u partitionID. **`Python`** se takođe može koristiti za ovo.

### Dva dodatna atributa

- **Nevidljivo**: To je boolean zastavica za **sakrivanje** unosa iz **UI** Keychain aplikacije
- **Opšte**: To je za čuvanje **metapodataka** (tako da nije ENKRYPTOVANO)
- Microsoft je čuvao u običnom tekstu sve osvežavajuće tokene za pristup osetljivim krajnjim tačkama.

## References

- [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
