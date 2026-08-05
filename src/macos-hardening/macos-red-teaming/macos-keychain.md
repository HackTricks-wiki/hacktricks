# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Glavni Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`) koristi se za čuvanje **user-specific credentials**, kao što su lozinke aplikacija, internet lozinke, korisnički generisani sertifikati, mrežne lozinke i korisnički generisani javni/privatni ključevi.
- **System Keychain** (`/Library/Keychains/System.keychain`) čuva **system-wide credentials**, kao što su WiFi lozinke, sistemski root sertifikati, sistemski privatni ključevi i lozinke sistemskih aplikacija.<sup>[[1]](#references)</sup>
- Moguće je pronaći i druge komponente, kao što su sertifikati, u `/System/Library/Keychains/*`
- U **iOS-u** postoji samo jedan **Keychain**, koji se nalazi u `/private/var/Keychains/`. Ovaj folder takođe sadrži baze podataka za `TrustStore`, autoritete sertifikata (`caissuercache`) i OSCP entries (`ocspache`).
- Aplikacije će imati pristup samo svom privatnom području u keychain-u, na osnovu svog application identifier-a.

### Pristup Password Keychain-u

Ove datoteke, iako nemaju inherentnu zaštitu i mogu biti **downloaded**, šifrovane su i za njihovu dekripciju je potrebna **user's plaintext password**. Alat kao što je [**Chainbreaker**](https://github.com/n0fate/chainbreaker) može se koristiti za dekripciju.<sup>[[1]](#references)</sup>

## Zaštite Keychain Entries

### ACLs

Svaki entry u keychain-u podleže pravilima **Access Control Lists (ACLs)**, koja određuju ko može da izvršava različite radnje nad keychain entry-jem, uključujući:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Omogućava holder-u da dobije clear text tajne.
- **ACLAuhtorizationExportWrapped**: Omogućava holder-u da dobije clear text šifrovan drugom prosleđenom lozinkom.
- **ACLAuhtorizationAny**: Omogućava holder-u da izvršava bilo koju radnju.

ACLs su dodatno praćene **listom trusted applications** koje mogu da izvršavaju ove radnje bez prikazivanja prompt-a. To može biti:<sup>[[1]](#references)</sup>

- **N`il`** (authorization nije potrebna, **everyone is trusted**)
- **Prazna** lista (**nobody** je trusted)
- **Lista** specifičnih **applications**.

Entry takođe može sadržati ključ **`ACLAuthorizationPartitionID`,** koji se koristi za identifikaciju vrednosti **teamid, apple** i **cdhash.**<sup>[[1]](#references)</sup>

- Ako je **teamid** naveden, da bi se vrednosti **entry-ja** pristupilo **without** **prompt-a**, korišćena aplikacija mora imati isti **teamid**.
- Ako je naveden **apple**, aplikacija mora biti **signed** od strane kompanije **Apple**.
- Ako je naveden **cdhash**, **app** mora imati navedeni **cdhash**.

### Kreiranje Keychain Entry-ja

Kada se kreira **new** **entry** pomoću **`Keychain Access.app`**, primenjuju se sledeća pravila:<sup>[[1]](#references)</sup>

- Sve aplikacije mogu da šifruju.
- **No apps** ne mogu da exportuju/dešifruju (bez prikazivanja prompt-a korisniku).
- Sve aplikacije mogu da vide proveru integriteta.
- Nijedna aplikacija ne može da menja ACLs.
- **partitionID** je postavljen na **`apple`**.

Kada **application** kreira entry u keychain-u, pravila su malo drugačija:<sup>[[1]](#references)</sup>

- Sve aplikacije mogu da šifruju.
- Samo **creating application** (ili druge aplikacije koje su eksplicitno dodate) mogu da exportuju/dešifruju (bez prikazivanja prompt-a korisniku).
- Sve aplikacije mogu da vide proveru integriteta.
- Nijedna aplikacija ne može da menja ACLs.
- **partitionID** je postavljen na **`teamid:[teamID here]`**.

## Pristup Keychain-u

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
> **Enumeracija i dumpovanje** tajni iz **keychain-a** koji **neće generisati prompt** mogu se obaviti pomoću alata [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Ostali API endpoints mogu se pronaći u izvornom kodu [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Izlistajte i dobijte **informacije** o svakom unosu u keychain koristeći **Security Framework**, ili možete proveriti i Apple-ov open source CLI alat [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Neki primeri API-ja:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** daje informacije o svakom unosu i postoje neki atributi koje možete podesiti prilikom njegovog korišćenja:
- **`kSecReturnData`**: Ako je true, pokušaće da dešifruje podatke (postavite na false da biste izbegli potencijalne pop-up prozore)
- **`kSecReturnRef`**: Dobijte i referencu na stavku u keychain-u (postavite na true ako kasnije utvrdite da možete da je dešifrujete bez pop-up prozora)
- **`kSecReturnAttributes`**: Dobijte metadata o unosima
- **`kSecMatchLimit`**: Koliko rezultata treba vratiti
- **`kSecClass`**: Koje vrste je unos u keychain-u

Dobijte **ACL-ove** svakog unosa:<sup>[[1]](#references)</sup>

- Pomoću API-ja **`SecAccessCopyACLList`** možete dobiti **ACL za stavku u keychain-u**, a on će vratiti listu ACL-ova (kao što su `ACLAuhtorizationExportClear` i drugi prethodno pomenuti), gde svaka lista sadrži:
- Opis
- **Trusted Application List**. Ovo može biti:
- Aplikacija: /Applications/Slack.app
- Binarni fajl: /usr/libexec/airportd
- Grupa: group://AirPort

Eksportujte podatke:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** dobija plaintext
- API **`SecItemExport`** eksportuje ključeve i sertifikate, ali možda ćete morati da postavite lozinke kako biste eksportovali sadržaj u šifrovanom obliku

A ovo su **zahtevi** da biste mogli da **eksportujete tajnu bez prompta**:<sup>[[1]](#references)</sup>

- Ako je navedena 1+ trusted aplikacija:
- Potrebne su odgovarajuće **autorizacije** (**`Nil`** ili morate biti **deo** dozvoljene liste aplikacija u autorizaciji za pristup informacijama o tajni)
- Potrebno je da code signature odgovara **PartitionID** vrednosti
- Potrebno je da code signature odgovara code signature-u jedne **trusted aplikacije** (ili morate biti član odgovarajućeg KeychainAccessGroup-a)
- Ako su **sve aplikacije trusted**:
- Potrebne su odgovarajuće **autorizacije**
- Potrebno je da code signature odgovara **PartitionID** vrednosti
- Ako nema **PartitionID** vrednosti, ovo nije potrebno

> [!CAUTION]
> Stoga, ako je navedena **1 aplikacija**, potrebno je **ubaciti code u tu aplikaciju**.
>
> Ako je **apple** naveden u vrednosti **partitionID**, možete mu pristupiti pomoću **`osascript`**; ovo važi za sve što veruje svim aplikacijama sa vrednošću apple u partitionID-u. I **`Python`** se može koristiti za ovo.

### Dodatna dva atributa

- **Invisible**: Boolean flag za **skrivanje** unosa iz **UI** Keychain aplikacije<sup>[[1]](#references)</sup>
- **General**: Služi za čuvanje **metadata** (dakle, NIJE ŠIFROVANO)<sup>[[1]](#references)</sup>
- Microsoft je čuvao sve refresh tokene u plaintext-u za pristup osetljivom endpoint-u.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
