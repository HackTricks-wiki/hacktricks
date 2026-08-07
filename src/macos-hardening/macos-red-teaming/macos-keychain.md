# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Glavni Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), koji se koristi za čuvanje **user-specific credentials** kao što su lozinke aplikacija, internet lozinke, certificates koje je generisao korisnik, network lozinke i javni/privatni ključevi koje je generisao korisnik.
- **System Keychain** (`/Library/Keychains/System.keychain`), koji čuva **system-wide credentials** kao što su WiFi lozinke, system root certificates, system private keys i system application lozinke.<sup>[[1]](#references)</sup>
- Moguće je pronaći i druge komponente, kao što su certificates, u `/System/Library/Keychains/*`
- U **iOS-u** postoji samo jedan **Keychain**, koji se nalazi u `/private/var/Keychains/`. Ovaj folder takođe sadrži baze podataka za `TrustStore`, certificate authorities (`caissuercache`) i OSCP entries (`ocspache`).
- Apps imaju pristup samo svom privatnom području u keychain-u, na osnovu svog application identifier-a.

### Password Keychain Access

Ovi fajlovi, iako nemaju inherentnu zaštitu i mogu biti **downloaded**, encrypted su i za njihovu decryption potrebna je **user's plaintext password**. Alat kao što je [**Chainbreaker**](https://github.com/n0fate/chainbreaker) može se koristiti za decryption.<sup>[[1]](#references)</sup>

## Zaštita Keychain Entries

### ACLs

Svaki entry u keychain-u je regulisan pomoću **Access Control Lists (ACLs)**, koje određuju ko može da izvršava različite radnje nad keychain entry-jem, uključujući:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Omogućava holder-u da dobije clear text secret-a.
- **ACLAuhtorizationExportWrapped**: Omogućava holder-u da dobije clear text encrypted pomoću druge navedene lozinke.
- **ACLAuhtorizationAny**: Omogućava holder-u da izvršava bilo koju radnju.

ACLs su dodatno praćeni **listom trusted applications** koje mogu da izvršavaju ove radnje bez prompt-a. To može biti:<sup>[[1]](#references)</sup>

- **N`il`** (authorization nije potrebna, **everyone is trusted**)
- **Prazna** lista (**nobody** je trusted)
- **Lista** specifičnih **applications**.

Entry takođe može sadržati key **`ACLAuthorizationPartitionID`,** koji se koristi za identifikaciju vrednosti **teamid, apple** i **cdhash**.<sup>[[1]](#references)</sup>

- Ako je naveden **teamid**, onda, da bi **access entry** vrednosti bio moguć **without** **prompt-a**, korišćena aplikacija mora imati **isti teamid**.
- Ako je navedeno **apple**, aplikacija mora biti **signed** od strane **Apple-a**.
- Ako je naveden **cdhash**, **app** mora imati konkretan **cdhash**.

### Kreiranje Keychain Entry-ja

Kada se kreira **novi** **entry** pomoću **`Keychain Access.app`**, primenjuju se sledeća pravila:<sup>[[1]](#references)</sup>

- Sve apps mogu da encrypt-uju.
- **No apps** ne mogu da export-uju/decrypt-uju (bez prompt-a korisniku).
- Sve apps mogu da vide integrity check.
- Nijedna app ne može da menja ACLs.
- **partitionID** je podešen na **`apple`**.

Kada **application kreira entry u keychain-u**, pravila su malo drugačija:<sup>[[1]](#references)</sup>

- Sve apps mogu da encrypt-uju.
- Samo **creating application** (ili bilo koja druga eksplicitno dodata app) može da export-uje/decrypt-uje (bez prompt-a korisniku).
- Sve apps mogu da vide integrity check.
- Nijedna app ne može da menja ACLs.
- **partitionID** je podešen na **`teamid:[teamID here]`**.

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
> **Enumerisanje i dumpovanje** secrets iz **keychain-a** koje **neće generisati prompt** može se obaviti pomoću alata [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Ostale API endpoint-e možete pronaći u izvornom kodu [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Izlistajte i preuzmite **info** o svakom keychain unosu koristeći **Security Framework**, ili možete proveriti i Apple-ov open source CLI alat [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Neki primeri API-ja:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** pruža informacije o svakom unosu, a pri njegovom korišćenju možete podesiti neke atribute:
- **`kSecReturnData`**: Ako je true, pokušaće da dešifruje podatke (postavite na false da biste izbegli potencijalne pop-up prozore)
- **`kSecReturnRef`**: Takođe preuzima referencu na keychain stavku (postavite na true ako kasnije utvrdite da možete da je dešifrujete bez pop-up prozora)
- **`kSecReturnAttributes`**: Preuzima metadata o unosima
- **`kSecMatchLimit`**: Koliko rezultata treba vratiti
- **`kSecClass`**: Koje vrste je keychain unos

Preuzmite **ACL-ove** svakog unosa:<sup>[[1]](#references)</sup>

- Pomoću API-ja **`SecAccessCopyACLList`** možete preuzeti **ACL za keychain stavku**, a on će vratiti listu ACL-ova (kao što su `ACLAuhtorizationExportClear` i ostali prethodno pomenuti), gde svaka lista sadrži:
- Opis
- **Trusted Application List**. Ovo može biti:
- Aplikacija: /Applications/Slack.app
- Binarni fajl: /usr/libexec/airportd
- Grupa: group://AirPort

Eksportujte podatke:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** preuzima plaintext
- API **`SecItemExport`** eksportuje ključeve i sertifikate, ali će možda biti potrebno postaviti lozinke za eksportovanje sadržaja u šifrovanom obliku

A ovo su **uslovi** za mogućnost **eksportovanja secreta bez prompta**:<sup>[[1]](#references)</sup>

- Ako je navedeno 1+ trusted aplikacija:
- Potrebne su odgovarajuće **authorizations** (**`Nil`** ili morate biti **deo** dozvoljene liste aplikacija u authorization-u za pristup informacijama secreta)
- Code signature mora da odgovara **PartitionID** vrednosti
- Code signature mora da odgovara onoj kod jedne **trusted aplikacije** (ili morate biti član odgovarajućeg KeychainAccessGroup-a)
- Ako su **sve aplikacije trusted**:
- Potrebne su odgovarajuće **authorizations**
- Code signature mora da odgovara **PartitionID** vrednosti
- Ako nema **PartitionID** vrednosti, ovo nije potrebno

> [!CAUTION]
> Stoga, ako je navedena **1 aplikacija**, potrebno je **ubaciti kod u tu aplikaciju**.
>
> Ako je **apple** naveden u **partitionID** vrednosti, možete mu pristupiti pomoću **`osascript`**, pa je to moguće za sve što veruje svim aplikacijama koje imaju apple u partitionID vrednosti. Za ovo se može koristiti i **`Python`**.

### Dodatna dva atributa

- **Invisible**: Boolean flag za **sakrivanje** unosa iz Keychain aplikacije u **UI-ju**<sup>[[1]](#references)</sup>
- **General**: Služi za čuvanje **metadata-e** (dakle, NIJE ŠIFROVANO)<sup>[[1]](#references)</sup>
- Microsoft je u plain text-u čuvao sve refresh tokene za pristup osetljivom endpoint-u.<sup>[[1]](#references)</sup>

## Reference

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
