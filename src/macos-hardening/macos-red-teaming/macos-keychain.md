# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Glavni Keychain-i

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), koji se koristi za čuvanje **user-specific credentials** kao što su lozinke aplikacija, internet lozinke, user-generated certificates, network lozinke i user-generated public/private keys.
- **System Keychain** (`/Library/Keychains/System.keychain`), koji čuva **system-wide credentials** kao što su WiFi lozinke, system root certificates, system private keys i system application passwords.<sup>[1]</sup>
- Moguće je pronaći i druge komponente, kao što su certificates, u `/System/Library/Keychains/*`
- U **iOS-u** postoji samo jedan **Keychain**, koji se nalazi u `/private/var/Keychains/`. Ovaj folder takođe sadrži baze podataka za `TrustStore`, certificate authorities (`caissuercache`) i OSCP entries (`ocspache`).
- Apps će u Keychain-u imati pristup samo svom privatnom području, na osnovu svog application identifier-a.

### Password Keychain Access

Ovi fajlovi, iako nemaju inherentnu zaštitu i mogu biti **downloaded**, encrypted su i za njihovu decryption neophodna je **user's plaintext password**. Za decryption se može koristiti alat kao što je [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[1]</sup>

## Zaštita Keychain Entries

### ACLs

Svaki entry u Keychain-u je kontrolisan pomoću **Access Control Lists (ACLs)**, koje određuju ko može izvršavati različite akcije nad Keychain entry-jem, uključujući:<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: Omogućava holder-u da dobije clear text secret-a.
- **ACLAuhtorizationExportWrapped**: Omogućava holder-u da dobije clear text encrypted pomoću druge prosleđene lozinke.
- **ACLAuhtorizationAny**: Omogućava holder-u izvršavanje bilo koje akcije.

ACLs su dodatno praćene **listom trusted applications** koje mogu izvršavati ove akcije bez prompt-a. To može biti:<sup>[1]</sup>

- **N`il`** (authorization nije potrebna, **everyone is trusted**)
- Prazna lista (**nobody** je trusted)
- **Lista** specifičnih **applications**.

Entry takođe može sadržati key **`ACLAuthorizationPartitionID`,** koji se koristi za identifikaciju vrednosti **teamid, apple** i **cdhash**.<sup>[1]</sup>

- Ako je **teamid** naveden, da bi se **access**-ovala vrednost entry-ja **bez** **prompt-a**, korišćena aplikacija mora imati **isti teamid**.
- Ako je naveden **apple**, aplikacija mora biti **signed** od strane **Apple-a**.
- Ako je naveden **cdhash**, **app** mora imati konkretan **cdhash**.

### Kreiranje Keychain Entry-ja

Kada se kreira **novi** **entry** pomoću **`Keychain Access.app`**, primenjuju se sledeća pravila:<sup>[1]</sup>

- Sve apps mogu da rade encryption.
- **Nijedna app** ne može da izvršava export/decryption (bez prompt-a user-u).
- Sve apps mogu da vide integrity check.
- Nijedna app ne može da menja ACLs.
- **partitionID** je podešen na **`apple`**.

Kada **application** kreira entry u Keychain-u, pravila su malo drugačija:<sup>[1]</sup>

- Sve apps mogu da rade encryption.
- Samo **application koja je kreirala entry** (ili bilo koje druge apps koje su eksplicitno dodate) može da izvršava export/decryption (bez prompt-a user-u).
- Sve apps mogu da vide integrity check.
- Nijedna app ne može da menja ACLs.
- **partitionID** je podešen na **`teamid:[teamID here]`**.

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
> Ostali API endpointi mogu se pronaći u izvornom kodu [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Izlistajte i preuzmite **info** o svakom unosu u keychain-u koristeći **Security Framework**, ili možete proveriti i Apple-ov open source cli alat [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Neki API primeri:<sup>[1]</sup>

- API **`SecItemCopyMatching`** daje info o svakom unosu, a prilikom njegovog korišćenja možete postaviti neke atribute:
- **`kSecReturnData`**: Ako je true, pokušaće da dešifruje podatke (postavite na false da biste izbegli potencijalne pop-up prozore)
- **`kSecReturnRef`**: Dobijate i referencu na keychain stavku (postavite na true ako kasnije utvrdite da možete da je dešifrujete bez pop-up prozora)
- **`kSecReturnAttributes`**: Dobijate metadata o unosima
- **`kSecMatchLimit`**: Koliko rezultata treba vratiti
- **`kSecClass`**: Koja je vrsta keychain unosa

Preuzmite **ACL-ove** svakog unosa:<sup>[1]</sup>

- Pomoću API-ja **`SecAccessCopyACLList`** možete dobiti **ACL za keychain stavku**, a on će vratiti listu ACL-ova (kao što su `ACLAuhtorizationExportClear` i ostali prethodno pomenuti), pri čemu svaka lista sadrži:
- Opis
- **Trusted Application List**. Ovo može biti:
- Aplikacija: /Applications/Slack.app
- Binarni fajl: /usr/libexec/airportd
- Grupa: group://AirPort

Eksportujte podatke:<sup>[1]</sup>

- API **`SecKeychainItemCopyContent`** preuzima plaintext
- API **`SecItemExport`** eksportuje ključeve i sertifikate, ali ćete možda morati da postavite lozinke kako biste eksportovali sadržaj enkriptovan

Ovo su **zahtevi** da biste mogli da **eksportujete tajnu bez prompt-a**:<sup>[1]</sup>

- Ako je navedena **1+ trusted** aplikacija:
- Potrebne su odgovarajuće **authorizations** (**`Nil`** ili morate biti **deo** dozvoljene liste aplikacija u authorization-u za pristup tajnim informacijama)
- Code signature mora odgovarati **PartitionID** vrednosti
- Code signature mora odgovarati potpisu jedne **trusted aplikacije** (ili morate biti član odgovarajućeg KeychainAccessGroup-a)
- Ako su **sve aplikacije trusted**:
- Potrebne su odgovarajuće **authorizations**
- Code signature mora odgovarati **PartitionID** vrednosti
- Ako nema **PartitionID** vrednosti, ovo nije potrebno

> [!CAUTION]
> Dakle, ako je navedena **1 aplikacija**, potrebno je **ubaciti code u tu aplikaciju**.
>
> Ako je **apple** naveden u **partitionID** vrednosti, možete mu pristupiti pomoću **`osascript`**, pa ovo važi za sve što veruje svim aplikacijama sa apple u partitionID vrednosti. Za ovo se može koristiti i **`Python`**.

### Dodatna dva atributa

- **Invisible**: Boolean flag za **skrivanje** unosa iz **UI** Keychain aplikacije<sup>[1]</sup>
- **General**: Služi za čuvanje **metadata** (dakle, NIJE ENCRYPTED)<sup>[1]</sup>
- Microsoft je čuvao sve refresh tokene u plain text-u za pristup osetljivom endpointu.<sup>[1]</sup>

## Reference

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
