# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Glavni Keychain-i

- **Korisnički Keychain** (`~/Library/Keychains/login.keychain-db`), koji se koristi za čuvanje **credentiala specifičnih za korisnika**, kao što su lozinke aplikacija, internet lozinke, sertifikati koje je kreirao korisnik, mrežne lozinke i javni/privatni ključevi koje je kreirao korisnik.
- **System Keychain** (`/Library/Keychains/System.keychain`), koji čuva **credentiale dostupne celom sistemu**, kao što su WiFi lozinke, sistemski root sertifikati, sistemski privatni ključevi i lozinke sistemskih aplikacija.<sup>[[1]](#references)</sup>
- Moguće je pronaći i druge komponente, kao što su sertifikati, u `/System/Library/Keychains/*`
- U **iOS-u** postoji samo jedan **Keychain**, koji se nalazi u `/private/var/Keychains/`. Ovaj folder takođe sadrži baze podataka za `TrustStore`, sertifikate sertifikacionih tela (`caissuercache`) i OSCP unose (`ocspache`).
- Aplikacije će u Keychain-u imati pristup samo svojoj privatnoj oblasti, na osnovu svog identifikatora aplikacije.

### Pristup Keychain-u lozinkom

Ovi fajlovi, iako nemaju ugrađenu zaštitu i mogu biti **downloadovani**, enkriptovani su i za njihovu dekripciju je potrebna **plaintext lozinka korisnika**. Za dekripciju se može koristiti alat kao što je [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Zaštite Keychain unosa

### ACL-ovi

Svaki unos u Keychain-u regulišu **Access Control Lists (ACLs)**, koje određuju ko može da izvrši različite radnje nad unosom u Keychain-u, uključujući:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Omogućava vlasniku da dobije plaintext tajne.
- **ACLAuthorizationExportWrapped**: Omogućava vlasniku da dobije plaintext enkriptovan drugom prosleđenom lozinkom.
- **ACLAuthorizationAny**: Omogućava vlasniku da izvrši bilo koju radnju.

ACL-ovi su dodatno praćeni **listom pouzdanih aplikacija** koje mogu izvršiti ove radnje bez prikazivanja prompta. To može biti:<sup>[[1]](#references)</sup>

- **N`il`** (nije potrebna autorizacija, **svima se veruje**)
- Prazna **lista** (**nikome** se ne veruje)
- **Lista** konkretnih **aplikacija**.

Pored toga, unos može sadržati ključ **`ACLAuthorizationPartitionID`,** koji se koristi za identifikaciju vrednosti **teamid, apple** i **cdhash**.<sup>[[1]](#references)</sup>

- Ako je naveden **teamid**, aplikacija mora imati **isti teamid** da bi **pristupila** vrednosti **unosa** bez **prompt-a**.
- Ako je naveden **apple**, aplikacija mora biti **potpisana** od strane kompanije **Apple**.
- Ako je naveden **cdhash**, **aplikacija** mora imati konkretan **cdhash**.

### Kreiranje unosa u Keychain-u

Kada se kreira **novi** **unos** pomoću **`Keychain Access.app`**, primenjuju se sledeća pravila:<sup>[[1]](#references)</sup>

- Sve aplikacije mogu da enkriptuju.
- **Nijedna aplikacija** ne može da izvrši export/dekripciju (bez prompt-a korisniku).
- Sve aplikacije mogu da vide proveru integriteta.
- Nijedna aplikacija ne može da menja ACL-ove.
- **partitionID** je postavljen na **`apple`**.

Kada **aplikacija kreira unos u Keychain-u**, pravila su malo drugačija:<sup>[[1]](#references)</sup>

- Sve aplikacije mogu da enkriptuju.
- Samo **aplikacija koja je kreirala unos** (ili druge aplikacije koje su izričito dodate) može da izvrši export/dekripciju (bez prompt-a korisniku).
- Sve aplikacije mogu da vide proveru integriteta.
- Nijedna aplikacija ne može da menja ACL-ove.
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### API-jevi

> [!TIP]
> **enumeration and dumping** tajnih podataka iz **keychain-a** koji **neće generisati prompt** može se obaviti pomoću alata [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Ostali API endpoint-i mogu se pronaći u izvornom kodu [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Izlistajte i pribavite **informacije** o svakom unosu u keychain-u koristeći **Security Framework**, ili možete proveriti i Apple-ov open source CLI alat [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Neki primeri API-ja:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** pruža informacije o svakom unosu, a pri njegovom korišćenju možete podesiti neke atribute:
- **`kSecReturnData`**: Ako je true, pokušaće da dešifruje podatke (postavite na false da biste izbegli potencijalne pop-up prozore)
- **`kSecReturnRef`**: Takođe pribavlja referencu na keychain stavku (postavite na true ako kasnije utvrdite da je možete dešifrovati bez pop-up prozora)
- **`kSecReturnAttributes`**: Pribavlja metadata podatke o unosima
- **`kSecMatchLimit`**: Koliko rezultata treba vratiti
- **`kSecClass`**: Koja je vrsta keychain unosa

Pribavite **ACL-ove** svakog unosa:<sup>[[1]](#references)</sup>

- Pomoću API-ja **`SecAccessCopyACLList`** možete pribaviti **ACL za keychain stavku**. On vraća listu ACL-ova (kao što su `ACLAuthorizationExportClear` i ostali prethodno pomenuti), pri čemu svaki unos ima:
- Description
- **Trusted Application List**. To može biti:
- Aplikacija: /Applications/Slack.app
- Binarni fajl: /usr/libexec/airportd
- Grupa: group://AirPort

Eksportujte podatke:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** pribavlja plaintext
- API **`SecItemExport`** eksportuje ključeve i sertifikate, ali ćete možda morati da postavite lozinke kako biste eksportovali sadržaj u šifrovanom obliku

A ovo su **zahtevi** da biste mogli da **eksportujete tajni podatak bez prompt-a**:<sup>[[1]](#references)</sup>

- Ako je navedena **1+ trusted** aplikacija:
- Potrebne su odgovarajuće **autorizacije** (**`Nil`** ili morate biti **deo** dozvoljene liste aplikacija u autorizaciji za pristup tajnim informacijama)
- Code signature mora odgovarati **PartitionID** vrednosti
- Code signature mora odgovarati code signature-u jedne **trusted app** (ili morate biti član odgovarajućeg KeychainAccessGroup-a)
- Ako su **sve aplikacije trusted**:
- Potrebne su odgovarajuće **autorizacije**
- Code signature mora odgovarati **PartitionID** vrednosti
- Ako nema **PartitionID** vrednosti, ovo nije potrebno

> [!CAUTION]
> Dakle, ako je **1 aplikacija navedena**, potrebno je da **injektujete code u tu aplikaciju**.
>
> Ako je **apple** naveden u **partitionID** vrednosti, možete mu pristupiti pomoću **`osascript`**, tako da se ovo odnosi na sve što veruje svim aplikacijama koje imaju apple u partitionID vrednosti. Za ovo se može koristiti i **`Python`**.

### Dodatna dva atributa

- **Invisible**: Ovo je boolean zastavica za **skrivanje** unosa iz **UI** Keychain aplikacije<sup>[[1]](#references)</sup>
- **General**: Koristi se za čuvanje **metadata podataka** (dakle, NIJE ŠIFROVANO)<sup>[[1]](#references)</sup>
- Microsoft je čuvao sve refresh tokene u plaintext obliku za pristup osetljivom endpoint-u.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Obijanje macOS Keychain-a" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
