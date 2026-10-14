# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Glavni Keychain-i

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), koji se koristi za čuvanje **akreditiva specifičnih za korisnika**, kao što su lozinke aplikacija, internet lozinke, sertifikati koje je generisao korisnik, mrežne lozinke i javni/privatni ključevi koje je generisao korisnik.
- **System Keychain** (`/Library/Keychains/System.keychain`), u kojem se čuvaju **akreditivi na nivou sistema**, kao što su WiFi lozinke, sistemski root sertifikati, privatni ključevi sistema i lozinke sistemskih aplikacija.<sup>[[1]](#references)</sup>
  - Moguće je pronaći i druge komponente, poput sertifikata, u `/System/Library/Keychains/*`
- U **iOS-u** postoji samo jedan **Keychain**, koji se nalazi u `/private/var/Keychains/`. Ovaj folder takođe sadrži baze podataka za `TrustStore`, sertifikaciona tela (`caissuercache`) i OSCP unose (`ocspache`).
  - Aplikacije će u Keychain-u imati pristup samo svojoj privatnoj oblasti, na osnovu identifikatora aplikacije.

### Pristup Keychain-u pomoću lozinke

Ove datoteke nemaju ugrađenu zaštitu i mogu da se **preuzmu**, ali su šifrovane i za njihovo dešifrovanje potrebna je **lozinka korisnika u otvorenom tekstu**. Za dešifrovanje se može koristiti alat kao što je [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Zaštita unosa u Keychain-u

### ACL-ovi

Svaki unos u Keychain-u regulišu **Access Control Lists (ACLs)**, koje određuju ko može da izvrši različite radnje nad unosom, uključujući:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Omogućava imaocu da dobije tajnu u otvorenom tekstu.
- **`kSecACLAuthorizationExportWrapped`**: Omogućava imaocu da dobije tajnu u otvorenom tekstu, šifrovanu drugom dostavljenom lozinkom.
- **`kSecACLAuthorizationAny`**: Omogućava imaocu da izvrši bilo koju radnju.

ACL-ove dodatno prati **lista pouzdanih aplikacija** koje mogu da izvrše ove radnje bez upita za potvrdu. Lista može biti:<sup>[[1]](#references)</sup>

- **N`il`** (autorizacija nije potrebna, **svima se veruje**)
- **Prazna** lista (**nikome** se ne veruje)
- **Lista** određenih **aplikacija**.

Unos može da sadrži i ključ **`kSecACLAuthorizationPartitionID`,** koji se koristi za identifikaciju vrednosti **teamid, apple** i **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Ako je naveden **teamid**, aplikacija mora da ima **isti teamid** da bi **pristupila vrednosti unosa** bez **upita za potvrdu**.
- Ako je naveden **apple**, aplikaciju mora da je **potpisao** **Apple**.
- Ako je naveden **cdhash**, **aplikacija** mora da ima određeni **cdhash**.

### Kreiranje unosa u Keychain-u

Kada se pomoću **`Keychain Access.app`** kreira **novi** **unos**, važe sledeća pravila:<sup>[[1]](#references)</sup>

- Sve aplikacije mogu da šifruju.
- **Nijedna aplikacija** ne može da izveze/dešifruje (bez upita za potvrdu korisniku).
- Sve aplikacije mogu da vide proveru integriteta.
- Nijedna aplikacija ne može da menja ACL-ove.
- **partitionID** se postavlja na **`apple`**.

Kada **aplikacija kreira unos u Keychain-u**, pravila su malo drugačija:<sup>[[1]](#references)</sup>

- Sve aplikacije mogu da šifruju.
- Samo **aplikacija koja je kreirala unos** (ili bilo koja druga eksplicitno dodata aplikacija) može da izveze/dešifruje (bez upita za potvrdu korisniku).
- Sve aplikacije mogu da vide proveru integriteta.
- Nijedna aplikacija ne može da menja ACL-ove.
- **partitionID** se postavlja na **`teamid:[teamID here]`**.

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
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` postavlja partition list stavke, dok `-k` prosleđuje trenutnu Keychain lozinku potrebnu za tu promenu; zastavica za unos lozinke je zastarela.<sup>[[4]](#references)</sup> Uspešno ažuriranje ne dokazuje da će kasnije čitanje proći bez upita: jedan posmatrani, onemogućeni prototip ipak je pokrenuo upit za potvrdu kada je preko `Security.framework` zatražio stavku. Podudarni ID particije samo je jedan deo ACL provera i provera pouzdanih aplikacija opisanih iznad, zato proverite stvarnu putanju čitanja.<sup>[[3]](#references)</sup>

### API-ji

> [!TIP]
> **Enumerisanje i dumpovanje** tajni iz keychain-a koje **neće pokrenuti upit** može se obaviti pomoću alata [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Ostale API krajnje tačke možete pronaći u izvornom kodu [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Izlistajte i dobijte **informacije** o svakom unosu u keychain-u pomoću **Security Framework-a** ili možete proveriti i Apple-ov CLI alat otvorenog koda [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Neki primeri API-ja:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** daje informacije o svakom unosu i ima nekoliko atributa koje možete da podesite pri njegovom korišćenju:
  - **`kSecReturnData`**: Ako je true, pokušaće da dešifruje podatke (postavite na false da biste izbegli moguće iskačuće prozore)
  - **`kSecReturnRef`**: Dobijte i referencu na stavku keychain-a (postavite na true ako kasnije utvrdite da možete da je dešifrujete bez iskačućeg prozora)
  - **`kSecReturnAttributes`**: Dobijte metapodatke o unosima
  - **`kSecMatchLimit`**: Koliko rezultata treba vratiti
  - **`kSecClass`**: Vrsta unosa u keychain

Dobijte **ACL-ove** za svaki unos:<sup>[[1]](#references)</sup>

- Pomoću API-ja **`SecAccessCopyACLList`** možete dobiti **ACL za stavku keychain-a**. Vraća listu ACL-ova (kao što su `kSecACLAuthorizationExportClear` i drugi prethodno pomenuti), pri čemu svaki unos sadrži:<sup>[[1]](#references)[[2]](#references)</sup>
  - Opis
  - **Lista pouzdanih aplikacija**. To može biti:
    - Aplikacija: /Applications/Slack.app
    - Binarna datoteka: /usr/libexec/airportd
    - Grupa: group://AirPort

Izvezite podatke:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** pribavlja otvoreni tekst
- API **`SecItemExport`** izvozi ključeve i sertifikate, ali je možda potrebno da postavite lozinke za izvoz šifrovanog sadržaja

A ovo su **uslovi** za **izvoz tajne bez upita**:<sup>[[1]](#references)</sup>

- Ako je navedena najmanje jedna (**1+**) pouzdana aplikacija:
  - Potrebna su odgovarajuća **ovlašćenja** (**`Nil`** ili da budete **deo** dozvoljene liste aplikacija u ovlašćenju za pristup poverljivim informacijama)
  - Potpis koda mora da odgovara vrednosti **PartitionID**
  - Potpis koda mora da odgovara potpisu jedne **pouzdane aplikacije** (ili da budete član odgovarajućeg KeychainAccessGroup-a)
- Ako su **sve aplikacije pouzdane**:
  - Potrebna su odgovarajuća **ovlašćenja**
  - Potpis koda mora da odgovara vrednosti **PartitionID**
    - Ako nema **PartitionID**, ovo nije potrebno

> [!CAUTION]
> Dakle, ako je navedena **1 aplikacija**, potrebno je da **ubrizgate kod u tu aplikaciju**.
>
> Ako je **apple** naveden u **partitionID**, možete mu pristupiti pomoću **`osascript`**, pa se to odnosi na sve aplikacije kojima se veruje kada je apple naveden u partitionID-u. Za ovo se može koristiti i **`Python`**.

### Dva dodatna atributa

- **Invisible**: Bulova zastavica za **sakrivanje** unosa u Keychain aplikaciji **UI**-ja<sup>[[1]](#references)</sup>
- **General**: Služi za čuvanje **metapodataka** (dakle, NIJE ŠIFROVAN)<sup>[[1]](#references)</sup>
  - Microsoft je čuvao sve refresh tokene u otvorenom tekstu radi pristupa osetljivoj krajnjoj tački.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: „Obijanje macOS Keychain-a“ - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Nova verzija MacSync macOS kradljivca cilja ljubitelje kriptovaluta i programere](https://securelist.com/macsync-new-version/121383/)
- [4] [Ogledna stranica man uputstva za Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
