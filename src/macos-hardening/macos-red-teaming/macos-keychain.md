# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Glavni Keychain-ovi

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), koji se koristi za čuvanje **akreditiva specifičnih za korisnika**, kao što su lozinke aplikacija, internet lozinke, korisnički generisani sertifikati, mrežne lozinke i korisnički generisani javni/privatni ključevi.
- **System Keychain** (`/Library/Keychains/System.keychain`), koji čuva **akreditive na nivou sistema**, kao što su WiFi lozinke, sistemski root sertifikati, privatni ključevi sistema i lozinke sistemskih aplikacija.<sup>[[1]](#references)</sup>
  - Moguće je pronaći druge komponente, poput sertifikata, u `/System/Library/Keychains/*`
- Keychain **data protection** za svakog korisnika prikazuje se kao **Local Items** ili **iCloud** u aplikaciji Keychain Access. Odvojen je od `login.keychain-db` i sadrži lokalne stavke i stavke koje se sinhronizuju; `security` je prvenstveno alat za file-based keychain-ove, pa kratak rezultat komande `dump-keychain` ne znači da ovde nema akreditiva.<sup>[[5]](#references)</sup>
- U **iOS-u** postoji samo jedan **Keychain**, koji se nalazi u `/private/var/Keychains/`. Ovaj direktorijum sadrži i baze podataka za `TrustStore`, certificate authorities (`caissuercache`) i OSCP stavke (`ocspache`).
  - Aplikacije imaju pristup samo svom privatnom delu keychain-a, na osnovu svog identifikatora aplikacije.

### Pristup lozinkama u Keychain-u

Kopirani **file-based** keychain nije u čistom tekstu. Za dešifrovanje njegovih zaštićenih stavki van mreže potrebna je lozinka keychain-a ili ekvivalentni ključni materijal; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) je namenjen ovom formatu.<sup>[[1]](#references)</sup> Ovo se razlikuje od čitanja uživo u otključanoj korisničkoj sesiji, gde kontrole pristupa stavkama mogu dozvoliti čitanje ili prikazati upit, bez ponovnog traženja lozinke za prijavu. Keychain data protection koristi drugačiji model zaštite i grupa pristupa.<sup>[[5]](#references)</sup>

## Zaštita Keychain stavki

### ACL-ovi file-based keychain-a

Pravila `SecAccess` ACL-a i partition-list pravila u nastavku opisuju **file-based** keychain-ove. Stavke keychain-a data protection umesto toga koriste grupe pristupa za code signing i opcione uslove `SecAccessControl`; na osnovu ispisa file-based ACL-a nemojte zaključivati o njihovoj dostupnosti.<sup>[[5]](#references)</sup>

Svaka stavka u file-based keychain-u podleže **Access Control Lists (ACLs)**, koje određuju ko može da izvršava različite radnje nad stavkom keychain-a, uključujući:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Omogućava vlasniku da dobije tajnu u čistom tekstu.
- **`kSecACLAuthorizationExportWrapped`**: Omogućava vlasniku da dobije tajnu u čistom tekstu, šifrovanu drugom navedenom lozinkom.
- **`kSecACLAuthorizationAny`**: Omogućava vlasniku da izvrši bilo koju radnju.

ACL-ove dodatno prati **lista pouzdanih aplikacija** koje mogu da izvrše ove radnje bez prikazivanja upita. To može biti:<sup>[[1]](#references)</sup>

- **N`il`** (nije potrebna autorizacija, **svima se veruje**)
- **Prazna** lista (**nikome** se ne veruje)
- **Lista** određenih **aplikacija**.

Stavka može da sadrži i ključ **`kSecACLAuthorizationPartitionID`,** koji se koristi za identifikovanje **teamid, apple** i **cdhash** vrednosti.<sup>[[1]](#references)[[2]](#references)</sup>

- Ako je naveden **teamid**, aplikacija mora da ima **isti teamid** da bi **pristupila vrednosti stavke** bez **upita**.
- Ako je naveden **apple**, aplikacija mora biti **potpisana** od strane **Apple-a**.
- Ako je naveden **cdhash**, **aplikacija** mora da ima određeni **cdhash**.

### Kreiranje stavke u file-based keychain-u

Prilikom kreiranja **nove** **stavke** pomoću **`Keychain Access.app`**, važe sledeća pravila:<sup>[[1]](#references)</sup>

- Sve aplikacije mogu da šifruju.
- **Nijedna aplikacija** ne može da izveze/dešifruje (bez upita korisniku).
- Sve aplikacije mogu da vide proveru integriteta.
- Nijedna aplikacija ne može da menja ACL-ove.
- **partitionID** je postavljen na **`apple`**.

Kada **aplikacija kreira stavku u keychain-u**, pravila su malo drugačija:<sup>[[1]](#references)</sup>

- Sve aplikacije mogu da šifruju.
- Samo **aplikacija koja je kreirala stavku** (ili druge izričito dodate aplikacije) može da izveze/dešifruje (bez upita korisniku).
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
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` postavlja partition list stavke, dok `-k` prosleđuje trenutnu Keychain lozinku potrebnu za tu izmenu; zastavica za unos lozinke je zastarela.<sup>[[4]](#references)</sup> Uspešna izmena ne dokazuje da će kasnije čitanje proći bez prompta: jedan posmatrani, onemogućeni prototip i dalje je prikazivao prompt za potvrdu kada je preko `Security.framework` upitom pristupao stavci. Podudaranje Partition ID-ja samo je jedan deo ACL i provera pouzdanih aplikacija opisanih iznad, zato proverite stvarni put čitanja.<sup>[[3]](#references)</sup>

### API-ji

> [!TIP]
> **Enumerisanje Keychain-a i izvlačenje** tajni koje **neće generisati prompt** moguće je obaviti alatom [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Druge API krajnje tačke možete pronaći u izvornom kodu [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Izlistajte i pribavite **informacije** o svakom Keychain unosu pomoću **Security Framework-a** ili pogledajte Apple-ov open source CLI alat [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Neki primeri API-ja:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** daje informacije o svakom unosu i omogućava podešavanje nekoliko atributa:
  - **`kSecReturnData`**: Ako je true, pokušaće da dešifruje podatke (postavite na false da biste izbegli moguće iskačuće prozore)
  - **`kSecReturnRef`**: Dobija referencu na objekat ključa, sertifikata ili identiteta; stavke lozinki nemaju takvu reprezentaciju objekta. Koristite `kSecReturnPersistentRef` da biste identifikovali lozinku za kasniji, ciljano usmeren upit.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Dobija metapodatke o unosima
  - **`kSecMatchLimit`**: Koliko rezultata treba vratiti
  - **`kSecClass`**: Koje vrste je Keychain unos

Dobijanje **ACL-ova** svakog unosa:<sup>[[1]](#references)</sup>

- Pomoću API-ja **`SecAccessCopyACLList`** možete dobiti **ACL Keychain stavke**. Vraća listu ACL-ova (kao što su `kSecACLAuthorizationExportClear` i ostali prethodno pomenuti), pri čemu svaki unos sadrži:<sup>[[1]](#references)[[2]](#references)</sup>
  - Opis
  - **Lista pouzdanih aplikacija**. To može biti:
    - Aplikacija: /Applications/Slack.app
    - Binarna datoteka: /usr/libexec/airportd
    - Grupa: group://AirPort

Izvoz podataka:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** dobija otvoreni tekst
- API **`SecItemExport`** izvozi ključeve i sertifikate, ali možda ćete morati da postavite lozinke kako biste izvezli šifrovani sadržaj

Ovo su **uslovi** za **izvoz tajne bez prompta**:<sup>[[1]](#references)</sup>

- Ako je navedena najmanje jedna **pouzdana** aplikacija:
  - Potrebna su odgovarajuća **ovlašćenja** (**`Nil`** ili članstvo u listi dozvoljenih aplikacija u ovlašćenju za pristup tajnim podacima)
  - Potreban je potpis koda koji se podudara sa **PartitionID**
  - Potreban je potpis koda koji se podudara sa potpisom jedne **pouzdane aplikacije** (ili članstvo u odgovarajućem KeychainAccessGroup)
- Ako su **sve aplikacije pouzdane**:
  - Potrebna su odgovarajuća **ovlašćenja**
  - Potreban je potpis koda koji se podudara sa **PartitionID**
    - Ako **nema PartitionID**, ovo nije potrebno

> [!CAUTION]
> Dakle, ako je navedena **jedna aplikacija**, potrebno je **ubrizgati kod в tu aplikaciju**.
>
> Ako je u **partitionID** naveden **apple**, možete mu pristupiti pomoću **`osascript`**; ovo važi za sve što veruje svim aplikacijama koje imaju apple u partitionID-ju. Za ovo se može koristiti i **`Python`**.

### Dva dodatna atributa

- **Invisible**: Bulova zastavica koja **sakriva** unos u Keychain aplikaciji **UI-ja**<sup>[[1]](#references)</sup>
- **General**: Služi za čuvanje **metapodataka** (dakle, NIJE ŠIFROVANO)<sup>[[1]](#references)</sup>
  - Microsoft je čuvao sve refresh tokene za pristup osetljivim krajnjim tačkama u otvorenom tekstu.<sup>[[1]](#references)</sup>

### Keychain zaštite podataka: prvo enumerišite, zatim upitom dohvatite jednu stavku

Pokrenite `SecItemCopyMatching` iz **potpisane aplikacije u kontekstu prijavljivanja ciljnog korisnika** uz `kSecUseDataProtectionKeychain: true`; nemojte pretpostaviti da su `security dump-keychain` ili podrazumevani SecItem upit pretražili ovo skladište. Pozivalac vidi samo grupe pristupa koje su mu odobrene.<sup>[[5]](#references)</sup>

Ako se testni kod izvršava unutar drugog procesa, pristup njegovom Keychain-u zaštite podataka zavisi od ovlašćenja te host izvršne datoteke. Pregledajte stvarna potpisana ovlašćenja pomoću `codesign -d --entitlements - /path/to/Target.app` i pogledajte [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) za povezane provere.<sup>[[7]](#references)</sup>

Najpre zatražite **samo atribute** za jednu klasu stavki. `kSecAttrSynchronizableAny` obuhvata i lokalna podudaranja i ona koja se sinhronizuju preko iCloud-a; ako ga izostavite, isključuju se sinhronizovane stavke.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` sprečava prikazivanje interfejsa za autentifikaciju tokom široke enumeracije, ali po cenu preskakanja zaštićenih podudaranja.<sup>[[9]](#references)</sup> Po potrebi ponovite postupak sa `kSecClassInternetPassword`.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

Za dozvoljeno čitanje tajne napravite **novi**, usko definisan upit za izabranu stavku (na primer, klasu, servis i nalog), postavite `kSecReturnData: true` i `kSecMatchLimit: kSecMatchLimitOne`, i očekujte autentifikaciju specifičnu za stavku ili grešku. Nemojte kombinovati `kSecReturnData` sa `kSecMatchLimitAll` za stavke sa lozinkama.<sup>[[10]](#references)</sup> Rezultat `errSecItemNotFound` može takođe ukazivati na pogrešno skladište, filter za sinhronizaciju ili nedostajuće ovlašćenje za access group, a ne na to da akreditiv ne postoji.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: „Obijanje brave macOS Keychain-a“ - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Nova verzija macOS kradljivca MacSync cilja ljubitelje kriptovaluta i programere](https://securelist.com/macsync-new-version/121383/)
- [4] [Ogledna kopija Apple security(1) man stranice](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — O API-jima i implementacijama keychain-a na Mac-u](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Osnove](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Zamke i najbolje prakse](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Pristupanje stavkama Keychain-a pomoću Face ID-a ili Touch ID-a](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
