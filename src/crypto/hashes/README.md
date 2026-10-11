# Hashes, MACs i KDF-ovi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni CTF obrasci

- „Potpis“ je zapravo `hash(secret || message)` → napad produžavanjem dužine.
- Hash-evi lozinki bez salt-a → brže ponovljeno razbijanje i napadi pomoću unapred izračunatih tabela.
- Mešanje hash-a i MAC-a (hash != autentikacija).

## Hash length extension attack

### Tehnika

Napad produžavanjem dužine može biti moguć kada server računa „potpis“ poput:

`sig = HASH(secret || message)`

i koristi hash funkciju Merkle-Damgård, kao što su MD5, SHA-1 ili SHA-256.

Ako znate:

- `message`
- `sig`
- hash funkciju
- (ili možete da brute-force-ujete) `len(secret)`

onda možete da izračunate važeći potpis za:

`message || padding || appended_data`

bez poznavanja tajne.<sup>[[1]](#references)</sup>

### Važno ograničenje: HMAC nije pogođen

Napadi produžavanjem dužine primenjuju se na ranjive konstrukcije sa prefiksom, kao što je `HASH(secret || message)`. Oni ne otkrivaju konstrukciju HMAC-a (na primer, HMAC-SHA256), koja kombinuje ključ sa odvojenim unutrašnjim i spoljašnjim primenama hash funkcije.<sup>[[1]](#references)[[2]](#references)</sup>

### Alati

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python binding-i za alat HashPump za napade produžavanjem dužine<sup>[[7]](#references)</sup>

### Dobro objašnjenje

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashovanje i razbijanje lozinki

### Prva pitanja<sup>[[4]](#references)</sup>

- Da li je hash **salt-ovan**? (potražite formate `salt$hash`)
- Da li se radi o **brzom hash-u** (MD5/SHA1/SHA256) ili **sporom KDF-u** (bcrypt/scrypt/argon2/PBKDF2)?
- Imate li **nagoveštaj o formatu** (hashcat mode / John format)?

### Praktični postupak<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifikujte hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Ako nema salt i hash je uobičajen: isprobajte online baze podataka i alate za identifikaciju iz odeljka o crypto workflow-u.
3. U suprotnom, pokušajte da ga razbijete:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Uobičajene greške koje možete da iskoristite

- Ista lozinka se koristi za više korisnika → razbijte jednu, pa napravite pivot.
- Skraćeni hash-evi / prilagođene transformacije → normalizujte ih i pokušajte ponovo.
- Slabi KDF parametri (npr. mali broj PBKDF2 iteracija) → i dalje ih je moguće razbiti.

### bcrypt oracle sa izabranim unosom i dodatom tajnom

Funkcija koju je moguće pozvati i koja vraća `bcrypt(user_input || secret)` može da otkrije informacije o dodatoj tajni ako njena bcrypt implementacija neprimetno skraćuje unos nakon 72 **bajta**. Ograničenje broja znakova pre UTF-8 kodiranja ne sprovodi to ograničenje broja bajtova: višebajtni znakovi mogu da popune bcrypt unos, ostavljajući prostor samo za mali prefiks tajne. Izabrani unosi i hash-evi koje funkcija vrati tada mogu da omoguće offline proveru mogućih završnih bajtova. Za ovo je neophodna kontrola nad unosom funkcije, poznavanje njene tačne transformacije i kodiranja, kao i implementacija koja zaista skraćuje unos; sama dostupnost funkcije ili bcrypt hash-a ne dokazuje ceo lanac. [Dokumentacija pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) navodi da trenutna funkcija `hashpw` javlja grešku za unose duže od 72 bajta, dok ih ranije verzije neprimetno skraćivale. Druge wrapper-e mogu da prethodno hash-uju ili odbace duge unose, zato proverite instaliranu implementaciju umesto da pretpostavljate da dolazi do skraćivanja.

Korišćenje otkrivene tajne za drugi nalog takođe zahteva dokaze da je njegov izloženi hash generisan **istom** tajnom i transformacijom, kao i zaseban credential ili putanju za prijavu. Pomoćnu skriptu za hashovanje koja se izvršava kao root treba posmatrati kao oracle samo ako korisnik sa nižim privilegijama može da je pozove u skladu sa važećim pravilima; pasivna enumeracija hosta ne mora da je pozove niti da joj prosleđuje izabrane lozinke.

## References

- [1] [SkullSecurity - Sve što treba da znate o napadima produžavanjem dužine hash-a](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Kod za autentikaciju poruke sa ključem i hash-om](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Cheat Sheet za čuvanje lozinki](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Primeri hash-eva za Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opcije komandne linije za John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python binding-i za HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
