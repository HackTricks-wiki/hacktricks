# Hash-evi, MAC-ovi i KDF-ovi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni CTF obrasci

- „Potpis“ je zapravo `hash(secret || message)` → length extension.
- Hash-evi lozinki bez salt-a → brže ponovljeno crackovanje i napadi pomoću unapred izračunatih tabela.
- Mešanje hash-a i MAC-a (hash != autentifikacija).

## Hash length extension attack

### Tehnika

Length-extension attack može biti moguć kada server izračunava „potpis“ poput:

`sig = HASH(secret || message)`

i koristi hash funkciju Merkle-Damgård, kao što su MD5, SHA-1 ili SHA-256.

Ako znate:

- `message`
- `sig`
- hash funkciju
- (ili možete brute-force-om da pronađete) `len(secret)`

onda možete da izračunate važeći potpis za:

`message || padding || appended_data`

bez poznavanja tajne.<sup>[[1]](#references)</sup>

### Važno ograničenje: HMAC nije pogođen

Length-extension napadi važe za ranjive konstrukcije sa prefiksom, kao što je `HASH(secret || message)`. Oni ne kompromituju HMAC konstrukciju (na primer, HMAC-SHA256), koja kombinuje ključ sa odvojenim unutrašnjim i spoljašnjim primenama hash funkcije.<sup>[[1]](#references)[[2]](#references)</sup>

### Alati

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python povezivanje za HashPump alat za length-extension<sup>[[7]](#references)</sup>

### Dobro objašnjenje

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashovanje lozinki i cracking

### Prva pitanja<sup>[[4]](#references)</sup>

- Da li koristi **salt**? (potražite formate `salt$hash`)
- Da li je u pitanju **brz hash** (MD5/SHA1/SHA256) ili **spor KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Da li imate **naznaku o formatu** (hashcat mode / John format)?

### Praktični postupak<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifikujte hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Ako nema salt i hash je čest, isprobajte online baze podataka i alate za identifikaciju iz odeljka o crypto workflow-u.
3. U suprotnom, crackujte:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Uobičajene greške koje možete da iskoristite

- Ista lozinka se ponavlja kod više korisnika → crackujte jednu pa pivot-ujte.
- Skraćeni hash-evi / prilagođene transformacije → normalizujte i pokušajte ponovo.
- Slabi KDF parametri (npr. mali broj PBKDF2 iteracija) → i dalje mogu da se crackuju.

### bcrypt oracle sa izabranim ulazom i dodatom tajnom

Pozivi helper-a koji vraća `bcrypt(user_input || secret)` mogu da otkriju informacije o dodatoj tajni ako njegova bcrypt implementacija neprimetno skraćuje ulaz nakon 72 **bajta**. Ograničenje broja znakova pre UTF-8 kodiranja ne nameće to ograničenje broja bajtova: višebajtni znakovi mogu da popune bcrypt ulaz, ostavljajući mesta samo za mali prefiks tajne. Izabrani ulazi i hash-evi koje helper vraća mogu zatim da omoguće offline proveru kandidata za završne bajtove. Za ovo je neophodna kontrola nad ulazom helper-a, poznavanje njegove tačne transformacije i kodiranja, kao i implementacija koja zaista skraćuje ulaz; sam poziv helper-a ili bcrypt hash ne dokazuju da su svi ovi uslovi ispunjeni. [Dokumentacija pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) navodi da trenutna verzija funkcije `hashpw` javlja grešku za ulaze duže od 72 bajta, dok ih je ranije ponašanje neprimetno skraćivalo. Drugi wrapper-i mogu unapred da izračunaju hash ili da odbiju dugačke ulaze, zato proverite instaliranu implementaciju umesto da pretpostavite da skraćuje ulaz.

Korišćenje otkrivene tajne za drugi nalog takođe zahteva dokaz da je njegov izloženi hash generisan pomoću **iste** tajne i transformacije, kao i zaseban put za pristup kredencijalima ili prijavljivanje. Helper za hashovanje koji se izvršava kao root treba posmatrati kao oracle samo ako korisnik sa nižim privilegijama može da ga pozove u skladu sa važećom politikom; pasivno popisivanje hosta ne mora da ga poziva niti da mu šalje izabrane lozinke.

## References

- [1] [SkullSecurity - Sve što treba da znate o hash length-extension napadima](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Kod za autentifikaciju poruka zasnovan na ključnom hash-u](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP kontrolna lista za čuvanje lozinki](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat primeri hash-eva](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opcije komandne linije za John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: Python povezivanje `hashpumpy` za HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
