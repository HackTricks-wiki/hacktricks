# Hashes, MACs i KDF-ovi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni CTF obrasci

- „Potpis“ je zapravo `hash(secret || message)` → length extension.
- Nesoljeni password hash-evi → brže ponovljeno crackingovanje i napadi pomoću unapred izračunatih vrednosti.
- Mešanje hash-a sa MAC-om (hash != autentifikacija).

## Pretrage MD5 hash-eva sa izabranim ulazom

Ovi Python primeri pretražuju dva različita obrasca izlaznih vrednosti: izabrani MD5 sufiks i MD5 vrednost koja počinje sa `0e`, iza čega slede samo cifre. Drugi obrazac je relevantan kada aplikacija ne pravi stroga poređenja numeričkih stringova; pogledajte ponašanje specifično za PHP i napomene o verzijama u odeljku [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force MD5 hash sufiksa

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Generisanje MD5 hash vrednosti 0e za labava poređenja

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Technique

Napad produžavanjem dužine može biti moguć kada server izračunava „potpis“ poput:

`sig = HASH(secret || message)`

i koristi Merkle-Damgård heš, kao što su MD5, SHA-1 ili SHA-256.

Ako znate:

- `message`
- `sig`
- heš funkciju
- (ili možete da brute-force-ujete) `len(secret)`

onda možete da izračunate važeći potpis za:

`message || padding || appended_data`

bez poznavanja tajne.<sup>[[1]](#references)</sup>

### Važno ograničenje: HMAC nije pogođen

Napadi produžavanjem dužine primenjuju se na ranjive konstrukcije sa prefiksom, kao što je `HASH(secret || message)`. Oni ne otkrivaju konstrukciju HMAC-a (na primer, HMAC-SHA256), koja kombinuje ključ sa zasebnim unutrašnjim i spoljnim primenama heš funkcije.<sup>[[1]](#references)[[2]](#references)</sup>

### Alati

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings za alat HashPump za produžavanje dužine<sup>[[7]](#references)</sup>

### Dobro objašnjenje

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Dvosmisleno heširanje torki i MAC-ovi

### Boundary-confusion attack

Inkrementalni API-ji za heširanje ne autentifikuju granice poziva. `update(A); update(B)` hešira isti niz bajtova kao `update(A + B)`. Zato heširanje ili MAC-ovanje sirove konkatenacije ne autentifikuje torku. Ako susedna polja imaju promenljivu dužinu, napadač može da preraspodeli bajtove u drugu torku bez pronalaženja kolizije u osnovnoj heš funkciji:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Ovo postaje iskoristivo kada verifikator veruje da sažetak vezuje značenja polja, ali ulaz koji kontroliše napadač može da stigne do drugog parsera ili koraka protokola koji dodeljuje drugačije granice. Commitments mogu dobiti alternativna otvaranja, a Fiat-Shamir transkripti mogu biti protumačeni kao različite tvrdnje. HMAC sprečava [hash length extension](#hash-length-extension-attack), ali `HMAC(K, A || B)` i dalje ima ovu dvosmislenost kodiranja torke, jer obe torke daju iste bajtove poruke.<sup>[[8]](#references)[[9]](#references)</sup>

Koristite ovaj postupak revizije da proverite da li dvosmisleno kodiranje torke prelazi bezbednosnu granicu.<sup>[[8]](#references)[[9]](#references)</sup>

1. Pronađite `HASH(A || B)`, `HMAC(K, A || B)` i uzastopne pozive `update()`/`Write()` nad dvama ili više polja.
2. Označite svako polje koje kontroliše napadač ili čija je dužina promenljiva. Pokušajte da prebacujete bajtove preko svake granice, a da pritom zadržite nepromenjenu ukupnu konkatenaciju. Uključite i prazna polja.
3. Proverite da li šeme s razdvajačima koriste bajtove razdvajača koje ulazi mogu da sadrže, da li postoje neslaganja u escapovanju i da li dizajni kodiraju dužinu samo nekih polja.
4. Pratite kako svaki potrošač parsira autentifikovane bajtove. Potencijalni slučaj je relevantan samo ako alternativna podela menja bezbednosnu odluku, tvrdnju dokaza, zapis, transakciju ili otvaranje commitmenta. Polja fiksne širine ili kanonska, injektivna serijalizacija sprečavaju ovaj konkretan napad.
5. Proverite da li se isti kodirani sažetak prihvata u drugoj verziji protokola, tipu poruke, rundi ili aplikaciji. Eksplicitno vežite ove kontekste umesto da se oslanjate na pozivaoce da ih drže odvojenim.

### SequenceHash i SequenceMAC

SequenceHash je konstrukcija nezavisna od hash funkcije za sekvence nizova bajtova. Svaka operacija `add()` je atomska: dodaje vrednost unutrašnjem hash-u, a zatim i fiksni 16-bajtni sufiks dužine u little-endian formatu. Prazne vrednosti ostaju zasebni objekti. Spoljašnji hash sprečava otkrivanje unutrašnjeg stanja podložnog proširenju dužine, dok opcioni niz za prilagođavanje omogućava razdvajanje domena. Nemojte zameniti `add()` uobičajenim upisima preko API-ja osnovne hash funkcije.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Izaberite customizer kao deo definicije protokola, uključujući dovoljno informacija za razlikovanje aplikacije, verzije protokola, tipa poruke i runde. SequenceHash i dalje zahteva da se sve strane usaglase oko redosleda polja, bajtnog kodiranja i kanonske serijalizacije, a ne može da zaštiti izostavljeno polje. Portove treba proveriti u odnosu na C2SP međuvectorske i završne test-vektore.<sup>[[8]](#references)[[11]](#references)</sup>

Za autentifikaciju, SequenceMAC pruža isti interfejs za atomsko kodiranje i prilagođavanje. Zahteva ključ od najmanje 32 bajta. Za razliku od predobrade HMAC ključa, njegova zaglavlja vezuju se za tačnu dužinu ključa: dugačak sirovi ključ nije ekvivalentan svom prehešu, a dodavanje nultih bajtova menja ključ. Ova razlika je važna kada komponente prihvataju različite reprezentacije ključa ili metapodatke o dužini.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API i ekvivalentne implementacije u Go i Rust dostupne su kao reference, ali implementacije protokola treba da prate važeću C2SP specifikaciju, umesto da ponovo stvaraju kodiranje na osnovu ovog sažetka.<sup>[[8]](#references)[[10]](#references)</sup>

## Hashiranje lozinki i probijanje

### Prva pitanja<sup>[[4]](#references)</sup>

- Da li koristi **salt**? (potražite formate `salt$hash`)
- Da li je u pitanju **brz hash** (MD5/SHA1/SHA256) ili **spor KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Imate li **naznaku o formatu** (hashcat mode / John format)?

### Praktičan postupak<sup>[[5]](#references)[[6]](#references)</sup>

1. Utvrdite hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Ako nije salted i čest je: isprobajte online baze podataka i alate za identifikaciju iz odeljka o crypto workflow-u.
3. U suprotnom, pokušajte da ga probijete:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Česte greške koje možete iskoristiti

- Ista lozinka se ponovo koristi za više korisnika → probijte jednu, pa napravite pivot.
- Skraćeni hash-evi / prilagođene transformacije → normalizujte ih i pokušajte ponovo.
- Slabi KDF parametri (npr. mali broj PBKDF2 iteracija) → i dalje ih je moguće probiti.

### bcrypt oracle sa izabranim ulazom i dodatnom tajnom

Pozivni pomoćni program koji vraća `bcrypt(user_input || secret)` može otkriti informacije o dodatoj tajni ako njegova bcrypt implementacija neprimetno odseca ulaz nakon 72 **bajta**. Ograničenje broja znakova pre UTF-8 kodiranja ne nameće to ograničenje broja bajtova: višebajtni znakovi mogu popuniti bcrypt ulaz, ostavljajući mesta samo za mali prefiks tajne. Izabrani ulazi i hash-evi koje program vrati tada mogu omogućiti offline proveru kandidata za završne bajtove. Za ovo je potrebno da možete da kontrolišete ulaz programa, da znate njegovu tačnu transformaciju i kodiranje i da implementacija zaista odseca ulaz; samo postojanje pozivnog programa ili bcrypt hash-a ne dokazuje da je ovaj lanac moguć. [Dokumentacija za pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) navodi da aktuelni `hashpw` podiže grešku za ulaze duže od 72 bajta, dok ih je ranije neprimetno odsecao. Drugi omotači mogu unapred da izračunaju hash ili da odbiju dugačke ulaze, zato proverite instaliranu implementaciju umesto da pretpostavljate da dolazi do odsecanja.

Upotreba oporavljene tajne za drugi nalog zahteva i dokaz da je njegov izloženi hash generisan sa **istom** tajnom i transformacijom, kao i zasebnu putanju za autentifikaciju ili prijavu. Pomoćni program za hashiranje koji se izvršava kao root treba posmatrati kao oracle samo ako korisnik sa nižim privilegijama može da ga pozove u skladu sa važećom politikom; pasivna enumeracija hosta ne mora da ga poziva niti da mu šalje izabrane lozinke.

## References

- [1] [SkullSecurity - Sve što treba da znate o napadima produžavanja dužine hash-a](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Kod za autentifikaciju poruka zasnovan na ključnom hash-u](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Podsetnik za čuvanje lozinki](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Primeri hash-eva za Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Opcije komandne linije](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python binding-i za HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Specifikacija za SequenceHash i SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: višestruko hashiranje za sve](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Python implementacija za SequenceHash](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Testni vektori za SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
