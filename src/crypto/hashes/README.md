# Hash vrednosti, MAC-ovi i KDF-ovi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni CTF obrasci

- „Potpis“ je zapravo `hash(secret || message)` → length extension.
- Hash vrednosti lozinki bez salt-a → brže ponovljeno razbijanje i napadi pomoću unapred izračunatih tabela.
- Mešanje hash-a sa MAC-om (hash != autentifikacija).

## Pretrage MD5 hash vrednosti sa izabranim ulazom

Ovi Python primeri pretražuju dva različita obrasca izlaza: izabrani MD5 sufiks i MD5 vrednost koja počinje sa `0e`, a nakon toga sadrži samo cifre. Potonji obrazac je relevantan kada aplikacija labavo upoređuje numeričke nizove; pogledajte ponašanje specifično za PHP i napomene o verzijama u odeljku [Labava poređenja u PHP-u](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute-force pretraga MD5 hash sufiksa

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

### Generisanje MD5 0e hash vrednosti za labava poređenja

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

### Tehnika

Napad produženjem dužine može biti moguć kada server izračunava „potpis“ poput:

`sig = HASH(secret || message)`

i koristi hash funkciju Merkle-Damgård, kao što su MD5, SHA-1 ili SHA-256.

Ako znate:

- `message`
- `sig`
- hash funkciju
- (ili možete brute-force-om da utvrdite) `len(secret)`

onda možete izračunati važeći potpis za:

`message || padding || appended_data`

bez poznavanja tajne.<sup>[[1]](#references)</sup>

### Važno ograničenje: HMAC nije pogođen

Napadi produženjem dužine odnose se na ranjive konstrukcije sa prefiksom, poput `HASH(secret || message)`. Oni ne otkrivaju HMAC konstrukciju (na primer, HMAC-SHA256), koja kombinuje ključ sa zasebnim unutrašnjim i spoljašnjim hash operacijama.<sup>[[1]](#references)[[2]](#references)</sup>

Da biste saznali kako da pronađete i testirate ove potpise u web API-jima, pogledajte [Potpisi zahteva i parametara](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Alati

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python povezivanja za alat HashPump za produženje dužine<sup>[[7]](#references)</sup>

### Dobro objašnjenje

[Sve što treba da znate o napadima produženjem dužine hash-a](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Dvosmisleno hashiranje torki i MAC-ovi

### Boundary-confusion attack

Inkrementalni hash API-ji ne autentifikuju granice poziva. `update(A); update(B)` izračunava hash istog niza bajtova kao `update(A + B)`. Zato hashiranje ili izračunavanje MAC-a nad sirovim konkateniranim podacima ne autentifikuje torku. Ako susedna polja imaju promenljivu dužinu, napadač može drugačije da podeli bajtove u torku, a da pritom ne pronađe koliziju u osnovnoj hash funkciji:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Ovo postaje moguće iskoristiti kada verifikator veruje da sažetak vezuje značenja polja, ali ulaz koji kontroliše napadač može stići do drugog parsera ili koraka protokola koji dodeljuje drugačije granice. Obavezivanja mogu dobiti alternativna otvaranja, a Fiat-Shamir transkripti mogu biti protumačeni kao drugačije tvrdnje. HMAC sprečava [hash length extension](#hash-length-extension-attack), ali `HMAC(K, A || B)` i dalje ima ovu dvosmislenost kodiranja torki, jer obe torke daju iste bajtove poruke.<sup>[[8]](#references)[[9]](#references)</sup>

Koristite ovaj postupak revizije da biste proverili da li dvosmisleno kodiranje torke prelazi bezbednosnu granicu.<sup>[[8]](#references)[[9]](#references)</sup>

1. Pronađite `HASH(A || B)`, `HMAC(K, A || B)` i uzastopne pozive `update()`/`Write()` nad dva ili više polja.
2. Označite svako polje koje kontroliše napadač ili čija je dužina promenljiva. Pokušajte da pomerite bajtove preko svake granice, a da pritom celokupna konkatenacija ostane nepromenjena. Uključite i prazna polja.
3. Proverite šeme sa graničnicima da biste utvrdili mogu li ulazi sadržati bajtove graničnika, postoje li neslaganja u escapovanju i da li dizajni kodiraju dužinu samo nekih polja.
4. Pratite kako svaki potrošač parsira autentifikovane bajtove. Alternativna podela je relevantna samo ako menja bezbednosnu odluku, iskaz dokaza, zapis, transakciju ili otvaranje obavezivanja. Polja fiksne dužine ili kanonizovana, injektivna serijalizacija sprečavaju ovaj konkretan napad.
5. Proverite da li je isti kodirani sažetak prihvaćen u drugoj verziji protokola, tipu poruke, rundi ili aplikaciji. Eksplicitno vežite ove kontekste, umesto da se oslanjate na pozivaoce da ih razdvoje.

### SequenceHash i SequenceMAC

SequenceHash je konstrukcija nezavisna od hash funkcije za nizove bajtovnih stringova. Svaka operacija `add()` je atomska: dodaje vrednost i fiksni 16-bajtni sufiks dužine u little-endian formatu unutrašnjem hash-u. Prazne vrednosti ostaju zasebni objekti. Spoljašnji hash sprečava izlaganje unutrašnjeg stanja čija se dužina može produžavati, dok opcioni prilagođeni string omogućava razdvajanje domena. Nemojte zameniti `add()` običnim upisima kroz API osnovne hash funkcije.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Izaberite prilagođivač kao deo definicije protokola, uključujući dovoljno informacija za razlikovanje aplikacije, verzije protokola, tipa poruke i runde. SequenceHash i dalje zahteva da se sve strane usaglase oko redosleda polja, kodiranja bajtova i kanonske serijalizacije, a ne može da zaštiti izostavljeno polje. Implementacije treba proveriti pomoću C2SP međuvektora i konačnih testnih vektora.<sup>[[8]](#references)[[11]](#references)</sup>

Za autentifikaciju, SequenceMAC pruža isti interfejs za atomsko kodiranje i prilagođavanje. Zahteva ključ od najmanje 32 bajta. Za razliku od predobrade ključa u HMAC-u, njegova zaglavlja vezuju se za tačnu dužinu ključa: dugi sirovi ključ nije ekvivalentan svom prehešu, a dodavanje nultih bajtova menja ključ. Ova razlika je važna kada komponente prihvataju različite prikaze ključa ili metapodatke o njegovoj dužini.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API i ekvivalentne implementacije u Go i Rust dostupne su kao reference, ali implementacije protokola treba da prate važeću C2SP specifikaciju, umesto da ponovo implementiraju kodiranje na osnovu ovog sažetka.<sup>[[8]](#references)[[10]](#references)</sup>

## Hashiranje lozinki i cracking

### Prva pitanja<sup>[[4]](#references)</sup>

- Da li hash koristi **salt**? (potražite formate `salt$hash`)
- Da li je u pitanju **brzi hash** (MD5/SHA1/SHA256) ili **spori KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Imate li **naznaku o formatu** (hashcat mode / John format)?

### Praktični postupak<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifikujte hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Ako je hash bez salta i čest: isprobajte online baze podataka i alate za identifikaciju iz odeljka o crypto workflow-u.
3. U suprotnom, pokušajte cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Česte greške koje možete da iskoristite

- Ista lozinka se koristi za više korisnika → crackujte jednu i pivotujte.
- Skraćeni hash-evi / prilagođene transformacije → normalizujte ih i pokušajte ponovo.
- Slabi KDF parametri (npr. mali broj PBKDF2 iteracija) → hash je i dalje moguće crackovati.

### bcrypt oracle sa izabranim ulazom i dodatnom tajnom

Pozivni pomoćni program koji vraća `bcrypt(user_input || secret)` može otkriti informacije o dodatnoj tajni ako njegova bcrypt implementacija нечујно скраћује улаз после 72 **бајта**. Ограничење броја знакова пре UTF-8 кодирања не спроводи то ограничење у бајтовима: вишебајтни знакови могу да попуне bcrypt улаз, остављајући места само за мали префикс тајне. Изабрани улази и њихови враћени хешеви тада могу да омогуће офлајн проверу могућих наставка у бајтовима. За ово је потребно да контролишете улаз помоћног програма, да знате његову тачну трансформацију и кодирање и да се имплементација заиста скраћује; сам позивни помоћни програм или bcrypt hash не доказује да је цео ланац могућ. [pyca/bcrypt документује](https://github.com/pyca/bcrypt#maximum-password-length) да актуелни `hashpw` изазива грешку за улазе дуже од 72 бајта, док је раније понашање било њихово нечујно скраћивање. Други wrappers могу да хеширају унапред или одбију дугачке улазе, зато проверите инсталирану имплементацију уместо да претпоставите да долази до скраћивања.

За коришћење откривене тајне против другог налога потребан је и доказ да је изложени hash генерисан помоћу **исте** тајне и трансформације, као и засебан пут за приступ акредитивима или пријаву. Помоћни програм за хеширање који се покреће као root треба посматрати као oracle само ако корисник са нижим привилегијама може да га позове у складу са важећом политиком; пасивно испитивање хоста не мора да га позива нити да му шаље изабране лозинке.

## References

- [1] [SkullSecurity - Sve što treba da znate o napadima produžavanja dužine hash-a](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Kod za autentifikaciju poruka sa ključem i hash-om](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Podsetnik za čuvanje lozinki](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat primeri hash-eva](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper opcije komandne linije](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: Python bindings za HashPump `hashpumpy`](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Specifikacija za SequenceHash i SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing za sve](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Python implementacija SequenceHash-a](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Test vektori za SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
