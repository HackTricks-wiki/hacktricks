# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Algemene CTF-patrone

- “Signature” is eintlik `hash(secret || message)` → length extension.
- Unsalted password hashes → vinniger herhaalde cracking en voorafberekende opsoekaanvalle.
- Hash word met MAC verwar (hash != authentication).

## MD5-hashsoektogte met gekose invoer

Hierdie Python-voorbeelde soek na twee verskillende uitvoerpatrone: ’n gekose MD5-agtervoegsel en ’n MD5-waarde wat met `0e` begin, gevolg deur slegs syfers. Laasgenoemde patroon is relevant wanneer ’n toepassing numeriese stringe losweg vergelyk; sien die PHP-spesifieke gedrag en weergawes se voorbehoude in [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force van MD5-hash-agtervoegsels

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

### MD5 0e hash generation vir los vergelykings

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

### Tegniek

’n Length-extension attack kan moontlik wees wanneer ’n bediener ’n "handtekening" soos hierdie bereken:

`sig = HASH(secret || message)`

en ’n Merkle-Damgård-hash soos MD5, SHA-1 of SHA-256 gebruik.

As jy weet:

- `message`
- `sig`
- hash-funksie
- (of die waarde van `len(secret)` kan brute-force)

Dan kan jy ’n geldige handtekening vir die volgende bereken:

`message || padding || appended_data`

sonder om die secret te ken.<sup>[[1]](#references)</sup>

### Belangrike beperking: HMAC word nie geraak nie

Length-extension attacks is van toepassing op kwesbare voorvoegselkonstruksies soos `HASH(secret || message)`. Dit stel nie die HMAC-konstruksie bloot nie (byvoorbeeld HMAC-SHA256), wat ’n sleutel met afsonderlike inner- en outer-hash-bewerkings kombineer.<sup>[[1]](#references)[[2]](#references)</sup>

### Gereedskap

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-bindings vir die HashPump length-extension tool<sup>[[7]](#references)</sup>

### Goeie verduideliking

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Ondubbelsinnige tuple-hashing en MACs

### Boundary-confusion attack

Inkrementele hash-API’s staaf nie oproepgrense nie. `update(A); update(B)` has die selfde greepstring as `update(A + B)`. Daarom staaf hashing of MAC-verwerking van rou aaneenskakeling nie ’n tuple nie. As aangrensende velde veranderlike lengtes het, kan ’n aanvaller die grepe in ’n ander tuple herverdeel sonder om ’n botsing in die onderliggende hash te vind:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Dit word uitbuitbaar wanneer die verifieerder glo dat die digest veldbetekenisse vaslê, maar invoer wat deur die aanvaller beheer word ’n ander parser of protokolstap kan bereik wat ander grense toeken. Commitments kan alternatiewe openings kry, en Fiat-Shamir-transkripsies kan as ander stellings geïnterpreteer word. HMAC voorkom [hash length extension](#hash-length-extension-attack), maar `HMAC(K, A || B)` het steeds hierdie dubbelsinnigheid in tuple-kodering, omdat albei tuples dieselfde boodskapgrepe oplewer.<sup>[[8]](#references)[[9]](#references)</sup>

Gebruik hierdie ouditwerkvloei om te toets of dubbelsinnige tuple-kodering ’n sekuriteitsgrens oorsteek.<sup>[[8]](#references)[[9]](#references)</sup>

1. Vind `HASH(A || B)`, `HMAC(K, A || B)` en opeenvolgende `update()`/`Write()`-aanroepe oor twee of meer velde.
2. Merk elke veld wat deur die aanvaller beheer word of veranderlike lengte het. Probeer grepe oor elke grens verskuif terwyl die volledige aaneenskakeling onveranderd bly. Sluit leë velde in.
3. Kontroleer skemas met skeidingstekens vir grepe wat as skeidingstekens dien maar in invoer kan voorkom, verskille in escaping, en ontwerpe wat slegs sommige velde se lengtes enkodeer.
4. Volg hoe elke verbruiker die geverifieerde grepe ontleed. ’n Kandidaat is slegs betekenisvol as ’n alternatiewe verdeling ’n sekuriteitsbesluit, bewysstelling, rekord, transaksie of commitment-opening verander. Velde met vaste breedte of ’n kanonieke, injektiewe serialisering voorkom hierdie spesifieke aanval.
5. Kontroleer of dieselfde geënkodeerde digest in ’n ander protokolweergawe, boodskaptipe, rondte of toepassing aanvaar word. Bind hierdie kontekste uitdruklik eerder as om daarop staat te maak dat aanroepers hulle geskei hou.

### SequenceHash and SequenceMAC

SequenceHash is ’n hash-onafhanklike konstruksie vir reekse grepreekse. Elke `add()`-bewerking is atomies: dit voeg die waarde en ’n vaste 16-greep little-endian-lengte-agtervoegsel by die innerlike hash. Leë waardes bly afsonderlike objekte. ’n Buitenste hash voorkom dat ’n lengte-uitbreibare innerlike toestand blootgelê word, terwyl ’n opsionele aanpassingsstring domeinskeiding bied. Moenie `add()` met die onderliggende hash-API se gewone skryfbewerkings vervang nie.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Kies die customizer as deel van die protokoldefinisie, insluitend genoeg inligting om die toepassing, protokolweergawe, boodskaptipe en rondte te onderskei. SequenceHash vereis steeds dat alle partye ooreenkom oor veldvolgorde, greepenkodering en kanonieke serialisering, en dit kan nie ’n weggelate veld beskerm nie. Implementerings moet aan die C2SP-intermediêre en finale toetsvektore getoets word.<sup>[[8]](#references)[[11]](#references)</sup>

Vir verifikasie bied SequenceMAC dieselfde atoomenkodering en customizer-koppelvlak. Dit vereis ’n sleutel van minstens 32 grepe. Anders as HMAC se sleutelvoorverwerking, bind die koptekste daarvan hulle aan die presiese sleutellengte: ’n lang rou sleutel is nie gelykstaande aan die vooraf gehashte weergawe daarvan nie, en die byvoeging van nulgrepe verander die sleutel. Hierdie onderskeid is belangrik wanneer komponente verskillende sleutelvoorstellings of lengtemetadata aanvaar.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Die Python API en ekwivalente Go- en Rust-implementasies is as verwysings beskikbaar, maar protokolimplementasies moet die huidige C2SP-spesifikasie volg eerder as om die enkodering uit hierdie opsomming te herskep.<sup>[[8]](#references)[[10]](#references)</sup>

## Wagwoord-hashing en cracking

### Eerste vrae<sup>[[4]](#references)</sup>

- Is dit **gesout**? (soek formate soos `salt$hash`)
- Is dit ’n **vinnige hash** (MD5/SHA1/SHA256) of ’n **stadige KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Het jy ’n **formaatwenk** (hashcat-modus / John-formaat)?

### Praktiese werkvloei<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiseer die hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. As dit ongesout en algemeen is: probeer aanlyn DB’s en identifikasiegereedskap uit die crypto-werkvloei-afdeling.
3. Crack dit andersins:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Algemene foute wat jy kan uitbuit

- Dieselfde wagwoord word oor gebruikers heen hergebruik → crack een, pivot.
- Afgekapte hashes / pasgemaakte transformasies → normaliseer en probeer weer.
- Swak KDF-parameters (bv. min PBKDF2-iterasies) → steeds crackbaar.

### Bcrypt-orakel met gekose invoer en ’n aangehegte geheim

’n Aanroepbare helper wat `bcrypt(user_input || secret)` teruggee, kan inligting oor ’n aangehegte geheim blootlê as sy bcrypt-implementasie invoer ná 72 **grepe** stilweg afkap. ’n Karakterlimiet voor UTF-8-enkodering handhaaf nie daardie greeplimiet nie: multigreepkarakters kan die bcrypt-invoer vul en net plek laat vir ’n klein voorvoegsel van die geheim. Gekose invoere en die hashes wat teruggegee word, kan dan vanlyn kontroles van kandidaat-agtervoegselgrepe moontlik maak. Dit vereis beheer oor die helper se invoer, kennis van die presiese transformasie en enkodering, en ’n implementasie wat werklik afkap; ’n aanroepbare helper of ’n bcrypt-hash alleen bewys nie hierdie ketting nie. [pyca/bcrypt dokumenteer](https://github.com/pyca/bcrypt#maximum-password-length) dat huidige `hashpw` ’n fout veroorsaak vir invoere langer as 72 grepe, terwyl vroeëre gedrag dit stilweg afgekap het. Ander wrappers kan lang invoere vooraf hash of verwerp, dus moet jy die geïnstalleerde implementasie nagaan eerder as om afkapping te aanvaar.

Om ’n herwonne geheim teen ’n ander rekening te gebruik, vereis ook bewyse dat sy blootgestelde hash met **dieselfde** geheim en transformasie gegenereer is, plus ’n afsonderlike geloofsbriewestel of aanmeldpad. ’n Hashing-helper wat as root loop, moet slegs as ’n orakel beskou word as die gebruiker met laer voorregte dit onder die effektiewe beleid kan aanroep; passiewe gasheerenumerasie hoef dit nie aan te roep of gekose wagwoorde in te dien nie.

## References

- [1] [SkullSecurity - Alles wat jy moet weet oor hash-lengte-uitbreidingsaanvalle](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Die gehashte boodskapverifikasiekode met sleutel](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP se kontrolelys vir wagwoordberging](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat-voorbeeldhashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper-opdragreëlopsies](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python-bindings vir HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash- en SequenceMAC-spesifikasie](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing vir die res van ons](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python-implementasie](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash-toetsvektore](https://github.com/C2SP/CCTV/tree/main/sequencehash)
