# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Algemene CTF-patrone

- “Handtekening” is eintlik `hash(secret || message)` → length extension.
- Onversoute wagwoord-hashes → vinniger herhaalde kraking en voorafberekende opsoekaanvalle.
- Hash met MAC verwar (hash != authentication).

## MD5-hashsoektogte met gekose invoer

Hierdie Python-voorbeelde soek na twee verskillende uitvoerpatrone: ’n gekose MD5-agtervoegsel en ’n MD5-waarde wat met `0e` begin, gevolg deur slegs syfers. Laasgenoemde patroon is relevant wanneer ’n toepassing numeriese stringe losweg vergelyk; sien die PHP-spesifieke gedrag en weergawes se voorbehoude in [PHP-loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force van MD5-hash-agtervoegsel

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

### MD5 0e hash-generering vir los vergelykings

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

’n Length-extension attack kan moontlik wees wanneer ’n bediener ’n "handtekening" soos volg bereken:

`sig = HASH(secret || message)`

en ’n Merkle-Damgård-hash soos MD5, SHA-1 of SHA-256 gebruik.

As jy die volgende ken:

- `message`
- `sig`
- hash-funksie
- (of `len(secret)` kan brute-force)

Dan kan jy ’n geldige handtekening vir die volgende bereken:

`message || padding || appended_data`

sonder om die geheim te ken.<sup>[[1]](#references)</sup>

### Belangrike beperking: HMAC word nie geraak nie

Length-extension attacks is van toepassing op kwesbare voorvoegselkonstruksies soos `HASH(secret || message)`. Dit stel nie die HMAC-konstruksie (byvoorbeeld HMAC-SHA256) bloot nie, wat ’n sleutel kombineer met afsonderlike binne- en buite-hash-bewerkings.<sup>[[1]](#references)[[2]](#references)</sup>

Vir inligting oor hoe om hierdie handtekeninge in web-API’s te vind en te toets, raadpleeg [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-bindings vir die HashPump length-extension-tool<sup>[[7]](#references)</sup>

### Goeie verduideliking

[Alles wat jy oor hash length extension attacks moet weet](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Onduidelike tuple-hashing en MAC’s

### Boundary-confusion attack

Inkrementele hash-API’s staaf nie oproepgrense nie. `update(A); update(B)` hash dieselfde grepe-string as `update(A + B)`. Daarom staaf hashing of MAC-bewerking van rou aaneenskakeling nie ’n tuple nie. As aangrensende velde veranderlike lengtes het, kan ’n aanvaller die grepe in ’n ander tuple herverdeel sonder om ’n botsing in die onderliggende hash te vind:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Dit word uitbuitbaar wanneer die verifier glo dat die digest veldbetekenisse bind, maar aanvaller-beheerde invoer ’n ander parser of protokolstap kan bereik wat ander grense toeken. Commitments kan alternatiewe openings kry, en Fiat-Shamir-transkripsies kan as ander stellings geïnterpreteer word. HMAC voorkom [hash length extension](#hash-length-extension-attack), maar `HMAC(K, A || B)` het steeds hierdie dubbelsinnigheid in tuple-enkodering, omdat albei tuples dieselfde boodskapgrepe oplewer.<sup>[[8]](#references)[[9]](#references)</sup>

Gebruik hierdie ouditwerkvloei om te toets of ’n dubbelsinnige tuple-enkodering ’n sekuriteitsgrens oorsteek.<sup>[[8]](#references)[[9]](#references)</sup>

1. Vind `HASH(A || B)`, `HMAC(K, A || B)` en opeenvolgende `update()`/`Write()`-aanroepe oor twee of meer velde.
2. Merk elke aanvaller-beheerde of veranderlike-lengte veld. Probeer grepe oor elke grens verskuif terwyl die volledige aaneenskakeling onveranderd bly. Sluit leë velde in.
3. Gaan skemas met skeidingstekens na vir skeidingstekengrepe wat invoer kan bevat, verskille in escaping en ontwerpe wat slegs sommige velde met lengtes enkodeer.
4. Volg hoe elke verbruiker die geauthentiseerde grepe ontleed. ’n Kandidaat is slegs betekenisvol as ’n alternatiewe verdeling ’n sekuriteitsbesluit, bewysstelling, rekord, transaksie of commitment-opening verander. Velden met vaste breedte of ’n kanonieke, injectiewe serialisering voorkom hierdie spesifieke aanval.
5. Gaan na of dieselfde geënkodeerde digest in ’n ander protokolweergawe, boodskaptipe, rondte of toepassing aanvaar word. Bind hierdie kontekste eksplisiet eerder as om daarop staat te maak dat oproepers hulle apart hou.

### SequenceHash en SequenceMAC

SequenceHash is ’n hash-agnostiese konstruksie vir rye grepe-stringe. Elke `add()`-bewerking is atomies: dit voeg die waarde en ’n vaste 16-greep-lengte-agtervoegsel in little-endian-volgorde by die innerlike hash. Leë waardes bly afsonderlike objekte. ’n Buitenste hash voorkom dat ’n lengte-uitbreibare innerlike toestand blootgelê word, terwyl ’n opsionele aanpassingsstring domeinskeiding verskaf. Moenie `add()` vervang met die onderliggende hash-API se gewone skryfbewerkings nie.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Kies die customizer as deel van die protokoldefinisie, met genoeg inligting om die toepassing, protokolweergawe, boodskaptipe en rondte te onderskei. SequenceHash vereis steeds dat alle partye ooreenkom oor veldvolgorde, byte-kodering en kanonieke serialisering, en dit kan nie ’n weggelate veld beskerm nie. Poorte moet teen die C2SP-intermediêre en finale toetsvektore nagegaan word.<sup>[[8]](#references)[[11]](#references)</sup>

Vir verifikasie bied SequenceMAC dieselfde atomiese koderings- en customization-koppelvlak. Dit vereis ’n sleutel van minstens 32 grepe. Anders as HMAC se sleutelvoorverwerking, bind die opskrifte daarvan aan die presiese sleutellengte: ’n lang rou sleutel is nie gelykstaande aan sy vooraf-hash nie, en die byvoeging van nulgrepe verander die sleutel. Hierdie onderskeid is belangrik wanneer komponente verskillende sleutelvoorstellings of lengtemetadata aanvaar.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Die Python-API en ekwivalente Go- en Rust-implementasies is as verwysings beskikbaar, maar protokolimplementasies behoort die aktuele C2SP-spesifikasie te volg eerder as om die enkodering uit hierdie opsomming te herskep.<sup>[[8]](#references)[[10]](#references)</sup>

## Wagwoord-hashing en cracking

### Eerste vrae<sup>[[4]](#references)</sup>

- Is dit **gesalt**? (soek na `salt$hash`-formate)
- Is dit ’n **vinnige hash** (MD5/SHA1/SHA256) of ’n **stadige KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Het jy ’n **formaatwenk** (hashcat-modus / John-formaat)?

### Praktiese werkvloei<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiseer die hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. As dit ongesalt en algemeen is: probeer aanlyn databasisse en identifikasiehulpmiddels uit die kripto-werkvloei-afdeling.
3. Crack dit andersins:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Algemene foute wat jy kan uitbuit

- Dieselfde wagwoord word deur verskeie gebruikers hergebruik → crack een en beweeg lateraal.
- Afgekapte hashes / pasgemaakte transformasies → normaliseer en probeer weer.
- Swak KDF-parameters (bv. min PBKDF2-iterasies) → kan steeds gecrack word.

### Bcrypt-orakel met gekose invoer en ’n bygevoegde geheim

’n Aanroepbare helper wat `bcrypt(user_input || secret)` teruggee, kan inligting oor ’n bygevoegde geheim blootlê as die bcrypt-implementasie die invoer stilweg ná 72 **grepe** afkap. ’n Karakterlimiet wat voor UTF-8-enkodering toegepas word, dwing nie daardie greeplimiet af nie: multigreepkarakters kan die bcrypt-invoer vul en net plek vir ’n klein voorvoegsel van die geheim laat. Gekose invoere en die hashes wat daarvoor teruggegee word, kan dan vanlyn kontroles van kandidaat-agtervoegselgrepe moontlik maak. Dit vereis beheer oor die helper se invoer, kennis van die presiese transformasie en enkodering daarvan, en ’n implementasie wat werklik afkap; ’n aanroepbare helper of ’n bcrypt-hash alleen bewys nie dat hierdie ketting bestaan nie. [pyca/bcrypt dokumenteer](https://github.com/pyca/bcrypt#maximum-password-length) dat die huidige `hashpw` ’n fout veroorsaak vir invoere langer as 72 grepe, terwyl vroeëre gedrag dit stilweg afgekap het. Ander omhulsels kan lang invoere vooraf hash of verwerp, dus moet jy die geïnstalleerde implementasie nagaan eerder as om afkapping te aanvaar.

Om ’n herwonne geheim teen ’n ander rekening te gebruik, vereis ook bewyse dat die blootgestelde hash met **dieselfde** geheim en transformasie gegenereer is, plus ’n afsonderlike toegangspad of aanmeldpad. ’n Hashing-helper wat as root loop, behoort slegs as ’n orakel beskou te word as die gebruiker met laer voorregte dit onder die geldende beleid kan aanroep; passiewe gasheerenumerasie hoef dit nie aan te roep of gekose wagwoorde in te dien nie.

## References

- [1] [SkullSecurity - Alles wat jy moet weet oor hash-lengte-uitbreidingsaanvalle](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Die HMAC (Keyed-Hash Message Authentication Code)](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP-kontrolelys vir wagwoordberging](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat-voorbeeldhashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper-opdragreëlopsies](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python-bindings vir HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash- en SequenceMAC-spesifikasie](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing vir die res van ons](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python-implementasie](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash-toetsvektore](https://github.com/C2SP/CCTV/tree/main/sequencehash)
