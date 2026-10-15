# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Mifumo ya kawaida ya CTF

- "Signature" ni `hash(secret || message)` kwa kweli → length extension.
- Password hashes zisizo na salt → kuvunjwa kwa haraka zaidi kwa majaribio yanayorudiwa na mashambulizi ya utafutaji wa thamani zilizokokotolewa awali.
- Kuchanganya hash na MAC (hash != authentication).

## Utafutaji wa MD5 hash kwa kutumia ingizo lililochaguliwa

Mifano hii ya Python hutafuta mifumo miwili tofauti ya matokeo: MD5 suffix iliyochaguliwa na thamani ya MD5 inayoanza na `0e` ikifuatiwa na tarakimu pekee. Mfumo wa pili ni muhimu programu inapolinganisha mifuatano ya nambari bila ukaguzi mkali wa aina; angalia tabia mahususi ya PHP na tahadhari kuhusu matoleo katika [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force ya MD5 hash suffix

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

### Uzalishaji wa hash ya MD5 0e kwa ulinganisho legevu

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

## Shambulio la kuongeza urefu wa hash

### Mbinu

Shambulio la kuongeza urefu linaweza kuwezekana seva inapokokotoa "sahihi" kama:

`sig = HASH(secret || message)`

na kutumia hash ya Merkle-Damgård kama MD5, SHA-1, au SHA-256.

Ikiwa unajua:

- `message`
- `sig`
- hash function
- (au unaweza kubashiri kwa nguvu) `len(secret)`

Basi unaweza kukokotoa sahihi halali ya:

`message || padding || appended_data`

bila kujua secret.<sup>[[1]](#references)</sup>

### Kizuizi muhimu: HMAC haiathiriwi

Mashambulio ya kuongeza urefu yanahusu miundo ya prefix iliyo hatarini kama `HASH(secret || message)`. Hayafichui muundo wa HMAC (kwa mfano, HMAC-SHA256), ambao huunganisha ufunguo na matumizi tofauti ya hash ya ndani na ya nje.<sup>[[1]](#references)[[2]](#references)</sup>

### Zana

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings za zana ya kuongeza urefu ya HashPump<sup>[[7]](#references)</sup>

### Maelezo mazuri

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing ya tuple yenye utata na MACs

### Shambulio la kuchanganya mipaka

API za hash za nyongeza hazithibitishi mipaka ya miito. `update(A); update(B)` huhash mfuatano uleule wa baiti kama `update(A + B)`. Kwa hivyo, kuhash au kutumia MAC kwenye muunganiko ghafi hakuthibitishi tuple. Ikiwa sehemu zilizo karibu zina urefu tofauti, mshambuliaji anaweza kugawa upya baiti hizo kuwa tuple tofauti bila kupata collision katika hash ya msingi:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Hili huwa rahisi kushambuliwa verifier anapoamini kuwa digest inafunga maana za field, lakini ingizo linalodhibitiwa na mshambuliaji linaweza kufikia parser au hatua tofauti ya protocol inayoweka mipaka mingine. Commitments zinaweza kupata openings mbadala, na transcripts za Fiat-Shamir zinaweza kutafsiriwa kama statements tofauti. HMAC huzuia [hash length extension](#hash-length-extension-attack), lakini `HMAC(K, A || B)` bado ina utata huu wa usimbaji wa tuple kwa sababu tuple zote mbili huzalisha bytes zilezile za ujumbe.<sup>[[8]](#references)[[9]](#references)</sup>

Tumia mtiririko huu wa ukaguzi kupima kama usimbaji wa tuple wenye utata unavuka mpaka wa usalama.<sup>[[8]](#references)[[9]](#references)</sup>

1. Tafuta `HASH(A || B)`, `HMAC(K, A || B)`, na mfululizo wa miito ya `update()`/`Write()` inayochakata field mbili au zaidi.
2. Weka alama kwa kila field inayodhibitiwa na mshambuliaji au yenye urefu unaobadilika. Jaribu kuhamisha bytes kutoka upande mmoja wa kila mpaka hadi mwingine huku mfuatano mzima uliounganishwa ukibaki vilevile. Jumuisha field tupu.
3. Kagua mipango ya vitenganishi ili kubaini kama ingizo linaweza kuwa na bytes za kitenganishi, kama kuna kutokubaliana kuhusu escaping, na kama muundo husimba urefu wa baadhi tu ya field.
4. Fuatilia jinsi kila mtumiaji anavyochanganua bytes zilizothibitishwa. Mgawanyo mbadala una umuhimu tu ikiwa unabadilisha uamuzi wa usalama, proof statement, record, transaction au commitment opening. Field zenye upana usiobadilika au serialization ya kawaida isiyo na utata huzuia shambulio hili mahususi.
5. Kagua kama digest ileile iliyosimbwa inakubaliwa katika toleo jingine la protocol, aina nyingine ya ujumbe, raundi nyingine au programu nyingine. Funga miktadha hii waziwazi badala ya kutegemea callers kuitenganisha.

### SequenceHash na SequenceMAC

SequenceHash ni ujenzi usiofungamana na aina maalum ya hash kwa mfuatano wa byte strings. Kila operesheni ya `add()` ni ya atomiki: huongeza thamani na kiambishi tamati cha urefu cha byte 16, chenye mpangilio wa little-endian, kwenye inner hash. Thamani tupu hubaki vitu tofauti. Outer hash huzuia kufichuliwa kwa hali ya inner inayoweza kurefushwa, huku string ya hiari ya customization ikitoa utenganishaji wa domain. Usibadilishe `add()` na miito ya kawaida ya write ya API ya hash ya msingi.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Chagua customizer kama sehemu ya ufafanuzi wa protocol, ukiweka maelezo ya kutosha kutofautisha application, toleo la protocol, aina ya ujumbe na round. SequenceHash bado inahitaji wahusika wote wakubaliane kuhusu mpangilio wa sehemu, byte encoding na canonical serialization, na haiwezi kulinda sehemu iliyoachwa. Ports zinapaswa kujaribiwa dhidi ya test vectors za kati na za mwisho za C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Kwa authentication, SequenceMAC hutoa interface ileile ya atomic encoding na customization. Inahitaji key yenye angalau byte 32. Tofauti na HMAC key preprocessing, headers zake hufunga urefu halisi wa key: raw key ndefu si sawa na prehash yake, na kuongeza byte sifuri hubadilisha key. Tofauti hii ni muhimu wakati components zinapokubali namna tofauti za kuwakilisha key au metadata ya urefu.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

API ya Python na utekelezaji sawia wa Go na Rust vinapatikana kama marejeo, lakini utekelezaji wa protocol unapaswa kufuata specification hai ya C2SP badala ya kuunda upya encoding kutokana na muhtasari huu.<sup>[[8]](#references)[[10]](#references)</sup>

## Hashing na kuvunja nywila

### Maswali ya kwanza<sup>[[4]](#references)</sup>

- Je, ina **salt**? (tafuta miundo ya `salt$hash`)
- Je, ni **hash ya haraka** (MD5/SHA1/SHA256) au **KDF ya polepole** (bcrypt/scrypt/argon2/PBKDF2)?
- Je, una **kidokezo cha format** (hashcat mode / John format)?

### Mchakato wa vitendo<sup>[[5]](#references)[[6]](#references)</sup>

1. Tambua hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Ikiwa haina salt na ni ya kawaida: jaribu DB za mtandaoni na zana za utambuzi kutoka sehemu ya crypto workflow.
3. Vinginevyo, ivunje:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Makosa ya kawaida unayoweza kutumia

- Nywila ileile imetumiwa tena na watumiaji tofauti → vunja moja, kisha tumia ufikiaji huo kuendelea.
- Hash zilizokatwa / mabadiliko maalum → zirekebishe ziwe katika muundo sanifu kisha ujaribu tena.
- Vigezo dhaifu vya KDF (kwa mfano, idadi ndogo ya marudio ya PBKDF2) → bado vinaweza kuvunjwa.

### Oracle ya bcrypt yenye input iliyochaguliwa na secret iliyoongezwa

Helper inayoweza kuitwa na kurudisha `bcrypt(user_input || secret)` inaweza kufichua taarifa kuhusu secret iliyoongezwa ikiwa utekelezaji wake wa bcrypt hukata input kimyakimya baada ya **bytes** 72. Kikomo cha idadi ya herufi kabla ya UTF-8 encoding hakihakikishi kikomo hicho cha bytes: herufi za multibyte zinaweza kujaza input ya bcrypt na kuacha nafasi ya kiambishi kidogo tu cha secret. Input zilizochaguliwa na hash zake zilizorejeshwa zinaweza kuruhusu ukaguzi wa offline wa bytes zinazoweza kuwa mwishoni. Hili linahitaji udhibiti wa input ya helper, uelewa wa mabadiliko na encoding yake kamili, na utekelezaji unaokata input kweli; helper inayoweza kuitwa au hash ya bcrypt pekee havithibitishi mfuatano huo. [pyca/bcrypt inaeleza](https://github.com/pyca/bcrypt#maximum-password-length) kwamba `hashpw` ya sasa hutoa hitilafu kwa input zinazozidi bytes 72, ilhali matoleo ya awali yalizikata kimyakimya. Wrappers nyingine zinaweza kufanya prehash au kukataa input ndefu, kwa hiyo thibitisha utekelezaji uliosakinishwa badala ya kudhani kuwa unakata input.

Kutumia secret iliyopatikana dhidi ya akaunti nyingine pia kunahitaji ushahidi kwamba hash yake iliyofichuliwa ilitengenezwa kwa **secret** na mabadiliko yaleyale, pamoja na njia tofauti ya kupata credential au kuingia. Helper ya hashing inayoendeshwa kama root inapaswa kuchukuliwa kama oracle tu ikiwa mtumiaji mwenye ruhusa za chini anaweza kuiita chini ya sera inayotumika; kuorodhesha host bila kuingilia si lazima kuhitaji kuiita au kuitumia kuwasilisha nywila zilizochaguliwa.

## References

- [1] [SkullSecurity - Kila kitu unachohitaji kujua kuhusu mashambulizi ya kuongeza urefu wa hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Msimbo wa uthibitishaji wa ujumbe wa Keyed-Hash](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings for HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Specification ya SequenceHash na SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing kwa ajili ya kila mtu](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Utekelezaji wa SequenceHash kwa Python](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Vekta za majaribio za SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
