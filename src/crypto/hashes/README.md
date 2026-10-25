# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Mifumo ya kawaida ya CTF

- `"Signature"` kwa kweli ni `hash(secret || message)` → length extension.
- Hashes za password zisizo na salt → cracking ya mara kwa mara kwa kasi zaidi na attacks za lookup zilizokokotolewa mapema.
- Kuchanganya hash na MAC (hash != authentication).

## Utafutaji wa hash za MD5 kwa input iliyochaguliwa

Mifano hii ya Python hutafuta mifumo miwili tofauti ya matokeo: suffix ya MD5 iliyochaguliwa na thamani ya MD5 inayoanza na `0e` ikifuatiwa na tarakimu pekee. Mfumo wa pili unahusika pale programu inapolinganisha strings za nambari bila ukaguzi mkali; tazama tabia na tahadhari za matoleo mahususi kwa PHP katika [ulinganisho usio mkali wa PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force ya suffix ya hash ya MD5

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

Shambulio la kuongeza urefu linaweza kuwezekana wakati seva inakokotoa "saini" kama:

`sig = HASH(secret || message)`

na kutumia hash ya Merkle-Damgård kama MD5, SHA-1, au SHA-256.

Ukijua:

- `message`
- `sig`
- hash function
- (au unaweza kubashiri kwa nguvu) `len(secret)`

Basi unaweza kukokotoa saini halali ya:

`message || padding || appended_data`

bila kujua siri.<sup>[[1]](#references)</sup>

### Kizuizi muhimu: HMAC haiathiriwi

Mashambulizi ya kuongeza urefu hutumika kwa miundo dhaifu ya prefix kama `HASH(secret || message)`. Hayafichui muundo wa HMAC (kwa mfano, HMAC-SHA256), ambao huchanganya ufunguo na matumizi tofauti ya hash ya ndani na ya nje.<sup>[[1]](#references)[[2]](#references)</sup>

Kwa maelezo ya jinsi ya kupata na kujaribu saini hizi katika web APIs, angalia [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Zana

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings za zana ya kuongeza urefu ya HashPump<sup>[[7]](#references)</sup>

### Maelezo mazuri

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing na MAC za tuple zenye utata

### Shambulio la kuchanganya mipaka

Hash APIs za incremental hazithibitishi mipaka ya miito. `update(A); update(B)` huhash mfuatano uleule wa byte kama `update(A + B)`. Kwa hiyo, kuhash au kutengeneza MAC kwa mfuatano ghafi hakuthibitishi tuple. Ikiwa sehemu zilizo karibu zina urefu unaobadilika, mshambuliaji anaweza kugawa upya byte hizo katika tuple tofauti bila kupata collision katika hash ya msingi:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Hili huwa exploitable verifier inapoamini kwamba digest inafunga maana za sehemu za data, lakini ingizo linalodhibitiwa na mshambuliaji linaweza kufikia parser au hatua tofauti ya protocol inayoweka mipaka mingine. Commitments zinaweza kupata namna mbadala za kufunguliwa, na transcript za Fiat-Shamir zinaweza kufasiriwa kama kauli tofauti. HMAC huzuia [hash length extension](#hash-length-extension-attack), lakini `HMAC(K, A || B)` bado ina utata huu wa usimbaji wa tuple, kwa sababu tuple zote mbili hutoa baiti zilezile za ujumbe.<sup>[[8]](#references)[[9]](#references)</sup>

Tumia mtiririko huu wa ukaguzi ili kubaini kama usimbaji wa tuple wenye utata unavuka mpaka wa usalama.<sup>[[8]](#references)[[9]](#references)</sup>

1. Tafuta `HASH(A || B)`, `HMAC(K, A || B)`, na miito ya `update()`/`Write()` mfululizo inayotumika kwa sehemu mbili au zaidi.
2. Weka alama kwenye kila sehemu inayodhibitiwa na mshambuliaji au yenye urefu unaobadilika. Jaribu kuhamisha baiti kutoka upande mmoja wa kila mpaka hadi mwingine huku jumla ya mfuatano ikibaki ileile. Jumuisha sehemu tupu.
3. Kagua mipango ya vitenganishi ili kubaini kama ingizo linaweza kuwa na baiti za kitenganishi, kama kuna kutokubaliana kuhusu namna ya kuficha au kutoroka baiti hizo, na kama baadhi tu ya sehemu ndizo zinazosimbwa pamoja na urefu wake.
4. Fuatilia jinsi kila mtumiaji anavyochanganua baiti zilizothibitishwa. Jaribio lina maana tu ikiwa ugawaji mbadala unabadilisha uamuzi wa usalama, kauli ya uthibitisho, rekodi, muamala au ufunguzi wa commitment. Sehemu zenye upana usiobadilika au usimbaji sanifu na usio na utata huzuia shambulio hili mahususi.
5. Angalia kama digest ileile iliyosimbwa inakubaliwa katika toleo jingine la protocol, aina nyingine ya ujumbe, raundi nyingine au programu nyingine. Funga miktadha hii waziwazi badala ya kutegemea wapigaji wake kuitenganisha.

### SequenceHash na SequenceMAC

SequenceHash ni ujenzi usiofungamana na aina mahususi ya hash kwa mfuatano wa nyuzi za baiti. Kila operesheni ya `add()` ni ya atomiki: huongeza thamani na kiambishi tamati kisichobadilika cha baiti 16 kinachoonyesha urefu kwa mpangilio wa little-endian kwenye hash ya ndani. Thamani tupu hubaki vitu tofauti. Hash ya nje huzuia hali ya ndani inayoweza kuongezewa urefu kufichuliwa, huku mfuatano wa hiari wa ubinafsishaji ukitoa utenganishaji wa domain. Usibadilishe `add()` na miito ya kawaida ya uandishi ya API ya hash ya msingi.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Chagua customizer kama sehemu ya ufafanuzi wa protocol, ukijumuisha maelezo ya kutosha kutofautisha application, toleo la protocol, aina ya ujumbe na round. SequenceHash bado inahitaji wahusika wote wakubaliane kuhusu mpangilio wa field, usimbaji wa byte na serialization kanoniki, na haiwezi kulinda field iliyoachwa. Port zinapaswa kujaribiwa dhidi ya intermediate na final test vectors za C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Kwa authentication, SequenceMAC hutoa kiolesura kilekile cha usimbaji atomiki na customization. Inahitaji key yenye urefu wa angalau byte 32. Tofauti na uchakataji wa awali wa key wa HMAC, headers zake hujumuisha urefu halisi wa key: raw key ndefu si sawa na prehash yake, na kuongeza byte sifuri hubadilisha key. Tofauti hii ni muhimu pale ambapo components zinakubali uwakilishi tofauti wa key au metadata ya urefu.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

API ya Python na utekelezaji sawia wa Go na Rust zinapatikana kama marejeo, lakini utekelezaji wa protocol unapaswa kufuata specification hai ya C2SP badala ya kuunda upya encoding kutoka muhtasari huu.<sup>[[8]](#references)[[10]](#references)</sup>

## Hashing na cracking ya password

### Maswali ya kwanza<sup>[[4]](#references)</sup>

- Ina **salt**? (tafuta fomati za `salt$hash`)
- Ni **fast hash** (MD5/SHA1/SHA256) au **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Una **kidokezo cha fomati** (hashcat mode / John format)?

### Utaratibu wa vitendo<sup>[[5]](#references)[[6]](#references)</sup>

1. Tambua hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Ikiwa haina salt na ni ya kawaida: jaribu DB za mtandaoni na zana za utambuzi kutoka sehemu ya crypto workflow.
3. Vinginevyo, ifanye cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Makosa ya kawaida unayoweza kutumia

- Password ileile imetumiwa tena na watumiaji tofauti → crack moja, kisha pivot.
- Hash zilizokatwa / transforms maalum → zisawazishe na ujaribu tena.
- Vigezo dhaifu vya KDF (kwa mfano, idadi ndogo ya PBKDF2 iterations) → bado zinaweza kufanyiwa cracking.

### bcrypt oracle ya ingizo lililochaguliwa yenye secret iliyoongezwa

Helper inayoweza kuitwa na kurudisha `bcrypt(user_input || secret)` inaweza kufichua taarifa kuhusu secret iliyoongezwa ikiwa utekelezaji wake wa bcrypt unakata ingizo kimyakimya baada ya **bytes** 72. Kikomo cha idadi ya herufi kinachotumika kabla ya UTF-8 encoding hakihakikishi kikomo hicho cha bytes: herufi za multibyte zinaweza kujaza ingizo la bcrypt huku zikiacha nafasi ya prefix ndogo tu ya secret. Ingizo zilizochaguliwa na hash zake zinazorudishwa zinaweza kuruhusu ukaguzi wa candidate suffix bytes bila kuunganisha kwenye mfumo. Hili linahitaji udhibiti wa ingizo la helper, ufahamu wa transform na encoding yake halisi, na utekelezaji unaokata ingizo kweli; helper inayoweza kuitwa au hash ya bcrypt peke yake haithibitishi mlolongo huu. [pyca/bcrypt inaeleza](https://github.com/pyca/bcrypt#maximum-password-length) kwamba `hashpw` ya sasa hutupa error kwa ingizo lenye zaidi ya bytes 72, ilhali tabia ya awali ilikuwa kuyakata kimyakimya. Wrappers nyingine zinaweza kufanya prehash au kukataa ingizo refu, kwa hiyo hakiki utekelezaji uliosakinishwa badala ya kudhani kuwa unakata ingizo.

Kutumia secret iliyopatikana dhidi ya account tofauti pia kunahitaji ushahidi kwamba hash yake iliyofichuliwa ilitengenezwa kwa secret na transform **ileile**, pamoja na credential au njia tofauti ya kuingia. Helper ya hashing inayoendeshwa na root inapaswa kuchukuliwa kama oracle tu ikiwa mtumiaji mwenye ruhusa za chini anaweza kuiita kulingana na policy inayotumika; kuorodhesha host bila kuingiliana nayo hakuhitaji kuiita au kutuma password zilizochaguliwa.

## References

- [1] [SkullSecurity - Kila kitu unachohitaji kujua kuhusu mashambulizi ya hash length-extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Uthibitishaji wa ujumbe wa Keyed-Hash](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Karatasi ya marejeo ya kuhifadhi Password](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - Hash za mfano](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Chaguo za mstari wa amri](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings za HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Specification ya SequenceHash na SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing kwa ajili yetu sote](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Utekelezaji wa SequenceHash wa Python](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Test vectors za SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
