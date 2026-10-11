# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Miundo ya kawaida ya CTF

- "Signature" ni `hash(secret || message)` kwa kweli → length extension.
- Password hashes zisizo na salt → cracking ya kurudia haraka zaidi na mashambulizi ya lookup yaliyotayarishwa mapema.
- Kuchanganya hash na MAC (hash != uthibitishaji).

## Hash length extension attack

### Mbinu

Length-extension attack inaweza kuwezekana pale server inapokokotoa "signature" kama:

`sig = HASH(secret || message)`

na kutumia hash ya Merkle-Damgård kama MD5, SHA-1 au SHA-256.

Ikiwa unajua:

- `message`
- `sig`
- hash function
- (au unaweza kubashiri kwa brute-force) `len(secret)`

Basi unaweza kukokotoa signature halali ya:

`message || padding || appended_data`

bila kujua secret.<sup>[[1]](#references)</sup>

### Kizuizi muhimu: HMAC haiathiriwi

Length-extension attacks hutumika kwa miundo dhaifu ya prefix kama `HASH(secret || message)`. Hazifichui muundo wa HMAC (kwa mfano, HMAC-SHA256), ambao huunganisha key na matumizi tofauti ya hash ya ndani na ya nje.<sup>[[1]](#references)[[2]](#references)</sup>

### Zana

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings za zana ya length-extension ya HashPump<sup>[[7]](#references)</sup>

### Maelezo mazuri

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Kuhash password na kuzivunja

### Maswali ya kwanza<sup>[[4]](#references)</sup>

- Je, ina **salt**? (tafuta miundo ya `salt$hash`)
- Je, ni **fast hash** (MD5/SHA1/SHA256) au **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
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

- Password ileile kutumiwa tena na watumiaji tofauti → vunja moja, kisha endelea.
- Hashes zilizokatwa / transforms maalum → sanifisha kisha ujaribu tena.
- Vigezo dhaifu vya KDF (kwa mfano, iterations chache za PBKDF2) → bado zinaweza kuvunjwa.

### bcrypt oracle ya input iliyochaguliwa yenye secret iliyoambatishwa

Helper inayoweza kuitwa na kurudisha `bcrypt(user_input || secret)` inaweza kufichua taarifa kuhusu secret iliyoambatishwa ikiwa utekelezaji wake wa bcrypt unakata input kimyakimya baada ya **bytes** 72. Kikomo cha idadi ya herufi kabla ya UTF-8 encoding hakihakikishi kikomo hicho cha bytes: herufi za multibyte zinaweza kujaza input ya bcrypt huku zikiacha nafasi ya prefix ndogo tu ya secret. Inputs zilizochaguliwa na hashes zake zilizorejeshwa zinaweza kisha kuruhusu ukaguzi wa candidate suffix bytes nje ya mtandao. Hili linahitaji uwezo wa kudhibiti input ya helper, kujua transform na encoding yake halisi, na kutumia implementation inayokata input kweli; kuwepo kwa helper inayoweza kuitwa au bcrypt hash pekee hakuthibitishi mlolongo huu. [pyca/bcrypt documents](https://github.com/pyca/bcrypt#maximum-password-length) kwamba `hashpw` za sasa hutoa error kwa inputs zinazozidi bytes 72, ilhali tabia ya awali ilikuwa kuzikata kimyakimya. Wrappers nyingine zinaweza kufanya prehash au kukataa inputs ndefu, kwa hiyo hakiki implementation iliyosakinishwa badala ya kudhani kwamba inakata input.

Kutumia secret iliyopatikana dhidi ya akaunti nyingine pia kunahitaji ushahidi kwamba hash yake iliyoonekana ilitengenezwa kwa **secret** na transform ileile, pamoja na credential au njia tofauti ya kuingia. Helper ya hashing inayoendeshwa na root inapaswa kuchunguzwa kama oracle ikiwa tu mtumiaji mwenye ruhusa za chini anaweza kuiita chini ya sera inayotumika; kufanya enumeration ya host bila kuiita au kuwasilisha password zilizochaguliwa kunaweza kutosha.

## References

- [1] [SkullSecurity - Kila kitu unachohitaji kujua kuhusu mashambulizi ya hash length-extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Msimbo wa Uthibitishaji wa Ujumbe wa Keyed-Hash](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Karatasi ya Mwongozo wa Kuhifadhi Password](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - Hashes za mfano](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Chaguo za command-line](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings za HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
