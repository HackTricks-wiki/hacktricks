# Hashes, MACs na KDFs

{{#include ../../banners/hacktricks-training.md}}

## Mifumo ya kawaida ya CTF

- "Saini" kwa kweli ni `hash(secret || message)` → length extension.
- Password hashes zisizo na salt → kurahisisha cracking ya mara kwa mara na mashambulizi ya lookup yaliyotayarishwa mapema.
- Kuchanganya hash na MAC (hash != authentication).

## Shambulio la hash length extension

### Mbinu

Shambulio la length extension linaweza kufanikiwa wakati server inakokotoa "saini" kama:

`sig = HASH(secret || message)`

na kutumia hash ya Merkle-Damgård kama MD5, SHA-1 au SHA-256.

Ukiwa na:

- `message`
- `sig`
- hash function
- (au ukiweza kubrute-force) `len(secret)`

Basi unaweza kukokotoa saini halali ya:

`message || padding || appended_data`

bila kujua secret.<sup>[[1]](#references)</sup>

### Kizuizi muhimu: HMAC haiathiriwi

Mashambulizi ya length extension hutumika kwa miundo ya prefix iliyo hatarini kama `HASH(secret || message)`. Hayafichui muundo wa HMAC (kwa mfano, HMAC-SHA256), unaounganisha key na matumizi tofauti ya hash ya ndani na ya nje.<sup>[[1]](#references)[[2]](#references)</sup>

### Zana

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings za zana ya length extension ya HashPump<sup>[[7]](#references)</sup>

### Ufafanuzi mzuri

[Kila kitu unachohitaji kujua kuhusu mashambulizi ya hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing na cracking

### Maswali ya kwanza<sup>[[4]](#references)</sup>

- Ina **salt**? (tafuta miundo ya `salt$hash`)
- Ni **fast hash** (MD5/SHA1/SHA256) au **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Una **dokezo la format** (hashcat mode / John format)?

### Mchakato wa vitendo<sup>[[5]](#references)[[6]](#references)</sup>

1. Tambua hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Ikiwa haina salt na ni ya kawaida: jaribu DB za mtandaoni na zana za kuitambua kutoka sehemu ya crypto workflow.
3. Vinginevyo, ifanye cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Makosa ya kawaida unayoweza kutumia

- Password ileile inatumika tena na watumiaji tofauti → crack moja, kisha pivot.
- Hashes zilizokatwa / mabadiliko maalum → zisawazishe kisha ujaribu tena.
- Vigezo dhaifu vya KDF (kwa mfano, PBKDF2 yenye iterations chache) → bado zinaweza kufanyiwa cracking.

### Oracle ya bcrypt inayokubali ingizo lililochaguliwa pamoja na secret iliyoongezwa

Helper inayoweza kuitwa na kurudisha `bcrypt(user_input || secret)` inaweza kufichua taarifa kuhusu secret iliyoongezwa ikiwa utekelezaji wake wa bcrypt unakata ingizo kimyakimya baada ya **bytes** 72. Kikomo cha idadi ya herufi kabla ya UTF-8 encoding hakihakikishi kikomo hicho cha bytes: herufi za multibyte zinaweza kujaza ingizo la bcrypt na kuacha nafasi ya prefix ndogo tu ya secret. Ingizo zilizochaguliwa na hashes zake zilizorejeshwa zinaweza kuruhusu ukaguzi wa nje ya mtandao wa bytes za suffix zinazowezekana. Hili linahitaji uwezo wa kudhibiti ingizo la helper, kujua transform na encoding yake halisi, na utekelezaji unaokata ingizo kwa kweli; helper inayoweza kuitwa au bcrypt hash pekee havithibitishi mnyororo huo. [pyca/bcrypt documents](https://github.com/pyca/bcrypt#maximum-password-length) kwamba `hashpw` za sasa husababisha error kwa ingizo zinazozidi bytes 72, ilhali matoleo ya awali yalizikata kimyakimya. Wrappers nyingine zinaweza kufanya prehash au kukataa ingizo ndefu, kwa hiyo hakiki utekelezaji uliosakinishwa badala ya kudhani kuwa unakata ingizo.

Kutumia secret iliyopatikana dhidi ya akaunti tofauti pia kunahitaji ushahidi kwamba hash yake iliyofichuliwa ilitengenezwa kwa **secret** na transform ileile, pamoja na credential au njia tofauti ya kuingia. Helper ya hashing inayoendeshwa na root inapaswa kuchukuliwa kuwa oracle ikiwa tu mtumiaji mwenye ruhusa za chini anaweza kuiendesha chini ya sera inayotumika; kuorodhesha host bila kuingilia hakuhitaji kuiendesha au kuwasilisha passwords zilizochaguliwa.

## References

- [1] [SkullSecurity - Kila kitu unachohitaji kujua kuhusu mashambulizi ya hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Msimbo wa uthibitishaji wa ujumbe wa Keyed-Hash](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Karatasi ya mwongozo wa kuhifadhi Password](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - Hashes za mfano](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Chaguo za mstari wa amri](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings za HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
