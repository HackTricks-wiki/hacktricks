# Algoritimu za Kriptografia/Ukandamizaji

{{#include ../../banners/hacktricks-training.md}}

## Kutambua Algoritimu

Ikiwa unaishia kwenye code **inayotumia shift rights and lefts, xors and several arithmetic operations** kuna uwezekano mkubwa kwamba ni utekelezaji wa **algoritimu ya kriptografia**. Hapa itaonyeshwa njia kadhaa za **kutambua algorimu inayotumika bila kuhitaji ku-reverse kila hatua**.

### API functions

**CryptDeriveKey**

Ikiwa function hii inatumika, unaweza kupata ni **algoritimu gani inatumiwa** ukitazama thamani ya parameter ya pili:

![](<../../images/image (156).png>)

Tazama hapa jedwali la algorimu zinazowezekana na thamani zao: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Inakandamiza na kuondoa ukandamizaji kwa buffer ya data.

**CryptAcquireContext**

Kutoka [docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): The **CryptAcquireContext** function inatumiwa kupata handle kwa key container maalum ndani ya cryptographic service provider (CSP) fulani. **Handle iliyorejeshwa inatumiwa katika mwito wa CryptoAPI** functions zinazotumia CSP iliyochaguliwa.

**CryptCreateHash**

Inaanzisha hashing ya mtiririko wa data. Ikiwa function hii inatumika, unaweza kupata ni **algoritimu gani inatumiwa** ukitazama thamani ya parameter ya pili:

![](<../../images/image (549).png>)

\
Tazama hapa jedwali la algorimu zinazowezekana na thamani zao: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

Mara nyingine ni rahisi kutambua algorimu kutokana na ukweli kwamba inahitaji kutumia thamani maalum na ya kipekee.

![](<../../images/image (833).png>)

Ikiwa utatafuta constant ya kwanza kwenye Google, utapata kile unachokiona hapa:

![](<../../images/image (529).png>)

Kwa hiyo, unaweza kubashiri kuwa function iliyotengenezwa tena ni **kalkuleta ya sha256.**\
Unaweza kutafuta yoyote ya constants nyingine na utaona (pengine) matokeo yanayofanana.

### data info

Ikiwa code haina constant yoyote muhimu inaweza kuwa **inapakia taarifa kutoka sehemu .data**.\
Unaweza kufikia data hiyo, **kunda dword ya kwanza** na kuitafuta kwenye google kama tulivyofanya katika sehemu iliyopita:

![](<../../images/image (531).png>)

Katika kesi hii, ukitafuta **0xA56363C6** unaweza kupata kuwa inahusiana na **meza za algorimu ya AES**.

## RC4 **(Symmetric Crypt)**

### Characteristics

Inaundwa na sehemu kuu 3:

- **Initialization stage/**: Inaunda **jedwali la thamani kutoka 0x00 hadi 0xFF** (256 bytes jumla, 0x100). Jedwali hili kawaida linaitwa **Substitution Box** (au SBox).
- **Scrambling stage**: Itapitia **jedwali iliyotengenezwa hapo awali** (loop ya iteresheni 0x100, tena) ikibadilisha kila thamani kwa bytes za **semi-random**. Ili kuunda bytes hizi za semi-random, RC4 **key inatumiwa**. RC4 **keys** zinaweza kuwa **katika urefu wa 1 mpaka 256 bytes**, ingawa kawaida inapendekezwa iwe zaidi ya 5 bytes. Kwa kawaida, RC4 keys huwa 16 bytes kwa urefu.
- **XOR stage**: Mwisho, plain-text au cyphertext ina **XORed na thamani zilizotengenezwa hapo awali**. Function ya encrypt na decrypt ni ile ile. Kwa hili, **loop kupitia 256 bytes zilizotengenezwa** itafanywa mara nyingi kadri inavyohitajika. Hii kawaida inatambulika kwenye decompiled code kwa kutumia **%256 (mod 256)**.

> [!TIP]
> **Ili kutambua RC4 katika disassembly/decompiled code unaweza kuangalia kwa loops 2 za size 0x100 (zikitumia key) na kisha XOR ya input data na thamani 256 zilizotengenezwa awali katika loops mbili, pengine ikitumia %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Angalia nambari 256 inayotumika kama counter na jinsi 0 inavyoandikwa kila nafasi ya chars 256)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **Characteristics**

- Matumizi ya **substitution boxes na lookup tables**
- Inaweza **kutofautishwa AES kutokana na matumizi ya thamani maalum za lookup table** (constants). _Kumbuka kwamba **constant** inaweza kuwa **imehifadhiwa** katika binary **au kuundwa** _**dynamically**._
- **encryption key** lazima iwe **inaogawika kwa 16** (kawaida 32B) na kawaida **IV** ya 16B inatumiwa.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### Characteristics

- Ni nadra kupata malware ikitumia lakini kuna mifano (Ursnif)
- Rahisi kubaini kama algorimu ni Serpent au la kwa msingi wa urefu wake (function isiyoababa sana)

### Identifying

Katika picha ifuatayo angalia jinsi constant **0x9E3779B9** inavyotumiwa (kumbuka constant hii pia inatumiwa na algorimu nyingine za crypto kama **TEA** -Tiny Encryption Algorithm).\
Pia angalia **ukubwa wa loop** (**132**) na **idadi ya operesheni za XOR** katika maagizo ya **disassembly** na katika mfano wa **code**:

![](<../../images/image (547).png>)

Kama ilivyotajwa hapo awali, code hii inaweza kuonekana ndani ya decompiler kama **function ndefu sana** kwa sababu **hakuna jumps** ndani yake. Code iliyotengenezwa tena inaweza kuonekana kama ifuatavyo:

![](<../../images/image (513).png>)

Kwa hiyo, inawezekana kutambua algorimu hii ukikagua **magic number** na **initial XORs**, ukaona **function ndefu sana** na **kulinganisha** baadhi ya **maagizo** ya function ndefu **na utekelezaji** (kama shift left by 7 na rotate left by 22).

## RSA **(Asymmetric Crypt)**

### Characteristics

- Ngumu zaidi kuliko algorimu symmetric
- Hakuna constants! (utekelezaji maalum ni mgumu kuyatambua)
- KANAL (crypto analyzer) hufeli kutoa vidokezo kwa RSA kwa sababu inategemea constants.

### Identifying by comparisons

![](<../../images/image (1113).png>)

- Katika line 11 (kushoto) kuna `+7) >> 3` ambayo ni sawa na line 35 (kulia): `+7) / 8`
- Line 12 (kushoto) inacheki kama `modulus_len < 0x040` na katika line 36 (kulia) inacheki kama `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Characteristics

- Functions 3: Init, Update, Final
- Init zaweza kufanana

### Identify

**Init**

Unaweza kuwatambua wote kwa kuangalia constants. Kumbuka kwamba sha_init ina constant 1 ambayo MD5 haina:

![](<../../images/image (406).png>)

**MD5 Transform**

Angalia matumizi ya constants zaidi

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Ndogo na yenye ufanisi zaidi kwani kazi yake ni kugundua mabadiliko ya bahati nasibu kwenye data
- Inatumia lookup tables (hivyo unaweza kutambua constants)

### Identify

Angalia **lookup table constants**:

![](<../../images/image (508).png>)

Algoritimu ya CRC inaonekana kama:

![](<../../images/image (391).png>)

## APLib (Compression)

### Characteristics

- Hakuna constants zinazotambulika
- Unaweza kujaribu kuandika algorimu kwa python na kutafuta vitu vinavyofanana mtandaoni

### Identify

Grafu ni kubwa sana:

![](<../../images/image (207) (2) (1).png>)

Angalia **mabano 3 ya kulinganisha kutambua**:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 inahitaji wanakagua HashEdDSA kukata sig = R || s na kukataa scalar yoyote yenye `s \geq n`, ambapo `n` ni order ya group. Maktaba ya `elliptic` ya JS iliruka ukaguzi huo wa bound, hivyo mwizi yeyote anayejua pair halali `(msg, R || s)` anaweza kutengeneza saini mbadala `s' = s + k·n` na kuendelea kucode tena `sig' = R || s'`.
- Routines za verification zinatumia tu `s mod n`, kwa hivyo s' zote zinazolingana na `s` zinakubaliwa hata kama ni byte strings tofauti. Mifumo inayochukulia saini kama tokeni za ki-kanuni (blockchain consensus, replay caches, DB keys, n.k.) inaweza kusababisha kutokuridhika kwa sababu utekelezaji mkali utakata s'.
- Unapokagua code nyingine ya HashEdDSA, hakikisha parser inathibitisha point `R` na urefu wa scalar; jaribu kuongeza mara nyingi `n` kwenye `s` inayojulikana kama nzuri ili kuthibitisha verifier inafungwa (fails closed).

### ECDSA truncation vs. leading-zero hashes

- Verifiers za ECDSA lazima zitumie bits za kushoto pekee `log2(n)` za message hash `H`. Katika `elliptic`, helper ya truncation ilihesabu `delta = (BN(msg).byteLength()*8) - bitlen(n)`; constructor ya `BN` inaondoa leading zero octets, hivyo hash yoyote inaanza na ≥4 zero bytes kwenye curves kama secp192r1 (192-bit order) ilionekana kuwa 224 bits badala ya 256.
- Verifier ilishift kulia kwa 32 bits badala ya 64, ikazalisha `E` isiyolingana na thamani iliyotumika na signer. Saini halali kwa hizo hashes kwa hivyo zinafaula kwa uwezekano ≈`2^-32` kwa input za SHA-256.
- Toa vector zote "zimefaa" pamoja na variants zenye leading-zero (kwa mfano, Wycheproof `ecdsa_secp192r1_sha256_test.json` case `tc296`) kwa utekelezaji lengwa; ikiwa verifier haikubaliani na signer, umepata hitilafu ya truncation inayoweza kutumiwa.

### Exercising Wycheproof vectors against libraries
- Wycheproof inakuja na sets za majaribio za JSON zinazoencode points zilizoharibika, scalars zinazosogezeka (malleable), hashes zisizo za kawaida na corner cases nyingine. Kujenga harness kuzunguka `elliptic` (au maktaba yoyote ya crypto) ni rahisi: pakua JSON, deserializa kila kesi ya mtihani, na hakikisha utekelezaji unalingana na flag ya `result` inayotarajiwa.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Kushindwa kunapaswa kupangwa ili kutofautisha spec violations na false positives. Kwa mende miwili hapo juu, kesi za Wycheproof zilizoanguka zilionyesha mara moja ukosefu wa ukaguzi wa wigo wa scalar (EdDSA) na kukatwa isiyosahihi kwa hash (ECDSA).
- Jumuisha harness kwenye CI ili regressions katika scalar parsing, hash handling, au coordinate validity zichochee mitihani mara tu zinapotokea. Hii ni hasa muhimu kwa high-level languages (JS, Python, Go) ambapo ubadilishaji mdogo wa bignum ni rahisi kukosewa.

## References

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
