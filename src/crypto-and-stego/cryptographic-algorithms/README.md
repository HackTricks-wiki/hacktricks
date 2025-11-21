# Algoritimu za Kriptografia/Ukandishaji

{{#include ../../banners/hacktricks-training.md}}

## Kutambua Algoritimu

Ikiwa unakutana na code **inayotumia shift rights and lefts, xors and several arithmetic operations** kuna uwezekano mkubwa kwamba ni utekelezaji wa **algoritimu ya kriptografia**. Hapa tutaonyesha njia kadhaa za **kutambua algoritimu inayotumika bila kuhitaji kureverse kila hatua**.

### API functions

**CryptDeriveKey**

Ikiwa function hii inatumiwa, unaweza kuona ni **algoritimu gani inayotumika** kwa kuchunguza thamani ya parameta wa pili:

![](<../../images/image (156).png>)

Tazama hapa jedwali la algoritimu zinazowezekana na thamani zao zilizoainishwa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Inabana na inafungua buffer ya data iliyotolewa.

**CryptAcquireContext**

From [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

Inaanzisha hashing ya mfululizo wa data. Ikiwa function hii inatumiwa, unaweza kuona ni **algoritimu gani inayotumika** kwa kuchunguza thamani ya parameta wa pili:

![](<../../images/image (549).png>)

\
Tazama hapa jedwali la algoritimu zinazowezekana na thamani zao zilizoainishwa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

Wakati mwingine ni rahisi kutambua algoritimu kwa sababu inahitaji kutumia thamani maalum na ya kipekee.

![](<../../images/image (833).png>)

Ikiutafuta constant ya kwanza kwenye Google hivi ndivyo utakavyopata:

![](<../../images/image (529).png>)

Kwa hiyo, unaweza kudhani kuwa function iliyotengenezwa tena ni **sha256 calculator.**\
Unaweza kutafuta yoyote ya constants nyingine na utapata (pengine) matokeo yanayofanana.

### data info

Ikiwa code haina constant muhimu inaweza kuwa inapakia taarifa kutoka kwenye sehemu ya .data.\
Unaweza kufikia data hiyo, **kuunganisha dword ya kwanza** na kuitafuta Google kama tulivyofanya katika sehemu iliyopita:

![](<../../images/image (531).png>)

Katika kesi hii, ukitafuta **0xA56363C6** utaona kuwa inalenga **meza za algoritmo ya AES**.

## RC4 **(Symmetric Crypt)**

### Sifa

Imejumuishwa sehemu kuu 3:

- **Initialization stage/**: Inaunda **jedwali la thamani kutoka 0x00 hadi 0xFF** (256 bytes jumla, 0x100). Jedwali hili kawaida huitwa **Substitution Box** (au SBox).
- **Scrambling stage**: Italazimika **kutembea kupitia jedwali** lililotengenezwa hapo awali (loop ya iteresheni 0x100, tena) ikibadilisha kila thamani kwa bytes **nusu-nasibu**. Ili kuunda bytes hizi nusu-nasibu, RC4 **key** inatumiwa. RC4 **keys** zinaweza kuwa kati ya **1 na 256 bytes kwa urefu**, hata hivyo kawaida inapendekezwa iwe zaidi ya 5 bytes. Kawaida, RC4 keys ni 16 bytes kwa urefu.
- **XOR stage**: Mwishowe, plain-text au ciphertext inafanyiwa **XOR** na thamani zilizoundwa hapo awali. Function ya kusimba na kufungua ni ile ile. Kwa hili, **loop kupitia bytes 256 zilizoundwa** itaendeshwa mara nyingi kama inavyohitajika. Hii kawaida inatambulika katika code iliyoreverse na **%256 (mod 256)**.

> [!TIP]
> **Ili kutambua RC4 katika disassembly/decompiled code unaweza kuangalia loops 2 za ukubwa 0x100 (wakati zinatumia key) na kisha XOR ya data ya ingizo na thamani 256 zilizoundwa hapo awali katika loop hizo 2, kwa kawaida zikitumia %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Angalia namba 256 inayotumika kama counter na jinsi 0 inavyoandikwa katika kila sehemu ya herufi 256)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### Sifa

- Matumizi ya **substitution boxes and lookup tables**
- Inawezekana **kutofautisha AES kutokana na matumizi ya thamani maalum za lookup table** (constants). _Kumbuka kuwa **constant** inaweza **kuhifadhiwa** katika binary **au kuundwa** _**dynamically**._
- The **encryption key** lazima iwe **divisible** kwa **16** (kawaida 32B) na kawaida **IV** ya 16B inatumiwa.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### Sifa

- Ni nadra kuona malware inayotumia lakini kuna mifano (Ursnif)
- Rahisi kubaini kama algoritimu ni Serpent au la kwa msingi wa urefu wake (function ndefu sana)

### Kutambua

Katika picha ifuatayo angalia jinsi constant **0x9E3779B9** inavyotumika (tumiaani kuwa constant hii pia inatumika na algorithm nyingine za crypto kama **TEA** -Tiny Encryption Algorithm).\
Pia angalia **ukubwa wa loop** (**132**) na **idadi ya operesheni za XOR** katika maagizo ya **disassembly** na katika mfano wa **code**:

![](<../../images/image (547).png>)

Kama ilivyotajwa hapo awali, code hii inaweza kuonekana ndani ya decompiler yoyote kama **function ndefu sana** kwa kuwa **hakuna jumps** ndani yake. Code iliyotengenezwa tena inaweza kuonekana kama ifuatavyo:

![](<../../images/image (513).png>)

Kwa hivyo, inawezekana kutambua algoritimu hii kwa kuangalia **magic number** na **XOR za awali**, kuona **function ndefu sana** na **kulinganisha** baadhi ya **maelekezo** ya function ndefu **na utekelezaji** (kama shift left kwa 7 na rotate left kwa 22).

## RSA **(Asymmetric Crypt)**

### Sifa

- Inayekuwa ngumu zaidi kuliko algoritimu za simetriki
- Hakuna constants! (utekelezaji maalum unakuwa mgumu kubaini)
- KANAL (a crypto analyzer) inashindwa kuonyesha vidokezo kwa RSA kwa sababu inategemea constants.

### Kutambua kwa kulinganisha

![](<../../images/image (1113).png>)

- Katika mstari 11 (kushoto) kuna `+7) >> 3` ambayo ni sawa na katika mstari 35 (kulia): `+7) / 8`
- Mstari 12 (kushoto) unakagua kama `modulus_len < 0x040` na mstari 36 (kulia) unakagua kama `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Sifa

- 3 functions: Init, Update, Final
- Functions za kuanzisha zinafanana

### Kutambua

**Init**

Unaweza kutambua zote kwa kuchunguza constants. Kumbuka kuwa sha_init ina constant 1 ambayo MD5 haina:

![](<../../images/image (406).png>)

**MD5 Transform**

Angalia matumizi ya constants nyingi zaidi

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Ndogo na yenye ufanisi kwa sababu kazi yake ni kugundua mabadiliko ya bahati nasibu katika data
- Inatumia lookup tables (kwa hivyo unaweza kutambua constants)

### Kutambua

Angalia **lookup table constants**:

![](<../../images/image (508).png>)

Algorithm ya CRC inaonekana kama:

![](<../../images/image (391).png>)

## APLib (Compression)

### Sifa

- Hakuna constants zinazotambulika
- Unaweza kujaribu kuandika algorithm kwa python na kutafuta mambo yanofanana mtandaoni

### Kutambua

Grafu ni kubwa kiasi:

![](<../../images/image (207) (2) (1).png>)

Angalia **misingi 3 ya kulinganisha ili kuitambua**:

![](<../../images/image (430).png>)

## Hitilafu za Utekelezaji wa Saini za Elliptic-Curve

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 inahitaji watakaguzi wa HashEdDSA wagawanye saini `sig = R || s` na wapige marufuku scalar yoyote yenye `s \geq n`, ambapo `n` ni group order. Maktaba ya JS `elliptic` iliruka ukaguzi huo wa kikomo, hivyo mshambulizi yeyote anayejua jozi halali `(msg, R || s)` anaweza kutengeneza saini mbadala `s' = s + k·n` na kuendelea kure-encode `sig' = R || s'`.
- Rutini za uthibitishaji zinatumia tu `s mod n`, kwa hivyo s' zote zenye kongruenti na s zinakubaliwa ingawa ni mfululizo wa byte tofauti. Mifumo inayotumia saini kama canonical tokens (blockchain consensus, replay caches, DB keys, etc.) zinaweza kupotoka kwa sababu utekelezaji mkali utakataza `s'`.
- Unapokagua code nyingine ya HashEdDSA, hakikisha parser inathibitisha point `R` na urefu wa scalar; jaribu kuongeza maradufu ya `n` kwa `s` inayojulikana kuwa nzuri ili kuthibitisha kuwa verifier itashindwa kufungwa (fails closed).

### ECDSA truncation vs. leading-zero hashes

- Watathibitishaji wa ECDSA wanapaswa kutumia tu bits kushoto za `log2(n)` za hash ya ujumbe `H`. Katika `elliptic`, msaidizi wa truncation alipata `delta = (BN(msg).byteLength()*8) - bitlen(n)`; constructor ya `BN` inaondoa octet za kuanzia zenye zero, kwa hivyo hash yoyote inaanza na ≥4 zero bytes kwenye curves kama secp192r1 (192-bit order) ilionekana kuwa 224 bits badala ya 256.
- Verifier ilishift kulia kwa 32 bits badala ya 64, ikazalisha `E` isiyolingana na thamani iliyotumika na signer. Hivyo saini halali kwa hayo hashes zitaanguka kwa uwezekano ≈`2^-32` kwa ingizo za SHA-256.
- Wasilisha vector zote “all good” na leading-zero variants (mfano, Wycheproof `ecdsa_secp192r1_sha256_test.json` kesi `tc296`) kwa utekelezaji lengwa; ikiwa verifier haitokubaliana na signer, umepata bug ya truncation inayoweza kutumika.

### Kutumia Wycheproof vectors dhidi ya maktaba
- Wycheproof inaletewa seti za mtihani za JSON zinazoweka malformed points, malleable scalars, unusual hashes na kesi nyingine za pembeni. Kujenga harness karibu na `elliptic` (au maktaba yoyote ya crypto) ni rahisi: pakia JSON, deserialize kila kesi ya mtihani, na thibitisha kuwa utekelezaji unaendana na bendera ya `result` inayotarajiwa.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Vifeli vinapaswa kuainishwa ili kutofautisha spec violations na false positives. Kwa mende mbili zilizo hapo juu, kesi zilizoshindwa za Wycheproof zilionyesha mara moja ukosefu wa ukaguzi wa wigo wa scalar (EdDSA) na kukatwa kwa hash isiyo sahihi (ECDSA).
- Jumlisha harness kwenye CI ili regressions katika uchambaji wa scalar, utunzaji wa hash, au uhalali wa kuratibu zizindue majaribio mara tu zinapotolewa. Hii ni hasa ya manufaa kwa lugha za ngazi ya juu (JS, Python, Go) ambapo mabadiliko madogo ya bignum ni rahisi kupotoka.

## Marejeo

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
