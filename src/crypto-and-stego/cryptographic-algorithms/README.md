# Cryptographic/Compression Algorithms

{{#include ../../banners/hacktricks-training.md}}

## Identifying Algorithms

Ikiwa unamaliza katika msimbo **ukitumia shift rights and lefts, xors na operesheni kadhaa za hesabu** ni uwezekano mkubwa kwamba ni utekelezaji wa **cryptographic algorithm**. Hapa kuna njia kadhaa za **kutambua algorithm inayotumika bila kuhitaji kubadilisha kila hatua**.

### API functions

**CryptDeriveKey**

Ikiwa kazi hii inatumika, unaweza kupata ni **algorithm gani inayotumika** ukichunguza thamani ya parameter ya pili:

![](<../../images/image (156).png>)

Angalia hapa jedwali la algorithms zinazowezekana na thamani zao zilizotolewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Inabana na kufungua buffer fulani ya data.

**CryptAcquireContext**

Kutoka [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Kazi ya **CryptAcquireContext** inatumika kupata mkono wa container maalum ya funguo ndani ya mtoa huduma maalum wa cryptographic (CSP). **Huu mkono uliorejeshwa unatumika katika wito wa kazi za CryptoAPI** zinazotumia CSP iliyochaguliwa.

**CryptCreateHash**

Inaanzisha hashing ya mtiririko wa data. Ikiwa kazi hii inatumika, unaweza kupata ni **algorithm gani inayotumika** ukichunguza thamani ya parameter ya pili:

![](<../../images/image (549).png>)

\
Angalia hapa jedwali la algorithms zinazowezekana na thamani zao zilizotolewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

Wakati mwingine ni rahisi sana kutambua algorithm kutokana na ukweli kwamba inahitaji kutumia thamani maalum na ya kipekee.

![](<../../images/image (833).png>)

Ikiwa unatafuta constant ya kwanza kwenye Google hii ndiyo unapata:

![](<../../images/image (529).png>)

Kwa hivyo, unaweza kudhani kwamba kazi iliyotolewa ni **sha256 calculator.**\
Unaweza kutafuta yoyote ya constants nyingine na utapata (labda) matokeo sawa.

### data info

Ikiwa msimbo huna constant yoyote muhimu inaweza kuwa **inapakia habari kutoka sehemu ya .data**.\
Unaweza kufikia data hiyo, **kundi la dword ya kwanza** na kutafuta katika google kama tulivyofanya katika sehemu iliyopita:

![](<../../images/image (531).png>)

Katika kesi hii, ikiwa utaangalia **0xA56363C6** unaweza kupata kwamba inahusiana na **meza za algorithm ya AES**.

## RC4 **(Symmetric Crypt)**

### Characteristics

Imepangwa kwa sehemu 3 kuu:

- **Initialization stage/**: Inaunda **meza ya thamani kutoka 0x00 hadi 0xFF** (256bytes kwa jumla, 0x100). Meza hii kwa kawaida inaitwa **Substitution Box** (au SBox).
- **Scrambling stage**: Itafanya **mzunguko kupitia meza** iliyoundwa hapo awali (mzunguko wa 0x100 iterations, tena) ikibadilisha kila thamani kwa **bytes za nadharia**. Ili kuunda hizi bytes za nadharia, funguo ya RC4 **inatumika**. Funguo za RC4 zinaweza kuwa **kati ya 1 na 256 bytes kwa urefu**, hata hivyo kawaida inapendekezwa iwe juu ya 5 bytes. Kwa kawaida, funguo za RC4 ni 16 bytes kwa urefu.
- **XOR stage**: Hatimaye, maandiko ya wazi au cyphertext **yanapigwa XOR na thamani zilizoundwa hapo awali**. Kazi ya kuandika na kufungua ni ile ile. Kwa hili, **mzunguko kupitia bytes 256 zilizoundwa** utafanywa mara nyingi kadri inavyohitajika. Hii kwa kawaida inatambuliwa katika msimbo uliotolewa na **%256 (mod 256)**.

> [!TIP]
> **Ili kutambua RC4 katika msimbo wa disassembly/decompiled unaweza kuangalia kwa mizunguko 2 ya ukubwa 0x100 (kwa kutumia funguo) na kisha XOR ya data ya ingizo na thamani 256 zilizoundwa hapo awali katika mizunguko 2 labda kwa kutumia %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Angalia nambari 256 inayotumika kama hesabu na jinsi 0 inavyoandikwa katika kila mahali pa wahusika 256)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **Characteristics**

- Matumizi ya **substitution boxes na lookup tables**
- Inawezekana **kutofautisha AES kutokana na matumizi ya thamani maalum za lookup table** (constants). _Kumbuka kwamba **constant** inaweza **kuhifadhiwa** katika binary **au kuundwa** _**dynamically**._
- Funguo ya **encryption** lazima iwe **inaweza kugawanywa** kwa **16** (kawaida 32B) na kawaida **IV** ya 16B inatumika.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### Characteristics

- Ni nadra kupata malware ikitumia lakini kuna mifano (Ursnif)
- Rahisi kubaini ikiwa algorithm ni Serpent au la kulingana na urefu wake (kazi ndefu sana)

### Identifying

Katika picha ifuatayo angalia jinsi constant **0x9E3779B9** inavyotumika (kumbuka kwamba constant hii pia inatumika na algorithms nyingine za crypto kama **TEA** -Tiny Encryption Algorithm).\
Pia angalia **ukubwa wa mzunguko** (**132**) na **idadi ya operesheni za XOR** katika **maagizo ya disassembly** na katika **mfano wa msimbo**:

![](<../../images/image (547).png>)

Kama ilivyotajwa hapo awali, msimbo huu unaweza kuonyeshwa ndani ya decompiler yoyote kama **kazi ndefu sana** kwani **hakuna kuruka** ndani yake. Msimbo uliotolewa unaweza kuonekana kama ifuatavyo:

![](<../../images/image (513).png>)

Kwa hivyo, inawezekana kutambua algorithm hii ukichunguza **nambari ya uchawi** na **XORs za awali**, kuona **kazi ndefu sana** na **kulinganisha** baadhi ya **maagizo** ya kazi ndefu **na utekelezaji** (kama shift left kwa 7 na rotate left kwa 22).

## RSA **(Asymmetric Crypt)**

### Characteristics

- Ngumu zaidi kuliko algorithms za symmetric
- Hakuna constants! (utekelezaji wa kawaida ni mgumu kubaini)
- KANAL (mchambuzi wa crypto) inashindwa kuonyesha vidokezo juu ya RSA kwani inategemea constants.

### Identifying by comparisons

![](<../../images/image (1113).png>)

- Katika mstari wa 11 (kushoto) kuna `+7) >> 3` ambayo ni sawa na katika mstari wa 35 (kulia): `+7) / 8`
- Mstari wa 12 (kushoto) unakagua ikiwa `modulus_len < 0x040` na katika mstari wa 36 (kulia) inakagua ikiwa `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Characteristics

- Kazi 3: Init, Update, Final
- Kazi za kuanzisha zinazofanana

### Identify

**Init**

Unaweza kutambua zote mbili ukichunguza constants. Kumbuka kwamba sha_init ina constant 1 ambayo MD5 haina:

![](<../../images/image (406).png>)

**MD5 Transform**

Kumbuka matumizi ya constants zaidi

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Ndogo na yenye ufanisi kwani kazi yake ni kupata mabadiliko yasiyokusudiwa katika data
- Inatumia lookup tables (hivyo unaweza kutambua constants)

### Identify

Angalia **lookup table constants**:

![](<../../images/image (508).png>)

Algorithm ya CRC hash inaonekana kama:

![](<../../images/image (391).png>)

## APLib (Compression)

### Characteristics

- Hakuna constants zinazotambulika
- Unaweza kujaribu kuandika algorithm hiyo katika python na kutafuta mambo yanayofanana mtandaoni

### Identify

Grafu ni kubwa sana:

![](<../../images/image (207) (2) (1).png>)

Angalia **kulinganisha 3 kutambua**:

![](<../../images/image (430).png>)

{{#include ../../banners/hacktricks-training.md}}
