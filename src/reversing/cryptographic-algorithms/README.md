# Algorithimu za Kijamii/Kupunguza

## Algorithimu za Kijamii/Kupunguza

{{#include ../../banners/hacktricks-training.md}}

## Kutambua Algorithimu

Ikiwa unamaliza katika msimbo **ukitumia shift kulia na kushoto, xors na operesheni kadhaa za hesabu** kuna uwezekano mkubwa kwamba ni utekelezaji wa **algorithimu ya kijamii**. Hapa kuna njia kadhaa za **kutambua algorithimu inayotumika bila kuhitaji kubadilisha kila hatua**.

### API functions

**CryptDeriveKey**

Ikiwa kazi hii inatumika, unaweza kupata ni **algorithimu gani inatumika** ukichunguza thamani ya parameter ya pili:

![](<../../images/image (375) (1) (1) (1) (1).png>)

Angalia hapa jedwali la algorithimu zinazowezekana na thamani zao zilizotengwa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Inapunguza na kufungua buffer fulani ya data.

**CryptAcquireContext**

Kutoka [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Kazi ya **CryptAcquireContext** inatumika kupata mkono wa chombo maalum cha funguo ndani ya mtoa huduma maalum wa kijamii (CSP). **Huu mkono uliorejeshwa unatumika katika wito wa kazi za CryptoAPI** zinazotumia CSP iliyochaguliwa.

**CryptCreateHash**

Inaanzisha hashing ya mtiririko wa data. Ikiwa kazi hii inatumika, unaweza kupata ni **algorithimu gani inatumika** ukichunguza thamani ya parameter ya pili:

![](<../../images/image (376).png>)

\
Angalia hapa jedwali la algorithimu zinazowezekana na thamani zao zilizotengwa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Misingi ya msimbo

Wakati mwingine ni rahisi sana kutambua algorithimu kutokana na ukweli kwamba inahitaji kutumia thamani maalum na ya kipekee.

![](<../../images/image (370).png>)

Ikiwa unatafuta msingi wa kwanza kwenye Google hii ndiyo unayopata:

![](<../../images/image (371).png>)

Kwa hivyo, unaweza kudhani kwamba kazi iliyotolewa ni **sha256 calculator.**\
Unaweza kutafuta yoyote ya misingi mingine na utapata (labda) matokeo sawa.

### taarifa za data

Ikiwa msimbo huna msingi wowote muhimu inaweza kuwa **inapakia taarifa kutoka sehemu ya .data**.\
Unaweza kufikia data hiyo, **kundi la dword ya kwanza** na kutafuta hiyo kwenye google kama tulivyofanya katika sehemu iliyopita:

![](<../../images/image (372).png>)

Katika kesi hii, ikiwa utaangalia **0xA56363C6** unaweza kupata kwamba inahusiana na **meza za algorithimu ya AES**.

## RC4 **(Kijamii Crypt)**

### Tabia

Imepangwa kwa sehemu 3 kuu:

- **Hatua ya Kuanza/**: Inaunda **meza ya thamani kutoka 0x00 hadi 0xFF** (256bytes kwa jumla, 0x100). Meza hii kwa kawaida inaitwa **Substitution Box** (au SBox).
- **Hatua ya Kuchanganya**: Itakuwa **inazunguka kupitia meza** iliyoundwa hapo awali (zunguko wa 0x100, tena) ikibadilisha kila thamani kwa **bytes za nadharia**. Ili kuunda hizi bytes za nadharia, funguo ya RC4 **inatumika**. Funguo za RC4 **zinaweza kuwa** **kati ya 1 na 256 bytes kwa urefu**, hata hivyo kawaida inapendekezwa iwe juu ya 5 bytes. Kwa kawaida, funguo za RC4 ni 16 bytes kwa urefu.
- **Hatua ya XOR**: Hatimaye, maandiko ya wazi au cyphertext **yanapigwa XOR na thamani zilizoundwa hapo awali**. Kazi ya kuandika na kufungua ni sawa. Kwa hili, **zunguko kupitia bytes 256 zilizoundwa** utafanywa mara nyingi kadri inavyohitajika. Hii kwa kawaida inatambuliwa katika msimbo uliotolewa na **%256 (mod 256)**.

> [!NOTE]
> **Ili kutambua RC4 katika msimbo wa disassembly/uliotolewa unaweza kuangalia kwa zunguko 2 za ukubwa 0x100 (kwa kutumia funguo) na kisha XOR ya data ya ingizo na thamani 256 zilizoundwa hapo awali katika zunguko 2 labda kwa kutumia %256 (mod 256)**

### **Hatua ya Kuanza/Substitution Box:** (Kumbuka nambari 256 inayotumika kama hesabu na jinsi 0 inavyoandikwa katika kila mahali pa wahusika 256)

![](<../../images/image (377).png>)

### **Hatua ya Kuchanganya:**

![](<../../images/image (378).png>)

### **Hatua ya XOR:**

![](<../../images/image (379).png>)

## **AES (Kijamii Crypt)**

### **Tabia**

- Matumizi ya **masanduku ya kubadilisha na meza za kutafuta**
- Inawezekana **kutofautisha AES kutokana na matumizi ya thamani maalum za meza za kutafuta** (misingi). _Kumbuka kwamba **misingi** inaweza **kuhifadhiwa** katika binary **au kuundwa** _**kikamilifu**._
- **Funguo ya kuandika** lazima iwe **inaweza kugawanywa** na **16** (kawaida 32B) na kawaida **IV** ya 16B inatumika.

### Misingi ya SBox

![](<../../images/image (380).png>)

## Serpent **(Kijamii Crypt)**

### Tabia

- Ni nadra kupata malware ikitumia lakini kuna mifano (Ursnif)
- Rahisi kubaini ikiwa algorithimu ni Serpent au la kulingana na urefu wake (kazi ndefu sana)

### Kutambua

Katika picha ifuatayo angalia jinsi msingi **0x9E3779B9** unavyotumika (kumbuka kwamba msingi huu pia unatumika na algorithimu nyingine za crypto kama **TEA** -Tiny Encryption Algorithm).\
Pia angalia **ukubwa wa zunguko** (**132**) na **idadi ya operesheni za XOR** katika **maelekezo ya disassembly** na katika **mfano wa msimbo**:

![](<../../images/image (381).png>)

Kama ilivyotajwa hapo awali, msimbo huu unaweza kuonyeshwa ndani ya decompiler yoyote kama **kazi ndefu sana** kwani **hakuna kuruka** ndani yake. Msimbo uliotolewa unaweza kuonekana kama ifuatavyo:

![](<../../images/image (382).png>)

Kwa hivyo, inawezekana kutambua algorithimu hii ukichunguza **nambari ya kichawi** na **XORs za awali**, kuona **kazi ndefu sana** na **kulinganisha** baadhi ya **maelekezo** ya kazi ndefu **na utekelezaji** (kama shift kushoto kwa 7 na kuzungusha kushoto kwa 22).

## RSA **(Kijamii Crypt)**

### Tabia

- Ngumu zaidi kuliko algorithimu za kijamii
- Hakuna misingi! (utekelezaji wa kawaida ni mgumu kubaini)
- KANAL (mchambuzi wa crypto) inashindwa kuonyesha vidokezo juu ya RSA kwani inategemea misingi.

### Kutambua kwa kulinganisha

![](<../../images/image (383).png>)

- Katika mstari wa 11 (kushoto) kuna `+7) >> 3` ambayo ni sawa na katika mstari wa 35 (kulia): `+7) / 8`
- Mstari wa 12 (kushoto) unakagua ikiwa `modulus_len < 0x040` na katika mstari wa 36 (kulia) inakagua ikiwa `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Tabia

- Kazi 3: Kuanza, Sasisha, Mwisho
- Kazi za kuanzisha zinazofanana

### Tambua

**Kuanza**

Unaweza kutambua zote mbili ukichunguza misingi. Kumbuka kwamba sha_init ina msingi 1 ambao MD5 haina:

![](<../../images/image (385).png>)

**MD5 Transform**

Kumbuka matumizi ya misingi zaidi

![](<../../images/image (253) (1) (1) (1).png>)

## CRC (hash)

- Ndogo na yenye ufanisi kwani kazi yake ni kupata mabadiliko yasiyokusudiwa katika data
- Inatumia meza za kutafuta (hivyo unaweza kutambua misingi)

### Tambua

Angalia **misingi ya meza za kutafuta**:

![](<../../images/image (387).png>)

Algorithimu ya hash ya CRC inaonekana kama:

![](<../../images/image (386).png>)

## APLib (Kupunguza)

### Tabia

- Hakuna misingi inayotambulika
- Unaweza kujaribu kuandika algorithimu hiyo katika python na kutafuta mambo yanayofanana mtandaoni

### Tambua

Grafu ni kubwa sana:

![](<../../images/image (207) (2) (1).png>)

Angalia **kulinganisha 3 kutambua**:

![](<../../images/image (384).png>)

{{#include ../../banners/hacktricks-training.md}}
