# Padding Oracle

{{#include ../banners/hacktricks-training.md}}

## CBC - Cipher Block Chaining

Katika hali ya CBC, **block iliyosimbwa awali inatumika kama IV** ili XOR na block inayofuata:

![https://defuse.ca/images/cbc_encryption.png](https://defuse.ca/images/cbc_encryption.png)

Ili kufungua CBC, **operesheni** **za kinyume** zinafanywa:

![https://defuse.ca/images/cbc_decryption.png](https://defuse.ca/images/cbc_decryption.png)

Tazama jinsi inavyohitajika kutumia **ufunguo wa usimbaji** na **IV**.

## Message Padding

Kadri usimbaji unavyofanywa katika **blocks za ukubwa thabiti**, **padding** mara nyingi inahitajika katika **block ya mwisho** kukamilisha urefu wake.\
Mara nyingi **PKCS7** inatumika, ambayo inazalisha padding **ikirejelea** **idadi** ya **bytes** **zinazohitajika** kukamilisha block. Kwa mfano, ikiwa block ya mwisho inakosa bytes 3, padding itakuwa `\x03\x03\x03`.

Tuchunguze mifano zaidi na **blocks 2 za urefu wa 8bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Kumbuka jinsi katika mfano wa mwisho **block ya mwisho ilikuwa kamili hivyo nyingine ilizalishwa tu na padding**.

## Padding Oracle

Wakati programu inafungua data iliyosimbwa, kwanza itafungua data; kisha itatoa padding. Wakati wa kusafisha padding, ikiwa **padding isiyo sahihi inasababisha tabia inayoweza kugundulika**, una **udhaifu wa padding oracle**. Tabia inayoweza kugundulika inaweza kuwa **kosa**, **ukosefu wa matokeo**, au **jibu lenye mwendo polepole**.

Ikiwa unagundua tabia hii, unaweza **kufungua data iliyosimbwa** na hata **kusimbwa kwa maandiko yoyote ya wazi**.

### Jinsi ya kutumia

Unaweza kutumia [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) kutekeleza udhaifu huu au tu fanya
```
sudo apt-get install padbuster
```
Ili kujaribu kama cookie ya tovuti ina udhaifu unaweza kujaribu:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** inamaanisha kwamba **base64** inatumika (lakini zingine zinapatikana, angalia menyu ya msaada).

Unaweza pia **kutumia udhaifu huu kuandika data mpya. Kwa mfano, fikiria kwamba maudhui ya cookie ni "**_**user=MyUsername**_**", basi unaweza kubadilisha kuwa "\_user=administrator\_" na kuongeza mamlaka ndani ya programu. Unaweza pia kufanya hivyo ukitumia `paduster`ukitaja -plaintext** parameter:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Ikiwa tovuti ina udhaifu, `padbuster` itajaribu moja kwa moja kubaini wakati kosa la padding linapotokea, lakini unaweza pia kuonyesha ujumbe wa kosa kwa kutumia parameter **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Nadharia

Kwa **muhtasari**, unaweza kuanza kufichua data iliyosimbwa kwa kubashiri thamani sahihi ambazo zinaweza kutumika kuunda **paddings tofauti**. Kisha, shambulio la padding oracle litaanza kufichua byte kutoka mwisho hadi mwanzo kwa kubashiri ni ipi itakuwa thamani sahihi inayounda padding ya **1, 2, 3, n.k.**.

![](<../images/image (561).png>)

Fikiria una maandiko yaliyosimbwa yanayochukua **blocks 2** yaliyoundwa na byte kutoka **E0 hadi E15**.\
Ili **kufichua** **block** ya **mwisho** (**E8** hadi **E15**), block nzima inapita kupitia "block cipher decryption" ikizalisha **byte za kati I0 hadi I15**.\
Hatimaye, kila byte ya kati inachanganywa na byte zilizopita zilizofichwa (E0 hadi E7). Hivyo:

- `C15 = D(E15) ^ E7 = I15 ^ E7`
- `C14 = I14 ^ E6`
- `C13 = I13 ^ E5`
- `C12 = I12 ^ E4`
- ...

Sasa, inawezekana **kubadilisha `E7` hadi `C15` iwe `0x01`**, ambayo pia itakuwa padding sahihi. Hivyo, katika kesi hii: `\x01 = I15 ^ E'7`

Hivyo, kupata E'7, inawezekana **kuhesabu I15**: `I15 = 0x01 ^ E'7`

Ambayo inaturuhusu **kuhesabu C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Kujua **C15**, sasa inawezekana **kuhesabu C14**, lakini wakati huu kwa kubashiri padding `\x02\x02`.

Hii BF ni ngumu kama ile ya awali kwani inawezekana kuhesabu `E''15` ambayo thamani yake ni 0x02: `E''7 = \x02 ^ I15` hivyo inahitajika tu kupata **`E'14`** inayozalisha **`C14` inayolingana na `0x02`**.\
Kisha, fanya hatua hizo hizo kufichua C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Fuata mnyororo huu hadi ufichue maandiko yote yaliyosimbwa.**

### Ugunduzi wa udhaifu

Jisajili na ujiandikishe na akaunti hii.\
Ikiwa unajaribu **kuingia mara nyingi** na kila wakati unapata **cookie ile ile**, kuna uwezekano wa **kitu** **kibaya** katika programu. **Cookie inayotumwa nyuma inapaswa kuwa ya kipekee** kila wakati unapoingia. Ikiwa cookie ni **daima** ile **ile**, kuna uwezekano itakuwa daima halali na hakuna **njia ya kuifuta**.

Sasa, ikiwa unajaribu **kubadilisha** **cookie**, unaweza kuona unapata **kosa** kutoka kwa programu.\
Lakini ikiwa unafanya BF padding (ukitumia padbuster kwa mfano) unafanikiwa kupata cookie nyingine halali kwa mtumiaji tofauti. Hali hii ina uwezekano mkubwa wa kuwa na udhaifu kwa padbuster.

### Marejeleo

- [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)


{{#include ../banners/hacktricks-training.md}}
