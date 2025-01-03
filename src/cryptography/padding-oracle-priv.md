{{#include ../banners/hacktricks-training.md}}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

# CBC - Cipher Block Chaining

In CBC-modus word die **vorige versleutelde blok as IV** gebruik om met die volgende blok te XOR:

![https://defuse.ca/images/cbc_encryption.png](https://defuse.ca/images/cbc_encryption.png)

Om CBC te ontsleutel, word die **teenoorgestelde** **operasies** uitgevoer:

![https://defuse.ca/images/cbc_decryption.png](https://defuse.ca/images/cbc_decryption.png)

Let op hoe dit nodig is om 'n **versleuteling** **sleutel** en 'n **IV** te gebruik.

# Boodskap Padding

Aangesien die versleuteling in **vaste** **grootte** **blokkies** uitgevoer word, is **padding** gewoonlik nodig in die **laaste** **blok** om sy lengte te voltooi.\
Gewoonlik word **PKCS7** gebruik, wat 'n padding genereer deur die **aantal** **bytes** **nodig** om die blok te **voltooi** te herhaal. Byvoorbeeld, as die laaste blok 3 bytes kort is, sal die padding `\x03\x03\x03` wees.

Kom ons kyk na meer voorbeelde met **2 blokkies van 8bytes lengte**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Let op hoe in die laaste voorbeeld die **laaste blok vol was, so 'n ander een is net met padding gegenereer**.

# Padding Oracle

Wanneer 'n toepassing versleutelde data ontsleutel, sal dit eers die data ontsleutel; dan sal dit die padding verwyder. Tydens die opruiming van die padding, as 'n **ongeldige padding 'n waarneembare gedrag veroorsaak**, het jy 'n **padding oracle kwesbaarheid**. Die waarneembare gedrag kan 'n **fout**, 'n **gebrek aan resultate**, of 'n **langsame reaksie** wees.

As jy hierdie gedrag waarneem, kan jy die **versleutelde data ontsleutel** en selfs **enige duidelike teks versleutel**.

## Hoe om te benut

Jy kan [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) gebruik om hierdie tipe kwesbaarheid te benut of net doen
```
sudo apt-get install padbuster
```
Om te toets of die koekie van 'n webwerf kwesbaar is, kan jy probeer:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Kodering 0** beteken dat **base64** gebruik word (maar ander is beskikbaar, kyk na die hulpmenu).

Jy kan ook **hierdie kwesbaarheid misbruik om nuwe data te enkripteer. Byvoorbeeld, veronderstel dat die inhoud van die koekie is "**_**user=MyUsername**_**", dan kan jy dit verander na "\_user=administrator\_" en bevoegdhede binne die aansoek opgradeer. Jy kan dit ook doen met `paduster` deur die -plaintext** parameter te spesifiseer:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
As die webwerf kwesbaar is, sal `padbuster` outomaties probeer om te vind wanneer die padding fout voorkom, maar jy kan ook die foutboodskap aandui deur die **-error** parameter te gebruik.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Die teorie

In **samevatting**, jy kan begin om die versleutelde data te ontsleutel deur die korrekte waardes te raai wat gebruik kan word om al die **verskillende opvullings** te skep. Dan sal die padding oracle aanval begin om bytes van die einde na die begin te ontsleutel deur te raai wat die korrekte waarde is wat **'n opvulling van 1, 2, 3, ens.** skep.

![](<../images/image (629) (1) (1).png>)

Stel jou voor jy het 'n paar versleutelde teks wat **2 blokke** beslaan wat gevorm word deur die bytes van **E0 tot E15**.\
Om die **laaste** **blok** (**E8** tot **E15**) te **ontsleutel**, gaan die hele blok deur die "blok-kodering ontsleuteling" wat die **intermediêre bytes I0 tot I15** genereer.\
Laastens, elke intermediêre byte word **XORed** met die vorige versleutelde bytes (E0 tot E7). So:

- `C15 = D(E15) ^ E7 = I15 ^ E7`
- `C14 = I14 ^ E6`
- `C13 = I13 ^ E5`
- `C12 = I12 ^ E4`
- ...

Nou, dit is moontlik om `E7` te **wysig totdat `C15` `0x01` is**, wat ook 'n korrekte opvulling sal wees. So, in hierdie geval: `\x01 = I15 ^ E'7`

So, om E'7 te vind, is dit **moontlik om I15 te bereken**: `I15 = 0x01 ^ E'7`

Wat ons toelaat om **C15 te bereken**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

As ons **C15** ken, is dit nou moontlik om **C14** te **bereken**, maar hierdie keer brute-forcing die opvulling `\x02\x02`.

Hierdie BF is net so kompleks soos die vorige een, aangesien dit moontlik is om die `E''15` waarvan die waarde 0x02 is te bereken: `E''7 = \x02 ^ I15` so dit is net nodig om die **`E'14`** te vind wat 'n **`C14` gelyk aan `0x02`** genereer.\
Dan, doen dieselfde stappe om C14 te ontsleutel: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Volg hierdie ketting totdat jy die hele versleutelde teks ontsleutel.**

## Opsporing van die kwesbaarheid

Registreer en skep 'n rekening en teken in met hierdie rekening.\
As jy **baie keer aanmeld** en altyd die **dieselfde koekie** kry, is daar waarskynlik **iets** **verkeerd** in die toepassing. Die **koekie wat teruggestuur word, moet uniek wees** elke keer wat jy aanmeld. As die koekie **altyd** die **dieselfde** is, sal dit waarskynlik altyd geldig wees en daar **sal geen manier wees om dit te ongeldig te maak** nie.

Nou, as jy probeer om die **koekie** te **wysig**, kan jy sien dat jy 'n **fout** van die toepassing kry.\
Maar as jy die opvulling BF (gebruik padbuster byvoorbeeld) kan jy 'n ander koekie kry wat geldig is vir 'n ander gebruiker. Hierdie scenario is hoogs waarskynlik kwesbaar vir padbuster.

## Verwysings

- [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{{#include ../banners/hacktricks-training.md}}
