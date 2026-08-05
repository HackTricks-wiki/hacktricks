# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Utangulizi

Kwa maelezo zaidi kuhusu jinsi tags za 125kHz zinavyofanya kazi, angalia:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Vitendo

Kwa maelezo zaidi kuhusu aina hizi za tags [**soma utangulizi huu**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Soma

Hujaribu **kusoma** maelezo ya kadi. Kisha inaweza **ku-emulate** kadi hizo.<sup>[[1]](#references)</sup>

> [!WARNING]
> Kumbuka kwamba baadhi ya intercom hujaribu kujilinda dhidi ya duplication ya funguo kwa kutuma write command kabla ya kusoma. Ikiwa write inafanikiwa, tag hiyo huchukuliwa kuwa fake. Flipper inapo-emulate RFID, hakuna njia kwa reader kuitofautisha na ile ya awali, hivyo matatizo kama hayo hayatokei.

### Add Manually

Unaweza kuunda **fake cards katika Flipper Zero kwa kuingiza data** wewe mwenyewe, kisha kuzi-emulate.

#### IDs kwenye kadi

Wakati mwingine, unapopata kadi, utapata ID yake (au sehemu yake) ikiwa imeandikwa na kuonekana kwenye kadi.

- **EM Marin**

Kwa mfano, kwenye kadi hii ya EM-Marin, inawezekana **kusoma bytes 3 za mwisho kati ya bytes 5 kwa uwazi** kwenye kadi halisi.\
Bytes 2 zilizobaki zinaweza kuwa brute-forced ikiwa huwezi kuzisoma kutoka kwenye kadi.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Hali hiyo hiyo hutokea kwenye kadi hii ya HID, ambapo ni bytes 2 tu kati ya 3 zinazoweza kupatikana zikiwa zimechapishwa kwenye kadi.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Baada ya **kunakili** kadi au **kuingiza** ID **wewe mwenyewe**, inawezekana kui-emulate kwa Flipper Zero au **kuiandika** kwenye kadi halisi.<sup>[[1]](#references)</sup>

## Marejeo

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
