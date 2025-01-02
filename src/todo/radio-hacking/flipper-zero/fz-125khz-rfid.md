# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Intro

Kwa maelezo zaidi kuhusu jinsi vitambulisho vya 125kHz vinavyofanya kazi angalia:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Kwa maelezo zaidi kuhusu aina hizi za vitambulisho [**soma utangulizi huu**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Inajaribu **kusoma** taarifa za kadi. Kisha inaweza **kuiga** hizo.

> [!WARNING]
> Kumbuka kwamba baadhi ya intercoms zinajaribu kujilinda kutokana na nakala za funguo kwa kutuma amri ya kuandika kabla ya kusoma. Ikiwa kuandika kunafanikiwa, kitambulisho hicho kinachukuliwa kuwa bandia. Wakati Flipper inapoiga RFID, hakuna njia kwa msomaji kutofautisha kati yake na ile ya asili, hivyo matatizo kama hayo hayatokea.

### Add Manually

Unaweza kuunda **kadi bandia katika Flipper Zero ukionyesha data** unazozingatia kwa mikono kisha uige.

#### IDs on cards

Wakati mwingine, unapopata kadi utaona ID (au sehemu) yake imeandikwa kwenye kadi inayoonekana.

- **EM Marin**

Kwa mfano katika kadi hii ya EM-Marin kwenye kadi halisi inawezekana **kusoma mwisho 3 wa 5 bytes wazi**.\
Bytes 2 nyingine zinaweza kujaribiwa kwa nguvu ikiwa huwezi kuzisoma kutoka kwenye kadi.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Vivyo hivyo inatokea katika kadi hii ya HID ambapo bytes 2 tu kati ya 3 zinaweza kupatikana zimeandikwa kwenye kadi

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Baada ya **kunakili** kadi au **kuingiza** ID **kwa mikono** inawezekana **kuiga** hiyo na Flipper Zero au **kuandika** kwenye kadi halisi.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
