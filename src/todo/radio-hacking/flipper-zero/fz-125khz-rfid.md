# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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

Kwa mfano katika kadi hii ya EM-Marin kwenye kadi halisi inawezekana **kusoma mwisho 3 kati ya 5 bytes wazi**.\
Mengine 2 yanaweza kujaribiwa kwa nguvu ikiwa huwezi kuyasoma kutoka kwenye kadi.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Vivyo hivyo inatokea katika kadi hii ya HID ambapo ni 2 tu kati ya 3 bytes zinaweza kupatikana zimeandikwa kwenye kadi

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Baada ya **kunakili** kadi au **kuingiza** ID **kwa mikono** inawezekana **kuiga** hiyo na Flipper Zero au **kuandika** kwenye kadi halisi.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
