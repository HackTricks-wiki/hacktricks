# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Kwa maelezo ya jinsi tag za 125 kHz zinavyofanya kazi, tazama:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[Utangulizi wa RFID ya masafa ya chini](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) unaeleza familia za kawaida za tag na miundo yake ya data.

## Vitendo

### Soma

Tumia **Soma** kunasa data ya tag. Baada ya kusoma kwa mafanikio, Flipper Zero inaweza kuiga tag iliyohifadhiwa.<sup>[[1]](#references)</sup>

> [!WARNING]
> Baadhi ya visomaji vya intercom hujaribu kutambua tag rudufu zinazoweza kuandikwa kwa kutuma amri ya kuandika kabla ya kusoma. Uigaji wa Flipper Zero hauonyeshi kumbukumbu ya tag inayoweza kuandikwa kwa njia hiyo hiyo.<sup>[[1]](#references)</sup>

### Ongeza mwenyewe

Unaweza kuweka data ya tag mwenyewe kwenye Flipper Zero, kuihifadhi, kisha kuiiga.<sup>[[1]](#references)</sup>

#### Vitambulisho kwenye kadi

Wakati mwingine kitambulisho chote au sehemu yake huchapishwa kwenye nje ya kadi.

- **EM Marin**

Kwa mfano, kadi ya EM-Marin iliyoonyeshwa inaonyesha baiti tatu za mwisho kati ya baiti zake tano za kitambulisho. Ikiwa tag haiwezi kusomwa, baiti mbili zilizokosekana zinaweza kupatikana kwa brute-force.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Vivyo hivyo, kadi ya HID iliyoonyeshwa huchapisha baiti mbili tu kati ya baiti zake tatu za kitambulisho.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Iga/Andika

Baada ya kusoma tag au kuweka kitambulisho chake mwenyewe, Flipper Zero inaweza kuiga kitambulisho kilichohifadhiwa. Kwa tag zinazoweza kuandikwa na zinazotumika, inaweza pia kuandika data iliyohifadhiwa kwenye kadi inayooana.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Kuchunguza kwa Kina Itifaki za RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
