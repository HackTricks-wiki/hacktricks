# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Kwa maelezo ya msingi kuhusu jinsi tags za 125 kHz zinavyofanya kazi, tazama:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[Utangulizi wa RFID ya masafa ya chini](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) unaeleza familia za kawaida za tags na miundo yake ya data.

## Vitendo

### Soma

Tumia **Read** kunasa data ya tag. Baada ya kusoma kwa mafanikio, Flipper Zero inaweza kuiga tag iliyohifadhiwa.<sup>[[1]](#references)</sup>

> [!WARNING]
> Baadhi ya wasomaji wa intercom hujaribu kugundua tags duplicate zinazoweza kuandikwa kwa kutuma amri ya write kabla ya kusoma. Emulation ya Flipper Zero haionyeshi memory ya tag inayoweza kuandikwa kwa njia hiyo hiyo.<sup>[[1]](#references)</sup>

### Ongeza kwa mikono

Unaweza kuingiza data ya tag kwa mikono kwenye Flipper Zero, kuihifadhi, kisha kuiiga.<sup>[[1]](#references)</sup>

#### IDs kwenye kadi

Wakati mwingine kadi huwa na ID yake yote au sehemu yake iliyochapishwa nje.

- **EM Marin**

Kwa mfano, kadi ya EM-Marin iliyoonyeshwa inaonyesha baiti tatu za mwisho kati ya baiti zake tano za ID. Ikiwa tag haiwezi kusomwa, baiti mbili zilizokosekana zinaweza kufanyiwa brute-force.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Vivyo hivyo, kadi ya HID iliyoonyeshwa huchapisha baiti mbili tu kati ya baiti zake tatu za ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Baada ya kusoma tag au kuingiza ID yake kwa mikono, Flipper Zero inaweza kuiga credential iliyohifadhiwa. Kwa tags zinazoweza kuandikwa na zinazoungwa mkono, inaweza pia kuandika data iliyohifadhiwa kwenye kadi inayooana.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Diving into RFID Protocols](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
