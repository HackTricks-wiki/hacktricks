# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Za osnovne informacije o tome kako rade oznake od 125 kHz, pogledajte:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[Uvod u RFID niske frekvencije](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) objašnjava uobičajene porodice oznaka i njihove formate podataka.

## Radnje

### Očitavanje

Koristite **Read** da biste zabeležili podatke sa oznake. Nakon uspešnog očitavanja, Flipper Zero može da emulira sačuvanu oznaku.<sup>[[1]](#references)</sup>

> [!WARNING]
> Neki čitači interfona pokušavaju da otkriju upisive duplikate oznaka tako što izdaju komandu za upis pre očitavanja. Flipper Zero emulacija ne omogućava pristup memoriji upisive oznake na isti način.<sup>[[1]](#references)</sup>

### Ručno dodavanje

Možete ručno da unesete podatke oznake u Flipper Zero, sačuvate ih, a zatim emulirate oznaku.<sup>[[1]](#references)</sup>

#### ID-jevi na karticama

Ponekad je ceo ID kartice ili njegov deo odštampan na njenoj spoljašnjosti.

- **EM Marin**

Na primer, na prikazanoj EM-Marin kartici vidljiva su poslednja tri od pet bajtova ID-ja. Ako oznaku nije moguće očitati, nedostajuća dva bajta mogu se pronaći brute-force metodom.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Slično tome, na prikazanoj HID kartici odštampana su samo dva od tri bajta ID-ja.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulacija/upisivanje

Nakon očitavanja oznake ili ručnog unosa njenog ID-ja, Flipper Zero može da emulira sačuvani credential. Za podržane upisive oznake, može i da upiše sačuvane podatke na kompatibilnu karticu.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Upoznavanje sa RFID protokolima](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
