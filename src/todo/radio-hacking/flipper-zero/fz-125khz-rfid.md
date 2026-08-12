# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Za osnovne informacije o načinu rada tagova od 125 kHz, pogledajte:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[Uvod u RFID niske frekvencije](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) objašnjava uobičajene porodice tagova i njihove formate podataka.

## Radnje

### Čitanje

Koristite **Read** da biste snimili podatke taga. Nakon uspešnog čitanja, Flipper Zero može da emulira sačuvani tag.<sup>[[1]](#references)</sup>

> [!WARNING]
> Neki interfonski čitači pokušavaju da otkriju upisive duplikate tagova tako što izdaju komandu za upis pre čitanja. Flipper Zero emulacija ne izlaže memoriju upisivog taga na isti način.<sup>[[1]](#references)</sup>

### Ručno dodavanje

Možete ručno uneti podatke taga u Flipper Zero, sačuvati ih, a zatim emulirati tag.<sup>[[1]](#references)</sup>

#### ID-jevi na karticama

Ponekad je ceo ID kartice ili njegov deo odštampan na njenoj spoljašnjoj strani.

- **EM Marin**

Na primer, prikazana EM-Marin kartica otkriva poslednja tri od svojih pet bajtova ID-ja. Ako tag ne može da se pročita, dva bajta koja nedostaju mogu se brute-force-ovati.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Slično tome, na prikazanoj HID kartici odštampana su samo dva od tri bajta ID-ja.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Nakon čitanja taga ili ručnog unosa njegovog ID-ja, Flipper Zero može da emulira sačuvani credential. Za podržane upisive tagove, takođe može da upiše sačuvane podatke na kompatibilnu karticu.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Istraživanje RFID protokola](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
