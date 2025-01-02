# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Uvod

Za više informacija o tome kako 125kHz oznake funkcionišu, proverite:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Akcije

Za više informacija o ovim tipovima oznaka [**pročitajte ovaj uvod**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Čitanje

Pokušava da **pročita** informacije sa kartice. Zatim može da je **emulira**.

> [!WARNING]
> Imajte na umu da neki interkomi pokušavaju da se zaštite od duplikacije ključeva slanjem komande za pisanje pre čitanja. Ako pisanje uspe, ta oznaka se smatra lažnom. Kada Flipper emulira RFID, ne postoji način za čitač da je razlikuje od originalne, tako da takvi problemi ne nastaju.

### Dodaj Ručno

Možete kreirati **lažne kartice u Flipper Zero označavajući podatke** koje ručno unesete, a zatim ih emulirati.

#### ID-ovi na karticama

Ponekad, kada dobijete karticu, pronaći ćete ID (ili deo) napisanu na vidljivom delu kartice.

- **EM Marin**

Na primer, na ovoj EM-Marin kartici moguće je **pročitati poslednja 3 od 5 bajtova u čistom obliku**.\
Ostala 2 mogu se probati da se otkriju ako ih ne možete pročitati sa kartice.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Isto se dešava na ovoj HID kartici gde se samo 2 od 3 bajta mogu pronaći odštampana na kartici.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emuliraj/Piši

Nakon **kopiranja** kartice ili **unošenja** ID-a **ručno**, moguće je **emulirati** je sa Flipper Zero ili **pisati** je na pravoj kartici.

## Reference

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
