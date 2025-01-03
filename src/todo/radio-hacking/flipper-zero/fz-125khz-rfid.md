# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Uvod

Za više informacija o tome kako 125kHz tagovi funkcionišu, proverite:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Akcije

Za više informacija o ovim tipovima tagova [**pročitajte ovaj uvod**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Čitanje

Pokušava da **pročita** informacije sa kartice. Zatim može da je **emulira**.

> [!WARNING]
> Imajte na umu da neki interkomi pokušavaju da se zaštite od dupliranja ključeva slanjem komande za pisanje pre čitanja. Ako pisanje uspe, taj tag se smatra lažnim. Kada Flipper emulira RFID, ne postoji način za čitač da ga razlikuje od originalnog, tako da takvi problemi ne nastaju.

### Dodaj Ručno

Možete kreirati **lažne kartice u Flipper Zero označavajući podatke** koje ručno unesete, a zatim ih emulirati.

#### ID-ovi na karticama

Ponekad, kada dobijete karticu, pronaći ćete ID (ili deo) napisan na vidljivom delu kartice.

- **EM Marin**

Na primer, na ovoj EM-Marin kartici moguće je **pročitati poslednja 3 od 5 bajtova u čistom obliku**.\
Ostala 2 mogu se brute-forced ako ih ne možete pročitati sa kartice.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Isto se dešava na ovoj HID kartici gde se samo 2 od 3 bajta mogu pronaći odštampana na kartici.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emuliraj/Piši

Nakon **kopiranja** kartice ili **unošenja** ID-a **ručno**, moguće je **emulirati** je sa Flipper Zero ili **pisati** je na pravoj kartici.

## Reference

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
