# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Intro

Za više informacija o tome kako 125kHz tagovi funkcionišu, proverite:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Za više informacija o ovim tipovima tagova [**pročitajte ovaj uvod**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Pokušava da **pročita** informacije sa kartice. Zatim može da je **emulira**.

> [!WARNING]
> Imajte na umu da neki interkomi pokušavaju da se zaštite od duplikacije ključeva slanjem komande za pisanje pre čitanja. Ako pisanje uspe, taj tag se smatra lažnim. Kada Flipper emulira RFID, ne postoji način za čitač da ga razlikuje od originalnog, tako da takvi problemi ne nastaju.

### Add Manually

Možete kreirati **lažne kartice u Flipper Zero označavajući podatke** koje ručno unesete, a zatim ih emulirati.

#### IDs on cards

Ponekad, kada dobijete karticu, naći ćete ID (ili deo) napisano na vidljivom delu kartice.

- **EM Marin**

Na primer, na ovoj EM-Marin kartici je moguće **pročitati poslednja 3 od 5 bajtova u čistom obliku**.\
Ostala 2 se mogu probiti ako ih ne možete pročitati sa kartice.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Isto se dešava na ovoj HID kartici gde se samo 2 od 3 bajta mogu naći odštampana na kartici.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Nakon **kopiranja** kartice ili **unošenja** ID-a **ručno**, moguće je **emulirati** je sa Flipper Zero ili **pisati** je na pravoj kartici.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
