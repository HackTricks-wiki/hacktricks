# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Uvod

Za više informacija o tome kako 125kHz tagovi funkcionišu, pogledajte:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Radnje

Za više informacija o ovim tipovima tagova [**pročitajte ovaj uvod**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Čitanje

Pokušava da **pročita** informacije sa kartice. Zatim ih može **emulirati**.<sup>[[1]](#references)</sup>

> [!WARNING]
> Imajte na umu da neki interfoni pokušavaju da se zaštite od dupliciranja ključeva slanjem write komande pre čitanja. Ako upis uspe, taj tag se smatra lažnim. Kada Flipper emulira RFID, čitač nema način da ga razlikuje od originala, tako da se takvi problemi ne javljaju.

### Ručno dodavanje

Možete kreirati **lažne kartice u uređaju Flipper Zero navođenjem podataka** ručno, a zatim ih emulirati.

#### ID-jevi na karticama

Ponekad ćete, kada dobijete karticu, pronaći ID (ili njegov deo) vidljivo ispisan na kartici.

- **EM Marin**

Na primer, na ovoj EM-Marin kartici moguće je **pročitati poslednja 3 od 5 bajtova u otvorenom obliku**.\
Preostala 2 bajta mogu se brute-force-ovati ako ih ne možete pročitati sa kartice.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Isto se dešava i kod ove HID kartice, gde se na kartici mogu pronaći odštampana samo 2 od 3 bajta

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulacija/upisivanje

Nakon **kopiranja** kartice ili **ručnog unošenja** ID-ja, moguće je **emulirati** je pomoću uređaja Flipper Zero ili ga **upisati** na pravu karticu.<sup>[[1]](#references)</sup>

## Reference

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
