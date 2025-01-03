# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Intro

Vir meer inligting oor hoe 125kHz etikette werk, kyk:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Vir meer inligting oor hierdie tipes etikette [**lees hierdie inleiding**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Probeer om die **kaartinligting** te **lees**. Dan kan dit **emuleer** word.

> [!WARNING]
> Let daarop dat sommige interkoms probeer om hulself te beskerm teen sleutelduplisering deur 'n skryfopdrag te stuur voordat hulle lees. As die skryf slaag, word daardie etiket as vals beskou. Wanneer Flipper RFID emuleer, is daar geen manier vir die leser om dit van die oorspronklike te onderskei nie, so sulke probleme ontstaan nie.

### Add Manually

Jy kan **vals kaarte in Flipper Zero skep wat die data** aandui wat jy handmatig invoer en dit dan emuleer.

#### IDs on cards

Soms, wanneer jy 'n kaart kry, sal jy die ID (of deel daarvan) op die kaart sigbaar vind.

- **EM Marin**

Byvoorbeeld, in hierdie EM-Marin kaart is dit moontlik om die **laaste 3 van 5 bytes in duidelik** te **lees**.\
Die ander 2 kan brute-forced word as jy dit nie van die kaart kan lees nie.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Dieselfde gebeur in hierdie HID kaart waar slegs 2 van die 3 bytes op die kaart gedruk kan word.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Na **kopieer** van 'n kaart of **invoer** van die ID **handmatig** is dit moontlik om dit met Flipper Zero te **emuleer** of dit op 'n werklike kaart te **skryf**.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
