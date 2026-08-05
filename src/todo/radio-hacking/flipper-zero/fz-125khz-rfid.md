# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Inleiding

Vir meer inligting oor hoe 125kHz-tags werk, kyk:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Aksies

Vir meer inligting oor hierdie tipe tags, [**lees hierdie inleiding**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lees

Probeer om die kaart se inligting te **lees**. Daarna kan dit **geëmuleer** word.<sup>[[1]](#references)</sup>

> [!WARNING]
> Let daarop dat sommige interkoms probeer om hulself teen sleutelduplisering te beskerm deur 'n skryfopdrag te stuur voordat hulle lees. As die skryfaksie slaag, word daardie tag as vals beskou. Wanneer Flipper RFID emuleer, is daar geen manier vir die leser om dit van die oorspronklike te onderskei nie, dus kom sulke probleme nie voor nie.

### Voeg handmatig by

Jy kan **valse kaarte in Flipper Zero skep deur die data aan te dui** wat jy handmatig ingevoer het, en dit dan emuleer.

#### ID's op kaarte

Soms, wanneer jy 'n kaart kry, sal jy die ID (of 'n deel daarvan) sigbaar op die kaart vind.

- **EM Marin**

Byvoorbeeld, op hierdie EM-Marin-kaart is dit moontlik om **die laaste 3 van 5 grepe in clear te lees**.\
Die ander 2 kan met brute-force gevind word as jy dit nie van die kaart kan lees nie.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Dieselfde gebeur met hierdie HID-kaart, waar slegs 2 uit 3 grepe op die kaart gedruk is

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emuleer/Skryf

Nadat jy 'n kaart **gekopieer** het of die ID **handmatig ingevoer** het, is dit moontlik om dit met Flipper Zero te **emuleer** of dit op 'n regte kaart te **skryf**.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
