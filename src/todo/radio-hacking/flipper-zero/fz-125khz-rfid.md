# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Vir agtergrond oor hoe 125 kHz-tags werk, sien:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

Die [inleiding tot laefrekwensie-RFID](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) verduidelik die algemene tag-families en hul dataformate.

## Aksies

### Lees

Gebruik **Lees** om die tag-data vas te lê. Ná 'n suksesvolle lees kan Flipper Zero die gestoorde tag emuleer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Sommige interkomlesers probeer skryfbare duplikaat-tags opspoor deur 'n skryfopdrag uit te reik voordat hulle lees. 'n Flipper Zero-emulasie stel nie skryfbare tag-geheue op dieselfde manier bloot nie.<sup>[[1]](#references)</sup>

### Voeg handmatig by

Jy kan tag-data handmatig in Flipper Zero invoer, dit stoor en dit daarna emuleer.<sup>[[1]](#references)</sup>

#### ID's op kaarte

Soms het 'n kaart die hele of 'n gedeelte van sy ID op die buitekant gedruk.

- **EM Marin**

Die afgebeelde EM-Marin-kaart wys byvoorbeeld die laaste drie van sy vyf ID-grepe. As die tag nie gelees kan word nie, kan die twee ontbrekende grepe met brute-force gevind word.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Net so druk die afgebeelde HID-kaart slegs twee van die drie ID-grepe.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emuleer/Skryf

Nadat 'n tag gelees is of sy ID handmatig ingevoer is, kan Flipper Zero die gestoorde credential emuleer. Vir ondersteunde skryfbare tags kan dit ook die gestoorde data na 'n versoenbare kaart skryf.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Duik in RFID-protokolle](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
