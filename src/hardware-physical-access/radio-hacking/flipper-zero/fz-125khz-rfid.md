# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Vir agtergrond oor hoe 125 kHz-tags werk, sien:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

Die [inleiding tot laefrekwensie-RFID](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) verduidelik die algemene tagfamilies en hul dataformate.

## Aksies

### Lees

Gebruik **Lees** om die tagdata vas te lê. Ná ’n suksesvolle lesing kan Flipper Zero die gestoorde tag naboots.<sup>[[1]](#references)</sup>

> [!WARNING]
> Sommige interkomlesers probeer skryfbare duplikaattags opspoor deur ’n skryfopdrag uit te reik voordat hulle lees. Flipper Zero-emulasie stel nie skryfbare taggeheue op dieselfde manier beskikbaar nie.<sup>[[1]](#references)</sup>

### Voeg handmatig by

Jy kan tagdata handmatig in Flipper Zero invoer, dit stoor en dit dan naboots.<sup>[[1]](#references)</sup>

#### ID's op kaarte

Soms is die hele ID of ’n deel daarvan op die buitekant van ’n kaart gedruk.

- **EM Marin**

Die afgebeelde EM-Marin-kaart wys byvoorbeeld die laaste drie van sy vyf ID-grepe. As die tag nie gelees kan word nie, kan die twee ontbrekende grepe met brute force gevind word.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Net so druk die afgebeelde HID-kaart slegs twee van die drie ID-grepe af.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Naboots/Skryf

Nadat ’n tag gelees is of sy ID handmatig ingevoer is, kan Flipper Zero die gestoorde toegangsbewys naboots. Vir ondersteunde skryfbare tags kan dit ook die gestoorde data na ’n versoenbare kaart skryf.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: ’n Diepduik in RFID-protokolle](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
