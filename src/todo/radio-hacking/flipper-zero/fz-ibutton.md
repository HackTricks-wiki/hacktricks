# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Vir meer inligting oor wat 'n iButton is, kyk:


{{#ref}}
../ibutton.md
{{#endref}}

## Ontwerp

Die **blou** deel van die volgende afbeelding wys hoe jy die **werklike iButton** moet **plaas** sodat die Flipper dit kan **lees.** Die **groen** deel wys hoe jy die leser met die Flipper Zero moet **aanraak** om 'n iButton **korrek te emuleer**.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Lees

In Leesmodus wag Flipper dat die iButton-sleutel aangeraak word en kan dit enige van drie tipes sleutels verwerk: **Dallas, Cyfral, en Metakom**. Flipper sal **die tipe sleutel self bepaal**. Die naam van die sleutelprotokol sal op die skerm bo die ID-nommer vertoon word.<sup>[[1]](#references)</sup>

### Voeg handmatig by

Dit is moontlik om 'n iButton van die volgende tipes **handmatig by te voeg**: **Dallas, Cyfral, en Metakom**

### **Emuleer**

Dit is moontlik om gestoorde iButtons te **emuleer** (gelees of handmatig bygevoeg).

> [!TIP]
> As jy nie die verwagte kontakte van die Flipper Zero teen die leser kan laat raak nie, kan jy **die eksterne GPIO gebruik:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Verwysings

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
