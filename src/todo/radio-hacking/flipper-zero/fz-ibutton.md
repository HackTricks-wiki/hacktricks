# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Vir meer inligting oor wat 'n iButton is, kyk:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

Die **blou** deel van die volgende beeld is hoe jy die **regte iButton** moet **plaas** sodat die Flipper dit kan **lees.** Die **groen** deel is hoe jy die **leser** met die Flipper zero moet **raak** om 'n iButton **korrek na te boots.**

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

In Leesmodus wag die Flipper vir die iButton-sleutel om te raak en kan dit enige van drie tipes sleutels verteer: **Dallas, Cyfral, en Metakom**. Flipper sal **die tipe van die sleutel self uitvind**. Die naam van die sleutelprotokol sal op die skerm bo die ID-nommer vertoon word.

### Add manually

Dit is moontlik om 'n iButton van tipe: **Dallas, Cyfral, en Metakom** **handmatig by te voeg.**

### **Emulate**

Dit is moontlik om **iButtons** wat gestoor is (gelees of handmatig bygevoeg) te **emuleer.**

> [!NOTE]
> As jy nie die verwagte kontakte van die Flipper Zero kan laat raak nie, kan jy die **eksterne GPIO gebruik:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
