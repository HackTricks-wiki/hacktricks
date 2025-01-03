# iButton

{{#include ../../banners/hacktricks-training.md}}

## Intro

iButton is 'n generiese naam vir 'n elektroniese identifikasiesleutel wat in 'n **muntvormige metaalhouer** gepak is. Dit word ook **Dallas Touch** Memory of kontakgeheue genoem. Alhoewel dit dikwels verkeerdelik as 'n “magnetiese” sleutel verwys word, is daar **niks magneties** daarin nie. Trouens, 'n volwaardige **mikrochip** wat op 'n digitale protokol werk, is binne-in versteek.

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Wat is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Gewoonlik impliseer iButton die fisiese vorm van die sleutel en leser - 'n ronde munt met twee kontakte. Vir die raam wat dit omring, is daar baie variasies van die mees algemene plastiekhouer met 'n gat tot ringe, hangers, ens.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Wanneer die sleutel die leser bereik, **raak die kontakte aan** en die sleutel word van krag voorsien om sy ID te **verzenden**. Soms word die sleutel **nie onmiddellik gelees** nie omdat die **kontak PSD van 'n interkom groter** is as wat dit behoort te wees. So die buitenste kontour van die sleutel en die leser kon nie aanraak nie. As dit die geval is, sal jy die sleutel oor een van die mure van die leser moet druk.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas sleutels ruil data uit met behulp van die 1-wire protokol. Met slegs een kontak vir datatransfer (!!) in beide rigtings, van meester na slaaf en omgekeerd. Die 1-wire protokol werk volgens die Meester-Slaaf model. In hierdie topologie begin die Meester altyd kommunikasie en die Slaaf volg sy instruksies.

Wanneer die sleutel (Slaaf) die interkom (Meester) kontak, draai die chip binne-in die sleutel aan, aangedryf deur die interkom, en die sleutel word geïnitialiseer. Daarna versoek die interkom die sleutel ID. Volgende, sal ons hierdie proses in meer detail ondersoek.

Flipper kan beide in Meester en Slaaf modi werk. In die sleutel leesmodus, tree Flipper op as 'n leser, dit wil sê dit werk as 'n Meester. En in die sleutel emulasie modus, doen die flipper asof dit 'n sleutel is, dit is in die Slaaf modus.

### Dallas, Cyfral & Metakom sleutels

Vir inligting oor hoe hierdie sleutels werk, kyk die bladsy [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Aanvalle

iButtons kan aangeval word met Flipper Zero:

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Verwysings

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
