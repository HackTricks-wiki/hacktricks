# iButton

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

iButton is 'n generiese naam vir 'n elektroniese identifikasiesleutel wat in 'n **muntvormige metaalhouer** verpak is. Dit word ook Dallas Touch-geheue of kontakgeheue genoem. Alhoewel daar dikwels verkeerdelik na dit as 'n “magnetiese” sleutel verwys word, is daar **niks magneties** daaraan nie. Trouens, 'n volwaardige **mikroskyfie** wat op 'n digitale protokol werk, is binne-in versteek.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Wat is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Gewoonlik verwys iButton na die fisiese vorm van die sleutel en leser - 'n ronde muntstuk met twee kontakte. Wat die raamwerk rondom dit betref, is daar baie variasies, van die algemeenste plastiekhouer met 'n gat tot ringe, hangertjies, ens.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Wanneer die sleutel die leser bereik, **raak die kontakte aan mekaar** en word die sleutel aangeskakel om sy ID te **versend**. Soms word die sleutel **nie onmiddellik gelees nie** omdat die **kontak-PSD van 'n interkom groter** as wat dit behoort te wees, is. Daarom kon die buitenste kontoere van die sleutel en leser nie aan mekaar raak nie. As dit die geval is, sal jy die sleutel teen een van die mure van die leser moet druk.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas-sleutels ruil data uit deur die 1-wire-protokol te gebruik. Met slegs een kontak vir data-oordrag (!!) in albei rigtings, van master na slave en omgekeerd. Die 1-wire-protokol werk volgens die Master-Slave-model. In hierdie topologie begin die Master altyd die kommunikasie, en die Slave volg sy instruksies.

Wanneer die sleutel (Slave) met die interkom (Master) kontak maak, skakel die skyfie binne die sleutel aan, aangedryf deur die interkom, en die sleutel word geïnisialiseer. Daarna versoek die interkom die sleutel se ID. Vervolgens sal ons hierdie proses in meer besonderhede ondersoek.

Flipper kan in beide Master- en Slave-modusse werk. In die sleutel-leesmodus tree Flipper as 'n leser op, dit wil sê dit werk as 'n Master. In die sleutel-emulasiemodus gee die Flipper voor om 'n sleutel te wees; dit is in die Slave-modus.<sup>[[1]](#references)</sup>

### Dallas-, Cyfral- & Metakom-sleutels

Vir inligting oor hoe hierdie sleutels werk, kyk na die bladsy [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Aanvalle

iButtons kan met Flipper Zero aangeval word:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Verwysings

- [1] [Tem iButton met Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
