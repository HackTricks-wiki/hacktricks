# iButton

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

iButton is 'n generiese naam vir 'n elektroniese identifikasiesleutel wat in 'n **muntvormige metaalhouer** verpak is. Dit word ook Dallas Touch Memory of contact memory genoem. Alhoewel daar dikwels verkeerdelik na dit as 'n “magnetiese” sleutel verwys word, is daar **niks magneties** daarin nie. Trouens, 'n volwaardige **mikroskyfie** wat op 'n digitale protokol werk, is daarin versteek.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Wat is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Gewoonlik verwys iButton na die fisiese vorm van die sleutel en leser - 'n ronde munt met twee kontakte. Wat die raamwerk rondom dit betref, is daar baie variasies, van die algemeenste plastiekhouer met 'n gaatjie tot ringe, hangertjies, ens.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Wanneer die sleutel die leser bereik, **raak die kontakte aan mekaar** en word die sleutel van krag voorsien om sy ID te **stuur**. Soms word die sleutel **nie onmiddellik gelees nie** omdat die **contact PSD van 'n interkom groter** is as wat dit behoort te wees. Die buitenste kontoere van die sleutel en die leser kon dus nie aan mekaar raak nie. Indien dit die geval is, sal jy die sleutel teen een van die mure van die leser moet druk.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas-sleutels ruil data uit met behulp van die 1-wire-protokol. Met slegs een kontak vir data-oordrag (!!) in albei rigtings, van master na slave en omgekeerd. Die 1-wire-protokol werk volgens die Master-Slave-model. In hierdie topologie begin die Master altyd kommunikasie en volg die Slave sy instruksies.

Wanneer die sleutel (Slave) met die interkom (Master) kontak maak, skakel die skyfie binne die sleutel aan, word dit deur die interkom van krag voorsien, en word die sleutel geïnisialiseer. Daarna versoek die interkom die sleutel se ID. Vervolgens sal ons hierdie proses in meer besonderhede ondersoek.

Flipper kan in beide Master- en Slave-modusse werk. In die sleutel-leesmodus tree Flipper as 'n leser op, dit wil sê dit werk as 'n Master. In die sleutelemulasiemodus maak flipper asof dit 'n sleutel is; dit is in die Slave-modus.

### Dallas-, Cyfral- & Metakom-sleutels

Vir inligting oor hoe hierdie sleutels werk, raadpleeg die bladsy [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Aanvalle

iButtons kan met Flipper Zero aangeval word:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Verwysings

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
