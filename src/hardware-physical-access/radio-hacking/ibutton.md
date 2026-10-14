# iButton

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

iButton is ’n generiese naam vir ’n elektroniese identifikasiesleutel wat in ’n **muntvormige metaalhouer** verpak is. Dit word ook Dallas Touch Memory of kontakgeheue genoem. Hoewel dit dikwels verkeerdelik ’n “magnetiese” sleutel genoem word, is daar **niks magneties** daarin nie. Trouens, ’n volwaardige **mikroskyfie** wat ’n digitale protokol gebruik, is daarin versteek.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Wat is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Die naam iButton beskryf die duursame muntvormige verpakking en kontakrangskikking. Houers sluit plastiekhangertjies, ringe en hangertjies in.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Wanneer albei kontakte aan die leser raak, ontvang die toestel krag en ruil dit data uit. As die ingesinkte kontakgeometrie verhoed dat die buitenste grondkontakte aan mekaar raak, kan jy die sleutel teen die leser se wand kantel om die kontak te herstel.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim-sleutels gebruik die 1-Wire-protokol: een datakontak dra tweerigtingverkeer en kan ook parasitiese krag verskaf, terwyl die metaalhouer die terugvoerkontak is. Die beheerder begin transaksies en die toestel reageer.<sup>[[2]](#references)</sup>

Wanneer die sleutel (Slave) aan die interkom (Master) raak, skakel die skyfie binne-in die sleutel aan, aangedryf deur die interkom, en word die sleutel geïnisialiseer. Daarna versoek die interkom die sleutel-ID. Vervolgens gaan ons hierdie proses in meer besonderhede bekyk.

Flipper kan as die beheerder optree wanneer ’n sleutel gelees word, en as die geëmuleerde toestel wanneer ’n gestoorde identifiseerder aan ’n leser voorgelê word.<sup>[[1]](#references)</sup>

### Dallas-, Cyfral- en Metakom-sleutels

Vir inligting oor hoe hierdie sleutels werk, kyk na die bladsy [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Aanvalle

iButtons kan met Flipper Zero aangeval word:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [iButton tem met Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 1-Wire-kommunikasie deur sagteware](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
