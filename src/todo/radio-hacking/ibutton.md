# iButton

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

iButton is 'n generiese naam vir 'n elektroniese identifikasiesleutel wat in 'n **muntvormige metaalhouer** verpak is. Dit word ook Dallas Touch Memory of contact memory genoem. Alhoewel daar dikwels verkeerdelik daarna verwys word as 'n “magnetiese” sleutel, is daar **niks magneties** daarin nie. Trouens, 'n volledige **mikroskyfie** wat op 'n digitale protokol werk, is daarin versteek.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Wat is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Die naam iButton beskryf die duursame muntvormige verpakking en kontakrangskikking. Houers sluit plastiekfobs, ringe en hangertjies in.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Wanneer albei kontakte die leser raak, ontvang die toestel krag en verruil dit data. As die ingesakte kontakgeometrie verhoed dat die buitenste grondkontakte mekaar raak, kan die sleutel teen die leser se wand gekantel word om kontak te herstel.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim-sleutels gebruik die 1-Wire-protokol: een datakontak dra tweerigtingverkeer en kan ook parasitiese krag voorsien, terwyl die metaalhouer die terugvoerkontak is. Die beheerder begin transaksies en die toestel reageer daarop.<sup>[[2]](#references)</sup>

Wanneer die sleutel (Slave) kontak maak met die interkom (Master), skakel die skyfie binne die sleutel aan, aangedryf deur die interkom, en die sleutel word geïnisialiseer. Daarna versoek die interkom die sleutel-ID. Vervolgens sal ons hierdie proses in meer besonderhede ondersoek.

Flipper kan as die beheerder optree wanneer 'n sleutel gelees word, en as die geëmuleerde toestel optree wanneer 'n gestoorde identifiseerder aan 'n leser voorgelê word.<sup>[[1]](#references)</sup>

### Dallas-, Cyfral- & Metakom-sleutels

Vir inligting oor hoe hierdie sleutels werk, besoek die bladsy [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Aanvalle

iButtons kan met Flipper Zero aangeval word:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 1-Wire communication through software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
