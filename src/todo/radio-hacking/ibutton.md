# iButton

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

iButton ni jina la jumla la ufunguo wa utambulisho wa kielektroniki uliowekwa ndani ya **kifuko cha chuma chenye umbo la sarafu**. Pia huitwa **Dallas Touch** Memory au contact memory. Ingawa mara nyingi huitwa kimakosa ufunguo wa “sumaku”, **hakuna kitu cha kimagneti** ndani yake. Kwa kweli, ndani yake kuna **microchip** kamili inayofanya kazi kwa kutumia digital protocol.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton ni nini? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Kwa kawaida, iButton humaanisha umbo la kimwili la ufunguo na reader - sarafu ya mviringo yenye contacts mbili. Kwa fremu inayouzunguka, kuna tofauti nyingi, kuanzia holder ya plastiki inayotumika zaidi yenye tundu hadi rings, pendants, n.k.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Ufunguo unapofikia reader, **contacts hugusana** na ufunguo hupewa nguvu ili **kutuma** ID yake. Wakati mwingine ufunguo **hausomwi** mara moja kwa sababu **contact PSD ya intercom ni kubwa** kuliko inavyopaswa kuwa. Kwa hiyo, kingo za nje za ufunguo na reader haziwezi kugusana. Hilo likitokea, utalazimika kubonyeza ufunguo dhidi ya mojawapo ya kuta za reader.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas keys hubadilishana data kwa kutumia 1-wire protocol. Kwa kutumia contact moja tu ya kuhamisha data (!!) katika pande zote mbili, kutoka master kwenda slave na kinyume chake. 1-wire protocol hufanya kazi kulingana na mfumo wa Master-Slave. Katika topolojia hii, Master daima huanzisha mawasiliano na Slave hufuata maelekezo yake.

Ufunguo (Slave) unapogusana na intercom (Master), chip iliyomo ndani ya ufunguo huwasha, ikiwezeshwa na intercom, na ufunguo huanzishwa. Baada ya hapo, intercom huomba ID ya ufunguo. Ifuatayo, tutaangalia mchakato huu kwa undani zaidi.

Flipper inaweza kufanya kazi katika modes za Master na Slave. Katika mode ya kusoma ufunguo, Flipper hufanya kazi kama reader, yaani hufanya kazi kama Master. Na katika mode ya ku-emulate ufunguo, Flipper hujifanya kuwa ufunguo; huwa katika mode ya Slave.

### Dallas, Cyfral & Metakom keys

Kwa maelezo kuhusu jinsi keys hizi zinavyofanya kazi, angalia ukurasa [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attacks

iButtons zinaweza ku-attackiwa kwa kutumia Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Marejeleo

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
