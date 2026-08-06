# iButton

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

iButton ni jina la jumla la ufunguo wa utambulisho wa kielektroniki uliofungashwa katika **kifaa cha chuma chenye umbo la sarafu**. Pia huitwa **Dallas Touch** Memory au contact memory. Ingawa mara nyingi huitwa kimakosa ufunguo wa “magnetic”, ndani yake **hakuna kitu cha sumaku**. Kwa kweli, ndani yake kuna **microchip** kamili inayotumia itifaki ya kidijitali.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton ni nini? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Kwa kawaida, iButton humaanisha umbo la kimwili la ufunguo na kisomaji - sarafu ya duara yenye viunganishi viwili. Kwa fremu inayouzunguka, kuna tofauti nyingi kuanzia kishikiliaji cha plastiki chenye tundu, ambacho ndicho kinachotumika zaidi, hadi pete, pendanti, n.k.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Ufunguo unapofikia kisomaji, **viunganishi hugusana** na ufunguo hupewa nguvu ya **kutuma** kitambulisho chake. Wakati mwingine ufunguo **hausomwi** mara moja kwa sababu **PSD ya mgusano ya intercom ni kubwa** kuliko inavyopaswa kuwa. Hivyo, mipaka ya nje ya ufunguo na kisomaji haiwezi kugusana. Ikiwa ndivyo, utahitaji kubonyeza ufunguo dhidi ya mojawapo ya kuta za kisomaji.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Itifaki ya 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas keys hubadilishana data kwa kutumia itifaki ya 1-wire. Ikiwa na contact moja tu ya kuhamisha data (!!) katika pande zote mbili, kutoka master kwenda slave na kinyume chake. Itifaki ya 1-wire hufanya kazi kulingana na muundo wa Master-Slave. Katika topolojia hii, Master huanzisha mawasiliano kila mara na Slave hufuata maagizo yake.

Ufunguo (Slave) unapogusana na intercom (Master), chipu iliyo ndani ya ufunguo hujiwasha, ikiendeshwa na intercom, na ufunguo huanzishwa. Baada ya hapo, intercom huomba kitambulisho cha ufunguo. Ifuatayo, tutaangalia mchakato huu kwa undani zaidi.

Flipper inaweza kufanya kazi katika hali za Master na Slave. Katika hali ya kusoma ufunguo, Flipper hufanya kazi kama kisomaji, yaani hufanya kazi kama Master. Na katika hali ya kuiga ufunguo, Flipper hujifanya kuwa ufunguo, hivyo huwa katika hali ya Slave.<sup>[[1]](#references)</sup>

### Funguo za Dallas, Cyfral & Metakom

Kwa maelezo kuhusu jinsi funguo hizi zinavyofanya kazi, angalia ukurasa [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Mashambulizi

iButtons zinaweza kushambuliwa kwa kutumia Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Marejeo

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
