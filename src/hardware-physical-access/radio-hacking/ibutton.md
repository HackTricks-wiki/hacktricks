# iButton

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

iButton ni jina la jumla la ufunguo wa utambulisho wa kielektroniki uliofungashwa ndani ya **chombo cha metali chenye umbo la sarafu**. Pia huitwa Dallas Touch Memory au contact memory. Ingawa mara nyingi huitwa kimakosa ufunguo wa “sumaku”, **hakuna chochote cha sumaku** ndani yake. Kwa hakika, **microchip** kamili inayotumia itifaki ya kidijitali imefichwa ndani.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton ni nini? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Jina iButton linaelezea kifungashio imara chenye umbo la sarafu na mpangilio wa mawasiliano. Vifungashio vyake ni pamoja na vishikio vya plastiki, pete na pendenti.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Mawasiliano yote mawili yanapogusana na reader, kifaa hupokea umeme na kubadilishana data. Ikiwa muundo wa mawasiliano uliorudishwa ndani unazuia mawasiliano ya nje ya ground kugusana, kuegemeza ufunguo dhidi ya ukuta wa reader kunaweza kurejesha mgusano.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Itifaki ya 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Funguo za Dallas/Maxim hutumia itifaki ya 1-Wire: mawasiliano moja ya data husafirisha trafiki ya pande mbili na yanaweza pia kutoa umeme wa parasitic, huku ganda la metali likiwa mawasiliano ya kurejesha mkondo. Controller huanzisha miamala, na kifaa hujibu.<sup>[[2]](#references)</sup>

Ufunguo (Slave) unapogusana na intercom (Master), chipu iliyo ndani ya ufunguo huwashwa kwa umeme unaotolewa na intercom, na ufunguo huanzishwa. Baada ya hapo, intercom huomba ID ya ufunguo. Sasa tutaangalia mchakato huu kwa undani zaidi.

Flipper inaweza kufanya kazi kama controller inaposoma ufunguo na kama kifaa kilichoigwa inapowasilisha kitambulisho kilichohifadhiwa kwa reader.<sup>[[1]](#references)</sup>

### Funguo za Dallas, Cyfral na Metakom

Kwa maelezo kuhusu jinsi funguo hizi zinavyofanya kazi, angalia ukurasa huu [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Mashambulizi

iButton zinaweza kushambuliwa kwa kutumia Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Kudhibiti iButton kwa Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Mawasiliano ya 1-Wire kupitia programu](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
