# iButton

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

iButton ni jina la jumla la ufunguo wa utambulisho wa kielektroniki uliowekwa ndani ya **kifuko cha chuma chenye umbo la sarafu**. Pia huitwa kumbukumbu ya **Dallas Touch** au kumbukumbu ya mguso. Ingawa mara nyingi huitwa kimakosa ufunguo wa “sumaku”, **hakuna kitu cha sumaku** ndani yake. Kwa hakika, ndani yake kuna **microchip** kamili inayotumia itifaki ya kidijitali.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton ni nini? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Jina iButton linaelezea kifurushi imara chenye umbo la sarafu na mpangilio wa sehemu za mguso. Vishikio vinajumuisha vishikio vya plastiki, pete na pendanti.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Miguso yote miwili inapokutana na msomaji, kifaa hupokea umeme na kubadilishana data. Ikiwa umbo lililozama la mguso linazuia miguso ya nje ya ground kukutana, kuuinamisha ufunguo dhidi ya ukuta wa msomaji kunaweza kurejesha mguso.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Itifaki ya 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Funguo za Dallas/Maxim hutumia itifaki ya 1-Wire: mguso mmoja wa data hubeba mawasiliano ya pande mbili na pia unaweza kutoa umeme wa parasitic, huku kifuko cha chuma kikiwa mguso wa kurejea. Kidhibiti huanzisha miamala na kifaa hujibu.<sup>[[2]](#references)</sup>

Ufunguo (Slave) unapogusana na intercom (Master), chipu iliyo ndani ya ufunguo huwashwa na intercom, na ufunguo huanzishwa. Baada ya hapo intercom huomba kitambulisho cha ufunguo. Sasa tutaichunguza mchakato huu kwa undani zaidi.

Flipper inaweza kufanya kazi kama kidhibiti wakati wa kusoma ufunguo na kama kifaa kilichoigwa wakati wa kuwasilisha kitambulisho kilichohifadhiwa kwa msomaji.<sup>[[1]](#references)</sup>

### Funguo za Dallas, Cyfral na Metakom

Kwa maelezo kuhusu jinsi funguo hizi zinavyofanya kazi, angalia ukurasa [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Mashambulizi

iButton zinaweza kushambuliwa kwa kutumia Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Kudhibiti iButton kwa Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Mawasiliano ya 1-Wire kupitia software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
