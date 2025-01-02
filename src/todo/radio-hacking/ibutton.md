# iButton

{{#include ../../banners/hacktricks-training.md}}

## Intro

iButton ni jina la jumla la funguo ya kitambulisho cha kielektroniki iliyowekwa katika **konteina ya chuma yenye umbo la sarafu**. Pia inaitwa **Dallas Touch** Memory au kumbukumbu ya mawasiliano. Ingawa mara nyingi inaitwa kwa makosa kama funguo “za magnetic”, hakuna **kitu chochote cha magnetic** ndani yake. Kwa kweli, **microchip** kamili inayofanya kazi kwenye protokali ya kidijitali imefichwa ndani.

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Kawaida, iButton inamaanisha umbo la kimwili la funguo na msomaji - sarafu ya mviringo yenye mawasiliano mawili. Kwa ajili ya fremu inayozunguka, kuna aina nyingi kutoka kwa holder ya plastiki yenye shimo hadi pete, mapambo, n.k.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Wakati funguo inafikia msomaji, **mawasiliano yanagusa** na funguo inapata nguvu ili **kupeleka** kitambulisho chake. Wakati mwingine funguo **haiwezi kusomwa** mara moja kwa sababu **PSD ya mawasiliano ya intercom ni kubwa** kuliko inavyopaswa kuwa. Hivyo, mipaka ya nje ya funguo na msomaji haiwezi kugusa. Ikiwa ndivyo ilivyo, itabidi ubonyeze funguo juu ya moja ya kuta za msomaji.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Funguo za Dallas hubadilishana data kwa kutumia protokali ya 1-wire. Kwa mawasiliano moja tu ya kuhamasisha data (!!) katika pande zote mbili, kutoka kwa bwana hadi mtumwa na kinyume chake. Protokali ya 1-wire inafanya kazi kulingana na mfano wa Bwana-Mtumwa. Katika topolojia hii, Bwana daima huanzisha mawasiliano na Mtumwa anafuata maagizo yake.

Wakati funguo (Mtumwa) inagusa intercom (Bwana), chip ndani ya funguo inawashwa, ikipata nguvu kutoka kwa intercom, na funguo inaanzishwa. Kufuatia hiyo, intercom inaomba kitambulisho cha funguo. Kisha, tutaangalia mchakato huu kwa undani zaidi.

Flipper inaweza kufanya kazi katika hali za Bwana na Mtumwa. Katika hali ya kusoma funguo, Flipper inafanya kazi kama msomaji hii inamaanisha inafanya kazi kama Bwana. Na katika hali ya kuiga funguo, flipper inajifanya kuwa funguo, iko katika hali ya Mtumwa.

### Dallas, Cyfral & Metakom keys

Kwa maelezo kuhusu jinsi funguo hizi zinavyofanya kazi angalia ukurasa [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacks

iButtons zinaweza kushambuliwa kwa Flipper Zero:

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
