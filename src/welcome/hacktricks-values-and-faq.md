# Thamani na Maswali Yanayoulizwa Mara kwa Mara kuhusu HackTricks

{{#include ../banners/hacktricks-training.md}}

## Thamani za HackTricks

> [!TIP]
> Hizi ndizo **thamani za Mradi wa HackTricks**:
>
> - Kutoa ufikiaji **BILA MALIPO** wa rasilimali za **EDUCATIONAL hacking** kwa **WATU WOTE** kwenye Internet.
>  - Hacking inahusu kujifunza, na kujifunza kunapaswa kuwa huru iwezekanavyo.
>  - Madhumuni ya kitabu hiki ni kutumika kama **rasilimali kamili ya kielimu**.
> - **KUHIFADHI** mbinu bora za **hacking** zinazochapishwa na jamii, huku tukiwapa **WAANDISHI** **HALISI** **sifa** zote.
>  - **Hatutaki sifa kutoka kwa watu wengine**, tunataka tu kuhifadhi mbinu nzuri kwa ajili ya kila mtu.
>  - Pia tunaandika **utafiti wetu wenyewe** katika HackTricks.
>  - Katika hali kadhaa tutaandika tu **muhtasari wa sehemu muhimu za mbinu hiyo katika HackTricks** na **kumhimiza msomaji kutembelea chapisho la asili** kwa maelezo zaidi.
> - **KUPANGA** mbinu zote za hacking katika kitabu ili ziwe **RAHISI ZAIDI KUPATIKANA**
>  - Timu ya HackTricks imetumia maelfu ya saa bila malipo **kwa ajili ya kupanga maudhui tu**, ili watu waweze **kujifunza kwa haraka zaidi**

<figure><img src="../images/hack tricks gif.gif" alt="" width="375"><figcaption></figcaption></figure>

## Maswali yanayoulizwa mara kwa mara kuhusu HackTricks

> [!TIP]
>
> - **Asanteni sana kwa rasilimali hizi, ninawezaje kuwashukuru?**

Unaweza kuishukuru hadharani timu ya HackTricks kwa kuandaa rasilimali hizi zote hadharani kupitia tweet inayomtaja [**@hacktricks_live**](https://twitter.com/hacktricks_live).\
Ikiwa unashukuru sana, unaweza pia [**kufadhili mradi hapa**](https://github.com/sponsors/carlospolop).\
Na usisahau **kuweka star kwenye miradi ya Github!** (Tafuta links hapa chini).

> [!TIP]
>
> - **Ninawezaje kuchangia kwenye mradi?**

Unaweza **kushiriki tips na tricks mpya na jamii au kurekebisha bugs** unazozipata kwenye vitabu kwa kutuma **Pull Request** kwenye kurasa husika za Github:

- [https://github.com/carlospolop/hacktricks](https://github.com/carlospolop/hacktricks)
- [https://github.com/carlospolop/hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)

Usisahau **kuweka star kwenye miradi ya Github!**

> [!TIP]
>
> - **Je, ninaweza kunakili maudhui kutoka HackTricks na kuyaweka kwenye blogu yangu?**

Ndiyo, unaweza, lakini **usisahau kutaja link(s) maalum** ambako maudhui hayo yalichukuliwa.

> [!TIP]
>
> - **Ninawezaje kurejelea ukurasa wa HackTricks?**

Mradi tu **link ya** ukurasa/kurasa ambako ulichukua maelezo ionekane, hiyo inatosha.\
Ikiwa unahitaji bibtex, unaweza kutumia kitu kama:
```latex
@misc{hacktricks-bibtexing,
author = {"HackTricks Team" or the Authors name of the specific page/trick},
title = {Title of the Specific Page},
year = {Year of Last Update (check it at the end of the page)},
url = {\url{https://book.hacktricks.wiki/specific-page}},
}
```
> [!WARNING]
>
> - **Je, naweza kunakili HackTricks yote kwenye blogu yangu?**

**Afadhali usifanye hivyo**. Hilo **halitamfaidi mtu yeyote**, kwa kuwa **maudhui yote tayari yanapatikana hadharani** bila malipo katika vitabu rasmi vya HackTricks.

Ikiwa unaogopa kwamba yatatoweka, yafork kwenye Github au uyapakue; kama nilivyosema, tayari yanapatikana bila malipo.

> [!WARNING]
>
> - **Kwa nini mna sponsors? Je, vitabu vya HackTricks ni kwa madhumuni ya kibiashara?**

**Thamani** ya kwanza ya **HackTricks** ni kutoa rasilimali za elimu ya hacking **BILA MALIPO** kwa ulimwengu **MZIMA**. Timu ya HackTricks **imetumia maelfu ya saa** kutoa maudhui haya, tena, **BILA MALIPO**.

Ikiwa unafikiri vitabu vya HackTricks vimeundwa kwa **madhumuni ya kibiashara**, **UMEKOSEA KABISA**.

Tuna sponsors kwa sababu, ingawa maudhui yote ni ya BURE, tunataka **kuipa jamii uwezekano wa kuthamini kazi yetu** ikiwa wanataka kufanya hivyo. Kwa hiyo, tunawapa watu chaguo la kutoa mchango kwa HackTricks kupitia [**Github sponsors**](https://github.com/sponsors/carlospolop), na **kampuni husika za cybersecurity** zinaweza kusponsor HackTricks na **kuwa na matangazo** kwenye kitabu, huku **matangazo** yakiwekwa kila mara katika maeneo yanayoyafanya **yaonekane**, lakini **yasivuruge mchakato wa kujifunza** ikiwa mtu ataelekeza umakini wake kwenye maudhui.

Hutapata HackTricks ikiwa imejaa matangazo yanayokera kama blogu nyingine zenye maudhui machache zaidi kuliko HackTricks, kwa sababu HackTricks haikuundwa kwa madhumuni ya kibiashara.

> [!CAUTION]
>
> - **Nifanye nini ikiwa ukurasa fulani wa HackTricks umejengwa kutokana na chapisho la blogu yangu lakini haujawekwa ref?**

**Tunaomba radhi sana. Hili halikupaswa kutokea**. Tafadhali, tujulishe kupitia Github issues, Twitter, Discord... kiungo cha ukurasa wa HackTricks wenye maudhui hayo na kiungo cha blogu yako, nasi **tutakichunguza na kukiongeza ASAP**.

> [!CAUTION]
>
> - **Nifanye nini ikiwa kuna maudhui kutoka kwenye blogu yangu katika HackTricks na sitaki yawepo huko?**

Kumbuka kwamba kuwa na viungo vya ukurasa wako katika HackTricks:

- Huboresha **SEO** yako
- Maudhui hayo **hutafsiriwa katika zaidi ya lugha 15**, hivyo kuwawezesha watu zaidi kuyafikia
- **HackTricks inawahimiza** watu **kuangalia ukurasa wako** (watu kadhaa wametueleza kwamba tangu baadhi ya kurasa zao ziwekwe katika HackTricks, wanapokea ziara zaidi)

Hata hivyo, ikiwa bado unataka maudhui ya blogu yako yaondolewe kutoka HackTricks, tujulishe tu, nasi bila shaka **tutaondoa kila kiungo cha blogu yako**, pamoja na maudhui yoyote yaliyotokana nayo.

> [!CAUTION]
>
> - **Nifanye nini nikikuta maudhui yaliyonakiliwa na kubandikwa katika HackTricks?**

Siku zote **tunawapa waandishi asili sifa zote**. Ukipata ukurasa wenye maudhui yaliyonakiliwa na kubandikwa bila chanzo asili kurejelewa, tujulishe, nasi ama **tutayaondoa**, **tutaongeza kiungo kabla ya maandishi**, au **tutayaandika upya huku tukiongeza kiungo**.

## LICENSE

Hakimiliki © Haki zote zimehifadhiwa isipokuwa ikiwa imeelezwa vinginevyo.

#### Muhtasari wa License:

- Attribution: Uko huru:
- Kushiriki — kunakili na kusambaza tena nyenzo katika medium au format yoyote.
- Kurekebisha — kuchanganya upya, kubadilisha, na kujenga juu ya nyenzo hiyo.

#### Masharti ya Ziada:

- Maudhui ya Watu Wengine: Baadhi ya sehemu za blogu/kitabu hiki zinaweza kujumuisha maudhui kutoka vyanzo vingine, kama vile dondoo kutoka blogu au machapisho mengine. Matumizi ya maudhui hayo hufanywa chini ya kanuni za matumizi ya haki au kwa ruhusa ya wazi kutoka kwa wenye hakimiliki husika. Tafadhali rejelea vyanzo asili kwa maelezo mahususi ya licensing kuhusu maudhui ya watu wengine.
- Uandishi: Maudhui asili yaliyoandikwa na HackTricks yako chini ya masharti ya license hii. Unahimizwa kumpa mwandishi sifa anaposhiriki au kurekebisha kazi hii.

#### Misamaha:

- Matumizi ya Kibiashara: Kwa maswali kuhusu matumizi ya kibiashara ya maudhui haya, tafadhali wasiliana nami.

License hii haitoi haki yoyote ya trademark au branding inayohusiana na maudhui haya. Trademarks na branding zote zinazoonekana katika blogu/kitabu hiki ni mali ya wamiliki wake husika.

**Kwa kufikia au kutumia HackTricks, unakubali kufuata masharti ya license hii. Ikiwa hukubaliani na masharti haya, tafadhali, usifikie tovuti hii.**

## **Kanusho**

> [!CAUTION]
> Kitabu hiki, 'HackTricks,' kimekusudiwa kwa madhumuni ya kielimu na ya kutoa taarifa pekee. Maudhui yaliyomo katika kitabu hiki yametolewa kwa msingi wa 'kama yalivyo', na waandishi pamoja na wachapishaji hawatoi uwakilishi au dhamana ya aina yoyote, iwe ya wazi au iliyodokezwa, kuhusu ukamilifu, usahihi, utegemezi, ufaafu, au upatikanaji wa taarifa, bidhaa, huduma, au michoro inayohusiana iliyo ndani ya kitabu hiki. Kwa hiyo, utegemezi wowote unaoweka kwenye taarifa hizo ni kwa hatari yako mwenyewe kabisa.
>
> Waandishi na wachapishaji hawatawajibika kwa hali yoyote kwa hasara au uharibifu wowote, ikiwa ni pamoja na bila kikomo hasara au uharibifu wa moja kwa moja au wa matokeo, au hasara au uharibifu wowote unaotokana na upotevu wa data au faida unaotokana na, au unaohusiana na, matumizi ya kitabu hiki.
>
> Zaidi ya hayo, techniques na tips zilizoelezwa katika kitabu hiki zimetolewa kwa madhumuni ya kielimu na ya kutoa taarifa pekee, na hazipaswi kutumiwa kwa shughuli zozote haramu au zenye nia mbaya. Waandishi na wachapishaji hawakubali wala kuunga mkono shughuli zozote haramu au zisizo za kimaadili, na matumizi yoyote ya taarifa zilizomo katika kitabu hiki ni kwa hatari na uamuzi wa mtumiaji mwenyewe.
>
> Mtumiaji anawajibika pekee kwa hatua zozote zinazochukuliwa kulingana na taarifa zilizomo katika kitabu hiki, na anapaswa daima kutafuta ushauri na msaada wa kitaalamu anapojaribu kutekeleza techniques au tips zozote zilizoelezwa humu.
>
> Kwa kutumia kitabu hiki, mtumiaji anakubali kuwaachilia waandishi na wachapishaji dhidi ya dhima na wajibu wowote unaohusiana na uharibifu, hasara, au madhara yoyote yanayoweza kusababishwa na matumizi ya kitabu hiki au taarifa zozote zilizomo ndani yake.

{{#include ../banners/hacktricks-training.md}}
