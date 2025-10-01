# HackTricks Maadili & Maswali Yanayoulizwa Mara kwa Mara

{{#include ../banners/hacktricks-training.md}}

## HackTricks Values

> [!TIP]
> Hizi ni **maadili ya Mradi wa HackTricks**:
>
> - Toa **FREE** access kwa **EDUCATIONAL hacking** resources kwa **INTANETI YOTE**.
>  - Hacking ni kuhusu kujifunza, na kujifunza kunapaswa kuwa bure iwezekanavyo.
>  - Madhumuni ya kitabu hiki ni kutumika kama **rasilimali ya EDUCATIONAL** kamili.
> - **STORE** techniques za ajabu za hacking ambazo jamii inachapisha ikimpa **ORIGINAL** **AUTHORS** sifa wote (**CREDITS**).
>  - **Hatutaki sifa za watu wengine**, tunataka tu kuhifadhi tricks nzuri kwa wote.
>  - Pia tunaandika **tafiti zetu** ndani ya HackTricks.
>  - Katika matukio kadhaa tutakuwa tukielezea **katika HackTricks muhtasari wa sehemu muhimu** za mbinu na tutamshauri msomaji kutembelea post ya asili kwa maelezo zaidi.
> - **ORGANIZE** techniques zote za hacking kwenye kitabu ili ziwe **RAHISI KUPATA**
>  - Timu ya HackTricks imewekeza maelfu ya saa bure **tu kwa kupanga yaliyomo** ili watu waweze **kujifunza haraka zaidi**

<figure><img src="../images/hack tricks gif.gif" alt="" width="375"><figcaption></figcaption></figure>

## HackTricks Maswali ya Mara kwa Mara

> [!TIP]
>
> - **Asante sana kwa rasilimali hizi, ninawezaje kuwashukuru?**

Unaweza kumshukuru hadharani timu za HackTricks kwa kuandaa rasilimali hizi zote kwa kuchapisha tweet ukimtaja [**@hacktricks_live**](https://twitter.com/hacktricks_live).\
Kama umefurahia hasa unaweza pia [**kuunga mkono mradi hapa**](https://github.com/sponsors/carlospolop).\
Na usisahau **kutoa nyota kwenye miradi ya Github!** (Tafuta viungo hapa chini).

> [!TIP]
>
> - **Ninawezaje kuchangia mradi?**

Unaweza **kushiriki tips na tricks mpya na jamii au kurekebisha bugs** unazopata kwenye vitabu kwa kutuma **Pull Request** kwenye kurasa husika za Github:

- [https://github.com/carlospolop/hacktricks](https://github.com/carlospolop/hacktricks)
- [https://github.com/carlospolop/hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)

Usisahau **kutoa nyota kwenye miradi ya Github!**

> [!TIP]
>
> - **Je, naweza kunakili sehemu ya yaliyomo kutoka HackTricks na kuviweka kwenye blogu yangu?**

Ndiyo, unaweza, lakini **usisahau kutaja link(s) maalumu** ambapo yaliyomo yalichukuliwa.

> [!TIP]
>
> - **Ninawezaje kunukuu ukurasa wa HackTricks?**

Iwapo link ya ukurasa(uke) uliochukua taarifa inatokea inatosha.\
Kama unahitaji bibtex unaweza kutumia kitu kama:
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
> - **Je, ninaweza kunakili HackTricks yote kwenye blogu yangu?**

**Ningependelea si**. Hiyo **haitakuwa na faida kwa yeyote** kwani **maudhui yote tayari yanapatikana hadharani** katika vitabu rasmi vya HackTricks kwa bure.

Ikiwa unaogopa yataondoka, chomeka (fork) kwenye Github au upakue; kama nilivyosema tayari ni bure.

> [!WARNING]
>
> - **Kwa nini mna wadhamini? Je, vitabu vya HackTricks vinalenga madhumuni ya kibiashara?**

Thamani ya kwanza ya **HackTricks** ni kutoa rasilimali za elimu ya hacking **BURE** kwa **WOTE** duniani. Timu ya HackTricks imeweka **maelfu ya saa** kutoa maudhui haya, tena, kwa **BURE**.

Ikiwa unafikiri vitabu vya HackTricks vimetengenezwa kwa **madhumuni ya kibiashara** wewe ni **UMEKOSA KABISA**.

Tuna wadhamini kwa sababu, hata kama maudhui yote ni BURE, tunataka **kutoa jamii uwezekano wa kuthamini kazi yetu** ikiwa wanataka. Kwa hivyo, tunawawezesha watu kuchangia HackTricks kupitia [**Github sponsors**](https://github.com/sponsors/carlospolop), na kampuni zinazofaa za usalama wa mtandao kuwadhamini HackTricks na kuwa na **matangazo** katika kitabu, ambapo **matangazo** hayo yamewekwa mahali pao ili yaonekane lakini **hayavurugi mchakato wa kujifunza** ikiwa mtu anazingatia maudhui.

Hautapata HackTricks imejazwa na matangazo ya kusumbua kama blogu nyingine zenye maudhui chache zaidi kuliko HackTricks, kwa sababu HackTricks haijatengenezwa kwa madhumuni ya kibiashara.

> [!CAUTION]
>
> - **Nifanye nini ikiwa ukurasa wa HackTricks umetegemea chapisho langu la blogu lakini haujatajwa?**

**Tunasikitika sana. Hii haipaswi kuwa imetokea.** Tafadhali tujulishe kupitia Github issues, Twitter, Discord... kiungo cha ukurasa wa HackTricks wenye maudhui na kiungo cha blogu yako na **tutakagua na kuiongeza KWA HARAKA**.

> [!CAUTION]
>
> - **Nifanye nini ikiwa kuna maudhui kutoka blogu yangu kwenye HackTricks na sitaki yawepo hapo?**

Kumbuka kwamba kuwa na viungo vya ukurasa wako katika HackTricks:

- Boresha yako **SEO**
- Maudhui yanatafsiriwa kwa **lugha zaidi ya 15**, hivyo kuwawezesha watu zaidi kupata maudhui haya
- **HackTricks inahimiza** watu **kutembelea ukurasa wako** (watu kadhaa wamenukuu kuwa tangu ukurasa wao uwiwe kwenye HackTricks wamepata ziara nyingi zaidi)

Hata hivyo, ikiwa bado unataka maudhui ya blogu yako yafutwe kutoka HackTricks tu tujulishe na tutafanya uhakika wa **kufuta kila kiungo kwa blogu yako**, na maudhui yoyote yanayotegemea nayo.

> [!CAUTION]
>
> - **Nifanye nini ikiwa nitapata maudhui yaliyotekelezwa copy-paste katika HackTricks?**

Sisi daima tunawapa waandishi wa asili sifa zote. Ikiwa utakutana na ukurasa wenye maudhui yaliyotekelezwa bila chanzo asili kurejelewa, tujulishe na tuteither **tutaitoa**, **tutaongeza kiungo kabla ya maandishi**, au **tutaandika tena tukiweka kiungo**.

## LESENI

Haki miliki © Haki zote zimehifadhiwa isipokuwa pale ambapo vimesemwa vingine.

#### Muhtasari wa Leseni:

- Attribution: Una uhuru wa:
- Share — nakili na sambaza tena nyenzo hii kwa njia yoyote au muundo wowote.
- Adapt — rekebisha, badilisha, na tengeneza juu ya nyenzo hii.

#### Masharti ya Ziada:

- Third-Party Content: Sehemu kadhaa za blogu/kitabu hiki zinaweza kujumuisha maudhui kutoka vyanzo vingine, kama vijembe kutoka blogu au machapisho mengine. Matumizi ya maudhui hayo hufanywa kwa misingi ya matumizi mwafaka (fair use) au kwa ruhusa wazi kutoka kwa wamiliki wa hakimiliki husika. Tafadhali rejea vyanzo vya asili kwa taarifa maalum za leseni kuhusu maudhui ya wahusika wa tatu.
- Authorship: Maudhui ya asili yaliyoandikwa na HackTricks yamo chini ya masharti ya leseni hii. Unahimizwa kumtaja mwandishi wakati wa kushiriki au kurekebisha kazi hii.

#### Msamaha:

- Commercial Use: Kwa maswali kuhusu matumizi ya kibiashara ya maudhui haya, tafadhali wasiliana nami.

Leseni hii haikupi haki yoyote ya alama za biashara au haki za ukuzaji chapa kuhusiana na maudhui. Alama zote za biashara na chapa zilizo kwenye blogu/kitabu hiki ni mali ya wamiliki wake.

**Kwa kufikia au kutumia HackTricks, unakubali kufuata masharti ya leseni hii. Ikiwa hukubaliani na masharti haya, tafadhali, usitumie tovuti hii.**

## **Tamko (Disclaimer)**

> [!CAUTION]
> Kitabu hiki, 'HackTricks,' kimekusudiwa kwa madhumuni ya elimu na taarifa pekee. Maudhui ndani ya kitabu hiki yanatolewa kwa msingi wa 'kama yalivyo', na waandishi na wachapishaji hawatoi taarifa wala dhamana za aina yoyote, za wazi au za fumbo, kuhusu ukamilifu, usahihi, uaminifu, ufanisi, au upatikana kwa taarifa, bidhaa, huduma, au grafiki zinazohusiana zilizo ndani ya kitabu hiki. Kila utegemezi utakaoweka kwenye taarifa hizo ni kwa hatari yako mwenyewe.
> 
> Waandishi na wachapishaji hawatakuwa na wajibu wala hawatalipwa kwa hasara au uharibifu wowote, ikijumuisha bila kikomo, hasara au uharibifu usio wa moja kwa moja au wa matokeo, au hasara au uharibifu wowote utakaotokana na kupoteza data au faida zinazotokana na, au kuhusiana na, matumizi ya kitabu hiki.
> 
> Zaidi ya hayo, mbinu na vidokezo vilivyoelezewa katika kitabu hiki vimetolewa kwa madhumuni ya elimu na taarifa pekee, na havipaswi kutumika kwa shughuli zozote zisizofaa kisheria au zenye nia mbaya. Waandishi na wachapishaji hawana msimamo wa kuunga mkono au kusapoti shughuli zozote zisizo za kisheria au zisizo za maadili, na matumizi yoyote ya taarifa zilizo ndani ya kitabu hiki ni kwa hatari na hiari ya mtumiaji.
> 
> Mtumiaji ndiye mwenye jukumu kamili kwa vitendo vyovyote vitakavyofanywa kwa msingi wa taarifa zilizo ndani ya kitabu hiki, na kila mara awe akitafuta ushauri na msaada wa kitaalamu anapojaribu kutekeleza mbinu au vidokezo vilivyoelezwa hapa.
> 
> Kwa kutumia kitabu hiki, mtumiaji anakubali kuwarejesha waandishi na wachapishaji huru kutokana na dhamana na jukumu lolote kwa uharibifu, hasara, au madhara ambayo yanaweza kuletwa na matumizi ya kitabu hiki au yoyote ya taarifa zilizo ndani yake.

{{#include ../banners/hacktricks-training.md}}
