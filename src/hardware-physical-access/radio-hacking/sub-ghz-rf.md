# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Milango ya Gereji

Vidhibiti vya mbali vya milango ya gereji hutumia masafa ya sub-GHz yanayotegemea eneo na bidhaa. Masafa kama 300, 310, 315, 390, na 433.92 MHz hupatikana, lakini hakuna bendi ya jumla ya milango ya gereji ya “300–190 MHz”. Tambua lebo ya kifaa lengwa, eneo lake la udhibiti wa masafa, na signal iliyozingatiwa kabla ya kutuma signal.<sup>[[1]](#references)</sup>

## Milango ya Gari

Vidhibiti vingi vya mbali vya funguo za gari hutumia **315 MHz au 433.92 MHz**, huku kanuni za kikanda na muundo wa gari vikiathiri uchaguzi. Masafa pekee hayafanyi 433 MHz kuwa na masafa marefu kuliko 315 MHz: nguvu ya usambazaji, ufanisi wa antena, modulation, unyeti wa kipokezi, usambazaji wa mawimbi, na kanuni za eneo vyote vina umuhimu. Ulaya hutumia 433.92 MHz kwa kawaida, ilhali 315 MHz hutumika sana Amerika Kaskazini na Japani.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Katika mfumo wa fixed-code ulioonyeshwa, kutuma kila code mara moja badala ya mara tano hupunguza muda unaokadiriwa hadi dakika sita:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Kuondoa kusubiri kwa ms 2 kati ya signal kunapunguza muda wa onyesho hilo hadi takriban dakika tatu.

Kutumia mfuatano wa De Bruijn kuingiliana kwa sehemu na mfuatano wa biti unaotarajiwa hupunguza shambulio lililoonyeshwa hadi takriban sekunde nane, ikiwa kipokezi kinakubali mfuatano endelevu bila kuhitaji preamble au kuanza upya kwa fremu.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame hutekeleza shambulio hili dhidi ya mifumo ya fixed-code inayooana.<sup>[[5]](#references)</sup>

Kuhitaji **preamble kutazuia** uboreshaji wa **De Bruijn Sequence**, na **rolling codes zitazuia shambulio hili** (tukidhani code ni ndefu vya kutosha isiweze kuvunjwa kwa brute force).

## Shambulio la Sub-GHz

Ili kushambulia signal hizi kwa Flipper Zero, angalia:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Ulinzi wa Rolling Codes

Vifungua milango ya gereji vya kiotomatiki kwa kawaida hutumia kidhibiti cha mbali kisichotumia waya kufungua na kufunga mlango wa gereji. Kidhibiti cha mbali **hutuma signal ya radio frequency (RF)** kwa kifungua mlango wa gereji, ambacho huwasha mota ili kufungua au kufunga mlango.

Inawezekana mtu akatumia kifaa kinachojulikana kama code grabber kunasa signal ya RF na kuirekodi kwa matumizi ya baadaye. Hili hujulikana kama **replay attack**. Ili kuzuia aina hii ya shambulio, vifungua milango vingi vya kisasa hutumia mbinu salama zaidi ya usimbaji fiche inayojulikana kama mfumo wa **rolling code**.

**Signal ya RF kwa kawaida hutumwa kwa kutumia rolling code**, maana yake code hubadilika kila inapotumika. Hii hufanya iwe **vigumu** kwa mtu **kunasa** signal hiyo na **kuitumia** kupata **ufikiaji usioidhinishwa** wa gereji.

Katika mfumo wa rolling code, kidhibiti cha mbali na kifungua mlango wa gereji huwa na **algorithm ya pamoja** ambayo **hutengeneza code mpya** kila kidhibiti cha mbali kinapotumika. Kifungua mlango wa gereji hujibu tu **code sahihi**, hivyo kufanya iwe vigumu zaidi kwa mtu kupata ufikiaji usioidhinishwa wa gereji kwa kunasa code tu.

### **Missing Link Attack**

Kimsingi, unasikiliza kitufe kikibonyezwa na **kunasa signal wakati kidhibiti cha mbali kiko nje ya masafa ya kifaa** (kwa mfano gari au gereji). Kisha unaenda kwenye kifaa na **kutumia code iliyonaswa kukifungua**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Kuingilia kwa makusudi mawasiliano ya RF ni kinyume cha sheria katika maeneo mengi na kunaweza kuvuruga mifumo muhimu kwa usalama. Fanya majaribio ya jamming katika maabara iliyokingwa, iliyoidhinishwa, na kwa kufuata kanuni husika za radio pekee.<sup>[[6]](#references)</sup>

Mshambuliaji anaweza **kujam signal karibu na gari au kipokezi** ili kipokezi kishindwe kusimbua code, kunasa kando usambazaji uliozuiwa, kuacha jamming, kisha kutuma tena code iliyonaswa.<sup>[[2]](#references)</sup>

Wakati fulani, mwathiriwa atatumia **funguo kufunga gari**, lakini shambulio litakuwa **limerekodi code za kutosha za “kufunga mlango”** ambazo huenda zikatumwa tena ili kufungua mlango (huenda **ikahitajika kubadilisha masafa**, kwa sababu baadhi ya magari hutumia code zilezile kufungua na kufunga lakini husikiliza amri zote mbili kwenye masafa tofauti).

> [!WARNING]
> **Jamming hufanya kazi**, lakini hugundulika kwa urahisi: ikiwa **mtu anayefunga gari atajaribu tu milango ili kuhakikisha imefungwa**, atagundua kuwa gari limeachwa bila kufungwa. Zaidi ya hayo, akijua kuhusu mashambulio haya, anaweza hata kugundua kuwa milango haikutoa **sauti** ya kufungwa au **taa** za gari hazikuwaka alipobonyeza kitufe cha ‘lock’.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Hii ni mbinu ya **Jamming iliyo fiche zaidi**. Mshambuliaji hujam signal ili mwathiriwa akijaribu kufunga mlango, isifanye kazi, lakini mshambuliaji **atarekodi code hii**. Kisha mwathiriwa **atajaribu kufunga gari tena** kwa kubonyeza kitufe, na gari **litarekodi code hii ya pili**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Mara moja baada ya hapo, **mshambuliaji anaweza kutuma code ya kwanza** na **gari litafungwa** (mwathiriwa atadhani kubonyeza kwa pili ndiko kulilofunga). Kisha mshambuliaji ataweza **kutuma code ya pili iliyoibwa ili kufungua** gari (tukidhani kwamba code ya **“kufunga gari” inaweza pia kutumika kulifungua**). Huenda ikahitajika kubadilisha masafa (kwa sababu baadhi ya magari hutumia code zilezile kufungua na kufunga lakini husikiliza amri zote mbili kwenye masafa tofauti).

Utekelezaji mmoja wa RollJam hutumia tofauti ya bandwidth ya vipokezi: jammer hutuma signal karibu vya kutosha na carrier ya kidhibiti cha mbali ili kupunguza unyeti wa kipokezi kipana zaidi cha gari, huku kipokezi chembamba zaidi cha mshambuliaji kikibaki kimeelekezwa kwenye signal ya kidhibiti cha mbali na kuweza kuirekodi. Offset na bandwidth husika hutegemea hardware lengwa.<sup>[[2]](#references)</sup>

> [!WARNING]
> Utekelezaji mwingine unaoonekana kwenye specifications unaonyesha kuwa **rolling code ni sehemu tu** ya code nzima inayotumwa. Yaani, code inayotumwa ni **ufunguo wa biti 24**, ambapo **biti 12 za kwanza ni rolling code**, **biti 8 zinazofuata ni amri** (kama kufunga au kufungua), na biti 4 za mwisho ni **checksum**. Magari yanayotumia aina hii pia huathirika kiasili, kwa sababu mshambuliaji anahitaji tu kubadilisha sehemu ya rolling code ili aweze **kutumia rolling code yoyote kwenye masafa yote mawili**.

> [!CAUTION]
> Kumbuka kwamba mwathiriwa akituma code ya tatu wakati mshambuliaji anatuma ya kwanza, code ya kwanza na ya pili zitabatilishwa.

### Alarm Sounding Jamming Attack

Katika jaribio lililofanywa dhidi ya mfumo wa rolling code wa ziada uliowekwa kwenye gari, **kutuma code ileile mara mbili** kuliwasha **kengele na immobiliser** mara moja, na kutoa fursa ya kipekee ya **denial of service**. Kwa kejeli, njia ya **kuzima kengele** na immobiliser ilikuwa **kubonyeza** **kidhibiti cha mbali**, hivyo kumpa mshambuliaji uwezo wa **kuendelea kutekeleza DoS attack**. Au changanya shambulio hili na **lililotangulia ili kupata code zaidi**, kwa kuwa mwathiriwa angependa kukomesha shambulio hilo haraka iwezekanavyo.<sup>[[2]](#references)</sup>

## References

- [1] [Nyaraka za Flipper Zero - masafa ya Sub-GHz ya kikanda](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Kukwepa Mifumo ya Rolling Code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Endesha Kama Umeidukua (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Jinsi ya Kudukua Gari - kutengeneza upya RollJam kwa YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Msimbo chanzo wa OpenSesame](https://github.com/samyk/opensesame)
- [6] [Ushauri wa Utekelezaji wa FCC - Utekelezaji dhidi ya Jammer](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
