# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Milango ya Gereji

Vifungua milango ya gereji kwa kawaida hufanya kazi katika masafa ya 300-190 MHz, huku masafa yanayotumika zaidi yakiwa 300 MHz, 310 MHz, 315 MHz, na 390 MHz. Masafa haya hutumiwa sana na vifungua milango ya gereji kwa sababu yana msongamano mdogo kuliko bendi nyingine za masafa na yana uwezekano mdogo wa kuingiliwa na vifaa vingine.

## Milango ya Magari

Vidhibiti vingi vya funguo za magari hufanya kazi katika **315 MHz au 433 MHz**. Haya yote ni masafa ya redio, na hutumiwa katika matumizi mbalimbali. Tofauti kuu kati ya masafa haya mawili ni kwamba 433 MHz ina range ndefu kuliko 315 MHz. Hii inamaanisha kuwa 433 MHz ni bora kwa matumizi yanayohitaji range ndefu, kama vile kuingia bila ufunguo kwa kutumia remote.\
Ulaya, 433.92MHz hutumiwa kwa kawaida, na Marekani pamoja na Japani hutumia 315MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Badala ya kutuma kila code mara 5 (hutumwa kwa njia hii ili kuhakikisha receiver anaipokea), ukituma mara moja tu, muda hupungua hadi dakika 6:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

na uk **ondoa kipindi cha kusubiri cha ms 2** kati ya signals unaweza **kupunguza muda hadi dakika 3.**

Zaidi ya hayo, kwa kutumia De Bruijn Sequence (njia ya kupunguza idadi ya bits zinazohitajika kutuma binary numbers zote zinazowezekana ili kufanya burteforce), **muda huu hupungua hadi sekunde 8**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Mfano wa attack hii ulitekelezwa katika [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Kuhitaji **preamble kutazuia optimization ya De Bruijn Sequence**, na **rolling codes zitazuia attack hii** (ikidhaniwa kuwa code ni ndefu vya kutosha kiasi kwamba haiwezi kufanyiwa bruteforce).

## Sub-GHz Attack

Ili ku-attack signals hizi kwa Flipper Zero, angalia:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Vifungua milango ya gereji vya kiotomatiki kwa kawaida hutumia remote control isiyotumia waya kufungua na kufunga mlango wa gereji. Remote control **hutuma signal ya radio frequency (RF)** kwa kifungua mlango wa gereji, ambacho huwasha motor ili kufungua au kufunga mlango.

Inawezekana kwa mtu kutumia kifaa kinachojulikana kama code grabber ku-intercept signal ya RF na kuihifadhi kwa matumizi ya baadaye. Hii inajulikana kama **replay attack**. Ili kuzuia aina hii ya attack, vifungua milango vya kisasa vya gereji hutumia njia salama zaidi ya encryption inayojulikana kama mfumo wa **rolling code**.

**RF signal kwa kawaida hutumwa kwa kutumia rolling code**, ambayo inamaanisha kuwa code hubadilika kila inapotumika. Hii humfanya mtu ashindwe kwa urahisi **ku-intercept** signal hiyo na **kuitumia** kupata access **isiyoidhinishwa** ya gereji.

Katika mfumo wa rolling code, remote control na kifungua mlango cha gereji huwa na **algorithm inayoshirikiwa** ambayo **hutengeneza code mpya** kila remote inapotumiwa. Kifungua mlango cha gereji kitajibu tu **code sahihi**, jambo linalofanya iwe vigumu zaidi kwa mtu kupata access isiyoidhinishwa ya gereji kwa kunasa code tu.

### **Missing Link Attack**

Kimsingi, unasikilizia kitufe na **unanasa signal wakati remote iko nje ya range** ya kifaa (kwa mfano gari au gereji). Kisha unasogea hadi kwenye kifaa na **kutumia code iliyonaswa kukifungua**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Mshambulizi anaweza **ku-jam signal karibu na gari au receiver** ili **receiver isiweze kwa kweli ‘kusikia’ code**, na hilo linapotokea unaweza tu **kunasa na ku-replay** code baada ya kuacha ku-jam.<sup>[[2]](#references)</sup>

Mhasiriwa wakati fulani atatumia **funguo kufunga gari**, lakini attack itakuwa **ime-record codes za kutosha za "close door"** ambazo kwa matumaini zinaweza kutumwa tena ili kufungua mlango (kubadilisha frequency kunaweza kuhitajika, kwa kuwa kuna magari yanayotumia codes zilezile kufungua na kufunga, lakini yanasikiliza commands zote mbili kwenye frequencies tofauti).

> [!WARNING]
> **Jamming hufanya kazi**, lakini huonekana kwa sababu mtu anayefunga gari akijaribu tu milango ili kuhakikisha kuwa imefungwa, ataona kuwa gari limefunguka. Zaidi ya hayo, ikiwa anafahamu attacks kama hizi, anaweza hata kugundua kuwa milango haikutoa **sauti** ya kufunga au **taa** za gari hazikuwaka alipobonyeza kitufe cha ‘lock’.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Hii ni **stealth Jamming technique**. Mshambulizi ata-jam signal, kwa hiyo mhasiriwa akijaribu kufunga mlango haitafanya kazi, lakini mshambulizi **ata-record code hii**. Kisha, mhasiriwa **atajaribu kufunga gari tena** kwa kubonyeza kitufe, na gari **lita-record code hii ya pili**.<sup>[[2]](#references)[[4]](#references)</sup>\
Mara tu baada ya hapo, **mshambulizi anaweza kutuma code ya kwanza** na **gari litafunga** (mhasiriwa atafikiri kuwa kubonyeza mara ya pili ndiko kulikofunga). Kisha, mshambulizi ataweza **kutuma code ya pili iliyoibwa ili kufungua** gari (ikidhaniwa kuwa **code ya "close car" inaweza pia kutumika kulifungua**). Kubadilisha frequency kunaweza kuhitajika (kwa kuwa kuna magari yanayotumia codes zilezile kufungua na kufunga, lakini yanasikiliza commands zote mbili kwenye frequencies tofauti).

Mshambulizi anaweza **ku-jam receiver ya gari na si receiver yake** kwa sababu ikiwa receiver ya gari inasikiliza, kwa mfano, broadband ya 1MHz, mshambulizi hata-**jam** frequency halisi inayotumiwa na remote bali **frequency iliyo karibu nayo katika spectrum hiyo**, huku receiver ya mshambulizi ikiwa inasikiliza range ndogo zaidi ambako anaweza kusikiliza signal ya remote **bila jam signal**.

> [!WARNING]
> Implementations nyingine zilizoonekana katika specifications zinaonyesha kuwa **rolling code ni sehemu** ya code yote inayotumwa. Kwa mfano, code inayotumwa ni **key ya bits 24**, ambapo **bits 12 za kwanza ni rolling code**, **bits 8 zinazofuata ni command** (kama lock au unlock), na bits 4 za mwisho ni **checksum**. Vehicles zinazotumia aina hii pia kwa kawaida huwa vulnerable, kwa sababu mshambulizi anahitaji tu kubadilisha sehemu ya rolling code ili aweze **kutumia rolling code yoyote kwenye frequencies zote mbili**.

> [!CAUTION]
> Kumbuka kuwa ikiwa mhasiriwa atatuma code ya tatu wakati mshambulizi anatuma ya kwanza, code ya kwanza na ya pili zitabatilishwa.

### Alarm Sounding Jamming Attack

Katika testing dhidi ya rolling code system ya aftermarket iliyowekwa kwenye gari, **kutuma code ileile mara mbili** kuliamsha mara moja **alarm** na immobiliser, na kutoa fursa ya kipekee ya **denial of service**. Kwa kushangaza, njia ya **kuzima alarm** na immobiliser ilikuwa **kubonyeza** **remote**, jambo lililompa mshambulizi uwezo wa **kuendelea kufanya DoS attack**. Au changanya attack hii na **iliyotangulia ili kupata codes zaidi**, kwa kuwa mhasiriwa atataka kusitisha attack haraka iwezekanavyo.<sup>[[2]](#references)</sup>

## Marejeo

- [1] [Ni Radio Frequency Gani Inayotumiwa na Vidhibiti vya Funguo za Magari?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Kukwepa Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Jinsi ya Ku-hack Gari - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
