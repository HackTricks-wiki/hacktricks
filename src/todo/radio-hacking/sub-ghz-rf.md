# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Milango ya Gereji

Vifungua milango ya gereji kwa kawaida hufanya kazi katika masafa ya 300-190 MHz, huku masafa yanayotumika zaidi yakiwa 300 MHz, 310 MHz, 315 MHz, na 390 MHz. Masafa haya hutumiwa sana na vifungua milango ya gereji kwa sababu yana msongamano mdogo kuliko bendi nyingine za masafa na yana uwezekano mdogo wa kuingiliwa na vifaa vingine.

## Milango ya Magari

Vifaa vingi vya remote za funguo za magari hufanya kazi kwenye **315 MHz au 433 MHz**. Haya yote ni masafa ya redio, na hutumiwa katika matumizi mbalimbali. Tofauti kuu kati ya masafa haya mawili ni kwamba 433 MHz ina range ndefu kuliko 315 MHz. Hii inamaanisha kuwa 433 MHz inafaa zaidi kwa matumizi yanayohitaji range ndefu, kama vile remote keyless entry.\
Huko Ulaya 433.92MHz hutumiwa kwa kawaida, na huko Marekani na Japan ni 315MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Badala ya kutuma kila code mara 5 (hutumwa hivyo ili kuhakikisha receiver anaipokea), ukituma mara moja tu, muda hupungua hadi dakika 6:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

na uk **ondoa kipindi cha kusubiri cha 2 ms** kati ya signals unaweza **kupunguza muda hadi dakika 3.**

Zaidi ya hayo, kwa kutumia De Bruijn Sequence (njia ya kupunguza idadi ya bits zinazohitajika kutuma binary numbers zote zinazowezekana kwa ajili ya brute-force), **muda huu hupunguzwa hadi sekunde 8 tu**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Mfano wa attack hii ulitekelezwa katika [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)<sup>[[3]](#references)</sup>

Kuhitaji **preamble kutaepusha optimization ya De Bruijn Sequence**, na **rolling codes zitazuia attack hii** (ikidhaniwa kuwa code ni ndefu vya kutosha isiweze kufanyiwa brute-force).

## Sub-GHz Attack

Ili ku-attack signals hizi kwa Flipper Zero angalia:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Ulinzi wa Rolling Codes

Vifungua milango ya gereji vya kiotomatiki kwa kawaida hutumia remote control isiyotumia waya kufungua na kufunga mlango wa gereji. Remote control **hutuma signal ya radio frequency (RF)** kwa kifungua mlango wa gereji, ambacho huamsha motor kufungua au kufunga mlango.

Mtu anaweza kutumia kifaa kinachojulikana kama code grabber kukatiza signal ya RF na kuihifadhi kwa matumizi ya baadaye. Hii inajulikana kama **replay attack**. Ili kuzuia aina hii ya attack, vifungua milango ya gereji vya kisasa hutumia mbinu salama zaidi ya encryption inayojulikana kama mfumo wa **rolling code**.

**Signal ya RF kwa kawaida hutumwa kwa kutumia rolling code**, ambayo inamaanisha kuwa code hubadilika kila inapotumiwa. Hii humfanya **mwingiliaji** ashindwe kwa urahisi **kukata** signal na **kuitumia** kupata ufikiaji **usioidhinishwa** wa gereji.

Katika mfumo wa rolling code, remote control na kifungua mlango wa gereji huwa na **algorithm ya pamoja** ambayo **hutengeneza code mpya** kila remote inapotumiwa. Kifungua mlango wa gereji kitajibu tu **code sahihi**, jambo linalofanya iwe vigumu zaidi kwa mtu kupata ufikiaji usioidhinishwa wa gereji kwa kunasa code pekee.

### **Missing Link Attack**

Kimsingi, unasikiliza kitufe na **unanasa signal wakati remote iko nje ya range** ya kifaa (kwa mfano gari au gereji). Kisha unasogea hadi kwenye kifaa na **kutumia code iliyonaswa kukifungua**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Mshambuliaji anaweza **kuzuia signal karibu na gari au receive**r ili **receiver asiweze kuisikia code**, na hilo linapotokea unaweza tu **kunasa na kurudia** code baada ya kuacha kuzuia signal.

Mwathiriwa wakati fulani atatumia **funguo kufunga gari**, lakini attack itakuwa **imesharekodi codes za kutosha za "kufunga mlango"** ambazo huenda zikatwekwa tena ili kufungua mlango (huenda **mabadiliko ya frequency yakahitajika**, kwa kuwa kuna magari yanayotumia codes zilezile kufungua na kufunga lakini yanasikiliza commands zote mbili kwenye frequencies tofauti).

> [!WARNING]
> **Jamming hufanya kazi**, lakini inaonekana kwa urahisi kwa sababu ikiwa **mtu anayefunga gari atajaribu tu milango** ili kuhakikisha imefungwa, ataona kuwa gari limefunguliwa. Zaidi ya hayo, ikiwa alikuwa anafahamu attacks kama hizi, angeweza hata kusikia kwamba milango haikutoa **sauti ya kufunga** au **taa za gari** hazikuwaka alipobonyeza kitufe cha ‘lock’.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Hii ni **mbinu ya Jamming iliyo fiche zaidi**. Mshambuliaji atazuia signal, kwa hiyo mwathiriwa anapojaribu kufunga mlango haitafanya kazi, lakini mshambuliaji **atarekodi code hii**. Kisha mwathiriwa **atajaribu kufunga gari tena** kwa kubonyeza kitufe, na gari **litarekodi code hii ya pili**.\
Mara moja baada ya hapo, **mshambuliaji anaweza kutuma code ya kwanza** na **gari litafungwa** (mwathiriwa atafikiri kuwa kubonyeza mara ya pili ndiko kulikofunga). Kisha mshambuliaji ataweza **kutuma code ya pili iliyoibwa ili kufungua** gari (ikidhaniwa kuwa **code ya "kufunga gari" inaweza pia kutumika kulifungua**). Huenda mabadiliko ya frequency yakahitajika (kwa kuwa kuna magari yanayotumia codes zilezile kufungua na kufunga lakini yanasikiliza commands zote mbili kwenye frequencies tofauti).<sup>[[3]](#references)[[2]](#references)</sup>

Mshambuliaji anaweza **ku-jam receiver ya gari na si receiver wake** kwa sababu ikiwa receiver ya gari inasikiliza, kwa mfano, broadband ya 1MHz, mshambuliaji hata-**jam** frequency halisi inayotumiwa na remote, bali **frequency iliyo karibu katika spectrum hiyo**, huku receiver ya mshambuliaji ikisikiliza range ndogo zaidi ambako anaweza kusikia signal ya remote **bila signal ya jam**.

> [!WARNING]
> Implementations nyingine zilizoonekana katika specifications zinaonyesha kuwa **rolling code ni sehemu** ya code yote inayotumwa. Yaani code inayotumwa ni **key ya bits 24**, ambapo **bits 12 za kwanza ni rolling code**, **bits 8 zinazofuata ni command** (kama vile lock au unlock), na bits 4 za mwisho ni **checksum**. Magari yanayotumia aina hii pia huathirika kiasili kwa sababu mshambuliaji anahitaji tu kubadilisha sehemu ya rolling code ili aweze **kutumia rolling code yoyote kwenye frequencies zote mbili**.

> [!CAUTION]
> Kumbuka kuwa mwathiriwa akituma code ya tatu wakati mshambuliaji anatuma ya kwanza, code ya kwanza na ya pili zitabatilishwa.

### Alarm Sounding Jamming Attack

Wakati wa kujaribu mfumo wa rolling code wa baada ya kiwandani uliowekwa kwenye gari, **kutuma code ileile mara mbili** mara moja **kuliwasha alarm** na immobiliser, na kutoa fursa ya kipekee ya **denial of service**. Kwa kushangaza, njia ya **kuzima alarm** na immobiliser ilikuwa **kubonyeza** **remote**, jambo lililompa mshambuliaji uwezo wa **kuendelea kufanya DoS attack**. Au changanya attack hii na **iliyotangulia ili kupata codes zaidi**, kwa kuwa mwathiriwa angependa kusitisha attack haraka iwezekanavyo.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
