# RF ya Sub-GHz

{{#include ../../banners/hacktricks-training.md}}

## Milango ya Gereji

Remote za milango ya gereji hutumia allocations za Sub-GHz zinazotegemea eneo na bidhaa. Masafa kama 300, 310, 315, 390, na 433.92 MHz hupatikana, lakini hakuna bendi ya jumla ya milango ya gereji ya “300–190 MHz”. Tambua label ya target, eneo la kisheria, na signal iliyotazamwa kabla ya kutransmit.<sup>[[1]](#references)</sup>

## Milango ya Magari

Key fob nyingi za magari hutumia **315 MHz au 433.92 MHz**, huku sheria za eneo na muundo wa gari vikiathiri chaguo hilo. Frequency pekee haimaanishi kuwa 433 MHz ina range ndefu kuliko 315 MHz: transmit power, ufanisi wa antenna, modulation, receiver sensitivity, propagation, na sheria za eneo zote zina umuhimu. Ulaya kwa kawaida hutumia 433.92 MHz, wakati 315 MHz hutumika sana Amerika Kaskazini na Japan.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Katika fixed-code system iliyoonyeshwa, kutuma kila code mara moja badala ya mara tano hupunguza muda unaokadiriwa hadi dakika sita:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Kuondoa kusubiri kwa 2 ms kati ya signals hupunguza demonstration hiyo hadi takriban dakika tatu.

Kutumia De Bruijn sequence ku-overlap candidate bit strings hupunguza attack iliyoonyeshwa hadi takriban sekunde nane wakati receiver inakubali continuous sequence bila preamble inayohitajika au frame reset.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame hutekeleza attack hii dhidi ya fixed-code systems zinazoendana.<sup>[[5]](#references)</sup>

Kuhitaji **preamble kutaepusha** optimization ya **De Bruijn Sequence** na **rolling codes zitaazuia attack hii** (tukidhani code ni ndefu vya kutosha kiasi kwamba haiwezi kubruteforce).

## Sub-GHz Attack

Ili ku-attack signals hizi kwa Flipper Zero angalia:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatic garage door openers kwa kawaida hutumia wireless remote control kufungua na kufunga mlango wa gereji. Remote control **hutuma radio frequency (RF) signal** kwa garage door opener, ambayo huamilisha motor kufungua au kufunga mlango.

Inawezekana mtu kutumia kifaa kinachojulikana kama code grabber ku-intercept RF signal na kuirekodi kwa matumizi ya baadaye. Hii inajulikana kama **replay attack**. Ili kuzuia aina hii ya attack, garage door openers wengi wa kisasa hutumia encryption method salama zaidi inayojulikana kama **rolling code** system.

**RF signal kwa kawaida hutumwa kwa kutumia rolling code**, ambayo inamaanisha kuwa code hubadilika kila matumizi. Hii humfanya mtu ashindwe kwa urahisi **ku-intercept** signal na **kuitumia** kupata access **isiyoidhinishwa** kwenye gereji.

Katika rolling code system, remote control na garage door opener huwa na **shared algorithm** ambayo **hutengeneza code mpya** kila remote inapotumiwa. Garage door opener itajibu tu **code sahihi**, jambo linalomfanya mtu ashindwe kwa kiasi kikubwa kupata access isiyoidhinishwa kwenye gereji kwa kunasa code pekee.

### **Missing Link Attack**

Kimsingi, unasikiliza button na **kunasa signal wakati remote iko nje ya range** ya device (kwa mfano gari au gereji). Kisha unasogea kwenye device na **kutumia code iliyonaswa kuifungua**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> RF interference ya makusudi ni kinyume cha sheria katika maeneo mengi ya kisheria na inaweza kuvuruga systems muhimu za usalama. Fanya majaribio ya jamming pekee katika maabara yenye shielding, iliyoidhinishwa, na kwa kufuata radio regulations zinazotumika.<sup>[[6]](#references)</sup>

Attacker anaweza **ku-jam signal karibu na gari au receiver** ili receiver ishindwe ku-decode code, kurekodi transmission iliyozuiwa kando, kuacha jamming, kisha ku-replay code iliyonaswa.<sup>[[2]](#references)</sup>

Victim wakati fulani atatumia **keys kufunga gari**, lakini attack itakuwa **ime-record "close door" codes za kutosha** ambazo huenda zikatumwa tena ili kufungua mlango (**kubadilisha frequency kunaweza kuhitajika** kwa kuwa kuna magari yanayotumia codes zilezile kufungua na kufunga lakini husikiliza commands zote mbili kwenye frequencies tofauti).

> [!WARNING]
> **Jamming inafanya kazi**, lakini inaonekana kwa urahisi kwa sababu **mtu anayefunga gari akijaribu tu milango** kuhakikisha imefungwa, ataona gari likiwa halijafungwa. Zaidi ya hayo, ikiwa angejua kuhusu attacks kama hizi, angeweza hata kugundua kuwa milango haikutoa **sauti** ya kufunga au **taa za gari** hazikuwaka alipobonyeza button ya ‘lock’.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Hii ni **stealth Jamming technique** zaidi. Attacker ata-jam signal, hivyo victim anapojaribu kufunga mlango haitafanya kazi, lakini attacker **ata-record code hii**. Kisha victim **atajaribu kufunga gari tena** kwa kubonyeza button na gari **litarekodi code hii ya pili**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Mara tu baada ya hapo **attacker anaweza kutuma code ya kwanza** na **gari litafungwa** (victim atafikiri kuwa kubonyeza mara ya pili ndiko kulikofunga). Kisha attacker ataweza **kutuma code ya pili iliyoibwa ili kufungua** gari (tukidhani kuwa **code ya "close car" inaweza pia kutumika kulifungua**). Kubadilisha frequency kunaweza kuhitajika (kwa kuwa kuna magari yanayotumia codes zilezile kufungua na kufunga lakini husikiliza commands zote mbili kwenye frequencies tofauti).

Utekelezaji mmoja wa RollJam hutumia receiver bandwidth: jammer hutransmit karibu vya kutosha na carrier ya remote ili kupunguza sensitivity ya receiver pana ya gari, wakati receiver nyembamba ya attacker hubaki ikiwa centered kwenye remote na bado inaweza kuirekodi. Offset na bandwidth halisi hutegemea target hardware.<sup>[[2]](#references)</sup>

> [!WARNING]
> Implementations nyingine zilizoonekana kwenye specifications zinaonyesha kuwa **rolling code ni sehemu** ya code yote inayotumwa. Yaani code inayotumwa ni **24 bit key** ambapo **12 za kwanza ni rolling code**, **8 zinazofuata ni command** (kama lock au unlock) na 4 za mwisho ni **checksum**. Vehicles zinazotumia aina hii pia huwa susceptible kiasili kwa sababu attacker anahitaji tu kubadilisha rolling code segment ili aweze **kutumia rolling code yoyote kwenye frequencies zote mbili**.

> [!CAUTION]
> Kumbuka kuwa victim akituma code ya tatu wakati attacker anatuma ya kwanza, code ya kwanza na ya pili zitakuwa invalidated.

### Alarm Sounding Jamming Attack

Katika majaribio dhidi ya rolling code system ya aftermarket iliyowekwa kwenye gari, **kutuma code ileile mara mbili** mara moja **kuliamilisha alarm** na immobiliser, na kutoa fursa ya kipekee ya **denial of service**. Kwa kushangaza, njia ya **kuzima alarm** na immobiliser ilikuwa **kubonyeza** **remote**, jambo lililompa attacker uwezo wa **kuendelea kufanya DoS attack**. Au changanya attack hii na **iliyotangulia ili kupata codes zaidi**, kwa sababu victim angependa kusimamisha attack haraka iwezekanavyo.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero documentation - regional Sub-GHz frequencies](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame source code](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - Jammer Enforcement](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
