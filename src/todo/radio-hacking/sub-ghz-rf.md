# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Vifunguo vya milango ya garaji kwa kawaida vinatumika katika masafa ya 300-190 MHz, ambapo masafa ya kawaida ni 300 MHz, 310 MHz, 315 MHz, na 390 MHz. Masafa haya yanatumika sana kwa sababu ni ya chini ya msongamano kuliko bendi nyingine za masafa na ni vigumu zaidi kukutana na usumbufu kutoka kwa vifaa vingine.

## Car Doors

Vifunguo vingi vya magari vinatumika kwenye **315 MHz au 433 MHz**. Hizi ni masafa ya redio, na zinatumika katika matumizi mbalimbali tofauti. Tofauti kuu kati ya masafa haya mawili ni kwamba 433 MHz ina eneo kubwa zaidi kuliko 315 MHz. Hii inamaanisha kwamba 433 MHz ni bora kwa matumizi yanayohitaji eneo kubwa, kama vile kuingia bila funguo.\
Nchini Uropa 433.92MHz inatumika sana na nchini Marekani na Japani ni 315MHz.

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Ikiwa badala ya kutuma kila msimbo mara 5 (tumewekwa hivi ili kuhakikisha mpokeaji anaupata) unautuma mara moja tu, muda unakuwa wa dakika 6:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

na ikiwa **unaondoa kipindi cha kusubiri cha 2 ms** kati ya ishara unaweza **kupunguza muda hadi dakika 3.**

Zaidi ya hayo, kwa kutumia Mfuatano wa De Bruijn (njia ya kupunguza idadi ya bits zinazohitajika kutuma nambari zote za binary zinazoweza kutumika kwa burteforce) **muda huu unakuwa wa sekunde 8 tu**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Mfano wa shambulio hili ulitekelezwa katika [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Kuhitaji **preamble kutazuia uboreshaji wa Mfuatano wa De Bruijn** na **nambari zinazozunguka zitalinda shambulio hili** (ikiwa nambari ni ndefu vya kutosha ili isiweze kuburute).

## Sub-GHz Attack

Ili kushambulia ishara hizi kwa Flipper Zero angalia:

{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Vifunguo vya milango ya garaji vya kiotomatiki kwa kawaida vinatumia udhibiti wa mbali wa wireless kufungua na kufunga mlango wa garaji. Udhibiti wa mbali **unatuma ishara ya masafa ya redio (RF)** kwa kifaa cha kufungua mlango wa garaji, ambacho kinafanya kazi kufungua au kufunga mlango.

Inawezekana kwa mtu kutumia kifaa kinachojulikana kama code grabber kukamata ishara ya RF na kuirekodi kwa matumizi ya baadaye. Hii inajulikana kama **replay attack**. Ili kuzuia aina hii ya shambulio, vifunguo vingi vya kisasa vya milango ya garaji vinatumia njia salama zaidi ya usimbaji inayoitwa **rolling code**.

**Ishara ya RF kwa kawaida inatumika kwa kutumia nambari inayozunguka**, ambayo inamaanisha kwamba nambari hubadilika kila wakati inapotumika. Hii inafanya iwe **vigumu** kwa mtu **kukamata** ishara na **kuitumia** kupata **ufikiaji usioidhinishwa** kwenye garaji.

Katika mfumo wa nambari zinazozunguka, udhibiti wa mbali na kifaa cha kufungua mlango wa garaji vina **algorithms zinazoshirikiwa** ambazo **zinaunda nambari mpya** kila wakati udhibiti unapotumika. Kifaa cha kufungua mlango wa garaji kitajibu tu kwa **nambari sahihi**, na kufanya iwe vigumu zaidi kwa mtu kupata ufikiaji usioidhinishwa kwenye garaji kwa kukamata nambari tu.

### **Missing Link Attack**

Kimsingi, unakusikia kwa kitufe na **kukamata ishara wakati udhibiti wa mbali uko nje ya anuwai** ya kifaa (kama gari au garaji). Kisha unahamia kwenye kifaa na **kutumia nambari iliyokamatwa kufungua**.

### Full Link Jamming Attack

Mshambuliaji anaweza **kuzuia ishara karibu na gari au mpokeaji** ili **mpokeaji asisikilize ‘nambari’**, na mara hiyo ikitokea unaweza tu **kukamata na kurudisha** nambari wakati umesitisha kuzuia.

Mtu aliyeathirika kwa wakati fulani atatumia **funguo kufunga gari**, lakini kisha shambulio litakuwa **limerekodi nambari za "fungua mlango"** ambazo kwa matumaini zinaweza kutumwa tena kufungua mlango (**mabadiliko ya masafa yanaweza kuhitajika** kwani kuna magari yanayotumia nambari sawa kufungua na kufunga lakini yanakusikiliza amri zote mbili katika masafa tofauti).

> [!WARNING]
> **Kuzuia inafanya kazi**, lakini inaonekana kama mtu **anayeweka gari anajaribu milango** ili kuhakikisha zimefungwa wangeweza kugundua gari halijafungwa. Zaidi ya hayo, ikiwa wangejua kuhusu mashambulizi kama haya wangeweza hata kusikiliza ukweli kwamba milango haikutoa **sauti** ya kufunga au **mwanga** wa magari haukudunda wakati walipobonyeza kitufe cha ‘fungua’.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Hii ni **mbinu ya kuzuia ya siri zaidi**. Mshambuliaji atazuia ishara, hivyo wakati mtu aliyeathirika anajaribu kufunga mlango haitafanya kazi, lakini mshambuliaji atarekodi **nambari hii**. Kisha, mtu aliyeathirika atajaribu **kufunga gari tena** kwa kubonyeza kitufe na gari litarekodi **nambari hii ya pili**.\
Mara moja baada ya hii **mshambuliaji anaweza kutuma nambari ya kwanza** na **gari litafungwa** (mtu aliyeathirika atafikiria kubonyeza pili kumefunga). Kisha, mshambuliaji ataweza **kutuma nambari ya pili iliyoporwa kufungua** gari (ikiwa **"nambari ya kufunga gari" inaweza pia kutumika kufungua**). Mabadiliko ya masafa yanaweza kuhitajika (kama kuna magari yanayotumia nambari sawa kufungua na kufunga lakini yanakusikiliza amri zote mbili katika masafa tofauti).

Mshambuliaji anaweza **kuzuia mpokeaji wa gari na si mpokeaji wake** kwa sababu ikiwa mpokeaji wa gari unakusikiliza kwa mfano katika broadband ya 1MHz, mshambuliaji hata **hatazuia** masafa halisi yanayotumiwa na udhibiti wa mbali bali **masafa ya karibu katika spektra hiyo** wakati **mpokeaji wa mshambuliaji atakuwa akisikiliza katika anuwai ndogo** ambapo anaweza kusikiliza ishara ya udhibiti wa mbali **bila ishara ya kuzuia**.

> [!WARNING]
> Utekelezaji mwingine ulioonekana katika maelezo ya kiufundi unaonyesha kwamba **nambari inayozunguka ni sehemu** ya jumla ya nambari inayotumwa. Yaani, nambari inayotumwa ni **funguo ya bit 24** ambapo **12 za kwanza ni nambari inayozunguka**, **8 za pili ni amri** (kama kufunga au kufungua) na **4 za mwisho ni **checksum**. Magari yanayotumia aina hii pia kwa asili yanakabiliwa na hatari kwani mshambuliaji anahitaji tu kubadilisha sehemu ya nambari inayozunguka ili kuweza **kutumia nambari yoyote inayozunguka katika masafa yote mawili**.

> [!CAUTION]
> Kumbuka kwamba ikiwa mtu aliyeathirika atatuma nambari ya tatu wakati mshambuliaji anatuma ya kwanza, nambari ya kwanza na ya pili zitabatilishwa.

### Alarm Sounding Jamming Attack

Kujaribu dhidi ya mfumo wa nambari zinazozunguka uliowekwa kwenye gari, **kutuma nambari ile ile mara mbili** mara moja **kulizindua alamu** na immobiliser ikitoa fursa ya kipekee ya **kukataa huduma**. Kwa bahati mbaya, njia ya **kuondoa alamu** na immobiliser ilikuwa **kubonyeza** **udhibiti wa mbali**, ikimpa mshambuliaji uwezo wa **kuendelea kufanya shambulio la DoS**. Au kuchanganya shambulio hili na **la awali ili kupata nambari zaidi** kwani mtu aliyeathirika angependa kusitisha shambulio haraka iwezekanavyo.

## References

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
