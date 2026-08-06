# Masharti ya Uwekezaji

{{#include ../banners/hacktricks-training.md}}

## Spot

Hii ndiyo njia ya msingi zaidi ya kufanya trading. Unaweza **kuonyesha kiasi cha asset na bei** unayotaka kununua au kuuza, na bei hiyo inapofikiwa, operesheni inatekelezwa.

Kwa kawaida unaweza pia kutumia **bei ya sasa ya soko** ili kufanya muamala haraka iwezekanavyo kwa bei ya sasa.

**Stop Loss - Limit**: Unaweza pia kuonyesha kiasi na bei za assets za kununua au kuuza, huku pia ukionyesha bei ya chini ya kununua au kuuza endapo itafikiwa (ili kusitisha hasara).

## Futures

Future ni mkataba ambapo pande 2 hukubaliana **kupata kitu hapo baadaye kwa bei iliyowekwa**. Kwa mfano, kuuza bitcoin 1 baada ya miezi 6 kwa bei ya $70,000.

Ni wazi kwamba ikiwa baada ya miezi 6 thamani ya bitcoin ni $80,000, upande wa muuzaji hupoteza pesa na upande wa mnunuzi hupata pesa. Ikiwa baada ya miezi 6 thamani ya bitcoin ni $60,000, kinyume chake hutokea.

Hata hivyo, hii inafaa kwa mfano kwa biashara zinazozalisha bidhaa na zinahitaji uhakika kwamba zitaweza kuiuza kwa bei itakayolipia gharama. Au biashara zinazotaka kuhakikisha bei zilizowekwa hapo baadaye za kitu fulani, hata kama bei hizo ni za juu.

Ingawa kwenye exchanges hii kwa kawaida hutumiwa kujaribu kupata faida.

* Kumbuka kwamba "Long position" inamaanisha mtu anaweka dau kwamba bei itaongezeka
* Wakati "short position" inamaanisha mtu anaweka dau kwamba bei itashuka

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Ikiwa msimamizi wa fund anaogopa kwamba baadhi ya stocks zitashuka, anaweza kuchukua short position kwenye assets kama bitcoins au mikataba ya futures ya S\&P 500. Hii itafanana na kununua au kuwa na baadhi ya assets na kuunda mkataba wa kuziuza wakati fulani hapo baadaye kwa bei kubwa zaidi.

Ikiwa bei itashuka, msimamizi wa fund atapata faida kwa sababu atauza assets kwa bei kubwa zaidi. Ikiwa bei ya assets itaongezeka, msimamizi hatapata faida hiyo, lakini bado atazihifadhi assets zake.

### Perpetual Futures

**Hizi ni "futures" zitakazodumu bila kikomo** (bila tarehe ya mwisho ya mkataba). Ni jambo la kawaida kuzipata, kwa mfano, kwenye crypto exchanges ambapo unaweza kuingia na kutoka kwenye futures kulingana na bei ya cryptos.

Kumbuka kwamba katika hali hizi faida na hasara vinaweza kutokea kwa wakati halisi; bei ikiongezeka kwa 1%, utapata faida ya 1%, na bei ikishuka kwa 1%, utapoteza 1%.

### Futures with Leverage

**Leverage** hukuwezesha kudhibiti position kubwa zaidi kwenye soko kwa kutumia kiasi kidogo cha pesa. Kimsingi hukuwezesha "kuweka dau" la pesa nyingi zaidi kuliko ulizo nazo, huku ukihatarisha pesa ulizo nazo tu.

Kwa mfano, ukifungua future position kwenye BTC/USDT kwa $100 na leverage ya 50x, hii inamaanisha kwamba ikiwa bei itaongezeka kwa 1%, utapata 1x50 = 50% ya uwekezaji wako wa awali ($50). Kwa hiyo utakuwa na $150.\
Hata hivyo, ikiwa bei itashuka kwa 1%, utapoteza 50% ya fedha zako ($59 katika hali hii). Na ikiwa bei itashuka kwa 2%, utapoteza dau lako lote (2x50 = 100%).

Kwa hiyo, kutumia leverage hukuwezesha kudhibiti kiasi cha pesa unachoweka kwenye dau huku ukiongeza faida na hasara.

## Tofauti Kati ya Futures na Options

Tofauti kuu kati ya futures na options ni kwamba mkataba huo ni wa hiari kwa mnunuzi: Anaweza kuamua kuutekeleza au la (kwa kawaida ataukutekeleza tu ikiwa atanufaika). Muuzaji lazima auze ikiwa mnunuzi anataka kutumia option.\
Hata hivyo, mnunuzi atamlipa muuzaji ada fulani kwa kufungua option (kwa hiyo muuzaji, ambaye inaonekana anachukua hatari kubwa zaidi, huanza kupata pesa).

### 1. **Wajibu dhidi ya Haki:**

* **Futures:** Unaponunua au kuuza mkataba wa futures, unaingia kwenye **makubaliano ya lazima** ya kununua au kuuza asset kwa bei maalum katika tarehe fulani ya baadaye. Mnunuzi na muuzaji wote **wanalazimika** kutimiza mkataba wakati wa kuisha kwake (isipokuwa mkataba umefungwa kabla ya hapo).
* **Options:** Kwenye options, una **haki, lakini si wajibu**, ya kununua (katika kesi ya **call option**) au kuuza (katika kesi ya **put option**) asset kwa bei maalum kabla ya au katika tarehe fulani ya mwisho. **Mnunuzi** ana option ya kuitekeleza, huku **muuzaji** akiwa na wajibu wa kutimiza trade ikiwa mnunuzi ataamua kutumia option hiyo.

### 2. **Hatari:**

* **Futures:** Mnunuzi na muuzaji wote huchukua **hatari isiyo na kikomo** kwa sababu wanalazimika kukamilisha mkataba. Hatari ni tofauti kati ya bei iliyokubaliwa na bei ya soko katika tarehe ya mwisho.
* **Options:** Hatari ya mnunuzi imewekewa kikomo na **premium** iliyolipwa kununua option. Ikiwa soko halisogei kwa faida ya mwenye option, anaweza kuiacha option iishe tu. Hata hivyo, **muuzaji** (writer) wa option ana hatari isiyo na kikomo ikiwa soko litasogea kwa kiasi kikubwa dhidi yake.

### 3. **Gharama:**

* **Futures:** Hakuna gharama ya awali zaidi ya margin inayohitajika kushikilia position, kwa sababu mnunuzi na muuzaji wote wanalazimika kukamilisha trade.
* **Options:** Mnunuzi lazima alipe **option premium** mapema kwa ajili ya haki ya kutumia option. Premium hii kimsingi ndiyo gharama ya option.

### 4. **Uwezekano wa Faida:**

* **Futures:** Faida au hasara inategemea tofauti kati ya bei ya soko wakati wa kuisha kwa mkataba na bei iliyokubaliwa kwenye mkataba.
* **Options:** Mnunuzi hupata faida soko linaposogea kwa manufaa yake na kuvuka strike price kwa kiasi kinachozidi premium iliyolipwa. Muuzaji hupata faida kwa kuhifadhi premium ikiwa option haitatumika.

{{#include ../banners/hacktricks-training.md}}
