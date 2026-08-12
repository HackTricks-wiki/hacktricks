# Masharti ya Uwekezaji

{{#include ../banners/hacktricks-training.md}}

## Spot

Spot trading hubadilisha asset kwa uwasilishaji wa papo hapo. Limit order hubainisha kiasi na bei ya juu au ya chini inayokubalika; hutekelezwa tu wakati market inaweza kukidhi bei hiyo au bei bora zaidi. Market order badala yake hulenga utekelezaji wa haraka kwa bei bora zinazopatikana wakati huo na inaweza kukumbwa na slippage.<sup>[[4]](#references)</sup>

Stop-limit order ina stop price inayowasha limit order. Inaweza kudhibiti bei ya utekelezaji, lakini haihakikishi utekelezaji ikiwa market itapita kiwango cha limit.<sup>[[4]](#references)</sup>

## Futures

Futures contract ni makubaliano yaliyosanifishwa ya kununua au kuuza commodity au financial instrument maalum katika tarehe ya baadaye. Kwa mfano, wahusika wawili wanaweza kukubaliana bei ya $70,000 kwa bitcoin moja, kwa settlement baada ya miezi sita.<sup>[[1]](#references)</sup>

Ikiwa settlement price ni $80,000, long side hupata faida na short side hupata hasara ikilinganishwa na bei ya contract ya $70,000. Ikiwa ni $60,000, mwelekeo hubadilika. Futures zinazouzwa kwenye exchanges halisi huwekwa kwenye mark to market na kwa kawaida hufungwa au ku-roll kabla ya expiration, kwa hiyo huu ni mfano uliorahisishwa.<sup>[[2]](#references)</sup>

Wazalishaji na watumiaji hutumia futures kuzuia price risk; washiriki wengine huzitumia kutafuta faida au kutoa liquidity.<sup>[[1]](#references)</sup>

- **Long position** kwa kawaida hupata faida wakati bei ya contract inapanda.
- **Short position** kwa kawaida hupata faida wakati bei ya contract inashuka.<sup>[[2]](#references)</sup>

### Hedging With Futures

Ikiwa fund manager anatarajia portfolio kushuka, anaweza kufanya short kwenye stock-index futures contract yenye correlation ya kutosha. Faida kutoka kwenye short hedge inaweza kufidia baadhi ya hasara za portfolio; basis risk humaanisha kuwa ulinganifu huo mara chache huwa kamili. Bitcoin future ingezuia bitcoin exposure, si portfolio ya stocks moja kwa moja.

Ikiwa market iliyofanyiwa hedge inashuka, short futures position inaweza kupata faida huku holdings zikishuka thamani. Ikiwa inapanda, holdings zinaweza kupata faida huku hedge ikipata hasara. Hedging hupunguza risk iliyochaguliwa badala ya kuunda faida iliyohakikishwa.<sup>[[1]](#references)</sup>

### Perpetual Futures

Perpetual contracts ni derivatives zisizo na tarehe maalum ya expiration. Crypto venues kwa kawaida hutumia malipo ya funding ya vipindi ili kusaidia kuweka bei yao karibu na spot price ya underlying asset; masharti hutofautiana kulingana na venue.<sup>[[3]](#references)</sup>

Faida na hasara hubadilika mark price inaposogea. Mabadiliko ya bei ya 1% huzalisha takriban mabadiliko ya 1% kwenye notional value ya position kabla ya fees na funding, lakini leverage inaweza kufanya hayo yawe asilimia kubwa zaidi ya collateral iliyowekwa.

### Futures with Leverage

**Leverage** humwezesha trader kudhibiti position yenye notional value kubwa kwa margin deposit ndogo. Hasara si lazima ziishie kwenye initial margin: liquidation, gaps, fees na kanuni za venue zinaweza kusababisha hasara za ziada.<sup>[[3]](#references)</sup>

Kwa mfano, margin ya $100 yenye leverage ya 50x hudhibiti position ya $5,000. Tukipuuza fees, funding na liquidation mechanics, mabadiliko mazuri ya 1% huzalisha faida ya $50 (50% ya initial margin), huku mabadiliko yasiyofaa ya 1% yakizalisha hasara ya $50. Mabadiliko yasiyofaa ya 2% yanalingana na $100, ingawa venue kwa kawaida italiquidate position kabla margin yote kuisha.

Leverage huongeza ukubwa wa faida na hasara na hufanya liquidation iwezekane baada ya mabadiliko madogo kwa kulinganisha lakini yasiyofaa.

## Differences Between Futures and Options

Option buyer hupokea haki, si wajibu, wa ku-exercise kulingana na masharti ya contract. Option writer ana wajibu unaolingana ikiwa buyer ata-exercise. Buyer humlipa writer premium kwa ajili ya haki hiyo.<sup>[[4]](#references)</sup>

### 1. **Wajibu dhidi ya Haki:**

* **Futures:** Unaponunua au kuuza futures contract, unaingia kwenye **binding agreement** ya kununua au kuuza asset kwa bei maalum katika tarehe ya baadaye. Buyer na seller wote **wanalazimika** kutimiza contract wakati wa expiration (isipokuwa contract ifungwe kabla ya hapo).
* **Options:** Ukiwa na options, una **haki, lakini si wajibu**, wa kununua (katika **call option**) au kuuza (katika **put option**) asset kwa bei maalum kabla au katika tarehe fulani ya expiration. **Buyer** ana chaguo la kutekeleza, huku **seller** akiwa na wajibu wa kukamilisha trade ikiwa buyer ataamua ku-exercise option.

### 2. **Risk:**

* **Futures:** Pande zote zinaweza kupata hasara kubwa. Ikiwa hasara ni theoretically unlimited hutegemea position na underlying asset: short position inaweza kuwa na hasara ya kinadharia isiyo na kikomo, huku long position isiweze kupoteza zaidi ya notional value ikiwa underlying haiwezi kushuka chini ya sifuri.
* **Options:** Buyer ambaye haandiki option nyingine kwa kawaida yuko kwenye risk ya premium aliyolipa. Naked call writer anaweza kukabiliwa na hasara ya kinadharia isiyo na kikomo; mikakati mingine ya kuandika options ina viwango tofauti vya risk vilivyo na au visivyo na kikomo.

### 3. **Gharama:**

* **Futures:** Hakuna gharama ya awali zaidi ya margin inayohitajika kushikilia position, kwa kuwa buyer na seller wote wana wajibu wa kukamilisha trade.
* **Options:** Buyer lazima alipe **option premium** mapema kwa ajili ya haki ya ku-exercise option. Premium hii kimsingi ndiyo gharama ya option.

### 4. **Uwezekano wa Faida:**

* **Futures:** Faida au hasara hutegemea tofauti kati ya market price wakati wa expiration na bei iliyokubaliwa kwenye contract.
* **Options:** Buyer hupata faida market inapokwenda kwa mwelekeo unaofaa na kuvuka strike price kwa kiasi kinachozidi premium iliyolipwa. Seller hupata faida kwa kuhifadhi premium ikiwa option haija-exercise.

## References

- [1] [CFTC - Madhumuni ya kiuchumi ya futures markets](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Misingi ya Futures Market](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Elewa risks za virtual-currency trading](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC Glossary - Option, premium na exercise](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
