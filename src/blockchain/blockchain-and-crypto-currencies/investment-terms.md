# Masharti ya Uwekezaji

{{#include ../../banners/hacktricks-training.md}}

## Spot

Biashara ya spot hubadilisha mali na kuikabidhi papo hapo. Agizo la kikomo hubainisha kiasi na bei ya juu au ya chini inayokubalika; hutekelezwa tu pale soko linapoweza kutoa bei hiyo au bora zaidi. Agizo la soko, badala yake, hulenga kutekelezwa mara moja kwa bei bora zinazopatikana wakati huo na linaweza kukumbwa na slippage.<sup>[[4]](#references)</sup>

Agizo la stop-limit huwa na bei ya kusimamisha inayowasha agizo la kikomo. Linaweza kudhibiti bei ya utekelezaji, lakini halihakikishi utekelezaji iwapo soko litapita bei ya kikomo.<sup>[[4]](#references)</sup>

## Futures

Mkataba wa futures ni makubaliano sanifu ya kununua au kuuza bidhaa au chombo cha kifedha kilichobainishwa katika tarehe ya baadaye. Kwa mfano, pande mbili zinaweza kukubaliana kuhusu bei ya $70,000 kwa bitcoin moja, huku malipo yakifanyika baada ya miezi sita.<sup>[[1]](#references)</sup>

Ikiwa bei ya malipo ni $80,000, upande wa long hupata faida na upande wa short hupata hasara ikilinganishwa na bei ya mkataba ya $70,000. Ikiwa bei ni $60,000, matokeo huwa kinyume. Futures halisi zinazouzwa kwenye masoko huhesabiwa upya kulingana na bei ya soko na kwa kawaida hufungwa au kuendelezwa kabla ya kuisha muda wake, kwa hiyo huu ni mfano uliorahisishwa.<sup>[[2]](#references)</sup>

Wazalishaji na watumiaji hutumia futures kuzuia hatari ya bei; washiriki wengine huzitumia kutafuta faida au kutoa ukwasi.<sup>[[1]](#references)</sup>

- **Nafasi ya long** kwa kawaida hupata faida bei ya mkataba inapopanda.
- **Nafasi ya short** kwa kawaida hupata faida bei ya mkataba inaposhuka.<sup>[[2]](#references)</sup>

### Kuzuia Hatari kwa Kutumia Futures

Ikiwa msimamizi wa mfuko anatarajia thamani ya jalada kushuka, anaweza kuuza short mkataba wa futures wa faharasa ya hisa unaohusiana vya kutosha na jalada hilo. Faida kutoka kwa short hedge inaweza kufidia baadhi ya hasara ya jalada; hatari ya tofauti ya msingi inamaanisha kuwa fidia hiyo huwa si kamili. Bitcoin future huzuia hatari ya mabadiliko ya bitcoin, si ya jalada la hisa moja kwa moja.

Ikiwa soko lililozuiwa hatari litashuka, nafasi ya short ya futures inaweza kupata faida huku thamani ya mali zilizoshikiliwa ikishuka. Likishuka? Ikiwa soko litapanda, mali zilizoshikiliwa zinaweza kupata thamani huku hedge ikipata hasara. Kuzuia hatari hupunguza hatari maalum, badala ya kuleta faida iliyohakikishwa.<sup>[[1]](#references)</sup>

### Perpetual Futures

Mikataba ya perpetual ni derivatives zisizo na tarehe maalum ya kuisha. Majukwaa ya crypto kwa kawaida hutumia malipo ya funding ya mara kwa mara kusaidia kuweka bei yake karibu na bei ya spot ya mali ya msingi; masharti hutofautiana kati ya majukwaa.<sup>[[3]](#references)</sup>

Kwa majaribio ya matumizi mabaya ya funding rate kwenye itifaki za perpetual za on-chain, tazama [Unyonyaji wa Perpetual Funding-Rate](perpetual-funding-rate-exploitation.md).

Faida na hasara hubadilika kadiri bei ya mark inavyobadilika. Mabadiliko ya bei ya 1% husababisha takribani mabadiliko ya 1% katika thamani ya notional ya nafasi kabla ya ada na funding, lakini leverage inaweza kufanya mabadiliko hayo yawe asilimia kubwa zaidi ya dhamana iliyowekwa.

### Futures zenye Leverage

**Leverage** humwezesha mfanyabiashara kudhibiti nafasi yenye thamani kubwa ya notional kwa kuweka kiasi kidogo cha margin. Hasara si lazima ziishie kwenye margin ya awali: liquidation, mabadiliko makubwa ya bei, ada na masharti ya jukwaa vinaweza kusababisha hasara zaidi.<sup>[[3]](#references)</sup>

Kwa mfano, margin ya $100 yenye leverage ya 50x hudhibiti nafasi ya $5,000. Tukipuuza ada, funding na taratibu za liquidation, mabadiliko yanayofaa ya 1% huleta faida ya $50 (50% ya margin ya awali), huku mabadiliko yasiyofaa ya 1% yakileta hasara ya $50. Mabadiliko yasiyofaa ya 2% ni sawa na $100, ingawa kwa kawaida jukwaa litaliquidate nafasi kabla margin yote haijaisha.

Leverage huongeza ukubwa wa faida na hasara na kufanya liquidation iwezekane baada ya mabadiliko yasiyofaa ya bei yaliyo madogo kiasi.

## Tofauti Kati ya Futures na Options

Mnunuzi wa option hupata haki, si wajibu, wa kutekeleza mkataba kulingana na masharti yake. Mwandishi wa option ana wajibu unaolingana ikiwa mnunuzi atatekeleza option hiyo. Mnunuzi humlipa mwandishi premium kwa haki hiyo.<sup>[[4]](#references)</sup>

### 1. **Wajibu dhidi ya Haki:**

* **Futures:** Unaponunua au kuuza mkataba wa futures, unaingia katika **makubaliano ya kisheria** ya kununua au kuuza mali kwa bei maalum katika tarehe ya baadaye. Mnunuzi na muuzaji wote **wana wajibu** wa kutekeleza mkataba muda wake unapoisha (isipokuwa mkataba umefungwa kabla ya hapo).
* **Options:** Kwa options, una **haki, lakini si wajibu**, ya kununua (kwa **call option**) au kuuza (kwa **put option**) mali kwa bei maalum kabla au katika tarehe fulani ya kuisha muda. **Mnunuzi** ana chaguo la kutekeleza mkataba, huku **muuzaji** akiwa na wajibu wa kutekeleza biashara ikiwa mnunuzi ataamua kutumia option hiyo.

### 2. **Hatari:**

* **Futures:** Pande zote mbili zinaweza kupata hasara kubwa. Ikiwa hasara haina kikomo kinadharia hutegemea nafasi na mali ya msingi: nafasi ya short inaweza kuwa na hasara ya kinadharia isiyo na kikomo, ilhali nafasi ya long haiwezi kupoteza zaidi ya thamani ya notional ikiwa mali ya msingi haiwezi kushuka chini ya sifuri.
* **Options:** Mnunuzi ambaye hauuzi option nyingine kwa kawaida huhatarisha premium aliyolipa pekee. Mwandishi wa naked call anaweza kukabiliwa na hasara ya kinadharia isiyo na kikomo; mikakati mingine ya kuandika options ina viwango tofauti vya hatari yenye kikomo au isiyo na kikomo.

### 3. **Gharama:**

* **Futures:** Hakuna gharama ya awali zaidi ya margin inayohitajika kushikilia nafasi, kwa kuwa mnunuzi na muuzaji wote wana wajibu wa kukamilisha biashara.
* **Options:** Mnunuzi lazima alipe **option premium** mapema kwa haki ya kutekeleza option hiyo. Premium hii ndiyo gharama ya option.

### 4. **Uwezo wa Kupata Faida:**

* **Futures:** Faida au hasara hutegemea tofauti kati ya bei ya soko muda wa kuisha kwa mkataba na bei iliyokubaliwa kwenye mkataba.
* **Options:** Mnunuzi hupata faida soko linapobadilika kwa manufaa yake na kuvuka strike price kwa kiasi kinachozidi premium aliyolipa. Muuzaji hupata faida kwa kubaki na premium ikiwa option haitatekelezwa.

## References

- [1] [CFTC - Madhumuni ya kiuchumi ya masoko ya futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Misingi ya Masoko ya Futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Fahamu hatari za biashara ya virtual currency](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Kamusi ya CFTC - Option, premium na utekelezaji](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
