# Masharti ya Uwekezaji

{{#include ../../banners/hacktricks-training.md}}

## Spot

Biashara ya Spot hubadilisha mali kwa uwasilishaji wa papo hapo. Agizo la kikomo hutaja kiasi na bei ya juu au ya chini inayokubalika; hutekelezwa tu pale soko linapoweza kutimiza bei hiyo au bei bora zaidi. Agizo la soko, badala yake, hulenga utekelezaji wa haraka kwa bei bora zinazopatikana wakati huo, na linaweza kukumbwa na slippage.<sup>[[4]](#references)</sup>

Agizo la stop-limit lina bei ya stop inayowasha agizo la kikomo. Linaweza kudhibiti bei ya utekelezaji, lakini halihakikishi utekelezaji ikiwa bei ya soko itapita kiwango cha kikomo.<sup>[[4]](#references)</sup>

## Futures

Mkataba wa futures ni makubaliano sanifu ya kununua au kuuza bidhaa au chombo maalum cha kifedha katika tarehe ya baadaye. Kwa mfano, pande mbili zinaweza kukubaliana bei ya $70,000 kwa bitcoin moja, kwa malipo baada ya miezi sita.<sup>[[1]](#references)</sup>

Ikiwa bei ya malipo ni $80,000, upande wa long hupata faida na upande wa short hupata hasara ikilinganishwa na bei ya mkataba ya $70,000. Ikiwa ni $60,000, hali huwa kinyume. Futures zinazouzwa kwenye soko hubadilishwa thamani kulingana na soko, na kwa kawaida hufungwa au kuhamishiwa mkataba mwingine kabla ya kuisha; huu ni mfano uliorahisishwa.<sup>[[2]](#references)</sup>

Wazalishaji na watumiaji hutumia futures kudhibiti hatari ya bei; washiriki wengine huzitumia kutafuta faida au kutoa ukwasi.<sup>[[1]](#references)</sup>

- **Long position** kwa kawaida hupata faida bei ya mkataba inapopanda.
- **Short position** kwa kawaida hupata faida bei ya mkataba inaposhuka.<sup>[[2]](#references)</sup>

### Kudhibiti Hatari kwa Futures

Ikiwa msimamizi wa mfuko anatarajia thamani ya jalada kushuka, anaweza kuuza kwa short mkataba wa futures wa faharasa ya hisa unaohusiana vya kutosha na jalada hilo. Faida kutoka kwa short hedge inaweza kufidia baadhi ya hasara za jalada; hatari ya tofauti ya msingi ina maana kwamba ulinganifu huo huwa si kamili. Bitcoin future inaweza kudhibiti hatari ya kuwa na bitcoin, si moja kwa moja jalada la hisa.

Ikiwa soko linalodhibitiwa litashuka, nafasi ya short futures inaweza kupata faida huku hisa zilizoshikiliwa zikipoteza thamani. Likiongezeka, hisa zinaweza kupata thamani huku hedge ikipata hasara. Kudhibiti hatari hupunguza hatari maalum, badala ya kutoa faida ya uhakika.<sup>[[1]](#references)</sup>

### Perpetual Futures

Mikataba ya perpetual ni derivatives zisizo na tarehe maalum ya kuisha. Majukwaa ya crypto hutumia kwa kawaida malipo ya funding ya mara kwa mara ili kusaidia kuweka bei yake karibu na bei ya msingi ya Spot; masharti hutofautiana kulingana na jukwaa.<sup>[[3]](#references)</sup>

Faida na hasara hubadilika bei ya mark inapobadilika. Mabadiliko ya bei ya 1% husababisha takriban mabadiliko ya 1% katika thamani ya jumla ya nafasi kabla ya ada na funding, lakini leverage inaweza kufanya mabadiliko hayo yawe asilimia kubwa zaidi ya dhamana iliyowekwa.

### Futures zenye Leverage

**Leverage** humwezesha mfanyabiashara kudhibiti nafasi yenye thamani kubwa kwa kuweka kiasi kidogo cha margin. Hasara huwa hazizuiliwi kila mara na margin ya awali: liquidation, mabadiliko ya ghafla ya bei, ada na kanuni za jukwaa vinaweza kusababisha hasara za ziada.<sup>[[3]](#references)</sup>

Kwa mfano, margin ya $100 yenye leverage ya 50x hudhibiti nafasi ya $5,000. Tukipuuza ada, funding na taratibu za liquidation, mabadiliko yanayofaa ya 1% huleta faida ya $50 (50% ya margin ya awali), huku mabadiliko yasiyofaa ya 1% yakileta hasara ya $50. Mabadiliko yasiyofaa ya 2% yanalingana na $100, ingawa kwa kawaida jukwaa litafanya liquidation ya nafasi kabla margin yote haijaisha.

Leverage huongeza faida na hasara, na huruhusu liquidation kutokea baada ya mabadiliko yasiyofaa ya bei yaliyo madogo kwa kulinganisha.

## Tofauti Kati ya Futures na Options

Mnunuzi wa option hupata haki, si wajibu, wa kutekeleza masharti ya mkataba. Mwandishi wa option ana wajibu unaolingana ikiwa mnunuzi atatekeleza option hiyo. Mnunuzi humlipa mwandishi premium kwa haki hiyo.<sup>[[4]](#references)</sup>

### 1. **Wajibu dhidi ya Haki:**

* **Futures:** Unaponunua au kuuza mkataba wa futures, unaingia katika **makubaliano ya lazima** ya kununua au kuuza mali kwa bei maalum katika tarehe ya baadaye. Mnunuzi na muuzaji wote **wana wajibu** wa kutimiza mkataba unapoisha (isipokuwa mkataba ufungwe kabla ya hapo).
* **Options:** Kwa options, una **haki, lakini si wajibu**, wa kununua (katika **call option**) au kuuza (katika **put option**) mali kwa bei maalum kabla ya tarehe maalum ya kuisha au tarehe hiyo. **Mnunuzi** ana chaguo la kutekeleza, huku **muuzaji** akiwa na wajibu wa kutimiza muamala ikiwa mnunuzi ataamua kutekeleza option.

### 2. **Hatari:**

* **Futures:** Pande zote zinaweza kupata hasara kubwa. Ikiwa hasara haina kikomo kinadharia hutegemea nafasi na mali ya msingi: nafasi ya short inaweza kuwa na hasara ya kinadharia isiyo na kikomo, huku nafasi ya long haiwezi kupoteza zaidi ya thamani yake yote ya jumla ikiwa mali ya msingi haiwezi kushuka chini ya sifuri.
* **Options:** Mnunuzi ambaye haandiki option nyingine kwa kawaida huhatarisha premium aliyolipa pekee. Mwandishi wa naked call anaweza kukabili hasara ya kinadharia isiyo na kikomo; mikakati mingine ya kuandika options huwa na viwango tofauti vya hatari yenye kikomo au isiyo na kikomo.

### 3. **Gharama:**

* **Futures:** Hakuna gharama ya awali zaidi ya margin inayohitajika ili kushikilia nafasi, kwa kuwa mnunuzi na muuzaji wana wajibu wa kukamilisha muamala.
* **Options:** Mnunuzi lazima alipe **option premium** mapema ili kupata haki ya kutekeleza option. Premium hii ndiyo gharama ya option.

### 4. **Uwezo wa Kupata Faida:**

* **Futures:** Faida au hasara hutegemea tofauti kati ya bei ya soko wakati wa kuisha na bei iliyokubaliwa kwenye mkataba.
* **Options:** Mnunuzi hupata faida soko linapobadilika kwa manufaa yake na kuvuka strike price kwa zaidi ya premium aliyolipa. Muuzaji hupata faida kwa kubakiza premium ikiwa option haitatekelezwa.

## References

- [1] [CFTC - Madhumuni ya kiuchumi ya masoko ya futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Misingi ya Soko la Futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Elewa hatari za biashara ya sarafu pepe](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Kamusi ya CFTC - Option, premium na utekelezaji](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
