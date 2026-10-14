# Blockchain na Sarafu za Kidijitali

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na hivyo kuendesha utekelezaji wa makubaliano bila wapatanishi.
- **Decentralized Applications (dApps)** hujengwa kwa kutumia smart contracts, zikiwa na sehemu ya mbele iliyo rahisi kutumia na sehemu ya nyuma iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** hutofautiana kwa kuwa coins hutumika kama pesa za kidijitali, ilhali tokens huwakilisha thamani au umiliki katika miktadha mahususi.
  - **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa mali.
- **DeFi** ni kifupi cha Decentralized Finance, inayotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** humaanisha Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

Kwa istilahi za spot orders, futures, leverage na options zinazotumiwa katika masoko ya crypto, tazama [Investment Terms](investment-terms.md).

## Mbinu za Makubaliano

Mbinu za makubaliano huhakikisha uthibitishaji wa miamala kwenye blockchain ni salama na unaokubaliwa:

- **Proof of Work (PoW)** hutegemea nguvu ya ukokotoaji kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji validators kumiliki kiasi fulani cha tokens, na hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Misingi ya Bitcoin

### Miamala

Miamala ya Bitcoin huhusisha kuhamisha fedha kati ya anwani. Miamala huthibitishwa kupitia sahihi za kidijitali, zinazohakikisha kuwa ni mmiliki wa private key pekee anayeweza kuanzisha uhamisho.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Multisignature Transactions** huhitaji sahihi nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala hujumuisha **inputs** (chanzo cha fedha), **outputs** (mahali zinapoenda), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuboresha uwezo wa Bitcoin wa kushughulikia miamala kwa kuruhusu miamala mingi ndani ya channel, huku hali ya mwisho pekee ikitangazwa kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha kutokujulikana kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Mbinu zake ni pamoja na biashara za fedha taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, huku **PayJoin** ikificha CoinJoins ionekane kama miamala ya kawaida ili kuongeza faragha.

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutokujulikana kwa watumiaji mara nyingi huwa sababu za wasiwasi. Huu hapa ni muhtasari rahisi wa mbinu kadhaa za kawaida ambazo washambuliaji wanaweza kutumia kuhatarisha faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Dhana ya Umiliki wa Pamoja wa Inputs**

Kwa kawaida, si jambo la kawaida kwa inputs za watumiaji tofauti kuunganishwa katika muamala mmoja kwa sababu ya ugumu wake. Kwa hiyo, **anwani mbili za input katika muamala mmoja mara nyingi huchukuliwa kuwa zinamilikiwa na mmiliki yuleyule**.

## **Utambuzi wa Anwani ya Change ya UTXO**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa sehemu yake tu itatumwa kwenye anwani nyingine, salio huenda kwenye anwani mpya ya change. Wanaochunguza wanaweza kudhani anwani hii mpya ni ya mtumaji, na hivyo kuhatarisha faragha.

### Mfano

Ili kupunguza hatari hii, huduma za mixing au matumizi ya anwani nyingi yanaweza kusaidia kuficha umiliki.

## **Kufichuka kwenye Mitandao ya Kijamii na Majukwaa**

Wakati mwingine watumiaji hushiriki anwani zao za Bitcoin mtandaoni, na hivyo **kurahisisha kuunganisha anwani hiyo na mmiliki wake**.

## **Uchambuzi wa Grafu ya Miamala**

Miamala inaweza kuonyeshwa kama grafu, na kufichua miunganisho inayowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Heuristic ya Input Isiyohitajika (Heuristic ya Optimal Change)**

Heuristic hii hutegemea kuchanganua miamala yenye inputs na outputs nyingi ili kukisia ni output ipi ni change inayorudishwa kwa mtumaji.

### Mfano

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ikiwa kuongeza inputs zaidi kunafanya change output kuwa kubwa kuliko input yoyote moja, kunaweza kuchanganya heuristic.

## **Kulazimisha Kutumia Tena Anwani**

Wavamizi wanaweza kutuma kiasi kidogo cha fedha kwenye anwani zilizotumika hapo awali, wakitumaini kuwa mpokeaji atazichanganya na inputs nyingine katika miamala ya baadaye, na hivyo kuunganisha anwani hizo.

### Tabia Sahihi ya Wallet

Wallet zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani zilizotumika awali na zilizo tupu, ili kuzuia uvujaji huu wa faragha.

## **Mbinu Nyingine za Uchambuzi wa Blockchain**

- **Kiasi Halisi cha Malipo:** Miamala isiyo na change ina uwezekano mkubwa wa kuwa kati ya anwani mbili zinazomilikiwa na mtumiaji mmoja.
- **Namba Zilizokaribu na Zima:** Namba iliyo karibu na zima katika muamala inadokeza kuwa ni malipo, huku output isiyo namba ya zima ikiwezekana kuwa change.
- **Utambuzi wa Wallet:** Wallet tofauti zina mifumo ya kipekee ya kuunda miamala, inayowawezesha wachambuzi kutambua software iliyotumika na huenda pia anwani ya change.
- **Uwiano wa Kiasi na Muda:** Kufichua nyakati au kiasi cha miamala kunaweza kufanya miamala hiyo iweze kufuatiliwa.

## **Uchambuzi wa Trafiki**

Kwa kufuatilia trafiki ya mtandao, wavamizi wanaweza kuunganisha miamala au blocks na anwani za IP, na hivyo kuhatarisha faragha ya watumiaji. Hili ni kweli hasa ikiwa taasisi inaendesha nodes nyingi za Bitcoin, jambo linaloongeza uwezo wake wa kufuatilia miamala.

## Zaidi

Kwa orodha kamili ya mashambulizi ya faragha na njia za kujilinda, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Miamala ya Bitcoin Isiyojulikana

## Njia za Kupata Bitcoins Bila Kujulikana

- **Miamala ya Pesa Taslimu**: Kupata bitcoin kwa kutumia pesa taslimu.
- **Njia Mbadala za Pesa Taslimu**: Kununua gift cards na kuzibadilisha mtandaoni kuwa bitcoin.
- **Mining**: Njia yenye faragha zaidi ya kupata bitcoins ni kupitia mining, hasa ukiifanya peke yako, kwa sababu mining pools zinaweza kujua anwani ya IP ya miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na haipendekezwi.

## Huduma za Kuchanganya

Kwa kutumia huduma ya kuchanganya, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kwa kubadilishana**, jambo linalofanya iwe vigumu kufuatilia mmiliki wa awali. Hata hivyo, hii inahitaji kuamini kwamba huduma hiyo haitahifadhi logs na itarudisha bitcoins hizo. Njia mbadala za kuchanganya ni pamoja na kasino za Bitcoin.

## CoinJoin

**CoinJoin** huunganisha miamala mingi kutoka kwa watumiaji tofauti na kuifanya muamala mmoja, hivyo kutatiza jitihada za kulinganisha inputs na outputs. Licha ya ufanisi wake, miamala yenye ukubwa wa kipekee wa inputs na outputs bado inaweza kufuatiliwa.

Mifano ya miamala ambayo huenda ilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa mixer ya Ethereum smart-contract inayotenganisha amana na utoaji wa fedha wa baadaye, angalia [Tornado Cash](https://tornado.cash).

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), huficha muamala kati ya pande mbili (kwa mfano, mteja na mfanyabiashara) ili uonekane kama muamala wa kawaida, bila outputs zenye viwango sawa zinazotambulisha CoinJoin. Hii hufanya iwe vigumu sana kuitambua na inaweza kubatilisha heuristic ya common-input-ownership inayotumiwa na taasisi zinazofuatilia miamala.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Miamala kama iliyo hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikibaki kutotofautishika na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika jitihada za kulinda faragha ya miamala.

# Mbinu Bora za Kulinda Faragha katika Sarafu za Kidijitali

## **Mbinu za Kusawazisha Wallet na Blockchain**

Ili kudumisha faragha na usalama, ni muhimu kusawazisha wallet na blockchain. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya kiwango cha juu. Miamala yote iliyowahi kufanywa huhifadhiwa ndani ya kifaa, hivyo haiwezekani kwa washambuliaji kubaini ni miamala au anwani zipi zinazomvutia mtumiaji.
- **Client-side block filtering**: Mbinu hii inahusisha kuunda vichujio kwa kila block kwenye blockchain, na hivyo kuruhusu wallet kubaini miamala husika bila kufichua mambo maalum yanayomvutia mtumiaji kwa waangalizi wa mtandao. Wallet nyepesi hupakua vichujio hivi, na kupakua block nzima tu inapopata ulinganifu na anwani za mtumiaji.

## **Kutumia Tor kwa Kutokujulikana**

Kwa kuwa Bitcoin hufanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP na kuimarisha faragha unapowasiliana na mtandao.

## **Kuzuia Kutumia Tena Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha faragha kwa kuunganisha miamala na huluki ileile. Wallet za kisasa huzuia matumizi ya tena ya anwani kupitia muundo wake.

## **Mikakati ya Kulinda Faragha ya Miamala**

- **Miamala mingi**: Kugawanya malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala na kuzuia mashambulizi ya faragha.
- **Kuepuka chenji**: Kuchagua miamala isiyohitaji matokeo ya chenji huimarisha faragha kwa kuvuruga mbinu za kutambua chenji.
- **Matokeo mengi ya chenji**: Ikiwa haiwezekani kuepuka chenji, kuunda matokeo mengi ya chenji bado kunaweza kuboresha faragha.

# **Monero: Kielelezo cha Kutokujulikana**

Monero imeundwa kuweka kipaumbele kwenye faragha ya miamala.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za kikokotozi zinazohitajika kutekeleza shughuli kwenye Ethereum, na bei yake huonyeshwa kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) huwa na kikomo cha gas na ada ya msingi, pamoja na ada ya kipaumbele ya kuhamasisha validator kuujumuisha. Watumiaji wanaweza kuweka ada ya juu zaidi ili kuhakikisha hawalipi kupita kiasi; kiasi cha ziada hurejeshwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala kwenye Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au za smart contract. Inahitaji ada na lazima ijumuishwe kwenye block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, sahihi ya mtumaji, thamani, data ya hiari, kikomo cha gas na ada. Muhimu zaidi, anwani ya mtumaji hutambuliwa kutokana na sahihi, hivyo haihitajiki kwenye data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na taratibu hizi ni za msingi kwa yeyote anayetaka kutumia sarafu za kidijitali huku akipa kipaumbele faragha na usalama.

## Red Teaming ya Web3 Inayolenga Thamani

- Orodhesha vipengele vinavyoshikilia thamani (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha fedha na jinsi anavyoweza kufanya hivyo.
- Linganisha kila kipengele na mbinu husika za MITRE AADAPT ili kubaini njia za kuongeza mamlaka.
- Fanyia mazoezi misururu ya mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kurekodi masharti ya awali yanayowezesha unyonyaji.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kuhujumu Mchakato wa Kutia Saini wa Web3

- Kuhujumu supply chain ya wallet UI kunaweza kubadilisha payload za EIP-712 kabla tu ya kutia saini, na kukusanya sahihi halali kwa ajili ya kuchukua udhibiti wa proxy kwa kutumia delegatecall (kwa mfano, kubadilisha slot-0 ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Kasoro za kawaida za smart-account ni pamoja na kukwepa udhibiti wa ufikiaji wa `EntryPoint`, sehemu za gas zisizotiwa saini, uthibitishaji unaobadilisha hali, replay ya ERC-1271, na kuvuja kwa ada kupitia revert baada ya uthibitishaji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Smart Contract

- Kutumia mutation testing ili kubaini mapungufu katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa ZK Proof / zkVM Guest

Prover anapotumia **zkVM** au proof circuit mahususi ya programu kuthibitisha dai, verifier hujifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **semantic constraints zisizotosha**, prover hasidi anaweza kutengeneza proof inayothibitishwa huku **vipimo vya umma au invariant inayodaiwa vikiwa si vya kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia witness/circuit bytes za faragha kama **ingizo lisiloaminika kutoka kwa mshambuliaji**, hata kama zimefichwa na proof.
- Epuka kuzifanyia deserialization kwa kutumia helpers zisizokagua, kama `rkyv::access_unchecked`, isipokuwa bytes hizo zilithibitishwa awali kupitia njia nyingine.
- Enum discriminants, relative pointers, lengths na indexes zilizopakiwa kutoka kwenye data ya serialized isiyoaminika lazima zithibitishwe kabla hazijaathiri mtiririko wa udhibiti au ufikiaji wa kumbukumbu.

Muundo wa ukaguzi wa vitendo:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ikiwa field kama `op.kind` ni enum na mshambuliaji anaweza kuingiza **discriminant iliyo nje ya masafa**, kila `match` inayofuata kwenye thamani hiyo inapaswa kuchukuliwa kuwa ya kutiliwa shaka.

### Bypass ya jump-table / UB

Ikiwa Rust itabadilisha `match` kubwa kuwa **jump table**, discriminant ya enum isiyo halali inaweza kusababisha **mtiririko wa udhibiti usiofafanuliwa**. Muundo hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **kaunta/vizuizi muhimu kwa usalama**.
2. `match` ya pili hutekeleza **semantiki halisi ya maagizo**.
3. Discriminant iliyo nje ya masafa hutumika kuashiria nje ya jump table ya kwanza na kufika kwenye msimbo unaohusishwa na ya pili.

Matokeo: operesheni bado inatekelezwa, lakini njia ya uhasibu inarukwa. Katika zkVM, hili linaweza kutengeneza proofs zinazoripoti vipimo visivyowezekana, kama vile gates chache, operesheni ghali chache, au rasilimali nyingine zenye mipaka zilizoghushiwa.

Orodha ya ukaguzi:

- Tafuta enums zinazodhibitiwa na mshambuliaji na ambazo zimeserialishwa kutoka kwa witness/private input.
- Kagua kauli za `match` zinazojirudia kwenye field ileile ya opcode/kind.
- Chukulia mchanganyiko wa `unsafe` + deserialization isiyokaguliwa + dispatch kubwa ya opcode kuwa hatari kubwa.
- Fanya reverse engineering ya binary iliyotolewa inapohitajika; mpangilio wa jump table unaweza kuwa muhimu zaidi kuliko source.

### Vizuizi vya kisemantiki vinavyokosekana katika interpreters zinazoweza kutenduliwa/maalum

Usihakiki usalama wa kumbukumbu tu; hakiki pia **sheria za kisemantiki** ambazo proof inapaswa kutekeleza.

Kwa seti za maagizo zinazoweza kutenduliwa/zilizo kama quantum, hakikisha operands zinazopaswa kuwa tofauti zinadhibitiwa ili ziwe tofauti. Operesheni inayofanana na Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

inakuwa si salama ikiwa mfumo wa mgeni hautakataa:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Katika hali hiyo, mpito huo hujibana na kuwa:

```text
q = q ^ (q & q) = 0
```

Hii huunda **primitive ya reset deterministic**, ikivunja dhana za reversibility na kuwezesha mahesabu yasiyokusudiwa kwa gharama nafuu. Katika mifumo ya proof inayothibitisha matumizi ya rasilimali, hii inaweza kuwawezesha washambuliaji kutimiza ukaguzi wa utendaji huku wakipita kando ya modeli ya gharama ambayo verifier anaamini inatekelezwa.

### Ushauri wa prover usio na vikwazo vya kutosha na arithmetiki ya moduli

Thamani zinazopakiwa kutoka kwenye advice/witness stack zinadhibitiwa na prover, hata zinapoelezwa kuwa quotients, remainders, inverses au hints zilizokokotolewa awali. Proof huthibitisha tu kwamba witness inatimiza constraints zilizotekelezwa; haithibitishi kwamba hesabu iliyokusudiwa ilifanyika ikiwa constraints hizo hazijumuishi ukaguzi wa aina, masafa au umbo la canonical.<sup>[[13]](#references)</sup>

Kwa helper ya reduction au Euclidean division, kagua uhusiano kamili wa namba kamili badala ya subtraction au multiplication ya mwisho pekee. Kila limb ya `q` na `r` lazima izuiwe kufuata upana wake uliotangazwa, ujenzi upya `x = q * m + r` lazima ushikilie katika uwakilishi wa namba kamili uliokusudiwa, na mpaka wa canonical `0 <= r < m` lazima utekelezwe. Thibitisha thamani **kabla** ya kuipitisha kwenye instruction nyembamba ya `u32`/`u64`; operesheni nyembamba haithibitishi kwa kurudi nyuma kwamba field element au thamani ya multi-limb ya awali ilikuwa na aina iliyotarajiwa.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Kufeli kwa `mod_12289` katika Miden kunaonyesha muundo wa exploit: quotient ilikaguliwa kama thamani ya 64-bit yenye limbs mbili, lakini remainder iliyotolewa kupitia advice ilifika kwenye `u32overflowing_sub` bila uthibitishaji sawa. Prover hasidi angeweza kuratibu thamani zisizo halali za quotient/remainder ili masharti ya subtraction yaliyotekelezwa yatimizwe, huku utaratibu ukirudisha remainder isiyo ya kihisabati. Kwa kuwa matokeo haya yalitumika katika uthibitishaji wa Falcon, hitilafu ya soundness ingeweza kuongezwa hadi kutengeneza signatures za authorization ghushi badala ya kutoa tu matokeo yasiyo sahihi ya hesabu.<sup>[[13]](#references)</sup>

### Kukagua cryptographic VM zinazotumia stack isiyo wazi

Lugha za stack huficha operands, kwa hiyo kwanza inua instructions hadi IR ambamo kila thamani ya stack inayotumiwa na kuzalishwa ni expression yenye provenance. Kisha pipeline ya uchanganuzi wa tahadhari inaweza:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Jenga call graph na ukisie athari za stack za input/output za procedure.
2. Tekeleza instructions zinazotumika kwa njia ya symbolic na uinue control flow hadi expressions za SSA/structured.
3. Sambaza facts za abstract kama `Unknown`, `ProvenU32`, `Bool`, provenance ya thamani, na uanzishaji wa local hadi kufikia fixed point.
4. Weka alama kwa thamani zinazotokana na advice zinazofika kwenye typed arithmetic au sinks zisizo sifuri bila sanitizer kwenye **kila** njia inayoingia.
5. Linganisha signatures zilizotangazwa na zilizokisiwa, na uthibitishe kuwa kila exit inadumisha thamani za stack zinazomilikiwa na caller.

Chukulia signature isiyojulikana au construct isiyotumika kama **pengo la uchanganuzi**, si matokeo safi. Dynamic calls, loops zisizohifadhi stack, na branches zenye athari tofauti za stack zinaweza kufanya ufuatiliaji sahihi wa stack-slot usiwezekane; decompiler salama hukataa au kuweka alama kwa hali hizi badala ya kutoa pseudocode inayoonekana sahihi lakini si sahihi.<sup>[[10]](#references)[[13]](#references)</sup>

Katika sehemu ambazo control flow huungana, hifadhi property tu ikiwa inashikilia kwa kila predecessor (kwa mfano, `ProvenU32 join Unknown = Unknown`). Pia tofautisha convergence ya fixed-point na kufikia kikomo cha iterations: ni over-approximation iliyokamilika na yenye soundness pekee inayoweza kuhalalisha kuchukulia kutokuwepo kwa diagnostic kama ushahidi kuwa executions zote zilizowakilishwa zinatimiza property hiyo.<sup>[[11]](#references)</sup>

### Tumia proof obligations kufichua masharti yaliyofichika

Kwa instruction sets ndogo, geuza procedures kuwa formal VM model inayotekelezeka, kisha thibitisha matokeo pamoja na mabadiliko kamili ya stack. Theorem inapaswa kujumuisha termination, inputs zenye aina sahihi, output prefix inayotarajiwa, na uhifadhi wa stack ya caller ambayo haijaguswa. Kagua kauli ya theorem kwa umakini sawa na proof: kernel inaweza kuthibitisha proof ya dai lililodhoofishwa bila kukusudia.<sup>[[12]](#references)[[13]](#references)</sup>

Hypotheses zisizotarajiwa ni matokeo muhimu. Katika ukaguzi wa Miden, proof ya 64-bit right rotation ilihitaji `shift mod 32 != 0`, na kufichua edge case inayofeli kwa inputs kubwa wakati shift ni kigawe cha 32; proof nyingine iligundua kuwa 256-bit `wrapping_mul` ilitupa thamani za stack zinazomilikiwa na caller. Ongeza boundary case iliyogunduliwa kwenye tests, kisha rekebisha implementation au imarisha precondition ya umma kwa makusudi badala ya kukubali kimyakimya dhana ya ziada.<sup>[[12]](#references)[[13]](#references)</sup>

### Mambo ya kupima katika mifumo ya ZK

- Fuzz parsers zote za guest kwa encodings za witness/private-input zilizoharibika.
- Hakikisha enum range inathibitishwa kabla ya opcode dispatch.
- Ongeza ukaguzi wa semantiki wa operand aliasing na miundo mingine batili ya instructions.
- Fuatilia kila chanzo cha advice/witness hadi kwenye kila typed arithmetic sink na hitaji uthibitishaji kwenye kila njia.<sup>[[11]](#references)[[13]](#references)</sup>
- Pima arithmetic helpers kwa limbs zisizo canonical, remainders zilizo nje ya range, na shift counts za mipakani.<sup>[[12]](#references)[[13]](#references)</sup>
- Hakikisha urefu wa stack na uhifadhi wa thamani zilizo chini ya arguments zilizotangazwa za procedure katika kila return.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Linganisha counters zilizoripotiwa/za umma na reference implementation huru.
- Kumbuka kuwa proof halali bado inaweza kuthibitisha **kauli isiyo sahihi** ikiwa guest program ina hitilafu.

## Uidhinishaji Unaotegemea Hali

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Unyonyaji wa DeFi/AMM

Ikiwa unatafiti unyonyaji wa vitendo wa DEX na AMM (Uniswap v4 hooks, matumizi mabaya ya rounding/precision, swaps za kuvuka threshold zilizoimarishwa na flash-loan), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa weighted pools za multi-asset zinazohifadhi virtual balances kwenye cache na zinaweza kutiwa sumu wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key na Private Key Zimefafanuliwa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Muamala wa multi-signature ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Muamala | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na ada | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Faragha - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tuliishinda proof ya Google ya zero-knowledge ya quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda sarafu za kidijitali za Elliptic Curve dhidi ya udhaifu wa Quantum: Makadirio ya Rasilimali na Hatua za Kupunguza Hatari (toleo lililorekebishwa)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repository ya proof-of-concept ya Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Muundo wa decompiler ya MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Injini ya static-analysis ya MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Model ya MASM-to-Lean na proofs za usahihi](https://github.com/trailofbits/masm-lean)
- [13] [Ukaguzi katika enzi ya AI (inayotosha)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
