# Blockchain na Sarafu za Kidijitali

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Mikataba Mahiri (Smart Contracts)** ni programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na kuwezesha utekelezaji wa makubaliano kiotomatiki bila wapatanishi.
- **Programu Zilizogatuliwa (dApps)** hutumia mikataba mahiri na hujumuisha kiolesura rafiki kwa watumiaji na sehemu ya nyuma iliyo wazi na inayoweza kukaguliwa.
- **Tokeni na Coins** hutofautiana: coins hutumika kama pesa za kidijitali, huku tokeni zikiwakilisha thamani au umiliki katika miktadha mahususi.
  - **Tokeni za Huduma (Utility Tokens)** hutoa ufikiaji wa huduma, na **Tokeni za Dhamana (Security Tokens)** huashiria umiliki wa mali.
- **DeFi** ni kifupi cha Decentralized Finance, inayotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** humaanisha mifumo ya kubadilishana iliyogatuliwa na mashirika huru yaliyogatuliwa, mtawalia.

## Mbinu za Makubaliano

Mbinu za makubaliano huhakikisha uthibitishaji salama wa miamala kwenye blockchain ambao washiriki wamekubaliana:

- **Proof of Work (PoW)** hutegemea nguvu ya kompyuta kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji wathibitishaji kumiliki kiasi fulani cha tokeni, na hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu kuhusu Bitcoin

### Miamala

Miamala ya Bitcoin huhusisha kuhamisha fedha kati ya anwani. Miamala huthibitishwa kwa sahihi za kidijitali, zinazohakikisha kuwa ni mmiliki wa ufunguo binafsi pekee anayeweza kuanzisha uhamisho.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Miamala ya Sahihi Nyingi (Multisignature Transactions)** huhitaji sahihi nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala ina **ingizo** (chanzo cha fedha), **matokeo** (unakopelekwa), **ada** (zinazolipwa kwa wachimbaji), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuboresha uwezo wa Bitcoin kuchakata miamala kwa kuruhusu miamala mingi ndani ya chaneli moja, na kutangaza hali ya mwisho pekee kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala vibaya. Mbinu kama **Mixers** na **CoinJoin** huboresha kutotambulika kwa kuficha miunganisho ya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Mbinu zake ni pamoja na biashara za fedha taslimu, uchimbaji, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu zaidi, huku **PayJoin** ikificha CoinJoins ionekane kama miamala ya kawaida ili kuongeza faragha.

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutotambulika kwa watumiaji mara nyingi huzua wasiwasi. Huu hapa ni muhtasari rahisi wa baadhi ya mbinu za kawaida ambazo washambuliaji wanaweza kutumia kuhatarisha faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Kwa kawaida, ni nadra ingizo za watumiaji tofauti kuunganishwa katika muamala mmoja kwa sababu ya ugumu unaohusika. Kwa hiyo, mara nyingi **huchukuliwa kuwa anwani mbili za ingizo katika muamala mmoja zinamilikiwa na mtu yuleyule**.

## **UTXO Change Address Detection**

UTXO, au **Matokeo ya Muamala Yasiyotumika (Unspent Transaction Output)**, lazima itumike yote katika muamala. Ikiwa sehemu yake tu itatumwa kwa anwani nyingine, salio hutumwa kwenye anwani mpya ya chenji. Watazamaji wanaweza kudhani kuwa anwani hii mpya ni ya mtumaji, jambo linalohatarisha faragha.

### Mfano

Ili kupunguza hatari hii, huduma za kuchanganya miamala au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Kufichuliwa kwenye Mitandao ya Kijamii na Majukwaa**

Wakati mwingine watumiaji hushiriki anwani zao za Bitcoin mtandaoni, na hivyo **kurahisisha kuhusisha anwani na mmiliki wake**.

## **Uchambuzi wa Grafu ya Miamala**

Miamala inaweza kuonyeshwa kama grafu, zikifichua miunganisho inayowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Mbinu hii hutegemea kuchanganua miamala yenye ingizo na matokeo mengi ili kukisia ni matokeo gani ni chenji inayorejeshwa kwa mtumaji.

### Mfano

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ikiwa kuongeza inputs kunafanya matokeo ya change kuwa makubwa kuliko input yoyote moja, hilo linaweza kuchanganya heuristic.

## **Forced Address Reuse**

Washambuliaji wanaweza kutuma kiasi kidogo kwa anwani zilizowahi kutumika, wakitumaini kwamba mpokeaji atazichanganya na inputs nyingine katika miamala ya baadaye, na hivyo kuunganisha anwani hizo.

### Tabia Sahihi ya Wallet

Wallet zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani zilizowahi kutumika na ambazo hazina salio, ili kuzuia leak hii ya faragha.

## **Mbinu Nyingine za Kuchanganua Blockchain**

- **Kiasi Halisi cha Malipo:** Miamala isiyo na change huenda ikawa kati ya anwani mbili zinazomilikiwa na mtumiaji yuleyule.
- **Nambari za Mviringo:** Nambari ya mviringo katika muamala hudokeza kuwa huo ni malipo, huku output isiyo ya mviringo huenda ikawa change.
- **Utambuzi wa Wallet:** Wallet tofauti zina mifumo ya kipekee ya kuunda miamala, hivyo wachanganuzi wanaweza kutambua programu iliyotumika na huenda pia anwani ya change.
- **Ulinganifu wa Kiasi na Muda:** Kuweka wazi nyakati au kiasi cha miamala kunaweza kufanya miamala iweze kufuatiliwa.

## **Uchanganuzi wa Trafiki**

Kwa kufuatilia trafiki ya mtandao, washambuliaji wanaweza kuunganisha miamala au blocks na anwani za IP, na kuhatarisha faragha ya watumiaji. Hili huwa na uwezekano mkubwa zaidi ikiwa mhusika anaendesha nodes nyingi za Bitcoin, jambo linalompa uwezo mkubwa zaidi wa kufuatilia miamala.

## Zaidi

Kwa orodha kamili ya mashambulizi ya faragha na ulinzi wake, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Miamala ya Bitcoin Isiyojulikana

## Njia za Kupata Bitcoins Bila Kujulikana

- **Miamala ya Pesa Taslimu**: Kupata bitcoin kwa kutumia pesa taslimu.
- **Njia Mbadala za Pesa Taslimu**: Kununua gift cards na kuzibadilisha mtandaoni kwa bitcoin.
- **Mining**: Njia yenye faragha zaidi ya kupata bitcoins ni kupitia mining, hasa ukiifanya peke yako, kwa sababu mining pools huenda zikajua anwani ya IP ya miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na haipendekezwi.

## Huduma za Mixing

Kwa kutumia mixing service, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti badala yake**, jambo linalofanya iwe vigumu kufuatilia mmiliki wa awali. Hata hivyo, hii inahitaji kuiamini huduma hiyo kwamba haitahifadhi logs na itarudisha bitcoins. Chaguo mbadala za mixing ni pamoja na kasino za Bitcoin.

## CoinJoin

**CoinJoin** huunganisha miamala mingi kutoka kwa watumiaji tofauti na kuifanya muamala mmoja, hivyo kutatiza juhudi za mtu yeyote anayejaribu kulinganisha inputs na outputs. Licha ya ufanisi wake, miamala yenye ukubwa wa kipekee wa inputs na outputs bado inaweza kufuatiliwa.

Mifano ya miamala ambayo huenda ilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa mixer ya Ethereum smart-contract inayotenganisha deposits na withdrawals za baadaye, angalia [Tornado Cash](https://tornado.cash).

## PayJoin

Aina tofauti ya CoinJoin, **PayJoin** (au P2EP), huficha muamala kati ya wahusika wawili (kwa mfano, mteja na mfanyabiashara) kwa kuufanya uonekane kama muamala wa kawaida, bila outputs zilizo sawa zinazotambulisha CoinJoin. Hii hufanya iwe vigumu sana kuutambua na inaweza kubatilisha heuristic ya common-input-ownership inayotumiwa na mashirika yanayofuatilia miamala.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Miamala kama iliyo hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikibaki kutofautishwa na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika juhudi za kulinda faragha ya miamala.

# Mbinu Bora za Kulinda Faragha katika Sarafu za Kidijitali

## **Mbinu za Kusawazisha Wallet**

Ili kudumisha faragha na usalama, ni muhimu kusawazisha wallet na blockchain. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya kiwango cha juu. Miamala yote iliyowahi kufanywa huhifadhiwa ndani ya kifaa, hivyo kuifanya isiwezekane kwa washambuliaji kubaini miamala au anwani ambazo mtumiaji anavutiwa nazo.
- **Uchujaji wa block upande wa client**: Mbinu hii inahusisha kuunda vichujio kwa kila block kwenye blockchain, na kuziwezesha wallet kutambua miamala inayohusika bila kufichua maslahi mahususi kwa wanaochunguza mtandao. Wallet nyepesi hupakua vichujio hivi, na kupakua block nzima tu kunapopatikana inayolingana na anwani za mtumiaji.

## **Kutumia Tor kwa Kutokujulikana**

Kwa kuwa Bitcoin hutumia mtandao wa peer-to-peer, inapendekezwa kutumia Tor kuficha anwani yako ya IP, na hivyo kuongeza faragha unapowasiliana na mtandao.

## **Kuzuia Matumizi Tena ya Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia anwani tena kunaweza kuhatarisha faragha kwa kuunganisha miamala na mtu yuleyule. Wallet za kisasa hukatisha tamaa matumizi tena ya anwani kupitia muundo wake.

## **Mikakati ya Kulinda Faragha ya Miamala**

- **Miamala mingi**: Kugawa malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala, na kuzuia mashambulizi dhidi ya faragha.
- **Kuepuka chenji**: Kuchagua miamala isiyohitaji matokeo ya chenji huboresha faragha kwa kuvuruga mbinu za kutambua chenji.
- **Matokeo mengi ya chenji**: Ikiwa kuepuka chenji hakuwezekani, kutengeneza matokeo mengi ya chenji bado kunaweza kuboresha faragha.

# **Monero: Nguzo ya Kutokujulikana**

Monero imeundwa kutanguliza faragha ya miamala.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za kimahesabu zinazohitajika kutekeleza shughuli kwenye Ethereum, na bei yake huonyeshwa kwa **gwei**. Kwa mfano, muamala unaogharimu gwei 2,310,000 (au ETH 0.00231) huhusisha kikomo cha gas na ada ya msingi, pamoja na ada ya kipaumbele ili kuhamasisha validator kuujumuisha. Watumiaji wanaweza kuweka ada ya juu kabisa ili kuhakikisha hawalipi zaidi ya inavyohitajika; kiasi kinachozidi hurejeshwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala kwenye Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au za mkataba mahiri. Inahitaji ada na lazima ijumuishwe kwenye block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, sahihi ya mtumaji, thamani, data ya hiari, kikomo cha gas na ada. Muhimu zaidi, anwani ya mtumaji hukisiwa kutoka kwenye sahihi, hivyo haihitajiki kwenye data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na taratibu hizi ni za msingi kwa yeyote anayetaka kutumia sarafu za kidijitali huku akitanguliza faragha na usalama.

## Value-Centric Web3 Red Teaming

- Orodhesha vipengele vyenye thamani (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha fedha na jinsi anavyoweza kufanya hivyo.
- Linganisha kila kipengele na mbinu husika za MITRE AADAPT ili kufichua njia za kupandisha marupurupu.
- Fanya mazoezi ya misururu ya mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kuandika masharti ya awali yanayowezesha unyonyaji.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Kuharibu wallet UI kupitia supply chain kunaweza kubadilisha payload za EIP-712 kabla tu ya kusainiwa, na kukusanya sahihi halali kwa ajili ya takeover za proxy zinazotegemea delegatecall (kwa mfano, kubadilisha slot-0 ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Makosa ya kawaida ya smart-account ni pamoja na kukwepa udhibiti wa ufikiaji wa `EntryPoint`, sehemu za gas zisizosainiwa, uthibitishaji unaobadilisha hali, replay ya ERC-1271, na kumaliza ada kupitia revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Mikataba Mahiri

- Kutumia mutation testing kutafuta maeneo dhaifu ambayo hayajashughulikiwa na test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa ZK Proof / zkVM Guest

Prover inapotumia **zkVM** au proof circuit maalum ya programu kuthibitisha dai, verifier hujifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **vikwazo vya kisemantiki vinavyokosekana**, prover hasidi anaweza kutengeneza proof inayothibitishwa ilhali **metrics za umma au invariant inayodaiwa si za kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia private witness/circuit bytes kama **ingizo lisiloaminika kutoka kwa mshambuliaji**, hata kama zimefichwa na proof.
- Epuka kuzisoma kwa kutumia helper zisizofanya ukaguzi, kama `rkyv::access_unchecked`, isipokuwa bytes hizo tayari zilithibitishwa kwa njia nyingine.
- Enum discriminants, relative pointers, lengths na indexes zilizopakiwa kutoka kwenye data iliyoserialishwa isiyoaminika lazima zithibitishwe kabla hazijaathiri mtiririko wa udhibiti au ufikiaji wa kumbukumbu.

Mbinu ya ukaguzi ya vitendo:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ikiwa field kama `op.kind` ni enum na mshambuliaji anaweza kuingiza **discriminant iliyo nje ya masafa**, kila `match` inayofuata kwenye thamani hiyo inapaswa kuchunguzwa kwa mashaka.

### Bypass ya jump table / UB counter

Ikiwa Rust inabadilisha `match` kubwa kuwa **jump table**, discriminant batili ya enum inaweza kusababisha **mtiririko wa udhibiti usiofafanuliwa**. Muundo hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **vihesabio/vizuizi muhimu kwa usalama**.
2. `match` ya pili hutekeleza **semantiki halisi za maagizo**.
3. Discriminant iliyo nje ya masafa hufikia nafasi iliyo nje ya jump table ya kwanza na kuingia kwenye msimbo unaohusishwa na ya pili.

Matokeo: operesheni bado hutekelezwa, lakini njia ya uhasibu hurukwa. Katika zkVM, hii inaweza kutengeneza proofs zinazoripoti vipimo visivyowezekana, kama vile gates chache, operesheni ghali chache, au rasilimali nyingine zenye vikomo zilizopotoshwa.

Orodha ya ukaguzi:

- Tafuta enum zinazodhibitiwa na mshambuliaji na kuserialishwa kutoka kwa witness/private input.
- Kagua kauli za `match` zinazojirudia kwenye field ileile ya opcode/kind.
- Chukulia `unsafe` + deserialization isiyokaguliwa + uelekezaji mkubwa wa opcode kuwa mchanganyiko wenye hatari kubwa.
- Fanya reverse engineering ya binary iliyotolewa inapohitajika; mpangilio wa jump table unaweza kuwa muhimu zaidi ya source.

### Kukosekana kwa vizuizi vya kisemantiki katika interpreters zinazoweza kugeuzwa/zilizobobea

Usihakikishe tu usalama wa kumbukumbu; hakikisha pia **sheria za kisemantiki** ambazo proof inapaswa kutekeleza.

Kwa seti za maagizo zinazoweza kugeuzwa/zinaofanana na quantum, hakikisha kwamba operands zinazopaswa kuwa tofauti zimewekewa kizuizi cha kuwa tofauti. Operesheni inayofanana na Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

inakuwa si salama ikiwa guest haitakataa:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Katika hali hiyo, mpito hubadilika na kuwa:

```text
q = q ^ (q & q) = 0
```

Hii huunda **primitive ya reset inayoweza kubainishwa**, ikivunja dhana za urejeshaji na kuwezesha ukokotoaji usiokusudiwa kwa gharama ndogo. Katika mifumo ya proof inayothibitisha matumizi ya rasilimali, hii inaweza kuruhusu washambuliaji kutimiza ukaguzi wa utendaji huku wakiepuka modeli ya gharama ambayo verifier anaamini inatekelezwa.

### Ushauri wa prover usio na vikwazo vya kutosha na hesabu ya modular

Thamani zilizopakiwa kutoka kwenye **stack ya advice/witness zinadhibitiwa na prover**, hata zinapoelezwa kuwa quotients, remainders, inverses au hints zilizokokotolewa mapema. Proof huthibitisha tu kwamba witness inatimiza constraints zilizotekelezwa; haithibitishi kwamba ukokotoaji uliokusudiwa ulifanyika ikiwa constraints hizo hazina ukaguzi wa aina, range au umbo la kanoniki.<sup>[[13]](#references)</sup>

Kwa helper ya reduction au mgawanyo wa Euclidean, kagua uhusiano kamili wa namba kamili badala ya subtraction au multiplication ya mwisho pekee. Kila limb ya `q` na `r` lazima izuiliwe kwenye upana wake uliotangazwa, reconstruction `x = q * m + r` lazima itimizwe katika uwakilishi wa namba kamili uliokusudiwa, na sharti la kanoniki `0 <= r < m` lazima litekelezwe. Thibitisha thamani **kabla** ya kuipitisha kwa instruction nyembamba ya `u32`/`u64`; operesheni nyembamba haithibitishi kwa kurudi nyuma kwamba field element au thamani ya limbs nyingi ya awali ilikuwa na aina iliyotarajiwa.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Hitilafu ya `mod_12289` katika Miden inaonyesha muundo wa exploit: quotient ilikaguliwa kama thamani ya 64-bit yenye limbs mbili, lakini remainder iliyotolewa kupitia advice ilifikia `u32overflowing_sub` bila uthibitishaji sawia. Prover hasidi angeweza kuratibu thamani zisizo halali za quotient/remainder ili masharti ya subtraction yaliyotekelezwa yatimizwe, huku utaratibu ukirejesha remainder isiyo ya kihisabati. Kwa kuwa matokeo haya yalitumika katika uthibitishaji wa Falcon, hitilafu ya soundness ingeweza kupanuliwa hadi kusababisha signatures za uidhinishaji bandia, badala ya kutoa tu matokeo yasiyo sahihi ya hesabu.<sup>[[13]](#references)</sup>

### Kukagua cryptographic VMs zenye stack isiyo wazi

Lugha za stack huficha operands, kwa hiyo kwanza badilisha instructions ziwe IR ambamo kila thamani ya stack iliyotumiwa au kuzalishwa ni expression yenye provenance. Kisha pipeline ya uchanganuzi wa tahadhari inaweza:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Jenga call graph na ukadirie athari za stack za inputs/outputs za procedures.
2. Tekeleza instructions zinazoungwa mkono kwa njia ya symbolic na ubadilishe control flow kuwa expressions za SSA/structured.
3. Sambaza facts za abstract kama `Unknown`, `ProvenU32`, `Bool`, provenance ya thamani, na uanzishaji wa local hadi kufikia fixed point.
4. Weka alama kwa thamani zilizotokana na advice zinazofikia typed arithmetic au non-zero sinks bila sanitizer kwenye **kila** njia inayoingia.
5. Linganisha signatures zilizotangazwa na zilizokadiriwa, na uhakikishe kila exit inahifadhi thamani za stack zinazomilikiwa na caller.

Chukulia signature isiyojulikana au construct isiyoungwa mkono kama **pengo la uchanganuzi**, si matokeo safi. Dynamic calls, loops zisizohifadhi stack, na branches zenye athari tofauti za stack zinaweza kufanya ufuatiliaji sahihi wa stack-slot usiwezekane; decompiler salama hukataa au kuweka alama kwa hali hizi badala ya kutoa pseudocode inayoonekana sahihi lakini si sahihi.<sup>[[10]](#references)[[13]](#references)</sup>

Katika sehemu ambazo control flow inaungana, hifadhi sifa tu ikiwa inatumika kwa predecessors zote (kwa mfano, `ProvenU32 join Unknown = Unknown`). Pia tofautisha convergence ya fixed-point na kufikia kikomo cha iterations: ni over-approximation iliyokamilika na iliyo sound tu inayoweza kuhalalisha kuchukulia kutokuwepo kwa diagnostic kama ushahidi kwamba executions zote zilizowakilishwa zinatimiza sifa hiyo.<sup>[[11]](#references)</sup>

### Tumia masharti ya uthibitisho kufichua preconditions zilizofichika

Kwa instruction sets ndogo, badilisha procedures ziwe formal VM model inayoweza kutekelezwa, kisha thibitisha matokeo na mabadiliko kamili ya stack. Theorem inapaswa kujumuisha termination, typed inputs, output prefix inayotarajiwa, na uhifadhi wa stack ya caller ambayo haijaguswa. Kagua tamko la theorem kwa umakini kama uthibitisho wenyewe: kernel inaweza kuthibitisha dai lililodhoofishwa kimakosa.<sup>[[12]](#references)[[13]](#references)</sup>

Hypotheses zisizotarajiwa ni matokeo muhimu. Katika ukaguzi wa Miden, uthibitisho wa mzunguko wa kulia wa 64-bit ulihitaji `shift mod 32 != 0`, jambo lililofichua edge case inayoshindwa kwa inputs kubwa wakati shift ni kizidisho cha 32; uthibitisho mwingine uligundua kwamba `wrapping_mul` ya 256-bit ilitupa thamani za stack zinazomilikiwa na caller. Ongeza boundary case iliyogunduliwa kwenye tests, kisha rekebisha implementation au uimarishe public precondition kwa makusudi badala ya kukubali kimyakimya dhana hiyo ya ziada.<sup>[[12]](#references)[[13]](#references)</sup>

### Mambo ya kupima katika mifumo ya ZK

- Fuzz parsers zote za guest kwa encodings zisizo sahihi za witness/private-input.
- Hakikisha enum range validation inafanywa kabla ya opcode dispatch.
- Ongeza semantic checks za operand aliasing na aina nyingine za instruction zisizo halali.
- Fuatilia kila chanzo cha advice/witness hadi kila typed arithmetic sink, na hitaji validation kwenye kila njia.<sup>[[11]](#references)[[13]](#references)</sup>
- Pima arithmetic helpers kwa limbs zisizo canonical, remainders zilizo nje ya range, na shift counts za mipakani.<sup>[[12]](#references)[[13]](#references)</sup>
- Hakikisha urefu wa stack na uhifadhi wa thamani zilizo chini ya arguments zilizotangazwa za procedure kwenye kila return.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Linganisha counters zilizoripotiwa/za umma na reference implementation huru.
- Kumbuka kwamba proof halali bado inaweza kuthibitisha **kauli isiyo sahihi** ikiwa guest program ina hitilafu.

## Uidhinishaji Unaotegemea Hali

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation ya DeFi/AMM

Ikiwa unatafiti exploitation ya vitendo ya DEXes na AMMs (Uniswap v4 hooks, matumizi mabaya ya rounding/precision, swaps zinazovuka threshold zilizokuzwa na flash-loan), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa weighted pools zenye assets nyingi zinazohifadhi virtual balances kwenye cache na zinazoweza kutiwa sumu wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key na Private Key zimefafanuliwa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Transactions za multi-signature ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tuliishinda zero-knowledge proof ya Google ya quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda Elliptic Curve Cryptocurrencies dhidi ya Quantum Vulnerabilities: Makadirio ya Rasilimali na Hatua za Kupunguza Hatari (toleo lililorekebishwa)](https://arxiv.org/abs/2603.28846v2)
- [9] [Hifadhi ya proof-of-concept ya Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Muundo wa decompiler ya MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Injini ya uchanganuzi tuli ya MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Model ya MASM-to-Lean na proofs za usahihi](https://github.com/trailofbits/masm-lean)
- [13] [Ukaguzi katika enzi ya AI (inayotosha kwa kiwango kizuri)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
