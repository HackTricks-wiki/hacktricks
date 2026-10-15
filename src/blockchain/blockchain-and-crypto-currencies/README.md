# Blockchain na Sarafu za Kidijitali

{{#include ../../banners/hacktricks-training.md}}

Sura hii inahusu dhana za blockchain na usalama wa on-chain. Kwa peer ya Bitcoin iliyo wazi, anza na [uhesabuji wa huduma ya Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); kwa frontend ya kivinjari, muunganisho wa wallet, au backend ya off-chain, tumia [pentesting ya DApp](../../pentesting-web/dapps-DecentralizedApplications.md). Kwa shughuli za faragha za cryptocurrency na mipaka yake, tumia [sura ya faragha ya cryptocurrency](../../privacy/cryptocurrency-privacy.md).

## Dhana za Msingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na hivyo kuendesha utekelezaji wa makubaliano bila wapatanishi.
- **Decentralized Applications (dApps)** hujengwa kwa kutumia smart contracts, zikiwa na front-end rahisi kutumia na back-end iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** hutofautiana kwa kuwa coins hutumika kama pesa za kidijitali, huku tokens zikiwakilisha thamani au umiliki katika miktadha mahususi.
  - **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa mali.
- **DeFi** ni kifupi cha Decentralized Finance, kinachotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** humaanisha mifumo ya Decentralized Exchange na mashirika ya Decentralized Autonomous, mtawalia.

Kwa istilahi za spot orders, futures, leverage na options zinazotumika katika masoko ya crypto, tazama [Istilahi za Uwekezaji](investment-terms.md).

## Mbinu za Makubaliano

Mbinu za makubaliano huhakikisha uthibitishaji salama na unaokubaliwa wa miamala kwenye blockchain:

- **Proof of Work (PoW)** hutegemea nguvu ya kompyuta kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji validators kushikilia kiasi fulani cha tokens, na hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu kuhusu Bitcoin

### Miamala

Miamala ya Bitcoin huhusisha uhamishaji wa fedha kati ya anwani. Miamala huthibitishwa kwa kutumia sahihi za kidijitali, zinazohakikisha kuwa mmiliki pekee wa private key ndiye anayeweza kuanzisha uhamishaji.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Miamala ya Multisignature** huhitaji sahihi nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala huwa na **inputs** (chanzo cha fedha), **outputs** (unakopelekwa), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuboresha uwezo wa Bitcoin wa kushughulikia miamala kwa kuruhusu miamala mingi ndani ya channel, huku hali ya mwisho pekee ikitangazwa kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha kutokujulikana kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Mbinu hizo zinajumuisha biashara za pesa taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, huku **PayJoin** ikificha CoinJoins ionekane kama miamala ya kawaida kwa ajili ya faragha zaidi.

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutokujulikana kwa watumiaji mara nyingi huzua wasiwasi. Huu hapa ni muhtasari rahisi wa baadhi ya mbinu za kawaida ambazo washambuliaji wanaweza kutumia kuhatarisha faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Dhana ya Umiliki wa Pamoja wa Inputs**

Kwa kawaida, ni nadra inputs kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kwa sababu ya ugumu unaohusika. Kwa hiyo, **anwani mbili za input katika muamala mmoja mara nyingi huchukuliwa kuwa za mmiliki yuleyule**.

## **Ugunduzi wa Anwani ya Change ya UTXO**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa sehemu yake tu itatumwa kwenye anwani nyingine, salio huenda kwenye anwani mpya ya change. Watazamaji wanaweza kudhani anwani hii mpya ni ya mtumaji, na hivyo kuhatarisha faragha.

### Mfano

Ili kupunguza hatari hii, huduma za mixing au matumizi ya anwani nyingi yanaweza kusaidia kuficha umiliki.

## **Kufichuka kwenye Mitandao ya Kijamii na Majukwaa**

Watumiaji wakati mwingine hushiriki anwani zao za Bitcoin mtandaoni, na hivyo kufanya iwe **rahisi kuunganisha anwani na mmiliki wake**.

## **Uchambuzi wa Grafu ya Miamala**

Miamala inaweza kuonyeshwa kama grafu, na kufichua miunganisho inayowezekana kati ya watumiaji kwa kutegemea mtiririko wa fedha.

## **Heuristic ya Input Isiyohitajika (Heuristic ya Optimal Change)**

Heuristic hii hutegemea kuchanganua miamala yenye inputs na outputs nyingi ili kubashiri ni output ipi ni change inayorejeshwa kwa mtumaji.

### Mfano

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ikiwa kuongeza inputs zaidi kunafanya change output kuwa kubwa kuliko input yoyote moja, hilo linaweza kuchanganya heuristic.

## **Kulazimisha Kutumia Tena Anwani**

Washambuliaji wanaweza kutuma kiasi kidogo cha bitcoin kwenye anwani zilizotumika hapo awali, wakitumaini mpokeaji atazichanganya na inputs nyingine katika miamala ya baadaye, na hivyo kuunganisha anwani hizo.

### Tabia Sahihi ya Wallet

Wallet zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani tupu zilizotumika tayari ili kuzuia leak hii ya faragha.

## **Mbinu Nyingine za Uchambuzi wa Blockchain**

- **Kiasi Halisi cha Malipo:** Miaka ambayo haina change huenda ikawa kati ya anwani mbili zinazomilikiwa na mtumiaji yuleyule.
- **Namba Zilizokamilika:** Namba iliyokamilika katika muamala huashiria malipo, huku tokeo lisilo namba iliyokamilika huenda likawa change.
- **Utambuzi wa Wallet:** Wallet tofauti huwa na mifumo ya kipekee ya kuunda miamala, inayowaruhusu wachambuzi kutambua programu iliyotumika na huenda pia anwani ya change.
- **Uhusiano wa Kiasi na Muda:** Kutoa taarifa za muda au kiasi cha miamala kunaweza kufanya miamala ifuatiliwe.

## **Uchambuzi wa Trafiki**

Kwa kufuatilia trafiki ya mtandao, washambuliaji wanaweza kuunganisha miamala au blocks na anwani za IP, na kuhatarisha faragha ya watumiaji. Hili ni kweli hasa ikiwa chombo kinaendesha nodes nyingi za Bitcoin, jambo linaloongeza uwezo wake wa kufuatilia miamala.

## Zaidi

Kwa orodha kamili ya mashambulizi na ulinzi wa faragha, tembelea [Faragha ya Bitcoin kwenye Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Miamala ya Bitcoin Isiyojulikana

## Njia za Kupata Bitcoins Bila Kujulikana

- **Miamala ya Pesa Taslimu**: Kupata bitcoin kwa kutumia pesa taslimu.
- **Njia Mbadala za Pesa Taslimu**: Kununua gift cards na kuzibadilisha mtandaoni kwa bitcoin.
- **Mining**: Njia yenye faragha zaidi ya kupata bitcoins ni kupitia mining, hasa ukiifanya peke yako, kwa sababu mining pools zinaweza kujua anwani ya IP ya mchimbaji. [Taarifa kuhusu Mining Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na haipendekezwi.

## Huduma za Kuchanganya

Kwa kutumia huduma ya kuchanganya, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kama malipo**, jambo linalofanya iwe vigumu kufuatilia mmiliki wa awali. Hata hivyo, hili linahitaji kuiamini huduma hiyo kwamba haitahifadhi logs na itarudisha bitcoins kweli. Chaguo mbadala za kuchanganya ni pamoja na kasino za Bitcoin.

## CoinJoin

**CoinJoin** huunganisha miamala mingi kutoka kwa watumiaji tofauti na kuifanya muamala mmoja, hivyo kufanya mchakato wa kulinganisha inputs na outputs kuwa mgumu. Licha ya ufanisi wake, miamala yenye ukubwa wa kipekee wa inputs na outputs bado inaweza kufuatiliwa.

Mifano ya miamala ambayo huenda ilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa mixer ya Ethereum smart-contract inayotenganisha amana na utoaji wa baadaye, tazama [Tornado Cash](https://tornado.cash).

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), huficha muamala kati ya wahusika wawili (kwa mfano, mteja na mfanyabiashara) ili uonekane kama muamala wa kawaida, bila outputs zilizo sawa zinazotambulisha CoinJoin. Hii hufanya iwe vigumu sana kuitambua na inaweza kubatilisha heuristic ya common-input-ownership inayotumiwa na vyombo vinavyofuatilia miamala.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Miamala kama iliyo hapo juu inaweza kuwa PayJoin, na hivyo kuboresha faragha huku ikibaki isiyotofautishwa na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika juhudi za kulinda faragha ya miamala.

# Mbinu Bora za Kulinda Faragha katika Sarafu za Kidijitali

## **Mbinu za Kusawazisha Pochi**

Ili kudumisha faragha na usalama, ni muhimu kusawazisha pochi na blockchain. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya kiwango cha juu. Miamala yote iliyowahi kufanywa huhifadhiwa ndani ya kifaa, jambo linalofanya isiwezekane kwa washambuliaji kutambua ni miamala au anwani zipi zinazomvutia mtumiaji.
- **Uchujaji wa block upande wa mteja**: Mbinu hii inahusisha kuunda vichujio kwa kila block katika blockchain, ili pochi ziweze kutambua miamala husika bila kufichua maslahi mahususi kwa wanaotazama mtandao. Pochi nyepesi hupakua vichujio hivi na kupakua block nzima tu anwani za mtumiaji zinapolingana na kilichomo.

## **Kutumia Tor kwa Kutokujulikana**

Kwa kuwa Bitcoin hufanya kazi kupitia mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP na kuongeza faragha unapowasiliana na mtandao.

## **Kuzuia Matumizi Tena ya Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia anwani tena kunaweza kuhatarisha faragha kwa kuunganisha miamala na mhusika yuleyule. Pochi za kisasa zimeundwa ili kuzuia matumizi tena ya anwani.

## **Mikakati ya Kulinda Faragha ya Miamala**

- **Miamala mingi**: Kugawanya malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala na kuzuia mashambulizi dhidi ya faragha.
- **Kuepuka chenji**: Kuchagua miamala isiyohitaji outputs za chenji huboresha faragha kwa kuvuruga mbinu za kutambua chenji.
- **Outputs nyingi za chenji**: Ikiwa kuepuka chenji hakuwezekani, kuunda outputs nyingi za chenji bado kunaweza kuboresha faragha.

# **Monero: Alama ya Kutokujulikana**

Monero imeundwa kuweka kipaumbele katika faragha ya miamala.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za kikokotozi zinazohitajika kutekeleza operesheni kwenye Ethereum, na bei yake huwekwa kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) huhusisha kikomo cha gas na ada ya msingi, pamoja na ada ya kipaumbele ili kuhamasisha validator kuujumuisha. Watumiaji wanaweza kuweka ada ya juu zaidi ili kuhakikisha hawalipi kupita kiasi; kiasi kinachozidi hurejeshwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala katika Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au za smart contract. Miamala huhitaji ada na lazima ijumuishwe katika block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, sahihi ya mtumaji, thamani, data ya hiari, kikomo cha gas na ada. Muhimu zaidi, anwani ya mtumaji hukokotolewa kutoka kwenye sahihi, hivyo haihitajiki katika data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na mifumo hii ni misingi muhimu kwa yeyote anayetaka kutumia sarafu za kidijitali huku akiweka kipaumbele katika faragha na usalama.

## Red Teaming ya Web3 Inayozingatia Thamani

- Orodhesha vipengele vinavyohifadhi au kudhibiti thamani (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha fedha na kwa njia gani.
- Linganisha kila kipengele na mbinu husika za MITRE AADAPT ili kufichua njia za kupandisha mamlaka.
- Fanyia mazoezi misururu ya mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kuandika masharti ya awali yanayowezesha unyonyaji.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kuhatarisha Mchakato wa Kusaini katika Web3

- Kuvuruga supply chain ya UI za pochi kunaweza kubadilisha payload za EIP-712 kabla tu ya kusainiwa, na kupata sahihi halali za kuteka proxy zinazotumia delegatecall (kwa mfano, kubadilisha slot-0 ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Hitilafu za kawaida katika smart account ni pamoja na kukwepa udhibiti wa ufikiaji wa `EntryPoint`, sehemu za gas zisizosainiwa, uthibitishaji unaobadilisha hali, replay ya ERC-1271 na kumaliza ada kwa kutumia revert baada ya uthibitishaji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Smart Contract

- Tumia mutation testing kutafuta mapungufu katika test suite:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa ZK Proof / zkVM Guest

Prover anapotumia **zkVM** au proof circuit maalumu kwa programu ili kuthibitisha dai, verifier hujifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **vikwazo vya kisemantiki vilivyokosekana**, prover hasidi anaweza kutengeneza proof inayothibitishwa huku **vipimo vya umma au invariant inayodaiwa vikiwa si vya kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia bytes za private witness/circuit kama **ingizo lisiloaminika linalodhibitiwa na mshambuliaji**, hata kama zimefichwa na proof.
- Epuka kuzisoma kwa kutumia helpers zisizokagua, kama `rkyv::access_unchecked`, isipokuwa bytes hizo zilikuwa tayari zimethibitishwa kwa njia nyingine.
- Ni lazima uthibitishe enum discriminants, relative pointers, lengths na indexes zilizopakiwa kutoka kwenye data iliyoserialishwa isiyoaminika kabla hazijaathiri mtiririko wa udhibiti au ufikiaji wa kumbukumbu.

Mfumo wa vitendo wa ukaguzi:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ikiwa field kama `op.kind` ni enum na mshambuliaji anaweza kuingiza **discriminant iliyo nje ya masafa**, kila `match` inayofuata kwenye thamani hiyo inapaswa kuchunguzwa kwa mashaka.

### Kukwepa counters kwa kutumia jump table / UB

Ikiwa Rust inabadilisha `match` kubwa kuwa **jump table**, discriminant batili ya enum inaweza kusababisha **mtiririko wa udhibiti usiofafanuliwa**. Muundo hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **counters/vikwazo muhimu kwa usalama**.
2. `match` ya pili hutekeleza **semantiki halisi za instruction**.
3. Discriminant iliyo nje ya masafa huweka index nje ya jump table ya kwanza na kuelekeza kwenye code inayohusishwa na ya pili.

Matokeo: operesheni bado inatekelezwa, lakini njia ya uhasibu inarukwa. Katika zkVM, hii inaweza kutengeneza proofs zinazoripoti metrics zisizowezekana, kama vile gates chache, operesheni ghali chache, au rasilimali nyingine zenye mipaka zilizopotoshwa.

Orodha ya ukaguzi:

- Tafuta enums zinazodhibitiwa na mshambuliaji, zilizodeserialize kutoka witness/private input.
- Kagua kauli za `match` zinazojirudia kwenye field ileile ya opcode/kind.
- Chukulia `unsafe` + deserialization isiyokaguliwa + dispatch kubwa ya opcode kuwa mchanganyiko hatari sana.
- Fanya reverse engineering ya binary iliyotolewa inapohitajika; mpangilio wa jump table unaweza kuwa muhimu zaidi kuliko source.

### Vikwazo vya kisemantiki vinavyokosekana katika interpreters zinazoweza kugeuzwa/maalum

Usihakiki usalama wa memory pekee; hakiki pia **sheria za kisemantiki** ambazo proof inapaswa kutekeleza.

Kwa seti za instruction zinazoweza kugeuzwa/zinaofanana na quantum, hakikisha operands zinazopaswa kuwa tofauti zimewekewa kikwazo ili ziwe tofauti. Operesheni inayofanana na Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

inakuwa si salama ikiwa guest haitakataa:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Katika hali hiyo, mpito hupunguzwa na kuwa:

```text
q = q ^ (q & q) = 0
```

Hii huunda **primitive ya reset inayojirudia kwa matokeo yale yale**, na kuvunja dhana za urejeshaji wa hali ya awali huku ikiwezesha ukokotoaji usiokusudiwa kwa gharama ndogo. Katika mifumo ya proof inayothibitisha matumizi ya rasilimali, hii inaweza kuwawezesha washambuliaji kutimiza ukaguzi wa utendaji huku wakikwepa modeli ya gharama ambayo verifier inaamini inatekelezwa.

### Ushauri wa prover usio na vikwazo vya kutosha na hesabu za modulo

Thamani zinazopakiwa kutoka kwenye stack ya **advice/witness zinadhibitiwa na prover**, hata zinapoelezwa kuwa quotients, remainders, inverses au hints zilizokokotolewa mapema. Proof huthibitisha tu kwamba witness inatimiza constraints zilizotekelezwa; haithibitishi ukokotoaji uliokusudiwa ikiwa constraints hizo hazijumuishi ukaguzi wa aina, masafa au umbo kanoniki.<sup>[[13]](#references)</sup>

Kwa helper ya reduction au Euclidean division, kagua uhusiano kamili wa namba kamili badala ya subtraction au multiplication ya mwisho pekee. Kila limb ya `q` na `r` lazima izuiwe ndani ya upana wake uliotangazwa, uundaji upya `x = q * m + r` lazima utimizwe katika uwakilishi wa namba kamili uliokusudiwa, na mpaka kanoniki `0 <= r < m` lazima utekelezwe. Thibitisha thamani **kabla** ya kuipitisha kwa instruction nyembamba ya `u32`/`u64`; operesheni nyembamba haithibitishi baada ya tukio kwamba field element au thamani ya multi-limb ya awali ilikuwa na aina iliyotarajiwa.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Kosa la `mod_12289` katika Miden linaonyesha muundo wa exploit: quotient ilikaguliwa kama thamani ya 64-bit yenye limbs mbili, lakini remainder iliyotolewa na advice ilifikia `u32overflowing_sub` bila uthibitishaji sawia. Prover hasidi angeweza kuratibu thamani batili za quotient/remainder ili vizuizi vya subtraction vilivyotekelezwa bado vitimizwe, huku procedure ikirejesha remainder isiyo ya kihisabati. Kwa kuwa matokeo haya yalitumika katika uthibitishaji wa Falcon, hitilafu ya soundness ingeweza kuongezeka na kuwa sahihi za authorization za kughushi, badala ya kutoa tu matokeo yasiyo sahihi ya hesabu.<sup>[[13]](#references)</sup>

### Kukagua cryptographic VM zenye stack isiyo dhahiri

Lugha za stack huficha operands, kwa hiyo kwanza badilisha instructions kuwa IR ambamo kila thamani ya stack inayotumiwa au kuzalishwa ni expression yenye provenance. Kisha pipeline ya uchanganuzi wa tahadhari inaweza:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Jenga call graph na ukadirie athari za stack za ingizo/tokeo za procedures.
2. Tekeleza instructions zinazotumika kwa njia ya symbolic na ubadilishe control flow kuwa expressions za SSA/structured.
3. Sambaza facts za abstract kama `Unknown`, `ProvenU32`, `Bool`, value provenance, na local initialization hadi ufikie fixed point.
4. Weka alama kwa thamani zinazotokana na advice zinapofikia typed arithmetic au sinks zinazohitaji thamani isiyo sifuri bila sanitizer kwenye **kila** njia inayoingia.
5. Linganisha signatures zilizotangazwa na zilizokadiriwa, na uhakikishe kuwa kila exit inadumisha thamani za stack zinazomilikiwa na caller.

Chukulia signature isiyojulikana au construct isiyoungwa mkono kama **pengo la uchanganuzi**, si matokeo safi. Dynamic calls, loops zisizobadilisha stack, na branches zenye athari tofauti za stack zinaweza kufanya ufuatiliaji sahihi wa stack-slot usiwezekane; decompiler salama hukataa au huweka alama kwa hali hizi badala ya kutoa pseudocode inayoonekana sahihi lakini si sahihi.<sup>[[10]](#references)[[13]](#references)</sup>

Katika control-flow joins, hifadhi property tu ikiwa inatumika kwa kila predecessor (kwa mfano, `ProvenU32 join Unknown = Unknown`). Pia tofautisha convergence ya fixed point na kufikia kikomo cha marudio: ni over-approximation iliyokamilika na iliyo sound pekee inayoweza kuhalalisha kuchukulia kutokuwepo kwa diagnostic kama ushahidi kwamba executions zote zilizowakilishwa zinatimiza property hiyo.<sup>[[11]](#references)</sup>

### Tumia proof obligations kufichua preconditions zilizofichika

Kwa instruction sets ndogo, geuza procedures kuwa formal VM model inayoweza kutekelezwa na uthibitishe matokeo pamoja na mabadiliko kamili ya stack. Theorem inapaswa kujumuisha termination, typed inputs, prefix ya matokeo inayotarajiwa, na uhifadhi wa stack ya caller ambayo haijaguswa. Kagua tamko la theorem kwa umakini sawa na proof: kernel inaweza kuthibitisha proof ya dai lililodhoofishwa bila kukusudia.<sup>[[12]](#references)[[13]](#references)</sup>

Hypotheses zisizotarajiwa ni matokeo muhimu. Katika ukaguzi wa Miden, proof ya mzunguko wa kulia wa 64-bit ilihitaji `shift mod 32 != 0`, ikifichua edge case inayoshindwa kwa inputs kubwa wakati shift ni kizidisho cha 32; proof nyingine iligundua kuwa `wrapping_mul` ya 256-bit ilitupa thamani za stack zinazomilikiwa na caller. Ongeza boundary case iliyogunduliwa kwenye tests, kisha rekebisha implementation au uimarishe public precondition kwa makusudi badala ya kukubali kimya kimya dhana hiyo ya ziada.<sup>[[12]](#references)[[13]](#references)</sup>

### Mambo ya kupima katika mifumo ya ZK

- Fuzz parsers zote za guest kwa encodings mbovu za witness/private-input.
- Hakikisha enum range validation inafanyika kabla ya opcode dispatch.
- Ongeza semantic checks za operand aliasing na aina nyingine za instruction zisizo halali.
- Fuatilia kila chanzo cha advice/witness hadi kila typed arithmetic sink na uhakikishe validation inafanyika kwenye kila njia.<sup>[[11]](#references)[[13]](#references)</sup>
- Pima arithmetic helpers kwa limbs zisizo canonical, remainders zilizo nje ya range, na shift counts za mipaka.<sup>[[12]](#references)[[13]](#references)</sup>
- Hakikisha urefu wa stack na uhifadhi wa thamani zilizo chini ya arguments zilizotangazwa za procedure kwenye kila return.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Linganisha counters zilizoripotiwa/za umma na reference implementation huru.
- Kumbuka kwamba proof halali bado inaweza kuthibitisha **dai lisilo sahihi** ikiwa guest program ina hitilafu.

## Authorization Inayotegemea Hali

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation ya DeFi/AMM

Ikiwa unachunguza exploitation ya vitendo ya DEX na AMM (Uniswap v4 hooks, matumizi mabaya ya rounding/precision, swaps zinazovuka threshold na kuimarishwa na flash loan), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa weighted pools zenye assets nyingi zinazohifadhi virtual balances kwenye cache na zinazoweza kuwekewa sumu wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key na Private Key Zimefafanuliwa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Transactions za multi-signature ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na ada | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Faragha - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tuliishinda proof ya Google's zero-knowledge ya quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda Cryptocurrencies za Elliptic Curve dhidi ya Udhaifu wa Quantum: Makadirio ya Rasilimali na Mikakati ya Kupunguza Hatari (toleo lililorekebishwa)](https://arxiv.org/abs/2603.28846v2)
- [9] [Hifadhi ya proof-of-concept ya Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Muundo wa MASM decompiler](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Injini ya uchanganuzi tuli ya MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Model ya MASM-to-Lean na proofs za usahihi](https://github.com/trailofbits/masm-lean)
- [13] [Ukaguzi katika enzi ya AI (inayotosha)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
