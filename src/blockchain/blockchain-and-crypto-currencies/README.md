# Blockchain na Sarafu za Crypto

{{#include ../../banners/hacktricks-training.md}}

Sura hii inashughulikia dhana za blockchain na usalama wa on-chain. Kwa Bitcoin peer iliyo wazi, anza na [uhesabuji wa huduma ya Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); kwa frontend ya kivinjari, muunganisho wa wallet, au backend ya off-chain, tumia [DApp pentesting](../../pentesting-web/dapps-DecentralizedApplications.md). Kwa shughuli za faragha za sarafu za crypto na mipaka yake, tumia [sura ya faragha ya sarafu za crypto](../../privacy/cryptocurrency-privacy.md).

## Dhana za Msingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na hivyo kuendesha utekelezaji wa makubaliano bila wahusika wa kati.
- **Decentralized Applications (dApps)** hujengwa kwa kutumia smart contracts, zikiwa na front-end inayotumiaji kwa urahisi na back-end iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** hutofautiana kwa kuwa coins hutumika kama pesa za kidijitali, ilhali tokens huwakilisha thamani au umiliki katika miktadha mahususi.
  - **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa mali.
- **DeFi** ni kifupi cha Decentralized Finance, inayotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** humaanisha Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

Kwa istilahi za spot orders, futures, leverage, na options zinazotumika katika masoko ya crypto, tazama [Istilahi za Uwekezaji](investment-terms.md). Kwa matumizi mabaya ya funding rate katika itifaki za perpetual, tazama [Unyonyaji wa Perpetual Funding Rate](perpetual-funding-rate-exploitation.md).

## Mbinu za Makubaliano

Mbinu za makubaliano huhakikisha uthibitishaji salama na unaokubaliwa wa miamala kwenye blockchain:

- **Proof of Work (PoW)** hutegemea nguvu ya kompyuta kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji validators kumiliki kiasi fulani cha tokens, na hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu ya Bitcoin

### Miamala

Miamala ya Bitcoin huhusisha uhamishaji wa fedha kati ya anwani. Miamala huthibitishwa kwa saini za kidijitali, zinazohakikisha kuwa mmiliki wa private key pekee ndiye anayeweza kuanzisha uhamisho.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Multisignature Transactions** huhitaji saini nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala huwa na **inputs** (chanzo cha fedha), **outputs** (unakoelekezwa), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuongeza uwezo wa Bitcoin wa kushughulikia miamala kwa kuruhusu miamala mingi ndani ya channel, huku hali ya mwisho pekee ikitangazwa kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mbinu kama **Mixers** na **CoinJoin** huboresha kutotambulika kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Mbinu zake ni pamoja na biashara za fedha taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, huku **PayJoin** ikificha CoinJoins zionekane kama miamala ya kawaida ili kuongeza faragha.

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutotambulika kwa watumiaji mara nyingi huzua wasiwasi. Huu hapa muhtasari rahisi wa mbinu kadhaa za kawaida ambazo washambuliaji wanaweza kutumia kuhatarisha faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Dhana ya Umiliki wa Pamoja wa Inputs**

Kwa kawaida, ni nadra inputs kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kwa sababu ya ugumu unaohusika. Kwa hiyo, mara nyingi **huchukuliwa kuwa anwani mbili za input katika muamala mmoja ni za mmiliki mmoja**.

## **Utambuzi wa Anwani ya Change ya UTXO**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa sehemu tu yake itatumwa kwa anwani nyingine, salio huenda kwenye anwani mpya ya change. Watazamaji wanaweza kudhani kuwa anwani hiyo mpya ni ya mtumaji, na hivyo kuhatarisha faragha.

### Mfano

Ili kupunguza hatari hii, huduma za mixing au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Kufichuka kupitia Mitandao ya Kijamii na Majukwaa**

Wakati mwingine watumiaji hushiriki anwani zao za Bitcoin mtandaoni, na hivyo kurahisisha **kuunganisha anwani hiyo na mmiliki wake**.

## **Uchambuzi wa Grafu ya Miamala**

Miamala inaweza kuonyeshwa kama grafu, na kufichua miunganisho inayowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Heuristic ya Input Isiyohitajika (Heuristic ya Change Bora)**

Heuristic hii hutegemea kuchanganua miamala yenye inputs na outputs nyingi ili kukisia ni output ipi ni change inayorudi kwa mtumaji.

### Mfano

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ikiwa kuongeza inputs zaidi kutafanya output ya change kuwa kubwa kuliko input yoyote moja, kunaweza kuchanganya heuristic.

## **Matumizi ya Lazima Tena ya Anwani**

Washambuliaji wanaweza kutuma kiasi kidogo cha fedha kwenye anwani zilizotumika hapo awali, wakitumaini kwamba mpokeaji ataziunganisha na inputs nyingine katika miamala ya baadaye, na hivyo kuunganisha anwani hizo.

### Tabia Sahihi ya Wallet

Wallet zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani zilizotumika awali na zilizo tupu, ili kuzuia leak hii ya faragha.

## **Mbinu Nyingine za Uchambuzi wa Blockchain**

- **Kiasi Halisi cha Malipo:** Miamala isiyo na change huenda ikawa kati ya anwani mbili zinazomilikiwa na mtumiaji yuleyule.
- **Nambari Zilizokamilika:** Nambari iliyokamilika kwenye muamala hudokeza kuwa ni malipo, huku output isiyo nambari iliyokamilika huenda ikawa change.
- **Utambuzi wa Wallet:** Wallet tofauti zina mifumo ya kipekee ya kuunda miamala, hivyo wachambuzi wanaweza kutambua software iliyotumika na huenda pia anwani ya change.
- **Uhusiano wa Kiasi na Muda:** Kufichua nyakati au kiasi cha miamala kunaweza kufanya miamala ifuatilike.

## **Uchambuzi wa Trafiki**

Kwa kufuatilia trafiki ya mtandao, washambuliaji wanaweza kuhusisha miamala au blocks na anwani za IP, na hivyo kuhatarisha faragha ya watumiaji. Hii ni kweli hasa ikiwa mtu au shirika linaendesha nodes nyingi za Bitcoin, jambo linaloongeza uwezo wao wa kufuatilia miamala.

## Zaidi

Kwa orodha kamili ya mashambulizi na ulinzi wa faragha, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Miamala ya Bitcoin Isiyojulikana

## Njia za Kupata Bitcoins Bila Kujulikana

- **Miamala ya Pesa Taslimu**: Kupata bitcoin kupitia pesa taslimu.
- **Njia Mbadala za Pesa Taslimu**: Kununua gift cards na kuzibadilisha mtandaoni kwa bitcoin.
- **Mining**: Njia yenye faragha zaidi ya kupata bitcoins ni kupitia mining, hasa ikifanywa peke yako, kwa sababu mining pools huenda zikajua anwani ya IP ya miner. [Maelezo kuhusu Mining Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na haipendekezwi.

## Huduma za Mixing

Kwa kutumia huduma ya mixing, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kama malipo**, jambo linalofanya iwe vigumu kufuatilia mmiliki wa awali. Hata hivyo, hii inahitaji kuiamini huduma hiyo kwamba haitahifadhi logs na kwamba itarudisha bitcoins hizo kweli. Chaguo mbadala za mixing ni pamoja na kasino za Bitcoin.

## CoinJoin

**CoinJoin** huunganisha miamala mingi kutoka kwa watumiaji tofauti na kuifanya muamala mmoja, jambo linalofanya mchakato wa kulinganisha inputs na outputs kuwa mgumu kwa yeyote anayejaribu kufanya hivyo. Licha ya ufanisi wake, miamala yenye ukubwa wa inputs na outputs wa kipekee bado inaweza kufuatiliwa.

Mifano ya miamala ambayo huenda ilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa mixer ya Ethereum smart-contract inayotenganisha amana na utoaji wa fedha unaofuata, angalia [Tornado Cash](https://tornado.cash).

## PayJoin

Toleo tofauti la CoinJoin, **PayJoin** (au P2EP), huficha muamala kati ya pande mbili (k.m., mteja na mfanyabiashara) kwa kuufanya uonekane kama muamala wa kawaida, bila outputs zilizo sawa zinazotambulisha CoinJoin. Hii hufanya iwe vigumu sana kuutambua na inaweza kubatilisha heuristic ya umiliki wa pamoja wa inputs inayotumiwa na mashirika yanayofuatilia miamala.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Miamala kama iliyo hapo juu inaweza kuwa PayJoin, na hivyo kuimarisha faragha huku ikiendelea kutofautishika na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika juhudi za kulinda faragha ya miamala.

# Mbinu Bora za Kulinda Faragha katika Sarafu za Kidijitali

## **Mbinu za Kusawazisha Wallet**

Ili kudumisha faragha na usalama, ni muhimu kusawazisha wallet na blockchain. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya kiwango cha juu. Miamala yote iliyowahi kufanywa huhifadhiwa ndani ya kifaa, hivyo washambuliaji hawawezi kutambua ni miamala au anwani zipi mtumiaji anazozifuatilia.
- **Uchuji wa block upande wa mteja**: Mbinu hii huhusisha kuunda vichujio kwa kila block kwenye blockchain, na kuiwezesha wallet kutambua miamala husika bila kufichua mambo yanayomvutia mtumiaji kwa waangalizi wa mtandao. Wallet nyepesi hupakua vichujio hivi, na kupakua block kamili tu inapopata inayolingana na anwani za mtumiaji.

## **Kutumia Tor kwa Kutokujulikana**

Kwa kuwa Bitcoin hutumia mtandao wa peer-to-peer, matumizi ya Tor yanapendekezwa ili kuficha anwani yako ya IP na kuimarisha faragha unapowasiliana na mtandao.

## **Kuzuia Kutumia Tena Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha faragha kwa kuhusisha miamala na huluki ileile. Wallet za kisasa zimeundwa ili kuzuia matumizi ya tena ya anwani.

## **Mikakati ya Kulinda Faragha ya Miamala**

- **Miamala mingi**: Kugawanya malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala na kuzuia mashambulizi dhidi ya faragha.
- **Kuepuka chenji**: Kuchagua miamala isiyohitaji matokeo ya chenji huimarisha faragha kwa kuvuruga mbinu za kugundua chenji.
- **Matokeo mengi ya chenji**: Ikiwa haiwezekani kuepuka chenji, kutoa matokeo mengi ya chenji bado kunaweza kuboresha faragha.

# **Monero: Kielelezo cha Kutokujulikana**

Monero imeundwa ili kutanguliza faragha ya miamala.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za kimahesabu zinazohitajika kutekeleza shughuli kwenye Ethereum, na bei yake huwekwa katika **gwei**. Kwa mfano, muamala unaogharimu gwei 2,310,000 (au ETH 0.00231) huhusisha kikomo cha gas na ada ya msingi, pamoja na ada ya kipaumbele ili kuhamasisha validator kuujumuisha. Watumiaji wanaweza kuweka ada ya juu zaidi ili kuhakikisha hawalipi kupita kiasi; kiasi kinachozidi hurudishwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala kwenye Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au za smart contract. Inahitaji ada na lazima ijumuishwe kwenye block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, sahihi ya mtumaji, thamani, data ya hiari, kikomo cha gas na ada. Muhimu zaidi, anwani ya mtumaji hukokotolewa kutokana na sahihi, hivyo haihitajiki kwenye data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na taratibu hizi ni msingi kwa yeyote anayetaka kutumia sarafu za kidijitali huku akitanguliza faragha na usalama.

## Red Teaming ya Web3 Inayolenga Thamani

- Orodhesha vipengele vinavyohifadhi thamani (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha fedha na jinsi gani.
- Linganisha kila kipengele na mbinu husika za MITRE AADAPT ili kufichua njia za kupandisha ruhusa.
- Fanyia mazoezi minyororo ya mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kuweka kumbukumbu za masharti yanayowezesha unyonyaji.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kuhujumu Mtiririko wa Uwekaji Saini wa Web3

- Uharibifu wa supply chain kwenye UI za wallet unaweza kubadilisha payload za EIP-712 kabla tu ya kusainiwa, na kuvuna sahihi halali kwa ajili ya kutwaa udhibiti wa proxy kupitia delegatecall (kwa mfano, kubadilisha slot-0 ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Kasoro za kawaida za smart-account ni pamoja na kukwepa udhibiti wa ufikiaji wa `EntryPoint`, sehemu za gas zisizosainiwa, uthibitishaji unaobadilisha hali, ERC-1271 replay, na kuisha kwa ada kupitia revert baada ya uthibitishaji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Smart Contract

- Kutumia mutation testing kutafuta mapungufu katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa ZK Proof / zkVM Guest

Prover inapotumia **zkVM** au proof circuit maalum ya programu kuthibitisha dai, verifier hujifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **semantic constraints zinazokosekana**, prover hasidi anaweza kutengeneza proof inayothibitishwa huku **metrics za umma au invariant inayodaiwa zikiwa si za kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia byte za private witness/circuit kama **ingizo lisiloaminika kutoka kwa mshambuliaji**, hata kama zimefichwa na proof.
- Epuka kuzisoma kwa kutumia helpers zisizokagua, kama `rkyv::access_unchecked`, isipokuwa byte hizo zilishathibitishwa kwa njia nyingine.
- Enum discriminants, relative pointers, lengths na indexes zinazopakiwa kutoka kwenye data iliyoserialishwa isiyoaminika lazima zithibitishwe kabla hazijaathiri mtiririko wa udhibiti au ufikiaji wa kumbukumbu.

Mbinu ya vitendo ya ukaguzi:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ikiwa sehemu kama `op.kind` ni enum na mshambulizi anaweza kuingiza **discriminant iliyo nje ya masafa**, kila `match` inayofuata kwenye thamani hiyo inapaswa kuchunguzwa kwa mashaka.

### Kuepuka ukaguzi wa jump-table / UB

Ikiwa Rust inabadilisha `match` kubwa kuwa **jump table**, discriminant batili ya enum inaweza kusababisha **mtiririko wa udhibiti usiofafanuliwa**. Muundo hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **vihesabio/vikwazo muhimu kwa usalama**.
2. `match` ya pili hutekeleza **semantiki halisi ya maelekezo**.
3. Discriminant iliyo nje ya masafa huashiria nje ya jump table ya kwanza na kuishia kwenye msimbo unaohusishwa na ya pili.

Matokeo: operesheni bado hutekelezwa, lakini njia ya uhasibu hurukwa. Katika zkVM, hali hii inaweza kutengeneza proofs zinazoripoti vipimo visivyowezekana, kama vile gates chache zaidi, operesheni ghali chache zaidi, au rasilimali nyingine zenye vikomo zilizoghushiwa.

Orodha ya ukaguzi:

- Tafuta enum zinazodhibitiwa na mshambulizi na kuserialishwa kutoka kwa witness/private input.
- Kagua kauli za `match` zinazorudiwa kwenye sehemu ileile ya opcode/kind.
- Chukulia `unsafe` + deserialization bila ukaguzi + dispatch kubwa ya opcode kuwa mchanganyiko hatari sana.
- Fanya reverse engineering ya binary iliyotolewa inapohitajika; mpangilio wa jump table unaweza kuwa muhimu zaidi kuliko msimbo wa chanzo.

### Vikwazo vya kisemantiki vinavyokosekana katika interpreters zinazoweza kutenduliwa/maalum

Usihakiki usalama wa kumbukumbu pekee; hakiki pia **sheria za kisemantiki** ambazo proof inapaswa kutekeleza.

Kwa seti za maelekezo zinazoweza kutenduliwa/zinazofanana na quantum, hakikisha operandi zinazopaswa kuwa tofauti zimewekewa kikwazo cha kuwa tofauti. Operesheni inayofanana na Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

inakuwa si salama ikiwa guest haitakataa:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Katika hali hiyo, mpito hurahisishwa na kuwa:

```text
q = q ^ (q & q) = 0
```

Hii huunda **primitive ya deterministic reset**, ikivunja dhana za reversibility na kuwezesha ukokotoaji usiokusudiwa kwa gharama ndogo zaidi. Katika mifumo ya proof inayothibitisha matumizi ya rasilimali, hii inaweza kuwawezesha washambuliaji kutimiza ukaguzi wa utendaji huku wakipita kielelezo cha gharama ambacho verifier inaamini kinatekelezwa.

### Ushauri wa prover usiodhibitiwa vya kutosha na hesabu za modular

Thamani zinazopakiwa kutoka kwenye **advice/witness stack zinadhibitiwa na prover**, hata zinapoelezwa kuwa quotients, remainders, inverses au hints zilizokokotolewa mapema. Proof huthibitisha tu kwamba witness inatimiza constraints zilizotekelezwa; haithibitishi kwamba ukokotoaji uliokusudiwa ulifanyika ikiwa constraints hizo hazina ukaguzi wa type, range au canonical form.<sup>[[13]](#references)</sup>

Kwa helper ya reduction au Euclidean division, kagua uhusiano kamili wa integer badala ya kuangalia tu subtraction au multiplication ya mwisho. Kila limb ya `q` na `r` lazima izuiliwe ndani ya upana wake uliotangazwa, reconstruction `x = q * m + r` lazima itimie katika uwakilishi wa integer uliokusudiwa, na sharti la canonical `0 <= r < m` lazima litekelezwe. Thibitisha thamani **kabla** ya kuipitisha kwa instruction nyembamba zaidi ya `u32`/`u64`; operation nyembamba haithibitishi kwa kurudi nyuma kwamba field element au thamani ya multi-limb ya awali ilikuwa na type iliyotarajiwa.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Kufeli kwa `mod_12289` katika Miden kunaonyesha muundo wa exploit: quotient ilikaguliwa kama thamani ya 64-bit yenye limbs mbili, lakini remainder iliyotolewa kupitia advice ilifikia `u32overflowing_sub` bila uthibitishaji sawia. Prover hasidi angeweza kuratibu thamani zisizo halali za quotient/remainder ili masharti ya subtraction yaliyotekelezwa yatimizwe huku procedure ikirejesha remainder isiyo ya kihisabati. Kwa kuwa matokeo haya yalitumika katika uthibitishaji wa Falcon, hitilafu ya soundness ingeweza kuongezeka na kuwa saini za authorization zilizoghushiwa, badala ya kutoa tu matokeo yasiyo sahihi ya hesabu.<sup>[[13]](#references)</sup>

### Kukagua cryptographic VM zenye stack fiche

Lugha za stack huficha operands, kwa hiyo kwanza badilisha instructions ziwe IR ambamo kila thamani ya stack inayotumiwa na kutolewa ni expression yenye provenance. Kisha pipeline ya tahadhari inaweza:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Jenga call graph na ukadirie athari za stack za ingizo/tokeo za procedures.
2. Tekeleza instructions zinazoungwa mkono kwa njia ya symbolic na uhamishe control flow kuwa expressions za SSA/structured.
3. Sambaza facts za abstract kama `Unknown`, `ProvenU32`, `Bool`, value provenance, na local initialization hadi kufikia fixed point.
4. Weka alama kwa thamani zinazotokana na advice zinazofikia typed arithmetic au non-zero sinks bila sanitizer kwenye **kila** njia inayoingia.
5. Linganisha signatures zilizotangazwa na zilizokadiriwa, na uthibitishe kuwa kila exit inahifadhi thamani za stack zinazomilikiwa na caller.

Chukulia signature isiyojulikana au construct isiyoungwa mkono kama **pengo la uchanganuzi**, wala si matokeo safi. Dynamic calls, loops zisizo stack-neutral, na branches zenye stack effects tofauti zinaweza kufanya ufuatiliaji sahihi wa stack-slot usiwezekane; decompiler salama zaidi hukataa au kuweka alama kwa hali hizi badala ya kutoa pseudocode inayoonekana sahihi lakini si sahihi.<sup>[[10]](#references)[[13]](#references)</sup>

Katika control-flow joins, hifadhi property tu ikiwa inatimizwa na kila predecessor (kwa mfano, `ProvenU32 join Unknown = Unknown`). Pia tofautisha convergence ya fixed-point na kufikia kikomo cha marudio: ni over-approximation iliyokamilika na iliyo sahihi tu inayoweza kuhalalisha kuchukulia kutokuwepo kwa diagnostic kama ushahidi kwamba executions zote zilizowakilishwa zinatimiza property hiyo.<sup>[[11]](#references)</sup>

### Tumia proof obligations kufichua masharti ya awali yaliyofichika

Kwa instruction sets ndogo, geuza procedures kuwa formal VM model inayoweza kutekelezwa na uthibitishe matokeo pamoja na mabadiliko kamili ya stack. Theorem inapaswa kujumuisha termination, inputs zenye types sahihi, prefix ya matokeo inayotarajiwa, na uhifadhi wa stack ya caller ambayo haijaguswa. Kagua kauli ya theorem kwa umakini kama proof yenyewe: kernel inaweza kuthibitisha proof ya dai lililodhoofishwa kimakosa.<sup>[[12]](#references)[[13]](#references)</sup>

Hypotheses zisizotarajiwa ni matokeo muhimu. Katika ukaguzi wa Miden, proof ya right rotation ya 64-bit ilihitaji `shift mod 32 != 0`, na hivyo kufichua edge case inayofeli kwa inputs kubwa wakati shift ni kizidishi cha 32; proof nyingine iligundua kuwa `wrapping_mul` ya 256-bit ilitupa thamani za stack zinazomilikiwa na caller. Ongeza boundary case iliyogunduliwa kwenye tests, kisha rekebisha implementation au uimarishe precondition ya umma kwa makusudi badala ya kukubali kimyakimya dhana hiyo ya ziada.<sup>[[12]](#references)[[13]](#references)</sup>

### Mambo ya kupima katika ZK systems

- Fuzz parsers zote za guest kwa encodings mbovu za witness/private-input.
- Hakikisha uthibitishaji wa enum range unafanyika kabla ya opcode dispatch.
- Ongeza ukaguzi wa kisemantiki wa operand aliasing na aina nyingine za instructions zisizo halali.
- Fuatilia kila chanzo cha advice/witness hadi kila typed arithmetic sink na uhitaji uthibitishaji kwenye kila njia.<sup>[[11]](#references)[[13]](#references)</sup>
- Pima arithmetic helpers kwa limbs zisizo canonical, remainders zilizo nje ya range, na shift counts za mipaka.<sup>[[12]](#references)[[13]](#references)</sup>
- Hakikisha stack height na uhifadhi wa thamani zilizo chini ya arguments zilizotangazwa za procedure katika kila return.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Linganisha counters zinazoripotiwa/za umma na reference implementation huru.
- Kumbuka kuwa proof halali bado inaweza kuthibitisha **kauli isiyo sahihi** ikiwa guest program ina hitilafu.

## Authorization Inayotegemea Hali

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation ya DeFi/AMM

Ikiwa unachunguza exploitation ya vitendo ya DEX na AMM (Uniswap v4 hooks, matumizi mabaya ya rounding/precision, swaps zinazovuka threshold na kuimarishwa na flash-loan), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa multi-asset weighted pools zinazohifadhi virtual balances kwenye cache na zinazoweza kudanganywa wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Ufunguo wa Umma na Ufunguo wa Faragha Umefafanuliwa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Muamala wa saini nyingi ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Muamala | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na ada | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Faragha - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tumevunja proof ya Google ya zero-knowledge ya quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda Elliptic Curve Cryptocurrencies dhidi ya Udhaifu wa Quantum: Makadirio ya Rasilimali na Hatua za Kupunguza Hatari (toleo lililowekewa viraka)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repository ya proof-of-concept ya Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Muundo wa MASM decompiler](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Injini ya static-analysis ya MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Muundo wa MASM-to-Lean na proofs za usahihi](https://github.com/trailofbits/masm-lean)
- [13] [Ukaguzi katika enzi ya AI (inayotosha kwa kiwango kizuri)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
