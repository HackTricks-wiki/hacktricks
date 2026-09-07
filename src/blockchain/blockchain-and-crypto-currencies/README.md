# Blockchain na Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na hivyo kuendesha utekelezaji wa makubaliano bila wapatanishi.
- **Decentralized Applications (dApps)** hujengwa juu ya smart contracts, zikiwa na front-end rahisi kutumia na back-end iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** hutofautiana kwa kuwa coins hutumika kama pesa za kidijitali, ilhali tokens huwakilisha thamani au umiliki katika miktadha maalum.
- **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa mali.
- **DeFi** ni kifupi cha Decentralized Finance, kinachotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** humaanisha Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Mbinu za Consensus

Mbinu za consensus huhakikisha uthibitishaji salama na unaokubaliwa wa miamala kwenye blockchain:

- **Proof of Work (PoW)** hutegemea uwezo wa kompyuta kwa ajili ya kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji validators kushikilia kiasi fulani cha tokens, hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu ya Bitcoin

### Miamala

Miamala ya Bitcoin huhusisha kuhamisha fedha kati ya anwani. Miamala huthibitishwa kupitia digital signatures, kuhakikisha kuwa ni mmiliki wa private key pekee anayeweza kuanzisha uhamishaji.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Multisignature Transactions** huhitaji signatures nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala hujumuisha **inputs** (chanzo cha fedha), **outputs** (mahali zinakopelekwa), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuboresha scalability ya Bitcoin kwa kuruhusu miamala mingi ndani ya channel, huku hali ya mwisho pekee ikitangazwa kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi dhidi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha anonymity kwa kuficha miunganisho ya miamala kati ya watumiaji.

## Kupata Bitcoins kwa Kutotambulika

Mbinu hizo zinajumuisha biashara za fedha taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, huku **PayJoin** ikificha CoinJoins kama miamala ya kawaida kwa faragha zaidi.

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na anonymity ya watumiaji mara nyingi huwa sababu za wasiwasi. Huu ni muhtasari rahisi wa mbinu kadhaa za kawaida ambazo attackers wanaweza kutumia kuhatarisha faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Kwa ujumla, ni nadra inputs kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kutokana na ugumu unaohusika. Kwa hiyo, **anwani mbili za input katika muamala mmoja mara nyingi hudhaniwa kuwa ni za mmiliki mmoja**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa sehemu yake pekee itatumwa kwa anwani nyingine, salio huenda kwenye anwani mpya ya change. Waangalizi wanaweza kudhani kuwa anwani hii mpya ni ya mtumaji, jambo linalohatarisha faragha.

### Mfano

Ili kupunguza hali hii, huduma za mixing au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Watumiaji wakati mwingine hushiriki anwani zao za Bitcoin mtandaoni, hivyo kufanya iwe **rahisi kuunganisha anwani hiyo na mmiliki wake**.

## **Transaction Graph Analysis**

Miamala inaweza kuonyeshwa kama graphs, na kufichua miunganisho inayowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii inategemea kuchanganua miamala yenye inputs na outputs nyingi ili kukisia ni output ipi iliyo change inayorejea kwa mtumaji.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ikiwa kuongeza inputs zaidi kutafanya change output iwe kubwa kuliko input yoyote moja, kunaweza kuchanganya heuristic.

## **Forced Address Reuse**

Attackers wanaweza kutuma kiasi kidogo kwenye addresses zilizowahi kutumika, wakitumaini kwamba mpokeaji atazichanganya na inputs nyingine katika transactions zijazo, hivyo kuunganisha addresses hizo.

### Tabia Sahihi ya Wallet

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye addresses zilizowahi kutumika na zilizo tupu, ili kuzuia privacy leak hii.

## **Mbinu Nyingine za Blockchain Analysis**

- **Exact Payment Amounts:** Transactions zisizo na change huenda zikawa kati ya addresses mbili zinazomilikiwa na user yuleyule.
- **Round Numbers:** Namba iliyokamilika katika transaction huashiria kwamba ni malipo, huku output isiyokamilika ikiwa huenda ikawa change.
- **Wallet Fingerprinting:** Wallets tofauti zina patterns za kipekee za kuunda transactions, zinazowawezesha analysts kutambua software iliyotumika na pengine change address.
- **Amount & Timing Correlations:** Kufichua nyakati au kiasi cha transactions kunaweza kufanya transactions zifuatiliwe.

## **Traffic Analysis**

Kwa kufuatilia network traffic, attackers wanaweza kuunganisha transactions au blocks na IP addresses, hivyo kuhatarisha privacy ya users. Hili ni kweli hasa ikiwa entity inaendesha Bitcoin nodes nyingi, jambo linaloongeza uwezo wake wa kufuatilia transactions.

## More

Kwa orodha kamili ya privacy attacks na defenses, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Miamala ya Bitcoin Isiyojulikana

## Njia za Kupata Bitcoins Bila Kujulikana

- **Cash Transactions**: Kupata bitcoin kupitia cash.
- **Cash Alternatives**: Kununua gift cards na kuzibadilisha online kuwa bitcoin.
- **Mining**: Njia yenye privacy zaidi ya kupata bitcoins ni kupitia mining, hasa inapofanywa peke yako kwa sababu mining pools huenda zikajua IP address ya miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na hakupendekezwi.

## Mixing Services

Kwa kutumia mixing service, user anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti badala yake**, jambo linalofanya iwe vigumu kufuatilia owner wa awali. Hata hivyo, hili linahitaji kuamini kwamba service haitahifadhi logs na kwamba itarudisha bitcoins. Chaguo mbadala za mixing zinajumuisha Bitcoin casinos.

## CoinJoin

**CoinJoin** huunganisha transactions nyingi kutoka kwa users tofauti kuwa transaction moja, hivyo kutatiza mchakato wa mtu yeyote anayejaribu kuoanisha inputs na outputs. Licha ya ufanisi wake, transactions zilizo na ukubwa wa kipekee wa inputs na outputs bado zinaweza kufuatiliwa.

Mifano ya transactions ambazo huenda zilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa Ethereum smart-contract mixer inayotenganisha deposits na withdrawals za baadaye, angalia [Tornado Cash](https://tornado.cash).

## PayJoin

Tofauti ya CoinJoin, **PayJoin** (au P2EP), huficha transaction kati ya parties wawili (kwa mfano, customer na merchant) kama transaction ya kawaida, bila tabia bainifu ya outputs zilizo sawa inayopatikana kwenye CoinJoin. Hili hufanya iwe vigumu sana kuitambua na linaweza kubatilisha common-input-ownership heuristic inayotumiwa na entities za transaction surveillance.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Miamala kama hiyo inaweza kuwa PayJoin, ikiboresha privacy huku ikiendelea kutotofautiana na miamala ya kawaida ya bitcoin.

**Kutumia PayJoin kunaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika jitihada za kulinda privacy ya miamala.

# Mbinu Bora za Privacy katika Cryptocurrencies

## **Mbinu za Kusawazisha Wallet**

Ili kudumisha privacy na usalama, kusawazisha wallet na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha privacy ya kiwango cha juu. Miamala yote iliyowahi kufanywa huhifadhiwa ndani ya kifaa, hivyo kuwafanya adversaries washindwe kutambua ni miamala au anwani zipi mtumiaji anavutiwa nazo.
- **Client-side block filtering**: Mbinu hii inahusisha kuunda filters kwa kila block katika blockchain, na kuruhusu wallet kutambua miamala husika bila kufichua maslahi mahususi kwa wachunguzi wa mtandao. Wallet nyepesi hupakua filters hizi, na kupakua blocks kamili tu inapopatikana match na anwani za mtumiaji.

## **Kutumia Tor kwa Anonymity**

Kwa kuwa Bitcoin hufanya kazi kwenye mtandao wa peer-to-peer, kutumia Tor kunapendekezwa ili kuficha anwani yako ya IP, na hivyo kuboresha privacy unapowasiliana na mtandao.

## **Kuzuia Kutumia Tena Anwani**

Ili kulinda privacy, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha privacy kwa kuunganisha miamala na entity moja. Wallet za kisasa huzuia matumizi tena ya anwani kupitia muundo wake.

## **Mikakati ya Privacy ya Miamala**

- **Multiple transactions**: Kugawanya malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala, na kuzuia privacy attacks.
- **Change avoidance**: Kuchagua miamala ambayo haihitaji change outputs huboresha privacy kwa kuvuruga mbinu za kutambua change.
- **Multiple change outputs**: Ikiwa kuepuka change hakuwezekani, kuunda change outputs nyingi bado kunaweza kuboresha privacy.

# **Monero: Mwanga wa Anonymity**

Monero imeundwa kuweka kipaumbele kwenye privacy ya miamala.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za computational zinazohitajika kutekeleza operations kwenye Ethereum, na huwekewa bei kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) huhusisha gas limit na base fee, pamoja na priority fee ya kuhamasisha validator kuujumuisha. Watumiaji wanaweza kuweka max fee ili kuhakikisha hawalipi zaidi ya inavyohitajika, huku ziada ikirejeshwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala katika Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au smart contract. Inahitaji fee na lazima ijumuishwe kwenye block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, signature ya mtumaji, value, data ya hiari, gas limit, na fees. Muhimu, anwani ya mtumaji hutambuliwa kutokana na signature, hivyo haihitajiki kuwekwa kwenye data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na mechanisms hizi ni msingi kwa mtu yeyote anayetaka kutumia cryptocurrencies huku akipa kipaumbele privacy na usalama.

## Red Teaming ya Web3 Inayolenga Value

- Tengeneza inventory ya components zenye value (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha funds na jinsi gani.
- Oanisha kila component na MITRE AADAPT tactics husika ili kufichua njia za privilege escalation.
- Fanya mazoezi ya flash-loan/oracle/credential/cross-chain attack chains ili kuthibitisha impact na kurekodi exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kuhatarisha Web3 Signing Workflow

- Supply-chain tampering ya wallet UIs inaweza kubadilisha EIP-712 payloads muda mfupi kabla ya signing, na kukusanya signatures halali kwa ajili ya delegatecall-based proxy takeovers (kwa mfano, slot-0 overwrite ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes zinajumuisha kukwepa access control ya `EntryPoint`, unsigned gas fields, stateful validation, ERC-1271 replay, na fee-drain kupitia revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Smart Contract

- Mutation testing ya kugundua blind spots katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa ZK Proof / zkVM Guest

Prover anapotumia **zkVM** au proof circuit mahususi ya application kuthibitisha claim, verifier anajifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **missing semantic constraints**, prover hasidi anaweza kutengeneza proof inayothibitishwa huku **public metrics au claimed invariant zikiwa si za kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia private witness/circuit bytes kama **untrusted attacker input** hata kama zimefichwa na proof.
- Epuka kuzideserialize kwa kutumia unchecked helpers kama `rkyv::access_unchecked` isipokuwa bytes hizo zilikuwa tayari zimethibitishwa out-of-band.
- Enum discriminants, relative pointers, lengths, na indexes zinazopakiwa kutoka kwenye serialized data isiyoaminika lazima zithibitishwe kabla hazijaathiri control flow au memory access.

Muundo wa vitendo wa audit:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Ikiwa field kama `op.kind` ni enum na mshambulizi anaweza kuingiza **out-of-range discriminant**, kila `match` ya baadaye kwenye thamani hiyo inakuwa ya kutiliwa shaka.

### Jump-table / UB counter bypass

Ikiwa Rust itabadilisha `match` kubwa kuwa **jump table**, enum discriminant isiyo halali inaweza kusababisha **undefined control flow**. Pattern hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **security-critical counters/constraints**.
2. `match` ya pili hutekeleza **real instruction semantics**.
3. Discriminant iliyo nje ya range hu-index baada ya jump table ya kwanza na kuingia kwenye code inayohusishwa na ya pili.

Matokeo: operesheni bado inatekelezwa, lakini njia ya accounting inarukwa. Katika zkVM, hii inaweza kuunda proofs zinazoripoti metrics zisizowezekana kama gates chache, operations ghali chache, au bounded resources nyingine zilizoghushiwa.

Review checklist:

- Tafuta enums zinazodhibitiwa na mshambulizi na ambazo zimeserialishwa kutoka kwenye witness/private input.
- Kagua statements za `match` zinazojirudia kwenye field ileile ya opcode/kind.
- Chukulia `unsafe` + unchecked deserialization + large opcode dispatch kuwa mchanganyiko wenye risk kubwa.
- Reverse engineer binary iliyotolewa inapohitajika; mpangilio wa jump-table unaweza kuwa muhimu zaidi kuliko source.

### Missing semantic constraints in reversible/specialized interpreters

Usihakiki memory safety pekee; pia hakiki **semantic rules** ambazo proof inapaswa kutekeleza.

Kwa instruction sets za reversible/quantum-like, hakikisha operands zinazopaswa kuwa tofauti zimewekewa constraint ya kuwa tofauti. Operesheni inayofanana na Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
inakuwa si salama ikiwa mgeni hatakataa:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Katika hali hiyo, mpito hujikunja kuwa:
```text
q = q ^ (q & q) = 0
```
Hii huunda **primitive ya reset ya deterministic**, ikivunja dhana za reversibility na kuwezesha computations zisizokusudiwa kwa gharama ndogo. Katika mifumo ya proof inayothibitisha matumizi ya rasilimali, hii inaweza kuwawezesha attackers kutimiza ukaguzi wa utendaji huku wakikwepa cost model ambayo verifier anaamini kuwa inatekelezwa.

### Mambo ya kupima katika mifumo ya ZK

- Fuzz guest parsers wote kwa witness/private-input encodings zilizoharibika.
- Hakikisha enum range validation inafanywa kabla ya opcode dispatch.
- Ongeza semantic checks za operand aliasing na aina nyingine za instructions zisizo halali.
- Linganisha counters zilizoripotiwa/za umma dhidi ya independent reference implementation.
- Kumbuka kwamba proof halali bado inaweza kuthibitisha **statement isiyo sahihi** ikiwa guest program ina bug.

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

Ikiwa unatafiti exploitation ya vitendo ya DEXes na AMMs (Uniswap v4 hooks, matumizi mabaya ya rounding/precision, flash-loan amplified threshold-crossing swaps), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa multi-asset weighted pools zinazohifadhi virtual balances kwenye cache na zinaweza kutiwa sumu wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key na Private Key Zimeelezwa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Multi-signature transactions ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tulishinda zero-knowledge proof ya Google ya quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda Elliptic Curve Cryptocurrencies dhidi ya Quantum Vulnerabilities: Resource Estimates na Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
