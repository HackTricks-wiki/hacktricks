# Blockchain na Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain wakati masharti fulani yanatimizwa, na hivyo kuendesha utekelezaji wa makubaliano bila intermediaries.
- **Decentralized Applications (dApps)** hujengwa juu ya smart contracts, zikiwa na front-end inayofaa kwa mtumiaji na back-end iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** hutofautiana kwa kuwa coins hutumika kama fedha za kidijitali, huku tokens zikiwakilisha thamani au umiliki katika miktadha mahususi.
- **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa asset.
- **DeFi** ni kifupi cha Decentralized Finance, inayotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** zinarejelea Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Mbinu za Consensus

Mbinu za consensus huhakikisha uthibitishaji salama na uliokubaliwa wa transactions kwenye blockchain:

- **Proof of Work (PoW)** hutegemea uwezo wa computational kwa uthibitishaji wa transaction.
- **Proof of Stake (PoS)** huhitaji validators kushikilia kiasi fulani cha tokens, na hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu ya Bitcoin

### Transactions

Bitcoin transactions huhusisha uhamishaji wa fedha kati ya addresses. Transactions huthibitishwa kupitia digital signatures, kuhakikisha kuwa ni mmiliki wa private key pekee anayeweza kuanzisha transfers.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Multisignature Transactions** huhitaji signatures nyingi ili kuidhinisha transaction.<sup>[[3]](#references)</sup>
- Transactions hujumuisha **inputs** (chanzo cha fedha), **outputs** (mahali pa kutumwa), **fees** (zinazolipwa kwa miners), na **scripts** (masharti ya transaction).

### Lightning Network

Inalenga kuboresha scalability ya Bitcoin kwa kuruhusu transactions nyingi ndani ya channel, huku hali ya mwisho pekee ikitangazwa kwenye blockchain.

## Masuala ya Privacy ya Bitcoin

Privacy attacks, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya transactions. Mikakati kama **Mixers** na **CoinJoin** huboresha anonymity kwa kuficha miunganisho ya transactions kati ya users.

## Kupata Bitcoins kwa Anonymous

Mbinu zinajumuisha biashara za fedha taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya transactions nyingi ili kufanya traceability iwe ngumu, huku **PayJoin** ikificha CoinJoins kama transactions za kawaida kwa privacy iliyoongezeka.

# Muhtasari wa Bitcoin Privacy Attacks

Katika ulimwengu wa Bitcoin, privacy ya transactions na anonymity ya users mara nyingi huwa mada za wasiwasi. Huu hapa ni muhtasari rahisi wa mbinu kadhaa za kawaida ambazo attackers wanaweza kutumia kuhatarisha Bitcoin privacy.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Kwa ujumla, ni nadra kwa inputs kutoka kwa users tofauti kuunganishwa katika transaction moja kutokana na ugumu unaohusika. Hivyo, **two input addresses in the same transaction are often assumed to belong to the same owner**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika transaction. Ikiwa sehemu yake pekee itatumwa kwenye address nyingine, salio huenda kwenye change address mpya. Observers wanaweza kudhani kuwa address hii mpya ni ya sender, na hivyo kuhatarisha privacy.

### Mfano

Ili kupunguza hili, mixing services au kutumia addresses nyingi kunaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Users wakati mwingine hushiriki Bitcoin addresses zao online, na hivyo kufanya iwe **easy to link the address to its owner**.

## **Transaction Graph Analysis**

Transactions zinaweza kuonyeshwa kama graphs, zikifichua miunganisho inayowezekana kati ya users kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii inategemea kuchanganua transactions zilizo na inputs na outputs nyingi ili kukisia ni output ipi iliyo change inayorudi kwa sender.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ikiwa kuongeza inputs zaidi kunafanya change output iwe kubwa kuliko input yoyote moja, kunaweza kuichanganya heuristic.

## **Forced Address Reuse**

Attackers wanaweza kutuma kiasi kidogo kwenye addresses zilizowahi kutumika, wakitumaini kwamba mpokeaji atazichanganya na inputs nyingine katika transactions za baadaye, hivyo kuunganisha addresses hizo.

### Correct Wallet Behavior

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye addresses zilizowahi kutumika na zilizo tupu ili kuzuia privacy leak hii.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions zisizo na change huenda zikawa kati ya addresses mbili zinazomilikiwa na user yuleyule.
- **Round Numbers:** Round number katika transaction huashiria kwamba ni malipo, huku output isiyo round ikiwa huenda ndiyo change.
- **Wallet Fingerprinting:** Wallets tofauti zina mifumo ya kipekee ya kuunda transactions, hivyo kuwawezesha analysts kutambua software iliyotumika na huenda change address.
- **Amount & Timing Correlations:** Kufichua nyakati au kiasi cha transactions kunaweza kufanya transactions zifuatiliwe.

## **Traffic Analysis**

Kwa kufuatilia network traffic, attackers wanaweza kuunganisha transactions au blocks na IP addresses, na hivyo kuhatarisha privacy ya users. Hili ni kweli hasa ikiwa entity inaendesha Bitcoin nodes nyingi, jambo linaloongeza uwezo wake wa kufuatilia transactions.

## More

Kwa orodha kamili ya privacy attacks na defenses, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Kupata bitcoin kupitia cash.
- **Cash Alternatives**: Kununua gift cards na kuzibadilisha online kuwa bitcoin.
- **Mining**: Njia yenye privacy zaidi ya kupata bitcoins ni kupitia mining, hasa inapofanywa peke yako kwa sababu mining pools zinaweza kujua IP address ya miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na haipendekezwi.

## Mixing Services

Kwa kutumia mixing service, user anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kwa malipo**, jambo linalofanya iwe vigumu kumfuatilia owner wa awali. Hata hivyo, hili linahitaji kuamini service hiyo kutohifadhi logs na kurejesha bitcoins hizo kwa kweli. Chaguo nyingine za mixing ni pamoja na Bitcoin casinos.

## CoinJoin

**CoinJoin** huunganisha transactions nyingi kutoka kwa users tofauti kuwa transaction moja, na kufanya mchakato wa kulinganisha inputs na outputs kuwa mgumu. Licha ya ufanisi wake, transactions zenye ukubwa wa kipekee wa inputs na outputs bado zinaweza kufuatiliwa.

Mifano ya transactions ambazo huenda zilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa Ethereum smart-contract mixer inayotenganisha deposits na withdrawals za baadaye, tazama [Tornado Cash](https://tornado.cash).

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), huficha transaction kati ya parties mbili (kwa mfano, customer na merchant) kama transaction ya kawaida, bila sifa ya outputs zilizo sawa inayotambulisha CoinJoin. Hili hufanya iwe vigumu sana kugundua na linaweza kubatilisha common-input-ownership heuristic inayotumiwa na entities zinazofuatilia transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Miamala kama hiyo inaweza kuwa PayJoin, ikiimarisha faragha huku ikiendelea kutotofautishwa na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika jitihada za kulinda faragha ya miamala.

# Mbinu Bora za Kulinda Faragha katika Cryptocurrencies

## **Mbinu za Kusawazisha Wallet**

Ili kudumisha faragha na usalama, kusawazisha wallet na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya juu zaidi. Miamala yote iliyowahi kufanywa huhifadhiwa kwenye kifaa cha ndani, hivyo kuwazuia wapinzani kutambua ni miamala au anwani zipi mtumiaji anavutiwa nazo.
- **Client-side block filtering**: Mbinu hii inahusisha kuunda filters kwa kila block kwenye blockchain, na kuziwezesha wallet kutambua miamala husika bila kufichua maslahi mahususi kwa waangalizi wa mtandao. Wallet nyepesi hupakua filters hizi na kupakua blocks kamili pekee inapopatikana match na anwani za mtumiaji.

## **Kutumia Tor kwa Kutokujulikana**

Kwa kuwa Bitcoin hufanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP na kuimarisha faragha unapowasiliana na mtandao.

## **Kuzuia Kutumia Tena Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha faragha kwa kuunganisha miamala na entity ileile. Wallet za kisasa huzuia matumizi ya tena ya anwani kupitia muundo wake.

## **Mikakati ya Kulinda Faragha ya Miamala**

- **Miamala mingi**: Kugawanya malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala na kuzuia privacy attacks.
- **Kuepuka change**: Kuchagua miamala isiyohitaji change outputs huimarisha faragha kwa kuvuruga mbinu za kugundua change.
- **Change outputs nyingi**: Ikiwa kuepuka change hakuwezekani, kuunda change outputs nyingi bado kunaweza kuboresha faragha.

# **Monero: Mwanga wa Kutokujulikana**

Monero imeundwa kuweka kipaumbele kwenye faragha ya miamala.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za kimahesabu zinazohitajika kutekeleza operations kwenye Ethereum, na huwekewa bei kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) huhusisha gas limit na base fee, pamoja na priority fee ya kuhamasisha validator kuujumuisha. Watumiaji wanaweza kuweka max fee ili kuhakikisha hawalipi zaidi, huku ziada ikirejeshwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala kwenye Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au smart contract. Inahitaji ada na lazima ijumuishwe kwenye block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, saini ya mtumaji, thamani, data ya hiari, gas limit na ada. Muhimu ni kwamba anwani ya mtumaji hutambuliwa kutokana na saini, hivyo haihitajiki ndani ya data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na taratibu hizi ni msingi kwa mtu yeyote anayetaka kutumia cryptocurrencies huku akiweka kipaumbele kwenye faragha na usalama.

## Red Teaming ya Web3 Inayolenga Thamani

- Orodhesha vipengele vinavyobeba thamani (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha fedha na jinsi anavyoweza kufanya hivyo.
- Linganisha kila kipengele na MITRE AADAPT tactics husika ili kufichua njia za privilege escalation.
- Fanya mazoezi ya attack chains za flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kurekodi exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kuhatarisha Web3 Signing Workflow

- Supply-chain tampering ya wallet UIs inaweza kubadilisha EIP-712 payloads muda mfupi kabla ya signing, na kukusanya signatures halali kwa ajili ya delegatecall-based proxy takeovers (kwa mfano, slot-0 overwrite ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Smart-account failure modes za kawaida zinajumuisha kupita `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, na fee-drain kupitia revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Smart Contract

- Mutation testing ya kutafuta maeneo yasiyofunikwa kwenye test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa ZK Proof / zkVM Guest

Prover anapotumia **zkVM** au proof circuit maalum ya application kuthibitisha dai, verifier hujifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **semantic constraints zilizokosekana**, prover hasidi anaweza kutengeneza proof inayothibitishwa huku **public metrics au invariant inayodaiwa ikiwa si ya kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia private witness/circuit bytes kama **untrusted attacker input** hata kama zimefichwa na proof.
- Epuka kuzideserialize kwa kutumia unchecked helpers kama `rkyv::access_unchecked`, isipokuwa bytes hizo zilithibitishwa tayari nje ya mfumo.
- Enum discriminants, relative pointers, lengths na indexes zilizopakiwa kutoka kwenye untrusted serialized data lazima zithibitishwe kabla hazijaathiri control flow au memory access.

Muundo wa vitendo wa audit:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Iwapo field kama `op.kind` ni enum na mshambuliaji anaweza kuingiza **out-of-range discriminant**, kila `match` inayofuata kwenye thamani hiyo inakuwa ya kutiliwa shaka.

### Jump-table / UB counter bypass

Ikiwa Rust itabadilisha `match` kubwa kuwa **jump table**, enum discriminant isiyo halali inaweza kusababisha **undefined control flow**. Muundo hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **counters/constraints muhimu kwa usalama**.
2. `match` ya pili hutekeleza **semantics halisi za instruction**.
3. Discriminant iliyo nje ya masafa hu-index baada ya jump table ya kwanza na kutua kwenye code inayohusishwa na ya pili.

Matokeo: operation bado inatekelezwa, lakini njia ya accounting inarukwa. Katika zkVM, hii inaweza kutengeneza proofs zinazoripoti metrics zisizowezekana, kama vile gates chache, operations ghali chache, au resources nyingine zenye mipaka zilizoghushiwa.

Checklist ya ukaguzi:

- Tafuta enums zinazodhibitiwa na mshambuliaji, zilizodeserialize kutoka witness/private input.
- Kagua statements za `match` zinazorudiwa kwenye opcode/kind field ileile.
- Chukulia `unsafe` + unchecked deserialization + large opcode dispatch kuwa mchanganyiko wa hatari kubwa.
- Reverse engineer binary iliyotolewa inapohitajika; mpangilio wa jump-table unaweza kuwa muhimu zaidi kuliko source.

### Missing semantic constraints in reversible/specialized interpreters

Usihakiki usalama wa memory pekee; pia hakiki **semantic rules** ambazo proof inapaswa kutekeleza.

Kwa instruction sets za reversible/quantum-like, hakikisha operands zinazopaswa kuwa tofauti kweli zimewekewa constraint ya kuwa tofauti. Operation inayofanana na Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
inakuwa si salama ikiwa guest hatakataa:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Katika hali hiyo, transition huishia kuwa:
```text
q = q ^ (q & q) = 0
```
Hii huunda **deterministic reset primitive**, kuvunja dhana za reversibility na kuwezesha computations za gharama ya chini ambazo hazikukusudiwa. Katika proof systems zinazothibitisha matumizi ya rasilimali, hii inaweza kuwawezesha attackers kutimiza functional checks huku wakipita cost model ambayo verifier anaamini inatekelezwa.

### Cha kupima katika ZK systems

- Fuzz guest parsers zote kwa witness/private-input encodings zilizoharibika.
- Thibitisha enum range validation kabla ya opcode dispatch.
- Ongeza semantic checks za operand aliasing na aina nyingine za instructions zisizo halali.
- Linganisha counters zilizoripotiwa/za umma na independent reference implementation.
- Kumbuka kuwa proof halali bado inaweza kuthibitisha **statement isiyo sahihi** ikiwa guest program ina bug.

## DeFi/AMM Exploitation

Ikiwa unatafiti exploitation ya vitendo ya DEXes na AMMs (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa multi-asset weighted pools zinazohifadhi virtual balances kwenye cache na zinaweza ku-poisoniwa wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key na Private Key Zimefafanuliwa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Multi-signature transactions ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tulishinda zero-knowledge proof ya Google ya quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda Elliptic Curve Cryptocurrencies dhidi ya Quantum Vulnerabilities: Resource Estimates na Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
