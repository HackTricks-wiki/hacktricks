# Blockchain na Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na kuendesha utekelezaji wa makubaliano bila wasuluhishi.
- **Decentralized Applications (dApps)** hujengwa juu ya smart contracts, zikiwa na front-end inayofaa watumiaji na back-end iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** hutofautiana kwa kuwa coins hutumika kama pesa za kidijitali, huku tokens zikiwakilisha thamani au umiliki katika muktadha maalum.
- **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa mali.
- **DeFi** ni kifupi cha Decentralized Finance, kinachotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** humaanisha Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Mbinu za Consensus

Mbinu za consensus huhakikisha uthibitishaji salama na unaokubaliwa wa miamala kwenye blockchain:

- **Proof of Work (PoW)** hutegemea uwezo wa kimahesabu kwa ajili ya kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji validators kumiliki kiasi fulani cha tokens, hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu ya Bitcoin

### Miamala

Miamala ya Bitcoin inahusisha kuhamisha fedha kati ya anwani. Miamala huthibitishwa kupitia sahihi za kidijitali, kuhakikisha kuwa ni mmiliki pekee wa private key anayeweza kuanzisha uhamishaji.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Multisignature Transactions** huhitaji sahihi nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala inajumuisha **inputs** (chanzo cha fedha), **outputs** (anakopelekwa), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Linalenga kuboresha scalability ya Bitcoin kwa kuruhusu miamala mingi ndani ya channel, huku hali ya mwisho pekee ikitangazwa kwenye blockchain.

## Wasiwasi wa Faragha katika Bitcoin

Mashambulizi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha anonymity kwa kuficha miunganisho ya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Mbinu zinajumuisha biashara za fedha taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, huku **PayJoin** ikificha CoinJoins kama miamala ya kawaida kwa faragha iliyoongezeka.

# Mashambulizi ya Faragha ya Bitcoin

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutokujulikana kwa watumiaji mara nyingi huwa mambo ya kuhangaisha. Huu ni muhtasari rahisi wa mbinu kadhaa za kawaida ambazo attackers wanaweza kutumia kuhatarisha faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Kwa ujumla, ni nadra inputs kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kutokana na ugumu unaohusika. Kwa hivyo, **anwani mbili za input katika muamala mmoja mara nyingi hudhaniwa kuwa za mmiliki yuleyule**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa ni sehemu tu inayotumwa kwa anwani nyingine, iliyobaki hupelekwa kwenye anwani mpya ya change. Waangalizi wanaweza kudhani kuwa anwani hii mpya ni ya mtumaji, hivyo kuhatarisha faragha.

### Mfano

Ili kupunguza hili, huduma za mixing au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Watumiaji wakati mwingine hushiriki anwani zao za Bitcoin mtandaoni, hivyo kufanya iwe **rahisi kuunganisha anwani na mmiliki wake**.

## **Transaction Graph Analysis**

Miamala inaweza kuonyeshwa kama graphs, ikifichua miunganisho inayowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii inategemea kuchanganua miamala yenye inputs na outputs nyingi ili kukisia ni output ipi iliyo change inayorudi kwa mtumaji.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If kuongeza inputs zaidi kunafanya change output kuwa kubwa kuliko input yoyote moja, kunaweza kuchanganya heuristic.

## **Forced Address Reuse**

Attackers wanaweza kutuma kiasi kidogo kwenye addresses zilizowahi kutumika, wakitumaini kwamba recipient atazichanganya na inputs nyingine katika transactions za baadaye, hivyo kuunganisha addresses pamoja.

### Correct Wallet Behavior

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye addresses zilizowahi kutumika na zilizo tupu, ili kuzuia privacy leak hii.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions zisizo na change huenda zikawa kati ya addresses mbili zinazomilikiwa na user yuleyule.
- **Round Numbers:** Namba ya mviringo katika transaction huashiria kuwa ni payment, huku output isiyo ya mviringo ikiwa huenda ndiyo change.
- **Wallet Fingerprinting:** Wallets tofauti zina patterns za kipekee za kuunda transactions, hivyo kuwawezesha analysts kutambua software iliyotumika na huenda change address.
- **Amount & Timing Correlations:** Kufichua nyakati au kiasi cha transactions kunaweza kufanya transactions zifuatiliwe.

## **Traffic Analysis**

Kwa kufuatilia network traffic, attackers wanaweza kuunganisha transactions au blocks na IP addresses, hivyo kuhatarisha privacy ya users. Hili ni kweli hasa ikiwa entity inaendesha Bitcoin nodes nyingi, jambo linaloongeza uwezo wake wa kufuatilia transactions.

## More

Kwa orodha kamili ya privacy attacks na defenses, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Kupata bitcoin kwa kutumia cash.
- **Cash Alternatives**: Kununua gift cards na kuzibadilisha online kuwa bitcoin.
- **Mining**: Njia yenye privacy zaidi ya kupata bitcoins ni kupitia mining, hasa inapofanywa peke yako, kwa sababu mining pools zinaweza kujua IP address ya miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata anonymously, ingawa ni kinyume cha sheria na haipendekezwi.

## Mixing Services

Kwa kutumia mixing service, user anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kwa malipo**, jambo linalofanya iwe vigumu kufuatilia owner wa awali. Hata hivyo, hii inahitaji kuamini service hiyo isihifadhi logs na irudishe bitcoins hizo kwa kweli. Chaguo mbadala za mixing zinajumuisha Bitcoin casinos.

## CoinJoin

**CoinJoin** huunganisha transactions nyingi kutoka kwa users tofauti kuwa transaction moja, hivyo kutatiza mchakato wa mtu yeyote anayejaribu kulinganisha inputs na outputs. Licha ya ufanisi wake, transactions zenye idadi ya kipekee ya inputs na outputs bado zinaweza kufuatiliwa.

Mifano ya transactions ambazo huenda zilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa service inayofanana kwenye Ethereum, angalia [Tornado Cash](https://tornado.cash), ambayo hufanya transactions zisiwe na utambulisho kwa kutumia funds kutoka kwa miners.

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), huficha transaction kati ya parties mbili (kwa mfano, customer na merchant) kama transaction ya kawaida, bila outputs zinazolingana kwa uwazi ambazo ni sifa ya CoinJoin. Hii hufanya iwe vigumu sana kutambua na inaweza kubatilisha common-input-ownership heuristic inayotumiwa na entities zinazofuatilia transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Miamala kama iliyo hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikibaki isiyotofautishwa na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika kutafuta faragha ya miamala.

# Mbinu Bora za Faragha katika Cryptocurrencies

## **Mbinu za Kusawazisha Wallet**

Ili kudumisha faragha na usalama, kusawazisha wallet na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya kiwango cha juu. Miamala yote iliyowahi kufanywa huhifadhiwa locally, hivyo kuwafanya adversaries washindwe kutambua ni miamala au anwani zipi mtumiaji anazovutiwa nazo.
- **Client-side block filtering**: Mbinu hii inahusisha kuunda filters kwa kila block katika blockchain, hivyo kuziwezesha wallet kutambua miamala inayohusiana bila kufichua maslahi mahususi kwa waangalizi wa network. Wallet nyepesi hupakua filters hizi na hupakua blocks kamili tu inapopatikana match na anwani za mtumiaji.

## **Kutumia Tor kwa Anonymity**

Kwa kuwa Bitcoin hutumia network ya peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP, na hivyo kuimarisha faragha unapowasiliana na network.

## **Kuzuia Kutumia Tena Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha faragha kwa kuunganisha miamala na entity ileile. Wallet za kisasa hukatisha tamaa matumizi ya tena ya anwani kupitia muundo wake.

## **Mikakati ya Faragha ya Miamala**

- **Multiple transactions**: Kugawanya malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala, na hivyo kuzuia mashambulizi ya faragha.
- **Change avoidance**: Kuchagua miamala isiyohitaji change outputs huimarisha faragha kwa kuvuruga mbinu za kugundua change.
- **Multiple change outputs**: Ikiwa kuepuka change haiwezekani, kuunda change outputs nyingi bado kunaweza kuboresha faragha.

# **Monero: Mwanga wa Anonymity**

Monero hushughulikia hitaji la anonymity kamili katika miamala ya kidigitali, na kuweka kiwango cha juu cha faragha.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za computational zinazohitajika kutekeleza operations kwenye Ethereum, na huwekwa bei kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) huhusisha gas limit na base fee, pamoja na tip ya kuwahamasisha miners. Watumiaji wanaweza kuweka max fee ili kuhakikisha hawalipi zaidi ya inavyohitajika, huku ziada ikirejeshwa.<sup>[[5]](#references)</sup>

## **Utekelezaji wa Miamala**

Miamala katika Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au smart contract. Zinahitaji fee na lazima ziminishwe. Taarifa muhimu katika muamala ni pamoja na mpokeaji, signature ya mtumaji, value, data ya hiari, gas limit, na fees. Muhimu, anwani ya mtumaji hutambuliwa kutokana na signature, hivyo si lazima iwekwe katika transaction data.<sup>[[4]](#references)</sup>

Mbinu na mechanisms hizi ni msingi kwa mtu yeyote anayetaka kushiriki katika cryptocurrencies huku akipa kipaumbele faragha na usalama.

## Value-Centric Web3 Red Teaming

- Tengeneza inventory ya components zenye value (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha funds na kwa njia gani.
- Panga kila component kulingana na MITRE AADAPT tactics zinazohusika ili kufichua njia za privilege escalation.
- Fanya mazoezi ya attack chains za flash-loan/oracle/credential/cross-chain ili kuthibitisha impact na kurekodi exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering ya wallet UIs inaweza kubadilisha EIP-712 payloads mara tu kabla ya signing, na kukusanya valid signatures kwa ajili ya delegatecall-based proxy takeovers (kwa mfano, slot-0 overwrite ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes ni pamoja na kupita access control ya `EntryPoint`, unsigned gas fields, stateful validation, ERC-1271 replay, na fee-drain kupitia revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing ili kupata blind spots katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Prover anapotumia **zkVM** au proof circuit maalum ya application kuthibitisha claim, verifier anajifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **missing semantic constraints**, prover hasidi anaweza kuunda proof inayothibitishwa huku **public metrics au claimed invariant zikiwa si za kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia private witness/circuit bytes kama **untrusted attacker input** hata kama zimefichwa na proof.
- Epuka kuzifanya deserialization kwa kutumia unchecked helpers kama `rkyv::access_unchecked` isipokuwa bytes hizo zilishathibitishwa out-of-band.
- Enum discriminants, relative pointers, lengths, na indexes zinazopakiwa kutoka kwenye untrusted serialized data lazima zivalidishwe kabla hazijaathiri control flow au memory access.

Mfumo wa practical audit:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Ikiwa field kama `op.kind` ni enum na attacker anaweza kuingiza **out-of-range discriminant**, kila `match` inayofuata kwenye thamani hiyo huwa ya kutiliwa shaka.

### Jump-table / UB counter bypass

Ikiwa Rust inabadilisha `match` kubwa kuwa **jump table**, enum discriminant isiyo halali inaweza kusababisha **undefined control flow**. Pattern hatari ni hii:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **security-critical counters/constraints**.
2. `match` ya pili hutekeleza **real instruction semantics**.
3. Out-of-range discriminant hu-index baada ya jump table ya kwanza na kuingia kwenye code inayohusishwa na ya pili.

Matokeo: operation bado inatekelezwa, lakini accounting path inarukwa. Katika zkVM, hii inaweza kuunda proofs zinazoripoti metrics zisizowezekana kama gates chache, expensive operations chache, au bounded resources nyingine zilizoghushiwa.

Review checklist:

- Tafuta enums zinazodhibitiwa na attacker na deserialized kutoka witness/private input.
- Kagua statements za `match` zinazorudiwa kwenye opcode/kind field hiyo hiyo.
- Chukulia `unsafe` + unchecked deserialization + large opcode dispatch kama mchanganyiko wa high-risk.
- Reverse engineer binary iliyotolewa inapohitajika; mpangilio wa jump-table unaweza kuwa muhimu zaidi kuliko source.

### Missing semantic constraints in reversible/specialized interpreters

Usihakiki memory safety pekee; pia hakiki **semantic rules** ambazo proof inakusudiwa kutekeleza.

Kwa instruction sets za reversible/quantum-like, hakikisha operands ambazo lazima ziwe tofauti zimewekewa constraints ili ziwe tofauti. Operation kama Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
inakuwa si salama ikiwa guest hatakataa:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Katika hali hiyo, transition hugeuka kuwa:
```text
q = q ^ (q & q) = 0
```
Hii huunda **deterministic reset primitive**, na kuvunja dhana za reversibility huku ikiwezesha computations zisizokusudiwa kwa gharama ndogo. Katika proof systems zinazothibitisha matumizi ya rasilimali, hili linaweza kuwawezesha attackers kutimiza checks za utendaji huku wakipita cost model ambayo verifier anaamini inalazimishwa.

### Mambo ya ku-test katika ZK systems

- Fuzz guest parsers zote kwa malformed witness/private-input encodings.
- Thibitisha enum range validation kabla ya opcode dispatch.
- Ongeza semantic checks za operand aliasing na aina nyingine za invalid instruction forms.
- Linganisha counters zilizoripotiwa/public na independent reference implementation.
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

## Marejeo

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key Explained - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [What are multi-signature transactions? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas and fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
