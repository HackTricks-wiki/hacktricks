# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** ni programu zinazotekelezwa kwenye blockchain wakati masharti fulani yametimizwa, zikifanya uwekaji otomatiki wa utekelezaji wa makubaliano bila wapatanishi.
- **Decentralized Applications (dApps)** hujengwa juu ya smart contracts, zikiwa na front-end rafiki kwa mtumiaji na back-end iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** hutofautisha ambapo coins hutumika kama pesa za kidijitali, ilhali tokens huwakilisha thamani au umiliki katika muktadha mahususi.
- **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa asset.
- **DeFi** ni kifupi cha Decentralized Finance, ikitoa huduma za kifedha bila mamlaka ya kati.
- **DEX** na **DAOs** hurejelea Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Consensus Mechanisms

Consensus mechanisms huhakikisha uthibitishaji salama na uliokubaliwa wa miamala kwenye blockchain:

- **Proof of Work (PoW)** hutegemea nguvu za kompyuta kwa uthibitishaji wa miamala.
- **Proof of Stake (PoS)** huhitaji validators kumiliki kiasi fulani cha tokens, na kupunguza matumizi ya nishati ikilinganishwa na PoW.

## Bitcoin Essentials

### Transactions

Bitcoin transactions huhusisha kuhamisha fedha kati ya addresses. Transactions huthibitishwa kupitia digital signatures, kuhakikisha ni mmiliki pekee wa private key anayeweza kuanzisha uhamisho.

#### Key Components:

- **Multisignature Transactions** huhitaji signatures nyingi ili kuidhinisha transaction.
- Transactions hujumuisha **inputs** (chanzo cha fedha), **outputs** (lengwa), **fees** (hulipwa kwa miners), na **scripts** (kanuni za transaction).

### Lightning Network

Lengo ni kuboresha scalability ya Bitcoin kwa kuruhusu transactions nyingi ndani ya channel, na kutangaza tu hali ya mwisho kwenye blockchain.

## Bitcoin Privacy Concerns

Mashambulizi ya privacy, kama **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya transactions. Mbinu kama **Mixers** na **CoinJoin** huboresha anonymity kwa kuficha uhusiano wa transactions kati ya users.

## Acquiring Bitcoins Anonymously

Mbinu ni pamoja na cash trades, mining, na kutumia mixers. **CoinJoin** huchanganya transactions nyingi ili kufanya traceability kuwa ngumu, huku **PayJoin** ikijificha kama CoinJoins za kawaida kwa privacy iliyoongezeka.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Katika ulimwengu wa Bitcoin, privacy ya transactions na anonymity ya users mara nyingi ni mada za wasiwasi. Hapa kuna muhtasari uliorahisishwa wa mbinu kadhaa za kawaida ambazo attackers hutumia kuvunja privacy ya Bitcoin.

## **Common Input Ownership Assumption**

Kwa kawaida ni nadra sana inputs kutoka kwa users tofauti kuunganishwa katika transaction moja kutokana na ugumu uliopo. Hivyo, **addresses mbili za input katika transaction moja mara nyingi hudhaniwa kuwa za mmiliki mmoja**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike kikamilifu katika transaction. Iwapo sehemu tu yake inatumwa kwa address nyingine, salio huenda kwenye new change address. Waangalizi wanaweza kudhani address hii mpya ni ya mtumaji, hivyo kuvunja privacy.

### Example

Ili kupunguza hili, huduma za mixing au kutumia addresses nyingi kunaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Wakati mwingine users hushiriki Bitcoin addresses zao mtandaoni, jambo linalofanya iwe **rahisi kuunganisha address na mmiliki wake**.

## **Transaction Graph Analysis**

Transactions zinaweza kuonyeshwa kama graphs, zikifichua uhusiano unaowezekana kati ya users kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii inategemea kuchanganua transactions zenye inputs na outputs nyingi ili kukisia ni output gani ni change inayorudi kwa mtumaji.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ikiongezeke, ikiwa kuongeza pembejeo zaidi kunafanya change output iwe kubwa kuliko pembejeo yoyote moja, inaweza kuchanganya heuristic.

## **Forced Address Reuse**

Washambuliaji wanaweza kutuma kiasi kidogo kwa addresses zilizotumiwa hapo awali, wakitarajia mpokeaji akiwaunganishe hizi na inputs nyingine katika transactions za baadaye, hivyo kuunganisha addresses pamoja.

### Correct Wallet Behavior

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye addresses zilizotumika tayari, zilizo tupu, ili kuzuia privacy leak hii.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions bila change huenda ni kati ya addresses mbili zinazomilikiwa na user yuleyule.
- **Round Numbers:** Namba ya mviringo katika transaction huashiria ni payment, na output isiyo ya mviringo huenda ndiyo change.
- **Wallet Fingerprinting:** Wallets tofauti zina unique transaction creation patterns, zikiruhusu analysts kutambua software iliyotumika na uwezekano wa change address.
- **Amount & Timing Correlations:** Kufichua nyakati za transaction au amounts kunaweza kufanya transactions zifuatiliwe.

## **Traffic Analysis**

Kwa kufuatilia network traffic, washambuliaji wanaweza kwa uwezekano kuunganisha transactions au blocks na IP addresses, na kuhatarisha privacy ya user. Hii ni kweli hasa ikiwa entity inaendesha Bitcoin nodes nyingi, na kuongeza uwezo wake wa kufuatilia transactions.

## More

Kwa orodha kamili ya privacy attacks na defenses, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Kupata bitcoin kupitia cash.
- **Cash Alternatives**: Kununua gift cards na kuzibadilisha online kwa bitcoin.
- **Mining**: Njia ya faragha zaidi ya kupata bitcoins ni kupitia mining, hasa ikifanywa peke yako kwa sababu mining pools zinaweza kujua IP address ya miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Kitaalamu, kuiba bitcoin inaweza kuwa njia nyingine ya kuipata anonymously, ingawa ni kinyume cha sheria na haipendekezwi.

## Mixing Services

Kwa kutumia mixing service, user anaweza **kutuma bitcoins** na kupokea **different bitcoins** kwa return, jambo linalofanya kufuatilia owner wa awali kuwa vigumu. Hata hivyo, hili linahitaji kuamini service isiweke logs na kweli irudishe bitcoins. Chaguzi mbadala za mixing ni pamoja na Bitcoin casinos.

## CoinJoin

**CoinJoin** huunganisha transactions nyingi kutoka kwa users tofauti kuwa moja, na kufanya mchakato wa yeyote anayejaribu kulinganisha inputs na outputs kuwa mgumu zaidi. Licha ya ufanisi wake, transactions zenye unique input na output sizes bado zinaweza kufuatiliwa.

Mfano wa transactions ambazo huenda zilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa taarifa zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa service inayofanana kwenye Ethereum, angalia [Tornado Cash](https://tornado.cash), ambayo inafanya transactions kuwa anonymous kwa funds kutoka kwa miners.

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), huficha transaction kati ya pande mbili (kwa mfano, customer na merchant) kama transaction ya kawaida, bila outputs zinazofanana kwa uwazi ambazo ni sifa ya CoinJoin. Hii inafanya iwe vigumu sana kugundua na inaweza kubatilisha common-input-ownership heuristic inayotumiwa na entities za ufuatiliaji wa transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika kutafuta faragha ya miamala.

# Mbinu Bora za Faragha katika Cryptocurrencies

## **Mbinu za Usawazishaji wa Wallet**

Ili kudumisha faragha na usalama, kusawazisha wallets na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya juu zaidi. Miamala yote iliyowahi kufanywa huhifadhiwa ndani ya kifaa, jambo linalofanya isiwezekane kwa washambuliaji kubaini ni miamala au anwani zipi mtumiaji anavutiwa nazo.
- **Client-side block filtering**: Mbinu hii inahusisha kuunda filters kwa kila block katika blockchain, ikiwaruhusu wallets kutambua miamala inayohusiana bila kufichua maslahi mahususi kwa wachunguzi wa mtandao. Lightweight wallets hupakua filters hizi, na huchukua full blocks tu inapopatikana match na anwani za mtumiaji.

## **Kutumia Tor kwa Kutokujulikana**

Kwa kuwa Bitcoin inafanya kazi kwenye peer-to-peer network, kutumia Tor kunapendekezwa ili kuficha IP address yako, na kuongeza faragha unapoingiliana na mtandao.

## **Kuzuia Matumizi Tena ya Address**

Ili kulinda faragha, ni muhimu kutumia address mpya kwa kila transaction. Kutumia tena addresses kunaweza kuhatarisha faragha kwa kuunganisha transactions na huluki ileile. Modern wallets hukatisha matumizi ya address reuse kupitia muundo wao.

## **Mikakati ya Faragha ya Transaction**

- **Multiple transactions**: Kugawa malipo katika transactions kadhaa kunaweza kuficha kiasi cha transaction, na kuzuia attacks za faragha.
- **Change avoidance**: Kuchagua transactions zisizohitaji change outputs huongeza faragha kwa kuvuruga mbinu za kugundua change.
- **Multiple change outputs**: Iwapo kuepuka change si rahisi, kuzalisha multiple change outputs bado kunaweza kuboresha faragha.

# **Monero: Mwanga wa Kutokujulikana**

Monero inashughulikia hitaji la kutokujulikana kabisa katika miamala ya kidijitali, ikiweka kiwango cha juu cha faragha.

# **Ethereum: Gas na Transactions**

## **Kuelewa Gas**

Gas hupima juhudi za kompyuta zinazohitajika kutekeleza operations kwenye Ethereum, na hupangwa kwa **gwei**. Kwa mfano, transaction inayogharimu 2,310,000 gwei (au 0.00231 ETH) inahusisha gas limit na base fee, pamoja na tip ya kuhamasisha miners. Watumiaji wanaweza kuweka max fee ili kuhakikisha hawalipi kupita kiasi, na ziada hurudishwa.

## **Kutekeleza Transactions**

Transactions katika Ethereum huhusisha sender na recipient, ambao wanaweza kuwa user au smart contract addresses. Zinahitaji fee na lazima zimined. Taarifa muhimu katika transaction ni pamoja na recipient, sender's signature, value, optional data, gas limit, na fees. Muhimu zaidi, sender's address hupatikana kutoka kwenye signature, hivyo kuondoa hitaji la kuiweka ndani ya transaction data.

Mbinu hizi na mechanisms hizi ni msingi kwa yeyote anayetaka kushiriki katika cryptocurrencies huku akiweka kipaumbele faragha na usalama.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

When a prover uses a **zkVM** or an application-specific proof circuit to attest a claim, the verifier is only learning that the **guest program executed as written**. If the guest contains **unsafe deserialization**, **undefined behavior**, or **missing semantic constraints**, a malicious prover may generate a proof that verifies while the **public metrics or claimed invariant are false**.

### Unsafe deserialization inside proof guests

- Treat private witness/circuit bytes as **untrusted attacker input** even if they are hidden by the proof.
- Avoid deserializing them with unchecked helpers such as `rkyv::access_unchecked` unless the bytes were already validated out-of-band.
- Enum discriminants, relative pointers, lengths, and indexes loaded from untrusted serialized data must be validated before they influence control flow or memory access.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Jika field seperti `op.kind` adalah enum dan penyerang dapat menyisipkan **out-of-range discriminant**, setiap `match` lanjutan pada nilai itu menjadi mencurigakan.

### Jump-table / UB counter bypass

Jika Rust menurunkan `match` besar menjadi **jump table**, discriminant enum yang tidak valid dapat menghasilkan **undefined control flow**. Pola berbahaya adalah:

1. Satu `match` memperbarui **security-critical counters/constraints**.
2. `match` kedua menjalankan **real instruction semantics**.
3. Discriminant `out-of-range` mengindeks melewati jump table pertama dan mendarat di kode yang terkait dengan yang kedua.

Hasil: operasi tetap dieksekusi, tetapi jalur akuntansi dilewati. Dalam zkVM ini dapat memalsukan proofs yang melaporkan metrik mustahil seperti jumlah gates yang lebih sedikit, lebih sedikit expensive operations, atau bounded resources palsu lainnya.

Daftar pemeriksaan:

- Cari enum yang dikendalikan attacker dan dideserialisasi dari witness/private input.
- Periksa pernyataan `match` berulang pada field opcode/kind yang sama.
- Anggap kombinasi `unsafe` + unchecked deserialization + dispatch opcode besar sebagai kombinasi berisiko tinggi.
- Reverse engineer binary yang dihasilkan bila perlu; layout jump-table bisa lebih penting daripada source.

### Missing semantic constraints in reversible/specialized interpreters

Jangan hanya memvalidasi memory safety; validasi juga aturan **semantic** yang hendak ditegakkan oleh proof.

Untuk instruction set reversible/quantum-like, pastikan operand yang harus berbeda memang benar-benar dikonstrain agar berbeda. Sebuah operasi Toffoli/CCX-like yang diimplementasikan sebagai:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
inakuwa si salama ikiwa mgeni hakatali:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Katika hali hiyo mpito huanguka kuwa:
```text
q = q ^ (q & q) = 0
```
Hii huunda **deterministic reset primitive**, ikivunja assumptions za reversibility na kuwezesha cheaper non-intended computations. Katika proof systems zinazothibitisha matumizi ya resources, hii inaweza kuruhusu attackers kutimiza functional checks huku wakipita cost model ambayo verifier anaamini inatekelezwa.

### Nini cha kujaribu katika ZK systems

- Fuzz parsers zote za guest na malformed witness/private-input encodings.
- Thibitisha enum range validation kabla ya opcode dispatch.
- Ongeza semantic checks kwa operand aliasing na aina nyingine za invalid instruction forms.
- Linganisha reported/public counters dhidi ya independent reference implementation.
- Kumbuka kwamba valid proof bado inaweza kuthibitisha **wrong statement** ikiwa guest program ina bug.

## DeFi/AMM Exploitation

Ukichunguza practical exploitation ya DEXes na AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa multi-asset weighted pools zinazohifadhi virtual balances na zinaweza kuharibiwa wakati `supply == 0`, jifunze:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
