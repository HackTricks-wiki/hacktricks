# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** blockchain पर ऐसे programs होते हैं जो कुछ conditions पूरी होने पर execute होते हैं, और intermediaries के बिना agreement executions को automate करते हैं।
- **Decentralized Applications (dApps)** smart contracts पर आधारित होते हैं, जिनमें एक user-friendly front-end और एक transparent, auditable back-end होता है।
- **Tokens & Coins** में coins digital money के रूप में काम करते हैं, जबकि tokens specific contexts में value या ownership represent करते हैं।
- **Utility Tokens** services तक access देते हैं, और **Security Tokens** asset ownership दर्शाते हैं।
- **DeFi** का मतलब Decentralized Finance है, जो central authorities के बिना financial services देता है।
- **DEX** और **DAOs** का मतलब क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations है।

## Consensus Mechanisms

Consensus mechanisms blockchain पर secure और agreed transaction validations सुनिश्चित करते हैं:

- **Proof of Work (PoW)** transaction verification के लिए computational power पर depend करता है।
- **Proof of Stake (PoS)** validators से एक निश्चित amount of tokens hold करने की मांग करता है, जिससे PoW की तुलना में energy consumption कम होती है।

## Bitcoin Essentials

### Transactions

Bitcoin transactions addresses के बीच funds transfer करने से संबंधित होते हैं। Transactions digital signatures के माध्यम से validated होती हैं, जिससे यह सुनिश्चित होता है कि केवल private key का owner ही transfers initiate कर सकता है।

#### Key Components:

- **Multisignature Transactions** transaction को authorize करने के लिए multiple signatures की आवश्यकता होती है।
- Transactions में **inputs** (funds का source), **outputs** (destination), **fees** (miners को paid), और **scripts** (transaction rules) शामिल होते हैं।

### Lightning Network

यह channels के भीतर multiple transactions की अनुमति देकर Bitcoin की scalability बढ़ाने का लक्ष्य रखता है, और केवल final state को blockchain पर broadcast करता है।

## Bitcoin Privacy Concerns

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks transaction patterns का exploit करते हैं। **Mixers** और **CoinJoin** जैसी strategies users के बीच transaction links को obscure करके anonymity बेहतर करती हैं।

## Acquiring Bitcoins Anonymously

Methods में cash trades, mining, और mixers का उपयोग शामिल है। **CoinJoin** traceability को complicate करने के लिए multiple transactions को mix करता है, जबकि **PayJoin** अधिक privacy के लिए CoinJoins को regular transactions की तरह disguise करता है।

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin की दुनिया में, transactions की privacy और users की anonymity अक्सर चिंता का विषय होती है। यहां several common methods का एक simplified overview है, जिनके माध्यम से attackers Bitcoin privacy compromise कर सकते हैं।

## **Common Input Ownership Assumption**

आमतौर पर अलग-अलग users के inputs को एक single transaction में combine करना rare होता है, क्योंकि इसमें complexity होती है। इसलिए, **same transaction में मौजूद दो input addresses को अक्सर same owner का माना जाता है**।

## **UTXO Change Address Detection**

एक UTXO, या **Unspent Transaction Output**, को transaction में पूरी तरह spend करना होता है। यदि इसका केवल एक हिस्सा दूसरे address पर भेजा जाता है, तो बाकी हिस्सा एक नए change address में जाता है। Observers यह मान सकते हैं कि यह नया address sender का है, जिससे privacy compromise होती है।

### Example

इसको mitigate करने के लिए, mixing services या multiple addresses का उपयोग ownership को obscure करने में मदद कर सकता है।

## **Social Networks & Forums Exposure**

Users कभी-कभी अपने Bitcoin addresses online share करते हैं, जिससे **address को उसके owner से link करना easy** हो जाता है।

## **Transaction Graph Analysis**

Transactions को graphs के रूप में visualize किया जा सकता है, जिससे funds के flow के आधार पर users के बीच संभावित connections reveal होते हैं।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic multiple inputs और outputs वाली transactions का analyze करके यह guess करने पर आधारित है कि कौन सा output change है जो sender को वापस जाता है।

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
यदि अधिक inputs जोड़ने से change output किसी भी single input से बड़ा हो जाता है, तो यह heuristic को भ्रमित कर सकता है।

## **Forced Address Reuse**

Attackers पहले से उपयोग किए गए addresses पर थोड़ी मात्रा भेज सकते हैं, यह उम्मीद करते हुए कि recipient भविष्य के transactions में इन्हें अन्य inputs के साथ combine करेगा, जिससे addresses आपस में link हो जाएंगे।

### Correct Wallet Behavior

Wallets को पहले से उपयोग किए गए, empty addresses पर प्राप्त coins का उपयोग करने से बचना चाहिए ताकि इस privacy leak को रोका जा सके।

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** जिन transactions में change नहीं होता, वे अक्सर उसी user के स्वामित्व वाले दो addresses के बीच होती हैं।
- **Round Numbers:** transaction में round number का होना यह संकेत देता है कि यह payment है, और non-round output संभवतः change है।
- **Wallet Fingerprinting:** अलग-अलग wallets में transaction creation के unique patterns होते हैं, जिससे analysts इस्तेमाल किए गए software और संभावित change address की पहचान कर सकते हैं।
- **Amount & Timing Correlations:** transaction times या amounts का disclosure transactions को traceable बना सकता है।

## **Traffic Analysis**

network traffic की monitoring करके, attackers संभावित रूप से transactions या blocks को IP addresses से link कर सकते हैं, जिससे user privacy compromise होती है। यह खास तौर पर तब सच है जब कोई entity कई Bitcoin nodes operate करती है, जिससे transactions को monitor करने की उसकी क्षमता बढ़ जाती है।

## More

privacy attacks और defenses की एक comprehensive list के लिए, [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) देखें।

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: cash के माध्यम से bitcoin प्राप्त करना।
- **Cash Alternatives**: gift cards खरीदना और उन्हें online bitcoin के बदले exchange करना।
- **Mining**: bitcoins earn करने का सबसे private method mining है, खासकर जब इसे अकेले किया जाए क्योंकि mining pools miner का IP address जान सकते हैं। [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: सैद्धांतिक रूप से, bitcoin चुराना इसे anonymously प्राप्त करने का एक और तरीका हो सकता है, हालांकि यह illegal है और recommended नहीं है।

## Mixing Services

एक mixing service का उपयोग करके, user **send bitcoins** कर सकता है और बदले में **different bitcoins** प्राप्त कर सकता है, जिससे original owner का पता लगाना मुश्किल हो जाता है। फिर भी, इसके लिए service पर भरोसा करना पड़ता है कि वह logs नहीं रखेगी और वास्तव में bitcoins वापस करेगी। Alternative mixing options में Bitcoin casinos शामिल हैं।

## CoinJoin

**CoinJoin** अलग-अलग users के multiple transactions को एक में merge करता है, जिससे inputs को outputs से match करने की कोशिश करने वाले किसी भी व्यक्ति के लिए process जटिल हो जाती है। इसकी effectiveness के बावजूद, unique input और output sizes वाले transactions फिर भी trace किए जा सकते हैं।

CoinJoin का उपयोग करने वाले example transactions में `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` शामिल हैं।

अधिक जानकारी के लिए, [CoinJoin](https://coinjoin.io/en) देखें। Ethereum पर एक समान service के लिए, [Tornado Cash](https://tornado.cash) देखें, जो miners के funds के साथ transactions को anonymize करता है।

## PayJoin

CoinJoin का एक variant, **PayJoin** (या P2EP), दो parties (जैसे, एक customer और एक merchant) के बीच transaction को regular transaction की तरह disguise करता है, बिना CoinJoin की खास समान outputs वाली विशेषता के। इससे इसे detect करना बेहद मुश्किल हो जाता है और transaction surveillance entities द्वारा इस्तेमाल किए जाने वाले common-input-ownership heuristic को invalidate कर सकता है।
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
ऊपर जैसी Transactions PayJoin हो सकती हैं, जो standard bitcoin transactions से अलग न दिखते हुए privacy बढ़ाती हैं।

**PayJoin का उपयोग traditional surveillance methods को काफी हद तक बाधित कर सकता है**, जिससे यह transactional privacy की खोज में एक promising development बन जाता है।

# Cryptocurrencies में Privacy के लिए Best Practices

## **Wallet Synchronization Techniques**

Privacy और security बनाए रखने के लिए, wallets को blockchain के साथ synchronize करना crucial है। दो methods अलग दिखती हैं:

- **Full node**: पूरी blockchain डाउनलोड करके, full node maximum privacy सुनिश्चित करता है। सभी transactions जो कभी भी हुई हैं, locally stored रहती हैं, जिससे adversaries के लिए यह पहचानना impossible हो जाता है कि user किन transactions या addresses में interested है।
- **Client-side block filtering**: इस method में blockchain के हर block के लिए filters बनाना शामिल है, जिससे wallets बिना specific interests को network observers के सामने expose किए relevant transactions identify कर सकते हैं। Lightweight wallets इन filters को डाउनलोड करती हैं, और केवल तब full blocks fetch करती हैं जब user के addresses के साथ match मिलता है।

## **Anonymity के लिए Tor का उपयोग**

चूंकि Bitcoin peer-to-peer network पर operate करता है, network के साथ interact करते समय अपनी IP address को mask करने और privacy बढ़ाने के लिए Tor का उपयोग recommended है।

## **Address Reuse से बचना**

Privacy सुरक्षित रखने के लिए, हर transaction के लिए नया address उपयोग करना vital है। Addresses reuse करने से transactions को same entity से link करके privacy compromise हो सकती है। Modern wallets अपने design के through address reuse को discourage करती हैं।

## **Transaction Privacy के लिए Strategies**

- **Multiple transactions**: एक payment को कई transactions में split करने से transaction amount अस्पष्ट हो सकता है, जिससे privacy attacks thwart होते हैं।
- **Change avoidance**: ऐसी transactions चुनना जिनमें change outputs की जरूरत न हो, change detection methods को बाधित करके privacy बढ़ाता है।
- **Multiple change outputs**: अगर change से बचना feasible न हो, तो multiple change outputs generate करना फिर भी privacy improve कर सकता है।

# **Monero: Anonymity का Beacon**

Monero digital transactions में absolute anonymity की जरूरत को address करता है, और privacy के लिए एक high standard set करता है।

# **Ethereum: Gas and Transactions**

## **Gas को समझना**

Gas Ethereum पर operations execute करने के लिए required computational effort को मापता है, जिसकी pricing **gwei** में होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) वाली transaction में gas limit और base fee शामिल होते हैं, साथ में miners को incentivize करने के लिए tip भी होती है। Users max fee set कर सकते हैं ताकि वे overpay न करें, और excess refunded हो जाता है।

## **Transactions Execute करना**

Ethereum में transactions में एक sender और एक recipient होता है, जो user या smart contract addresses दोनों हो सकते हैं। इनके लिए fee चाहिए और इन्हें mined होना चाहिए। Transaction में essential information में recipient, sender's signature, value, optional data, gas limit, और fees शामिल हैं। खास बात यह है कि sender's address signature से deduced होता है, इसलिए transaction data में इसे शामिल करने की जरूरत नहीं होती।

ये practices और mechanisms उन सभी के लिए foundational हैं जो privacy और security को प्राथमिकता देते हुए cryptocurrencies का उपयोग करना चाहते हैं।

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

जब कोई prover **zkVM** या application-specific proof circuit का उपयोग किसी claim को attest करने के लिए करता है, तो verifier केवल यह सीख रहा होता है कि **guest program executed as written**। अगर guest में **unsafe deserialization**, **undefined behavior**, या **missing semantic constraints** हों, तो एक malicious prover ऐसा proof बना सकता है जो verify हो जाए, जबकि **public metrics या claimed invariant false** हों।

### Proof guests के अंदर unsafe deserialization

- Private witness/circuit bytes को **untrusted attacker input** मानें, भले ही वे proof द्वारा hidden हों।
- उन्हें unchecked helpers जैसे `rkyv::access_unchecked` से deserialize करने से बचें, जब तक bytes पहले out-of-band validate न की गई हों।
- Untrusted serialized data से loaded enum discriminants, relative pointers, lengths, और indexes को control flow या memory access को प्रभावित करने से पहले validate करना चाहिए।

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
यदि कोई field जैसे `op.kind` एक enum है और attacker एक **out-of-range discriminant** inject कर सकता है, तो उस value पर हर downstream `match` suspicious बन जाता है।

### Jump-table / UB counter bypass

यदि Rust किसी बड़े `match` को **jump table** में lower करता है, तो invalid enum discriminant **undefined control flow** पैदा कर सकता है। एक खतरनाक pattern यह है:

1. एक `match` **security-critical counters/constraints** अपडेट करता है।
2. दूसरा `match` **real instruction semantics** execute करता है।
3. out-of-range discriminant पहले jump table को bypass करके आगे index करता है और दूसरे वाले से जुड़े code में land करता है।

Result: operation फिर भी execute होती है, लेकिन accounting path skip हो जाता है। zkVM में इससे ऐसे proofs forge हो सकते हैं जो impossible metrics report करें, जैसे fewer gates, fewer expensive operations, या other falsified bounded resources।

Review checklist:

- attacker-controlled enums देखें जो witness/private input से deserialized हों।
- same opcode/kind field पर repeated `match` statements inspect करें।
- `unsafe` + unchecked deserialization + large opcode dispatch को high-risk combination मानें।
- ज़रूरत पड़ने पर emitted binary reverse engineer करें; jump-table layout source से ज़्यादा important हो सकता है।

### Reversible/specialized interpreters में missing semantic constraints

सिर्फ memory safety validate न करें; proof जिन **semantic rules** को enforce करना चाहता है, उन्हें भी validate करें।

Reversible/quantum-like instruction sets के लिए, सुनिश्चित करें कि जिन operands का distinct होना ज़रूरी है, वे सच में distinct होने के लिए constrained हों। एक Toffoli/CCX-like operation जो इस तरह implement की गई हो:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
यदि guest अस्वीकार नहीं करता है, तो यह unsafe हो जाता है:
```text
op.q_control1 == op.q_control2 == op.q_target
```
उस स्थिति में ट्रांज़िशन इस में collapse हो जाता है:
```text
q = q ^ (q & q) = 0
```
यह एक **deterministic reset primitive** बनाता है, reversibility assumptions को तोड़ता है, और cheaper non-intended computations को सक्षम करता है। ऐसे proof systems में जो resource usage को attest करते हैं, इससे attackers functional checks pass कर सकते हैं जबकि verifier जिस cost model को enforce मान रहा है, उसे bypass कर सकते हैं।

### ZK systems में क्या test करना है

- सभी guest parsers को malformed witness/private-input encodings के साथ fuzz करें।
- opcode dispatch से पहले enum range validation assert करें।
- operand aliasing और अन्य invalid instruction forms के लिए semantic checks जोड़ें।
- reported/public counters की तुलना एक independent reference implementation से करें।
- याद रखें कि एक valid proof भी **गलत statement** prove कर सकता है अगर guest program buggy हो।

## DeFi/AMM Exploitation

अगर आप DEXes और AMMs की practical exploitation पर research कर रहे हैं (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

उन multi-asset weighted pools के लिए जो virtual balances cache करते हैं और `supply == 0` होने पर poison किए जा सकते हैं, अध्ययन करें:

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
