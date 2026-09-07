# Blockchain and暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときに blockchain 上で実行されるプログラムとして定義され、仲介者なしで合意事項の履行を自動化します。
- **Decentralized Applications (dApps)** は smart contracts を基盤として構築され、使いやすいフロントエンドと、透明性があり監査可能なバックエンドを備えています。
- **Tokens & Coins** は、coins がデジタルマネーとして機能する一方、tokens は特定のコンテキストにおける価値や所有権を表すという点で異なります。
- **Utility Tokens** はサービスへのアクセスを与え、**Security Tokens** は資産の所有権を示します。
- **DeFi** は Decentralized Finance の略で、中央権威なしに金融サービスを提供します。
- **DEX** と **DAOs** は、それぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## Consensus Mechanisms

Consensus mechanisms は blockchain 上で安全かつ合意されたトランザクション検証を確実にします。

- **Proof of Work (PoW)** は、トランザクションの検証に計算能力を利用します。
- **Proof of Stake (PoS)** は、validators に一定量の tokens の保有を要求し、PoW と比較してエネルギー消費を削減します。<sup>[[1]](#references)</sup>

## Bitcoin の基本

### Transactions

Bitcoin transactions では、addresses 間で資金を移転します。Transactions は digital signatures によって検証され、private key の所有者だけが移転を開始できることを保証します。<sup>[[2]](#references)</sup>

#### 主な構成要素：

- **Multisignature Transactions** は、transaction を承認するために複数の signatures を必要とします。<sup>[[3]](#references)</sup>
- Transactions は、**inputs**（資金源）、**outputs**（送金先）、**fees**（miners に支払われる手数料）、**scripts**（transaction のルール）で構成されます。

### Lightning Network

複数の transactions を channel 内で実行し、最終状態のみを blockchain にブロードキャストすることで、Bitcoin の scalability を向上させることを目的とします。

## Bitcoin のプライバシーに関する懸念

**Common Input Ownership** や **UTXO Change Address Detection** などの privacy attacks は、transaction patterns を悪用します。**Mixers** や **CoinJoin** などの strategies は、users 間の transaction links を隠すことで anonymity を向上させます。

## Bitcoin を匿名で取得する

方法には、現金取引、mining、mixers の利用などがあります。**CoinJoin** は複数の transactions を混合して追跡を困難にし、**PayJoin** は CoinJoins を通常の transactions に見せかけて、より高い privacy を実現します。

# Bitcoin Privacy Attacks の概要

Bitcoin の世界では、transactions の privacy と users の anonymity はしばしば懸念事項となります。以下では、attackers が Bitcoin の privacy を侵害する一般的な方法を簡単に説明します。<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

複雑さのため、異なる users の inputs が 1 つの transaction にまとめられることは一般的にまれです。そのため、**同じ transaction 内の 2 つの input addresses は、同じ owner に属すると想定されることが多くなります**。

## **UTXO Change Address Detection**

UTXO、つまり **Unspent Transaction Output** は、transaction 内で全額を使用する必要があります。その一部だけが別の address に送られた場合、残りは新しい change address に送られます。Observers は、この新しい address が sender に属すると推測できるため、privacy が侵害されます。

### 例

これを軽減するには、mixing services の利用や複数の addresses の使用によって ownership を分かりにくくできます。

## **Social Networks & Forums Exposure**

Users が online で Bitcoin addresses を共有することがあり、**その address と owner を簡単に結び付けられる**ようになります。

## **Transaction Graph Analysis**

Transactions は graphs として可視化でき、資金の流れに基づいて users 間の潜在的なつながりを明らかにします。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

この heuristic は、複数の inputs と outputs を持つ transactions を分析し、どの output が sender に戻される change なのかを推測するものです。

### 例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
入力を追加することで、変更出力が単一の入力よりも大きくなる場合、heuristicを混乱させる可能性があります。

## **Forced Address Reuse**

攻撃者は、過去に使用されたアドレスに少額を送信し、受取人が将来のトランザクションでそれらを他の入力と統合することで、アドレス同士がリンクされることを期待する場合があります。

### Correct Wallet Behavior

Walletは、既に使用済みで残高が空のアドレスで受け取ったコインを使用しないようにして、このprivacy leakを防ぐべきです。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** 変更がないトランザクションは、同じユーザーが所有する2つのアドレス間で行われた可能性が高いです。
- **Round Numbers:** トランザクション内の切りのよい金額は支払いであることを示唆し、切りのよくない出力は変更である可能性が高いです。
- **Wallet Fingerprinting:** Walletごとに固有のトランザクション作成パターンがあるため、analystは使用されたソフトウェアを特定し、変更アドレスを推測できる可能性があります。
- **Amount & Timing Correlations:** トランザクションの時刻や金額を開示すると、トランザクションがtraceableになる可能性があります。

## **Traffic Analysis**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックをIPアドレスにリンクし、ユーザーのprivacyを侵害できる可能性があります。これは、あるentityが多数のBitcoin nodeを運用している場合に特に当てはまり、トランザクションを監視する能力が高まります。

## More

privacy攻撃と防御の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)を参照してください。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 現金でbitcoinを入手する。
- **Cash Alternatives**: gift cardを購入し、オンラインでbitcoinと交換する。
- **Mining**: bitcoinを得る最もprivateな方法はMiningです。特にsoloで行う場合はprivate性が高くなります。これは、mining poolがminerのIPアドレスを把握する可能性があるためです。[Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論上は、bitcoinを盗むことも匿名で入手する方法の一つですが、違法であり推奨されません。

## Mixing Services

mixing serviceを使用すると、ユーザーは**bitcoinを送信**し、**異なるbitcoinを受け取る**ことができるため、元の所有者のtraceを困難にできます。ただし、これはserviceがlogsを保存せず、実際にbitcoinを返すことを信頼する必要があります。代替のmixing手段にはBitcoin casinoがあります。

## CoinJoin

**CoinJoin**は、異なるユーザーによる複数のトランザクションを1つに統合し、入力と出力を照合しようとする者にとって、その処理を複雑にします。効果的ではあるものの、入力と出力のサイズがuniqueなトランザクションは、依然としてtraceされる可能性があります。

CoinJoinが使用された可能性のあるトランザクションの例には、`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a`および`85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`があります。

詳細については、[CoinJoin](https://coinjoin.io/en)を参照してください。depositと後のwithdrawalを分離するEthereum smart-contract mixerについては、[Tornado Cash](https://tornado.cash)を参照してください。

## PayJoin

CoinJoinのvariantである**PayJoin**（またはP2EP）は、2者（例：customerとmerchant）間のトランザクションを、CoinJoinに特徴的な同額の出力を持たない通常のトランザクションとして偽装します。これにより検出が極めて困難になり、トランザクション監視entityが使用するcommon-input-ownership heuristicが無効になる可能性があります。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
上記のようなトランザクションはPayJoinである可能性があり、標準的なbitcoinトランザクションと区別できないままプライバシーを高められます。

**PayJoinの利用は従来の監視手法を大きく妨げる可能性があり**、トランザクションプライバシーの実現に向けた有望な発展です。

# Cryptocurrencyのプライバシーに関するBest Practices

## **Walletの同期技術**

プライバシーとセキュリティを維持するには、Walletをblockchainと同期することが重要です。特に次の2つの方法があります。

- **Full node**: blockchain全体をダウンロードすることで、Full nodeは最大限のプライバシーを確保します。これまでに行われたすべてのトランザクションがローカルに保存されるため、攻撃者がユーザーの関心対象であるトランザクションやアドレスを特定することはできません。
- **Client-side block filtering**: この方法では、blockchain内のすべてのblockに対するfilterを作成し、ネットワーク監視者に具体的な関心対象を公開せずに、Walletが関連するトランザクションを特定できるようにします。軽量Walletはこれらのfilterをダウンロードし、ユーザーのアドレスとの一致が見つかった場合にのみfull blockを取得します。

## **匿名性のためのTorの利用**

Bitcoinはpeer-to-peer network上で動作するため、Torを使用してIP addressを隠し、networkとのやり取りにおけるプライバシーを高めることが推奨されます。

## **Addressの再利用防止**

プライバシーを守るには、トランザクションごとに新しいaddressを使用することが重要です。addressを再利用すると、トランザクションが同一のエンティティに関連付けられ、プライバシーが侵害される可能性があります。最新のWalletは、その設計によってaddressの再利用を避けるようになっています。

## **トランザクションプライバシーのためのStrategies**

- **Multiple transactions**: 支払いを複数のトランザクションに分割すると、トランザクション金額を分かりにくくし、プライバシー攻撃を阻止できます。
- **Change avoidance**: change outputを必要としないトランザクションを選択すると、changeの検出手法を妨害してプライバシーを高められます。
- **Multiple change outputs**: changeを避けられない場合でも、複数のchange outputを生成することでプライバシーを改善できます。

# **Monero: 匿名性の象徴**

Moneroは、トランザクションプライバシーを優先するように設計されています。

# **Ethereum: Gasとトランザクション**

## **Gasの理解**

GasはEthereum上で操作を実行するために必要な計算量を表し、**gwei**で価格が設定されます。たとえば、2,310,000 gwei（または0.00231 ETH）のコストがかかるトランザクションには、Gas limitとbase feeが含まれ、validatorによる取り込みを促すためのpriority feeも設定されます。ユーザーはmax feeを設定して過払いを防ぐことができ、余った分は返金されます。<sup>[[5]](#references)</sup>

## **トランザクションの実行**

Ethereumのトランザクションにはsenderとrecipientが含まれ、それぞれuser addressまたはsmart contract addressにできます。トランザクションにはfeeが必要であり、blockに含められなければなりません。トランザクションに含まれる重要な情報は、recipient、senderのsignature、value、任意のdata、Gas limit、feeです。特に、senderのaddressはsignatureから導出されるため、トランザクションdataに含める必要はありません。<sup>[[4]](#references)</sup>

これらの実践と仕組みは、プライバシーとセキュリティを重視しながらcryptocurrencyを利用したい人にとっての基盤となります。

## Value-Centric Web3 Red Teaming

- valueを持つcomponent（signer、oracle、bridge、automation）を一覧化し、誰がどのようにfundを移動できるのかを把握する。
- 各componentを関連するMITRE AADAPT tacticにマッピングし、privilege escalationの経路を明らかにする。
- flash-loan/oracle/credential/cross-chainのattack chainをrehearseし、影響を検証するとともに、exploit可能な前提条件を記録する。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing WorkflowのCompromise

- Wallet UIのsupply-chain tamperingによって、signing直前にEIP-712 payloadを改変し、delegatecallベースのproxy takeover（例: Safe masterCopyのslot-0 overwrite）に利用できる有効なsignatureを収集される可能性がある。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 一般的なsmart-accountのfailure modeには、`EntryPoint`のaccess controlのbypass、unsigned gas field、stateful validation、ERC-1271 replay、validation後のrevertによるfee-drainなどがあります。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- test suiteのblind spotを見つけるためのmutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

proverが**zkVM**またはapplication-specific proof circuitを使用してclaimを証明する場合、verifierが知ることができるのは、**guest programが記述どおりに実行された**という事実だけです。guestに**unsafe deserialization**、**undefined behavior**、または**missing semantic constraints**が含まれている場合、悪意のあるproverは、**public metricsまたはclaimed invariantがfalse**であるにもかかわらず検証に成功するproofを生成できます。<sup>[[7]](#references)</sup>

### proof guest内のUnsafe deserialization

- private witness/circuit bytesは、proofによって隠されている場合でも、**untrusted attacker input**として扱う。
- bytesがすでにout-of-bandで検証されている場合を除き、`rkyv::access_unchecked`などのunchecked helperを使用してdeserializeすることを避ける。
- untrusted serialized dataから読み込まれるenum discriminant、relative pointer、length、indexは、control flowまたはmemory accessに影響を与える前に検証する必要がある。

実践的なaudit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
`op.kind` のようなフィールドが enum であり、攻撃者が **範囲外の discriminant** を注入できる場合、その値に対する下流のすべての `match` は疑わしいものになります。

### Jump-table / UB counter bypass

Rust が大規模な `match` を **jump table** に変換する場合、無効な enum discriminant によって **undefined control flow** が発生する可能性があります。危険なパターンは次のとおりです:<sup>[[7]](#references)[[9]](#references)</sup>

1. 1つ目の `match` が **security-critical counters/constraints** を更新する。
2. 2つ目の `match` が **実際の命令セマンティクス** を実行する。
3. 範囲外の discriminant が最初の jump table の先をインデックスし、2つ目の jump table に関連付けられたコードへ到達する。

結果: operation は実行されるものの、accounting path はスキップされます。zkVM では、より少ない gates、より少ない高コストな operations、その他の制限対象リソースなど、実現不可能な metrics を報告する proof を偽造できます。

Review checklist:

- witness/private input から deserialize された、攻撃者が制御可能な enum を探す。
- 同じ opcode/kind フィールドに対する、繰り返し使用される `match` statements を調査する。
- `unsafe` + unchecked deserialization + 大規模な opcode dispatch の組み合わせを high-risk とみなす。
- 必要に応じて生成された binary を reverse engineer する。jump-table の layout は source より重要になる場合があります。

### reversible/specialized interpreters における semantic constraints の欠落

memory safety だけを validate せず、proof が enforce すべき **semantic rules** も validate してください。

reversible/quantum-like instruction sets では、distinct でなければならない operands が実際に distinct であることを ensure してください。次のように実装された Toffoli/CCX-like operation は:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
ゲストが拒否しない場合、安全でなくなる：
```text
op.q_control1 == op.q_control2 == op.q_target
```
その場合、遷移は次のように崩れます：
```text
q = q ^ (q & q) = 0
```
これにより、**決定論的なリセットプリミティブ**が生成され、可逆性の前提が崩れ、意図されていない計算をより低コストで実行できるようになります。リソース使用量を証明する proof system では、攻撃者が機能チェックを満たしながら、verifier が適用していると考えているコストモデルを回避できる可能性があります。

### ZK systems でテストすべき項目

- すべての guest parser に対して、malformed な witness/private-input encoding を用いて fuzzing を行う。
- opcode dispatch の前に enum の範囲検証を行う。
- operand aliasing やその他の無効な命令形式に対する semantic check を追加する。
- 報告されたカウンターおよび public counter を、独立した reference implementation と比較する。
- guest program にバグがある場合、有効な proof でも**誤った statement**を証明できることを忘れない。

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX および AMM の実践的な exploitation（Uniswap v4 hooks、丸め誤差・precision の悪用、flash loan により増幅された threshold-crossing swap）を調査している場合は、以下を確認してください。

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

virtual balance を cache し、`supply == 0` のときに poison される可能性がある multi-asset weighted pool については、以下を調査してください。

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key と Private Key の解説 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [multi-signature transaction とは？ - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaction | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas と fee | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google の quantum cryptanalysis に対する zero-knowledge proof を破った方法](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum Vulnerability から Elliptic Curve Cryptocurrency を保護する：Resource Estimate と Mitigation（patched version）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
