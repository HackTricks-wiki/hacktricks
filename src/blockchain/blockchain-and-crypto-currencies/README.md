# Blockchain and Crypto-Currencies

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときに blockchain 上で実行されるプログラムとして定義され、中 intermediaries を介さずに合意の履行を自動化します。
- **Decentralized Applications (dApps)** は smart contracts を基盤として構築され、ユーザーフレンドリーな front-end と、透明性があり監査可能な back-end を備えています。
- **Tokens & Coins** は用途が異なり、coins はデジタルマネーとして機能する一方、tokens は特定のコンテキストにおける価値や所有権を表します。
- **Utility Tokens** はサービスへのアクセスを付与し、**Security Tokens** は資産の所有権を示します。
- **DeFi** は Decentralized Finance を意味し、中央集権的な権 authority なしで金融サービスを提供します。
- **DEX** と **DAOs** は、それぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## Consensus Mechanisms

Consensus mechanisms は blockchain 上で安全かつ合意された transaction の検証を保証します。

- **Proof of Work (PoW)** は、transaction の検証に計算能力を利用します。
- **Proof of Stake (PoS)** は validators に一定量の tokens の保有を要求し、PoW と比較して energy consumption を削減します。<sup>[[1]](#references)</sup>

## Bitcoin の基本

### Transactions

Bitcoin transactions では、addresses 間で funds を transfer します。Transactions は digital signatures によって検証され、private key の所有者だけが transfers を開始できることを保証します。<sup>[[2]](#references)</sup>

#### 主な構成要素：

- **Multisignature Transactions** は、transaction を承認するために複数の signatures を必要とします。<sup>[[3]](#references)</sup>
- Transactions は、**inputs**（funds の source）、**outputs**（destination）、**fees**（miners に支払われる手数料）、**scripts**（transaction のルール）で構成されます。

### Lightning Network

channel 内で複数の transactions を実行し、最終的な state のみを blockchain に broadcast することで、Bitcoin の scalability を向上させることを目的とします。

## Bitcoin の Privacy に関する懸念

**Common Input Ownership** や **UTXO Change Address Detection** などの privacy attacks は、transaction patterns を悪用します。**Mixers** や **CoinJoin** などの strategies は、users 間の transaction links を隠すことで anonymity を向上させます。

## Bitcoin を匿名で取得する

Methods には、cash trades、mining、mixers の利用などがあります。**CoinJoin** は複数の transactions を混合して traceability を困難にし、**PayJoin** は CoinJoins を通常の transactions に偽装して privacy をさらに高めます。

# Bitcoin Privacy Attacks の概要

Bitcoin の世界では、transactions の privacy と users の anonymity は、しばしば懸念事項となります。ここでは、attackers が Bitcoin の privacy を侵害する可能性がある、いくつかの一般的な methods について簡略化して説明します。<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

複雑さのため、異なる users の inputs が単一の transaction にまとめられることは一般的にまれです。そのため、**同じ transaction 内の 2 つの input addresses は、同じ owner に属すると仮定されることが多くなります**。

## **UTXO Change Address Detection**

UTXO、つまり **Unspent Transaction Output** は、transaction 内ですべて消費されなければなりません。その一部だけが別の address に送られた場合、残りは新しい change address に送られます。Observers は、この新しい address が sender に属すると推測でき、privacy が損なわれます。

### 例

これを軽減するには、mixing services の利用や複数の addresses の使用によって ownership を隠すことができます。

## **Social Networks & Forums Exposure**

Users は Bitcoin addresses を online で共有することがあり、その結果、**address と owner を簡単に結び付けられるようになります**。

## **Transaction Graph Analysis**

Transactions は graphs として可視化でき、funds の flow に基づいて users 間の潜在的な connections を明らかにします。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

この heuristic は、複数の inputs と outputs を持つ transactions を分析し、どの output が sender に戻る change なのかを推測するものです。

### 例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
入力を追加することで、change output が単一の入力よりも大きくなる場合、heuristic を混乱させる可能性があります。

## **Forced Address Reuse**

攻撃者は、以前使用されたアドレスに少額を送信し、受取人が将来のトランザクションでこれらを他の入力と統合することで、アドレス同士がリンクされることを期待します。

### Correct Wallet Behavior

Wallet は、すでに使用済みで空になっているアドレスで受け取った coin を使用しないようにして、この privacy leak を防ぐべきです。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** change のないトランザクションは、同じユーザーが所有する2つのアドレス間で行われた可能性が高いです。
- **Round Numbers:** トランザクション内の切りのよい数値は、それが支払いであることを示唆し、切りのよくない output は change である可能性が高くなります。
- **Wallet Fingerprinting:** 異なる wallet には固有のトランザクション作成パターンがあるため、分析者は使用された software や change address を特定できる可能性があります。
- **Amount & Timing Correlations:** トランザクションの時刻や金額を開示すると、トランザクションが追跡可能になることがあります。

## **Traffic Analysis**

Network traffic を監視することで、攻撃者はトランザクションや block を IP address にリンクし、ユーザーの privacy を侵害できる可能性があります。これは、ある entity が多数の Bitcoin node を運用している場合に特に当てはまり、トランザクションを監視する能力が高まります。

## More

privacy 攻撃と防御の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) を参照してください。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 現金を使って bitcoin を取得する方法です。
- **Cash Alternatives**: gift card を購入し、online で bitcoin と交換する方法です。
- **Mining**: bitcoins を獲得する最も privacy の高い方法は mining です。特に solo で行う場合は、mining pool が miner の IP address を把握する可能性があるため、privacy が高くなります。[Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論上、bitcoin を盗むことも匿名で取得する方法の一つになり得ますが、違法であり、推奨されません。

## Mixing Services

mixing service を使用すると、ユーザーは **bitcoin を送信**し、**異なる bitcoin を受け取る**ことができるため、元の所有者を追跡することが困難になります。ただし、service が log を保存せず、実際に bitcoin を返すことを信頼する必要があります。その他の mixing option には Bitcoin casino があります。

## CoinJoin

**CoinJoin** は、異なるユーザーによる複数のトランザクションを1つに統合し、input と output を一致させようとする者の分析を複雑にします。効果的ではあるものの、input と output のサイズが固有のトランザクションは、依然として追跡できる可能性があります。

CoinJoin が使用された可能性のあるトランザクションの例として、`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` と `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` があります。

詳細については、[CoinJoin](https://coinjoin.io/en) を参照してください。deposit と後続の withdrawal を分離する Ethereum smart-contract mixer については、[Tornado Cash](https://tornado.cash) を参照してください。

## PayJoin

CoinJoin の variant である **PayJoin**（または P2EP）は、2者間（例：customer と merchant）のトランザクションを、CoinJoin に特徴的な同一 output を持たない通常のトランザクションとして偽装します。これにより検出が極めて困難になり、トランザクション監視 entity が使用する common-input-ownership heuristic が無効になる可能性があります。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
上記のようなトランザクションはPayJoinである可能性があり、通常のbitcoinトランザクションと見分けがつかないままプライバシーを強化できます。

**PayJoinの利用は従来の監視手法を大きく妨害する可能性があり**、トランザクションプライバシーの追求において有望な発展といえます。

# 暗号資産におけるプライバシーのベストプラクティス

## **Wallet同期の手法**

プライバシーとセキュリティを維持するには、Walletをblockchainと同期することが重要です。特に注目すべき方法は2つあります。

- **Full node**: blockchain全体をダウンロードすることで、Full nodeは最大限のプライバシーを確保します。これまでに行われたすべてのトランザクションがローカルに保存されるため、攻撃者がユーザーの関心対象であるトランザクションやアドレスを特定することはできません。
- **Client-side block filtering**: この方法では、blockchain内のすべてのブロックに対してfiltersを作成し、network observerに具体的な関心対象を公開せずに、Walletが関連するトランザクションを特定できるようにします。Lightweight walletはこれらのfiltersをダウンロードし、ユーザーのアドレスとの一致が見つかった場合にのみ完全なブロックを取得します。

## **匿名性のためのTorの利用**

Bitcoinはpeer-to-peer network上で動作するため、Torを使用してIPアドレスを隠すことが推奨されます。これにより、networkとのやり取りにおけるプライバシーが向上します。

## **アドレス再利用の防止**

プライバシーを保護するには、すべてのトランザクションで新しいアドレスを使用することが重要です。アドレスを再利用すると、トランザクションが同一のエンティティに関連付けられ、プライバシーが損なわれる可能性があります。現代のWalletは、その設計によってアドレスの再利用を防止しています。

## **トランザクションプライバシーの戦略**

- **Multiple transactions**: 支払いを複数のトランザクションに分割すると、トランザクション金額を分かりにくくし、プライバシー攻撃を阻止できます。
- **Change avoidance**: change outputを必要としないトランザクションを選択すると、change detection手法を妨害してプライバシーを向上させられます。
- **Multiple change outputs**: changeの回避が不可能な場合でも、複数のchange outputを生成することでプライバシーを改善できます。

# **Monero: 匿名性の象徴**

Moneroは、トランザクションプライバシーを優先するように設計されています。

# **Ethereum: Gasとトランザクション**

## **Gasの理解**

GasはEthereum上で操作を実行するために必要な計算処理量を表し、**gwei**で価格設定されます。たとえば、2,310,000 gwei（または0.00231 ETH）のコストがかかるトランザクションには、Gas limitとbase feeが含まれ、validatorによる取り込みを促すためのpriority feeも設定されます。ユーザーはmax feeを設定して過払いを防ぐことができ、余剰分は返金されます。<sup>[[5]](#references)</sup>

## **トランザクションの実行**

Ethereumのトランザクションには送信者と受信者が含まれ、これらはユーザーアドレスまたはsmart contractアドレスのいずれかです。トランザクションにはfeeが必要であり、ブロックに含める必要があります。トランザクションに含まれる基本情報は、受信者、送信者のsignature、value、任意のdata、Gas limit、feeです。注目すべき点として、送信者のアドレスはsignatureから導出されるため、トランザクションdataに含める必要はありません。<sup>[[4]](#references)</sup>

これらのプラクティスと仕組みは、プライバシーとセキュリティを重視しながら暗号資産を利用したい人にとって基盤となるものです。

## Value-Centric Web3 Red Teaming

- valueを持つコンポーネント（signer、oracle、bridge、automation）の一覧を作成し、誰がどのように資金を移動できるのかを把握する。
- 各コンポーネントを関連するMITRE AADAPT tacticsにマッピングし、privilege escalation pathを明らかにする。
- flash-loan/oracle/credential/cross-chain attack chainをrehearseして影響を検証し、exploit可能な前提条件を文書化する。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UIのsupply-chain tamperingにより、署名直前にEIP-712 payloadを変更し、delegatecall-based proxy takeover（例: Safe masterCopyのslot-0 overwrite）に利用可能な有効なsignatureを窃取できる。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 一般的なsmart-accountのfailure modeには、`EntryPoint` access controlのbypass、unsigned gas field、stateful validation、ERC-1271 replay、validation後のrevertによるfee-drainが含まれます。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- test suiteのblind spotを発見するためのmutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

proverが**zkVM**またはapplication-specific proof circuitを使用してclaimを証明する場合、verifierが知ることができるのは、**guest programが記述どおりに実行された**という事実だけです。guestに**unsafe deserialization**、**undefined behavior**、または**semantic constraintの欠落**が存在すると、悪意のあるproverは、**public metricまたはclaimed invariantがfalse**であるにもかかわらず検証に成功するproofを生成できる可能性があります。<sup>[[7]](#references)</sup>

### proof guest内のUnsafe deserialization

- private witness/circuit bytesは、proofによって隠されている場合でも、**untrusted attacker input**として扱う。
- bytesがout-of-bandですでに検証されていない限り、`rkyv::access_unchecked`のようなunchecked helperによるdeserializationは避ける。
- untrusted serialized dataから読み込まれるenum discriminant、relative pointer、length、indexは、control flowやmemory accessに影響を与える前に検証する必要があります。

実践的なaudit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
`op.kind` のようなフィールドが enum であり、攻撃者が **範囲外の discriminant** を注入できる場合、その値に対する後続のすべての `match` は疑わしいものになります。

### Jump-table / UB counter bypass

Rust が大規模な `match` を **jump table** に変換する場合、無効な enum discriminant によって **undefined control flow** が発生する可能性があります。危険なパターンは次のとおりです。<sup>[[7]](#references)[[9]](#references)</sup>

1. 1つ目の `match` が **security-critical counters/constraints** を更新する。
2. 2つ目の `match` が **実際の instruction semantics** を実行する。
3. 範囲外の discriminant が最初の jump table の範囲外をインデックスし、2つ目の jump table に関連付けられたコードへ着地する。

結果として、operation は実行されますが、accounting path はスキップされます。zkVM では、これにより、gate 数、expensive operation 数、その他の制限対象リソースが少ないと報告するなど、本来あり得ない metrics を示す proof を偽造できます。

Review checklist:

- witness/private input から deserialize された、攻撃者が制御可能な enum を探す。
- 同じ opcode/kind field に対する、繰り返し使用される `match` statement を調査する。
- `unsafe` + unchecked deserialization + large opcode dispatch の組み合わせを high-risk とみなす。
- 必要に応じて生成された binary を reverse engineer する。jump-table の layout は source より重要になる場合がある。

### reversible/specialized interpreters における semantic constraints の欠落

memory safety だけを検証するのではなく、proof が enforce することを意図した **semantic rules** も検証してください。

reversible/quantum-like instruction sets では、distinct でなければならない operands が実際に distinct であることを確実に constraint してください。次のように実装された Toffoli/CCX-like operation は、<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
ゲストが拒否しない場合、安全でなくなる：
```text
op.q_control1 == op.q_control2 == op.q_target
```
その場合、遷移は次のように縮約されます:
```text
q = q ^ (q & q) = 0
```
これは**決定論的なリセットプリミティブ**を作り出し、可逆性の前提を破壊するとともに、本来意図されていない計算をより低コストで実行できるようにします。リソース使用量を証明する proof systems では、これにより攻撃者は機能チェックを満たしながら、verifier が適用していると想定するコストモデルを回避できる可能性があります。

### ZK systems でテストすべき項目

- すべての guest parser に対して、不正な witness/private-input エンコーディングを用いて fuzzing を行う。
- opcode dispatch の前に enum の範囲検証を行う。
- operand aliasing やその他の無効な命令形式に対する semantic checks を追加する。
- 報告されたカウンターおよび public counters を、独立した reference implementation と比較する。
- guest program にバグがある場合、有効な proof でも**誤った statement**を証明できてしまうことを忘れない。

## DeFi/AMM の Exploitation

DEX および AMM（Uniswap v4 hooks、丸め誤差/精度の悪用、flash loan により増幅された閾値越え swap）の実用的な exploitation を調査している場合は、以下を確認してください。

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

virtual balances をキャッシュし、`supply == 0` の場合に poison される可能性がある multi-asset weighted pools については、以下を調査してください。

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [公開鍵と秘密鍵の解説 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [multi-signature transactions とは？ - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas と手数料 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google の quantum cryptanalysis に対する zero-knowledge proof を打ち破った](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [量子脆弱性に対する Elliptic Curve Cryptocurrencies の保護：Resource Estimates and Mitigations（patched version）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
