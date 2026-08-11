# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときに blockchain 上で実行されるプログラムとして定義され、仲介者なしで合意事項の履行を自動化します。
- **Decentralized Applications (dApps)** は smart contracts を基盤として構築され、ユーザーフレンドリーなフロントエンドと、透明性があり監査可能なバックエンドを備えています。
- **Tokens & Coins** は、coins がデジタルマネーとして機能する一方で、tokens は特定のコンテキストにおける価値や所有権を表すという違いがあります。
- **Utility Tokens** はサービスへのアクセスを許可し、**Security Tokens** は資産の所有権を示します。
- **DeFi** は Decentralized Finance の略で、中央当局なしで金融サービスを提供します。
- **DEX** と **DAOs** は、それぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## Consensus Mechanisms

Consensus mechanisms は、blockchain 上で安全かつ合意されたトランザクション検証を保証します。

- **Proof of Work (PoW)** は、トランザクションの検証に計算能力を利用します。
- **Proof of Stake (PoS)** は、validators に一定量の tokens の保有を要求し、PoW と比較してエネルギー消費を削減します。<sup>[[1]](#references)</sup>

## Bitcoin Essentials

### Transactions

Bitcoin transactions では、addresses 間で funds を移転します。Transactions は digital signatures を通じて検証され、private key の所有者だけが transfers を開始できることを保証します。<sup>[[2]](#references)</sup>

#### Key Components:

- **Multisignature Transactions** は、transaction を承認するために複数の signatures を要求します。<sup>[[3]](#references)</sup>
- Transactions は、**inputs**（funds の送信元）、**outputs**（送信先）、**fees**（miners に支払われる手数料）、**scripts**（transaction のルール）で構成されます。

### Lightning Network

複数の transactions を1つの channel 内で実行し、最終状態のみを blockchain に broadcast することで、Bitcoin の scalability を向上させることを目的としています。

## Bitcoin Privacy Concerns

**Common Input Ownership** や **UTXO Change Address Detection** などの privacy attacks は、transaction patterns を悪用します。**Mixers** や **CoinJoin** などの strategies は、users 間の transaction links を隠すことで anonymity を向上させます。

## Acquiring Bitcoins Anonymously

Methods には、cash trades、mining、mixers の利用などがあります。**CoinJoin** は複数の transactions を混合して traceability を困難にし、**PayJoin** は CoinJoins を通常の transactions に偽装して、privacy をさらに高めます。

# Summary of Bitcoin Privacy Attacks

Bitcoin の世界では、transactions の privacy と users の anonymity はしばしば懸念事項となります。ここでは、attackers が Bitcoin の privacy を侵害する可能性のある、いくつかの一般的な methods を簡単に説明します。<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

複雑さのため、異なる users の inputs が1つの transaction にまとめられることは一般的にまれです。そのため、**同じ transaction 内の2つの input addresses は、同じ owner に属すると仮定されることが多くなります**。

## **UTXO Change Address Detection**

UTXO、つまり **Unspent Transaction Output** は、transaction 内で全額を使用する必要があります。その一部だけが別の address に送られた場合、残りは新しい change address に送られます。Observers は、この新しい address が sender に属すると仮定できるため、privacy が侵害されます。

### 例

これを軽減するには、mixing services を利用するか、複数の addresses を使用して ownership を隠す方法があります。

## **Social Networks & Forums Exposure**

Users が Bitcoin addresses をオンラインで共有することがあり、**その address と owner を簡単に紐付けられる**ようになります。

## **Transaction Graph Analysis**

Transactions は graphs として可視化でき、funds の流れに基づいて users 間の潜在的なつながりを明らかにできます。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

この heuristic は、複数の inputs と outputs を含む transactions を分析し、sender に戻される change がどの output かを推測することに基づいています。

### 例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
入力を追加すると、変更出力が単一の入力よりも大きくなる場合、heuristic を混乱させる可能性があります。

## **Forced Address Reuse**

攻撃者は、以前使用されたアドレスに少額を送信し、受取人が将来のトランザクションでそれらを他の入力とまとめることで、アドレス同士が関連付けられることを期待する場合があります。

### Correct Wallet Behavior

Wallet は、すでに使用済みで残高が空のアドレスで受け取ったコインを使用しないようにし、この privacy leak を防ぐべきです。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** change のないトランザクションは、同一ユーザーが所有する2つのアドレス間で行われた可能性が高いです。
- **Round Numbers:** トランザクション内の切りのよい金額は支払いであることを示し、切りのよくないもう一方の出力が change である可能性があります。
- **Wallet Fingerprinting:** Wallet ごとに固有のトランザクション作成パターンがあるため、analyst は使用されたソフトウェアを特定し、change address を推測できる可能性があります。
- **Amount & Timing Correlations:** トランザクションの時刻や金額を開示すると、トランザクションが追跡可能になる場合があります。

## **Traffic Analysis**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックを IP アドレスと関連付け、ユーザーのプライバシーを侵害できる可能性があります。特に、ある組織が多数の Bitcoin node を運用している場合は、トランザクションを監視する能力が高まるため、この傾向が強くなります。

## More

privacy attack と防御策の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) を参照してください。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 現金で bitcoin を入手する方法です。
- **Cash Alternatives**: gift card を購入し、オンラインで bitcoin と交換する方法です。
- **Mining**: bitcoin を入手する最も privacy の高い方法は mining です。特に solo で行う場合は privacy が高くなります。mining pool は miner の IP アドレスを把握できる可能性があるためです。[Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論上は、bitcoin を盗むことも匿名で入手する方法になり得ますが、違法であり推奨されません。

## Mixing Services

mixing service を使用すると、ユーザーは **bitcoin を送信し**、**異なる bitcoin を受け取る**ことができるため、元の所有者を追跡することが困難になります。ただし、service がログを保存せず、実際に bitcoin を返すことを信頼する必要があります。その他の mixing option には Bitcoin casino があります。

## CoinJoin

**CoinJoin** は、異なるユーザーによる複数のトランザクションを1つに統合し、入力と出力を照合しようとする者にとって、その過程を複雑にします。効果的ではあるものの、入力と出力のサイズが一意なトランザクションは、依然として追跡できる可能性があります。

CoinJoin が使用された可能性のあるトランザクションの例として、`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` および `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` があります。

詳細については、[CoinJoin](https://coinjoin.io/en) を参照してください。deposit と後の withdrawal を分離する Ethereum smart-contract mixer については、[Tornado Cash](https://tornado.cash) を参照してください。

## PayJoin

CoinJoin の一種である **PayJoin**（または P2EP）は、2者間（例：customer と merchant）のトランザクションを、CoinJoin に特徴的な同額出力を持たない通常のトランザクションに見せかけます。これにより検出が非常に困難になり、トランザクション surveillance entity が使用する common-input-ownership heuristic を無効化できる可能性があります。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
上記のようなトランザクションはPayJoinである可能性があり、標準的なbitcoinトランザクションと区別できないまま、privacyを高めることができます。

**PayJoinの利用は、従来の監視手法を大きく混乱させる可能性があり**、トランザクションprivacyの追求において有望な発展です。

# Cryptocurrencyにおけるprivacyのベストプラクティス

## **Wallet同期のテクニック**

privacyとsecurityを維持するには、walletをblockchainと同期することが重要です。特に注目すべき方法は2つあります。

- **Full node**: blockchain全体をdownloadすることで、full nodeは最大限のprivacyを確保します。これまでに行われたすべてのトランザクションがローカルに保存されるため、攻撃者がユーザーの関心のあるトランザクションやaddressを特定することはできません。
- **Client-side block filtering**: この方法では、blockchain内のすべてのblockに対するfilterを作成し、network observerに具体的な関心対象を公開することなく、walletが関連するトランザクションを特定できるようにします。Lightweight walletはこれらのfilterをdownloadし、ユーザーのaddressとの一致が見つかった場合にのみ完全なblockを取得します。

## **AnonymityのためのTorの利用**

Bitcoinはpeer-to-peer network上で動作するため、IP addressを隠す目的でTorを使用することが推奨されます。これにより、networkとの通信時のprivacyが向上します。

## **Addressの再利用を防止する**

privacyを保護するには、すべてのトランザクションで新しいaddressを使用することが重要です。addressを再利用すると、トランザクションが同じentityに関連付けられ、privacyが損なわれる可能性があります。Modern walletは、その設計によってaddressの再利用を推奨しないようになっています。

## **トランザクションprivacyのための戦略**

- **Multiple transactions**: 支払いを複数のトランザクションに分割することで、トランザクション金額を分かりにくくし、privacy attackを妨げることができます。
- **Change avoidance**: change outputを必要としないトランザクションを選択すると、change detection methodを妨げ、privacyを高められます。
- **Multiple change outputs**: changeの回避が現実的でない場合でも、複数のchange outputを生成することでprivacyを改善できます。

# **Monero: Anonymityの先駆者**

Moneroは、トランザクションprivacyを優先するように設計されています。

# **Ethereum: Gasとトランザクション**

## **Gasを理解する**

GasはEthereum上でoperationを実行するために必要な計算量を測定するもので、**gwei**で価格設定されます。たとえば、2,310,000 gwei（または0.00231 ETH）のコストがかかるトランザクションには、gas limitとbase feeが含まれ、validatorによる取り込みを促すためのpriority feeも設定されます。ユーザーはmax feeを設定して過払いを防ぐことができ、余剰分は返金されます。<sup>[[5]](#references)</sup>

## **トランザクションの実行**

Ethereumのトランザクションにはsenderとrecipientが含まれ、これらはuser addressまたはsmart contract addressのいずれかです。トランザクションにはfeeが必要であり、blockに含められなければなりません。トランザクションの基本情報には、recipient、senderのsignature、value、任意のdata、gas limit、feeが含まれます。特に、senderのaddressはsignatureから導出されるため、トランザクションdataに含める必要はありません。<sup>[[4]](#references)</sup>

これらのプラクティスと仕組みは、privacyとsecurityを優先しながらcryptocurrencyを利用したい人にとって基礎となるものです。

## Value-Centric Web3 Red Teaming

- valueを持つcomponent（signer、oracle、bridge、automation）をInventory化し、誰がどのようにfundを移動できるかを把握する。
- 各componentを関連するMITRE AADAPT tacticにマッピングし、privilege escalation pathを明らかにする。
- flash-loan/oracle/credential/cross-chain attack chainをリハーサルし、impactを検証するとともに、exploit可能な前提条件を文書化する。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- wallet UIへのsupply-chain tamperingにより、signing直前にEIP-712 payloadを改変し、delegatecallベースのproxy takeover（例: Safe masterCopyのslot-0 overwrite）に利用できる有効なsignatureを窃取できる。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 一般的なsmart-accountのfailure modeには、`EntryPoint` access controlのbypass、unsigned gas field、stateful validation、ERC-1271 replay、validation後のrevertによるfee-drainなどがあります。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- test suiteのblind spotを発見するためのmutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

proverが**zkVM**またはapplication-specific proof circuitを使用してclaimを証明する場合、verifierが知ることができるのは、**guest programが記述どおりに実行された**という事実だけです。guestに**unsafe deserialization**、**undefined behavior**、または**不足しているsemantic constraint**が含まれている場合、悪意のあるproverは、proof自体はverifyされる一方で、**public metricまたは主張されたinvariantが偽である**proofを生成できる可能性があります。<sup>[[7]](#references)</sup>

### Proof guest内のUnsafe deserialization

- private witness/circuit bytesは、proofによって隠されている場合でも、**untrusted attacker input**として扱う。
- bytesがすでにout-of-bandで検証されていない限り、`rkyv::access_unchecked`のようなunchecked helperを使ってdeserializationしない。
- untrustedなserialized dataから読み込まれるenum discriminant、relative pointer、length、indexは、control flowやmemory accessに影響を与える前に検証する必要がある。

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

1. 1つ目の `match` が **security-critical なカウンター/制約** を更新する。
2. 2つ目の `match` が **実際の命令セマンティクス** を実行する。
3. 範囲外の discriminant が最初の jump table の先をインデックスし、2つ目の jump table に関連付けられたコードへ到達する。

結果として、操作自体は実行される一方、accounting path はスキップされます。zkVM では、これにより、ゲート数、コストの高い操作数、その他の制限対象リソースが少ないと報告するなど、実現不可能なメトリクスを偽装した proof を生成できます。

確認 checklist:

- witness/private input から deserialize された、攻撃者が制御可能な enum を探す。
- 同じ opcode/kind フィールドに対する、繰り返し使用されている `match` 文を調査する。
- `unsafe` + unchecked deserialization + 大規模な opcode dispatch の組み合わせは、高リスクとして扱う。
- 必要に応じて、生成された binary を reverse engineer する。jump-table の配置は、source よりも重要になる場合がある。

### reversible/specialized interpreter における semantic constraints の欠落

memory safety だけを検証してはなりません。proof が強制することを意図している **semantic rules** も検証してください。

reversible/quantum-like instruction set では、互いに異なる必要があるオペランドが、実際に distinct であることを制約されているか確認してください。次のように実装された Toffoli/CCX-like operation は、<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
ゲストが拒否しない場合、安全でなくなる：
```text
op.q_control1 == op.q_control2 == op.q_target
```
その場合、遷移は次のように縮退します：
```text
q = q ^ (q & q) = 0
```
これは**決定論的なリセットプリミティブ**を生み出し、可逆性の前提を破壊するとともに、意図されていない計算をより低コストで実行可能にします。リソース使用量を証明する proof system では、攻撃者が機能チェックを満たしながら、検証者が適用されていると信じているコストモデルを回避できる可能性があります。

### ZK systems でテストすべき項目

- すべての guest parser に対して、不正な witness/private-input エンコーディングを用いた fuzzing を行う。
- opcode dispatch の前に enum の範囲検証を行う。
- operand aliasing やその他の不正な命令形式に対する意味検証を追加する。
- 報告されたカウンタおよび公開カウンタを、独立した reference implementation と比較する。
- guest program にバグがある場合、valid proof でも**誤った statement**を証明できることを忘れない。

## DeFi/AMM Exploitation

DEXes および AMMs の実用的な Exploitation（Uniswap v4 hooks、丸め誤差・精度の悪用、flash-loan によって増幅された threshold-crossing swaps）を調査している場合は、以下を確認してください。

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

virtual balances をキャッシュし、`supply == 0` の場合に poisoning される可能性がある multi-asset weighted pools については、以下を調査してください。

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [公開鍵と秘密鍵の解説 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [マルチシグネチャトランザクションとは？ - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [トランザクション | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas と手数料 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [プライバシー - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google の量子暗号解析に対する zero-knowledge proof を打ち破った](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [量子脆弱性から楕円曲線暗号通貨を保護する：リソース見積もりと緩和策（パッチ適用版）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept リポジトリ](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
