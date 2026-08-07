# Blockchainと暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときに blockchain 上で実行されるプログラムとして定義され、中間者なしで契約の履行を自動化します。
- **Decentralized Applications (dApps)** は Smart Contracts を基盤として構築され、使いやすいフロントエンドと、透明性があり監査可能なバックエンドを備えています。
- **Tokens & Coins** は、coin がデジタルマネーとして機能する一方、token は特定の文脈における価値や所有権を表すという点で異なります。
- **Utility Tokens** はサービスへのアクセスを付与し、**Security Tokens** は資産の所有権を示します。
- **DeFi** は Decentralized Finance の略で、中央当局なしで金融サービスを提供します。
- **DEX** と **DAOs** は、それぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## Consensus Mechanisms

Consensus mechanisms は、blockchain 上で安全かつ合意されたトランザクション検証を保証します。

- **Proof of Work (PoW)** は、トランザクションの検証に計算能力を利用します。
- **Proof of Stake (PoS)** は、validators に一定量の token の保有を要求し、PoW と比較してエネルギー消費を削減します。<sup>[[1]](#references)</sup>

## Bitcoin の基礎

### Transactions

Bitcoin transactions では、address 間で資金を移転します。Transactions は digital signatures によって検証され、private key の所有者だけが transfer を開始できることを保証します。<sup>[[2]](#references)</sup>

#### 主な構成要素：

- **Multisignature Transactions** は、transaction を承認するために複数の signature を必要とします。<sup>[[3]](#references)</sup>
- Transactions は、**inputs**（資金の送信元）、**outputs**（送信先）、**fees**（miners に支払われる手数料）、**scripts**（transaction のルール）で構成されます。

### Lightning Network

複数の transactions を channel 内で実行できるようにすることで Bitcoin の scalability を高め、最終状態だけを blockchain に broadcast することを目的とします。

## Bitcoin のプライバシーに関する懸念

**Common Input Ownership** や **UTXO Change Address Detection** などの privacy attacks は、transaction patterns を悪用します。**Mixers** や **CoinJoin** などの strategies は、users 間の transaction links を隠すことで anonymity を向上させます。

## Bitcoin を匿名で取得する

方法には、cash trades、mining、mixers の利用などがあります。**CoinJoin** は複数の transactions を混合して traceability を困難にします。一方、**PayJoin** は CoinJoins を通常の transactions に偽装し、privacy をさらに高めます。

# Bitcoin Privacy Atacks

# Bitcoin Privacy Attacks の概要

Bitcoin の世界では、transactions の privacy と users の anonymity はしばしば懸念事項になります。ここでは、attackers が Bitcoin の privacy を侵害する一般的な方法をいくつか簡単に説明します。<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

異なる users の inputs が複雑さのために単一の transaction にまとめられることは一般的にまれです。そのため、**同じ transaction 内の2つの input addresses は、同じ owner に属すると仮定されることが多くなります**。

## **UTXO Change Address Detection**

UTXO、つまり **Unspent Transaction Output** は、transaction 内で全額を使用する必要があります。その一部だけが別の address に送られた場合、残額は新しい change address に送られます。Observers は、この新しい address が sender に属すると推測できるため、privacy が侵害されます。

### 例

これを軽減するには、mixing services を利用するか、複数の addresses を使用して ownership を隠す方法があります。

## **Social Networks & Forums Exposure**

Users が online で Bitcoin addresses を共有することがあり、**その address と owner を簡単に結び付けられる**ようになります。

## **Transaction Graph Analysis**

Transactions は graphs として可視化でき、funds の流れに基づいて users 間の潜在的な connections を明らかにします。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

この heuristic は、複数の inputs と outputs を持つ transactions を分析し、どの output が sender に戻る change なのかを推測することに基づいています。

### 例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
入力を追加することで、change output が単一の入力より大きくなる場合、heuristic を混乱させる可能性があります。

## **Forced Address Reuse**

攻撃者は、以前使用されたアドレスに少額を送信し、受取人が将来のトランザクションでそれらを他の入力と組み合わせることを期待します。これにより、アドレス同士が関連付けられる可能性があります。

### Correct Wallet Behavior

Wallet は、すでに使用済みで残高が空のアドレスで受け取った coin を使用しないようにして、このプライバシー leak を防ぐべきです。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** change のないトランザクションは、同じユーザーが所有する2つのアドレス間で行われた可能性があります。
- **Round Numbers:** トランザクション内の切りのよい金額は、それが支払いであることを示唆し、切りのよくない output が change である可能性があります。
- **Wallet Fingerprinting:** Wallet ごとに固有のトランザクション作成パターンがあるため、analyst は使用された software を特定し、change address を推測できる可能性があります。
- **Amount & Timing Correlations:** トランザクションの時刻や金額を開示すると、トランザクションが追跡可能になる場合があります。

## **Traffic Analysis**

Network traffic を監視することで、攻撃者はトランザクションや block を IP address に関連付け、ユーザーの privacy を侵害できる可能性があります。特に、ある entity が多数の Bitcoin node を運用している場合、その entity のトランザクション監視能力が高まるため、この問題は顕著になります。

## More

privacy attack と defense の包括的な一覧については、[Bitcoin Wiki の Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) を参照してください。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 現金で bitcoin を入手する。
- **Cash Alternatives**: gift card を購入し、online で bitcoin と交換する。
- **Mining**: bitcoin を獲得する最も privacy の高い方法は mining です。特に単独で行う場合は、mining pool が miner の IP address を把握する可能性があるため、より privacy が高くなります。[Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論上は、bitcoin を盗むことも匿名で入手する方法の1つですが、違法であり、推奨されません。

## Mixing Services

mixing service を使用すると、ユーザーは **bitcoin を送信し**、その代わりに **異なる bitcoin を受け取る** ことができるため、元の所有者を追跡することが困難になります。ただし、service が log を保存せず、実際に bitcoin を返すことを信頼する必要があります。その他の mixing の選択肢には Bitcoin casino があります。

## CoinJoin

**CoinJoin** は、異なるユーザーによる複数のトランザクションを1つに統合し、input と output の対応付けを試みる者にとって、その過程を複雑にします。効果的ではありますが、input と output のサイズが一意なトランザクションは、依然として追跡される可能性があります。

CoinJoin を使用した可能性のあるトランザクションの例として、`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` と `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` があります。

詳細については、[CoinJoin](https://coinjoin.io/en) を参照してください。Ethereum 上の類似サービスについては、miner からの funds を使用してトランザクションを anonymize する [Tornado Cash](https://tornado.cash) を確認してください。

## PayJoin

CoinJoin の variant である **PayJoin**（または P2EP）は、2者間（例：customer と merchant）のトランザクションを、CoinJoin に特徴的な同一 output なしの通常のトランザクションに偽装します。そのため検出が非常に困難になり、トランザクション監視 entity が使用する一般的な common-input-ownership heuristic を無効化できる可能性があります。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
上記のようなトランザクションはPayJoinである可能性があり、標準的なBitcoinトランザクションと区別できないまま、プライバシーを強化できます。

**PayJoinの利用は、従来の監視手法を大きく妨げる可能性があり**、トランザクションプライバシーの実現に向けた有望な発展です。

# 暗号資産におけるプライバシーのベストプラクティス

## **Wallet Synchronization Techniques**

プライバシーとセキュリティを維持するには、WalletをBlockchainと同期することが重要です。特に注目すべき方法は2つあります。

- **Full node**: Blockchain全体をダウンロードすることで、Full nodeは最大限のプライバシーを確保します。これまでに行われたすべてのトランザクションがローカルに保存されるため、攻撃者がユーザーの関心対象であるトランザクションやアドレスを特定することはできません。
- **Client-side block filtering**: この方法では、Blockchain内のすべてのブロックに対してフィルターを作成し、ネットワーク監視者に具体的な関心対象を公開せずに、Walletが関連するトランザクションを特定できるようにします。軽量Walletはこれらのフィルターをダウンロードし、ユーザーのアドレスとの一致が見つかった場合にのみ完全なブロックを取得します。

## **匿名性のためのTorの利用**

Bitcoinはpeer-to-peer network上で動作するため、IPアドレスを隠し、ネットワークとの通信時のプライバシーを高める目的でTorの利用が推奨されます。

## **アドレス再利用の防止**

プライバシーを保護するには、トランザクションごとに新しいアドレスを使用することが重要です。アドレスを再利用すると、トランザクションが同一のエンティティに関連付けられ、プライバシーが侵害される可能性があります。最新のWalletは、その設計によってアドレスの再利用を防止しています。

## **トランザクションプライバシーのための戦略**

- **Multiple transactions**: 支払いを複数のトランザクションに分割することで、トランザクション金額を不明瞭にし、プライバシー攻撃を阻止できます。
- **Change avoidance**: Change outputを必要としないトランザクションを選択すると、Change検出手法を妨げることでプライバシーを高められます。
- **Multiple change outputs**: Changeを避けられない場合でも、複数のChange outputを生成することでプライバシーを改善できます。

# **Monero: 匿名性の象徴**

Moneroはデジタルトランザクションにおける完全な匿名性のニーズに対応し、プライバシーに関する高い基準を確立しています。

# **Ethereum: Gasとトランザクション**

## **Gasの理解**

GasはEthereum上で操作を実行するために必要な計算量を表し、**gwei**で価格設定されます。例えば、2,310,000 gwei（または0.00231 ETH）のコストがかかるトランザクションには、Gas limitとbase feeが含まれ、さらにminerへのインセンティブとしてtipが加えられます。ユーザーはmax feeを設定して過払いを防ぐことができ、余剰分は返金されます。<sup>[[5]](#references)</sup>

## **トランザクションの実行**

Ethereumのトランザクションには送信者と受信者が関与し、それぞれuser addressまたはsmart contract addressのいずれかになります。トランザクションにはfeeが必要であり、miningされなければなりません。トランザクションに含まれる重要な情報は、受信者、送信者のsignature、value、任意のdata、Gas limit、feeです。特に、送信者のaddressはsignatureから導出されるため、トランザクションdataに含める必要はありません。<sup>[[4]](#references)</sup>

これらのプラクティスと仕組みは、プライバシーとセキュリティを重視しながら暗号資産を利用したい人にとって、基本となるものです。

## Value-Centric Web3 Red Teaming

- Value-bearing component（signer、oracle、bridge、automation）を一覧化し、誰がどのようにfundを移動できるかを把握する。
- 各componentを関連するMITRE AADAPT tacticに対応付け、privilege escalation pathを明らかにする。
- flash-loan/oracle/credential/cross-chain attack chainをrehearseし、影響を検証するとともに、exploit可能なpreconditionを文書化する。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UIのsupply-chain tamperingにより、signing直前にEIP-712 payloadを改変し、delegatecall-based proxy takeover（例: Safe masterCopyのslot-0 overwrite）に利用できる有効なsignatureを収集される可能性がある。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Smart-accountにおける一般的なfailure modeには、`EntryPoint` access controlのbypass、unsigned gas field、stateful validation、ERC-1271 replay、validation後のrevertによるfee-drainが含まれる。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suiteのblind spotを発見するためのmutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

proverが**zkVM**またはapplication-specific proof circuitを使用してclaimを証明する場合、verifierが知ることができるのは、**guest programが記述どおりに実行された**という事実だけです。guestに**unsafe deserialization**、**undefined behavior**、または**missing semantic constraints**が含まれている場合、悪意のあるproverは、**public metricsまたはclaimed invariantが偽である**にもかかわらず検証に成功するproofを生成できる可能性があります。<sup>[[7]](#references)</sup>

### proof guest内のUnsafe deserialization

- private witness/circuit bytesは、proofによって隠されている場合でも、**untrusted attacker input**として扱う。
- bytesがすでにout-of-bandで検証されている場合を除き、`rkyv::access_unchecked`のようなunchecked helperによるdeserializationを避ける。
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

Rust が大きな `match` を **jump table** に変換する場合、無効な enum discriminant によって **undefined control flow** が発生する可能性があります。危険なパターンは次のとおりです。<sup>[[7]](#references)[[9]](#references)</sup>

1. 1つ目の `match` が **security-critical counters/constraints** を更新する。
2. 2つ目の `match` が **実際の命令セマンティクス** を実行する。
3. 範囲外の discriminant が最初の jump table の末尾を越えてインデックスし、2つ目の jump table に関連付けられたコードへ到達する。

結果として、操作自体は実行されますが、accounting path がスキップされます。zkVM では、より少ない gates、より少ない高コストな操作、その他の制限対象リソースなど、不可能なメトリクスを報告する proof を偽造できます。

Review checklist:

- witness/private input からデシリアライズされる、攻撃者が制御可能な enum を探す。
- 同じ opcode/kind フィールドに対する、繰り返し使用される `match` 文を調査する。
- `unsafe` + unchecked deserialization + 大規模な opcode dispatch の組み合わせは、高リスクとみなす。
- 必要に応じて、生成された binary を reverse engineer する。jump-table のレイアウトは、source よりも重要になる場合がある。

### reversible/specialized interpreters における semantic constraints の欠落

memory safety だけを検証してはいけません。proof が強制することを意図している **semantic rules** も検証してください。

reversible/quantum-like instruction sets では、互いに異なる必要がある operands が、実際に distinct となるよう制約されていることを確認してください。次のように実装された Toffoli/CCX-like operation:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
ゲストが拒否しないと安全でなくなる：
```text
op.q_control1 == op.q_control2 == op.q_target
```
その場合、遷移は次のように簡略化されます：
```text
q = q ^ (q & q) = 0
```
これは**決定論的なリセットプリミティブ**を生成し、可逆性に関する前提を破壊するとともに、意図されていない計算をより低コストで実行可能にします。リソース使用量を証明するシステムでは、攻撃者が機能チェックを満たしながら、検証者が適用していると想定するコストモデルを回避できる可能性があります。

### ZKシステムでテストすべき項目

- すべての guest parser に対して、不正な witness/private-input エンコーディングを用いた fuzzing を実行する。
- opcode dispatch の前に enum の範囲検証を行う。
- オペランドの aliasing やその他の不正な命令形式について、セマンティックチェックを追加する。
- 報告されたカウンタおよび公開カウンタを、独立した reference implementation と比較する。
- guest program にバグがある場合、有効な proof でも**誤った statement**を証明できることを忘れない。

## DeFi/AMM Exploitation

DEX および AMM（Uniswap v4 hooks、丸め誤差・精度の悪用、flash-loan で増幅した閾値超過スワップ）の実際の exploitation を調査している場合は、以下を参照してください。

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

virtual balances をキャッシュし、`supply == 0` のときに poison される可能性がある multi-asset weighted pools については、以下を調査してください。

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## 参考資料

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [公開鍵と秘密鍵の解説 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [multi-signature transactions とは？ - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas and fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google の量子暗号解析に対する zero-knowledge proof を打ち破った](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [量子脆弱性から楕円曲線暗号通貨を保護する：リソース見積もりと緩和策（patched version）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
