# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときに blockchain 上で実行されるプログラムです。仲介者を介さずに契約の履行を自動化します。
- **Decentralized Applications (dApps)** は smart contracts を基盤として構築され、使いやすいフロントエンドと、透明性が高く監査可能なバックエンドを備えています。
- **Tokens & Coins** は用途が異なります。coins はデジタル通貨として機能する一方、tokens は特定の状況における価値や所有権を表します。
  - **Utility Tokens** はサービスへのアクセスを提供し、**Security Tokens** は資産の所有権を示します。
- **DeFi** は Decentralized Finance の略で、中央機関を介さずに金融サービスを提供します。
- **DEX** と **DAOs** は、それぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## Consensus Mechanisms

Consensus mechanisms は、blockchain 上で安全かつ合意に基づいたトランザクション検証を実現します。

- **Proof of Work (PoW)** は、トランザクションの検証に計算能力を利用します。
- **Proof of Stake (PoS)** では、validator が一定量の tokens を保有する必要があります。PoW と比べてエネルギー消費を抑えられます。<sup>[[1]](#references)</sup>

## Bitcoin の基本

### トランザクション

Bitcoin のトランザクションでは、アドレス間で資金を送金します。トランザクションは digital signatures によって検証され、private key の所有者だけが送金を開始できるようになっています。<sup>[[2]](#references)</sup>

#### 主な構成要素:

- **Multisignature Transactions** では、トランザクションの承認に複数の署名が必要です。<sup>[[3]](#references)</sup>
- トランザクションは **inputs**（資金の送信元）、**outputs**（送信先）、**fees**（miner に支払う手数料）、**scripts**（トランザクションのルール）で構成されます。

### Lightning Network

channel 内で複数のトランザクションを実行し、最終状態のみを blockchain に記録することで、Bitcoin のスケーラビリティ向上を目指します。

## Bitcoin のプライバシーに関する懸念

**Common Input Ownership** や **UTXO Change Address Detection** などのプライバシー攻撃は、トランザクションのパターンを悪用します。**Mixers** や **CoinJoin** などの手法は、ユーザー間のトランザクションの関連性を見えにくくし、匿名性を高めます。

## 匿名で Bitcoin を入手する方法

現金での取引、mining、mixers の利用などが挙げられます。**CoinJoin** は複数のトランザクションを混ぜて追跡を困難にします。一方、**PayJoin** は CoinJoins を通常のトランザクションに見せかけ、プライバシーをさらに高めます。

# Bitcoin のプライバシー攻撃の概要

Bitcoin の世界では、トランザクションのプライバシーやユーザーの匿名性が懸念されることがよくあります。攻撃者が Bitcoin のプライバシーを侵害する一般的な手法を、以下に簡潔にまとめます。<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

複雑さから、異なるユーザーの inputs が1つのトランザクションにまとめられることは一般にまれです。そのため、**同じトランザクションに含まれる2つの input アドレスは、同一の所有者に属すると推測されることがよくあります**。

## **UTXO Change Address Detection**

UTXO（**Unspent Transaction Output**）は、トランザクション内で全額を使用する必要があります。一部だけを別のアドレスに送ると、残額は新しい change address に送られます。観察者は、この新しいアドレスが送信者のものだと推測できるため、プライバシーが侵害される可能性があります。

### 例

これを軽減するには、mixing services を使うか、複数のアドレスを使用して所有者を特定しにくくします。

## **Social Networks & Forums Exposure**

ユーザーがオンラインで Bitcoin アドレスを共有することがあり、その結果、**アドレスと所有者を簡単に結び付けられる**場合があります。

## **Transaction Graph Analysis**

トランザクションをグラフとして可視化することで、資金の流れに基づいてユーザー間の潜在的なつながりを明らかにできます。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

このヒューリスティックでは、複数の inputs と outputs を持つトランザクションを分析し、どの output が送信者に返される change なのかを推測します。

### 例

```bash
2 btc --> 4 btc
3 btc     1 btc
```

入力を追加したことで、お釣りの額がいずれか1つの入力額を上回ると、ヒューリスティックが誤判定する可能性があります。

## **強制的なアドレス再利用**

攻撃者は、受取人が今後のトランザクションでこれらを他の入力と組み合わせ、アドレス同士を紐付けることを期待して、以前に使われたアドレスに少額を送る場合があります。

### ウォレットの適切な動作

ウォレットは、このプライバシー leak を防ぐため、使用済みで残高が空のアドレスで受け取ったコインを再利用しないようにするべきです。

## **その他のブロックチェーン分析手法**

- **正確な支払額:** お釣りのないトランザクションは、同じユーザーが所有する2つのアドレス間で行われた可能性があります。
- **切りのよい金額:** トランザクションの金額が切りのよい数値なら、それは支払いである可能性があり、切りの悪い出力がお釣りである可能性があります。
- **ウォレットのフィンガープリンティング:** ウォレットごとにトランザクション作成パターンが異なるため、分析者は使用されたソフトウェアを特定し、お釣り用アドレスを推測できる可能性があります。
- **金額とタイミングの相関:** トランザクションの時刻や金額を公開すると、トランザクションが追跡可能になることがあります。

## **トラフィック分析**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックをIPアドレスに紐付け、ユーザーのプライバシーを侵害できる可能性があります。多くのBitcoinノードを運用する組織は、トランザクションを監視する能力が高まるため、特に注意が必要です。

## その他

プライバシー攻撃と防御策の包括的な一覧については、[Bitcoin WikiのBitcoin Privacy](https://en.bitcoin.it/wiki/Privacy)を参照してください。

# 匿名のBitcoinトランザクション

## 匿名でBitcoinを入手する方法

- **現金取引**: 現金でBitcoinを入手する。
- **現金の代替手段**: ギフトカードを購入し、オンラインでBitcoinと交換する。
- **マイニング**: Bitcoinを得る最もプライバシー性の高い方法はマイニングです。特に単独で行う場合が該当します。マイニングプールはマイナーのIPアドレスを把握している可能性があるためです。[マイニングプールの情報](https://en.bitcoin.it/wiki/Pooled_mining)
- **窃盗**: 理論上、Bitcoinを盗むことも匿名で入手する方法の1つですが、違法であり、推奨されません。

## ミキシングサービス

ミキシングサービスを利用すると、ユーザーは**Bitcoinを送信**し、代わりに**別のBitcoinを受け取る**ことができるため、元の所有者を追跡するのが難しくなります。ただし、ログを保存せず、実際にBitcoinを返すというサービスへの信頼が必要です。Bitcoinカジノも、ミキシングの代替手段です。

## CoinJoin

**CoinJoin**は、複数のユーザーによる複数のトランザクションを1つにまとめ、入力と出力を対応付けようとする人の作業を困難にします。効果的ではあるものの、入力と出力のサイズに特徴があるトランザクションは、依然として追跡される可能性があります。

CoinJoinが使われた可能性のあるトランザクションの例として、`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a`や`85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`があります。

詳しくは[CoinJoin](https://coinjoin.io/en)を参照してください。入金と後の出金を分離するEthereumのスマートコントラクトミキサーについては、[Tornado Cash](https://tornado.cash)を参照してください。

## PayJoin

CoinJoinの派生方式である**PayJoin**（P2EPとも呼ばれます）は、2者間（例: 顧客と販売者）のトランザクションを、CoinJoin特有の同額の出力を使わずに通常のトランザクションに見せかけます。そのため検出が非常に困難であり、トランザクション監視組織が利用する、入力の共通所有者に関する一般的なヒューリスティックを無効化できる可能性があります。

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

上記のようなトランザクションはPayJoinである可能性があり、標準的なbitcoinトランザクションと見分けがつかないまま、プライバシーを高められます。

**PayJoinの利用は、従来の監視手法を大きく妨げる可能性があり**、トランザクションのプライバシーを追求するうえで有望な進展です。

# 暗号資産のプライバシーを守るベストプラクティス

## **ウォレットの同期方法**

プライバシーとセキュリティを維持するには、ウォレットをブロックチェーンと同期することが重要です。特に次の2つの方法があります。

- **フルノード**: ブロックチェーン全体をダウンロードすることで、フルノードは最大限のプライバシーを実現します。これまでに行われたすべてのトランザクションがローカルに保存されるため、ユーザーがどのトランザクションやアドレスに関心があるのかを敵対者が特定することはできません。
- **クライアント側のブロックフィルタリング**: この方法では、ブロックチェーン内の各ブロックに対するフィルタを作成し、ネットワーク監視者に特定の関心事を明かさずに、ウォレットが関連するトランザクションを特定できるようにします。軽量ウォレットはこれらのフィルタをダウンロードし、ユーザーのアドレスと一致するものが見つかった場合にのみ、完全なブロックを取得します。

## **匿名性を高めるTorの利用**

Bitcoinはピアツーピアネットワーク上で動作するため、IPアドレスを隠し、ネットワークとのやり取りにおけるプライバシーを高める目的で、Torの利用が推奨されます。

## **アドレスの再利用を防ぐ**

プライバシーを守るには、トランザクションごとに新しいアドレスを使うことが重要です。アドレスを再利用すると、トランザクションが同一の主体に紐付けられ、プライバシーが損なわれる可能性があります。最新のウォレットは、設計上、アドレスの再利用を避けるようになっています。

## **トランザクションのプライバシーを守る戦略**

- **複数のトランザクション**: 支払いを複数のトランザクションに分割すると、金額を分かりにくくし、プライバシー侵害を狙う攻撃を阻止できます。
- **釣り銭の回避**: 釣り銭出力が不要なトランザクションを選ぶと、釣り銭を検出する手法を妨げ、プライバシーを高められます。
- **複数の釣り銭出力**: 釣り銭を避けられない場合でも、釣り銭出力を複数生成することで、プライバシーを向上させられます。

# **Monero: 匿名性の象徴**

Moneroは、トランザクションのプライバシーを最優先するように設計されています。

# **Ethereum: Gasとトランザクション**

## **Gasを理解する**

Gasは、Ethereumで操作を実行するために必要な計算量を表し、**gwei**単位で価格が設定されます。たとえば、2,310,000 gwei（または0.00231 ETH）のトランザクションには、gas limitとbase feeが含まれ、validatorによる取り込みを促すpriority feeが加わります。ユーザーは上限手数料を設定して過払いを防ぐことができ、余剰分は返金されます。<sup>[[5]](#references)</sup>

## **トランザクションの実行**

Ethereumのトランザクションには、送信者と受信者が含まれます。どちらもユーザーまたはスマートコントラクトのアドレスです。トランザクションには手数料が必要で、ブロックに含められなければなりません。トランザクションに含まれる主な情報は、受信者、送信者の署名、値、任意のデータ、gas limit、手数料です。特筆すべき点として、送信者のアドレスは署名から導出されるため、トランザクションデータに含める必要はありません。<sup>[[4]](#references)</sup>

これらの慣行や仕組みは、プライバシーとセキュリティを重視しながら暗号資産を利用する人にとって、基礎となるものです。

## Web3の価値中心型Red Teaming

- 価値を保有するコンポーネント（signer、oracle、bridge、automation）を洗い出し、誰がどのように資金を移動できるかを把握する。
- 各コンポーネントを関連するMITRE AADAPTのtacticに対応付け、権限昇格の経路を明らかにする。
- flash-loan/oracle/credential/cross-chainの攻撃チェーンを演習し、影響を検証するとともに、悪用可能な前提条件を記録する。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3署名ワークフローの侵害

- ウォレットUIへのサプライチェーン改ざんにより、署名直前にEIP-712 payloadを改変し、delegatecallベースのproxy乗っ取り（例: Safe masterCopyのslot-0上書き）に使える有効な署名を窃取できる。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## アカウント抽象化（ERC-4337）

- スマートアカウントでよくある障害モードには、`EntryPoint`のアクセス制御の回避、署名されていないgasフィールド、stateful validation、ERC-1271のreplay、validation後にrevertさせることによる手数料の流出がある。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## スマートコントラクトのセキュリティ

- テストスイートの見落としを見つけるためのmutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVMのゲスト完全性

proverが**zkVM**またはアプリケーション固有のproof circuitを使って主張を証明する場合、verifierが知るのは、**guest programが記述どおりに実行された**ということだけです。guestに**安全でないデシリアライズ**、**未定義動作**、または**意味上の制約の不足**があると、悪意あるproverは、**公開メトリクスや主張された不変条件が誤っている**にもかかわらず検証に通るproofを生成できる可能性があります。<sup>[[7]](#references)</sup>

### proof guest内の安全でないデシリアライズ

- proofによって隠されている場合でも、private witness/circuitのバイト列は**信頼できない攻撃者の入力**として扱う。
- バイト列が別の手段で事前に検証されていない限り、`rkyv::access_unchecked`のような検査を行わないヘルパーを使ったデシリアライズは避ける。
- 信頼できないシリアライズデータから読み込むenumのdiscriminant、relative pointer、長さ、インデックスは、制御フローやメモリアクセスに影響する前に検証する。

実践的な監査パターン:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind` のようなフィールドが enum であり、攻撃者が **範囲外の判別値** を注入できる場合、その値に対する後続の `match` はすべて疑わしいものとして扱ってください。

### Jump-table / UB によるカウンターバイパス

Rust が大きな `match` を **jump table** にコンパイルする場合、無効な enum の判別値によって **未定義の制御フロー** が発生する可能性があります。危険なパターンは次のとおりです。<sup>[[7]](#references)[[9]](#references)</sup>

1. ある `match` が **セキュリティ上重要なカウンタや制約** を更新する。
2. 2つ目の `match` が **実際の命令の意味論** を処理する。
3. 範囲外の判別値が最初の jump table の範囲外をインデックスし、2つ目の jump table に関連付けられたコードに到達する。

結果：操作は実行される一方で、計数処理はスキップされます。zkVM では、ゲート数や高コストな操作の数が少ないなど、不可能なメトリクスやその他の制限付きリソースの虚偽報告を含む証明を偽造できる可能性があります。

レビュー時のチェックリスト：

- witness/private input からデシリアライズされる、攻撃者が制御可能な enum を探す。
- 同じ opcode/kind フィールドに対する `match` が繰り返されていないか確認する。
- `unsafe`、未検証のデシリアライズ、大規模な opcode ディスパッチが組み合わさっている場合は、リスクが高いものとして扱う。
- 必要に応じて生成されたバイナリをリバースエンジニアリングする。jump table の配置は、ソースコードよりも重要な場合がある。

### 可逆／特化型インタープリターにおける意味論的制約の欠如

メモリ安全性だけを検証するのではなく、証明が強制することを意図した **意味論的ルール** も検証してください。

可逆／量子的な命令セットでは、異なる値である必要のあるオペランドが、実際に異なる値であることを制約で保証してください。Toffoli/CCX に似た操作が次のように実装されている場合：<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

ゲストが拒否しない場合、安全ではなくなる：

```text
op.q_control1 == op.q_control2 == op.q_target
```

その場合、遷移は次のように縮退します：

```text
q = q ^ (q & q) = 0
```

これは**決定論的なリセットプリミティブ**を作り出し、可逆性の前提を破ることで、本来意図されていない計算をより低コストで実行可能にします。リソース使用量を証明するproof systemでは、攻撃者が機能チェックを満たしながら、検証者が適用されていると信じているコストモデルを回避できる可能性があります。

### ZK systemでテストすること

- すべてのguest parserに、不正なwitness/private-inputエンコーディングを与えてfuzzingする。
- opcodeのdispatch前にenumの範囲が検証されることを確認する。
- operandのaliasingや、その他の無効な命令形式に対するsemantic checkを追加する。
- 報告されたカウンターや公開カウンターを、独立したreference implementationと比較する。
- guest programにバグがある場合、有効なproofでも**誤ったstatement**を証明してしまうことがある点に注意する。

## 状態依存の認可

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMMの悪用

DEXやAMM（Uniswap v4 hooks、丸め／精度の悪用、flash loanで閾値を超えさせるswapなど）の実践的な悪用について調べる場合は、以下を確認してください。

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

virtual balanceをキャッシュし、`supply == 0`のときにpoisoningされる可能性のある、複数アセットのweighted poolについては、以下を確認してください。

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia（Proof of stake）](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [公開鍵と秘密鍵の解説 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [マルチシグトランザクションとは？ - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [トランザクション | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gasと手数料 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [プライバシー - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Googleの量子暗号解析に対するzero-knowledge proofを破った](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [楕円曲線暗号通貨の量子脆弱性対策：リソース見積もりと緩和策（パッチ適用版）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bitsのproof-of-conceptリポジトリ](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
