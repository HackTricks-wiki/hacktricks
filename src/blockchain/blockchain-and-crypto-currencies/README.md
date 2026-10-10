# Blockchain と暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **スマートコントラクト**は、特定の条件が満たされたときに blockchain 上で実行されるプログラムです。仲介者なしで合意内容の実行を自動化します。
- **分散型アプリケーション（dApps）**はスマートコントラクトを基盤とし、使いやすいフロントエンドと、透明性が高く監査可能なバックエンドを備えます。
- **トークンとコイン**は、コインがデジタル通貨として機能するのに対し、トークンは特定の状況における価値や所有権を表す点で異なります。
  - **ユーティリティトークン**はサービスへのアクセスを許可し、**セキュリティトークン**は資産の所有権を示します。
- **DeFi**は Decentralized Finance（分散型金融）の略で、中央機関を介さない金融サービスを提供します。
- **DEX**と**DAO**は、それぞれ分散型取引所プラットフォームと分散型自律組織を指します。

## コンセンサスメカニズム

コンセンサスメカニズムは、blockchain 上のトランザクション検証を安全に行い、合意を確立します。

- **Proof of Work（PoW）**は、トランザクションの検証に計算能力を利用します。
- **Proof of Stake（PoS）**では、バリデーターが一定量のトークンを保有する必要があり、PoW と比べてエネルギー消費を抑えられます。<sup>[[1]](#references)</sup>

## Bitcoin の基本

### トランザクション

Bitcoin のトランザクションでは、アドレス間で資金を移転します。トランザクションはデジタル署名によって検証され、秘密鍵の所有者だけが送金を開始できるようになっています。<sup>[[2]](#references)</sup>

#### 主な構成要素：

- **マルチシグトランザクション**では、トランザクションを承認するために複数の署名が必要です。<sup>[[3]](#references)</sup>
- トランザクションは、**入力**（資金の送信元）、**出力**（送信先）、**手数料**（マイナーへの支払い）、**スクリプト**（トランザクションのルール）で構成されます。

### Lightning Network

チャネル内で複数のトランザクションを行い、最終状態のみを blockchain にブロードキャストすることで、Bitcoin のスケーラビリティ向上を目指します。

## Bitcoin のプライバシーに関する懸念

**共通入力の所有者特定**や**UTXO のお釣りアドレス検出**などのプライバシー攻撃は、トランザクションのパターンを悪用します。**Mixers**や**CoinJoin**などの手法は、ユーザー間のトランザクションのつながりを分かりにくくし、匿名性を高めます。

## 匿名で Bitcoin を入手する

現金取引、マイニング、Mixers の利用などの方法があります。**CoinJoin**は複数のトランザクションを混ぜて追跡を困難にし、**PayJoin**はCoinJoinを通常のトランザクションに見せかけてプライバシーをさらに高めます。

# Bitcoin のプライバシー攻撃の概要

Bitcoin の世界では、トランザクションのプライバシーとユーザーの匿名性がしばしば懸念されます。以下では、攻撃者がBitcoinのプライバシーを侵害する一般的な手法を簡単に説明します。<sup>[[6]](#references)</sup>

## **共通入力の所有者に関する仮定**

複雑さを伴うため、異なるユーザーの入力が1つのトランザクションにまとめられることは一般にまれです。そのため、**同じトランザクション内の2つの入力アドレスは、同じ所有者のものと見なされることがよくあります**。

## **UTXO のお釣りアドレス検出**

UTXO（**未使用トランザクション出力**）は、トランザクションで全額を使う必要があります。その一部だけが別のアドレスに送られた場合、残額は新しいお釣りアドレスに送られます。観察者は、この新しいアドレスが送信者のものだと推測できるため、プライバシーが損なわれる可能性があります。

### 例

これを軽減するには、ミキシングサービスを利用したり、複数のアドレスを使用したりして、所有者を分かりにくくする方法があります。

## **ソーシャルネットワークやフォーラムでの露出**

ユーザーがBitcoinアドレスをオンラインで共有することがあり、その場合、**アドレスとその所有者を簡単に結び付けられます**。

## **トランザクショングラフ分析**

トランザクションをグラフとして可視化することで、資金の流れに基づいてユーザー間のつながりを推測できる場合があります。

## **不要な入力のヒューリスティック（最適なお釣りのヒューリスティック）**

このヒューリスティックは、複数の入力と出力があるトランザクションを分析し、どの出力がお釣りとして送信者に戻るものかを推測します。

### 例

```bash
2 btc --> 4 btc
3 btc     1 btc
```

入力を追加した結果、changeの出力額がどの入力額よりも大きくなると、ヒューリスティックが誤解する可能性があります。

## **強制的なアドレス再利用**

攻撃者は、以前使われたアドレスに少額を送金し、受取人が将来のトランザクションでそれらを他の入力と組み合わせることで、アドレス同士が関連付けられることを狙う場合があります。

### 適切なウォレットの動作

ウォレットは、プライバシーのleakを防ぐため、すでに使用済みで残高がゼロのアドレスで受け取ったコインの使用を避けるべきです。

## **その他のブロックチェーン分析手法**

- **正確な支払額:** changeのないトランザクションは、同じユーザーが所有する2つのアドレス間で行われた可能性があります。
- **切りのよい金額:** トランザクションの金額が切りのよい数値なら、支払いであることが示唆され、端数のある出力はchangeである可能性があります。
- **ウォレットのフィンガープリンティング:** ウォレットごとにトランザクション作成パターンが異なるため、分析者は使用されたソフトウェアを特定し、changeアドレスを推測できる可能性があります。
- **金額とタイミングの相関:** トランザクションの時刻や金額を明らかにすると、トランザクションを追跡される可能性があります。

## **トラフィック分析**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックをIPアドレスに関連付け、ユーザーのプライバシーを侵害できる可能性があります。多くのBitcoinノードを運用する組織では、トランザクションを監視する能力が高まるため、特に注意が必要です。

## その他

プライバシー攻撃と防御の包括的なリストについては、[Bitcoin WikiのBitcoin Privacy](https://en.bitcoin.it/wiki/Privacy)を参照してください。

# 匿名のBitcoinトランザクション

## Bitcoinを匿名で入手する方法

- **現金取引**: 現金でbitcoinを入手する方法です。
- **現金の代替手段**: ギフトカードを購入し、オンラインでbitcoinと交換する方法です。
- **マイニング**: bitcoinを得る最もプライバシー性の高い方法はマイニングです。特に単独で行う場合は、マイニングプールがマイナーのIPアドレスを把握している可能性があるため、よりプライバシーを保てます。[マイニングプールに関する情報](https://en.bitcoin.it/wiki/Pooled_mining)
- **窃盗**: 理論上、bitcoinを盗むことも匿名で入手する方法になり得ますが、違法であり、推奨されません。

## ミキシングサービス

ミキシングサービスを利用すると、ユーザーは**bitcoinを送信**し、代わりに**別のbitcoinを受け取る**ことができ、元の所有者を追跡しにくくなります。ただし、ログを保存せず、実際にbitcoinを返すサービスであることを信頼する必要があります。代替となるミキシング手段には、Bitcoinカジノがあります。

## CoinJoin

**CoinJoin**は、複数のユーザーのトランザクションを1つにまとめ、入力と出力を対応付けようとする作業を困難にします。効果的ではありますが、入力と出力のサイズに特徴があるトランザクションは、追跡される可能性があります。

CoinJoinが使われた可能性のあるトランザクションの例として、`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a`と`85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`があります。

詳しくは、[CoinJoin](https://coinjoin.io/en)を参照してください。入金と後の出金を分離するEthereumのスマートコントラクトミキサーについては、[Tornado Cash](https://tornado.cash)を参照してください。

## PayJoin

CoinJoinの変種である**PayJoin**（またはP2EP）は、2者（例: 顧客と販売者）の間のトランザクションを、CoinJoinに特徴的な同額の出力を使わずに通常のトランザクションに見せかけます。そのため検出は非常に困難であり、トランザクション監視組織が利用する共通入力所有権ヒューリスティックを無効化できる可能性があります。

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

上記のようなトランザクションはPayJoinである可能性があり、標準的なbitcoinトランザクションと見分けがつかないまま、プライバシーを高められます。

**PayJoinの利用は従来の監視手法を大きく妨げる可能性があり**、取引のプライバシーを実現するうえで有望な発展です。

# 暗号通貨のプライバシーに関するベストプラクティス

## **Walletの同期方法**

プライバシーとセキュリティを保つには、walletをblockchainと同期することが重要です。特に有効な方法は2つあります。

- **Full node**: blockchain全体をダウンロードすることで、full nodeは最大限のプライバシーを確保します。これまでのすべてのトランザクションがローカルに保存されるため、攻撃者がユーザーの関心対象であるトランザクションやアドレスを特定することはできません。
- **クライアント側のblockフィルタリング**: blockchain内の各blockに対するフィルタを作成し、特定の関心対象をネットワーク上の観測者に公開せずに、walletが関連するトランザクションを識別できるようにする方法です。軽量walletはこのフィルタをダウンロードし、ユーザーのアドレスとの一致が見つかった場合にのみ、完全なblockを取得します。

## **匿名性を高めるためのTorの利用**

Bitcoinはピアツーピアネットワーク上で動作するため、Torを使ってIPアドレスを隠し、ネットワークとの通信時のプライバシーを高めることが推奨されます。

## **アドレスの再利用を防ぐ**

プライバシーを守るには、トランザクションごとに新しいアドレスを使うことが重要です。アドレスを再利用すると、トランザクションが同一の主体に結び付けられ、プライバシーが損なわれる可能性があります。最新のwalletは、設計上アドレスの再利用を避けるようになっています。

## **トランザクションのプライバシー対策**

- **複数のトランザクション**: 支払いを複数のトランザクションに分割すると、取引額を分かりにくくし、プライバシー攻撃を阻止できます。
- **お釣りの回避**: お釣りの出力が不要なトランザクションを選ぶと、お釣りの検出手法を妨げ、プライバシーを高められます。
- **複数のお釣り出力**: お釣りを避けられない場合でも、お釣りの出力を複数生成すれば、プライバシーを高められます。

# **Monero: 匿名性の象徴**

Moneroは、トランザクションのプライバシーを最優先するよう設計されています。

# **Ethereum: Gasとトランザクション**

## **Gasを理解する**

Gasは、Ethereum上で操作を実行するために必要な計算量を表し、**gwei**単位で価格が設定されます。たとえば、2,310,000 gwei（または0.00231 ETH）かかるトランザクションには、gas limitとbase feeがあり、validatorによる取り込みを促すためのpriority feeも設定できます。ユーザーは上限手数料を設定して過払いを防ぐことができ、余剰分は返金されます。<sup>[[5]](#references)</sup>

## **トランザクションの実行**

Ethereumのトランザクションには、送信者と受信者が含まれます。これらはユーザーまたはsmart contractのアドレスです。トランザクションには手数料が必要で、blockに含められなければなりません。トランザクションに含まれる重要な情報は、受信者、送信者の署名、価値、任意のデータ、gas limit、手数料です。特に、送信者のアドレスは署名から導出されるため、トランザクションデータに含める必要はありません。<sup>[[4]](#references)</sup>

これらのプラクティスと仕組みは、プライバシーとセキュリティを優先しながら暗号通貨を利用したい人にとって、基本となるものです。

## 価値を重視したWeb3 Red Teaming

- 資金を動かせる主体とその方法を把握するため、価値を持つコンポーネント（signer、oracle、bridge、automation）を洗い出す。
- 各コンポーネントを関連するMITRE AADAPTの戦術に対応付け、権限昇格の経路を明らかにする。
- flash-loan／oracle／credential／cross-chainの攻撃チェーンをリハーサルし、影響を検証するとともに、悪用可能な前提条件を記録する。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3署名ワークフローの侵害

- wallet UIのサプライチェーン改ざんにより、署名直前にEIP-712 payloadを変更し、delegatecallベースのproxy乗っ取り（例: Safe masterCopyのslot-0上書き）に使える有効な署名を窃取できる。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- smart accountでよくある障害モードには、`EntryPoint`のアクセス制御の回避、未署名のgasフィールド、stateful validation、ERC-1271のリプレイ、検証後のrevertによる手数料の枯渇などがあります。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- テストスイートの見落としを見つけるmutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guestの完全性

proverが**zkVM**またはアプリケーション固有のproof circuitを使って主張を証明する場合、verifierが把握できるのは、**guest programが記述どおりに実行されたこと**だけです。guestに**安全でないデシリアライズ**、**未定義動作**、または**意味上の制約の欠落**があると、悪意あるproverは、proofが検証に通る一方で、**公開された指標や主張された不変条件が偽である**ようなproofを生成できる可能性があります。<sup>[[7]](#references)</sup>

### proof guest内での安全でないデシリアライズ

- private witness／circuitのバイト列は、proofによって隠されていても、**信頼できない攻撃者入力**として扱う。
- バイト列が事前に別の方法で検証されていない限り、`rkyv::access_unchecked`などの検証を行わないヘルパーでデシリアライズしない。
- 信頼できないシリアライズ済みデータから読み込まれるenum discriminant、relative pointer、length、indexは、制御フローやメモリアクセスに影響する前に検証する。

実践的な監査パターン:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind` のようなフィールドが enum で、攻撃者が **範囲外の discriminant** を注入できる場合、その値に対する下流のすべての `match` が疑わしくなります。

### Jump-table / UB によるカウンター回避

Rust が大きな `match` を **jump table** にコンパイルする場合、無効な enum discriminant によって **未定義の制御フロー** が発生することがあります。危険なパターンは次のとおりです。<sup>[[7]](#references)[[9]](#references)</sup>

1. ある `match` が **セキュリティ上重要なカウンターや制約** を更新する。
2. 2つ目の `match` が **実際の命令の意味論** を実行する。
3. 範囲外の discriminant が最初の jump table の範囲外をインデックスし、2つ目の jump table に関連付けられたコードに到達する。

結果: 操作は実行される一方で、計上処理はスキップされます。zkVM では、ゲート数や高コストの操作数が少なく報告されるなど、あり得ないメトリクスを示す偽造証明を作成できる可能性があります。

確認事項:

- witness/private input からデシリアライズされる、攻撃者が制御可能な enum を探す。
- 同じ opcode/kind フィールドに対する `match` が繰り返されていないか調べる。
- `unsafe`、チェックなしのデシリアライズ、大規模な opcode dispatch の組み合わせは高リスクとして扱う。
- 必要に応じて生成されたバイナリをリバースエンジニアリングする。jump table の配置はソースコード以上に重要な場合がある。

### 可逆/特殊化インタープリターにおける意味論的制約の欠落

メモリ安全性だけを検証するのではなく、証明が強制するべき **意味論的ルール** も検証してください。

可逆/量子的な命令セットでは、異なる必要があるオペランドが実際に異なるよう制約されていることを確認してください。Toffoli/CCX に類似した操作が次のように実装されている場合:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

ゲスト側が拒否しないと安全でなくなる:

```text
op.q_control1 == op.q_control2 == op.q_target
```

その場合、遷移は次のように簡約されます:

```text
q = q ^ (q & q) = 0
```

これは**決定論的なリセットプリミティブ**を生み出し、可逆性の前提を崩して、より低コストで意図しない計算を可能にします。リソース使用量を証明するproof systemでは、攻撃者が機能チェックを満たしながら、verifierが適用されていると考えるコストモデルを回避できる可能性があります。

### ZKシステムでテストすること

- 形式が不正なwitness/private-inputエンコーディングを使い、すべてのguest parserをfuzzする。
- opcodeのdispatch前にenumの範囲が検証されることを確認する。
- operand aliasingやその他の無効な命令形式に対するsemantic checkを追加する。
- 報告された／公開されたcounterを、独立したreference implementationと比較する。
- guest programにバグがあれば、有効なproofでも**誤ったstatement**を証明してしまうことがある点に注意する。

## State依存の認可

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEXやAMMの実践的なexploit（Uniswap v4 hooks、丸め／精度の悪用、flash loanで増幅した閾値超過swap）を調査している場合は、こちらを確認してください。

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

仮想残高をキャッシュし、`supply == 0`のときに汚染される可能性があるマルチアセットのweighted poolについては、こちらを調査してください。

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [公開鍵と秘密鍵の解説 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [マルチシグトランザクションとは？ - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [トランザクション | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gasと手数料 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [プライバシー - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Googleの量子暗号解析に対するzero-knowledge proofを破った](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [量子脆弱性に対する楕円曲線暗号通貨のセキュリティ強化：リソース推定と緩和策（修正版）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bitsのproof-of-conceptリポジトリ](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
