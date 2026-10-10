# Blockchainと暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときに blockchain 上で実行されるプログラムとして定義され、中間者を介さずに合意の履行を自動化します。
- **Decentralized Applications (dApps)** は smart contracts を基盤とし、使いやすいフロントエンドと、透明性が高く監査可能なバックエンドを備えています。
- **Tokens & Coins** は用途が異なり、coins はデジタル通貨として機能する一方、tokens は特定の状況における価値や所有権を表します。
  - **Utility Tokens** はサービスへのアクセスを許可し、**Security Tokens** は資産の所有権を示します。
- **DeFi** は Decentralized Finance の略で、中央機関を介さずに金融サービスを提供します。
- **DEX** と **DAOs** は、それぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## Consensus Mechanisms

Consensus mechanisms は、blockchain 上のトランザクションが安全に検証され、合意されることを保証します。

- **Proof of Work (PoW)** は、トランザクションの検証に計算能力を利用します。
- **Proof of Stake (PoS)** では、validator が一定量の tokens を保有する必要があり、PoW と比べてエネルギー消費を抑えられます。<sup>[[1]](#references)</sup>

## Bitcoin の基本

### Transactions

Bitcoin transactions は、アドレス間で資金を送金します。トランザクションはデジタル署名によって検証され、秘密鍵の所有者だけが送金を開始できるようにします。<sup>[[2]](#references)</sup>

#### 主な構成要素:

- **Multisignature Transactions** では、トランザクションの承認に複数の署名が必要です。<sup>[[3]](#references)</sup>
- Transactions は、**inputs** (資金の送信元)、**outputs** (送信先)、**fees** (miner に支払われる手数料)、**scripts** (トランザクションのルール) で構成されます。

### Lightning Network

channel 内で複数のトランザクションを可能にし、最終状態のみを blockchain に送信することで、Bitcoin の scalability 向上を目指します。

## Bitcoin のプライバシーに関する懸念

**Common Input Ownership** や **UTXO Change Address Detection** などのプライバシー攻撃は、トランザクションのパターンを悪用します。**Mixers** や **CoinJoin** などの手法は、ユーザー間のトランザクションのつながりをわかりにくくすることで、匿名性を高めます。

## Bitcoin を匿名で入手する

方法には、現金での取引、mining、mixers の利用などがあります。**CoinJoin** は複数のトランザクションを混ぜて追跡を困難にし、**PayJoin** は CoinJoin を通常のトランザクションに見せかけ、プライバシーをさらに高めます。

# Bitcoin のプライバシー攻撃の概要

Bitcoin の世界では、トランザクションのプライバシーやユーザーの匿名性がしばしば懸念されます。以下に、攻撃者が Bitcoin のプライバシーを侵害する一般的な手法を簡単に説明します。<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

複雑さのため、異なるユーザーの inputs が1つのトランザクションにまとめられることは一般にまれです。そのため、**同じトランザクションに含まれる2つの入力アドレスは、同じ所有者に属すると推定されることがよくあります**。

## **UTXO Change Address Detection**

UTXO、すなわち **Unspent Transaction Output** は、トランザクション内で全額を使用する必要があります。その一部だけを別のアドレスに送ると、残額は新しいお釣り用アドレスに送られます。観察者は、この新しいアドレスが送信者のものだと推定できるため、プライバシーが損なわれる可能性があります。

### 例

これを軽減するには、mixing services を利用したり、複数のアドレスを使ったりして、所有者を特定しにくくする方法があります。

## **ソーシャルネットワークやフォーラムでの露出**

ユーザーが Bitcoin アドレスをオンラインで共有することがあり、その結果、**アドレスとその所有者を簡単に結び付けられる**場合があります。

## **Transaction Graph Analysis**

Transactions はグラフとして可視化でき、資金の流れに基づいてユーザー間のつながりが明らかになる可能性があります。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

この heuristic は、複数の inputs と outputs を持つトランザクションを分析し、どの output がお釣りとして送信者に戻るものかを推測します。

### 例

```bash
2 btc --> 4 btc
3 btc     1 btc
```

入力を追加した結果、change outputがどの単一の入力よりも大きくなると、heuristicが誤認する可能性があります。

## **強制的なアドレス再利用**

攻撃者は、過去に使用されたアドレスに少額を送金し、受取人が今後のトランザクションでその資金を他の入力とまとめることで、アドレス同士が関連付けられることを狙う場合があります。

### Walletの正しい動作

Walletは、このプライバシーleakを防ぐため、使用済みで残高がゼロのアドレスで受け取ったコインの使用を避けるべきです。

## **その他のBlockchain分析手法**

- **正確な支払い金額:** お釣りがないトランザクションは、同じユーザーが所有する2つのアドレス間で行われた可能性があります。
- **切りのよい金額:** トランザクションの金額が切りのよい数字であれば、支払いであることが示唆され、切りのよくない金額の出力はお釣りである可能性があります。
- **Walletのフィンガープリンティング:** Walletごとにトランザクション作成パターンが異なるため、分析者は使用されたソフトウェアを特定し、お釣り用アドレスを推測できる可能性があります。
- **金額とタイミングの相関:** トランザクションの時刻や金額を公開すると、トランザクションが追跡可能になることがあります。

## **トラフィック分析**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックをIPアドレスと関連付け、ユーザーのプライバシーを侵害できる可能性があります。多くのBitcoinノードを運用する組織は、トランザクションを監視する能力が高まるため、特にその傾向があります。

## さらに詳しく

プライバシー攻撃と防御の包括的な一覧は、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)を参照してください。

# 匿名のBitcoinトランザクション

## 匿名でBitcoinを入手する方法

- **現金取引**: 現金でbitcoinを入手する。
- **現金の代替手段**: ギフトカードを購入し、オンラインでbitcoinと交換する。
- **マイニング**: bitcoinを入手する最もプライバシー性の高い方法はマイニングです。特に単独で行う方法が適しています。マイニングプールはマイナーのIPアドレスを把握している可能性があるためです。[マイニングプールの情報](https://en.bitcoin.it/wiki/Pooled_mining)
- **窃盗**: 理論上、bitcoinを盗むことも匿名で入手する方法の1つですが、違法であり、推奨されません。

## Mixingサービス

Mixingサービスを利用すると、ユーザーは**bitcoinを送信**し、その代わりに**別のbitcoinを受け取る**ことができ、元の所有者を追跡するのが難しくなります。ただし、サービスがログを保存せず、実際にbitcoinを返すことを信頼する必要があります。Bitcoinカジノも、代替となるmixingの選択肢です。

## CoinJoin

**CoinJoin**は、複数のユーザーのトランザクションを1つにまとめ、入力と出力を対応付けようとする人の作業を複雑にします。効果的ではありますが、入力と出力のサイズが独特なトランザクションは、依然として追跡される可能性があります。

CoinJoinが使われた可能性のあるトランザクションの例として、`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a`および`85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`があります。

詳細は[CoinJoin](https://coinjoin.io/en)を参照してください。入金と後の出金を分離するEthereumのsmart-contract mixerについては、[Tornado Cash](https://tornado.cash)を参照してください。

## PayJoin

CoinJoinの派生方式である**PayJoin**（またはP2EP）は、2者（例: 顧客と販売者）の間のトランザクションを、CoinJoinに特徴的な同額の出力を使わずに、通常のトランザクションに見せかけます。そのため検出が非常に難しくなり、トランザクション監視組織が使う、共通入力の所有者を推定するheuristicを無効化できる可能性があります。

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

上記のようなトランザクションはPayJoinである可能性があり、標準的なbitcoinトランザクションと区別できないまま、プライバシーを高められます。

**PayJoinの利用は、従来の監視手法を大きく妨げる可能性があり**、トランザクションのプライバシーを追求するうえで有望な発展です。

# 暗号通貨のプライバシーに関するベストプラクティス

## **ウォレットの同期方法**

プライバシーとセキュリティを保つには、ブロックチェーンとウォレットを同期することが重要です。特に優れた方法は2つあります。

- **フルノード**: ブロックチェーン全体をダウンロードすることで、フルノードは最大限のプライバシーを確保します。これまでに行われたすべてのトランザクションがローカルに保存されるため、攻撃者がユーザーの関心のあるトランザクションやアドレスを特定することはできません。
- **クライアント側ブロックフィルタリング**: この方法では、ブロックチェーン内の各ブロックに対してフィルターを作成し、特定の関心をネットワーク監視者に明かさずに、ウォレットが関連するトランザクションを特定できるようにします。軽量ウォレットはこれらのフィルターをダウンロードし、ユーザーのアドレスとの一致が見つかった場合にのみ、ブロック全体を取得します。

## **匿名性のためのTorの利用**

Bitcoinはピアツーピアネットワーク上で動作するため、IPアドレスを隠し、ネットワークとの通信時のプライバシーを高める目的でTorの使用が推奨されます。

## **アドレスの再利用を防ぐ**

プライバシーを守るには、トランザクションごとに新しいアドレスを使うことが重要です。アドレスを再利用すると、トランザクションが同一の主体に結び付けられ、プライバシーが損なわれる可能性があります。最新のウォレットは、その設計によってアドレスの再利用を避けるよう促します。

## **トランザクションのプライバシー対策**

- **複数のトランザクション**: 支払いを複数のトランザクションに分割すると、トランザクション金額を分かりにくくし、プライバシー攻撃を妨げられます。
- **お釣りの回避**: お釣りの出力を必要としないトランザクションを選ぶことで、お釣りを特定する手法を妨げ、プライバシーを高められます。
- **複数のお釣り出力**: お釣りを避けられない場合でも、複数のお釣り出力を生成すれば、プライバシーを改善できます。

# **Monero: 匿名性の灯台**

Moneroは、トランザクションのプライバシーを優先するように設計されています。

# **Ethereum: Gasとトランザクション**

## **Gasを理解する**

Gasは、Ethereum上で処理を実行するために必要な計算量を表し、**gwei**で価格が設定されます。たとえば、2,310,000 gwei（または0.00231 ETH）のトランザクションには、Gas上限と基本手数料があり、バリデーターに取り込んでもらうための優先手数料も設定されます。ユーザーは最大手数料を設定することで、過払いを防げます。超過分は返金されます。<sup>[[5]](#references)</sup>

## **トランザクションの実行**

Ethereumのトランザクションには送信者と受信者が含まれ、どちらもユーザーアドレスまたはスマートコントラクトアドレスにできます。トランザクションには手数料が必要で、ブロックに含められなければなりません。トランザクションの必須情報には、受信者、送信者の署名、価値、任意のデータ、Gas上限、手数料が含まれます。特筆すべき点として、送信者のアドレスは署名から導出されるため、トランザクションデータに含める必要はありません。<sup>[[4]](#references)</sup>

これらの慣行や仕組みは、プライバシーとセキュリティを重視しながら暗号通貨を利用したい人にとって、基礎となるものです。

## Value-Centric Web3 Red Teaming

- 価値を持つコンポーネント（signer、oracle、bridge、automation）を棚卸しし、誰がどのように資金を移動できるかを把握する。
- 各コンポーネントを関連するMITRE AADAPTの戦術に対応付け、権限昇格の経路を明らかにする。
- flash-loan/oracle/credential/cross-chainの攻撃チェーンをリハーサルし、影響を検証して、悪用可能な前提条件を記録する。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3署名ワークフローの侵害

- wallet UIへのサプライチェーン改ざんにより、署名直前にEIP-712 payloadを改変し、delegatecallベースのproxy takeover（例: Safe masterCopyのslot-0上書き）に利用できる有効な署名を窃取する可能性があります。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- smart accountでよくある障害モードには、`EntryPoint`のアクセス制御の回避、署名されていないGasフィールド、stateful validation、ERC-1271のリプレイ、validation後のrevertによる手数料の枯渇があります。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## スマートコントラクトのセキュリティ

- テストスイートの盲点を見つけるためのmutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guestの完全性

proverが**zkVM**またはアプリケーション固有のproof circuitを使って主張を証明する場合、verifierが知るのは、**guest programが記述どおりに実行された**ということだけです。guestに**安全でないデシリアライズ**、**未定義動作**、または**意味上の制約の不足**があると、悪意のあるproverは、検証には成功するものの、**公開されたメトリクスや主張された不変条件が偽である**proofを生成する可能性があります。<sup>[[7]](#references)</sup>

### proof guest内の安全でないデシリアライズ

- private witness/circuitのバイト列は、proofによって隠されていても、**信頼できない攻撃者入力**として扱う。
- バイト列がすでに別の方法で検証されている場合を除き、`rkyv::access_unchecked`など、チェックを行わないヘルパーでデシリアライズしない。
- 信頼できないシリアライズ済みデータから読み込まれるenumのdiscriminant、relative pointer、length、indexは、制御フローやメモリアクセスに影響する前に検証する。

実践的な監査パターン:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind`のようなフィールドがenumであり、攻撃者が**範囲外の判別値**を注入できる場合、その値に対する後続の`match`はすべて疑わしいものとして扱います。

### Jump-table / UBによるカウンタ回避

Rustが大きな`match`を**jump table**に変換する場合、無効なenum判別値によって**未定義の制御フロー**が発生する可能性があります。危険なパターンは次のとおりです。<sup>[[7]](#references)[[9]](#references)</sup>

1. 1つ目の`match`が**セキュリティ上重要なカウンタや制約**を更新する。
2. 2つ目の`match`が**実際の命令の意味論**を実行する。
3. 範囲外の判別値が1つ目のjump tableの範囲外をインデックスし、2つ目のjump tableに関連付けられたコードへ到達する。

結果：操作は実行される一方で、計上処理はスキップされます。zkVMでは、ゲート数、コストの高い操作の数、その他の制限付きリソースを実際より少なく報告するなど、不可能なメトリクスを示す証明を偽造できる可能性があります。

確認項目：

- witness/private inputからデシリアライズされる、攻撃者制御のenumを探す。
- 同じopcode/kindフィールドに対して、繰り返し使われる`match`文を調べる。
- `unsafe`、未検証のデシリアライズ、大規模なopcode dispatchが組み合わさっている場合は、高リスクとして扱う。
- 必要に応じて生成されたバイナリをリバースエンジニアリングする。jump tableのレイアウトは、ソースコード以上に重要な場合がある。

### 可逆/特化型インタプリタにおける意味論的制約の欠如

メモリ安全性だけを検証してはいけません。証明で強制するべき**意味論上のルール**も検証してください。

可逆/量子風の命令セットでは、異なる必要があるオペランドが実際に異なるよう制約されていることを確認してください。Toffoli/CCX風の操作が次のように実装されている場合：<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

ゲストが拒否しない場合、危険になる：

```text
op.q_control1 == op.q_control2 == op.q_target
```

その場合、遷移は次の形に集約されます：

```text
q = q ^ (q & q) = 0
```

これは**決定論的なリセットプリミティブ**を生み出し、可逆性の前提を崩すとともに、意図しない計算をより低コストで可能にします。リソース使用量を証明するシステムでは、攻撃者が機能チェックを満たしつつ、検証者が適用されていると信じているコストモデルを回避できる可能性があります。

### ZKシステムでテストすべきこと

- 不正なwitness/private-inputエンコーディングを使い、すべてのゲストパーサーに対してファジングを行う。
- opcodeのディスパッチ前にenumの範囲が検証されることを確認する。
- オペランドのエイリアシングや、その他の無効な命令形式に対するセマンティックチェックを追加する。
- 報告されたカウンター／公開カウンターを、独立した参照実装と照合する。
- ゲストプログラムにバグがあれば、有効な証明でも**誤った命題**を証明している可能性があることを忘れない。

## 状態依存の認可

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMMの悪用

DEXやAMMの実践的な悪用（Uniswap v4 hooks、丸め／精度の悪用、flash loanで増幅した閾値突破スワップ）を調査している場合は、以下を確認してください。

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

仮想残高をキャッシュし、`supply == 0` のときに汚染される可能性があるマルチアセットの加重プールについては、以下を調べてください。

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [プルーフ・オブ・ステーク - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [公開鍵と秘密鍵の解説 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [マルチシグトランザクションとは？ - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [トランザクション | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gasと手数料 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [プライバシー - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Googleの量子暗号解析に対するゼロ知識証明を破った](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [楕円曲線暗号通貨の量子脆弱性対策：リソース推定と緩和策（パッチ適用版）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bitsの概念実証リポジトリ](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
