# Blockchainと暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときに blockchain 上で実行されるプログラムであり、仲介者を介さずに契約の履行を自動化します。
- **Decentralized Applications (dApps)** は smart contracts を基盤として構築され、使いやすいフロントエンドと、透明性が高く監査可能なバックエンドを備えています。
- **Tokens & Coins** は、coins がデジタル通貨として機能する一方で、tokens は特定の状況における価値や所有権を表すという違いがあります。
  - **Utility Tokens** はサービスへのアクセスを可能にし、**Security Tokens** は資産の所有権を示します。
- **DeFi** は Decentralized Finance の略で、中央管理者を介さない金融サービスを提供します。
- **DEX** と **DAOs** は、それぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## コンセンサスメカニズム

コンセンサスメカニズムは、blockchain 上のトランザクション検証における安全性と合意を保証します。

- **Proof of Work (PoW)** は、トランザクションの検証に計算能力を利用します。
- **Proof of Stake (PoS)** では、validator が一定量の tokens を保有する必要があり、PoW と比べてエネルギー消費を抑えられます。<sup>[[1]](#references)</sup>

## Bitcoinの基礎

### トランザクション

Bitcoinのトランザクションでは、アドレス間で資金を送金します。トランザクションはデジタル署名によって検証されるため、秘密鍵の所有者だけが送金を開始できます。<sup>[[2]](#references)</sup>

#### 主な構成要素:

- **Multisignature Transactions** では、トランザクションの承認に複数の署名が必要です。<sup>[[3]](#references)</sup>
- トランザクションは、**inputs**（資金の送金元）、**outputs**（送金先）、**fees**（minerへの支払い）、**scripts**（トランザクションのルール）で構成されます。

### Lightning Network

channel 内で複数のトランザクションを実行し、最終状態のみを blockchain に送信することで、Bitcoinのスケーラビリティを高めることを目指します。

## Bitcoinのプライバシーに関する懸念

**Common Input Ownership** や **UTXO Change Address Detection** などのプライバシー攻撃は、トランザクションのパターンを悪用します。**Mixers** や **CoinJoin** などの手法は、ユーザー間のトランザクションのつながりを見えにくくすることで、匿名性を高めます。

## 匿名でBitcoinを入手する

現金取引、mining、mixers の利用などの方法があります。**CoinJoin** は複数のトランザクションを混ぜ合わせて追跡を困難にし、**PayJoin** は CoinJoin を通常のトランザクションに見せかけて、プライバシーをさらに高めます。

# Bitcoinのプライバシー攻撃の概要

Bitcoinの世界では、トランザクションのプライバシーとユーザーの匿名性がしばしば懸念の対象になります。ここでは、攻撃者がBitcoinのプライバシーを侵害する一般的な手法をいくつか簡単に紹介します。<sup>[[6]](#references)</sup>

## **共通入力の所有者に関する仮定**

異なるユーザーのinputsが1つのトランザクションにまとめられることは、複雑さのため一般にまれです。そのため、**同じトランザクション内の2つの入力アドレスは、同じ所有者のものだと推定されることがよくあります**。

## **UTXOのお釣りアドレスの検出**

UTXO（**Unspent Transaction Output**）は、トランザクションで全額を使用する必要があります。一部だけを別のアドレスに送ると、残額は新しいお釣りアドレスに送られます。観察者は、この新しいアドレスが送信者のものだと推定できるため、プライバシーが損なわれる可能性があります。

### 例

これを軽減するには、mixingサービスを利用したり、複数のアドレスを使ったりして、所有者を特定しにくくする方法があります。

## **ソーシャルネットワークやフォーラムでの露出**

ユーザーがBitcoinアドレスをオンラインで共有することがあり、**そのアドレスと所有者を簡単に結び付けられる**可能性があります。

## **トランザクショングラフ分析**

トランザクションをグラフとして可視化すると、資金の流れに基づいてユーザー間の潜在的なつながりが明らかになることがあります。

## **不要な入力のヒューリスティック（最適なお釣りのヒューリスティック）**

このヒューリスティックは、複数のinputsとoutputsを持つトランザクションを分析し、どのoutputがお釣りとして送信者に戻されたものかを推測します。

### 例

```bash
2 btc --> 4 btc
3 btc     1 btc
```

入力を増やした結果、change output がどの単一の input よりも大きくなると、ヒューリスティックが誤認する可能性があります。

## **Forced Address Reuse**

攻撃者は、以前使われたアドレスに少額を送ることがあります。受取人が将来の取引でそれらをほかの入力とまとめることで、アドレス同士が結び付けられるのを狙っています。

### Correct Wallet Behavior

このプライバシー leak を防ぐため、ウォレットは使用済みで残高がゼロのアドレスに届いたコインを使わないようにするべきです。

## **Other Blockchain Analysis Techniques**

- **正確な支払い額:** お釣りがない取引は、同じユーザーが所有する2つのアドレス間で行われた可能性があります。
- **切りのよい金額:** 取引額が切りのよい数字なら、それは支払いであり、切りのよくない出力がお釣りである可能性があります。
- **Wallet Fingerprinting:** ウォレットごとに取引を作成するパターンが異なるため、分析者は使用ソフトウェアを特定し、お釣りアドレスを推測できる場合があります。
- **金額とタイミングの相関:** 取引の時刻や金額を明かすと、取引を追跡される可能性があります。

## **Traffic Analysis**

ネットワークトラフィックを監視することで、攻撃者は取引やブロックをIPアドレスに結び付け、ユーザーのプライバシーを侵害できる可能性があります。多数のBitcoinノードを運用する主体は、取引を監視する能力が高まるため、特に注意が必要です。

## その他

プライバシー攻撃と防御の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)を参照してください。

# 匿名でのBitcoin取引

## 匿名でBitcoinを入手する方法

- **現金取引**: 現金でbitcoinを入手する。
- **現金の代替手段**: ギフトカードを購入し、オンラインでbitcoinと交換する。
- **マイニング**: bitcoinを得る最もプライバシーを保ちやすい方法はマイニングです。特に単独で行う場合が該当します。マイニングプールはマイナーのIPアドレスを知る可能性があるためです。[マイニングプールに関する情報](https://en.bitcoin.it/wiki/Pooled_mining)
- **盗難**: 理論上、bitcoinを盗むことも匿名で入手する方法になり得ますが、違法であり、推奨されません。

## Mixing Services

mixing serviceを使うと、ユーザーは**bitcoinを送信**し、代わりに**別のbitcoinを受け取る**ことができます。そのため、元の所有者を追跡するのが難しくなります。ただし、ログを保存せず、実際にbitcoinを返すサービスだと信頼する必要があります。Bitcoinカジノも代替のmixing手段です。

## CoinJoin

**CoinJoin**は、異なるユーザーによる複数の取引を1つにまとめることで、入力と出力を照合しようとする者の作業を難しくします。効果的ではありますが、入力と出力のサイズが特異な取引は、依然として追跡される可能性があります。

CoinJoinが使われた可能性のある取引の例として、`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a`と`85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`があります。

詳しくは[CoinJoin](https://coinjoin.io/en)を参照してください。入金と後の出金を分離するEthereum smart-contract mixerについては、[Tornado Cash](https://tornado.cash)を参照してください。

## PayJoin

CoinJoinの一種である**PayJoin**（またはP2EP）は、2者間（例: 顧客と販売者）の取引を通常の取引に見せかけます。CoinJoinに特徴的な、同額の出力はありません。そのため検出は非常に困難であり、取引監視主体が使用する、共通入力の所有権に基づく一般的なヒューリスティックを無効化できる可能性があります。

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

上記のようなトランザクションはPayJoinの可能性があり、標準的なビットコイン取引と見分けがつかないまま、プライバシーを高められます。

**PayJoinの利用は、従来の監視手法を大きく妨げる可能性があり**、取引のプライバシーを追求するうえで有望な取り組みです。

# 暗号資産のプライバシーを守るためのベストプラクティス

## **ウォレットの同期方法**

プライバシーとセキュリティを保つには、ウォレットをブロックチェーンと同期することが重要です。主な方法は次の2つです。

- **Full node**: ブロックチェーン全体をダウンロードすることで、Full nodeは最大限のプライバシーを確保します。これまでに行われたすべてのトランザクションがローカルに保存されるため、攻撃者がユーザーの関心のあるトランザクションやアドレスを特定することはできません。
- **クライアント側のブロックフィルタリング**: ブロックチェーン内の各ブロックに対してフィルターを作成し、ネットワーク上の監視者に特定の関心事を明かさずに、ウォレットが関連するトランザクションを特定できるようにする方法です。軽量ウォレットはこれらのフィルターをダウンロードし、ユーザーのアドレスとの一致が見つかった場合にのみ、ブロック全体を取得します。

## **匿名性のためのTorの利用**

Bitcoinはピアツーピアネットワーク上で動作するため、IPアドレスを隠し、ネットワークとのやり取りにおけるプライバシーを高めるために、Torの利用が推奨されます。

## **アドレスの再利用を防ぐ**

プライバシーを守るには、トランザクションごとに新しいアドレスを使うことが重要です。アドレスを再利用すると、トランザクションが同一の主体に関連付けられ、プライバシーが損なわれる可能性があります。最新のウォレットは、設計によってアドレスの再利用を防いでいます。

## **トランザクションのプライバシーを守る方法**

- **複数のトランザクション**: 支払いを複数のトランザクションに分けると、取引金額を隠し、プライバシー攻撃を防ぎやすくなります。
- **お釣りの回避**: お釣りの出力を必要としないトランザクションを選ぶと、お釣りの検出手法を妨げ、プライバシーを高められます。
- **複数のお釣り出力**: お釣りを避けられない場合でも、複数のお釣り出力を生成すれば、プライバシーを向上できます。

# **Monero: 匿名性の旗手**

Moneroは、トランザクションのプライバシーを最優先するよう設計されています。

# **Ethereum: Gasとトランザクション**

## **Gasについて**

GasはEthereum上で操作を実行するために必要な計算量を測る単位で、**gwei**で価格が設定されます。たとえば、2,310,000 gwei（または0.00231 ETH）のトランザクションには、Gas limitと基本手数料があり、バリデーターに取り込んでもらうための優先手数料も設定されます。ユーザーは上限手数料を設定して過払いを防ぐことができ、余剰分は返金されます。<sup>[[5]](#references)</sup>

## **トランザクションの実行**

Ethereumのトランザクションには送信者と受信者があり、どちらもユーザーまたはスマートコントラクトのアドレスを指定できます。トランザクションには手数料が必要で、ブロックに取り込まれなければなりません。トランザクションに含まれる重要な情報は、受信者、送信者の署名、値、任意のデータ、Gas limit、手数料です。特に、送信者のアドレスは署名から導出されるため、トランザクションデータに含める必要はありません。<sup>[[4]](#references)</sup>

これらの方法と仕組みは、プライバシーとセキュリティを重視しながら暗号資産を利用したい人にとって、基礎となるものです。

## Web3の価値中心型Red Teaming

- 資金を移動できる主体とその方法を把握するため、価値を持つコンポーネント（署名者、オラクル、ブリッジ、自動化機構）を一覧化する。
- 各コンポーネントを関連するMITRE AADAPTの戦術に対応付け、権限昇格の経路を明らかにする。
- フラッシュローン／オラクル／認証情報／クロスチェーン攻撃の連鎖をリハーサルし、影響を検証して、悪用可能な前提条件を記録する。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3署名ワークフローの侵害

- ウォレットUIへのサプライチェーン改ざんにより、署名直前にEIP-712ペイロードを改変し、有効な署名を窃取して、delegatecallベースのプロキシ乗っ取り（例: Safe masterCopyのslot-0上書き）に悪用できる。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- スマートアカウントでよくある障害モードには、`EntryPoint`のアクセス制御の回避、署名されていないGasフィールド、状態を変更する検証、ERC-1271のリプレイ、検証後のrevertによる手数料の枯渇などがあります。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## スマートコントラクトセキュリティ

- テストスイートの盲点を見つけるためのMutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guestの完全性

proverが**zkVM**またはアプリケーション固有のproof circuitを使って主張を証明する場合、verifierが知るのは、**guest programが記述どおりに実行された**ということだけです。guestに**安全でないデシリアライズ**、**未定義動作**、または**意味的制約の不足**があると、悪意のあるproverは、検証に成功する一方で、**公開メトリクスや主張された不変条件が偽である**proofを生成できる可能性があります。<sup>[[7]](#references)</sup>

### proof guest内の安全でないデシリアライズ

- proofによって隠されている場合でも、秘密のwitness／circuitのバイト列は**信頼できない攻撃者入力**として扱う。
- バイト列が別の手段ですでに検証されている場合を除き、`rkyv::access_unchecked`のような検査を行わないヘルパーでデシリアライズしない。
- 信頼できないシリアライズデータから読み込まれるenumの判別値、相対ポインター、長さ、インデックスは、制御フローやメモリアクセスに影響する前に検証する。

実践的な監査パターン:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind` のようなフィールドが enum で、攻撃者が**範囲外の discriminant**を注入できる場合、その値に対する後続の `match` はすべて要注意です。

### Jump-table / UB によるカウンタ回避

Rust が大きな `match` を**jump table**にコンパイルする場合、無効な enum discriminant によって**未定義の制御フロー**が発生する可能性があります。危険なパターンは次のとおりです。<sup>[[7]](#references)[[9]](#references)</sup>

1. ある `match` が**セキュリティ上重要なカウンタや制約**を更新する。
2. 2つ目の `match` が**実際の命令の意味論**を処理する。
3. 範囲外の discriminant が最初の jump table の範囲外を参照し、2つ目の jump table に関連するコードへ到達する。

結果: 操作は実行される一方で、計数処理がスキップされます。zkVM では、ゲート数や高コストな操作の回数が実際より少ないなど、あり得ないメトリクスを報告する proof を偽造できる可能性があります。

レビュー時のチェック項目:

- witness/private input からデシリアライズされる、攻撃者が制御可能な enum を探す。
- 同じ opcode/kind フィールドに対する `match` が繰り返し使われていないか確認する。
- `unsafe`、検証なしのデシリアライズ、大規模な opcode dispatch の組み合わせは高リスクとして扱う。
- 必要に応じて生成されたバイナリをリバースエンジニアリングする。jump table の配置がソースコードより重要な場合がある。

### 可逆／特殊化されたインタープリターにおける意味論的制約の欠落

メモリ安全性だけを検証するのではなく、proof が強制するべき**意味論的ルール**も検証してください。

可逆／量子的な命令セットでは、異なる必要があるオペランドが実際に異なるよう制約されていることを確認してください。次のように実装された Toffoli/CCX 類似の操作は:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

ゲストが拒否しないと、安全でなくなる:

```text
op.q_control1 == op.q_control2 == op.q_target
```

その場合、遷移は次の形に簡約されます:

```text
q = q ^ (q & q) = 0
```

これは**決定論的なリセットプリミティブ**を作り出し、可逆性に関する前提を崩して、意図しない計算をより低コストで実行可能にします。リソース使用量を証明する証明システムでは、攻撃者が機能チェックを満たしながら、検証者が適用されていると考えるコストモデルを回避できる可能性があります。

### 制約が不十分な prover advice と剰余演算

**advice/witness スタックから読み込まれる値は prover が制御します**。事前計算された商、剰余、逆元、ヒントとして説明されていても同様です。証明によって確立されるのは、witness が実装された制約を満たすことだけです。制約に型、範囲、正規形のチェックが欠けていれば、意図された計算が行われたことまでは確立されません。<sup>[[13]](#references)</sup>

剰余演算やユークリッド除算のヘルパーを監査する場合は、最後の減算や乗算だけでなく、整数関係全体を確認してください。`q` と `r` の各 limb が宣言された幅に制約されていること、再構成式 `x = q * m + r` が意図された整数表現で成り立つこと、正準範囲 `0 <= r < m` が強制されていることが必要です。値をより狭い `u32`/`u64` 命令に渡す**前に**検証してください。狭い演算を行っても、元のフィールド要素や複数 limb の値が期待された型だったことが遡って証明されるわけではありません。<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Midenにおける`mod_12289`の失敗は、典型的なexploitパターンを示しています。商は2つの64-bit limbとして検証されていましたが、adviceから与えられた剰余は、同等の検証を受けないまま`u32overflowing_sub`に渡されていました。悪意あるproverは、無効な商と剰余を連携させ、実装された減算制約を満たしながら、数学的に正しくない剰余を手続きから返させることができました。この結果はFalconの検証に使われていたため、健全性の破綻は単なる誤った算術結果にとどまらず、偽造された認可署名につながる可能性がありました。<sup>[[13]](#references)</sup>

### 暗黙スタック型暗号VMの監査

スタック言語ではオペランドが隠されているため、まず命令をIRに変換し、消費・生成される各スタック値を由来情報付きの式として表現します。その後、保守的な解析パイプラインで次の処理を行います。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. 呼び出しグラフを構築し、手続きの入力・出力スタック効果を推論する。
2. 対応する命令をシンボリック実行し、制御フローをSSAまたは構造化式に変換する。
3. `Unknown`、`ProvenU32`、`Bool`、値の由来、ローカル変数の初期化状態などの抽象的な事実を、固定点に達するまで伝播させる。
4. advice由来の値が、すべての入力経路でサニタイザーを通らずに、型付き算術演算やゼロ以外を要求するsinkに到達する場合、警告する。
5. 宣言されたシグネチャと推論されたシグネチャを比較し、すべての終了時に呼び出し元が所有するスタック値が保持されることを検証する。

シグネチャが不明、または未対応の構文がある場合は、安全という結果ではなく、**解析上のギャップ**として扱ってください。動的呼び出し、スタック効果が一定でないループ、スタック効果が異なる分岐があると、スタックスロットを健全に追跡できないことがあります。より安全なdecompilerは、もっともらしいが誤った擬似コードを出力するのではなく、このようなケースを拒否するか、明示的にマークします。<sup>[[10]](#references)[[13]](#references)</sup>

制御フローの合流点では、すべての先行ブロックで成り立つ場合に限り、その性質を維持します（たとえば、`ProvenU32 join Unknown = Unknown`）。また、固定点への収束と、反復回数の上限に達した状態を区別してください。診断がないことを、表現されたすべての実行がその性質を満たす証拠として扱えるのは、収束した健全な過大近似の場合だけです。<sup>[[11]](#references)</sup>

### 証明義務で隠れた前提条件を明らかにする

命令セットが小さい場合は、手続きを実行可能な形式VMモデルに変換し、結果とスタック全体の変換の両方を証明します。定理では、停止性、型付き入力、期待される出力の先頭部分、変更されない呼び出し元スタックの保持を対象にする必要があります。証明と同じくらい注意深く定理文も監査してください。カーネルは、誤って弱められた主張の証明も検証できます。<sup>[[12]](#references)[[13]](#references)</sup>

予期しない仮定は、有益な発見につながります。Midenのレビューでは、64-bit右ローテーションの証明に`shift mod 32 != 0`が必要となり、shiftが32の倍数である大きな入力で失敗するエッジケースが明らかになりました。別の証明では、256-bitの`wrapping_mul`が呼び出し元所有のスタック値を破棄することが判明しました。発見した境界ケースをテストに追加し、追加の仮定を黙って受け入れるのではなく、実装を修正するか公開する事前条件を意図的に強化してください。<sup>[[12]](#references)[[13]](#references)</sup>

### ZKシステムでテストする項目

- 形式が不正なwitness/private-inputエンコーディングを使い、すべてのguest parserをfuzzする。
- opcodeのディスパッチ前にenumの範囲検証が行われることを確認する。
- オペランドのエイリアスやその他の無効な命令形式を意味的に検査する。
- すべてのadvice/witnessソースから型付き算術演算の各sinkまでを追跡し、すべての経路で検証が行われることを確認する。<sup>[[11]](#references)[[13]](#references)</sup>
- 非正規のlimb、範囲外の剰余、境界値のshift回数を使って算術ヘルパーをテストする。<sup>[[12]](#references)[[13]](#references)</sup>
- すべてのreturnで、スタックの高さと、手続きの宣言済み引数より下にある値が保持されることを確認する。<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- 報告されたカウンターや公開カウンターを、独立した参照実装と比較する。
- guest programにバグがあれば、有効な証明でも**誤った命題**を証明する可能性があることを忘れないでください。

## 状態依存の認可

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMMの悪用

DEXやAMMの実践的な悪用（Uniswap v4 hooks、丸め・精度の悪用、flash loanで増幅したしきい値超過swap）を調査している場合は、次を参照してください。

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

仮想残高をキャッシュし、`supply == 0`の場合に汚染される可能性があるマルチアセットの加重プールについては、次を参照してください。

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
- [7] [Trail of Bits - Googleの量子暗号解読ゼロ知識証明を破った](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [量子脆弱性から楕円曲線暗号通貨を保護する：リソース推定と緩和策（修正版）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bitsのproof-of-conceptリポジトリ](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompilerのアーキテクチャ](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM静的解析エンジン](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASMからLeanへのモデルと正当性証明](https://github.com/trailofbits/masm-lean)
- [13] [（十分に優れた）AI時代の監査](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
