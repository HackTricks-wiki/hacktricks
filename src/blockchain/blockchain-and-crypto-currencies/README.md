# ブロックチェーンと暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときにブロックチェーン上で実行されるプログラムとして定義され、仲介者なしで合意の実行を自動化します。
- **Decentralized Applications (dApps)** は、ユーザーフレンドリーなフロントエンドと透明で監査可能なバックエンドを備えた、Smart Contracts を基盤とするアプリケーションです。
- **Tokens & Coins** は区別され、coins はデジタルマネーとして機能し、tokens は特定のコンテキストでの価値や所有権を表します。
- **Utility Tokens** はサービスへのアクセス権を付与し、**Security Tokens** は資産の所有を示します。
- **DeFi** は分散型金融を意味し、中央機関なしで金融サービスを提供します。
- **DEX** と **DAOs** はそれぞれ分散型取引所プラットフォームと分散型自律組織を指します。

## コンセンサスメカニズム

コンセンサスメカニズムは、ブロックチェーン上で安全かつ合意されたトランザクション検証を保証します:

- **Proof of Work (PoW)** はトランザクション検証のために計算能力を利用します。
- **Proof of Stake (PoS)** は検証者が一定量のトークンを保有することを要求し、PoW と比べてエネルギー消費を削減します。

## Bitcoin の基本

### トランザクション

Bitcoin トランザクションはアドレス間で資金を移動することを含みます。トランザクションはデジタル署名によって検証され、秘密鍵の所有者のみが送金を開始できることを保証します。

#### 主要な構成要素:

- **Multisignature Transactions** はトランザクションを承認するために複数の署名を必要とします。
- トランザクションは **inputs**（資金の出所）、**outputs**（送金先）、**fees**（miners に支払われる手数料）、および **scripts**（トランザクションルール）で構成されます。

### Lightning Network

Lightning Network は、チャネル内で複数のトランザクションを可能にし、最終状態のみをブロックチェーンにブロードキャストすることで Bitcoin のスケーラビリティを向上させることを目的としています。

## Bitcoin のプライバシーに関する懸念

**Common Input Ownership** や **UTXO Change Address Detection** のようなプライバシー攻撃はトランザクションパターンを悪用します。**Mixers** や **CoinJoin** のような戦略は、ユーザー間のトランザクションリンクを隠すことで匿名性を向上させます。

## 匿名での Bitcoin の取得

方法には現金取引、マイニング、mixers の利用などがあります。**CoinJoin** は複数のトランザクションを混ぜて追跡を困難にし、**PayJoin** はCoinJoinを通常のトランザクションに偽装してさらなるプライバシーを提供します。

# Bitcoin Privacy Atacks

# Bitcoin プライバシー攻撃の概要

Bitcoin の世界では、トランザクションのプライバシーやユーザーの匿名性がしばしば問題になります。以下は、攻撃者が Bitcoin のプライバシーを侵害する一般的な方法の簡潔な概要です。

## **Common Input Ownership Assumption**

異なるユーザーの inputs が単一のトランザクションで結合されることは一般に稀であるため、**同一トランザクション内の2つの input アドレスは同一所有者に属すると推定されることが多い**です。

## **UTXO Change Address Detection**

UTXO（**Unspent Transaction Output**）はトランザクションで完全に消費される必要があります。もしその一部だけが別のアドレスに送られると、残りは新しい change address に送られます。観察者はこの新しいアドレスが送信者に属すると推測でき、プライバシーが侵害されます。

### 例

これを軽減するために、mixing services や複数のアドレスを使用して所有権を曖昧にすることが有効です。

## **Social Networks & Forums Exposure**

ユーザーがオンラインで自分の Bitcoin アドレスを共有することがあり、これにより**アドレスと所有者を簡単に結びつける**ことができます。

## **Transaction Graph Analysis**

トランザクションはグラフとして可視化でき、資金の流れに基づいてユーザー間の潜在的なつながりを明らかにします。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

このヒューリスティックは、複数の inputs と outputs を持つトランザクションを分析して、どの出力が送信者に返る change であるかを推測することに基づいています。

### 例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
もし複数の入力を追加してchange outputが任意の単一入力より大きくなると、ヒューリスティックを混乱させる可能性がある。

## **強制的なアドレス再利用**

攻撃者は、受取人が将来のトランザクションでこれらを他の入力と組み合わせることを期待して、以前に使用されたアドレスに少額を送ることがあり、これによりアドレスが互いに結びつけられる。

### 正しいウォレットの挙動

ウォレットは、既に使用された空のアドレスで受け取ったコインを使用することを避け、この privacy leak を防ぐべきである。

## **その他のブロックチェーン解析手法**

- **Exact Payment Amounts:** change のないトランザクションは、同一ユーザが管理する2つのアドレス間の取引である可能性が高い。
- **Round Numbers:** トランザクションに丸い数が含まれている場合、それが支払いであることを示唆し、非丸い出力がお釣りである可能性が高い。
- **Wallet Fingerprinting:** ウォレットごとに独自のトランザクション生成パターンがあり、解析者は使用されたソフトウェアを特定し、場合によってはchange addressを突き止めることができる。
- **Amount & Timing Correlations:** トランザクションの時間や金額を明らかにすると、トランザクションが追跡可能になることがある。

## **トラフィック解析**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックをIPアドレスに結びつけ、ユーザのプライバシーを侵害する可能性がある。特に、多数のBitcoinノードを運用する主体は、トランザクションを監視する能力が強化されるため、この傾向が強くなる。

## さらに

プライバシー攻撃と防御の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) を参照せよ。

# 匿名のBitcoinトランザクション

## Bitcoinを匿名で入手する方法

- **Cash Transactions**: 現金でBitcoinを取得する。
- **Cash Alternatives**: ギフトカードを購入し、オンラインでBitcoinと交換する。
- **Mining**: Bitcoinを得る最もプライベートな方法はマイニングであり、特に単独で行う場合は最も匿名性が高い。マイニングプールはマイナーのIPアドレスを把握している可能性がある。[Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論的には、Bitcoinを盗むことも匿名取得の一手段になり得るが、違法であり推奨されない。

## Mixing Services

ミキシングサービスを利用すると、ユーザは**send bitcoins**して**different bitcoins in return**を受け取り、元の所有者を辿ることを困難にできる。ただし、サービスがログを保持しないこと、実際にBitcoinを返すことを信頼する必要がある。代替のミキシング手段としてBitcoinのカジノなどがある。

## CoinJoin

CoinJoinは複数のユーザからのトランザクションを一つにまとめ、入力と出力の対応を追うことを困難にする。とはいえ、入力や出力のサイズが特徴的なトランザクションは依然として追跡される可能性がある。

CoinJoinを使用した可能性があるトランザクションの例には `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` や `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` がある。

詳細は [CoinJoin](https://coinjoin.io/en) を参照。Ethereum上の類似サービスとしては、マイナー資金でトランザクションを匿名化する [Tornado Cash](https://tornado.cash) がある。

## PayJoin

CoinJoinの亜種であるPayJoin（またはP2EP）は、取引を2当事者（例：顧客と商人）の間の通常のトランザクションとして偽装し、CoinJoinに特徴的な等価な出力を伴わないため検出が非常に困難になる。これにより、transaction surveillance entitiesが使用する common-input-ownership heuristic を無効にする可能性がある。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# 暗号通貨におけるプライバシーのベストプラクティス

## **Wallet Synchronization Techniques**

プライバシーとセキュリティを維持するには、wallet をブロックチェーンと同期させることが重要です。特に次の2つの方法が有効です:

- **Full node**: ブロックチェーン全体をダウンロードすることで、full node は最大限のプライバシーを確保します。過去の全てのトランザクションがローカルに保存されるため、第三者がユーザーがどのトランザクションやアドレスに関心を持っているかを特定することはできません。
- **Client-side block filtering**: これはブロックごとにフィルタを作成し、wallet が該当するトランザクションを特定できるようにする方法です。ネットワークの監視者に特定の関心を露呈することなく関連トランザクションを検出できます。軽量なウォレットはこれらのフィルタだけをダウンロードし、ユーザーのアドレスと一致した場合にのみフルブロックを取得します。

## **Utilizing Tor for Anonymity**

Bitcoin がピアツーピアネットワーク上で動作していることを踏まえ、Tor を使用して IP アドレスを隠すことは推奨されます。これによりネットワークとのやり取り時のプライバシーが向上します。

## **Preventing Address Reuse**

プライバシーを守るためには、取引ごとに新しいアドレスを使うことが重要です。アドレスの再利用は取引を同一主体に結び付け、プライバシーを損なう可能性があります。現代のウォレットは設計上、アドレスの再利用を抑制しています。

## **Strategies for Transaction Privacy**

- **Multiple transactions**: 支払いを複数のトランザクションに分割することで、送金額を不明瞭にし、プライバシー攻撃を難しくできます。
- **Change avoidance**: change outputs を発生させないトランザクションを選ぶことで、チェンジ検出手法を妨げ、プライバシーを高められます。
- **Multiple change outputs**: change を避けられない場合でも、複数の change outputs を生成することでプライバシーを改善できます。

# **Monero: A Beacon of Anonymity**

Monero はデジタル取引における完全な匿名性の必要性に応え、プライバシーの高い基準を設定しています。

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas は Ethereum 上で操作を実行するために必要な計算量を測る単位で、価格は **gwei** で表されます。例えば、2,310,000 gwei（0.00231 ETH）かかるトランザクションは、gas limit と base fee を伴い、マイナーを促すための tip が含まれることがあります。ユーザーは max fee を設定して過剰支払いを避け、余剰分は返金されます。

## **Executing Transactions**

Ethereum のトランザクションは送信者と受信者を含み、受信者はユーザーアドレスか smart contract アドレスのいずれかです。これらは手数料を必要とし、マイニングされる必要があります。トランザクションに含まれる重要な情報は受信者、送信者の署名、価値、任意のデータ、gas limit、および手数料です。特筆すべきは、送信者のアドレスは署名から推定されるため、トランザクションデータ中に明示的に含める必要がない点です。

これらの慣行と仕組みは、プライバシーとセキュリティを重視して暗号通貨と関わる者にとって基礎となるものです。

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
