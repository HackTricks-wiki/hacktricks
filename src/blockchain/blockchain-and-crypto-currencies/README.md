# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** は、特定の条件が満たされたときにブロックチェーン上で実行されるプログラムであり、仲介者なしで合意の実行を自動化します。
- **Decentralized Applications (dApps)** はスマートコントラクトを基盤とし、ユーザーフレンドリーなフロントエンドと透明で監査可能なバックエンドを備えます。
- **Tokens & Coins** は区別され、coins はデジタル通貨としての役割を果たし、tokens は特定のコンテキストでの価値や所有権を表します。
- **Utility Tokens** はサービスへのアクセスを付与し、**Security Tokens** は資産の所有権を示します。
- **DeFi** は分散型金融を指し、中央当局なしで金融サービスを提供します。
- **DEX** と **DAOs** はそれぞれ Decentralized Exchange Platforms（分散型取引所）と Decentralized Autonomous Organizations（分散型自律組織）を指します。

## Consensus Mechanisms

コンセンサスメカニズムは、ブロックチェーン上で取引の検証を安全かつ合意的に行うことを保証します：

- **Proof of Work (PoW)** は取引検証に計算資源を依存します。
- **Proof of Stake (PoS)** は検証者が一定量のトークンを保有することを要求し、PoW と比べてエネルギー消費を削減します。

## Bitcoin Essentials

### Transactions

Bitcoin のトランザクションはアドレス間で資金を移転することを伴います。トランザクションはデジタル署名によって検証され、秘密鍵の所有者だけが送金を開始できることを保証します。

#### Key Components:

- **Multisignature Transactions** はトランザクションを承認するために複数の署名を必要とします。
- トランザクションは **inputs**（資金の出所）、**outputs**（送金先）、**fees**（miner に支払われる手数料）、および **scripts**（トランザクションのルール）で構成されます。

### Lightning Network

Lightning Network はチャネル内で複数のトランザクションを行い、最終状態のみをブロックチェーンにブロードキャストすることで Bitcoin のスケーラビリティを向上させることを目的としています。

## Bitcoin Privacy Concerns

Common Input Ownership や UTXO Change Address Detection のようなプライバシー攻撃はトランザクションパターンを悪用します。Mixers や CoinJoin のような戦略は、ユーザー間のトランザクションの関連付けを曖昧にして匿名性を向上させます。

## Acquiring Bitcoins Anonymously

方法には現金取引、マイニング、mixers の使用などがあります。**CoinJoin** は複数のトランザクションを混ぜて追跡を困難にし、**PayJoin** は通常のトランザクションに見せかけて CoinJoin を行うことでさらにプライバシーを高めます。

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin の世界では、トランザクションのプライバシーやユーザーの匿名性がしばしば問題になります。以下は攻撃者が Bitcoin のプライバシーを侵害する一般的な手法の簡潔な概要です。

## **Common Input Ownership Assumption**

異なるユーザーの inputs が単一のトランザクションで結合されることは通常稀であるため、**同じトランザクション内の二つの入力アドレスは同一の所有者に属すると推定されることが多い**です。

## **UTXO Change Address Detection**

UTXO（**Unspent Transaction Output**）はトランザクション内で完全に消費される必要があります。もしその一部だけが別のアドレスに送られると、残りは新しい change address に送られます。観察者はその新しいアドレスが送信者に属すると推定でき、プライバシーが損なわれます。

### Example

これを緩和するために、mixing services を使ったり複数のアドレスを使用したりすることで所有権を曖昧にすることが有効です。

## **Social Networks & Forums Exposure**

ユーザーがオンラインで自分の Bitcoin アドレスを共有することがあり、これによって**アドレスと所有者を結びつけることが容易になる**ことがあります。

## **Transaction Graph Analysis**

トランザクションはグラフとして可視化でき、資金の流れに基づいてユーザー間の潜在的な関連を明らかにします。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

このヒューリスティックは、複数の inputs と outputs を持つトランザクションを分析して、どの output が送信者に戻る change であるかを推測することに基づきます。

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
追加の inputs を加えることで change output が任意の単一の input より大きくなる場合、heuristic を混乱させることがある。

## **Forced Address Reuse**

攻撃者は、受取人がこれらを将来の transactions において他の inputs と組み合わせることを期待して、以前に使用された addresses に少額を送ることがある。これにより addresses が相互に結び付けられる可能性がある。

### Correct Wallet Behavior

Wallets は既に使用されて空になった addresses で受け取ったコインを使うのを避け、この privacy leak を防ぐべきである。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** change のない Transactions は、同一ユーザーが所有する二つの addresses 間の取引である可能性が高い。
- **Round Numbers:** Transaction における丸い数字（切りの良い金額）は支払いを示唆し、非丸い output が change である可能性が高い。
- **Wallet Fingerprinting:** 異なる wallets は独自の transaction 作成パターンを持ち、analysts は使用されたソフトウェアを特定し、潜在的に change address を特定できる。
- **Amount & Timing Correlations:** transaction の時刻や金額を公開すると、取引が追跡可能になることがある。

## **Traffic Analysis**

network traffic を監視することで、攻撃者は transactions や blocks を IP addresses に結び付け、ユーザーのプライバシーを侵害する可能性がある。特に、ある主体が多数の Bitcoin nodes を運用している場合、transactions の監視能力が高まるため、このリスクは大きくなる。

## More

プライバシー攻撃と防御の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) を参照してください。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 現金を使って Bitcoins を取得する方法。
- **Cash Alternatives**: ギフトカードを購入してオンラインで Bitcoin と交換する方法。
- **Mining**: 最もプライベートな方法で Bitcoin を得るのは mining で、特に単独で行う場合がそうである。なぜなら mining pools はマイナーの IP address を知る可能性があるからだ。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論上、Bitcoin を盗むことも匿名で入手する方法になり得るが、違法であり推奨されない。

## Mixing Services

mixing service を利用すると、ユーザーは Bitcoins を送って異なる Bitcoins を受け取り、元の所有者の追跡を困難にすることができる。しかしこれは、そのサービスがログを保持せず、実際に Bitcoins を返すことを信頼する必要がある。代替の mixing オプションには Bitcoin casinos が含まれる。

## CoinJoin

CoinJoin は複数のユーザーの Transactions を1つに結合し、inputs と outputs を照合しようとする者にとって困難にする。とはいえ、個別の input や output のサイズが独特な場合は、依然として追跡される可能性がある。

例として CoinJoin を使用した可能性のある transactions には `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` と `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` がある。

詳細は [CoinJoin](https://coinjoin.io/en) を参照。Ethereum 上の類似サービスとしては [Tornado Cash](https://tornado.cash) があり、miners の資金を用いて transactions を匿名化する。

## PayJoin

CoinJoin の変種である PayJoin (または P2EP) は、（例えば顧客と販売者のような）二者間の取引を CoinJoin 特有の等しい outputs を伴わない通常の transaction のように偽装する。これにより検出が極めて難しくなり、transaction surveillance entities が用いる common-input-ownership heuristic を無効にする可能性がある。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# 暗号通貨におけるプライバシーのベストプラクティス

## **ウォレット同期技術**

プライバシーとセキュリティを維持するためには、ウォレットをブロックチェーンと同期することが重要です。特に次の2つの方法が目立ちます：

- **Full node**: ブロックチェーン全体をダウンロードすることで、Full node は最大限のプライバシーを確保します。すべての取引がローカルに保存されるため、攻撃者がユーザーの関心のある取引やアドレスを特定することは不可能になります。
- **Client-side block filtering**: この方法はブロックチェーン内の各ブロックに対してフィルタを作成するもので、ウォレットがネットワークの観測者に特定の関心を明かすことなく関連する取引を識別できるようにします。ライトウェイトなウォレットはこれらのフィルタをダウンロードし、ユーザーのアドレスに一致した場合にのみフルブロックを取得します。

## **Utilizing Tor for Anonymity**

Bitcoin がピアツーピアネットワーク上で動作することを考えると、Tor の使用は IP アドレスを隠すために推奨され、ネットワークとやり取りする際のプライバシーを向上させます。

## **Preventing Address Reuse**

プライバシーを守るためには、各取引ごとに新しいアドレスを使うことが重要です。アドレスの使い回しは取引を同一主体に結びつけ、プライバシーを損なう可能性があります。モダンなウォレットは設計上アドレスの使い回しを抑制します。

## **Strategies for Transaction Privacy**

- **Multiple transactions**: 支払いを複数の取引に分割することで取引金額を曖昧にし、プライバシー攻撃を阻止できます。
- **Change avoidance**: お釣り（change outputs）が不要な取引を選ぶことで、チェンジ検出手法を混乱させ、プライバシーが向上します。
- **Multiple change outputs**: チェンジを避けられない場合でも、複数のチェンジ出力を生成することでプライバシーを改善できます。

# **Monero: A Beacon of Anonymity**

Monero はデジタル取引における絶対的な匿名性のニーズに応え、高いプライバシー基準を設定しています。

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas は Ethereum 上で操作を実行するために必要な計算量を測る単位で、価格は **gwei** で表されます。例えば、2,310,000 gwei（または 0.00231 ETH）の費用がかかる取引は、gas limit と base fee を伴い、マイナーへのインセンティブとして tip が加わります。ユーザーは max fee を設定して過支払いを防げるようになっており、余剰は払い戻されます。

## **Executing Transactions**

Ethereum の取引は送信者と受信者を含み、いずれもユーザーアドレスかスマートコントラクトアドレスであり得ます。取引には手数料が必要で、マイニングされる必要があります。取引に含まれる重要な情報は、受信者、送信者の署名、value、任意の data、gas limit、そして手数料です。特筆すべきは、送信者のアドレスは署名から導出されるため、取引データに明示的に含める必要がない点です。

これらの手法と仕組みは、プライバシーとセキュリティを優先して暗号通貨に関与しようとする人にとって基盤となるものです。

## 参考資料

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM の悪用

もし DEXes や AMMs の実践的な悪用を調査しているなら（Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps）、次を参照してください：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
