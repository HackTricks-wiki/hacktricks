# ブロックチェーンと暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときにブロックチェーン上で実行されるプログラムであり、中間者を必要とせずに合意の実行を自動化します。
- **dApps** はスマートコントラクト上に構築され、使いやすいフロントエンドと透明で監査可能なバックエンドを備えた分散型アプリケーションです。
- **Tokens & Coins** は区別され、coins はデジタルマネーとして機能し、tokens は特定の文脈での価値や所有権を表します。
- **Utility Tokens** はサービスへのアクセスを与え、**Security Tokens** は資産の所有を示します。
- **DeFi** は分散型金融を意味し、中央当局なしで金融サービスを提供します。
- **DEX** と **DAOs** はそれぞれ分散型取引所プラットフォームと分散型自律組織を指します。

## コンセンサスメカニズム

コンセンサスメカニズムは、ブロックチェーン上での取引検証が安全かつ合意されたものになるようにします:

- **Proof of Work (PoW)** はトランザクション検証に計算能力を利用します。
- **Proof of Stake (PoS)** は検証者が一定量のトークンを保有することを要求し、PoWと比べてエネルギー消費を削減します。

## Bitcoin の基礎

### トランザクション

Bitcoin のトランザクションはアドレス間で資金を移動する行為です。トランザクションはデジタル署名によって検証され、プライベートキーの所有者だけが送金を開始できることを保証します。

#### 主要構成要素:

- **Multisignature Transactions** はトランザクションの承認に複数の署名を必要とします。
- トランザクションは **inputs**（資金の出所）、**outputs**（送金先）、**fees**（マイナーに支払われる手数料）、および **scripts**（トランザクションのルール）で構成されます。

### Lightning Network

Lightning Network は、チャネル内で複数のトランザクションを行い、最終的な状態のみをブロックチェーンにブロードキャストすることで Bitcoin のスケーラビリティを向上させることを目的としています。

## Bitcoin のプライバシーに関する懸念

Common Input Ownership や UTXO Change Address Detection のようなプライバシー攻撃は、トランザクションパターンを悪用します。Mixers や CoinJoin のような戦略は、ユーザー間のトランザクションの関連付けを隠すことで匿名性を高めます。

## 匿名で Bitcoin を取得する方法

方法には現金取引、マイニング、ミキサーの使用などがあります。**CoinJoin** は複数のトランザクションを混ぜて追跡を困難にし、**PayJoin** は CoinJoin を通常のトランザクションのように見せかけてより高いプライバシーを実現します。

# Bitcoin プライバシー攻撃

# Bitcoin プライバシー攻撃の概要

Bitcoin の世界では、トランザクションのプライバシーやユーザーの匿名性がしばしば問題になります。以下は攻撃者が Bitcoin のプライバシーを侵害する一般的な手法の簡潔な概要です。

## **Common Input Ownership Assumption**

異なるユーザーの inputs が単一のトランザクションで組み合わされることは稀であるため、**同じトランザクション内の 2 つの入力アドレスは同一の所有者に属すると見なされることが多い**です。

## **UTXO Change Address Detection**

UTXO（Unspent Transaction Output）はトランザクションで全額を使い切る必要があります。部分的に別のアドレスに送られた場合、残りは新しい change address に送られます。観察者はこの新しいアドレスが送信者に属すると推測でき、プライバシーが損なわれます。

### 例

これを緩和するために、ミキシングサービスや複数のアドレスを使用することで所有権を曖昧にするのが有効です。

## **ソーシャルネットワークやフォーラムでの露出**

ユーザーがオンラインで自分の Bitcoin アドレスを共有することがあり、これにより**アドレスと所有者を簡単に結びつける**ことが可能になります。

## **トランザクショングラフ分析**

トランザクションはグラフとして可視化でき、資金の流れに基づいてユーザー間の潜在的な関連を明らかにします。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

このヒューリスティックは、複数の入力と出力を持つトランザクションを分析して、どの出力が送信者に返る change であるかを推測することに基づいています。

### 例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
もし追加のインプットを加えることでお釣り出力が任意の単一インプットよりも大きくなると、ヒューリスティックが混乱する可能性があります。

## **Forced Address Reuse**

攻撃者は以前に使用されたアドレスに少額を送金し、受取人が将来のトランザクションでそれらを他のインプットと組み合わせることを期待して、アドレス同士を紐付けることがあります。

### Correct Wallet Behavior

ウォレットは、このプライバシー leak を防ぐため、既に使用済みで空になったアドレスで受け取ったコインを使用しないようにするべきです。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** お釣りがないトランザクションは、同一ユーザーが所有する2つのアドレス間での取引である可能性が高い。
- **Round Numbers:** トランザクションに丸い数値がある場合、それは支払いを示唆しており、丸くない出力が お釣りになる可能性が高い。
- **Wallet Fingerprinting:** ウォレットごとにトランザクション生成のパターンが異なるため、アナリストは使用ソフトウェアを特定したり、場合によってはお釣りアドレスを推測したりできる。
- **Amount & Timing Correlations:** トランザクションの時刻や金額を公開すると、トランザクションが追跡可能になることがある。

## **Traffic Analysis**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックをIPアドレスに結び付け、ユーザーのプライバシーを侵害する可能性がある。特に、多数の Bitcoin ノードを運営する組織はトランザクションの監視能力が高まるため、これが当てはまる。

## さらに

プライバシー攻撃と防御の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) を参照してください。

# 匿名Bitcoinトランザクション

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 現金でビットコインを入手する方法。
- **Cash Alternatives**: ギフトカードを購入してオンラインでビットコインに交換する。
- **Mining**: ビットコインを得る最もプライベートな方法はマイニングで、単独で行う場合が特にプライベートである。なぜならマイニングプールはマイナーのIPアドレスを知る可能性があるためです。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論上、ビットコインを盗むことも匿名で入手する方法になり得るが、違法であり推奨されない。

## Mixing Services

ミキシングサービスを利用すると、ユーザーは**ビットコインを送金**して**異なるビットコインを受け取る**ことができ、元の所有者を追跡しにくくなる。ただし、そのサービスがログを保持しないこと、実際にビットコインを返すことを信頼する必要がある。代替のミキシングオプションとしては Bitcoin カジノがある。

## CoinJoin

CoinJoin は異なるユーザーからの複数のトランザクションを1つに統合し、インプットとアウトプットを照合しようとする者の作業を複雑にする。とはいえ、入力や出力のサイズが一意なトランザクションは依然として追跡される可能性がある。

CoinJoin を使用した可能性のあるトランザクションの例には `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` と `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` がある。

詳細は [CoinJoin](https://coinjoin.io/en) を参照してください。Ethereum 上の類似サービスについては、マイナーからの資金でトランザクションを匿名化する [Tornado Cash](https://tornado.cash) を確認してください。

## PayJoin

CoinJoin の変種である **PayJoin** (または P2EP) は、トランザクションを（例えば顧客と商人の）二者間の通常の取引として偽装し、CoinJoin に特徴的な等しい出力を示さない。これにより検出が非常に難しくなり、トランザクション監視主体が使用する common-input-ownership heuristic を無効化する可能性がある。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin の利用は従来の監視手法を大きく混乱させる可能性があり、トランザクションのプライバシー追求において有望な進展です。**

# 暗号通貨におけるプライバシーのベストプラクティス

## **Wallet Synchronization Techniques**

プライバシーとセキュリティを維持するには、wallet を blockchain と同期させることが重要です。特に有力な方法が2つあります:

- **Full node**: ブロックチェーン全体をダウンロードすることで、full node は最大のプライバシーを確保します。過去のすべてのトランザクションがローカルに保存されるため、攻撃者がユーザーが関心を持つトランザクションやアドレスを特定することは不可能になります。
- **Client-side block filtering**: この方法は blockchain の各ブロック用にフィルタを作成することを含み、wallet がネットワーク観測者に特定の興味を露呈することなく関連するトランザクションを識別できるようにします。lightweight wallets はこれらのフィルタをダウンロードし、ユーザーのアドレスと一致した場合にのみ完全なブロックを取得します。

## **Utilizing Tor for Anonymity**

Bitcoin がピアツーピアネットワークで動作することを踏まえ、ネットワークとのやり取り時に IP アドレスを隠すために Tor を使用することが推奨されます。

## **Preventing Address Reuse**

プライバシーを守るため、各トランザクションごとに新しいアドレスを使うことが重要です。アドレスを再利用するとトランザクションが同一主体に結び付けられ、プライバシーが損なわれます。最新の wallet は設計上アドレスの再利用を抑止します。

## **Strategies for Transaction Privacy**

- **Multiple transactions**: 支払いを複数のトランザクションに分けることで金額を曖昧にし、プライバシー攻撃を阻止できます。
- **Change avoidance**: change outputs を作らないトランザクションを選ぶと、change 検出手法を妨害してプライバシーが向上します。
- **Multiple change outputs**: change を避けられない場合でも、複数の change outputs を生成することでプライバシーを改善できます。

# **Monero: A Beacon of Anonymity**

Monero はデジタルトランザクションにおける絶対的な匿名性のニーズに応え、高いプライバシー基準を確立しています。

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas は Ethereum 上で操作を実行するために必要な計算コストを測る単位で、価格は **gwei** で表されます。例えば、2,310,000 gwei（または 0.00231 ETH）の取引では、gas limit と base fee があり、マイナーへのインセンティブとして tip が付与されます。ユーザーは max fee を設定して過剰支払いを防げ、差額は返金されます。

## **Executing Transactions**

Ethereum のトランザクションは送信者と受信者を含み、いずれもユーザーアドレスまたは smart contract のアドレスになり得ます。手数料が必要で、マイニングされる必要があります。トランザクションに含まれる主な情報は、受信者、送信者の署名、value、任意の data、gas limit、および fees です。特に、送信者のアドレスは署名から復元されるため、トランザクションデータ内に送信者アドレスを含める必要はありません。

これらの慣行とメカニズムは、プライバシーとセキュリティを優先して暗号通貨を扱う者にとって基礎となります。

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) を把握し、誰がどのように資金を移動できるかを理解する。
- 各コンポーネントを関連する MITRE AADAPT tactics にマッピングして、権限昇格の経路を露呈させる。
- flash-loan/oracle/credential/cross-chain の攻撃チェーンを演習して影響を検証し、悪用可能な前提条件を文書化する。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

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
