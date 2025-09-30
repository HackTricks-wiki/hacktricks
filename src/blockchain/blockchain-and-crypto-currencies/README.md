# ブロックチェーンと暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときにブロックチェーン上で実行されるプログラムであり、中間者なしに契約の実行を自動化します。
- **Decentralized Applications (dApps)** は Smart Contracts を基盤とし、使いやすいフロントエンドと透明で監査可能なバックエンドを備えています。
- **Tokens & Coins** は、coins がデジタル通貨として機能し、tokens が特定の文脈で価値や所有権を表すという点で区別されます。
- **Utility Tokens** はサービスへのアクセスを提供し、**Security Tokens** は資産の所有を示します。
- **DeFi** は Decentralized Finance の略で、中央当局なしに金融サービスを提供します。
- **DEX** と **DAOs** はそれぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## コンセンサスメカニズム

コンセンサスメカニズムは、ブロックチェーン上でトランザクションの検証が安全かつ合意されたものとなることを保証します:

- **Proof of Work (PoW)** はトランザクションの検証に計算能力を利用します。
- **Proof of Stake (PoS)** はバリデータが一定量のトークンを保有することを要求し、PoW と比べてエネルギー消費を削減します。

## Bitcoin の基礎

### トランザクション

Bitcoin のトランザクションはアドレス間で資金を移動することを含みます。トランザクションはデジタル署名によって検証され、プライベートキーの所有者のみが送金を開始できることを保証します。

#### 主要コンポーネント:

- **Multisignature Transactions** はトランザクションを承認するために複数の署名を必要とします。
- トランザクションは **inputs**（資金の出所）、**outputs**（宛先）、**fees**（マイナーに支払われる手数料）、および **scripts**（トランザクションのルール）で構成されます。

### Lightning Network

チャネル内で複数のトランザクションを許可し、最終的な状態のみをブロックチェーンにブロードキャストすることで、Bitcoin のスケーラビリティを向上させることを目的としています。

## Bitcoin のプライバシー上の懸念

Privacy attack（プライバシー攻撃）として **Common Input Ownership** や **UTXO Change Address Detection** のようなものがあり、トランザクションのパターンを悪用します。**Mixers** や **CoinJoin** のような戦略は、ユーザー間のトランザクションのつながりを不明瞭にすることで匿名性を高めます。

## Bitcoin を匿名で取得する方法

手法には現金取引、マイニング、ミキサーの利用などがあります。**CoinJoin** は複数のトランザクションを混ぜて追跡可能性を複雑にし、**PayJoin** は CoinJoin を通常のトランザクションとして偽装してプライバシーを高めます。

# Bitcoin のプライバシー攻撃

# Bitcoin プライバシー攻撃の概要

Bitcoin の世界では、トランザクションのプライバシーやユーザーの匿名性がしばしば懸念の対象になります。ここでは、攻撃者が Bitcoin のプライバシーを侵害するいくつかの一般的な手法の簡潔な概要を示します。

## **Common Input Ownership Assumption**

異なるユーザーの inputs が複雑さのために単一トランザクションで結合されることは一般的に稀です。したがって、**同じトランザクション内の2つの input アドレスは同一の所有者に属するとみなされることが多い**です。

## **UTXO Change Address Detection**

UTXO（**Unspent Transaction Output**）はトランザクションで完全に消費されなければなりません。もし一部だけが別のアドレスに送られた場合、残りは新しい change address に送られます。観察者はこの新しいアドレスが送信者に属すると推定でき、プライバシーが損なわれます。

### 例

これを軽減するために、ミキシングサービスを利用したり複数のアドレスを使用することで所有権を不明瞭にすることができます。

## **Social Networks & Forums Exposure**

ユーザーは時々自身の Bitcoin アドレスをオンラインで共有し、その結果 **アドレスを所有者に結びつけることが容易になる**ことがあります。

## **Transaction Graph Analysis**

トランザクションはグラフとして可視化でき、資金の流れに基づいてユーザー間の潜在的なつながりを明らかにします。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

このヒューリスティックは、複数の inputs と outputs を持つトランザクションを解析して、どの output が送信者に戻る change であるかを推測することに基づいています。

### 例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
もし追加の入力によってお釣り出力が任意の単一入力よりも大きくなる場合、ヒューリスティックが混乱することがある。

## **Forced Address Reuse**

攻撃者は以前に使用されたアドレスへ少額を送金し、受取人が将来のトランザクションでこれらを他の入力と結合することを期待してアドレスを結びつけようとすることがある。

### Correct Wallet Behavior

ウォレットは、この privacy leak を防ぐために、既に使用済みの空のアドレスで受け取ったコインを使用することを避けるべきである。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** お釣りのないトランザクションは、同一ユーザが所有する2つのアドレス間である可能性が高い。
- **Round Numbers:** トランザクション内の切りの良い金額は支払いを示唆し、切りの悪い出力がたいていお釣りである可能性が高い。
- **Wallet Fingerprinting:** ウォレットごとに独特のトランザクション作成パターンがあり、解析者は使用ソフトウェアやお釣りアドレスを特定できる可能性がある。
- **Amount & Timing Correlations:** トランザクションの時間や金額を公開すると、トランザクションが追跡可能になることがある。

## **Traffic Analysis**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックをIPアドレスに結び付け、ユーザのプライバシーを侵害できる可能性がある。特に、多数のBitcoinノードを運営する組織はトランザクションを監視する能力が高まるため、このリスクが大きい。

## More

プライバシー攻撃と防御の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) を参照してください。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 現金でビットコインを取得する。
- **Cash Alternatives**: ギフトカードを購入し、オンラインでビットコインと交換する。
- **Mining**: ビットコインを得る最もプライベートな方法はマイニングで、特にソロで行う場合はプライバシーが高い。マイニングプールはマイナーのIPアドレスを把握している可能性がある。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論上、ビットコインを盗むことは匿名で入手する方法になり得るが、違法であり推奨されない。

## Mixing Services

ミキシングサービスを使用すると、ユーザは**ビットコインを送信し**、**別のビットコインを受け取る**ことができ、これにより元の所有者の追跡が困難になる。しかし、サービスがログを保持しないこと、実際にビットコインを返すことを信頼する必要がある。代替のミキシング手段としてはBitcoinカジノがある。

## CoinJoin

**CoinJoin** は複数のユーザのトランザクションを1つに合体させ、入力と出力を対応付けようとする者の作業を複雑にする。とはいえ、入力や出力のサイズがユニークなトランザクションは依然として追跡される可能性がある。

CoinJoinを使用した可能性があるトランザクションの例には `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` と `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` が含まれる。

詳細は[CoinJoin](https://coinjoin.io/en) を参照。Ethereum上の類似サービスとしては[Tornado Cash](https://tornado.cash) があり、マイナーからの資金を用いてトランザクションを匿名化する。

## PayJoin

CoinJoinの派生である **PayJoin** (または P2EP) は、2者（例: 顧客と商人）間のトランザクションをCoinJoinの特徴的な等額出力を伴わない通常のトランザクションとして偽装する。これにより検出が非常に困難になり、トランザクション監視機関が使用する common-input-ownership heuristic を無効にする可能性がある。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
上記のようなトランザクションはPayJoinである可能性があり、標準的なbitcoinトランザクションと見分けがつかないままプライバシーを強化します。

**PayJoinの利用は従来の監視手法を大きく混乱させる可能性があり、トランザクションのプライバシー追求において有望な進展です。**

# 暗号通貨におけるプライバシーのベストプラクティス

## **ウォレット同期手法**

プライバシーとセキュリティを維持するために、ウォレットをブロックチェーンと同期することが重要です。特に次の2つの方法が挙げられます：

- **Full node**: ブロックチェーン全体をダウンロードすることで、Full nodeは最大のプライバシーを確保します。すべての取引がローカルに保存されるため、攻撃者がユーザーが関心を持つトランザクションやアドレスを特定することが不可能になります。
- **Client-side block filtering**: この方法はブロックチェーンの各ブロックに対するフィルタを作成するもので、ウォレットがネットワークの観測者に特定の関心を露呈することなく関連するトランザクションを識別できるようにします。ライトウォレットはこれらのフィルタをダウンロードし、ユーザーのアドレスと一致したときにのみフルブロックを取得します。

## **匿名化のためのTorの利用**

Bitcoinがピアツーピアネットワーク上で動作していることを考えると、ネットワークとやり取りする際のプライバシーを高めるためにIPアドレスを隠す目的でTorの使用が推奨されます。

## **アドレス再利用の防止**

プライバシーを保護するためには、各トランザクションごとに新しいアドレスを使用することが重要です。アドレスを再利用すると、トランザクションが同一の主体に結び付けられ、プライバシーが損なわれる可能性があります。モダンなウォレットは設計上、アドレスの再利用を抑制します。

## **トランザクションプライバシーのための戦略**

- **Multiple transactions**: 支払いを複数のトランザクションに分割することで、トランザクション額を曖昧にし、プライバシー攻撃を難しくします。
- **Change avoidance**: change outputsを必要としないトランザクションを選ぶことで、change検出手法を撹乱し、プライバシーが向上します。
- **Multiple change outputs**: changeを避けられない場合でも、複数のchange outputsを生成することでプライバシーが改善されます。

# **Monero: A Beacon of Anonymity**

Moneroはデジタル取引における絶対的な匿名性のニーズに対応しており、プライバシーの高い基準を提示しています。

# **Ethereum: Gas and Transactions**

## **Gasの理解**

GasはEthereum上で処理を実行するために必要な計算リソースを測る単位で、単価は **gwei** で表されます。例えば、2,310,000 gwei（または0.00231 ETH）の取引では、gas limitとbase feeが関係し、マイナーへのインセンティブとしてtipが加えられます。ユーザーはmax feeを設定して過払いを防げ、余剰分は返金されます。

## **トランザクションの実行**

Ethereumのトランザクションは送信者と受信者を含み、これらはユーザーアドレスまたはsmart contractアドレスのいずれかです。トランザクションには手数料が必要で、マイニングされる必要があります。トランザクションに含まれる基本情報は、recipient、senderのsignature、value、任意のdata、gas limit、およびfeesなどです。特に、senderのアドレスはsignatureから導出されるため、トランザクションデータ内で明示する必要はありません。

これらの手法とメカニズムは、プライバシーとセキュリティを優先して暗号通貨に関わろうとする人にとって基礎的なものです。

## スマートコントラクトセキュリティ

- テストスイートの盲点を見つけるためのMutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## 参考文献

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMMの悪用研究

もしDEXやAMM（Uniswap v4 hooks、rounding/precision abuse、flash‑loan amplified threshold‑crossing swaps）の実践的な悪用を調査している場合は、次を参照してください：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
