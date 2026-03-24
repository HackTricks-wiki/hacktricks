# ブロックチェーンと暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **スマートコントラクト** は、特定の条件が満たされたときにブロックチェーン上で実行されるプログラムとして定義され、中間者なしで契約の実行を自動化します。
- **分散型アプリケーション (dApps)** はスマートコントラクトを基盤とし、ユーザーフレンドリーなフロントエンドと透明で監査可能なバックエンドを備えます。
- **トークン & コイン** は区別され、コインはデジタルマネーとして機能し、トークンは特定のコンテキストでの価値や所有権を表します。
- **ユーティリティトークン** はサービスへのアクセスを与え、**セキュリティトークン** は資産の所有権を示します。
- **DeFi** は分散型金融（Decentralized Finance）を指し、中央機関なしで金融サービスを提供します。
- **DEX** と **DAO** は、それぞれ分散型取引所（Decentralized Exchange Platforms）と分散型自律組織（Decentralized Autonomous Organizations）を指します。

## 合意形成メカニズム

合意形成メカニズムは、ブロックチェーン上で安全かつ合意されたトランザクション検証を保証します:

- **Proof of Work (PoW)** はトランザクション検証のために計算能力を必要とします。
- **Proof of Stake (PoS)** は検証者が一定量のトークンを保有することを要求し、PoWと比べてエネルギー消費を削減します。

## ビットコインの基礎

### トランザクション

ビットコインのトランザクションはアドレス間で資金を転送することを含みます。トランザクションはデジタル署名によって検証され、秘密鍵の所有者だけが送金を開始できることを保証します。

#### 主要な構成要素:

- **マルチシグネチャトランザクション** はトランザクションの承認に複数の署名を必要とします。
- トランザクションは **inputs**（資金の出所）、**outputs**（送金先）、**fees**（マイナーに支払われる手数料）、および **scripts**（トランザクションルール）で構成されます。

### Lightning Network

複数のトランザクションをチャネル内で行い、最終状態のみをブロックチェーンにブロードキャストすることで、Bitcoinのスケーラビリティを向上させることを目的としています。

## ビットコインのプライバシー上の懸念

Common Input OwnershipやUTXO Change Address Detectionのようなプライバシー攻撃は、トランザクションパターンを悪用します。MixersやCoinJoinのような戦略は、ユーザー間のトランザクションリンクを隠蔽して匿名性を向上させます。

## ビットコインを匿名で取得する方法

方法には現金取引、マイニング、ミキサーの使用などがあります。**CoinJoin** は複数のトランザクションを混ぜて追跡を困難にし、**PayJoin** はCoinJoinを通常のトランザクションのように偽装してより高いプライバシーを提供します。

# ビットコインのプライバシー攻撃

# ビットコインのプライバシー攻撃の概要

ビットコインの世界では、トランザクションのプライバシーやユーザーの匿名性がしばしば問題となります。以下は、攻撃者がビットコインのプライバシーを侵害する一般的な手法を簡潔にまとめたものです。

## **Common Input Ownership Assumption（共通入力所有仮定）**

異なるユーザーの入力が単一のトランザクションで結合されることは通常稀であるため、**同じトランザクション内の2つの入力アドレスはしばしば同一の所有者に属すると推定されます**。

## **UTXO Change Address Detection（UTXOのお釣りアドレス検出）**

UTXO（Unspent Transaction Output、未使用トランザクション出力）はトランザクションで全額を使い切る必要があります。一部だけが別のアドレスに送られる場合、残りは新しいお釣りアドレスに送られます。観察者はこの新しいアドレスが送信者に属すると推測でき、プライバシーが侵害されます。

### 例

これを軽減するために、ミキシングサービスの使用や複数のアドレスを用いると所有権の秘匿に役立ちます。

## **ソーシャルネットワーク & フォーラムによる露出**

ユーザーがオンラインで自分のビットコインアドレスを共有することがあり、アドレスと所有者を容易に結び付けることができます。

## **トランザクショングラフ分析**

トランザクションはグラフとして視覚化でき、資金の流れに基づいてユーザー間の潜在的なつながりを明らかにします。

## **不要入力ヒューリスティック（最適お釣りヒューリスティック）**

このヒューリスティックは、複数の入力と出力を持つトランザクションを分析して、どの出力が送信者に返るお釣りであるかを推測することに基づきます。

### 例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
もし入力を増やすことでお釣り出力が任意の単一入力よりも大きくなると、そのヒューリスティックを混乱させる可能性がある。

## **Forced Address Reuse**

攻撃者は以前に使用されたアドレスへ少額を送り、受取人が将来のトランザクションでそれらを他の入力と結合することを期待して、アドレス同士を結び付けようとすることがある。

### Correct Wallet Behavior

ウォレットはこのプライバシー leak を防ぐため、既に使用された空のアドレスで受け取ったコインを使用しないようにすべきである。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** お釣りのないトランザクションは、同一ユーザーが所有する2つのアドレス間の取引である可能性が高い。
- **Round Numbers:** トランザクション内の端数のない丸い数字は支払いであることを示唆し、丸くない出力が釣り銭である可能性が高い。
- **Wallet Fingerprinting:** ウォレットごとにトランザクション生成のパターンが異なるため、解析者は使用されたソフトウェアや場合によっては釣り銭アドレスを特定できることがある。
- **Amount & Timing Correlations:** トランザクションの時刻や金額を公開すると、追跡可能になることがある。

## **Traffic Analysis**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックをIPアドレスに結び付け、ユーザーのプライバシーを損なう可能性がある。団体が多数の Bitcoin ノードを運営している場合は特に、トランザクション監視能力が向上するためこのリスクは高くなる。

## More

詳細なプライバシー攻撃と防御の一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) を参照。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 現金でビットコインを入手する方法。
- **Cash Alternatives**: ギフトカードを購入してオンラインでビットコインと交換する方法。
- **Mining**: 単独で行うマイニングは、最もプライベートにビットコインを得る方法である。マイニングプールはマイナーのIPアドレスを把握している可能性があるため、特に単独マイニングが推奨される。[Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論的には、ビットコインを盗むことも匿名で入手する方法になり得るが、違法であり推奨されない。

## Mixing Services

ミキシングサービスを利用すると、ユーザーはビットコインを送り、代わりに別のビットコインを受け取ることができるため、元の所有者の追跡が困難になる。ただし、サービスがログを保持しないことや実際にビットコインを返すことを信頼する必要がある。代替のミキシング手段としては Bitcoin カジノなどがある。

## CoinJoin

**CoinJoin** は複数のユーザーからのトランザクションを1つにまとめ、入力と出力を対応付けようとする者の作業を複雑にする。効果的ではあるが、入力や出力のサイズがユニークなトランザクションは依然として追跡される可能性がある。

例として CoinJoin を使用した可能性のあるトランザクションには `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` と `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` がある。

詳細は [CoinJoin](https://coinjoin.io/en) を参照。Ethereum 上の類似サービスとしては [Tornado Cash](https://tornado.cash) があり、マイナー由来の資金でトランザクションを匿名化する。

## PayJoin

CoinJoin の亜種である **PayJoin**（または P2EP）は、取引を2者（例：顧客と商人）の間の通常のトランザクションに偽装し、CoinJoin に特徴的な等しい出力を伴わないため検出が非常に難しい。これにより、トランザクション監視を行う組織が使用する common-input-ownership ヒューリスティックを無効化する可能性がある。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin の利用は従来の監視手法を大きく混乱させる可能性があり**, トランザクションのプライバシー追求において有望な進展です。

# 暗号通貨におけるプライバシーのベストプラクティス

## **ウォレット同期手法**

プライバシーとセキュリティを維持するために、ウォレットをブロックチェーンと同期させることは非常に重要です。特に注目すべき方法が二つあります:

- **Full node**: ブロックチェーン全体をダウンロードすることで、Full node は最大限のプライバシーを確保します。すべてのトランザクションがローカルに保存されるため、敵対者がユーザが関心を持つトランザクションやアドレスを特定することが不可能になります。
- **Client-side block filtering**: この方法はブロックチェーン内の各ブロックに対してフィルタを作成し、ウォレットがネットワーク監視者に特定の関心を露呈することなく関連トランザクションを識別できるようにします。ライトウォレットはこれらのフィルタをダウンロードし、ユーザのアドレスと一致した場合のみフルブロックを取得します。

## **匿名性のための Tor の利用**

Bitcoin がピアツーピアネットワーク上で動作することを考えると、Tor を使用して IP アドレスを隠すことが推奨されます。これによりネットワークとやり取りする際のプライバシーが向上します。

## **アドレスの再利用防止**

プライバシーを保護するためには、取引ごとに新しいアドレスを使うことが重要です。アドレスを再利用するとトランザクションが同一主体に紐づき、プライバシーが侵害される可能性があります。現代のウォレットは設計上、アドレス再利用を推奨しないようになっています。

## **トランザクションのプライバシー戦略**

- **Multiple transactions**: 支払いを複数のトランザクションに分割することで、金額を不明瞭にし、プライバシー攻撃を阻止できます。
- **Change avoidance**: おつり出力を必要としないトランザクションを選ぶことで、change detection 手法を混乱させ、プライバシーを高められます。
- **Multiple change outputs**: おつり回避が不可能な場合でも、複数の change output を生成することでプライバシーを改善できます。

# **Monero: A Beacon of Anonymity**

Monero はデジタルトランザクションにおける絶対的な匿名性のニーズに応え、高水準のプライバシーを提供します。

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas は Ethereum 上で操作を実行するのに必要な計算量を測る指標で、価格は **gwei** で表されます。例えば、2,310,000 gwei（または 0.00231 ETH）のトランザクションでは、gas limit と base fee が関係し、マイナーを奨励する tip が付くことがあります。ユーザは max fee を設定して過払いを防ぎ、余剰分は払い戻されます。

## **Executing Transactions**

Ethereum のトランザクションは送信者と受信者が関与し、受信者はユーザか smart contract のアドレスになり得ます。トランザクションは手数料を必要とし、マイニングされなければなりません。トランザクションに含まれる主要な情報は受信者、送信者の署名、value、任意の data、gas limit、および手数料です。特筆すべきは、送信者のアドレスは署名から導出されるため、トランザクションデータ内に送信者アドレスを明示する必要がない点です。

これらの慣行とメカニズムは、プライバシーとセキュリティを重視して暗号通貨に関わる人々にとって基礎となるものです。

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- サプライチェーンでの wallet UI の改ざんにより、署名直前に EIP-712 payload を変異させ、delegatecall ベースの proxy takeover（例: Safe masterCopy の slot-0 上書き）に有効な署名を収集される可能性があります。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
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
