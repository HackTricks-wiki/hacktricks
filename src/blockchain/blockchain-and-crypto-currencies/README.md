# ブロックチェーンと暗号通貨

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** は、特定の条件が満たされたときにブロックチェーン上で実行されるプログラムとして定義され、仲介者なしで合意の実行を自動化します。
- **Decentralized Applications (dApps)** は smart contracts の上に構築され、ユーザーフレンドリーなフロントエンドと透明で監査可能なバックエンドを備えます。
- **Tokens & Coins** は、coins がデジタル通貨として機能する一方で、tokens が特定のコンテキストで価値や所有権を表すという違いがあります。
- **Utility Tokens** はサービスへのアクセスを付与し、**Security Tokens** は資産の所有を示します。
- **DeFi** は Decentralized Finance の略で、中央当局なしで金融サービスを提供します。
- **DEX** と **DAOs** はそれぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## コンセンサス機構

コンセンサス機構はブロックチェーン上で取引の検証を安全かつ合意されたものにします：

- **Proof of Work (PoW)** は取引検証のために計算能力に依存します。
- **Proof of Stake (PoS)** はバリデータが一定量の tokens を保有することを要求し、PoW と比べてエネルギー消費を低減します。

## Bitcoin の基礎

### トランザクション

Bitcoin トランザクションはアドレス間で資金を移転することを含みます。トランザクションは digital signatures によって検証され、private key の所有者だけが転送を開始できることを保証します。

#### 主要構成要素:

- **Multisignature Transactions** はトランザクションを承認するために複数の署名を必要とします。
- トランザクションは **inputs**（資金の出所）、**outputs**（宛先）、**fees**（miners に支払われる手数料）、および **scripts**（トランザクションのルール）で構成されます。

### Lightning Network

Lightning Network は、チャネル内で複数のトランザクションを可能にし、最終状態のみを blockchain にブロードキャストすることで、Bitcoin のスケーラビリティを向上させることを目的としています。

## Bitcoin のプライバシー上の懸念

Privacy attacks、例えば **Common Input Ownership** や **UTXO Change Address Detection** はトランザクションのパターンを悪用します。**Mixers** や **CoinJoin** のような戦略は、ユーザー間のトランザクションのつながりを隠すことで匿名性を高めます。

## Bitcoin を匿名で取得する方法

方法には現金取引、mining、mixers の使用が含まれます。**CoinJoin** は複数のトランザクションを混ぜて追跡を困難にし、**PayJoin** は CoinJoin を通常のトランザクションに偽装してさらにプライバシーを高めます。

# Bitcoin Privacy Atacks

# Bitcoin プライバシー攻撃の概要

Bitcoin の世界では、トランザクションのプライバシーやユーザーの匿名性がしばしば懸念されます。以下は、攻撃者が Bitcoin のプライバシーを侵害するためによく使ういくつかの一般的な手法の簡潔な概要です。

## **Common Input Ownership Assumption**

複数のユーザーからの inputs が単一のトランザクションにまとめられることは、関与する複雑性のため一般的には稀です。したがって、**同じトランザクション内の二つの入力アドレスは同一の所有者に属すると推定されることが多い**です。

## **UTXO Change Address Detection**

UTXO、すなわち **Unspent Transaction Output** はトランザクション内で完全に使われなければなりません。もし一部だけが別のアドレスに送られると、残りは新しい change address に送られます。観察者はこの新しいアドレスが送信者に属すると推定でき、プライバシーが侵害されます。

### 例

これを緩和するために、mixing services や複数のアドレスの使用が所有権を隠すのに役立ちます。

## **Social Networks & Forums Exposure**

ユーザーは時折オンラインで自分の Bitcoin アドレスを共有するため、アドレスと所有者を結びつけることが**容易**になります。

## **Transaction Graph Analysis**

トランザクションはグラフとして可視化でき、資金の流れに基づいてユーザー間の潜在的なつながりを明らかにします。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

このヒューリスティックは、複数の inputs と outputs を持つトランザクションを分析し、どの output が送信者に戻る change であるかを推測することに基づいています。

### 例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

攻撃者は、受取人が将来のトランザクションでこれらを他の入力と組み合わせることを期待して、以前に使用されたアドレスに少額を送ることがあります。これによりアドレス同士が結びつけられる可能性があります。

### Correct Wallet Behavior

ウォレットは、このプライバシー leak を防ぐために、既に使用されていて空になっているアドレスで受け取ったコインを使用しないようにすべきです。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** お釣りがないトランザクションは、同じユーザが所有する2つのアドレス間の取引である可能性が高いです。
- **Round Numbers:** トランザクションに丸い数字が含まれている場合、それは支払いであることを示唆しており、丸くない出力が通常はお釣りです。
- **Wallet Fingerprinting:** 異なるウォレットはトランザクション生成のパターンが固有であるため、解析者は使用されたソフトウェアを特定し、場合によっては change address を見つけられることがあります。
- **Amount & Timing Correlations:** トランザクションの時間や金額を公開すると、トランザクションが追跡可能になることがあります。

## **Traffic Analysis**

ネットワークトラフィックを監視することで、攻撃者はトランザクションやブロックをIPアドレスに結び付け、ユーザのプライバシーを損なう可能性があります。特に多数の Bitcoin ノードを運用している主体は、トランザクションの監視能力が強化されます。

## More

プライバシー攻撃と防御の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) を参照してください。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 現金で bitcoin を取得する方法。
- **Cash Alternatives**: ギフトカードを購入してオンラインで bitcoin に交換する方法。
- **Mining**: 最もプライベートな方法はマイニングで、特にソロマイニングではより匿名性が高いです。マイニングプールはマイナーのIPアドレスを把握している可能性があります。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論上はビットコインを盗むことも匿名取得の方法になり得ますが、違法であり推奨されません。

## Mixing Services

ミキシングサービスを利用することで、ユーザはビットコインを**送金**し、代わりに**異なるビットコインを受け取る**ことができ、元の所有者の追跡を困難にします。ただし、サービスがログを保持しないことや実際にビットコインを返すことを信頼する必要があります。代替のミキシング手段として Bitcoin カジノがあります。

## CoinJoin

**CoinJoin** は複数ユーザのトランザクションを1つに合成することで、入力と出力の対応付けを困難にします。とはいえ、ユニークな入力・出力サイズを持つトランザクションは依然として追跡される可能性があります。

CoinJoin を使用した可能性のある例として、`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` と `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` があります。

詳細は [CoinJoin](https://coinjoin.io/en) を参照してください。Ethereum 上の類似サービスとしては、マイナーの資金を使ってトランザクションを匿名化する [Tornado Cash](https://tornado.cash) があります。

## PayJoin

CoinJoin の変種である **PayJoin**（または P2EP）は、顧客と商人など二者間のトランザクションを通常のトランザクションに紛れ込ませ、CoinJoin に特徴的な等しい出力を伴わないため検出が非常に難しくなります。これにより、取引監視機関が使用する common-input-ownership heuristic を無効にする可能性があります。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin の利用は従来の監視手法に大きな影響を与え得るため、取引プライバシーの向上において有望な進展です。**

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

プライバシーとセキュリティを維持するために、wallet を blockchain と同期させることが重要です。特に有効な2つの方法:

- **Full node**: ブロックチェーン全体をダウンロードすることで、full node は最大限のプライバシーを確保します。過去のすべての取引がローカルに保存されるため、攻撃者がユーザーの関心のある取引やアドレスを特定することが不可能になります。
- **Client-side block filtering**: この方法では、ブロックごとにフィルタを作成し、wallet が関連する取引を特定できるようにしてネットワーク監視者に特定の関心を露出しません。ライトウェイト wallet はこれらのフィルタだけをダウンロードし、ユーザーのアドレスと一致した場合にのみフルブロックを取得します。

## **Utilizing Tor for Anonymity**

Bitcoin がピア・トゥ・ピアネットワークで動作することを鑑み、ネットワークとやり取りする際の IP アドレスを隠すために Tor の使用が推奨されます。

## **Preventing Address Reuse**

プライバシーを守るためには、取引ごとに新しいアドレスを使うことが重要です。アドレスの再利用は取引を同一主体に結びつけてプライバシーを損なう可能性があります。現代の wallet は設計上、アドレスの再利用を避けるようになっています。

## **Strategies for Transaction Privacy**

- **Multiple transactions**: 支払いを複数の取引に分割することで、金額を不明瞭にし、プライバシー攻撃を妨害できます。
- **Change avoidance**: change 出力を必要としない取引を選ぶことで、change 検出手法を乱しプライバシーを高めます。
- **Multiple change outputs**: change を避けられない場合でも、複数の change 出力を生成することでプライバシーを改善できます。

# **Monero: A Beacon of Anonymity**

Monero はデジタル取引における絶対的匿名性の要件に応え、プライバシーの高い基準を設定しています。

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas は Ethereum 上で操作を実行するために必要な計算量を測る指標で、単位は **gwei** です。例えば、取引が 2,310,000 gwei（0.00231 ETH）かかる場合、gas limit と base fee があり、miner を刺激するための tip があります。ユーザーは max fee を設定して過払いを防ぐことができ、超過分は返金されます。

## **Executing Transactions**

Ethereum の取引は送信者と受信者（ユーザーまたは smart contract のアドレス）が関与し、手数料が必要でマイニングされなければなりません。取引に含まれる主要な情報は受信者、送信者の署名、value、任意の data、gas limit、手数料などです。送信者のアドレスは署名から導出されるため、取引データ内に明示的に含める必要はありません。

これらの慣行とメカニズムは、プライバシーとセキュリティを重視して暗号通貨に関与する人々にとって基本となるものです。

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
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
