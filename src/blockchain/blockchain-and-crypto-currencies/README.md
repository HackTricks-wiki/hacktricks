# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** は、特定の条件が満たされたときに blockchain 上で実行されるプログラムとして定義され、仲介者なしで合意の実行を自動化します。
- **Decentralized Applications (dApps)** は smart contracts の上に構築され、使いやすいフロントエンドと、透明で監査可能なバックエンドを備えています。
- **Tokens & Coins** は、coins がデジタルマネーとして機能するのに対し、tokens は特定の文脈における価値や所有権を表します。
- **Utility Tokens** はサービスへのアクセスを付与し、**Security Tokens** は資産の所有権を示します。
- **DeFi** は Decentralized Finance の略で、中央管理者なしで金融サービスを提供します。
- **DEX** と **DAOs** は、それぞれ Decentralized Exchange Platforms と Decentralized Autonomous Organizations を指します。

## Consensus Mechanisms

Consensus mechanisms は blockchain 上で安全で合意された transaction の検証を保証します:

- **Proof of Work (PoW)** は transaction の検証に計算能力を利用します。
- **Proof of Stake (PoS)** は validator に一定量の tokens の保有を求め、PoW と比べてエネルギー消費を削減します。

## Bitcoin Essentials

### Transactions

Bitcoin transactions は addresses 間での資金移動を伴います。Transactions は digital signatures によって検証され、private key の所有者のみが transfer を開始できることが保証されます。

#### Key Components:

- **Multisignature Transactions** は、transaction を承認するために複数の signature を必要とします。
- Transactions は **inputs**（資金の供給元）、**outputs**（送金先）、**fees**（miners に支払う手数料）、および **scripts**（transaction のルール）で構成されます。

### Lightning Network

Bitcoin のスケーラビリティを高めることを目的とし、channel 内で複数の transaction を可能にし、最終状態のみを blockchain に送信します。

## Bitcoin Privacy Concerns

**Common Input Ownership** や **UTXO Change Address Detection** のような privacy attacks は transaction のパターンを悪用します。**Mixers** や **CoinJoin** のような手法は、ユーザー間の transaction のつながりを不明瞭にすることで匿名性を向上させます。

## Acquiring Bitcoins Anonymously

方法には、現金取引、mining、そして mixers の利用が含まれます。**CoinJoin** は複数の transaction を混合して追跡を困難にし、**PayJoin** は CoinJoin を通常の transaction に見せかけることで、より高い privacy を実現します。

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin の世界では、transaction の privacy とユーザーの匿名性はしばしば懸念事項となります。以下は、attackers が Bitcoin privacy を侵害するために用いるいくつかの一般的な手法の簡略化した概要です。

## **Common Input Ownership Assumption**

一般に、異なるユーザーの inputs が 1 つの transaction にまとめられることは、複雑さのためにまれです。したがって、**同じ transaction 内の 2 つの input address は同じ所有者に属すると見なされることが多い**です。

## **UTXO Change Address Detection**

UTXO、すなわち **Unspent Transaction Output** は、transaction で全額を使い切る必要があります。もしその一部だけが別の address に送られると、残りは新しい change address に送られます。観測者はこの新しい address が送信者のものだと推測でき、privacy が損なわれます。

### Example

これを軽減するには、mixing services を利用するか、複数の addresses を使って所有者を判別しにくくする方法があります。

## **Social Networks & Forums Exposure**

ユーザーは時々オンラインで自分の Bitcoin address を共有し、address と所有者を**簡単に結び付けられる**ようにしてしまいます。

## **Transaction Graph Analysis**

Transactions は graph として可視化でき、資金の流れに基づいてユーザー間の潜在的なつながりを明らかにします。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

この heuristic は、複数の inputs と outputs を持つ transactions を分析して、どの output が送信者に戻る change かを推測するものです。

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
より多くの入力を追加すると change output がどの単一 input よりも大きくなる場合、その heuristic を混乱させることがあります。

## **Forced Address Reuse**

攻撃者は、以前に使用された address に少額を送信し、受信者が将来の transaction でこれらを他の inputs と結合することを期待します。これにより、address 同士が関連付けられます。

### Correct Wallet Behavior

wallet は、すでに使用済みの空の address で受け取った coins を使わないようにすべきです。これにより、この privacy leak を防げます。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** change のない transaction は、同じ user が所有する 2 つの address 間で行われている可能性が高いです。
- **Round Numbers:** transaction 内の round number は、それが payment であり、round でない output が change である可能性を示します。
- **Wallet Fingerprinting:** 異なる wallet は固有の transaction 作成パターンを持つため、analyst は使用された software と、場合によっては change address を特定できます。
- **Amount & Timing Correlations:** transaction の time や amount を公開すると、transaction を追跡可能にすることがあります。

## **Traffic Analysis**

network traffic を監視することで、attackers は transaction や block を IP address に関連付けられる可能性があり、user privacy が損なわれます。これは特に、ある entity が多数の Bitcoin node を運用している場合に当てはまり、transaction の監視能力が高まります。

## More

privacy attacks と defenses の包括的な一覧については、[Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) を参照してください。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: cash を通じて bitcoin を入手すること。
- **Cash Alternatives**: gift card を購入し、オンラインで bitcoin と交換すること。
- **Mining**: bitcoin を最も private に得る方法は mining です。特に単独で行う場合、mining pool が miner の IP address を知る可能性があるためです。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理論上は、bitcoin を盗むことも匿名で入手する別の方法になり得ますが、違法であり推奨されません。

## Mixing Services

mixing service を使うと、user は **bitcoins を送信** し、代わりに **異なる bitcoins** を受け取ることができ、元の所有者の追跡が難しくなります。ただし、service が log を保持せず、実際に bitcoins を返すことを信頼する必要があります。代替の mixing 手段には Bitcoin casino があります。

## CoinJoin

**CoinJoin** は、異なる user の複数の transaction を 1 つにまとめ、inputs と outputs を対応付けようとする人にとっての process を複雑にします。効果的ではあるものの、unique な input と output size を持つ transaction は、なお追跡される可能性があります。

CoinJoin を使用した可能性のある example transaction には `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` と `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` があります。

詳細については、[CoinJoin](https://coinjoin.io/en) を参照してください。Ethereum の同様の service については、[Tornado Cash](https://tornado.cash) を確認してください。これは miner の資金を使って transaction を匿名化します。

## PayJoin

**CoinJoin** の派生である **PayJoin** (または P2EP) は、2 者間の transaction（例: customer と merchant）を通常の transaction のように偽装し、CoinJoin に特徴的な等しい outputs を持ちません。これにより検出が極めて困難になり、transaction surveillance entity が使用する common-input-ownership heuristic を無効化できる可能性があります。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoinの活用は従来の監視手法を大きく崩す可能性があり**、取引プライバシーの追求において有望な発展です。

# 仮想通貨におけるプライバシーのベストプラクティス

## **Wallet Synchronization Techniques**

プライバシーとセキュリティを維持するには、wallet を blockchain と同期させることが重要です。特に目立つ2つの方法があります。

- **Full node**: blockchain 全体をダウンロードすることで、full node は最大限のプライバシーを確保します。過去に行われたすべての transaction がローカルに保存されるため、攻撃者がユーザーの関心のある transaction や address を特定することはできません。
- **Client-side block filtering**: この方法では blockchain の各 block に対して filter を作成し、network observer に特定の関心を明かすことなく、wallet が関連する transaction を識別できるようにします。軽量 wallet はこれらの filter をダウンロードし、ユーザーの address と一致した場合にのみ full block を取得します。

## **匿名性のためのTorの利用**

Bitcoin は peer-to-peer network で動作するため、network とのやり取り時の privacy を高めるには、IP address を隠すために Tor の使用が推奨されます。

## **Address Reuse の防止**

プライバシーを守るには、transaction ごとに新しい address を使うことが不可欠です。address を再利用すると、transaction が同じ主体に結び付けられ、privacy が損なわれます。現代の wallet は設計上、address reuse を避けるよう促します。

## **Transaction Privacy のための戦略**

- **Multiple transactions**: 支払いを複数の transaction に分割すると transaction amount を分かりにくくでき、privacy attack を妨げます。
- **Change avoidance**: change output を必要としない transaction を選ぶことで、change detection methods を崩し、privacy を高められます。
- **Multiple change outputs**: change を避けられない場合でも、複数の change output を生成することで privacy を改善できます。

# **Monero: 匿名性の灯台**

Monero は、デジタル transaction における完全な匿名性の必要性に応え、privacy の高い基準を打ち立てています。

# **Ethereum: Gas と Transaction**

## **Gas の理解**

Gas は Ethereum 上で operation を実行するのに必要な computational effort を表し、**gwei** で価格付けされます。たとえば、2,310,000 gwei（または 0.00231 ETH）の transaction には gas limit と base fee があり、miner へのインセンティブとして tip が含まれます。ユーザーは max fee を設定して払い過ぎを防げ、超過分は返金されます。

## **Transaction の実行**

Ethereum の transaction には sender と recipient が含まれ、これらは user または smart contract address のいずれでもあり得ます。fee が必要で、mined されなければなりません。transaction の必須情報には、recipient、sender's signature、value、任意の data、gas limit、fees が含まれます。特に、sender's address は signature から推定されるため、transaction data に含める必要はありません。

これらの実践と仕組みは、privacy と security を優先しながら cryptocurrencies を扱うすべての人にとって基礎となります。

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

## ZK Proof / zkVM Guest Integrity

When a prover uses a **zkVM** or an application-specific proof circuit to attest a claim, the verifier is only learning that the **guest program executed as written**. If the guest contains **unsafe deserialization**, **undefined behavior**, or **missing semantic constraints**, a malicious prover may generate a proof that verifies while the **public metrics or claimed invariant are false**.

### Unsafe deserialization inside proof guests

- Treat private witness/circuit bytes as **untrusted attacker input** even if they are hidden by the proof.
- Avoid deserializing them with unchecked helpers such as `rkyv::access_unchecked` unless the bytes were already validated out-of-band.
- Enum discriminants, relative pointers, lengths, and indexes loaded from untrusted serialized data must be validated before they influence control flow or memory access.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
If a field such as `op.kind` is an enum and an attacker can inject an **out-of-range discriminant**, every downstream `match` on that value becomes suspicious.

### Jump-table / UB counter bypass

If Rust lowers a large `match` into a **jump table**, an invalid enum discriminant may produce **undefined control flow**. A dangerous pattern is:

1. One `match` updates **security-critical counters/constraints**.
2. A second `match` performs the **real instruction semantics**.
3. An out-of-range discriminant indexes past the first jump table and lands in code associated with the second one.

Result: the operation still executes, but the accounting path is skipped. In a zkVM this can forge proofs that report impossible metrics such as fewer gates, fewer expensive operations, or other falsified bounded resources.

Review checklist:

- Look for attacker-controlled enums deserialized from witness/private input.
- Inspect repeated `match` statements over the same opcode/kind field.
- Treat `unsafe` + unchecked deserialization + large opcode dispatch as a high-risk combination.
- Reverse engineer the emitted binary when needed; jump-table layout can matter more than the source.

### Missing semantic constraints in reversible/specialized interpreters

Do not just validate memory safety; also validate the **semantic rules** that the proof is meant to enforce.

For reversible/quantum-like instruction sets, ensure operands that must be distinct are actually constrained to be distinct. A Toffoli/CCX-like operation implemented as:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
ゲストが拒否しない場合は安全でなくなります:
```text
op.q_control1 == op.q_control2 == op.q_target
```
その場合、遷移は次のように崩壊する:
```text
q = q ^ (q & q) = 0
```
This creates a **deterministic reset primitive**, 可逆性の前提を壊し、より安価な意図しない計算を可能にします。リソース使用を証明する proof systems では、これにより攻撃者は機能チェックを満たしつつ、verifier が強制されていると考えるコストモデルを回避できます。

### ZK systems でテストすべきこと

- すべての guest parsers を、壊れた witness/private-input エンコーディングで fuzz する。
- opcode dispatch の前に enum の範囲検証を assert する。
- operand aliasing やその他の無効な instruction 形式に対する semantic checks を追加する。
- 報告された/public counters を独立した reference implementation と比較する。
- 有効な proof であっても、guest program が buggy なら **間違った statement** を証明してしまう可能性があることを忘れない。

## DeFi/AMM Exploitation

DEXes や AMMs の実践的な exploitation（Uniswap v4 hooks、rounding/precision abuse、flash‑loan によって増幅された threshold‑crossing swaps）を調査している場合は、こちらを確認してください:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

`supply == 0` のときにキャッシュされた virtual balances が poisoned され得る multi-asset weighted pools については、こちらを参照してください:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
