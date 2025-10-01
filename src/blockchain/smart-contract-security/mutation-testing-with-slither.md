# Mutation Testing: Solidity向け Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing は、Solidityコードに小さな変更（mutants）を体系的に導入してテストスイートを再実行することで「テストをテスト」します。テストが失敗すればそのmutantはkillされます。テストが通り続ければmutantは生き残り、行/分岐カバレッジでは検出できないテストスイートの盲点を明らかにします。

重要なポイント：カバレッジはコードが実行されたことを示すだけであり、Mutation testing は挙動が実際にアサートされているかを示します。

## なぜカバレッジは誤解を招くのか

次の単純な閾値チェックを考えてみましょう:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit tests that only check a value below and a value above the threshold can reach 100% line/branch coverage while failing to assert the equality boundary (==). A refactor to `deposit >= 2 ether` would still pass such tests, silently breaking protocol logic.

ミニマムとマックスの値だけをチェックするユニットテストは、等価境界（==）を検証していなくても行/分岐カバレッジを100%に到達できることがある。`deposit >= 2 ether` にリファクタリングしてもそのテストは通り続け、プロトコルのロジックを密かに破壊してしまう。

Mutation testing exposes this gap by mutating the condition and verifying your tests fail.

ミューテーションテストは条件を変異させ、テストが失敗することを確認することでこのギャップを明らかにする。

## Common Solidity mutation operators

Slither’s mutation engine applies many small, semantics-changing edits, such as:
- Operator replacement: `+` ↔ `-`, `*` ↔ `/`, etc.
- Assignment replacement: `+=` → `=`, `-=` → `=`
- Constant replacement: non-zero → `0`, `true` ↔ `false`
- Condition negation/replacement inside `if`/loops
- Comment out whole lines (CR: Comment Replacement)
- Replace a line with `revert()`
- Data type swaps: e.g., `int128` → `int64`

Slither のミューテーションエンジンは、小さく意味を変える多数の編集を適用します。例えば：
- 演算子の置換：`+` ↔ `-`, `*` ↔ `/` など
- 代入の置換：`+=` → `=`, `-=` → `=`
- 定数の置換：非ゼロ → `0`, `true` ↔ `false`
- `if`/ループ内の条件の否定/置換
- 行全体をコメントアウト (CR: Comment Replacement)
- 行を `revert()` に置き換え
- データ型の入れ替え：例 `int128` → `int64`

Goal: Kill 100% of generated mutants, or justify survivors with clear reasoning.

目標：生成されたミュータントを100%排除する、または生き残ったものを明確な理由で正当化すること。

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:

## slither-mutate を使ったミューテーションテストの実行

要件：Slither v0.10.2+。

- オプションとミューテータを一覧表示：
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry の例（結果をキャプチャして完全なログを保持する）:
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry を使用していない場合、`--test-cmd` をテストを実行するコマンド（例: `npx hardhat test`, `npm test`）に置き換えてください。

Artifacts and reports are stored in `./mutation_campaign` by default. 検出されなかった（生存した）ミュータントは検査のためそこにコピーされます。

### 出力の理解

Report lines look like:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 括弧内のタグは mutator のエイリアスです（例: `CR` = Comment Replacement）。
- `UNCAUGHT` は変異した振る舞いの下でテストが合格したことを意味します → アサーションが不足している。

## Reducing runtime: prioritize impactful mutants

Mutation campaigns は数時間〜数日かかることがあります。コストを削減するためのヒント:
- Scope: まずは重要な contracts/directories のみを対象にし、徐々に拡大する。
- Prioritize mutators: 行上の高優先度の mutant が生き残った場合（例: 行全体がコメント化されるなど）、その行に対する低優先度のバリアントはスキップできる。
- Parallelize tests if your runner allows it; cache dependencies/builds.
- Fail-fast: 変更が明確にアサーションの欠落を示している場合は早期に停止する。

## Triage workflow for surviving mutants

1) 変異した行と振る舞いを検査する。
- 変異行を適用してフォーカスしたテストを実行し、ローカルで再現する。

2) テストを強化して、返り値だけでなく state をアサートする。
- 等価性や境界チェックを追加する（例: 閾値の `==` をテスト）。
- ポストコンディションをアサートする: balances、total supply、authorization の効果、そして emitted events。

3) 過度に許容的な mocks を現実的な振る舞いに置き換える。
- mocks が transfers、failure paths、そして on-chain で発生する event emissions を強制することを確認する。

4) fuzz tests のために invariants を追加する。
- 例: value の保存則、non-negative balances、authorization invariants、該当する場合の monotonic supply。

5) survivors が消えるか明示的に正当化されるまで slither-mutate を再実行する。

## Case study: revealing missing state assertions (Arkis protocol)

Arkis DeFi protocol の監査中の mutation campaign で、次のような survivors が表面化しました:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
代入をコメントアウトしてもテストが壊れなかったため、事後状態のアサーションが欠如していることが証明された。根本原因：実際のトークン転送を検証するのではなく、ユーザー制御の `_cmd.value` を信用していた。攻撃者は期待される転送と実際の転送をずらして資金を流出させ得る。結果：プロトコルの支払能力に対する高リスク。

Guidance: 価値転送、会計、またはアクセス制御に影響する残存変異は、除去されるまで高リスクとして扱うこと。

## 実践チェックリスト

- 対象を絞ったキャンペーンを実行：
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 残存変異をトリアージし、変異した振る舞いで失敗するようなテスト／不変条件を作成する。
- 残高、供給量、認可、イベントをアサートする。
- 境界テストを追加する（`==`、オーバーフロー/アンダーフロー、ゼロアドレス、ゼロ量、空配列）。
- 現実的でないモックは置き換え、故障モードをシミュレートする。
- すべての変異が検出（kill）されるか、コメントと根拠で正当化されるまで繰り返す。

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
