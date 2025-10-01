# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing は、Solidity コードに小さな変更（mutants）を系統的に導入してテストスイートを再実行することで「テストをテスト」します。テストが失敗すればその mutant は排除されます。テストが通り続ければ mutant は生き残り、行/分岐カバレッジでは検出できないテストスイートの盲点を明らかにします。

重要なポイント: カバレッジはコードが実行されたことを示しますが、mutation testing は振る舞いが実際に検証されているかを示します。

## なぜカバレッジは誤解を招くか

次のような単純な閾値チェックを考えてみてください:
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

Mutation testing exposes this gap by mutating the condition and verifying your tests fail.

## Common Solidity mutation operators

Slither’s mutation engine applies many small, semantics-changing edits, such as:
- 演算子置換: `+` ↔ `-`、`*` ↔ `/` など
- 代入置換: `+=` → `=`、`-=` → `=`
- 定数置換: 非ゼロ → `0`、`true` ↔ `false`
- `if`/ループ内の条件の否定/置換
- 行全体をコメントアウト (CR: Comment Replacement)
- 行を `revert()` に置き換える
- データ型の差し替え: 例: `int128` → `int64`

Goal: Kill 100% of generated mutants, or justify survivors with clear reasoning.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry の例 (結果を取得して完全なログを保持する):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry を使用しない場合は、`--test-cmd` をテストの実行方法（例: `npx hardhat test`, `npm test`）に置き換えてください。

Artifacts and reports are stored in `./mutation_campaign` by default. Uncaught (surviving) mutants are copied there for inspection.

### 出力の理解

レポートの行は次のようになります:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 角括弧内のタグはミューテータのエイリアスです（例: `CR` = Comment Replacement）。
- `UNCAUGHT`は、ミューテーションされた振る舞いのもとでテストが通ったことを意味します → アサーションが欠けている。

## 実行時間の短縮: 影響の大きいミューテントを優先する

ミューテーションキャンペーンは数時間〜数日かかることがあります。コストを削減するためのヒント:
- スコープ: まず重要な contracts/directories に限定し、そこから拡大する。
- ミューテータの優先順位付け: ある行で高優先度のミューテントが生き残った場合（例: 行全体がコメント化される）、その行の低優先度バリアントはスキップできる。
- テストの並列化: runner が許せばテストを並列化し、依存関係/ビルドをキャッシュする。
- Fail-fast: 変更が明らかにアサーションの抜けを示すときは早期に停止する。

## 生き残ったミューテントのトリアージワークフロー

1) 変異した行と振る舞いを検査する。
- 変異行を適用してローカルで再現し、フォーカスしたテストを実行する。

2) テストを強化して、戻り値だけでなく状態をアサートする。
- 等価性や境界チェックを追加する（例: テストで threshold `==` を確認）。
- 事後条件をアサートする: 残高、総供給量（total supply）、認可の影響、発行されたイベントなど。

3) 過度に許容的なモックを現実的な振る舞いに置き換える。
- モックがオンチェーンで発生する転送、失敗経路、イベント発火を適切に再現するようにする。

4) fuzz テスト向けに不変条件（invariants）を追加する。
- 例: 価値保存、負でない残高、認可に関する不変条件、該当する場合の単調増加する供給量。

5) 生き残りが潰されるか明確に正当化されるまで slither-mutate を再実行する。

## ケーススタディ: 状態アサーションの欠如を明らかにする事例 (Arkis protocol)

Arkis DeFi プロトコルの監査中のミューテーションキャンペーンにより、以下のような生き残りが明らかになった:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
代入をコメントアウトしてもテストは壊れず、事後状態に対するアサーションが欠如していることが証明された。根本原因：コードが実際のトークン転送を検証する代わりに、ユーザー制御の `_cmd.value` を信用していた。攻撃者は期待される転送と実際の転送をずらして資金を奪取できる。結果：プロトコルの支払い能力に対する高重大度のリスク。

ガイダンス：値の移転、会計、またはアクセス制御に影響を与える生存したミュータントは、検出（killed）されるまで高リスクとして扱うこと。

## Practical checklist

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 生存したミュータントをトリアージし、変異した挙動下で失敗するようなテスト／不変条件を書き込む。
- 残高、供給量、認可、イベントをアサートする。
- 境界テストを追加する（`==`、オーバーフロー/アンダーフロー、ゼロアドレス、ゼロ量、空配列）。
- 非現実的なモックを置き換え、障害モードをシミュレートする。
- すべてのミュータントが検出（killed）されるか、コメントと合理的な説明で正当化されるまで反復する。

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
