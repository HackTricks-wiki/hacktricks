# Solidity のミューテーションテスト (Slither (slither-mutate) を使用)

{{#include ../../../banners/hacktricks-training.md}}

ミューテーションテストは、Solidity コードに小さな変更（ミュータント）を体系的に導入し、テストスイートを再実行することで「テストをテスト」します。テストが失敗すればミュータントは殺されます。テストが通り続ける場合、ミュータントは生き残り、line/branch coverage では検出できないテストスイートの盲点を明らかにします。

重要なポイント: coverage はコードが実行されたことを示すだけで、mutation testing は振る舞いが実際にアサートされているかどうかを示します。

## なぜ coverage は誤解を招くか

次の単純なしきい値チェックを考えてみよう:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
ユニットテストが閾値より下の値と閾値より上の値だけをチェックしている場合、等価性境界（==）をアサートしていなくても行/分岐カバレッジを100%に到達することがある。`deposit >= 2 ether` にリファクタリングしても、そのようなテストは通り続け、プロトコルのロジックを黙って破壊してしまう。

ミューテーションテストは条件を変更してテストが失敗することを検証することで、このギャップを暴露する。

## 一般的な Solidity のミューテーションオペレータ

Slither’s mutation engine は次のような、小さな意味を変える編集を多数適用する:
- 演算子の置換: `+` ↔ `-`, `*` ↔ `/`, など
- 代入の置換: `+=` → `=`, `-=` → `=`
- 定数の置換: non-zero → `0`, `true` ↔ `false`
- `if`/ループ内の条件の否定/置換
- 行全体をコメントアウト（CR: Comment Replacement）
- 行を `revert()` に置換
- データ型の入れ替え: 例: `int128` → `int64`

目標: 生成されたミュータントを100%排除する、または生存したものについて明確な理由で正当化する。

## slither-mutate を使ったミューテーションテストの実行

Requirements: Slither v0.10.2+.

- オプションとミューテータの一覧:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundryの例 (capture results and keep a full log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry を使用していない場合は、`--test-cmd` をテスト実行コマンド（例: `npx hardhat test`, `npm test`）に置き換えてください。

成果物とレポートはデフォルトで `./mutation_campaign` に保存されます。検出されずに残った（生存した）ミュータントは検査のためにそこにコピーされます。

### 出力の理解

レポート行は次のようになります:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 角括弧内のタグは mutator のエイリアスです（例: `CR` = Comment Replacement）。
- `UNCAUGHT` は、変異した振る舞いの下でテストがパスしたことを意味します → アサーションが欠けている。

## 実行時間の短縮: 影響の大きい変異体(mutants)を優先する

Mutation campaigns は数時間〜数日かかることがあります。コスト削減のヒント：
- 範囲: まず重要な contracts/ディレクトリのみを対象にし、その後拡大する。
- Prioritize mutators: ある行で優先度の高い mutator が生き残った場合（例: 行全体がコメント化される）、その行については優先度の低いバリアントをスキップできる。
- テストを並列化できるなら並列化する；依存関係やビルドをキャッシュする。
- Fail-fast: 変更が明らかにアサーションの欠落を示す場合は早期に停止する。

## 生き残った mutants のトリアージワークフロー

1) 変異した行と振る舞いを確認する。
- 変異行を適用してフォーカスしたテストを実行し、ローカルで再現する。

2) テストを強化して、戻り値だけでなく状態をアサートする。
- 等価性や境界チェックを追加（例: 閾値が `==` であることをテスト）。
- 事後条件をアサート: 残高、総供給量、権限の効果、発行されたイベントなど。

3) 過度に許容的なモックを、実際の振る舞いに置き換える。
- モックがチェーン上で起こる transfers、失敗パス、イベント発行を強制することを確認する。

4) ファズテスト用の不変条件を追加する。
- 例: 価値保存、負でない残高、権限に関する不変式、適用可能なら単調増加する供給量など。

5) slither-mutate を再実行し、survivors が排除されるか明確に正当化されるまで続ける。

## ケーススタディ: 欠落した状態アサーションを露呈する事例 (Arkis protocol)

Arkis DeFi protocol の監査中に実施した mutation campaign では、次のような survivors が表面化した：
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
代入をコメントアウトしてもテストが壊れなかったため、ポストステートのアサーションが欠如していることが明らかになった。根本原因: 実際のトークン転送を検証せず、ユーザー制御の _cmd.value を信用していた。攻撃者は期待される転送と実際の転送をずらして資金を流出させる可能性がある。結果: プロトコルの支払能力（solvency）に対する高重大度のリスク。

ガイダンス: 価値転送、会計、またはアクセス制御に影響する survivors（生き残ったミュータント）は、kill（無効化）されるまで高リスクとして扱うこと。

## 実践チェックリスト

- 対象を絞ったキャンペーンを実行する:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- survivorsをトリアージし、変異した振る舞い下で失敗するテスト／不変条件を書きます。
- 残高、供給量、承認、イベントを検証する。
- 境界テストを追加する（`==`、オーバーフロー/アンダーフロー、zero-address、zero-amount、空配列）。
- 現実的でないモックを置き換え、失敗モードをシミュレートする。
- すべてのミュータントが kill されるか、コメントと根拠で正当化されるまで反復する。

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
