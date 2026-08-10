# Smart Contracts の Mutation Testing (slither-mutate, mewt, MuTON)

Mutation testing は、contract code に小さな変更（mutants）を体系的に加え、test suite を再実行することで「tests をテスト」します。test が失敗した場合、その mutant は kill されます。tests がそのまま pass した場合、その mutant は survive し、line/branch coverage では検出できない盲点が明らかになります。

重要な考え方: Coverage は code が実行されたことを示します。mutation testing は、behavior が実際に assertion されているかを示します。<sup>[[2]](#references)</sup>

## Coverage が欺く可能性がある理由

次の単純な threshold check を考えてみましょう:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
しきい値を下回る値と上回る値だけをチェックする Unit test は、等値境界（==）のアサートに失敗していても、100% の line/branch coverage に達する可能性があります。`deposit >= 2 ether` への refactor を行ってもこのような test は引き続き pass し、protocol logic を気付かないうちに壊してしまいます。<sup>[[2]](#references)</sup>

Mutation testing は、condition を mutation し、test が fail することを検証することで、このギャップを明らかにします。

Smart contract では、生き残った mutant は多くの場合、以下に関するチェックの欠落に対応します。
- Authorization と role boundary
- Accounting/value-transfer invariant
- Revert condition と failure path
- Boundary condition（`==`、zero value、empty array、max/min value）

## 最も高い security signal を持つ mutation operator

Contract auditing に役立つ mutation class:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: statement を `revert()` に置き換え、未実行の path を明らかにする
- **Medium severity**: 行を comment out / logic を削除し、検証されていない side effect を明らかにする
- **Low severity**: `>=` -> `>` や `+` -> `-` のような、微妙な operator または constant の置換
- その他の一般的な編集: assignment の置換、boolean の反転、condition の否定、type の変更

実用上の目標は、意味のある mutant をすべて kill し、無関係または semantic equivalent であるため生き残った mutant については明示的に根拠を示すことです。

## regex より syntax-aware mutation が優れている理由

以前の mutation engine は regex または行単位の書き換えに依存していました。これは機能しますが、重要な制限があります。<sup>[[1]](#references)</sup>
- 複数行の statement を安全に mutation することが難しい
- Language structure が理解されないため、comment/token が不適切に対象となる可能性がある
- 弱い行に対して考えられるすべての variant を生成すると、大量の runtime を浪費する

AST または Tree-sitter ベースの tooling は、raw line ではなく構造化された node を対象にすることで、この問題を改善します。<sup>[[1]](#references)</sup>
- **slither-mutate** は Slither の Solidity AST を使用します。<sup>[[4]](#references)</sup>
- **mewt** は language-agnostic な core として Tree-sitter を使用します。<sup>[[6]](#references)</sup>
- **MuTON** は `mewt` を基盤とし、FunC、Tolk、Tact などの TON language を first-class support します。<sup>[[7]](#references)</sup>

これにより、複数行の construct と expression-level mutation の信頼性が、regex のみに依存する approach よりも大幅に向上します。

## slither-mutate で mutation testing を実行する

Requirements: Slither v0.10.2+。

- Options と mutator を一覧表示する:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry example（結果を取得し、完全なログを保持）:<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry を使用しない場合は、`--test-cmd` をテストの実行方法（例: `npx hardhat test`、`npm test`）に置き換えてください。

Artifacts はデフォルトで `./mutation_campaign` に保存されます。捕捉されなかった（surviving）mutants は、検査用にそこへコピーされます。<sup>[[5]](#references)</sup>

### 出力の理解

Report の行は次のようになります:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 角括弧内のタグは mutator の alias です（例: `CR` = Comment Replacement）。
- `UNCAUGHT` は、mutated behavior のもとでテストが通過したことを意味します → assertion が不足しています。

## 実行時間の短縮: 影響の大きい mutants を優先する

Mutation campaign には数時間から数日かかることがあります。コストを削減するためのヒント:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: まず重要な contracts/directories のみに対象を絞り、その後拡張します。
- Mutators の優先順位付け: ある行の high-priority mutant が生き残った場合（たとえば `revert()` や comment-out）、その行の lower-priority variants はスキップします。
- 2 段階の campaign を使用する: まず focused/fast tests を実行し、その後 uncaught mutants のみを full suite で再テストします。
- 可能な場合は mutation targets を特定の test commands に対応付けます（例: auth code -> auth tests）。
- 時間が限られている場合は、campaign の対象を high/medium severity mutants に制限します。
- runner が対応している場合は tests を parallelize し、dependencies/builds を cache します。
- Fail-fast: 変更によって assertion gap が明確に示された時点で早期に停止します。

実行時間の計算は厳しいものです: `1000 mutants x 5-minute tests ~= 83 hours`。そのため、campaign の設計は mutator 自体と同じくらい重要です。<sup>[[1]](#references)</sup>

## Persistent campaigns と大規模な triage

以前の workflow の弱点の 1 つは、結果を `stdout` にのみ出力することでした。長時間の campaign では、これにより pause/resume、filtering、review が難しくなります。<sup>[[1]](#references)</sup>

`mewt`/`MuTON` は、mutants と outcomes を SQLite-backed campaigns に保存することでこの問題を改善します。メリット:<sup>[[1]](#references)</sup>
- 進捗を失わずに長時間の実行を pause および resume できる
- 特定の file または mutation class にある uncaught mutants のみを filter できる
- review tooling 用に結果を SARIF へ export/translate できる
- raw terminal logs の代わりに、AI-assisted triage へ小さく filter された result sets を渡せる

Persistent results は、mutation testing が一度限りの手動 review ではなく audit pipeline の一部になった場合に特に有用です。

## 生き残った mutants の triage workflow

1) mutated line と behavior を確認します。
- mutated line を適用し、focused test を実行してローカルで再現します。

2) return values だけでなく state を assertion するよう tests を強化します。
- equality-boundary checks を追加します（例: threshold `==` をテストする）。
- post-conditions を assertion します: balances、total supply、authorization effects、emitted events。

3) 過度に permissive な mocks を realistic behavior に置き換えます。
- mocks が on-chain で発生する transfers、failure paths、event emissions を強制するようにします。

4) fuzz tests に invariants を追加します。
- 例: value の conservation、non-negative balances、authorization invariants、該当する場合は monotonic supply。

5) true positives と semantic no-ops を分離します。
- 例: `x > 0` -> `x != 0` は、`x` が unsigned の場合は意味がありません。

6) survivors が kill されるか、明示的に正当化されるまで campaign を再実行します。

## Case study: 不足していた state assertions の発見（Arkis protocol）

Arkis DeFi protocol の audit 中に実施された mutation campaign により、次のような survivors が明らかになりました:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
代入をコメントアウトしてもテストは失敗しなかった。これは、post-state assertions が欠落していることを示している。根本原因は、実際の token transfers を検証せず、ユーザーが制御できる `_cmd.value` を信頼していたことだった。攻撃者は、想定された transfers と実際の transfers の同期を外して、資金を流出させることができた。結果として、protocol の solvency に対する高深刻度のリスクとなった。<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: value transfers、accounting、または access control に影響する survivors は、kill されるまで high-risk として扱う。

## Do not blindly generate tests to kill every mutant

Mutation-driven test generation は、現在の実装が誤っている場合に裏目に出る可能性がある。例として、`priority >= 2` を `priority > 2` に mutation すると挙動は変わるが、正しい修正が常に「`priority == 2` のテストを書く」ことになるとは限らない。その挙動自体がバグである可能性もある。<sup>[[1]](#references)</sup>

より安全な workflow:
- surviving mutants を使用して、曖昧な要件を特定する
- specs、protocol docs、または reviewers から期待される挙動を検証する
- その後でのみ、その挙動を test/invariant としてエンコードする

そうしなければ、実装上の偶発的な挙動を test suite にハードコードし、誤った安心感を得るリスクがある。

## Practical checklist

- 対象を絞った campaign を実行する:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 利用可能な場合は、regex-only mutation よりも syntax-aware mutators（AST/Tree-sitter）を優先する。
- survivors を triage し、mutation 後の挙動で失敗する tests/invariants を作成する。
- balances、supply、authorizations、events を assert する。
- 境界値テストを追加する（`==`、overflows/underflows、zero-address、zero-amount、empty arrays）。
- 非現実的な mocks を置き換え、failure modes をシミュレートする。
- tooling が対応している場合は結果を persist し、triage の前に uncaught mutants を filter する。
- runtime を管理可能な範囲に保つため、two-phase または per-target campaigns を使用する。
- すべての mutants が kill されるか、comments と rationale によって正当化されるまで反復する。

## References

- [1] [agentic era における Mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [テストで検出できないバグを見つけるために mutation testing を使用する (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
