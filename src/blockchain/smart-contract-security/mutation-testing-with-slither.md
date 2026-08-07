# Smart Contract の Mutation Testing（slither-mutate、mewt、MuTON）

{{#include ../../banners/hacktricks-training.md}}

Mutation testing は、contract code に小さな変更（mutant）を体系的に加え、test suite を再実行することで「tests your tests」を行います。test が失敗すれば、その mutant は kill されます。test がそのまま pass すれば、mutant は survive し、line/branch coverage では検出できない盲点が明らかになります。

重要な考え方：Coverage は code が実行されたことを示します。Mutation testing は、behavior が実際に assert されているかどうかを示します。<sup>[[2]](#references)</sup>

## Coverage が誤解を招く理由

次の単純な threshold check を考えてみましょう：
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
しきい値未満の値としきい値を超える値だけをチェックする Unit tests は、等価境界（==）のアサーションに失敗していても、line/branch coverage 100% に到達できます。`deposit >= 2 ether` へのリファクタリングを行っても、このようなテストは通過し、プロトコルロジックを静かに壊してしまいます。<sup>[[2]](#references)</sup>

Mutation testing は、条件を mutation し、テストが失敗することを検証することで、このギャップを明らかにします。

Smart contract では、surviving mutants は頻繁に次の不足しているチェックに対応します。
- Authorization と role の境界
- Accounting/value-transfer の不変条件
- Revert 条件と failure path
- 境界条件（`==`、ゼロ値、空の配列、最大値/最小値）

## セキュリティ上のシグナルが最も高い mutation operator

Contract auditing に役立つ mutation class:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: statement を `revert()` に置き換え、未実行の path を明らかにする
- **Medium severity**: 行を comment out / logic を削除し、検証されていない副作用を明らかにする
- **Low severity**: `>=` -> `>` や `+` -> `-` のような、微妙な operator または constant の置換
- その他の一般的な編集: assignment の置換、boolean の反転、condition の否定、type の変更

実務上の目標は、意味のある mutant をすべて kill し、無関係または semantic に同等な surviving mutant については明示的に正当化することです。

## regex より syntax-aware mutation が優れている理由

従来の mutation engine は regex または行単位の書き換えに依存していました。これは機能しますが、重要な制限があります。<sup>[[1]](#references)</sup>
- 複数行の statement を安全に mutation することが難しい
- 言語構造が理解されないため、comment/token が不適切に対象となる可能性がある
- 弱い行上で考えられるすべての variant を生成すると、大量の runtime を浪費する

AST または Tree-sitter ベースの tooling は、raw line ではなく構造化された node を対象にすることで、この問題を改善します。<sup>[[1]](#references)</sup>
- **slither-mutate** は Slither の Solidity AST を使用する
- **mewt** は language-agnostic な core として Tree-sitter を使用する
- **MuTON** は `mewt` を基盤とし、FunC、Tolk、Tact などの TON language を first-class support する

これにより、複数行の construct と expression-level mutation を、regex のみに依存する approach よりもはるかに信頼性高く扱えます。

## slither-mutate で mutation testing を実行する

Requirements: Slither v0.10.2+。

- Options と mutator を一覧表示する:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundryの例（結果を保存し、完全なログを保持）:<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundryを使用しない場合は、`--test-cmd`をテストの実行方法に置き換えます（例：`npx hardhat test`、`npm test`）。

Artifactsはデフォルトで`./mutation_campaign`に保存されます。キャッチされなかった（生存した）mutantsは、検査用にそこへコピーされます。<sup>[[5]](#references)</sup>

### 出力の理解

Reportの行は次のようになります：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 角括弧内のタグは mutator の alias です（例：`CR` = Comment Replacement）。
- `UNCAUGHT` は、mutated behavior の下でもテストが成功したことを意味します → assertion が不足しています。

## runtime の削減：影響の大きい mutants を優先する

Mutation campaigns には数時間から数日かかる場合があります。コストを削減するためのヒント：<sup>[[1]](#references)[[2]](#references)</sup>
- Scope：最初は critical な contracts/directories のみに限定し、その後拡大します。
- mutators の優先順位付け：ある行で high-priority mutant が生き残った場合（例：`revert()` または comment-out）、その行の lower-priority variants はスキップします。
- 2 段階の campaigns を使用する：最初に focused/fast tests を実行し、その後 uncaught mutants のみを full suite で再テストします。
- 可能な場合は mutation targets を特定の test commands に対応付けます（例：auth code -> auth tests）。
- 時間が限られている場合は、high/medium severity mutants に campaigns を限定します。
- runner が対応している場合は tests を parallelize し、dependencies/builds を cache します。
- Fail-fast：変更によって assertion gap が明確に示されたら、早期に停止します。

runtime の計算は厳しいものです：`1000 mutants x 5-minute tests ~= 83 hours`。そのため、campaign の設計は mutator 自体と同じくらい重要です。

## Persistent campaigns と大規模な triage

以前の workflow の弱点の 1 つは、結果を `stdout` にのみ出力することでした。長時間の campaigns では、これにより pause/resume、filtering、review が難しくなります。<sup>[[1]](#references)</sup>

`mewt`/`MuTON` は、mutants と outcomes を SQLite-backed campaigns に保存することで、この問題を改善します。メリット：<sup>[[1]](#references)</sup>
- 進行状況を失わずに、長時間の runs を pause と resume する
- 特定の file または mutation class にある uncaught mutants のみを filter する
- review tooling 用に結果を SARIF へ export/translate する
- raw terminal logs ではなく、AI-assisted triage に対して、より小さく filtered された result sets を提供する

Persistent results は、mutation testing が一度限りの手動 review ではなく audit pipeline の一部になった場合に、特に役立ちます。

## surviving mutants の triage workflow

1) mutated line と behavior を確認します。
- mutated line を適用し、focused test を実行して locally reproduce します。

2) return values だけでなく state を assertion するように tests を強化します。
- equality-boundary checks を追加します（例：threshold `==` をテスト）。
- post-conditions を assertion します：balances、total supply、authorization effects、emitted events。

3) overly permissive な mocks を realistic な behavior に置き換えます。
- mocks が、on-chain で発生する transfers、failure paths、event emissions を強制するようにします。

4) fuzz tests 用の invariants を追加します。
- 例：value の conservation、non-negative balances、authorization invariants、該当する場合は monotonic supply。

5) true positives と semantic no-ops を分離します。
- 例：`x > 0` -> `x != 0` は、`x` が unsigned の場合は意味がありません。

6) survivors が kill されるか、明示的に正当化されるまで campaign を再実行します。

## Case study：missing state assertions の発見（Arkis protocol）

Arkis DeFi protocol の audit 中に実施された mutation campaign により、次のような survivors が明らかになりました：<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
代入をコメントアウトしてもテストは壊れず、post-state assertions が不足していることが証明されました。根本原因は、実際の token transfer を検証せず、ユーザーが制御できる `_cmd.value` を信頼していたことです。攻撃者は、想定された transfer と実際の transfer の間に不整合を生じさせ、資金を drain できました。結果として、protocol の solvency に対する高 severity のリスクがありました。<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: value transfer、accounting、または access control に影響する survivors は、kill されるまで high-risk として扱ってください。

## すべての mutant を kill するために、テストを盲目的に生成しない

Mutation-driven test generation は、現在の実装が誤っている場合に逆効果になることがあります。例として、`priority >= 2` を `priority > 2` に mutation すると動作が変わりますが、正しい修正が常に「`priority == 2` のテストを書く」ことであるとは限りません。その動作自体が bug である可能性があります。<sup>[[1]](#references)</sup>

より安全な workflow:
- surviving mutants を使用して、曖昧な要件を特定する
- specs、protocol docs、または reviewers から期待される動作を検証する
- その後でのみ、その動作を test/invariant として記述する

そうしないと、実装上の偶然を test suite にハードコードし、誤った安心感を得るリスクがあります。

## Practical checklist

- 対象を絞った campaign を実行する:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 利用可能な場合は、regex のみによる mutation よりも syntax-aware mutators（AST/Tree-sitter）を優先する。
- survivors を triage し、mutation 後の動作で fail する tests/invariants を作成する。
- balances、supply、authorizations、events を assert する。
- 境界値テスト（`==`、overflows/underflows、zero-address、zero-amount、empty arrays）を追加する。
- 非現実的な mocks を置き換え、failure modes をシミュレートする。
- tooling が対応している場合は結果を persist し、triage 前に uncaught mutants を filter する。
- runtime を管理可能に保つため、two-phase または per-target campaigns を使用する。
- すべての mutants が kill されるか、comments と rationale によって正当化されるまで反復する。

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
