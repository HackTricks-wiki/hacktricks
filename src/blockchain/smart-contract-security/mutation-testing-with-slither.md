# Smart Contracts向けMutation Testing (slither-mutate、mewt、MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testingは、コントラクトコードに小さな変更（ミュータント）を体系的に導入し、テストスイートを再実行することで「テストをテスト」します。テストが失敗すれば、ミュータントはkillされます。テストがそのまま成功すれば、ミュータントは生存し、line/branch coverageでは検出できないblind spotが明らかになります。

重要な点：Coverageはコードが実行されたことを示します。Mutation testingは、動作が実際にassertされているかを示します。<sup>[[2]](#references)</sup>

## Coverageが誤解を招く理由

次のシンプルなthreshold checkを考えてみましょう。
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
しきい値未満の値としきい値を超える値だけを確認する Unit tests は、等値境界（==）の検証に失敗していても、line/branch coverage 100% に到達できます。`deposit >= 2 ether` へのリファクタリングを行っても、このようなテストは通過するため、protocol logic が気付かないうちに破壊されます。<sup>[[2]](#references)</sup>

Mutation testing は、条件をmutateし、テストが失敗することを検証することで、この欠落を明らかにします。

smart contracts では、生き残ったmutantsが、以下に関するチェックの欠落を示すことがよくあります。
- Authorization と role の境界
- Accounting/value-transfer invariants
- Revert conditions と failure paths
- 境界条件（`==`、ゼロ値、空の配列、最大値/最小値）

## 最も高いセキュリティシグナルを持つmutation operators

contract auditingに役立つmutation classes:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: ステートメントを `revert()` に置き換え、未実行のパスを明らかにする
- **Medium severity**: 行をコメントアウト / logicを削除し、検証されていない副作用を明らかにする
- **Low severity**: `>=` -> `>` や `+` -> `-` のような、微妙な演算子または定数の置き換え
- その他の一般的な編集: assignment replacement、boolean flips、condition negation、type changes

実践的な目標は、意味のあるmutantsをすべてkillし、無関係または意味的に同等である生存mutantsについて明示的に根拠を示すことです。

## regexよりもsyntax-aware mutationが優れている理由

以前のmutation enginesは、regexまたは行単位の書き換えに依存していました。これは機能しますが、重要な制限があります:<sup>[[1]](#references)</sup>
- 複数行のステートメントを安全にmutateすることが難しい
- 言語構造が理解されないため、コメント/トークンが不適切に対象となる可能性がある
- 弱い行ごとに考えられるすべてのvariantを生成すると、大量のruntimeを浪費する

ASTまたはTree-sitterベースのtoolingは、raw linesではなく構造化されたnodesを対象にすることで、この問題を改善します:<sup>[[1]](#references)</sup>
- **slither-mutate** は Slither の Solidity AST を使用します<sup>[[4]](#references)</sup>
- **mewt** は language-agnostic なcoreとして Tree-sitter を使用します<sup>[[6]](#references)</sup>
- **MuTON** は `mewt` を基盤とし、FunC、Tolk、Tact などの TON languages をfirst-class supportします<sup>[[7]](#references)</sup>

これにより、複数行のconstructsやexpression-level mutationsの信頼性が、regex-only approachesよりも大幅に向上します。

## slither-mutateでMutation testingを実行する

Requirements: Slither v0.10.2+。

- options と mutators を一覧表示:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundryの例（結果を取得し、完全なログを保持）:<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundryを使用しない場合は、`--test-cmd`をテストの実行方法に置き換えます（例：`npx hardhat test`、`npm test`）。

Artifactsはデフォルトで`./mutation_campaign`に保存されます。捕捉されなかった（生存した）mutantsは、検査のためにそこへコピーされます。<sup>[[5]](#references)</sup>

### 出力の理解

レポートの行は次のようになります：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 角括弧内のタグは mutator の alias です（例：`CR` = Comment Replacement）。
- `UNCAUGHT` は、mutated behavior の下でもテストが成功したことを意味します → assertion が不足しています。

## runtime の削減：影響の大きい mutants を優先する

Mutation campaign には数時間から数日かかる場合があります。コストを削減するためのヒント：<sup>[[1]](#references)[[2]](#references)</sup>
- Scope：まず重要な contract/directory のみを対象にし、その後拡張する。
- mutator の優先順位付け：ある行で high-priority mutant が生き残った場合（`revert()` や comment-out など）、その行の lower-priority variant はスキップする。
- 2段階の campaign を使用する：まず focused/fast test を実行し、その後 uncaught mutant のみを full suite で再テストする。
- 可能な場合は mutation target を特定の test command に対応付ける（例：auth code -> auth test）。
- 時間が限られている場合は、high/medium severity の mutant に campaign を限定する。
- runner が対応している場合は test を並列化し、dependency/build を cache する。
- Fail-fast：変更によって assertion gap が明確に示されたら早期に停止する。

runtime の計算は厳しいものです：`1000 mutants x 5-minute tests ~= 83 hours` となるため、campaign の設計は mutator 自体と同じくらい重要です。<sup>[[1]](#references)</sup>

## Persistent campaign と大規模な triage

以前の workflow の弱点の1つは、結果を `stdout` にのみ出力することでした。長時間の campaign では、これにより pause/resume、filtering、review が難しくなります。<sup>[[1]](#references)</sup>

`mewt`/`MuTON` は、mutant と outcome を SQLite-backed campaign に保存することでこの問題を改善します。利点：<sup>[[1]](#references)</sup>
- 進捗を失わずに長時間の run を pause/resume できる
- 特定の file または mutation class にある uncaught mutant のみを filter できる
- review tooling 用に結果を SARIF へ export/translate できる
- raw terminal log の代わりに、AI-assisted triage へ小さく filter した result set を渡せる

Persistent result は、mutation testing が一回限りの手動 review ではなく audit pipeline の一部になった場合に特に役立ちます。

## surviving mutant の triage workflow

1) mutated line と behavior を調査する。
- mutated line を適用して focused test を実行し、local で再現する。

2) return value だけでなく state を assert するよう test を強化する。
- equality boundary check を追加する（例：threshold `==` をテストする）。
- post-condition を assert する：balance、total supply、authorization effect、emitted event。

3) 過度に permissive な mock を現実的な behavior に置き換える。
- mock が on-chain で発生する transfer、failure path、event emission を強制することを確認する。

4) fuzz test 用の invariant を追加する。
- 例：value の conservation、non-negative balance、authorization invariant、該当する場合は monotonic supply。

5) true positive と semantic no-op を分離する。
- 例：`x > 0` -> `x != 0` は、`x` が unsigned の場合は意味がない。

6) survivor が kill されるか、明示的に正当化されるまで campaign を再実行する。

## Case study：missing state assertion の発見（Arkis protocol）

Arkis DeFi protocol の audit 中に実施された mutation campaign により、次のような survivor が明らかになりました：<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
代入をコメントアウトしてもテストが壊れなかったことから、post-state assertion が欠落していることが証明されました。根本原因は、実際の token transfer を検証せず、ユーザーが制御できる `_cmd.value` を信頼していたことです。攻撃者は、想定された transfer と実際の transfer の間に不整合を生じさせ、資金を流出させることができました。結果として、protocol の solvency に対する重大度の高いリスクとなります。<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: value transfer、accounting、または access control に影響する、まだ kill されていない mutant は、kill されるまで high-risk として扱ってください。

## すべての mutant を kill するために、テストを盲目的に生成しない

Mutation-driven test generation は、現在の実装が間違っている場合に逆効果となる可能性があります。例として、`priority >= 2` を `priority > 2` に mutation すると挙動が変わりますが、正しい修正が常に「`priority == 2` のテストを書く」ことであるとは限りません。その挙動自体が bug である可能性もあります。<sup>[[1]](#references)</sup>

より安全な workflow:
- 生き残った mutant を使用して、曖昧な要件を特定する
- spec、protocol documentation、または reviewer から期待される挙動を検証する
- その後でのみ、その挙動を test/invariant として実装する

そうしないと、実装上の偶然を test suite にハードコードし、誤った確信を得るリスクがあります。

## 実践的な checklist

- 対象を絞った campaign を実行する:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 利用可能な場合は、regex のみに依存する mutation よりも、syntax-aware mutator（AST/Tree-sitter）を優先する。
- 生き残った mutant を triage し、mutation 後の挙動で fail する test/invariant を作成する。
- balance、supply、authorization、event を assert する。
- 境界値のテスト（`==`、overflow/underflow、zero-address、zero-amount、empty array）を追加する。
- 非現実的な mock を置き換え、failure mode をシミュレートする。
- tooling が対応している場合は結果を永続化し、triage 前に uncaught mutant を filter する。
- runtime を管理しやすくするため、two-phase または target ごとの campaign を使用する。
- すべての mutant が kill されるか、comments と rationale によって正当化されるまで反復する。

## References

- [1] [agentic era 向けの Mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Mutation testing を使用して、テストが検出できない bug を見つける（Trail of Bits）](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review（Appendix C）](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither（GitHub）](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
