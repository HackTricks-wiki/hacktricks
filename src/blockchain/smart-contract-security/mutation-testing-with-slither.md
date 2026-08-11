# Smart Contracts の Mutation Testing（slither-mutate、mewt、MuTON）

{{#include ../../banners/hacktricks-training.md}}

Mutation testing は、contract code に小さな変更（mutants）を体系的に導入し、test suite を再実行することで「tests your tests」を行います。テストが失敗した場合、その mutant は killed されます。テストがなお成功する場合、その mutant は survives し、line/branch coverage では検出できない blind spot が明らかになります。

重要な考え方：Coverage は code が実行されたことを示します。Mutation testing は、behavior が実際に assert されているかどうかを示します。<sup>[[2]](#references)</sup>

## Coverage が欺く可能性がある理由

次の単純な threshold check を考えてみましょう。
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
しきい値未満の値としきい値超過の値だけをチェックする unit tests は、等値境界（==）のアサートに失敗していても、100%の行/分岐カバレッジに到達できます。`deposit >= 2 ether` へのリファクタリングを行っても、このようなテストは通過してしまい、プロトコルのロジックをひそかに破壊します。<sup>[[2]](#references)</sup>

Mutation testing は、条件を変異させ、テストが失敗することを検証することで、このギャップを明らかにします。

スマートコントラクトでは、生き残った mutant は、次のような不足しているチェックに対応することが多くあります。
- 認可とロール境界
- Accounting/value-transfer 不変条件
- revert 条件と失敗パス
- 境界条件（`==`、ゼロ値、空の配列、最大値/最小値）

## セキュリティシグナルが最も高い mutation operators

コントラクト auditing に役立つ mutation class:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: ステートメントを `revert()` に置き換え、未実行のパスを明らかにする
- **Medium severity**: 行をコメントアウトする / ロジックを削除し、検証されていない副作用を明らかにする
- **Low severity**: `>=` -> `>` や `+` -> `-` のような、微妙な演算子または定数の置換
- その他の一般的な編集: 代入の置換、ブール値の反転、条件の否定、型の変更

実務上の目標は、意味のある mutant をすべて kill し、無関係または意味的に同等である生き残った mutant については明示的に根拠を示すことです。

## regex より syntax-aware mutation が優れている理由

従来の mutation engine は、regex または行単位の書き換えに依存していました。これは機能しますが、次のような重要な制限があります。<sup>[[1]](#references)</sup>
- 複数行のステートメントを安全に変異させることが難しい
- 言語構造を理解しないため、コメント/トークンが不適切に対象となる可能性がある
- 脆弱な行で考えられるすべてのバリエーションを生成すると、実行時間を大量に浪費する

AST または Tree-sitter ベースの tooling は、未加工の行ではなく構造化されたノードを対象にすることで、この問題を改善します。<sup>[[1]](#references)</sup>
- **slither-mutate** は Slither の Solidity AST を使用します。<sup>[[4]](#references)</sup>
- **mewt** は language-agnostic なコアとして Tree-sitter を使用します。<sup>[[6]](#references)</sup>
- **MuTON** は `mewt` を基盤とし、FunC、Tolk、Tact などの TON languages を first-class support します。<sup>[[7]](#references)</sup>

これにより、複数行の構造や expression-level mutations の信頼性が、regex のみに依存するアプローチよりも大幅に向上します。

## slither-mutate で mutation testing を実行する

要件: Slither v0.10.2 以降。

- オプションと mutators を一覧表示する:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundryの例（結果を取得し、完全なログを保持）:<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry を使用しない場合は、`--test-cmd` をテストの実行方法に置き換えてください（例: `npx hardhat test`、`npm test`）。

Artifacts はデフォルトで `./mutation_campaign` に保存されます。捕捉されなかった（生き残った）ミュータントは、調査用にそこへコピーされます。<sup>[[5]](#references)</sup>

### 出力の理解

Report の行は次のようになります:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 角括弧内のタグは mutator の alias です（例：`CR` = Comment Replacement）。
- `UNCAUGHT` は、mutated behavior の下でテストが通過したことを意味します → assertion が不足しています。

## 実行時間の短縮：影響の大きい mutants を優先する

Mutation campaign には数時間から数日かかることがあります。コストを削減するためのヒント：<sup>[[1]](#references)[[2]](#references)</sup>
- Scope：まず重要な contracts/directories のみに絞り、その後拡大する。
- mutators の優先順位付け：ある行の high-priority mutant が生き残った場合（`revert()` や comment-out など）、その行の lower-priority variants はスキップする。
- 2 段階の campaign を使用する：まず focused/fast tests を実行し、その後 uncaught mutants のみ full suite で再テストする。
- 可能な場合は、mutation targets を特定の test commands に対応付ける（例：auth code -> auth tests）。
- 時間が限られている場合は、campaign を high/medium severity mutants に制限する。
- runner が対応していれば tests を parallelize し、dependencies/builds を cache する。
- Fail-fast：変更によって assertion gap が明確に示された時点で早期停止する。

実行時間の計算は過酷です：`1000 mutants x 5-minute tests ~= 83 hours` となるため、campaign の設計は mutator 自体と同じくらい重要です。<sup>[[1]](#references)</sup>

## 大規模な Persistent campaign と triage

古い workflow の弱点の 1 つは、結果を `stdout` にのみ出力することです。長時間の campaign では、これにより pause/resume、filtering、review が難しくなります。<sup>[[1]](#references)</sup>

`mewt`/`MuTON` は、mutants と outcomes を SQLite-backed campaign に保存することでこの問題を改善します。利点：<sup>[[1]](#references)</sup>
- 進捗を失わずに長時間の実行を pause と resume できる
- 特定の file または mutation class に含まれる uncaught mutants のみを filter できる
- review tooling 用に結果を SARIF へ export/translate できる
- raw terminal logs の代わりに、AI-assisted triage へ小さく filter された result sets を渡せる

Mutation testing が一度限りの manual review ではなく audit pipeline の一部になると、Persistent results は特に有用です。

## 生き残った mutants の triage workflow

1) mutated line と behavior を inspect する。
- mutated line を適用し、focused test を実行して local で reproduce する。

2) return values だけでなく state を assert するよう tests を強化する。
- equality-boundary checks を追加する（例：threshold `==` をテストする）。
- post-conditions を assert する：balances、total supply、authorization effects、emitted events。

3) 過度に permissive な mocks を realistic な behavior に置き換える。
- mocks が on-chain で発生する transfers、failure paths、event emissions を enforce するようにする。

4) fuzz tests に invariants を追加する。
- 例：value の conservation、non-negative balances、authorization invariants、該当する場合は monotonic supply。

5) true positives と semantic no-ops を分離する。
- 例：`x > 0` -> `x != 0` は、`x` が unsigned の場合は意味がない。

6) survivors が kill されるか、明示的に正当化されるまで campaign を再実行する。

## Case study：missing state assertions の発見（Arkis protocol）

Arkis DeFi protocol の audit 中に実施された mutation campaign により、次のような survivors が明らかになりました：<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
assignment をコメントアウトしてもテストが壊れなかったことから、post-state assertions が不足していることが証明されました。根本原因は、実際の token transfer を検証せず、ユーザーが制御可能な `_cmd.value` を信頼していたことです。攻撃者は、想定された transfer と実際の transfer を非同期化して資金を流出させることができました。結果として、protocol の solvency に対する重大度の高いリスクが生じます。<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: value transfer、accounting、または access control に影響する survivor は、kill されるまで高リスクとして扱ってください。

## すべての mutant を kill するために、テストを盲目的に生成しない

Mutation-driven test generation は、現在の実装が誤っている場合に逆効果となる可能性があります。例として、`priority >= 2` を `priority > 2` に mutate すると動作が変わりますが、正しい修正が必ずしも「`priority == 2` のテストを書く」こととは限りません。その動作自体が bug である可能性もあります。<sup>[[1]](#references)</sup>

より安全な workflow:
- surviving mutant を使用して、曖昧な要件を特定する
- spec、protocol docs、または reviewer から期待される動作を検証する
- その後でのみ、その動作を test/invariant としてコード化する

そうしないと、実装上の偶発的な動作を test suite にハードコードし、誤った安心感を得るリスクがあります。

## 実践的な checklist

- 対象を絞った campaign を実行する:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 利用可能な場合は、regex のみに依存する mutation よりも syntax-aware mutator（AST/Tree-sitter）を優先する。
- survivor を triage し、mutate された動作で失敗する test/invariant を作成する。
- balance、supply、authorization、event を assert する。
- 境界値のテスト（`==`、overflow/underflow、zero-address、zero-amount、empty array）を追加する。
- 非現実的な mock を置き換え、failure mode をシミュレートする。
- tooling が対応している場合は結果を永続化し、triage 前に uncaught mutant を filter する。
- runtime を管理可能に保つため、two-phase campaign または target ごとの campaign を使用する。
- すべての mutant が kill されるか、comment と rationale によって正当化されるまで反復する。

## References

- [1] [agentic era における Mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [テストが検出できない bug を見つけるために mutation testing を使用する (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review（Appendix C）](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither（GitHub）](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
