# スマートコントラクトのミューテーションテスト（slither-mutate、mewt、MuTON）

{{#include ../../banners/hacktricks-training.md}}

ミューテーションテストは、コントラクトのコードに小さな変更（ミュータント）を体系的に加え、テストスイートを再実行することで「テストをテスト」します。テストが失敗すれば、ミュータントは kill されます。テストが成功したままなら、ミュータントは生き残り、行カバレッジや分岐カバレッジでは検出できない盲点が明らかになります。

重要な考え方：カバレッジはコードが実行されたことを示します。ミューテーションテストは、動作が実際にアサートされているかを示します。<sup>[[2]](#references)</sup>

## カバレッジが誤解を招く理由

次のシンプルな閾値チェックを考えてみましょう：

```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
    if (deposit >= 1 ether) {
        return true;
    } else {
        return false;
    }
}
```

Unit testでthreshold未満の値とthreshold超過の値だけを確認していても、等値境界（==）をassertしていなければ、line/branch coverageが100%に達することがあります。`deposit >= 2 ether`へのリファクタリングもそのようなテストを通過し、protocol logicを気づかないうちに壊す可能性があります。<sup>[[2]](#references)</sup>

Mutation testingではconditionをmutateし、テストが失敗することを確認して、このギャップを明らかにします。

smart contractでは、生き残ったmutantは次のようなチェックの欠落を示すことがよくあります。
- Authorizationとroleの境界
- Accounting/value-transferのinvariant
- Revert conditionとfailure path
- 境界条件（`==`、zero value、empty array、最大値/最小値）

## セキュリティ上のシグナルが最も強いmutation operator

contractの監査に役立つmutation class:<sup>[[1]](#references)[[2]](#references)</sup>
- **重大度: 高**: statementを`revert()`に置き換え、未実行のpathを明らかにする
- **重大度: 中**: 行をコメントアウトする / logicを削除し、検証されていないside effectを明らかにする
- **重大度: 低**: `>=` -> `>`や`+` -> `-`など、微妙なoperatorやconstantの置き換え
- その他の一般的な変更: assignmentの置き換え、booleanの反転、conditionの否定、typeの変更

実践上の目標は、意味のあるmutantをすべてkillし、無関係または意味的に同等な生存mutantについて明示的に根拠を示すことです。

## regexよりsyntax-awareなmutationが優れている理由

以前のmutation engineはregexや行単位の書き換えに依存していました。これは機能しますが、重要な制約があります。<sup>[[1]](#references)</sup>
- 複数行のstatementは安全にmutateするのが難しい
- 言語構造が理解されないため、commentやtokenが不適切に対象となる可能性がある
- 弱い行であらゆるvariantを生成すると、実行時間を大幅に浪費する

ASTやTree-sitterベースのtoolingでは、生の行ではなく構造化されたnodeを対象にすることで、この問題を改善できます。<sup>[[1]](#references)</sup>
- **slither-mutate**はSlitherのSolidity ASTを使用します。<sup>[[4]](#references)</sup>
- **mewt**はlanguage-agnosticなcoreとしてTree-sitterを使用します。<sup>[[6]](#references)</sup>
- **MuTON**は`mewt`を基盤とし、FunC、Tolk、TactなどのTON languageをfirst-classでサポートします。<sup>[[7]](#references)</sup>

これにより、複数行のconstructやexpressionレベルのmutationを、regexのみに依存する方法よりもはるかに確実に行えます。

## slither-mutateでmutation testingを実行する

要件: Slither v0.10.2以降。

- optionとmutatorを一覧表示する:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Foundry の例（結果を取得し、完全なログを保存する）:<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Foundryを使用しない場合は、`--test-cmd`をテストの実行方法（例：`npx hardhat test`、`npm test`）に置き換えてください。

Artifactsはデフォルトで`./mutation_campaign`に保存されます。捕捉されなかった（生き残った）mutantは、調査できるようそこにコピーされます。<sup>[[5]](#references)</sup>

### 出力の見方

レポートの行は次のようになります:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- 角括弧内のタグは mutator alias です（例: `CR` = Comment Replacement）。
- `UNCAUGHT` は、変更された動作でもテストが成功したことを意味します → assertion が不足しています。

## 実行時間の短縮: 影響の大きい mutant を優先する

Mutation campaign は数時間から数日かかることがあります。コストを抑えるヒント:<sup>[[1]](#references)[[2]](#references)</sup>
- 対象範囲: まず重要な contract／ディレクトリのみに絞り、その後対象を広げます。
- mutator の優先順位付け: ある行で優先度の高い mutant が生き残った場合（例: `revert()` やコメントアウト）、その行の優先度が低いバリエーションはスキップします。
- 2段階の campaign を実施: まず対象を絞った高速テストを実行し、その後、uncaught mutant のみフルテストスイートで再テストします。
- 可能であれば、mutation target を特定のテストコマンドに対応付けます（例: auth code → auth tests）。
- 時間が限られている場合は、severity が high／medium の mutant に campaign を限定します。
- runner が対応していればテストを並列実行し、依存関係や build を cache します。
- Fail-fast: assertion の不足が明確に示されたら、早めに停止します。

実行時間の計算は厳しいものです: `1000 mutants x 5-minute tests ~= 83 hours`。そのため、campaign の設計は mutator 自体と同じくらい重要です。<sup>[[1]](#references)</sup>

## 大規模な persistent campaign と triage

以前の workflow の弱点の1つは、結果を `stdout` にのみ出力することです。長時間の campaign では、一時停止／再開、フィルタリング、レビューが難しくなります。<sup>[[1]](#references)</sup>

`mewt`／`MuTON` は、mutant と結果を SQLite ベースの campaign に保存することで、この問題を改善します。利点:<sup>[[1]](#references)</sup>
- 進捗を失わずに長時間の実行を一時停止／再開できる
- 特定のファイルまたは mutation class に含まれる uncaught mutant のみをフィルタリングできる
- レビューツール向けに結果を SARIF にエクスポート／変換できる
- AI-assisted triage に、未加工の terminal log ではなく、フィルタリングした小規模な結果セットを渡せる

Mutation testing が一度限りの手動レビューではなく audit pipeline の一部となる場合、結果を persistent に保存しておくと特に便利です。

## 生き残った mutant の triage workflow

1) 変更された行と動作を調べます。
   - 変更された行を適用して対象を絞ったテストを実行し、ローカルで再現します。

2) 戻り値だけでなく、状態を検証するようテストを強化します。
   - 境界値の等価チェックを追加します（例: 閾値 `==` のテスト）。
   - 事後条件を検証します: balance、total supply、authorization の効果、発行された event。

3) 過度に寛容な mock を、実際の動作に近いものに置き換えます。
   - on-chain で発生する transfer、failure path、event emission を mock が強制することを確認します。

4) fuzz test に invariant を追加します。
   - 例: value の保存、負にならない balance、authorization invariant、該当する場合は単調に増加する supply。

5) true positive と semantic no-op を区別します。
   - 例: 符号なしの値では `x > 0` → `x != 0` に意味がありません。

6) 生き残ったものが kill されるか、明示的に正当化されるまで campaign を再実行します。

## ケーススタディ: state assertion の不足を明らかにする（Arkis protocol）

Arkis DeFi protocol の audit 中に実施した mutation campaign で、次のような mutant が生き残りました:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

代入をコメントアウトしてもテストは失敗せず、事後状態のアサーションが不足していることが分かりました。根本原因は、実際のトークン移転を検証せず、ユーザーが制御できる `_cmd.value` をコードが信頼していたことです。攻撃者は想定された移転と実際の移転を不一致にさせ、資金を流出させることができました。結果として、プロトコルの支払能力に深刻なリスクが生じます。<sup>[[2]](#references)[[3]](#references)</sup>

指針: 価値の移転、会計処理、アクセス制御に影響する生き残ったmutantは、除去されるまで高リスクとして扱います。

## すべてのmutantを除去するテストを盲目的に生成しない

Mutation駆動のテスト生成は、現行実装が誤っている場合、逆効果になることがあります。例: `priority >= 2` を `priority > 2` に変更すると動作が変わりますが、正しい修正が常に「`priority == 2` のテストを書く」こととは限りません。その動作自体がバグかもしれません。<sup>[[1]](#references)</sup>

より安全なワークフロー:
- 生き残ったmutantを使って、要件が曖昧な箇所を特定する
- 仕様、プロトコル文書、またはレビュー担当者から期待される動作を確認する
- その後で初めて、その動作をテストまたは不変条件として記述する

そうしないと、実装上の偶然をテストスイートに固定してしまい、誤った安心感を得るおそれがあります。

## 実践チェックリスト

- 対象を絞ったcampaignを実行する:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- 利用できる場合は、正規表現のみのmutationより構文を認識するmutator（AST/Tree-sitter）を優先する。
- 生き残ったmutantをトリアージし、変更後の動作で失敗するテスト/不変条件を書く。
- 残高、供給量、認可、イベントを検証する。
- 境界値テスト（`==`、オーバーフロー/アンダーフロー、ゼロアドレス、ゼロ額、空配列）を追加する。
- 非現実的なmockを置き換え、障害モードをシミュレートする。
- ツールが対応している場合は結果を保存し、トリアージ前に捕捉されなかったmutantを除外する。
- 実行時間を管理できるよう、2段階またはターゲットごとのcampaignを使う。
- すべてのmutantが除去されるか、コメントと根拠によって正当化されるまで反復する。

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
