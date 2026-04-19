# Smart Contracts の Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing は、contract code に小さな変更（mutants）を体系的に加えて test suite を再実行することで、「tests を test する」手法です。test が失敗すれば、その mutant は kill されます。tests がそれでも pass するなら、その mutant は survive し、line/branch coverage では検出できない blind spot を明らかにします。

Key idea: Coverage は code が実行されたことを示し、mutation testing は behavior が実際に assert されているかを示します。

## Why coverage can deceive

この simple な threshold check を考えてみましょう:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
単体テストが閾値の下と上の値だけを確認していると、== の等価境界を検証していなくても 100% の line/branch coverage に達することがあります。`deposit >= 2 ether` への refactor でもそのようなテストは通ってしまい、protocol ロジックが静かに壊れます。

Mutation testing は、条件を変異させて tests が失敗することを確認することで、このギャップを露呈させます。

smart contracts では、生き残った mutants はしばしば次の不足したチェックに対応します:
- Authorization と role の境界
- Accounting/value-transfer の invariant
- revert 条件と failure path
- 境界条件 (`==`、ゼロ値、空配列、最大/最小値)

## 最も security signal が高い Mutation operators

contract auditing に有用な mutation classes:
- **High severity**: 実行されていない path を露出させるために文を `revert()` に置き換える
- **Medium severity**: 未検証の side effect を明らかにするために行をコメントアウト / ロジックを削除する
- **Low severity**: `>=` -> `>` や `+` -> `-` のような微妙な operator や定数の入れ替え
- その他の一般的な編集: assignment replacement、boolean flip、condition negation、type change

実用上の目標は、意味のある mutants をすべて kill し、無関係または意味的に等価な survivors は明確に正当化することです。

## regex より syntax-aware mutation が優れている理由

古い mutation engine は regex や行ベースの rewrite に依存していました。これは機能しますが、重要な制限があります:
- 複数行の文を安全に mutate するのが難しい
- 言語構造を理解しないため、comment/token を誤って対象にしてしまう
- 弱い line 上で考えられる全バリアントを生成すると、runtime を大量に無駄にする

AST や Tree-sitter ベースの tooling は、raw line ではなく構造化された node を対象にすることでこれを改善します:
- **slither-mutate** は Slither の Solidity AST を使用
- **mewt** は言語非依存の core として Tree-sitter を使用
- **MuTON** は `mewt` を基盤にし、FunC、Tolk、Tact のような TON languages への first-class support を追加

これにより、複数行の構成要素や expression-level の mutation が regex のみの手法よりもはるかに信頼性の高いものになります。

## slither-mutate を使った mutation testing の実行

要件: Slither v0.10.2+。

- オプションと mutators を一覧表示:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry example (結果をキャプチャして完全なログを保持):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundryを使わない場合は、`--test-cmd` をテストの実行方法に置き換えてください（例: `npx hardhat test`, `npm test`）。

Artifacts はデフォルトで `./mutation_campaign` に保存されます。捕捉されなかった（生き残った）mutants は、確認用にそこへコピーされます。

### 出力の理解

Report lines は次のようになります:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 括弧内のタグは mutator alias です（例: `CR` = Comment Replacement）。
- `UNCAUGHT` は、変異後の挙動でもテストが通ったことを意味します → assertion が不足しています。

## runtime を削減する: 影響の大きい mutants を優先する

Mutation campaigns は数時間から数日かかることがあります。コストを下げるためのヒント:
- Scope: まずは重要な contracts/directories のみに絞り、その後広げる。
- mutators を優先する: ある行で高優先度の mutant が生き残った場合（たとえば `revert()` や comment-out）、その行の低優先度の variant はスキップする。
- 二段階の campaigns を使う: まずは focused/fast tests を実行し、その後 full suite で uncaught mutants のみを再テストする。
- 可能なら mutation targets を特定の test commands に対応付ける（たとえば auth code -> auth tests）。
- 時間が厳しいときは、高/中 severity の mutants のみに絞る。
- runner が対応していれば tests を parallelize する。依存関係/builds は cache する。
- Fail-fast: 変更が assertion gap を明確に示したら早めに停止する。

runtime の計算はかなり厳しいです: `1000 mutants x 5-minute tests ~= 83 hours` なので、campaign design は mutator 自体と同じくらい重要です。

## 永続的な campaigns と大規模 triage

古いワークフローの弱点の1つは、結果を `stdout` にしか出さないことです。長い campaigns では、これだと pause/resume、filtering、review が難しくなります。

`mewt`/`MuTON` は、mutants と outcomes を SQLite-backed campaigns に保存することでこれを改善します。利点:
- 長い実行を progress を失わずに pause/resume できる
- 特定の file や mutation class にある uncaught mutants だけを filter できる
- review tooling 用に結果を SARIF に export/translate できる
- 生の terminal logs ではなく、より小さく絞り込まれた result sets を AI-assisted triage に渡せる

Persistent results は、mutation testing が単発の manual review ではなく audit pipeline の一部になる場合に特に有用です。

## surviving mutants の triage workflow

1) mutated line と挙動を確認する。
- mutated line を適用して focused test を実行し、local で再現する。

2) return values だけでなく state を assert するよう tests を強化する。
- equality-boundary checks を追加する（例: threshold `==` を test する）。
- post-conditions を assert する: balances、total supply、authorization effects、emit された events。

3) 過度に許容的な mocks を現実的な挙動に置き換える。
- mocks が transfers、failure paths、on-chain で発生する event emissions を強制するようにする。

4) fuzz tests に invariants を追加する。
- 例: conservation of value、non-negative balances、authorization invariants、該当する場合は monotonic supply。

5) 真の positive と semantic no-op を分ける。
- 例: `x > 0` -> `x != 0` は、`x` が unsigned なら意味がありません。

6) survivors が kill されるか、明確に正当化されるまで campaign を再実行する。

## ケーススタディ: 不足している state assertions の露出（Arkis protocol）

Arkis DeFi protocol の audit 中の mutation campaign では、次のような survivors が見つかりました:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
割り当てをコメントアウトしてもテストは壊れず、欠落している post-state assertions があることが証明された。根本原因: コードが実際の token transfers を検証せず、ユーザー制御の `_cmd.value` を信頼していた。攻撃者は期待された transfer と実際の transfer をずらして資金を吸い取れる。結果: protocol の solvency に対する high severity リスク。

Guidance: value transfers、accounting、access control に影響する survivor は、kill されるまでは high-risk とみなすこと。

## すべての mutant を殺すためにテストを闇雲に生成しない

Mutation-driven test generation は、現在の implementation が間違っている場合に逆効果になりうる。例: `priority >= 2` を `priority > 2` に mutating すると behavior は変わるが、正しい修正が常に「`priority == 2` のテストを書く」とは限らない。その behavior 自体が bug かもしれない。

より安全な workflow:
- surviving mutants を使って曖昧な requirements を特定する
- specs、protocol docs、reviewers から期待される behavior を検証する
- その後でのみ、その behavior を test/invariant として encode する

そうしないと、implementation の偶然の振る舞いを test suite にハードコードしてしまい、誤った安心感を得ることになる。

## 実践チェックリスト

- targeted campaign を実行する:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 可能なら regex-only mutation より syntax-aware mutators (AST/Tree-sitter) を優先する。
- survivors を triage し、mutated behavior の下では失敗する test/invariant を書く。
- balances、supply、authorizations、events を assert する。
- boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays) を追加する。
- 現実離れした mocks を置き換え、failure modes をシミュレートする。
- tooling が対応しているなら結果を永続化し、triage 前に uncaught mutants を filter する。
- runtime を管理しやすくするために two-phase または per-target campaigns を使う。
- すべての mutants が kill されるか、コメントと rationale 付きで正当化されるまで反復する。

## 参考文献

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
