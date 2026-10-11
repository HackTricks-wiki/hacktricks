# State Divergence and Default-Value Authorization Bypasses

{{#include ../../banners/hacktricks-training.md}}

認可が明示的なロールではなく、導出された経済状態に依存することがあります。たとえば、「呼び出し元が供給量全体を所有している」といった条件です。この判定に使われる値が異なるストアから取得される場合、古い重複値によって、正当な所有権に基づく簡略化が認可バイパスに変わることがあります。Provenance marker moduleでは、ライブな呼び出し元の残高と、固定供給量でない資産について更新されていないマーカー内の供給量メタデータを比較するという、危険な組み合わせが示されました。<sup>[[1]](#references)</sup>

## 認可境界として重複状態を監査する

権限チェックで使われるすべての値について、**すべての表現**を列挙します。正規モジュールの状態、オブジェクトのフィールド、キャッシュされた集計値、インデックス、スナップショット、ブリッジの記録、オフチェーンのミラーなどです。次に、各オブジェクトモードでどのコピーが更新されるかを特定するため、作成、mint、burn、transfer、reset、migration、同期の各経路を追跡します。あるフィールドは、特定のモードでは権威ある値でも、別のモードでは参考情報にすぎない場合があります。<sup>[[1]](#references)</sup>

実践的なレビュー手順は次のとおりです。<sup>[[1]](#references)</sup>

1. 保護対象のアクションを特定し、各認可分岐を真偽値の述語に単純化する。
2. 各オペランドについて、保存先、更新経路、ライフサイクル状態、信頼できる情報源を記録する。
3. 片方の表現だけが更新される遷移を生成し、すべてのコピーを比較する。
4. 各遷移の後、作成したばかりのアカウントから保護対象のアクションを試みる。
5. バイパス後の影響まで調べる。アクションがACLを変更する場合は、自分に永続ロールを付与し、通常の特権APIを呼び出す。

`cachedSupply == balance`、`metadataOwner == caller`、`snapshotShares == currentShares` のように、両辺で同期ルールが異なる場合は、疑わしいパターンです。一方のオペランドに権威ある値を照会していても、もう一方が古い値なら比較が安全になるわけではありません。<sup>[[1]](#references)</sup>

## デフォルト値の等価性によるバイパス

両方のオペランドが、それぞれ独立に同じデフォルト値を取り得る場合も、等価性の述語は安全ではありません。次のチェックは、`supply` がゼロである場合、ゼロが古いメタデータによるものか、正当に資金が投入されていないオブジェクトによるものかを問わず、空のアカウントに「供給量全体の制御」を付与します。<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

正規ストアに切り替えれば状態の不一致は解消されますが、**空オブジェクトのケース**は解決しません。セキュリティ上の性質には独立した有効性条件を含める必要があります。Provenance のパッチでは、稼働中の銀行の供給量を使い、呼び出し元の残高を比較する前に、供給量が nil またはゼロの場合は拒否します。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

quorum counts、ownership percentages、debt、collateral、epochs、nonces、timestamps、countersにも同じ考え方を適用します。`callerValue == protectedValue` は、保護対象の値が独立して有効であり、想定されたドメインに属することが確認されるまでは、callerを認可してはなりません。<sup>[[1]](#references)</sup>

## ACL乗っ取りから正規の特権操作へ

ACL編集操作のバイパスは、永続的な権限昇格の手段となります。Provenanceのケースでは、トークンを1つも持たない非特権アカウントが、古い `0 == 0` の供給量テストを通過し、自身に管理、mint、withdrawalの権限を付与できました。その後、通常のメッセージハンドラーを使って資産をmintしたり、エスクローから資産を引き出したりできました。そのため、ACL変更後に別の脆弱性を悪用する必要はありませんでした。<sup>[[1]](#references)</sup>

一般的な悪用手順：<sup>[[1]](#references)</sup>

1. 権威のないフィールドが最新の状態と異なるオブジェクト、または保護対象の値がデフォルト値であるオブジェクトを見つけます。
2. 新規または空のIDを使い、そのローカル値を古い値またはデフォルト値に一致させます。
3. ロール管理、所有権移転、またはポリシー更新のエンドポイントを呼び出し、自身に永続的な権限を付与します。
4. 正規の状態からACLを読み取り、変更が永続化されたことを確認します。
5. 正規の高影響操作（mint、withdraw、upgrade、所有権の移転、ポリシーの変更）を実行します。

影響をトリアージする際は、認可バイパスだけで調査を止めず、新しいロールから到達可能なすべての権限を確認してください。エスクローのようなアカウントは、乗っ取りを可能にした古いメタデータを持つオブジェクトとは無関係の資産を保管している場合があります。<sup>[[1]](#references)</sup>

## 不変条件とstateful-fuzzingの対象

実装とは独立して認可条件を定義します。全供給量を条件とするショートカットの最小限の不変条件は次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

モデル/ステートマシン fuzzer を使って、個別の呼び出しではなく、作成、ゼロ値での初期化、有効化/確定、mint、burn、transfer、リセット、migration、sync 呼び出し、ACL の変更を含む一連の操作を生成します。各遷移の後に重複した表現を比較し、新しいアカウントが保護対象の操作を一切実行できないことを検証します。ゼロ、1 単位、一部所有、全額所有、実際より小さい古い値、実際より大きい古い値の明示的なケースを用意します。<sup>[[1]](#references)[[2]](#references)</sup>

シグナルの強い回帰テストのプロパティは次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

- 権威ある供給量がゼロの場合、所有権や管理者権限があることを意味しない。
- 一部保有者は、重複した供給量が自身の残高と等しくても、管理者になれない。
- 実際に全額を保有するアカウントは、実際の供給量が正である場合、意図されたショートカットを引き続き利用できる。
- 自身への権限付与に失敗しても ACL は変更されず、その後の特権付き呼び出しも可能にならない。
- モードの変更によって、認可チェックでどの表現を権威あるものとして扱うかが暗黙に変わらない。

## References

- [1] [状態の不整合による不正アクセスの可能性 (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - 古い供給量チェックを修正](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - 総供給量がゼロの場合に認可ショートカットを拒否](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
