# State Divergence and Default-Value Authorization Bypasses

{{#include ../../banners/hacktricks-training.md}}

Authorization が明示的な role ではなく、derived economic state に依存する場合があります。たとえば、「caller が entire supply を所有している」といった条件です。この predicate の値が異なる store から取得される場合、stale な duplicate によって、正当な ownership shortcut が authorization bypass に変わる可能性があります。Provenance marker module は、危険な組み合わせを示しました。live な caller balance と、non-fixed-supply assets に対して更新されない marker-local supply metadata が比較されていました。<sup>[[1]](#references)</sup>

## Audit duplicated state as an authorization boundary

permission check で使用されるすべての値について、**all representations** を列挙します。canonical module state、object fields、cached aggregates、indexes、snapshots、bridge records、off-chain mirrors が含まれます。次に、各 object mode でどの copy が更新されるかを判断するため、create、mint、burn、transfer、reset、migration、synchronization の各 path をすべて追跡します。ある field が、ある mode では authoritative であり、別の mode では informational である場合があります。<sup>[[1]](#references)</sup>

実践的な review workflow は次のとおりです。<sup>[[1]](#references)</sup>

1. protected actions を特定し、各 authorization branch を boolean predicate に簡約する。
2. 各 operand について、その store、update paths、lifecycle states、source of truth を記録する。
3. 1つの representation だけを更新する transitions を生成し、すべての copy を比較する。
4. 各 transition の後、fresh account から protected action を試行する。
5. bypass の先まで確認する。その action が ACL を編集する場合は、persistent roles を自分自身に付与し、通常の privileged APIs を呼び出す。

suspicious な pattern には、`cachedSupply == balance`、`metadataOwner == caller`、`snapshotShares == currentShares` などがあります。特に、両辺で異なる synchronization rules が使用されている場合は注意が必要です。一方の operand について authoritative value を query しても、もう一方の operand が stale である場合、comparison が安全になるわけではありません。<sup>[[1]](#references)</sup>

## Default-Value equality bypass

両方の operand が独立して同じ default value を取れる場合、equality predicate も安全ではありません。以下の check は、`supply` が zero のとき、empty account に「full supply control」を付与します。zero が stale metadata によるものか、正当に unfunded な object によるものかは問いません。<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
canonical store に切り替えると divergence は修正されますが、**empty-object のケース**は修正されません。セキュリティプロパティには独立した validity condition を含める必要があります。Provenance patch では live bank supply を使用し、caller balance と比較する前に nil またはゼロの supply を拒否します。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
quorum counts、ownership percentages、debt、collateral、epochs、nonces、timestamps、countersにも同じ考え方を適用します。`callerValue == protectedValue`は、protected valueが独立して有効であり、想定されたdomainに属していることが確認されるまで、callerを認可してはなりません。<sup>[[1]](#references)</sup>

## ACL takeoverから正規の特権操作へ

ACLを編集する操作におけるbypassは、永続的なprivilege-escalation primitiveです。Provenanceのケースでは、tokenを1つも持たないunprivileged accountが、古い`0 == 0`のsupply testを通過し、自身にadministrative、mint、withdrawal permissionsを付与してから、通常のmessage handlersを使ってassetsをmintしたりescrowからwithdrawしたりできました。したがって、このexploitにはACL変更後の2つ目のvulnerabilityは必要ありませんでした。<sup>[[1]](#references)</sup>

一般的なexploitation sequence:<sup>[[1]](#references)</sup>

1. non-authoritative fieldがlive stateと異なるobject、またはprotected valueがdefaultになっているobjectを見つける。
2. local valueがその古い値またはdefault valueと一致するように、新しい/空のidentityを使用する。
3. role-management、ownership-transfer、またはpolicy-update endpointを呼び出し、自身に永続的なcapabilitiesを付与する。
4. canonical stateからACLを読み取り、永続化を確認する。
5. 正規のhigh-impact operation（mint、withdraw、upgrade、transfer ownership、またはchange policy）を実行する。

影響をtriageする際は、authorization bypassで調査を止めず、新しいroleから到達可能なすべてのcapabilityを確認してください。Escrowのようなaccountは、stale metadataによってtakeoverが可能になったobjectとは無関係なassetsを保管している場合があります。<sup>[[1]](#references)</sup>

## Invariantとstateful-fuzzingの対象

authorizationはimplementationから独立して指定してください。full-supply shortcutの場合、最小限のinvariantは次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
model/state-machine fuzzerを使用して、単独の呼び出しではなくシーケンスを生成し、creation、zero-value initialization、activation/finalization、minting、burning、transfers、resets、migrations、sync calls、ACL changesを網羅します。各transitionの後に重複した表現を比較し、新規アカウントが保護されたactionを実行できないことをassertします。zero、one unit、partial ownership、full ownership、stale-low、stale-highの値を明示的なケースとしてseedします。<sup>[[1]](#references)[[2]](#references)</sup>

高いシグナル対ノイズ比を持つregression propertiesは次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

- authoritative supplyがZeroであっても、ownershipやadministrationを意味しない。
- duplicate supplyが自身のbalanceと等しい場合でも、partial holdersがadministratorsになることはない。
- live supplyがpositiveである場合、true full holderは意図されたshortcutを保持する。
- 失敗したself-grantsはACLを変更せず、後続のprivileged callsを有効化しない。
- mode changesによって、authorization checkがどのrepresentationをauthoritativeとして扱うかが暗黙的に変わることはない。

## References

- [1] [State divergence enables unauthorized access (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - stale supply checksを修正](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - total-supply authorization shortcutでzero supplyを拒否](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
