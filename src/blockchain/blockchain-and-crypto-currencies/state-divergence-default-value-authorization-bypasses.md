# 상태 불일치 및 기본값 권한 부여 우회

{{#include ../../banners/hacktricks-training.md}}

권한 부여는 명시적인 역할 대신 파생된 경제 상태에 의존하는 경우가 있습니다. 예를 들어 "호출자가 전체 공급량을 소유한다"와 같은 경우입니다. 해당 조건의 값이 서로 다른 저장소에서 가져오면, 오래된 중복 값으로 인해 정상적인 소유권 지름길이 권한 부여 우회로 바뀔 수 있습니다. Provenance marker 모듈은 이러한 위험한 조합을 보여 주었습니다. 실시간 호출자 잔액을 non-fixed-supply 자산에 대해 업데이트되지 않은 marker-local 공급량 메타데이터와 비교한 것입니다.<sup>[[1]](#references)</sup>

## 권한 부여 경계로서의 중복 상태 감사

권한 검사에 사용되는 모든 값에 대해 **모든 표현**을 열거합니다. canonical module state, object fields, cached aggregates, indexes, snapshots, bridge records, off-chain mirrors를 포함합니다. 그런 다음 모든 create, mint, burn, transfer, reset, migration 및 synchronization 경로를 추적하여 각 object mode에서 어떤 복사본이 업데이트되는지 확인합니다. 어떤 필드는 한 mode에서는 authoritative하고 다른 mode에서는 informational할 수 있습니다.<sup>[[1]](#references)</sup>

실용적인 검토 workflow는 다음과 같습니다.<sup>[[1]](#references)</sup>

1. 보호된 action을 찾고 각 authorization branch를 boolean predicate로 단순화합니다.
2. 각 operand에 대해 해당 store, update paths, lifecycle states 및 source of truth를 기록합니다.
3. 하나의 표현만 업데이트하는 transition을 생성한 다음 모든 복사본을 비교합니다.
4. 각 transition 이후 fresh account에서 보호된 action을 시도합니다.
5. bypass 이후에도 계속 진행합니다. action이 ACL을 수정한다면 self-grant persistent roles를 수행하고 일반적인 privileged APIs를 호출합니다.

서로 다른 synchronization rules를 가진 두 값의 비교에서 `cachedSupply == balance`, `metadataOwner == caller`, `snapshotShares == currentShares`와 같은 패턴은 의심해야 합니다. 한 operand에 대해 authoritative value를 조회하더라도 다른 operand가 오래된 값이라면 비교가 안전해지지 않습니다.<sup>[[1]](#references)</sup>

## 기본값 동일성 우회

두 operand가 독립적으로 동일한 기본값을 가질 수 있는 경우에도 equality predicate는 안전하지 않습니다. 아래 검사는 `supply`가 0일 때 모든 빈 계정에 "전체 공급량 제어" 권한을 부여합니다. 0이 오래된 메타데이터에서 비롯되었는지, 정상적으로 자금이 공급되지 않은 object에서 비롯되었는지와 관계없이 적용됩니다.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
canonical store로 전환하면 divergence는 해결되지만 **empty-object case**는 해결되지 않습니다. 보안 속성에는 독립적인 유효성 조건이 포함되어야 합니다. Provenance patch는 live bank supply를 사용하며, caller balance를 비교하기 전에 nil 또는 zero supply를 거부합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
quorum counts, ownership percentages, debt, collateral, epochs, nonces, timestamps, counters에도 동일한 원칙을 적용해야 합니다. `callerValue == protectedValue`는 보호된 값이 독립적으로 유효하고 예상된 도메인에 속한다는 것이 확인되기 전까지 caller를 authorize해서는 안 됩니다.<sup>[[1]](#references)</sup>

## ACL takeover to legitimate privileged operations

ACL을 편집하는 작업의 bypass는 지속적인 privilege-escalation primitive입니다. Provenance 사례에서는 token이 0개인 unprivileged account가 오래된 `0 == 0` supply 테스트를 통과하고, 자신에게 administrative, mint, withdrawal permission을 부여한 다음 일반 message handler를 사용해 asset을 mint하거나 escrow에서 인출할 수 있었습니다. 따라서 exploit에는 ACL 변경 이후 두 번째 vulnerability가 필요하지 않았습니다.<sup>[[1]](#references)</sup>

General exploitation sequence:<sup>[[1]](#references)</sup>

1. non-authoritative field가 live state와 다르거나, protected value가 default인 object를 찾습니다.
2. local value가 해당 stale/default value와 일치하도록 새로운/비어 있는 identity를 사용합니다.
3. role-management, ownership-transfer 또는 policy-update endpoint를 호출하고 자신에게 지속적인 capability를 부여합니다.
4. canonical state에서 ACL을 읽어 persistence를 확인합니다.
5. legitimate high-impact operation(mint, withdraw, upgrade, transfer ownership 또는 change policy)을 호출합니다.

Impact를 triage할 때는 authorization bypass에서 멈추지 말고 새 role에서 접근 가능한 모든 capability를 조사해야 합니다. Escrow와 유사한 account는 stale metadata가 takeover를 가능하게 한 object와 관련 없는 asset을 custody하고 있을 수 있습니다.<sup>[[1]](#references)</sup>

## Invariant and stateful-fuzzing targets

authorization을 implementation과 독립적으로 지정해야 합니다. full-supply shortcut의 최소 invariant는 다음과 같습니다.<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
model/state-machine fuzzer를 사용해 isolated calls가 아닌 sequences를 생성하고, creation, zero-value initialization, activation/finalization, minting, burning, transfers, resets, migrations, sync calls 및 ACL changes를 포함하세요. 모든 transition 후 duplicated representations를 비교하고, fresh account가 보호된 action을 수행할 수 없는지 assert하세요. zero, one unit, partial ownership, full ownership, stale-low 및 stale-high 값에 대한 명시적 cases를 seed하세요.<sup>[[1]](#references)[[2]](#references)</sup>

High-signal regression properties는 다음과 같습니다:<sup>[[1]](#references)[[2]](#references)</sup>

- Zero authoritative supply는 ownership 또는 administration을 절대 의미하지 않습니다.
- Partial holders는 duplicate supply가 자신의 balance와 같아져도 administrators가 될 수 없습니다.
- 실제 full holder는 live supply가 positive일 때 의도된 shortcut을 유지합니다.
- 실패한 self-grants는 ACL을 변경하거나 이후의 privileged calls를 활성화하지 않습니다.
- Mode changes는 authorization check가 어떤 representation을 authoritative로 취급하는지 조용히 변경할 수 없습니다.

## References

- [1] [State divergence가 unauthorized access를 가능하게 함 (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - stale supply checks 수정](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - total-supply authorization shortcut에서 zero supply 거부](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
