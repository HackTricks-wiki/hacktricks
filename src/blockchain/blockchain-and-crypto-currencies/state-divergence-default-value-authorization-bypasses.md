# 상태 불일치와 기본값을 이용한 권한 우회

{{#include ../../banners/hacktricks-training.md}}

권한 검사는 명시적인 역할 대신 파생된 경제 상태에 의존하는 경우가 있습니다. 예를 들어, "호출자가 전체 공급량을 소유한다"와 같은 검사입니다. 해당 조건의 값이 서로 다른 저장소에서 가져온다면, 오래된 중복 값 때문에 정당한 소유권 예외가 권한 우회로 이어질 수 있습니다. Provenance marker 모듈에서는 위험한 조합을 확인할 수 있었습니다. 호출자의 현재 잔액을 marker에 저장된 공급량 메타데이터와 비교했지만, 고정 공급량이 아닌 자산에서는 해당 메타데이터가 갱신되지 않았습니다.<sup>[[1]](#references)</sup>

## 중복 상태를 권한 경계로 감사하기

권한 검사에 사용되는 모든 값에 대해 정식 모듈 상태, 객체 필드, 캐시된 집계 값, 인덱스, 스냅샷, 브리지 레코드, 오프체인 미러 등 **모든 표현 방식**을 나열합니다. 그런 다음 생성, 발행, 소각, 전송, 초기화, 마이그레이션, 동기화 경로를 모두 추적해 객체 모드별로 어떤 사본이 갱신되는지 확인합니다. 한 필드가 특정 모드에서는 권위 있는 값이지만, 다른 모드에서는 참고용일 수 있습니다.<sup>[[1]](#references)</sup>

실용적인 검토 절차는 다음과 같습니다.<sup>[[1]](#references)</sup>

1. 보호된 작업을 찾고 각 권한 분기를 불리언 조건식으로 정리합니다.
2. 각 피연산자에 대해 저장 위치, 갱신 경로, 수명 주기 상태, 기준 데이터의 출처를 기록합니다.
3. 한 표현 방식만 갱신하는 상태 전이를 만들고 모든 사본을 비교합니다.
4. 각 상태 전이 후 새 계정으로 보호된 작업을 시도합니다.
5. 우회에 그치지 말고 계속 진행합니다. 해당 작업이 ACL을 수정한다면, 스스로에게 지속적인 역할을 부여한 뒤 일반 권한 API를 호출합니다.

서로 다른 동기화 규칙을 적용받는 두 값을 비교할 때 `cachedSupply == balance`, `metadataOwner == caller`, `snapshotShares == currentShares`와 같은 패턴은 의심해야 합니다. 한 피연산자에 대해 권위 있는 값을 조회하더라도 다른 피연산자가 오래된 값이라면 비교가 안전해지는 것은 아닙니다.<sup>[[1]](#references)</sup>

## 기본값 일치 우회

두 피연산자가 각각 같은 기본값을 가질 수 있는 경우에도 등호 조건식은 안전하지 않습니다. 아래 검사는 `supply`가 0일 때 모든 빈 계정에 "전체 공급량 제어" 권한을 부여합니다. 0이 오래된 메타데이터에서 비롯되었든, 자금이 아직 들어오지 않은 객체의 정상적인 값이든 상관없습니다.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

canonical store로 전환하면 divergence는 해결되지만 **빈 객체 사례**는 해결되지 않습니다. 보안 속성에는 독립적인 유효성 조건이 포함되어야 합니다. Provenance 패치는 실시간 bank supply를 사용하고, 호출자의 잔액을 비교하기 전에 nil 또는 0인 supply를 거부합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

quorum count, 소유권 비율, 부채, 담보, epoch, nonce, timestamp, counter에도 같은 논리를 적용하세요. `callerValue == protectedValue`는 보호 대상 값이 독립적으로 유효하고 예상된 도메인에 속하는지 확인되기 전까지 caller를 승인해서는 안 됩니다.<sup>[[1]](#references)</sup>

## ACL 탈취로 정당한 권한 작업 수행

ACL 편집 작업의 bypass는 지속적인 권한 상승 수단입니다. Provenance 사례에서는 토큰이 0개인 권한 없는 계정이 오래된 `0 == 0` 공급량 검사를 통과해 자신에게 administrative, mint, withdrawal 권한을 부여한 다음, 일반 message handler를 사용해 자산을 발행하거나 escrow를 인출할 수 있었습니다. 따라서 ACL 변경 후에는 두 번째 취약점이 필요하지 않았습니다.<sup>[[1]](#references)</sup>

일반적인 exploit 순서:<sup>[[1]](#references)</sup>

1. 권위가 없는 필드가 live state와 다르거나 보호 대상 값이 기본값인 객체를 찾습니다.
2. 새 identity 또는 빈 identity를 사용해 해당 identity의 로컬 값이 오래된 값 또는 기본값과 일치하도록 합니다.
3. role-management, ownership-transfer 또는 policy-update endpoint를 호출해 자신에게 지속적인 권한을 부여합니다.
4. canonical state에서 ACL을 읽어 변경이 유지되는지 확인합니다.
5. 정당한 고영향 작업(mint, withdraw, upgrade, ownership transfer 또는 policy 변경)을 실행합니다.

영향을 분류할 때는 권한 bypass만 확인하고 멈추지 말고 새 role로 접근할 수 있는 모든 권한을 살펴보세요. escrow와 유사한 계정은 오래된 metadata가 탈취를 가능하게 한 객체와 무관한 자산도 보관할 수 있습니다.<sup>[[1]](#references)</sup>

## 불변식 및 상태 기반 퍼징 대상

authorization을 구현과 독립적으로 명시하세요. 전체 공급량을 대상으로 하는 shortcut의 최소 불변식은 다음과 같습니다.<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

모델/상태 머신 fuzzer를 사용해 개별 호출이 아닌 시퀀스를 생성하고, 생성, zero-value 초기화, 활성화/종료, minting, burning, 전송, 초기화, 마이그레이션, sync 호출, ACL 변경을 다루세요. 각 전환 후 중복 표현을 비교하고, 새 계정이 보호된 작업을 수행할 수 없는지 확인하세요. zero, one unit, 부분 소유, 전체 소유, 실제보다 낮은 stale 값, 실제보다 높은 stale 값을 명시적 케이스로 추가하세요.<sup>[[1]](#references)[[2]](#references)</sup>

신호가 높은 회귀 속성은 다음과 같습니다.<sup>[[1]](#references)[[2]](#references)</sup>

- 권위 있는 공급량이 zero라고 해서 소유권이나 관리 권한이 생기지는 않습니다.
- 중복 공급량이 잔액과 같다는 이유만으로 부분 보유자가 관리자가 될 수는 없습니다.
- 실제로 전체를 보유한 사용자는 현재 공급량이 양수일 때 의도된 단축 경로를 계속 이용할 수 있습니다.
- 실패한 self-grant는 ACL을 변경하거나 후속 privileged 호출을 가능하게 해서는 안 됩니다.
- 모드 변경으로 인해 권한 검사에서 어느 표현을 권위 있는 것으로 취급하는지가 조용히 바뀌어서는 안 됩니다.

## References

- [1] [상태 불일치로 무단 접근이 가능해짐 (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - 오래된 공급량 검사 수정](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - 총 공급량 권한 부여 단축 경로에서 zero 공급량 거부](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
