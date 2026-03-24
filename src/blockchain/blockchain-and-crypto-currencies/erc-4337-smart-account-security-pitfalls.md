# ERC-4337 스마트 계정 보안 함정

{{#include ../../banners/hacktricks-training.md}}

ERC-4337의 계정 추상화는 지갑을 프로그래밍 가능한 시스템으로 바꿉니다. 핵심 흐름은 번들 전체에 걸친 **validate-then-execute**입니다: `EntryPoint`는 어떤 `UserOperation`도 실행하기 전에 각각을 검증합니다. 이 순서로 인해 검증이 관대하거나 상태 의존적일 때 비직관적인 공격 표면이 생깁니다.

## 1) 특권 함수의 직접 호출 우회
EntryPoint(또는 검증된 executor 모듈)에 제한되지 않은 외부에서 호출 가능한 `execute`(또는 자금 이동) 함수는 계정의 자금을 직접 빼내기 위해 바로 호출될 수 있습니다.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
안전한 패턴: `EntryPoint`로 제한하고, 관리자/자체 관리 흐름 (모듈 설치, 검증자 변경, 업그레이드)에는 `msg.sender == address(this)`를 사용하세요.
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 서명되지 않았거나 검증되지 않은 gas 필드 -> 수수료 탈취
서명 검증이 의도(`callData`)만을 검증하고 gas 관련 필드를 검증하지 않으면, bundler나 frontrunner가 수수료를 부풀려 ETH를 탈취할 수 있다. 서명된 페이로드는 최소한 다음 항목들을 바인딩해야 한다:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

방어 패턴: `EntryPoint`가 제공하는 `userOpHash`(gas 필드를 포함함)를 사용하거나 각 필드에 대해 엄격한 상한을 설정하라.
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle semantics)
모든 검증이 실행보다 먼저 수행되기 때문에, 검증 결과를 컨트랙트 상태에 저장하는 것은 안전하지 않습니다. 같은 번들(bundle)의 다른 op가 이를 덮어쓸 수 있어, 실행이 공격자가 조작한 상태를 사용하게 될 수 있습니다.

`validateUserOp`에서 storage를 쓰는 것을 피하세요. 불가피하다면 임시 데이터의 키로 `userOpHash`를 사용하고 사용 후 결정론적으로 삭제하세요(가능하면 무상태 검증을 권장).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)`는 서명을 **이 컨트랙트**와 **이 체인**에 묶어야 합니다. 원시 해시(raw hash)로 복구하면 서명이 계정이나 체인 간에 재플레이될 수 있습니다.

EIP-712 typed data를 사용하세요(도메인에 `verifyingContract`와 `chainId` 포함) 그리고 성공 시 정확한 ERC-1271 매직 값 `0x1626ba7e`를 반환하세요.

## 5) Reverts do not refund after validation
`validateUserOp`가 성공하면 이후 실행이 revert하더라도 수수료는 확정됩니다. 공격자는 실패하는 op를 반복 제출해도 계정에서 수수료를 계속 가져갈 수 있습니다.

paymasters의 경우, `validateUserOp`에서 공유 풀에서 지불하고 `postOp`에서 사용자에게 청구하는 방식은 취약합니다. `postOp`가 결제를 되돌리지 않고 revert할 수 있기 때문입니다. 검증 시점에 자금을 안전하게 확보하세요(사용자별 에스크로/예치) 그리고 `postOp`는 최소한으로 유지하고 revert하지 않도록 설계하세요.

## 6) ERC-7702 initialization frontrun
ERC-7702는 EOA가 단일 tx에 대해 smart-account 코드를 실행할 수 있게 합니다. 초기화가 외부에서 호출 가능하면, frontrunner가 자신을 owner로 설정할 수 있습니다.

대응책: 초기화는 **self-call**에서만, 그리고 한 번만 허용하세요.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## 병합 전 빠른 점검
- `EntryPoint`의 `userOpHash`를 사용해 서명을 검증하세요 (gas 필드를 바인딩).
- 권한이 있는 함수는 적절히 `EntryPoint` 및/또는 `address(this)`로 제한하세요.
- `validateUserOp`는 상태 비저장으로 유지하세요.
- ERC-1271에 대해 EIP-712 도메인 분리를 적용하고 성공 시 `0x1626ba7e`를 반환하세요.
- `postOp`는 최소화하고, 한정되며, revert가 발생하지 않도록 유지하세요; 검증 중에 수수료를 확보하세요.
- ERC-7702의 경우 init은 self-call에서만 그리고 한 번만 허용하세요.

## 참고자료

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
