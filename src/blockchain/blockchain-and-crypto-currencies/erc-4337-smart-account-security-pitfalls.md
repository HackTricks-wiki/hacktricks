# ERC-4337 Smart Account 보안 취약점

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 계정 추상화는 wallet을 programmable system으로 전환합니다. 핵심 흐름은 전체 bundle에 걸친 **validate-then-execute**입니다. `EntryPoint`는 어떤 `UserOperation`도 실행하기 전에 모든 `UserOperation`을 검증합니다. 이러한 순서는 validation이 permissive하거나 stateful하거나 bundler simulation 규칙과 일치하지 않을 때 예상하기 어려운 attack surface를 만듭니다.

## 1) privileged function의 Direct-call bypass
`EntryPoint`(또는 검증된 executor module)로 제한되지 않은 외부 호출 가능 `execute`(또는 자금 이동) function은 직접 호출되어 account를 drain하는 데 악용될 수 있습니다.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
안전한 패턴: `EntryPoint`로 제한하고, 관리자/자체 관리 흐름(모듈 설치, validator 변경, 업그레이드)에는 `msg.sender == address(this)`를 사용합니다.
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 서명되지 않았거나 검증되지 않은 gas 필드 -> fee drain
서명 검증이 intent(`callData`)만 포함하고 gas 관련 필드는 포함하지 않는 경우, bundler 또는 frontrunner가 수수료를 부풀려 ETH를 drain할 수 있습니다. 서명된 payload에는 최소한 다음 항목이 포함되어야 합니다.<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

방어 패턴: gas 필드를 포함하는 `EntryPoint` 제공 `userOpHash`를 사용하고, 각 필드에 엄격한 상한을 설정합니다.<sup>[[1]](#references)</sup>
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
모든 validation은 execution 전에 실행되므로, validation 결과를 contract state에 저장하는 것은 안전하지 않습니다. 동일한 bundle의 다른 op가 해당 값을 덮어쓸 수 있으며, 그 결과 execution이 attacker-influenced state를 사용하게 됩니다.<sup>[[1]](#references)</sup>

`validateUserOp`에서 storage에 쓰는 작업을 피하세요. 불가피하다면 임시 데이터를 `userOpHash`별로 keying하고 사용 후 deterministically 삭제하세요(stateless validation을 우선).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)`는 signature를 **이 contract**와 **이 chain**에 바인딩해야 합니다. raw hash에 대해 recover하면 signature가 accounts 또는 chains 간에 replay될 수 있습니다.<sup>[[1]](#references)</sup>

EIP-712 typed data를 사용하세요(domain에 `verifyingContract`와 `chainId` 포함). 성공 시 정확한 ERC-1271 magic value `0x1626ba7e`를 반환해야 합니다.<sup>[[1]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp`가 성공하면 이후 execution이 revert되더라도 fees는 이미 committed됩니다. Attacker는 실패할 ops를 반복해서 제출하면서도 account에서 fees를 계속 수취할 수 있습니다.<sup>[[1]](#references)</sup>

Paymaster의 경우 `validateUserOp`에서 shared pool에서 지불하고 `postOp`에서 users에게 charge하는 방식은 취약합니다. `postOp`가 payment를 되돌리지 않은 채 revert될 수 있기 때문입니다. validation 중 funds를 secure하게 확보하고(per-user escrow/deposit), `postOp`는 minimal하고 non-reverting하게 유지하며, 최악의 reimbursement 경로에 대비해 `paymasterPostOpGasLimit`을 책정하세요.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
첫 번째 `UserOperation`에는 흔히 `initCode`가 포함되며, validation 중 **factory**를 통해 account가 deployed됩니다. 이 경로는 최초 사용 시에만 실행되므로 audit가 충분하지 않기 쉽습니다.<sup>[[2]](#references)</sup>

일반적인 failures:

- factory/initializer가 `msg.sender == entryPoint`를 신뢰하지만, ERC-4337 deployment 경로는 `EntryPoint`에서 직접 `initCode`를 호출하지 않습니다.
- salt, owner, validator 또는 module configuration이 signed intent에 완전히 bound되지 않아, frontrunner가 첫 deployment를 race하여 attacker-controlled settings로 counterfactual address를 선점할 수 있습니다.
- factory가 non-idempotent하여, 첫 사용 flow가 반복되면 이미 생성된 address를 반환하는 대신 wallet을 brick합니다.

Safe pattern: signed deployment parameters에서 expected sender를 재계산하고, deployment를 deterministic하게 만들며(일반적으로 `CREATE2`), initialization을 one-shot으로 만드세요.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundlers가 거부하는 validation 로직
Validation 코드는 로컬 테스트에서는 올바르게 동작하면서도 실제 bundlers에서는 사용할 수 없을 수 있습니다. Public bundlers는 off-chain에서 `validateUserOp()` / `validatePaymasterUserOp()`를 시뮬레이션하며, inclusion 전에 일반적으로 전체 `debug_traceCall(handleOps)`를 실행합니다.

따라서 validation 내부에서 다음 패턴을 사용하면 위험합니다.

- `TIMESTAMP`, `NUMBER`, `BLOCKHASH`와 같은 block-dependent opcode
- `SSTORE`와 같은 state write
- storage에 대한 bound가 없는 iteration
- simulation과 inclusion 사이에 변경될 수 있는 임의의 external call 또는 oracle read

나쁜 예시:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // SSTORE in validation
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Validation을 결정론적이고 제한된 preflight 함수로 취급하세요. 공유 상태나 external lookup이 정말 필요하다면, 해당 복잡성을 staked/reputation-tracked entity로 옮기고 unit tests만이 아니라 정확한 bundler simulation 경로를 테스트하세요.

## 8) ERC-7702 initialization frontrun
ERC-7702를 사용하면 EOA가 단일 tx 동안 smart-account code를 실행할 수 있습니다. initialization을 external callable로 허용하면 frontrunner가 자신을 owner로 설정할 수 있습니다.<sup>[[1]](#references)</sup>

Mitigation: initialization은 **self-call**에서만, 그리고 한 번만 허용하세요.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## 빠른 merge 전 검사
- `EntryPoint`의 `userOpHash`를 사용해 서명을 검증합니다(gas 필드를 바인딩).
- 적절한 경우 권한 있는 함수를 `EntryPoint` 및/또는 `address(this)`로 제한합니다.
- `validateUserOp`를 상태 비저장(stateless), 결정론적이며 bundler simulation 규칙과 호환되도록 유지합니다.
- ERC-1271에 EIP-712 domain separation을 적용하고, 성공 시 `0x1626ba7e`를 반환합니다.
- `postOp`를 최소화하고, 실행 범위를 제한하며, revert하지 않도록 합니다. validation 중 수수료를 안전하게 처리합니다.
- 첫 번째 `initCode` 경로는 별도로 테스트합니다. 결정론적 배포, idempotent factory 동작, one-shot initialization을 확인합니다.
- 배포 전에 전체 bundler simulation(`simulateValidation` 및 trace가 적용된 `handleOps`)을 실행합니다.
- ERC-7702의 경우 self-call에서만 init을 허용하고, 한 번만 실행되도록 합니다.



## 참고 자료

- [1] [ERC-4337 smart account의 6가지 실수 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Alt Mempool을 사용한 Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
