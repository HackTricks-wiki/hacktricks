# ERC-4337 Smart Account 보안 취약점

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction은 wallet을 programmable system으로 전환합니다. 핵심 흐름은 전체 bundle에 걸친 **validate-then-execute**입니다. `EntryPoint`는 어떤 `UserOperation`도 실행하기 전에 모든 `UserOperation`을 검증합니다. 이 순서로 인해 validation이 permissive하거나 stateful하거나 bundler simulation 규칙과 일치하지 않을 때, 쉽게 파악하기 어려운 attack surface가 발생합니다.

## 1) Privileged function의 Direct-call bypass
`EntryPoint`(또는 검증된 executor module)로 제한되지 않은 외부 호출 가능한 `execute`(또는 자금을 이동하는) function은 직접 호출되어 account를 drain하는 데 악용될 수 있습니다.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
안전한 패턴: `EntryPoint`로 제한하고, admin/self-management 흐름(모듈 설치, validator 변경, 업그레이드)에는 `msg.sender == address(this)`를 사용합니다.
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 서명되지 않았거나 검증되지 않은 gas 필드 -> 수수료 고갈
서명 검증이 intent(`callData`)만 다루고 gas 관련 필드를 다루지 않는 경우, bundler 또는 frontrunner가 수수료를 부풀려 ETH를 고갈시킬 수 있습니다. 서명된 payload에는 최소한 다음 항목이 포함되어야 합니다.<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

방어 패턴: `EntryPoint`가 제공하는 `userOpHash`(gas 필드를 포함)를 사용하고, 각 필드에 엄격한 상한을 설정합니다.<sup>[[1]](#references)</sup>
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
모든 validation은 execution 전에 실행되므로, contract state에 validation 결과를 저장하는 것은 안전하지 않습니다. 동일한 bundle의 다른 op가 해당 값을 덮어쓸 수 있으며, 그 결과 execution이 attacker가 영향을 미친 state를 사용하게 됩니다.<sup>[[1]](#references)</sup>

`validateUserOp`에서 storage에 기록하지 마세요. 불가피한 경우 임시 데이터를 `userOpHash`로 keying하고 사용 후 결정적으로 삭제하세요(stateless validation을 우선적으로 사용).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)`는 signature를 **이 contract**와 **이 chain**에 반드시 binding해야 합니다. raw hash에 대해 recover하면 signature가 여러 account 또는 chain에서 replay될 수 있습니다.<sup>[[1]](#references)</sup>

EIP-712 typed data를 사용하세요(domain에 `verifyingContract`와 `chainId`를 포함). 성공 시 정확한 ERC-1271 magic value `0x1626ba7e`를 반환해야 합니다.<sup>[[1]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp`가 성공하면 이후 execution이 revert하더라도 fee는 이미 committed됩니다. 따라서 attacker는 실패할 ops를 반복해서 제출하면서도 account에서 fee를 계속 수취할 수 있습니다.<sup>[[1]](#references)</sup>

paymaster의 경우 `validateUserOp`에서 shared pool에서 지불하고 `postOp`에서 users에게 청구하는 방식은 취약합니다. `postOp`가 revert되어도 payment가 되돌려지지 않을 수 있기 때문입니다. validation 중 자금을 확보하고(per-user escrow/deposit), `postOp`는 최소화하며 revert하지 않도록 하고, 최악의 reimbursement 경로에 대비해 `paymasterPostOpGasLimit`을 충분히 설정하세요.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
첫 번째 `UserOperation`에는 대개 `initCode`가 포함되며, 이로 인해 validation 중 **factory**를 통해 account가 deploy됩니다. 이 경로는 최초 사용 시에만 실행되므로 audit가 충분하지 않은 경우가 많습니다.<sup>[[2]](#references)</sup>

일반적인 failure:

- factory/initializer가 `msg.sender == entryPoint`를 신뢰하지만, ERC-4337 deployment 경로는 `EntryPoint`에서 직접 `initCode`를 호출하지 **않습니다**.
- salt, owner, validator 또는 module configuration이 signed intent에 완전히 binding되지 않아, frontrunner가 최초 deployment에서 경쟁하여 attacker가 제어하는 설정으로 counterfactual address를 선점할 수 있습니다.
- factory가 idempotent하지 않아, 최초 사용 flow가 반복되면 이미 생성된 address를 반환하는 대신 wallet이 작동 불능 상태가 됩니다.

Safe pattern: signed deployment parameters로부터 expected sender를 다시 계산하고, deployment를 deterministic하게 만들며(일반적으로 `CREATE2` 사용), initialization이 한 번만 실행되도록 하세요.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundler가 거부하는 Validation 로직
Validation code는 local tests에서 올바르게 동작하더라도 실제 bundler에서는 사용할 수 없을 수 있습니다. Public bundler는 off-chain에서 `validateUserOp()` / `validatePaymasterUserOp()`를 simulate하며, inclusion 전에 일반적으로 전체 `debug_traceCall(handleOps)`를 실행합니다.<sup>[[3]](#references)</sup>

따라서 다음과 같은 패턴은 validation 내부에서 위험합니다:

- `TIMESTAMP`, `NUMBER`, `BLOCKHASH`와 같은 block-dependent opcode
- `SSTORE`와 같은 state write
- storage에 대한 unbounded iteration
- simulation과 inclusion 사이에 변경될 수 있는 arbitrary external call 또는 oracle read

잘못된 예:
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
검증을 deterministic하고 bounded된 preflight function으로 취급하세요. 공유 상태나 external lookup이 정말 필요하다면 해당 복잡성을 staked/reputation-tracked entities로 옮기고, unit tests뿐만 아니라 정확한 bundler simulation path를 테스트하세요.

## 8) ERC-7702 initialization frontrun
ERC-7702를 사용하면 EOA가 단일 tx 동안 smart-account code를 실행할 수 있습니다. initialization이 external callable이라면 frontrunner가 자신을 owner로 설정할 수 있습니다.<sup>[[1]](#references)</sup>

Mitigation: initialization은 **self-call**을 통해서만, 그리고 한 번만 허용하세요.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## 빠른 pre-merge 점검
- `EntryPoint`의 `userOpHash`를 사용해 서명을 검증합니다(gas fields를 바인딩).
- 적절한 경우 권한이 필요한 함수를 `EntryPoint` 및/또는 `address(this)`로 제한합니다.
- `validateUserOp`는 상태 비저장(stateless), 결정적(deterministic)이며 bundler simulation 규칙과 호환되도록 유지합니다.
- ERC-1271에 EIP-712 domain separation을 적용하고, 성공 시 `0x1626ba7e`를 반환합니다.
- `postOp`는 최소화하고, 제한된 범위로 유지하며, revert하지 않도록 합니다. validation 중 수수료를 안전하게 처리합니다.
- 첫 번째 `initCode` 경로를 별도로 테스트합니다: 결정적 배포, 멱등적인 factory 동작, 일회성 초기화.
- 배포 전에 전체 bundler simulation(`simulateValidation` 및 trace된 `handleOps`)을 실행합니다.
- ERC-7702의 경우 self-call에서만, 그리고 한 번만 init을 허용합니다.

## References

- [1] [Six mistakes in ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
