# ERC-4337 Smart Account 보안 취약점

ERC-4337 account abstraction은 wallet을 programmable system으로 전환합니다. 핵심 흐름은 전체 bundle에 걸친 **validate-then-execute**입니다. 즉, `EntryPoint`는 어떤 작업도 실행하기 전에 모든 `UserOperation`을 검증합니다.<sup>[[5]](#references)</sup> 이러한 순서로 인해 validation이 permissive하거나 stateful하거나 bundler simulation rules와 일치하지 않을 때 예상하기 어려운 attack surface가 발생합니다.

## 1) Privileged function의 Direct-call bypass
`EntryPoint`(또는 검증된 executor module)로 제한되지 않은 externally callable `execute`(또는 fund-moving) function은 직접 호출되어 account를 drain하는 데 악용될 수 있습니다.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
안전한 패턴: `EntryPoint`로 제한하고, 관리자/자체 관리 흐름(모듈 설치, validator 변경, 업그레이드)에는 `msg.sender == address(this)`를 사용합니다.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 서명되지 않았거나 검증되지 않은 gas 필드 -> fee drain
서명 검증이 의도(`callData`)만 다루고 gas 관련 필드는 다루지 않는 경우, bundler 또는 frontrunner가 수수료를 부풀려 ETH를 drain할 수 있습니다. 서명된 payload는 최소한 다음 항목에 바인딩되어야 합니다:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

방어 패턴: `EntryPoint`가 제공하는 `userOpHash`(gas 필드를 포함)를 사용하거나 각 필드에 엄격한 상한을 설정합니다.<sup>[[2]](#references)[[5]](#references)</sup>
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
모든 validation이 execution 전에 실행되므로, contract state에 validation 결과를 저장하는 것은 안전하지 않습니다. 동일한 bundle의 다른 op가 해당 값을 덮어쓸 수 있으며, 그 결과 execution이 attacker가 영향을 준 state를 사용하게 됩니다.<sup>[[2]](#references)</sup>

`validateUserOp`에서 storage를 작성하지 마세요. 불가피하다면 임시 데이터를 `userOpHash`별로 저장하고 사용 후 결정적으로 삭제하세요(stateless validation을 우선).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)`는 signature를 **이 contract** 및 **이 chain**에 바인딩해야 합니다. raw hash에 대해 recover하면 signature가 여러 account 또는 chain에서 replay될 수 있습니다.<sup>[[1]](#references)[[4]](#references)</sup>

EIP-712 typed data를 사용하고(`verifyingContract` 및 `chainId`를 포함하는 domain), 성공 시 정확한 ERC-1271 magic value `0x1626ba7e`를 반환하세요.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp`가 성공하면 이후 execution이 revert되더라도 fee는 이미 확정됩니다. 공격자는 실패할 작업을 반복적으로 제출하면서도 account에서 fee를 계속 징수할 수 있습니다.<sup>[[2]](#references)</sup>

paymaster의 경우 `validateUserOp`에서 shared pool에서 지불하고 `postOp`에서 user에게 청구하는 방식은 취약합니다. `postOp`가 payment를 되돌리지 않은 채 revert할 수 있기 때문입니다. validation 중 자금을 확보하고(user별 escrow/deposit), `postOp`는 최소한으로 유지하며 revert되지 않도록 하고, 최악의 reimbursement 경로에 맞춰 `paymasterPostOpGasLimit`을 설정하세요.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
첫 번째 `UserOperation`은 흔히 `initCode`를 포함하며, 이로 인해 validation 중 **factory**를 통해 account가 deploy됩니다. 이 경로는 최초 사용 시에만 실행되므로 audit가 충분히 이루어지지 않기 쉽습니다.<sup>[[5]](#references)</sup>

일반적인 failure는 다음과 같습니다.<sup>[[5]](#references)</sup>

- factory/initializer가 `msg.sender == entryPoint`를 신뢰하지만, ERC-4337 deployment 경로는 `EntryPoint`에서 직접 `initCode`를 호출하지 않습니다.
- salt, owner, validator 또는 module configuration이 signed intent에 완전히 바인딩되지 않아, frontrunner가 첫 deployment를 race하고 attacker가 제어하는 설정으로 counterfactual address를 선점할 수 있습니다.
- factory가 non-idempotent하여, 첫 사용 flow가 반복되면 이미 생성된 address를 반환하는 대신 wallet이 동작 불능 상태가 됩니다.

안전한 pattern: signed deployment parameters에서 expected sender를 다시 계산하고, deployment를 결정적으로 수행하며(일반적으로 `CREATE2`), initialization을 one-shot으로 만드세요.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundlers가 거부하는 Validation 로직
Validation code는 local tests에서 올바르게 동작하더라도 실제 bundlers에서는 사용할 수 없을 수 있습니다. bundlers는 validation을 여러 번 실행하며, 제출 전에 traced full-bundle validation을 수행해야 합니다.<sup>[[6]](#references)</sup>

이러한 validation-scope 규칙에 따르면 다음 패턴은 위험합니다:<sup>[[6]](#references)</sup>

- `TIMESTAMP`, `NUMBER`, `BLOCKHASH`와 같은 block-dependent opcodes
- 허용된 account/entity scope를 벗어난 storage access 또는 storage에 대한 제한 없는 iteration
- 허용된 validation scope 외부의 mutable state에 의존하는 external calls 또는 oracle reads

Bad example:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // stateful validation can be clobbered by another op
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
검증은 결정론적이고 범위가 제한된 preflight 함수로 처리합니다. 공유 상태 또는 외부 조회가 필요한 경우에는 staked-entity 규칙을 따르고, unit tests뿐만 아니라 동일한 multi-pass bundler simulation 경로도 테스트해야 합니다.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702는 EOA에 smart-account code에 대한 지속적인 delegation을 부여하지만, delegation은 initialization을 원자적으로 실행하지 않습니다. initialization이 외부에서 호출 가능하면 observer가 이를 front-run하여 자신을 owner로 설정할 수 있습니다.<sup>[[7]](#references)</sup>

완화 방법: initialization calldata가 EOA에 의해 authorized되도록 요구하고, initialization은 한 번만 허용합니다. ERC-4337 EIP-7702 flow에서는 caller를 `EntryPoint.senderCreator()`로도 제한해야 합니다.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## 빠른 pre-merge 점검
- `EntryPoint`의 `userOpHash`를 사용하여 signature를 검증합니다(gas 필드를 바인딩).
- 적절한 경우 권한이 필요한 함수를 `EntryPoint` 및/또는 `address(this)`로 제한합니다.
- `validateUserOp`를 stateless하고 deterministic하게 유지하며 bundler simulation 규칙과 호환되도록 합니다.
- ERC-1271에 EIP-712 domain separation을 적용하고, 성공 시 `0x1626ba7e`를 반환합니다.
- `postOp`를 최소화하고, 범위를 제한하며, revert하지 않도록 합니다. validation 중 fee를 보호합니다.
- 첫 번째 `initCode` 경로를 별도로 테스트합니다: deterministic deployment, idempotent factory 동작, one-shot initialization.
- 배포 전에 bundler의 multi-pass validation과 traced full-bundle check를 실행합니다.
- ERC-7702에서는 init을 EOA authorization에 바인딩하고 한 번만 허용합니다. ERC-4337 흐름에서는 호출자를 `EntryPoint.senderCreator()`로 제한합니다.

## References

- [1] [ERC1271 Replay - 15개 이상의 팀에 영향 (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [ERC-4337 smart account의 6가지 실수 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Contracts를 위한 표준 Signature Validation Method](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Typed structured data hashing 및 signing](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Alt Mempool을 사용한 Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: EOAs를 위한 Set Code](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
