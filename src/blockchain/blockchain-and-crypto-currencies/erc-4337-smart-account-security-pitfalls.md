# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction은 wallets를 프로그래밍 가능한 시스템으로 바꿉니다. 핵심 흐름은 전체 bundle에 걸친 **validate-then-execute**입니다: `EntryPoint`는 어떤 `UserOperation`이든 실행하기 전에 모든 `UserOperation`을 validate합니다. 이 순서는 validation이 permissive하거나, stateful하거나, bundler simulation 규칙과 일관되지 않을 때 직관적이지 않은 attack surface를 만듭니다.

## 1) Direct-call bypass of privileged functions
`EntryPoint`(또는 검증된 executor module)로 제한되지 않은 외부에서 호출 가능한 `execute`(또는 fund-moving) 함수는 직접 호출되어 account를 drain할 수 있습니다.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
안전한 패턴: `EntryPoint`로 제한하고, admin/self-management 흐름(module install, validator changes, upgrades)에는 `msg.sender == address(this)`를 사용합니다.
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 서명되지 않았거나 검증되지 않은 gas 필드 -> fee drain
서명 검증이 intent(`callData`)만 커버하고 gas 관련 필드는 커버하지 않으면, bundler나 frontrunner가 fee를 부풀려 ETH를 drain할 수 있습니다. 서명된 payload는 최소한 다음을 bind해야 합니다:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

방어 패턴: `EntryPoint`가 제공하는 `userOpHash`(gas 필드를 포함함)를 사용하고/or 각 필드를 엄격히 cap하세요.
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
모든 validation이 execution 전에 실행되므로, validation 결과를 contract state에 저장하는 것은 unsafe 합니다. 같은 bundle의 다른 op가 이를 overwrite할 수 있고, 그 결과 execution이 attacker-influenced state를 사용하게 됩니다.

`validateUserOp`에서 storage에 쓰지 마십시오. unavoidable하다면, `userOpHash`로 temporary data를 keying하고 사용 후 deterministic하게 delete 하십시오 (stateless validation을 prefer).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)`는 signatures를 **이 contract**와 **이 chain**에 bind해야 합니다. raw hash 위에서 recover하면 signatures가 accounts나 chains across replay될 수 있습니다.

EIP-712 typed data를 사용하고 (domain에 `verifyingContract`와 `chainId`를 포함), success 시 정확한 ERC-1271 magic value `0x1626ba7e`를 return 하십시오.

## 5) Reverts do not refund after validation
`validateUserOp`가 성공하면, execution이 나중에 revert되더라도 fees는 committed 됩니다. Attackers는 실패할 op를 반복적으로 submit할 수 있고, 그래도 account에서 fees를 collect할 수 있습니다.

paymasters의 경우, `validateUserOp`에서 shared pool에서 paying하고 `postOp`에서 users를 charging하는 방식은 fragile 합니다. `postOp`가 payment를 undo하지 못한 채 revert될 수 있기 때문입니다. validation 동안 funds를 secure 하십시오 (per-user escrow/deposit), `postOp`는 minimal하고 non-reverting으로 유지하고, worst-case reimbursement path를 위해 `paymasterPostOpGasLimit`을 budget 하십시오.

## 6) Counterfactual deployment / factory assumptions
첫 `UserOperation`은 종종 `initCode`를 포함하며, 이는 validation 동안 account가 **factory**를 통해 deployed 되게 합니다. 이 path는 first use에서만 실행되므로 under-audit 되기 쉽습니다.

Common failures:

- factory/initializer가 `msg.sender == entryPoint`를 trust 하지만, ERC-4337 deployment path는 `initCode`를 `EntryPoint`에서 직접 call하지 않습니다.
- salt, owner, validator, 또는 module configuration이 signed intent에 fully bound되지 않아, frontrunner가 first deployment를 race해서 attacker-controlled settings로 counterfactual address를 burn할 수 있습니다.
- factory가 non-idempotent라서, repeated first-use flow가 이미 생성된 address를 반환하는 대신 wallet을 brick합니다.

Safe pattern: signed deployment parameters로부터 expected sender를 recompute하고, deployment를 deterministic하게 만들고 (typically `CREATE2`), initialization을 one-shot으로 만드십시오.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundlers가 거부하는 validation logic
Validation code는 로컬 테스트에서는 올바를 수 있지만, 실제 bundlers에서는 사용할 수 없게 될 수 있습니다. 공개 bundlers는 `validateUserOp()` / `validatePaymasterUserOp()`를 off-chain에서 시뮬레이션하고, 포함 전에 보통 전체 `debug_traceCall(handleOps)`를 실행합니다.

이로 인해 validation 안에서 다음 패턴들은 위험합니다:

- `TIMESTAMP`, `NUMBER`, `BLOCKHASH` 같은 block-dependent opcodes
- `SSTORE` 같은 state writes
- storage에 대한 무제한 iteration
- 시뮬레이션과 포함 사이에 달라질 수 있는 arbitrary external calls 또는 oracle reads

Bad example:
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
validation을 deterministic한, bounded preflight function으로 취급하세요. 정말로 shared state나 external lookups가 필요하다면, 그 복잡성을 staked/reputation-tracked entities로 밀어 넣고, unit tests만이 아니라 정확한 bundler simulation path를 테스트하세요.

## 8) ERC-7702 initialization frontrun
ERC-7702는 EOA가 단일 tx 동안 smart-account code를 실행할 수 있게 합니다. initialization이 externally callable이면, frontrunner가 자신을 owner로 설정할 수 있습니다.

Mitigation: initialization은 **self-call**에서만, 그리고 단 한 번만 허용하세요.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## 빠른 병합 전 점검
- `EntryPoint`의 `userOpHash`를 사용해 서명을 검증하세요(gas 필드를 bind함).
- 특권 함수는 적절히 `EntryPoint` 및/또는 `address(this)`로 제한하세요.
- `validateUserOp`는 stateless, deterministic 해야 하며 bundler simulation 규칙과 호환되어야 합니다.
- ERC-1271에 대해 EIP-712 domain separation을 적용하고, 성공 시 `0x1626ba7e`를 반환하세요.
- `postOp`는 최소, bounded, non-reverting 이어야 하며; validation 동안 fee를 secure하세요.
- 첫 `initCode` 경로를 별도로 테스트하세요: deterministic deployment, idempotent factory behavior, one-shot initialization.
- 배포 전에 전체 bundler simulation(`simulateValidation`과 traced `handleOps`)을 실행하세요.
- ERC-7702의 경우, init은 self-call에서만 그리고 한 번만 허용하세요.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
