# Пастки безпеки Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction перетворює wallets на програмовані системи. Основний потік — **validate-then-execute** для всього bundle: `EntryPoint` валідовує кожен `UserOperation` перед виконанням будь-якого з них. Така послідовність створює неочевидну attack surface, коли validation є permissive, stateful або не узгоджується з bundler simulation rules.

## 1) Direct-call bypass of privileged functions
Будь-яка externally callable `execute` (або fund-moving) функція, яка не обмежена `EntryPoint` (або перевіреним executor module), може бути викликана напряму, щоб drain the account.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Безпечний шаблон: обмежуйте до `EntryPoint`, і використовуйте `msg.sender == address(this)` для flows адміністрування/self-management (встановлення module, зміни validator, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Unsigned or unchecked gas fields -> fee drain
Якщо перевірка signature охоплює лише intent (`callData`), але не gas-related fields, bundler або frontrunner можуть inflate fees і drain ETH. Підписаний payload має прив’язувати щонайменше:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: use the `EntryPoint`-provided `userOpHash` (which includes gas fields) and/or strictly cap each field.
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
Оскільки всі validations виконуються до будь-якого execution, зберігати результати validation у стані contract небезпечно. Інша op в тому ж bundle може перезаписати їх, через що execution використає state, на який вплинув attacker.

Уникайте запису в storage у `validateUserOp`. Якщо цього не уникнути, ключуйте тимчасові дані за `userOpHash` і видаляйте їх детерміновано після використання (краще stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` має прив’язувати signatures до **цього contract** і **цієї chain**. Recovering over raw hash дозволяє signatures replay across accounts or chains.

Використовуйте EIP-712 typed data (domain включає `verifyingContract` і `chainId`) і повертайте точне ERC-1271 magic value `0x1626ba7e` у разі успіху.

## 5) Reverts do not refund after validation
Після того як `validateUserOp` успішно пройшов, fees фіксуються навіть якщо execution пізніше revert-иться. Attackers можуть багаторазово надсилати ops, які fail-яться, і все одно списувати fees з account.

Для paymasters, оплата зі спільного pool у `validateUserOp` і charging users у `postOp` є fragile, бо `postOp` може revert-нутися без undo payment. Secure funds під час validation (per-user escrow/deposit), тримайте `postOp` мінімальним і non-reverting, і закладайте `paymasterPostOpGasLimit` для worst-case reimbursement path.

## 6) Counterfactual deployment / factory assumptions
Перша `UserOperation` часто містить `initCode`, що спричиняє deployment account через **factory** під час validation. Цей path легко недоаудитити, бо він виконується лише під час first use.

Поширені failures:

- Factory/initializer довіряє `msg.sender == entryPoint`, але ERC-4337 deployment path **не** викликає `initCode` напряму з `EntryPoint`.
- Salt, owner, validator або module configuration не повністю прив’язані до signed intent, тому frontrunner може випередити перший deployment і спалити counterfactual address із attacker-controlled settings.
- Factory не idempotent, тому повторний first-use flow ламає wallet замість того, щоб повертати вже створену address.

Safe pattern: перераховуйте expected sender із signed deployment parameters, робіть deployment deterministic (зазвичай `CREATE2`), і робіть initialization one-shot.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Логіка валідації, яку відхиляють bundlers
Код валідації може бути правильним у локальних тестах і все одно бути непридатним у реальних bundlers. Публічні bundlers симулюють `validateUserOp()` / `validatePaymasterUserOp()` off-chain і зазвичай запускають повний `debug_traceCall(handleOps)` перед включенням.

Це робить такі патерни небезпечними всередині validation:

- Opcode-и, що залежать від блоку, такі як `TIMESTAMP`, `NUMBER` або `BLOCKHASH`
- Записи в state, такі як `SSTORE`
- Необмежена ітерація по storage
- Будь-які зовнішні calls або oracle reads, які можуть змінитися між simulation і inclusion

Поганий приклад:
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
Ставтеся до validation як до детермінованої, bounded preflight function. Якщо вам справді потрібен shared state або external lookups, перенесіть цю complexity у staked/reputation-tracked entities і тестуйте exact bundler simulation path, а не лише unit tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 дає змогу EOA запускати smart-account code для одного tx. Якщо initialization є externally callable, frontrunner може призначити себе owner.

Mitigation: дозволяйте initialization лише через **self-call** і лише once.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Швидкі перевірки перед merge
- Перевірте signatures за допомогою `EntryPoint`'s `userOpHash` (зв’язує gas поля).
- Обмежте privileged functions до `EntryPoint` та/або `address(this)` відповідно.
- Залишайте `validateUserOp` stateless, deterministic і сумісним із bundler simulation rules.
- Забезпечте EIP-712 domain separation для ERC-1271 і повертайте `0x1626ba7e` у разі success.
- Зробіть `postOp` minimal, bounded і non-reverting; secure fees під час validation.
- Окремо протестуйте перший шлях `initCode`: deterministic deployment, idempotent поведінку factory і one-shot initialization.
- Запустіть повну bundler simulation (`simulateValidation` плюс traced `handleOps`) перед випуском.
- Для ERC-7702 дозволяйте init лише через self-call і лише один раз.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
