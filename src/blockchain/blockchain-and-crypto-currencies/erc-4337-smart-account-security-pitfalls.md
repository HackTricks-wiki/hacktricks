# Підводні камені безпеки Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

Абстракція акаунтів ERC-4337 перетворює гаманці на програмовані системи. Основний flow — **validate-then-execute** у межах усього bundle: `EntryPoint` перевіряє кожну `UserOperation` перед виконанням будь-якої з них. Такий порядок створює неочевидну attack surface, коли validation є надто permissive, stateful або не узгоджується з правилами симуляції bundler.

## 1) Обхід через прямий виклик privileged functions
Будь-яку externally callable функцію `execute` (або функцію, що переміщує кошти), яка не обмежена `EntryPoint` (або перевіреним executor module), можна викликати напряму для спустошення акаунта.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Безпечний шаблон: обмежте доступ до `EntryPoint` і використовуйте `msg.sender == address(this)` для потоків адміністрування/самокерування (встановлення модулів, зміни валідаторів, оновлення).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Непідписані або неперевірені поля gas -> drain комісій
Якщо перевірка підпису охоплює лише намір (`callData`), але не поля, пов’язані з gas, bundler або frontrunner може завищити комісії та вивести ETH. Підписаний payload має щонайменше прив’язувати:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Захисний підхід: використовуйте наданий `EntryPoint` `userOpHash` (який містить поля gas) та/або суворо обмежуйте кожне поле.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Перезапис результатів stateful validation (семантика bundle)
Оскільки всі validations виконуються перед будь-яким execution, зберігати результати validation у state контракту небезпечно. Інша op у тому самому bundle може їх перезаписати, через що ваш execution використає state, на який вплинув attacker.<sup>[[1]](#references)</sup>

Уникайте запису в storage у `validateUserOp`. Якщо цього не уникнути, прив'язуйте тимчасові дані до `userOpHash` і детерміновано видаляйте їх після використання (краще використовувати stateless validation).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay між accounts/chains (відсутність domain separation)
`isValidSignature(bytes32 hash, bytes sig)` має прив'язувати signatures до **цього contract** і **цього chain**. Відновлення підписанта для raw hash дає змогу повторно використовувати signatures між accounts або chains.<sup>[[1]](#references)</sup>

Використовуйте EIP-712 typed data (domain містить `verifyingContract` і `chainId`) і повертайте точне ERC-1271 magic value `0x1626ba7e` у разі успіху.<sup>[[1]](#references)</sup>

## 5) Reverts не повертають кошти після validation
Після успішного виконання `validateUserOp` fees вважаються committed, навіть якщо execution згодом завершується revert. Attackers можуть багаторазово надсилати ops, які завершаться помилкою, і все одно списувати fees з account.<sup>[[1]](#references)</sup>

Для paymasters оплата зі shared pool у `validateUserOp` і стягнення коштів з users у `postOp` є ненадійними, оскільки `postOp` може завершитися revert без скасування payment. Захищайте кошти під час validation (per-user escrow/deposit), зводьте `postOp` до мінімуму та не допускайте revert, а `paymasterPostOpGasLimit` розраховуйте для worst-case reimbursement path.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / припущення щодо factory
Перша `UserOperation` часто містить `initCode`, що спричиняє deployment account через **factory** під час validation. Цей path легко недооцінити під час аудиту, оскільки він виконується лише під час першого використання.<sup>[[2]](#references)</sup>

Поширені помилки:

- Factory/initializer покладається на `msg.sender == entryPoint`, але шлях deployment в ERC-4337 **не** викликає `initCode` безпосередньо з `EntryPoint`.
- Salt, owner, validator або конфігурація module не повністю прив'язані до signed intent, тому frontrunner може випередити перший deployment і зайняти counterfactual address із settings, контрольованими attacker.
- Factory є non-idempotent, тому повторний flow першого використання ламає wallet замість повернення вже створеної address.

Безпечний pattern: повторно обчислюйте expected sender із signed deployment parameters, зробіть deployment детермінованим (зазвичай через `CREATE2`) і виконуйте initialization лише один раз.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Логіка валідації, яку відхиляють bundlers
Код валідації може бути коректним у локальних тестах і водночас непридатним для використання в реальних bundlers. Публічні bundlers симулюють `validateUserOp()` / `validatePaymasterUserOp()` off-chain і зазвичай виконують повний `debug_traceCall(handleOps)` перед включенням.

Це робить такі шаблони небезпечними всередині валідації:

- Операкоди, залежні від блоку, такі як `TIMESTAMP`, `NUMBER` або `BLOCKHASH`
- Записи до стану, такі як `SSTORE`
- Необмежена ітерація по storage
- Довільні зовнішні виклики або читання oracle, які можуть змінитися між симуляцією та включенням

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
Розглядайте validation як детерміновану, обмежену preflight-функцію. Якщо вам справді потрібен shared state або зовнішні lookups, перенесіть цю складність у staked/reputation-tracked entities і тестуйте точний шлях bundler simulation, а не лише unit tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 дає змогу EOA виконувати код smart-account протягом однієї tx. Якщо initialization доступна для зовнішнього виклику, frontrunner може призначити себе owner.<sup>[[1]](#references)</sup>

Mitigation: дозволяйте initialization лише через **self-call** і лише один раз.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Швидкі перевірки перед злиттям
- Перевіряйте підписи за допомогою `userOpHash` з `EntryPoint` (прив’язує поля gas).
- Обмежуйте привілейовані функції `EntryPoint` та/або `address(this)` відповідно до ситуації.
- Зберігайте `validateUserOp` безстанною, детермінованою та сумісною з правилами симуляції bundler.
- Забезпечуйте розділення доменів EIP-712 для ERC-1271 і повертайте `0x1626ba7e` у разі успіху.
- Робіть `postOp` мінімальною, обмеженою за ресурсами та такою, що не спричиняє revert; захищайте комісії під час валідації.
- Окремо тестуйте перший шлях `initCode`: детерміноване розгортання, ідемпотентну поведінку factory та одноразову ініціалізацію.
- Перед випуском запускайте повну симуляцію bundler (`simulateValidation` разом із трасованим `handleOps`).
- Для ERC-7702 дозволяйте init лише під час self-call і лише один раз.



## Посилання

- [1] [Шість помилок у смарт-акаунтах ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: абстракція акаунтів із використанням Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
