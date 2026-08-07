# Недоліки безпеки Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

Абстракція акаунтів ERC-4337 перетворює гаманці на програмовані системи. Основний процес — **validate-then-execute** для всього bundle: `EntryPoint` перевіряє кожен `UserOperation`, перш ніж виконати будь-який із них. Такий порядок створює неочевидну поверхню атаки, якщо перевірка є надто permissive, залежить від стану або не узгоджується з правилами симуляції bundler.

## 1) Обхід обмежень privileged-функцій через прямий виклик
Будь-яку externally callable функцію `execute` (або функцію, що переміщує кошти), яка не обмежена `EntryPoint` (або перевіреним executor module), можна викликати напряму, щоб спустошити акаунт.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Безпечний шаблон: обмежте до `EntryPoint` і використовуйте `msg.sender == address(this)` для потоків адміністрування/самокерування (встановлення модулів, зміни валідаторів, оновлення).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Непідписані або неперевірені gas-поля -> fee drain
Якщо перевірка підпису охоплює лише intent (`callData`), але не поля, пов’язані з gas, bundler або frontrunner може завищити комісії та drain ETH. Підписаний payload має щонайменше включати:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Захисний підхід: використовувати наданий `EntryPoint` `userOpHash` (який містить поля gas) та/або суворо обмежувати кожне поле.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Перезаписування стану валідації (семантика bundle)
Оскільки всі валідації виконуються до будь-якого виконання, зберігати результати валідації у стані контракту небезпечно. Інша операція в тому самому bundle може їх перезаписати, через що ваше виконання використовуватиме стан, на який вплинув attacker.<sup>[[1]](#references)</sup>

Уникайте запису в storage у `validateUserOp`. Якщо це неминуче, прив’язуйте тимчасові дані до `userOpHash` і детерміновано видаляйте їх після використання (надавайте перевагу stateless validation).<sup>[[1]](#references)</sup>

## 4) Replay ERC-1271 між акаунтами та chain (відсутній domain separation)
`isValidSignature(bytes32 hash, bytes sig)` має прив’язувати підписи до **цього контракту** та **цього chain**. Відновлення підписувача за raw hash дає змогу відтворювати підписи між акаунтами або chain.<sup>[[1]](#references)</sup>

Використовуйте EIP-712 typed data (domain містить `verifyingContract` і `chainId`) і повертайте точне magic value ERC-1271 `0x1626ba7e` у разі успіху.<sup>[[1]](#references)</sup>

## 5) Revert не повертає кошти після валідації
Після успішного виконання `validateUserOp` комісії вважаються зафіксованими, навіть якщо виконання згодом завершиться revert. Attackers можуть повторно надсилати ops, які завершаться помилкою, і все одно стягувати комісії з акаунта.<sup>[[1]](#references)</sup>

Для paymasters оплата зі спільного pool у `validateUserOp` і стягнення коштів із користувачів у `postOp` є ненадійними, оскільки `postOp` може завершитися revert без скасування платежу. Резервуйте кошти під час валідації (окремий escrow/deposit для кожного користувача), залишайте `postOp` мінімальним і таким, що не завершується revert, та закладайте в `paymasterPostOpGasLimit` бюджет для шляху відшкодування у найгіршому випадку.<sup>[[1]](#references)</sup>

## 6) Припущення щодо counterfactual deployment / factory
Перша `UserOperation` часто містить `initCode`, що спричиняє deployment акаунта через **factory** під час валідації. Цей шлях легко недостатньо перевірити, оскільки він виконується лише під час першого використання.<sup>[[2]](#references)</sup>

Поширені помилки:

- Factory/initializer довіряє умові `msg.sender == entryPoint`, але шлях deployment в ERC-4337 **не** викликає `initCode` безпосередньо з `EntryPoint`.
- Salt, owner, validator або конфігурація module не повністю прив’язані до підписаного intent, тому frontrunner може випередити перший deployment і зайняти counterfactual address із налаштуваннями, контрольованими attacker.
- Factory не є idempotent, тому повторний flow першого використання робить wallet непридатним замість повернення вже створеної address.

Безпечний pattern: повторно обчислюйте очікуваний sender на основі підписаних параметрів deployment, робіть deployment детермінованим (зазвичай через `CREATE2`) і виконуйте initialization лише один раз.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic that bundlers reject
Код validation може бути коректним у локальних тестах і водночас непридатним для використання в реальних bundlers. Public bundlers симулюють `validateUserOp()` / `validatePaymasterUserOp()` off-chain і зазвичай виконують повний `debug_traceCall(handleOps)` перед включенням.<sup>[[3]](#references)</sup>

Через це такі патерни є небезпечними всередині validation:

- Опкоди, залежні від блоку, як-от `TIMESTAMP`, `NUMBER` або `BLOCKHASH`
- Записи до state, як-от `SSTORE`
- Необмежена ітерація по storage
- Довільні external calls або oracle reads, які можуть змінитися між simulation і включенням

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
Розглядайте validation як детерміновану, обмежену preflight-функцію. Якщо вам справді потрібен shared state або зовнішні lookup-запити, перенесіть цю складність у staked/reputation-tracked entities і тестуйте точний bundler simulation path, а не лише unit tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 дає змогу EOA виконувати код smart-account протягом однієї tx. Якщо initialization можна викликати externally, frontrunner може призначити себе owner.<sup>[[1]](#references)</sup>

Mitigation: дозволяйте initialization лише через **self-call** і лише один раз.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Швидкі перевірки перед злиттям
- Перевіряйте підписи за допомогою `userOpHash` з `EntryPoint` (він прив'язує поля gas).
- Обмежуйте привілейовані функції до `EntryPoint` та/або `address(this)` відповідно до вимог.
- Робіть `validateUserOp` безстанним, детермінованим і сумісним із правилами симуляції bundler.
- Забезпечуйте розділення доменів EIP-712 для ERC-1271 і повертайте `0x1626ba7e` у разі успіху.
- Робіть `postOp` мінімальним, обмеженим за ресурсами та таким, що не спричиняє revert; захищайте комісії під час валідації.
- Окремо тестуйте перший шлях `initCode`: детерміноване розгортання, ідемпотентну поведінку factory та одноразову ініціалізацію.
- Перед випуском запускайте повну симуляцію bundler (`simulateValidation` разом із трасованим `handleOps`).
- Для ERC-7702 дозволяйте init лише під час self-call і лише один раз.

## Посилання

- [1] [Шість помилок у smart accounts ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: абстракція акаунтів із використанням альтернативного mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: правила області валідації абстракції акаунтів](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
