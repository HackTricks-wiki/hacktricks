# Недоліки безпеки Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

Абстракція акаунтів ERC-4337 перетворює гаманці на програмовані системи. Основний процес — **validate-then-execute** у межах усього bundle: `EntryPoint` перевіряє кожен `UserOperation` перед виконанням будь-якого з них.<sup>[[5]](#references)</sup> Такий порядок створює неочевидну attack surface, якщо validation є надто permissive, stateful або не узгоджується з правилами симуляції bundler.

## 1) Обхід обмежень прямих викликів привілейованих функцій
Будь-яку externally callable функцію `execute` (або функцію переміщення коштів), яка не обмежена `EntryPoint` (або перевіреним executor module), можна викликати напряму, щоб спустошити акаунт.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Безпечний шаблон: обмежте доступ до `EntryPoint` і використовуйте `msg.sender == address(this)` для адміністративних операцій і операцій самокерування (встановлення модулів, зміни валідаторів, оновлення).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Непідписані або неперевірені поля gas -> drain комісій
Якщо перевірка підпису охоплює лише намір (`callData`), але не поля, пов’язані з gas, bundler або frontrunner може завищити комісії та drain ETH. Підписаний payload має принаймні прив’язувати:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Захисний підхід: використовуйте наданий `EntryPoint` `userOpHash` (який містить поля gas) та/або суворо обмежуйте кожне поле.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Перезапис stateful validation (семантика bundle)
Оскільки всі перевірки виконуються до будь-якого виконання, зберігати результати перевірки у state контракту небезпечно. Інша op у тому самому bundle може перезаписати їх, через що ваше виконання використає state, контрольований attacker.<sup>[[2]](#references)</sup>

Уникайте запису в storage у `validateUserOp`. Якщо це неминуче, прив'язуйте тимчасові дані до `userOpHash` і детерміновано видаляйте їх після використання (перевагу слід надавати stateless validation).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay між акаунтами/мережами (відсутність domain separation)
`isValidSignature(bytes32 hash, bytes sig)` має прив'язувати підписи до **цього контракту** та **цієї мережі**. Відновлення підписанта за raw hash дозволяє виконувати replay підписів між акаунтами або мережами.<sup>[[1]](#references)[[4]](#references)</sup>

Використовуйте типізовані дані EIP-712 (domain містить `verifyingContract` і `chainId`) і повертайте точне magic value ERC-1271 `0x1626ba7e` у разі успіху.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Revert не повертає кошти після validation
Після успішного виконання `validateUserOp` комісії вважаються зафіксованими, навіть якщо виконання згодом завершиться revert. Attackers можуть повторно надсилати ops, які завершаться помилкою, і все одно стягувати комісії з акаунта.<sup>[[2]](#references)</sup>

Для paymasters оплата зі спільного pool у `validateUserOp` та стягнення коштів з користувачів у `postOp` є ненадійними, оскільки `postOp` може завершитися revert без скасування платежу. Захищайте кошти під час validation (використовуйте escrow/deposit для кожного користувача), мінімізуйте `postOp` і не допускайте його revert, а також закладайте в `paymasterPostOpGasLimit` бюджет для worst-case шляху відшкодування.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Припущення щодо counterfactual deployment / factory
Перша `UserOperation` часто містить `initCode`, що спричиняє розгортання акаунта через **factory** під час validation. Цей шлях легко недостатньо перевірити, оскільки він виконується лише під час першого використання.<sup>[[5]](#references)</sup>

Поширені помилки включають:<sup>[[5]](#references)</sup>

- Factory/initializer довіряє умові `msg.sender == entryPoint`, але шлях розгортання ERC-4337 **не** викликає `initCode` безпосередньо з `EntryPoint`.
- Salt, owner, validator або конфігурація module не повністю прив'язані до підписаного intent, тому frontrunner може випередити перше розгортання та зайняти counterfactual address налаштуваннями, контрольованими attacker.
- Factory не є idempotent, тому повторний first-use flow ламає wallet замість повернення вже створеної address.

Безпечний підхід: повторно обчислюйте очікуваний sender на основі підписаних параметрів розгортання, робіть розгортання детермінованим (зазвичай через `CREATE2`) і виконуйте initialization лише один раз.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Логіка валідації, яку відхиляють bundlers

Код валідації може бути коректним у локальних тестах і водночас непридатним для використання в реальних bundlers. Bundlers запускають валідацію кілька разів і повинні виконувати повну валідацію bundle із трасуванням перед його надсиланням.<sup>[[6]](#references)</sup>

Відповідно до правил області дії валідації, небезпечними є такі патерни:<sup>[[6]](#references)</sup>

- Опкоди, що залежать від блока, як-от `TIMESTAMP`, `NUMBER` або `BLOCKHASH`
- Доступ до storage за межами дозволеної області account/entity або необмежена ітерація по storage
- Зовнішні виклики або читання з oracle, що залежать від змінюваного стану за межами дозволеної області валідації

Поганий приклад:
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
Розглядайте валідацію як детерміновану, обмежену функцію попередньої перевірки. Якщо необхідні спільний стан або зовнішні запити, дотримуйтеся правил для staked-entity і тестуйте той самий шлях багатоетапної симуляції bundler, а не лише модульні тести.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 надає EOA постійну делегацію коду smart-account; делегація не виконує ініціалізацію атомарно. Якщо ініціалізація доступна для зовнішнього виклику, спостерігач може виконати front-run і встановити себе як власника.<sup>[[7]](#references)</sup>

Пом’якшення: вимагайте, щоб calldata ініціалізації була авторизована EOA, і дозволяйте ініціалізацію лише один раз. У потоці ERC-4337 EIP-7702 також обмежте caller значенням `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Швидкі перевірки перед злиттям
- Перевіряйте підписи за допомогою `userOpHash` від `EntryPoint` (він прив’язує поля gas).
- Обмежуйте привілейовані функції до `EntryPoint` та/або `address(this)` відповідно до ситуації.
- Робіть `validateUserOp` stateless, детермінованою та сумісною з правилами симуляції bundler.
- Забезпечуйте domain separation за EIP-712 для ERC-1271 і повертайте `0x1626ba7e` у разі успіху.
- Робіть `postOp` мінімальною, обмеженою та такою, що не спричиняє revert; захищайте комісії під час валідації.
- Окремо тестуйте перший шлях `initCode`: детерміноване розгортання, idempotent-поведінку factory та одноразову ініціалізацію.
- Перед випуском запускайте багатопрохідну валідацію bundler і перевірку повного bundle з трасуванням.
- Для ERC-7702 прив’язуйте init до авторизації EOA і дозволяйте його лише один раз; у потоках ERC-4337 обмежуйте caller до `EntryPoint.senderCreator()`.

## References

- [1] [Replay ERC1271 — постраждали понад 15 команд (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Шість помилок у smart accounts ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Стандартний метод перевірки підписів для контрактів](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Хешування та підписування типізованих структурованих даних](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Абстракція акаунтів із використанням Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Правила області валідації абстракції акаунтів](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Встановлення code для EOA](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
