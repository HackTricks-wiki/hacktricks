# ERC-4337 Вразливості безпеки Smart Account

Абстракція акаунтів ERC-4337 перетворює wallets на програмовані системи. Основний процес — **validate-then-execute** у межах усього bundle: `EntryPoint` перевіряє кожну `UserOperation`, перш ніж виконувати будь-яку з них.<sup>[[5]](#references)</sup> Такий порядок створює неочевидну поверхню атаки, коли валідація є permissive, stateful або непослідовною з правилами симуляції bundler.

## 1) Обхід через прямий виклик privileged functions
Будь-яку externally callable функцію `execute` (або функцію, що переміщує кошти), яка не обмежена `EntryPoint` (або перевіреним executor module), можна викликати напряму для спустошення акаунта.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Безпечний шаблон: обмежте доступ до `EntryPoint` і використовуйте `msg.sender == address(this)` для адміністративних потоків/потоків самокерування (встановлення модулів, зміни валідаторів, оновлення).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Непідписані або неперевірені поля gas -> drain комісій
Якщо перевірка підпису охоплює лише intent (`callData`), але не поля, пов'язані з gas, bundler або frontrunner може завищити комісії та drain ETH. Підписаний payload має охоплювати щонайменше:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Захисний підхід: використовувати наданий `EntryPoint` хеш `userOpHash` (який містить поля gas) та/або суворо обмежувати кожне поле.<sup>[[2]](#references)[[5]](#references)</sup>
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
Оскільки всі validations виконуються до будь-якого execution, зберігати результати validation у стані контракту небезпечно. Інша op у тому самому bundle може їх перезаписати, через що ваш execution використає state, контрольований attacker.<sup>[[2]](#references)</sup>

Уникайте запису storage у `validateUserOp`. Якщо цього не можна уникнути, прив’язуйте тимчасові дані до `userOpHash` і детерміновано видаляйте їх після використання (надавайте перевагу stateless validation).<sup>[[2]](#references)</sup>

## 4) Replay ERC-1271 між accounts/chains (відсутній domain separation)
`isValidSignature(bytes32 hash, bytes sig)` має прив’язувати signatures до **цього контракту** та **цього chain**. Відновлення підписувача для raw hash дає змогу відтворювати signatures між accounts або chains.<sup>[[1]](#references)[[4]](#references)</sup>

Використовуйте typed data EIP-712 (domain містить `verifyingContract` і `chainId`) та повертайте точне magic value ERC-1271 `0x1626ba7e` у разі успіху.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Revert не повертає кошти після validation
Після успішного виконання `validateUserOp` fees вважаються committed, навіть якщо execution згодом завершиться revert. Attackers можуть повторно надсилати ops, які завершаться помилкою, і все одно списувати fees з account.<sup>[[2]](#references)</sup>

Для paymasters оплата зі shared pool у `validateUserOp` і списання коштів з users у `postOp` є ненадійними, оскільки `postOp` може завершитися revert без скасування платежу. Захищайте кошти під час validation (per-user escrow/deposit), залишайте `postOp` мінімальним і таким, що не викликає revert, та закладайте `paymasterPostOpGasLimit` для worst-case reimbursement path.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / припущення щодо factory
Перша `UserOperation` часто містить `initCode`, що призводить до deployment account через **factory** під час validation. Цей path легко недостатньо перевірити, оскільки він виконується лише під час першого використання.<sup>[[5]](#references)</sup>

Поширені помилки включають:<sup>[[5]](#references)</sup>

- Factory/initializer покладається на `msg.sender == entryPoint`, але deployment path ERC-4337 **не** викликає `initCode` безпосередньо з `EntryPoint`.
- Salt, owner, validator або module configuration не повністю прив’язані до signed intent, тому frontrunner може випередити перший deployment і зайняти counterfactual address з attacker-controlled settings.
- Factory є non-idempotent, тому повторний first-use flow блокує wallet замість повернення вже створеної address.

Безпечний pattern: повторно обчислюйте expected sender із signed deployment parameters, робіть deployment детермінованим (зазвичай через `CREATE2`) і забезпечуйте одноразову initialization.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Логіка валідації, яку відхиляють bundlers

Код валідації може бути коректним у локальних тестах і водночас непридатним для використання в реальних bundlers. Bundlers запускають валідацію кілька разів, тому перед submission слід виконувати повну валідацію bundle з tracing.<sup>[[6]](#references)</sup>

За таких правил щодо області валідації небезпечними є такі патерни:<sup>[[6]](#references)</sup>

- Опкоди, що залежать від block, такі як `TIMESTAMP`, `NUMBER` або `BLOCKHASH`
- Доступ до storage поза межами дозволеної області account/entity або необмежена ітерація по storage
- External calls або oracle reads, що залежать від mutable state поза межами дозволеної області валідації

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
Розглядайте валідацію як детерміновану обмежену preflight-функцію. Якщо потрібні спільний стан або зовнішні lookup-запити, дотримуйтеся правил для staked-entity і тестуйте той самий шлях багатоетапної симуляції bundler, а не лише unit-тести.<sup>[[6]](#references)</sup>

## 8) ERC-7702 front-run під час ініціалізації
ERC-7702 надає EOA постійну делегацію до коду smart-account; делегація не виконує ініціалізацію атомарно. Якщо ініціалізація доступна для зовнішнього виклику, спостерігач може виконати front-run і призначити себе власником.<sup>[[7]](#references)</sup>

Пом'якшення: вимагайте, щоб calldata ініціалізації була авторизована EOA, і дозволяйте ініціалізацію лише один раз. У потоці ERC-4337 EIP-7702 також обмежте caller значенням `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Швидкі перевірки перед злиттям
- Перевіряйте signatures за допомогою `userOpHash` `EntryPoint` (прив’язує поля gas).
- Обмежуйте privileged functions до `EntryPoint` та/або `address(this)` відповідно до ситуації.
- Робіть `validateUserOp` stateless, deterministic і сумісним із правилами simulation bundler.
- Забезпечуйте domain separation EIP-712 для ERC-1271 і повертайте `0x1626ba7e` у разі успіху.
- Робіть `postOp` мінімальним, обмеженим і таким, що не спричиняє revert; захищайте fees під час validation.
- Окремо тестуйте перший шлях `initCode`: deterministic deployment, idempotent behavior factory та одноразову initialization.
- Перед shipping запускайте multi-pass validation bundler і traced full-bundle check.
- Для ERC-7702 прив’язуйте init до authorization EOA і дозволяйте його лише один раз; у flows ERC-4337 обмежуйте caller до `EntryPoint.senderCreator()`.

## References

- [1] [Replay ERC1271 - постраждали понад 15 команд (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Шість помилок у smart accounts ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Стандартний метод перевірки signatures для контрактів](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Хешування та підписування типізованих структурованих даних](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction із використанням Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Правила scope validation для Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Встановлення коду для EOA](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
