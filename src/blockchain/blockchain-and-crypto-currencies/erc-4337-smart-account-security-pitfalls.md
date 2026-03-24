# ERC-4337 Підводні камені безпеки смарт-акаунтів

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction перетворює гаманці на програмовані системи. Основний потік — **validate-then-execute** для всього bundle: `EntryPoint` перевіряє кожен `UserOperation` перед тим, як виконати будь-який з них. Такий порядок створює неочевидну поверхню для атак, коли валідація є надмірно дозволяючою або станозалежною.

## 1) Direct-call bypass of privileged functions
Будь-яка зовні викликана функція `execute` (або функція переміщення коштів), яка не обмежена `EntryPoint` (або перевіреним executor module), може бути викликана напряму для спустошення акаунта.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Безпечний шаблон: обмежити доступ до `EntryPoint` і використовувати `msg.sender == address(this)` для адміністративних/самокерованих потоків (установка модуля, зміни валідатора, оновлення).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Не підписані або неперевірені поля gas -> виснаження комісій
Якщо валідація підпису покриває лише намір (`callData`), але не поля, пов'язані з gas, bundler або frontrunner можуть завищити комісії та спустошити ETH. Підписаний payload має включати принаймні:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Захисний підхід: використовуйте `EntryPoint`-provided `userOpHash` (який включає gas поля) та/або строго обмежуйте кожне поле.
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
Оскільки всі валідації виконуються перед будь-яким виконанням, зберігання результатів валідації в стані контракту небезпечне. Інша операція у тому ж bundle може перезаписати ці дані, через що ваше виконання використовуватиме стан, змінений зловмисником.

Уникайте запису в storage в `validateUserOp`. Якщо це неминуче, індексуйте тимчасові дані за `userOpHash` та видаляйте їх детерміновано після використання (надавайте перевагу stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` має прив'язувати підписи до цього контракту та цієї мережі (домену). Відновлення підписувача по сирому hash дозволяє повторно використовувати підписи між акаунтами або мережами.

Використовуйте EIP-712 typed data (домен включає `verifyingContract` і `chainId`) і повертайте точне магічне значення ERC-1271 `0x1626ba7e` при успіху.

## 5) Reverts do not refund after validation
Як тільки `validateUserOp` проходить успішно, комісії фіксуються навіть якщо виконання пізніше відкотиться. Зловмисники можуть багаторазово подавати операції, які завершаться помилкою, і все одно збирати комісії з акаунта.

Для paymasters, сплата зі спільного пулу в `validateUserOp` і списання з користувачів у `postOp` є крихкою, бо `postOp` може відкотитися без скасування платежу. Захищайте кошти під час валідації (пер-юзер ескроу/депозит) і тримайте `postOp` мінімальним та таким, що не відкатується.

## 6) ERC-7702 initialization frontrun
ERC-7702 дозволяє EOA виконати код smart-account для одного tx. Якщо ініціалізацію можна викликати зовні, frontrunner може призначити себе owner.

Mitigation: дозволяйте ініціалізацію лише при **self-call** і лише один раз.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Швидкі перевірки перед злиттям
- Перевіряти підписи, використовуючи `EntryPoint`'s `userOpHash` (зв'язує поля gas).
- Обмежити привілейовані функції тільки `EntryPoint` і/або `address(this)` за необхідності.
- Забезпечити, щоб `validateUserOp` був безстанним.
- Застосувати EIP-712 domain separation для ERC-1271 та повертати `0x1626ba7e` при успіху.
- Тримати `postOp` мінімальним, обмеженим і таким, що не викликає revert; захистити комісії під час валідації.
- Для ERC-7702 дозволяти init лише при self-call і лише один раз.

## Посилання

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
