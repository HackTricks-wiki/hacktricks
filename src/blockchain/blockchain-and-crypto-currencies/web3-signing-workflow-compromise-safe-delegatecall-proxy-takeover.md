# Компрометація процесу підписання Web3 і захоплення Safe Delegatecall Proxy

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Ланцюжок викрадення коштів із cold-wallet поєднав **компрометацію supply chain вебінтерфейсу Safe{Wallet}** з **on-chain primitive delegatecall, який перезаписав вказівник implementation проксі (slot 0)**. Основні висновки:

- Якщо dApp може інжектити code у процес підписання, він може змусити signer створити валідний **EIP-712 signature для вибраних зловмисником полів**, а потім відновити початкові дані UI, щоб інші signers нічого не помітили.
- Safe proxies зберігають `masterCopy` (implementation) у **storage slot 0**. Delegatecall до contract, який записує дані в slot 0, фактично “оновлює” Safe до attacker logic, надаючи повний контроль над wallet.

## Off-chain: цільова мутація підписання в Safe{Wallet}

Підроблений Safe bundle (`_app-*.js`) вибірково атакував певні адреси Safe та signer. Інжектована logic виконувалася безпосередньо перед signing call:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: жорстко задані allowlists для victim Safes/signers запобігали шуму та знижували ймовірність виявлення.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: поля (`to`, `data`, `operation`, gas) перезаписувалися безпосередньо перед `signTransaction`, а потім відновлювалися, тому proposal payloads у UI виглядали безпечно, тоді як signatures відповідали payloads атакувальника.
- **EIP-712 opacity**: wallets показували структуровані дані, але не декодували вкладений calldata і не виділяли `operation = delegatecall`, через що mutated message фактично підписувалося всліпу.

### Актуальність валідації Gateway
Safe proposals надсилаються до **Safe Client Gateway**. До впровадження посилених перевірок gateway міг прийняти proposal, у якому `safeTxHash`/signature відповідали іншим полям, ніж JSON body, якщо UI переписував їх після підписання. Після інциденту gateway тепер відхиляє proposals, якщо hash/signature не відповідають надісланій транзакції. Аналогічну server-side перевірку hash слід застосовувати до будь-якого signing-orchestration API.

### Ключові моменти інциденту Bybit/Safe 2025 року
- Виведення коштів із cold-wallet Bybit 21 лютого 2025 року (~401k ETH) повторило ту саму схему: скомпрометований Safe S3 bundle спрацьовував лише для Bybit signers і змінював `operation=0` → `1`, вказуючи `to` на попередньо розгорнутий attacker contract, який записував у slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Закешований Wayback `_app-52c9031bfa03da47.js` показує, що логіка була прив’язана до Safe Bybit (`0x1db9…cf4`) та адрес signer-ів, після чого bundle одразу відновлювався до чистого через дві хвилини після виконання, відтворюючи трюк “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (наприклад, `0x9622…c7242`) містив прості функції `sweepETH/sweepERC20`, а також `transfer(address,uint256)`, яка записувала implementation slot. Виконання `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` змінювало implementation proxy та надавало повний контроль.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: захоплення Delegatecall proxy через колізію слотів

Safe proxies зберігають `masterCopy` у **storage slot 0** і делегують усю логіку йому. Оскільки Safe підтримує **`operation = 1` (delegatecall)**, будь-яка підписана транзакція може вказати на довільний contract і виконати його code у storage context proxy.<sup>[[3]](#references)</sup>

Attacker contract імітував ERC-20 `transfer(address,uint256)`, але натомість записував `_to` у slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Шлях виконання:<sup>[[1]](#references)[[3]](#references)</sup>
1. Victims підписують `execTransaction` з `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy перевіряє підписи для цих параметрів.
3. Proxy виконує delegatecall до `attackerContract`; тіло `transfer` записує значення у slot 0.
4. Slot 0 (`masterCopy`) тепер вказує на логіку, контрольовану attacker → **повний takeover wallet і виведення коштів**.

### Примітки щодо Guard і версій (hardening після інциденту)
- Safes >= v1.3.0 можуть встановити **Guard**, щоб блокувати `delegatecall` або застосовувати ACL до `to`/selectors; Bybit використовував v1.1.1, тому hook для Guard був відсутній. Для отримання цього control plane потрібно оновити контракти (і повторно додати owners).

## Чекліст виявлення та hardening

- **Цілісність UI**: фіксуйте JS assets / SRI; monitor bundle diffs; розглядайте signing UI як частину trust boundary.
- **Валідація під час підписання**: hardware wallets з **EIP-712 clear-signing**; явно відображайте `operation` і декодуйте вкладені calldata. Відхиляйте підписання, коли `operation = 1`, якщо це не дозволено policy.
- **Перевірки hash на стороні сервера**: gateways/services, які relay proposals, мають повторно обчислювати `safeTxHash` і перевіряти, що підписи відповідають надісланим полям.
- **Policy/allowlists**: правила preflight для `to`, selectors, asset types і заборона delegatecall, крім перевірених flows. Перед broadcasting повністю підписаних transactions вимагайте внутрішній policy service.
- **Дизайн контрактів**: уникайте надання довільного delegatecall у multisig/treasury wallets, якщо це не є суворо необхідним. Розміщуйте upgrade pointers подалі від slot 0 або захищайте їх явною upgrade logic і access control.
- **Моніторинг**: надсилайте alert про виконання delegatecall з wallets, що зберігають treasury funds, а також про proposals, у яких `operation` змінюється зі стандартних `call` patterns.

## References

- [1] [Forensic breakdown експлойту Bybit Safe від AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Аналіз compromise Safe bundle від Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Поглиблений технічний аналіз hack Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
