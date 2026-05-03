# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** — це програми, що виконуються на blockchain, коли виконуються певні умови, автоматизуючи виконання угод без посередників.
- **Decentralized Applications (dApps)** будуються на основі smart contracts, мають зручний front-end і прозорий, аудиторний back-end.
- **Tokens & Coins** розрізняються тим, що coins слугують цифровими грошима, тоді як tokens представляють цінність або право власності в конкретних контекстах.
- **Utility Tokens** надають доступ до сервісів, а **Security Tokens** позначають право власності на актив.
- **DeFi** означає Decentralized Finance, пропонуючи фінансові послуги без центральних органів.
- **DEX** і **DAOs** означають Decentralized Exchange Platforms та Decentralized Autonomous Organizations відповідно.

## Consensus Mechanisms

Consensus mechanisms забезпечують безпечну та узгоджену валідацію транзакцій у blockchain:

- **Proof of Work (PoW)** спирається на обчислювальну потужність для верифікації транзакцій.
- **Proof of Stake (PoS)** вимагає, щоб валідатори тримали певну кількість tokens, зменшуючи споживання енергії порівняно з PoW.

## Bitcoin Essentials

### Transactions

Bitcoin transactions передбачають переказ коштів між адресами. Транзакції валідуються через digital signatures, що гарантує, що лише власник private key може ініціювати перекази.

#### Key Components:

- **Multisignature Transactions** вимагають кількох signatures для авторизації transaction.
- Transactions складаються з **inputs** (джерело коштів), **outputs** (призначення), **fees** (сплачуються miners) і **scripts** (правила transaction).

### Lightning Network

Має на меті підвищити масштабованість Bitcoin, дозволяючи виконувати multiple transactions у межах channel, і лише фінальний стан передаючи до blockchain.

## Bitcoin Privacy Concerns

Privacy attacks, такі як **Common Input Ownership** і **UTXO Change Address Detection**, використовують шаблони transactions. Стратегії на кшталт **Mixers** і **CoinJoin** покращують анонімність, приховуючи зв’язки між transactions користувачів.

## Acquiring Bitcoins Anonymously

Способи включають готівкові угоди, mining і використання mixers. **CoinJoin** змішує multiple transactions, ускладнюючи відстеження, тоді як **PayJoin** маскує CoinJoins під звичайні transactions для вищого рівня privacy.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

У світі Bitcoin privacy транзакцій і анонімність користувачів часто є предметом занепокоєння. Ось спрощений огляд кількох поширених методів, за допомогою яких attackers можуть скомпрометувати Bitcoin privacy.

## **Common Input Ownership Assumption**

Зазвичай рідко, коли inputs від різних користувачів об’єднуються в одній transaction через складність цього процесу. Тому **дві input addresses в одній transaction часто вважаються такими, що належать одному й тому самому власнику**.

## **UTXO Change Address Detection**

UTXO, або **Unspent Transaction Output**, має бути повністю витрачений у transaction. Якщо лише частину надіслано на іншу address, решта переходить на нову change address. Спостерігачі можуть припустити, що ця нова address належить відправнику, що компрометує privacy.

### Example

Щоб зменшити це, можуть допомогти mixing services або використання кількох addresses для приховування ownership.

## **Social Networks & Forums Exposure**

Користувачі інколи діляться своїми Bitcoin addresses онлайн, що робить **easy to link the address to its owner**.

## **Transaction Graph Analysis**

Transactions можна візуалізувати як graphs, що виявляє потенційні зв’язки між користувачами на основі руху коштів.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ця heuristic базується на аналізі transactions з кількома inputs і outputs, щоб вгадати, який output є change, що повертається відправнику.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Якщо додавання більшої кількості inputs робить change output більшим за будь-який окремий input, це може заплутати heuristic.

## **Forced Address Reuse**

Attackers можуть надсилати малі суми на вже використані addresses, сподіваючись, що отримувач поєднає їх з іншими inputs у майбутніх transactions, тим самим пов’язуючи addresses між собою.

### Correct Wallet Behavior

Wallets мають уникати використання coins, отриманих на вже використані, порожні addresses, щоб запобігти цьому privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions без change імовірно відбуваються між двома addresses, що належать одному й тому самому user.
- **Round Numbers:** Кругле число в transaction вказує на payment, а не круглий output, імовірно, є change.
- **Wallet Fingerprinting:** Різні wallets мають унікальні patterns створення transactions, що дає analysts змогу визначити використане software і потенційно change address.
- **Amount & Timing Correlations:** Розкриття часу або сум transactions може зробити transactions відстежуваними.

## **Traffic Analysis**

Відстежуючи network traffic, attackers можуть потенційно пов’язати transactions або blocks з IP addresses, компрометуючи user privacy. Це особливо актуально, якщо entity керує багатьма Bitcoin nodes, посилюючи її здатність моніторити transactions.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Отримання bitcoin через cash.
- **Cash Alternatives**: Купівля gift cards і обмін їх онлайн на bitcoin.
- **Mining**: Найбільш приватний method заробити bitcoins — через mining, особливо якщо робити це самостійно, тому що mining pools можуть знати IP address miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Теоретично, крадіжка bitcoin могла б бути іншим method отримати його anonymously, хоча це незаконно і не рекомендується.

## Mixing Services

Using a mixing service, user може **send bitcoins** і отримати **different bitcoins in return**, що ускладнює відстеження original owner. Проте це вимагає довіри до service: він не має зберігати logs і справді повинен повернути bitcoins. Альтернативні mixing options включають Bitcoin casinos.

## CoinJoin

**CoinJoin** об’єднує multiple transactions від different users в одну, ускладнюючи процес для будь-кого, хто намагається зіставити inputs з outputs. Попри свою ефективність, transactions з унікальними input і output sizes усе ще потенційно можна відстежити.

Приклади transactions, що могли використовувати CoinJoin, включають `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` і `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Варіант CoinJoin, **PayJoin** (або P2EP), маскує transaction між двома parties (наприклад, customer і merchant) під звичайну transaction, без характерних однакових outputs, властивих CoinJoin. Це робить її надзвичайно складною для виявлення і може знецінити common-input-ownership heuristic, який використовують transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Транзакції, подібні до наведених вище, можуть бути PayJoin, підвищуючи приватність і водночас залишаючись невідрізнюваними від стандартних bitcoin-транзакцій.

**Використання PayJoin може значно порушити традиційні методи спостереження**, роблячи його перспективною розробкою в прагненні до транзакційної приватності.

# Найкращі практики для приватності в криптовалютах

## **Техніки синхронізації гаманця**

Щоб підтримувати приватність і безпеку, синхронізація гаманців із блокчейном є критично важливою. Вирізняються два методи:

- **Повний вузол**: Завантажуючи весь блокчейн, повний вузол забезпечує максимальну приватність. Усі транзакції, коли-небудь здійснені, зберігаються локально, що унеможливлює для супротивників визначити, якими транзакціями або адресами цікавиться користувач.
- **Фільтрація блоків на боці клієнта**: Цей метод передбачає створення фільтрів для кожного блоку в блокчейні, що дозволяє гаманцям визначати релевантні транзакції без розкриття конкретних інтересів мережевим спостерігачам. Легкі гаманці завантажують ці фільтри, отримуючи повні блоки лише тоді, коли знайдено збіг з адресами користувача.

## **Використання Tor для анонімності**

Оскільки Bitcoin працює в peer-to-peer мережі, рекомендується використовувати Tor, щоб приховати вашу IP-адресу, підвищуючи приватність під час взаємодії з мережею.

## **Запобігання повторному використанню адрес**

Щоб захистити приватність, важливо використовувати нову адресу для кожної транзакції. Повторне використання адрес може скомпрометувати приватність, пов’язуючи транзакції з тією самою сутністю. Сучасні гаманці відмовляють від повторного використання адрес завдяки своїй архітектурі.

## **Стратегії для приватності транзакцій**

- **Кілька транзакцій**: Розділення платежу на кілька транзакцій може приховати суму транзакції, ускладнюючи privacy attacks.
- **Уникнення change**: Вибір транзакцій, які не потребують change outputs, підвищує приватність, порушуючи методи виявлення change.
- **Кілька change outputs**: Якщо уникнути change неможливо, генерація кількох change outputs все ще може покращити приватність.

# **Monero: Маяк анонімності**

Monero задовольняє потребу в абсолютній анонімності в цифрових транзакціях, встановлюючи високий стандарт приватності.

# **Ethereum: Gas і транзакції**

## **Розуміння Gas**

Gas вимірює обчислювальні зусилля, потрібні для виконання операцій в Ethereum, і оцінюється в **gwei**. Наприклад, транзакція, що коштує 2,310,000 gwei (або 0.00231 ETH), включає gas limit і base fee, а також tip для стимулювання miners. Користувачі можуть встановити max fee, щоб не переплатити, а надлишок буде повернено.

## **Виконання транзакцій**

Транзакції в Ethereum включають відправника і одержувача, якими можуть бути адреси користувача або smart contract. Вони потребують fee і мають бути mined. Істотна інформація в транзакції включає одержувача, підпис відправника, value, optional data, gas limit і fees. Важливо, що адреса відправника виводиться з підпису, тому немає потреби включати її в дані транзакції.

Ці практики та механізми є базовими для кожного, хто хоче працювати з криптовалютами, надаючи пріоритет приватності та безпеці.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Коли prover використовує **zkVM** або application-specific proof circuit для підтвердження твердження, verifier дізнається лише те, що **guest program виконалася так, як написано**. Якщо guest містить **unsafe deserialization**, **undefined behavior** або **missing semantic constraints**, зловмисний prover може згенерувати proof, який перевіряється, тоді як **public metrics або claimed invariant є хибними**.

### Unsafe deserialization inside proof guests

- Сприймайте bytes приватного witness/circuit як **недовірений вхід від атакувальника**, навіть якщо їх приховує proof.
- Уникайте десеріалізації за допомогою unchecked helpers, таких як `rkyv::access_unchecked`, якщо bytes не були вже попередньо валідовані поза межами.
- Enum discriminants, relative pointers, lengths і indexes, завантажені з недовірених serialized data, мають бути перевірені перед тим, як вони вплинуть на control flow або memory access.

Практичний шаблон аудиту:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Якщо поле на кшталт `op.kind` є enum і атакер може ввести **discriminant поза діапазоном**, кожен подальший `match` по цьому значенню стає підозрілим.

### Jump-table / UB counter bypass

Якщо Rust зводить великий `match` у **jump table**, невалідний discriminant enum може спричинити **undefined control flow**. Небезпечний шаблон такий:

1. Один `match` оновлює **security-critical counters/constraints**.
2. Другий `match` виконує **реальну семантику інструкції**.
3. Discriminant поза діапазоном індексує за межі першої jump table і потрапляє в код, пов’язаний із другою.

Результат: операція все одно виконується, але шлях обліку пропускається. У zkVM це може підробити proofs, які показують неможливі метрики, як-от менше gates, менше дорогих операцій або інші фальсифіковані bounded resources.

Checklist для перевірки:

- Шукайте enum, контрольовані атакером, десеріалізовані з witness/private input.
- Перевіряйте повторні `match`-вирази над тим самим opcode/kind полем.
- Розглядайте `unsafe` + unchecked deserialization + великий opcode dispatch як високоризикову комбінацію.
- За потреби реверс-інженерте згенерований binary; layout jump-table може мати більше значення, ніж source.

### Missing semantic constraints in reversible/specialized interpreters

Не просто перевіряйте memory safety; також перевіряйте **semantic rules**, які proof має enforce.

Для reversible/quantum-like instruction sets переконайтеся, що операнди, які мають бути різними, справді constrained як різні. Операція на кшталт Toffoli/CCX, реалізована як:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
стає небезпечним, якщо гість не відхиляє:
```text
op.q_control1 == op.q_control2 == op.q_target
```
У такому випадку перехід зводиться до:
```text
q = q ^ (q & q) = 0
```
Це створює **deterministic reset primitive**, ламаючи припущення про оборотність і даючи змогу виконувати дешевші ненавмисні обчислення. У proof systems, що підтверджують використання ресурсів, це може дозволити атакувальникам проходити функціональні перевірки, водночас обходячи cost model, який, як вважає verifier, застосовується.

### Що тестувати в ZK systems

- Fuzz усі guest parsers із malformed witness/private-input encodings.
- Перевіряйте validation діапазону enum перед opcode dispatch.
- Додавайте semantic checks для operand aliasing та інших invalid instruction forms.
- Порівнюйте reported/public counters з незалежною reference implementation.
- Пам’ятайте, що valid proof усе ще може доводити **wrong statement**, якщо guest program має bug.

## DeFi/AMM Exploitation

Якщо ви досліджуєте практичну exploitation DEXes і AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), дивіться:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Для multi-asset weighted pools, що кешують virtual balances і можуть бути poisoned, коли `supply == 0`, вивчіть:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
