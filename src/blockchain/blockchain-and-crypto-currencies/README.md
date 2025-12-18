# Блокчейн та криптовалюти

{{#include ../../banners/hacktricks-training.md}}

## Базові поняття

- **Smart Contracts** визначаються як програми, що виконуються в блокчейні, коли виконуються певні умови, автоматизуючи виконання угод без посередників.
- **Decentralized Applications (dApps)** будуються на основі smart contracts, маючи зручний для користувача фронтенд та прозорий, перевіряємий бекенд.
- **Tokens & Coins** відрізняються тим, що coins слугують цифровими грошима, тоді як токени представляють вартість або право власності в певних контекстах.
- **Utility Tokens** дають доступ до сервісів, а **Security Tokens** означають право власності на актив.
- **DeFi** означає Decentralized Finance — надання фінансових послуг без центральних органів.
- **DEX** та **DAOs** відповідно означають Decentralized Exchange Platforms та Decentralized Autonomous Organizations.

## Механізми консенсусу

Механізми консенсусу забезпечують безпечну та узгоджену валідацію транзакцій у блокчейні:

- **Proof of Work (PoW)** покладається на обчислювальну потужність для верифікації транзакцій.
- **Proof of Stake (PoS)** вимагає від валідаторів утримувати певну кількість токенів, зменшуючи енергоспоживання порівняно з PoW.

## Основи Bitcoin

### Транзакції

Транзакції в Bitcoin передбачають передачу коштів між адресами. Транзакції верифікуються за допомогою цифрових підписів, що забезпечує можливість ініціювати переказ лише власнику приватного ключа.

#### Ключові компоненти:

- **Multisignature Transactions** вимагають кількох підписів для авторизації транзакції.
- Транзакції складаються з **inputs** (джерело коштів), **outputs** (призначення), **fees** (сплачені майнерам) та **scripts** (правила транзакції).

### Lightning Network

Метою є підвищити масштабованість Bitcoin, дозволяючи багатьом транзакціям відбуватися в межах каналу, при цьому в блокчейн публікується лише фінальний стан.

## Проблеми приватності в Bitcoin

Атаки на приватність, такі як **Common Input Ownership** та **UTXO Change Address Detection**, експлуатують патерни транзакцій. Стратегії на кшталт **Mixers** та **CoinJoin** покращують анонімність, приховуючи зв’язки транзакцій між користувачами.

## Анонімне придбання Bitcoin

Методи включають обмін готівкою, майнінг та використання mixers. **CoinJoin** змішує кілька транзакцій, ускладнюючи трасування, тоді як **PayJoin** маскує CoinJoins під звичайні транзакції для підвищеної приватності.

# Bitcoin Privacy Atacks

# Підсумок атак на приватність в Bitcoin

У світі Bitcoin приватність транзакцій і анонімність користувачів часто є проблемними. Нижче спрощений огляд кількох поширених методів, якими нападники можуть компрометувати приватність у Bitcoin.

## **Common Input Ownership Assumption**

Зазвичай рідко коли inputs від різних користувачів комбінуються в одній транзакції через складність цього процесу. Тому **два input-адреси в одній транзакції часто припускають належність одному власнику**.

## **UTXO Change Address Detection**

UTXO, або **Unspent Transaction Output**, має бути повністю витрачений у транзакції. Якщо відправляється лише частина, решта йде на нову change-адресу. Спостерігачі можуть припустити, що ця нова адреса належить відправнику, що порушує приватність.

### Приклад

Для пом'якшення цього можна використовувати mixing-сервіси або кілька адрес, щоб ускладнити визначення власника.

## **Соціальні мережі та форуми**

Користувачі іноді публікують свої Bitcoin-адреси онлайн, що робить **легким прив'язати адресу до її власника**.

## **Аналіз графа транзакцій**

Транзакції можна візуалізувати як графи, що розкривають потенційні зв’язки між користувачами на основі потоку коштів.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Цей евристичний підхід заснований на аналізі транзакцій з кількома inputs та outputs, щоб вгадати, який output є change, що повертається відправнику.

### Приклад
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Якщо додавання додаткових входів робить вихід для здачі більшим за будь-який окремий вхід, це може ввести евристику в оману.

## **Forced Address Reuse**

Атакуючі можуть відправляти невеликі суми на вже використані адреси, сподіваючись, що одержувач у майбутніх транзакціях поєднає їх з іншими входами, тим самим пов'язавши адреси між собою.

### Correct Wallet Behavior

Гаманці повинні уникати використання монет, отриманих на вже використані, порожні адреси, щоб запобігти цьому privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Транзакції без здачі, ймовірно, відбуваються між двома адресами, що належать одному користувачу.
- **Round Numbers:** Кругла сума в транзакції вказує на оплату, а неокруглий вихід, ймовірно, є здачею.
- **Wallet Fingerprinting:** Різні гаманці мають унікальні шаблони створення транзакцій, що дозволяє аналітикам виявляти використане програмне забезпечення і потенційно адресу здачі.
- **Amount & Timing Correlations:** Розкриття часу або сум транзакцій може зробити їх простежуваними.

## **Traffic Analysis**

Моніторячи мережевий трафік, атакуючі потенційно можуть пов'язати транзакції чи блоки з IP-адресами, підриваючи приватність користувачів. Це особливо актуально, якщо організація оперує багатьма Bitcoin nodes, що підвищує її можливості моніторити транзакції.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Анонімні транзакції Bitcoin

## Способи отримання Bitcoin анонімно

- **Cash Transactions**: Придбання Bitcoin за готівку.
- **Cash Alternatives**: Купівля подарункових карток та обмін їх онлайн на Bitcoin.
- **Mining**: Найприватніший метод заробітку Bitcoin — майнінг, особливо у соло-режимі, оскільки mining pools можуть знати IP-адресу майнера. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Теоретично, крадіжка Bitcoin може бути ще одним способом отримати їх анонімно, хоча це незаконно і не рекомендовано.

## Mixing Services

Використовуючи сервіс змішування, користувач може **відправити Bitcoin** і отримати **інші Bitcoin натомість**, що ускладнює відстежування початкового власника. Однак це потребує довіри до сервісу, що він не веде логи і дійсно поверне Bitcoin. Альтернативні варіанти змішування включають Bitcoin-казино.

## CoinJoin

**CoinJoin** об'єднує кілька транзакцій від різних користувачів в одну, ускладнюючи зіставлення входів з виходами. Незважаючи на ефективність, транзакції з унікальними розмірами входів і виходів все ще можуть бути простежені.

Прикладами транзакцій, що могли використовувати CoinJoin, є `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` та `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# Найкращі практики для приватності в криптовалютах

## **Техніки синхронізації гаманців**

Для збереження приватності та безпеки синхронізація гаманців з блокчейном є критичною. Виділяються два методи:

- Full node: Завантажуючи весь блокчейн, full node забезпечує максимальну приватність. Всі транзакції зберігаються локально, ускладнюючи завдання супротивника щодо визначення, які саме транзакції або адреси цікавлять користувача.
- Client-side block filtering: Цей метод передбачає створення фільтрів для кожного блоку в блокчейні, що дозволяє гаманцям виявляти релевантні транзакції, не розкриваючи конкретних інтересів спостерігачам мережі. Легкі гаманці завантажують ці фільтри і запитують повні блоки лише тоді, коли знайдено співпадіння з адресами користувача.

## **Використання Tor для анонімності**

Оскільки Bitcoin працює в peer-to-peer мережі, рекомендовано використовувати Tor для приховування IP-адреси та підвищення приватності при взаємодії з мережею.

## **Запобігання повторному використанню адрес**

Щоб захистити приватність, важливо використовувати нову адресу для кожної транзакції. Повторне використання адрес може скомпрометувати приватність, пов’язуючи транзакції з одним і тим же суб’єктом. Сучасні гаманці відмовляють від повторного використання адрес у своїх дизайнах.

## **Стратегії для приватності транзакцій**

- Кілька транзакцій: Розбивка платежу на кілька транзакцій може ускладнити визначення суми транзакції та зірвати атаки на приватність.
- Уникнення виходів здачі: Вибір транзакцій, які не потребують виходів здачі, підвищує приватність, порушуючи методи виявлення здачі.
- Кілька виходів здачі: Якщо уникнути здачі неможливо, створення кількох виходів здачі все одно покращує приватність.

# **Monero: маяк анонімності**

Monero вирішує потребу в абсолютній анонімності цифрових транзакцій, встановлюючи високий стандарт приватності.

# **Ethereum: Gas та транзакції**

## **Розуміння Gas**

Gas вимірює обчислювальні зусилля, необхідні для виконання операцій в Ethereum, його вартість задається в **gwei**. Наприклад, транзакція вартістю 2,310,000 gwei (або 0.00231 ETH) включає gas limit і базову плату, з додатковою tip для стимулювання майнерів. Користувачі можуть встановити max fee, щоб не переплатити; надлишок повертається.

## **Виконання транзакцій**

Транзакції в Ethereum мають відправника і отримувача, які можуть бути як користувацькими, так і smart contract адресами. Вони потребують оплати збору і повинні бути замайнені. Основна інформація в транзакції включає отримувача, підпис відправника, value, опціональні дані, gas limit та збори. Зауважте, що адреса відправника виводиться з підпису, тому її не потрібно включати в дані транзакції.

Ці практики та механізми є базовими для кожного, хто прагне працювати з криптовалютами з орієнтацією на приватність і безпеку.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Посилання

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
