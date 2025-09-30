# Блокчейн та криптовалюти

{{#include ../../banners/hacktricks-training.md}}

## Базові поняття

- **Smart Contracts** визначаються як програми, що виконуються на блокчейні за настання певних умов, автоматизуючи виконання угод без посередників.
- **Decentralized Applications (dApps)** базуються на смарт-контрактах, мають зручний для користувача front-end та прозорий, підлягаючий аудиту back-end.
- **Tokens & Coins** різняться тим, що монети виконують роль цифрових грошей, тоді як токени представляють вартість або право власності в конкретних контекстах.
- **Utility Tokens** надають доступ до сервісів, а **Security Tokens** означають право власності на активи.
- **DeFi** означає Decentralized Finance, що пропонує фінансові послуги без центральних органів.
- **DEX** та **DAOs** позначають відповідно Decentralized Exchange Platforms та Decentralized Autonomous Organizations.

## Механізми консенсусу

Механізми консенсусу забезпечують безпечну та погоджену валідацію транзакцій у блокчейні:

- **Proof of Work (PoW)** покладається на обчислювальну потужність для верифікації транзакцій.
- **Proof of Stake (PoS)** вимагає від валідаторів тримати певну кількість токенів, зменшуючи енергоспоживання порівняно з PoW.

## Основи Bitcoin

### Транзакції

Транзакції Bitcoin передбачають передачу коштів між адресами. Транзакції валідуються за допомогою цифрових підписів, що гарантує, що лише власник приватного ключа може ініціювати перекази.

#### Ключові компоненти:

- **Multisignature Transactions** вимагають кількох підписів для авторизації транзакції.
- Транзакції складаються з **inputs** (джерело коштів), **outputs** (одержувач), **fees** (сплачені майнерам) та **scripts** (правила транзакції).

### Lightning Network

Має на меті підвищити масштабованість Bitcoin, дозволяючи виконувати кілька транзакцій у межах каналу й передавати в блокчейн лише кінцевий стан.

## Проблеми конфіденційності Bitcoin

Атаки на приватність, такі як **Common Input Ownership** та **UTXO Change Address Detection**, використовують закономірності транзакцій. Стратегії на кшталт **Mixers** та **CoinJoin** підвищують анонімність, затемнюючи зв'язки транзакцій між користувачами.

## Анонімне придбання Bitcoin

Методи включають обмін готівкою, майнінг та використання mixers. **CoinJoin** змішує кілька транзакцій, ускладнюючи трасування, тоді як **PayJoin** маскує CoinJoin як звичайні транзакції для посилення приватності.

# Атаки на приватність Bitcoin

# Короткий огляд атак на приватність Bitcoin

У світі Bitcoin приватність транзакцій і анонімність користувачів часто викликають занепокоєння. Ось спрощений огляд кількох поширених методів, якими зловмисники можуть підірвати приватність у Bitcoin.

## **Common Input Ownership Assumption**

Зазвичай рідко коли inputs від різних користувачів комбінуються в одній транзакції через пов'язану складність. Тому **дві адреси-входи в одній транзакції часто припускають, що належать одному власнику**.

## **UTXO Change Address Detection**

UTXO, або **Unspent Transaction Output**, має бути повністю витраченою в транзакції. Якщо відправляється лише частина, залишок надсилається на нову change-адресу. Спостерігачі можуть припустити, що ця нова адреса належить відправнику, що підриває приватність.

### Приклад

Щоб пом'якшити це, служби змішування або використання кількох адрес можуть допомогти затемнити право власності.

## **Social Networks & Forums Exposure**

Користувачі іноді публікують свої адреси Bitcoin онлайн, що робить **легким зв'язати адресу з її власником**.

## **Transaction Graph Analysis**

Транзакції можна візуалізувати у вигляді графів, що виявляє потенційні зв'язки між користувачами на основі потоків коштів.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Цей евристичний підхід ґрунтується на аналізі транзакцій з кількома inputs та outputs, щоб вгадати, який output є рештою (change), що повертається відправнику.

### Приклад
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Примусове повторне використання адрес**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Правильна поведінка гаманця

Wallets should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **Інші техніки аналізу блокчейну**

- **Exact Payment Amounts:** Транзакції без change, ймовірно, між двома адресами, які належать одному користувачеві.
- **Round Numbers:** Кругле число в транзакції свідчить про те, що це платіж, а некруглий вихід, швидше за все, є change.
- **Wallet Fingerprinting:** Різні гаманці мають унікальні шаблони створення транзакцій, що дозволяє аналітикам ідентифікувати використане ПО і, можливо, адресу change.
- **Amount & Timing Correlations:** Розкриття часу або сум транзакцій може зробити їх простежуваними.

## **Аналіз трафіку**

By monitoring network traffic, attackers can potentially link transactions or blocks to IP addresses, compromising user privacy. This is especially true if an entity operates many Bitcoin nodes, enhancing their ability to monitor transactions.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquiring bitcoin through cash.
- **Cash Alternatives**: Purchasing gift cards and exchanging them online for bitcoin.
- **Mining**: The most private method to earn bitcoins is through mining, especially when done alone because mining pools may know the miner's IP address. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretically, stealing bitcoin could be another method to acquire it anonymously, although it's illegal and not recommended.

## Mixing Services

By using a mixing service, a user can **send bitcoins** and receive **different bitcoins in return**, which makes tracing the original owner difficult. Yet, this requires trust in the service not to keep logs and to actually return the bitcoins. Alternative mixing options include Bitcoin casinos.

## CoinJoin

**CoinJoin** merges multiple transactions from different users into one, complicating the process for anyone trying to match inputs with outputs. Despite its effectiveness, transactions with unique input and output sizes can still potentially be traced.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Транзакції, подібні до наведених вище, можуть бути PayJoin, що підвищує конфіденційність, залишаючись невідрізненними від стандартних bitcoin-транзакцій.

**Використання PayJoin може суттєво підірвати традиційні методи спостереження**, роблячи його перспективним кроком у прагненні до приватності транзакцій.

# Кращі практики конфіденційності у криптовалютах

## **Техніки синхронізації гаманців**

Щоб підтримувати конфіденційність і безпеку, синхронізація гаманців з блокчейном є критично важливою. Виділяються два методи:

- **Full node**: Завантажуючи весь блокчейн, full node забезпечує максимальну конфіденційність. Всі транзакції зберігаються локально, що унеможливлює для супротивника визначити, які саме транзакції або адреси цікавлять користувача.
- **Client-side block filtering**: Цей метод передбачає створення фільтрів для кожного блоку в блокчейні, дозволяючи гаманцям ідентифікувати релевантні транзакції без розкриття конкретних інтересів спостерігачам мережі. Легковісні гаманці завантажують ці фільтри, отримуючи повні блоки лише коли знаходять співпадіння з адресами користувача.

## **Використання Tor для анонімності**

Оскільки Bitcoin працює в peer-to-peer мережі, рекомендується використовувати Tor для приховування вашої IP-адреси, що підвищує приватність під час взаємодії з мережею.

## **Запобігання повторного використання адрес**

Щоб захистити приватність, важливо використовувати нову адресу для кожної транзакції. Повторне використання адрес може скомпрометувати приватність, пов’язавши транзакції з тією самою сутністю. Сучасні гаманці відвертають від повторного використання адрес через свій дизайн.

## **Стратегії приватності транзакцій**

- **Multiple transactions**: Розбивка платежу на кілька транзакцій може затемнити суму платежу, ускладнюючи атаки на приватність.
- **Change avoidance**: Вибір транзакцій, які не вимагають change-outputs, підвищує приватність, порушуючи методи виявлення зміни.
- **Multiple change outputs**: Якщо уникнути change не вдається, генерація кількох change-outputs може все ж покращити приватність.

# **Monero: маяк анонімності**

Monero вирішує потребу абсолютної анонімності в цифрових транзакціях, встановлюючи високий стандарт приватності.

# **Ethereum: Gas і транзакції**

## **Розуміння Gas**

Gas вимірює обчислювальні зусилля, необхідні для виконання операцій в Ethereum, ціною в **gwei**. Наприклад, транзакція вартістю 2,310,000 gwei (або 0.00231 ETH) включає gas limit і base fee, а також tip для стимулювання майнерів. Користувачі можуть встановити max fee, щоб уникнути переплат, при цьому надлишок повертається.

## **Виконання транзакцій**

Транзакції в Ethereum включають відправника та отримувача, які можуть бути як користувацькими, так і smart contract адресами. Вони потребують плати та мають бути замайнені. Необхідна інформація в транзакції включає отримувача, підпис відправника, значення, опціональні дані, gas limit та збори. Зауважте, що адреса відправника виводиться з підпису, тому її не потрібно вказувати в даних транзакції.

Ці практики та механізми є основою для будь-кого, хто прагне взаємодіяти з криптовалютами, віддаючи пріоритет приватності та безпеці.

## Безпека смарт-контрактів

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Джерела

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

Якщо ви досліджуєте практичну експлуатацію DEXes і AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), перегляньте:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
