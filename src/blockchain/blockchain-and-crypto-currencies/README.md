# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** are defined as programs that execute on a blockchain when certain conditions are met, automating agreement executions without intermediaries.
- **Decentralized Applications (dApps)** build upon smart contracts, featuring a user-friendly front-end and a transparent, auditable back-end.
- **Tokens & Coins** differentiate where coins serve as digital money, while tokens represent value or ownership in specific contexts.
- **Utility Tokens** grant access to services, and **Security Tokens** signify asset ownership.
- **DeFi** stands for Decentralized Finance, offering financial services without central authorities.
- **DEX** and **DAOs** refer to Decentralized Exchange Platforms and Decentralized Autonomous Organizations, respectively.

## Consensus Mechanisms

Consensus mechanisms ensure secure and agreed transaction validations on the blockchain:

- **Proof of Work (PoW)** relies on computational power for transaction verification.
- **Proof of Stake (PoS)** demands validators to hold a certain amount of tokens, reducing energy consumption compared to PoW.

## Bitcoin Essentials

### Transactions

Bitcoin transactions involve transferring funds between addresses. Transactions are validated through digital signatures, ensuring only the owner of the private key can initiate transfers.

#### Key Components:

- **Multisignature Transactions** require multiple signatures to authorize a transaction.
- Transactions consist of **inputs** (source of funds), **outputs** (destination), **fees** (paid to miners), and **scripts** (transaction rules).

### Lightning Network

Aims to enhance Bitcoin's scalability by allowing multiple transactions within a channel, only broadcasting the final state to the blockchain.

## Bitcoin Privacy Concerns

Privacy attacks, such as **Common Input Ownership** and **UTXO Change Address Detection**, exploit transaction patterns. Strategies like **Mixers** and **CoinJoin** improve anonymity by obscuring transaction links between users.

## Acquiring Bitcoins Anonymously

Methods include cash trades, mining, and using mixers. **CoinJoin** mixes multiple transactions to complicate traceability, while **PayJoin** disguises CoinJoins as regular transactions for heightened privacy.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

In the world of Bitcoin, the privacy of transactions and the anonymity of users are often subjects of concern. Here's a simplified overview of several common methods through which attackers can compromise Bitcoin privacy.

## **Common Input Ownership Assumption**

It is generally rare for inputs from different users to be combined in a single transaction due to the complexity involved. Thus, **two input addresses in the same transaction are often assumed to belong to the same owner**.

## **UTXO Change Address Detection**

A UTXO, or **Unspent Transaction Output**, must be entirely spent in a transaction. If only a part of it is sent to another address, the remainder goes to a new change address. Observers can assume this new address belongs to the sender, compromising privacy.

### Example

To mitigate this, mixing services or using multiple addresses can help obscure ownership.

## **Social Networks & Forums Exposure**

Users sometimes share their Bitcoin addresses online, making it **easy to link the address to its owner**.

## **Transaction Graph Analysis**

Transactions can be visualized as graphs, revealing potential connections between users based on the flow of funds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

This heuristic is based on analyzing transactions with multiple inputs and outputs to guess which output is the change returning to the sender.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Якщо додавання більшої кількості входів робить вихідну суму більшою, ніж будь-який окремий вхід, це може збити евристику.

## **Forced Address Reuse**

Зловмисники можуть надсилати невеликі суми на раніше використані адреси в надії, що отримувач об’єднає їх з іншими входами в майбутніх транзакціях, тим самим пов’язавши адреси між собою.

### Correct Wallet Behavior

Гаманці повинні уникати використання монет, отриманих на вже використані, порожні адреси, щоб запобігти цьому privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Транзакції без решти (change) ймовірно відбуваються між двома адресами, що належать одному користувачу.
- **Round Numbers:** Кругле число в транзакції натякає на платіж, де некруглий вихід ймовірно є change.
- **Wallet Fingerprinting:** Різні гаманці мають унікальні патерни створення транзакцій, що дозволяє аналітикам ідентифікувати використане програмне забезпечення і потенційно change-адресу.
- **Amount & Timing Correlations:** Розкриття часу чи сум транзакцій може зробити транзакції відстежуваними.

## **Traffic Analysis**

Спостерігаючи мережевий трафік, зловмисники можуть потенційно пов’язати транзакції або блоки з IP-адресами, підриваючи приватність користувачів. Це особливо актуально, якщо якась сутність керує великою кількістю Bitcoin-вузлів, що підвищує її здатність моніторити транзакції.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Придбання bitcoin за готівку.
- **Cash Alternatives**: Купівля подарункових карт і обмін їх в інтернеті на bitcoin.
- **Mining**: Найприватніший спосіб здобувати bitcoins — майнінг, особливо коли ви майните самостійно, бо в майнінгових пулах можуть знати IP-адресу майнера. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Теоретично крадіжка bitcoin також може бути методом отримання анонімних коштів, але це незаконно і не рекомендовано.

## Mixing Services

Використовуючи mixing service, користувач може **надіслати bitcoins** і отримати **інші bitcoins натомість**, що ускладнює відстеження початкового власника. Проте це вимагає довіри до сервісу, що він не зберігає логи і дійсно поверне bitcoins. Альтернативою є Bitcoin-казино.

## CoinJoin

**CoinJoin** об’єднує кілька транзакцій від різних користувачів в одну, ускладнюючи зіставлення входів і виходів. Незважаючи на ефективність, транзакції з унікальними розмірами входів і виходів все ще можуть бути простежені.

Приклади транзакцій, які могли використати CoinJoin: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` та `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Варіант CoinJoin, **PayJoin** (або P2EP), маскує транзакцію між двома сторонами (наприклад, покупцем і продавцем) як звичайну транзакцію, без характерних рівних виходів CoinJoin. Це робить його вкрай важко виявити і може знецінити евристику common-input-ownership, яку використовують служби моніторингу транзакцій.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Транзакції, як-от наведені вище, можуть бути PayJoin, що підвищує приватність, залишаючись невиразними серед стандартних bitcoin транзакцій.

**Використання PayJoin може суттєво порушити традиційні методи нагляду**, роблячи його перспективним напрямом у прагненні до приватності транзакцій.

# Кращі практики щодо приватності в криптовалютах

## **Техніки синхронізації гаманців**

Щоб зберегти приватність і безпеку, синхронізація гаманців з блокчейном є критичною. Виділяються два методи:

- **Full node**: Завантажуючи весь блокчейн, full node забезпечує максимальну приватність. Всі здійснені транзакції зберігаються локально, що унеможливлює для супротивників визначити, які саме транзакції або адреси цікавлять користувача.
- **Client-side block filtering**: Цей метод передбачає створення фільтрів для кожного блоку в блокчейні, дозволяючи гаманцям ідентифікувати релевантні транзакції без розкриття конкретних інтересів мережевим спостерігачам. Легкі гаманці завантажують ці фільтри і витягують повні блоки лише коли знаходять співпадіння з адресами користувача.

## **Використання Tor для анонімності**

Оскільки Bitcoin працює в піринговій мережі, рекомендується використовувати Tor для маскування вашої IP-адреси, що підвищує приватність під час взаємодії з мережею.

## **Запобігання повторному використанню адрес**

Щоб захистити приватність, важливо використовувати нову адресу для кожної транзакції. Повторне використання адрес може скомпрометувати приватність, пов’язуючи транзакції з одним і тим же суб’єктом. Сучасні гаманці проектуються таким чином, щоб відмовляти користувачів від повторного використання адрес.

## **Стратегії для приватності транзакцій**

- **Кілька транзакцій**: Розбивка платежу на кілька транзакцій може приховати суму платежу, ускладнюючи атаки на приватність.
- **Уникнення здачі**: Вибір транзакцій, які не потребують виходів здачі, підвищує приватність, порушуючи методи виявлення здачі.
- **Кілька виходів здачі**: Якщо уникнути здачі неможливо, генерація кількох виходів здачі все одно може покращити приватність.

# **Monero: Маяк анонімності**

Monero відповідає на потребу абсолютної анонімності в цифрових транзакціях, встановлюючи високий стандарт приватності.

# **Ethereum: Gas та транзакції**

## **Розуміння Gas**

Gas вимірює обчислювальні зусилля, необхідні для виконання операцій в Ethereum, ціною в **gwei**. Наприклад, транзакція вартістю 2,310,000 gwei (або 0.00231 ETH) включає gas limit і базовий збір, а також підказку (tip) для мотивації майнерів. Користувачі можуть встановити максимальний збір, щоб не переплачувати, надлишок повертається.

## **Виконання транзакцій**

Транзакції в Ethereum включають відправника і отримувача, які можуть бути як користувацькими, так і адресами смарт-контрактів. Вони потребують збору і мають бути замайнені. Основна інформація в транзакції включає отримувача, підпис відправника, суму, опціональні дані, gas limit і збори. Варто зазначити, що адреса відправника виводиться з підпису, тому її не потрібно вказувати у даних транзакції.

Ці практики та механізми є основою для кожного, хто прагне працювати з криптовалютами, надаючи пріоритет приватності та безпеці.

## Безпека смарт-контрактів

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

## Експлуатація DeFi/AMM

Якщо ви досліджуєте практичну експлуатацію DEXes і AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), перегляньте:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Для multi-asset weighted pools, що кешують віртуальні баланси і можуть бути отруєні коли `supply == 0`, вивчіть:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
