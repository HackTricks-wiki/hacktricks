# Блокчейн та Криптовalюти

{{#include ../../banners/hacktricks-training.md}}

## Основні поняття

- **Smart Contracts** визначаються як програми, що виконуються на блокчейні при виконанні певних умов, автоматизуючи виконання угод без посередників.
- **Decentralized Applications (dApps)** будуються на основі смарт-контрактів, мають дружній для користувача front-end і прозорий, піддаваний аудиту back-end.
- **Tokens & Coins** відрізняються тим, що coins слугують цифровими грошима, тоді як tokens уособлюють цінність або право власності в конкретних контекстах.
- **Utility Tokens** надають доступ до сервісів, а **Security Tokens** позначають право власності на активи.
- **DeFi** означає Decentralized Finance, що надає фінансові послуги без центральних органів.
- **DEX** та **DAOs** відповідно позначають Decentralized Exchange Platforms і Decentralized Autonomous Organizations.

## Механізми консенсусу

Механізми консенсусу забезпечують безпечну та узгоджену валідацію транзакцій у блокчейні:

- **Proof of Work (PoW)** покладається на обчислювальну потужність для перевірки транзакцій.
- **Proof of Stake (PoS)** вимагає від валідаторів утримувати певну кількість токенів, знижуючи енергоспоживання у порівнянні з PoW.

## Основи Bitcoin

### Транзакції

Транзакції Bitcoin включають переведення коштів між адресами. Транзакції підтверджуються цифровими підписами, що гарантує, що лише власник приватного ключа може ініціювати перекази.

#### Ключові компоненти:

- **Multisignature Transactions** вимагають кількох підписів для авторизації транзакції.
- Транзакції складаються з **inputs** (джерело коштів), **outputs** (призначення), **fees** (сплачуються miners) і **scripts** (правила транзакції).

### Lightning Network

Має на меті покращити масштабованість Bitcoin, дозволяючи проводити багато транзакцій у межах каналу й тільки публікувати кінцевий стан у блокчейн.

## Проблеми конфіденційності Bitcoin

Атаки на конфіденційність, такі як **Common Input Ownership** і **UTXO Change Address Detection**, експлуатують шаблони транзакцій. Стратегії на кшталт **Mixers** і **CoinJoin** підвищують анонімність, затемнюючи зв'язки між транзакціями користувачів.

## Анонімне придбання Bitcoin

Методи включають готівкові угоди, майнінг і використання mixers. **CoinJoin** змішує кілька транзакцій, ускладнюючи трасування, тоді як **PayJoin** маскує CoinJoin як звичайні транзакції для підвищення приватності.

# Bitcoin Privacy Atacks

# Підсумок атак на конфіденційність Bitcoin

У світі Bitcoin конфіденційність транзакцій і анонімність користувачів часто викликають занепокоєння. Нижче спрощений огляд кількох поширених методів, якими нападники можуть скомпрометувати приватність Bitcoin.

## **Common Input Ownership Assumption**

Зазвичай рідко трапляється, що inputs від різних користувачів поєднуються в одній транзакції через складність процесу. Тому **два input-адреси в одній транзакції часто вважаються належними одному й тому ж власнику**.

## **UTXO Change Address Detection**

UTXO, або **Unspent Transaction Output**, має бути витрачений повністю в транзакції. Якщо відправляється лише частина, решта повертається на нову change-адресу. Спостерігачі можуть припустити, що ця нова адреса належить відправникові, що ставить під загрозу приватність.

### Приклад

Щоб зменшити це, сервіси mixing або використання кількох адрес можуть допомогти затемнити власність.

## **Social Networks & Forums Exposure**

Користувачі іноді публічно діляться своїми Bitcoin-адресами, що робить **легким прив'язати адресу до її власника**.

## **Transaction Graph Analysis**

Транзакції можна візуалізувати як графи, що виявляє потенційні зв'язки між користувачами на основі потоків коштів.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Цей евристичний підхід базується на аналізі транзакцій із кількома inputs та outputs, щоб вгадати, який output є change, що повертається відправникові.

### Приклад
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior

Wallets should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Транзакції без change ймовірно відбуваються між двома адресами, що належать одному користувачу.
- **Round Numbers:** Кругла сума в транзакції натякає, що це платіж, а не-круглий вихід швидше за все є change.
- **Wallet Fingerprinting:** Різні wallets мають унікальні патерни створення транзакцій, що дозволяє аналітикам ідентифікувати використане програмне забезпечення та потенційно change address.
- **Amount & Timing Correlations:** Розкриття часу або сум транзакцій може зробити їх відстежуваними.

## **Traffic Analysis**

Моніторинг мережевого трафіку може дозволити атакам пов’язати транзакції або блоки з IP-адресами, компрометуючи конфіденційність користувачів. Це особливо справедливо, якщо якась організація оперує багатьма Bitcoin nodes, що підвищує їхню здатність відстежувати транзакції.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Придбання bitcoin за готівку.
- **Cash Alternatives**: Купівля подарункових карток і обмін їх онлайн на bitcoin.
- **Mining**: Найприватніший спосіб заробити bitcoins — майнінг, особливо в одиночку, оскільки mining pools можуть знати IP-адресу майнера. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Теоретично, крадіжка bitcoin також могла б бути способом придбати їх анонімно, хоча це незаконно і не рекомендовано.

## Mixing Services

Використовуючи mixing service, користувач може **відправити bitcoins** і отримати **інші bitcoins натомість**, що ускладнює відстеження початкового власника. Однак це вимагає довіри до сервісу, що він не зберігає логи і дійсно повертає bitcoins. Альтернативою mixing можуть бути Bitcoin casinos.

## CoinJoin

CoinJoin об’єднує кілька транзакцій від різних користувачів в одну, ускладнюючи для сторонніх зіставлення inputs з outputs. Незважаючи на ефективність, транзакції з унікальними розмірами inputs та outputs все ще можуть бути простежені.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), маскує транзакцію між двома сторонами (наприклад, клієнтом і продавцем) як звичайну транзакцію, без характерних однакових виходів, властивих CoinJoin. Це робить її виявлення дуже складним і може знецінити common-input-ownership heuristic, яку використовують сервіси моніторингу транзакцій.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Транзакції, подібні до наведених вище, можуть бути PayJoin, що підвищує конфіденційність і при цьому залишається невідрізненним від стандартних Bitcoin-транзакцій.

**Використання PayJoin може суттєво порушити традиційні методи спостереження**, роблячи його перспективним у розвитку транзакційної приватності.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Щоб підтримувати конфіденційність та безпеку, синхронізація гаманців із блокчейном є критичною. Виділяються два методи:

- **Full node**: Завантажуючи весь блокчейн, full node забезпечує максимальну приватність. Всі коли-небудь здійснені транзакції зберігаються локально, що унеможливлює для противників визначити, які саме транзакції чи адреси цікавлять користувача.
- **Client-side block filtering**: Цей метод передбачає створення фільтрів для кожного блоку в блокчейні, що дозволяє гаманцям ідентифікувати релевантні транзакції без розкриття конкретних інтересів спостерігачам мережі. Легкі гаманці завантажують ці фільтри і завантажують повні блоки лише коли знаходять співпадіння з адресами користувача.

## **Utilizing Tor for Anonymity**

Оскільки Bitcoin працює в peer-to-peer мережі, рекомендується використовувати Tor для приховування вашої IP-адреси, підвищуючи приватність при взаємодії з мережею.

## **Preventing Address Reuse**

Щоб захистити приватність, важливо використовувати нову адресу для кожної транзакції. Повторне використання адрес може скомпрометувати приватність, пов’язавши транзакції з однією сутністю. Сучасні гаманці відмовляються від повторного використання адрес через їхній дизайн.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Розбивка платежу на кілька транзакцій може ускладнити визначення суми транзакції, зірвавши атаки на приватність.
- **Change avoidance**: Вибір транзакцій, що не потребують change outputs, підвищує приватність, порушуючи методи виявлення зміни.
- **Multiple change outputs**: Якщо уникнути change неможливо, генерація кількох change outputs також може покращити приватність.

# **Monero: A Beacon of Anonymity**

Monero відповідає на потребу в абсолютній анонімності в цифрових транзакціях, встановлюючи високі стандарти приватності.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas вимірює обчислювальні зусилля, необхідні для виконання операцій в Ethereum, і ціниться в **gwei**. Наприклад, транзакція вартістю 2,310,000 gwei (або 0.00231 ETH) включає gas limit і базову плату, з підказкою (tip) для стимулювання майнерів. Користувачі можуть встановити max fee, щоб не переплачувати; надлишок повертається.

## **Executing Transactions**

Транзакції в Ethereum включають відправника і одержувача, якими можуть бути як користувацькі, так і smart contract адреси. Вони вимагають комісію і мають бути замайнені. Основна інформація в транзакції включає одержувача, підпис відправника, value, опціональні data, gas limit та fees. Зауважте, що адреса відправника виводиться з підпису, тому в самих даних транзакції вона не потрібна.

Ці практики та механізми є основою для будь-кого, хто хоче взаємодіяти з криптовалютами, віддаючи пріоритет приватності та безпеці.

## References

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
