# Приватність криптовалют

{{#include ../banners/hacktricks-training.md}}

Приватність криптовалют — це питання протоколу й операцій, а не синонім таємності чи імунітету. Публічні реєстри, біржі, wallet servers, мережеві peers, merchants і подальші транзакції розкривають різні частини графа.

Почніть із [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md), де для кожної техніки використовується формат переваги/недоліки/процедура/виявлення. Ця сторінка розширює опис специфічних для криптовалют механізмів та операційних обмежень.

{% hint style="danger" %}
Цей розділ призначений для законного self-custody та мінімізації даних. Не використовуйте його для відмивання доходів, обходу санкцій/податків/звітності, транзакцій із забороненими сторонами, введення в оману регульованого провайдера або роботи без ліцензії як сервіс передачі коштів. Технологія приватності не змінює законне походження чи право власності на кошти.
{% endhint %}

## Модель загроз за рівнями

| Рівень | Спостерігач | Типове розкриття |
|---|---|---|
| Придбання/off-ramp | Біржа, банк, broker, P2P-контрагент | Особа, рахунок фінансування, призначення, пристрій, IP, час |
| Реєстр | Будь-хто, хто запускає analytics | Адреси/outputs, суми й час у прозорих chains; специфічні для протоколу метадані в інших випадках |
| Wallet backend | RPC provider, explorer, remote node | Запити адрес, баланси, IP, трансляція транзакцій |
| Мережа | ISP, peers, вхідний вузол anonymity-network | IP, час, обсяг і використання протоколу |
| Контрагент | Платник/отримувач | Invoice/address, доставка, розмова, обліковий запис і час |
| Endpoint | Malware, cloud backup, фізичне вилучення | Seed, keys, labels, history, screenshots і clipboard |

Self-custody може усунути custodian із ланцюга контролю, але не стирає реєстр, запис про придбання, мережеві метадані чи докази на endpoint.

## Порівняння протоколів

| Метод | Корисна властивість приватності | Важливі обмеження |
|---|---|---|
| Bitcoin on-chain | Self-custody; свіжі адреси уникають простого повторного використання адрес | Публічний постійний граф транзакцій; евристики сум, часу й витрат |
| Bitcoin PayJoin | Input отримувача може зламати евристику common-input-ownership | Обидва wallet мають підтримувати функцію; транзакція залишається публічною; підтримка нерівномірна |
| Bitcoin CoinJoin | Створює неоднозначність між скоординованими учасниками | Розпізнавані шаблони, pre/post links, консолідація, policy/legal/provider risk |
| Lightning | Onion-routed payments не публікуються глобально як звичайні перекази | Відкриття/закриття каналів відбувається on-chain; endpoints, peers, probes або custodian можуть виводити дані |
| Monero | Сильніша default on-chain конфіденційність отримувача, суми та набору відправників | Зв’язки через exchange, node, час, endpoint і контрагента залишаються |
| Ethereum/stablecoins | Широка доступність і smart-contract interoperability | Публічний state/actions; RPC metadata; централізовані емітенти можуть блокувати/заморожувати/звітувати |

## Bitcoin: базовий рівень із захистом приватності

Bitcoin є pseudonymous, а не anonymous. Підтверджені транзакції є публічними й довговічними; повторне використання адрес, common-input ownership, виявлення change та публічно ідентифіковані адреси можуть формувати кластери.<sup>[[1]](#references)</sup>

### Workflow

1. **Оберіть wallet для self-custody, який підтримується.** Завантажуйте його з офіційного проєкту, перевіряйте signatures/hashes, якщо це пропонується, і встановлюйте security updates.
2. **Створіть wallet на довіреному endpoint.** Запишіть recovery seed offline; ніколи не зберігайте його в email, chat, screenshots або звичайних cloud notes. Перевірте recovery до внесення значної суми.
3. **Зберігайте hot лише операційні кошти.** Для довгострокової вартості використовуйте відповідне offline/hardware custody із планом recovery, який не розкриває seed в одному вразливому місці.
4. **Створюйте нову receive address/invoice для кожної транзакції.** Не публікуйте статичну адресу, якщо можливі invoice server або authenticated private delivery.
5. **За можливості використовуйте власний full node.** Сторонній explorer/electrum server може дізнатися запитані адреси та IP metadata. Налаштовуйте лише wallet-supported Tor/proxy behavior; Tor приховує network edge, але не blockchain graph.
6. **Приватно позначайте кожен UTXO** із зазначенням джерела, власника, призначення та compliance state. Увімкніть coin control, щоб непов’язані identity contexts не витрачалися разом.
7. **Перегляньте транзакцію:** вибрані inputs, destination для change, суму, fee, контрагента та те, чи об’єднує витрата compartments. Уникайте непотрібної консолідації.
8. **Зберігайте законні записи окремо та в зашифрованому вигляді.** Зберігайте acquisition basis, invoices, authorization і tax/reporting information, не публікуючи відповідність між ними.
9. **Розглядайте подальше витрачання як частину того самого рішення щодо приватності.** Добре відокремлений receipt може бути повторно пов’язаний, коли його output витрачається разом з ідентифікованими коштами.

Документація Bitcoin Core щодо приватності пояснює, що full node не розкриває wallet queries стороннім серверам, але broadcast транзакцій і публічна history все одно потребують аналізу.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin — це collaborative payment, у якій отримувач додає input. Це спростовує спрощене припущення, що всі inputs належать відправнику. BIP 78 описує початковий інтерактивний протокол; draft BIP 77 визначає асинхронний дизайн v2 з використанням encrypted mailbox/OHTTP.<sup>[[3]](#references)</sup>

Безпечне використання:

1. Переконайтеся, що обидва підтримувані wallet підтримують однакову версію PayJoin.
2. Отримайте PayJoin-capable invoice через authenticated channel; захищайте його як будь-який payment request.
3. Перевірте початкову суму та destination, після чого дозвольте wallet перевірити proposal/PSBT, внесок у fee та заборонені substitutions.
4. Підтвердьте підсумок у wallet. Не схвалюйте вручну неочікуваний output, суму або надмірну fee.
5. Якщо negotiation не вдався, з’ясуйте, чи wallet безпечно переходить до звичайного платежу або потребує нового invoice.
6. Зберігайте приватні receipt/records, необхідні для підтвердження власності, accounting і спорів.

PayJoin покращує одну heuristic chain-analysis; він не приховує платіж від сторін, acquisition platform, endpoints або публічного реєстру.

## CoinJoin: переваги та обмеження

CoinJoin координує кількох користувачів в одній транзакції, щоб зробити mapping між inputs і outputs менш визначеним. Дослідження конкретних історичних дизайнів Wasabi та Samourai виявило добре розпізнавані транзакції й показало, що pre/post-mix behavior може суттєво звужувати anonymity.<sup>[[4]](#references)</sup> Цей результат не слід узагальнювати на кожну реалізацію чи майбутню версію, але він демонструє, чому число “anonymity-set” не є гарантією.

Перед будь-яким законним використанням:

- перевірте чинне місцеве законодавство, санкційний статус, політику exchange/custodian і податкові/звітні обов’язки;
- використовуйте підтримуване non-custodial software, отримане з офіційного проєкту;
- зрозумійте модель coordinator, fees, controls проти denial-of-service і те, чи продовжує працювати поточний service — zkSNACKs припинив роботу свого coordinator у 2024 році, хоча можуть існувати інші Wasabi coordinators;
- приватно зберігайте source-of-funds і transaction records;
- ніколи не приймайте невідомі кошти від імені іншої особи та не використовуйте custodial “mixer”, який обіцяє withdrawals без можливості відстеження;
- зберігайте outputs розділеними за source/context та уникайте подальшої консолідації, яка знищує передбачену неоднозначність.

Юридичні наслідки залежать від фактів і юрисдикції. Визнання вини Samourai у 2025 році стосувалося свідомої роботи без ліцензії як money transmitter, який переміщував кримінальні доходи; це не означає, що кожна collaborative transaction або користувач, який прагне приватності, є злочинцем.<sup>[[5]](#references)</sup>

## Lightning Network

Onion routing Sphinx у Lightning розроблено так, щоб проміжний hop знав свого попередника й наступника, а не весь route.<sup>[[6]](#references)</sup> Це не забезпечує blanket anonymity: channel funding/closure є публічними, nodes оголошують topology, counterparties знають endpoints, routing/probing може виявляти balances або сторони, а custodial wallet бачить account activity свого користувача.

Для кращої приватності:

1. Якщо важлива приватність посередника, віддавайте перевагу підтримуваному non-custodial wallet; спочатку сплануйте channel backup/recovery.
2. Використовуйте свіжий invoice або offer для кожного платежу. Перевірте, чи конкретний wallet підтримує BOLT 12/route blinding, а не припускайте це.
3. Не публікуйте непотрібні node aliases, контактні дані та стабільні network endpoints.
4. За потреби підключайтеся через підтримувану privacy network, розуміючи, що patterns uptime/timing все одно можуть корелюватися.
5. Не припускайте, що off-chain payment не залишає записів: sender, receiver, peers, watchtowers, liquidity providers і wallet services можуть зберігати спостереження.

Опубліковані дослідження продемонстрували виведення sender/recipient і channel-balance з публічних даних та активного probing, хоча атаки й mitigations розвиваються.<sup>[[7]](#references)</sup>

## Monero

Monero використовує one-time stealth addresses для outputs, RingCT для приховування сум і ring signatures для забезпечення ймовірнісної неоднозначності відправника; поточні технічні specifications документують ring size 16 (15 decoys).<sup>[[8]](#references)</sup> Це сильніші default для on-chain конфіденційності, ніж у прозорих реєстрах, але не магічний захист від помилок endpoint або операційних помилок.

### Законний workflow

1. **Придбавайте законно.** Регульована біржа може знати про купівлю та withdrawal, навіть якщо подальші on-chain details є конфіденційними. Зберігайте записи про джерело, basis і звітність.
2. **Встановіть офіційний підтримуваний wallet** і перевірте його завантаження відповідно до інструкцій проєкту. Створіть backup seed offline і перевірте restoration на невеликій сумі.
3. **Для максимальної приватності wallet queries віддавайте перевагу local node.** Якщо це непрактично, оберіть trusted remote node, доступний через офіційно підтримувану onion/I2P configuration. Remote node може логувати IP, requests, timing і transaction IDs; деякі lightweight designs розкривають view key.
4. **Використовуйте новий subaddress для кожного payer, campaign або invoice.** Payer може пов’язати повторне використання того самого subaddress.<sup>[[9]](#references)</sup>
5. **Локально позначайте incoming contexts.** Уникайте операційного об’єднання розділених receipts, якщо обізнаний payer може розпізнати подальшу поведінку.
6. **Захищайте network metadata.** Дотримуйтеся офіційної configuration для anonymity-network; враховуйте задокументовані leaks із timestamps, переривчастої синхронізації, bandwidth shape і повторного використання stream.<sup>[[10]](#references)</sup>
7. **Зберігайте compliance/audit data приватними.** Розкривайте view key або transaction proof лише свідомо, призначеному auditor/party, і точно розумійте, що саме він розкриває.

Історичні дослідження traceability охоплюють bugs та епохи вибору decoys, які згодом змінилися; не застосовуйте старі відсотки успішності до поточних транзакцій. Так само FCMP++ станом на research cutoff цього розділу у вересні 2026 року залишається roadmap work, а не розгорнутим захистом.<sup>[[11]](#references)</sup>

## Ethereum і stablecoins

Власні матеріали Ethereum щодо приватності зазначають, що on-chain actions є видимими, а wallet/RPC infrastructure додає exposure IP і metadata.<sup>[[12]](#references)</sup> Token transfers, approvals, smart-contract interactions, name services і gas funding можуть пов’язувати особи.

Централізовані stablecoins додають контроль емітента. Поточні умови USDC і Tether передбачають повноваження блокувати/заморожувати addresses або assets і виконувати legal/process obligations.<sup>[[13]](#references)</sup> Вони можуть бути корисними платіжними інструментами, але є невдалим вибором, коли вимогою є censorship resistance або on-chain anonymity.

## Межі compliance

- Рекомендації FATF реалізуються через національне законодавство та змінюються з часом; її оновлення 2026 року наголошує на VASP licensing/registration і реалізації Travel Rule.<sup>[[14]](#references)</sup>
- У США FinCEN відрізняє особу, яка використовує convertible virtual currency для власних goods/services, від бізнесу, що приймає та передає або обмінює її; важливі факти й подальші правила.<sup>[[15]](#references)</sup>
- Regulation of the European Union щодо переказу коштів вимагає інформацію про originator/beneficiary, якщо залучений crypto-asset service provider, і додає verification rules для певних переказів на/із self-hosted addresses.<sup>[[16]](#references)</sup>
- Санкції та податкові обов’язки продовжують діяти. Проводьте screening відповідно до вимог, відмовляйте забороненим сторонам і ведіть records; lists і legal status можуть швидко змінюватися.<sup>[[17]](#references)</sup>

До операцій зі значними коштами, транскордонної діяльності, coordination із privacy-enhancing функціями або обміну/передачі коштів у форматі бізнесу отримайте актуальну professional advice для відповідних юрисдикцій.

Для Bitcoin Silent Payments, повністю shielded Zcash, GNU Taler, federated Chaumian e-cash і BOLT 12 перейдіть до [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Захистіть свою приватність](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Функції приватності](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Проста пропозиція PayJoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adoption and Actual Privacy of Decentralized CoinJoin Implementations in Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Засновники Samourai Wallet визнали провину (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Протокол Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Емпіричний аналіз приватності в Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) та [Технічні specifications](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Networks](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Дослідження еволюції приватності Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Приватність в Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Умови USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Цільове оновлення щодо Virtual Assets і VASPs за 2026 рік](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Застосування правил FinCEN до осіб, які адмініструють, обмінюють або використовують Virtual Currencies](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Рекомендації щодо санкційного compliance для індустрії Virtual Currency](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
