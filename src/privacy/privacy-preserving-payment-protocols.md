# Протоколи платежів із захистом приватності

Advanced payment systems can hide a payer from the merchant, hide a recipient or amount from a public ledger, or prevent a mint from linking withdrawal to redemption. These are different properties. None erases acquisition, device, network, delivery, accounting, sanctions or endpoint records.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) provides a standardized `Pros`, `Cons`, step-by-step `Procedure`, and `Detection` entry for every payment family. This page expands the advanced protocols.

{% hint style="danger" %}
Використовуйте лише законні кошти та контрагентів. Не використовуйте privacy protocols для обходу обов'язкової ідентифікації, санкцій, податків, перевірок джерела коштів або звітування про транзакції. Не здійснюйте діяльність exchange, mint або transmission service без розуміння ліцензійних вимог, custody, AML та обов'язків із захисту споживачів.
{% endhint %}

## Порівняння advanced options

| Protocol | Що приховується від public/merchant | Trusted or observing party | Зрілість/доступність |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Зовнішні спостерігачі не можуть пов'язати багаторазово використовуваний payment code з його одноразовими outputs | Public Bitcoin graph залишається; wallet/index server може бачити сканування | Специфікацію завершено; підтримка wallet відрізняється |
| Zcash fully shielded Orchard | Sender, receiver та amount зашифровані on-chain | Wallet backend/network і acquisition/off-ramp залишаються | Розгорнуто; підтримка shielded відрізняється залежно від wallet/exchange |
| GNU Taler | Merchant не обов'язково дізнається особу payer; дохід merchant залишається підзвітним | Taler exchange/bank бачить funding; merchant бачить order | Deployments географічно обмежені |
| Federated Chaumian e-cash | Federation не повинна пов'язувати видані notes з внутрішніми transfers/redemption | Guardian quorum зберігає reserves; gateways бачать активність на межі | Emerging community deployments |
| Lightning BOLT 12/route blinding | Зменшує розкриття receiver/node та route | Endpoints, selected hops, funding chain і wallet services | Підтримка залежить від wallet |
| Virtual card/token | Merchant отримує обмежений credential, а не багаторазово використовуваний PAN | Issuer/network зберігають payer і transaction | Зрілий і широко доступний |

## Bitcoin Silent Payments (BIP 352)

Silent Payments дають змогу receiver опублікувати один статичний payment code, тоді як кожен sender виводить унікальний Taproot output. Зовнішній спостерігач chain не може безпосередньо пов'язати ці outputs з опублікованим code, і не потрібні ні інтерактивний запит адреси, ні on-chain notification output. BIP 352 має статус **Complete**, але створює витрати на scanning і несумісний з wallet, які його не реалізували.<sup>[[1]](#references)</sup>

### Workflow receiver

1. Виберіть maintained wallet, який явно підтримує receiving через BIP 352; перевірте цю функцію за актуальною документацією wallet, а не за заявою в social media.
2. Створіть backup wallet seed і матеріал Silent Payment descriptor/key за задокументованим wallet методом recovery. Перевірте discovery на невеликій сумі в testnet/mainnet перед публікацією code.
3. Створюйте окремі **labels** для кампаній, invoices або counterparties, якщо wallet підтримує BIP 352 labels. Labels допомагають локальному accounting, не публікуючи адреси, які можна пов'язати.
4. Публікуйте статичний Silent Payment code через authenticated channel. Він багаторазово використовується, але impostor може підмінити його власним code.
5. Коли це практично можливо, виконуйте scanning через локальний full node. Сторонній index/scanning server може дізнатися час запитів або filter data, навіть якщо не може витрачати кошти.
6. Зберігайте виявлені UTXOs із labels і застосовуйте ті самі правила coin-control, що й для звичайного Bitcoin. Їх spending або consolidation може розкрити зв'язки ownership.
7. Переконайтеся, що recovery виявляє платежі без залежності від зовнішнього index, для якого не створено backup.

### Workflow sender

1. Переконайтеся, що wallet підтримує sending на цю address version, і authenticate статичний довгий code receiver.
2. Дозвольте wallet створити output; ніколи не конвертуйте і не обрізайте code вручну.
3. Уважно перевіряйте вибрані inputs. Silent Payments покращують privacy адреси recipient, але inputs sender все одно залишаються в public graph.
4. Використовуйте підтримувану wallet поведінку fee bumping/PSBT. BIP 352 вимагає повторного derivation outputs, якщо inputs змінюються, а деякі signing modes є небезпечними.
5. Зберігайте зашифрований receipt або proof, необхідний для disputes/accounting.

Silent Payments вирішують проблему повторної публікації адреси recipient. Вони не приховують amount, timing transaction, sender cluster, acquisition history або подальше co-spending.

## Zcash fully shielded payments

Zcash підтримує transparent і shielded value pools. Shielded transactions Orchard використовують zero-knowledge proofs, щоб nodes могли перевіряти validity, поки деталі transaction зашифровані; Unified Addresses можуть містити кілька типів receiver.<sup>[[2]](#references)</sup> Privacy залежить від фактичного path, вибраного wallet, а не від першого символу відображеної адреси.

### Shielded workflow

1. Виберіть maintained wallet, який чітко зазначає поведінку **shielded-by-default** і поточну підтримку Orchard. Перевірте download і створіть backup/test seed.
2. Законно отримайте ZEC і зафіксуйте basis/source. Exchange усе одно знає про acquisition і withdrawal.
3. Отримуйте кошти на Unified Address, яку підтримує wallet, а потім перевірте, чи потрапила transaction до shielded pool. Не припускайте automatic shielding без перевірки поведінки wallet.
4. Надавайте перевагу **shielded-to-shielded** transfers. Переміщення transparent-to-shielded і shielded-to-transparent на межі розкривають public values/timing і можуть уможливити кореляцію amount; Orchard specification зазначає, що spending на non-Orchard address розкриває transaction value.<sup>[[3]](#references)</sup>
5. Уникайте distinctive exact-amount round trips і негайних перетинів межі. Це privacy hygiene, а не дозвіл приховувати ownership або reporting.
6. Використовуйте підтримуваний wallet network-privacy path. Shielded cryptography не приховує IP/timing від wallet servers або peers.
7. Зберігайте внутрішні compliance records і використовуйте viewing keys лише для цілеспрямованого audit/disclosure після розуміння їхнього scope.
8. Перед sending перевірте підтримку wallet/exchange receiver; вимушений transparent receiver змінює privacy property.

## GNU Taler: anonymous payer, accountable merchant

GNU Taler — це open electronic-payment protocol, що використовує traditional currencies, blind signatures і інтеграцію з regulated exchange/bank. Його design має на меті зберігати анонімність customers для merchants, водночас merchants залишаються ідентифікованими та оподатковуваними.<sup>[[4]](#references)</sup> Це не cryptocurrency, а availability залежить від сумісних regional exchange, bank, wallet і merchant.

### User workflow where deployed

1. Визначте operating Taler exchange і merchant у відповідній currency/jurisdiction; ознайомтеся з їхніми актуальними terms, fees, KYC і privacy notices.
2. Встановіть official wallet і перевірте його source. Захищайте wallet backup/recovery data як готівку, оскільки wallet value може бути bearer asset.
3. Withdraw value через підтримуваний bank/exchange flow, використовуючи правдиву інформацію. Funding institution/exchange може знати про withdrawal, навіть якщо blind signatures розривають прямий coin-to-withdrawal link.
4. Перевірте merchant contract у wallet: merchant identity, item/summary, amount, fees, refund і delivery terms.
5. Здійсніть payment і збережіть receipt data, необхідні для refund, warranty, accounting або tax.
6. Не використовуйте повторно optional merchant session/account identifiers, якщо потрібна merchant unlinkability.
7. Враховуйте wallet, network і delivery metadata у threat model; payment cryptography Taler не приховує shipping address або compromised endpoint.

Merchant і exchange залишаються accountable, а operation будь-якого з цих компонентів може бути regulated payment-service activity.

## Federated Chaumian e-cash

Chaumian e-cash використовує blind signatures, щоб mint підписував token, не бачачи пізніше витрачений unblinded token. Fedimint розподіляє custody reserves і signing між guardian federation; його документація зазначає, що guardians бачать aggregate reserves/outstanding notes, але не повинні бачити individual balance або хто кому платив усередині federation.<sup>[[5]](#references)</sup>

Це **custodial bearer value**. Достатній guardian quorum контролює reserves; failure federation, dishonest guardians, software bugs або втрата client state можуть спричинити втрату. Deposits, withdrawals і Lightning gateways є видимими boundary events і можуть корелювати timing/amount.

### Limited-risk workflow

1. Використовуйте лише невелику суму, яку можете дозволити собі втратити. Вважайте public/unknown federations ризикованішими за guardians із реальною відповідальністю.
2. Перевірте federation invite через authenticated channel і зафіксуйте guardian identities, quorum, jurisdiction, fees, recovery та shutdown policy.
3. Встановіть maintained compatible wallet, перевірте його і зрозумійте його backup scheme до внесення депозиту.
4. Внесіть законно отриманий Bitcoin через задокументований path. Зафіксуйте peg-in для accounting і припускайте, що його timing/amount є public або відомі на boundary.
5. Усередині federation використовуйте fresh payment requests і не додавайте account/chat/delivery identifiers, які відновлюють link, усунутий blind signature.
6. Для Lightning payments розглядайте gateway як додаткового observer invoices і boundary timing.
7. Redeem/withdraw відповідно до policy, очікуючи, що distinctive amount і immediate timing можуть корелювати з deposit або external payment.
8. Зберігайте tax/source/authorization records приватно; не просіть guardians або gateways неправдиво описувати activity.

Не описуйте federated e-cash як trustless, self-custodial або гарантовано anonymous.

## BOLT 12 offers and route blinding

BOLT 12 offers можуть бути багаторазово використовуваними без публікації стабільної on-chain address і можуть використовувати blinded paths, щоб payer не мусив дізнаватися clear node identity/path receiver. Це доповнює, але не замінює наявну onion routing у Lightning.

Перед використанням:

1. Переконайтеся, що sender і receiver wallets підтримують однакові актуальні BOLT 12 features; не робіть висновок про support лише з generic “Lightning” branding.
2. Authenticate offer out of band і перевірте amount, issuer/description та recurrence rules.
3. Використовуйте fresh invoice/payment context, згенерований з offer.
4. Мінімізуйте node aliases, public contact information і stable network endpoints.
5. Припускайте, що sender/receiver, first/last hop, wallet service, channel graph і on-chain funding/closure все одно розкривають частини relationship.

## Auditability without public disclosure

Privacy та audit можуть співіснувати:

- Зберігайте labels, invoices, authorization, cost basis і ownership mapping у зашифрованому вигляді поза public protocol.
- Відокремлюйте **view/audit key** від spending key, якщо protocol його надає; спочатку перевірте його точне disclosure на sample wallet.
- Надавайте auditor мінімальний proof із визначеним scope, а не seed або unrestricted spending credential.
- Фіксуйте software version, protocol/pool, transaction ID або proof, counterparty purpose і exchange-rate source під час transaction.
- Визначте retention і deletion замість накопичення постійного незашифрованого identity graph.

## Selection checklist

- [ ] Hidden field і observer названі точно.
- [ ] Wallet/protocol support перевірено станом на дату transaction.
- [ ] Acquisition, network, node/RPC, counterparty, delivery і later-spend links задокументовані.
- [ ] Ризики custody, recovery, liquidity, issuer/federation solvency і refund прийняті.
- [ ] Обов'язкові identity, tax, sanctions, source та organizational records залишаються точними.
- [ ] Невеликий end-to-end test, включно з recovery та audit proof, успішно виконано.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
