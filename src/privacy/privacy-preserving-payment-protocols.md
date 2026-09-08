# Протоколи платежів із захистом приватності

{{#include ../banners/hacktricks-training.md}}

Advanced payment systems can hide a payer from the merchant, hide a recipient or amount from a public ledger, or prevent a mint from linking withdrawal to redemption. These are different properties. None erases acquisition, device, network, delivery, accounting, sanctions or endpoint records.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) надає стандартизовані записи `Pros`, `Cons`, покрокову `Procedure` і `Detection` для кожної платіжної категорії. Ця сторінка розширює інформацію про advanced protocols.

{% hint style="danger" %}
Використовуйте лише законні кошти та контрагентів. Не використовуйте privacy protocols для обходу обов'язкової ідентифікації, санкцій, податків, перевірок джерела коштів або звітності про транзакції. Не здійснюйте діяльність обмінника, mint або сервісу переказу без розуміння вимог щодо ліцензування, зберігання коштів, AML та захисту прав споживачів.
{% endhint %}

## Порівняння advanced options

| Protocol | Що приховується від public/merchant | Trusted or observing party | Зрілість/доступність |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Сторонні спостерігачі не можуть пов'язати багаторазово використовуваний payment code з його одноразовими outputs | Public Bitcoin graph залишається; wallet/index server може бачити сканування | Специфікацію завершено; підтримка wallet відрізняється |
| Zcash fully shielded Orchard | Відправник, отримувач і сума шифруються on-chain | Wallet backend/network та acquisition/off-ramp залишаються видимими | Розгорнуто; підтримка shielded відрізняється залежно від wallet/exchange |
| GNU Taler | Merchant не обов'язково дізнається особу payer; дохід merchant залишається підзвітним | Taler exchange/bank бачить funding; merchant бачить order | Deployments географічно обмежені |
| Federated Chaumian e-cash | Federation не повинна пов'язувати видані notes із внутрішніми transfers/redemption | Guardian quorum зберігає reserves; gateways бачать активність на межі | Emerging community deployments |
| Lightning BOLT 12/route blinding | Зменшує розкриття receiver/node і маршруту | Endpoints, вибрані hops, funding chain та wallet services | Підтримка залежить від wallet |
| Virtual card/token | Merchant отримує обмежений credential, а не багаторазово використовуваний PAN | Issuer/network зберігають дані payer і transaction | Зрілий і широко доступний |

## Bitcoin Silent Payments (BIP 352)

Silent Payments дають змогу отримувачу опублікувати один статичний payment code, тоді як кожен відправник виводить унікальний Taproot output. Зовнішній спостерігач chain не може безпосередньо пов'язати ці outputs з опублікованим code, а інтерактивний запит address або on-chain notification output не потрібні. BIP 352 має статус **Complete**, але створює витрати на scanning і несумісний із wallet, які його не реалізували.<sup>[[1]](#references)</sup>

### Workflow отримувача

1. Виберіть maintained wallet, який явно підтримує receiving через BIP 352; перевіряйте функцію за поточною документацією wallet, а не за твердженням у social media.
2. Створіть backup seed wallet і матеріалів Silent Payment descriptor/key за документованим методом recovery wallet. Перевірте discovery на невеликій сумі testnet/mainnet перед публікацією code.
3. Створюйте окремі **labels** для campaigns, invoices або counterparties, якщо wallet підтримує BIP 352 labels. Labels допомагають локальному accounting без публікації addresses, які можна пов'язати.
4. Публікуйте статичний Silent Payment code через authenticated channel. Він багаторазовий, але impostor може підмінити його власним code.
5. За можливості виконуйте scanning через local full node. Third-party index/scanning server може дізнатися час запитів або дані filters, навіть якщо не може витрачати кошти.
6. Зберігайте виявлені UTXOs із labels і застосовуйте ті самі правила coin-control, що й для звичайного Bitcoin. Spending або consolidating їх може розкрити зв'язки власності.
7. Переконайтеся, що recovery виявляє payments без залежності від external index, для якого не створено backup.

### Workflow відправника

1. Переконайтеся, що wallet підтримує sending на цю address version, і authenticate довгий статичний code отримувача.
2. Дозвольте wallet створити output; ніколи не конвертуйте та не обрізайте code вручну.
3. Уважно перевіряйте вибрані inputs. Silent Payments покращують privacy address отримувача, але inputs відправника все ще перебувають у public graph.
4. Використовуйте wallet-supported fee bumping/PSBT behavior. BIP 352 вимагає повторного derivation outputs, якщо inputs змінюються, а деякі signing modes є небезпечними.
5. Зберігайте encrypted receipt або proof, необхідний для disputes/accounting.

Silent Payments вирішують проблему повторної публікації address отримувача. Вони не приховують amount, transaction timing, sender cluster, acquisition history або подальше co-spending.

## Zcash fully shielded payments

Zcash підтримує transparent і shielded value pools. Shielded transactions Orchard використовують zero-knowledge proofs, щоб nodes могли перевіряти validity, тоді як деталі transaction зашифровані; Unified Addresses можуть містити кілька типів receivers.<sup>[[2]](#references)</sup> Privacy залежить від фактичного path, вибраного wallet, а не від першого символу відображеної address.

### Shielded workflow

1. Виберіть maintained wallet, який чітко визначає поведінку **shielded-by-default** і поточну підтримку Orchard. Перевірте download і створіть backup/test seed.
2. Законно отримайте ZEC і зафіксуйте basis/source. Exchange усе одно знає про acquisition і withdrawal.
3. Отримуйте на Unified Address, яку підтримує wallet, а потім перевірте, чи transaction потрапила до shielded pool. Не припускайте automatic shielding без підтвердження поведінки wallet.
4. Надавайте перевагу transfers **shielded-to-shielded**. Boundary movements transparent-to-shielded і shielded-to-transparent розкривають public values/timing і можуть уможливити кореляцію amount; Orchard specification зазначає, що spending на non-Orchard address розкриває transaction value.<sup>[[3]](#references)</sup>
5. Уникайте характерних transfers туди й назад із точною сумою та негайних boundary crossings. Це privacy hygiene, а не дозвіл приховувати ownership або reporting.
6. Використовуйте підтримуваний wallet network-privacy path. Shielded cryptography не приховує IP/timing від wallet servers або peers.
7. Зберігайте internal compliance records і використовуйте viewing keys лише для навмисного audit/disclosure після розуміння їх scope.
8. Перед відправленням підтвердіть підтримку wallet/exchange отримувача; вимушений transparent receiver змінює privacy property.

## GNU Taler: anonymous payer, accountable merchant

GNU Taler — це open electronic-payment protocol, що використовує traditional currencies, blind signatures і regulated exchange/bank integration. Його design має на меті зберігати анонімність customers для merchants, водночас merchants залишаються identifiable і taxable.<sup>[[4]](#references)</sup> Це не cryptocurrency, а availability залежить від сумісних regional exchange, bank, wallet і merchant.

### User workflow where deployed

1. Визначте operating Taler exchange і merchant у відповідній currency/jurisdiction; прочитайте їхні актуальні terms, fees, KYC і privacy notices.
2. Встановіть official wallet і перевірте його source. Захищайте wallet backup/recovery data як готівку, оскільки wallet value може бути bearer asset.
3. Withdraw value через supported bank/exchange flow, використовуючи правдиву інформацію. Funding institution/exchange може знати про withdrawal, навіть якщо blind signatures розривають прямий coin-to-withdrawal link.
4. Перегляньте merchant contract у wallet: merchant identity, item/summary, amount, fees, refund і delivery terms.
5. Здійсніть payment і збережіть receipt data, необхідні для refund, warranty, accounting або tax.
6. Не використовуйте повторно optional merchant session/account identifiers, якщо потрібна merchant unlinkability.
7. Враховуйте wallet, network і delivery metadata у threat model; payment cryptography Taler не приховує shipping address або compromised endpoint.

Merchant і exchange залишаються підзвітними, а operation будь-якого з цих компонентів може бути регульованою payment-service activity.

## Federated Chaumian e-cash

Chaumian e-cash використовує blind signatures, щоб mint підписував token, не бачачи unblinded token, який згодом витрачається. Fedimint розподіляє reserve custody і signing між guardian federation; його documentation зазначає, що guardians бачать aggregate reserves/outstanding notes, але не повинні бачити окремий balance або те, хто кому платив усередині federation.<sup>[[5]](#references)</sup>

Це **custodial bearer value**. Достатній guardian quorum контролює reserves; federation failure, dishonest guardians, software bugs або lost client state можуть спричинити втрату. Deposits, withdrawals і Lightning gateways є видимими boundary events і можуть корелювати timing/amount.

### Limited-risk workflow

1. Використовуйте лише невелику суму, яку можете дозволити собі втратити. Вважайте public/unknown federations ризикованішими за guardians із real-world accountability.
2. Перевірте federation invite через authenticated channel і зафіксуйте identities guardians, quorum, jurisdiction, fees, recovery та shutdown policy.
3. Встановіть maintained compatible wallet, перевірте його та зрозумійте його backup scheme до внесення deposit.
4. Внесіть lawfully acquired Bitcoin через documented path. Зафіксуйте peg-in для accounting і припускайте, що його timing/amount є public або відомі на boundary.
5. Усередині federation використовуйте fresh payment requests і не додавайте account/chat/delivery identifiers, які відтворюють link, усунутий blind signature.
6. Для Lightning payments вважайте gateway додатковим observer invoices і boundary timing.
7. Redeem/withdraw відповідно до policy, очікуючи, що distinctive amount і immediate timing можуть корелювати з deposit або external payment.
8. Приватно зберігайте tax/source/authorization records; не просіть guardians або gateways неправдиво відображати activity.

Не описуйте federated e-cash як trustless, self-custodial або гарантовано anonymous.

## BOLT 12 offers and route blinding

BOLT 12 offers можуть бути багаторазовими без публікації stable on-chain address і можуть використовувати blinded paths, щоб payer не мусив дізнаватися clear node identity/path отримувача. Це доповнює, але не замінює наявну onion routing у Lightning.

Перед використанням:

1. Переконайтеся, що wallets відправника й отримувача підтримують однакові актуальні BOLT 12 features; не робіть висновок про support лише з загального branding “Lightning”.
2. Authenticate offer out of band і перевірте amount, issuer/description та recurrence rules.
3. Використовуйте fresh invoice/payment context, згенерований з offer.
4. Зводьте до мінімуму node aliases, public contact information і stable network endpoints.
5. Припускайте, що sender/receiver, first/last hop, wallet service, channel graph і on-chain funding/closure все ще розкривають частини relationship.

## Auditability without public disclosure

Privacy і audit можуть співіснувати:

- Зберігайте labels, invoices, authorization, cost basis і ownership mapping encrypted поза public protocol.
- Відокремлюйте **view/audit key** від spending key, якщо protocol це підтримує; спочатку перевірте його точне disclosure на sample wallet.
- Надавайте auditor proof із мінімально необхідним scope, а не seed або unrestricted spending credential.
- Фіксуйте software version, protocol/pool, transaction ID або proof, counterparty purpose і exchange-rate source під час transaction.
- Визначте retention і deletion замість накопичення постійного unencrypted identity graph.

## Selection checklist

- [ ] Hidden field і observer визначені точно.
- [ ] Wallet/protocol support перевірено станом на дату transaction.
- [ ] Acquisition, network, node/RPC, counterparty, delivery і later-spend links задокументовані.
- [ ] Ризики custody, recovery, liquidity, issuer/federation solvency і refund прийняті.
- [ ] Обов'язкові identity, tax, sanctions, source та organizational records залишаються точними.
- [ ] Невеликий end-to-end test, включно з recovery і audit proof, успішно пройдено.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [Документація GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Як це працює](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
