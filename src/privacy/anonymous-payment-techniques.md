# Каталог анонімних платіжних технік

{{#include ../banners/hacktricks-training.md}}

Цей каталог охоплює **сімейства** платежів: від звичайної готівки до e-cash із blind-signature та обфускації публічних блокчейнів. «Анонімний» завжди означає анонімний щодо конкретного спостерігача. Merchant, issuer, mint, exchange, blockchain analyst, network provider, employer і фізичний спостерігач бачать різні факти.

Наведені процедури призначені для законних коштів, правдивих облікових записів і авторизованих закупівель. Техніки, метою яких у цитованих випадках були laundering, обходження санкцій або identity fraud, пояснюються та виявляються, але їхня процедура є синтетичною forensic-вправою, а не інструкціями зі скоєння злочину.

## Матриця охоплення

| Сімейство | Основна властивість приватності | Основний спостерігач/рівень довіри | Статус |
|---|---|---|---|
| Готівка та її еквіваленти | відсутність віддаленого запису в платіжній мережі | отримувач і фізичне середовище | законний workflow |
| Prepaid/gift/voucher value | відокремлює redemption від primary card | seller, issuer і redemption service | законний workflow, залежить від юрисдикції |
| Virtual/tokenized card | приховує багаторазовий PAN або розділяє merchants | issuer/network/wallet все одно ідентифікує payer | законний workflow |
| Payment app/intermediary | merchant може бачити alias/intermediary | app збирає identity/device/transaction | базовий варіант для порівняння |
| Bitcoin hygiene/Silent Payments | pseudonyms і unlinkability отримувача | public graph і wallet/network boundary | придатне до розгортання |
| PayJoin/CoinJoin | послаблює common ownership/linkage heuristics | participants/coordinator/network/public graph | придатне там, де підтримується; потрібен legal review |
| Lightning/BOLT 12 | off-chain routing і зменшення шляху до отримувача | endpoints, hops, services і channel graph | придатне там, де підтримується |
| Monero/Zcash/MWEB | протокольна on-chain confidentiality | acquisition, endpoint, network і boundary | придатне там, де законно/підтримується |
| Ethereum ZK application | приховує визначений зв’язок statement/action | public inputs, RPC, relayer і app | специфічне для застосунку |
| Cashu/Fedimint/Taler | payer privacy через blind-signature | mint/federation/exchange custody і boundaries | нове/залежить від deployment |
| Stablecoins | зручний цифровий settlement | transparent chain та issuer freeze/control | не є базовим анонімним варіантом |
| Swaps/bridges/DEX | переміщує value між assets/chains | обидва graphs, contracts і providers | forensic mechanics; лише звичайні законні swaps |
| Mixers/peel/structuring | збільшує graph ambiguity/work | entry/exit graph і service records | лише синтетична вправа з виявлення |
| Nominees/mules/OTC/fronts | вставляє human/business intermediaries | facilitators, banks, communications | лише аналіз criminal abuse |
| Reusable/stealth payment addresses | нова адреса отримувача для кожного платежу | public announcement/notification і wallet boundaries | придатне там, де підтримується |
| Confidential sidechain/state channel | приховує amount/asset або проміжні updates | peers, bridge/federation і lifecycle settlement | специфічне для протоколу |
| Carrier/open-banking/platform billing | приховує primary card від merchant | carrier, bank/PISP або platform ідентифікує customer | звичайний ідентифікований платіж |
| Mutual credit/net settlement | менше зовнішніх settlement records | private ledger operator має повну відповідність | лише для ідентифікованих учасників |

## Готівка

**Механіка:** фізична bearer value переходить з рук у руки без online issuer authorization або public ledger.

**Переваги:** merchant не обов’язково дізнається bank/card identity; немає віддаленого transaction graph; зрозуміло та остаточно.

**Недоліки:** лише face-to-face; theft/loss; change/receipt/serial або reporting controls; withdrawal, cameras, witnesses і location все одно можуть пов’язати payer.

**Процедура:** (1) підтвердити законність/прийнятність cash і правила щодо сум/reporting; (2) законно withdraw або отримати кошти та вести приватний accounting; (3) оплатити звичайному merchant без зайвих loyalty/account identifiers; (4) попросити лише необхідний receipt; (5) не надавати shipping/account data, якщо покупка цього не потребує; (6) внутрішньо зафіксувати законну business purpose.

**Виявлення:** звіряти till/receipt/inventory, cameras і access logs згідно з applicable policy; перевіряти незвичайні cash refunds або повторні суми трохи нижче control threshold, не вважаючи саме використання готівки підозрілим.

## Money order, postal order, cashier instrument і cash on delivery

**Механіка:** regulated issuer перетворює cash/account funds на numbered instrument, payable named recipient; COD відкладає collection до delivery.

**Переваги:** recipient може не отримати primary bank/card number payer; придатне там, де cash не можна передати віддалено; чіткий receipt.

**Недоліки:** issuer/retailer зберігає purchase/identity data відповідно до вимог; serial tracking; recipient/delivery address; loss/fraud і регіональні обмеження; зазвичай не anonymous.

**Процедура:** (1) перевірити issuer rules, limits, identification і recipient acceptance; (2) купувати з правдивими даними та законними коштами; (3) негайно заповнити payee/amount; (4) зберегти serial/receipt; (5) використати tracked delivery відповідно до вартості; (6) звірити redemption/refund.

**Виявлення:** issuer purchase/redemption record, instrument serial, retailer/camera, shipping і recipient account; позначати alteration, duplicate serials та швидке географічно несумісне redemption.

## Open-loop prepaid card

**Механіка:** network-branded stored-value credential авторизується проти prepaid balance, а не primary credit account.

**Переваги:** обмежує merchant exposure і втрати; відділяє merchant від main PAN; працює online там, де приймається.

**Недоліки:** purchase/activation/reload/registration і device records; KYC та limits різняться; billing-address failures; cash-out/refund restrictions; “no name” не означає відсутність issuer record.

**Процедура:** (1) перевірити current issuer identity, fees, KYC, geography і online/recurring support; (2) придбати через authorized seller із законними коштами; (3) зареєструвати правдиві обов’язкові дані; (4) використовувати для однієї compartment/purpose; (5) не структурувати loads і не підробляти residency; (6) зберігати purchase/expense evidence та закрити/утилізувати card за issuer terms.

**Виявлення:** об’єднати seller/activation, funding, device/IP, merchant authorization, balance checks і redemption/refund. Значення мають patterns, а не сам prepaid label.

## Closed-loop gift card, voucher і transferable service credit

**Механіка:** numbered value redeemable лише в одного merchant/service або ecosystem. Airtime/game/store credits є варіантами.

**Переваги:** merchant може бачити лише code/balance; обмежений blast radius; просте gifting і budget separation.

**Недоліки:** seller/service записують purchase/activation/redemption; account/device/delivery все одно пов’язують activity; scams, resale discounts та expiry/region limits; слабкі refund rights.

**Процедура:** (1) купувати лише через authorized channels; (2) записати code value, не розкриваючи secret; (3) не прив’язувати identifying loyalty account без потреби; (4) redeem через окремий legitimate merchant account/context; (5) зберігати receipt до acceptance; (6) ніколи не купувати codes на unsolicited “tax/support/ransom” demand.

**Виявлення:** code issuance/redemption time, device/account convergence, bulk/threshold-pattern purchase, один device, що перевіряє багато balances, і швидке віддалене redemption.

## Cryptocurrency-funded card або gift-code broker

**Механіка:** intermediary приймає cryptocurrency та видає card, voucher або merchant code. Це cross-rail conversion: merchant бачить звичайну card/gift value, а broker пов’язує on-chain deposit з issuance і delivery.

**Переваги:** merchant не отримує funding wallet; корисне для legitimate merchants, які не приймають crypto; обмежена stored value.

**Недоліки:** не anonymous щодо broker/issuer; KYC, sanctions, exchange і card-program rules; public deposit graph; account/device/email і code redemption знову з’єднують обидві сторони; scam/insolvency risk.

**Процедура:** (1) перевірити legal entity, card issuer, supported jurisdiction, KYC, fees і refund policy; (2) використовувати лише lawful documented funds; (3) протестувати найменшу denomination; (4) перевірити network/merchant restrictions; (5) зберігати blockchain transaction і broker receipt для accounting; (6) не використовувати broker, який обіцяє identity fraud, sanctions bypass або “untraceable” cash-out.

**Виявлення:** корелювати broker deposit addresses, unique amount/time, account/device з issued-card authorization або gift-code redemption; issuer і broker records поєднують public chain із merchant.

## Virtual або merchant-locked card

**Механіка:** issuer пов’язує generated PAN/token із real account, часто обмежуючи merchant, amount або expiration.

**Переваги:** не розкриває reusable PAN; merchant compartmentation; spend limits і просте revocation; зрілий fraud control.

**Недоліки:** issuer усе одно знає payer, funding, merchant, device/IP і time; merchant бачить account/delivery; деякі refunds/recurring charges не працюють; не anonymous.

**Процедура:** (1) використовувати official feature regulated issuer; (2) створити card для одного merchant/engagement; (3) встановити найменший корисний limit і expiry; (4) використовувати accurate billing, якщо потрібно; (5) перевірити statement descriptor/refund behavior; (6) freeze/delete після final settlement, зберігши audit evidence.

**Виявлення:** issuer token-to-account mapping, merchant authorization, device і delivery. Defenders використовують merchant-specific reuse, velocity і account-takeover signals.

## Mobile-wallet network token

**Механіка:** EMV payment tokenization замінює PAN на constrained credential, часто прив’язаний до device, merchant або payment scenario.<sup>[[1]](#references)</sup>

**Переваги:** merchant не отримує reusable PAN; device cryptography/dynamic data зменшують cloning; token можна revoke без заміни card.

**Недоліки:** issuer, token service, wallet platform і network зберігають mappings/transactions; device/platform account і location можуть ідентифікувати payer.

**Процедура:** (1) enroll legitimate card в official wallet; (2) захистити platform account/device strong authentication; (3) перевірити device token/last digits під час purchase; (4) вимкнути непотрібні location/analytics, якщо підтримується; (5) негайно disable lost devices/token; (6) переглядати issuer і wallet records.

**Виявлення:** token requestor/device cryptogram та issuer mapping, wallet/account telemetry, merchant terminal і physical evidence.

## Payment app, marketplace wallet і centralized intermediary

**Механіка:** service підтримує accounts і transfers внутрішньо або через bank/card rails; merchant може бачити alias, тоді як service бачить обидві сторони.

**Переваги:** зручність, dispute/refund mechanisms; recipient не обов’язково бачить bank/card details.

**Недоліки:** centralized identity/social/transaction/device graph; freezes і legal process; counterparties можуть розкрити profile; data use може перевищувати payment necessity.<sup>[[2]](#references)</sup>

**Процедура:** (1) прочитати identity, privacy, retention і buyer-protection terms; (2) мінімізувати optional profile/contact synchronization; (3) використовувати окремий truthful account лише якщо це дозволено terms; (4) увімкнути MFA/alerts; (5) перевірити recipient і privacy memo/profile; (6) export records і закрити непотрібні links.

**Виявлення:** provider account, device/IP, contact graph, funding/withdrawal, memo і merchant records. Alias означає pseudonymity щодо counterparty, а не anonymity щодо platform.

## Bank transfer, ACH, wire і instant-account payment

**Механіка:** regulated institutions переміщують value між identified accounts та обмінюються необхідними payment data.

**Переваги:** швидкість, accountability, обмежена reversibility, сильні records; virtual account numbers можуть зменшити merchant disclosure.

**Недоліки:** banks/processors знають обидві сторони; statements і references; не anonymous; cross-border і Travel Rule/AML data.

**Процедура:** використовувати лише коли accountability прийнятна: незалежно перевірити beneficiary, мінімізувати optional memo data, застосовувати bank-provided virtual account/reference, якщо доступно, увімкнути alerts, зберегти invoice і виконати reconciliation.

**Виявлення:** deterministic bank/payment records, beneficiary/account ownership, device/session і fraud controls. Це baseline, а не anonymity technique.

## Account і merchant compartmentation

**Механіка:** окремі lawful identities/accounts, email aliases, cards і delivery contexts не дають unrelated merchants легко об’єднати activity, хоча issuer/controller зберігає mapping.

**Переваги:** зменшує breach і cross-merchant linkage; легко audit; сумісне з regulated payments.

**Недоліки:** provider все одно поєднує compartments; recovery phone/device/IP і shipping можуть reconnect їх; policy може забороняти multiple accounts.

**Процедура:** (1) визначити одну purpose; (2) створювати лише terms-compliant aliases/subaccounts; (3) використовувати merchant-specific token/card; (4) вимкнути cross-account contact/ad personalization; (5) вести encrypted controller ledger; (6) retire identifiers після завершення refunds/retention needs.

**Виявлення:** providers об’єднують recovery, device, funding та IP; merchants об’єднують delivery, browser і account behavior. Defenders мають відрізняти законну compartmentation від synthetic identity fraud.

## Controlled red-team procurement

**Механіка:** SOC не знає про purchase, тоді як exercise controller зберігає legal entity, operator та infrastructure mapping.

**Переваги:** реалістична detection exercise; відсутність personal exposure; негайні deconfliction і audit.

**Недоліки:** не anonymous щодо organization/provider; governance overhead; leaks, якщо controller ledger оброблено неналежно.

**Процедура:** (1) виділити engagement-specific organization card/wallet/budget; (2) розділити purchaser/operator roles; (3) записати asset, amount, service, purpose і kill date; (4) зберігати attribution mapping з обмеженим controller access; (5) ніколи не використовувати false identity/mule/stolen funds; (6) після завершення розкрити та reconcile indicators і refunds.

**Виявлення:** controller maps provider invoice та asset; SOC тестує independent discovery через domain, certificate, hosting і traffic, а не через cardholder data.

## Bitcoin address hygiene і coin control

**Механіка:** fresh receive addresses, local labeling і selective UTXO spending зменшують address reuse та accidental compartment merging у public ledger.

**Переваги:** широко підтримується; self-custodial; усуває найпростіший public linkage.

**Недоліки:** усі transactions/amounts залишаються public; common-input/change/timing і подальша consolidation можуть пов’язати activity; acquisition/RPC/network records зберігаються.

**Процедура:** (1) встановити/перевірити maintained wallet; (2) backup і test seed recovery; (3) використовувати нову address для кожного invoice; (4) локально маркувати source/purpose; (5) використовувати coin control, щоб не об’єднувати contexts; (6) віддавати перевагу local node або privacy-aware connection; (7) перевіряти change/fees і зберігати lawful accounting.<sup>[[3]](#references)</sup>

**Виявлення:** address graph, common-input/change heuristics з урахуванням uncertainty, exact amount/time, consolidation, service deposits, node/RPC broadcast timing і off-chain records.

## Bitcoin Silent Payments

**Механіка:** BIP 352 дає receiver змогу публікувати static code, тоді як senders виводять унікальні Taproot outputs через ECDH; зовнішні observers не можуть безпосередньо пов’язати outputs із code.<sup>[[4]](#references)</sup>

**Переваги:** reusable public identifier без address reuse; не потрібні interactive address request або notification output; змішується з Taproot outputs.

**Недоліки:** scanning cost receiver; wallet support різниться; amount/sender graph і spending залишаються public; index server може бачити scans.

**Процедура:** (1) вибрати current BIP 352 wallet; (2) backup/test descriptor і scanning recovery; (3) створити labeled code, якщо підтримується; (4) authenticate published code; (5) sender перевіряє inputs і надсилає small test; (6) receiver сканує через власний node, якщо можливо; (7) тримати received UTXOs окремо.

**Виявлення:** за design output сам по собі не дає надійної ідентифікації; analysts використовують sender inputs, amount/time, later spending, wallet/network/index і counterparty records.

## PayJoin

**Механіка:** payer і payee додають inputs до однієї payment transaction, ламаючи припущення, що всі inputs належать одному owner.<sup>[[5]](#references)</sup>

**Переваги:** звичайний payment із покращеною privacy; послаблює common heuristic для ширшого graph; не потребує equal-output crowd.

**Недоліки:** потрібні interaction/support; receiver endpoint availability; amount і final transaction public; implementation і fallback metadata.

**Процедура:** (1) переконатися, що maintained wallets підтримують однакову PayJoin version; (2) authenticate invoice/endpoint; (3) почати з wallet PayJoin-enabled payment URI; (4) перевірити final amount/fee та sign лише очікувані inputs; (5) не виконувати manual transaction surgery; (6) перевірити broadcast і receipt; (7) зафіксувати fallback, якщо negotiation не вдалася.

**Виявлення:** blockchain analysts не повинні автоматично застосовувати common-input clustering; endpoint/provider може логувати negotiation; використовувати wallet/network і later-spend evidence, а не лише transaction shape.

## CoinJoin

**Механіка:** кілька participants спільно створюють transaction з багатьма inputs/outputs, часто однакових denominations, збільшуючи ambiguity input-output correspondence.

**Переваги:** більший on-chain ambiguity set; існують self-custodial designs; measurable round structure.

**Недоліки:** coordinator/peer/network metadata; fees/liquidity; recognizable transaction shape; toxic change і later consolidation знищують gains; legal/provider availability різниться.

**Процедура:** (1) перевірити current wallet/coordinator availability і legality; (2) встановити official wallet та зробити backup; (3) використовувати лише lawful UTXOs; (4) зрозуміти denomination, fee і coordinator model; (5) маркувати та розділяти change/mixed outputs; (6) ніколи не консолідувати їх разом; (7) маршрутизувати network traffic лише офіційно підтриманим способом і зберігати accounting.

**Виявлення:** визначати collaborative structure без автоматичного припущення злочину; обчислювати можливі mappings/anonymity set, потім перевіряти change/consolidation, service boundaries і network/coordinator records.

## Lightning Network

**Механіка:** HTLC payments проходять onion-routed channels; більшість payment details не публікується on chain, але funding/closing і public channel information залишаються.

**Переваги:** швидко, низькі fees; intermediaries зазвичай бачать лише adjacent hops; routine payment details залишаються off chain.

**Недоліки:** sender/receiver і first/last hop знають більше; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets ідентифікують users.

**Процедура:** (1) свідомо обрати self-custodial або custodial; (2) перевірити wallet/seed/channel recovery; (3) використовувати invoice для exact payment; (4) використовувати private channels/LSP features лише після оцінки tradeoffs; (5) захистити node IP через supported Tor, якщо потрібно; (6) не reuse identifying invoices; (7) вести channel і payment accounting.<sup>[[6]](#references)</sup>

**Виявлення:** node/LSP/custodian logs, channel graph/probes, payment failure/timing і on-chain funding/closure; відсутність public transaction не означає відсутність records.

## BOLT 12 offers і route blinding

**Механіка:** reusable offer створює fresh invoices і може рекламувати blinded paths, щоб payer не дізнавався clear node/path receiver.

**Переваги:** receiver privacy; reusable donation/payment endpoint без static invoice; інтегрується з Lightning onion routing.

**Недоліки:** wallet support різниться; endpoints, selected hops і funding залишаються; public contact або network endpoint може повторно ідентифікувати receiver.

**Процедура:** (1) підтвердити matching BOLT 12 support; (2) authenticate offer; (3) request fresh invoice; (4) перевірити amount/issuer/recurrence; (5) оплатити через wallet; (6) перевірити receipt/refund behavior; (7) мінімізувати node alias/contact і зберігати accounting.<sup>[[7]](#references)</sup>

**Виявлення:** wallet/LSP і first/last-hop telemetry, offer distribution account, timing/value і funding graph; route blinding навмисно обмежує visibility payer.

## Monero

**Механіка:** one-time stealth addresses приховують recipient linkage, RingCT приховує amounts, а ring signatures створюють sender ambiguity.

**Переваги:** privacy є default on chain; confidentiality sender/receiver/amount; зріла dedicated wallet/node ecosystem.

**Недоліки:** acquisition/off-ramp і endpoint/network/counterparty records; remote node бачить queries/IP; exchange support/legal treatment різниться; невеликі operational mistakes усе ще поєднують contexts.

**Процедура:** (1) acquire lawfully і зберігати basis/source; (2) встановити/перевірити official maintained wallet; (3) backup/test seed; (4) використовувати local node або documented Tor/I2P remote-node path; (5) новий subaddress для кожного payer/invoice; (6) локально маркувати contexts; (7) deliberate disclosure transaction proof/view access.<sup>[[8]](#references)</sup>

**Виявлення:** зосередитися на exchange/merchant/device/network і seized-wallet evidence; сам protocol use не є підозрілим, а public chain навмисно розкриває менше.

## Zcash fully shielded Orchard

**Механіка:** zero-knowledge proofs перевіряють shielded transfers, тоді як sender, receiver і amount зашифровані; transparent pools і pool transitions залишаються public.

**Переваги:** сильна shielded on-chain confidentiality; viewing keys підтримують scoped audit; protocol-enforced validity.

**Недоліки:** wallet/exchange support і фактичний pool choice різняться; transparent boundary timing/value correlation; network/RPC і endpoint залишаються.

**Процедура:** (1) вибрати maintained Orchard shielded-by-default wallet; (2) verify/backup; (3) lawful obtain ZEC; (4) receive на supported Unified Address і підтвердити pool; (5) надавати перевагу shielded-to-shielded; (6) використовувати supported network privacy; (7) протестувати viewing-key disclosure на small wallet перед audit.<sup>[[9]](#references)</sup>

**Виявлення:** transparent boundary і service records, wallet/network metadata та viewing keys, коли вони lawfully provided; не припускати, що всі Unified Address payments були shielded.

## Mimblewimble і Litecoin MWEB

**Механіка:** confidential transactions приховують amounts, а Mimblewimble-style aggregation прибирає традиційну address-rich history; Litecoin реалізує optional extension block поряд із transparent chain.

**Переваги:** confidential amounts і краща fungibility у private domain; efficient pruning/aggregation.

**Недоліки:** opt-in boundary peg-in/out є public і correlatable; wallet/exchange support; interactive/address model differences; network і acquisition records.

**Процедура:** (1) вибрати maintained wallet з explicit MWEB support; (2) verify/backup і test small amount; (3) acquire lawfully; (4) peg into MWEB і перевірити balance domain; (5) transact лише з compatible receiver; (6) уникати негайного distinctive peg-out; (7) зберігати private audit records.<sup>[[10]](#references)</sup>

**Виявлення:** public peg-in/out timing/value, exchange/wallet/node data і later transparent spends; internal confidential transfer details навмисно зменшені.

## Ethereum zero-knowledge privacy applications

**Механіка:** circuit доводить statement — membership, valid note ownership або authorization — не розкриваючи secret; verifier contract перевіряє доказ. Deposits, withdrawals, public inputs, events і gas все одно можуть розкрити links.

**Переваги:** programmable selective disclosure; anonymous-set applications; verifiable rules без розкриття всіх data.

**Недоліки:** contract/circuit bugs; small anonymity set; public boundaries; RPC/IP/session/analytics/gas funding; application і sanctions/legal risk.

**Процедура:** (1) точно визначити, що приховує proof; (2) використовувати audited maintained application, де lawful; (3) перевірити public inputs/events і deposit/withdraw rules; (4) розділити action wallet і gas sponsorship відповідно до protocol; (5) privacy-aware RPC/network path; (6) test with small value; (7) зберігати compliance records.<sup>[[11]](#references)</sup>

**Виявлення:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics і eventual exchange/merchant boundary. Не стверджувати, що ZK proof приховує fields, оголошені public.

## Stablecoins

**Механіка:** tokens transfer на public chain; centralized issuers можуть freeze/blacklist або redeem щодо identified accounts.

**Переваги:** price stability, liquidity і merchant support; fast settlement; simple accounting.

**Недоліки:** transparent address/amount/contract graph; gas funding; issuer і exchange identity/control; sanctions screening; зазвичай слабка anonymity.

**Процедура:** трактувати як identified payment: використовувати fresh business address лише для compartmentation, перевіряти token contract/network, тестувати small amount, захищати wallet, використовувати trusted RPC/local node, зберігати basis/source і перевіряти required parties.

**Виявлення:** complete token event graph, issuer freeze list/actions, exchange/RPC/device і gas-funding relationships.

## Cashu Chaumian e-cash

**Механіка:** mint blind-signs client-generated bearer secrets, забезпечені mint’s Bitcoin/Lightning reserves; mint може запобігати double-spend без прямого linking issuance з подальшим redemption.

**Переваги:** accountless bearer tokens; instant peer transfer; mint не може безпосередньо пов’язати blinded withdrawal зі spend; tokens можуть передаватися як data/QR.

**Недоліки:** mint custody/solvency/censorship; bearer data loss/theft; denomination/timing і Lightning boundaries; network metadata; рання software ecosystem.<sup>[[12]](#references)</sup>

**Процедура:** (1) спочатку використовувати official test mint або tiny disposable value; (2) встановити maintained wallet і перевірити backup/restore limitations; (3) authenticate mint і переглянути custody/fees; (4) mint small amount; (5) надсилати token authenticated private channel/QR; (6) receiver swaps token перед визнанням final; (7) redeem і reconcile. Ніколи не зберігати значну value у untrusted mint.

**Виявлення:** mint бачить network, issue/redeem/Lightning boundaries і spent-token set, але blinding прибирає direct token linkage; endpoints/messages і distinctive amount/timing можуть відновити links.

## Fedimint federated e-cash

**Механіка:** threshold guardians зберігають reserves і blind-sign e-cash; internal bearer transfers private від guardians, тоді як Lightning gateways bridge external payments.

**Переваги:** розподілена custody; private internal transfer; community governance; жоден guardian не контролює reserve нижче threshold.

**Недоліки:** guardian quorum/custody/software risk; gateway бачить invoices/timing; deposit/withdraw boundaries; складність client-state recovery.

**Процедура:** (1) verify federation invite/guardians/quorum/jurisdiction; (2) встановити maintained client і test recovery; (3) deposit small lawful amount; (4) використовувати fresh internal payment requests; (5) вважати gateway observer для Lightning; (6) test redemption; (7) зберігати source/tax records поза public payment data.<sup>[[13]](#references)</sup>

**Виявлення:** federation бачить aggregate issuance/redemption, gateways — external invoices, Bitcoin/Lightning — boundaries, а endpoint/communication evidence може пов’язати internal transfers.

## GNU Taler

**Механіка:** bank-integrated blind-signature e-cash має зберігати payer anonymous для merchants, тоді як merchants і income залишаються accountable.

**Переваги:** payer privacy by design; ordinary currency; merchant accountability/refunds; speculative token не потрібен.

**Недоліки:** limited deployments; exchange/bank бачить funding; merchant бачить order/delivery; wallet bearer/recovery risk; regulated operators.

**Процедура:** (1) знайти current exchange/merchant для jurisdiction/currency; (2) прочитати KYC/fees/privacy; (3) встановити official wallet; (4) lawfully withdraw із supported bank/exchange; (5) review merchant contract; (6) pay і зберігати receipt/refund data; (7) уникати зайвих merchant session identifiers.<sup>[[14]](#references)</sup>

**Виявлення:** bank/exchange withdrawal і merchant deposit є accountable boundaries; merchant order/device/delivery та timing можуть корелювати навіть за blinded coins.

## Cross-chain bridge, atomic swap і decentralized exchange

**Механіка:** contract/service locks/burns один asset і releases/mints інший, або counterparties atomically exchange. Це ламає single-ledger view, але не economic continuity.

**Переваги:** asset/network interoperability; можна уникнути одного centralized custodian; звичайне portfolio/liquidity use.

**Недоліки:** обидва chains public; time/value/fees/liquidity і contracts корелюють; bridge/relayer/frontend/RPC records; smart-contract/counterparty і regulatory risk.

**Законна процедура swaps:** (1) verify official contract/service та legal availability; (2) inspect custody/audit/fees/slippage; (3) small test; (4) записати обидва transaction IDs і rate; (5) protect approvals; (6) reconcile destination asset і revoke unnecessary approval. Не використовувати swaps для disguise source of funds.

**Виявлення:** bridge deposit/withdraw events, unique amount minus fees, time order, liquidity, relayer/RPC/frontend і later service deposits.

## Centralized mixer або tumbler

**Механіка:** service приймає deposits у pool і пізніше повертає інші units, намагаючись приховати direct input-output mapping.

**Переваги:** теоретично може збільшити transaction ambiguity.

**Недоліки:** operator може steal/log; entry/exit timing/value analysis; sanctions/money-transmission і criminal exposure; seizures можуть розкрити mappings; taint/rejection risk.

**Процедура:** operational mixing guide не надається. Безпечно відтворювати graph через [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): створювати synthetic deposits, pooled outputs, fees і delays; надати analysts incomplete mappings; виміряти, які heuristics працюють; потім розкрити ground truth.

**Виявлення:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs і downstream consolidation. Позначати probabilistic attribution.

## Peel chains, fan-out/fan-in і structuring

**Механіка:** повторні transactions відокремлюють small payments від change, розділяють value між addresses, reconverge collectors або ділять amounts, щоб уникнути review.

**Переваги:** збільшує workload наївного analyst і кількість addresses.

**Недоліки:** recognizable value/cadence/transaction continuity; consolidation і service endpoints; structuring може бути illegal; fees і operational errors.

**Процедура:** використовувати лише synthetic CSV/testnet data: генерувати великий source, repeated payment/change edges, parallel branches і один collector; додавати benign exchange-like examples; налаштовувати detection і документувати false positives.

**Виявлення:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint і off-chain records. Exchange hot wallets можуть нагадувати ці patterns, тому context обов’язковий.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker і front company

**Механіка:** інша person/account/company receives, converts або spends funds, вставляючи legal і operational layers між controller та transaction.

**Переваги для adversary:** named account не одразу ідентифікує controller; можна bridge cash, crypto, goods і jurisdictions.

**Недоліки:** identity fraud/money-laundering exposure; кожен participant додає communications, bank/company/tax/shipping records, fees, inconsistency і witnesses; facilitator reuse створює hubs.

**Процедура:** не emulювати це на real people/accounts. Створити synthetic graph із controller, recruiter, mule, OTC, shell merchant і beneficiary; додати device/IP/message/bank edges; попросити investigators відрізнити account holder від controller і зафіксувати evidence confidence.

**Виявлення:** shared device/IP/recovery, unusual beneficiary/velocity, багато unrelated senders, immediate onward movement, company/director/invoice inconsistency, communications і cash/commodity delivery.

## NFTs, gambling, merchant goods і refund loops

**Механіка:** value конвертується у self-priced asset, wagering balance, resalable goods або refunds для створення іншої transaction narrative.

**Переваги для adversary:** змінює asset form і додає marketplace/merchant intermediaries.

**Недоліки:** marketplace/account/device і wash-trade graph; odds/play і refund records; delivery/resale evidence; fees/losses; fraud/laundering liability.

**Процедура:** concealment workflow не надається. Використовувати synthetic marketplace data із related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument і common shipping; перевіряти detection на legitimate collectors/customers.

**Виявлення:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery і proceeds reconvergence.

## Physical bearer wallet або offline token transfer

**Механіка:** device, paper/QR, hardware bearer instrument або e-cash token передає control of secret, а не broadcast payment під час handover.

**Переваги:** немає live network event під час exchange; корисно offline; physical cash-like custody.

**Недоліки:** copy/theft/loss і невизначена exclusivity; subsequent redemption/broadcast links; physical meeting/shipping; counterfeit/tamper risk.

**Процедура:** (1) використовувати лише reviewed instrument/protocol; (2) privately initialize/verify authenticity; (3) load лише small lawful value; (4) transfer у documented authorized context; (5) receiver verify або sweep promptly, як вимагає protocol; (6) не припускати, що sender не зберіг copy; (7) приватно записати ownership/tax evidence.

**Виявлення:** purchase/funding і eventual sweep/redemption, device serial/tamper evidence, delivery/meeting і endpoint records.

## Merchant-scoped invoice або one-time payment request

**Механіка:** merchant створює single-use request із amount, expiry і order reference. Payer settles через supported rail без передачі merchant reusable credential; issuer/payment processor усе одно може ідентифікувати обидві сторони.

**Переваги:** обмежує credential reuse і accidental cross-merchant identifiers; exact amount/expiry зменшують errors; сумісне зі звичайним accounting/refunds.

**Недоліки:** invoice, delivery, browser, processor і issuer все одно пов’язують order; unique amount/time може посилити correlation; malicious payment links поширені.

**Процедура:** (1) незалежно authenticate merchant; (2) request fresh invoice із exact amount, asset/network і expiry; (3) inspect destination/refund rules; (4) оплатити з approved engagement compartment; (5) перевірити, що merchant підтверджує той самий invoice; (6) зберегти receipt і transaction reference; (7) expire, а не reuse request.

**Виявлення:** merchant і processor поєднують invoice, session і settlement; unique amounts/timing і delivery ідентифікують payer. **Captured wallet/device:** invoice history розкриває counterparties і purpose; мінімізувати непотрібне memo data, шифрувати device і зберігати authoritative accounting у controlled finance system.

## Prepaid service credit і capability token

**Механіка:** service перетворює conventional payment на bounded internal credits або bearer capability. Подальше API/resource use може не передавати original card кожного разу, але service часто може map issuance to redemption.

**Переваги:** обмежує spend і compromise loss; відділяє workers від funding credential; підтримує per-project budgets і revocation.

**Недоліки:** зазвичай pseudonymous, не anonymous; service database, redemption IP і unique usage pattern пов’язують activity; bearer tokens можуть бути stolen; refunds можуть вимагати original payer.

**Процедура:** (1) купити credits через organization account; (2) створити один project і budget; (3) issue narrow token із service, amount і expiry constraints; (4) зберігати лише в approved secret manager або workload identity path; (5) тестувати rejection поза scope і після expiry; (6) monitor consumption; (7) revoke і reconcile unused value.

**Виявлення:** provider поєднує funding account, project, token issuance і usage; defenders alert на geographic/process changes та anomalous consumption. **Captured node:** припускати, що remaining capability може бути spent; застосовувати short expiry, low balance, audience binding і immediate server-side revocation.

## Privacy Pass або blinded authorization token

**Механіка:** issuer створює privacy-preserving authorization token, який origin може validate без linking redemption до issuance. Він може означати paid entitlement або rate-limited access, але не є general currency. Architecture розділяє client, attester, issuer і origin roles та попереджає, що IP/timing або collusion можуть знищити unlinkability.<sup>[[18]](#references)</sup>

**Переваги:** unlinkable redemption для supported services; origin не потребує reusable account cookie; cached tokens можуть розділяти issuance і use у часі.

**Недоліки:** application-specific; issuer/attester trust і anonymity-set partitioning; IP/browser metadata залишаються; token theft або distinctive issuance timing можуть корелювати use.

**Процедура:** (1) використовувати implementation, що відповідає relevant Privacy Pass token type; (2) визначити entitlement, який доводить token; (3) розділити issuer і origin administration, якщо цього потребує threat model; (4) мінімізувати challenge metadata; (5) issue several test tokens і redeem each once на owned origins; (6) порівняти logs на forbidden stable identifiers; (7) тестувати replay, expiry та revocation/abuse controls.

**Виявлення:** origins бачать redemption IP/time і token validity; issuers/attesters — issuance context; analysts тестують timing і metadata partitions без припущення cryptographic break. **Captured client:** unspent bearer tokens можуть бути використані; обмежити value, lifetime і audience, не cache funding credential разом із ними.

## Delegated organization procurement або fiscal sponsor

**Механіка:** authorized procurement team, reseller або fiscal sponsor укладає contract і платить, а operational team отримує bounded service. Це role separation із truthful records, а не nominee або false identity.

**Переваги:** vendors не обов’язково отримують identity кожного operator або personal payment details; central compliance, tax і refund handling; чіткі budget/offboarding.

**Недоліки:** sponsor знає beneficiary і purpose; contracts, approvals, delivery і accounts залишаються; додаткові delay/fees; слабке separation, якщо одна person адмініструє всі layers.

**Процедура:** (1) document business purpose, beneficiary і approving authority; (2) select organization-approved intermediary; (3) contract under truthful details; (4) provision project-scoped subaccount без personal billing credential; (5) розділити finance administrators і operators; (6) reconcile invoices/access; (7) завершити service і delegated access після closeout.

**Виявлення:** procurement, identity-provider, vendor і delivery records поєднують chain. **Captured operational device:** має розкривати service project, але не finance credentials; зберігати invoices і payer identities у finance system, а не field nodes.

## Escrow або conditional settlement

**Механіка:** trusted escrow agent або smart contract утримує value до виконання documented conditions. Це може зменшити direct disclosure між payer і payee, тоді як escrow та underlying payment rails зберігають relationship.

**Переваги:** dispute і delivery protection; payer і merchant можуть не передавати одне одному reusable credentials; auditable release conditions.

**Недоліки:** escrow custody/contract risk, fees і identity obligations; on-chain contracts public; order, shipping і dispute data залишаються; не anonymous щодо intermediary.

**Процедура:** (1) verify legal entity, custody, fees, dispute forum і supported assets; (2) створити точний written milestone та refund path; (3) fund з approved organization account; (4) незалежно verify receipt і release authorization; (5) release лише після evidence; (6) зберегти complete audit record; (7) закрити unused permissions або contract approvals.

**Виявлення:** escrow account/contract events, funding і release time, beneficiary та dispute records розкривають transaction. **Captured device:** session tokens або contract approvals можуть дозволити release; вимагати окремого approver/MFA і revoke active sessions після втрати.

## Batched або pooled organization settlement

**Механіка:** багато approved obligations агрегуються й settle у меншій кількості bank/blockchain transactions, а private internal ledger призначає кожну частку. Batching може зменшити public per-purchase detail, але coordinator зберігає повну attribution.

**Переваги:** lower fees; менше public graph edges; приховує individual line items від public observer при aggregation; простий internal accounting.

**Недоліки:** coordinator є complete observer і high-value target; distinctive totals/timing можуть correlate; custody/reconciliation risk; при зловживанні може нагадувати structuring.

**Процедура:** (1) визначити participants і lawful obligations в accounting system; (2) встановити regular business-justified batch window, а не thresholds для обходу controls; (3) вимагати dual approval aggregate; (4) settle з authenticated recipients; (5) reconcile кожен internal line до batch; (6) вести refunds як linked corrections; (7) захистити ledger access і зберігати за policy.

**Виявлення:** coordinator ledger, approval і beneficiary records дають ground truth; public analysts обережно використовують input/output/value/time clustering. **Captured payer device:** має містити лише requisition, а не pool signing key або participant ledger.

## Account-abstraction paymaster або sponsored gas

**Механіка:** relayer/bundler подає smart-account operation, а paymaster сплачує transaction fees, усуваючи direct native-gas funding edge від user wallet. Це покращує одну властивість graph, але operation, contract і service telemetry залишаються public/observable.<sup>[[19]](#references)</sup>

**Переваги:** прибирає common gas-funding link; підтримує scoped sponsorship і rate limits; полегшує onboarding legitimate privacy applications.

**Недоліки:** paymaster/bundler/RPC/frontend можуть correlate requests; contract events і public inputs залишаються; sponsorship policy fingerprint cohort; malicious contracts/approvals можуть викрасти assets.

**Процедура:** (1) використовувати audited maintained smart account і paymaster на correct network; (2) перевірити public fields і sponsor logs; (3) обмежити sponsorship за contract, function, amount, nonce і expiry; (4) test low value; (5) submit через intended privacy-aware path; (6) verify operation і fee payer on chain; (7) revoke allowances/session keys і зберігати compliance records.

**Виявлення:** join UserOperation, EntryPoint, paymaster, bundler/RPC і application logs; обережно cluster identical sponsorship policy. **Captured wallet:** session keys і pending approvals можуть бути використані навіть без gas; жорстко обмежити scope і revoke через account recovery policy.

## Threshold або multisignature payment authorization

**Механіка:** spending вимагає threshold незалежних signers. Це не приховує transaction, але відокремлює payment authority від captured laptop, field node або single operator.

**Переваги:** сильний compromise/insider resistance; accountable approval; жоден field device не має complete signing authority; підтримує recovery.

**Недоліки:** coordination/availability; signer/device/account metadata може корелювати participants; неправильний backup спричиняє loss; public multisig patterns можуть бути identifiable.

**Процедура:** (1) визначити signers, threshold, limits і recovery до funding; (2) initialize на окремих supported hardware/accounts; (3) незалежно verify addresses/backups; (4) дати field workloads лише unsigned requisition capability; (5) вимагати out-of-band review recipient, amount і purpose; (6) test recovery і one-signer loss на small value; (7) rotate signer після compromise.

**Виявлення:** approval system, signer device і public script/contract дають evidence; defenders alert на policy або signer-set changes. **Captured node:** має розкривати максимум одну low-authority session key або unsigned request; ніколи не cache quorum material разом.

## Closed-loop community або event currency

**Механіка:** cooperative, conference або private test environment видає credits, redeemable лише між enrolled participants. Internal transfer може менше expose global payment networks, але operator контролює issuance/redemption.

**Переваги:** bounded economic domain; можна тестувати offline або privacy-preserving payment UX; обмежує external card exposure; чіткі experimental controls.

**Недоліки:** small anonymity set; operator і merchants бачать activity; limited acceptance/redemption; licensing, consumer-protection і tax rules можуть застосовуватися навіть до local value.

**Процедура:** (1) legal/compliance review і publication issuer terms; (2) enroll consenting test participants; (3) cap issuance і заборонити cash-like misuse; (4) використовувати fresh payment requests і мінімізувати public participant identifiers; (5) записувати aggregate reserves і private individual receipts; (6) test loss/refund/redemption; (7) close ledger і повернути residual value as promised.

**Виявлення:** issuer ledger, enrollment, merchant і redemption records реконструюють flows; unusual circular transfers або rapid cash-out потребують review. **Captured wallet:** local balance і counterparties можуть бути exposed; cap value, encrypt state і підтримувати issuer-side freeze/reissue з auditable record.

## Bitcoin reusable payment codes і private payment instructions

**Механіка:** BIP 47 payment codes використовують reusable public identifier плюс ECDH-derived one-time deposit addresses; BIP 351 описує новіший private-payment instruction design. Вони зменшують public address reuse, дозволяючи recipient публікувати stable payment instructions. Notification, wallet support, funding і subsequent coin selection все ще впливають на privacy.<sup>[[20]](#references)</sup>

**Переваги:** одна public instruction може створювати distinct addresses; recipient не повинен публікувати кожну invoice address; compatible wallets можуть monitor derived payments; корисно для повторних lawful donors/customers.

**Недоліки:** wallet interoperability різниться; notification transactions або published payment code пов’язують relationship context; sender, recipient і public graph бачать transactions; careless consolidation/change handling знищує benefit.

**Процедура:** (1) підтвердити, що обидва maintained wallets підтримують exact same specification/version; (2) backup і test recovery на low-value wallet; (3) out-of-band authenticate recipient payment code; (4) small lawful test; (5) перевірити fresh derived address; (6) locally label relationship і застосувати coin control; (7) test recovery/refund behavior перед використанням.

**Виявлення:** analysts перевіряють notification patterns, funding/change, later consolidation і service boundaries; public-code publication ідентифікує recipient context, навіть коли deposit addresses відрізняються. **Capture-resilient OPSEC:** тримати spend keys поза field devices і expose максимум watch-only relationship view. **Monitoring:** alert на unexpected notification transactions, reused derived addresses, wallet gap-limit/recovery errors і unplanned consolidation.

## EVM stealth addresses (ERC-5564)

**Механіка:** sender derives one-time stealth account із recipient stealth meta-address і публікує announcement з ephemeral public key та view tag. Recipient сканує announcements viewing key і виводить відповідний spend key. Recipient linkage покращується, але sender, amount/token, gas, announcement і later spending залишаються visible.<sup>[[21]](#references)</sup>

**Переваги:** non-interactive fresh receiver address; reusable meta-address; розділені viewing/spending roles; працює для supported EVM assets/applications.

**Недоліки:** announcement scanning і spam; funding gas для new address може relink; sender знає recipient; public token/amount і eventual consolidation залишаються; implementation/wallet support різняться.

**Процедура:** (1) спочатку audited maintained implementation на test network; (2) generate separate viewing/spending material і backup; (3) authenticate meta-address; (4) low-value test і announcement; (5) scan і derive stealth account; (6) test supported gas sponsorship без personal funding edge; (7) записати public fields і зберігати lawful accounting.

**Виявлення:** follow announcement caller, token/amount, timing, gas sponsor, spending і consolidation; view key може довести receipt без grant spend. **Capture-resilient OPSEC:** networked scanner має мати лише viewing role, якщо підтримується; spend/recovery keys тримати окремо. **Monitoring:** alert на malformed/spam announcements, view-key access, unexpected spend derivation і stealth outputs moved without approval.

## Liquid Confidential Transactions

**Механіка:** Liquid за замовчуванням blinds output amounts і asset types через commitments/proofs, залишаючи visible transaction graph, input/output count, fee і block time. Peg-in/peg-out і service boundaries залишаються linkable; users можуть selectively disclose blinding data.<sup>[[22]](#references)</sup>

**Переваги:** confidential amount/asset type by default; fast sidechain settlement; selective audit через blinding keys/descriptors; приховує commercially sensitive values від public observers.

**Недоліки:** graph structure і timing залишаються; federation/bridge і exchange trust; peg boundaries/unconfidential outputs; wallet/node/network records; receiver і sender знають transaction.

**Процедура:** (1) вибрати maintained Liquid wallet і verify backup model; (2) testnet або small lawful amount; (3) receive на confidential address і перевірити, що wallet marks output blinded; (4) send test confidential transaction; (5) перевірити public explorer fields; (6) export лише scoped blinding proof для audit; (7) document peg/exchange boundaries і reconcile funds.

**Виявлення:** analyze visible graph/fee/time, peg/exchange records, network metadata і later unblinding evidence; не infer hidden amount/asset. **Capture-resilient OPSEC:** separate spend seed, blinding/view data і watch-only operations. **Monitoring:** alert на accidental unconfidential addresses, unknown peg requests, descriptor changes і unapproved unblinding-key export.

## General payment або state channel

**Механіка:** participants lock funds, exchange signed off-chain state updates і публікують лише opening, closing або disputed state on chain. Intermediate payments не broadcast globally, але peers і routing/intermediary services бачать свою частину, а endpoints мають зберігати latest enforceable state.<sup>[[23]](#references)</sup>

**Переваги:** багато fast low-fee interactions із private-to-public-ledger; менше global transaction detail; bounded channel balance; корисно для metered services і repeated counterparties.

**Недоліки:** channel peers знають one another і можуть зберігати updates; opening/closing/value/timing корелюють; online monitoring може бути потрібним у challenge windows; implementation/liquidity risk; сам по собі не є великим anonymity set.

**Процедура:** (1) choose maintained audited implementation і зрозуміти dispute window; (2) open low-value test channel між owned parties; (3) exchange signed state updates із unique nonces; (4) backup latest enforceable state; (5) close cooperatively; (6) rehearse stale-state rejection на testnet; (7) preserve accounting і channel-peer records.

**Виявлення:** public chain показує lifecycle/disputes; peers, watch services і application transport показують off-chain timing/parties. **Capture-resilient OPSEC:** cap hot balance і зберігати latest signed state в encrypted recoverable store окремо від field nodes. **Monitoring:** постійно стежити за stale-state publication, missed backup, peer-key change і approaching challenge deadline.

## Mobile carrier billing

**Механіка:** online service списує purchase з mobile subscription або prepaid balance через carrier billing system. Merchant може отримати carrier authorization замість card/bank details, тоді як carrier знає subscriber/line, device/network context, merchant, amount і time.<sup>[[24]](#references)</sup>

**Переваги:** merchant не отримує card number; широка phone availability; придатне для low-value digital goods; carrier може cap і reverse charges.

**Недоліки:** strongly identified через SIM/account і часто device; малі limits і високі fees; merchant-category restrictions; account takeover/SIM-swap risk; carrier і aggregator створюють повний transaction trail.

**Процедура:** (1) підтвердити availability, limit, fee і refund terms організаційного carrier account; (2) вмикати лише на dedicated organization line, якщо виправдано; (3) встановити lowest useful spend cap; (4) купити benign test item; (5) verify merchant/carrier receipts; (6) disable recurring authorization; (7) reconcile і вимкнути feature після assessment.

**Виявлення:** carrier, aggregator і merchant records поєднують line, subscriber, IP/device і charge; enterprise telecom invoices розкривають це. **Capture-resilient OPSEC:** не використовувати personal number і вимагати carrier-account MFA поза field device. **Monitoring:** enable instant charge/SIM-change alerts і зупинятися при unexpected premium-service enrollment, forwarding або account recovery.

## Open-banking payment initiation

**Механіка:** за explicit user consent regulated PISP просить account-servicing bank initiate transfer. Merchant може не отримати card credentials, але PISP і banks зберігають regulated payer, payee, consent, device і transaction records.<sup>[[25]](#references)</sup>

**Переваги:** немає reusable card number на checkout; strong bank authentication; exact account-to-account settlement; consent/status APIs; clear reconciliation.

**Недоліки:** не anonymous щодо banks/PISP; payee часто бачить legal account details або reference; phishing/redirect risk; jurisdiction/refund protections різняться; consent metadata додає observer.

**Процедура:** (1) перевірити, що PISP regulated, а merchant callback domain authentic; (2) починати з merchant request; (3) у bank review payee, amount, reference і requested consent; (4) authorize лише single payment; (5) independently verify final status; (6) revoke residual consent; (7) зберегти receipt і reconcile.

**Виявлення:** bank/PISP/merchant logs і transfer references дають strong attribution. **Capture-resilient OPSEC:** тримати banking authentication/recovery поза operational/field devices; device має містити лише paid-service entitlement. **Monitoring:** bank transaction/consent alerts; розслідувати нові PISP grants, changed payee або status callbacks поза expected session.

## Platform wallet, app-store balance або in-app credit

**Механіка:** platform bills user або redeems account credit, потім видає signed receipt/entitlement application. App developer може не отримати original funding instrument, тоді як platform maps account, device, funding, product і redemption.<sup>[[26]](#references)</sup>

**Переваги:** merchant/developer не отримує primary PAN; fraud/refund і family/business controls; small prepaid balance обмежує exposure; signed receipts спрощують entitlement verification.

**Недоліки:** platform account є strong identity/behavior hub; device і storefront geography; gift-balance purchase/redemption trail; limited cash-out; fraud controls можуть freeze funds; це не cross-platform money.

**Процедура:** (1) використовувати organization-managed platform account, якщо policy дозволяє; (2) review funding, region, refund і transferable-value rules; (3) додати лише approved budget; (4) купити benign product через official store; (5) перевірити, що application отримує лише expected receipt fields; (6) disable recurring purchase; (7) reconcile і remove account з operational hardware.

**Виявлення:** platform receipts/server notifications, account/device login і funding records реконструюють purchase. **Capture-resilient OPSEC:** ніколи не входити з field node у personal store account; передавати лише scoped app entitlement, якщо можливо. **Monitoring:** enable new-device/purchase alerts; investigate receipt replay, family/account changes або unexpected restore events.

## Mutual credit, clearing або periodic net settlement

**Механіка:** participants записують obligations у private ledger і періодично settle лише кожну net position. Окремі service events можуть не створювати окремі public payments, але ledger operator і counterparties зберігають детальну attribution.

**Переваги:** менше external transactions і fees; public observers бачать лише net settlement; працює для repeated organizations; explicit credit limits обмежують exposure.

**Недоліки:** centralized ledger є повним evidence і fraud target; counterparty/default risk; legal/accounting/tax duties; small membership set; unusual net transfers все одно можуть розкрити relationships.

**Процедура:** (1) використовувати лише identified consenting organizations із legal/accounting approval; (2) визначити unit, credit limit, settlement interval і dispute rules; (3) immutable approval для кожного obligation; (4) окремі finance roles рахують і approve net positions; (5) settle через ordinary lawful rail; (6) reconcile individual lines із settlement; (7) close access і retain records за policy.

**Виявлення:** ledger, invoices, approvals і final bank/chain settlement дають ground truth; analysts не повинні infer missing gross activity лише з net transfer. **Capture-resilient OPSEC:** operational devices можуть submit bounded requisitions, але не edit balances або authorize settlement. **Monitoring:** alert на credit-limit breach, backdated entries, administrator changes, reconciliation mismatch і settlement to new beneficiary.

## Матриця exposure під час capture/compromise

Це застосовується як seizure/loss test до кожного family. Мета — обмежити spend authority і unrelated identity disclosure, зберігаючи lawful accounting, а не стирати transactions або перешкоджати investigation.

| Сімейство технік | Що може розкрити captured wallet/device/account | Мінімальний authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value і physical contacts | носити лише approved amount; окремий private accounting; prompt loss report; no false records |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption і account/session tokens | low balance; одна purpose; truthful registration; issuer freeze/revocation |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery і merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; no shared recovery account |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices і project | role separation; least-privilege subaccount; finance credentials never on operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator або dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph і network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP і payment database | minimal hot balance; encrypted backup; separate node identity; close/recover за documented plan |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC і boundary transactions | separate spend/view roles; hardware support; no exchange session on field node |
| Stablecoins, swaps, bridges і DEX | transparent graph, approvals, RPC/front-end state і destination assets | revoke allowances; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; encrypted backup; redeem/reissue; never colocate funding credential |
| Paymaster, multisig/threshold | session key, one signer, pending operations і sponsor policy | narrow session key; independent quorum; signer rotation; field device cannot reach threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph і participant records | no operational use; emulate лише synthetic/testnet evidence |
| Community/event currency | enrollment, local balance, counterparties і redemption | capped value; issuer freeze/reissue; consent і private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements і derived outputs | watch/view-only network role; offline/hardware spend role; no personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries і disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device і funding source | organization account; external MFA; low limit; no personal account on field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals і settlement ledger | operational requisition only; separate immutable ledger і dual finance approval |

## Monitoring possible discovery або payment compromise

Payment denial, compliance review або wallet offline не доводять наявність investigation. Monitor лише accounts, ledgers і infrastructure, які organization має право спостерігати; ніколи не probe providers або counterparties, щоб перевірити їхню співпрацю з investigators.

| Охоплені техніки | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund або loss report | missing instrument, redemption outside approved order, altered receipt або custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap або recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice і consumption | cross-project token, unknown admin, limit breach, invoice mismatch або unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation і beneficiary change | altered amount/payee, backdated ledger, unilateral release або unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels і consolidation | unknown spend, reused recipient output, wallet gap/recovery failure або unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure або coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP і chain dispute | unknown invoice payment, peer-key change, stale close або approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor і boundary transaction | spend without approval, transparent/unconfidential downgrade, key export або unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key і issuer action | wrong contract/public field, unknown approval/spend, paymaster change або issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway і bearer balance | unknown redemption, mint key/terms change, restore failure або balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate і destination | contract/route mismatch, unlimited approval, missing destination або bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum і recovery audit | unknown proposal/signer, threshold reduction, recovery activation або policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | synthetic lab ground truth і detection output only | будь-який real account, person або value входить в emulation: негайно stop |

## Workflow вибору і перевірки

1. Визначити, яка party не повинна дізнатися яке field.
2. Визначити issuer/mint/custodian, public ledger, network/RPC, merchant і physical observers.
3. Перевірити current support, legality, limits, custody, recovery і refund behavior.
4. Виконати small lawful end-to-end test.
5. Перевірити merchant receipt, provider statement, public chain і wallet/node logs.
6. Протестувати backup/recovery і deliberate audit disclosure.
7. Зберігати required source, ownership, tax, sanctions і engagement records accurate, але access-controlled.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Observations on data collection by large payment platforms](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Protect your privacy](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — A Simple Payjoin Proposal](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technical specifications and network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Building privacy applications with zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol and privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — How it works](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers and users of virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information and crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — The Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
