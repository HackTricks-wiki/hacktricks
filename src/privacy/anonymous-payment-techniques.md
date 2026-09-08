# Каталог технік анонімних платежів

Цей каталог охоплює **сімейства** платежів — від звичайної готівки до e-cash із blind signatures та обфускації в public-chain. «Анонімний» завжди означає анонімний відносно конкретного спостерігача. Merchant, issuer, mint, exchange, blockchain analyst, network provider, employer і фізичний спостерігач бачать різні факти.

Наведені процедури призначені для законних коштів, правдивих облікових записів і дозволених закупівель. Техніки, метою яких у наведених випадках були laundering, sanctions evasion або identity fraud, пояснюються та виявляються, але їхня процедура є синтетичною forensic-вправою, а не інструкцією зі скоєння злочину.

## Coverage matrix

| Сімейство | Основна властивість приватності | Основний спостерігач/рівень довіри | Статус |
|---|---|---|---|
| Cash and cash equivalents | відсутність віддаленого запису в платіжній мережі | одержувач і фізичне середовище | законний workflow |
| Prepaid/gift/voucher value | відокремлює redemption від основної картки | seller, issuer і redemption service | законний workflow, залежить від юрисдикції |
| Virtual/tokenized card | приховує повторно використовуваний PAN або розділяє merchants | issuer/network/wallet усе одно ідентифікує платника | законний workflow |
| Payment app/intermediary | merchant може бачити alias/intermediary | app збирає identity/device/transaction | базове порівняння |
| Bitcoin hygiene/Silent Payments | pseudonyms і unlinkability одержувача | public graph і межа wallet/network | deployable |
| PayJoin/CoinJoin | послаблює евристики спільного володіння/зв’язку | participants/coordinator/network/public graph | deployable, де підтримується; потрібен legal review |
| Lightning/BOLT 12 | off-chain routing і зменшення шляху до одержувача | endpoints, hops, services і channel graph | deployable, де підтримується |
| Monero/Zcash/MWEB | on-chain confidentiality на рівні протоколу | acquisition, endpoint, network і межі | deployable, де це законно/підтримується |
| Ethereum ZK application | приховує визначений statement/action link | public inputs, RPC, relayer і app | залежить від застосунку |
| Cashu/Fedimint/Taler | приватність платника через blind signatures | mint/federation/exchange custody і межі | emerging/deployment-specific |
| Stablecoins | зручний digital settlement | transparent chain плюс issuer freeze/control | не є базовим анонімним варіантом |
| Swaps/bridges/DEX | переміщує value між assets/chains | обидва graphs, contracts і providers | forensic mechanics; лише звичайні законні swaps |
| Mixers/peel/structuring | збільшує неоднозначність/складність graph | entry/exit graph і service records | лише синтетична вправа з виявлення |
| Nominees/mules/OTC/fronts | додає людських/бізнес-посередників | facilitators, banks, communications | лише аналіз criminal abuse |
| Reusable/stealth payment addresses | нова адреса одержувача для кожного платежу | public announcement/notification і wallet boundaries | deployable, де підтримується |
| Confidential sidechain/state channel | приховує amount/asset або проміжні оновлення | peers, bridge/federation і lifecycle settlement | залежить від протоколу |
| Carrier/open-banking/platform billing | приховує основну картку від merchant | carrier, bank/PISP або platform ідентифікує клієнта | звичайний ідентифікований платіж |
| Mutual credit/net settlement | менше зовнішніх settlement records | private ledger operator має повне зіставлення | лише ідентифіковані учасники |

## Cash

**Mechanics:** фізична bearer value переходить з рук у руки без online issuer authorization або public ledger.

**Pros:** merchant не обов’язково дізнається bank/card identity; немає remote transaction graph; широко зрозумілий і остаточний спосіб.

**Cons:** лише face-to-face; крадіжка/втрата; контроль здачі/чека/серійного номера або reporting; withdrawal, cameras, witnesses і location усе одно можуть пов’язати платника.

**Procedure:** (1) підтвердити, що cash є законною та прийнятною, а також перевірити правила щодо суми/reporting; (2) законно зняти або отримати кошти й вести приватний облік; (3) оплатити звичайному merchant без зайвих loyalty/account identifiers; (4) попросити лише обов’язковий receipt; (5) не надавати shipping/account data, якщо покупка цього не потребує; (6) внутрішньо зафіксувати законну business purpose.

**Detection:** звіряти till/receipt/inventory, cameras і access logs відповідно до policy; розслідувати незвичні cash refunds або повторювані суми трохи нижче контрольного порога, не вважаючи звичайне використання cash підозрілим саме по собі.

## Money order, postal order, cashier instrument and cash on delivery

**Mechanics:** regulated issuer перетворює cash/account funds на numbered instrument, payable named recipient; COD відкладає collection до delivery.

**Pros:** recipient може не отримати primary bank/card number платника; придатний там, де cash не можна переслати дистанційно; чіткий receipt.

**Cons:** issuer/retailer зберігає purchase/identity data відповідно до вимог; serial tracking; recipient/delivery address; ризик втрати/шахрайства й регіональні обмеження; зазвичай не anonymous.

**Procedure:** (1) перевірити правила issuer, limits, identification і прийняття recipient; (2) купувати з правдивими даними та законними коштами; (3) негайно заповнити payee/amount; (4) зберегти serial/receipt; (5) використовувати tracked delivery відповідно до вартості; (6) звірити redemption/refund.

**Detection:** issuer purchase/redemption record, instrument serial, retailer/camera, shipping і recipient account; виявляти alteration, duplicate serials і швидке географічно несумісне redemption.

## Open-loop prepaid card

**Mechanics:** network-branded stored-value credential авторизується проти prepaid balance, а не основного credit account.

**Pros:** обмежує merchant exposure і втрати; відокремлює merchant від main PAN; придатна online там, де приймається.

**Cons:** purchase/activation/reload/registration і device records; KYC та limits відрізняються; billing-address failures; обмеження cash-out/refund; «no name» не означає відсутність issuer record.

**Procedure:** (1) перевірити актуальні issuer identity, fees, KYC, geography та online/recurring support; (2) придбати через authorized seller за законні кошти; (3) зареєструвати правдиві обов’язкові дані; (4) використовувати для однієї compartment/purpose; (5) не структурувати loads і не вигадувати residency; (6) зберігати purchase/expense evidence та закрити/утилізувати картку відповідно до issuer terms.

**Detection:** поєднувати seller/activation, funding, device/IP, merchant authorization, balance checks і redemption/refund. Важливіші patterns, ніж сам prepaid label.

## Closed-loop gift card, voucher and transferable service credit

**Mechanics:** numbered value можна redeem лише в одного merchant/service або ecosystem. Airtime/game/store credits є варіантами.

**Pros:** merchant-одержувач може бачити лише code/balance; обмежений blast radius; зручні gifting і budget separation.

**Cons:** seller і service log purchase/activation/redemption; account/device/delivery усе ще пов’язують активність; scams, resale discounts і expiry/region limits; слабкі refund rights.

**Procedure:** (1) купувати лише через authorized channels; (2) записати code value, не розкриваючи secret; (3) не прив’язувати identifying loyalty account, якщо це не потрібно; (4) redeem через окремий legitimate merchant account/context; (5) зберігати receipt до прийняття; (6) ніколи не купувати codes на неочікувану вимогу щодо «tax/support/ransom».

**Detection:** code issuance/redemption time, device/account convergence, bulk/threshold-pattern purchase, один device, що перевіряє багато balances, і швидке віддалене redemption.

## Cryptocurrency-funded card or gift-code broker

**Mechanics:** intermediary приймає cryptocurrency і видає card, voucher або merchant code. Це cross-rail conversion: merchant бачить звичайну card/gift value, а broker пов’язує on-chain deposit з issuance і delivery.

**Pros:** merchant не отримує funding wallet; корисно для законних merchants, які не приймають crypto; обмежена stored value.

**Cons:** не anonymous від broker/issuer; KYC, sanctions, exchange і card-program rules; public deposit graph; account/device/email і code redemption повторно з’єднують обидві сторони; scam/insolvency risk.

**Procedure:** (1) перевірити legal entity, card issuer, supported jurisdiction, KYC, fees і refund policy; (2) використовувати лише законні документовані кошти; (3) протестувати найменшу denomination; (4) перевірити network/merchant restrictions до purchase; (5) зберегти blockchain transaction і broker receipt для accounting; (6) ніколи не використовувати broker, який обіцяє identity fraud, sanctions bypass або «untraceable» cash-out.

**Detection:** корелювати broker deposit addresses, unique amount/time, account/device і issued-card authorization або gift-code redemption; issuer і broker records поєднують public chain із merchant.

## Virtual or merchant-locked card

**Mechanics:** issuer пов’язує generated PAN/token із real account, часто обмежуючи merchant, amount або expiration.

**Pros:** запобігає розкриттю reusable PAN; merchant compartmentation; spend limits і просте revocation; зрілий fraud control.

**Cons:** issuer усе одно знає payer, funding, merchant, device/IP і time; merchant бачить account/delivery; деякі refunds/recurring charges не працюють; не anonymous.

**Procedure:** (1) використовувати official feature regulated issuer; (2) створити card для одного merchant/engagement; (3) встановити найменші корисні limit і expiry; (4) використовувати точний billing там, де потрібно; (5) перевірити statement descriptor/refund behavior; (6) freeze/delete після final settlement, зберігши audit evidence.

**Detection:** issuer token-to-account mapping, merchant authorization, device і delivery. Defenders використовують merchant-specific reuse, velocity і account-takeover signals.

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization замінює PAN на constrained credential, часто прив’язаний до device, merchant або payment scenario.<sup>[[1]](#references)</sup>

**Pros:** merchant не отримує reusable PAN; device cryptography/dynamic data зменшують cloning; можна revoke без заміни card.

**Cons:** issuer, token service, wallet platform і network зберігають mappings/transactions; device/platform account і location можуть ідентифікувати платника.

**Procedure:** (1) enroll легітимну card в official wallet; (2) захистити platform account/device сильною authentication; (3) перевірити device token/last digits під час purchase; (4) вимкнути непотрібні location/analytics, якщо підтримується; (5) негайно видалити token із втрачених devices; (6) перевірити issuer і wallet records.

**Detection:** token requestor/device cryptogram та issuer mapping, wallet/account telemetry, merchant terminal і physical evidence.

## Payment app, marketplace wallet and centralized intermediary

**Mechanics:** service підтримує accounts і transfers внутрішньо або через bank/card rails; merchant може бачити alias, тоді як service бачить обидві сторони.

**Pros:** зручність, dispute/refund mechanisms; recipient не обов’язково бачить bank/card details.

**Cons:** централізований identity/social/transaction/device graph; freezes і legal process; counterparties можуть розкрити profile; data use може перевищувати payment necessity.<sup>[[2]](#references)</sup>

**Procedure:** (1) прочитати identity, privacy, retention і buyer-protection terms; (2) мінімізувати optional profile/contact synchronization; (3) використовувати окремий правдивий account лише коли це дозволяють terms; (4) увімкнути MFA/alerts; (5) перевірити recipient та privacy memo/profile; (6) export records і закрити невикористані links.

**Detection:** provider account, device/IP, contact graph, funding/withdrawal, memo і merchant records. Alias — це pseudonymity відносно counterparty, а не anonymity відносно platform.

## Bank transfer, ACH, wire and instant-account payment

**Mechanics:** regulated institutions переміщують value між identified accounts і обмінюються обов’язковими payment data.

**Pros:** швидкий, accountable, у деяких випадках reversible, сильні records; virtual account numbers можуть зменшити merchant disclosure.

**Cons:** banks/processors знають обидві сторони; statements і references; не anonymous; cross-border і Travel Rule/AML data.

**Procedure:** використовувати лише коли accountability прийнятна: незалежно перевіряти beneficiary, мінімізувати optional memo data, використовувати bank-provided virtual account/reference, якщо доступно, увімкнути alerts, зберігати invoice і reconcile.

**Detection:** deterministic bank/payment records, beneficiary/account ownership, device/session і fraud controls. Це baseline, а не anonymity technique.

## Account and merchant compartmentation

**Mechanics:** окремі законні identities/accounts, email aliases, cards і delivery contexts не дають unrelated merchants тривіально об’єднати activity, хоча issuer/controller зберігає mapping.

**Pros:** зменшує breach і cross-merchant linkage; легко audit; сумісно з regulated payments.

**Cons:** provider усе одно зіставляє compartments; recovery phone/device/IP і shipping можуть повторно з’єднати їх; policy може забороняти multiple accounts.

**Procedure:** (1) визначити одну purpose; (2) створювати лише terms-compliant aliases/subaccounts; (3) використовувати merchant-specific token/card; (4) вимкнути cross-account contact/ad personalization; (5) вести encrypted controller ledger; (6) retire identifiers після завершення refunds/retention needs.

**Detection:** providers об’єднують recovery, device, funding і IP; merchants — delivery, browser і account behavior. Defenders мають відрізняти законну compartmentation від synthetic identity fraud.

## Controlled red-team procurement

**Mechanics:** SOC не знає про purchase, тоді як exercise controller зберігає mapping legal entity, operator і infrastructure.

**Pros:** реалістична detection exercise; відсутність personal exposure; негайне deconfliction і audit.

**Cons:** не anonymous для organization/provider; governance overhead; leaks, якщо controller ledger оброблено неналежно.

**Procedure:** (1) виділити engagement-specific organization card/wallet/budget; (2) розділити purchaser/operator roles; (3) записати asset, amount, service, purpose і kill date; (4) зберігати attribution mapping з обмеженим controller access; (5) ніколи не використовувати false identity/mule/stolen funds; (6) після завершення розкрити/reconcile indicators і refunds.

**Detection:** controller зіставляє provider invoice і asset; SOC перевіряє незалежне виявлення через domain, certificate, hosting і traffic, а не через cardholder data.

## Bitcoin address hygiene and coin control

**Mechanics:** fresh receive addresses, local labeling і selective UTXO spending зменшують address reuse та випадкове об’єднання compartments у public ledger.

**Pros:** широко підтримується; self-custodial; уникає найпростішого public linkage.

**Cons:** усі transactions/amounts залишаються public; common-input/change/timing і подальше consolidation пов’язують activity; acquisition/RPC/network records залишаються.

**Procedure:** (1) встановити/перевірити maintained wallet; (2) створити backup і протестувати seed recovery; (3) використовувати нову address для кожного invoice; (4) локально маркувати source/purpose; (5) застосовувати coin control, щоб не об’єднувати contexts; (6) надавати перевагу local node або privacy-aware connection; (7) переглядати change/fees і зберігати законний accounting.<sup>[[3]](#references)</sup>

**Detection:** address graph, common-input/change heuristics з урахуванням uncertainty, exact amount/time, consolidation, service deposits, node/RPC broadcast timing і off-chain records.

## Bitcoin Silent Payments

**Mechanics:** BIP 352 дозволяє receiver публікувати static code, а senders виводять унікальні Taproot outputs через ECDH; зовнішні observers не можуть безпосередньо пов’язати outputs із code.<sup>[[4]](#references)</sup>

**Pros:** reusable public identifier без address reuse; немає interactive address request або notification output; змішується з Taproot outputs.

**Cons:** receiver має виконувати scanning; wallet support відрізняється; amount/sender graph і spending залишаються public; index server може бачити scans.

**Procedure:** (1) вибрати current BIP 352 wallet; (2) backup/test descriptor і scanning recovery; (3) створити labeled code, якщо підтримується; (4) authenticate published code; (5) sender переглядає inputs і надсилає small test; (6) receiver сканує, бажано через власний node; (7) зберігати received UTXOs окремо.

**Detection:** за самим output надійно визначити не можна — це задумано; analysts використовують sender inputs, amount/time, later spending, wallet/network/index і counterparty records.

## PayJoin

**Mechanics:** payer і payee додають inputs до однієї payment transaction, руйнуючи припущення, що всі inputs належать одному owner.<sup>[[5]](#references)</sup>

**Pros:** звичайний payment із покращеною privacy; послаблює common heuristic для ширшого graph; не потребує equal-output crowd.

**Cons:** потрібні interaction/support; receiver endpoint availability; amount і final transaction public; implementation і fallback metadata.

**Procedure:** (1) переконатися, що обидва maintained wallets підтримують ту саму PayJoin version; (2) authenticate invoice/endpoint; (3) почати з wallet PayJoin-enabled payment URI; (4) перевірити final amount/fee і підписувати лише очікувані inputs; (5) не виконувати manual transaction surgery; (6) verify broadcast і receipt; (7) зафіксувати fallback, якщо negotiation fails.

**Detection:** blockchain analysts не повинні автоматично об’єднувати inputs за common ownership; endpoint/provider може log negotiation; використовувати wallet/network і later-spend evidence, а не лише transaction shape.

## CoinJoin

**Mechanics:** кілька participants спільно створюють transaction із багатьма inputs/outputs, часто рівних denominations, збільшуючи неоднозначність відповідності input-output.

**Pros:** більша on-chain ambiguity set; існують self-custodial designs; measurable round structure.

**Cons:** coordinator/peer/network metadata; fees/liquidity; identifiable transaction shape; toxic change і подальше consolidation знищують gains; legal/provider availability varies.

**Procedure:** (1) перевірити current wallet/coordinator availability і legality; (2) встановити official wallet і зробити backup; (3) використовувати лише lawful UTXOs; (4) зрозуміти denomination, fee і coordinator model; (5) маркувати/separate change і mixed outputs; (6) ніколи не об’єднувати їх разом; (7) маршрутизувати network traffic лише офіційно підтримуваним способом і зберігати accounting.

**Detection:** ідентифікувати collaborative structure без припущення про crime; розрахувати можливі mappings/anonymity set, потім відстежувати change/consolidation, service boundaries і network/coordinator records.

## Lightning Network

**Mechanics:** HTLC payments проходять через onion-routed channels; більшість payment details не публікується on chain, тоді як funding/closing і public channel information публічні.

**Pros:** швидко, low fee; intermediaries зазвичай бачать лише сусідні hops; звичайні payment details залишаються off chain.

**Cons:** sender/receiver і first/last hop знають більше; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets ідентифікують users.

**Procedure:** (1) усвідомлено вибрати self-custodial або custodial; (2) перевірити wallet/seed/channel recovery; (3) використовувати invoice для exact payment; (4) використовувати private channels/LSP features лише після оцінки tradeoffs; (5) захищати node IP через підтримуваний Tor, якщо потрібно; (6) не повторно використовувати identifying invoices; (7) вести channel і payment accounting.<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs, channel graph/probes, payment failure/timing і on-chain funding/closure; відсутність public transaction не означає відсутність records.

## BOLT 12 offers and route blinding

**Mechanics:** reusable offer створює fresh invoices і може рекламувати blinded paths, тому payer не мусить дізнаватися receiver's clear node/path.

**Pros:** receiver privacy; reusable donation/payment endpoint без static invoice; інтеграція з Lightning onion routing.

**Cons:** wallet support varies; endpoints, selected hops і funding залишаються; public contact або network endpoint може повторно ідентифікувати receiver.

**Procedure:** (1) підтвердити matching BOLT 12 support; (2) authenticate offer; (3) request fresh invoice; (4) review amount/issuer/recurrence; (5) pay через wallet; (6) verify receipt/refund behavior; (7) мінімізувати node alias/contact і зберігати accounting.<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP і first/last-hop telemetry, offer distribution account, timing/value і funding graph; route blinding навмисно обмежує visibility payer.

## Monero

**Mechanics:** one-time stealth addresses приховують recipient linkage, RingCT приховує amounts, а ring signatures забезпечують sender ambiguity.

**Pros:** privacy є default on chain; confidentiality sender/receiver/amount; зріла dedicated wallet/node ecosystem.

**Cons:** acquisition/off-ramp та endpoint/network/counterparty records; remote node бачить queries/IP; exchange support/legal treatment varies; невеликі operational mistakes усе ще можуть поєднати contexts.

**Procedure:** (1) acquire lawfully і зберігати basis/source; (2) встановити/перевірити official maintained wallet; (3) backup/test seed; (4) використовувати local node або documented Tor/I2P remote-node path; (5) використовувати нову subaddress для кожного payer/invoice; (6) локально маркувати contexts; (7) навмисно розкривати transaction proof/view access лише за потреби.<sup>[[8]](#references)</sup>

**Detection:** зосередитися на exchange/merchant/device/network і seized-wallet evidence; саме protocol use не є підозрілим, а public chain навмисно розкриває менше.

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs перевіряють shielded transfers, тоді як sender, receiver і amount зашифровані; transparent pools і pool transitions залишаються public.

**Pros:** сильна shielded on-chain confidentiality; viewing keys можуть підтримувати scoped audit; protocol-enforced validity.

**Cons:** wallet/exchange support і фактичний вибір pool різняться; transparent boundary timing/value correlation; network/RPC і endpoint залишаються.

**Procedure:** (1) вибрати maintained Orchard shielded-by-default wallet; (2) verify/backup; (3) отримати ZEC законно; (4) receive до supported Unified Address і підтвердити pool; (5) надавати перевагу shielded-to-shielded; (6) використовувати supported network privacy; (7) протестувати viewing-key disclosure на small wallet до audit.<sup>[[9]](#references)</sup>

**Detection:** transparent boundary і service records, wallet/network metadata та viewing keys, якщо їх lawfully надано; не припускати, що всі Unified Address payments були shielded.

## Mimblewimble and Litecoin MWEB

**Mechanics:** confidential transactions приховують amounts, а Mimblewimble-style aggregation видаляє звичайну address-rich history; Litecoin реалізує optional extension block поряд із transparent chain.

**Pros:** confidential amounts і покращена fungibility у private domain; efficient pruning/aggregation.

**Cons:** opt-in boundary peg-in/out є public і correlatable; wallet/exchange support; interactive/address model differences; network і acquisition records.

**Procedure:** (1) вибрати maintained wallet з explicit MWEB support; (2) verify/backup і протестувати small amount; (3) acquire lawfully; (4) peg into MWEB і перевірити balance domain; (5) transact лише з compatible receiver; (6) уникати immediate distinctive peg-out; (7) зберігати private audit records.<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value, exchange/wallet/node data і later transparent spends; internal confidential transfer details навмисно зменшені.

## Ethereum zero-knowledge privacy applications

**Mechanics:** circuit доводить statement — membership, valid note ownership або authorization — без розкриття secret; verifier contract перевіряє proof. Deposits, withdrawals, public inputs, events і gas усе ще можуть розкривати links.

**Pros:** programmable selective disclosure; anonymous-set applications; verifiable rules без розкриття всіх data.

**Cons:** contract/circuit bugs; small anonymity set; public boundaries; RPC/IP/session/analytics/gas funding; application і sanctions/legal risk.

**Procedure:** (1) точно визначити, що приховує proof; (2) використовувати audited maintained application там, де це законно; (3) перевірити public inputs/events і deposit/withdraw rules; (4) розділити action wallet і gas sponsorship відповідно до protocol design; (5) використовувати privacy-aware RPC/network path; (6) тестувати з small value; (7) зберігати compliance records.<sup>[[11]](#references)</sup>

**Detection:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics і eventual exchange/merchant boundary. Не стверджувати, що ZK proof приховує fields, оголошені public.

## Stablecoins

**Mechanics:** tokens transfer через public chain; centralized issuers можуть freeze/blacklist або redeem проти identified accounts.

**Pros:** price stability, liquidity і merchant support; fast settlement; simple accounting.

**Cons:** transparent address/amount/contract graph; gas funding; issuer і exchange identity/control; sanctions screening; загалом слабка anonymity.

**Procedure:** розглядати як identified payment: використовувати fresh business address лише для compartmentation, перевіряти token contract/network, тестувати small amount, захищати wallet, використовувати trusted RPC/local node, зберігати basis/source і screen required parties.

**Detection:** повний token event graph, issuer freeze list/actions, exchange/RPC/device і gas-funding relationships.

## Cashu Chaumian e-cash

**Mechanics:** mint blind-signs client-generated bearer secrets, забезпечених mint's Bitcoin/Lightning reserves; він може запобігати double-spend без прямого зіставлення issuance з подальшим redemption.

**Pros:** accountless bearer tokens; instant peer transfer; mint не може безпосередньо пов’язати blinded withdrawal зі spend; tokens можуть передаватися як data/QR.

**Cons:** mint custody/solvency/censorship; bearer data loss/theft; denomination/timing і Lightning boundaries; network metadata; early software ecosystem.<sup>[[12]](#references)</sup>

**Procedure:** (1) спочатку використовувати official test mint або tiny disposable value; (2) встановити maintained wallet і перевірити backup/restore limitations; (3) authenticate mint та review custody/fees; (4) mint small amount; (5) send token через authenticated private channel/QR; (6) receiver swaps token до того, як вважати його final; (7) redeem і reconcile. Ніколи не зберігати meaningful value у untrusted mint.

**Detection:** mint бачить network, issue/redeem/Lightning boundaries і spent-token set, але blinding усуває direct token linkage; endpoints/messages і distinctive amount/timing можуть відновити links.

## Fedimint federated e-cash

**Mechanics:** threshold guardians зберігають reserves і blind-sign e-cash; internal bearer transfers private від guardians, тоді як Lightning gateways з’єднують external payments.

**Pros:** розподіляє custody; private internal transfer; community governance; жоден guardian не контролює reserve нижче threshold.

**Cons:** guardian quorum/custody/software risk; gateway бачить invoices/timing; deposit/withdraw boundaries; client-state recovery complexity.

**Procedure:** (1) перевірити federation invite/guardians/quorum/jurisdiction; (2) встановити maintained client і протестувати recovery; (3) deposit small lawful amount; (4) використовувати fresh internal payment requests; (5) розглядати gateway як observer для Lightning; (6) протестувати redemption; (7) зберігати source/tax records поза public payment data.<sup>[[13]](#references)</sup>

**Detection:** federation бачить aggregate issuance/redemption, gateways — external invoices, Bitcoin/Lightning — boundaries, а endpoint/communication evidence може пов’язати internal transfers.

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash прагне зберігати payer anonymous для merchants, водночас merchants і income залишаються accountable.

**Pros:** payer privacy by design; ordinary currency; merchant accountability/refunds; speculative token не потрібен.

**Cons:** limited deployments; exchange/bank бачить funding; merchant бачить order/delivery; wallet bearer/recovery risk; regulated operators.

**Procedure:** (1) знайти current exchange/merchant для jurisdiction/currency; (2) прочитати KYC/fees/privacy; (3) встановити official wallet; (4) lawfully withdraw із supported bank/exchange; (5) review merchant contract; (6) pay і зберегти receipt/refund data; (7) уникати unnecessary merchant session identifiers.<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal і merchant deposit є accountable boundaries; merchant order/device/delivery і timing можуть корелювати, навіть коли coins blinded.

## Cross-chain bridge, atomic swap and decentralized exchange

**Mechanics:** contract/service locks/burns one asset і releases/mints another, або counterparties atomically exchange. Це розділяє single-ledger view, але не economic continuity.

**Pros:** asset/network interoperability; можна уникнути одного centralized custodian; звичайне portfolio/liquidity use.

**Cons:** обидва chains public; time/value/fees/liquidity і contracts корелюють; bridge/relayer/frontend/RPC records; smart-contract/counterparty і regulatory risk.

**Procedure for lawful swaps:** (1) перевірити official contract/service і legal availability; (2) перевірити custody/audit/fees/slippage; (3) використати small test; (4) записати обидва transaction IDs і rate; (5) захистити approvals; (6) reconcile destination asset і revoke unnecessary approval. Не використовувати swaps для маскування source of funds.

**Detection:** bridge deposit/withdraw events, unique amount minus fees, time order, liquidity, relayer/RPC/frontend і later service deposits.

## Centralized mixer or tumbler

**Mechanics:** service приймає deposits у pool і пізніше повертає інші units, намагаючись приховати direct input-output mapping.

**Pros:** теоретично може збільшити transaction ambiguity.

**Cons:** operator може steal/log; entry/exit timing/value analysis; sanctions/money-transmission і criminal exposure; seizures можуть розкрити mappings; taint/rejection risk.

**Procedure:** operational mixing guide не надається. Безпечно відтворювати graph, розширюючи [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): створювати synthetic deposits, pooled outputs, fees і delays; надавати analysts incomplete mappings; вимірювати, які heuristics працюють; потім розкривати ground truth.

**Detection:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs і downstream consolidation. Позначати probabilistic attribution.

## Peel chains, fan-out/fan-in and structuring

**Mechanics:** repeated transactions відокремлюють small payments від change, розподіляють value між багатьма addresses, зводять її до collectors або ділять amounts, щоб уникати review.

**Pros:** збільшує workload наївного analyst і кількість addresses.

**Cons:** впізнавані value/cadence/transaction continuity; consolidation і service endpoints; structuring саме по собі може бути незаконним; fees і operational errors.

**Procedure:** використовувати лише synthetic CSV/testnet data: генерувати large source, repeated payment/change edges, parallel branches і one collector; додати benign exchange-like examples; налаштувати detection і документувати false positives.

**Detection:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint і off-chain records. Exchange hot wallets можуть мати схожі patterns, тому context обов’язковий.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mechanics:** інша person/account/company отримує, конвертує або витрачає funds, вставляючи legal і operational layers між controller та transaction.

**Pros to an adversary:** named account не одразу ідентифікує controller; можна з’єднати cash, crypto, goods і jurisdictions.

**Cons:** identity fraud/money-laundering exposure; кожен participant додає communications, bank/company/tax/shipping records, fees, inconsistency і witnesses; повторне використання facilitator створює hubs.

**Procedure:** не імітувати з реальними people/accounts. Створити synthetic graph з controller, recruiter, mule, OTC, shell merchant і beneficiary; додати device/IP/message/bank edges; запропонувати investigators відрізнити account holder від controller і зафіксувати evidence confidence.

**Detection:** shared device/IP/recovery, unusual beneficiary/velocity, багато unrelated senders, immediate onward movement, company/director/invoice inconsistency, communications і cash/commodity delivery.

## NFTs, gambling, merchant goods and refund loops

**Mechanics:** value конвертується в self-priced asset, wagering balance, resalable goods або refunds, щоб створити іншу transaction narrative.

**Pros to an adversary:** змінює asset form і додає marketplace/merchant intermediaries.

**Cons:** marketplace/account/device і wash-trade graph; odds/play і refund records; delivery/resale evidence; fees/losses; fraud/laundering liability.

**Procedure:** concealment workflow не надається. Використовувати synthetic marketplace data із related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument і common shipping; перевіряти detection на legitimate collectors/customers.

**Detection:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery і proceeds reconvergence.

## Physical bearer wallet or offline token transfer

**Mechanics:** device, paper/QR, hardware bearer instrument або e-cash token передає control secret, а не broadcast payment під час handover.

**Pros:** немає live network event під час exchange; корисно offline; physical cash-like custody.

**Cons:** copy/theft/loss і невизначена exclusivity; subsequent redemption/broadcast links; physical meeting/shipping; counterfeit/tamper risk.

**Procedure:** (1) використовувати лише reviewed instrument/protocol; (2) privately initialize/verify authenticity; (3) load only small lawful value; (4) transfer у documented authorized context; (5) receiver verify або sweep promptly, як вимагає protocol; (6) ніколи не припускати, що sender не зберіг copy; (7) приватно зберігати ownership/tax evidence.

**Detection:** purchase/funding і eventual sweep/redemption, device serial/tamper evidence, delivery/meeting і endpoint records.

## Merchant-scoped invoice or one-time payment request

**Mechanics:** merchant створює single-use request із amount, expiry і order reference. Payer здійснює settlement через supported rail без прямого розкриття reusable credential merchant; issuer або payment processor усе одно може ідентифікувати обидві сторони.

**Pros:** обмежує credential reuse і випадкові cross-merchant identifiers; exact amount/expiry зменшують errors; сумісно зі звичайними accounting і refunds.

**Cons:** invoice, delivery, browser, processor і issuer усе ще пов’язують order; unique amount/time може посилити correlation; malicious payment links поширені.

**Procedure:** (1) незалежно authenticate merchant; (2) request fresh invoice з exact amount, asset/network і expiry; (3) inspect destination і refund rules; (4) pay із approved engagement compartment; (5) verify, що merchant підтвердив той самий invoice; (6) зберегти receipt і transaction reference; (7) expire, а не reuse request.

**Detection:** merchant і processor об’єднують invoice, session і settlement; unique amounts/timing і delivery ідентифікують payer. **Captured wallet/device:** invoice history розкриває counterparties і purpose; мінімізувати unnecessary memo data, encrypt device і зберігати authoritative accounting у controlled finance system.

## Prepaid service credit and capability token

**Mechanics:** service перетворює conventional payment на bounded internal credits або bearer capability. Подальше API/resource use може не подавати original card для кожного request, але service часто може зіставити issuance з redemption.

**Pros:** обмежує spend і compromise loss; відокремлює day-to-day workers від funding credential; підтримує per-project budgets і revocation.

**Cons:** зазвичай pseudonymous, не anonymous; service database, redemption IP і unique usage pattern пов’язують activity; bearer tokens можуть бути викрадені; refunds можуть вимагати original payer.

**Procedure:** (1) purchase credits через organization account; (2) створити один project і budget; (3) видати narrow token з service, amount і expiry constraints; (4) зберігати лише в approved secret manager або workload identity path; (5) перевірити rejection поза scope і після expiry; (6) monitor consumption; (7) revoke і reconcile unused value.

**Detection:** provider зіставляє funding account, project, token issuance і usage; defenders alert на geographic/process changes і anomalous consumption. **Captured node:** вважати, що його remaining capability може бути витрачена; використовувати short expiry, low balance, audience binding і immediate server-side revocation.

## Privacy Pass or blinded authorization token

**Mechanics:** issuer створює privacy-preserving authorization token, який origin може validate без linking redemption до issuance. Він може означати paid entitlement або rate-limited access, але не є general currency. Architecture розділяє client, attester, issuer і origin roles та попереджає, що IP/timing або collusion можуть скасувати unlinkability.<sup>[[18]](#references)</sup>

**Pros:** unlinkable redemption для supported services; немає reusable account cookie на origin; cached tokens можуть розділити issuance і use у часі.

**Cons:** application-specific; issuer/attester trust і anonymity-set partitioning; IP і browser metadata залишаються; token theft або distinctive issuance timing можуть корелювати use.

**Procedure:** (1) використовувати implementation, що відповідає relevant Privacy Pass token type; (2) точно визначити, яке entitlement доводить token; (3) розділити issuer і origin administration, якщо цього вимагає threat model; (4) мінімізувати challenge metadata; (5) issue several test tokens і redeem each once на owned origins; (6) порівняти logs на forbidden stable identifiers; (7) протестувати replay, expiry і revocation/abuse controls.

**Detection:** origins бачать redemption IP/time і token validity; issuers/attesters бачать issuance context; analysts тестують timing і metadata partitions, не припускаючи cryptographic break. **Captured client:** unspent bearer tokens можуть бути використані; обмежити їх value, lifetime і audience, ніколи не кешувати funding credential разом із ними.

## Delegated organization procurement or fiscal sponsor

**Mechanics:** authorized procurement team, reseller або fiscal sponsor укладає contract і платить, тоді як operational team отримує bounded service. Це role separation із truthful records, а не nominee або false identity.

**Pros:** vendors не мусять отримувати identity або personal payment details кожного operator; central compliance, tax і refund handling; чіткі budget і offboarding.

**Cons:** sponsor знає beneficiary і purpose; contracts, approvals, delivery і accounts залишаються; додаткові delay/fees; слабка separation, якщо одна особа адмініструє всі layers.

**Procedure:** (1) документувати business purpose, beneficiary і approving authority; (2) вибрати organization-approved intermediary; (3) укласти contract із truthful details; (4) provision project-scoped subaccount без personal billing credential; (5) розділити finance administrators і operators; (6) reconcile invoices і access; (7) завершити service та delegated access під час closeout.

**Detection:** procurement, identity-provider, vendor і delivery records об’єднують chain. **Captured operational device:** він має розкривати service project, але не finance credentials; зберігати invoices і payer identities у finance system, а не на field nodes.

## Escrow or conditional settlement

**Mechanics:** trusted escrow agent або smart contract утримує value до виконання documented conditions. Це може зменшити direct disclosure між payer і payee, однак escrow і underlying payment rails зберігають relationship.

**Pros:** dispute і delivery protection; payer і merchant можуть розкривати одне одному менше reusable credentials; auditable release conditions.

**Cons:** escrow custody/contract risk, fees і identity obligations; on-chain contracts public; order, shipping і dispute data залишаються; не anonymous для intermediary.

**Procedure:** (1) перевірити legal entity, custody, fees, dispute forum і supported assets; (2) створити exact written milestone і refund path; (3) fund із approved organization account; (4) independently verify receipt і release authorization; (5) release лише після evidence; (6) зберегти complete audit record; (7) закрити unused permissions або contract approvals.

**Detection:** escrow account/contract events, funding і release time, beneficiary і dispute records розкривають transaction. **Captured device:** session tokens або contract approvals можуть дозволити release; вимагати separate approver/MFA і revoke active sessions у разі втрати.

## Batched or pooled organization settlement

**Mechanics:** багато approved obligations об’єднуються й settlement виконується в меншій кількості bank/blockchain transactions із private internal ledger, який призначає кожну частку. Batching може зменшити public per-purchase detail, але coordinator зберігає повну attribution.

**Pros:** нижчі fees; менше public graph edges; приховує individual line items від public observer, коли amounts aggregate; простий internal accounting.

**Cons:** coordinator є complete observer і high-value target; distinctive totals/timing можуть корелювати; custody і reconciliation risk; у разі зловживання може нагадувати structuring.

**Procedure:** (1) визначити participants і lawful obligations в accounting system; (2) встановити regular business-justified batch window, а не thresholds для уникнення controls; (3) вимагати dual approval aggregate; (4) settle authenticated recipients; (5) reconcile кожну internal line з batch; (6) обробляти refunds як linked corrections; (7) захищати ledger access і зберігати відповідно до policy.

**Detection:** coordinator ledger, approval і beneficiary records дають ground truth; public analysts обережно використовують input/output/value/time clustering. **Captured payer device:** він має містити лише requisition, а не pool signing key або participant ledger.

## Account-abstraction paymaster or sponsored gas

**Mechanics:** relayer/bundler подає smart-account operation, а paymaster оплачує transaction fees, усуваючи direct native-gas funding edge від user wallet. Це покращує одну graph property; operation, contract і service telemetry залишаються public або observable.<sup>[[19]](#references)</sup>

**Pros:** прибирає common gas-funding link; підтримує scoped sponsorship і rate limits; краще onboarding для legitimate privacy applications.

**Cons:** paymaster/bundler/RPC/front end можуть корелювати requests; contract events і public inputs залишаються; sponsorship policy fingerprint cohort; malicious contracts або approvals можуть викрасти assets.

**Procedure:** (1) використовувати audited maintained smart account і paymaster у correct network; (2) перевірити public fields і sponsor logs; (3) обмежити sponsorship за contract, function, amount, nonce і expiry; (4) тестувати з low value; (5) submit через intended privacy-aware path application; (6) verify operation і fee payer on chain; (7) revoke allowances/session keys і зберігати compliance records.

**Detection:** об’єднувати UserOperation, EntryPoint, paymaster, bundler/RPC і application logs; обережно cluster identical sponsorship policy. **Captured wallet:** session keys і pending approvals можуть бути використані навіть без gas; жорстко обмежувати їх і revoke через account recovery policy.

## Threshold or multisignature payment authorization

**Mechanics:** для spending потрібен threshold незалежних signers. Це не приховує transaction, але дозволяє відокремити payment authority від captured laptop, field node або single operator.

**Pros:** сильний захист від compromise та insider; accountable approval; жоден field device не має complete signing authority; підтримує recovery.

**Cons:** coordination і availability; signer/device/account metadata може корелювати participants; поганий backup design спричиняє loss; public multisig patterns можуть бути identifiable.

**Procedure:** (1) визначити signers, threshold, limits і recovery до funding; (2) initialize на окремих supported hardware/accounts; (3) independently verify addresses і backups; (4) надати field workloads лише unsigned requisition capability; (5) вимагати out-of-band review recipient, amount і purpose; (6) протестувати recovery і one-signer loss із small value; (7) rotate signer після compromise.

**Detection:** approval system, signer device і public script/contract дають evidence; defenders alert на policy або signer-set changes. **Captured node:** він має розкривати щонайбільше одну low-authority session key або unsigned request; ніколи не кешувати quorum material разом.

## Closed-loop community or event currency

**Mechanics:** cooperative, conference або private test environment видає credits, redeemable лише між enrolled participants. Internal transfer може менше exposed global payment networks, тоді як operator контролює issuance і redemption.

**Pros:** bounded economic domain; можна тестувати offline або privacy-preserving payment UX; обмежує external card exposure; чіткі experimental controls.

**Cons:** small anonymity set; operator і merchants бачать activity; limited acceptance/redemption; licensing, consumer-protection і tax rules можуть застосовуватись навіть до local value.

**Procedure:** (1) отримати legal/compliance review і опублікувати issuer terms; (2) enroll consenting test participants; (3) обмежити issuance і заборонити cash-like misuse; (4) використовувати fresh payment requests і мінімізувати public participant identifiers; (5) записувати aggregate reserves і private individual receipts; (6) тестувати loss/refund/redemption; (7) закрити ledger і повернути residual value як обіцяно.

**Detection:** issuer ledger, enrollment, merchant і redemption records реконструюють flows; unusual circular transfers або rapid cash-out потребують review. **Captured wallet:** local balance і counterparties можуть бути exposed; cap value, encrypt state і підтримувати issuer-side freeze/reissue з auditable record.

## Bitcoin reusable payment codes and private payment instructions

**Mechanics:** BIP 47 payment codes використовують reusable public identifier плюс ECDH-derived one-time deposit addresses; BIP 351 визначає новіший private-payment instruction design. Вони зменшують public address reuse, дозволяючи recipient публікувати stable payment instructions. Notification, wallet support, funding і subsequent coin selection усе ще впливають на privacy.<sup>[[20]](#references)</sup>

**Pros:** одна public instruction може створювати distinct addresses; recipient не мусить публікувати кожну invoice address; compatible wallets можуть monitor derived payments; корисно для repeated lawful donors/customers.

**Cons:** wallet interoperability varies; notification transactions або published payment code пов’язують relationship context; sender, recipient і public graph усе ще бачать transactions; careless consolidation або change handling знищують benefit.

**Procedure:** (1) підтвердити, що обидва maintained wallets підтримують exact same specification/version; (2) backup і test recovery на low-value wallet; (3) out-of-band authenticate recipient payment code; (4) send small lawful test; (5) verify fresh derived address; (6) locally label relationship і застосувати coin control; (7) протестувати recovery та refund behavior до використання.

**Detection:** analysts перевіряють notification patterns, funding/change, later consolidation і service boundaries; public-code publication ідентифікує recipient context, навіть якщо deposit addresses різні. **Capture-resilient OPSEC:** тримати spend keys поза field devices і відкривати не більше watch-only relationship view. **Monitoring:** alert на unexpected notification transactions, reused derived addresses, wallet gap-limit/recovery errors і unplanned consolidation.

## EVM stealth addresses (ERC-5564)

**Mechanics:** sender виводить one-time stealth account із recipient stealth meta-address і публікує announcement з ephemeral public key та view tag. Recipient сканує announcements через viewing key і виводить відповідний spend key. Recipient linkage покращується, але sender, amount/token, gas, announcement і later spending залишаються visible.<sup>[[21]](#references)</sup>

**Pros:** non-interactive fresh receiver address; reusable meta-address; окремі viewing і spending roles; працює з supported EVM assets/applications.

**Cons:** announcement scanning і spam; funding gas для new address може relink; sender знає recipient; public token/amount і eventual consolidation залишаються; implementation і wallet support відрізняються.

**Procedure:** (1) спершу використовувати audited maintained implementation на test network; (2) генерувати окремі viewing і spending material та backup; (3) authenticate meta-address; (4) send low-value test і announcement; (5) scan і derive stealth account; (6) test supported gas sponsorship без personal funding edge; (7) record public fields і зберігати lawful accounting.

**Detection:** відстежувати announcement caller, token/amount, timing, gas sponsor, spending і consolidation; view key може довести receipt без надання spend. **Capture-resilient OPSEC:** networked scanner має мати лише viewing role, якщо підтримується; spend і recovery keys зберігати окремо. **Monitoring:** alert на malformed/spam announcements, view-key access, unexpected spend derivation і stealth outputs moved without approval.

## Liquid Confidential Transactions

**Mechanics:** Liquid за замовчуванням blinds output amounts і asset types через commitments/proofs, водночас залишаючи visible transaction graph, input/output count, fee і block time. Peg-in/peg-out та service boundaries залишаються linkable, а users можуть selectively disclose blinding data.<sup>[[22]](#references)</sup>

**Pros:** confidential amount і asset type by default; fast sidechain settlement; selective audit через blinding keys/descriptors; приховує commercially sensitive values від public observers.

**Cons:** graph structure і timing залишаються; federation/bridge і exchange trust; peg boundaries і unconfidential outputs; wallet/node/network records; receiver і sender знають свою transaction.

**Procedure:** (1) вибрати maintained Liquid wallet і перевірити backup model; (2) використовувати testnet або small lawful amount; (3) receive на confidential address і перевірити, що wallet позначає output як blinded; (4) send test confidential transaction; (5) перевірити, які explorer fields залишаються public; (6) export лише scoped blinding proof, потрібний для audit; (7) документувати peg/exchange boundaries і reconcile funds.

**Detection:** аналізувати visible graph/fee/time, peg і exchange records, network metadata і later unblinding evidence; не виводити hidden amount або asset. **Capture-resilient OPSEC:** розділяти spend seed, blinding/view data і watch-only operations. **Monitoring:** alert на accidental unconfidential addresses, unknown peg requests, descriptor changes і unapproved unblinding-key export.

## General payment or state channel

**Mechanics:** participants lock funds, exchange signed off-chain state updates і публікують on chain лише opening, closing або disputed state. Intermediate payments не broadcast globally, але peers і routing/intermediary services бачать свою частину, а endpoints мають зберігати latest enforceable state.<sup>[[23]](#references)</sup>

**Pros:** багато fast low-fee interactions, private від public ledger; менше global transaction detail; bounded channel balance; корисно для metered services і repeated counterparties.

**Cons:** channel peers знають одне одного й можуть зберігати updates; opening/closing/value/timing корелюють; online monitoring може бути потрібним у challenge windows; implementation і liquidity risk; сам по собі не є large anonymity set.

**Procedure:** (1) вибрати maintained audited implementation і зрозуміти dispute window; (2) відкрити low-value test channel між owned parties; (3) exchange signed state updates з unique nonces; (4) backup latest enforceable state; (5) close cooperatively; (6) rehearse stale-state rejection на testnet; (7) зберігати accounting і channel-peer records.

**Detection:** public chain показує lifecycle/disputes; peers, watch services і application transport розкривають off-chain timing і parties. **Capture-resilient OPSEC:** обмежити hot balance і зберігати latest signed state в encrypted recoverable store окремо від field nodes. **Monitoring:** безперервно стежити за stale-state publication, missed backup, peer-key change і наближенням challenge deadline.

## Mobile carrier billing

**Mechanics:** online service списує purchase з mobile subscription або prepaid balance через carrier billing system. Merchant може отримати carrier authorization замість card/bank details, тоді як carrier знає subscriber/line, device/network context, merchant, amount і time.<sup>[[24]](#references)</sup>

**Pros:** merchant не отримує card number; широка доступність phone; придатно для low-value digital goods; carrier може cap і reverse charges.

**Cons:** strongly identified через SIM/account і часто device; small limits і high fees; merchant category restrictions; account takeover/SIM-swap risk; carrier і aggregator створюють complete transaction trail.

**Procedure:** (1) підтвердити availability, limit, fee і refund terms з organization carrier account; (2) увімкнути лише на dedicated organization line, якщо це justified; (3) встановити найнижчий корисний spend cap; (4) придбати benign test item; (5) verify merchant і carrier receipts; (6) disable recurring authorization; (7) reconcile і вимкнути feature після assessment.

**Detection:** carrier, aggregator і merchant records об’єднують line, subscriber, IP/device і charge; enterprise telecom invoices це розкривають. **Capture-resilient OPSEC:** не використовувати personal number і вимагати carrier-account MFA поза field device. **Monitoring:** увімкнути instant charge/SIM-change alerts і зупинитися при unexpected premium-service enrollment, forwarding або account recovery.

## Open-banking payment initiation

**Mechanics:** з explicit user consent regulated payment-initiation service provider (PISP) просить account-servicing bank ініціювати transfer. Merchant може не отримати card credentials, але PISP і banks зберігають regulated payer, payee, consent, device і transaction records.<sup>[[25]](#references)</sup>

**Pros:** checkout без reusable card number; сильна bank authentication; exact account-to-account settlement; consent і status APIs; чіткий reconciliation.

**Cons:** не anonymous для banks/PISP; payee часто бачить legal account details або reference; phishing/redirect risk; jurisdiction і refund protections varies; consent metadata додає observer.

**Procedure:** (1) перевірити, що PISP усе ще regulated, а merchant callback domain authentic; (2) почати з merchant request; (3) переглянути payee, amount, reference і requested consent у bank; (4) authorize лише single payment; (5) independently verify final status; (6) revoke residual consent, якщо є; (7) зберегти receipt і reconcile.

**Detection:** bank/PISP/merchant logs і transfer references забезпечують сильну attribution. **Capture-resilient OPSEC:** banking authentication і recovery тримати поза operational/field devices; device має містити лише paid-service entitlement. **Monitoring:** використовувати bank transaction/consent alerts і розслідувати new PISP grants, changed payee або status callbacks поза expected session.

## Platform wallet, app-store balance or in-app credit

**Mechanics:** platform bill user або redeem account credit, а потім видає signed receipt/entitlement application. App developer може не отримувати original funding instrument, тоді як platform зіставляє account, device, funding, product і redemption.<sup>[[26]](#references)</sup>

**Pros:** merchant/developer не отримує primary PAN; fraud/refund і family/business controls; small prepaid balance може обмежити exposure; signed receipts спрощують entitlement verification.

**Cons:** platform account є сильним identity і behavior hub; device і storefront geography; gift-balance purchase/redemption trail; limited cash-out; fraud controls можуть freeze funds; це не cross-platform money.

**Procedure:** (1) використовувати organization-managed platform account, якщо policy дозволяє; (2) перевірити funding, region, refund і transferable-value rules; (3) додавати лише approved budget; (4) придбати benign product через official store; (5) verify, що application отримує лише expected receipt fields; (6) disable recurring purchase; (7) reconcile і видалити account з operational hardware.

**Detection:** platform receipts/server notifications, account/device login і funding records реконструюють purchase. **Capture-resilient OPSEC:** ніколи не входити на field node через personal store account; де можливо, надавати лише scoped app entitlement. **Monitoring:** увімкнути new-device/purchase alerts і досліджувати receipt replay, family/account changes або unexpected restore events.

## Mutual credit, clearing or periodic net settlement

**Mechanics:** participants записують obligations у private ledger і періодично settlement лише кожної net position. Individual service events не мусять створювати окремі public payments, але ledger operator і counterparties зберігають детальну attribution.

**Pros:** менше external transactions і fees; public observers бачать лише net settlement; підходить repeated organizations; explicit credit limits обмежують exposure.

**Cons:** centralized ledger є complete evidence і fraud target; counterparty/default risk; legal/accounting/tax duties; small membership set; unusual net transfers усе ще можуть розкрити relationships.

**Procedure:** (1) використовувати лише identified consenting organizations із legal/accounting approval; (2) визначити unit, credit limit, settlement interval і dispute rules; (3) фіксувати кожне obligation з immutable approval; (4) окремі finance roles мають розраховувати й approve net positions; (5) settle через ordinary lawful rail; (6) reconcile individual lines із settlement; (7) закрити access і зберігати records відповідно до policy.

**Detection:** ledger, invoices, approvals і final bank/chain settlement дають ground truth; analysts не повинні виводити missing gross activity лише з net transfer. **Capture-resilient OPSEC:** operational devices можуть подавати bounded requisitions, але не редагувати balances або authorize settlement. **Monitoring:** alert на credit-limit breach, backdated entries, administrator changes, reconciliation mismatch і settlement до new beneficiary.

## Capture/compromise exposure matrix

Це застосовується як seizure/loss test до кожного family. Мета — обмежити spend authority і unrelated identity disclosure, зберігаючи lawful accounting, а не стирати transactions або перешкоджати investigation.

| Сімейство технік | Що може розкрити captured wallet/device/account | Мінімальний authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value і physical contacts | носити лише approved amount; окремий private accounting; prompt loss report; no false records |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption і account/session tokens | low balance; one purpose; truthful registration; issuer freeze/revocation, де доступно |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery і merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; no shared recovery account |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices і project | role separation; least-privilege subaccount; finance credentials ніколи не зберігати на operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator або dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph і network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP і payment database | minimal hot balance; encrypted backup; separate node identity; close/recover за documented plan |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC і boundary transactions | separate spend/view roles; hardware support, де доступно; no exchange session на field node |
| Stablecoins, swaps, bridges and DEX | transparent graph, approvals, RPC/front-end state і destination assets | revoke allowances; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; encrypted backup, як підтримує protocol; redeem/reissue; never colocate funding credential |
| Paymaster, multisig/threshold | session key, one signer, pending operations і sponsor policy | narrow session key; independent quorum; signer rotation; field device не може reach threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph і participant records | no operational use; лише synthetic/testnet evidence |
| Community/event currency | enrollment, local balance, counterparties і redemption | capped value; issuer freeze/reissue; consent і private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements і derived outputs | watch/view-only network role; offline/hardware spend role; no personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries і disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device і funding source | organization account; external MFA; low limit; no personal account на field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals і settlement ledger | operational requisition only; separate immutable ledger і dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial, compliance review або wallet going offline не доводять, що investigation існує. Monitor лише accounts, ledgers і infrastructure, які organization має право спостерігати; ніколи не probe providers або counterparties, щоб перевірити, чи співпрацюють вони з investigators.

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund або loss report | missing instrument, redemption поза approved order, altered receipt або custody break |
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
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | synthetic lab ground truth і detection output only | будь-який real account, person або value entering emulation: негайно stop |

## Selection and verification workflow

1. Визначити, яка party не повинна дізнатися яке field.
2. Визначити issuer/mint/custodian, public ledger, network/RPC, merchant і physical observers.
3. Перевірити current support, legality, limits, custody, recovery і refund behavior.
4. Виконати small lawful end-to-end test.
5. Перевірити merchant receipt, provider statement, public chain і wallet/node logs.
6. Протестувати backup/recovery і deliberate audit disclosure.
7. Зберігати required source, ownership, tax, sanctions і engagement records точними, але access-controlled.

## References

- [1] [EMVCo — Токенізація платежів](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Спостереження щодо збору даних великими платіжними платформами](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Захист приватності](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Проста пропозиція Payjoin](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Протокол onion routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Технічні специфікації та network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Створення privacy applications із zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol and privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — Як це працює](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Індикатори red flags для Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers and users of virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — Інформація про transfers і crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Архітектура Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
