# Katalogus van Anonymous Payment Techniques

{{#include ../banners/hacktricks-training.md}}

Hierdie katalogus dek payment **families** vanaf gewone kontant tot blind-signature e-cash en public-chain obfuscation. “Anonymous” beteken altyd anonymous teenoor 'n benoemde waarnemer. 'n Merchant, issuer, mint, exchange, blockchain analyst, network provider, employer en fisiese waarnemer sien verskillende feite.

Die prosedures hieronder is vir wettige fondse, waarheidsgetroue accounts en gemagtigde aankope. Techniques waarvan die doel in die aangehaalde gevalle laundering, sanctions evasion of identity fraud was, word verduidelik en opgespoor, maar die prosedure daarvan is 'n sintetiese forensiese oefening—not instructions for performing the crime.

## Coverage matrix

| Family | Main privacy property | Main observer/trust | Treatment |
|---|---|---|---|
| Cash and cash equivalents | geen afgeleë payment-network rekord nie | ontvanger en fisiese omgewing | wettige workflow |
| Prepaid/gift/voucher value | skei redemption van primary card | seller, issuer en redemption service | wettige workflow; jurisdiksie wissel |
| Virtual/tokenized card | verberg herbruikbare PAN of skei merchants | issuer/network/wallet identifiseer steeds die payer | wettige workflow |
| Payment app/intermediary | merchant sien moontlik alias/intermediary | app versamel identity/device/transaction | vergelykingsbasis |
| Bitcoin hygiene/Silent Payments | pseudonyms en recipient unlinkability | public graph en wallet/network boundary | deployable |
| PayJoin/CoinJoin | verswak common ownership/linkage heuristics | participants/coordinator/network/public graph | deployable waar ondersteun; legal review |
| Lightning/BOLT 12 | off-chain routing en vermindering van receiver-path data | endpoints, hops, services en channel graph | deployable waar ondersteun |
| Monero/Zcash/MWEB | protocol-level on-chain confidentiality | acquisition, endpoint, network en boundary bly sigbaar | deployable waar wettig/ondersteun |
| Ethereum ZK application | verberg 'n gespesifiseerde statement/action-link | public inputs, RPC, relayer en app | application-specific |
| Cashu/Fedimint/Taler | blind-signature payer privacy | mint/federation/exchange custody en boundaries | emerging/deployment-specific |
| Stablecoins | gerieflike digital settlement | transparent chain plus issuer freeze/control | nie 'n anonymity-baseline nie |
| Swaps/bridges/DEX | verskuif value oor asset/chain | beide graphs, contracts en providers | forensiese meganika; slegs gewone wettige swaps |
| Mixers/peel/structuring | verhoog graph ambiguity/work | entry/exit graph en service records | slegs sintetiese detection exercise |
| Nominees/mules/OTC/fronts | plaas menslike/besigheidsintermediaries in | facilitators, banks, communications | slegs criminal-abuse analysis |
| Reusable/stealth payment addresses | vars recipient address per payment | public announcement/notification en wallet boundaries | deployable waar ondersteun |
| Confidential sidechain/state channel | verberg amount/asset of intermediate updates | peers, bridge/federation en lifecycle settlement | protocol-specific |
| Carrier/open-banking/platform billing | verberg primary card van merchant | carrier, bank/PISP of platform identifiseer customer | gewone geïdentifiseerde payment |
| Mutual credit/net settlement | minder eksterne settlement records | private ledger operator het volledige mapping | slegs geïdentifiseerde participants |

## Cash

**Mechanics:** fisiese bearer value verander hande sonder 'n aanlyn issuer authorization of public ledger.

**Pros:** merchant hoef nie bank/card identity te leer nie; geen afgeleë transaction graph nie; algemeen verstaanbaar en finaal.

**Cons:** slegs face-to-face; theft/loss; change/receipt/serial- of reporting-controls; withdrawal, cameras, witnesses en location kan steeds die payer koppel.

**Procedure:** (1) bevestig dat cash wettig/aanvaarbaar is en enige amount/reporting rule; (2) onttrek of ontvang dit wettig en hou private accounting records; (3) betaal 'n gewone merchant sonder onnodige loyalty/account-identifiers; (4) vra slegs die vereiste receipt; (5) vermy shipping/account-data indien die aankoop dit nie nodig het nie; (6) teken die wettige besigheidsdoel intern aan.

**Detection:** versoen till/receipt/inventory, cameras en access logs volgens toepaslike policy; ondersoek ongewone cash-refunding of herhaalde amounts net onder 'n control sonder om gewone cash-use op sigself verdag te behandel.

## Money order, postal order, cashier instrument and cash on delivery

**Mechanics:** 'n gereguleerde issuer omskep cash/account-funds in 'n genommerde instrument betaalbaar aan 'n benoemde ontvanger; COD stel collection tot delivery uit.

**Pros:** ontvanger ontvang moontlik nie die payer se primary bank/card number nie; bruikbaar waar cash nie op afstand kan beweeg nie; duidelike receipt.

**Cons:** issuer/retailer behou purchase/identity-data soos vereis; serial tracking; recipient/delivery address; loss/fraud en streekbeperkings; gewoonlik nie anonymous nie.

**Procedure:** (1) kontroleer issuer-reëls, limits, identification en recipient acceptance; (2) koop met waarheidsgetroue information en wettige funds; (3) voltooi payee/amount onmiddellik; (4) bewaar serial/receipt; (5) gebruik tracked delivery wat by die value pas; (6) versoen redemption/refund.

**Detection:** issuer purchase/redemption-record, instrument serial, retailer/camera, shipping en recipient account; flag alteration, duplicate serials en vinnige geografies-inkonsekwente redemption.

## Open-loop prepaid card

**Mechanics:** 'n network-branded stored-value credential authoriseer teen 'n prepaid balance eerder as 'n primary credit account.

**Pros:** beperk merchant exposure en loss; skei merchant van die main PAN; bruikbaar aanlyn waar aanvaar.

**Cons:** purchase/activation/reload/registration en device-records; KYC en limits wissel; billing-address failures; cash-out/refund-beperkings; “no name” beteken nie geen issuer-record nie.

**Procedure:** (1) verifieer huidige issuer identity, fees, KYC, geography en online/recurring support; (2) verkry dit deur 'n gemagtigde seller met wettige funds; (3) registreer waarheidsgetroue vereiste data; (4) gebruik dit vir een compartment/purpose; (5) moenie loads structureer of residency vervals nie; (6) behou purchase/expense-evidence en sluit dit volgens issuer-terms.

**Detection:** koppel seller/activation, funding, device/IP, merchant authorization, balance checks en redemption/refund. Patrone is belangriker as die prepaid-label.

## Closed-loop gift card, voucher and transferable service credit

**Mechanics:** genommerde value is slegs met een merchant/service of ecosystem redeemable. Airtime/game/store credits is variante.

**Pros:** recipient merchant sien moontlik slegs code/balance; beperkte blast radius; maklike gifting en budget separation.

**Cons:** seller en service log purchase/activation/redemption; account/device/delivery koppel steeds; scams, resale discounts en expiry/region-limits; swak refund-rights.

**Procedure:** (1) koop slegs deur gemagtigde channels; (2) teken code-value aan sonder om die secret bloot te stel; (3) vermy attachment aan 'n identifying loyalty-account indien onnodig; (4) redeem deur 'n separate legitimate merchant-account/context; (5) hou receipt totdat dit aanvaar is; (6) koop nooit codes vir 'n ongevraagde “tax/support/ransom”-eis nie.

**Detection:** code issuance/redemption-time, device/account-convergence, bulk/threshold-pattern purchase, een device wat baie balances nagaan, en verafgeleë vinnige redemption.

## Cryptocurrency-funded card or gift-code broker

**Mechanics:** 'n intermediary aanvaar cryptocurrency en reik 'n card, voucher of merchant-code uit. Dit is 'n cross-rail conversion: die merchant sien gewone card/gift-value, terwyl die broker die on-chain deposit met issuance en delivery verbind.

**Pros:** merchant ontvang nie die funding-wallet nie; nuttig vir wettige merchants wat nie crypto aanvaar nie; begrensde stored value.

**Cons:** nie anonymous teenoor broker/issuer nie; KYC, sanctions, exchange en card-program-reëls; public deposit graph; account/device/email en code-redemption verbind beide kante weer; scam/insolvency-risk.

**Procedure:** (1) verifieer die legal entity, card issuer, supported jurisdiction, KYC, fees en refund-policy; (2) gebruik slegs wettige gedokumenteerde funds; (3) toets die kleinste denomination; (4) verifieer network/merchant-restrictions voor purchase; (5) behou beide blockchain-transaction en broker-receipt vir accounting; (6) gebruik nooit 'n broker wat identity fraud, sanctions bypass of “untraceable” cash-out belowe nie.

**Detection:** korreleer broker deposit-addresses, unique amount/time, account/device en issued-card authorization of gift-code redemption; issuer- en broker-records oorbrug die public chain na die merchant.

## Virtual or merchant-locked card

**Mechanics:** die issuer map 'n generated PAN/token na die real account, dikwels met beperking van merchant, amount of expiration.

**Pros:** voorkom reusable PAN disclosure; merchant compartmentation; spend limits en maklike revocation; mature fraud control.

**Cons:** issuer ken steeds payer, funding, merchant, device/IP en time; merchant sien account/delivery; sommige refunds/recurring charges faal; nie anonymous nie.

**Procedure:** (1) gebruik die regulated issuer se official feature; (2) skep 'n card vir een merchant/engagement; (3) stel die kleinste nuttige limit en expiry; (4) gebruik accurate billing waar vereis; (5) verifieer statement-descriptor/refund-behavior; (6) freeze/delete na final settlement terwyl audit-evidence behoue bly.

**Detection:** issuer token-to-account mapping, merchant authorization, device en delivery. Defenders gebruik merchant-specific reuse, velocity en account-takeover signals.

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization vervang die PAN met 'n constrained credential, dikwels gebind aan 'n device, merchant of payment scenario.<sup>[[1]](#references)</sup>

**Pros:** merchant ontvang nie die reusable PAN nie; device cryptography/dynamic data verminder cloning; revocable sonder card replacement.

**Cons:** issuer, token service, wallet platform en network behou mappings/transactions; device/platform-account en location kan payer identifiseer.

**Procedure:** (1) enrol 'n legitimate card in die official wallet; (2) beskerm platform account/device met strong authentication; (3) verifieer device token/last digits by purchase; (4) disable unnecessary location/analytics waar ondersteun; (5) remove lost devices/token onmiddellik; (6) review issuer- en wallet-records.

**Detection:** token requestor/device cryptogram en issuer mapping, wallet/account telemetry, merchant terminal en fisiese evidence.

## Payment app, marketplace wallet and centralized intermediary

**Mechanics:** die service maintain accounts en transfers internally of oor bank/card-rails; die merchant sien moontlik 'n alias terwyl die service beide parties sien.

**Pros:** convenience, dispute/refund-mechanisms; recipient sien nie noodwendig bank/card-details nie.

**Cons:** centralized identity/social/transaction graph; freezes en legal process; counterparties kan profile blootlê; data use kan payment-necessity oorskry.<sup>[[2]](#references)</sup>

**Procedure:** (1) lees identity, privacy, retention en buyer-protection terms; (2) beperk optional profile/contact-synchronization; (3) gebruik 'n separate truthful account slegs wanneer terms dit toelaat; (4) enable MFA/alerts; (5) verifieer recipient en privacy van memo/profile; (6) export records en close unused links.

**Detection:** provider account, device/IP, contact graph, funding/withdrawal, memo en merchant records. 'n Alias is pseudonymity teenoor 'n counterparty, nie anonymity teenoor die platform nie.

## Bank transfer, ACH, wire and instant-account payment

**Mechanics:** regulated institutions move value tussen geïdentifiseerde accounts en exchange required payment-data.

**Pros:** vinnig, accountable, in beperkte gevalle reversible, strong records; virtual account-numbers kan merchant-disclosure verminder.

**Cons:** banks/processors ken beide kante; statements en references; nie anonymous nie; cross-border en Travel Rule/AML-data.

**Procedure:** gebruik dit slegs wanneer accountability aanvaarbaar is: verifieer beneficiary independently, beperk optional memo-data, gebruik 'n bank-provided virtual account/reference waar beskikbaar, enable alerts, behou invoice en reconcile.

**Detection:** deterministic bank/payment records, beneficiary/account ownership, device/session en fraud-controls. Dit is 'n baseline, nie 'n anonymity-technique nie.

## Account and merchant compartmentation

**Mechanics:** separate lawful identities/accounts, email-aliases, cards en delivery-contexts voorkom dat unrelated merchants activity maklik saamvoeg terwyl 'n issuer/controller die mapping behou.

**Pros:** verminder breach en cross-merchant linkage; maklik om te audit; compatible met regulated payments.

**Cons:** provider map steeds compartments; recovery phone/device/IP en shipping kan dit herverbind; policy kan multiple accounts verbied.

**Procedure:** (1) definieer een purpose; (2) skep slegs terms-compliant aliases/subaccounts; (3) gebruik 'n merchant-specific token/card; (4) disable cross-account contact/ad-personalization; (5) hou 'n encrypted controller-ledger; (6) retire identifiers nadat refunds/retention needs eindig.

**Detection:** providers join recovery, device, funding en IP; merchants join delivery, browser en account-behavior. Defenders moet legitimate compartmentation van synthetic identity fraud onderskei.

## Controlled red-team procurement

**Mechanics:** die SOC is blind vir 'n purchase terwyl 'n exercise controller legal entity, operator en infrastructure-mapping behou.

**Pros:** realistic detection exercise; geen personal exposure; immediate deconfliction en audit.

**Cons:** nie anonymous teenoor organization/provider nie; governance-overhead; leaks indien controller-ledger verkeerd hanteer word.

**Procedure:** (1) alloceer 'n engagement-specific organization card/wallet/budget; (2) skei purchaser/operator-rolle; (3) teken asset, amount, service, purpose en kill date aan; (4) stoor attribution mapping met beperkte controller access; (5) gebruik nooit false identity/mule/stolen funds nie; (6) reveal/reconcile indicators en refunds tydens closeout.

**Detection:** controller map provider invoice en asset; SOC toets onafhanklike discovery deur domain, certificate, hosting en traffic eerder as cardholder data.

## Bitcoin address hygiene and coin control

**Mechanics:** fresh receive addresses, local labeling en selective UTXO spending verminder address reuse en accidental compartment-merging op 'n public ledger.

**Pros:** breed ondersteun; self-custodial; vermy die eenvoudigste public linkage.

**Cons:** alle transactions/amounts bly public; common-input/change/timing en latere consolidation verbind activity; acquisition/RPC/network-records bly.

**Procedure:** (1) install/verify 'n maintained wallet; (2) back up en toets seed recovery; (3) gebruik 'n nuwe address per invoice; (4) label source/purpose locally; (5) gebruik coin control om merging van contexts te vermy; (6) verkies 'n local node of privacy-aware connection; (7) preview change/fees en behou wettige accounting.<sup>[[3]](#references)</sup>

**Detection:** address graph, common-input/change heuristics met uncertainty, exact amount/time, consolidation, service deposits, node/RPC broadcast timing en off-chain records.

## Bitcoin Silent Payments

**Mechanics:** BIP 352 laat 'n receiver toe om 'n static code te publish terwyl senders unique Taproot outputs deur ECDH derive; external observers kan outputs nie direk aan die code koppel nie.<sup>[[4]](#references)</sup>

**Pros:** reusable public identifier sonder address reuse; geen interactive address request of notification output nie; meng met Taproot outputs.

**Cons:** receiver scanning cost; wallet support wissel; amount/sender graph en spending bly public; index server kan scans observeer.

**Procedure:** (1) kies 'n current BIP 352 wallet; (2) back up/test descriptor en scanning recovery; (3) generate labeled code waar ondersteun; (4) authenticate die published code; (5) sender review inputs en stuur 'n small test; (6) receiver scan verkieslik deur eie node; (7) hou received UTXOs separated.

**Detection:** nie betroubaar identifiseerbaar uit output alleen volgens ontwerp nie; analysts gebruik sender inputs, amount/time, later spending, wallet/network/index en counterparty records.

## PayJoin

**Mechanics:** payer en payee dra inputs by tot een payment transaction, wat die assumption breek dat alle inputs een owner het.<sup>[[5]](#references)</sup>

**Pros:** gewone payment met improved privacy; bevoordeel die breër graph deur 'n common heuristic te verswak; geen equal-output crowd nodig nie.

**Cons:** interactive/support-requirement; receiver endpoint availability; amount en final transaction public; implementation en fallback metadata.

**Procedure:** (1) bevestig dat beide maintained wallets dieselfde PayJoin-version ondersteun; (2) authenticate invoice/endpoint; (3) begin vanuit die wallet se PayJoin-enabled payment URI; (4) inspect final amount/fee en sign slegs expected inputs; (5) vermy manual transaction surgery; (6) verify broadcast en receipt; (7) record fallback indien negotiation faal.

**Detection:** blockchain analysts moet nie common-input clustering forceer nie; endpoint/provider kan negotiation log; gebruik wallet/network en later-spend evidence eerder as transaction shape alleen.

## CoinJoin

**Mechanics:** meerdere participants skep collaboratively 'n transaction met baie inputs/outputs, dikwels equal denominations, wat ambiguity oor input-output-correspondence verhoog.

**Pros:** groter on-chain ambiguity set; self-custodial designs bestaan; meetbare round-structure.

**Cons:** coordinator/peer/network metadata; fees/liquidity; identifiseerbare transaction-shape; toxic change en latere consolidation vernietig gains; legal/provider-availability wissel.

**Procedure:** (1) verifieer current wallet/coordinator availability en legality; (2) install official wallet en back up; (3) gebruik slegs lawful UTXOs; (4) verstaan denomination, fee en coordinator-model; (5) hou change en mixed outputs labeled/separate; (6) consolidateer hulle nooit saam nie; (7) route network-traffic soos officially supported en behou accounting.

**Detection:** identifiseer collaborative structure sonder om crime te veronderstel; bereken possible mappings/anonymity-set, en monitor dan change/consolidation, service boundaries en network/coordinator-records.

## Lightning Network

**Mechanics:** HTLC payments traverse onion-routed channels; meeste payment-details word nie on-chain gepublish nie, terwyl funding/closing en public channel-information wel sigbaar is.

**Pros:** vinnig, low fee; intermediaries sien normaalweg adjacent hops; routine payment-details bly off-chain.

**Cons:** sender/receiver en first/last hop weet meer; probing, timing, channel graph, liquidity/wallet/LSP-records; custodial wallets identifiseer users.

**Procedure:** (1) kies self-custodial versus custodial bewustelik; (2) verify wallet/seed/channel recovery; (3) gebruik 'n invoice vir die exact payment; (4) verkies private channels/LSP-features slegs nadat tradeoffs gelees is; (5) beskerm node IP met supported Tor waar nodig; (6) vermy reuse van identifying invoices; (7) hou channel- en payment-accounting.<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs, channel graph/probes, payment failure/timing en on-chain funding/closure; geen public transaction beteken nie geen records nie.

## BOLT 12 offers and route blinding

**Mechanics:** 'n reusable offer produseer fresh invoices en kan blinded paths adverteer sodat die payer nie die receiver se clear node/path hoef te leer nie.

**Pros:** receiver privacy; reusable donation/payment endpoint sonder static invoice; integreer met Lightning onion routing.

**Cons:** wallet support wissel; endpoints, selected hops en funding bly; public contact of network endpoint kan receiver re-identifiseer.

**Procedure:** (1) bevestig matching BOLT 12 support; (2) authenticate offer; (3) request 'n fresh invoice; (4) review amount/issuer/recurrence; (5) betaal deur die wallet; (6) verify receipt/refund-behavior; (7) minimize node alias/contact en behou accounting.<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP en first/last-hop telemetry, offer-distribution account, timing/value en funding graph; route blinding beperk payer-visibility doelbewus.

## Monero

**Mechanics:** one-time stealth addresses verberg recipient linkage, RingCT verberg amounts en ring signatures verskaf sender ambiguity.

**Pros:** privacy is default on chain; sender/receiver/amount confidentiality; mature dedicated wallet/node ecosystem.

**Cons:** acquisition/off-ramp en endpoint/network/counterparty-records; remote node sien queries/IP; exchange support/legal treatment wissel; klein operational mistakes kan contexts steeds koppel.

**Procedure:** (1) acquire lawfully en behou basis/source; (2) install/verify official maintained wallet; (3) back up/test seed; (4) gebruik 'n local node of documented Tor/I2P remote-node path; (5) gebruik new subaddress per payer/invoice; (6) label contexts locally; (7) disclose transaction proof/view access slegs doelbewus.<sup>[[8]](#references)</sup>

**Detection:** fokus op exchange/merchant/device/network en seized-wallet evidence; protocol use alleen is nie suspicious nie en die public chain exposeer doelbewus minder.

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs validate shielded transfers terwyl sender, receiver en amount encrypted is; transparent pools en pool transitions bly public.

**Pros:** strong shielded on-chain confidentiality; viewing keys kan scoped audit ondersteun; protocol-enforced validity.

**Cons:** wallet/exchange support en actual pool-choice wissel; transparent boundary timing/value-correlation; network/RPC en endpoint bly.

**Procedure:** (1) kies 'n maintained Orchard shielded-by-default wallet; (2) verify/back up; (3) obtain ZEC lawfully; (4) ontvang na supported Unified Address en bevestig pool; (5) verkies shielded-to-shielded; (6) gebruik supported network privacy; (7) toets viewing-key disclosure op 'n small wallet voor audit.<sup>[[9]](#references)</sup>

**Detection:** transparent boundary en service records, wallet/network metadata en viewing keys waar wettig provided; moenie aanvaar alle Unified Address-payments was shielded nie.

## Mimblewimble and Litecoin MWEB

**Mechanics:** confidential transactions verberg amounts en Mimblewimble-style aggregation verwyder conventional address-rich history; Litecoin implementeer 'n optional extension block langs sy transparent chain.

**Pros:** confidential amounts en verbeterde fungibility in die private domain; efficient pruning/aggregation.

**Cons:** opt-in boundary peg-in/out is public en correlatable; wallet/exchange support; interactive/address-model-verskille; network- en acquisition-records.

**Procedure:** (1) kies 'n maintained wallet met explicit MWEB support; (2) verify/back up en toets small amount; (3) acquire lawfully; (4) peg into MWEB en verify balance domain; (5) transakt slegs met 'n compatible receiver; (6) vermy immediate distinctive peg-out; (7) behou private audit records.<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value, exchange/wallet/node-data en later transparent spends; internal confidential-transfer-details word doelbewus verminder.

## Ethereum zero-knowledge privacy applications

**Mechanics:** 'n circuit bewys 'n statement—membership, valid note ownership of authorization—sonder om die secret te reveal; 'n verifier-contract check dit. Deposits, withdrawals, public inputs, events en gas kan steeds links blootlê.

**Pros:** programmable selective disclosure; anonymous-set applications; verifiable rules sonder om alle data te reveal.

**Cons:** contract/circuit bugs; small anonymity set; public boundaries; RPC/IP/session/analytics/gas funding; application en sanctions/legal risk.

**Procedure:** (1) definieer presies wat die proof verberg; (2) gebruik 'n audited maintained application waar wettig; (3) inspect public inputs/events en deposit/withdraw rules; (4) skei action-wallet en gas sponsorship soos die protocol bedoel; (5) gebruik 'n privacy-aware RPC/network path; (6) toets met small value; (7) behou compliance-records.<sup>[[11]](#references)</sup>

**Detection:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics en eventual exchange/merchant-boundary. Moenie beweer die ZK-proof verberg velde wat as public verklaar is nie.

## Stablecoins

**Mechanics:** tokens transfer op 'n public chain; centralized issuers kan freeze/blacklist of redeem teen identified accounts.

**Pros:** price stability, liquidity en merchant support; fast settlement; easy accounting.

**Cons:** transparent address/amount/contract graph; gas funding; issuer en exchange identity/control; sanctions screening; algemeen swak anonymity.

**Procedure:** behandel dit as identified payment: gebruik 'n fresh business-address slegs vir compartmentation, verify token contract/network, toets small amount, protect wallet, use trusted RPC/local node, retain basis/source en screen required parties.

**Detection:** complete token-event graph, issuer freeze-list/actions, exchange/RPC/device en gas-funding relationships.

## Cashu Chaumian e-cash

**Mechanics:** 'n mint blind-sign client-generated bearer-secrets backed by the mint se Bitcoin/Lightning-reserves; dit kan double-spend voorkom sonder om issuance direk aan latere redemption te koppel.

**Pros:** accountless bearer-tokens; instant peer-transfer; mint kan blinded withdrawal nie direk aan spend koppel nie; tokens kan as data/QR move.

**Cons:** mint custody/solvency/censorship; bearer-data loss/theft; denomination/timing en Lightning-boundaries; network-metadata; early software ecosystem.<sup>[[12]](#references)</sup>

**Procedure:** (1) gebruik eers 'n official test mint of tiny disposable value; (2) install 'n maintained wallet en toets backup/restore limitations; (3) authenticate mint en review custody/fees; (4) mint 'n small amount; (5) send token oor 'n authenticated private channel/QR; (6) receiver swap token voor dit as final beskou word; (7) redeem en reconcile. Moet nooit meaningful value in 'n untrusted mint store nie.

**Detection:** mint sien network, issue/redeem/Lightning boundaries en spent-token-set, maar blinding verwyder direct token linkage; endpoints/messages en distinctive amount/timing kan links restoreer.

## Fedimint federated e-cash

**Mechanics:** 'n threshold guardians hou reserves en blind-sign e-cash; internal bearer transfers is private teenoor guardians, terwyl Lightning-gateways external payments bridge.

**Pros:** distribueer custody; private internal transfer; community governance; geen enkele guardian beheer die reserve onder die threshold nie.

**Cons:** guardian quorum/custody/software-risk; gateway observeer invoices/timing; deposit/withdraw-boundaries; client-state recovery complexity.

**Procedure:** (1) verify federation invite/guardians/quorum/jurisdiction; (2) install maintained client en toets recovery; (3) deposit 'n small lawful amount; (4) gebruik fresh internal payment requests; (5) behandel gateway as observer vir Lightning; (6) toets redemption; (7) behou source/tax records buite public payment-data.<sup>[[13]](#references)</sup>

**Detection:** federation sien aggregate issuance/redemption, gateways sien external invoices, Bitcoin/Lightning toon boundaries, en endpoint/communication-evidence kan internal transfers koppel.

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash poog om payer anonymous teenoor merchants te hou terwyl merchants en income accountable bly.

**Pros:** payer privacy by design; gewone currency; merchant accountability/refunds; geen speculative token nodig nie.

**Cons:** beperkte deployments; exchange/bank sien funding; merchant sien order/delivery; wallet bearer/recovery-risk; regulated operators.

**Procedure:** (1) vind 'n current exchange/merchant vir die jurisdiction/currency; (2) lees KYC/fees/privacy; (3) install official wallet; (4) withdraw lawfully van supported bank/exchange; (5) review merchant contract; (6) pay en behou receipt/refund-data; (7) vermy onnodige merchant session-identifiers.<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal en merchant deposit is accountable boundaries; merchant order/device/delivery en timing kan korreleer selfs wanneer coins blinded is.

## Cross-chain bridge, atomic swap and decentralized exchange

**Mechanics:** 'n contract/service lock/burn een asset en release/mint 'n ander, of counterparties exchange atomically. Dit breek 'n single-ledger view, nie economic continuity nie.

**Pros:** asset/network interoperability; kan een centralized custodian vermy; ordinary portfolio/liquidity use.

**Cons:** beide chains is public; time/value/fees/liquidity en contracts korreleer; bridge/relayer/frontend/RPC-records; smart-contract/counterparty en regulatory risk.

**Procedure for lawful swaps:** (1) verify official contract/service en legal availability; (2) inspect custody/audit/fees/slippage; (3) gebruik 'n small test; (4) record both transaction IDs en rate; (5) protect approvals; (6) reconcile destination asset en revoke unnecessary approval. Moenie swaps gebruik om source of funds te disguise nie.

**Detection:** bridge deposit/withdraw events, unique amount minus fees, time order, liquidity, relayer/RPC/frontend en later service deposits.

## Centralized mixer or tumbler

**Mechanics:** 'n service ontvang deposits in 'n pool en return later different units, met die doel om direct input-output mapping te obscureer.

**Pros:** kan transaction ambiguity in theory vergroot.

**Cons:** operator kan steal/log; entry/exit timing/value-analysis; sanctions/money-transmission en criminal exposure; seizures kan mappings blootlê; taint/rejection-risk.

**Procedure:** geen operational mixing-guide word verskaf nie. Reproduceer die graph veilig deur [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) uit te brei: skep synthetic deposits, pooled outputs, fees en delays; gee analysts incomplete mappings; meet watter heuristics werk; reveal dan ground truth.

**Detection:** service wallet/contract-identification, entry/exit candidate-sets, amount/fee/timing, deposit-address-reuse, seized/provider-logs en downstream consolidation. Label probabilistic attribution.

## Peel chains, fan-out/fan-in and structuring

**Mechanics:** repeated transactions peel small payments from change, split value oor baie addresses, reconverge collectors, of divide amounts om review te vermy.

**Pros:** verhoog naive analyst-workload en address-count.

**Cons:** herkenbare value/cadence/transaction-continuity; consolidation en service endpoints; structuring kan self illegal wees; fees en operational errors.

**Procedure:** gebruik slegs synthetic CSV/testnet-data: generate a large source, repeated payment/change edges, parallel branches en one collector; voeg benign exchange-like examples by; tune detection en document false positives.

**Detection:** graph continuity, repeated change-pattern, cadence, just-below-control amounts, common service endpoint en off-chain records. Exchange hot wallets kan hierdie patrone resemble, dus is context mandatory.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mechanics:** 'n ander persoon/account/company ontvang, convert of spend funds, wat legal en operational layers tussen controller en transaction plaas.

**Pros to an adversary:** named account identifiseer nie onmiddellik die controller nie; kan cash, crypto, goods en jurisdictions bridge.

**Cons:** identity fraud/money-laundering exposure; elke participant voeg communications, bank/company/tax/shipping-records, fees, inconsistency en witnesses by; facilitator reuse create hubs.

**Procedure:** moenie met real people/accounts emulate nie. Build 'n synthetic graph met controller, recruiter, mule, OTC, shell merchant en beneficiary; seed device/IP/message/bank-edges; vra investigators om account-holder van controller te onderskei en evidence-confidence te record.

**Detection:** shared device/IP/recovery, unusual beneficiary/velocity, baie unrelated senders, immediate onward movement, company/director/invoice-inconsistency, communications en cash/commodity delivery.

## NFTs, gambling, merchant goods and refund loops

**Mechanics:** value word omskep in 'n self-priced asset, wagering balance, resalable goods of refunds om 'n ander transaction narrative te skep.

**Pros to an adversary:** verander asset-form en voeg marketplace/merchant-intermediaries by.

**Cons:** marketplace/account/device en wash-trade graph; odds/play en refund records; delivery/resale evidence; fees/losses; fraud/laundering liability.

**Procedure:** geen concealment-workflow nie. Gebruik synthetic marketplace-data met related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument en common shipping; validate detection teen legitimate collectors/customers.

**Detection:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery en proceeds reconvergence.

## Physical bearer wallet or offline token transfer

**Mechanics:** 'n device, paper/QR, hardware bearer instrument of e-cash token transfer control van 'n secret eerder as om 'n payment by handover te broadcast.

**Pros:** geen live network event tydens exchange nie; nuttig offline; physical cash-like custody.

**Cons:** copy/theft/loss en uncertain exclusivity; later redemption/broadcast links; physical meeting/shipping; counterfeit/tamper-risk.

**Procedure:** (1) gebruik slegs 'n reviewed instrument/protocol; (2) initialize/verify authenticity privately; (3) load slegs small lawful value; (4) transfer in 'n documented authorized context; (5) receiver verify of sweep promptly soos die protocol vereis; (6) moenie aanvaar sender het geen copy behou nie; (7) record ownership/tax-evidence privately.

**Detection:** purchase/funding en eventual sweep/redemption, device serial/tamper evidence, delivery/meeting en endpoint records.

## Merchant-scoped invoice or one-time payment request

**Mechanics:** die merchant create 'n single-use request met amount, expiry en order-reference. Die payer settle dit deur 'n supported rail sonder om 'n reusable credential direk aan die merchant te expose; issuer of payment-processor kan steeds beide parties identifiseer.

**Pros:** beperk credential reuse en accidental cross-merchant identifiers; exact amount/expiry verminder errors; compatible met ordinary accounting en refunds.

**Cons:** invoice, delivery, browser, processor en issuer link steeds order; 'n unique amount/time kan correlation versterk; malicious payment-links is common.

**Procedure:** (1) authenticate merchant independently; (2) request 'n fresh invoice met exact amount, asset/network en expiry; (3) inspect destination en refund-rules; (4) pay from approved engagement-compartment; (5) verify merchant acknowledge dieselfde invoice; (6) preserve receipt en transaction-reference; (7) expire rather than reuse request.

**Detection:** merchant en processor join invoice, session en settlement; unique amounts/timing en delivery identifiseer payer. **Captured wallet/device:** invoice-history expose counterparties en purpose; minimise unnecessary memo-data, encrypt device en hou authoritative accounting in die controlled finance-system.

## Prepaid service credit and capability token

**Mechanics:** 'n service convert 'n conventional payment in bounded internal credits of 'n bearer capability. Subsequent API/resource-use kan vermy om die original card op elke request te present, maar service kan issuance dikwels aan redemption map.

**Pros:** caps spend en compromise loss; skei day-to-day workers van funding credential; support per-project budgets en revocation.

**Cons:** gewoonlik pseudonymous, nie anonymous nie; service database, redemption IP en unique usage-pattern koppel activity; bearer tokens kan gesteal word; refunds kan original payer vereis.

**Procedure:** (1) purchase credits deur organization account; (2) create one project en budget; (3) issue 'n narrow token met service, amount en expiry constraints; (4) store dit slegs in approved secret-manager of workload-identity path; (5) test rejection buite scope en ná expiry; (6) monitor consumption; (7) revoke en reconcile unused value.

**Detection:** provider join funding-account, project, token-issuance en usage; defenders alert on geographic/process changes en anomalous consumption. **Captured node:** assume remaining capability kan spent word; use short expiry, low balance, audience binding en immediate server-side revocation.

## Privacy Pass or blinded authorization token

**Mechanics:** 'n issuer produce 'n privacy-preserving authorization-token wat 'n origin kan validate sonder om redemption aan issuance te link. Dit kan paid entitlement of rate-limited access represent, maar is nie general currency nie. Die architecture skei client, attester, issuer en origin roles en waarsku dat IP/timing of collusion unlinkability kan undo.<sup>[[18]](#references)</sup>

**Pros:** unlinkable redemption vir supported services; geen reusable account-cookie by origin nie; cached tokens kan issuance en use in time separate.

**Cons:** application-specific; issuer/attester trust en anonymity-set partitioning; IP en browser metadata bly; token theft of distinctive issuance timing kan use correlate.

**Procedure:** (1) gebruik 'n implementation wat aan die relevante Privacy Pass token-type conform; (2) define presies watter entitlement die token prove; (3) separate issuer en origin administration waar die threat model dit vereis; (4) minimize challenge metadata; (5) issue several test tokens en redeem elk een keer by owned origins; (6) compare logs vir forbidden stable identifiers; (7) test replay, expiry en revocation/abuse-controls.

**Detection:** origins sien redemption IP/time en token-validity; issuers/attesters sien issuance-context; analysts toets timing en metadata-partitions sonder om 'n cryptographic break te veronderstel. **Captured client:** unspent bearer-tokens mag bruikbaar wees; bind hul value, lifetime en audience, en cache nooit die funding credential daarmee saam nie.

## Delegated organization procurement or fiscal sponsor

**Mechanics:** 'n authorized procurement team, reseller of fiscal sponsor contract en pay terwyl die operational team 'n bounded service ontvang. Dit is role separation met truthful records, nie 'n nominee of false identity nie.

**Pros:** vendors hoef nie elke operator se identity of personal payment-details te ontvang nie; central compliance, tax en refund-handling; clear budget en offboarding.

**Cons:** sponsor ken beneficiary en purpose; contracts, approvals, delivery en accounts bly; added delay/fees; swak separation indien dieselfde persoon elke layer administreer.

**Procedure:** (1) document business purpose, beneficiary en approving authority; (2) select organization-approved intermediary; (3) contract onder truthful details; (4) provision 'n project-scoped subaccount sonder personal billing credential; (5) separate finance administrators van operators; (6) reconcile invoices en access; (7) terminate beide service en delegated access by closeout.

**Detection:** procurement, identity-provider, vendor en delivery-records join die chain. **Captured operational device:** dit moet die service-project reveal maar nie finance credentials nie; hou invoices en payer identities in finance-system, nie op field nodes nie.

## Escrow or conditional settlement

**Mechanics:** 'n trusted escrow-agent of smart contract hou value totdat documented conditions met word. Dit kan direct disclosure tussen payer en payee verminder, terwyl escrow en underlying payment rails die relationship behou.

**Pros:** dispute en delivery protection; payer en merchant kan minder reusable credentials aan mekaar expose; auditable release-conditions.

**Cons:** escrow custody/contract-risk, fees en identity-obligations; on-chain contracts is public; order, shipping en dispute-data bly; nie anonymous teenoor intermediary nie.

**Procedure:** (1) verify legal entity, custody, fees, dispute forum en supported assets; (2) create exact written milestone en refund-path; (3) fund from approved organization account; (4) verify receipt en release authorization independently; (5) release slegs ná evidence; (6) preserve complete audit-record; (7) close unused permissions of contract approvals.

**Detection:** escrow account/contract events, funding en release-time, beneficiary en dispute-records reveal transaction. **Captured device:** session tokens of contract approvals may permit release; require separate approver/MFA en revoke active sessions on loss.

## Batched or pooled organization settlement

**Mechanics:** baie approved obligations word geaggregateer en settled in fewer bank or blockchain transactions, met 'n private internal ledger wat elke share assign. Batching kan public per-purchase detail verminder, maar coordinator retain complete attribution.

**Pros:** lower fees; fewer public graph edges; verberg individual line items vir 'n public observer wanneer amounts aggregated is; straightforward internal accounting.

**Cons:** coordinator is complete observer en high-value target; distinctive totals/timing kan correlate; custody en reconciliation-risk; kan resemble structuring if abused.

**Procedure:** (1) define participants en lawful obligations in accounting-system; (2) set regular, business-justified batch-window eerder as thresholds designed to avoid controls; (3) require dual approval of aggregate; (4) settle to authenticated recipients; (5) reconcile every internal line to batch; (6) handle refunds as linked corrections; (7) protect ledger access en retain dit per policy.

**Detection:** coordinator ledger, approval en beneficiary records provide ground truth; public analysts use input/output/value/time-clustering cautiously. **Captured payer device:** dit moet slegs sy requisition bevat, nie pool se signing-key of participant-ledger nie.

## Account-abstraction paymaster or sponsored gas

**Mechanics:** 'n relayer/bundler submit 'n smart-account operation en 'n paymaster betaal transaction fees, wat 'n direct native-gas funding-edge van user-wallet vermy. Dit verbeter een graph-property; operation, contract en service telemetry bly public of observable.<sup>[[19]](#references)</sup>

**Pros:** verwyder 'n common gas-funding-link; support scoped sponsorship en rate limits; better onboarding vir legitimate privacy applications.

**Cons:** paymaster/bundler/RPC/front end kan requests correlate; contract events en public inputs bly; sponsorship-policy fingerprint 'n cohort; malicious contracts of approvals kan assets steel.

**Procedure:** (1) gebruik audited maintained smart-account en paymaster op die korrekte network; (2) inspect watter fields public is en wat sponsor log; (3) limit sponsorship per contract, function, amount, nonce en expiry; (4) toets met low value; (5) submit deur application se intended privacy-aware path; (6) verify operation en fee-payer on chain; (7) revoke allowances/session-keys en behou compliance-records.

**Detection:** join UserOperation, EntryPoint, paymaster, bundler/RPC en application logs; cluster identical sponsorship-policy cautiously. **Captured wallet:** session-keys en pending approvals kan bruikbaar wees selfs sonder gas; scope hulle tightly en revoke deur account se recovery-policy.

## Threshold or multisignature payment authorization

**Mechanics:** spending vereis 'n threshold van independent signers. Dit verberg nie die transaction nie, maar laat payment-authority van 'n captured laptop, field-node of single-operator skei.

**Pros:** strong compromise en insider-resistance; accountable approval; geen single field-device hou complete signing-authority nie; support recovery.

**Cons:** coordination en availability; signer/device/account metadata kan participants correlate; bad backup design cause loss; public multisig-patterns kan identifiable wees.

**Procedure:** (1) define signers, threshold, limits en recovery voor funding; (2) initialize op separate supported hardware/accounts; (3) verify addresses en backups independently; (4) gee field-workloads slegs unsigned requisition capability; (5) require out-of-band review van recipient, amount en purpose; (6) toets recovery en one-signer loss met small value; (7) rotate signer ná compromise.

**Detection:** approval-system, signer-device en public script/contract verskaf evidence; defenders alert op policy of signer-set changes. **Captured node:** dit moet hoogstens one low-authority session-key of unsigned request expose; cache nooit quorum material saam nie.

## Closed-loop community or event currency

**Mechanics:** 'n cooperative, conference of private test-environment issue credits wat slegs onder enrolled participants redeemable is. Internal transfer kan minder aan global payment-networks expose, terwyl operator issuance en redemption beheer.

**Pros:** bounded economic domain; kan offline of privacy-preserving payment UX toets; beperk external card-exposure; clear experimental controls.

**Cons:** small anonymity-set; operator en merchants observe activity; beperkte acceptance en redemption; licensing, consumer-protection en tax-rules kan selfs op local value apply.

**Procedure:** (1) obtain legal/compliance review en publish issuer-terms; (2) enrol consenting test-participants; (3) cap issuance en prohibit cash-like misuse; (4) gebruik fresh payment requests en minimize public participant-identifiers; (5) record aggregate reserves en private individual receipts; (6) test loss/refund/redemption; (7) close ledger en return residual value as promised.

**Detection:** issuer ledger, enrollment, merchant en redemption-records reconstruct flows; unusual circular transfers of rapid cash-out warrant review. **Captured wallet:** local balance en counterparties kan expose; cap value, encrypt state en support issuer-side freeze/reissue met auditable record.

## Bitcoin reusable payment codes and private payment instructions

**Mechanics:** BIP 47 payment codes gebruik 'n reusable public identifier plus ECDH-derived one-time deposit-addresses; BIP 351 specifyer 'n newer private-payment-instruction design. Hulle verminder public address reuse terwyl 'n recipient stable payment instructions kan publish. Notification, wallet support, funding en subsequent coin selection beïnvloed steeds privacy.<sup>[[20]](#references)</sup>

**Pros:** one public instruction kan distinct addresses yield; recipient hoef nie elke invoice-address publish nie; compatible wallets kan derived payments monitor; useful vir repeated lawful donors/customers.

**Cons:** wallet interoperability wissel; notification transactions of published payment code link 'n relationship-context; sender, recipient en public graph sien steeds transactions; careless consolidation of change handling defeats benefit.

**Procedure:** (1) confirm both maintained wallets support exact same specification/version; (2) back up en test recovery op 'n low-value wallet; (3) authenticate recipient payment-code out of band; (4) send small lawful test; (5) verify fresh derived address used; (6) label relationship locally en apply coin control; (7) test recovery en refund-behavior voor relying on it.

**Detection:** analysts examine notification patterns, funding/change, later consolidation en service boundaries; public-code publication identify recipient-context selfs wanneer deposit-addresses verskil. **Capture-resilient OPSEC:** hou spend-keys off field-devices en expose hoogstens 'n watch-only relationship-view. **Monitoring:** alert op unexpected notification-transactions, reused derived-addresses, wallet gap-limit/recovery-errors en unplanned consolidation.

## EVM stealth addresses (ERC-5564)

**Mechanics:** 'n sender derive 'n one-time stealth-account van 'n recipient se stealth meta-address en publish 'n announcement met ephemeral public-key en view-tag. Die recipient scan announcements met 'n viewing-key en derive die corresponding spend-key. Recipient-linkage verbeter, maar sender, amount/token, gas, announcement en later spending bly visible.<sup>[[21]](#references)</sup>

**Pros:** non-interactive fresh receiver-address; reusable meta-address; separate viewing en spending roles; works across supported EVM assets/applications.

**Cons:** announcement-scanning en spam; funding gas vir new address kan dit relink; sender ken recipient; public token/amount en eventual consolidation bly; implementation en wallet support wissel.

**Procedure:** (1) gebruik audited maintained implementation eers op 'n test network; (2) generate separate viewing en spending material en back up; (3) authenticate meta-address; (4) send low-value test en announcement; (5) scan en derive stealth-account; (6) test supported gas-sponsorship sonder personal funding-edge; (7) record public fields en preserve lawful accounting.

**Detection:** follow announcement caller, token/amount, timing, gas sponsor, spending en consolidation; 'n view-key kan receipt prove sonder spend toe te laat. **Capture-resilient OPSEC:** 'n networked scanner moet slegs viewing-role hê waar supported; hou spend- en recovery-keys elders. **Monitoring:** alert op malformed/spam announcements, view-key access, unexpected spend derivation en stealth outputs moved without approval.

## Liquid Confidential Transactions

**Mechanics:** Liquid blind output amounts en asset-types by default met commitments en proofs terwyl transaction graph, input/output count, fee en block-time visible bly. Peg-in/peg-out en service boundaries bly linkable, en users kan blinding-data selectively disclose.<sup>[[22]](#references)</sup>

**Pros:** confidential amount en asset-type by default; fast sidechain settlement; selective audit through blinding keys/descriptors; verberg commercially sensitive values vir public observers.

**Cons:** graph structure en timing bly; federation/bridge en exchange-trust; peg boundaries en unconfidential outputs; wallet/node/network-records; receiver en sender ken hul transaction.

**Procedure:** (1) select maintained Liquid-wallet en verify backup-model; (2) use testnet of small lawful amount; (3) receive na confidential address en verify wallet mark output blinded; (4) send test confidential transaction; (5) inspect watter explorer-fields public bly; (6) export slegs scoped blinding-proof needed vir audit; (7) document peg/exchange-boundaries en reconcile funds.

**Detection:** analyse visible graph/fee/time, peg en exchange-records, network metadata en later unblinding evidence; moenie hidden amount of asset infer nie. **Capture-resilient OPSEC:** skei spend-seed, blinding/view-data en watch-only operations. **Monitoring:** alert op accidental unconfidential addresses, unknown peg requests, descriptor changes en unapproved unblinding-key export.

## General payment or state channel

**Mechanics:** participants lock funds, exchange signed off-chain state-updates en publish slegs opening, closing of disputed state on chain. Intermediate payments word nie globally broadcast nie, maar peers en routing/intermediary-services observeer hul portion en endpoints moet die latest enforceable state retain.<sup>[[23]](#references)</sup>

**Pros:** baie vinnige low-fee private-to-public-ledger interactions; minder global transaction-detail; bounded channel-balance; useful vir metered services en repeated counterparties.

**Cons:** channel-peers ken mekaar en kan updates retain; opening/closing/value/timing correlate; online monitoring mag required wees tydens challenge-windows; implementation en liquidity-risk; nie op sigself 'n large anonymity-set nie.

**Procedure:** (1) choose maintained audited implementation en verstaan dispute-window; (2) open low-value test-channel tussen owned parties; (3) exchange signed state-updates met unique nonces; (4) back up latest enforceable state; (5) close cooperatively; (6) rehearse stale-state rejection op testnet; (7) preserve accounting en channel-peer-records.

**Detection:** public chain expose lifecycle/disputes; peers, watch-services en application-transport expose off-chain timing en parties. **Capture-resilient OPSEC:** cap hot-balance en hou latest signed state in encrypted recoverable store apart van field-nodes. **Monitoring:** watch voortdurend vir stale-state publication, missed backup, peer-key change en naderende challenge-deadline.

## Mobile carrier billing

**Mechanics:** 'n online service charge 'n purchase teen 'n mobile subscription of prepaid balance deur die carrier-billing system. Merchant kan 'n carrier authorization in plaas van card/bank-details ontvang, terwyl carrier subscriber/line, device/network-context, merchant, amount en time ken.<sup>[[24]](#references)</sup>

**Pros:** geen card-number by merchant nie; breë phone availability; bruikbaar vir low-value digital goods; carrier kan charges cap en reverse.

**Cons:** strongly identified deur SIM/account en dikwels device; small limits en high fees; merchant-category restrictions; account-takeover/SIM-swap-risk; carrier en aggregator skep complete transaction trail.

**Procedure:** (1) bevestig service availability, limit, fee en refund-terms met organization carrier-account; (2) enable dit slegs op 'n dedicated organization-line indien justified; (3) stel lowest useful spend-cap; (4) purchase benign test-item; (5) verify merchant en carrier receipts; (6) disable recurring authorization; (7) reconcile en turn off feature ná assessment.

**Detection:** carrier, aggregator en merchant records join line, subscriber, IP/device en charge; enterprise telecom invoices expose dit. **Capture-resilient OPSEC:** moenie 'n personal number gebruik nie en require carrier-account MFA buite field-device. **Monitoring:** enable instant charge/SIM-change-alerts en stop by unexpected premium-service-enrollment, forwarding of account-recovery.

## Open-banking payment initiation

**Mechanics:** met explicit user-consent vra 'n regulated payment-initiation service provider (PISP) die account-servicing bank om 'n transfer te initiate. Merchant ontvang moontlik nie card-credentials nie, maar PISP en banks behou regulated payer, payee, consent, device en transaction records.<sup>[[25]](#references)</sup>

**Pros:** geen reusable card-number by checkout nie; strong bank-authentication; exact account-to-account settlement; consent en status APIs; clear reconciliation.

**Cons:** nie anonymous teenoor banks/PISP nie; payee sien dikwels legal account-details of reference; phishing/redirect-risk; jurisdiction en refund-protections wissel; consent-metadata voeg another observer by.

**Procedure:** (1) verify PISP is currently regulated en merchant callback-domain authentic; (2) start from merchant-request; (3) review payee, amount, reference en requested consent at bank; (4) authorize slegs single payment; (5) verify final status independently; (6) revoke residual consent if any; (7) retain receipt en reconcile.

**Detection:** bank/PISP/merchant logs en transfer-references provide strong attribution. **Capture-resilient OPSEC:** hou banking authentication en recovery off operational/field-devices; device moet slegs paid-service entitlement hold. **Monitoring:** gebruik bank transaction/consent-alerts en investigate new PISP-grants, changed payee of status-callbacks outside expected session.

## Platform wallet, app-store balance or in-app credit

**Mechanics:** 'n platform bill die user of redeem account-credit, en issue dan 'n signed receipt of entitlement aan 'n application. App developer ontvang moontlik nie original funding-instrument nie, terwyl platform account, device, funding, product en redemption map.<sup>[[26]](#references)</sup>

**Pros:** merchant/developer kry geen primary PAN nie; fraud/refund en family/business-controls; small prepaid balance kan exposure cap; signed receipts simplify entitlement verification.

**Cons:** platform account is strong identity en behavior-hub; device en storefront-geography; gift-balance purchase/redemption-trail; limited cash-out; fraud-controls kan funds freeze; nie cross-platform money nie.

**Procedure:** (1) use organization-managed platform account waar policy permits; (2) review funding, region, refund en transferable-value rules; (3) add only approved budget; (4) purchase benign product through official store; (5) verify application receives only expected receipt-fields; (6) disable recurring purchase; (7) reconcile en remove account van operational hardware.

**Detection:** platform receipts/server notifications, account/device-login en funding records reconstruct purchase. **Capture-resilient OPSEC:** sign nooit 'n field node in by 'n personal store-account nie; provide slegs scoped app-entitlement waar moontlik. **Monitoring:** enable new-device/purchase-alerts en investigate receipt replay, family/account changes of unexpected restore events.

## Mutual credit, clearing or periodic net settlement

**Mechanics:** participants record obligations in a private ledger en settle periodically slegs elke net position. Individual service-events hoef nie separate public payments te create nie, maar ledger-operator en counterparties retain detailed attribution.

**Pros:** fewer external transactions en fees; public observers sien slegs net settlement; werk vir repeated organizations; explicit credit limits contain exposure.

**Cons:** centralized ledger is complete evidence en fraud-target; counterparty/default-risk; legal/accounting/tax-duties; small membership-set; unusual net-transfers kan relationships reveal.

**Procedure:** (1) gebruik slegs identified consenting organizations met legal/accounting approval; (2) define unit, credit limit, settlement interval en dispute-rules; (3) record every obligation met immutable approval; (4) laat separate finance-roles net-positions calculate en approve; (5) settle deur ordinary lawful rail; (6) reconcile individual lines to settlement; (7) close access en retain records under policy.

**Detection:** ledger, invoices, approvals en final bank/chain settlement provide ground truth; analysts should not infer missing gross activity solely from net-transfer. **Capture-resilient OPSEC:** operational devices kan bounded requisitions submit maar nie balances edit of settlement authorize nie. **Monitoring:** alert op credit-limit breach, backdated entries, administrator changes, reconciliation mismatch en settlement to new beneficiary.

## Capture/compromise exposure matrix

Dit pas 'n seizure/loss-test op elke family toe. Die doel is om spend-authority en unrelated identity-disclosure te beperk terwyl lawful accounting behoue bly—not to erase transactions or defeat an investigation.

| Technique family | A captured wallet/device/account can reveal | Minimum authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value en physical contacts | dra slegs approved amount; separate private accounting; prompt loss report; geen false records |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption en account/session-tokens | low balance; one purpose; truthful registration; issuer freeze/revocation waar beskikbaar |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery en merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; geen shared recovery-account |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices en project | role separation; least-privilege subaccount; finance credentials nooit op operational/field-nodes nie |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator of dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph en network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP en payment database | minimal hot balance; encrypted backup; separate node identity; close/recover per documented plan |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC en boundary transactions | separate spend/view roles; hardware support waar beskikbaar; geen exchange-session op field-node nie |
| Stablecoins, swaps, bridges and DEX | transparent graph, approvals, RPC/front-end state en destination assets | revoke allowances; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; encrypted backup soos protocol supports; redeem/reissue; never colocate funding credential |
| Paymaster, multisig/threshold | session key, one signer, pending operations en sponsor policy | narrow session-key; independent quorum; signer rotation; field-device cannot reach threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph en participant records | geen operational use nie; emulate slegs met synthetic/testnet evidence |
| Community/event currency | enrollment, local balance, counterparties en redemption | capped value; issuer freeze/reissue; consent en private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements en derived outputs | watch/view-only network role; offline/hardware spend-role; geen personal funding-session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries en disputes | separate spend/view/state-backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store-account, consent, receipt, device en funding-source | organization account; external MFA; low limit; geen personal account op field-hardware |
| Mutual-credit clearing | members, obligations, limits, approvals en settlement ledger | operational requisition only; separate immutable ledger en dual finance approval |

## Monitoring possible discovery or payment compromise

Payment-denial, 'n compliance-review of 'n wallet wat offline gaan bewys nie dat 'n investigation bestaan nie. Monitor slegs accounts, ledgers en infrastructure wat die organization geregtig is om te observeer; probeer nooit providers of counterparties om te toets of hulle met investigators saamwerk nie.

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund of loss report | missing instrument, redemption buite approved order, altered receipt of custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap of recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice en consumption | cross-project token, unknown admin, limit breach, invoice mismatch of unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation en beneficiary change | altered amount/payee, backdated ledger, unilateral release of unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels en consolidation | unknown spend, reused recipient output, wallet gap/recovery failure of unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure of coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP en chain dispute | unknown invoice payment, peer-key change, stale close of approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor en boundary transaction | spend without approval, transparent/unconfidential downgrade, key export of unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session-key en issuer action | wrong contract/public field, unknown approval/spend, paymaster change of issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway en bearer balance | unknown redemption, mint key/terms change, restore failure of balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate en destination | contract/route mismatch, unlimited approval, missing destination of bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum en recovery audit | unknown proposal/signer, threshold reduction, recovery activation of policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | synthetic lab ground truth en detection output only | enige real account, person of value wat die emulation betree: stop onmiddellik |

## Selection and verification workflow

1. Noem watter party nie watter field moet leer nie.
2. Identifiseer issuer/mint/custodian, public ledger, network/RPC, merchant en physical observers.
3. Verify current support, legality, limits, custody, recovery en refund-behavior.
4. Gebruik 'n small lawful end-to-end test.
5. Inspect merchant receipt, provider statement, public chain en wallet/node logs.
6. Test backup/recovery en deliberate audit-disclosure.
7. Hou required source, ownership, tax, sanctions en engagement-records accurate maar access-controlled.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Waarnemings oor data-insameling deur groot payment platforms](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Beskerm jou privacy](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — 'n Eenvoudige Payjoin-voorstel](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Tegniese spesifikasies en network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Bou privacy-applications met zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol en privacy-beperkings](https://docs.cashu.space/faq)
- [13] [Fedimint — Hoe dit werk](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Red Flag Indicators vir Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers en users van virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — Transfer information en crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Die Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State en payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
