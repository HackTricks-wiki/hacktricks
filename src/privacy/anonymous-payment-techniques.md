# Anonymous Payment Technique Catalog

This catalog covers payment **families** from ordinary cash through blind-signature e-cash and public-chain obfuscation. “Anonymous” always means anonymous from a named observer. A merchant, issuer, mint, exchange, blockchain analyst, network provider, employer and physical observer see different facts.

The procedures below are for lawful funds, truthful accounts and authorized procurement. Techniques whose purpose in the cited cases was laundering, sanctions evasion or identity fraud are explained and detected, but their procedure is a synthetic forensic exercise—not instructions for performing the crime.

## Coverage matrix

| Family | Main privacy property | Main observer/trust | Treatment |
|---|---|---|---|
| Cash and cash equivalents | no remote payment-network record | recipient and physical environment | lawful workflow |
| Prepaid/gift/voucher value | separates redemption from primary card | seller, issuer and redemption service | lawful workflow, jurisdiction varies |
| Virtual/tokenized card | hides reusable PAN or separates merchants | issuer/network/wallet still identifies payer | lawful workflow |
| Payment app/intermediary | merchant may see alias/intermediary | app collects identity/device/transaction | comparison baseline |
| Bitcoin hygiene/Silent Payments | pseudonyms and recipient unlinkability | public graph and wallet/network boundary | deployable |
| PayJoin/CoinJoin | weakens common ownership/linkage heuristics | participants/coordinator/network/public graph | deployable where supported; legal review |
| Lightning/BOLT 12 | off-chain routing and receiver-path reduction | endpoints, hops, services and channel graph | deployable where supported |
| Monero/Zcash/MWEB | protocol-level on-chain confidentiality | acquisition, endpoint, network and boundary remain | deployable where lawful/supported |
| Ethereum ZK application | hides a specified statement/action link | public inputs, RPC, relayer and app | application-specific |
| Cashu/Fedimint/Taler | blind-signature payer privacy | mint/federation/exchange custody and boundaries | emerging/deployment-specific |
| Stablecoins | convenient digital settlement | transparent chain plus issuer freeze/control | not anonymous baseline |
| Swaps/bridges/DEX | moves value across asset/chain | both graphs, contracts and providers | forensic mechanics; ordinary lawful swaps only |
| Mixers/peel/structuring | increases graph ambiguity/work | entry/exit graph and service records | synthetic detection exercise only |
| Nominees/mules/OTC/fronts | inserts human/business intermediaries | facilitators, banks, communications | criminal-abuse analysis only |
| Reusable/stealth payment addresses | fresh recipient address per payment | public announcement/notification and wallet boundaries | deployable where supported |
| Confidential sidechain/state channel | hides amount/asset or intermediate updates | peers, bridge/federation and lifecycle settlement | protocol-specific |
| Carrier/open-banking/platform billing | hides primary card from merchant | carrier, bank/PISP or platform identifies customer | ordinary identified payment |
| Mutual credit/net settlement | fewer external settlement records | private ledger operator has full mapping | identified participants only |

## Cash

**Mechanics:** physical bearer value changes hands without an online issuer authorization or public ledger.

**Pros:** merchant need not learn bank/card identity; no remote transaction graph; broadly understandable and final.

**Cons:** face-to-face only; theft/loss; change/receipt/serial or reporting controls; withdrawal, cameras, witnesses and location still link the payer.

**Procedure:** (1) confirm cash is legal/accepted and any amount/reporting rule; (2) withdraw or receive it lawfully and keep private accounting records; (3) pay an ordinary merchant without unnecessary loyalty/account identifiers; (4) request only the receipt required; (5) avoid shipping/account data if the purchase does not need it; (6) record legitimate business purpose internally.

**Detection:** reconcile till/receipt/inventory, cameras and access logs under applicable policy; investigate unusual cash refunding or repeated just-below-control amounts without treating ordinary cash use as suspicious by itself.

## Money order, postal order, cashier instrument and cash on delivery

**Mechanics:** a regulated issuer converts cash/account funds into a numbered instrument payable to a named recipient; COD defers collection to delivery.

**Pros:** recipient may not receive the payer's primary bank/card number; usable where cash cannot travel remotely; clear receipt.

**Cons:** issuer/retailer retains purchase/identity data as required; serial tracking; recipient/delivery address; loss/fraud and regional restrictions; not generally anonymous.

**Procedure:** (1) check issuer rules, limits, identification and recipient acceptance; (2) buy with truthful information and lawful funds; (3) complete payee/amount immediately; (4) preserve serial/receipt; (5) use tracked delivery appropriate to value; (6) reconcile redemption/refund.

**Detection:** issuer purchase/redemption record, instrument serial, retailer/camera, shipping and recipient account; flag alteration, duplicate serials and rapid geographically inconsistent redemption.

## Open-loop prepaid card

**Mechanics:** a network-branded stored-value credential authorizes against a prepaid balance rather than a primary credit account.

**Pros:** limits merchant exposure and loss; separates merchant from main PAN; usable online where accepted.

**Cons:** purchase/activation/reload/registration and device records; KYC and limits vary; billing-address failures; cash-out/refund restrictions; “no name” does not mean no issuer record.

**Procedure:** (1) verify current issuer identity, fees, KYC, geography and online/recurring support; (2) acquire through an authorized seller with lawful funds; (3) register truthful required data; (4) use for one compartment/purpose; (5) do not structure loads or fabricate residency; (6) retain purchase/expense evidence and close/dispose per issuer terms.

**Detection:** join seller/activation, funding, device/IP, merchant authorization, balance checks and redemption/refund. Patterns matter more than the prepaid label.

## Closed-loop gift card, voucher and transferable service credit

**Mechanics:** numbered value is redeemable only with one merchant/service or ecosystem. Airtime/game/store credits are variants.

**Pros:** recipient merchant may see only code/balance; limited blast radius; easy gifting and budget separation.

**Cons:** seller and service log purchase/activation/redemption; account/device/delivery still link; scams, resale discounts and expiry/region limits; weak refund rights.

**Procedure:** (1) buy only from authorized channels; (2) record code value without exposing the secret; (3) avoid attaching an identifying loyalty account if unnecessary; (4) redeem through a separate legitimate merchant account/context; (5) keep receipt until accepted; (6) never buy codes for an unsolicited “tax/support/ransom” demand.

**Detection:** code issuance/redemption time, device/account convergence, bulk/threshold-pattern purchase, one device checking many balances, and distant rapid redemption.

## Cryptocurrency-funded card or gift-code broker

**Mechanics:** an intermediary accepts cryptocurrency and issues a card, voucher or merchant code. This is a cross-rail conversion: the merchant sees ordinary card/gift value, while the broker links the on-chain deposit to issuance and delivery.

**Pros:** merchant does not receive the funding wallet; useful for legitimate merchants that do not accept crypto; bounded stored value.

**Cons:** not anonymous from broker/issuer; KYC, sanctions, exchange and card-program rules; public deposit graph; account/device/email and code redemption reconnect both sides; scam/insolvency risk.

**Procedure:** (1) verify the legal entity, card issuer, supported jurisdiction, KYC, fees and refund policy; (2) use only lawful documented funds; (3) test the smallest denomination; (4) verify network/merchant restrictions before purchase; (5) preserve both blockchain transaction and broker receipt for accounting; (6) never use a broker promising identity fraud, sanctions bypass or “untraceable” cash-out.

**Detection:** correlate broker deposit addresses, unique amount/time, account/device and issued-card authorization or gift-code redemption; issuer and broker records bridge the public chain to the merchant.

## Virtual or merchant-locked card

**Mechanics:** the issuer maps a generated PAN/token to the real account, often restricting merchant, amount or expiration.

**Pros:** prevents reusable PAN disclosure; merchant compartmentation; spend limits and easy revocation; mature fraud control.

**Cons:** issuer still knows payer, funding, merchant, device/IP and time; merchant sees account/delivery; some refunds/recurring charges fail; not anonymous.

**Procedure:** (1) use the regulated issuer's official feature; (2) create a card for one merchant/engagement; (3) set the smallest useful limit and expiry; (4) use accurate billing where required; (5) verify statement descriptor/refund behavior; (6) freeze/delete after final settlement while retaining audit evidence.

**Detection:** issuer token-to-account mapping, merchant authorization, device and delivery. Defenders use merchant-specific reuse, velocity and account takeover signals.

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization substitutes a constrained credential for the PAN, often bound to a device, merchant or payment scenario.<sup>[[1]](#references)</sup>

**Pros:** merchant does not receive the reusable PAN; device cryptography/dynamic data reduce cloning; revocable without replacing card.

**Cons:** issuer, token service, wallet platform and network retain mappings/transactions; device/platform account and location may identify payer.

**Procedure:** (1) enroll a legitimate card in the official wallet; (2) protect platform account/device with strong authentication; (3) verify device token/last digits at purchase; (4) disable unnecessary location/analytics where supported; (5) remove lost devices/token immediately; (6) review issuer and wallet records.

**Detection:** token requestor/device cryptogram and issuer mapping, wallet/account telemetry, merchant terminal and physical evidence.

## Payment app, marketplace wallet and centralized intermediary

**Mechanics:** the service maintains accounts and transfers internally or over bank/card rails; the merchant may see an alias while the service sees both parties.

**Pros:** convenience, dispute/refund mechanisms, recipient does not necessarily see bank/card details.

**Cons:** centralized identity/social/transaction/device graph; freezes and legal process; counterparties can expose profile; data use may exceed payment necessity.<sup>[[2]](#references)</sup>

**Procedure:** (1) read identity, privacy, retention and buyer-protection terms; (2) minimize optional profile/contact synchronization; (3) use a separate truthful account only when terms allow; (4) enable MFA/alerts; (5) verify recipient and privacy of memo/profile; (6) export records and close unused links.

**Detection:** provider account, device/IP, contact graph, funding/withdrawal, memo and merchant records. An alias is pseudonymity from a counterparty, not anonymity from the platform.

## Bank transfer, ACH, wire and instant-account payment

**Mechanics:** regulated institutions move value between identified accounts and exchange required payment data.

**Pros:** fast, accountable, reversible in limited cases, strong records; virtual account numbers may reduce merchant disclosure.

**Cons:** banks/processors know both sides; statements and references; not anonymous; cross-border and Travel Rule/AML data.

**Procedure:** use only when accountability is acceptable: verify beneficiary independently, minimize optional memo data, use a bank-provided virtual account/reference where available, enable alerts, retain invoice and reconcile.

**Detection:** deterministic bank/payment records, beneficiary/account ownership, device/session and fraud controls. This is a baseline, not an anonymity technique.

## Account and merchant compartmentation

**Mechanics:** separate lawful identities/accounts, email aliases, cards and delivery contexts prevent unrelated merchants from trivially joining activity while an issuer/controller keeps the mapping.

**Pros:** reduces breach and cross-merchant linkage; easy to audit; compatible with regulated payments.

**Cons:** provider still maps compartments; recovery phone/device/IP and shipping can reconnect them; policy may forbid multiple accounts.

**Procedure:** (1) define one purpose; (2) create only terms-compliant aliases/subaccounts; (3) use a merchant-specific token/card; (4) disable cross-account contact/ad personalization; (5) keep an encrypted controller ledger; (6) retire identifiers after refunds/retention needs end.

**Detection:** providers join recovery, device, funding and IP; merchants join delivery, browser and account behavior. Defenders should distinguish legitimate compartmentation from synthetic identity fraud.

## Controlled red-team procurement

**Mechanics:** the SOC is blind to a purchase while an exercise controller retains legal entity, operator and infrastructure mapping.

**Pros:** realistic detection exercise; no personal exposure; immediate deconfliction and audit.

**Cons:** not anonymous to organization/provider; governance overhead; leaks if the controller ledger is mishandled.

**Procedure:** (1) allocate an engagement-specific organization card/wallet/budget; (2) separate purchaser/operator roles; (3) record asset, amount, service, purpose and kill date; (4) store attribution mapping with limited controller access; (5) never use false identity/mule/stolen funds; (6) reveal/reconcile indicators and refunds at closeout.

**Detection:** controller maps provider invoice and asset; SOC tests independent discovery through domain, certificate, hosting and traffic rather than cardholder data.

## Bitcoin address hygiene and coin control

**Mechanics:** fresh receive addresses, local labeling and selective UTXO spending reduce address reuse and accidental compartment merging on a public ledger.

**Pros:** broadly supported; self-custodial; avoids the simplest public linkage.

**Cons:** all transactions/amounts remain public; common-input/change/timing and later consolidation link activity; acquisition/RPC/network records remain.

**Procedure:** (1) install/verify a maintained wallet; (2) back up and test seed recovery; (3) use a new address per invoice; (4) label source/purpose locally; (5) use coin control to avoid merging contexts; (6) prefer a local node or privacy-aware connection; (7) preview change/fees and retain lawful accounting.<sup>[[3]](#references)</sup>

**Detection:** address graph, common-input/change heuristics with uncertainty, exact amount/time, consolidation, service deposits, node/RPC broadcast timing and off-chain records.

## Bitcoin Silent Payments

**Mechanics:** BIP 352 lets a receiver publish a static code while senders derive unique Taproot outputs via ECDH; outside observers cannot directly link outputs to the code.<sup>[[4]](#references)</sup>

**Pros:** reusable public identifier without address reuse; no interactive address request or notification output; blends into Taproot outputs.

**Cons:** receiver scanning cost; wallet support varies; amount/sender graph and spending remain public; index server can observe scans.

**Procedure:** (1) select a current BIP 352 wallet; (2) back up/test descriptor and scanning recovery; (3) generate labeled code where supported; (4) authenticate the published code; (5) sender reviews inputs and sends a small test; (6) receiver scans preferably through own node; (7) keep received UTXOs separated.

**Detection:** not reliably identifiable from output alone by design; analysts use sender inputs, amount/time, later spending, wallet/network/index and counterparty records.

## PayJoin

**Mechanics:** payer and payee contribute inputs to one payment transaction, breaking the assumption that all inputs share one owner.<sup>[[5]](#references)</sup>

**Pros:** ordinary payment with improved privacy; benefits the wider graph by weakening a common heuristic; no equal-output crowd required.

**Cons:** interactive/support requirement; receiver endpoint availability; amount and final transaction public; implementation and fallback metadata.

**Procedure:** (1) confirm both maintained wallets support the same PayJoin version; (2) authenticate invoice/endpoint; (3) start from the wallet's PayJoin-enabled payment URI; (4) inspect final amount/fee and sign only expected inputs; (5) avoid manual transaction surgery; (6) verify broadcast and receipt; (7) record fallback if negotiation fails.

**Detection:** blockchain analysts must not force common-input clustering; endpoint/provider may log negotiation; use wallet/network and later-spend evidence rather than transaction shape alone.

## CoinJoin

**Mechanics:** multiple participants collaboratively create a transaction with many inputs/outputs, commonly equal denominations, increasing ambiguity about input-output correspondence.

**Pros:** larger on-chain ambiguity set; self-custodial designs exist; measurable round structure.

**Cons:** coordinator/peer/network metadata; fees/liquidity; identifiable transaction shape; toxic change and later consolidation destroy gains; legal/provider availability varies.

**Procedure:** (1) verify current wallet/coordinator availability and legality; (2) install official wallet and back up; (3) use only lawful UTXOs; (4) understand denomination, fee and coordinator model; (5) keep change and mixed outputs labeled/separate; (6) never consolidate them together; (7) route network traffic as officially supported and preserve accounting.

**Detection:** identify collaborative structure without assuming crime; calculate possible mappings/anonymity set, then watch change/consolidation, service boundaries and network/coordinator records.

## Lightning Network

**Mechanics:** HTLC payments traverse onion-routed channels; most payment details are not published on chain, while funding/closing and public channel information are.

**Pros:** fast, low fee; intermediaries normally see adjacent hops; routine payment details stay off chain.

**Cons:** sender/receiver and first/last hop know more; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets identify users.

**Procedure:** (1) choose self-custodial versus custodial knowingly; (2) verify wallet/seed/channel recovery; (3) use an invoice for the exact payment; (4) prefer private channels/LSP features only after reading tradeoffs; (5) protect node IP with supported Tor where needed; (6) avoid reusing identifying invoices; (7) keep channel and payment accounting.<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs, channel graph/probes, payment failure/timing and on-chain funding/closure; no public transaction does not mean no records.

## BOLT 12 offers and route blinding

**Mechanics:** a reusable offer produces fresh invoices and may advertise blinded paths so the payer need not learn the receiver's clear node/path.

**Pros:** receiver privacy; reusable donation/payment endpoint without static invoice; integrates with Lightning onion routing.

**Cons:** wallet support varies; endpoints, selected hops and funding remain; public contact or network endpoint can reidentify receiver.

**Procedure:** (1) confirm matching BOLT 12 support; (2) authenticate offer; (3) request a fresh invoice; (4) review amount/issuer/recurrence; (5) pay through the wallet; (6) verify receipt/refund behavior; (7) minimize node alias/contact and preserve accounting.<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP and first/last-hop telemetry, offer distribution account, timing/value and funding graph; route blinding intentionally limits payer visibility.

## Monero

**Mechanics:** one-time stealth addresses hide recipient linkage, RingCT hides amounts and ring signatures provide sender ambiguity.

**Pros:** privacy is default on chain; sender/receiver/amount confidentiality; mature dedicated wallet/node ecosystem.

**Cons:** acquisition/off-ramp and endpoint/network/counterparty records; remote node sees queries/IP; exchange support/legal treatment varies; small operational mistakes still link contexts.

**Procedure:** (1) acquire lawfully and retain basis/source; (2) install/verify official maintained wallet; (3) back up/test seed; (4) use a local node or documented Tor/I2P remote-node path; (5) use new subaddress per payer/invoice; (6) label contexts locally; (7) disclose transaction proof/view access only deliberately.<sup>[[8]](#references)</sup>

**Detection:** focus on exchange/merchant/device/network and seized-wallet evidence; protocol use alone is not suspicious and the public chain deliberately exposes less.

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs validate shielded transfers while sender, receiver and amount are encrypted; transparent pools and pool transitions remain public.

**Pros:** strong shielded on-chain confidentiality; viewing keys can support scoped audit; protocol-enforced validity.

**Cons:** wallet/exchange support and actual pool choice vary; transparent boundary timing/value correlation; network/RPC and endpoint remain.

**Procedure:** (1) select a maintained Orchard shielded-by-default wallet; (2) verify/back up; (3) obtain ZEC lawfully; (4) receive to supported Unified Address and confirm pool; (5) prefer shielded-to-shielded; (6) use supported network privacy; (7) test viewing-key disclosure on a small wallet before audit.<sup>[[9]](#references)</sup>

**Detection:** transparent boundary and service records, wallet/network metadata and viewing keys where lawfully provided; do not assume all Unified Address payments were shielded.

## Mimblewimble and Litecoin MWEB

**Mechanics:** confidential transactions hide amounts and Mimblewimble-style aggregation removes conventional address-rich history; Litecoin implements an optional extension block alongside its transparent chain.

**Pros:** confidential amounts and improved fungibility in the private domain; efficient pruning/aggregation.

**Cons:** opt-in boundary peg-in/out is public and correlatable; wallet/exchange support; interactive/address model differences; network and acquisition records.

**Procedure:** (1) choose a maintained wallet with explicit MWEB support; (2) verify/back up and test small amount; (3) acquire lawfully; (4) peg into MWEB and verify balance domain; (5) transact only with a compatible receiver; (6) avoid immediate distinctive peg-out; (7) retain private audit records.<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value, exchange/wallet/node data and later transparent spends; internal confidential transfer details are intentionally reduced.

## Ethereum zero-knowledge privacy applications

**Mechanics:** a circuit proves a statement—membership, valid note ownership or authorization—without revealing the secret; a verifier contract checks it. Deposits, withdrawals, public inputs, events and gas can still expose links.

**Pros:** programmable selective disclosure; anonymous-set applications; verifiable rules without revealing all data.

**Cons:** contract/circuit bugs; small anonymity set; public boundaries; RPC/IP/session/analytics/gas funding; application and sanctions/legal risk.

**Procedure:** (1) define exactly what the proof hides; (2) use an audited maintained application where lawful; (3) inspect public inputs/events and deposit/withdraw rules; (4) separate action wallet and gas sponsorship as the protocol intends; (5) use a privacy-aware RPC/network path; (6) test with small value; (7) preserve compliance records.<sup>[[11]](#references)</sup>

**Detection:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics and eventual exchange/merchant boundary. Do not claim the ZK proof hides fields declared public.

## Stablecoins

**Mechanics:** tokens transfer on a public chain; centralized issuers may freeze/blacklist or redeem against identified accounts.

**Pros:** price stability, liquidity and merchant support; fast settlement; easy accounting.

**Cons:** transparent address/amount/contract graph; gas funding; issuer and exchange identity/control; sanctions screening; generally poor anonymity.

**Procedure:** treat as identified payment: use a fresh business address only for compartmentation, verify token contract/network, test small amount, protect wallet, use trusted RPC/local node, retain basis/source and screen required parties.

**Detection:** complete token event graph, issuer freeze list/actions, exchange/RPC/device and gas-funding relationships.

## Cashu Chaumian e-cash

**Mechanics:** a mint blindly signs client-generated bearer secrets backed by the mint's Bitcoin/Lightning reserves; it can prevent double-spend without directly linking issuance to later redemption.

**Pros:** accountless bearer tokens; instant peer transfer; mint cannot directly link blinded withdrawal to spend; tokens can move as data/QR.

**Cons:** mint custody/solvency/censorship; bearer data loss/theft; denomination/timing and Lightning boundaries; network metadata; early software ecosystem.<sup>[[12]](#references)</sup>

**Procedure:** (1) use an official test mint or tiny disposable value first; (2) install a maintained wallet and test backup/restore limitations; (3) authenticate mint and review custody/fees; (4) mint a small amount; (5) send token over an authenticated private channel/QR; (6) receiver swaps token before treating it final; (7) redeem and reconcile. Never store meaningful value in an untrusted mint.

**Detection:** mint sees network, issue/redeem/Lightning boundaries and spent-token set but blinding removes direct token linkage; endpoints/messages and distinctive amount/timing can restore links.

## Fedimint federated e-cash

**Mechanics:** a threshold of guardians holds reserves and blind-signs e-cash; internal bearer transfers are private from guardians, while Lightning gateways bridge external payments.

**Pros:** distributes custody; private internal transfer; community governance; no single guardian controls reserve below threshold.

**Cons:** guardian quorum/custody/software risk; gateway observes invoices/timing; deposit/withdraw boundaries; client-state recovery complexity.

**Procedure:** (1) verify federation invite/guardians/quorum/jurisdiction; (2) install maintained client and test recovery; (3) deposit a small lawful amount; (4) use fresh internal payment requests; (5) treat gateway as observer for Lightning; (6) test redemption; (7) retain source/tax records outside public payment data.<sup>[[13]](#references)</sup>

**Detection:** federation sees aggregate issuance/redemption, gateways see external invoices, Bitcoin/Lightning show boundaries, and endpoint/communication evidence can link internal transfers.

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash aims to keep the payer anonymous to merchants while merchants and income remain accountable.

**Pros:** payer privacy by design; ordinary currency; merchant accountability/refunds; no speculative token required.

**Cons:** limited deployments; exchange/bank sees funding; merchant sees order/delivery; wallet bearer/recovery risk; regulated operators.

**Procedure:** (1) locate a current exchange/merchant for the jurisdiction/currency; (2) read KYC/fees/privacy; (3) install official wallet; (4) withdraw lawfully from supported bank/exchange; (5) review merchant contract; (6) pay and preserve receipt/refund data; (7) avoid unnecessary merchant session identifiers.<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal and merchant deposit are accountable boundaries; merchant order/device/delivery and timing may correlate even when coins are blinded.

## Cross-chain bridge, atomic swap and decentralized exchange

**Mechanics:** a contract/service locks/burns one asset and releases/mints another, or counterparties atomically exchange. It breaks a single-ledger view, not economic continuity.

**Pros:** asset/network interoperability; can avoid one centralized custodian; ordinary portfolio/liquidity use.

**Cons:** both chains are public; time/value/fees/liquidity and contracts correlate; bridge/relayer/frontend/RPC records; smart-contract/counterparty and regulatory risk.

**Procedure for lawful swaps:** (1) verify official contract/service and legal availability; (2) inspect custody/audit/fees/slippage; (3) use a small test; (4) record both transaction IDs and rate; (5) protect approvals; (6) reconcile destination asset and revoke unnecessary approval. Do not use swaps to disguise source of funds.

**Detection:** bridge deposit/withdraw events, unique amount minus fees, time order, liquidity, relayer/RPC/frontend and later service deposits.

## Centralized mixer or tumbler

**Mechanics:** a service receives deposits into a pool and returns different units later, attempting to obscure direct input-output mapping.

**Pros:** can enlarge transaction ambiguity in theory.

**Cons:** operator can steal/log; entry/exit timing/value analysis; sanctions/money-transmission and criminal exposure; seizures expose mappings; taint/rejection risk.

**Procedure:** no operational mixing guide is provided. Reproduce the graph safely by extending [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): create synthetic deposits, pooled outputs, fees and delays; give analysts incomplete mappings; measure which heuristics work; then reveal ground truth.

**Detection:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs and downstream consolidation. Label probabilistic attribution.

## Peel chains, fan-out/fan-in and structuring

**Mechanics:** repeated transactions peel small payments from change, split value across many addresses, reconverge collectors, or divide amounts to avoid review.

**Pros:** increases naive analyst workload and address count.

**Cons:** recognizable value/cadence/transaction continuity; consolidation and service endpoints; structuring can itself be illegal; fees and operational errors.

**Procedure:** use only synthetic CSV/testnet data: generate a large source, repeated payment/change edges, parallel branches and one collector; add benign exchange-like examples; tune detection and document false positives.

**Detection:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint and off-chain records. Exchange hot wallets can resemble these patterns, so context is mandatory.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mechanics:** another person/account/company receives, converts or spends funds, inserting legal and operational layers between controller and transaction.

**Pros to an adversary:** named account does not immediately identify controller; can bridge cash, crypto, goods and jurisdictions.

**Cons:** identity fraud/money-laundering exposure; every participant adds communications, bank/company/tax/shipping records, fees, inconsistency and witnesses; facilitator reuse creates hubs.

**Procedure:** do not emulate with real people/accounts. Build a synthetic graph with controller, recruiter, mule, OTC, shell merchant and beneficiary; seed device/IP/message/bank edges; ask investigators to distinguish account holder from controller and record evidence confidence.

**Detection:** shared device/IP/recovery, unusual beneficiary/velocity, many unrelated senders, immediate onward movement, company/director/invoice inconsistency, communications and cash/commodity delivery.

## NFTs, gambling, merchant goods and refund loops

**Mechanics:** value is converted into a self-priced asset, wagering balance, resalable goods or refunds to create a different transaction narrative.

**Pros to an adversary:** changes asset form and introduces marketplace/merchant intermediaries.

**Cons:** marketplace/account/device and wash-trade graph; odds/play and refund records; delivery/resale evidence; fees/losses; fraud/laundering liability.

**Procedure:** no concealment workflow. Use synthetic marketplace data with related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument and common shipping; validate detection against legitimate collectors/customers.

**Detection:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery and proceeds reconvergence.

## Physical bearer wallet or offline token transfer

**Mechanics:** a device, paper/QR, hardware bearer instrument or e-cash token transfers control of a secret rather than broadcasting a payment at handover.

**Pros:** no live network event during exchange; useful offline; physical cash-like custody.

**Cons:** copy/theft/loss and uncertain exclusivity; later redemption/broadcast links; physical meeting/shipping; counterfeit/tamper risk.

**Procedure:** (1) use only a reviewed instrument/protocol; (2) initialize/verify authenticity privately; (3) load only small lawful value; (4) transfer in a documented authorized context; (5) receiver verifies or sweeps promptly as protocol requires; (6) never assume the sender retained no copy; (7) record ownership/tax evidence privately.

**Detection:** purchase/funding and eventual sweep/redemption, device serial/tamper evidence, delivery/meeting and endpoint records.

## Merchant-scoped invoice or one-time payment request

**Mechanics:** the merchant creates a single-use request containing amount, expiry and order reference. The payer settles it through a supported rail without exposing a reusable credential directly to the merchant; the issuer or payment processor may still identify both parties.

**Pros:** limits credential reuse and accidental cross-merchant identifiers; exact amount/expiry reduce errors; compatible with ordinary accounting and refunds.

**Cons:** invoice, delivery, browser, processor and issuer still link the order; a unique amount/time can strengthen correlation; malicious payment links are common.

**Procedure:** (1) authenticate the merchant independently; (2) request a fresh invoice with exact amount, asset/network and expiry; (3) inspect the destination and refund rules; (4) pay from the approved engagement compartment; (5) verify the merchant acknowledges the same invoice; (6) preserve receipt and transaction reference; (7) expire rather than reuse the request.

**Detection:** merchant and processor join invoice, session and settlement; unique amounts/timing and delivery identify the payer. **Captured wallet/device:** invoice history exposes counterparties and purpose; minimize unnecessary memo data, encrypt the device and keep authoritative accounting in the controlled finance system.

## Prepaid service credit and capability token

**Mechanics:** a service converts a conventional payment into bounded internal credits or a bearer capability. Subsequent API/resource use can avoid presenting the original card on every request, but the service can often map issuance to redemption.

**Pros:** caps spend and compromise loss; separates day-to-day workers from the funding credential; supports per-project budgets and revocation.

**Cons:** usually pseudonymous, not anonymous; service database, redemption IP and unique usage pattern link activity; bearer tokens can be stolen; refunds may require the original payer.

**Procedure:** (1) purchase credits through an organization account; (2) create one project and budget; (3) issue a narrow token with service, amount and expiry constraints; (4) store it only in the approved secret manager or workload identity path; (5) test rejection outside scope and after expiry; (6) monitor consumption; (7) revoke and reconcile unused value.

**Detection:** provider joins funding account, project, token issuance and usage; defenders alert on geographic/process changes and anomalous consumption. **Captured node:** assume its remaining capability can be spent; use short expiry, low balance, audience binding and immediate server-side revocation.

## Privacy Pass or blinded authorization token

**Mechanics:** an issuer produces a privacy-preserving authorization token that an origin can validate without linking redemption to issuance. It can represent paid entitlement or rate-limited access, but is not itself a general currency. The architecture separates client, attester, issuer and origin roles and warns that IP/timing or collusion can undo unlinkability.<sup>[[18]](#references)</sup>

**Pros:** unlinkable redemption for supported services; no reusable account cookie at the origin; cached tokens can separate issuance and use in time.

**Cons:** application-specific; issuer/attester trust and anonymity-set partitioning; IP and browser metadata remain; token theft or distinctive issuance timing can correlate use.

**Procedure:** (1) use an implementation conforming to the relevant Privacy Pass token type; (2) define exactly what entitlement the token proves; (3) separate issuer and origin administration where the threat model requires it; (4) minimize challenge metadata; (5) issue several test tokens and redeem each once at owned origins; (6) compare logs for forbidden stable identifiers; (7) test replay, expiry and revocation/abuse controls.

**Detection:** origins see redemption IP/time and token validity; issuers/attesters see issuance context; analysts test timing and metadata partitions without assuming a cryptographic break. **Captured client:** unspent bearer tokens may be usable; bound their value, lifetime and audience, and never cache the funding credential with them.

## Delegated organization procurement or fiscal sponsor

**Mechanics:** an authorized procurement team, reseller or fiscal sponsor contracts and pays while the operational team receives a bounded service. This is role separation with truthful records, not a nominee or false identity.

**Pros:** vendors need not receive every operator's identity or personal payment details; central compliance, tax and refund handling; clear budget and offboarding.

**Cons:** sponsor knows the beneficiary and purpose; contracts, approvals, delivery and accounts remain; added delay/fees; weak separation if the same individual administers every layer.

**Procedure:** (1) document business purpose, beneficiary and approving authority; (2) select an organization-approved intermediary; (3) contract under truthful details; (4) provision a project-scoped subaccount with no personal billing credential; (5) separate finance administrators from operators; (6) reconcile invoices and access; (7) terminate both service and delegated access at closeout.

**Detection:** procurement, identity-provider, vendor and delivery records join the chain. **Captured operational device:** it should reveal the service project but not finance credentials; keep invoices and payer identities in the finance system, not on field nodes.

## Escrow or conditional settlement

**Mechanics:** a trusted escrow agent or smart contract holds value until documented conditions are met. It can reduce direct disclosure between payer and payee, while escrow and underlying payment rails retain the relationship.

**Pros:** dispute and delivery protection; payer and merchant can expose fewer reusable credentials to each other; auditable release conditions.

**Cons:** escrow custody/contract risk, fees and identity obligations; on-chain contracts are public; order, shipping and dispute data remain; not anonymous to the intermediary.

**Procedure:** (1) verify legal entity, custody, fees, dispute forum and supported assets; (2) create an exact written milestone and refund path; (3) fund from an approved organization account; (4) verify receipt and release authorization independently; (5) release only after evidence; (6) preserve the complete audit record; (7) close unused permissions or contract approvals.

**Detection:** escrow account/contract events, funding and release time, beneficiary and dispute records reveal the transaction. **Captured device:** session tokens or contract approvals may permit release; require separate approver/MFA and revoke active sessions on loss.

## Batched or pooled organization settlement

**Mechanics:** many approved obligations are aggregated and settled in fewer bank or blockchain transactions, with a private internal ledger assigning each share. Batching can reduce public per-purchase detail but the coordinator retains complete attribution.

**Pros:** lower fees; fewer public graph edges; hides individual line items from a public observer when amounts are aggregated; straightforward internal accounting.

**Cons:** coordinator is a complete observer and high-value target; distinctive totals/timing can correlate; custody and reconciliation risk; can resemble structuring if abused.

**Procedure:** (1) define participants and lawful obligations in the accounting system; (2) set a regular, business-justified batch window rather than thresholds designed to avoid controls; (3) require dual approval of the aggregate; (4) settle to authenticated recipients; (5) reconcile every internal line to the batch; (6) handle refunds as linked corrections; (7) protect ledger access and retain it per policy.

**Detection:** coordinator ledger, approval and beneficiary records provide ground truth; public analysts use input/output/value/time clustering cautiously. **Captured payer device:** it should contain only its requisition, not the pool's signing key or participant ledger.

## Account-abstraction paymaster or sponsored gas

**Mechanics:** a relayer/bundler submits a smart-account operation and a paymaster pays transaction fees, avoiding a direct native-gas funding edge from the user wallet. It improves one graph property; the operation, contract and service telemetry remain public or observable.<sup>[[19]](#references)</sup>

**Pros:** removes a common gas-funding link; supports scoped sponsorship and rate limits; better onboarding for legitimate privacy applications.

**Cons:** paymaster/bundler/RPC/front end can correlate requests; contract events and public inputs remain; sponsorship policy fingerprints a cohort; malicious contracts or approvals can steal assets.

**Procedure:** (1) use an audited maintained smart account and paymaster on the correct network; (2) inspect which fields are public and what the sponsor logs; (3) limit sponsorship by contract, function, amount, nonce and expiry; (4) test with low value; (5) submit through the application's intended privacy-aware path; (6) verify the operation and fee payer on chain; (7) revoke allowances/session keys and retain compliance records.

**Detection:** join UserOperation, EntryPoint, paymaster, bundler/RPC and application logs; cluster identical sponsorship policy cautiously. **Captured wallet:** session keys and pending approvals may be usable even without gas; scope them tightly and revoke through the account's recovery policy.

## Threshold or multisignature payment authorization

**Mechanics:** spending requires a threshold of independent signers. It does not hide the transaction, but lets payment authority be separated from any captured laptop, field node or single operator.

**Pros:** strong compromise and insider resistance; accountable approval; no single field device holds complete signing authority; supports recovery.

**Cons:** coordination and availability; signer/device/account metadata can correlate participants; bad backup design causes loss; public multisig patterns can be identifiable.

**Procedure:** (1) define signers, threshold, limits and recovery before funding; (2) initialize on separate supported hardware/accounts; (3) verify addresses and backups independently; (4) give field workloads only unsigned requisition capability; (5) require out-of-band review of recipient, amount and purpose; (6) test recovery and one-signer loss with small value; (7) rotate a signer after compromise.

**Detection:** approval system, signer device and public script/contract provide evidence; defenders alert on policy or signer-set changes. **Captured node:** it should expose at most one low-authority session key or unsigned request; never cache quorum material together.

## Closed-loop community or event currency

**Mechanics:** a cooperative, conference or private test environment issues credits redeemable only among enrolled participants. Internal transfer may expose less to global payment networks, while the operator controls issuance and redemption.

**Pros:** bounded economic domain; can test offline or privacy-preserving payment UX; limits external card exposure; clear experimental controls.

**Cons:** small anonymity set; operator and merchants observe activity; limited acceptance and redemption; licensing, consumer-protection and tax rules may apply even to local value.

**Procedure:** (1) obtain legal/compliance review and publish issuer terms; (2) enroll consenting test participants; (3) cap issuance and prohibit cash-like misuse; (4) use fresh payment requests and minimize public participant identifiers; (5) record aggregate reserves and private individual receipts; (6) test loss/refund/redemption; (7) close the ledger and return residual value as promised.

**Detection:** issuer ledger, enrollment, merchant and redemption records reconstruct flows; unusual circular transfers or rapid cash-out warrant review. **Captured wallet:** local balance and counterparties may be exposed; cap value, encrypt state and support issuer-side freeze/reissue with an auditable record.

## Bitcoin reusable payment codes and private payment instructions

**Mechanics:** BIP 47 payment codes use a reusable public identifier plus ECDH-derived one-time deposit addresses; BIP 351 specifies a newer private-payment instruction design. They reduce public address reuse while allowing a recipient to publish stable payment instructions. Notification, wallet support, funding and subsequent coin selection still affect privacy.<sup>[[20]](#references)</sup>

**Pros:** one public instruction can yield distinct addresses; recipient need not publish every invoice address; compatible wallets can monitor derived payments; useful for repeated lawful donors/customers.

**Cons:** wallet interoperability varies; notification transactions or published payment code link a relationship context; sender, recipient and public graph still see transactions; careless consolidation or change handling defeats the benefit.

**Procedure:** (1) confirm that both maintained wallets support the exact same specification/version; (2) back up and test recovery on a low-value wallet; (3) authenticate the recipient payment code out of band; (4) send a small lawful test; (5) verify that a fresh derived address was used; (6) label the relationship locally and apply coin control; (7) test recovery and refund behavior before relying on it.

**Detection:** analysts examine notification patterns, funding/change, later consolidation and service boundaries; public-code publication identifies the recipient context even when deposit addresses differ. **Capture-resilient OPSEC:** keep spend keys off field devices and expose at most a watch-only relationship view. **Monitoring:** alert on unexpected notification transactions, reused derived addresses, wallet gap-limit/recovery errors and unplanned consolidation.

## EVM stealth addresses (ERC-5564)

**Mechanics:** a sender derives a one-time stealth account from a recipient's stealth meta-address and publishes an announcement containing an ephemeral public key and view tag. The recipient scans announcements with a viewing key and derives the corresponding spend key. Recipient linkage improves, but sender, amount/token, gas, announcement and later spending remain visible.<sup>[[21]](#references)</sup>

**Pros:** non-interactive fresh receiver address; reusable meta-address; separate viewing and spending roles; works across supported EVM assets/applications.

**Cons:** announcement scanning and spam; funding gas for the new address can relink it; sender knows recipient; public token/amount and eventual consolidation remain; implementation and wallet support vary.

**Procedure:** (1) use an audited maintained implementation on a test network first; (2) generate separate viewing and spending material and back it up; (3) authenticate the meta-address; (4) send a low-value test and announcement; (5) scan and derive the stealth account; (6) test supported gas sponsorship without a personal funding edge; (7) record public fields and preserve lawful accounting.

**Detection:** follow announcement caller, token/amount, timing, gas sponsor, spending and consolidation; a view key can prove receipt without granting spend. **Capture-resilient OPSEC:** a networked scanner should have only the viewing role where supported; keep spend and recovery keys elsewhere. **Monitoring:** alert on malformed/spam announcements, view-key access, unexpected spend derivation and stealth outputs moved without approval.

## Liquid Confidential Transactions

**Mechanics:** Liquid blinds output amounts and asset types by default using commitments and proofs while leaving the transaction graph, input/output count, fee and block time visible. Peg-in/peg-out and service boundaries remain linkable, and users can selectively disclose blinding data.<sup>[[22]](#references)</sup>

**Pros:** confidential amount and asset type by default; fast sidechain settlement; selective audit through blinding keys/descriptors; hides commercially sensitive values from public observers.

**Cons:** graph structure and timing remain; federation/bridge and exchange trust; peg boundaries and unconfidential outputs; wallet/node/network records; receiver and sender know their transaction.

**Procedure:** (1) select a maintained Liquid wallet and verify its backup model; (2) use testnet or a small lawful amount; (3) receive to a confidential address and verify the wallet marks the output blinded; (4) send a test confidential transaction; (5) inspect which explorer fields remain public; (6) export only the scoped blinding proof needed for audit; (7) document peg/exchange boundaries and reconcile funds.

**Detection:** analyze visible graph/fee/time, peg and exchange records, network metadata and later unblinding evidence; do not infer hidden amount or asset. **Capture-resilient OPSEC:** separate spend seed, blinding/view data and watch-only operations. **Monitoring:** alert on accidental unconfidential addresses, unknown peg requests, descriptor changes and unapproved unblinding-key export.

## General payment or state channel

**Mechanics:** participants lock funds, exchange signed off-chain state updates and publish only opening, closing or disputed state on chain. Intermediate payments are not globally broadcast, but peers and routing/intermediary services observe their portion and endpoints must retain the latest enforceable state.<sup>[[23]](#references)</sup>

**Pros:** many fast low-fee private-to-public-ledger interactions; less global transaction detail; bounded channel balance; useful for metered services and repeated counterparties.

**Cons:** channel peers know one another and can retain updates; opening/closing/value/timing correlate; online monitoring may be required during challenge windows; implementation and liquidity risk; not a large anonymity set by itself.

**Procedure:** (1) choose a maintained audited implementation and understand its dispute window; (2) open a low-value test channel between owned parties; (3) exchange signed state updates with unique nonces; (4) back up the latest enforceable state; (5) close cooperatively; (6) rehearse stale-state rejection on testnet; (7) preserve accounting and channel-peer records.

**Detection:** public chain exposes lifecycle/disputes; peers, watch services and application transport expose off-chain timing and parties. **Capture-resilient OPSEC:** cap hot balance and keep the latest signed state in an encrypted recoverable store separate from field nodes. **Monitoring:** watch continuously for stale-state publication, missed backup, peer-key change and an approaching challenge deadline.

## Mobile carrier billing

**Mechanics:** an online service charges a purchase to a mobile subscription or prepaid balance through the carrier billing system. The merchant may receive a carrier authorization instead of card/bank details, while the carrier knows the subscriber/line, device/network context, merchant, amount and time.<sup>[[24]](#references)</sup>

**Pros:** no card number at the merchant; broad phone availability; usable for low-value digital goods; carrier can cap and reverse charges.

**Cons:** strongly identified by SIM/account and often device; small limits and high fees; merchant category restrictions; account takeover/SIM-swap risk; carrier and aggregator create a complete transaction trail.

**Procedure:** (1) confirm service availability, limit, fee and refund terms with the organization carrier account; (2) enable it only on a dedicated organization line if justified; (3) set the lowest useful spend cap; (4) purchase a benign test item; (5) verify merchant and carrier receipts; (6) disable recurring authorization; (7) reconcile and turn off the feature after the assessment.

**Detection:** carrier, aggregator and merchant records join line, subscriber, IP/device and charge; enterprise telecom invoices expose it. **Capture-resilient OPSEC:** do not use a personal number and require carrier-account MFA outside the field device. **Monitoring:** enable instant charge/SIM-change alerts and stop on unexpected premium-service enrollment, forwarding or account recovery.

## Open-banking payment initiation

**Mechanics:** with explicit user consent, a regulated payment-initiation service provider (PISP) asks the account-servicing bank to initiate a transfer. The merchant may not receive card credentials, but the PISP and banks retain regulated payer, payee, consent, device and transaction records.<sup>[[25]](#references)</sup>

**Pros:** no reusable card number at checkout; strong bank authentication; exact account-to-account settlement; consent and status APIs; clear reconciliation.

**Cons:** not anonymous to banks/PISP; payee often sees legal account details or reference; phishing/redirect risk; jurisdiction and refund protections vary; consent metadata adds another observer.

**Procedure:** (1) verify that the PISP is currently regulated and the merchant callback domain is authentic; (2) start from the merchant request; (3) review payee, amount, reference and requested consent at the bank; (4) authorize only the single payment; (5) verify final status independently; (6) revoke residual consent if any; (7) retain receipt and reconcile.

**Detection:** bank/PISP/merchant logs and transfer references provide strong attribution. **Capture-resilient OPSEC:** keep banking authentication and recovery off operational/field devices; the device should hold only a paid-service entitlement. **Monitoring:** use bank transaction/consent alerts and investigate new PISP grants, changed payee or status callbacks outside the expected session.

## Platform wallet, app-store balance or in-app credit

**Mechanics:** a platform bills the user or redeems account credit, then issues a signed receipt or entitlement to an application. The app developer may not receive the original funding instrument, while the platform maps account, device, funding, product and redemption.<sup>[[26]](#references)</sup>

**Pros:** merchant/developer gets no primary PAN; fraud/refund and family/business controls; small prepaid balance can cap exposure; signed receipts simplify entitlement verification.

**Cons:** platform account is a strong identity and behavior hub; device and storefront geography; gift-balance purchase/redemption trail; limited cash-out; fraud controls can freeze funds; not cross-platform money.

**Procedure:** (1) use an organization-managed platform account where policy permits; (2) review funding, region, refund and transferable-value rules; (3) add only the approved budget; (4) purchase a benign product through the official store; (5) verify the application receives only expected receipt fields; (6) disable recurring purchase; (7) reconcile and remove the account from operational hardware.

**Detection:** platform receipts/server notifications, account/device login and funding records reconstruct the purchase. **Capture-resilient OPSEC:** never sign a field node into a personal store account; provide only a scoped app entitlement where possible. **Monitoring:** enable new-device/purchase alerts and investigate receipt replay, family/account changes or unexpected restore events.

## Mutual credit, clearing or periodic net settlement

**Mechanics:** participants record obligations in a private ledger and periodically settle only each net position. Individual service events need not create separate public payments, but the ledger operator and counterparties retain detailed attribution.

**Pros:** fewer external transactions and fees; public observers see only net settlement; works for repeated organizations; explicit credit limits contain exposure.

**Cons:** centralized ledger is complete evidence and a fraud target; counterparty/default risk; legal/accounting/tax duties; small membership set; unusual net transfers can still reveal relationships.

**Procedure:** (1) use only identified consenting organizations with legal/accounting approval; (2) define unit, credit limit, settlement interval and dispute rules; (3) record every obligation with immutable approval; (4) let separate finance roles calculate and approve net positions; (5) settle through an ordinary lawful rail; (6) reconcile individual lines to the settlement; (7) close access and retain records under policy.

**Detection:** ledger, invoices, approvals and final bank/chain settlement provide ground truth; analysts should not infer missing gross activity solely from the net transfer. **Capture-resilient OPSEC:** operational devices can submit bounded requisitions but cannot edit balances or authorize settlement. **Monitoring:** alert on credit-limit breach, backdated entries, administrator changes, reconciliation mismatch and settlement to a new beneficiary.

## Capture/compromise exposure matrix

This applies a seizure/loss test to every family. The objective is to limit spend authority and unrelated identity disclosure while retaining lawful accounting—not to erase transactions or defeat an investigation.

| Technique family | A captured wallet/device/account can reveal | Minimum authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value and physical contacts | carry only approved amount; separate private accounting; prompt loss report; no false records |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption and account/session tokens | low balance; one purpose; truthful registration; issuer freeze/revocation where available |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery and merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; no shared recovery account |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices and project | role separation; least-privilege subaccount; finance credentials never on operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator or dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph and network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP and payment database | minimal hot balance; encrypted backup; separate node identity; close/recover per documented plan |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC and boundary transactions | separate spend/view roles; hardware support where available; no exchange session on field node |
| Stablecoins, swaps, bridges and DEX | transparent graph, approvals, RPC/front-end state and destination assets | revoke allowances; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; encrypted backup as protocol supports; redeem/reissue; never colocate funding credential |
| Paymaster, multisig/threshold | session key, one signer, pending operations and sponsor policy | narrow session key; independent quorum; signer rotation; field device cannot reach threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph and participant records | no operational use; emulate with synthetic/testnet evidence only |
| Community/event currency | enrollment, local balance, counterparties and redemption | capped value; issuer freeze/reissue; consent and private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements and derived outputs | watch/view-only network role; offline/hardware spend role; no personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries and disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device and funding source | organization account; external MFA; low limit; no personal account on field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals and settlement ledger | operational requisition only; separate immutable ledger and dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial, a compliance review or a wallet going offline does not prove that an investigation exists. Monitor only accounts, ledgers and infrastructure the organization is entitled to observe; never probe providers or counterparties to test whether they are cooperating with investigators.

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund or loss report | missing instrument, redemption outside approved order, altered receipt or custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap or recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice and consumption | cross-project token, unknown admin, limit breach, invoice mismatch or unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation and beneficiary change | altered amount/payee, backdated ledger, unilateral release or unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels and consolidation | unknown spend, reused recipient output, wallet gap/recovery failure or unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure or coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP and chain dispute | unknown invoice payment, peer-key change, stale close or approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor and boundary transaction | spend without approval, transparent/unconfidential downgrade, key export or unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key and issuer action | wrong contract/public field, unknown approval/spend, paymaster change or issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway and bearer balance | unknown redemption, mint key/terms change, restore failure or balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate and destination | contract/route mismatch, unlimited approval, missing destination or bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum and recovery audit | unknown proposal/signer, threshold reduction, recovery activation or policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | synthetic lab ground truth and detection output only | any real account, person or value entering the emulation: stop immediately |

## Selection and verification workflow

1. Name which party must not learn which field.
2. Identify issuer/mint/custodian, public ledger, network/RPC, merchant and physical observers.
3. Verify current support, legality, limits, custody, recovery and refund behavior.
4. Use a small lawful end-to-end test.
5. Inspect the merchant receipt, provider statement, public chain and wallet/node logs.
6. Test backup/recovery and deliberate audit disclosure.
7. Keep required source, ownership, tax, sanctions and engagement records accurate but access-controlled.

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
