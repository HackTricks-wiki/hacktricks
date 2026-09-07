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
