# Financial Obfuscation Tradecraft

{{#include ../banners/hacktricks-training.md}}

Payment privacy is an attribution problem, not a payment-brand problem. An operation leaves evidence when value is acquired, moved, converted, spent and delivered. A public-chain address can be pseudonymous while an exchange, card issuer, merchant, mobile device or shipping camera identifies the person behind it.

This page explains financial-obfuscation patterns used in cybercrime and state-linked operations so defenders can recognize them. It does **not** provide a laundering, sanctions-evasion, false-identity or KYC-bypass procedure.

## The end-to-end value graph

```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
      |              |                |                 |             |
 bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```

An actor attempts to prevent any observer from seeing both ends. Investigators do the reverse: preserve records at each boundary, normalize time/value/fees and identify the **reconvergence point** where separate personas reuse one facilitator, device, account, merchant or destination.

## Instruments and their real observers

| Instrument | Hidden from merchant/public | Still visible to |
|---|---|---|
| Issuer virtual card/token | underlying card number | issuer, network/token provider, wallet, merchant account and delivery systems |
| Prepaid/gift value | sometimes legal name at ordinary purchase | retailer/payment rail, activation/redemption service, cameras, device and delivery |
| Cash | public ledger and remote issuer | counterparties, cameras, withdrawal/serial controls where applicable, physical search |
| Bitcoin/new address | direct legal name | every blockchain observer; wallet/network peers; acquisition/off-ramp services |
| CoinJoin/PayJoin | simple common-input/payment heuristics | public transaction, coordinator/peer/network metadata and later spending behavior |
| Privacy coin | public sender/receiver/amount, depending on protocol | acquisition/off-ramp, wallet endpoint, network observer and counterparty |
| Centralized mixer | direct deposit-to-withdraw link | mixer operator/logs, blockchain entry/exit sets and counterparties |
| Cross-chain bridge/swap | continuity on one chain | both chains, bridge/swap service, timing/value and liquidity constraints |
| OTC/P2P broker | direct exchange account in some cases | broker, communications, bank/cash movement, counterparties and devices |

## Cards, prepaid value, nominees and mules

### Virtual and masked cards

An issuer can create a merchant-locked or disposable card number. This reduces merchant exposure and cross-merchant number reuse. The issuer still maps it to the customer, funding account, device, IP and transaction. Billing descriptors, merchant account, shipping address and browser data remain linkable.

“No-name” card marketing does not imply anonymous settlement. Regulated issuers and distributors may perform identity checks, retain records, impose geography/amount limits and respond to legal process. A card obtained through a stolen identity adds identity theft; it does not remove issuer/device/merchant telemetry.

### Prepaid and gift value

Prepaid cards and gift codes separate a later redemption from the original payment instrument, but create a numbered object with purchase, activation, balance-query and redemption events. Patterns that matter include bulk purchases, repeated denomination just below controls, distant rapid redemption, one device checking many balances, or many cards converging on one merchant/account.

### Nominees, money mules and merchant fronts

A nominee or mule supplies an account and legal identity that sits between the operator and a service. Networks may layer recruiters, account holders, payment processors, shell merchants and cash-out brokers. This creates distance, but every participant adds communications, fees, behavioral inconsistency and a potential cooperating witness. Front companies add incorporation, tax, banking, director, invoice, hosting and shipment records.

Defenders should investigate shared devices/IPs, beneficiary reuse, geolocation contradictions, velocity inconsistent with account history, circular transfers, multiple unrelated senders converging, and immediate onward movement. Do not assume the named account holder is the controlling actor; treat them as a node requiring role determination.

## Public-chain transaction-obfuscation patterns

### Address rotation and coin control

Creating a new address for every receipt prevents trivial address reuse, but transactions can still join ownership through common inputs, change detection, exact value/time and later consolidation. **Coin control** lets a wallet choose which outputs to spend and avoid joining compartments. It improves hygiene; it cannot remove an already public link.

### Peel chains

A peel chain repeatedly spends a large balance, sending a smaller amount outward and returning the remainder to a new address:

```text
100 -> payment 3 + change 97
 97 -> payment 4 + change 93
 93 -> payment 2 + change 91 -> ...
```

The address changes at every step, but value continuity, cadence and transaction structure often form a recognizable chain. Legitimate exchange hot wallets can behave similarly, so attribution requires service/context evidence. DOJ has used peel-chain analysis in DPRK-linked forfeiture cases.<sup>[[1]](#references)</sup>

### Structuring and fan-out/fan-in

- **Fan-out:** one source splits into many addresses to increase investigative workload or prepare parallel conversion.
- **Fan-in:** many sources consolidate into one collector, revealing common control or a service.
- **Structuring:** repeated smaller transfers seek to avoid review thresholds or blend into ordinary volume.
- **Commingling:** illicit and unrelated funds share wallets, pools or services, making simplistic proportional claims unsafe.

Graph shape is a lead, not proof. Analysts should account for fees, UTXO/account model, service behavior and change conventions.

### CoinJoin and PayJoin

In a typical CoinJoin, several participants contribute inputs and receive outputs in one collaborative transaction, often with equal output denominations. This breaks the assumption that every input and output in a transaction has one owner. The anonymity set is limited by participant count and later behavior: unequal change, toxic change, consolidation or crossing a known service can reintroduce links.

PayJoin modifies an ordinary payment so both payer and payee contribute inputs, directly invalidating the common-input ownership heuristic for that transaction. It is primarily a payment privacy protocol, not a bulk laundering service. Detection should avoid declaring all inputs co-owned and should express uncertainty rather than force a false cluster.

### Centralized mixers and tumblers

A centralized mixer accepts deposits and later pays different coins from a pooled reserve, often after fees and delays. Its privacy depends on pool size, withdrawal policy, logs, operator honesty and resistance to seizure. Entry and exit timing/value analysis, deposit addresses, service wallet clustering and records can narrow the set. Operators can steal funds or retain a complete mapping.

Legal exposure is substantial and jurisdiction-specific. DOJ cases against ChipMixer, Samourai Wallet and Tornado Cash developers/operators and changing sanctions litigation show that protocol, custody, control and money-transmission facts matter; a label such as “decentralized” is not a legal conclusion.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps and bridges

Chain hopping converts an asset or moves it through a bridge, breaking a one-ledger query but not economic continuity:

```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
        t0, amount A                    t1, amount B - fees
```

Analysts correlate bridge contracts/service deposit addresses, transaction order, time window, exchange rate, fees, liquidity and unique amount. Repeated swaps may enlarge ambiguity while adding provider/API/wallet telemetry. FATF specifically identifies chain hopping, mixers, peer-to-peer services and anonymity-enhanced currencies as risk indicators when combined with suspicious context.<sup>[[3]](#references)</sup>

### NFTs, gambling and merchant purchases

Self-dealing or collusive NFT trades can give funds an apparent sale narrative; gambling may exchange deposits for withdrawals; goods can convert digital value into resalable inventory. These paths leave marketplace accounts, creator/royalty links, wash-trading graphs, odds/play history, device logs, delivery and resale evidence. A loss or fee is not proof that provenance disappeared.

## Privacy-preserving cryptocurrencies

Privacy protocols differ technically:

- **Monero** uses one-time addresses, ring signatures and confidential amounts, reducing public sender/receiver/amount visibility. Network observation, wallet compromise, acquisition/off-ramp and counterparty records remain outside those on-chain protections.
- **Zcash shielded pools** can hide sender, receiver and amount when shielded transactions are used; transparent addresses and transitions between pools remain public, and usage patterns affect the effective anonymity set.
- **Bitcoin** is transparent by default. New addresses, CoinJoin, PayJoin and Lightning change particular linkage assumptions but do not make all layers private.

Privacy technology has legitimate safety and commercial uses. From an investigative perspective, when the ledger provides less information, endpoint, service, network and human evidence become more important. Never infer criminality from the choice of a privacy-preserving protocol alone.

## DPRK multi-layer case model

Public DOJ allegations and forfeiture actions describe a composed process, not one trick:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workers used fictitious/stolen identity material and VPNs to obtain remote employment;
2. employers paid cryptocurrency, including stablecoins;
3. funds moved in smaller amounts, crossed chains or tokens, purchased NFTs or were commingled;
4. other stolen funds entered mixers;
5. OTC traders and front companies converted value into fiat payments or goods;
6. repeated facilitators, accounts and blockchain paths allowed investigators to reconnect the layers.

Treasury stated that Lazarus used Blender.io to process part of the Axie Infinity/Ronin theft, while the FBI has published addresses and urged bridges, exchanges, RPC operators and analytics firms to block funds linked to later TraderTraitor thefts.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

The lesson is bidirectional: state actors use ordinary commercial/criminal services, and public blockchains let defenders follow value even when names are initially unknown.

## Detection workflow

1. **Preserve the raw transaction identifiers and records.** Screenshots and rounded fiat values are insufficient.
2. **Normalize assets and time.** Record chain, token contract, units, block time, service time zone, fees and exchange-rate source.
3. **Label evidence confidence.** Distinguish a service-published address, deterministic contract event, clustering heuristic and external intelligence.
4. **Trace both directions.** Find funding origin, immediate dispersal, reconvergence, bridge exits, service deposits and spend/delivery.
5. **Join off-chain evidence.** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping and communication records often resolve ambiguity.
6. **Test alternative explanations.** Exchanges, custodians, payroll and privacy protocols can produce fan-in/out or co-spends without common beneficial ownership.
7. **Monitor rather than prematurely close.** A dormant output may become attributable when it later reaches a service.
8. **Apply current sanctions/AML obligations with counsel.** Rules and designations change; historical association is not a substitute for current legal analysis.

## Safe red-team procurement model

An authorized team may need the target SOC not to recognize its hosting payment while the engagement controller retains accountability:

- use an engagement-specific organization card or documented corporate wallet;
- keep billing, tax and provider records accurate;
- separate the operator from procurement duties and limit access to the attribution map;
- never use a mule, false identity, stolen card, sanctions workaround or unlicensed exchanger;
- record asset, amount, owner, service, date, refund path and teardown evidence;
- disclose relevant payment/provider indicators to the controller after the exercise.

This creates **blindness to the exercise participant**, not blindness to law, provider or governance.

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework (peel-chain example and DPRK investigations)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer takedown](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Forfeiture complaint concerning $7.74 million allegedly laundered for DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions and Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea responsible for the 2025 Bybit theft](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Application of regulations to virtual-currency users, administrators and exchangers](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
