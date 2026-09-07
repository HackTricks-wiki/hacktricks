# Cryptocurrency Privacy

Cryptocurrency privacy is a protocol-and-operations question, not a synonym for secrecy or immunity. Public ledgers, exchanges, wallet servers, network peers, merchants and later transactions expose different parts of the graph.

{% hint style="danger" %}
This chapter is for lawful self-custody and data minimization. Do not use it to launder proceeds, evade sanctions/tax/reporting, transact with prohibited parties, mislead a regulated provider, or operate an unlicensed transmission service. Privacy technology does not change the legal origin or ownership of funds.
{% endhint %}

## Threat model by layer

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange, bank, broker, P2P counterparty | Identity, funding account, destination, device, IP, time |
| Ledger | Anyone running analytics | Addresses/outputs, amounts and time on transparent chains; protocol-specific metadata elsewhere |
| Wallet backend | RPC provider, explorer, remote node | Address queries, balances, IP, transaction broadcast |
| Network | ISP, peers, anonymity-network entry | IP, timing, volume and protocol use |
| Counterparty | Payer/payee | Invoice/address, delivery, conversation, account and timing |
| Endpoint | Malware, cloud backup, physical seizure | Seed, keys, labels, history, screenshots and clipboard |

Self-custody can remove a custodian from the control path but does not erase the ledger, acquisition record, network metadata or endpoint evidence.

## Protocol comparison

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody; fresh addresses avoid simple address reuse | Public permanent transaction graph; amount/timing and spending heuristics |
| Bitcoin PayJoin | Receiver input can break the common-input-ownership heuristic | Both wallets need support; transaction remains public; support is uneven |
| Bitcoin CoinJoin | Creates ambiguity among coordinated participants | Recognizable patterns, pre/post links, consolidation, policy/legal/provider risk |
| Lightning | Onion-routed payments are not globally published as ordinary transfers | Channels open/close on-chain; endpoints, peers, probes or custodian may infer data |
| Monero | Stronger default on-chain confidentiality for receiver, amount and sender set | Exchange, node, timing, endpoint and counterparty links remain |
| Ethereum/stablecoins | Broad availability and smart-contract interoperability | Public state/actions; RPC metadata; centralized issuers may block/freeze/report |

## Bitcoin: privacy-preserving baseline

Bitcoin is pseudonymous, not anonymous. Confirmed transactions are public and durable; address reuse, common-input ownership, change detection and publicly identified addresses can build clusters.<sup>[[1]](#references)</sup>

### Workflow

1. **Choose a maintained self-custody wallet.** Download from the official project, verify signatures/hashes when offered, and apply security updates.
2. **Create the wallet on a trusted endpoint.** Record the recovery seed offline; never place it in email, chat, screenshots or ordinary cloud notes. Test recovery before significant value.
3. **Keep only operational value hot.** Use suitable offline/hardware custody for longer-term value, with a recovery plan that does not expose the seed to a single fragile location.
4. **Generate a fresh receive address/invoice for every transaction.** Do not publish a static address when an invoice server or authenticated private delivery is possible.
5. **Use your own full node when feasible.** A third-party explorer/electrum server can learn queried addresses and IP metadata. Configure only wallet-supported Tor/proxy behavior; Tor hides a network edge, not the blockchain graph.
6. **Label every UTXO privately** with source, owner, purpose and compliance state. Enable coin control so unrelated identity contexts are not co-spent.
7. **Preview the transaction:** selected inputs, change destination, amount, fee, counterparty and whether the spend merges compartments. Avoid unnecessary consolidation.
8. **Keep lawful records separately and encrypted.** Preserve acquisition basis, invoices, authorization and tax/reporting information without publishing the mapping.
9. **Treat later spending as part of the same privacy decision.** A well-separated receipt can be relinked when its output is co-spent with identified funds.

Bitcoin Core's privacy documentation explains that a full node avoids revealing wallet queries to third-party servers but that transaction broadcast and public history still need analysis.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin is a collaborative payment in which the receiver adds an input. This defeats the simplistic assumption that all inputs belong to the sender. BIP 78 describes the original interactive protocol; draft BIP 77 defines an asynchronous v2 design using an encrypted mailbox/OHTTP.<sup>[[3]](#references)</sup>

Safe use:

1. Confirm that both maintained wallets support the same PayJoin version.
2. Obtain the PayJoin-capable invoice over an authenticated channel; protect it like any payment request.
3. Check the original amount and destination, then let the wallet validate the proposal/PSBT, fee contribution and prohibited substitutions.
4. Confirm the final wallet summary. Do not manually approve an unexpected output, amount or excessive fee.
5. If negotiation fails, understand whether the wallet safely falls back to an ordinary payment or requires a new invoice.
6. Retain the private receipt/records required for ownership, accounting and disputes.

PayJoin improves one chain-analysis heuristic; it does not hide the payment from the parties, acquisition platform, endpoints, or public ledger.

## CoinJoin: benefits and limits

CoinJoin coordinates multiple users in one transaction to make input-output mapping less certain. Research on specific historical Wasabi and Samourai designs found highly recognizable transactions and showed that pre/post-mix behavior can substantially narrow anonymity.<sup>[[4]](#references)</sup> That result should not be generalized to every implementation or future version, but it demonstrates why an “anonymity-set” number is not a guarantee.

Before any lawful use:

- check current local law, sanctions status, exchange/custodian policy and tax/reporting duties;
- use maintained, non-custodial software obtained from its official project;
- understand the coordinator model, fees, denial-of-service controls and whether the current service still operates—zkSNACKs ended its coordinator in 2024, although other Wasabi coordinators may exist;
- preserve source-of-funds and transaction records privately;
- never accept unknown funds on someone else's behalf or use a custodial “mixer” promising untraceable withdrawals;
- keep outputs separated by source/context and avoid later consolidation that destroys the intended ambiguity.

Legal outcomes are fact- and jurisdiction-specific. The 2025 Samourai guilty pleas concerned knowingly operating an unlicensed money transmitter that moved criminal proceeds; they do not establish that every collaborative transaction or privacy-seeking user is criminal.<sup>[[5]](#references)</sup>

## Lightning Network

Lightning's Sphinx onion routing is designed so an intermediate hop learns its predecessor and successor rather than the entire route.<sup>[[6]](#references)</sup> It is not blanket anonymity: channel funding/closure is public, nodes advertise topology, counterparties know endpoints, routing/probing can infer balances or parties, and a custodial wallet sees its user's account activity.

For better privacy:

1. Prefer a maintained non-custodial wallet if intermediary privacy matters; plan channel backup/recovery first.
2. Use a fresh invoice or offer for each payment. Verify whether the exact wallet supports BOLT 12/route blinding rather than assuming it does.
3. Avoid publishing unnecessary node aliases, contact details and stable network endpoints.
4. Connect through a supported privacy network if appropriate, understanding that uptime/timing patterns can still correlate.
5. Do not infer that an off-chain payment has no records: sender, receiver, peers, watchtowers, liquidity providers and wallet services may retain observations.

Published research has demonstrated sender/recipient and channel-balance inference from public data and active probing, though attacks and mitigations evolve.<sup>[[7]](#references)</sup>

## Monero

Monero uses one-time stealth addresses for outputs, RingCT to hide amounts, and ring signatures to provide probabilistic sender ambiguity; its current technical specifications document a ring size of 16 (15 decoys).<sup>[[8]](#references)</sup> These are stronger defaults for on-chain confidentiality than transparent ledgers, not magic protection from endpoint or operational mistakes.

### Lawful workflow

1. **Acquire lawfully.** A regulated exchange may know the purchase and withdrawal even when later on-chain details are confidential. Keep source, basis and reporting records.
2. **Install the official maintained wallet** and verify its download according to project instructions. Back up the seed offline and test restoration with a small amount.
3. **Prefer a local node** for maximum wallet-query privacy. If that is impractical, choose a trusted remote node reachable over an officially supported onion/I2P configuration. A remote node can log IP, requests, timing and transaction IDs; some lightweight designs disclose a view key.
4. **Use a new subaddress per payer, campaign or invoice.** A payer can correlate repeated use of the same subaddress.<sup>[[9]](#references)</sup>
5. **Label incoming contexts locally.** Avoid operationally merging separated receipts where a knowledgeable payer could recognize subsequent behavior.
6. **Protect network metadata.** Follow the official anonymity-network configuration; recognize documented leaks from timestamps, intermittent synchronization, bandwidth shape and stream reuse.<sup>[[10]](#references)</sup>
7. **Keep compliance/audit data private.** Disclose a view key or transaction proof only deliberately, to the intended auditor/party, and understand exactly what it reveals.

Historical traceability studies include bugs and decoy-selection eras that have since changed; do not apply old success percentages to current transactions. Likewise, FCMP++ remains roadmap work as of this chapter's September 2026 research cutoff, not a deployed protection.<sup>[[11]](#references)</sup>

## Ethereum and stablecoins

Ethereum's own privacy material notes that on-chain actions are visible and that wallet/RPC infrastructure adds IP and metadata exposure.<sup>[[12]](#references)</sup> Token transfers, approvals, smart-contract interactions, name services and gas funding can all connect identities.

Centralized stablecoins add issuer control. Current USDC and Tether terms reserve powers to block/freeze addresses or assets and comply with legal/process obligations.<sup>[[13]](#references)</sup> They may be useful payment instruments, but they are poor choices when the requirement is censorship resistance or on-chain anonymity.

## Compliance boundaries

- FATF recommendations are implemented through national law and change over time; its 2026 update emphasizes VASP licensing/registration and Travel Rule implementation.<sup>[[14]](#references)</sup>
- In the US, FinCEN distinguishes a person using convertible virtual currency for their own goods/services from a business accepting and transmitting or exchanging it; facts and later rules matter.<sup>[[15]](#references)</sup>
- The EU Transfer of Funds Regulation requires originator/beneficiary information where a crypto-asset service provider is involved and adds verification rules for certain transfers to/from self-hosted addresses.<sup>[[16]](#references)</sup>
- Sanctions and tax duties continue to apply. Screen as required, refuse prohibited parties, and maintain records; lists and legal status can change quickly.<sup>[[17]](#references)</sup>

Before material value, cross-border activity, privacy-enhancing coordination or business-like exchange/transmission, obtain current professional advice for the relevant jurisdictions.

## References

- [1] [Bitcoin.org — Protect your privacy](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy features](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — A Simple Payjoin Proposal](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adoption and Actual Privacy of Decentralized CoinJoin Implementations in Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Founders of Samourai Wallet plead guilty (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — An Empirical Analysis of Privacy in the Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html), and [Technical specifications](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Networks](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Exploring the Evolution of Monero's Privacy (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privacy on Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC Terms](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — 2026 Targeted Update on Virtual Assets and VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Application of FinCEN's Regulations to Persons Administering, Exchanging, or Using Virtual Currencies](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Sanctions Compliance Guidance for the Virtual Currency Industry](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
