# Privacy-Preserving Payment Protocols

Advanced payment systems can hide a payer from the merchant, hide a recipient or amount from a public ledger, or prevent a mint from linking withdrawal to redemption. These are different properties. None erases acquisition, device, network, delivery, accounting, sanctions or endpoint records.

{% hint style="danger" %}
Use only lawful funds and counterparties. Do not use privacy protocols to defeat required identification, sanctions, tax, source-of-funds checks or transaction reporting. Do not operate an exchange, mint or transmission service without understanding licensing, custody, AML and consumer-protection duties.
{% endhint %}

## Compare the advanced options

| Protocol | Hides from public/merchant | Trusted or observing party | Maturity/availability |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Outsiders cannot link a reusable payment code to its one-time outputs | Public Bitcoin graph remains; wallet/index server may see scans | Specification complete; wallet support varies |
| Zcash fully shielded Orchard | Sender, receiver and amount are encrypted on-chain | Wallet backend/network and acquisition/off-ramp remain | Deployed; shielded support varies by wallet/exchange |
| GNU Taler | Merchant need not learn payer identity; merchant income stays accountable | Taler exchange/bank sees funding; merchant sees order | Deployments are geographically limited |
| Federated Chaumian e-cash | Federation should not link issued notes to internal transfers/redemption | Guardian quorum custodies reserves; gateways see boundary activity | Emerging community deployments |
| Lightning BOLT 12/route blinding | Reduces receiver/node and route disclosure | Endpoints, selected hops, funding chain and wallet services | Support is wallet-dependent |
| Virtual card/token | Merchant receives constrained credential, not reusable PAN | Issuer/network retain payer and transaction | Mature and widely available |

## Bitcoin Silent Payments (BIP 352)

Silent Payments let a receiver publish one static payment code while each sender derives a unique Taproot output. An outside chain observer cannot directly link those outputs back to the published code, and no interactive address request or on-chain notification output is required. BIP 352 is marked **Complete**, but it introduces scanning cost and is incompatible with wallets that have not implemented it.<sup>[[1]](#references)</sup>

### Receiver workflow

1. Select a maintained wallet that explicitly supports BIP 352 receiving; verify the feature against the wallet's current documentation, not a social-media claim.
2. Back up the wallet seed and Silent Payment descriptor/key material using the wallet's documented recovery method. Test discovery on a small testnet/mainnet amount before publishing the code.
3. Generate separate **labels** for campaigns, invoices or counterparties where the wallet supports BIP 352 labels. Labels aid local accounting without publishing linkable addresses.
4. Publish the static Silent Payment code over an authenticated channel. It is reusable, but an impostor can substitute their own code.
5. Scan through a local full node when practical. A third-party index/scanning server can learn request timing or filter data even if it cannot spend.
6. Keep discovered UTXOs labeled and apply the same coin-control rules as ordinary Bitcoin. Spending or consolidating them can reveal ownership relationships.
7. Confirm recovery discovers payments without relying on an unbacked-up external index.

### Sender workflow

1. Confirm the wallet supports sending to the address version and authenticate the receiver's long static code.
2. Let the wallet construct the output; never convert or truncate the code manually.
3. Review selected inputs carefully. Silent Payments improve recipient-address privacy but sender inputs are still on the public graph.
4. Use wallet-supported fee bumping/PSBT behavior. BIP 352 requires output re-derivation if inputs change, and some signing modes are unsafe.
5. Retain an encrypted receipt or proof needed for disputes/accounting.

Silent Payments solve repeated recipient-address publication. They do not hide amount, transaction timing, sender cluster, acquisition history or later co-spending.

## Zcash fully shielded payments

Zcash supports transparent and shielded value pools. Orchard shielded transactions use zero-knowledge proofs so nodes can verify validity while transaction details are encrypted; Unified Addresses can contain multiple receiver types.<sup>[[2]](#references)</sup> Privacy depends on the actual path selected by the wallet, not the first character of a displayed address.

### Shielded workflow

1. Choose a maintained wallet that clearly identifies **shielded-by-default** behavior and current Orchard support. Verify the download and back up/test the seed.
2. Obtain ZEC lawfully and record basis/source. An exchange still knows the acquisition and withdrawal.
3. Receive to a Unified Address supported by the wallet, then inspect whether the transaction landed in a shielded pool. Do not assume automatic shielding without confirming wallet behavior.
4. Prefer **shielded-to-shielded** transfers. Transparent-to-shielded and shielded-to-transparent boundary movements expose public values/timing and can enable amount correlation; the Orchard specification notes that spending to a non-Orchard address reveals transaction value.<sup>[[3]](#references)</sup>
5. Avoid distinctive exact-amount round trips and immediate boundary crossings. This is privacy hygiene, not permission to obscure ownership or reporting.
6. Use the wallet's supported network-privacy path. Shielded cryptography does not hide IP/timing from wallet servers or peers.
7. Keep internal compliance records and use viewing keys only for deliberate audit/disclosure after understanding their scope.
8. Confirm recipient wallet/exchange support before sending; a forced transparent receiver changes the privacy property.

## GNU Taler: anonymous payer, accountable merchant

GNU Taler is an open electronic-payment protocol using traditional currencies, blind signatures and regulated exchange/bank integration. Its design aims to keep customers anonymous to merchants while merchants remain identifiable and taxable.<sup>[[4]](#references)</sup> It is not a cryptocurrency and availability depends on a compatible regional exchange, bank, wallet and merchant.

### User workflow where deployed

1. Identify an operating Taler exchange and merchant in the relevant currency/jurisdiction; read their current terms, fees, KYC and privacy notices.
2. Install the official wallet and verify its source. Protect wallet backup/recovery data like cash because wallet value can be a bearer asset.
3. Withdraw value through the supported bank/exchange flow using truthful information. The funding institution/exchange may know the withdrawal even though blind signatures break the direct coin-to-withdrawal link.
4. Review the merchant contract in the wallet: merchant identity, item/summary, amount, fees, refund and delivery terms.
5. Pay and preserve the receipt data required for refund, warranty, accounting or tax.
6. Do not reuse optional merchant session/account identifiers if merchant unlinkability is required.
7. Keep wallet, network and delivery metadata in the threat model; Taler's payment cryptography does not hide a shipping address or compromised endpoint.

The merchant and exchange remain accountable, and operating either component can be a regulated payment-service activity.

## Federated Chaumian e-cash

Chaumian e-cash uses blind signatures so a mint signs a token without seeing the unblinded token later spent. Fedimint distributes reserve custody and signing across a guardian federation; its documentation states that guardians see aggregate reserves/outstanding notes but should not see individual balance or who paid whom inside the federation.<sup>[[5]](#references)</sup>

This is **custodial bearer value**. A sufficient guardian quorum controls reserves; federation failure, dishonest guardians, software bugs or lost client state can cause loss. Deposits, withdrawals and Lightning gateways are visible boundary events and can correlate timing/amount.

### Limited-risk workflow

1. Use only a small amount you can afford to lose. Treat public/unknown federations as higher risk than guardians with real-world accountability.
2. Verify the federation invite through an authenticated channel and record guardian identities, quorum, jurisdiction, fees, recovery and shutdown policy.
3. Install a maintained compatible wallet, verify it, and understand its backup scheme before depositing.
4. Deposit lawfully acquired Bitcoin through the documented path. Record the peg-in for accounting and assume its timing/amount is public or known at the boundary.
5. Inside the federation, use fresh payment requests and avoid adding account/chat/delivery identifiers that recreate the link the blind signature removed.
6. For Lightning payments, treat the gateway as an additional observer of invoices and boundary timing.
7. Redeem/withdraw according to policy, expecting that a distinctive amount and immediate timing can correlate with a deposit or external payment.
8. Keep tax/source/authorization records privately; do not ask guardians or gateways to misstate activity.

Do not describe federated e-cash as trustless, self-custodial or guaranteed anonymous.

## BOLT 12 offers and route blinding

BOLT 12 offers can be reusable without publishing a stable on-chain address and may use blinded paths so a payer need not learn the receiver's clear node identity/path. This complements, but does not replace, Lightning's existing onion routing.

Before use:

1. Confirm sender and receiver wallets support the same current BOLT 12 features; do not infer support from generic “Lightning” branding.
2. Authenticate the offer out of band and check amount, issuer/description and recurrence rules.
3. Use a fresh invoice/payment context generated from the offer.
4. Keep node aliases, public contact information and stable network endpoints minimal.
5. Assume sender/receiver, first/last hop, wallet service, channel graph and on-chain funding/closure still disclose parts of the relationship.

## Auditability without public disclosure

Privacy and audit can coexist:

- Keep labels, invoices, authorization, cost basis and ownership mapping encrypted outside the public protocol.
- Separate a **view/audit key** from a spending key when the protocol provides one; test its exact disclosure on a sample wallet first.
- Give an auditor the minimum scoped proof rather than a seed or unrestricted spending credential.
- Record software version, protocol/pool, transaction ID or proof, counterparty purpose and exchange-rate source at transaction time.
- Define retention and deletion instead of accumulating a permanent unencrypted identity graph.

## Selection checklist

- [ ] The hidden field and observer are named precisely.
- [ ] Wallet/protocol support was verified as of the transaction date.
- [ ] Acquisition, network, node/RPC, counterparty, delivery and later-spend links are documented.
- [ ] Custody, recovery, liquidity, issuer/federation solvency and refund risks are accepted.
- [ ] Required identity, tax, sanctions, source and organizational records remain accurate.
- [ ] A small end-to-end test, including recovery and audit proof, succeeded.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
