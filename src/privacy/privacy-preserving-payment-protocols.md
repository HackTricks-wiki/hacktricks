# Privacy-Preserving Payment Protocols

{{#include ../banners/hacktricks-training.md}}

Advanced payment systems can hide a payer from the merchant, hide a recipient or amount from a public ledger, or prevent a mint from linking withdrawal to redemption. These are different properties. None erases acquisition, device, network, delivery, accounting, sanctions or endpoint records.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md)는 모든 payment family에 대해 표준화된 `Pros`, `Cons`, 단계별 `Procedure`, `Detection` 항목을 제공합니다. 이 페이지에서는 advanced protocols를 확장하여 설명합니다.

{% hint style="danger" %}
법적으로 허용된 자금과 거래 상대방만 사용하십시오. 필수 identification, sanctions, tax, source-of-funds checks 또는 transaction reporting을 회피하기 위해 privacy protocols를 사용하지 마십시오. licensing, custody, AML 및 consumer-protection duties를 이해하지 않은 상태로 exchange, mint 또는 transmission service를 운영하지 마십시오.
{% endhint %}

## Compare the advanced options

| Protocol | public/merchant로부터 숨기는 정보 | Trusted or observing party | Maturity/availability |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | 외부 관찰자는 재사용 가능한 payment code를 일회성 outputs에 연결할 수 없음 | Public Bitcoin graph는 그대로 남음; wallet/index server는 scans를 확인할 수 있음 | Specification complete; wallet support varies |
| Zcash fully shielded Orchard | Sender, receiver 및 amount가 on-chain에서 암호화됨 | Wallet backend/network 및 acquisition/off-ramp는 그대로 남음 | Deployed; shielded support varies by wallet/exchange |
| GNU Taler | Merchant가 payer identity를 알 필요 없음; merchant income은 추적 가능하게 유지됨 | Taler exchange/bank는 funding을 확인함; merchant는 order를 확인함 | Deployments are geographically limited |
| Federated Chaumian e-cash | Federation은 issued notes를 internal transfers/redemption에 연결하지 않아야 함 | Guardian quorum이 reserves를 custody함; gateways는 boundary activity를 확인함 | Emerging community deployments |
| Lightning BOLT 12/route blinding | Receiver/node 및 route disclosure를 줄임 | Endpoints, selected hops, funding chain 및 wallet services | Support is wallet-dependent |
| Virtual card/token | Merchant는 재사용 가능한 PAN이 아닌 제한된 credential를 받음 | Issuer/network는 payer 및 transaction을 보유함 | Mature and widely available |

## Bitcoin Silent Payments (BIP 352)

Silent Payments를 사용하면 receiver가 하나의 static payment code를 게시하고 각 sender가 고유한 Taproot output을 도출할 수 있습니다. 외부 chain observer는 해당 outputs를 게시된 code에 직접 연결할 수 없으며, interactive address request 또는 on-chain notification output도 필요하지 않습니다. BIP 352는 **Complete**로 표시되어 있지만 scanning cost가 발생하고 이를 구현하지 않은 wallets와 호환되지 않습니다.<sup>[[1]](#references)</sup>

### Receiver workflow

1. BIP 352 receiving을 명시적으로 지원하는 maintained wallet을 선택합니다. social-media claim이 아니라 wallet의 최신 documentation을 기준으로 feature를 검증하십시오.
2. wallet의 documented recovery method를 사용하여 wallet seed와 Silent Payment descriptor/key material을 back up합니다. code를 게시하기 전에 소액의 testnet/mainnet amount로 discovery를 테스트하십시오.
3. wallet이 BIP 352 labels를 지원하는 경우 campaigns, invoices 또는 counterparties마다 별도의 **labels**를 생성합니다. Labels는 linkable addresses를 게시하지 않고 local accounting을 지원합니다.
4. Authenticated channel을 통해 static Silent Payment code를 게시합니다. 재사용할 수 있지만 impostor가 자신의 code로 대체할 수 있습니다.
5. 가능한 경우 local full node를 통해 scan합니다. Third-party index/scanning server는 spend할 수 없더라도 request timing 또는 filter data를 알 수 있습니다.
6. Discovered UTXOs에 labels를 유지하고 일반 Bitcoin과 동일한 coin-control rules를 적용합니다. 이를 spending 또는 consolidating하면 ownership relationships가 드러날 수 있습니다.
7. Backed-up external index에 의존하지 않고 recovery가 payments를 발견하는지 확인합니다.

### Sender workflow

1. wallet이 해당 address version으로 전송하는 것을 지원하는지 확인하고 receiver의 긴 static code를 authenticate합니다.
2. wallet이 output을 구성하도록 하며 code를 수동으로 변환하거나 truncate하지 마십시오.
3. 선택된 inputs를 신중하게 검토합니다. Silent Payments는 recipient-address privacy를 향상시키지만 sender inputs는 여전히 public graph에 남습니다.
4. Wallet-supported fee bumping/PSBT behavior를 사용합니다. BIP 352는 inputs가 변경되면 output re-derivation을 요구하며 일부 signing modes는 안전하지 않습니다.
5. Disputes/accounting에 필요한 encrypted receipt 또는 proof를 보관합니다.

Silent Payments는 반복적인 recipient-address publication 문제를 해결합니다. Amount, transaction timing, sender cluster, acquisition history 또는 later co-spending을 숨기지는 않습니다.

## Zcash fully shielded payments

Zcash는 transparent 및 shielded value pools를 지원합니다. Orchard shielded transactions는 zero-knowledge proofs를 사용하므로 nodes는 validity를 검증하면서 transaction details는 암호화된 상태로 유지할 수 있습니다. Unified Addresses에는 여러 receiver types가 포함될 수 있습니다.<sup>[[2]](#references)</sup> Privacy는 표시된 address의 첫 번째 character가 아니라 wallet이 실제로 선택한 path에 따라 달라집니다.

### Shielded workflow

1. **shielded-by-default** behavior와 최신 Orchard support를 명확히 식별하는 maintained wallet을 선택합니다. Download를 검증하고 seed를 back up/test합니다.
2. ZEC를 합법적으로 취득하고 basis/source를 기록합니다. Exchange는 여전히 acquisition 및 withdrawal을 알고 있습니다.
3. Wallet이 지원하는 Unified Address로 receive한 다음 transaction이 shielded pool에 들어갔는지 확인합니다. Wallet behavior를 확인하지 않고 automatic shielding을 가정하지 마십시오.
4. **shielded-to-shielded** transfers를 우선합니다. Transparent-to-shielded 및 shielded-to-transparent boundary movements는 public values/timing을 노출하고 amount correlation을 가능하게 할 수 있습니다. Orchard specification은 non-Orchard address로 spending하면 transaction value가 드러난다고 설명합니다.<sup>[[3]](#references)</sup>
5. Distinctive exact-amount round trips와 immediate boundary crossings를 피합니다. 이는 privacy hygiene이며 ownership 또는 reporting을 숨길 수 있는 권한이 아닙니다.
6. Wallet이 지원하는 network-privacy path를 사용합니다. Shielded cryptography는 wallet servers 또는 peers로부터 IP/timing을 숨기지 않습니다.
7. Internal compliance records를 유지하고 viewing keys는 scope를 이해한 후 의도적인 audit/disclosure에만 사용합니다.
8. 전송 전에 recipient wallet/exchange support를 확인합니다. Transparent receiver를 강제로 사용하면 privacy property가 변경됩니다.

## GNU Taler: anonymous payer, accountable merchant

GNU Taler는 traditional currencies, blind signatures 및 regulated exchange/bank integration을 사용하는 open electronic-payment protocol입니다. 이 설계는 customers를 merchants에게 anonymous로 유지하면서 merchants는 identifiable and taxable 상태로 남도록 하는 것을 목표로 합니다.<sup>[[4]](#references)</sup> 이는 cryptocurrency가 아니며 availability는 호환되는 regional exchange, bank, wallet 및 merchant에 따라 달라집니다.

### User workflow where deployed

1. 관련 currency/jurisdiction에서 운영 중인 Taler exchange와 merchant를 확인하고 현재 terms, fees, KYC 및 privacy notices를 읽습니다.
2. Official wallet을 설치하고 source를 검증합니다. Wallet value가 bearer asset일 수 있으므로 wallet backup/recovery data를 cash처럼 보호합니다.
3. Truthful information을 사용하여 지원되는 bank/exchange flow를 통해 value를 withdraw합니다. Blind signatures가 direct coin-to-withdrawal link를 끊더라도 funding institution/exchange는 withdrawal을 알 수 있습니다.
4. Wallet에서 merchant contract를 검토합니다: merchant identity, item/summary, amount, fees, refund 및 delivery terms.
5. Pay한 후 refund, warranty, accounting 또는 tax에 필요한 receipt data를 보관합니다.
6. Merchant unlinkability가 필요한 경우 optional merchant session/account identifiers를 재사용하지 마십시오.
7. Wallet, network 및 delivery metadata를 threat model에 포함합니다. Taler의 payment cryptography는 shipping address 또는 compromised endpoint를 숨기지 않습니다.

Merchant와 exchange는 계속 accountable 상태이며, 두 구성 요소 중 하나를 운영하는 것은 regulated payment-service activity가 될 수 있습니다.

## Federated Chaumian e-cash

Chaumian e-cash는 blind signatures를 사용하므로 mint가 token에 서명할 때 나중에 spend되는 unblinded token을 볼 수 없습니다. Fedimint는 guardian federation 전체에 reserve custody와 signing을 분산합니다. Documentation에 따르면 guardians는 aggregate reserves/outstanding notes를 확인하지만 federation 내부의 individual balance 또는 who paid whom은 확인하지 않아야 합니다.<sup>[[5]](#references)</sup>

이는 **custodial bearer value**입니다. Sufficient guardian quorum이 reserves를 control하며 federation failure, dishonest guardians, software bugs 또는 lost client state로 인해 손실이 발생할 수 있습니다. Deposits, withdrawals 및 Lightning gateways는 visible boundary events이며 timing/amount를 correlate할 수 있습니다.

### Limited-risk workflow

1. 잃어도 감당할 수 있는 소액만 사용합니다. Public/unknown federations는 real-world accountability가 있는 guardians보다 높은 risk로 취급합니다.
2. Authenticated channel을 통해 federation invite를 검증하고 guardian identities, quorum, jurisdiction, fees, recovery 및 shutdown policy를 기록합니다.
3. Maintained compatible wallet을 설치하고 검증하며 deposit하기 전에 backup scheme을 이해합니다.
4. Documented path를 통해 lawfully acquired Bitcoin을 deposit합니다. Peg-in을 accounting 목적으로 기록하고 timing/amount가 boundary에서 public 또는 known 상태라고 가정합니다.
5. Federation 내부에서는 fresh payment requests를 사용하고 blind signature가 제거한 link를 재생성할 수 있는 account/chat/delivery identifiers를 추가하지 마십시오.
6. Lightning payments의 경우 gateway를 invoices 및 boundary timing을 확인하는 additional observer로 취급합니다.
7. Policy에 따라 redeem/withdraw하며 distinctive amount와 immediate timing이 deposit 또는 external payment와 correlate될 수 있음을 예상합니다.
8. Tax/source/authorization records를 private하게 유지하며 guardians 또는 gateways에 activity를 허위로 기록하도록 요청하지 마십시오.

Federated e-cash를 trustless, self-custodial 또는 guaranteed anonymous라고 설명하지 마십시오.

## BOLT 12 offers and route blinding

BOLT 12 offers는 stable on-chain address를 게시하지 않고도 재사용할 수 있으며 blinded paths를 사용할 수 있습니다. 이를 통해 payer는 receiver의 clear node identity/path를 알 필요가 없습니다. 이는 Lightning의 기존 onion routing을 보완하지만 대체하지는 않습니다.

사용하기 전에:

1. Sender와 receiver wallets가 동일한 최신 BOLT 12 features를 지원하는지 확인합니다. 일반적인 “Lightning” branding만으로 support를 추론하지 마십시오.
2. Out of band로 offer를 authenticate하고 amount, issuer/description 및 recurrence rules를 확인합니다.
3. Offer에서 생성된 fresh invoice/payment context를 사용합니다.
4. Node aliases, public contact information 및 stable network endpoints를 최소화합니다.
5. Sender/receiver, first/last hop, wallet service, channel graph 및 on-chain funding/closure가 여전히 relationship의 일부를 드러낸다고 가정합니다.

## Auditability without public disclosure

Privacy와 audit는 함께 존재할 수 있습니다.

- Labels, invoices, authorization, cost basis 및 ownership mapping을 public protocol 외부에서 암호화하여 보관합니다.
- Protocol이 제공하는 경우 **view/audit key**를 spending key와 분리합니다. 먼저 sample wallet에서 정확한 disclosure 범위를 테스트합니다.
- Auditor에게 seed 또는 unrestricted spending credential 대신 최소 범위의 proof를 제공합니다.
- Transaction 시점에 software version, protocol/pool, transaction ID 또는 proof, counterparty purpose 및 exchange-rate source를 기록합니다.
- Permanent unencrypted identity graph가 축적되지 않도록 retention 및 deletion을 정의합니다.

## Selection checklist

- [ ] 숨겨지는 field와 observer가 정확히 명시되어 있습니다.
- [ ] Wallet/protocol support가 transaction date 기준으로 검증되었습니다.
- [ ] Acquisition, network, node/RPC, counterparty, delivery 및 later-spend links가 문서화되었습니다.
- [ ] Custody, recovery, liquidity, issuer/federation solvency 및 refund risks를 수용했습니다.
- [ ] Required identity, tax, sanctions, source 및 organizational records가 정확하게 유지됩니다.
- [ ] Recovery와 audit proof를 포함한 소규모 end-to-end test가 성공했습니다.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
