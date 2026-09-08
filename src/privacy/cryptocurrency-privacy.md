# Cryptocurrency Privacy

Cryptocurrency privacy는 secrecy나 immunity의 동의어가 아니라 protocol 및 operations에 관한 문제입니다. Public ledger, exchange, wallet server, network peer, merchant 및 이후 transaction은 graph의 서로 다른 부분을 노출합니다.

기법별 pros/cons/procedure/detection 형식은 [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md)에서 확인하세요. 이 페이지에서는 cryptocurrency에 특화된 mechanics와 operational limits를 확장해 설명합니다.

{% hint style="danger" %}
이 장은 합법적인 self-custody와 data minimization을 위한 것입니다. 범죄 수익 세탁, sanctions/tax/reporting 회피, 금지된 당사자와의 transaction, 규제 대상 provider 오도 또는 무허가 transmission service 운영에 사용하지 마세요. Privacy technology는 자금의 법적 출처나 소유권을 변경하지 않습니다.
{% endhint %}

## Layer별 threat model

| Layer | Observer | 일반적인 disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange, bank, broker, P2P counterparty | Identity, funding account, destination, device, IP, time |
| Ledger | Analytics를 실행하는 누구나 | Transparent chain에서는 address/output, amount와 time; 그 외에는 protocol-specific metadata |
| Wallet backend | RPC provider, explorer, remote node | Address query, balance, IP, transaction broadcast |
| Network | ISP, peer, anonymity-network entry | IP, timing, volume 및 protocol 사용 |
| Counterparty | Payer/payee | Invoice/address, delivery, conversation, account 및 timing |
| Endpoint | Malware, cloud backup, physical seizure | Seed, key, label, history, screenshot 및 clipboard |

Self-custody는 control path에서 custodian을 제거할 수 있지만 ledger, acquisition record, network metadata 또는 endpoint evidence를 삭제하지는 않습니다.

## Protocol 비교

| Method | 유용한 privacy property | 중요한 limits |
|---|---|---|
| Bitcoin on-chain | Self-custody; fresh address를 사용하면 단순한 address reuse를 방지 | Public permanent transaction graph; amount/timing 및 spending heuristic |
| Bitcoin PayJoin | Receiver input이 common-input-ownership heuristic을 무력화할 수 있음 | 양쪽 wallet이 모두 지원해야 함; transaction은 여전히 public; 지원이 고르지 않음 |
| Bitcoin CoinJoin | Coordinated participant 간 ambiguity 생성 | 식별 가능한 pattern, pre/post link, consolidation, policy/legal/provider risk |
| Lightning | Onion-routed payment은 일반 transfer처럼 global하게 게시되지 않음 | Channel open/close는 on-chain; endpoint, peer, probe 또는 custodian이 data를 추론할 수 있음 |
| Monero | Receiver, amount 및 sender set에 대해 더 강력한 기본 on-chain confidentiality | Exchange, node, timing, endpoint 및 counterparty link는 남음 |
| Ethereum/stablecoins | 폭넓은 availability 및 smart-contract interoperability | Public state/action; RPC metadata; centralized issuer가 block/freeze/report할 수 있음 |

## Bitcoin: privacy-preserving baseline

Bitcoin은 pseudonymous이지 anonymous가 아닙니다. Confirmed transaction은 public하고 지속됩니다. Address reuse, common-input ownership, change detection 및 공개적으로 식별된 address는 cluster를 구성할 수 있습니다.<sup>[[1]](#references)</sup>

### Workflow

1. **유지 관리되는 self-custody wallet을 선택합니다.** 공식 project에서 다운로드하고, 제공되는 경우 signature/hash를 검증하며, security update를 적용하세요.
2. **신뢰할 수 있는 endpoint에서 wallet을 생성합니다.** Recovery seed를 offline으로 기록하고, email, chat, screenshot 또는 일반적인 cloud note에 절대 저장하지 마세요. 상당한 value를 넣기 전에 recovery를 테스트하세요.
3. **Hot wallet에는 operational value만 보관합니다.** 장기 value에는 적절한 offline/hardware custody를 사용하고, seed가 하나의 취약한 위치에 노출되지 않도록 recovery plan을 마련하세요.
4. **모든 transaction마다 fresh receive address/invoice를 생성합니다.** Invoice server나 authenticated private delivery가 가능한 경우 static address를 공개하지 마세요.
5. **가능하면 자체 full node를 사용합니다.** Third-party explorer/electrum server는 조회한 address와 IP metadata를 파악할 수 있습니다. Wallet이 지원하는 Tor/proxy 동작만 설정하세요. Tor는 network edge를 숨기지만 blockchain graph를 숨기지는 않습니다.
6. **모든 UTXO에 source, owner, purpose 및 compliance state를 private하게 label합니다.** 관련 없는 identity context가 함께 spend되지 않도록 coin control을 활성화하세요.
7. **Transaction을 미리 확인합니다:** 선택된 input, change destination, amount, fee, counterparty 및 해당 spend가 compartment를 병합하는지 확인하세요. 불필요한 consolidation을 피하세요.
8. **합법적인 record를 별도로 암호화해 보관합니다.** Acquisition basis, invoice, authorization 및 tax/reporting 정보를 mapping을 공개하지 않는 방식으로 보존하세요.
9. **이후 spending도 동일한 privacy decision의 일부로 취급합니다.** 잘 분리된 receipt도 그 output이 식별된 funds와 함께 co-spent되면 다시 연결될 수 있습니다.

Bitcoin Core의 privacy documentation은 full node가 third-party server에 wallet query를 공개하지 않도록 해주지만, transaction broadcast와 public history도 여전히 분석 대상이라는 점을 설명합니다.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin은 receiver가 input을 추가하는 collaborative payment입니다. 이를 통해 모든 input이 sender에 속한다는 단순한 가정을 무력화합니다. BIP 78은 원래의 interactive protocol을 설명하며, draft BIP 77은 encrypted mailbox/OHTTP를 사용하는 asynchronous v2 design을 정의합니다.<sup>[[3]](#references)</sup>

안전한 사용:

1. 양쪽 maintained wallet이 동일한 PayJoin version을 지원하는지 확인합니다.
2. Authenticated channel을 통해 PayJoin-capable invoice를 받고, 다른 payment request와 동일하게 보호합니다.
3. Original amount와 destination을 확인한 다음, wallet이 proposal/PSBT, fee contribution 및 금지된 substitution을 검증하도록 합니다.
4. 최종 wallet summary를 확인합니다. 예상하지 못한 output, amount 또는 과도한 fee를 수동으로 승인하지 마세요.
5. Negotiation이 실패하면 wallet이 ordinary payment로 안전하게 fallback하는지 또는 새 invoice가 필요한지 파악합니다.
6. Ownership, accounting 및 dispute에 필요한 private receipt/record를 보관합니다.

PayJoin은 하나의 chain-analysis heuristic을 개선하지만, 당사자, acquisition platform, endpoint 또는 public ledger에서 payment를 숨기지는 않습니다.

## CoinJoin: benefits와 limits

CoinJoin은 여러 사용자를 하나의 transaction으로 조정하여 input-output mapping을 덜 확실하게 만듭니다. 특정 historical Wasabi 및 Samourai design에 관한 research는 매우 식별하기 쉬운 transaction을 발견했으며, pre/post-mix behavior가 anonymity를 상당히 좁힐 수 있음을 보여주었습니다.<sup>[[4]](#references)</sup> 이 결과를 모든 implementation이나 future version에 일반화해서는 안 되지만, “anonymity-set” 숫자가 guarantee가 아닌 이유를 보여줍니다.

합법적으로 사용하기 전에:

- 현재 local law, sanctions status, exchange/custodian policy 및 tax/reporting 의무를 확인하세요.
- 공식 project에서 취득한 maintained, non-custodial software를 사용하세요.
- Coordinator model, fee, denial-of-service control 및 현재 service가 여전히 운영되는지 이해하세요. zkSNACKs는 2024년에 coordinator를 종료했지만, 다른 Wasabi coordinator가 존재할 수 있습니다.
- Source-of-funds 및 transaction record를 private하게 보존하세요.
- 다른 사람을 대신하여 unknown funds를 받거나, 추적 불가능한 withdrawal을 약속하는 custodial “mixer”를 사용하지 마세요.
- Output을 source/context별로 분리하고, 의도한 ambiguity를 없애는 이후 consolidation을 피하세요.

법적 결과는 사실관계와 관할권에 따라 다릅니다. 2025년 Samourai guilty plea는 범죄 수익을 이동시킨 무허가 money transmitter를 고의로 운영한 것과 관련된 것이며, 모든 collaborative transaction이나 privacy-seeking user가 범죄자라는 의미는 아닙니다.<sup>[[5]](#references)</sup>

## Lightning Network

Lightning의 Sphinx onion routing은 intermediate hop이 전체 route가 아니라 predecessor와 successor를 파악하도록 설계되었습니다.<sup>[[6]](#references)</sup> 그러나 blanket anonymity는 아닙니다. Channel funding/closure는 public하고, node는 topology를 advertise하며, counterparty는 endpoint를 알고, routing/probing은 balance나 party를 추론할 수 있고, custodial wallet은 사용자의 account activity를 확인할 수 있습니다.

더 나은 privacy를 위해:

1. Intermediary privacy가 중요하다면 maintained non-custodial wallet을 우선하고, 먼저 channel backup/recovery를 계획하세요.
2. 각 payment에 fresh invoice 또는 offer를 사용하세요. 정확한 wallet이 BOLT 12/route blinding을 지원하는지 확인하고, 지원한다고 가정하지 마세요.
3. 불필요한 node alias, contact detail 및 stable network endpoint를 공개하지 마세요.
4. 적절한 경우 supported privacy network를 통해 연결하되, uptime/timing pattern이 여전히 correlate될 수 있음을 이해하세요.
5. Off-chain payment에 record가 없다고 추론하지 마세요. Sender, receiver, peer, watchtower, liquidity provider 및 wallet service가 observation을 보관할 수 있습니다.

Published research는 public data와 active probing을 통해 sender/recipient 및 channel-balance inference가 가능함을 입증했지만, attack과 mitigation은 발전하고 있습니다.<sup>[[7]](#references)</sup>

## Monero

Monero는 output에 one-time stealth address를, amount를 숨기기 위해 RingCT를, 확률적인 sender ambiguity를 제공하기 위해 ring signature를 사용합니다. 현재 technical specification은 ring size를 16(15 decoy)으로 설명합니다.<sup>[[8]](#references)</sup> 이는 transparent ledger보다 on-chain confidentiality에 강한 기본값을 제공하지만, endpoint나 operational mistake로부터 보호하는 마법 같은 수단은 아닙니다.

### 합법적인 workflow

1. **합법적으로 acquire하세요.** Regulated exchange는 이후 on-chain detail이 confidential하더라도 purchase와 withdrawal을 파악할 수 있습니다. Source, basis 및 reporting record를 보관하세요.
2. **공식 maintained wallet을 설치하고** project instruction에 따라 download를 검증하세요. Seed를 offline으로 backup하고, 소액으로 restoration을 테스트하세요.
3. **최대 wallet-query privacy를 위해 local node를 우선하세요.** 이것이 실용적이지 않다면, 공식적으로 지원되는 onion/I2P configuration을 통해 접근 가능한 신뢰할 수 있는 remote node를 선택하세요. Remote node는 IP, request, timing 및 transaction ID를 기록할 수 있으며, 일부 lightweight design은 view key를 노출합니다.
4. **Payer, campaign 또는 invoice마다 새로운 subaddress를 사용하세요.** Payer는 동일한 subaddress의 반복 사용을 correlate할 수 있습니다.<sup>[[9]](#references)</sup>
5. **Incoming context를 local하게 label하세요.** Knowledgeable payer가 이후 behavior를 인식할 수 있는 경우, 분리된 receipt를 operationally merge하지 마세요.
6. **Network metadata를 보호하세요.** 공식 anonymity-network configuration을 따르고, timestamp, intermittent synchronization, bandwidth shape 및 stream reuse에서 발생하는 documented leak을 인지하세요.<sup>[[10]](#references)</sup>
7. **Compliance/audit data를 private하게 보관하세요.** View key나 transaction proof는 의도적으로, 대상 auditor/party에게만 공개하고, 정확히 무엇을 reveal하는지 이해하세요.

Historical traceability study에는 이후 변경된 bug와 decoy-selection era가 포함되어 있습니다. 오래된 success percentage를 current transaction에 적용하지 마세요. 마찬가지로 이 장의 2026년 9월 research cutoff 기준 FCMP++는 배포된 protection이 아니라 여전히 roadmap 작업입니다.<sup>[[11]](#references)</sup>

## Ethereum 및 stablecoins

Ethereum 자체의 privacy material은 on-chain action이 보이며 wallet/RPC infrastructure가 IP와 metadata exposure를 추가한다고 설명합니다.<sup>[[12]](#references)</sup> Token transfer, approval, smart-contract interaction, name service 및 gas funding은 모두 identity를 연결할 수 있습니다.

Centralized stablecoin은 issuer control을 추가합니다. 현재 USDC 및 Tether terms는 address나 asset을 block/freeze하고 legal/process obligation을 준수할 권한을 보유한다고 명시합니다.<sup>[[13]](#references)</sup> 유용한 payment instrument일 수는 있지만, censorship resistance나 on-chain anonymity가 요구되는 경우에는 적합하지 않습니다.

## Compliance boundaries

- FATF recommendation은 national law를 통해 구현되며 시간이 지나면서 변경됩니다. 2026 update는 VASP licensing/registration 및 Travel Rule implementation을 강조합니다.<sup>[[14]](#references)</sup>
- 미국에서 FinCEN은 자신의 goods/services를 위해 convertible virtual currency를 사용하는 사람과, 이를 accept 및 transmit하거나 exchange하는 business를 구분합니다. 사실관계와 이후 rules가 중요합니다.<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation은 crypto-asset service provider가 관련된 경우 originator/beneficiary information을 요구하며, self-hosted address와의 특정 transfer에 verification rule을 추가합니다.<sup>[[16]](#references)</sup>
- Sanction 및 tax 의무는 계속 적용됩니다. 필요한 경우 screen하고, 금지된 party를 거부하며, record를 유지하세요. List와 legal status는 빠르게 변경될 수 있습니다.<sup>[[17]](#references)</sup>

상당한 value, cross-border activity, privacy-enhancing coordination 또는 business-like exchange/transmission을 수행하기 전에 관련 관할권에 대한 최신 professional advice를 받으세요.

Bitcoin Silent Payments, fully shielded Zcash, GNU Taler, federated Chaumian e-cash 및 BOLT 12에 대해서는 [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md)를 계속 참조하세요.

## References

- [1] [Bitcoin.org — Privacy 보호](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy 기능](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — 간단한 PayJoin 제안](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Bitcoin의 Decentralized CoinJoin Implementation 도입 및 실제 Privacy (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Samourai Wallet 창립자들의 guilty plea (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Lightning Network의 Privacy에 대한 실증 분석](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth address](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signature](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) 및 [Technical specification](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Network](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Monero Privacy의 진화 탐구 (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Ethereum의 Privacy](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC Terms](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Virtual Asset 및 VASP에 대한 2026 Targeted Update](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Virtual Currency를 Administer, Exchange 또는 Use하는 사람에 대한 FinCEN Regulations의 적용](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Virtual Currency Industry를 위한 Sanctions Compliance Guidance](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
