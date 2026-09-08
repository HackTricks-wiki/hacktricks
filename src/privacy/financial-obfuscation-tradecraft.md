# Financial Obfuscation Tradecraft

Payment privacy는 attribution 문제가 아니라 payment brand 문제가 아니다. 자금은 acquisition, 이동, conversion, spending, delivery 과정에서 증거를 남긴다. Public-chain address는 pseudonymous일 수 있지만, exchange, card issuer, merchant, mobile device 또는 shipping camera가 그 뒤에 있는 사람을 식별할 수 있다.

이 페이지는 defender가 이를 인식할 수 있도록 cybercrime 및 state-linked operation에서 사용되는 financial-obfuscation pattern을 설명한다. 이는 laundering, sanctions evasion, false identity 또는 KYC bypass 절차를 제공하지 **않는다**.

## The end-to-end value graph
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
행위자는 어떤 관찰자도 양쪽 끝을 모두 볼 수 없도록 하려 한다. 조사관은 그 반대로 한다. 각 경계에서 기록을 보존하고, 시간/가치/수수료를 정규화하며, 서로 다른 페르소나가 하나의 facilitator, device, account, merchant 또는 destination을 재사용하는 **재수렴 지점**을 식별한다.

## 수단과 실제 관찰자

| 수단 | merchant/public로부터 숨겨지는 정보 | 여전히 볼 수 있는 주체 |
|---|---|---|
| Issuer virtual card/token | underlying card number | issuer, network/token provider, wallet, merchant account 및 delivery systems |
| Prepaid/gift value | 일반적인 구매에서 legal name이 표시되지 않는 경우가 있음 | retailer/payment rail, activation/redemption service, cameras, device 및 delivery |
| Cash | public ledger 및 remote issuer | counterparties, cameras, 해당되는 경우 withdrawal/serial controls, physical search |
| Bitcoin/new address | direct legal name | 모든 blockchain observer; wallet/network peers; acquisition/off-ramp services |
| CoinJoin/PayJoin | 단순한 common-input/payment heuristics | public transaction, coordinator/peer/network metadata 및 이후 spending behavior |
| Privacy coin | protocol에 따라 public sender/receiver/amount | acquisition/off-ramp, wallet endpoint, network observer 및 counterparty |
| Centralized mixer | direct deposit-to-withdraw link | mixer operator/logs, blockchain entry/exit sets 및 counterparties |
| Cross-chain bridge/swap | 하나의 chain에서의 연속성 | 양쪽 chain, bridge/swap service, timing/value 및 liquidity constraints |
| OTC/P2P broker | 일부 경우 direct exchange account | broker, communications, bank/cash movement, counterparties 및 devices |

## Cards, prepaid value, nominees 및 mules

### Virtual 및 masked cards

issuer는 merchant-locked 또는 disposable card number를 생성할 수 있다. 이는 merchant에 대한 노출과 merchant 간 number 재사용을 줄인다. 그러나 issuer는 여전히 이를 customer, funding account, device, IP 및 transaction에 매핑한다. Billing descriptors, merchant account, shipping address 및 browser data도 계속 연결될 수 있다.

“No-name” card marketing이 anonymous settlement을 의미하는 것은 아니다. Regulated issuer와 distributor는 identity check를 수행하고, records를 보존하며, geography/amount limits를 적용하고, legal process에 대응할 수 있다. stolen identity로 획득한 card는 identity theft를 추가할 뿐이며, issuer/device/merchant telemetry를 제거하지 않는다.

### Prepaid 및 gift value

Prepaid cards와 gift codes는 이후 redemption을 original payment instrument와 분리하지만, purchase, activation, balance-query 및 redemption events가 발생하는 번호가 부여된 object를 만든다. 중요한 패턴으로는 bulk purchases, controls 바로 아래 금액의 반복적인 denomination, distant rapid redemption, 하나의 device에서 많은 balance를 조회하는 행위, 또는 여러 card가 하나의 merchant/account로 수렴하는 행위가 있다.

### Nominees, money mules 및 merchant fronts

nominee 또는 mule은 operator와 service 사이에 위치하는 account와 legal identity를 제공한다. Networks는 recruiter, account holder, payment processor, shell merchant 및 cash-out broker를 여러 계층으로 구성할 수 있다. 이는 거리를 만들지만, 각 participant는 communications, fees, behavioral inconsistency 및 협조할 가능성이 있는 witness를 추가한다. Front company는 incorporation, tax, banking, director, invoice, hosting 및 shipment records를 추가한다.

Defender는 shared devices/IPs, beneficiary reuse, geolocation contradictions, account history와 일치하지 않는 velocity, circular transfers, 서로 관련 없는 여러 sender의 수렴 및 즉각적인 onward movement를 조사해야 한다. 명의상 account holder가 controlling actor라고 가정하지 말고, role determination이 필요한 node로 취급해야 한다.

## Public-chain transaction-obfuscation patterns

### Address rotation 및 coin control

모든 receipt마다 새 address를 생성하면 단순한 address reuse를 방지할 수 있지만, common inputs, change detection, exact value/time 및 이후 consolidation을 통해 transactions가 여전히 동일 소유권으로 연결될 수 있다. **Coin control**을 사용하면 wallet이 어떤 outputs를 spend할지 선택하고 compartments를 결합하지 않을 수 있다. 이는 hygiene를 개선하지만, 이미 public이 된 link를 제거할 수는 없다.

### Peel chains

peel chain은 큰 balance를 반복적으로 spend하면서 더 작은 amount를 외부로 보내고 remainder를 새 address로 반환한다:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
주소는 각 단계마다 바뀌지만, 가치의 연속성, 거래 간격 및 transaction 구조는 흔히 식별 가능한 chain을 형성합니다. 합법적인 exchange hot wallet도 유사하게 작동할 수 있으므로, attribution에는 서비스 및 context 증거가 필요합니다. DOJ는 북한(DPRK) 연계 forfeiture 사건에서 peel-chain analysis를 사용했습니다.<sup>[[1]](#references)</sup>

### Structuring and fan-out/fan-in

- **Fan-out:** 하나의 source가 여러 주소로 분할하여 investigation workload를 늘리거나 병렬적인 conversion을 준비합니다.
- **Fan-in:** 여러 source가 하나의 collector로 통합되어 common control 또는 service를 드러냅니다.
- **Structuring:** 반복적인 소액 transfer를 통해 review threshold를 피하거나 일반적인 거래량에 섞이려 합니다.
- **Commingling:** illicit funds와 무관한 funds가 wallet, pool 또는 service를 공유하여 단순한 비례적 판단을 위험하게 만듭니다.

Graph shape는 lead일 뿐 proof가 아닙니다. Analysts는 fee, UTXO/account model, service behavior 및 change convention을 고려해야 합니다.

### CoinJoin and PayJoin

일반적인 CoinJoin에서는 여러 participant가 하나의 collaborative transaction에 input을 제공하고 output을 수령하며, output denomination은 동일한 경우가 많습니다. 이로 인해 transaction의 모든 input과 output에 각각 하나의 owner가 있다는 가정이 깨집니다. Anonymity set은 participant 수와 이후 behavior에 의해 제한됩니다. unequal change, toxic change, consolidation 또는 알려진 service와의 접점이 link를 다시 만들 수 있습니다.

PayJoin은 payer와 payee가 모두 input을 제공하도록 일반적인 payment를 수정하여, 해당 transaction에 대한 common-input ownership heuristic을 직접 무효화합니다. 이는 주로 payment privacy protocol이며, 대규모 laundering service가 아닙니다. Detection에서는 모든 input이 공동 소유라고 단정하지 말고, 잘못된 cluster를 강제로 만들기보다 uncertainty를 표현해야 합니다.

### Centralized mixers and tumblers

Centralized mixer는 deposit을 수락한 뒤 pooled reserve에서 서로 다른 coin을 지급하며, fee와 delay가 적용되는 경우가 많습니다. Privacy는 pool size, withdrawal policy, logs, operator honesty 및 seizure에 대한 resistance에 좌우됩니다. Entry와 exit의 timing/value analysis, deposit address, service wallet clustering 및 records를 통해 대상 범위를 좁힐 수 있습니다. Operators는 funds를 훔치거나 전체 mapping을 보관할 수 있습니다.

Legal exposure는 상당하며 jurisdiction에 따라 다릅니다. ChipMixer, Samourai Wallet 및 Tornado Cash developers/operators에 대한 DOJ 사건과 변화하는 sanctions litigation은 protocol, custody, control 및 money-transmission 사실이 중요하다는 점을 보여줍니다. “decentralized”라는 label은 legal conclusion이 아닙니다.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps and bridges

Chain hopping은 asset을 conversion하거나 bridge를 통해 이동시켜 하나의 ledger query를 중단시키지만, economic continuity 자체를 없애지는 않습니다:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
분석가들은 bridge contracts/service deposit addresses, transaction order, time window, exchange rate, fees, liquidity 및 unique amount를 상호 연관시킵니다. 반복적인 swap은 모호성을 키울 수 있지만 provider/API/wallet telemetry도 추가합니다. FATF는 의심스러운 맥락과 결합될 때 chain hopping, mixers, peer-to-peer services 및 anonymity-enhanced currencies를 위험 지표로 명시합니다.<sup>[[3]](#references)</sup>

### NFTs, gambling 및 merchant purchases

Self-dealing 또는 collusive NFT trades는 자금에 겉보기 sale narrative를 부여할 수 있으며, gambling은 deposits를 withdrawals로 교환할 수 있고, goods는 digital value를 재판매 가능한 inventory로 전환할 수 있습니다. 이러한 경로에는 marketplace accounts, creator/royalty links, wash-trading graphs, odds/play history, device logs, delivery 및 resale evidence가 남습니다. 손실 또는 fee가 provenance가 사라졌다는 증거는 아닙니다.

## Privacy-preserving cryptocurrencies

Privacy protocols는 기술적으로 서로 다릅니다.

- **Monero**는 one-time addresses, ring signatures 및 confidential amounts를 사용하여 공개된 sender/receiver/amount visibility를 줄입니다. Network observation, wallet compromise, acquisition/off-ramp 및 counterparty records는 이러한 on-chain protections의 범위 밖에 여전히 존재합니다.
- **Zcash shielded pools**는 shielded transactions가 사용될 때 sender, receiver 및 amount를 숨길 수 있습니다. transparent addresses와 pool 간 transition은 여전히 공개되며, 사용 패턴은 실제 anonymity set에 영향을 줍니다.
- **Bitcoin**은 기본적으로 transparent합니다. New addresses, CoinJoin, PayJoin 및 Lightning은 특정 linkage assumptions를 변경하지만 모든 layer를 private하게 만들지는 않습니다.

Privacy technology에는 정당한 안전 및 상업적 용도가 있습니다. 조사 관점에서 ledger가 제공하는 정보가 적을수록 endpoint, service, network 및 human evidence가 더 중요해집니다. Privacy-preserving protocol을 선택했다는 사실만으로 범죄성을 추론해서는 안 됩니다.

## DPRK multi-layer case model

공개된 DOJ allegations 및 forfeiture actions는 하나의 trick이 아닌 결합된 process를 설명합니다.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workers는 허위 또는 도난된 identity material과 VPN을 사용하여 remote employment를 얻었습니다.
2. employers는 stablecoins를 포함한 cryptocurrency로 대금을 지급했습니다.
3. funds는 더 작은 amounts로 이동하고, chains 또는 tokens를 넘나들며, NFTs를 구매하거나 commingled되었습니다.
4. 다른 stolen funds는 mixers로 유입되었습니다.
5. OTC traders 및 front companies는 value를 fiat payments 또는 goods로 전환했습니다.
6. 반복적으로 사용된 facilitators, accounts 및 blockchain paths를 통해 investigators는 layer들을 다시 연결할 수 있었습니다.

Treasury는 Lazarus가 Axie Infinity/Ronin theft의 일부를 처리하기 위해 Blender.io를 사용했다고 밝혔으며, FBI는 addresses를 공개하고 bridges, exchanges, RPC operators 및 analytics firms에 이후 TraderTraitor thefts와 연결된 funds를 차단하도록 촉구했습니다.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

교훈은 양방향입니다. state actors는 일반적인 commercial/criminal services를 사용하며, public blockchains를 통해 이름을 처음에는 알 수 없는 경우에도 defenders가 value를 추적할 수 있습니다.

## Detection workflow

1. **Raw transaction identifiers 및 records를 보존합니다.** Screenshots 및 반올림된 fiat values만으로는 충분하지 않습니다.
2. **Assets 및 time을 normalize합니다.** Chain, token contract, units, block time, service time zone, fees 및 exchange-rate source를 기록합니다.
3. **Evidence confidence를 label합니다.** Service-published address, deterministic contract event, clustering heuristic 및 external intelligence를 구분합니다.
4. **양방향으로 trace합니다.** Funding origin, immediate dispersal, reconvergence, bridge exits, service deposits 및 spend/delivery를 찾습니다.
5. **Off-chain evidence를 결합합니다.** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping 및 communication records가 모호성을 해소하는 경우가 많습니다.
6. **대체 설명을 검증합니다.** Exchanges, custodians, payroll 및 privacy protocols는 common beneficial ownership 없이도 fan-in/out 또는 co-spends를 생성할 수 있습니다.
7. **성급하게 종료하지 말고 monitor합니다.** Dormant output은 이후 service에 도달할 때 attributable해질 수 있습니다.
8. **Counsel과 함께 현재 sanctions/AML obligations를 적용합니다.** Rules 및 designations는 변경되며, historical association은 current legal analysis를 대신할 수 없습니다.

## Safe red-team procurement model

Authorized team은 engagement controller가 accountability를 유지하는 동안 target SOC가 hosting payment를 인식하지 못하도록 해야 할 수 있습니다.

- Engagement-specific organization card 또는 documented corporate wallet를 사용합니다.
- Billing, tax 및 provider records를 정확하게 유지합니다.
- Operator와 procurement duties를 분리하고 attribution map에 대한 access를 제한합니다.
- Mule, false identity, stolen card, sanctions workaround 또는 unlicensed exchanger를 절대 사용하지 않습니다.
- Asset, amount, owner, service, date, refund path 및 teardown evidence를 기록합니다.
- Exercise 후 관련 payment/provider indicators를 controller에게 공개합니다.

이는 **exercise participant에 대한 blindness**를 만드는 것이지, law, provider 또는 governance에 대한 blindness를 만드는 것이 아닙니다.

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework (peel-chain example and DPRK investigations)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer takedown](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Forfeiture complaint concerning $7.74 million allegedly laundered for DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions and Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea responsible for the 2025 Bybit theft](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Application of regulations to virtual-currency users, administrators and exchangers](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
