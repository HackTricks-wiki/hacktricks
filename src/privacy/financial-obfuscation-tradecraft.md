# 금융 난독화 Tradecraft

{{#include ../banners/hacktricks-training.md}}

Payment privacy는 payment-brand 문제가 아니라 attribution 문제입니다. 가치가 획득되고, 이동하고, 전환되고, 사용되고, 전달되는 과정에서 operation은 증거를 남깁니다. public-chain address는 pseudonymous일 수 있지만, exchange, card issuer, merchant, mobile device 또는 shipping camera가 그 뒤에 있는 사람을 식별할 수 있습니다.

이 페이지는 defenders가 이를 인식할 수 있도록 cybercrime 및 state-linked operations에서 사용되는 financial-obfuscation 패턴을 설명합니다. 이는 laundering, sanctions-evasion, false-identity 또는 KYC-bypass 절차를 제공하지 **않습니다**.

## 엔드투엔드 가치 그래프
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
행위자는 어떤 관찰자도 양쪽 끝을 모두 보지 못하도록 하려 한다. 조사관은 그 반대로 한다. 각 경계에서 기록을 보존하고, 시간/값/수수료를 정규화하며, 서로 다른 페르소나가 하나의 facilitator, device, account, merchant 또는 destination을 재사용하는 **reconvergence point**를 식별한다.

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

issuer는 merchant-locked 또는 disposable card number를 생성할 수 있다. 이는 merchant의 노출과 여러 merchant에서의 번호 재사용을 줄인다. 그러나 issuer는 여전히 이를 customer, funding account, device, IP 및 transaction에 매핑한다. Billing descriptors, merchant account, shipping address 및 browser data도 계속 연결될 수 있다.

“No-name” card marketing은 익명 settlement를 의미하지 않는다. 규제를 받는 issuer와 distributor는 identity check를 수행하고, 기록을 보관하며, geography/amount limit를 적용하고, legal process에 대응할 수 있다. stolen identity를 통해 얻은 card는 identity theft를 추가할 뿐이며, issuer/device/merchant telemetry를 제거하지 않는다.

### Prepaid and gift value

Prepaid card와 gift code는 이후 redemption을 최초 payment instrument와 분리하지만, purchase, activation, balance-query 및 redemption event가 기록되는 번호가 있는 객체를 만든다. 중요한 패턴으로는 대량 구매, control 바로 아래의 denomination을 반복적으로 구매하는 행위, 먼 거리에서의 신속한 redemption, 하나의 device로 여러 balance를 조회하는 행위, 또는 여러 card가 하나의 merchant/account로 수렴하는 행위가 있다.

### Nominees, money mules and merchant fronts

nominee 또는 mule은 operator와 service 사이에 위치하는 account와 legal identity를 제공한다. Network는 recruiter, account holder, payment processor, shell merchant 및 cash-out broker를 여러 층으로 구성할 수 있다. 이는 거리를 만들지만, 각 participant는 communications, fees, behavioral inconsistency 및 잠재적인 협조 witness를 추가한다. Front company는 incorporation, tax, banking, director, invoice, hosting 및 shipment records를 추가한다.

Defender는 shared devices/IPs, beneficiary reuse, geolocation contradictions, account history와 일치하지 않는 velocity, circular transfers, 서로 관련 없는 여러 sender가 한 곳으로 수렴하는 현상, 그리고 즉각적인 onward movement를 조사해야 한다. 명의상 account holder가 controlling actor라고 가정하지 말고, 역할을 판단해야 하는 node로 취급해야 한다.

## Public-chain transaction-obfuscation patterns

### Address rotation and coin control

모든 receipt마다 새로운 address를 생성하면 단순한 address reuse를 방지할 수 있지만, common inputs, change detection, exact value/time 및 이후 consolidation을 통해 transaction 간 소유 관계가 연결될 수 있다. **Coin control**을 사용하면 wallet이 어떤 output을 지출할지 선택하고 compartment 간 연결을 피할 수 있다. 이는 hygiene를 개선하지만, 이미 public이 된 link를 제거할 수는 없다.

### Peel chains

peel chain은 큰 balance를 반복적으로 지출하면서, 작은 amount를 외부로 보내고 나머지를 새로운 address로 반환한다:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
주소는 각 단계마다 바뀌지만, 가치의 연속성, 빈도 및 transaction 구조는 종종 식별 가능한 chain을 형성합니다. Legitimate exchange hot wallet도 유사하게 동작할 수 있으므로, attribution에는 service/context evidence가 필요합니다. DOJ는 DPRK-linked forfeiture cases에서 peel-chain analysis를 사용했습니다.<sup>[[1]](#references)</sup>

### Structuring 및 fan-out/fan-in

- **Fan-out:** 하나의 source가 여러 address로 분할하여 조사 workload를 늘리거나 병렬 conversion을 준비합니다.
- **Fan-in:** 여러 source가 하나의 collector로 통합되어 common control 또는 service를 드러냅니다.
- **Structuring:** 반복적인 소액 transfer를 통해 review threshold를 피하거나 일반적인 volume에 섞이려 합니다.
- **Commingling:** illicit 및 unrelated funds가 wallet, pool 또는 service를 공유하여 단순한 비례 추정이 안전하지 않게 됩니다.

Graph shape는 단서일 뿐 증거가 아닙니다. Analysts는 fees, UTXO/account model, service behavior 및 change conventions를 고려해야 합니다.

### CoinJoin 및 PayJoin

일반적인 CoinJoin에서는 여러 participant가 하나의 collaborative transaction에 inputs를 제공하고 outputs를 받으며, 종종 동일한 output denomination을 사용합니다. 이는 transaction의 모든 input과 output이 하나의 owner를 가진다는 가정을 무너뜨립니다. Anonymity set은 participant 수와 이후 behavior에 의해 제한됩니다. unequal change, toxic change, consolidation 또는 known service와의 연결로 인해 link가 다시 드러날 수 있습니다.

PayJoin은 payer와 payee가 모두 inputs를 제공하도록 일반적인 payment를 수정하여, 해당 transaction에 대한 common-input ownership heuristic을 직접 무효화합니다. 이는 주로 payment privacy protocol이며, bulk laundering service가 아닙니다. Detection에서는 모든 input이 공동 소유라고 선언하지 않아야 하며, 잘못된 cluster를 강제로 만들기보다는 uncertainty를 표현해야 합니다.

### Centralized mixers 및 tumblers

Centralized mixer는 deposits를 받고, fees와 delays를 적용한 후 pooled reserve에서 서로 다른 coins를 지급합니다. Privacy는 pool size, withdrawal policy, logs, operator honesty 및 seizure에 대한 resistance에 좌우됩니다. Entry 및 exit timing/value analysis, deposit addresses, service wallet clustering 및 records를 통해 대상 범위를 좁힐 수 있습니다. Operators는 funds를 훔치거나 complete mapping을 보유할 수 있습니다.

Legal exposure는 상당하며 jurisdiction에 따라 다릅니다. ChipMixer, Samourai Wallet 및 Tornado Cash developers/operators에 대한 DOJ cases와 변화하는 sanctions litigation은 protocol, custody, control 및 money-transmission 사실이 중요하다는 점을 보여줍니다. “decentralized”라는 label은 legal conclusion이 아닙니다.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps 및 bridges

Chain hopping은 asset을 변환하거나 bridge를 통해 이동시켜 하나의 ledger query를 무력화하지만, economic continuity를 없애지는 않습니다:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
분석가들은 bridge contracts/service deposit addresses, transaction order, time window, exchange rate, fees, liquidity 및 unique amount를 상관 분석합니다. 반복적인 swap은 모호성을 키울 수 있지만 provider/API/wallet telemetry도 추가합니다. FATF는 의심스러운 맥락과 결합될 경우 chain hopping, mixers, peer-to-peer services 및 anonymity-enhanced currencies를 위험 지표로 명시합니다.<sup>[[3]](#references)</sup>

### NFTs, gambling and merchant purchases

자기거래 또는 공모에 의한 NFT 거래는 자금에 겉보기상 판매 내역을 부여할 수 있고, 도박은 입금을 출금으로 바꿀 수 있으며, 상품은 digital value를 재판매 가능한 inventory로 전환할 수 있습니다. 이러한 경로에는 marketplace accounts, creator/royalty links, wash-trading graphs, odds/play history, device logs, delivery 및 resale evidence가 남습니다. 손실이나 수수료가 발생했다고 해서 provenance가 사라졌다는 증거는 아닙니다.

## Privacy-preserving cryptocurrencies

Privacy protocols는 기술적으로 서로 다릅니다.

- **Monero**는 일회성 주소, ring signatures 및 confidential amounts를 사용하여 공개적으로 확인 가능한 sender/receiver/amount 정보를 줄입니다. Network observation, wallet compromise, acquisition/off-ramp 및 counterparty records는 여전히 이러한 on-chain 보호 범위 밖에 있습니다.
- **Zcash shielded pools**는 shielded transactions가 사용될 때 sender, receiver 및 amount를 숨길 수 있습니다. 그러나 transparent addresses와 pool 간 전환은 공개되며, 사용 패턴은 실질적인 anonymity set에 영향을 줍니다.
- **Bitcoin**은 기본적으로 투명합니다. New addresses, CoinJoin, PayJoin 및 Lightning은 특정 linkage 가정을 변경하지만 모든 계층을 private하게 만들지는 않습니다.

Privacy technology는 정당한 안전 및 상업적 용도로 사용됩니다. 조사 관점에서는 ledger가 제공하는 정보가 적을수록 endpoint, service, network 및 human evidence가 더욱 중요해집니다. Privacy-preserving protocol을 선택했다는 사실만으로 범죄성을 추론해서는 안 됩니다.

## DPRK multi-layer case model

공개된 DOJ allegations 및 forfeiture actions는 하나의 수법이 아니라 결합된 과정을 설명합니다.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. 근로자들은 허위 또는 도난 신원 자료와 VPNs를 사용하여 원격 고용을 얻었습니다.
2. 고용주는 stablecoins를 포함한 cryptocurrency로 대금을 지급했습니다.
3. 자금은 더 작은 금액으로 이동하고, chain 또는 token을 넘나들며, NFTs를 구매하거나 다른 자금과 혼합되었습니다.
4. 다른 도난 자금은 mixers로 유입되었습니다.
5. OTC traders와 front companies는 value를 fiat payments 또는 goods로 전환했습니다.
6. 반복적으로 사용된 facilitators, accounts 및 blockchain paths를 통해 조사관들은 여러 계층을 다시 연결할 수 있었습니다.

재무부는 Lazarus가 Axie Infinity/Ronin theft의 일부를 처리하기 위해 Blender.io를 사용했다고 밝혔으며, FBI는 addresses를 공개하고 bridges, exchanges, RPC operators 및 analytics firms에 이후 TraderTraitor thefts와 연결된 자금을 차단하도록 촉구했습니다.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

교훈은 양방향입니다. 국가 행위자는 일반적인 상업 및 범죄 서비스를 사용하며, public blockchains는 이름을 처음에는 알 수 없더라도 방어자가 value를 추적할 수 있게 합니다.

## Detection workflow

1. **원시 transaction identifiers와 records를 보존합니다.** Screenshots와 반올림된 fiat values만으로는 충분하지 않습니다.
2. **Assets와 time을 정규화합니다.** Chain, token contract, units, block time, service time zone, fees 및 exchange-rate source를 기록합니다.
3. **Evidence confidence를 표시합니다.** Service-published address, deterministic contract event, clustering heuristic 및 external intelligence를 구분합니다.
4. **양방향으로 추적합니다.** Funding origin, immediate dispersal, reconvergence, bridge exits, service deposits 및 spend/delivery를 찾습니다.
5. **Off-chain evidence를 결합합니다.** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping 및 communication records는 모호성을 해소하는 경우가 많습니다.
6. **대안적 설명을 검증합니다.** Exchanges, custodians, payroll 및 privacy protocols는 common beneficial ownership 없이도 fan-in/out 또는 co-spends를 만들 수 있습니다.
7. **성급하게 종결하지 말고 모니터링합니다.** Dormant output은 나중에 service에 도달하면 귀속 가능해질 수 있습니다.
8. **법률 자문과 함께 현재의 sanctions/AML 의무를 적용합니다.** Rules와 designations는 변경되므로, 과거의 연관성은 현재의 법적 분석을 대신할 수 없습니다.

## Safe red-team procurement model

승인된 team은 engagement controller가 책임을 유지하는 동안 대상 SOC가 자신의 hosting payment를 인식하지 못하도록 해야 할 수 있습니다.

- engagement-specific organization card 또는 문서화된 corporate wallet을 사용합니다.
- Billing, tax 및 provider records를 정확하게 유지합니다.
- Operator를 procurement duties에서 분리하고 attribution map에 대한 access를 제한합니다.
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
{{#include ../banners/hacktricks-training.md}}
