# Private Digital Payments

Payment privacy는 거래 데이터의 통제된 공개를 의미합니다. 이는 불법 자금을 합법적으로 보이게 하거나, 세금 또는 제재를 회피하거나, KYC를 무력화하거나, 허위 신원을 사용하거나, 승인되지 않은 engagement를 숨기는 방법이 아닙니다. Payment는 merchant에게는 private할 수 있지만 issuer, network, employer, tax authority 또는 investigator에게는 완전히 공개된 상태로 남을 수 있습니다.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md)는 각 family에 대해 `Pros`, `Cons`, 합법적인 단계별 `Procedure` 및 `Detection`을 포함한 정규화된 inventory입니다. 이 페이지에서는 conventional payment methods를 확장하여 설명합니다.

{% hint style="danger" %}
도난당한 계정, synthetic identities, money mules, 허위 거주지 또는 자금 출처 주장, transaction splitting(“structuring”), 불투명한 “no-KYC card” broker를 절대 사용하지 마십시오. 관련된 모든 관할권의 최신 법률과 provider 약관을 확인하십시오.
{% endhint %}

## Define the privacy property

rail을 선택하기 전에 observer를 명시하십시오.

| Observer | 일반적인 데이터 | 유용한 통제 수단 | 남는 정보 |
|---|---|---|---|
| Merchant | 이름, 이메일, 주소, card token, IP/device, basket | Guest checkout, 최소한의 optional data, merchant별 virtual card | Delivery, account 및 fraud telemetry |
| Issuer/payment processor | 법적 신원, funding source, merchant, 금액, 시간, device | 우수한 privacy/security 약관을 갖춘 regulated provider 선택 | Provider는 여전히 records를 처리하고 보관하거나 공개할 수 있음 |
| Employer/engagement owner | Expense, operator 및 목적 | 별도의 engagement budget 및 access-controlled ledger | 정당한 governance에는 내부 attribution이 필요함 |
| Public blockchain observer | Chain에 따라 addresses, flows, amounts 및 time | 적절한 protocol 및 wallet discipline | Acquisition, endpoints 및 이후 spending이 activity를 다시 연결할 수 있음 |
| Network/RPC/node operator | IP, wallet queries, transaction broadcasts | Local node 또는 적합한 privacy network | Timing 및 endpoint behavior가 여전히 상관관계를 보일 수 있음 |
| Physical observer | 얼굴, 위치, 차량, CCTV, receipt | 일반적인 situational privacy | Cash를 사용해도 사람이 물리적으로 보이지 않게 되지는 않음 |

CFPB는 payment apps가 identity, device, location, contacts, transaction 및 behavioral data를 수집할 수 있다고 설명합니다. 또한 state privacy rules가 monetization 또는 모든 secondary use를 반드시 막지는 않습니다.<sup>[[1]](#references)</sup> 제품명만으로 privacy를 추정하지 말고 실제 provider notice를 읽으십시오.

## Compare payment methods

| Method | Privacy benefit | Main observers/links | Appropriate use |
|---|---|---|---|
| Cash | Payment-network ledger가 없음 | Recipient, cameras, witnesses, cash-reporting rules | 허용되는 경우 합법적인 현지 구매 |
| Open-loop prepaid/gift card | Card number를 주 결제 카드와 분리 | Seller, activation/registration provider, funding source, merchant | Budgeting 또는 제한적인 merchant compartmentalization |
| Virtual/one-time card number | Merchant로부터 재사용 가능한 PAN을 숨김; 쉽게 revoke 가능 | Issuer는 여전히 identity와 transaction을 알고 있음 | Online merchant compartmentalization |
| Mobile-wallet token | Device/merchant가 underlying PAN 대신 token을 받음 | Wallet provider, issuer, payment network 및 merchant | Credential security이지 anonymity가 아님 |
| Bank transfer/app | 편리한 audit trail | Bank/app, counterparty 및 linked identity | 책임이 명확한 organizational payments |
| Cryptocurrency | Protocol에 따라 다름; self-custody는 custodian exposure를 줄일 수 있음 | Public ledger 또는 privacy protocol, exchange, endpoint, counterparty | Protocol별 분석 후 합법적인 transfers |

## Cash

Cash는 여전히 privacy와 inclusion에 중요하다고 인식되며 payment-network record를 남기지 않습니다.<sup>[[2]](#references)</sup> 그러나 CCTV, witnesses, device location, receipts, 특수한 경우의 serial-number tracing 또는 법적 reporting을 무력화하지는 못합니다.

### Lawful workflow

1. Transaction 전에 acceptance 및 현지 cash limits를 확인하십시오. Limits는 국가와 party type에 따라 다르며 시간이 지나면서 변경됩니다.
2. 정직한 하나의 transaction으로 일반적인 구매를 진행하십시오. Threshold 또는 report를 피하기 위해 **절대 분할하지 마십시오**.
3. Optional loyalty tracking 또는 marketing collection을 거부하십시오. Warranty, safety, delivery, tax 또는 law에 필요한 data는 사실대로 제공하십시오.
4. 필요한 proof of purchase와 required accounting records를 retention date와 함께 encrypted storage에 보관하십시오.
5. Organization의 경우 approved process를 통해 reimburse하고 operator, authorization, purpose, amount, date 및 receipt를 기록하십시오.

미국에서는 특정 trades 또는 businesses가 $10,000를 초과하는 cash receipts에 대해 Form 8300을 제출해야 하며, 여기에는 related transactions도 포함됩니다. Transaction을 의도적으로 나누는 행위 자체가 unlawful structuring일 수 있습니다.<sup>[[3]](#references)</sup> 다른 관할권은 다릅니다. 예를 들어 Spain은 자체적인 statutory cash-payment restriction을 공표하고 있습니다.<sup>[[4]](#references)</sup>

## Prepaid and gift cards

“Prepaid”가 anonymous를 의미하지는 않습니다. Shop, issuer, program manager, funding bank 및 merchant는 purchase, activation, device, IP, location 및 spend를 서로 연계할 수 있습니다. Reloads, ATM access, international use, higher limits 또는 loss protection에는 일반적으로 registration이 필요합니다.

US consumer guidance에 따르면 issuers는 legal verification을 위해 identity data를 요청할 수 있으며 verification이 실패하면 registered card를 거부할 수 있습니다.<sup>[[5]](#references)</sup> FinCEN rules는 어떤 prepaid programs와 participants에 AML duties가 적용되는지 정의합니다.<sup>[[6]](#references)</sup> EU에서는 Directive (EU) 2018/843에 따라 제한적인 anonymous e-money exceptions가 축소되었습니다. Regulation (EU) 2024/1624는 framework를 다시 변경하지만 일반적으로 **2027년 7월 10일**부터 적용되므로, 2026년에 이미 operative하다고 설명하지 마십시오.<sup>[[7]](#references)</sup>

Prepaid value는 identifiable issuer로부터 합법적으로 취득했고, 약관이 intended use를 허용하며, 그 목적이 budgeting 또는 primary payment credential과의 separation인 경우에만 사용하십시오. Resale markets와 검증할 수 없는 “no-name” cards를 광고하는 brokers를 피하십시오. Value가 stolen이거나 이미 redeemed되었거나 지리적으로 제한되었거나 seizure 대상일 수 있습니다.

## Virtual cards and wallet tokens

Virtual card number(VCN)는 일반적으로 실제 verified account 뒤에서 발급됩니다. Merchant-specific 또는 single-use numbers는 breach와 cross-merchant PAN correlation을 줄이지만 transaction을 issuer로부터 **숨기지는 않습니다**. Network tokenization도 card credential 대신 제한된 token으로 대체합니다.<sup>[[8]](#references)</sup>

### Merchant-compartmentalized workflow

1. Accurate identity, residence 및 funding data를 사용하여 regulated issuer에 account를 개설하십시오.
2. 고유한 password, 가능한 경우 phishing-resistant MFA, login alerts 및 offline에 보관한 recovery codes로 account를 보호하십시오.
3. Merchant-locked 또는 one-time VCN을 생성하십시오. 지원되는 경우 합리적인 amount/time limit를 설정하십시오.
4. Guest checkout을 사용하고 **optional** profile, loyalty 및 marketing fields만 생략하십시오. Required한 경우 정확한 billing, delivery 및 tax data를 제공하십시오.
5. Unrelated identity providers에 로그인하지 마십시오. Engagement/account browser compartment 및 approved network path를 사용하십시오.
6. Receipt와 VCN-to-purpose mapping을 encrypted internal ledger에 저장하십시오.
7. Refund/chargeback window가 지난 후 number를 freeze 또는 revoke하고 parent account에서 예상하지 못한 authorizations를 모니터링하십시오.

Capital One과 Google은 virtual numbers가 underlying account에 계속 연결된다고 설명하며, EMVCo/Visa는 tokenization을 payer anonymity가 아닌 credential substitution 및 domain restriction으로 설명합니다.<sup>[[8]](#references)</sup>

## Delivery, accounts and refunds

Payment는 linkage graph의 하나의 edge일 뿐입니다.

- Unique card도 personal email, phone, browser profile, IP address 또는 loyalty account를 재사용하면 무력화됩니다.
- Physical delivery에는 일반적으로 합법적인 recipient와 location이 필요합니다. 관계없는 사람의 address를 사용하거나 resident를 사칭하지 마십시오. Fabricated details보다 approved business receiving services가 안전합니다.
- Digital goods는 account identity, IP, device fingerprint, license activation 및 downloads를 기록할 수 있습니다.
- Refunds는 일반적으로 original rail로 반환됩니다. Funds를 받아 다른 곳으로 전달하거나 refund해 달라는 요청은 fraud 및 money-mule warning입니다.
- Merchant descriptors, invoice text 및 shipping notifications는 sensitive purchase를 account delegates에게 노출할 수 있으므로 access와 alerts를 신중하게 설정하십시오.

## Authorized red-team purchases

Engagement는 외부적으로는 discreet해야 하지만 내부적으로는 accountable해야 합니다.

1. Written scope, purpose, spending ceiling, approver, permitted merchants/assets 및 reimbursement rule을 확보하십시오.
2. Organization-controlled payment account와 engagement 또는 merchant별 separate VCN 또는 sub-account를 사용하십시오.
3. Provider에 accurate billing 및 registrant details를 유지하십시오. Public registration privacy는 exposure를 최소화할 수 있지만 거짓말할 permission은 아닙니다.
4. Operator, approval, purpose, date, amount, counterparty, asset identifier 및 receipt를 encrypted ledger에 정확히 기록하십시오.
5. 필요한 경우 counterparties를 screen하고 provider, sanctions, tax 및 reporting obligations를 따르십시오.
6. Finance에는 필요한 access만 제공하고, operators에게는 필요한 제한적인 spending capability만 제공하십시오.
7. Teardown 중 payment credentials를 close 또는 freeze하고 pending charges/refunds를 reconcile한 뒤 policy에 따라 records를 보존하십시오.

Crypto-specific choices는 [Cryptocurrency Privacy](cryptocurrency-privacy.md)를 계속 참조하십시오. 해당 purchases를 지원하는 infrastructure는 [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)를 참조하십시오.

## Verification checklist

- [ ] 원하는 privacy property와 observers를 기록했다.
- [ ] Provider, merchant 및 jurisdiction rules를 최근에 확인했다.
- [ ] Identity 및 source-of-funds statements가 사실이다.
- [ ] Required verification을 무력화하지 않는 범위에서 optional merchant data를 최소화했다.
- [ ] Funding, device, network, account, delivery 및 refund linkages를 이해했다.
- [ ] Threshold avoidance, prohibited counterparty, mule, stolen credential 또는 third-party identity가 관련되지 않았다.
- [ ] Required receipts, approvals, tax records 및 recovery information을 encrypted 및 access-controlled 상태로 보관했다.

## References

- [1] [US CFPB — Consumer Payment 및 기타 Personal Financial Data의 Collection, Use 및 Monetization에 관한 정보 요청](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Euro area 소비자의 payment attitudes에 관한 연구 (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Form 8300 Instructions](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Cash payments reporting](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Prepaid card를 activate 또는 register하기 위해 personal information을 요구받는 이유](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) 및 [Prepaid card가 거부될 수 있는지 여부](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Prepaid Access에 관한 Final Rule](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Virtual credit cards 사용](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
