# Private Digital Payments

{{#include ../banners/hacktricks-training.md}}

Payment privacy는 transaction data를 통제하여 공개하는 것입니다. 이는 불법 자금을 합법적으로 보이게 하거나, tax 또는 sanctions를 회피하거나, KYC를 무력화하거나, 허위 신원을 사용하거나, 승인되지 않은 engagement를 숨기는 방법이 아닙니다. Payment는 merchant로부터는 private할 수 있지만 issuer, network, employer, tax authority 또는 investigator에게는 완전히 공개된 상태일 수 있습니다.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md)는 각 family에 대한 `Pros`, `Cons`, 합법적인 단계별 `Procedure` 및 `Detection`을 정규화하여 정리한 목록입니다. 이 페이지에서는 일반적인 payment method를 확장하여 설명합니다.

{% hint style="danger" %}
도난한 account, synthetic identity, money mule, 허위 residency 또는 source-of-funds 주장, threshold를 피하기 위한 transaction splitting(“structuring”), 불투명한 “no-KYC card” broker를 절대 사용하지 마세요. 관련된 모든 jurisdiction의 최신 법률과 provider 약관을 확인하세요.
{% endhint %}

## Define the privacy property

rail을 선택하기 전에 observer를 명시하세요.

| Observer | Typical data | Useful control | What remains |
|---|---|---|---|
| Merchant | 이름, email, address, card token, IP/device, basket | Guest checkout, 선택 항목 최소화, merchant별 virtual card | Delivery, account 및 fraud telemetry |
| Issuer/payment processor | 법적 신원, funding source, merchant, amount, time, device | privacy/security 약관이 우수한 regulated provider 선택 | Provider는 여전히 record를 처리하고 보관하거나 공개할 수 있음 |
| Employer/engagement owner | Expense, operator 및 purpose | 분리된 engagement budget 및 access-controlled ledger | 정당한 governance에는 내부 attribution이 필요함 |
| Public blockchain observer | Chain에 따라 address, flow, amount 및 time | 적절한 protocol 및 wallet discipline | Acquisition, endpoint 및 이후 spending을 통해 activity가 다시 연결될 수 있음 |
| Network/RPC/node operator | IP, wallet query, transaction broadcast | Local node 또는 적절한 privacy network | Timing 및 endpoint behavior가 여전히 상관관계를 보일 수 있음 |
| Physical observer | Face, location, vehicle, CCTV, receipt | 일반적인 상황별 privacy | Cash는 사람을 물리적으로 보이지 않게 만들지 않음 |

CFPB는 payment app이 identity, device, location, contacts, transaction 및 behavioral data를 수집할 수 있다고 설명합니다. 또한 state privacy rule이 monetization 또는 모든 secondary use를 반드시 막는 것은 아닙니다.<sup>[[1]](#references)</sup> Product name만으로 privacy를 추론하지 말고 실제 provider notice를 읽으세요.

## Compare payment methods

| Method | Privacy benefit | Main observers/links | Appropriate use |
|---|---|---|---|
| Cash | Payment-network ledger가 없음 | Recipient, camera, witness, cash-reporting rule | 허용되는 경우 합법적인 local purchase |
| Open-loop prepaid/gift card | Card number를 primary card와 분리 | Seller, activation/registration provider, funding source, merchant | Budgeting 또는 제한적인 merchant compartmentalization |
| Virtual/one-time card number | Merchant로부터 reusable PAN을 숨김; 쉽게 revoke 가능 | Issuer는 여전히 identity와 transaction을 알고 있음 | Online merchant compartmentalization |
| Mobile-wallet token | Device/merchant가 underlying PAN 대신 token을 받음 | Wallet provider, issuer, payment network 및 merchant | Credential security이지 anonymity가 아님 |
| Bank transfer/app | 편리한 audit trail | Bank/app, counterparty 및 linked identity | 책임이 명확한 organizational payment |
| Cryptocurrency | Protocol에 따라 다름; self-custody는 custodian exposure를 줄일 수 있음 | Public ledger 또는 privacy protocol, exchange, endpoint, counterparty | Protocol별 분석 후 합법적인 transfer |

## Cash

Cash는 여전히 privacy와 inclusion에 중요하다고 인식되며 payment-network record를 남기지 않습니다.<sup>[[2]](#references)</sup> 그러나 CCTV, witness, device location, receipt, 특수한 경우의 serial-number tracing 또는 법적 reporting을 무력화하지는 않습니다.

### Lawful workflow

1. Transaction 전에 acceptance와 local cash limit을 확인하세요. Limit은 국가와 party type에 따라 다르며 시간이 지나면서 변경됩니다.
2. 일반적인 purchase를 정직한 하나의 transaction으로 진행하세요. Threshold 또는 report를 피하기 위해 **절대 분할하지 마세요**.
3. 선택적인 loyalty tracking 또는 marketing collection을 거부하세요. Warranty, safety, delivery, tax 또는 law에 필요한 data는 사실대로 제공하세요.
4. 필요한 proof of purchase와 필수 accounting record를 retention date와 함께 encrypted storage에 보관하세요.
5. Organization의 경우 승인된 process를 통해 reimburse하고 operator, authorization, purpose, amount, date 및 receipt를 기록하세요.

미국에서는 특정 trade 또는 business가 $10,000를 초과하는 cash receipt에 대해 Form 8300을 제출해야 하며, 여기에는 related transaction도 포함됩니다. Transaction을 의도적으로 나누는 행위 자체가 불법 structuring일 수 있습니다.<sup>[[3]](#references)</sup> 다른 jurisdiction은 다릅니다. 예를 들어 Spain은 자체적인 statutory cash-payment restriction을 공표하고 있습니다.<sup>[[4]](#references)</sup>

## Prepaid and gift cards

“Prepaid”는 anonymous를 의미하지 않습니다. Shop, issuer, program manager, funding bank 및 merchant가 purchase, activation, device, IP, location 및 spend를 상호 연관시킬 수 있습니다. Reload, ATM access, international use, higher limit 또는 loss protection에는 일반적으로 registration이 필요합니다.

US consumer guidance에 따르면 issuer는 법적 verification을 위해 identity data를 요청할 수 있으며 verification에 실패하면 registered card를 거부할 수 있습니다.<sup>[[5]](#references)</sup> FinCEN rule은 어떤 prepaid program 및 participant에게 AML duty가 적용되는지 정의합니다.<sup>[[6]](#references)</sup> EU에서는 Directive (EU) 2018/843에 의해 제한적인 anonymous e-money exception이 축소되었습니다. Regulation (EU) 2024/1624가 framework를 다시 변경하지만 일반적으로 **2027년 7월 10일**부터 적용되므로, 2026년에 이미 시행 중이라고 설명하지 마세요.<sup>[[7]](#references)</sup>

Prepaid value는 identifiable issuer로부터 합법적으로 취득했고, 약관이 intended use를 허용하며, benefit이 budgeting 또는 primary payment credential과의 separation인 경우에만 사용하세요. Resale market과 검증할 수 없는 “no-name” card를 광고하는 broker는 피하세요. 해당 value는 도난되었거나, 이미 redeemed되었거나, geographic restriction이 있거나, seizure 대상일 수 있습니다.

## Virtual cards and wallet tokens

Virtual card number(VCN)는 일반적으로 실제 verified account를 기반으로 발급됩니다. Merchant-specific 또는 single-use number는 breach와 merchant 간 PAN correlation을 줄이지만 transaction을 issuer에게 숨기지는 **않습니다**. Network tokenization도 card credential을 제한된 token으로 대체합니다.<sup>[[8]](#references)</sup>

### Merchant-compartmentalized workflow

1. 정확한 identity, residence 및 funding data를 사용하여 regulated issuer에 account를 개설하세요.
2. Unique password, 가능한 경우 phishing-resistant MFA, login alert 및 offline에 보관한 recovery code로 account를 보호하세요.
3. Merchant-locked 또는 one-time VCN을 생성하세요. 지원되는 경우 합리적인 amount/time limit을 설정하세요.
4. Guest checkout을 사용하고 **optional** profile, loyalty 및 marketing field만 생략하세요. 필요한 경우 정확한 billing, delivery 및 tax data를 제공하세요.
5. 관련 없는 identity provider에 로그인하지 마세요. Engagement/account browser compartment와 승인된 network path를 사용하세요.
6. Receipt와 VCN-to-purpose mapping을 encrypted internal ledger에 저장하세요.
7. Refund/chargeback window가 끝난 후 number를 freeze 또는 revoke하고 parent account에서 예상하지 못한 authorization을 모니터링하세요.

Capital One과 Google은 virtual number가 underlying account에 계속 연결된다고 설명합니다. EMVCo/Visa는 tokenization을 payer anonymity가 아니라 credential substitution 및 domain restriction으로 설명합니다.<sup>[[8]](#references)</sup>

## Delivery, accounts and refunds

Payment는 linkage graph에서 하나의 edge일 뿐입니다.

- Personal email, phone, browser profile, IP address 또는 loyalty account를 재사용하면 unique card도 무력화됩니다.
- Physical delivery에는 일반적으로 합법적인 recipient와 location이 필요합니다. 관계없는 사람의 address를 사용하거나 resident를 사칭하지 마세요. 승인된 business receiving service가 fabricated detail보다 안전합니다.
- Digital goods는 account identity, IP, device fingerprint, license activation 및 download를 기록할 수 있습니다.
- Refund는 일반적으로 original rail로 반환됩니다. Funds를 받은 뒤 다른 곳으로 전달하거나 refund하라는 요청은 fraud 및 money-mule warning입니다.
- Merchant descriptor, invoice text 및 shipping notification이 account delegate에게 sensitive purchase를 노출할 수 있으므로 access와 alert를 신중하게 설정하세요.

## Authorized red-team purchases

Engagement는 외부적으로는 discreet해야 하지만 내부적으로는 accountable해야 합니다.

1. Written scope, purpose, spending ceiling, approver, permitted merchant/asset 및 reimbursement rule을 확보하세요.
2. Organization이 관리하는 payment account와 engagement 또는 merchant별 별도 VCN 또는 sub-account를 사용하세요.
3. Provider에는 정확한 billing 및 registrant detail을 유지하세요. Public registration privacy는 exposure를 줄일 수 있지만 거짓말할 권한을 부여하지 않습니다.
4. Operator, approval, purpose, date, amount, counterparty, asset identifier 및 receipt를 encrypted ledger에 정확히 기록하세요.
5. 필요한 경우 counterparty를 screen하고 provider, sanctions, tax 및 reporting obligation을 따르세요.
6. Finance에는 필요한 access만 제공하고, operator에게는 필요한 제한된 spending capability만 제공하세요.
7. Teardown 중 payment credential을 close 또는 freeze하고 pending charge/refund를 reconcile하며 policy에 따라 record를 보존하세요.

Crypto-specific choice는 [Cryptocurrency Privacy](cryptocurrency-privacy.md)를 계속 참조하세요. 해당 purchase가 지원하는 infrastructure는 [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)를 참조하세요.

## Verification checklist

- [ ] 원하는 privacy property와 observer를 문서화했습니다.
- [ ] Provider, merchant 및 jurisdiction rule을 최근에 확인했습니다.
- [ ] Identity 및 source-of-funds statement가 사실입니다.
- [ ] Required verification을 무력화하지 않는 범위에서 optional merchant data를 최소화했습니다.
- [ ] Funding, device, network, account, delivery 및 refund linkage를 이해하고 있습니다.
- [ ] Threshold avoidance, prohibited counterparty, mule, stolen credential 또는 third-party identity가 포함되지 않았습니다.
- [ ] Required receipt, approval, tax record 및 recovery information을 encrypted access-controlled 방식으로 보관했습니다.

## References

- [1] [US CFPB — Consumer Payment 및 기타 Personal Financial Data의 수집, 사용 및 Monetization에 관한 정보 요청](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Euro area 소비자의 payment attitude에 관한 연구(SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Form 8300 지침](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Cash payment reporting](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Prepaid card를 activate 또는 register하기 위해 personal information을 요구받는 이유](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) 및 [Prepaid card를 거부당할 수 있는가?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Prepaid Access에 관한 최종 Rule](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Virtual credit card 사용](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
