# Private Digital Payments

{{#include ../banners/hacktricks-training.md}}

Payment privacy, transaction data का नियंत्रित disclosure है। यह illegal funds को legitimate बनाने, tax या sanctions से बचने, KYC को defeat करने, false identities का उपयोग करने या unauthorized engagement को छिपाने का तरीका नहीं है। कोई payment merchant से private हो सकता है, जबकि issuer, network, employer, tax authority या investigator को पूरी तरह दिखाई देता रहे।

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) normalized inventory है, जिसमें प्रत्येक family के लिए `Pros`, `Cons`, lawful step-by-step `Procedure` और `Detection` दिए गए हैं। यह page conventional payment methods का विस्तार करता है।

{% hint style="danger" %}
चोरी किए गए accounts, synthetic identities, money mules, fictitious residency या source-of-funds claims, transaction splitting (“structuring”), अथवा opaque “no-KYC card” brokers का कभी उपयोग न करें। प्रत्येक relevant jurisdiction में current law और provider terms जांचें।
{% endhint %}

## Define the privacy property

Rail चुनने से पहले observer का नाम तय करें:

| Observer | Typical data | Useful control | What remains |
|---|---|---|---|
| Merchant | Name, email, address, card token, IP/device, basket | Guest checkout, minimum optional data, merchant-specific virtual card | Delivery, account and fraud telemetry |
| Issuer/payment processor | Legal identity, funding source, merchant, amount, time, device | Choose a regulated provider with good privacy/security terms | The provider still processes and may retain/disclose records |
| Employer/engagement owner | Expense, operator and purpose | Separate engagement budget and access-controlled ledger | Legitimate governance requires internal attribution |
| Public blockchain observer | Addresses, flows, amounts and time, depending on chain | Appropriate protocol and wallet discipline | Acquisition, endpoints and later spending can relink activity |
| Network/RPC/node operator | IP, wallet queries, transaction broadcasts | Local node or suitable privacy network | Timing and endpoint behavior may still correlate |
| Physical observer | Face, location, vehicle, CCTV, receipt | Ordinary situational privacy | Cash does not make a person physically invisible |

CFPB के अनुसार payment apps identity, device, location, contacts, transaction और behavioral data एकत्र कर सकते हैं; state privacy rules monetization या सभी secondary use को आवश्यक रूप से नहीं रोकते।<sup>[[1]](#references)</sup> किसी product name से privacy का अनुमान लगाने के बजाय actual provider notice पढ़ें।

## Compare payment methods

| Method | Privacy benefit | Main observers/links | Appropriate use |
|---|---|---|---|
| Cash | No payment-network ledger | Recipient, cameras, witnesses, cash-reporting rules | Lawful local purchases where accepted |
| Open-loop prepaid/gift card | Separates the card number from a main card | Seller, activation/registration provider, funding source, merchant | Budgeting or limited merchant compartmentalization |
| Virtual/one-time card number | Hides reusable PAN from merchant; easy revocation | Issuer still knows identity and transaction | Online merchant compartmentalization |
| Mobile-wallet token | Device/merchant receives a token instead of underlying PAN | Wallet provider, issuer, payment network and merchant | Credential security, not anonymity |
| Bank transfer/app | Convenient audit trail | Bank/app, counterparty and linked identity | Accountable organizational payments |
| Cryptocurrency | Varies by protocol; self-custody can reduce custodian exposure | Public ledger or privacy protocol, exchange, endpoint, counterparty | Lawful transfers after protocol-specific analysis |

## Cash

Cash को अभी भी privacy और inclusion के लिए important माना जाता है, और यह payment-network record से बचाता है।<sup>[[2]](#references)</sup> यह CCTV, witnesses, device location, receipts, special cases में serial-number tracing या legal reporting को defeat नहीं करता।

### Lawful workflow

1. Transaction से पहले acceptance और local cash limits जांचें। Limits country और party type के अनुसार अलग होते हैं और समय के साथ बदलते हैं।
2. Ordinary purchase को एक honest transaction में करें। Threshold या report से बचने के लिए **इसे कभी split न करें**।
3. Optional loyalty tracking या marketing collection को decline करें। Warranty, safety, delivery, tax या law के लिए required data सत्य रूप से दें।
4. Necessary proof of purchase और required accounting records को retention date के साथ encrypted storage में रखें।
5. Organization के लिए approved process के माध्यम से reimburse करें और operator, authorization, purpose, amount, date और receipt record करें।

United States में कुछ trades या businesses $10,000 से अधिक के cash receipts के लिए Form 8300 file करते हैं, जिसमें related transactions भी शामिल हैं; transactions को जानबूझकर अलग-अलग करना स्वयं unlawful structuring हो सकता है।<sup>[[3]](#references)</sup> अन्य jurisdictions अलग हैं—उदाहरण के लिए, Spain अपना statutory cash-payment restriction प्रकाशित करता है।<sup>[[4]](#references)</sup>

## Prepaid and gift cards

“Prepaid” का अर्थ anonymous नहीं है। Shop, issuer, program manager, funding bank और merchant purchase, activation, device, IP, location और spend को correlate कर सकते हैं। Reloads, ATM access, international use, higher limits या loss protection के लिए सामान्यतः registration आवश्यक होता है।

US consumer guidance बताती है कि issuers legal verification के लिए identity data मांग सकते हैं और verification विफल होने पर registered card को decline कर सकते हैं।<sup>[[5]](#references)</sup> FinCEN rules यह define करते हैं कि किन prepaid programs और participants पर AML duties लागू होती हैं।<sup>[[6]](#references)</sup> EU में narrow anonymous e-money exceptions को Directive (EU) 2018/843 द्वारा कम किया गया; Regulation (EU) 2024/1624 framework को फिर बदलता है, लेकिन सामान्यतः **10 July 2027** से लागू होता है, इसलिए इसे 2026 में पहले से operative न बताएं।<sup>[[7]](#references)</sup>

Prepaid value का उपयोग केवल तब करें जब वह identifiable issuer से lawfully प्राप्त हो, उसके terms intended use की अनुमति देते हों और इसका उद्देश्य budgeting या primary payment credential से separation हो। Resale markets और unverifiable “no-name” cards का विज्ञापन करने वाले brokers से बचें: value stolen, पहले से redeemed, geographically restricted या seizure के अधीन हो सकती है।

## Virtual cards and wallet tokens

Virtual card number (VCN) सामान्यतः real, verified account के पीछे issue किया जाता है। Merchant-specific या single-use numbers breach और cross-merchant PAN correlation को कम करते हैं; वे transaction को issuer से **नहीं** छिपाते। Network tokenization भी card credential के स्थान पर constrained token का उपयोग करती है।<sup>[[8]](#references)</sup>

### Merchant-compartmentalized workflow

1. Accurate identity, residence और funding data का उपयोग करके regulated issuer के साथ account खोलें।
2. इसे unique password, जहां उपलब्ध हो वहां phishing-resistant MFA, login alerts और offline stored recovery codes से secure करें।
3. Merchant-locked या one-time VCN generate करें। यदि supported हो तो reasonable amount/time limit set करें।
4. Guest checkout का उपयोग करें और केवल **optional** profile, loyalty और marketing fields को omit करें। Required होने पर accurate billing, delivery और tax data दें।
5. Unrelated identity providers में sign in करने से बचें; engagement/account browser compartment और approved network path का उपयोग करें।
6. Receipt और VCN-to-purpose mapping को encrypted internal ledger में save करें।
7. Refund/chargeback window के बाद number को freeze या revoke करें; unexpected authorizations के लिए parent account monitor करें।

Capital One और Google document करते हैं कि virtual numbers underlying account से जुड़े रहते हैं, जबकि EMVCo/Visa tokenization को payer anonymity के बजाय credential substitution और domain restriction के रूप में describe करते हैं।<sup>[[8]](#references)</sup>

## Delivery, accounts and refunds

Payment linkage graph में केवल एक edge है:

- Unique card को personal email, phone, browser profile, IP address या loyalty account के reuse से defeat किया जा सकता है।
- Physical delivery के लिए सामान्यतः lawful recipient और location आवश्यक होते हैं। किसी uninvolved व्यक्ति का address उपयोग न करें और resident का impersonate न करें। Fabricated details की तुलना में approved business receiving services अधिक सुरक्षित हैं।
- Digital goods account identity, IP, device fingerprint, license activation और downloads log कर सकते हैं।
- Refunds सामान्यतः original rail पर वापस आते हैं। Funds प्राप्त करके उन्हें कहीं और forward/refund करने के requests fraud और money-mule warning होते हैं।
- Merchant descriptors, invoice text और shipping notifications account delegates को sensitive purchase expose कर सकते हैं; access और alerts को सोच-समझकर set करें।

## Authorized red-team purchases

Engagement externally discreet और internally accountable होना चाहिए:

1. Written scope, purpose, spending ceiling, approver, permitted merchants/assets और reimbursement rule प्राप्त करें।
2. Organization-controlled payment account और प्रत्येक engagement या merchant के लिए separate VCN या sub-account का उपयोग करें।
3. Providers के पास accurate billing और registrant details रखें। Public registration privacy exposure को कम कर सकती है, लेकिन lie करने की permission नहीं है।
4. Operator, approval, purpose, date, amount, counterparty, asset identifier और receipt का encrypted ledger maintain करें।
5. Required होने पर counterparties को screen करें और provider, sanctions, tax तथा reporting obligations का पालन करें।
6. Finance को केवल आवश्यक access दें; operators को केवल आवश्यक limited spending capability दें।
7. Teardown के दौरान payment credentials close या freeze करें, pending charges/refunds reconcile करें और policy के अनुसार records retain करें।

Crypto-specific choices के लिए [Cryptocurrency Privacy](cryptocurrency-privacy.md) देखें। उन purchases द्वारा supported infrastructure के लिए [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) देखें।

## Verification checklist

- [ ] Desired privacy property और observers लिखे गए हैं।
- [ ] Provider, merchant और jurisdiction rules हाल में check किए गए हैं।
- [ ] Identity और source-of-funds statements truthful हैं।
- [ ] Required verification को defeat किए बिना optional merchant data minimized है।
- [ ] Funding, device, network, account, delivery और refund linkages समझे गए हैं।
- [ ] Threshold avoidance, prohibited counterparty, mule, stolen credential या third-party identity शामिल नहीं है।
- [ ] Required receipts, approvals, tax records और recovery information encrypted और access-controlled हैं।

## References

- [1] [US CFPB — Consumer Payment और अन्य Personal Financial Data के Collection, Use और Monetization के संबंध में Information का अनुरोध](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — euro area में consumers के payment attitudes पर Study (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Form 8300 के Instructions](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Cash payments की Reporting](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Prepaid card को activate या register करने के लिए personal information क्यों मांगी जा रही है?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) और [क्या मुझे prepaid card के लिए decline किया जा सकता है?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Prepaid Access पर Final Rule](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Virtual credit cards का उपयोग](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
