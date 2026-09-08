# Private Digital Payments

भुगतान privacy, transaction data का नियंत्रित disclosure है। यह illegal funds को legitimate बनाने, tax या sanctions से बचने, KYC को निष्प्रभावी करने, false identities का उपयोग करने या unauthorized engagement छिपाने का तरीका नहीं है। कोई payment merchant से private हो सकता है, जबकि issuer, network, employer, tax authority या investigator को पूरी तरह दिखाई देता है।

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) प्रत्येक family के लिए `Pros`, `Cons`, lawful step-by-step `Procedure` और `Detection` वाला normalized inventory है। यह page conventional payment methods का विस्तार करता है।

{% hint style="danger" %}
कभी भी stolen accounts, synthetic identities, money mules, fictitious residency या source-of-funds claims, transaction splitting (“structuring”), या अस्पष्ट “no-KYC card” brokers का उपयोग न करें। प्रत्येक relevant jurisdiction में current law और provider terms की जाँच करें।
{% endhint %}

## privacy property परिभाषित करें

Rail चुनने से पहले observer का नाम निर्धारित करें:

| Observer | सामान्य data | उपयोगी control | क्या बना रहता है |
|---|---|---|---|
| Merchant | Name, email, address, card token, IP/device, basket | Guest checkout, minimum optional data, merchant-specific virtual card | Delivery, account और fraud telemetry |
| Issuer/payment processor | Legal identity, funding source, merchant, amount, time, device | अच्छे privacy/security terms वाले regulated provider का चुनाव | Provider अभी भी records को process, retain और disclose कर सकता है |
| Employer/engagement owner | Expense, operator और purpose | Separate engagement budget और access-controlled ledger | Legitimate governance के लिए internal attribution आवश्यक है |
| Public blockchain observer | Addresses, flows, amounts और time, chain पर निर्भर | Appropriate protocol और wallet discipline | Acquisition, endpoints और बाद का spending activity को फिर से link कर सकता है |
| Network/RPC/node operator | IP, wallet queries, transaction broadcasts | Local node या suitable privacy network | Timing और endpoint behavior अभी भी correlate हो सकते हैं |
| Physical observer | Face, location, vehicle, CCTV, receipt | सामान्य situational privacy | Cash किसी व्यक्ति को physically invisible नहीं बनाता |

CFPB के अनुसार payment apps identity, device, location, contacts, transaction और behavioral data एकत्र कर सकते हैं; state privacy rules monetization या सभी secondary use को आवश्यक रूप से नहीं रोकते हैं।<sup>[[1]](#references)</sup> Product name से privacy का अनुमान लगाने के बजाय actual provider notice पढ़ें।

## Payment methods की तुलना करें

| Method | Privacy benefit | Main observers/links | Appropriate use |
|---|---|---|---|
| Cash | कोई payment-network ledger नहीं | Recipient, cameras, witnesses, cash-reporting rules | जहाँ स्वीकार्य हो, वहाँ lawful local purchases |
| Open-loop prepaid/gift card | Card number को main card से अलग करता है | Seller, activation/registration provider, funding source, merchant | Budgeting या सीमित merchant compartmentalization |
| Virtual/one-time card number | Merchant से reusable PAN छिपाता है; आसान revocation | Issuer identity और transaction को अभी भी जानता है | Online merchant compartmentalization |
| Mobile-wallet token | Device/merchant को underlying PAN के बजाय token मिलता है | Wallet provider, issuer, payment network और merchant | Credential security, anonymity नहीं |
| Bank transfer/app | सुविधाजनक audit trail | Bank/app, counterparty और linked identity | Accountable organizational payments |
| Cryptocurrency | Protocol के अनुसार बदलता है; self-custody custodian exposure घटा सकता है | Public ledger या privacy protocol, exchange, endpoint, counterparty | Protocol-specific analysis के बाद lawful transfers |

## Cash

Cash को अभी भी privacy और inclusion के लिए महत्वपूर्ण माना जाता है, और यह payment-network record से बचाता है।<sup>[[2]](#references)</sup> यह CCTV, witnesses, device location, receipts, विशेष मामलों में serial-number tracing या legal reporting को निष्प्रभावी नहीं करता।

### Lawful workflow

1. Transaction से पहले acceptance और local cash limits जाँचें। Limits country और party type के अनुसार अलग होती हैं और समय के साथ बदलती हैं।
2. एक सामान्य और ईमानदार transaction में purchase करें। Threshold या report से बचने के लिए **इसे कभी split न करें**।
3. Optional loyalty tracking या marketing collection अस्वीकार करें। Warranty, safety, delivery, tax या law के लिए आवश्यक data सत्य रूप से दें।
4. आवश्यक proof of purchase और required accounting records को retention date के साथ encrypted storage में रखें।
5. Organization के लिए approved process के माध्यम से reimbursement करें और operator, authorization, purpose, amount, date और receipt दर्ज करें।

United States में कुछ trades या businesses $10,000 से अधिक cash receipts के लिए Form 8300 file करते हैं, जिसमें related transactions भी शामिल हैं; जानबूझकर transactions को अलग-अलग करना स्वयं unlawful structuring हो सकता है।<sup>[[3]](#references)</sup> अन्य jurisdictions अलग हैं—उदाहरण के लिए, Spain अपनी statutory cash-payment restriction प्रकाशित करता है।<sup>[[4]](#references)</sup>

## Prepaid और gift cards

“Prepaid” का अर्थ anonymous नहीं है। Shop, issuer, program manager, funding bank और merchant purchase, activation, device, IP, location और spend को correlate कर सकते हैं। Reloads, ATM access, international use, higher limits या loss protection के लिए आमतौर पर registration आवश्यक होता है।

US consumer guidance बताती है कि issuers legal verification के लिए identity data माँग सकते हैं और verification विफल होने पर registered card को decline कर सकते हैं।<sup>[[5]](#references)</sup> FinCEN rules यह निर्धारित करते हैं कि किन prepaid programs और participants पर AML duties लागू होती हैं।<sup>[[6]](#references)</sup> EU में narrow anonymous e-money exceptions को Directive (EU) 2018/843 द्वारा कम किया गया; Regulation (EU) 2024/1624 framework को फिर बदलता है, लेकिन सामान्यतः **10 July 2027** से लागू होता है, इसलिए इसे 2026 में पहले से operative न बताएं।<sup>[[7]](#references)</sup>

Prepaid value का उपयोग केवल तब करें जब वह identifiable issuer से lawfully प्राप्त हो, उसके terms intended use की अनुमति देते हों, और इसका benefit budgeting या primary payment credential से separation हो। Resale markets और unverifiable “no-name” cards का advertising करने वाले brokers से बचें: value stolen, पहले से redeemed, geographically restricted या seizure के अधीन हो सकती है।

## Virtual cards और wallet tokens

Virtual card number (VCN) आमतौर पर real, verified account के पीछे issue किया जाता है। Merchant-specific या single-use numbers breach और cross-merchant PAN correlation को कम करते हैं; वे transaction को issuer से **नहीं** छिपाते। Network tokenization भी card credential के स्थान पर constrained token रखता है।<sup>[[8]](#references)</sup>

### Merchant-compartmentalized workflow

1. Accurate identity, residence और funding data का उपयोग करके regulated issuer के साथ account खोलें।
2. Unique password, जहाँ उपलब्ध हो वहाँ phishing-resistant MFA, login alerts और offline stored recovery codes से इसे secure करें।
3. Merchant-locked या one-time VCN generate करें। यदि supported हो तो reasonable amount/time limit set करें।
4. Guest checkout का उपयोग करें और केवल **optional** profile, loyalty और marketing fields छोड़ें। आवश्यक होने पर accurate billing, delivery और tax data दें।
5. Unrelated identity providers में sign in करने से बचें; engagement/account browser compartment और approved network path का उपयोग करें।
6. Receipt और VCN-to-purpose mapping को encrypted internal ledger में save करें।
7. Refund/chargeback window के बाद number को freeze या revoke करें; unexpected authorizations के लिए parent account monitor करें।

Capital One और Google document करते हैं कि virtual numbers underlying account से जुड़े रहते हैं, जबकि EMVCo/Visa tokenization को payer anonymity के बजाय credential substitution और domain restriction के रूप में describe करते हैं।<sup>[[8]](#references)</sup>

## Delivery, accounts और refunds

Payment linkage graph में केवल एक edge है:

- Personal email, phone, browser profile, IP address या loyalty account को reuse करने पर unique card का benefit समाप्त हो जाता है।
- Physical delivery के लिए सामान्यतः lawful recipient और location चाहिए। किसी uninvolved व्यक्ति के address का उपयोग या resident का impersonation न करें। Approved business receiving services, fabricated details से अधिक सुरक्षित हैं।
- Digital goods account identity, IP, device fingerprint, license activation और downloads log कर सकते हैं।
- Refund आमतौर पर original rail पर लौटते हैं। Funds प्राप्त करके उन्हें कहीं और forward/refund करने के requests fraud और money-mule warning हैं।
- Merchant descriptors, invoice text और shipping notifications किसी sensitive purchase को account delegates के सामने उजागर कर सकते हैं; access और alerts को जानबूझकर set करें।

## Authorized red-team purchases

Engagement बाहरी रूप से discreet और internally accountable होना चाहिए:

1. Written scope, purpose, spending ceiling, approver, permitted merchants/assets और reimbursement rule प्राप्त करें।
2. Organization-controlled payment account और प्रत्येक engagement या merchant के लिए separate VCN या sub-account का उपयोग करें।
3. Providers के साथ accurate billing और registrant details रखें। Public registration privacy exposure को कम कर सकती है, लेकिन झूठ बोलने की अनुमति नहीं है।
4. Operator, approval, purpose, date, amount, counterparty, asset identifier और receipt का encrypted ledger बनाए रखें।
5. आवश्यकतानुसार counterparties को screen करें और provider, sanctions, tax तथा reporting obligations का पालन करें।
6. Finance को केवल आवश्यक access दें; operators को केवल आवश्यक limited spending capability दें।
7. Teardown के दौरान payment credentials को close या freeze करें, pending charges/refunds reconcile करें और policy के अनुसार records retain करें।

Crypto-specific choices के लिए [Cryptocurrency Privacy](cryptocurrency-privacy.md) पर जाएँ। उन purchases को support करने वाले infrastructure के लिए [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) देखें।

## Verification checklist

- [ ] Desired privacy property और observers लिखे गए हैं।
- [ ] Provider, merchant और jurisdiction rules को हाल ही में check किया गया है।
- [ ] Identity और source-of-funds statements truthful हैं।
- [ ] Required verification को निष्प्रभावी किए बिना optional merchant data को minimize किया गया है।
- [ ] Funding, device, network, account, delivery और refund linkages समझे गए हैं।
- [ ] Threshold avoidance, prohibited counterparty, mule, stolen credential या third-party identity शामिल नहीं है।
- [ ] Required receipts, approvals, tax records और recovery information encrypted और access-controlled हैं।

## References

- [1] [US CFPB — Consumer Payment और अन्य Personal Financial Data के Collection, Use और Monetization के संबंध में Information का अनुरोध](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — euro area में consumers के payment attitudes पर Study (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Form 8300 के लिए Instructions](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Cash payments की reporting](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Prepaid card को activate या register करने के लिए personal information क्यों माँगी जा रही है?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) और [क्या मुझे prepaid card से decline किया जा सकता है?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Prepaid Access पर Final Rule](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Virtual credit cards का उपयोग](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
