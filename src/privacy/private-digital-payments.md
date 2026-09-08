# Private Digital Payments

Payment privacyとは、transaction dataの開示を管理することです。これは、違法資金を合法的に見せかけたり、taxやsanctionsを回避したり、KYCを打ち破ったり、虚偽の身元を使用したり、無許可のengagementを隠したりする方法ではありません。Paymentはmerchantからはprivateであっても、issuer、network、employer、tax authority、investigatorからは完全に可視化されている場合があります。

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md)は、各familyについて`Pros`、`Cons`、合法的な手順の`Procedure`、`Detection`をまとめた標準化されたinventoryです。このページでは、従来型のpayment methodsを詳しく説明します。

{% hint style="danger" %}
盗難アカウント、synthetic identities、money mules、架空の居住地やsource-of-fundsの申告、transaction splitting（“structuring”）、または不透明な“no-KYC card” brokersは決して使用しないでください。関連するすべてのjurisdictionで、現行法とproviderのtermsを確認してください。
{% endhint %}

## Define the privacy property

railを選ぶ前に、observerを明確にします。

| Observer | Typical data | Useful control | What remains |
|---|---|---|---|
| Merchant | Name、email、address、card token、IP/device、basket | Guest checkout、optional dataの最小化、merchant-specific virtual card | Delivery、account、fraud telemetry |
| Issuer/payment processor | Legal identity、funding source、merchant、amount、time、device | privacy/security termsの優れたregulated providerを選ぶ | Providerは引き続きrecordsを処理し、保持または開示する可能性がある |
| Employer/engagement owner | Expense、operator、purpose | engagement budgetとaccess-controlled ledgerの分離 | Legitimate governanceには内部でのattributionが必要 |
| Public blockchain observer | Addresses、flows、amounts、time（chainによって異なる） | 適切なprotocolとwallet discipline | Acquisition、endpoints、後のspendingによってactivityが再び関連付けられる可能性がある |
| Network/RPC/node operator | IP、wallet queries、transaction broadcasts | Local nodeまたは適切なprivacy network | Timingとendpoint behaviorは相関付けられる可能性がある |
| Physical observer | Face、location、vehicle、CCTV、receipt | 通常のsituational privacy | Cashでもpersonを物理的に不可視にはできない |

CFPBは、payment appsがidentity、device、location、contacts、transaction、behavioral dataを収集できると説明しています。state privacy rulesによっても、monetizationやすべてのsecondary useが必ずしも防止されるわけではありません。<sup>[[1]](#references)</sup> Product nameからprivacyを推測せず、実際のprovider noticeを読んでください。

## Compare payment methods

| Method | Privacy benefit | Main observers/links | Appropriate use |
|---|---|---|---|
| Cash | Payment-network ledgerが存在しない | Recipient、cameras、witnesses、cash-reporting rules | 利用可能な地域での合法的なlocal purchases |
| Open-loop prepaid/gift card | Card numberをmain cardから分離 | Seller、activation/registration provider、funding source、merchant | Budgetingまたは限定的なmerchant compartmentalization |
| Virtual/one-time card number | Merchantからreusable PANを隠し、容易にrevocationできる | Issuerはidentityとtransactionを把握する | Online merchant compartmentalization |
| Mobile-wallet token | Device/merchantにはunderlying PANの代わりにtokenが渡される | Wallet provider、issuer、payment network、merchant | Credential securityであり、anonymityではない |
| Bank transfer/app | 便利なaudit trail | Bank/app、counterparty、linked identity | Accountableなorganizational payments |
| Cryptocurrency | Protocolによって異なる。self-custodyはcustodian exposureを減らせる場合がある | Public ledgerまたはprivacy protocol、exchange、endpoint、counterparty | Protocol-specific analysis後の合法的なtransfers |

## Cash

Cashは現在もprivacyとinclusionに重要だと考えられており、payment-network recordを回避できます。<sup>[[2]](#references)</sup> ただし、CCTV、witnesses、device location、receipts、特殊なケースにおけるserial-number tracing、または法的なreportingを回避するものではありません。

### Lawful workflow

1. Transaction前に、acceptanceとlocal cash limitsを確認します。Limitsはcountryとparty typeによって異なり、時間とともに変化します。
2. 通常のpurchaseを、正直な1回のtransactionとして行います。Thresholdやreportを避けるために**決して分割しないでください**。
3. Optionalなloyalty trackingやmarketing collectionを拒否します。Warranty、safety、delivery、tax、lawに必要なdataは、正確に提供します。
4. 必要なproof of purchaseとrequired accounting recordsを、retention dateとともにencrypted storageへ保存します。
5. Organizationの場合は、approved processを通じてreimburseし、operator、authorization、purpose、amount、date、receiptを記録します。

米国では、一定のtradesまたはbusinessesは、related transactionsを含む10,000ドル超のcash receiptsについてForm 8300を提出します。Transactionsを意図的に分割すること自体が、unlawful structuringとなる可能性があります。<sup>[[3]](#references)</sup> その他のjurisdictionsでは異なり、たとえばSpainは独自のstatutory cash-payment restrictionを公開しています。<sup>[[4]](#references)</sup>

## Prepaid and gift cards

“Prepaid”はanonymousを意味しません。Shop、issuer、program manager、funding bank、merchantは、purchase、activation、device、IP、location、spendを相関付ける可能性があります。Reloads、ATM access、international use、higher limits、loss protectionでは、通常registrationが必要です。

US consumer guidanceでは、issuersがlegal verificationのためにidentity dataを要求する可能性があり、verificationに失敗した場合はregistered cardを拒否できると説明されています。<sup>[[5]](#references)</sup> FinCEN rulesは、どのprepaid programsとparticipantsにAML dutiesがあるかを定義しています。<sup>[[6]](#references)</sup> EUでは、narrow anonymous e-money exceptionsがDirective (EU) 2018/843によって縮小されました。Regulation (EU) 2024/1624はframeworkを再び変更しますが、一般的には**10 July 2027**から適用されるため、2026年にすでにoperativeであるかのように説明しないでください。<sup>[[7]](#references)</sup>

Prepaid valueは、識別可能なissuerから合法的に取得され、termsが意図したuseを許可し、そのbenefitがbudgetingまたはprimary payment credentialからの分離である場合にのみ使用してください。Resale marketsや、検証不能な“no-name” cardsを宣伝するbrokersは避けてください。Valueが盗まれていたり、すでにredeemedされていたり、geographically restrictedであったり、seizureの対象となる可能性があります。

## Virtual cards and wallet tokens

Virtual card number（VCN）は通常、実在しverifiedされたaccountの背後で発行されます。Merchant-specificまたはsingle-use numbersは、breachとcross-merchant PAN correlationを減らしますが、issuerからtransactionを隠すものでは**ありません**。Network tokenizationも同様に、card credentialを制約付きtokenへ置き換えます。<sup>[[8]](#references)</sup>

### Merchant-compartmentalized workflow

1. Accurateなidentity、residence、funding dataを使用し、regulated issuerでaccountを開設します。
2. Unique password、利用可能な場合はphishing-resistant MFA、login alerts、offlineに保存したrecovery codesで保護します。
3. Merchant-lockedまたはone-time VCNを生成します。対応している場合は、reasonableなamount/time limitを設定します。
4. Guest checkoutを使用し、**optional**なprofile、loyalty、marketing fieldsのみ省略します。必要な場合は、正確なbilling、delivery、tax dataを提供します。
5. Unrelated identity providersへのsign inを避け、engagement/account browser compartmentとapproved network pathを使用します。
6. Receiptと、VCN-to-purpose mappingをencrypted internal ledgerに保存します。
7. Refund/chargeback window後にnumberをfreezeまたはrevokeし、parent accountでunexpected authorizationsを監視します。

Capital OneとGoogleは、virtual numbersがunderlying accountに紐付いたままであると説明しています。一方、EMVCo/Visaは、tokenizationをpayer anonymityではなくcredential substitutionとdomain restrictionとして説明しています。<sup>[[8]](#references)</sup>

## Delivery, accounts and refunds

Paymentはlinkage graphの1つのedgeにすぎません。

- Unique cardも、personal email、phone、browser profile、IP address、loyalty accountを再利用すれば無効になります。
- Physical deliveryには通常、合法的なrecipientとlocationが必要です。関係のないpersonのaddressを使用したり、residentになりすましたりしないでください。Approved business receiving servicesは、fabricated detailsより安全です。
- Digital goodsでは、account identity、IP、device fingerprint、license activation、downloadsが記録される可能性があります。
- Refundは通常、original railに返されます。Fundsを受け取り、別の場所へforward/refundするよう求める要求は、fraudおよびmoney-mule warningです。
- Merchant descriptors、invoice text、shipping notificationsによって、sensitive purchaseがaccount delegatesに露出する可能性があります。Accessとalertsを意図的に設定してください。

## Authorized red-team purchases

Engagementは、外部からはdiscreetであり、内部ではaccountableであるべきです。

1. Written scope、purpose、spending ceiling、approver、permitted merchants/assets、reimbursement ruleを取得します。
2. Organization-controlled payment accountと、engagementまたはmerchantごとに別のVCNまたはsub-accountを使用します。
3. Providerには正確なbillingおよびregistrant detailsを保持します。Public registration privacyによってexposureを最小化できる場合はありますが、嘘をつく許可ではありません。
4. Operator、approval、purpose、date、amount、counterparty、asset identifier、receiptのencrypted ledgerを維持します。
5. 必要に応じてcounterpartiesをscreenし、provider、sanctions、tax、reporting obligationsに従います。
6. Financeには必要なaccessのみを付与し、operatorsには必要な限定的spending capabilityのみを付与します。
7. Teardown中にpayment credentialsをcloseまたはfreezeし、pending charges/refundsをreconcileし、policyに従ってrecordsを保持します。

Crypto-specific choicesについては、[Cryptocurrency Privacy](cryptocurrency-privacy.md)を参照してください。これらのpurchasesを支えるinfrastructureについては、[Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)を参照してください。

## Verification checklist

- [ ] Desired privacy propertyとobserversが書き出されている。
- [ ] Provider、merchant、jurisdictionのrulesを最近確認した。
- [ ] Identityとsource-of-funds statementsが正確である。
- [ ] Required verificationを妨げることなく、optional merchant dataを最小化している。
- [ ] Funding、device、network、account、delivery、refund linkagesを理解している。
- [ ] Threshold avoidance、prohibited counterparty、mule、stolen credential、third-party identityが関与していない。
- [ ] Required receipts、approvals、tax records、recovery informationがencryptedかつaccess-controlledである。

## References

- [1] [US CFPB — Consumer Paymentおよびその他のPersonal Financial DataのCollection、Use、Monetizationに関するRequest for Information](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — euro areaのconsumersにおけるpayment attitudesに関するStudy（SPACE）2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Form 8300のInstructions](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Cash paymentsのReporting](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Prepaid cardをactivateまたはregisterするためにpersonal informationを求められる理由](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) および [Prepaid cardを拒否される可能性](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Prepaid Accessに関するFinal Rule](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Virtual credit cardsの使用](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
