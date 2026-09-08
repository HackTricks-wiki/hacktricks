# Privacy-Preserving Payment Protocols

{{#include ../banners/hacktricks-training.md}}

Advanced payment systems किसी payer को merchant से छिपा सकते हैं, public ledger से recipient या amount छिपा सकते हैं, या mint को withdrawal को redemption से जोड़ने से रोक सकते हैं। ये अलग-अलग properties हैं। इनमें से कोई भी acquisition, device, network, delivery, accounting, sanctions या endpoint records को समाप्त नहीं करता।

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) प्रत्येक payment family के लिए standardized `Pros`, `Cons`, step-by-step `Procedure`, और `Detection` entry प्रदान करता है। यह page advanced protocols का विस्तार करता है।

{% hint style="danger" %}
केवल lawful funds और counterparties का उपयोग करें। आवश्यक identification, sanctions, tax, source-of-funds checks या transaction reporting से बचने के लिए privacy protocols का उपयोग न करें। Licensing, custody, AML और consumer-protection duties को समझे बिना exchange, mint या transmission service संचालित न करें।
{% endhint %}

## Advanced options की तुलना

| Protocol | Public/merchant से क्या छिपाता है | Trusted या observing party | Maturity/availability |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Outsiders reusable payment code को उसके one-time outputs से link नहीं कर सकते | Public Bitcoin graph बना रहता है; wallet/index server scans देख सकता है | Specification complete; wallet support अलग-अलग है |
| Zcash fully shielded Orchard | Sender, receiver और amount on-chain encrypted होते हैं | Wallet backend/network और acquisition/off-ramp बने रहते हैं | Deployed; shielded support wallet/exchange के अनुसार अलग-अलग है |
| GNU Taler | Merchant को payer identity जानने की आवश्यकता नहीं; merchant income accountable रहती है | Taler exchange/bank funding देखता है; merchant order देखता है | Deployments भौगोलिक रूप से सीमित हैं |
| Federated Chaumian e-cash | Federation को issued notes को internal transfers/redemption से link नहीं करना चाहिए | Guardian quorum reserves की custody रखता है; gateways boundary activity देखते हैं | Emerging community deployments |
| Lightning BOLT 12/route blinding | Receiver/node और route disclosure कम करता है | Endpoints, selected hops, funding chain और wallet services | Support wallet-dependent है |
| Virtual card/token | Merchant को reusable PAN के बजाय constrained credential मिलता है | Issuer/network payer और transaction को बनाए रखते हैं | Mature और widely available |

## Bitcoin Silent Payments (BIP 352)

Silent Payments receiver को एक static payment code publish करने देते हैं, जबकि प्रत्येक sender एक unique Taproot output derive करता है। कोई बाहरी chain observer उन outputs को published code से सीधे link नहीं कर सकता, और किसी interactive address request या on-chain notification output की आवश्यकता नहीं होती। BIP 352 को **Complete** चिह्नित किया गया है, लेकिन इसमें scanning cost आती है और यह उन wallets के साथ incompatible है जिन्होंने इसे implement नहीं किया है।<sup>[[1]](#references)</sup>

### Receiver workflow

1. ऐसा maintained wallet चुनें जो स्पष्ट रूप से BIP 352 receiving support करता हो; feature को wallet के current documentation से verify करें, न कि social-media claim से।
2. Wallet seed और Silent Payment descriptor/key material का backup wallet की documented recovery method से लें। Code publish करने से पहले छोटी testnet/mainnet amount पर discovery का परीक्षण करें।
3. जहाँ wallet BIP 352 labels support करता हो, वहाँ campaigns, invoices या counterparties के लिए अलग **labels** generate करें। Labels linkable addresses publish किए बिना local accounting में सहायता करते हैं।
4. Static Silent Payment code को authenticated channel पर publish करें। यह reusable है, लेकिन कोई impostor अपना code substitute कर सकता है।
5. जब व्यावहारिक हो, local full node के माध्यम से scan करें। Third-party index/scanning server request timing या filter data जान सकता है, भले ही वह spend न कर सके।
6. Discovered UTXOs को labeled रखें और ordinary Bitcoin जैसे ही coin-control rules लागू करें। उन्हें spend या consolidate करने से ownership relationships प्रकट हो सकते हैं।
7. पुष्टि करें कि recovery किसी unbacked-up external index पर निर्भर हुए बिना payments discover करती है।

### Sender workflow

1. पुष्टि करें कि wallet address version पर sending support करता है और receiver के long static code को authenticate करें।
2. Wallet को output construct करने दें; code को manually convert या truncate न करें।
3. Selected inputs की सावधानी से समीक्षा करें। Silent Payments recipient-address privacy बेहतर करते हैं, लेकिन sender inputs अभी भी public graph पर होते हैं।
4. Wallet-supported fee bumping/PSBT behavior का उपयोग करें। BIP 352 में inputs बदलने पर output re-derivation आवश्यक है, और कुछ signing modes unsafe होते हैं।
5. Disputes/accounting के लिए आवश्यक encrypted receipt या proof सुरक्षित रखें।

Silent Payments repeated recipient-address publication की समस्या हल करते हैं। वे amount, transaction timing, sender cluster, acquisition history या बाद के co-spending को नहीं छिपाते।

## Zcash fully shielded payments

Zcash transparent और shielded value pools का support करता है। Orchard shielded transactions zero-knowledge proofs का उपयोग करते हैं, ताकि nodes validity verify कर सकें जबकि transaction details encrypted रहें; Unified Addresses में multiple receiver types हो सकते हैं।<sup>[[2]](#references)</sup> Privacy wallet द्वारा चुने गए actual path पर निर्भर करती है, displayed address के पहले character पर नहीं।

### Shielded workflow

1. ऐसा maintained wallet चुनें जो **shielded-by-default** behavior और current Orchard support को स्पष्ट रूप से बताता हो। Download verify करें और seed का backup/test करें।
2. ZEC को lawfully प्राप्त करें और basis/source record करें। Exchange acquisition और withdrawal को फिर भी जानता है।
3. Wallet द्वारा supported Unified Address पर receive करें, फिर जांचें कि transaction shielded pool में पहुँची है या नहीं। Wallet behavior confirm किए बिना automatic shielding न मानें।
4. **Shielded-to-shielded** transfers को प्राथमिकता दें। Transparent-to-shielded और shielded-to-transparent boundary movements public values/timing expose करते हैं और amount correlation सक्षम कर सकते हैं; Orchard specification के अनुसार non-Orchard address पर spend करने से transaction value प्रकट होती है।<sup>[[3]](#references)</sup>
5. Distinctive exact-amount round trips और immediate boundary crossings से बचें। यह privacy hygiene है, ownership या reporting को obscure करने की अनुमति नहीं।
6. Wallet के supported network-privacy path का उपयोग करें। Shielded cryptography wallet servers या peers से IP/timing को नहीं छिपाती।
7. Internal compliance records रखें और viewing keys का उपयोग केवल deliberate audit/disclosure के लिए करें, उनका scope समझने के बाद।
8. भेजने से पहले recipient wallet/exchange support की पुष्टि करें; forced transparent receiver privacy property बदल देता है।

## GNU Taler: anonymous payer, accountable merchant

GNU Taler traditional currencies, blind signatures और regulated exchange/bank integration का उपयोग करने वाला open electronic-payment protocol है। इसका design customers को merchants से anonymous रखने का लक्ष्य रखता है, जबकि merchants identifiable और taxable रहते हैं।<sup>[[4]](#references)</sup> यह cryptocurrency नहीं है और availability compatible regional exchange, bank, wallet और merchant पर निर्भर करती है।

### जहाँ deployed हो वहाँ user workflow

1. Relevant currency/jurisdiction में operating Taler exchange और merchant की पहचान करें; उनके current terms, fees, KYC और privacy notices पढ़ें।
2. Official wallet install करें और उसका source verify करें। Wallet backup/recovery data को cash की तरह सुरक्षित रखें, क्योंकि wallet value bearer asset हो सकती है।
3. Truthful information का उपयोग करके supported bank/exchange flow से value withdraw करें। Funding institution/exchange withdrawal जान सकता है, भले ही blind signatures direct coin-to-withdrawal link तोड़ दें।
4. Wallet में merchant contract की समीक्षा करें: merchant identity, item/summary, amount, fees, refund और delivery terms।
5. Pay करें और refund, warranty, accounting या tax के लिए आवश्यक receipt data सुरक्षित रखें।
6. यदि merchant unlinkability आवश्यक है, तो optional merchant session/account identifiers reuse न करें।
7. Wallet, network और delivery metadata को threat model में रखें; Taler की payment cryptography shipping address या compromised endpoint को नहीं छिपाती।

Merchant और exchange accountable रहते हैं, और किसी भी component को operate करना regulated payment-service activity हो सकता है।

## Federated Chaumian e-cash

Chaumian e-cash blind signatures का उपयोग करता है, ताकि mint किसी token को sign कर सके और बाद में spend किए गए unblinded token को न देख सके। Fedimint reserve custody और signing को guardian federation में distribute करता है; इसके documentation के अनुसार guardians aggregate reserves/outstanding notes देखते हैं, लेकिन federation के भीतर individual balance या किसने किसे pay किया, यह नहीं देखना चाहिए।<sup>[[5]](#references)</sup>

यह **custodial bearer value** है। पर्याप्त guardian quorum reserves को control करता है; federation failure, dishonest guardians, software bugs या lost client state से loss हो सकता है। Deposits, withdrawals और Lightning gateways visible boundary events हैं और timing/amount को correlate कर सकते हैं।

### Limited-risk workflow

1. केवल उतनी छोटी amount का उपयोग करें जिसे खोने का जोखिम उठा सकें। Public/unknown federations को real-world accountability वाले guardians की तुलना में higher risk मानें।
2. Federation invite को authenticated channel के माध्यम से verify करें और guardian identities, quorum, jurisdiction, fees, recovery और shutdown policy record करें।
3. Maintained compatible wallet install और verify करें, तथा deposit करने से पहले उसकी backup scheme समझें।
4. Lawfully acquired Bitcoin को documented path के माध्यम से deposit करें। Accounting के लिए peg-in record करें और मानें कि उसका timing/amount boundary पर public या ज्ञात है।
5. Federation के भीतर fresh payment requests का उपयोग करें और ऐसे account/chat/delivery identifiers जोड़ने से बचें जो blind signature द्वारा हटाए गए link को फिर बना दें।
6. Lightning payments के लिए gateway को invoices और boundary timing के अतिरिक्त observer के रूप में मानें।
7. Policy के अनुसार redeem/withdraw करें और अपेक्षा रखें कि distinctive amount तथा immediate timing किसी deposit या external payment से correlate हो सकते हैं।
8. Tax/source/authorization records privately रखें; guardians या gateways से activity को गलत तरीके से बताने के लिए न कहें।

Federated e-cash को trustless, self-custodial या guaranteed anonymous के रूप में वर्णित न करें।

## BOLT 12 offers और route blinding

BOLT 12 offers stable on-chain address publish किए बिना reusable हो सकते हैं और blinded paths का उपयोग कर सकते हैं, ताकि payer को receiver की clear node identity/path जानने की आवश्यकता न हो। यह Lightning के existing onion routing का पूरक है, replacement नहीं।

उपयोग से पहले:

1. पुष्टि करें कि sender और receiver wallets समान current BOLT 12 features support करते हैं; generic “Lightning” branding से support का अनुमान न लगाएँ।
2. Offer को out of band authenticate करें और amount, issuer/description तथा recurrence rules जांचें।
3. Offer से generated fresh invoice/payment context का उपयोग करें।
4. Node aliases, public contact information और stable network endpoints को न्यूनतम रखें।
5. मानें कि sender/receiver, first/last hop, wallet service, channel graph और on-chain funding/closure अभी भी relationship के कुछ हिस्से disclose करते हैं।

## Public disclosure के बिना auditability

Privacy और audit साथ-साथ रह सकते हैं:

- Labels, invoices, authorization, cost basis और ownership mapping को public protocol के बाहर encrypted रखें।
- जहाँ protocol एक key प्रदान करता हो, वहाँ **view/audit key** को spending key से अलग रखें; पहले sample wallet पर इसके exact disclosure का परीक्षण करें।
- Auditor को seed या unrestricted spending credential के बजाय minimum scoped proof दें।
- Transaction के समय software version, protocol/pool, transaction ID या proof, counterparty purpose और exchange-rate source record करें।
- Permanent unencrypted identity graph जमा करने के बजाय retention और deletion परिभाषित करें।

## Selection checklist

- [ ] Hidden field और observer को precisely नामित किया गया है।
- [ ] Wallet/protocol support को transaction date के अनुसार verify किया गया है।
- [ ] Acquisition, network, node/RPC, counterparty, delivery और later-spend links documented हैं।
- [ ] Custody, recovery, liquidity, issuer/federation solvency और refund risks स्वीकार किए गए हैं।
- [ ] आवश्यक identity, tax, sanctions, source और organizational records accurate बने हुए हैं।
- [ ] Recovery और audit proof सहित छोटा end-to-end test सफल रहा।

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
