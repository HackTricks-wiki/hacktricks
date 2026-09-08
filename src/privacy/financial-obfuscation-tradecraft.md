# Financial Obfuscation Tradecraft

{{#include ../banners/hacktricks-training.md}}

Payment privacy, payment-brand की समस्या नहीं बल्कि attribution की समस्या है। किसी operation में evidence तब छूटता है जब value प्राप्त की जाती है, स्थानांतरित की जाती है, बदली जाती है, खर्च की जाती है और वितरित की जाती है। एक public-chain address pseudonymous हो सकता है, जबकि exchange, card issuer, merchant, mobile device या shipping camera इसके पीछे मौजूद व्यक्ति की पहचान कर सकता है।

यह पेज cybercrime और state-linked operations में उपयोग किए जाने वाले financial-obfuscation patterns समझाता है, ताकि defenders उन्हें पहचान सकें। यह **laundering, sanctions-evasion, false-identity या KYC-bypass procedure** प्रदान **नहीं** करता।

## End-to-end value graph
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
एक actor किसी भी observer को दोनों छोर देखने से रोकने का प्रयास करता है। Investigators इसका उलटा करते हैं: हर boundary पर records सुरक्षित रखते हैं, समय/value/fees को normalize करते हैं और उस **पुनः-अभिसरण बिंदु** की पहचान करते हैं जहाँ अलग-अलग personas एक ही facilitator, device, account, merchant या destination का दोबारा उपयोग करते हैं।

## Instruments और उनके वास्तविक observers

| Instrument | Merchant/public से छिपा हुआ | फिर भी किसे दिखाई देता है |
|---|---|---|
| Issuer virtual card/token | underlying card number | issuer, network/token provider, wallet, merchant account और delivery systems |
| Prepaid/gift value | सामान्य purchase के समय कभी-कभी legal name | retailer/payment rail, activation/redemption service, cameras, device और delivery |
| Cash | public ledger और remote issuer | counterparties, cameras, जहाँ लागू हो वहाँ withdrawal/serial controls, physical search |
| Bitcoin/new address | direct legal name | हर blockchain observer; wallet/network peers; acquisition/off-ramp services |
| CoinJoin/PayJoin | simple common-input/payment heuristics | public transaction, coordinator/peer/network metadata और बाद का spending behavior |
| Privacy coin | protocol के अनुसार public sender/receiver/amount | acquisition/off-ramp, wallet endpoint, network observer और counterparty |
| Centralized mixer | direct deposit-to-withdraw link | mixer operator/logs, blockchain entry/exit sets और counterparties |
| Cross-chain bridge/swap | एक chain पर continuity | दोनों chains, bridge/swap service, timing/value और liquidity constraints |
| OTC/P2P broker | कुछ मामलों में direct exchange account | broker, communications, bank/cash movement, counterparties और devices |

## Cards, prepaid value, nominees और mules

### Virtual और masked cards

Issuer merchant-locked या disposable card number बना सकता है। इससे merchant exposure और अलग-अलग merchants पर number reuse कम होता है। फिर भी issuer इसे customer, funding account, device, IP और transaction से map करता है। Billing descriptors, merchant account, shipping address और browser data linkable बने रहते हैं।

“No-name” card marketing anonymous settlement का संकेत नहीं है। Regulated issuers और distributors identity checks कर सकते हैं, records रख सकते हैं, geography/amount limits लगा सकते हैं और legal process का जवाब दे सकते हैं। Stolen identity के माध्यम से प्राप्त card identity theft जोड़ता है; यह issuer/device/merchant telemetry को समाप्त नहीं करता।

### Prepaid और gift value

Prepaid cards और gift codes बाद के redemption को original payment instrument से अलग करते हैं, लेकिन एक numbered object बनाते हैं जिसमें purchase, activation, balance-query और redemption events होते हैं। महत्वपूर्ण patterns में bulk purchases, controls से ठीक नीचे बार-बार की गई denomination, दूर स्थित स्थान पर तेज redemption, एक device द्वारा कई balances की जाँच, या कई cards का एक merchant/account पर converging शामिल हैं।

### Nominees, money mules और merchant fronts

Nominee या mule एक account और legal identity उपलब्ध कराता है जो operator और service के बीच स्थित होता है। Networks recruiters, account holders, payment processors, shell merchants और cash-out brokers की layers बना सकते हैं। इससे दूरी तो बनती है, लेकिन प्रत्येक participant communications, fees, behavioral inconsistency और संभावित cooperating witness जोड़ता है। Front companies incorporation, tax, banking, director, invoice, hosting और shipment records जोड़ती हैं।

Defenders को shared devices/IPs, beneficiary reuse, geolocation contradictions, account history से असंगत velocity, circular transfers, कई असंबंधित senders का एक जगह converging होना और तुरंत onward movement की जाँच करनी चाहिए। यह न मानें कि named account holder ही controlling actor है; उन्हें role determination की आवश्यकता वाले node के रूप में देखें।

## Public-chain transaction-obfuscation patterns

### Address rotation और coin control

हर receipt के लिए नया address बनाने से trivial address reuse रुकता है, लेकिन common inputs, change detection, exact value/time और बाद में consolidation के माध्यम से transactions अभी भी ownership से जुड़ सकते हैं। **Coin control** wallet को यह चुनने देता है कि किन outputs को spend करना है और किन compartments को जोड़ने से बचना है। इससे hygiene बेहतर होती है; यह पहले से public link को समाप्त नहीं कर सकता।

### Peel chains

Peel chain में large balance को बार-बार spend किया जाता है, जिसमें छोटी amount बाहर भेजी जाती है और शेष राशि नए address में वापस भेजी जाती है:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
पता हर चरण पर बदलता है, लेकिन value continuity, cadence और transaction structure अक्सर एक पहचानने योग्य chain बनाते हैं। Legitimate exchange hot wallets भी इसी तरह व्यवहार कर सकते हैं, इसलिए attribution के लिए service/context evidence आवश्यक है। DOJ ने DPRK-linked forfeiture cases में peel-chain analysis का उपयोग किया है।<sup>[[1]](#references)</sup>

### Structuring और fan-out/fan-in

- **Fan-out:** एक source कई addresses में विभाजित होता है, ताकि investigative workload बढ़े या parallel conversion की तैयारी हो।
- **Fan-in:** कई sources एक collector में consolidate होते हैं, जिससे common control या किसी service का संकेत मिलता है।
- **Structuring:** बार-बार किए गए छोटे transfers review thresholds से बचने या ordinary volume में घुलने का प्रयास करते हैं।
- **Commingling:** illicit और unrelated funds एक ही wallets, pools या services में साझा होते हैं, जिससे सरल proportional claims असुरक्षित हो जाते हैं।

Graph shape एक lead है, proof नहीं। Analysts को fees, UTXO/account model, service behavior और change conventions को ध्यान में रखना चाहिए।

### CoinJoin और PayJoin

एक typical CoinJoin में कई participants inputs contribute करते हैं और एक collaborative transaction में outputs प्राप्त करते हैं, अक्सर equal output denominations के साथ। इससे यह assumption टूटती है कि किसी transaction में हर input और output का एक ही owner होता है। Anonymity set participant count और बाद के behavior से सीमित होता है: unequal change, toxic change, consolidation या किसी known service से crossing links को फिर से उजागर कर सकता है।

PayJoin एक ordinary payment को इस तरह modify करता है कि payer और payee दोनों inputs contribute करें, जिससे उस transaction के लिए common-input ownership heuristic सीधे invalid हो जाती है। यह मुख्य रूप से payment privacy protocol है, bulk laundering service नहीं। Detection में सभी inputs को co-owned घोषित करने से बचना चाहिए और false cluster थोपने के बजाय uncertainty व्यक्त करनी चाहिए।

### Centralized mixers और tumblers

एक centralized mixer deposits स्वीकार करता है और बाद में pooled reserve से अलग coins का भुगतान करता है, अक्सर fees और delays के बाद। इसकी privacy pool size, withdrawal policy, logs, operator honesty और seizure के प्रतिरोध पर निर्भर करती है। Entry और exit timing/value analysis, deposit addresses, service wallet clustering और records संभावित set को सीमित कर सकते हैं। Operators funds चुरा सकते हैं या complete mapping बनाए रख सकते हैं।

Legal exposure substantial और jurisdiction-specific है। ChipMixer, Samourai Wallet और Tornado Cash developers/operators के विरुद्ध DOJ cases तथा बदलती sanctions litigation दिखाती है कि protocol, custody, control और money-transmission facts महत्वपूर्ण होते हैं; “decentralized” जैसा label legal conclusion नहीं है।<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps और bridges

Chain hopping किसी asset को convert करता है या उसे किसी bridge के माध्यम से स्थानांतरित करता है, जिससे एक-ledger query बाधित होती है, लेकिन economic continuity समाप्त नहीं होती:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
विश्लेषक bridge contracts/service deposit addresses, transaction order, time window, exchange rate, fees, liquidity और unique amount का correlation करते हैं। बार-बार किए गए swaps ambiguity बढ़ा सकते हैं, जबकि provider/API/wallet telemetry भी जुड़ जाता है। FATF विशेष रूप से chain hopping, mixers, peer-to-peer services और anonymity-enhanced currencies को suspicious context के साथ संयुक्त होने पर risk indicators के रूप में पहचानता है।<sup>[[3]](#references)</sup>

### NFTs, gambling और merchant purchases

Self-dealing या collusive NFT trades funds को apparent sale narrative दे सकते हैं; gambling deposits को withdrawals में बदल सकता है; goods digital value को resalable inventory में परिवर्तित कर सकते हैं। ये paths marketplace accounts, creator/royalty links, wash-trading graphs, odds/play history, device logs, delivery और resale evidence छोड़ते हैं। कोई loss या fee इस बात का proof नहीं है कि provenance गायब हो गया।

## Privacy-preserving cryptocurrencies

Privacy protocols तकनीकी रूप से अलग-अलग होते हैं:

- **Monero** one-time addresses, ring signatures और confidential amounts का उपयोग करता है, जिससे public sender/receiver/amount visibility कम हो जाती है। Network observation, wallet compromise, acquisition/off-ramp और counterparty records उन on-chain protections के बाहर बने रहते हैं।
- **Zcash shielded pools** shielded transactions का उपयोग किए जाने पर sender, receiver और amount को छिपा सकते हैं; transparent addresses और pools के बीच transitions public रहते हैं, और usage patterns effective anonymity set को प्रभावित करते हैं।
- **Bitcoin** default रूप से transparent है। New addresses, CoinJoin, PayJoin और Lightning विशेष linkage assumptions को बदलते हैं, लेकिन सभी layers को private नहीं बनाते।

Privacy technology के legitimate safety और commercial uses हैं। Investigative perspective से, जब ledger कम information प्रदान करता है, तो endpoint, service, network और human evidence अधिक महत्वपूर्ण हो जाते हैं। केवल privacy-preserving protocol चुनने से criminality का अनुमान कभी न लगाएं।

## DPRK multi-layer case model

Public DOJ allegations और forfeiture actions एक composed process का वर्णन करते हैं, न कि किसी एक trick का:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workers ने remote employment प्राप्त करने के लिए fictitious/stolen identity material और VPNs का उपयोग किया;
2. employers ने cryptocurrency, जिसमें stablecoins भी शामिल हैं, का payment किया;
3. funds छोटी amounts में move हुए, chains या tokens को पार किया, NFTs खरीदे या commingled किए गए;
4. अन्य stolen funds mixers में पहुंचे;
5. OTC traders और front companies ने value को fiat payments या goods में परिवर्तित किया;
6. repeated facilitators, accounts और blockchain paths ने investigators को layers को फिर से जोड़ने की अनुमति दी।

Treasury ने बताया कि Lazarus ने Axie Infinity/Ronin theft के एक हिस्से को process करने के लिए Blender.io का उपयोग किया, जबकि FBI ने addresses publish किए हैं और bridges, exchanges, RPC operators तथा analytics firms से बाद के TraderTraitor thefts से linked funds को block करने का आग्रह किया है।<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

इससे मिलने वाला lesson bidirectional है: state actors ordinary commercial/criminal services का उपयोग करते हैं, और public blockchains defenders को value follow करने देते हैं, भले ही names शुरुआत में unknown हों।

## Detection workflow

1. **Raw transaction identifiers और records को preserve करें।** Screenshots और rounded fiat values insufficient हैं।
2. **Assets और time को normalize करें।** Chain, token contract, units, block time, service time zone, fees और exchange-rate source record करें।
3. **Evidence confidence को label करें।** Service-published address, deterministic contract event, clustering heuristic और external intelligence के बीच distinction रखें।
4. **दोनों directions trace करें।** Funding origin, immediate dispersal, reconvergence, bridge exits, service deposits और spend/delivery खोजें।
5. **Off-chain evidence को join करें।** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping और communication records अक्सर ambiguity दूर कर देते हैं।
6. **Alternative explanations test करें।** Exchanges, custodians, payroll और privacy protocols common beneficial ownership के बिना fan-in/out या co-spends उत्पन्न कर सकते हैं।
7. **Prematurely close करने के बजाय monitor करें।** कोई dormant output बाद में attributable हो सकता है, जब वह किसी service तक पहुंचे।
8. **Counsel के साथ current sanctions/AML obligations लागू करें।** Rules और designations बदलते रहते हैं; historical association current legal analysis का substitute नहीं है।

## Safe red-team procurement model

किसी authorized team को target SOC द्वारा अपने hosting payment को recognize न किए जाने की आवश्यकता हो सकती है, जबकि engagement controller accountability बनाए रखता है:

- engagement-specific organization card या documented corporate wallet का उपयोग करें;
- billing, tax और provider records को accurate रखें;
- operator को procurement duties से अलग रखें और attribution map तक access सीमित करें;
- mule, false identity, stolen card, sanctions workaround या unlicensed exchanger का कभी उपयोग न करें;
- asset, amount, owner, service, date, refund path और teardown evidence record करें;
- exercise के बाद relevant payment/provider indicators controller को disclose करें।

इससे **exercise participant के प्रति blindness** उत्पन्न होती है, law, provider या governance के प्रति blindness नहीं।

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework (peel-chain example और DPRK investigations)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer takedown](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Forfeiture complaint concerning $7.74 million allegedly laundered for DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions और Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea responsible for the 2025 Bybit theft](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Application of regulations to virtual-currency users, administrators and exchangers](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
