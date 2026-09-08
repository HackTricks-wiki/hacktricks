# Anonymous Payment Technique Catalog

यह catalog साधारण cash से लेकर blind-signature e-cash और public-chain obfuscation तक payment **families** को कवर करता है। “Anonymous” का अर्थ हमेशा किसी नामित observer से anonymous होना है। Merchant, issuer, mint, exchange, blockchain analyst, network provider, employer और physical observer अलग-अलग facts देखते हैं।

नीचे दी गई procedures lawful funds, truthful accounts और authorized procurement के लिए हैं। जिन techniques का cited cases में उद्देश्य laundering, sanctions evasion या identity fraud था, उन्हें समझाया और detect किया गया है, लेकिन उनकी procedure synthetic forensic exercise है—crime करने के instructions नहीं।

## Coverage matrix

| Family | Main privacy property | Main observer/trust | Treatment |
|---|---|---|---|
| Cash और cash equivalents | remote payment-network record नहीं | recipient और physical environment | lawful workflow |
| Prepaid/gift/voucher value | primary card से redemption अलग करता है | seller, issuer और redemption service | lawful workflow, jurisdiction अलग हो सकता है |
| Virtual/tokenized card | reusable PAN छिपाता या merchants को अलग करता है | issuer/network/wallet फिर भी payer की पहचान करते हैं | lawful workflow |
| Payment app/intermediary | merchant को alias/intermediary दिख सकता है | app identity/device/transaction collect करता है | comparison baseline |
| Bitcoin hygiene/Silent Payments | pseudonyms और recipient unlinkability | public graph और wallet/network boundary | deployable |
| PayJoin/CoinJoin | common ownership/linkage heuristics कमजोर करता है | participants/coordinator/network/public graph | जहाँ supported हो deployable; legal review |
| Lightning/BOLT 12 | off-chain routing और receiver-path reduction | endpoints, hops, services और channel graph | जहाँ supported हो deployable |
| Monero/Zcash/MWEB | protocol-level on-chain confidentiality | acquisition, endpoint, network और boundary फिर भी रहते हैं | जहाँ lawful/supported हो deployable |
| Ethereum ZK application | specified statement/action link छिपाता है | public inputs, RPC, relayer और app | application-specific |
| Cashu/Fedimint/Taler | blind-signature payer privacy | mint/federation/exchange custody और boundaries | emerging/deployment-specific |
| Stablecoins | सुविधाजनक digital settlement | transparent chain और issuer freeze/control | anonymous baseline नहीं |
| Swaps/bridges/DEX | assets/chain के बीच value ले जाता है | दोनों graphs, contracts और providers | forensic mechanics; केवल ordinary lawful swaps |
| Mixers/peel/structuring | graph ambiguity/work बढ़ाता है | entry/exit graph और service records | केवल synthetic detection exercise |
| Nominees/mules/OTC/fronts | human/business intermediaries जोड़ता है | facilitators, banks, communications | केवल criminal-abuse analysis |
| Reusable/stealth payment addresses | हर payment के लिए fresh recipient address | public announcement/notification और wallet boundaries | जहाँ supported हो deployable |
| Confidential sidechain/state channel | amount/asset या intermediate updates छिपाता है | peers, bridge/federation और lifecycle settlement | protocol-specific |
| Carrier/open-banking/platform billing | merchant से primary card छिपाता है | carrier, bank/PISP या platform customer की पहचान करते हैं | ordinary identified payment |
| Mutual credit/net settlement | external settlement records कम करता है | private ledger operator के पास पूरा mapping | केवल identified participants |

## Cash

**Mechanics:** physical bearer value online issuer authorization या public ledger के बिना हाथ बदलती है।

**Pros:** merchant को bank/card identity जानने की आवश्यकता नहीं; remote transaction graph नहीं; व्यापक रूप से समझने योग्य और final।

**Cons:** केवल face-to-face; theft/loss; change/receipt/serial या reporting controls; withdrawal, cameras, witnesses और location फिर भी payer को link कर सकते हैं।

**Procedure:** (1) पुष्टि करें कि cash legal/accepted है और amount/reporting rule क्या है; (2) इसे lawful तरीके से withdraw या receive करें और private accounting records रखें; (3) अनावश्यक loyalty/account identifiers के बिना ordinary merchant को pay करें; (4) केवल आवश्यक receipt लें; (5) यदि purchase को shipping/account data की जरूरत न हो तो उसे न दें; (6) legitimate business purpose internally record करें।

**Detection:** लागू policy के तहत till/receipt/inventory, cameras और access logs का reconciliation करें; unusual cash refunding या बार-बार control threshold से थोड़ा कम amounts की जाँच करें, लेकिन ordinary cash use को अकेले suspicious न मानें।

## Money order, postal order, cashier instrument और cash on delivery

**Mechanics:** regulated issuer cash/account funds को named recipient के payable numbered instrument में बदलता है; COD delivery तक collection टालता है।

**Pros:** recipient को payer का primary bank/card number नहीं मिल सकता; cash को दूर भेजे बिना उपयोगी; स्पष्ट receipt।

**Cons:** issuer/retailer आवश्यक purchase/identity data रखता है; serial tracking; recipient/delivery address; loss/fraud और regional restrictions; सामान्यतः anonymous नहीं।

**Procedure:** (1) issuer rules, limits, identification और recipient acceptance जाँचें; (2) truthful information और lawful funds से खरीदें; (3) payee/amount तुरंत भरें; (4) serial/receipt सुरक्षित रखें; (5) value के अनुसार tracked delivery लें; (6) redemption/refund का reconciliation करें।

**Detection:** issuer purchase/redemption record, instrument serial, retailer/camera, shipping और recipient account देखें; alteration, duplicate serials और geographically inconsistent rapid redemption को flag करें।

## Open-loop prepaid card

**Mechanics:** network-branded stored-value credential primary credit account के बजाय prepaid balance के विरुद्ध authorize होता है।

**Pros:** merchant exposure और loss सीमित करता है; main PAN से merchant को अलग करता है; accepted होने पर online उपयोगी।

**Cons:** purchase/activation/reload/registration और device records; KYC और limits अलग-अलग; billing-address failures; cash-out/refund restrictions; “no name” का अर्थ issuer record न होना नहीं है।

**Procedure:** (1) current issuer identity, fees, KYC, geography और online/recurring support verify करें; (2) lawful funds से authorized seller के माध्यम से लें; (3) आवश्यक truthful data register करें; (4) एक compartment/purpose के लिए उपयोग करें; (5) loads structure या residency fabricate न करें; (6) purchase/expense evidence रखें और issuer terms के अनुसार close/dispose करें।

**Detection:** seller/activation, funding, device/IP, merchant authorization, balance checks और redemption/refund को जोड़ें। Prepaid label से अधिक patterns महत्वपूर्ण हैं।

## Closed-loop gift card, voucher और transferable service credit

**Mechanics:** numbered value केवल एक merchant/service या ecosystem में redeem होती है। Airtime/game/store credits इसके variants हैं।

**Pros:** recipient merchant को केवल code/balance दिख सकता है; सीमित blast radius; gifting और budget separation आसान।

**Cons:** seller और service purchase/activation/redemption log करते हैं; account/device/delivery फिर भी link करते हैं; scams, resale discounts और expiry/region limits; कमजोर refund rights।

**Procedure:** (1) केवल authorized channels से खरीदें; (2) code value record करें लेकिन secret expose न करें; (3) अनावश्यक identifying loyalty account से attach न करें; (4) अलग legitimate merchant account/context में redeem करें; (5) accepted होने तक receipt रखें; (6) unsolicited “tax/support/ransom” demand के लिए codes कभी न खरीदें।

**Detection:** code issuance/redemption time, device/account convergence, bulk/threshold-pattern purchase, एक device से कई balances check करना और दूर-दूर rapid redemption देखें।

## Cryptocurrency-funded card या gift-code broker

**Mechanics:** intermediary cryptocurrency स्वीकार करके card, voucher या merchant code जारी करता है। यह cross-rail conversion है: merchant को ordinary card/gift value दिखती है, जबकि broker on-chain deposit को issuance और delivery से जोड़ता है।

**Pros:** merchant को funding wallet नहीं मिलता; crypto स्वीकार न करने वाले legitimate merchants के लिए उपयोगी; bounded stored value।

**Cons:** broker/issuer से anonymous नहीं; KYC, sanctions, exchange और card-program rules; public deposit graph; account/device/email और code redemption दोनों sides को फिर जोड़ते हैं; scam/insolvency risk।

**Procedure:** (1) legal entity, card issuer, supported jurisdiction, KYC, fees और refund policy verify करें; (2) केवल lawful documented funds लें; (3) सबसे छोटी denomination test करें; (4) purchase से पहले network/merchant restrictions देखें; (5) accounting के लिए blockchain transaction और broker receipt दोनों रखें; (6) identity fraud, sanctions bypass या “untraceable” cash-out का वादा करने वाले broker का उपयोग न करें।

**Detection:** broker deposit addresses, unique amount/time, account/device और issued-card authorization या gift-code redemption correlate करें; issuer और broker records public chain को merchant से जोड़ते हैं।

## Virtual या merchant-locked card

**Mechanics:** issuer generated PAN/token को real account से map करता है और अक्सर merchant, amount या expiration restrict करता है।

**Pros:** reusable PAN disclosure रोकता है; merchant compartmentation; spend limits और easy revocation; mature fraud control।

**Cons:** issuer payer, funding, merchant, device/IP और time जानता है; merchant account/delivery देखता है; कुछ refunds/recurring charges fail होते हैं; anonymous नहीं।

**Procedure:** (1) regulated issuer का official feature उपयोग करें; (2) एक merchant/engagement के लिए card बनाएँ; (3) सबसे छोटा उपयोगी limit और expiry set करें; (4) आवश्यक होने पर accurate billing दें; (5) statement descriptor/refund behavior verify करें; (6) final settlement के बाद freeze/delete करें और audit evidence रखें।

**Detection:** issuer token-to-account mapping, merchant authorization, device और delivery देखें। Defenders merchant-specific reuse, velocity और account takeover signals उपयोग करते हैं।

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization PAN के स्थान पर constrained credential रखती है, जो device, merchant या payment scenario से bound हो सकती है।<sup>[[1]](#references)</sup>

**Pros:** merchant को reusable PAN नहीं मिलता; device cryptography/dynamic data cloning कम करते हैं; card replace किए बिना revoke किया जा सकता है।

**Cons:** issuer, token service, wallet platform और network mappings/transactions रखते हैं; device/platform account और location payer की पहचान कर सकते हैं।

**Procedure:** (1) legitimate card को official wallet में enroll करें; (2) strong authentication से platform account/device सुरक्षित करें; (3) purchase पर device token/last digits verify करें; (4) जहाँ supported हो unnecessary location/analytics बंद करें; (5) lost device/token तुरंत disable करें; (6) issuer और wallet records review करें।

**Detection:** token requestor/device cryptogram और issuer mapping, wallet/account telemetry, merchant terminal और physical evidence देखें।

## Payment app, marketplace wallet और centralized intermediary

**Mechanics:** service accounts रखती है और transfers internally या bank/card rails पर करती है; merchant को alias दिख सकता है, जबकि service दोनों parties को देखती है।

**Pros:** सुविधा, dispute/refund mechanisms, recipient को bank/card details आवश्यक रूप से नहीं दिखते।

**Cons:** centralized identity/social/transaction/device graph; freezes और legal process; counterparties profile expose कर सकते हैं; data use payment necessity से अधिक हो सकता है।<sup>[[2]](#references)</sup>

**Procedure:** (1) identity, privacy, retention और buyer-protection terms पढ़ें; (2) optional profile/contact synchronization कम करें; (3) terms अनुमति दें तभी अलग truthful account उपयोग करें; (4) MFA/alerts enable करें; (5) recipient और memo/profile privacy verify करें; (6) records export करें और unused links बंद करें।

**Detection:** provider account, device/IP, contact graph, funding/withdrawal, memo और merchant records देखें। Alias counterparty से pseudonymity है, platform से anonymity नहीं।

## Bank transfer, ACH, wire और instant-account payment

**Mechanics:** regulated institutions identified accounts के बीच value transfer करती हैं और required payment data exchange करती हैं।

**Pros:** तेज, accountable, सीमित मामलों में reversible, strong records; virtual account numbers merchant disclosure कम कर सकते हैं।

**Cons:** banks/processors दोनों sides जानते हैं; statements और references; anonymous नहीं; cross-border तथा Travel Rule/AML data।

**Procedure:** केवल तब उपयोग करें जब accountability स्वीकार्य हो: beneficiary को independently verify करें, optional memo data कम रखें, उपलब्ध होने पर bank-provided virtual account/reference लें, alerts enable करें, invoice रखें और reconcile करें।

**Detection:** deterministic bank/payment records, beneficiary/account ownership, device/session और fraud controls। यह anonymity technique नहीं, baseline है।

## Account और merchant compartmentation

**Mechanics:** अलग lawful identities/accounts, email aliases, cards और delivery contexts unrelated merchants को activity trivially join करने से रोकते हैं, जबकि issuer/controller mapping रखता है।

**Pros:** breach और cross-merchant linkage कम; audit आसान; regulated payments के साथ compatible।

**Cons:** provider compartments map करता है; recovery phone/device/IP और shipping उन्हें फिर जोड़ सकते हैं; policy multiple accounts मना कर सकती है।

**Procedure:** (1) एक purpose तय करें; (2) terms-compliant aliases/subaccounts ही बनाएँ; (3) merchant-specific token/card लें; (4) cross-account contact/ad personalization बंद करें; (5) encrypted controller ledger रखें; (6) refunds/retention needs खत्म होने पर identifiers retire करें।

**Detection:** providers recovery, device, funding और IP join करते हैं; merchants delivery, browser और account behavior जोड़ते हैं। Legitimate compartmentation को synthetic identity fraud से अलग करें।

## Controlled red-team procurement

**Mechanics:** SOC purchase से blind रहता है, जबकि exercise controller legal entity, operator और infrastructure mapping रखता है।

**Pros:** realistic detection exercise; personal exposure नहीं; immediate deconfliction और audit।

**Cons:** organization/provider से anonymous नहीं; governance overhead; controller ledger mishandle होने पर leaks।

**Procedure:** (1) engagement-specific organization card/wallet/budget दें; (2) purchaser/operator roles अलग रखें; (3) asset, amount, service, purpose और kill date record करें; (4) attribution mapping limited controller access में रखें; (5) false identity/mule/stolen funds कभी न उपयोग करें; (6) closeout पर indicators और refunds reveal/reconcile करें।

**Detection:** controller provider invoice और asset map करता है; SOC cardholder data के बजाय domain, certificate, hosting और traffic से independent discovery test करता है।

## Bitcoin address hygiene और coin control

**Mechanics:** fresh receive addresses, local labeling और selective UTXO spending public ledger पर address reuse तथा accidental compartment merging कम करते हैं।

**Pros:** व्यापक support; self-custodial; सबसे सरल public linkage से बचाव।

**Cons:** सभी transactions/amounts public रहते हैं; common-input/change/timing और later consolidation activity link कर सकते हैं; acquisition/RPC/network records रहते हैं।

**Procedure:** (1) maintained wallet install/verify करें; (2) seed backup और recovery test करें; (3) हर invoice के लिए नया address लें; (4) source/purpose locally label करें; (5) contexts merge न करने के लिए coin control लें; (6) local node या privacy-aware connection prefer करें; (7) change/fees preview करें और lawful accounting रखें।<sup>[[3]](#references)</sup>

**Detection:** address graph, uncertainty सहित common-input/change heuristics, exact amount/time, consolidation, service deposits, node/RPC broadcast timing और off-chain records देखें।

## Bitcoin Silent Payments

**Mechanics:** BIP 352 receiver को static code publish करने देता है, जबकि senders ECDH के माध्यम से unique Taproot outputs derive करते हैं; बाहरी observers outputs को सीधे code से link नहीं कर सकते।<sup>[[4]](#references)</sup>

**Pros:** address reuse के बिना reusable public identifier; interactive address request या notification output नहीं; Taproot outputs में blend होता है।

**Cons:** receiver scanning cost; wallet support अलग-अलग; amount/sender graph और spending public रहते हैं; index server scans देख सकता है।

**Procedure:** (1) current BIP 352 wallet चुनें; (2) descriptor और scanning recovery backup/test करें; (3) जहाँ supported हो labeled code generate करें; (4) published code authenticate करें; (5) sender inputs review करके छोटा test भेजे; (6) receiver preferably own node से scan करे; (7) received UTXOs अलग रखें।

**Detection:** design के कारण output अकेले से reliable identification नहीं; analysts sender inputs, amount/time, later spending, wallet/network/index और counterparty records उपयोग करते हैं।

## PayJoin

**Mechanics:** payer और payee एक payment transaction में inputs देते हैं, जिससे यह assumption टूटती है कि सभी inputs एक owner के हैं।<sup>[[5]](#references)</sup>

**Pros:** बेहतर privacy वाला ordinary payment; common heuristic कमजोर करके wider graph को लाभ; equal-output crowd आवश्यक नहीं।

**Cons:** interactive/support requirement; receiver endpoint availability; amount और final transaction public; implementation और fallback metadata।

**Procedure:** (1) दोनों maintained wallets का same PayJoin version support confirm करें; (2) invoice/endpoint authenticate करें; (3) wallet के PayJoin-enabled payment URI से शुरू करें; (4) final amount/fee inspect करें और केवल expected inputs sign करें; (5) manual transaction surgery न करें; (6) broadcast और receipt verify करें; (7) negotiation fail होने पर fallback record करें।

**Detection:** blockchain analysts common-input clustering force न करें; endpoint/provider negotiation log कर सकते हैं; केवल transaction shape के बजाय wallet/network और later-spend evidence उपयोग करें।

## CoinJoin

**Mechanics:** कई participants अनेक inputs/outputs वाली transaction collaboratively बनाते हैं, अक्सर equal denominations के साथ, जिससे input-output correspondence अस्पष्ट होता है।

**Pros:** बड़ा on-chain ambiguity set; self-custodial designs; measurable round structure।

**Cons:** coordinator/peer/network metadata; fees/liquidity; identifiable transaction shape; toxic change और later consolidation gains नष्ट करते हैं; legal/provider availability अलग-अलग।

**Procedure:** (1) current wallet/coordinator availability और legality verify करें; (2) official wallet install और backup करें; (3) केवल lawful UTXOs लें; (4) denomination, fee और coordinator model समझें; (5) change और mixed outputs label/separate रखें; (6) उन्हें कभी consolidate न करें; (7) officially supported network routing लें और accounting रखें।

**Detection:** collaborative structure identify करें लेकिन crime assume न करें; possible mappings/anonymity set calculate करें, फिर change/consolidation, service boundaries और network/coordinator records देखें।

## Lightning Network

**Mechanics:** HTLC payments onion-routed channels से गुजरते हैं; अधिकांश payment details chain पर publish नहीं होतीं, जबकि funding/closing और public channel information रहती है।

**Pros:** तेज, low fee; intermediaries सामान्यतः adjacent hops देखते हैं; routine payment details off-chain रहती हैं।

**Cons:** sender/receiver और first/last hop अधिक जानते हैं; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets users की पहचान करते हैं।

**Procedure:** (1) self-custodial या custodial विकल्प समझकर चुनें; (2) wallet/seed/channel recovery verify करें; (3) exact payment का invoice लें; (4) tradeoffs पढ़ने के बाद private channels/LSP features prefer करें; (5) आवश्यकता पर supported Tor से node IP protect करें; (6) identifying invoices reuse न करें; (7) channel और payment accounting रखें।<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs, channel graph/probes, payment failure/timing और on-chain funding/closure देखें; public transaction न होना records न होने के बराबर नहीं।

## BOLT 12 offers और route blinding

**Mechanics:** reusable offer fresh invoices बनाता है और blinded paths advertise कर सकता है, जिससे payer को receiver का clear node/path जानना आवश्यक नहीं।

**Pros:** receiver privacy; static invoice के बिना reusable donation/payment endpoint; Lightning onion routing के साथ integration।

**Cons:** wallet support अलग-अलग; endpoints, selected hops और funding फिर भी रहते हैं; public contact या network endpoint receiver को reidentify कर सकता है।

**Procedure:** (1) matching BOLT 12 support confirm करें; (2) offer authenticate करें; (3) fresh invoice request करें; (4) amount/issuer/recurrence review करें; (5) wallet से pay करें; (6) receipt/refund behavior verify करें; (7) node alias/contact कम रखें और accounting रखें।<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP और first/last-hop telemetry, offer distribution account, timing/value और funding graph देखें; route blinding payer visibility सीमित करता है।

## Monero

**Mechanics:** one-time stealth addresses recipient linkage छिपाते हैं, RingCT amounts छिपाता है और ring signatures sender ambiguity देते हैं।

**Pros:** on chain default privacy; sender/receiver/amount confidentiality; mature dedicated wallet/node ecosystem।

**Cons:** acquisition/off-ramp और endpoint/network/counterparty records; remote node queries/IP देखता है; exchange support/legal treatment अलग-अलग; छोटे operational mistakes contexts link कर सकते हैं।

**Procedure:** (1) lawful तरीके से acquire करें और basis/source रखें; (2) official maintained wallet install/verify करें; (3) seed backup/test करें; (4) local node या documented Tor/I2P remote-node path लें; (5) हर payer/invoice के लिए नया subaddress लें; (6) contexts locally label करें; (7) transaction proof/view access केवल सोच-समझकर disclose करें।<sup>[[8]](#references)</sup>

**Detection:** exchange/merchant/device/network और seized-wallet evidence पर ध्यान दें; protocol use अकेले suspicious नहीं और public chain जानबूझकर कम expose करती है।

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs shielded transfers validate करते हैं, जबकि sender, receiver और amount encrypted रहते हैं; transparent pools और pool transitions public रहते हैं।

**Pros:** strong shielded on-chain confidentiality; viewing keys scoped audit में मदद कर सकती हैं; protocol-enforced validity।

**Cons:** wallet/exchange support और actual pool choice अलग-अलग; transparent boundary timing/value correlation; network/RPC और endpoint फिर भी रहते हैं।

**Procedure:** (1) maintained Orchard shielded-by-default wallet चुनें; (2) verify/backup करें; (3) ZEC lawfully प्राप्त करें; (4) supported Unified Address में receive करके pool confirm करें; (5) shielded-to-shielded prefer करें; (6) supported network privacy लें; (7) audit से पहले छोटे wallet पर viewing-key disclosure test करें।<sup>[[9]](#references)</sup>

**Detection:** transparent boundary और service records, wallet/network metadata और lawfully provided viewing keys देखें; हर Unified Address payment shielded है ऐसा न मानें।

## Mimblewimble और Litecoin MWEB

**Mechanics:** confidential transactions amounts छिपाती हैं और Mimblewimble-style aggregation conventional address-rich history हटाती है; Litecoin transparent chain के साथ optional extension block देता है।

**Pros:** private domain में confidential amounts और बेहतर fungibility; efficient pruning/aggregation।

**Cons:** opt-in boundary peg-in/out public और correlatable; wallet/exchange support; interactive/address model differences; network और acquisition records।

**Procedure:** (1) explicit MWEB support वाला maintained wallet चुनें; (2) verify/backup करें और small amount test करें; (3) lawfully acquire करें; (4) MWEB में peg करके balance domain verify करें; (5) compatible receiver के साथ ही transact करें; (6) तुरंत distinctive peg-out से बचें; (7) private audit records रखें।<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value, exchange/wallet/node data और later transparent spends देखें; internal confidential transfer details जानबूझकर कम होते हैं।

## Ethereum zero-knowledge privacy applications

**Mechanics:** circuit secret बताए बिना membership, valid note ownership या authorization जैसी statement prove करता है; verifier contract उसे check करता है। Deposits, withdrawals, public inputs, events और gas फिर भी links expose कर सकते हैं।

**Pros:** programmable selective disclosure; anonymous-set applications; सभी data reveal किए बिना verifiable rules।

**Cons:** contract/circuit bugs; छोटा anonymity set; public boundaries; RPC/IP/session/analytics/gas funding; application और sanctions/legal risk।

**Procedure:** (1) स्पष्ट करें कि proof exactly क्या छिपाता है; (2) lawful होने पर audited maintained application लें; (3) public inputs/events और deposit/withdraw rules inspect करें; (4) protocol के अनुसार action wallet और gas sponsorship अलग रखें; (5) privacy-aware RPC/network path लें; (6) small value से test करें; (7) compliance records रखें।<sup>[[11]](#references)</sup>

**Detection:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics और eventual exchange/merchant boundary देखें। ZK proof public घोषित fields छिपाता है ऐसा दावा न करें।

## Stablecoins

**Mechanics:** tokens public chain पर transfer होते हैं; centralized issuers freeze/blacklist कर सकते हैं या identified accounts के विरुद्ध redeem कर सकते हैं।

**Pros:** price stability, liquidity और merchant support; fast settlement; easy accounting।

**Cons:** transparent address/amount/contract graph; gas funding; issuer और exchange identity/control; sanctions screening; सामान्यतः कमजोर anonymity।

**Procedure:** इन्हें identified payment मानें: compartmentation के लिए fresh business address लें, token contract/network verify करें, small amount test करें, wallet सुरक्षित रखें, trusted RPC/local node लें, basis/source रखें और required parties screen करें।

**Detection:** complete token event graph, issuer freeze list/actions, exchange/RPC/device और gas-funding relationships देखें।

## Cashu Chaumian e-cash

**Mechanics:** mint client-generated bearer secrets को blind-sign करता है और mint के Bitcoin/Lightning reserves से backed होता है; double-spend रोक सकता है, बिना issuance को later redemption से सीधे link किए।

**Pros:** accountless bearer tokens; instant peer transfer; mint blinded withdrawal को spend से directly link नहीं कर सकता; tokens data/QR के रूप में move हो सकते हैं।

**Cons:** mint custody/solvency/censorship; bearer data loss/theft; denomination/timing और Lightning boundaries; network metadata; early software ecosystem।<sup>[[12]](#references)</sup>

**Procedure:** (1) पहले official test mint या tiny disposable value लें; (2) maintained wallet install करें और backup/restore limitations test करें; (3) mint authenticate तथा custody/fees review करें; (4) छोटी राशि mint करें; (5) authenticated private channel/QR से token भेजें; (6) receiver final मानने से पहले token swap करे; (7) redeem और reconcile करें। Untrusted mint में meaningful value न रखें।

**Detection:** mint network, issue/redeem/Lightning boundaries और spent-token set देखता है, पर blinding direct token linkage हटाती है; endpoints/messages और distinctive amount/timing links वापस ला सकते हैं।

## Fedimint federated e-cash

**Mechanics:** guardians का threshold reserves रखता और e-cash blind-sign करता है; internal bearer transfers guardians से private रहते हैं, जबकि Lightning gateways external payments bridge करते हैं।

**Pros:** distributed custody; private internal transfer; community governance; threshold से कम reserve पर कोई single guardian control नहीं करता।

**Cons:** guardian quorum/custody/software risk; gateway invoices/timing देखता है; deposit/withdraw boundaries; client-state recovery complexity।

**Procedure:** (1) federation invite/guardians/quorum/jurisdiction verify करें; (2) maintained client install और recovery test करें; (3) small lawful amount deposit करें; (4) fresh internal payment requests लें; (5) gateway को Lightning observer मानें; (6) redemption test करें; (7) public payment data से अलग source/tax records रखें।<sup>[[13]](#references)</sup>

**Detection:** federation aggregate issuance/redemption देखती है, gateways external invoices देखते हैं, Bitcoin/Lightning boundaries दिखाते हैं और endpoint/communication evidence internal transfers link कर सकते हैं।

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash merchants से payer को anonymous रखने का लक्ष्य रखता है, जबकि merchants और income accountable रहते हैं।

**Pros:** design द्वारा payer privacy; ordinary currency; merchant accountability/refunds; speculative token आवश्यक नहीं।

**Cons:** limited deployments; exchange/bank funding देखता है; merchant order/delivery देखता है; wallet bearer/recovery risk; regulated operators।

**Procedure:** (1) jurisdiction/currency के लिए current exchange/merchant खोजें; (2) KYC/fees/privacy पढ़ें; (3) official wallet install करें; (4) supported bank/exchange से lawfully withdraw करें; (5) merchant contract review करें; (6) pay करके receipt/refund data रखें; (7) unnecessary merchant session identifiers से बचें।<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal और merchant deposit accountable boundaries हैं; blinded coins के बावजूद merchant order/device/delivery और timing correlate हो सकते हैं।

## Cross-chain bridge, atomic swap और decentralized exchange

**Mechanics:** contract/service एक asset को lock/burn करके दूसरे को release/mint करता है, या counterparties atomically exchange करती हैं। यह single-ledger view तोड़ता है, economic continuity नहीं।

**Pros:** asset/network interoperability; एक centralized custodian से बचाव संभव; ordinary portfolio/liquidity use।

**Cons:** दोनों chains public; time/value/fees/liquidity और contracts correlate करते हैं; bridge/relayer/frontend/RPC records; smart-contract/counterparty और regulatory risk।

**Procedure for lawful swaps:** (1) official contract/service और legal availability verify करें; (2) custody/audit/fees/slippage inspect करें; (3) small test करें; (4) दोनों transaction IDs और rate record करें; (5) approvals protect करें; (6) destination asset reconcile करें और unnecessary approval revoke करें। Source of funds छिपाने के लिए swaps न उपयोग करें।

**Detection:** bridge deposit/withdraw events, fees के बाद unique amount, time order, liquidity, relayer/RPC/frontend और later service deposits correlate करें।

## Centralized mixer या tumbler

**Mechanics:** service pool में deposits लेती और बाद में अलग units लौटाती है, direct input-output mapping obscure करने का प्रयास करती है।

**Pros:** theory में transaction ambiguity बढ़ा सकती है।

**Cons:** operator steal/log कर सकता है; entry/exit timing/value analysis; sanctions/money-transmission और criminal exposure; seizures mappings expose करते हैं; taint/rejection risk।

**Procedure:** operational mixing guide नहीं दी जाती। [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) बढ़ाकर graph safely reproduce करें: synthetic deposits, pooled outputs, fees और delays बनाएँ; analysts को incomplete mappings दें; देखें कौन-सी heuristics काम करती हैं; फिर ground truth reveal करें।

**Detection:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs और downstream consolidation देखें। Probabilistic attribution label करें।

## Peel chains, fan-out/fan-in और structuring

**Mechanics:** repeated transactions change से छोटे payments peel करती हैं, value को अनेक addresses में split करती हैं, collectors पर reconverge करती हैं या review से बचने के लिए amounts divide करती हैं।

**Pros:** naive analyst workload और address count बढ़ता है।

**Cons:** recognizable value/cadence/transaction continuity; consolidation और service endpoints; structuring स्वयं illegal हो सकता है; fees और operational errors।

**Procedure:** केवल synthetic CSV/testnet data लें: large source, repeated payment/change edges, parallel branches और collector generate करें; benign exchange-like examples जोड़ें; detection tune करें और false positives document करें।

**Detection:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint और off-chain records देखें। Exchange hot wallets समान दिख सकते हैं, इसलिए context अनिवार्य है।<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker और front company

**Mechanics:** दूसरा व्यक्ति/account/company funds receive, convert या spend करता है और controller तथा transaction के बीच legal/operational layers डालता है।

**Pros to an adversary:** named account तुरंत controller की पहचान नहीं करता; cash, crypto, goods और jurisdictions bridge कर सकता है।

**Cons:** identity fraud/money-laundering exposure; प्रत्येक participant communications, bank/company/tax/shipping records, fees, inconsistency और witnesses जोड़ता है; facilitator reuse hubs बनाता है।

**Procedure:** real people/accounts से emulate न करें। Controller, recruiter, mule, OTC, shell merchant और beneficiary वाला synthetic graph बनाएँ; device/IP/message/bank edges seed करें; investigators से account holder और controller अलग पहचानने तथा evidence confidence record करने को कहें।

**Detection:** shared device/IP/recovery, unusual beneficiary/velocity, कई unrelated senders, immediate onward movement, company/director/invoice inconsistency, communications और cash/commodity delivery देखें।

## NFTs, gambling, merchant goods और refund loops

**Mechanics:** value को self-priced asset, wagering balance, resalable goods या refunds में बदला जाता है ताकि अलग transaction narrative बने।

**Pros to an adversary:** asset form बदलता है और marketplace/merchant intermediaries जोड़ता है।

**Cons:** marketplace/account/device और wash-trade graph; odds/play और refund records; delivery/resale evidence; fees/losses; fraud/laundering liability।

**Procedure:** concealment workflow नहीं। Related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument और common shipping वाला synthetic marketplace data लें; legitimate collectors/customers के विरुद्ध detection validate करें।

**Detection:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery और proceeds reconvergence देखें।

## Physical bearer wallet या offline token transfer

**Mechanics:** device, paper/QR, hardware bearer instrument या e-cash token handover पर payment broadcast करने के बजाय secret का control transfer करता है।

**Pros:** exchange के समय live network event नहीं; offline उपयोगी; physical cash-like custody।

**Cons:** copy/theft/loss और uncertain exclusivity; later redemption/broadcast links; physical meeting/shipping; counterfeit/tamper risk।

**Procedure:** (1) reviewed instrument/protocol ही लें; (2) authenticity privately initialize/verify करें; (3) केवल small lawful value load करें; (4) documented authorized context में transfer करें; (5) protocol के अनुसार receiver prompt verify/sweep करे; (6) sender ने copy नहीं रखी ऐसा कभी न मानें; (7) ownership/tax evidence privately रखें।

**Detection:** purchase/funding और eventual sweep/redemption, device serial/tamper evidence, delivery/meeting और endpoint records देखें।

## Merchant-scoped invoice या one-time payment request

**Mechanics:** merchant amount, expiry और order reference वाला single-use request बनाता है। Payer supported rail से settle करता है और reusable credential merchant को सीधे नहीं देता; issuer या payment processor फिर भी दोनों parties की पहचान कर सकता है।

**Pros:** credential reuse और accidental cross-merchant identifiers कम; exact amount/expiry errors घटाते हैं; ordinary accounting/refunds compatible।

**Cons:** invoice, delivery, browser, processor और issuer order link करते हैं; unique amount/time correlation मजबूत कर सकते हैं; malicious payment links सामान्य हैं।

**Procedure:** (1) merchant independently authenticate करें; (2) exact amount, asset/network और expiry वाला fresh invoice माँगें; (3) destination और refund rules inspect करें; (4) approved engagement compartment से pay करें; (5) merchant acknowledgment verify करें; (6) receipt और transaction reference रखें; (7) request reuse करने के बजाय expire करें।

**Detection:** merchant और processor invoice, session और settlement जोड़ते हैं; unique amounts/timing और delivery payer पहचानते हैं। **Captured wallet/device:** invoice history counterparties और purpose expose करती है; unnecessary memo data कम करें, device encrypt करें और authoritative accounting controlled finance system में रखें।

## Prepaid service credit और capability token

**Mechanics:** service conventional payment को bounded internal credits या bearer capability में बदलती है। Subsequent API/resource use में हर request पर original card न दिखाना पड़ सकता है, लेकिन service issuance को redemption से map कर सकती है।

**Pros:** spend और compromise loss सीमित; day-to-day workers को funding credential से अलग; per-project budgets और revocation।

**Cons:** सामान्यतः pseudonymous, anonymous नहीं; service database, redemption IP और unique usage pattern activity link करते हैं; bearer tokens चोरी हो सकते हैं; refunds original payer माँग सकते हैं।

**Procedure:** (1) organization account से credits खरीदें; (2) एक project और budget बनाएँ; (3) service, amount और expiry constraints वाला narrow token issue करें; (4) approved secret manager या workload identity path में ही रखें; (5) scope/expiry के बाहर rejection test करें; (6) consumption monitor करें; (7) unused value revoke और reconcile करें।

**Detection:** provider funding account, project, token issuance और usage जोड़ता है; geographic/process changes और anomalous consumption पर alert करें। **Captured node:** remaining capability खर्च हो सकती है; short expiry, low balance, audience binding और immediate server-side revocation लें।

## Privacy Pass या blinded authorization token

**Mechanics:** issuer privacy-preserving authorization token बनाता है जिसे origin issuance से link किए बिना validate कर सकता है। यह paid entitlement या rate-limited access हो सकता है, general currency नहीं। Architecture client, attester, issuer और origin roles अलग करती है और चेतावनी देती है कि IP/timing या collusion unlinkability समाप्त कर सकते हैं।<sup>[[18]](#references)</sup>

**Pros:** supported services में unlinkable redemption; origin पर reusable account cookie नहीं; cached tokens issuance और use को समय में अलग कर सकते हैं।

**Cons:** application-specific; issuer/attester trust और anonymity-set partitioning; IP/browser metadata रहते हैं; token theft या distinctive issuance timing use correlate कर सकते हैं।

**Procedure:** (1) relevant Privacy Pass token type के अनुरूप implementation लें; (2) token द्वारा सिद्ध entitlement स्पष्ट करें; (3) threat model में आवश्यक हो तो issuer और origin administration अलग करें; (4) challenge metadata कम करें; (5) कई test tokens issue करके owned origins पर प्रत्येक को एक बार redeem करें; (6) forbidden stable identifiers के लिए logs compare करें; (7) replay, expiry और revocation/abuse controls test करें।

**Detection:** origins redemption IP/time और token validity देखते हैं; issuers/attesters issuance context देखते हैं; analysts timing और metadata partitions test करें, cryptographic break assume न करें। **Captured client:** unspent bearer tokens usable हो सकते हैं; value, lifetime और audience bind करें और funding credential इनके साथ cache न करें।

## Delegated organization procurement या fiscal sponsor

**Mechanics:** authorized procurement team, reseller या fiscal sponsor contract और payment करता है, जबकि operational team bounded service प्राप्त करती है। यह truthful records वाला role separation है, nominee या false identity नहीं।

**Pros:** vendors को हर operator की identity या personal payment details नहीं मिलती; central compliance, tax और refund handling; clear budget/offboarding।

**Cons:** sponsor beneficiary और purpose जानता है; contracts, approvals, delivery और accounts रहते हैं; delay/fees; वही व्यक्ति हर layer administer करे तो separation कमजोर।

**Procedure:** (1) business purpose, beneficiary और approving authority document करें; (2) organization-approved intermediary चुनें; (3) truthful details पर contract करें; (4) personal billing credential के बिना project-scoped subaccount दें; (5) finance administrators और operators अलग रखें; (6) invoices और access reconcile करें; (7) closeout पर service और delegated access terminate करें।

**Detection:** procurement, identity-provider, vendor और delivery records chain जोड़ते हैं। **Captured operational device:** service project दिखना चाहिए, finance credentials नहीं; invoices और payer identities field nodes के बजाय finance system में रखें।

## Escrow या conditional settlement

**Mechanics:** trusted escrow agent या smart contract documented conditions पूरी होने तक value रखता है। Payer/payee के बीच direct disclosure घट सकता है, लेकिन escrow और underlying rails relationship रखते हैं।

**Pros:** dispute और delivery protection; parties एक-दूसरे को कम reusable credentials expose कर सकती हैं; auditable release conditions।

**Cons:** escrow custody/contract risk, fees और identity obligations; on-chain contracts public; order, shipping और dispute data रहते हैं; intermediary से anonymous नहीं।

**Procedure:** (1) legal entity, custody, fees, dispute forum और supported assets verify करें; (2) exact written milestone और refund path बनाएँ; (3) approved organization account से fund करें; (4) receipt और release authorization independently verify करें; (5) evidence के बाद release करें; (6) complete audit record रखें; (7) unused permissions/contract approvals बंद करें।

**Detection:** escrow account/contract events, funding और release time, beneficiary और dispute records transaction दिखाते हैं। **Captured device:** session tokens या contract approvals release कर सकते हैं; separate approver/MFA लें और loss पर active sessions revoke करें।

## Batched या pooled organization settlement

**Mechanics:** कई approved obligations aggregate करके कम bank/blockchain transactions में settle किए जाते हैं और private internal ledger प्रत्येक share assign करता है। Public per-purchase detail घट सकता है, लेकिन coordinator complete attribution रखता है।

**Pros:** lower fees; कम public graph edges; aggregated amounts होने पर public observer से individual line items छिपते हैं; straightforward internal accounting।

**Cons:** coordinator complete observer और high-value target; distinctive totals/timing correlate कर सकते हैं; custody/reconciliation risk; abuse होने पर structuring जैसा दिख सकता है।

**Procedure:** (1) accounting system में participants और lawful obligations define करें; (2) controls से बचने के लिए thresholds के बजाय regular business-justified batch window रखें; (3) aggregate का dual approval लें; (4) authenticated recipients को settle करें; (5) हर internal line को batch से reconcile करें; (6) refunds को linked corrections बनाएं; (7) ledger access protect करें और policy के अनुसार retain करें।

**Detection:** coordinator ledger, approval और beneficiary records ground truth देते हैं; public analysts input/output/value/time clustering सावधानी से उपयोग करें। **Captured payer device:** इसमें केवल requisition हो, pool signing key या participant ledger नहीं।

## Account-abstraction paymaster या sponsored gas

**Mechanics:** relayer/bundler smart-account operation submit करता है और paymaster transaction fees देता है, जिससे user wallet से direct native-gas funding edge हटता है। एक graph property सुधरती है; operation, contract और service telemetry public/observable रहते हैं।<sup>[[19]](#references)</sup>

**Pros:** common gas-funding link हटता है; scoped sponsorship और rate limits; legitimate privacy applications के लिए बेहतर onboarding।

**Cons:** paymaster/bundler/RPC/front end requests correlate कर सकते हैं; contract events और public inputs रहते हैं; sponsorship policy cohort fingerprint करती है; malicious contracts/approvals assets चुरा सकते हैं।

**Procedure:** (1) correct network पर audited maintained smart account और paymaster लें; (2) public fields और sponsor logs inspect करें; (3) sponsorship को contract, function, amount, nonce और expiry से limit करें; (4) low value test करें; (5) application के intended privacy-aware path से submit करें; (6) chain पर operation और fee payer verify करें; (7) allowances/session keys revoke करें और compliance records रखें।

**Detection:** UserOperation, EntryPoint, paymaster, bundler/RPC और application logs join करें; identical sponsorship policy को सावधानी से cluster करें। **Captured wallet:** gas के बिना भी session keys और pending approvals usable हो सकते हैं; उन्हें tightly scope करें और recovery policy से revoke करें।

## Threshold या multisignature payment authorization

**Mechanics:** spending के लिए independent signers का threshold आवश्यक है। यह transaction नहीं छिपाता, लेकिन payment authority को captured laptop, field node या single operator से अलग करता है।

**Pros:** compromise और insider resistance; accountable approval; कोई single field device complete signing authority नहीं रखता; recovery support।

**Cons:** coordination/availability; signer/device/account metadata participants correlate कर सकते हैं; खराब backup से loss; public multisig patterns identifiable हो सकते हैं।

**Procedure:** (1) funding से पहले signers, threshold, limits और recovery define करें; (2) separate supported hardware/accounts पर initialize करें; (3) addresses और backups independently verify करें; (4) field workloads को केवल unsigned requisition capability दें; (5) recipient, amount और purpose का out-of-band review लें; (6) small value से recovery और one-signer loss test करें; (7) compromise के बाद signer rotate करें।

**Detection:** approval system, signer device और public script/contract evidence देते हैं; policy या signer-set changes पर alert करें। **Captured node:** अधिकतम एक low-authority session key या unsigned request expose हो; quorum material साथ cache न करें।

## Closed-loop community या event currency

**Mechanics:** cooperative, conference या private test environment enrolled participants के बीच redeemable credits issue करता है। Internal transfer global payment networks को कम expose कर सकता है, पर operator issuance/redemption control करता है।

**Pros:** bounded economic domain; offline या privacy-preserving payment UX test; external card exposure सीमित; clear experimental controls।

**Cons:** छोटा anonymity set; operator और merchants activity देखते हैं; limited acceptance/redemption; local value पर भी licensing, consumer-protection और tax rules लागू हो सकते हैं।

**Procedure:** (1) legal/compliance review लें और issuer terms publish करें; (2) consenting test participants enroll करें; (3) issuance cap करें और cash-like misuse रोकें; (4) fresh payment requests लें और public participant identifiers कम करें; (5) aggregate reserves और private individual receipts record करें; (6) loss/refund/redemption test करें; (7) ledger बंद करें और promised residual value लौटाएँ।

**Detection:** issuer ledger, enrollment, merchant और redemption records flows reconstruct करते हैं; unusual circular transfers या rapid cash-out review योग्य हैं। **Captured wallet:** local balance और counterparties expose हो सकते हैं; value cap, state encryption और auditable issuer freeze/reissue रखें।

## Bitcoin reusable payment codes और private payment instructions

**Mechanics:** BIP 47 reusable public identifier और ECDH-derived one-time deposit addresses उपयोग करता है; BIP 351 newer private-payment instruction design देता है। ये public address reuse घटाते हैं, लेकिन notification, wallet support, funding और subsequent coin selection privacy प्रभावित करते हैं।<sup>[[20]](#references)</sup>

**Pros:** एक public instruction से distinct addresses; recipient को हर invoice address publish नहीं करना; compatible wallets derived payments monitor कर सकते हैं; repeated lawful donors/customers के लिए उपयोगी।

**Cons:** wallet interoperability अलग-अलग; notification transactions या published payment code relationship context link करते हैं; sender, recipient और public graph transactions देखते हैं; careless consolidation/change benefit नष्ट करते हैं।

**Procedure:** (1) दोनों maintained wallets exact same specification/version support करते हैं या नहीं verify करें; (2) low-value wallet पर backup/recovery test करें; (3) recipient payment code out of band authenticate करें; (4) small lawful test भेजें; (5) fresh derived address verify करें; (6) relationship locally label करें और coin control लें; (7) relying से पहले recovery और refund behavior test करें।

**Detection:** notification patterns, funding/change, later consolidation और service boundaries examine करें; public-code publication recipient context identify करती है भले deposit addresses अलग हों। **Capture-resilient OPSEC:** spend keys field devices से बाहर रखें और अधिकतम watch-only relationship view expose करें। **Monitoring:** unexpected notification transactions, reused derived addresses, wallet gap-limit/recovery errors और unplanned consolidation पर alert करें।

## EVM stealth addresses (ERC-5564)

**Mechanics:** sender recipient के stealth meta-address से one-time stealth account derive करता है और ephemeral public key तथा view tag वाला announcement publish करता है। Recipient viewing key से announcements scan करके corresponding spend key derive करता है। Recipient linkage सुधरता है, लेकिन sender, amount/token, gas, announcement और later spending visible रहते हैं।<sup>[[21]](#references)</sup>

**Pros:** non-interactive fresh receiver address; reusable meta-address; viewing और spending roles अलग; supported EVM assets/applications में काम करता है।

**Cons:** announcement scanning और spam; new address को gas fund करने से relink हो सकता है; sender recipient जानता है; public token/amount और eventual consolidation रहते हैं; implementation/wallet support अलग-अलग।

**Procedure:** (1) पहले test network पर audited maintained implementation लें; (2) separate viewing/spending material generate और backup करें; (3) meta-address authenticate करें; (4) low-value test और announcement भेजें; (5) scan करके stealth account derive करें; (6) personal funding edge के बिना supported gas sponsorship test करें; (7) public fields record करें और lawful accounting रखें।

**Detection:** announcement caller, token/amount, timing, gas sponsor, spending और consolidation follow करें; view key spend दिए बिना receipt prove कर सकती है। **Capture-resilient OPSEC:** networked scanner को जहाँ supported हो केवल viewing role दें; spend/recovery keys अलग रखें। **Monitoring:** malformed/spam announcements, view-key access, unexpected spend derivation और बिना approval moved stealth outputs पर alert करें।

## Liquid Confidential Transactions

**Mechanics:** Liquid commitments और proofs से output amounts और asset types default रूप से blind करता है, जबकि transaction graph, input/output count, fee और block time visible रहते हैं। Peg-in/peg-out और service boundaries linkable रहती हैं, और users blinding data selectively disclose कर सकते हैं।<sup>[[22]](#references)</sup>

**Pros:** default confidential amount और asset type; fast sidechain settlement; blinding keys/descriptors से selective audit; public observers से commercially sensitive values छिपते हैं।

**Cons:** graph structure और timing रहते हैं; federation/bridge और exchange trust; peg boundaries और unconfidential outputs; wallet/node/network records; sender और receiver transaction जानते हैं।

**Procedure:** (1) maintained Liquid wallet चुनें और backup model verify करें; (2) testnet या small lawful amount लें; (3) confidential address पर receive करके wallet में blinded output verify करें; (4) test confidential transaction भेजें; (5) देखें explorer में कौन-से fields public रहते हैं; (6) audit के लिए केवल scoped blinding proof export करें; (7) peg/exchange boundaries document और funds reconcile करें।

**Detection:** visible graph/fee/time, peg और exchange records, network metadata और later unblinding evidence analyze करें; hidden amount या asset infer न करें। **Capture-resilient OPSEC:** spend seed, blinding/view data और watch-only operations अलग रखें। **Monitoring:** accidental unconfidential addresses, unknown peg requests, descriptor changes और unapproved unblinding-key export पर alert करें।

## General payment या state channel

**Mechanics:** participants funds lock करते हैं, signed off-chain state updates exchange करते हैं और chain पर opening, closing या disputed state publish करते हैं। Intermediate payments globally broadcast नहीं होते, पर peers और routing/intermediary services अपना हिस्सा देखते हैं तथा endpoints latest enforceable state रखते हैं।<sup>[[23]](#references)</sup>

**Pros:** कई fast low-fee private-to-public-ledger interactions; कम global transaction detail; bounded channel balance; metered services और repeated counterparties के लिए उपयोगी।

**Cons:** channel peers एक-दूसरे को जानते और updates रख सकते हैं; opening/closing/value/timing correlate; challenge windows में online monitoring आवश्यक हो सकता है; implementation/liquidity risk; अपने आप बड़ा anonymity set नहीं।

**Procedure:** (1) maintained audited implementation और dispute window समझें; (2) owned parties के बीच low-value test channel खोलें; (3) unique nonces वाले signed state updates exchange करें; (4) latest enforceable state backup करें; (5) cooperatively close करें; (6) testnet पर stale-state rejection rehearse करें; (7) accounting और channel-peer records रखें।

**Detection:** public chain lifecycle/disputes दिखाती है; peers, watch services और application transport off-chain timing/parties expose करते हैं। **Capture-resilient OPSEC:** hot balance cap करें और latest signed state encrypted recoverable store में field nodes से अलग रखें। **Monitoring:** stale-state publication, missed backup, peer-key change और approaching challenge deadline लगातार देखें।

## Mobile carrier billing

**Mechanics:** online service mobile subscription या prepaid balance पर purchase charge करती है। Merchant को card/bank details के बजाय carrier authorization मिल सकती है, जबकि carrier subscriber/line, device/network context, merchant, amount और time जानता है।<sup>[[24]](#references)</sup>

**Pros:** merchant को card number नहीं; broad phone availability; low-value digital goods; carrier charges cap/reverse कर सकता है।

**Cons:** SIM/account और अक्सर device से strongly identified; small limits/high fees; merchant category restrictions; account takeover/SIM-swap risk; carrier और aggregator complete trail बनाते हैं।

**Procedure:** (1) organization carrier account में availability, limit, fee और refund terms confirm करें; (2) justified होने पर dedicated organization line पर ही enable करें; (3) lowest useful spend cap रखें; (4) benign test item खरीदें; (5) merchant और carrier receipts verify करें; (6) recurring authorization बंद करें; (7) reconcile करके assessment के बाद feature बंद करें।

**Detection:** carrier, aggregator और merchant records line, subscriber, IP/device और charge जोड़ते हैं; enterprise telecom invoices इसे दिखाते हैं। **Capture-resilient OPSEC:** personal number न लें और carrier-account MFA field device से बाहर रखें। **Monitoring:** instant charge/SIM-change alerts और unexpected premium-service enrollment, forwarding या account recovery पर stop करें।

## Open-banking payment initiation

**Mechanics:** explicit user consent के साथ regulated PISP account-servicing bank से transfer initiate करता है। Merchant को card credentials नहीं मिल सकते, लेकिन PISP और banks regulated payer, payee, consent, device और transaction records रखते हैं।<sup>[[25]](#references)</sup>

**Pros:** checkout पर reusable card number नहीं; strong bank authentication; exact account-to-account settlement; consent/status APIs; clear reconciliation।

**Cons:** banks/PISP से anonymous नहीं; payee को legal account details/reference मिल सकते हैं; phishing/redirect risk; jurisdiction/refund protections अलग-अलग; consent metadata extra observer है।

**Procedure:** (1) PISP regulated है और merchant callback domain authentic है verify करें; (2) merchant request से शुरू करें; (3) bank में payee, amount, reference और requested consent review करें; (4) केवल single payment authorize करें; (5) final status independently verify करें; (6) residual consent revoke करें; (7) receipt रखें और reconcile करें।

**Detection:** bank/PISP/merchant logs और transfer references strong attribution देते हैं। **Capture-resilient OPSEC:** banking authentication और recovery operational/field devices से बाहर रखें; device में केवल paid-service entitlement हो। **Monitoring:** bank transaction/consent alerts लें और new PISP grants, changed payee या unexpected status callbacks investigate करें।

## Platform wallet, app-store balance या in-app credit

**Mechanics:** platform user को bill या account credit redeem करके application को signed receipt/entitlement देती है। App developer को original funding instrument नहीं मिल सकता, जबकि platform account, device, funding, product और redemption map करता है।<sup>[[26]](#references)</sup>

**Pros:** merchant/developer को primary PAN नहीं; fraud/refund और family/business controls; छोटा prepaid balance exposure cap करता है; signed receipts entitlement verification सरल करते हैं।

**Cons:** platform account strong identity/behavior hub; device/storefront geography; gift-balance purchase/redemption trail; limited cash-out; fraud controls funds freeze कर सकते हैं; cross-platform money नहीं।

**Procedure:** (1) policy अनुमति दे तो organization-managed platform account उपयोग करें; (2) funding, region, refund और transferable-value rules पढ़ें; (3) केवल approved budget जोड़ें; (4) official store से benign product खरीदें; (5) application को expected receipt fields ही मिलते हैं verify करें; (6) recurring purchase बंद करें; (7) reconcile करके operational hardware से account हटाएँ।

**Detection:** platform receipts/server notifications, account/device login और funding records purchase reconstruct करते हैं। **Capture-resilient OPSEC:** field node पर personal store account sign in न करें; जहाँ संभव हो scoped app entitlement दें। **Monitoring:** new-device/purchase alerts enable करें और receipt replay, family/account changes या unexpected restore events जाँचें।

## Mutual credit, clearing या periodic net settlement

**Mechanics:** participants private ledger में obligations record करते और समय-समय पर केवल net position settle करते हैं। Individual service events को अलग public payments बनाने की आवश्यकता नहीं, लेकिन ledger operator और counterparties detailed attribution रखते हैं।

**Pros:** कम external transactions/fees; public observers केवल net settlement देखते हैं; repeated organizations के लिए उपयोगी; explicit credit limits exposure सीमित करते हैं।

**Cons:** centralized ledger complete evidence और fraud target; counterparty/default risk; legal/accounting/tax duties; छोटा membership set; unusual net transfers relationships दिखा सकते हैं।

**Procedure:** (1) legal/accounting approval वाले identified consenting organizations ही लें; (2) unit, credit limit, settlement interval और dispute rules define करें; (3) हर obligation immutable approval के साथ record करें; (4) अलग finance roles net positions calculate और approve करें; (5) ordinary lawful rail से settle करें; (6) individual lines को settlement से reconcile करें; (7) access बंद करें और policy के अनुसार records रखें।

**Detection:** ledger, invoices, approvals और final bank/chain settlement ground truth देते हैं; analysts केवल net transfer से missing gross activity infer न करें। **Capture-resilient OPSEC:** operational devices bounded requisitions submit करें, balances edit या settlement authorize न कर सकें। **Monitoring:** credit-limit breach, backdated entries, administrator changes, reconciliation mismatch और new beneficiary settlement पर alert करें।

## Capture/compromise exposure matrix

यह हर family पर seizure/loss test लागू करता है। उद्देश्य lawful accounting रखते हुए spend authority और unrelated identity disclosure सीमित करना है—transactions मिटाना या investigation रोकना नहीं।

| Technique family | A captured wallet/device/account can reveal | Minimum authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value और physical contacts | केवल approved amount रखें; private accounting अलग; prompt loss report; false records नहीं |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption और account/session tokens | low balance; one purpose; truthful registration; available होने पर issuer freeze/revocation |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery और merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; shared recovery account नहीं |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices और project | role separation; least-privilege subaccount; finance credentials operational/field nodes पर नहीं |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator या dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph और network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP और payment database | minimal hot balance; encrypted backup; separate node identity; documented close/recovery |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC और boundary transactions | separate spend/view roles; जहाँ उपलब्ध hardware support; field node पर exchange session नहीं |
| Stablecoins, swaps, bridges और DEX | transparent graph, approvals, RPC/front-end state और destination assets | allowances revoke; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; protocol-supported encrypted backup; redeem/reissue; funding credential अलग |
| Paymaster, multisig/threshold | session key, one signer, pending operations और sponsor policy | narrow session key; independent quorum; signer rotation; field device threshold तक न पहुँचे |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph और participant records | operational use नहीं; केवल synthetic/testnet evidence से emulate |
| Community/event currency | enrollment, local balance, counterparties और redemption | capped value; issuer freeze/reissue; consent और private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements और derived outputs | watch/view-only network role; offline/hardware spend role; personal funding session नहीं |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries और disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device और funding source | organization account; external MFA; low limit; field hardware पर personal account नहीं |
| Mutual-credit clearing | members, obligations, limits, approvals और settlement ledger | operational requisition only; separate immutable ledger और dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial, compliance review या wallet offline होना investigation का proof नहीं है। केवल उन्हीं accounts, ledgers और infrastructure को monitor करें जिन्हें organization observe करने के लिए अधिकृत है; providers या counterparties को probe करके यह test न करें कि वे investigators के साथ cooperate कर रहे हैं या नहीं।

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund या loss report | missing instrument, approved order से बाहर redemption, altered receipt या custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap या recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice और consumption | cross-project token, unknown admin, limit breach, invoice mismatch या unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation और beneficiary change | altered amount/payee, backdated ledger, unilateral release या unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels और consolidation | unknown spend, reused recipient output, wallet gap/recovery failure या unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure या coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP और chain dispute | unknown invoice payment, peer-key change, stale close या approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor और boundary transaction | spend without approval, transparent/unconfidential downgrade, key export या unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key और issuer action | wrong contract/public field, unknown approval/spend, paymaster change या issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway और bearer balance | unknown redemption, mint key/terms change, restore failure या balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate और destination | contract/route mismatch, unlimited approval, missing destination या bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum और recovery audit | unknown proposal/signer, threshold reduction, recovery activation या policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | केवल synthetic lab ground truth और detection output | कोई real account, person या value emulation में प्रवेश करे: तुरंत stop |

## Selection and verification workflow

1. निर्धारित करें कि कौन-सी party को कौन-सा field नहीं जानना चाहिए।
2. Issuer/mint/custodian, public ledger, network/RPC, merchant और physical observers पहचानें।
3. Current support, legality, limits, custody, recovery और refund behavior verify करें।
4. Small lawful end-to-end test करें।
5. Merchant receipt, provider statement, public chain और wallet/node logs inspect करें।
6. Backup/recovery और deliberate audit disclosure test करें।
7. Required source, ownership, tax, sanctions और engagement records accurate लेकिन access-controlled रखें।

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — बड़े payment platforms द्वारा data collection पर observations](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — अपनी privacy सुरक्षित करें](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — एक सरल Payjoin proposal](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technical specifications और network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — zero-knowledge proofs के साथ privacy applications बनाना](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol और privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — यह कैसे काम करता है](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — virtual currency के administrators, exchangers और users](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information और crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — The Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State और payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
