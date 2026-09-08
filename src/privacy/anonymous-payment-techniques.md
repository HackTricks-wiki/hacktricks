# Katalogi ya Mbinu za Malipo Yasiyotambulisha

{{#include ../banners/hacktricks-training.md}}

Katalogi hii inahusu **familia** za malipo, kuanzia pesa taslimu za kawaida hadi blind-signature e-cash na public-chain obfuscation. “Anonymous” daima humaanisha kutotambulika kwa mtazamaji fulani aliyetajwa. Mfanyabiashara, issuer, mint, exchange, blockchain analyst, network provider, mwajiri na mtazamaji wa kimwili huona taarifa tofauti.

Taratibu zilizo hapa ni za fedha halali, akaunti zenye taarifa za kweli na ununuzi ulioidhinishwa. Mbinu ambazo katika visa vilivyotajwa zilitumika kwa laundering, sanctions evasion au identity fraud zinaelezwa na kugunduliwa, lakini utaratibu wake ni zoezi la synthetic forensic, si maelekezo ya kutenda uhalifu.

## Coverage matrix

| Family | Sifa kuu ya privacy | Mtazamaji/main trust | Matibabu |
|---|---|---|---|
| Cash and cash equivalents | hakuna rekodi ya mbali ya payment-network | mpokeaji na mazingira ya kimwili | lawful workflow |
| Prepaid/gift/voucher value | hutenganisha redemption na primary card | seller, issuer na redemption service | lawful workflow, hutofautiana kwa jurisdiction |
| Virtual/tokenized card | huficha PAN inayotumika tena au hutenganisha merchants | issuer/network/wallet bado humtambua payer | lawful workflow |
| Payment app/intermediary | merchant anaweza kuona alias/intermediary | app hukusanya identity/device/transaction | comparison baseline |
| Bitcoin hygiene/Silent Payments | pseudonyms na recipient unlinkability | public graph na wallet/network boundary | deployable |
| PayJoin/CoinJoin | hudhoofisha common ownership/linkage heuristics | participants/coordinator/network/public graph | deployable where supported; legal review |
| Lightning/BOLT 12 | off-chain routing na kupunguza njia ya receiver | endpoints, hops, services na channel graph | deployable where supported |
| Monero/Zcash/MWEB | on-chain confidentiality ya kiwango cha protocol | acquisition, endpoint, network na boundary bado vipo | deployable where lawful/supported |
| Ethereum ZK application | huficha statement/action link iliyoainishwa | public inputs, RPC, relayer na app | application-specific |
| Cashu/Fedimint/Taler | payer privacy kupitia blind signatures | mint/federation/exchange custody na boundaries | emerging/deployment-specific |
| Stablecoins | digital settlement rahisi | transparent chain pamoja na issuer freeze/control | not anonymous baseline |
| Swaps/bridges/DEX | huhamisha value kati ya assets/chains | graphs zote mbili, contracts na providers | forensic mechanics; ordinary lawful swaps only |
| Mixers/peel/structuring | huongeza graph ambiguity/work | entry/exit graph na service records | synthetic detection exercise only |
| Nominees/mules/OTC/fronts | huingiza intermediaries wa kibinadamu/kibiashara | facilitators, banks, communications | criminal-abuse analysis only |
| Reusable/stealth payment addresses | address mpya ya receiver kwa kila malipo | public announcement/notification na wallet boundaries | deployable where supported |
| Confidential sidechain/state channel | huficha amount/asset au intermediate updates | peers, bridge/federation na lifecycle settlement | protocol-specific |
| Carrier/open-banking/platform billing | huficha primary card kwa merchant | carrier, bank/PISP au platform humtambua customer | ordinary identified payment |
| Mutual credit/net settlement | rekodi chache za nje za settlement | private ledger operator ana mapping yote | identified participants only |

## Cash

**Mechanics:** physical bearer value hubadilishana mikononi bila online issuer authorization au public ledger.

**Pros:** merchant hahitaji kujua bank/card identity; hakuna remote transaction graph; inaeleweka kwa upana na ni final.

**Cons:** face-to-face tu; theft/loss; change/receipt/serial au reporting controls; withdrawal, cameras, witnesses na location bado vinaweza kumuunganisha payer.

**Procedure:** (1) thibitisha kuwa cash ni halali/inakubaliwa na angalia sheria za amount/reporting; (2) withdraw au ipokee kihalali na hifadhi accounting records za faragha; (3) mlipie merchant wa kawaida bila loyalty/account identifiers zisizo za lazima; (4) omba receipt inayohitajika tu; (5) epuka shipping/account data ikiwa ununuzi hauihitaji; (6) rekodi internally madhumuni halali ya biashara.

**Detection:** linganisha till/receipt/inventory, cameras na access logs kulingana na policy; chunguza unusual cash refunding au repeated amounts zilizo chini kidogo ya control bila kuchukulia matumizi ya kawaida ya cash kuwa ya kutiliwa shaka yenyewe.

## Money order, postal order, cashier instrument and cash on delivery

**Mechanics:** regulated issuer hubadilisha cash/account funds kuwa instrument yenye namba inayolipwa kwa recipient aliyetajwa; COD huahirisha collection hadi delivery.

**Pros:** recipient huenda asipokee primary bank/card number ya payer; hutumika pale cash haiwezi kusafirishwa remotely; receipt iliyo wazi.

**Cons:** issuer/retailer huhifadhi purchase/identity data kama inavyotakiwa; serial tracking; recipient/delivery address; loss/fraud na regional restrictions; kwa kawaida si anonymous.

**Procedure:** (1) kagua issuer rules, limits, identification na recipient acceptance; (2) nunua kwa taarifa za kweli na lawful funds; (3) jaza payee/amount mara moja; (4) hifadhi serial/receipt; (5) tumia delivery yenye tracking inayolingana na value; (6) linganisha redemption/refund.

**Detection:** issuer purchase/redemption record, instrument serial, retailer/camera, shipping na recipient account; flag alteration, duplicate serials na redemption za haraka zisizoendana kijiografia.

## Open-loop prepaid card

**Mechanics:** stored-value credential yenye brand ya network hu-authorize dhidi ya prepaid balance badala ya primary credit account.

**Pros:** hupunguza merchant exposure na loss; hutenganisha merchant na main PAN; hutumika online inapokubaliwa.

**Cons:** purchase/activation/reload/registration na device records; KYC na limits hutofautiana; billing-address failures; cash-out/refund restrictions; “no name” haimaanishi hakuna issuer record.

**Procedure:** (1) thibitisha issuer identity, fees, KYC, geography na online/recurring support; (2) pata kupitia authorized seller kwa lawful funds; (3) register data ya kweli inayohitajika; (4) itumie kwa purpose moja iliyotenganishwa; (5) usifanye structuring ya loads au kutengeneza residency ya uongo; (6) hifadhi ushahidi wa purchase/expense na ifunge/dispose kulingana na issuer terms.

**Detection:** unganisha seller/activation, funding, device/IP, merchant authorization, balance checks na redemption/refund. Patterns ni muhimu zaidi kuliko label ya prepaid.

## Closed-loop gift card, voucher and transferable service credit

**Mechanics:** value yenye namba inaweza kutumiwa tu kwa merchant/service au ecosystem moja. Airtime/game/store credits ni variants.

**Pros:** merchant anayepokea anaweza kuona code/balance pekee; blast radius ndogo; gifting na budget separation rahisi.

**Cons:** seller na service hu-log purchase/activation/redemption; account/device/delivery bado huunganisha; scams, resale discounts na expiry/region limits; refund rights dhaifu.

**Procedure:** (1) nunua kupitia authorized channels pekee; (2) rekodi code value bila kufichua secret; (3) epuka kuunganisha loyalty account inayotambulisha ikiwa si lazima; (4) redeem kupitia merchant account/context halali iliyotenganishwa; (5) hifadhi receipt hadi ikubaliwe; (6) usinunue codes kwa ombi lisilotarajiwa la “tax/support/ransom”.

**Detection:** code issuance/redemption time, device/account convergence, bulk/threshold-pattern purchase, device moja kukagua balances nyingi na redemption ya haraka kutoka maeneo ya mbali.

## Cryptocurrency-funded card or gift-code broker

**Mechanics:** intermediary hupokea cryptocurrency na kutoa card, voucher au merchant code. Hii ni cross-rail conversion: merchant huona card/gift value ya kawaida, huku broker akiunganisha on-chain deposit na issuance/delivery.

**Pros:** merchant hapokei funding wallet; husaidia merchants halali wasiokubali crypto; stored value yenye mipaka.

**Cons:** si anonymous kutoka kwa broker/issuer; KYC, sanctions, exchange na card-program rules; public deposit graph; account/device/email na code redemption huunganisha pande zote; scam/insolvency risk.

**Procedure:** (1) thibitisha legal entity, card issuer, supported jurisdiction, KYC, fees na refund policy; (2) tumia lawful documented funds pekee; (3) jaribu denomination ndogo zaidi; (4) thibitisha network/merchant restrictions kabla ya kununua; (5) hifadhi blockchain transaction na broker receipt kwa accounting; (6) usitumie broker anayeahidi identity fraud, sanctions bypass au “untraceable” cash-out.

**Detection:** linganisha broker deposit addresses, unique amount/time, account/device na issued-card authorization au gift-code redemption; issuer na broker records huunganisha public chain na merchant.

## Virtual or merchant-locked card

**Mechanics:** issuer huunganisha generated PAN/token na real account, mara nyingi ikiweka merchant, amount au expiration restrictions.

**Pros:** huzuia kufichua PAN inayoweza kutumika tena; merchant compartmentation; spend limits na revocation rahisi; fraud control iliyokomaa.

**Cons:** issuer bado anajua payer, funding, merchant, device/IP na time; merchant huona account/delivery; refunds/recurring charges zinaweza kushindwa; si anonymous.

**Procedure:** (1) tumia feature rasmi ya regulated issuer; (2) tengeneza card kwa merchant/engagement moja; (3) weka limit na expiry ndogo inayofaa; (4) tumia billing sahihi inapohitajika; (5) thibitisha statement descriptor/refund behavior; (6) freeze/delete baada ya final settlement huku ukihifadhi audit evidence.

**Detection:** issuer token-to-account mapping, merchant authorization, device na delivery. Defenders hutumia merchant-specific reuse, velocity na account takeover signals.

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization hubadilisha PAN kwa constrained credential, mara nyingi ikiwa imefungwa kwa device, merchant au payment scenario.<sup>[[1]](#references)</sup>

**Pros:** merchant hapokei reusable PAN; device cryptography/dynamic data hupunguza cloning; inaweza kurevokewa bila kubadilisha card.

**Cons:** issuer, token service, wallet platform na network huhifadhi mappings/transactions; device/platform account na location vinaweza kumtambua payer.

**Procedure:** (1) enroll legitimate card kwenye official wallet; (2) linda platform account/device kwa strong authentication; (3) thibitisha device token/last digits wakati wa purchase; (4) zima location/analytics zisizo za lazima zinapowezekana; (5) disable lost devices/token mara moja; (6) kagua issuer na wallet records.

**Detection:** token requestor/device cryptogram na issuer mapping, wallet/account telemetry, merchant terminal na physical evidence.

## Payment app, marketplace wallet and centralized intermediary

**Mechanics:** service hudumisha accounts na transfers internally au kupitia bank/card rails; merchant anaweza kuona alias huku service ikiona pande zote.

**Pros:** convenience, dispute/refund mechanisms; recipient si lazima aone bank/card details.

**Cons:** centralized identity/social/transaction/device graph; freezes na legal process; counterparties wanaweza kufichua profile; data use inaweza kuzidi hitaji la payment.<sup>[[2]](#references)</sup>

**Procedure:** (1) soma identity, privacy, retention na buyer-protection terms; (2) punguza profile/contact synchronization ya hiari; (3) tumia separate truthful account pale terms zinaporuhusu; (4) enable MFA/alerts; (5) thibitisha recipient na privacy ya memo/profile; (6) export records na funga links zisizotumika.

**Detection:** provider account, device/IP, contact graph, funding/withdrawal, memo na merchant records. Alias ni pseudonymity kutoka kwa counterparty, si anonymity kutoka kwa platform.

## Bank transfer, ACH, wire and instant-account payment

**Mechanics:** regulated institutions huhamisha value kati ya identified accounts na kubadilishana payment data inayohitajika.

**Pros:** fast, accountable, reversible kwa hali chache, strong records; virtual account numbers zinaweza kupunguza merchant disclosure.

**Cons:** banks/processors wanajua pande zote; statements na references; si anonymous; cross-border na Travel Rule/AML data.

**Procedure:** tumia tu accountability inapokubalika: thibitisha beneficiary independently, punguza memo data ya hiari, tumia virtual account/reference inayotolewa na bank inapopatikana, enable alerts, hifadhi invoice na reconcile.

**Detection:** deterministic bank/payment records, beneficiary/account ownership, device/session na fraud controls. Hii ni baseline, si anonymity technique.

## Account and merchant compartmentation

**Mechanics:** lawful identities/accounts, email aliases, cards na delivery contexts zilizotenganishwa huzuia merchants wasiohusiana kuunganisha shughuli kwa urahisi, huku issuer/controller akihifadhi mapping.

**Pros:** hupunguza breach na cross-merchant linkage; rahisi kukagua; inaendana na regulated payments.

**Cons:** provider bado huunganisha compartments; recovery phone/device/IP na shipping vinaweza kuziunganisha tena; policy inaweza kukataza accounts nyingi.

**Procedure:** (1) fafanua purpose moja; (2) tengeneza aliases/subaccounts zinazofuata terms pekee; (3) tumia merchant-specific token/card; (4) zima cross-account contact/ad personalization; (5) hifadhi controller ledger iliyosimbwa; (6) retire identifiers baada ya refunds/retention needs kuisha.

**Detection:** providers huunganisha recovery, device, funding na IP; merchants huunganisha delivery, browser na account behavior. Defenders watofautishe compartmentation halali na synthetic identity fraud.

## Controlled red-team procurement

**Mechanics:** SOC haijui purchase, huku exercise controller akihifadhi legal entity, operator na infrastructure mapping.

**Pros:** realistic detection exercise; hakuna personal exposure; deconfliction na audit ya haraka.

**Cons:** si anonymous kwa organization/provider; governance overhead; leaks endapo controller ledger itashughulikiwa vibaya.

**Procedure:** (1) allocate engagement-specific organization card/wallet/budget; (2) tenganisha purchaser/operator roles; (3) rekodi asset, amount, service, purpose na kill date; (4) hifadhi attribution mapping kwa controller access ndogo; (5) usitumie false identity/mule/stolen funds; (6) reveal/reconcile indicators na refunds wakati wa closeout.

**Detection:** controller huunganisha provider invoice na asset; SOC hujaribu independent discovery kupitia domain, certificate, hosting na traffic badala ya cardholder data.

## Bitcoin address hygiene and coin control

**Mechanics:** fresh receive addresses, local labeling na selective UTXO spending hupunguza address reuse na accidental compartment merging kwenye public ledger.

**Pros:** inasaidiwa kwa upana; self-custodial; huepuka public linkage rahisi zaidi.

**Cons:** transactions/amounts zote hubaki public; common-input/change/timing na later consolidation huunganisha activity; acquisition/RPC/network records hubaki.

**Procedure:** (1) install/verify maintained wallet; (2) back up na test seed recovery; (3) tumia address mpya kwa kila invoice; (4) label source/purpose locally; (5) tumia coin control kuepuka kuunganisha contexts; (6) pendelea local node au privacy-aware connection; (7) preview change/fees na hifadhi lawful accounting.<sup>[[3]](#references)</sup>

**Detection:** address graph, common-input/change heuristics zikiwa na uncertainty, exact amount/time, consolidation, service deposits, node/RPC broadcast timing na off-chain records.

## Bitcoin Silent Payments

**Mechanics:** BIP 352 huruhusu receiver kuchapisha static code huku senders wakitengeneza unique Taproot outputs kupitia ECDH; observers wa nje hawawezi kuunganisha outputs moja kwa moja na code.<sup>[[4]](#references)</sup>

**Pros:** reusable public identifier bila address reuse; hakuna interactive address request au notification output; huchanganyika na Taproot outputs.

**Cons:** receiver scanning cost; wallet support hutofautiana; amount/sender graph na spending hubaki public; index server inaweza kuona scans.

**Procedure:** (1) chagua wallet ya sasa inayounga BIP 352; (2) back up/test descriptor na scanning recovery; (3) generate labeled code inapowezekana; (4) authenticate published code; (5) sender akague inputs na atume test ndogo; (6) receiver ascan kupitia own node inapowezekana; (7) hifadhi received UTXOs zikiwa zimetenganishwa.

**Detection:** kwa design output pekee haitambuliki kwa uhakika; analysts hutumia sender inputs, amount/time, later spending, wallet/network/index na counterparty records.

## PayJoin

**Mechanics:** payer na payee huchangia inputs kwenye payment transaction moja, hivyo kuvunja assumption kwamba inputs zote zina owner mmoja.<sup>[[5]](#references)</sup>

**Pros:** payment ya kawaida yenye privacy iliyoboreshwa; hudhoofisha common heuristic kwa graph nzima; hakuna ulazima wa equal-output crowd.

**Cons:** huhitaji interactive/support; receiver endpoint availability; amount na final transaction ni public; implementation na fallback metadata.

**Procedure:** (1) thibitisha wallets zote mbili zinaunga PayJoin version ileile; (2) authenticate invoice/endpoint; (3) anza kupitia wallet's PayJoin-enabled payment URI; (4) inspect final amount/fee na sign inputs zinazotarajiwa tu; (5) epuka manual transaction surgery; (6) verify broadcast na receipt; (7) rekodi fallback ikiwa negotiation itashindwa.

**Detection:** blockchain analysts wasilazimishe common-input clustering; endpoint/provider inaweza ku-log negotiation; tumia wallet/network na later-spend evidence badala ya transaction shape pekee.

## CoinJoin

**Mechanics:** participants wengi hushirikiana kuunda transaction yenye inputs/outputs nyingi, mara nyingi denominations zinazolingana, na kuongeza ambiguity ya input-output correspondence.

**Pros:** on-chain ambiguity set kubwa; self-custodial designs zipo; round structure inayoweza kupimwa.

**Cons:** coordinator/peer/network metadata; fees/liquidity; transaction shape inayotambulika; toxic change na later consolidation huharibu gains; legal/provider availability hutofautiana.

**Procedure:** (1) thibitisha current wallet/coordinator availability na legality; (2) install official wallet na back up; (3) tumia lawful UTXOs pekee; (4) elewa denomination, fee na coordinator model; (5) label na tenga change na mixed outputs; (6) usizi-consolidate pamoja; (7) route network traffic kama officially supported na hifadhi accounting.

**Detection:** tambua collaborative structure bila kudhani uhalifu; hesabu possible mappings/anonymity set, kisha fuatilia change/consolidation, service boundaries na network/coordinator records.

## Lightning Network

**Mechanics:** HTLC payments hupitia onion-routed channels; payment details nyingi hazichapishwi on chain, huku funding/closing na public channel information zikitangazwa.

**Pros:** haraka, fee ndogo; intermediaries kwa kawaida huona adjacent hops; routine payment details hubaki off chain.

**Cons:** sender/receiver na first/last hop wanajua zaidi; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets huwatambua users.

**Procedure:** (1) chagua self-custodial au custodial kwa uelewa; (2) thibitisha wallet/seed/channel recovery; (3) tumia invoice ya exact payment; (4) pendelea private channels/LSP features baada ya kusoma tradeoffs; (5) linda node IP kwa supported Tor inapohitajika; (6) epuka invoices zenye identifying information zinazotumika tena; (7) hifadhi channel na payment accounting.<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs, channel graph/probes, payment failure/timing na on-chain funding/closure; kutokuwepo kwa public transaction hakumaanishi hakuna records.

## BOLT 12 offers and route blinding

**Mechanics:** reusable offer huzalisha fresh invoices na inaweza kutangaza blinded paths ili payer asijue clear node/path ya receiver.

**Pros:** receiver privacy; reusable donation/payment endpoint bila static invoice; huunganishwa na Lightning onion routing.

**Cons:** wallet support hutofautiana; endpoints, selected hops na funding hubaki; public contact au network endpoint inaweza kumtambua receiver tena.

**Procedure:** (1) thibitisha matching BOLT 12 support; (2) authenticate offer; (3) request fresh invoice; (4) review amount/issuer/recurrence; (5) lipa kupitia wallet; (6) verify receipt/refund behavior; (7) punguza node alias/contact na hifadhi accounting.<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP na first/last-hop telemetry, offer distribution account, timing/value na funding graph; route blinding hupunguza kwa makusudi payer visibility.

## Monero

**Mechanics:** one-time stealth addresses huficha recipient linkage, RingCT huficha amounts na ring signatures hutoa sender ambiguity.

**Pros:** privacy ni default on chain; sender/receiver/amount confidentiality; dedicated wallet/node ecosystem iliyokomaa.

**Cons:** acquisition/off-ramp na endpoint/network/counterparty records; remote node huona queries/IP; exchange support/legal treatment hutofautiana; makosa madogo ya uendeshaji bado huunganisha contexts.

**Procedure:** (1) acquire lawfully na hifadhi basis/source; (2) install/verify official maintained wallet; (3) back up/test seed; (4) tumia local node au documented Tor/I2P remote-node path; (5) tumia subaddress mpya kwa kila payer/invoice; (6) label contexts locally; (7) disclose transaction proof/view access kwa makusudi pekee.<sup>[[8]](#references)</sup>

**Detection:** lenga exchange/merchant/device/network na seized-wallet evidence; protocol use yenyewe si suspicious na public chain imeundwa kufichua kidogo.

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs huthibitisha shielded transfers huku sender, receiver na amount zikiwa encrypted; transparent pools na pool transitions hubaki public.

**Pros:** shielded on-chain confidentiality imara; viewing keys zinaweza kusaidia scoped audit; protocol-enforced validity.

**Cons:** wallet/exchange support na pool choice halisi hutofautiana; transparent boundary timing/value correlation; network/RPC na endpoint hubaki.

**Procedure:** (1) chagua maintained Orchard shielded-by-default wallet; (2) verify/back up; (3) pata ZEC kihalali; (4) receive kwa supported Unified Address na confirm pool; (5) pendelea shielded-to-shielded; (6) tumia supported network privacy; (7) test viewing-key disclosure kwenye small wallet kabla ya audit.<sup>[[9]](#references)</sup>

**Detection:** transparent boundary na service records, wallet/network metadata na viewing keys pale zinapotolewa kihalali; usidhani malipo yote ya Unified Address yalikuwa shielded.

## Mimblewimble and Litecoin MWEB

**Mechanics:** confidential transactions huficha amounts na Mimblewimble-style aggregation huondoa conventional address-rich history; Litecoin hutekeleza optional extension block pamoja na transparent chain.

**Pros:** confidential amounts na fungibility iliyoboreshwa katika private domain; pruning/aggregation yenye ufanisi.

**Cons:** opt-in boundary peg-in/out ni public na inaweza kuunganishwa; wallet/exchange support; tofauti za interactive/address model; network na acquisition records.

**Procedure:** (1) chagua maintained wallet yenye MWEB support iliyo wazi; (2) verify/back up na test amount ndogo; (3) acquire lawfully; (4) peg into MWEB na verify balance domain; (5) transact na compatible receiver pekee; (6) epuka immediate distinctive peg-out; (7) hifadhi private audit records.<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value, exchange/wallet/node data na later transparent spends; internal confidential transfer details zimepunguzwa kwa makusudi.

## Ethereum zero-knowledge privacy applications

**Mechanics:** circuit huthibitisha statement—membership, valid note ownership au authorization—bila kufichua secret; verifier contract hui-check. Deposits, withdrawals, public inputs, events na gas bado vinaweza kufichua links.

**Pros:** programmable selective disclosure; applications zenye anonymous set; rules zinazoweza kuthibitishwa bila kufichua data yote.

**Cons:** contract/circuit bugs; anonymity set ndogo; public boundaries; RPC/IP/session/analytics/gas funding; application na sanctions/legal risk.

**Procedure:** (1) fafanua hasa proof inachoficha; (2) tumia maintained audited application pale ni halali; (3) inspect public inputs/events na deposit/withdraw rules; (4) tenga action wallet na gas sponsorship kama protocol inavyokusudia; (5) tumia privacy-aware RPC/network path; (6) test kwa value ndogo; (7) hifadhi compliance records.<sup>[[11]](#references)</sup>

**Detection:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics na eventual exchange/merchant boundary. Usidai ZK proof huficha fields zilizotangazwa kuwa public.

## Stablecoins

**Mechanics:** tokens huhamishwa kwenye public chain; centralized issuers wanaweza kufreeze/blacklist au redeem dhidi ya identified accounts.

**Pros:** price stability, liquidity na merchant support; settlement ya haraka; accounting rahisi.

**Cons:** transparent address/amount/contract graph; gas funding; issuer na exchange identity/control; sanctions screening; kwa kawaida anonymity dhaifu.

**Procedure:** zichukulie kama identified payment: tumia fresh business address kwa compartmentation tu, thibitisha token contract/network, test amount ndogo, linda wallet, tumia trusted RPC/local node, hifadhi basis/source na screen parties zinazohitajika.

**Detection:** complete token event graph, issuer freeze list/actions, exchange/RPC/device na gas-funding relationships.

## Cashu Chaumian e-cash

**Mechanics:** mint husaini kwa upofu bearer secrets zilizotengenezwa na client, zikiwa backed na mint's Bitcoin/Lightning reserves; inaweza kuzuia double-spend bila kuunganisha issuance moja kwa moja na redemption ya baadaye.

**Pros:** accountless bearer tokens; peer transfer ya papo hapo; mint haiwezi kuunganisha moja kwa moja blinded withdrawal na spend; tokens zinaweza kusafirishwa kama data/QR.

**Cons:** mint custody/solvency/censorship; bearer data loss/theft; denomination/timing na Lightning boundaries; network metadata; software ecosystem changa.<sup>[[12]](#references)</sup>

**Procedure:** (1) tumia official test mint au value ndogo inayoweza kupotezwa kwanza; (2) install maintained wallet na test backup/restore limitations; (3) authenticate mint na review custody/fees; (4) mint amount ndogo; (5) tuma token kupitia authenticated private channel/QR; (6) receiver abadilishe token kabla ya kuichukulia kuwa final; (7) redeem na reconcile. Usihifadhi value muhimu kwenye mint isiyoaminika.

**Detection:** mint huona network, issue/redeem/Lightning boundaries na spent-token set, lakini blinding huondoa direct token linkage; endpoints/messages na distinctive amount/timing vinaweza kurejesha links.

## Fedimint federated e-cash

**Mechanics:** threshold ya guardians hushikilia reserves na husaini e-cash kwa upofu; internal bearer transfers ni private kutoka kwa guardians, huku Lightning gateways zikiunganisha external payments.

**Pros:** custody iliyogawanywa; private internal transfer; community governance; guardian mmoja hawezi kudhibiti reserve chini ya threshold.

**Cons:** guardian quorum/custody/software risk; gateway huona invoices/timing; deposit/withdraw boundaries; client-state recovery complexity.

**Procedure:** (1) thibitisha federation invite/guardians/quorum/jurisdiction; (2) install maintained client na test recovery; (3) deposit small lawful amount; (4) tumia fresh internal payment requests; (5) mchukulie gateway kama observer wa Lightning; (6) test redemption; (7) hifadhi source/tax records nje ya public payment data.<sup>[[13]](#references)</sup>

**Detection:** federation huona aggregate issuance/redemption, gateways huona external invoices, Bitcoin/Lightning huonyesha boundaries, na endpoint/communication evidence inaweza kuunganisha internal transfers.

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash inalenga kumfanya payer asiweze kutambuliwa na merchants huku merchants na income zikiendelea kuwajibika.

**Pros:** payer privacy by design; ordinary currency; merchant accountability/refunds; hakuna speculative token inayohitajika.

**Cons:** deployments chache; exchange/bank huona funding; merchant huona order/delivery; wallet bearer/recovery risk; regulated operators.

**Procedure:** (1) tafuta exchange/merchant ya sasa kwa jurisdiction/currency; (2) soma KYC/fees/privacy; (3) install official wallet; (4) withdraw lawfully kutoka supported bank/exchange; (5) review merchant contract; (6) pay na hifadhi receipt/refund data; (7) epuka unnecessary merchant session identifiers.<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal na merchant deposit ni accountable boundaries; merchant order/device/delivery na timing vinaweza ku-correlate hata coins zikiwa blinded.

## Cross-chain bridge, atomic swap and decentralized exchange

**Mechanics:** contract/service hufunga/burn asset moja na kutoa/mint nyingine, au counterparties hubadilishana atomically. Huvunja single-ledger view, si economic continuity.

**Pros:** asset/network interoperability; inaweza kuepuka centralized custodian mmoja; matumizi ya kawaida ya portfolio/liquidity.

**Cons:** chains zote ni public; time/value/fees/liquidity na contracts hu-correlate; bridge/relayer/frontend/RPC records; smart-contract/counterparty na regulatory risk.

**Procedure for lawful swaps:** (1) thibitisha official contract/service na legal availability; (2) inspect custody/audit/fees/slippage; (3) tumia small test; (4) rekodi transaction IDs zote mbili na rate; (5) linda approvals; (6) reconcile destination asset na revoke approval zisizo za lazima. Usitumie swaps kuficha source of funds.

**Detection:** bridge deposit/withdraw events, unique amount minus fees, time order, liquidity, relayer/RPC/frontend na later service deposits.

## Centralized mixer or tumbler

**Mechanics:** service hupokea deposits kwenye pool na baadaye kurudisha units tofauti, ikijaribu kuficha direct input-output mapping.

**Pros:** kinadharia inaweza kuongeza transaction ambiguity.

**Cons:** operator anaweza kuiba/ku-log; entry/exit timing/value analysis; sanctions/money-transmission na criminal exposure; seizures hufichua mappings; taint/rejection risk.

**Procedure:** hakuna operational mixing guide inayotolewa. Zalisha graph kwa usalama kwa kupanua [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): tengeneza synthetic deposits, pooled outputs, fees na delays; wape analysts mappings zisizokamilika; pima heuristics zinazofanya kazi; kisha disclose ground truth.

**Detection:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs na downstream consolidation. Label probabilistic attribution.

## Peel chains, fan-out/fan-in and structuring

**Mechanics:** transactions zinazorudiwa huondoa small payments kutoka change, hugawa value kwenye addresses nyingi, huziunganisha kwa collectors au hugawa amounts ili kuepuka review.

**Pros:** huongeza workload na address count kwa analyst asiye na heuristics bora.

**Cons:** value/cadence/transaction continuity inayotambulika; consolidation na service endpoints; structuring yenyewe inaweza kuwa illegal; fees na operational errors.

**Procedure:** tumia synthetic CSV/testnet data pekee: generate source kubwa, repeated payment/change edges, parallel branches na collector mmoja; ongeza benign exchange-like examples; tune detection na document false positives.

**Detection:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint na off-chain records. Exchange hot wallets zinaweza kufanana na patterns hizi, hivyo context ni lazima.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mechanics:** mtu/account/company mwingine hupokea, hubadilisha au kutumia funds, akiingiza legal na operational layers kati ya controller na transaction.

**Pros to an adversary:** named account haitambui controller mara moja; inaweza kuunganisha cash, crypto, goods na jurisdictions.

**Cons:** identity fraud/money-laundering exposure; kila participant huongeza communications, bank/company/tax/shipping records, fees, inconsistency na witnesses; facilitator reuse huunda hubs.

**Procedure:** usiige kwa kutumia watu/accounts halisi. Jenga synthetic graph yenye controller, recruiter, mule, OTC, shell merchant na beneficiary; seed device/IP/message/bank edges; waombe investigators watofautishe account holder na controller na warekodi evidence confidence.

**Detection:** shared device/IP/recovery, unusual beneficiary/velocity, senders wengi wasiohusiana, immediate onward movement, company/director/invoice inconsistency, communications na cash/commodity delivery.

## NFTs, gambling, merchant goods and refund loops

**Mechanics:** value hubadilishwa kuwa self-priced asset, wagering balance, resalable goods au refunds ili kuunda transaction narrative tofauti.

**Pros to an adversary:** hubadilisha asset form na kuingiza marketplace/merchant intermediaries.

**Cons:** marketplace/account/device na wash-trade graph; odds/play na refund records; delivery/resale evidence; fees/losses; fraud/laundering liability.

**Procedure:** hakuna concealment workflow. Tumia synthetic marketplace data yenye related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument na common shipping; validate detection dhidi ya legitimate collectors/customers.

**Detection:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery na proceeds reconvergence.

## Physical bearer wallet or offline token transfer

**Mechanics:** device, paper/QR, hardware bearer instrument au e-cash token huhamisha control ya secret badala ya kutangaza payment wakati wa handover.

**Pros:** hakuna live network event wakati wa exchange; useful offline; physical cash-like custody.

**Cons:** copy/theft/loss na exclusivity isiyo na uhakika; later redemption/broadcast huunganisha; physical meeting/shipping; counterfeit/tamper risk.

**Procedure:** (1) tumia reviewed instrument/protocol pekee; (2) initialize/verify authenticity privately; (3) load lawful value ndogo tu; (4) transfer kwenye authorized context iliyorekodiwa; (5) receiver athibitishe au asweep prompt kulingana na protocol; (6) usidhani sender hakuhifadhi copy; (7) rekodi ownership/tax evidence privately.

**Detection:** purchase/funding na eventual sweep/redemption, device serial/tamper evidence, delivery/meeting na endpoint records.

## Merchant-scoped invoice or one-time payment request

**Mechanics:** merchant huunda request ya matumizi mara moja yenye amount, expiry na order reference. Payer huilipa kupitia supported rail bila kufichua reusable credential moja kwa moja kwa merchant; issuer au payment processor bado anaweza kuwatambua wote.

**Pros:** hupunguza credential reuse na accidental cross-merchant identifiers; exact amount/expiry hupunguza errors; inaendana na accounting na refunds za kawaida.

**Cons:** invoice, delivery, browser, processor na issuer bado huunganisha order; unique amount/time inaweza kuimarisha correlation; malicious payment links ni za kawaida.

**Procedure:** (1) authenticate merchant independently; (2) omba fresh invoice yenye exact amount, asset/network na expiry; (3) inspect destination na refund rules; (4) pay kutoka approved engagement compartment; (5) thibitisha merchant anakubali invoice hiyo hiyo; (6) hifadhi receipt na transaction reference; (7) expire badala ya kutumia request tena.

**Detection:** merchant na processor huunganisha invoice, session na settlement; unique amounts/timing na delivery humtambua payer. **Captured wallet/device:** invoice history hufichua counterparties na purpose; punguza memo data isiyo ya lazima, encrypt device na hifadhi authoritative accounting kwenye controlled finance system.

## Prepaid service credit and capability token

**Mechanics:** service hubadilisha conventional payment kuwa bounded internal credits au bearer capability. API/resource use ya baadaye inaweza kuepuka kuwasilisha original card kila request, lakini service mara nyingi inaweza kuunganisha issuance na redemption.

**Pros:** huweka kikomo cha spend na compromise loss; hutenganisha day-to-day workers na funding credential; huwezesha per-project budgets na revocation.

**Cons:** kwa kawaida ni pseudonymous, si anonymous; service database, redemption IP na unique usage pattern huunganisha activity; bearer tokens zinaweza kuibwa; refunds zinaweza kuhitaji original payer.

**Procedure:** (1) purchase credits kupitia organization account; (2) create project na budget moja; (3) issue narrow token yenye service, amount na expiry constraints; (4) hifadhi kwenye approved secret manager au workload identity path pekee; (5) test rejection nje ya scope na baada ya expiry; (6) monitor consumption; (7) revoke na reconcile unused value.

**Detection:** provider huunganisha funding account, project, token issuance na usage; defenders wa-alert geographic/process changes na anomalous consumption. **Captured node:** chukulia remaining capability inaweza kutumiwa; tumia short expiry, low balance, audience binding na immediate server-side revocation.

## Privacy Pass or blinded authorization token

**Mechanics:** issuer hutoa privacy-preserving authorization token ambayo origin inaweza ku-validate bila kuunganisha redemption na issuance. Inaweza kuwakilisha paid entitlement au rate-limited access, lakini si general currency. Architecture hutenganisha client, attester, issuer na origin roles na huonya kuwa IP/timing au collusion vinaweza kuondoa unlinkability.<sup>[[18]](#references)</sup>

**Pros:** unlinkable redemption kwa services zinazoiunga; hakuna reusable account cookie kwenye origin; cached tokens zinaweza kutenganisha issuance na use kwa wakati.

**Cons:** application-specific; issuer/attester trust na anonymity-set partitioning; IP na browser metadata hubaki; token theft au distinctive issuance timing inaweza ku-correlate use.

**Procedure:** (1) tumia implementation inayofuata relevant Privacy Pass token type; (2) fafanua entitlement inayothibitishwa na token; (3) tenganisha issuer na origin administration pale threat model inapohitaji; (4) punguza challenge metadata; (5) issue test tokens kadhaa na redeem kila mmoja mara moja kwenye owned origins; (6) linganisha logs kwa stable identifiers zilizokatazwa; (7) test replay, expiry na revocation/abuse controls.

**Detection:** origins huona redemption IP/time na token validity; issuers/attesters huona issuance context; analysts hupima timing na metadata partitions bila kudhani cryptographic break. **Captured client:** bearer tokens ambazo hazijatumika zinaweza kutumika; punguza value, lifetime na audience, na usiwahi kuhifadhi funding credential pamoja nazo.

## Delegated organization procurement or fiscal sponsor

**Mechanics:** authorized procurement team, reseller au fiscal sponsor huingia mkataba na kulipa huku operational team ikipokea service yenye mipaka. Hii ni role separation yenye records za kweli, si nominee au false identity.

**Pros:** vendors hawahitaji kupokea identity au personal payment details za kila operator; central compliance, tax na refund handling; budget na offboarding zilizo wazi.

**Cons:** sponsor anamjua beneficiary na purpose; contracts, approvals, delivery na accounts hubaki; delay/fees; separation dhaifu ikiwa mtu yuleyule anaendesha layers zote.

**Procedure:** (1) document business purpose, beneficiary na approving authority; (2) chagua intermediary aliyeidhinishwa na organization; (3) contract kwa truthful details; (4) provision project-scoped subaccount isiyo na personal billing credential; (5) tenga finance administrators na operators; (6) reconcile invoices na access; (7) terminate service na delegated access wakati wa closeout.

**Detection:** procurement, identity-provider, vendor na delivery records huunganisha chain. **Captured operational device:** inapaswa kufichua service project lakini si finance credentials; hifadhi invoices na payer identities kwenye finance system, si field nodes.

## Escrow or conditional settlement

**Mechanics:** trusted escrow agent au smart contract hushikilia value hadi conditions zilizorekodiwa zitimie. Inaweza kupunguza disclosure ya moja kwa moja kati ya payer na payee, huku escrow na underlying payment rails zikihifadhi relationship.

**Pros:** dispute na delivery protection; payer na merchant wanaweza kufichuana reusable credentials chache; release conditions zinazoweza kukaguliwa.

**Cons:** escrow custody/contract risk, fees na identity obligations; on-chain contracts ni public; order, shipping na dispute data hubaki; si anonymous kwa intermediary.

**Procedure:** (1) thibitisha legal entity, custody, fees, dispute forum na supported assets; (2) tengeneza milestone ya maandishi na refund path; (3) fund kutoka approved organization account; (4) verify receipt na release authorization independently; (5) release baada ya evidence pekee; (6) hifadhi complete audit record; (7) close unused permissions au contract approvals.

**Detection:** escrow account/contract events, funding na release time, beneficiary na dispute records hufichua transaction. **Captured device:** session tokens au contract approvals zinaweza kuruhusu release; hitaji separate approver/MFA na revoke active sessions ikipotea.

## Batched or pooled organization settlement

**Mechanics:** approved obligations nyingi hukusanywa na kulipwa katika bank au blockchain transactions chache, huku private internal ledger ikiassign kila share. Batching inaweza kupunguza public per-purchase detail lakini coordinator huhifadhi attribution yote.

**Pros:** fees ndogo; public graph edges chache; huficha individual line items kwa public observer wakati amounts zimeaggregated; internal accounting rahisi.

**Cons:** coordinator ni complete observer na high-value target; distinctive totals/timing zinaweza ku-correlate; custody na reconciliation risk; inaweza kufanana na structuring ikitumiwa vibaya.

**Procedure:** (1) define participants na lawful obligations kwenye accounting system; (2) weka regular business-justified batch window, si thresholds za kukwepa controls; (3) hitaji dual approval ya aggregate; (4) settle kwa authenticated recipients; (5) reconcile kila internal line na batch; (6) shughulikia refunds kama linked corrections; (7) linda ledger access na ihifadhi kulingana na policy.

**Detection:** coordinator ledger, approval na beneficiary records hutoa ground truth; public analysts watumie input/output/value/time clustering kwa tahadhari. **Captured payer device:** inapaswa kuwa na requisition yake tu, si pool signing key au participant ledger.

## Account-abstraction paymaster or sponsored gas

**Mechanics:** relayer/bundler huwasilisha smart-account operation na paymaster hulipa transaction fees, hivyo kuondoa direct native-gas funding edge kutoka user wallet. Huboresha graph property moja; operation, contract na service telemetry hubaki public au observable.<sup>[[19]](#references)</sup>

**Pros:** huondoa gas-funding link ya kawaida; huwezesha scoped sponsorship na rate limits; onboarding bora kwa legitimate privacy applications.

**Cons:** paymaster/bundler/RPC/front end zinaweza ku-correlate requests; contract events na public inputs hubaki; sponsorship policy hutambulisha cohort; malicious contracts au approvals zinaweza kuiba assets.

**Procedure:** (1) tumia audited maintained smart account na paymaster kwenye network sahihi; (2) inspect fields za public na sponsor logs; (3) limit sponsorship kwa contract, function, amount, nonce na expiry; (4) test low value; (5) submit kupitia intended privacy-aware path ya application; (6) verify operation na fee payer on chain; (7) revoke allowances/session keys na hifadhi compliance records.

**Detection:** unganisha UserOperation, EntryPoint, paymaster, bundler/RPC na application logs; cluster identical sponsorship policy kwa tahadhari. **Captured wallet:** session keys na pending approvals zinaweza kutumika hata bila gas; ziweke katika scope ndogo na revoke kupitia account recovery policy.

## Threshold or multisignature payment authorization

**Mechanics:** spending huhitaji threshold ya independent signers. Haifichi transaction, lakini hutenganisha payment authority na captured laptop, field node au operator mmoja.

**Pros:** compromise na insider resistance imara; accountable approval; hakuna single field device yenye signing authority kamili; recovery support.

**Cons:** coordination na availability; signer/device/account metadata inaweza kuunganisha participants; backup mbaya husababisha loss; public multisig patterns zinaweza kutambulika.

**Procedure:** (1) define signers, threshold, limits na recovery kabla ya funding; (2) initialize kwenye hardware/accounts tofauti; (3) verify addresses na backups independently; (4) wape field workloads unsigned requisition capability tu; (5) hitaji out-of-band review ya recipient, amount na purpose; (6) test recovery na one-signer loss kwa value ndogo; (7) rotate signer baada ya compromise.

**Detection:** approval system, signer device na public script/contract hutoa evidence; defenders wa-alert policy au signer-set changes. **Captured node:** inapaswa kufichua low-authority session key moja au unsigned request tu; usihifadhi quorum material pamoja.

## Closed-loop community or event currency

**Mechanics:** cooperative, conference au private test environment hutoa credits zinazoweza kutumiwa tu na enrolled participants. Internal transfer inaweza kufichua kidogo kwa global payment networks, huku operator akidhibiti issuance na redemption.

**Pros:** bounded economic domain; inaweza kujaribu offline au privacy-preserving payment UX; hupunguza external card exposure; experimental controls zilizo wazi.

**Cons:** anonymity set ndogo; operator na merchants huona activity; acceptance na redemption chache; licensing, consumer-protection na tax rules zinaweza kutumika hata kwa local value.

**Procedure:** (1) pata legal/compliance review na publish issuer terms; (2) enroll consenting test participants; (3) cap issuance na kataza cash-like misuse; (4) tumia fresh payment requests na punguza public participant identifiers; (5) rekodi aggregate reserves na private individual receipts; (6) test loss/refund/redemption; (7) close ledger na rudisha residual value kama ilivyoahidiwa.

**Detection:** issuer ledger, enrollment, merchant na redemption records hujenga upya flows; unusual circular transfers au rapid cash-out zihitaji review. **Captured wallet:** local balance na counterparties zinaweza kufichuliwa; cap value, encrypt state na support issuer-side freeze/reissue yenye auditable record.

## Bitcoin reusable payment codes and private payment instructions

**Mechanics:** BIP 47 payment codes hutumia reusable public identifier pamoja na ECDH-derived one-time deposit addresses; BIP 351 hubainisha private-payment instruction design mpya zaidi. Hupunguza public address reuse huku recipient akichapisha stable payment instructions. Notification, wallet support, funding na subsequent coin selection bado huathiri privacy.<sup>[[20]](#references)</sup>

**Pros:** instruction moja ya public inaweza kutoa addresses tofauti; recipient hahitaji kuchapisha kila invoice address; compatible wallets zinaweza kufuatilia derived payments; muhimu kwa lawful donors/customers wanaorudia.

**Cons:** wallet interoperability hutofautiana; notification transactions au published payment code huunganisha relationship context; sender, recipient na public graph bado huona transactions; careless consolidation au change handling huharibu faida.

**Procedure:** (1) thibitisha wallets zote zinaunga specification/version ileile; (2) back up na test recovery kwenye low-value wallet; (3) authenticate recipient payment code out of band; (4) tuma small lawful test; (5) thibitisha fresh derived address imetumika; (6) label relationship locally na apply coin control; (7) test recovery na refund behavior kabla ya kuitegemea.

**Detection:** analysts huchunguza notification patterns, funding/change, later consolidation na service boundaries; public-code publication hutambua recipient context hata deposit addresses zikitofautiana. **Capture-resilient OPSEC:** weka spend keys nje ya field devices na expose watch-only relationship view pekee. **Monitoring:** alert on unexpected notification transactions, reused derived addresses, wallet gap-limit/recovery errors na unplanned consolidation.

## EVM stealth addresses (ERC-5564)

**Mechanics:** sender hutengeneza one-time stealth account kutoka stealth meta-address ya recipient na kuchapisha announcement yenye ephemeral public key na view tag. Recipient huscan announcements kwa viewing key na hutengeneza spend key inayolingana. Recipient linkage huboreka, lakini sender, amount/token, gas, announcement na later spending hubaki visible.<sup>[[21]](#references)</sup>

**Pros:** fresh receiver address isiyohitaji interaction; reusable meta-address; viewing na spending roles zilizotenganishwa; hufanya kazi kwa supported EVM assets/applications.

**Cons:** announcement scanning na spam; funding gas ya address mpya inaweza kuiunganisha tena; sender anamjua recipient; public token/amount na eventual consolidation hubaki; implementation na wallet support hutofautiana.

**Procedure:** (1) tumia audited maintained implementation kwenye test network kwanza; (2) generate separate viewing na spending material na back up; (3) authenticate meta-address; (4) tuma low-value test na announcement; (5) scan na derive stealth account; (6) test supported gas sponsorship bila personal funding edge; (7) rekodi public fields na hifadhi lawful accounting.

**Detection:** fuata announcement caller, token/amount, timing, gas sponsor, spending na consolidation; view key inaweza kuthibitisha receipt bila kutoa spend. **Capture-resilient OPSEC:** networked scanner iwe na viewing role pekee inapowezekana; hifadhi spend na recovery keys kwingine. **Monitoring:** alert on malformed/spam announcements, view-key access, unexpected spend derivation na stealth outputs zinazohamishwa bila approval.

## Liquid Confidential Transactions

**Mechanics:** Liquid huficha output amounts na asset types kwa default kwa kutumia commitments na proofs huku transaction graph, input/output count, fee na block time zikiwa visible. Peg-in/peg-out na service boundaries hubaki linkable, na users wanaweza kufichua blinding data kwa kuchagua.<sup>[[22]](#references)</sup>

**Pros:** confidential amount na asset type kwa default; sidechain settlement ya haraka; selective audit kupitia blinding keys/descriptors; huficha commercial values nyeti kwa public observers.

**Cons:** graph structure na timing hubaki; federation/bridge na exchange trust; peg boundaries na unconfidential outputs; wallet/node/network records; receiver na sender wanajua transaction yao.

**Procedure:** (1) chagua maintained Liquid wallet na verify backup model; (2) tumia testnet au lawful amount ndogo; (3) receive kwenye confidential address na verify wallet imeonyesha output kuwa blinded; (4) tuma test confidential transaction; (5) inspect explorer fields zinazobaki public; (6) export blinding proof yenye scope inayohitajika kwa audit pekee; (7) document peg/exchange boundaries na reconcile funds.

**Detection:** analyze visible graph/fee/time, peg na exchange records, network metadata na later unblinding evidence; usidhanie hidden amount au asset. **Capture-resilient OPSEC:** tenga spend seed, blinding/view data na watch-only operations. **Monitoring:** alert on accidental unconfidential addresses, unknown peg requests, descriptor changes na unapproved unblinding-key export.

## General payment or state channel

**Mechanics:** participants hufunga funds, hubadilishana signed off-chain state updates na kuchapisha opening, closing au disputed state tu on chain. Intermediate payments hazitangazwi globally, lakini peers na routing/intermediary services huona sehemu yao na endpoints lazima zihifadhi latest enforceable state.<sup>[[23]](#references)</sup>

**Pros:** interactions nyingi za haraka, low-fee, private-to-public-ledger; global transaction detail kidogo; channel balance yenye mipaka; useful kwa metered services na counterparties wanaorudia.

**Cons:** channel peers wanajuana na wanaweza kuhifadhi updates; opening/closing/value/timing hu-correlate; online monitoring inaweza kuhitajika wakati wa challenge windows; implementation na liquidity risk; si anonymity set kubwa yenyewe.

**Procedure:** (1) chagua maintained audited implementation na elewa dispute window; (2) fungua low-value test channel kati ya owned parties; (3) exchange signed state updates zenye unique nonces; (4) back up latest enforceable state; (5) close cooperatively; (6) rehearse stale-state rejection kwenye testnet; (7) hifadhi accounting na channel-peer records.

**Detection:** public chain hufichua lifecycle/disputes; peers, watch services na application transport hufichua off-chain timing na parties. **Capture-resilient OPSEC:** cap hot balance na hifadhi latest signed state kwenye encrypted recoverable store iliyotenganishwa na field nodes. **Monitoring:** fuatilia stale-state publication, missed backup, peer-key change na approaching challenge deadline.

## Mobile carrier billing

**Mechanics:** online service hutoza purchase kwa mobile subscription au prepaid balance kupitia carrier billing system. Merchant anaweza kupokea carrier authorization badala ya card/bank details, huku carrier akijua subscriber/line, device/network context, merchant, amount na time.<sup>[[24]](#references)</sup>

**Pros:** hakuna card number kwa merchant; phone availability pana; hutumika kwa low-value digital goods; carrier anaweza kuweka cap na kureverse charges.

**Cons:** hutambulika sana kupitia SIM/account na mara nyingi device; limits ndogo na fees kubwa; merchant category restrictions; account takeover/SIM-swap risk; carrier na aggregator huunda complete transaction trail.

**Procedure:** (1) thibitisha availability, limit, fee na refund terms na organization carrier account; (2) enable kwenye dedicated organization line ikiwa justified; (3) weka lowest useful spend cap; (4) purchase benign test item; (5) verify merchant na carrier receipts; (6) zima recurring authorization; (7) reconcile na zima feature baada ya assessment.

**Detection:** carrier, aggregator na merchant records huunganisha line, subscriber, IP/device na charge; enterprise telecom invoices huifichua. **Capture-resilient OPSEC:** usitumie personal number na hitaji carrier-account MFA nje ya field device. **Monitoring:** enable instant charge/SIM-change alerts na simama kwenye unexpected premium-service enrollment, forwarding au account recovery.

## Open-banking payment initiation

**Mechanics:** kwa user consent iliyo wazi, regulated payment-initiation service provider (PISP) huomba account-servicing bank ianzishe transfer. Merchant huenda asipokee card credentials, lakini PISP na banks huhifadhi regulated payer, payee, consent, device na transaction records.<sup>[[25]](#references)</sup>

**Pros:** hakuna reusable card number checkout; strong bank authentication; exact account-to-account settlement; consent na status APIs; reconciliation iliyo wazi.

**Cons:** si anonymous kwa banks/PISP; payee mara nyingi huona legal account details au reference; phishing/redirect risk; jurisdiction na refund protections hutofautiana; consent metadata huongeza observer mwingine.

**Procedure:** (1) thibitisha PISP bado inadhibitiwa na merchant callback domain ni authentic; (2) anza kutoka merchant request; (3) review payee, amount, reference na requested consent bankini; (4) authorize payment hiyo moja tu; (5) verify final status independently; (6) revoke residual consent ikiwa ipo; (7) hifadhi receipt na reconcile.

**Detection:** bank/PISP/merchant logs na transfer references hutoa attribution imara. **Capture-resilient OPSEC:** weka banking authentication na recovery nje ya operational/field devices; device iwe na paid-service entitlement pekee. **Monitoring:** tumia bank transaction/consent alerts na chunguza new PISP grants, changed payee au status callbacks nje ya session inayotarajiwa.

## Platform wallet, app-store balance or in-app credit

**Mechanics:** platform humtoza user au redeem account credit, kisha hutoa signed receipt au entitlement kwa application. App developer huenda asipokee original funding instrument, huku platform ikiunganisha account, device, funding, product na redemption.<sup>[[26]](#references)</sup>

**Pros:** merchant/developer hapokei primary PAN; fraud/refund na family/business controls; small prepaid balance inaweza kuweka exposure cap; signed receipts hurahisisha entitlement verification.

**Cons:** platform account ni identity na behavior hub yenye nguvu; device na storefront geography; gift-balance purchase/redemption trail; cash-out chache; fraud controls zinaweza kufreeze funds; si money ya cross-platform.

**Procedure:** (1) tumia organization-managed platform account pale policy inaporuhusu; (2) review funding, region, refund na transferable-value rules; (3) ongeza approved budget pekee; (4) purchase benign product kupitia official store; (5) verify application inapokea receipt fields zinazotarajiwa tu; (6) zima recurring purchase; (7) reconcile na remove account kutoka operational hardware.

**Detection:** platform receipts/server notifications, account/device login na funding records hujenga upya purchase. **Capture-resilient OPSEC:** usiingize personal store account kwenye field node; toa scoped app entitlement pekee inapowezekana. **Monitoring:** enable new-device/purchase alerts na chunguza receipt replay, family/account changes au unexpected restore events.

## Mutual credit, clearing or periodic net settlement

**Mechanics:** participants huandika obligations kwenye private ledger na mara kwa mara husettle net position pekee. Individual service events si lazima zitengeneze public payments tofauti, lakini ledger operator na counterparties huhifadhi attribution ya kina.

**Pros:** external transactions na fees chache; public observers huona net settlement pekee; inafaa kwa organizations zinazorudia; credit limits zilizo wazi hupunguza exposure.

**Cons:** centralized ledger ni evidence kamili na fraud target; counterparty/default risk; legal/accounting/tax duties; membership ndogo; unusual net transfers bado zinaweza kufichua relationships.

**Procedure:** (1) tumia identified consenting organizations pekee kwa legal/accounting approval; (2) define unit, credit limit, settlement interval na dispute rules; (3) rekodi kila obligation kwa immutable approval; (4) finance roles tofauti zihesabu na kuidhinisha net positions; (5) settle kupitia ordinary lawful rail; (6) reconcile individual lines na settlement; (7) close access na hifadhi records kulingana na policy.

**Detection:** ledger, invoices, approvals na final bank/chain settlement hutoa ground truth; analysts wasidhanie gross activity iliyokosekana kutokana na net transfer pekee. **Capture-resilient OPSEC:** operational devices ziwasilishe bounded requisitions lakini zisiweze ku-edit balances au ku-authorize settlement. **Monitoring:** alert on credit-limit breach, backdated entries, administrator changes, reconciliation mismatch na settlement kwa beneficiary mpya.

## Capture/compromise exposure matrix

Hii hutumia seizure/loss test kwa kila family. Lengo ni kupunguza spend authority na disclosure ya identity isiyohusiana huku lawful accounting ikiendelea—si kufuta transactions au kuzuia investigation.

| Technique family | Wallet/device/account iliyotekwa inaweza kufichua | Minimum authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value na physical contacts | beba approved amount tu; tenga private accounting; ripoti loss haraka; hakuna false records |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption na account/session tokens | low balance; purpose moja; truthful registration; issuer freeze/revocation inapopatikana |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery na merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; shared recovery account hairuhusiwi |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices na project | role separation; least-privilege subaccount; finance credentials kamwe zisiwe operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator au dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph na network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP na payment database | minimal hot balance; encrypted backup; separate node identity; close/recover kwa documented plan |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC na boundary transactions | separate spend/view roles; hardware support inapopatikana; hakuna exchange session kwenye field node |
| Stablecoins, swaps, bridges and DEX | transparent graph, approvals, RPC/front-end state na destination assets | revoke allowances; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; encrypted backup kulingana na protocol; redeem/reissue; usicolocate funding credential |
| Paymaster, multisig/threshold | session key, one signer, pending operations na sponsor policy | narrow session key; independent quorum; signer rotation; field device isifike threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph na participant records | hakuna operational use; emulate kwa synthetic/testnet evidence pekee |
| Community/event currency | enrollment, local balance, counterparties na redemption | capped value; issuer freeze/reissue; consent na private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements na derived outputs | watch/view-only network role; offline/hardware spend role; hakuna personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries na disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device na funding source | organization account; external MFA; low limit; hakuna personal account kwenye field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals na settlement ledger | operational requisition only; separate immutable ledger na dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial, compliance review au wallet kwenda offline hakuthibitishi kuwa investigation ipo. Monitor accounts, ledgers na infrastructure ambayo organization ina haki ya kuobserve pekee; usiwahi ku-probe providers au counterparties kujaribu kujua kama wanashirikiana na investigators.

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund au loss report | missing instrument, redemption nje ya approved order, altered receipt au custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap au recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice na consumption | cross-project token, unknown admin, limit breach, invoice mismatch au unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation na beneficiary change | altered amount/payee, backdated ledger, unilateral release au unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels na consolidation | unknown spend, reused recipient output, wallet gap/recovery failure au unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure au coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP na chain dispute | unknown invoice payment, peer-key change, stale close au approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor na boundary transaction | spend without approval, transparent/unconfidential downgrade, key export au unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key na issuer action | wrong contract/public field, unknown approval/spend, paymaster change au issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway na bearer balance | unknown redemption, mint key/terms change, restore failure au balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate na destination | contract/route mismatch, unlimited approval, missing destination au bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum na recovery audit | unknown proposal/signer, threshold reduction, recovery activation au policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | synthetic lab ground truth na detection output only | real account, person au value yoyote kuingia emulation: stop immediately |

## Selection and verification workflow

1. Taja ni party gani haipaswi kujua field ipi.
2. Tambua issuer/mint/custodian, public ledger, network/RPC, merchant na physical observers.
3. Thibitisha current support, legality, limits, custody, recovery na refund behavior.
4. Tumia small lawful end-to-end test.
5. Inspect merchant receipt, provider statement, public chain na wallet/node logs.
6. Test backup/recovery na deliberate audit disclosure.
7. Hifadhi source, ownership, tax, sanctions na engagement records zinazohitajika zikiwa sahihi lakini access-controlled.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Observations on data collection by large payment platforms](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Protect your privacy](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — A Simple Payjoin Proposal](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technical specifications and network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Building privacy applications with zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol and privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — How it works](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers and users of virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information and crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — The Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
