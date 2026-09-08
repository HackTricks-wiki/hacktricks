# Katalogi ya Mbinu za Malipo Yasiyotambulisha Mtumiaji

Katalogi hii inahusu **familia** za malipo, kuanzia pesa taslimu za kawaida hadi e-cash yenye blind-signature na obfuscation kwenye public-chain. “Anonymous” humaanisha tu kutotambulika kwa mtazamaji fulani aliyetajwa. Merchant, issuer, mint, exchange, blockchain analyst, network provider, mwajiri na mtazamaji wa kimwili huona taarifa tofauti.

Taratibu zilizo hapa ni za fedha halali, akaunti zenye taarifa za kweli na procurement iliyoidhinishwa. Mbinu ambazo katika mifano iliyotajwa zilitumika kwa laundering, kukwepa sanctions au udanganyifu wa utambulisho zinaelezwa na kutambuliwa, lakini utaratibu wake ni zoezi la synthetic forensic, si maagizo ya kutenda uhalifu.

## Coverage matrix

| Family | Sifa kuu ya privacy | Mtazamaji/tegemeo kuu | Matumizi |
|---|---|---|---|
| Cash and cash equivalents | hakuna rekodi ya mbali ya payment-network | mpokeaji na mazingira ya kimwili | lawful workflow |
| Prepaid/gift/voucher value | hutenganisha redemption na primary card | seller, issuer na redemption service | lawful workflow, hutegemea jurisdiction |
| Virtual/tokenized card | huficha PAN inayotumika tena au hutenganisha merchants | issuer/network/wallet bado humtambua mlipaji | lawful workflow |
| Payment app/intermediary | merchant anaweza kuona alias/intermediary | app hukusanya identity/device/transaction | comparison baseline |
| Bitcoin hygiene/Silent Payments | pseudonyms na kutounganisha mpokeaji | public graph na wallet/network boundary | deployable |
| PayJoin/CoinJoin | hudhoofisha heuristics za common ownership/linkage | participants/coordinator/network/public graph | deployable where supported; legal review |
| Lightning/BOLT 12 | off-chain routing na kupunguza receiver-path | endpoints, hops, services na channel graph | deployable where supported |
| Monero/Zcash/MWEB | on-chain confidentiality ya protocol | acquisition, endpoint, network na boundary bado zipo | deployable where lawful/supported |
| Ethereum ZK application | huficha statement/action link maalum | public inputs, RPC, relayer na app | application-specific |
| Cashu/Fedimint/Taler | payer privacy kupitia blind-signature | mint/federation/exchange custody na boundaries | emerging/deployment-specific |
| Stablecoins | digital settlement rahisi | transparent chain pamoja na issuer freeze/control | not anonymous baseline |
| Swaps/bridges/DEX | huhamisha value kati ya assets/chains | graphs zote mbili, contracts na providers | forensic mechanics; ordinary lawful swaps only |
| Mixers/peel/structuring | huongeza utata wa graph/work | entry/exit graph na service records | synthetic detection exercise only |
| Nominees/mules/OTC/fronts | huingiza intermediaries wa watu/biashara | facilitators, banks, communications | criminal-abuse analysis only |
| Reusable/stealth payment addresses | address mpya ya mpokeaji kwa kila malipo | public announcement/notification na wallet boundaries | deployable where supported |
| Confidential sidechain/state channel | huficha amount/asset au updates za kati | peers, bridge/federation na lifecycle settlement | protocol-specific |
| Carrier/open-banking/platform billing | huficha primary card kwa merchant | carrier, bank/PISP au platform humtambua mteja | ordinary identified payment |
| Mutual credit/net settlement | rekodi chache za external settlement | private ledger operator ana mapping yote | identified participants only |

## Cash

**Mechanics:** physical bearer value hubadilishwa bila issuer authorization ya mtandaoni au public ledger.

**Pros:** merchant hahitaji kujua bank/card identity; hakuna remote transaction graph; inaeleweka na huwa final.

**Cons:** face-to-face pekee; wizi/upotevu; change/receipt/serial au reporting controls; withdrawal, cameras, witnesses na location bado vinaweza kumuunganisha mlipaji.

**Procedure:** (1) thibitisha kuwa cash ni halali na inakubaliwa, pamoja na kanuni za kiasi/reporting; (2) withdraw au ipokee kihalali na weka accounting ya faragha; (3) lipa merchant wa kawaida bila loyalty/account identifiers zisizo za lazima; (4) omba receipt inayohitajika tu; (5) epuka shipping/account data ikiwa ununuzi hauihitaji; (6) hifadhi ndani rekodi ya legitimate business purpose.

**Detection:** linganisha till/receipt/inventory, cameras na access logs kulingana na policy; chunguza refunds za cash zisizo za kawaida au kiasi kinachojirudia chini kidogo ya control, bila kuchukulia matumizi ya kawaida ya cash kuwa ya kutiliwa shaka.

## Money order, postal order, cashier instrument and cash on delivery

**Mechanics:** regulated issuer hubadilisha cash/account funds kuwa instrument yenye namba, inayolipwa kwa recipient aliyetajwa; COD huahirisha collection hadi delivery.

**Pros:** recipient huenda asipate primary bank/card number ya payer; hutumika cash isiposafirishwa kwa mbali; receipt iliyo wazi.

**Cons:** issuer/retailer huhifadhi purchase/identity data inapohitajika; serial tracking; recipient/delivery address; loss/fraud na vikwazo vya eneo; kwa kawaida si anonymous.

**Procedure:** (1) kagua rules, limits, identification na recipient acceptance ya issuer; (2) nunua kwa taarifa za kweli na fedha halali; (3) jaza payee/amount mara moja; (4) hifadhi serial/receipt; (5) tumia delivery yenye tracking inayolingana na thamani; (6) linganisha redemption/refund.

**Detection:** issuer purchase/redemption record, instrument serial, retailer/camera, shipping na recipient account; flag alteration, duplicate serials na redemption ya haraka isiyolingana kijiografia.

## Open-loop prepaid card

**Mechanics:** credential yenye nembo ya network hu-authorize dhidi ya prepaid balance badala ya primary credit account.

**Pros:** hupunguza merchant exposure na hasara; hutenganisha merchant na main PAN; hutumika online inapokubaliwa.

**Cons:** purchase/activation/reload/registration na device records; KYC na limits hutofautiana; billing-address failures; cash-out/refund restrictions; “no name” haimaanishi hakuna issuer record.

**Procedure:** (1) thibitisha issuer, fees, KYC, geography na online/recurring support; (2) ipate kupitia seller aliyeidhinishwa kwa fedha halali; (3) sajili taarifa za kweli zinazohitajika; (4) itumie kwa purpose moja iliyotenganishwa; (5) usipange loads au kutengeneza residency ya uongo; (6) hifadhi ushahidi wa purchase/expense na ifunge kulingana na masharti.

**Detection:** unganisha seller/activation, funding, device/IP, merchant authorization, balance checks na redemption/refund. Patterns ni muhimu zaidi kuliko lebo ya prepaid.

## Closed-loop gift card, voucher and transferable service credit

**Mechanics:** value yenye namba inaweza kutumika kwa merchant/service au ecosystem moja tu. Airtime/game/store credits ni variants.

**Pros:** recipient merchant anaweza kuona code/balance pekee; blast radius ndogo; gifting na budget separation rahisi.

**Cons:** seller na service hu-log purchase/activation/redemption; account/device/delivery bado huunganisha; scams, resale discounts na expiry/region limits; refund rights dhaifu.

**Procedure:** (1) nunua kupitia authorized channels pekee; (2) rekodi code value bila kufichua secret; (3) usiunganishe loyalty account yenye utambulisho ikiwa si lazima; (4) redeem kupitia merchant account/context tofauti iliyo halali; (5) hifadhi receipt hadi ikubaliwe; (6) usinunue codes kwa ombi lisilotarajiwa la “tax/support/ransom”.

**Detection:** issuance/redemption time ya code, device/account convergence, bulk/threshold-pattern purchase, device moja inayokagua balances nyingi na redemption ya haraka kutoka maeneo ya mbali.

## Cryptocurrency-funded card or gift-code broker

**Mechanics:** intermediary hupokea cryptocurrency na kutoa card, voucher au merchant code. Hii ni cross-rail conversion: merchant huona card/gift value ya kawaida, broker akiunganisha on-chain deposit na issuance/delivery.

**Pros:** merchant hapokei funding wallet; husaidia merchants halali wasiokubali crypto; stored value yenye mipaka.

**Cons:** si anonymous kwa broker/issuer; KYC, sanctions, exchange na card-program rules; public deposit graph; account/device/email na code redemption huunganisha pande zote; scam/insolvency risk.

**Procedure:** (1) thibitisha legal entity, card issuer, jurisdiction, KYC, fees na refund policy; (2) tumia fedha halali zenye documentation; (3) jaribu denomination ndogo zaidi; (4) thibitisha network/merchant restrictions kabla ya purchase; (5) hifadhi blockchain transaction na broker receipt kwa accounting; (6) usitumie broker anayeahidi identity fraud, sanctions bypass au “untraceable” cash-out.

**Detection:** correlate broker deposit addresses, unique amount/time, account/device na issued-card authorization au gift-code redemption; issuer na broker records huunganisha public chain na merchant.

## Virtual or merchant-locked card

**Mechanics:** issuer huunganisha PAN/token iliyotengenezwa na account halisi, mara nyingi ikiweka merchant, amount au expiration limits.

**Pros:** huzuia kufichuliwa kwa PAN inayotumika tena; merchant compartmentation; spend limits na revocation rahisi; fraud control iliyokomaa.

**Cons:** issuer bado anajua payer, funding, merchant, device/IP na time; merchant huona account/delivery; refunds/recurring charges zinaweza kushindwa; si anonymous.

**Procedure:** (1) tumia feature rasmi ya regulated issuer; (2) tengeneza card kwa merchant/engagement moja; (3) weka limit na expiry ndogo inayofaa; (4) tumia billing sahihi inapohitajika; (5) thibitisha statement descriptor/refund behavior; (6) freeze/delete baada ya settlement ya mwisho huku ukihifadhi audit evidence.

**Detection:** issuer token-to-account mapping, merchant authorization, device na delivery. Defenders hutumia merchant-specific reuse, velocity na account-takeover signals.

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization hubadilisha PAN kwa credential yenye mipaka, mara nyingi iliyofungwa kwa device, merchant au payment scenario.<sup>[[1]](#references)</sup>

**Pros:** merchant hapokei reusable PAN; device cryptography/dynamic data hupunguza cloning; inaweza revocable bila kubadilisha card.

**Cons:** issuer, token service, wallet platform na network huhifadhi mappings/transactions; device/platform account na location vinaweza kumtambua payer.

**Procedure:** (1) enroll legitimate card kwenye official wallet; (2) linda platform account/device kwa strong authentication; (3) thibitisha device token/last digits wakati wa purchase; (4) zima location/analytics zisizo za lazima inapowezekana; (5) disable lost devices/token mara moja; (6) kagua issuer na wallet records.

**Detection:** token requestor/device cryptogram na issuer mapping, wallet/account telemetry, merchant terminal na physical evidence.

## Payment app, marketplace wallet and centralized intermediary

**Mechanics:** service hudumisha accounts na transfers internally au kupitia bank/card rails; merchant anaweza kuona alias huku service ikiona pande zote mbili.

**Pros:** urahisi, dispute/refund mechanisms, recipient si lazima aone bank/card details.

**Cons:** centralized identity/social/transaction/device graph; freezes na legal process; counterparties wanaweza kufichua profile; data use inaweza kuzidi mahitaji ya payment.<sup>[[2]](#references)</sup>

**Procedure:** (1) soma masharti ya identity, privacy, retention na buyer protection; (2) punguza profile/contact synchronization ya hiari; (3) tumia separate truthful account tu masharti yanaporuhusu; (4) enable MFA/alerts; (5) thibitisha recipient na privacy ya memo/profile; (6) export records na funga links zisizotumika.

**Detection:** provider account, device/IP, contact graph, funding/withdrawal, memo na merchant records. Alias ni pseudonymity kwa counterparty, si anonymity kwa platform.

## Bank transfer, ACH, wire and instant-account payment

**Mechanics:** regulated institutions huhamisha value kati ya identified accounts na kubadilishana payment data inayohitajika.

**Pros:** haraka, accountable, wakati mwingine reversible, records nzuri; virtual account numbers zinaweza kupunguza taarifa anazoona merchant.

**Cons:** banks/processors wanajua pande zote; statements na references; si anonymous; cross-border na Travel Rule/AML data.

**Procedure:** tumia tu accountability inapokubalika: thibitisha beneficiary kwa njia huru, punguza memo data ya hiari, tumia virtual account/reference ya bank inapopatikana, enable alerts, hifadhi invoice na reconcile.

**Detection:** deterministic bank/payment records, beneficiary/account ownership, device/session na fraud controls. Hii ni baseline, si anonymity technique.

## Account and merchant compartmentation

**Mechanics:** identities/accounts, email aliases, cards na delivery contexts tofauti huzuia merchants wasiohusiana kuunganisha activity kwa urahisi, huku issuer/controller akihifadhi mapping.

**Pros:** hupunguza breach na cross-merchant linkage; ni rahisi ku-audit; inaendana na regulated payments.

**Cons:** provider bado huunganisha compartments; recovery phone/device/IP na shipping vinaweza kuviunganisha; policy inaweza kuzuia multiple accounts.

**Procedure:** (1) fafanua purpose moja; (2) tengeneza aliases/subaccounts zinazofuata masharti; (3) tumia merchant-specific token/card; (4) zima cross-account contact/ad personalization; (5) hifadhi encrypted controller ledger; (6) retire identifiers baada ya refunds/retention needs kuisha.

**Detection:** providers huunganisha recovery, device, funding na IP; merchants huunganisha delivery, browser na account behavior. Defenders watofautishe compartmentation halali na synthetic identity fraud.

## Controlled red-team procurement

**Mechanics:** SOC haijui purchase, huku exercise controller akihifadhi mapping ya legal entity, operator na infrastructure.

**Pros:** detection exercise halisi; hakuna personal exposure; deconfliction na audit ya haraka.

**Cons:** si anonymous kwa organization/provider; governance overhead; leaks endapo controller ledger itashughulikiwa vibaya.

**Procedure:** (1) tenga organization card/wallet/budget ya engagement; (2) tenga majukumu ya purchaser/operator; (3) rekodi asset, amount, service, purpose na kill date; (4) hifadhi attribution mapping kwa controller access iliyopunguzwa; (5) usitumie false identity/mule/stolen funds; (6) reveal/reconcile indicators na refunds wakati wa closeout.

**Detection:** controller huunganisha provider invoice na asset; SOC hujaribu discovery huru kupitia domain, certificate, hosting na traffic badala ya cardholder data.

## Bitcoin address hygiene and coin control

**Mechanics:** fresh receive addresses, local labeling na selective UTXO spending hupunguza address reuse na accidental compartment merging kwenye public ledger.

**Pros:** ina support pana; self-custodial; huepuka public linkage rahisi.

**Cons:** transactions/amounts zote bado ziko public; common-input/change/timing na consolidation ya baadaye huunganisha activity; acquisition/RPC/network records bado zipo.

**Procedure:** (1) install/verify wallet inayodumishwa; (2) backup na test seed recovery; (3) tumia address mpya kwa kila invoice; (4) label source/purpose locally; (5) tumia coin control kuepuka kuunganisha contexts; (6) pendelea local node au privacy-aware connection; (7) preview change/fees na hifadhi lawful accounting.<sup>[[3]](#references)</sup>

**Detection:** address graph, common-input/change heuristics zenye uncertainty, exact amount/time, consolidation, service deposits, node/RPC broadcast timing na off-chain records.

## Bitcoin Silent Payments

**Mechanics:** BIP 352 huruhusu receiver kuchapisha static code huku senders wakitengeneza unique Taproot outputs kupitia ECDH; observers wa nje hawawezi kuunganisha outputs moja kwa moja na code.<sup>[[4]](#references)</sup>

**Pros:** reusable public identifier bila address reuse; hakuna interactive address request au notification output; huonekana kama Taproot outputs za kawaida.

**Cons:** receiver scanning cost; wallet support hutofautiana; amount/sender graph na spending bado ni public; index server inaweza kuona scans.

**Procedure:** (1) chagua wallet ya sasa inayounga mkono BIP 352; (2) backup/test descriptor na scanning recovery; (3) tengeneza labeled code inapoungwa mkono; (4) authenticate published code; (5) sender akague inputs na atume test ndogo; (6) receiver ascan ikiwezekana kupitia own node; (7) weka received UTXOs zikiwa separated.

**Detection:** kwa design output pekee haitambuliki kwa uhakika; analysts hutumia sender inputs, amount/time, later spending, wallet/network/index na counterparty records.

## PayJoin

**Mechanics:** payer na payee huchangia inputs kwenye payment transaction moja, hivyo kuvunja dhana kwamba inputs zote zina owner mmoja.<sup>[[5]](#references)</sup>

**Pros:** payment ya kawaida yenye privacy bora; hudhoofisha heuristic ya common ownership; haihitaji equal-output crowd.

**Cons:** interactive/support requirement; receiver endpoint availability; amount na final transaction ni public; implementation na fallback metadata.

**Procedure:** (1) thibitisha wallets zote mbili zinazodumishwa zinaunga mkono PayJoin version moja; (2) authenticate invoice/endpoint; (3) anza kupitia wallet's PayJoin-enabled payment URI; (4) kagua final amount/fee na sign inputs zinazotarajiwa tu; (5) usifanye manual transaction surgery; (6) verify broadcast na receipt; (7) rekodi fallback negotiation ikishindwa.

**Detection:** blockchain analysts wasilazimishe common-input clustering; endpoint/provider inaweza ku-log negotiation; tumia wallet/network na later-spend evidence, si transaction shape pekee.

## CoinJoin

**Mechanics:** participants wengi hutengeneza transaction kwa pamoja ikiwa na inputs/outputs nyingi, mara nyingi denominations sawa, na kuongeza utata wa input-output correspondence.

**Pros:** on-chain ambiguity set kubwa; self-custodial designs zipo; round structure inayoweza kupimika.

**Cons:** coordinator/peer/network metadata; fees/liquidity; transaction shape inayotambulika; toxic change na later consolidation huharibu faida; legal/provider availability hutofautiana.

**Procedure:** (1) thibitisha wallet/coordinator availability na legality; (2) install official wallet na backup; (3) tumia lawful UTXOs pekee; (4) elewa denomination, fee na coordinator model; (5) weka change na mixed outputs zikiwa labeled/separate; (6) usiwahi kuzi-consolidate pamoja; (7) elekeza network traffic kulingana na support rasmi na hifadhi accounting.

**Detection:** tambua collaborative structure bila kudhani uhalifu; hesabu possible mappings/anonymity set, kisha fuatilia change/consolidation, service boundaries na network/coordinator records.

## Lightning Network

**Mechanics:** HTLC payments hupitia onion-routed channels; payment details nyingi hazichapishwi on chain, huku funding/closing na public channel information zikiendelea kuonekana.

**Pros:** haraka na fee ndogo; intermediaries kwa kawaida huona hops za karibu; routine payment details hubaki off chain.

**Cons:** sender/receiver na first/last hop hujua zaidi; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets huwatambua users.

**Procedure:** (1) chagua self-custodial au custodial kwa uelewa; (2) verify wallet/seed/channel recovery; (3) tumia invoice ya exact payment; (4) pendelea private channels/LSP features baada ya kusoma tradeoffs; (5) linda node IP kwa Tor inayoungwa mkono inapohitajika; (6) epuka reusable identifying invoices; (7) hifadhi channel na payment accounting.<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs, channel graph/probes, payment failure/timing na on-chain funding/closure; kutokuwepo kwa public transaction hakumaanishi hakuna records.

## BOLT 12 offers and route blinding

**Mechanics:** reusable offer hutengeneza fresh invoices na inaweza kutangaza blinded paths ili payer asijue clear node/path ya receiver.

**Pros:** receiver privacy; reusable donation/payment endpoint bila static invoice; huunganishwa na Lightning onion routing.

**Cons:** wallet support hutofautiana; endpoints, selected hops na funding bado zipo; public contact au network endpoint inaweza kumtambua receiver.

**Procedure:** (1) thibitisha BOLT 12 support inayolingana; (2) authenticate offer; (3) omba fresh invoice; (4) kagua amount/issuer/recurrence; (5) lipa kupitia wallet; (6) verify receipt/refund behavior; (7) punguza node alias/contact na hifadhi accounting.<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP na first/last-hop telemetry, offer distribution account, timing/value na funding graph; route blinding hupunguza kwa makusudi visibility ya payer.

## Monero

**Mechanics:** one-time stealth addresses huficha recipient linkage, RingCT huficha amounts na ring signatures hutoa sender ambiguity.

**Pros:** privacy ni default on chain; sender/receiver/amount confidentiality; mature wallet/node ecosystem maalum.

**Cons:** acquisition/off-ramp na endpoint/network/counterparty records; remote node huona queries/IP; exchange support/legal treatment hutofautiana; makosa madogo ya operation bado huunganisha contexts.

**Procedure:** (1) acquire kihalali na hifadhi basis/source; (2) install/verify official maintained wallet; (3) backup/test seed; (4) tumia local node au documented Tor/I2P remote-node path; (5) tumia new subaddress kwa kila payer/invoice; (6) label contexts locally; (7) disclose transaction proof/view access kwa makusudi tu.<sup>[[8]](#references)</sup>

**Detection:** lenga exchange/merchant/device/network na seized-wallet evidence; matumizi ya protocol pekee si suspicious, na public chain kwa makusudi hufichua kidogo.

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs huthibitisha shielded transfers huku sender, receiver na amount zikiwa encrypted; transparent pools na pool transitions hubaki public.

**Pros:** shielded on-chain confidentiality yenye nguvu; viewing keys kwa scoped audit; validity inayotekelezwa na protocol.

**Cons:** wallet/exchange support na pool choice halisi hutofautiana; transparent boundary timing/value correlation; network/RPC na endpoint bado zipo.

**Procedure:** (1) chagua maintained Orchard shielded-by-default wallet; (2) verify/backup; (3) pata ZEC kihalali; (4) receive kwenye supported Unified Address na confirm pool; (5) pendelea shielded-to-shielded; (6) tumia supported network privacy; (7) test viewing-key disclosure kwa wallet ndogo kabla ya audit.<sup>[[9]](#references)</sup>

**Detection:** transparent boundary na service records, wallet/network metadata na viewing keys zinapotolewa kihalali; usidhani Unified Address payments zote zilikuwa shielded.

## Mimblewimble and Litecoin MWEB

**Mechanics:** confidential transactions huficha amounts na Mimblewimble-style aggregation huondoa conventional address-rich history; Litecoin hutekeleza optional extension block pamoja na transparent chain.

**Pros:** confidential amounts na fungibility bora katika private domain; pruning/aggregation yenye ufanisi.

**Cons:** opt-in boundary peg-in/out ni public na inaweza kuhusishwa; wallet/exchange support; interactive/address model differences; network na acquisition records.

**Procedure:** (1) chagua maintained wallet yenye MWEB support iliyo wazi; (2) verify/backup na test kiasi kidogo; (3) acquire kihalali; (4) peg into MWEB na verify balance domain; (5) transact na compatible receiver pekee; (6) epuka distinctive peg-out ya haraka; (7) hifadhi private audit records.<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value, exchange/wallet/node data na later transparent spends; internal confidential transfer details zimepunguzwa kwa makusudi.

## Ethereum zero-knowledge privacy applications

**Mechanics:** circuit huthibitisha statement—membership, valid note ownership au authorization—bila kufichua secret; verifier contract huikagua. Deposits, withdrawals, public inputs, events na gas bado zinaweza kufichua links.

**Pros:** programmable selective disclosure; anonymous-set applications; rules zinazoweza kuthibitishwa bila kufichua data yote.

**Cons:** contract/circuit bugs; anonymity set ndogo; public boundaries; RPC/IP/session/analytics/gas funding; application na sanctions/legal risk.

**Procedure:** (1) fafanua hasa proof inaficha nini; (2) tumia application iliyoauditiwa na kudumishwa pale inapokuwa halali; (3) kagua public inputs/events na deposit/withdraw rules; (4) tenga action wallet na gas sponsorship kulingana na protocol; (5) tumia privacy-aware RPC/network path; (6) test kwa value ndogo; (7) hifadhi compliance records.<sup>[[11]](#references)</sup>

**Detection:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics na eventual exchange/merchant boundary. Usidai ZK proof inaficha fields zilizotangazwa kuwa public.

## Stablecoins

**Mechanics:** tokens huhamishwa kwenye public chain; centralized issuers wanaweza freeze/blacklist au redeem dhidi ya identified accounts.

**Pros:** price stability, liquidity na merchant support; settlement ya haraka; accounting rahisi.

**Cons:** transparent address/amount/contract graph; gas funding; issuer na exchange identity/control; sanctions screening; anonymity kwa kawaida ni dhaifu.

**Procedure:** ichukulie kama identified payment: tumia fresh business address kwa compartmentation pekee, thibitisha token contract/network, test kiasi kidogo, linda wallet, tumia trusted RPC/local node, hifadhi basis/source na screen parties zinazohitajika.

**Detection:** complete token event graph, issuer freeze list/actions, exchange/RPC/device na gas-funding relationships.

## Cashu Chaumian e-cash

**Mechanics:** mint husaini kwa upofu bearer secrets zilizotengenezwa na client na backed by mint's Bitcoin/Lightning reserves; inaweza kuzuia double-spend bila kuunganisha issuance moja kwa moja na redemption ya baadaye.

**Pros:** accountless bearer tokens; peer transfer ya papo hapo; mint haiwezi kuunganisha moja kwa moja blinded withdrawal na spend; tokens zinaweza kusafirishwa kama data/QR.

**Cons:** mint custody/solvency/censorship; bearer data loss/theft; denomination/timing na Lightning boundaries; network metadata; software ecosystem changa.<sup>[[12]](#references)</sup>

**Procedure:** (1) tumia official test mint au value ndogo inayoweza kupotezwa; (2) install maintained wallet na test backup/restore limitations; (3) authenticate mint na kagua custody/fees; (4) mint kiasi kidogo; (5) tuma token kupitia private channel/QR iliyo authenticated; (6) receiver abadilishe token kabla ya kuichukulia final; (7) redeem na reconcile. Usihifadhi value muhimu kwenye mint isiyoaminika.

**Detection:** mint huona network, issue/redeem/Lightning boundaries na spent-token set, lakini blinding huondoa direct token linkage; endpoints/messages na distinctive amount/timing zinaweza kurejesha links.

## Fedimint federated e-cash

**Mechanics:** threshold ya guardians huhifadhi reserves na kusaini e-cash kwa upofu; internal bearer transfers ni private kwa guardians, huku Lightning gateways zikiunganisha external payments.

**Pros:** custody iliyogawanywa; private internal transfer; community governance; guardian mmoja hawezi kudhibiti reserve chini ya threshold.

**Cons:** guardian quorum/custody/software risk; gateway huona invoices/timing; deposit/withdraw boundaries; client-state recovery complexity.

**Procedure:** (1) verify federation invite/guardians/quorum/jurisdiction; (2) install maintained client na test recovery; (3) deposit kiasi kidogo cha halali; (4) tumia fresh internal payment requests; (5) ichukulie gateway kama observer wa Lightning; (6) test redemption; (7) hifadhi source/tax records nje ya public payment data.<sup>[[13]](#references)</sup>

**Detection:** federation huona aggregate issuance/redemption, gateways huona external invoices, Bitcoin/Lightning huonyesha boundaries, na endpoint/communication evidence inaweza kuunganisha internal transfers.

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash inalenga kumfanya payer asiweze kutambuliwa na merchants huku merchants na income zikiendelea kuwa accountable.

**Pros:** payer privacy kwa design; ordinary currency; merchant accountability/refunds; hakuna speculative token inayohitajika.

**Cons:** deployments chache; exchange/bank huona funding; merchant huona order/delivery; wallet bearer/recovery risk; regulated operators.

**Procedure:** (1) tafuta exchange/merchant ya sasa kwa jurisdiction/currency; (2) soma KYC/fees/privacy; (3) install official wallet; (4) withdraw kihalali kutoka supported bank/exchange; (5) kagua merchant contract; (6) pay na hifadhi receipt/refund data; (7) epuka unnecessary merchant session identifiers.<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal na merchant deposit ni accountable boundaries; merchant order/device/delivery na timing vinaweza ku-correlate hata coins zikiwa blinded.

## Cross-chain bridge, atomic swap and decentralized exchange

**Mechanics:** contract/service hufunga/burn asset moja na ku-release/mint nyingine, au counterparties hubadilishana atomically. Huvunja view ya ledger moja, si continuity ya kiuchumi.

**Pros:** asset/network interoperability; inaweza kuepuka centralized custodian mmoja; matumizi ya kawaida ya portfolio/liquidity.

**Cons:** chains zote mbili ni public; time/value/fees/liquidity na contracts hu-correlate; bridge/relayer/frontend/RPC records; smart-contract/counterparty na regulatory risk.

**Procedure for lawful swaps:** (1) verify official contract/service na legal availability; (2) kagua custody/audit/fees/slippage; (3) tumia test ndogo; (4) rekodi transaction IDs zote mbili na rate; (5) linda approvals; (6) reconcile destination asset na revoke approval zisizo za lazima. Usitumie swaps kuficha source of funds.

**Detection:** bridge deposit/withdraw events, unique amount minus fees, time order, liquidity, relayer/RPC/frontend na later service deposits.

## Centralized mixer or tumbler

**Mechanics:** service hupokea deposits kwenye pool na baadaye kurudisha units tofauti, ikijaribu kuficha direct input-output mapping.

**Pros:** kinadharia inaweza kuongeza transaction ambiguity.

**Cons:** operator anaweza kuiba/log; entry/exit timing/value analysis; sanctions/money-transmission na criminal exposure; seizures zinaweza kufichua mappings; taint/rejection risk.

**Procedure:** hakuna operational mixing guide inayotolewa. Reproduce graph kwa usalama kwa kupanua [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): tengeneza synthetic deposits, pooled outputs, fees na delays; wape analysts mappings zisizokamilika; pima heuristics zinazofanya kazi; kisha reveal ground truth.

**Detection:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs na downstream consolidation. Weka probabilistic attribution ikiwa ni hivyo.

## Peel chains, fan-out/fan-in and structuring

**Mechanics:** transactions zinazorudiwa hu-peel payments ndogo kutoka change, hugawa value kwa addresses nyingi, hukusanya tena collectors, au hugawa amounts ili kuepuka review.

**Pros:** huongeza kazi ya analyst asiye na heuristics bora na idadi ya addresses.

**Cons:** value/cadence/transaction continuity inayotambulika; consolidation na service endpoints; structuring inaweza kuwa illegal yenyewe; fees na operational errors.

**Procedure:** tumia synthetic CSV/testnet data pekee: generate source kubwa, repeated payment/change edges, parallel branches na collector mmoja; ongeza benign exchange-like examples; boresha detection na andika false positives.

**Detection:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint na off-chain records. Exchange hot wallets zinaweza kufanana, hivyo context ni lazima.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mechanics:** mtu/account/company mwingine hupokea, hubadilisha au hutumia funds, akiingiza legal na operational layers kati ya controller na transaction.

**Pros to an adversary:** named account haimtambulishi controller mara moja; inaweza kuunganisha cash, crypto, goods na jurisdictions.

**Cons:** identity fraud/money-laundering exposure; kila participant huongeza communications, bank/company/tax/shipping records, fees, inconsistencies na witnesses; facilitator reuse huunda hubs.

**Procedure:** usi-emulate kwa watu/accounts halisi. Tengeneza synthetic graph yenye controller, recruiter, mule, OTC, shell merchant na beneficiary; weka device/IP/message/bank edges; waombe investigators watofautishe account holder na controller na waandike evidence confidence.

**Detection:** shared device/IP/recovery, unusual beneficiary/velocity, senders wengi wasiohusiana, immediate onward movement, company/director/invoice inconsistency, communications na cash/commodity delivery.

## NFTs, gambling, merchant goods and refund loops

**Mechanics:** value hubadilishwa kuwa self-priced asset, wagering balance, resalable goods au refunds ili kuunda transaction narrative tofauti.

**Pros to an adversary:** hubadilisha asset form na kuingiza marketplace/merchant intermediaries.

**Cons:** marketplace/account/device na wash-trade graph; odds/play na refund records; delivery/resale evidence; fees/losses; fraud/laundering liability.

**Procedure:** hakuna concealment workflow. Tumia synthetic marketplace data yenye related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument na common shipping; validate detection dhidi ya legitimate collectors/customers.

**Detection:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery na proceeds reconvergence.

## Physical bearer wallet or offline token transfer

**Mechanics:** device, paper/QR, hardware bearer instrument au e-cash token huhamisha control ya secret badala ya kutangaza payment wakati wa handover.

**Pros:** hakuna live network event wakati wa exchange; inafaa offline; physical cash-like custody.

**Cons:** copy/theft/loss na exclusivity isiyo na uhakika; later redemption/broadcast huunganisha; physical meeting/shipping; counterfeit/tamper risk.

**Procedure:** (1) tumia instrument/protocol iliyokaguliwa; (2) initialize/verify authenticity privately; (3) load lawful value ndogo tu; (4) transfer katika authorized context iliyoandikwa; (5) receiver athibitishe au asweep haraka kulingana na protocol; (6) usidhani sender hakuhifadhi copy; (7) hifadhi ownership/tax evidence privately.

**Detection:** purchase/funding na eventual sweep/redemption, device serial/tamper evidence, delivery/meeting na endpoint records.

## Merchant-scoped invoice or one-time payment request

**Mechanics:** merchant huunda request ya matumizi moja yenye amount, expiry na order reference. Payer huitatua kupitia supported rail bila kufichua reusable credential moja kwa moja kwa merchant; issuer au payment processor bado anaweza kuwatambua wote.

**Pros:** hupunguza credential reuse na accidental cross-merchant identifiers; exact amount/expiry hupunguza makosa; inaendana na accounting na refunds za kawaida.

**Cons:** invoice, delivery, browser, processor na issuer bado huunganisha order; unique amount/time inaweza kuimarisha correlation; malicious payment links ni za kawaida.

**Procedure:** (1) authenticate merchant independently; (2) omba fresh invoice yenye exact amount, asset/network na expiry; (3) kagua destination na refund rules; (4) pay kutoka approved engagement compartment; (5) verify merchant amekubali invoice hiyo; (6) hifadhi receipt na transaction reference; (7) expire badala ya kutumia request tena.

**Detection:** merchant na processor huunganisha invoice, session na settlement; unique amounts/timing na delivery hutambua payer. **Captured wallet/device:** invoice history hufichua counterparties na purpose; punguza memo data, encrypt device na hifadhi authoritative accounting katika controlled finance system.

## Prepaid service credit and capability token

**Mechanics:** service hubadilisha conventional payment kuwa bounded internal credits au bearer capability. API/resource use ya baadaye inaweza kuepuka kuwasilisha original card kwa kila request, lakini service mara nyingi inaweza kuunganisha issuance na redemption.

**Pros:** huweka kikomo cha spend na compromise loss; hutenganisha workers wa kila siku na funding credential; huwezesha per-project budgets na revocation.

**Cons:** kwa kawaida ni pseudonymous, si anonymous; service database, redemption IP na unique usage pattern huunganisha activity; bearer tokens zinaweza kuibwa; refunds zinaweza kuhitaji original payer.

**Procedure:** (1) nunua credits kupitia organization account; (2) tengeneza project na budget moja; (3) toa token yenye service, amount na expiry constraints; (4) ihifadhi katika approved secret manager au workload identity path; (5) test rejection nje ya scope na baada ya expiry; (6) monitor consumption; (7) revoke na reconcile unused value.

**Detection:** provider huunganisha funding account, project, token issuance na usage; defenders wa-alert geographic/process changes na anomalous consumption. **Captured node:** chukulia remaining capability inaweza kutumiwa; tumia short expiry, low balance, audience binding na immediate server-side revocation.

## Privacy Pass or blinded authorization token

**Mechanics:** issuer hutengeneza privacy-preserving authorization token ambayo origin inaweza ku-validate bila kuunganisha redemption na issuance. Inaweza kuwakilisha paid entitlement au rate-limited access, lakini si general currency. Architecture hutenganisha client, attester, issuer na origin roles na inaonya kuwa IP/timing au collusion inaweza kuvunja unlinkability.<sup>[[18]](#references)</sup>

**Pros:** unlinkable redemption kwa services zinazoiunga mkono; hakuna reusable account cookie kwa origin; cached tokens zinaweza kutenganisha issuance na use kwa muda.

**Cons:** application-specific; issuer/attester trust na anonymity-set partitioning; IP na browser metadata bado zipo; token theft au distinctive issuance timing inaweza ku-correlate use.

**Procedure:** (1) tumia implementation inayofuata Privacy Pass token type husika; (2) fafanua entitlement inayothibitishwa; (3) tenga issuer na origin administration inapohitajika na threat model; (4) punguza challenge metadata; (5) issue test tokens kadhaa na redeem kila moja mara moja kwenye origins zako; (6) linganisha logs kwa stable identifiers zilizokatazwa; (7) test replay, expiry na revocation/abuse controls.

**Detection:** origins huona redemption IP/time na token validity; issuers/attesters huona issuance context; analysts hupima timing na metadata partitions bila kudhani cryptographic break. **Captured client:** unspent bearer tokens zinaweza kutumika; punguza value, lifetime na audience, na usihifadhi funding credential pamoja nazo.

## Delegated organization procurement or fiscal sponsor

**Mechanics:** authorized procurement team, reseller au fiscal sponsor huingia mkataba na kulipa huku operational team ikipokea service yenye mipaka. Hii ni role separation yenye records za kweli, si nominee au false identity.

**Pros:** vendors hawahitaji kupokea identity au personal payment details za kila operator; central compliance, tax na refund handling; budget na offboarding zilizo wazi.

**Cons:** sponsor anamjua beneficiary na purpose; contracts, approvals, delivery na accounts hubaki; delay/fees huongezeka; separation ni dhaifu mtu mmoja akisimamia layers zote.

**Procedure:** (1) andika business purpose, beneficiary na approving authority; (2) chagua intermediary aliyeidhinishwa na organization; (3) contract kwa taarifa za kweli; (4) provision project-scoped subaccount bila personal billing credential; (5) tenga finance administrators na operators; (6) reconcile invoices na access; (7) terminate service na delegated access wakati wa closeout.

**Detection:** procurement, identity-provider, vendor na delivery records huunganisha chain. **Captured operational device:** inapaswa kufichua service project, si finance credentials; hifadhi invoices na payer identities katika finance system, si field nodes.

## Escrow or conditional settlement

**Mechanics:** trusted escrow agent au smart contract hushikilia value hadi conditions zilizoandikwa zitimizwe. Inaweza kupunguza disclosure ya moja kwa moja kati ya payer/payee, huku escrow na payment rails zikihifadhi relationship.

**Pros:** dispute na delivery protection; payer na merchant wanaweza kufichuana reusable credentials chache; release conditions zinazoweza ku-audit.

**Cons:** escrow custody/contract risk, fees na identity obligations; on-chain contracts ni public; order, shipping na dispute data hubaki; si anonymous kwa intermediary.

**Procedure:** (1) verify legal entity, custody, fees, dispute forum na supported assets; (2) tengeneza milestone iliyoandikwa na refund path; (3) fund kutoka approved organization account; (4) verify receipt na release authorization independently; (5) release baada ya evidence pekee; (6) hifadhi audit record yote; (7) funga permissions/contract approvals zisizotumika.

**Detection:** escrow account/contract events, funding/release time, beneficiary na dispute records hufichua transaction. **Captured device:** session tokens au contract approvals zinaweza kuruhusu release; hitaji separate approver/MFA na revoke active sessions inapopotea.

## Batched or pooled organization settlement

**Mechanics:** obligations nyingi zilizoidhinishwa hukusanywa na kulipwa katika bank au blockchain transactions chache, huku private internal ledger ikiassign kila share. Batching inaweza kupunguza public per-purchase detail, lakini coordinator huhifadhi attribution yote.

**Pros:** fees ndogo; public graph edges chache; huficha line items kwa public observer wakati amounts zimeaggregated; internal accounting rahisi.

**Cons:** coordinator ni complete observer na high-value target; distinctive totals/timing zinaweza ku-correlate; custody na reconciliation risk; inaweza kufanana na structuring ikitumiwa vibaya.

**Procedure:** (1) fafanua participants na lawful obligations katika accounting system; (2) weka regular business-justified batch window, si thresholds za kukwepa controls; (3) hitaji dual approval ya aggregate; (4) settle kwa recipients waliothibitishwa; (5) reconcile kila internal line na batch; (6) handle refunds kama linked corrections; (7) linda ledger access na hifadhi kulingana na policy.

**Detection:** coordinator ledger, approval na beneficiary records hutoa ground truth; public analysts watumie input/output/value/time clustering kwa tahadhari. **Captured payer device:** iwe na requisition yake pekee, si pool signing key au participant ledger.

## Account-abstraction paymaster or sponsored gas

**Mechanics:** relayer/bundler hu-submit smart-account operation na paymaster hulipa transaction fees, hivyo kuondoa direct native-gas funding edge kutoka user wallet. Huboresha graph property moja; operation, contract na service telemetry bado ni public au observable.<sup>[[19]](#references)</sup>

**Pros:** huondoa common gas-funding link; scoped sponsorship na rate limits; onboarding bora kwa legitimate privacy applications.

**Cons:** paymaster/bundler/RPC/front end zinaweza ku-correlate requests; contract events na public inputs hubaki; sponsorship policy hutambulisha cohort; malicious contracts/approvals zinaweza kuiba assets.

**Procedure:** (1) tumia audited maintained smart account na paymaster kwenye network sahihi; (2) kagua fields za public na sponsor logs; (3) punguza sponsorship kwa contract, function, amount, nonce na expiry; (4) test value ndogo; (5) submit kupitia intended privacy-aware path; (6) verify operation na fee payer on chain; (7) revoke allowances/session keys na hifadhi compliance records.

**Detection:** unganisha UserOperation, EntryPoint, paymaster, bundler/RPC na application logs; cluster identical sponsorship policy kwa tahadhari. **Captured wallet:** session keys na pending approvals zinaweza kutumika bila gas; ziweke na scope ndogo na revoke kupitia recovery policy.

## Threshold or multisignature payment authorization

**Mechanics:** spending huhitaji threshold ya independent signers. Haifichi transaction, lakini hutenganisha payment authority na laptop, field node au operator mmoja aliyekamatwa.

**Pros:** compromise na insider resistance yenye nguvu; approval accountable; field device moja haina signing authority kamili; recovery inawezekana.

**Cons:** coordination na availability; signer/device/account metadata inaweza kuunganisha participants; backup mbaya husababisha loss; public multisig patterns zinaweza kutambulika.

**Procedure:** (1) fafanua signers, threshold, limits na recovery kabla ya funding; (2) initialize kwenye hardware/accounts tofauti; (3) verify addresses na backups independently; (4) field workloads zipate unsigned requisition capability pekee; (5) hitaji out-of-band review ya recipient, amount na purpose; (6) test recovery na one-signer loss kwa value ndogo; (7) rotate signer baada ya compromise.

**Detection:** approval system, signer device na public script/contract hutoa evidence; defenders wa-alert policy au signer-set changes. **Captured node:** ifichue at most one low-authority session key au unsigned request; usiweke quorum material pamoja.

## Closed-loop community or event currency

**Mechanics:** cooperative, conference au private test environment hutoa credits zinazoweza kutumika kwa enrolled participants pekee. Internal transfer inaweza kufichua kidogo kwa global payment networks, huku operator akidhibiti issuance na redemption.

**Pros:** bounded economic domain; huwezesha kujaribu offline au privacy-preserving payment UX; hupunguza external card exposure; experimental controls wazi.

**Cons:** anonymity set ndogo; operator na merchants huona activity; acceptance/redemption ndogo; licensing, consumer-protection na tax rules zinaweza kutumika hata kwa local value.

**Procedure:** (1) pata legal/compliance review na chapisha issuer terms; (2) enroll consenting test participants; (3) cap issuance na zuia misuse ya cash-like; (4) tumia fresh payment requests na punguza public participant identifiers; (5) rekodi aggregate reserves na private individual receipts; (6) test loss/refund/redemption; (7) close ledger na rudisha residual value kama ilivyoahidiwa.

**Detection:** issuer ledger, enrollment, merchant na redemption records hujenga flows; circular transfers zisizo za kawaida au rapid cash-out zitathminiwe. **Captured wallet:** local balance na counterparties zinaweza kufichuka; cap value, encrypt state na support issuer-side freeze/reissue yenye audit record.

## Bitcoin reusable payment codes and private payment instructions

**Mechanics:** BIP 47 payment codes hutumia reusable public identifier pamoja na ECDH-derived one-time deposit addresses; BIP 351 huainisha private-payment instruction design mpya zaidi. Hupunguza public address reuse huku recipient akiweza kuchapisha stable payment instructions. Notification, wallet support, funding na subsequent coin selection bado huathiri privacy.<sup>[[20]](#references)</sup>

**Pros:** instruction moja ya public hutoa addresses tofauti; recipient hahitaji kuchapisha kila invoice address; wallets zinazoendana zinaweza kufuatilia derived payments; inafaa kwa donors/customers halali wanaojirudia.

**Cons:** wallet interoperability hutofautiana; notification transactions au published payment code huunganisha relationship context; sender, recipient na public graph bado huona transactions; careless consolidation/change handling huondoa faida.

**Procedure:** (1) thibitisha wallets zote mbili zinazodumishwa zinaunga mkono specification/version ileile; (2) backup na test recovery kwenye low-value wallet; (3) authenticate recipient payment code out of band; (4) tuma lawful test ndogo; (5) verify fresh derived address imetumika; (6) label relationship locally na tumia coin control; (7) test recovery/refund behavior kabla ya kutegemea mfumo.

**Detection:** analysts huchunguza notification patterns, funding/change, later consolidation na service boundaries; public-code publication hutambulisha recipient context hata deposit addresses zikitofautiana. **Capture-resilient OPSEC:** weka spend keys mbali na field devices na expose watch-only relationship view pekee. **Monitoring:** alert unexpected notification transactions, reused derived addresses, wallet gap-limit/recovery errors na unplanned consolidation.

## EVM stealth addresses (ERC-5564)

**Mechanics:** sender hutengeneza one-time stealth account kutoka stealth meta-address ya recipient na kuchapisha announcement yenye ephemeral public key na view tag. Recipient huchanganua announcements kwa viewing key na hutengeneza spend key inayolingana. Recipient linkage huboreka, lakini sender, amount/token, gas, announcement na later spending hubaki visible.<sup>[[21]](#references)</sup>

**Pros:** fresh receiver address isiyohitaji interaction; reusable meta-address; viewing na spending roles tofauti; hufanya kazi kwa supported EVM assets/applications.

**Cons:** announcement scanning na spam; funding gas ya address mpya inaweza kuirelink; sender anamjua recipient; public token/amount na eventual consolidation hubaki; implementation/wallet support hutofautiana.

**Procedure:** (1) tumia audited maintained implementation kwenye test network kwanza; (2) generate separate viewing/spending material na backup; (3) authenticate meta-address; (4) tuma low-value test na announcement; (5) scan na derive stealth account; (6) test supported gas sponsorship bila personal funding edge; (7) rekodi public fields na hifadhi lawful accounting.

**Detection:** fuatilia announcement caller, token/amount, timing, gas sponsor, spending na consolidation; view key inaweza kuthibitisha receipt bila kutoa spend. **Capture-resilient OPSEC:** networked scanner iwe na viewing role pekee inapowezekana; weka spend/recovery keys sehemu nyingine. **Monitoring:** alert malformed/spam announcements, view-key access, unexpected spend derivation na stealth outputs zilizosogezwa bila approval.

## Liquid Confidential Transactions

**Mechanics:** Liquid huficha output amounts na asset types kwa default kwa commitments na proofs, huku transaction graph, input/output count, fee na block time zikiwa visible. Peg-in/peg-out na service boundaries hubaki linkable, na users wanaweza kufichua blinding data kwa kuchagua.<sup>[[22]](#references)</sup>

**Pros:** confidential amount/asset type kwa default; sidechain settlement ya haraka; selective audit kupitia blinding keys/descriptors; huficha commercial values nyeti kwa public observers.

**Cons:** graph structure na timing hubaki; federation/bridge na exchange trust; peg boundaries na unconfidential outputs; wallet/node/network records; sender na receiver wanajua transaction yao.

**Procedure:** (1) chagua maintained Liquid wallet na verify backup model; (2) tumia testnet au lawful amount ndogo; (3) receive kwa confidential address na verify wallet imeonyesha output kuwa blinded; (4) tuma confidential transaction ya majaribio; (5) kagua explorer fields zinazoonekana public; (6) export blinding proof iliyohitajika kwa audit pekee; (7) document peg/exchange boundaries na reconcile funds.

**Detection:** analyze visible graph/fee/time, peg na exchange records, network metadata na later unblinding evidence; usikadirie hidden amount au asset. **Capture-resilient OPSEC:** tenga spend seed, blinding/view data na watch-only operations. **Monitoring:** alert accidental unconfidential addresses, unknown peg requests, descriptor changes na unapproved unblinding-key export.

## General payment or state channel

**Mechanics:** participants hufunga funds, hubadilishana signed off-chain state updates na kuchapisha opening, closing au disputed state pekee on chain. Intermediate payments hazitangazwi globally, lakini peers na routing/intermediary services huona sehemu zao na endpoints lazima zihifadhi latest enforceable state.<sup>[[23]](#references)</sup>

**Pros:** interactions nyingi za haraka na fee ndogo kati ya private na public ledger; global transaction detail ndogo; bounded channel balance; inafaa kwa metered services na counterparties wanaojirudia.

**Cons:** channel peers wanajuana na wanaweza kuhifadhi updates; opening/closing/value/timing hu-correlate; online monitoring inaweza kuhitajika wakati wa challenge windows; implementation/liquidity risk; si anonymity set kubwa yenyewe.

**Procedure:** (1) chagua maintained audited implementation na elewa dispute window; (2) open low-value test channel kati ya parties zako; (3) exchange signed state updates zenye unique nonces; (4) backup latest enforceable state; (5) close cooperatively; (6) rehearse stale-state rejection kwenye testnet; (7) hifadhi accounting na channel-peer records.

**Detection:** public chain huonyesha lifecycle/disputes; peers, watch services na application transport hufichua off-chain timing na parties. **Capture-resilient OPSEC:** cap hot balance na hifadhi latest signed state katika encrypted recoverable store iliyotengwa na field nodes. **Monitoring:** fuatilia stale-state publication, missed backup, peer-key change na challenge deadline inayokaribia.

## Mobile carrier billing

**Mechanics:** online service hutoza purchase kwenye mobile subscription au prepaid balance kupitia carrier billing. Merchant anaweza kupokea carrier authorization badala ya card/bank details, huku carrier akijua subscriber/line, device/network context, merchant, amount na time.<sup>[[24]](#references)</sup>

**Pros:** hakuna card number kwa merchant; phone availability pana; inafaa kwa digital goods za thamani ndogo; carrier anaweza kuweka caps na kureverse charges.

**Cons:** hutambuliwa sana kupitia SIM/account na mara nyingi device; limits ndogo na fees kubwa; merchant category restrictions; account takeover/SIM-swap risk; carrier na aggregator huunda trail kamili.

**Procedure:** (1) thibitisha availability, limit, fee na refund terms kwa organization carrier account; (2) enable kwenye dedicated organization line ikiwa justified; (3) weka spend cap ndogo inayofaa; (4) purchase benign test item; (5) verify merchant na carrier receipts; (6) zima recurring authorization; (7) reconcile na zima feature baada ya assessment.

**Detection:** carrier, aggregator na merchant records huunganisha line, subscriber, IP/device na charge; enterprise telecom invoices huifichua. **Capture-resilient OPSEC:** usitumie personal number na hitaji carrier-account MFA nje ya field device. **Monitoring:** enable instant charge/SIM-change alerts na simamisha kwenye premium-service enrollment, forwarding au account recovery isiyotarajiwa.

## Open-banking payment initiation

**Mechanics:** kwa user consent iliyo wazi, regulated PISP huomba account-servicing bank ianzishe transfer. Merchant huenda asipokee card credentials, lakini PISP na banks huhifadhi regulated payer, payee, consent, device na transaction records.<sup>[[25]](#references)</sup>

**Pros:** hakuna reusable card number checkout; strong bank authentication; exact account-to-account settlement; consent/status APIs; reconciliation iliyo wazi.

**Cons:** si anonymous kwa banks/PISP; payee mara nyingi huona legal account details au reference; phishing/redirect risk; jurisdiction na refund protections hutofautiana; consent metadata huongeza observer.

**Procedure:** (1) verify PISP bado inadhibitiwa na merchant callback domain ni halali; (2) anza kutoka merchant request; (3) review payee, amount, reference na consent katika bank; (4) authorize single payment pekee; (5) verify final status independently; (6) revoke residual consent; (7) hifadhi receipt na reconcile.

**Detection:** bank/PISP/merchant logs na transfer references hutoa attribution yenye nguvu. **Capture-resilient OPSEC:** banking authentication/recovery zibaki nje ya operational/field devices; device ishikilie paid-service entitlement pekee. **Monitoring:** tumia bank transaction/consent alerts na chunguza PISP grants mpya, payee iliyobadilika au status callbacks zisizotarajiwa.

## Platform wallet, app-store balance or in-app credit

**Mechanics:** platform humtoza user au redeem account credit, kisha hutoa signed receipt/entitlement kwa application. App developer huenda asipokee original funding instrument, huku platform ikiunganisha account, device, funding, product na redemption.<sup>[[26]](#references)</sup>

**Pros:** merchant/developer hapati primary PAN; fraud/refund na family/business controls; prepaid balance ndogo huweka exposure cap; signed receipts hurahisisha entitlement verification.

**Cons:** platform account ni identity na behavior hub yenye nguvu; device na storefront geography; gift-balance purchase/redemption trail; cash-out ndogo; fraud controls zinaweza kufreeze funds; si money ya cross-platform.

**Procedure:** (1) tumia organization-managed platform account pale policy inaporuhusu; (2) kagua funding, region, refund na transferable-value rules; (3) ongeza approved budget pekee; (4) nunua benign product kupitia official store; (5) verify app inapokea receipt fields zinazotarajiwa pekee; (6) zima recurring purchase; (7) reconcile na ondoa account kwenye operational hardware.

**Detection:** platform receipts/server notifications, account/device login na funding records hujenga purchase. **Capture-resilient OPSEC:** usisign field node kwenye personal store account; toa scoped app entitlement inapowezekana. **Monitoring:** enable new-device/purchase alerts na chunguza receipt replay, family/account changes au unexpected restore events.

## Mutual credit, clearing or periodic net settlement

**Mechanics:** participants huandika obligations katika private ledger na mara kwa mara husettle net position pekee. Individual service events huenda zisitoe public payments tofauti, lakini ledger operator na counterparties huhifadhi attribution ya kina.

**Pros:** external transactions na fees chache; public observers huona net settlement pekee; inafaa kwa organizations zinazojirudia; credit limits wazi hupunguza exposure.

**Cons:** centralized ledger ni evidence kamili na fraud target; counterparty/default risk; legal/accounting/tax duties; membership ndogo; net transfers zisizo za kawaida bado zinaweza kuonyesha relationships.

**Procedure:** (1) tumia identified consenting organizations pekee zenye legal/accounting approval; (2) fafanua unit, credit limit, settlement interval na dispute rules; (3) rekodi kila obligation kwa immutable approval; (4) finance roles tofauti zihesabu na kuidhinisha net positions; (5) settle kupitia lawful rail ya kawaida; (6) reconcile lines zote na settlement; (7) funga access na hifadhi records kulingana na policy.

**Detection:** ledger, invoices, approvals na final bank/chain settlement hutoa ground truth; analysts wasikadirie gross activity iliyokosekana kutokana na net transfer pekee. **Capture-resilient OPSEC:** operational devices zi-submit bounded requisitions pekee na zisiweze ku-edit balances au kuidhinisha settlement. **Monitoring:** alert credit-limit breach, backdated entries, administrator changes, reconciliation mismatch na settlement kwa beneficiary mpya.

## Capture/compromise exposure matrix

Hii hutumia seizure/loss test kwa kila family. Lengo ni kupunguza spend authority na disclosure ya identity zisizohusiana huku lawful accounting ikibaki—si kufuta transactions au kuzuia investigation.

| Technique family | A captured wallet/device/account can reveal | Minimum authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value na physical contacts | carry approved amount pekee; separate private accounting; report loss haraka; hakuna false records |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption na account/session tokens | low balance; purpose moja; truthful registration; issuer freeze/revocation inapopatikana |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery na merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; no shared recovery account |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices na project | role separation; least-privilege subaccount; finance credentials zisitoke kwenye operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator au dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph na network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP na payment database | minimal hot balance; encrypted backup; separate node identity; close/recover kwa mpango ulioandikwa |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC na boundary transactions | separate spend/view roles; hardware support inapopatikana; no exchange session on field node |
| Stablecoins, swaps, bridges and DEX | transparent graph, approvals, RPC/front-end state na destination assets | revoke allowances; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; encrypted backup kulingana na protocol; redeem/reissue; funding credential isitenganishwe |
| Paymaster, multisig/threshold | session key, one signer, pending operations na sponsor policy | narrow session key; independent quorum; signer rotation; field device isifikie threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph na participant records | no operational use; emulate kwa synthetic/testnet evidence pekee |
| Community/event currency | enrollment, local balance, counterparties na redemption | capped value; issuer freeze/reissue; consent na private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements na derived outputs | watch/view-only network role; offline/hardware spend role; no personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries na disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device na funding source | organization account; external MFA; low limit; no personal account on field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals na settlement ledger | operational requisition only; separate immutable ledger na dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial, compliance review au wallet kwenda offline hakuthibitishi investigation ipo. Monitor accounts, ledgers na infrastructure ambayo organization ina ruhusa ya kuobserve pekee; usiwahi ku-probe providers au counterparties kujaribu kujua kama wanashirikiana na investigators.

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
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | synthetic lab ground truth na detection output pekee | real account, person au value yoyote kuingia emulation: stop immediately |

## Selection and verification workflow

1. Taja ni party gani haipaswi kujua field gani.
2. Tambua issuer/mint/custodian, public ledger, network/RPC, merchant na physical observers.
3. Thibitisha support ya sasa, legality, limits, custody, recovery na refund behavior.
4. Tumia small lawful end-to-end test.
5. Kagua merchant receipt, provider statement, public chain na wallet/node logs.
6. Test backup/recovery na deliberate audit disclosure.
7. Hifadhi source, ownership, tax, sanctions na engagement records zinazohitajika kwa usahihi, lakini zikiwa access-controlled.

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
