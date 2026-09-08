# Anonymous Payment Technique Catalog

Bu katalog, sıradan nakitten blind-signature e-cash ve public-chain obfuscation yöntemlerine kadar ödeme **ailelerini** kapsar. “Anonymous” her zaman adı bilinen bir gözlemciye karşı anonimlik anlamına gelir. Merchant, issuer, mint, exchange, blockchain analyst, network provider, employer ve fiziksel gözlemci farklı olguları görür.

Aşağıdaki prosedürler hukuka uygun fonlar, doğru bilgiler içeren hesaplar ve yetkili procurement içindir. Atıf yapılan vakalarda amacı laundering, sanctions evasion veya identity fraud olan teknikler açıklanır ve tespit edilir; ancak prosedürleri suçu gerçekleştirme talimatı değil, sentetik bir forensic exercise niteliğindedir.

## Coverage matrix

| Family | Main privacy property | Main observer/trust | Treatment |
|---|---|---|---|
| Cash and cash equivalents | uzaktan ödeme ağı kaydı yoktur | alıcı ve fiziksel ortam | hukuka uygun workflow |
| Prepaid/gift/voucher value | redemption'ı ana karttan ayırır | seller, issuer ve redemption service | hukuka uygun workflow, jurisdiction'a göre değişir |
| Virtual/tokenized card | yeniden kullanılabilir PAN'ı gizler veya merchant'ları ayırır | issuer/network/wallet yine payer'ı tanımlar | hukuka uygun workflow |
| Payment app/intermediary | merchant alias/intermediary görebilir | app identity/device/transaction toplar | karşılaştırma baseline'ı |
| Bitcoin hygiene/Silent Payments | pseudonym ve alıcı unlinkability | public graph ve wallet/network boundary | deployable |
| PayJoin/CoinJoin | common ownership/linkage heuristic'lerini zayıflatır | participants/coordinator/network/public graph | desteklendiğinde deployable; legal review |
| Lightning/BOLT 12 | off-chain routing ve receiver-path exposure'ı azaltır | endpoints, hops, services ve channel graph | desteklendiğinde deployable |
| Monero/Zcash/MWEB | protocol-level on-chain confidentiality | acquisition, endpoint, network ve boundary yine görünür | hukuka uygun/desteklenen yerlerde deployable |
| Ethereum ZK application | belirli bir statement/action bağlantısını gizler | public inputs, RPC, relayer ve app | application-specific |
| Cashu/Fedimint/Taler | blind-signature payer privacy | mint/federation/exchange custody ve boundaries | emerging/deployment-specific |
| Stablecoins | pratik digital settlement | transparent chain ve issuer freeze/control | anonymous baseline değildir |
| Swaps/bridges/DEX | değeri asset/chain arasında taşır | her iki graph, contract ve provider | forensic mechanics; yalnızca ordinary lawful swaps |
| Mixers/peel/structuring | graph ambiguity/work miktarını artırır | entry/exit graph ve service records | yalnızca synthetic detection exercise |
| Nominees/mules/OTC/fronts | insan/business intermediary ekler | facilitators, banks, communications | yalnızca criminal-abuse analysis |
| Reusable/stealth payment addresses | her ödeme için yeni recipient address | public announcement/notification ve wallet boundaries | desteklendiğinde deployable |
| Confidential sidechain/state channel | amount/asset veya intermediate update'leri gizler | peers, bridge/federation ve lifecycle settlement | protocol-specific |
| Carrier/open-banking/platform billing | primary card'ı merchant'tan gizler | carrier, bank/PISP veya platform customer'ı tanımlar | ordinary identified payment |
| Mutual credit/net settlement | daha az external settlement record | private ledger operator tam eşleştirmeye sahiptir | yalnızca identified participants |

## Cash

**Mechanics:** fiziksel bearer value, online issuer authorization veya public ledger olmadan el değiştirir.

**Pros:** merchant'ın bank/card identity'sini öğrenmesi gerekmez; remote transaction graph yoktur; yaygın olarak anlaşılır ve kesindir.

**Cons:** yalnızca yüz yüze; theft/loss; change/receipt/serial veya reporting controls; withdrawal, cameras, witnesses ve location yine payer'ı ilişkilendirebilir.

**Procedure:** (1) cash'ın yasal/kabul edilir olduğunu ve amount/reporting rule'larını doğrulayın; (2) hukuka uygun biçimde çekin veya alın ve private accounting records tutun; (3) gereksiz loyalty/account identifiers kullanmadan ordinary merchant'a ödeme yapın; (4) yalnızca gerekli receipt'i isteyin; (5) satın alma gerektirmiyorsa shipping/account data vermeyin; (6) legitimate business purpose'ı iç kayıtlarınıza yazın.

**Detection:** geçerli policy kapsamında till/receipt/inventory, cameras ve access logs'u reconcile edin; ordinary cash kullanımını tek başına şüpheli saymadan unusual cash refunding veya tekrar eden just-below-control amounts'ı inceleyin.

## Money order, postal order, cashier instrument and cash on delivery

**Mechanics:** regulated issuer, cash/account funds'ı named recipient'a ödenecek numbered instrument'a dönüştürür; COD tahsilatı delivery'ye erteler.

**Pros:** recipient payer'ın primary bank/card number'ını almayabilir; cash'ın uzaktan gönderilemediği yerlerde kullanılabilir; açık receipt.

**Cons:** issuer/retailer gerektiğinde purchase/identity data tutar; serial tracking; recipient/delivery address; loss/fraud ve bölgesel kısıtlamalar; genellikle anonymous değildir.

**Procedure:** (1) issuer rules, limits, identification ve recipient acceptance'ı kontrol edin; (2) truthful information ve lawful funds kullanın; (3) payee/amount'ı hemen doldurun; (4) serial/receipt'i koruyun; (5) değere uygun tracked delivery kullanın; (6) redemption/refund'ı reconcile edin.

**Detection:** issuer purchase/redemption record, instrument serial, retailer/camera, shipping ve recipient account; alteration, duplicate serials ve coğrafi olarak tutarsız hızlı redemption'ı işaretleyin.

## Open-loop prepaid card

**Mechanics:** network-branded stored-value credential, primary credit account yerine prepaid balance'a karşı authorization yapar.

**Pros:** merchant exposure ve loss'u sınırlar; merchant'ı main PAN'dan ayırır; kabul edilen yerlerde online kullanılabilir.

**Cons:** purchase/activation/reload/registration ve device records; KYC ve limits değişir; billing-address failures; cash-out/refund restrictions; “no name”, issuer record olmadığı anlamına gelmez.

**Procedure:** (1) güncel issuer identity, fees, KYC, geography ve online/recurring support'u doğrulayın; (2) lawful funds ile authorized seller'dan alın; (3) gerekli truthful data'yı kaydedin; (4) tek compartment/purpose için kullanın; (5) loads'u structure etmeyin veya residency uydurmayın; (6) purchase/expense evidence saklayın ve issuer terms'e göre kapatın/elden çıkarın.

**Detection:** seller/activation, funding, device/IP, merchant authorization, balance checks ve redemption/refund'ı birleştirin. Prepaid etiketi yerine pattern'ler önemlidir.

## Closed-loop gift card, voucher and transferable service credit

**Mechanics:** numbered value yalnızca tek bir merchant/service veya ecosystem'de redeem edilir. Airtime/game/store credits varyantlardır.

**Pros:** recipient merchant yalnızca code/balance görebilir; sınırlı blast radius; kolay gifting ve budget separation.

**Cons:** seller ve service purchase/activation/redemption log'lar; account/device/delivery yine bağ kurar; scams, resale discounts ve expiry/region limits; zayıf refund rights.

**Procedure:** (1) yalnızca authorized channels'dan alın; (2) secret'ı açığa çıkarmadan code value'yu kaydedin; (3) gereksizse identifying loyalty account'a bağlamayın; (4) ayrı legitimate merchant account/context üzerinden redeem edin; (5) kabul edilene kadar receipt'i saklayın; (6) unsolicited “tax/support/ransom” talebi için asla code satın almayın.

**Detection:** code issuance/redemption time, device/account convergence, bulk/threshold-pattern purchase, tek cihazın birçok balance'ı kontrol etmesi ve uzak konumlarda hızlı redemption.

## Cryptocurrency-funded card or gift-code broker

**Mechanics:** intermediary cryptocurrency kabul eder ve card, voucher veya merchant code verir. Bu bir cross-rail conversion'dır: merchant ordinary card/gift value görür; broker on-chain deposit'i issuance ve delivery ile bağlar.

**Pros:** merchant funding wallet'ı görmez; crypto kabul etmeyen legitimate merchant'lar için kullanılabilir; bounded stored value.

**Cons:** broker/issuer'a karşı anonymous değildir; KYC, sanctions, exchange ve card-program rules; public deposit graph; account/device/email ve code redemption iki tarafı yeniden bağlar; scam/insolvency risk.

**Procedure:** (1) legal entity, card issuer, supported jurisdiction, KYC, fees ve refund policy'yi doğrulayın; (2) yalnızca lawful documented funds kullanın; (3) en küçük denomination ile test edin; (4) purchase öncesi network/merchant restrictions'ı kontrol edin; (5) accounting için blockchain transaction ve broker receipt'in ikisini de saklayın; (6) identity fraud, sanctions bypass veya “untraceable” cash-out vaat eden broker'ları kullanmayın.

**Detection:** broker deposit addresses, unique amount/time, account/device ve issued-card authorization veya gift-code redemption'ı ilişkilendirin; issuer ve broker records public chain'i merchant'a bağlar.

## Virtual or merchant-locked card

**Mechanics:** issuer generated PAN/token'ı real account'a eşler; çoğu zaman merchant, amount veya expiration kısıtlar.

**Pros:** reusable PAN disclosure'ı önler; merchant compartmentation; spend limits ve kolay revocation; gelişmiş fraud control.

**Cons:** issuer payer, funding, merchant, device/IP ve time'ı bilir; merchant account/delivery görür; bazı refunds/recurring charges başarısız olur; anonymous değildir.

**Procedure:** (1) regulated issuer'ın official feature'ını kullanın; (2) tek merchant/engagement için card oluşturun; (3) en küçük yararlı limit ve expiry belirleyin; (4) gerektiğinde accurate billing kullanın; (5) statement descriptor/refund behavior'ı doğrulayın; (6) final settlement sonrası freeze/delete edin ve audit evidence'ı saklayın.

**Detection:** issuer token-to-account mapping, merchant authorization, device ve delivery. Defenders merchant-specific reuse, velocity ve account-takeover signals kullanır.

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization, PAN yerine çoğu zaman device, merchant veya payment scenario'ya bağlı constrained credential kullanır.<sup>[[1]](#references)</sup>

**Pros:** merchant reusable PAN almaz; device cryptography/dynamic data cloning'i azaltır; card değiştirmeden revoke edilebilir.

**Cons:** issuer, token service, wallet platform ve network mappings/transactions tutar; device/platform account ve location payer'ı belirleyebilir.

**Procedure:** (1) legitimate card'ı official wallet'a kaydedin; (2) platform account/device'i strong authentication ile koruyun; (3) purchase sırasında device token/last digits'ı doğrulayın; (4) destekleniyorsa gereksiz location/analytics'i kapatın; (5) kayıp device/token'ları hemen disable edin; (6) issuer ve wallet records'ı inceleyin.

**Detection:** token requestor/device cryptogram ve issuer mapping, wallet/account telemetry, merchant terminal ve physical evidence.

## Payment app, marketplace wallet and centralized intermediary

**Mechanics:** service accounts tutar ve transfers'ı internal olarak veya bank/card rails üzerinden yürütür; merchant alias görebilirken service her iki tarafı görür.

**Pros:** convenience, dispute/refund mechanisms; recipient bank/card details'ı zorunlu olarak görmez.

**Cons:** centralized identity/social/transaction/device graph; freezes ve legal process; counterparties profile'ı açığa çıkarabilir; data use payment necessity'yi aşabilir.<sup>[[2]](#references)</sup>

**Procedure:** (1) identity, privacy, retention ve buyer-protection terms'ü okuyun; (2) optional profile/contact synchronization'ı azaltın; (3) terms izin veriyorsa ayrı truthful account kullanın; (4) MFA/alerts etkinleştirin; (5) recipient ve memo/profile privacy'sini doğrulayın; (6) records'ı export edin ve kullanılmayan links'i kapatın.

**Detection:** provider account, device/IP, contact graph, funding/withdrawal, memo ve merchant records. Alias, counterparty'ye karşı pseudonymity'dir; platform'a karşı anonymity değildir.

## Bank transfer, ACH, wire and instant-account payment

**Mechanics:** regulated institutions identified accounts arasında value taşır ve gerekli payment data'yı değiştirir.

**Pros:** hızlı, accountable, sınırlı durumlarda reversible, güçlü records; virtual account numbers merchant disclosure'ı azaltabilir.

**Cons:** banks/processors her iki tarafı bilir; statements ve references; anonymous değildir; cross-border ve Travel Rule/AML data.

**Procedure:** yalnızca accountability kabul edilebilirken kullanın: beneficiary'yi bağımsız doğrulayın, optional memo data'yı azaltın, mümkünse bank-provided virtual account/reference kullanın, alerts etkinleştirin, invoice saklayın ve reconcile edin.

**Detection:** deterministic bank/payment records, beneficiary/account ownership, device/session ve fraud controls. Bu baseline'dır; anonymity technique değildir.

## Account and merchant compartmentation

**Mechanics:** ayrı lawful identities/accounts, email aliases, cards ve delivery contexts, unrelated merchants'ın activity'yi kolayca birleştirmesini önler; issuer/controller mapping'i korur.

**Pros:** breach ve cross-merchant linkage'ı azaltır; audit kolaydır; regulated payments ile uyumludur.

**Cons:** provider compartments'ı yine eşler; recovery phone/device/IP ve shipping yeniden bağlayabilir; policy multiple accounts'ı yasaklayabilir.

**Procedure:** (1) tek purpose belirleyin; (2) yalnızca terms-compliant aliases/subaccounts oluşturun; (3) merchant-specific token/card kullanın; (4) cross-account contact/ad personalization'ı kapatın; (5) encrypted controller ledger tutun; (6) refunds/retention needs sona erince identifiers'ı retire edin.

**Detection:** providers recovery, device, funding ve IP'yi birleştirir; merchants delivery, browser ve account behavior'ı birleştirir. Defenders legitimate compartmentation ile synthetic identity fraud'ı ayırmalıdır.

## Controlled red-team procurement

**Mechanics:** SOC purchase'ı görmezken exercise controller legal entity, operator ve infrastructure mapping'i tutar.

**Pros:** realistic detection exercise; personal exposure yok; immediate deconfliction ve audit.

**Cons:** organization/provider'a karşı anonymous değildir; governance overhead; controller ledger kötü yönetilirse leak.

**Procedure:** (1) engagement-specific organization card/wallet/budget ayırın; (2) purchaser/operator rollerini ayırın; (3) asset, amount, service, purpose ve kill date'i kaydedin; (4) attribution mapping'i limited controller access ile saklayın; (5) false identity/mule/stolen funds kullanmayın; (6) closeout'ta indicators ve refunds'ı açıklayın/reconcile edin.

**Detection:** controller provider invoice ve asset'i eşler; SOC cardholder data yerine domain, certificate, hosting ve traffic üzerinden bağımsız discovery'yi test eder.

## Bitcoin address hygiene and coin control

**Mechanics:** fresh receive addresses, local labeling ve selective UTXO spending, public ledger'da address reuse ve accidental compartment merging'i azaltır.

**Pros:** geniş destek; self-custodial; en basit public linkage'ı önler.

**Cons:** tüm transactions/amounts public kalır; common-input/change/timing ve later consolidation activity'yi bağlar; acquisition/RPC/network records kalır.

**Procedure:** (1) maintained wallet kurup doğrulayın; (2) seed recovery'yi backup edip test edin; (3) her invoice için yeni address kullanın; (4) source/purpose'ı local olarak label'layın; (5) contexts'leri birleştirmemek için coin control kullanın; (6) local node veya privacy-aware connection tercih edin; (7) change/fees'i preview edin ve lawful accounting tutun.<sup>[[3]](#references)</sup>

**Detection:** address graph, belirsizlik içeren common-input/change heuristics, exact amount/time, consolidation, service deposits, node/RPC broadcast timing ve off-chain records.

## Bitcoin Silent Payments

**Mechanics:** BIP 352, receiver'ın static code yayınlamasına; sender'ların ECDH ile unique Taproot outputs türetmesine izin verir. Dış gözlemciler outputs'ı code'a doğrudan bağlayamaz.<sup>[[4]](#references)</sup>

**Pros:** address reuse olmadan reusable public identifier; interactive address request veya notification output gerekmez; Taproot outputs'a karışır.

**Cons:** receiver scanning cost; wallet support değişir; amount/sender graph ve spending public kalır; index server scans'i görebilir.

**Procedure:** (1) güncel BIP 352 wallet seçin; (2) descriptor ve scanning recovery'yi backup/test edin; (3) destekleniyorsa labeled code üretin; (4) published code'u authenticate edin; (5) sender inputs'i inceler ve küçük test gönderir; (6) receiver tercihen own node üzerinden scan eder; (7) received UTXO'ları ayrı tutun.

**Detection:** tasarım gereği output'tan güvenilir biçimde belirlenemez; analysts sender inputs, amount/time, later spending, wallet/network/index ve counterparty records kullanır.

## PayJoin

**Mechanics:** payer ve payee tek payment transaction'a input'lar ekler; tüm inputs'in tek owner'a ait olduğu varsayımını bozar.<sup>[[5]](#references)</sup>

**Pros:** improved privacy ile ordinary payment; common heuristic'i zayıflatarak wider graph'a fayda sağlar; equal-output crowd gerekmez.

**Cons:** interactive/support requirement; receiver endpoint availability; amount ve final transaction public; implementation/fallback metadata.

**Procedure:** (1) iki maintained wallet'ın aynı PayJoin version'ını desteklediğini doğrulayın; (2) invoice/endpoint'i authenticate edin; (3) wallet'ın PayJoin-enabled payment URI'sinden başlatın; (4) final amount/fee'yi inceleyin ve yalnızca beklenen inputs'i sign edin; (5) manual transaction surgery yapmayın; (6) broadcast ve receipt'i doğrulayın; (7) negotiation başarısız olursa fallback'i kaydedin.

**Detection:** blockchain analysts common-input clustering'ı zorunlu varsaymamalıdır; endpoint/provider negotiation log'layabilir; yalnızca transaction shape yerine wallet/network ve later-spend evidence kullanın.

## CoinJoin

**Mechanics:** birden fazla participant birçok inputs/outputs içeren transaction'ı birlikte oluşturur; çoğunlukla equal denominations kullanılır ve input-output correspondence belirsizleşir.

**Pros:** daha büyük on-chain ambiguity set; self-custodial designs; ölçülebilir round structure.

**Cons:** coordinator/peer/network metadata; fees/liquidity; identifiable transaction shape; toxic change ve later consolidation gains'i yok eder; legal/provider availability değişir.

**Procedure:** (1) current wallet/coordinator availability ve legality'yi doğrulayın; (2) official wallet kurup backup alın; (3) yalnızca lawful UTXO'lar kullanın; (4) denomination, fee ve coordinator modelini anlayın; (5) change ve mixed outputs'ı label'layıp ayırın; (6) bunları asla birlikte consolidate etmeyin; (7) network traffic'ı official support'a göre yönlendirin ve accounting saklayın.

**Detection:** collaborative structure'ı crime varsaymadan tanımlayın; possible mappings/anonymity set hesaplayın, ardından change/consolidation, service boundaries ve network/coordinator records'ı izleyin.

## Lightning Network

**Mechanics:** HTLC payments onion-routed channels üzerinden ilerler; payment details'ın çoğu chain'de yayınlanmaz, ancak funding/closing ve public channel information görünür.

**Pros:** hızlı, düşük fee; intermediaries normalde adjacent hops görür; routine payment details off-chain kalır.

**Cons:** sender/receiver ve first/last hop daha fazlasını bilir; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets users'ı tanımlar.

**Procedure:** (1) self-custodial veya custodial seçimini bilinçli yapın; (2) wallet/seed/channel recovery'yi doğrulayın; (3) exact payment için invoice kullanın; (4) tradeoff'ları okuduktan sonra private channels/LSP features tercih edin; (5) gerektiğinde supported Tor ile node IP'yi koruyun; (6) identifying invoices'ı yeniden kullanmayın; (7) channel ve payment accounting tutun.<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs, channel graph/probes, payment failure/timing ve on-chain funding/closure; public transaction olmaması records olmadığı anlamına gelmez.

## BOLT 12 offers and route blinding

**Mechanics:** reusable offer fresh invoices üretir ve blinded paths ilan edebilir; böylece payer receiver'ın clear node/path'ini öğrenmek zorunda kalmaz.

**Pros:** receiver privacy; static invoice olmadan reusable donation/payment endpoint; Lightning onion routing ile entegre.

**Cons:** wallet support değişir; endpoints, selected hops ve funding kalır; public contact veya network endpoint receiver'ı yeniden tanımlayabilir.

**Procedure:** (1) matching BOLT 12 support'u doğrulayın; (2) offer'ı authenticate edin; (3) fresh invoice isteyin; (4) amount/issuer/recurrence'ı inceleyin; (5) wallet üzerinden ödeyin; (6) receipt/refund behavior'ı doğrulayın; (7) node alias/contact'ı azaltın ve accounting saklayın.<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP ve first/last-hop telemetry, offer distribution account, timing/value ve funding graph; route blinding payer visibility'sini kasıtlı olarak sınırlar.

## Monero

**Mechanics:** one-time stealth addresses recipient linkage'ı gizler, RingCT amounts'ı gizler ve ring signatures sender ambiguity sağlar.

**Pros:** on-chain privacy default'tur; sender/receiver/amount confidentiality; mature dedicated wallet/node ecosystem.

**Cons:** acquisition/off-ramp ve endpoint/network/counterparty records; remote node queries/IP'yi görür; exchange support/legal treatment değişir; küçük operational mistakes contexts'leri bağlar.

**Procedure:** (1) lawful şekilde acquire edin ve basis/source saklayın; (2) official maintained wallet kurup doğrulayın; (3) seed'i backup/test edin; (4) local node veya documented Tor/I2P remote-node path kullanın; (5) payer/invoice başına yeni subaddress kullanın; (6) contexts'i local label'layın; (7) transaction proof/view access'i yalnızca bilinçli olarak paylaşın.<sup>[[8]](#references)</sup>

**Detection:** exchange/merchant/device/network ve seized-wallet evidence'a odaklanın; protocol kullanımı tek başına suspicious değildir ve public chain bilerek daha az bilgi açığa çıkarır.

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs shielded transfers'ı doğrular; sender, receiver ve amount encrypted kalır; transparent pools ve pool transitions public'tir.

**Pros:** güçlü shielded on-chain confidentiality; viewing keys scoped audit sağlayabilir; protocol-enforced validity.

**Cons:** wallet/exchange support ve gerçek pool choice değişir; transparent boundary timing/value correlation; network/RPC ve endpoint kalır.

**Procedure:** (1) shielded-by-default maintained Orchard wallet seçin; (2) verify/backup yapın; (3) ZEC'i lawful şekilde elde edin; (4) supported Unified Address'a alın ve pool'u doğrulayın; (5) shielded-to-shielded tercih edin; (6) supported network privacy kullanın; (7) audit öncesi viewing-key disclosure'ı küçük wallet'ta test edin.<sup>[[9]](#references)</sup>

**Detection:** transparent boundary ve service records, wallet/network metadata ve lawful şekilde sağlanan viewing keys; tüm Unified Address payments'ın shielded olduğunu varsaymayın.

## Mimblewimble and Litecoin MWEB

**Mechanics:** confidential transactions amounts ve Mimblewimble-style aggregation conventional address-rich history'yi gizler/azaltır; Litecoin transparent chain yanında optional extension block uygular.

**Pros:** private domain'de confidential amounts ve improved fungibility; efficient pruning/aggregation.

**Cons:** opt-in boundary peg-in/out public ve correlatable; wallet/exchange support; interactive/address model differences; network ve acquisition records.

**Procedure:** (1) explicit MWEB support'lu maintained wallet seçin; (2) verify/backup yapıp küçük amount test edin; (3) lawful şekilde acquire edin; (4) MWEB'e peg edin ve balance domain'i doğrulayın; (5) yalnızca compatible receiver ile transact edin; (6) immediate distinctive peg-out'tan kaçının; (7) private audit records saklayın.<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value, exchange/wallet/node data ve later transparent spends; internal confidential transfer details kasıtlı olarak azaltılmıştır.

## Ethereum zero-knowledge privacy applications

**Mechanics:** circuit, secret'ı açığa çıkarmadan statement—membership, valid note ownership veya authorization—kanıtlar; verifier contract bunu kontrol eder. Deposits, withdrawals, public inputs, events ve gas yine bağlantıları açığa çıkarabilir.

**Pros:** programmable selective disclosure; anonymous-set applications; tüm data'yı göstermeden verifiable rules.

**Cons:** contract/circuit bugs; small anonymity set; public boundaries; RPC/IP/session/analytics/gas funding; application ve sanctions/legal risk.

**Procedure:** (1) proof'un tam olarak neyi gizlediğini belirleyin; (2) lawful olduğu yerde audited maintained application kullanın; (3) public inputs/events ve deposit/withdraw rules'ı inceleyin; (4) action wallet ve gas sponsorship'ı protocol'ün öngördüğü şekilde ayırın; (5) privacy-aware RPC/network path kullanın; (6) küçük value ile test edin; (7) compliance records saklayın.<sup>[[11]](#references)</sup>

**Detection:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics ve eventual exchange/merchant boundary. ZK proof'un public ilan edilen field'ları gizlediğini söylemeyin.

## Stablecoins

**Mechanics:** tokens public chain üzerinde transfer edilir; centralized issuers freeze/blacklist uygulayabilir veya identified accounts'a karşı redeem edebilir.

**Pros:** price stability, liquidity ve merchant support; fast settlement; kolay accounting.

**Cons:** transparent address/amount/contract graph; gas funding; issuer ve exchange identity/control; sanctions screening; genellikle zayıf anonymity.

**Procedure:** identified payment olarak ele alın: yalnızca compartmentation için fresh business address kullanın, token contract/network'ü doğrulayın, küçük amount test edin, wallet'ı koruyun, trusted RPC/local node kullanın, basis/source saklayın ve required parties'yi screen edin.

**Detection:** complete token event graph, issuer freeze list/actions, exchange/RPC/device ve gas-funding relationships.

## Cashu Chaumian e-cash

**Mechanics:** mint, client-generated bearer secrets'ı blind-sign eder; bunlar mint'in Bitcoin/Lightning reserves'ıyla desteklenir. Mint, issuance'ı later redemption'a doğrudan bağlamadan double-spend'i önleyebilir.

**Pros:** accountless bearer tokens; instant peer transfer; mint blinded withdrawal ile spend'i doğrudan bağlayamaz; tokens data/QR olarak hareket edebilir.

**Cons:** mint custody/solvency/censorship; bearer data loss/theft; denomination/timing ve Lightning boundaries; network metadata; erken software ecosystem.<sup>[[12]](#references)</sup>

**Procedure:** (1) önce official test mint veya çok küçük disposable value kullanın; (2) maintained wallet kurup backup/restore limitations'ı test edin; (3) mint'i authenticate edin ve custody/fees'i inceleyin; (4) küçük amount mint edin; (5) token'ı authenticated private channel/QR ile gönderin; (6) receiver token'ı final kabul etmeden önce swap etsin; (7) redeem ve reconcile edin. Untrusted mint'te anlamlı value tutmayın.

**Detection:** mint network, issue/redeem/Lightning boundaries ve spent-token set'i görür; blinding direct token linkage'ı kaldırır; endpoints/messages ve distinctive amount/timing bağları geri kurabilir.

## Fedimint federated e-cash

**Mechanics:** guardians'ın threshold'u reserves tutar ve e-cash'i blind-sign eder; internal bearer transfers guardians'tan gizlidir; Lightning gateways external payments'ı bağlar.

**Pros:** custody dağıtılır; private internal transfer; community governance; threshold altındayken tek guardian reserve'ü kontrol etmez.

**Cons:** guardian quorum/custody/software risk; gateway invoices/timing'i görür; deposit/withdraw boundaries; client-state recovery complexity.

**Procedure:** (1) federation invite/guardians/quorum/jurisdiction'ı doğrulayın; (2) maintained client kurup recovery'yi test edin; (3) küçük lawful amount deposit edin; (4) fresh internal payment requests kullanın; (5) gateway'i Lightning observer olarak değerlendirin; (6) redemption'ı test edin; (7) source/tax records'ı public payment data dışında saklayın.<sup>[[13]](#references)</sup>

**Detection:** federation aggregate issuance/redemption'ı görür, gateways external invoices'ı görür, Bitcoin/Lightning boundaries'i gösterir ve endpoint/communication evidence internal transfers'ı bağlayabilir.

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash, merchants'a karşı payer'ı anonymous tutmayı; merchants ve income'ı accountable bırakmayı amaçlar.

**Pros:** design gereği payer privacy; ordinary currency; merchant accountability/refunds; speculative token gerekmez.

**Cons:** limited deployments; exchange/bank funding'ı görür; merchant order/delivery'yi görür; wallet bearer/recovery risk; regulated operators.

**Procedure:** (1) jurisdiction/currency için güncel exchange/merchant bulun; (2) KYC/fees/privacy'yi okuyun; (3) official wallet kurun; (4) supported bank/exchange'ten lawful şekilde withdraw edin; (5) merchant contract'ı inceleyin; (6) pay edin ve receipt/refund data saklayın; (7) gereksiz merchant session identifiers kullanmayın.<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal ve merchant deposit accountable boundaries'tir; merchant order/device/delivery ve timing, coins blinded olsa bile correlation sağlayabilir.

## Cross-chain bridge, atomic swap and decentralized exchange

**Mechanics:** contract/service bir asset'i lock/burn eder ve diğerini release/mint eder veya counterparties atomically exchange yapar. Single-ledger görünümünü böler; economic continuity'yi bozmaz.

**Pros:** asset/network interoperability; tek centralized custodian'dan kaçınabilir; ordinary portfolio/liquidity use.

**Cons:** her iki chain public'tir; time/value/fees/liquidity ve contracts correlate olur; bridge/relayer/frontend/RPC records; smart-contract/counterparty ve regulatory risk.

**Procedure for lawful swaps:** (1) official contract/service ve legal availability'yi doğrulayın; (2) custody/audit/fees/slippage'ı inceleyin; (3) küçük test kullanın; (4) her iki transaction ID ve rate'i kaydedin; (5) approvals'ı koruyun; (6) destination asset'i reconcile edin ve unnecessary approval'ları revoke edin. Source of funds'ı gizlemek için swaps kullanmayın.

**Detection:** bridge deposit/withdraw events, unique amount minus fees, time order, liquidity, relayer/RPC/frontend ve later service deposits.

## Centralized mixer or tumbler

**Mechanics:** service deposits'ı pool'a alır ve daha sonra farklı units döndürerek direct input-output mapping'i gizlemeye çalışır.

**Pros:** teorik olarak transaction ambiguity'yi artırabilir.

**Cons:** operator steal/log yapabilir; entry/exit timing/value analysis; sanctions/money-transmission ve criminal exposure; seizures mappings'i açığa çıkarır; taint/rejection risk.

**Procedure:** operational mixing guide sağlanmaz. Graph'ı güvenli biçimde [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) üzerinden reproduce edin: synthetic deposits, pooled outputs, fees ve delays oluşturun; analysts'e incomplete mappings verin; hangi heuristics'in çalıştığını ölçün; sonra ground truth'u açıklayın.

**Detection:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs ve downstream consolidation. Probabilistic attribution olarak etiketleyin.

## Peel chains, fan-out/fan-in and structuring

**Mechanics:** repeated transactions change'den küçük payments ayırır, value'yu birçok address'e böler, collectors'ta reconverge eder veya review'dan kaçınmak için amounts'ı böler.

**Pros:** naive analyst workload ve address count'u artırır.

**Cons:** tanınabilir value/cadence/transaction continuity; consolidation ve service endpoints; structuring kendi başına illegal olabilir; fees ve operational errors.

**Procedure:** yalnızca synthetic CSV/testnet data kullanın: large source, repeated payment/change edges, parallel branches ve one collector üretin; benign exchange-like examples ekleyin; detection'ı tune edin ve false positives'ı belgeleyin.

**Detection:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint ve off-chain records. Exchange hot wallets benzer görünebilir; context zorunludur.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mechanics:** başka bir kişi/account/company funds alır, dönüştürür veya harcar; controller ile transaction arasına legal ve operational layers eklenir.

**Pros to an adversary:** named account controller'ı hemen tanımlamaz; cash, crypto, goods ve jurisdictions arasında bridge kurabilir.

**Cons:** identity fraud/money-laundering exposure; her participant communications, bank/company/tax/shipping records, fees, inconsistency ve witnesses ekler; facilitator reuse hubs oluşturur.

**Procedure:** gerçek kişiler/accounts ile emulate etmeyin. Controller, recruiter, mule, OTC, shell merchant ve beneficiary içeren synthetic graph oluşturun; device/IP/message/bank edges ekleyin; investigators'tan account holder ile controller'ı ayırmalarını ve evidence confidence kaydetmelerini isteyin.

**Detection:** shared device/IP/recovery, unusual beneficiary/velocity, birçok unrelated sender, immediate onward movement, company/director/invoice inconsistency, communications ve cash/commodity delivery.

## NFTs, gambling, merchant goods and refund loops

**Mechanics:** value self-priced asset, wagering balance, resalable goods veya refunds'a dönüştürülerek farklı transaction narrative oluşturulur.

**Pros to an adversary:** asset formunu değiştirir ve marketplace/merchant intermediaries ekler.

**Cons:** marketplace/account/device ve wash-trade graph; odds/play ve refund records; delivery/resale evidence; fees/losses; fraud/laundering liability.

**Procedure:** concealment workflow yoktur. Related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument ve common shipping içeren synthetic marketplace data kullanın; detection'ı legitimate collectors/customers'a karşı doğrulayın.

**Detection:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery ve proceeds reconvergence.

## Physical bearer wallet or offline token transfer

**Mechanics:** device, paper/QR, hardware bearer instrument veya e-cash token, handover sırasında payment broadcast etmek yerine secret üzerindeki control'ü aktarır.

**Pros:** exchange sırasında live network event yok; offline kullanım; physical cash-like custody.

**Cons:** copy/theft/loss ve uncertain exclusivity; later redemption/broadcast links; physical meeting/shipping; counterfeit/tamper risk.

**Procedure:** (1) yalnızca reviewed instrument/protocol kullanın; (2) authenticity'yi private olarak initialize/verify edin; (3) yalnızca küçük lawful value yükleyin; (4) authorized documented context'te transfer edin; (5) receiver protocol gerektiriyorsa prompt verify/sweep yapsın; (6) sender'ın copy tutmadığını varsaymayın; (7) ownership/tax evidence'ı private kaydedin.

**Detection:** purchase/funding ve eventual sweep/redemption, device serial/tamper evidence, delivery/meeting ve endpoint records.

## Merchant-scoped invoice or one-time payment request

**Mechanics:** merchant amount, expiry ve order reference içeren single-use request oluşturur. Payer, reusable credential'ı merchant'a doğrudan vermeden supported rail üzerinden settle eder; issuer/payment processor yine her iki tarafı tanımlayabilir.

**Pros:** credential reuse ve accidental cross-merchant identifiers'ı sınırlar; exact amount/expiry errors'ı azaltır; ordinary accounting/refunds ile uyumludur.

**Cons:** invoice, delivery, browser, processor ve issuer order'ı bağlar; unique amount/time correlation'ı güçlendirebilir; malicious payment links yaygındır.

**Procedure:** (1) merchant'ı bağımsız authenticate edin; (2) exact amount, asset/network ve expiry içeren fresh invoice isteyin; (3) destination ve refund rules'ı inceleyin; (4) approved engagement compartment'tan ödeyin; (5) merchant'ın aynı invoice'ı acknowledge ettiğini doğrulayın; (6) receipt ve transaction reference saklayın; (7) request'i reuse etmek yerine expire edin.

**Detection:** merchant ve processor invoice, session ve settlement'ı birleştirir; unique amounts/timing ve delivery payer'ı tanımlar. **Captured wallet/device:** invoice history counterparties ve purpose'ı açığa çıkarır; unnecessary memo data'yı azaltın, device'i encrypt edin ve authoritative accounting'i controlled finance system'da tutun.

## Prepaid service credit and capability token

**Mechanics:** service conventional payment'ı bounded internal credits veya bearer capability'ye dönüştürür. Subsequent API/resource use her request'te original card'ı göstermeyebilir; ancak service issuance ile redemption'ı çoğu zaman eşleyebilir.

**Pros:** spend ve compromise loss'u sınırlar; day-to-day workers'ı funding credential'dan ayırır; per-project budgets ve revocation destekler.

**Cons:** genellikle pseudonymous, anonymous değil; service database, redemption IP ve unique usage pattern activity'yi bağlar; bearer tokens çalınabilir; refunds original payer gerektirebilir.

**Procedure:** (1) credits'ı organization account üzerinden satın alın; (2) tek project ve budget oluşturun; (3) service, amount ve expiry constraints içeren narrow token verin; (4) yalnızca approved secret manager veya workload identity path'te saklayın; (5) scope dışı ve expiry sonrası rejection'ı test edin; (6) consumption'ı izleyin; (7) unused value'yu revoke ve reconcile edin.

**Detection:** provider funding account, project, token issuance ve usage'ı birleştirir; defenders geographic/process changes ve anomalous consumption için alert üretir. **Captured node:** remaining capability'nin harcanabileceğini varsayın; short expiry, low balance, audience binding ve immediate server-side revocation kullanın.

## Privacy Pass or blinded authorization token

**Mechanics:** issuer, origin'in redemption'ı issuance'a bağlamadan doğrulayabileceği privacy-preserving authorization token üretir. Paid entitlement veya rate-limited access temsil edebilir; general currency değildir. Architecture client, attester, issuer ve origin rollerini ayırır ve IP/timing veya collusion'ın unlinkability'yi bozabileceğini belirtir.<sup>[[18]](#references)</sup>

**Pros:** desteklenen services için unlinkable redemption; origin'de reusable account cookie yok; cached tokens issuance ve use'ı zaman bakımından ayırabilir.

**Cons:** application-specific; issuer/attester trust ve anonymity-set partitioning; IP/browser metadata kalır; token theft veya distinctive issuance timing use'ı correlate edebilir.

**Procedure:** (1) relevant Privacy Pass token type'a uygun implementation kullanın; (2) token'ın kanıtladığı entitlement'ı tanımlayın; (3) threat model gerektiriyorsa issuer ve origin administration'ı ayırın; (4) challenge metadata'yı azaltın; (5) birkaç test token issue edin ve owned origins'te her birini bir kez redeem edin; (6) forbidden stable identifiers için logs'u karşılaştırın; (7) replay, expiry ve revocation/abuse controls'ı test edin.

**Detection:** origins redemption IP/time ve token validity'yi görür; issuers/attesters issuance context'i görür; analysts cryptographic break varsaymadan timing ve metadata partitions'ı test eder. **Captured client:** unspent bearer tokens kullanılabilir; value, lifetime ve audience'ı sınırlandırın ve funding credential'ı bunlarla cache etmeyin.

## Delegated organization procurement or fiscal sponsor

**Mechanics:** authorized procurement team, reseller veya fiscal sponsor contract yapar ve ödeme yapar; operational team bounded service alır. Bu truthful records içeren role separation'dır; nominee veya false identity değildir.

**Pros:** vendors her operator'ın identity veya personal payment details'ını almak zorunda kalmaz; central compliance, tax ve refund handling; açık budget ve offboarding.

**Cons:** sponsor beneficiary ve purpose'ı bilir; contracts, approvals, delivery ve accounts kalır; delay/fees; aynı kişi her layer'ı yönetirse separation zayıflar.

**Procedure:** (1) business purpose, beneficiary ve approving authority'yi document edin; (2) organization-approved intermediary seçin; (3) truthful details ile contract yapın; (4) personal billing credential içermeyen project-scoped subaccount provision edin; (5) finance administrators ve operators'ı ayırın; (6) invoices ve access'i reconcile edin; (7) closeout'ta service ve delegated access'i sonlandırın.

**Detection:** procurement, identity-provider, vendor ve delivery records zinciri birleştirir. **Captured operational device:** service project'i gösterebilir, finance credentials'ı göstermemelidir; invoices ve payer identities'ı field nodes yerine finance system'da tutun.

## Escrow or conditional settlement

**Mechanics:** trusted escrow agent veya smart contract, documented conditions karşılanana kadar value tutar. Payer ve payee arasındaki direct disclosure'ı azaltabilir; escrow ve underlying payment rails relationship'i korur.

**Pros:** dispute/delivery protection; payer ve merchant reusable credentials'ı birbirine daha az açabilir; auditable release conditions.

**Cons:** escrow custody/contract risk, fees ve identity obligations; on-chain contracts public; order, shipping ve dispute data kalır; intermediary'ye karşı anonymous değildir.

**Procedure:** (1) legal entity, custody, fees, dispute forum ve supported assets'ı doğrulayın; (2) exact written milestone ve refund path oluşturun; (3) approved organization account'tan fund edin; (4) receipt ve release authorization'ı bağımsız doğrulayın; (5) yalnızca evidence sonrası release edin; (6) complete audit record saklayın; (7) kullanılmayan permissions/contract approvals'ı kapatın.

**Detection:** escrow account/contract events, funding ve release time, beneficiary ve dispute records transaction'ı açığa çıkarır. **Captured device:** session tokens veya contract approvals release'e izin verebilir; separate approver/MFA isteyin ve loss durumunda active sessions'ı revoke edin.

## Batched or pooled organization settlement

**Mechanics:** çok sayıda approved obligation aggregate edilir ve daha az bank/blockchain transaction ile settle edilir; private internal ledger her share'i atar. Batching public per-purchase detail'i azaltabilir; coordinator complete attribution tutar.

**Pros:** lower fees; fewer public graph edges; amounts aggregated olduğunda public observer'dan individual line items gizlenir; straightforward internal accounting.

**Cons:** coordinator complete observer ve high-value target'tır; distinctive totals/timing correlate olabilir; custody/reconciliation risk; kötüye kullanılırsa structuring'e benzeyebilir.

**Procedure:** (1) participants ve lawful obligations'ı accounting system'da tanımlayın; (2) controls'tan kaçınmak için threshold yerine regular, business-justified batch window belirleyin; (3) aggregate için dual approval isteyin; (4) authenticated recipients'a settle edin; (5) her internal line'ı batch'e reconcile edin; (6) refunds'ı linked corrections olarak ele alın; (7) ledger access'i koruyun ve policy'ye göre saklayın.

**Detection:** coordinator ledger, approval ve beneficiary records ground truth sağlar; public analysts input/output/value/time clustering'i dikkatle kullanmalıdır. **Captured payer device:** yalnızca requisition içermeli, pool signing key veya participant ledger içermemelidir.

## Account-abstraction paymaster or sponsored gas

**Mechanics:** relayer/bundler smart-account operation'ı gönderir ve paymaster transaction fees'i öder; user wallet'tan direct native-gas funding edge'i ortadan kalkar. Bir graph property'yi iyileştirir; operation, contract ve service telemetry public/observable kalır.<sup>[[19]](#references)</sup>

**Pros:** common gas-funding link'i kaldırır; scoped sponsorship ve rate limits destekler; legitimate privacy applications için onboarding'i iyileştirir.

**Cons:** paymaster/bundler/RPC/front end requests'ı correlate edebilir; contract events ve public inputs kalır; sponsorship policy cohort'u fingerprint eder; malicious contracts/approvals assets çalabilir.

**Procedure:** (1) doğru network'te audited maintained smart account ve paymaster kullanın; (2) hangi fields'ların public olduğunu ve sponsor'un ne log'ladığını inceleyin; (3) sponsorship'ı contract, function, amount, nonce ve expiry ile sınırlandırın; (4) düşük value ile test edin; (5) application's intended privacy-aware path üzerinden submit edin; (6) operation ve fee payer'ı chain üzerinde doğrulayın; (7) allowances/session keys'i revoke edin ve compliance records saklayın.

**Detection:** UserOperation, EntryPoint, paymaster, bundler/RPC ve application logs'u birleştirin; identical sponsorship policy'yi dikkatle cluster edin. **Captured wallet:** session keys ve pending approvals gas olmadan da kullanılabilir; dar scope verin ve account recovery policy üzerinden revoke edin.

## Threshold or multisignature payment authorization

**Mechanics:** spending için independent signers'ın threshold'u gerekir. Transaction'ı gizlemez; payment authority'yi captured laptop, field node veya tek operatörden ayırır.

**Pros:** strong compromise/insider resistance; accountable approval; field device complete signing authority tutmaz; recovery desteklenir.

**Cons:** coordination/availability; signer/device/account metadata participants'ı correlate edebilir; kötü backup loss'a yol açar; public multisig patterns identifiable olabilir.

**Procedure:** (1) funding öncesi signers, threshold, limits ve recovery'yi belirleyin; (2) separate supported hardware/accounts üzerinde initialize edin; (3) addresses ve backups'ı bağımsız doğrulayın; (4) field workloads'a yalnızca unsigned requisition capability verin; (5) recipient, amount ve purpose için out-of-band review isteyin; (6) recovery ve one-signer loss'u küçük value ile test edin; (7) compromise sonrası signer rotate edin.

**Detection:** approval system, signer device ve public script/contract evidence sağlar; policy veya signer-set changes için alert üretin. **Captured node:** en fazla low-authority session key veya unsigned request açığa çıkarmalı; quorum material'ı birlikte cache etmeyin.

## Closed-loop community or event currency

**Mechanics:** cooperative, conference veya private test environment, yalnızca enrolled participants arasında redeem edilebilen credits çıkarır. Internal transfer global payment networks'e daha az exposure sağlayabilir; issuance/redemption operator kontrolündedir.

**Pros:** bounded economic domain; offline veya privacy-preserving payment UX test edilebilir; external card exposure sınırlanır; clear experimental controls.

**Cons:** small anonymity set; operator/merchants activity'yi görür; limited acceptance/redemption; local value için bile licensing, consumer-protection ve tax rules uygulanabilir.

**Procedure:** (1) legal/compliance review alın ve issuer terms yayınlayın; (2) consenting test participants enroll edin; (3) issuance'ı cap edin ve cash-like misuse'ı yasaklayın; (4) fresh payment requests kullanın ve public participant identifiers'ı azaltın; (5) aggregate reserves ve private individual receipts kaydedin; (6) loss/refund/redemption'ı test edin; (7) ledger'ı kapatın ve residual value'yu promise edildiği gibi iade edin.

**Detection:** issuer ledger, enrollment, merchant ve redemption records flows'u yeniden kurar; unusual circular transfers veya rapid cash-out inceleme gerektirir. **Captured wallet:** local balance ve counterparties açığa çıkabilir; value'yu cap edin, state'i encrypt edin ve auditable issuer-side freeze/reissue destekleyin.

## Bitcoin reusable payment codes and private payment instructions

**Mechanics:** BIP 47 reusable public identifier ve ECDH-derived one-time deposit addresses kullanır; BIP 351 newer private-payment instruction design belirtir. Recipient'in stable payment instructions yayınlamasına izin verirken public address reuse'ı azaltır. Notification, wallet support, funding ve subsequent coin selection privacy'yi etkiler.<sup>[[20]](#references)</sup>

**Pros:** tek public instruction distinct addresses üretebilir; recipient her invoice address'ını yayınlamak zorunda kalmaz; compatible wallets derived payments'ı monitor edebilir; repeated lawful donors/customers için yararlı.

**Cons:** wallet interoperability değişir; notification transactions veya published payment code relationship context'i bağlar; sender, recipient ve public graph transactions'ı görür; careless consolidation/change handling faydayı yok eder.

**Procedure:** (1) iki maintained wallet'ın aynı specification/version'ı desteklediğini doğrulayın; (2) low-value wallet'ta backup/recovery test edin; (3) recipient payment code'u out of band authenticate edin; (4) küçük lawful test gönderin; (5) fresh derived address kullanıldığını doğrulayın; (6) relationship'i local label'layın ve coin control uygulayın; (7) reliance öncesi recovery/refund behavior'ı test edin.

**Detection:** analysts notification patterns, funding/change, later consolidation ve service boundaries'i inceler; public-code publication, deposit addresses farklı olsa bile recipient context'i belirler. **Capture-resilient OPSEC:** spend keys'i field devices'tan uzak tutun ve en fazla watch-only relationship view açın. **Monitoring:** unexpected notification transactions, reused derived addresses, wallet gap-limit/recovery errors ve unplanned consolidation için alert üretin.

## EVM stealth addresses (ERC-5564)

**Mechanics:** sender recipient'ın stealth meta-address'inden one-time stealth account türetir ve ephemeral public key ile view tag içeren announcement yayınlar. Recipient viewing key ile announcements'ı scan eder ve matching spend key'i türetir. Recipient linkage iyileşir; sender, amount/token, gas, announcement ve later spending görünür kalır.<sup>[[21]](#references)</sup>

**Pros:** non-interactive fresh receiver address; reusable meta-address; viewing ve spending roles ayrıdır; supported EVM assets/applications arasında çalışır.

**Cons:** announcement scanning ve spam; new address için gas funding relink edebilir; sender recipient'ı bilir; public token/amount ve eventual consolidation kalır; implementation/wallet support değişir.

**Procedure:** (1) audited maintained implementation'ı önce test network'te kullanın; (2) separate viewing/spending material üretip backup alın; (3) meta-address'i authenticate edin; (4) low-value test ve announcement gönderin; (5) stealth account'ı scan edip derive edin; (6) personal funding edge olmadan supported gas sponsorship'ı test edin; (7) public fields'ı kaydedin ve lawful accounting saklayın.

**Detection:** announcement caller, token/amount, timing, gas sponsor, spending ve consolidation'ı takip edin; view key receipt'i spend yetkisi vermeden kanıtlayabilir. **Capture-resilient OPSEC:** networked scanner mümkünse yalnızca viewing role taşımalı; spend ve recovery keys başka yerde tutulmalıdır. **Monitoring:** malformed/spam announcements, view-key access, unexpected spend derivation ve unapproved stealth outputs movement için alert üretin.

## Liquid Confidential Transactions

**Mechanics:** Liquid, commitments ve proofs kullanarak output amounts ve asset types'ı default olarak blind eder; transaction graph, input/output count, fee ve block time görünür kalır. Peg-in/peg-out ve service boundaries linkable'dır; users blinding data'yı selective disclose edebilir.<sup>[[22]](#references)</sup>

**Pros:** default confidential amount ve asset type; fast sidechain settlement; blinding keys/descriptors ile selective audit; commercially sensitive values public observers'tan gizlenir.

**Cons:** graph structure ve timing kalır; federation/bridge ve exchange trust; peg boundaries ve unconfidential outputs; wallet/node/network records; receiver ve sender transaction'ı bilir.

**Procedure:** (1) maintained Liquid wallet seçin ve backup model'ini doğrulayın; (2) testnet veya küçük lawful amount kullanın; (3) confidential address'a alın ve wallet'ın output'u blinded işaretlediğini doğrulayın; (4) test confidential transaction gönderin; (5) explorer fields'ın hangilerinin public kaldığını inceleyin; (6) audit için gereken scoped blinding proof'u export edin; (7) peg/exchange boundaries'i document edip funds'u reconcile edin.

**Detection:** visible graph/fee/time, peg ve exchange records, network metadata ve later unblinding evidence'ı analiz edin; hidden amount veya asset hakkında çıkarım yapmayın. **Capture-resilient OPSEC:** spend seed, blinding/view data ve watch-only operations'ı ayırın. **Monitoring:** accidental unconfidential addresses, unknown peg requests, descriptor changes ve unapproved unblinding-key export için alert üretin.

## General payment or state channel

**Mechanics:** participants funds lock eder, signed off-chain state updates değiş tokuş eder ve chain'e yalnızca opening, closing veya disputed state'i yayınlar. Intermediate payments globally broadcast edilmez; ancak peers ve routing/intermediary services kendi kısımlarını görür, endpoints ise latest enforceable state'i tutmalıdır.<sup>[[23]](#references)</sup>

**Pros:** birçok hızlı, düşük fee'li private-to-public-ledger interaction; daha az global transaction detail; bounded channel balance; metered services ve repeated counterparties için yararlı.

**Cons:** channel peers birbirini bilir ve updates tutabilir; opening/closing/value/timing correlate olur; challenge windows sırasında online monitoring gerekebilir; implementation/liquidity risk; tek başına büyük anonymity set değildir.

**Procedure:** (1) maintained audited implementation seçin ve dispute window'u anlayın; (2) owned parties arasında low-value test channel açın; (3) unique nonces ile signed state updates exchange edin; (4) latest enforceable state'i backup edin; (5) cooperatively close edin; (6) testnet'te stale-state rejection'ı rehearse edin; (7) accounting ve channel-peer records saklayın.

**Detection:** public chain lifecycle/disputes'ı gösterir; peers, watch services ve application transport off-chain timing/parties'yi açığa çıkarır. **Capture-resilient OPSEC:** hot balance'ı sınırlayın ve latest signed state'i field nodes'tan ayrı encrypted recoverable store'da tutun. **Monitoring:** stale-state publication, missed backup, peer-key change ve approaching challenge deadline'ı sürekli izleyin.

## Mobile carrier billing

**Mechanics:** online service purchase'ı mobile subscription veya prepaid balance'a carrier billing system üzerinden charge eder. Merchant card/bank details yerine carrier authorization alabilir; carrier subscriber/line, device/network context, merchant, amount ve time'ı bilir.<sup>[[24]](#references)</sup>

**Pros:** merchant card number almaz; geniş phone availability; low-value digital goods; carrier charges'ı cap/reverse edebilir.

**Cons:** SIM/account ve çoğu zaman device ile strongly identified; small limits ve high fees; merchant category restrictions; account takeover/SIM-swap risk; carrier ve aggregator complete trail oluşturur.

**Procedure:** (1) organization carrier account ile availability, limit, fee ve refund terms'ü doğrulayın; (2) gerekçeliyse dedicated organization line'da etkinleştirin; (3) lowest useful spend cap belirleyin; (4) benign test item satın alın; (5) merchant/carrier receipts'ı doğrulayın; (6) recurring authorization'ı kapatın; (7) reconcile edin ve assessment sonrası feature'ı kapatın.

**Detection:** carrier, aggregator ve merchant records line, subscriber, IP/device ve charge'ı birleştirir; enterprise telecom invoices açığa çıkarır. **Capture-resilient OPSEC:** personal number kullanmayın ve carrier-account MFA'yı field device dışında tutun. **Monitoring:** instant charge/SIM-change alerts etkinleştirin; unexpected premium-service enrollment, forwarding veya account recovery'de durun.

## Open-banking payment initiation

**Mechanics:** explicit user consent ile regulated PISP, account-servicing bank'ten transfer başlatmasını ister. Merchant card credentials almayabilir; PISP ve banks regulated payer, payee, consent, device ve transaction records tutar.<sup>[[25]](#references)</sup>

**Pros:** checkout'ta reusable card number yok; strong bank authentication; exact account-to-account settlement; consent/status APIs; clear reconciliation.

**Cons:** banks/PISP'ye karşı anonymous değildir; payee legal account details veya reference görebilir; phishing/redirect risk; jurisdiction/refund protections değişir; consent metadata ek observer'dır.

**Procedure:** (1) PISP'in halen regulated olduğunu ve merchant callback domain'inin authentic olduğunu doğrulayın; (2) merchant request'ten başlayın; (3) bank'te payee, amount, reference ve requested consent'i inceleyin; (4) yalnızca single payment authorize edin; (5) final status'ı bağımsız doğrulayın; (6) residual consent varsa revoke edin; (7) receipt saklayın ve reconcile edin.

**Detection:** bank/PISP/merchant logs ve transfer references güçlü attribution sağlar. **Capture-resilient OPSEC:** banking authentication ve recovery'yi operational/field devices'tan uzak tutun; device yalnızca paid-service entitlement taşımalıdır. **Monitoring:** bank transaction/consent alerts kullanın; new PISP grants, changed payee veya expected session dışındaki status callbacks'i inceleyin.

## Platform wallet, app-store balance or in-app credit

**Mechanics:** platform user'ı bill eder veya account credit redeem eder, ardından application'a signed receipt/entitlement verir. App developer original funding instrument'ı almayabilir; platform account, device, funding, product ve redemption'ı eşler.<sup>[[26]](#references)</sup>

**Pros:** merchant/developer primary PAN almaz; fraud/refund ve family/business controls; küçük prepaid balance exposure'ı sınırlar; signed receipts entitlement verification'ı kolaylaştırır.

**Cons:** platform account güçlü identity/behavior hub'dır; device ve storefront geography; gift-balance purchase/redemption trail; limited cash-out; fraud controls funds'ı freeze edebilir; cross-platform money değildir.

**Procedure:** (1) policy izin veriyorsa organization-managed platform account kullanın; (2) funding, region, refund ve transferable-value rules'ı inceleyin; (3) yalnızca approved budget ekleyin; (4) official store üzerinden benign product satın alın; (5) application'ın yalnızca beklenen receipt fields'ı aldığını doğrulayın; (6) recurring purchase'ı kapatın; (7) reconcile edin ve account'ı operational hardware'dan kaldırın.

**Detection:** platform receipts/server notifications, account/device login ve funding records purchase'ı yeniden kurar. **Capture-resilient OPSEC:** field node'u personal store account'a sign-in ettirmeyin; mümkünse yalnızca scoped app entitlement sağlayın. **Monitoring:** new-device/purchase alerts etkinleştirin; receipt replay, family/account changes veya unexpected restore events'i inceleyin.

## Mutual credit, clearing or periodic net settlement

**Mechanics:** participants obligations'ı private ledger'a kaydeder ve yalnızca net position'larını periodik olarak settle eder. Individual service events ayrı public payments oluşturmayabilir; ledger operator ve counterparties detailed attribution tutar.

**Pros:** fewer external transactions/fees; public observers yalnızca net settlement görür; repeated organizations için çalışır; explicit credit limits exposure'ı sınırlar.

**Cons:** centralized ledger complete evidence ve fraud target'tır; counterparty/default risk; legal/accounting/tax duties; small membership set; unusual net transfers relationships'i açığa çıkarabilir.

**Procedure:** (1) yalnızca identified consenting organizations ve legal/accounting approval kullanın; (2) unit, credit limit, settlement interval ve dispute rules belirleyin; (3) her obligation'ı immutable approval ile kaydedin; (4) ayrı finance roles net positions'ı hesaplayıp approve etsin; (5) ordinary lawful rail ile settle edin; (6) individual lines'ı settlement'a reconcile edin; (7) access'i kapatın ve policy'ye göre records saklayın.

**Detection:** ledger, invoices, approvals ve final bank/chain settlement ground truth sağlar; analysts yalnızca net transfer'den missing gross activity çıkarmamalıdır. **Capture-resilient OPSEC:** operational devices bounded requisitions gönderebilir; balances'ı edit edemez veya settlement authorize edemez. **Monitoring:** credit-limit breach, backdated entries, administrator changes, reconciliation mismatch ve new beneficiary settlement için alert üretin.

## Capture/compromise exposure matrix

Bu bölüm her family için seizure/loss test uygular. Amaç transactions'ı silmek veya investigation'ı engellemek değil; lawful accounting'i korurken spend authority ve unrelated identity disclosure'ı sınırlamaktır.

| Technique family | A captured wallet/device/account can reveal | Minimum authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value ve physical contacts | yalnızca approved amount taşıyın; private accounting'i ayırın; loss'u hemen bildirin; false records tutmayın |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption ve account/session tokens | düşük balance; tek purpose; truthful registration; varsa issuer freeze/revocation |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery ve merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; shared recovery account kullanmayın |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices ve project | role separation; least-privilege subaccount; finance credentials operational/field nodes'ta tutulmamalı |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator veya dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph ve network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP ve payment database | minimal hot balance; encrypted backup; separate node identity; documented close/recovery |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC ve boundary transactions | separate spend/view roles; available olduğunda hardware support; field node'da exchange session yok |
| Stablecoins, swaps, bridges ve DEX | transparent graph, approvals, RPC/front-end state ve destination assets | allowances revoke; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; protocol destekliyorsa encrypted backup; redeem/reissue; funding credential'ı colocate etmeyin |
| Paymaster, multisig/threshold | session key, one signer, pending operations ve sponsor policy | narrow session key; independent quorum; signer rotation; field device threshold'a erişemez |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph ve participant records | operational use yok; yalnızca synthetic/testnet evidence ile emulate edin |
| Community/event currency | enrollment, local balance, counterparties ve redemption | capped value; issuer freeze/reissue; consent ve private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements ve derived outputs | watch/view-only network role; offline/hardware spend role; personal funding session yok |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries ve disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device ve funding source | organization account; external MFA; low limit; field hardware'da personal account yok |
| Mutual-credit clearing | members, obligations, limits, approvals ve settlement ledger | operational requisition only; separate immutable ledger ve dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial, compliance review veya wallet'ın offline olması investigation bulunduğunu kanıtlamaz. Yalnızca organization'ın gözlemleme yetkisi olan accounts, ledgers ve infrastructure'ı izleyin; providers veya counterparties'nin investigators ile iş birliği yapıp yapmadığını test etmek için probe etmeyin.

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund veya loss report | missing instrument, approved order dışı redemption, altered receipt veya custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap veya recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice ve consumption | cross-project token, unknown admin, limit breach, invoice mismatch veya unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation ve beneficiary change | altered amount/payee, backdated ledger, unilateral release veya unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels ve consolidation | unknown spend, reused recipient output, wallet gap/recovery failure veya unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure veya coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP ve chain dispute | unknown invoice payment, peer-key change, stale close veya approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor ve boundary transaction | spend without approval, transparent/unconfidential downgrade, key export veya unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key ve issuer action | wrong contract/public field, unknown approval/spend, paymaster change veya issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway ve bearer balance | unknown redemption, mint key/terms change, restore failure veya balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate ve destination | contract/route mismatch, unlimited approval, missing destination veya bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum ve recovery audit | unknown proposal/signer, threshold reduction, recovery activation veya policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | yalnızca synthetic lab ground truth ve detection output | gerçek account, person veya value emulation'a girerse hemen durun |

## Selection and verification workflow

1. Hangi party'nin hangi field'ı öğrenmemesi gerektiğini belirtin.
2. Issuer/mint/custodian, public ledger, network/RPC, merchant ve physical observers'ı belirleyin.
3. Güncel support, legality, limits, custody, recovery ve refund behavior'ı doğrulayın.
4. Küçük ve lawful bir end-to-end test yapın.
5. Merchant receipt, provider statement, public chain ve wallet/node logs'u inceleyin.
6. Backup/recovery ve deliberate audit disclosure'ı test edin.
7. Gerekli source, ownership, tax, sanctions ve engagement records'ı doğru fakat access-controlled biçimde tutun.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Büyük ödeme platformları tarafından veri toplanmasına ilişkin gözlemler](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Gizliliğinizi koruyun](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Basit Bir Payjoin Önerisi](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technical specifications and network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Zero-knowledge proofs ile privacy applications oluşturma](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol and privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — Nasıl çalışır](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Virtual currency administrators, exchangers ve users](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information and crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
