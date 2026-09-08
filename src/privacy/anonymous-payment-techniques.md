# Anonymous Payment Technique Catalog

{{#include ../banners/hacktricks-training.md}}

Bu katalog, sıradan nakitten blind-signature e-cash'e ve public-chain obfuscation yöntemlerine kadar ödeme **ailelerini** kapsar. “Anonymous” her zaman adı belirtilmiş bir gözlemciye göre anonymous anlamına gelir. Merchant, issuer, mint, exchange, blockchain analyst, network provider, employer ve fiziksel gözlemci farklı gerçekleri görür.

Aşağıdaki prosedürler yasal fonlar, doğru hesaplar ve yetkili tedarik içindir. Atıf yapılan vakalarda amacı laundering, sanctions evasion veya identity fraud olan teknikler açıklanır ve tespit edilir; ancak prosedürleri suçu gerçekleştirme talimatı değil, sentetik bir adli inceleme çalışmasıdır.

## Coverage matrix

| Family | Main privacy property | Main observer/trust | Treatment |
|---|---|---|---|
| Cash and cash equivalents | uzak ödeme ağı kaydı yok | alıcı ve fiziksel ortam | yasal iş akışı |
| Prepaid/gift/voucher value | redemption'ı birincil karttan ayırır | seller, issuer ve redemption service | yasal iş akışı, yargı bölgesine göre değişir |
| Virtual/tokenized card | yeniden kullanılabilir PAN'ı gizler veya merchant'ları ayırır | issuer/network/wallet yine payer'ı tanımlar | yasal iş akışı |
| Payment app/intermediary | merchant alias/intermediary görebilir | app identity/device/transaction toplar | karşılaştırma temeli |
| Bitcoin hygiene/Silent Payments | pseudonym ve alıcı ilişkilendirilemezliği | public graph ve wallet/network sınırı | uygulanabilir |
| PayJoin/CoinJoin | common ownership/linkage sezgilerini zayıflatır | participant/coordinator/network/public graph | desteklenen yerlerde uygulanabilir; hukuki inceleme gerekir |
| Lightning/BOLT 12 | off-chain routing ve receiver-path azaltımı | endpoint, hop, service ve channel graph | desteklenen yerlerde uygulanabilir |
| Monero/Zcash/MWEB | protocol seviyesinde on-chain confidentiality | acquisition, endpoint, network ve sınırlar yine kalır | yasal/desteklenen yerlerde uygulanabilir |
| Ethereum ZK application | belirli bir statement/action bağlantısını gizler | public input, RPC, relayer ve app | uygulamaya özgü |
| Cashu/Fedimint/Taler | blind-signature payer privacy | mint/federation/exchange custody ve sınırlar | gelişmekte/dağıtıma özgü |
| Stablecoins | kullanışlı digital settlement | transparent chain ve issuer freeze/control | anonymous için temel değildir |
| Swaps/bridges/DEX | değeri asset/chain'ler arasında taşır | her iki graph, contract ve provider | adli mekanikler; yalnızca olağan yasal swap'lar |
| Mixers/peel/structuring | graph belirsizliğini/iş yükünü artırır | giriş/çıkış graph'ı ve service kayıtları | yalnızca sentetik tespit çalışması |
| Nominees/mules/OTC/fronts | insan/business intermediary ekler | facilitator, bank, communication | yalnızca suç amaçlı kötüye kullanım analizi |
| Reusable/stealth payment addresses | her ödeme için yeni alıcı adresi | public announcement/notification ve wallet sınırları | desteklenen yerlerde uygulanabilir |
| Confidential sidechain/state channel | amount/asset veya ara güncellemeleri gizler | peer, bridge/federation ve lifecycle settlement | protocol'a özgü |
| Carrier/open-banking/platform billing | birincil kartı merchant'tan gizler | carrier, bank/PISP veya platform customer'ı tanımlar | sıradan tanımlı ödeme |
| Mutual credit/net settlement | daha az harici settlement kaydı | private ledger operator tam eşleştirmeye sahiptir | yalnızca tanımlı katılımcılar |

## Cash

**Mechanics:** physical bearer value, online issuer authorization veya public ledger olmadan el değiştirir.

**Pros:** merchant bank/card identity öğrenmek zorunda değildir; remote transaction graph yoktur; genel olarak anlaşılır ve kesindir.

**Cons:** yalnızca yüz yüze; theft/loss; para üstü/receipt/serial veya reporting kontrolleri; withdrawal, camera, witness ve konum yine payer'ı ilişkilendirebilir.

**Procedure:** (1) nakdin yasal ve kabul edilir olduğunu ve amount/reporting kurallarını doğrula; (2) nakdi yasal biçimde çek veya al ve private accounting kayıtlarını tut; (3) gereksiz loyalty/account identifier kullanmadan ordinary merchant'a ödeme yap; (4) yalnızca gerekli receipt'i iste; (5) alışveriş gerektirmiyorsa shipping/account verisi verme; (6) meşru business purpose'ı kurum içinde kaydet.

**Detection:** uygulanabilir policy kapsamında till/receipt/inventory, camera ve access log'larını uzlaştır; sıradan nakit kullanımını tek başına şüpheli saymadan olağandışı cash refund veya kontrol eşiğinin hemen altındaki tekrar eden tutarları incele.

## Money order, postal order, cashier instrument and cash on delivery

**Mechanics:** regulated issuer, cash/account funds'ı named recipient'a ödenecek numaralı bir instrument'a dönüştürür; COD tahsilatı delivery'ye erteler.

**Pros:** recipient payer'ın primary bank/card number'ını almayabilir; nakdin uzaktan taşınamadığı yerlerde kullanılabilir; açık receipt.

**Cons:** issuer/retailer gerektiği ölçüde purchase/identity data saklar; serial tracking; recipient/delivery address; loss/fraud ve bölgesel kısıtlamalar; genellikle anonymous değildir.

**Procedure:** (1) issuer kurallarını, limitleri, identification gereksinimlerini ve recipient kabulünü kontrol et; (2) doğru bilgiler ve yasal fonlarla satın al; (3) payee/amount alanlarını hemen doldur; (4) serial/receipt'i koru; (5) değere uygun tracked delivery kullan; (6) redemption/refund işlemini uzlaştır.

**Detection:** issuer purchase/redemption kaydı, instrument serial, retailer/camera, shipping ve recipient account; alteration, duplicate serial ve coğrafi olarak tutarsız hızlı redemption durumlarını işaretle.

## Open-loop prepaid card

**Mechanics:** network-branded stored-value credential, primary credit account yerine prepaid balance üzerinden authorization yapar.

**Pros:** merchant exposure ve kaybı sınırlar; merchant'ı main PAN'dan ayırır; kabul edildiği yerlerde online kullanılabilir.

**Cons:** purchase/activation/reload/registration ve device kayıtları; KYC ve limitler değişir; billing-address hataları; cash-out/refund kısıtları; “no name” issuer kaydı olmadığı anlamına gelmez.

**Procedure:** (1) güncel issuer identity, fees, KYC, geography ve online/recurring desteğini doğrula; (2) authorized seller'dan yasal fonlarla edin; (3) gereken doğru bilgileri kaydet; (4) tek bir compartment/purpose için kullan; (5) load'ları structure etme veya sahte residency oluşturma; (6) purchase/expense kanıtını sakla ve issuer şartlarına göre kapat/elden çıkar.

**Detection:** seller/activation, funding, device/IP, merchant authorization, balance check ve redemption/refund kayıtlarını birleştir. Prepaid etiketi değil, pattern'ler önemlidir.

## Closed-loop gift card, voucher and transferable service credit

**Mechanics:** numbered value yalnızca tek merchant/service veya ecosystem içinde redeem edilebilir. Airtime/game/store credit türleri varyanttır.

**Pros:** recipient merchant yalnızca code/balance görebilir; sınırlı blast radius; kolay gifting ve budget separation.

**Cons:** seller/service purchase/activation/redemption kaydeder; account/device/delivery yine bağlantı kurar; scam, resale discount, expiry/region limitleri; zayıf refund hakları.

**Procedure:** (1) yalnızca authorized channel'lardan satın al; (2) code value'yu secret'ı açığa çıkarmadan kaydet; (3) gereksizse identifying loyalty account bağlama; (4) ayrı bir legitimate merchant account/context üzerinden redeem et; (5) kabul edilene kadar receipt'i sakla; (6) unsolicited “tax/support/ransom” talebi için hiçbir zaman code satın alma.

**Detection:** code issuance/redemption zamanı, device/account convergence, bulk/threshold-pattern purchase, çok sayıda balance kontrol eden tek device ve uzak konumlarda hızlı redemption.

## Cryptocurrency-funded card or gift-code broker

**Mechanics:** intermediary cryptocurrency kabul eder ve card, voucher veya merchant code verir. Bu bir cross-rail conversion'dır: merchant ordinary card/gift value görür; broker ise on-chain deposit'i issuance ve delivery ile bağlar.

**Pros:** merchant funding wallet'ı görmez; crypto kabul etmeyen meşru merchant'lar için kullanılabilir; sınırlandırılmış stored value.

**Cons:** broker/issuer'a karşı anonymous değildir; KYC, sanctions, exchange ve card-program kuralları; public deposit graph; account/device/email ve code redemption iki tarafı yeniden bağlar; scam/insolvency riski.

**Procedure:** (1) legal entity, card issuer, supported jurisdiction, KYC, fees ve refund policy'yi doğrula; (2) yalnızca yasal ve belgelenmiş fon kullan; (3) en küçük denomination ile test et; (4) satın alma öncesi network/merchant kısıtlarını kontrol et; (5) blockchain transaction ve broker receipt'i accounting için sakla; (6) identity fraud, sanctions bypass veya “untraceable” cash-out vaat eden broker'ları kullanma.

**Detection:** broker deposit address'leri, unique amount/time, account/device ve issued-card authorization veya gift-code redemption'ı ilişkilendir; issuer ve broker kayıtları public chain'i merchant'a bağlar.

## Virtual or merchant-locked card

**Mechanics:** issuer, generated PAN/token'ı gerçek account'a eşler ve çoğu zaman merchant, amount veya expiration ile sınırlar.

**Pros:** reusable PAN disclosure'ı önler; merchant compartmentation; spend limit ve kolay revocation; gelişmiş fraud control.

**Cons:** issuer payer, funding, merchant, device/IP ve zamanı bilir; merchant account/delivery görür; bazı refund/recurring charge başarısız olur; anonymous değildir.

**Procedure:** (1) regulated issuer'ın official feature'ını kullan; (2) tek merchant/engagement için card oluştur; (3) gerekli en düşük limit ve expiry'yi ayarla; (4) gerektiğinde doğru billing kullan; (5) statement descriptor/refund davranışını doğrula; (6) final settlement sonrası freeze/delete et ve audit evidence'ı koru.

**Detection:** issuer token-to-account mapping, merchant authorization, device ve delivery. Defenders merchant-specific reuse, velocity ve account-takeover sinyallerini kullanır.

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization, PAN yerine çoğu zaman device, merchant veya payment scenario'ya bağlı sınırlı bir credential koyar.<sup>[[1]](#references)</sup>

**Pros:** merchant reusable PAN almaz; device cryptography/dynamic data cloning'i azaltır; card replacement olmadan revoke edilebilir.

**Cons:** issuer, token service, wallet platform ve network mapping/transaction saklar; device/platform account ve location payer'ı tanımlayabilir.

**Procedure:** (1) legitimate card'ı official wallet'a enroll et; (2) platform account/device'ı güçlü authentication ile koru; (3) purchase sırasında device token/last digits'i doğrula; (4) destekleniyorsa gereksiz location/analytics'i kapat; (5) kayıp device/token'ları hemen disable et; (6) issuer ve wallet kayıtlarını incele.

**Detection:** token requestor/device cryptogram ve issuer mapping, wallet/account telemetry, merchant terminal ve physical evidence.

## Payment app, marketplace wallet and centralized intermediary

**Mechanics:** service account'ları tutar ve transferleri internal olarak veya bank/card rail'leri üzerinden yürütür; merchant alias görebilirken service iki tarafı da görür.

**Pros:** convenience, dispute/refund mekanizmaları; recipient bank/card ayrıntılarını görmeyebilir.

**Cons:** centralized identity/social/transaction/device graph; freezes ve legal process; karşı taraf profile'ı açığa çıkarabilir; data use payment ihtiyacını aşabilir.<sup>[[2]](#references)</sup>

**Procedure:** (1) identity, privacy, retention ve buyer-protection şartlarını oku; (2) optional profile/contact synchronization'ı azalt; (3) şartlar izin veriyorsa ayrı ve truthful account kullan; (4) MFA/alerts etkinleştir; (5) recipient ve memo/profile privacy'sini doğrula; (6) kayıtları export et ve kullanılmayan bağlantıları kapat.

**Detection:** provider account, device/IP, contact graph, funding/withdrawal, memo ve merchant records. Alias, counterparty'ye karşı pseudonymity'dir; platforma karşı anonymity değildir.

## Bank transfer, ACH, wire and instant-account payment

**Mechanics:** regulated institutions, identified account'lar arasında value taşır ve gerekli payment data'yı değiş tokuş eder.

**Pros:** hızlı, accountable, sınırlı durumlarda reversible, güçlü kayıtlar; virtual account number merchant disclosure'ını azaltabilir.

**Cons:** bank/processors iki tarafı bilir; statements ve references; anonymous değildir; cross-border ve Travel Rule/AML data.

**Procedure:** yalnızca accountability kabul edilebilir olduğunda kullan: beneficiary'yi bağımsız doğrula, optional memo data'yı azalt, mümkünse bank-provided virtual account/reference kullan, alerts etkinleştir, invoice'ı sakla ve uzlaştır.

**Detection:** deterministic bank/payment records, beneficiary/account ownership, device/session ve fraud controls. Bu anonymity technique değil, baseline'dır.

## Account and merchant compartmentation

**Mechanics:** ayrı lawful identities/accounts, email aliases, cards ve delivery contexts, ilgisiz merchant'ların activity'yi kolayca birleştirmesini önler; issuer/controller mapping'i tutar.

**Pros:** breach ve cross-merchant linkage'i azaltır; audit kolaydır; regulated payments ile uyumludur.

**Cons:** provider compartment'ları yine eşler; recovery phone/device/IP ve shipping yeniden bağlayabilir; policy birden fazla account'ı yasaklayabilir.

**Procedure:** (1) tek bir purpose tanımla; (2) yalnızca terms-compliant alias/subaccount oluştur; (3) merchant-specific token/card kullan; (4) cross-account contact/ad personalization'ı kapat; (5) encrypted controller ledger tut; (6) refund/retention ihtiyacı sona erince identifier'ları retire et.

**Detection:** provider recovery, device, funding ve IP'yi birleştirir; merchant delivery, browser ve account behavior'ı eşler. Defenders legitimate compartmentation ile synthetic identity fraud'u ayırmalıdır.

## Controlled red-team procurement

**Mechanics:** SOC satın alma işlemine karşı blind iken exercise controller legal entity, operator ve infrastructure mapping'i tutar.

**Pros:** gerçekçi detection exercise; kişisel exposure yok; hızlı deconfliction ve audit.

**Cons:** organization/provider'a karşı anonymous değildir; governance yükü; controller ledger kötü yönetilirse leak.

**Procedure:** (1) engagement-specific organization card/wallet/budget ayır; (2) purchaser/operator rollerini ayır; (3) asset, amount, service, purpose ve kill date kaydet; (4) attribution mapping'i sınırlı controller erişimiyle sakla; (5) false identity/mule/stolen funds kullanma; (6) kapanışta indicator ve refund'ları açıkla/uzlaştır.

**Detection:** controller provider invoice ve asset'i eşler; SOC cardholder data yerine domain, certificate, hosting ve traffic üzerinden bağımsız discovery'yi test eder.

## Bitcoin address hygiene and coin control

**Mechanics:** fresh receive address'ler, local labeling ve selective UTXO spending, public ledger'da address reuse ve yanlışlıkla compartment merge edilmesini azaltır.

**Pros:** yaygın destek; self-custodial; en basit public linkage'i önler.

**Cons:** tüm transaction/amount'lar public kalır; common-input/change/timing ve sonraki consolidation bağlantı kurar; acquisition/RPC/network kayıtları kalır.

**Procedure:** (1) maintained wallet kur ve doğrula; (2) seed backup al ve recovery test et; (3) her invoice için yeni address kullan; (4) source/purpose'u local label'la; (5) context'leri birleştirmemek için coin control kullan; (6) local node veya privacy-aware connection tercih et; (7) change/fee'leri önizle ve lawful accounting'i koru.<sup>[[3]](#references)</sup>

**Detection:** address graph, belirsizlik içeren common-input/change heuristics, exact amount/time, consolidation, service deposits, node/RPC broadcast timing ve off-chain records.

## Bitcoin Silent Payments

**Mechanics:** BIP 352, receiver'ın static code yayınlamasına ve sender'ların ECDH ile unique Taproot output türetmesine izin verir; dış gözlemciler output'ları doğrudan code'a bağlayamaz.<sup>[[4]](#references)</sup>

**Pros:** address reuse olmadan reusable public identifier; interactive address request veya notification output gerekmez; Taproot output'larına benzer.

**Cons:** receiver scanning maliyeti; wallet desteği değişir; amount/sender graph ve spending public kalır; index server scan'leri görebilir.

**Procedure:** (1) güncel BIP 352 wallet seç; (2) descriptor ve scanning recovery'yi backup/test et; (3) destekleniyorsa labeled code üret; (4) published code'u authenticate et; (5) sender input'ları inceleyip küçük test gönderir; (6) receiver tercihen kendi node'u üzerinden scan eder; (7) alınan UTXO'ları ayrı tut.

**Detection:** tasarım gereği yalnız output'tan güvenilir şekilde tanımlanamaz; analysts sender input, amount/time, later spending, wallet/network/index ve counterparty kayıtlarını kullanır.

## PayJoin

**Mechanics:** payer ve payee tek payment transaction'a input ekler; tüm input'ların tek owner'a ait olduğu varsayımını bozar.<sup>[[5]](#references)</sup>

**Pros:** daha iyi privacy sağlayan ordinary payment; common heuristic'i zayıflatarak genel graph'a fayda sağlar; equal-output crowd gerekmez.

**Cons:** interactive/support gereksinimi; receiver endpoint availability; amount ve final transaction public; implementation ve fallback metadata.

**Procedure:** (1) maintained wallet'ların aynı PayJoin version'ı desteklediğini doğrula; (2) invoice/endpoint'i authenticate et; (3) wallet'ın PayJoin-enabled payment URI'sinden başla; (4) final amount/fee'yi incele ve yalnızca beklenen input'ları sign et; (5) manual transaction surgery yapma; (6) broadcast ve receipt'i doğrula; (7) negotiation başarısızsa fallback'i kaydet.

**Detection:** blockchain analysts common-input clustering'i zorlamamalı; endpoint/provider negotiation loglayabilir; yalnız transaction shape yerine wallet/network ve later-spend kanıtı kullan.

## CoinJoin

**Mechanics:** birden çok participant, çok sayıda input/output içeren ve çoğunlukla equal denomination kullanan ortak transaction oluşturur; input-output correspondence belirsizleşir.

**Pros:** daha büyük on-chain ambiguity set; self-custodial designs; ölçülebilir round structure.

**Cons:** coordinator/peer/network metadata; fees/liquidity; tanımlanabilir transaction shape; toxic change ve later consolidation gains'i yok eder; legal/provider availability değişir.

**Procedure:** (1) güncel wallet/coordinator availability ve legality'yi doğrula; (2) official wallet kur ve backup al; (3) yalnız lawful UTXO kullan; (4) denomination, fee ve coordinator modelini anla; (5) change ve mixed output'ları label'layıp ayrı tut; (6) bunları asla birlikte consolidate etme; (7) network traffic'i resmi olarak desteklenen şekilde yönlendir ve accounting'i koru.

**Detection:** collaborative structure'ı suçu varsaymadan tanımla; possible mapping/anonymity set hesapla, ardından change/consolidation, service boundaries ve network/coordinator records'ı izle.

## Lightning Network

**Mechanics:** HTLC payments onion-routed channel'lar üzerinden geçer; payment detail'lerinin çoğu chain'de yayınlanmaz, ancak funding/closing ve public channel information yayınlanır.

**Pros:** hızlı, düşük fee; intermediary'ler normalde komşu hop'ları görür; rutin payment detail'leri off-chain kalır.

**Cons:** sender/receiver ve first/last hop daha fazlasını bilir; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallet'lar user'ları tanımlar.

**Procedure:** (1) self-custodial veya custodial seçimini bilinçli yap; (2) wallet/seed/channel recovery'yi doğrula; (3) exact payment için invoice kullan; (4) tradeoff'ları okuduktan sonra private channel/LSP feature'larını tercih et; (5) gerektiğinde supported Tor ile node IP'yi koru; (6) identifying invoice'ları tekrar kullanma; (7) channel ve payment accounting'i tut.<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs, channel graph/probes, payment failure/timing ve on-chain funding/closure; public transaction olmaması kayıt olmadığı anlamına gelmez.

## BOLT 12 offers and route blinding

**Mechanics:** reusable offer fresh invoice üretir ve payer'ın receiver clear node/path'ini öğrenmemesi için blinded path yayınlayabilir.

**Pros:** receiver privacy; static invoice olmadan reusable donation/payment endpoint; Lightning onion routing ile uyumlu.

**Cons:** wallet support değişir; endpoint, selected hop ve funding kalır; public contact veya network endpoint receiver'ı yeniden tanımlayabilir.

**Procedure:** (1) eşleşen BOLT 12 desteğini doğrula; (2) offer'ı authenticate et; (3) fresh invoice iste; (4) amount/issuer/recurrence'i incele; (5) wallet üzerinden öde; (6) receipt/refund davranışını doğrula; (7) node alias/contact'ı azalt ve accounting'i koru.<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP ve first/last-hop telemetry, offer distribution account, timing/value ve funding graph; route blinding payer visibility'yi kasıtlı olarak sınırlar.

## Monero

**Mechanics:** one-time stealth address'ler recipient linkage'i gizler, RingCT amount'ları gizler ve ring signature'lar sender ambiguity sağlar.

**Pros:** on-chain privacy default'tur; sender/receiver/amount confidentiality; gelişmiş dedicated wallet/node ecosystem.

**Cons:** acquisition/off-ramp ve endpoint/network/counterparty records; remote node queries/IP görür; exchange support/legal treatment değişir; küçük operational hatalar context'leri yine bağlar.

**Procedure:** (1) yasal edin ve basis/source'u sakla; (2) resmi maintained wallet kur/doğrula; (3) seed backup ve test yap; (4) local node veya belgelenmiş Tor/I2P remote-node path kullan; (5) her payer/invoice için yeni subaddress kullan; (6) context'leri local label'la; (7) transaction proof/view access'i yalnızca bilinçli biçimde paylaş.<sup>[[8]](#references)</sup>

**Detection:** exchange/merchant/device/network ve seized-wallet evidence'a odaklan; protocol kullanımı tek başına şüpheli değildir ve public chain kasıtlı olarak daha az bilgi açığa çıkarır.

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proof'lar shielded transfer'ları doğrular; sender, receiver ve amount encrypted kalır; transparent pool'lar ve pool transition'lar public'tir.

**Pros:** güçlü shielded on-chain confidentiality; viewing key scoped audit sağlayabilir; protocol-enforced validity.

**Cons:** wallet/exchange support ve gerçek pool seçimi değişir; transparent boundary timing/value correlation; network/RPC ve endpoint kalır.

**Procedure:** (1) shielded-by-default Orchard wallet seç; (2) verify/backup yap; (3) ZEC'i yasal edin; (4) supported Unified Address'e al ve pool'u doğrula; (5) shielded-to-shielded tercih et; (6) supported network privacy kullan; (7) audit öncesi küçük wallet'ta viewing-key disclosure'ı test et.<sup>[[9]](#references)</sup>

**Detection:** transparent boundary ve service records, wallet/network metadata ve yasal olarak sağlanan viewing key'ler; tüm Unified Address payment'larının shielded olduğunu varsayma.

## Mimblewimble and Litecoin MWEB

**Mechanics:** confidential transaction'lar amount ve Mimblewimble-style aggregation conventional address-rich history'yi gizler/azaltır; Litecoin transparent chain yanında optional extension block uygular.

**Pros:** private domain'de confidential amount ve gelişmiş fungibility; efficient pruning/aggregation.

**Cons:** opt-in boundary peg-in/out public ve correlate edilebilir; wallet/exchange support; interactive/address-model farklılıkları; network ve acquisition records.

**Procedure:** (1) açık MWEB desteği olan maintained wallet seç; (2) verify/backup yap ve küçük tutarla test et; (3) yasal edin; (4) MWEB'e peg et ve balance domain'i doğrula; (5) yalnız compatible receiver ile işlem yap; (6) distinctive immediate peg-out'tan kaçın; (7) private audit records tut.<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value, exchange/wallet/node data ve later transparent spends; internal confidential transfer detail'leri bilinçli olarak azaltılmıştır.

## Ethereum zero-knowledge privacy applications

**Mechanics:** circuit, membership, valid note ownership veya authorization gibi bir statement'ı secret'ı açığa çıkarmadan kanıtlar; verifier contract bunu kontrol eder. Deposit, withdrawal, public input, event ve gas yine bağlantı açığa çıkarabilir.

**Pros:** programmable selective disclosure; anonymous-set applications; tüm data'yı açmadan doğrulanabilir kurallar.

**Cons:** contract/circuit bug'ları; küçük anonymity set; public boundaries; RPC/IP/session/analytics/gas funding; application ve sanctions/legal risk.

**Procedure:** (1) proof'un tam olarak neyi gizlediğini tanımla; (2) yasal olduğu sürece audited maintained application kullan; (3) public input/event ve deposit/withdraw kurallarını incele; (4) action wallet ve gas sponsorship'ı protocol'un amaçladığı biçimde ayır; (5) privacy-aware RPC/network path kullan; (6) küçük value ile test et; (7) compliance records koru.<sup>[[11]](#references)</sup>

**Detection:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics ve eventual exchange/merchant boundary. ZK proof'un public ilan edilen alanları gizlediğini iddia etme.

## Stablecoins

**Mechanics:** token'lar public chain üzerinde transfer edilir; centralized issuer'lar freeze/blacklist yapabilir veya identified account'lara karşı redeem edebilir.

**Pros:** price stability, liquidity ve merchant support; hızlı settlement; kolay accounting.

**Cons:** transparent address/amount/contract graph; gas funding; issuer ve exchange identity/control; sanctions screening; genellikle zayıf anonymity.

**Procedure:** identified payment olarak ele al: compartmentation için fresh business address kullan, token contract/network'i doğrula, küçük transfer test et, wallet'ı koru, trusted RPC/local node kullan, basis/source'u sakla ve gerekli tarafları screen et.

**Detection:** complete token event graph, issuer freeze list/actions, exchange/RPC/device ve gas-funding relationships.

## Cashu Chaumian e-cash

**Mechanics:** mint, client tarafından üretilen bearer secret'ları blind-sign eder ve bunları mint'in Bitcoin/Lightning reserves'i destekler; issuance'ı sonraki redemption'a doğrudan bağlamadan double-spend'i önleyebilir.

**Pros:** accountless bearer token'lar; anında peer transfer; mint blinded withdrawal'ı spend'e doğrudan bağlayamaz; token'lar data/QR olarak taşınabilir.

**Cons:** mint custody/solvency/censorship; bearer data loss/theft; denomination/timing ve Lightning boundaries; network metadata; erken software ecosystem.<sup>[[12]](#references)</sup>

**Procedure:** (1) önce official test mint veya küçük disposable value kullan; (2) maintained wallet kur ve backup/restore kısıtlarını test et; (3) mint'i authenticate et ve custody/fees'i incele; (4) küçük amount mint et; (5) token'ı authenticated private channel/QR üzerinden gönder; (6) receiver token'ı final saymadan önce swap eder; (7) redeem ve reconcile et. Güvenilmeyen mint'te anlamlı value saklama.

**Detection:** mint network, issue/redeem/Lightning boundaries ve spent-token set'i görür; blinding direct token linkage'i kaldırır; endpoint/message ve distinctive amount/timing bağlantıyı geri kurabilir.

## Fedimint federated e-cash

**Mechanics:** guardian'ların threshold'u reserve tutar ve e-cash'i blind-sign eder; internal bearer transfer'lar guardian'lardan gizlidir, Lightning gateway'leri external payment'ları bağlar.

**Pros:** custody dağıtılır; private internal transfer; community governance; threshold altındayken tek guardian reserve'i kontrol etmez.

**Cons:** guardian quorum/custody/software risk; gateway invoice/timing görür; deposit/withdraw boundaries; client-state recovery karmaşıklığı.

**Procedure:** (1) federation invite/guardian/quorum/jurisdiction'ı doğrula; (2) maintained client kur ve recovery test et; (3) küçük lawful amount deposit et; (4) fresh internal payment request kullan; (5) gateway'i Lightning observer olarak kabul et; (6) redemption test et; (7) source/tax records'ı public payment data dışında tut.<sup>[[13]](#references)</sup>

**Detection:** federation aggregate issuance/redemption'ı görür, gateway external invoice'ları görür, Bitcoin/Lightning boundary'leri gösterir ve endpoint/communication evidence internal transfer'ları bağlayabilir.

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash, merchant'lar için payer'ı anonymous tutmayı; merchant ve income için accountability'yi amaçlar.

**Pros:** design gereği payer privacy; ordinary currency; merchant accountability/refunds; speculative token gerekmez.

**Cons:** sınırlı deployment; exchange/bank funding'ı görür; merchant order/delivery'yi görür; wallet bearer/recovery risk; regulated operators.

**Procedure:** (1) jurisdiction/currency için güncel exchange/merchant bul; (2) KYC/fees/privacy'yi oku; (3) official wallet kur; (4) supported bank/exchange'den yasal biçimde withdraw et; (5) merchant contract'ı incele; (6) pay et ve receipt/refund data'yı sakla; (7) gereksiz merchant session identifier'larını kullanma.<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal ve merchant deposit accountable boundaries'dir; merchant order/device/delivery ve timing, coin'ler blinded olsa bile correlate edilebilir.

## Cross-chain bridge, atomic swap and decentralized exchange

**Mechanics:** contract/service bir asset'i lock/burn eder ve diğerini release/mint eder veya counterparties atomically exchange yapar. Single-ledger view'ı böler, economic continuity'yi değil.

**Pros:** asset/network interoperability; tek centralized custodian'dan kaçınabilir; ordinary portfolio/liquidity kullanımı.

**Cons:** iki chain de public'tir; time/value/fees/liquidity ve contracts correlate olur; bridge/relayer/frontend/RPC records; smart-contract/counterparty ve regulatory risk.

**Procedure for lawful swaps:** (1) official contract/service ve legal availability'yi doğrula; (2) custody/audit/fees/slippage'i incele; (3) küçük test kullan; (4) iki transaction ID ve rate'i kaydet; (5) approvals'ı koru; (6) destination asset'i reconcile et ve gereksiz approval'ı revoke et. Source of funds'i disguise etmek için swap kullanma.

**Detection:** bridge deposit/withdraw events, unique amount minus fees, time order, liquidity, relayer/RPC/frontend ve later service deposits.

## Centralized mixer or tumbler

**Mechanics:** service deposit'leri pool'a alır ve daha sonra farklı unit'ler döndürerek direct input-output mapping'i gizlemeye çalışır.

**Pros:** teoride transaction ambiguity'yi artırabilir.

**Cons:** operator steal/log yapabilir; entry/exit timing/value analysis; sanctions/money-transmission ve criminal exposure; seizure mapping'leri açığa çıkarır; taint/rejection riski.

**Procedure:** operational mixing guide verilmez. Graph'ı güvenli biçimde yeniden üretmek için [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph)'yı genişlet: synthetic deposits, pooled outputs, fees ve delays oluştur; analysts'e eksik mapping ver; hangi heuristic'lerin çalıştığını ölç; sonra ground truth'u açıkla.

**Detection:** service wallet/contract identification, entry/exit candidate set'leri, amount/fee/timing, deposit address reuse, seized/provider logs ve downstream consolidation. Probabilistic attribution olarak etiketle.

## Peel chains, fan-out/fan-in and structuring

**Mechanics:** tekrar eden transaction'lar change'ten küçük payment'lar ayırır, value'yu birçok address'e böler, collector'larda yeniden birleştirir veya incelemeden kaçınmak için amount'ları böler.

**Pros:** naive analyst workload ve address count'u artırır.

**Cons:** tanınabilir value/cadence/transaction continuity; consolidation ve service endpoints; structuring kendi başına illegal olabilir; fees ve operational errors.

**Procedure:** yalnız synthetic CSV/testnet data kullan: büyük source, tekrarlanan payment/change edge'leri, parallel branches ve tek collector üret; benign exchange-like örnekler ekle; detection'ı ayarla ve false positive'leri belgele.

**Detection:** graph continuity, repeated change pattern, cadence, just-below-control amount'lar, common service endpoint ve off-chain records. Exchange hot wallet'ları benzer görünebilir; context zorunludur.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mechanics:** başka bir kişi/account/company funds'ı alır, dönüştürür veya harcar; controller ile transaction arasına legal ve operational layers eklenir.

**Pros to an adversary:** named account controller'ı hemen tanımlamaz; cash, crypto, goods ve jurisdiction'ları bağlayabilir.

**Cons:** identity fraud/money-laundering exposure; her participant communication, bank/company/tax/shipping records, fee, inconsistency ve witness ekler; facilitator reuse hubs oluşturur.

**Procedure:** gerçek people/account'larla emulate etme. Controller, recruiter, mule, OTC, shell merchant ve beneficiary içeren synthetic graph kur; device/IP/message/bank edge'leri ekle; investigators'ın account holder ile controller'ı ayırmasını ve evidence confidence kaydetmesini iste.

**Detection:** shared device/IP/recovery, unusual beneficiary/velocity, çok sayıda ilgisiz sender, immediate onward movement, company/director/invoice inconsistency, communications ve cash/commodity delivery.

## NFTs, gambling, merchant goods and refund loops

**Mechanics:** value self-priced asset, wagering balance, resalable goods veya refund'a dönüştürülerek farklı transaction narrative oluşturulur.

**Pros to an adversary:** asset formunu değiştirir ve marketplace/merchant intermediary ekler.

**Cons:** marketplace/account/device ve wash-trade graph; odds/play ve refund records; delivery/resale evidence; fees/losses; fraud/laundering liability.

**Procedure:** concealment workflow yoktur. Related-wallet self-trade, implausible pricing, minimal play, mismatched refund instrument ve common shipping içeren synthetic marketplace data kullan; detection'ı legitimate collector/customer'lara karşı doğrula.

**Detection:** circular/self-funded trades, common ownership/funding, price outlier'ları, immediate resale/refund, minimal economic activity, shared device/delivery ve proceeds reconvergence.

## Physical bearer wallet or offline token transfer

**Mechanics:** device, paper/QR, hardware bearer instrument veya e-cash token, handover sırasında payment broadcast etmek yerine secret control'ünü aktarır.

**Pros:** exchange sırasında live network event yok; offline kullanım; physical cash-like custody.

**Cons:** copy/theft/loss ve uncertain exclusivity; later redemption/broadcast link kurar; physical meeting/shipping; counterfeit/tamper riski.

**Procedure:** (1) yalnızca reviewed instrument/protocol kullan; (2) authenticity'yi private biçimde initialize/verify et; (3) yalnızca küçük lawful value yükle; (4) authorized ve belgelenmiş context'te transfer et; (5) receiver protocol gerektiriyorsa hemen verify veya sweep et; (6) sender'ın copy tutmadığını varsayma; (7) ownership/tax evidence'ı private kaydet.

**Detection:** purchase/funding ve eventual sweep/redemption, device serial/tamper evidence, delivery/meeting ve endpoint records.

## Merchant-scoped invoice or one-time payment request

**Mechanics:** merchant amount, expiry ve order reference içeren single-use request oluşturur. Payer bunu supported rail üzerinden settle eder; reusable credential doğrudan merchant'a açılmaz, ancak issuer veya payment processor yine iki tarafı tanımlayabilir.

**Pros:** credential reuse ve accidental cross-merchant identifier'larını sınırlar; exact amount/expiry hataları azaltır; ordinary accounting/refund ile uyumludur.

**Cons:** invoice, delivery, browser, processor ve issuer order'ı bağlar; unique amount/time correlation'ı güçlendirebilir; malicious payment link'ler yaygındır.

**Procedure:** (1) merchant'ı bağımsız authenticate et; (2) exact amount, asset/network ve expiry içeren fresh invoice iste; (3) destination ve refund kurallarını incele; (4) approved engagement compartment'tan öde; (5) merchant'ın aynı invoice'ı kabul ettiğini doğrula; (6) receipt ve transaction reference'ı sakla; (7) request'i reuse etmek yerine expire et.

**Detection:** merchant ve processor invoice, session ve settlement'ı eşler; unique amount/timing ve delivery payer'ı tanımlar. **Captured wallet/device:** invoice history counterparties ve purpose'u açığa çıkarır; gereksiz memo data'yı azalt, device'ı encrypt et ve authoritative accounting'i controlled finance system'da tut.

## Prepaid service credit and capability token

**Mechanics:** service conventional payment'ı bounded internal credit veya bearer capability'ye dönüştürür. Sonraki API/resource kullanımı her request'te original card sunmadan yapılabilir, ancak service issuance ile redemption'ı çoğunlukla eşleyebilir.

**Pros:** spend ve compromise loss'u sınırlar; day-to-day worker'ları funding credential'dan ayırır; per-project budget ve revocation destekler.

**Cons:** genellikle pseudonymous, anonymous değil; service database, redemption IP ve unique usage pattern activity'yi bağlar; bearer token çalınabilir; refund original payer'ı gerektirebilir.

**Procedure:** (1) credit'i organization account üzerinden satın al; (2) tek project ve budget oluştur; (3) service, amount ve expiry kısıtlı narrow token ver; (4) yalnız approved secret manager veya workload identity path'te sakla; (5) scope dışında ve expiry sonrasında rejection'ı test et; (6) consumption'ı izle; (7) unused value'yu revoke ve reconcile et.

**Detection:** provider funding account, project, token issuance ve usage'ı birleştirir; defenders geographic/process changes ve anomalous consumption için alert kurar. **Captured node:** kalan capability'nin harcanabileceğini varsay; short expiry, low balance, audience binding ve immediate server-side revocation kullan.

## Privacy Pass or blinded authorization token

**Mechanics:** issuer, origin'in redemption'ı issuance'a bağlamadan doğrulayabildiği privacy-preserving authorization token üretir. Paid entitlement veya rate-limited access temsil edebilir, ancak general currency değildir. Architecture client, attester, issuer ve origin rollerini ayırır; IP/timing veya collusion unlinkability'yi bozabilir.<sup>[[18]](#references)</sup>

**Pros:** supported service'lerde unlinkable redemption; origin'de reusable account cookie yok; cached token'lar issuance ve use'ı zaman bakımından ayırabilir.

**Cons:** application-specific; issuer/attester trust ve anonymity-set partitioning; IP ve browser metadata kalır; token theft veya distinctive issuance timing kullanım ile correlate olabilir.

**Procedure:** (1) relevant Privacy Pass token type ile uyumlu implementation kullan; (2) token'ın hangi entitlement'ı kanıtladığını tanımla; (3) threat model gerektiriyorsa issuer ve origin administration'ı ayır; (4) challenge metadata'yı azalt; (5) birkaç test token issue et ve owned origin'lerde her birini bir kez redeem et; (6) forbidden stable identifier'lar için log'ları karşılaştır; (7) replay, expiry ve revocation/abuse control'lerini test et.

**Detection:** origin redemption IP/time ve token validity'yi görür; issuer/attester issuance context'i görür; analysts cryptographic break varsaymadan timing ve metadata partition'larını test eder. **Captured client:** unspent bearer token kullanılabilir; value, lifetime ve audience'ı sınırla ve funding credential'ı bunlarla birlikte cache etme.

## Delegated organization procurement or fiscal sponsor

**Mechanics:** authorized procurement team, reseller veya fiscal sponsor contract yapar ve ödeme yapar; operational team bounded service alır. Bu truthful records ile role separation'dır; nominee veya false identity değildir.

**Pros:** vendor her operator'ın identity veya personal payment detail'ini almaz; central compliance, tax ve refund handling; açık budget ve offboarding.

**Cons:** sponsor beneficiary ve purpose'u bilir; contracts, approvals, delivery ve accounts kalır; delay/fees; aynı kişi her katmanı yönetirse separation zayıflar.

**Procedure:** (1) business purpose, beneficiary ve approving authority'yi belgele; (2) organization-approved intermediary seç; (3) truthful details ile contract yap; (4) personal billing credential içermeyen project-scoped subaccount provision et; (5) finance administrator ve operator'ları ayır; (6) invoice ve access'i reconcile et; (7) closeout'ta service ve delegated access'i terminate et.

**Detection:** procurement, identity-provider, vendor ve delivery records chain'i birleştirir. **Captured operational device:** service project'i göstermeli, finance credential'larını göstermemelidir; invoice ve payer identity'lerini field node'larda değil finance system'da tut.

## Escrow or conditional settlement

**Mechanics:** trusted escrow agent veya smart contract, documented conditions karşılanana kadar value tutar. Payer/payee arasındaki direct disclosure'ı azaltabilir; escrow ve underlying rails ilişkiyi tutar.

**Pros:** dispute ve delivery protection; payer/merchant birbirine daha az reusable credential açar; auditable release conditions.

**Cons:** escrow custody/contract risk, fees ve identity obligations; on-chain contracts public; order, shipping ve dispute data kalır; intermediary'ye karşı anonymous değildir.

**Procedure:** (1) legal entity, custody, fees, dispute forum ve supported asset'leri doğrula; (2) exact written milestone ve refund path oluştur; (3) approved organization account'tan fund et; (4) receipt ve release authorization'ı bağımsız doğrula; (5) yalnız evidence sonrasında release et; (6) complete audit record'ı sakla; (7) unused permission veya contract approval'ları kapat.

**Detection:** escrow account/contract events, funding/release time, beneficiary ve dispute records transaction'ı açığa çıkarır. **Captured device:** session token veya contract approval release'e izin verebilir; ayrı approver/MFA iste ve loss durumunda active session'ları revoke et.

## Batched or pooled organization settlement

**Mechanics:** birçok approved obligation aggregate edilir ve daha az bank/blockchain transaction'ında settle edilir; private internal ledger her share'i atar. Batching public per-purchase detail'i azaltabilir, ancak coordinator complete attribution tutar.

**Pros:** düşük fee; daha az public graph edge; amount'lar aggregate edildiğinde public observer'dan individual line item'ları gizler; kolay internal accounting.

**Cons:** coordinator complete observer ve high-value target'tır; distinctive total/timing correlate olabilir; custody/reconciliation risk; kötüye kullanılırsa structuring'e benzeyebilir.

**Procedure:** (1) participants ve lawful obligations'ı accounting system'da tanımla; (2) controls'tan kaçınma amacı taşıyan thresholds yerine regular, business-justified batch window belirle; (3) aggregate için dual approval iste; (4) authenticated recipient'lara settle et; (5) her internal line'ı batch'e reconcile et; (6) refund'ları linked correction olarak işle; (7) ledger access'i koru ve policy'ye göre sakla.

**Detection:** coordinator ledger, approval ve beneficiary records ground truth sağlar; public analysts input/output/value/time clustering'i dikkatle kullanır. **Captured payer device:** yalnız requisition içermeli, pool signing key veya participant ledger içermemelidir.

## Account-abstraction paymaster or sponsored gas

**Mechanics:** relayer/bundler smart-account operation gönderir ve paymaster transaction fee'lerini öder; user wallet'tan direct native-gas funding edge'i kaldırır. Bir graph property'sini iyileştirir, ancak operation, contract ve service telemetry public/observable kalır.<sup>[[19]](#references)</sup>

**Pros:** common gas-funding link'i kaldırır; scoped sponsorship ve rate limit sağlar; legitimate privacy application'ları için onboarding'i iyileştirir.

**Cons:** paymaster/bundler/RPC/front end request'leri correlate edebilir; contract event ve public input kalır; sponsorship policy cohort'u fingerprint eder; malicious contract/approval asset çalabilir.

**Procedure:** (1) correct network'te audited maintained smart account ve paymaster kullan; (2) public olan field'ları ve sponsor log'larını incele; (3) sponsorship'ı contract, function, amount, nonce ve expiry ile sınırla; (4) low value ile test et; (5) application's intended privacy-aware path üzerinden submit et; (6) operation ve fee payer'ı chain'de doğrula; (7) allowance/session key'leri revoke et ve compliance records tut.

**Detection:** UserOperation, EntryPoint, paymaster, bundler/RPC ve application logs'u birleştir; identical sponsorship policy'yi dikkatle cluster et. **Captured wallet:** session key ve pending approval gas olmadan da kullanılabilir; dar scope ver ve account recovery policy üzerinden revoke et.

## Threshold or multisignature payment authorization

**Mechanics:** spending bağımsız signer'ların threshold'unu gerektirir. Transaction'ı gizlemez; payment authority'yi captured laptop, field node veya tek operator'dan ayırır.

**Pros:** güçlü compromise ve insider resistance; accountable approval; tek field device complete signing authority tutmaz; recovery desteklenir.

**Cons:** coordination ve availability; signer/device/account metadata participant'ları correlate edebilir; kötü backup loss'a yol açar; public multisig pattern'leri tanınabilir.

**Procedure:** (1) funding öncesi signer, threshold, limit ve recovery'yi tanımla; (2) ayrı supported hardware/account'larda initialize et; (3) address ve backup'ları bağımsız doğrula; (4) field workload'lara yalnız unsigned requisition capability ver; (5) recipient, amount ve purpose için out-of-band review iste; (6) küçük value ile recovery ve one-signer loss test et; (7) compromise sonrası signer rotate et.

**Detection:** approval system, signer device ve public script/contract evidence sağlar; defenders policy veya signer-set değişikliklerinde alert kurar. **Captured node:** en fazla tek low-authority session key veya unsigned request açığa çıkarmalı; quorum material'ı birlikte cache etme.

## Closed-loop community or event currency

**Mechanics:** cooperative, conference veya private test environment, yalnız enrolled participants arasında redeem edilebilen credit issue eder. Internal transfer global payment network'lere daha az bilgi açabilir; issuer/redemption operator kontrolündedir.

**Pros:** bounded economic domain; offline veya privacy-preserving payment UX test edilebilir; external card exposure sınırlanır; açık experimental controls.

**Cons:** küçük anonymity set; operator ve merchant activity'yi görür; acceptance/redemption sınırlı; local value için bile licensing, consumer-protection ve tax kuralları geçerli olabilir.

**Procedure:** (1) legal/compliance review al ve issuer terms yayınla; (2) consenting test participant'ları enroll et; (3) issuance'ı sınırla ve cash-like misuse'ı yasakla; (4) fresh payment request kullan ve public participant identifier'larını azalt; (5) aggregate reserves ve private individual receipts kaydet; (6) loss/refund/redemption test et; (7) ledger'ı kapat ve residual value'yu vaat edildiği şekilde iade et.

**Detection:** issuer ledger, enrollment, merchant ve redemption records flow'ları yeniden kurar; unusual circular transfer veya rapid cash-out inceleme gerektirir. **Captured wallet:** local balance ve counterparties açığa çıkabilir; value'yu sınırla, state'i encrypt et ve issuer-side freeze/reissue'ı auditable record ile destekle.

## Bitcoin reusable payment codes and private payment instructions

**Mechanics:** BIP 47 reusable public identifier ve ECDH-derived one-time deposit address kullanır; BIP 351 daha yeni private-payment instruction tasarımını belirtir. Public address reuse'ı azaltır, recipient'ın stable payment instruction yayınlamasına izin verir. Notification, wallet support, funding ve sonraki coin selection privacy'yi etkiler.<sup>[[20]](#references)</sup>

**Pros:** tek public instruction distinct address'ler üretebilir; recipient her invoice address'ini yayınlamak zorunda değildir; compatible wallet'lar derived payment'ları izleyebilir; tekrarlanan lawful donor/customer için yararlı.

**Cons:** wallet interoperability değişir; notification transaction veya published payment code relationship context'i bağlar; sender, recipient ve public graph transaction'ları görür; dikkatsiz consolidation/change handling faydayı yok eder.

**Procedure:** (1) maintained wallet'ların exact specification/version'ı desteklediğini doğrula; (2) low-value wallet'ta backup ve recovery test et; (3) recipient payment code'u out-of-band authenticate et; (4) küçük lawful test gönder; (5) fresh derived address kullanıldığını doğrula; (6) relationship'i local label'la ve coin control uygula; (7) kullanmadan önce recovery/refund behavior test et.

**Detection:** analysts notification pattern, funding/change, later consolidation ve service boundaries'i inceler; public-code publication deposit address'leri farklı olsa da recipient context'ini tanımlar. **Capture-resilient OPSEC:** spend key'leri field device'lardan uzak tut ve en fazla watch-only relationship view aç. **Monitoring:** unexpected notification transaction, reused derived address, wallet gap-limit/recovery error ve unplanned consolidation için alert kur.

## EVM stealth addresses (ERC-5564)

**Mechanics:** sender, recipient stealth meta-address'inden one-time stealth account türetir ve ephemeral public key/view tag içeren announcement yayınlar. Recipient viewing key ile announcement'ları tarar ve karşılık gelen spend key'i türetir. Recipient linkage iyileşir; ancak sender, amount/token, gas, announcement ve sonraki spending görünür kalır.<sup>[[21]](#references)</sup>

**Pros:** non-interactive fresh receiver address; reusable meta-address; viewing ve spending rollerinin ayrılması; supported EVM asset/application'larında çalışma.

**Cons:** announcement scanning ve spam; new address için gas funding yeniden link kurabilir; sender recipient'ı bilir; public token/amount ve eventual consolidation kalır; implementation/wallet support değişir.

**Procedure:** (1) önce test network'te audited maintained implementation kullan; (2) ayrı viewing/spending material üret ve backup al; (3) meta-address'i authenticate et; (4) low-value test ve announcement gönder; (5) stealth account'ı scan edip türet; (6) personal funding edge olmadan supported gas sponsorship'ı test et; (7) public field'ları kaydet ve lawful accounting'i koru.

**Detection:** announcement caller, token/amount, timing, gas sponsor, spending ve consolidation'ı izle; view key spend vermeden receipt'i kanıtlayabilir. **Capture-resilient OPSEC:** networked scanner supported olduğunda yalnız viewing role'e sahip olmalı; spend/recovery key'leri başka yerde tut. **Monitoring:** malformed/spam announcement, view-key access, unexpected spend derivation ve approval olmadan taşınan stealth output'lar için alert kur.

## Liquid Confidential Transactions

**Mechanics:** Liquid, commitments ve proofs kullanarak output amount ve asset type'larını default olarak blind eder; transaction graph, input/output count, fee ve block time görünür kalır. Peg-in/peg-out ve service boundaries linkable kalır; users blinding data'yı selective disclose edebilir.<sup>[[22]](#references)</sup>

**Pros:** default confidential amount ve asset type; hızlı sidechain settlement; blinding key/descriptor ile selective audit; commercially sensitive value'ları public observer'dan gizler.

**Cons:** graph structure ve timing kalır; federation/bridge ve exchange trust; peg boundaries ve unconfidential output; wallet/node/network records; receiver ve sender transaction'larını bilir.

**Procedure:** (1) maintained Liquid wallet seç ve backup modelini doğrula; (2) testnet veya küçük lawful amount kullan; (3) confidential address'e al ve wallet'ın output'u blinded işaretlediğini doğrula; (4) test confidential transaction gönder; (5) explorer'da hangi field'ların public kaldığını incele; (6) audit için gereken scoped blinding proof'u export et; (7) peg/exchange boundaries'i belgele ve funds'ı reconcile et.

**Detection:** visible graph/fee/time, peg ve exchange records, network metadata ve later unblinding evidence'ı analiz et; hidden amount veya asset hakkında çıkarım yapma. **Capture-resilient OPSEC:** spend seed, blinding/view data ve watch-only operations'ı ayır. **Monitoring:** accidental unconfidential address, unknown peg request, descriptor change ve unapproved unblinding-key export için alert kur.

## General payment or state channel

**Mechanics:** participants funds lock eder, signed off-chain state update'ler değiş tokuş eder ve chain'e yalnız opening, closing veya disputed state yayınlar. Intermediate payment'lar global broadcast edilmez; peers ve routing/intermediary services kendi kısımlarını görür; endpoints latest enforceable state'i tutmalıdır.<sup>[[23]](#references)</sup>

**Pros:** çok sayıda hızlı, low-fee private-to-public-ledger interaction; daha az global transaction detail; bounded channel balance; metered service ve repeated counterparty için kullanışlı.

**Cons:** channel peers birbirini bilir ve update'leri saklayabilir; opening/closing/value/timing correlate olur; challenge window sırasında online monitoring gerekebilir; implementation/liquidity risk; tek başına büyük anonymity set değildir.

**Procedure:** (1) maintained audited implementation seç ve dispute window'u anla; (2) owned parties arasında low-value test channel aç; (3) unique nonce'larla signed state update değiş tokuş et; (4) latest enforceable state'i backup et; (5) cooperative close yap; (6) testnet'te stale-state rejection rehearse et; (7) accounting ve channel-peer records'ı koru.

**Detection:** public chain lifecycle/disputes'i açığa çıkarır; peers, watch service ve application transport off-chain timing ve parties'i açığa çıkarır. **Capture-resilient OPSEC:** hot balance'ı sınırla ve latest signed state'i field node'lardan ayrı encrypted recoverable store'da tut. **Monitoring:** stale-state publication, missed backup, peer-key change ve approaching challenge deadline'ı sürekli izle.

## Mobile carrier billing

**Mechanics:** online service purchase'ı mobile subscription veya prepaid balance'a carrier billing system üzerinden yükler. Merchant card/bank detail yerine carrier authorization alabilir; carrier subscriber/line, device/network context, merchant, amount ve zamanı bilir.<sup>[[24]](#references)</sup>

**Pros:** merchant'ta card number yok; geniş phone availability; low-value digital goods; carrier charge'ı cap/reverse edebilir.

**Cons:** SIM/account ve çoğu zaman device ile güçlü biçimde tanımlıdır; küçük limit ve yüksek fee; merchant category kısıtları; account takeover/SIM-swap riski; carrier ve aggregator complete trail oluşturur.

**Procedure:** (1) organization carrier account ile availability, limit, fee ve refund terms'i doğrula; (2) gerekçeliyse yalnız dedicated organization line'da etkinleştir; (3) en düşük useful spend cap'i ayarla; (4) benign test item satın al; (5) merchant ve carrier receipt'lerini doğrula; (6) recurring authorization'ı kapat; (7) reconcile et ve assessment sonrası feature'ı kapat.

**Detection:** carrier, aggregator ve merchant records line, subscriber, IP/device ve charge'ı birleştirir; enterprise telecom invoice'ları açığa çıkarır. **Capture-resilient OPSEC:** personal number kullanma ve carrier-account MFA'yı field device dışında tut. **Monitoring:** instant charge/SIM-change alerts etkinleştir; unexpected premium-service enrollment, forwarding veya account recovery'de dur.

## Open-banking payment initiation

**Mechanics:** explicit user consent ile regulated PISP, account-servicing bank'ten transfer başlatmasını ister. Merchant card credential almayabilir; PISP ve banks regulated payer, payee, consent, device ve transaction records'ı tutar.<sup>[[25]](#references)</sup>

**Pros:** checkout'ta reusable card number yok; güçlü bank authentication; exact account-to-account settlement; consent/status API'leri; açık reconciliation.

**Cons:** banks/PISP'ye karşı anonymous değildir; payee çoğu zaman legal account details veya reference görür; phishing/redirect riski; jurisdiction/refund protections değişir; consent metadata ek observer oluşturur.

**Procedure:** (1) PISP'in güncel regulated olduğunu ve merchant callback domain'inin authentic olduğunu doğrula; (2) merchant request'ten başla; (3) bank'te payee, amount, reference ve requested consent'i incele; (4) yalnız tek payment'ı authorize et; (5) final status'u bağımsız doğrula; (6) residual consent varsa revoke et; (7) receipt'i sakla ve reconcile et.

**Detection:** bank/PISP/merchant logs ve transfer reference'ları güçlü attribution sağlar. **Capture-resilient OPSEC:** banking authentication ve recovery'yi operational/field device'lardan uzak tut; device yalnız paid-service entitlement taşımalı. **Monitoring:** bank transaction/consent alert'leri kullan; new PISP grant, changed payee veya expected session dışındaki status callback'lerini incele.

## Platform wallet, app-store balance or in-app credit

**Mechanics:** platform user'ı charge eder veya account credit redeem eder, ardından application'a signed receipt/entitlement verir. App developer original funding instrument'ı görmeyebilir; platform account, device, funding, product ve redemption'ı eşler.<sup>[[26]](#references)</sup>

**Pros:** merchant/developer primary PAN almaz; fraud/refund ve family/business controls; küçük prepaid balance exposure'ı sınırlar; signed receipt entitlement verification'ı kolaylaştırır.

**Cons:** platform account güçlü identity/behavior hub'dır; device ve storefront geography; gift-balance purchase/redemption trail; limited cash-out; fraud controls funds'ı freeze edebilir; cross-platform money değildir.

**Procedure:** (1) policy izin veriyorsa organization-managed platform account kullan; (2) funding, region, refund ve transferable-value kurallarını incele; (3) yalnız approved budget ekle; (4) official store'dan benign product satın al; (5) application'ın yalnız beklenen receipt field'larını aldığını doğrula; (6) recurring purchase'ı kapat; (7) reconcile et ve account'ı operational hardware'dan kaldır.

**Detection:** platform receipt/server notification, account/device login ve funding records purchase'ı yeniden kurar. **Capture-resilient OPSEC:** field node'u personal store account'a sign-in ettirme; mümkünse yalnız scoped app entitlement sağla. **Monitoring:** new-device/purchase alerts etkinleştir; receipt replay, family/account change veya unexpected restore event'lerini incele.

## Mutual credit, clearing or periodic net settlement

**Mechanics:** participants obligation'ları private ledger'a kaydeder ve periyodik olarak yalnız net position'larını settle eder. Individual service event'leri ayrı public payment üretmeyebilir; ledger operator ve counterparties ayrıntılı attribution tutar.

**Pros:** daha az external transaction ve fee; public observer yalnız net settlement görür; repeated organization'lar için uygundur; explicit credit limits exposure'ı sınırlar.

**Cons:** centralized ledger complete evidence ve fraud target'tır; counterparty/default risk; legal/accounting/tax duties; küçük membership set; unusual net transfer ilişkileri açığa çıkarabilir.

**Procedure:** (1) yalnız identified consenting organizations ve legal/accounting approval ile kullan; (2) unit, credit limit, settlement interval ve dispute rules tanımla; (3) every obligation'ı immutable approval ile kaydet; (4) ayrı finance roles net position'ları hesaplayıp onaylasın; (5) ordinary lawful rail ile settle et; (6) individual lines'ı settlement'a reconcile et; (7) access'i kapat ve policy'ye göre kayıtları sakla.

**Detection:** ledger, invoices, approvals ve final bank/chain settlement ground truth sağlar; analysts yalnız net transfer'den missing gross activity çıkarımı yapmamalıdır. **Capture-resilient OPSEC:** operational devices bounded requisition gönderebilir, ancak balance düzenleyemez veya settlement authorize edemez. **Monitoring:** credit-limit breach, backdated entry, administrator change, reconciliation mismatch ve new beneficiary settlement için alert kur.

## Capture/compromise exposure matrix

Bu bölüm her aileye seizure/loss test'i uygular. Amaç transaction'ları silmek veya investigation'ı engellemek değil; spend authority ve ilgisiz identity disclosure'ı sınırlarken lawful accounting'i korumaktır.

| Technique family | A captured wallet/device/account can reveal | Minimum authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipt, serial, note, remaining bearer value ve physical contact'lar | yalnız approved amount taşı; private accounting'i ayır; loss'u hemen bildir; false record tutma |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption ve account/session token'ları | düşük balance; tek purpose; truthful registration; mümkünse issuer freeze/revocation |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transaction, recovery ve merchant history | device lock; transaction alert; merchant scope; remote issuer suspension; shared recovery account kullanma |
| Bank compartment, delegated procurement, red-team procurement | organization, approver, vendor, invoice ve project | role separation; least-privilege subaccount; finance credential'ları operational/field node'larda tutma |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator veya dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/key, label, address, transaction graph ve network config | hardware/offline signing; encrypted wallet; passphrase limit; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channel, invoice, peer/LSP ve payment database | minimal hot balance; encrypted backup; separate node identity; documented close/recovery |
| Monero, Zcash, MWEB, ZK applications | spend/view key, local wallet history, RPC ve boundary transaction | separate spend/view role; available hardware support; field node'da exchange session bulundurmama |
| Stablecoins, swaps, bridges and DEX | transparent graph, approval, RPC/frontend state ve destination asset | allowance revoke; verified contract; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer token, mint/federation/exchange, issuance/redemption cache | small balance; protocol destekliyorsa encrypted backup; redeem/reissue; funding credential'ı colocate etmeme |
| Paymaster, multisig/threshold | session key, one signer, pending operation ve sponsor policy | narrow session key; independent quorum; signer rotation; field device threshold'a erişemez |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communication, graph ve participant records | operational use yok; yalnız synthetic/testnet evidence ile emulate et |
| Community/event currency | enrollment, local balance, counterparties ve redemption | capped value; issuer freeze/reissue; consent ve private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend key, relationship metadata, announcement ve derived output | watch/view-only network role; offline/hardware spend role; personal funding session yok |
| Liquid confidential/state channels | seed, blinding data/latest state, peer, boundary ve dispute | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device ve funding source | organization account; external MFA; low limit; field hardware'da personal account yok |
| Mutual-credit clearing | member, obligation, limit, approval ve settlement ledger | yalnız operational requisition; separate immutable ledger ve dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial, compliance review veya wallet'ın offline olması investigation olduğunu kanıtlamaz. Yalnızca organization'ın gözlemleme yetkisi bulunan account, ledger ve infrastructure'ı izle; provider veya counterparty'leri investigators ile iş birliği yapıp yapmadıklarını anlamak için probe etme.

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund veya loss report | missing instrument, approved order dışı redemption, altered receipt veya custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alert, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap veya recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice ve consumption | cross-project token, unknown admin, limit breach, invoice mismatch veya unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation ve beneficiary change | altered amount/payee, backdated ledger, unilateral release veya unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transaction, notification/scan state, address reuse, UTXO label ve consolidation | unknown spend, reused recipient output, wallet gap/recovery failure veya unapproved merge |
| PayJoin/CoinJoin | proposal input/output/fee, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure veya coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP ve chain dispute | unknown invoice payment, peer-key change, stale close veya approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch event, pool/domain/address type, descriptor ve boundary transaction | unapproved spend, transparent/unconfidential downgrade, key export veya unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key ve issuer action | wrong contract/public field, unknown approval/spend, paymaster change veya issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway ve bearer balance | unknown redemption, mint key/terms change, restore failure veya balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmation, rate ve destination | contract/route mismatch, unlimited approval, missing destination veya bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum ve recovery audit | unknown proposal/signer, threshold reduction, recovery activation veya policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | yalnız synthetic lab ground truth ve detection output | gerçek account, person veya value emulation'a girerse hemen dur |

## Selection and verification workflow

1. Hangi tarafın hangi alanı öğrenmemesi gerektiğini belirt.
2. Issuer/mint/custodian, public ledger, network/RPC, merchant ve physical observer'ları tanımla.
3. Güncel support, legality, limits, custody, recovery ve refund behavior'ı doğrula.
4. Küçük ve lawful bir end-to-end test kullan.
5. Merchant receipt, provider statement, public chain ve wallet/node log'larını incele.
6. Backup/recovery ve deliberate audit disclosure'ı test et.
7. Gerekli source, ownership, tax, sanctions ve engagement kayıtlarını doğru fakat access-controlled tut.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Büyük ödeme platformlarının data collection uygulamalarına ilişkin gözlemler](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Privacy'nizi koruyun](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Basit bir Payjoin önerisi](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technical specifications and network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Zero-knowledge proof'larla privacy application oluşturma](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol ve privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — Nasıl çalışır](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Virtual currency administrators, exchangers ve users](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information ve crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
