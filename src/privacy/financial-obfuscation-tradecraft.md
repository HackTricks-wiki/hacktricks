# Finansal Gizleme Taktikleri

Ödeme gizliliği, ödeme markası değil, ilişkilendirme problemidir. Bir operasyon; değer edinildiğinde, taşındığında, dönüştürüldüğünde, harcandığında ve teslim edildiğinde kanıt bırakır. Bir public-chain adresi pseudonymous olabilir; ancak bir exchange, kart kuruluşu, merchant, mobil cihaz veya kargo kamerası arkasındaki kişiyi tespit edebilir.

Bu sayfa, savunucuların bunları tanıyabilmesi için cybercrime ve devlet bağlantılı operasyonlarda kullanılan finansal gizleme modellerini açıklar. Bir laundering, yaptırımlardan kaçınma, sahte kimlik veya KYC-bypass prosedürü sunmaz.

## Uçtan uca değer grafiği
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Bir actor, herhangi bir gözlemcinin her iki ucu da görmesini engellemeye çalışır. Investigators ise tersini yapar: her sınırda kayıtları korur, zamanı/değeri/ücretleri normalize eder ve ayrı personaların aynı facilitator, cihaz, hesap, merchant veya destination'ı yeniden kullandığı **reconvergence point**'i belirler.

## Instruments ve bunların gerçek gözlemcileri

| Instrument | Merchant/public'dan gizli | Hâlâ görünür olduğu taraflar |
|---|---|---|
| Issuer virtual card/token | underlying card number | issuer, network/token provider, wallet, merchant account ve delivery systems |
| Prepaid/gift value | ordinary purchase sırasında bazen legal name | retailer/payment rail, activation/redemption service, cameras, device ve delivery |
| Cash | public ledger ve remote issuer | counterparties, cameras, uygulanabildiği yerlerde withdrawal/serial controls, physical search |
| Bitcoin/new address | doğrudan legal name | her blockchain observer; wallet/network peers; acquisition/off-ramp services |
| CoinJoin/PayJoin | basit common-input/payment heuristics | public transaction, coordinator/peer/network metadata ve sonraki spending behavior |
| Privacy coin | protokole bağlı olarak public sender/receiver/amount | acquisition/off-ramp, wallet endpoint, network observer ve counterparty |
| Centralized mixer | doğrudan deposit-to-withdraw link | mixer operator/logs, blockchain entry/exit sets ve counterparties |
| Cross-chain bridge/swap | tek bir chain üzerindeki continuity | her iki chain, bridge/swap service, timing/value ve liquidity constraints |
| OTC/P2P broker | bazı durumlarda direct exchange account | broker, communications, bank/cash movement, counterparties ve devices |

## Cards, prepaid value, nominees ve mules

### Virtual ve masked cards

Bir issuer, merchant-locked veya disposable card number oluşturabilir. Bu, merchant exposure'ını ve merchant'lar arası number reuse'u azaltır. Issuer yine de bunu customer, funding account, device, IP ve transaction ile eşleştirir. Billing descriptors, merchant account, shipping address ve browser data link edilebilir olmaya devam eder.

“No-name” card marketing, anonymous settlement anlamına gelmez. Regulated issuer'lar ve distributor'lar identity checks gerçekleştirebilir, kayıtları saklayabilir, geography/amount limits uygulayabilir ve legal process'e yanıt verebilir. Stolen identity kullanılarak elde edilen bir card, identity theft oluşturur; issuer/device/merchant telemetry'sini ortadan kaldırmaz.

### Prepaid ve gift value

Prepaid cards ve gift codes, sonraki redemption'ı original payment instrument'tan ayırır; ancak purchase, activation, balance-query ve redemption event'lerine sahip numaralı bir object oluşturur. Önem taşıyan pattern'ler arasında bulk purchases, controls'un hemen altında tekrarlanan denomination'lar, uzaktan yapılan hızlı redemption, tek bir device'ın birçok balance'ı kontrol etmesi veya birçok card'ın tek bir merchant/account üzerinde birleşmesi bulunur.

### Nominees, money mules ve merchant fronts

Bir nominee veya mule, operator ile service arasında duran bir account ve legal identity sağlar. Network'ler recruiter'ları, account holder'ları, payment processor'ları, shell merchant'ları ve cash-out broker'larını katmanlandırabilir. Bu mesafe yaratır; ancak her participant communications, fees, behavioral inconsistency ve cooperating witness olasılığı ekler. Front company'ler incorporation, tax, banking, director, invoice, hosting ve shipment records ekler.

Defenders; shared devices/IPs, beneficiary reuse, geolocation contradictions, account history ile tutarsız velocity, circular transfers, birbiriyle ilgisiz birden çok sender'ın tek noktada birleşmesini ve hemen sonrasında gerçekleşen onward movement'ı araştırmalıdır. Named account holder'ın controlling actor olduğunu varsaymayın; role determination gerektiren bir node olarak ele alın.

## Public-chain transaction-obfuscation patterns

### Address rotation ve coin control

Her receipt için yeni bir address oluşturmak, basit address reuse'u engeller; ancak transactions yine de common inputs, change detection, exact value/time ve sonraki consolidation yoluyla aynı ownership altında birleştirilebilir. **Coin control**, bir wallet'ın hangi output'ları spend edeceğini seçmesine ve compartment'ları birleştirmekten kaçınmasına olanak tanır. Hygiene'ı iyileştirir; zaten public olan bir link'i ortadan kaldıramaz.

### Peel chains

Bir peel chain, büyük bir balance'ı tekrar tekrar spend ederek daha küçük bir amount'ı dışarı gönderir ve kalan miktarı yeni bir address'e geri gönderir:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Adres her adımda değişir, ancak değer sürekliliği, ritim ve işlem yapısı çoğu zaman tanınabilir bir zincir oluşturur. Meşru exchange hot wallet'ları da benzer şekilde davranabilir; bu nedenle attribution için service/context kanıtı gerekir. DOJ, DPRK bağlantılı forfeiture davalarında peel-chain analysis kullanmıştır.<sup>[[1]](#references)</sup>

### Structuring ve fan-out/fan-in

- **Fan-out:** bir kaynak, investigative workload'u artırmak veya paralel conversion hazırlamak için birçok adrese bölünür.
- **Fan-in:** birçok kaynak tek bir collector'da birleştirilir; bu durum ortak control veya bir service olduğunu ortaya çıkarır.
- **Structuring:** tekrarlanan daha küçük transferler, review threshold'larından kaçınmaya veya sıradan işlem hacmine karışmaya çalışır.
- **Commingling:** illicit ve ilgisiz fonlar wallet'ları, pool'ları veya service'leri paylaşır; bu da basit oransal iddiaları güvensiz hale getirir.

Graph şekli bir lead'dir, kanıt değildir. Analistler fee'leri, UTXO/account model'ini, service davranışını ve change kurallarını hesaba katmalıdır.

### CoinJoin ve PayJoin

Tipik bir CoinJoin'de birkaç participant input sağlar ve çoğu zaman eşit output denominations ile tek bir collaborative transaction içinde output alır. Bu, bir transaction'daki her input ve output'un tek bir owner'a ait olduğu varsayımını geçersiz kılar. Anonymity set, participant sayısı ve sonraki davranışlarla sınırlıdır: eşit olmayan change, toxic change, consolidation veya bilinen bir service'ten geçiş, link'leri yeniden oluşturabilir.

PayJoin, hem payer'ın hem de payee'nin input sağlamasını mümkün kılacak şekilde ordinary payment'ı değiştirir ve böylece o transaction için common-input ownership heuristic'ini doğrudan geçersiz kılar. Esas olarak bir payment privacy protocol'üdür; bulk laundering service değildir. Detection, tüm input'ların ortak owner'a ait olduğunu ilan etmekten kaçınmalı ve yanlış bir cluster'ı zorlamak yerine belirsizliği ifade etmelidir.

### Centralized mixers ve tumblers

Centralized mixer, deposit'ları kabul eder ve daha sonra, çoğu zaman fee'ler ve gecikmeler sonrasında, pooled reserve'dan farklı coin'lerle ödeme yapar. Privacy; pool büyüklüğüne, withdrawal policy'ye, log'lara, operator dürüstlüğüne ve seizure'a dayanıklılığa bağlıdır. Entry ve exit zaman/değer analizi, deposit address'leri, service wallet clustering ve kayıtlar olası kümenin daraltılmasını sağlayabilir. Operator'lar fonları çalabilir veya eksiksiz bir mapping'i saklayabilir.

Legal exposure önemli ölçüdedir ve jurisdiction'a özgüdür. DOJ'nin ChipMixer, Samourai Wallet ve Tornado Cash developer/operator'larına karşı davaları ile değişen sanctions litigation süreçleri; protocol, custody, control ve money-transmission unsurlarının önem taşıdığını gösterir. “Decentralized” gibi bir etiket, hukuki bir sonuç değildir.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps ve bridges

Chain hopping bir asset'i dönüştürür veya bridge üzerinden taşır; böylece tek bir ledger sorgusunu kesintiye uğratır, ancak economic continuity'yi bozmaz:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analistler bridge contract/service deposit adreslerini, işlem sırasını, zaman aralığını, exchange rate'i, ücretleri, likiditeyi ve benzersiz tutarı ilişkilendirir. Tekrarlanan swap'ler belirsizliği artırabilirken provider/API/wallet telemetry verileri de eklenebilir. FATF, şüpheli bağlamla birlikte kullanıldığında chain hopping, mixers, peer-to-peer services ve anonymity-enhanced currencies unsurlarını özellikle risk göstergeleri olarak tanımlar.<sup>[[3]](#references)</sup>

### NFT'ler, gambling ve merchant purchases

Kendi kendine işlem yapma veya gizli anlaşmalı NFT trades, fonlara görünürde bir satış anlatısı kazandırabilir; gambling, yatırma işlemlerini çekimlerle değiştirebilir; goods ise dijital değeri yeniden satılabilir envantere dönüştürebilir. Bu yollar marketplace hesapları, creator/royalty bağlantıları, wash-trading grafikleri, odds/play geçmişi, device log'ları, teslimat ve yeniden satış kanıtları bırakır. Bir loss veya fee, provenance'ın ortadan kalktığının kanıtı değildir.

## Privacy-preserving cryptocurrencies

Privacy protocols teknik olarak farklılık gösterir:

- **Monero**, tek kullanımlık adresler, ring signatures ve confidential amounts kullanarak public sender/receiver/amount görünürlüğünü azaltır. Network observation, wallet compromise, acquisition/off-ramp ve counterparty kayıtları bu on-chain korumaların dışında kalır.
- **Zcash shielded pools**, shielded transactions kullanıldığında sender, receiver ve amount bilgilerini gizleyebilir; transparent addresses ve pool'lar arasındaki geçişler public kalır ve kullanım patterns, effective anonymity set'i etkiler.
- **Bitcoin**, varsayılan olarak transparent'tır. New addresses, CoinJoin, PayJoin ve Lightning belirli linkage varsayımlarını değiştirir, ancak tüm katmanları private hale getirmez.

Privacy technology meşru güvenlik ve ticari kullanımlara sahiptir. Investigative perspective açısından ledger daha az bilgi sağladığında endpoint, service, network ve human evidence daha önemli hale gelir. Yalnızca privacy-preserving protocol seçimine dayanarak asla criminality çıkarımı yapmayın.

## DPRK multi-layer case model

Public DOJ allegations ve forfeiture actions, tek bir numaradan ziyade birleştirilmiş bir süreci tanımlar:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. çalışanlar, remote employment elde etmek için sahte/çalınmış identity material ve VPN'ler kullandı;
2. işverenler, stablecoin'ler dahil olmak üzere cryptocurrency ile ödeme yaptı;
3. fonlar daha küçük tutarlara bölündü, chain veya token'lar arasında taşındı, NFT'ler satın aldı veya commingled edildi;
4. diğer çalınmış fonlar mixers'a girdi;
5. OTC traders ve front companies, değeri fiat payments veya goods'a dönüştürdü;
6. tekrarlanan facilitators, hesaplar ve blockchain paths, investigators'ın katmanları yeniden ilişkilendirmesini sağladı.

Treasury, Lazarus'un Axie Infinity/Ronin theft'in bir bölümünü işlemek için Blender.io kullandığını belirtirken FBI, adresler yayımladı ve bridges, exchanges, RPC operators ile analytics firms'ı daha sonraki TraderTraitor theft'lerle bağlantılı fonları block etmeye çağırdı.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Ders çift yönlüdür: state actors sıradan commercial/criminal services kullanır ve public blockchains, isimler başlangıçta bilinmese bile defenders'ın değeri takip etmesine olanak tanır.

## Detection workflow

1. **Raw transaction identifiers ve kayıtları koruyun.** Screenshots ve yuvarlanmış fiat values yeterli değildir.
2. **Assets ve zamanı normalize edin.** Chain, token contract, units, block time, service time zone, fees ve exchange-rate source bilgilerini kaydedin.
3. **Evidence confidence'ı etiketleyin.** Service-published address, deterministic contract event, clustering heuristic ve external intelligence unsurlarını birbirinden ayırın.
4. **Her iki yönü de izleyin.** Funding origin, immediate dispersal, reconvergence, bridge exits, service deposits ve spend/delivery akışlarını bulun.
5. **Off-chain evidence'ı birleştirin.** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping ve communication records genellikle belirsizliği giderir.
6. **Alternatif açıklamaları test edin.** Exchanges, custodians, payroll ve privacy protocols, common beneficial ownership olmadan fan-in/out veya co-spends oluşturabilir.
7. **Premature close yerine monitor edin.** Dormant bir output, daha sonra bir service'e ulaştığında attributable hale gelebilir.
8. **Güncel sanctions/AML obligations'ı counsel ile uygulayın.** Rules ve designations değişir; historical association, current legal analysis'ın yerine geçmez.

## Safe red-team procurement model

Authorized bir team, engagement controller accountability'yi korurken target SOC'nin hosting payment'ı fark etmemesine ihtiyaç duyabilir:

- engagement-specific organization card veya documented corporate wallet kullanın;
- billing, tax ve provider records'ı doğru tutun;
- operator'ı procurement duties'ten ayırın ve attribution map'e erişimi sınırlayın;
- asla mule, false identity, stolen card, sanctions workaround veya unlicensed exchanger kullanmayın;
- asset, amount, owner, service, date, refund path ve teardown evidence bilgilerini kaydedin;
- exercise sonrasında ilgili payment/provider indicators'ı controller'a açıklayın.

Bu, **exercise participant'a karşı blindness** oluşturur; law, provider veya governance'a karşı blindness oluşturmaz.

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework (peel-chain example and DPRK investigations)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer takedown](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Forfeiture complaint concerning $7.74 million allegedly laundered for DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions and Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea responsible for the 2025 Bybit theft](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Application of regulations to virtual-currency users, administrators and exchangers](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
