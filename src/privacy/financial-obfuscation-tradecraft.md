# Financial Obfuscation Tradecraft

{{#include ../banners/hacktricks-training.md}}

Ödeme gizliliği, ödeme markası değil, attribution problemidir. Bir operasyon; değer edinildiğinde, taşındığında, dönüştürüldüğünde, harcandığında ve teslim edildiğinde kanıt bırakır. Public-chain adresi pseudonymous olabilir; ancak bir exchange, kart issuer'ı, merchant, mobil cihaz veya kargo kamerası arkasındaki kişiyi tespit edebilir.

Bu sayfa, defender'ların bunları tanıyabilmesi için cybercrime ve devlet bağlantılı operasyonlarda kullanılan financial-obfuscation kalıplarını açıklar. Bir laundering, sanctions-evasion, false-identity veya KYC-bypass prosedürü sağlamaz.

## Uçtan uca değer grafiği
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Bir aktör, hiçbir gözlemcinin her iki ucu da görmesini engellemeye çalışır. Araştırmacılar ise bunun tersini yapar: her sınırdaki kayıtları korur, zamanı/değeri/ücretleri normalize eder ve ayrı personeların aynı aracı, cihazı, hesabı, merchant'ı veya hedefi yeniden kullandığı **yeniden birleşme noktasını** belirler.

## Enstrümanlar ve bunları gerçekten gözlemleyenler

| Enstrüman | Merchant'tan/kamuoyundan gizli olan | Hâlâ görünür olduğu taraflar |
|---|---|---|
| Issuer sanal kartı/token'ı | asıl kart numarası | issuer, network/token sağlayıcısı, wallet, merchant hesabı ve teslimat sistemleri |
| Prepaid/gift value | sıradan satın alımda bazen yasal ad | retailer/payment rail, aktivasyon/kullanım hizmeti, kameralar, cihaz ve teslimat |
| Cash | kamu ledger'ı ve uzak issuer | karşı taraflar, kameralar, uygulanabildiğinde çekim/seri numarası kontrolleri, fiziksel arama |
| Bitcoin/yeni adres | doğrudan yasal ad | her blockchain gözlemcisi; wallet/network peer'ları; acquisition/off-ramp hizmetleri |
| CoinJoin/PayJoin | basit ortak-input/payment sezgisel yöntemleri | kamuya açık transaction, coordinator/peer/network metadata'sı ve sonraki harcama davranışı |
| Privacy coin | protokole bağlı olarak kamuya açık sender/receiver/amount | acquisition/off-ramp, wallet endpoint'i, network gözlemcisi ve karşı taraf |
| Centralized mixer | doğrudan deposit-to-withdraw bağlantısı | mixer operator/log'ları, blockchain giriş/çıkış kümeleri ve karşı taraflar |
| Cross-chain bridge/swap | tek bir chain üzerindeki süreklilik | her iki chain, bridge/swap hizmeti, zamanlama/değer ve likidite kısıtlamaları |
| OTC/P2P broker | bazı durumlarda doğrudan exchange hesabı | broker, iletişimler, banka/cash hareketi, karşı taraflar ve cihazlar |

## Kartlar, prepaid value, nominee'ler ve muller

### Virtual ve masked card'lar

Bir issuer, merchant'a kilitlenmiş veya tek kullanımlık bir kart numarası oluşturabilir. Bu, merchant'ın maruz kaldığı bilgiyi ve farklı merchant'lar arasında kart numarasının yeniden kullanılmasını azaltır. Issuer yine de bunu müşteriye, funding hesabına, cihaza, IP'ye ve transaction'a bağlar. Billing descriptor'ları, merchant hesabı, shipping address ve browser verileri ilişkilendirilebilir olmaya devam eder.

“İsimsiz” kart pazarlaması, anonim settlement anlamına gelmez. Regüle issuer'lar ve distribütörler identity check gerçekleştirebilir, kayıtları saklayabilir, coğrafi/tutar limitleri uygulayabilir ve yasal süreçlere yanıt verebilir. Stolen identity kullanılarak edinilen bir kart identity theft oluşturur; issuer/device/merchant telemetry'sini ortadan kaldırmaz.

### Prepaid ve gift value

Prepaid card'lar ve gift code'lar, sonraki redemption işlemini ilk payment instrument'ından ayırır; ancak satın alma, activation, balance-query ve redemption olayları bulunan numaralı bir nesne oluşturur. Önem taşıyan pattern'ler arasında toplu satın alımlar, kontrollerin hemen altında kalan denomination'ların tekrarlı şekilde alınması, uzak bir konumda hızlı redemption, tek bir cihazın çok sayıda balance sorgulaması veya çok sayıda kartın tek bir merchant/account üzerinde birleşmesi bulunur.

### Nominee'ler, money mule'lar ve merchant front'ları

Bir nominee veya mule, operator ile bir hizmet arasına yerleşen bir hesap ve yasal kimlik sağlar. Network'ler recruiter'ları, account holder'ları, payment processor'ları, shell merchant'ları ve cash-out broker'larını katmanlandırabilir. Bu mesafe yaratır; ancak her katılımcı iletişim kayıtları, ücretler, davranışsal tutarsızlıklar ve iş birliği yapabilecek potansiyel bir tanık ekler. Front şirketleri kuruluş, vergi, bankacılık, director, fatura, hosting ve shipment kayıtları oluşturur.

Defender'lar ortak cihazları/IP'leri, beneficiary tekrar kullanımını, geolocation çelişkilerini, hesap geçmişiyle tutarsız velocity'yi, circular transfer'ları, birden fazla ilgisiz sender'ın aynı noktada birleşmesini ve hemen ardından gerçekleşen onward movement'ı araştırmalıdır. Adı geçen account holder'ın controlling actor olduğunu varsaymayın; onları rol belirlemesi gerektiren bir node olarak ele alın.

## Public-chain transaction-obfuscation pattern'leri

### Address rotation ve coin control

Her receipt için yeni bir address oluşturmak, basit address reuse'ı önler; ancak transaction'lar yine de common input'lar, change detection, exact value/time ve sonraki consolidation yoluyla aynı sahipliğe bağlanabilir. **Coin control**, bir wallet'ın hangi output'ları harcayacağını seçmesine ve compartment'ları birleştirmekten kaçınmasına olanak tanır. Bu, hijyeni iyileştirir; daha önce kamuya açık hâle gelmiş bir bağlantıyı ortadan kaldıramaz.

### Peel chain'ler

Bir peel chain, büyük bir balance'ı tekrar tekrar harcayarak daha küçük bir tutarı dışarı gönderir ve kalan miktarı yeni bir address'e geri gönderir:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Adres her adımda değişir, ancak değer sürekliliği, işlem ritmi ve işlem yapısı çoğu zaman tanınabilir bir zincir oluşturur. Meşru exchange hot wallet'ları da benzer şekilde davranabilir; bu nedenle attribution için hizmet/bağlam kanıtı gerekir. DOJ, DPRK bağlantılı müsadere davalarında peel-chain analizini kullanmıştır.<sup>[[1]](#references)</sup>

### Structuring ve fan-out/fan-in

- **Fan-out:** bir kaynak, araştırma yükünü artırmak veya paralel dönüşüm hazırlamak için birçok adrese bölünür.
- **Fan-in:** birçok kaynak tek bir toplayıcıda birleştirilir; bu durum ortak kontrolü veya bir hizmeti ortaya çıkarır.
- **Structuring:** tekrarlanan daha küçük transferler, inceleme eşiklerinden kaçınmayı veya sıradan işlem hacmine karışmayı amaçlar.
- **Commingling:** yasa dışı ve ilgisiz fonlar wallet'ları, pool'ları veya hizmetleri paylaşır; bu da basit orantısal iddiaları güvensiz hâle getirir.

Grafik şekli bir ipucudur, kanıt değildir. Analistler ücretleri, UTXO/account modelini, hizmet davranışını ve change kurallarını hesaba katmalıdır.

### CoinJoin ve PayJoin

Tipik bir CoinJoin işleminde, birkaç katılımcı tek bir ortak işlemde input'lar sağlar ve çoğu zaman eşit output miktarları alır. Bu, bir işlemdeki her input ve output'un tek bir sahibi olduğu varsayımını bozar. Anonimlik kümesi, katılımcı sayısı ve sonraki davranışlarla sınırlıdır: eşit olmayan change, toxic change, consolidation veya bilinen bir hizmetten geçiş, bağlantıları yeniden kurabilir.

PayJoin, hem payer hem de payee'nin input'lara katkıda bulunacağı şekilde sıradan bir ödemeyi değiştirir ve böylece o işlem için common-input ownership heuristic'ini doğrudan geçersiz kılar. Öncelikle bir ödeme privacy protokolüdür; bulk laundering service değildir. Detection, tüm input'ların ortak mülkiyette olduğunu varsaymaktan kaçınmalı ve yanlış bir cluster zorlamak yerine belirsizliği ifade etmelidir.

### Merkezi mixer'lar ve tumbler'lar

Merkezi bir mixer, deposit'leri kabul eder ve daha sonra, çoğunlukla ücretler ve gecikmeler sonrasında, pool'lanmış bir rezervden farklı coin'ler öder. Privacy düzeyi; pool boyutuna, withdrawal politikasına, log'lara, operator dürüstlüğüne ve seizure'a karşı dirence bağlıdır. Giriş ve çıkış zaman/değer analizi, deposit adresleri, service wallet clustering ve kayıtlar olası kümenin daraltılmasını sağlayabilir. Operator'lar fonları çalabilir veya eksiksiz bir eşleştirmeyi saklayabilir.

Hukuki risk önemli ölçüdedir ve yargı alanına göre değişir. ChipMixer, Samourai Wallet ve Tornado Cash geliştiricileri/operator'larına karşı DOJ davaları ile değişen yaptırım davaları, protocol, custody, control ve money-transmission olgularının önemli olduğunu göstermektedir; “decentralized” gibi bir etiket hukuki bir sonuç değildir.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swap'ler ve bridge'ler

Chain hopping, bir asset'i dönüştürür veya bir bridge üzerinden taşır; bu, tek bir ledger sorgusunu kesintiye uğratır ancak ekonomik sürekliliği bozmaz:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analistler bridge contract/service deposit adreslerini, işlem sırasını, zaman aralığını, exchange rate'i, ücretleri, likiditeyi ve benzersiz tutarı ilişkilendirir. Tekrarlanan swap'ler belirsizliği artırabilir; ancak provider/API/wallet telemetry de ekler. FATF, chain hopping, mixer'lar, peer-to-peer services ve anonymity-enhanced currencies'i, şüpheli bağlamla birlikte kullanıldıklarında risk göstergeleri olarak özellikle tanımlar.<sup>[[3]](#references)</sup>

### NFT'ler, kumar ve merchant purchases

Self-dealing veya collusive NFT işlemleri, fonlara görünürde bir satış anlatısı kazandırabilir; kumar, yatırılan fonları çekimlerle değiştirebilir; mallar ise dijital değeri yeniden satılabilir envantere dönüştürebilir. Bu yollar marketplace hesapları, creator/royalty bağlantıları, wash-trading grafikleri, odds/play geçmişi, device log'ları, teslimat ve yeniden satış kanıtları bırakır. Bir kayıp veya ücret, provenance'ın ortadan kalktığının kanıtı değildir.

## Gizliliği koruyan kripto paralar

Privacy protocol'leri teknik açıdan farklılık gösterir:

- **Monero**, tek kullanımlık adresler, ring signatures ve confidential amounts kullanarak sender/receiver/amount görünürlüğünü azaltır. Network observation, wallet compromise, acquisition/off-ramp ve counterparty kayıtları bu on-chain korumaların dışında kalır.
- **Zcash shielded pools**, shielded transactions kullanıldığında sender, receiver ve amount bilgilerini gizleyebilir; transparent addresses ve pool'lar arasındaki geçişler public kalır ve kullanım kalıpları etkin anonymity set'i etkiler.
- **Bitcoin**, varsayılan olarak transparandır. New addresses, CoinJoin, PayJoin ve Lightning belirli linkage varsayımlarını değiştirir; ancak tüm katmanları private hale getirmez.

Privacy technology'nin meşru güvenlik ve ticari kullanımları vardır. Investigative perspective açısından ledger daha az bilgi sağladığında endpoint, service, network ve human evidence daha önemli hale gelir. Yalnızca privacy-preserving protocol seçimine dayanarak hiçbir zaman criminality çıkarımı yapmayın.

## DPRK multi-layer case model

Kamuya açık DOJ iddiaları ve forfeiture işlemleri, tek bir hileyi değil, birleştirilmiş bir süreci açıklar:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workers, remote employment elde etmek için fictitious/stolen identity material ve VPN'ler kullandı;
2. employers, stablecoin'ler de dahil olmak üzere cryptocurrency ile ödeme yaptı;
3. fonlar daha küçük tutarlara bölündü, chain'ler veya token'lar arasında geçirildi, NFT'ler satın alındı ya da fonlar commingle edildi;
4. diğer stolen funds mixer'lara girdi;
5. OTC traders ve front companies, değeri fiat payments veya goods'a dönüştürdü;
6. tekrarlanan facilitators, hesaplar ve blockchain paths, investigators'ın katmanları yeniden birbirine bağlamasına olanak sağladı.

Treasury, Lazarus'un Axie Infinity/Ronin theft'inin bir bölümünü işlemek için Blender.io kullandığını belirtirken FBI, adresler yayımlamış ve bridge'leri, exchange'leri, RPC operator'larını ve analytics firm'alarını daha sonraki TraderTraitor theft'leriyle bağlantılı fonları block etmeye çağırmıştır.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Ders iki yönlüdür: state actors sıradan commercial/criminal services kullanır ve public blockchains, isimler başlangıçta bilinmiyor olsa bile defenders'ın value'yu takip etmesine olanak tanır.

## Detection workflow

1. **Raw transaction identifier'ları ve kayıtları koruyun.** Screenshots ve yuvarlanmış fiat değerleri yetersizdir.
2. **Asset'leri ve zamanı normalize edin.** Chain, token contract, units, block time, service time zone, fees ve exchange-rate source bilgilerini kaydedin.
3. **Evidence confidence'ı etiketleyin.** Service tarafından yayımlanan address, deterministic contract event, clustering heuristic ve external intelligence ayrımını yapın.
4. **Her iki yönü de trace edin.** Funding origin, immediate dispersal, reconvergence, bridge exits, service deposits ve spend/delivery noktalarını bulun.
5. **Off-chain evidence'ı birleştirin.** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping ve communication records çoğu zaman belirsizliği çözer.
6. **Alternatif açıklamaları test edin.** Exchange'ler, custodians, payroll ve privacy protocol'leri common beneficial ownership olmadan fan-in/out veya co-spends oluşturabilir.
7. **Prematurely close etmek yerine monitor edin.** Dormant bir output, daha sonra bir service'e ulaştığında attributable hale gelebilir.
8. **Güncel sanctions/AML yükümlülüklerini counsel ile uygulayın.** Rules ve designations değişir; historical association, current legal analysis'ın yerine geçmez.

## Safe red-team procurement model

Authorized bir ekibin, engagement controller accountability'yi korurken target SOC'un hosting payment'ını fark etmemesine ihtiyaç duyduğu durumlarda:

- engagement-specific organization card veya documented corporate wallet kullanın;
- billing, tax ve provider records bilgilerini doğru tutun;
- operator'ı procurement duties'ten ayırın ve attribution map'e erişimi sınırlandırın;
- hiçbir zaman mule, false identity, stolen card, sanctions workaround veya unlicensed exchanger kullanmayın;
- asset, amount, owner, service, date, refund path ve teardown evidence bilgilerini kaydedin;
- exercise sonrasında ilgili payment/provider indicator'larını controller'a açıklayın.

Bu, **exercise participant'a karşı blindness** oluşturur; law, provider veya governance'a karşı blindness oluşturmaz.

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework (peel-chain example and DPRK investigations)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer takedown'ı](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank temsilcisi crypto-laundering conspiracies nedeniyle suçlandı](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — DPRK adına allegedly laundered edilen $7.74 million ile ilgili forfeiture complaint](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions ve Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea, 2025 Bybit theft'inden sorumlu](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — regulations'ın virtual-currency users, administrators ve exchangers'a uygulanması](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
