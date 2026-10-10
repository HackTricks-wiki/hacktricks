# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) framework'ü, dijital varlık sistemlerini hedef alan adversarial eylem ve teknikleri kategorilere ayırır.<sup>[[1]](#references)</sup> Bunu bir **threat-modeling omurgası** olarak ele alın: varlık basabilen, fiyatlandırabilen, yetkilendirebilen veya yönlendirebilen her bileşeni listeleyin, bu temas noktalarını AADAPT teknikleriyle eşleştirin ve ardından ortamın geri döndürülemez ekonomik kayıplara karşı koyup koyamayacağını ölçen red-team senaryoları yürütün.

## 1. Değer taşıyan bileşenlerin envanterini çıkarın
Zincir dışı olsa bile değer durumunu etkileyebilecek her şeyin haritasını oluşturun.<sup>[[2]](#references)</sup>

- **Custodial imzalama hizmetleri** (HSM/KMS kümeleri, Vault/KMaaS, botlar veya back-office işleri tarafından kullanılan imzalama API'leri). Anahtar kimliklerini, politikaları, otomasyon kimliklerini ve onay iş akışlarını kaydedin.
- **Sözleşmelerin yönetim ve yükseltme yolları** (proxy yöneticileri, governance timelock'ları, acil durdurma anahtarları, parametre kayıt defterleri). Bunları kimin/ne tür bir bileşenin, hangi quorum veya gecikme koşuluyla çağırabildiğini ekleyin.
- **Borç verme, AMM'ler, vault'lar, staking, bridge'ler veya settlement raylarını yöneten zincir üstü protokol mantığı**. Bu mantığın dayandığı değişmezleri belgeleyin (oracle fiyatları, teminat oranları, rebalance sıklığı…).
- **İşlemleri oluşturan zincir dışı otomasyon** (market-making botları, CI/CD pipeline'ları, cron işleri, serverless işlevleri). Bunlar çoğunlukla imza isteğinde bulunabilen API anahtarları veya service principal'lar barındırır.
- **Oracle'lar ve data feed'ler** (aggregator bileşimi, quorum, sapma eşikleri, güncelleme sıklığı). Otomatik risk mantığının dayandığı tüm upstream kaynakları not edin.
- **Bridge'ler ve cross-chain router'lar** (lock/mint sözleşmeleri, relayer'lar, settlement işleri); zincirleri veya custodial yığınları birbirine bağlar.

Teslimat: Varlıkların nasıl hareket ettiğini, hareketi kimin yetkilendirdiğini ve hangi harici sinyallerin iş mantığını etkilediğini gösteren bir value-flow diyagramı.

## 2. Bileşenleri AADAPT davranışlarıyla eşleştirin
AADAPT taksonomisini her bileşen için somut saldırı adaylarına dönüştürün.<sup>[[2]](#references)</sup>

| Bileşen | Birincil AADAPT odağı |
| --- | --- |
| İmzalama/KMS ortamları | Kimlik bilgisi hırsızlığı, politika atlatma, imza kötüye kullanımı, governance ele geçirme |
| Oracle'lar/feed'ler | Girdi zehirleme, aggregation manipülasyonu, sapma eşiğini atlatma |
| Zincir üstü protokoller | Flash-loan ekonomik manipülasyonu, invariant ihlali, parametreleri yeniden yapılandırma |
| Otomasyon pipeline'ları | Ele geçirilmiş bot/CI kimlikleri, batch replay, yetkisiz deployment |
| Bridge'ler/router'lar | Cross-chain izini kaybettirme, hızlı hop laundering, settlement senkronizasyonunun bozulması |

Bu eşleştirme, yalnızca sözleşmeleri değil, değeri dolaylı olarak yönlendirebilen her kimliği/otomasyonu da test etmenizi sağlar.

## 3. Saldırganın uygulanabilirliğine ve iş etkisine göre önceliklendirin

1. **Operasyonel zayıflıklar**: açığa çıkmış CI kimlik bilgileri, aşırı yetkili IAM rolleri, yanlış yapılandırılmış KMS politikaları, rastgele imza isteğinde bulunabilen otomasyon hesapları, bridge yapılandırmalarını içeren herkese açık bucket'lar vb.
2. **Değere özgü zayıflıklar**: hassas oracle parametreleri, çok taraflı onaylar olmadan yükseltilebilen sözleşmeler, flash-loan'a duyarlı likidite, timelock'ları atlatan governance eylemleri.

Kuyruğu bir saldırgan gibi ele alın: bugün başarıya ulaşabilecek operasyonel dayanak noktalarından başlayın, ardından derin protokol/ekonomik manipülasyon yollarına ilerleyin.<sup>[[2]](#references)</sup>

## 4. Kontrollü, üretimi gerçekçi kılan ortamlarda yürütün
- **Fork edilmiş mainnet'ler / izole testnet'ler**: flash-loan yollarının, oracle sapmalarının ve bridge akışlarının gerçek fonlara dokunmadan uçtan uca çalışması için bytecode'u, storage'ı ve likiditeyi çoğaltın.<sup>[[2]](#references)</sup>
- **Etki alanı planlaması**: bir senaryoyu tetiklemeden önce circuit breaker'ları, duraklatılabilir modülleri, rollback runbook'larını ve yalnızca testte kullanılacak admin anahtarlarını belirleyin.
- **Paydaşlarla koordinasyon**: izleme ekiplerinin bu trafiği beklemesi için custodial hizmet sağlayıcılarını, oracle operatörlerini, bridge iş ortaklarını ve compliance ekiplerini bilgilendirin.
- **Yasal onay**: simülasyonların düzenlemeye tabi kanalları etkileyebileceği durumlarda kapsamı, yetkilendirmeyi ve durdurma koşullarını belgeleyin.

## 5. Telemetriyi AADAPT teknikleriyle uyumlu hâle getirin
Her senaryonun eyleme dönüştürülebilir tespit verileri üretmesi için telemetri akışlarını enstrümante edin.<sup>[[2]](#references)</sup>

- **Zincir düzeyinde izler**: flash-loan paketlerini, reentrancy benzeri yapıları ve sözleşmeler arası geçişleri yeniden oluşturmak için tam çağrı grafikleri, gas kullanımı, işlem nonce'ları ve block timestamp'leri.
- **Uygulama/API logları**: her zincir üstü işlemi IP'ler ve kimlik doğrulama yöntemleriyle birlikte bir insan veya otomasyon kimliğine (session ID, OAuth client, API key, CI job ID) bağlayın.
- **KMS/HSM logları**: her imza için key ID, çağıran principal, politika sonucu, hedef adres ve neden kodları. Değişiklik zaman aralıklarını ve yüksek riskli işlemleri referans alın.
- **Oracle/feed metaverileri**: her güncelleme için veri kaynağı bileşimi, bildirilen değer, hareketli ortalamalardan sapma, tetiklenen eşikler ve kullanılan failover yolları.
- **Bridge/swap izleri**: zincirler arasındaki lock/mint/unlock olaylarını correlation ID'ler, chain ID'ler, relayer kimliği ve hop zamanlamasıyla ilişkilendirin.
- **Anomali işaretleri**: slippage artışları, anormal teminatlandırma oranları, olağandışı gas yoğunluğu veya cross-chain hız gibi türetilmiş metrikler.

Analistlerin gözlemlenebilir verileri uygulanan AADAPT tekniğiyle eşleştirebilmesi için her şeyi senaryo ID'leri veya sentetik kullanıcı ID'leriyle etiketleyin.

## 6. Purple-team döngüsü ve olgunluk metrikleri
1. Senaryoyu kontrollü ortamda çalıştırın ve tespitleri (uyarılar, dashboard'lar, çağrılan müdahale ekipleri) kaydedin.<sup>[[2]](#references)</sup>
2. Her adımı belirli AADAPT teknikleriyle ve zincir/uygulama/KMS/oracle/bridge katmanlarında üretilen gözlemlenebilir verilerle eşleştirin.
3. Tespit hipotezleri oluşturup uygulayın (eşik kuralları, korelasyon aramaları, invariant kontrolleri).
4. Ortalama tespit süresi (MTTD) ve ortalama kontrol altına alma süresi (MTTC) iş toleranslarını karşılayana ve playbook'lar değer kaybını güvenilir biçimde durdurana kadar yeniden çalıştırın.

Program olgunluğunu üç eksende takip edin:<sup>[[2]](#references)</sup>
- **Görünürlük**: her kritik değer yolunda her katman için telemetri bulunması.
- **Kapsam**: uçtan uca uygulanan öncelikli AADAPT tekniklerinin oranı.
- **Müdahale**: geri döndürülemez kayıp yaşanmadan önce sözleşmeleri duraklatma, anahtarları iptal etme veya akışları dondurma becerisi.

Tipik kilometre taşları: (1) değer envanterinin ve AADAPT eşlemesinin tamamlanması, (2) tespitler uygulanarak ilk uçtan uca senaryonun yürütülmesi, (3) kapsamı genişleten ve MTTD/MTTC'yi düşüren üç aylık purple-team döngüleri.<sup>[[2]](#references)</sup>

## 7. Senaryo şablonları
AADAPT davranışlarıyla doğrudan eşleşen simülasyonlar tasarlamak için bu tekrarlanabilir planları kullanın.<sup>[[2]](#references)</sup>

### Senaryo A – Flash-loan ekonomik manipülasyonu
- **Amaç**: AMM fiyatlarını/likiditesini bozmak ve geri ödemeden önce yanlış fiyatlandırılmış borçları, likidasyonları veya mint işlemlerini tetiklemek için tek bir işlem içinde geçici sermaye ödünç almak.
- **Yürütme**:
  1. Hedef zinciri fork edin ve havuzları üretime benzer likiditeyle doldurun.
  2. Flash loan aracılığıyla yüksek tutarda varlık ödünç alın.
  3. Borç verme, vault veya türev mantığının dayandığı fiyat/eşik sınırlarını aşmak için ayarlanmış swap'ler gerçekleştirin.
  4. Sapmanın hemen ardından hedef sözleşmeyi çağırın (borç alma, likide etme, mint etme) ve flash loan'ı geri ödeyin.
- **Ölçüm**: Invariant ihlali başarılı oldu mu? Slippage/fiyat sapması izleyicileri, circuit breaker'lar veya governance duraklatma kancaları tetiklendi mi? Analitik sistemler anormal gas/çağrı grafiği örüntüsünü ne kadar sürede işaretledi?

### Senaryo B – Oracle/data feed zehirleme
- **Amaç**: manipüle edilmiş feed'lerin yıkıcı otomatik eylemleri (toplu likidasyonlar, hatalı settlement'lar) tetikleyip tetikleyemediğini belirlemek.
- **Yürütme**:
  1. Fork/testnet ortamında kötü niyetli bir feed deploy edin veya aggregator ağırlıklarını/quorum değerini/güncelleme sıklığını tolere edilen sapmanın ötesine taşıyın.
  2. Bağımlı sözleşmelerin zehirlenmiş değerleri kullanmasına ve standart mantıklarını yürütmesine izin verin.
- **Ölçüm**: Feed düzeyindeki out-of-band uyarılar, fallback oracle'ın devreye girmesi, minimum/maksimum sınırların uygulanması ve anomalinin başlamasıyla operatörün müdahalesi arasındaki gecikme.

### Senaryo C – Kimlik bilgisi/imza kötüye kullanımı
- **Amaç**: tek bir imzalayanın veya otomasyon kimliğinin ele geçirilmesinin yetkisiz yükseltmelere, parametre değişikliklerine veya hazine varlıklarının boşaltılmasına olanak verip vermediğini test etmek.
- **Yürütme**:
  1. Hassas imzalama haklarına sahip kimlikleri listeleyin (operatörler, CI token'ları, KMS/HSM çağıran service account'lar, multisig katılımcıları).
  2. Kapsam dâhilinde, laboratuvar ortamında bu kimlik bilgilerini/anahtarlarını yeniden kullanarak ele geçirilme durumunu simüle edin.
  3. Ayrıcalıklı eylemleri deneyin: proxy'leri yükseltmek, risk parametrelerini değiştirmek, varlıkları mint etmek/duraklatmak veya governance tekliflerini tetiklemek.
- **Ölçüm**: KMS/HSM logları anomali uyarıları (günün saati, hedef adres değişimi, yüksek riskli işlemlerde artış) oluşturuyor mu? Politikalar veya multisig eşikleri tek taraflı kötüye kullanımı önleyebiliyor mu? Throttle/rate limit'leri veya ek onaylar uygulanıyor mu?

### Senaryo D – Cross-chain izini kaybettirme ve izlenebilirlik boşlukları
- **Amaç**: savunucuların bridge'ler, DEX router'lar ve privacy hop'ları üzerinden hızla laundering işlemine tabi tutulan varlıkları ne kadar iyi izleyip durdurabildiğini değerlendirmek.
- **Yürütme**:
  1. Yaygın bridge'ler arasında lock/mint işlemlerini zincirleyin, her hop'ta swap'leri/mixer'ları araya ekleyin ve hop başına correlation ID'leri koruyun.
  2. İzleme gecikmesini zorlamak için transferleri hızlandırın (dakikalar/bloklar içinde birden çok hop).
- **Ölçüm**: Telemetri ve ticari zincir analitiği genelinde olayları ilişkilendirme süresi, yeniden oluşturulan yolun eksiksizliği, gerçek bir olayda dondurma noktalarını belirleyebilme ve anormal cross-chain hız/değer için uyarıların doğruluğu.

## References

- [1] [Dijital Varlıklar için AADAPT(TM) Cyber Threat Framework (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Red Team Yol Haritası olarak MITRE AADAPT Framework (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
