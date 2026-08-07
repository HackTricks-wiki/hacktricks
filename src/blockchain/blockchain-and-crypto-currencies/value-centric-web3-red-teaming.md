# Değer Odaklı Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrisi, yalnızca altyapıyı değil, dijital değeri manipüle eden saldırgan davranışlarını kapsar. Bunu bir **threat-modeling omurgası** olarak ele alın: varlıkları mint edebilen, fiyatlandırabilen, yetkilendirebilen veya yönlendirebilen her bileşeni listeleyin, bu temas noktalarını AADAPT teknikleriyle eşleyin ve ardından ortamın geri döndürülemez ekonomik kayba dayanıp dayanamayacağını ölçen red-team senaryoları yürütün.

## 1. Değer taşıyan bileşenlerin envanterini çıkarın
Off-chain olsa bile değer durumunu etkileyebilen her şeyi haritalandırın.<sup>[[1]](#references)</sup>

- **Custodial signing services** (HSM/KMS kümeleri, Vault/KMaaS, botlar veya back-office işleri tarafından kullanılan signing API'leri). Key ID'leri, policy'leri, automation identity'lerini ve approval workflow'larını kaydedin.
- Kontratlar için **admin ve upgrade yolları** (proxy admin'leri, governance timelock'ları, emergency pause key'leri, parameter registry'leri). Bunları kimin/ne tarafından ve hangi quorum veya delay altında çağırabildiğini ekleyin.
- Lending, AMM, vault, staking, bridge veya settlement rail işlemlerini yöneten **on-chain protocol logic**. Bu bileşenlerin varsaydığı invariant'ları (oracle fiyatları, collateral oranları, rebalance sıklığı…) belgeleyin.
- Transaction oluşturan **off-chain automation** (market-making bot'ları, CI/CD pipeline'ları, cron job'ları, serverless function'lar). Bunlar çoğu zaman signature talep edebilen API key'leri veya service principal'ları barındırır.
- **Oracle'lar ve data feed'ler** (aggregator bileşimi, quorum, deviation threshold'ları, update sıklığı). Automated risk logic tarafından kullanılan her upstream kaynağı not edin.
- Chain'leri veya custodial stack'leri birbirine bağlayan **bridge'ler ve cross-chain router'lar** (lock/mint contract'ları, relayer'lar, settlement job'ları).

Teslimat: Varlıkların nasıl hareket ettiğini, hareketi kimin yetkilendirdiğini ve hangi external signal'ların business logic'i etkilediğini gösteren bir value-flow diagram.

## 2. Bileşenleri AADAPT davranışlarıyla eşleyin
AADAPT taxonomy'sini her bileşen için somut attack candidate'larına dönüştürün.<sup>[[1]](#references)</sup>

| Bileşen | Birincil AADAPT odağı |
| --- | --- |
| Signing/KMS estate'leri | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracle'lar/feed'ler | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocol'ler | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipeline'ları | Compromised bot/CI identity'leri, batch replay, unauthorized deployment |
| Bridge'ler/router'lar | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Bu eşleme, yalnızca contract'ları değil, değeri dolaylı olarak yönlendirebilen her identity/automation bileşenini test etmenizi sağlar.

## 3. Saldırganın uygulanabilirliği ile business impact'e göre önceliklendirin

1. **Operational weakness'lar**: exposed CI credential'ları, fazla yetkili IAM role'leri, yanlış yapılandırılmış KMS policy'leri, arbitrary signature talep edebilen automation account'ları, bridge config'lerini içeren public bucket'lar vb.
2. **Value-specific weakness'lar**: hassas oracle parameter'ları, multi-party approval olmadan upgrade edilebilen contract'lar, flash-loan'a duyarlı liquidity, timelock'ları bypass eden governance action'ları.

Kuyruğu bir adversary gibi yönetin: bugün başarılı olabilecek operational foothold'larla başlayın, ardından derin protocol/economic manipulation yollarına ilerleyin.<sup>[[1]](#references)</sup>

## 4. Kontrollü ve production-gerçekçi ortamlarda yürütün
- **Forked mainnet'ler / isolated testnet'ler**: flash-loan path'lerinin, oracle drift'lerinin ve bridge flow'larının gerçek fonlara dokunmadan uçtan uca çalışması için bytecode'u, storage'ı ve liquidity'yi çoğaltın.<sup>[[1]](#references)</sup>
- **Blast-radius planning**: bir senaryoyu patlatmadan önce circuit breaker'ları, pausable module'leri, rollback runbook'larını ve yalnızca testte kullanılacak admin key'lerini tanımlayın.
- **Stakeholder coordination**: custodian'ları, oracle operator'larını, bridge partner'larını ve compliance ekiplerini bilgilendirin; böylece monitoring ekipleri trafiği bekler.
- **Legal sign-off**: simülasyonların regulated rail'lere ulaşabileceği durumlarda kapsamı, yetkilendirmeyi ve stop condition'ları belgeleyin.

## 5. AADAPT teknikleriyle hizalanmış telemetry
Her senaryonun kullanılabilir detection verisi üretmesi için telemetry stream'lerini instrument edin.<sup>[[1]](#references)</sup>

- **Chain-level trace'ler**: flash-loan bundle'larını, reentrancy-like structure'ları ve cross-contract hop'larını yeniden oluşturmak için full call graph'lar, gas kullanımı, transaction nonce'ları ve block timestamp'leri.
- **Application/API log'ları**: her on-chain tx'i IP'ler ve auth method'larıyla birlikte bir human veya automation identity'sine (session ID, OAuth client, API key, CI job ID) bağlayın.
- **KMS/HSM log'ları**: her signature için key ID, caller principal, policy sonucu, destination address ve reason code'ları. Change window'ları ve high-risk operation'ları baseline olarak belirleyin.
- **Oracle/feed metadata'sı**: her update için data source bileşimi, bildirilen değer, rolling average'lardan sapma, tetiklenen threshold'lar ve kullanılan failover path'leri.
- **Bridge/swap trace'leri**: chain'ler arasındaki lock/mint/unlock event'lerini correlation ID'ler, chain ID'ler, relayer identity'si ve hop timing ile ilişkilendirin.
- **Anomaly marker'ları**: slippage spike'ları, anormal collateralization ratio'ları, unusual gas density veya cross-chain velocity gibi türetilmiş metric'ler.

Analistlerin observables'ı uygulanan AADAPT tekniğiyle eşleştirebilmesi için her şeyi scenario ID'leri veya synthetic user ID'leriyle etiketleyin.

## 6. Purple-team döngüsü ve maturity metric'leri
1. Senaryoyu kontrollü ortamda çalıştırın ve detection'ları (alert'ler, dashboard'lar, pager'a gönderilen responder bildirimleri) kaydedin.<sup>[[1]](#references)</sup>
2. Her adımı belirli AADAPT teknikleriyle ve chain/app/KMS/oracle/bridge plane'lerinde üretilen observables ile eşleyin.
3. Detection hypothesis'leri (threshold rule'ları, correlation search'leri, invariant check'leri) oluşturup deploy edin.
4. Mean time to detect (MTTD) ve mean time to contain (MTTC) business tolerance'larını karşılayana ve playbook'lar value loss'u güvenilir biçimde durdurana kadar yeniden çalıştırın.

Program maturity'sini üç eksende izleyin:<sup>[[1]](#references)</sup>
- **Visibility**: her kritik value path'in her plane'de telemetry'si bulunması.
- **Coverage**: önceliklendirilen AADAPT tekniklerinin uçtan uca uygulanan oranı.
- **Response**: geri döndürülemez kayıptan önce contract'ları pause etme, key'leri revoke etme veya flow'ları freeze etme becerisi.

Tipik kilometre taşları: (1) tamamlanmış value inventory + AADAPT mapping, (2) detection'ları uygulanmış ilk uçtan uca senaryo, (3) coverage'ı genişleten ve MTTD/MTTC'yi düşüren quarterly purple-team cycle'ları.<sup>[[1]](#references)</sup>

## 7. Senaryo template'leri
AADAPT davranışlarıyla doğrudan eşleşen simülasyonlar tasarlamak için bu tekrarlanabilir blueprint'leri kullanın.<sup>[[1]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: tek bir transaction içinde geçici sermaye borçlanarak AMM fiyatlarını/liquidity'yi bozmak ve geri ödemeden önce yanlış fiyatlandırılmış borrow, liquidation veya mint işlemlerini tetiklemek.
- **Execution**:
1. Target chain'i fork edin ve pool'ları production benzeri liquidity ile seed edin.
2. Flash loan aracılığıyla büyük bir notional borçlanın.
3. Lending, vault veya derivative logic'inin dayandığı price/threshold boundary'lerini aşmak için kalibre edilmiş swap'ler gerçekleştirin.
4. Distortion'ın hemen ardından victim contract'ı çağırın (borrow, liquidate, mint) ve flash loan'u geri ödeyin.
- **Measurement**: Invariant violation başarılı oldu mu? Slippage/price-deviation monitor'ları, circuit breaker'lar veya governance pause hook'ları tetiklendi mi? Analytics'in abnormal gas/call graph pattern'ini işaretlemesi ne kadar sürdü?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: manipulated feed'lerin destructive automated action'ları (mass liquidation, hatalı settlement) tetikleyip tetikleyemeyeceğini belirlemek.
- **Execution**:
1. Fork/testnet üzerinde malicious feed deploy edin veya aggregator weight'lerini/quorum'u/update cadence'i tolerated deviation'ın ötesine taşıyacak şekilde değiştirin.
2. Bağımlı contract'ların poisoned value'ları tüketmesine ve standart logic'lerini çalıştırmasına izin verin.
- **Measurement**: Feed-level out-of-band alert'leri, fallback oracle activation, min/max bound enforcement ve anomaly onset ile operator response arasındaki latency.

### Scenario C – Credential/signing abuse
- **Objective**: tek bir signer'ın veya automation identity'sinin compromise edilmesinin unauthorized upgrade, parameter change veya treasury drain işlemlerini mümkün kılıp kılmadığını test etmek.
- **Execution**:
1. Sensitive signing right'lara sahip identity'leri listeleyin (operator'lar, CI token'ları, KMS/HSM çağıran service account'lar, multisig participant'ları).
2. Compromise'ı simüle edin (credential/key'lerini lab scope içinde yeniden kullanın).
3. Privileged action'ları deneyin: proxy'leri upgrade edin, risk parameter'larını değiştirin, asset mint/pause işlemleri gerçekleştirin veya governance proposal'ları tetikleyin.
- **Measurement**: KMS/HSM log'ları anomaly alert'leri (time-of-day, destination drift, high-risk operation burst'ü) oluşturuyor mu? Policy'ler veya multisig threshold'ları unilateral abuse'u engelleyebiliyor mu? Throttle/rate limit'leri veya additional approval'lar uygulanıyor mu?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: defender'ların bridge'ler, DEX router'lar ve privacy hop'ları arasında hızla launder edilen asset'leri ne kadar iyi trace edip interdict edebildiğini değerlendirmek.
- **Execution**:
1. Common bridge'ler arasında lock/mint operation'larını zincirleyin, her hop'ta swap/mixer işlemlerini araya ekleyin ve hop başına correlation ID'leri koruyun.
2. Monitoring latency'sini zorlamak için transfer'leri hızlandırın (dakikalar/block'lar içinde multi-hop).
- **Measurement**: Telemetry + commercial chain analytics genelinde event'leri correlate etme süresi, yeniden oluşturulan path'in eksiksizliği, gerçek bir incident sırasında freeze için choke point'leri belirleyebilme ve abnormal cross-chain velocity/value için alert fidelity.

## Kaynaklar

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
