# Değer Odaklı Web3 Red Teaming (MITRE AADAPT)

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) framework'ü, dijital asset sistemlerini hedefleyen adversarial action ve technique'leri kategorize eder.<sup>[[1]](#references)</sup> Bunu bir **threat-modeling omurgası** olarak ele alın: asset mint edebilen, fiyatlayabilen, yetkilendirebilen veya yönlendirebilen her component'i listeleyin, bu touchpoint'leri AADAPT technique'leriyle eşleyin ve ardından environment'ın geri döndürülemez ekonomik kayba direnip direnemediğini ölçen red-team senaryoları çalıştırın.

## 1. Değer taşıyan component'lerin envanterini çıkarın
Off-chain olsa bile value state'i etkileyebilen her şeyin bir haritasını oluşturun.<sup>[[2]](#references)</sup>

- **Custodial signing service'leri** (HSM/KMS cluster'ları, Vault/KMaaS, bot'lar veya back-office job'ları tarafından kullanılan signing API'leri). Key ID'lerini, policy'leri, automation identity'lerini ve approval workflow'larını kaydedin.
- Contract'lar için **admin ve upgrade path'leri** (proxy admin'leri, governance timelock'ları, emergency pause key'leri, parameter registry'leri). Bunları kimin/ne tarafından, hangi quorum veya delay altında çağırabildiğini dahil edin.
- Lending, AMM, vault, staking, bridge veya settlement rail'lerini işleyen **on-chain protocol logic'i**. Bunların varsaydığı invariant'ları belgeleyin (oracle price'ları, collateral ratio'ları, rebalance sıklığı…).
- Transaction oluşturan **off-chain automation** (market-making bot'ları, CI/CD pipeline'ları, cron job'ları, serverless function'lar). Bunlar çoğunlukla signature talep edebilen API key'leri veya service principal'ları barındırır.
- **Oracle'lar ve data feed'ler** (aggregator composition, quorum, deviation threshold'ları, update sıklığı). Automated risk logic tarafından güvenilen her upstream'i not edin.
- Chain'leri veya custodial stack'lerini birbirine bağlayan **bridge'ler ve cross-chain router'lar** (lock/mint contract'ları, relayer'lar, settlement job'ları).

Çıktı: Asset'lerin nasıl hareket ettiğini, hareketi kimin authorize ettiğini ve business logic'i hangi external signal'ların etkilediğini gösteren bir value-flow diagram.

## 2. Component'leri AADAPT behavior'larına eşleyin
AADAPT taxonomy'sini her component için somut attack candidate'larına dönüştürün.<sup>[[2]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estate'leri | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracle/feed'ler | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocol'ler | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipeline'ları | Compromised bot/CI identity'leri, batch replay, unauthorized deployment |
| Bridge/router'lar | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Bu mapping, yalnızca contract'ları değil, value'yu dolaylı olarak yönlendirebilen her identity/automation'ı da test etmenizi sağlar.

## 3. Attacker feasibility ve business impact'e göre önceliklendirin

1. **Operational weakness'lar**: exposed CI credential'ları, aşırı yetkili IAM role'leri, yanlış yapılandırılmış KMS policy'leri, arbitrary signature talep edebilen automation account'ları, bridge config'lerini içeren public bucket'lar vb.
2. **Value-specific weakness'lar**: hassas oracle parameter'ları, multi-party approval olmadan upgradable contract'lar, flash-loan'a duyarlı liquidity, timelock'ları bypass eden governance action'ları.

Kuyruğu bir adversary gibi çalıştırın: bugün başarıya ulaşabilecek operational foothold'larla başlayın, ardından derin protocol/economic manipulation path'lerine ilerleyin.<sup>[[2]](#references)</sup>

## 4. Kontrollü ve production-gerçekçi environment'larda çalıştırın
- **Fork edilmiş mainnet'ler / izole testnet'ler**: Flash-loan path'lerinin, oracle drift'lerinin ve bridge flow'larının gerçek fonlara dokunmadan uçtan uca çalışması için bytecode'u, storage'ı ve liquidity'yi kopyalayın.<sup>[[2]](#references)</sup>
- **Blast radius planlaması**: Bir senaryoyu tetiklemeden önce circuit breaker'ları, pausable module'leri, rollback runbook'larını ve yalnızca test için kullanılan admin key'lerini tanımlayın.
- **Stakeholder koordinasyonu**: Custodian'ları, oracle operator'larını, bridge partner'larını ve compliance ekiplerini bilgilendirin; böylece monitoring ekipleri trafiği bekler.
- **Legal sign-off**: Simülasyonlar regulated rail'lere geçebilecekse scope'u, authorization'ı ve stop condition'ları belgeleyin.

## 5. AADAPT technique'leriyle uyumlu telemetry
Her senaryonun uygulanabilir detection verisi üretmesi için telemetry stream'lerini instrument edin.<sup>[[2]](#references)</sup>

- **Chain-level trace'ler**: Flash-loan bundle'larını, reentrancy-like structure'ları ve cross-contract hop'larını yeniden oluşturmak için full call graph'ları, gas kullanımını, transaction nonce'larını ve block timestamp'lerini toplayın.
- **Application/API log'ları**: Her on-chain tx'i IP'ler ve auth method'larıyla birlikte bir human veya automation identity'sine (session ID, OAuth client, API key, CI job ID) bağlayın.
- **KMS/HSM log'ları**: Her signature için key ID, caller principal, policy sonucu, destination address ve reason code'larını kaydedin. Change window'ları ve high-risk operation'ları baseline olarak belirleyin.
- **Oracle/feed metadata'sı**: Her update için data source composition'ını, reported value'yu, rolling average'lardan sapmayı, tetiklenen threshold'ları ve kullanılan failover path'lerini kaydedin.
- **Bridge/swap trace'leri**: Chain'ler arasındaki lock/mint/unlock event'lerini correlation ID'ler, chain ID'ler, relayer identity'si ve hop timing ile ilişkilendirin.
- **Anomaly marker'ları**: Slippage spike'ları, anormal collateralization ratio'ları, unusual gas density veya cross-chain velocity gibi türetilmiş metric'ler.

Analyst'lerin observables'ları uygulanan AADAPT technique'iyle eşleyebilmesi için her şeyi scenario ID'leri veya synthetic user ID'leriyle tag'leyin.

## 6. Purple-team loop ve maturity metric'leri
1. Senaryoyu kontrollü environment'ta çalıştırın ve detection'ları (alert'ler, dashboard'lar, page edilen responder'lar) kaydedin.<sup>[[2]](#references)</sup>
2. Her adımı, ilgili AADAPT technique'lerine ve chain/app/KMS/oracle/bridge plane'lerinde üretilen observables'lara eşleyin.
3. Detection hypothesis'leri (threshold rule'ları, correlation search'leri, invariant check'leri) oluşturup deploy edin.
4. Mean time to detect (MTTD) ve mean time to contain (MTTC) business tolerance'larını karşılayana ve playbook'lar value loss'u güvenilir şekilde durdurana kadar yeniden çalıştırın.

Program maturity'sini üç eksende takip edin:<sup>[[2]](#references)</sup>
- **Visibility**: Her critical value path'in her plane'de telemetry'si bulunur.
- **Coverage**: Önceliklendirilmiş AADAPT technique'lerinin uçtan uca uygulanan oranı.
- **Response**: Geri döndürülemez kayıptan önce contract'ları pause etme, key'leri revoke etme veya flow'ları freeze etme yeteneği.

Tipik milestones: (1) tamamlanmış value inventory + AADAPT mapping, (2) detection'ların implement edildiği ilk uçtan uca senaryo, (3) coverage'ı artıran ve MTTD/MTTC'yi düşüren quarterly purple-team cycle'ları.<sup>[[2]](#references)</sup>

## 7. Scenario template'leri
AADAPT behavior'larına doğrudan eşlenen simülasyonlar tasarlamak için bu tekrarlanabilir blueprint'leri kullanın.<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: Tek bir transaction içinde geçici sermaye borçlanarak AMM price'larını/liquidity'sini bozmak ve geri ödemeden önce yanlış fiyatlandırılmış borrow, liquidation veya mint işlemlerini tetiklemek.
- **Execution**:
1. Hedef chain'i fork edin ve pool'ları production benzeri liquidity ile seed edin.
2. Flash loan üzerinden büyük bir notional borçlanın.
3. Lending, vault veya derivative logic'inin dayandığı price/threshold sınırlarını aşacak şekilde calibrated swap'ler gerçekleştirin.
4. Distortion'ın hemen ardından victim contract'ı invoke edin (borrow, liquidate, mint) ve flash loan'u geri ödeyin.
- **Measurement**: Invariant violation başarılı oldu mu? Slippage/price-deviation monitor'ları, circuit breaker'lar veya governance pause hook'ları tetiklendi mi? Analytics'in anormal gas/call graph pattern'ını flag'lemesi ne kadar sürdü?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: Manipulated feed'lerin destructive automated action'ları (mass liquidation, yanlış settlement) tetikleyip tetikleyemeyeceğini belirlemek.
- **Execution**:
1. Fork/testnet'te malicious feed deploy edin veya aggregator weight'lerini/quorum'u/update sıklığını tolere edilen deviation'ın dışına çıkaracak şekilde ayarlayın.
2. Dependent contract'ların poisoned value'ları tüketmesine ve standart logic'lerini çalıştırmasına izin verin.
- **Measurement**: Feed-level out-of-band alert'ler, fallback oracle activation'ı, min/max bound enforcement'ı ve anomaly başlangıcı ile operator response arasındaki latency.

### Scenario C – Credential/signing abuse
- **Objective**: Tek bir signer'ın veya automation identity'sinin compromise edilmesinin unauthorized upgrade, parameter change veya treasury drain işlemlerini mümkün kılıp kılmadığını test etmek.
- **Execution**:
1. Sensitive signing right'larına sahip identity'leri listeleyin (operator'lar, CI token'ları, KMS/HSM çağıran service account'lar, multisig participant'ları).
2. Compromise'ı simüle edin (credential/key'lerini lab scope'u içinde yeniden kullanın).
3. Privileged action'ları deneyin: proxy'leri upgrade edin, risk parameter'larını değiştirin, asset'leri mint/pause edin veya governance proposal'larını tetikleyin.
- **Measurement**: KMS/HSM log'ları anomaly alert'i oluşturuyor mu (time-of-day, destination drift, high-risk operation burst'ü)? Policy'ler veya multisig threshold'ları unilateral abuse'u önleyebiliyor mu? Throttle/rate limit'ler veya additional approval'lar uygulanıyor mu?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: Defender'ların bridge'ler, DEX router'lar ve privacy hop'ları üzerinden hızla launder edilen asset'leri ne kadar iyi trace edip engelleyebildiğini değerlendirmek.
- **Execution**:
1. Common bridge'ler arasında lock/mint operation'larını zincirleyin, her hop'ta swap/mixer'ları araya ekleyin ve hop başına correlation ID'lerini koruyun.
2. Monitoring latency'sini zorlamak için transfer'leri hızlandırın (dakikalar/block'lar içinde multi-hop).
- **Measurement**: Telemetry ve commercial chain analytics genelinde event'leri correlate etme süresi, yeniden oluşturulan path'in eksiksizliği, gerçek bir incident'ta freeze için choke point'leri belirleyebilme ve anormal cross-chain velocity/value için alert fidelity.

## References

- [1] [Dijital Asset'ler için AADAPT(TM) Cyber Threat Framework (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Red Team Roadmap olarak MITRE AADAPT Framework'ü (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
