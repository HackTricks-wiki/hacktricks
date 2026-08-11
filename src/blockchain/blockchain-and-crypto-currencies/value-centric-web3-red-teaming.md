# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) framework'ü, digital asset sistemlerini hedefleyen adversarial action ve technique'leri kategorilere ayırır.<sup>[[1]](#references)</sup> Bunu bir **threat-modeling omurgası** olarak ele alın: asset mint edebilen, fiyatlandırabilen, authorize edebilen veya yönlendirebilen her component'i enumerate edin, bu touchpoint'leri AADAPT technique'leriyle map edin ve ardından environment'ın geri döndürülemez ekonomik kayba direnip direnemediğini ölçen red-team senaryoları yürütün.

## 1. Inventory value-bearing components
Off-chain olsa bile value state'i etkileyebilen her şeyin bir map'ini oluşturun.<sup>[[2]](#references)</sup>

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, bot'lar veya back-office job'lar tarafından kullanılan signing API'leri). Key ID'lerini, policy'leri, automation identity'lerini ve approval workflow'larını kaydedin.
- Contract'lar için **Admin & upgrade paths** (proxy admin'leri, governance timelock'ları, emergency pause key'leri, parameter registry'leri). Bunları kimin/ne tarafından, hangi quorum veya delay kapsamında çağırabildiğini dahil edin.
- Lending, AMM'ler, vault'lar, staking, bridge'ler veya settlement rail'lerini yöneten **On-chain protocol logic**. Bu logic'in varsaydığı invariant'ları (oracle price'ları, collateral ratio'ları, rebalance cadence'i…) belgeleyin.
- Transaction oluşturan **Off-chain automation** (market-making bot'ları, CI/CD pipeline'ları, cron job'ları, serverless function'lar). Bunlar çoğunlukla signature talep edebilen API key'leri veya service principal'ları barındırır.
- **Oracle'lar & data feed'ler** (aggregator composition, quorum, deviation threshold'ları, update cadence'i). Automated risk logic tarafından güvenilen her upstream'i not edin.
- Chain'leri veya custodial stack'leri birbirine bağlayan **Bridge'ler ve cross-chain router'lar** (lock/mint contract'ları, relayer'lar, settlement job'ları).

Deliverable: asset'lerin nasıl hareket ettiğini, hareketi kimin authorize ettiğini ve hangi external signal'ların business logic'i etkilediğini gösteren bir value-flow diagram.

## 2. Map components to AADAPT behaviors
AADAPT taxonomy'sini her component için somut attack candidate'larına dönüştürün.<sup>[[2]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estate'leri | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracle'lar/feed'ler | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocol'ler | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipeline'ları | Compromised bot/CI identity'leri, batch replay, unauthorized deployment |
| Bridge'ler/router'lar | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Bu mapping, yalnızca contract'ları değil, value'yu dolaylı olarak yönlendirebilen her identity/automation'ı da test etmenizi sağlar.

## 3. Prioritize by attacker feasibility vs. business impact

1. **Operational weaknesses**: exposed CI credential'ları, aşırı yetkili IAM role'leri, yanlış yapılandırılmış KMS policy'leri, arbitrary signature talep edebilen automation account'ları, bridge config'lerini içeren public bucket'lar vb.
2. **Value-specific weaknesses**: kırılgan oracle parameter'ları, multi-party approval olmadan upgradable contract'lar, flash-loan'a duyarlı liquidity, timelock'ları bypass eden governance action'ları.

Queue'yu bir adversary gibi yönetin: bugün başarıya ulaşabilecek operational foothold'larla başlayın, ardından derin protocol/economic manipulation path'lerine ilerleyin.<sup>[[2]](#references)</sup>

## 4. Execute in controlled, production-realistic environments
- **Forked mainnet'ler / isolated testnet'ler**: flash-loan path'lerinin, oracle drift'lerinin ve bridge flow'larının gerçek fonlara dokunmadan uçtan uca çalışabilmesi için bytecode'u, storage'ı ve liquidity'yi yeniden oluşturun.<sup>[[2]](#references)</sup>
- **Blast-radius planning**: bir senaryoyu tetiklemeden önce circuit breaker'ları, pausable module'leri, rollback runbook'larını ve yalnızca testte kullanılacak admin key'lerini tanımlayın.
- **Stakeholder coordination**: custodian'ları, oracle operator'larını, bridge partner'larını ve compliance ekiplerini bilgilendirin; böylece monitoring ekipleri trafiği bekler.
- **Legal sign-off**: simulation'lar regulated rail'lere ulaşabilecekse kapsamı, authorization'ı ve stop condition'ları belgeleyin.

## 5. Telemetry aligned with AADAPT techniques
Her senaryonun uygulanabilir detection data üretmesi için telemetry stream'lerini instrument edin.<sup>[[2]](#references)</sup>

- **Chain-level trace'ler**: flash-loan bundle'larını, reentrancy-like structure'ları ve cross-contract hop'larını yeniden oluşturmak için full call graph'lar, gas kullanımı, transaction nonce'ları ve block timestamp'leri.
- **Application/API log'ları**: her on-chain tx'i IP'ler ve auth method'larıyla birlikte bir human veya automation identity'sine (session ID, OAuth client, API key, CI job ID) bağlayın.
- **KMS/HSM log'ları**: her signature için key ID, caller principal, policy result, destination address ve reason code'ları. Change window'larını ve high-risk operation'ları baseline olarak belirleyin.
- **Oracle/feed metadata'sı**: update başına data source composition, reported value, rolling average'dan deviation, tetiklenen threshold'lar ve kullanılan failover path'leri.
- **Bridge/swap trace'leri**: chain'ler arasındaki lock/mint/unlock event'lerini correlation ID'ler, chain ID'leri, relayer identity'si ve hop timing ile correlate edin.
- **Anomaly marker'ları**: slippage spike'ları, anormal collateralization ratio'ları, sıra dışı gas density veya cross-chain velocity gibi türetilmiş metric'ler.

Analyst'lerin observables'ı uygulanan AADAPT technique'iyle eşleştirebilmesi için her şeyi scenario ID'leri veya synthetic user ID'leriyle tag'leyin.

## 6. Purple-team loop & maturity metrics
1. Senaryoyu controlled environment'ta çalıştırın ve detection'ları (alert'ler, dashboard'lar, page edilen responder'lar) kaydedin.<sup>[[2]](#references)</sup>
2. Her adımı belirli AADAPT technique'leriyle ve chain/app/KMS/oracle/bridge plane'lerinde üretilen observables'la map edin.
3. Detection hypothesis'leri (threshold rule'ları, correlation search'leri, invariant check'leri) oluşturun ve deploy edin.
4. Mean time to detect (MTTD) ve mean time to contain (MTTC) business tolerance'larına ulaşana ve playbook'lar value loss'u güvenilir biçimde durdurana kadar yeniden çalıştırın.

Program maturity'sini üç eksende takip edin:<sup>[[2]](#references)</sup>
- **Visibility**: her critical value path'inde her plane için telemetry bulunması.
- **Coverage**: önceliklendirilen AADAPT technique'lerinin uçtan uca uygulanan oranı.
- **Response**: geri döndürülemez loss gerçekleşmeden contract'ları pause etme, key'leri revoke etme veya flow'ları freeze etme yeteneği.

Tipik milestone'lar: (1) tamamlanmış value inventory + AADAPT mapping, (2) detection'ları implement edilmiş ilk uçtan uca senaryo, (3) coverage'ı genişleten ve MTTD/MTTC'yi düşüren quarterly purple-team cycle'ları.<sup>[[2]](#references)</sup>

## 7. Scenario templates
AADAPT behavior'larına doğrudan map edilen simulation'lar tasarlamak için bu tekrarlanabilir blueprint'leri kullanın.<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: tek bir transaction içinde geçici capital borrow ederek AMM price/liquidity'sini bozmak ve geri ödemeden önce yanlış fiyatlandırılmış borrow, liquidation veya mint işlemlerini tetiklemek.
- **Execution**:
1. Target chain'i fork edin ve pool'ları production-like liquidity ile seed edin.
2. Flash loan üzerinden büyük bir notional borrow edin.
3. Lending, vault veya derivative logic'inin dayandığı price/threshold sınırlarını aşacak şekilde calibrated swap'ler gerçekleştirin.
4. Distortion'ın hemen ardından victim contract'ı invoke edin (borrow, liquidate, mint) ve flash loan'u repay edin.
- **Measurement**: Invariant violation başarılı oldu mu? Slippage/price-deviation monitor'ları, circuit breaker'lar veya governance pause hook'ları tetiklendi mi? Analytics'in anormal gas/call graph pattern'ini flag'lemesi ne kadar sürdü?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: manipulated feed'lerin destructive automated action'ları (mass liquidation'lar, yanlış settlement'lar) tetikleyip tetikleyemediğini belirlemek.
- **Execution**:
1. Fork/testnet'te malicious feed deploy edin veya aggregator weight'lerini/quorum'u/update cadence'ini tolerated deviation'ın dışına çıkacak şekilde ayarlayın.
2. Dependent contract'ların poisoned value'ları tüketmesine ve standard logic'lerini yürütmesine izin verin.
- **Measurement**: Feed-level out-of-band alert'leri, fallback oracle activation'ı, min/max bound enforcement ve anomaly onset ile operator response arasındaki latency.

### Scenario C – Credential/signing abuse
- **Objective**: tek bir signer'ın veya automation identity'sinin compromise edilmesinin unauthorized upgrade'lere, parameter change'lerine veya treasury drain'lerine izin verip vermediğini test etmek.
- **Execution**:
1. Sensitive signing right'lara sahip identity'leri enumerate edin (operator'lar, CI token'ları, KMS/HSM invoke eden service account'lar, multisig participant'ları).
2. Compromise'ı simulate edin (lab scope içinde credential/key'lerini yeniden kullanın).
3. Privileged action'ları deneyin: proxy'leri upgrade edin, risk parameter'larını değiştirin, asset'leri mint/pause edin veya governance proposal'ları tetikleyin.
- **Measurement**: KMS/HSM log'ları anomaly alert'leri üretiyor mu (time-of-day, destination drift, high-risk operation burst'ü)? Policy'ler veya multisig threshold'ları unilateral abuse'u önleyebiliyor mu? Throttle/rate limit'leri veya ek approval'lar enforce ediliyor mu?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: defender'ların bridge'ler, DEX router'ları ve privacy hop'ları üzerinden hızla launder edilen asset'leri ne kadar iyi trace ve interdict edebildiğini değerlendirmek.
- **Execution**:
1. Common bridge'ler arasında lock/mint operation'larını chain edin, her hop'ta swap/mixer'ları interleave edin ve hop başına correlation ID'lerini koruyun.
2. Monitoring latency'sini zorlamak için transfer'leri hızlandırın (dakikalar/block'lar içinde multi-hop).
- **Measurement**: Telemetry + commercial chain analytics üzerinden event'leri correlate etme süresi, yeniden oluşturulan path'in eksiksizliği, gerçek bir incident sırasında freeze için choke point'leri belirleyebilme yeteneği ve anormal cross-chain velocity/value için alert fidelity.

## References

- [1] [Digital Asset'ler için AADAPT(TM) Cyber Threat Framework (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Red Team Roadmap olarak MITRE AADAPT Framework (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
