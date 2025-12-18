# Değer-Odaklı Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrisi, altyapıyı değil dijital değeri manipüle eden saldırgan davranışlarını yakalar. Bunu bir tehdit-modelleme omurgası olarak ele alın: varlık mint edebilen, fiyatlayabilen, yetkilendirebilen veya yönlendirebilen her bileşeni listeleyin, bu temas noktalarını AADAPT tekniklerine eşleyin ve ardından ortamın geri döndürülemeyecek ekonomik kayba karşı direnip direnemeyeceğini ölçen red-team senaryoları tasarlayın.

## 1. Değer-taşıyan bileşenleri envanterleyin
Değer durumunu etkileyebilecek her şeyi, zincir dışı olsa bile, haritalandırın.

- Custodial signing services (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Anahtar ID'lerini, politikaları, otomasyon kimliklerini ve onay iş akışlarını kaydedin.
- Admin & upgrade paths for contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Kimlerin/neyin çağırabileceğini ve hangi çoğunluk veya gecikme altında olduğunu dahil edin.
- On-chain protocol logic handling lending, AMMs, vaults, staking, bridges, or settlement rails. Varsaydıkları invariantları belgeleyin (oracle fiyatları, teminat oranları, rebalance cadences…).
- Off-chain automation that builds transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Bunlar genellikle imza talep edebilen API anahtarları veya service principals tutar.
- Oracles & data feeds (aggregator composition, quorum, deviation thresholds, update cadence). Otomatik risk mantığı tarafından güvenilen her upstream'i not alın.
- Bridges and cross-chain routers (lock/mint contracts, relayers, settlement jobs) zincirleri veya custodial stack'leri birbirine bağlayan.

Teslimat: Varlıkların nasıl hareket ettiğini, kimin hareketi yetkilendirdiğini ve hangi dış sinyallerin iş mantığını etkilediğini gösteren bir değer-akış diyagramı.

## 2. Bileşenleri AADAPT davranışlarına eşleyin
AADAPT taksonomisini bileşen başına somut saldırı adaylarına çevirin.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Bu eşleme, sadece contract'ları değil, dolaylı olarak değeri yönlendirebilecek her kimliği/otomasyonu test etmenizi sağlar.

## 3. Saldırganın yapılabilirliği vs. iş etkisine göre önceliklendirin

1. Operational weaknesses: açığa çıkmış CI credentials, fazla ayrıcalıklı IAM rolleri, yanlış yapılandırılmış KMS politikaları, rastgele imza talep edebilen otomasyon hesapları, bridge konfigürasyonlarına açık public bucket'lar vb.
2. Value-specific weaknesses: kırılgan oracle parametreleri, çok taraflı onay olmadan upgrade edilebilen contract'lar, flash-loan hassas likidite, timelock'ları atlayan governance eylemleri.

Sıralamayı bir saldırgan gibi çalıştırın: bugün başarılı olabilecek operasyonel ayak izleriyle başlayın, sonra derin protokol/ekonomik manipülasyon yollarına ilerleyin.

## 4. Kontrollü, production-gerçekçi ortamlarda yürütün
- Forked mainnets / isolated testnets: bytecode, storage ve likiditeyi çoğaltın ki flash-loan yolları, oracle driftleri ve bridge akışları gerçek fonlara dokunmadan uçtan uca çalışsın.
- Blast-radius planning: bir senaryoyu patlatmadan önce circuit breaker'ları, pausable modülleri, rollback runbook'larını ve yalnızca test için admin anahtarlarını tanımlayın.
- Stakeholder coordination: custodian'lar, oracle operator'ler, bridge partner'ları ve compliance'i bilgilendirin ki onların monitoring ekipleri trafiği beklesin.
- Legal sign-off: simülasyonlar regüle edilmiş rayları aşabilecekse kapsamı, yetkilendirmeyi ve durdurma koşullarını belgeleyin.

## 5. AADAPT teknikleriyle hizalanmış telemetri
Her senaryonun eyleme geçirilebilir tespit verisi üretmesi için telemetri akışlarını instrument edin.

- Chain-level traces: flash-loan paketlerini, reentrancy-benzeri yapıları ve cross-contract hop'ları yeniden oluşturmak için tam çağrı grafikleri, gas kullanımı, transaction nonce'ları, blok zaman damgaları.
- Application/API logs: her on-chain tx'yi bir insan veya otomasyon kimliğiyle (session ID, OAuth client, API key, CI job ID) IP'ler ve auth yöntemleri ile bağlayın.
- KMS/HSM logs: her imza için key ID, caller principal, policy sonucu, destination adres ve reason code'ları. Değişim pencerelerini ve yüksek riskli işlemleri baseline'layın.
- Oracle/feed metadata: update başına veri kaynağı bileşimi, raporlanan değer, rolling average'lardan sapma, tetiklenen threshold'lar ve failover yolları.
- Bridge/swap traces: zincirler arasında lock/mint/unlock event'lerini correlation ID'ler, chain ID'ler, relayer identity ve hop timing ile korele edin.
- Anomaly markers: slippage spike'ları, anormal collateralization oranları, olağandışı gas yoğunluğu veya cross-chain velocity gibi türetilmiş metrikler.

Her şeyi scenario ID'leri veya sentetik kullanıcı ID'leri ile tag'leyin ki analistler gözlemleri çalıştırılan AADAPT tekniği ile hizalayabilsin.

## 6. Purple-team döngüsü & olgunluk metrikleri
1. Senaryoyu kontrollü ortamda çalıştırın ve tespitleri (alert'ler, dashboard'lar, responder'ların çağrılması) yakalayın.
2. Her adımı zincir/app/KMS/oracle/bridge düzlemlerinde üretilen gözlemlerle birlikte belirli AADAPT tekniklerine eşleyin.
3. Tespit hipotezleri oluşturun ve devreye alın (eşik kuralları, korelasyon aramaları, invariant kontrolleri).
4. MTTD ve MTTC iş toleranslarını karşılayana kadar yeniden çalıştırın ve playbook'lar değer kaybını güvenilir şekilde durdurana dek iyileştirin.

Program olgunluğunu üç eksende takip edin:
- Visibility: her kritik değer yolunun her düzlemde telemetriye sahip olması.
- Coverage: önceliklendirilen AADAPT tekniklerinin uçtan uca ne oranda tatbik edildiği.
- Response: irreversible kayıp olmadan önce contract'ları pause etme, anahtarları iptal etme veya akışları dondurma yeteneği.

Tipik kilometre taşları: (1) tamamlanmış değer envanteri + AADAPT eşlemesi, (2) tespitlerle ilk uçtan uca senaryo, (3) kapsama alanını genişleten ve MTTD/MTTC'yi düşüren üç aylık purple-team döngüleri.

## 7. Senaryo şablonları
AADAPT davranışlarına doğrudan eşlenen simülasyonlar tasarlamak için bu tekrarlanabilir blueprint'leri kullanın.

### Scenario A – Flash-loan economic manipulation
- Objective: borrow transient capital inside one transaction to distort AMM prices/liquidity and trigger mispriced borrows, liquidations, or mints before repaying.
- Execution:
1. Fork the target chain and seed pools with production-like liquidity.
2. Borrow large notional via flash loan.
3. Perform calibrated swaps to cross price/threshold boundaries relied on by lending, vault, or derivative logic.
4. Invoke the victim contract immediately after the distortion (borrow, liquidate, mint) and repay the flash loan.
- Measurement: Invariant ihlali başarılı oldu mu? Slippage/price-deviation monitörleri, circuit breaker'lar veya governance pause hook'ları tetiklendi mi? Analitiklerin anormal gas/çağrı grafiği desenini ne kadar sürede işaretlediği?

### Scenario B – Oracle/data-feed poisoning
- Objective: determine whether manipulated feeds can trigger destructive automated actions (mass liquidations, incorrect settlements).
- Execution:
1. In the fork/testnet, deploy a malicious feed or adjust aggregator weights/quorum/update cadence beyond tolerated deviation.
2. Let dependent contracts consume the poisoned values and execute their standard logic.
- Measurement: Feed seviyesinde out-of-band alert'ler, fallback oracle activation, min/max bound enforcement ve anomali başlangıcı ile operator yanıtı arasındaki gecikme.

### Scenario C – Credential/signing abuse
- Objective: test whether compromising a single signer or automation identity enables unauthorized upgrades, parameter changes, or treasury drains.
- Execution:
1. Enumerate identities with sensitive signing rights (operators, CI tokens, service accounts invoking KMS/HSM, multisig participants).
2. Simulate compromise (re-use their credentials/keys within the lab scope).
3. Attempt privileged actions: upgrade proxies, change risk parameters, mint/pause assets, or trigger governance proposals.
- Measurement: KMS/HSM log'ları anomaly alert'leri (time-of-day, destination drift, burst of high-risk operations) yükseltiyor mu? Politika veya multisig eşikleri tek taraflı suistimali engelleyebiliyor mu? Throttle'lar/rate limit'ler veya ek onaylar uygulanıyor mu?

### Scenario D – Cross-chain evasion & traceability gaps
- Objective: evaluate how well defenders can trace and interdict assets rapidly laundered across bridges, DEX routers, and privacy hops.
- Execution:
1. Chain together lock/mint operations across common bridges, interleave swaps/mixers on each hop, and maintain per-hop correlation IDs.
2. Accelerate transfers to stress monitoring latency (multi-hop within minutes/blocks).
- Measurement: Telemetri + commercial chain analytics arasında olayları korelasyonlamak için geçen süre, yeniden inşa edilen yolun tamlığı, gerçek bir olayda dondurmak için tanımlanabilecek choke point'lerin tespiti ve anormal cross-chain velocity/value için alert doğruluğu.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
