# Attribution, Tespit ve Karşı Önlemler

Attribution-evasion altyapısı, bireysel göstergeleri kullanılabilir olmaktan çıkaracak şekilde tasarlanır. Savunmacılar ham kanıtları korumalı, ilişkileri modellemeli ve IP, domain veya persona değişikliğinden sonra da devam eden davranışları aramalıdır.

## Kanıt hiyerarşisi

| Kanıt | Kullanışlı olduğu alan | Temel sınırlama |
|---|---|---|
| Kaynak IP/ASN/jeolokasyon | görünen çıkış noktasını ve sağlayıcıyı konumlandırma | çıkış noktası bir relay, NAT veya kurban olabilir; jeolokasyon yaklaşık sonuç verir |
| Pasif DNS/kayıt | altyapı geçmişi ve ortak barındırma | privacy/redaction ve paylaşımlı hosting boşluklar oluşturur |
| Certificate/TLS/HTTP fingerprint | tekrarlanan deployment'ları kümelendirme | yaygın software ve taklit, false positive oluşturur |
| Akış zamanlaması ve byte yapısı | relay aşamalarını ve tekrarlanan beacon'ları ilişkilendirme | CDN/NAT ve sınırlı görünürlük kesinliği azaltır |
| Endpoint process/identity | bir bağlantının neden gerçekleştiğini açıklama | edge/IoT üzerinde bulunmayabilir; attacker native tools kullanabilir |
| Cloud/CDN/API audit | tenant'ı ve altyapı kontrolünü belirleme | saklama süreleri ve provider/legal erişimi değişiklik gösterir |
| Payment/account/device | procurement'ı bir kişi/varlıkla ilişkilendirme | nominee, compromise ve paylaşımlı cihazlar dikkate alınmalıdır |
| Ele geçirilmiş implant/configuration | key'leri, peer'leri, controller'ları ve build bağlantılarını ortaya çıkarma | toplama bütünlüğü ve ele geçirme zamanı önemlidir |
| İnsan/fiziksel kanıt | dijital olayı bir konum/operator ile ilişkilendirme | müdahalecidir, yargı alanına bağlıdır ve sıkı işlem gerektirir |

Hiçbir satır, yüksek güvenilirlikli bir state attribution sonucunu tek başına desteklememelidir. Birbiriyle yarışan hipotezler kullanın ve her birini yanlışlayacak gözlemi belirtin.

## Minimum telemetry

1. **DNS:** client, question, type, answers, TTL, response code, resolver ve timestamp.
2. **Network flow:** source/destination/port, start/end, packets/bytes, TCP flags ve sensor location.
3. **TLS/HTTP:** görünür olduğunda SNI, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status ve byte count. Hassas full URL'leri koruyun.
4. **Identity:** authentication result, factor/certificate/device, source, application, session ID ve risk decision.
5. **Endpoint:** initiating process, parent, user, binary signature/hash ve destination.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface ve flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token ve result.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP ve posture.

Clock'ları senkronize edin, original time zone'ları koruyun, NAT/proxy sınırlarını belgeleyin ve 31 günlük bir ORB node'un ömrünü aşacak kadar geçmiş veriyi saklayın.

## Bir attribution graph oluşturma

Gözlemleri, türleri belirtilmiş düğümler ve edge'ler olarak temsil edin:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Kullanışlı düğümler arasında IP, prefix, ASN, domain, DNS account, certificate/key, JA3/JA4-like fingerprint, HTTP grammar, file/config hash, cloud tenant, API token, email, persona, payment instrument ve physical device bulunur. Her edge için `first_seen`, `last_seen`, sensor/source, confidence ve bunun observed mı yoksa inferred mı olduğu belirtilmelidir.

Tek başına graph density yanıltıcıdır: Bir CDN veya certificate authority, birbiriyle ilgisiz birçok aktörü birbirine bağlar. Aynı API account, SSH key, origin allowlist, benzersiz response body veya control protocol gibi nadir ve operator-controlled ilişkileri, yaygın hosting ilişkilerinden daha yüksek ağırlıklandırın.

## ORB ve compromised-router hunting

### Gözlemlenen bir exit üzerinden

1. Adresin hosting, residential, mobile, education veya business olup olmadığını belirleyin; residential kaynakları göz ardı etmeyin.
2. Sınırlı bir dönem için historical DNS, services/certificates, open ports ve gözlemlenen scan/exploitation behavior verilerini toplayın.
3. Nadir service fingerprint'lerini, controller destination'larını, certificate material'ını veya rotation timing'ini paylaşan peer'leri arayın.
4. Olası rolleri sınıflandırın: access, traversal, exit/staging veya administration.
5. Birden fazla ilgisiz intrusion cluster'ın aynı pool'u kullanıp kullanmadığını kontrol edin; multi-tenancy doğrudan actor attribution'ını zayıflatır, ancak ORB hipotezini güçlendirir.
6. Eski IP'ler ortadan kaybolduktan sonra role profile ile eşleşen yeni node'ları izleyin.

### Network owner tarafında

- Yeni Internet-exposed management ve default/legacy authentication için alert oluşturun.
- Router/firewall/VPN configuration değişikliklerini ve admin authentication işlemlerini cihaz dışına gönderin.
- Normalde çok az session başlatan infrastructure'dan yapılan outbound connection'lar için baseline oluşturun.
- Yeni proxy/listener process'lerini, tunnel'ları, scheduled task'ları, firmware değişikliklerini ve beklenmeyen DNS'i tespit edin.
- End-of-life cihazları değiştirin; volatile malware'ı kaldıran bir reboot, exposure'ı düzeltmez.
- Management işlemlerini authenticated administration plane ve bilinen source'larla sınırlandırın.

Mandiant, kısa ömürlü IP blocking topology ve lifecycle'ı yakalayamadığından, ORB infrastructure'ının gelişen bir entity olarak izlenmesini önerir.<sup>[[1]](#references)</sup>

## Fast-flux ve dynamic-DNS analitiği

Registered domain ve sliding window üzerinden aggregation yapın. Kullanışlı bir score şunları birleştirebilir:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Alanları tek bir eşik yerine birden fazla bağımsız özellikle araştırın. Bir CDN/anti-DDoS allow-model ile karşılaştırın ve single flux ile double flux'ı ayırt etmek için authoritative name-server rotation'ı kontrol edin. DGA'lar için client başına NXDOMAIN burst'lerini, uzunluk/karakter dağılımını, host'lar arasındaki senkronize sorguları ve bunları oluşturan process'i ekleyin. MITRE'ın güncel guidance'ı da benzer şekilde yüksek frekanslı değişiklikleri, düşük TTL'i ve process/network correlation'ı vurgular.<sup>[[2]](#references)</sup>

## Domain-fronting tespiti

Enterprise endpoint'i veya yetkili bir inspection point her iki identity'ye de sahipse şunları karşılaştırın:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
SNI ve authority ilgisiz tenant'lara ait olduğunda, process onaylı bir client olmadığında, session periyodik/uzun ömürlü olduğunda ve iç origin nadir görüldüğünde güven düzeyini artırın. Boş SNI, otomatik olarak malicious kabul edilmemeli; kaydedilmesi gereken bir özelliktir. ECH, SNI'ı wire üzerinde gizleyebilir; bu nedenle endpoint, DNS ve provider/CDN log'ları daha önemli hale gelir. MITRE, hem uyumsuz hem de boş-SNI varyantlarını belgeler.<sup>[[3]](#references)</sup>

## Dead-drop resolver sequence detection

Yüksek sinyalli davranış, engellenmiş bir domain değil, bir sequence'dir:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Fleet genelinde aynı object path'leri, response hash'lerini, API identifier'larını ve follow-on destination'ları araştırın. Actor bunları düzenleyebileceği veya silebileceği için alınan içeriği koruyun. Gereksiz service API'lerini kısıtlayın ve approved application'ların enterprise proxy'leri kullanmasını zorunlu tutun; ancak developer tools ve automation'ı hesaba katın. MITRE, gerçek prosedürlerde GitHub, forumlar, documents ve social/web services'ı listeler.<sup>[[4]](#references)</sup>

## Redirector ve yeniden kullanılabilir deployment clustering

Domain'ler ve adresler değişse bile operator'ler genellikle aynı automation'ı yeniden deploy eder. Şu kombinasyonlar üzerinden cluster oluşturun:

- certificate field'ları/key reuse ve issuance timing;
- TLS version/cipher/extension order ve server behavior;
- aynı HTTP status, header order, cache behavior, icon/body ve error page;
- unusual port pair'leri ve redirect chain'leri;
- DNS provider/name-server pattern'i ve TTL schedule'ı;
- deployment time, uptime ve maintenance window;
- back-end origin exposure veya aynı allowlist'ler.

Tek bir generic Nginx page zayıf bir kanıttır. Birbirinden bağımsız birkaç nadir eşleşme ve temporal continuity, infrastructure-cluster hipotezini destekleyebilir.

## Residential proxy ve impossible-session detection

Session identity'sini IP layer'ının üzerinde koruyun. Şu kombinasyonları flag'leyin:

- tek bir session/device fingerprint, travel'ın izin verdiğinden daha hızlı şekilde country/ASN değiştiriyor;
- consumer IP her request'te değişirken cookie'ler ve TLS/browser identity sabit kalıyor;
- claimed local device, exit ile uyumsuz latency/time-zone/language sergiliyor;
- bir address, ilgisiz account population'ları dönüşümlü olarak kullanıyor veya backconnect proxy behavior gösteriyor;
- privileged session, organization's device certificate'ı olmadan residential access üzerinden görünüyor.

Carrier NAT, accessibility tools, corporate VPN'ler ve travel benign anomaly'ler oluşturabilir. Yalnızca “residential proxy” label'larına dayanarak irreversible blocking uygulamak yerine step-up authentication veya investigation gerektirin.

## Wireless ve covert-device detection

RADIUS/NAC'i AP ve physical context ile birleştirin:

1. ilk kez görülen account-device-AP kombinasyonlarını bulun;
2. managed EAP certificate/posture olmadan kullanılan credential'ları belirleyin;
3. eşzamanlı session'ları ve badge/building presence'ı karşılaştırın;
4. olağandışı zayıf/edge signal'ı ve AP'ler arasındaki hareketi inceleyin;
5. yakındaki managed endpoint'lerde wireless scanning, newly enabled interface bridge/NAT, virtual adapter veya tunnel arayın;
6. yeni switchport, DHCP, USB network ve PoE activity'yi inventory'ye alın;
7. kanıtlar desteklediğinde authorized RF/physical sweep gerçekleştirin.

Bu, hem APT28-style nearest-neighbor path'ini hem de bir exercise drop'u yakalar. MAC randomization identity veya guilt olarak değerlendirilmemelidir.

## Financial-attribution detection

- Exact chain, token, address, transaction ve block identifier'larını koruyun.
- Value'yu change, peel chain'leri, fan-out/in, mixer'lar, bridge'ler ve service deposit'leri üzerinden takip ederken heuristic'leri label'layın.
- Zamanı, fee'ler çıkarılmış amount'u, contract event'i, liquidity'yi ve destination-chain withdrawal'ı correlate edin.
- Lawful exchange, bridge, merchant, account, device ve delivery record'larını edinin veya koruyun.
- Applicable program kapsamındaki güncel sanctioned entity/address'leri ve türevlerini screen edin; eski static list'e güvenmeyin.
- Privacy-protocol kullanımını wrongdoing kanıtı olarak değil, risk-context girdisi olarak değerlendirin.

FATF'nin red flag'leri açıkça context'e bağlıdır: unusual pattern, amount/frequency, geography, source of funds ve anonymity-enhancing services birlikte anlamlı hale gelir.<sup>[[5]](#references)</sup>

## Deception ve canary'ler

Defender'lar, sıradan kullanıcıların kimliğini açığa çıkarmaya çalışmadan high-confidence signal'lar oluşturabilir:

- tek bir system'den asla çıkmaması gereken unique credential veya document'lar;
- fake administrative endpoint'ler ve decoy share'ler;
- yalnızca controlled artifact'lara gömülmüş instrumented DNS name'leri;
- meşru kullanımı olmayan canary cloud key'leri;
- hiçbir managed device'ın sahip olmadığı decoy Wi-Fi identity'si.

Deception'ı dikkatle scope'layın ve yönetin. Canary, defender'ın kendi asset'inin misuse edilmesini belirlemeli; ilgisiz third-party traffic toplamamalıdır.

## Countermeasure öncelikleri

1. Desteklenmeyen Internet-facing router'ları, VPN'leri ve appliance'ları kaldırın.
2. Internal/wireless access dahil olmak üzere phishing-resistant MFA ve device-bound certificate'ları zorunlu tutun.
3. Yeterince immutable identity, endpoint, DNS, flow, proxy, cloud ve network-device log'larını merkezileştirin.
4. Management ve egress'i kısıtlayın; externally reachable her service'i inventory'ye alın.
5. Unauthorized asset'lar için DNS, certificate transparency ve cloud configuration'ı monitor edin.
6. Process-to-network ve object-level SaaS visibility'yi koruyun.
7. Cross-layer investigation'ları ve neighboring-provider coordination'ı exercise edin.
8. Yalnızca IP blocklist'lerini değil, infrastructure cluster'larını ve behavior'ları takip edin.

## Analytical discipline

Confidence language kullanın:

- **Observed:** sensor/provider record ilişkiyi doğrudan gösteriyor.
- **Strongly supported:** birden fazla bağımsız observation, alternatiflere kıyasla bu seçeneği destekliyor.
- **Assessed:** belirtilen assumption'lar ve evidence'a dayalı inference.
- **Unknown:** eksik visibility bir sonuca varılmasını engelliyor.

Her zaman en az iki hypothesis bulundurun: actor-operated infrastructure ile compromised/shared intermediary; one actor ile multi-tenant service; deliberate evasion ile legitimate privacy/CDN behavior. Uncertainty'yi açıklayabilme becerisi doğru detection'ın bir parçasıdır.

## References

- [1] [Google Cloud/Mandiant — China-nexus espionage actor'ler ORB network'lerini kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Virtual Asset'ler için Red Flag Indicator'leri](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRC actor'leri compromise ediyor ve persistent access'ı sürdürüyor](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Communications infrastructure için enhanced visibility ve hardening guidance](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
