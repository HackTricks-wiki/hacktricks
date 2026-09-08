# Attribution, Detection and Countermeasures

{{#include ../banners/hacktricks-training.md}}

Attribution-evasion altyapısı, tekil göstergeleri kullan-at hâle getirmek için tasarlanır. Savunmacılar ham kanıtları korumalı, ilişkileri modellemeli ve IP, domain veya persona değişikliğinden sonra da devam eden davranışları aramalıdır.

## Kanıt hiyerarşisi

| Kanıt | Kullanım amacı | Temel sınırlama |
|---|---|---|
| Source IP/ASN/geolocation | görünür çıkış noktasını ve sağlayıcıyı konumlandırmak | çıkış bir relay, NAT veya victim olabilir; geolocation yaklaşık sonuç verir |
| Passive DNS/registration | altyapı geçmişi ve ortak barındırmayı belirlemek | privacy/redaction ve shared hosting boşluklar oluşturur |
| Certificate/TLS/HTTP fingerprint | tekrarlanan deployment'ları kümelendirmek | yaygın yazılımlar ve mimicry false positive oluşturur |
| Flow timing and byte shape | relay aşamalarını ve tekrarlanan beacon'ları ilişkilendirmek | CDN/NAT ve sınırlı görünürlük kesinliği azaltır |
| Endpoint process/identity | bir bağlantının neden gerçekleştiğini açıklamak | edge/IoT üzerinde bulunmayabilir; attacker native tools kullanabilir |
| Cloud/CDN/API audit | tenant'ı ve altyapı üzerindeki kontrolü belirlemek | retention ve provider/legal access değişiklik gösterir |
| Payment/account/device | procurement sürecini bir kişi/kuruluşla ilişkilendirmek | nominee, compromise ve paylaşılan cihazlar dikkate alınmalıdır |
| Seized implant/configuration | anahtarları, peer'leri, controller'ları ve build bağlantılarını ortaya çıkarmak | collection integrity ve seizure zamanı önemlidir |
| Human/physical evidence | dijital olayı bir konum/operator ile ilişkilendirmek | intrusive'dir, jurisdiction'a bağlıdır ve sıkı handling gerektirir |

Hiçbir satır, yüksek güvenilirlikli bir state attribution sonucunu tek başına taşımamalıdır. Birbiriyle yarışan hipotezler kullanın ve her birini yanlışlayacak gözlemi belirtin.

## Minimum telemetri

1. **DNS:** client, question, type, answers, TTL, response code, resolver ve timestamp.
2. **Network flow:** source/destination/port, start/end, packets/bytes, TCP flags ve sensor location.
3. **TLS/HTTP:** görünür olduğunda SNI, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status ve byte count. Hassas full URL'leri koruyun.
4. **Identity:** authentication result, factor/certificate/device, source, application, session ID ve risk decision.
5. **Endpoint:** bağlantıyı başlatan process, parent, user, binary signature/hash ve destination.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface ve flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token ve result.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP ve posture.

Saatleri senkronize edin, orijinal time zone'ları koruyun, NAT/proxy sınırlarını belgeleyin ve 31 günlük bir ORB node'unun ömrünü aşacak kadar geçmiş veriyi saklayın.

## Build an attribution graph

Gözlemleri türü belirtilmiş node'lar ve edge'ler olarak temsil edin:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Yararlı düğümler arasında IP, prefix, ASN, domain, DNS account, certificate/key, JA3/JA4-like fingerprint, HTTP grammar, file/config hash, cloud tenant, API token, email, persona, payment instrument ve physical device bulunur. Her bağlantı `first_seen`, `last_seen`, sensor/source, confidence ve gözlemlenmiş mi yoksa çıkarımsal mı olduğunu içermelidir.

Yalnızca graph yoğunluğu yanıltıcıdır: Bir CDN veya certificate authority, birbiriyle ilgisiz birçok aktörü birbirine bağlar. Aynı API account, SSH key, origin allowlist, benzersiz response body veya control protocol gibi nadir ve operatör tarafından kontrol edilen ilişkileri, yaygın hosting ilişkilerinden daha yüksek ağırlıklandırın.

## ORB ve ele geçirilmiş router arama

### Gözlemlenen bir çıkış noktasından

1. Adresin hosting, residential, mobile, education veya business amacıyla kullanılıp kullanılmadığını belirleyin; residential kaynakları göz ardı etmeyin.
2. Sınırlı bir dönem için geçmiş DNS, services/certificates, open ports ve gözlemlenen scan/exploitation davranışlarını toplayın.
3. Nadir service fingerprint'lerini, controller hedeflerini, certificate materyalini veya rotation zamanlamasını paylaşan eşleri arayın.
4. Olası rolleri sınıflandırın: access, traversal, exit/staging veya administration.
5. Birden fazla ilgisiz intrusion cluster'ın aynı pool'u kullanıp kullanmadığını kontrol edin; multi-tenancy doğrudan actor attribution'ı zayıflatır, ancak ORB hipotezini güçlendirir.
6. Eski IP'ler ortadan kalktıktan sonra role profile ile eşleşen yeni düğümleri izleyin.

### Network owner tarafında

- Yeni Internet-exposed management ve default/legacy authentication için uyarı oluşturun.
- Router/firewall/VPN configuration değişikliklerini ve admin authentication işlemlerini cihaz dışına gönderin.
- Normalde çok az session başlatan infrastructure kaynaklı outbound connection'lar için baseline oluşturun.
- Yeni proxy/listener process'lerini, tunnel'ları, scheduled task'ları, firmware değişikliklerini ve beklenmeyen DNS'i tespit edin.
- Kullanım ömrü sona ermiş cihazları değiştirin; volatile malware'i kaldıran bir reboot, exposure'ı düzeltmez.
- Management işlemlerini authenticated bir administration plane ve bilinen kaynaklarla sınırlandırın.

Mandiant, kısa ömürlü IP blocking işlemleri topology ve lifecycle'ı kapsamadığından ORB infrastructure'ın gelişen bir entity olarak izlenmesini önerir.<sup>[[1]](#references)</sup>

## Fast-flux ve dynamic-DNS analytics

Registered domain ve sliding window temelinde aggregate edin. Uygulanabilir bir score şunları birleştirebilir:
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
Alan adlarını tek bir eşik yerine birden fazla bağımsız özellikle inceleyin. Bir CDN/anti-DDoS izin modeliyle karşılaştırın ve single flux ile double flux'ı ayırt etmek için authoritative name-server rotation'ı kontrol edin. DGA'lar için istemci başına NXDOMAIN burst'lerini, uzunluk/karakter dağılımını, host'lar arasındaki senkronize sorguları ve bunları oluşturan process'i ekleyin. MITRE'nin güncel guidance'ı da benzer şekilde yüksek frekanslı değişiklikleri, düşük TTL'i ve process/network correlation'ı vurgular.<sup>[[2]](#references)</sup>

## Domain-fronting tespiti

Kurumsal endpoint'in veya yetkili bir inspection point'in her iki identity'ye de sahip olduğu durumlarda şunları karşılaştırın:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
SNI ve authority ilgisiz tenant'lara ait olduğunda, process onaylı bir client olmadığında, session periyodik/uzun ömürlü olduğunda ve inner origin nadir görüldüğünde güveni artırın. Empty SNI, otomatik olarak malicious kabul edilmemeli; kaydedilmesi gereken bir özelliktir. ECH, SNI'ı wire üzerinde gizleyebilir; bu nedenle endpoint, DNS ve provider/CDN logları daha önemli hâle gelir. MITRE, hem uyumsuz hem de blank-SNI varyantlarını belgeler.<sup>[[3]](#references)</sup>

## Dead-drop resolver sequence detection

Yüksek sinyalli davranış, blocked domain yerine bir sequence'dir:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Filonun tamamında aynı object path'leri, response hash'lerini, API identifier'larını ve takip eden destination'ları araştırın. Actor bunları düzenleyebileceği veya silebileceği için alınan içeriği koruyun. Gereksiz service API'lerini kısıtlayın ve onaylı application'ların enterprise proxy'leri kullanmasını zorunlu tutun; ancak developer tool'larını ve automation'ı hesaba katın. MITRE, gerçek prosedürlerde GitHub, forumlar, document'lar ve social/web service'leri listeler.<sup>[[4]](#references)</sup>

## Redirector ve yeniden kullanılabilir deployment kümelendirmesi

Domain'ler ve address'ler değişse bile operator'ler çoğu zaman aynı automation'ı yeniden deploy eder. Şu bileşimler üzerinden kümeleyin:

- certificate field'ları/key reuse ve issuance timing;
- TLS version/cipher/extension order ve server behavior;
- identical HTTP status, header order, cache behavior, icon/body ve error page;
- unusual port pair'leri ve redirect chain'leri;
- DNS provider/name-server pattern'i ve TTL schedule;
- deployment time, uptime ve maintenance window;
- back-end origin exposure veya identical allowlist'ler.

Tek bir generic Nginx page'i zayıf kanıttır. Birden fazla nadir ve bağımsız eşleşme ile temporal continuity, infrastructure-cluster hipotezini destekleyebilir.

## Residential proxy ve impossible-session detection

Session identity'sini IP katmanının üzerinde koruyun. Şu tür bileşimleri işaretleyin:

- bir session/device fingerprint, travel'ın izin verdiğinden daha hızlı biçimde country/ASN değiştiriyor;
- bir consumer IP her request'te değişirken cookie'ler ve TLS/browser identity sabit kalıyor;
- iddia edilen local device'ın latency/time-zone/language değerleri exit ile tutarsız;
- bir address, ilgisiz account population'ları dönüşümlü olarak kullanıyor veya backconnect proxy behavior sergiliyor;
- privileged session, organization'ın device certificate'ı olmadan residential access üzerinden görünüyor.

Carrier NAT, accessibility tool'ları, corporate VPN'ler ve seyahat benign anomaly'ler oluşturabilir. Yalnızca “residential proxy” etiketlerine dayanarak geri döndürülemez blocking uygulamak yerine step-up authentication veya investigation isteyin.

## Wireless ve covert-device detection

RADIUS/NAC'i AP ve fiziksel bağlamla birleştirin:

1. ilk kez görülen account–device–AP kombinasyonlarını bulun;
2. managed EAP certificate/posture olmadan kullanılan credential'ları belirleyin;
3. eşzamanlı session'ları ve badge/building presence'ı karşılaştırın;
4. alışılmadık derecede zayıf/edge signal'ı ve AP'ler arasındaki hareketi inceleyin;
5. yakındaki managed endpoint'lerde wireless scanning, yeni etkinleştirilmiş interface bridge/NAT, virtual adapter veya tunnel arayın;
6. yeni switchport, DHCP, USB network ve PoE activity'sini envanterleyin;
7. kanıt bunu desteklediğinde yetkili bir RF/physical sweep gerçekleştirin.

Bu yöntem hem APT28 tarzı nearest-neighbor path'i hem de bir exercise drop'ını yakalar. MAC randomization identity veya guilt olarak değerlendirilmemelidir.

## Financial-attribution detection

- Exact chain, token, address, transaction ve block identifier'larını koruyun.
- Value'yu change, peel chain, fan-out/in, mixer, bridge ve service deposit'leri üzerinden takip ederken heuristic'leri etiketleyin.
- Time, amount minus fee, contract event, liquidity ve destination-chain withdrawal'ı ilişkilendirin.
- Yasal exchange, bridge, merchant, account, device ve delivery record'larını temin edin veya koruyun.
- Geçerli sanctioned entity/address'leri ve ilgili türevlerini applicable program kapsamında tarayın; eski bir static list'e güvenmeyin.
- Privacy-protocol kullanımını wrongdoing kanıtı olarak değil, risk-context girdisi olarak değerlendirin.

FATF'nin red flag'leri açıkça bağlamsaldır: unusual pattern, amount/frequency, geography, source of funds ve anonymity-enhancing service'ler birlikte anlam kazanır.<sup>[[5]](#references)</sup>

## Deception ve canary'ler

Defender'lar, sıradan kullanıcıların kimliğini anonimleştirmeye çalışmadan high-confidence signal'lar oluşturabilir:

- tek bir system'den asla çıkmaması gereken unique credential'lar veya document'lar;
- fake administrative endpoint'ler ve decoy share'ler;
- yalnızca controlled artifact'lara gömülü instrumented DNS name'leri;
- legitimate use'ı olmayan canary cloud key'leri;
- hiçbir managed device'ın sahip olmadığı decoy Wi-Fi identity'si.

Deception'ı dikkatle kapsamlandırın ve yönetin. Canary, defender'ın kendi asset'inin kötüye kullanımını belirlemeli; ilgisiz third-party traffic toplamamalıdır.

## Countermeasure öncelikleri

1. Desteklenmeyen Internet-facing router, VPN ve appliance'ları kaldırın.
2. Internal/wireless access dahil olmak üzere phishing-resistant MFA ve device-bound certificate'ları zorunlu tutun.
3. Yeterince immutable identity, endpoint, DNS, flow, proxy, cloud ve network-device log'larını merkezileştirin.
4. Management ve egress'i kısıtlayın; externally reachable her service'i envanterleyin.
5. Unauthorized asset'lar için DNS, certificate transparency ve cloud configuration'ı izleyin.
6. Process-to-network ve object-level SaaS görünürlüğünü koruyun.
7. Cross-layer investigation'ları ve neighboring-provider coordination'ı uygulamalı olarak test edin.
8. Yalnızca IP blocklist'lerini değil, infrastructure cluster'larını ve behavior'ları takip edin.

## Analytical discipline

Confidence language kullanın:

- **Observed:** sensor/provider record, ilişkiyi doğrudan gösteriyor.
- **Strongly supported:** birden fazla bağımsız gözlem, alternatiflere kıyasla bu görüşü destekliyor.
- **Assessed:** belirtilen varsayımlara ve kanıtlara dayalı inference.
- **Unknown:** eksik görünürlük bir sonuca varılmasını engelliyor.

Her zaman en az iki hipotezi koruyun: actor-operated infrastructure ve compromised/shared intermediary; one actor ve multi-tenant service; deliberate evasion ve legitimate privacy/CDN behavior. Belirsizliği açıklayabilme yeteneği, doğru detection'ın bir parçasıdır.

## References

- [1] [Google Cloud/Mandiant — China-nexus espionage actor'leri ORB network'lerini kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Virtual Asset'ler için Red Flag Indicator'ları](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRC actor'leri compromise gerçekleştiriyor ve persistent access sürdürüyor](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Communications infrastructure için enhanced visibility ve hardening guidance](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
