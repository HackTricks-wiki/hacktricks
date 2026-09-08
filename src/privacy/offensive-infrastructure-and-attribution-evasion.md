# Offensive Infrastructure ve Attribution Evasion

Bir operator, tek bir proxy üzerinden nadiren anlamlı bir anonimlik elde eder. Gerçek kampanyalar bir **separation graph** oluşturur: operator bir access node'a ulaşır, traversal node'ları bu node'u exit'ten gizler, redirector'lar gerçek C2'yi korur ve disposable name'ler public edge'i işaret eder.

Her yolun normalize edilmiş artılar/eksiler/deployment/detection görünümü için [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) sayfasını kullanın. Bu sayfa adversarial infrastructure composition konusunu daha derinlemesine ele alır.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Bir hedef tarafından görülen son adres bu nedenle bir yolun kanıtıdır; klavyeyi kimin kontrol ettiğinin kanıtı değildir. MITRE, başlıca bileşenleri Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) ve Web Service (T1102) ile eşleştirir.<sup>[[1]](#references)</sup>

## Altyapı sınıfları

| Sınıf | Bir aktör bunu neden kullanır | Kalıcı maruziyet | Defender'ın en iyi pivot noktası |
|---|---|---|---|
| Kiralanmış VPS/cloud | Hızlı, öngörülebilir, yönlendirilebilir ve yeniden kurulması kolay | tenant, faturalandırma, console, source-login ve image geçmişi | account/control-plane olayları ve tekrarlanan server fingerprint |
| Commercial VPN/Tor | Büyük paylaşımlı çıkış kümesi; server administration gerektirmez | provider/guard görünürlüğü ve uçtan uca zamanlama | hedef davranışı, endpoint kanıtı ve flow korelasyonu |
| Residential/mobile proxy | Tüketici ASN'i ve coğrafi makullük | broker/customer kayıtları; proxyware veya infected-host davranışı | impossible travel, proxy protokolleri ve oturum bazında adres değişimi |
| Compromised server/router/IoT | Mağdurun itibarını ve yargı alanını ödünç alır | implant, management flow ve tekrarlanan upstream controller | tek bir exit IP yerine device telemetry ve ORB topology |
| CDN/redirector | Public edge'i back-end C2'den ayırır | TLS/HTTP grammar, certificate, routing ve cloud-account artifacts | edge-to-origin korelasyonu ve request-shape clustering |
| Legitimate web service | İzin verilen GitHub/cloud/social trafiğine karışır | API token, tenant/object identifiers ve unusual process lineage | endpoint process ile service/API semantics |
| Physical/cellular/satellite path | Görünen fiziksel kaynağı değiştirir | RF, carrier, subscriber, device ve location kayıtları | radio/physical ve network kanıtlarının birleştirilmesi |

## Operational relay box ağları

Bir **ORB network**, intermediate service olarak kullanılan, yönetilen bir proxy filosudur. Mandiant bunları, kiralanmış server'lardan oluşan provisioned network'ler, compromised router/IoT'lardan oluşan non-provisioned network'ler ve hybrid'ler olarak ayırır. Olgun bir topology dört mantıksal role sahiptir:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** Inventory, credentials, health ve routing policy'yi yönetir.
2. **Access/relay node:** Customer veya operator'leri authenticate eder; değişen bir mesh'e yönelik stable entry noktasıdır.
3. **Traversal nodes:** Bir veya daha fazla kiralanmış ya da compromised system, opaque connection'ları relay eder.
4. **Exit/staging node:** Reconnaissance, exploitation veya C2 target'larına son source address'i sunar.

Mesh, exit'leri ülkeye, ASN'e, latency'ye veya availability'ye göre seçebilir ve unhealthy node'ları rotate edebilir. Birden fazla threat group aynı network'ü kiralayabilir. Mandiant, bir IPv4 address'in bazı ORB'lerle yalnızca 31 gün boyunca ilişkili kaldığını gözlemlemiştir; bu nedenle stale bir IP listesi engellemek yerine **network'ün gelişen, aktör benzeri bir entity olarak ele alınmasını** önerir.<sup>[[2]](#references)</sup>

### Bunun sağladıkları—and what it leaks

- Hedef, coğrafi olarak yakın ve görünüşte residential olabilecek bir exit görür.
- Exit, hedefi ve kendisinden önceki hop'u görür; operator'ü mutlaka görmez.
- Access service, customer'ı ve route request'i görür. Bağımsız şekilde yönetilen bir mesh, customer'ı exit'lerden ayırabilir; ancak güçlü bir counterparty record oluşturur.
- Tekrarlanan port'lar, handshake sırası, server banner'ları, certificate'lar, uptime pencereleri ve controller ilişkileri, IP'ler rotate edilirken bile filoyu açığa çıkarabilir.
- Compromised router çoğu zaman endpoint telemetry'den yoksundur; ancak ISP'sinde subscriber ve flow data bulunur; el konulması implant/configuration artifacts'larını açığa çıkarır.

{% hint style="info" %}
Yetkili bir exercise için topology'yi kuruluşa ait VM'ler veya router'larla yeniden oluşturun ve controller'ın attribution map'ini koruyun. Açık proxy'leri veya üçüncü taraf cihazları işe dahil etmeyin. [Lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain), bir intermediary'yi mağdur etmeden defender'ın görebileceği aynı hop yapısını oluşturur.
{% endhint %}

## Residential ve mobile proxy network'leri

Residential proxy service'leri oturumları tüketici broadband adreslerine atar; mobile proxy'ler carrier NAT pool'ları üzerinden çıkış yapar. Tedarik; açıkça kaydolmuş appliance'lar, tüketici uygulamalarına eklenmiş SDK/proxyware, reseller'lar veya malware kaynaklı olabilir. Bu kaynaklar eşdeğer değildir: bilgilendirilmiş consent olmaması, bir privacy service'i compromised infrastructure'a dönüştürür.

Rotation mode'ları detection'ı etkiler:

- **per-request rotation**, higher-layer identity sabit kalırken hızlı IP ve ASN/geography süreksizlikleri oluşturur;
- **sticky sessions**, bir exit'i dakikalar veya saatler boyunca koruyarak sıradan bir subscriber'a benzer;
- **backconnect gateways**, customer'a tek bir broker endpoint'i sunar ve exit'leri dahili olarak seçer;
- **mobile pools**, birçok gerçek subscriber'ı az sayıda carrier NAT address'inin arkasına yerleştirir; bu da bir IP block'unu maliyetli hale getirir.

Defender'lar IP'yi authenticated session, TLS/client fingerprint, HTTP ordering, device cookie ve behavior ile correlate etmelidir. Görünüşte yerel bir residential login'in ardından, tüm higher-layer feature'lar aynı kalırken başka bir ülkenin gelmesi, yalnızca reputation'dan daha güçlüdür. Bunun tersine, address sharing ve mobile handoff meşru churn oluşturabilir; bu nedenle residential/proxy sınıflandırmasını hiçbir zaman verdict olarak değerlendirmeyin.

## Multi-hop proxy chain'leri

MITRE, external proxy'leri **multi-hop proxies (T1090.003)**'ten ayırır. Önemli özellik hop sayısı değil, knowledge ve administration'ın ayrılmasıdır.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Taraflardan biri A ve B'yi işletiyorsa paylaşılan loglar veya akış zamanlaması devrenin yeniden oluşturulmasını sağlayabilir. Aynı endpoint/account üzerinden sıralı ticari VPN'ler eklemek, ortak kimlik, ödeme ve zamanlama kanıtlarını korurken gecikme ekleyebilir. Tor, bağımsız olarak seçilen relay'ler ve paylaşımlı bir client tasarımıyla bu sorunu azaltır; ancak düşük gecikmeli etkileşimli bir ağ, her iki ucu da ölçen bir gözlemciye karşı direnç garantisi veremez.

Yaygın hatalar arasında DNS veya IPv6 bypass, uygulamaların kendi socket'lerini açması, yönetim trafiğinin relay'lere doğrudan ulaşması, senkronize etkinlik, yeniden kullanılan SSH key'leri ve kimliği belirleyici account'lara giriş yapılması bulunur. Doğru doğrulama bir failure test'idir: her relay'i sırayla durdurun ve workload'un clear bir yola geri dönemediğini gösterin.

## Redirector katmanları ve trafik şekillendirme

Public bir **redirector**, operation'a özgü bir grammar ile eşleşen trafiği kabul eder ve korunan bir team server'a iletir. Diğer her şey reddedilebilir veya zararsız içerik olarak sunulabilir.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Birden fazla katman maruziyeti sınırlar: bir public domain'i yakmak, team server'ın açığa çıkmasını gerektirmez. CDN'ler anycast kapasitesi ve itibarlı bir dış domain ekler; ancak CDN hesabı ve edge log'ları attribution noktalarına dönüşür. TLS fingerprints, certificate histories, ayırt edici path/header sırası, response sizes, redirect davranışı ve origin allowlist'leri görünüşte ilgisiz front'ları aynı kümede toplayabilir.

Detection için reverse-proxy alanlarını normalization öncesinde kaydedin, SNI/Host/authority değerlerini karşılaştırın, nadir header kombinasyonlarını inceleyin, response body'lerini ve TLS fingerprints'leri kümelendirin, yapılandırma örtüşmeleri için cloud/CDN audit log'larını arayın. Yetkili red team'ler gerçek bir markayı kopyalamaktan veya credential collection işlemini ilgisiz bir third party arkasına yerleştirmekten kaçınmalıdır.

## Domain fronting and domainless fronting

Klasik **domain fronting (T1090.004)** ile TLS bağlantısı SNI'da izin verilen bir front domain'i duyururken şifrelenmiş HTTP `Host` veya HTTP/2 `:authority`, farklı bir back-end domain'i ister. İşbirliği yapan bir CDN, iç değere göre yönlendirme yapar. TLS decryption yapmayan bir network observer front'u görür; CDN ise her iki değeri ve origin'i görür. Domainless varyantlarda SNI boş olabilirken başka bir routing field hedefi seçer.<sup>[[4]](#references)</sup>

Bu sihirli bir impersonation değildir: yalnızca intermediary uyuşmazlığa kasıtlı veya kazara izin verdiğinde ve iç name'i nasıl route edeceğini bildiğinde çalışır. Büyük provider'lar cross-account fronting'i kısıtlamıştır. Encrypted ClientHello (ECH), on-path observer'ın görebileceklerini değiştirir; ancak CDN, endpoint veya application kayıtlarını ortadan kaldırmaz.

Detection noktaları şunları içerir:

- endpoint process ancestry ve bu application için beklenmeyen destination;
- TLS inspection'ın hukuka uygun ve kullanılabilir olduğu durumlarda SNI ile HTTP authority uyuşmazlığı;
- bir tenant/front'un başka bir authority/origin'e routing yaptığını gösteren CDN log'ları;
- normalde etkileşimli olan bir service'e yönelik olağandışı uzun süreli veya periyodik session'lar;
- değişen front domain'leri boyunca sabit encrypted flow sizes ve cadence.

Güvenli lab, routing uyuşmazlığını sahip olunan bir reverse proxy üzerinde simüle eder; public CDN'yi kötüye kullanmaz.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution, mantıksal bir service'i sabit infrastructure'dan ayırır:

- **DDNS:** authenticated bir client, address'i değiştikten sonra sabit bir name'i günceller.
- **DGA:** hem endpoint hem de controller, bir time/key seed'den aday domain name'ler türetir; operator bunların küçük bir alt kümesini register eder.
- **Fast flux:** bir name, çoğunlukla düşük TTL'lerle, hızla değişen compromised/proxy address'lerden oluşan bir küme döndürür.
- **Double flux:** hem service address'leri hem de authoritative name-server address'leri döner ve control layer'ı da gizler.

Fast flux yalnızca “çok sayıda DNS yanıtı” değil, adversarial olarak kullanılan bir load-distribution pattern'idir. Daha güçlü kanıt; düşük TTL, yüksek unique-address sayısı, geniş ASN/geography dağılımı, kısa node ömrü, tekrarlanan application davranışı ve şüpheli registration history'yi birleştirir. CDN'ler bu özelliklerin birkaçını meşru olarak paylaşır. MITRE, DNS davranışının process ve sonraki connection'larla ilişkilendirilmesini önerir.<sup>[[5]](#references)</sup>

Bir DGA; lexical entropy, consonant/digit patterns, NXDOMAIN bursts, eşzamanlı first-seen domain'ler ve process context aracılığıyla tespit edilebilir. Wordlist DGA'ları ve generative model'ler basit entropy kurallarını aşar; bu da fleet genelinde temporal clustering ve endpoint lineage'ı daha önemli hâle getirir.

## Compromised domains and domain shadowing

Bir actor, registrar/DNS hesabını hijack edebilir, dangling bir subdomain'i ele geçirebilir veya aksi hâlde itibarlı bir domain'in altına records ekleyebilir. **Domain shadowing**, meşru apex'i korurken çok sayıda attacker-controlled subdomain'in değişen delivery veya C2 host'larına işaret etmesini sağlar. Domain'in yaşını ve reputation'ını ödünç alır ve domain genelinde blocking işleminden kaçabilir.<sup>[[6]](#references)</sup>

Defender'lar registrar ve authoritative-DNS audit log'larına, MFA'ya, registry/registrar lock'larına, yeni delegation/API token/name server'lar için alert'lere, certificate-transparency monitoring'e ve DNS tarafından referans verilen cloud resource envanterine ihtiyaç duyar. Bir subdomain'in resolution ve certificate history'sini apex reputation'ından bağımsız olarak inceleyin.

## Web services and dead-drop resolvers

Bir **dead-drop resolver (T1102.001)**, mevcut C2'ye yönelik encoded bir pointer'ı meşru bir post, profile, document, repository, cloud object veya blockchain field içinde saklar. Malware public object'i alır, bir domain/IP'yi decode eder ve sonraki stage'e bağlanır. Bidirectional varyantlar, service API'leri üzerinden command veya file alışverişi yapar.<sup>[[7]](#references)</sup>

Bu yöntem dayanıklılık sağlar ve back-end C2'yi static binary analysis'den gizler. Ancak aynı zamanda sabit object, tenant, repository, API ve access-pattern identifier'ları oluşturur. Defender'lar şu verileri birleştirmelidir:

1. service'e bağlanan process;
2. tam API path/object ve response hash;
3. decoding veya string-processing activity;
4. kısa süre sonra gerçekleşen yeni outbound connection; ve
5. fleet'in başka yerlerindeki aynı davranış.

Tüm GitHub, cloud storage veya social media'yı engellemek genellikle uygulanabilir değildir. Service-aware egress policy ve process-level correlation, yalnızca domain'e dayalı blocking'den daha etkilidir.

## Personas, accounts and procurement compartments

Infrastructure anonymity; persona, recovery email, phone, payment, browser veya admin IP compartment'lar arasında köprü kurduğunda başarısız olur. State-linked operations, kullanımdan çok önce social profile'lar, email identity'leri ve cloud account'lar oluşturmuştur; ATT&CK bunu social, email ve cloud sub-technique'lerini içeren Establish Accounts (T1585) olarak kaydeder.<sup>[[8]](#references)</sup>

Bir defender veya investigator şu verilerden bir graph oluşturur:

- creation ve first-login zamanı, locale, time zone ve çalışma schedule'ı;
- recovery field'ları, MFA device'ları, identity document'ları ve payment instrument'ları;
- browser/TLS fingerprint'leri ve source-network history;
- avatar reuse, image provenance, writing style ve social-graph growth;
- ortak domain registrant, name server, certificate, analytics ID veya repository commit'i;
- public relay architecture'ı bypass eden management-plane action'ları.

Yetkili bir red team için synthetic persona'lar exercise controller'a belgelenmeli, organization-owned recovery/payment channel'ları kullanılmalı, gerçek ve ilgisiz kişilerin impersonation'ından kaçınılmalı ve planlı bir retirement süreci bulunmalıdır. SOC blind kalabilir; operation hesap verilemez hâle gelmemelidir.

## Emerging compound patterns to threat-model

Aşağıdakiler, **defender-driven compositions** olup named bir actor'ın her bir exact design'ı deploy ettiğine dair iddialar değildir. Zaten gözlemlenmiş primitive'leri birleştirir ve purple-team hypothesis'leri olarak kullanılabilir.

### Asymmetric one-way tasking

Command'lar public, broadcast veya append-only bir source üzerinden gelirken result'lar gecikme sonrasında ilgisiz bir channel üzerinden çıkar. Primitive örnekleri arasında web-service one-way communication ve dead drop'lar bulunur. Ayrım, tek bir flow'un bidirectional görünmesini engeller ve basit request/response correlation'ı zorlaştırır.<sup>[[9]](#references)</sup>

**Detection:** object-level read'leri koruyun, ardından process state change'lerini ve daha sonraki outbound transfer'ları daha geniş bir zaman aralığında ilişkilendirin. Anında reply gelmese bile aynı public object'i okuyan nadir bir process arayın.

### Multi-stage channel promotion

Sessiz bir first stage inventory gerçekleştirir ve yalnızca seçilen system'leri ilgisiz bir second-stage channel'a yükseltir. İkinci endpoint, protocol ve process, first stage ile hiçbir infrastructure'ı paylaşmayabilir. Bu, yetenekli infrastructure'ın maruziyetini sınırlar ve ATT&CK'te açıkça T1104 olarak modellenmiştir.<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` zincirini birleştirin; ilk domain'i block ettikten sonra incident'i kapatmayın.

### Cross-protocol relay translation

Farklı hop'lar packet'leri transparently forward etmek yerine HTTPS, QUIC, WebSocket, DNS, SSH veya bir message-queue API'sini translate eder. Translation, tek bir end-to-end protocol fingerprint'ini ortadan kaldırır; ancak ayırt edici timing, buffering ve semantic conversion özelliklerine sahip gateway'ler oluşturur. Protocol tunneling (T1572), proxy'ler ve service impersonation ile birleştirilebilir.<sup>[[11]](#references)</sup>

**Detection:** bir protocol alan ve başka bir protocol başlatan gateway host'larını, sıkı şekilde ilişkili byte/time davranışıyla arayın; endpoint intent'ini taşınan gerçek protocol ile karşılaştırın.

### Passive activation on edge devices

Bir implant beacon göndermek yerine router/VPN'e zaten ulaşan traffic'i izler ve yalnızca magic value, source-port pattern veya authenticated token gördüğünde etkinleşir. Normal traffic gerçek service'e devam eder. ATT&CK bunu Traffic Signaling (T1205) olarak adlandırır ve belgelenmiş network-device ve APT örnekleri bulunur.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, yetkili bir hunt sırasında raw packet capture, beklenmeyen socket filter'ları ve differential service behavior. Periyodik beacon'ın olmaması edge device'ın temiz olduğunu kanıtlamaz.

### Serverless and ephemeral origin rotation

Bir front sabit bir mantıksal identity'yi korurken kısa ömürlü function/container'lar birden fazla region/account'ta tek tek stage'leri işler. Bu, disk ömrünü ve sabit origin IP'lerini azaltır; ancak control-plane creation, image/layer, role, secret, request ID ve billing telemetry kalıcı graph'a dönüşür.

**Detection:** cloud audit ve invocation log'larını workload dışında saklayın; deployment template'lerini, role'leri, environment key'lerini ve front-to-origin ilişkilerini kümeleyin.

### Privacy-layer diversity

Bir operation, bilerek tek tip bir chain'den kaçınabilir: örneğin bir channel leased relay kullanır, tasking public object kullanır, exit sahip olunan bir lab cellular link'inden gelir ve administration ayrı bir organization network'ü kullanır. Bu, tek bir provider'ın ele geçirilmesinin değerini azaltır; ancak cross-layer timing ve operational-error riskini artırır.

**Detection:** identity, DNS, SaaS, network ve cloud sensor'ları üzerinden campaign timeline'ları oluşturun. Identical indicator'lar yerine synchronized state transition'ları arayın.

### Decentralized or transparency-log dead drops

Bir actor, küçük bir encrypted pointer'ı dayanıklı herhangi bir public append-only system'e, content-addressed store'a veya transparency benzeri bir feed'e yerleştirebilir. Public object dayanıklıdır; ancak exact index/content hash ve client polling behavior sabit identifier'lara dönüşür.

**Detection:** tam API/object identifier'larını ve response hash'lerini kaydedin; immutable object'leri poll eden nonstandard process'lerin ardından decoding veya yeni connection gelmesi durumunda alert üretin.

### Delayed store-and-forward operations

Interactive C2 güçlü timing correlation oluşturur. Store-and-forward design, encrypted job'ları batch hâline getirir ve result'ları dakikalar veya saatler sonra farklı bir queue ya da physical transfer üzerinden geri gönderir. End-to-end timing'in daha zayıf olması karşılığında responsiveness'ten vazgeçer.

**Detection:** correlation window'larını genişletin, periodic queue access'i modelleyin ve endpoint staging'i inceleyin. Batching, signal'i packet timing'den scheduled process/file behavior'a taşır; onu ortadan kaldırmaz.

## Design review: think in observers

Her path için deployment öncesinde ve collection sonrasında bu tabloyu doldurun:

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Tek bir sıradan provider her sütunu doldurabiliyorsa architecture, target'tan concealment sağlar; ancak sağlam separation sağlamaz. Hiçbir internal controller activity'yi bir engagement'a geri eşleyemiyorsa bu yapı professional red teaming için uygun değildir.

## References

- [1] [MITRE ATT&CK — Infrastructure Edinme (T1583), Infrastructure Ele Geçirme (T1584) ve Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actor'ları ORB network'lerini kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastructure Ele Geçirme: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Account Oluşturma (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
