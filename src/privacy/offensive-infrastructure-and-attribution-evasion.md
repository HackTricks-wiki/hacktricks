# Offensive Infrastructure and Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

Bir operatör, tek bir proxy üzerinden nadiren anlamlı bir anonimlik elde eder. Gerçek kampanyalar bir **ayrıştırma grafiği** oluşturur: operatör bir access node'a ulaşır, traversal node'ları bu node'u exit'ten gizler, redirector'lar gerçek C2'yi korur ve disposable name'ler public edge'i işaret eder.

Her yolun normalize edilmiş avantajlar/dezavantajlar/deployment/detection görünümü için [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) sayfasını kullanın. Bu sayfa adversarial infrastructure composition konusunu daha derinlemesine ele alır.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Bir hedef tarafından görülen son adres bu nedenle bir yolun kanıtıdır; klavyeyi kimin kontrol ettiğinin kanıtı değildir. MITRE, başlıca bileşenleri Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) ve Web Service (T1102) ile eşleştirir.<sup>[[1]](#references)</sup>

## Infrastructure sınıfları

| Sınıf | Bir aktör bunu neden kullanır | Kalıcı maruziyet | Defender'ın en iyi pivotu |
|---|---|---|---|
| Kiralanmış VPS/cloud | Hızlı, öngörülebilir, yönlendirilebilir ve yeniden kurulması kolay | tenant, faturalandırma, konsol, source-login ve image geçmişi | hesap/control-plane olayları ve tekrarlanan server fingerprint |
| Commercial VPN/Tor | Geniş paylaşımlı egress kümesi; server yönetimi gerekmez | provider/guard görünürlüğü ve uçtan uca zamanlama | hedef davranışı, endpoint kanıtı ve flow korelasyonu |
| Residential/mobile proxy | Tüketici ASN'i ve coğrafi makullük | broker/müşteri kayıtları; proxyware veya infected-host davranışı | imkansız seyahat, proxy protokolleri ve session bazında address churn |
| Ele geçirilmiş server/router/IoT | Mağdurun itibarını ve yargı alanını ödünç alır | implant, yönetim flow'u ve tekrarlanan upstream controller | tek bir exit IP yerine device telemetry ve ORB topolojisi |
| CDN/redirector | Public edge'i back-end C2'den ayırır | TLS/HTTP grammar'ı, sertifika, routing ve cloud-account artefact'ları | edge-to-origin korelasyonu ve request-shape clustering |
| Meşru web service | İzin verilen GitHub/cloud/social trafiğiyle karışır | API token, tenant/object identifier'ları ve sıra dışı process lineage | endpoint process'i ile service/API semantiği |
| Fiziksel/cellular/satellite path | Görünen fiziksel origin'i değiştirir | RF, carrier, subscriber, device ve location kayıtları | radio/physical ve network kanıtlarının birlikte kullanılması |

## Operational relay box ağları

Bir **ORB network**, intermediate service olarak kullanılan yönetilen bir proxy fleet'idir. Mandiant bunları leased server'lardan oluşan provisioned network'ler, ele geçirilmiş router/IoT'lardan oluşan non-provisioned network'ler ve hybrid'ler olarak ayırır. Olgun bir topolojide dört mantıksal rol bulunur:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory, credential'lar, health ve routing policy'yi yönetir.
2. **Access/relay node:** müşterileri veya operator'leri authenticate eder; değişen bir mesh'e girişi sağlayan stable entry'dir.
3. **Traversal node'ları:** bir veya daha fazla leased veya compromised system, opaque connection'ları relay eder.
4. **Exit/staging node:** reconnaissance, exploitation veya C2 hedeflerine son source address'i sunar.

Mesh, exit'leri ülkeye, ASN'e, latency'ye veya availability'ye göre seçebilir ve health'i bozulan node'ları rotate edebilir. Birden fazla threat group aynı network'ü kiralayabilir. Mandiant, bir IPv4 address'in bazı ORB'lerle 31 gün kadar kısa bir süre ilişkilendirildiğini gözlemlemiştir; bu nedenle stale bir IP listesi engellemek yerine **network'ü gelişen, aktör benzeri bir entity olarak** ele almayı önerir.<sup>[[2]](#references)</sup>

### Bunun sağladıkları ve neyi leak ettiği

- Hedef, coğrafi olarak yakın ve görünüşte residential olabilecek bir exit görür.
- Exit, hedefi ve kendisinden önceki hop'u görür; operator'ü görmesi gerekmez.
- Access service, müşteriyi ve route request'i görür. Bağımsız olarak yönetilen bir mesh, müşteriyi exit'lerden ayrı tutabilir; ancak güçlü bir counterparty record oluşturur.
- Tekrarlanan port'lar, handshake sırası, server banner'ları, sertifikalar, uptime aralıkları ve controller ilişkileri, IP'ler rotate edilirken bile fleet'i açığa çıkarabilir.
- Ele geçirilmiş bir router çoğunlukla endpoint telemetry'den yoksundur; ancak ISP'si yine de subscriber ve flow verilerine sahiptir. El koyma, implant/configuration artefact'larını açığa çıkarır.

{% hint style="info" %}
Yetkili bir exercise için topolojiyi kuruma ait VM'ler veya router'larla yeniden oluşturun ve controller'ın attribution map'ini saklayın. Açık proxy'leri veya üçüncü taraf cihazları devreye sokmayın. [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain), bir intermediary'yi mağdur etmeden aynı defender-visible hop yapısını oluşturur.
{% endhint %}

## Residential ve mobile proxy network'leri

Residential proxy service'leri session'ları tüketici broadband address'lerine atar; mobile proxy'ler carrier NAT pool'ları üzerinden egress sağlar. Kaynak; açıkça kaydedilmiş appliance'lar, consumer application'lara eklenmiş SDK/proxyware, reseller'lar veya malware olabilir. Bu origin'ler birbirine eşdeğer değildir: informed consent olmaması, bir privacy service'i compromised infrastructure'a dönüştürür.

Rotation mode'ları detection'ı etkiler:

- **per-request rotation**, higher-layer identity sabit kalırken hızlı IP ve ASN/geography discontinuity'leri üretir;
- **sticky session**'lar bir exit'i dakikalarca veya saatlerce korur ve sıradan bir subscriber'ı andırır;
- **backconnect gateway**'leri müşteriye tek bir broker endpoint'i gösterir ve exit'leri dahili olarak seçer;
- **mobile pool**'lar çok sayıda gerçek subscriber'ı az sayıda carrier NAT address'inin arkasına yerleştirir; bu da bir IP block'u maliyetli hale getirir.

Defender'lar IP'yi authenticated session, TLS/client fingerprint, HTTP ordering, device cookie ve behavior ile korele etmelidir. Sözde local bir residential login'in, tüm higher-layer feature'lar aynı kalırken başka bir ülkeyle takip edilmesi, tek başına reputation'dan daha güçlüdür. Buna karşılık address sharing ve mobile handoff meşru churn oluşturabilir; bu nedenle residential/proxy classification'ını hiçbir zaman verdict olarak ele almayın.

## Multi-hop proxy chain'leri

MITRE, external proxy'leri **multi-hop proxy'lerden (T1090.003)** ayırır. Önemli özellik hop sayısı değil, knowledge ve administration'ın ayrılmasıdır.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Bir taraf A ve B'yi işletiyorsa, paylaşılan loglar veya akış zamanlaması circuit'ü yeniden oluşturabilir. Aynı endpoint/account üzerinden art arda kullanılan ticari VPN'ler, ortak kimlik, ödeme ve zamanlama kanıtlarını korurken gecikme ekleyebilir. Tor, bağımsız olarak seçilen relay'ler ve paylaşılan bir client tasarımıyla bu sorunu azaltır; ancak düşük gecikmeli interaktif bir network, her iki ucu da ölçen bir gözlemciye karşı direnç garantisi veremez.

Yaygın hatalar arasında DNS veya IPv6 bypass'ı, uygulamaların kendi socket'lerini açması, management trafiğinin relay'lere doğrudan ulaşması, senkronize etkinlik, yeniden kullanılan SSH key'leri ve kimliği belirleyen account'lara giriş yapılması bulunur. Doğru verification bir failure test'tir: her relay'i sırayla durdurun ve workload'un clear path'e fallback yapamadığını gösterin.

## Redirector katmanları ve trafik şekillendirme

Public bir **redirector**, operation'a özel bir grammar ile eşleşen trafiği kabul eder ve korunan bir team server'a iletir. Diğer her şey reddedilebilir veya zararsız içerikle sunulabilir.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Birden fazla katman maruziyeti sınırlar: bir public domain'in yanması team server'ı açığa çıkarmak zorunda değildir. CDN'ler anycast kapasitesi ve itibarlı bir dış domain ekler; ancak CDN hesabı ve edge logları attribution noktalarına dönüşür. TLS fingerprint'leri, certificate geçmişleri, ayırt edici path/header sırası, response boyutları, redirect davranışı ve origin allowlist'leri, görünüşte ilgisiz front'ları kümelendirebilir.

Detection için reverse-proxy alanlarını normalization'dan önce kaydedin, SNI/Host/authority değerlerini karşılaştırın, nadir header kombinasyonlarını inceleyin, response body'leri ve TLS fingerprint'lerini kümeleyin ve cloud/CDN audit log'larında configuration örtüşmesi arayın. Yetkili red team'ler gerçek bir brand'i kopyalamaktan veya credential collection'ı ilgisiz bir third party'nin arkasına yerleştirmekten kaçınmalıdır.

## Domain fronting ve domainless fronting

Klasik **domain fronting (T1090.004)** ile TLS bağlantısı, SNI'da izin verilen bir front domain'i duyururken şifrelenmiş HTTP `Host` veya HTTP/2 `:authority`, farklı bir back-end domain'i ister. İşbirliği yapan bir CDN, inner değere göre routing yapar. TLS decryption uygulanmayan bir network observer front'u görür; CDN ise her iki değeri ve origin'i görür. Domainless varyantlarda SNI boş olabilirken başka bir routing alanı hedefi seçer.<sup>[[4]](#references)</sup>

Bu sihirli bir impersonation değildir: yalnızca intermediary uyuşmazlığa kasıtlı olarak veya yanlışlıkla izin verdiğinde ve inner name'i nasıl route edeceğini bildiğinde çalışır. Büyük provider'lar cross-account fronting'i kısıtlamıştır. Encrypted ClientHello (ECH), on-path observer'ın görebileceklerini değiştirir; ancak CDN, endpoint veya application kayıtlarını ortadan kaldırmaz.

Detection noktaları şunları içerir:

- endpoint process ancestry ve bu application için beklenmeyen destination;
- TLS inspection'ın hukuka uygun ve mevcut olduğu durumlarda SNI ile HTTP authority arasındaki uyuşmazlık;
- bir tenant/front'ın başka bir authority/origin'e routing yaptığını gösteren CDN logları;
- normalde interactive olan bir service'e yönelik olağandışı uzun ömürlü veya periyodik session'lar;
- değişen front domain'leri üzerinden sabit encrypted flow boyutları ve cadence.

Güvenli lab, routing uyuşmazlığını sahip olunan bir reverse proxy üzerinde simüle eder; public CDN'yi kötüye kullanmaz.

## Dynamic resolution: DDNS, DGA ve fast flux

Dynamic resolution, mantıksal bir service'i sabit infrastructure'dan ayırır:

- **DDNS:** authenticated bir client, address değiştikten sonra stable bir name'i günceller.
- **DGA:** hem endpoint hem de controller, bir time/key seed üzerinden aday domain name'leri türetir; operator bunların küçük bir alt kümesini register eder.
- **Fast flux:** bir name, genellikle düşük TTL'lerle, hızla değişen bir dizi compromised/proxy address döndürür.
- **Double flux:** hem service address'leri hem de authoritative name-server address'leri rotate edilir; böylece control layer da gizlenir.

Fast flux, yalnızca “çok sayıda DNS cevabı” değil, adversarial olarak kullanılan bir load-distribution pattern'idir. Daha güçlü kanıt; düşük TTL, yüksek unique-address sayısı, geniş ASN/geography dağılımı, kısa node ömrü, tekrarlanan application davranışı ve şüpheli registration geçmişini birleştirir. CDN'ler bu özelliklerin birçoğunu meşru olarak paylaşır. MITRE, DNS davranışının process ve sonraki connection'larla ilişkilendirilmesini önerir.<sup>[[5]](#references)</sup>

Bir DGA; lexical entropy, consonant/digit pattern'leri, NXDOMAIN burst'leri, eşzamanlı first-seen domain'ler ve process context kullanılarak tespit edilebilir. Wordlist DGA'ları ve generative model'ler basit entropy kurallarını aşar; bu nedenle fleet genelindeki temporal clustering ve endpoint lineage daha önemli hale gelir.

## Compromised domain'ler ve domain shadowing

Bir actor registrar/DNS hesabını hijack edebilir, dangling bir subdomain'i ele geçirebilir veya aksi halde itibarlı bir domain'in altına record'lar ekleyebilir. **Domain shadowing**, meşru apex'i korurken çok sayıda attacker-controlled subdomain'in değişen delivery veya C2 host'larına yönelmesini sağlar. Domain'in yaşından ve reputation'ından yararlanır ve domain-wide blocking'den kaçabilir.<sup>[[6]](#references)</sup>

Defender'ların registrar ve authoritative-DNS audit log'larına, MFA'ya, registry/registrar lock'larına, yeni delegation/API token/name server'lar için alert'lere, certificate-transparency monitoring'e ve DNS tarafından referans verilen cloud resource envanterine ihtiyacı vardır. Bir subdomain'in resolution ve certificate geçmişini apex reputation'ından bağımsız olarak inceleyin.

## Web services ve dead-drop resolver'lar

Bir **dead-drop resolver (T1102.001)**, current C2'ye giden encoded bir pointer'ı meşru bir post, profile, document, repository, cloud object veya blockchain field içinde saklar. Malware public object'i fetch eder, bir domain/IP decode eder ve sonraki stage'e bağlanır. Bidirectional varyantlar, service API'leri üzerinden command veya file alışverişi yapar.<sup>[[7]](#references)</sup>

Bu yöntem dayanıklılık sağlar ve back-end C2'yi static binary analysis'ten gizler. Ayrıca stable object, tenant, repository, API ve access-pattern identifier'ları oluşturur. Defender'lar şunları ilişkilendirmelidir:

1. service'e bağlanan process'i;
2. exact API path/object ve response hash'i;
3. decoding veya string-processing activity'yi;
4. kısa süre sonra gerçekleşen yeni outbound connection'ı; ve
5. fleet'in başka yerlerindeki identical behavior'ı.

Tüm GitHub, cloud storage veya social media'yı block etmek nadiren uygulanabilirdir. Service-aware egress policy ve process-level correlation, domain-only blocking'den daha iyi sonuç verir.

## Persona'lar, hesaplar ve procurement compartment'ları

Infrastructure anonymity, bir persona, recovery email, phone, payment, browser veya admin IP'si compartment'lar arasında köprü kurduğunda başarısız olur. State-linked operation'lar, kullanımdan çok önce social profile'lar, email identity'leri ve cloud account'lar oluşturmuştur; ATT&CK bunu, social, email ve cloud sub-technique'lerini içeren Establish Accounts (T1585) olarak kaydeder.<sup>[[8]](#references)</sup>

Bir defender veya investigator şu unsurlardan bir graph oluşturur:

- creation ve first-login zamanı, locale, time zone ve çalışma schedule'ı;
- recovery field'ları, MFA device'ları, identity document'ları ve payment instrument'ları;
- browser/TLS fingerprint'leri ve source-network geçmişi;
- avatar reuse, image provenance, writing style ve social-graph growth;
- paylaşılan domain registrant, name server, certificate, analytics ID veya repository commit'i;
- public relay architecture'ı atlayan management-plane action'ları.

Yetkili bir red team için synthetic persona'lar exercise controller'a belgelenmeli, organization-owned recovery/payment channel'ları kullanılmalı, gerçek ve ilgisiz kişilerin impersonation'ından kaçınılmalı ve planlı bir retirement uygulanmalıdır. SOC blind kalabilir; operation accountablity dışına çıkmamalıdır.

## Threat model'e eklenecek emerging compound pattern'ler

Aşağıdakiler, **defender-driven composition'lar**dır; named bir actor'ın her bir exact design'ı deploy ettiği iddiası değildir. Zaten gözlemlenmiş primitive'leri birleştirir ve useful purple-team hypothesis'leri oluştururlar.

### Asymmetric one-way tasking

Command'lar public, broadcast veya append-only bir source üzerinden gelirken result'lar gecikmeyle ilgisiz bir channel üzerinden çıkar. Primitive örnekleri arasında web-service one-way communication ve dead drop'lar bulunur. Ayrım, tek bir flow'un bidirectional görünmesini engeller ve basit request/response correlation'ı zorlaştırır.<sup>[[9]](#references)</sup>

**Detection:** object-level read'leri koruyun, ardından process state change'lerini ve daha sonraki outbound transfer'ları daha geniş bir zaman aralığında ilişkilendirin. Immediate reply gelmese bile aynı public object'i okuyan nadir bir process arayın.

### Multi-stage channel promotion

Sessiz bir first stage inventory gerçekleştirir ve yalnızca seçili system'leri ilgisiz bir second-stage channel'a yükseltir. İkinci endpoint, protocol ve process, first stage ile hiçbir infrastructure paylaşmayabilir. Bu, capable infrastructure'ın maruziyetini sınırlar ve ATT&CK'te açıkça T1104 olarak modellenmiştir.<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` zincirini birleştirin; first domain'i block ettikten sonra incident'ı sonlandırmayın.

### Cross-protocol relay translation

Farklı hop'lar, packet'ları transparently forward etmek yerine HTTPS, QUIC, WebSocket, DNS, SSH veya message-queue API'leri arasında translation yapar. Translation, tek bir end-to-end protocol fingerprint'ini ortadan kaldırır; ancak distinctive timing, buffering ve semantic conversion özelliklerine sahip gateway'ler oluşturur. Protocol tunneling (T1572), proxy'ler ve service impersonation ile birleştirilebilir.<sup>[[11]](#references)</sup>

**Detection:** bir protocol alan ve başka bir protocol başlatan gateway host'larını, tightly coupled byte/time behavior ile arayın; endpoint intent'i taşınan actual protocol ile karşılaştırın.

### Passive activation on edge device'lar

Beaconing yerine implant, bir router/VPN'e zaten ulaşan traffic'i izler ve yalnızca magic value, source-port pattern veya authenticated token gördüğünde activate olur. Normal traffic gerçek service'e devam eder. ATT&CK bunu, belgelenmiş network-device ve APT örnekleriyle Traffic Signaling (T1205) olarak adlandırır.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, yetkili bir hunt sırasında raw packet capture, beklenmeyen socket filter'ları ve differential service behavior. Periodic beacon'ın yokluğu edge device'ın temiz olduğunu kanıtlamaz.

### Serverless ve ephemeral origin rotation

Bir front stable logical identity'yi korurken kısa ömürlü function/container'lar birkaç region/account'ta ayrı stage'leri işler. Bu, disk ömrünü ve sabit origin IP'lerini azaltır; ancak control-plane creation, image/layer, role, secret, request ID ve billing telemetry kalıcı graph'a dönüşür.

**Detection:** cloud audit ve invocation log'larını workload dışında saklayın; deployment template'lerini, role'leri, environment key'lerini ve front-to-origin relationship'lerini cluster'layın.

### Privacy-layer diversity

Bir operation, kasıtlı olarak tek tip bir chain'den kaçınabilir: örneğin bir channel leased relay kullanır, tasking public object kullanır, exit owned lab cellular link'ten gelir ve administration ayrı bir organization network'ü kullanır. Bu, tek bir provider'ı compromise etmenin değerini azaltır; ancak cross-layer timing ve operational-error riskini artırır.

**Detection:** identity, DNS, SaaS, network ve cloud sensor'ları arasında campaign timeline'ları oluşturun. Identical indicator'lar yerine synchronized state transition'ları arayın.

### Decentralized veya transparency-log dead drop'ları

Bir actor, küçük bir encrypted pointer'ı dayanıklı herhangi bir public append-only system'e, content-addressed store'a veya transparency-like feed'e yerleştirebilir. Public object dayanıklıdır; ancak exact index/content hash ve client polling behavior stable identifier'lara dönüşür.

**Detection:** full API/object identifier'larını ve response hash'lerini kaydedin; immutable object'leri poll eden nonstandard process'lerin ardından decoding veya yeni connection gerçekleştiğinde alert üretin.

### Delayed store-and-forward operation'lar

Interactive C2 güçlü timing correlation oluşturur. Store-and-forward design, encrypted job'ları batch'ler ve result'ları dakikalar veya saatler sonra farklı bir queue ya da physical transfer üzerinden döndürür. Daha zayıf end-to-end timing karşılığında responsiveness'tan vazgeçer.

**Detection:** correlation window'larını genişletin, periodic queue access'i modelleyin ve endpoint staging'i inceleyin. Batching, signal'ı packet timing'den scheduled process/file behavior'a taşır; onu ortadan kaldırmaz.

## Design review: observer'ları düşünün

Her path için deployment öncesinde ve collection sonrasında bu tabloyu doldurun:

| Layer | Source'u görür mü? | Destination'ı görür mü? | Content'i görür mü? | Stable identifier'lar | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Tek bir ordinary provider her sütunu doldurabiliyorsa architecture, target'tan concealment sağlar; ancak robust separation sağlamaz. Hiçbir internal controller activity'yi bir engagement'a geri map edemiyorsa bu architecture professional red teaming için uygun değildir.

## References

- [1] [MITRE ATT&CK — Infrastructure Edinme (T1583), Infrastructure Compromise (T1584) ve Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actor'leri ORB network'leri kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domain'ler (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
