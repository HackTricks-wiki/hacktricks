# Offensive Infrastructure ve Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

Bir operator, tek bir proxy üzerinden nadiren anlamlı bir anonymity elde eder. Gerçek campaign'ler bir **separation graph** oluşturur: operator bir access node'a ulaşır, traversal node'ları bu node'u exit node'dan gizler, redirector'lar gerçek C2'yi korur ve disposable name'ler public edge'i işaret eder.

Her path'in normalize edilmiş avantajlar/dezavantajlar/deployment/detection görünümü için [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) sayfasını kullanın. Bu sayfa adversarial infrastructure composition konusunu daha derinlemesine ele alır.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Hedefin gördüğü son adres bu nedenle bir yolun kanıtıdır; klavyeyi kimin kontrol ettiğinin kanıtı değildir. MITRE, başlıca bileşenleri Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) ve Web Service (T1102) ile eşleştirir.<sup>[[1]](#references)</sup>

## Infrastructure sınıfları

| Sınıf | Bir actor bunu neden kullanır | Kalıcı maruziyet | Defender'ın en iyi pivot'u |
|---|---|---|---|
| Kiralanmış VPS/cloud | Hızlı, öngörülebilir, yönlendirilebilir ve yeniden oluşturulması kolay | tenant, faturalandırma, console, source-login ve image geçmişi | account/control-plane event'leri ve tekrarlanan server fingerprint |
| Commercial VPN/Tor | Büyük paylaşımlı egress kümesi; server administration gerektirmez | provider/guard görünürlüğü ve uçtan uca zamanlama | destination davranışı, endpoint kanıtı ve flow correlation |
| Residential/mobile proxy | Consumer ASN ve coğrafi açıdan makul görünüm | broker/customer kayıtları; proxyware veya infected-host davranışı | impossible travel, proxy protokolleri ve session bazında address churn |
| Compromised server/router/IoT | Victim reputation'ını ve jurisdiction'ı ödünç alır | implant, management flow ve tekrarlanan upstream controller | tek bir exit IP yerine device telemetry ve ORB topology |
| CDN/redirector | Public edge'i back-end C2'den ayırır | TLS/HTTP grammar, certificate, routing ve cloud-account artifact'ları | edge-to-origin correlation ve request-shape clustering |
| Legitimate web service | İzin verilen GitHub/cloud/social trafiğine karışır | API token, tenant/object identifier'ları ve alışılmadık process lineage | endpoint process'i ile service/API semantics |
| Physical/cellular/satellite path | Görünen fiziksel origin'i değiştirir | RF, carrier, subscriber, device ve location kayıtları | radio/physical ve network kanıtlarının birleştirilmesi |

## Operational relay box ağları

Bir **ORB network**, intermediate service olarak kullanılan yönetilen bir proxy filosudur. Mandiant bunları leased server'lardan oluşan provisioned network'ler, compromised router/IoT cihazlarından oluşan non-provisioned network'ler ve hybrid'ler olarak ayırır. Olgun bir topology'de dört logical role bulunur:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** Inventory, credential'ları, health durumunu ve routing policy'yi yönetir.
2. **Access/relay node:** Customer'ları veya operator'ları authenticate eder; değişken bir mesh'e yönelik stable entry noktasıdır.
3. **Traversal nodes:** Bir veya daha fazla leased veya compromised system, opaque connection'ları relay eder.
4. **Exit/staging node:** Reconnaissance, exploitation veya C2 target'larına son source address'i sunar.

Mesh, exit'leri country, ASN, latency veya availability'ye göre seçebilir ve sağlıksız node'ları rotate edebilir. Birden fazla threat group aynı network'ü kiralayabilir. Mandiant, bir IPv4 address'in bazı ORB'lerle ilişkili kalmasının 31 gün kadar kısa olabildiğini gözlemlemiştir; bu nedenle stale bir IP listesini blocklamak yerine **network'ün gelişen, actor benzeri bir entity olarak ele alınmasını** önerir.<sup>[[2]](#references)</sup>

### Bunun sağladıkları—and bunun sızdırdığı şeyler

- Target, coğrafi olarak yakın ve görünüşte residential olabilecek bir exit görür.
- Exit, target'ı ve kendisinden önceki hop'u görür; operator'ı mutlaka görmez.
- Access service, customer'ı ve route request'i görür. Bağımsız olarak yönetilen bir mesh, customer'ı exit'lerden ayrı tutabilir; ancak güçlü bir karşı taraf kaydı oluşturur.
- Tekrarlanan port'lar, handshake sırası, server banner'ları, certificate'lar, uptime window'ları ve controller ilişkileri, IP'ler rotate edilirken bile filoyu açığa çıkarabilir.
- Compromised router çoğunlukla endpoint telemetry'den yoksundur; ancak ISP'sinde subscriber ve flow verileri bulunur; el koyma implant/configuration artifact'larını açığa çıkarır.

{% hint style="info" %}
Yetkili bir exercise için topology'yi kuruluşa ait VM'ler veya router'larla yeniden oluşturun ve controller'ın attribution map'ini koruyun. Open proxy'leri veya üçüncü taraf cihazları devreye sokmayın. [Lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain), bir intermediary'yi victim durumuna düşürmeden defender'ın görebildiği aynı hop structure'ı oluşturur.
{% endhint %}

## Residential ve mobile proxy network'leri

Residential proxy service'leri session'ları consumer broadband address'lerine atar; mobile proxy'ler carrier NAT pool'ları üzerinden egress yapar. Supply; açıkça kaydettirilmiş appliance'lerden, consumer application'lara bundled edilmiş SDK/proxyware'den, reseller'lardan veya malware'den gelebilir. Bu origin'ler eşdeğer değildir: informed consent'in olmaması, bir privacy service'ini compromised infrastructure'a dönüştürür.

Rotation mode'ları detection'ı etkiler:

- **per-request rotation**, higher-layer identity sabit kalırken hızlı IP ve ASN/geography discontinuity'leri oluşturur;
- **sticky sessions**, bir exit'i dakikalar veya saatler boyunca koruyarak ordinary subscriber'a benzer;
- **backconnect gateway'ler**, customer'a tek bir broker endpoint'i sunar ve exit'leri dahili olarak seçer;
- **mobile pool'lar**, çok sayıda genuine subscriber'ı az sayıdaki carrier NAT address'inin arkasına yerleştirir; bu da bir IP block'unu maliyetli hale getirir.

Defender'lar IP'yi authenticated session, TLS/client fingerprint, HTTP ordering, device cookie ve behavior ile correlate etmelidir. Sözde local bir residential login'in ardından, tüm higher-layer feature'lar aynı kalırken başka bir country'den login gelmesi, tek başına reputation'dan daha güçlü bir göstergedir. Buna karşılık address sharing ve mobile handoff meşru churn oluşturabilir; bu nedenle residential/proxy classification'ı asla kesin hüküm olarak değerlendirmeyin.

### Proxyware control plane'leri ve reseller çakışması

Bir residential pool'u düz bir exit listesi olarak modellemeyin. IPIDEA ecosystem'inin analizi, yeniden kullanılabilir bir **two-tier control plane** ortaya çıkardı: embedded SDK önce device/enrollment metadata'sını bir Tier One domain'e bildirir ve scheduling ile Tier Two `connect`/`proxy` IP:port çiftlerini alır. Node, encoded bir task için Tier Two connect port'unu periyodik olarak poll eder, eşleştirilmiş proxy port'una ikinci bir connection açar ve sağlanan byte'ları istenen destination'a relay eder. Görünüşte farklı SDK'lar ve proxy brand'leri ayrı discovery domain'lerine sahipti; ancak ortak ownership ve reseller ilişkileri üzerinden paylaşılan Tier Two infrastructure'ında ve çakışan exit pool'larında birleşiyorlardı.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Bu, bir residential IP bloğundan daha kalıcı hunting pivot'leri sağlar:<sup>[[13]](#references)</sup>

- beklenmeyen bir utility, VPN, game veya embedded-device process'i sabit bir device ID/customer key gönderir ve değişen bir server list alır;
- endpoint, alışılmadık bir port üzerindeki doğrudan bir IP'yi poll eder, ardından yeni bir destination socket açmadan hemen önce aynı adres üzerindeki başka bir porta bağlanır;
- görünüşte farklı markalar Tier Two adreslerini, protocol grammar'larını, SDK code'unu veya exit-node örtüşmesini paylaşır;
- farklı Tier One domain'lerine bağlanan farklı uygulamalar, aynı Tier Two pool'undan adresler alır.

Bu örtüşme attribution'ı da sınırlar: Bir vendor'ın advertised pool'unda bir IP görülmesi, ilgili zamanda hangi reseller'ın, customer'ın veya threat actor'ın bunu kullandığını kanıtlamaz. Flow timestamp'lerini, process lineage'ını, Tier One response body'lerini ve Tier Two task identifier'larını koruyun.<sup>[[13]](#references)</sup> Yetkili bir exercise kapsamında bu hierarchy'yi yalnızca kuruluşa ait endpoint'lerle emulate edin; consumer device'larını veya üçüncü taraf proxyware'i asla enroll etmeyin.

## Multi-hop proxy zincirleri

MITRE, external proxy'leri **multi-hop proxies (T1090.003)**'ten ayırır. Önemli olan hop sayısı değil, knowledge ve administration'ın ayrılmasıdır.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Taraflardan biri A ve B'yi işletiyorsa paylaşılan loglar veya akış zamanlaması circuit'ü yeniden oluşturabilir. Aynı endpoint/account üzerinden ardışık ticari VPN'ler eklemek, ortak kimlik, ödeme ve zamanlama kanıtlarını korurken gecikme ekleyebilir. Tor, bağımsız olarak seçilen relay'ler ve ortak bir client tasarımıyla bu sorunu azaltır; ancak düşük gecikmeli etkileşimli bir network, her iki ucu da ölçen bir gözlemciye karşı dayanıklılık garantisi veremez.

Yaygın hatalar arasında DNS veya IPv6 bypass, uygulamaların kendi socket'lerini açması, management trafiğinin relay'lere doğrudan ulaşması, senkronize etkinlik, yeniden kullanılan SSH key'leri ve kimliği belirleyici account'lara giriş yapılması bulunur. Doğru verification bir failure test'idir: her relay'i sırayla durdurun ve workload'un clear path'e geri dönemediğini gösterin.

### Tunnel çökmesi ve upstream sızıntısı

Bir relay architecture çoğu zaman en fazla attribution'a, başarısız olduğunda olanak tanır. Unit 42; victim-facing VPS'ler, relay VPS'leri, residential proxy'ler, Tor ve diğer proxy servislerini kullanan çok katmanlı bir espionage path'i belgeledi. Bir tunnel atlandığında veya çöktüğünde, gizli upstream infrastructure relay ve victim-facing sistemlere doğrudan bağlandı. Aynı investigation, upstream infrastructure üzerinde kısa süreliğine açığa çıkan bir X.509 certificate'ı da tier'lar arası pivot olarak kullandı.<sup>[[14]](#references)</sup>

**Data plane**'i (`victim <-> exit`), **control plane**'den (`operator/upstream -> relay administration`) ayrı tutun. Her owned tier'da ingress ve authentication log'larını, certificate geçmişlerini ve kısa süreli başarısız bağlantıları—yalnızca başarılı C2 session'larını değil—saklayın. Yalnızca relay kesintileri sırasında görünen veya birden fazla victim-facing node'u doğrudan yöneten bir source, sıradan bir exit'ten daha güçlü bir upstream adayıdır; ancak ASN/geolocation hâlâ bir hipotezdir, operator kimliğinin kanıtı değildir.

Yetkili bir lab, workload'un fail closed olmasını sağlamalıdır. Linux network namespace içinde izole edilmiş bir workload için ilk route tunnel'ı kullanmalıdır; tunnel kaldırıldıktan sonra hem request hem de route lookup, physical uplink'i seçmek yerine başarısız olmalıdır:
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
DNS ve IPv6 için testi ve her relay sınırında tekrarlayın. Herhangi bir probe başarılı olursa, policy routing veya firewall'ı düzeltmeden önce gerçek interface/source address'i kaydedin; bu gözlem, bir investigator'ın göreceği attribution leak'tir.

## Redirector tiers and traffic shaping

Public bir **redirector**, operation-specific grammar ile eşleşen trafiği kabul eder ve korumalı bir team server'a iletir. Diğer her şey reddedilebilir veya zararsız içerik sunulabilir.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Birden fazla katman maruziyeti sınırlar: herkese açık bir domain'i yakmak, team server'ı açığa çıkarmak zorunda değildir. CDN'ler anycast kapasitesi ve itibarlı bir dış domain ekler; ancak CDN hesabı ve edge log'ları attribution noktalarına dönüşür. TLS fingerprint'leri, certificate geçmişleri, ayırt edici path'ler/header sırası, response boyutları, redirect davranışı ve origin allowlist'leri, görünüşte ilgisiz front'ları aynı kümede toplayabilir.

Detection için reverse-proxy alanlarını normalization'dan önce kaydedin, SNI/Host/authority değerlerini karşılaştırın, nadir header kombinasyonlarını inceleyin, response body'leri ve TLS fingerprint'lerini kümelendirin ve configuration örtüşmesi için cloud/CDN audit log'larını arayın. Authorized red team'ler gerçek bir brand'i kopyalamaktan veya credential collection'ı ilgisiz bir üçüncü tarafın arkasına yerleştirmekten kaçınmalıdır.

## Domain fronting and domainless fronting

Klasik **domain fronting (T1090.004)** ile TLS bağlantısı SNI'da izin verilen bir front domain'i duyururken, şifrelenmiş HTTP `Host` veya HTTP/2 `:authority`, farklı bir back-end domain'i ister. İşbirliği yapan bir CDN, routing işlemini içteki değere göre gerçekleştirir. TLS decryption yapmayan bir network observer front'u görür; CDN ise her iki değeri ve origin'i görür. Domainless varyantlarda SNI boş olabilir; başka bir routing alanı destination'ı seçer.<sup>[[4]](#references)</sup>

Bu sihirli bir impersonation değildir: yalnızca intermediary uyuşmazlığa kasıtlı olarak veya yanlışlıkla izin verdiğinde ve içteki adı nasıl route edeceğini bildiğinde çalışır. Major provider'lar cross-account fronting'i kısıtlamıştır. Encrypted ClientHello (ECH), on-path observer'ın görebileceklerini değiştirir; ancak CDN, endpoint veya application kayıtlarını ortadan kaldırmaz.

Detection noktaları şunları içerir:

- endpoint process ancestry ve bu application için beklenmeyen destination;
- TLS inspection'ın hukuka uygun ve mevcut olduğu durumlarda SNI ile HTTP authority arasındaki uyuşmazlık;
- bir tenant/front'ın başka bir authority/origin'e routing yaptığını gösteren CDN log'ları;
- normalde interactive olan bir service'e yönelik olağandışı uzun süreli veya periyodik session'lar;
- değişen front domain'leri boyunca sabit şifrelenmiş flow boyutları ve cadence.

Güvenli lab, routing uyuşmazlığını sahip olunan bir reverse proxy üzerinde simüle eder; public CDN'i kötüye kullanmaz.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution, logical service'i sabit infrastructure'dan ayırır:

- **DDNS:** authenticated client, address değiştiğinde stable name'i günceller.
- **DGA:** hem endpoint hem de controller, bir time/key seed'den candidate domain'ler türetir; operator bunların küçük bir alt kümesini register eder.
- **Fast flux:** bir name, çoğunlukla düşük TTL'lerle, hızla değişen bir dizi compromised/proxy address döndürür.
- **Double flux:** hem service address'leri hem de authoritative name-server address'leri rotate edilir; böylece control layer da gizlenir.

Fast flux, adversarial olarak kullanılan bir load-distribution pattern'idir; yalnızca “çok sayıda DNS cevabı” değildir. Daha güçlü kanıt; düşük TTL, yüksek unique-address sayısı, geniş ASN/coğrafya dağılımı, kısa node lifetime, tekrarlanan application davranışı ve şüpheli registration history'nin bir arada değerlendirilmesiyle elde edilir. CDN'ler bu özelliklerin birkaçını meşru şekilde paylaşır. MITRE, DNS davranışının process ve sonraki connection'larla correlation edilmesini önerir.<sup>[[5]](#references)</sup>

Bir DGA; lexical entropy, consonant/digit pattern'leri, NXDOMAIN burst'leri, synchronized first-seen domain'ler ve process context kullanılarak tespit edilebilir. Wordlist DGA'ları ve generative model'ler basit entropy kurallarını aşar; bu nedenle fleet-wide temporal clustering ve endpoint lineage daha önemli hale gelir.

## Compromised domains and domain shadowing

Bir actor, registrar/DNS hesabını hijack edebilir, dangling subdomain'i ele geçirebilir veya başka açıdan itibarlı bir domain'in altına record'lar ekleyebilir. **Domain shadowing**, legitimate apex'i korurken çok sayıda attacker-controlled subdomain'in değişen delivery veya C2 host'larına işaret etmesini sağlar. Domain'in yaşı ve reputation'ından yararlanır ve domain-wide blocking'den kaçabilir.<sup>[[6]](#references)</sup>

Defender'ların registrar ve authoritative-DNS audit log'larına, MFA'ya, registry/registrar lock'larına, yeni delegation/API token/name server'lar için alert'lere, certificate-transparency monitoring'e ve DNS tarafından referans verilen cloud resource envanterine ihtiyacı vardır. Bir subdomain'in resolution ve certificate history'sini apex reputation'ından bağımsız olarak inceleyin.

## Web services and dead-drop resolvers

Bir **dead-drop resolver (T1102.001)**, current C2'ye yönelik encoded pointer'ı legitimate bir post, profile, document, repository, cloud object veya blockchain field içinde saklar. Malware public object'i alır, bir domain/IP'yi decode eder ve sonraki stage'e bağlanır. Bidirectional varyantlar, service API'leri üzerinden command veya file alışverişi yapar.<sup>[[7]](#references)</sup>

Bu yöntem dayanıklılık sağlar ve back-end C2'yi static binary analysis'ten gizler. Ayrıca stable object, tenant, repository, API ve access-pattern identifier'ları oluşturur. Defender'lar aşağıdakileri ilişkilendirmelidir:

1. service'e bağlanan process'i;
2. exact API path/object ve response hash'i;
3. decoding veya string-processing activity'yi;
4. kısa süre sonra gerçekleşen yeni outbound connection'ı; ve
5. fleet'in başka yerlerindeki identical behavior'ı.

Tüm GitHub, cloud storage veya social media'yı block etmek genellikle uygulanabilir değildir. Service-aware egress policy ve process-level correlation, domain-only blocking'den daha iyi sonuç verir.

## Personas, accounts and procurement compartments

Infrastructure anonymity, bir persona, recovery email, phone, payment, browser veya admin IP'si compartment'lar arasında köprü kurduğunda başarısız olur. State-linked operation'lar, kullanımdan çok önce social profile'lar, email identity'leri ve cloud account'lar oluşturmuştur; ATT&CK bunu social, email ve cloud sub-technique'lerini içeren Establish Accounts (T1585) olarak kaydeder.<sup>[[8]](#references)</sup>

Bir defender veya investigator şu kaynaklardan bir graph oluşturur:

- creation ve first-login zamanı, locale, time zone ve çalışma schedule'ı;
- recovery field'ları, MFA device'ları, identity document'ları ve payment instrument'ları;
- browser/TLS fingerprint'leri ve source-network history;
- avatar reuse, image provenance, writing style ve social-graph growth;
- paylaşılan domain registrant, name server, certificate, analytics ID veya repository commit'i;
- public relay architecture'ı bypass eden management-plane action'ları.

Authorized red team için synthetic persona'lar exercise controller'a belgelenmeli, organization-owned recovery/payment channel'ları kullanılmalı, gerçek ve ilgisiz kişilerin impersonation'ından kaçınılmalı ve planlı bir retirement süreci bulunmalıdır. SOC blind kalabilir; ancak operation unaccountable hale gelmemelidir.

## Emerging compound patterns to threat-model

Aşağıdakiler, **defender-driven composition**'lardır; named bir actor'ın her exact design'ı deploy ettiğine dair iddia değildir. Zaten gözlemlenmiş primitive'leri birleştirir ve purple-team hypothesis'leri olarak kullanışlıdır.

### Asymmetric one-way tasking

Command'lar public, broadcast veya append-only bir source üzerinden gelirken result'lar gecikme sonrasında ilgisiz bir channel'dan çıkar. Primitive örnekleri arasında web-service one-way communication ve dead drop'lar bulunur. Ayrıştırma, tek bir flow'un bidirectional görünmesini engeller ve basit request/response correlation'ı zorlaştırır.<sup>[[9]](#references)</sup>

**Detection:** object-level read'leri koruyun; ardından process state change'lerini ve daha sonraki outbound transfer'ları daha geniş bir zaman aralığında correlate edin. Immediate reply gelmese bile aynı public object'i okuyan nadir bir process arayın.

### Multi-stage channel promotion

Sessiz bir first stage inventory gerçekleştirir ve yalnızca seçilen system'leri ilgisiz bir second-stage channel'a promote eder. Second endpoint, protocol ve process, first stage ile hiçbir infrastructure paylaşmayabilir. Bu, capable infrastructure'ın maruziyetini sınırlar ve ATT&CK'te açıkça T1104 olarak modellenir.<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` zincirini birleştirin; ilk domain'i block ettikten sonra incident'ı kapatmayın.

### Cross-protocol relay translation

Farklı hop'lar packet'leri transparently forward etmek yerine HTTPS, QUIC, WebSocket, DNS, SSH veya message-queue API'lerini translate eder. Translation, tek bir end-to-end protocol fingerprint'ini ortadan kaldırır; ancak distinctive timing, buffering ve semantic conversion özelliklerine sahip gateway'ler oluşturur. Protocol tunneling (T1572), proxy'ler ve service impersonation ile birleştirilebilir.<sup>[[11]](#references)</sup>

**Detection:** bir protocol alan ve başka bir protocol başlatan, tightly coupled byte/time behavior gösteren gateway host'larını arayın; endpoint intent'i gerçekten taşınan protocol ile karşılaştırın.

### Passive activation on edge devices

Bir implant beacon göndermek yerine router/VPN'e zaten ulaşan traffic'i izler ve yalnızca magic value, source-port pattern veya authenticated token gördüğünde activate olur. Normal traffic gerçek service'e devam eder. ATT&CK bunu Traffic Signaling (T1205) olarak adlandırır ve network-device ile APT örneklerini belgeler.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, authorized hunt sırasında raw packet capture, beklenmeyen socket filter'ları ve differential service behavior. Periodic beacon bulunmaması, bir edge device'ın temiz olduğunu kanıtlamaz.

### Serverless and ephemeral origin rotation

Bir front stable logical identity'yi korurken short-lived function/container'lar farklı region/account'larda tek tek stage'leri işler. Bu, disk lifetime'ını ve sabit origin IP'lerini azaltır; ancak control-plane creation, image/layer, role, secret, request ID ve billing telemetry kalıcı graph haline gelir.

**Detection:** cloud audit ve invocation log'larını workload dışında saklayın; deployment template'lerini, role'ları, environment key'lerini ve front-to-origin relationship'lerini cluster'layın.

### Privacy-layer diversity

Bir operation kasıtlı olarak tek bir homogeneous chain'den kaçınabilir: örneğin bir channel leased relay kullanır, tasking public object üzerinden yapılır, exit owned lab cellular link'ten gelir ve administration ayrı bir organization network'ü kullanır. Bu, tek bir provider'ın compromise edilmesinin değerini azaltır; ancak cross-layer timing ve operational-error riskini artırır.

**Detection:** identity, DNS, SaaS, network ve cloud sensor'ları boyunca campaign timeline'ları oluşturun. Identical indicator'lar yerine synchronized state transition'ları arayın.

### Decentralized or transparency-log dead drops

Bir actor, küçük bir encrypted pointer'ı herhangi bir durable public append-only system'e, content-addressed store'a veya transparency-like feed'e yerleştirebilir. Public object dayanıklıdır; ancak exact index/content hash ve client polling behavior stable identifier'lara dönüşür.

**Detection:** full API/object identifier'larını ve response hash'lerini kaydedin; immutable object'leri poll eden nonstandard process'lerin ardından decoding veya yeni connection'lar gelmesi durumunda alert üretin.

### Delayed store-and-forward operations

Interactive C2 güçlü timing correlation oluşturur. Store-and-forward design, encrypted job'ları batch'ler ve result'ları dakikalar veya saatler sonra farklı bir queue ya da physical transfer üzerinden döndürür. Daha zayıf end-to-end timing karşılığında responsiveness'tan vazgeçer.

**Detection:** correlation window'larını uzatın, periodic queue access'i modelleyin ve endpoint staging'i inceleyin. Batching, signal'i packet timing'den scheduled process/file behavior'a taşır; onu ortadan kaldırmaz.

## Design review: think in observers

Her path için deployment öncesinde ve collection sonrasında aşağıdaki tabloyu doldurun:

| Katman | Source'u görür mü? | Destination'ı görür mü? | Content'i görür mü? | Stable identifier'lar | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Tek bir ordinary provider her sütunu doldurabiliyorsa architecture, target'tan concealment sağlar ancak sağlam separation sağlamaz. Hiçbir internal controller activity'yi bir engagement'a geri map edemiyorsa bu architecture professional red teaming için uygun değildir.

## References

- [1] [MITRE ATT&CK — Infrastructure Edinme (T1583), Infrastructure Compromise (T1584) ve Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actor'ları ORB network'lerini kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastructure Compromise: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Account Establishment (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Dünyanın En Büyük Residential Proxy Network'ünü Disrupt Etmek](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: Global Espionage'ı Ortaya Çıkarmak](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
