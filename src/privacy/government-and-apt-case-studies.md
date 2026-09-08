# Hükümet ve APT Vaka Çalışmaları

{{#include ../banners/hacktricks-training.md}}

Bu kamuya açık vakalar, ayrı privacy tekniklerinin gerçek operasyonlarda nasıl birleştirildiğini gösterir. Attribution etiketleri, alıntılanan araştırmacılar veya hükümetler tarafından kullanılan etiketlerdir; tek başına bir IP adresi, tool örtüşmesi veya jeopolitik uyum kesin attribution kanıtı değildir.

## APT28: uzaktan en yakın komşu Wi-Fi erişimi

**Kamuya açık bulgu.** Volexity, 2022'deki bir intrusion'ı GruesomeLarch/APT28 ile ilişkilendirdi. Validated bir credential ile Internet erişimi MFA tarafından durdurulduktan sonra actor, hedefin yakınındaki kuruluşları compromise etti ve yakındaki dual-homed bir host üzerinden hedefin enterprise Wi-Fi ağına ulaştı. Wi-Fi yolu, dışarıdan gerekli olan MFA olmadan credential'ı kabul etti.<sup>[[1]](#references)</sup>

**Privacy etkisi.** Son erişim fiziksel radyo menzilinden kaynaklandı ve aradaki kuruluşlar victim durumundaydı. Operasyon seyahati önledi ve conventional IP geolocation'ın komşuyu işaret etmesine neden oldu.

**Bunu açığa çıkaran şey.** Target alert'i, host/network investigation, credential activity, interface topology ve fiziksel yakınlık tek bir chain olarak analiz edilmek zorundaydı. Anormal olan yalnızca yeni bir IP değildi; nearby sistemler compromise edilirken legitimate bir identity'nin unusual bir Wi-Fi/device context üzerinden gelmesiydi.

**Defensive lesson.** Wi-Fi için certificate/device-backed access uygulayın, RADIUS'u NAC/MDM ve fiziksel context ile correlate edin ve son hop'un operator olduğunu varsaymak yerine komşu infrastructure'ı investigate edin.

## APT28: GRU tarafından yeniden kullanılan criminal Moobot infrastructure'ı

**Kamuya açık bulgu.** Şubat 2024'te US Department of Justice, yüzlerce Ubiquiti EdgeOS router'dan oluşan bir botnet'i açıkladı. Criminal actor'lar, bilinen default administrator credential'larını koruyan router'lara Moobot yüklemişti; GRU Unit 26165 daha sonra script'ler ve file'lar ekleyerek mevcut bir criminal botnet'i spearphishing ve credential theft için kullanılan bir espionage platform'una dönüştürdü.<sup>[[2]](#references)</sup>

**Privacy etkisi.** GRU tüm infrastructure'ı kendisi kurmadı. Zaten compromise edilmiş bir fleet'i kullanmak, actor ile target'lar arasına ilgisiz home ve small-office adresleri yerleştirdi, devlet faaliyetlerini criminal activity ile karıştırdı ve actor'a özgü registration artifact'larını azalttı.

**Bunu açığa çıkaran şey.** Router file'ları, malware control behavior ve non-content routing information investigation'ı destekledi. Disruption, firewall rule'larını geçici olarak değiştirdi ve malicious file'ları kaldırdı; DOJ ise değiştirilmemiş default credential'ların reinfection'a izin verebileceği konusunda uyardı.

**Defensive lesson.** Desteklenmeyen router'ları değiştirin, Internet'e açık administration'ı kaldırın, default'ları değiştirin, patch uygulayın, edge-device configuration/flow data toplayın ve fleet behavior için hunt yapın. “Residential US IP”, US operator kanıtı değildir.

## Volt Typhoon: KV Botnet ve living off the land

**Kamuya açık bulgu.** DOJ ve ortak bir CISA advisory'si, PRC state-sponsored Volt Typhoon'un, critical infrastructure'ı hedefleyen activity'nin PRC origin'ini gizlemek için öncelikle compromise edilmiş, kullanım ömrünün sonuna gelmiş Cisco ve NETGEAR SOHO router'larından oluşan KV Botnet'i kullandığını açıkladı. Victim'ların içinde actor, valid account'ları ve built-in administration tool'larını tercih etti; kurumlar bazı environment'larda access'in en az beş yıl sürdüğünü bildirdi.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Gizlilik etkisi.** ORB benzeri yol, erişim sonrasında origin'i gizlerken living-off-the-land yaklaşımı yeni binary'leri ve signature fırsatlarını azalttı. Network ve endpoint gizliliği birbirini güçlendirdi.

**Bunu açığa çıkaranlar.** Router/controller yapısı, mahkeme yetkili teknik izleme, tekrarlanan etkinlik ve kurbanlar arası analiz, tek bir IOC'den daha önemliydi. Açıklanan vakalarda router'ı yeniden başlatmak volatile KV malware'i kaldırdı, ancak cihazın temel end-of-life riskini düzeltmedi.

**Savunma dersi.** EOL edge device'ları değiştirin, authentication ve network-device log'larını merkezileştirin, administrator davranışı için baseline oluşturun, outbound connectivity'yi kısıtlayın ve identity, endpoint ile network katmanları arasındaki davranışsal dizileri araştırın.

## China-nexus ORB networks: infrastructure as a service

**Public finding.** Mandiant, birden fazla China-nexus espionage actor tarafından kullanılan ORB network'lerinden oluşan bir ekosistem tanımladı. Provisioned network'ler kiralanmış VPS node'ları kullanırken, non-provisioned network'ler ele geçirilmiş IoT ve router'ları kullandı; hybrid network'ler bunları birleştirdi. ORB3/SPACEHOP, APT5/APT15 ile ilişkilendirilen etkinlikleri destekledi. ORB2/FLORAHOX; bir administration server, kiralanmış server'lar, özelleştirilmiş bir Tor layer ve ele geçirilmiş Cisco, ASUS ve DrayTek cihazlarını birleştirdi. Mandiant, bazı network'lerin bağımsız olarak yönetildiğini ve birden fazla APT actor'a kiralandığını değerlendirdi.<sup>[[5]](#references)</sup>

**Privacy effect.** Infrastructure bir service boundary haline geldi. Bir operator, victim fleet'ini korumadan geographic/residential exit'ler elde edebilirken, bunu paylaşan çok sayıda customer basit actor-to-IP eşleştirmesini zayıflattı. Fleet'in hızlı şekilde değiştirilmesi “IOC extinction” sürecini hızlandırdı.

**What exposed it.** Network topography, cloned server image'ları, port/service'ler, controller ilişkileri, router implant'ları ve lifecycle pattern'leri cluster edilebilir olmaya devam etti. Mandiant, bazı node IP'lerinin bir ORB içinde 31 gün kadar kısa süre kaldığını bildirdi.

**Defensive lesson.** Bir ORB'yi değişen bir entity olarak izleyin: node rolleri, service fingerprint'leri, upstream ilişkileri, scan davranışı ve rotation ritmi. Bir IP indicator'ının süresinin dolması cluster'ı güncellemeli, vakayı silmemelidir.

## PRC global espionage system: routers, trusted links and traffic mirroring

**Public finding.** 2025 tarihli çok uluslu bir advisory, Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 ve GhostEmperor dahil olmak üzere commercial reporting'de kullanılan adlarla örtüşen bir etkinliği tanımladı. Kurumlar, telecommunications ve network provider'lara ulaşmak için kiralanmış VPS'lerin ve ele geçirilmiş intermediate router'ların kullanıldığını bildirdi. Actor'ler trusted provider/customer link'leri üzerinden pivot etti, route'ları değiştirdi, GRE/IPsec tunnel'ları oluşturdu, device container'ları kullandı ve authentication ile customer traffic'i toplamak için SPAN/RSPAN/ERSPAN veya native packet capture'ı etkinleştirdi.<sup>[[13]](#references)</sup>

**Privacy effect.** Ele geçirilmiş bir router aynı anda relay, observation point ve trusted network participant görevi görür. Private interconnection'lar public Internet etrafında tasarlanmış kontrolleri aşabilir; traffic mirroring ise endpoint agent deploy etmeden credential'ları toplayabilir.

**What exposes it.** Configuration diff'leri, beklenmeyen SNMP/SSH/web administration, yeni static route/tunnel'lar, mirror session'lar, Guest Shell container'ları, PCAP file'ları, TACACS+/RADIUS destination değişiklikleri ve devre dışı bırakılmış logging. Advisory, bazı intermediate router'ların daha önce adı açıklanmış bir public botnet'in parçası olmadığını vurgular; bu nedenle bilinen ORB indicator'larının bulunmaması aklayıcı değildir.

**Defensive lesson.** Out-of-band administration, merkezi configuration/authentication log'ları, signed-image ve runtime integrity kontrolleri, management-interface egress kısıtlamaları ve route/mirror/tunnel/AAA değişiklikleri için alert'ler kullanın. Şüpheli bir compromise'ı eviction öncesinde trusted peer'lar genelinde kapsamlandırın.

## UNC3886 RedPenguin: passive backdoors on ISP routers

**Public finding.** Mandiant, end-of-life Juniper MX router'larındaki özel TINYSHELL-derived backdoor'ları UNC3886'ya atfetti. Set, active ve passive implant'ları, meşru daemon'ları taklit eden adları, log-disabling davranışını, trusted process'e process injection'ı, SOCKS proxy yeteneğini ve ORB staging node'ları olarak değerlendirilen infrastructure'ı içeriyordu. Passive variant'lar `libpcap` üzerinden packet'leri inceledi ve yalnızca bir magic pattern sonrasında etkinleşti; bunlardan biri trigger'da sağlanan active callback'e geçebiliyordu.<sup>[[14]](#references)</sup>

**Privacy effect.** Passive implant'ın keşfedilecek periyodik bir beacon'ı yoktur. Gerçek bir network appliance ile port/traffic paylaşır, kısa süreliğine etkinleşir ve doğrudan nihai controller'a bağlanmak yerine bir ORB üzerinden relay yapabilir.

**What exposes it.** Memory analysis, disk üzerindeki ve çalışan code arasındaki farklılıklar, beklenmeyen packet-capture filter/socket davranışı, yalnızca meşru daemon'lara yaklaşık olarak benzeyen process/file adları, terminal server'lar üzerinden administration, eksik log'lar ve staging node'lar ile backend controller arasındaki iki aşamalı ilişki.

**Defensive lesson.** Filesystem/configuration kanıtlarının yanı sıra memory de edinin, process/module'leri bilinen iyi bir image ile karşılaştırın, packet-capture/socket-filter kullanımını izleyin, management terminal server'larını güvenli hale getirin ve EOL network hardware'ını değiştirin. Temiz bir outbound-beacon araştırması, sistemin tamamen güvenli olduğu anlamına gelmez.

## APT29: Tor domain fronting

**Public finding.** MITRE, APT29'un C2 traffic'ini domain-front etmek için `meek` Tor pluggable transport kullandığını kaydeder. Dış TLS name'i izin verilen CDN-hosted bir domain gibi görünürken, iç HTTP host gerçek route'u seçiyordu.<sup>[[6]](#references)</sup>

**Privacy effect.** Filtering yapan bir observer, iç destination yerine yaygın bir front/CDN görebilir ve bunu engellemek collateral damage riski yaratabilirdi.

**What exposes it.** CDN routing mismatch'i gözlemleyebilir; endpoint veya lawful TLS visibility sahibi bir defender ise process, authority, connection lifetime, byte pattern ve sonraki etkinliği ilişkilendirebilir. Provider policy değişiklikleri tekniği devre dışı bırakabilir.

**Defensive lesson.** Yalnızca SNI allowlisting'e güvenmeyin. Application-aware egress uygulayın, görülebildiği durumlarda TLS ve HTTP identity'lerini karşılaştırın ve network event'ini başlatan process ile ilişkilendirin.

## APT41 and other dead-drop resolvers

**Public finding.** MITRE, APT41'in C2 bilgilerini yayınlamak veya almak için GitHub, Pastebin, Microsoft TechNet, Cloudflare ve community forum'ları dahil meşru siteleri kullandığını belgeler. State-linked diğer tooling'ler de benzer şekilde post, document ve social media kullanmıştır.<sup>[[7]](#references)</sup>

**Privacy effect.** Bir binary, sabit bir C2 address yerine meşru bir service/object içerir. Object, infrastructure'ı değiştirmek için düzenlenebilir ve ilk request yaygın TLS traffic'i içinde kaybolur.

**What exposes it.** Object veya account identifier sabittir; nadir process'ler bunu tekrar tekrar fetch eder; content decode edilir ve ardından ikinci bir outbound connection gerçekleşir. Provider account ve API record'ları publication'ı operator'e bağlayabilir.

**Defensive lesson.** Tam proxy path'lerini/object ID'lerini ve endpoint process lineage'ını koruyun. “GitHub'a bağlandı” gibi domain-level bir event fazla kabadır.

## Turla: satellite-address C2

**Public finding.** Kaspersky, Turla'nın eski tek yönlü DVB-S Internet service'lerinden gelen şifrelenmemiş downstream broadcast'leri kötüye kullandığını bildirdi. Satellite footprint içindeki bir operator, meşru bir subscriber address seçip bu adrese broadcast edilen reply'leri alabiliyordu; böylece C2, farklı bir region'daki satellite provider'ın arkasında host ediliyor gibi görünüyordu.<sup>[[8]](#references)</sup>

**Privacy effect.** Görünen server address receiver'ı tanımlamıyordu ve geleneksel hosting seizure/WHOIS süreçleri daha az faydalıydı.

**What exposes it.** Actor yine de bir outbound request path'ine ihtiyaç duyuyordu; routing asimetrikti; meşru subscriber C2 exchange'i başlatmıyordu ve RF/provider investigation receiving footprint'i daraltabilirdi.

**Defensive lesson.** Geolocation'ı yalnızca hipotezlerden biri olarak ele alın. Path symmetry, RTT, routing ownership ve iddia edilen endpoint'in gözlemlenen service'i gerçekten üretip üretemeyeceğini doğrulayın.

## Cyclops Blink and VPNFilter: edge devices as durable cover

**Public finding.** 2022 tarihli bir NCSC/CISA/FBI/NSA advisory, Sandworm'un WatchGuard cihazlarındaki modular Cyclops Blink malware'ini tanımladı. Bu malware firmware update olarak kalıcı biçimde deploy ediliyor ve module ekleyebiliyordu. DOJ ayrıca APT28'in daha önceki router ve NAS device botnet'i VPNFilter'ı intelligence collection, destructive activity ve misattribution gerçekleştirebilen bir yapı olarak tanımladı.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Privacy effect.** Edge appliance'lar sürekli online'dır, infrastructure olarak trusted durumdadır ve EDR tarafından yetersiz şekilde kapsanır. Firmware persistence sıradan bir restart sonrasında varlığını sürdürebilir ve victim device'ı relay veya control point haline getirebilir.

**What exposes it.** Firmware integrity, vendor-specific implant protocol, beklenmeyen management exposure, configuration değişiklikleri ve outbound beaconing. Edge device'lar şeffaf plumbing değil, forensic subject olarak ele alınmalıdır.

## DPRK: identity, network and financial layering

**Public finding.** DOJ vakaları, DPRK worker'larının false veya stolen identity material ve VPN kullanarak remote job'lar elde ettiğini, cryptocurrency aldığını, transferleri böldüğünü, asset/chain swap yaptığını, NFT kullandığını ve proceeds'i commingle ettiğini açıklar. Diğer vakalar, OTC trader'ların ve front company'lerin stolen crypto'yu satın alımlara dönüştürdüğünü açıklar. Treasury ve FBI, Lazarus/TraderTraitor proceeds'lerini mixer'lara public olarak bağlamış ve büyük theft'lerden elde edilen address'leri tanımlamıştır.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Privacy effect.** Bu “a private coin” değildir. Bu, çok alanlı bir chain'dir: persona ve remote access worker location'ını gizler; crypto value taşır; layering basit transaction anlatılarını koparır; OTC trader'lar/front company'ler goods ve fiat'a geçiş sağlar.

**What exposes it.** Employer/device anomaly'leri, yeniden kullanılan facilitator'lar, blockchain timing/value continuity, exchange/bridge record'ları, sanctioned address'ler, account identity ve shipment/company record'ları chain'i yeniden birbirine bağlar.

**Defensive lesson.** Hiring, IAM, endpoint, payroll, blockchain ve sanctions ekiplerinin ortak bir case model'ine ihtiyacı vardır. Daha fazla ayrıntı [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) bölümünde yer alır.

## Cross-case patterns

| Pattern | APT examples | Defender adaptation |
|---|---|---|
| Exit başka bir victim'dır | APT28/Moobot, Volt Typhoon/KV, ORB'ler | exit'i investigate ve remediate edin; onu actor location'ı ile eşitlemeyin |
| Kontroller boundary'ye göre farklılaşır | APT28 nearest neighbor | internal/wireless access'e Internet access ile aynı identity assurance'ı sağlayın |
| Meşru service bir routing layer'dır | APT29, APT41 | yalnızca destination domain'i değil, object/path/process context'i koruyun |
| Edge device'larda telemetry yoktur | KV, Moobot, Cyclops Blink, ORB'ler | config/auth/flow log'larını merkezileştirin ve firmware/inventory'yi doğrulayın |
| Infrastructure paylaşılır ve kısa ömürlüdür | China-nexus ORB'leri | behavior/topology'yi cluster edin ve role change'lerini zaman içinde izleyin |
| Birkaç zayıf ayrım birleşir | DPRK persona'ları + VPN + crypto + OTC | identity, device, network, payment ve physical evidence'ı birleştirin |

## References

- [1] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — GRU-controlled Moobot router botnet'inin engellenmesi](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — PRC KV Botnet'inin engellenmesi](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — PRC actor'leri US critical infrastructure'a compromise gerçekleştiriyor ve kalıcı erişimi sürdürüyor](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — China-nexus espionage actor'leri ORB network'lerini kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops Blink advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — APT28 VPNFilter disruption](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Blender.io sanctions and Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Chinese state-sponsored actor'lerin dünya genelindeki network'leri compromise etmesine karşı koyma](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 Juniper router'larını hedefliyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
