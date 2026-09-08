# Government and APT Vaka Çalışmaları

Bu kamuya açık vakalar, ayrı privacy tekniklerinin gerçek operasyonlarda nasıl birleştirildiğini gösterir. Attribution etiketleri, adı geçen araştırmacılar veya hükümetler tarafından kullanılan etiketlerdir; tek başına bir IP adresi, tool örtüşmesi veya jeopolitik uyum kesin attribution kanıtı değildir.

## APT28: uzaktan en yakın komşu Wi-Fi erişimi

**Kamuya açık bulgu.** Volexity, 2022 yılında gerçekleşen bir intrusion'ı GruesomeLarch/APT28'e atfetti. Doğrulanmış bir credential ile Internet erişimi MFA tarafından durdurulduktan sonra actor, hedefin yakınındaki kuruluşları compromise etti ve yakındaki dual-homed bir host üzerinden hedefin kurumsal Wi-Fi ağına ulaştı. Wi-Fi yolu, dışarıdan gerekli olan MFA olmadan credential'ı kabul etti.<sup>[[1]](#references)</sup>

**Privacy etkisi.** Son erişim fiziksel radyo menzilinden kaynaklandı ve aradaki kuruluşlar victim durumundaydı. Operasyon seyahat gerektirmedi ve conventional IP geolocation'ın bir komşuyu göstermesine neden oldu.

**Bunu açığa çıkaranlar.** Hedef alert'i, host/network investigation'ı, credential activity'si, interface topology'si ve fiziksel yakınlık tek bir zincir olarak analiz edilmek zorundaydı. Anormal olan yalnızca yeni bir IP değildi; meşru bir identity'nin, yakındaki sistemler compromise edilmişken alışılmadık bir Wi-Fi/device context üzerinden gelmesiydi.

**Defensive lesson.** Wi-Fi erişimine certificate/device-backed access uygulayın, RADIUS'u NAC/MDM ve fiziksel context ile correlate edin ve son hop'un operator olduğunu varsaymak yerine komşu altyapıyı investigate edin.

## APT28: GRU tarafından yeniden kullanılan criminal Moobot altyapısı

**Kamuya açık bulgu.** Şubat 2024'te US Department of Justice, yüzlerce Ubiquiti EdgeOS router'dan oluşan bir botnet'i tanımladı. Criminal actor'ler, bilinen default administrator credential'larını koruyan router'lara Moobot yüklemişti; GRU Unit 26165 daha sonra script ve file'lar ekleyerek mevcut bir criminal botnet'i spearphishing ve credential theft için kullanılan bir espionage platformuna dönüştürdü.<sup>[[2]](#references)</sup>

**Privacy etkisi.** GRU tüm altyapıyı kendisi oluşturmadı. Önceden compromise edilmiş bir fleet'i kullanmak, actor ile hedeflerin arasına ilgisiz ev ve küçük ofis adresleri yerleştirdi, state activity ile criminal activity'yi birbirine karıştırdı ve actor'a özgü registration artifact'larını azalttı.

**Bunu açığa çıkaranlar.** Router file'ları, malware control behavior'ı ve content içermeyen routing information investigation'ı destekledi. Disruption, firewall rule'larını geçici olarak değiştirdi ve malicious file'ları kaldırdı; DOJ ise değiştirilmemiş default credential'ların reinfection'a izin verebileceği konusunda uyardı.

**Defensive lesson.** Desteklenmeyen router'ları değiştirin, Internet'e açık administration'ı kaldırın, default'ları değiştirin, patch uygulayın, edge-device configuration/flow data toplayın ve fleet behavior için hunt yapın. “Residential US IP” bir US operator kanıtı değildir.

## Volt Typhoon: KV Botnet ve living off the land

**Kamuya açık bulgu.** DOJ ve ortak bir CISA advisory'si, PRC destekli Volt Typhoon'un kritik altyapıyı hedef alan activity'nin PRC kaynaklı olduğunu gizlemek için, çoğunlukla compromise edilmiş kullanım ömrü sona ermiş Cisco ve NETGEAR SOHO router'larından oluşan KV Botnet'i kullandığını açıkladı. Victim'ların içinde actor, valid account'ları ve yerleşik administration tool'larını tercih etti; kurumlar bazı ortamlarda erişimin en az beş yıl sürdüğünü bildirdi.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Gizlilik etkisi.** ORB benzeri yol, erişim sonrasında living-off-the-land yaklaşımı yeni binary'leri ve signature fırsatlarını azaltırken kaynağı gizledi. Network ve endpoint gizliliği birbirini güçlendirdi.

**Bunu açığa çıkaran şey.** Router/controller yapısı, mahkeme onaylı teknik izleme, tekrarlanan etkinlik ve kurbanlar arası analiz, tek bir IOC'den daha önemliydi. Açıklanan vakalarda router'ı yeniden başlatmak volatile KV malware'i kaldırdı, ancak cihazın temel end-of-life riskini düzeltmedi.

**Savunma dersi.** EOL edge cihazlarını değiştirin, authentication ve network-device loglarını merkezileştirin, administrator davranışı için baseline oluşturun, outbound connectivity'yi kısıtlayın ve identity, endpoint ve network katmanları arasındaki davranış dizilerini hunt edin.

## China-nexus ORB networks: infrastructure as a service

**Public finding.** Mandiant, birden fazla China-nexus espionage actor tarafından kullanılan ORB networks ekosistemini tanımladı. Provisioned networks, kiralanmış VPS node'ları kullandı; non-provisioned networks, ele geçirilmiş IoT ve router'ları kullandı; hybrid networks ise bunları birleştirdi. ORB3/SPACEHOP, APT5/APT15 ile ilişkili activity'yi destekledi. ORB2/FLORAHOX; bir administration server, kiralanmış server'lar, özelleştirilmiş bir Tor layer ve ele geçirilmiş Cisco, ASUS ve DrayTek cihazlarını birleştirdi. Mandiant, bazı network'lerin bağımsız olarak yönetildiğini ve birden fazla APT actor'a kiralandığını değerlendirdi.<sup>[[5]](#references)</sup>

**Gizlilik etkisi.** Infrastructure bir service boundary haline geldi. Tek bir operator, victim fleet'ini korumadan coğrafi/konut tipi exit'ler edinebilirken, aynı infrastructure'ı paylaşan çok sayıda müşteri basit actor-to-IP eşleştirmesini zorlaştırdı. Fleet'in hızlı şekilde değiştirilmesi “IOC extinction” sürecini hızlandırdı.

**Bunu açığa çıkaran şey.** Network topography, klonlanmış server image'ları, port/service'ler, controller ilişkileri, router implant'ları ve lifecycle pattern'leri cluster'lanabilir olmaya devam etti. Mandiant, bazı node IP'lerinin bir ORB içinde 31 gün kadar kısa süre kaldığını bildirdi.

**Savunma dersi.** Bir ORB'yi değişen bir entity olarak takip edin: node rolleri, service fingerprint'leri, upstream ilişkileri, scan davranışı ve rotation ritmi. Süresi dolan bir IP indicator'ı cluster'ı güncellemeli, vakayı silmemelidir.

## PRC global espionage system: routers, trusted links and traffic mirroring

**Public finding.** 2025 tarihli çok uluslu bir advisory, Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 ve GhostEmperor dahil olmak üzere commercial reporting'de kullanılan adlarla örtüşen activity'yi tanımladı. Kurumlar, telecommunications ve network provider'lara ulaşmak için kiralanmış VPS'ler ve ele geçirilmiş intermediate router'lar kullanıldığını bildirdi. Actor'ler trusted provider/customer link'leri üzerinden pivot etti, route'ları değiştirdi, GRE/IPsec tunnel'ları oluşturdu, device container'ları kullandı ve authentication ile customer traffic'i toplamak için SPAN/RSPAN/ERSPAN veya native packet capture'ı etkinleştirdi.<sup>[[13]](#references)</sup>

**Gizlilik etkisi.** Ele geçirilmiş bir router aynı anda relay, observation point ve trusted network participant olarak işlev görür. Private interconnection'lar public Internet etrafında tasarlanan kontrolleri aşabilirken, traffic mirroring bir endpoint agent dağıtmadan credential'ları toplar.

**Bunu açığa çıkaran şey.** Configuration diff'leri, beklenmeyen SNMP/SSH/web administration, yeni static route/tunnel'lar, mirror session'ları, Guest Shell container'ları, PCAP dosyaları, TACACS+/RADIUS destination değişiklikleri ve devre dışı bırakılmış logging. Advisory, bazı intermediate router'ların daha önce adı açıklanmış public botnet'lerin parçası olmadığını vurgular; bu nedenle bilinen ORB indicator'larının bulunmaması aklayıcı değildir.

**Savunma dersi.** Out-of-band administration, merkezi configuration/authentication log'ları, signed-image ve runtime integrity kontrolleri, management-interface egress kısıtlamaları ve route/mirror/tunnel/AAA değişiklikleri için alert'ler kullanın. Şüpheli bir compromise'ın kapsamını eviction işleminden önce trusted peer'lar genelinde belirleyin.

## UNC3886 RedPenguin: passive backdoors on ISP routers

**Public finding.** Mandiant, end-of-life Juniper MX router'lar üzerindeki custom TINYSHELL-derived backdoor'ları UNC3886'ya bağladı. Set içerisinde active ve passive implant'lar, legitimate daemon'ları taklit eden adlar, log-disabling davranışı, trusted process'e process injection, SOCKS proxy yeteneği ve ORB staging node'ları olduğu değerlendirilen infrastructure bulunuyordu. Passive variant'lar `libpcap` üzerinden packet'leri inceledi ve yalnızca bir magic pattern sonrasında etkinleşti; bunlardan biri trigger içinde sağlanan active callback'e geçebiliyordu.<sup>[[14]](#references)</sup>

**Gizlilik etkisi.** Passive implant'ın keşfedilmesini sağlayacak periodic beacon'ı yoktur. Gerçek bir network appliance ile port'ları/traffic'i paylaşır, kısa süreliğine etkinleşir ve doğrudan ultimate controller'a bağlanmak yerine bir ORB üzerinden relay yapabilir.

**Bunu açığa çıkaran şey.** Memory analysis, disk üzerindeki kod ile çalışan kod arasındaki farklar, beklenmeyen packet-capture filter/socket davranışı, legitimate daemon'lara yalnızca yaklaşık olarak benzeyen process/file adları, terminal server'lar üzerinden administration, eksik log'lar ve staging node'ları ile backend controller arasındaki two-stage ilişki.

**Savunma dersi.** Filesystem/configuration kanıtlarının yanı sıra memory de edinin, process/module'leri bilinen-good image ile karşılaştırın, packet-capture/socket-filter kullanımını izleyin, management terminal server'larını güvence altına alın ve EOL network hardware'ini değiştirin. Temiz bir outbound-beacon hunt'ı, sistemin tamamen güvenli olduğuna dair kanıt değildir.

## APT29: Tor domain fronting

**Public finding.** MITRE, APT29'un C2 traffic'ini domain-front etmek için `meek` Tor pluggable transport kullandığını kaydeder. Dış TLS name'i izin verilen CDN-hosted bir domain gibi görünürken, iç HTTP host gerçek route'u seçiyordu.<sup>[[6]](#references)</sup>

**Gizlilik etkisi.** Filtering yapan bir observer, iç destination yerine ortak bir front/CDN görebilir ve bunu engellemek collateral damage riski doğurabilirdi.

**Bunu açığa çıkaran şey.** CDN routing mismatch'i gözlemleyebilir; endpoint veya lawful TLS visibility'e sahip bir defender ise process, authority, connection lifetime, byte pattern ve sonraki activity'yi correlate edebilir. Provider policy değişiklikleri technique'i devre dışı bırakabilir.

**Savunma dersi.** Yalnızca SNI allowlisting'e güvenmeyin. Application-aware egress uygulayın, görünür olduğu yerlerde TLS ve HTTP identity'lerini karşılaştırın ve network event'ini başlatan process ile birleştirin.

## APT41 and other dead-drop resolvers

**Public finding.** MITRE, APT41'in C2 information yayınlamak veya almak için GitHub, Pastebin, Microsoft TechNet, Cloudflare ve community forum'ları dahil legitimate site'ları kullandığını belgeler. State-linked diğer tooling'ler de posts, documents ve social media'yı benzer şekilde kullanmıştır.<sup>[[7]](#references)</sup>

**Gizlilik etkisi.** Bir binary, stable bir C2 address yerine legitimate bir service/object içerir. Object, infrastructure'ı rotate etmek için düzenlenebilir ve ilk request yaygın TLS traffic'i içinde kaybolur.

**Bunu açığa çıkaran şey.** Object veya account identifier sabittir; nadir kullanılan process'ler bunu tekrar tekrar fetch eder; content decode edilir ve ardından ikinci bir outbound connection gelir. Provider account ve API kayıtları publication'ı operator ile ilişkilendirebilir.

**Savunma dersi.** Tam proxy path'lerini/object ID'lerini ve endpoint process lineage'ını koruyun. “GitHub'a bağlandı” gibi domain-level bir event fazla geneldir.

## Turla: satellite-address C2

**Public finding.** Kaspersky, Turla'nın eski one-way DVB-S Internet service'lerinden gelen şifrelenmemiş downstream broadcast'leri kötüye kullandığını bildirdi. Satellite footprint içindeki bir operator, legitimate bir subscriber address seçerek o adrese broadcast edilen yanıtları alabilir; böylece C2, farklı bir bölgedeki satellite provider arkasında hosted görünürdü.<sup>[[8]](#references)</sup>

**Gizlilik etkisi.** Görünürdeki server address receiver'ı tanımlamıyordu ve geleneksel hosting seizure/WHOIS süreçleri daha az faydalıydı.

**Bunu açığa çıkaran şey.** Actor'ün hâlâ bir outbound request path'ine ihtiyacı vardı, routing asymmetric'ti, legitimate subscriber C2 exchange'i başlatmıyordu ve RF/provider investigation receiving footprint'i daraltabilirdi.

**Savunma dersi.** Geolocation'ı yalnızca hipotezlerden biri olarak değerlendirin. Path symmetry, RTT, routing ownership ve iddia edilen endpoint'in gözlemlenen service'i gerçekten üretip üretemeyeceğini doğrulayın.

## Cyclops Blink and VPNFilter: edge devices as durable cover

**Public finding.** 2022 tarihli bir NCSC/CISA/FBI/NSA advisory, Sandworm'un WatchGuard cihazları üzerindeki modular Cyclops Blink malware'ini tanımladı. Malware, firmware update olarak persistently deploy ediliyor ve module ekleyebiliyordu. DOJ ayrıca APT28'in daha önceki router ve NAS device botnet'i VPNFilter'ın intelligence collection, destructive activity ve misattribution yapabildiğini açıkladı.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Gizlilik etkisi.** Edge appliance'lar sürekli online'dır, infrastructure olarak trusted kabul edilir ve EDR tarafından yetersiz şekilde kapsanır. Firmware persistence, ordinary restart'tan sonra varlığını sürdürebilir ve victim device'ı relay veya control point'e dönüştürebilir.

**Bunu açığa çıkaran şey.** Firmware integrity, vendor-specific implant protocol, beklenmeyen management exposure, configuration değişiklikleri ve outbound beaconing. Edge device'lar transparent plumbing değil, forensic subject olarak ele alınmalıdır.

## DPRK: identity, network and financial layering

**Public finding.** DOJ vakaları, DPRK workers'ın false veya stolen identity material ve VPN kullanarak remote jobs elde ettiğini, cryptocurrency aldığını, transferleri böldüğünü, asset/chain swap yaptığını, NFT kullandığını ve proceeds'leri commingle ettiğini açıklar. Diğer vakalar, OTC trader'ların ve front company'lerin stolen crypto'yu purchases'a dönüştürdüğünü anlatır. Treasury ve FBI, Lazarus/TraderTraitor proceeds'lerini mixer'lara publicly bağlamış ve major theft'lerden elde edilen address'leri tanımlamıştır.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Gizlilik etkisi.** Bu, “private coin” değildir. Bu, multi-domain bir chain'dir: persona ve remote access worker location'ı gizler; crypto value'yu taşır; layering basit transaction narrative'lerini bozar; OTC trader'lar/front company'ler goods ve fiat'a geçiş sağlar.

**Bunu açığa çıkaran şey.** Employer/device anomalileri, yeniden kullanılan facilitator'lar, blockchain timing/value continuity, exchange/bridge kayıtları, sanctioned address'ler, account identity ve shipment/company kayıtları chain'i yeniden birleştirir.

**Savunma dersi.** Hiring, IAM, endpoint, payroll, blockchain ve sanctions ekiplerinin ortak bir case model'e ihtiyacı vardır. Daha fazla ayrıntı [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) bölümünde yer alır.

## Cross-case patterns

| Pattern | APT examples | Defender adaptation |
|---|---|---|
| Exit başka bir victim'dır | APT28/Moobot, Volt Typhoon/KV, ORBs | exit'i investigate ve remediate edin; onu actor location'ı ile eşitlemeyin |
| Controls boundary'ye göre farklıdır | APT28 nearest neighbor | internal/wireless access'e Internet access ile aynı identity assurance seviyesini sağlayın |
| Legitimate service bir routing layer'dır | APT29, APT41 | yalnızca destination domain'ı değil, object/path/process context'ini de saklayın |
| Edge device'larda telemetry yoktur | KV, Moobot, Cyclops Blink, ORBs | config/auth/flow log'larını merkezileştirin ve firmware/inventory'yi doğrulayın |
| Infrastructure shared ve kısa ömürlüdür | China-nexus ORBs | behavior/topology'yi cluster'layın ve role değişikliklerini zaman içinde takip edin |
| Birkaç zayıf separation birleşir | DPRK personas + VPN + crypto + OTC | identity, device, network, payment ve physical evidence'ı birleştirin |

## References

- [1] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Moobot router botnet'in GRU kontrollü şekilde disruption'ı](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — PRC KV Botnet'inin disruption'ı](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — PRC actor'leri compromise ediyor ve US critical infrastructure'a persistent access sağlıyor](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — China-nexus espionage actor'leri ORB networks kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops Blink advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — APT28 VPNFilter disruption'ı](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — DPRK Foreign Trade Bank temsilcisi crypto-laundering conspiracies ile suçlandı](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Blender.io sanctions ve Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Chinese state-sponsored actor'lerin dünya genelindeki network'leri compromise etmesine karşı koyma](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 Juniper router'larını hedefliyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
