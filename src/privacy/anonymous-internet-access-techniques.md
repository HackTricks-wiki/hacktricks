# Anonymous Internet Access Technique Catalog

{{#include ../banners/hacktricks-training.md}}

Bu, canonical access-path envanteridir. Her vendor adını değil, protocol ve operational **family**'leri kapsar. Hiçbir Internet path'i anonymity garantilemez: account, browser, endpoint, timing, payment, cloud-control-plane ve physical evidence, mükemmel görünen bir route'u etkisiz kılabilir.

Her entry aynı fields'ları kullanır. “Procedure”, lawful deployment veya owned-lab emulation anlamına gelir. Gerçek technique bir router'ı compromise etmeye, access çalmaya veya istemeyen bir intermediary'yi abuse etmeye bağlıysa reproduction, exercise tarafından sahip olunan sistemleri kullanır.

## Coverage matrix

| Family | Destination sees | Strongest property | Speed | Treatment |
|---|---|---|---|---|
| Shared NAT/CGNAT | paylaşılan public address | subscribers arasındaki belirsizlik | high | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | hızlı source-address separation | high | deployable |
| Multi-hop/split relay, MASQUE | final proxy | bilgi bölünmesi veya full-IP tunnel | high/moderate | trusted relay'lerle deployable |
| Tor, bridge, onion service | exit veya onion identity | multi-party path ve ortak browser | moderate | deployable |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay veya timing resistance | low/variable | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | source/request partitioning | high | yalnızca supported applications |
| Public Wi-Fi, travel router | venue/tunnel address | location/access-path değişimi | high | permission required |
| Cellular/eSIM, satellite | carrier/provider address | bağımsız physical uplink | high/variable | subscription/provider observes |
| Remote browser/jump host | remote workspace | endpoint ve egress separation | high | deployable |
| Residential/mobile proxy | consumer/carrier address | consumer-network görünümü | high | consent/provenance critical |
| ORB/compromised relay | başka bir victim'ın address'i | origin concealment ve borrowed reputation | high | owned-lab reproduction only |
| CDN/fronting/redirector | CDN/front address | back-end infrastructure protection | high | provider/owner approval required |
| Fast flux/DGA/dead drop | rotating node/service | infrastructure discovery resistance | variable | owned-lab reproduction only |
| Drop/nearest-neighbor | local target-adjacent address | geographic/network boundary geçişi | high | owned-site lab only |
| Store-and-forward/offline | gateway veya physical receiver | interactive timing linkage azalması | low | application-specific |
| Pluggable/refraction transport | Tor entry veya cooperating diversion proxy | censorship-resistant reachability | variable | supported client veya research lab |
| IPFS gateway/PIR/remote fetcher | gateway veya application service | publisher/query/request partitioning | variable | bounded application only |
| Anycast/QUIC/MPTCP | stable broker veya multiple subflows | rendezvous ve session continuity | high | availability, not anonymity |
| CI/CD automation runner | hosted runner address | disposable accountable egress | high | owned workflow only |
| Non-IP local first hop | organization gateway | Internet stack'in sensörden kaldırılması | low | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** Birden çok user aynı public address'i paylaşır; access provider, subscriber-side address ve port'ları public tuple'a map eder.

**Pros:** hızlıdır; özel client gerekmez; destination-side IP yalnızca bir household, venue veya carrier pool'u gösterebilir.

**Cons:** provider subscriber/port/time mapping'lerini tutabilir; account ve fingerprint'ler kalır; diğer user'lar address reputation'ını bozabilir.

**Procedure:** (1) authorized access'in NAT/CGNAT kullanıp kullanmadığını doğrulayın; (2) owned endpoint'te exact public IP ve source port'u kaydedin; (3) application identity'lerini ayırın; (4) shared addressing'i privacy control olarak görmeyin; (5) ISP destinations'ı öğrenmemeliyse daha güçlü bir path kullanın.

**Detection:** destination'lar yalnızca IP'yi değil source port ve precise time'ı tutmalıdır. Provider'lar NAT allocation log'larını correlate eder; investigators account/device/browser evidence'ını birleştirir.

## Commercial VPN

**Mechanics:** Encrypted full-tunnel connection VPN'de sonlanır; destinations VPN'in egress'ini görür. VPN normalde source, timing ve destinations'ı ilişkilendirebilir.

**Pros:** hızlı ve basittir; local passive observation'a karşı korur; stable veya shared exits sağlar; controlled red-team egress için uygundur.

**Cons:** concentrated trust; billing/login telemetry; kill-switch/DNS/IPv6 failures; shared exits çoğunlukla reputation-blocked olur.

**Procedure:** (1) provider, owner, jurisdiction, retention ve assessment policy'sini belirleyin; (2) signed official client'ı kurun; (3) full tunnel, always-on ve fail-closed behavior'ı etkinleştirin; (4) DNS ve IPv6'yı bilinçli biçimde route edin; (5) owned endpoint'te görülen IPv4/IPv6/DNS'i doğrulayın; (6) tunnel'ı durdurup yeniden bağlanın ve clear fallback olmadığını doğrulayın.<sup>[[1]](#references)</sup>

**Detection:** local network'ler VPN infrastructure'a giden uzun encrypted flow görür; provider'lar authentication/connection kayıtlarına sahiptir; destinations ASN/reputation ile account, TLS/browser ve behavior correlation kullanır.

## Self-hosted VPN or rented VPS egress

**Mechanics:** Operator, WireGuard/OpenVPN gateway'ini kontrol eder veya traffic'i rented server üzerinden forward eder.

**Pros:** öngörülebilir yüksek hız; fixed allowlistable address; custom logging/firewall; iyi incident control.

**Cons:** anonymity set küçüktür; cloud tenant, payment, source login, API ve image history operator'ı bağlar; distinctive new server kolayca cluster edilir.

**Procedure:** (1) engagement-specific organization project oluşturun; (2) supported image ve fixed address provision edin; (3) management'ı MFA/key-based administration ile sınırlandırın; (4) full-tunnel egress ve DNS configure edin; (5) mümkünse yalnızca scoped destinations'a izin verin; (6) leak/failure behavior'ı test edin; (7) controller audit records'ı saklayın; (8) teardown sırasında credentials ve resources'ı destroy edin.

**Detection:** hosting ASN, first-seen address, certificate/service fingerprint ve scanning behavior'ı correlate edin; cloud owners control-plane, console, billing ve flow logs kullanır.

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** Application, proxy'den TCP stream açmasını ister; SOCKS, version'a göre name resolution ve UDP de taşıyabilir; SSH stream'leri tek encrypted session içinde forward eder.

**Pros:** lightweight; per-application; hızlı; chaining ve segmented networks'e erişim için kullanışlı.

**Cons:** applications bunu bypass edebilir; DNS leak olabilir; proxy adjacent endpoints'ı görür; browser state kalır; open proxies trap veya compromised system olabilir.

**Procedure:** (1) proxy'yi owned host'ta deploy edin; (2) authentication isteyin ve source/destination'ı kısıtlayın; (3) tek disposable application profile configure edin; (4) gerektiğinde remote DNS resolution sağlayın; (5) owned DNS/HTTP endpoint ile doğrulayın; (6) workload için direct egress'i block edin; (7) proxy credentials'ı inspect ve rotate edin.

**Detection:** tunnel-capable processes, CONNECT/SOCKS negotiation, long SSH sessions ve application'la uyumsuz destinations belirlenir; proxy logs stream'leri yeniden oluşturur.

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** Website destination'ı fetch eder ve links/forms'u kendi origin'i üzerinden rewrite eder veya extension browser requests'ı proxy'ye yönlendirir. Destination service'i görür; service TLS termination sonrasında plaintext'i okuyabilir, content inject veya retain edebilir.

**Pros:** system-wide client gerekmez; simple browsing için hızlıdır; VPN installation'ın mümkün olmadığı yerlerde çalışır.

**Cons:** proxy credentials/content okuyabilir, downloads rewrite edebilir ve user'ları fingerprint edebilir; scripts/WebSockets/downloads bypass edebilir; browser extension geniş privileges'a sahiptir; anonymity set küçük ve blocking yaygındır.

**Procedure:** (1) yalnızca authorized testing için organization-operated proxy kullanın; (2) personal account içermeyen disposable browser'da isolate edin; (3) password entry ve sensitive downloads'u yasaklayın; (4) owned page'deki her subresource'un proxy üzerinden çözüldüğünü doğrulayın; (5) WebSocket, download ve form behavior'ı test edin; (6) kullanım sonrası extension/profile'ı kaldırın.

**Detection:** destination proxy'yi loglar; enterprise proxy/DNS ve extension inventory service'i belirler; content-security/reporting veya owned canary subresources direct bypass'ı gösterir; proxy logs user session'ı targets'a map eder.

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** Entry source'u görür; traversal relay'leri onu destination'ı gören exit'ten ayırır.

**Pros:** normal relay'lerin hiçbirinin iki ucu bilmesi gerekmez; bir node'un failure/seizure'ı daha az bilgi açığa çıkarır; geography esnektir.

**Cons:** shared administration/logs split'i bozar; latency ve timing correlation vardır; failure ve DNS routes artar; aynı account/payment her hop'u birleştirebilir.

**Procedure:** (1) her hop'un hangi observer'ı ortadan kaldırdığını tanımlayın; (2) separation önemliyse independently administered owned/approved relay kullanın; (3) workload'dan yalnızca entry access'i zorlayın; (4) her relay'in yalnızca sonraki hop'a erişebildiğini doğrulayın; (5) her layer'daki logs'u doğrulayın; (6) her hop'u durdurup fail-closed behavior'ı doğrulayın. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) ile reproduce edin.

**Detection:** adjacent NetFlow timing/volume, repeated proxy handshakes ve common controller infrastructure correlate edilir; exit'ten operator geography çıkarımı yapmayın.

## Split-knowledge application relay and OHTTP

**Mechanics:** Client stateless HTTP message'ı gateway'e encrypt eder ve relay üzerinden gönderir. Relay client IP'yi, request'i görmeden görür; gateway request'i görür fakat normalde yalnızca relay IP'sini görür.

**Pros:** supported requests için güçlü ve auditable privacy partition; general anonymity networks'ten daha düşük overhead.

**Cons:** arbitrary browsing değildir; cookies/authentication relink edebilir; relay/gateway collusion ve traffic analysis sürer; application bunu implement etmelidir.

**Procedure:** (1) RFC 9458'i açıkça destekleyen application seçin; (2) gateway keys'i official configuration path üzerinden doğrulayın; (3) stable per-user fields kullanmayın; (4) yalnızca supported stateless request gönderin; (5) relay, gateway ve target logs'u karşılaştırın; (6) direct fallback olmadan key rotation/failure'ı test edin.<sup>[[2]](#references)</sup>

**Detection:** enterprise endpoints initiating process ve OHTTP relay'i açığa çıkarır; gateways malformed/replayed traffic'i tespit eder; timing ve stable payload/account fields requests'leri correlate edebilir.

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT over TLS/QUIC, UDP veya IP packets'larını proxy üzerinden taşır. Modern VPN-like tunnel uygulayabilir ve transport'u HTTP/3 ile blend edebilir; ancak proxy observer olarak kalır.<sup>[[3]](#references)</sup>

**Pros:** efficient multiplexing/roaming; UDP veya full IP support; modern HTTP infrastructure üzerinden deploy edilebilir.

**Cons:** anonymity network değildir; proxy/account source ve destinations'ı görür; QUIC/HTTP fingerprints ve well-known paths endpoints/providers tarafından görünür.

**Procedure:** (1) RFC 9298/9484 support'unu belgeleyen client/service kullanın; (2) proxy certificate/configuration'ı authenticate edin; (3) allowed target routes tanımlayın; (4) path içinde encrypted DNS etkinleştirin; (5) owned endpoints karşısında UDP, TCP, IPv6 ve failover'ı doğrulayın; (6) proxy request ve flow logs'u inceleyin.

**Detection:** endpoints client process ve virtual interface'i görür; networks proxy'ye sürdürülen QUIC/TLS'i sınıflandırabilir; proxy logs CONNECT target/path'i ve assigned routes'ı açığa çıkarır.

## Tor Browser

**Mechanics:** Tor guard, middle ve exit relays seçer; layered encryption her relay'in view'unu sınırlar. Tor Browser fingerprinting'e direnmek üzere standardize edilmiş browser sağlar.

**Pros:** büyük public anonymity set; normal relay'lerin hiçbiri iki ucu bilmez; server işletmeden destination unlinkability.

**Cons:** daha yavaş; TCP-focused; exit reputation/blocks; logins ve disclosures user'ı tanımlar; low-latency timing correlation sürer.

**Procedure:** (1) Tor Browser'ı project'ten download ve verify edin; (2) defaults'ı koruyun ve extensions kullanmayın; (3) uygun security level seçin; (4) ayrı identity/session oluşturun; (5) identifying accounts ve external active documents kullanmayın; (6) HTTPS veya authenticated onion services kullanın; (7) exit'i yalnızca owned endpoint ile doğrulayın.<sup>[[4]](#references)</sup>

**Detection:** local networks bridge/transport kullanılmadığında known guard traffic'i tespit edebilir; destinations exits ve Tor Browser behavior'ı görür; end-to-end observers timing/volume correlate eder.

## Tor bridges and pluggable transports

**Mechanics:** Non-public bridge public guard'ın yerini alır; obfs4, Snowflake veya WebTunnel ilk-hop transport'unu simple blocking/probing'e karşı değiştirir.

**Pros:** censorship'ı aşar ve obvious public-relay destinations'ı gizler; entry sonrasında Tor circuit korunur.

**Cons:** transport patterns/bridge discovery mümkün kalır; performance değişkendir; accounts veya global timing'e karşı ek koruma sağlamaz.

**Procedure:** (1) önce direct Tor deneyin; (2) Tor Browser Connection settings'te built-in supported transport seçin veya official bridge isteyin; (3) random binaries/lists kullanmayın; (4) bağlanıp benign test çalıştırın; (5) reconnect ve clock'ı test edin; (6) diğer browser settings'i standard bırakın.<sup>[[5]](#references)</sup>

**Detection:** censors destination discovery, protocol/flow classification ve active probing kullanır; defenders circumvention use ile compromise'ı ayırmalı ve endpoint process/context'e dayanmalıdır.

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Tor direct Tor use'u access ISP'den gizler fakat source'u VPN'e açar. Tor-before-VPN, VPN'e post-Tor traffic ve çoğu zaman stable customer/tunnel identity verir.

**Pros:** doğru tasarlanırsa belirli bir observer'ı ortadan kaldırır; bir layer'ı block eden network'lere erişebilir.

**Cons:** complexity, uncommon fingerprint, leaks, reduced anonymity set ve false confidence; Tor Project combinations'ı advanced kabul eder.<sup>[[6]](#references)</sup>

**Procedure:** (1) kaldırılan ve eklenen observer'ı yazın; (2) disposable environment kullanın; (3) yalnızca amaçlanan outer path'i kurun; (4) firewall routes zorlayın; (5) DNS/IPv4/IPv6 ve her failure order'ı doğrulayın; (6) iki provider'ın visibility'sini karşılaştırın; (7) ölçülebilir advantage yoksa stack'i bırakın.

**Detection:** local/VPN/Tor observers farklı adjacent layers görür; timing end-to-end kalır; unusual nested tunnel fingerprints ve provider accounts sessions'ı bağlayabilir.

## Onion service

**Mechanics:** Client ve service rendezvous'a Tor circuits kurar; service IP'sini gizler ve exit'i ortadan kaldırır.

**Pros:** source ve service location protection; end-to-end onion authentication; public inbound port yoktur; optional client authorization.

**Cons:** updates/analytics/errors origin leak edebilir; onion key critical'dir; application identity/timing ve host compromise sürer.

**Procedure:** (1) application'ı isolate edin ve yalnızca loopback/socket'e bind edin; (2) supported Tor kurun; (3) official instructions ile v3 onion service configure edin; (4) stable identity gerekiyorsa key'i protect/back up edin; (5) closed use için client authorization ekleyin; (6) third-party fetches'i kaldırın; (7) origin'e externally erişilemediğini doğrulayın.<sup>[[7]](#references)</sup>

**Detection:** host/network defenders Tor process/configuration ve outbound circuits'ı bulur; application errors, DNS, certificates veya third-party resources origin'i açığa çıkarabilir.

## I2P internal services

**Mechanics:** I2P, overlay içindeki destinations için ayrı unidirectional inbound/outbound tunnels kullanır; public-Internet outproxies ek bir trust point oluşturur.

**Pros:** decentralized internal publishing; official exit dependency yoktur; inbound/outbound paths ayrıdır.

**Cons:** general web replacement değildir; ecosystem küçüktür; long-running peer behavior vardır; outproxy public browsing'i gözlemleyebilir.

**Procedure:** (1) official source'tan install edin; (2) dedicated context kullanın; (3) integration/bandwidth stabilization'a izin verin; (4) I2P-native owned service'e erişin; (5) açıkça gerekmedikçe outproxy kullanmayın; (6) shutdown sonrası direct fallback olmadığını doğrulayın; (7) local peer ve service logs'u inceleyin.<sup>[[8]](#references)</sup>

**Detection:** local networks long-lived peer traffic ve bootstrap behavior görür; endpoints router/application processes'i açığa çıkarır; outproxies exits'i loglar.

## Mixnets

**Mechanics:** Fixed-size packets, batching, delay, reordering ve cover traffic timing correlation'ı azaltır; gateways applications'ı bridge eder.

**Pros:** low-latency proxies'e göre timing analysis'e daha dirençli; asynchronous messages/transactions için yararlı.

**Cons:** latency, bandwidth overhead, küçük deployment ve application limitations; gateway/account metadata kalabilir.

**Procedure:** (1) maintained client ve supported application seçin; (2) actual threat model'i okuyun; (3) ayrı compartment'ta install edin; (4) owned endpoint'e benign data gönderin; (5) latency/reliability ve reply path'i ölçün; (6) gateway failure'ı test edin; (7) yalnızca speed için delays/cover traffic'i disable etmeyin.<sup>[[9]](#references)</sup>

**Detection:** endpoints client'ı tanımlar; access networks gateways/packet cadence'i sınıflandırabilir; gateways ve exits adjacent roles'ı görür; broader correlation daha uzun statistical windows gerektirir.

## GNUnet anonymous file sharing

**Mechanics:** GNUnet publish/search/download requests'lerini peers üzerinden route edebilir ve anonymity level'a göre cover traffic ekleyebilir. Documentation, default level 1'in cover traffic gerektirmediği ve powerful traffic analysis'in origin'i bulabileceği konusunda uyarır.<sup>[[10]](#references)</sup>

**Pros:** decentralized, application-native anonymous sharing; ayarlanabilir cover-traffic requirement.

**Cons:** ordinary anonymous web access değildir; performance/storage cost; peer ve traffic-analysis limitations; GNUnet VPN documentation IP overlay'ın iyi anonymity sağlamadığını söyler.

**Procedure:** (1) maintained official build kurun; (2) test peer'i isolate edin; (3) bandwidth/storage sınırlandırın; (4) seçilen anonymity level ile harmless unique test file publish edin; (5) başka owned peer'den retrieve edin; (6) cover-traffic ve latency'yi kaydedin; (7) IP VPN component'in equivalent anonymity sağladığını iddia etmeyin.

**Detection:** peer bootstrap, overlay traffic, local datastore/process ve file identifiers; broad observer traffic volume'u cover traffic'e göre analiz edebilir.

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQ resolver'a encrypt eder; ODoH client address'i proxy ve resolver arasında böler; ECH inner TLS ClientHello/server name'i encrypt eder.

**Pros:** bazı local observers için plaintext DNS/SNI'yi kaldırır; ODoH source/query knowledge'ı partition eder.

**Cons:** IP-anonymity path değildir; resolver/proxy/server roles'ü korur; destination IP/timing/volume ve endpoint kalır; fallback leak edebilir.

**Procedure:** (1) DNS'in OS, application veya tunnel tarafından sahiplenileceğini seçin; (2) strict encrypted mode veya supported ODoH etkinleştirin; (3) unique owned domain test edin; (4) clear query olmadığını local capture ile doğrulayın; (5) resolver'ı fail edip intended behavior'ı doğrulayın; (6) ECH için server diagnostics'in inner ClientHello acceptance gösterdiğini doğrulayın.<sup>[[11]](#references)</sup>

**Detection:** endpoint/resolver logs queries'i açığa çıkarır; networks encrypted-resolver endpoints ve destination flows'u tanır; ECH state path üzerinde gizli olsa da endpoints/CDN'de görünür.

## Split-provider privacy relay

**Mechanics:** iCloud Private Relay gibi products client'ı bilen ingress ve destination'ı bilen independently operated egress kullanır; coarse region handling uygular.

**Pros:** low-friction split knowledge; hızlı; supported traffic için integrated DNS/web protection.

**Cons:** product/application scope sınırlıdır; account/platform provider customer'ı yine tanımlar; arbitrary system anonymity değildir; collusion/legal ve timing risks sürer.

**Procedure:** (1) supported exact applications ve traffic types'ı doğrulayın; (2) uygun yerde dedicated platform context altında feature'ı etkinleştirin; (3) region behavior seçin; (4) Safari/DNS ile unsupported applications'ı ayrı test edin; (5) destination address'i inceleyin; (6) network switching/failure'ı test edin.<sup>[[12]](#references)</sup>

**Detection:** access ingress'i görür; destination egress'i görür; platform/relay logs ve account records kendi layer'larını kapsar; unsupported applications normal paths'i açığa çıkarır.

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** Browsing/tool execution remote system'de gerçekleşir; destination remote egress'i, workspace provider ise operator connection ve control plane'i görür.

**Pros:** hızlı; risky content'i isolate eder; stable controlled egress; disposable state ve güçlü organizational audit.

**Cons:** provider/admin session/account'ı gözlemleyebilir; screen/clipboard/file channels leak eder; remote browser fingerprint unique olabilir; workspace owner'a karşı anonymous değildir.

**Procedure:** (1) engagement başına bir organization-owned workspace oluşturun; (2) MFA isteyin ve administration'ı sınırlandırın; (3) clipboard/upload/download'u disable veya constrain edin; (4) approved fixed egress üzerinden route edin; (5) personal IdP/sync kullanmayın; (6) yalnızca reviewed evidence export edin; (7) workspace ve credentials'ı schedule'a göre destroy edin.

**Detection:** provider ve IdP logs user'ı session'a map eder; destinations workspace egress/browser'ı cluster eder; enterprise defenders remote-control protocols ve anomalous cloud sessions'ı belirler.

## Public or guest Wi-Fi

**Mechanics:** Traffic venue NAT veya orada başlatılan tunnel üzerinden çıkar.

**Pros:** yüksek hız ve shared non-home address; dedicated infrastructure gerekmez.

**Cons:** venue association/DHCP/portal, camera, purchase ve location evidence; hostile peers/APs; terms; physical risk.

**Procedure:** (1) guests'a sunulan access'i alın ve SSID'yi staff ile doğrulayın; (2) patched low-trust device kullanın; (3) sharing/auto-join'u disable ve private MAC'i enable edin; (4) portal'ı reused identity olmadan tamamlayın; (5) fail-closed VPN/Tor path başlatın; (6) tethered traffic'i doğrulayın; (7) network'ü forget edin.

**Detection:** venue AP, MAC, DHCP, portal ve time'ı correlate eder; destination venue/tunnel'ı görür; investigators physical ve device evidence'ı birleştirir. Access control'ü asla bypass etmeyin.

## Travel router

**Mechanics:** Operator-owned router venue Wi-Fi/Ethernet'e katılır ve enforced tunnel policy içeren isolated internal network sağlar.

**Pros:** workstations'ı isolate eder; central kill switch/DNS; consistent client network; privileged endpoints'ı local broadcasts'tan korur.

**Cons:** router stable radio/DHCP fingerprint olur; attack surface ekler; captive portals ve tethering tunnel'ı bypass edebilir.

**Procedure:** (1) supported firmware'i update edin; (2) unique management credentials ayarlayın ve WAN admin/WPS/UPnP'yi disable edin; (3) izin veriliyorsa private upstream MAC configure edin; (4) ayrı internal SSID oluşturun; (5) full-tunnel DNS/IPv6 firewall policy enforce edin; (6) portal, reconnect ve tunnel failure'ı test edin.

**Detection:** venue router association ve traffic shape'i görür; local RF/DHCP fingerprinting onu belirler; VPN provider venue source'u görür.

## Cellular, prepaid SIM and eSIM

**Mechanics:** Modem carrier radio access ve genellikle carrier NAT kullanır; VPN/Tor layer destination-visible exit'i değiştirebilir.

**Pros:** local wired/Wi-Fi network'ten bağımsız; mobile; hızlı; authorized drops için yararlı backhaul.

**Cons:** carrier subscriber/eSIM, IMSI, IMEI, cells, time ve assigned ports'u bilir; registration laws değişir; personal phone ile co-location devices'ı bağlar.

**Procedure:** (1) service'i lawful ve gerekli accurate details ile alın; (2) organization-owned separate modem/device kullanın; (3) exercise controller'a kaydedin; (4) unrelated radios/accounts'ı disable edin; (5) approved tunnel kurun; (6) tethered clients'ın gerçekten tunnel'ı izlediğini test edin; (7) travel öncesi provider ve retention assumptions'ı doğrulayın.<sup>[[13]](#references)</sup>

**Detection:** carrier records ve RF location; enterprise USB/PCI/MDM inventory ve rogue-hotspot surveys; destination/tunnel timing.

## Satellite Internet and satellite downlink abuse

**Mechanics:** Normal service registered terminal/provider kullanır. Older one-way DVB-S abuse, beam içindeki receiver'ın legitimate subscriber'a adreslenmiş unencrypted downlink traffic'i gözlemlemesine ve outbound requests için başka path kullanmasına izin verirdi.

**Pros:** geniş footprint; independent last mile; historical one-way abuse C2'yi subscriber geography'sine yanlış atfedebilirdi.

**Cons:** equipment/RF/provider records; latency ve coverage; modern bidirectional systems farklıdır; outbound path ve asymmetric routing evidence olarak kalır.

**Procedure:** lawful access için owned terminal register edin ve gerektiği gibi traffic'i tunnel edin. Historical Turla behavior'ı emulate etmek için synthetic one-way packet captures'ı RF-free lab'da replay edin ve request yapmayan host'a reply'ı analysts'in tespit edip etmediğini test edin; live satellite traffic intercept etmeyin.<sup>[[14]](#references)</sup>

**Detection:** provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency ve malware configuration.

## Residential/mobile proxy or consented proxyware

**Mechanics:** Backconnect gateway consumer broadband/mobile exits atar; exits sticky veya rotating olabilir. Supply consensual, deceptively bundled veya malicious olabilir.

**Pros:** hızlı; geographic choice; consumer ASN bazı hosting blocks'ları aşar; large pools.

**Cons:** provenance/consent ve legal risk; broker customer'ı görür; infected exits victims'a zarar verir; rotation anomalies oluşturur; pahalı ve unreliable'dır.

**Procedure:** emulation için yalnızca documented, informed-consent organization-owned agents kullanın: (1) test endpoints enroll edin; (2) owners/IPs inventory edin; (3) gateway configure edin; (4) sticky/per-request modes rotate edin; (5) yalnızca owned target'a gönderin; (6) gateway/exit/target logs'u karşılaştırın; (7) tüm agents'ı kaldırın.

**Detection:** impossible travel, rapid IP/ASN değişiminde stable browser/account, backconnect protocols, proxyware process/network artifacts ve broker/controller relations.

## ORB, botnet and compromised edge-device relays

**Mechanics:** Leased veya compromised routers/IoT/servers, fleet olarak yönetilen access, traversal ve exit roles oluşturur. Birden çok APT customer paylaşabilir.

**Pros:** borrowed reputation/geography; short-lived exits; resilient multi-hop mesh; actor-to-IP direct link zayıftır.

**Cons:** criminal victimization; implant/controller ve fleet patterns; intermediary seizure; inconsistent performance; operator/customer service records.

**Procedure:** Gerçek devices'ları asla compromise etmeyin. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) kullanın: (1) isolated entry/transit/target networks oluşturun; (2) owned dual-homed relay containers bağlayın; (3) yalnızca one test port forward edin; (4) benign request gönderin; (5) target'ın yalnızca exit'i gördüğünü doğrulayın; (6) exit'i rotate edin; (7) named assets'ların tümünü tear down edin.<sup>[[15]](#references)</sup>

**Detection:** topology, ports/services, controller relations, implant fingerprints ve node lifecycle takip edilir; edge configuration/flow/integrity telemetry centralize edilir; exit IP'yi actor'la eşitlemeyin.

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** Public edge yalnızca grammar'a uyan traffic'i forward eder; fronting, intermediary izin verdiğinde benign outer SNI ile farklı inner HTTP authority veya blank SNI kullanır.

**Pros:** back-end'i gizler/protect eder; fast global edge; destination'ı shared service ile blend eder; rapid cutover.

**Cons:** CDN tüm routing ve tenant'ı görür; birçok provider cross-tenant fronting'i yasaklar; SNI/Host/process/flow ve account artifacts; configuration reuse campaigns'ı cluster eder.

**Procedure:** yalnızca owned reverse proxy'de [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging) ile reproduce edin: local certificate/edge oluşturun, mismatched Host'u owned target'a route edin, SNI ve Host loglayın, normal/mismatched requests gönderin, sonra containers'ı kaldırın.<sup>[[16]](#references)</sup>

**Detection:** endpoint veya terminating edge'de SNI/ECH/Host/`:authority` karşılaştırın; initiating process, tenant/origin, request grammar ve flow cadence'i birleştirin.

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNS stable name'i update eder; DGA changing candidate names üretir; fast flux service addresses'ı low TTL ile rotate eder; double flux name servers'ı da rotate eder.

**Pros:** resilient discovery; rapid infrastructure replacement; controller'ı many nodes arkasında gizler.

**Cons:** DNS centralized telemetry oluşturur; entropy/NXDOMAIN/churn; low TTL ve broad ASN patterns; registration ve authoritative infrastructure kalır.

**Procedure:** [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry) kullanın: owned zone'u five-second TTL ile RFC 5737 addresses döndürecek şekilde serve edin, tekrar tekrar query edin, synthetic epoch'i değiştirin ve analytics'i doğrulayın. Test records'ı third parties'e yönlendirmeyin.<sup>[[17]](#references)</sup>

**Detection:** sliding-window unique answers/ASNs, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters ve process follow-on; legitimate CDNs'leri context ile exclude edin.

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** Public post, repository, document, object veya feed encoded current endpoint veya task içerir. Client results'ı başka channel üzerinden döndürebilir.

**Pros:** high-reputation allowed service; TLS; binary değiştirmeden endpoint rotation; asymmetric tasking simple flow correlation'ı zorlaştırır.

**Cons:** stable object/account/API identifiers; provider records; endpoint decode/follow-on sequence; content seized veya changed olabilir.

**Procedure:** [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence) kullanın: bir owned container'da encoded pointer host edin, short-lived client'tan fetch/decode edin, ikinci owned service'e contact edin, iki log'u koruyun ve teardown yapın.

**Detection:** unusual process → stable object read → decode → new destination sequence'ini correlate edin; content'i hash/preserve edin ve yalnızca domain değil full object paths'i tutun.

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** Functions/short-lived jobs provider NAT veya front arkasında çalışır; logical service stable kalırken instances ve addresses rotate eder.

**Pros:** rapid deployment/destruction; provider-scale shared egress; little local disk; elastic regional routing.

**Cons:** tenant, role, API, image, secret, invocation, billing ve front-to-origin logs kalıcıdır; cold-start/platform fingerprints; provider policy.

**Procedure:** (1) organization-owned exercise tenant kullanın; (2) yalnızca owned endpoint'e request yapan benign function deploy edin; (3) project/role/image/config kaydedin; (4) several instances arasında invoke edin; (5) target IPs'yi audit/request IDs ile karşılaştırın; (6) log retention'ı test edin; (7) function, roles ve secrets'ı kaldırın.

**Detection:** cloud audit/invocation logs, unusual role creation, stable request grammar ile shared egress, image/layer ve secret reuse, front-origin correlation.

## Authorized on-site drop

**Mechanics:** Inventoried small computer local wired/Wi-Fi ve outbound VPN/cellular rendezvous kullanarak local source olarak görünür.

**Pros:** realistic internal-origin testing; yüksek hız; NAC, physical inventory ve egress controls test edilebilir.

**Cons:** physical discovery/theft; serial/MAC/USB/DHCP/PoE/RF ve camera evidence; loss credentials'ı açığa çıkarabilir.

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) izleyin: (1) exact written placement authority alın; (2) serial, MAC, photo, location ve retrieval time kaydedin; (3) signed minimal image ve short-lived mutual credentials kullanın; (4) outbound-only destinations/capabilities sınırlandırın; (5) server-side quarantine ve bandwidth limits ekleyin; (6) SOC visibility ve loss response test edin; (7) retrieve edin, gerekli evidence'ı koruyun ve agreed lifecycle policy'ye göre sanitize edin. Consenting olmayan venue'da asla gizlemeyin.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera ve physical inspection.

## Nearest-neighbor wireless pivot

**Mechanics:** Actor target'ın radio range'indeki host'u kontrol eder, sonra target Wi-Fi credentials kullanarak boundary'yi uzaktan geçer. APT28 nearby compromised organizations'ı bu şekilde kullandı.<sup>[[18]](#references)</sup>

**Pros:** operator travel gerekmez; target local radio source görür; yalnızca Internet entry'ye uygulanan controls bypass edilir.

**Cons:** nearby compromised/owned dual-radio host ve valid access gerekir; RADIUS/NAC/AP ve neighbor endpoint evidence; signal/device anomalies.

**Procedure:** yalnızca [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) ile reproduce edin: owned pivot'i neighbor ve target lab SSIDs'lerine join edin, yalnızca one service forward edin, iki AP/pivot logs'u toplayın, sonra EAP-TLS/device posture etkinleştirip ikinci attempt'in fail olduğunu doğrulayın.

**Detection:** RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login ve physical presence correlate edilir; nearby endpoints'te simultaneous radios, forwarding ve tunnels aranır.

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** Traffic one interactive Internet session yerine local peers, asynchronous gateways, removable media veya scheduled queues üzerinden ilerler.

**Pros:** disruption/censorship sırasında çalışır; delayed/batched delivery simple timing'i zayıflatır; local communication için central last mile gerekmez.

**Cons:** high latency; small anonymity set; custody/physical metadata; malicious peers; data sonunda onu gözlemleyen gateway'e ulaşır.

**Procedure:** (1) isolated owned three-node mesh veya file queue oluşturun; (2) content'i end to end encrypt/authenticate edin; (3) origin'den direct Internet routes'ı kaldırın; (4) controlled delay sonrası benign file relay edin; (5) yalnızca gateway'in owned destination'a contact ettiğini doğrulayın; (6) custody/timestamps'ı karşılaştırın; (7) evidence'ı koruyup approved closeout'ta temporary media/queues'ı sanitize edin.

**Detection:** endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity ve content identifiers. Interactive-flow analysis yerine longer correlation windows kullanılır.

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN), public relay address allocate eder ve client ile peers arasında UDP, TCP veya TLS traffic taşır. ICE policy direct candidate'ı expose etmek yerine relay kullanımını zorlayabilir. TURN reachability çözer, general anonymity değil: server client'ı authenticate eder ve allocations, peers, time ve volume'u görür.<sup>[[19]](#references)</sup>

**Pros:** widely implemented; restrictive NAT'ı yönetir; mobile WebRTC'yi destekler; relay-only policy doğru enforce edilirse peer client'ın direct transport address'ini almaz.

**Cons:** TURN operator iki adjacent side'ı görür; application identity, media fingerprint ve signaling kalır; relay-only bandwidth ve latency maliyeti getirir; misconfiguration host veya server-reflexive candidates toplayabilir.

**Procedure:** (1) TLS ve short-lived credentials içeren organization-owned TURN service deploy edin; (2) realms, peers, ports, quotas ve expiration'ı kısıtlayın; (3) test application'ı relay-only ICE yapın; (4) owned peer'i arayın; (5) `getStats()` ve packet capture ile yalnızca relay candidates'ın media taşıdığını doğrulayın; (6) relay'i fail edip direct fallback olmadığını doğrulayın; (7) engagement allocation logs'unu koruyun.

**Detection:** signaling, browser process ve TURN allocations session'ı relay'e bağlar; networks TURN ports veya TLS endpoints'e sustained flows görür; peer allocated relay'i görür. **Captured node:** application state ve ephemeral TURN credentials realm ve rendezvous service'i açığa çıkarabilir. Exposure'ı per-device, short-lived credentials ile azaltın ve operator authentication'ı yalnızca controller'da tutun.

## Outbound-only rendezvous or reverse overlay

**Mechanics:** NAT arkasındaki node, organization-controlled broker'a authenticated connection başlatır. Operator broker'a ayrı authenticate olur; broker narrow management channel authorize eder; inbound port forwarding veya direct operator-to-node route gerekmez.

**Pros:** NAT ve captive last miles arkasında stable; central revocation ve audit; field-node address changes operator discovery gerektirmez; operator identity ile node credential'ını temizce ayırır.

**Cons:** broker high-value correlation point olur; periodic keepalives tanınabilir; broad tunnel unsafe pivot olabilir; broker loss management'ı bitirir.

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous) izleyin: one scoped device identity issue edin, yalnızca owned broker ve approved management service'e izin verin, authenticated keepalive kullanın, fail-closed routing enforce edin, address changes ve reboot recovery test edin ve loss drill sırasında identity'yi revoke edin. WireGuard, gerçekten gerektiğinde broadly useful NAT interval olarak 25-second persistent keepalive belgeler.<sup>[[20]](#references)</sup>

**Detection:** broker ve identity-provider logs iki tarafı map eder; access network repeated encrypted destination/cadence görür; endpoint inventory overlay agent'ı gösterir. **Captured node:** device key, broker name, tunnel addresses ve cached task data'nın açığa çıktığını varsayın. Operator private key, personal account veya reusable controller token içermemelidir.

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** Field workload authenticated mailbox'ı signed, pre-approved jobs için poll eder ve bounded results post eder. Operator ayrı control plane üzerinden queue'ya yazar; aralarında interactive socket yoktur.

**Pros:** intermittent links'e dayanır; timing ve addressing'i decouple eder; quotas/schema capability'yi sınırlar; centralized audit/revocation kolaydır.

**Cons:** polling cadence ve stable object/queue names fingerprint oluşturur; provider logs producer/consumer'ı birleştirir; delayed control; captured queued data exercise'ı açığa çıkarabilir.

**Procedure:** (1) bir engagement queue ve device identity oluşturun; (2) benign, explicitly scoped jobs için signed schema tanımlayın; (3) message TTL, maximum result size ve rate ayarlayın; (4) node'un yalnızca kendi queue'sunu pull ve result prefix'ine write etmesine izin verin; (5) offline accumulation, duplicate delivery ve revocation test edin; (6) immutable access logs'u centralize edin; (7) retention requirements karşılanınca queue'yu silin.

**Detection:** unusual process tarafından periodic API calls, stable bucket/object/queue paths, identical user-agent/TLS behavior ve fetch-then-new-connection sequence aranır. **Captured node:** local cache pending jobs ve object names'i gösterebilir; cache'i encrypted, bounded ve disposable tutun, authoritative controller logs'u koruyun.

## Dual-uplink failover and connection migration

**Mechanics:** Approved field node iki independent uplink'e sahiptir; örneğin venue Ethernet/Wi-Fi ve organization cellular. Routes değişirken overlay veya message broker üzerinden control session korunur. Bu availability engineering'dir, anonymity değildir.

**Pros:** provider, AP veya captive-portal failure'ından kurtulur; planned maintenance destekler; suspect path'i hızla isolate etmeyi sağlar.

**Cons:** iki provider iki location/account record oluşturur; simultaneous use correlation'ı kolaylaştırır; failover sırasında route/DNS leaks; cellular co-location evidence kalır.

**Procedure:** (1) iki organization-owned interface ve provider'ı register edin; (2) deterministic route priorities ve health checks'i owned endpoints'e ayarlayın; (3) DNS ve management'ı overlay'e bind edin; (4) secondary path'in inbound traffic kabul etmesini önleyin; (5) her path'i unplug edip session recovery, source policy ve direct destination access olmadığını doğrulayın; (6) unplanned path change için alert oluşturun; (7) data use ve roaming limits'i document edin.

**Detection:** same device certificate, request grammar ve timing ASNs arasında correlate edilir; local inventory iki radio'yu görür; carriers/venues kendi records'ını tutar. **Captured node:** SIM/device identifiers ve known SSIDs görünür olabilir; organization assets kullanın ve node'u personal devices ile pair/co-locate etmeyin.

## Organization private APN or managed cellular tunnel

**Mechanics:** Carrier private APN enrolled SIM'leri private routed domain'e yerleştirir veya traffic'i enterprise gateway'e tunnel eder. Device'ı public mobile Internet'ten ayırır fakat carrier veya contracting organization'dan gizlemez.

**Pros:** stable private addressing; carrier-level enrollment ve traffic policy; public inbound exposure yoktur; authorized remote appliances için kullanışlıdır.

**Cons:** subscriber, IMSI/IMEI, cell ve billing attribution güçlüdür; procurement lead time/cost; carrier/gateway outage; operator'a karşı anonymous değildir.

**Procedure:** (1) APN'yi assessment organization's name altında contract edin; (2) yalnızca registered SIMs ve gateway prefixes whitelist edin; (3) application-layer mutual authentication ekleyin; (4) APN route'unu rendezvous ve update services ile sınırlandırın; (5) SIM removal, roaming, public-Internet breakout ve revocation test edin; (6) carrier/gateway records'u monitor edin; (7) closeout'ta her SIM'i cancel veya quarantine edin.

**Detection:** carrier inventory ve cell telemetry, APN gateway flows, SIM/IMEI mismatch ve enterprise asset records. **Captured node:** storage encrypted olsa da SIM/modem contract'ı tanımlar; capture resilience deniability değil, rapid suspension ve narrow authorization demektir.

## Long-range point-to-point wireless bridge

**Mechanics:** Directional Wi-Fi veya başka licensed/unlicensed point-to-point radio, iki owner-approved site'ı bağlar; Internet egress remote site'tadır. Commercial proxy kullanmadan apparent IP location'ı değiştirebilir.

**Pros:** high throughput; intermediate wired carriers'tan bağımsız; controllable RF/routing; segmentation ve remote-site monitoring testleri için yararlı.

**Cons:** line-of-sight, spectrum, landlord ve regulatory constraints; distinctive RF emissions/hardware; iki endpoint physical evidence'tır; weather/power/alignment stability'yi etkiler.

**Procedure:** (1) iki site için written permission alın ve spectrum/power rules'ı doğrulayın; (2) approved parameters dışında transmit etmeden path survey yapın; (3) authenticated encryption ve management VLAN kullanın; (4) bridge'i owned rendezvous veya test subnet ile sınırlayın; (5) failover, alignment, power recovery ve RF containment test edin; (6) iki radio'yu label/inventory edin; (7) exercise sonrası remove edin ve configuration reset'i doğrulayın.

**Detection:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic ve remote-site egress logs. **Captured node:** configuration peer ve management domain'i gösterir; unique exercise credentials kullanın, personal management accounts kullanmayın ve peer-key'leri hızla revoke edin.

## Consented cooperative or community exit

**Mechanics:** Volunteers veya partner organizations published policy altında knowingly relay çalıştırır. Traffic shared community pool'dan çıkar; coordination layer abuse ve revocation'ı account eder.

**Pros:** diverse non-cloud networks; explicit consent proxyware'den güvenlidir; shared governance trust'ı dağıtabilir; research ve censorship-resilience studies için yararlı.

**Cons:** küçük pools ve membership records anonymity'yi azaltır; exit operators complaints alır ve traffic metadata görür; malicious participants, variable uptime ve jurisdiction differences.

**Procedure:** (1) acceptable-use ve logging policy yayınlayın; (2) her operator'dan informed opt-in alın; (3) unique relay identity issue edin ve destinations/rates'i kısıtlayın; (4) abuse handling ve one-action revocation sağlayın; (5) testing sırasında yalnızca owned endpoints'a authorized traffic gönderin; (6) churn ve correlation exposure ölçün; (7) consent bittiğinde relay'i temizce kaldırın.

**Detection:** membership/control-plane records, relay certificates, common software fingerprint ve exit behavior pool'u belirler. **Captured node:** relay configuration cooperative'i tanımlayabilir fakat client identities içermemelidir; client-to-session accountability'yi access control altındaki authorized controller'da tutun.

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extensions, stable address'in her outbound connection için reuse edilmemesi amacıyla temporary interface identifiers oluşturur. Provider prefix changes rotation ekleyebilir; ancak delegated prefix, subscriber record ve upper-layer fingerprint kalır.<sup>[[21]](#references)</sup>

**Pros:** stable interface identifier ile passive long-term tracking'i azaltır; common operating systems'e built-in'dir; relay overhead yoktur.

**Cons:** source anonymity değildir; ISP/local network prefix/device'i bilir; DNS, accounts ve browser state sessions'ı bağlar; address churn allowlists/logging'i zorlaştırır.

**Procedure:** (1) owned client'ta current stable ve temporary addresses'ı inspect edin; (2) third-party spoofing yerine OS-supported privacy-address default'u etkinleştirin; (3) address lifetimes boyunca owned IPv6 endpoint'i tekrar tekrar request edin; (4) inbound services'ın yalnızca intended stable addresses'e bind olduğunu doğrulayın; (5) DHCPv6/RA/neighbor ve precise endpoint logs'u tutun; (6) her IPv6 address için VPN/firewall behavior'ı test edin.

**Detection:** one address = one device varsaymak yerine delegated prefix, layer-2 identity, neighbor discovery, account ve endpoint telemetry correlate edilir. **Captured node:** network profiles ve interface identifiers kalır; temporary addressing tek passive identifier'ı önler, forensic attribution'ı değil.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** Pluggable transport first Tor connection'ın görünümünü veya bridge'e ulaşma biçimini değiştirir. Snowflake short-lived volunteer WebRTC proxies kullanır, WebTunnel ordinary HTTPS'e benzer, obfs4 simple protocol identification ve active probing'e direnç gösterir, meek supported web infrastructure üzerinden relay eder. Bunlar Tor'a censorship-circumvention transport'larıdır; extra end-to-end anonymity layers değildir.<sup>[[22]](#references)</sup>

**Pros:** direct Tor veya known relays block edildiğinde yararlı; Snowflake stable public bridge address'ten kaçınır; maintained Tor clients'a entegredir; destination ordinary Tor properties alır.

**Cons:** lower/variable performance; broker/front/bridge ve local network farklı metadata görür; transport fingerprints ve blocking mümkündür; volunteer proxy Tor'un yerini almaz ve application plaintext'i için trusted sayılmamalıdır.

**Procedure:** (1) official Tor Browser veya supported Tor client'ı install/verify edin; (2) Connection/Bridges içinde built-in transport seçin; (3) yalnızca owned diagnostic page'e bağlanın; (4) page'in Snowflake/WebTunnel peer'i değil Tor exit gördüğünü doğrulayın; (5) bootstrap/performance'ı karşılaştırın; (6) transport'u fail edip client'ın silently direct bağlanmadığını doğrulayın; (7) test sonrası standard supported configuration'a dönün.

**Detection:** censor destination allowlists, TLS/WebRTC behavior, broker discovery ve flow analysis'i birleştirebilir; endpoints Tor ve transport configuration'ı açığa çıkarır. **Capture-resilient OPSEC:** standard client kullanın, personal browser state'i kopyalamayın ve bridge/broker history'nin recoverable olduğunu varsayın. **Monitoring:** Tor bootstrap logs, unexpected direct DNS/connection attempts ve controller-side owned-page observations izlenmelidir; transport failure discovery proof değildir.

## Refraction networking or decoy routing

**Mechanics:** Cooperating network operator, apparently allowed decoy'a adreslenmiş traffic içindeki covert signal'ı tespit eder ve flow'u circumvention proxy'ye divert eder. Deployment path üzerinde infrastructure gerektirir; client yalnızca innocent website seçerek bunu oluşturamaz.<sup>[[23]](#references)</sup>

**Pros:** apparent destination censor için collateral damage olmadan block edilmesi zor olabilir; public bridge address dağıtılması gerekmez; on-path-assisted circumvention için yararlı research model.

**Cons:** specialized ISP/transit participation; deployability/performance routing'e bağlı; client-to-decoy flow ve proxy-side activity kalır; global/cooperating observer timing correlate edebilir.

**Procedure:** uninvolved networks üzerinden signal göndermeyin. Isolated lab'da reproduce edin: (1) owned client, router, decoy ve proxy namespaces oluşturun; (2) benign tagged test request kullanın; (3) owned router'ın yalnızca o tag'i proxy'ye redirect etmesine izin verin; (4) pre/post-routing tuples ve request IDs loglayın; (5) ordinary ve signaled flows'u karşılaştırın; (6) false positives ve removal test edin; (7) lab routes'ı destroy edin.

**Detection:** authorized network operators routing divergence, unusual client hello/tag behavior ve decoy-versus-back-end flow discrepancies'i inceleyebilir. **Capture-resilient OPSEC:** research client yalnızca test keys ve documentation addresses tutmalıdır. **Monitoring:** signed lab-router decisions ile proxy arrivals karşılaştırılmalı; production transit providers'ı signaling tespiti için probe etmeyin.

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gateway IPFS content identifier (CID)'yi cache veya peers'ten retrieve eder ve verifiable content'i client'a döndürür. Original publisher final reader yerine gateway veya other peers'i görebilir; gateway reader IP ve requested CID'yi görür. Native peer-to-peer retrieval client'ı peers ve DHT/routing participants'a açar.<sup>[[24]](#references)</sup>

**Pros:** caches publisher ve reader'ı ayırabilir; immutable content hash ile verify edilir; replicated data tek host failure'ından kurtulur; HTTP clients native peer stack gerektirmez.

**Cons:** public CIDs ve gateway logs interests'i açığa çıkarır; first retrieval timing publisher/reader'ı correlate edebilir; malicious web content ve path-style same-origin hazards; public gateways best-effort'tur ve abuse'u yasaklar.

**Procedure:** (1) harmless test file'ı owned private IPFS swarm veya owned gateway'e publish edin; (2) CID'yi kaydedin; (3) separate owned HTTP gateway üzerinden subdomain isolation ile retrieve edin; (4) bytes'ı CID'ye karşı verify edin; (5) caching sonrası tekrar edin; (6) publisher, peer ve gateway logs'u karşılaştırın; (7) retention bitince unpin ve test content'i kaldırın.

**Detection:** gateways source/CID loglar; DHT ve peer connections retrieval'i gösterir; endpoint history ve file hashes content'i tanımlar. **Capture-resilient OPSEC:** read-only field client'ta private publishing key tutmayın ve sensitive content'i content addressing öncesi encrypt edin. **Monitoring:** unexpected pinning, peer-set change, allowlist dışı CID requests veya gateway account notices için alert verin.

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR), stated single- veya multi-server threat model altında client'ın database'den bir record retrieve ederken selected index'i server'dan cryptographically gizlemesini sağlar. Bounded dataset için query selection'ı korur; general web access veya IP anonymity değildir.<sup>[[25]](#references)</sup>

**Pros:** strong application-specific query privacy; measurable leakage model; key directories, blocklists veya small public databases için yararlı; exact lookup terms'i açığa çıkarma gereğini azaltabilir.

**Cons:** computation/bandwidth overhead; relay ile birleşmedikçe server connection time/IP'yi bilir; dataset version, response size ve application state users'ı partition edebilir; implementation maturity değişir.

**Procedure:** (1) synthetic owned database üzerinde audited PIR implementation deploy edin; (2) dataset version ve parameters publish edin; (3) identical request sizes ile several indices retrieve edin; (4) correctness'ı local verify edin; (5) server logs'u karşılaştırın ve index'in bulunmadığını doğrulayın; (6) malicious/truncated responses ve version mismatch test edin; (7) anonymous browsing demek yerine exact privacy assumption'ı document edin.

**Detection:** networks service use ve volume'u görür; endpoint telemetry client ve final record use'u açığa çıkarır; compromised server datasets veya timing'i manipulate edebilir. **Capture-resilient OPSEC:** client'ta yalnızca public database parameters ve bounded cache tutun. **Monitoring:** signed dataset roots, fixed request shapes, error-rate changes ve server-key rotations doğrulanmalıdır.

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** Remote service URL fetch veya render eder ve screenshot, metadata veya sanitized content döndürür. Destination fetcher address'i görür; service requester, URL ve result'ı görür. Link-preview bots, security scanners veya third-party URL fetchers'ı abuse etmek authorized proxy use değildir.

**Pros:** active content'i workstation'dan isolate eder; destination controlled fetcher fingerprint'i alır; file type, size, destination ve rendering limits enforce edilebilir; disposable execution environment.

**Cons:** service complete request knowledge'a sahiptir; account/API/billing records; SSRF ve data-exfiltration risk; scripts, authentication ve interactive sites çalışmayabilir; unique URLs requester/fetch'i correlate eder.

**Procedure:** (1) strict allowlist of owned test domains içeren organization-owned fetcher deploy edin; (2) private, link-local, metadata ve redirect-to-unapproved addresses'ı block edin; (3) methods, redirects, bytes ve render time'ı cap edin; (4) credentials/cookies strip edin; (5) owned URL submit edin; (6) requester, fetcher ve target logs'u karşılaştırın; (7) render instance'ı destroy edin ve policy'ye göre central audit saklayın.

**Detection:** target service ASN/fingerprint'i görür; provider/controller logs requester'ı URL'ye map eder; endpoint process/API calls submission'ı gösterir. **Capture-resilient OPSEC:** arbitrary destination authority olmayan one short-lived project token kullanın. **Monitoring:** allowlist denials, redirect violations, controller job ID'siz fetches ve provider abuse notices için alert verin.

## Anycast rendezvous pool

**Mechanics:** Multiple organization-controlled nodes one stable service address'i advertise/front eder ve routing nearby instance'ı seçer. Anycast availability'yi artırır ve individual back-end'i client'tan gizler; operator yine tüm instances'ı kontrol eder ve service address stable'dır.<sup>[[26]](#references)</sup>

**Pros:** resilient regional ingress; instance failure'ında field reconfiguration gerekmez; DDoS/load distribution; central policy sessions'ı known nodes arasında taşıyabilir.

**Cons:** BGP/CDN ve provider records organization'ı tanımlar; path changes stateful sessions'ı bozabilir; monitoring client location'a göre değişir; stable address kolay block veya reputation-cluster edilir.

**Procedure:** provider-supported organization project veya isolated routing lab kullanın: (1) iki identical authenticated health endpoint deploy edin; (2) bir documented service address expose edin; (3) session state'i edge yerine broker'da tutun; (4) bir node'u withdraw edip reconnection'ı doğrulayın; (5) certificate, policy ve log consistency'yi test edin; (6) unauthorized origin/region için alert oluşturun; (7) closeout'ta advertisements ve credentials'ı kaldırın.

**Detection:** BGP/RPKI/history, provider tenancy, certificates ve identical service behavior pool'u tanımlar. **Capture-resilient OPSEC:** edge yalnızca regional service identity tutmalı, operator veya fleet-enrollment key tutmamalıdır. **Monitoring:** every region'ı authorized monitors ile probe edin, route origin ve configuration digest'i karşılaştırın; unexpected origin incident sayılır.

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection IDs NAT rebinding veya address changes sırasında client session'ı canlı tutabilir; Multipath TCP reliable byte stream'i multiple subflows üzerinden taşıyabilir. Wi-Fi/cellular transitions sürekliliğini artırır fakat common peer'e eski ve yeni paths'i açar ve cross-path correlation'ı kolaylaştırabilir.<sup>[[27]](#references)</sup>

**Pros:** uplink changes sırasında faster recovery; application session restart gerektirmez; MPTCP resilience ve throughput'u birleştirebilir; approved field nodes için değerlidir.

**Cons:** anonymity değildir; peer migration/subflows'u görür; connection identifiers ve simultaneous traffic paths'i bağlar; middlebox/carrier support değişkendir; duplicated provider records exposure'ı artırır.

**Procedure:** (1) supported transport'u yalnızca owned field client ve rendezvous arasında enable edin; (2) application'ı IP'den bağımsız authenticate edin; (3) approved Wi-Fi üzerinde bounded transfer başlatın; (4) organization cellular'a geçin; (5) path validation, data integrity ve clear/direct fallback olmadığını doğrulayın; (6) idle timeout ve return'ü test edin; (7) every path transition için broker records tutun.

**Detection:** peer address migration veya MPTCP subflows'u doğrudan görür; access providers kendi kısımlarını görür; connection IDs, TLS identity ve timing ikisini birleştirir. **Capture-resilient OPSEC:** yalnızca device-scoped session material saklayın ve resumable state'i hızla expire edin. **Monitoring:** impossible path changes, simultaneous unapproved networks, migration storms ve quarantine sonrası resumption için alert verin.

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** Organization-owned workflow hosted runner üzerinde bounded network check çalıştırır. Destination cloud runner address'i görür; platform repository, actor, workflow, token, log ve billing attribution'ı tutar. Bu, provider'dan anonymity değil accountable egress ile remote execution'dır.<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment; reproducible job definition; inbound connection yoktur; geographically distributed availability checks için yararlı; strong controller audit.

**Cons:** platform ve organization initiator'ı tanımlar; broad workflow tokens ve untrusted pull requests tehlikelidir; shared IP reputation; logs/artifacts secrets veya target data tutabilir.

**Procedure:** (1) assessment için private organization repository ve environment oluşturun; (2) yalnızca manually approved, fixed benign jobs'ı owned endpoints'a izin verin; (3) minimal read-only workflow permissions ve no production secrets kullanın; (4) check çalıştırın; (5) workflow, provider ve target records'ı karşılaştırın; (6) artifacts'ta credentials olmadığını doğrulayın; (7) environment token'ı silin ve gerekli audit'i saklayın.

**Detection:** provider audit ve workflow logs direct attribution sağlar; targets runner ASNs/ranges ve stable request grammar'ı tanır. **Capture-resilient OPSEC:** field-device, signing, wallet veya cloud-administrator secrets'ı runner variables'a koymayın. **Monitoring:** branch/environment approval isteyin ve workflow edits, fork execution, secret reads ve unexpected destinations için alert verin.

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio veya serial/optical link nearby sensor'dan owner-approved Internet gateway'e bounded messages taşır. Field device'in Internet route'u yoktur; tek egress gateway'dir. Radio range/protocol limits bunu telemetry/store-and-forward design yapar, interactive anonymous Internet değil.

**Pros:** smallest field device'tan Internet stack ve credentials'ı kaldırır; low power; gateway policy'yi centralize eder; temporary dead zones bridge edebilir.

**Cons:** RF/physical discovery, pairing ve device identifiers; small bandwidth/range; gateway tüm messages'ı link eder; spectrum/encryption restrictions değişir; capture queued data'yı açığa çıkarabilir.

**Procedure:** (1) site ve spectrum approval alın; (2) one owned sensor'ı one owned gateway ile unique keys kullanarak pair edin; (3) signed fixed-size message types, TTL ve rate tanımlayın; (4) sensor'a default IP route vermeyin; (5) gateway'in yalnızca owned collector'a forward etmesine izin verin; (6) replay, range loss ve gateway outage test edin; (7) iki device'ı inventory ve retrieve edin.

**Detection:** RF survey, pairing database, physical inspection ve gateway process/flow logs path'i açığa çıkarır. **Capture-resilient OPSEC:** sensor yalnızca pairwise key ve bounded encrypted queue tutmalı; operator, Wi-Fi, cellular veya controller credentials tutmamalıdır. **Monitoring:** new peers, sequence rollback, key failure, unusual RF rate ve unregistered gateway üzerinden gelen messages için alert verin.

## Capture/compromise exposure matrix

Bu table yukarıdaki her family için capture-resilience check uygular. “Minimize”, authorized assets üzerindeki secrets ve blast radius'u azaltmak demektir; evidence'ı temizlemek veya investigation'dan saklanmak anlamına gelmez.

| Technique family | A captured endpoint/relay can reveal | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | known networks, DHCP/portal history, MACs, tunnel peer | separate organization device; supported ise private MAC; personal accounts yok; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames, keys, routes, logs ve adjacent hop | engagement başına one identity; short TTL; narrow routes; broker-side revocation; master keys yok |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers ve cached requests | payload identifiers'ı minimize et; approved config pinle; bounded cache; strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software, bridge/onion material, local state ve peer history | standard client; separate service keys; encrypted minimal state; compromised service identity rotate et |
| Remote browser/VDI/jump host | workspace token, clipboard/files ve remote tenant | phishing-resistant MFA at gateway; transfer channels disabled; rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider ve approximate location | organization contract; personal co-location yok; narrow APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | yalnızca consented/owned nodes; signed agent; per-node credential; controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment ve billing references | dedicated project; least-privilege role; short-lived deploy token; provider audit centrally retained |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results ve custody data | signed bounded jobs; TTL; encrypted cache; separate producer identity; immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artifacts | written placement; unique device identity; operator secret yok; tamper/state telemetry; revoke and recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route ve uplink profiles | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed paths |
| IPv6 temporary addressing | profiles, prefix history ve endpoint/application state | yalnızca anti-tracking olarak değerlendir; network logs koru; endpoint compartmentation ile eşleştir |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state ve research keys | standard client veya isolated lab; personal browser state yok; production signaling yok |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway veya service token | encrypted bounded cache; public-only parameters; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state ve known paths | regional identity only; short resumption lifetime; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs ve artifacts | least-privilege workflow; production/field/wallet secrets yok; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages ve gateway identity | unique pairwise key; fixed message schema; Wi-Fi/cellular/operator credential yok |

## Monitoring possible discovery for every access family

Client-side hiçbir test investigator veya defender'ın izlediğini kanıtlayamaz. Engagement'ın sahip olduğu systems'teki changes'ı monitor edin, controller/client ile corroborate edin ve observers'ı probe etmek yerine durun. Aşağıdaki rows yukarıdaki her technique'i kapsar; bunları [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise) ile birleştirin.

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | unapproved network/SIM/device, unexplained relocation veya provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback veya out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer veya provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health ve owned canary page | personal-account crossover, unexpected non-Tor connection veya compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association ve content hash | unknown peer/gateway, sequence rollback, unauthorized content veya missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export ve cloud audit | unknown login/workflow edit, secret read, unexpected destination veya project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature ve TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use veya site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation ve broker session | impossible migration, simultaneous unapproved paths veya revoke sonrası session resumption |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root veya provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Choosing and testing a path

1. Kaldırılacak observer'ı ve gizlenecek data'yı adlandırın.
2. Onu kaldıran en az complex family'yi seçin.
3. Source, entry, traversal, exit, DNS, account ve payment observers'ı çizin.
4. Ayrı endpoint/application identity kullanın.
5. IPv4, IPv6, DNS, WebRTC/application bypass ve destination view'u doğrulayın.
6. Her hop'u bozun ve failure'ın closed olduğunu doğrulayın.
7. Kontrol ettiğiniz her component'teki logs'u karşılaştırın.
8. Residual timing, provider, endpoint ve physical links'i kaydedin.

## References

- [1] [EFF — Choosing the VPN that is right for you](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
{{#include ../banners/hacktricks-training.md}}
