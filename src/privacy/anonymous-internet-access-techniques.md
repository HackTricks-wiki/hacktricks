# Anonymous Internet Access Technique Catalog

यह canonical access-path inventory है। इसमें हर vendor name नहीं, बल्कि protocol और operational **families** शामिल हैं। कोई भी Internet path anonymity की गारंटी नहीं देता: account, browser, endpoint, timing, payment, cloud-control-plane और physical evidence किसी perfect दिखने वाले route को विफल कर सकते हैं।

हर entry में समान fields हैं। “Procedure” का अर्थ lawful deployment या owned-lab emulation है। जहाँ वास्तविक technique router compromise करने, access चुराने या किसी अनिच्छुक intermediary का दुरुपयोग करने पर निर्भर करती है, वहाँ reproduction में exercise के स्वामित्व वाले systems का उपयोग किया गया है।

## Coverage matrix

| Family | Destination sees | Strongest property | Speed | Treatment |
|---|---|---|---|---|
| Shared NAT/CGNAT | shared public address | subscribers के बीच ambiguity | high | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | तेज source-address separation | high | deployable |
| Multi-hop/split relay, MASQUE | final proxy | knowledge split या full-IP tunnel | high/moderate | trusted relays के साथ deployable |
| Tor, bridge, onion service | exit या onion identity | multi-party path और common browser | moderate | deployable |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay या timing resistance | low/variable | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | source/request partitioning | high | केवल supported applications |
| Public Wi-Fi, travel router | venue/tunnel address | location/access-path change | high | permission required |
| Cellular/eSIM, satellite | carrier/provider address | independent physical uplink | high/variable | subscription/provider observes |
| Remote browser/jump host | remote workspace | endpoint और egress separation | high | deployable |
| Residential/mobile proxy | consumer/carrier address | consumer-network appearance | high | consent/provenance critical |
| ORB/compromised relay | किसी अन्य victim का address | origin concealment और borrowed reputation | high | केवल owned-lab reproduction |
| CDN/fronting/redirector | CDN/front address | back-end infrastructure protection | high | provider/owner approval required |
| Fast flux/DGA/dead drop | rotating node/service | infrastructure discovery resistance | variable | केवल owned-lab reproduction |
| Drop/nearest-neighbor | local target-adjacent address | geographic/network boundary पार करना | high | केवल owned-site lab |
| Store-and-forward/offline | gateway या physical receiver | interactive timing linkage कम करना | low | application-specific |
| Pluggable/refraction transport | Tor entry या cooperating diversion proxy | censorship-resistant reachability | variable | supported client या research lab |
| IPFS gateway/PIR/remote fetcher | gateway या application service | publisher/query/request partitioning | variable | bounded application only |
| Anycast/QUIC/MPTCP | stable broker या multiple subflows | rendezvous और session continuity | high | availability, anonymity नहीं |
| CI/CD automation runner | hosted runner address | disposable accountable egress | high | केवल owned workflow |
| Non-IP local first hop | organization gateway | sensor से Internet stack हटाना | low | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** कई users एक public address share करते हैं; access provider subscriber-side addresses और ports को public tuple से map करता है।

**Pros:** तेज; special client की आवश्यकता नहीं; destination-side IP केवल household, venue या carrier pool की पहचान कर सकता है।

**Cons:** provider subscriber/port/time mappings रख सकता है; accounts और fingerprints बने रहते हैं; अन्य users address reputation को नुकसान पहुँचा सकते हैं।

**Procedure:** (1) पुष्टि करें कि authorized access NAT/CGNAT का उपयोग करता है; (2) owned endpoint पर exact public IP और source port record करें; (3) application identities अलग रखें; (4) shared addressing को privacy control न मानें; (5) यदि ISP को destinations नहीं पता चलने चाहिए तो stronger path उपयोग करें।

**Detection:** destinations को केवल IP नहीं, source port और precise time भी retain करना चाहिए। Providers NAT allocation logs को correlate करते हैं; investigators account/device/browser evidence जोड़ते हैं।

## Commercial VPN

**Mechanics:** encrypted full-tunnel connection VPN पर terminate होता है; destinations उसका egress देखते हैं। VPN सामान्यतः source, timing और destinations को जोड़ सकता है।

**Pros:** तेज; सरल; local passive observation से सुरक्षा; stable या shared exits; controlled red-team egress के लिए उपयोगी।

**Cons:** concentrated trust; billing/login telemetry; kill-switch/DNS/IPv6 failures; shared exits अक्सर reputation-blocked होते हैं।

**Procedure:** (1) provider, owner, jurisdiction, retention और assessment policy पहचानें; (2) signed official client install करें; (3) full tunnel, always-on और fail-closed behavior enable करें; (4) DNS और IPv6 को जानबूझकर route करें; (5) owned endpoint पर observed IPv4/IPv6/DNS verify करें; (6) tunnel stop/reconnect करके clear fallback न होने की पुष्टि करें।<sup>[[1]](#references)</sup>

**Detection:** local networks VPN infrastructure तक लंबे encrypted flow देखते हैं; providers के पास authentication/connection records होते हैं; destinations ASN/reputation के साथ account, TLS/browser और behavior correlation उपयोग करते हैं।

## Self-hosted VPN or rented VPS egress

**Mechanics:** operator WireGuard/OpenVPN gateway नियंत्रित करता है या rented server के माध्यम से traffic forward करता है।

**Pros:** predictable high speed; fixed allowlistable address; custom logging/firewall; incident control के लिए अच्छा।

**Cons:** anonymity set छोटा; cloud tenant, payment, source login, API और image history operator से जुड़ते हैं; distinctive नया server आसानी से cluster किया जा सकता है।

**Procedure:** (1) engagement-specific organization project बनाएं; (2) supported image और fixed address provision करें; (3) management को MFA/key-based administration तक सीमित करें; (4) full-tunnel egress और DNS configure करें; (5) जहाँ व्यावहारिक हो केवल scoped destinations allow करें; (6) leak/failure behavior test करें; (7) controller audit records retain करें; (8) teardown पर credentials और resources नष्ट करें।

**Detection:** hosting ASN, first-seen address, certificate/service fingerprint और scanning behavior correlate करें; cloud owners control-plane, console, billing और flow logs उपयोग करते हैं।

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** application proxy से TCP stream खोलने को कहती है; SOCKS version के अनुसार name resolution और UDP भी भेज सकता है; SSH streams को एक encrypted session के भीतर forward करता है।

**Pros:** lightweight; per-application; तेज; chaining और segmented networks तक पहुँचने के लिए उपयोगी।

**Cons:** applications इसे bypass कर सकती हैं; DNS leak हो सकता है; proxy adjacent endpoints देखता है; browser state बनी रहती है; open proxies traps या compromised systems हो सकते हैं।

**Procedure:** (1) proxy owned host पर deploy करें; (2) authentication आवश्यक करें और source/destination सीमित करें; (3) एक disposable application profile configure करें; (4) आवश्यकता होने पर remote DNS resolution सुनिश्चित करें; (5) owned DNS/HTTP endpoint से verify करें; (6) workload के लिए direct egress block करें; (7) proxy credentials inspect और rotate करें।

**Detection:** tunnel-capable processes, CONNECT/SOCKS negotiation, लंबे SSH sessions और application से असंगत destinations पहचानें; proxy logs streams reconstruct करते हैं।

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** website destination fetch करके links/forms को अपने origin से rewrite करती है, या extension browser requests को proxy की ओर भेजती है। Destination service को देखता है, जबकि service TLS termination के बाद plaintext पढ़, content inject या retain कर सकती है।

**Pros:** system-wide client नहीं चाहिए; simple browsing के लिए तेज; जहाँ VPN install संभव न हो वहाँ काम करता है।

**Cons:** proxy credentials/content पढ़, downloads rewrite और users fingerprint कर सकता है; scripts/WebSockets/downloads bypass कर सकते हैं; browser extension को broad privileges मिलते हैं; anonymity set छोटा और blocking सामान्य है।

**Procedure:** (1) authorized testing के लिए केवल organization-operated proxy उपयोग करें; (2) इसे बिना personal accounts वाले disposable browser में isolate करें; (3) password entry और sensitive downloads रोकें; (4) owned page पर हर subresource proxy से resolve होने की पुष्टि करें; (5) WebSocket, download और form behavior test करें; (6) उपयोग के बाद extension/profile हटाएँ।

**Detection:** destination proxy log करता है; enterprise proxy/DNS और extension inventory service पहचानते हैं; content-security/reporting या owned canary subresources direct bypass दिखाते हैं; proxy logs user session को targets से map करते हैं।

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** entry source देखता है, जबकि एक या अधिक traversal relays उसे exit से अलग करते हैं; exit destination देखता है।

**Pros:** किसी सामान्य relay को दोनों ends नहीं मिलते; एक node की failure/seizure से कम जानकारी मिलती है; geography flexible है।

**Cons:** shared administration/logs split को विफल करते हैं; latency; timing correlation; अधिक failure और DNS routes; वही account/payment हर hop को जोड़ सकते हैं।

**Procedure:** (1) निर्धारित करें कि प्रत्येक hop कौन-सा observer हटाता है; (2) separation आवश्यक होने पर independently administered owned/approved relays उपयोग करें; (3) workload से केवल entry-only access enforce करें; (4) प्रत्येक relay को केवल अगले hop तक पहुँच दें; (5) हर layer पर logs verify करें; (6) हर hop रोककर fail-closed behavior confirm करें। [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) से reproduce करें।

**Detection:** adjacent NetFlow timing/volume, repeated proxy handshakes और common controller infrastructure correlate करें; exit से operator geography का अनुमान न लगाएँ।

## Split-knowledge application relay and OHTTP

**Mechanics:** client stateless HTTP message को gateway के लिए encrypt करके relay के माध्यम से भेजता है। Relay client IP देखता है पर request नहीं; gateway request देखता है पर सामान्यतः केवल relay IP देखता है।

**Pros:** supported requests के लिए मजबूत, auditable privacy partition; general anonymity networks से कम overhead।

**Cons:** arbitrary browsing नहीं; cookies/authentication relink कर सकते हैं; relay/gateway collusion और traffic analysis बने रहते हैं; application को इसे implement करना होता है।

**Procedure:** (1) ऐसा application चुनें जो RFC 9458 को स्पष्ट रूप से support करता हो; (2) official configuration path से gateway keys verify करें; (3) stable per-user fields से बचें; (4) केवल supported stateless request भेजें; (5) relay, gateway और target logs compare करें; (6) direct fallback के बिना key rotation/failure test करें।<sup>[[2]](#references)</sup>

**Detection:** enterprise endpoints initiating process और OHTTP relay दिखाते हैं; gateways malformed/replayed traffic detect करते हैं; timing और stable payload/account fields requests correlate कर सकते हैं।

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT over TLS/QUIC UDP या IP packets को proxy से ले जाता है। यह modern VPN-जैसा tunnel और HTTP/3 के साथ transport blending लागू कर सकता है, लेकिन proxy observer बना रहता है।<sup>[[3]](#references)</sup>

**Pros:** efficient multiplexing/roaming; UDP या full IP support; modern HTTP infrastructure के माध्यम से deployable।

**Cons:** anonymity network नहीं; proxy/account source और destinations देखता है; QUIC/HTTP fingerprints और well-known paths endpoints/providers को दिखाई देते हैं।

**Procedure:** (1) ऐसा client/service उपयोग करें जो RFC 9298/9484 support document करता हो; (2) proxy certificate/configuration authenticate करें; (3) allowed target routes तय करें; (4) path के भीतर encrypted DNS enable करें; (5) owned endpoints के विरुद्ध UDP, TCP, IPv6 और failover verify करें; (6) proxy request और flow logs inspect करें।

**Detection:** endpoints client process और virtual interface देखते हैं; networks proxy तक sustained QUIC/TLS classify कर सकते हैं; proxy logs CONNECT target/path दिखाते हैं।

## Tor Browser

**Mechanics:** Tor guard, middle और exit relays चुनता है; layered encryption प्रत्येक relay का view सीमित करती है। Tor Browser fingerprinting resistance के लिए standardized browser जोड़ता है।

**Pros:** बड़ा public anonymity set; कोई सामान्य relay दोनों ends नहीं जानता; servers operate किए बिना destination unlinkability।

**Cons:** धीमा; TCP-focused; exit reputation/blocks; logins और disclosures user की पहचान कराते हैं; low-latency timing correlation बना रहता है।

**Procedure:** (1) project से Tor Browser download और verify करें; (2) defaults रखें और extensions से बचें; (3) उचित security level चुनें; (4) अलग identity/session बनाएं; (5) identifying accounts और external active documents से बचें; (6) HTTPS या authenticated onion services उपयोग करें; (7) exit को केवल owned endpoint से verify करें।<sup>[[4]](#references)</sup>

**Detection:** bridge/transport न होने पर local networks known guard traffic पहचान सकते हैं; destinations exits और Tor Browser behavior देखते हैं; end-to-end observers timing/volume correlate करते हैं।

## Tor bridges and pluggable transports

**Mechanics:** non-public bridge public guard को replace करता है; obfs4, Snowflake या WebTunnel simple blocking/probing से बचने के लिए first-hop transport बदलते हैं।

**Pros:** censorship bypass और obvious public-relay destinations छिपाता है; entry के बाद Tor circuit बना रहता है।

**Cons:** transport patterns/bridge discovery संभव रहती है; performance variable है; accounts या global timing से सुरक्षा नहीं देता।

**Procedure:** (1) पहले direct Tor आजमाएँ; (2) Tor Browser Connection settings में built-in supported transport चुनें या official bridge माँगें; (3) random binaries/lists उपयोग न करें; (4) connect करके benign test चलाएँ; (5) reconnect और clock test करें; (6) बाकी browser settings standard रखें।<sup>[[5]](#references)</sup>

**Detection:** censors destination discovery, protocol/flow classification और active probing उपयोग करते हैं; defenders को circumvention use और compromise में अंतर करना चाहिए तथा endpoint process/context पर निर्भर रहना चाहिए।

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Tor access ISP से direct Tor use छिपाता है लेकिन source VPN को दिखाता है। Tor-before-VPN में VPN को post-Tor traffic और अक्सर stable customer/tunnel identity मिलती है।

**Pros:** सही design में specific observer हटाता है; एक layer block करने वाले networks तक पहुँच सकता है।

**Cons:** complexity, uncommon fingerprint, leaks, reduced anonymity set और false confidence; Tor Project combinations को advanced मानता है।<sup>[[6]](#references)</sup>

**Procedure:** (1) हटाए गए और जोड़े गए observer लिखें; (2) disposable environment उपयोग करें; (3) केवल intended outer path स्थापित करें; (4) firewall routes enforce करें; (5) DNS/IPv4/IPv6 और हर failure order verify करें; (6) दोनों providers की visibility compare करें; (7) measurable advantage न होने पर stack छोड़ दें।

**Detection:** local/VPN/Tor observers अलग adjacent layers देखते हैं; timing end-to-end बना रहता है; unusual nested tunnel fingerprints और provider accounts sessions जोड़ सकते हैं।

## Onion service

**Mechanics:** client और service दोनों rendezvous तक Tor circuits बनाते हैं, जिससे service IP छिपती है और exit की आवश्यकता नहीं रहती।

**Pros:** source और service location protection; end-to-end onion authentication; public inbound port नहीं; optional client authorization।

**Cons:** updates/analytics/errors से origin leak; onion key critical है; application identity/timing और host compromise बने रहते हैं।

**Procedure:** (1) application isolate करें और केवल loopback/socket पर bind करें; (2) supported Tor install करें; (3) official instructions से v3 onion service configure करें; (4) stable identity आवश्यक होने पर key protect/back up करें; (5) closed use के लिए client authorization जोड़ें; (6) third-party fetches हटाएँ; (7) externally verify करें कि origin reachable नहीं है।<sup>[[7]](#references)</sup>

**Detection:** host/network defenders Tor process/configuration और outbound circuits पाते हैं; application errors, DNS, certificates या third-party resources origin expose कर सकते हैं।

## I2P internal services

**Mechanics:** I2P overlay के भीतर destinations के लिए अलग unidirectional inbound/outbound tunnels उपयोग करता है; public-Internet outproxies trust point जोड़ते हैं।

**Pros:** decentralized internal publishing; official exit dependency नहीं; अलग inbound/outbound paths।

**Cons:** general web replacement नहीं; छोटा ecosystem; long-running peer behavior; outproxy public browsing observe कर सकता है।

**Procedure:** (1) official source से install करें; (2) dedicated context उपयोग करें; (3) integration/bandwidth stabilization की अनुमति दें; (4) I2P-native owned service access करें; (5) explicitly required न हो तो outproxies से बचें; (6) shutdown पर direct fallback न होने की पुष्टि करें; (7) local peer और service logs inspect करें।<sup>[[8]](#references)</sup>

**Detection:** local networks long-lived peer traffic और bootstrap behavior देखते हैं; endpoints router/application processes expose करते हैं; outproxies exits log करते हैं।

## Mixnets

**Mechanics:** fixed-size packets, batching, delay, reordering और cover traffic timing correlation कम करते हैं; gateways applications bridge करते हैं।

**Pros:** low-latency proxies की तुलना में timing analysis के विरुद्ध बेहतर resistance; asynchronous messages/transactions के लिए उपयोगी।

**Cons:** latency, bandwidth overhead, छोटा deployment और application limits; gateway/account metadata persist कर सकता है।

**Procedure:** (1) maintained client और supported application चुनें; (2) actual threat model पढ़ें; (3) separate compartment में install करें; (4) owned endpoint को benign data भेजें; (5) latency/reliability और reply path मापें; (6) gateway failure test करें; (7) केवल speed के लिए delays/cover traffic disable न करें।<sup>[[9]](#references)</sup>

**Detection:** endpoints client पहचानते हैं; access networks gateways/packet cadence classify कर सकते हैं; gateways और exits adjacent roles देखते हैं, जबकि व्यापक correlation के लिए लंबे statistical windows चाहिए।

## GNUnet anonymous file sharing

**Mechanics:** GNUnet peers के माध्यम से publish/search/download requests route कर सकता है और anonymity level के अनुसार cover traffic जोड़ सकता है। इसके documentation में चेतावनी है कि default level 1 cover traffic आवश्यक नहीं करता और powerful traffic analysis origin पहचान सकता है।<sup>[[10]](#references)</sup>

**Pros:** decentralized, application-native anonymous sharing; cover-traffic requirement tunable।

**Cons:** ordinary anonymous web access नहीं; performance/storage cost; peer और traffic-analysis limitations; GNUnet VPN documentation के अनुसार उसका IP overlay अच्छी anonymity नहीं देता।

**Procedure:** (1) maintained official build install करें; (2) test peer isolate करें; (3) bandwidth/storage cap करें; (4) चुने गए anonymity level के साथ harmless unique test file publish करें; (5) दूसरे owned peer से retrieve करें; (6) cover-traffic और latency record करें; (7) IP VPN component को equivalent anonymity देने का दावा न करें।

**Detection:** peer bootstrap, overlay traffic, local datastore/process और file identifiers; broad observer cover traffic के विरुद्ध traffic volume analyze कर सकता है।

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQ resolver तक encrypt करते हैं; ODoH client address और query को proxy तथा resolver के बीच split करता है; ECH inner TLS ClientHello/server name encrypt करता है।

**Pros:** कुछ local observers से plaintext DNS/SNI हटाता है; ODoH source/query knowledge partition करता है।

**Cons:** IP-anonymity path नहीं; resolver/proxy/server की भूमिकाएँ बनी रहती हैं; destination IP/timing/volume और endpoint बने रहते हैं; fallback leak कर सकता है।

**Procedure:** (1) तय करें कि OS, application या tunnel DNS own करेगा; (2) strict encrypted mode या supported ODoH enable करें; (3) unique owned domain test करें; (4) local capture से clear query न होने की पुष्टि करें; (5) resolver fail करके intended behavior verify करें; (6) ECH के लिए confirm करें कि server diagnostics inner ClientHello acceptance दिखाते हैं।<sup>[[11]](#references)</sup>

**Detection:** endpoint/resolver logs queries expose करते हैं; networks encrypted-resolver endpoints और destination flows पहचानते हैं; ECH state endpoints/CDN को दिखाई देती है, path पर hidden होने पर भी।

## Split-provider privacy relay

**Mechanics:** iCloud Private Relay जैसे products ऐसे ingress का उपयोग करते हैं जो client जानता है और independently operated egress का जो destination जानता है, साथ में coarse region handling होती है।

**Pros:** low-friction split knowledge; तेज; supported traffic के लिए integrated DNS/web protection।

**Cons:** product/application scope सीमित; account/platform provider customer पहचानता है; arbitrary system anonymity नहीं; collusion/legal और timing risks।

**Procedure:** (1) exact supported applications और traffic types confirm करें; (2) उचित होने पर dedicated platform context में feature enable करें; (3) region behavior चुनें; (4) Safari/DNS और unsupported applications अलग test करें; (5) destination address inspect करें; (6) network switching/failure test करें।<sup>[[12]](#references)</sup>

**Detection:** access ingress देखता है; destination egress देखता है; platform/relay logs और account records अपनी respective layer को जोड़ते हैं; unsupported applications normal paths expose करती हैं।

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** browsing/tool execution remote system पर होता है; destination उसका egress देखता है, जबकि workspace provider operator connection और control plane देखता है।

**Pros:** तेज; risky content isolate करता है; stable controlled egress; disposable state और strong organizational audit।

**Cons:** provider/admin session/account observe कर सकता है; screen/clipboard/file channels leak करते हैं; remote browser fingerprint unique हो सकता है; workspace owner से anonymity नहीं।

**Procedure:** (1) प्रत्येक engagement के लिए एक organization-owned workspace बनाएं; (2) MFA आवश्यक करें और administration सीमित करें; (3) clipboard/upload/download disable या constrain करें; (4) approved fixed egress से route करें; (5) personal IdP/sync उपयोग न करें; (6) केवल reviewed evidence export करें; (7) schedule के अनुसार workspace और credentials नष्ट करें।

**Detection:** provider और IdP logs user को session से map करते हैं; destinations workspace egress/browser cluster करते हैं; enterprise defenders remote-control protocols और anomalous cloud sessions पहचानते हैं।

## Public or guest Wi-Fi

**Mechanics:** traffic venue NAT या वहाँ शुरू किए गए tunnel से बाहर निकलता है।

**Pros:** तेज और shared non-home address; dedicated infrastructure नहीं।

**Cons:** venue association/DHCP/portal, camera, purchase और location evidence; hostile peers/APs; terms; physical risk।

**Procedure:** (1) guests को दिया गया access लें और staff से SSID verify करें; (2) patched low-trust device उपयोग करें; (3) sharing/auto-join disable और private MAC enable करें; (4) reused identity के बिना portal पूरा करें; (5) fail-closed VPN/Tor path शुरू करें; (6) tethered traffic verify करें; (7) network भूल जाएँ।

**Detection:** venue AP, MAC, DHCP, portal और time correlate करता है; destination venue/tunnel देखता है; investigators physical और device evidence जोड़ते हैं। Access control को कभी bypass न करें।

## Travel router

**Mechanics:** operator-owned router venue Wi-Fi/Ethernet से जुड़ता है और enforced tunnel policy वाला isolated internal network देता है।

**Pros:** workstations isolate करता है; central kill switch/DNS; consistent client network; privileged endpoints को local broadcasts से बचाता है।

**Cons:** router stable radio/DHCP fingerprint बनता है; attack surface जोड़ता है; captive portals और tethering tunnel bypass कर सकते हैं।

**Procedure:** (1) supported firmware update करें; (2) unique management credentials set करें और WAN admin/WPS/UPnP disable करें; (3) जहाँ permitted हो private upstream MAC configure करें; (4) separate internal SSID बनाएं; (5) full-tunnel DNS/IPv6 firewall policy enforce करें; (6) portal, reconnect और tunnel failure test करें।

**Detection:** venue router association और traffic shape देखता है; local RF/DHCP fingerprinting इसे पहचानती है; VPN provider venue source देखता है।

## Cellular, prepaid SIM and eSIM

**Mechanics:** modem carrier radio access और सामान्यतः carrier NAT उपयोग करता है; VPN/Tor layer destination-visible exit बदल सकती है।

**Pros:** local wired/Wi-Fi network से independent; mobile; high speed; authorized drops के backhaul के लिए उपयोगी।

**Cons:** carrier subscriber/eSIM, IMSI, IMEI, cells, time और assigned ports जानता है; registration laws अलग हैं; personal phone के साथ co-location devices जोड़ती है।

**Procedure:** (1) required accurate details के साथ lawful service प्राप्त करें; (2) organization-owned separate modem/device उपयोग करें; (3) exercise controller के साथ record करें; (4) unrelated radios/accounts disable करें; (5) approved tunnel स्थापित करें; (6) test करें कि tethered clients वास्तव में इसका पालन करते हैं; (7) travel से पहले provider और retention assumptions verify करें।<sup>[[13]](#references)</sup>

**Detection:** carrier records और RF location; enterprise USB/PCI/MDM inventory और rogue-hotspot surveys; destination/tunnel timing।

## Satellite Internet and satellite downlink abuse

**Mechanics:** normal service registered terminal/provider उपयोग करती है। पुराने one-way DVB-S abuse में receiver beam के भीतर legitimate subscriber को संबोधित unencrypted downlink traffic देख सकता था और outbound requests के लिए दूसरा path उपयोग कर सकता था।

**Pros:** wide footprint; independent last mile; historical one-way abuse C2 को subscriber geography से गलत जोड़ सकता था।

**Cons:** equipment/RF/provider records; latency और coverage; modern bidirectional systems अलग हैं; outbound path और asymmetric routing evidence बने रहते हैं।

**Procedure:** lawful access के लिए owned terminal register करें और आवश्यकता अनुसार traffic tunnel करें। Historical Turla behavior emulate करने के लिए RF-free lab में synthetic one-way packet captures replay करें और test करें कि analysts ऐसे host को detect करते हैं या नहीं जिसने request नहीं की; live satellite traffic intercept न करें।<sup>[[14]](#references)</sup>

**Detection:** provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency और malware configuration।

## Residential/mobile proxy or consented proxyware

**Mechanics:** backconnect gateway consumer broadband/mobile exits assign करता है, sticky या rotating रूप में। Supply consensual, deceptively bundled या malicious हो सकती है।

**Pros:** तेज; geographic choice; consumer ASN कुछ hosting blocks से बचाता है; बड़े pools।

**Cons:** provenance/consent और legal risk; broker customer देखता है; infected exits victims को नुकसान पहुँचाते हैं; rotation anomalies बनाती है; expensive और unreliable।

**Procedure:** emulation के लिए केवल documented, informed-consent organization-owned agents उपयोग करें: (1) test endpoints enroll करें; (2) owners/IPs inventory करें; (3) gateway configure करें; (4) sticky/per-request modes rotate करें; (5) केवल owned target को भेजें; (6) gateway/exit/target logs compare करें; (7) हर agent हटाएँ।

**Detection:** impossible travel, rapid IP/ASN changes के बावजूद stable browser/account, backconnect protocols, proxyware process/network artifacts और broker/controller relations।

## ORB, botnet and compromised edge-device relays

**Mechanics:** leased या compromised routers/IoT/servers access, traversal और exit roles बनाते हैं जिन्हें fleet के रूप में administer किया जाता है। कई APT customers इसे share कर सकते हैं।

**Pros:** borrowed reputation/geography; short-lived exits; resilient multi-hop mesh; actor-to-IP direct link कमजोर।

**Cons:** criminal victimization; implant/controller और fleet patterns; intermediary seizure; inconsistent performance; operator/customer service records।

**Procedure:** वास्तविक devices compromise न करें। [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) उपयोग करें: (1) isolated entry/transit/target networks बनाएं; (2) owned dual-homed relay containers जोड़ें; (3) केवल एक test port forward करें; (4) benign request भेजें; (5) verify करें कि target केवल exit देखता है; (6) exit rotate करें; (7) सभी named assets tear down करें।<sup>[[15]](#references)</sup>

**Detection:** topology, ports/services, controller relations, implant fingerprints और node lifecycle track करें; edge configuration/flow/integrity telemetry centralize करें; exit IP को actor न मानें।

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** public edge केवल grammar से matching traffic forward करता है; fronting में intermediary अनुमति देने पर benign outer SNI और अलग inner HTTP authority, या blank SNI रखा जाता है।

**Pros:** back-end छिपाता/protect करता है; fast global edge; destination को shared service में blend करता है; rapid cutover।

**Cons:** CDN सभी routing और tenant देखता है; कई providers cross-tenant fronting रोकते हैं; SNI/Host/process/flow और account artifacts; configuration reuse campaigns को cluster करता है।

**Procedure:** केवल owned reverse proxy पर [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging) से reproduce करें: local certificate/edge बनाएं, एक mismatched Host को owned target पर route करें, SNI और Host log करें, normal/mismatched requests भेजें, फिर containers हटाएँ।<sup>[[16]](#references)</sup>

**Detection:** endpoint या terminating edge पर SNI/ECH/Host/`:authority` compare करें; initiating process, tenant/origin, request grammar और flow cadence जोड़ें।

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNS stable name update करता है; DGA बदलते candidate names बनाता है; fast flux low TTL पर service addresses rotate करता है; double flux name servers भी rotate करता है।

**Pros:** resilient discovery; infrastructure replacement तेज; controller कई nodes के पीछे छिपता है।

**Cons:** DNS centralized telemetry बनाता है; entropy/NXDOMAIN/churn; low TTL और broad ASN patterns; registration और authoritative infrastructure बने रहते हैं।

**Procedure:** [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry) उपयोग करें: owned zone को RFC 5737 addresses और five-second TTL के साथ serve करें, बार-बार query करें, synthetic epoch बदलें और analytics validate करें। Test records को third parties की ओर point न करें।<sup>[[17]](#references)</sup>

**Detection:** sliding-window unique answers/ASNs, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters और process follow-on; legitimate CDNs को context के साथ exclude करें।

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** public post, repository, document, object या feed में encoded current endpoint या task होता है। Client दूसरे channel से results लौटा सकता है।

**Pros:** high-reputation allowed service; TLS; binary बदले बिना endpoint rotation; asymmetric tasking simple flow correlation कठिन बनाती है।

**Cons:** stable object/account/API identifiers; provider records; endpoint decode/follow-on sequence; content seize या बदल सकता है।

**Procedure:** [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence) उपयोग करें: एक owned container पर encoded pointer host करें, short-lived client से fetch/decode करें, दूसरे owned service से contact करें, दोनों logs preserve करें और teardown करें।

**Detection:** unusual process → stable object read → decode → new destination correlate करें; content hash/preserve करें और केवल domain नहीं, full object paths retain करें।

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** functions/short-lived jobs provider NAT या front के पीछे चलते हैं; logical service stable रहती है जबकि instances और addresses rotate होते हैं।

**Pros:** rapid deployment/destruction; provider-scale shared egress; local disk कम; elastic regional routing।

**Cons:** tenant, role, API, image, secret, invocation, billing और front-to-origin logs durable हैं; cold-start और platform fingerprints; provider policy।

**Procedure:** (1) organization-owned exercise tenant उपयोग करें; (2) benign function deploy करें जो केवल owned endpoint request करे; (3) project/role/image/config record करें; (4) कई instances में invoke करें; (5) target IPs को audit/request IDs से compare करें; (6) log retention test करें; (7) function, roles और secrets हटाएँ।

**Detection:** cloud audit/invocation logs, unusual role creation, stable request grammar के साथ shared egress, image/layer और secret reuse, तथा front-origin correlation।

## Authorized on-site drop

**Mechanics:** inventoried small computer local wired/Wi-Fi और outbound VPN/cellular rendezvous उपयोग करता है तथा local source प्रस्तुत करता है।

**Pros:** realistic internal-origin testing; high speed; NAC, physical inventory और egress controls test कर सकता है।

**Cons:** physical discovery/theft; serial/MAC/USB/DHCP/PoE/RF और camera evidence; loss से credentials expose हो सकते हैं।

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) का पालन करें: (1) exact written placement authority लें; (2) serial, MAC, photo, location और retrieval time record करें; (3) signed minimal image और short-lived mutual credentials उपयोग करें; (4) outbound-only destinations/capabilities सीमित करें; (5) server-side quarantine और bandwidth limits जोड़ें; (6) SOC visibility और loss response test करें; (7) retrieve करके required evidence preserve करें, फिर agreed lifecycle policy के अनुसार sanitize करें। Unconsenting venue में कभी न छिपाएँ।

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera और physical inspection।

## Nearest-neighbor wireless pivot

**Mechanics:** actor target के radio range में host नियंत्रित करता है और target Wi-Fi credentials का उपयोग करके remotely boundary पार करता है। APT28 ने nearby compromised organizations का इस प्रकार उपयोग किया।<sup>[[18]](#references)</sup>

**Pros:** operator travel नहीं; target local radio source देखता है; केवल Internet entry पर लागू controls bypass हो सकते हैं।

**Cons:** nearby compromised/owned dual-radio host और valid access आवश्यक; RADIUS/NAC/AP तथा neighbor endpoint evidence; signal/device anomalies।

**Procedure:** केवल [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) से reproduce करें: owned pivot को neighbor और target lab SSIDs से join करें, केवल एक service forward करें, दोनों AP/pivot logs collect करें, फिर EAP-TLS/device posture enable करके पुष्टि करें कि दूसरा प्रयास विफल होता है।

**Detection:** RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login और physical presence correlate करें; nearby endpoints में simultaneous radios, forwarding और tunnels खोजें।

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** traffic एक interactive Internet session के बजाय local peers, asynchronous gateways, removable media या scheduled queues से गुजरता है।

**Pros:** disruption/censorship में काम करता है; delayed/batched delivery simple timing कमजोर करती है; local communication के लिए central last mile नहीं।

**Cons:** high latency; छोटा anonymity set; custody/physical metadata; malicious peers; data अंततः ऐसे gateway तक पहुँचता है जो उसे observe करता है।

**Procedure:** (1) isolated owned three-node mesh या file queue बनाएं; (2) content end to end encrypt/authenticate करें; (3) origin से direct Internet routes हटाएँ; (4) controlled delay के बाद benign file relay करें; (5) verify करें कि केवल gateway owned destination से contact करता है; (6) custody/timestamps compare करें; (7) required evidence preserve करके approved closeout पर temporary media/queues sanitize करें।

**Detection:** endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity और content identifiers। Longer correlation windows interactive-flow analysis की जगह लेते हैं।

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN) public relay address allocate करता है और client तथा peers के बीच UDP, TCP या TLS traffic ले जाता है। ICE policy direct candidate expose करने के बजाय relay use force कर सकती है। TURN reachability हल करता है, general anonymity नहीं: server client authenticate करता है और allocations, peers, time तथा volume देखता है।<sup>[[19]](#references)</sup>

**Pros:** widely implemented; restrictive NAT संभालता है; mobile WebRTC support; relay-only policy सही होने पर peer को client का direct transport address नहीं मिलता।

**Cons:** TURN operator दोनों adjacent sides देखता है; application identity, media fingerprint और signaling बने रहते हैं; relay-only bandwidth और latency खर्च करता है; misconfiguration host या server-reflexive candidates collect कर सकती है।

**Procedure:** (1) TLS और short-lived credentials वाला organization-owned TURN service deploy करें; (2) realms, peers, ports, quotas और expiration सीमित करें; (3) test application को relay-only ICE पर set करें; (4) owned peer को call करें; (5) `getStats()` और packet capture inspect करके confirm करें कि केवल relay candidates ने media carry किया; (6) relay fail करके direct fallback न होने की पुष्टि करें; (7) engagement के लिए allocation logs retain करें।

**Detection:** signaling, browser process और TURN allocations session को relay से जोड़ते हैं; networks TURN ports या TLS endpoints तक sustained flows देखते हैं; peer allocated relay देखता है। **Captured node:** application state और ephemeral TURN credentials realm और rendezvous service बता सकते हैं। Per-device, short-lived credentials से exposure घटाएँ और operator authentication केवल controller पर रखें।

## Outbound-only rendezvous or reverse overlay

**Mechanics:** NAT के पीछे node organization-controlled broker से authenticated connection शुरू करता है। Operator अलग से broker को authenticate करता है, जो narrow management channel authorize करता है; inbound port forwarding या direct operator-to-node route आवश्यक नहीं।

**Pros:** NAT और captive last miles के पीछे stable; central revocation और audit; field-node address changes पर operator discovery आवश्यक नहीं; operator identity और node credential अलग रहते हैं।

**Cons:** broker high-value correlation point बनता है; periodic keepalives पहचानने योग्य हैं; broad tunnel unsafe pivot बन सकता है; broker loss management समाप्त करता है।

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous) follow करें: एक scoped device identity issue करें, केवल owned broker और approved management service allow करें, authenticated keepalive उपयोग करें, fail-closed routing enforce करें, address changes और reboot recovery test करें, तथा loss drill में identity revoke करें। WireGuard आवश्यकता होने पर 25-second persistent keepalive को broadly useful NAT interval document करता है।<sup>[[20]](#references)</sup>

**Detection:** broker और identity-provider logs दोनों sides map करते हैं; access network repeated encrypted destination/cadence देखता है; endpoint inventory overlay agent दिखाती है। **Captured node:** device key, broker name, tunnel addresses और cached task data exposed मानें। इसमें operator private key, personal account या reusable controller token नहीं होना चाहिए।

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** field workload signed, pre-approved jobs के लिए authenticated mailbox poll करता है और bounded results post करता है। Operator अलग control plane से queue में लिखता है; दोनों के बीच interactive socket नहीं।

**Pros:** intermittent links सहता है; timing और addressing decouple करता है; quotas और schemas capability सीमित कर सकते हैं; centralized audit और revocation सरल।

**Cons:** polling cadence और stable object/queue names fingerprint बनाते हैं; provider logs producer और consumer जोड़ते हैं; delayed control; captured queued data exercise expose कर सकता है।

**Procedure:** (1) एक engagement queue और device identity बनाएं; (2) benign, explicitly scoped jobs का signed schema तय करें; (3) message TTL, maximum result size और rate set करें; (4) node को केवल अपनी queue pull और केवल अपने result prefix में write करने दें; (5) offline accumulation, duplicate delivery और revocation test करें; (6) immutable access logs centralize करें; (7) retention requirements पूरी होने के बाद queue delete करें।

**Detection:** unusual process द्वारा periodic API calls, stable bucket/object/queue paths, identical user-agent या TLS behavior, और fetch-then-new-connection sequence खोजें। **Captured node:** local cache pending jobs और object names बता सकता है; cache encrypted, bounded और disposable रखें, जबकि authoritative controller logs preserve करें।

## Dual-uplink failover and connection migration

**Mechanics:** approved field node के पास दो independent uplinks होते हैं—जैसे venue Ethernet/Wi-Fi और organization cellular—और routes बदलने पर overlay या message broker के माध्यम से control session बनाए रखता है। यह availability engineering है, anonymity नहीं।

**Pros:** एक provider, AP या captive-portal failure सहता है; planned maintenance support; suspect path को जल्दी isolate कर सकता है।

**Cons:** दो providers दो location/account records बनाते हैं; simultaneous use correlation आसान करता है; failover में route और DNS leaks; cellular co-location evidence बना रहता है।

**Procedure:** (1) दोनों organization-owned interfaces और providers register करें; (2) owned endpoints के लिए deterministic route priorities और health checks दें; (3) DNS और management को overlay से bind करें; (4) secondary path को inbound traffic स्वीकार करने से रोकें; (5) हर path unplug करके session recovery, source policy और direct destination access न होने की पुष्टि करें; (6) unplanned path change पर alert करें; (7) data use और roaming limits document करें।

**Detection:** ASNs के across same device certificate, request grammar और timing correlate करें; local inventory दोनों radios देखती है; carriers/venues अपने records retain करते हैं। **Captured node:** दोनों SIM/device identifiers और known SSIDs visible हो सकते हैं; organization assets उपयोग करें और node को personal devices से कभी co-locate/pair न करें।

## Organization private APN or managed cellular tunnel

**Mechanics:** carrier private APN enrolled SIMs को private routed domain में रखता है या traffic enterprise gateway तक tunnel करता है। यह device को public mobile Internet से अलग करता है, पर carrier या contracting organization से नहीं छिपाता।

**Pros:** stable private addressing; carrier-level enrollment और traffic policy; public inbound exposure से बचाव; authorized remote appliances के लिए उपयोगी।

**Cons:** subscriber, IMSI/IMEI, cell और billing attribution मजबूत हैं; procurement lead time और cost; carrier/gateway outage; operator से anonymous नहीं।

**Procedure:** (1) assessment organization के नाम पर APN contract करें; (2) केवल registered SIMs और gateway prefixes whitelist करें; (3) application-layer mutual authentication जोड़ें; (4) APN route को rendezvous और update services तक सीमित करें; (5) SIM removal, roaming, public-Internet breakout और revocation test करें; (6) carrier और gateway records monitor करें; (7) closeout पर हर SIM cancel या quarantine करें।

**Detection:** carrier inventory और cell telemetry, APN gateway flows, SIM/IMEI mismatch और enterprise asset records। **Captured node:** storage encrypted होने पर भी SIM और modem contract identify करते हैं; capture resilience का अर्थ deniability नहीं, बल्कि rapid suspension और narrow authorization है।

## Long-range point-to-point wireless bridge

**Mechanics:** directional Wi-Fi या licensed/unlicensed point-to-point radio दो owner-approved sites जोड़ता है, और Internet egress remote site पर होता है। Commercial proxy के बिना apparent IP location बदली जा सकती है।

**Pros:** high throughput; intermediate wired carriers से independent; controllable RF और routing; segmentation और remote-site monitoring test करने के लिए उपयोगी।

**Cons:** line-of-sight, spectrum, landlord और regulatory constraints; distinctive RF emissions और hardware; दोनों endpoints physical evidence हैं; weather/power/alignment stability प्रभावित करते हैं।

**Procedure:** (1) दोनों sites की written permission लें और spectrum/power rules verify करें; (2) approved parameters के बाहर transmit किए बिना path survey करें; (3) authenticated encryption और management VLAN उपयोग करें; (4) bridge को owned rendezvous या test subnet तक सीमित करें; (5) failover, alignment, power recovery और RF containment test करें; (6) दोनों radios label/inventory करें; (7) exercise के बाद remove करके configuration reset verify करें।

**Detection:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic और remote-site egress logs। **Captured node:** configuration peer और management domain बताती है; unique exercise credentials उपयोग करें, personal management accounts नहीं, और peer key तुरंत revoke करें।

## Consented cooperative or community exit

**Mechanics:** volunteers या partner organizations published policy के तहत जानबूझकर relays चलाते हैं। Traffic shared community pool से exit होता है, जबकि coordination layer abuse और revocation account करती है।

**Pros:** diverse non-cloud networks; explicit consent proxyware से सुरक्षित; shared governance trust बाँट सकती है; research और censorship-resilience studies के लिए उपयोगी।

**Cons:** छोटे pools और membership records anonymity घटाते हैं; exit operators complaints और traffic metadata देखते हैं; malicious participants, variable uptime और jurisdiction differences।

**Procedure:** (1) acceptable-use और logging policy publish करें; (2) प्रत्येक operator से informed opt-in लें; (3) unique relay identity issue करें और destinations/rates सीमित करें; (4) abuse handling और one-action revocation दें; (5) testing में केवल owned endpoints को authorized traffic भेजें; (6) churn और correlation exposure मापें; (7) consent समाप्त होने पर relay cleanly हटाएँ।

**Detection:** membership/control-plane records, relay certificates, common software fingerprint और exit behavior pool पहचानते हैं। **Captured node:** relay configuration cooperative पहचान सकती है, पर client identities नहीं होनी चाहिए; client-to-session accountability authorized controller पर access control के तहत रखें।

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extensions temporary interface identifiers बनाते हैं ताकि हर outbound connection में stable address reuse न हो। Provider prefix changes rotation जोड़ सकते हैं, लेकिन delegated prefix, subscriber record और upper-layer fingerprint बने रहते हैं।<sup>[[21]](#references)</sup>

**Pros:** stable interface identifier द्वारा passive long-term tracking घटाता है; common operating systems में built in; relay overhead नहीं।

**Cons:** source anonymity नहीं; ISP और local network prefix/device जानते हैं; DNS, accounts और browser state sessions जोड़ते हैं; address churn allowlists और logging जटिल करता है।

**Procedure:** (1) owned client पर current stable और temporary addresses inspect करें; (2) third-party spoofing के बजाय OS-supported privacy-address default enable करें; (3) address lifetimes के दौरान owned IPv6 endpoint को बार-बार request करें; (4) confirm करें कि inbound services केवल intended stable addresses पर bind हैं; (5) DHCPv6/RA/neighbor और precise endpoint logs retain करें; (6) हर IPv6 address के लिए VPN/firewall behavior test करें।

**Detection:** एक address को एक device मानने के बजाय delegated prefix, layer-2 identity, neighbor discovery, account और endpoint telemetry correlate करें। **Captured node:** network profiles और interface identifiers बने रहते हैं; temporary addressing एक passive identifier रोकता है, forensic attribution नहीं।

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** pluggable transport first Tor connection के appearance या bridge तक पहुँचने का तरीका बदलता है। Snowflake short-lived volunteer WebRTC proxies उपयोग करता है, WebTunnel ordinary HTTPS जैसा दिखता है, obfs4 simple protocol identification और active probing रोकता है, और meek supported web infrastructure से relay करता है। ये Tor में जाने वाले censorship-circumvention transports हैं, extra end-to-end anonymity layers नहीं।<sup>[[22]](#references)</sup>

**Pros:** direct Tor या known relays block होने पर उपयोगी; Snowflake stable public bridge address से बचता है; maintained Tor clients में integrated; destination को सामान्य Tor properties मिलती हैं।

**Cons:** lower या variable performance; broker/front/bridge और local network अलग metadata देखते हैं; transport fingerprints और blocking संभव; volunteer proxy Tor का replacement नहीं और application plaintext पर trusted नहीं होना चाहिए।

**Procedure:** (1) official Tor Browser या supported Tor client install और verify करें; (2) Connection/Bridges में built-in transport चुनें; (3) केवल owned diagnostic page से connect करें; (4) confirm करें कि page Tor exit देखता है, Snowflake/WebTunnel peer नहीं; (5) bootstrap और performance compare करें; (6) transport fail करके direct connection silently न होने की पुष्टि करें; (7) test के बाद standard supported configuration पर लौटें।

**Detection:** censor destination allowlists, TLS/WebRTC behavior, broker discovery और flow analysis जोड़ सकता है; endpoints Tor और transport configuration expose करते हैं। **Capture-resilient OPSEC:** standard client उपयोग करें, personal browser state copy न करें और bridge/broker history recoverable मानें। **Monitoring:** Tor bootstrap logs, unexpected direct DNS/connection attempts और controller-side owned-page observations देखें; transport failure discovery का प्रमाण नहीं है।

## Refraction networking or decoy routing

**Mechanics:** cooperating network operator apparently allowed decoy को संबोधित traffic में covert signal detect करके flow को circumvention proxy की ओर divert करता है। Deployment के लिए network path में infrastructure चाहिए; client केवल innocent website चुनकर इसे create नहीं कर सकता।<sup>[[23]](#references)</sup>

**Pros:** apparent destination को censor के लिए collateral damage के बिना block करना कठिन हो सकता है; public bridge address distribute नहीं करना पड़ता; on-path-assisted circumvention का उपयोगी research model।

**Cons:** specialized ISP/transit participation; deployability और performance routing पर निर्भर; client-to-decoy flow और proxy-side activity बनी रहती है; global/cooperating observer timing correlate कर सकता है।

**Procedure:** uninvolved networks के माध्यम से signal न करें। Isolated lab में architecture reproduce करें: (1) owned client, router, decoy और proxy namespaces बनाएं; (2) benign tagged test request उपयोग करें; (3) owned router को केवल उस tag को proxy तक redirect करने दें; (4) pre/post-routing tuples और request IDs log करें; (5) ordinary और signaled flows compare करें; (6) false positives और removal test करें; (7) lab routes नष्ट करें।

**Detection:** authorized network operators routing divergence, unusual client hello/tag behavior और decoy-versus-back-end flow discrepancies inspect कर सकते हैं। **Capture-resilient OPSEC:** research client में केवल test keys और documentation addresses रखें। **Monitoring:** signed lab-router decisions को proxy arrivals से compare करें; production transit providers को probe करके signaling detection निर्धारित न करें।

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gateway IPFS content identifier (CID) retrieve करता है, संभवतः cache या peers से, और verifiable content client को लौटाता है। Original publisher final reader के बजाय gateway या अन्य peers देख सकता है; gateway reader IP और requested CID देखता है। Native peer-to-peer retrieval client को peers और DHT/routing participants के सामने expose करता है।<sup>[[24]](#references)</sup>

**Pros:** caches publisher और reader अलग कर सकते हैं; immutable content hash-verifiable; replicated data एक host के बाद भी रहता है; HTTP clients को native peer stack नहीं चाहिए।

**Cons:** public CIDs और gateway logs interests दिखाते हैं; first retrieval timing publisher और reader correlate कर सकता है; malicious web content और path-style same-origin hazards; public gateways best-effort हैं और abuse रोकते हैं।

**Procedure:** (1) harmless test file owned private IPFS swarm या owned gateway पर publish करें; (2) CID record करें; (3) subdomain isolation के साथ separate owned HTTP gateway से retrieve करें; (4) bytes को CID से verify करें; (5) caching के बाद दोहराएँ; (6) publisher, peer और gateway logs compare करें; (7) retention समाप्त होने पर unpin और test content हटाएँ।

**Detection:** gateways source/CID log करते हैं; DHT और peer connections retrieval दिखाते हैं; endpoint history और file hashes content पहचानते हैं। **Capture-resilient OPSEC:** read-only field client पर private publishing key न रखें और content addressing से पहले sensitive content encrypt करें। **Monitoring:** unexpected pinning, peer-set change, allowlist के बाहर CID requests या gateway account notices पर alert करें।

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR) client को database से एक record retrieve करने देता है और stated single- या multi-server threat model के अंतर्गत selected index को server से cryptographically छिपाता है। यह bounded dataset में query selection protect करता है; general web access या IP anonymity नहीं।<sup>[[25]](#references)</sup>

**Pros:** मजबूत application-specific query privacy; measurable leakage model; key directories, blocklists या छोटे public databases के लिए उपयोगी; exact lookup terms reveal करने की आवश्यकता घटा सकता है।

**Cons:** computation/bandwidth overhead; relay के बिना server connection time/IP जानता है; dataset version, response size और application state users partition कर सकते हैं; implementation maturity अलग-अलग है।

**Procedure:** (1) synthetic owned database के विरुद्ध audited PIR implementation deploy करें; (2) dataset version और parameters publish करें; (3) identical request sizes के माध्यम से कई indices retrieve करें; (4) correctness locally verify करें; (5) server logs compare करके confirm करें कि index absent है; (6) malicious/truncated responses और version mismatch test करें; (7) इसे anonymous browsing कहने के बजाय exact privacy assumption document करें।

**Detection:** networks service use और volume देखते हैं; endpoint telemetry client और final record use expose करती है; compromised server datasets या timing manipulate कर सकता है। **Capture-resilient OPSEC:** client पर केवल public database parameters और bounded cache रखें। **Monitoring:** signed dataset roots, fixed request shapes, error-rate changes और server-key rotations validate करें।

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** remote service URL fetch या render करके screenshot, metadata या sanitized content लौटाती है। Destination fetcher address देखता है; service requester, URL और result देखती है। Link-preview bots, security scanners या third-party URL fetchers का abuse authorized proxy use नहीं है।

**Pros:** active content workstation से isolate; destination controlled fetcher fingerprint पाता है; file type, size, destination और rendering limits enforce कर सकता है; disposable execution environment।

**Cons:** service को request की पूरी जानकारी; account/API/billing records; SSRF और data-exfiltration risk; scripts, authentication और interactive sites काम न कर सकते हैं; unique URLs requester और fetch correlate करते हैं।

**Procedure:** (1) strict allowlist of owned test domains वाला organization-owned fetcher deploy करें; (2) private, link-local, metadata और redirect-to-unapproved addresses block करें; (3) methods, redirects, bytes और render time cap करें; (4) credentials/cookies strip करें; (5) owned URL submit करें; (6) requester, fetcher और target logs compare करें; (7) render instance destroy करें और policy के अनुसार central audit retain करें।

**Detection:** target service ASN/fingerprint देखता है; provider और controller logs requester को URL से map करते हैं; endpoint process/API calls submission दिखाते हैं। **Capture-resilient OPSEC:** arbitrary destination authority के बिना एक short-lived project token उपयोग करें। **Monitoring:** allowlist denials, redirect violations, controller job ID के बिना fetches और provider abuse notices पर alert करें।

## Anycast rendezvous pool

**Mechanics:** multiple organization-controlled nodes एक stable service address advertise या front करते हैं और routing nearby instance चुनती है। Anycast availability सुधारता और individual back-end client से छिपाता है, लेकिन operator सभी instances नियंत्रित करता है और service address stable रहता है।<sup>[[26]](#references)</sup>

**Pros:** resilient regional ingress; एक instance fail होने पर field reconfiguration नहीं; DDoS/load distribution; central policy known nodes के बीच sessions move कर सकती है।

**Cons:** BGP/CDN और provider records organization पहचानते हैं; path changes stateful sessions तोड़ सकते हैं; client location के अनुसार monitoring अलग; single stable address आसानी से blocked या reputation-clustered होता है।

**Procedure:** provider-supported organization project या isolated routing lab उपयोग करें: (1) दो identical authenticated health endpoints deploy करें; (2) एक documented service address expose करें; (3) session state edge के बजाय broker पर रखें; (4) एक node withdraw करके reconnection verify करें; (5) certificate, policy और log consistency test करें; (6) unauthorized origin/region पर alert करें; (7) closeout पर advertisements और credentials हटाएँ।

**Detection:** BGP/RPKI/history, provider tenancy, certificates और identical service behavior pool पहचानते हैं। **Capture-resilient OPSEC:** edge पर केवल regional service identity हो, operator या fleet-enrollment key नहीं। **Monitoring:** authorized monitors से हर region probe करें, route origin और configuration digest compare करें, unexpected origin को incident मानें।

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection IDs NAT rebinding या address changes के दौरान client session alive रख सकते हैं; Multipath TCP एक reliable byte stream को multiple subflows में ले जा सकता है। ये Wi-Fi/cellular transitions में continuity सुधारते हैं, लेकिन common peer को पुराने और नए paths दिखाते हैं और cross-path correlation आसान कर सकते हैं।<sup>[[27]](#references)</sup>

**Pros:** uplink changes में faster recovery; application session restart आवश्यक नहीं; MPTCP resilience और throughput जोड़ सकता है; approved field nodes के लिए उपयोगी।

**Cons:** anonymity नहीं; peer migration/subflows देखता है; connection identifiers और simultaneous traffic paths जोड़ते हैं; middlebox/carrier support अलग; duplicated provider records exposure बढ़ाते हैं।

**Procedure:** (1) supported transport केवल owned field client और rendezvous के बीच enable करें; (2) application को IP से स्वतंत्र authenticate करें; (3) approved Wi-Fi पर bounded transfer शुरू करें; (4) organization cellular पर switch करें; (5) path validation, data integrity और clear/direct fallback न होने की पुष्टि करें; (6) idle timeout और return test करें; (7) हर path transition के broker records retain करें।

**Detection:** peer address migration या MPTCP subflows सीधे देखता है; access providers अपना हिस्सा देखते हैं; connection IDs, TLS identity और timing दोनों जोड़ते हैं। **Capture-resilient OPSEC:** केवल device-scoped session material store करें और resumable state जल्दी expire करें। **Monitoring:** impossible path changes, simultaneous unapproved networks, migration storms और quarantine के बाद resumption पर alert करें।

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** organization-owned workflow hosted runner पर bounded network check चलाता है। Destination cloud runner address देखता है, जबकि platform repository, actor, workflow, token, log और billing attribution रखता है। यह accountable egress वाला remote execution है, provider से anonymity नहीं।<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment; reproducible job definition; inbound connection नहीं; geographically distributed availability checks के लिए उपयोगी; strong controller audit।

**Cons:** platform और organization initiator पहचानते हैं; broad workflow tokens और untrusted pull requests खतरनाक; shared IP reputation; logs/artifacts secrets या target data retain कर सकते हैं।

**Procedure:** (1) assessment के लिए private organization repository और environment बनाएं; (2) केवल manually approved, fixed benign jobs को owned endpoints पर अनुमति दें; (3) minimal read-only workflow permissions और production secrets नहीं; (4) check चलाएँ; (5) workflow, provider और target records compare करें; (6) verify करें कि artifacts में credentials नहीं; (7) environment token delete करें और required audit retain करें।

**Detection:** provider audit और workflow logs direct attribution देते हैं; targets runner ASNs/ranges और stable request grammar पहचानते हैं। **Capture-resilient OPSEC:** field-device, signing, wallet या cloud-administrator secrets runner variables में कभी न रखें। **Monitoring:** branch/environment approval आवश्यक करें और workflow edits, fork execution, secret reads तथा unexpected destinations पर alert करें।

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio या serial/optical link nearby sensor से owner-approved Internet gateway तक bounded messages ले जाता है। Field device के पास Internet route नहीं; gateway ही egress है। Radio range और protocol limits इसे telemetry/store-and-forward design बनाते हैं, interactive anonymous Internet नहीं।

**Pros:** smallest field device से Internet stack और credentials हटाता है; low power; gateway policy centralize करता है; temporary dead zones bridge कर सकता है।

**Cons:** RF/physical discovery, pairing और device identifiers; कम bandwidth और range; gateway सभी messages जोड़ता है; spectrum और encryption restrictions अलग; capture queued data expose कर सकता है।

**Procedure:** (1) site और spectrum approval लें; (2) unique keys के साथ एक owned sensor को एक owned gateway से pair करें; (3) signed fixed-size message types, TTL और rate तय करें; (4) sensor को default IP route न दें; (5) gateway को केवल owned collector तक forward करने दें; (6) replay, range loss और gateway outage test करें; (7) दोनों devices inventory और retrieve करें।

**Detection:** RF survey, pairing database, physical inspection और gateway process/flow logs path दिखाते हैं। **Capture-resilient OPSEC:** sensor में केवल pairwise key और bounded encrypted queue रखें; operator, Wi-Fi, cellular या controller credentials कभी नहीं। **Monitoring:** new peers, sequence rollback, key failure, unusual RF rate और unregistered gateway से आने वाले messages पर alert करें।

## Capture/compromise exposure matrix

यह table ऊपर की प्रत्येक family पर capture-resilience check लागू करती है। “Minimize” का अर्थ authorized assets पर secrets और blast radius घटाना है; इसका अर्थ evidence clear करना या investigation से छिपना नहीं।

| Technique family | A captured endpoint/relay can reveal | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | known networks, DHCP/portal history, MACs, tunnel peer | separate organization device; जहाँ supported हो private MAC; personal accounts नहीं; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames, keys, routes, logs और adjacent hop | प्रति engagement एक identity; short TTL; narrow routes; broker-side revocation; master keys नहीं |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers और cached requests | payload identifiers कम करें; approved config pin करें; bounded cache; strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software, bridge/onion material, local state और peer history | standard client; separate service keys; encrypted minimal state; compromised service identity rotate करें |
| Remote browser/VDI/jump host | workspace token, clipboard/files और remote tenant | gateway पर phishing-resistant MFA; transfer channels disabled; rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider और approximate location | organization contract; personal co-location नहीं; narrow APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | केवल consented/owned nodes; signed agent; per-node credential; controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment और billing references | dedicated project; least-privilege role; short-lived deploy token; provider audit centrally retain |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results और custody data | signed bounded jobs; TTL; encrypted cache; separate producer identity; immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artifacts | written placement; unique device identity; operator secret नहीं; tamper/state telemetry; revoke और recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route और uplink profiles | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed paths |
| IPv6 temporary addressing | profiles, prefix history और endpoint/application state | इसे केवल anti-tracking मानें; network logs preserve करें; endpoint compartmentation के साथ pair करें |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state और research keys | standard client या isolated lab; personal browser state नहीं; production signaling नहीं |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway या service token | encrypted bounded cache; public-only parameters; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state और every known path | regional identity only; short resumption lifetime; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs और artifacts | least-privilege workflow; production/field/wallet secrets नहीं; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages और gateway identity | unique pairwise key; fixed message schema; Wi-Fi/cellular/operator credential नहीं |

## Monitoring possible discovery for every access family

कोई client-side test यह सिद्ध नहीं करता कि investigator या defender watching नहीं कर रहा। Engagement के स्वामित्व वाले systems में changes monitor करें, उन्हें controller/client से corroborate करें और observers को probe करने के बजाय stop करें। नीचे की rows ऊपर की हर technique को cover करती हैं; इन्हें [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise) के साथ मिलाएँ।

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | unapproved network/SIM/device, unexplained relocation या provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback या out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer या provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health और owned canary page | personal-account crossover, unexpected non-Tor connection या compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association और content hash | unknown peer/gateway, sequence rollback, unauthorized content या missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export और cloud audit | unknown login/workflow edit, secret read, unexpected destination या project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature और TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use या site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation और broker session | impossible migration, simultaneous unapproved paths या session resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root या provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Choosing and testing a path

1. हटाए जाने वाले observer और छिपाए जाने वाले data का नाम दें।
2. उसे हटाने वाली least-complex family चुनें।
3. source, entry, traversal, exit, DNS, account और payment observers draw करें।
4. अलग endpoint/application identity उपयोग करें।
5. IPv4, IPv6, DNS, WebRTC/application bypass और destination view verify करें।
6. हर hop तोड़कर failure closed होने की पुष्टि करें।
7. अपने control वाले प्रत्येक component पर logs compare करें।
8. residual timing, provider, endpoint और physical links record करें।

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
