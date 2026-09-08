# Katalogus van Anonymous Internet Access Techniques

Dit is die kanonieke inventaris van toegangspaaie. Dit dek protokol- en operasionele **families**, nie elke verskaffernaam nie. Geen Internet-pad waarborg anonymity nie: rekening-, browser-, endpoint-, tydsberekening-, betalings-, cloud-control-plane- en fisiese bewyse kan ’n roete wat perfek lyk, verydel.

Elke inskrywing gebruik dieselfde velde. “Procedure” beteken ’n wettige deployment of ’n emulasie in ’n laboratorium wat jy besit. Waar die werklike tegniek afhang van die kompromittering van ’n router, diefstal van toegang of misbruik van ’n onwillige intermediary, vervang die reproduction dit met stelsels wat deur die oefening besit word.

## Coverage matrix

| Family | Wat die bestemming sien | Sterkste eienskap | Spoed | Behandeling |
|---|---|---|---|---|
| Shared NAT/CGNAT | gedeelde openbare address | ambiguity among subscribers | hoog | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | vinnige source-address separation | hoog | deployable |
| Multi-hop/split relay, MASQUE | finale proxy | knowledge split of volledige IP-tunnel | hoog/matig | deployable with trusted relays |
| Tor, bridge, onion service | exit- of onion identity | multi-party path en algemene browser | matig | deployable |
| I2P, GNUnet, mixnet | overlay-peer/gateway | overlay- of timing-resistance | laag/varieerbaar | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | source/request-partitioning | hoog | supported applications only |
| Public Wi-Fi, travel router | venue/tunnel address | location/access-path change | hoog | permission required |
| Cellular/eSIM, satellite | carrier/provider address | onafhanklike fisiese uplink | hoog/varieerbaar | subscription/provider observes |
| Remote browser/jump host | remote workspace | endpoint- en egress-separation | hoog | deployable |
| Residential/mobile proxy | consumer/carrier address | consumer-network appearance | hoog | consent/provenance critical |
| ORB/compromised relay | another victim's address | origin concealment en borrowed reputation | hoog | owned-lab reproduction only |
| CDN/fronting/redirector | CDN/front address | beskerm back-end infrastructure | hoog | provider/owner approval required |
| Fast flux/DGA/dead drop | rotating node/service | infrastructure discovery resistance | varieerbaar | owned-lab reproduction only |
| Drop/nearest-neighbor | local target-adjacent address | crosses geographic/network boundary | hoog | owned-site lab only |
| Store-and-forward/offline | gateway or physical receiver | verminder interactive timing linkage | laag | application-specific |
| Pluggable/refraction transport | Tor entry or cooperating diversion proxy | censorship-resistant reachability | varieerbaar | supported client or research lab |
| IPFS gateway/PIR/remote fetcher | gateway or application service | publisher/query/request partitioning | varieerbaar | bounded application only |
| Anycast/QUIC/MPTCP | stable broker or multiple subflows | rendezvous en session continuity | hoog | availability, not anonymity |
| CI/CD automation runner | hosted runner address | disposable accountable egress | hoog | owned workflow only |
| Non-IP local first hop | organization gateway | verwyder Internet stack from sensor | laag | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** verskeie users deel een openbare address; die access provider map subscriber-side addresses en ports na die openbare tuple.

**Pros:** vinnig; geen spesiale client nie; die destination-side IP identifiseer moontlik net ’n household, venue of carrier pool.

**Cons:** die provider kan subscriber/port/time mappings behou; accounts en fingerprints bly; ander users kan die address reputation beskadig.

**Procedure:** (1) bevestig of die gemagtigde access NAT/CGNAT gebruik; (2) teken die presiese openbare IP en source port by ’n endpoint wat jy besit aan; (3) hou application identities geskei; (4) behandel shared addressing nie as ’n privacy control nie; (5) gebruik ’n sterker path indien die ISP nie destinations mag leer nie.

**Detection:** destinations behoort source port en presiese tyd, nie net IP nie, te behou. Providers korreleer NAT-allocation logs; investigators koppel account-, device- en browser-bewyse.

## Commercial VPN

**Mechanics:** ’n Encrypted full-tunnel connection terminateer by die VPN; destinations sien sy egress. Die VPN kan normaalweg source, timing en destinations koppel.

**Pros:** vinnig; eenvoudig; beskerm teen plaaslike passive observation; stabiele of gedeelde exits; goed vir controlled red-team egress.

**Cons:** concentrated trust; billing/login telemetry; kill-switch/DNS/IPv6 failures; shared exits word dikwels deur reputation geblokkeer.

**Procedure:** (1) identifiseer provider, owner, jurisdiction, retention en assessment policy; (2) installeer die signed official client; (3) enable full tunnel, always-on en fail-closed gedrag; (4) route DNS en IPv6 doelbewus; (5) verify observed IPv4/IPv6/DNS by ’n endpoint wat jy besit; (6) stop/reconnect die tunnel en bevestig dat geen clear fallback voorkom nie.<sup>[[1]](#references)</sup>

**Detection:** plaaslike networks sien ’n lang encrypted flow na VPN-infrastructure; providers het authentication/connection records; destinations gebruik ASN/reputation saam met account-, TLS/browser- en behavior-correlation.

## Self-hosted VPN or rented VPS egress

**Mechanics:** die operator beheer ’n WireGuard/OpenVPN gateway of forward traffic deur ’n rented server.

**Pros:** voorspelbare hoë spoed; fixed allowlistable address; custom logging/firewall; goeie incident control.

**Cons:** klein anonymity set; cloud tenant, payment, source login, API en image history koppel die operator; ’n distinctive nuwe server is maklik om te cluster.

**Procedure:** (1) skep ’n engagement-specific organization project; (2) provision ’n supported image en fixed address; (3) beperk management tot MFA/key-based administration; (4) configure full-tunnel egress en DNS; (5) allow slegs scoped destinations waar prakties; (6) test leak/failure behavior; (7) retain controller audit records; (8) destroy credentials en resources tydens teardown.

**Detection:** korreleer hosting ASN, first-seen address, certificate/service fingerprint en scanning behavior; cloud owners gebruik control-plane-, console-, billing- en flow-logs.

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** ’n application vra ’n proxy om ’n TCP-stream oop te maak; SOCKS kan ook name resolution en UDP vervoer, afhangend van die weergawe; SSH forward streams binne een encrypted session.

**Pros:** liggewig; per-application; vinnig; nuttig vir chaining en toegang tot segmented networks.

**Cons:** applications kan dit bypass; DNS kan leak; proxy sien aangrensende endpoints; browser state bly bestaan; open proxies kan traps of compromised systems wees.

**Procedure:** (1) deploy die proxy op ’n host wat jy besit; (2) require authentication en restrict source/destination; (3) configure een disposable application profile; (4) verseker remote DNS resolution waar nodig; (5) verify met ’n owned DNS/HTTP endpoint; (6) block direct egress vir die workload; (7) inspect en rotate proxy credentials.

**Detection:** identifiseer tunnel-capable processes, CONNECT/SOCKS negotiation, lang SSH-sessions en destinations wat nie by die application pas nie; proxy logs reconstruct streams.

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** ’n website fetch ’n destination en rewrite links/forms deur sy eie origin, of ’n extension stuur browser requests na ’n proxy. Die destination sien die service, terwyl die service plaintext kan sien ná TLS-termination en content kan inject of retain.

**Pros:** geen system-wide client nie; vinnig vir eenvoudige browsing; werk waar VPN-installation onmoontlik is.

**Cons:** proxy kan credentials/content lees, downloads rewrite en users fingerprint; scripts/WebSockets/downloads kan bypass; browser extension het breë privileges; klein anonymity set en gereelde blocking.

**Procedure:** (1) gebruik slegs ’n organization-operated proxy vir authorized testing; (2) isoleer dit in ’n disposable browser sonder personal accounts; (3) verbied password entry en sensitive downloads; (4) verify dat elke subresource op ’n owned page deur die proxy resolve; (5) test WebSocket-, download- en form behavior; (6) remove die extension/profile ná gebruik.

**Detection:** destination log die proxy; enterprise proxy/DNS en extension inventory identifiseer die service; content-security/reporting of owned canary subresources onthul direct bypass; proxy logs map user session na targets.

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** ’n entry sien die source, terwyl een of meer traversal relays dit skei van ’n exit wat die destination sien.

**Pros:** geen gewone relay benodig beide ends nie; failure/seizure van een node onthul minder; buigsame geography.

**Cons:** shared administration/logs vernietig die split; latency; timing correlation; meer failure- en DNS-routes; dieselfde account/payment kan elke hop verbind.

**Procedure:** (1) definieer watter observer elke hop verwyder; (2) gebruik independently administered owned/approved relays waar separation belangrik is; (3) enforce entry-only access vanaf die workload; (4) ensure elke relay kan slegs die volgende hop bereik; (5) verify logs by elke layer; (6) stop elke hop en confirm fail-closed behavior. Reproduceer met [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detection:** korreleer aangrensende NetFlow timing/volume, repeated proxy handshakes en common controller infrastructure; moenie operator geography uit die exit aflei nie.

## Split-knowledge application relay and OHTTP

**Mechanics:** die client encrypt ’n stateless HTTP-message na ’n gateway en stuur dit deur ’n relay. Die relay sien client IP maar nie die request nie; die gateway sien die request maar normaalweg net die relay IP.

**Pros:** sterk, auditable privacy partition vir supported requests; laer overhead as general anonymity networks.

**Cons:** nie arbitrary browsing nie; cookies/authentication kan relink; relay/gateway collusion en traffic analysis bly; application moet dit implementeer.

**Procedure:** (1) selecteer ’n application wat RFC 9458 uitdruklik ondersteun; (2) verify gateway keys deur die official configuration path; (3) vermy stable per-user fields; (4) stuur slegs die supported stateless request; (5) compare relay-, gateway- en target-logs; (6) test key rotation/failure sonder direct fallback.<sup>[[2]](#references)</sup>

**Detection:** enterprise endpoints expose die initiating process en OHTTP relay; gateways detect malformed/replayed traffic; timing en stable payload/account fields kan requests korreleer.

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT oor TLS/QUIC dra UDP- of IP-packets deur ’n proxy. Dit kan ’n moderne VPN-like tunnel implementeer en transport met HTTP/3 blend, maar die proxy bly ’n observer.<sup>[[3]](#references)</sup>

**Pros:** doeltreffende multiplexing/roaming; ondersteun UDP of volledige IP; deploy deur moderne HTTP-infrastructure.

**Cons:** nie ’n anonymity network nie; proxy/account sien source en destinations; QUIC/HTTP fingerprints en well-known paths is sigbaar vir endpoints/providers.

**Procedure:** (1) gebruik ’n client/service wat RFC 9298/9484-support dokumenteer; (2) authenticate die proxy certificate/configuration; (3) define allowed target routes; (4) enable encrypted DNS binne die path; (5) verify UDP, TCP, IPv6 en failover teen owned endpoints; (6) inspect proxy request- en flow-logs.

**Detection:** endpoints sien die client process en virtual interface; networks kan sustained QUIC/TLS na ’n proxy klassifiseer; proxy logs expose CONNECT target/path en assigned routes.

## Tor Browser

**Mechanics:** Tor kies guard-, middle- en exit-relays; layered encryption beperk elke relay se view. Tor Browser voeg ’n standardized browser by wat ontwerp is om fingerprinting te weerstaan.

**Pros:** groot public anonymity set; geen gewone relay ken albei ends nie; destination unlinkability sonder operating servers.

**Cons:** stadiger; TCP-focused; exit reputation/blocks; logins en disclosures identifiseer die user; low-latency timing correlation bly moontlik.

**Procedure:** (1) download en verify Tor Browser vanaf die project; (2) behou defaults en vermy extensions; (3) kies ’n gepaste security level; (4) skep ’n separate identity/session; (5) vermy identifying accounts en external active documents; (6) gebruik HTTPS of authenticated onion services; (7) verify die exit slegs met ’n owned endpoint.<sup>[[4]](#references)</sup>

**Detection:** plaaslike networks kan known guard traffic identifiseer tensy ’n bridge/transport gebruik word; destinations sien exits en Tor Browser behavior; end-to-end observers korreleer timing/volume.

## Tor bridges and pluggable transports

**Mechanics:** ’n non-public bridge vervang die public guard; obfs4, Snowflake of WebTunnel verander die first-hop transport om simple blocking/probing te weerstaan.

**Pros:** omseil censorship en verberg obvious public-relay destinations; behou die Tor circuit ná entry.

**Cons:** transport patterns/bridge discovery bly moontlik; variable performance; bied geen ekstra protection teen accounts of global timing nie.

**Procedure:** (1) probeer direct Tor eerste; (2) kies in Tor Browser Connection settings ’n ingeboude supported transport of versoek ’n official bridge; (3) moenie random binaries/lists gebruik nie; (4) connect en run ’n benign test; (5) test reconnect en clock; (6) hou alle ander browser settings standard.<sup>[[5]](#references)</sup>

**Detection:** censors gebruik destination discovery, protocol/flow classification en active probing; defenders moet circumvention use van compromise onderskei en op endpoint process/context staatmaak.

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Tor verberg direct Tor use teenoor die access ISP maar stel die source aan die VPN bloot. Tor-before-VPN gee die VPN post-Tor traffic en dikwels ’n stable customer/tunnel identity.

**Pros:** verwyder ’n spesifieke observer wanneer dit korrek ontwerp is; kan networks bereik wat een layer block.

**Cons:** complexity, uncommon fingerprint, leaks, reduced anonymity set en false confidence; Tor Project beskou combinations as advanced.<sup>[[6]](#references)</sup>

**Procedure:** (1) skryf neer watter observer verwyder en watter nuwe observer ingevoer word; (2) gebruik ’n disposable environment; (3) establish slegs die intended outer path; (4) enforce firewall routes; (5) verify DNS/IPv4/IPv6 en elke failure order; (6) compare beide providers se visibility; (7) abandon die stack indien dit geen measurable advantage het nie.

**Detection:** local/VPN/Tor observers sien verskillende aangrensende layers; timing bly end-to-end; unusual nested tunnel fingerprints en provider accounts kan sessions link.

## Onion service

**Mechanics:** client en service bou albei Tor circuits na ’n rendezvous, wat die service IP verberg en ’n exit vermy.

**Pros:** source- en service-location protection; end-to-end onion authentication; geen public inbound port nie; optional client authorization.

**Cons:** origin leaks deur updates/analytics/errors; onion key is critical; application identity/timing en host compromise bly.

**Procedure:** (1) isoleer die application en bind dit slegs aan loopback/socket; (2) install supported Tor; (3) configure ’n v3 onion service volgens official instructions; (4) protect/back up sy key slegs indien stable identity nodig is; (5) add client authorization vir closed use; (6) remove third-party fetches; (7) verify externally dat die origin nie reachable is nie.<sup>[[7]](#references)</sup>

**Detection:** host/network defenders vind Tor process/configuration en outbound circuits; application errors, DNS, certificates of third-party resources kan origin blootstel.

## I2P internal services

**Mechanics:** I2P gebruik separate unidirectional inbound/outbound tunnels vir destinations binne die overlay; public-Internet outproxies voeg ’n trust point by.

**Pros:** decentralized internal publishing; geen official exit dependency nie; separate inbound/outbound paths.

**Cons:** nie ’n general web replacement nie; kleiner ecosystem; long-running peer behavior; outproxy kan public browsing observeer.

**Procedure:** (1) install vanaf die official source; (2) gebruik ’n dedicated context; (3) permit integration/bandwidth stabilization; (4) access ’n I2P-native owned service; (5) vermy outproxies tensy uitdruklik nodig; (6) verify shutdown gee geen direct fallback nie; (7) inspect local peer- en service-logs.<sup>[[8]](#references)</sup>

**Detection:** local networks sien long-lived peer traffic en bootstrap behavior; endpoints expose router/application processes; outproxies log exits.

## Mixnets

**Mechanics:** fixed-size packets, batching, delay, reordering en cover traffic verminder timing correlation; gateways bridge applications.

**Pros:** beter weerstand teen timing analysis as low-latency proxies; nuttig vir asynchronous messages/transactions.

**Cons:** latency, bandwidth overhead, kleiner deployment en application limits; gateway/account metadata kan bly.

**Procedure:** (1) selecteer ’n maintained client en supported application; (2) lees die actual threat model; (3) install in ’n separate compartment; (4) stuur benign data na ’n owned endpoint; (5) meet latency/reliability en reply path; (6) test gateway failure; (7) disable nooit delays/cover traffic bloot vir spoed nie.<sup>[[9]](#references)</sup>

**Detection:** endpoints identify die client; access networks kan gateways/packet cadence klassifiseer; gateways en exits observeer aangrensende roles, terwyl breër correlation langer statistical windows benodig.

## GNUnet anonymous file sharing

**Mechanics:** GNUnet kan publish/search/download requests deur peers routeer en cover traffic byvoeg volgens ’n anonymity level. Sy eie documentation waarsku dat default level 1 nie cover traffic vereis nie en dat kragtige traffic analysis origin kan identifiseer.<sup>[[10]](#references)</sup>

**Pros:** decentralized, application-native anonymous sharing; tunable cover-traffic requirement.

**Cons:** nie gewone anonymous web access nie; performance/storage cost; peer- en traffic-analysis limitations; GNUnet VPN documentation sê sy IP overlay bied nie goeie anonymity nie.

**Procedure:** (1) install ’n maintained official build; (2) isoleer ’n test peer; (3) cap bandwidth/storage; (4) publish ’n harmless unique test file met ’n gekose anonymity level; (5) retrieve vanaf ’n ander owned peer; (6) record cover-traffic en latency; (7) moenie beweer dat die IP VPN-component equivalent anonymity bied nie.

**Detection:** peer bootstrap, overlay traffic, local datastore/process en file identifiers; ’n broad observer kan traffic volume teenoor cover traffic ontleed.

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQ encrypt na ’n resolver; ODoH split client address van query tussen proxy en resolver; ECH encrypt die inner TLS ClientHello/server name.

**Pros:** verwyder plaintext DNS/SNI van sommige local observers; ODoH partition source/query knowledge.

**Cons:** nie ’n IP-anonymity path nie; resolver/proxy/server behou roles; destination IP/timing/volume en endpoint bly; fallback kan leak.

**Procedure:** (1) kies of OS, application of tunnel DNS besit; (2) enable strict encrypted mode of supported ODoH; (3) test ’n unique owned domain; (4) capture locally om te confirm geen clear query nie; (5) laat die resolver fail en verify intended behavior; (6) confirm vir ECH dat server diagnostics inner ClientHello acceptance toon.<sup>[[11]](#references)</sup>

**Detection:** endpoint/resolver logs expose queries; networks identifiseer encrypted-resolver endpoints en destination flows; ECH state is sigbaar by endpoints/CDN selfs wanneer dit op die path versteek is.

## Split-provider privacy relay

**Mechanics:** products soos iCloud Private Relay gebruik ’n ingress wat die client ken en ’n independently operated egress wat die destination ken, met coarse region handling.

**Pros:** low-friction split knowledge; vinnig; integrated DNS/web protection vir supported traffic.

**Cons:** product/application scope is beperk; account/platform provider identifiseer steeds die customer; nie arbitrary system anonymity nie; collusion/legal en timing risks.

**Procedure:** (1) bevestig presies watter applications en traffic types ondersteun word; (2) enable die feature onder ’n dedicated platform context waar gepas; (3) kies region behavior; (4) test Safari/DNS en unsupported applications separately; (5) inspect destination address; (6) test network switching/failure.<sup>[[12]](#references)</sup>

**Detection:** access sien ingress; destination sien egress; platform/relay logs en account records span hul respective layer; unsupported applications expose normal paths.

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** browsing/tool execution gebeur op ’n remote system; die destination sien sy egress terwyl die workspace provider die operator connection en control plane sien.

**Pros:** vinnig; isoleer risky content; stable controlled egress; disposable state en strong organizational audit.

**Cons:** provider/admin kan session/account observeer; screen/clipboard/file channels leak; remote browser fingerprint kan unique wees; nie anonymous teenoor die workspace owner nie.

**Procedure:** (1) create one organization-owned workspace per engagement; (2) require MFA en restrict administration; (3) disable of constrain clipboard/upload/download; (4) route deur approved fixed egress; (5) gebruik geen personal IdP/sync nie; (6) export slegs reviewed evidence; (7) destroy workspace en credentials volgens schedule.

**Detection:** provider- en IdP-logs map user na session; destinations cluster workspace egress/browser; enterprise defenders identify remote-control protocols en anomalous cloud sessions.

## Public or guest Wi-Fi

**Mechanics:** traffic exit deur die venue NAT of ’n tunnel wat daar begin word.

**Pros:** hoë spoed en ’n shared non-home address; geen dedicated infrastructure nie.

**Cons:** venue association/DHCP/portal, camera, purchase en location evidence; hostile peers/APs; terms; physical risk.

**Procedure:** (1) obtain access offered to guests en verify SSID with staff; (2) gebruik ’n patched low-trust device; (3) disable sharing/auto-join en enable private MAC; (4) complete portal sonder reused identity; (5) start ’n fail-closed VPN/Tor path; (6) verify tethered traffic; (7) forget the network.

**Detection:** venue correlate AP, MAC, DHCP, portal en time; destination sien venue/tunnel; investigators combine physical en device evidence. Moet nooit access control omseil nie.

## Travel router

**Mechanics:** ’n operator-owned router join venue Wi-Fi/Ethernet en verskaf ’n isolated internal network met enforced tunnel policy.

**Pros:** isoleer workstations; central kill switch/DNS; consistent client network; shield privileged endpoints teen local broadcasts.

**Cons:** router word ’n stable radio/DHCP fingerprint; voeg attack surface by; captive portals en tethering kan tunnel bypass.

**Procedure:** (1) update supported firmware; (2) set unique management credentials en disable WAN admin/WPS/UPnP; (3) configure private upstream MAC waar permitted; (4) create separate internal SSID; (5) enforce full-tunnel DNS/IPv6 firewall policy; (6) test portal, reconnect en tunnel failure.

**Detection:** venue sien router association en traffic shape; local RF/DHCP fingerprinting identifiseer dit; VPN provider sien venue source.

## Cellular, prepaid SIM and eSIM

**Mechanics:** ’n modem gebruik carrier radio access en gewoonlik carrier NAT; ’n VPN/Tor-layer kan die destination-visible exit verander.

**Pros:** independent van local wired/Wi-Fi network; mobile; high speed; nuttige backhaul vir authorized drops.

**Cons:** carrier ken subscriber/eSIM, IMSI, IMEI, cells, time en assigned ports; registration laws vary; co-location met personal phone link devices.

**Procedure:** (1) obtain service lawfully met accurate required details; (2) use organization-owned separate modem/device; (3) record it with exercise controller; (4) disable unrelated radios/accounts; (5) establish approved tunnel; (6) test of tethered clients dit werklik volg; (7) verify provider- en retention-assumptions voor travel.<sup>[[13]](#references)</sup>

**Detection:** carrier records en RF location; enterprise USB/PCI/MDM inventory en rogue-hotspot surveys; destination/tunnel timing.

## Satellite Internet and satellite downlink abuse

**Mechanics:** normal service gebruik ’n registered terminal/provider. Ouer one-way DVB-S abuse het ’n receiver binne ’n beam toegelaat om unencrypted downlink traffic te observeer wat aan ’n legitimate subscriber gerig is, terwyl ’n ander path vir outbound requests gebruik is.

**Pros:** wide footprint; independent last mile; historical one-way abuse kon C2 aan ’n subscriber geography misattributeer.

**Cons:** equipment/RF/provider records; latency en coverage; moderne bidirectional systems verskil; outbound path en asymmetric routing bly evidence.

**Procedure:** vir lawful access, register ’n owned terminal en tunnel traffic soos vereis. Om historical Turla behavior te emulateer, replay synthetic one-way packet captures binne ’n RF-free lab en test of analysts ’n reply aan ’n host detecteer wat geen request gemaak het nie; moenie live satellite traffic intercept nie.<sup>[[14]](#references)</sup>

**Detection:** provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency en malware configuration.

## Residential/mobile proxy or consented proxyware

**Mechanics:** ’n backconnect gateway assign consumer broadband/mobile exits, sticky of rotating. Supply kan consensual, deceptively bundled of malicious wees.

**Pros:** hoë spoed; geographic choice; consumer ASN vermy sommige hosting blocks; groot pools.

**Cons:** provenance/consent en legal risk; broker sien customer; infected exits benadeel victims; rotation skep anomalies; duur en unreliable.

**Procedure:** gebruik slegs documented, informed-consent organization-owned agents vir emulation: (1) enroll test endpoints; (2) inventory owners/IPs; (3) configure gateway; (4) rotate sticky/per-request modes; (5) stuur slegs na ’n owned target; (6) compare gateway/exit/target logs; (7) remove elke agent.

**Detection:** impossible travel, stable browser/account oor rapid IP/ASN changes, backconnect protocols, proxyware process/network artifacts en broker/controller relations.

## ORB, botnet and compromised edge-device relays

**Mechanics:** leased of compromised routers/IoT/servers vorm access-, traversal- en exit-roles wat as ’n fleet geadministreer word. Verskeie APT customers kan dit deel.

**Pros:** borrowed reputation/geography; short-lived exits; resilient multi-hop mesh; weak direct actor-to-IP link.

**Cons:** criminal victimization; implant/controller en fleet patterns; intermediary seizure; inconsistent performance; operator/customer service records.

**Procedure:** moenie werklike devices compromise nie. Gebruik [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) create isolated entry/transit/target networks; (2) attach owned dual-homed relay containers; (3) forward slegs een test port; (4) send ’n benign request; (5) verify target sien slegs exit; (6) rotate exit; (7) tear down alle named assets.<sup>[[15]](#references)</sup>

**Detection:** track topology, ports/services, controller relations, implant fingerprints en node lifecycle; centralize edge configuration/flow/integrity telemetry; moenie exit IP met actor gelykstel nie.

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** ’n public edge forward slegs traffic wat by ’n grammar pas; fronting plaas ’n benign outer SNI en ander inner HTTP authority, of blank SNI, wanneer die intermediary dit toelaat.

**Pros:** hide/protect back-end; fast global edge; blend destination met ’n shared service; rapid cutover.

**Cons:** CDN sien alle routing en tenant; baie providers verbied cross-tenant fronting; SNI/Host/process/flow en account artifacts; configuration reuse cluster campaigns.

**Procedure:** reproduceer slegs op ’n owned reverse proxy met [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): create local certificate/edge, route one mismatched Host na ’n owned target, log SNI en Host, stuur normal/mismatched requests, verwyder dan containers.<sup>[[16]](#references)</sup>

**Detection:** compare SNI/ECH/Host/`:authority` by endpoint of terminating edge; join initiating process, tenant/origin, request grammar en flow cadence.

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNS update ’n stable name; DGA derive changing candidate names; fast flux rotate service addresses met low TTL; double flux rotate ook name servers.

**Pros:** resilient discovery; rapid infrastructure replacement; shield controller agter baie nodes.

**Cons:** DNS skep centralized telemetry; entropy/NXDOMAIN/churn; low TTL en broad ASN patterns; registration en authoritative infrastructure bly.

**Procedure:** gebruik [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): serve ’n owned zone wat RFC 5737-addresses met five-second TTL teruggee, query dit herhaaldelik, verander die synthetic epoch, en validate analytics. Moet nooit test records na third parties wys nie.<sup>[[17]](#references)</sup>

**Detection:** sliding-window unique answers/ASNs, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters en process follow-on; exclude legitimate CDNs met context.

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** ’n public post, repository, document, object of feed bevat ’n encoded current endpoint of task. Die client kan results oor ’n ander channel terugstuur.

**Pros:** allowed high-reputation service; TLS; endpoint rotation sonder binary change; asymmetric tasking bemoeilik simple flow correlation.

**Cons:** stable object/account/API identifiers; provider records; endpoint decode/follow-on sequence; content kan seized of changed word.

**Procedure:** gebruik [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): host ’n encoded pointer op een owned container, fetch/decode vanaf ’n short-lived client, contact ’n second owned service, preserve both logs, en tear down.

**Detection:** correlate unusual process → stable object read → decode → new destination; hash/preserve content en behou full object paths, nie slegs domain nie.

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** functions/short-lived jobs loop agter provider NAT of ’n front; logical service bly stable terwyl instances en addresses rotate.

**Pros:** rapid deployment/destruction; provider-scale shared egress; min local disk; elastic regional routing.

**Cons:** tenant, role, API, image, secret, invocation, billing en front-to-origin logs is durable; cold-start en platform fingerprints; provider policy.

**Procedure:** (1) gebruik organization-owned exercise tenant; (2) deploy ’n benign function wat slegs ’n owned endpoint request; (3) record project/role/image/config; (4) invoke oor verskeie instances; (5) compare target IPs met audit/request IDs; (6) test log retention; (7) remove function, roles en secrets.

**Detection:** cloud audit/invocation logs, unusual role creation, shared egress plus stable request grammar, image/layer en secret reuse, en front-origin correlation.

## Authorized on-site drop

**Mechanics:** ’n inventoried small computer gebruik local wired/Wi-Fi en outbound VPN/cellular rendezvous, en present ’n local source.

**Pros:** realistic internal-origin testing; hoë spoed; kan NAC, physical inventory en egress controls test.

**Cons:** physical discovery/theft; serial/MAC/USB/DHCP/PoE/RF en camera evidence; loss kan credentials exposeer.

**Procedure:** volg [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) obtain exact written placement authority; (2) record serial, MAC, photo, location en retrieval time; (3) use signed minimal image en short-lived mutual credentials; (4) restrict outbound-only destinations/capabilities; (5) add server-side quarantine en bandwidth limits; (6) test SOC visibility en loss response; (7) retrieve, preserve required evidence, dan sanitize onder die agreed lifecycle policy. Moet nooit een in ’n venue versteek wat nie toestemming gegee het nie.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera en physical inspection.

## Nearest-neighbor wireless pivot

**Mechanics:** ’n actor beheer ’n host binne radio range van die target, en gebruik dan target Wi-Fi credentials om die boundary remotely te kruis. APT28 het nearby compromised organizations só gebruik.<sup>[[18]](#references)</sup>

**Pros:** geen operator travel nie; target sien ’n local radio source; bypass controls wat slegs op Internet entry toegepas word.

**Cons:** vereis nearby compromised/owned dual-radio host en valid access; RADIUS/NAC/AP en neighbor endpoint evidence; signal/device anomalies.

**Procedure:** reproduceer slegs met die [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): join an owned pivot to neighbor en target lab SSIDs, forward slegs one service, collect both AP/pivot logs, enable dan EAP-TLS/device posture en bevestig die second attempt fails.

**Detection:** correlate RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login en physical presence; hunt nearby endpoints vir simultaneous radios, forwarding en tunnels.

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** traffic traverse local peers, asynchronous gateways, removable media of scheduled queues eerder as een interactive Internet session.

**Pros:** werk tydens disruption/censorship; delayed/batched delivery verswak simple timing; geen central last mile vir local communication nie.

**Cons:** hoë latency; small anonymity set; custody/physical metadata; malicious peers; data reach uiteindelik ’n gateway wat dit observeer.

**Procedure:** (1) build isolated owned three-node mesh of file queue; (2) encrypt/authenticate content end to end; (3) remove direct Internet routes from origin; (4) relay ’n benign file ná ’n controlled delay; (5) verify slegs gateway contacts owned destination; (6) compare custody/timestamps; (7) preserve required evidence, dan sanitize temporary media/queues by approved closeout.

**Detection:** endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity en content identifiers. Longer correlation windows vervang interactive-flow analysis.

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN) alloceer ’n public relay address en dra UDP-, TCP- of TLS-traffic tussen ’n client en peers. ’n ICE-policy kan relay use forseer in plaas van ’n direct candidate bloot te stel. TURN los reachability op, nie general anonymity nie: die server authenticateer die client en observeer allocations, peers, time en volume.<sup>[[19]](#references)</sup>

**Pros:** widely implemented; hanteer restrictive NAT; ondersteun mobile WebRTC; die peer ontvang nie die client se direct transport address wanneer relay-only policy korrek afgedwing word nie.

**Cons:** TURN operator sien beide aangrensende sides; application identity, media fingerprint en signaling bly; relay-only kos bandwidth en latency; misconfiguration kan steeds host- of server-reflexive candidates gather.

**Procedure:** (1) deploy organization-owned TURN service met TLS en short-lived credentials; (2) restrict realms, peers, ports, quotas en expiration; (3) set test application to relay-only ICE; (4) call an owned peer; (5) inspect `getStats()` en packet capture om te bevestig slegs relay candidates media gedra het; (6) fail die relay en confirm geen direct fallback nie; (7) retain allocation logs vir die engagement.

**Detection:** signaling, browser process en TURN allocations join die session aan die relay; networks observeer sustained flows na TURN ports of TLS endpoints; peer sien die allocated relay. **Captured node:** application state en ephemeral TURN credentials kan realm en rendezvous service onthul. Minimize exposure met per-device, short-lived credentials en hou operator authentication slegs by die controller.

## Outbound-only rendezvous or reverse overlay

**Mechanics:** ’n node agter NAT initiateer ’n authenticated connection na ’n organization-controlled broker. Die operator authenticateer separately by die broker, wat ’n narrow management channel authorizeer; geen inbound port forwarding of direct operator-to-node route is nodig nie.

**Pros:** stable agter NAT en captive last miles; central revocation en audit; field-node address changes vereis geen operator discovery nie; skei operator identity skoon van node credential.

**Cons:** broker word ’n high-value correlation point; periodic keepalives is recognizable; ’n broad tunnel kan ’n unsafe pivot word; broker loss beëindig management.

**Procedure:** volg [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): issue one scoped device identity, permit slegs ’n owned broker en approved management service, use authenticated keepalive, enforce fail-closed routing, test address changes en reboot recovery, en revoke identity tydens loss drill. WireGuard dokumenteer ’n 25-second persistent keepalive as ’n broadly useful NAT interval wanneer dit werklik nodig is.<sup>[[20]](#references)</sup>

**Detection:** broker- en identity-provider-logs map beide sides; access network sien ’n repeated encrypted destination/cadence; endpoint inventory wys overlay agent. **Captured node:** aanvaar dat device key, broker name, tunnel addresses en cached task data blootgestel is. Dit mag geen operator private key, personal account of reusable controller token bevat nie.

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** ’n field workload poll ’n authenticated mailbox vir signed, pre-approved jobs en post bounded results. Die operator skryf deur ’n separate control plane; geen interactive socket bestaan tussen hulle nie.

**Pros:** verdra intermittent links; decouple timing en addressing; quotas en schemas beperk capability; eenvoudige centralized audit en revocation.

**Cons:** polling cadence en stable object/queue names fingerprint die system; provider logs join producer en consumer; delayed control; captured queued data kan die exercise exposeer.

**Procedure:** (1) create one engagement queue en one device identity; (2) define signed schema van benign, explicitly scoped jobs; (3) set message TTL, maximum result size en rate; (4) allow node om slegs sy queue te pull en slegs sy result prefix te write; (5) test offline accumulation, duplicate delivery en revocation; (6) centralize immutable access logs; (7) delete queue nadat retention requirements nagekom is.

**Detection:** hunt periodic API calls deur ’n unusual process, stable bucket/object/queue paths, identical user-agent of TLS behavior, en fetch-then-new-connection sequence. **Captured node:** local cache kan pending jobs en object names reveal; hou cache encrypted, bounded en disposable, terwyl authoritative controller logs behoue bly.

## Dual-uplink failover and connection migration

**Mechanics:** ’n approved field node het twee onafhanklike uplinks—soos venue Ethernet/Wi-Fi en organization cellular—en behou sy control session deur ’n overlay of message broker wanneer routes change. Dit is availability engineering, nie anonymity nie.

**Pros:** survive one provider, AP of captive-portal failure; support planned maintenance; permit quick isolation van ’n suspect path.

**Cons:** twee providers skep twee location/account records; simultaneous use maak correlation makliker; route en DNS leaks tydens failover; cellular co-location evidence bly.

**Procedure:** (1) register both organization-owned interfaces en providers; (2) assign deterministic route priorities en health checks na owned endpoints; (3) bind DNS en management aan die overlay; (4) prevent secondary path om inbound traffic te aanvaar; (5) unplug elke path en verify session recovery, source policy en geen direct destination access; (6) alert op unplanned path change; (7) document data use en roaming limits.

**Detection:** correlate dieselfde device certificate, request grammar en timing oor ASNs; local inventory sien beide radios; carriers/venues behou hul eie records. **Captured node:** beide SIM/device identifiers en known SSIDs kan sigbaar wees; gebruik organization assets en moenie die node met personal devices co-locate of pair nie.

## Organization private APN or managed cellular tunnel

**Mechanics:** ’n carrier private APN plaas enrolled SIMs in ’n private routed domain of tunnel traffic na ’n enterprise gateway. Dit skei die device van die public mobile Internet, maar verberg dit nie vir carrier of contracting organization nie.

**Pros:** stable private addressing; carrier-level enrollment en traffic policy; vermy public inbound exposure; nuttig vir authorized remote appliances.

**Cons:** subscriber, IMSI/IMEI, cell en billing attribution is sterk; procurement lead time en cost; carrier/gateway outage; nie anonymous teenoor die operator nie.

**Procedure:** (1) contract die APN in die assessment organization se name; (2) whitelist slegs registered SIMs en gateway prefixes; (3) add application-layer mutual authentication; (4) restrict APN route na rendezvous en update services; (5) test SIM removal, roaming, public-Internet breakout en revocation; (6) monitor carrier en gateway records; (7) cancel of quarantine elke SIM by closeout.

**Detection:** carrier inventory en cell telemetry, APN gateway flows, SIM/IMEI mismatch en enterprise asset records. **Captured node:** SIM en modem identifiseer die contract selfs wanneer storage encrypted is; capture resilience beteken dus rapid suspension en narrow authorization, nie deniability nie.

## Long-range point-to-point wireless bridge

**Mechanics:** directional Wi-Fi of ander licensed/unlicensed point-to-point radio verbind twee owner-approved sites, met Internet egress by die remote site. Dit kan die apparent IP location verskuif sonder ’n commercial proxy.

**Pros:** high throughput; independent van intermediate wired carriers; controllable RF en routing; nuttig vir testing van segmentation en remote-site monitoring.

**Cons:** line-of-sight, spectrum, landlord en regulatory constraints; distinctive RF emissions en hardware; beide endpoints is fisiese evidence; weather/power/alignment beïnvloed stability.

**Procedure:** (1) obtain written permission vir beide sites en verify spectrum/power rules; (2) survey path sonder transmission buite approved parameters; (3) use authenticated encryption en management VLAN; (4) restrict bridge tot ’n owned rendezvous of test subnet; (5) test failover, alignment, power recovery en RF containment; (6) label/inventory both radios; (7) remove them en verify configuration reset ná exercise.

**Detection:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic en remote-site egress logs. **Captured node:** configuration reveal peer en management domain; gebruik unique exercise credentials, geen personal management accounts nie, en rapid peer-key revocation.

## Consented cooperative or community exit

**Mechanics:** volunteers of partner organizations run relays knowingly onder ’n published policy. Traffic exit uit ’n shared community pool terwyl die coordination layer abuse en revocation account.

**Pros:** diverse non-cloud networks; explicit consent is safer than proxyware; shared governance kan trust versprei; nuttig vir research en censorship-resilience studies.

**Cons:** small pools en membership records verminder anonymity; exit operators ontvang complaints en observeer traffic metadata; malicious participants, variable uptime en jurisdiction differences.

**Procedure:** (1) publish acceptable-use en logging policy; (2) obtain informed opt-in van elke operator; (3) issue unique relay identity en restrict destinations/rates; (4) provide abuse handling en one-action revocation; (5) stuur tydens testing slegs authorized traffic na owned endpoints; (6) measure churn en correlation exposure; (7) remove relay cleanly wanneer consent eindig.

**Detection:** membership/control-plane records, relay certificates, common software fingerprint en exit behavior identifiseer die pool. **Captured node:** relay configuration kan cooperative identifiseer maar behoort nie client identities te bevat nie; store client-to-session accountability by die authorized controller onder access control.

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extensions create temporary interface identifiers sodat ’n stable address nie vir elke outbound connection hergebruik word nie. Provider prefix changes kan rotation byvoeg, maar die delegated prefix, subscriber record en upper-layer fingerprint bly.<sup>[[21]](#references)</sup>

**Pros:** verminder passive long-term tracking deur ’n stable interface identifier; ingebou in common operating systems; geen relay overhead nie.

**Cons:** nie source anonymity nie; ISP en local network ken steeds prefix/device; DNS, accounts en browser state link sessions; address churn bemoeilik allowlists en logging.

**Procedure:** (1) inspect current stable en temporary addresses op ’n owned client; (2) enable OS-supported privacy-address default eerder as third-party spoofing; (3) request ’n owned IPv6 endpoint herhaaldelik oor address lifetimes; (4) confirm inbound services bind slegs aan bedoelde stable addresses; (5) retain DHCPv6/RA/neighbor en precise endpoint logs; (6) test VPN/firewall behavior vir elke IPv6 address.

**Detection:** correlate delegated prefix, layer-2 identity, neighbor discovery, account en endpoint telemetry in plaas daarvan om een address as een device te behandel. **Captured node:** network profiles en interface identifiers bly; temporary addressing voorkom een passive identifier, nie forensic attribution nie.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** ’n pluggable transport verander hoe die eerste Tor connection lyk of hoe dit ’n bridge bereik. Snowflake gebruik short-lived volunteer WebRTC proxies, WebTunnel lyk soos ordinary HTTPS, obfs4 weerstaan eenvoudige protocol identification en active probing, en meek relay deur supported web infrastructure. Hulle is censorship-circumvention transports into Tor, nie ekstra end-to-end anonymity layers nie.<sup>[[22]](#references)</sup>

**Pros:** nuttig wanneer direct Tor of known relays geblokkeer word; Snowflake vermy ’n stable public bridge address; integrated in maintained Tor clients; destination ontvang steeds ordinary Tor properties.

**Cons:** laer of variable performance; broker/front/bridge en local network observeer verskillende metadata; transport fingerprints en blocking bly moontlik; volunteer proxy vervang nie Tor nie en behoort nie met application plaintext vertrou te word nie.

**Procedure:** (1) install en verify official Tor Browser of supported Tor client; (2) select built-in transport in Connection/Bridges; (3) connect slegs na owned diagnostic page; (4) confirm page sien ’n Tor exit, nie die Snowflake/WebTunnel peer nie; (5) compare bootstrap en performance; (6) fail transport en confirm client connect nie silently direct nie; (7) return na standard supported configuration ná test.

**Detection:** ’n censor kan destination allowlists, TLS/WebRTC behavior, broker discovery en flow analysis combineer; endpoints expose Tor en transport configuration. **Capture-resilient OPSEC:** gebruik standard client, copy nooit personal browser state daarin nie, en aanvaar dat bridge/broker history recoverable is. **Monitoring:** monitor Tor bootstrap logs, unexpected direct DNS/connection attempts en controller-side owned-page observations; transport failure is nie proof of discovery nie.

## Refraction networking or decoy routing

**Mechanics:** ’n cooperating network operator detecteer ’n covert signal in traffic wat apparently aan ’n allowed decoy gerig is en divert die flow na ’n circumvention proxy. Deployment vereis infrastructure in die network path; dit is nie iets wat ’n client kan create bloot deur ’n innocent website te select nie.<sup>[[23]](#references)</sup>

**Pros:** apparent destination kan moeilik wees vir ’n censor om te block sonder collateral damage; geen public bridge address hoef distributed te word nie; nuttig as research model vir on-path-assisted circumvention.

**Cons:** specialized ISP/transit participation; deployability en performance hang van routing af; client-to-decoy flow en proxy-side activity bly; ’n global of cooperating observer kan timing correlateer.

**Procedure:** moenie deur uninvolved networks signal nie. Reproduceer die architecture in ’n isolated lab: (1) create owned client, router, decoy en proxy namespaces; (2) use benign tagged test request; (3) laat owned router slegs daardie tag na proxy redirect; (4) log pre/post-routing tuples en request IDs; (5) compare ordinary en signaled flows; (6) test false positives en removal; (7) destroy lab routes.

**Detection:** authorized network operators kan routing divergence, unusual client hello/tag behavior en decoy-versus-back-end flow discrepancies inspecteer. **Capture-resilient OPSEC:** research client moet slegs test keys en documentation addresses bevat. **Monitoring:** compare signed lab-router decisions met proxy arrivals; moenie production transit providers probe om te bepaal of hulle signaling detected het nie.

## Content-addressed gateway or cached peer retrieval

**Mechanics:** ’n HTTP gateway retrieveer ’n IPFS content identifier (CID), moontlik uit sy cache of peers, en return die verifiable content aan die client. Die original publisher kan die gateway of ander peers sien eerder as die final reader; gateway sien reader IP en requested CID. Native peer-to-peer retrieval stel die client aan peers en DHT/routing participants bloot.<sup>[[24]](#references)</sup>

**Pros:** publisher en reader kan deur caches geskei word; immutable content is hash-verifiable; replicated data oorleef een host; HTTP clients benodig geen native peer stack nie.

**Cons:** public CIDs en gateway logs reveal interests; first retrieval timing kan publisher en reader correlateer; malicious web content en path-style same-origin hazards; public gateways is best-effort en verbied abuse.

**Procedure:** (1) publish harmless test file na ’n owned private IPFS swarm of owned gateway; (2) record CID; (3) retrieve deur ’n separate owned HTTP gateway using subdomain isolation; (4) verify bytes teenoor CID; (5) repeat after caching; (6) compare publisher-, peer- en gateway-logs; (7) unpin en remove test content wanneer retention eindig.

**Detection:** gateways log source/CID; DHT en peer connections reveal retrieval; endpoint history en file hashes identify content. **Capture-resilient OPSEC:** store geen private publishing key op ’n read-only field client nie en encrypt sensitive content voor content addressing. **Monitoring:** alert op unexpected pinning, peer-set change, CID requests buite allowlist of gateway account notices.

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR) laat ’n client een record uit ’n database retrieve terwyl die selected index cryptographically vir die server versteek word onder ’n stated single- of multi-server threat model. Dit beskerm query selection vir ’n bounded dataset; dit is nie general web access of IP anonymity nie.<sup>[[25]](#references)</sup>

**Pros:** strong application-specific query privacy; measurable leakage model; nuttig vir key directories, blocklists of small public databases; kan die behoefte verminder om presiese lookup terms te reveal.

**Cons:** computation/bandwidth overhead; server leer connection time/IP tensy combined met ’n relay; dataset version, response size en application state kan users partition; implementation maturity varieer.

**Procedure:** (1) deploy audited PIR implementation teenoor synthetic owned database; (2) publish dataset version en parameters; (3) retrieve verskeie indices deur identical request sizes; (4) verify correctness locally; (5) compare server logs en confirm index afwesig is; (6) test malicious/truncated responses en version mismatch; (7) document exact privacy assumption eerder as om dit anonymous browsing te noem.

**Detection:** networks sien service use en volume; endpoint telemetry expose client en final record use; compromised server kan datasets of timing manipulateer. **Capture-resilient OPSEC:** hou slegs public database parameters en ’n bounded cache op die client. **Monitoring:** validate signed dataset roots, fixed request shapes, error-rate changes en server-key rotations.

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** ’n remote service fetch of render ’n URL en return ’n screenshot, metadata of sanitized content. Die destination sien die fetcher address; service sien requester, URL en result. Abusing link-preview bots, security scanners of third-party URL fetchers is nie authorized proxy use nie.

**Pros:** isoleer active content van die workstation; destination ontvang ’n controlled fetcher fingerprint; kan file type, size, destination en rendering limits afdwing; disposable execution environment.

**Cons:** service het volledige request knowledge; account/API/billing records; SSRF en data-exfiltration risk; scripts, authentication en interactive sites werk moontlik nie; unique URLs correlate requester en fetch.

**Procedure:** (1) deploy organization-owned fetcher met strict allowlist van owned test domains; (2) block private, link-local, metadata en redirect-to-unapproved addresses; (3) cap methods, redirects, bytes en render time; (4) strip credentials/cookies; (5) submit owned URL; (6) compare requester-, fetcher- en target-logs; (7) destroy render instance en retain central audit volgens policy.

**Detection:** target sien service ASN/fingerprint; provider en controller logs map requester na URL; endpoint process/API calls show submission. **Capture-resilient OPSEC:** gebruik one short-lived project token sonder arbitrary destination authority. **Monitoring:** alert op allowlist denials, redirect violations, fetches sonder controller job ID en provider abuse notices.

## Anycast rendezvous pool

**Mechanics:** multiple organization-controlled nodes advertise of front one stable service address, en routing select ’n nearby instance. Anycast verbeter availability en hide ’n individual back-end van die client, maar operator beheer steeds alle instances en die service address bly stable.<sup>[[26]](#references)</sup>

**Pros:** resilient regional ingress; geen field reconfiguration wanneer een instance fail nie; DDoS/load distribution; central policy kan sessions tussen known nodes move.

**Cons:** BGP/CDN en provider records identifiseer organization; path changes kan stateful sessions break; monitoring verskil volgens client location; een stable address is maklik geblok of reputation-clustered.

**Procedure:** gebruik ’n provider-supported organization project of isolated routing lab: (1) deploy two identical authenticated health endpoints; (2) expose one documented service address; (3) keep session state at broker rather than edge; (4) withdraw one node en verify reconnection; (5) test certificate, policy en log consistency; (6) alert op unauthorized origin/region; (7) remove advertisements en credentials by closeout.

**Detection:** BGP/RPKI/history, provider tenancy, certificates en identical service behavior identify pool. **Capture-resilient OPSEC:** edge hou slegs regional service identity en geen operator- of fleet-enrollment key nie. **Monitoring:** probe elke region vanaf authorized monitors, compare route origin en configuration digest, en treat unexpected origin as incident.

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection IDs kan ’n client session alive hou oor NAT rebinding of address changes; Multipath TCP kan een reliable byte stream oor multiple subflows dra. Dit verbeter continuity oor Wi-Fi/cellular transitions, maar expose old en new paths aan die common peer en kan cross-path correlation makliker maak.<sup>[[27]](#references)</sup>

**Pros:** vinniger recovery tydens uplink changes; application session hoef nie restart nie; MPTCP kan resilience en throughput combineer; waardevol vir approved field nodes.

**Cons:** nie anonymity nie; peer sien migration/subflows; connection identifiers en simultaneous traffic link paths; middlebox/carrier support varieer; duplicated provider records verhoog exposure.

**Procedure:** (1) enable supported transport slegs tussen owned field client en rendezvous; (2) authenticate application independently of IP; (3) begin bounded transfer op approved Wi-Fi; (4) switch na organization cellular; (5) confirm path validation, data integrity en geen clear/direct fallback; (6) test idle timeout en return; (7) retain broker records van elke path transition.

**Detection:** peer observeer address migration of MPTCP subflows direk; access providers sien hul deel; connection IDs, TLS identity en timing join beide. **Capture-resilient OPSEC:** store slegs device-scoped session material en expire resumable state vinnig. **Monitoring:** alert op impossible path changes, simultaneous unapproved networks, migration storms en resumption ná quarantine.

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** ’n organization-owned workflow executeer ’n bounded network check op ’n hosted runner. Destination sien ’n cloud runner address terwyl platform repository, actor, workflow, token, log en billing attribution behou. Dit is remote execution met accountable egress, nie anonymity teenoor die provider nie.<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment; reproducible job definition; geen inbound connection nie; nuttig vir geographically distributed availability checks; strong controller audit.

**Cons:** platform en organization identifiseer initiator; broad workflow tokens en untrusted pull requests is dangerous; shared IP reputation; logs/artifacts kan secrets of target data retain.

**Procedure:** (1) create private organization repository en environment vir assessment; (2) permit slegs manually approved, fixed benign jobs teenoor owned endpoints; (3) use minimal read-only workflow permissions en geen production secrets nie; (4) run check; (5) compare workflow-, provider- en target-records; (6) verify artifacts contain no credentials; (7) delete environment token en retain required audit.

**Detection:** provider audit en workflow logs provide direct attribution; targets identify runner ASNs/ranges en stable request grammar. **Capture-resilient OPSEC:** plaas nooit field-device, signing, wallet of cloud-administrator secrets in runner variables nie. **Monitoring:** require branch/environment approval en alert op workflow edits, fork execution, secret reads en unexpected destinations.

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio of ’n serial/optical link dra bounded messages vanaf ’n nearby sensor na ’n owner-approved Internet gateway. Die field device self het geen Internet route nie; gateway is die enigste egress. Radio range en protocol limits maak dit ’n telemetry/store-and-forward design, nie interactive anonymous Internet nie.

**Pros:** verwyder Internet stack en credentials van die kleinste field device; low power; gateway centralize policy; kan temporary dead zones bridge.

**Cons:** RF/physical discovery, pairing en device identifiers; small bandwidth en range; gateway link steeds alle messages; spectrum en encryption restrictions varieer; capture kan queued data expose.

**Procedure:** (1) obtain site en spectrum approval; (2) pair one owned sensor met one owned gateway met unique keys; (3) define signed fixed-size message types, TTL en rate; (4) gee sensor geen default IP route nie; (5) laat gateway slegs na owned collector forward; (6) test replay, range loss en gateway outage; (7) inventory en retrieve beide devices.

**Detection:** RF survey, pairing database, physical inspection en gateway process/flow logs reveal path. **Capture-resilient OPSEC:** sensor hou slegs pairwise key en bounded encrypted queue, nooit operator-, Wi-Fi-, cellular- of controller-credentials nie. **Monitoring:** alert op new peers, sequence rollback, key failure, unusual RF rate en messages wat deur ’n unregistered gateway arriveer.

## Capture/compromise exposure matrix

Hierdie tabel pas ’n capture-resilience check op elke family hierbo toe. “Minimize” beteken verminder secrets en blast radius op authorized assets; dit beteken nooit om evidence te clear of vir ’n investigation weg te steek nie.

| Technique family | Wat ’n captured endpoint/relay kan onthul | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | known networks, DHCP/portal history, MACs, tunnel peer | separate organization device; private MAC waar supported; geen personal accounts nie; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames, keys, routes, logs en adjacent hop | one identity per engagement; short TTL; narrow routes; broker-side revocation; geen master keys nie |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers en cached requests | minimize payload identifiers; pin approved config; bounded cache; strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software, bridge/onion material, local state en peer history | standard client; separate service keys; encrypted minimal state; rotate compromised service identity |
| Remote browser/VDI/jump host | workspace token, clipboard/files en remote tenant | phishing-resistant MFA at gateway; disabled transfer channels; rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider en approximate location | organization contract; geen personal co-location nie; narrow APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | only consented/owned nodes; signed agent; per-node credential; controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment en billing references | dedicated project; least-privilege role; short-lived deploy token; provider audit retained centrally |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results en custody data | signed bounded jobs; TTL; encrypted cache; separate producer identity; immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artifacts | written placement; unique device identity; no operator secret; tamper/state telemetry; revoke and recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route en uplink profiles | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed paths |
| IPv6 temporary addressing | profiles, prefix history en endpoint/application state | treat as anti-tracking only; preserve network logs; pair with endpoint compartmentation |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state en research keys | standard client of isolated lab; geen personal browser state nie; geen production signaling |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway of service token | encrypted bounded cache; public-only parameters; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state en every known path | regional identity only; short resumption lifetime; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs en artifacts | least-privilege workflow; geen production/field/wallet secrets nie; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages en gateway identity | unique pairwise key; fixed message schema; geen Wi-Fi/cellular/operator credential |

## Monitoring possible discovery for every access family

Geen client-side test bewys dat ’n investigator of defender watch nie. Monitor changes in systems wat die engagement besit, corroborateer dit met die controller/client, en stop eerder as om observers te probe. Die rows hieronder dek elke technique hierbo; combineer dit met die [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | unapproved network/SIM/device, unexplained relocation of provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback of out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer of provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health en owned canary page | personal-account crossover, unexpected non-Tor connection of compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association en content hash | unknown peer/gateway, sequence rollback, unauthorized content of missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export en cloud audit | unknown login/workflow edit, secret read, unexpected destination of project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature en TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use of site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation en broker session | impossible migration, simultaneous unapproved paths of session resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pinning/query/destination, unsigned dataset root of provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Choosing and testing a path

1. Noem die observer wat verwyder en die data wat versteek moet word.
2. Kies die least complex family wat dit verwyder.
3. Teken source, entry, traversal, exit, DNS, account en payment observers.
4. Gebruik ’n separate endpoint/application identity.
5. Verify IPv4, IPv6, DNS, WebRTC/application bypass en destination view.
6. Break elke hop en confirm dat failure closed is.
7. Compare logs by elke component wat jy beheer.
8. Record residual timing, provider-, endpoint- en physical links.

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
