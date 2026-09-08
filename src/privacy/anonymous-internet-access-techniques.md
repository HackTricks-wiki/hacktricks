# Katalogi ya Mbinu za Ufikiaji wa Intaneti Bila Kutambulika

{{#include ../banners/hacktricks-training.md}}

Hii ni orodha kuu ya njia za ufikiaji. Inahusu **familia** za itifaki na uendeshaji, si kila jina la vendor. Hakuna njia ya Intaneti inayohakikisha kutotambulika: ushahidi wa akaunti, browser, endpoint, muda, malipo, cloud-control-plane na eneo halisi unaweza kushinda njia inayoonekana kuwa kamilifu.

Kila ingizo hutumia sehemu zilezile. “Procedure” inamaanisha deployment halali au emulation katika lab inayomilikiwa. Pale mbinu halisi inategemea ku-compromise router, kuiba access au kutumia intermediary asiye tayari, reproduction hutumia mifumo inayomilikiwa na zoezi.

## Coverage matrix

| Family | Destination sees | Strongest property | Speed | Treatment |
|---|---|---|---|---|
| Shared NAT/CGNAT | anwani ya public inayoshirikiwa | utata kati ya subscribers | high | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | anwani ya relay | kutenganisha source-address haraka | high | deployable |
| Multi-hop/split relay, MASQUE | proxy ya mwisho | kugawanya maarifa au tunnel kamili ya IP | high/moderate | deployable with trusted relays |
| Tor, bridge, onion service | exit au utambulisho wa onion | njia ya wahusika wengi na browser ya kawaida | moderate | deployable |
| I2P, GNUnet, mixnet | peer/gateway ya overlay | upinzani wa overlay au timing | low/variable | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | kugawanya source na request | high | supported applications only |
| Public Wi-Fi, travel router | anwani ya venue/tunnel | kubadilisha location/access-path | high | permission required |
| Cellular/eSIM, satellite | anwani ya carrier/provider | uplink huru ya kimwili | high/variable | subscription/provider observes |
| Remote browser/jump host | workspace ya mbali | kutenganisha endpoint na egress | high | deployable |
| Residential/mobile proxy | anwani ya consumer/carrier | kuonekana kama consumer network | high | consent/provenance critical |
| ORB/compromised relay | anwani ya victim mwingine | kuficha origin na kutumia reputation iliyokopwa | high | owned-lab reproduction only |
| CDN/fronting/redirector | anwani ya CDN/front | kulinda back-end infrastructure | high | provider/owner approval required |
| Fast flux/DGA/dead drop | node/service inayozunguka | upinzani dhidi ya kugunduliwa kwa infrastructure | variable | owned-lab reproduction only |
| Drop/nearest-neighbor | anwani iliyo karibu na target | kuvuka mpaka wa kijiografia/network | high | owned-site lab only |
| Store-and-forward/offline | gateway au receiver wa kimwili | kupunguza uhusiano wa interactive timing | low | application-specific |
| Pluggable/refraction transport | Tor entry au diversion proxy inayoshirikiana | reachability inayostahimili censorship | variable | supported client or research lab |
| IPFS gateway/PIR/remote fetcher | gateway au application service | kugawanya publisher/query/request | variable | bounded application only |
| Anycast/QUIC/MPTCP | broker thabiti au subflows nyingi | rendezvous na kuendelea kwa session | high | availability, not anonymity |
| CI/CD automation runner | anwani ya hosted runner | egress inayoweza kutupwa na inayowajibika | high | owned workflow only |
| Non-IP local first hop | gateway ya organization | kuondoa Internet stack kwenye sensor | low | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** watumiaji kadhaa hushiriki public address moja; access provider huchora anwani na ports za upande wa subscriber kwenda kwenye public tuple.

**Pros:** haraka; client maalum haihitajiki; IP ya upande wa destination pekee inaweza kutambua household, venue au carrier pool tu.

**Cons:** provider anaweza kuhifadhi mapping za subscriber/port/time; accounts na fingerprints hubaki; watumiaji wengine wanaweza kuharibu reputation ya address.

**Procedure:** (1) thibitisha kama access iliyoidhinishwa hutumia NAT/CGNAT; (2) rekodi public IP na source port kamili kwenye endpoint inayomilikiwa; (3) tenga application identities; (4) usichukulie shared addressing kama privacy control; (5) tumia njia imara zaidi ikiwa ISP haipaswi kujua destinations.

**Detection:** destinations zinapaswa kuhifadhi source port na muda sahihi, si IP pekee. Providers huunganisha NAT allocation logs; investigators huunganisha ushahidi wa account/device/browser.

## Commercial VPN

**Mechanics:** connection iliyosimbwa ya full-tunnel huishia kwenye VPN; destinations huona egress yake. VPN kwa kawaida inaweza kuhusisha source, timing na destinations.

**Pros:** haraka; rahisi; hulinda dhidi ya local passive observation; exits thabiti au zinazoshirikiwa; inafaa kwa controlled red-team egress.

**Cons:** trust iliyokolezwa; billing/login telemetry; hitilafu za kill-switch/DNS/IPv6; shared exits mara nyingi huzuiwa kwa sababu ya reputation.

**Procedure:** (1) tambua provider, owner, jurisdiction, retention na assessment policy; (2) sakinisha official client iliyosainiwa; (3) wezesha full tunnel, always-on na fail-closed behavior; (4) elekeza DNS na IPv6 kwa makusudi; (5) thibitisha IPv4/IPv6/DNS inayoonekana kwenye endpoint inayomilikiwa; (6) simamisha/unganisha tena tunnel na thibitisha hakuna fallback ya wazi.<sup>[[1]](#references)</sup>

**Detection:** local networks huona encrypted flow ndefu kwenda VPN infrastructure; providers wana authentication/connection records; destinations hutumia ASN/reputation pamoja na account, TLS/browser na behavior correlation.

## Self-hosted VPN or rented VPS egress

**Mechanics:** operator anadhibiti WireGuard/OpenVPN gateway au hupitisha traffic kupitia server iliyokodiwa.

**Pros:** speed ya kutabirika; address isiyobadilika inayoweza kuwekwa kwenye allowlist; logging/firewall maalum; incident control nzuri.

**Cons:** anonymity set ndogo; cloud tenant, payment, source login, API na image history humhusisha operator; server mpya yenye sifa maalum ni rahisi ku-cluster.

**Procedure:** (1) tengeneza organization project maalum kwa engagement; (2) provision image inayoungwa mkono na fixed address; (3) zuia management kwa MFA/key-based administration; (4) sanidi full-tunnel egress na DNS; (5) ruhusu destinations zilizo na scope pekee inapowezekana; (6) test leak/failure behavior; (7) hifadhi controller audit records; (8) futa credentials na resources wakati wa teardown.

**Detection:** unganisha hosting ASN, address iliyoonekana mara ya kwanza, certificate/service fingerprint na scanning behavior; cloud owners hutumia control-plane, console, billing na flow logs.

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** application huomba proxy ifungue TCP stream; SOCKS inaweza pia kuwasilisha name resolution na UDP kulingana na version; SSH hupitisha streams ndani ya encrypted session moja.

**Pros:** nyepesi; kwa kila application; haraka; inafaa kwa chaining na kufikia networks zilizogawanywa.

**Cons:** applications zinaweza kuipita; DNS inaweza ku-leak; proxy huona endpoints zilizo karibu; browser state hubaki; open proxies zinaweza kuwa traps au systems zilizo-compromise.

**Procedure:** (1) deploy proxy kwenye host inayomilikiwa; (2) hitaji authentication na zuia source/destination; (3) sanidi disposable application profile moja; (4) hakikisha remote DNS resolution pale inapohitajika; (5) thibitisha kwa owned DNS/HTTP endpoint; (6) zuia direct egress ya workload; (7) kagua na rotate proxy credentials.

**Detection:** tambua processes zinazoweza kuunda tunnels, CONNECT/SOCKS negotiation, SSH sessions ndefu na destinations zisizoendana na application; proxy logs hujenga upya streams.

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** website hufetch destination na kubadilisha links/forms zipitie origin yake, au extension huelekeza browser requests kwenye proxy. Destination huona service, huku service ikiona plaintext baada ya TLS termination na inaweza kuingiza au kuhifadhi content.

**Pros:** system-wide client haihitajiki; haraka kwa browsing rahisi; hufanya kazi VPN installation inaposhindikana.

**Cons:** proxy inaweza kusoma credentials/content, kubadilisha downloads na fingerprint users; scripts/WebSockets/downloads zinaweza kuipita; browser extension ina privileges pana; anonymity set ndogo na blocking ya mara kwa mara.

**Procedure:** (1) tumia tu proxy inayoendeshwa na organization kwa authorized testing; (2) itenge kwenye disposable browser isiyo na personal accounts; (3) kataza password entry na sensitive downloads; (4) thibitisha kila subresource kwenye owned page inapitia proxy; (5) test WebSocket, download na form behavior; (6) ondoa extension/profile baada ya matumizi.

**Detection:** destination hu-log proxy; enterprise proxy/DNS na extension inventory hutambua service; content-security/reporting au owned canary subresources hufichua direct bypass; proxy logs huunganisha user session na targets.

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** entry huona source, huku traversal relays moja au zaidi zikitenganisha source na exit inayoona destination.

**Pros:** relay ya kawaida haihitaji kuona ncha zote; failure/seizure ya node moja hufichua machache; geography inayoweza kubadilishwa.

**Cons:** shared administration/logs huvunja separation; latency; timing correlation; failure na DNS routes zaidi; account/payment ileile inaweza kuunganisha kila hop.

**Procedure:** (1) fafanua observer anayeondolewa na kila hop; (2) tumia relays zinazomilikiwa/kuidhinishwa na administrators huru pale separation inapohitajika; (3) enforce entry-only access kutoka workload; (4) hakikisha kila relay inaweza kufikia hop inayofuata pekee; (5) thibitisha logs katika kila layer; (6) simamisha kila hop na thibitisha fail-closed behavior. Reproduce kwa [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detection:** unganisha adjacent NetFlow timing/volume, repeated proxy handshakes na common controller infrastructure; usikisie geography ya operator kutoka exit.

## Split-knowledge application relay and OHTTP

**Mechanics:** client husimba stateless HTTP message kwenda gateway na kuituma kupitia relay. Relay huona client IP lakini si request; gateway huona request lakini kwa kawaida huona relay IP pekee.

**Pros:** privacy partition imara na inayoweza kukaguliwa kwa requests zinazoungwa mkono; overhead ndogo kuliko general anonymity networks.

**Cons:** si browsing ya kiholela; cookies/authentication zinaweza kuunganisha tena; relay/gateway collusion na traffic analysis hubaki; application lazima iiunge mkono.

**Procedure:** (1) chagua application inayounga mkono RFC 9458 waziwazi; (2) thibitisha gateway keys kupitia official configuration path; (3) epuka stable per-user fields; (4) tuma supported stateless request pekee; (5) linganisha relay, gateway na target logs; (6) test key rotation/failure bila direct fallback.<sup>[[2]](#references)</sup>

**Detection:** enterprise endpoints hufichua initiating process na OHTTP relay; gateways hugundua traffic iliyoharibika/iliyoreplayed; timing na stable payload/account fields zinaweza kuunganisha requests.

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT kupitia TLS/QUIC hubeba UDP au IP packets kupitia proxy. Inaweza kutekeleza tunnel ya kisasa kama VPN na kuchanganya transport na HTTP/3, lakini proxy hubaki observer.<sup>[[3]](#references)</sup>

**Pros:** multiplexing/roaming yenye ufanisi; inasaidia UDP au full IP; hu-deploy kupitia modern HTTP infrastructure.

**Cons:** si anonymity network; proxy/account huona source na destinations; QUIC/HTTP fingerprints na well-known paths huonekana kwa endpoints/providers.

**Procedure:** (1) tumia client/service inayodocument RFC 9298/9484 support; (2) authenticate proxy certificate/configuration; (3) fafanua allowed target routes; (4) enable encrypted DNS ndani ya path; (5) verify UDP, TCP, IPv6 na failover dhidi ya owned endpoints; (6) inspect proxy request na flow logs.

**Detection:** endpoints huona client process na virtual interface; networks zinaweza kuainisha sustained QUIC/TLS kwenda proxy; proxy logs hufichua CONNECT target/path na assigned routes.

## Tor Browser

**Mechanics:** Tor huchagua guard, middle na exit relays; layered encryption hupunguza kile kila relay inaweza kuona. Tor Browser huongeza browser iliyosanifiwa ili kupinga fingerprinting.

**Pros:** public anonymity set kubwa; relay moja ya kawaida haijui ncha zote; destination unlinkability bila kuendesha servers.

**Cons:** polepole; inalenga TCP; exit reputation/blocks; logins na disclosures humtambua user; low-latency timing correlation hubaki.

**Procedure:** (1) download na verify Tor Browser kutoka project; (2) acha defaults na epuka extensions; (3) chagua security level inayofaa; (4) tengeneza identity/session tofauti; (5) epuka identifying accounts na external active documents; (6) tumia HTTPS au authenticated onion services; (7) thibitisha exit kupitia owned endpoint pekee.<sup>[[4]](#references)</sup>

**Detection:** local networks zinaweza kutambua known guard traffic isipokuwa bridge/transport itumike; destinations huona exits na Tor Browser behavior; end-to-end observers huunganisha timing/volume.

## Tor bridges and pluggable transports

**Mechanics:** bridge isiyo ya public huchukua nafasi ya public guard; obfs4, Snowflake au WebTunnel hubadilisha first-hop transport ili kupinga blocking/probing rahisi.

**Pros:** huzunguka censorship na kuficha destinations za public relays zilizo wazi; huhifadhi Tor circuit baada ya entry.

**Cons:** transport patterns/bridge discovery bado vinawezekana; performance hubadilika; hailindi dhidi ya accounts au global timing.

**Procedure:** (1) jaribu direct Tor kwanza; (2) katika Tor Browser Connection settings chagua supported transport iliyojengwa ndani au omba official bridge; (3) usitumie binaries/lists zisizoaminika; (4) connect na fanya benign test; (5) test reconnect na clock; (6) weka browser settings nyingine zote kuwa standard.<sup>[[5]](#references)</sup>

**Detection:** censors hutumia destination discovery, protocol/flow classification na active probing; defenders wanapaswa kutenganisha matumizi ya circumvention na compromise na kutegemea endpoint process/context.

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Tor huficha matumizi ya Tor moja kwa moja kutoka access ISP lakini huonyesha source kwa VPN. Tor-before-VPN huipa VPN traffic ya baada ya Tor na mara nyingi stable customer/tunnel identity.

**Pros:** huondoa observer maalum inapoundwa vizuri; inaweza kufikia networks zinazozuia layer moja.

**Cons:** complexity, fingerprint isiyo ya kawaida, leaks, anonymity set iliyopunguzwa na false confidence; Tor Project huchukulia combinations hizi kuwa advanced.<sup>[[6]](#references)</sup>

**Procedure:** (1) andika observer anayeondolewa na observer mpya anayeletwa; (2) tumia disposable environment; (3) anzisha outer path iliyokusudiwa pekee; (4) enforce firewall routes; (5) verify DNS/IPv4/IPv6 na kila failure order; (6) linganisha visibility ya providers wote; (7) acha stack ikiwa haina faida inayopimika.

**Detection:** local/VPN/Tor observers huona layers zilizo karibu tofauti; timing hubaki end-to-end; nested tunnel fingerprints zisizo za kawaida na provider accounts zinaweza kuunganisha sessions.

## Onion service

**Mechanics:** client na service huunda Tor circuits kwenda rendezvous, zikificha service IP na kuepuka exit.

**Pros:** ulinzi wa source na service location; end-to-end onion authentication; hakuna public inbound port; client authorization ya hiari.

**Cons:** origin inaweza kuvuja kupitia updates/analytics/errors; onion key ni muhimu; application identity/timing na host compromise hubaki.

**Procedure:** (1) tenga application na uifunge kwenye loopback/socket pekee; (2) install supported Tor; (3) configure v3 onion service kwa official instructions; (4) linda/back up key yake ikiwa stable identity inahitajika; (5) ongeza client authorization kwa matumizi yaliyofungwa; (6) ondoa third-party fetches; (7) thibitisha externally kuwa origin haifikiwi.<sup>[[7]](#references)</sup>

**Detection:** host/network defenders hupata Tor process/configuration na outbound circuits; application errors, DNS, certificates au third-party resources zinaweza kufichua origin.

## I2P internal services

**Mechanics:** I2P hutumia inbound/outbound tunnels tofauti zisizo za mwelekeo mmoja kwa destinations ndani ya overlay; outproxies za public Internet huongeza trust point.

**Pros:** publishing ya ndani iliyogatuliwa; hakuna official exit dependency; inbound/outbound paths tofauti.

**Cons:** si replacement ya general web; ecosystem ndogo; peer behavior ya muda mrefu; outproxy inaweza kuona public browsing.

**Procedure:** (1) install kutoka official source; (2) tumia dedicated context; (3) ruhusu integration/bandwidth stabilization; (4) fikia owned I2P-native service; (5) epuka outproxies isipokuwa zinahitajika wazi; (6) thibitisha shutdown haitoi direct fallback; (7) inspect local peer na service logs.<sup>[[8]](#references)</sup>

**Detection:** local networks huona peer traffic ya muda mrefu na bootstrap behavior; endpoints hufichua router/application processes; outproxies hu-log exits.

## Mixnets

**Mechanics:** fixed-size packets, batching, delay, reordering na cover traffic hupunguza timing correlation; gateways huunganisha applications.

**Pros:** upinzani bora dhidi ya timing analysis kuliko low-latency proxies; inafaa kwa asynchronous messages/transactions.

**Cons:** latency, bandwidth overhead, deployment ndogo na application limits; gateway/account metadata inaweza kudumu.

**Procedure:** (1) chagua client iliyotunzwa na supported application; (2) soma threat model halisi; (3) install kwenye compartment tofauti; (4) tuma benign data kwenye owned endpoint; (5) pima latency/reliability na reply path; (6) test gateway failure; (7) usiwahi kuzima delays/cover traffic kwa ajili ya speed.<sup>[[9]](#references)</sup>

**Detection:** endpoints hutambua client; access networks zinaweza kuainisha gateways/packet cadence; gateways na exits huona roles zilizo karibu, huku correlation pana ikihitaji statistical windows ndefu.

## GNUnet anonymous file sharing

**Mechanics:** GNUnet inaweza kupitisha publish/search/download requests kupitia peers na kuongeza cover traffic kulingana na anonymity level. Documentation yake inaonya kuwa default level 1 haihitaji cover traffic na powerful traffic analysis inaweza kutambua origin.<sup>[[10]](#references)</sup>

**Pros:** sharing iliyogatuliwa na ya application-native bila kutambulika; cover-traffic requirement inayoweza kurekebishwa.

**Cons:** si anonymous web access ya kawaida; gharama ya performance/storage; limitations za peers na traffic analysis; GNUnet VPN documentation inasema IP overlay yake haitoi anonymity nzuri.

**Procedure:** (1) install maintained official build; (2) isolate test peer; (3) punguza bandwidth/storage; (4) publish harmless unique test file kwa anonymity level iliyochaguliwa; (5) retrieve kutoka owned peer nyingine; (6) rekodi cover-traffic na latency; (7) usidai IP VPN component inatoa anonymity sawa.

**Detection:** peer bootstrap, overlay traffic, local datastore/process na file identifiers; broad observer anaweza kuchambua traffic volume ikilinganishwa na cover traffic.

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQ husimba kwenda resolver; ODoH hugawanya client address na query kati ya proxy na resolver; ECH husimba inner TLS ClientHello/server name.

**Pros:** huondoa plaintext DNS/SNI kutoka kwa baadhi ya local observers; ODoH hugawanya maarifa ya source/query.

**Cons:** si IP-anonymity path; resolver/proxy/server huhifadhi roles; destination IP/timing/volume na endpoint hubaki; fallback inaweza ku-leak.

**Procedure:** (1) chagua kama OS, application au tunnel itamiliki DNS; (2) enable strict encrypted mode au supported ODoH; (3) test unique owned domain; (4) capture locally kuthibitisha hakuna clear query; (5) fail resolver na verify intended behavior; (6) kwa ECH, thibitisha server diagnostics zinaonyesha inner ClientHello acceptance.<sup>[[11]](#references)</sup>

**Detection:** endpoint/resolver logs hufichua queries; networks hutambua encrypted-resolver endpoints na destination flows; ECH state huonekana kwenye endpoints/CDN hata ikiwa imefichwa kwenye path.

## Split-provider privacy relay

**Mechanics:** bidhaa kama iCloud Private Relay hutumia ingress inayojua client na egress inayoendeshwa kwa kujitegemea inayojua destination, ikiwa na coarse region handling.

**Pros:** split knowledge yenye friction ndogo; haraka; integrated DNS/web protection kwa traffic inayoungwa mkono.

**Cons:** product/application scope ni ndogo; account/platform provider bado humtambua customer; si system anonymity ya kiholela; collusion/legal na timing risks.

**Procedure:** (1) thibitisha applications na traffic types zinazoungwa mkono; (2) enable feature chini ya dedicated platform context inapofaa; (3) chagua region behavior; (4) test Safari/DNS na unsupported applications kando; (5) inspect destination address; (6) test network switching/failure.<sup>[[12]](#references)</sup>

**Detection:** access huona ingress; destination huona egress; platform/relay logs na account records huenea kwenye layer zao; unsupported applications hufichua normal paths.

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** browsing/tool execution hufanyika kwenye remote system; destination huona egress yake huku workspace provider akiona operator connection na control plane.

**Pros:** haraka; hutenga risky content; controlled egress thabiti; disposable state na organizational audit imara.

**Cons:** provider/admin anaweza kuona session/account; screen/clipboard/file channels huvuja; remote browser fingerprint inaweza kuwa ya kipekee; si anonymous kwa workspace owner.

**Procedure:** (1) tengeneza workspace moja inayomilikiwa na organization kwa kila engagement; (2) hitaji MFA na zuia administration; (3) disable au constrain clipboard/upload/download; (4) route kupitia approved fixed egress; (5) usitumie personal IdP/sync; (6) export reviewed evidence pekee; (7) destroy workspace na credentials kwa ratiba.

**Detection:** provider na IdP logs huunganisha user na session; destinations hu-cluster workspace egress/browser; enterprise defenders hutambua remote-control protocols na anomalous cloud sessions.

## Public or guest Wi-Fi

**Mechanics:** traffic hutoka kupitia venue NAT au tunnel iliyoanzishwa hapo.

**Pros:** speed kubwa na shared non-home address; infrastructure maalum haihitajiki.

**Cons:** venue association/DHCP/portal, camera, purchase na location evidence; hostile peers/APs; terms; physical risk.

**Procedure:** (1) pata access inayotolewa kwa guests na thibitisha SSID na staff; (2) tumia patched low-trust device; (3) disable sharing/auto-join na enable private MAC; (4) maliza portal bila reused identity; (5) anzisha fail-closed VPN/Tor path; (6) thibitisha tethered traffic; (7) forget network.

**Detection:** venue huunganisha AP, MAC, DHCP, portal na time; destination huona venue/tunnel; investigators huunganisha physical na device evidence. Never bypass access control.

## Travel router

**Mechanics:** router inayomilikiwa na operator hujiunga na venue Wi-Fi/Ethernet na kutoa internal network iliyotengwa yenye tunnel policy inayotekelezwa.

**Pros:** hutenga workstations; central kill switch/DNS; client network thabiti; hulinda privileged endpoints dhidi ya local broadcasts.

**Cons:** router huwa stable radio/DHCP fingerprint; huongeza attack surface; captive portals na tethering zinaweza kupita tunnel.

**Procedure:** (1) update supported firmware; (2) weka unique management credentials na disable WAN admin/WPS/UPnP; (3) configure private upstream MAC inapokubalika; (4) tengeneza separate internal SSID; (5) enforce full-tunnel DNS/IPv6 firewall policy; (6) test portal, reconnect na tunnel failure.

**Detection:** venue huona router association na traffic shape; local RF/DHCP fingerprinting huitambua; VPN provider huona venue source.

## Cellular, prepaid SIM and eSIM

**Mechanics:** modem hutumia carrier radio access na kwa kawaida carrier NAT; VPN/Tor layer inaweza kubadilisha exit inayoonekana kwa destination.

**Pros:** huru kutoka local wired/Wi-Fi network; mobile; speed kubwa; backhaul muhimu kwa authorized drops.

**Cons:** carrier anajua subscriber/eSIM, IMSI, IMEI, cells, time na assigned ports; registration laws hutofautiana; co-location na personal phone huunganisha devices.

**Procedure:** (1) pata service kihalali kwa details sahihi zinazohitajika; (2) tumia modem/device tofauti inayomilikiwa na organization; (3) irekodi kwa exercise controller; (4) disable unrelated radios/accounts; (5) establish approved tunnel; (6) test kama tethered clients wanaifuata kweli; (7) thibitisha assumptions za provider na retention kabla ya safari.<sup>[[13]](#references)</sup>

**Detection:** carrier records na RF location; enterprise USB/PCI/MDM inventory na rogue-hotspot surveys; destination/tunnel timing.

## Satellite Internet and satellite downlink abuse

**Mechanics:** service ya kawaida hutumia terminal/provider iliyosajiliwa. Zamani, one-way DVB-S abuse iliruhusu receiver ndani ya beam kuona unencrypted downlink traffic iliyolengwa kwa subscriber halali huku ikitumia njia nyingine kwa outbound requests.

**Pros:** footprint pana; last mile huru; historical one-way abuse ingeweza kuhusisha C2 na subscriber geography kimakosa.

**Cons:** equipment/RF/provider records; latency na coverage; modern bidirectional systems hutofautiana; outbound path na asymmetric routing hubaki ushahidi.

**Procedure:** kwa lawful access, sajili owned terminal na tunnel traffic inavyohitajika. Ku-emulate historical Turla behavior, replay synthetic one-way packet captures ndani ya RF-free lab na test kama analysts hugundua reply kwa host ambayo haikufanya request; usi-intercept live satellite traffic.<sup>[[14]](#references)</sup>

**Detection:** provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency na malware configuration.

## Residential/mobile proxy or consented proxyware

**Mechanics:** backconnect gateway hutoa consumer broadband/mobile exits, ziwe sticky au zinazozunguka. Supply inaweza kuwa ya ridhaa, iliyofungwa kwa udanganyifu au malicious.

**Pros:** speed kubwa; geographic choice; consumer ASN huepuka baadhi ya hosting blocks; pools kubwa.

**Cons:** provenance/consent na legal risk; broker humwona customer; infected exits huumiza victims; rotation huunda anomalies; gharama na reliability duni.

**Procedure:** tumia tu documented, informed-consent organization-owned agents kwa emulation: (1) enroll test endpoints; (2) inventory owners/IPs; (3) configure gateway; (4) rotate sticky/per-request modes; (5) tuma kwa owned target pekee; (6) linganisha gateway/exit/target logs; (7) ondoa kila agent.

**Detection:** impossible travel, stable browser/account kwenye rapid IP/ASN changes, backconnect protocols, proxyware process/network artifacts na broker/controller relations.

## ORB, botnet and compromised edge-device relays

**Mechanics:** leased au compromised routers/IoT/servers huunda access, traversal na exit roles zinazosimamiwa kama fleet. APT customers wengi wanaweza kuishiriki.

**Pros:** reputation/geography iliyokopwa; exits za muda mfupi; resilient multi-hop mesh; direct actor-to-IP link dhaifu.

**Cons:** criminal victimization; implant/controller na fleet patterns; intermediary seizure; performance isiyotabirika; operator/customer service records.

**Procedure:** usiwahi ku-compromise devices halisi. Tumia [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) tengeneza isolated entry/transit/target networks; (2) ambatanisha owned dual-homed relay containers; (3) forward test port moja pekee; (4) tuma benign request; (5) thibitisha target huona exit pekee; (6) rotate exit; (7) tear down assets zote zilizotajwa.<sup>[[15]](#references)</sup>

**Detection:** fuatilia topology, ports/services, controller relations, implant fingerprints na node lifecycle; centralize edge configuration/flow/integrity telemetry; usilinganishe exit IP na actor.

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** public edge hupitisha traffic inayolingana na grammar pekee; fronting huweka benign outer SNI na inner HTTP authority tofauti, au blank SNI, intermediary inapoiruhusu.

**Pros:** huficha/linda back-end; global edge yenye speed; huchanganya destination na shared service; cutover ya haraka.

**Cons:** CDN huona routing na tenant zote; providers wengi hukataza cross-tenant fronting; SNI/Host/process/flow na account artifacts; configuration reuse hu-cluster campaigns.

**Procedure:** reproduce kwenye owned reverse proxy pekee kwa [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): tengeneza local certificate/edge, route Host moja isiyolingana kwenda owned target, log SNI na Host, tuma normal/mismatched requests, kisha ondoa containers.<sup>[[16]](#references)</sup>

**Detection:** linganisha SNI/ECH/Host/`:authority` kwenye endpoint au terminating edge; unganisha initiating process, tenant/origin, request grammar na flow cadence.

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNS husasisha stable name; DGA hutengeneza changing candidate names; fast flux huzungusha service addresses kwa low TTL; double flux pia huzungusha name servers.

**Pros:** discovery yenye resilience; infrastructure replacement ya haraka; huficha controller nyuma ya nodes nyingi.

**Cons:** DNS huunda centralized telemetry; entropy/NXDOMAIN/churn; low TTL na broad ASN patterns; registration na authoritative infrastructure hubaki.

**Procedure:** tumia [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): serve owned zone inayorudisha RFC 5737 addresses zenye TTL ya sekunde tano, i-query mara kwa mara, badilisha synthetic epoch, na validate analytics. Usiwahi kuelekeza test records kwa third parties.<sup>[[17]](#references)</sup>

**Detection:** unique answers/ASNs za sliding window, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters na process follow-on; tenga legitimate CDNs kwa context.

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** public post, repository, document, object au feed huwa na encoded current endpoint au task. Client inaweza kurudisha results kupitia channel nyingine.

**Pros:** allowed high-reputation service; TLS; endpoint rotation bila kubadilisha binary; asymmetric tasking huzuia simple flow correlation.

**Cons:** stable object/account/API identifiers; provider records; endpoint decode/follow-on sequence; content inaweza kushikwa au kubadilishwa.

**Procedure:** tumia [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): host encoded pointer kwenye owned container moja, fetch/decode kutoka short-lived client, contact owned service ya pili, hifadhi logs zote mbili, kisha tear down.

**Detection:** unganisha unusual process → stable object read → decode → new destination; hash/preserve content na hifadhi full object paths, si domain pekee.

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** functions/short-lived jobs huendesha nyuma ya provider NAT au front; logical service hubaki stable huku instances na addresses zikizunguka.

**Pros:** deployment/destruction ya haraka; shared egress ya kiwango cha provider; local disk kidogo; elastic regional routing.

**Cons:** tenant, role, API, image, secret, invocation, billing na front-to-origin logs hudumu; cold-start na platform fingerprints; provider policy.

**Procedure:** (1) tumia organization-owned exercise tenant; (2) deploy benign function inayotuma requests kwa owned endpoint pekee; (3) rekodi project/role/image/config; (4) invoke kwenye instances kadhaa; (5) linganisha target IPs na audit/request IDs; (6) test log retention; (7) remove function, roles na secrets.

**Detection:** cloud audit/invocation logs, unusual role creation, shared egress pamoja na stable request grammar, image/layer na secret reuse, na front-origin correlation.

## Authorized on-site drop

**Mechanics:** small computer iliyoorodheshwa hutumia local wired/Wi-Fi na outbound VPN/cellular rendezvous, ikionyesha local source.

**Pros:** realistic internal-origin testing; speed kubwa; inaweza kupima NAC, physical inventory na egress controls.

**Cons:** physical discovery/theft; serial/MAC/USB/DHCP/PoE/RF na camera evidence; kupotea kunaweza kufichua credentials.

**Procedure:** fuata [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) pata written placement authority kamili; (2) rekodi serial, MAC, photo, location na retrieval time; (3) tumia signed minimal image na short-lived mutual credentials; (4) zuia outbound-only destinations/capabilities; (5) ongeza server-side quarantine na bandwidth limits; (6) test SOC visibility na loss response; (7) retrieve, preserve required evidence, kisha sanitize kulingana na lifecycle policy iliyokubaliwa. Usifiche moja kwenye venue isiyokubali.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera na physical inspection.

## Nearest-neighbor wireless pivot

**Mechanics:** actor hudhibiti host iliyo kwenye radio range ya target, kisha hutumia target Wi-Fi credentials kuvuka boundary remotely. APT28 ilitumia compromised organizations za karibu kwa njia hii.<sup>[[18]](#references)</sup>

**Pros:** operator hahitaji kusafiri; target huona local radio source; hupita controls zinazotumika kwenye Internet entry pekee.

**Cons:** inahitaji nearby compromised/owned dual-radio host na valid access; RADIUS/NAC/AP na neighbor endpoint evidence; signal/device anomalies.

**Procedure:** reproduce kwa owned systems pekee kwa [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): join owned pivot kwenye neighbor na target lab SSIDs, forward service moja pekee, collect AP/pivot logs zote mbili, kisha enable EAP-TLS/device posture na thibitisha attempt ya pili inashindikana.

**Detection:** unganisha RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login na physical presence; hunt nearby endpoints kwa simultaneous radios, forwarding na tunnels.

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** traffic hupitia local peers, asynchronous gateways, removable media au scheduled queues badala ya interactive Internet session moja.

**Pros:** hufanya kazi wakati wa disruption/censorship; delivery iliyocheleweshwa/batched hudhoofisha simple timing; hakuna central last mile kwa local communication.

**Cons:** latency kubwa; anonymity set ndogo; custody/physical metadata; malicious peers; data hatimaye hufika gateway inayoiona.

**Procedure:** (1) jenga isolated owned three-node mesh au file queue; (2) encrypt/authenticate content end to end; (3) ondoa direct Internet routes kutoka origin; (4) relay benign file baada ya controlled delay; (5) thibitisha gateway pekee huwasiliana na owned destination; (6) linganisha custody/timestamps; (7) hifadhi evidence inayohitajika, kisha sanitize temporary media/queues wakati wa approved closeout.

**Detection:** endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity na content identifiers. Windows ndefu za correlation huchukua nafasi ya interactive-flow analysis.

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN) hugawa public relay address na hubeba UDP, TCP au TLS traffic kati ya client na peers. ICE policy inaweza kulazimisha relay badala ya kuonyesha direct candidate. TURN hutatua reachability, si general anonymity: server hum-authenticate client na huona allocations, peers, time na volume.<sup>[[19]](#references)</sup>

**Pros:** inatekelezwa kwa upana; hushughulikia restrictive NAT; inasaidia mobile WebRTC; peer haipokei direct transport address ya client wakati relay-only policy imelazimishwa vizuri.

**Cons:** TURN operator huona pande zote zilizo karibu; application identity, media fingerprint na signaling hubaki; relay-only hutumia bandwidth na latency; misconfiguration bado inaweza kukusanya host au server-reflexive candidates.

**Procedure:** (1) deploy organization-owned TURN service yenye TLS na short-lived credentials; (2) zuia realms, peers, ports, quotas na expiration; (3) weka test application kutumia relay-only ICE; (4) call owned peer; (5) inspect `getStats()` na packet capture kuthibitisha relay candidates pekee ndizo zilibeba media; (6) fail relay na thibitisha hakuna direct fallback; (7) hifadhi allocation logs kwa engagement.

**Detection:** signaling, browser process na TURN allocations huunganisha session na relay; networks huona sustained flows kwenda TURN ports au TLS endpoints; peer huona allocated relay. **Captured node:** application state na ephemeral TURN credentials zinaweza kufichua realm na rendezvous service. Punguza exposure kwa per-device, short-lived credentials na weka operator authentication kwenye controller pekee.

## Outbound-only rendezvous or reverse overlay

**Mechanics:** node iliyo nyuma ya NAT huanzisha authenticated connection kwenda broker inayodhibitiwa na organization. Operator hujithibitisha kwa broker kando, ambayo huidhinisha narrow management channel; inbound port forwarding wala direct operator-to-node route haihitajiki.

**Pros:** thabiti nyuma ya NAT na captive last miles; central revocation na audit; kubadilika kwa field-node address hakuhitaji operator discovery; hutenganisha operator identity na node credential.

**Cons:** broker huwa high-value correlation point; periodic keepalives hutambulika; broad tunnel inaweza kuwa unsafe pivot; broker ikipotea management huisha.

**Procedure:** fuata [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): toa device identity moja yenye scope, ruhusu owned broker na approved management service pekee, tumia authenticated keepalive, enforce fail-closed routing, test address changes na reboot recovery, na revoke identity wakati wa loss drill. WireGuard hudocument 25-second persistent keepalive kama NAT interval inayotumika kwa upana inapohitajika kweli.<sup>[[20]](#references)</sup>

**Detection:** broker na identity-provider logs huunganisha pande zote; access network huona repeated encrypted destination/cadence; endpoint inventory huonyesha overlay agent. **Captured node:** chukulia device key, broker name, tunnel addresses na cached task data kuwa vimefichuka. Haipaswi kuwa na operator private key, personal account au reusable controller token.

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** field workload hu-poll authenticated mailbox kwa signed, pre-approved jobs na hu-post bounded results. Operator huandika queue kupitia control plane tofauti; hakuna interactive socket kati yao.

**Pros:** huvumilia intermittent links; hutenganisha timing na addressing; quotas na schemas zinaweza kupunguza capability; centralized audit na revocation ni rahisi.

**Cons:** polling cadence na stable object/queue names hu-fingerprint system; provider logs huunganisha producer na consumer; control iliyochelewa; queued data iliyonaswa inaweza kufichua zoezi.

**Procedure:** (1) tengeneza engagement queue moja na device identity moja; (2) fafanua signed schema ya benign, explicitly scoped jobs; (3) weka message TTL, maximum result size na rate; (4) ruhusu node ipull queue yake pekee na iandike result prefix yake pekee; (5) test offline accumulation, duplicate delivery na revocation; (6) centralize immutable access logs; (7) delete queue baada ya retention requirements kutimizwa.

**Detection:** tafuta periodic API calls za unusual process, stable bucket/object/queue paths, user-agent au TLS behavior inayofanana, na fetch-then-new-connection sequence. **Captured node:** local cache inaweza kufichua pending jobs na object names; weka cache ikiwa encrypted, bounded na disposable, huku ukihifadhi authoritative controller logs.

## Dual-uplink failover and connection migration

**Mechanics:** approved field node ina uplinks mbili huru—kama venue Ethernet/Wi-Fi na organization cellular—na huweka control session kupitia overlay au message broker routes zinapobadilika. Hii ni availability engineering, si anonymity.

**Pros:** hustahimili failure ya provider, AP au captive portal moja; husaidia planned maintenance; huruhusu kutenga path yenye shaka haraka.

**Cons:** providers wawili huunda location/account records mbili; matumizi ya pamoja hurahisisha correlation; route na DNS leaks wakati wa failover; cellular co-location evidence hubaki.

**Procedure:** (1) register interfaces na providers wote wanaomilikiwa na organization; (2) assign deterministic route priorities na health checks kwa owned endpoints; (3) bind DNS na management kwenye overlay; (4) zuia secondary path isipokee inbound traffic; (5) unplug kila path na verify session recovery, source policy na hakuna direct destination access; (6) alert on unplanned path change; (7) document data use na roaming limits.

**Detection:** unganisha device certificate ileile, request grammar na timing across ASNs; local inventory huona radios zote mbili; carriers/venues huhifadhi records zao. **Captured node:** SIM/device identifiers zote mbili na known SSIDs zinaweza kuonekana; tumia organization assets na usiwahi kuisogeza au kui-pair na personal devices.

## Organization private APN or managed cellular tunnel

**Mechanics:** carrier private APN huweka enrolled SIMs kwenye private routed domain au hutunnel traffic kwenda enterprise gateway. Hutenganisha device na public mobile Internet lakini haifichi kwa carrier au contracting organization.

**Pros:** private addressing thabiti; carrier-level enrollment na traffic policy; huepuka public inbound exposure; inafaa kwa authorized remote appliances.

**Cons:** subscriber, IMSI/IMEI, cell na billing attribution ni imara; procurement lead time na gharama; carrier/gateway outage; si anonymous kwa operator.

**Procedure:** (1) contract APN kwa jina la assessment organization; (2) whitelist registered SIMs na gateway prefixes pekee; (3) ongeza application-layer mutual authentication; (4) restrict APN route kwa rendezvous na update services; (5) test SIM removal, roaming, public-Internet breakout na revocation; (6) monitor carrier na gateway records; (7) cancel au quarantine kila SIM wakati wa closeout.

**Detection:** carrier inventory na cell telemetry, APN gateway flows, SIM/IMEI mismatch na enterprise asset records. **Captured node:** SIM na modem hutambua contract hata storage ikiwa encrypted; capture resilience hapa inamaanisha suspension ya haraka na authorization finyu, si deniability.

## Long-range point-to-point wireless bridge

**Mechanics:** directional Wi-Fi au licensed/unlicensed point-to-point radio huunganisha sites mbili zilizoidhinishwa na owners, ikiwa na Internet egress kwenye remote site. Inaweza kuhamisha apparent IP location bila commercial proxy.

**Pros:** throughput kubwa; huru kutoka intermediate wired carriers; RF na routing zinazodhibitika; inafaa kupima segmentation na remote-site monitoring.

**Cons:** line-of-sight, spectrum, landlord na regulatory constraints; RF emissions na hardware za kipekee; endpoints zote mbili ni physical evidence; weather/power/alignment huathiri stability.

**Procedure:** (1) pata written permission ya sites zote mbili na thibitisha spectrum/power rules; (2) survey path bila transmitting nje ya parameters zilizoidhinishwa; (3) tumia authenticated encryption na management VLAN; (4) restrict bridge kwa owned rendezvous au test subnet; (5) test failover, alignment, power recovery na RF containment; (6) label/inventory radios zote mbili; (7) remove na verify configuration reset baada ya zoezi.

**Detection:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic na remote-site egress logs. **Captured node:** configuration hufichua peer na management domain; tumia unique exercise credentials, bila personal management accounts, na revocation ya haraka ya peer-key.

## Consented cooperative or community exit

**Mechanics:** volunteers au partner organizations huendesha relays kwa ujuzi na consent chini ya published policy. Traffic hutoka shared community pool huku coordination layer ikifuatilia abuse na revocation.

**Pros:** diverse non-cloud networks; explicit consent ni salama kuliko proxyware; shared governance inaweza kugawanya trust; inafaa kwa research na censorship-resilience studies.

**Cons:** pools ndogo na membership records hupunguza anonymity; exit operators hupokea complaints na huona traffic metadata; malicious participants, uptime inayobadilika na jurisdiction tofauti.

**Procedure:** (1) publish acceptable-use na logging policy; (2) pata informed opt-in kutoka kwa kila operator; (3) toa unique relay identity na restrict destinations/rates; (4) toa abuse handling na one-action revocation; (5) tuma authorized traffic kwa owned endpoints pekee wakati wa testing; (6) pima churn na correlation exposure; (7) ondoa relay kwa usafi consent inapoisha.

**Detection:** membership/control-plane records, relay certificates, common software fingerprint na exit behavior hutambua pool. **Captured node:** relay configuration inaweza kutambua cooperative lakini haipaswi kuwa na client identities; hifadhi client-to-session accountability kwenye authorized controller chini ya access control.

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extensions huunda temporary interface identifiers ili stable address isitumiwe tena kwa kila outbound connection. Provider prefix changes zinaweza kuongeza rotation, lakini delegated prefix, subscriber record na upper-layer fingerprint hubaki.<sup>[[21]](#references)</sup>

**Pros:** hupunguza passive long-term tracking kwa stable interface identifier; imejengwa kwenye common operating systems; hakuna relay overhead.

**Cons:** si source anonymity; ISP na local network bado zinajua prefix/device; DNS, accounts na browser state huunganisha sessions; address churn huchanganya allowlists na logging.

**Procedure:** (1) inspect stable na temporary addresses za current owned client; (2) enable OS-supported privacy-address default badala ya third-party spoofing; (3) request owned IPv6 endpoint mara kwa mara katika address lifetimes; (4) confirm inbound services zina-bind intended stable addresses pekee; (5) retain DHCPv6/RA/neighbor na precise endpoint logs; (6) test VPN/firewall behavior kwa kila IPv6 address.

**Detection:** unganisha delegated prefix, layer-2 identity, neighbor discovery, account na endpoint telemetry badala ya kuchukulia address moja kama device moja. **Captured node:** network profiles na interface identifiers hubaki; temporary addressing huzuia passive identifier moja, si forensic attribution.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** pluggable transport hubadilisha jinsi first Tor connection inavyoonekana au jinsi inavyofika bridge. Snowflake hutumia short-lived volunteer WebRTC proxies, WebTunnel hufanana na ordinary HTTPS, obfs4 hupinga simple protocol identification na active probing, na meek hupitisha kupitia supported web infrastructure. Hizi ni censorship-circumvention transports zinazoingia Tor, si additional end-to-end anonymity layers.<sup>[[22]](#references)</sup>

**Pros:** muhimu direct Tor au known relays zinapozuiwa; Snowflake huepuka stable public bridge address; imeunganishwa kwenye maintained Tor clients; destination bado hupokea Tor properties za kawaida.

**Cons:** performance ya chini au inayobadilika; broker/front/bridge na local network huona metadata tofauti; transport fingerprints na blocking bado vinawezekana; volunteer proxy haibadilishi Tor na haipaswi kuaminiwa na application plaintext.

**Procedure:** (1) install na verify official Tor Browser au supported Tor client; (2) select built-in transport kwenye Connection/Bridges; (3) connect kwenye owned diagnostic page pekee; (4) thibitisha page huona Tor exit, si Snowflake/WebTunnel peer; (5) linganisha bootstrap na performance; (6) fail transport na verify client hai-connect direct kimya kimya; (7) rudi kwenye standard supported configuration baada ya test.

**Detection:** censor anaweza kuchanganya destination allowlists, TLS/WebRTC behavior, broker discovery na flow analysis; endpoints hufichua Tor na transport configuration. **Capture-resilient OPSEC:** tumia standard client, usiwahi kunakili personal browser state ndani yake, na chukulia bridge/broker history inaweza kupatikana. **Monitoring:** fuatilia Tor bootstrap logs, unexpected direct DNS/connection attempts na owned-page observations za controller; transport failure si uthibitisho wa discovery.

## Refraction networking or decoy routing

**Mechanics:** cooperating network operator hugundua covert signal kwenye traffic inayoonekana kuelekezwa kwa allowed decoy na ku-divert flow kwenda circumvention proxy. Deployment inahitaji infrastructure kwenye network path; client haiwezi kuunda hii kwa kuchagua innocent website tu.<sup>[[23]](#references)</sup>

**Pros:** apparent destination inaweza kuwa ngumu kwa censor kuzuia bila collateral damage; hakuna public bridge address ya kusambaza; useful research model kwa on-path-assisted circumvention.

**Cons:** specialized ISP/transit participation; deployability na performance hutegemea routing; client-to-decoy flow na proxy-side activity hubaki; global au cooperating observer anaweza kuunganisha timing.

**Procedure:** usisignal kupitia networks zisizohusika. Reproduce architecture kwenye isolated lab: (1) tengeneza owned client, router, decoy na proxy namespaces; (2) tumia benign tagged test request; (3) acha owned router i-redirect tag hiyo pekee kwenda proxy; (4) log pre/post-routing tuples na request IDs; (5) linganisha ordinary na signaled flows; (6) test false positives na removal; (7) destroy lab routes.

**Detection:** authorized network operators wanaweza kukagua routing divergence, unusual client hello/tag behavior na tofauti za decoy-versus-back-end flow. **Capture-resilient OPSEC:** research client inapaswa kuwa na test keys na documentation addresses pekee. **Monitoring:** linganisha signed lab-router decisions na proxy arrivals; usiprobe production transit providers ili kujua kama waligundua signaling.

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gateway huretrieve IPFS content identifier (CID), pengine kutoka cache au peers, na kumrudishia client content inayoweza kuthibitishwa. Original publisher anaweza kuona gateway au peers wengine badala ya final reader; gateway huona reader IP na requested CID. Native peer-to-peer retrieval humweka client wazi kwa peers na DHT/routing participants.<sup>[[24]](#references)</sup>

**Pros:** publisher na reader wanaweza kutenganishwa na caches; immutable content inaweza kuthibitishwa kwa hash; replicated data hudumu host moja inapopotea; HTTP clients hazihitaji native peer stack.

**Cons:** public CIDs na gateway logs hufichua interests; timing ya first retrieval inaweza kuunganisha publisher na reader; malicious web content na path-style same-origin hazards; public gateways ni best-effort na hukataza abuse.

**Procedure:** (1) publish harmless test file kwenye owned private IPFS swarm au owned gateway; (2) rekodi CID yake; (3) retrieve kupitia separate owned HTTP gateway yenye subdomain isolation; (4) verify bytes dhidi ya CID; (5) repeat baada ya caching; (6) linganisha publisher, peer na gateway logs; (7) unpin na remove test content retention inapoisha.

**Detection:** gateways hu-log source/CID; DHT na peer connections hufichua retrieval; endpoint history na file hashes hutambua content. **Capture-resilient OPSEC:** usihifadhi private publishing key kwenye read-only field client na encrypt sensitive content kabla ya content addressing. **Monitoring:** alert on unexpected pinning, peer-set change, CID requests nje ya allowlist au gateway account notices.

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR) humruhusu client kuretrieve record moja kutoka database huku ikificha kwa cryptography index iliyochaguliwa kutoka kwa server chini ya stated single- au multi-server threat model. Hulinda query selection kwa bounded dataset; si general web access au IP anonymity.<sup>[[25]](#references)</sup>

**Pros:** query privacy imara ya application-specific; leakage model inayopimika; inafaa kwa key directories, blocklists au small public databases; inaweza kupunguza hitaji la kufichua search terms halisi.

**Cons:** computation/bandwidth overhead; server hujua connection time/IP isipokuwa relay iongezwe; dataset version, response size na application state zinaweza kugawanya users; implementation maturity hutofautiana.

**Procedure:** (1) deploy audited PIR implementation dhidi ya synthetic owned database; (2) publish dataset version na parameters; (3) retrieve indices kadhaa kwa identical request sizes; (4) verify correctness locally; (5) linganisha server logs na thibitisha index haipo; (6) test malicious/truncated responses na version mismatch; (7) document exact privacy assumption badala ya kuiita anonymous browsing.

**Detection:** networks huona service use na volume; endpoint telemetry hufichua client na final record use; compromised server inaweza kubadilisha datasets au timing. **Capture-resilient OPSEC:** hifadhi public database parameters na bounded cache pekee kwenye client. **Monitoring:** validate signed dataset roots, fixed request shapes, error-rate changes na server-key rotations.

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** remote service hufetch au hu-render URL na kurudisha screenshot, metadata au sanitized content. Destination huona fetcher address; service huona requester, URL na result. Kutumia vibaya link-preview bots, security scanners au third-party URL fetchers si authorized proxy use.

**Pros:** hutenga active content kutoka workstation; destination hupokea controlled fetcher fingerprint; inaweza kutekeleza file type, size, destination na rendering limits; disposable execution environment.

**Cons:** service ina request knowledge kamili; account/API/billing records; SSRF na data-exfiltration risk; scripts, authentication na interactive sites zinaweza kutofanya kazi; unique URLs huunganisha requester na fetch.

**Procedure:** (1) deploy organization-owned fetcher yenye strict allowlist ya owned test domains; (2) block private, link-local, metadata na redirect-to-unapproved addresses; (3) cap methods, redirects, bytes na render time; (4) strip credentials/cookies; (5) submit owned URL; (6) linganisha requester, fetcher na target logs; (7) destroy render instance na retain central audit kulingana na policy.

**Detection:** target huona service ASN/fingerprint; provider na controller logs huunganisha requester na URL; endpoint process/API calls huonyesha submission. **Capture-resilient OPSEC:** tumia short-lived project token moja isiyo na arbitrary destination authority. **Monitoring:** alert on allowlist denials, redirect violations, fetches bila controller job ID na provider abuse notices.

## Anycast rendezvous pool

**Mechanics:** nodes nyingi zinazodhibitiwa na organization hutangaza au kufront stable service address moja, na routing huchagua instance iliyo karibu. Anycast huboresha availability na kuficha back-end binafsi kutoka client, lakini operator bado hudhibiti instances zote na service address ni stable.<sup>[[26]](#references)</sup>

**Pros:** regional ingress yenye resilience; hakuna field reconfiguration instance moja inaposhindwa; DDoS/load distribution; central policy inaweza kuhamisha sessions kati ya nodes zinazojulikana.

**Cons:** BGP/CDN na provider records hutambua organization; path changes zinaweza kuvunja stateful sessions; monitoring hutofautiana kwa client location; stable address moja ni rahisi ku-block au ku-cluster kwa reputation.

**Procedure:** tumia organization project inayoungwa mkono na provider au isolated routing lab: (1) deploy authenticated health endpoints mbili zinazofanana; (2) expose documented service address moja; (3) weka session state kwa broker badala ya edge; (4) withdraw node moja na verify reconnection; (5) test certificate, policy na log consistency; (6) alert on unauthorized origin/region; (7) remove advertisements na credentials wakati wa closeout.

**Detection:** BGP/RPKI/history, provider tenancy, certificates na identical service behavior hutambua pool. **Capture-resilient OPSEC:** edge ishikilie regional service identity pekee, bila operator au fleet-enrollment key. **Monitoring:** probe kila region kutoka authorized monitors, linganisha route origin na configuration digest, na chukulia unexpected origin kuwa incident.

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection IDs zinaweza kuweka client session hai wakati wa NAT rebinding au address changes; Multipath TCP inaweza kubeba reliable byte stream moja kwenye subflows nyingi. Huboresha continuity wakati wa Wi-Fi/cellular transitions lakini huonyesha paths za zamani na mpya kwa peer yuleyule na inaweza kurahisisha cross-path correlation.<sup>[[27]](#references)</sup>

**Pros:** recovery ya haraka wakati uplink inabadilika; application session haihitaji kuanza upya; MPTCP inaweza kuchanganya resilience na throughput; muhimu kwa approved field nodes.

**Cons:** si anonymity; peer huona migration/subflows; connection identifiers na simultaneous traffic huunganisha paths; middlebox/carrier support hutofautiana; provider records mbili huongeza exposure.

**Procedure:** (1) enable supported transport kati ya owned field client na rendezvous pekee; (2) authenticate application bila kutegemea IP; (3) anza bounded transfer kwenye approved Wi-Fi; (4) switch kwenda organization cellular; (5) confirm path validation, data integrity na hakuna clear/direct fallback; (6) test idle timeout na return; (7) retain broker records za kila path transition.

**Detection:** peer huona moja kwa moja address migration au MPTCP subflows; access providers huona sehemu zao; connection IDs, TLS identity na timing huunganisha zote mbili. **Capture-resilient OPSEC:** hifadhi device-scoped session material pekee na expire resumable state haraka. **Monitoring:** alert on impossible path changes, simultaneous unapproved networks, migration storms na resumption baada ya quarantine.

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** organization-owned workflow hutekeleza bounded network check kwenye hosted runner. Destination huona cloud runner address huku platform ikihifadhi repository, actor, workflow, token, log na billing attribution. Hii ni remote execution yenye accountable egress, si anonymity dhidi ya provider.<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment; job definition inayoweza kurudiwa; hakuna inbound connection; inafaa kwa geographically distributed availability checks; controller audit imara.

**Cons:** platform na organization humtambua initiator; broad workflow tokens na untrusted pull requests ni hatari; shared IP reputation; logs/artifacts zinaweza kuhifadhi secrets au target data.

**Procedure:** (1) tengeneza private organization repository na environment kwa assessment; (2) ruhusu manually approved, fixed benign jobs pekee dhidi ya owned endpoints; (3) tumia minimal read-only workflow permissions na production secrets zisizokuwepo; (4) run check; (5) linganisha workflow, provider na target records; (6) verify artifacts hazina credentials; (7) delete environment token na retain required audit.

**Detection:** provider audit na workflow logs hutoa attribution ya moja kwa moja; targets hutambua runner ASNs/ranges na stable request grammar. **Capture-resilient OPSEC:** usiweke field-device, signing, wallet au cloud-administrator secrets kwenye runner variables. **Monitoring:** hitaji branch/environment approval na alert on workflow edits, fork execution, secret reads na unexpected destinations.

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio au serial/optical link hubeba bounded messages kutoka nearby sensor kwenda owner-approved Internet gateway. Field device yenyewe haina Internet route; gateway ndiyo egress pekee. Radio range na protocol limits hufanya huu kuwa telemetry/store-and-forward design, si interactive anonymous Internet.

**Pros:** huondoa Internet stack na credentials kutoka field device ndogo; low power; gateway huweka policy katikati; inaweza kuvuka temporary dead zones.

**Cons:** RF/physical discovery, pairing na device identifiers; bandwidth na range ndogo; gateway bado huunganisha messages zote; spectrum na encryption restrictions hutofautiana; capture inaweza kufichua queued data.

**Procedure:** (1) pata site na spectrum approval; (2) pair owned sensor moja na owned gateway moja kwa unique keys; (3) fafanua signed fixed-size message types, TTL na rate; (4) usipe sensor default IP route; (5) acha gateway i-forward kwenda owned collector pekee; (6) test replay, range loss na gateway outage; (7) inventory na retrieve devices zote mbili.

**Detection:** RF survey, pairing database, physical inspection na gateway process/flow logs hufichua path. **Capture-resilient OPSEC:** sensor ishikilie pairwise key na bounded encrypted queue pekee, kamwe operator, Wi-Fi, cellular au controller credentials. **Monitoring:** alert on new peers, sequence rollback, key failure, unusual RF rate na messages zinazofika kupitia unregistered gateway.

## Capture/compromise exposure matrix

Jedwali hili hutumia capture-resilience check kwa kila family hapo juu. “Minimize” inamaanisha kupunguza secrets na blast radius kwenye assets zilizoidhinishwa; kamwe haimaanishi kufuta ushahidi au kujificha dhidi ya investigation.

| Technique family | A captured endpoint/relay can reveal | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | known networks, DHCP/portal history, MACs, tunnel peer | separate organization device; private MAC where supported; no personal accounts; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames, keys, routes, logs and adjacent hop | one identity per engagement; short TTL; narrow routes; broker-side revocation; no master keys |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers and cached requests | minimize payload identifiers; pin approved config; bounded cache; strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software, bridge/onion material, local state and peer history | standard client; separate service keys; encrypted minimal state; rotate compromised service identity |
| Remote browser/VDI/jump host | workspace token, clipboard/files and remote tenant | phishing-resistant MFA at gateway; disabled transfer channels; rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider and approximate location | organization contract; no personal co-location; narrow APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | only consented/owned nodes; signed agent; per-node credential; controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment and billing references | dedicated project; least-privilege role; short-lived deploy token; provider audit retained centrally |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results and custody data | signed bounded jobs; TTL; encrypted cache; separate producer identity; immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artifacts | written placement; unique device identity; no operator secret; tamper/state telemetry; revoke and recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route and uplink profiles | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed paths |
| IPv6 temporary addressing | profiles, prefix history and endpoint/application state | treat as anti-tracking only; preserve network logs; pair with endpoint compartmentation |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state and research keys | standard client or isolated lab; no personal browser state; no production signaling |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway or service token | encrypted bounded cache; public-only parameters; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state and every known path | regional identity only; short resumption lifetime; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs and artifacts | least-privilege workflow; no production/field/wallet secrets; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages and gateway identity | unique pairwise key; fixed message schema; no Wi-Fi/cellular/operator credential |

## Monitoring possible discovery for every access family

Hakuna client-side test inayothibitisha kuwa investigator au defender anatazama. Monitor changes kwenye systems zinazo-owned na engagement, zithibitishe na controller/client, na simamisha badala ya kuwaprobe observers. Rows zifuatazo zinahusisha techniques zote hapo juu; zichanganye na [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | unapproved network/SIM/device, unexplained relocation or provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback or out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer or provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health and owned canary page | personal-account crossover, unexpected non-Tor connection or compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association and content hash | unknown peer/gateway, sequence rollback, unauthorized content or missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export and cloud audit | unknown login/workflow edit, secret read, unexpected destination or project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature and TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use or site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation and broker session | impossible migration, simultaneous unapproved paths or session resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root or provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Choosing and testing a path

1. Taja observer wa kuondoa na data ya kuficha.
2. Chagua family yenye complexity ndogo zaidi inayemwondoa.
3. Chora observers wa source, entry, traversal, exit, DNS, account na payment.
4. Tumia endpoint/application identity tofauti.
5. Thibitisha IPv4, IPv6, DNS, WebRTC/application bypass na destination view.
6. Vunja kila hop na thibitisha failure imefungwa.
7. Linganisha logs katika kila component unayodhibiti.
8. Rekodi timing, provider, endpoint na physical links zilizobaki.

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
