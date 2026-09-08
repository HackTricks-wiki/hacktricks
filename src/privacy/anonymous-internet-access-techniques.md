# Anonymous Internet Access Technique Catalog

{{#include ../banners/hacktricks-training.md}}

This is the canonical access-path inventory. It covers protocol and operational **families**, not every vendor name. No Internet path guarantees anonymity: account, browser, endpoint, timing, payment, cloud-control-plane and physical evidence can defeat a perfect-looking route.

Every entry uses the same fields. “Procedure” means a lawful deployment or an owned-lab emulation. Where the real technique depends on compromising a router, stealing access or abusing an unwilling intermediary, the reproduction substitutes systems owned by the exercise.

## Coverage matrix

| Family | Destination sees | Strongest property | Speed | Treatment |
|---|---|---|---|---|
| Shared NAT/CGNAT | shared public address | ambiguity among subscribers | high | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | fast source-address separation | high | deployable |
| Multi-hop/split relay, MASQUE | final proxy | knowledge split or full-IP tunnel | high/moderate | deployable with trusted relays |
| Tor, bridge, onion service | exit or onion identity | multi-party path and common browser | moderate | deployable |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay or timing resistance | low/variable | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | source/request partitioning | high | supported applications only |
| Public Wi-Fi, travel router | venue/tunnel address | location/access-path change | high | permission required |
| Cellular/eSIM, satellite | carrier/provider address | independent physical uplink | high/variable | subscription/provider observes |
| Remote browser/jump host | remote workspace | endpoint and egress separation | high | deployable |
| Residential/mobile proxy | consumer/carrier address | consumer-network appearance | high | consent/provenance critical |
| ORB/compromised relay | another victim's address | origin concealment and borrowed reputation | high | owned-lab reproduction only |
| CDN/fronting/redirector | CDN/front address | protects back-end infrastructure | high | provider/owner approval required |
| Fast flux/DGA/dead drop | rotating node/service | infrastructure discovery resistance | variable | owned-lab reproduction only |
| Drop/nearest-neighbor | local target-adjacent address | crosses geographic/network boundary | high | owned-site lab only |
| Store-and-forward/offline | gateway or physical receiver | reduces interactive timing linkage | low | application-specific |
| Pluggable/refraction transport | Tor entry or cooperating diversion proxy | censorship-resistant reachability | variable | supported client or research lab |
| IPFS gateway/PIR/remote fetcher | gateway or application service | publisher/query/request partitioning | variable | bounded application only |
| Anycast/QUIC/MPTCP | stable broker or multiple subflows | rendezvous and session continuity | high | availability, not anonymity |
| CI/CD automation runner | hosted runner address | disposable accountable egress | high | owned workflow only |
| Non-IP local first hop | organization gateway | removes Internet stack from sensor | low | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** several users share one public address; the access provider maps subscriber-side addresses and ports to the public tuple.

**Pros:** fast; no special client; destination-side IP alone may identify only a household, venue or carrier pool.

**Cons:** the provider can retain subscriber/port/time mappings; accounts and fingerprints remain; other users can damage address reputation.

**Procedure:** (1) confirm whether the authorized access uses NAT/CGNAT; (2) record the exact public IP and source port at an owned endpoint; (3) keep application identities separated; (4) do not treat shared addressing as a privacy control; (5) use a stronger path if the ISP must not learn destinations.

**Detection:** destinations should retain source port and precise time, not IP alone. Providers correlate NAT allocation logs; investigators join account/device/browser evidence.

## Commercial VPN

**Mechanics:** an encrypted full-tunnel connection terminates at the VPN; destinations see its egress. The VPN can normally associate source, timing and destinations.

**Pros:** fast; simple; protects against local passive observation; stable or shared exits; good for controlled red-team egress.

**Cons:** concentrated trust; billing/login telemetry; kill-switch/DNS/IPv6 failures; shared exits are often reputation-blocked.

**Procedure:** (1) identify provider, owner, jurisdiction, retention and assessment policy; (2) install the signed official client; (3) enable full tunnel, always-on and fail-closed behavior; (4) route DNS and IPv6 deliberately; (5) verify observed IPv4/IPv6/DNS at an owned endpoint; (6) stop/reconnect the tunnel and confirm no clear fallback.<sup>[[1]](#references)</sup>

**Detection:** local networks see a long encrypted flow to VPN infrastructure; providers have authentication/connection records; destinations use ASN/reputation plus account, TLS/browser and behavior correlation.

## Self-hosted VPN or rented VPS egress

**Mechanics:** the operator controls a WireGuard/OpenVPN gateway or forwards traffic through a rented server.

**Pros:** predictable high speed; fixed allowlistable address; custom logging/firewall; good incident control.

**Cons:** low anonymity set; cloud tenant, payment, source login, API and image history link the operator; a distinctive new server is easy to cluster.

**Procedure:** (1) create an engagement-specific organization project; (2) provision a supported image and fixed address; (3) restrict management to MFA/key-based administration; (4) configure full-tunnel egress and DNS; (5) allow only scoped destinations where practical; (6) test leak/failure behavior; (7) retain controller audit records; (8) destroy credentials and resources at teardown.

**Detection:** correlate hosting ASN, first-seen address, certificate/service fingerprint and scanning behavior; cloud owners use control-plane, console, billing and flow logs.

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** an application asks a proxy to open a TCP stream; SOCKS can also convey name resolution and UDP depending on version; SSH forwards streams inside one encrypted session.

**Pros:** lightweight; per-application; fast; useful for chaining and reaching segmented networks.

**Cons:** applications can bypass it; DNS may leak; proxy sees adjacent endpoints; browser state remains; open proxies may be traps or compromised systems.

**Procedure:** (1) deploy the proxy on an owned host; (2) require authentication and restrict source/destination; (3) configure one disposable application profile; (4) ensure remote DNS resolution when required; (5) verify with an owned DNS/HTTP endpoint; (6) block direct egress for the workload; (7) inspect and rotate proxy credentials.

**Detection:** identify tunnel-capable processes, CONNECT/SOCKS negotiation, long SSH sessions and destinations inconsistent with the application; proxy logs reconstruct streams.

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** a website fetches a destination and rewrites links/forms through its own origin, or an extension directs browser requests to a proxy. The destination sees the service, while the service can see plaintext after TLS termination and inject or retain content.

**Pros:** no system-wide client; fast for simple browsing; works where VPN installation is impossible.

**Cons:** proxy can read credentials/content, rewrite downloads and fingerprint users; scripts/WebSockets/downloads may bypass; browser extension has broad privileges; small anonymity set and frequent blocking.

**Procedure:** (1) use only an organization-operated proxy for authorized testing; (2) isolate it in a disposable browser with no personal accounts; (3) prohibit password entry and sensitive downloads; (4) verify every subresource at an owned page resolves through the proxy; (5) test WebSocket, download and form behavior; (6) remove the extension/profile after use.

**Detection:** destination logs the proxy; enterprise proxy/DNS and extension inventory identify the service; content-security/reporting or owned canary subresources reveal direct bypass; proxy logs map user session to targets.

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** an entry sees the source while one or more traversal relays separate it from an exit that sees the destination.

**Pros:** no ordinary relay needs both ends; failure/seizure of one node reveals less; flexible geography.

**Cons:** shared administration/logs defeat the split; latency; timing correlation; more failure and DNS routes; same account/payment can join every hop.

**Procedure:** (1) define which observer each hop removes; (2) use independently administered owned/approved relays when separation matters; (3) enforce entry-only access from the workload; (4) ensure each relay can reach only the next hop; (5) verify logs at every layer; (6) stop each hop and confirm fail-closed behavior. Reproduce with [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detection:** correlate adjacent NetFlow timing/volume, repeated proxy handshakes and common controller infrastructure; do not infer operator geography from the exit.

## Split-knowledge application relay and OHTTP

**Mechanics:** the client encrypts a stateless HTTP message to a gateway and sends it through a relay. The relay sees client IP but not the request; the gateway sees the request but normally only the relay IP.

**Pros:** strong, auditable privacy partition for supported requests; lower overhead than general anonymity networks.

**Cons:** not arbitrary browsing; cookies/authentication can relink; relay/gateway collusion and traffic analysis remain; application must implement it.

**Procedure:** (1) select an application that explicitly supports RFC 9458; (2) verify gateway keys through the official configuration path; (3) avoid stable per-user fields; (4) send only the supported stateless request; (5) compare relay, gateway and target logs; (6) test key rotation/failure without direct fallback.<sup>[[2]](#references)</sup>

**Detection:** enterprise endpoints expose the initiating process and OHTTP relay; gateways detect malformed/replayed traffic; timing and stable payload/account fields can correlate requests.

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT over TLS/QUIC carries UDP or IP packets through a proxy. It can implement a modern VPN-like tunnel and blend transport with HTTP/3, but the proxy remains an observer.<sup>[[3]](#references)</sup>

**Pros:** efficient multiplexing/roaming; supports UDP or full IP; deploys through modern HTTP infrastructure.

**Cons:** not an anonymity network; proxy/account sees source and destinations; QUIC/HTTP fingerprints and well-known paths are visible to endpoints/providers.

**Procedure:** (1) use a client/service that documents RFC 9298/9484 support; (2) authenticate the proxy certificate/configuration; (3) define allowed target routes; (4) enable encrypted DNS inside the path; (5) verify UDP, TCP, IPv6 and failover against owned endpoints; (6) inspect proxy request and flow logs.

**Detection:** endpoints see the client process and virtual interface; networks can classify sustained QUIC/TLS to a proxy; proxy logs expose CONNECT target/path and assigned routes.

## Tor Browser

**Mechanics:** Tor selects guard, middle and exit relays; layered encryption limits each relay's view. Tor Browser adds a standardized browser intended to resist fingerprinting.

**Pros:** large public anonymity set; no one ordinary relay knows both ends; destination unlinkability without operating servers.

**Cons:** slower; TCP-focused; exit reputation/blocks; logins and disclosures identify the user; low-latency timing correlation remains.

**Procedure:** (1) download and verify Tor Browser from the project; (2) keep defaults and avoid extensions; (3) choose an appropriate security level; (4) create a separate identity/session; (5) avoid identifying accounts and external active documents; (6) use HTTPS or authenticated onion services; (7) verify the exit only with an owned endpoint.<sup>[[4]](#references)</sup>

**Detection:** local networks can identify known guard traffic unless a bridge/transport is used; destinations see exits and Tor Browser behavior; end-to-end observers correlate timing/volume.

## Tor bridges and pluggable transports

**Mechanics:** a non-public bridge replaces the public guard; obfs4, Snowflake or WebTunnel changes the first-hop transport to resist simple blocking/probing.

**Pros:** circumvents censorship and hides obvious public-relay destinations; retains the Tor circuit after entry.

**Cons:** transport patterns/bridge discovery remain possible; variable performance; does not add protection against accounts or global timing.

**Procedure:** (1) try direct Tor first; (2) in Tor Browser Connection settings select a built-in supported transport or request an official bridge; (3) do not use random binaries/lists; (4) connect and run a benign test; (5) test reconnect and clock; (6) keep all other browser settings standard.<sup>[[5]](#references)</sup>

**Detection:** censors use destination discovery, protocol/flow classification and active probing; defenders should distinguish circumvention use from compromise and rely on endpoint process/context.

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Tor hides direct Tor use from the access ISP but exposes the source to the VPN. Tor-before-VPN gives the VPN post-Tor traffic and often a stable customer/tunnel identity.

**Pros:** removes a specific observer when designed correctly; can reach networks that block one layer.

**Cons:** complexity, uncommon fingerprint, leaks, reduced anonymity set and false confidence; Tor Project treats combinations as advanced.<sup>[[6]](#references)</sup>

**Procedure:** (1) write the observer removed and new observer introduced; (2) use a disposable environment; (3) establish only the intended outer path; (4) enforce firewall routes; (5) verify DNS/IPv4/IPv6 and each failure order; (6) compare both providers' visibility; (7) abandon the stack if it has no measurable advantage.

**Detection:** local/VPN/Tor observers see different adjacent layers; timing remains end-to-end; unusual nested tunnel fingerprints and provider accounts can link sessions.

## Onion service

**Mechanics:** both client and service build Tor circuits to a rendezvous, hiding the service IP and avoiding an exit.

**Pros:** source and service location protection; end-to-end onion authentication; no public inbound port; optional client authorization.

**Cons:** origin leaks through updates/analytics/errors; onion key is critical; application identity/timing and host compromise remain.

**Procedure:** (1) isolate the application and bind it only to loopback/socket; (2) install supported Tor; (3) configure a v3 onion service using official instructions; (4) protect/back up its key only if stable identity is needed; (5) add client authorization for closed use; (6) remove third-party fetches; (7) externally verify the origin is not reachable.<sup>[[7]](#references)</sup>

**Detection:** host/network defenders find Tor process/configuration and outbound circuits; application errors, DNS, certificates or third-party resources can expose origin.

## I2P internal services

**Mechanics:** I2P uses separate unidirectional inbound/outbound tunnels for destinations inside the overlay; public-Internet outproxies add a trust point.

**Pros:** decentralized internal publishing; no official exit dependency; separate inbound/outbound paths.

**Cons:** not a general web replacement; smaller ecosystem; long-running peer behavior; outproxy can observe public browsing.

**Procedure:** (1) install from the official source; (2) use a dedicated context; (3) allow integration/bandwidth stabilization; (4) access an I2P-native owned service; (5) avoid outproxies unless explicitly required; (6) verify shutdown gives no direct fallback; (7) inspect local peer and service logs.<sup>[[8]](#references)</sup>

**Detection:** local networks see long-lived peer traffic and bootstrap behavior; endpoints expose router/application processes; outproxies log exits.

## Mixnets

**Mechanics:** fixed-size packets, batching, delay, reordering and cover traffic reduce timing correlation; gateways bridge applications.

**Pros:** better resistance to timing analysis than low-latency proxies; useful for asynchronous messages/transactions.

**Cons:** latency, bandwidth overhead, smaller deployment and application limits; gateway/account metadata can persist.

**Procedure:** (1) select a maintained client and supported application; (2) read the actual threat model; (3) install in a separate compartment; (4) send benign data to an owned endpoint; (5) measure latency/reliability and reply path; (6) test gateway failure; (7) never disable delays/cover traffic merely for speed.<sup>[[9]](#references)</sup>

**Detection:** endpoints identify the client; access networks can classify gateways/packet cadence; gateways and exits observe adjacent roles, while broader correlation requires longer statistical windows.

## GNUnet anonymous file sharing

**Mechanics:** GNUnet can route publish/search/download requests through peers and add cover traffic according to an anonymity level. Its own documentation warns that default level 1 does not require cover traffic and powerful traffic analysis may identify origin.<sup>[[10]](#references)</sup>

**Pros:** decentralized, application-native anonymous sharing; tunable cover-traffic requirement.

**Cons:** not ordinary anonymous web access; performance/storage cost; peer and traffic-analysis limitations; GNUnet VPN documentation says its IP overlay does not provide good anonymity.

**Procedure:** (1) install a maintained official build; (2) isolate a test peer; (3) cap bandwidth/storage; (4) publish a harmless unique test file with a chosen anonymity level; (5) retrieve from another owned peer; (6) record cover-traffic and latency; (7) avoid claiming the IP VPN component provides equivalent anonymity.

**Detection:** peer bootstrap, overlay traffic, local datastore/process and file identifiers; a broad observer can analyze traffic volume against cover traffic.

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQ encrypt to a resolver; ODoH splits client address from query between proxy and resolver; ECH encrypts the inner TLS ClientHello/server name.

**Pros:** removes plaintext DNS/SNI from some local observers; ODoH partitions source/query knowledge.

**Cons:** not an IP-anonymity path; resolver/proxy/server retain roles; destination IP/timing/volume and endpoint remain; fallback can leak.

**Procedure:** (1) choose whether OS, application or tunnel owns DNS; (2) enable strict encrypted mode or supported ODoH; (3) test a unique owned domain; (4) capture locally to confirm no clear query; (5) fail the resolver and verify intended behavior; (6) for ECH, confirm server diagnostics show inner ClientHello acceptance.<sup>[[11]](#references)</sup>

**Detection:** endpoint/resolver logs expose queries; networks identify encrypted-resolver endpoints and destination flows; ECH state is visible at endpoints/CDN even when hidden on path.

## Split-provider privacy relay

**Mechanics:** products such as iCloud Private Relay use an ingress that knows the client and an independently operated egress that knows the destination, with coarse region handling.

**Pros:** low-friction split knowledge; fast; integrated DNS/web protection for supported traffic.

**Cons:** product/application scope is limited; account/platform provider still identifies customer; not arbitrary system anonymity; collusion/legal and timing risks.

**Procedure:** (1) confirm exact applications and traffic types supported; (2) enable the feature under a dedicated platform context where appropriate; (3) select region behavior; (4) test Safari/DNS and unsupported applications separately; (5) inspect the destination address; (6) test network switching/failure.<sup>[[12]](#references)</sup>

**Detection:** access sees ingress; destination sees egress; platform/relay logs and account records span their respective layer; unsupported applications expose normal paths.

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** browsing/tool execution occurs on a remote system; the destination sees its egress while the workspace provider sees the operator connection and control plane.

**Pros:** fast; isolates risky content; stable controlled egress; disposable state and strong organizational audit.

**Cons:** provider/admin can observe session/account; screen/clipboard/file channels leak; remote browser fingerprint may be unique; not anonymous to the workspace owner.

**Procedure:** (1) create one organization-owned workspace per engagement; (2) require MFA and restrict administration; (3) disable or constrain clipboard/upload/download; (4) route through approved fixed egress; (5) use no personal IdP/sync; (6) export only reviewed evidence; (7) destroy workspace and credentials on schedule.

**Detection:** provider and IdP logs map user to session; destinations cluster workspace egress/browser; enterprise defenders identify remote-control protocols and anomalous cloud sessions.

## Public or guest Wi-Fi

**Mechanics:** traffic exits through the venue NAT or a tunnel started there.

**Pros:** high speed and a shared non-home address; no dedicated infrastructure.

**Cons:** venue association/DHCP/portal, camera, purchase and location evidence; hostile peers/APs; terms; physical risk.

**Procedure:** (1) obtain access offered to guests and verify SSID with staff; (2) use a patched low-trust device; (3) disable sharing/auto-join and enable private MAC; (4) complete the portal without reused identity; (5) start a fail-closed VPN/Tor path; (6) verify tethered traffic; (7) forget the network.

**Detection:** venue correlates AP, MAC, DHCP, portal and time; destination sees venue/tunnel; investigators combine physical and device evidence. Never bypass access control.

## Travel router

**Mechanics:** an operator-owned router joins venue Wi-Fi/Ethernet and provides an isolated internal network with enforced tunnel policy.

**Pros:** isolates workstations; central kill switch/DNS; consistent client network; shields privileged endpoints from local broadcasts.

**Cons:** router becomes a stable radio/DHCP fingerprint; adds attack surface; captive portals and tethering can bypass tunnel.

**Procedure:** (1) update supported firmware; (2) set unique management credentials and disable WAN admin/WPS/UPnP; (3) configure private upstream MAC where permitted; (4) create a separate internal SSID; (5) enforce full-tunnel DNS/IPv6 firewall policy; (6) test portal, reconnect and tunnel failure.

**Detection:** venue sees the router association and traffic shape; local RF/DHCP fingerprinting identifies it; VPN provider sees venue source.

## Cellular, prepaid SIM and eSIM

**Mechanics:** a modem uses carrier radio access and usually carrier NAT; a VPN/Tor layer can change the destination-visible exit.

**Pros:** independent from local wired/Wi-Fi network; mobile; high speed; useful backhaul for authorized drops.

**Cons:** carrier knows subscriber/eSIM, IMSI, IMEI, cells, time and assigned ports; registration laws vary; co-location with personal phone links devices.

**Procedure:** (1) obtain service lawfully with accurate required details; (2) use an organization-owned separate modem/device; (3) record it with the exercise controller; (4) disable unrelated radios/accounts; (5) establish approved tunnel; (6) test whether tethered clients actually follow it; (7) verify provider and retention assumptions before travel.<sup>[[13]](#references)</sup>

**Detection:** carrier records and RF location; enterprise USB/PCI/MDM inventory and rogue-hotspot surveys; destination/tunnel timing.

## Satellite Internet and satellite downlink abuse

**Mechanics:** normal service uses a registered terminal/provider. Older one-way DVB-S abuse let a receiver inside a beam observe unencrypted downlink traffic addressed to a legitimate subscriber while using another path for outbound requests.

**Pros:** wide footprint; independent last mile; historical one-way abuse could misattribute C2 to a subscriber geography.

**Cons:** equipment/RF/provider records; latency and coverage; modern bidirectional systems differ; outbound path and asymmetric routing remain evidence.

**Procedure:** for lawful access, register an owned terminal and tunnel traffic as required. To emulate historical Turla behavior, replay synthetic one-way packet captures inside an RF-free lab and test whether analysts detect a reply to a host that made no request; do not intercept live satellite traffic.<sup>[[14]](#references)</sup>

**Detection:** provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency and malware configuration.

## Residential/mobile proxy or consented proxyware

**Mechanics:** a backconnect gateway assigns consumer broadband/mobile exits, either sticky or rotating. Supply may be consensual, deceptively bundled or malicious.

**Pros:** high speed; geographic choice; consumer ASN avoids some hosting blocks; large pools.

**Cons:** provenance/consent and legal risk; broker sees customer; infected exits harm victims; rotation creates anomalies; expensive and unreliable.

**Procedure:** use only documented, informed-consent organization-owned agents for emulation: (1) enroll test endpoints; (2) inventory owners/IPs; (3) configure a gateway; (4) rotate sticky/per-request modes; (5) send only to an owned target; (6) compare gateway/exit/target logs; (7) remove every agent.

**Detection:** impossible travel, stable browser/account across rapid IP/ASN changes, backconnect protocols, proxyware process/network artifacts and broker/controller relations.

## ORB, botnet and compromised edge-device relays

**Mechanics:** leased or compromised routers/IoT/servers form access, traversal and exit roles administered as a fleet. Multiple APT customers may share it.

**Pros:** borrowed reputation/geography; short-lived exits; resilient multi-hop mesh; weak direct actor-to-IP link.

**Cons:** criminal victimization; implant/controller and fleet patterns; intermediary seizure; inconsistent performance; operator/customer service records.

**Procedure:** never compromise real devices. Use [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) create isolated entry/transit/target networks; (2) attach owned dual-homed relay containers; (3) forward only one test port; (4) send a benign request; (5) verify target sees only exit; (6) rotate exit; (7) tear down all named assets.<sup>[[15]](#references)</sup>

**Detection:** track topology, ports/services, controller relations, implant fingerprints and node lifecycle; centralize edge configuration/flow/integrity telemetry; do not equate exit IP with actor.

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** a public edge forwards only traffic matching a grammar; fronting places a benign outer SNI and different inner HTTP authority, or blank SNI, when the intermediary permits it.

**Pros:** hides/protects back-end; fast global edge; blends destination with a shared service; rapid cutover.

**Cons:** CDN sees all routing and tenant; many providers prohibit cross-tenant fronting; SNI/Host/process/flow and account artifacts; configuration reuse clusters campaigns.

**Procedure:** reproduce only on an owned reverse proxy with [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): create a local certificate/edge, route one mismatched Host to an owned target, log SNI and Host, send normal/mismatched requests, then remove containers.<sup>[[16]](#references)</sup>

**Detection:** compare SNI/ECH/Host/`:authority` at endpoint or terminating edge; join initiating process, tenant/origin, request grammar and flow cadence.

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNS updates a stable name; DGA derives changing candidate names; fast flux rotates service addresses at low TTL; double flux also rotates name servers.

**Pros:** resilient discovery; rapid infrastructure replacement; shields controller behind many nodes.

**Cons:** DNS creates centralized telemetry; entropy/NXDOMAIN/churn; low TTL and broad ASN patterns; registration and authoritative infrastructure remain.

**Procedure:** use [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): serve an owned zone returning RFC 5737 addresses with five-second TTL, query it repeatedly, change the synthetic epoch, and validate analytics. Never point test records at third parties.<sup>[[17]](#references)</sup>

**Detection:** sliding-window unique answers/ASNs, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters and process follow-on; exclude legitimate CDNs with context.

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** a public post, repository, document, object or feed contains an encoded current endpoint or task. The client may return results over another channel.

**Pros:** allowed high-reputation service; TLS; endpoint rotation without changing binary; asymmetric tasking frustrates simple flow correlation.

**Cons:** stable object/account/API identifiers; provider records; endpoint decode/follow-on sequence; content can be seized or changed.

**Procedure:** use [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): host an encoded pointer on one owned container, fetch/decode from a short-lived client, contact a second owned service, preserve both logs, then tear down.

**Detection:** correlate unusual process → stable object read → decode → new destination; hash/preserve content and retain full object paths, not just domain.

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** functions/short-lived jobs run behind provider NAT or a front; logical service stays stable while instances and addresses rotate.

**Pros:** rapid deployment/destruction; provider-scale shared egress; little local disk; elastic regional routing.

**Cons:** tenant, role, API, image, secret, invocation, billing and front-to-origin logs are durable; cold-start and platform fingerprints; provider policy.

**Procedure:** (1) use an organization-owned exercise tenant; (2) deploy a benign function that requests only an owned endpoint; (3) record project/role/image/config; (4) invoke across several instances; (5) compare target IPs with audit/request IDs; (6) test log retention; (7) remove function, roles and secrets.

**Detection:** cloud audit/invocation logs, unusual role creation, shared egress plus stable request grammar, image/layer and secret reuse, and front-origin correlation.

## Authorized on-site drop

**Mechanics:** an inventoried small computer uses local wired/Wi-Fi and outbound VPN/cellular rendezvous, presenting a local source.

**Pros:** realistic internal-origin testing; high speed; can test NAC, physical inventory and egress controls.

**Cons:** physical discovery/theft; serial/MAC/USB/DHCP/PoE/RF and camera evidence; loss may expose credentials.

**Procedure:** follow [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) obtain exact written placement authority; (2) record serial, MAC, photo, location and retrieval time; (3) use a signed minimal image and short-lived mutual credentials; (4) restrict outbound-only destinations/capabilities; (5) add server-side quarantine and bandwidth limits; (6) test SOC visibility and loss response; (7) retrieve, preserve required evidence, then sanitize under the agreed lifecycle policy. Never hide one in an unconsenting venue.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera and physical inspection.

## Nearest-neighbor wireless pivot

**Mechanics:** an actor controls a host in radio range of the target, then uses target Wi-Fi credentials to cross the boundary remotely. APT28 used nearby compromised organizations this way.<sup>[[18]](#references)</sup>

**Pros:** no operator travel; target sees a local radio source; bypasses controls applied only to Internet entry.

**Cons:** requires nearby compromised/owned dual-radio host and valid access; RADIUS/NAC/AP and neighbor endpoint evidence; signal/device anomalies.

**Procedure:** reproduce only with the [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): join an owned pivot to neighbor and target lab SSIDs, forward only one service, collect both AP/pivot logs, then enable EAP-TLS/device posture and confirm the second attempt fails.

**Detection:** correlate RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login and physical presence; hunt nearby endpoints for simultaneous radios, forwarding and tunnels.

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** traffic traverses local peers, asynchronous gateways, removable media or scheduled queues rather than one interactive Internet session.

**Pros:** works during disruption/censorship; delayed/batched delivery weakens simple timing; no central last mile for local communication.

**Cons:** high latency; small anonymity set; custody/physical metadata; malicious peers; data eventually reaches a gateway that observes it.

**Procedure:** (1) build an isolated owned three-node mesh or file queue; (2) encrypt/authenticate content end to end; (3) remove direct Internet routes from origin; (4) relay a benign file after a controlled delay; (5) verify only gateway contacts owned destination; (6) compare custody/timestamps; (7) preserve required evidence, then sanitize temporary media/queues at approved closeout.

**Detection:** endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity and content identifiers. Longer correlation windows replace interactive-flow analysis.

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN) allocates a public relay address and carries UDP, TCP or TLS traffic between a client and peers. An ICE policy can force relay use instead of exposing a direct candidate. TURN solves reachability, not general anonymity: the server authenticates the client and observes allocations, peers, time and volume.<sup>[[19]](#references)</sup>

**Pros:** widely implemented; handles restrictive NAT; supports mobile WebRTC; the peer does not receive the client's direct transport address when relay-only policy is correctly enforced.

**Cons:** the TURN operator sees both adjacent sides; application identity, media fingerprint and signaling remain; relay-only costs bandwidth and latency; misconfiguration can still gather host or server-reflexive candidates.

**Procedure:** (1) deploy an organization-owned TURN service with TLS and short-lived credentials; (2) restrict realms, peers, ports, quotas and expiration; (3) set the test application to relay-only ICE; (4) call an owned peer; (5) inspect `getStats()` and packet capture to confirm only relay candidates carried media; (6) fail the relay and confirm there is no direct fallback; (7) retain allocation logs for the engagement.

**Detection:** signaling, browser process and TURN allocations join the session to the relay; networks observe sustained flows to TURN ports or TLS endpoints; the peer sees the allocated relay. **Captured node:** application state and ephemeral TURN credentials may reveal the realm and rendezvous service. Minimize exposure with per-device, short-lived credentials and keep operator authentication only at the controller.

## Outbound-only rendezvous or reverse overlay

**Mechanics:** a node behind NAT initiates an authenticated connection to an organization-controlled broker. The operator separately authenticates to the broker, which authorizes a narrow management channel; neither inbound port forwarding nor a direct operator-to-node route is required.

**Pros:** stable behind NAT and captive last miles; central revocation and audit; field-node address changes do not require operator discovery; cleanly separates operator identity from the node credential.

**Cons:** the broker becomes a high-value correlation point; periodic keepalives are recognizable; a broad tunnel can become an unsafe pivot; loss of the broker ends management.

**Procedure:** follow [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): issue one scoped device identity, permit only an owned broker and approved management service, use authenticated keepalive, enforce fail-closed routing, test address changes and reboot recovery, and revoke the identity during the loss drill. WireGuard documents a 25-second persistent keepalive as a broadly useful NAT interval when it is actually needed.<sup>[[20]](#references)</sup>

**Detection:** broker and identity-provider logs map both sides; the access network sees a repeated encrypted destination/cadence; endpoint inventory shows the overlay agent. **Captured node:** assume its device key, broker name, tunnel addresses and cached task data are exposed. It must contain no operator private key, personal account or reusable controller token.

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** a field workload polls an authenticated mailbox for signed, pre-approved jobs and posts bounded results. The operator writes to the queue through a separate control plane; there is no interactive socket between them.

**Pros:** tolerates intermittent links; decouples timing and addressing; quotas and schemas can constrain capability; easy centralized audit and revocation.

**Cons:** polling cadence and stable object/queue names fingerprint the system; provider logs join producer and consumer; delayed control; captured queued data may expose the exercise.

**Procedure:** (1) create one engagement queue and one device identity; (2) define a signed schema of benign, explicitly scoped jobs; (3) set message TTL, maximum result size and rate; (4) allow the node to pull only its queue and write only its result prefix; (5) test offline accumulation, duplicate delivery and revocation; (6) centralize immutable access logs; (7) delete the queue after retention requirements are met.

**Detection:** hunt for periodic API calls by an unusual process, stable bucket/object/queue paths, identical user-agent or TLS behavior, and a fetch-then-new-connection sequence. **Captured node:** local cache can reveal pending jobs and object names; keep cache encrypted, bounded and disposable, while preserving authoritative controller logs.

## Dual-uplink failover and connection migration

**Mechanics:** an approved field node has two independent uplinks—such as venue Ethernet/Wi-Fi and organization cellular—and keeps its control session through an overlay or message broker as routes change. This is availability engineering, not anonymity.

**Pros:** survives one provider, AP or captive-portal failure; supports planned maintenance; permits quick isolation of a suspect path.

**Cons:** two providers create two location/account records; simultaneous use makes correlation easier; route and DNS leaks during failover; cellular co-location evidence remains.

**Procedure:** (1) register both organization-owned interfaces and providers; (2) assign deterministic route priorities and health checks to owned endpoints; (3) bind DNS and management to the overlay; (4) prevent the secondary path from accepting inbound traffic; (5) unplug each path and verify session recovery, source policy and no direct destination access; (6) alert on unplanned path change; (7) document data use and roaming limits.

**Detection:** correlate the same device certificate, request grammar and timing across ASNs; local inventory sees both radios; carriers/venues retain their own records. **Captured node:** both SIM/device identifiers and known SSIDs may be visible; use organization assets and never co-locate or pair the node with personal devices.

## Organization private APN or managed cellular tunnel

**Mechanics:** a carrier private APN places enrolled SIMs into a private routed domain or tunnels traffic to an enterprise gateway. It separates the device from the public mobile Internet but does not hide it from the carrier or contracting organization.

**Pros:** stable private addressing; carrier-level enrollment and traffic policy; avoids public inbound exposure; useful for authorized remote appliances.

**Cons:** subscriber, IMSI/IMEI, cell and billing attribution are strong; procurement lead time and cost; carrier/gateway outage; not anonymous to the operator.

**Procedure:** (1) contract the APN in the assessment organization's name; (2) whitelist only registered SIMs and gateway prefixes; (3) add application-layer mutual authentication; (4) restrict the APN route to the rendezvous and update services; (5) test SIM removal, roaming, public-Internet breakout and revocation; (6) monitor carrier and gateway records; (7) cancel or quarantine every SIM at closeout.

**Detection:** carrier inventory and cell telemetry, APN gateway flows, SIM/IMEI mismatch and enterprise asset records. **Captured node:** the SIM and modem identify the contract even when storage is encrypted; capture resilience therefore means rapid suspension and narrow authorization, not deniability.

## Long-range point-to-point wireless bridge

**Mechanics:** directional Wi-Fi or another licensed/unlicensed point-to-point radio connects two owner-approved sites, with Internet egress at the remote site. It can move the apparent IP location without using a commercial proxy.

**Pros:** high throughput; independent of intermediate wired carriers; controllable RF and routing; useful for testing segmentation and remote-site monitoring.

**Cons:** line-of-sight, spectrum, landlord and regulatory constraints; distinctive RF emissions and hardware; both endpoints are physical evidence; weather/power/alignment affect stability.

**Procedure:** (1) obtain written permission for both sites and verify spectrum/power rules; (2) survey the path without transmitting outside approved parameters; (3) use authenticated encryption and a management VLAN; (4) restrict the bridge to an owned rendezvous or test subnet; (5) test failover, alignment, power recovery and RF containment; (6) label/inventory both radios; (7) remove them and verify configuration reset after the exercise.

**Detection:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic and remote-site egress logs. **Captured node:** configuration reveals its peer and management domain; use unique exercise credentials, no personal management accounts and rapid peer-key revocation.

## Consented cooperative or community exit

**Mechanics:** volunteers or partner organizations knowingly run relays under a published policy. Traffic exits from a shared community pool while the coordination layer accounts for abuse and revocation.

**Pros:** diverse non-cloud networks; explicit consent is safer than proxyware; shared governance can distribute trust; useful for research and censorship-resilience studies.

**Cons:** small pools and membership records reduce anonymity; exit operators receive complaints and observe traffic metadata; malicious participants, variable uptime and jurisdiction differences.

**Procedure:** (1) publish an acceptable-use and logging policy; (2) obtain informed opt-in from each operator; (3) issue a unique relay identity and restrict destinations/rates; (4) provide abuse handling and one-action revocation; (5) send only authorized traffic to owned endpoints during testing; (6) measure churn and correlation exposure; (7) remove the relay cleanly when consent ends.

**Detection:** membership/control-plane records, relay certificates, common software fingerprint and exit behavior identify the pool. **Captured node:** relay configuration may identify the cooperative but should not contain client identities; store client-to-session accountability at the authorized controller under access control.

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extensions create temporary interface identifiers so a stable address is not reused for every outbound connection. Provider prefix changes can add rotation, but the delegated prefix, subscriber record and upper-layer fingerprint remain.<sup>[[21]](#references)</sup>

**Pros:** reduces passive long-term tracking by a stable interface identifier; built into common operating systems; no relay overhead.

**Cons:** not source anonymity; ISP and local network still know the prefix/device; DNS, accounts and browser state link sessions; address churn complicates allowlists and logging.

**Procedure:** (1) inspect current stable and temporary addresses on an owned client; (2) enable the OS-supported privacy-address default rather than third-party spoofing; (3) request an owned IPv6 endpoint repeatedly across address lifetimes; (4) confirm inbound services bind only intended stable addresses; (5) retain DHCPv6/RA/neighbor and precise endpoint logs; (6) test VPN/firewall behavior for every IPv6 address.

**Detection:** correlate delegated prefix, layer-2 identity, neighbor discovery, account and endpoint telemetry instead of treating one address as one device. **Captured node:** network profiles and interface identifiers remain; temporary addressing prevents one passive identifier, not forensic attribution.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** a pluggable transport changes how the first Tor connection appears or how it reaches a bridge. Snowflake uses short-lived volunteer WebRTC proxies, WebTunnel resembles ordinary HTTPS, obfs4 resists simple protocol identification and active probing, and meek relays through supported web infrastructure. They are censorship-circumvention transports into Tor, not extra end-to-end anonymity layers.<sup>[[22]](#references)</sup>

**Pros:** useful when direct Tor or known relays are blocked; Snowflake avoids a stable public bridge address; integrated into maintained Tor clients; destination still receives ordinary Tor properties.

**Cons:** lower or variable performance; broker/front/bridge and local network observe different metadata; transport fingerprints and blocking remain possible; volunteer proxy does not replace Tor and should not be trusted with application plaintext.

**Procedure:** (1) install and verify the official Tor Browser or supported Tor client; (2) select the built-in transport in Connection/Bridges; (3) connect only to an owned diagnostic page; (4) confirm the page sees a Tor exit, not the Snowflake/WebTunnel peer; (5) compare bootstrap and performance; (6) fail the transport and confirm the client does not silently connect directly; (7) return to the standard supported configuration after the test.

**Detection:** a censor can combine destination allowlists, TLS/WebRTC behavior, broker discovery and flow analysis; endpoints expose Tor and transport configuration. **Capture-resilient OPSEC:** use the standard client, never copy personal browser state into it, and assume bridge/broker history is recoverable. **Monitoring:** watch Tor bootstrap logs, unexpected direct DNS/connection attempts and controller-side owned-page observations; transport failure is not proof of discovery.

## Refraction networking or decoy routing

**Mechanics:** a cooperating network operator detects a covert signal in traffic apparently addressed to an allowed decoy and diverts the flow to a circumvention proxy. Deployment requires infrastructure in the network path; it is not something a client can create merely by selecting an innocent website.<sup>[[23]](#references)</sup>

**Pros:** the apparent destination may be difficult for a censor to block without collateral damage; no public bridge address must be distributed; useful research model for on-path-assisted circumvention.

**Cons:** specialized ISP/transit participation; deployability and performance depend on routing; client-to-decoy flow and proxy-side activity remain; a global or cooperating observer can correlate timing.

**Procedure:** do not signal through uninvolved networks. Reproduce the architecture in an isolated lab: (1) create owned client, router, decoy and proxy namespaces; (2) use a benign tagged test request; (3) let the owned router redirect only that tag to the proxy; (4) log pre/post-routing tuples and request IDs; (5) compare ordinary and signaled flows; (6) test false positives and removal; (7) destroy the lab routes.

**Detection:** authorized network operators can inspect routing divergence, unusual client hello/tag behavior and decoy-versus-back-end flow discrepancies. **Capture-resilient OPSEC:** a research client should hold only test keys and documentation addresses. **Monitoring:** compare signed lab-router decisions with proxy arrivals; do not probe production transit providers to determine whether they detected signaling.

## Content-addressed gateway or cached peer retrieval

**Mechanics:** an HTTP gateway retrieves an IPFS content identifier (CID), possibly from its cache or peers, and returns the verifiable content to the client. The original publisher may see the gateway or other peers rather than the final reader; the gateway sees the reader IP and requested CID. Native peer-to-peer retrieval exposes the client to peers and DHT/routing participants.<sup>[[24]](#references)</sup>

**Pros:** publisher and reader can be separated by caches; immutable content is hash-verifiable; replicated data survives one host; HTTP clients require no native peer stack.

**Cons:** public CIDs and gateway logs reveal interests; first retrieval timing can correlate publisher and reader; malicious web content and path-style same-origin hazards; public gateways are best-effort and prohibit abuse.

**Procedure:** (1) publish a harmless test file to an owned private IPFS swarm or owned gateway; (2) record its CID; (3) retrieve it through a separate owned HTTP gateway using subdomain isolation; (4) verify the bytes against the CID; (5) repeat after caching; (6) compare publisher, peer and gateway logs; (7) unpin and remove test content when retention ends.

**Detection:** gateways log source/CID; DHT and peer connections reveal retrieval; endpoint history and file hashes identify content. **Capture-resilient OPSEC:** store no private publishing key on a read-only field client and encrypt sensitive content before content addressing. **Monitoring:** alert on unexpected pinning, peer-set change, CID requests outside the allowlist or gateway account notices.

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR) lets a client retrieve one record from a database while cryptographically hiding the selected index from the server under a stated single- or multi-server threat model. It protects query selection for a bounded dataset; it is not general web access or IP anonymity.<sup>[[25]](#references)</sup>

**Pros:** strong application-specific query privacy; measurable leakage model; useful for key directories, blocklists or small public databases; can reduce the need to reveal exact lookup terms.

**Cons:** computation/bandwidth overhead; server learns connection time/IP unless combined with a relay; dataset version, response size and application state can partition users; implementation maturity varies.

**Procedure:** (1) deploy an audited PIR implementation against a synthetic owned database; (2) publish dataset version and parameters; (3) retrieve several indices through identical request sizes; (4) verify correctness locally; (5) compare server logs and confirm the index is absent; (6) test malicious/truncated responses and version mismatch; (7) document the exact privacy assumption rather than calling it anonymous browsing.

**Detection:** networks see service use and volume; endpoint telemetry exposes the client and final record use; a compromised server can manipulate datasets or timing. **Capture-resilient OPSEC:** keep only public database parameters and a bounded cache on the client. **Monitoring:** validate signed dataset roots, fixed request shapes, error-rate changes and server-key rotations.

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** a remote service fetches or renders a URL and returns a screenshot, metadata or sanitized content. The destination sees the fetcher address; the service sees the requester, URL and result. Abusing link-preview bots, security scanners or third-party URL fetchers is not authorized proxy use.

**Pros:** isolates active content from the workstation; destination receives a controlled fetcher fingerprint; can enforce file type, size, destination and rendering limits; disposable execution environment.

**Cons:** service has complete request knowledge; account/API/billing records; SSRF and data-exfiltration risk; scripts, authentication and interactive sites may not work; unique URLs correlate requester and fetch.

**Procedure:** (1) deploy an organization-owned fetcher with a strict allowlist of owned test domains; (2) block private, link-local, metadata and redirect-to-unapproved addresses; (3) cap methods, redirects, bytes and render time; (4) strip credentials/cookies; (5) submit an owned URL; (6) compare requester, fetcher and target logs; (7) destroy the render instance and retain central audit according to policy.

**Detection:** target sees the service ASN/fingerprint; provider and controller logs map requester to URL; endpoint process/API calls show submission. **Capture-resilient OPSEC:** use one short-lived project token with no arbitrary destination authority. **Monitoring:** alert on allowlist denials, redirect violations, fetches without a controller job ID and provider abuse notices.

## Anycast rendezvous pool

**Mechanics:** multiple organization-controlled nodes advertise or front one stable service address, and routing selects a nearby instance. Anycast improves availability and hides an individual back-end from the client, but the operator still controls all instances and the service address is stable.<sup>[[26]](#references)</sup>

**Pros:** resilient regional ingress; no field reconfiguration when one instance fails; DDoS/load distribution; central policy can move sessions among known nodes.

**Cons:** BGP/CDN and provider records identify the organization; path changes can break stateful sessions; monitoring differs by client location; a single stable address is easily blocked or reputation-clustered.

**Procedure:** use a provider-supported organization project or an isolated routing lab: (1) deploy two identical authenticated health endpoints; (2) expose one documented service address; (3) keep session state at the broker rather than an edge; (4) withdraw one node and verify reconnection; (5) test certificate, policy and log consistency; (6) alert on unauthorized origin/region; (7) remove advertisements and credentials at closeout.

**Detection:** BGP/RPKI/history, provider tenancy, certificates and identical service behavior identify the pool. **Capture-resilient OPSEC:** an edge holds only regional service identity and no operator or fleet-enrollment key. **Monitoring:** probe every region from authorized monitors, compare route origin and configuration digest, and treat an unexpected origin as an incident.

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection IDs can keep a client session alive across NAT rebinding or address changes; Multipath TCP can carry one reliable byte stream across multiple subflows. They improve continuity across Wi-Fi/cellular transitions but expose old and new paths to the common peer and can make cross-path correlation easier.<sup>[[27]](#references)</sup>

**Pros:** faster recovery during uplink changes; application session need not restart; MPTCP can combine resilience and throughput; valuable for approved field nodes.

**Cons:** not anonymity; peer sees migration/subflows; connection identifiers and simultaneous traffic link paths; middlebox/carrier support varies; duplicated provider records increase exposure.

**Procedure:** (1) enable the supported transport only between an owned field client and rendezvous; (2) authenticate the application independently of IP; (3) begin a bounded transfer on approved Wi-Fi; (4) switch to organization cellular; (5) confirm path validation, data integrity and no clear/direct fallback; (6) test idle timeout and return; (7) retain broker records of every path transition.

**Detection:** the peer directly observes address migration or MPTCP subflows; access providers see their part; connection IDs, TLS identity and timing join both. **Capture-resilient OPSEC:** store only device-scoped session material and expire resumable state quickly. **Monitoring:** alert on impossible path changes, simultaneous unapproved networks, migration storms and resumption after quarantine.

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** an organization-owned workflow executes a bounded network check on a hosted runner. The destination sees a cloud runner address while the platform retains repository, actor, workflow, token, log and billing attribution. This is remote execution with accountable egress, not anonymity from the provider.<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment; reproducible job definition; no inbound connection; useful for geographically distributed availability checks; strong controller audit.

**Cons:** platform and organization identify the initiator; broad workflow tokens and untrusted pull requests are dangerous; shared IP reputation; logs/artifacts can retain secrets or target data.

**Procedure:** (1) create a private organization repository and environment for the assessment; (2) permit only manually approved, fixed benign jobs against owned endpoints; (3) use minimal read-only workflow permissions and no production secrets; (4) run the check; (5) compare workflow, provider and target records; (6) verify artifacts contain no credentials; (7) delete the environment token and retain required audit.

**Detection:** provider audit and workflow logs provide direct attribution; targets identify runner ASNs/ranges and stable request grammar. **Capture-resilient OPSEC:** never place field-device, signing, wallet or cloud-administrator secrets in runner variables. **Monitoring:** require branch/environment approval and alert on workflow edits, fork execution, secret reads and unexpected destinations.

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio or a serial/optical link carries bounded messages from a nearby sensor to an owner-approved Internet gateway. The field device itself has no Internet route; the gateway is the only egress. Radio range and protocol limits make this a telemetry/store-and-forward design, not interactive anonymous Internet.

**Pros:** removes an Internet stack and credentials from the smallest field device; low power; gateway centralizes policy; can bridge temporary dead zones.

**Cons:** RF/physical discovery, pairing and device identifiers; small bandwidth and range; gateway still links all messages; spectrum and encryption restrictions vary; capture can expose queued data.

**Procedure:** (1) obtain site and spectrum approval; (2) pair one owned sensor with one owned gateway using unique keys; (3) define signed fixed-size message types, TTL and rate; (4) give the sensor no default IP route; (5) let the gateway forward only to an owned collector; (6) test replay, range loss and gateway outage; (7) inventory and retrieve both devices.

**Detection:** RF survey, pairing database, physical inspection and gateway process/flow logs reveal the path. **Capture-resilient OPSEC:** the sensor holds only its pairwise key and bounded encrypted queue, never operator, Wi-Fi, cellular or controller credentials. **Monitoring:** alert on new peers, sequence rollback, key failure, unusual RF rate and messages arriving through an unregistered gateway.

## Capture/compromise exposure matrix

This table applies a capture-resilience check to every family above. “Minimize” means reduce secrets and blast radius on authorized assets; it never means clearing evidence or hiding from an investigation.

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

No client-side test proves that an investigator or defender is watching. Monitor changes in systems the engagement owns, corroborate them with the controller/client, and stop rather than probing observers. The rows below cover every technique above; combine them with the [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

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

1. Name the observer to remove and data to hide.
2. Select the least complex family that removes it.
3. Draw source, entry, traversal, exit, DNS, account and payment observers.
4. Use a separate endpoint/application identity.
5. Verify IPv4, IPv6, DNS, WebRTC/application bypass and destination view.
6. Break every hop and confirm failure is closed.
7. Compare logs at every component you control.
8. Record residual timing, provider, endpoint and physical links.

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
