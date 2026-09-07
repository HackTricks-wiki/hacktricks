# Anonymous Internet Access Technique Catalog

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

**Procedure:** (1) obtain exact written placement authority; (2) record serial, MAC, photo, location and retrieval time; (3) use signed minimal image and short-lived mutual credentials; (4) restrict outbound-only destinations/capabilities; (5) add remote kill/bandwidth limits; (6) test SOC visibility; (7) retrieve and attest wipe. Never hide one in an unconsenting venue.

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

**Procedure:** (1) build an isolated owned three-node mesh or file queue; (2) encrypt/authenticate content end to end; (3) remove direct Internet routes from origin; (4) relay a benign file after a controlled delay; (5) verify only gateway contacts owned destination; (6) compare custody/timestamps; (7) wipe temporary media/queues per policy.

**Detection:** endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity and content identifiers. Longer correlation windows replace interactive-flow analysis.

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
