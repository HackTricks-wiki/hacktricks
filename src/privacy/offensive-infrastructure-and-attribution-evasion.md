# Offensive Infrastructure and Attribution Evasion

An operator rarely obtains meaningful anonymity from a single proxy. Real campaigns build a **separation graph**: the operator reaches an access node, traversal nodes hide that node from the exit, redirectors protect the real C2, and disposable names point to the public edge.

Use the [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) for a normalized pros/cons/deployment/detection view of every path. This page goes deeper into adversarial infrastructure composition.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

The last address seen by a target is therefore evidence of a path, not proof of who controlled the keyboard. MITRE maps the major components to Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) and Web Service (T1102).<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | Why an actor uses it | Durable exposure | Defender's best pivot |
|---|---|---|---|
| Rented VPS/cloud | Fast, predictable, routable, easy to rebuild | tenant, billing, console, source-login and image history | account/control-plane events and repeated server fingerprint |
| Commercial VPN/Tor | Large shared egress set; no server administration | provider/guard visibility and end-to-end timing | destination behavior, endpoint evidence and flow correlation |
| Residential/mobile proxy | Consumer ASN and geographic plausibility | broker/customer records; proxyware or infected-host behavior | impossible travel, proxy protocols and address churn by session |
| Compromised server/router/IoT | Borrows victim reputation and jurisdiction | implant, management flow and repeated upstream controller | device telemetry and ORB topology, not one exit IP |
| CDN/redirector | Separates public edge from back-end C2 | TLS/HTTP grammar, certificate, routing and cloud-account artifacts | edge-to-origin correlation and request-shape clustering |
| Legitimate web service | Blends into allowed GitHub/cloud/social traffic | API token, tenant/object identifiers and unusual process lineage | endpoint process plus service/API semantics |
| Physical/cellular/satellite path | Changes the apparent physical origin | RF, carrier, subscriber, device and location records | radio/physical and network evidence combined |

## Operational relay box networks

An **ORB network** is a managed proxy fleet used as an intermediate service. Mandiant divides them into provisioned networks of leased servers, non-provisioned networks of compromised routers/IoT, and hybrids. A mature topology has four logical roles:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** maintains inventory, credentials, health and routing policy.
2. **Access/relay node:** authenticates customers or operators; it is the stable entry to a changing mesh.
3. **Traversal nodes:** one or more leased or compromised systems relay opaque connections.
4. **Exit/staging node:** presents the final source address to reconnaissance, exploitation or C2 targets.

The mesh can select exits by country, ASN, latency or availability and rotate unhealthy nodes. Multiple threat groups may rent the same network. Mandiant observed an IPv4 address remain associated with some ORBs for as little as 31 days; it therefore recommends treating the **network as an evolving actor-like entity**, rather than blocking a stale list of IPs.<sup>[[2]](#references)</sup>

### What this buys—and what it leaks

- The target sees an exit that may be geographically nearby and apparently residential.
- The exit sees the target and the preceding hop, not necessarily the operator.
- The access service sees the customer and the route request. An independently managed mesh may keep the customer separated from the exits, but it creates a powerful counterparty record.
- Repeated ports, handshake order, server banners, certificates, uptime windows and controller relationships can expose the fleet even while IPs rotate.
- A compromised router frequently lacks endpoint telemetry, but its ISP still has subscriber and flow data; a seizure exposes implant/configuration artifacts.

{% hint style="info" %}
For an authorized exercise, reproduce the topology with organization-owned VMs or routers and keep the controller's attribution map. Do not recruit open proxies or third-party devices. The [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) creates the same defender-visible hop structure without victimizing an intermediary.
{% endhint %}

## Residential and mobile proxy networks

Residential proxy services assign sessions to consumer broadband addresses; mobile proxies egress through carrier NAT pools. Supply can come from expressly enrolled appliances, SDK/proxyware bundled into consumer applications, resellers, or malware. These origins are not equivalent: lack of informed consent turns a privacy service into compromised infrastructure.

Rotation modes affect detection:

- **per-request rotation** produces rapid IP and ASN/geography discontinuities while higher-layer identity remains stable;
- **sticky sessions** keep an exit for minutes or hours, resembling an ordinary subscriber;
- **backconnect gateways** expose one broker endpoint to the customer and choose exits internally;
- **mobile pools** place many genuine subscribers behind a small set of carrier NAT addresses, making an IP block costly.

Defenders should correlate the IP with authenticated session, TLS/client fingerprint, HTTP ordering, device cookie and behavior. A supposedly local residential login followed by another country while all higher-layer features remain identical is stronger than reputation alone. Conversely, address sharing and mobile handoff create legitimate churn, so never treat residential/proxy classification as a verdict.

## Multi-hop proxy chains

MITRE distinguishes external proxies from **multi-hop proxies (T1090.003)**. The important property is not hop count but separation of knowledge and administration.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

If one party operates A and B, shared logs or flow timing can reconstruct the circuit. Adding sequential commercial VPNs from the same endpoint/account may add latency while leaving common identity, payment and timing evidence. Tor reduces this problem with independently selected relays and a shared client design, but a low-latency interactive network cannot promise resistance to an observer that measures both ends.

Common failures are DNS or IPv6 bypass, applications opening their own sockets, management traffic reaching relays directly, synchronized activity, reused SSH keys, and logging into identifying accounts. The correct verification is a failure test: stop every relay in turn and show that the workload cannot fall back to a clear path.

## Redirector tiers and traffic shaping

A public **redirector** accepts traffic that matches an operation-specific grammar and forwards it to a protected team server. Everything else can be rejected or served innocuous content.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Multiple tiers limit exposure: burning a public domain need not expose the team server. CDNs add anycast capacity and a reputable outer domain, but the CDN account and edge logs become attribution points. TLS fingerprints, certificate histories, distinctive paths/header order, response sizes, redirect behavior and origin allowlists can cluster supposedly unrelated fronts.

For detection, record reverse-proxy fields before normalization, compare SNI/Host/authority, inspect rare header combinations, cluster response bodies and TLS fingerprints, and search cloud/CDN audit logs for configuration overlap. For authorized red teams, avoid copying a real brand or placing credential collection behind an unrelated third party.

## Domain fronting and domainless fronting

With classic **domain fronting (T1090.004)**, the TLS connection advertises an allowed front domain in SNI while the encrypted HTTP `Host` or HTTP/2 `:authority` requests a different back-end domain. A cooperating CDN routes on the inner value. A network observer without TLS decryption sees the front; the CDN sees both values and the origin. In domainless variants, SNI may be empty while another routing field selects the destination.<sup>[[4]](#references)</sup>

This is not magic impersonation: it works only when the intermediary intentionally or accidentally permits the mismatch and knows how to route the inner name. Major providers have restricted cross-account fronting. Encrypted ClientHello (ECH) changes what an on-path observer can see but does not erase CDN, endpoint or application records.

Detection points include:

- endpoint process ancestry and destination not expected for that application;
- SNI versus HTTP authority mismatch where TLS inspection is lawful and available;
- CDN logs showing one tenant/front routing to another authority/origin;
- unusual long-lived or periodic sessions to a normally interactive service;
- stable encrypted flow sizes and cadence across changing front domains.

The safe lab simulates the routing mismatch on an owned reverse proxy; it does not abuse a public CDN.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution decouples a logical service from fixed infrastructure:

- **DDNS:** an authenticated client updates a stable name after its address changes.
- **DGA:** both endpoint and controller derive candidate domain names from a time/key seed; the operator registers a small subset.
- **Fast flux:** a name returns a rapidly changing set of compromised/proxy addresses, often with low TTLs.
- **Double flux:** both service addresses and authoritative name-server addresses rotate, hiding the control layer too.

Fast flux is a load-distribution pattern used adversarially, not merely “many DNS answers.” Stronger evidence combines low TTL, high unique-address count, wide ASN/geography dispersion, short node lifetime, repeated application behavior and suspicious registration history. CDNs legitimately share several of those properties. MITRE recommends correlating DNS behavior with the process and subsequent connections.<sup>[[5]](#references)</sup>

A DGA can be detected through lexical entropy, consonant/digit patterns, NXDOMAIN bursts, synchronized first-seen domains and process context. Wordlist DGAs and generative models defeat simple entropy rules, making fleet-wide temporal clustering and endpoint lineage more important.

## Compromised domains and domain shadowing

An actor may hijack a registrar/DNS account, take over a dangling subdomain, or add records beneath an otherwise reputable domain. **Domain shadowing** preserves the legitimate apex while large numbers of attacker-controlled subdomains point at changing delivery or C2 hosts. It borrows age and reputation and may evade domain-wide blocking.<sup>[[6]](#references)</sup>

Defenders need registrar and authoritative-DNS audit logs, MFA, registry/registrar locks, alerts for new delegations/API tokens/name servers, certificate-transparency monitoring, and an inventory of cloud resources referenced by DNS. Investigate a subdomain's resolution and certificate history independently of the apex reputation.

## Web services and dead-drop resolvers

A **dead-drop resolver (T1102.001)** stores an encoded pointer to current C2 inside a legitimate post, profile, document, repository, cloud object or blockchain field. Malware fetches the public object, decodes a domain/IP and contacts the next stage. Bidirectional variants exchange commands or files through service APIs.<sup>[[7]](#references)</sup>

This provides resilience and hides back-end C2 from static binary analysis. It also creates stable object, tenant, repository, API and access-pattern identifiers. Defenders should join:

1. the process that contacted the service;
2. exact API path/object and response hash;
3. decoding or string-processing activity;
4. the new outbound connection shortly afterward; and
5. identical behavior elsewhere in the fleet.

Blocking all GitHub, cloud storage or social media is rarely viable. Service-aware egress policy and process-level correlation outperform domain-only blocking.

## Personas, accounts and procurement compartments

Infrastructure anonymity fails when a persona, recovery email, phone, payment, browser or admin IP bridges compartments. State-linked operations have cultivated social profiles, email identities and cloud accounts long before use; ATT&CK records this as Establish Accounts (T1585), including social, email and cloud sub-techniques.<sup>[[8]](#references)</sup>

A defender or investigator builds a graph from:

- creation and first-login time, locale, time zone and working schedule;
- recovery fields, MFA devices, identity documents and payment instruments;
- browser/TLS fingerprints and source-network history;
- avatar reuse, image provenance, writing style and social-graph growth;
- shared domain registrant, name server, certificate, analytics ID or repository commit;
- management-plane actions that bypass the public relay architecture.

For an authorized red team, synthetic personas should be documented to the exercise controller, use organization-owned recovery/payment channels, avoid impersonating real uninvolved people, and have a planned retirement. The SOC may remain blind; the operation must not become unaccountable.

## Emerging compound patterns to threat-model

The following are **defender-driven compositions**, not claims that a named actor has deployed each exact design. They combine already observed primitives and are useful purple-team hypotheses.

### Asymmetric one-way tasking

Commands arrive through a public, broadcast or append-only source while results leave through an unrelated channel after a delay. Examples of the primitive include web-service one-way communication and dead drops. Separation prevents a single flow from looking bidirectional and frustrates simple request/response correlation.<sup>[[9]](#references)</sup>

**Detection:** preserve object-level reads, then correlate process state changes and later outbound transfers across a wider window. Hunt for a rare process reading the same public object even when no immediate reply follows.

### Multi-stage channel promotion

A quiet first stage performs inventory and only promotes selected systems to an unrelated second-stage channel. The second endpoint, protocol and process may share no infrastructure with the first. This limits exposure of capable infrastructure and is explicitly modeled as ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** join `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; do not close the incident after blocking the first domain.

### Cross-protocol relay translation

Different hops translate HTTPS, QUIC, WebSocket, DNS, SSH or a message-queue API rather than transparently forwarding packets. Translation removes a single end-to-end protocol fingerprint but creates gateways with distinctive timing, buffering and semantic conversion. Protocol tunneling (T1572) can be combined with proxies and service impersonation.<sup>[[11]](#references)</sup>

**Detection:** look for gateway hosts that receive one protocol and initiate another with tightly coupled byte/time behavior; compare endpoint intent to the protocol actually carried.

### Passive activation on edge devices

Instead of beaconing, an implant monitors traffic already reaching a router/VPN and activates only on a magic value, source-port pattern or authenticated token. Normal traffic continues to the real service. ATT&CK calls this Traffic Signaling (T1205), with documented network-device and APT examples.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture during an authorized hunt, unexpected socket filters and differential service behavior. Absence of a periodic beacon does not prove an edge device is clean.

### Serverless and ephemeral origin rotation

A front keeps a stable logical identity while short-lived functions/containers handle individual stages in several regions/accounts. This reduces disk lifetime and fixed origin IPs, but control-plane creation, image/layer, role, secret, request ID and billing telemetry become the durable graph.

**Detection:** retain cloud audit and invocation logs outside the workload; cluster deployment templates, roles, environment keys and front-to-origin relationships.

### Privacy-layer diversity

An operation may deliberately avoid one homogeneous chain: for example, one channel uses a leased relay, tasking uses a public object, an exit comes from an owned lab cellular link, and administration uses a separate organization network. This reduces the value of compromising one provider but increases cross-layer timing and operational-error risk.

**Detection:** build campaign timelines across identity, DNS, SaaS, network and cloud sensors. Search for synchronized state transitions rather than identical indicators.

### Decentralized or transparency-log dead drops

An actor can place a small encrypted pointer in any durable public append-only system, content-addressed store or transparency-like feed. The public object is resilient, but its exact index/content hash and the client polling behavior become stable identifiers.

**Detection:** record full API/object identifiers and response hashes; alert on nonstandard processes polling immutable objects followed by decoding or new connections.

### Delayed store-and-forward operations

Interactive C2 creates strong timing correlation. A store-and-forward design batches encrypted jobs and returns results minutes or hours later through a different queue or physical transfer. It sacrifices responsiveness for weaker end-to-end timing.

**Detection:** lengthen correlation windows, model periodic queue access and examine endpoint staging. Batching moves the signal from packet timing to scheduled process/file behavior; it does not erase it.

## Design review: think in observers

For every path, fill this table before deployment and after collection:

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

If one ordinary provider can fill every column, the architecture provides concealment from the target but not robust separation. If no internal controller can map activity back to an engagement, it is unsuitable for professional red teaming.

## References

- [1] [MITRE ATT&CK — Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), and Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
