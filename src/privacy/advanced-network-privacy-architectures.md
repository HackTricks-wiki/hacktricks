# Advanced Network Privacy Architectures

Complexity is useful only when it removes a specific observer or failure mode. A unique tunnel stack, custom packet shape, rare user agent, or frequently rotating infrastructure can become a stronger fingerprint than a standard configuration used by thousands of people.

The [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) supplies the common `Pros`/`Cons`/`Procedure`/`Detection` schema. This page expands the more complex architectures and trust boundaries.

The advanced goal is therefore **separation of knowledge**: no ordinary component should simultaneously possess the user identity, destination, plaintext, and long-term activity history. This is not invisibility, and collusion, legal process, endpoint compromise, or end-to-end traffic correlation can still reconstruct the path.

## Architecture selection

| Pattern | Property gained | New trust/failure | Suitable use |
|---|---|---|---|
| Standard Tor Browser | Shared browser fingerprint and multi-relay path | Low latency permits traffic correlation | General anonymous web browsing |
| Tor bridge + pluggable transport | Makes direct Tor blocking/classification harder | Bridge/transport can still be detected; bridge learns source | Censored networks |
| Onion service | Hides service IP; avoids exit; authenticates onion identity | Onion key and server endpoint become critical assets | Private publishing, intake or administration |
| Independent ingress + egress relays | No single relay normally sees source and destination | Operators may collude; timing crosses both | High-performance supported applications |
| Oblivious HTTP | Separates source IP from encrypted stateless HTTP request | Requires application, relay and gateway support | Telemetry, queries, submissions without session state |
| VPN-only workload namespace | Kernel-enforced absence of a clear-network route | VPN still sees both ends; host/root remains trusted | Authorized engagement tools and fixed egress |
| Disposable remote browser | Destination is isolated from local browser/endpoint | Workspace provider sees activity and login identity | Untrusted sites/files and controlled research |
| I2P internal service | Separate inbound/outbound overlay tunnels; no official exits | Smaller/different ecosystem; long-running peer behavior | Services native to I2P, not ordinary web replacement |
| Mixnet/asynchronous delivery | Delay, batching and cover traffic resist timing analysis | High latency, limited applications and maturity | Messages/tasks that do not need interaction |

## Split-knowledge relays

A two-operator relay pattern can outperform a single VPN for a narrow application:

```text
client identity/IP
        |
 ingress relay -- sees client, not clear request/destination detail
        |
 encrypted request
        |
 egress gateway -- sees request/destination, not client IP
        |
 target service
```

Apple Private Relay is a deployed example: Apple operates the ingress while a different content provider operates the egress, so neither ordinarily sees both the client IP and browsing destination.<sup>[[1]](#references)</sup> This is a product-specific Safari/DNS privacy service, not an all-device anonymity network, and it deliberately preserves coarse region.

Oblivious HTTP (OHTTP) standardizes a narrower application pattern. The relay sees the client and encrypted gateway traffic; the gateway decrypts the HTTP message but sees the relay, not the client. RFC 9458 warns that it requires willing relay/gateway support, is best for requests without cookies/authentication/session state, and excludes traffic analysis from its guarantees.<sup>[[2]](#references)</sup>

### Design checklist

1. Define the exact application messages to protect; do not silently proxy arbitrary authenticated web sessions.
2. Use independently operated ingress and egress organizations with separate administration, credentials, logging and legal control where possible.
3. Encrypt the application request to the gateway so the ingress cannot read it.
4. Remove client-derived forwarding headers, TLS identifiers and stable per-user tokens at the appropriate layer.
5. Avoid unique keys, cookies or payload fields that let the gateway relink requests despite transport separation.
6. Aggregate, minimize and expire logs on both sides; document collusion and compelled-disclosure risk.
7. Pad or batch only according to a reviewed protocol. Homemade traffic shaping can create a unique signature without stopping correlation.
8. Test with controlled canary requests and compare what the client, ingress, gateway and target each record.

For ordinary interactive browsing, use Tor Browser rather than inventing a private OHTTP proxy. OHTTP protects a supported application transaction, not a full browser identity.

## Enforce the route per workload

A kill switch based only on mutable host routes can fail during DHCP renewal, sleep/wake, IPv6 changes or a tunnel crash. A stronger Linux pattern gives a container or network namespace only a loopback interface and a tunnel interface. WireGuard documents that an interface can be created in a physical namespace, moved into a workload namespace, and retain its encrypted UDP socket in the original namespace.<sup>[[3]](#references)</sup>

### Deployment pattern

1. Build this first on a disposable/local-console host; namespace mistakes can remove remote access.
2. Put the physical Ethernet/Wi-Fi interface and DHCP/supplicant in a **physical** namespace.
3. Create the WireGuard interface there so its encrypted transport socket has physical-network access.
4. Move only the WireGuard interface into the **workload** namespace and make it the sole default route.
5. Give the workload a namespace-specific resolver that is reachable only through the tunnel. Account explicitly for IPv6.
6. Run the browser/tool container in that namespace with no host networking, privileged capability, shared browser directory or personal credential agent.
7. Stop the tunnel and verify that the workload cannot resolve or connect to a controlled IPv4 or IPv6 endpoint.
8. Test endpoint roaming, DHCP renewal, suspend/resume and captive-portal handling outside the workload namespace.
9. Log the namespace/tunnel configuration hash and approved egress address for engagement accountability.

This provides **route enforcement**, not anonymity from the VPN or engagement bastion. A compromised host/root can inspect or change namespaces.

## Tor bridges and pluggable transports

Bridges are non-public Tor entry relays. Pluggable transports alter the first-hop traffic so simple blocking or protocol classification is harder. They do not add anonymous relay layers after entry and do not defeat an observer capable of broader timing correlation.

| Transport | First-hop approach | Practical tradeoff |
|---|---|---|
| **obfs4** | Makes traffic look random and resists active probing | A known bridge address can still be blocked |
| **Snowflake** | Uses short-lived volunteer WebRTC proxies to reach a bridge | Performance varies; broker/STUN/WebRTC patterns exist |
| **WebTunnel** | Carries bridge traffic in an HTTPS-like WebSocket tunnel | Depends on a reachable web front and can still be classified |

The Tor Project describes Snowflake and WebTunnel as censorship-circumvention transports, not perfect indistinguishability.<sup>[[4]](#references)</sup>

### Safe workflow

1. Start with Tor Browser's direct connection. Add a bridge only when blocking or visibility in the local observer model justifies it.
2. Use built-in transports or bridge lines obtained through Tor Project channels. Do not download random transport binaries or public bridge lists from forums.
3. Try the least complex supported option that connects reliably; record why it was chosen.
4. Keep Tor Browser otherwise standard. A bridge does not make custom extensions, account logins or unusual browser settings safe.
5. Test reconnect and clock correctness. Do not repeatedly cycle transports in a way that sends a distinctive sequence to the same local observer.
6. Reassess if the censor or network policy changes; use may itself be sensitive or restricted in some locations.

## Onion services as a private rendezvous

An onion service makes outbound Tor circuits to introduction points and rendezvous relays, so it needs no public inbound port and does not expose its server IP through the onion protocol. Client-to-service traffic stays inside Tor and the onion address authenticates the service key.<sup>[[5]](#references)</sup>

For a lawful intake portal, private repository, administrative interface or engagement evidence drop:

1. Run the application on a dedicated host/VM and bind it to loopback or an isolated Unix socket.
2. Install Tor from its official repository and follow the official v3 onion-service setup; never use obsolete v2 instructions.
3. Protect the onion service private key like a TLS/signing key. Back it up only if stable identity is required.
4. Add onion-service client authorization for a closed group and deliver credentials over an independently authenticated channel.<sup>[[6]](#references)</sup>
5. Keep the origin from fetching third-party fonts, analytics, updates or webhooks that reveal its public IP or operator account.
6. Put authentication and authorization in the application too; possession of the onion address is not access control.
7. Patch, rate-limit and monitor the service without embedding third-party telemetry.
8. From a separate test context, confirm that DNS, email, error pages, file metadata and response headers do not disclose the origin.
9. For red-team use, list the service, owner, purpose and shutdown time in the ROE. Do not use it to conceal out-of-scope C2.

## Remote browser and disposable workspace

A remote browser moves rendering and risky content away from the local endpoint and can present an engagement-specific cloud egress. It protects the local device from some content and persistence; it does not make the operator anonymous to the workspace provider. AWS, for example, documents collection of portal, identity, policy, preference and session-log data even though the disposable browser instance is discarded at session end.<sup>[[7]](#references)</sup>

Use one organization-controlled workspace per engagement, restrict downloads/uploads/clipboard, disable personal identity providers, send its fixed egress through the approved bastion, and expire the workspace after evidence export. Treat the provider console, IdP and administrator as observers.

## I2P and internal overlays

I2P builds separate unidirectional inbound and outbound tunnels and has no official network-layer exits; it is primarily for services inside I2P.<sup>[[8]](#references)</sup> It is not a drop-in faster way to browse the public Internet. Outproxies introduce a trust point, and the official threat model explicitly calls for more research and does not claim perfect anonymity.

Use I2P only when both ends intentionally support it, isolate its long-lived router from personal applications, and understand that peers/local networks can observe I2P participation. Do not increase hop counts or tune peer selection without evidence: unusual settings can reduce performance and the anonymity set.

## Correlation-resistant operations

- Prefer a common, supported client configuration over a unique build.
- Separate identities at the endpoint; no routing topology repairs account, payment, recovery or content reuse.
- For non-interactive tasks, prefer a reviewed asynchronous protocol/mixnet over manually adding sleeps or fake traffic.
- Avoid operating supposedly separate identities in a synchronized pattern from the same physical context.
- Use a one-way export gate: untrusted content enters a disposable renderer; only a reviewed, sanitized result leaves.
- Keep clocks correct for protocol security, but remove unnecessary precise timestamps from published artifacts.
- Minimize session duration and stale infrastructure without rapid “fast-flux” rotation, which is conspicuous and damages accountability.

## Techniques that cannot use uninvolved third parties

These are genuine adversary techniques, not imaginary or unimportant ones. Their mechanics and detection are covered in [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md), and the [APT case studies](government-and-apt-case-studies.md). During an authorized exercise, reproduce their observable behavior with owned substitutes:

- model residential/mobile exit churn with controlled relay pools, never markets of unclear consent;
- model open proxies, compromised routers and botnets with owned VMs/routers;
- model stolen cloud accounts with a designated exercise tenant and synthetic victim identity;
- model domain fronting on an owned reverse proxy rather than an unwilling CDN;
- model third-party Wi-Fi with two isolated APs owned by the lab;
- treat custom encryption, multi-VPN chains and identifier rotation as test hypotheses whose flow, account and endpoint artifacts remain detectable.

For an authorized red team, any attempt to make traffic less recognizable must be an explicit detection objective in the ROE, have a controller-held attribution map, and include a stop/deconfliction mechanism.

## Verification matrix

| Test | Expected result | Failure means |
|---|---|---|
| Tunnel/bridge stopped | Workload has no direct IPv4/IPv6/DNS path | Route enforcement is incomplete |
| Target log inspected | Only planned egress/application identity appears | Header, route or account leak |
| Ingress log inspected | Source present; clear target/request absent | Trust split failed at ingress |
| Egress log inspected | Relay/request present; source identity absent | Trust split failed at egress |
| Onion origin scanned externally | No public origin service is reachable/linked | Origin leaked or is dual-homed |
| Disposable session ended | Instance state gone; approved evidence retained separately | Persistence boundary failed |
| Controller lookup exercised | Activity maps promptly to engagement/operator | Red-team accountability failed |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
