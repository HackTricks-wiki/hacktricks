# Attribution, Detection and Countermeasures

{{#include ../banners/hacktricks-training.md}}

Attribution-evasion infrastructure is designed to make individual indicators disposable. Defenders should preserve raw evidence, model relationships, and hunt for behavior that survives a change of IP, domain or persona.

## Evidence hierarchy

| Evidence | Useful for | Main caveat |
|---|---|---|
| Source IP/ASN/geolocation | locate the visible exit and provider | exit may be a relay, NAT or victim; geolocation is approximate |
| Passive DNS/registration | infrastructure history and co-hosting | privacy/redaction and shared hosting create gaps |
| Certificate/TLS/HTTP fingerprint | cluster repeated deployments | common software and mimicry create false positives |
| Flow timing and byte shape | link relay stages and recurring beacons | CDNs/NAT and limited visibility reduce certainty |
| Endpoint process/identity | explain why a connection occurred | not present on edge/IoT; attacker may use native tools |
| Cloud/CDN/API audit | identify tenant and infrastructure control | retention and provider/legal access vary |
| Payment/account/device | connect procurement to a person/entity | nominee, compromise and shared devices must be considered |
| Seized implant/configuration | expose keys, peers, controllers and build links | collection integrity and time of seizure matter |
| Human/physical evidence | connect digital event to place/operator | intrusive, jurisdiction-dependent, requires strict handling |

No single row should carry a high-confidence state attribution. Use competing hypotheses and state which observation would falsify each one.

## Minimum telemetry

1. **DNS:** client, question, type, answers, TTL, response code, resolver and timestamp.
2. **Network flow:** source/destination/port, start/end, packets/bytes, TCP flags and sensor location.
3. **TLS/HTTP:** SNI when visible, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status and byte count. Protect sensitive full URLs.
4. **Identity:** authentication result, factor/certificate/device, source, application, session ID and risk decision.
5. **Endpoint:** initiating process, parent, user, binary signature/hash and destination.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface and flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token and result.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP and posture.

Synchronize clocks, keep original time zones, document NAT/proxy boundaries, and retain enough history to outlive a 31-day ORB node.

## Build an attribution graph

Represent observations as typed nodes and edges:

```text
[persona]--created-->[cloud account]--deployed-->[VPS]
    |                       |                     |
 recovery               login-from             TLS fingerprint
    |                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```

Useful nodes include IP, prefix, ASN, domain, DNS account, certificate/key, JA3/JA4-like fingerprint, HTTP grammar, file/config hash, cloud tenant, API token, email, persona, payment instrument and physical device. Every edge needs `first_seen`, `last_seen`, sensor/source, confidence and whether it is observed or inferred.

Graph density alone is misleading: a CDN or certificate authority connects many unrelated actors. Weight rare operator-controlled relationships—same API account, SSH key, origin allowlist, unique response body or control protocol—more heavily than common hosting.

## ORB and compromised-router hunting

### From an observed exit

1. Determine whether the address is hosting, residential, mobile, education or business; do not discard residential sources.
2. Pull historical DNS, services/certificates, open ports and observed scan/exploitation behavior for a bounded period.
3. Search for peers sharing rare service fingerprints, controller destinations, certificate material or rotation timing.
4. Classify likely roles: access, traversal, exit/staging or administration.
5. Check whether multiple unrelated intrusion clusters used the same pool; multi-tenancy weakens direct actor attribution but strengthens an ORB hypothesis.
6. Track new nodes matching the role profile after old IPs disappear.

### At the network owner

- Alert on new Internet-exposed management and default/legacy authentication.
- Send router/firewall/VPN configuration changes and admin authentication off-device.
- Baseline outbound connections from infrastructure that normally initiates few sessions.
- Detect new proxy/listener processes, tunnels, scheduled tasks, firmware changes and unexpected DNS.
- Replace end-of-life devices; a reboot that removes volatile malware does not fix the exposure.
- Restrict management to an authenticated administration plane and known sources.

Mandiant recommends tracking ORB infrastructure as an evolving entity because short-lived IP blocking does not capture topology and lifecycle.<sup>[[1]](#references)</sup>

## Fast-flux and dynamic-DNS analytics

Aggregate by registered domain and a sliding window. A practical score can combine:

```text
score =
  2 * low_median_ttl
  + 2 * unique_answer_count
  + 2 * unique_asn_count
  + geographic_dispersion
  + nxdomain_or_answer_churn
  + first_seen_recently
  + suspicious_process_or_follow_on
```

Investigate domains with several independent features, not one threshold. Compare against a CDN/anti-DDoS allow-model and check authoritative name-server rotation to distinguish single from double flux. For DGAs, add per-client NXDOMAIN bursts, length/character distribution, synchronized queries across hosts and the process generating them. MITRE's current guidance likewise emphasizes high-frequency changes, low TTL and process/network correlation.<sup>[[2]](#references)</sup>

## Domain-fronting detection

Where the enterprise endpoint or an authorized inspection point has both identities, compare:

```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```

Raise confidence when SNI and authority belong to unrelated tenants, the process is not an approved client, the session is periodic/long-lived, and the inner origin is rare. Empty SNI is a feature to record, not automatically malicious. ECH may hide SNI on the wire, so endpoint, DNS and provider/CDN logs become more important. MITRE documents both mismatched and blank-SNI variants.<sup>[[3]](#references)</sup>

## Dead-drop resolver sequence detection

The high-signal behavior is a sequence rather than a blocked domain:

```text
unusual process
  -> reads one stable public object/profile/post
  -> receives small encoded-looking content
  -> decodes/parses it
  -> contacts a new domain or address within a short interval
```

Hunt fleet-wide for identical object paths, response hashes, API identifiers and follow-on destinations. Preserve the fetched content because the actor can edit or delete it. Restrict unneeded service APIs and require approved applications to use enterprise proxies, but account for developer tools and automation. MITRE lists GitHub, forums, documents and social/web services in real procedures.<sup>[[4]](#references)</sup>

## Redirector and reusable-deployment clustering

Even when domains and addresses change, operators often redeploy the same automation. Cluster on combinations of:

- certificate fields/key reuse and issuance timing;
- TLS version/cipher/extension order and server behavior;
- identical HTTP status, header order, cache behavior, icon/body and error page;
- unusual port pairs and redirect chains;
- DNS provider/name-server pattern and TTL schedule;
- deployment time, uptime and maintenance window;
- back-end origin exposure or identical allowlists.

A single generic Nginx page is weak evidence. Several rare independent matches plus temporal continuity can justify an infrastructure-cluster hypothesis.

## Residential proxy and impossible-session detection

Maintain the session identity above the IP layer. Flag combinations such as:

- one session/device fingerprint changes countries/ASNs faster than travel permits;
- a consumer IP changes every request while cookies and TLS/browser identity remain fixed;
- the claimed local device has latency/time-zone/language inconsistent with the exit;
- an address alternates unrelated account populations or exhibits backconnect proxy behavior;
- a privileged session appears from residential access without the organization's device certificate.

Carrier NAT, accessibility tools, corporate VPNs and travel produce benign anomalies. Require step-up authentication or investigation instead of irreversible blocking based solely on “residential proxy” labels.

## Wireless and covert-device detection

Join RADIUS/NAC with AP and physical context:

1. find first-seen account–device–AP combinations;
2. identify credentials used without a managed EAP certificate/posture;
3. compare concurrent sessions and badge/building presence;
4. inspect unusually weak/edge signal and movement between APs;
5. search nearby managed endpoints for wireless scanning, a newly enabled interface bridge/NAT, virtual adapters or tunnels;
6. inventory new switchport, DHCP, USB network and PoE activity;
7. perform an authorized RF/physical sweep when the evidence supports it.

This catches both an APT28-style nearest-neighbor path and an exercise drop. MAC randomization must not be treated as identity or guilt.

## Financial-attribution detection

- Preserve exact chain, token, address, transaction and block identifiers.
- Follow value through change, peel chains, fan-out/in, mixers, bridges and service deposits while labeling heuristics.
- Correlate time, amount minus fees, contract event, liquidity and destination-chain withdrawal.
- Obtain or preserve lawful exchange, bridge, merchant, account, device and delivery records.
- Screen current sanctioned entities/addresses and derivatives under the applicable program; do not rely on an old static list.
- Treat privacy-protocol use as a risk-context input, not proof of wrongdoing.

FATF's red flags are explicitly contextual: unusual pattern, amount/frequency, geography, source of funds and anonymity-enhancing services become meaningful together.<sup>[[5]](#references)</sup>

## Deception and canaries

Defenders can create high-confidence signals without trying to deanonymize ordinary users:

- unique credentials or documents that should never leave one system;
- fake administrative endpoints and decoy shares;
- instrumented DNS names embedded only in controlled artifacts;
- canary cloud keys with no legitimate use;
- a decoy Wi-Fi identity that no managed device possesses.

Scope and govern deception carefully. A canary should identify misuse of the defender's own asset, not collect unrelated third-party traffic.

## Countermeasure priorities

1. Remove unsupported Internet-facing routers, VPNs and appliances.
2. Require phishing-resistant MFA and device-bound certificates, including internal/wireless access.
3. Centralize immutable-enough identity, endpoint, DNS, flow, proxy, cloud and network-device logs.
4. Restrict management and egress; inventory every externally reachable service.
5. Monitor DNS, certificate transparency and cloud configuration for unauthorized assets.
6. Preserve process-to-network and object-level SaaS visibility.
7. Exercise cross-layer investigations and neighboring-provider coordination.
8. Track infrastructure clusters and behaviors, not only IP blocklists.

## Analytical discipline

Use confidence language:

- **Observed:** sensor/provider record directly shows the relationship.
- **Strongly supported:** multiple independent observations favor it over alternatives.
- **Assessed:** inference based on stated assumptions and evidence.
- **Unknown:** missing visibility prevents a conclusion.

Always keep at least two hypotheses: actor-operated infrastructure versus compromised/shared intermediary; one actor versus multi-tenant service; deliberate evasion versus legitimate privacy/CDN behavior. The ability to explain uncertainty is part of a correct detection.

## References

- [1] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRC actors compromise and maintain persistent access](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Enhanced visibility and hardening guidance for communications infrastructure](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
