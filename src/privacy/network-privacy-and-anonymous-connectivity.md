# Network Privacy & Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Network privacy is a routing decision, not a complete identity. Select a path by asking who should be unable to connect **source**, **destination**, **content**, and **timing**.

For the normalized inventory—`Pros`, `Cons`, step-by-step `Procedure`, and `Detection` for every access-path family—start with the [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). This page expands the common deployable options.

## What each observer can usually see

| Path | Local network / ISP | Intermediary | Destination | Main limitation | Relative speed |
|---|---|---|---|---|---|
| Direct HTTPS | Source, destination metadata, timing/volume | Hosting/CDN sees connection | Source IP, browser/app data | No source-IP privacy | Fastest |
| Commercial VPN | Source connected to VPN; not usual destination metadata | VPN sees source and destination metadata | VPN egress IP | One provider becomes a correlation point | Usually fast |
| Self-hosted VPN/VPS | Source connected to VPS | Host/account/payment/control-plane logs | VPS egress IP | Easy to attribute to the rented server/account | Usually fast |
| Tor Browser | Source connected to Tor/bridge; timing/volume | Relays each see a limited portion | Tor exit, browser data | Slower; account/endpoint/correlation risks | Moderate/slow |
| Tails/Whonix | Similar Tor path, with stronger routing boundaries | Same Tor limitations | Tor exit/application data | Operational mistakes and host/hardware remain | Moderate/slow |
| Public guest Wi-Fi + HTTPS | Venue sees local device/timing and destinations | Venue ISP sees metadata | Guest public IP | Physical/captive-portal/device correlation | Fast/variable |
| Cellular hotspot | Carrier sees subscriber/device/location and destinations | VPN/Tor if used | Carrier, VPN, or Tor egress IP | Mobile subscription and location are durable identifiers | Fast/variable |
| Mixnet | Access sees mixnet use; timing/volume | Multiple mixing nodes | Gateway/egress | Emerging ecosystem; latency and bandwidth cost | Slowest |

HTTPS protects content in transit but not all metadata. EFF notes that domain, time, and traffic size can remain visible to intermediaries even when page paths, credentials, and messages are encrypted.<sup>[[1]](#references)</sup>

## VPNs: fast privacy with concentrated trust

A VPN is useful for hiding destination metadata from the access ISP, protecting a first hop on an untrusted network, presenting a stable engagement egress address, or reaching a private network. It does **not** make a user anonymous. The VPN sees the source connection and can observe destination metadata; accounts, cookies, GPS, fingerprints, and payment information remain.<sup>[[1]](#references)</sup>

### Provider evaluation checklist

1. **Ownership and jurisdiction:** identify the legal entity, parent company, operating countries, infrastructure subcontractors, and applicable legal process.
2. **Collected data:** distinguish account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries, and destination logs. “No browsing logs” does not mean “no data.”
3. **Retention and deletion:** find precise durations and whether backups, fraud systems, and processors follow the same schedule.
4. **Evidence:** prefer public audits with scope, date, findings, and remediation; reproducible/open clients; transparency reports; and documented incidents.
5. **Protocol and client:** maintained WireGuard, OpenVPN, or another reviewed protocol; automatic updates; DNS and IPv6 handling; kill switch; and per-platform leak tests.
6. **Business model:** understand how a free or subsidized service is funded. App-store presence alone is not evidence of trustworthy operation.
7. **Payment fit:** alternative payment can reduce billing disclosure to the VPN but does not erase the source IP observed at every connection.

### Configure and verify a VPN

1. Install the provider/organization's signed client from its official source.
2. Select **full tunnel** unless a documented route must bypass it. Split tunneling creates correlation and leak paths.
3. Enable fail-closed/always-on behavior and block traffic during reconnect.
4. Send DNS through the tunnel and test both IPv4 and IPv6. Disable a protocol only if it cannot be safely tunneled and the loss of functionality is accepted.
5. Test sleep/wake, network switching, captive-portal login, tunnel crash, and hotspot tethering. NCSC warns that tethered clients may bypass a phone's VPN on some platforms.<sup>[[2]](#references)</sup>
6. Use an organization-controlled test endpoint to record observed IPv4, IPv6, DNS resolver, and connection timing. Do not expose a sensitive engagement to random “leak test” sites.
7. Re-test after client, OS, network, or policy changes.

### Hostile-LAN routing bypasses

A VPN can remain visibly “connected” while selected packets bypass it because the operating system chooses a route **before** the VPN encrypts the packet. TunnelCrack demonstrated two ways to abuse common routing exceptions: **LocalNet** makes an Internet destination appear to be on the directly connected subnet, while **ServerIP** spoofs VPN-gateway resolution so a target address inherits the clear-network exception needed by the VPN transport. These are client/routing failures rather than breaks in WireGuard, OpenVPN, IPsec, or TLS; HTTPS payloads remain end-to-end encrypted, but the local observer can recover destination/timing metadata and any cleartext protocol data.<sup>[[18]](#references)</sup>

TunnelVision applies the same pre-encryption primitive through DHCP option 121. A malicious or compromised DHCP server can install a classless route that is more specific than the VPN's catch-all route, selecting the physical interface for an arbitrary host or range. The VPN control channel can stay alive, so a kill switch triggered only by tunnel disconnection may not activate and a single public “IP leak” check can miss selective bypasses.<sup>[[19]](#references)</sup>

A packet-filter kill switch that permits only DHCP and the authenticated VPN transport on the physical interface should turn this into fail-closed behavior, but targeted route injection can still create a selective-denial side channel. For high-consequence Linux workloads, prefer the stronger [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), where the application namespace has no physical interface or clear-network default route.<sup>[[19]](#references)</sup>

#### Owned-lab verification

Test the exact client/OS/version on an owned AP, DHCP server, VPN endpoint, and destination; product-wide claims age quickly because routing and packet-filter implementations are platform-specific. Capture on the endpoint itself as well as the test server—an egress-IP website alone does not prove that every destination follows the tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Connect the VPN, record the VPN-server address, and save every IPv4/IPv6 routing table and policy-routing rule. On Windows use `route print`; on macOS use `netstat -rn`; on Linux use the commands below.
2. Query the selected route for several owned destination IPs. The next hop/interface must be the tunnel, except for the documented VPN transport endpoint.
3. For TunnelVision, renew the lease on the controlled DHCP network and install an option 121 route **only for an owned test destination**. A pass means traffic is still tunneled or blocked—never emitted as destination traffic on the physical interface.
4. For LocalNet, assign the client a lab-only public documentation subnet such as `203.0.113.0/24` and place the owned test destination within it. Verify that enabling LAN access does not make Internet-class destinations bypass the tunnel.
5. For ServerIP, before VPN connection have controlled DNS resolve the owned VPN hostname to the owned test destination, while the lab gateway forwards the VPN transport to the real owned VPN endpoint. The client must not exempt unrelated application traffic to the spoofed address.
6. Repeat with “local network access” both enabled and disabled, after reconnect, sleep/wake, network switching, and a VPN-process crash. Test IPv4, IPv6, and DNS independently.
7. Inspect the physical-interface capture. It should contain DHCP and encrypted packets to the VPN server, not packets addressed directly to the owned test destination. Also confirm that a rejected bypass cannot silently fall back after user prompts or connectivity repair.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: मजबूत web unlinkability

Tor कई relays के माध्यम से एक circuit बनाता है, इसलिए सामान्यतः कोई एक relay source और destination दोनों को नहीं जानता। Destination को user's IP के बजाय Tor exit दिखाई देता है; local network को सामान्यतः Tor connection दिखाई देता है।<sup>[[3]](#references)</sup> Tor को low-latency TCP applications के लिए बनाया गया है, इसलिए यह धीमा है और ऐसे adversary से protection की guarantee नहीं दे सकता जो दोनों ends को correlate कर सके।<sup>[[4]](#references)</sup>

### सुरक्षित Tor Browser workflow

1. Tor Browser केवल Tor Project या किसी official mirror से download करें और संभव हो तो signature verify करें।
2. सामान्य browser को Tor SOCKS port पर point करने के बजाय **Tor Browser** का उपयोग करें। सामान्य browsers DNS/WebRTC और identifying state leak कर सकते हैं।<sup>[[5]](#references)</sup>
3. Default size, fonts, extensions और privacy settings बनाए रखें। अतिरिक्त add-ons browser को अधिक unique बना सकते हैं।<sup>[[6]](#references)</sup>
4. जब बढ़ी हुई breakage स्वीकार्य हो, तो **Safer** या **Safest** security level चुनें।
5. जब direct Tor blocked हो या सामान्य relay IPs स्थानीय visibility को अस्वीकार्य बना दें, तो bridge का उपयोग करें। Bridges आसान recognition को कम करते हैं; वे traffic analysis समाप्त नहीं करते।<sup>[[7]](#references)</sup>
6. किसी identifying account में log in न करें, identifying information न दें, और downloaded active documents को किसी external networked application में न खोलें।
7. प्रत्येक identity के लिए अलग session/context का उपयोग करें। “New circuit” browser/application identity मिटाने के समान नहीं है; उचित स्थिति में **New Identity** का उपयोग करें या isolated environment restart करें।
8. Authenticated HTTPS या authenticated onion service को प्राथमिकता दें। Tor exit unencrypted HTTP traffic देख सकता है।

### Tor plus VPN

इनका संयोजन अपने-आप अधिक सुरक्षित नहीं होता। Tor से पहले VPN ISP से direct Tor relay connections छिपा सकता है, जबकि VPN source देखता है; VPN से पहले Tor रखने पर VPN को post-Tor activity का स्थिर view मिलता है और anonymity set छोटा हो सकता है। Misconfiguration leaks उत्पन्न कर सकता है। Tor Project ऐसे combinations की recommendation केवल advanced, explicit threat models के लिए करता है।<sup>[[8]](#references)</sup>

## Public और guest Wi-Fi

Modern HTTPS का अर्थ है कि passive neighbors सामान्यतः properly encrypted web content नहीं पढ़ सकते, लेकिन guest Wi-Fi anonymity नहीं है। Venue association times, device identifiers, captive-portal data, destinations और DHCP details record कर सकता है; cameras, purchases, transport और physical observation user की पहचान कर सकते हैं। समान नाम वाला fake hotspot portal credentials capture कर सकता है या unencrypted traffic manipulate कर सकता है।<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. केवल guests के लिए offered network या ऐसा network उपयोग करें जिसके लिए owner ने explicit permission दी हो। Staff से exact SSID और portal procedure पूछें।
2. Arrival से पहले endpoint और travel router update करें। File/printer sharing, inbound discovery, auto-join और remembered-network probing disable करें।
3. OS का private/randomized Wi-Fi address enable करें। Current Apple systems open/weak networks पर rotating addresses उपयोग कर सकते हैं; modern Android randomization सामान्यतः प्रति SSID persistent होती है। इससे केवल एक local identifier कम होता है।<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Privileged workstation और guest network के बीच organization-controlled travel router या low-trust bridge device को प्राथमिकता दें। इससे firewall/VPN policy centralize होती है, लेकिन router venue से छिपता नहीं है।<sup>[[12]](#references)</sup>
5. Captive portal केवल designated low-trust device/browser के माध्यम से पूरा करें। कथित anonymous context के लिए personal या reused credentials कभी enter न करें। Connectivity स्थापित होने के बाद portal browser बंद करें।
6. Sensitive activity से पहले full-tunnel VPN या Tor शुरू करें और fail-closed behavior confirm करें।
7. उपयोग के बाद network भूलें और portal account/data-retention policy review करें।

{% hint style="danger" %}
किसी neighbor का Wi-Fi crack करना, portal bypass करना, leaked guest credentials का उपयोग करना, किसी अन्य guest का access clone करना, या café में Raspberry Pi छिपाना unauthorized activity है—यह privacy technique नहीं है। सुरक्षित विकल्प lawful guest network, client-approved site, या property owner's written consent के साथ रखा और recover किया गया documented drop node हैं।
{% endhint %}

## Travel routers

Travel router workstation को hostile local broadcasts से isolate कर सकता है, firewall enforce कर सकता है, consistent internal SSID provide कर सकता है और VPN को automatically reconnect कर सकता है। यह **anonymous** नहीं है: upstream इसकी radio identity और traffic timing देखता है, और इसका VPN provider tunnel source देखता है।

- Supported OpenWrt/vendor firmware का उपयोग करें और unused services हटाएं।
- Ethernet या unique password वाले dedicated management SSID के माध्यम से administer करें।
- WAN-side administration, UPnP, WPS, file sharing और unsolicited inbound traffic disable करें।
- केवल जहां supported और permitted हो, randomized/private WAN MAC का उपयोग करें।
- Router पर VPN policy enforce करें, जिसमें DNS और IPv6 शामिल हैं, और tunnel fail होने पर egress block करें।
- यह न मानें कि phone hotspot tethered devices को phone के VPN के माध्यम से tunnel करता है; इसका test करें।

## Cellular, SIMs और eSIMs

Cellular सुविधाजनक है, लेकिन anonymous नहीं है। Operators subscriber/device identifiers और network attachment से derived location maintain करते हैं; eSIM अभी भी mobile subscription है। Prepaid का अर्थ reliably unregistered नहीं होता—requirements देश के अनुसार अलग होती हैं और बदलती रहती हैं।<sup>[[13]](#references)</sup>

Operationally:

- Personal data का exposure कम करने के लिए अलग, supported device का उपयोग करें, fictional subscriber बनाने के लिए नहीं।
- यदि co-location threat model में है, तो “separate” device को personal phone के साथ लगातार न रखें।
- Unused cellular, Wi-Fi, Bluetooth और location access disable करें; powering off, UI toggles की तुलना में stronger radio boundary है।
- Sensitive traffic को approved VPN/Tor path के अंदर रखें, यह समझते हुए कि carrier subscription/device location और tunnel endpoint अभी भी जानता है।
- National regulator या local counsel से current registration और retention rules verify करें; “anonymous SIM countries” की online lists पर निर्भर न रहें।

## DNS और TLS metadata

- **DoH/DoT/DoQ** client और resolver के बीच DNS encrypt करते हैं, जिससे simple local reading या modification रुकती है, लेकिन resolver queries और transport identifiers अभी भी देखता है। वे trust को स्थानांतरित करते हैं; anonymity provide नहीं करते।<sup>[[14]](#references)</sup>
- **ODoH** एक proxy जोड़ता है, जिससे resolver को client IP जानने की आवश्यकता नहीं रहती, बशर्ते proxy और target collude न करें। Traffic analysis स्पष्ट रूप से scope से बाहर है।<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** TLS handshake में inner server name को protect कर सकता है, जब client, DNS और server इसका support करते हों। Destination IP, timing, volume और endpoint visible रहते हैं।<sup>[[16]](#references)</sup>
- Correctly configured VPN या Tor environment में DNS को उस environment के supported route का अनुसरण करना चाहिए। अलग resolver जोड़ने से नया observer या fingerprint बन सकता है।

### Encrypted-DNS/ECH verification workflow

1. तय करें कि DNS को VPN/Tor environment, OS या application control करता है। Unrelated resolvers stack करने के बजाय इसे **one** intended layer में configure करें।
2. Resolver की published privacy/retention policy के आधार पर resolver चुनें और जहां platform support करता हो, strict encrypted mode enable करें। Opportunistic fallback silently plaintext पर लौट सकता है।
3. अपने control वाले authoritative test zone के अंतर्गत unique subdomain query करें; confirm करें कि authoritative log intended recursive resolver को देखता है।
4. Authorization के साथ केवल test device का traffic capture करें। Confirm करें कि access network plaintext DNS नहीं पढ़ सकता, यह समझते हुए कि वह encrypted resolver/tunnel endpoint देख सकता है।
5. किसी blocked/unreachable encrypted resolver का test करें। Pass condition चुना गया fail-closed या documented fallback behavior है—accidental clear query नहीं।
6. ECH के लिए controlled ECH-enabled host का उपयोग करें और client/server diagnostics inspect करके confirm करें कि **inner** ClientHello accepted हुआ। केवल HTTPS record offer होना ECH के सफल होने का proof नहीं है।
7. Network changes, captive portals, browser updates और VPN reconnects के बाद दोहराएं। Record करें कि DNS/ECH का ownership किस component के पास है, ताकि बाद के administrators bypass न बना दें।

## Mixnets

Nym या Katzenpost जैसे Mixnets timing correlation का प्रतिरोध करने के लिए fixed-size packets, delay, reordering और cover traffic जोड़ते हैं। इन properties की कीमत latency और bandwidth है, और independent deployment-scale evidence सीमित है। Current consumer mixnets को **emerging/high-latency options** मानें, Tor/VPNs के faster या guaranteed replacements नहीं।<sup>[[17]](#references)</sup>

### Evaluation workflow

1. Maintained client और exact supported application की पहचान करें; undocumented proxy के माध्यम से arbitrary browser/system traffic force न करें।
2. Entry, mix nodes, gateway, destination और collusion assumptions के लिए current threat model पढ़ें।
3. Official signed source से अलग test compartment में install करें और केवल benign owned endpoint का उपयोग करें।
4. Delivery latency, message-size limits, reliability, retransmission और gateway unavailable होने पर behavior measure करें।
5. Intended path और source confirm करने के लिए local traffic और owned endpoint inspect करें। Check करें कि replies उसी privacy design का उपयोग करते हैं या नहीं।
6. Shutdown/failure test करें: application को silently direct Internet access पर fallback नहीं करना चाहिए।
7. केवल speed के लिए cover traffic disable न करें, delays कम न करें या unusual fixed routes न चुनें; ये changes stated anonymity model को invalid कर सकते हैं।
8. इसे experimental रखें, जब तक specific deployment, independent analysis और operational reliability consequence level के अनुरूप न हों।

## Network preflight checklist

- [ ] Authorization में access network, target, dates और source infrastructure शामिल हैं।
- [ ] Endpoint में कोई unrelated identities या active sync sessions नहीं हैं।
- [ ] IPv4, IPv6, DNS और reconnect behavior plan से match करते हैं।
- [ ] Controlled DHCP/local-subnet route injection test traffic को physical interface पर move नहीं कर सकता।
- [ ] Destination को केवल expected egress दिखाई देता है।
- [ ] Captive portal और hotspot behavior को sensitive traffic के बिना test किया गया है।
- [ ] Local sharing/discovery और automatic network joining disable हैं।
- [ ] Observer table और residual traffic-correlation risk स्वीकार किए गए हैं।
- [ ] Provider policy, retention और emergency contact current हैं।

Split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P और disposable remote browsers के लिए [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) पर आगे पढ़ें।



## References

- [1] [EFF — अपने लिए सही VPN चुनना](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor द्वारा प्रदान की जाने वाली privacy और anonymity protections](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor का संक्षिप्त परिचय](https://spec.torproject.org/intro/)
- [5] [Tor Project — अन्य browsers के साथ Tor का उपयोग](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser में Plugins और add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor को unblock करना](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — VPN के साथ Tor Browser का उपयोग](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — क्या Public Wi-Fi Networks सुरक्षित हैं?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple devices के साथ Wi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomization लागू करना](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstations के लिए Principles](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operators के लिए Recommendations](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Bypassing Tunnels: Routing Tables का दुरुपयोग करके VPN Client Traffic Leak करना](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Attackers Routing-Based VPNs को Total VPN Leak के लिए Decloak कैसे कर सकते हैं](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
