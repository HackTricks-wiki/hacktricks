# Network Privacy और Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Network privacy एक routing decision है, complete identity नहीं। यह पूछकर path चुनें कि किसे **source**, **destination**, **content**, और **timing** को connect करने में असमर्थ होना चाहिए।

Normalized inventory—हर access-path family के लिए `Pros`, `Cons`, step-by-step `Procedure`, और `Detection`—के लिए [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) से शुरू करें। यह page सामान्यतः deploy किए जा सकने वाले options को विस्तार से बताता है।

## हर observer सामान्यतः क्या देख सकता है

| Path | Local network / ISP | Intermediary | Destination | Main limitation | Relative speed |
|---|---|---|---|---|---|
| Direct HTTPS | Source, destination metadata, timing/volume | Hosting/CDN connection देखता है | Source IP, browser/app data | Source-IP privacy नहीं | Fastest |
| Commercial VPN | Source VPN से connected; सामान्य destination metadata नहीं | VPN source और destination metadata देखता है | VPN egress IP | एक provider correlation point बन जाता है | Usually fast |
| Self-hosted VPN/VPS | Source VPS से connected | Host/account/payment/control-plane logs | VPS egress IP | Rented server/account से आसानी से attribute किया जा सकता है | Usually fast |
| Tor Browser | Source Tor/bridge से connected; timing/volume | प्रत्येक relay सीमित हिस्सा देखता है | Tor exit, browser data | Slower; account/endpoint/correlation risks | Moderate/slow |
| Tails/Whonix | अधिक मजबूत routing boundaries वाला समान Tor path | वही Tor limitations | Tor exit/application data | Operational mistakes और host/hardware फिर भी मौजूद रहते हैं | Moderate/slow |
| Public guest Wi-Fi + HTTPS | Venue local device/timing और destinations देखता है | Venue ISP metadata देखता है | Guest public IP | Physical/captive-portal/device correlation | Fast/variable |
| Cellular hotspot | Carrier subscriber/device/location और destinations देखता है | यदि उपयोग किया जाए तो VPN/Tor | Carrier, VPN, या Tor egress IP | Mobile subscription और location स्थायी identifiers हैं | Fast/variable |
| Mixnet | Access mixnet उपयोग देखता है; timing/volume | Multiple mixing nodes | Gateway/egress | Emerging ecosystem; latency और bandwidth cost | Slowest |

HTTPS transit में content की सुरक्षा करता है, लेकिन सभी metadata की नहीं। EFF के अनुसार page paths, credentials और messages encrypted होने पर भी domain, time और traffic size intermediaries को दिखाई दे सकते हैं।<sup>[[1]](#references)</sup>

## VPNs: concentrated trust के साथ fast privacy

VPN destination metadata को access ISP से छिपाने, untrusted network पर first hop को सुरक्षित करने, stable engagement egress address दिखाने, या private network तक पहुंचने के लिए उपयोगी है। यह user को **anonymous** नहीं बनाता। VPN source connection देखता है और destination metadata observe कर सकता है; accounts, cookies, GPS, fingerprints और payment information फिर भी मौजूद रहते हैं।<sup>[[1]](#references)</sup>

### Provider evaluation checklist

1. **Ownership और jurisdiction:** legal entity, parent company, operating countries, infrastructure subcontractors और लागू legal process की पहचान करें।
2. **Collected data:** account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries और destination logs में अंतर करें। “No browsing logs” का अर्थ “no data” नहीं है।
3. **Retention और deletion:** सटीक durations पता करें और देखें कि backups, fraud systems और processors उसी schedule का पालन करते हैं या नहीं।
4. **Evidence:** scope, date, findings और remediation वाले public audits; reproducible/open clients; transparency reports; और documented incidents को प्राथमिकता दें।
5. **Protocol और client:** maintained WireGuard, OpenVPN या कोई अन्य reviewed protocol; automatic updates; DNS और IPv6 handling; kill switch; तथा प्रत्येक platform के लिए leak tests।
6. **Business model:** समझें कि free या subsidized service को funding कैसे मिलती है। केवल app-store presence trustworthy operation का evidence नहीं है।
7. **Payment fit:** alternative payment VPN को billing disclosure कम कर सकता है, लेकिन प्रत्येक connection पर observed source IP को मिटाता नहीं है।

### VPN configure और verify करें

1. Provider/organization का signed client केवल उसके official source से install करें।
2. **full tunnel** चुनें, जब तक किसी documented route को bypass करना आवश्यक न हो। Split tunneling correlation और leak paths बनाता है।
3. Fail-closed/always-on behavior enable करें और reconnect के दौरान traffic block करें।
4. DNS को tunnel के माध्यम से भेजें और IPv4 तथा IPv6 दोनों test करें। किसी protocol को केवल तब disable करें जब उसे safely tunneled नहीं किया जा सकता और functionality की हानि स्वीकार हो।
5. Sleep/wake, network switching, captive-portal login, tunnel crash और hotspot tethering test करें। NCSC चेतावनी देता है कि कुछ platforms पर tethered clients phone के VPN को bypass कर सकते हैं।<sup>[[2]](#references)</sup>
6. Observed IPv4, IPv6, DNS resolver और connection timing record करने के लिए organization-controlled test endpoint उपयोग करें। Sensitive engagement को random “leak test” sites के सामने expose न करें।
7. Client, OS, network या policy changes के बाद फिर से test करें।

## Tor Browser: stronger web unlinkability

Tor कई relays के माध्यम से circuit बनाता है, इसलिए सामान्यतः कोई single relay source और destination दोनों नहीं जानता। Destination को user के IP के बजाय Tor exit दिखाई देता है; local network को सामान्यतः Tor connection दिखाई देता है।<sup>[[3]](#references)</sup> Tor low-latency TCP applications के लिए बनाया गया है, इसलिए यह slower है और ऐसे adversary के विरुद्ध protection की guarantee नहीं देता जो दोनों ends को correlate कर सके।<sup>[[4]](#references)</sup>

### Safe Tor Browser workflow

1. Tor Browser केवल Tor Project या official mirror से download करें और संभव हो तो signature verify करें।
2. Normal browser को Tor SOCKS port पर point करने के बजाय **Tor Browser** उपयोग करें। Ordinary browsers DNS/WebRTC और identifying state leak कर सकते हैं।<sup>[[5]](#references)</sup>
3. Default size, fonts, extensions और privacy settings बनाए रखें। अतिरिक्त add-ons browser को अधिक unique बना सकते हैं।<sup>[[6]](#references)</sup>
4. जब बढ़ी हुई breakage स्वीकार्य हो, तब **Safer** या **Safest** security level चुनें।
5. Direct Tor blocked होने पर या ordinary relay IPs से unacceptable local visibility बनने पर bridge उपयोग करें। Bridges आसान recognition कम करते हैं; traffic analysis समाप्त नहीं करते।<sup>[[7]](#references)</sup>
6. Identifying account में log in न करें, identifying information न दें, और downloaded active documents को external networked application में न खोलें।
7. प्रत्येक identity के लिए अलग session/context उपयोग करें। “New circuit” browser/application identity मिटाने के समान नहीं है; आवश्यकतानुसार **New Identity** उपयोग करें या isolated environment restart करें।
8. Authenticated HTTPS या authenticated onion service को प्राथमिकता दें। Tor exit unencrypted HTTP traffic observe कर सकता है।

### Tor plus VPN

दोनों को combine करना स्वतः safer नहीं है। Tor से पहले VPN ISP से direct Tor relay connections छिपा सकता है, जबकि VPN source देखता है; VPN से पहले Tor VPN को post-Tor activity का stable view देता है और anonymity set छोटा कर सकता है। Misconfiguration leaks ला सकती है। Tor Project ऐसे combinations की सलाह केवल advanced, explicit threat models के लिए देता है।<sup>[[8]](#references)</sup>

## Public और guest Wi-Fi

Modern HTTPS का अर्थ है कि passive neighbors सामान्यतः properly encrypted web content नहीं पढ़ सकते, लेकिन guest Wi-Fi anonymity नहीं है। Venue association times, device identifiers, captive-portal data, destinations और DHCP details record कर सकता है; cameras, purchases, transport और physical observation user की पहचान कर सकते हैं। समान नाम वाला fake hotspot portal credentials capture कर सकता है या unencrypted traffic manipulate कर सकता है।<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. केवल guests के लिए उपलब्ध network या owner की explicit permission वाले network का उपयोग करें। Staff से exact SSID और portal procedure पूछें।
2. Arrival से पहले endpoint और travel router update करें। File/printer sharing, inbound discovery, auto-join और remembered-network probing disable करें।
3. OS का private/randomized Wi-Fi address enable करें। Current Apple systems open/weak networks पर rotating addresses उपयोग कर सकते हैं; modern Android randomization सामान्यतः per SSID persistent होती है। इससे केवल एक local identifier कम होता है।<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Privileged workstation और guest network के बीच organization-controlled travel router या low-trust bridge device को प्राथमिकता दें। यह firewall/VPN policy को centralize करता है, लेकिन venue से router को नहीं छिपाता।<sup>[[12]](#references)</sup>
5. Captive portal केवल designated low-trust device/browser के माध्यम से complete करें। Supposedly anonymous context के लिए personal या reused credentials कभी enter न करें। Connectivity स्थापित होने के बाद portal browser बंद करें।
6. Sensitive activity से पहले full-tunnel VPN या Tor start करें और fail-closed behavior confirm करें।
7. उपयोग के बाद network forget करें और portal account/data-retention policy review करें।

{% hint style="danger" %}
किसी neighbor का Wi-Fi crack करना, portal bypass करना, leaked guest credentials उपयोग करना, किसी अन्य guest का access clone करना, या café में Raspberry Pi छिपाना unauthorized activity है—यह privacy technique नहीं है। Safe equivalents lawful guest network, client-approved site, या property owner's written consent से रखा और recover किया गया documented drop node हैं।
{% endhint %}

## Travel routers

Travel router workstation को hostile local broadcasts से isolate कर सकता है, firewall enforce कर सकता है, consistent internal SSID दे सकता है और VPN को automatically reconnect कर सकता है। यह **anonymous** नहीं है: upstream इसकी radio identity और traffic timing देखता है, और इसका VPN provider tunnel source देखता है।

- Supported OpenWrt/vendor firmware उपयोग करें और unused services हटाएं।
- Ethernet या unique password वाले dedicated management SSID पर administer करें।
- WAN-side administration, UPnP, WPS, file sharing और unsolicited inbound traffic disable करें।
- केवल जहां supported और permitted हो, randomized/private WAN MAC उपयोग करें।
- Router पर VPN policy enforce करें, जिसमें DNS और IPv6 शामिल हों, और tunnel fail होने पर egress block करें।
- यह assume न करें कि phone hotspot tethered devices को phone के VPN के माध्यम से tunnel करता है; इसे test करें।

## Cellular, SIMs और eSIMs

Cellular सुविधाजनक है, लेकिन anonymous नहीं है। Operators subscriber/device identifiers और network attachment से derived location maintain करते हैं; eSIM भी mobile subscription है। Prepaid का अर्थ reliably unregistered नहीं होता—requirements देश के अनुसार बदलती हैं और update होती रहती हैं।<sup>[[13]](#references)</sup>

Operationally:

- Personal data exposure कम करने के लिए अलग, supported device उपयोग करें, fictional subscriber बनाने के लिए नहीं।
- यदि co-location threat model में है, तो personal phone के साथ “separate” device लगातार साथ न रखें।
- Unused cellular, Wi-Fi, Bluetooth और location access disable करें; UI toggles की तुलना में powering off stronger radio boundary है।
- Sensitive traffic को approved VPN/Tor path के अंदर रखें, यह समझते हुए कि carrier subscription/device location और tunnel endpoint फिर भी जानता है।
- National regulator या local counsel से current registration और retention rules verify करें; “anonymous SIM countries” की online lists पर निर्भर न रहें।

## DNS और TLS metadata

- **DoH/DoT/DoQ** client और resolver के बीच DNS encrypt करते हैं, जिससे simple local reading या modification रुकती है, लेकिन resolver queries और transport identifiers फिर भी देखता है। वे trust move करते हैं; anonymity प्रदान नहीं करते।<sup>[[14]](#references)</sup>
- **ODoH** एक proxy जोड़ता है ताकि resolver को client IP जानने की आवश्यकता न हो, यह मानते हुए कि proxy और target collude नहीं करते। Traffic analysis स्पष्ट रूप से out of scope है।<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** TLS handshake में inner server name की सुरक्षा कर सकता है, जब client, DNS और server इसे support करते हों। Destination IP, timing, volume और endpoint दिखाई देते रहते हैं।<sup>[[16]](#references)</sup>
- Correctly configured VPN या Tor environment के साथ DNS को उस environment के supported route का पालन करना चाहिए। Separate resolver जोड़ने से नया observer या fingerprint बन सकता है।

### Encrypted-DNS/ECH verification workflow

1. तय करें कि DNS VPN/Tor environment, OS या application द्वारा controlled है। Unrelated resolvers stack करने के बजाय इसे **one** intended layer में configure करें।
2. Published privacy/retention policy वाले resolver चुनें और जहां platform support करता हो strict encrypted mode enable करें। Opportunistic fallback silently plaintext पर लौट सकता है।
3. अपने control वाले authoritative test zone के अंतर्गत unique subdomain query करें; confirm करें कि authoritative log intended recursive resolver को देखता है।
4. Authorization के साथ केवल test device का traffic capture करें। Confirm करें कि access network plaintext DNS नहीं पढ़ सकता, यह समझते हुए कि वह encrypted resolver/tunnel endpoint देख सकता है।
5. Blocked/unreachable encrypted resolver test करें। Pass condition चुना हुआ fail-closed या documented fallback behavior है—accidental clear query नहीं।
6. ECH के लिए controlled ECH-enabled host उपयोग करें और client/server diagnostics inspect कर यह confirm करें कि **inner** ClientHello accepted हुआ। केवल HTTPS record offer होना ECH success का proof नहीं है।
7. Network changes, captive portals, browser updates और VPN reconnects के बाद repeat करें। Record करें कि DNS/ECH का ownership किस component के पास है, ताकि बाद के administrators bypass न बना दें।

## Mixnets

Nym या Katzenpost जैसे Mixnets timing correlation का विरोध करने के लिए fixed-size packets, delay, reordering और cover traffic जोड़ते हैं। इन properties की कीमत latency और bandwidth है, और independent deployment-scale evidence सीमित है। Current consumer mixnets को **emerging/high-latency options** मानें, Tor/VPNs के faster या guaranteed replacements नहीं।<sup>[[17]](#references)</sup>

### Evaluation workflow

1. Maintained client और exact supported application identify करें; undocumented proxy के माध्यम से arbitrary browser/system traffic force न करें।
2. Entry, mix nodes, gateway, destination और collusion assumptions के लिए current threat model पढ़ें।
3. Official signed source से separate test compartment में install करें और केवल benign owned endpoint उपयोग करें।
4. Delivery latency, message-size limits, reliability, retransmission और gateway unavailable होने पर behavior measure करें।
5. Intended path और source confirm करने के लिए local traffic और owned endpoint inspect करें। देखें कि replies उसी privacy design का उपयोग करते हैं या नहीं।
6. Shutdown/failure test करें: application silently direct Internet access पर fallback नहीं होना चाहिए।
7. केवल speed के लिए cover traffic disable न करें, delays कम न करें या unusual fixed routes न चुनें; ये changes stated anonymity model को invalid कर सकते हैं।
8. जब तक specific deployment, independent analysis और operational reliability consequence level को meet न करें, इसे experimental रखें।

## Network preflight checklist

- [ ] Authorization में access network, target, dates और source infrastructure शामिल हैं।
- [ ] Endpoint में कोई unrelated identities या active sync sessions नहीं हैं।
- [ ] IPv4, IPv6, DNS और reconnect behavior plan के अनुरूप हैं।
- [ ] Destination को केवल expected egress दिखाई देता है।
- [ ] Captive portal और hotspot behavior को sensitive traffic के बिना test किया गया है।
- [ ] Local sharing/discovery और automatic network joining disable हैं।
- [ ] Observer table और residual traffic-correlation risk स्वीकार किए गए हैं।
- [ ] Provider policy, retention और emergency contact current हैं।

Split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P और disposable remote browsers के लिए [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) पर जाएं।

## References

- [1] [EFF — Choosing the VPN That's Right for You](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — The privacy and anonymity protections Tor offers](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — A short introduction to Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Using Tor with other browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins and add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Are Public Wi-Fi Networks Safe?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy with Apple devices](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implement MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principles for Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recommendations for DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
