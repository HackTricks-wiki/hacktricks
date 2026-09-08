# Advanced Network Privacy Architectures

जटिलता तभी उपयोगी होती है जब वह किसी विशिष्ट observer या failure mode को हटाती हो। कोई unique tunnel stack, custom packet shape, rare user agent या बार-बार बदलता infrastructure, हजारों लोगों द्वारा उपयोग किए जाने वाले standard configuration की तुलना में अधिक मजबूत fingerprint बन सकता है।

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) सामान्य `Pros`/`Cons`/`Procedure`/`Detection` schema प्रदान करता है। यह पृष्ठ अधिक जटिल architectures और trust boundaries का विस्तार करता है।

इसलिए advanced goal **ज्ञान का विभाजन** है: किसी भी सामान्य component के पास एक साथ user identity, destination, plaintext और long-term activity history नहीं होनी चाहिए। इसका अर्थ invisibility नहीं है, और collusion, legal process, endpoint compromise या end-to-end traffic correlation अभी भी path को पुनर्निर्मित कर सकते हैं।

## Architecture selection

| Pattern | प्राप्त property | नया trust/failure | उपयुक्त उपयोग |
|---|---|---|---|
| Standard Tor Browser | साझा browser fingerprint और multi-relay path | Low latency traffic correlation की अनुमति देती है | सामान्य anonymous web browsing |
| Tor bridge + pluggable transport | Direct Tor blocking/classification को कठिन बनाता है | Bridge/transport का detection अभी भी संभव है; bridge source जानता है | Censored networks |
| Onion service | Service IP छिपाता है; exit से बचता है; onion identity को authenticate करता है | Onion key और server endpoint critical assets बन जाते हैं | Private publishing, intake या administration |
| Independent ingress + egress relays | सामान्यतः कोई एक relay source और destination दोनों नहीं देखता | Operators collude कर सकते हैं; timing दोनों से होकर गुजरती है | High-performance supported applications |
| Oblivious HTTP | Source IP को encrypted stateless HTTP request से अलग करता है | Application, relay और gateway support आवश्यक है | Session state के बिना telemetry, queries, submissions |
| VPN-only workload namespace | Kernel-enforced clear-network route की अनुपस्थिति | VPN अभी भी दोनों ends देखता है; host/root पर trust बना रहता है | Authorized engagement tools और fixed egress |
| Disposable remote browser | Destination को local browser/endpoint से isolate करता है | Workspace provider activity और login identity देखता है | Untrusted sites/files और controlled research |
| I2P internal service | अलग inbound/outbound overlay tunnels; कोई official exits नहीं | छोटा/अलग ecosystem; long-running peer behavior | I2P के native services, ordinary web replacement नहीं |
| Mixnet/asynchronous delivery | Delay, batching और cover traffic timing analysis का प्रतिरोध करते हैं | High latency, सीमित applications और कम maturity | ऐसे messages/tasks जिन्हें interaction की आवश्यकता नहीं |

## Split-knowledge relays

दो-operator relay pattern किसी सीमित application के लिए single VPN से बेहतर प्रदर्शन कर सकता है:
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
Apple Private Relay एक deployed उदाहरण है: Apple ingress संचालित करता है, जबकि एक अलग content provider egress संचालित करता है, इसलिए सामान्यतः दोनों में से कोई भी client IP और browsing destination दोनों नहीं देखता।<sup>[[1]](#references)</sup> यह product-specific Safari/DNS privacy service है, न कि all-device anonymity network, और यह जानबूझकर coarse region बनाए रखता है।

Oblivious HTTP (OHTTP) एक संकीर्ण application pattern को standardize करता है। Relay client और encrypted gateway traffic देखता है; gateway HTTP message को decrypt करता है, लेकिन client के बजाय relay को देखता है। RFC 9458 चेतावनी देता है कि इसके लिए इच्छुक relay/gateway support आवश्यक है, यह cookies/authentication/session state के बिना requests के लिए सबसे उपयुक्त है, और traffic analysis को अपनी guarantees से बाहर रखता है।<sup>[[2]](#references)</sup>

### Design checklist

1. सुरक्षित किए जाने वाले exact application messages परिभाषित करें; authenticated web sessions को चुपचाप arbitrary proxy न करें।
2. जहाँ संभव हो, अलग administration, credentials, logging और legal control वाले independently operated ingress और egress organizations का उपयोग करें।
3. Application request को gateway के लिए encrypt करें ताकि ingress उसे पढ़ न सके।
4. उचित layer पर client-derived forwarding headers, TLS identifiers और stable per-user tokens हटा दें।
5. Unique keys, cookies या payload fields से बचें, जो transport separation के बावजूद gateway को requests को relink करने दें।
6. दोनों sides पर logs को aggregate, minimize और expire करें; collusion और compelled-disclosure risk को document करें।
7. Padding या batching का उपयोग केवल reviewed protocol के अनुसार करें। Homemade traffic shaping correlation रोकने के बजाय unique signature बना सकता है।
8. Controlled canary requests के साथ test करें और तुलना करें कि client, ingress, gateway और target प्रत्येक क्या record करते हैं।

Ordinary interactive browsing के लिए private OHTTP proxy बनाने के बजाय Tor Browser का उपयोग करें। OHTTP एक supported application transaction को protect करता है, full browser identity को नहीं।

## Workload के अनुसार route enforce करें

केवल mutable host routes पर आधारित kill switch DHCP renewal, sleep/wake, IPv6 changes या tunnel crash के दौरान fail हो सकता है। एक मजबूत Linux pattern container या network namespace को केवल loopback interface और tunnel interface देता है। WireGuard document करता है कि interface को physical namespace में बनाया जा सकता है, workload namespace में move किया जा सकता है, और उसका encrypted UDP socket original namespace में बनाए रखा जा सकता है।<sup>[[3]](#references)</sup>

### Deployment pattern

1. इसे पहले disposable/local-console host पर build करें; namespace की गलतियाँ remote access हटा सकती हैं।
2. Physical Ethernet/Wi-Fi interface और DHCP/supplicant को **physical** namespace में रखें।
3. वहाँ WireGuard interface बनाएँ ताकि उसके encrypted transport socket को physical-network access मिले।
4. केवल WireGuard interface को **workload** namespace में move करें और उसे sole default route बनाएँ।
5. Workload को namespace-specific resolver दें, जो केवल tunnel के माध्यम से reachable हो। IPv6 को स्पष्ट रूप से account करें।
6. Browser/tool container को उस namespace में no host networking, privileged capability, shared browser directory या personal credential agent के साथ चलाएँ।
7. Tunnel रोकें और verify करें कि workload controlled IPv4 या IPv6 endpoint को resolve या connect नहीं कर सकता।
8. Workload namespace के बाहर endpoint roaming, DHCP renewal, suspend/resume और captive-portal handling test करें।
9. Engagement accountability के लिए namespace/tunnel configuration hash और approved egress address log करें।

यह **route enforcement** प्रदान करता है, VPN या engagement bastion से anonymity नहीं। Compromised host/root namespaces को inspect या change कर सकता है।

## Tor bridges और pluggable transports

Bridges non-public Tor entry relays होते हैं। Pluggable transports first-hop traffic को बदलते हैं, जिससे simple blocking या protocol classification कठिन हो जाती है। वे entry के बाद anonymous relay layers नहीं जोड़ते और broader timing correlation करने में सक्षम observer को defeat नहीं करते।

| Transport | First-hop approach | Practical tradeoff |
|---|---|---|
| **obfs4** | Traffic को random जैसा दिखाता है और active probing का प्रतिरोध करता है | ज्ञात bridge address को फिर भी block किया जा सकता है |
| **Snowflake** | Bridge तक पहुँचने के लिए short-lived volunteer WebRTC proxies का उपयोग करता है | Performance बदलता रहता है; broker/STUN/WebRTC patterns मौजूद होते हैं |
| **WebTunnel** | Bridge traffic को HTTPS-जैसे WebSocket tunnel में ले जाता है | Reachable web front पर निर्भर करता है और फिर भी classified हो सकता है |

Tor Project Snowflake और WebTunnel को censorship-circumvention transports के रूप में describe करता है, perfect indistinguishability के रूप में नहीं।<sup>[[4]](#references)</sup>

### Safe workflow

1. Tor Browser के direct connection से शुरू करें। Bridge केवल तब जोड़ें जब local observer model में blocking या visibility इसे उचित ठहराए।
2. Tor Project channels से प्राप्त built-in transports या bridge lines का उपयोग करें। Forums से random transport binaries या public bridge lists download न करें।
3. जो supported option reliably connect हो, उसमें सबसे कम complex विकल्प आज़माएँ; इसे चुनने का कारण record करें।
4. Tor Browser को अन्यथा standard रखें। Bridge custom extensions, account logins या unusual browser settings को safe नहीं बनाता।
5. Reconnect और clock correctness test करें। Transports को इस तरह बार-बार cycle न करें कि same local observer को distinctive sequence दिखाई दे।
6. यदि censor या network policy बदलती है तो reassess करें; कुछ locations में इसका उपयोग स्वयं sensitive या restricted हो सकता है।

## Private rendezvous के रूप में Onion services

Onion service introduction points और rendezvous relays के लिए outbound Tor circuits बनाता है, इसलिए इसे public inbound port की आवश्यकता नहीं होती और onion protocol के माध्यम से इसका server IP expose नहीं होता। Client-to-service traffic Tor के भीतर रहता है और onion address service key को authenticate करता है।<sup>[[5]](#references)</sup>

Lawful intake portal, private repository, administrative interface या engagement evidence drop के लिए:

1. Application को dedicated host/VM पर चलाएँ और उसे loopback या isolated Unix socket से bind करें।
2. Tor को उसके official repository से install करें और official v3 onion-service setup का पालन करें; obsolete v2 instructions का कभी उपयोग न करें।
3. Onion service private key को TLS/signing key की तरह protect करें। केवल stable identity आवश्यक होने पर ही उसका backup लें।
4. Closed group के लिए onion-service client authorization जोड़ें और credentials को independently authenticated channel से deliver करें।<sup>[[6]](#references)</sup>
5. Origin को third-party fonts, analytics, updates या webhooks fetch करने से रोकें, जो उसका public IP या operator account reveal कर सकते हैं।
6. Application में भी authentication और authorization रखें; onion address का possession access control नहीं है।
7. Third-party telemetry embed किए बिना service को patch, rate-limit और monitor करें।
8. अलग test context से confirm करें कि DNS, email, error pages, file metadata और response headers origin disclose नहीं करते।
9. Red-team use के लिए service, owner, purpose और shutdown time को ROE में list करें। Out-of-scope C2 छिपाने के लिए इसका उपयोग न करें।

## Remote browser और disposable workspace

Remote browser rendering और risky content को local endpoint से दूर ले जाता है और engagement-specific cloud egress प्रस्तुत कर सकता है। यह local device को कुछ content और persistence से protect करता है; यह operator को workspace provider के लिए anonymous नहीं बनाता। उदाहरण के लिए, AWS portal, identity, policy, preference और session-log data के collection को document करता है, भले ही disposable browser instance session समाप्त होने पर discard हो जाए।<sup>[[7]](#references)</sup>

प्रत्येक engagement के लिए एक organization-controlled workspace का उपयोग करें, downloads/uploads/clipboard को restrict करें, personal identity providers disable करें, उसके fixed egress को approved bastion के माध्यम से भेजें, और evidence export के बाद workspace expire करें। Provider console, IdP और administrator को observers मानें।

## I2P और internal overlays

I2P अलग unidirectional inbound और outbound tunnels बनाता है और इसके official network-layer exits नहीं हैं; यह मुख्यतः I2P के भीतर services के लिए है।<sup>[[8]](#references)</sup> यह public Internet browse करने का drop-in faster तरीका नहीं है। Outproxies एक trust point जोड़ते हैं, और official threat model स्पष्ट रूप से अधिक research की आवश्यकता बताता है तथा perfect anonymity का दावा नहीं करता।

I2P का उपयोग केवल तब करें जब दोनों ends जानबूझकर इसका support करते हों, इसके long-lived router को personal applications से isolate करें, और समझें कि peers/local networks I2P participation observe कर सकते हैं। Evidence के बिना hop counts न बढ़ाएँ और peer selection tune न करें: unusual settings performance और anonymity set दोनों को घटा सकती हैं।

## Correlation-resistant operations

- Unique build के बजाय common, supported client configuration को प्राथमिकता दें।
- Endpoint पर identities अलग रखें; कोई routing topology account, payment, recovery या content reuse को repair नहीं करती।
- Non-interactive tasks के लिए manually sleeps या fake traffic जोड़ने के बजाय reviewed asynchronous protocol/mixnet को प्राथमिकता दें।
- Supposedly separate identities को same physical context से synchronized pattern में operate करने से बचें।
- One-way export gate का उपयोग करें: untrusted content disposable renderer में प्रवेश करे; केवल reviewed, sanitized result बाहर जाए।
- Protocol security के लिए clocks सही रखें, लेकिन published artifacts से अनावश्यक precise timestamps हटा दें।
- Session duration और stale infrastructure को minimize करें; rapid “fast-flux” rotation से बचें, क्योंकि यह conspicuous होती है और accountability को नुकसान पहुँचाती है।

## Uninvolved third parties का उपयोग न कर सकने वाली techniques

ये वास्तविक adversary techniques हैं, imaginary या unimportant नहीं। इनके mechanics और detection को [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md), और [APT case studies](government-and-apt-case-studies.md) में cover किया गया है। Authorized exercise के दौरान owned substitutes के साथ उनके observable behavior को reproduce करें:

- Residential/mobile exit churn को controlled relay pools से model करें, unclear consent वाले markets से कभी नहीं;
- Open proxies, compromised routers और botnets को owned VMs/routers से model करें;
- Stolen cloud accounts को designated exercise tenant और synthetic victim identity से model करें;
- Unwilling CDN के बजाय owned reverse proxy पर domain fronting को model करें;
- Third-party Wi-Fi को lab के owned दो isolated APs से model करें;
- Custom encryption, multi-VPN chains और identifier rotation को test hypotheses मानें, जिनके flow, account और endpoint artifacts detectable बने रहें।

Authorized red team के लिए traffic को कम recognizable बनाने का कोई भी प्रयास ROE में explicit detection objective होना चाहिए, उसमें controller-held attribution map होना चाहिए, और stop/deconfliction mechanism शामिल होना चाहिए।

## Verification matrix

| Test | Expected result | Failure means |
|---|---|---|
| Tunnel/bridge stopped | Workload के पास direct IPv4/IPv6/DNS path नहीं है | Route enforcement incomplete है |
| Target log inspected | केवल planned egress/application identity दिखाई देती है | Header, route या account leak |
| Ingress log inspected | Source मौजूद है; clear target/request अनुपस्थित है | Ingress पर trust split fail हुआ |
| Egress log inspected | Relay/request मौजूद है; source identity अनुपस्थित है | Egress पर trust split fail हुआ |
| Onion origin scanned externally | कोई public origin service reachable/linked नहीं है | Origin leak हुआ या dual-homed है |
| Disposable session ended | Instance state समाप्त है; approved evidence अलग retained है | Persistence boundary fail हुई |
| Controller lookup exercised | Activity तुरंत engagement/operator से map होती है | Red-team accountability fail हुई |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
