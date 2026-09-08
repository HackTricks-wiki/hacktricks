# Attribution, Detection और Countermeasures

{{#include ../banners/hacktricks-training.md}}

Attribution-evasion infrastructure को इस तरह डिज़ाइन किया जाता है कि individual indicators को आसानी से बदला या त्यागा जा सके। Defenders को raw evidence सुरक्षित रखना चाहिए, relationships का model बनाना चाहिए, और ऐसे behavior की तलाश करनी चाहिए जो IP, domain या persona बदलने के बाद भी बना रहे।

## Evidence hierarchy

| Evidence | Useful for | Main caveat |
|---|---|---|
| Source IP/ASN/geolocation | दिखाई देने वाले exit और provider का स्थान पता करना | exit relay, NAT या victim हो सकता है; geolocation approximate होती है |
| Passive DNS/registration | infrastructure history और co-hosting | privacy/redaction और shared hosting के कारण gaps बनते हैं |
| Certificate/TLS/HTTP fingerprint | बार-बार होने वाले deployments को cluster करना | common software और mimicry false positives पैदा कर सकते हैं |
| Flow timing and byte shape | relay stages और recurring beacons को जोड़ना | CDNs/NAT और limited visibility certainty कम करते हैं |
| Endpoint process/identity | यह समझाना कि connection क्यों हुआ | edge/IoT पर मौजूद नहीं; attacker native tools का उपयोग कर सकता है |
| Cloud/CDN/API audit | tenant और infrastructure control की पहचान करना | retention और provider/legal access अलग-अलग होते हैं |
| Payment/account/device | procurement को किसी व्यक्ति/entity से जोड़ना | nominee, compromise और shared devices पर विचार करना आवश्यक है |
| Seized implant/configuration | keys, peers, controllers और build links उजागर करना | collection integrity और seizure का समय महत्वपूर्ण है |
| Human/physical evidence | digital event को place/operator से जोड़ना | intrusive, jurisdiction-dependent और strict handling आवश्यक है |

किसी एक row को high-confidence state attribution का आधार नहीं बनाना चाहिए। Competing hypotheses का उपयोग करें और बताएं कि कौन-सा observation प्रत्येक hypothesis को falsify करेगा।

## Minimum telemetry

1. **DNS:** client, question, type, answers, TTL, response code, resolver और timestamp।
2. **Network flow:** source/destination/port, start/end, packets/bytes, TCP flags और sensor location।
3. **TLS/HTTP:** visible होने पर SNI, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status और byte count। Sensitive full URLs को सुरक्षित रखें।
4. **Identity:** authentication result, factor/certificate/device, source, application, session ID और risk decision।
5. **Endpoint:** initiating process, parent, user, binary signature/hash और destination।
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface और flow logs।
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token और result।
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP और posture।

Clocks को synchronize करें, original time zones बनाए रखें, NAT/proxy boundaries को document करें, और 31-day ORB node से अधिक समय तक काम आने लायक पर्याप्त history retain करें।

## Build an attribution graph

Observations को typed nodes और edges के रूप में represent करें:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
उपयोगी nodes में IP, prefix, ASN, domain, DNS account, certificate/key, JA3/JA4-like fingerprint, HTTP grammar, file/config hash, cloud tenant, API token, email, persona, payment instrument और physical device शामिल हैं। हर edge में `first_seen`, `last_seen`, sensor/source, confidence और यह जानकारी होनी चाहिए कि वह observed है या inferred।

केवल graph density भ्रामक हो सकती है: CDN या certificate authority कई असंबंधित actors को जोड़ते हैं। सामान्य hosting की तुलना में operator-controlled ऐसे relationships को अधिक महत्व दें जो दुर्लभ हों—जैसे वही API account, SSH key, origin allowlist, unique response body या control protocol।

## ORB और compromised-router hunting

### किसी observed exit से

1. निर्धारित करें कि address hosting, residential, mobile, education या business है; residential sources को न हटाएं।
2. एक सीमित अवधि के लिए historical DNS, services/certificates, open ports और observed scan/exploitation behavior प्राप्त करें।
3. ऐसे peers खोजें जो rare service fingerprints, controller destinations, certificate material या rotation timing साझा करते हों।
4. संभावित roles वर्गीकृत करें: access, traversal, exit/staging या administration।
5. जांचें कि क्या कई असंबंधित intrusion clusters ने उसी pool का उपयोग किया; multi-tenancy direct actor attribution को कमजोर करती है, लेकिन ORB hypothesis को मजबूत करती है।
6. पुराने IPs के गायब होने के बाद role profile से मेल खाने वाले नए nodes को track करें।

### Network owner के स्तर पर

- नए Internet-exposed management और default/legacy authentication पर alert करें।
- Router/firewall/VPN configuration changes और admin authentication को off-device भेजें।
- ऐसे infrastructure से होने वाले outbound connections का baseline बनाएं, जो सामान्यतः बहुत कम sessions शुरू करता है।
- नए proxy/listener processes, tunnels, scheduled tasks, firmware changes और unexpected DNS का पता लगाएं।
- End-of-life devices को बदलें; volatile malware हटाने वाला reboot exposure को ठीक नहीं करता।
- Management को authenticated administration plane और ज्ञात sources तक सीमित रखें।

Mandiant evolving entity के रूप में ORB infrastructure को track करने की सलाह देता है, क्योंकि short-lived IP blocking topology और lifecycle को capture नहीं करती।<sup>[[1]](#references)</sup>

## Fast-flux और dynamic-DNS analytics

Registered domain और sliding window के आधार पर aggregate करें। एक practical score में ये शामिल किए जा सकते हैं:
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
कई independent features वाले domains की जांच करें, केवल एक threshold के आधार पर नहीं। इसकी तुलना CDN/anti-DDoS allow-model से करें और single flux तथा double flux में अंतर करने के लिए authoritative name-server rotation की जांच करें। DGAs के लिए, प्रत्येक client के NXDOMAIN bursts, length/character distribution, hosts के बीच synchronized queries और उन्हें generate करने वाले process को शामिल करें। MITRE का वर्तमान guidance भी high-frequency changes, low TTL और process/network correlation पर जोर देता है।<sup>[[2]](#references)</sup>

## Domain-fronting detection

जहां enterprise endpoint या authorized inspection point के पास दोनों identities हों, वहां तुलना करें:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
जब SNI और authority असंबंधित tenants से संबंधित हों, process approved client न हो, session periodic/long-lived हो और inner origin दुर्लभ हो, तो confidence बढ़ाएँ। Empty SNI को record करने योग्य feature मानें, इसे अपने-आप malicious न मानें। ECH wire पर SNI छिपा सकता है, इसलिए endpoint, DNS और provider/CDN logs अधिक महत्वपूर्ण हो जाते हैं। MITRE mismatched और blank-SNI variants दोनों को document करता है।<sup>[[3]](#references)</sup>

## Dead-drop resolver sequence detection

High-signal behavior blocked domain के बजाय एक sequence होता है:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
पूरे fleet में समान object paths, response hashes, API identifiers और follow-on destinations के लिए hunt करें। fetched content को preserve करें क्योंकि actor इसे edit या delete कर सकता है। अनावश्यक service APIs को restrict करें और approved applications के लिए enterprise proxies का उपयोग अनिवार्य करें, लेकिन developer tools और automation का भी ध्यान रखें। MITRE वास्तविक procedures में GitHub, forums, documents और social/web services को सूचीबद्ध करता है।<sup>[[4]](#references)</sup>

## Redirector और reusable-deployment clustering

Domains और addresses बदलने पर भी operators अक्सर वही automation फिर से deploy करते हैं। निम्नलिखित के संयोजनों के आधार पर cluster करें:

- certificate fields/key reuse और issuance timing;
- TLS version/cipher/extension order और server behavior;
- identical HTTP status, header order, cache behavior, icon/body और error page;
- unusual port pairs और redirect chains;
- DNS provider/name-server pattern और TTL schedule;
- deployment time, uptime और maintenance window;
- back-end origin exposure या identical allowlists।

एक single generic Nginx page कमजोर evidence है। कई rare independent matches और temporal continuity मिलकर infrastructure-cluster hypothesis को उचित ठहरा सकते हैं।

## Residential proxy और impossible-session detection

Session identity को IP layer से ऊपर बनाए रखें। निम्नलिखित combinations को flag करें:

- एक session/device fingerprint travel की अनुमति से अधिक तेजी से countries/ASNs बदलता है;
- consumer IP हर request पर बदलता है, जबकि cookies और TLS/browser identity स्थिर रहते हैं;
- claimed local device में exit के अनुरूप latency/time-zone/language नहीं है;
- कोई address असंबंधित account populations के बीच alternate करता है या backconnect proxy behavior दिखाता है;
- कोई privileged session संगठन के device certificate के बिना residential access से दिखाई देता है।

Carrier NAT, accessibility tools, corporate VPNs और travel benign anomalies उत्पन्न कर सकते हैं। केवल “residential proxy” labels के आधार पर irreversible blocking करने के बजाय step-up authentication या investigation आवश्यक करें।

## Wireless और covert-device detection

RADIUS/NAC को AP और physical context के साथ जोड़ें:

1. पहली बार दिखने वाले account–device–AP combinations खोजें;
2. ऐसे credentials पहचानें जिनका उपयोग managed EAP certificate/posture के बिना हुआ हो;
3. concurrent sessions और badge/building presence की तुलना करें;
4. असामान्य रूप से कमजोर/edge signal और APs के बीच movement की जांच करें;
5. nearby managed endpoints में wireless scanning, newly enabled interface bridge/NAT, virtual adapters या tunnels खोजें;
6. नए switchport, DHCP, USB network और PoE activity की inventory करें;
7. जब evidence इसका समर्थन करे, तो authorized RF/physical sweep करें।

यह APT28-style nearest-neighbor path और exercise drop, दोनों को पकड़ सकता है। MAC randomization को identity या guilt नहीं माना जाना चाहिए।

## Financial-attribution detection

- Exact chain, token, address, transaction और block identifiers को preserve करें।
- Value को change, peel chains, fan-out/in, mixers, bridges और service deposits के माध्यम से follow करें और heuristics को label करें।
- Time, amount minus fees, contract event, liquidity और destination-chain withdrawal को correlate करें।
- Lawful exchange, bridge, merchant, account, device और delivery records प्राप्त या preserve करें।
- Applicable program के अंतर्गत वर्तमान sanctioned entities/addresses और derivatives को screen करें; पुरानी static list पर निर्भर न रहें।
- Privacy-protocol use को risk-context input मानें, wrongdoing का proof नहीं।

FATF के red flags स्पष्ट रूप से contextual हैं: unusual pattern, amount/frequency, geography, source of funds और anonymity-enhancing services साथ में meaningful बनते हैं।<sup>[[5]](#references)</sup>

## Deception और canaries

Defenders ordinary users को deanonymize करने का प्रयास किए बिना high-confidence signals बना सकते हैं:

- unique credentials या documents जिन्हें कभी भी किसी एक system से बाहर नहीं जाना चाहिए;
- fake administrative endpoints और decoy shares;
- controlled artifacts में ही embedded instrumented DNS names;
- ऐसे canary cloud keys जिनका कोई legitimate use नहीं है;
- एक decoy Wi-Fi identity जिसे कोई managed device possess नहीं करता।

Deception का scope और governance सावधानी से तय करें। Canary को defender के अपने asset के misuse की पहचान करनी चाहिए, unrelated third-party traffic collect नहीं करना चाहिए।

## Countermeasure priorities

1. Unsupported Internet-facing routers, VPNs और appliances हटाएँ।
2. Internal/wireless access सहित phishing-resistant MFA और device-bound certificates आवश्यक करें।
3. Immutable-enough identity, endpoint, DNS, flow, proxy, cloud और network-device logs को centralize करें।
4. Management और egress को restrict करें; externally reachable प्रत्येक service की inventory रखें।
5. Unauthorized assets के लिए DNS, certificate transparency और cloud configuration को monitor करें।
6. Process-to-network और object-level SaaS visibility preserve करें।
7. Cross-layer investigations और neighboring-provider coordination का अभ्यास करें।
8. केवल IP blocklists नहीं, बल्कि infrastructure clusters और behaviors को track करें।

## Analytical discipline

Confidence language का उपयोग करें:

- **Observed:** sensor/provider record सीधे relationship दिखाता है।
- **Strongly supported:** कई independent observations alternatives की तुलना में इसे support करते हैं।
- **Assessed:** stated assumptions और evidence पर आधारित inference।
- **Unknown:** missing visibility किसी conclusion को रोकती है।

हमेशा कम से कम दो hypotheses रखें: actor-operated infrastructure बनाम compromised/shared intermediary; one actor बनाम multi-tenant service; deliberate evasion बनाम legitimate privacy/CDN behavior। Uncertainty को explain करने की क्षमता सही detection का हिस्सा है।

## References

- [1] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRC actors compromise and maintain persistent access](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Enhanced visibility and hardening guidance for communications infrastructure](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
