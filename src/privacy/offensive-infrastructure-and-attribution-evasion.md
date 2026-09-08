# Offensive Infrastructure और Attribution Evasion

एक operator को किसी एक proxy से शायद ही कभी सार्थक anonymity मिलती है। वास्तविक campaigns एक **separation graph** बनाती हैं: operator किसी access node तक पहुंचता है, traversal nodes उस node को exit से छिपाते हैं, redirectors वास्तविक C2 की सुरक्षा करते हैं, और disposable names public edge की ओर संकेत करते हैं।

हर path के normalized pros/cons/deployment/detection view के लिए [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) का उपयोग करें। यह page adversarial infrastructure composition में अधिक गहराई से जाता है।
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
इसलिए target द्वारा देखा गया अंतिम address किसी path का evidence है, keyboard को नियंत्रित करने वाले व्यक्ति का proof नहीं। MITRE major components को Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) और Web Service (T1102) से map करता है।<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | कोई actor इसका उपयोग क्यों करता है | Durable exposure | Defender का best pivot |
|---|---|---|---|
| Rented VPS/cloud | तेज, predictable, routable और आसानी से rebuild होने वाला | tenant, billing, console, source-login और image history | account/control-plane events और repeated server fingerprint |
| Commercial VPN/Tor | बड़ा shared egress set; server administration की आवश्यकता नहीं | provider/guard visibility और end-to-end timing | destination behavior, endpoint evidence और flow correlation |
| Residential/mobile proxy | Consumer ASN और geographic plausibility | broker/customer records; proxyware या infected-host behavior | impossible travel, proxy protocols और session के अनुसार address churn |
| Compromised server/router/IoT | victim की reputation और jurisdiction उधार लेता है | implant, management flow और repeated upstream controller | device telemetry और ORB topology, केवल एक exit IP नहीं |
| CDN/redirector | public edge को back-end C2 से अलग करता है | TLS/HTTP grammar, certificate, routing और cloud-account artifacts | edge-to-origin correlation और request-shape clustering |
| Legitimate web service | अनुमत GitHub/cloud/social traffic में blend हो जाता है | API token, tenant/object identifiers और unusual process lineage | endpoint process तथा service/API semantics |
| Physical/cellular/satellite path | apparent physical origin बदलता है | RF, carrier, subscriber, device और location records | radio/physical और network evidence को combine करना |

## Operational relay box networks

एक **ORB network** intermediate service के रूप में उपयोग की जाने वाली managed proxy fleet है। Mandiant इन्हें leased servers वाले provisioned networks, compromised routers/IoT वाले non-provisioned networks और hybrids में विभाजित करता है। Mature topology में चार logical roles होते हैं:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory, credentials, health और routing policy maintain करता है।
2. **Access/relay node:** customers या operators को authenticate करता है; बदलते हुए mesh में stable entry होता है।
3. **Traversal nodes:** एक या अधिक leased या compromised systems opaque connections को relay करते हैं।
4. **Exit/staging node:** reconnaissance, exploitation या C2 targets के सामने final source address प्रस्तुत करता है।

Mesh country, ASN, latency या availability के आधार पर exits चुन सकता है और unhealthy nodes को rotate कर सकता है। Multiple threat groups एक ही network को rent कर सकते हैं। Mandiant ने देखा कि कुछ ORBs के साथ कोई IPv4 address केवल 31 दिनों तक associated रहा; इसलिए वह stale IPs की list block करने के बजाय **network को evolving actor-like entity मानने** की recommendation देता है।<sup>[[2]](#references)</sup>

### यह क्या हासिल करता है—और क्या leak करता है

- Target को ऐसा exit दिखाई देता है जो geographically nearby और apparently residential हो सकता है।
- Exit target और preceding hop को देखता है, operator को आवश्यक रूप से नहीं।
- Access service customer और route request को देखती है। Independently managed mesh customer को exits से अलग रख सकता है, लेकिन इससे एक powerful counterparty record बनता है।
- Repeated ports, handshake order, server banners, certificates, uptime windows और controller relationships fleet को expose कर सकते हैं, भले ही IPs rotate होते रहें।
- Compromised router में अक्सर endpoint telemetry नहीं होती, लेकिन उसके ISP के पास subscriber और flow data फिर भी होता है; seizure से implant/configuration artifacts expose हो जाते हैं।

{% hint style="info" %}
Authorized exercise के लिए organization-owned VMs या routers के साथ topology को reproduce करें और controller का attribution map सुरक्षित रखें। Open proxies या third-party devices को recruit न करें। [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) वही defender-visible hop structure बनाती है, बिना किसी intermediary को victim बनाए।
{% endhint %}

## Residential और mobile proxy networks

Residential proxy services sessions को consumer broadband addresses पर assign करती हैं; mobile proxies carrier NAT pools के माध्यम से egress करते हैं। Supply expressly enrolled appliances, consumer applications में bundled SDK/proxyware, resellers या malware से आ सकती है। ये origins equivalent नहीं हैं: informed consent की कमी privacy service को compromised infrastructure में बदल देती है।

Rotation modes detection को प्रभावित करते हैं:

- **per-request rotation** higher-layer identity को stable रखते हुए rapid IP और ASN/geography discontinuities पैदा करता है;
- **sticky sessions** किसी exit को minutes या hours तक बनाए रखते हैं, जिससे वह ordinary subscriber जैसा दिखाई देता है;
- **backconnect gateways** customer के सामने एक broker endpoint expose करते हैं और exits को internally चुनते हैं;
- **mobile pools** कई genuine subscribers को carrier NAT addresses के छोटे set के पीछे रखते हैं, जिससे IP block करना costly हो जाता है।

Defenders को IP को authenticated session, TLS/client fingerprint, HTTP ordering, device cookie और behavior के साथ correlate करना चाहिए। Supposedly local residential login के बाद किसी अन्य country का login हो, जबकि सभी higher-layer features identical रहें, तो यह केवल reputation से stronger signal है। इसके विपरीत, address sharing और mobile handoff legitimate churn पैदा कर सकते हैं, इसलिए residential/proxy classification को कभी verdict न मानें।

## Multi-hop proxy chains

MITRE external proxies और **multi-hop proxies (T1090.003)** के बीच distinction करता है। Important property hop count नहीं, बल्कि knowledge और administration का separation है।<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
यदि कोई एक ही पक्ष A और B संचालित करता है, तो साझा logs या flow timing से circuit को फिर से बनाया जा सकता है। एक ही endpoint/account से sequential commercial VPNs जोड़ने पर latency बढ़ सकती है, लेकिन common identity, payment और timing evidence बना रहता है। Tor independently selected relays और shared client design के ज़रिए इस समस्या को कम करता है, लेकिन low-latency interactive network ऐसे observer के विरुद्ध resistance का वादा नहीं कर सकता जो दोनों सिरों को measure करता हो।

सामान्य failures में DNS या IPv6 bypass, applications द्वारा अपने sockets खोलना, management traffic का relays तक सीधे पहुँचना, synchronized activity, reused SSH keys और identifying accounts में login करना शामिल हैं। सही verification एक failure test है: हर relay को बारी-बारी से रोकें और दिखाएँ कि workload किसी clear path पर fallback नहीं कर सकता।

## Redirector tiers और traffic shaping

एक public **redirector** उस traffic को स्वीकार करता है जो operation-specific grammar से match करता है और उसे protected team server तक forward करता है। बाकी सभी requests को reject किया जा सकता है या innocuous content serve किया जा सकता है।
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
कई tiers exposure को सीमित करते हैं: किसी public domain को burn करने से team server expose होना आवश्यक नहीं है। CDNs anycast capacity और एक reputable outer domain जोड़ते हैं, लेकिन CDN account और edge logs attribution points बन जाते हैं। TLS fingerprints, certificate histories, distinctive paths/header order, response sizes, redirect behavior और origin allowlists उन fronts को cluster कर सकते हैं जिन्हें अलग-अलग समझा जा रहा था।

Detection के लिए normalization से पहले reverse-proxy fields रिकॉर्ड करें, SNI/Host/authority की तुलना करें, दुर्लभ header combinations की जांच करें, response bodies और TLS fingerprints को cluster करें, और configuration overlap के लिए cloud/CDN audit logs खोजें। Authorized red teams के लिए किसी वास्तविक brand की नकल करने या किसी असंबंधित third party के पीछे credential collection रखने से बचें।

## Domain fronting and domainless fronting

Classic **domain fronting (T1090.004)** में TLS connection SNI में एक allowed front domain advertise करता है, जबकि encrypted HTTP `Host` या HTTP/2 `:authority` किसी अलग back-end domain का अनुरोध करता है। सहयोगी CDN inner value के आधार पर route करता है। TLS decryption के बिना network observer को front दिखाई देता है; CDN दोनों values और origin देखता है। Domainless variants में SNI खाली हो सकता है, जबकि कोई अन्य routing field destination चुनता है।<sup>[[4]](#references)</sup>

यह कोई जादुई impersonation नहीं है: यह तभी काम करता है जब intermediary जानबूझकर या गलती से इस mismatch की अनुमति दे और inner name को route करना जानता हो। Major providers ने cross-account fronting को प्रतिबंधित किया है। Encrypted ClientHello (ECH) on-path observer जो देख सकता है उसे बदलता है, लेकिन CDN, endpoint या application records को समाप्त नहीं करता।

Detection points में शामिल हैं:

- endpoint process ancestry और उस application के लिए अप्रत्याशित destination;
- जहां TLS inspection lawful और उपलब्ध हो, वहां SNI और HTTP authority के बीच mismatch;
- CDN logs में एक tenant/front का दूसरे authority/origin पर routing दिखना;
- सामान्यतः interactive service के लिए असामान्य long-lived या periodic sessions;
- बदलते front domains के बावजूद स्थिर encrypted flow sizes और cadence।

Safe lab किसी owned reverse proxy पर routing mismatch को simulate करता है; यह public CDN का दुरुपयोग नहीं करता।

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution किसी logical service को fixed infrastructure से अलग कर देता है:

- **DDNS:** authenticated client address बदलने के बाद एक stable name को update करता है।
- **DGA:** endpoint और controller दोनों time/key seed से candidate domain names derive करते हैं; operator उनमें से एक छोटे subset को register करता है।
- **Fast flux:** कोई name compromised/proxy addresses का तेजी से बदलता set लौटाता है, अक्सर low TTLs के साथ।
- **Double flux:** service addresses और authoritative name-server addresses दोनों rotate होते हैं, जिससे control layer भी छिप जाती है।

Fast flux adversarial रूप से उपयोग किया जाने वाला load-distribution pattern है, केवल “कई DNS answers” नहीं। अधिक मजबूत evidence में low TTL, high unique-address count, व्यापक ASN/geography dispersion, short node lifetime, दोहराया गया application behavior और suspicious registration history को साथ देखा जाता है। CDNs वैध रूप से इनमें से कई properties साझा करते हैं। MITRE DNS behavior को process और subsequent connections के साथ correlate करने की सलाह देता है।<sup>[[5]](#references)</sup>

DGA का detection lexical entropy, consonant/digit patterns, NXDOMAIN bursts, synchronized first-seen domains और process context से किया जा सकता है। Wordlist DGAs और generative models सरल entropy rules को विफल कर देते हैं, इसलिए fleet-wide temporal clustering और endpoint lineage अधिक महत्वपूर्ण हो जाते हैं।

## Compromised domains and domain shadowing

कोई actor registrar/DNS account hijack कर सकता है, किसी dangling subdomain पर takeover कर सकता है, या किसी अन्यथा reputable domain के नीचे records जोड़ सकता है। **Domain shadowing** legitimate apex को बनाए रखते हुए बड़ी संख्या में attacker-controlled subdomains को बदलते delivery या C2 hosts की ओर point करता है। यह domain की age और reputation का लाभ उठाता है और domain-wide blocking से बच सकता है।<sup>[[6]](#references)</sup>

Defenders को registrar और authoritative-DNS audit logs, MFA, registry/registrar locks, नई delegations/API tokens/name servers के लिए alerts, certificate-transparency monitoring और DNS द्वारा referenced cloud resources की inventory की आवश्यकता होती है। किसी subdomain की resolution और certificate history की जांच apex reputation से स्वतंत्र रूप से करें।

## Web services and dead-drop resolvers

एक **dead-drop resolver (T1102.001)** किसी legitimate post, profile, document, repository, cloud object या blockchain field के भीतर current C2 का encoded pointer रखता है। Malware public object को fetch करता है, domain/IP decode करता है और next stage से संपर्क करता है। Bidirectional variants service APIs के माध्यम से commands या files का आदान-प्रदान करते हैं।<sup>[[7]](#references)</sup>

यह resilience प्रदान करता है और static binary analysis से back-end C2 को छिपाता है। साथ ही यह stable object, tenant, repository, API और access-pattern identifiers बनाता है। Defenders को निम्नलिखित को जोड़ना चाहिए:

1. वह process जिसने service से संपर्क किया;
2. exact API path/object और response hash;
3. decoding या string-processing activity;
4. उसके तुरंत बाद हुआ नया outbound connection; और
5. fleet में अन्यत्र समान behavior।

सभी GitHub, cloud storage या social media को block करना आमतौर पर व्यवहार्य नहीं है। Service-aware egress policy और process-level correlation, domain-only blocking से बेहतर परिणाम देते हैं।

## Personas, accounts and procurement compartments

जब persona, recovery email, phone, payment, browser या admin IP compartments को जोड़ देते हैं, तो infrastructure anonymity विफल हो जाती है। State-linked operations ने उपयोग से काफी पहले social profiles, email identities और cloud accounts तैयार किए हैं; ATT&CK इसे Establish Accounts (T1585) के रूप में दर्ज करता है, जिसमें social, email और cloud sub-techniques शामिल हैं।<sup>[[8]](#references)</sup>

Defender या investigator निम्नलिखित से एक graph बनाता है:

- creation और first-login time, locale, time zone और working schedule;
- recovery fields, MFA devices, identity documents और payment instruments;
- browser/TLS fingerprints और source-network history;
- avatar reuse, image provenance, writing style और social-graph growth;
- shared domain registrant, name server, certificate, analytics ID या repository commit;
- management-plane actions जो public relay architecture को bypass करते हैं।

Authorized red team के लिए synthetic personas को exercise controller के सामने document किया जाना चाहिए, organization-owned recovery/payment channels का उपयोग करना चाहिए, वास्तविक असंबंधित लोगों का impersonation करने से बचना चाहिए और उनकी planned retirement होनी चाहिए। SOC blind रह सकता है; operation को unaccountable नहीं बनना चाहिए।

## Emerging compound patterns to threat-model

निम्नलिखित **defender-driven compositions** हैं; ये यह दावा नहीं हैं कि किसी named actor ने प्रत्येक exact design को deploy किया है। ये पहले से देखे गए primitives को जोड़ते हैं और उपयोगी purple-team hypotheses हैं।

### Asymmetric one-way tasking

Commands किसी public, broadcast या append-only source से आते हैं, जबकि results delay के बाद किसी असंबंधित channel से बाहर जाते हैं। Primitive के उदाहरणों में web-service one-way communication और dead drops शामिल हैं। यह separation किसी एक flow को bidirectional दिखने से रोकता है और simple request/response correlation को कठिन बनाता है।<sup>[[9]](#references)</sup>

**Detection:** object-level reads को preserve करें, फिर process state changes और बाद के outbound transfers को एक विस्तृत window में correlate करें। ऐसे rare process की तलाश करें जो उसी public object को पढ़ रहा हो, भले ही तुरंत कोई reply न आए।

### Multi-stage channel promotion

एक quiet first stage inventory करता है और केवल selected systems को किसी असंबंधित second-stage channel पर promote करता है। Second endpoint, protocol और process का first stage के साथ कोई infrastructure साझा न हो सकता है। यह capable infrastructure का exposure सीमित करता है और ATT&CK T1104 के रूप में explicitly modeled है।<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` को जोड़ें; first domain को block करने के बाद incident बंद न करें।

### Cross-protocol relay translation

अलग-अलग hops packets को transparently forward करने के बजाय HTTPS, QUIC, WebSocket, DNS, SSH या message-queue API का translation करते हैं। Translation एक single end-to-end protocol fingerprint को हटा देता है, लेकिन distinctive timing, buffering और semantic conversion वाले gateways बनाता है। Protocol tunneling (T1572) को proxies और service impersonation के साथ combine किया जा सकता है।<sup>[[11]](#references)</sup>

**Detection:** ऐसे gateway hosts की तलाश करें जो एक protocol receive करके दूसरा initiate करते हैं और जिनका byte/time behavior tightly coupled है; endpoint intent की तुलना वास्तव में carried protocol से करें।

### Passive activation on edge devices

Beaconing के बजाय implant पहले से router/VPN तक पहुंचने वाले traffic को monitor करता है और केवल magic value, source-port pattern या authenticated token पर activate होता है। Normal traffic वास्तविक service तक जाता रहता है। ATT&CK इसे Traffic Signaling (T1205) कहता है, जिसके documented network-device और APT examples हैं।<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, authorized hunt के दौरान raw packet capture, unexpected socket filters और differential service behavior की जांच करें। Periodic beacon का न होना यह सिद्ध नहीं करता कि edge device clean है।

### Serverless and ephemeral origin rotation

एक front stable logical identity बनाए रखता है, जबकि short-lived functions/containers कई regions/accounts में individual stages संभालते हैं। इससे disk lifetime और fixed origin IPs कम होते हैं, लेकिन control-plane creation, image/layer, role, secret, request ID और billing telemetry durable graph बन जाते हैं।

**Detection:** cloud audit और invocation logs को workload के बाहर retain करें; deployment templates, roles, environment keys और front-to-origin relationships को cluster करें।

### Privacy-layer diversity

कोई operation जानबूझकर एक homogeneous chain से बच सकता है: उदाहरण के लिए, एक channel leased relay का उपयोग करता है, tasking public object का, exit owned lab cellular link से आता है और administration अलग organization network से होती है। इससे एक provider को compromise करने का लाभ घटता है, लेकिन cross-layer timing और operational-error risk बढ़ता है।

**Detection:** identity, DNS, SaaS, network और cloud sensors पर campaign timelines बनाएं। Identical indicators के बजाय synchronized state transitions खोजें।

### Decentralized or transparency-log dead drops

कोई actor किसी durable public append-only system, content-addressed store या transparency-like feed में छोटा encrypted pointer रख सकता है। Public object resilient होता है, लेकिन उसका exact index/content hash और client polling behavior stable identifiers बन जाते हैं।

**Detection:** full API/object identifiers और response hashes रिकॉर्ड करें; decoding या नए connections के बाद immutable objects को poll करने वाले nonstandard processes पर alert करें।

### Delayed store-and-forward operations

Interactive C2 मजबूत timing correlation बनाता है। Store-and-forward design encrypted jobs को batch करता है और results को मिनटों या घंटों बाद किसी अलग queue या physical transfer के माध्यम से लौटाता है। यह कमजोर end-to-end timing के बदले responsiveness का त्याग करता है।

**Detection:** correlation windows को लंबा करें, periodic queue access को model करें और endpoint staging की जांच करें। Batching signal को packet timing से scheduled process/file behavior में स्थानांतरित करता है; इसे समाप्त नहीं करता।

## Design review: think in observers

हर path के लिए deployment से पहले और collection के बाद यह table भरें:

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

यदि कोई ordinary provider प्रत्येक column भर सकता है, तो architecture target से concealment प्रदान करता है, लेकिन robust separation नहीं। यदि कोई internal controller activity को engagement से map back नहीं कर सकता, तो यह professional red teaming के लिए उपयुक्त नहीं है।

## References

- [1] [MITRE ATT&CK — Infrastructure प्राप्त करना (T1583), Infrastructure को compromise करना (T1584), और Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors ORB networks का उपयोग करते हैं](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastructure को compromise करना: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Accounts स्थापित करना (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
