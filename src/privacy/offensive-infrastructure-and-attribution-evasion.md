# Offensive Infrastructure और Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

किसी एक proxy से operator को शायद ही कभी सार्थक anonymity मिलती है। असली campaigns एक **separation graph** बनाते हैं: operator एक access node तक पहुँचता है, traversal nodes उस node को exit से छिपाते हैं, redirectors असली C2 की सुरक्षा करते हैं, और disposable names public edge की ओर इशारा करते हैं।

हर path के normalized pros/cons/deployment/detection विवरण के लिए [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) का उपयोग करें। यह पेज adversarial infrastructure composition को अधिक विस्तार से समझाता है।

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

लक्ष्य को दिखाई देने वाला आखिरी पता किसी पथ का सबूत है, इसलिए यह इस बात का प्रमाण नहीं कि keyboard किसके नियंत्रण में था। MITRE मुख्य घटकों को Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) और Web Service (T1102) से जोड़ता है।<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | कोई actor इसे क्यों इस्तेमाल करता है | लंबे समय तक बने रहने वाले निशान | Defender का सबसे उपयोगी pivot |
|---|---|---|---|
| किराए का VPS/cloud | तेज़, पूर्वानुमेय, routable और दोबारा बनाना आसान | tenant, billing, console, source-login और image history | account/control-plane घटनाएँ और बार-बार दिखने वाला server fingerprint |
| Commercial VPN/Tor | बड़ा shared egress set; server administration की ज़रूरत नहीं | provider/guard की दृश्यता और end-to-end timing | destination का व्यवहार, endpoint के सबूत और flow correlation |
| Residential/mobile proxy | Consumer ASN और भौगोलिक विश्वसनीयता | broker/customer रिकॉर्ड; proxyware या संक्रमित-host का व्यवहार | असंभव यात्रा, proxy protocols और session के अनुसार address churn |
| Compromised server/router/IoT | पीड़ित की प्रतिष्ठा और jurisdiction का लाभ उठाता है | implant, management flow और बार-बार दिखने वाला upstream controller | device telemetry और ORB topology, न कि केवल एक exit IP |
| CDN/redirector | सार्वजनिक edge को back-end C2 से अलग करता है | TLS/HTTP grammar, certificate, routing और cloud-account artifacts | edge-to-origin correlation और request-shape clustering |
| वैध web service | अनुमत GitHub/cloud/social traffic में घुल-मिल जाता है | API token, tenant/object identifiers और असामान्य process lineage | endpoint process के साथ service/API semantics |
| भौतिक/cellular/satellite path | दिखाई देने वाला भौतिक origin बदलता है | RF, carrier, subscriber, device और location records | radio/physical और network के सबूतों का संयोजन |

## Operational relay box networks

**ORB network** एक प्रबंधित proxy fleet है, जिसे मध्यवर्ती सेवा के रूप में इस्तेमाल किया जाता है। Mandiant इन्हें leased servers वाले provisioned networks, compromised routers/IoT वाले non-provisioned networks और hybrids में बाँटता है। एक परिपक्व topology में चार तार्किक भूमिकाएँ होती हैं:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory, credentials, health और routing policy का प्रबंधन करता है।
2. **Access/relay node:** ग्राहकों या operators को authenticate करता है; यह बदलते mesh में स्थिर प्रवेश-बिंदु है।
3. **Traversal nodes:** एक या अधिक leased या compromised systems, opaque connections को relay करते हैं।
4. **Exit/staging node:** reconnaissance, exploitation या C2 targets को अंतिम source address दिखाता है।

Mesh देश, ASN, latency या availability के आधार पर exits चुन सकता है और खराब node को बदल सकता है। कई threat groups एक ही network किराए पर ले सकते हैं। Mandiant ने देखा कि कुछ ORBs से जुड़ा IPv4 address केवल 31 दिनों तक बना रहा; इसलिए वह पुराने IPs की सूची को block करने के बजाय **network को बदलती हुई actor-जैसी इकाई** मानने की सलाह देता है।<sup>[[2]](#references)</sup>

### इससे क्या मिलता है—और क्या leak होता है

- लक्ष्य को ऐसा exit दिखता है जो भौगोलिक रूप से पास और देखने में residential हो सकता है।
- Exit को लक्ष्य और उससे पहले वाला hop दिखता है, ज़रूरी नहीं कि operator भी दिखे।
- Access service को ग्राहक और route request दिखती है। अलग से प्रबंधित mesh ग्राहक को exits से अलग रख सकता है, लेकिन इससे counterparty का एक अहम रिकॉर्ड बनता है।
- बार-बार दिखने वाले ports, handshake order, server banners, certificates, uptime windows और controller संबंध fleet को उजागर कर सकते हैं, भले ही IPs बदलते रहें।
- Compromised router में अक्सर endpoint telemetry नहीं होती, लेकिन उसके ISP के पास subscriber और flow data फिर भी होता है; जब्त करने पर implant/configuration artifacts सामने आते हैं।

{% hint style="info" %}
किसी अधिकृत exercise के लिए, संगठन के स्वामित्व वाले VMs या routers से यही topology बनाएँ और controller का attribution map सुरक्षित रखें। Open proxies या तीसरे पक्ष के devices का इस्तेमाल न करें। [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) वही hop structure बनाती है जो defender को दिखाई देगा, बिना किसी intermediary को नुकसान पहुँचाए।
{% endhint %}

## Residential and mobile proxy networks

Residential proxy services sessions को consumer broadband addresses देती हैं; mobile proxies carrier NAT pools के ज़रिए egress करती हैं। इनकी supply स्पष्ट सहमति से नामांकित appliances, consumer applications में शामिल SDK/proxyware, resellers या malware से आ सकती है। ये स्रोत एक जैसे नहीं हैं: सूचित सहमति के अभाव में privacy service, compromised infrastructure बन जाती है।

Rotation modes detection को प्रभावित करते हैं:

- **per-request rotation** से IP और ASN/geography में तेज़ बदलाव होते हैं, जबकि higher-layer identity स्थिर रहती है;
- **sticky sessions** किसी exit को मिनटों या घंटों तक बनाए रखते हैं, जो सामान्य subscriber जैसा दिखता है;
- **backconnect gateways** ग्राहक को एक broker endpoint दिखाते हैं और exits अंदरूनी तौर पर चुनते हैं;
- **mobile pools** कई वास्तविक subscribers को carrier NAT addresses के छोटे समूह के पीछे रखते हैं, जिससे IP block करना महँगा पड़ता है।

Defenders को IP का मिलान authenticated session, TLS/client fingerprint, HTTP ordering, device cookie और व्यवहार से करना चाहिए। अगर कथित तौर पर स्थानीय residential login के बाद, सभी higher-layer features समान रहते हुए, दूसरे देश का login दिखे, तो यह अकेली reputation से अधिक मजबूत संकेत है। दूसरी ओर, address sharing और mobile handoff से सामान्य बदलाव भी आते हैं, इसलिए residential/proxy classification को कभी अंतिम निष्कर्ष न मानें।

### Proxyware control planes और reseller overlap

Residential pool को exits की एक सपाट सूची न मानें। IPIDEA ecosystem के विश्लेषण से दोबारा इस्तेमाल किया जा सकने वाला **two-tier control plane** सामने आया: embedded SDK पहले device/enrollment metadata को Tier One domain पर भेजता है और scheduling के साथ Tier Two `connect`/`proxy` IP:port pairs प्राप्त करता है। Node समय-समय पर encoded task के लिए Tier Two connect port पर poll करता है, जोड़ी वाले proxy port से दूसरा connection खोलता है और दिए गए bytes को अनुरोधित destination तक relay करता है। नाममात्र के अलग SDKs और proxy brands के discovery domains अलग थे, लेकिन साझा ownership और reseller संबंधों के कारण वे shared Tier Two infrastructure और overlapping exit pools पर आकर मिलते थे।<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

इससे residential IP block की तुलना में अधिक टिकाऊ hunting pivots मिलते हैं:<sup>[[13]](#references)</sup>

- कोई अप्रत्याशित utility, VPN, game या embedded-device process एक स्थिर device ID/customer key भेजता है और बदलती हुई server list प्राप्त करता है;
- endpoint किसी असामान्य port पर direct IP को poll करता है, फिर नया destination socket खोलने से ठीक पहले उसी address के किसी अन्य port से connect करता है;
- कई दिखने में अलग brands के Tier Two addresses, protocol grammar, SDK code या exit-node overlap साझा होते हैं;
- अलग-अलग Tier One domains से संपर्क करने वाले अलग-अलग applications को एक ही Tier Two pool से addresses मिलते हैं।

यह overlap attribution को भी सीमित करता है: किसी vendor के advertised pool में IP दिखने से यह साबित नहीं होता कि संबंधित समय पर किस reseller, customer या threat actor ने उसका उपयोग किया। Flow timestamps, process lineage, Tier One response bodies और Tier Two task identifiers सुरक्षित रखें।<sup>[[13]](#references)</sup> किसी authorized exercise में, इस hierarchy का अनुकरण केवल संगठन के स्वामित्व वाले endpoints पर करें; consumer devices या third-party proxyware को कभी enroll न करें।

## Multi-hop proxy chains

MITRE external proxies और **multi-hop proxies (T1090.003)** में अंतर करता है। महत्वपूर्ण बात hops की संख्या नहीं, बल्कि knowledge और administration का अलग-अलग होना है।<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

यदि एक ही पक्ष A और B को संचालित करता है, तो साझा logs या flow timing से circuit का पुनर्निर्माण किया जा सकता है। एक ही endpoint/account से क्रमिक commercial VPNs जोड़ने से latency बढ़ सकती है, लेकिन साझा पहचान, भुगतान और timing के सबूत बने रहते हैं। Tor स्वतंत्र रूप से चुने गए relays और साझा client design से इस समस्या को कम करता है, लेकिन कम-latency वाला interactive network ऐसे observer के विरुद्ध प्रतिरोध का वादा नहीं कर सकता जो दोनों सिरों को मापता हो।

आम विफलताओं में DNS या IPv6 bypass, applications का अपने sockets खोलना, management traffic का सीधे relays तक पहुँचना, synchronized activity, दोबारा इस्तेमाल की गई SSH keys और पहचान उजागर करने वाले accounts में login करना शामिल हैं। सही verification एक failure test है: हर relay को बारी-बारी से रोकें और दिखाएँ कि workload किसी clear path पर fallback नहीं कर सकता।

### Tunnel का विफल होना और upstream leakage

Relay architecture अक्सर विफल होने पर सबसे अधिक attributable होती है। Unit 42 ने एक multi-tier espionage path का दस्तावेज़ीकरण किया जिसमें victim-facing VPSs, relay VPSs, residential proxies, Tor और अन्य proxy services इस्तेमाल की गई थीं; जब tunnel छूट गया या टूट गया, तो छिपा हुआ upstream infrastructure सीधे relay और victim-facing systems से जुड़ गया। इसी जाँच में upstream infrastructure पर थोड़े समय के लिए उजागर हुए एक X.509 certificate का इस्तेमाल cross-tier pivot के रूप में भी किया गया।<sup>[[14]](#references)</sup>

**data plane** (`victim <-> exit`) को **control plane** (`operator/upstream -> relay administration`) से अलग रखें। हर अपने नियंत्रण वाले tier पर ingress और authentication logs, certificate histories और कम अवधि वाले असफल connections सुरक्षित रखें—सिर्फ सफल C2 sessions ही नहीं। ऐसा source जो केवल relay outages के दौरान दिखाई देता है या सीधे कई victim-facing nodes का प्रशासन करता है, सामान्य exit की तुलना में upstream candidate होने की अधिक संभावना रखता है; फिर भी उसका ASN/geolocation एक परिकल्पना है, operator की पहचान का प्रमाण नहीं।

एक authorized lab में workload को fail closed होना चाहिए। Linux network namespace में अलग रखे गए workload के लिए पहला route tunnel से होकर जाना चाहिए; tunnel हटाने के बाद request और route lookup—दोनों विफल होने चाहिए, न कि physical uplink को चुनना चाहिए:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS और IPv6 के लिए तथा हर relay boundary पर परीक्षण दोहराएँ। अगर कोई probe सफल होता है, तो policy routing या firewall को ठीक करने से पहले वास्तविक interface/source address दर्ज करें; यही वह attribution leak है जिसे कोई investigator देखेगा।

## Redirector tiers and traffic shaping

एक सार्वजनिक **redirector** उस traffic को स्वीकार करता है जो operation-specific grammar से मेल खाता है और उसे protected team server तक forward करता है। बाकी सभी traffic को अस्वीकार किया जा सकता है या उसे अहानिकर content दिखाया जा सकता है।

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

कई स्तर exposure को सीमित करते हैं: किसी public domain का जल जाना ज़रूरी नहीं कि team server को भी उजागर करे। CDN anycast क्षमता और एक प्रतिष्ठित outer domain जोड़ते हैं, लेकिन CDN account और edge logs attribution के बिंदु बन जाते हैं। TLS fingerprints, certificate histories, विशिष्ट paths/header order, response sizes, redirect behavior और origin allowlists कथित तौर पर असंबंधित fronts को आपस में जोड़ सकते हैं।

Detection के लिए, normalization से पहले reverse-proxy fields रिकॉर्ड करें, SNI/Host/authority की तुलना करें, दुर्लभ header combinations की जाँच करें, response bodies और TLS fingerprints को cluster करें, और configuration overlap के लिए cloud/CDN audit logs खोजें। अधिकृत red teams को किसी असली brand की नकल करने या किसी असंबंधित third party के पीछे credential collection रखने से बचना चाहिए।

## Domain fronting and domainless fronting

क्लासिक **domain fronting (T1090.004)** में, TLS connection SNI में एक अनुमत front domain दिखाता है, जबकि encrypted HTTP `Host` या HTTP/2 `:authority` किसी अलग back-end domain का अनुरोध करता है। सहयोगी CDN अंदरूनी value के आधार पर routing करता है। TLS decryption के बिना network observer को front दिखता है; CDN दोनों values और origin देखता है। Domainless variants में SNI खाली हो सकता है, जबकि कोई अन्य routing field destination चुनता है।<sup>[[4]](#references)</sup>

यह कोई जादुई impersonation नहीं है: यह तभी काम करता है, जब intermediary जानबूझकर या अनजाने में इस mismatch की अनुमति दे और अंदरूनी नाम के आधार पर routing करना जानता हो। प्रमुख providers ने cross-account fronting पर पाबंदियाँ लगाई हैं। Encrypted ClientHello (ECH) से on-path observer क्या देख सकता है, यह बदलता है, लेकिन CDN, endpoint या application के records मिटते नहीं हैं।

Detection के बिंदुओं में शामिल हैं:

- endpoint process ancestry और ऐसा destination जिसकी उस application से अपेक्षा न हो;
- जहाँ TLS inspection वैध और उपलब्ध हो, वहाँ SNI और HTTP authority के बीच mismatch;
- CDN logs में एक tenant/front का किसी दूसरी authority/origin पर routing करना;
- सामान्यतः interactive service से असामान्य रूप से लंबे समय तक या नियमित अंतराल पर चलने वाले sessions;
- बदलते front domains के बावजूद encrypted flows के आकार और cadence का स्थिर रहना।

सुरक्षित lab में अपने नियंत्रण वाले reverse proxy पर routing mismatch का simulation किया जाता है; किसी public CDN का दुरुपयोग नहीं।

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution किसी logical service को fixed infrastructure से अलग करता है:

- **DDNS:** address बदलने के बाद authenticated client एक स्थिर नाम update करता है।
- **DGA:** endpoint और controller, दोनों time/key seed से संभावित domain names निकालते हैं; operator उनमें से कुछ को register करता है।
- **Fast flux:** कोई नाम तेजी से बदलते compromised/proxy addresses का समूह लौटाता है, अक्सर कम TTLs के साथ।
- **Double flux:** service addresses और authoritative name-server addresses, दोनों बदलते रहते हैं, जिससे control layer भी छिप जाती है।

Fast flux एक load-distribution pattern है जिसका adversarial रूप से उपयोग होता है; यह केवल “कई DNS answers” नहीं है। अधिक मज़बूत साक्ष्य में कम TTL, unique addresses की बड़ी संख्या, ASN/geography का व्यापक फैलाव, nodes का कम जीवनकाल, बार-बार एक जैसा application behavior और संदिग्ध registration history शामिल हैं। CDNs में इनमें से कई विशेषताएँ वैध रूप से भी होती हैं। MITRE, DNS behavior को process और उसके बाद होने वाले connections से जोड़कर देखने की सिफारिश करता है।<sup>[[5]](#references)</sup>

DGA का पता lexical entropy, consonant/digit patterns, NXDOMAIN bursts, synchronized first-seen domains और process context के ज़रिए लगाया जा सकता है। Wordlist DGAs और generative models, सरल entropy rules को निष्प्रभावी कर देते हैं; इसलिए पूरे fleet में समय-आधारित clustering और endpoint lineage अधिक महत्वपूर्ण हैं।

## Compromised domains and domain shadowing

कोई actor registrar/DNS account hijack कर सकता है, किसी dangling subdomain पर कब्ज़ा कर सकता है, या किसी अन्यथा प्रतिष्ठित domain के तहत records जोड़ सकता है। **Domain shadowing** वैध apex को बरकरार रखते हुए बड़ी संख्या में attacker-controlled subdomains को बदलते delivery या C2 hosts पर point करता है। इससे domain की उम्र और प्रतिष्ठा का लाभ मिलता है और domain-wide blocking से बचा जा सकता है।<sup>[[6]](#references)</sup>

Defenders को registrar और authoritative-DNS audit logs, MFA, registry/registrar locks, नई delegations/API tokens/name servers के लिए alerts, certificate-transparency monitoring और DNS में संदर्भित cloud resources की inventory चाहिए। किसी subdomain के resolution और certificate history की जाँच apex की प्रतिष्ठा से अलग करें।

## Web services and dead-drop resolvers

**Dead-drop resolver (T1102.001)** किसी वैध post, profile, document, repository, cloud object या blockchain field में मौजूदा C2 का encoded pointer रखता है। Malware उस public object को fetch करता है, domain/IP decode करता है और अगले stage से संपर्क करता है। Bidirectional variants service APIs के ज़रिए commands या files का आदान-प्रदान करते हैं।<sup>[[7]](#references)</sup>

GitHub-विशिष्ट resolver का एक variant, authenticated repository channel विफल होने पर ही Issues Search API का उपयोग करता है। Client मौजूदा तारीख, repository और issue type से मेल खाने वाले issues खोजता है, हर issue के comments URL पर जाता है, और `<!--` तथा `-->` markers के बीच से ciphertext निकालता है। हर host के लिए अलग, तारीख से निकली decryption के बाद, `Owner`, `LicRepo` और `LicToken` जैसे fields primary repository owner, path और token की जगह ले लेते हैं। इससे operator client बदले बिना credentials और endpoints बदल सकता है; issue comment resolver है, जबकि repository files tasking channel बने रहते हैं।<sup>[[15]](#references)</sup>

इससे resilience मिलती है और static binary analysis से back-end C2 छिपता है। साथ ही, इससे स्थिर object, tenant, repository, API और access-pattern identifiers बनते हैं। Defenders को ये चीज़ें जोड़कर देखनी चाहिए:

1. service से संपर्क करने वाला process;
2. सटीक API path/object और response hash;
3. decoding या string-processing activity;
4. उसके कुछ ही समय बाद होने वाला नया outbound connection; और
5. fleet में अन्य जगहों पर दिखने वाला समान behavior।

सभी GitHub, cloud storage या social media को block करना शायद ही कभी व्यावहारिक होता है। Service-aware egress policy और process-level correlation, केवल domain को block करने से बेहतर हैं।

## Personas, accounts and procurement compartments

जब कोई persona, recovery email, phone, payment, browser या admin IP अलग-अलग compartments को जोड़ता है, तो infrastructure anonymity विफल हो जाती है। State-linked operations ने इस्तेमाल से बहुत पहले social profiles, email identities और cloud accounts तैयार किए हैं; ATT&CK इसे Establish Accounts (T1585) के रूप में दर्ज करता है, जिसमें social, email और cloud sub-techniques शामिल हैं।<sup>[[8]](#references)</sup>

Defender या investigator इनसे एक graph बनाता है:

- creation और first-login का समय, locale, time zone और काम का schedule;
- recovery fields, MFA devices, identity documents और payment instruments;
- browser/TLS fingerprints और source-network history;
- avatar का दोबारा उपयोग, image provenance, लिखने की शैली और social-graph का विकास;
- साझा domain registrant, name server, certificate, analytics ID या repository commit;
- management-plane actions जो public relay architecture को bypass करते हैं।

अधिकृत red team के लिए, synthetic personas को exercise controller के सामने दर्ज किया जाना चाहिए, संगठन के स्वामित्व वाले recovery/payment channels का उपयोग करना चाहिए, वास्तविक असंबंधित लोगों की नकल करने से बचना चाहिए और उन्हें retire करने की योजना होनी चाहिए। SOC को जानकारी न हो सकती है; लेकिन operation जवाबदेही से बाहर नहीं होना चाहिए।

## Emerging compound patterns to threat-model

निम्नलिखित **defender-driven compositions** हैं, न कि यह दावा कि किसी नामित actor ने इनमें से हर सटीक design तैनात किया है। ये पहले से देखे गए primitives को जोड़ते हैं और purple-team hypotheses के रूप में उपयोगी हैं।

### Asymmetric one-way tasking

Commands किसी public, broadcast या append-only source से आते हैं, जबकि results कुछ देर बाद किसी असंबंधित channel से बाहर जाते हैं। इस primitive के उदाहरणों में web-service one-way communication और dead drops शामिल हैं। अलग-अलग channels का उपयोग एक flow को bidirectional दिखने से रोकता है और सरल request/response correlation को कठिन बनाता है।<sup>[[9]](#references)</sup>

**Detection:** object-level reads सुरक्षित रखें, फिर process state changes और बाद के outbound transfers को एक बड़ी time window में correlate करें। ऐसे दुर्लभ process की तलाश करें जो उसी public object को पढ़ता हो, भले ही उसके तुरंत बाद कोई reply न आए।

### Multi-stage channel promotion

एक शांत first stage inventory करता है और केवल चुने हुए systems को किसी असंबंधित second-stage channel पर भेजता है। दूसरा endpoint, protocol और process, पहले stage के infrastructure से बिल्कुल असंबंधित हो सकते हैं। इससे सक्षम infrastructure का exposure सीमित होता है और इसे ATT&CK T1104 में स्पष्ट रूप से model किया गया है।<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` को जोड़कर देखें; पहले domain को block करने के बाद incident बंद न करें।

### Cross-protocol relay translation

अलग-अलग hops packets को पारदर्शी रूप से forward करने के बजाय HTTPS, QUIC, WebSocket, DNS, SSH या message-queue API के बीच translation करते हैं। Translation से एकल end-to-end protocol fingerprint हट जाता है, लेकिन ऐसे gateways बनते हैं जिनकी timing, buffering और semantic conversion विशिष्ट होती है। Protocol tunneling (T1572) को proxies और service impersonation के साथ जोड़ा जा सकता है।<sup>[[11]](#references)</sup>

**Detection:** ऐसे gateway hosts खोजें जो एक protocol प्राप्त करके दूसरा शुरू करते हैं और जिनके byte/time behavior में कड़ा संबंध हो; endpoint के उद्देश्य की तुलना वास्तव में ले जाए जा रहे protocol से करें।

### Passive activation on edge devices

Beacon भेजने के बजाय, कोई implant router/VPN तक पहले से पहुँच रहे traffic पर नज़र रखता है और केवल किसी magic value, source-port pattern या authenticated token मिलने पर सक्रिय होता है। सामान्य traffic वास्तविक service तक पहुँचता रहता है। ATT&CK इसे Traffic Signaling (T1205) कहता है और इसके documented network-device तथा APT examples मौजूद हैं।<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, अधिकृत hunt के दौरान raw packet capture, अप्रत्याशित socket filters और service behavior में अंतर की जाँच करें। नियमित beacon का न होना इस बात का प्रमाण नहीं कि edge device साफ़ है।

### Serverless and ephemeral origin rotation

कई regions/accounts में छोटी अवधि वाले functions/containers अलग-अलग stages संभालते हैं, जबकि front की logical identity स्थिर रहती है। इससे disk पर रहने की अवधि और fixed origin IPs कम होते हैं, लेकिन control-plane creation, image/layer, role, secret, request ID और billing telemetry स्थायी graph बन जाते हैं।

**Detection:** workload के बाहर cloud audit और invocation logs रखें; deployment templates, roles, environment keys और front-to-origin relationships को cluster करें।

### Privacy-layer diversity

कोई operation जानबूझकर एक जैसी chain से बच सकता है: उदाहरण के लिए, एक channel leased relay का उपयोग करे, tasking public object से हो, exit अपने नियंत्रण वाले lab cellular link से आए और administration किसी अलग organization network से हो। इससे किसी एक provider के compromise का महत्व कम होता है, लेकिन अलग-अलग layers के बीच timing और operational errors का जोखिम बढ़ता है।

**Detection:** identity, DNS, SaaS, network और cloud sensors से campaign timelines बनाएँ। एक जैसे indicators के बजाय synchronized state transitions खोजें।

### Decentralized or transparency-log dead drops

कोई actor किसी भी टिकाऊ public append-only system, content-addressed store या transparency-जैसी feed में छोटा encrypted pointer रख सकता है। Public object resilient होता है, लेकिन उसका सटीक index/content hash और client का polling behavior स्थिर identifiers बन जाते हैं।

**Detection:** पूरे API/object identifiers और response hashes रिकॉर्ड करें; ऐसे nonstandard processes के लिए alerts बनाएँ जो immutable objects को poll करने के बाद decoding या नए connections करते हैं।

### Delayed store-and-forward operations

Interactive C2 से timing का मज़बूत correlation बनता है। Store-and-forward design encrypted jobs को batch करता है और कुछ मिनटों या घंटों बाद अलग queue या physical transfer के ज़रिए results लौटाता है। इससे responsiveness घटती है, लेकिन end-to-end timing का correlation कमज़ोर पड़ता है।

**Detection:** correlation windows बढ़ाएँ, periodic queue access को model करें और endpoint staging की जाँच करें। Batching signal को packet timing से scheduled process/file behavior में ले जाती है; इसे मिटाती नहीं।

## Design review: think in observers

हर path के लिए, deployment से पहले और collection के बाद यह table भरें:

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

यदि कोई एक सामान्य provider हर column भर सकता है, तो architecture target से concealment तो देता है, लेकिन मज़बूत separation नहीं। यदि कोई internal controller activity को किसी engagement से जोड़ नहीं सकता, तो यह professional red teaming के लिए अनुपयुक्त है।

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
- [13] [Google Threat Intelligence Group — Disrupting the World's Largest Residential Proxy Network](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: Uncovering Global Espionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign Targets Iraqi Infrastructure](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
