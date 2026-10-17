# Offensive Infrastructure and Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

एक operator को केवल एक proxy से शायद ही कभी सार्थक anonymity मिलती है। वास्तविक campaigns एक **separation graph** बनाते हैं: operator एक access node तक पहुँचता है, traversal nodes उस node को exit से छिपाते हैं, redirectors असली C2 की सुरक्षा करते हैं, और disposable names public edge की ओर इंगित करते हैं।

हर path के सामान्यीकृत pros/cons/deployment/detection विवरण के लिए [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) देखें। यह पेज adversarial infrastructure composition पर अधिक विस्तार से बताता है।

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

लक्ष्य द्वारा देखा गया आखिरी पता इसलिए किसी पथ का सबूत है, न कि इस बात का प्रमाण कि कीबोर्ड किसके नियंत्रण में था। MITRE प्रमुख घटकों को Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) और Web Service (T1102) से जोड़ता है।<sup>[[1]](#references)</sup>

## इंफ्रास्ट्रक्चर वर्ग

| वर्ग | कोई actor इसका इस्तेमाल क्यों करता है | लंबे समय तक रहने वाले जोखिम के संकेत | डिफेंडर का सबसे अच्छा pivot |
|---|---|---|---|
| किराए का VPS/cloud | तेज़, भरोसेमंद, routable और दोबारा बनाने में आसान | tenant, billing, console, source-login और image history | account/control-plane घटनाएँ और बार-बार दिखने वाला server fingerprint |
| Commercial VPN/Tor | बड़ा shared egress सेट; server administration की ज़रूरत नहीं | provider/guard की दृश्यता और end-to-end timing | destination का व्यवहार, endpoint के सबूत और flow correlation |
| Residential/mobile proxy | Consumer ASN और भौगोलिक विश्वसनीयता | broker/customer records; proxyware या संक्रमित-host का व्यवहार | असंभव यात्रा, proxy protocols और session के अनुसार address में बदलाव |
| Compromised server/router/IoT | victim की प्रतिष्ठा और jurisdiction का फ़ायदा उठाता है | implant, management flow और बार-बार दिखने वाला upstream controller | device telemetry और ORB topology, न कि सिर्फ़ एक exit IP |
| CDN/redirector | सार्वजनिक edge को back-end C2 से अलग करता है | TLS/HTTP grammar, certificate, routing और cloud-account artifacts | edge-to-origin correlation और request-shape clustering |
| वैध web service | अनुमति-प्राप्त GitHub/cloud/social traffic में घुल-मिल जाता है | API token, tenant/object identifiers और असामान्य process lineage | endpoint process के साथ service/API semantics |
| भौतिक/cellular/satellite path | दिखने वाला भौतिक origin बदलता है | RF, carrier, subscriber, device और location records | radio/physical और network के सबूतों को मिलाकर देखना |

## Operational relay box networks

**ORB network** एक managed proxy fleet है, जिसका इस्तेमाल बीच की सेवा के रूप में किया जाता है। Mandiant इन्हें leased servers वाले provisioned networks, compromised routers/IoT वाले non-provisioned networks और hybrids में बाँटता है। एक परिपक्व topology में चार तार्किक भूमिकाएँ होती हैं:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory, credentials, health और routing policy बनाए रखता है।
2. **Access/relay node:** customers या operators को authenticate करता है; बदलते mesh में यही स्थिर entry point होता है।
3. **Traversal nodes:** एक या अधिक leased या compromised systems, opaque connections को relay करते हैं।
4. **Exit/staging node:** reconnaissance, exploitation या C2 targets के सामने अंतिम source address दिखाता है।

Mesh देश, ASN, latency या उपलब्धता के आधार पर exits चुन सकता है और खराब nodes को बदल सकता है। कई threat groups एक ही network किराए पर ले सकते हैं। Mandiant ने देखा कि कुछ ORBs से जुड़ा IPv4 पता केवल 31 दिनों तक बना रहा; इसलिए वह पुरानी IPs की सूची को block करने के बजाय **network को समय के साथ बदलती actor-जैसी इकाई** मानने की सलाह देता है।<sup>[[2]](#references)</sup>

### इससे क्या मिलता है—और यह क्या leak करता है

- लक्ष्य को ऐसा exit दिखता है जो भौगोलिक रूप से पास और देखने में residential हो सकता है।
- Exit को लक्ष्य और उससे पहले वाला hop दिखता है, ज़रूरी नहीं कि operator भी दिखे।
- Access service को customer और route request दिखते हैं। अलग से managed mesh customer को exits से अलग रख सकता है, लेकिन इससे counterparty का एक अहम रिकॉर्ड बनता है।
- बार-बार इस्तेमाल होने वाले ports, handshake का क्रम, server banners, certificates, uptime windows और controller के संबंध—IP बदलने पर भी fleet को उजागर कर सकते हैं।
- Compromised router में अक्सर endpoint telemetry नहीं होती, लेकिन उसके ISP के पास अब भी subscriber और flow data होता है; जब्ती से implant/configuration artifacts उजागर होते हैं।

{% hint style="info" %}
अधिकृत exercise के लिए, संगठन के स्वामित्व वाले VMs या routers से topology दोहराएँ और controller का attribution map सुरक्षित रखें। Open proxies या third-party devices का इस्तेमाल न करें। [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) वही hop structure बनाती है जो डिफेंडर को दिखेगा—बिना किसी intermediary को नुकसान पहुँचाए।
{% endhint %}

## Residential और mobile proxy networks

Residential proxy services sessions को consumer broadband addresses देती हैं; mobile proxies carrier NAT pools के ज़रिए egress करती हैं। इनकी आपूर्ति स्पष्ट रूप से नामांकित appliances, consumer applications में bundled SDK/proxyware, resellers या malware से हो सकती है। ये सभी स्रोत एक जैसे नहीं हैं: सूचित सहमति के बिना privacy service, compromised infrastructure बन जाती है।

Rotation modes detection को प्रभावित करते हैं:

- **per-request rotation** से IP और ASN/geography में तेज़ बदलाव होते हैं, जबकि higher-layer identity स्थिर रहती है;
- **sticky sessions** किसी exit को मिनटों या घंटों तक बनाए रखते हैं, जिससे वह सामान्य subscriber जैसा दिखता है;
- **backconnect gateways** customer को एक broker endpoint दिखाते हैं और अंदरूनी तौर पर exits चुनते हैं;
- **mobile pools** कई वास्तविक subscribers को कुछ carrier NAT addresses के पीछे रखते हैं, जिससे IP block करना महँगा पड़ता है।

डिफेंडर को IP का मिलान authenticated session, TLS/client fingerprint, HTTP ordering, device cookie और व्यवहार से करना चाहिए। यदि कथित तौर पर स्थानीय residential login के बाद दूसरे देश से गतिविधि हो, जबकि higher-layer की सभी विशेषताएँ एक जैसी रहें, तो यह केवल reputation के आधार पर मिलने वाले संकेत से अधिक मज़बूत सबूत है। इसके उलट, address sharing और mobile handoff से सामान्य बदलाव हो सकते हैं, इसलिए residential/proxy classification को कभी अंतिम निर्णय न मानें।

### Proxyware control planes और reseller का overlap

Residential pool को exits की एक साधारण सूची न मानें। IPIDEA ecosystem के विश्लेषण से दोबारा इस्तेमाल होने वाला **two-tier control plane** सामने आया: embedded SDK पहले device/enrollment metadata को Tier One domain पर भेजता है और बदले में scheduling तथा Tier Two `connect`/`proxy` IP:port pairs प्राप्त करता है। Node समय-समय पर encoded task के लिए Tier Two connect port से संपर्क करता है, paired proxy port से दूसरा connection खोलता है और दिए गए bytes को अनुरोधित destination तक relay करता है। नाम से अलग दिखने वाले SDKs और proxy brands के discovery domains अलग थे, लेकिन साझा ownership और reseller संबंधों के ज़रिए वे एक ही Tier Two infrastructure और overlapping exit pools पर आकर मिलते थे।<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

यह residential IP block से अधिक टिकाऊ hunting pivots देता है:<sup>[[13]](#references)</sup>

- कोई अप्रत्याशित utility, VPN, game या embedded-device process एक स्थिर device ID/customer key भेजता है और बदलती हुई server list प्राप्त करता है;
- endpoint किसी असामान्य port पर direct IP को poll करता है, फिर नया destination socket खोलने से ठीक पहले उसी address के दूसरे port से connect करता है;
- कई दिखने में अलग-अलग brands के Tier Two addresses, protocol grammar, SDK code या exit-node overlap साझा होते हैं;
- अलग-अलग Tier One domains से संपर्क करने वाले भिन्न applications को एक ही Tier Two pool से addresses मिलते हैं।

यह overlap attribution को भी सीमित करता है: किसी एक vendor के advertised pool में IP दिखना यह साबित नहीं करता कि संबंधित समय पर किस reseller, customer या threat actor ने उसका इस्तेमाल किया था। Flow timestamps, process lineage, Tier One response bodies और Tier Two task identifiers सुरक्षित रखें।<sup>[[13]](#references)</sup> किसी authorized exercise में, इस hierarchy का अनुकरण केवल organization-owned endpoints के साथ करें; consumer devices या third-party proxyware को कभी enroll न करें।

## Multi-hop proxy chains

MITRE external proxies और **multi-hop proxies (T1090.003)** में अंतर करता है। महत्वपूर्ण बात hops की संख्या नहीं, बल्कि knowledge और administration का अलगाव है।<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

यदि एक ही पक्ष A और B को संचालित करता है, तो साझा logs या flow timing से circuit का पुनर्निर्माण किया जा सकता है। एक ही endpoint/account से क्रमिक commercial VPNs जोड़ने पर latency बढ़ सकती है, जबकि साझा identity, payment और timing के प्रमाण बने रहते हैं। Tor स्वतंत्र रूप से चुने गए relays और साझा client design से इस समस्या को कम करता है, लेकिन कम-latency वाला interactive network ऐसे observer के विरुद्ध प्रतिरोध की गारंटी नहीं दे सकता जो दोनों छोरों को मापता हो।

आम विफलताओं में DNS या IPv6 bypass, applications का अपने sockets खोलना, management traffic का सीधे relays तक पहुँचना, synchronized activity, SSH keys का दोबारा उपयोग और पहचान उजागर करने वाले accounts में login करना शामिल हैं। सही verification एक failure test है: हर relay को बारी-बारी से रोकें और दिखाएँ कि workload किसी clear path पर fallback नहीं कर सकता।

### Tunnel collapse और upstream leakage

Relay architecture अक्सर विफल होने पर सबसे अधिक attribution योग्य होता है। Unit 42 ने एक multi-tier espionage path का दस्तावेज़ीकरण किया, जिसमें victim-facing VPSs, relay VPSs, residential proxies, Tor और अन्य proxy services का उपयोग किया गया था; जब tunnel छूट गया या collapse हुआ, तो छिपा हुआ upstream infrastructure सीधे relay और victim-facing systems से जुड़ गया। इसी investigation में upstream infrastructure पर थोड़ी देर के लिए उजागर हुए X.509 certificate का उपयोग cross-tier pivot के रूप में भी किया गया।<sup>[[14]](#references)</sup>

**data plane** (`victim <-> exit`) को **control plane** (`operator/upstream -> relay administration`) से अलग रखें। केवल सफल C2 sessions ही नहीं, बल्कि अपने स्वामित्व वाले हर tier पर ingress और authentication logs, certificate histories और थोड़े समय के failed connections भी सुरक्षित रखें। ऐसा source जो केवल relay outages के दौरान दिखाई देता है या कई victim-facing nodes का सीधे administration करता है, वह सामान्य exit की तुलना में अधिक मज़बूत upstream candidate है; फिर भी उसका ASN/geolocation केवल एक परिकल्पना है, operator की पहचान का प्रमाण नहीं।

अधिकृत lab में workload को fail closed होना चाहिए। Linux network namespace में अलग-थलग किए गए workload के लिए पहला route tunnel का उपयोग करे; उसे हटाने के बाद request और route lookup—दोनों विफल होने चाहिए, न कि physical uplink का चयन होना चाहिए:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS और IPv6 के लिए, और हर relay boundary पर, परीक्षण दोहराएँ। यदि कोई probe सफल होता है, तो policy routing या firewall को ठीक करने से पहले वास्तविक interface/source address दर्ज करें; जाँचकर्ता को यही attribution leak दिखाई देगा।

## Redirector tiers और traffic shaping

एक सार्वजनिक **redirector** उस traffic को स्वीकार करता है जो operation-specific grammar से मेल खाता है और उसे सुरक्षित team server तक forward करता है। बाकी सब reject किया जा सकता है या innocuous content परोसा जा सकता है।

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

कई स्तर exposure को सीमित करते हैं: सार्वजनिक domain को burn करने से team server का खुलासा ज़रूरी नहीं होता। CDN anycast capacity और एक प्रतिष्ठित outer domain जोड़ते हैं, लेकिन CDN account और edge logs attribution के बिंदु बन जाते हैं। TLS fingerprints, certificate histories, विशिष्ट paths/header order, response sizes, redirect behavior और origin allowlists कथित रूप से असंबंधित fronts को एक साथ जोड़ सकते हैं।

Detection के लिए normalization से पहले reverse-proxy fields रिकॉर्ड करें, SNI/Host/authority की तुलना करें, दुर्लभ header combinations की जाँच करें, response bodies और TLS fingerprints को cluster करें, और configuration overlap के लिए cloud/CDN audit logs खोजें। अधिकृत red teams को किसी वास्तविक brand की नकल करने या credential collection को किसी असंबंधित third party के पीछे रखने से बचना चाहिए।

## Domain fronting और domainless fronting

पारंपरिक **domain fronting (T1090.004)** में TLS connection SNI में एक अनुमत front domain बताता है, जबकि encrypted HTTP `Host` या HTTP/2 `:authority` किसी अलग back-end domain का अनुरोध करता है। सहयोगी CDN भीतर वाले मान के आधार पर routing करता है। TLS decryption के बिना network observer को front दिखता है; CDN दोनों मान और origin देखता है। Domainless variants में SNI खाली हो सकता है, जबकि कोई अन्य routing field destination चुनता है।<sup>[[4]](#references)</sup>

यह कोई जादुई impersonation नहीं है: यह तभी काम करता है जब intermediary जानबूझकर या अनजाने में इस mismatch की अनुमति दे और भीतर वाले नाम को route करना जानता हो। बड़े providers ने cross-account fronting पर पाबंदियाँ लगाई हैं। Encrypted ClientHello (ECH) on-path observer की दृश्यता बदलता है, लेकिन CDN, endpoint या application records मिटाता नहीं है।

Detection के बिंदुओं में शामिल हैं:

- endpoint process ancestry और ऐसा destination जिसकी उस application से अपेक्षा न हो;
- जहाँ TLS inspection कानूनी और उपलब्ध हो, वहाँ SNI और HTTP authority के बीच mismatch;
- CDN logs में एक tenant/front का किसी अन्य authority/origin की ओर routing करना;
- सामान्यतः interactive service के साथ असामान्य रूप से लंबे या periodic sessions;
- बदलते front domains के बावजूद encrypted flows के आकार और cadence का स्थिर रहना।

सुरक्षित lab में अपने reverse proxy पर routing mismatch का simulation करें; सार्वजनिक CDN का दुरुपयोग न करें।

## Dynamic resolution: DDNS, DGA और fast flux

Dynamic resolution किसी logical service को fixed infrastructure से अलग करता है:

- **DDNS:** address बदलने के बाद एक authenticated client स्थिर नाम को update करता है।
- **DGA:** endpoint और controller, दोनों time/key seed से संभावित domain names निकालते हैं; operator उनमें से कुछ को register करता है।
- **Fast flux:** कोई नाम compromised/proxy addresses का तेजी से बदलता हुआ समूह लौटाता है, अक्सर कम TTLs के साथ।
- **Double flux:** service addresses और authoritative name-server addresses, दोनों बदलते रहते हैं, जिससे control layer भी छिप जाती है।

Fast flux, adversarial रूप से इस्तेमाल किया जाने वाला load-distribution pattern है; यह केवल “कई DNS answers” नहीं है। अधिक मज़बूत साक्ष्य में कम TTL, unique addresses की बड़ी संख्या, व्यापक ASN/geography dispersion, node का कम जीवनकाल, बार-बार एक जैसा application behavior और संदिग्ध registration history शामिल हैं। CDNs में इनमें से कई गुण वैध रूप से पाए जाते हैं। MITRE, DNS behavior को process और उसके बाद के connections से correlate करने की सलाह देता है।<sup>[[5]](#references)</sup>

DGA का पता lexical entropy, consonant/digit patterns, NXDOMAIN bursts, एक ही समय पर पहली बार दिखे domains और process context से लगाया जा सकता है। Wordlist DGAs और generative models सरल entropy rules को निष्प्रभावी कर देते हैं, इसलिए पूरे fleet में temporal clustering और endpoint lineage अधिक महत्वपूर्ण हैं।

## Compromised domains और domain shadowing

कोई actor registrar/DNS account hijack कर सकता है, dangling subdomain takeover कर सकता है, या किसी अन्यथा प्रतिष्ठित domain के नीचे records जोड़ सकता है। **Domain shadowing** में वैध apex बरकरार रहता है, जबकि बड़ी संख्या में attacker-controlled subdomains बदलते delivery या C2 hosts की ओर संकेत करते हैं। यह domain की उम्र और reputation का लाभ उठाता है और पूरे domain को block करने से बच सकता है।<sup>[[6]](#references)</sup>

Defenders को registrar और authoritative-DNS audit logs, MFA, registry/registrar locks, नई delegations/API tokens/name servers के alerts, certificate-transparency monitoring और DNS द्वारा संदर्भित cloud resources की inventory चाहिए। किसी subdomain की resolution और certificate history की जाँच apex की reputation से स्वतंत्र रूप से करें।

## Web services और dead-drop resolvers

**Dead-drop resolver (T1102.001)** किसी वैध post, profile, document, repository, cloud object या blockchain field में मौजूदा C2 का encoded pointer रखता है। Malware उस public object को fetch करता है, domain/IP decode करता है और अगले stage से संपर्क करता है। Bidirectional variants, service APIs के ज़रिए commands या files का आदान-प्रदान करते हैं।<sup>[[7]](#references)</sup>

GitHub-विशिष्ट resolver का एक variant, authenticated repository channel विफल होने पर ही Issues Search API का उपयोग करता है। Client मौजूदा तारीख, repository और issue type से मेल खाते issues खोजता है, हर issue के comments URL पर जाता है और `<!--` तथा `-->` markers के बीच से ciphertext निकालता है। Per-host, date-derived decryption के बाद `Owner`, `LicRepo` और `LicToken` जैसे fields primary repository owner, path और token की जगह लेते हैं। इससे operator client को बदले बिना credentials और endpoints बदल सकता है; issue comment resolver है, जबकि repository files tasking channel बने रहते हैं।<sup>[[15]](#references)</sup>

एक Android variant startup पर दो public Telegram pages में से एक चुनता है और APK में embedded marker के दो occurrences के बीच से ciphertext निकालता है। यह value को Base64URL-decode करता है और AES-128-CBC से decrypt करता है: `SHA-256(marker)` के पहले 16 bytes key होते हैं और अगले 16 bytes IV। Plaintext वास्तविक C2 base URL होता है, Telegram page URL नहीं। Resolution को दोहराते समय page content और सटीक marker को जस का तस रखें; public page बदलने से APK को दोबारा बनाए बिना endpoint बदल जाता है।<sup>[[16]](#references)</sup>

इससे resilience मिलती है और static binary analysis से back-end C2 छिपा रहता है। साथ ही, इससे स्थिर object, tenant, repository, API और access-pattern identifiers बनते हैं। Defenders को इनका मिलान करना चाहिए:

1. service से संपर्क करने वाला process;
2. सटीक API path/object और response hash;
3. decoding या string-processing activity;
4. थोड़ी देर बाद बना नया outbound connection; और
5. पूरे fleet में कहीं और दिखता यही behavior।

सभी GitHub, cloud storage या social media को block करना शायद ही व्यावहारिक हो। Service-aware egress policy और process-level correlation, केवल domain blocking से बेहतर हैं।

## Personas, accounts और procurement compartments

जब कोई persona, recovery email, phone, payment, browser या admin IP compartments को जोड़ता है, तो infrastructure anonymity विफल हो जाती है। State-linked operations ने उपयोग से काफी पहले social profiles, email identities और cloud accounts तैयार किए हैं; ATT&CK इसे Establish Accounts (T1585) के रूप में दर्ज करता है, जिसमें social, email और cloud sub-techniques शामिल हैं।<sup>[[8]](#references)</sup>

Defender या investigator इनसे एक graph बनाता है:

- creation और first-login का समय, locale, time zone और कामकाज का schedule;
- recovery fields, MFA devices, identity documents और payment instruments;
- browser/TLS fingerprints और source-network history;
- avatar का दोबारा इस्तेमाल, image provenance, writing style और social-graph growth;
- साझा domain registrant, name server, certificate, analytics ID या repository commit;
- management-plane actions, जो public relay architecture को bypass करते हैं।

अधिकृत red team के लिए synthetic personas को exercise controller के सामने दर्ज किया जाना चाहिए, organization-owned recovery/payment channels का उपयोग करना चाहिए, वास्तविक और असंबंधित लोगों की impersonation से बचना चाहिए, और उन्हें retire करने की योजना होनी चाहिए। SOC को अनजान रखा जा सकता है; operation को जवाबदेही से मुक्त नहीं होना चाहिए।

## Threat-model में शामिल करने योग्य उभरते compound patterns

नीचे दिए गए उदाहरण **defender-driven compositions** हैं; इनका आशय यह दावा करना नहीं है कि किसी नामित actor ने हर सटीक design को deploy किया है। ये पहले से देखे गए primitives को जोड़ते हैं और purple-team hypotheses के रूप में उपयोगी हैं।

### Asymmetric one-way tasking

Commands किसी public, broadcast या append-only source से आते हैं, जबकि results कुछ देर बाद किसी असंबंधित channel से बाहर जाते हैं। इस primitive के उदाहरणों में web-service one-way communication और dead drops शामिल हैं। अलग-अलग channels के कारण कोई एक flow bidirectional नहीं दिखता और सरल request/response correlation मुश्किल हो जाता है।<sup>[[9]](#references)</sup>

**Detection:** object-level reads सुरक्षित रखें, फिर व्यापक समयावधि में process state changes और बाद के outbound transfers को correlate करें। ऐसे दुर्लभ process खोजें जो उसी public object को पढ़ते हों, भले ही उसके तुरंत बाद कोई reply न आए।

### Multi-stage channel promotion

एक शांत first stage inventory करता है और केवल चुने हुए systems को किसी असंबंधित second-stage channel पर भेजता है। दूसरे endpoint, protocol और process का पहले stage के infrastructure से कोई साझा संबंध नहीं हो सकता। इससे सक्षम infrastructure का exposure सीमित होता है और इसे ATT&CK T1104 में स्पष्ट रूप से model किया गया है।<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` को जोड़ें; पहले domain को block करने के बाद incident बंद न करें।

### Cross-protocol relay translation

अलग-अलग hops packets को पारदर्शी रूप से forward करने के बजाय HTTPS, QUIC, WebSocket, DNS, SSH या message-queue API का अनुवाद करते हैं। इससे एकल end-to-end protocol fingerprint हट जाता है, लेकिन ऐसे gateways बनते हैं जिनकी timing, buffering और semantic conversion विशिष्ट होती है। Protocol tunneling (T1572) को proxies और service impersonation के साथ जोड़ा जा सकता है।<sup>[[11]](#references)</sup>

**Detection:** ऐसे gateway hosts खोजें जो एक protocol प्राप्त करके दूसरे protocol से tightly coupled byte/time behavior के साथ connection शुरू करते हों; endpoint के उद्देश्य की तुलना वास्तव में उपयोग किए गए protocol से करें।

### Edge devices पर passive activation

Beaconing के बजाय, कोई implant router/VPN तक पहले से पहुँच रहे traffic को monitor करता है और केवल किसी magic value, source-port pattern या authenticated token मिलने पर सक्रिय होता है। सामान्य traffic वास्तविक service तक पहुँचता रहता है। ATT&CK इसे Traffic Signaling (T1205) कहता है; इसके documented network-device और APT examples भी हैं।<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity जाँचें, अधिकृत hunt के दौरान raw packet capture करें, अनपेक्षित socket filters और service behavior में अंतर खोजें। Periodic beacon न दिखना इस बात का प्रमाण नहीं है कि edge device साफ़ है।

### Serverless और ephemeral origin rotation

एक front स्थिर logical identity बनाए रखता है, जबकि अल्पकालिक functions/containers कई regions/accounts में अलग-अलग stages को संभालते हैं। इससे disk पर रहने की अवधि और fixed origin IPs कम होते हैं, लेकिन control-plane creation, image/layer, role, secret, request ID और billing telemetry स्थायी graph बन जाते हैं।

**Detection:** cloud audit और invocation logs workload के बाहर सुरक्षित रखें; deployment templates, roles, environment keys और front-to-origin संबंधों को cluster करें।

### Privacy-layer diversity

कोई operation जानबूझकर एक समान chain से बच सकता है: उदाहरण के लिए, एक channel leased relay का उपयोग करता है, tasking public object से होती है, exit अपने lab के cellular link से आता है और administration अलग organization network से होती है। इससे किसी एक provider के compromise का महत्व घटता है, लेकिन अलग-अलग layers के बीच timing और operational-error का जोखिम बढ़ता है।

**Detection:** identity, DNS, SaaS, network और cloud sensors से campaign timelines बनाएँ। समान indicators के बजाय synchronized state transitions खोजें।

### Decentralized या transparency-log dead drops

कोई actor किसी टिकाऊ public append-only system, content-addressed store या transparency-जैसी feed में एक छोटा encrypted pointer रख सकता है। Public object टिकाऊ होता है, लेकिन उसका सटीक index/content hash और client का polling behavior स्थिर identifiers बन जाते हैं।

**Detection:** पूरे API/object identifiers और response hashes रिकॉर्ड करें; ऐसे गैर-मानक processes पर alert करें जो immutable objects को poll करने के बाद decoding या नए connections करते हैं।

### Delayed store-and-forward operations

Interactive C2 timing का मज़बूत correlation पैदा करता है। Store-and-forward design encrypted jobs को batch करता है और मिनटों या घंटों बाद, किसी दूसरे queue या physical transfer के ज़रिए results लौटाता है। इससे responsiveness घटती है, लेकिन end-to-end timing कम स्पष्ट होती है।

**Detection:** correlation windows लंबी रखें, periodic queue access को model करें और endpoint staging की जाँच करें। Batching signal को packet timing से हटाकर scheduled process/file behavior में ले जाती है; उसे मिटाती नहीं है।

## Design review: observers के नज़रिए से सोचें

हर path के लिए deployment से पहले और collection के बाद यह table भरें:

| Layer | क्या source दिखता है? | क्या destination दिखता है? | क्या content दिखता है? | स्थिर identifiers | Retention/कानूनी owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

यदि कोई एक सामान्य provider हर column भर सकता है, तो architecture target से concealment तो देती है, लेकिन मज़बूत separation नहीं। यदि कोई भी internal controller activity को engagement से नहीं जोड़ सकता, तो यह professional red teaming के लिए उपयुक्त नहीं है।

## References

- [1] [MITRE ATT&CK — Infrastructure हासिल करना (T1583), Infrastructure compromise करना (T1584), और Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors ORB networks का उपयोग करते हैं](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastructure compromise करना: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Accounts स्थापित करना (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — दुनिया के सबसे बड़े Residential Proxy Network को बाधित करना](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: वैश्विक जासूसी का पर्दाफाश](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign ने इराकी Infrastructure को निशाना बनाया](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI ने Overlays बनाए। Victims ने अपने PIN खो दिए](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
