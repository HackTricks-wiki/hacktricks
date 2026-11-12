# Offensive Infrastructure और Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

किसी एक proxy से operator को शायद ही कभी सार्थक anonymity मिलती है। वास्तविक campaigns एक **separation graph** बनाते हैं: operator एक access node तक पहुँचता है, traversal nodes उस node को exit से छिपाते हैं, redirectors असली C2 की रक्षा करते हैं, और disposable names public edge की ओर संकेत करते हैं।

हर path के सामान्यीकृत pros/cons/deployment/detection विवरण के लिए [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) देखें। इस पेज में adversarial infrastructure composition पर अधिक विस्तार से चर्चा की गई है।

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

इसलिए लक्ष्य द्वारा देखा गया अंतिम पता किसी रास्ते का प्रमाण है, न कि इस बात का सबूत कि कीबोर्ड किसने नियंत्रित किया। MITRE इसके प्रमुख घटकों को Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) और Web Service (T1102) से जोड़ता है।<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | कोई actor इसका उपयोग क्यों करता है | लंबे समय तक बने रहने वाला जोखिम | Defender का सबसे अच्छा pivot |
|---|---|---|---|
| Rented VPS/cloud | तेज़, पूर्वानुमेय, routable, फिर से बनाना आसान | tenant, billing, console, source-login और image history | account/control-plane events और बार-बार दिखने वाला server fingerprint |
| Commercial VPN/Tor | बड़ा साझा egress सेट; server प्रशासन की ज़रूरत नहीं | provider/guard की दृश्यता और end-to-end timing | destination behavior, endpoint evidence और flow correlation |
| Residential/mobile proxy | Consumer ASN और भौगोलिक विश्वसनीयता | broker/customer records; proxyware या संक्रमित-host behavior | impossible travel, proxy protocols और session के अनुसार address churn |
| Compromised server/router/IoT | victim की reputation और jurisdiction का लाभ | implant, management flow और बार-बार दिखने वाला upstream controller | device telemetry और ORB topology, न कि केवल एक exit IP |
| CDN/redirector | सार्वजनिक edge को back-end C2 से अलग करता है | TLS/HTTP grammar, certificate, routing और cloud-account artifacts | edge-to-origin correlation और request-shape clustering |
| Legitimate web service | अनुमत GitHub/cloud/social traffic में घुल-मिल जाता है | API token, tenant/object identifiers और असामान्य process lineage | endpoint process और service/API semantics |
| Physical/cellular/satellite path | दिखने वाले भौतिक origin को बदलता है | RF, carrier, subscriber, device और location records | radio/physical और network evidence को मिलाकर देखना |

## Operational relay box networks

**ORB network** एक managed proxy fleet है, जिसका उपयोग मध्यवर्ती सेवा के रूप में होता है। Mandiant इन्हें leased servers के provisioned networks, compromised routers/IoT के non-provisioned networks और hybrids में बाँटता है। एक परिपक्व topology में चार तार्किक भूमिकाएँ होती हैं:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory, credentials, health और routing policy बनाए रखता है।
2. **Access/relay node:** ग्राहकों या operators को authenticate करता है; बदलते mesh में यही स्थिर प्रवेश बिंदु होता है।
3. **Traversal nodes:** एक या अधिक leased या compromised systems, opaque connections को relay करते हैं।
4. **Exit/staging node:** reconnaissance, exploitation या C2 targets के सामने अंतिम source address प्रस्तुत करता है।

Mesh देश, ASN, latency या availability के आधार पर exits चुन सकता है और खराब nodes को बदल सकता है। कई threat groups एक ही network किराये पर ले सकते हैं। Mandiant ने पाया कि कुछ ORBs से जुड़ा IPv4 address केवल 31 दिनों तक बना रहा; इसलिए वह IPs की पुरानी सूची को block करने के बजाय **network को बदलती हुई actor-जैसी इकाई** मानने की सलाह देता है।<sup>[[2]](#references)</sup>

### इससे क्या मिलता है—और क्या उजागर होता है

- लक्ष्य को ऐसा exit दिखता है जो भौगोलिक रूप से पास और देखने में residential हो सकता है।
- Exit को लक्ष्य और उससे पहले वाला hop दिखता है, ज़रूरी नहीं कि operator भी दिखे।
- Access service को ग्राहक और route request दिखती है। स्वतंत्र रूप से managed mesh ग्राहक को exits से अलग रख सकता है, लेकिन इससे counterparty का एक अहम रिकॉर्ड बनता है।
- बार-बार दिखने वाले ports, handshake order, server banners, certificates, uptime windows और controller relationships, IPs बदलने पर भी fleet को उजागर कर सकते हैं।
- Compromised router में अक्सर endpoint telemetry नहीं होती, लेकिन उसके ISP के पास subscriber और flow data फिर भी होता है; जब्ती से implant/configuration artifacts उजागर होते हैं।

{% hint style="info" %}
अधिकृत exercise के लिए, संगठन के स्वामित्व वाले VMs या routers से topology को दोहराएँ और controller का attribution map सुरक्षित रखें। Open proxies या third-party devices का उपयोग न करें। [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) वही hop structure बनाती है जो defender को दिखेगा, लेकिन किसी intermediary को नुकसान पहुँचाए बिना।
{% endhint %}

## Residential and mobile proxy networks

Residential proxy services sessions को consumer broadband addresses देती हैं; mobile proxies, carrier NAT pools के ज़रिए egress करती हैं। इनकी आपूर्ति स्पष्ट रूप से नामांकित appliances, consumer applications में bundled SDK/proxyware, resellers या malware से हो सकती है। ये स्रोत एक जैसे नहीं हैं: सूचित सहमति का अभाव privacy service को compromised infrastructure बना देता है।

Rotation modes से detection प्रभावित होता है:

- **per-request rotation** तेज़ी से IP और ASN/geography में बदलाव करती है, जबकि higher-layer identity स्थिर रहती है;
- **sticky sessions** किसी exit को मिनटों या घंटों तक बनाए रखती हैं, जिससे वह सामान्य subscriber जैसा लगता है;
- **backconnect gateways** ग्राहक को एक broker endpoint दिखाते हैं और exits का चयन अंदरूनी तौर पर करते हैं;
- **mobile pools** कई वास्तविक subscribers को carrier NAT addresses के छोटे समूह के पीछे रखते हैं, जिससे IP block करना महँगा पड़ता है।

Defenders को IP का मिलान authenticated session, TLS/client fingerprint, HTTP ordering, device cookie और behavior से करना चाहिए। यदि कथित तौर पर स्थानीय residential login के बाद किसी दूसरे देश का login हो, जबकि सभी higher-layer features एक जैसे रहें, तो यह केवल reputation से अधिक ठोस संकेत है। दूसरी ओर, address sharing और mobile handoff से वैध बदलाव होते हैं, इसलिए residential/proxy classification को कभी अंतिम निर्णय न मानें।

### Proxyware control planes और reseller overlap

Residential pool को exits की एक सपाट सूची के रूप में न देखें। IPIDEA ecosystem के विश्लेषण से दोबारा इस्तेमाल होने वाला **two-tier control plane** सामने आया: embedded SDK पहले device/enrollment metadata को Tier One domain पर भेजता है और फिर scheduling के साथ Tier Two `connect`/`proxy` IP:port pairs प्राप्त करता है। Node, encoded task के लिए समय-समय पर Tier Two connect port को poll करता है, paired proxy port से दूसरा connection खोलता है और दिए गए bytes को अनुरोधित destination तक relay करता है। नाममात्र के तौर पर अलग SDKs और proxy brands के discovery domains अलग थे, लेकिन साझा ownership और reseller relationships के चलते वे साझा Tier Two infrastructure और एक-दूसरे से मिलते-जुलते exit pools तक पहुँचते थे।<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

यह residential IP block की तुलना में अधिक टिकाऊ hunting pivots देता है:<sup>[[13]](#references)</sup>

- कोई अप्रत्याशित utility, VPN, game या embedded-device process स्थिर device ID/customer key भेजता है और बदलती हुई server list प्राप्त करता है;
- endpoint किसी असामान्य port पर सीधे IP को poll करता है, फिर नया destination socket खोलने से ठीक पहले उसी address के किसी दूसरे port से connect करता है;
- कई दिखावटी brands के Tier Two addresses, protocol grammar, SDK code या exit-node overlap समान होते हैं;
- अलग-अलग Tier One domains से संपर्क करने वाले भिन्न applications को उसी Tier Two pool से addresses मिलते हैं।

यह overlap attribution को भी सीमित करता है: किसी vendor के advertised pool में IP दिखने से यह साबित नहीं होता कि संबंधित समय पर किस reseller, customer या threat actor ने उसका उपयोग किया था। Flow timestamps, process lineage, Tier One response bodies और Tier Two task identifiers सुरक्षित रखें।<sup>[[13]](#references)</sup> अधिकृत exercise में, इस hierarchy का अनुकरण केवल संगठन के स्वामित्व वाले endpoints के साथ करें; consumer devices या third-party proxyware को कभी enroll न करें।

## Multi-hop proxy chains

MITRE external proxies और **multi-hop proxies (T1090.003)** में अंतर करता है। महत्वपूर्ण बात hops की संख्या नहीं, बल्कि knowledge और administration का अलगाव है।<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

यदि एक ही पक्ष A और B संचालित करता है, तो साझा logs या flow timing से circuit का पुनर्निर्माण किया जा सकता है। एक ही endpoint/account से क्रमिक commercial VPNs जोड़ने पर latency बढ़ सकती है, लेकिन साझा identity, payment और timing के सबूत बने रहते हैं। Tor स्वतंत्र रूप से चुने गए relays और साझा client design के ज़रिए इस समस्या को कम करता है, लेकिन low-latency interactive network ऐसे observer के विरुद्ध प्रतिरोध की गारंटी नहीं दे सकता जो दोनों सिरों को मापता हो।

आम विफलताओं में DNS या IPv6 bypass, applications का अपने sockets खोलना, management traffic का सीधे relays तक पहुँचना, synchronized activity, दोबारा इस्तेमाल की गई SSH keys और पहचान बताने वाले accounts में login करना शामिल हैं। सही verification एक failure test है: बारी-बारी से हर relay रोकें और दिखाएँ कि workload किसी clear path पर fallback नहीं कर सकता।

### Tunnel collapse और upstream leakage

Relay architecture अक्सर विफल होने पर सबसे अधिक attributable होती है। Unit 42 ने espionage के एक multi-tier रास्ते का दस्तावेज़ीकरण किया, जिसमें victim-facing VPSs, relay VPSs, residential proxies, Tor और अन्य proxy services का उपयोग किया गया था; जब कोई tunnel छूट गया या collapse हो गया, तो छिपा हुआ upstream infrastructure सीधे relay और victim-facing systems से जुड़ गया। इसी investigation में upstream infrastructure पर थोड़े समय के लिए उजागर हुए X.509 certificate का उपयोग cross-tier pivot के रूप में भी किया गया।<sup>[[14]](#references)</sup>

**data plane** (`victim <-> exit`) को **control plane** (`operator/upstream -> relay administration`) से अलग रखें। हर अपने नियंत्रण वाले tier पर ingress और authentication logs, certificate histories और थोड़े समय के failed connections सुरक्षित रखें—सिर्फ सफल C2 sessions नहीं। ऐसा source जो केवल relay outages के दौरान दिखाई देता है या कई victim-facing nodes का सीधे administration करता है, सामान्य exit की तुलना में बेहतर upstream candidate है; फिर भी उसका ASN/geolocation एक hypothesis है, operator की पहचान का प्रमाण नहीं।

एक authorized lab में workload को fail closed होना चाहिए। Linux network namespace में अलग किए गए workload के लिए, पहला route tunnel का उपयोग करना चाहिए; उसे हटाने के बाद request और route lookup—दोनों विफल होने चाहिए, न कि physical uplink चुनना चाहिए:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS और IPv6 के लिए तथा हर relay boundary पर परीक्षण दोहराएँ। अगर कोई probe सफल हो, तो policy routing या firewall को ठीक करने से पहले वास्तविक interface/source address दर्ज करें; यही attribution leak है जिसे कोई जाँचकर्ता देखेगा।

## Redirector tiers और traffic shaping

एक सार्वजनिक **redirector** उस traffic को स्वीकार करता है जो operation-specific grammar से मेल खाता है और उसे protected team server तक forward करता है। बाकी सभी traffic को अस्वीकार किया जा सकता है या उसे हानिरहित content दिखाया जा सकता है।

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

कई tiers exposure को सीमित करते हैं: किसी public domain को burn करने से team server का खुलासा होना ज़रूरी नहीं है। CDN anycast capacity और एक प्रतिष्ठित बाहरी domain जोड़ते हैं, लेकिन CDN account और edge logs attribution points बन जाते हैं। TLS fingerprints, certificate histories, विशिष्ट paths/header order, response sizes, redirect behavior और origin allowlists उन fronts को समूहित कर सकते हैं जिन्हें असंबंधित समझा जाता है।

Detection के लिए, normalization से पहले reverse-proxy fields रिकॉर्ड करें, SNI/Host/authority की तुलना करें, दुर्लभ header combinations का निरीक्षण करें, response bodies और TLS fingerprints को समूहित करें, और configuration overlap के लिए cloud/CDN audit logs खोजें। अधिकृत red teams को किसी असली brand की नकल करने या credential collection को किसी असंबंधित third party के पीछे रखने से बचना चाहिए।

## Domain fronting और domainless fronting

क्लासिक **domain fronting (T1090.004)** में, TLS connection SNI में एक अनुमत front domain बताता है, जबकि encrypted HTTP `Host` या HTTP/2 `:authority` किसी दूसरे back-end domain का अनुरोध करता है। सहयोगी CDN inner value के आधार पर routing करता है। TLS decryption के बिना network observer को front दिखता है; CDN को दोनों values और origin दिखते हैं। Domainless variants में, SNI खाली हो सकता है, जबकि कोई अन्य routing field destination चुनता है।<sup>[[4]](#references)</sup>

यह कोई जादुई impersonation नहीं है: यह तभी काम करता है जब intermediary जानबूझकर या अनजाने में इस mismatch की अनुमति दे और inner name को route करना जानता हो। प्रमुख providers ने अलग-अलग accounts के बीच fronting पर पाबंदियाँ लगाई हैं। Encrypted ClientHello (ECH) बदलता है कि on-path observer क्या देख सकता है, लेकिन CDN, endpoint या application records को मिटाता नहीं है।

Detection points में शामिल हैं:

- endpoint process ancestry और ऐसा destination जो उस application के लिए अपेक्षित न हो;
- जहाँ TLS inspection वैध और उपलब्ध हो, वहाँ SNI और HTTP authority के बीच mismatch;
- CDN logs में एक tenant/front से दूसरे authority/origin की ओर routing दिखना;
- सामान्यतः interactive service से असामान्य रूप से लंबे समय तक चलने वाले या periodic sessions;
- बदलते front domains के बावजूद encrypted flow sizes और cadence का स्थिर रहना।

सुरक्षित lab में अपने स्वामित्व वाले reverse proxy पर routing mismatch का simulation किया जाता है; किसी public CDN का दुरुपयोग नहीं किया जाता।

## Dynamic resolution: DDNS, DGA और fast flux

Dynamic resolution किसी logical service को स्थिर infrastructure से अलग करता है:

- **DDNS:** कोई authenticated client, address बदलने के बाद एक स्थिर name को update करता है।
- **DGA:** endpoint किसी seed से domain names निकालता है, जो अक्सर समय या key होता है, लेकिन कभी-कभी बदलती public content भी हो सकती है; operator सक्रिय name के लिए DNS व्यवस्थित करता है।<sup>[[17]](#references)</sup>
- **Fast flux:** कोई name, तेज़ी से बदलते compromised/proxy addresses का समूह लौटाता है, अक्सर कम TTLs के साथ।
- **Double flux:** service addresses और authoritative name-server addresses, दोनों बदलते रहते हैं; इससे control layer भी छिप जाती है।

Fast flux एक load-distribution pattern है जिसका adversarial तरीके से उपयोग किया जाता है; यह केवल “कई DNS answers” नहीं है। अधिक मज़बूत साक्ष्य में कम TTL, unique addresses की बड़ी संख्या, व्यापक ASN/geography dispersion, node का कम जीवनकाल, बार-बार एक जैसा application behavior और संदिग्ध registration history शामिल हैं। CDNs में भी इनमें से कई विशेषताएँ वैध रूप से होती हैं। MITRE, DNS behavior को process और उसके बाद के connections के साथ correlate करने की सिफ़ारिश करता है।<sup>[[5]](#references)</sup>

DGA को lexical entropy, consonant/digit patterns, NXDOMAIN bursts, एक ही समय पर पहली बार दिखने वाले domains और process context के ज़रिए detect किया जा सकता है। Wordlist DGAs और generative models सरल entropy rules को निष्प्रभावी कर देते हैं, इसलिए पूरे fleet में temporal clustering और endpoint lineage अधिक महत्वपूर्ण हो जाते हैं।

### Wordlist DGA के लिए mutable image seed

DGA का समय पर निर्भर होना ज़रूरी नहीं है। एक loader, किसी public Telegram channel page को fetch करता है, उसके `tgme_page_photo_image` element का `src` पढ़ता है, उस profile image को download करता है और decoded pixels के बजाय उसकी **फ़ाइल के आखिरी 50 bytes** का hash बनाता है। चार hash seeds से एक adjective, noun, verb और number चुने जाते हैं। Image बदलने से नया client भेजे बिना derived DNS name बदल जाता है। दोनों sides पर ठीक वही downloaded image bytes और word-list का वही क्रम रखें; image को दोबारा encode करने या list का क्रम बदलने पर अलग names बनेंगे।<sup>[[17]](#references)</sup>

Client से word lists प्राप्त होने के बाद, इससे name-selection step दोहराया जा सकता है। Source का byte-wise hash, 64-bit accumulator, multiplier `0x1000193` और हर component के लिए अलग-अलग seeds इस्तेमाल करता है:<sup>[[17]](#references)</sup>

<details>
<summary>Image-seeded wordlist name selection दोहराएँ</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

[dead-drop resolver](#web-services-and-dead-drop-resolvers) के विपरीत, जो endpoint को ही प्रकाशित करता है, यहाँ public object केवल एक बदल सकने वाला seed देता है; client स्थानीय रूप से endpoint निकालता है।

इसके बाद generated name के लिए `https://dns.google/resolve?name=<domain>&type=TXT` के ज़रिए DNS TXT record पूछा जाता है। Client JSON response के `data` field को Base64-decode करता है, embedded public key से Ed25519 signature सत्यापित करता है और उसके बाद ही command को AES-ECB से decrypt करता है। देखे गए plaintext की शुरुआत method selector और encrypted payload के URL से होती है। Signature जाँच का मतलब है कि केवल resolve होने वाला TXT record स्वीकार्य tasking नहीं दे सकता।<sup>[[17]](#references)</sup>

## Compromised domains और domain shadowing

कोई actor registrar/DNS account hijack कर सकता है, dangling subdomain पर कब्ज़ा कर सकता है या किसी अन्यथा प्रतिष्ठित domain के अंतर्गत records जोड़ सकता है। **Domain shadowing** वैध apex को बनाए रखते हुए बड़ी संख्या में attacker-नियंत्रित subdomains को बदलते delivery या C2 hosts की ओर point करता है। इससे domain की उम्र और प्रतिष्ठा का लाभ मिलता है और पूरे domain पर आधारित blocking से बच निकलना संभव हो सकता है।<sup>[[6]](#references)</sup>

Defenders को registrar और authoritative-DNS audit logs, MFA, registry/registrar locks, नई delegations/API tokens/name servers के लिए alerts, certificate-transparency monitoring और DNS द्वारा संदर्भित cloud resources की सूची चाहिए। Subdomain के resolution और certificate history की जाँच apex की प्रतिष्ठा से स्वतंत्र रूप से करें।

## Web services और dead-drop resolvers

**Dead-drop resolver (T1102.001)** किसी वैध post, profile, document, repository, cloud object या blockchain field के भीतर मौजूदा C2 का encoded pointer रखता है। Malware public object fetch करता है, domain/IP decode करता है और अगले stage से संपर्क करता है। Bidirectional variants service APIs के ज़रिए commands या files का आदान-प्रदान करते हैं।<sup>[[7]](#references)</sup>

GitHub-विशिष्ट resolver का एक variant, authenticated repository channel विफल होने पर ही Issues Search API का उपयोग करता है। Client मौजूदा तारीख, repository और issue type से मेल खाने वाले issues खोजता है, हर issue के comments URL पर जाता है और `<!--` तथा `-->` markers के बीच का ciphertext निकालता है। प्रति-host, तारीख से निकली decryption के बाद, `Owner`, `LicRepo` और `LicToken` जैसे fields प्राथमिक repository owner, path और token की जगह ले लेते हैं। इससे operator client को बदले बिना credentials और endpoints बदल सकता है; issue comment resolver का काम करता है, जबकि repository files tasking channel बने रहते हैं।<sup>[[15]](#references)</sup>

एक Android variant startup पर दो public Telegram pages में से एक चुनता है और APK में embedded marker की दो occurrences के बीच का ciphertext निकालता है। यह value को Base64URL-decode करता है और AES-128-CBC से decrypt करता है: `SHA-256(marker)` के पहले 16 bytes key होते हैं और बाकी 16 bytes IV। Plaintext वास्तविक C2 base URL होता है, Telegram page URL नहीं। Resolution को दोहराते समय page content और सटीक marker जस के तस रखें; public page बदलने से APK दोबारा बनाए बिना endpoint बदला जा सकता है।<sup>[[16]](#references)</sup>

इससे resilience मिलती है और static binary analysis से back-end C2 छिपा रहता है। साथ ही, इससे स्थिर object, tenant, repository, API और access-pattern identifiers बनते हैं। Defenders को इनका संबंध जोड़ना चाहिए:

1. service से संपर्क करने वाली process;
2. सटीक API path/object और response hash;
3. decoding या string-processing activity;
4. थोड़ी देर बाद बना नया outbound connection; और
5. fleet में अन्यत्र दिखने वाला समान व्यवहार।

सभी GitHub, cloud storage या social media को block करना शायद ही व्यावहारिक हो। Service-aware egress policy और process-level correlation, केवल domain-आधारित blocking से बेहतर हैं।

## Personas, accounts और procurement compartments

जब कोई persona, recovery email, phone, payment, browser या admin IP compartments के बीच संबंध जोड़ता है, तो infrastructure anonymity विफल हो जाती है। State-linked operations ने उपयोग से काफी पहले social profiles, email identities और cloud accounts तैयार किए हैं; ATT&CK इसे Establish Accounts (T1585) के रूप में दर्ज करता है, जिसमें social, email और cloud sub-techniques शामिल हैं।<sup>[[8]](#references)</sup>

Defender या investigator निम्नलिखित से एक graph बनाता है:

- creation और first-login का समय, locale, time zone और काम का schedule;
- recovery fields, MFA devices, identity documents और payment instruments;
- browser/TLS fingerprints और source-network history;
- avatar का दोबारा उपयोग, image provenance, writing style और social-graph की वृद्धि;
- साझा domain registrant, name server, certificate, analytics ID या repository commit;
- ऐसे management-plane actions जो public relay architecture को bypass करते हैं।

अधिकृत red team के लिए synthetic personas को exercise controller के दस्तावेज़ में दर्ज करना चाहिए, संगठन-स्वामित्व वाले recovery/payment channels का उपयोग करना चाहिए, असंबद्ध वास्तविक लोगों का रूप धारण करने से बचना चाहिए और उन्हें retire करने की योजना रखनी चाहिए। SOC अनजान रह सकता है; operation को जवाबदेही से मुक्त नहीं होना चाहिए।

## Threat-model में शामिल होने वाले उभरते compound patterns

निम्नलिखित **defender-driven compositions** हैं; ये यह दावा नहीं करते कि किसी नामित actor ने हर सटीक design तैनात किया है। ये पहले से देखे गए primitives को जोड़ते हैं और उपयोगी purple-team hypotheses हैं।

### Asymmetric one-way tasking

Commands किसी public, broadcast या append-only source से आते हैं, जबकि results विलंब के बाद किसी असंबंधित channel से बाहर जाते हैं। इसके primitive के उदाहरणों में web-service one-way communication और dead drops शामिल हैं। अलगाव से कोई एक flow bidirectional नहीं दिखता और साधारण request/response correlation कठिन हो जाता है।<sup>[[9]](#references)</sup>

**Detection:** object-level reads सुरक्षित रखें, फिर process state changes और बाद के outbound transfers को एक बड़ी समयावधि में correlate करें। ऐसी दुर्लभ process खोजें जो उसी public object को पढ़ती है, भले ही उसके बाद तुरंत कोई reply न आए।

### Multi-stage channel promotion

एक शांत first stage inventory करता है और केवल चुने हुए systems को असंबंधित second-stage channel पर भेजता है। दूसरे endpoint, protocol और process का पहले वाले infrastructure से कोई संबंध नहीं हो सकता। इससे सक्षम infrastructure का खुलासा सीमित रहता है और इसे ATT&CK T1104 में स्पष्ट रूप से model किया गया है।<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` को जोड़ें; पहले domain को block करने के बाद incident बंद न करें।

### Cross-protocol relay translation

अलग-अलग hops packets को पारदर्शी रूप से forward करने के बजाय HTTPS, QUIC, WebSocket, DNS, SSH या message-queue API का रूपांतरण करते हैं। रूपांतरण से एक अकेला end-to-end protocol fingerprint हट जाता है, लेकिन ऐसे gateways बनते हैं जिनकी timing, buffering और semantic conversion विशिष्ट होती है। Protocol tunneling (T1572) को proxies और service impersonation के साथ जोड़ा जा सकता है।<sup>[[11]](#references)</sup>

**Detection:** ऐसे gateway hosts खोजें जो एक protocol प्राप्त करके किसी दूसरे protocol से संपर्क करते हैं और जिनके byte/time व्यवहार में कड़ा संबंध हो; endpoint के उद्देश्य की तुलना वास्तव में भेजे गए protocol से करें।

### Edge devices पर passive activation

Beaconing करने के बजाय, implant router/VPN तक पहले से पहुँच रहे traffic को monitor करता है और केवल magic value, source-port pattern या authenticated token मिलने पर activate होता है। सामान्य traffic वास्तविक service तक पहुँचता रहता है। ATT&CK इसे Traffic Signaling (T1205) कहता है और इसमें network-device तथा APT के दस्तावेज़ीकृत उदाहरण हैं।<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, अधिकृत hunt के दौरान raw packet capture, अप्रत्याशित socket filters और service के व्यवहार में अंतर की जाँच करें। Periodic beacon न दिखना इस बात का प्रमाण नहीं है कि edge device साफ़ है।

### Serverless और ephemeral origin rotation

एक front स्थिर logical identity बनाए रखता है, जबकि कम अवधि वाले functions/containers कई regions/accounts में अलग-अलग stages संभालते हैं। इससे disk पर मौजूदगी का समय और निश्चित origin IPs घटते हैं, लेकिन control-plane creation, image/layer, role, secret, request ID और billing telemetry टिकाऊ graph बन जाते हैं।

**Detection:** cloud audit और invocation logs को workload के बाहर सुरक्षित रखें; deployment templates, roles, environment keys और front-to-origin संबंधों के समूहों की पहचान करें।

### Privacy-layer diversity

कोई operation जानबूझकर एक समान chain से बच सकता है: उदाहरण के लिए, एक channel leased relay का उपयोग करे, tasking के लिए public object हो, exit के लिए स्वामित्व वाला lab cellular link और administration के लिए अलग organization network। इससे किसी एक provider को compromise करने का लाभ कम होता है, लेकिन layers के बीच timing और operational-error का जोखिम बढ़ता है।

**Detection:** identity, DNS, SaaS, network और cloud sensors के आधार पर campaign timelines बनाएँ। एक जैसे indicators के बजाय synchronized state transitions खोजें।

### Decentralized या transparency-log dead drops

कोई actor किसी टिकाऊ public append-only system, content-addressed store या transparency-जैसी feed में छोटा encrypted pointer रख सकता है। Public object resilient होता है, लेकिन उसका सटीक index/content hash और client का polling behavior स्थिर identifiers बन जाते हैं।

**Detection:** पूरे API/object identifiers और response hashes दर्ज करें; ऐसे nonstandard processes पर alert करें जो immutable objects को poll करने के बाद decoding या नए connections करते हैं।

### Delayed store-and-forward operations

Interactive C2 से timing का मज़बूत संबंध बनता है। Store-and-forward design encrypted jobs को batch करता है और कुछ मिनटों या घंटों बाद, किसी अलग queue या physical transfer के ज़रिए results लौटाता है। इससे responsiveness घटती है, लेकिन end-to-end timing का संबंध कमज़ोर होता है।

**Detection:** correlation windows बढ़ाएँ, periodic queue access को model करें और endpoint staging की जाँच करें। Batching signal को packet timing से scheduled process/file behavior में ले जाती है; उसे मिटाती नहीं है।

## Design review: observers के नज़रिए से सोचें

हर path के लिए deployment से पहले और collection के बाद यह table भरें:

| Layer | Source दिखता है? | Destination दिखता है? | Content दिखता है? | स्थिर identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

अगर कोई एक सामान्य provider हर column भर सकता है, तो architecture target से concealment देता है, लेकिन मज़बूत separation नहीं। अगर कोई भी internal controller activity को engagement से नहीं जोड़ सकता, तो यह professional red teaming के लिए अनुपयुक्त है।

## References

- [1] [MITRE ATT&CK — Infrastructure प्राप्त करना (T1583), Infrastructure Compromise करना (T1584), और Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors, ORB networks का उपयोग करते हैं](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastructure Compromise करना: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Accounts स्थापित करना (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — दुनिया के सबसे बड़े Residential Proxy Network को बाधित करना](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: वैश्विक जासूसी का खुलासा](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign ने Iraqi Infrastructure को निशाना बनाया](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI ने Overlays बनाए। Victims के PIN खो गए](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — हस्ताक्षरित ChatGPT और Claude Binaries के ज़रिए पुराने Tricks का इस्तेमाल](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
