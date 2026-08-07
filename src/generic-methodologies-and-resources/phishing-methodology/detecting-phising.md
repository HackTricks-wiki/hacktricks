# Phishing का पता लगाना

{{#include ../../banners/hacktricks-training.md}}

## परिचय

Phishing attempt का पता लगाने के लिए **आजकल उपयोग की जा रही phishing techniques को समझना** महत्वपूर्ण है। इस post के parent page पर आपको यह जानकारी मिल सकती है, इसलिए यदि आपको आज उपयोग की जा रही techniques के बारे में जानकारी नहीं है, तो मेरा सुझाव है कि आप parent page पर जाएं और कम से कम उस section को पढ़ें।

यह post इस विचार पर आधारित है कि **attackers किसी तरह victim के domain name की नकल करने या उसका उपयोग करने का प्रयास करेंगे**। यदि आपके domain का नाम `example.com` है और किसी कारण से आपको पूरी तरह अलग domain name, जैसे `youwonthelottery.com`, का उपयोग करके phish किया जाता है, तो ये techniques उसका पता नहीं लगा पाएंगी।

## Domain name variations

Email के अंदर **similar domain** name का उपयोग करने वाले **phishing** attempts को **uncover** करना काफी **आसान** है।\
इसके लिए केवल **सबसे संभावित phishing names की एक list generate** करनी होगी, जिनका attacker उपयोग कर सकता है, और **check** करना होगा कि वे **registered** हैं या नहीं, अथवा केवल यह check करना होगा कि उनका उपयोग करने वाला कोई **IP** है या नहीं।

### Suspicious domains ढूंढना

इस उद्देश्य के लिए आप निम्नलिखित में से किसी भी tool का उपयोग कर सकते हैं। ध्यान दें कि ये tools domain को कोई IP assigned है या नहीं, यह check करने के लिए DNS requests भी automatically perform करेंगे:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: यदि आप candidate list generate करते हैं, तो उसे अपने DNS resolver logs में भी feed करें, ताकि **अपने org के अंदर से होने वाले NXDOMAIN lookups** का पता लगाया जा सके (जब users किसी typo वाले domain तक पहुंचने का प्रयास करते हैं, उससे पहले कि attacker उसे register करे)। यदि policy अनुमति देती है, तो इन domains को Sinkhole या पहले से block करें।

### Bitflipping

**आप parent page पर इस technique का संक्षिप्त explanation पा सकते हैं। या मूल research यहां पढ़ें:** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

उदाहरण के लिए, domain microsoft.com में 1 bit modification करने से यह _windnws.com._ में बदल सकता है।\
**Attackers victim से संबंधित अधिक से अधिक bit-flipping domains register कर सकते हैं, ताकि legitimate users को अपने infrastructure पर redirect किया जा सके**।<sup>[[1]](#references)</sup>

**सभी संभावित bit-flipping domain names को भी monitor किया जाना चाहिए।**

यदि आपको homoglyph/IDN lookalikes (जैसे Latin/Cyrillic characters को मिलाना) पर भी विचार करना है, तो देखें:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

Potential suspicious domain names की list मिलने के बाद आपको उन्हें **check** करना चाहिए (मुख्य रूप से HTTP और HTTPS ports), ताकि **यह देखा जा सके कि वे victim के domain से मिलते-जुलते किसी login form का उपयोग कर रहे हैं या नहीं**।\
आप port 3333 को भी check कर सकते हैं, ताकि यह देखा जा सके कि वह open है और `gophish` का कोई instance run कर रहा है या नहीं।\
यह जानना भी उपयोगी है कि **मिले हुए प्रत्येक suspicious domain की आयु कितनी है**; domain जितना नया होगा, risk उतना ही अधिक होगा।\
आप suspicious HTTP और/या HTTPS web page के **screenshots** भी प्राप्त कर सकते हैं, ताकि यह देखा जा सके कि वह suspicious है या नहीं, और ऐसी स्थिति में **अधिक गहराई से जांच करने के लिए उस तक पहुंचा जा सके**।

### Advanced checks

यदि आप एक कदम आगे जाना चाहते हैं, तो मेरा सुझाव है कि आप **उन suspicious domains को monitor करें और समय-समय पर (हर दिन? इसमें केवल कुछ seconds/minutes लगते हैं) और अधिक domains खोजें**। आपको संबंधित IPs के खुले हुए **ports** को भी **check** करना चाहिए और **`gophish` या similar tools के instances खोजने चाहिए** (हां, attackers भी गलतियां करते हैं), साथ ही **suspicious domains और subdomains के HTTP और HTTPS web pages को monitor करना चाहिए**, ताकि यह देखा जा सके कि उन्होंने victim के web pages से कोई login form copy किया है या नहीं।\
इसे **automate करने** के लिए मेरा सुझाव है कि victim के domains के login forms की एक list रखें, suspicious web pages को spider करें और suspicious domains के अंदर मिले प्रत्येक login form की तुलना victim के domain के प्रत्येक login form से `ssdeep` जैसे tool का उपयोग करके करें।\
यदि आपको suspicious domains के login forms मिल गए हैं, तो आप **junk credentials send** करने का प्रयास कर सकते हैं और **check कर सकते हैं कि क्या यह आपको victim के domain पर redirect कर रहा है**।

---

### favicon और web fingerprints (Shodan/ZoomEye/Censys के माध्यम से) द्वारा Hunting

कई phishing kits उस brand के favicons को reuse करते हैं जिसका वे impersonate करते हैं। Internet-wide scanners base64-encoded favicon का MurmurHash3 compute करते हैं। आप hash generate करके उसके आधार पर pivot कर सकते हैं:

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan पर query करें: `http.favicon.hash:309020573`
- Tooling के साथ: hashes और Shodan/ZoomEye/Censys के लिए dorks generate करने हेतु favfreak जैसे community tools देखें।

Notes
- Favicons दोबारा उपयोग किए जाते हैं; matches को leads मानें और कार्रवाई करने से पहले content और certs को validate करें।
- बेहतर precision के लिए domain-age और keyword heuristics को combine करें।

### URL telemetry hunting (urlscan.io)

`urlscan.io` submitted URLs के historical screenshots, DOM, requests और TLS metadata को store करता है। आप brand abuse और clones के लिए hunt कर सकते हैं:<sup>[[2]](#references)</sup>

Example queries (UI or API):
- अपने legit domains को exclude करके lookalikes खोजें: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- आपकी assets को hotlink करने वाली sites खोजें: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Results को recent तक सीमित करें: `AND date:>now-7d` जोड़ें

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON से इन पर pivot करें:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` का उपयोग lookalikes के लिए बहुत नए certificates पहचानने हेतु करें
- `task.source` जैसी values, जैसे `certstream-suspicious`, का उपयोग findings को CT monitoring से जोड़ने के लिए करें

### RDAP के माध्यम से domain age (scriptable)

RDAP machine-readable creation events लौटाता है। यह **नए registered domains (NRDs)** को flag करने के लिए उपयोगी है।
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
अपने pipeline को registration age buckets (जैसे, <7 days, <30 days) के साथ domains को tag करके समृद्ध करें और उसके अनुसार triage को प्राथमिकता दें।

### AiTM infrastructure को पहचानने के लिए TLS/JAx fingerprints

Modern credential-phishing में session tokens चुराने के लिए **Adversary-in-the-Middle (AiTM)** reverse proxies (जैसे, Evilginx) का उपयोग तेजी से बढ़ रहा है। आप network-side detections जोड़ सकते हैं:

- Egress पर TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) log करें। कुछ Evilginx builds में स्थिर JA4 client/server values देखे गए हैं। Known-bad fingerprints पर केवल weak signal के रूप में alert करें और हमेशा content तथा domain intel से पुष्टि करें।<sup>[[3]](#references)</sup>
- CT या urlscan से खोजे गए lookalike hosts के लिए TLS certificate metadata (issuer, SAN count, wildcard use, validity) को proactively record करें और DNS age तथा geolocation के साथ correlate करें।

> Note: Fingerprints को enrichment के रूप में मानें, sole blockers के रूप में नहीं; frameworks विकसित होते रहते हैं और उन्हें randomise या obfuscate किया जा सकता है।

### Keywords का उपयोग करने वाले domain names

Parent page में domain name variation technique का भी उल्लेख है, जिसमें **victim के domain name को किसी बड़े domain के अंदर रखा जाता है** (जैसे, paypal.com के लिए paypal-financial.com)।

#### Certificate Transparency

पिछले "Brute-Force" approach को अपनाना संभव नहीं है, लेकिन certificate transparency की सहायता से ऐसे phishing attempts को **uncover करना संभव है**। जब भी किसी CA द्वारा certificate emit किया जाता है, उसके details public किए जाते हैं। इसका अर्थ है कि certificate transparency को पढ़कर या monitor करके **ऐसे domains खोजे जा सकते हैं जिनके name में कोई keyword मौजूद हो**। उदाहरण के लिए, यदि कोई attacker [https://paypal-financial.com](https://paypal-financial.com) का certificate generate करता है, तो certificate देखकर "paypal" keyword खोजना और यह जानना संभव है कि suspicious email का उपयोग किया जा रहा है।

[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) post सुझाव देती है कि आप किसी specific keyword को प्रभावित करने वाले certificates को खोजने के लिए Censys का उपयोग कर सकते हैं और उन्हें date (केवल "new" certificates) तथा CA issuer "Let's Encrypt" के आधार पर filter कर सकते हैं:<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

हालांकि, आप free web [**crt.sh**](https://crt.sh) का उपयोग करके "the same" कर सकते हैं। आप **keyword के लिए search** कर सकते हैं और यदि चाहें तो results को **date और CA के आधार पर filter** कर सकते हैं।

![Domain names using keywords - Certificate Transparency: हालांकि, आप free web crt.sh का उपयोग करके "the same" कर सकते हैं। आप keyword के लिए search कर सकते हैं और results को date तथा...](<../../images/image (519).png>)

इस अंतिम option का उपयोग करके आप Matching Identities field से यह भी देख सकते हैं कि क्या real domain की कोई identity suspicious domains में से किसी से match करती है (ध्यान दें कि suspicious domain false positive हो सकता है)।

**एक अन्य alternative** शानदार project [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) है। CertStream नए generated certificates की real-time stream प्रदान करता है, जिसका उपयोग आप (near) real-time में specified keywords का पता लगाने के लिए कर सकते हैं। वास्तव में, [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) नाम का एक project है जो यही कार्य करता है।

Practical tip: CT hits को triage करते समय NRDs, untrusted/unknown registrars, privacy-proxy WHOIS और बहुत हाल के `NotBefore` times वाले certs को प्राथमिकता दें। Noise कम करने के लिए अपने owned domains/brands की allowlist बनाए रखें।

#### **New domains**

**एक अंतिम alternative** कुछ TLDs के लिए **newly registered domains** की list एकत्र करना है ([Whoxy](https://www.whoxy.com/newly-registered-domains/) ऐसी service प्रदान करता है) और इन domains में **keywords check करना** है। हालांकि, लंबे domains आमतौर पर एक या अधिक subdomains का उपयोग करते हैं; इसलिए keyword FLD के अंदर दिखाई नहीं देगा और आप phishing subdomain को खोज नहीं पाएंगे।

Additional heuristic: alerting में कुछ **file-extension TLDs** (जैसे, `.zip`, `.mov`) को अतिरिक्त suspicion के साथ treat करें। Lures में इन्हें अक्सर filenames समझ लिया जाता है; बेहतर precision के लिए TLD signal को brand keywords और NRD age के साथ combine करें।

## References

- [1] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
