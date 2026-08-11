# Phishing का पता लगाना

{{#include ../../banners/hacktricks-training.md}}

## परिचय

Phishing प्रयास का पता लगाने के लिए **आजकल उपयोग की जा रही phishing techniques को समझना** महत्वपूर्ण है। इस पोस्ट के parent page पर आपको यह जानकारी मिल सकती है, इसलिए यदि आपको यह जानकारी नहीं है कि आज कौन-सी techniques उपयोग की जा रही हैं, तो मेरा सुझाव है कि आप parent page पर जाएं और कम से कम उस section को पढ़ें।

यह पोस्ट इस विचार पर आधारित है कि **attackers किसी न किसी तरह victim के domain name की नकल करने या उसका उपयोग करने का प्रयास करेंगे**। यदि आपके domain का नाम `example.com` है और किसी कारण से आपको `youwonthelottery.com` जैसे पूरी तरह अलग domain name का उपयोग करके phish किया जाता है, तो ये techniques उसका पता नहीं लगा पाएंगी।

## Domain name में बदलाव

Email के अंदर **similar domain** name का उपयोग करने वाले **phishing** प्रयासों का **पता लगाना** काफी **आसान** है।\
इतना करना पर्याप्त है कि **सबसे संभावित phishing names की एक list तैयार की जाए**, जिन्हें attacker उपयोग कर सकता है और **जांच की जाए** कि वे **registered** हैं या नहीं, अथवा केवल यह जांचा जाए कि क्या कोई **IP** उनका उपयोग कर रहा है।

### संदिग्ध domains का पता लगाना

इस उद्देश्य के लिए आप निम्नलिखित में से किसी भी tool का उपयोग कर सकते हैं। दोनों candidate domains को resolve करके जांचते हैं कि वे उपयोग में हैं या नहीं।<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

सुझाव: यदि आप candidate list तैयार करते हैं, तो उसे अपने DNS resolver logs में भी feed करें, ताकि **अपने org के अंदर से होने वाले NXDOMAIN lookups** का पता लगाया जा सके (जब users attacker के domain को वास्तव में register करने से पहले किसी typo वाले domain तक पहुंचने का प्रयास करते हैं)। यदि policy अनुमति देती है, तो इन domains को Sinkhole करें या पहले से block कर दें।

### Bitflipping

**संक्षिप्त विवरण के लिए parent page देखें; primary Windows.com bitsquatting research के लिए [Remy Hax's write-up](https://remyhax.xyz/posts/bitsquatting-windows/) और [BleepingComputer's report](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) देखें।**<sup>[[1]](#references)[[2]](#references)</sup>

उदाहरण के लिए, domain microsoft.com में 1 bit modification इसे _windnws.com_ में बदल सकती है।\
**Attackers victim से संबंधित अधिक से अधिक bit-flipping domains register कर सकते हैं, ताकि legitimate users को अपने infrastructure पर redirect किया जा सके**।<sup>[[1]](#references)[[2]](#references)</sup>

**सभी संभावित bit-flipping domain names की भी निगरानी की जानी चाहिए।**

यदि आपको homoglyph/IDN lookalikes पर भी विचार करना है (जैसे Latin/Cyrillic characters को मिलाना), तो देखें:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

संभावित संदिग्ध domain names की list तैयार करने के बाद आपको उन्हें **जांचना** चाहिए (मुख्य रूप से HTTP और HTTPS ports), ताकि **यह देखा जा सके कि वे victim के domain से मिलते-जुलते किसी login form का उपयोग कर रहे हैं या नहीं**।\
आप port 3333 की भी जांच कर सकते हैं, ताकि पता चल सके कि वह खुला है और `gophish` का कोई instance चल रहा है या नहीं।\
यह जानना भी उपयोगी है कि **मिले हुए प्रत्येक संदिग्ध domain की उम्र कितनी है**; domain जितना नया होगा, जोखिम उतना ही अधिक होगा।\
आप संदिग्ध HTTP और/या HTTPS web page के **screenshots** भी ले सकते हैं, ताकि पता चल सके कि वह संदिग्ध है या नहीं और ऐसी स्थिति में **अधिक गहराई से जांच करने के लिए उस तक पहुंचा जा सके**।

### Advanced checks

यदि आप एक कदम आगे जाना चाहते हैं, तो मेरा सुझाव है कि आप **उन संदिग्ध domains की निगरानी करें और समय-समय पर (हर दिन? इसमें केवल कुछ seconds/minutes लगते हैं) और अधिक domains खोजें**। आपको संबंधित IPs के खुले हुए **ports** की भी **जांच करनी चाहिए** और **`gophish` या इसी तरह के tools के instances की खोज करनी चाहिए** (हां, attackers भी गलतियां करते हैं), साथ ही **संदिग्ध domains और subdomains के HTTP और HTTPS web pages की निगरानी करनी चाहिए**, ताकि पता चल सके कि उन्होंने victim के web pages से कोई login form copy किया है या नहीं।\
इसे **automate करने** के लिए मेरा सुझाव है कि victim के domains के login forms की एक list रखें, संदिग्ध web pages को spider करें और संदिग्ध domains के अंदर मिले प्रत्येक login form की तुलना victim के domain के प्रत्येक login form से `ssdeep` जैसे tool का उपयोग करके करें।\
यदि आपने संदिग्ध domains के login forms ढूंढ लिए हैं, तो आप **junk credentials भेजने** का प्रयास कर सकते हैं और **जांच सकते हैं कि क्या वह आपको victim के domain पर redirect कर रहा है**।

---

### favicon और web fingerprints द्वारा Hunting (Shodan/Censys)

कई phishing kits उस brand के favicons का दोबारा उपयोग करते हैं जिसका वे impersonate कर रहे होते हैं। Shodan अपने base64-encoded favicon data को MurmurHash3 से hash करता है, जबकि Censys अपने favicon hash fields उपलब्ध कराता है।<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> आप Shodan-compatible hash generate करके उस पर pivot कर सकते हैं:

Python उदाहरण (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan पर query करें: `http.favicon.hash:309020573`
- Tooling के साथ: hashes calculate करने और Shodan dorks generate करने के लिए favfreak जैसे community tools देखें।<sup>[[16]](#references)</sup>

Notes
- Favicons का पुनः उपयोग किया जाता है; matches को leads मानें और कार्रवाई करने से पहले content और certs को validate करें।
- बेहतर precision के लिए इसे domain-age और keyword heuristics के साथ combine करें।

### URL telemetry hunting (urlscan.io)

`urlscan.io` submitted URLs के historical screenshots, DOM, requests और TLS metadata को store करता है। आप brand abuse और clones के लिए hunt कर सकते हैं:<sup>[[8]](#references)</sup>

Example queries (UI या API):
- अपने legit domains को exclude करके lookalikes खोजें: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- आपकी assets को hotlink करने वाली sites खोजें: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Recent results तक सीमित करें: अंत में `AND date:>now-7d` जोड़ें

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON से इन पर pivot करें:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` का उपयोग lookalikes के लिए बहुत नए certificates पहचानने हेतु करें
- `task.source` में `certstream-suspicious` जैसे values का उपयोग findings को CT monitoring से जोड़ने हेतु करें

### RDAP के माध्यम से Domain age (scriptable)

RDAP machine-readable registration events लौटाता है। यह **newly registered domains (NRDs)** को flag करने के लिए उपयोगी है।<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
अपने pipeline को registration age buckets (जैसे, <7 days, <30 days) के साथ domains को tag करके enrich करें और उसके अनुसार triage को प्राथमिकता दें।

### AiTM infrastructure को पहचानने के लिए TLS/JAx fingerprints

Credential-phishing में session tokens चुराने के लिए **Adversary-in-the-Middle (AiTM)** reverse proxies (जैसे, Evilginx) का उपयोग किया जा सकता है।<sup>[[11]](#references)</sup> आप network-side detections जोड़ सकते हैं:

- Egress पर TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) log करें। कुछ Evilginx builds में स्थिर JA4 client/server values देखे गए हैं। Known-bad fingerprints पर केवल weak signal के रूप में alert करें और हमेशा content तथा domain intel से पुष्टि करें।<sup>[[12]](#references)</sup>
- CT या urlscan के माध्यम से खोजे गए lookalike hosts के लिए TLS certificate metadata (issuer, SAN count, wildcard use, validity) proactively record करें और इसे DNS age तथा geolocation के साथ correlate करें।

> Note: Fingerprints को enrichment के रूप में लें, sole blockers के रूप में नहीं; frameworks विकसित होते रहते हैं और fingerprints को randomise या obfuscate कर सकते हैं।

### Keywords का उपयोग करने वाले domain names

Parent page में एक domain name variation technique का भी उल्लेख है, जिसमें **victim's domain name को किसी बड़े domain के अंदर रखा जाता है** (जैसे, paypal.com के लिए paypal-financial.com)।

#### Certificate Transparency

Certificate Transparency (CT) logs certificate identities को expose करते हैं, इसलिए Subject या SAN names में brand keywords खोजने से lookalike domains का पता चल सकता है (उदाहरण के लिए, `paypal-financial.com` का certificate `paypal` keyword को expose करता है)। उपयोगी होने पर results को issuance date और CA के आधार पर filter करें, और candidates को validate करें क्योंकि keyword matches false positives हो सकते हैं।<sup>[[13]](#references)</sup>

Patrik Hudak का मूल [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) इस workflow को Censys में प्रदर्शित करता है, जिसमें certificate date और issuer, जैसे Let's Encrypt, के filters शामिल हैं।<sup>[[13]](#references)</sup>

आप free [**crt.sh**](https://crt.sh) service का उपयोग keyword खोजने और results को date तथा CA के आधार पर filter करने के लिए भी कर सकते हैं।<sup>[[13]](#references)</sup>

इसका Matching Identities field real domain की identities की suspicious domains के साथ तुलना करने में सहायता कर सकता है, लेकिन matches को proof के बजाय leads मानें।<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) लगभग real time में CT updates stream करता है, और [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) suspicious certificate names को score करने के लिए उस stream का उपयोग करता है।<sup>[[14]](#references)[[15]](#references)</sup>

Practical tip: CT hits को triage करते समय NRDs, untrusted/unknown registrars, privacy-proxy WHOIS, और बहुत हाल के `NotBefore` times वाले certs को प्राथमिकता दें। Noise कम करने के लिए अपने owned domains/brands की allowlist बनाए रखें।

#### **New domains**

दूसरा विकल्प TLD के अनुसार newly registered domains collect करना (उदाहरण के लिए, [Whoxy](https://www.whoxy.com/newly-registered-domains/) के माध्यम से) और brand keywords के लिए filter करना है। जब keyword registered domain में मौजूद नहीं होता, तो यह subdomains पर hosted phishing को miss कर देता है।<sup>[[13]](#references)</sup>

Additional heuristic: alerting में कुछ **file-extension TLDs** (जैसे, `.zip`, `.mov`) को extra suspicion के साथ treat करें। Lures में इन्हें अक्सर filenames समझ लिया जाता है; बेहतर precision के लिए TLD signal को brand keywords और NRD age के साथ combine करें।

## References

- [1] [Remy Hax – Windows.com की Bitsquatting](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Bitflipping के साथ Microsoft's windows.com के traffic को hijack करना](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Deep Dive: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol के लिए JSON Responses](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: cloud token theft को रोकने, detect करने और respond करने के तरीके](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream का परिचय](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
