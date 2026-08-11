# Phishing का पता लगाना

{{#include ../../banners/hacktricks-training.md}}

## परिचय

Phishing प्रयास का पता लगाने के लिए **आजकल उपयोग की जा रही phishing techniques को समझना** महत्वपूर्ण है। इस पोस्ट के parent page पर आपको यह जानकारी मिल सकती है, इसलिए यदि आपको आज उपयोग की जा रही techniques की जानकारी नहीं है, तो मैं आपको parent page पर जाकर कम-से-कम वह section पढ़ने की सलाह देता हूं।

यह पोस्ट इस विचार पर आधारित है कि **attackers किसी न किसी तरह victim के domain name की नकल करने या उसका उपयोग करने का प्रयास करेंगे**। यदि आपके domain का नाम `example.com` है और किसी कारण से आपको पूरी तरह अलग domain name, जैसे `youwonthelottery.com`, का उपयोग करके phish किया जाता है, तो ये techniques उसका पता नहीं लगा पाएंगी।

## Domain name में बदलाव

Email के अंदर **similar domain** name का उपयोग करने वाले **phishing** प्रयासों का **पता लगाना** काफी **आसान** है।\
इसके लिए केवल **सबसे संभावित phishing names की एक सूची बनाना** और **जांचना** पर्याप्त है कि वे **registered** हैं या नहीं, अथवा केवल यह जांचना कि उनका उपयोग करने वाला कोई **IP** है या नहीं।

### संदिग्ध domains का पता लगाना

इस उद्देश्य के लिए आप निम्नलिखित में से किसी भी tool का उपयोग कर सकते हैं। दोनों candidate domains को resolve करके यह जांचते हैं कि वे उपयोग में हैं या नहीं।<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

सुझाव: यदि आप candidate list बनाते हैं, तो उसे अपने DNS resolver logs में भी feed करें, ताकि **अपने org के अंदर से होने वाले NXDOMAIN lookups** का पता लगाया जा सके (जब users किसी typo वाले domain तक पहुंचने का प्रयास करते हैं, इससे पहले कि attacker उसे वास्तव में register करे)। यदि policy इसकी अनुमति देती है, तो इन domains को sinkhole करें या पहले से block कर दें।

### Bitflipping

**संक्षिप्त विवरण के लिए parent page देखें; primary Windows.com bitsquatting research के लिए [Remy Hax's write-up](https://remyhax.xyz/posts/bitsquatting-windows/) और [BleepingComputer's report](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) देखें**।<sup>[[1]](#references)[[2]](#references)</sup>

उदाहरण के लिए, domain microsoft.com में 1 bit का modification इसे _windnws.com._ में बदल सकता है।\
**Attackers victim से संबंधित अधिक-से-अधिक bit-flipping domains register कर सकते हैं, ताकि legitimate users को अपने infrastructure पर redirect किया जा सके**।<sup>[[1]](#references)[[2]](#references)</sup>

**सभी संभावित bit-flipping domain names की भी निगरानी की जानी चाहिए।**

यदि आपको homoglyph/IDN lookalikes पर भी विचार करना है (जैसे Latin/Cyrillic characters को मिलाना), तो देखें:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

संभावित संदिग्ध domain names की सूची मिलने के बाद आपको उन्हें **जांचना** चाहिए (मुख्य रूप से HTTP और HTTPS ports), ताकि **यह देखा जा सके कि वे victim के domain से मिलते-जुलते किसी login form का उपयोग कर रहे हैं या नहीं**।\
आप port 3333 को भी जांच सकते हैं, ताकि यह देखा जा सके कि वह open है और `gophish` का कोई instance चल रहा है या नहीं।\
यह जानना भी उपयोगी है कि पाए गए प्रत्येक संदिग्ध domain की **उम्र कितनी है**; domain जितना नया होगा, जोखिम उतना ही अधिक होगा।\
आप संदिग्ध HTTP और/या HTTPS web page के **screenshots** भी ले सकते हैं, ताकि यह देखा जा सके कि वह संदिग्ध है या नहीं, और ऐसी स्थिति में **अधिक गहराई से जांच करने के लिए उस तक पहुंच सकें**।

### Advanced checks

यदि आप एक कदम आगे जाना चाहते हैं, तो मैं आपको **उन संदिग्ध domains की निगरानी करने और समय-समय पर और domains खोजने** (हर दिन? इसमें केवल कुछ seconds/minutes लगते हैं) की सलाह देता हूं। आपको संबंधित IPs के open **ports** भी **जांचने** चाहिए और **`gophish` या इसी तरह के tools के instances खोजने चाहिए** (हां, attackers भी गलतियां करते हैं), साथ ही **संदिग्ध domains और subdomains के HTTP और HTTPS web pages की निगरानी करनी चाहिए**, ताकि यह देखा जा सके कि उन्होंने victim के web pages से कोई login form copy किया है या नहीं।\
इसे **automate करने** के लिए मैं victim के domains के login forms की एक सूची रखने, संदिग्ध web pages को spider करने और संदिग्ध domains के अंदर मिले प्रत्येक login form की तुलना victim के domain के प्रत्येक login form से `ssdeep` जैसे tool का उपयोग करके करने की सलाह देता हूं।\
यदि आपने संदिग्ध domains के login forms का पता लगा लिया है, तो आप **junk credentials भेजने** और **यह जांचने** का प्रयास कर सकते हैं कि क्या वे आपको victim के domain पर redirect कर रहे हैं।

---

### favicon और web fingerprints द्वारा Hunting (Shodan/Censys)

कई phishing kits उस brand के favicons का पुनः उपयोग करते हैं जिसकी वे नकल कर रहे होते हैं। Shodan अपने base64-encoded favicon data को MurmurHash3 से hash करता है, जबकि Censys अपने favicon hash fields उपलब्ध कराता है।<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> आप Shodan-compatible hash generate करके उस पर pivot कर सकते हैं:

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan पर query करें: `http.favicon.hash:309020573`
- Tooling के साथ: hashes calculate करने और Shodan dorks generate करने के लिए favfreak जैसे community tools देखें।<sup>[[16]](#references)</sup>

नोट्स
- Favicons का पुनः उपयोग किया जाता है; matches को leads की तरह लें और कार्रवाई करने से पहले content और certs को validate करें।
- बेहतर precision के लिए इसे domain-age और keyword heuristics के साथ combine करें।

### URL telemetry hunting (urlscan.io)

`urlscan.io` submit किए गए URLs के historical screenshots, DOM, requests और TLS metadata को store करता है। आप brand abuse और clones के लिए hunt कर सकते हैं:<sup>[[8]](#references)</sup>

Example queries (UI या API):
- अपने legit domains को exclude करते हुए lookalikes खोजें: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- आपकी assets को hotlink करने वाली sites खोजें: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Results को recent तक सीमित करें: `AND date:>now-7d` जोड़ें

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON से इन फ़ील्ड्स पर pivot करें:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` का उपयोग lookalikes के लिए बहुत नए certificates की पहचान करने हेतु करें
- निष्कर्षों को CT monitoring से जोड़ने के लिए `task.source` में `certstream-suspicious` जैसे values देखें

### RDAP के माध्यम से domain age (scriptable)

RDAP machine-readable registration events लौटाता है। इसका उपयोग **नए registered domains (NRDs)** को flag करने के लिए किया जा सकता है।<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
अपने pipeline को registration age buckets (जैसे, <7 days, <30 days) के साथ domains को tag करके enrich करें और उसके अनुसार triage को prioritise करें।

### AiTM infrastructure को पहचानने के लिए TLS/JAx fingerprints

Credential-phishing में session tokens चुराने के लिए **Adversary-in-the-Middle (AiTM)** reverse proxies (जैसे, Evilginx) का उपयोग किया जा सकता है।<sup>[[11]](#references)</sup> आप network-side detections जोड़ सकते हैं:

- Egress पर TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) log करें। कुछ Evilginx builds में stable JA4 client/server values देखे गए हैं। Known-bad fingerprints पर केवल weak signal के रूप में alert करें और हमेशा content तथा domain intel से पुष्टि करें।<sup>[[12]](#references)</sup>
- CT या urlscan के माध्यम से खोजे गए lookalike hosts के लिए TLS certificate metadata (issuer, SAN count, wildcard use, validity) proactively record करें और इसे DNS age तथा geolocation से correlate करें।

> Note: Fingerprints को enrichment के रूप में treat करें, sole blockers के रूप में नहीं; frameworks evolve हो सकते हैं और randomise या obfuscate किए जा सकते हैं।

### Keywords का उपयोग करने वाले domain names

Parent page में एक domain name variation technique का भी उल्लेख है, जिसमें **victim's domain name को किसी बड़े domain के अंदर रखा जाता है** (जैसे, paypal.com के लिए paypal-financial.com)।

#### Certificate Transparency

Certificate Transparency (CT) logs certificate identities को expose करते हैं, इसलिए Subject या SAN names में brand keywords खोजना lookalike domains को reveal कर सकता है (उदाहरण के लिए, `paypal-financial.com` के लिए certificate `paypal` keyword को expose करता है)। उपयोगी होने पर results को issuance date और CA से filter करें, और candidates को validate करें क्योंकि keyword matches false positives हो सकते हैं।<sup>[[13]](#references)</sup>

Patrik Hudak का original [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) Censys में इस workflow को demonstrate करता है, जिसमें certificate date और issuer, जैसे Let's Encrypt, के filters शामिल हैं।<sup>[[13]](#references)</sup>

![Lookalike domains की पहचान के लिए उपयोग किए गए Censys certificate search results](<../../images/image (1115).png>)

आप keyword search करने और results को date तथा CA से filter करने के लिए free [**crt.sh**](https://crt.sh) service का भी उपयोग कर सकते हैं।<sup>[[13]](#references)</sup>

![Suspicious certificate identities के लिए crt.sh keyword search](<../../images/image (519).png>)

इसका Matching Identities field real domain की identities की suspicious domains के साथ तुलना करने में मदद कर सकता है, लेकिन matches को proof के बजाय leads के रूप में treat करें।<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) लगभग real time में CT updates stream करता है, और [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) suspicious certificate names को score करने के लिए उस stream का उपयोग करता है।<sup>[[14]](#references)[[15]](#references)</sup>

Practical tip: CT hits को triage करते समय NRDs, untrusted/unknown registrars, privacy-proxy WHOIS और बहुत recent `NotBefore` times वाले certs को prioritise करें। Noise कम करने के लिए अपने owned domains/brands की allowlist maintain करें।

#### **New domains**

दूसरा विकल्प TLD के अनुसार newly registered domains collect करना (उदाहरण के लिए, [Whoxy](https://www.whoxy.com/newly-registered-domains/) के माध्यम से) और brand keywords के लिए filter करना है। जब keyword registered domain में मौजूद नहीं होता, तो यह subdomains पर hosted phishing को miss कर देता है।<sup>[[13]](#references)</sup>

Additional heuristic: कुछ **file-extension TLDs** (जैसे, `.zip`, `.mov`) को alerting में extra suspicion के साथ treat करें। Lures में इन्हें अक्सर filenames समझ लिया जाता है; बेहतर precision के लिए TLD signal को brand keywords और NRD age के साथ combine करें।

## References

- [1] [Remy Hax – Windows.com पर Bitsquatting](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [bitflipping के साथ Microsoft's windows.com पर traffic hijack करना](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Deep Dive: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol के लिए JSON Responses](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: cloud token theft को prevent, detect और respond कैसे करें](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream का परिचय](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
