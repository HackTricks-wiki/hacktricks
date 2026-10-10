# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## परिचय

Phishing के प्रयास का पता लगाने के लिए **आजकल इस्तेमाल की जा रही phishing techniques को समझना** ज़रूरी है। इस पोस्ट के parent page पर आपको यह जानकारी मिल सकती है। इसलिए, अगर आपको पता नहीं है कि आज कौन-सी techniques इस्तेमाल की जा रही हैं, तो मेरा सुझाव है कि आप parent page पर जाकर कम-से-कम वह section पढ़ें।

यह पोस्ट इस विचार पर आधारित है कि **attackers किसी तरह victim के domain name की नकल करने या उसका इस्तेमाल करने की कोशिश करेंगे**। अगर आपके domain का नाम `example.com` है और किसी वजह से आपको `youwonthelottery.com` जैसे बिल्कुल अलग domain name का इस्तेमाल करके phish किया जाता है, तो ये techniques उसका पता नहीं लगा पाएंगी।

## Domain name में बदलाव

ईमेल में **मिलते-जुलते domain name** का इस्तेमाल करने वाले **phishing** प्रयासों को **पकड़ना** काफी **आसान** है।\
इसके लिए बस **उन सबसे संभावित phishing names की सूची बनानी** होती है जिनका attacker इस्तेमाल कर सकता है और **जाँचना** होता है कि वे **registered** हैं या नहीं, या यह देखना होता है कि कोई **IP** उनका इस्तेमाल कर रहा है या नहीं।

### संदिग्ध domains खोजना

इस काम के लिए आप इनमें से कोई भी tool इस्तेमाल कर सकते हैं। दोनों candidate domains को resolve करके जाँचते हैं कि वे इस्तेमाल में हैं या नहीं।<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

सुझाव: अगर आप candidate list बनाते हैं, तो उसे अपने DNS resolver logs में भी डालें, ताकि **आपके org के अंदर से होने वाली NXDOMAIN lookups** का पता लगाया जा सके (यानी users किसी typo पर पहुँचने की कोशिश कर रहे हों, इससे पहले कि attacker उसे register करे)। अगर policy अनुमति देती है, तो इन domains को sinkhole करें या पहले से block कर दें।

### Bitflipping

**संक्षिप्त विवरण के लिए parent page देखें; Windows.com bitsquatting पर मूल शोध के लिए [Remy Hax की write-up](https://remyhax.xyz/posts/bitsquatting-windows/) और [BleepingComputer की report](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) देखें**।<sup>[[1]](#references)[[2]](#references)</sup>

उदाहरण के लिए, domain microsoft.com में 1 bit का बदलाव उसे _windnws.com_ में बदल सकता है।\
**Attackers victim से संबंधित जितने संभव हों उतने bit-flipping domains register कर सकते हैं, ताकि वैध users को उनके infrastructure पर redirect किया जा सके**।<sup>[[1]](#references)[[2]](#references)</sup>

**सभी संभावित bit-flipping domain names को भी monitor किया जाना चाहिए।**

अगर आपको homoglyph/IDN lookalikes (जैसे Latin/Cyrillic characters को मिलाकर लिखे गए नाम) पर भी ध्यान देना है, तो देखें:

{{#ref}}
homograph-attacks.md
{{#endref}}

### बुनियादी जाँच

संभावित संदिग्ध domain names की सूची मिलने के बाद आपको उन्हें (मुख्य रूप से HTTP और HTTPS ports पर) **जाँचना** चाहिए, ताकि **पता चले कि वे victim के domain के किसी login form से मिलता-जुलता form इस्तेमाल कर रहे हैं या नहीं**।\
आप port 3333 को भी जाँच सकते हैं कि वह खुला है और उस पर `gophish` का instance चल रहा है या नहीं।\
यह जानना भी दिलचस्प है कि **पता लगाए गए हर संदिग्ध domain की उम्र कितनी है**—जितना नया होगा, उतना ही जोखिम भरा होगा।\
आप संदिग्ध HTTP और/या HTTPS web page के **screenshots** भी ले सकते हैं, ताकि पता चले कि वह संदिग्ध है या नहीं; और अगर है, तो **ज़्यादा गहराई से जाँचने के लिए उस तक पहुँचें**।

### उन्नत जाँच

अगर आप एक कदम आगे जाना चाहते हैं, तो मेरा सुझाव है कि आप **उन संदिग्ध domains को monitor करें और समय-समय पर नए domains खोजें** (हर दिन? इसमें बस कुछ seconds/minutes लगते हैं)। आपको संबंधित IPs के खुले **ports** भी **जाँचने** चाहिए और **`gophish` या ऐसे ही tools के instances खोजने चाहिए** (हाँ, attackers से भी गलतियाँ होती हैं)। साथ ही, संदिग्ध domains और subdomains के HTTP और HTTPS web pages को **monitor करें**, ताकि पता चले कि उन्होंने victim के web pages से कोई login form copy किया है या नहीं।\
इसे **automate करने** के लिए मेरा सुझाव है कि victim के domains के login forms की सूची रखें, संदिग्ध web pages को spider करें और संदिग्ध domains में मिले हर login form की तुलना victim के domain के हर login form से `ssdeep` जैसे tool का इस्तेमाल करके करें।\
अगर आपको संदिग्ध domains के login forms मिल गए हैं, तो आप **junk credentials भेजकर** **जाँच सकते हैं कि वे आपको victim के domain पर redirect करते हैं या नहीं**।

---

### Favicon और web fingerprints से खोज (Shodan/Censys)

कई phishing kits उस brand के favicons का फिर से इस्तेमाल करते हैं जिसकी वे नकल करते हैं। Shodan, base64-encoded favicon data का MurmurHash3 hash बनाता है, जबकि Censys अपने favicon hash fields दिखाता है।<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> आप Shodan-compatible hash बना सकते हैं और उसके आधार पर खोज कर सकते हैं:

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
- Favicons का दोबारा उपयोग होता है; matches को leads मानें और कार्रवाई करने से पहले content और certs validate करें।
- बेहतर precision के लिए domain-age और keyword heuristics को मिलाएँ।

### URL telemetry की खोज (urlscan.io)

`urlscan.io` सबमिट किए गए URLs के historical screenshots, DOM, requests और TLS metadata स्टोर करता है। आप brand abuse और clones की खोज कर सकते हैं:<sup>[[8]](#references)</sup>

उदाहरण queries (UI या API):
- अपने वैध domains को छोड़कर मिलते-जुलते domains खोजें: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- अपनी assets को hotlink करने वाली sites खोजें: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- हाल के results तक सीमित रखें: `AND date:>now-7d` जोड़ें

API का उदाहरण:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

JSON से इन पर pivot करें:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` से lookalikes के लिए बहुत नए certs पहचानें
- `task.source` जैसे `certstream-suspicious` से findings को CT monitoring से जोड़ें

### RDAP के ज़रिए domain age (scriptable)

RDAP machine-readable registration events देता है। **नए registered domains (NRDs)** को flag करने के लिए उपयोगी।<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

अपने pipeline को registration age buckets (जैसे, <7 दिन, <30 दिन) के साथ domains टैग करके बेहतर बनाएं और उसके अनुसार triage को प्राथमिकता दें।

### AiTM infrastructure की पहचान के लिए TLS/JAx fingerprints

Credential-phishing में session tokens चुराने के लिए **Adversary-in-the-Middle (AiTM)** reverse proxies (जैसे, Evilginx) का इस्तेमाल हो सकता है।<sup>[[11]](#references)</sup> आप network-side detections जोड़ सकते हैं:

- Egress पर TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) लॉग करें। Evilginx के कुछ builds में स्थिर JA4 client/server values देखे गए हैं। ज्ञात-बुरे fingerprints पर केवल कमजोर संकेत के रूप में alert करें और हमेशा content तथा domain intel से पुष्टि करें।<sup>[[12]](#references)</sup>
- CT या urlscan के ज़रिए मिले lookalike hosts के लिए TLS certificate metadata (issuer, SAN count, wildcard use, validity) सक्रिय रूप से रिकॉर्ड करें और इसे DNS age तथा geolocation के साथ correlate करें।

> Note: Fingerprints को enrichment की तरह लें, अकेले blockers की तरह नहीं; frameworks विकसित होते रहते हैं और fingerprints को randomise या obfuscate किया जा सकता है।

### Keywords का इस्तेमाल करने वाले domain names

Parent page में domain name variation technique का भी उल्लेख है, जिसमें **victim का domain name किसी बड़े domain के भीतर रखा जाता है** (जैसे, paypal.com के लिए paypal-financial.com)।

#### Certificate Transparency

Certificate Transparency (CT) logs में certificate identities दिखाई देती हैं, इसलिए Subject या SAN names में brand keywords खोजने से lookalike domains का पता चल सकता है (उदाहरण के लिए, `paypal-financial.com` के certificate में `paypal` keyword दिखाई देता है)। ज़रूरत पड़ने पर results को issuance date और CA के आधार पर filter करें, और संभावित domains की पुष्टि करें, क्योंकि keyword matches false positives हो सकते हैं।<sup>[[13]](#references)</sup>

Patrik Hudak का मूल [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) Censys में इस workflow को दिखाता है, जिसमें certificate date और Let's Encrypt जैसे issuer के filters शामिल हैं।<sup>[[13]](#references)</sup>

![Lookalike domains की पहचान के लिए इस्तेमाल किए गए Censys certificate search results](<../../images/image (1115).png>)

आप keyword खोजने और results को date तथा CA के आधार पर filter करने के लिए मुफ्त [**crt.sh**](https://crt.sh) service का भी इस्तेमाल कर सकते हैं।<sup>[[13]](#references)</sup>

![संदिग्ध certificate identities के लिए crt.sh keyword search](<../../images/image (519).png>)

इसका Matching Identities field असली domain की identities की संदिग्ध domains से तुलना करने में मदद कर सकता है, लेकिन matches को सबूत नहीं, बल्कि आगे जांच के संकेत मानें।<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) लगभग real time में CT updates stream करता है, और [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) संदिग्ध certificate names को score करने के लिए उस stream का इस्तेमाल करता है।<sup>[[14]](#references)[[15]](#references)</sup>

व्यावहारिक सुझाव: CT hits की triage करते समय NRDs, untrusted/unknown registrars, privacy-proxy WHOIS और हाल ही के `NotBefore` times वाले certs को प्राथमिकता दें। शोर कम करने के लिए अपने स्वामित्व वाले domains/brands की allowlist बनाए रखें।

#### **नए domains**

दूसरा विकल्प है TLD के अनुसार नए registered domains इकट्ठा करना (उदाहरण के लिए, [Whoxy](https://www.whoxy.com/newly-registered-domains/) के ज़रिए) और brand keywords के लिए filter करना। इससे subdomains पर host की गई phishing का पता नहीं चलता, जब registered domain में keyword मौजूद न हो।<sup>[[13]](#references)</sup>

अतिरिक्त heuristic: कुछ **file-extension TLDs** (जैसे, `.zip`, `.mov`) को alerting में अतिरिक्त संदेह के साथ लें। Lures में इन्हें अक्सर filenames समझ लिया जाता है; बेहतर precision के लिए TLD signal को brand keywords और NRD age के साथ मिलाएं।

## References

- [1] [Remy Hax – Windows.com पर Bitsquatting](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Bitflipping के ज़रिए Microsoft के windows.com पर traffic hijack करना](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [गहन विश्लेषण: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol सहायता](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol के लिए JSON Responses](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: cloud token theft को रोकना, पहचानना और उसका जवाब देना](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing की खोज: Tools और Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream का परिचय](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
