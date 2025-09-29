# Phishing का पता लगाना

{{#include ../../banners/hacktricks-training.md}}

## परिचय

Phishing प्रयास का पता लगाने के लिए यह महत्वपूर्ण है कि आप **समझें कि आजकल कौन सी phishing techniques इस्तेमाल हो रही हैं**। इस पोस्ट के parent पेज पर आप यह जानकारी पा सकते हैं, इसलिए अगर आप यह नहीं जानते कि आज किन techniques का उपयोग हो रहा है तो मैं सुझाव दूंगा कि आप parent पेज पर जाएँ और कम से कम उस सेक्शन को पढ़ लें।

यह पोस्ट इस विचार पर आधारित है कि **हमलावर किसी न किसी तरह पीड़ित के domain नाम की नकल करने या उसका उपयोग करने की कोशिश करेंगे**। अगर आपका domain `example.com` है और किसी कारण से आपको पूरी तरह से अलग domain जैसे `youwonthelottery.com` का उपयोग करके phish किया जा रहा है, तो ये techniques उसे उजागर नहीं करेंगी।

## डोमेन नाम के वैरिएशन

उन phishing प्रयासों को उजागर करना जिनमें ईमेल के अंदर समान domain नाम का उपयोग किया गया हो, अपेक्षित रूप से काफी आसान है।\
पर्याप्त है कि आप हमलावर द्वारा इस्तेमाल किए जा सकने वाले सबसे संभावित phishing नामों की एक सूची generate करें और जांचें कि वे **रजिस्टर्ड** हैं या नहीं या बस यह देखें कि क्या कोई **IP** उनका उपयोग कर रहा है।

### संदिग्ध डोमेनों का पता लगाना

इस उद्देश्य के लिए आप निम्न टूल्स में से किसी का उपयोग कर सकते हैं। ध्यान दें कि ये टूल्स स्वतः DNS अनुरोध भी कर के यह जाँचते हैं कि डोमेन को कोई IP असाइन है या नहीं:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: अगर आप एक candidate सूची generate करते हैं, तो इसे अपने DNS resolver लॉग्स में भी फीड करें ताकि आप अपने org के अंदर से होने वाले **NXDOMAIN lookups** का पता लगा सकें (उपयोगकर्ता किसी टाइपो तक पहुँचने की कोशिश कर रहे हैं इससे पहले कि हमलावर वास्तव में उसे रजिस्टर करे)। नीति अनुमति देती है तो इन डोमेनों को Sinkhole या pre-block करें।

### Bitflipping

**You can find a short the explanation of this technique in the parent page. Or read the original research in** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

For example, a 1 bit modification in the domain microsoft.com can transform it into _windnws.com._\
**Attackers may register as many bit-flipping domains as possible related to the victim to redirect legitimate users to their infrastructure**.

**All possible bit-flipping domain names should be also monitored.**

If you also need to consider homoglyph/IDN lookalikes (e.g., mixing Latin/Cyrillic characters), check:

{{#ref}}
homograph-attacks.md
{{#endref}}

### बेसिक जाँच

एक बार जब आपके पास संभावित संदिग्ध डोमेन नामों की सूची हो, तो आपको उन्हें **जांचना** चाहिए (मुख्य रूप से पोर्ट्स HTTP और HTTPS) ताकि यह देखा जा सके कि क्या वे पीड़ित के किसी login form जैसा कोई form उपयोग कर रहे हैं।\
आप पोर्ट 3333 भी चेक कर सकते हैं यह देखने के लिए कि क्या यह खुला है और `gophish` का इंस्टेंस चल रहा है।\
यह भी जानना दिलचस्प होगा कि प्रत्येक खोजे गए संदिग्ध डोमेन की उम्र कितनी है — जितना नया होगा उतना अधिक जोखिम होगा।\
आप HTTP और/या HTTPS संदिग्ध वेब पेज के **screenshots** भी ले सकते हैं ताकि देखें कि यह संदिग्ध है या नहीं और उस स्थिति में **गहरा निरीक्षण करने के लिए इसे access करें**।

### एडवांस्ड जाँच

अगर आप एक कदम आगे जाना चाहते हैं तो मैं सुझाव दूँगा कि आप उन संदिग्ध डोमेनों की निगरानी करें और समय-समय पर (हर दिन?) और नए संदिग्ध डोमेनों की तलाश करें (यह कुछ सेकंड/मिनट ही लेता है)। आपको संबंधित IPs के खुले पोर्ट्स भी जांचने चाहिए और `gophish` या समान tools के इंस्टेंस की खोज करनी चाहिए (हाँ, हमलावर भी गलतियाँ करते हैं) और संदिग्ध डोमेनों और सबडोमेनों के HTTP और HTTPS वेब पेजों की निगरानी करनी चाहिए ताकि देखा जा सके कि क्या उन्होंने पीड़ित के वेब पेजों से कोई लॉगिन फॉर्म कॉपी किया है।\
इसे ऑटोमेट करने के लिए मेरा सुझाव है कि पीड़ित के डोमेनों के लॉगिन फॉर्म्स की एक सूची रखें, संदिग्ध वेब पेजों को spider करें और प्रत्येक पाए गए लॉगिन फॉर्म की तुलना पीड़ित के डोमेन के प्रत्येक लॉगिन फॉर्म से कुछ जैसे `ssdeep` का उपयोग करके करें।\
अगर आपने संदिग्ध डोमेनों के लॉगिन फॉर्म्स का पता लगा लिया है, तो आप जंक क्रेडेंशियल भेजकर यह जांचने की कोशिश कर सकते हैं कि क्या यह आपको पीड़ित के domain पर redirect कर रहा है।

---

### favicon और वेब फिंगरप्रिंट्स से शिकार (Shodan/ZoomEye/Censys)

कई phishing kits उस ब्रांड के favicon को reuse करते हैं जिसकी वे impersonate कर रहे होते हैं। Internet-wide scanners base64-encoded favicon का MurmurHash3 compute करते हैं। आप hash generate कर सकते हैं और उस पर pivot कर सकते हैं:

Python उदाहरण (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan पर क्वेरी: `http.favicon.hash:309020573`
- टूलिंग: favfreak जैसे community tools देखें ताकि Shodan/ZoomEye/Censys के लिए hashes और dorks जनरेट कर सकें।

Notes
- Favicons पुनः उपयोग होते हैं; मेल खाने वाले परिणामों को leads के रूप में मानें और कार्रवाई करने से पहले content और certs को validate करें।
- बेहतर सटीकता के लिए domain-age और keyword heuristics के साथ संयोजन करें।

### URL telemetry hunting (urlscan.io)

`urlscan.io` सबमिट किए गए URLs के historical screenshots, DOM, requests और TLS metadata को स्टोर करता है। आप brand abuse और clones के लिए खोज कर सकते हैं:

Example queries (UI or API):
- Find lookalikes excluding your legit domains: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Find sites hotlinking your assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restrict to recent results: append `AND date:>now-7d`

API उदाहरण:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON से pivot करें:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` का उपयोग lookalikes के लिए बहुत नए certs खोजने के लिए करें
- `task.source` के मान, जैसे `certstream-suspicious`, का उपयोग findings को CT monitoring से जोड़ने के लिए करें

### RDAP के माध्यम से डोमेन उम्र (scriptable)

RDAP मशीन-पठनीय पंजीकरण घटनाएँ लौटाता है। **नए पंजीकृत डोमेन (NRDs)** को चिह्नित करने में उपयोगी।
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
अपनी पाइपलाइन को डोमेनों को उनके registration age buckets (उदा., <7 days, <30 days) के साथ टैग करके समृद्ध करें और तदनुसार triage को प्राथमिकता दें।

### TLS/JAx फिंगरप्रिंट्स से AiTM इन्फ्रास्ट्रक्चर की पहचान

आधुनिक credential-phishing में बढ़ते हुए **Adversary-in-the-Middle (AiTM)** reverse proxies (उदा., Evilginx) का उपयोग session tokens चुराने के लिए होता है। आप network-side detections जोड़ सकते हैं:

- egress पर TLS/HTTP फिंगरप्रिंट्स (JA3/JA4/JA4S/JA4H) को लॉग करें। कुछ Evilginx builds में स्थिर JA4 client/server मान देखे गए हैं। केवल कमजोर संकेत के रूप में known-bad fingerprints पर अलर्ट करें और हमेशा content और domain intel से पुष्टि करें।
- CT या urlscan के माध्यम से मिले lookalike hosts के लिए TLS certificate metadata (issuer, SAN count, wildcard use, validity) को सक्रिय रूप से रिकॉर्ड करें और DNS age तथा geolocation के साथ correlate करें।

> नोट: फिंगरप्रिंट्स को enrichment के रूप में मानें, केवल blockers के रूप में नहीं; frameworks विकसित होते हैं और वे randomise या obfuscate कर सकते हैं।

### कीवर्ड का उपयोग करने वाले डोमेन नाम

मूल पृष्ठ में एक डोमेन नाम वेरिएशन तकनीक का भी ज़िक्र है, जिसमें **victim's domain name को एक बड़े डोमेन के अंदर रखा जाता है** (उदा., paypal-financial.com for paypal.com)।

#### Certificate Transparency

पिछला "Brute-Force" तरीका अपनाना संभव नहीं है, पर certificate transparency की वजह से ऐसे phishing प्रयासों का पता लगाया जा सकता है। हर बार जब कोई CA द्वारा certificate जारी होता है, उसके विवरण सार्वजनिक किए जाते हैं। इसका मतलब है कि certificate transparency को पढ़कर या मॉनिटर करके ऐसे डोमेन्स ढूँढना संभव है जिनके नाम में कोई कीवर्ड इस्तेमाल हुआ हो। उदाहरण के लिए, अगर कोई attacker [https://paypal-financial.com](https://paypal-financial.com) का certificate बनाता है, तो certificate देखकर कीवर्ड "paypal" मिल सकता है और पता चल सकता है कि suspicious email उपयोग किया जा रहा है।

पोस्ट [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) सुझाव देता है कि आप Censys का उपयोग किसी विशेष कीवर्ड से संबंधित certificates खोजने के लिए कर सकते हैं और date (केवल "new" certificates) तथा CA issuer "Let's Encrypt" के अनुसार filter कर सकते हैं:

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

हालाँकि, आप free वेब **crt.sh** का उपयोग करके "उसी" काम को कर सकते हैं। आप **कीवर्ड खोज** सकते हैं और परिणामों को **date और CA** के अनुसार filter कर सकते हैं यदि आप चाहें।

![](<../../images/image (519).png>)

इस विकल्प का उपयोग करके आप Matching Identities फ़ील्ड का उपयोग भी कर सकते हैं यह देखने के लिए कि क्या किसी असली डोमेन की कोई identity किसी suspicious domain से मिलती है (ध्यान दें कि एक suspicious domain false positive हो सकता है)।

**एक और विकल्प** है शानदार प्रोजेक्ट **CertStream**। CertStream newly generated certificates का real-time stream देता है जिसे आप निर्दिष्ट कीवर्ड्स का (near) real-time पता लगाने के लिए उपयोग कर सकते हैं। वास्तव में, एक प्रोजेक्ट है **phishing_catcher** जो यही करता है।

व्यावहारिक सुझाव: जब CT hits का triage कर रहे हों, NRDs, untrusted/unknown registrars, privacy-proxy WHOIS, और बहुत हाल के `NotBefore` समय वाले certs को प्राथमिकता दें। शोर कम करने के लिए अपने मालिकाना डोमेनों/ब्रांड्स की allowlist बनाए रखें।

#### **New domains**

**एक अंतिम विकल्प** यह है कि कुछ TLDs के लिए **newly registered domains** की एक सूची इकट्ठा करें ([Whoxy](https://www.whoxy.com/newly-registered-domains/) ऐसी सेवा प्रदान करता है) और इन डोमेन्स में कीवर्ड्स चेक करें। हालाँकि, लंबे डोमेन्स आमतौर पर एक या अधिक subdomains का उपयोग करते हैं, इसलिए कीवर्ड FLD के अंदर प्रकट नहीं होगा और आप phishing subdomain नहीं पाएंगे।

अतिरिक्त heuristic: कुछ **file-extension TLDs** (उदा., `.zip`, `.mov`) को alerting में अतिरिक्त संदेह के साथ मानें। ये अक्सर lures में filenames के साथ भ्रमित होते हैं; बेहतर सटीकता के लिए TLD संकेत को brand keywords और NRD age के साथ मिलाएँ।

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
