# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks के लोगो और मोशन डिज़ाइन द्वारा_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks को स्थानीय रूप से चलाएँ
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export LANG="master" # Leave master for english
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for HindiP
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## कॉर्पोरेट प्रायोजक

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) एक बेहतरीन साइबर सुरक्षा कंपनी है जिसका स्लोगन **HACK THE UNHACKABLE** है। वे अपना शोध करते हैं और अपनी खुद की hacking tools डेवलप करते हैं ताकि **कई मूल्यवान साइबर सुरक्षा सेवाएँ** प्रदान कर सकें जैसे pentesting, Red teams और training।

आप उनका **ब्लॉग** यहाँ देख सकते हैं: [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** HackTricks जैसे साइबर सुरक्षा ओपन सोर्स प्रोजेक्ट्स का भी समर्थन करता है :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) **Spain** में सबसे प्रासंगिक साइबर सुरक्षा इवेंट और **Europe** में सबसे महत्वपूर्ण इवेंट्स में से एक है। **the mission of promoting technical knowledge** के साथ, यह Congress तकनीक और साइबर सुरक्षा पेशेवरों के लिए हर अनुशासन में एक सक्रिय मिलन स्थल है।

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** Europe की #1 ethical hacking और bug bounty platform है।

**Bug bounty tip**: **sign up** करें **Intigriti** पर, यह hackers द्वारा, hackers के लिए बनाया गया एक premium **bug bounty platform** है! आज ही हमारे साथ जुड़ें: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) और $100,000 तक के bounties कमाना शुरू करें!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) का उपयोग करें ताकि आप आसानी से दुनिया के सबसे advanced community tools से शक्तिशाली workflows बना और automate कर सकें।

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ताकि आप experienced hackers और bug bounty hunters के साथ संवाद कर सकें!

- **Hacking Insights:** ऐसे कंटेंट से जुड़ें जो hacking के रोमांच और चुनौतियों में गहराई तक जाता है
- **Real-Time Hack News:** रियल-टाइम खबरों और इनसाइट्स के जरिये तेज़ी से बदलती hacking दुनिया के साथ अपडेट रहें
- **Latest Announcements:** नए लॉन्च होने वाले bug bounties और महत्वपूर्ण प्लेटफ़ॉर्म अपडेट्स की जानकारी पाते रहें

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) और आज ही top hackers के साथ सहयोग शुरू करें!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** हमारे 20+ custom tools का उपयोग करके attack surface को map करें, उन security issues को खोजें जो privileges escalate करने देते हैं, और automated exploits का उपयोग करके आवश्यक evidence इकट्ठा करें, जिससे आपके मेहनत के नतीजे प्रभावशाली reports में बदल सकें।

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** तेज़ और आसान real-time APIs प्रदान करता है ताकि आप search engine results तक पहुँच सकें। वे search engines को scrape करते हैं, proxies को हैंडल करते हैं, captchas को सुलझाते हैं, और आपके लिए सभी rich structured data को parse करते हैं।

SerpApi की किसी भी subscription में Google, Bing, Baidu, Yahoo, Yandex और अन्य search engines के scraping के लिए 50+ अलग APIs तक पहुँच शामिल है.\
अन्य प्रदाताओं के विपरीत, **SerpApi सिर्फ organic results नहीं scrape करता**। SerpApi responses में लगातार सभी ads, inline images और videos, knowledge graphs, और search results में मौजूद अन्य elements और features शामिल होते हैं।

Current SerpApi customers में **Apple, Shopify, और GrubHub** शामिल हैं।\
अधिक जानकारी के लिए उनका [**blog**](https://serpapi.com/blog/) देखें, या उनके [**playground**](https://serpapi.com/playground) में एक उदाहरण आज़माएँ।\
आप यहाँ एक free account बना सकते हैं: [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

वह तकनीकें और कौशल सीखें जो vulnerability research, penetration testing, और reverse engineering करने के लिए आवश्यक हैं ताकि आप mobile applications और devices की सुरक्षा कर सकें। हमारे on-demand courses के माध्यम से **iOS और Android security** में महारत हासिल करें और **get certified**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) अम्स्टर्डम (Amsterdam) स्थित एक professional साइबर सुरक्षा कंपनी है जो आधुनिक दृष्टिकोण के साथ दुनिया भर के व्यवसायों को नवीनतम साइबर खतरों के खिलाफ बचाने में मदद करती है, और offensive-security services प्रदान करती है।

WebSec एक अंतरराष्ट्रीय security कंपनी है जिसकी offices Amsterdam और Wyoming में हैं। वे **all-in-one security services** प्रदान करते हैं जिसका मतलब है कि वे सब कुछ करते हैं; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campaigns, Code Review, Exploit Development, Security Experts Outsourcing और बहुत कुछ।

WebSec की एक और खास बात यह है कि industry average की तुलना में वे अपनी skills पर बहुत confident हैं, इस हद तक कि वे **best quality results** की गारंटी देते हैं; उनकी वेबसाइट पर लिखा है "**If we can't hack it, You don't pay it!**". अधिक जानकारी के लिए उनकी [**website**](https://websec.net/en/) और [**blog**](https://websec.net/blog/) देखें!

इसके अलावा WebSec HackTricks का भी **committed supporter** है।

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) एक data breach (leak) search engine है. \
हम सभी प्रकार के data leaks (बड़े और छोटे दोनों) पर random string search (जैसे google) प्रदान करते हैं -- केवल बड़े leaks ही नहीं -- और यह डेटा कई स्रोतों से आता है. \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration — ये सभी वे features हैं जो एक pentester को चाहिए.\
**HackTricks हमारे लिए एक महान सीखने का प्लेटफ़ॉर्म बना रहता है और हमें इसे sponsor करते हुए गर्व है!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) industry experts द्वारा निर्मित और संचालित प्रभावी साइबर सुरक्षा training विकसित और प्रदान करता है। उनके प्रोग्राम सिर्फ सिद्धांत तक सीमित नहीं हैं बल्कि teams को गहन समझ और actionable skills से लैस करते हैं, custom environments का उपयोग करके जो वास्तविक दुनिया के threats को प्रतिबिंबित करते हैं। कस्टम training के लिए inquiries के लिए हमसे संपर्क करें [**यहाँ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)।

**उनकी training के अलग होने के कारण:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions शिक्षा (Education) और FinTech संस्थानों के लिए विशेषीकृत साइबर सुरक्षा सेवाएँ प्रदान करता है, जिनका फोकस penetration testing, cloud security assessments, और compliance readiness (SOC 2, PCI-DSS, NIST) पर है। हमारी टीम में OSCP और CISSP प्रमाणित professionals शामिल हैं, जो हर engagement में गहरी technical expertise और industry-standard insight लाते हैं।

हम automated scans से आगे जाकर **manual, intelligence-driven testing** प्रदान करते हैं जो high-stakes environments के लिए अनुकूलित होता है। छात्र रिकॉर्ड की सुरक्षा से लेकर वित्तीय लेन-देन की सुरक्षा तक, हम संगठनों को उनकी सबसे महत्वपूर्ण चीजों की रक्षा में मदद करते हैं।

_“A quality defense requires knowing the offense, we provide security through understanding.”_

नवीनतम साइबर सुरक्षा अपडेट्स के लिए हमारे [**blog**](https://www.lasttowersolutions.com/blog) पर जाएँ।

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE DevOps, DevSecOps, और developers को सक्षम बनाता है ताकि वे Kubernetes clusters को प्रभावी तरीके से manage, monitor, और secure कर सकें। हमारे AI-driven insights, advanced security framework, और intuitive CloudMaps GUI का उपयोग करके आप अपने clusters का visualization कर सकते हैं, उनकी स्थिति समझ सकते हैं, और आत्मविश्वास के साथ कार्रवाई कर सकते हैं।

इसके अलावा, K8Studio **सभी प्रमुख kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift और अधिक) के साथ compatible है।

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

इन्हें यहाँ देखें:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
